"""威胁类型收口 - 覆盖校验 + 删旧加新 + 映射写入，一次落盘原子完成。

threat-type 技能的收口脚本（链路第三步）：宿主 agent 依据工作单
（threat_worklist.py 产物）完成来源字段分组判定与威胁分类后，把分组
判定 JSON 交给本脚本做确定性校验与写回。目标子规则＝事件标注威胁组
自动寻址；三态写回（链路自产整体替换 / 存量合并 / 缺失新增）与
orgValue 合并语义的共存约定见 ``_shared/threat_policy.py``。

CLI 用法:
    python threat_finalize.py --input <配置文件>
                              --worklist <工作单.json>
                              --judgments <分组判定.json>
                              [--output <路径>] [--no-export]

输入: 配置族文件（Base64 txt / 原生 JSON / TXT，规则数组）+
      工作单 JSON（threat_worklist.py 产物，声明值集来源）+
      分组判定 JSON（宿主 agent 产物）:
      ``{"groups": [{"source_field": X, "rules": [...],
        "pairs": [{"mappingType", "orgValue", "mappingValue"}]}],
        "skipped_rules": [...]}``（裸数组视为纯 groups；skipped_rules
        可省）。
输出: ``<输入名>_threatfilled.json`` + Base64 导出
      ``threatmapping_config_{时间戳}.txt`` + stdout JSON 摘要。

守卫链（任一命中整单拒绝，一行不写）:
- 工作单/判定文件缺失或结构不符 → ``input_required`` / ``invalid_input``；
- 工作单与配置的威胁子规则不一致 → ``invalid_input``（重新生成工作单）；
- 分组判定未恰好划分全部威胁子规则（非威胁规则入组 / 重复分组 /
  既未分组也未跳过）→ ``invalid_input``（附规则标识与具体规则名）；
- 跨组同值归类不一致（同一声明值在不同组映射到不同威胁类型）→
  ``invalid_input``（``value_mapped_inconsistently``，各组分类必须来自
  同一次判定）；
- 来源字段不在工作单候选中、或不在某子规则字段池中 → ``invalid_input``；
- 分组无有效映射对 → ``invalid_input``；
- 标准字段目录威胁类型行异常 → ``threat_mapping_reference_unavailable``；
- 组内声明值全部为无语义数字代码 →
  ``threat_mapping_source_context_required``（请换来源字段或提供代码表）；
- 统一覆盖校验（四规则：枚举外 / 缺项 / 重叠 / 多余行）→
  ``threat_mapping_coverage_rejected``（附规则标识与具体值/行）。

写回语义（按子规则三态）:
- **chain**（威胁类型条目带 ``%{X}`` 引用绑定＝链路自产）：先删后加
  整体替换——清除该子规则全部威胁类型条目与绑定，追加唯一新绑定
  ``%{来源字段}`` 与新条目（``field=threat_type / entity=威胁 /
  sim=true / core=false``），mappings 全量重建；
- **absent**：同 chain 的追加写法（无旧物可清）；
- **existing**（存量条目）：保留条目原状，解绑其固定值绑定后按
  orgValue 合并更新 mappings（与枚举填充共用 ``_shared/enum_merge``
  的合并语义，手工维护的值映射与链路写入可共存）；
- 零变更 → 成功幂等提示，产物照常输出。
"""

from __future__ import annotations

import argparse
import copy
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

_SKILLS_ROOT = Path(__file__).resolve().parents[2]
if str(_SKILLS_ROOT) not in sys.path:
    sys.path.insert(0, str(_SKILLS_ROOT))

from _shared import report as skill_report
from _shared.config_io import ConfigIOError, load_entities
from _shared.enum_merge import (
    apply_pairs_to_entry,
    dedup_pairs_first_wins,
    unbind_fixed_bindings,
)
from _shared.enum_table import normalize_pairs
from _shared.threat_policy import (
    THREAT_COVERAGE_ERROR_CODE,
    THREAT_FIELD_CHAIN,
    THREAT_SOURCE_CONTEXT_ERROR_CODE,
    THREAT_TYPE_FIELD,
    ThreatPolicyError,
    append_threat_type_binding,
    collect_threat_rule_names,
    find_threat_type_entries,
    inspect_threat_field_state,
    is_code_only_value,
    make_threat_type_normalize_entry,
    remove_threat_type_writings,
    rule_sample_count,
    threat_field_pools,
    threat_whitelist,
    validate_cross_group_consistency,
    validate_group_assignment,
    validate_threat_coverage,
)


def _print_error(code: str, message: str) -> int:
    return skill_report.print_error(code, message)


# ---------------------------------------------------------------------------
# 工作单与分组判定输入
# ---------------------------------------------------------------------------


def _load_json(path: str, what: str) -> Any:
    file_path = Path(path)
    if not file_path.is_file():
        raise ValueError(f"找不到{what}: {file_path}")
    try:
        return json.loads(file_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"{what}不是合法 JSON: {exc}") from exc


def load_worklist(path: str) -> Dict[str, Any]:
    """解析工作单 JSON，校验必需区块，返回规整后的 dict。

    契约：``threat_rules``（名单）与 ``candidates``（每字段 value_counts
    全量首现序）。声明值集取 value_counts 的键（全量，不受 --max-values
    截断影响——覆盖校验的输入集合必须与提取集合一致）。
    """
    raw = _load_json(path, "工作单文件")
    if not isinstance(raw, dict):
        raise ValueError("工作单须为对象（threat_worklist.py 产物）")
    threat_rules = raw.get("threat_rules")
    candidates = raw.get("candidates")
    if not isinstance(threat_rules, list) or not threat_rules:
        raise ValueError("工作单缺少 threat_rules 名单，请用 threat_worklist.py 重新生成")
    if not isinstance(candidates, list):
        raise ValueError("工作单缺少 candidates 画像，请用 threat_worklist.py 重新生成")

    value_profiles: Dict[str, List[str]] = {}
    for candidate in candidates:
        if not isinstance(candidate, dict):
            raise ValueError("工作单 candidates 元素必须是对象")
        field = str(candidate.get("field") or "")
        counts = candidate.get("value_counts")
        if not field or not isinstance(counts, dict):
            raise ValueError(f"工作单候选 {field!r} 缺少 value_counts，请重新生成工作单")
        value_profiles[field] = [str(value) for value in counts]
    return {"threat_rules": [str(name) for name in threat_rules], "values": value_profiles}


def load_judgments(path: str) -> Tuple[List[Dict[str, Any]], List[str]]:
    """解析分组判定 JSON → (groups, skipped_rules)。

    契约：``{"groups": [...], "skipped_rules": [...]}``（裸数组视为纯
    groups）；group 元素须含 source_field / rules / pairs。
    """
    raw = _load_json(path, "分组判定文件")
    if isinstance(raw, dict):
        groups = raw.get("groups")
        skipped = raw.get("skipped_rules", [])
    else:
        groups = raw
        skipped = []
    if not isinstance(groups, list) or not groups:
        raise ValueError("分组判定须为 {groups: [...]} 对象或裸数组，且至少一个分组")
    if not isinstance(skipped, list):
        raise ValueError("skipped_rules 须为数组")

    normalized_groups: List[Dict[str, Any]] = []
    for group in groups:
        if not isinstance(group, dict):
            raise ValueError("groups 元素必须是对象（source_field / rules / pairs）")
        source_field = str(group.get("source_field") or "").strip()
        rules = group.get("rules")
        pairs = group.get("pairs")
        if not source_field:
            raise ValueError("分组缺少 source_field（来源字段名）")
        if not isinstance(rules, list) or not rules:
            raise ValueError(f"分组（来源字段 {source_field!r}）缺少 rules 名单")
        if not isinstance(pairs, list) or not pairs:
            raise ValueError(f"分组（来源字段 {source_field!r}）缺少 pairs 映射对")
        normalized_groups.append(
            {
                "source_field": source_field,
                "rules": [str(name) for name in rules],
                "pairs": pairs,
            }
        )
    return normalized_groups, [str(name) for name in skipped]


# ---------------------------------------------------------------------------
# 写回（按子规则三态）
# ---------------------------------------------------------------------------


def write_group_to_rule(
    entity: Dict[str, Any],
    source_field: str,
    pairs: List[Dict[str, str]],
) -> Dict[str, Any]:
    """把一组映射行写进单条子规则（原地修改），返回写回摘要。

    三态（对齐 _shared/threat_policy 设计裁决）：
    - chain：先删后加整体替换，mappings 全量重建；
    - absent：追加绑定与新条目；
    - existing：解绑固定值绑定后 orgValue 合并（共用 _shared/enum_merge）。
    """
    state = inspect_threat_field_state(entity)
    summary: Dict[str, Any] = {"state": state}

    if state in (THREAT_FIELD_CHAIN, "absent"):
        if state == THREAT_FIELD_CHAIN:
            remove_threat_type_writings(entity)
        append_threat_type_binding(entity, source_field)
        entity.setdefault("normalize", []).append(
            make_threat_type_normalize_entry(
                source_field, pairs, sample_count=rule_sample_count(entity)
            )
        )
        summary.update(
            {
                "added": len(pairs),
                "updated": 0,
                "unchanged": 0,
                "unbound": 0,
                "rebuilt": state == THREAT_FIELD_CHAIN,
            }
        )
        return summary

    # existing：保留条目，解绑固定值绑定后按 orgValue 合并
    unbound = unbind_fixed_bindings(entity, [THREAT_TYPE_FIELD])
    stats = {"added": 0, "updated": 0, "unchanged": 0}
    entries = find_threat_type_entries(entity)
    for entry in entries:
        applied = apply_pairs_to_entry(entry, pairs)
        for key in stats:
            stats[key] += applied[key]
    summary.update({"unbound": unbound, "rebuilt": False, **stats})
    if not entries:
        # 理论不可达（existing 态必有条目）；防御性如实记录
        summary["state"] = "absent"
    return summary


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="threat_finalize.py",
        description="威胁类型收口：覆盖校验 + 删旧加新 + 映射写入（原子幂等）",
    )
    parser.add_argument(
        "--input", "-i", required=True,
        help="配置文件路径（Base64 txt / 原生 JSON / TXT，内容为 JSON 数组）",
    )
    parser.add_argument(
        "--worklist", required=True,
        help="工作单 JSON 路径（threat_worklist.py 产物，声明值集来源）",
    )
    parser.add_argument(
        "--judgments", required=True,
        help="分组判定 JSON 路径（宿主 agent 产物：groups + skipped_rules）",
    )
    parser.add_argument(
        "--output", "-o", default=None,
        help=f"修改后配置 JSON 输出路径（缺省 <输入名>{skill_report.DEFAULT_OUTPUT_SUFFIXES['threatfilled']}）",
    )
    parser.add_argument(
        "--no-export", action="store_true",
        help="不产出 Base64 导出文件（缺省会一并产出）",
    )
    args = parser.parse_args(argv)

    try:
        worklist = load_worklist(args.worklist)
        groups, skipped_rules = load_judgments(args.judgments)
    except ValueError as exc:
        return _print_error("invalid_input", str(exc))

    try:
        config = load_entities(args.input)
    except ConfigIOError as exc:
        return _print_error(exc.code, exc.message)

    # 工作单与配置的威胁子规则必须一致（配置后改过 → 重新生成工作单）
    try:
        threat_rules = collect_threat_rule_names(config)
    except ThreatPolicyError as exc:
        return _print_error(exc.code, exc.message)
    if threat_rules != worklist["threat_rules"]:
        return _print_error(
            "invalid_input",
            "工作单与当前配置的威胁子规则不一致（配置可能已修改），"
            "请先用 threat_worklist.py 重新生成工作单",
        )

    violation = validate_group_assignment(threat_rules, groups, skipped_rules)
    if violation is not None:
        return _print_error(
            "invalid_input", f"分组判定不成立（{violation['rule']}）: {violation['message']}"
        )

    try:
        whitelist = threat_whitelist()
    except ThreatPolicyError as exc:
        return _print_error(exc.code, exc.message)

    pools = threat_field_pools(config, threat_rules)

    # 逐组校验（结构 → 声明值集 → 覆盖四规则），全部通过才进入写回
    prepared_groups: List[Dict[str, Any]] = []
    for group in groups:
        source_field = group["source_field"]
        declared = worklist["values"].get(source_field)
        if declared is None:
            return _print_error(
                "invalid_input",
                f"来源字段 {source_field!r} 不在工作单候选字段中，"
                f"请修正分组或重新生成工作单",
            )
        for name in group["rules"]:
            if source_field not in pools.get(name, []):
                return _print_error(
                    "invalid_input",
                    f"来源字段 {source_field!r} 不在子规则 {name!r} 的字段池中，"
                    f"请为该子规则另行判定来源字段",
                )
        try:
            pairs = normalize_pairs(group["pairs"])
        except ValueError as exc:
            return _print_error(
                "invalid_input",
                f"分组（来源字段 {source_field!r}）的映射对契约不符: {exc}",
            )
        if not pairs:
            return _print_error(
                "invalid_input",
                f"分组（来源字段 {source_field!r}）没有有效映射对",
            )
        pairs, duplicates = dedup_pairs_first_wins(pairs)
        if declared and all(is_code_only_value(value) for value in declared):
            return _print_error(
                THREAT_SOURCE_CONTEXT_ERROR_CODE,
                f"来源字段 {source_field!r} 的声明值全部为无语义数字代码，"
                f"无法可靠映射威胁类型；请改用含语义的来源字段，"
                f"或提供代码表后重试",
            )
        coverage = validate_threat_coverage(declared, pairs, whitelist)
        if coverage is not None:
            return _print_error(
                THREAT_COVERAGE_ERROR_CODE,
                f"{coverage['rule']}: {coverage['message']}"
                f"（分组来源字段 {source_field!r}）",
            )
        prepared_groups.append(
            {
                "source_field": source_field,
                "rules": group["rules"],
                "pairs": pairs,
                "declared": declared,
                "declared_count": len(declared),
                "duplicates": duplicates,
            }
        )

    # 跨组同值归类一致性（各组分类必须来自同一次判定）
    inconsistency = validate_cross_group_consistency(prepared_groups)
    if inconsistency is not None:
        return _print_error(
            "invalid_input",
            f"分组判定不成立（{inconsistency['rule']}）: {inconsistency['message']}",
        )

    # 写回（深拷贝，原子：全部校验已通过，一次构造一次落盘）
    updated = copy.deepcopy(config)
    by_name = {
        entity.get("name"): entity
        for entity in updated
        if isinstance(entity, dict) and entity.get("name")
    }

    group_reports: List[Dict[str, Any]] = []
    total_added = total_updated = total_unbound = 0
    rebuilt_rules = 0
    for group in prepared_groups:
        rule_reports = []
        for name in group["rules"]:
            summary = write_group_to_rule(
                by_name[name], group["source_field"], group["pairs"]
            )
            total_added += summary["added"]
            total_updated += summary["updated"]
            total_unbound += summary["unbound"]
            if summary.get("rebuilt"):
                rebuilt_rules += 1
            rule_reports.append({"rule": name, **summary})
        group_reports.append(
            {
                "source_field": group["source_field"],
                "rules": rule_reports,
                "declared_count": group["declared_count"],
                "pair_count": len(group["pairs"]),
                "duplicates": group["duplicates"],
            }
        )

    changes = total_added + total_updated + total_unbound
    skipped_note = f"；跳过 {len(skipped_rules)} 条（用户裁决）" if skipped_rules else ""
    if changes == 0:
        message = "威胁类型映射已全部存在，无变更" + skipped_note
    else:
        message = (
            f"写入映射 {total_added + total_updated} 行（新增 {total_added}、"
            f"更新 {total_updated}）"
            + (f"、整体重建 {rebuilt_rules} 条子规则" if rebuilt_rules else "")
            + (f"、解绑固定值绑定 {total_unbound} 处" if total_unbound else "")
            + f"，分组 {len(prepared_groups)} 组、覆盖 {sum(len(g['rules']) for g in prepared_groups)} 条威胁子规则"
            + skipped_note
        )

    input_path = Path(args.input)
    output = (
        Path(args.output)
        if args.output
        else skill_report.default_output_path(input_path, "threatfilled")
    )
    written = skill_report.write_result(
        updated, output, kind="threatmapping_config", make_export=not args.no_export
    )
    payload = {
        "status": "success",
        "message": message,
        "output": str(written["json_path"]),
        "export": str(written["export_path"]) if written["export_path"] else None,
        "groups": group_reports,
        "skipped_rules": skipped_rules,
        "whitelist_size": len(whitelist),
    }
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
