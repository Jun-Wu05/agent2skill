"""映射收口 - 校验宿主 agent 判定并产出映射结果、事件标注与入口规则。

field-mapping 技能的阶段②脚本（收口）：宿主 agent 读取阶段①
（mapping_candidates.py）产出的候选单后，为每个待映射字段判定标准字段
（mappings.json，两列精简契约）并可为每条子规则判定事件名称（21 分类
名单内）。本脚本做确定性收口——sanitize（裁剪臆造/回填遗漏/黑名单与
候选外降级）、枚举字段短路合并（自动判定优先）、一对一占用裁决（既有
映射恒赢 → 精确命中 → 相似度 → 原行序）、写回、事件标注（级别查表
绑定、非法不写）与入口规则生成（白板路径），并按平台下载命名导出 Base64。

CLI 用法:
    白板路径:  python mapping_finalize.py --subrules <白板_subrules.json>
                                    --classified <分类结果.json> --mappings <判定.json>
                                    --vendor <厂商> --product <产品>
                                    [--output ...] [--entry-output ...] [--no-export]
    配置路径:  python mapping_finalize.py --config <配置文件> --mappings <判定.json>
                                    [--output ...] [--no-export]

mappings.json 契约（宿主 agent 语义层）:
    {"mappings": [{"field": "<原始字段名>", "standard": "<中文系统属性名>|未匹配"}],
     "events":   [{"rule_name": "<子规则名>", "event_name": "<21 分类名>"}]}
    （裸数组视为纯 mappings，无 events）

输出:
    白板路径: 映射后子规则 JSON（缺省 <输入名>_mapped_subrules.json）+ 入口规则 JSON
        （缺省 <输入名>_entry_rules.json）+ Base64 导出
        （mappedconfig_subrules_YYYYMMDD_HHMM.txt / mappedconfig_mainrules_YYYYMMDD_HHMM.txt）
    配置路径: 映射后配置 JSON（缺省 <输入名>_mapped_config.json）+ Base64 导出
        （fieldmapped_config_YYYYMMDD_HHMM.txt）
    两者均附 stdout JSON 摘要（映射/未匹配/短路/sanitize/冲突/事件统计）。

版本守卫（guide.md 纪律，脚本不做）：重新收口前确认白板子规则未因重新
分类而重建——白板重建会使 mappings.json 判定失去依据。
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

_SKILLS_ROOT = Path(__file__).resolve().parents[2]
if str(_SKILLS_ROOT) not in sys.path:
    sys.path.insert(0, str(_SKILLS_ROOT))

from _shared import report as skill_report
from _shared import standard_catalog
from _shared.candidate_retrieval import DEFAULT_TOP_K, CandidateRetriever
from _shared.config_io import ConfigIOError, load_entities
from _shared.event_binding import ALL_EVENT_NAMES, apply_event_fields_to_sub_rules
from _shared.mapping_apply import (
    apply_decisions_to_config,
    apply_decisions_to_subrules,
    collect_config_rules,
    collect_existing_occupants,
    collect_expected_fields,
    collect_subrule_rules,
    resolve_occupancy_conflicts,
    sanitize_decisions,
)
from _shared.rule_gen import (
    RuleSourceFields,
    detect_entry_format,
    generate_entry_rule,
)


def _print_error(code: str, message: str) -> int:
    return skill_report.print_error(code, message)


def _load_json_file(path: str, what: str):
    file_path = Path(path)
    if not file_path.is_file():
        return None, _print_error("input_required", f"找不到{what}: {file_path}")
    try:
        data = json.loads(file_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        return None, _print_error("invalid_input", f"{what}不是合法 JSON: {exc}")
    return data, None


def _parse_mappings(raw: Any) -> Tuple[List[Any], List[Any]]:
    """mappings.json → (mappings 数组, events 数组)；裸数组视为纯 mappings。"""
    if isinstance(raw, list):
        return raw, []
    if isinstance(raw, dict):
        mappings = raw.get("mappings")
        events = raw.get("events")
        if events is None:
            events = []
        if not isinstance(mappings, list):
            raise ValueError("mappings 必须是数组")
        if not isinstance(events, list):
            raise ValueError("events 必须是数组")
        return mappings, events
    raise ValueError("mappings.json 须为 {mappings, events} 对象或裸数组")


def _enum_auto_decisions(
    expected_fields: List[str], catalog: standard_catalog.StandardFieldCatalog
) -> Dict[str, standard_catalog.StandardField]:
    """枚举字段确定性短路：{字段: 目录记录}。"""
    auto: Dict[str, standard_catalog.StandardField] = {}
    for field in expected_fields:
        short = standard_catalog.resolve_enum_field(field, catalog)
        if short is None:
            continue
        record = catalog.lookup(short[0])
        if record is not None:
            auto[field] = record
    return auto


def _collect_event_judgments(events: List[Any], rule_names: set) -> Tuple[Dict[str, str], Dict[str, list]]:
    """events 段 → ({规则名: 事件名}, 跳过明细)；非法/未知不写（宁缺勿错）。"""
    judgments: Dict[str, str] = {}
    unknown: List[str] = []
    invalid: List[str] = []
    for item in events:
        if not isinstance(item, dict):
            invalid.append(str(item))
            continue
        rule_name = str(item.get("rule_name", "") or "")
        event_name = str(item.get("event_name", "") or "")
        if rule_name not in rule_names:
            unknown.append(rule_name)
            continue
        if event_name not in ALL_EVENT_NAMES:
            invalid.append(rule_name)
            continue
        judgments[rule_name] = event_name
    return judgments, {
        "unknown_rule": sorted(set(unknown)),
        "invalid_event": sorted(set(invalid)),
    }


def _base_stem(path: Path) -> str:
    """子规则输入名去掉 _subrules（或历史 .subrules）后缀作为产物基名。"""
    stem = path.stem
    for suffix in ("_subrules", ".subrules"):
        if stem.endswith(suffix):
            return stem[: -len(suffix)]
    return stem


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="mapping_finalize.py",
        description="映射收口：sanitize + 占用裁决 + 写回 + 事件标注 + 入口规则 + 导出（阶段②：收口）",
    )
    parser.add_argument("--subrules", default=None, help="白板子规则 JSON 路径（白板路径）")
    parser.add_argument("--config", default=None, help="配置文件路径（配置路径，Base64/JSON/TXT）")
    parser.add_argument("--mappings", required=True, help="宿主 agent 判定 JSON 路径")
    parser.add_argument("--classified", default=None, help="分类结果 JSON 路径（log-classification 产物，白板路径必填）")
    parser.add_argument("--vendor", default=None, help="数据源厂商（白板路径必填）")
    parser.add_argument("--product", default=None, help="数据源产品（白板路径必填）")
    parser.add_argument("--output", "-o", default=None, help="映射结果 JSON 输出路径（缺省按路径命名）")
    parser.add_argument("--entry-output", default=None, help="入口规则 JSON 输出路径（仅白板路径，缺省 <输入名>_entry_rules.json）")
    parser.add_argument("--no-export", action="store_true", help="不产出 Base64 导出文件（缺省会一并产出）")
    parser.add_argument("--top-k", type=int, default=DEFAULT_TOP_K, help=f"候选校验上限，与阶段①一致（缺省 {DEFAULT_TOP_K}）")
    args = parser.parse_args(argv)

    if bool(args.subrules) == bool(args.config):
        return _print_error(
            "invalid_input",
            "必须且只能指定 --subrules（白板路径）或 --config（配置路径）之一",
        )

    mappings_raw, err = _load_json_file(args.mappings, "判定文件")
    if err is not None:
        return err
    try:
        mappings, events = _parse_mappings(mappings_raw)
    except ValueError as exc:
        return _print_error("invalid_input", f"mappings.json 契约不符: {exc}")

    input_path = Path(args.subrules or args.config)
    try:
        entities = load_entities(input_path)
    except ConfigIOError as exc:
        return _print_error(exc.code, exc.message)

    classification: Optional[dict] = None
    if args.subrules:
        missing = [
            flag
            for flag, value in (
                ("--classified", args.classified),
                ("--vendor", args.vendor),
                ("--product", args.product),
            )
            if not value
        ]
        if missing:
            return _print_error(
                "invalid_input",
                f"白板路径必须提供 {'、'.join(missing)}（厂商/产品用于入口规则与数据源字段）",
            )
        classification, err = _load_json_file(args.classified, "分类结果")
        if err is not None:
            return err
        if not isinstance(classification, dict):
            return _print_error("invalid_input", "分类结果必须是 JSON 对象")
        _, _, _, is_syslog_kv = detect_entry_format(classification)
        if is_syslog_kv and not classification.get("feature_identifier"):
            return _print_error(
                "invalid_input",
                "日志头+KV 格式的入口规则需要日志头正则（feature_identifier），"
                "当前分类产物未提供——该格式暂不支持，见 guide 约束与边界",
            )
        rules = collect_subrule_rules(entities)
    else:
        rules = collect_config_rules(entities)

    expected = collect_expected_fields(rules)

    try:
        catalog = standard_catalog.load_catalog()
    except (FileNotFoundError, ValueError) as exc:
        return _print_error("invalid_input", f"标准字段目录加载失败: {exc}")
    retriever = CandidateRetriever(catalog)

    # 枚举短路（自动判定优先）→ sanitize → 合并
    auto = _enum_auto_decisions(expected, catalog)
    decisions, sanitize_report = sanitize_decisions(
        mappings, expected, catalog, retriever, args.top_k
    )
    explicit_fields = {
        str(item.get("field", "") or "")
        for item in mappings
        if isinstance(item, dict)
    }
    overridden = sorted(field for field in auto if field in explicit_fields)
    decisions.update(auto)

    # 一对一占用裁决（既有映射恒赢 → 精确命中 → 相似度 → 原行序）
    occupants = collect_existing_occupants(entities)
    decisions, conflicts = resolve_occupancy_conflicts(
        decisions, expected, occupants, retriever, args.top_k
    )
    matched = sum(1 for field in expected if decisions.get(field) is not None)

    if args.subrules:
        mapped = apply_decisions_to_subrules(entities, decisions, catalog)

        # 事件名称标注（判定写回之后；非法/缺失不写）
        rule_names = {str(entity.get("name", "") or "") for entity in entities}
        judgments, event_notes = _collect_event_judgments(events, rule_names)
        mapped = apply_event_fields_to_sub_rules(mapped, judgments)

        # 入口规则（本身不含字段映射）
        try:
            source_fields = RuleSourceFields(product=args.product, log_vendor=args.vendor)
        except ValueError as exc:
            return _print_error("invalid_input", str(exc))
        entry_rule = generate_entry_rule(
            classification, rule_source_fields=source_fields
        )

        base = _base_stem(input_path)
        mapped_output = (
            Path(args.output)
            if args.output
            else input_path.with_name(base + "_mapped_subrules.json")
        )
        entry_output = (
            Path(args.entry_output)
            if args.entry_output
            else input_path.with_name(base + "_entry_rules.json")
        )
        written = skill_report.write_result(
            mapped, mapped_output, make_export=not args.no_export,
            kind="mappedconfig_subrules",
        )
        entry_written = skill_report.write_result(
            [entry_rule], entry_output, make_export=not args.no_export,
            kind="mappedconfig_mainrules",
        )

        skip_note = (
            "没有待映射字段（全部已映射或属排除索引，既有映射保留）——"
            if not expected
            else ""
        )
        payload = {
            "status": "success",
            "message": (
                skip_note
                + f"待映射字段 {len(expected)} 个：匹配成功 {matched}、"
                f"未匹配 {len(expected) - matched}（枚举短路 {len(auto)} 个、"
                f"占用冲突 {len(conflicts)} 组）；事件标注 {len(judgments)} 条子规则；"
                f"入口规则已生成"
            ),
            "output": str(written["json_path"]),
            "export": str(written["export_path"]) if written["export_path"] else None,
            "entry_output": str(entry_written["json_path"]),
            "entry_export": str(entry_written["export_path"]) if entry_written["export_path"] else None,
            "field_count": len(expected),
            "matched": matched,
            "unmatched": len(expected) - matched,
            "enum_short_circuited": len(auto),
            "sanitized": sanitize_report,
            "enum_overridden": overridden,
            "conflicts": conflicts,
            "events": {"annotated": len(judgments), **event_notes},
        }
    else:
        updated = apply_decisions_to_config(entities, decisions, catalog)
        base = input_path.stem
        output = (
            Path(args.output)
            if args.output
            else input_path.with_name(base + "_mapped_config.json")
        )
        written = skill_report.write_result(
            updated, output, make_export=not args.no_export,
            kind="fieldmapped_config",
        )
        skip_note = (
            "没有待映射字段（全部已映射或属排除索引，既有映射保留）——"
            if not expected
            else ""
        )
        payload = {
            "status": "success",
            "message": (
                skip_note
                + f"待映射字段 {len(expected)} 个：匹配成功 {matched}、"
                f"未匹配 {len(expected) - matched}（枚举短路 {len(auto)} 个、"
                f"占用冲突 {len(conflicts)} 组）；既有映射保留不动"
            ),
            "output": str(written["json_path"]),
            "export": str(written["export_path"]) if written["export_path"] else None,
            "field_count": len(expected),
            "matched": matched,
            "unmatched": len(expected) - matched,
            "enum_short_circuited": len(auto),
            "sanitized": sanitize_report,
            "enum_overridden": overridden,
            "conflicts": conflicts,
        }

    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
