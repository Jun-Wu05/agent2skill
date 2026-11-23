"""手动映射调整 - 对已有字段归属映射的设置（改判）与清除。

field-mapping 技能的手动修正通道：自动收口之后对个别字段的归属判定
不满意时，点名「把 X 改成 Y」（--set，可重复）或「清除 X 的映射」
（--clear，逗号分隔）。只动归属四件 field/entity/sim/core，不触碰
normalize[].mappings——值映射维护（取消值映射）属枚举子模块，两者
镜像对称：清除归属保留值映射，取消值映射保留归属标注。

CLI 用法:
    python mapping_adjust.py --input <配置文件>
                             [--set <字段=标准字段名>]... [--clear <字段,...>]
                             [--target <子规则,...>] [--group all|threat|non-threat]
                             [--output <路径>] [--no-export]

输入: 配置族文件（Base64 txt / 原生 JSON / TXT，规则数组；日志分类/
      字段映射的产物同为规则数组，不做来源区分）
输出: ``<输入名>_adjusted.json`` + Base64 导出
      ``mappingadjusted_config_{时间戳}.txt`` + stdout JSON 摘要
      （sets/clears 逐目标明细，含 previous_values 旧值清单）。

作用域: 缺省全局生效（同 index/field 名的全部条目一并调整）；
--target 按子规则名收窄、--group 按事件名称分组收窄（target 优先）。

守卫链（任一命中整单拒绝，一行不写；手动输入显式失败，不降级）:
- ``--set``/``--clear`` 均未提供；set 规格不符 ``字段=标准字段名``；
  clear 解析后为空名单；同批目标重复（set 间 / clear 间 / set 与
  clear 重叠）→ ``invalid_input``；
- ``--target`` 未知名 → ``rule_name_not_found``；``--group`` 无事件
  标注 → ``event_annotation_required``（复用目标范围解析底座）；
- 目标在作用域内无同名 index/field 条目 → ``field_not_found``
  （附「原始名(标准名)」词汇表）；
- 标准字段名歧义（只经 field 名命中且对应 ≥2 个原始字段）→
  ``field_name_ambiguous``（请改用原始字段名）；
- 目标命中输入侧排除索引（original_log/日志类型/事件名称/事件级别，
  审计锚点与链路持有字段）→ ``reserved_field_rejected``；
- set 目标命中映射目标黑名单（事件名称/事件级别/日志类型/威胁类型）
  → ``invalid_input``（专属链路持有，报错指引对应链路）；
- set 目标名不在标准字段目录 → ``invalid_input``（目录外名称）；
- set 命中条目已带值映射 → ``invalid_input``（旧值映射属旧标准字段的
  枚举，改判必错配；请先取消值映射再调整归属）；
- 一对一占用不变量：set 目标标准字段已被其他原始字段占用（占用按
  原始状态评估，同批 clear 不解锁，交换场景分两步各原子跑）→
  ``mapping_target_occupied``（报错指明占用者）；
- clear 目标命中的全部条目都没有归属标注 → ``mapping_not_found``
  （禁止静默成功，防寻址写错被掩盖）。

写回: set 写归属四件（field=目录规范名 / entity=目录首个对象 /
sim=True / core=False）；clear 置空四件、条目与值映射原样保留。
幂等: set 目标已是该标准字段（四件一致）→ 成功计 unchanged；
clear 落空拒绝。威胁链路产物的归属标注允许手工清除（链路产物与
手工维护共存，随时重跑链路恢复）。
"""

from __future__ import annotations

import argparse
import copy
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Tuple

_SKILLS_ROOT = Path(__file__).resolve().parents[2]
if str(_SKILLS_ROOT) not in sys.path:
    sys.path.insert(0, str(_SKILLS_ROOT))

from _shared import report as skill_report
from _shared import standard_catalog
from _shared.config_io import ConfigIOError, load_entities
from _shared.entity_scope import entities_in_scope, resolve_field_scope
from _shared.enum_targets import field_vocab, resolve_targets
from _shared.mapping_apply import (
    collect_existing_occupants,
    write_attribution,
)
from _shared.standard_catalog import (
    MAPPING_EXCLUDED_INDICES,
    MAPPING_EXCLUDED_STANDARD_FIELDS,
    StandardField,
)

_VOCAB_HINT_LIMIT = 20

#: 映射目标黑名单字段的报错指引（专属链路持有，手动映射不得冒充）。
_BLACKLIST_HINTS = {
    "事件名称": "事件名称/事件级别由事件标注链路持有，请用字段调整的添加字段标注（自动联动写入事件级别）",
    "事件级别": "事件名称/事件级别由事件标注链路持有，请用字段调整的添加字段标注事件名称（级别自动联动）",
    "日志类型": "日志类型由日志分类链路持有（也可用字段调整的添加字段补固定值）",
    "威胁类型": "威胁类型由威胁类型链路持有（也可用字段调整的添加字段补固定值）",
}


def _print_error(code: str, message: str) -> int:
    return skill_report.print_error(code, message)


def _vocab_hint(config: Any) -> str:
    vocab = field_vocab(config)
    return "、".join(vocab[:_VOCAB_HINT_LIMIT]) + (
        " 等" if len(vocab) > _VOCAB_HINT_LIMIT else ""
    )


def parse_clear_list(raw: Optional[str]) -> List[str]:
    """逗号分隔字段名单 → 去空白列表；None/空串 → []（由调用方拒绝）。"""
    if not raw:
        return []
    return [item.strip() for item in raw.split(",") if item.strip()]


def parse_set_specs(raw_values: List[str]) -> List[Tuple[str, str]]:
    """--set 原始值列表 → (字段, 标准字段名) 列表；格式不符抛 ValueError。"""
    specs: List[Tuple[str, str]] = []
    for raw in raw_values:
        field, sep, standard = raw.partition("=")
        if not sep:
            raise ValueError(f"set 规格不符（应为 字段=标准字段名）: {raw}")
        field = field.strip()
        standard = standard.strip()
        if not field or not standard:
            raise ValueError(f"set 规格不符（字段与标准字段名均不可为空）: {raw}")
        specs.append((field, standard))
    return specs


def _entry_index(entry: Mapping) -> str:
    """条目 index 归一化（None/非串 → 空串、去空白）。"""
    return str(entry.get("index") or "").strip()


def _entry_field(entry: Mapping) -> str:
    """条目归属标注 field 归一化（None/非串 → 空串、去空白）。"""
    return str(entry.get("field") or "").strip()


def _distinct_hit_index(entries: List[dict]) -> Optional[str]:
    """目标命中条目的唯一原始字段名；多个不同原始字段返回 None。

    仅经标准字段名命中且对应多个原始字段时由歧义守卫拒绝；
    经 index 命中的目标天然只有一个原始字段名。
    """
    indexes = {_entry_index(entry) for _owner, entry in entries}
    indexes.discard("")
    if len(indexes) == 1:
        return next(iter(indexes))
    return None


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="mapping_adjust.py",
        description="手动调整已有字段归属映射（设置改判 / 清除标注，值映射不动）",
    )
    parser.add_argument(
        "--input", "-i", required=True,
        help="配置文件路径（Base64 txt / 原生 JSON / TXT，内容为 JSON 数组）",
    )
    parser.add_argument(
        "--set", dest="sets", action="append", default=[],
        metavar="字段=标准字段名",
        help="把目标字段的归属映射设置为标准字段名（可重复多次）",
    )
    parser.add_argument(
        "--clear", default=None,
        help="清除目标字段的归属映射标注（值映射保留），逗号分隔",
    )
    parser.add_argument(
        "--target", default=None,
        help="目标子规则名（按 name 精确寻址），逗号分隔；缺省全部 entity",
    )
    parser.add_argument(
        "--group", default="all", choices=["all", "threat", "non-threat"],
        help="按已标注事件名称分组寻址（threat=威胁组 / non-threat=非威胁组）；"
             "与 --target 并存时 target 优先",
    )
    parser.add_argument(
        "--output", "-o", default=None,
        help="修改后配置 JSON 输出路径（缺省 <输入名>_adjusted.json）",
    )
    parser.add_argument(
        "--no-export", action="store_true",
        help="不产出 Base64 导出文件（缺省会一并产出）",
    )
    args = parser.parse_args(argv)

    # ---- 指令解析与互斥校验 ----
    try:
        set_specs = parse_set_specs(args.sets)
    except ValueError as exc:
        return _print_error("invalid_input", str(exc))
    clear_fields = parse_clear_list(args.clear)

    if not set_specs and not clear_fields:
        return _print_error(
            "invalid_input", "请至少提供一个 --set 或 --clear 指令",
        )

    set_targets = [field for field, _standard in set_specs]
    for name, values in (("set", set_targets), ("clear", clear_fields)):
        duplicates = [value for value in set(values) if values.count(value) > 1]
        if duplicates:
            return _print_error(
                "invalid_input",
                f"同一命令内 {name} 目标重复: {'、'.join(duplicates)}；请逐条调整",
            )
    overlap = [field for field in clear_fields if field in set_targets]
    if overlap:
        return _print_error(
            "invalid_input",
            f"同一目标既设置又清除: {'、'.join(overlap)}；请明确单一意图",
        )

    # ---- 配置加载与作用域解析 ----
    try:
        entities = load_entities(args.input)
    except ConfigIOError as exc:
        return _print_error(exc.code, exc.message)

    target_names = (
        [item.strip() for item in args.target.split(",") if item.strip()]
        if args.target
        else None
    )
    targets, scope_error = resolve_field_scope(entities, target_names, args.group)
    if scope_error:
        return _print_error(scope_error["code"], scope_error["message"])

    updated = copy.deepcopy(entities)
    scoped = list(entities_in_scope(updated, targets))

    all_fields = set_targets + clear_fields
    matches = resolve_targets(scoped, all_fields)

    missing = [field for field in all_fields if not matches[field]]
    if missing:
        return _print_error(
            "field_not_found",
            f"未找到字段（{'、'.join(missing)}）。可用字段（原始名(标准名)）: "
            + _vocab_hint(scoped),
        )

    # ---- 歧义守卫（仅经 field 名命中且对应多个原始字段）----
    for field in all_fields:
        field_only = [
            entry
            for _owner, entry in matches[field]
            if _entry_index(entry) and entry.get("index") != field
        ]
        distinct_indexes = {_entry_index(entry) for entry in field_only}
        if len(distinct_indexes) >= 2:
            candidates: List[str] = []
            for entry in field_only:
                display = f"{entry.get('index')}({entry.get('field')})"
                if display not in candidates:
                    candidates.append(display)
            return _print_error(
                "field_name_ambiguous",
                f"字段「{field}」是标准字段名，对应多个原始字段: "
                + "、".join(candidates)
                + "。请改用其中的原始字段名",
            )

    # ---- set 目标唯一原始字段守卫：index 与标准字段名混命中 → 歧义拒绝 ----
    # 目标名既是某条目的原始字段名、又是其他条目的标准字段名时，命中跨多个
    # 原始字段：占用会按自身误判非冲突、写回后多个原始字段同持一个标准字段
    # ——一律拒绝，请改用唯一确定的原始字段名。
    for field, _standard_name in set_specs:
        hit_indexes = {_entry_index(entry) for _owner, entry in matches[field]}
        hit_indexes.discard("")
        if len(hit_indexes) > 1:
            return _print_error(
                "field_name_ambiguous",
                f"set 目标「{field}」命中多个不同原始字段"
                + f"（{'、'.join(sorted(hit_indexes))}）；"
                "目标名既匹配原始字段名又匹配标准字段名，请改用唯一确定的原始字段名",
            )

    # ---- 同批命中重叠守卫（按命中条目判定，非目标字符串）----
    # 双侧寻址（index 与标准字段名）可指向同一条目：字符串判重拦不住，
    # 后写会覆盖先写（如 set 写入后被 clear 置空还双双报成功）——按条目
    # 身份判重叠，命中交集非空即拒绝。
    def _hit_ids(field: str) -> set:
        return {id(entry) for _owner, entry in matches[field]}

    set_hit_ids = {field: _hit_ids(field) for field, _standard_name in set_specs}
    clear_hit_ids = {field: _hit_ids(field) for field in clear_fields}
    for i, (field_a, _standard_a) in enumerate(set_specs):
        for field_b, _standard_b in set_specs[i + 1 :]:
            if set_hit_ids[field_a] & set_hit_ids[field_b]:
                return _print_error(
                    "invalid_input",
                    f"set 目标「{field_a}」与「{field_b}」命中同一条目"
                    "（经原始字段名与标准字段名双重寻址）；请明确单一目标",
                )
        for field_c in clear_fields:
            if set_hit_ids[field_a] & clear_hit_ids[field_c]:
                return _print_error(
                    "invalid_input",
                    f"set 目标「{field_a}」与 clear 目标「{field_c}」命中同一条目"
                    "（经原始字段名与标准字段名双重寻址）；同一命令内不可既设置又清除",
                )

    # ---- 目录加载（set 需要目录解析）----
    catalog = None
    if set_specs:
        try:
            catalog = standard_catalog.load_catalog()
        except (FileNotFoundError, ValueError) as exc:
            return _print_error("invalid_input", f"标准字段目录加载失败: {exc}")

    # ---- 排除索引守卫（set 与 clear 同规：审计锚点/链路持有字段不动）----
    for field in all_fields:
        excluded_hits = {
            _entry_index(entry)
            for _owner, entry in matches[field]
            if _entry_index(entry) in MAPPING_EXCLUDED_INDICES
        }
        if excluded_hits:
            return _print_error(
                "reserved_field_rejected",
                f"目标「{field}」命中输入侧排除索引（审计锚点/链路持有字段）: "
                + "、".join(sorted(excluded_hits))
                + "；这些条目不参与字段映射，不允许手动调整",
            )

    # ---- set 守卫：黑名单 / 目录外 / 值映射在身 / 占用不变量 ----
    records: Dict[str, StandardField] = {}
    for field, standard_name in set_specs:
        if standard_name in MAPPING_EXCLUDED_STANDARD_FIELDS:
            return _print_error(
                "invalid_input",
                f"「{standard_name}」为映射目标黑名单字段："
                + _BLACKLIST_HINTS[standard_name],
            )
        record = catalog.lookup(standard_name)
        if record is None:
            return _print_error(
                "invalid_input",
                f"标准字段名「{standard_name}」不在标准字段目录内；"
                "请使用目录中的中文系统属性名称",
            )
        records[field] = record

    for field, _standard_name in set_specs:
        with_mappings = [
            entry for _owner, entry in matches[field] if entry.get("mappings")
        ]
        if with_mappings:
            return _print_error(
                "invalid_input",
                f"目标「{field}」命中的条目已带值映射（mappings）；"
                "旧值映射属旧标准字段的枚举，改判后必错配，"
                "请先取消值映射（枚举子模块的取消映射）再调整归属",
            )

    # 占用按原始状态评估（整单写回前），同批 clear 不解锁
    occupants = collect_existing_occupants(updated)
    by_standard: Dict[str, List[str]] = {}
    for field, standard_name in set_specs:
        by_standard.setdefault(standard_name, []).append(field)
    for standard_name, fields in by_standard.items():
        if len(fields) > 1:
            return _print_error(
                "mapping_target_occupied",
                f"同一命令内多个目标指向标准字段「{standard_name}」"
                + f"（{'、'.join(fields)}）；一对一占用，请逐个调整",
            )
        field = fields[0]
        occupant = occupants.get(standard_name)
        hit_index = _distinct_hit_index(matches[field])
        if occupant is not None and occupant != hit_index:
            return _print_error(
                "mapping_target_occupied",
                f"标准字段「{standard_name}」已被原始字段「{occupant}」占用；"
                "请先清除其映射标注或更换目标"
                "（占用按调整前状态评估，同一命令内的清除不会解锁）",
            )

    # ---- clear 守卫：无可清标注 → 禁止静默成功 ----
    for field in clear_fields:
        if not any(_entry_field(entry) for _owner, entry in matches[field]):
            return _print_error(
                "mapping_not_found",
                f"目标字段「{field}」没有可清除的归属映射标注"
                "（field 为空；若要取消值映射请用枚举子模块的取消映射）",
            )

    # ---- 写回（守卫全过，整单原子生效）----
    set_reports = []
    for field, standard_name in set_specs:
        record = records[field]
        changed = unchanged = 0
        previous: List[str] = []
        for _owner, entry in matches[field]:
            old_field = _entry_field(entry)
            if old_field and old_field not in previous:
                previous.append(old_field)
            old_state = (
                entry.get("field"),
                entry.get("entity"),
                entry.get("sim"),
                entry.get("core"),
            )
            write_attribution(entry, record)
            new_state = (
                entry.get("field"),
                entry.get("entity"),
                entry.get("sim"),
                entry.get("core"),
            )
            if old_state == new_state:
                unchanged += 1
            else:
                changed += 1
        set_reports.append(
            {
                "field": field,
                "standard": standard_name,
                "changed": changed,
                "unchanged": unchanged,
                "previous_values": previous,
            }
        )

    clear_reports = []
    for field in clear_fields:
        cleared = skipped = 0
        previous: List[str] = []
        for _owner, entry in matches[field]:
            old_field = _entry_field(entry)
            if old_field:
                if old_field not in previous:
                    previous.append(old_field)
                write_attribution(entry, None)
                cleared += 1
            else:
                skipped += 1
        clear_reports.append(
            {
                "field": field,
                "cleared": cleared,
                "skipped": skipped,
                "previous_values": previous,
            }
        )

    parts = []
    if set_reports:
        total_set = sum(item["changed"] + item["unchanged"] for item in set_reports)
        specs_text = "、".join(
            f"{item['field']}→{item['standard']}" for item in set_reports
        )
        parts.append(f"已设置 {total_set} 个条目的归属映射（{specs_text}）")
    if clear_reports:
        total_cleared = sum(item["cleared"] for item in clear_reports)
        parts.append(
            f"已清除 {total_cleared} 个条目的归属映射标注（"
            + "、".join(item["field"] for item in clear_reports)
            + "，值映射保留）"
        )
    message = "；".join(parts)

    input_path = Path(args.input)
    output = (
        Path(args.output)
        if args.output
        else input_path.with_name(input_path.stem + "_adjusted.json")
    )
    written = skill_report.write_result(
        updated, output, kind="mappingadjusted_config", make_export=not args.no_export
    )
    payload = {
        "status": "success",
        "message": message,
        "output": str(written["json_path"]),
        "export": str(written["export_path"]) if written["export_path"] else None,
        "sets": set_reports,
        "clears": clear_reports,
    }
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
