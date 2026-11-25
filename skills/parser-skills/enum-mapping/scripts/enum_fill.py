"""枚举填充 - 把映射对按 orgValue 合并更新写入 normalize[].mappings。

enum-mapping 技能的填充脚本：宿主 agent 整理好映射对（JSON 判定产物或
用户手工映射表 Excel）后，本脚本做确定性校验与写回。目标条目匹配
``normalize`` 中 index 或 field 同名者（全部命中条目都写）。

CLI 用法:
    python enum_fill.py --input <配置文件>
                        (--mappings <映射对.json> | --excel <映射表.xlsx>)
                        [--output <路径>] [--no-export]

输入: 配置族文件（Base64 txt / 原生 JSON / TXT，规则数组）+
      映射对二选一——
      - ``--mappings`` JSON: ``{"mappings": [{"field": <目标字段>,
        "pairs": [{"orgValue", "mappingValue", "mappingType"(可省)}]}]}``
        （裸数组视为纯 mappings）；归一规则与 Excel 入口共用
        ``_shared/enum_table.normalize_pairs``；
      - ``--excel`` 映射表（Sheet 名=目标字段、三列，经
        ``_shared/enum_table.load_enum_table`` 读取）。
输出: ``<输入名>_enumfilled.json`` + Base64 导出
      ``enummapping_config_{时间戳}.txt`` + stdout JSON 摘要。

守卫链（任一命中整单拒绝，一行不写）:
- ``--mappings`` 与 ``--excel`` 必须二选一；
- 契约不符（结构错 / 字段缺失 / 字段无有效映射对）→ ``invalid_input``；
- 任一目标字段在配置中无同名 index/field 条目 →
  ``enum_target_field_mismatch``（附可用字段提示）。
- **不做目标黑名单**（用户 2026-11-20 真实验收裁决）：任何字段都可经
  枚举填充维护值映射，包括威胁类型等链路持有字段——各链路与手工填充
  走同一套 orgValue 合并语义，可共存。

写回语义（实现收口于 ``_shared/enum_merge.py``，与 threat-type 收口
脚本共用）:
- 同 orgValue 原地更新 mappingValue / mappingType，新 orgValue 追加，
  未提及的既有映射保留（无状态幂等；删除走取消映射脚本）；
- 同 orgValue 在输入内重复 → 首现胜出，记入摘要 duplicates；
- 填充即解绑：全配置范围内删除 addFields 过滤器里目标字段的固定值绑定
  （``%{}`` 引用绑定保留，清空后的 addFields 条目整体移除）；
- 只追加 / 更新 mappings，不改写条目外层 value / field / sim 等元数据；
- 零变更 → 成功幂等提示，产物照常输出。
"""

from __future__ import annotations

import argparse
import copy
import json
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

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
from _shared.enum_table import (
    EnumTableError,
    load_enum_table,
    normalize_pairs,
)
from _shared.enum_targets import available_field_names, resolve_targets

_AVAILABLE_FIELD_HINT_LIMIT = 20


def _print_error(code: str, message: str) -> int:
    return skill_report.print_error(code, message)


# ---------------------------------------------------------------------------
# 映射对输入
# ---------------------------------------------------------------------------

def load_mapping_fields_from_json(path: str) -> Tuple[Dict[str, List[dict]], List[str]]:
    """解析 JSON 映射对文件 → (目标字段→映射对 保序, 重复字段名单)。

    契约：{"mappings": [{"field", "pairs"}]} 或裸数组；字段缺失 / 结构
    错 / 字段无有效映射对 → ValueError（调用方转 invalid_input）；
    重复字段 first-wins 记入重复名单。
    """
    file_path = Path(path)
    if not file_path.is_file():
        raise ValueError(f"找不到映射对文件: {file_path}")
    try:
        raw = json.loads(file_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"映射对文件不是合法 JSON: {exc}") from exc

    if isinstance(raw, dict):
        items = raw.get("mappings")
    else:
        items = raw
    if not isinstance(items, list):
        raise ValueError("映射对文件须为 {mappings: [...]} 对象或裸数组")

    fields: Dict[str, List[dict]] = {}
    duplicates: List[str] = []
    for item in items:
        if not isinstance(item, dict):
            raise ValueError("mappings 元素必须是对象（field / pairs）")
        field = str(item.get("field", "") or "").strip()
        if not field:
            raise ValueError("mappings 元素缺少 field（目标字段名）")
        if field in fields:
            duplicates.append(field)
            continue
        try:
            pairs = normalize_pairs(item.get("pairs"))
        except ValueError as exc:
            raise ValueError(f"字段 {field!r} 的映射对契约不符: {exc}") from exc
        if not pairs:
            raise ValueError(f"目标字段 {field!r} 没有有效映射对")
        fields[field] = pairs
    if not fields:
        raise ValueError("映射对为空：没有可用的目标字段")
    return fields, duplicates


def load_mapping_fields_from_excel(path: str) -> Tuple[Dict[str, List[dict]], List[str]]:
    """读取映射表 Excel → (目标字段→映射对 保序, 空重复名单)。"""
    table = load_enum_table(path)
    fields: Dict[str, List[dict]] = {}
    for entry in table["fields"]:
        fields[entry["field"]] = entry["pairs"]
    if not fields:
        raise ValueError("映射表为空：没有任何工作表")
    return fields, []


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="enum_fill.py",
        description="把映射对按 orgValue 合并更新写入 normalize[].mappings（枚举填充）",
    )
    parser.add_argument(
        "--input", "-i", required=True,
        help="配置文件路径（Base64 txt / 原生 JSON / TXT，内容为 JSON 数组）",
    )
    parser.add_argument(
        "--mappings", default=None,
        help="映射对 JSON 路径（agent 判定产物，与 --excel 二选一）",
    )
    parser.add_argument(
        "--excel", default=None,
        help="映射表 Excel 路径（Sheet 名=目标字段、三列，与 --mappings 二选一）",
    )
    parser.add_argument(
        "--output", "-o", default=None,
        help=f"修改后配置 JSON 输出路径（缺省 <输入名>{skill_report.DEFAULT_OUTPUT_SUFFIXES['enumfilled']}）",
    )
    parser.add_argument(
        "--no-export", action="store_true",
        help="不产出 Base64 导出文件（缺省会一并产出）",
    )
    args = parser.parse_args(argv)

    if bool(args.mappings) == bool(args.excel):
        return _print_error(
            "invalid_input", "必须且只能指定 --mappings（JSON）或 --excel（映射表）之一"
        )

    # 目标名直接命中黑名单 → 整单拒绝
    try:
        if args.mappings:
            fields, duplicate_fields = load_mapping_fields_from_json(args.mappings)
        else:
            fields, duplicate_fields = load_mapping_fields_from_excel(args.excel)
    except EnumTableError as exc:
        return _print_error(exc.code, exc.message)
    except ValueError as exc:
        return _print_error("invalid_input", str(exc))

    target_fields = list(fields)
    # 输入内同 orgValue 去重（首现胜出），重复计数并入字段摘要
    pair_duplicates: Dict[str, int] = {}
    for field in target_fields:
        fields[field], pair_duplicates[field] = dedup_pairs_first_wins(fields[field])

    try:
        config = load_entities(args.input)
    except ConfigIOError as exc:
        return _print_error(exc.code, exc.message)

    updated = copy.deepcopy(config)
    matches = resolve_targets(updated, target_fields)

    missing = [field for field in target_fields if not matches[field]]
    if missing:
        available = available_field_names(updated)
        hint = "、".join(available[:_AVAILABLE_FIELD_HINT_LIMIT]) + (
            " 等" if len(available) > _AVAILABLE_FIELD_HINT_LIMIT else ""
        )
        return _print_error(
            "enum_target_field_mismatch",
            f"映射对的目标字段（{'、'.join(missing)}）在当前配置中不存在，"
            f"请检查目标字段名与配置中的字段是否一致，或先在解析规则中补充该字段；"
            f"可用字段: {hint}",
        )

    unbound = unbind_fixed_bindings(updated, target_fields)

    field_reports = []
    total_added = total_updated = 0
    for field in target_fields:
        stats = {"added": 0, "updated": 0, "unchanged": 0}
        for _owner, entry in matches[field]:
            applied = apply_pairs_to_entry(entry, fields[field])
            for key in stats:
                stats[key] += applied[key]
        total_added += stats["added"]
        total_updated += stats["updated"]
        field_reports.append(
            {
                "field": field,
                "targets": len(matches[field]),
                "duplicates": pair_duplicates[field] + duplicate_fields.count(field),
                **stats,
            }
        )

    changes = total_added + total_updated
    if changes == 0 and unbound == 0:
        message = "枚举映射已全部存在，无变更"
    elif changes == 0:
        message = "枚举映射已全部存在，无映射变更"
    else:
        message = (
            f"写入映射对 {changes} 条（新增 {total_added}、更新 {total_updated}），"
            f"命中 {sum(report['targets'] for report in field_reports)} 个条目"
        )
    if unbound:
        message += f"；解绑固定值绑定 {unbound} 处"

    input_path = Path(args.input)
    output = (
        Path(args.output)
        if args.output
        else skill_report.default_output_path(input_path, "enumfilled")
    )
    written = skill_report.write_result(
        updated, output, kind="enummapping_config", make_export=not args.no_export
    )
    payload = {
        "status": "success",
        "message": message,
        "output": str(written["json_path"]),
        "export": str(written["export_path"]) if written["export_path"] else None,
        "fields": field_reports,
        "unbound": unbound,
    }
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
