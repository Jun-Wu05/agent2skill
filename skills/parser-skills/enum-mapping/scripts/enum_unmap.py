"""取消映射 - 置空目标字段的 normalize[].mappings（条目与字段标注保留）。

enum-mapping 技能的取消脚本：「取消/删除 X 的映射」只清值映射，
normalize 条目本身与 field 标注原样保留——与删除字段（field-adjust
的 delete，移除整个字段）语义分离，两者不可互换。

CLI 用法:
    python enum_unmap.py --input <配置文件> --fields <字段A,字段B>
                         [--output <路径>] [--no-export]

输入: 配置族文件（Base64 txt / 原生 JSON / TXT，规则数组）
输出: ``<输入名>.enumunmapped.json`` + Base64 导出
      ``enummapping_config_{时间戳}.txt`` + stdout JSON 摘要。

守卫链（任一命中整单拒绝，一行不写）:
- ``--fields`` 解析后为空名单 → ``invalid_input``；
- 目标黑名单（original_log / 日志类型 / 事件名称 / 事件级别 / 威胁类型，
  目标名直接命中或经 field 名命中黑名单条目）→
  ``reserved_field_rejected``；
- 目标在配置中无同名 index/field 条目 → ``field_not_found``
  （附「原始名(标准名)」可用字段词汇表）；
- 标准字段名歧义：目标只经 field 名命中、且对应 ≥2 个不同原始字段
  → ``field_name_ambiguous``（列出候选，请改用原始字段名）；
- 目标命中的全部条目都没有 mappings → ``mapping_not_found``
  （禁止静默成功）。

清空语义: 目标命中的全部条目（index 同名 + field 同名消歧后）一并置空
``mappings = []``；有条目本来就没有 mappings 时如实记入 skipped。
"""

from __future__ import annotations

import argparse
import copy
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

_SKILLS_ROOT = Path(__file__).resolve().parents[2]
if str(_SKILLS_ROOT) not in sys.path:
    sys.path.insert(0, str(_SKILLS_ROOT))

from _shared import report as skill_report
from _shared.config_io import ConfigIOError, load_entities
from _shared.enum_targets import field_vocab, resolve_targets
from _shared.standard_catalog import ENUM_MAPPING_EXCLUDED_INDICES

_VOCAB_HINT_LIMIT = 20


def _print_error(code: str, message: str) -> int:
    return skill_report.print_error(code, message)


def _vocab_hint(config: Any) -> str:
    vocab = field_vocab(config)
    return "、".join(vocab[:_VOCAB_HINT_LIMIT]) + (
        " 等" if len(vocab) > _VOCAB_HINT_LIMIT else ""
    )


def parse_field_list(raw: Optional[str]) -> List[str]:
    """逗号分隔字段名单 → 去空白列表；None/空串 → []（由调用方拒绝）。"""
    if not raw:
        return []
    return [item.strip() for item in raw.split(",") if item.strip()]


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="enum_unmap.py",
        description="置空目标字段的 normalize[].mappings（取消映射，条目与字段标注保留）",
    )
    parser.add_argument(
        "--input", "-i", required=True,
        help="配置文件路径（Base64 txt / 原生 JSON / TXT，内容为 JSON 数组）",
    )
    parser.add_argument(
        "--fields", required=True,
        help="目标字段名单（index 或 field 同名命中），逗号分隔",
    )
    parser.add_argument(
        "--output", "-o", default=None,
        help="修改后配置 JSON 输出路径（缺省 <输入名>.enumunmapped.json）",
    )
    parser.add_argument(
        "--no-export", action="store_true",
        help="不产出 Base64 导出文件（缺省会一并产出）",
    )
    args = parser.parse_args(argv)

    target_fields = parse_field_list(args.fields)
    if not target_fields:
        return _print_error(
            "invalid_input",
            "--fields 解析后为空名单：请提供有效目标字段，多个字段用逗号分隔",
        )

    direct_blacklist = [
        field for field in target_fields if field in ENUM_MAPPING_EXCLUDED_INDICES
    ]
    if direct_blacklist:
        return _print_error(
            "reserved_field_rejected",
            "目标字段由专属链路持有，拒绝取消映射: "
            + "、".join(direct_blacklist)
            + "（黑名单: original_log / 日志类型 / 事件名称 / 事件级别 / 威胁类型）",
        )

    try:
        config = load_entities(args.input)
    except ConfigIOError as exc:
        return _print_error(exc.code, exc.message)

    updated = copy.deepcopy(config)
    matches = resolve_targets(updated, target_fields)

    missing = [field for field in target_fields if not matches[field]]
    if missing:
        return _print_error(
            "field_not_found",
            f"未找到字段（{'、'.join(missing)}）。可用字段（原始名(标准名)）: "
            + _vocab_hint(updated),
        )

    indirect_blacklist = [
        field
        for field in target_fields
        if any(
            entry.get("index") in ENUM_MAPPING_EXCLUDED_INDICES
            for _owner, entry in matches[field]
        )
    ]
    if indirect_blacklist:
        return _print_error(
            "reserved_field_rejected",
            "目标字段命中由专属链路持有的条目，拒绝取消映射: "
            + "、".join(indirect_blacklist)
            + "（黑名单: original_log / 日志类型 / 事件名称 / 事件级别 / 威胁类型）",
        )

    # 标准字段名歧义：只经 field 名命中且对应 ≥2 个不同原始字段
    for field in target_fields:
        field_only = [
            entry
            for _owner, entry in matches[field]
            if entry.get("index") != field
        ]
        distinct_indexes = {str(entry.get("index") or "") for entry in field_only}
        if len(distinct_indexes) >= 2:
            candidates = "、".join(
                f"{entry.get('index')}({entry.get('field')})"
                for entry in field_only
            )
            return _print_error(
                "field_name_ambiguous",
                f"字段「{field}」是标准字段名，对应多个原始字段: {candidates}。"
                f"请改用其中的原始字段名",
            )

    # 禁止静默成功：目标命中的全部条目都没有 mappings → 拒绝
    for field in target_fields:
        if not any(
            entry.get("mappings") for _owner, entry in matches[field]
        ):
            return _print_error(
                "mapping_not_found",
                f"目标字段「{field}」没有可取消的映射（mappings 为空）",
            )

    field_reports = []
    total_cleared = 0
    for field in target_fields:
        cleared = skipped = 0
        for _owner, entry in matches[field]:
            if entry.get("mappings"):
                entry["mappings"] = []
                cleared += 1
            else:
                skipped += 1
        total_cleared += cleared
        field_reports.append({"field": field, "cleared": cleared, "skipped": skipped})

    message = (
        f"已取消 {total_cleared} 个条目的值映射（字段 "
        + "、".join(target_fields)
        + "）；条目与字段标注保留"
    )

    input_path = Path(args.input)
    output = (
        Path(args.output)
        if args.output
        else input_path.with_name(input_path.stem + ".enumunmapped.json")
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
    }
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
