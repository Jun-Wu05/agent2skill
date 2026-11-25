"""枚举值提取 - 对日志数据表按目标字段做全量取值、首现序列表与计数。

enum-mapping 技能的提取脚本：宿主 agent 完成格式识别与分隔符判定后，
把结论以显式参数传入，本脚本用 ``_shared/log_extract`` 的确定性提取器
（聚合入口 ``_shared/enum_profile.build_enum_values``）逐行取值——JSON
支持点分隔嵌套路径与 syslog 头回退；KV 支持自定义分隔符与日志头标记
剥离。值逐字保留（不去空白、不改大小写），仅完全空白的值视为未命中。
聚合结果交宿主 agent 整理映射对（归类硬约束见 guide.md），再交给填充
脚本 enum_fill.py 写回。

CLI 用法:
    python enum_extract.py --input <日志数据表.xlsx> --field <字段名>
                           --format json|kv
                           [--field-delimit <字段分隔符，缺省空格>]
                           [--kv-delimit <键值分隔符，缺省 =>]
                           [--header-end-marker <日志头结束标记>]
                           [--max-values <值列表上限，缺省 100>]
                           [--output <枚举值.json>] [--template]

输入: Excel 数据表（须含「原始日志」列）
输出: 枚举值 JSON（缺省 <输入名>_enum_values.json）+ stdout JSON 摘要；
      ``--template`` 另产映射表模板 ``enumvalues_{时间戳}.xlsx``
      （Sheet 名=字段、三列，orgValue 与 EQUAL 预填、mappingValue 留空），
      供整理映射对后直接走填充入口。
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

_SKILLS_ROOT = Path(__file__).resolve().parents[2]
if str(_SKILLS_ROOT) not in sys.path:
    sys.path.insert(0, str(_SKILLS_ROOT))

from _shared import report as skill_report
from _shared.enum_profile import DEFAULT_MAX_VALUES, build_enum_values
from _shared.log_input import LogInputError, load_log_table


from _shared.report import print_error as _print_error


def write_mapping_template(report: Dict[str, Any], path: Path) -> Path:
    """把枚举值报告写成映射表模板 xlsx（orgValue 与 EQUAL 预填）。

    orgValue 取**全量**唯一值（value_counts 的首现序键），不受
    ``--max-values`` 截断影响——归类环节的输出集合必须与提取集合一致。
    """
    from openpyxl import Workbook

    workbook = Workbook()
    sheet = workbook.active
    sheet.title = report["field"]
    sheet.append(["mappingType", "orgValue", "mappingValue"])
    for value in report["value_counts"]:
        sheet.append(["EQUAL", value, None])
    path.parent.mkdir(parents=True, exist_ok=True)
    workbook.save(path)
    return path


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="enum_extract.py",
        description="对日志数据表按目标字段提取枚举值列表与计数（枚举提取）",
    )
    parser.add_argument(
        "--input", "-i", required=True,
        help="日志数据表 Excel 路径（须含「原始日志」列）",
    )
    parser.add_argument(
        "--field", required=True,
        help="目标字段名（JSON 支持点分隔嵌套路径，如 event.action）",
    )
    parser.add_argument(
        "--format", required=True, choices=["json", "kv"],
        help="日志体格式（宿主 agent 识别结论）",
    )
    parser.add_argument(
        "--field-delimit", default=" ",
        help="KV 字段分隔符（字段之间，如 \"||\"；缺省空格）",
    )
    parser.add_argument(
        "--kv-delimit", default="=",
        help="KV 键值分隔符（key 与 value 之间，如 \":\"；缺省 =）",
    )
    parser.add_argument(
        "--header-end-marker", default="",
        help="日志头与日志体的分隔标记（如 \"app[1]: \"；缺省不剥离）",
    )
    parser.add_argument(
        "--max-values", type=int, default=DEFAULT_MAX_VALUES,
        help=f"值列表与样本上限（缺省 {DEFAULT_MAX_VALUES}；计数全量不截断）",
    )
    parser.add_argument(
        "--output", "-o", default=None,
        help=f"枚举值 JSON 输出路径（缺省 <输入名>{skill_report.DEFAULT_OUTPUT_SUFFIXES['enum_values']}）",
    )
    parser.add_argument(
        "--template", action="store_true",
        help="另产映射表模板 xlsx（Sheet 名=字段、三列、orgValue 预填）",
    )
    args = parser.parse_args(argv)

    field = args.field.strip()
    if not field:
        return _print_error("invalid_input", "--field 为空：请提供目标字段名")
    if args.max_values < 1:
        return _print_error("invalid_input", "--max-values 必须 ≥ 1")

    try:
        table = load_log_table(args.input)
    except LogInputError as exc:
        return _print_error(exc.code, exc.message)

    input_path = Path(args.input)
    output = (
        Path(args.output)
        if args.output
        else skill_report.default_output_path(input_path, "enum_values")
    )

    report = build_enum_values(
        raw_log_lines=table["raw_log_lines"],
        log_format=args.format,
        field=field,
        field_delimit=args.field_delimit,
        kv_delimit=args.kv_delimit,
        header_end_marker=args.header_end_marker,
        max_values=args.max_values,
    )
    if report["matched_lines"] == 0:
        return _print_error(
            "enum_extract_empty",
            f"未提取到枚举值：全部 {report['total_lines']} 行均未命中字段 "
            f"{field!r}，请核对格式与分隔符判定",
        )
    report["input"] = str(input_path)
    report["sheet"] = table["sheet"]

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    payload: Dict[str, Any] = {
        "status": "success",
        "message": (
            f"共 {report['total_lines']} 行，命中 {report['matched_lines']} 行，"
            f"枚举值 {len(report['values'])} 个（唯一 {report['unique_count']} 个）"
            + (
                f"；值列表已截断至 {report['max_values']}"
                if report["truncated"]
                else ""
            )
            + (
                "；--header-end-marker 已忽略（JSON 提取自带日志头回退）"
                if args.format == "json" and args.header_end_marker
                else ""
            )
        ),
        "output": str(output),
    }

    if args.template:
        template_path = write_mapping_template(
            report, output.parent / skill_report.download_filename("enumvalues_table")
        )
        payload["template"] = str(template_path)

    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
