"""枚举值提取 - 对日志数据表按目标字段做全量取值、首现序列表与计数。

enum-mapping 技能的提取脚本：宿主 agent 完成格式识别与分隔符判定后，
把结论以显式参数传入，本脚本用 ``_shared/log_extract`` 的确定性提取器
逐行取值——JSON 支持点分隔嵌套路径与 syslog 头回退；KV 支持自定义
分隔符与日志头标记剥离。值逐字保留（不去空白、不改大小写），仅完全
空白的值视为未命中。聚合结果交宿主 agent 整理映射对（归类硬约束见
guide.md），再交给填充脚本 enum_fill.py 写回。

CLI 用法:
    python enum_extract.py --input <日志数据表.xlsx> --field <字段名>
                           --format json|kv
                           [--field-delimit <字段分隔符，缺省空格>]
                           [--kv-delimit <键值分隔符，缺省 =>]
                           [--header-end-marker <日志头结束标记>]
                           [--max-values <值列表上限，缺省 100>]
                           [--output <枚举值.json>] [--template]

输入: Excel 数据表（须含「原始日志」列）
输出: 枚举值 JSON（缺省 <输入名>.enum_values.json）+ stdout JSON 摘要；
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
from _shared.log_extract import KvValueExtractor, extract_json_value, strip_header
from _shared.log_input import LogInputError, load_log_table

DEFAULT_MAX_VALUES = 100
_SAMPLE_MAX_CHARS = 300
_UNMATCHED_SAMPLE_LIMIT = 3


def _print_error(code: str, message: str) -> int:
    return skill_report.print_error(code, message)


def build_enum_values(
    raw_log_lines: List[str],
    log_format: str,
    field: str,
    field_delimit: str,
    kv_delimit: str,
    header_end_marker: str,
    max_values: int = DEFAULT_MAX_VALUES,
) -> Dict[str, Any]:
    """确定性提取主入口：逐行取值聚合，返回枚举值报告 dict。

    值列表与每值首条样本截断到 max_values（首现序）；value_counts 与
    unique_count 全量不截断。matched_lines 为 0 时仍返回报告，由 CLI
    层转 enum_extract_empty 错误。
    """
    if log_format == "json":
        extractor = extract_json_value
        lines = list(raw_log_lines)
        format_context: Dict[str, Optional[str]] = {
            "field_delimit": None,
            "kv_delimit": None,
        }
    else:
        if header_end_marker:
            lines = [
                strip_header(line, header_end_marker, is_json=False)
                for line in raw_log_lines
            ]
        else:
            lines = list(raw_log_lines)
        extractor = KvValueExtractor(field_delimit, kv_delimit).extract_value
        format_context = {"field_delimit": field_delimit, "kv_delimit": kv_delimit}

    first_seen: List[str] = []
    counts: Dict[str, int] = {}
    samples: Dict[str, str] = {}
    unmatched_samples: List[str] = []
    matched_lines = 0

    for line in lines:
        value = extractor(line, field)
        if value is None or str(value).strip() == "":
            if len(unmatched_samples) < _UNMATCHED_SAMPLE_LIMIT:
                sample = line[:_SAMPLE_MAX_CHARS].strip()
                if sample and sample not in unmatched_samples:
                    unmatched_samples.append(sample)
            continue
        matched_lines += 1
        text = str(value)
        if text not in counts:
            counts[text] = 0
            first_seen.append(text)
            samples[text] = line[:_SAMPLE_MAX_CHARS].strip()
        counts[text] += 1

    total_lines = len(raw_log_lines)
    listed = first_seen[:max_values]
    return {
        "field": field,
        "log_format": log_format,
        "format_context": format_context,
        "header_end_marker": header_end_marker if log_format == "kv" else "",
        "total_lines": total_lines,
        "matched_lines": matched_lines,
        "unmatched_lines": total_lines - matched_lines,
        "unmatched_samples": unmatched_samples,
        "unique_count": len(counts),
        "values": listed,
        "value_counts": {value: counts[value] for value in first_seen},
        "original_log": {value: samples[value] for value in listed},
        "max_values": max_values,
        "truncated": len(first_seen) > len(listed),
    }


def write_mapping_template(report: Dict[str, Any], path: Path) -> Path:
    """把枚举值报告写成映射表模板 xlsx（orgValue 与 EQUAL 预填）。"""
    from openpyxl import Workbook

    workbook = Workbook()
    sheet = workbook.active
    sheet.title = report["field"]
    sheet.append(["mappingType", "orgValue", "mappingValue"])
    for value in report["values"]:
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
        help="枚举值 JSON 输出路径（缺省 <输入名>.enum_values.json）",
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
        else input_path.with_name(input_path.stem + ".enum_values.json")
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
