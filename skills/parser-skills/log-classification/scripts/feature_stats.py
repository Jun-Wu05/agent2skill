"""特征统计 - 对日志数据表按分类特征字段做全量提取聚合与覆盖统计。

log-classification 技能的阶段①脚本（计数员）：宿主 agent 完成格式识别
与分类特征字段判定后，把结论以显式参数传入，本脚本做确定性的全量
统计——特征值计数、样本采集、覆盖率、未匹配样本，产出统计报告 JSON。
语义归类（每个特征值归哪个日志类型）由宿主 agent 读取报告后完成，
再交给阶段②脚本 classify_finalize.py 收口。

CLI 用法:
    python feature_stats.py --input <日志数据表.xlsx> --format json|kv
                            --feature-field <字段名>
                            [--field-delimit <字段分隔符，缺省空格>]
                            [--kv-delimit <键值分隔符，缺省 =>]
                            [--header-end-marker <日志头结束标记>]
                            [--output <统计报告.json>]

输入: Excel 数据表（须含「原始日志」列）
输出: 统计报告 JSON（缺省 <输入名>.stats.json）+ stdout JSON 摘要

数据裁决（照工作台 #259/#121 移植，全部确定性）:
- 声称 kv 分隔符零匹配且字段分隔符为空白时，对称重试另一种键值分隔符；
- 声称字段分隔符零匹配时，对候选集（声称值 + 常见符号 + 数据派生）逐个
  用特征键行覆盖率探针打分，取最高且达阈值者重试聚合；
- 日志头标记剥离后特征键行存在率骤降（<50%）时判定标记无效，回退整行。
所有裁决记入报告 adjudications 字段，宿主 agent 可核对。
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional

_SKILLS_ROOT = Path(__file__).resolve().parents[2]
if str(_SKILLS_ROOT) not in sys.path:
    sys.path.insert(0, str(_SKILLS_ROOT))

from _shared.log_extract import (
    BODY_KEY_COVERAGE_THRESHOLD,
    KvValueExtractor,
    aggregate_by_field,
    derive_separator_candidates,
    extract_json_value,
    kv_key_line_coverage,
    strip_header,
)
from _shared.log_input import LogInputError, load_log_table


def _print_error(code: str, message: str) -> int:
    print(json.dumps(
        {"status": "error", "code": code, "message": message},
        ensure_ascii=False, indent=2,
    ))
    return 1


def _strip_header_lines(
    logs_str: str, feature_field: str, marker: str, field_delimit: str, kv_delimit: str,
):
    """按 marker 剥日志头；剥离使特征键行存在率骤降时判定 marker 无效回退。

    返回 (body_logs, effective_marker, adjudication_or_None)。
    """
    lines = [line for line in logs_str.split("\n") if line.strip()]
    body_lines = [strip_header(line, marker, is_json=False) for line in lines]
    probe = KvValueExtractor(field_delimit, kv_delimit)
    before = sum(1 for line in lines if probe.extract_value(line, feature_field) is not None)
    after = sum(1 for line in body_lines if probe.extract_value(line, feature_field) is not None)
    if before > 0 and after < before * 0.5:
        return (
            logs_str,
            "",
            {
                "kind": "header_end_marker",
                "from": marker,
                "to": "",
                "reason": f"剥离后特征键行存在率 {before}->{after}，判定标记无效，回退整行",
            },
        )
    return "\n".join(body_lines), marker, None


def _kv_adjudicate(
    logs_str: str,
    feature_field: str,
    field_delimit: str,
    kv_delimit: str,
    header_end_marker: str,
):
    """KV 路径的数据裁决 + 聚合。

    返回 (aggregation, field_delimit, kv_delimit, effective_marker, adjudications)。
    """
    adjudications: List[dict] = []

    body_logs = logs_str
    effective_marker = header_end_marker
    if header_end_marker:
        body_logs, effective_marker, adjudication = _strip_header_lines(
            logs_str, feature_field, header_end_marker, field_delimit, kv_delimit
        )
        if adjudication:
            adjudications.append(adjudication)

    extractor = KvValueExtractor(field_delimit, kv_delimit)
    aggregation = aggregate_by_field(body_logs, feature_field, extractor.extract_value)
    matched = aggregation["matched_lines"]

    # 裁决一：空白字段分隔符 + 声称键值分隔符零匹配 → 对称重试另一种
    if matched == 0 and field_delimit in (" ", "space", "\t") and kv_delimit in ("=", ":"):
        alternative = ":" if kv_delimit == "=" else "="
        retry = aggregate_by_field(
            body_logs, feature_field,
            KvValueExtractor(field_delimit, alternative).extract_value,
        )
        if retry["matched_lines"] > 0:
            adjudications.append({
                "kind": "kv_delimit", "from": kv_delimit, "to": alternative,
                "reason": f"声称键值分隔符 {kv_delimit!r} 零匹配，备选 {alternative!r} 命中",
            })
            aggregation = retry
            kv_delimit = alternative
            matched = retry["matched_lines"]

    # 裁决二：仍零匹配 → 候选分隔符覆盖率探针（声称值 + 常见符号 + 数据派生）
    if matched == 0:
        candidates: List[str] = []
        for candidate in (
            field_delimit, "||", "|", ";", ",", "\t", "space",
            *derive_separator_candidates(body_logs),
        ):
            if candidate and candidate not in candidates:
                candidates.append(candidate)
        best_delimit = None
        best_coverage = 0.0
        for candidate in candidates:
            coverage = kv_key_line_coverage(body_logs, feature_field, candidate, kv_delimit)
            if coverage > best_coverage:
                best_delimit, best_coverage = candidate, coverage
        if best_delimit is not None and best_coverage >= BODY_KEY_COVERAGE_THRESHOLD:
            retry = aggregate_by_field(
                body_logs, feature_field,
                KvValueExtractor(best_delimit, kv_delimit).extract_value,
            )
            if retry["matched_lines"] > 0:
                adjudications.append({
                    "kind": "field_delimit", "from": field_delimit, "to": best_delimit,
                    "reason": f"声称字段分隔符 {field_delimit!r} 零匹配，"
                              f"探针裁决改用 {best_delimit!r}（特征键行覆盖率 {best_coverage:.0%}）",
                })
                aggregation = retry
                field_delimit = best_delimit

    return aggregation, field_delimit, kv_delimit, effective_marker, adjudications


def build_stats_report(
    logs_str: str,
    log_format: str,
    feature_field: str,
    field_delimit: str,
    kv_delimit: str,
    header_end_marker: str,
) -> dict:
    """确定性统计主入口：提取聚合 + 数据裁决，返回统计报告 dict。"""
    adjudications: List[dict] = []
    if log_format == "json":
        # JSON 提取自带 syslog 头 + {...} 回退，样本保留原始行
        aggregation = aggregate_by_field(logs_str, feature_field, extract_json_value)
        format_context = {"field_delimit": None, "kv_delimit": None}
        effective_marker = header_end_marker
    else:
        (
            aggregation, field_delimit, kv_delimit, effective_marker, adjudications,
        ) = _kv_adjudicate(
            logs_str, feature_field, field_delimit, kv_delimit, header_end_marker
        )
        format_context = {"field_delimit": field_delimit, "kv_delimit": kv_delimit}

    total = aggregation["total_lines"]
    matched = aggregation["matched_lines"]
    return {
        "log_format": log_format,
        "format_context": format_context,
        "header_end_marker": effective_marker,
        "feature_field": feature_field,
        "total_lines": total,
        "matched_lines": matched,
        "coverage": (matched / total) if total else 0.0,
        "value_count": aggregation["value_count"],
        "top_values": aggregation["top_values"],
        "values": aggregation["values"],
        "unmatched_lines": aggregation["unmatched_lines"],
        "unmatched_samples": aggregation["unmatched_samples"],
        "adjudications": adjudications,
    }


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="feature_stats.py",
        description="对日志数据表按分类特征字段做全量提取聚合与覆盖统计（阶段①：计数员）",
    )
    parser.add_argument(
        "--input", "-i", required=True,
        help="日志数据表 Excel 路径（须含「原始日志」列）",
    )
    parser.add_argument(
        "--format", required=True, choices=["json", "kv"],
        help="日志体格式（宿主 agent 识别结论）",
    )
    parser.add_argument(
        "--feature-field", required=True,
        help="分类特征字段名（JSON 支持点分隔嵌套路径，如 event.action）",
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
        "--output", "-o", default=None,
        help="统计报告 JSON 输出路径（缺省 <输入名>.stats.json）",
    )
    args = parser.parse_args(argv)

    feature_field = args.feature_field.strip()
    if not feature_field:
        return _print_error(
            "invalid_input", "--feature-field 为空：请提供分类特征字段名"
        )

    try:
        table = load_log_table(args.input)
    except LogInputError as exc:
        return _print_error(exc.code, exc.message)

    input_path = Path(args.input)
    output = (
        Path(args.output)
        if args.output
        else input_path.with_name(input_path.stem + ".stats.json")
    )

    report = build_stats_report(
        logs_str="\n".join(table["raw_log_lines"]),
        log_format=args.format,
        feature_field=feature_field,
        field_delimit=args.field_delimit,
        kv_delimit=args.kv_delimit,
        header_end_marker=args.header_end_marker,
    )
    report["input"] = str(input_path)
    report["sheet"] = table["sheet"]

    output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    payload = {
        "status": "success",
        "message": (
            f"共 {report['total_lines']} 行，命中 {report['matched_lines']} 行"
            f"（{report['coverage']:.1%}），特征值 {report['value_count']} 个"
            + (f"；数据裁决 {len(report['adjudications'])} 项" if report["adjudications"] else "")
        ),
        "output": str(output),
    }
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
