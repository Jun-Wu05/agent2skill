"""分类收口 - 校验宿主 agent 的语义归类并产出分类结果与白板子规则。

log-classification 技能的阶段②脚本（文书）：宿主 agent 读取阶段①
（feature_stats.py）产出的统计报告后，为每个特征值写业务含义标注
（labels.json），本脚本做确定性的收口——集合对齐（裁剪臆造/回填遗漏）、
真实样本回配、覆盖校验、装配分类结果 JSON（平台兼容 schema）与
白板子规则（每特征值一条无映射子规则骨架），并按平台下载命名导出
Base64 文件。

CLI 用法:
    python classify_finalize.py --input <日志数据表.xlsx> --stats <stats.json>
                                --labels <labels.json>
                                [--output <分类结果.json>]
                                [--subrules-output <子规则.json>]
                                [--no-export]

labels.json 契约（宿主 agent 语义层，logtype 必须严格等于统计报告中的
特征值）:
    {"classification_details": [{"logtype": "<特征值>", "meaning": "<业务含义>"}]}
    （也接受裸数组 [{"logtype": ..., "meaning": ...}]）

输出: 分类结果 JSON（缺省 <输入名>.classified.json）+ 白板子规则 JSON
（缺省 <输入名>.subrules.json）+ Base64 导出
（unmappedconfig_subrules_YYYYMMDD_HHMM.txt）+ stdout JSON 摘要

版本守卫（guide.md 纪律，脚本不做）：重新生成本产物前，确认下游尚未
基于旧分类产出字段映射结果——白板重建会使其失去依据。
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Callable, Dict, List, Optional

_SKILLS_ROOT = Path(__file__).resolve().parents[2]
if str(_SKILLS_ROOT) not in sys.path:
    sys.path.insert(0, str(_SKILLS_ROOT))

from _shared import report as skill_report
from _shared.log_extract import (
    KvValueExtractor,
    extract_json_body,
    extract_json_value,
    strip_header,
)
from _shared.log_input import LogInputError, load_log_table
from _shared.rule_gen import generate_sub_rules


def _print_error(code: str, message: str) -> int:
    return skill_report.print_error(code, message)


def _load_json_file(path: str, what: str):
    file_path = Path(path)
    if not file_path.is_file():
        return None, _print_error("input_required", f"找不到{what}: {file_path}")
    try:
        return json.loads(file_path.read_text(encoding="utf-8")), None
    except json.JSONDecodeError as exc:
        return None, _print_error("invalid_input", f"{what}不是合法 JSON: {exc}")


def _normalize_labels(raw) -> List[Dict[str, str]]:
    """labels 接受 {"classification_details": [...]} 或裸数组两种形态。"""
    if isinstance(raw, list):
        details = raw
    elif isinstance(raw, dict):
        details = raw.get("classification_details", [])
    else:
        raise ValueError("labels 根对象必须是数组或含 classification_details 的对象")
    if not isinstance(details, list):
        raise ValueError("classification_details 必须是数组")
    normalized = []
    for item in details:
        if not isinstance(item, dict) or not item.get("logtype"):
            raise ValueError("每个标注必须是含 logtype 的对象")
        normalized.append(
            {"logtype": str(item["logtype"]), "meaning": str(item.get("meaning", ""))}
        )
    return normalized


def sanitize_details(
    labels: List[Dict[str, str]], stats: dict,
) -> tuple:
    """集合对齐：裁剪臆造、回填遗漏。

    返回 (details, notes)：details 按统计报告的值序（计数降序）排列，
    notes = {"trimmed": [...], "backfilled": [...]} 供 agent 核对。
    """
    values: Dict[str, dict] = stats.get("values", {})
    labeled = {}
    for item in labels:
        labeled[item["logtype"]] = item["meaning"]
    trimmed = sorted(lt for lt in labeled if lt not in values)
    backfilled = sorted(val for val in values if val not in labeled)

    details = []
    for val, info in values.items():
        details.append({
            "logtype": val,
            "meaning": labeled.get(val, ""),
            "count": info.get("count", 0),
            "sample": (info.get("samples") or [""])[0],
            "real_samples": "",
        })
    return details, {"trimmed": trimmed, "backfilled": backfilled}


def _build_body_extractor(stats: dict) -> Callable[[str], object]:
    """按统计报告的格式上下文构造 (line -> (body, value)) 提取器。"""
    log_format = stats.get("log_format", "")
    feature_field = stats.get("feature_field", "")
    marker = stats.get("header_end_marker", "")
    context = stats.get("format_context") or {}

    if log_format == "json":
        def extract(line: str):
            body = extract_json_body(line) or line
            value = extract_json_value(body, feature_field)
            if value is None and body != line:
                value = extract_json_value(line, feature_field)
            return body, value
        return extract

    field_delimit = context.get("field_delimit") or " "
    kv_delimit = context.get("kv_delimit") or "="
    kv_extractor = KvValueExtractor(field_delimit, kv_delimit)

    def extract(line: str):
        body = strip_header(line, marker, is_json=False) if marker else line
        value = kv_extractor.extract_value(body, feature_field)
        if value is None and body != line:
            value = kv_extractor.extract_value(line, feature_field)
        return body, value
    return extract


def match_real_samples(details: List[dict], raw_lines: List[str], stats: dict) -> None:
    """用真实日志行回配 sample / real_samples。

    每个特征值取第一条命中行作 sample；real_samples 为日志体（JSON 取
    {...}，KV 按有效 marker 剥头，无标记取整行）。
    """
    extract = _build_body_extractor(stats)
    log_format = stats.get("log_format", "")
    marker = stats.get("header_end_marker", "")

    wanted = {d["logtype"] for d in details}
    matched: Dict[str, str] = {}
    for line in raw_lines:
        if not line.strip():
            continue
        if len(matched) >= len(wanted):
            break
        _body, value = extract(line)
        if value is not None:
            val_str = str(value)
            if val_str in wanted and val_str not in matched:
                matched[val_str] = line

    for detail in details:
        line = matched.get(detail["logtype"], "")
        detail["sample"] = line
        if not line:
            detail["real_samples"] = ""
        elif log_format == "json":
            detail["real_samples"] = strip_header(line, marker, is_json=True)
        elif marker:
            detail["real_samples"] = strip_header(line, marker, is_json=False)
        else:
            detail["real_samples"] = line


def build_classification(
    stats: dict, details: List[dict], sanitize_notes: dict,
) -> dict:
    """装配平台兼容的分类结果 JSON。"""
    log_format = stats.get("log_format", "")
    marker = stats.get("header_end_marker", "")
    context = stats.get("format_context") or {}

    if log_format == "json":
        format_name = "JSON"
        format_detail = "日志头+JSON" if marker else "纯JSON"
        analysis = {
            "has_json_structure": True,
            "has_cef_prefix": False,
            "has_key_value_pairs": False,
            "has_delimited_structure": False,
            "delimit": "",
            "tab": "",
        }
        feature_identifier = r"(\{[\S\s]*\})"
    else:
        format_name = "KV"
        format_detail = "日志头+KV" if marker else "纯KV"
        analysis = {
            "has_json_structure": False,
            "has_cef_prefix": False,
            "has_key_value_pairs": True,
            "has_delimited_structure": False,
            "delimit": context.get("field_delimit") or " ",
            "tab": context.get("kv_delimit") or "=",
        }
        feature_identifier = ""

    total = stats.get("total_lines", 0)
    matched = stats.get("matched_lines", 0)
    return {
        "status": "SUCCESS",
        "log_format": format_name,
        "log_format_detail": format_detail,
        "feature_field": stats.get("feature_field", ""),
        "feature_identifier": feature_identifier,
        "feature_count": len(details),
        "total_valid_lines": total,
        "covered_lines": matched,
        "coverage": {
            "total_lines": total,
            "matched_lines": matched,
            "unmatched_lines": stats.get("unmatched_lines", total - matched),
            "unmatched_samples": stats.get("unmatched_samples", []),
        },
        "classification_details": details,
        "analysis": analysis,
        "categorical_features": stats.get("feature_field", ""),
        "Diversion_method": "日志类型",
        "fail_reason": "",
        "feature_body_group": 0,
        "feature_value_group": 0,
        "sanitized": sanitize_notes,
    }


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="classify_finalize.py",
        description="校验语义归类并产出分类结果 + 白板子规则 + Base64 导出（阶段②：文书）",
    )
    parser.add_argument("--input", "-i", required=True, help="日志数据表 Excel 路径")
    parser.add_argument("--stats", required=True, help="阶段①统计报告 JSON 路径")
    parser.add_argument("--labels", required=True, help="宿主 agent 语义标注 JSON 路径")
    parser.add_argument(
        "--output", "-o", default=None,
        help="分类结果 JSON 输出路径（缺省 <输入名>.classified.json）",
    )
    parser.add_argument(
        "--subrules-output", default=None,
        help="白板子规则 JSON 输出路径（缺省 <输入名>.subrules.json）",
    )
    parser.add_argument(
        "--no-export", action="store_true",
        help="不产出 Base64 导出文件（缺省会一并产出）",
    )
    args = parser.parse_args(argv)

    stats, err = _load_json_file(args.stats, "统计报告")
    if err is not None:
        return err
    labels_raw, err = _load_json_file(args.labels, "标注文件")
    if err is not None:
        return err

    try:
        labels = _normalize_labels(labels_raw)
    except ValueError as exc:
        return _print_error("invalid_input", f"labels 契约不符: {exc}")

    values = stats.get("values", {})
    if not values:
        return _print_error(
            "invalid_input",
            "统计报告没有任何特征值（matched=0）：请先重跑 feature_stats 换特征字段或修正格式参数",
        )

    try:
        table = load_log_table(args.input)
    except LogInputError as exc:
        return _print_error(exc.code, exc.message)

    input_path = Path(args.input)
    output = (
        Path(args.output)
        if args.output
        else input_path.with_name(input_path.stem + ".classified.json")
    )
    subrules_output = (
        Path(args.subrules_output)
        if args.subrules_output
        else input_path.with_name(input_path.stem + ".subrules.json")
    )

    raw_lines = table["raw_log_lines"]

    # 1. 集合对齐 → 2. 真实样本回配 → 3. 装配分类结果
    details, sanitize_notes = sanitize_details(labels, stats)
    match_real_samples(details, raw_lines, stats)
    classification = build_classification(stats, details, sanitize_notes)
    classification["input"] = str(input_path)
    classification["sheet"] = table["sheet"]

    # 4. 白板子规则：行归属用特征值精确匹配
    extract_line = _build_body_extractor(stats)

    def line_matcher(logtype: str, line: str) -> bool:
        _body, value = extract_line(line)
        return value is not None and str(value) == logtype

    subrules = generate_sub_rules(
        classification, "\n".join(raw_lines), line_matcher=line_matcher
    )

    output.write_text(
        json.dumps(classification, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    written = skill_report.write_result(
        subrules, subrules_output, make_export=not args.no_export,
        kind="unmappedconfig_subrules",
    )

    payload = {
        "status": "success",
        "message": (
            f"日志类型 {classification['feature_count']} 个"
            f"（覆盖 {classification['covered_lines']}/{classification['total_valid_lines']} 行），"
            f"白板子规则 {len(subrules)} 条"
            + (f"；裁剪臆造 {len(sanitize_notes['trimmed'])} 项、回填遗漏 {len(sanitize_notes['backfilled'])} 项"
               if sanitize_notes["trimmed"] or sanitize_notes["backfilled"] else "")
        ),
        "output": str(output),
        "subrules": str(written["json_path"]),
        "export": str(written["export_path"]) if written["export_path"] else None,
    }
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
