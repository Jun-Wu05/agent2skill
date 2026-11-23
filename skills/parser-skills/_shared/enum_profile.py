"""枚举值画像：按目标字段对日志行做全量取值、首现序列表与计数。

``build_enum_values`` 原为 enum-mapping 提取脚本的聚合入口，现为枚举
族共用底座（enum-mapping 的 enum_extract 与 threat-type 的
threat_worklist 共用，禁止在技能脚本内复制聚合逻辑）。值逐字保留
（不去空白、不改大小写），仅完全空白的值视为未命中。
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from _shared.log_extract import KvValueExtractor, extract_json_value, strip_header

DEFAULT_MAX_VALUES = 100
_SAMPLE_MAX_CHARS = 300
_UNMATCHED_SAMPLE_LIMIT = 3


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
    unique_count 全量不截断。matched_lines 为 0 时仍返回报告，由调用方
    转业务错误（如 enum_extract_empty）。
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


__all__ = ["DEFAULT_MAX_VALUES", "build_enum_values"]
