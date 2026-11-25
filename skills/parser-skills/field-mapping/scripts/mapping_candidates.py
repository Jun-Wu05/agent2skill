"""映射候选开单 - 为待映射字段产出 Top-K 标准字段候选与值画像。

field-mapping 技能的阶段①脚本（开单）：确定性检索标准字段目录，为白板子规则
（白板路径）或解析规则配置（配置路径）中的每个待映射字段产出 Top-K 候选（附
目录元数据）、值画像与枚举字段短路标记，交宿主 agent 判断；agent 的判定产物
（mappings.json 契约见 guide.md）由阶段②（mapping_finalize.py）收口。

值画像分级：白板路径给 --excel 时用全量日志（json 规则逐行解析 JSON 体、
kv 规则逐行提取键值），未给或解析器不支持时退回白板子规则自带样本；配置
路径用
配置 normalize[].result 预览值。

CLI 用法:
    白板路径:  python mapping_candidates.py --subrules <白板_subrules.json>
                                    [--excel <日志数据表.xlsx>]
    配置路径:  python mapping_candidates.py --config <配置文件>
    通用:         [--output <候选.json>] [--top-k 10]

输入支持: --subrules / --config 均为规则 JSON 数组（Base64 txt / 原生 JSON /
TXT 自动识别）；--excel 须为含「原始日志」列的数据表。
输出: 候选 JSON（缺省 <输入名>_candidates.json）+ stdout JSON 摘要
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional

_SKILLS_ROOT = Path(__file__).resolve().parents[2]
if str(_SKILLS_ROOT) not in sys.path:
    sys.path.insert(0, str(_SKILLS_ROOT))

from _shared import report as skill_report
from _shared import standard_catalog
from _shared.candidate_retrieval import DEFAULT_TOP_K, CandidateRetriever
from _shared.config_io import ConfigIOError, load_entities
from _shared.log_extract import KvValueExtractor, extract_json_body, extract_json_value
from _shared.log_input import LogInputError, load_log_table
from _shared.mapping_apply import (  # noqa: F401  再导出供测试与下游引用
    collect_config_rules,
    collect_subrule_rules,
    mappable_indexes,
)
from _shared.rule_gen import value_to_str

#: 每个值画像保留的去重值上限（按计数降序、值字典序）。
_MAX_PROFILE_VALUES = 10

_SUPPORTED_EXCEL_PARSERS = ("json", "delimitWithKeyMap")


from _shared.report import print_error as _print_error


# ---------------------------------------------------------------------------
# 值画像
# ---------------------------------------------------------------------------


def _new_profile(owner: str, source: str) -> dict:
    return {
        "owner": owner,
        "source": source,
        "scanned_lines": 0,
        "hit_lines": 0,
        "empty_count": 0,
        "values": Counter(),
    }


def _record_hit(profile: dict, value: Any) -> None:
    text = value_to_str(value)
    profile["hit_lines"] += 1
    if text == "":
        profile["empty_count"] += 1
    else:
        profile["values"][text] += 1


def _profile_payload(profile: dict) -> dict:
    """画像 → JSON 载荷：值按计数降序、值字典序截断前 10。"""
    values = sorted(profile["values"].items(), key=lambda kv: (-kv[1], kv[0]))
    return {
        "owner": profile["owner"],
        "source": profile["source"],
        "scanned_lines": profile["scanned_lines"],
        "hit_lines": profile["hit_lines"],
        "empty_count": profile["empty_count"],
        "distinct_count": len(profile["values"]),
        "values": dict(values[:_MAX_PROFILE_VALUES]),
    }


def _flatten_json(obj: Any) -> Optional[dict]:
    """JSON 对象展平一层（parent.child），与白板子规则 normalize 索引形态对齐。"""
    if not isinstance(obj, dict):
        return None
    flat: Dict[str, Any] = {}
    for key, value in obj.items():
        if isinstance(value, dict):
            for child, child_value in value.items():
                flat[f"{key}.{child}"] = child_value
        else:
            flat[key] = value
    return flat


def build_excel_profiles(
    rules: List[dict], raw_lines: List[str]
) -> Dict[str, List[dict]]:
    """全量日志扫描画像：json 规则逐行解析 JSON 体，kv 规则逐行提取键值。

    解析器不支持的规则不产出 excel 画像（由样本画像兜底）。
    """
    parsed: List[Optional[dict]] = []
    for line in raw_lines:
        body = extract_json_body(line)
        flat = None
        if body:
            try:
                flat = _flatten_json(json.loads(body))
            except (json.JSONDecodeError, ValueError):
                flat = None
        parsed.append(flat)

    profiles: Dict[str, List[dict]] = {}
    extractors: Dict[tuple, KvValueExtractor] = {}
    for rule in rules:
        if rule.get("parser_name") not in _SUPPORTED_EXCEL_PARSERS:
            continue
        extractor = None
        if rule["parser_name"] == "delimitWithKeyMap":
            key = (rule["delimit"], rule["tab"])
            if key not in extractors:
                extractors[key] = KvValueExtractor(rule["delimit"], rule["tab"])
            extractor = extractors[key]
        for field in rule["fields"]:
            profile = _new_profile(rule["owner"], "excel")
            profile["scanned_lines"] = len(raw_lines)
            for position, line in enumerate(raw_lines):
                if rule["parser_name"] == "json":
                    flat = parsed[position]
                    if flat is not None and field in flat:
                        _record_hit(profile, flat[field])
                else:
                    value = extractor.extract_value(line, field)
                    if value is not None:
                        _record_hit(profile, value)
            profiles.setdefault(field, []).append(profile)
    return profiles


def build_sample_profiles(rules: List[dict]) -> Dict[str, List[dict]]:
    """样本画像：用白板子规则自带 sample（每规则单样本）。"""
    profiles: Dict[str, List[dict]] = {}
    for rule in rules:
        sample = rule.get("sample")
        if not sample:
            continue
        extractor = None
        if rule.get("parser_name") == "delimitWithKeyMap":
            extractor = KvValueExtractor(rule["delimit"], rule["tab"])
        for field in rule["fields"]:
            profile = _new_profile(rule["owner"], "sample")
            profile["scanned_lines"] = 1
            if extractor is not None:
                value = extractor.extract_value(sample, field)
            else:
                value = extract_json_value(sample, field)
            if value is not None:
                _record_hit(profile, value)
            profiles.setdefault(field, []).append(profile)
    return profiles


def build_config_profiles(rules: List[dict]) -> Dict[str, List[dict]]:
    """配置画像：配置路径用 normalize[].result 预览值。"""
    profiles: Dict[str, List[dict]] = {}
    for rule in rules:
        for field in rule["fields"]:
            values = rule.get("results", {}).get(field, [])
            profile = _new_profile(rule["owner"], "config_preview")
            profile["scanned_lines"] = len(values)
            for value in values:
                _record_hit(profile, value)
            profiles.setdefault(field, []).append(profile)
    return profiles


def build_b2_profiles(
    rules: List[dict], raw_lines: Optional[List[str]]
) -> Dict[str, List[dict]]:
    """白板路径值画像分级：全量日志 > 样本兜底。"""
    if raw_lines is None:
        return build_sample_profiles(rules)
    profiles = build_excel_profiles(rules, raw_lines)
    fallback_rules = [
        rule
        for rule in rules
        if rule.get("parser_name") not in _SUPPORTED_EXCEL_PARSERS
    ]
    for field, items in build_sample_profiles(fallback_rules).items():
        profiles.setdefault(field, []).extend(items)
    return profiles


# ---------------------------------------------------------------------------
# 候选文档
# ---------------------------------------------------------------------------


def build_candidates_document(
    rules: List[dict],
    profiles: Dict[str, List[dict]],
    catalog: standard_catalog.StandardFieldCatalog,
    top_k: int = DEFAULT_TOP_K,
):
    """组装候选 JSON 文档：字段保序、枚举短路标记、Top-K 候选。"""
    retriever = CandidateRetriever(catalog)
    field_order: List[str] = []
    for rule in rules:
        for field in rule["fields"]:
            if field not in field_order:
                field_order.append(field)

    fields_payload: List[dict] = []
    short_circuited = 0
    for field in field_order:
        short = standard_catalog.resolve_enum_field(field, catalog)
        candidates: List[dict] = []
        if short is None:
            candidates = [
                candidate.as_dict()
                for candidate in retriever.retrieve(field, top_k)
            ]
        else:
            short_circuited += 1
        fields_payload.append(
            {
                "field": field,
                "enum_short_circuit": (
                    {"standard": short[0], "source": short[1]} if short else None
                ),
                "value_profiles": [
                    _profile_payload(profile)
                    for profile in profiles.get(field, [])
                ],
                "candidates": candidates,
            }
        )
    return {"fields": fields_payload}, short_circuited


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="mapping_candidates.py",
        description="映射候选开单：待映射字段 → Top-K 候选 + 值画像 + 枚举短路标记（阶段①：开单）",
    )
    parser.add_argument("--subrules", default=None, help="白板子规则 JSON 路径（白板路径）")
    parser.add_argument("--config", default=None, help="配置文件路径（配置路径，Base64/JSON/TXT）")
    parser.add_argument(
        "--excel", default=None, help="日志数据表 Excel 路径（可选；给全量日志算值画像）"
    )
    parser.add_argument(
        "--output", "-o", default=None,
        help=f"候选 JSON 输出路径（缺省 <输入名>{skill_report.DEFAULT_OUTPUT_SUFFIXES['candidates']}）",
    )
    parser.add_argument(
        "--top-k", type=int, default=DEFAULT_TOP_K,
        help=f"每字段候选数上限（缺省 {DEFAULT_TOP_K}）",
    )
    args = parser.parse_args(argv)

    if bool(args.subrules) == bool(args.config):
        return _print_error(
            "invalid_input",
            "必须且只能指定 --subrules（白板路径）或 --config（配置路径）之一",
        )

    input_path = Path(args.subrules or args.config)
    try:
        entities = load_entities(input_path)
    except ConfigIOError as exc:
        return _print_error(exc.code, exc.message)

    if args.subrules:
        rules = collect_subrule_rules(entities)
        raw_lines: Optional[List[str]] = None
        if args.excel:
            try:
                table = load_log_table(args.excel)
            except LogInputError as exc:
                return _print_error(exc.code, exc.message)
            raw_lines = table["raw_log_lines"]
        profiles = build_b2_profiles(rules, raw_lines)
    else:
        rules = collect_config_rules(entities)
        profiles = build_config_profiles(rules)

    output = (
        Path(args.output)
        if args.output
        else skill_report.default_output_path(input_path, "candidates")
    )

    if not rules:
        # 全映射跳过守卫：全部已映射或属排除索引 → 成功跳过（空候选单，既有映射保留）
        output.write_text(
            json.dumps({"fields": []}, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        payload = {
            "status": "success",
            "message": "没有待映射字段：全部已映射或属于排除索引——跳过开单（既有映射保留）",
            "output": str(output),
            "field_count": 0,
            "enum_short_circuited": 0,
        }
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 0

    try:
        catalog = standard_catalog.load_catalog()
    except (FileNotFoundError, ValueError) as exc:
        return _print_error("invalid_input", f"标准字段目录加载失败: {exc}")

    document, short_circuited = build_candidates_document(
        rules, profiles, catalog, args.top_k
    )

    output.write_text(
        json.dumps(document, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )

    field_count = len(document["fields"])
    payload = {
        "status": "success",
        "message": (
            f"待映射字段 {field_count} 个（枚举短路 {short_circuited} 个），"
            f"候选已写入 {output.name}"
        ),
        "output": str(output),
        "field_count": field_count,
        "enum_short_circuited": short_circuited,
    }
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
