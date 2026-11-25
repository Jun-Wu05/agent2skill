"""威胁分类工作单 - 圈定威胁子规则、候选字段值画像与威胁类型白名单。

threat-type 技能的开单脚本（链路第一步）：宿主 agent 先完成日志格式
识别与分隔符判定（结论以显式参数传入），本脚本产出确定性工作单——
威胁组子规则清单（事件标注自动寻址）、每条子规则的可判定字段池、
每个候选字段的全日志值画像（唯一值计数 / 首现序列表 / 首条样本 /
无语义数字代码标记）、各子规则威胁类型字段现状（三态）与威胁类型
标准枚举白名单（单一事实源＝标准字段目录）。宿主 agent 据此做来源
字段判定（按子规则、同名字段归组）与威胁分类，产出分组判定 JSON
交收口脚本 threat_finalize.py 写回。

值画像为全日志口径（per 候选字段全局提取，不区分子规则行归属）；
子规则级行归属为已知边界，记档于 references/threat_schema.md。

CLI 用法:
    python threat_worklist.py --input <配置文件> --log <日志数据表.xlsx>
                              --format json|kv
                              [--field-delimit <字段分隔符，缺省空格>]
                              [--kv-delimit <键值分隔符，缺省 =>]
                              [--header-end-marker <日志头结束标记>]
                              [--max-values <值列表上限，缺省 100>]
                              [--output <工作单.json>]

输入: 配置族文件（Base64 txt / 原生 JSON / TXT，规则数组）+
      日志数据表 Excel（须含「原始日志」列）。
输出: 工作单 JSON（缺省 <输入名>_threat_worklist.json）+ stdout JSON 摘要。

守卫链:
- 无任何事件标注的子规则 → ``event_annotation_required``；
- 有标注但无威胁组成员 → ``rule_name_not_found``；
- 标准字段目录威胁类型行缺失/非枚举/为空 →
  ``threat_mapping_reference_unavailable``。
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
from _shared.config_io import ConfigIOError, load_entities
from _shared.enum_profile import DEFAULT_MAX_VALUES, build_enum_values
from _shared.log_input import LogInputError, load_log_table
from _shared.threat_policy import (
    ThreatPolicyError,
    collect_threat_rule_names,
    inspect_threat_field_state,
    is_code_only_value,
    threat_field_pools,
    threat_whitelist,
)


def _print_error(code: str, message: str) -> int:
    return skill_report.print_error(code, message)


def build_candidate_profiles(
    raw_log_lines: List[str],
    log_format: str,
    field_delimit: str,
    kv_delimit: str,
    header_end_marker: str,
    pools: Dict[str, List[str]],
    threat_rules: List[str],
    max_values: int,
) -> List[Dict[str, Any]]:
    """按字段池并集产出每个候选字段的全日志值画像（首现序）。

    候选顺序＝威胁子规则序内字段首现序；每个画像附 present_in_rules
    （该字段出现在哪些威胁子规则的字段池中）。值提取复用
    ``_shared/enum_profile.build_enum_values``（与枚举提取同一聚合逻辑）。
    """
    present: Dict[str, List[str]] = {}
    for rule in threat_rules:
        for field in pools.get(rule, []):
            present.setdefault(field, [])
            if rule not in present[field]:
                present[field].append(rule)

    profiles: List[Dict[str, Any]] = []
    for field in present:
        report = build_enum_values(
            raw_log_lines=raw_log_lines,
            log_format=log_format,
            field=field,
            field_delimit=field_delimit,
            kv_delimit=kv_delimit,
            header_end_marker=header_end_marker,
            max_values=max_values,
        )
        listed = report["values"]
        code_only_values = [value for value in listed if is_code_only_value(value)]
        profiles.append(
            {
                "field": field,
                "present_in_rules": present[field],
                "present_rule_count": len(present[field]),
                "matched_lines": report["matched_lines"],
                "unique_count": report["unique_count"],
                "values": listed,
                "value_counts": report["value_counts"],
                "samples": report["original_log"],
                "code_only_values": code_only_values,
                "all_code_only": bool(listed)
                and len(code_only_values) == len(listed),
                "truncated": report["truncated"],
            }
        )
    return profiles


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="threat_worklist.py",
        description="圈定威胁子规则、候选字段值画像与威胁类型白名单（威胁分类工作单）",
    )
    parser.add_argument(
        "--input", "-i", required=True,
        help="配置文件路径（Base64 txt / 原生 JSON / TXT，内容为 JSON 数组）",
    )
    parser.add_argument(
        "--log", required=True,
        help="日志数据表 Excel 路径（须含「原始日志」列）",
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
        help=f"每个候选字段的值列表与样本上限（缺省 {DEFAULT_MAX_VALUES}；计数全量不截断）",
    )
    parser.add_argument(
        "--output", "-o", default=None,
        help=f"工作单 JSON 输出路径（缺省 <输入名>{skill_report.DEFAULT_OUTPUT_SUFFIXES['threat_worklist']}）",
    )
    args = parser.parse_args(argv)

    if args.max_values < 1:
        return _print_error("invalid_input", "--max-values 必须 ≥ 1")

    try:
        config = load_entities(args.input)
    except ConfigIOError as exc:
        return _print_error(exc.code, exc.message)

    try:
        threat_rules = collect_threat_rule_names(config)
    except ThreatPolicyError as exc:
        return _print_error(exc.code, exc.message)

    try:
        table = load_log_table(args.log)
    except LogInputError as exc:
        return _print_error(exc.code, exc.message)

    try:
        whitelist = list(threat_whitelist())
    except ThreatPolicyError as exc:
        return _print_error(exc.code, exc.message)

    pools = threat_field_pools(config, threat_rules)
    profiles = build_candidate_profiles(
        raw_log_lines=table["raw_log_lines"],
        log_format=args.format,
        field_delimit=args.field_delimit,
        kv_delimit=args.kv_delimit,
        header_end_marker=args.header_end_marker,
        pools=pools,
        threat_rules=threat_rules,
        max_values=args.max_values,
    )

    threat_field_states: Dict[str, str] = {}
    wanted = set(threat_rules)
    for entity in config:
        if not isinstance(entity, dict):
            continue
        name = entity.get("name")
        if name in wanted and name not in threat_field_states:
            threat_field_states[name] = inspect_threat_field_state(entity)

    input_path = Path(args.input)
    output = (
        Path(args.output)
        if args.output
        else skill_report.default_output_path(input_path, "threat_worklist")
    )
    worklist: Dict[str, Any] = {
        "input": str(input_path),
        "log_input": str(Path(args.log)),
        "log_format": args.format,
        "header_end_marker": args.header_end_marker if args.format == "kv" else "",
        "threat_rules": threat_rules,
        "rule_count": len(threat_rules),
        "threat_field_states": threat_field_states,
        "candidates": profiles,
        "whitelist": whitelist,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(worklist, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    no_value_fields = [p["field"] for p in profiles if p["matched_lines"] == 0]
    message = (
        f"威胁子规则 {len(threat_rules)} 条，候选字段 {len(profiles)} 个，"
        f"白名单 {len(whitelist)} 值"
    )
    if no_value_fields:
        message += (
            f"；{len(no_value_fields)} 个候选字段在日志中无取值"
            f"（{'、'.join(no_value_fields[:5])}"
            + (" 等" if len(no_value_fields) > 5 else "")
            + "）"
        )
    if args.format == "json" and args.header_end_marker:
        message += "；--header-end-marker 已忽略（JSON 提取自带日志头回退）"

    payload = {
        "status": "success",
        "message": message,
        "output": str(output),
        "threat_rules": threat_rules,
        "candidate_count": len(profiles),
        "whitelist_size": len(whitelist),
    }
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
