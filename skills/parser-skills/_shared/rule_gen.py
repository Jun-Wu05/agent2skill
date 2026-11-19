"""规则骨架与装配：子规则模板、normalize 条目构建、白板子规则生成。

纯离线实现（无外部进程、无 LLM API 依赖）。log-classification 生成
白板子规则（无字段映射）、field-mapping 后续填充映射与生成入口规则都
必须经过本模块，禁止复制。

设计取舍（记录在案，出处见 issue tracker #10）：
- KV 子规则 normalize 的行过滤默认用 logtype 子串匹配，调用方可传
  line_matcher 升级为特征值精确匹配（严格更强）；
- 精确匹配命中零行时**不回退全量行**——那会把其他类型的字段并进本
  子规则，掩盖匹配失败（normalize 只剩日志类型条目，失败可见）。
"""

from __future__ import annotations

import copy
import json
import time
import uuid
from typing import Any, Callable, Dict, List, Optional

from _shared.log_extract import extract_kv_keys

# ---------------------------------------------------------------------------
# 模板
# ---------------------------------------------------------------------------

_SUB_RULE_TEMPLATE: Dict[str, Any] = {
    "name": "",
    "sysType": 0,
    "createtime": 0,
    "source": 0,
    "entities": ["日志"],
    "description": "",
    "normalize": [],
    "lasttime": 0,
    "parser": {
        "name": "nothing",
        "resolverType": "event",
        "unmappingKeep": False,
        "deviceType": "1",
        "filter": [
            {
                "fields": {
                    "product": "",
                    "event_name": "",
                    "event_level": "",
                    "log_vendor": "",
                },
                "name": "addFields",
                "id": "additional_fields_filter",
            }
        ],
        "subResolver": 1,
    },
    "resolverType": "event",
    "deviceType": {"id": "1", "name": "设备分类", "parentId": ""},
    "simEntities": ["日志", "事件"],
    "version": "v1",
    "change": 0,
    "id": "",
    "properties": [],
    "parserV2": None,
    "sample": "",
    "subResolver": 1,
    "deleted": 0,
}


def get_sub_rule_template() -> Dict[str, Any]:
    """返回子规则模板的深拷贝（防止调用方污染模块级常量）。"""
    return copy.deepcopy(_SUB_RULE_TEMPLATE)


# ---------------------------------------------------------------------------
# 工具
# ---------------------------------------------------------------------------

def now_ms() -> int:
    return int(time.time() * 1000)


def new_uuid() -> str:
    return str(uuid.uuid4())


def value_to_str(value: Any) -> str:
    """JSON 值 → normalize result 字符串形式。

    None → ""；bool → "true"/"false"；数值 → str；str → 原值；
    dict/list → json.dumps（ensure_ascii=False, sort_keys=True）。
    """
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def escape_delimit(delimit: str) -> str:
    """转义 parser.delimit 的语义化名称（"space"→\\s、"tab"→\\t 等）。"""
    semantic = {"space": "\\s", "comma": ",", "semicolon": ";", "tab": "\\t"}
    mapped = semantic.get(delimit.lower())
    if mapped is not None:
        return mapped
    if delimit == "\\t":
        return "\\t"
    return delimit


# ---------------------------------------------------------------------------
# normalize 条目构建
# ---------------------------------------------------------------------------

def make_kv_normalize_entry(index: str, value: Any) -> Dict[str, Any]:
    """key:value normalize 条目（field/sim/entity 均为 null）。"""
    return {
        "mappings": [],
        "field": None,
        "sim": None,
        "result": [value_to_str(value)],
        "info": None,
        "entity": None,
        "required": False,
        "core": None,
        "value": None,
        "index": index,
    }


def make_original_log_entry(raw_text: str) -> Dict[str, Any]:
    """original_log normalize 条目（field/sim/entity 有特殊值）。"""
    return {
        "mappings": [],
        "field": "original_log",
        "sim": True,
        "result": [raw_text],
        "info": None,
        "entity": "日志",
        "required": False,
        "core": False,
        "value": None,
        "index": "original_log",
    }


def make_log_type_entry(logtype: str) -> Dict[str, Any]:
    """日志类型 normalize 条目（KV / syslog+JSON 子规则末尾）。"""
    return {
        "mappings": [],
        "field": "log_type",
        "sim": True,
        "result": [logtype],
        "info": None,
        "entity": "日志",
        "required": False,
        "core": False,
        "value": "",
        "index": "日志类型",
    }


def build_json_normalize_entries(
    real_samples_str: str, logtype: str = "", is_syslog_json: bool = False,
) -> List[Dict[str, Any]]:
    """解析 real_samples JSON 构建子规则 normalize 条目。

    第 1 层 key 按字母序展开（dict 值展开 1 层 parent.child），
    original_log 按字母序自然归位；is_syslog_json 追加日志类型条目。
    real_samples 非合法 JSON 时抛 json.JSONDecodeError（失败关闭）。
    """
    data: Dict[str, Any] = json.loads(real_samples_str)
    entries: List[Dict[str, Any]] = []
    for key in sorted(data.keys()):
        value = data[key]
        if isinstance(value, dict):
            entries.append(make_kv_normalize_entry(key, value))
            for child_key in sorted(value.keys()):
                entries.append(make_kv_normalize_entry(f"{key}.{child_key}", value[child_key]))
        else:
            entries.append(make_kv_normalize_entry(key, value))
    entries.append(make_original_log_entry(real_samples_str))
    entries.sort(key=lambda e: e["index"])
    if is_syslog_json:
        entries.append(make_log_type_entry(logtype))
    return entries


def build_kv_normalize_entries_from_lines(
    lines: List[str], logtype: str, delimit: str = " ", tab: str = "=",
) -> List[Dict[str, Any]]:
    """从属于该日志类型的日志行聚合字段名构建 normalize 条目。

    字段名按字母序排列、result 为空数组；末尾追加日志类型条目。
    """
    keys = extract_kv_keys("\n".join(lines), delimit, tab=tab)
    entries = [make_kv_normalize_entry(key, None) for key in keys]
    entries.sort(key=lambda e: e["index"])
    entries.append(make_log_type_entry(logtype))
    return entries


# ---------------------------------------------------------------------------
# 子规则生成
# ---------------------------------------------------------------------------

def _build_sub_rule_name(
    logtype: str,
    diversion_method: str,
    is_json: bool,
    is_kv: bool,
    feature_field: str,
) -> str:
    if is_json:
        return f"{logtype}_{feature_field}_json_子规则"
    if is_kv:
        return f"{logtype}_kv_子规则"
    return f"{logtype}_{diversion_method}_子规则"


def _resolve_sub_parser_name(analysis: Dict[str, Any]) -> str:
    if analysis.get("has_key_value_pairs"):
        return "delimitWithKeyMap"
    if analysis.get("has_delimited_structure"):
        return "delimit"
    return "orgRegex"


def _apply_sub_parser_config(
    rule: Dict[str, Any], parser_name: str, analysis: Dict[str, Any],
) -> None:
    if parser_name == "json":
        pass
    elif parser_name == "delimitWithKeyMap":
        rule["parser"]["tab"] = analysis.get("tab", ":")
        rule["parser"]["delimit"] = escape_delimit(analysis.get("delimit", ";"))
    elif parser_name == "delimit":
        rule["parser"]["delimit"] = analysis.get("delimit", "")
        rule["parser"]["fields"] = []


def generate_sub_rule(
    detail: Dict[str, Any],
    diversion_method: str,
    analysis: Dict[str, Any],
    all_logs_str: str = "",
    *,
    is_json: bool = False,
    is_syslog_json: bool = False,
    is_kv: bool = False,
    feature_field: str = "",
    line_matcher: Optional[Callable[[str, str], bool]] = None,
) -> Dict[str, Any]:
    """为单条 classification_detail 生成一条白板子规则。

    line_matcher(logtype, line) -> bool：判定日志行归属（特征值精确
    匹配）；缺省时用 logtype 子串匹配。
    """
    logtype = detail.get("logtype", "")
    rule_name = _build_sub_rule_name(
        logtype, diversion_method, is_json, is_kv, feature_field
    )
    sample = detail.get("real_samples") or detail.get("sample", "")

    parser_name = "json" if is_json else _resolve_sub_parser_name(analysis)
    rule = get_sub_rule_template()

    ts = now_ms()
    rule["id"] = new_uuid()
    rule["name"] = rule_name
    rule["description"] = rule_name
    rule["sample"] = sample
    rule["createtime"] = ts
    rule["lasttime"] = ts
    rule["subResolver"] = 1
    rule["parser"]["name"] = parser_name
    rule["parser"]["subResolver"] = 1
    _apply_sub_parser_config(rule, parser_name, analysis)

    # syslog+JSON / KV 子规则追加日志类型 addFields
    if is_syslog_json or is_kv:
        rule["parser"]["filter"].append({
            "fields": {"日志类型": logtype},
            "name": "addFields",
            "id": "",
        })

    if is_json:
        rule["normalize"] = build_json_normalize_entries(
            real_samples_str=sample, logtype=logtype, is_syslog_json=is_syslog_json,
        )
    elif is_kv and all_logs_str:
        lines = [line for line in all_logs_str.split("\n") if line.strip()]
        if line_matcher is not None:
            # 精确匹配：命中零行不回退全量（失败可见，normalize 只剩日志类型）
            filtered = [line for line in lines if line_matcher(logtype, line)]
        else:
            filtered = [line for line in lines if logtype in line] or lines
        rule["normalize"] = build_kv_normalize_entries_from_lines(
            filtered, logtype,
            delimit=analysis.get("delimit", " "),
            tab=analysis.get("tab", "="),
        )
    else:
        rule["normalize"] = []

    rule["properties"] = []
    return rule


def generate_sub_rules(
    classification: Dict[str, Any],
    all_logs_str: str = "",
    line_matcher: Optional[Callable[[str, str], bool]] = None,
) -> List[Dict[str, Any]]:
    """遍历 classification_details 生成白板子规则列表。"""
    diversion_method = classification.get("Diversion_method", "")
    analysis = classification.get("analysis", {})
    details = classification.get("classification_details", [])

    log_format = (classification.get("log_format", "") or "").upper()
    is_json = "JSON" in log_format
    is_kv = "KV" in log_format
    format_detail = classification.get("log_format_detail", "") or ""
    is_syslog_json = is_json and ("日志头" in format_detail)
    feature_field = classification.get("feature_field", "")

    return [
        generate_sub_rule(
            detail,
            diversion_method,
            analysis,
            all_logs_str,
            is_json=is_json,
            is_syslog_json=is_syslog_json,
            is_kv=is_kv,
            feature_field=feature_field,
            line_matcher=line_matcher,
        )
        for detail in details
    ]
