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
from dataclasses import dataclass
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


# 入口规则模板（parser.subResolver=0，normalize 预置 original_log 条目）
_ENTRY_RULE_TEMPLATE: Dict[str, Any] = {
    "name": "",
    "sysType": 0,
    "createtime": 0,
    "source": 0,
    "entities": ["日志"],
    "description": "",
    "normalize": [
        {
            "mappings": [],
            "field": "original_log",
            "sim": True,
            "result": [],
            "info": None,
            "entity": "日志",
            "required": False,
            "core": None,
            "value": None,
            "index": "original_log",
        }
    ],
    "lasttime": 0,
    "parser": {
        "name": "nothing",
        "resolverType": "event",
        "unmappingKeep": False,
        "deviceType": "1",
        "filter": None,
        "subResolver": 0,
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
    "subResolver": 0,
    "deleted": 0,
}


def get_entry_rule_template() -> Dict[str, Any]:
    """返回入口规则模板的深拷贝（防止调用方污染模块级常量）。"""
    return copy.deepcopy(_ENTRY_RULE_TEMPLATE)


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


def make_entry_log_type_entry() -> Dict[str, Any]:
    """入口规则的日志类型 normalize 条目（占位：result 为空，不提供样本值）。"""
    return {
        "mappings": [],
        "field": "log_type",
        "sim": True,
        "result": [],
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


# ---------------------------------------------------------------------------
# 入口规则：filter 构建器
# ---------------------------------------------------------------------------


def _make_case(value: str, rule: Dict[str, Any]) -> Dict[str, Any]:
    """conditionMatch / redirect 共享的 case 节点。"""
    return {"value": value, "rule": rule, "name": "case", "id": ""}


def make_addfields_filter() -> Dict[str, Any]:
    """additional_fields_filter 节点（入口/子规则通用基础 filter）。"""
    return {
        "fields": {
            "product": "",
            "event_name": "",
            "event_level": "",
            "log_vendor": "",
        },
        "name": "addFields",
        "id": "additional_fields_filter",
    }


def make_redirect_filter(logtypes: List[str]) -> Dict[str, Any]:
    """非 JSON 且非 KV 格式入口规则的 redirect filter（cases 覆盖所有 logtype）。"""
    cases = [
        _make_case(logtype, {"fields": ["test"], "name": "removeFields", "id": ""})
        for logtype in logtypes
    ]
    return {
        "name": "redirect",
        "field": "1",
        "id": "",
        "default": {"name": "none"},
        "cases": cases,
    }


def make_condition_match_filter(logtypes: List[str]) -> Dict[str, Any]:
    """纯 JSON / syslog+JSON 入口规则的 conditionMatch filter。

    每个 case 的 value 格式固定为 ``original_log like '{logtype}'``。
    """
    cases = [
        _make_case(
            f"original_log like '{logtype}'",
            {"fields": {"1": "1"}, "name": "addFields", "id": ""},
        )
        for logtype in logtypes
    ]
    return {"cases": cases, "default": {"name": "none"}, "name": "conditionMatch", "id": ""}


def make_logtype_mapping_filter(feature_field: str) -> Dict[str, Any]:
    """日志类型映射 addFields filter（纯 JSON / 纯 KV 入口规则通用）。

    key 恒为「日志类型」，value 格式固定为 ``%{feature_field}``。
    """
    return {
        "fields": {"日志类型": f"%{{{feature_field}}}"},
        "name": "addFields",
        "id": "",
    }


def make_kv_condition_match_filter(
    logtypes: List[str], feature_field: str
) -> Dict[str, Any]:
    """纯 KV 入口规则的 conditionMatch filter。

    每个 case 的 value 格式固定为 ``{feature_field} like '{logtype}'``。
    """
    cases = [
        _make_case(
            f"{feature_field} like '{logtype}'",
            {"fields": {"1": "1"}, "name": "addFields", "id": ""},
        )
        for logtype in logtypes
    ]
    return {"cases": cases, "default": {"name": "none"}, "name": "conditionMatch", "id": ""}


def make_syslog_kv_condition_match_filter(logtypes: List[str]) -> Dict[str, Any]:
    """syslog+KV 入口规则的 conditionMatch filter。

    每个 case 的 value 格式固定为 ``original_log like '{logtype}'``。
    """
    cases = [
        _make_case(
            f"original_log like '{logtype}'",
            {"fields": {"1": "1"}, "name": "addFields", "id": ""},
        )
        for logtype in logtypes
    ]
    return {"cases": cases, "default": {"name": "none"}, "name": "conditionMatch", "id": ""}


# ---------------------------------------------------------------------------
# 入口规则：数据源字段
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RuleSourceFields:
    """用户显式提供的规则来源信息（厂商/产品必填，数据源缺省补全）。"""

    product: str
    log_vendor: str
    data_source: str = ""

    def __post_init__(self) -> None:
        normalized_product = str(self.product or "").strip()
        normalized_vendor = str(self.log_vendor or "").strip()
        normalized_source = str(self.data_source or "").strip()
        missing = []
        if not normalized_product:
            missing.append("数据源产品")
        if not normalized_vendor:
            missing.append("数据源厂商")
        if missing:
            raise ValueError(f"请填写{'、'.join(missing)}")
        object.__setattr__(self, "product", normalized_product)
        object.__setattr__(self, "log_vendor", normalized_vendor)
        object.__setattr__(
            self,
            "data_source",
            normalized_source or f"{normalized_product}({normalized_vendor})",
        )


_SOURCE_FIELD_SPECS = (
    ("product", "数据源产品", True),
    ("log_vendor", "数据源厂商", True),
    ("data_source", "数据源", False),
)


def make_source_fields_filter(fields: RuleSourceFields) -> Dict[str, Any]:
    """追加在入口 parser.filter 末尾的数据源固定值绑定。"""
    return {
        "fields": {
            "data_source": fields.data_source,
            "log_vendor": fields.log_vendor,
            "product": fields.product,
        },
        "name": "addFields",
        "id": "",
    }


def make_source_normalize_entries(fields: RuleSourceFields) -> List[Dict[str, Any]]:
    """产品、厂商、数据源三条入口 normalize。"""
    return [
        {
            "mappings": [],
            "field": key,
            "sim": False,
            "result": [getattr(fields, key)],
            "info": None,
            "entity": "日志",
            "required": False,
            "core": core,
            "value": None,
            "index": key,
        }
        for key, _name, core in _SOURCE_FIELD_SPECS
    ]


def make_source_properties(fields: RuleSourceFields) -> List[Dict[str, Any]]:
    """入口规则展示用的三个数据源属性声明。"""
    return [
        {
            "format": None,
            "name": name,
            "sim": False,
            "info": [],
            "key": key,
            "entity": "日志",
            "sample": [getattr(fields, key)],
            "type": "object",
            "required": False,
            "core": core,
        }
        for key, name, core in _SOURCE_FIELD_SPECS
    ]


# ---------------------------------------------------------------------------
# 入口规则：生成
# ---------------------------------------------------------------------------


def _make_entry_properties(logtypes: List[str], rule_name: str) -> List[Dict[str, Any]]:
    """入口规则的 properties（日志类型 log_type + 解析规则链 rule_name_list）。"""
    return [
        {
            "format": None,
            "name": "日志类型",
            "sim": True,
            "info": [],
            "key": "log_type",
            "entity": "日志",
            "sample": logtypes,
            "type": "object",
            "required": None,
            "core": None,
        },
        {
            "format": None,
            "name": "解析规则链",
            "sim": None,
            "info": [],
            "key": "rule_name_list",
            "entity": None,
            "sample": [f"[{rule_name}]" for _ in logtypes],
            "type": "object",
            "required": None,
            "core": None,
        },
    ]


def _detect_entry_format(classification: Dict[str, Any]):
    """按分类结果判定入口规则格式分支（返回四个布尔）。"""
    log_format = (classification.get("log_format", "") or "").upper()
    format_detail = classification.get("log_format_detail", "") or ""
    is_json = "JSON" in log_format
    is_kv = "KV" in log_format
    is_syslog_json = is_json and ("日志头" in format_detail)
    is_syslog_kv = is_kv and ("日志头" in format_detail)
    is_pure_kv = is_kv and not is_syslog_kv
    return is_json, is_syslog_json, is_pure_kv, is_syslog_kv


def generate_entry_rule(
    classification: Dict[str, Any],
    rule_source_fields: Optional[RuleSourceFields] = None,
) -> Dict[str, Any]:
    """为一份分类结果生成一条入口规则（按 logtype 路由到子规则的总闸）。

    name：有数据源字段时 ``{厂商}_{产品}_通用_入口规则{MMDD}``，否则
    ``入口规则_{YYYYMMDD}``；sample 为各 logtype 样本以 ``#next#`` 连接；
    normalize 预置 original_log（result=样本列表），纯 JSON / 纯 KV 追加
    「日志类型」条目；properties 声明日志类型与解析规则链（有数据源字段
    时另加三条数据源声明）。注意：入口规则本身不含字段映射。
    """
    resolved_date = time.strftime("%Y%m%d")
    rule_name = (
        f"{rule_source_fields.log_vendor}_{rule_source_fields.product}_通用_"
        f"入口规则{resolved_date[-4:]}"
        if rule_source_fields
        else f"入口规则_{resolved_date}"
    )
    details = classification.get("classification_details", [])
    logtypes = [str(detail.get("logtype", "")) for detail in details]
    samples = [str(detail.get("sample", "")) for detail in details]

    rule = get_entry_rule_template()

    ts = now_ms()
    rule["id"] = new_uuid()
    rule["name"] = rule_name
    rule["description"] = rule_name
    rule["sample"] = "#next#".join(samples)
    rule["createtime"] = ts
    rule["lasttime"] = ts
    rule["parser"]["subResolver"] = 0

    is_json, is_syslog_json, is_pure_kv, is_syslog_kv = _detect_entry_format(
        classification
    )
    feature_field = classification.get("feature_field", "")
    analysis = classification.get("analysis", {})

    if is_json:
        if is_syslog_json:
            rule["parser"]["name"] = "orgRegex"
            rule["parser"]["value"] = r"(\{[\S\s]*\})"
            rule["parser"]["filter"] = [
                make_addfields_filter(),
                make_condition_match_filter(logtypes),
            ]
        else:
            rule["parser"]["name"] = "json"
            rule["parser"].pop("value", None)
            rule["parser"]["filter"] = [
                make_addfields_filter(),
                make_condition_match_filter(logtypes),
                make_logtype_mapping_filter(feature_field),
            ]
    elif is_pure_kv:
        rule["parser"]["name"] = "delimitWithKeyMap"
        rule["parser"]["tab"] = analysis.get("tab", "=")
        rule["parser"]["delimit"] = escape_delimit(analysis.get("delimit", " "))
        rule["parser"]["filter"] = [
            make_addfields_filter(),
            make_logtype_mapping_filter(feature_field),
            make_kv_condition_match_filter(logtypes, feature_field),
        ]
    elif is_syslog_kv:
        rule["parser"]["name"] = "orgRegex"
        rule["parser"]["value"] = classification.get("feature_identifier", "")
        rule["parser"]["filter"] = [
            make_addfields_filter(),
            make_syslog_kv_condition_match_filter(logtypes),
        ]
    else:
        rule["parser"]["name"] = "orgRegex"
        rule["parser"]["value"] = classification.get("feature_identifier", "")
        rule["parser"]["filter"] = [
            make_addfields_filter(),
            make_redirect_filter(logtypes),
        ]

    if rule_source_fields:
        rule["parser"]["filter"].append(make_source_fields_filter(rule_source_fields))

    rule["properties"] = _make_entry_properties(logtypes, rule_name)
    if rule_source_fields:
        rule["properties"].extend(make_source_properties(rule_source_fields))

    for norm in rule.get("normalize", []):
        if norm.get("index") == "original_log":
            norm["result"] = samples

    # 纯 JSON / 纯 KV 追加日志类型条目；syslog 系已在子规则侧处理
    if (is_json and not is_syslog_json) or is_pure_kv:
        rule["normalize"].append(make_entry_log_type_entry())

    if rule_source_fields:
        rule["normalize"].extend(make_source_normalize_entries(rule_source_fields))

    return rule
