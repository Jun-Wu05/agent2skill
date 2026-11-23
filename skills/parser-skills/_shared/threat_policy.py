"""威胁类型链路纯策略（threat-type 子模块的确定性底座）。

威胁链路三段共用本模块：开单脚本
``threat_worklist.py`` 产出威胁子规则清单与候选字段值画像，宿主 agent 做
来源字段判定（按子规则、同名字段归组）与威胁分类，收口脚本
``threat_finalize.py`` 做统一覆盖校验与写回。本模块只承载纯函数——不
IO、不 LLM、不读会话。

关键裁决：
- 覆盖校验失败＝整单拒绝（``threat_mapping_coverage_rejected``，四规则
  标识 + 具体值/行指明），不降级、不洗白；
- 来源字段按子规则判定、同名字段自动归组（异构字段名场景不取交集，
  覆盖校验与映射行写入均按组进行）；
- 三态写回：链路自产（威胁类型条目带 ``%{X}`` 引用绑定）→ 该子规则
  整体替换、mappings 全量重建；存量条目 / absent → orgValue 合并
  （与枚举填充共用合并语义——任何字段都可经枚举填充/取消维护值映射
  的共存约定）；
- 目标子规则＝事件标注威胁组自动寻址，不支持点名。
"""

from __future__ import annotations

import re
from typing import Any, Collection, Dict, List, Mapping, Optional, Sequence, Tuple

from _shared.entity_scope import resolve_field_scope
from _shared.enum_merge import remove_addfields_keys
from _shared.enum_table import split_regular_prefix
from _shared.standard_catalog import MAPPING_EXCLUDED_INDICES, load_catalog

#: 威胁类型的显示名（normalize index / addFields 键）。
THREAT_TYPE_FIELD = "威胁类型"
#: 威胁类型条目的标准元数据（field 列）。
THREAT_TYPE_FIELD_KEY = "threat_type"
#: 威胁类型条目的标准元数据（entity 列）。
THREAT_TYPE_ENTITY = "威胁"

#: 覆盖校验失败的稳定错误码（收口脚本整单拒绝时使用）。
THREAT_COVERAGE_ERROR_CODE = "threat_mapping_coverage_rejected"
#: 声明值全部为无语义数字代码时的稳定错误码（先于校验拒绝，不采信猜测）。
THREAT_SOURCE_CONTEXT_ERROR_CODE = "threat_mapping_source_context_required"

#: 字段池剔除项＝映射排除索引（审计锚点/链路持有字段）+ 威胁类型自身
#: （链路目标，不能同时充当来源）。
_POOL_EXCLUDED = frozenset(MAPPING_EXCLUDED_INDICES) | {THREAT_TYPE_FIELD}

# 无语义数字代码：数字 + 常见代码分隔符（输入不含任何语义证据，
# 不允许按代码表以外的直觉猜测）。
_CODE_ONLY_SEPARATORS = "-_.:/"

_DETAIL_LIMIT = 5


class ThreatPolicyError(Exception):
    """威胁链路策略失败。code 为稳定错误码，message 面向用户。"""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


# ---------------------------------------------------------------------------
# 白名单（单一事实源＝标准字段目录「威胁类型」行）
# ---------------------------------------------------------------------------


def threat_whitelist(catalog: Any = None) -> Tuple[str, ...]:
    """返回威胁类型标准枚举白名单（标准字段目录单一事实源）。

    目录中威胁类型行缺失 / 非枚举 / 枚举值为空时抛 ThreatPolicyError
    （threat_mapping_reference_unavailable 语义）。
    """
    resolved = catalog if catalog is not None else load_catalog()
    field = resolved.lookup(THREAT_TYPE_FIELD)
    if field is None:
        raise ThreatPolicyError(
            "threat_mapping_reference_unavailable",
            "标准字段目录中没有「威胁类型」行，无法校验映射结果",
        )
    if field.data_type != "枚举":
        raise ThreatPolicyError(
            "threat_mapping_reference_unavailable",
            f"标准字段目录中「威胁类型」属性类型为 {field.data_type!r}，应为「枚举」",
        )
    values = tuple(
        value.strip() for value in field.enum_values.split(",") if value.strip()
    )
    if not values:
        raise ThreatPolicyError(
            "threat_mapping_reference_unavailable",
            "标准字段目录中「威胁类型」枚举值为空，无法校验映射结果",
        )
    return values


# ---------------------------------------------------------------------------
# 威胁子规则圈定与字段池
# ---------------------------------------------------------------------------


def collect_threat_rule_names(config: Sequence[Mapping]) -> List[str]:
    """圈定威胁组子规则名（事件标注 + 绑定表确定性分组）。

    无任何事件标注 → event_annotation_required；有标注但无威胁组成员 →
    rule_name_not_found（均经 ThreatPolicyError 抛出，消息含提示）。
    """
    _targets, error = resolve_field_scope(list(config), None, "threat")
    if error is not None:
        raise ThreatPolicyError(error["code"], error["message"])
    return list(_targets or [])


def threat_field_pools(
    config: Sequence[Mapping], rule_names: Sequence[str]
) -> Dict[str, List[str]]:
    """收集每条威胁子规则的可判定字段池（normalize index，剔除元字段）。

    剔除映射排除索引（original_log / 日志类型 / 事件名称 / 事件级别）与
    威胁类型自身；返回 ``{规则名: [index, ...]}``（保序去重）；找不到的
    规则名不出现在结果里，由调用方（分组校验）兜住。
    """
    wanted = set(rule_names)
    pools: Dict[str, List[str]] = {}
    for entity in config:
        if not isinstance(entity, Mapping):
            continue
        name = str(entity.get("name") or "")
        if name not in wanted:
            continue
        indexes: List[str] = []
        for entry in entity.get("normalize") or []:
            if not isinstance(entry, Mapping):
                continue
            index = str(entry.get("index") or "")
            if index and index not in _POOL_EXCLUDED and index not in indexes:
                indexes.append(index)
        pools[name] = indexes
    return pools


def rule_sample_count(rule: Mapping) -> int:
    """按子规则既有 normalize 条目的 result 长度推导样本数（无条目回退 1）。"""
    for entry in rule.get("normalize") or []:
        result = entry.get("result") if isinstance(entry, Mapping) else None
        if isinstance(result, list) and result:
            return len(result)
    return 1


# ---------------------------------------------------------------------------
# 值判定（无语义数字代码 / 行覆盖）
# ---------------------------------------------------------------------------


def is_code_only_value(value: Any) -> bool:
    """去空白后仅由数字与常见代码分隔符组成＝无语义证据，不允许猜测。"""
    stripped = "".join(str(value).split())
    if not stripped:
        return False
    return all(char.isdigit() or char in _CODE_ONLY_SEPARATORS for char in stripped)


def _row_pattern_flags(org_value: str) -> Tuple[str, int]:
    """剥离 REGULAR 行的 (?i) 前缀，返回 (模式, flags)。"""
    prefix, body = split_regular_prefix(org_value)
    return body, re.IGNORECASE if prefix else 0


def row_covers_value(pair: Mapping, value: str) -> bool:
    """判断映射行是否覆盖该值（REGULAR 全匹配 / EQUAL 字面相等）。

    REGULAR 支持行首 ``(?i)`` 大小写不敏感标记（对齐平台运行时语义）；
    非法正则视为不命中。
    """
    org_value = str(pair.get("orgValue") or "")
    if not org_value:
        return False
    mapping_type = str(pair.get("mappingType") or "EQUAL")
    if mapping_type == "REGULAR":
        pattern, flags = _row_pattern_flags(org_value)
        try:
            return re.fullmatch(pattern, value, flags) is not None
        except re.error:
            return False
    return org_value == value


# ---------------------------------------------------------------------------
# 统一来源覆盖校验（整单拒绝，四规则 + 具体指明）
# ---------------------------------------------------------------------------


def _preview(items: Sequence[str]) -> str:
    shown = [str(item) for item in items[:_DETAIL_LIMIT]]
    text = "、".join(shown)
    if len(items) > _DETAIL_LIMIT:
        text += " 等"
    return text


def validate_threat_coverage(
    declared_values: Sequence[str],
    pairs: Sequence[Mapping],
    whitelist: Collection[str],
) -> Optional[Dict[str, str]]:
    """对声明值集做确定性覆盖校验；通过返回 None，否则返回违规详情。

    规则（整单拒绝，报错指明具体值/行）：
    - ``mapping_value_out_of_enum``：映射目标值不在标准枚举白名单内；
    - ``declared_input_uncovered``：某个声明值没有任何映射行覆盖；
    - ``declared_input_multi_matched``：某个声明值被多条映射行同时命中
      （重叠正则不依赖行序裁决，同一输入命中多条即拒绝）；
    - ``row_out_of_source``：某条映射行没有命中任何声明值（多余行）。
    """
    valid_targets = {str(target).strip() for target in whitelist}
    row_list = list(pairs)

    out_of_enum = [
        str(row.get("mappingValue") or "")
        for row in row_list
        if str(row.get("mappingValue") or "").strip() not in valid_targets
    ]
    if out_of_enum:
        return {
            "rule": "mapping_value_out_of_enum",
            "message": f"映射目标值不在威胁类型标准枚举内: {_preview(out_of_enum)}",
        }

    uncovered: List[str] = []
    multi_matched: List[str] = []
    hit_counts = [0] * len(row_list)
    for declared in declared_values:
        value = str(declared)
        matches = [
            index for index, row in enumerate(row_list) if row_covers_value(row, value)
        ]
        if not matches:
            uncovered.append(value)
        elif len(matches) > 1:
            multi_matched.append(value)
        else:
            hit_counts[matches[0]] += 1
    if uncovered:
        return {
            "rule": "declared_input_uncovered",
            "message": f"以下声明值没有任何映射行覆盖: {_preview(uncovered)}",
        }
    if multi_matched:
        return {
            "rule": "declared_input_multi_matched",
            "message": f"以下声明值被多条映射行同时命中（正则重叠）: {_preview(multi_matched)}",
        }

    idle_rows = [
        str(row.get("orgValue") or "")
        for index, row in enumerate(row_list)
        if hit_counts[index] == 0
    ]
    if idle_rows:
        return {
            "rule": "row_out_of_source",
            "message": f"以下映射行没有命中任何声明值（多余行）: {_preview(idle_rows)}",
        }
    return None


def validate_group_assignment(
    threat_rule_names: Sequence[str],
    groups: Sequence[Mapping],
    skipped_rule_names: Sequence[str],
) -> Optional[Dict[str, str]]:
    """校验分组判定对威胁子规则的覆盖（每组/跳过名单恰好划分全部威胁子规则）。

    违规（收口脚本转 invalid_input）：
    - ``rule_not_in_threat_group``：分组或跳过名单引用了非威胁子规则；
    - ``rule_assigned_twice``：子规则被分组两次、或同时分组与跳过；
    - ``rule_unassigned``：威胁子规则既未分组也未声明跳过。
    """
    threat_set = set(threat_rule_names)
    assigned: Dict[str, str] = {}
    for group in groups:
        source_field = str(group.get("source_field") or "")
        for name in group.get("rules") or []:
            name = str(name)
            if name not in threat_set:
                return {
                    "rule": "rule_not_in_threat_group",
                    "message": f"分组（来源字段 {source_field!r}）引用的 {name!r} 不是威胁组子规则",
                }
            if name in assigned:
                return {
                    "rule": "rule_assigned_twice",
                    "message": f"子规则 {name!r} 被重复分组（{assigned[name]!r} 与 {source_field!r}）",
                }
            assigned[name] = source_field
    for name in skipped_rule_names:
        name = str(name)
        if name not in threat_set:
            return {
                "rule": "rule_not_in_threat_group",
                "message": f"跳过名单中的 {name!r} 不是威胁组子规则",
            }
        if name in assigned:
            return {
                "rule": "rule_assigned_twice",
                "message": f"子规则 {name!r} 同时被分组（{assigned[name]!r}）与声明跳过",
            }
        assigned[name] = "skipped"
    unassigned = [name for name in threat_rule_names if name not in assigned]
    if unassigned:
        return {
            "rule": "rule_unassigned",
            "message": (
                "以下威胁子规则既未分组也未声明跳过，请为它们点名来源字段"
                f"或加入跳过名单: {_preview(unassigned)}"
            ),
        }
    return None


def validate_cross_group_consistency(
    group_payloads: Sequence[Mapping],
) -> Optional[Dict[str, str]]:
    """跨组同值归类一致性校验（分组判定必须来自同一次分类）。

    同一声明值出现在多个组的值集中时，各组解析出的映射值必须一致
    （``value_mapped_inconsistently``）；一致返回 None。每组内已由
    统一覆盖校验保证恰好一行命中，这里只比跨组结果。
    """
    resolved: Dict[str, Dict[str, str]] = {}
    for payload in group_payloads:
        source = str(payload.get("source_field") or "")
        pairs = payload.get("pairs") or ()
        for declared in payload.get("declared") or ():
            value = str(declared)
            for pair in pairs:
                if row_covers_value(pair, value):
                    resolved.setdefault(value, {})[source] = str(
                        pair.get("mappingValue")
                    )
                    break
    inconsistencies = [
        value
        for value, mapping in resolved.items()
        if len(mapping) > 1 and len(set(mapping.values())) > 1
    ]
    if inconsistencies:
        return {
            "rule": "value_mapped_inconsistently",
            "message": (
                "以下声明值跨组映射不一致（各组分类必须来自同一次判定，"
                f"同一值只允许一个威胁类型）: {_preview(sorted(inconsistencies))}"
            ),
        }
    return None


# ---------------------------------------------------------------------------
# 三态探测与条目构造 / 清理
# ---------------------------------------------------------------------------

THREAT_FIELD_CHAIN = "chain"
"""威胁类型条目带 %{引用} 绑定（链路自产标志）：先删后加整体替换。"""
THREAT_FIELD_EXISTING = "existing"
"""威胁类型为存量条目（上传配置历史/他方写入）：保留条目，合并映射。"""
THREAT_FIELD_ABSENT = "absent"
"""目标子规则中无威胁类型条目：正常加字段 + 绑定 + 填充。"""


def _threat_entry_matches(entry: Mapping) -> bool:
    """normalize 条目是否为威胁类型（index 或 field 同名）。"""
    return entry.get("index") == THREAT_TYPE_FIELD or entry.get("field") == THREAT_TYPE_FIELD


def inspect_threat_field_state(entity: Mapping) -> str:
    """探测单条子规则中威胁类型字段的现状（决定写回分支）。

    判定规则（确定性）：addFields 绑定过滤器含 ``威胁类型: %{...}``
    引用值 → chain（链路自产）；normalize 条目 index 或 field 命中威胁
    类型 → existing（存量）；都没有 → absent。
    """
    parser = entity.get("parser")
    if isinstance(parser, Mapping):
        for filter_item in parser.get("filter") or []:
            if (
                isinstance(filter_item, Mapping)
                and filter_item.get("name") == "addFields"
                and filter_item.get("id") == ""
                and isinstance(filter_item.get("fields"), Mapping)
            ):
                bound = filter_item["fields"].get(THREAT_TYPE_FIELD)
                if isinstance(bound, str) and bound.startswith("%{"):
                    return THREAT_FIELD_CHAIN
    for entry in entity.get("normalize") or []:
        if isinstance(entry, Mapping) and _threat_entry_matches(entry):
            return THREAT_FIELD_EXISTING
    return THREAT_FIELD_ABSENT


def make_threat_type_normalize_entry(
    source_field: str,
    pairs: Sequence[Mapping],
    sample_count: int = 1,
) -> Dict[str, Any]:
    """构建【威胁类型】normalize 条目（引用绑定 + 标准元数据 + 映射行）。

    形状对齐 field-adjust 受控链路条目（事件名称/事件级别同构）：
    ``field=threat_type / entity=威胁 / sim=true / core=false``，result
    为 ``%{来源字段}`` 引用（按样本数复制，运行时由解析器替换）。
    """
    return {
        "mappings": [dict(pair) for pair in pairs],
        "field": THREAT_TYPE_FIELD_KEY,
        "sim": True,
        "result": [f"%{{{source_field}}}"] * max(1, sample_count),
        "info": None,
        "entity": THREAT_TYPE_ENTITY,
        "required": False,
        "core": False,
        "value": None,
        "index": THREAT_TYPE_FIELD,
    }


def remove_threat_type_writings(entity: Mapping) -> Dict[str, int]:
    """清除单条子规则中威胁类型的全部 normalize 条目与 addFields 绑定。

    链路自产整体替换的前半步（原地修改）：normalize 中 index/field 命中
    威胁类型的条目全部移除；id 为空串的 addFields 过滤器里威胁类型键
    全部移除（固定值与 ``%{}`` 引用一并清，与链路自产探测的 id 守卫
    对称），清空后的 addFields 条目整体移除。
    返回 ``{"entries_removed": n, "bindings_removed": n}``。
    """
    entries_removed = 0
    normalize = entity.get("normalize")
    if isinstance(normalize, list):
        kept = []
        for entry in normalize:
            if isinstance(entry, Mapping) and _threat_entry_matches(entry):
                entries_removed += 1
            else:
                kept.append(entry)
        entity["normalize"] = kept

    bindings_removed = 0
    parser = entity.get("parser")
    if isinstance(parser, Mapping):
        filters = parser.get("filter")
        if isinstance(filters, list):
            bindings_removed = remove_addfields_keys(
                filters,
                [THREAT_TYPE_FIELD],
                keep_reference=False,
                require_empty_id=True,
            )
    return {
        "entries_removed": entries_removed,
        "bindings_removed": bindings_removed,
    }


def append_threat_type_binding(entity: Mapping, source_field: str) -> None:
    """追加 addFields 绑定 ``威胁类型: %{来源字段}``（原地修改）。

    形状对齐 field-adjust 添加字段：绑定值原样存储 ``%{index}``，运行时
    由解析器替换为来源字段的实际值。
    """
    parser = entity.get("parser")
    if not isinstance(parser, Mapping):
        parser = {}
        entity["parser"] = parser
    filters = parser.get("filter")
    if not isinstance(filters, list):
        filters = []
        parser["filter"] = filters
    filters.append(
        {
            "name": "addFields",
            "id": "",
            "fields": {THREAT_TYPE_FIELD: f"%{{{source_field}}}"},
        }
    )


def find_threat_type_entries(entity: Mapping) -> List[Mapping]:
    """返回子规则中全部威胁类型 normalize 条目（按出现顺序，原地引用）。"""
    entries = []
    for entry in entity.get("normalize") or []:
        if isinstance(entry, Mapping) and _threat_entry_matches(entry):
            entries.append(entry)
    return entries


__all__ = [
    "THREAT_COVERAGE_ERROR_CODE",
    "THREAT_FIELD_ABSENT",
    "THREAT_FIELD_CHAIN",
    "THREAT_FIELD_EXISTING",
    "THREAT_SOURCE_CONTEXT_ERROR_CODE",
    "THREAT_TYPE_ENTITY",
    "THREAT_TYPE_FIELD",
    "THREAT_TYPE_FIELD_KEY",
    "ThreatPolicyError",
    "append_threat_type_binding",
    "collect_threat_rule_names",
    "find_threat_type_entries",
    "inspect_threat_field_state",
    "is_code_only_value",
    "make_threat_type_normalize_entry",
    "remove_threat_type_writings",
    "row_covers_value",
    "rule_sample_count",
    "threat_field_pools",
    "threat_whitelist",
    "validate_cross_group_consistency",
    "validate_group_assignment",
    "validate_threat_coverage",
]
