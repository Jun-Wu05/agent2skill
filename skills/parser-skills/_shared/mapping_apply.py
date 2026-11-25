"""映射收口底座：字段收集、sanitize、一对一占用裁决与写回。

开单（mapping_candidates.py）与收口（mapping_finalize.py）共用本模块：
- ``mappable_indexes`` / ``collect_subrule_rules`` / ``collect_config_rules`` /
  ``collect_expected_fields``：待映射字段收集（已有映射与输入侧排除索引
  跳过，保序去重）；
- ``sanitize_decisions``：agent 判定集合对齐（裁剪候选单外的臆造字段、
  回填遗漏为未匹配）+ 守卫降级（映射目标黑名单 / 目录外自造名 / 候选外
  输出一律降级「未匹配」——占用裁决的证据链保持完整）；
- ``collect_existing_occupants`` / ``resolve_occupancy_conflicts``：一对一
  占用不变量（标准字段 ← 唯一原始字段），既有映射恒赢，新判定按
  「精确命中 → 候选相似度 → 原行序」裁决；
- ``apply_decisions_to_subrules`` / ``apply_decisions_to_config``：写回。
  子规则版对未匹配**清空**（防重新映射残留旧映射）；配置版只写 field 为
  空的条目、未匹配保持原样（既有映射保留）。
"""

from __future__ import annotations

import copy
from typing import Any, Dict, List, Mapping, MutableMapping, Optional

from .candidate_retrieval import CandidateRetriever
from .standard_catalog import (
    MAPPING_EXCLUDED_INDICES,
    MAPPING_EXCLUDED_STANDARD_FIELDS,
    StandardField,
    StandardFieldCatalog,
)

#: 判定契约中的未匹配字面量。
UNMATCHED = "未匹配"

#: parser.delimit 的语义化转义还原（与 rule_gen.escape_delimit 互逆）。
_DELIMIT_UNESCAPE = {"\\s": " ", "\\t": "\t"}


def unescape_delimit(delimit: str) -> str:
    return _DELIMIT_UNESCAPE.get(delimit, delimit)


def mappable_indexes(entity: Mapping) -> List[str]:
    """entity normalize 中参与字段映射的原始字段名（保序去重）。

    已有映射（field 非空）与输入侧排除索引跳过；已映射条目由收口阶段
    原样保留。
    """
    indexes: List[str] = []
    for entry in entity.get("normalize") or []:
        index = entry.get("index")
        if not index or not isinstance(index, str):
            continue
        if entry.get("field") not in (None, ""):
            continue
        if index in MAPPING_EXCLUDED_INDICES:
            continue
        if index not in indexes:
            indexes.append(index)
    return indexes


def collect_subrule_rules(entities: List[Mapping]) -> List[Dict[str, Any]]:
    """白板路径：白板子规则 → 规则集（owner / 字段 / 解析器 / 样本）。"""
    rules: List[Dict[str, Any]] = []
    for entity in entities or []:
        fields = mappable_indexes(entity)
        if not fields:
            continue
        parser = entity.get("parser") or {}
        rules.append(
            {
                "owner": str(entity.get("name", "") or ""),
                "fields": fields,
                "parser_name": str(parser.get("name", "") or ""),
                "tab": str(parser.get("tab", "=") or "="),
                "delimit": unescape_delimit(str(parser.get("delimit", " ") or " ")),
                "sample": entity.get("sample") or "",
            }
        )
    return rules


def collect_config_rules(entities: List[Mapping]) -> List[Dict[str, Any]]:
    """配置路径：配置 → 规则集（值画像用 normalize[].result 预览值）。"""
    rules: List[Dict[str, Any]] = []
    for entity in entities or []:
        fields = mappable_indexes(entity)
        if not fields:
            continue
        results: Dict[str, list] = {}
        for entry in entity.get("normalize") or []:
            index = entry.get("index")
            if index in fields and index not in results:
                results[index] = list(entry.get("result") or [])
        rules.append(
            {
                "owner": str(entity.get("name", "") or ""),
                "fields": fields,
                "results": results,
            }
        )
    return rules


def collect_expected_fields(rules: List[Mapping]) -> List[str]:
    """规则集 → 待映射字段全集（跨规则 first-seen 保序去重）。"""
    field_order: List[str] = []
    for rule in rules or []:
        for field in rule.get("fields", []):
            if field not in field_order:
                field_order.append(field)
    return field_order


def _canonical_entity(record: StandardField) -> str:
    """目录记录「对象」列首个对象（多值逗号分隔）。"""
    return record.objects.split(",")[0].strip()


def write_attribution(entry: MutableMapping, record: Optional[StandardField]) -> None:
    """写归属四件 field/entity/sim/core（record 为 None 时整体置空）。

    归属写回的单一事实源：子规则写回（匹配写标准元数据、未匹配清空）
    与手动调整（设置写四件、清除置空四件）共用；配置写回只在
    record 非 None 时调用（既有映射保留语义由调用方保证）。
    field 写目录字段名（英文别名，平台原生形态，与威胁/事件链路同形）；
    entity 写目录首个对象（中文）。
    """
    if record is not None:
        entry["field"] = record.field_name
        entry["entity"] = _canonical_entity(record)
        entry["sim"] = True
        entry["core"] = False
    else:
        entry["field"] = None
        entry["entity"] = None
        entry["sim"] = None
        entry["core"] = None


def _candidate_score(
    retriever: CandidateRetriever,
    field: str,
    standard_name: str,
    top_k: int,
) -> tuple:
    """查该字段候选列表中目标标准的 (分数, 是否精确层)；不在候选内返回 (0.0, False)。

    精确层判据用候选的 exact 标志（检索层显式记录），不按分数反推——词法层
    jaccard 满分的候选分数同为 1.0，按分数判会把它们误升精确层。
    """
    for candidate in retriever.retrieve(field, top_k):
        if candidate.name == standard_name:
            return candidate.score, candidate.exact
    return 0.0, False


def sanitize_decisions(
    raw_mappings: List[Any],
    expected_fields: List[str],
    catalog: StandardFieldCatalog,
    retriever: CandidateRetriever,
    top_k: int = 10,
):
    """agent 原始判定 → 合法判定表 + sanitize 报告。

    返回 ``(decisions, report)``：decisions 覆盖全部期望字段（缺失回填
    None=未匹配）；report 记 trimmed（候选单外的臆造字段）/ backfilled
    （遗漏字段）/ degraded（守卫降级明细）/ duplicates（重复判定的落选值）。
    """
    decisions: Dict[str, Optional[StandardField]] = {}
    trimmed: List[str] = []
    degraded: List[Dict[str, str]] = []
    duplicates: List[str] = []

    for item in raw_mappings or []:
        if not isinstance(item, dict):
            trimmed.append(str(item))
            continue
        field = str(item.get("field", "") or "")
        standard = str(item.get("standard", "") or "").strip()
        if field not in expected_fields:
            trimmed.append(field)
            continue
        if field in decisions:
            duplicates.append(field)
            continue
        if not standard or standard == UNMATCHED:
            decisions[field] = None
            continue
        if standard in MAPPING_EXCLUDED_STANDARD_FIELDS:
            degraded.append(
                {"field": field, "standard": standard, "reason": "映射目标黑名单"}
            )
            decisions[field] = None
            continue
        record = catalog.lookup(standard)
        if record is None:
            degraded.append(
                {"field": field, "standard": standard, "reason": "目录外名称"}
            )
            decisions[field] = None
            continue
        score, _exact = _candidate_score(retriever, field, standard, top_k)
        if score <= 0.0:
            degraded.append(
                {"field": field, "standard": standard, "reason": "候选外"}
            )
            decisions[field] = None
            continue
        decisions[field] = record

    backfilled = [field for field in expected_fields if field not in decisions]
    for field in backfilled:
        decisions[field] = None

    report = {
        "trimmed": trimmed,
        "backfilled": backfilled,
        "degraded": degraded,
        "duplicates": duplicates,
    }
    return decisions, report


def collect_existing_occupants(
    entities: List[Mapping], catalog: Optional[StandardFieldCatalog] = None
) -> Dict[str, str]:
    """收集既有映射占用的 {标准字段名: 原始字段名}（first-wins）。

    只统计 normalize 条目 field 非空者；占用键默认取 field 原文（目录外
    的外部映射名同样占用）。传入 catalog 时，能被目录解析的占用键归一为
    规范名（中英文别名互通——平台原生配置 field 列为英文别名，判定与
    写回以规范名为准），查不到的保留原文。
    """
    occupants: Dict[str, str] = {}
    for entity in entities or []:
        for entry in entity.get("normalize") or []:
            if not isinstance(entry, dict):
                continue
            field_value = str(entry.get("field") or "").strip()
            index = str(entry.get("index") or "")
            if field_value and index:
                key = field_value
                if catalog is not None:
                    record = catalog.lookup(field_value)
                    if record is not None:
                        key = record.system_property_name
                occupants.setdefault(key, index)
    return occupants


def resolve_occupancy_conflicts(
    decisions: Dict[str, Optional[StandardField]],
    expected_fields: List[str],
    existing_occupants: Mapping[str, str],
    retriever: CandidateRetriever,
    top_k: int = 10,
):
    """一对一占用裁决（原地修改 decisions），返回冲突报告列表。

    规则：既有映射恒赢（同原始字段的重新判定不算冲突）；新判定之间按
    「精确命中 → 候选相似度 → 原行序（expected_fields 顺序）」选保留行，
    败者降级未匹配。
    """
    conflicts: List[Dict[str, Any]] = []
    by_standard: Dict[str, List[str]] = {}
    for field in expected_fields:
        record = decisions.get(field)
        if record is not None:
            by_standard.setdefault(record.system_property_name, []).append(field)

    for standard, fields in by_standard.items():
        occupant = existing_occupants.get(standard)
        if occupant is not None:
            losers = [field for field in fields if field != occupant]
            if losers:
                for field in losers:
                    decisions[field] = None
                conflicts.append(
                    {
                        "standard": standard,
                        "winner": occupant,
                        "winner_source": "existing",
                        "losers": losers,
                    }
                )
            continue
        if len(fields) > 1:
            scored = []
            for position, field in enumerate(fields):
                score, exact = _candidate_score(retriever, field, standard, top_k)
                scored.append((0 if exact else 1, -score, position, field))
            scored.sort()
            winner = scored[0][3]
            losers = [field for field in fields if field != winner]
            for field in losers:
                decisions[field] = None
            conflicts.append(
                {
                    "standard": standard,
                    "winner": winner,
                    "winner_source": "candidate",
                    "losers": losers,
                }
            )
    return decisions, conflicts


def apply_decisions_to_subrules(
    sub_rules: List[Mapping],
    decisions: Mapping[str, Optional[StandardField]],
    catalog: StandardFieldCatalog,
) -> List[Dict[str, Any]]:
    """把判定写回子规则（深拷贝，不修改原数据）。

    命中判定的条目：匹配成功写 field=目录字段名（英文别名）/
    entity=目录首个对象 / sim=True / core=False；未匹配一律清空
    （防重新映射残留旧映射）。排除索引与不在判定内的条目不动。
    """
    result = copy.deepcopy(sub_rules)
    for rule in result:
        for entry in rule.get("normalize") or []:
            index = entry.get("index")
            if not index or index in MAPPING_EXCLUDED_INDICES:
                continue
            if index not in decisions:
                continue
            record = decisions[index]
            write_attribution(entry, record)
    return result


def apply_decisions_to_config(
    config: Any,
    decisions: Mapping[str, Optional[StandardField]],
    catalog: StandardFieldCatalog,
) -> Any:
    """把判定递归写回配置（深拷贝，不修改原数据）。

    只写 index 命中判定且原 field 为空的条目（既有映射保留）；未匹配与
    排除索引保持原样。
    """
    updated = copy.deepcopy(config)

    def _apply(obj: Any) -> None:
        if isinstance(obj, dict):
            normalize = obj.get("normalize")
            if isinstance(normalize, list):
                for entry in normalize:
                    if not isinstance(entry, dict):
                        continue
                    index = entry.get("index", "")
                    if not index or index in MAPPING_EXCLUDED_INDICES:
                        continue
                    if str(entry.get("field") or "").strip():
                        continue
                    record = decisions.get(index)
                    if record is not None:
                        write_attribution(entry, record)
            for value in obj.values():
                _apply(value)
        elif isinstance(obj, list):
            for item in obj:
                _apply(item)

    _apply(updated)
    return updated
