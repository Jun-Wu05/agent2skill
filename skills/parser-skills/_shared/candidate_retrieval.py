"""标准字段候选检索：纯词法打分产出 Top-K 附元数据候选（零网络、零第三方依赖）。

召回与排序（全部确定性）：
1. 精确层——目录查找索引（规范化名/紧凑名/中文系统属性名/中文别名），命中
   置顶 sim=1.0；嵌套字段名（含 ``.``）另走去前缀变体精确匹配；
2. 查询侧中文别名桥接——查询串恰好是同义词表某键的中文别名时（如「源IP」
   是 ``src_ip`` 键的别名），把该键并入查询信号（展开 token / 中文别名 /
   标签 / 精确查找），弥补中文查询进不了英文展开链的缺口；
3. 词法层——查询端（英文缩写展开 + 中文别名 + 标签）与索引端（展开英文名 +
   标签 + 系统属性名内的中文别名 + 描述关键词）求 Jaccard 重叠；
4. 字符层——紧凑名与中文系统属性名的字符相似度，作为词法零重叠时的兜底。

排序键：精确层优先 → 英文 token 重叠数降序 → Jaccard 降序 → 字符相似降序 →
名称字典序；字符相似只作兜底排序信号，不与 Jaccard 混比（避免短字段靠前缀
相似压过语义正确项）。低于阈值（0.15）的词法/字符候选丢弃。映射目标黑名单
字段在候选阶段即被排除，任何层都不出现。
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from difflib import SequenceMatcher
from typing import Mapping, Sequence

from .standard_catalog import (
    MAPPING_EXCLUDED_STANDARD_FIELDS,
    StandardField,
    StandardFieldCatalog,
    compact_field_name,
    normalize_field_name,
)

#: 词法/字符候选的相似度下限，低于该值的候选丢弃（低于精确层的兜底信号）。
LEXICAL_SIMILARITY_THRESHOLD = 0.15

#: 默认候选数上限。
DEFAULT_TOP_K = 10

#: 描述参与关键词提取的截断长度。
_MAX_DESCRIPTION_LENGTH = 200

_ASCII_WORD_RE = re.compile(r"[a-zA-Z][a-zA-Z0-9_]*")
_CJK_RANGE = ("\u4e00", "\u9fff")


@dataclass(frozen=True, slots=True)
class Candidate:
    """一条标准字段候选（附目录元数据）。"""

    name: str
    score: float
    field_name: str
    by_stripped: str
    object: str
    data_type: str
    description: str
    enum_whitelist: tuple[str, ...]

    def as_dict(self) -> dict:
        """转为 JSON 友好的字典（枚举白名单转 list）。"""
        return {
            "name": self.name,
            "score": self.score,
            "field_name": self.field_name,
            "by_stripped": self.by_stripped,
            "object": self.object,
            "type": self.data_type,
            "description": self.description,
            "enum_whitelist": list(self.enum_whitelist),
        }


def split_field_tokens(field_name: str) -> list[str]:
    """把 camelCase / kebab / snake 书写的字段名拆为小写 token 列表。"""
    name = field_name.replace("-", "_")
    name = re.sub(r"([a-z])([A-Z])", r"\1_\2", name)
    name = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", name)
    return [token for token in name.split("_") if token]


def expand_field_name(field_name: str, synonyms: Mapping[str, Mapping]) -> str:
    """按同义词表把缩写 token 展开为全称（token 级查 en，整名复合 key 回退）。"""
    tokens = split_field_tokens(field_name)
    expanded = []
    for token in tokens:
        entry = synonyms.get(token.lower())
        expanded.append(entry.get("en") or token if entry else token)
    full_entry = synonyms.get("_".join(tokens).lower())
    if full_entry and full_entry.get("en"):
        expanded.append(full_entry["en"])
    return " ".join(expanded)


def generate_field_tags(
    field_name: str, tag_rules: Mapping[str, Sequence[str]]
) -> list[str]:
    """token 级匹配标签关键词集合（任一 token 命中即打标，防子串误伤）。"""
    if not tag_rules:
        return []
    tokens = set(token.lower() for token in split_field_tokens(field_name))
    tags: set[str] = set()
    for tag, keywords in tag_rules.items():
        if tokens & set(keywords):
            tags.add(tag)
    return sorted(tags)


def collect_zh_synonyms(field_name: str, synonyms: Mapping[str, Mapping]) -> list[str]:
    """收集各 token 与整名复合 key 对应的中文别名（去重保序）。"""
    tokens = split_field_tokens(field_name)
    zh_list: list[str] = []
    seen: set[str] = set()

    def _add(entry: Mapping) -> None:
        for zh in entry.get("zh", ()):
            if zh and zh not in seen:
                zh_list.append(str(zh))
                seen.add(zh)

    for token in tokens:
        entry = synonyms.get(token.lower())
        if entry:
            _add(entry)
    full_entry = synonyms.get("_".join(tokens).lower())
    if full_entry:
        _add(full_entry)
    return zh_list


def strip_field_prefix(name: str) -> list[str]:
    """为嵌套字段名（含 ``.``）生成去前缀变体（去一层、至多两层，不含原名）。"""
    parts = name.split(".")
    if len(parts) <= 1:
        return []
    variants = [".".join(parts[1:])]
    if len(parts) > 2:
        variants.append(".".join(parts[2:]))
    return variants


def _is_cjk(char: str) -> bool:
    return _CJK_RANGE[0] <= char <= _CJK_RANGE[1]


def _description_keywords(description: str) -> set[str]:
    """描述中的英文单词（小写）；中文描述由系统属性名侧的别名/字符层承担。"""
    text = description[:_MAX_DESCRIPTION_LENGTH]
    return set(word.lower() for word in _ASCII_WORD_RE.findall(text))


def _ratio(left: str, right: str) -> float:
    if not left or not right:
        return 0.0
    return SequenceMatcher(None, left, right).ratio()


def _jaccard(left: set[str], right: set[str]) -> float:
    if not left or not right:
        return 0.0
    union = left | right
    return len(left & right) / len(union)


class CandidateRetriever:
    """对一份目录实例批量检索候选（索引端 token 集只预计算一次）。"""

    def __init__(self, catalog: StandardFieldCatalog) -> None:
        self._catalog = catalog
        self._synonyms = catalog.synonyms
        self._tag_rules = catalog.tag_rules
        self._records = [
            field
            for field in catalog.fields
            if field.system_property_name not in MAPPING_EXCLUDED_STANDARD_FIELDS
        ]
        all_zh_aliases = {
            alias
            for entry in catalog.synonyms.values()
            for alias in entry.get("zh", ())
            if alias
        }
        self._alias_to_key: dict[str, str] = {}
        for key, entry in catalog.synonyms.items():
            for alias in entry.get("zh", ()):
                if alias and alias not in self._alias_to_key:
                    self._alias_to_key[alias] = key
        self._record_tokens: dict[int, set[str]] = {}
        for position, field in enumerate(self._records):
            tokens = set(expand_field_name(field.field_name, self._synonyms).split())
            tokens.update(generate_field_tags(field.field_name, self._tag_rules))
            tokens.update(
                alias
                for alias in all_zh_aliases
                if alias in field.system_property_name
            )
            tokens.update(_description_keywords(field.description))
            self._record_tokens[position] = tokens

    def retrieve(self, field_name: str, top_k: int = DEFAULT_TOP_K) -> list[Candidate]:
        """检索一个原始字段名的 Top-K 候选（确定性）。"""
        if not field_name:
            return []

        # 查询侧中文别名桥接：查询串恰为同义词表某键的中文别名时并入该键
        bridge_key = self._alias_to_key.get(field_name)
        effective_names = [field_name] + ([bridge_key] if bridge_key else [])

        scored: dict[int, dict] = {}

        # 精确层：原名查找（规范化/紧凑/中文系统名/中文别名四路索引）
        for name in effective_names:
            exact = self._catalog.lookup(name)
            if exact is not None and self._not_excluded(exact):
                position = self._position_of(exact)
                if position not in scored:
                    scored[position] = {"score": 1.0, "by_stripped": "", "tier": 0}

        # 去前缀变体精确层
        for variant in strip_field_prefix(field_name):
            hit = self._catalog.lookup(variant)
            if hit is None or not self._not_excluded(hit):
                continue
            position = self._position_of(hit)
            if position not in scored:
                scored[position] = {"score": 1.0, "by_stripped": variant, "tier": 0}

        # 词法 + 字符层
        query_tokens: set[str] = set()
        query_expanded: set[str] = set()
        for name in effective_names:
            query_expanded.update(expand_field_name(name, self._synonyms).split())
            query_tokens.update(expand_field_name(name, self._synonyms).split())
            query_tokens.update(generate_field_tags(name, self._tag_rules))
            query_tokens.update(collect_zh_synonyms(name, self._synonyms))
        compact_query = compact_field_name(field_name)
        for position, field in enumerate(self._records):
            if position in scored:
                continue
            jaccard = _jaccard(query_tokens, self._record_tokens[position])
            char_sim = max(
                _ratio(compact_query, compact_field_name(field.field_name)),
                _ratio(field_name, field.system_property_name),
            )
            sim = max(jaccard, char_sim)
            if sim >= LEXICAL_SIMILARITY_THRESHOLD:
                scored[position] = {"score": sim, "by_stripped": "", "tier": 1}

        # 重排：精确层优先 → 英文 token 重叠降序 → Jaccard 降序 → 字符相似降序 → 名称字典序
        reranked: list[tuple[int, int, float, float, str, int]] = []
        for position, info in scored.items():
            field = self._records[position]
            overlap = len(
                query_expanded
                & set(expand_field_name(field.field_name, self._synonyms).split())
            )
            jaccard = _jaccard(query_tokens, self._record_tokens[position])
            reranked.append(
                (
                    info["tier"],
                    -overlap,
                    -jaccard,
                    -info["score"],
                    field.system_property_name,
                    position,
                )
            )
        reranked.sort()

        candidates: list[Candidate] = []
        for _, _, _, _, _, position in reranked[: max(top_k, 0)]:
            field = self._records[position]
            info = scored[position]
            enum_whitelist = (
                tuple(v.strip() for v in field.enum_values.split(",") if v.strip())
                if field.enum_values
                else ()
            )
            candidates.append(
                Candidate(
                    name=field.system_property_name,
                    score=round(info["score"], 4),
                    field_name=field.field_name,
                    by_stripped=info["by_stripped"],
                    object=field.objects,
                    data_type=field.data_type,
                    description=field.description,
                    enum_whitelist=enum_whitelist,
                )
            )
        return candidates

    def _not_excluded(self, field: StandardField) -> bool:
        return field.system_property_name not in MAPPING_EXCLUDED_STANDARD_FIELDS

    def _position_of(self, field: StandardField) -> int:
        for position, item in enumerate(self._records):
            if item is field:
                return position
        raise KeyError(field.system_property_name)


def retrieve_candidates(
    field_name: str,
    catalog: StandardFieldCatalog,
    top_k: int = DEFAULT_TOP_K,
) -> list[Candidate]:
    """单字段检索便捷入口（批量场景请复用 CandidateRetriever 实例）。"""
    return CandidateRetriever(catalog).retrieve(field_name, top_k)
