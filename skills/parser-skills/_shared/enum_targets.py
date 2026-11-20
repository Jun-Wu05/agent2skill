"""枚举目标解析：配置内 normalize 条目的寻址、命中与词汇表。

enum-mapping 填充（enum_fill.py）与取消映射（enum_unmap.py）共用：
- ``iter_normalize_entries``：递归遍历配置产出 (owner, entry)；
- ``resolve_targets``：目标字段 → 全部命中条目（index 或 field 同名）；
- ``available_field_names`` / ``field_vocab``：错误提示用的可用字段清单
  （扁平名单 / 「原始名(标准名)」词汇表）。

目标解析必须经过本模块，禁止在技能脚本内复制遍历或命中逻辑。
"""

from __future__ import annotations

from typing import Any, Dict, Iterator, List, Tuple


def iter_normalize_entries(obj: Any) -> Iterator[Tuple[dict, dict]]:
    """递归遍历配置，产出 (持有 normalize 的节点, normalize 条目)。"""
    if isinstance(obj, dict):
        normalize = obj.get("normalize")
        if isinstance(normalize, list):
            for entry in normalize:
                if isinstance(entry, dict):
                    yield obj, entry
        for value in obj.values():
            yield from iter_normalize_entries(value)
    elif isinstance(obj, list):
        for item in obj:
            yield from iter_normalize_entries(item)


def resolve_targets(
    config: Any, target_fields: List[str]
) -> Dict[str, List[Tuple[dict, dict]]]:
    """目标字段 → 全部命中 (owner, entry)；index 或 field 同名即命中。"""
    matches: Dict[str, List[Tuple[dict, dict]]] = {field: [] for field in target_fields}
    lookup = set(target_fields)
    for owner, entry in iter_normalize_entries(config):
        index = entry.get("index")
        field_value = entry.get("field")
        for target in lookup:
            if index == target or field_value == target:
                matches[target].append((owner, entry))
    return matches


def available_field_names(config: Any) -> List[str]:
    """配置内全部 index / field 名（非空、保序去重）。"""
    names: List[str] = []

    def _add(name: Any) -> None:
        text = str(name or "").strip()
        if text and text not in names:
            names.append(text)

    for _owner, entry in iter_normalize_entries(config):
        _add(entry.get("index"))
        _add(entry.get("field"))
    return names


def field_vocab(config: Any) -> List[str]:
    """「原始名(标准名)」词汇表（field 为空时只原始名），保序去重。"""
    vocab: List[str] = []

    def _add(index: Any, field_value: Any) -> None:
        index_text = str(index or "").strip()
        field_text = str(field_value or "").strip()
        if not index_text:
            return
        display = f"{index_text}({field_text})" if field_text else index_text
        if display not in vocab:
            vocab.append(display)

    for _owner, entry in iter_normalize_entries(config):
        _add(entry.get("index"), entry.get("field"))
    return vocab
