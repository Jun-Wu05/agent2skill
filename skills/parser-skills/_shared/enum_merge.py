"""枚举映射对写回底座：orgValue 级合并更新与固定值绑定解绑。

enum-mapping 的填充脚本与 threat-type 的收口脚本共用的写回语义
（任何字段都可经枚举填充/取消维护值映射后，各链路共用的合并约定），
禁止在技能脚本内复制：
- 同 orgValue 原地更新 mappingValue / mappingType，新 orgValue 追加，
  未提及的既有映射保留（无状态幂等；删除走取消映射脚本）；
- 输入内同 orgValue 首现胜出去重；
- 解绑＝删除 addFields 过滤器里目标字段的固定值绑定（``%{}`` 引用
  绑定保留，清空后的 addFields 条目整体移除）。
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Tuple


def remove_addfields_keys(
    filters: List[Any],
    target_fields: Iterable[str],
    *,
    keep_reference: bool = True,
    require_empty_id: bool = False,
) -> int:
    """从 addFields 过滤器列表移除目标字段键（列表原地修改）。

    两种调用语义共用本函数（filter 级单一事实源）：
    - 枚举解绑：``keep_reference=True``——只删固定值绑定，``%{}`` 引用
      保留；``require_empty_id=False``——不区分过滤器 id；
    - 威胁链路整体替换：``keep_reference=False``——固定值与 ``%{}``
      引用一并清；``require_empty_id=True``——只动 id 为空串的
      addFields（与链路自产探测的 id 守卫对称）。

    fields 清空后的 addFields 条目整体移除。返回移除键计数。
    """
    removed = 0
    targets = set(target_fields)
    kept: List[Any] = []
    for item in filters:
        if (
            isinstance(item, dict)
            and item.get("name") == "addFields"
            and (not require_empty_id or item.get("id") == "")
            and isinstance(item.get("fields"), dict)
        ):
            fields = item["fields"]
            for target in list(fields):
                if target in targets and (
                    not keep_reference or not str(fields[target]).startswith("%{")
                ):
                    del fields[target]
                    removed += 1
            if not fields:
                continue  # 清空后的 addFields 条目整体移除
        kept.append(item)
    filters[:] = kept
    return removed


def unbind_fixed_bindings(config: Any, target_fields: List[str]) -> int:
    """删除 addFields 过滤器里目标字段的固定值绑定（原地修改）。

    ``%{}`` 引用绑定保留；fields 清空后的 addFields 条目整体移除。
    返回解绑计数。
    """
    unbound = 0

    def _walk(obj: Any) -> None:
        nonlocal unbound
        if isinstance(obj, dict):
            parser = obj.get("parser")
            if isinstance(parser, dict):
                filters = parser.get("filter")
                if isinstance(filters, list):
                    unbound += remove_addfields_keys(
                        filters, target_fields, keep_reference=True
                    )
            for value in obj.values():
                _walk(value)
        elif isinstance(obj, list):
            for item in obj:
                _walk(item)

    _walk(config)
    return unbound


def dedup_pairs_first_wins(pairs: List[Dict[str, str]]) -> Tuple[List[Dict[str, str]], int]:
    """输入内同 orgValue 去重（首现胜出），返回 (去重结果, 重复计数)。"""
    seen: Dict[str, Dict[str, str]] = {}
    duplicates = 0
    for pair in pairs:
        if pair["orgValue"] in seen:
            duplicates += 1
            continue
        seen[pair["orgValue"]] = pair
    return list(seen.values()), duplicates


def apply_pairs_to_entry(entry: dict, pairs: List[Dict[str, str]]) -> Dict[str, int]:
    """把归一后的映射对按 orgValue 合并更新进条目（原地修改）。

    返回 {added, updated, unchanged}。既有映射顺序保留，新 orgValue
    追加在末尾。
    """
    existing = entry.get("mappings")
    if not isinstance(existing, list):
        existing = []
        entry["mappings"] = existing
    by_org = {}
    for position, mapping in enumerate(existing):
        if isinstance(mapping, dict) and mapping.get("orgValue") not in by_org:
            by_org[mapping["orgValue"]] = position

    added = updated = unchanged = 0
    for pair in pairs:
        org = pair["orgValue"]
        if org in by_org:
            current = existing[by_org[org]]
            if (
                current.get("mappingValue") == pair["mappingValue"]
                and current.get("mappingType") == pair["mappingType"]
            ):
                unchanged += 1
            else:
                current["mappingValue"] = pair["mappingValue"]
                current["mappingType"] = pair["mappingType"]
                updated += 1
        else:
            by_org[org] = len(existing)
            existing.append(dict(pair))
            added += 1
    return {"added": added, "updated": updated, "unchanged": unchanged}


__all__ = [
    "apply_pairs_to_entry",
    "dedup_pairs_first_wins",
    "remove_addfields_keys",
    "unbind_fixed_bindings",
]
