"""目标 entity 范围圈定（按 name 精确匹配的寻址底座）。

field-adjust 各子命令共用的目标范围迭代器：target_names 为 None 表示
全部 entity，名单外的不产出。子模块脚本共用本模块，禁止复制。
"""

from __future__ import annotations

from typing import Iterator, List, Optional


def entities_in_scope(
    data: list, target_names: Optional[List[str]]
) -> Iterator[dict]:
    """产出目标范围内的 entity（target_names 为 None 时产出全部）。"""
    targets = set(target_names) if target_names else None
    for entity in data:
        if targets is None or entity.get("name") in targets:
            yield entity
