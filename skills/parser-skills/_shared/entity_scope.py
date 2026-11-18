"""目标 entity 范围圈定（按 name 精确匹配的寻址底座）。

field-adjust 各子命令共用的目标范围工具：target_names 为 None 表示
全部 entity，名单外的不产出；resolve_field_scope 把 target / group
参数解析为目标名单（含存在性与分组校验）。子模块脚本共用本模块，
禁止复制。
"""

from __future__ import annotations

from typing import Iterator, List, Optional, Tuple

from _shared.event_binding import THREAT_EVENT_NAMES, read_entity_event_name


def entities_in_scope(
    data: list, target_names: Optional[List[str]]
) -> Iterator[dict]:
    """产出目标范围内的 entity（target_names 为 None 时产出全部）。"""
    targets = set(target_names) if target_names else None
    for entity in data:
        if targets is None or entity.get("name") in targets:
            yield entity


def resolve_field_scope(
    data: list,
    target_names: Optional[List[str]],
    group: str,
) -> Tuple[Optional[List[str]], Optional[dict]]:
    """把 target / group 解析为目标名单。

    - target 非空：逐名校验存在性，未知名返回 rule_name_not_found；
      与 group 并存时 target 优先。
    - group 非 all：按已标注【事件名称】+ 绑定表确定性分组；
      无任何标注返回 event_annotation_required；组内无匹配返回
      rule_name_not_found。
    - 其余：None 表示全部 entity。
    """
    if target_names:
        available = [
            entity.get("name")
            for entity in data
            if isinstance(entity, dict)
            and isinstance(entity.get("name"), str)
            and entity.get("name")
        ]
        available_set = set(available)
        unknown = [name for name in target_names if name not in available_set]
        if unknown:
            preview = "、".join(available[:20]) + ("等" if len(available) > 20 else "")
            return None, {
                "status": "error",
                "code": "rule_name_not_found",
                "message": f"未找到子规则: {'、'.join(unknown)}。可用子规则: {preview}",
            }
        return list(target_names), None

    if group != "all":
        wanted_threat = group == "threat"
        targets = []
        annotated = False
        for entity in data:
            event_name = read_entity_event_name(entity)
            if event_name is None:
                continue
            annotated = True
            if (event_name in THREAT_EVENT_NAMES) == wanted_threat:
                name = entity.get("name")
                if isinstance(name, str) and name:
                    targets.append(name)
        if not annotated:
            return None, {
                "status": "error",
                "code": "event_annotation_required",
                "message": (
                    "没有已标注【事件名称】的子规则，无法按威胁/非威胁分组；"
                    "可先用添加字段为子规则标注【事件名称】后再试"
                ),
            }
        if not targets:
            return None, {
                "status": "error",
                "code": "rule_name_not_found",
                "message": f"没有属于{'威胁' if wanted_threat else '非威胁'}组的子规则",
            }
        return targets, None

    return None, None
