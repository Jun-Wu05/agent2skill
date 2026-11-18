"""删除字段 - 从解析规则（mapping entity）中移除字段。

field-adjust 技能的 delete 子命令：文件输入/输出契约，无 session、无外部
依赖；系统保留字段被拒绝删除，事件名称+事件级别绑定对联动删除，被引用
字段（merger 源字段 / %{字段} 占位）删除前做悬空引用拦截。

CLI 用法:
    python delete_fields.py --input <配置文件> --fields 字段a,字段b
                            [--target 规则A,规则B]
                            [--group {all,threat,non-threat}]
                            [--output <输出.json>] [--no-export]

输入支持: Base64 txt / 原生 JSON / TXT（须为 JSON 数组）
输出: 修改后配置 JSON + 平台可导入的 Base64 文件（fieldadjusted_config_YYYYMMDD_HHMM.txt）
"""

from __future__ import annotations

import copy
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, List, Literal, Mapping, Optional

_SKILLS_ROOT = Path(__file__).resolve().parents[2]
if str(_SKILLS_ROOT) not in sys.path:
    sys.path.insert(0, str(_SKILLS_ROOT))

from _shared.event_binding import (  # noqa: E402
    EVENT_LEVEL_FIELD,
    EVENT_NAME_FIELD,
    THREAT_EVENT_NAMES,
    read_entity_event_name,
)


# 系统保留字段，不允许删除：
# - original_log / rule_name_list：脚本原有保留字段
# - 日志类型：子规则分流依赖的核心字段，删除会破坏规则结构
RESERVED_FIELDS = {"original_log", "rule_name_list", "日志类型"}


def delete_field(
    data: list,
    fields_to_delete: List[str],
    target_names: Optional[List[str]] = None,
) -> dict:
    """
    对 mapping entity 列表执行字段删除

    每个目标 entity 的 normalize 中移除匹配条目，parser.filter 中清理
    同名 addFields 绑定并写入 removeFields 过滤器（已有则合并）。

    Args:
        data: 解码后的 JSON 数组（mapping entities）
        fields_to_delete: 要删除的字段名列表，如 ["a"] 或 ["a", "b"]
        target_names: 目标 entity 名单（按 name 精确匹配）；
                      None 表示全部 entity。名单外的 entity 原样透传。

    Returns:
        {"status": "success"|"error", "data": [...], "message": "...",
         "not_found": [...]|None}
    """
    if not data:
        return {"status": "error", "message": "输入数据为空"}

    if not fields_to_delete:
        return {"status": "error", "message": "未指定要删除的字段"}

    reserved = [f for f in fields_to_delete if f in RESERVED_FIELDS]
    if reserved:
        return {
            "status": "error",
            "message": f"字段 {reserved} 为系统保留字段，不允许删除",
        }

    targets = set(target_names) if target_names else None
    results = []
    applied = 0
    total_deleted = 0
    skipped_empty = 0
    skipped_reasons: list[tuple[str, str]] = []
    # 字段是否在任一目标 entity 中存在（不被逐 entity 覆盖）
    present_anywhere: dict[str, bool] = {f: False for f in fields_to_delete}
    for entity in data:
        entity = copy.deepcopy(entity)

        if targets is not None and entity.get("name") not in targets:
            results.append(entity)
            continue

        normalize = entity.get("normalize") or []
        name = entity.get("name") or "<未命名>"
        if not normalize:
            # 无 normalize 的 entity 无字段可删，如实跳过
            skipped_empty += 1
            results.append(entity)
            continue

        # 构建 index → normalize item 映射
        norm_map = {item.get("index"): item for item in normalize if item.get("index")}

        deletable = [f for f in fields_to_delete if f in norm_map]
        for f in deletable:
            present_anywhere[f] = True

        if not deletable:
            skipped_reasons.append((name, f"缺 {'、'.join(fields_to_delete)}"))
            results.append(entity)
            continue

        # 1. 清理同名 addFields 绑定，避免旧绑定在后续重新添加字段后继续
        # 生效。过滤器还有其他键时只删目标键；fields 清空时删除整个空
        # addFields 过滤器。
        parser = entity.get("parser") or {}
        # 入口规则模板的 filter 可能为 null，初始化为空数组再追加
        filters = parser.get("filter") or []

        cleaned_filters = []
        for filter_item in filters:
            if filter_item.get("name") == "addFields" and isinstance(
                filter_item.get("fields"), dict
            ):
                remaining_fields = {
                    key: value
                    for key, value in filter_item["fields"].items()
                    if key not in deletable
                }
                if not remaining_fields:
                    continue
                filter_item["fields"] = remaining_fields
            cleaned_filters.append(filter_item)
        filters = cleaned_filters

        # 检查是否已存在 removeFields 过滤器，有则合并（去重追加）
        existing_remove = None
        for i, f in enumerate(filters):
            if f.get("name") == "removeFields":
                existing_remove = i
                break

        if existing_remove is not None:
            existing_fields = filters[existing_remove].get("fields", [])
            for fld in deletable:
                if fld not in existing_fields:
                    existing_fields.append(fld)
            filters[existing_remove]["fields"] = existing_fields
        else:
            filters.append(
                {
                    "name": "removeFields",
                    "id": "",
                    "fields": list(deletable),
                }
            )

        parser["filter"] = filters
        entity["parser"] = parser

        # 2. 移除 normalize 条目（仅移除该 entity 实际存在的字段）
        entity["normalize"] = [
            item for item in normalize if item.get("index") not in deletable
        ]

        applied += 1
        total_deleted += len(deletable)
        results.append(entity)

    # 未找到 = 所有目标 entity 都没有该字段
    not_found = [f for f, present in present_anywhere.items() if not present]
    message = f"成功从 {applied} 个 entity 删除 {total_deleted} 个字段"
    if targets is not None:
        message += f"（目标 {len(targets)} 个）"
    if skipped_reasons:
        detail = "；".join(f"{n}（{r}）" for n, r in skipped_reasons[:5])
        more = f" 等 {len(skipped_reasons)} 条" if len(skipped_reasons) > 5 else ""
        message += f"；跳过：{detail}{more}"
    if skipped_empty:
        message += f"（跳过 {skipped_empty} 个无 normalize 的 entity）"
    if not_found:
        message += f"；未找到字段: {', '.join(not_found)}（不存在于任何子规则）"
    return {
        "status": "success",
        "data": results,
        "message": message,
        "not_found": not_found if not_found else None,
    }


# ---------------------------------------------------------------------------
# 删除守卫链（寻址 / 保留字段 / 绑定对联动 / 悬空引用）
# ---------------------------------------------------------------------------

ReferenceKind = Literal["merger", "placeholder"]


@dataclass(frozen=True, slots=True)
class DanglingFieldReference:
    """删除后会失效的字段引用。"""

    entity_name: str
    kind: ReferenceKind
    fields: tuple[str, ...]


def find_dangling_references(
    entities: Iterable[Mapping[str, Any]],
    deleted_names: Iterable[str],
) -> tuple[DanglingFieldReference, ...]:
    """找出 merger 源字段与 ``%{字段}`` 占位中对被删字段的引用。"""
    deleted = set(deleted_names)
    conflicts: list[DanglingFieldReference] = []
    for entity in entities:
        name = entity.get("name") or "<未命名>"
        parser = entity.get("parser") or {}
        for filter_item in parser.get("filter") or []:
            if not isinstance(filter_item, dict):
                continue
            if filter_item.get("name") == "merger":
                overlap = tuple(sorted(deleted & set(filter_item.get("fields") or [])))
                if overlap:
                    conflicts.append(DanglingFieldReference(str(name), "merger", overlap))
            fields = filter_item.get("fields")
            if isinstance(fields, dict):
                for value in fields.values():
                    if not isinstance(value, str):
                        continue
                    references = tuple(
                        sorted(field for field in deleted if f"%{{{field}}}" in value)
                    )
                    if references:
                        conflicts.append(
                            DanglingFieldReference(
                                str(name), "placeholder", (references[0],)
                            )
                        )
    return tuple(conflicts)


def _entities_in_scope(data: list, target_names: Optional[List[str]]):
    targets = set(target_names) if target_names else None
    for entity in data:
        if targets is None or entity.get("name") in targets:
            yield entity


def _resolve_field_scope(
    data: list,
    target_names: Optional[List[str]],
    group: str,
) -> tuple[Optional[List[str]], Optional[dict]]:
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


def _with_error_code(result: dict) -> dict:
    """给 delete_field 的错误结果补稳定错误码。"""
    if result.get("status") == "error":
        message = str(result.get("message", ""))
        code = "reserved_field_rejected" if "保留字段" in message else "invalid_input"
        result = dict(result)
        result.setdefault("code", code)
    return result


def delete_field_guarded(
    data: list,
    fields: List[str],
    target_names: Optional[List[str]] = None,
    group: str = "all",
) -> dict:
    """带守卫链的字段删除。

    守卫顺序（任一命中即拒绝，稳定错误码）：
    1. data / fields 空校验 → invalid_input；
    2. 寻址解析：target 未知名 → rule_name_not_found；group 分组
       无标注 → event_annotation_required、组内无匹配 → rule_name_not_found；
    3. 保留字段拦截 → reserved_field_rejected；
    4. 删【事件名称】或【事件级别】任一时自动扩展为两者，避免留下
       绑定残缺；
    5. 悬空引用守卫（仅查目标范围内 entity）：merger 源字段引用或
       %{字段} 占位引用 → field_reference_conflict。
    """
    if not data:
        return {"status": "error", "code": "invalid_input", "message": "输入数据为空"}
    if not fields:
        return {"status": "error", "code": "invalid_input", "message": "未指定要删除的字段"}

    targets, scope_error = _resolve_field_scope(data, target_names, group)
    if scope_error is not None:
        return scope_error

    reserved_hit = [name for name in fields if name in RESERVED_FIELDS]
    if reserved_hit:
        return {
            "status": "error",
            "code": "reserved_field_rejected",
            "message": f"字段 {reserved_hit} 为系统保留字段，不允许删除",
        }

    effective_fields = list(fields)
    pair_note = ""
    if any(name in (EVENT_NAME_FIELD, EVENT_LEVEL_FIELD) for name in effective_fields):
        for pair_name in (EVENT_NAME_FIELD, EVENT_LEVEL_FIELD):
            if pair_name not in effective_fields:
                effective_fields.append(pair_name)
        pair_note = "；已联动删除绑定对（事件名称+事件级别）"

    issues = []
    for conflict in find_dangling_references(
        _entities_in_scope(data, targets), effective_fields
    ):
        if conflict.kind == "merger":
            issues.append(
                f"{conflict.entity_name}: merger 源字段引用 {list(conflict.fields)}"
            )
        else:
            issues.append(f"{conflict.entity_name}: %{{{conflict.fields[0]}}} 引用")
    if issues:
        return {
            "status": "error",
            "code": "field_reference_conflict",
            "message": "以下引用了被删字段，请先解除引用再删除：" + "；".join(issues[:5]),
        }

    result = delete_field(data, effective_fields, targets)
    if result.get("status") != "success":
        return _with_error_code(result)
    return {
        "status": "success",
        "data": result["data"],
        "message": str(result.get("message", "")) + pair_note,
        "not_found": result.get("not_found"),
    }
