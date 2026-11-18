"""合并字段 - 把多个源字段的值合并为一个新字段。

field-adjust 技能的 merge 子命令：文件输入/输出契约，无 session、无外部
依赖；对每个目标 entity 写入 merger 过滤器（运行时按分隔符拼接源字段值）
并追加 normalize 预览条目（源字段样本值按序拼接的预览值）。源字段保留
不删（merger 运行时依赖源字段）。

CLI 用法:
    python merge_fields.py --input <配置文件> --sources 字段a,字段b
                           --target-field 合并结果 [--sep <分隔符>]
                           [--target 规则A,规则B]
                           [--group {all,threat,non-threat}]
                           [--output <输出.json>] [--no-export]

输入支持: Base64 txt / 原生 JSON / TXT（须为 JSON 数组）
输出: 修改后配置 JSON + 平台可导入的 Base64 文件（fieldadjusted_config_YYYYMMDD_HHMM.txt）
"""

from __future__ import annotations

import argparse
import copy
import json
import sys
from pathlib import Path
from typing import List, Optional

_SKILLS_ROOT = Path(__file__).resolve().parents[2]
if str(_SKILLS_ROOT) not in sys.path:
    sys.path.insert(0, str(_SKILLS_ROOT))

from _shared import report as skill_report  # noqa: E402
from _shared.config_io import ConfigIOError, load_entities  # noqa: E402
from _shared.entity_scope import resolve_field_scope  # noqa: E402
from _shared.event_binding import EVENT_LEVEL_FIELD, EVENT_NAME_FIELD  # noqa: E402
from _shared.field_policy import RESERVED_FIELDS  # noqa: E402


def merge_field(
    data: list,
    source_fields: List[str],
    target_field: str,
    sep: str = "",
    target_names: Optional[List[str]] = None,
) -> dict:
    """
    对 mapping entity 列表执行字段合并（per-entity 自适应）

    子规则字段集互不相同（映射表展示的是并集）：源字段齐全且目标字段
    不存在的 entity 执行合并；缺任一源或目标已存在的 entity 跳过并按
    子规则名报告；所有目标 entity 都缺源时返回 field_not_found。

    对执行合并的 entity：parser.filter 写入（或原地更新同目标的）
    merger 过滤器；normalize 追加目标字段预览条目（源字段样本值按序
    用分隔符拼接）。源字段条目保留不删。

    Args:
        data: 解码后的 JSON 数组（mapping entities）
        source_fields: 源字段名列表，如 ["a", "b"]，至少 2 个
        target_field: 合并产出的目标字段名，如 "d"
        sep: 分隔符，如 "" 或 "-"
        target_names: 目标 entity 名单（按 name 精确匹配）；
                      None 表示全部 entity。名单外的 entity 原样透传。

    Returns:
        {"status": "success"|"error", "data": [...], "message": "..."}
    """
    if not data:
        return {"status": "error", "code": "invalid_input", "message": "输入数据为空"}

    if not source_fields:
        return {"status": "error", "code": "invalid_input", "message": "未指定源字段"}

    if len(source_fields) < 2:
        return {
            "status": "error",
            "code": "invalid_input",
            "message": "至少需要 2 个源字段",
        }

    if not target_field:
        return {"status": "error", "code": "invalid_input", "message": "目标字段名不能为空"}

    targets = set(target_names) if target_names else None
    results = []
    applied = 0
    skipped_empty = 0
    skipped_reasons: list[tuple[str, str]] = []
    all_missing_source = True
    union_indexes: set[str] = set()

    for entity in data:
        entity = copy.deepcopy(entity)

        if targets is not None and entity.get("name") not in targets:
            results.append(entity)
            continue

        normalize = entity.get("normalize") or []
        name = entity.get("name") or "<未命名>"
        if not normalize:
            # 无 normalize 的 entity 无源字段可合并，如实跳过
            skipped_empty += 1
            results.append(entity)
            continue

        # 构建 index → normalize item 映射
        norm_map = {item.get("index"): item for item in normalize if item.get("index")}
        union_indexes.update(norm_map)

        missing = [f for f in source_fields if f not in norm_map]
        if missing:
            skipped_reasons.append((name, f"缺 {'、'.join(missing)}"))
            results.append(entity)
            continue
        all_missing_source = False

        # 目标字段已存在时该 entity 跳过而非整体失败（per-entity 自适应）
        if target_field in norm_map:
            skipped_reasons.append((name, f"目标 '{target_field}' 已存在"))
            results.append(entity)
            continue

        # 计算合并后的预览值（源字段样本值按序拼接）
        merged_result = sep.join(
            norm_map[f].get("result", [""])[0] if norm_map[f].get("result") else ""
            for f in source_fields
        )

        # 1. 写入 merger 过滤器；同目标的已有 merger 原地更新
        parser = entity.get("parser") or {}
        # 入口规则模板的 filter 可能为 null，初始化为空数组再追加
        filters = parser.get("filter") or []

        existing_idx = None
        for i, f in enumerate(filters):
            if f.get("name") == "merger" and f.get("field") == target_field:
                existing_idx = i
                break

        merger_entry = {
            "name": "merger",
            "field": target_field,
            "sep": sep,
            "id": "",
            "fields": list(source_fields),
        }

        if existing_idx is not None:
            filters[existing_idx] = merger_entry
        else:
            filters.append(merger_entry)

        parser["filter"] = filters
        entity["parser"] = parser

        # 2. 追加 normalize 预览条目
        normalize_entry = {
            "mappings": [],
            "field": None,
            "sim": None,
            "result": [merged_result],
            "info": None,
            "entity": None,
            "required": False,
            "core": None,
            "value": None,
            "index": target_field,
        }

        normalize.append(normalize_entry)
        entity["normalize"] = normalize

        applied += 1
        results.append(entity)

    # 所有目标 entity 都缺源字段 → 真正的 field_not_found（并集词表辅助定位）
    if applied == 0 and skipped_reasons and all_missing_source:
        preview = "、".join(sorted(union_indexes)[:30])
        return {
            "status": "error",
            "code": "field_not_found",
            "message": (
                f"源字段 {source_fields} 不存在于任何（目标）子规则；"
                f"全部子规则字段并集: {preview}"
                + ("等" if len(union_indexes) > 30 else "")
            ),
        }

    message = f"成功合并 {applied} 个 entity 的字段为 '{target_field}'"
    if targets is not None:
        message += f"（目标 {len(targets)} 个）"
    if skipped_reasons:
        detail = "；".join(f"{n}（{r}）" for n, r in skipped_reasons[:5])
        more = f" 等 {len(skipped_reasons)} 条" if len(skipped_reasons) > 5 else ""
        message += f"；跳过：{detail}{more}"
    if skipped_empty:
        message += f"（跳过 {skipped_empty} 个无 normalize 的 entity）"
    return {"status": "success", "data": results, "message": message}


# ---------------------------------------------------------------------------
# 合并守卫链（寻址 / 保留字段 / 事件绑定字段 / 自引用）
# ---------------------------------------------------------------------------


def merge_field_guarded(
    data: list,
    source_fields: List[str],
    target_field: str,
    sep: str = "",
    target_names: Optional[List[str]] = None,
    group: str = "all",
) -> dict:
    """带守卫链的字段合并。

    守卫顺序（任一命中即拒绝，稳定错误码）：
    1. data / 源字段 / 目标字段名空校验与源字段数下限 → invalid_input；
    2. 寻址解析：target 未知名 → rule_name_not_found；group 分组
       无标注 → event_annotation_required、组内无匹配 → rule_name_not_found；
    3. 目标字段为系统保留字段 → reserved_field_rejected；
    4. 目标字段为【事件名称】/【事件级别】→ invalid_event_name
       （事件字段请走添加字段，自动联动绑定对）；
    5. 自引用（目标字段 ∈ 源字段）→ invalid_input。
    """
    if not data:
        return {"status": "error", "code": "invalid_input", "message": "输入数据为空"}
    if not source_fields:
        return {"status": "error", "code": "invalid_input", "message": "未指定源字段"}
    if len(source_fields) < 2:
        return {
            "status": "error",
            "code": "invalid_input",
            "message": "至少需要 2 个源字段",
        }
    if not target_field:
        return {"status": "error", "code": "invalid_input", "message": "目标字段名不能为空"}

    targets, scope_error = resolve_field_scope(data, target_names, group)
    if scope_error is not None:
        return scope_error

    if target_field in RESERVED_FIELDS:
        return {
            "status": "error",
            "code": "reserved_field_rejected",
            "message": f"目标字段 '{target_field}' 为系统保留字段，不允许作为合并目标",
        }

    if target_field in (EVENT_NAME_FIELD, EVENT_LEVEL_FIELD):
        return {
            "status": "error",
            "code": "invalid_event_name",
            "message": (
                f"目标字段 '{target_field}' 为事件绑定字段；事件名称/事件级别"
                "请通过添加字段设置（自动按绑定关系联动写入）"
            ),
        }

    if target_field in source_fields:
        return {
            "status": "error",
            "code": "invalid_input",
            "message": (
                f"目标字段 '{target_field}' 与源字段重名（自引用），"
                "请为合并结果另取字段名"
            ),
        }

    return merge_field(data, source_fields, target_field, sep, targets)
