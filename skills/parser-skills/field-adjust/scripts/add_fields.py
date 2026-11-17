"""添加字段 - 在解析规则（mapping entity）中新增字段。

field-adjust 技能的 add 子命令：文件输入/输出契约，无 session、无外部
依赖；事件名称受确定性绑定守卫约束，并自动联动写入事件级别。

CLI 用法:
    python add_fields.py --input <配置文件> --field <字段名> [--value <值>]
                         [--output <输出.json>] [--target 规则A,规则B]
                         [--skip-existing] [--no-export]

输入支持: Base64 txt / 原生 JSON / TXT（须为 JSON 数组）
输出: 修改后配置 JSON + 平台可导入的 Base64 文件（fieldadjusted_config_YYYYMMDD_HHMM.txt）
"""

from __future__ import annotations

import argparse
import copy
import json
import sys
from pathlib import Path
from typing import Any, List, Mapping, Optional

_SKILLS_ROOT = Path(__file__).resolve().parents[2]
if str(_SKILLS_ROOT) not in sys.path:
    sys.path.insert(0, str(_SKILLS_ROOT))

from _shared import report as skill_report
from _shared.config_io import ConfigIOError, load_entities
from _shared.event_binding import (
    EVENT_LEVEL_FIELD,
    EVENT_NAME_FIELD,
    EVENT_NAME_LEVEL_BINDING,
    event_level_normalize_metadata,
    event_name_normalize_metadata,
)


def add_field(
    data: list,
    field_name: str,
    field_value: Optional[str] = None,
    target_names: Optional[List[str]] = None,
    skip_existing: bool = False,
    normalize_metadata: Optional[Mapping[str, Any]] = None,
) -> dict:
    """
    对 mapping entity 列表执行字段添加

    每个 entity 的 normalize 中添加新字段条目，
    parser.filter 中添加 addFields 过滤器。

    Args:
        data: 解码后的 JSON 数组（mapping entities）
        field_name: 新字段名，如 "主机ip"
        field_value: 字段值，如 "1.1.1.1" 或 "%{reqheader}"。
                     为 None 时表示用户未提供值。
        target_names: 目标 entity 名单（按 name 精确匹配）；
                      None 表示全部 entity。名单外的 entity 原样透传。
        skip_existing: 已有同名字段的 entity 跳过而不是整体失败。
        normalize_metadata: 受控链路为生成字段提供的标准元数据；
                            普通字段添加默认为 None。

    Returns:
        {"status": "success"|"error", "data": [...], "message": "..."}
    """
    if not data:
        return {"status": "error", "message": "输入数据为空"}

    if not field_name:
        return {"status": "error", "message": "字段名不能为空"}

    targets = set(target_names) if target_names else None
    results = []
    applied = 0
    skipped = 0
    skipped_existing = 0
    for entity in data:
        entity = copy.deepcopy(entity)

        if targets is not None and entity.get("name") not in targets:
            results.append(entity)
            continue

        # 获取 normalize 列表
        normalize = entity.get("normalize") or []
        if not normalize:
            # 无 normalize 的 entity 无法承载新字段，如实跳过
            skipped += 1
            results.append(entity)
            continue

        # 构建 index → normalize item 映射
        norm_map = {item.get("index"): item for item in normalize if item.get("index")}

        # 检查字段是否已存在
        if field_name in norm_map:
            if skip_existing:
                skipped_existing += 1
                results.append(entity)
                continue
            return {
                "status": "error",
                "message": f"字段 '{field_name}' 已存在，请先删除或更换名称",
            }

        # 处理值
        result_value = field_value if field_value is not None else ""

        # 1. 添加 addFields filter
        parser = entity.get("parser") or {}
        # 入口规则模板的 filter 可能为 null，初始化为空数组再追加
        filters = parser.get("filter") or []

        # 删除后重新添加同名字段时，撤销对应 removeFields 标记；否则最终
        # 配置会同时声明“删除”和“添加”同一字段。其他删除项保持不变。
        retained_filters = []
        for filter_item in filters:
            if filter_item.get("name") != "removeFields" or not isinstance(
                filter_item.get("fields"), list
            ):
                retained_filters.append(filter_item)
                continue
            remaining_fields = [
                item for item in filter_item["fields"] if item != field_name
            ]
            if remaining_fields:
                filter_item["fields"] = remaining_fields
                retained_filters.append(filter_item)
        filters = retained_filters

        addfields_entry = {
            "name": "addFields",
            "id": "",
            "fields": {
                field_name: result_value,
            },
        }
        filters.append(addfields_entry)

        parser["filter"] = filters
        entity["parser"] = parser

        # 2. 添加 normalize 条目
        normalize_entry = {
            "mappings": [],
            "field": None,
            "sim": None,
            "result": [result_value] if result_value else [],
            "info": None,
            "entity": None,
            "required": False,
            "core": None,
            "value": None,
            "index": field_name,
        }
        for metadata_key in ("field", "entity", "sim", "core", "mappings", "value"):
            if normalize_metadata is not None and metadata_key in normalize_metadata:
                normalize_entry[metadata_key] = normalize_metadata[metadata_key]
        normalize.append(normalize_entry)
        entity["normalize"] = normalize

        applied += 1
        results.append(entity)

    message = f"成功为 {applied} 个 entity 添加字段 '{field_name}'"
    if targets is not None:
        message += f"（目标 {len(targets)} 个）"
    if skipped_existing:
        message += f"（{skipped_existing} 个已存在该字段，跳过）"
    if skipped:
        message += f"（跳过 {skipped} 个无 normalize 的 entity）"
    return {"status": "success", "data": results, "message": message}


# ---------------------------------------------------------------------------
# 事件名称绑定守卫（确定性规则，见 skills/_shared/event_binding.py）
# ---------------------------------------------------------------------------


def _entities_in_scope(data: list, target_names: Optional[List[str]]):
    targets = set(target_names) if target_names else None
    for entity in data:
        if targets is None or entity.get("name") in targets:
            yield entity


def _has_field(entity: dict, field_name: str) -> bool:
    """检查 entity 是否已存在某字段（normalize index 或 addFields 绑定）。"""
    for entry in entity.get("normalize") or []:
        if isinstance(entry, dict) and entry.get("index") == field_name:
            return True
    parser = entity.get("parser") or {}
    for filter_item in parser.get("filter") or []:
        if (
            isinstance(filter_item, dict)
            and filter_item.get("name") == "addFields"
            and filter_item.get("id") == ""
            and isinstance(filter_item.get("fields"), dict)
            and field_name in filter_item["fields"]
        ):
            return True
    return False


def _with_error_code(result: dict) -> dict:
    """给 add_field 的错误结果补稳定错误码。"""
    if result.get("status") == "error":
        message = str(result.get("message", ""))
        code = "invalid_input"
        if "已存在" in message:
            code = "field_conflict"
        result = dict(result)
        result.setdefault("code", code)
    return result


def add_field_guarded(
    data: list,
    field_name: str,
    field_value: Optional[str] = None,
    target_names: Optional[List[str]] = None,
    skip_existing: bool = False,
) -> dict:
    """带事件名称绑定守卫的字段添加。

    - 直接添加【事件级别】被拒绝：级别随【事件名称】按绑定表联动写入。
    - 【事件名称】必须是 21 个合法分类名之一且不支持引用型值；
      合法时自动联动写入绑定的【事件级别】（同目标范围）。
    - 目标范围内已存在【事件级别】时返回 event_level_conflict
      （skip_existing=True 时跳过该检查，由跳过语义兜底）。
    """
    if field_name == EVENT_LEVEL_FIELD:
        return {
            "status": "error",
            "code": "event_level_direct_add_rejected",
            "message": (
                "不支持单独添加【事件级别】；请添加【事件名称】，"
                "事件级别会按绑定关系自动联动写入"
            ),
        }
    if field_name == EVENT_NAME_FIELD:
        if isinstance(field_value, str) and field_value.startswith("%{"):
            return {
                "status": "error",
                "code": "invalid_event_name",
                "message": "【事件名称】必须是固定分类名，不支持引用型值",
            }
        if field_value not in EVENT_NAME_LEVEL_BINDING:
            legal = "、".join(EVENT_NAME_LEVEL_BINDING)
            return {
                "status": "error",
                "code": "invalid_event_name",
                "message": f"【事件名称】必须是以下分类名之一: {legal}",
            }
        if not skip_existing:
            for entity in _entities_in_scope(data, target_names):
                if _has_field(entity, EVENT_LEVEL_FIELD):
                    return {
                        "status": "error",
                        "code": "event_level_conflict",
                        "message": (
                            "【事件级别】已存在；修改【事件名称】请先删除"
                            "【事件名称】和【事件级别】再重新添加"
                        ),
                    }
        first = _with_error_code(
            add_field(
                data,
                EVENT_NAME_FIELD,
                field_value,
                target_names,
                skip_existing,
                normalize_metadata=event_name_normalize_metadata(field_value),
            )
        )
        if first.get("status") != "success":
            return first
        level = EVENT_NAME_LEVEL_BINDING[field_value]
        second = _with_error_code(
            add_field(
                first["data"],
                EVENT_LEVEL_FIELD,
                level,
                target_names,
                skip_existing,
                normalize_metadata=event_level_normalize_metadata(level),
            )
        )
        if second.get("status") != "success":
            return second
        return {
            "status": "success",
            "data": second["data"],
            "message": (
                f"{first['message']}，已按绑定关系联动写入【事件级别】={level}"
            ),
        }
    return _with_error_code(
        add_field(data, field_name, field_value, target_names, skip_existing)
    )


# ---------------------------------------------------------------------------
# CLI（文件输入/输出契约）
# ---------------------------------------------------------------------------


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="add_fields.py",
        description="在解析规则（mapping entities）中添加字段",
    )
    parser.add_argument(
        "--input", "-i", required=True,
        help="配置文件路径（Base64 txt / 原生 JSON / TXT，内容为 JSON 数组）",
    )
    parser.add_argument("--field", "-f", required=True, help="新字段名")
    parser.add_argument(
        "--value", "-v", default=None,
        help="字段值：固定值或 %%{index} 引用；缺省为空",
    )
    parser.add_argument(
        "--output", "-o", default=None,
        help="修改后配置 JSON 输出路径（缺省 <输入名>.modified.json）",
    )
    parser.add_argument(
        "--target", default=None,
        help="目标子规则名（按 name 精确寻址），逗号分隔；缺省全部 entity",
    )
    parser.add_argument(
        "--skip-existing", action="store_true",
        help="已存在同名字段的 entity 跳过而非整体失败",
    )
    parser.add_argument(
        "--no-export", action="store_true",
        help="不产出 Base64 导出文件（缺省会一并产出）",
    )
    args = parser.parse_args(argv)

    try:
        data = load_entities(args.input)
    except ConfigIOError as exc:
        print(
            json.dumps(
                {"status": "error", "code": exc.code, "message": exc.message},
                ensure_ascii=False,
            )
        )
        return 1

    target_names = None
    if args.target:
        target_names = [name.strip() for name in args.target.split(",") if name.strip()]

    result = add_field_guarded(
        data, args.field, args.value, target_names, args.skip_existing
    )
    if result.get("status") != "success":
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 1

    input_path = Path(args.input)
    output = (
        Path(args.output)
        if args.output
        else input_path.with_name(input_path.stem + ".modified.json")
    )
    written = skill_report.write_result(
        result["data"], output, make_export=not args.no_export
    )
    payload = {
        "status": "success",
        "message": result["message"],
        "output": str(written["json_path"]),
        "export": str(written["export_path"]) if written["export_path"] else None,
    }
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
