"""base64 解码字段 - 对解析规则中的指定字段启用运行时 base64 解码。

field-adjust 技能的 base64-decode 子命令：文件输入/输出契约，无 session、
无外部依赖；对每个目标 entity 在（或新建的）解码 addFields 过滤器中写入
``{字段名: Base64Decode OGNL}``，运行时由解析器**原地覆盖**字段值；
不新增字段、不双写 normalize（与添加字段的双写语义不同）。重复调用
幂等：合并进已有解码过滤器，不重复追加。

CLI 用法:
    python decode_fields.py --input <配置文件> --fields req_header,req_body
                            [--target 规则A,规则B]
                            [--group {all,threat,non-threat}]
                            [--output <输出.json>] [--no-export]

输入支持: Base64 txt / 原生 JSON / TXT（须为 JSON 数组）
输出: 修改后配置 JSON + 平台可导入的 Base64 文件（fieldadjusted_config_YYYYMMDD_HHMM.txt）
"""

from __future__ import annotations

import copy
import sys
from pathlib import Path
from typing import List, Optional

_SKILLS_ROOT = Path(__file__).resolve().parents[2]
if str(_SKILLS_ROOT) not in sys.path:
    sys.path.insert(0, str(_SKILLS_ROOT))

from _shared import cli  # noqa: E402
from _shared.entity_scope import resolve_field_scope  # noqa: E402
from _shared.event_binding import EVENT_LEVEL_FIELD, EVENT_NAME_FIELD  # noqa: E402
from _shared.field_policy import RESERVED_FIELDS  # noqa: E402

# 运行时 OGNL 解码语句模板：值原地覆盖原字段（key=字段名）
_OGNL_TEMPLATE = "<%@com.hansight.dataviewer.utils.Base64@Base64Decode({field})%>"


def _is_decode_filter(filter_item: dict) -> bool:
    """判断 addFields filter 是否为 base64 解码过滤器（全部值都是解码 OGNL）。"""
    if filter_item.get("name") != "addFields" or filter_item.get("id") != "":
        return False
    fields = filter_item.get("fields")
    if not isinstance(fields, dict) or not fields:
        return False
    return all(
        isinstance(value, str) and "Base64Decode(" in value
        for value in fields.values()
    )


def _validate_decode_args(data: list, field_names: List[str]) -> Optional[dict]:
    """输入校验（decode_fields 与 decode_fields_guarded 共用）。"""
    if not data:
        return {"status": "error", "code": "invalid_input", "message": "输入数据为空"}
    if not field_names:
        return {"status": "error", "code": "invalid_input", "message": "未指定要解码的字段"}
    return None


def decode_fields(
    data: list,
    field_names: List[str],
    target_names: Optional[List[str]] = None,
) -> dict:
    """
    对 mapping entity 列表的指定字段启用 base64 解码（per-entity 自适应）

    只改 parser.filter：在（或新建的）解码 addFields 过滤器中写入
    ``{字段名: Base64Decode OGNL}``，运行时由解析器原地覆盖字段值；
    不改 normalize（与添加字段的双写语义不同）。

    子规则字段集互不相同：字段齐全的 entity 启用解码；缺任一字段的
    entity 跳过并按子规则名报告；所有目标 entity 都缺字段时返回
    field_not_found（只点名真正缺失的字段 + 全部子规则字段并集预览）。

    Args:
        data: 解码后的 JSON 数组（mapping entities）
        field_names: 需要 base64 解码的字段名列表
        target_names: 目标 entity 名单（按 name 精确匹配）；
                      None 表示全部 entity。名单外的 entity 原样透传。

    Returns:
        {"status": "success"|"error", "data": [...], "message": "..."}
    """
    error = _validate_decode_args(data, field_names)
    if error is not None:
        return error

    targets = set(target_names) if target_names else None
    results = []
    applied = 0
    skipped_empty = 0
    skipped_reasons: list[tuple[str, str]] = []
    all_missing_field = True
    missing_anywhere: set[str] = set()
    union_indexes: set[str] = set()

    for entity in data:
        entity = copy.deepcopy(entity)

        if targets is not None and entity.get("name") not in targets:
            results.append(entity)
            continue

        normalize = entity.get("normalize") or []
        name = entity.get("name") or "<未命名>"
        if not normalize:
            skipped_empty += 1
            results.append(entity)
            continue

        norm_indexes = {item.get("index") for item in normalize if item.get("index")}
        union_indexes.update(norm_indexes)

        missing = [f for f in field_names if f not in norm_indexes]
        if missing:
            missing_anywhere.update(missing)
            skipped_reasons.append((name, f"缺 {'、'.join(missing)}"))
            results.append(entity)
            continue
        all_missing_field = False

        parser = entity.get("parser") or {}
        # 入口规则模板的 filter 可能为 null，初始化为空数组再追加
        filters = parser.get("filter") or []

        # 合并进已有的解码过滤器，保持幂等（重复调用不重复追加）
        decode_filter = next((f for f in filters if _is_decode_filter(f)), None)
        if decode_filter is None:
            decode_filter = {"fields": {}, "name": "addFields", "id": ""}
            filters.append(decode_filter)

        for field_name in field_names:
            decode_filter["fields"][field_name] = _OGNL_TEMPLATE.format(field=field_name)

        parser["filter"] = filters
        entity["parser"] = parser

        applied += 1
        results.append(entity)

    # 所有目标 entity 都缺字段 → 真正的 field_not_found（并集词表辅助定位）
    if applied == 0 and skipped_reasons and all_missing_field:
        preview = "、".join(sorted(union_indexes)[:30])
        missing_names = [f for f in field_names if f in missing_anywhere]
        return {
            "status": "error",
            "code": "field_not_found",
            "message": (
                f"字段 {'、'.join(missing_names)} 不存在于任何（目标）子规则；"
                f"全部子规则字段并集: {preview}"
                + ("等" if len(union_indexes) > 30 else "")
            ),
        }

    message = f"成功为 {applied} 个 entity 启用 base64 解码: {', '.join(field_names)}"
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
# 解码守卫链（寻址 / 保留字段 / 事件绑定字段）
# ---------------------------------------------------------------------------


def decode_fields_guarded(
    data: list,
    field_names: List[str],
    target_names: Optional[List[str]] = None,
    group: str = "all",
) -> dict:
    """带守卫链的 base64 字段解码。

    守卫顺序（任一命中即拒绝，稳定错误码）：
    1. data / 字段名空校验 → invalid_input；
    2. 寻址解析：target 未知名 → rule_name_not_found；group 分组
       无标注 → event_annotation_required、组内无匹配 → rule_name_not_found；
    3. 任一字段为系统保留字段 → reserved_field_rejected（original_log 是
       原始日志审计锚点，运行时被 OGNL 覆盖会断审计链）；
    4. 任一字段为【事件名称】/【事件级别】→ invalid_event_name
       （解码会破坏事件绑定，事件字段请走添加字段）。
    """
    error = _validate_decode_args(data, field_names)
    if error is not None:
        return error

    targets, scope_error = resolve_field_scope(data, target_names, group)
    if scope_error is not None:
        return scope_error

    reserved = [f for f in field_names if f in RESERVED_FIELDS]
    if reserved:
        return {
            "status": "error",
            "code": "reserved_field_rejected",
            "message": (
                f"字段 {'、'.join(reserved)} 为系统保留字段，"
                "不允许启用 base64 解码"
            ),
        }

    event_fields = [
        f for f in field_names if f in (EVENT_NAME_FIELD, EVENT_LEVEL_FIELD)
    ]
    if event_fields:
        return {
            "status": "error",
            "code": "invalid_event_name",
            "message": (
                f"字段 {'、'.join(event_fields)} 为事件绑定字段，"
                "解码会破坏事件名称/事件级别绑定；"
                "事件字段请通过添加字段设置（自动按绑定关系联动写入）"
            ),
        }

    return decode_fields(data, field_names, targets)


# ---------------------------------------------------------------------------
# CLI（文件输入/输出契约，同形骨架见 _shared/cli.py）
# ---------------------------------------------------------------------------


_SPEC = cli.CliSpec(
    prog="decode_fields.py",
    description="对解析规则（mapping entities）中的指定字段启用运行时 base64 解码",
    arguments=(
        (
            ("--fields", "-f"),
            {
                "required": True,
                "help": "要 base64 解码的字段名，逗号分隔（须为已有字段，解码原地覆盖其值）",
            },
        ),
    ),
    execute=lambda args, data, target_names: decode_fields_guarded(
        data, cli.parse_csv(args.fields), target_names, args.group
    ),
)


def main(argv: Optional[List[str]] = None) -> int:
    return cli.run_cli(_SPEC, argv)


if __name__ == "__main__":
    sys.exit(main())
