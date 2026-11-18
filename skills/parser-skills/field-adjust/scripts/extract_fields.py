"""正则提取字段 - 从解析规则的已有字段中按正则提取新字段。

field-adjust 技能的 regex-extract 子命令：文件输入/输出契约，无 session、
无外部依赖；对每个目标 entity 双写 ``parser.filter`` 的 customFunction
过滤器（functionName=extractRegexField，args 三元组 = 新增字段 / 被提取
字段 / 正则）与 normalize 末尾的新字段预览条目（预览值取第一个捕获组，
无捕获组取整条匹配）。

正则表达式由宿主 agent 按样本生成后传入；脚本只做确定性校验：必须可
编译（否则 invalid_pattern），有样本时必须 ``re.fullmatch`` 全匹配整条
样本（非全匹配不生效，整体拒绝 pattern_mismatch）。

CLI 用法:
    python extract_fields.py --input <配置文件> --source-field original_log
                            --pattern '<正则>' [--field 新字段]
                            [--keyword 关键词]
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
import re
import sys
from pathlib import Path
from typing import List, Optional

_SKILLS_ROOT = Path(__file__).resolve().parents[2]
if str(_SKILLS_ROOT) not in sys.path:
    sys.path.insert(0, str(_SKILLS_ROOT))

from _shared import report as skill_report  # noqa: E402
from _shared.config_io import ConfigIOError, load_entities  # noqa: E402
from _shared.entity_scope import entities_in_scope, resolve_field_scope  # noqa: E402
from _shared.event_binding import EVENT_LEVEL_FIELD, EVENT_NAME_FIELD  # noqa: E402
from _shared.field_policy import RESERVED_FIELDS  # noqa: E402

# 运行时 OGNL 提取语句（固定；arg2=被提取字段，arg3=正则）
_OGNL_TEMPLATE = (
    '<%@com.hansight.dataviewer.utils.ognl.OgnlUtils@regexExtraction(arg2,"arg3")%>'
)


def _base_name(keyword: Optional[str], source_field: str) -> str:
    """缺省命名基准：提取关键词优先，无关键词时退回源字段名尾段。"""
    return (keyword or "").strip() or source_field.rsplit(".", 1)[-1]


def _default_field_name(
    keyword: Optional[str], source_field: str, norm_map: dict
) -> str:
    """缺省命名：基准名已存在时加 new 前缀消解冲突。"""
    base = _base_name(keyword, source_field)
    if base not in norm_map:
        return base
    return f"new{base}"


def _normalize_entry(index: str, result_value: str) -> dict:
    """构建正则提取新增字段的 normalize 条目（result 为样本预览值）。"""
    return {
        "mappings": [],
        "field": None,
        "sim": None,
        "result": [result_value] if result_value else [],
        "info": None,
        "entity": None,
        "required": False,
        "core": None,
        "value": None,
        "index": index,
    }


def _build_function_item(new_field: str, source_field: str, pattern: str) -> dict:
    """构建一个 extractRegexField 函数条目（args 三元组）。"""
    return {
        "functionName": "extractRegexField",
        "ognl": _OGNL_TEMPLATE,
        "functionViewName": "正则提取",
        "fieldName": "",
        "args": [
            {
                "name": "新增字段",
                "args": "arg1",
                "detail": "新增字段名称",
                "type": "field",
                "value": new_field,
            },
            {
                "name": "被提取字段",
                "args": "arg2",
                "detail": "字符格式字段",
                "type": "args",
                "value": source_field,
            },
            {
                "name": "正则表达式",
                "args": "arg3",
                "detail": "只提取第一个匹配项",
                "type": "args",
                "value": pattern,
            },
        ],
    }


def _is_custom_function_filter(filter_item: dict) -> bool:
    """判断 filter 是否为可合并的 customFunction 过滤器。"""
    return (
        filter_item.get("name") == "customFunction"
        and filter_item.get("id") == ""
    )


def _validate_extract_args(data: list, source_field: str, pattern: str) -> Optional[dict]:
    """输入校验（extract_field 与 extract_field_guarded 共用）。"""
    if not data:
        return {"status": "error", "code": "invalid_input", "message": "输入数据为空"}
    if not source_field:
        return {"status": "error", "code": "invalid_input", "message": "未指定被提取字段"}
    if not pattern:
        return {"status": "error", "code": "invalid_input", "message": "未指定正则表达式"}
    try:
        re.compile(pattern)
    except re.error as error:
        return {
            "status": "error",
            "code": "invalid_pattern",
            "message": f"正则表达式不合法: {error}",
        }
    return None


def extract_field(
    data: list,
    new_field: Optional[str],
    source_field: str,
    pattern: str,
    keyword: Optional[str] = None,
    target_names: Optional[List[str]] = None,
) -> dict:
    """
    对 mapping entity 列表新增正则提取字段（per-entity 自适应）。

    双写：parser.filter 追加（或合并进）customFunction 过滤器；
    normalize 末尾追加新字段条目。被提取字段有样本值时，正则必须
    **全匹配**整条样本（非全匹配不生效，整体拒绝）；预览值取第一个
    捕获组（无捕获组取整条匹配）。

    Args:
        data: 解码后的 JSON 数组（mapping entities）
        new_field: 新字段名；None 时按 keyword（提取目标关键词）自动
            命名——关键词已存在则加 new 前缀；keyword 也缺省时退回
            被提取字段名尾段。
        source_field: 被提取字段（必须为 normalize 里的 index；可为
            original_log 等「原始日志里的 X」主用例字段）
        pattern: 正则表达式（必须可编译、全匹配样本整条）
        keyword: 提取目标关键词（如 "client"、"Referer"），缺省命名用
        target_names: 目标 entity 名单（按 name 精确匹配）；
            None 表示全部 entity。名单外的 entity 原样透传。

    Returns:
        {"status": "success"|"error", "code"?, "data"?, "message": "..."}
    """
    error = _validate_extract_args(data, source_field, pattern)
    if error is not None:
        return error
    compiled = re.compile(pattern)

    targets = set(target_names) if target_names else None
    results = []
    applied = 0
    skipped_empty = 0
    skipped_reasons: list[tuple[str, str]] = []
    all_missing_source = True
    union_indexes: set[str] = set()
    resolved_name = new_field or None

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

        norm_map = {item.get("index"): item for item in normalize if item.get("index")}
        union_indexes.update(norm_map)

        # 缺被提取字段的子规则跳过并按名报告（子规则字段集互不相同）
        if source_field not in norm_map:
            skipped_reasons.append((name, f"缺 {source_field}"))
            results.append(entity)
            continue
        all_missing_source = False

        # 新字段名解析：显式传入优先；缺省按提取关键词命名（冲突加 new 前缀）
        if not resolved_name:
            resolved_name = _default_field_name(keyword, source_field, norm_map)
        if resolved_name in norm_map:
            return {
                "status": "error",
                "code": "field_conflict",
                "message": f"新增字段 '{resolved_name}' 已存在，请先删除或更换名称",
            }

        # 样本验证：正则必须全匹配整条样本（非全匹配不生效，整体拒绝）
        sample_entry = norm_map.get(source_field, {})
        sample_result = sample_entry.get("result") or []
        sample_text = str(sample_result[0]) if sample_result else ""
        preview_value = ""
        if sample_text:
            matched = compiled.fullmatch(sample_text)
            if matched is None:
                return {
                    "status": "error",
                    "code": "pattern_mismatch",
                    "message": (
                        f"正则无法全匹配「{source_field}」的样本"
                        "（必须整条匹配才能生效），请调整正则或样本"
                    ),
                }
            preview_value = matched.group(1) if matched.groups() else matched.group(0)

        # 1. 追加（或合并进）customFunction 过滤器
        parser = entity.get("parser") or {}
        # 入口规则模板的 filter 可能为 null，初始化为空数组再追加
        filters = parser.get("filter") or []
        custom_filter = next(
            (f for f in filters if _is_custom_function_filter(f)), None
        )
        if custom_filter is None:
            custom_filter = {
                "custom_name": "extractRegexField",
                "fields": [],
                "name": "customFunction",
                "id": "",
            }
            filters.append(custom_filter)

        function_item = _build_function_item(resolved_name, source_field, pattern)
        existing_index = next(
            (
                i for i, item in enumerate(custom_filter.get("fields") or [])
                if isinstance(item, dict)
                and any(
                    arg.get("args") == "arg1" and arg.get("value") == resolved_name
                    for arg in item.get("args", [])
                    if isinstance(arg, dict)
                )
            ),
            None,
        )
        if existing_index is not None:
            custom_filter["fields"][existing_index] = function_item
        else:
            custom_filter["fields"].append(function_item)

        parser["filter"] = filters
        entity["parser"] = parser

        # 2. normalize 双写（预览值）；同名函数条目覆盖时不再追加
        if existing_index is None:
            normalize.append(_normalize_entry(resolved_name, preview_value))
            entity["normalize"] = normalize

        applied += 1
        results.append(entity)

    # 所有目标子规则都缺被提取字段 → 真正的 field_not_found（并集词表辅助定位）
    if applied == 0 and skipped_reasons and all_missing_source:
        preview = "、".join(sorted(union_indexes)[:30])
        return {
            "status": "error",
            "code": "field_not_found",
            "message": (
                f"字段 {source_field} 不存在于任何（目标）子规则；"
                f"全部子规则字段并集: {preview}"
                + ("等" if len(union_indexes) > 30 else "")
            ),
        }

    display_name = resolved_name or _base_name(keyword, source_field)
    message = (
        f"成功为 {applied} 个 entity 添加正则提取字段 '{display_name}'"
        f"（来源: {source_field}）"
    )
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
# 提取守卫链（寻址 / 新增字段名保留字段 / 新增字段名事件绑定字段）
# ---------------------------------------------------------------------------


def extract_field_guarded(
    data: list,
    new_field: Optional[str],
    source_field: str,
    pattern: str,
    keyword: Optional[str] = None,
    target_names: Optional[List[str]] = None,
    group: str = "all",
) -> dict:
    """带守卫链的正则提取字段。

    守卫顺序（任一命中即拒绝，稳定错误码）：
    1. data / 被提取字段 / 正则空校验与编译校验 → invalid_input /
       invalid_pattern；
    2. 寻址解析：target 未知名 → rule_name_not_found；group 分组无标注
       → event_annotation_required、组内无匹配 → rule_name_not_found；
    3. 新增字段名（显式传入，或缺省命名消解后的终名）为系统保留字段
       → reserved_field_rejected（只拦新增字段名——被提取字段不受限，
       original_log 是「原始日志里的 X」主用例；缺省命名在首个将执行
       写入的子规则上模拟消解，基准名撞保留字段但会加 new 前缀消解
       时不误拦）；
    4. 新增字段名为【事件名称】/【事件级别】→ invalid_event_name
       （提取值无 21 分类保证，事件字段请走添加字段）。
    """
    error = _validate_extract_args(data, source_field, pattern)
    if error is not None:
        return error

    targets, scope_error = resolve_field_scope(data, target_names, group)
    if scope_error is not None:
        return scope_error

    # 新增字段名守卫的对象是实际写入的名字：显式传入直接查；缺省
    # 命名先模拟首个将执行写入的子规则上的消解（new 前缀）再查终名
    # ——基准名撞保留字段但会消解为 new 前缀名时不误拦（如
    # source=original_log 且不带 --field/--keyword 的主用例调用形态）
    if new_field:
        candidate_name = new_field
    else:
        candidate_name = _base_name(keyword, source_field)
        for entity in entities_in_scope(data, targets):
            norm_indexes = {
                item.get("index")
                for item in entity.get("normalize") or []
                if item.get("index")
            }
            if source_field in norm_indexes:
                candidate_name = _default_field_name(
                    keyword, source_field, norm_indexes
                )
                break
    if candidate_name in RESERVED_FIELDS:
        return {
            "status": "error",
            "code": "reserved_field_rejected",
            "message": (
                f"新增字段名 '{candidate_name}' 为系统保留字段，"
                "不允许作为正则提取的目标字段"
            ),
        }

    if candidate_name in (EVENT_NAME_FIELD, EVENT_LEVEL_FIELD):
        return {
            "status": "error",
            "code": "invalid_event_name",
            "message": (
                f"新增字段名 '{candidate_name}' 为事件绑定字段，"
                "提取值无 21 分类保证，会破坏事件名称/事件级别绑定；"
                "事件字段请通过添加字段设置（自动按绑定关系联动写入）"
            ),
        }

    return extract_field(
        data,
        new_field,
        source_field,
        pattern,
        keyword=keyword,
        target_names=targets,
    )


# ---------------------------------------------------------------------------
# CLI（文件输入/输出契约）
# ---------------------------------------------------------------------------


def main(argv: Optional[List[str]] = None) -> int:
    """CLI 入口：文件契约包装（读配置 → 守卫链 → 双写 → 落盘报告）。"""
    parser = argparse.ArgumentParser(
        prog="extract_fields.py",
        description="从解析规则（mapping entities）的已有字段中按正则提取新字段",
    )
    parser.add_argument(
        "--input", "-i", required=True,
        help="配置文件路径（Base64 txt / 原生 JSON / TXT，内容为 JSON 数组）",
    )
    parser.add_argument(
        "--source-field", "-s", required=True,
        help="被提取字段名（须为已有字段，如 original_log / req_header）",
    )
    parser.add_argument(
        "--pattern", "-p", required=True,
        help="正则表达式（由 agent 按样本生成；必须全匹配样本整条才生效）",
    )
    parser.add_argument(
        "--field", default=None,
        help="新字段名；缺省按 --keyword 命名（冲突加 new 前缀），"
             "再退回源字段名尾段",
    )
    parser.add_argument(
        "--keyword", default=None,
        help="提取目标关键词（如 client、Referer），缺省命名用",
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
        "--group", default="all", choices=["all", "threat", "non-threat"],
        help="按已标注事件名称分组寻址（threat=威胁组 / non-threat=非威胁组）；"
             "与 --target 并存时 target 优先",
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

    new_field = args.field or None  # 空串归一为 None（触发缺省命名链）
    target_names = None
    if args.target:
        target_names = [name.strip() for name in args.target.split(",") if name.strip()]

    result = extract_field_guarded(
        data,
        new_field,
        args.source_field,
        args.pattern,
        keyword=args.keyword,
        target_names=target_names,
        group=args.group,
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
