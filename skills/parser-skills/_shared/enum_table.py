"""枚举映射表族输入：Sheet 名=目标字段的三列映射 Excel → 归一映射对。

契约（openpyxl 实现，映射表族读取的唯一入口，禁止在技能脚本内复制）：
- 每张工作表名 = 目标字段名；前三列按位置读：mappingType / orgValue /
  mappingValue，首行为列头从第 2 行读起（列头语言不限，按位置识别）；
- 空行跳过；mappingType 留空或非法回退 EQUAL（合法值 EQUAL / REGULAR，
  大小写不敏感）；REGULAR 且未以 ``.*`` 开头时自动加 ``.*`` 前后缀通配
  （行首 ``(?i)`` 标记保留在最前）；
  orgValue / mappingValue 去首尾空白；orgValue 为空跳过；mappingValue
  为空回退（包裹后的）orgValue；
- 任一工作表无有效规则 → 整表拒收，不产生部分结果；
- 返回 ``{"fields": [{"field": <Sheet 名>, "pairs": [...]}],
  "row_count": <有效行总数>}``，按工作表顺序。

normalize_pairs 供 JSON 映射对入口复用同一套归一规则（EQUAL 缺省 /
REGULAR 包裹 / 回退语义），两入口不得各自实现。
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

#: mappingType 合法值（写入 normalize[].mappings 的匹配方式）。
VALID_MAPPING_TYPES = ("EQUAL", "REGULAR")

#: REGULAR 行首大小写不敏感标记（对齐平台运行时正则语义）。
CASE_INSENSITIVE_PREFIX = "(?i)"


class EnumTableError(Exception):
    """映射表文件读取失败。code 为稳定错误码，message 面向用户。"""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def split_regular_prefix(org_value: str) -> Tuple[str, str]:
    """剥离 REGULAR 行首大小写不敏感标记，返回 (前缀, 主体)。

    归一（本模块，前缀保留在最前）与覆盖匹配（threat_policy，前缀转
    IGNORECASE flags）共用本函数，禁止两处各自识别。
    """
    if org_value[:4].lower() == CASE_INSENSITIVE_PREFIX:
        return org_value[:4], org_value[4:]
    return "", org_value


def normalize_pair(
    mapping_type: Any, org_value: Any, mapping_value: Any
) -> Optional[Dict[str, str]]:
    """归一一条映射对；orgValue 为空返回 None（该行跳过）。

    归一规则：mappingType 留空或非法回退 EQUAL；REGULAR 未以 ``.*``
    开头时自动加 ``.*`` 前后缀通配（行首 ``(?i)`` 大小写不敏感标记保留
    在最前、通配加在其后，对齐平台运行时正则语义）；orgValue /
    mappingValue 去首尾空白；mappingValue 为空回退（包裹后的）orgValue。
    """
    normalized_type = str(mapping_type or "").strip().upper()
    if normalized_type not in VALID_MAPPING_TYPES:
        normalized_type = "EQUAL"
    org = "" if org_value is None else str(org_value).strip()
    if not org:
        return None
    if normalized_type == "REGULAR":
        flag_prefix, body = split_regular_prefix(org)
        if not body.startswith(".*"):
            body = ".*" + body + ".*"
        org = flag_prefix + body
    mapped = "" if mapping_value is None else str(mapping_value).strip()
    if not mapped:
        mapped = org
    return {"mappingType": normalized_type, "orgValue": org, "mappingValue": mapped}


def normalize_pairs(raw_pairs: Any) -> List[Dict[str, str]]:
    """归一 JSON 映射对数组（与 Excel 入口共用归一规则）。

    非 dict 元素抛 ValueError（调用方转 invalid_input）；orgValue 为空
    的元素跳过（与 Excel 行为一致）。
    """
    pairs: List[Dict[str, str]] = []
    for item in raw_pairs or []:
        if not isinstance(item, dict):
            raise ValueError("映射对必须是对象（orgValue / mappingValue / mappingType）")
        pair = normalize_pair(
            item.get("mappingType"), item.get("orgValue"), item.get("mappingValue")
        )
        if pair is not None:
            pairs.append(pair)
    return pairs


def load_enum_table(path: Union[str, Path]) -> Dict[str, Any]:
    """读取枚举映射表 Excel，返回 {fields, row_count}。

    文件缺失抛 input_required；形状不符（非 xlsx、无工作表、任一
    工作表无有效规则）抛 invalid_input——整表拒收，不产生部分结果。
    """
    file_path = Path(path)
    if not file_path.is_file():
        raise EnumTableError("input_required", f"找不到映射表文件: {file_path}")

    from openpyxl import load_workbook

    try:
        workbook = load_workbook(file_path, read_only=True)
    except Exception as exc:  # openpyxl 对损坏文件抛多种异常，统一收口
        raise EnumTableError(
            "invalid_input", f"无法读取 Excel 文件（可能不是 xlsx 格式）: {exc}"
        ) from exc

    try:
        if not workbook.sheetnames:
            raise EnumTableError("invalid_input", "映射表文件没有任何工作表")
        fields: List[Dict[str, Any]] = []
        row_count = 0
        for sheet_name in workbook.sheetnames:
            sheet = workbook[sheet_name]
            pairs: List[Dict[str, str]] = []
            for row in sheet.iter_rows(min_row=2, max_col=3, values_only=True):
                mapping_type = row[0] if len(row) > 0 else None
                org_value = row[1] if len(row) > 1 else None
                mapping_value = row[2] if len(row) > 2 else None
                pair = normalize_pair(mapping_type, org_value, mapping_value)
                if pair is not None:
                    pairs.append(pair)
            if not pairs:
                raise EnumTableError(
                    "invalid_input", f"枚举映射 Sheet「{sheet_name}」没有有效规则"
                )
            row_count += len(pairs)
            fields.append({"field": sheet_name, "pairs": pairs})
    finally:
        workbook.close()

    return {"fields": fields, "row_count": row_count}
