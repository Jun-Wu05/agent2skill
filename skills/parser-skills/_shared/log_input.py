"""Excel 数据族输入：日志数据表 → raw_log_lines 的确定性读取。

契约（照工作台 web/file_handlers 的行为复刻，openpyxl 实现）：
- 只读第一张工作表；
- 列头 = 首行，列名**包含**「原始日志」子串即命中（容忍「原始日志（脱敏后）」
  等变体），取第一个命中列；
- 缺「原始日志」列 / 无有效数据行 / 非 Excel 文件 / 无工作表 → 整单拒收，
  不产生部分结果；
- 空单元格（None/纯空白）跳过；单元格内换行（\\r\\n）替换为空格，防止单条
  日志被拆散成多行碎片；
- 返回 {raw_log_lines: list[str], columns: list[str], sheet: str}，
  columns 为下游字段映射场景预留。

数据族文件读取必须经过本模块，禁止在技能脚本内复制读取逻辑。
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Union

RAW_LOG_COLUMN_KEY = "原始日志"

_NEWLINE_RE = re.compile(r"[\r\n]+")


class LogInputError(Exception):
    """数据文件读取失败。code 为稳定错误码，message 面向用户。"""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def _cell_to_line(value: Any) -> Union[str, None]:
    """单元格值 → 日志行；空单元格（None/纯空白）返回 None。"""
    if value is None:
        return None
    text = str(value)
    if not text.strip():
        return None
    return _NEWLINE_RE.sub(" ", text)


def load_log_table(path: Union[str, Path]) -> dict:
    """读取 Excel 日志数据表，返回 raw_log_lines / columns / sheet。

    文件缺失抛 input_required；形状不符（非 Excel、无工作表、空表、
    缺「原始日志」列、该列无有效数据）抛 invalid_input。
    """
    from openpyxl import load_workbook

    file_path = Path(path)
    if not file_path.is_file():
        raise LogInputError("input_required", f"找不到数据文件: {file_path}")

    try:
        workbook = load_workbook(file_path, read_only=True)
    except Exception as exc:  # openpyxl 对损坏文件抛多种异常，统一收口
        raise LogInputError(
            "invalid_input", f"无法读取 Excel 文件（可能不是 xlsx 格式）: {exc}"
        ) from exc

    try:
        # 防御性守卫：正常工具产不出零工作表的 xlsx（openpyxl/Excel 均拒绝
        # 保存），但手改压缩包可造出，此时整单拒收
        if not workbook.sheetnames:
            raise LogInputError("invalid_input", "Excel 文件没有任何工作表")
        sheet = workbook[workbook.sheetnames[0]]
        sheet_name = sheet.title
        rows = list(sheet.iter_rows(values_only=True))
    finally:
        workbook.close()

    if not rows:
        raise LogInputError("invalid_input", "Excel 数据表为空（无列头行）")

    header = ["" if cell is None else str(cell) for cell in rows[0]]
    raw_index = next(
        (idx for idx, name in enumerate(header) if RAW_LOG_COLUMN_KEY in name),
        None,
    )
    if raw_index is None:
        raise LogInputError(
            "invalid_input",
            f"数据表缺少「{RAW_LOG_COLUMN_KEY}」列，实际列头: {header}",
        )

    raw_log_lines = []
    for row in rows[1:]:
        value = row[raw_index] if raw_index < len(row) else None
        line = _cell_to_line(value)
        if line is not None:
            raw_log_lines.append(line)

    if not raw_log_lines:
        raise LogInputError(
            "invalid_input", f"「{RAW_LOG_COLUMN_KEY}」列没有有效数据行"
        )

    return {"raw_log_lines": raw_log_lines, "columns": header, "sheet": sheet_name}
