"""测试共用：合成 xlsx 夹具（openpyxl 现场生成，不入库二进制）。"""

from __future__ import annotations

from openpyxl import Workbook


def make_xlsx(path, rows, sheet_name="数据表", extra_sheets=()):
    """合成 xlsx：rows[0] 为列头行，其后为数据行；None 表示空单元格。"""
    workbook = Workbook()
    sheet = workbook.active
    sheet.title = sheet_name
    for row in rows:
        sheet.append(list(row))
    for name in extra_sheets:
        workbook.create_sheet(name)
    workbook.save(path)
