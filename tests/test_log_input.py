"""log_input 单元测试：Excel 数据族读取契约（照工作台行为复刻）。

接缝：_shared.log_input.load_log_table(path) -> dict，以及
LogInputError(code, message) 稳定错误码。夹具用 openpyxl 在临时目录
现场合成 xlsx，不入库二进制。
"""

from __future__ import annotations

import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for path in (str(ROOT), str(ROOT / "skills" / "parser-skills")):
    if path not in sys.path:
        sys.path.insert(0, path)

from openpyxl import Workbook  # noqa: E402

from _shared import log_input  # noqa: E402


def _make_xlsx(path, rows, sheet_name="数据表", extra_sheets=()):
    """合成 xlsx：rows[0] 为列头行，其后为数据行；None 表示空单元格。"""
    workbook = Workbook()
    sheet = workbook.active
    sheet.title = sheet_name
    for row in rows:
        sheet.append(list(row))
    for name in extra_sheets:
        workbook.create_sheet(name)
    workbook.save(path)


class LoadLogTableTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self._tmp, ignore_errors=True)

    def _path(self, name="logs.xlsx"):
        return Path(self._tmp) / name

    def test_reads_raw_log_lines_with_columns_and_sheet(self):
        path = self._path()
        _make_xlsx(path, [["序号", "原始日志", "备注"], [1, "log line A", "x"], [2, "log line B", "y"]])
        result = log_input.load_log_table(path)
        self.assertEqual(result["raw_log_lines"], ["log line A", "log line B"])
        self.assertEqual(result["columns"], ["序号", "原始日志", "备注"])
        self.assertEqual(result["sheet"], "数据表")

    def test_column_substring_match_hits(self):
        path = self._path()
        _make_xlsx(path, [["原始日志（脱敏后）"], ["type=attack src=1.1.1.1"]])
        result = log_input.load_log_table(path)
        self.assertEqual(result["raw_log_lines"], ["type=attack src=1.1.1.1"])

    def test_missing_column_rejected_with_columns_in_message(self):
        path = self._path()
        _make_xlsx(path, [["时间", "事件"], ["t1", "e1"]])
        with self.assertRaises(log_input.LogInputError) as ctx:
            log_input.load_log_table(path)
        self.assertEqual(ctx.exception.code, "invalid_input")
        self.assertIn("原始日志", ctx.exception.message)
        self.assertIn("时间", ctx.exception.message)

    def test_header_only_table_rejected(self):
        path = self._path()
        _make_xlsx(path, [["原始日志"]])
        with self.assertRaises(log_input.LogInputError) as ctx:
            log_input.load_log_table(path)
        self.assertEqual(ctx.exception.code, "invalid_input")

    def test_fully_empty_sheet_rejected(self):
        path = self._path()
        _make_xlsx(path, [])
        with self.assertRaises(log_input.LogInputError) as ctx:
            log_input.load_log_table(path)
        self.assertEqual(ctx.exception.code, "invalid_input")

    def test_raw_column_all_empty_rejected(self):
        path = self._path()
        _make_xlsx(path, [["原始日志", "备注"], [None, "x"], [None, "y"]])
        with self.assertRaises(log_input.LogInputError) as ctx:
            log_input.load_log_table(path)
        self.assertEqual(ctx.exception.code, "invalid_input")

    def test_missing_file_input_required(self):
        with self.assertRaises(log_input.LogInputError) as ctx:
            log_input.load_log_table(self._path("no_such.xlsx"))
        self.assertEqual(ctx.exception.code, "input_required")

    def test_not_excel_rejected(self):
        path = self._path()
        path.write_text("这不是 Excel，就是普通文本", encoding="utf-8")
        with self.assertRaises(log_input.LogInputError) as ctx:
            log_input.load_log_table(path)
        self.assertEqual(ctx.exception.code, "invalid_input")

    def test_cell_newlines_replaced_with_space(self):
        path = self._path()
        _make_xlsx(path, [["原始日志"], ["line1\r\nline2\n\nline3"]])
        result = log_input.load_log_table(path)
        self.assertEqual(result["raw_log_lines"], ["line1 line2 line3"])

    def test_empty_cells_skipped(self):
        path = self._path()
        _make_xlsx(path, [["原始日志"], [None], ["kept"], [""]])
        result = log_input.load_log_table(path)
        self.assertEqual(result["raw_log_lines"], ["kept"])

    def test_non_string_cells_stringified(self):
        path = self._path()
        _make_xlsx(path, [["原始日志"], [12345], [3.5]])
        result = log_input.load_log_table(path)
        self.assertEqual(result["raw_log_lines"], ["12345", "3.5"])

    def test_first_sheet_used_when_multiple(self):
        path = self._path()
        _make_xlsx(path, [["原始日志"], ["from-first-sheet"]], extra_sheets=["第二张"])
        result = log_input.load_log_table(path)
        self.assertEqual(result["raw_log_lines"], ["from-first-sheet"])
        self.assertEqual(result["sheet"], "数据表")

    def test_first_matching_column_wins(self):
        path = self._path()
        _make_xlsx(path, [["原始日志", "原始日志副本"], ["左列", "右列"]])
        result = log_input.load_log_table(path)
        self.assertEqual(result["raw_log_lines"], ["左列"])

    def test_short_rows_treated_as_empty_cell(self):
        path = self._path()
        _make_xlsx(path, [["备注", "原始日志"], ["only-remark"]])
        # 数据行缺「原始日志」列 → 该行视为空单元格；列全空 → 拒收
        with self.assertRaises(log_input.LogInputError) as ctx:
            log_input.load_log_table(path)
        self.assertEqual(ctx.exception.code, "invalid_input")


if __name__ == "__main__":
    unittest.main()
