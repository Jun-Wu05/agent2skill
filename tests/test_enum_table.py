"""enum_table 读取器测试：映射表 Excel → 归一映射对的读取契约。

接缝：_shared/enum_table.py 的 load_enum_table(path) 与
normalize_pairs(raw_pairs)——返回 {fields, row_count} 或抛
EnumTableError(code, message)；归一规则（EQUAL 缺省 / REGULAR 包裹 /
回退语义）对 Excel 与 JSON 两入口一致。夹具用 excel_helpers 现场合成 xlsx。
"""

from __future__ import annotations

import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILLS = ROOT / "skills" / "parser-skills"
for path in (str(ROOT), str(ROOT / "tests"), str(SKILLS)):
    if path not in sys.path:
        sys.path.insert(0, path)

from _shared.enum_table import (  # noqa: E402
    EnumTableError,
    load_enum_table,
    normalize_pairs,
)
from excel_helpers import make_multi_sheet_xlsx  # noqa: E402

HEADER = ["mappingType", "orgValue", "mappingValue"]


class EnumTableLoadTest(unittest.TestCase):
    def setUp(self):
        tmp_root = ROOT / ".tmp_tests"
        tmp_root.mkdir(exist_ok=True)
        self._tmp = Path(tempfile.mkdtemp(dir=str(tmp_root)))
        self.addCleanup(self._cleanup)

    def _cleanup(self):
        shutil.rmtree(self._tmp, ignore_errors=True)
        tmp_root = ROOT / ".tmp_tests"
        if tmp_root.is_dir() and not any(tmp_root.iterdir()):
            tmp_root.rmdir()

    def _write(self, sheets, name="mappings.xlsx"):
        path = self._tmp / name
        make_multi_sheet_xlsx(path, sheets)
        return path

    def test_normalization_rules(self):
        path = self._write(
            [
                (
                    "event_type",
                    [
                        HEADER,
                        ["EQUAL", "login", "登录"],
                        [None, " logout ", " 注销 "],
                        ["REGULAR", "attack", None],
                        ["EQUAL", "", "空原始值"],
                        ["bogus", "x", "y"],
                        ["REGULAR", ".*deny.*", "拒绝"],
                        [None, None, None],
                    ],
                )
            ]
        )
        table = load_enum_table(path)
        self.assertEqual(table["row_count"], 5)
        self.assertEqual(len(table["fields"]), 1)
        entry = table["fields"][0]
        self.assertEqual(entry["field"], "event_type")
        self.assertEqual(
            entry["pairs"],
            [
                {"mappingType": "EQUAL", "orgValue": "login", "mappingValue": "登录"},
                {"mappingType": "EQUAL", "orgValue": "logout", "mappingValue": "注销"},
                # REGULAR 自动包裹；mappingValue 空回退（包裹后的）orgValue
                {
                    "mappingType": "REGULAR",
                    "orgValue": ".*attack.*",
                    "mappingValue": ".*attack.*",
                },
                # mappingType 非法回退 EQUAL
                {"mappingType": "EQUAL", "orgValue": "x", "mappingValue": "y"},
                # 已带 .* 前缀不再包裹
                {"mappingType": "REGULAR", "orgValue": ".*deny.*", "mappingValue": "拒绝"},
            ],
        )

    def test_multiple_sheets_keep_order_and_count(self):
        path = self._write(
            [
                ("b_field", [HEADER, ["EQUAL", "v1", "s1"]]),
                ("a_field", [HEADER, ["EQUAL", "v2", "s2"], ["EQUAL", "v3", "s3"]]),
            ]
        )
        table = load_enum_table(path)
        self.assertEqual(
            [entry["field"] for entry in table["fields"]], ["b_field", "a_field"]
        )
        self.assertEqual(table["row_count"], 3)

    def test_sheet_without_valid_rules_rejects_whole_workbook(self):
        path = self._write(
            [
                ("good", [HEADER, ["EQUAL", "v1", "s1"]]),
                ("bad", [HEADER, ["EQUAL", "", "空原始值"]]),
            ]
        )
        with self.assertRaises(EnumTableError) as caught:
            load_enum_table(path)
        self.assertEqual(caught.exception.code, "invalid_input")
        self.assertIn("bad", caught.exception.message)

    def test_empty_sheet_rejects_workbook(self):
        path = self._write([("good", [HEADER, ["EQUAL", "v1", "s1"]]), ("empty", [])])
        with self.assertRaises(EnumTableError) as caught:
            load_enum_table(path)
        self.assertEqual(caught.exception.code, "invalid_input")

    def test_header_only_sheet_rejects_workbook(self):
        path = self._write([("only_header", [HEADER])])
        with self.assertRaises(EnumTableError) as caught:
            load_enum_table(path)
        self.assertEqual(caught.exception.code, "invalid_input")

    def test_missing_file_raises_input_required(self):
        with self.assertRaises(EnumTableError) as caught:
            load_enum_table(self._tmp / "nope.xlsx")
        self.assertEqual(caught.exception.code, "input_required")

    def test_not_xlsx_raises_invalid_input(self):
        path = self._tmp / "bad.xlsx"
        path.write_text("不是 Excel", encoding="utf-8")
        with self.assertRaises(EnumTableError) as caught:
            load_enum_table(path)
        self.assertEqual(caught.exception.code, "invalid_input")


class NormalizePairsTest(unittest.TestCase):
    def test_json_pairs_share_excel_normalization(self):
        pairs = normalize_pairs(
            [
                {"orgValue": " login ", "mappingValue": "登录"},
                {"orgValue": "attack", "mappingValue": "", "mappingType": "REGULAR"},
                {"orgValue": "", "mappingValue": "空原始值"},
                {"orgValue": "ok", "mappingValue": "好", "mappingType": "equal"},
            ]
        )
        self.assertEqual(
            pairs,
            [
                {"mappingType": "EQUAL", "orgValue": "login", "mappingValue": "登录"},
                {
                    "mappingType": "REGULAR",
                    "orgValue": ".*attack.*",
                    "mappingValue": ".*attack.*",
                },
                {"mappingType": "EQUAL", "orgValue": "ok", "mappingValue": "好"},
            ],
        )

    def test_non_dict_item_raises(self):
        with self.assertRaises(ValueError):
            normalize_pairs(["junk"])

    def test_none_and_empty_input(self):
        self.assertEqual(normalize_pairs(None), [])
        self.assertEqual(normalize_pairs([]), [])


if __name__ == "__main__":
    unittest.main()
