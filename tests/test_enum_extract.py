"""enum_extract CLI 端到端测试：日志 Excel → 枚举值 JSON 的文件契约。

接缝：enum-mapping/scripts/enum_extract.py 的 main(argv)——
stdout JSON（status/message/output[/template] 或 status/error/code/message）
+ 枚举值 JSON 产物 + 可选映射表模板 xlsx + 退出码。
夹具用 excel_helpers 现场合成 xlsx。
"""

from __future__ import annotations

import contextlib
import io
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILLS = ROOT / "skills" / "parser-skills"
SCRIPTS = SKILLS / "enum-mapping" / "scripts"
for path in (str(ROOT), str(ROOT / "tests"), str(SKILLS), str(SCRIPTS)):
    if path not in sys.path:
        sys.path.insert(0, path)

import enum_extract  # noqa: E402
from _shared.enum_table import load_enum_table  # noqa: E402
from excel_helpers import make_xlsx  # noqa: E402


class EnumExtractCliTest(unittest.TestCase):
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

    def _xlsx(self, lines, name="logs.xlsx"):
        path = self._tmp / name
        make_xlsx(path, [["原始日志"]] + [[line] for line in lines])
        return path

    def _run(self, *argv):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = enum_extract.main([*argv])
        return code, json.loads(buf.getvalue())

    def _read(self, path):
        return json.loads(Path(path).read_text(encoding="utf-8"))

    def test_json_happy_path(self):
        xlsx = self._xlsx(
            [
                '{"event_type": "login", "user": "u1"}',
                '{"event_type": "logout", "user": "u2"}',
                '{"event_type": "login", "user": "u3"}',
                '{"user": "u4"}',
            ]
        )
        code, payload = self._run(
            "--input", str(xlsx), "--field", "event_type", "--format", "json"
        )
        self.assertEqual(code, 0)
        self.assertEqual(payload["status"], "success")
        report = self._read(payload["output"])
        self.assertEqual(report["field"], "event_type")
        self.assertEqual(report["log_format"], "json")
        self.assertEqual(report["total_lines"], 4)
        self.assertEqual(report["matched_lines"], 3)
        self.assertEqual(report["unmatched_lines"], 1)
        self.assertEqual(report["unique_count"], 2)
        self.assertEqual(report["values"], ["login", "logout"])  # 首现序
        self.assertEqual(report["value_counts"], {"login": 2, "logout": 1})
        self.assertEqual(
            report["original_log"],
            {
                "login": '{"event_type": "login", "user": "u1"}',
                "logout": '{"event_type": "logout", "user": "u2"}',
            },
        )
        self.assertFalse(report["truncated"])

    def test_json_nested_path_and_syslog_header(self):
        xlsx = self._xlsx(
            [
                "<190>Nov 20 host app[1]: {\"event\": {\"action\": \"login\"}}",
                "<190>Nov 20 host app[1]: {\"event\": {\"action\": \"logout\"}}",
            ]
        )
        code, payload = self._run(
            "--input", str(xlsx), "--field", "event.action", "--format", "json"
        )
        self.assertEqual(code, 0)
        report = self._read(payload["output"])
        self.assertEqual(report["values"], ["login", "logout"])

    def test_kv_with_header_end_marker(self):
        xlsx = self._xlsx(
            [
                "Jan 01 00:00:01 host app[1]: type=attack",
                "Jan 01 00:00:02 host app[1]: type=login",
            ]
        )
        code, payload = self._run(
            "--input", str(xlsx), "--field", "type", "--format", "kv",
            "--header-end-marker", "app[1]: ",
        )
        self.assertEqual(code, 0)
        report = self._read(payload["output"])
        self.assertEqual(report["values"], ["attack", "login"])
        self.assertEqual(report["value_counts"], {"attack": 1, "login": 1})

    def test_max_values_truncates_list_but_not_counts(self):
        xlsx = self._xlsx(
            [
                "type=a", "type=b", "type=c", "type=a",
            ]
        )
        code, payload = self._run(
            "--input", str(xlsx), "--field", "type", "--format", "kv",
            "--max-values", "2",
        )
        self.assertEqual(code, 0)
        report = self._read(payload["output"])
        self.assertEqual(report["values"], ["a", "b"])  # 首现序前 2
        self.assertEqual(report["value_counts"], {"a": 2, "b": 1, "c": 1})  # 计数全量
        self.assertEqual(report["unique_count"], 3)
        self.assertEqual(sorted(report["original_log"]), ["a", "b"])  # 样本同步截断
        self.assertTrue(report["truncated"])

    def test_template_produces_mapping_table(self):
        xlsx = self._xlsx(["type=login", "type=logout"])
        code, payload = self._run(
            "--input", str(xlsx), "--field", "type", "--format", "kv", "--template"
        )
        self.assertEqual(code, 0)
        template_path = Path(payload["template"])
        self.assertTrue(template_path.is_file())
        self.assertTrue(template_path.name.startswith("enumvalues_"))
        self.assertTrue(template_path.suffix == ".xlsx")
        table = load_enum_table(template_path)
        self.assertEqual(len(table["fields"]), 1)
        self.assertEqual(table["fields"][0]["field"], "type")
        self.assertEqual(
            table["fields"][0]["pairs"],
            [
                {"mappingType": "EQUAL", "orgValue": "login", "mappingValue": "login"},
                {"mappingType": "EQUAL", "orgValue": "logout", "mappingValue": "logout"},
            ],
        )

    def test_without_template_no_template_key(self):
        xlsx = self._xlsx(["type=login"])
        code, payload = self._run(
            "--input", str(xlsx), "--field", "type", "--format", "kv"
        )
        self.assertEqual(code, 0)
        self.assertNotIn("template", payload)
        report = self._read(payload["output"])
        self.assertEqual(report["values"], ["login"])

    def test_zero_match_raises_enum_extract_empty(self):
        xlsx = self._xlsx(["nothing=here", "also=nothing"])
        code, payload = self._run(
            "--input", str(xlsx), "--field", "missing", "--format", "kv"
        )
        self.assertEqual(code, 1)
        self.assertEqual(payload["status"], "error")
        self.assertEqual(payload["code"], "enum_extract_empty")

    def test_empty_field_invalid_input(self):
        xlsx = self._xlsx(["type=login"])
        code, payload = self._run(
            "--input", str(xlsx), "--field", "  ", "--format", "kv"
        )
        self.assertEqual(code, 1)
        self.assertEqual(payload["code"], "invalid_input")

    def test_missing_input_file(self):
        code, payload = self._run(
            "--input", str(self._tmp / "nope.xlsx"), "--field", "x", "--format", "kv"
        )
        self.assertEqual(code, 1)
        self.assertEqual(payload["code"], "input_required")


if __name__ == "__main__":
    unittest.main()
