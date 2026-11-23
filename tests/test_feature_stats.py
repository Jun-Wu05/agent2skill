"""feature_stats CLI 端到端测试：Excel → 统计报告的文件契约。

接缝：log-classification/scripts/feature_stats.py 的 main(argv)——
stdout JSON（status/message/output 或 status/error/code/message）+
stats JSON 产物 + 退出码。夹具用 excel_helpers 现场合成 xlsx。
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
SCRIPTS = SKILLS / "log-classification" / "scripts"
for path in (str(ROOT), str(ROOT / "tests"), str(SKILLS), str(SCRIPTS)):
    if path not in sys.path:
        sys.path.insert(0, path)

import feature_stats  # noqa: E402
from excel_helpers import make_xlsx  # noqa: E402


class FeatureStatsCliTest(unittest.TestCase):
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
            code = feature_stats.main([*argv])
        return code, json.loads(buf.getvalue())

    def _read_stats(self, path):
        return json.loads(Path(path).read_text(encoding="utf-8"))

    def test_json_format_happy_path(self):
        xlsx = self._xlsx(
            [
                '{"event": {"action": "login"}, "user": "u1"}',
                '{"event": {"action": "login"}, "user": "u2"}',
                '{"event": {"action": "logout"}, "user": "u3"}',
            ]
        )
        code, payload = self._run(
            "--input", str(xlsx), "--format", "json", "--feature-field", "event.action"
        )
        self.assertEqual(code, 0)
        self.assertEqual(payload["status"], "success")
        stats = self._read_stats(payload["output"])
        self.assertEqual(stats["log_format"], "json")
        self.assertEqual(stats["feature_field"], "event.action")
        self.assertEqual(stats["total_lines"], 3)
        self.assertEqual(stats["matched_lines"], 3)
        self.assertAlmostEqual(stats["coverage"], 1.0)
        self.assertEqual(stats["values"]["login"]["count"], 2)
        self.assertEqual(stats["values"]["logout"]["count"], 1)
        self.assertEqual(stats["top_values"], ["login", "logout"])

    def test_kv_format_with_defaults(self):
        xlsx = self._xlsx(
            ["type=attack src=1.1.1.1", "type=login src=2.2.2.2", "type=attack src=3.3.3.3"]
        )
        code, payload = self._run(
            "--input", str(xlsx), "--format", "kv", "--feature-field", "type"
        )
        self.assertEqual(code, 0)
        stats = self._read_stats(payload["output"])
        self.assertEqual(stats["format_context"], {"field_delimit": " ", "kv_delimit": "="})
        self.assertEqual(stats["values"]["attack"]["count"], 2)
        self.assertEqual(stats["values"]["login"]["count"], 1)

    def test_kv_custom_delimiters(self):
        xlsx = self._xlsx(
            ["type:attack||src:1.1.1.1", "type:login||src:2.2.2.2"]
        )
        code, payload = self._run(
            "--input", str(xlsx), "--format", "kv", "--feature-field", "type",
            "--field-delimit", "||", "--kv-delimit", ":",
        )
        self.assertEqual(code, 0)
        stats = self._read_stats(payload["output"])
        self.assertEqual(stats["values"]["attack"]["count"], 1)
        self.assertEqual(stats["values"]["login"]["count"], 1)

    def test_header_end_marker_strips_for_kv(self):
        xlsx = self._xlsx(
            [
                "Jan 01 00:00:01 host app[1]: type=attack",
                "Jan 01 00:00:02 host app[1]: type=login",
            ]
        )
        code, payload = self._run(
            "--input", str(xlsx), "--format", "kv", "--feature-field", "type",
            "--header-end-marker", "app[1]: ",
        )
        self.assertEqual(code, 0)
        stats = self._read_stats(payload["output"])
        self.assertEqual(stats["matched_lines"], 2)
        self.assertEqual(stats["values"]["attack"]["count"], 1)

    def test_invalid_header_marker_reverts(self):
        # marker="=" 会把首个 = 前的整段当日志头剥掉，特征键行存在率骤降
        # → 数据裁决判定 marker 无效，回退整行
        xlsx = self._xlsx(["type=attack src=1.1.1.1", "type=login src=2.2.2.2"])
        code, payload = self._run(
            "--input", str(xlsx), "--format", "kv", "--feature-field", "type",
            "--header-end-marker", "=",
        )
        self.assertEqual(code, 0)
        stats = self._read_stats(payload["output"])
        self.assertEqual(stats["matched_lines"], 2)
        self.assertTrue(
            any(a["kind"] == "header_end_marker" for a in stats["adjudications"])
        )

    def test_wrong_field_delimit_fixed_by_probe(self):
        # 声称字段分隔符 ","，数据实际用 "||" 且特征键不在行首（行首键会在
        # 错误分隔符下吞掉整行尾巴造成假匹配，键不在行首才真正零匹配）
        # → 探针改判 "||"
        xlsx = self._xlsx(
            ["src:1.1.1.1||type:attack", "src:2.2.2.2||type:login"]
        )
        code, payload = self._run(
            "--input", str(xlsx), "--format", "kv", "--feature-field", "type",
            "--field-delimit", ",", "--kv-delimit", ":",
        )
        self.assertEqual(code, 0)
        stats = self._read_stats(payload["output"])
        self.assertEqual(stats["matched_lines"], 2)
        self.assertEqual(stats["values"]["attack"]["count"], 1)
        self.assertEqual(stats["values"]["login"]["count"], 1)
        adjudications = stats["adjudications"]
        self.assertTrue(any(a["kind"] == "field_delimit" and a["to"] == "||" for a in adjudications))

    def test_wrong_kv_delimit_fixed_by_alternative(self):
        # 声称 kv 分隔符 "="（零匹配），数据实际用 ":" → 对称重试
        xlsx = self._xlsx(["type:attack src:1.1.1.1", "type:login src:2.2.2.2"])
        code, payload = self._run(
            "--input", str(xlsx), "--format", "kv", "--feature-field", "type",
            "--kv-delimit", "=",
        )
        self.assertEqual(code, 0)
        stats = self._read_stats(payload["output"])
        self.assertEqual(stats["matched_lines"], 2)
        self.assertTrue(
            any(a["kind"] == "kv_delimit" for a in stats["adjudications"])
        )

    def test_unmatched_reported(self):
        xlsx = self._xlsx(["type=a", "no feature here", "type=a"])
        code, payload = self._run(
            "--input", str(xlsx), "--format", "kv", "--feature-field", "type"
        )
        self.assertEqual(code, 0)
        stats = self._read_stats(payload["output"])
        self.assertEqual(stats["matched_lines"], 2)
        self.assertEqual(stats["unmatched_lines"], 1)
        self.assertEqual(stats["unmatched_samples"], ["no feature here"])

    def test_default_output_path(self):
        xlsx = self._xlsx(['{"type": "a"}'])
        code, payload = self._run(
            "--input", str(xlsx), "--format", "json", "--feature-field", "type"
        )
        self.assertEqual(code, 0)
        expected = self._tmp / "logs_stats.json"
        self.assertEqual(Path(payload["output"]), expected)
        self.assertTrue(expected.is_file())

    def test_custom_output_path(self):
        xlsx = self._xlsx(['{"type": "a"}'])
        out = self._tmp / "my_stats.json"
        code, payload = self._run(
            "--input", str(xlsx), "--format", "json", "--feature-field", "type",
            "--output", str(out),
        )
        self.assertEqual(code, 0)
        self.assertEqual(Path(payload["output"]), out)

    def test_missing_file_error(self):
        code, payload = self._run(
            "--input", str(self._tmp / "nope.xlsx"),
            "--format", "json", "--feature-field", "type",
        )
        self.assertEqual(code, 1)
        self.assertEqual(payload["status"], "error")
        self.assertEqual(payload["code"], "input_required")

    def test_blank_feature_field_rejected(self):
        xlsx = self._xlsx(['{"type": "a"}'])
        code, payload = self._run(
            "--input", str(xlsx), "--format", "json", "--feature-field", "  "
        )
        self.assertEqual(code, 1)
        self.assertEqual(payload["status"], "error")
        self.assertEqual(payload["code"], "invalid_input")

    def test_invalid_format_rejected_by_argparse(self):
        xlsx = self._xlsx(['{"type": "a"}'])
        with self.assertRaises(SystemExit):
            feature_stats.main(
                ["--input", str(xlsx), "--format", "xml", "--feature-field", "type"]
            )


if __name__ == "__main__":
    unittest.main()
