"""classify_finalize CLI 端到端测试：stats + labels + Excel → 分类结果 + 白板子规则。

接缝：log-classification/scripts/classify_finalize.py 的 main(argv)——
先经 feature_stats（阶段①）产出 stats.json，再写 labels.json（宿主 agent
语义层），跑阶段②校验 stdout JSON 与三份产物（classified.json /
subrules.json / Base64 导出）。
"""

from __future__ import annotations

import base64
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

import classify_finalize  # noqa: E402
import feature_stats  # noqa: E402
from excel_helpers import make_xlsx  # noqa: E402


class ClassifyFinalizeCliTest(unittest.TestCase):
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

    def _prepare(self, lines, format_args, labels, name="logs.xlsx"):
        """跑阶段①产 stats.json，写 labels.json，返回 (xlsx, stats, labels)。"""
        xlsx = self._tmp / name
        make_xlsx(xlsx, [["原始日志"]] + [[line] for line in lines])
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = feature_stats.main(
                ["--input", str(xlsx), "--feature-field", "type", *format_args]
            )
        assert code == 0, buf.getvalue()
        stats = self._tmp / (name.replace(".xlsx", "_stats.json"))
        assert stats.is_file()
        labels_path = self._tmp / "labels.json"
        labels_path.write_text(
            json.dumps({"classification_details": labels}, ensure_ascii=False),
            encoding="utf-8",
        )
        return xlsx, stats, labels_path

    def _run_finalize(self, xlsx, stats, labels, *extra):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = classify_finalize.main(
                ["--input", str(xlsx), "--stats", str(stats), "--labels", str(labels), *extra]
            )
        return code, json.loads(buf.getvalue())

    def test_kv_end_to_end(self):
        xlsx, stats, labels = self._prepare(
            ["type:attack||src:1.1.1.1", "type:login||src:2.2.2.2", "type:attack||port:22"],
            ["--format", "kv", "--field-delimit", "||", "--kv-delimit", ":"],
            [{"logtype": "attack", "meaning": "攻击告警"}, {"logtype": "login", "meaning": "登录事件"}],
        )
        code, payload = self._run_finalize(xlsx, stats, labels)
        self.assertEqual(code, 0)
        self.assertEqual(payload["status"], "success")

        classified = json.loads(Path(payload["output"]).read_text(encoding="utf-8"))
        self.assertEqual(classified["status"], "SUCCESS")
        self.assertEqual(classified["log_format"], "KV")
        self.assertEqual(classified["feature_count"], 2)
        details = classified["classification_details"]
        self.assertEqual(details[0]["logtype"], "attack")
        self.assertEqual(details[0]["meaning"], "攻击告警")
        self.assertEqual(details[0]["count"], 2)
        self.assertEqual(details[0]["real_samples"], "type:attack||src:1.1.1.1")
        self.assertEqual(details[1]["logtype"], "login")
        self.assertEqual(details[1]["count"], 1)
        self.assertEqual(classified["coverage"]["matched_lines"], 3)

        subrules = json.loads(Path(payload["subrules"]).read_text(encoding="utf-8"))
        self.assertEqual(len(subrules), 2)
        self.assertEqual(subrules[0]["name"], "attack_kv_子规则")
        self.assertEqual(subrules[1]["name"], "login_kv_子规则")

        export = Path(payload["export"])
        self.assertTrue(export.is_file())
        self.assertRegex(export.name, r"^unmappedconfig_subrules_\d{8}_\d{4}\.txt$")
        decoded = json.loads(base64.b64decode(export.read_text(encoding="utf-8")))
        self.assertEqual(decoded, subrules)

    def test_json_end_to_end_real_samples_is_body(self):
        xlsx, stats, labels = self._prepare(
            ['<189>Jan 01 host app[1]: {"type": "attack", "user": "u1"}'],
            ["--format", "json"],
            [{"logtype": "attack", "meaning": "攻击告警"}],
        )
        code, payload = self._run_finalize(xlsx, stats, labels)
        self.assertEqual(code, 0)
        classified = json.loads(Path(payload["output"]).read_text(encoding="utf-8"))
        detail = classified["classification_details"][0]
        self.assertEqual(detail["logtype"], "attack")
        self.assertEqual(detail["real_samples"], '{"type": "attack", "user": "u1"}')
        self.assertEqual(classified["log_format"], "JSON")
        subrules = json.loads(Path(payload["subrules"]).read_text(encoding="utf-8"))
        self.assertEqual(subrules[0]["name"], "attack_type_json_子规则")

    def test_sanitize_trims_invented_and_backfills_missing(self):
        xlsx, stats, labels = self._prepare(
            ["type=a", "type=b"],
            ["--format", "kv"],
            [{"logtype": "ghost", "meaning": "臆造"}, {"logtype": "a", "meaning": "甲类"}],
        )
        code, payload = self._run_finalize(xlsx, stats, labels)
        self.assertEqual(code, 0)
        classified = json.loads(Path(payload["output"]).read_text(encoding="utf-8"))
        logtypes = [d["logtype"] for d in classified["classification_details"]]
        self.assertEqual(sorted(logtypes), ["a", "b"])
        meanings = {d["logtype"]: d["meaning"] for d in classified["classification_details"]}
        self.assertEqual(meanings["a"], "甲类")
        self.assertEqual(meanings["b"], "")
        self.assertEqual(classified["sanitized"]["trimmed"], ["ghost"])
        self.assertEqual(classified["sanitized"]["backfilled"], ["b"])

    def test_labels_missing_file(self):
        xlsx, stats, _ = self._prepare(["type=a"], ["--format", "kv"], [])
        code, payload = self._run_finalize(xlsx, stats, self._tmp / "nope.json")
        self.assertEqual(code, 1)
        self.assertEqual(payload["code"], "input_required")

    def test_labels_bad_json(self):
        xlsx, stats, _ = self._prepare(["type=a"], ["--format", "kv"], [])
        bad = self._tmp / "bad.json"
        bad.write_text("{{{不是json", encoding="utf-8")
        code, payload = self._run_finalize(xlsx, stats, bad)
        self.assertEqual(code, 1)
        self.assertEqual(payload["code"], "invalid_input")

    def test_labels_accepts_bare_list(self):
        xlsx, stats, _ = self._prepare(
            ["type=a"], ["--format", "kv"], [{"logtype": "a", "meaning": "甲"}]
        )
        bare = self._tmp / "bare_labels.json"
        bare.write_text(json.dumps([{"logtype": "a", "meaning": "甲类"}]), encoding="utf-8")
        code, payload = self._run_finalize(xlsx, stats, bare)
        self.assertEqual(code, 0)
        classified = json.loads(Path(payload["output"]).read_text(encoding="utf-8"))
        self.assertEqual(classified["classification_details"][0]["meaning"], "甲类")

    def test_stats_without_values_rejected(self):
        xlsx = self._tmp / "logs.xlsx"
        make_xlsx(xlsx, [["原始日志"], ["unrelated line"]])
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            feature_stats.main(["--input", str(xlsx), "--format", "kv", "--feature-field", "type"])
        stats = self._tmp / "logs_stats.json"
        labels = self._tmp / "labels.json"
        labels.write_text(json.dumps({"classification_details": []}), encoding="utf-8")
        code, payload = self._run_finalize(xlsx, stats, labels)
        self.assertEqual(code, 1)
        self.assertEqual(payload["code"], "invalid_input")

    def test_no_export_flag(self):
        xlsx, stats, labels = self._prepare(
            ["type=a"], ["--format", "kv"], [{"logtype": "a", "meaning": "甲"}]
        )
        code, payload = self._run_finalize(xlsx, stats, labels, "--no-export")
        self.assertEqual(code, 0)
        self.assertIsNone(payload["export"])
        exports = list(self._tmp.glob("unmappedconfig_subrules_*.txt"))
        self.assertEqual(exports, [])

    def test_custom_output_paths(self):
        xlsx, stats, labels = self._prepare(
            ["type=a"], ["--format", "kv"], [{"logtype": "a", "meaning": "甲"}]
        )
        out = self._tmp / "my_classified.json"
        sub_out = self._tmp / "my_subrules.json"
        code, payload = self._run_finalize(
            xlsx, stats, labels, "--output", str(out), "--subrules-output", str(sub_out)
        )
        self.assertEqual(code, 0)
        self.assertEqual(Path(payload["output"]), out)
        self.assertEqual(Path(payload["subrules"]), sub_out)
        self.assertTrue(out.is_file())
        self.assertTrue(sub_out.is_file())


if __name__ == "__main__":
    unittest.main()
