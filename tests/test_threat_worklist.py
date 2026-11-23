"""threat_worklist CLI 端到端测试：配置 + 日志表 → 威胁分类工作单文件契约。

接缝：threat-type/scripts/threat_worklist.py 的 main(argv)——
stdout JSON（status/message/output/threat_rules/candidate_count/
whitelist_size 或 status/error/code/message）+ <输入名>.threat_worklist.json
产物 + 退出码。守卫链与画像契约见脚本 docstring；夹具为合成 entities
JSON 与日志 xlsx。
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
SCRIPTS = SKILLS / "threat-type" / "scripts"
for path in (str(ROOT), str(ROOT / "tests"), str(SKILLS), str(SCRIPTS)):
    if path not in sys.path:
        sys.path.insert(0, path)

import threat_worklist  # noqa: E402
from excel_helpers import make_xlsx  # noqa: E402


def make_entry(index):
    return {
        "mappings": [],
        "field": None,
        "sim": None,
        "result": [],
        "info": None,
        "entity": None,
        "required": False,
        "core": None,
        "value": None,
        "index": index,
    }


def make_entity(name="规则A", indexes=(), event_name=None):
    filters = []
    if event_name is not None:
        filters.append(
            {"name": "addFields", "id": "", "fields": {"事件名称": event_name}}
        )
    return {
        "name": name,
        "parser": {"name": "json", "filter": filters},
        "normalize": [make_entry(index) for index in indexes],
        "sample": "",
    }


LOG_ROWS = [
    ["原始日志"],
    ['{"threat_name": "挖矿行为", "sev_code": "1"}'],
    ['{"threat_name": "勒索病毒Locky", "sev_code": "2"}'],
    ['{"threat_name": "挖矿行为", "sev_code": "1"}'],
    ['{"threat_info": "检测到Webshell上传", "sev_code": "3"}'],
    ['{"threat_name": "4457", "sev_code": "9"}'],
]


class ThreatWorklistCliTest(unittest.TestCase):
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

    def _config(self, entities, name="config.json"):
        path = self._tmp / name
        path.write_text(
            json.dumps(entities, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        return path

    def _log(self, rows=LOG_ROWS, name="logs.xlsx"):
        path = self._tmp / name
        make_xlsx(path, rows)
        return path

    def _run(self, *argv):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = threat_worklist.main(list(argv))
        return code, json.loads(stdout.getvalue())

    def _default_config(self):
        return [
            make_entity("恶意软件规则", ["threat_name", "sev_code"], event_name="病毒检测"),
            make_entity("Web攻击规则", ["threat_name", "threat_info"], event_name="网络攻击"),
            make_entity("登录规则", ["user"], event_name="登录事件"),
            make_entity("未标注规则", ["x"]),
        ]

    def test_success_worklist_contract(self):
        config = self._config(self._default_config())
        log = self._log()
        code, payload = self._run(
            "--input", str(config), "--log", str(log), "--format", "json"
        )
        self.assertEqual(code, 0)
        self.assertEqual(payload["status"], "success")
        self.assertEqual(payload["threat_rules"], ["恶意软件规则", "Web攻击规则"])
        self.assertEqual(payload["candidate_count"], 3)
        self.assertGreater(payload["whitelist_size"], 100)

        worklist = json.loads(
            Path(payload["output"]).read_text(encoding="utf-8")
        )
        self.assertEqual(worklist["threat_rules"], ["恶意软件规则", "Web攻击规则"])
        self.assertEqual(worklist["rule_count"], 2)
        self.assertEqual(
            worklist["threat_field_states"],
            {"恶意软件规则": "absent", "Web攻击规则": "absent"},
        )
        self.assertIn("挖矿木马", worklist["whitelist"])

        by_field = {c["field"]: c for c in worklist["candidates"]}
        self.assertEqual(
            set(by_field), {"threat_name", "sev_code", "threat_info"}
        )
        threat_name = by_field["threat_name"]
        self.assertEqual(
            threat_name["present_in_rules"], ["恶意软件规则", "Web攻击规则"]
        )
        self.assertEqual(threat_name["present_rule_count"], 2)
        self.assertEqual(threat_name["matched_lines"], 4)
        self.assertEqual(threat_name["unique_count"], 3)
        self.assertEqual(
            threat_name["value_counts"],
            {"挖矿行为": 2, "勒索病毒Locky": 1, "4457": 1},
        )
        self.assertIn("挖矿行为", threat_name["samples"])
        self.assertEqual(threat_name["code_only_values"], ["4457"])
        self.assertFalse(threat_name["all_code_only"])

        sev = by_field["sev_code"]
        self.assertEqual(sev["present_in_rules"], ["恶意软件规则"])
        self.assertTrue(sev["all_code_only"])
        self.assertEqual(sev["code_only_values"], ["1", "2", "3", "9"])

    def test_output_default_naming(self):
        config = self._config(self._default_config())
        log = self._log()
        code, payload = self._run(
            "--input", str(config), "--log", str(log), "--format", "json"
        )
        self.assertEqual(code, 0)
        self.assertTrue(payload["output"].endswith("config.threat_worklist.json"))

    def test_threat_field_states_reflect_config(self):
        entities = self._default_config()
        entities[0]["parser"]["filter"].append(
            {"name": "addFields", "id": "", "fields": {"威胁类型": "%{threat_name}"}}
        )
        config = self._config(entities)
        code, payload = self._run(
            "--input", str(config), "--log", str(self._log()), "--format", "json"
        )
        self.assertEqual(code, 0)
        worklist = json.loads(Path(payload["output"]).read_text(encoding="utf-8"))
        self.assertEqual(
            worklist["threat_field_states"],
            {"恶意软件规则": "chain", "Web攻击规则": "absent"},
        )

    def test_no_annotation_rejected(self):
        config = self._config([make_entity("规则A", ["x"])])
        code, payload = self._run(
            "--input", str(config), "--log", str(self._log()), "--format", "json"
        )
        self.assertEqual(code, 1)
        self.assertEqual(payload["code"], "event_annotation_required")

    def test_no_threat_member_rejected(self):
        config = self._config(
            [make_entity("登录规则", ["user"], event_name="登录事件")]
        )
        code, payload = self._run(
            "--input", str(config), "--log", str(self._log()), "--format", "json"
        )
        self.assertEqual(code, 1)
        self.assertEqual(payload["code"], "rule_name_not_found")

    def test_missing_log_file_rejected(self):
        config = self._config(self._default_config())
        code, payload = self._run(
            "--input", str(config), "--log", str(self._tmp / "不存在.xlsx"),
            "--format", "json",
        )
        self.assertEqual(code, 1)
        self.assertEqual(payload["code"], "input_required")

    def test_json_format_ignores_header_marker(self):
        config = self._config(self._default_config())
        code, payload = self._run(
            "--input", str(config), "--log", str(self._log()), "--format", "json",
            "--header-end-marker", "app[1]: ",
        )
        self.assertEqual(code, 0)
        self.assertIn("--header-end-marker 已忽略", payload["message"])

    def test_kv_format_extraction(self):
        kv_rows = [
            ["原始日志"],
            ["threat_name=挖矿行为 sev=1"],
            ["threat_name=勒索病毒Locky sev=2"],
        ]
        config = self._config(self._default_config())
        code, payload = self._run(
            "--input", str(config), "--log", str(self._log(kv_rows)), "--format", "kv"
        )
        self.assertEqual(code, 0)
        worklist = json.loads(Path(payload["output"]).read_text(encoding="utf-8"))
        by_field = {c["field"]: c for c in worklist["candidates"]}
        self.assertEqual(
            by_field["threat_name"]["value_counts"], {"挖矿行为": 1, "勒索病毒Locky": 1}
        )

    def test_candidate_not_in_logs_profiled_with_zero(self):
        entities = self._default_config()
        entities[0]["normalize"].append(make_entry("ghost_field"))
        config = self._config(entities)
        code, payload = self._run(
            "--input", str(config), "--log", str(self._log()), "--format", "json"
        )
        self.assertEqual(code, 0)
        worklist = json.loads(Path(payload["output"]).read_text(encoding="utf-8"))
        by_field = {c["field"]: c for c in worklist["candidates"]}
        ghost = by_field["ghost_field"]
        self.assertEqual(ghost["matched_lines"], 0)
        self.assertEqual(ghost["unique_count"], 0)
        self.assertEqual(ghost["values"], [])
        self.assertFalse(ghost["all_code_only"])  # 空值集不算全代码
        self.assertIn("无取值", payload["message"])
        self.assertIn("ghost_field", payload["message"])
        # threat_info 只出现在 Web攻击规则，但日志行 4 有值
        self.assertEqual(by_field["threat_info"]["matched_lines"], 1)

    def test_max_values_truncates_list_only(self):
        rows = [["原始日志"]] + [
            [f'{{"threat_name": "值{i}", "sev_code": "1"}}'] for i in range(8)
        ]
        entities = [
            make_entity("恶意软件规则", ["threat_name"], event_name="病毒检测"),
        ]
        config = self._config(entities)
        code, payload = self._run(
            "--input", str(config), "--log", str(self._log(rows)), "--format", "json",
            "--max-values", "3",
        )
        self.assertEqual(code, 0)
        worklist = json.loads(Path(payload["output"]).read_text(encoding="utf-8"))
        candidate = worklist["candidates"][0]
        self.assertEqual(len(candidate["values"]), 3)
        self.assertEqual(candidate["unique_count"], 8)
        self.assertTrue(candidate["truncated"])
        self.assertEqual(len(candidate["value_counts"]), 8)


if __name__ == "__main__":
    unittest.main()
