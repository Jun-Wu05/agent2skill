"""mapping_finalize 单元测试：映射收口（sanitize + 占用裁决 + 写回 + 事件
标注 + 入口规则 + 导出）的文件契约 CLI（进程内 main() 调用）。"""

from __future__ import annotations

import base64
import contextlib
import glob
import io
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for path in (
    str(ROOT),
    str(ROOT / "skills" / "parser-skills"),
    str(ROOT / "skills" / "parser-skills" / "field-mapping" / "scripts"),
    str(ROOT / "tests"),
):
    if path not in sys.path:
        sys.path.insert(0, path)

import mapping_finalize as mf  # noqa: E402
from _shared import report as skill_report  # noqa: E402


def _entry(index, field=None):
    return {
        "mappings": [],
        "field": field,
        "sim": None,
        "result": [],
        "info": None,
        "entity": None,
        "required": False,
        "core": None,
        "value": None,
        "index": index,
    }


def _subrule(name, normalize, sample=""):
    return {
        "name": name,
        "parser": {"name": "json", "filter": []},
        "normalize": normalize,
        "sample": sample,
    }


def _classified():
    return {
        "status": "SUCCESS",
        "log_format": "JSON",
        "log_format_detail": "纯JSON",
        "feature_field": "action",
        "feature_identifier": r"(\{[\S\s]*\})",
        "Diversion_method": "日志类型",
        "analysis": {
            "has_json_structure": True,
            "has_cef_prefix": False,
            "has_key_value_pairs": False,
            "has_delimited_structure": False,
            "delimit": "",
            "tab": "",
        },
        "classification_details": [
            {"logtype": "登录", "meaning": "登录", "sample": '{"action":"登录"}'},
            {"logtype": "拦截", "meaning": "拦截", "sample": '{"action":"拦截"}'},
        ],
    }


WHITEBOARD_SUBRULES = [
    _subrule(
        "登录_json_子规则",
        [
            _entry("dst_ip"),
            _entry("src_address"),
            _entry("src_ip"),
            _entry("user"),
            _entry("http_method"),
            _entry("日志类型", field="log_type"),
            _entry("original_log", field="original_log"),
        ],
        sample='{"dst_ip":"1.1.1.1"}',
    ),
    _subrule(
        "block_json_子规则",
        [_entry("dst_ip"), _entry("http_method")],
        sample='{"http_method":"GET"}',
    ),
]

WHITEBOARD_MAPPINGS = {
    "mappings": [
        {"field": "dst_ip", "standard": "目的地址"},
        {"field": "src_address", "standard": "源地址"},
        {"field": "src_ip", "standard": "源地址"},
        {"field": "user", "standard": "未匹配"},
        {"field": "http_method", "standard": "事件名称"},
        {"field": "臆造字段", "standard": "源地址"},
    ],
    "events": [
        {"rule_name": "登录_json_子规则", "event_name": "登录事件"},
        {"rule_name": "block_json_子规则", "event_name": "不存在的分类"},
        {"rule_name": "未知规则", "event_name": "web访问"},
    ],
}


class ExportNameTemplateTest(unittest.TestCase):
    def test_new_download_kinds(self):
        self.assertEqual(
            skill_report.download_filename("mappedconfig_subrules", "20261119_1200"),
            "mappedconfig_subrules_20261119_1200.txt",
        )
        self.assertEqual(
            skill_report.download_filename("mappedconfig_mainrules", "20261119_1200"),
            "mappedconfig_mainrules_20261119_1200.txt",
        )
        self.assertEqual(
            skill_report.download_filename("fieldmapped_config", "20261119_1200"),
            "fieldmapped_config_20261119_1200.txt",
        )


class WhiteboardPathEndToEndTest(unittest.TestCase):
    def setUp(self):
        self._tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self._tmp, ignore_errors=True)
        self.subrules = self._tmp / "whiteboard_subrules.json"
        self.subrules.write_text(
            json.dumps(WHITEBOARD_SUBRULES, ensure_ascii=False), encoding="utf-8"
        )
        self.classified = self._tmp / "whiteboard_classified.json"
        self.classified.write_text(
            json.dumps(_classified(), ensure_ascii=False), encoding="utf-8"
        )
        self.mappings = self._tmp / "mappings.json"
        self.mappings.write_text(
            json.dumps(WHITEBOARD_MAPPINGS, ensure_ascii=False), encoding="utf-8"
        )

    def _run(self, extra=None):
        argv = [
            "--subrules", str(self.subrules),
            "--classified", str(self.classified),
            "--mappings", str(self.mappings),
            "--vendor", "奇安信",
            "--product", "天擎",
        ] + (extra or [])
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = mf.main(argv)
        return code, stdout.getvalue()

    def test_b2_full_flow(self):
        code, stdout = self._run()
        self.assertEqual(code, 0)
        payload = json.loads(stdout)
        self.assertEqual(payload["status"], "success")
        self.assertEqual(payload["field_count"], 5)
        self.assertEqual(payload["matched"], 3)
        self.assertEqual(payload["unmatched"], 2)
        self.assertEqual(payload["enum_short_circuited"], 1)
        self.assertEqual(payload["enum_overridden"], ["http_method"])
        self.assertEqual(payload["sanitized"]["trimmed"], ["臆造字段"])
        self.assertEqual(
            payload["sanitized"]["degraded"],
            [{"field": "http_method", "standard": "事件名称", "reason": "映射目标黑名单"}],
        )
        self.assertEqual(len(payload["conflicts"]), 1)
        self.assertEqual(payload["conflicts"][0]["standard"], "源地址")
        self.assertEqual(payload["conflicts"][0]["winner"], "src_address")
        self.assertEqual(payload["conflicts"][0]["winner_source"], "candidate")
        self.assertEqual(payload["conflicts"][0]["losers"], ["src_ip"])
        self.assertEqual(payload["events"]["annotated"], 1)
        self.assertEqual(payload["events"]["unknown_rule"], ["未知规则"])
        self.assertEqual(payload["events"]["invalid_event"], ["block_json_子规则"])

        # 映射后子规则
        mapped = json.loads(
            Path(payload["output"]).read_text(encoding="utf-8")
        )
        login = next(r for r in mapped if r["name"] == "登录_json_子规则")
        by_index = {e["index"]: e for e in login["normalize"]}
        self.assertEqual(by_index["dst_ip"]["field"], "目的地址")
        self.assertTrue(by_index["dst_ip"]["sim"])
        self.assertFalse(by_index["dst_ip"]["core"])
        self.assertTrue(by_index["dst_ip"]["entity"])  # 目录首个对象
        self.assertEqual(by_index["src_address"]["field"], "源地址")
        self.assertIsNone(by_index["src_ip"]["field"])  # 占用冲突败者清空
        self.assertIsNone(by_index["user"]["field"])  # agent 判未匹配清空
        self.assertEqual(by_index["http_method"]["field"], "HTTP请求方法")  # 枚举短路
        self.assertEqual(by_index["日志类型"]["field"], "log_type")  # 排除索引不动
        self.assertEqual(by_index["original_log"]["field"], "original_log")
        # 事件标注写入（登录事件 → 信息）
        event_filter = login["parser"]["filter"][-1]
        self.assertEqual(
            event_filter["fields"],
            {"事件名称": "登录事件", "事件级别": "信息"},
        )
        self.assertEqual(
            [e["index"] for e in login["normalize"][-2:]], ["事件名称", "事件级别"]
        )
        # block 子规则：全局判定逐子规则写回；无事件判定不写
        block = next(r for r in mapped if r["name"] == "block_json_子规则")
        block_by_index = {e["index"]: e for e in block["normalize"]}
        self.assertEqual(block_by_index["dst_ip"]["field"], "目的地址")
        self.assertEqual(block_by_index["http_method"]["field"], "HTTP请求方法")
        self.assertEqual(block["parser"]["filter"], [])

        # 入口规则
        entries = json.loads(
            Path(payload["entry_output"]).read_text(encoding="utf-8")
        )
        self.assertEqual(len(entries), 1)
        entry = entries[0]
        self.assertTrue(entry["name"].startswith("奇安信_天擎_通用_入口规则"))
        self.assertEqual(entry["parser"]["name"], "json")

        # Base64 导出（缺省命名契约）
        self.assertTrue(
            glob.glob(str(self._tmp / "mappedconfig_subrules_*.txt"))
        )
        self.assertTrue(
            glob.glob(str(self._tmp / "mappedconfig_mainrules_*.txt"))
        )
        export_path = glob.glob(str(self._tmp / "mappedconfig_subrules_*.txt"))[0]
        decoded = base64.b64decode(
            Path(export_path).read_text(encoding="utf-8").strip()
        )
        self.assertEqual(json.loads(decoded.decode("utf-8")), mapped)

    def test_default_output_names_strip_subrules_suffix(self):
        code, stdout = self._run()
        self.assertEqual(code, 0)
        payload = json.loads(stdout)
        self.assertEqual(
            Path(payload["output"]), self._tmp / "whiteboard_mapped_subrules.json"
        )
        self.assertEqual(
            Path(payload["entry_output"]), self._tmp / "whiteboard_entry_rules.json"
        )

    def test_no_export_flag(self):
        code, stdout = self._run(["--no-export"])
        self.assertEqual(code, 0)
        payload = json.loads(stdout)
        self.assertIsNone(payload["export"])
        self.assertFalse(glob.glob(str(self._tmp / "mappedconfig_*.txt")))


class ConfigPathEndToEndTest(unittest.TestCase):
    def setUp(self):
        self._tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self._tmp, ignore_errors=True)

    def _write_config(self, entities, name="config.json"):
        path = self._tmp / name
        path.write_text(json.dumps(entities, ensure_ascii=False), encoding="utf-8")
        return path

    def _write_mappings(self, payload):
        path = self._tmp / "mappings.json"
        path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        return path

    def _run(self, config, mappings, extra=None):
        argv = ["--config", str(config), "--mappings", str(mappings)] + (extra or [])
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = mf.main(argv)
        return code, stdout.getvalue()

    def test_a6_writes_and_preserves(self):
        config = self._write_config(
            [
                {
                    "name": "某厂_AUDIT_json_子规则",
                    "normalize": [
                        _entry("dst_ip"),
                        _entry("legacy", field="外部映射名"),
                        _entry("user"),
                    ],
                }
            ]
        )
        mappings = self._write_mappings(
            {"mappings": [
                {"field": "dst_ip", "standard": "目的地址"},
                {"field": "user", "standard": "未匹配"},
            ]}
        )
        code, stdout = self._run(config, mappings)
        self.assertEqual(code, 0)
        payload = json.loads(stdout)
        self.assertEqual(payload["field_count"], 2)
        self.assertEqual(payload["matched"], 1)
        self.assertEqual(payload["unmatched"], 1)
        self.assertEqual(
            Path(payload["output"]), self._tmp / "config_mapped_config.json"
        )
        updated = json.loads(Path(payload["output"]).read_text(encoding="utf-8"))
        by_index = {e["index"]: e for e in updated[0]["normalize"]}
        self.assertEqual(by_index["dst_ip"]["field"], "目的地址")
        self.assertTrue(by_index["dst_ip"]["sim"])
        # 未匹配保持原样（field 仍为空），既有映射保留
        self.assertIsNone(by_index["user"]["field"])
        self.assertEqual(by_index["legacy"]["field"], "外部映射名")
        self.assertTrue(glob.glob(str(self._tmp / "fieldmapped_config_*.txt")))

    def test_a6_existing_occupant_wins(self):
        config = self._write_config(
            [
                {
                    "name": "a_子规则",
                    "normalize": [
                        _entry("legacy_src", field="源地址"),
                        _entry("src_ip"),
                    ],
                }
            ]
        )
        mappings = self._write_mappings(
            {"mappings": [{"field": "src_ip", "standard": "源地址"}]}
        )
        code, stdout = self._run(config, mappings)
        self.assertEqual(code, 0)
        payload = json.loads(stdout)
        self.assertEqual(payload["matched"], 0)
        self.assertEqual(len(payload["conflicts"]), 1)
        self.assertEqual(payload["conflicts"][0]["winner"], "legacy_src")
        self.assertEqual(payload["conflicts"][0]["winner_source"], "existing")
        updated = json.loads(Path(payload["output"]).read_text(encoding="utf-8"))
        by_index = {e["index"]: e for e in updated[0]["normalize"]}
        self.assertIsNone(by_index["src_ip"]["field"])
        self.assertEqual(by_index["legacy_src"]["field"], "源地址")


class ErrorContractTest(unittest.TestCase):
    def setUp(self):
        self._tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self._tmp, ignore_errors=True)

    def _run(self, argv):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = mf.main(argv)
        return code, stdout.getvalue()

    def _write(self, name, payload):
        path = self._tmp / name
        path.write_text(
            payload if isinstance(payload, str) else json.dumps(payload, ensure_ascii=False),
            encoding="utf-8",
        )
        return path

    def test_neither_mode_invalid_input(self):
        code, stdout = self._run(["--mappings", "x.json"])
        self.assertEqual(code, 1)
        self.assertIn("invalid_input", stdout)

    def test_both_modes_invalid_input(self):
        code, stdout = self._run(
            ["--subrules", "a.json", "--config", "b.txt", "--mappings", "m.json"]
        )
        self.assertEqual(code, 1)
        self.assertIn("invalid_input", stdout)

    def test_missing_mappings_file(self):
        code, stdout = self._run(
            ["--config", str(self._tmp / "nope.json"), "--mappings", str(self._tmp / "m.json")]
        )
        self.assertEqual(code, 1)
        self.assertIn("input_required", stdout)

    def test_bad_mappings_contract(self):
        config = self._write("config.json", [{"name": "a", "normalize": [_entry("dst_ip")]}])
        mappings = self._write("m.json", {"foo": 1})
        code, stdout = self._run(["--config", str(config), "--mappings", str(mappings)])
        self.assertEqual(code, 1)
        self.assertIn("mappings.json 契约不符", stdout)

    def test_b2_missing_vendor_rejected(self):
        subrules = self._write(
            "w_subrules.json",
            [{"name": "a", "parser": {"name": "json"}, "normalize": [_entry("dst_ip")]}],
        )
        classified = self._write("c.json", _classified())
        mappings = self._write(
            "m.json", {"mappings": [{"field": "dst_ip", "standard": "目的地址"}]}
        )
        code, stdout = self._run(
            ["--subrules", str(subrules), "--classified", str(classified),
             "--mappings", str(mappings), "--product", "天擎"]
        )
        self.assertEqual(code, 1)
        self.assertIn("--vendor", stdout)

    def test_b2_syslog_kv_without_identifier_rejected(self):
        subrules = self._write(
            "w_subrules.json",
            [{"name": "a", "parser": {"name": "json"}, "normalize": [_entry("user")]}],
        )
        classification = _classified()
        classification["log_format"] = "KV"
        classification["log_format_detail"] = "日志头+KV"
        classification["feature_identifier"] = ""
        classified = self._write("c.json", classification)
        mappings = self._write("m.json", {"mappings": []})
        code, stdout = self._run(
            ["--subrules", str(subrules), "--classified", str(classified),
             "--mappings", str(mappings), "--vendor", "v", "--product", "p"]
        )
        self.assertEqual(code, 1)
        self.assertIn("feature_identifier", stdout)

    def test_all_mapped_skips_successfully(self):
        # 全映射跳过守卫：成功跳过（零匹配产物照常输出），既有映射保留
        config = self._write(
            "config.json",
            [{"name": "a", "normalize": [_entry("src_ip", field="源地址")]}],
        )
        mappings = self._write("m.json", {"mappings": []})
        code, stdout = self._run(["--config", str(config), "--mappings", str(mappings)])
        self.assertEqual(code, 0)
        payload = json.loads(stdout)
        self.assertEqual(payload["status"], "success")
        self.assertEqual(payload["field_count"], 0)
        self.assertIn("没有待映射字段", payload["message"])
        updated = json.loads(Path(payload["output"]).read_text(encoding="utf-8"))
        self.assertEqual(
            updated[0]["normalize"][0]["field"], "源地址"
        )


if __name__ == "__main__":
    unittest.main()
