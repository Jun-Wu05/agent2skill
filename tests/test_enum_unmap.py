"""enum_unmap CLI 端到端测试：配置 + 字段名单 → 置空 mappings 的文件契约。

接缝：enum-mapping/scripts/enum_unmap.py 的 main(argv)——
stdout JSON（status/message/output/export/fields 或
status/error/code/message）+ <输入名>_enumunmapped.json 产物 +
enummapping_config Base64 导出 + 退出码。
取消映射 = 置空 normalize[].mappings（条目与 field 标注保留），
与删除字段（field-adjust）语义分离；守卫链见脚本 docstring。
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

import enum_unmap  # noqa: E402


def make_entry(index, field=None, mappings=None):
    return {
        "mappings": mappings if mappings is not None else [],
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


def make_entity(name="规则A", entries=()):
    return {
        "name": name,
        "parser": {"name": "kv", "tab": "=", "delimit": "\\s", "filter": []},
        "normalize": list(entries),
        "sample": "",
    }


MAPPING = {"mappingType": "EQUAL", "orgValue": "login", "mappingValue": "登录"}


class EnumUnmapCliTest(unittest.TestCase):
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

    def _run(self, *argv):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = enum_unmap.main([*argv])
        return code, json.loads(buf.getvalue())

    def _read_output(self, payload):
        return json.loads(Path(payload["output"]).read_text(encoding="utf-8"))

    def test_unmap_clears_mappings_keeps_entry(self):
        config = self._config(
            [make_entity(entries=[make_entry("event_type", field="事件状态", mappings=[MAPPING])])]
        )
        code, payload = self._run("--input", str(config), "--fields", "event_type")
        self.assertEqual(code, 0)
        self.assertEqual(payload["status"], "success")
        self.assertTrue(payload["output"].endswith("_enumunmapped.json"))
        result = self._read_output(payload)
        entry = result[0]["normalize"][0]
        self.assertEqual(entry["mappings"], [])
        self.assertEqual(entry["index"], "event_type")  # 条目保留
        self.assertEqual(entry["field"], "事件状态")  # 字段标注保留
        self.assertEqual(payload["fields"][0]["cleared"], 1)

    def test_match_by_field_name(self):
        config = self._config(
            [make_entity(entries=[make_entry("etype", field="事件状态", mappings=[MAPPING])])]
        )
        code, payload = self._run("--input", str(config), "--fields", "事件状态")
        self.assertEqual(code, 0)
        result = self._read_output(payload)
        self.assertEqual(result[0]["normalize"][0]["mappings"], [])

    def test_clears_all_entries_sharing_index(self):
        config = self._config(
            [
                make_entity(name="r1", entries=[make_entry("event_type", mappings=[MAPPING])]),
                make_entity(name="r2", entries=[make_entry("event_type", mappings=[dict(MAPPING)])]),
            ]
        )
        code, payload = self._run("--input", str(config), "--fields", "event_type")
        self.assertEqual(code, 0)
        result = self._read_output(payload)
        self.assertEqual(result[0]["normalize"][0]["mappings"], [])
        self.assertEqual(result[1]["normalize"][0]["mappings"], [])
        self.assertEqual(payload["fields"][0]["cleared"], 2)

    def test_missing_field_rejects_with_vocab_hint(self):
        config = self._config(
            [make_entity(entries=[make_entry("event_type", field="事件状态", mappings=[MAPPING])])]
        )
        code, payload = self._run("--input", str(config), "--fields", "no_such")
        self.assertEqual(code, 1)
        self.assertEqual(payload["status"], "error")
        self.assertEqual(payload["code"], "field_not_found")
        self.assertIn("event_type(事件状态)", payload["message"])

    def test_chain_held_field_unmap_allowed(self):
        # 用户 2026-11-20 真实验收裁决：取消映射与填充对称，不做目标黑名单
        config = self._config(
            [make_entity(entries=[make_entry("威胁类型", mappings=[MAPPING])])]
        )
        code, payload = self._run("--input", str(config), "--fields", "威胁类型")
        self.assertEqual(code, 0)
        result = self._read_output(payload)
        self.assertEqual(result[0]["normalize"][0]["mappings"], [])

    def test_standard_name_ambiguous_rejects(self):
        config = self._config(
            [
                make_entity(
                    name="r1",
                    entries=[make_entry("etype1", field="事件状态", mappings=[MAPPING])],
                ),
                make_entity(
                    name="r2",
                    entries=[make_entry("etype2", field="事件状态", mappings=[MAPPING])],
                ),
            ]
        )
        code, payload = self._run("--input", str(config), "--fields", "事件状态")
        self.assertEqual(code, 1)
        self.assertEqual(payload["code"], "field_name_ambiguous")
        self.assertIn("etype1", payload["message"])
        self.assertIn("etype2", payload["message"])
        # 整单拒绝：不产出文件
        self.assertEqual(list(self._tmp.glob("*_enumunmapped.json")), [])

    def test_no_mappings_rejects_no_silent_success(self):
        config = self._config([make_entity(entries=[make_entry("event_type", mappings=[])])])
        code, payload = self._run("--input", str(config), "--fields", "event_type")
        self.assertEqual(code, 1)
        self.assertEqual(payload["code"], "mapping_not_found")

    def test_mixed_targets_all_or_nothing(self):
        config = self._config(
            [
                make_entity(
                    entries=[
                        make_entry("has_mappings", mappings=[MAPPING]),
                        make_entry("no_mappings", mappings=[]),
                    ]
                )
            ]
        )
        code, payload = self._run(
            "--input", str(config), "--fields", "has_mappings,no_mappings"
        )
        self.assertEqual(code, 1)
        self.assertEqual(payload["code"], "mapping_not_found")
        self.assertEqual(list(self._tmp.glob("*_enumunmapped.json")), [])

    def test_empty_fields_list_rejected(self):
        config = self._config([make_entity(entries=[make_entry("event_type", mappings=[MAPPING])])])
        code, payload = self._run("--input", str(config), "--fields", " , ")
        self.assertEqual(code, 1)
        self.assertEqual(payload["code"], "invalid_input")

    def test_ambiguous_candidates_skip_missing_index(self):
        # 无 index 的条目不进歧义候选（不出现 None(...)），也不计入判歧
        config = self._config(
            [
                make_entity(
                    entries=[
                        make_entry("etype1", field="事件状态", mappings=[MAPPING]),
                        make_entry(None, field="事件状态", mappings=[MAPPING]),
                        make_entry("etype2", field="事件状态", mappings=[MAPPING]),
                    ]
                )
            ]
        )
        code, payload = self._run("--input", str(config), "--fields", "事件状态")
        self.assertEqual(code, 1)
        self.assertEqual(payload["code"], "field_name_ambiguous")
        self.assertIn("etype1", payload["message"])
        self.assertIn("etype2", payload["message"])
        self.assertNotIn("None", payload["message"])

    def test_config_load_error(self):
        code, payload = self._run(
            "--input", str(self._tmp / "nope.json"), "--fields", "x"
        )
        self.assertEqual(code, 1)
        self.assertEqual(payload["code"], "config_required")


if __name__ == "__main__":
    unittest.main()
