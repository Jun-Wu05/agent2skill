"""enum_fill CLI 端到端测试：配置 + 映射对 → normalize[].mappings 的文件契约。

接缝：enum-mapping/scripts/enum_fill.py 的 main(argv)——
stdout JSON（status/message/output/export/fields/unbound 或
status/error/code/message）+ <输入名>.enumfilled.json 产物 +
enummapping_config Base64 导出 + 退出码。
守卫链与写回语义见脚本 docstring；夹具为合成 entities JSON 与 xlsx。
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

import enum_fill  # noqa: E402
from _shared.config_io import decode_config_text  # noqa: E402
from excel_helpers import make_multi_sheet_xlsx  # noqa: E402

HEADER = ["mappingType", "orgValue", "mappingValue"]


def make_entry(index, field=None, mappings=None, value=None, with_mappings_key=True):
    entry = {
        "field": field,
        "sim": None,
        "result": [],
        "info": None,
        "entity": None,
        "required": False,
        "core": None,
        "value": value,
        "index": index,
    }
    if with_mappings_key:
        entry = {"mappings": mappings if mappings is not None else [], **entry}
    elif mappings:
        raise ValueError("with_mappings_key=False 时不应给 mappings")
    return entry


def make_entity(name="规则A", entries=(), filters=()):
    return {
        "name": name,
        "parser": {"name": "kv", "tab": "=", "delimit": "\\s", "filter": list(filters)},
        "normalize": list(entries),
        "sample": "",
    }


class EnumFillCliTest(unittest.TestCase):
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

    def _mappings_json(self, payload, name="pairs.json"):
        path = self._tmp / name
        path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        return path

    def _excel(self, sheets, name="mappings.xlsx"):
        path = self._tmp / name
        make_multi_sheet_xlsx(path, sheets)
        return path

    def _run(self, *argv):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = enum_fill.main([*argv])
        return code, json.loads(buf.getvalue())

    def _read_output(self, payload):
        return json.loads(Path(payload["output"]).read_text(encoding="utf-8"))

    def test_json_fill_appends_by_index(self):
        config = self._config(
            [make_entity(entries=[make_entry("event_type", value=None)])]
        )
        pairs = self._mappings_json(
            {
                "mappings": [
                    {
                        "field": "event_type",
                        "pairs": [
                            {"orgValue": "login", "mappingValue": "登录"},
                            {"orgValue": "logout", "mappingValue": "注销"},
                        ],
                    }
                ]
            }
        )
        code, payload = self._run("--input", str(config), "--mappings", str(pairs))
        self.assertEqual(code, 0)
        self.assertEqual(payload["status"], "success")
        result = self._read_output(payload)
        entry = result[0]["normalize"][0]
        self.assertEqual(
            entry["mappings"],
            [
                {"mappingType": "EQUAL", "orgValue": "login", "mappingValue": "登录"},
                {"mappingType": "EQUAL", "orgValue": "logout", "mappingValue": "注销"},
            ],
        )
        # 外层 value / field / sim 等元数据不动
        self.assertIsNone(entry["value"])
        self.assertIsNone(entry["field"])
        # Base64 导出回解等同
        exported = decode_config_text(Path(payload["export"]).read_text(encoding="utf-8"))
        self.assertEqual(exported, result)
        self.assertEqual(payload["fields"][0]["added"], 2)
        self.assertEqual(payload["fields"][0]["targets"], 1)

    def test_match_by_field_name(self):
        config = self._config(
            [make_entity(entries=[make_entry("etype", field="事件状态")])]
        )
        pairs = self._mappings_json(
            {"mappings": [{"field": "事件状态", "pairs": [{"orgValue": "ok", "mappingValue": "成功"}]}]}
        )
        code, payload = self._run("--input", str(config), "--mappings", str(pairs))
        self.assertEqual(code, 0)
        result = self._read_output(payload)
        self.assertEqual(
            result[0]["normalize"][0]["mappings"],
            [{"mappingType": "EQUAL", "orgValue": "ok", "mappingValue": "成功"}],
        )

    def test_fill_creates_mappings_key_when_absent(self):
        entry = make_entry("event_type", with_mappings_key=False)
        config = self._config([make_entity(entries=[entry])])
        pairs = self._mappings_json(
            {"mappings": [{"field": "event_type", "pairs": [{"orgValue": "a", "mappingValue": "甲"}]}]}
        )
        code, payload = self._run("--input", str(config), "--mappings", str(pairs))
        self.assertEqual(code, 0)
        result = self._read_output(payload)
        self.assertEqual(
            result[0]["normalize"][0]["mappings"],
            [{"mappingType": "EQUAL", "orgValue": "a", "mappingValue": "甲"}],
        )

    def test_excel_entry_point_equivalent(self):
        config = self._config(
            [make_entity(entries=[make_entry("event_type", field="事件状态")])]
        )
        excel = self._excel(
            [("事件状态", [HEADER, ["EQUAL", "login", "登录"]])]
        )
        code, payload = self._run("--input", str(config), "--excel", str(excel))
        self.assertEqual(code, 0)
        result = self._read_output(payload)
        self.assertEqual(
            result[0]["normalize"][0]["mappings"],
            [{"mappingType": "EQUAL", "orgValue": "login", "mappingValue": "登录"}],
        )

    def test_same_orgvalue_updates_in_place(self):
        existing = [{"mappingType": "EQUAL", "orgValue": "login", "mappingValue": "旧值"}]
        config = self._config(
            [make_entity(entries=[make_entry("event_type", mappings=existing)])]
        )
        pairs = self._mappings_json(
            {
                "mappings": [
                    {
                        "field": "event_type",
                        "pairs": [
                            {"orgValue": "login", "mappingValue": "登录"},
                            {"orgValue": "logout", "mappingValue": "注销"},
                        ],
                    }
                ]
            }
        )
        code, payload = self._run("--input", str(config), "--mappings", str(pairs))
        self.assertEqual(code, 0)
        result = self._read_output(payload)
        self.assertEqual(
            result[0]["normalize"][0]["mappings"],
            [
                {"mappingType": "EQUAL", "orgValue": "login", "mappingValue": "登录"},
                {"mappingType": "EQUAL", "orgValue": "logout", "mappingValue": "注销"},
            ],
        )
        self.assertEqual(payload["fields"][0]["updated"], 1)
        self.assertEqual(payload["fields"][0]["added"], 1)

    def test_identical_rerun_is_idempotent_success(self):
        config = self._config(
            [
                make_entity(
                    entries=[
                        make_entry(
                            "event_type",
                            mappings=[
                                {
                                    "mappingType": "EQUAL",
                                    "orgValue": "login",
                                    "mappingValue": "登录",
                                }
                            ],
                        )
                    ]
                )
            ]
        )
        pairs = self._mappings_json(
            {"mappings": [{"field": "event_type", "pairs": [{"orgValue": "login", "mappingValue": "登录"}]}]}
        )
        code, payload = self._run("--input", str(config), "--mappings", str(pairs))
        self.assertEqual(code, 0)
        self.assertIn("无变更", payload["message"])
        self.assertEqual(payload["fields"][0]["unchanged"], 1)
        self.assertEqual(payload["fields"][0]["added"], 0)

    def test_input_duplicate_orgvalue_first_wins(self):
        config = self._config([make_entity(entries=[make_entry("event_type")])])
        pairs = self._mappings_json(
            {
                "mappings": [
                    {
                        "field": "event_type",
                        "pairs": [
                            {"orgValue": "login", "mappingValue": "登录"},
                            {"orgValue": "login", "mappingValue": "后到"},
                        ],
                    }
                ]
            }
        )
        code, payload = self._run("--input", str(config), "--mappings", str(pairs))
        self.assertEqual(code, 0)
        result = self._read_output(payload)
        self.assertEqual(
            result[0]["normalize"][0]["mappings"],
            [{"mappingType": "EQUAL", "orgValue": "login", "mappingValue": "登录"}],
        )
        self.assertEqual(payload["fields"][0]["duplicates"], 1)

    def test_unbind_fixed_value_binding_keeps_reference(self):
        filters = [
            {
                "name": "addFields",
                "id": "",
                "fields": {"event_type": "固定值", "other": "%{src}"},
            }
        ]
        config = self._config(
            [make_entity(entries=[make_entry("event_type")], filters=filters)]
        )
        pairs = self._mappings_json(
            {"mappings": [{"field": "event_type", "pairs": [{"orgValue": "a", "mappingValue": "甲"}]}]}
        )
        code, payload = self._run("--input", str(config), "--mappings", str(pairs))
        self.assertEqual(code, 0)
        self.assertEqual(payload["unbound"], 1)
        result = self._read_output(payload)
        fields = result[0]["parser"]["filter"][0]["fields"]
        self.assertNotIn("event_type", fields)
        self.assertEqual(fields["other"], "%{src}")

    def test_unbind_drops_empty_addfields_item(self):
        filters = [{"name": "addFields", "id": "", "fields": {"event_type": "固定值"}}]
        config = self._config(
            [make_entity(entries=[make_entry("event_type")], filters=filters)]
        )
        pairs = self._mappings_json(
            {"mappings": [{"field": "event_type", "pairs": [{"orgValue": "a", "mappingValue": "甲"}]}]}
        )
        code, payload = self._run("--input", str(config), "--mappings", str(pairs))
        self.assertEqual(code, 0)
        result = self._read_output(payload)
        self.assertEqual(result[0]["parser"]["filter"], [])

    def test_missing_target_rejects_whole_run(self):
        config = self._config(
            [make_entity(entries=[make_entry("event_type")])]
        )
        pairs = self._mappings_json(
            {
                "mappings": [
                    {"field": "event_type", "pairs": [{"orgValue": "a", "mappingValue": "甲"}]},
                    {"field": "no_such_field", "pairs": [{"orgValue": "b", "mappingValue": "乙"}]},
                ]
            }
        )
        code, payload = self._run("--input", str(config), "--mappings", str(pairs))
        self.assertEqual(code, 1)
        self.assertEqual(payload["status"], "error")
        self.assertEqual(payload["code"], "enum_target_field_mismatch")
        self.assertIn("no_such_field", payload["message"])
        self.assertIn("event_type", payload["message"])  # 可用字段提示
        # 整单拒绝：不产出任何文件
        outputs = list(self._tmp.glob("*.enumfilled.json"))
        self.assertEqual(outputs, [])

    def test_blacklist_target_rejected(self):
        config = self._config(
            [make_entity(entries=[make_entry("事件名称", field="event_name")])]
        )
        pairs = self._mappings_json(
            {"mappings": [{"field": "event_name", "pairs": [{"orgValue": "a", "mappingValue": "甲"}]}]}
        )
        code, payload = self._run("--input", str(config), "--mappings", str(pairs))
        self.assertEqual(code, 1)
        self.assertEqual(payload["code"], "reserved_field_rejected")

    def test_blacklisted_index_name_rejected(self):
        config = self._config(
            [make_entity(entries=[make_entry("威胁类型")])]
        )
        pairs = self._mappings_json(
            {"mappings": [{"field": "威胁类型", "pairs": [{"orgValue": "a", "mappingValue": "甲"}]}]}
        )
        code, payload = self._run("--input", str(config), "--mappings", str(pairs))
        self.assertEqual(code, 1)
        self.assertEqual(payload["code"], "reserved_field_rejected")

    def test_inputs_mutually_exclusive(self):
        config = self._config([make_entity(entries=[make_entry("event_type")])])
        pairs = self._mappings_json(
            {"mappings": [{"field": "event_type", "pairs": [{"orgValue": "a", "mappingValue": "甲"}]}]}
        )
        excel = self._excel([("event_type", [HEADER, ["EQUAL", "a", "甲"]])])
        code, payload = self._run(
            "--input", str(config), "--mappings", str(pairs), "--excel", str(excel)
        )
        self.assertEqual(code, 1)
        self.assertEqual(payload["code"], "invalid_input")
        code, payload = self._run("--input", str(config))
        self.assertEqual(code, 1)
        self.assertEqual(payload["code"], "invalid_input")

    def test_field_without_valid_pairs_rejected(self):
        config = self._config([make_entity(entries=[make_entry("event_type")])])
        pairs = self._mappings_json(
            {"mappings": [{"field": "event_type", "pairs": [{"orgValue": "", "mappingValue": "x"}]}]}
        )
        code, payload = self._run("--input", str(config), "--mappings", str(pairs))
        self.assertEqual(code, 1)
        self.assertEqual(payload["code"], "invalid_input")
        self.assertIn("event_type", payload["message"])

    def test_bad_json_contract_rejected(self):
        config = self._config([make_entity(entries=[make_entry("event_type")])])
        pairs = self._mappings_json({"mappings": [{"field": "event_type"}]})
        code, payload = self._run("--input", str(config), "--mappings", str(pairs))
        self.assertEqual(code, 1)
        self.assertEqual(payload["code"], "invalid_input")
        pairs = self._mappings_json({"mappings": ["junk"]})
        code, payload = self._run("--input", str(config), "--mappings", str(pairs))
        self.assertEqual(code, 1)
        self.assertEqual(payload["code"], "invalid_input")

    def test_excel_reader_error_passthrough(self):
        config = self._config([make_entity(entries=[make_entry("event_type")])])
        excel = self._excel([("empty_sheet", [HEADER])])
        code, payload = self._run("--input", str(config), "--excel", str(excel))
        self.assertEqual(code, 1)
        self.assertEqual(payload["code"], "invalid_input")

    def test_config_load_error(self):
        pairs = self._mappings_json(
            {"mappings": [{"field": "x", "pairs": [{"orgValue": "a", "mappingValue": "甲"}]}]}
        )
        code, payload = self._run(
            "--input", str(self._tmp / "nope.json"), "--mappings", str(pairs)
        )
        self.assertEqual(code, 1)
        self.assertEqual(payload["code"], "config_required")


if __name__ == "__main__":
    unittest.main()
