"""delete_fields 单元与端到端测试。

覆盖 delete_field 核心行为、删除守卫链与文件契约端到端。
"""

from __future__ import annotations

import base64
import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILLS = ROOT / "skills" / "parser-skills"
for path in (str(ROOT), str(SKILLS), str(SKILLS / "field-adjust" / "scripts")):
    if path not in sys.path:
        sys.path.insert(0, path)

import delete_fields  # noqa: E402
from _shared.event_binding import EVENT_LEVEL_FIELD, EVENT_NAME_FIELD  # noqa: E402


def make_entity(name: str, *, normalize=None, filters=None) -> dict:
    return {
        "name": name,
        "parser": {"name": "json", "filter": filters},
        "normalize": normalize if normalize is not None else [],
    }


def norm_entry(index: str, result=None, field=None) -> dict:
    return {
        "mappings": [],
        "field": field,
        "sim": None,
        "result": result if result is not None else [],
        "info": None,
        "entity": None,
        "required": False,
        "core": None,
        "value": None,
        "index": index,
    }


class DeleteFieldCoreTest(unittest.TestCase):
    """delete_field() 纯函数核心行为。"""

    def setUp(self):
        self.data = [
            make_entity(
                "rule_a",
                normalize=[
                    norm_entry("src_ip", ["10.0.0.1"]),
                    norm_entry("主机ip", ["1.1.1.1"]),
                ],
                filters=[
                    {
                        "name": "addFields",
                        "id": "",
                        "fields": {"主机ip": "1.1.1.1", "备注": "x"},
                    }
                ],
            ),
            make_entity(
                "rule_b",
                normalize=[
                    norm_entry("src_ip", ["1.2.3.4"]),
                    norm_entry("dst_ip", ["2.3.4.5"]),
                ],
            ),
            make_entity("rule_empty"),
        ]

    def _ok(self, result):
        self.assertEqual(result["status"], "success")
        return result["data"]

    def test_deletes_normalize_entry_and_writes_removefields(self):
        updated = self._ok(delete_fields.delete_field(self.data, ["主机ip"]))
        rule_a = updated[0]
        indexes = [e["index"] for e in rule_a["normalize"]]
        self.assertNotIn("主机ip", indexes)
        self.assertIn("src_ip", indexes)
        remove_filter = rule_a["parser"]["filter"][-1]
        self.assertEqual(remove_filter["name"], "removeFields")
        self.assertEqual(remove_filter["id"], "")
        self.assertEqual(remove_filter["fields"], ["主机ip"])

    def test_multiple_fields_across_entities(self):
        result = delete_fields.delete_field(self.data, ["src_ip", "dst_ip"])
        self.assertIn("成功从 2 个 entity 删除 3 个字段", result["message"])
        updated = result["data"]
        self.assertNotIn(
            "src_ip", [e["index"] for e in updated[0]["normalize"]]
        )
        self.assertNotIn(
            "src_ip", [e["index"] for e in updated[1]["normalize"]]
        )
        self.assertNotIn(
            "dst_ip", [e["index"] for e in updated[1]["normalize"]]
        )

    def test_addfields_binding_cleaned_partially(self):
        updated = self._ok(delete_fields.delete_field(self.data, ["主机ip"]))
        kept = [
            f for f in updated[0]["parser"]["filter"]
            if f.get("name") == "addFields" and f.get("id") == ""
        ]
        self.assertEqual(len(kept), 1)
        self.assertEqual(kept[0]["fields"], {"备注": "x"})

    def test_addfields_filter_removed_when_emptied(self):
        data = [
            make_entity(
                "rule_a",
                normalize=[norm_entry("主机ip", ["1.1.1.1"])],
                filters=[
                    {"name": "addFields", "id": "", "fields": {"主机ip": "1.1.1.1"}},
                ],
            )
        ]
        updated = self._ok(delete_fields.delete_field(data, ["主机ip"]))
        names = [f.get("name") for f in updated[0]["parser"]["filter"]]
        self.assertNotIn("addFields", names)
        self.assertIn("removeFields", names)

    def test_merges_into_existing_removefields(self):
        data = [
            make_entity(
                "rule_a",
                normalize=[norm_entry("src_ip", ["1"])],
                filters=[
                    {"name": "removeFields", "id": "", "fields": ["旧字段"]},
                ],
            )
        ]
        updated = self._ok(delete_fields.delete_field(data, ["src_ip"]))
        remove_filter = updated[0]["parser"]["filter"][0]
        self.assertEqual(remove_filter["fields"], ["旧字段", "src_ip"])

    def test_missing_field_success_with_not_found(self):
        result = delete_fields.delete_field(self.data, ["不存在"])
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["not_found"], ["不存在"])
        self.assertIn("未找到字段: 不存在（不存在于任何子规则）", result["message"])
        # 字段在任何子规则都没有时不计入删除数
        self.assertIn("成功从 0 个 entity 删除 0 个字段", result["message"])

    def test_target_scope_and_passthrough(self):
        result = delete_fields.delete_field(self.data, ["src_ip"], ["rule_a"])
        self.assertIn("目标 1 个", result["message"])
        updated = result["data"]
        self.assertNotIn("src_ip", [e["index"] for e in updated[0]["normalize"]])
        # 名单外 entity 原样透传
        self.assertIn("src_ip", [e["index"] for e in updated[1]["normalize"]])
        self.assertEqual(len(updated[1]["normalize"]), 2)

    def test_entity_without_normalize_skipped_and_counted(self):
        result = delete_fields.delete_field(self.data, ["src_ip"])
        self.assertIn("跳过 1 个无 normalize 的 entity", result["message"])
        self.assertEqual(result["data"][2]["normalize"], [])

    def test_null_filter_initialized(self):
        data = [make_entity("rule_b", normalize=[norm_entry("src_ip", ["1"])])]
        updated = self._ok(delete_fields.delete_field(data, ["src_ip"]))
        self.assertEqual(
            [f["name"] for f in updated[0]["parser"]["filter"]], ["removeFields"]
        )

    def test_input_not_mutated(self):
        snapshot = json.dumps(self.data, ensure_ascii=False)
        delete_fields.delete_field(self.data, ["主机ip", "src_ip"])
        self.assertEqual(json.dumps(self.data, ensure_ascii=False), snapshot)

    def test_empty_data_error(self):
        result = delete_fields.delete_field([], ["x"])
        self.assertEqual(result["status"], "error")

    def test_empty_fields_error(self):
        result = delete_fields.delete_field(self.data, [])
        self.assertEqual(result["status"], "error")

    def test_reserved_field_rejected(self):
        result = delete_fields.delete_field(self.data, ["original_log"])
        self.assertEqual(result["status"], "error")
        self.assertIn("系统保留字段", result["message"])


if __name__ == "__main__":
    unittest.main()
