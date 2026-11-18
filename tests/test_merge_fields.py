"""merge_fields 单元与端到端测试。

覆盖 merge_field 核心行为、合并守卫链与文件契约端到端。
"""

from __future__ import annotations

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

import merge_fields  # noqa: E402
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


class MergeFieldCoreTest(unittest.TestCase):
    """merge_field() 纯函数核心行为。"""

    def setUp(self):
        self.data = [
            make_entity(
                "rule_a",
                normalize=[
                    norm_entry("a", ["1"]),
                    norm_entry("b", ["2"]),
                ],
            ),
            make_entity(
                "rule_b",
                normalize=[
                    norm_entry("a", ["x"]),
                ],
            ),
            make_entity("rule_empty"),
        ]

    def _ok(self, result):
        self.assertEqual(result["status"], "success")
        return result["data"]

    def test_merges_two_fields_into_new_field(self):
        updated = self._ok(merge_fields.merge_field(self.data, ["a", "b"], "c", "-"))
        rule_a = updated[0]
        merger = rule_a["parser"]["filter"][-1]
        self.assertEqual(merger["name"], "merger")
        self.assertEqual(merger["field"], "c")
        self.assertEqual(merger["sep"], "-")
        self.assertEqual(merger["id"], "")
        self.assertEqual(merger["fields"], ["a", "b"])
        preview = rule_a["normalize"][-1]
        self.assertEqual(preview["index"], "c")
        self.assertEqual(preview["result"], ["1-2"])
        self.assertEqual(preview["mappings"], [])
        # 源字段条目保留（merger 运行时依赖源字段）
        indexes = [e["index"] for e in rule_a["normalize"]]
        self.assertIn("a", indexes)
        self.assertIn("b", indexes)

    def test_sep_defaults_to_empty_string(self):
        updated = self._ok(merge_fields.merge_field(self.data, ["a", "b"], "c"))
        merger = updated[0]["parser"]["filter"][-1]
        self.assertEqual(merger["sep"], "")
        self.assertEqual(updated[0]["normalize"][-1]["result"], ["12"])

    def test_missing_source_skips_entity_and_reports(self):
        result = merge_fields.merge_field(self.data, ["a", "b"], "c")
        self.assertEqual(result["status"], "success")
        self.assertIn("成功合并 1 个 entity", result["message"])
        self.assertIn("rule_b（缺 b）", result["message"])
        # 缺源的 rule_b 原样保留，未写入 merger
        self.assertEqual(result["data"][1]["parser"]["filter"], None)

    def test_target_exists_skips_entity_and_reports(self):
        data = [
            make_entity("rule_a", normalize=[norm_entry("a", ["1"]), norm_entry("b", ["2"])]),
            make_entity(
                "rule_c",
                normalize=[norm_entry("a", ["3"]), norm_entry("b", ["4"]), norm_entry("c", ["旧"])],
            ),
        ]
        result = merge_fields.merge_field(data, ["a", "b"], "c")
        self.assertEqual(result["status"], "success")
        self.assertIn("rule_c（目标 'c' 已存在）", result["message"])
        self.assertIn("成功合并 1 个 entity", result["message"])
        self.assertEqual(result["data"][1]["normalize"][-1]["result"], ["旧"])

    def test_all_missing_source_reports_field_not_found(self):
        result = merge_fields.merge_field(self.data, ["a", "z"], "c")
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["code"], "field_not_found")
        self.assertIn("不存在于任何（目标）子规则", result["message"])
        # 消息附全部子规则字段并集预览，帮助定位名字错误
        self.assertIn("a", result["message"])
        self.assertIn("b", result["message"])

    def test_existing_merger_for_target_updated_in_place(self):
        data = [
            make_entity(
                "rule_a",
                normalize=[norm_entry("a", ["1"]), norm_entry("b", ["2"])],
                filters=[
                    {"name": "addFields", "id": "", "fields": {"x": "1"}},
                    {"name": "merger", "id": "", "field": "c", "sep": "+", "fields": ["x", "y"]},
                ],
            )
        ]
        updated = self._ok(merge_fields.merge_field(data, ["a", "b"], "c", "-"))
        filters = updated[0]["parser"]["filter"]
        self.assertEqual(len(filters), 2)
        merger = filters[1]
        self.assertEqual(merger["fields"], ["a", "b"])
        self.assertEqual(merger["sep"], "-")

    def test_null_filter_initialized(self):
        data = [
            make_entity("rule_a", normalize=[norm_entry("a", ["1"]), norm_entry("b", ["2"])]),
        ]
        updated = self._ok(merge_fields.merge_field(data, ["a", "b"], "c"))
        self.assertEqual(
            [f["name"] for f in updated[0]["parser"]["filter"]], ["merger"]
        )

    def test_target_scope_and_passthrough(self):
        result = merge_fields.merge_field(self.data, ["a", "b"], "c", "", ["rule_a"])
        self.assertIn("目标 1 个", result["message"])
        updated = result["data"]
        self.assertEqual(updated[0]["parser"]["filter"][-1]["name"], "merger")
        # 名单外 entity 原样透传
        self.assertEqual(updated[1]["parser"]["filter"], None)

    def test_entity_without_normalize_skipped_and_counted(self):
        result = merge_fields.merge_field(self.data, ["a", "b"], "c")
        self.assertIn("跳过 1 个无 normalize 的 entity", result["message"])
        self.assertEqual(result["data"][2]["normalize"], [])

    def test_input_not_mutated(self):
        snapshot = json.dumps(self.data, ensure_ascii=False)
        merge_fields.merge_field(self.data, ["a", "b"], "c", "-")
        self.assertEqual(json.dumps(self.data, ensure_ascii=False), snapshot)

    def test_empty_data_error(self):
        result = merge_fields.merge_field([], ["a", "b"], "c")
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["code"], "invalid_input")

    def test_fewer_than_two_sources_error(self):
        result = merge_fields.merge_field(self.data, ["a"], "c")
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["code"], "invalid_input")
        self.assertIn("至少需要 2 个源字段", result["message"])

    def test_empty_target_field_error(self):
        result = merge_fields.merge_field(self.data, ["a", "b"], "")
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["code"], "invalid_input")


if __name__ == "__main__":
    unittest.main()
