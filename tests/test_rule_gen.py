"""rule_gen 单元测试：规则骨架模板与子规则装配（照工作台 rule_generator 复刻）。

接缝：get_sub_rule_template / value_to_str / escape_delimit /
generate_sub_rules（输入为工作台兼容的 classification dict）。
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILLS = ROOT / "skills" / "parser-skills"
for path in (str(ROOT), str(ROOT / "tests"), str(SKILLS)):
    if path not in sys.path:
        sys.path.insert(0, path)

from _shared import rule_gen  # noqa: E402


def _kv_classification():
    return {
        "status": "SUCCESS",
        "log_format": "KV",
        "log_format_detail": "纯KV",
        "feature_field": "type",
        "feature_count": 2,
        "total_valid_lines": 3,
        "covered_lines": 3,
        "Diversion_method": "日志类型",
        "analysis": {
            "has_json_structure": False,
            "has_cef_prefix": False,
            "has_key_value_pairs": True,
            "has_delimited_structure": False,
            "delimit": "||",
            "tab": ":",
        },
        "classification_details": [
            {
                "logtype": "attack",
                "meaning": "攻击告警",
                "count": 2,
                "sample": "type:attack||src:1.1.1.1",
                "real_samples": "type:attack||src:1.1.1.1",
            },
            {
                "logtype": "login",
                "meaning": "登录事件",
                "count": 1,
                "sample": "type:login||src:2.2.2.2",
                "real_samples": "type:login||src:2.2.2.2",
            },
        ],
    }


def _json_classification():
    return {
        "status": "SUCCESS",
        "log_format": "JSON",
        "log_format_detail": "纯JSON",
        "feature_field": "event.action",
        "feature_count": 1,
        "total_valid_lines": 1,
        "covered_lines": 1,
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
            {
                "logtype": "login",
                "meaning": "登录事件",
                "count": 1,
                "sample": '{"user": "u1", "event": {"action": "login"}}',
                "real_samples": '{"user": "u1", "event": {"action": "login"}}',
            }
        ],
    }


class TemplateTest(unittest.TestCase):
    def test_sub_rule_template_shape(self):
        rule = rule_gen.get_sub_rule_template()
        self.assertEqual(rule["parser"]["subResolver"], 1)
        self.assertEqual(rule["entities"], ["日志"])
        addfields = rule["parser"]["filter"][0]
        self.assertEqual(addfields["name"], "addFields")
        self.assertEqual(
            sorted(addfields["fields"]), ["event_level", "event_name", "log_vendor", "product"]
        )
        self.assertEqual(rule["deviceType"], {"id": "1", "name": "设备分类", "parentId": ""})

    def test_template_deep_copied(self):
        rule = rule_gen.get_sub_rule_template()
        rule["parser"]["filter"][0]["fields"]["product"] = "污染"
        fresh = rule_gen.get_sub_rule_template()
        self.assertEqual(fresh["parser"]["filter"][0]["fields"]["product"], "")


class UtilsTest(unittest.TestCase):
    def test_value_to_str(self):
        self.assertEqual(rule_gen.value_to_str(None), "")
        self.assertEqual(rule_gen.value_to_str(True), "true")
        self.assertEqual(rule_gen.value_to_str(False), "false")
        self.assertEqual(rule_gen.value_to_str(3), "3")
        self.assertEqual(rule_gen.value_to_str(3.5), "3.5")
        self.assertEqual(rule_gen.value_to_str("x"), "x")
        self.assertEqual(rule_gen.value_to_str({"b": 1, "a": 2}), '{"a": 2, "b": 1}')

    def test_escape_delimit(self):
        self.assertEqual(rule_gen.escape_delimit("space"), "\\s")
        self.assertEqual(rule_gen.escape_delimit("tab"), "\\t")
        self.assertEqual(rule_gen.escape_delimit("||"), "||")
        self.assertEqual(rule_gen.escape_delimit(";"), ";")


class GenerateSubRulesKvTest(unittest.TestCase):
    def setUp(self):
        self.all_logs = "\n".join(
            [
                "type:attack||src:1.1.1.1",
                "type:attack||port:22",
                "type:login||src:2.2.2.2",
            ]
        )
        self.rules = rule_gen.generate_sub_rules(_kv_classification(), self.all_logs)

    def test_one_rule_per_logtype(self):
        self.assertEqual(len(self.rules), 2)
        self.assertEqual(
            [r["name"] for r in self.rules], ["attack_kv_子规则", "login_kv_子规则"]
        )

    def test_parser_config(self):
        rule = self.rules[0]
        self.assertEqual(rule["parser"]["name"], "delimitWithKeyMap")
        self.assertEqual(rule["parser"]["tab"], ":")
        self.assertEqual(rule["parser"]["delimit"], "||")
        self.assertEqual(rule["parser"]["subResolver"], 1)
        self.assertEqual(rule["subResolver"], 1)

    def test_filter_has_logtype_addfields(self):
        filters = self.rules[0]["parser"]["filter"]
        self.assertEqual(filters[0]["name"], "addFields")
        self.assertEqual(filters[0]["id"], "additional_fields_filter")
        logtype_filter = filters[1]
        self.assertEqual(logtype_filter["fields"], {"日志类型": "attack"})
        self.assertEqual(logtype_filter["name"], "addFields")

    def test_normalize_keys_sorted_with_logtype_last(self):
        rule = self.rules[0]  # attack 行：type/src/port
        indexes = [e["index"] for e in rule["normalize"]]
        self.assertEqual(indexes, sorted(indexes))
        self.assertEqual(indexes[-1], "日志类型")
        self.assertIn("src", indexes)
        self.assertIn("port", indexes)
        logtype_entry = rule["normalize"][-1]
        self.assertEqual(logtype_entry["result"], ["attack"])

    def test_common_fields_filled(self):
        rule = self.rules[0]
        self.assertTrue(rule["id"])
        self.assertGreater(rule["createtime"], 0)
        self.assertEqual(rule["lasttime"], rule["createtime"])
        self.assertEqual(rule["description"], rule["name"])
        self.assertEqual(rule["sample"], "type:attack||src:1.1.1.1")
        self.assertEqual(rule["properties"], [])


class GenerateSubRulesJsonTest(unittest.TestCase):
    def setUp(self):
        self.rules = rule_gen.generate_sub_rules(_json_classification())

    def test_rule_name_and_parser(self):
        rule = self.rules[0]
        self.assertEqual(rule["name"], "login_event.action_json_子规则")
        self.assertEqual(rule["parser"]["name"], "json")
        self.assertNotIn("tab", rule["parser"])

    def test_no_logtype_filter_for_pure_json(self):
        filters = self.rules[0]["parser"]["filter"]
        self.assertEqual(len(filters), 1)
        self.assertEqual(filters[0]["id"], "additional_fields_filter")

    def test_normalize_from_real_sample(self):
        entries = self.rules[0]["normalize"]
        indexes = [e["index"] for e in entries]
        self.assertEqual(
            indexes, ["event", "event.action", "original_log", "user"]
        )
        original_log = entries[2]
        self.assertEqual(original_log["field"], "original_log")
        self.assertEqual(original_log["entity"], "日志")
        self.assertEqual(original_log["sim"], True)


if __name__ == "__main__":
    unittest.main()
