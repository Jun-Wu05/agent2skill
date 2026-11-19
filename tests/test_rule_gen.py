"""rule_gen 单元测试：规则骨架模板与子规则/入口规则装配。

接缝：get_sub_rule_template / get_entry_rule_template / value_to_str /
escape_delimit / generate_sub_rules / generate_entry_rule（输入为平台
兼容的 classification dict）。
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

    def test_exact_match_empty_does_not_fall_back_to_all_lines(self):
        # 精确匹配（line_matcher）命中零行时不得回退全量行——那会把其他
        # 类型的字段并进本子规则 normalize，掩盖匹配失败
        rules = rule_gen.generate_sub_rules(
            _kv_classification(), "type:attack||src:1.1.1.1",
            line_matcher=lambda logtype, line: False,
        )
        indexes = [e["index"] for e in rules[0]["normalize"]]
        self.assertEqual(indexes, ["日志类型"])

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


def _entry_classification(log_format="JSON", log_format_detail="纯JSON",
                          feature_field="action", feature_identifier=r"(\{[\S\s]*\})",
                          analysis=None, details=None):
    return {
        "status": "SUCCESS",
        "log_format": log_format,
        "log_format_detail": log_format_detail,
        "feature_field": feature_field,
        "feature_identifier": feature_identifier,
        "Diversion_method": "日志类型",
        "analysis": analysis
        or {
            "has_json_structure": log_format == "JSON",
            "has_cef_prefix": False,
            "has_key_value_pairs": log_format == "KV",
            "has_delimited_structure": False,
            "delimit": "||" if log_format == "KV" else "",
            "tab": ":" if log_format == "KV" else "",
        },
        "classification_details": details
        or [
            {
                "logtype": "登录",
                "meaning": "登录",
                "sample": '{"action":"登录","user":"a"}',
                "real_samples": '{"action":"登录","user":"a"}',
            },
            {
                "logtype": "登出",
                "meaning": "登出",
                "sample": '{"action":"登出"}',
                "real_samples": '{"action":"登出"}',
            },
        ],
    }


def _source_fields():
    return rule_gen.RuleSourceFields(product="天擎", log_vendor="奇安信")


class EntryRuleTemplateTest(unittest.TestCase):
    def test_template_shape(self):
        template = rule_gen.get_entry_rule_template()
        self.assertEqual(template["parser"]["subResolver"], 0)
        self.assertIsNone(template["parser"]["filter"])
        self.assertEqual(template["normalize"][0]["index"], "original_log")
        self.assertEqual(template["normalize"][0]["field"], "original_log")
        self.assertEqual(template["subResolver"], 0)

    def test_template_deep_copy(self):
        first = rule_gen.get_entry_rule_template()
        first["normalize"][0]["result"].append("x")
        second = rule_gen.get_entry_rule_template()
        self.assertEqual(second["normalize"][0]["result"], [])


class RuleSourceFieldsTest(unittest.TestCase):
    def test_strips_and_fills_default_data_source(self):
        fields = rule_gen.RuleSourceFields(product=" 天擎 ", log_vendor=" 奇安信 ")
        self.assertEqual(fields.product, "天擎")
        self.assertEqual(fields.log_vendor, "奇安信")
        self.assertEqual(fields.data_source, "天擎(奇安信)")

    def test_missing_required_raises(self):
        with self.assertRaises(ValueError):
            rule_gen.RuleSourceFields(product="", log_vendor="奇安信")
        with self.assertRaises(ValueError):
            rule_gen.RuleSourceFields(product="天擎", log_vendor="")

    def test_source_builders(self):
        fields = _source_fields()
        filter_item = rule_gen.make_source_fields_filter(fields)
        self.assertEqual(filter_item["name"], "addFields")
        self.assertEqual(filter_item["id"], "")
        self.assertEqual(
            filter_item["fields"],
            {"data_source": "天擎(奇安信)", "log_vendor": "奇安信", "product": "天擎"},
        )
        entries = rule_gen.make_source_normalize_entries(fields)
        self.assertEqual([e["index"] for e in entries], ["product", "log_vendor", "data_source"])
        self.assertEqual(entries[0]["result"], ["天擎"])
        self.assertTrue(entries[0]["core"])
        self.assertFalse(entries[2]["core"])
        properties = rule_gen.make_source_properties(fields)
        self.assertEqual([p["key"] for p in properties], ["product", "log_vendor", "data_source"])
        self.assertEqual(properties[0]["sample"], ["天擎"])


class GenerateEntryRuleTest(unittest.TestCase):
    def test_pure_json_entry_rule(self):
        rule = rule_gen.generate_entry_rule(
            _entry_classification(), rule_source_fields=_source_fields()
        )
        self.assertTrue(rule["name"].startswith("奇安信_天擎_通用_入口规则"))
        self.assertEqual(len(rule["name"]) - len("奇安信_天擎_通用_入口规则"), 4)
        self.assertEqual(rule["sample"], '{"action":"登录","user":"a"}#next#{"action":"登出"}')
        self.assertEqual(rule["parser"]["name"], "json")
        self.assertNotIn("value", rule["parser"])
        self.assertEqual(rule["parser"]["subResolver"], 0)
        filters = rule["parser"]["filter"]
        self.assertEqual([f["name"] for f in filters], ["addFields", "conditionMatch", "addFields", "addFields"])
        self.assertEqual(
            [case["value"] for case in filters[1]["cases"]],
            ["original_log like '登录'", "original_log like '登出'"],
        )
        self.assertEqual(filters[2]["fields"], {"日志类型": "%{action}"})
        self.assertEqual(
            filters[3]["fields"]["product"], "天擎"
        )
        self.assertEqual(
            [p["key"] for p in rule["properties"]],
            ["log_type", "rule_name_list", "product", "log_vendor", "data_source"],
        )
        self.assertEqual(rule["properties"][0]["sample"], ["登录", "登出"])
        self.assertEqual(rule["properties"][1]["sample"], [f"[{rule['name']}]", f"[{rule['name']}]"])
        normalize = rule["normalize"]
        self.assertEqual(normalize[0]["result"], ['{"action":"登录","user":"a"}', '{"action":"登出"}'])
        self.assertEqual(normalize[1]["index"], "日志类型")
        self.assertEqual(normalize[1]["result"], [])
        self.assertEqual([e["index"] for e in normalize[2:]], ["product", "log_vendor", "data_source"])

    def test_syslog_json_entry_rule(self):
        rule = rule_gen.generate_entry_rule(
            _entry_classification(log_format_detail="日志头+JSON"),
            rule_source_fields=_source_fields(),
        )
        self.assertEqual(rule["parser"]["name"], "orgRegex")
        self.assertEqual(rule["parser"]["value"], r"(\{[\S\s]*\})")
        self.assertEqual([f["name"] for f in rule["parser"]["filter"]], ["addFields", "conditionMatch", "addFields"])
        indexes = [e["index"] for e in rule["normalize"]]
        self.assertEqual(indexes, ["original_log", "product", "log_vendor", "data_source"])

    def test_pure_kv_entry_rule(self):
        classification = _entry_classification(
            log_format="KV",
            log_format_detail="纯KV",
            feature_field="type",
            feature_identifier="",
            details=[
                {"logtype": "登录", "meaning": "登录", "sample": "type:登录||user:a"},
                {"logtype": "登出", "meaning": "登出", "sample": "type:登出"},
            ],
        )
        rule = rule_gen.generate_entry_rule(classification, rule_source_fields=_source_fields())
        self.assertEqual(rule["parser"]["name"], "delimitWithKeyMap")
        self.assertEqual(rule["parser"]["tab"], ":")
        self.assertEqual(rule["parser"]["delimit"], "||")
        filters = rule["parser"]["filter"]
        self.assertEqual(
            [f["name"] for f in filters], ["addFields", "addFields", "conditionMatch", "addFields"]
        )
        self.assertEqual(filters[1]["fields"], {"日志类型": "%{type}"})
        self.assertEqual(
            [case["value"] for case in filters[2]["cases"]],
            ["type like '登录'", "type like '登出'"],
        )
        indexes = [e["index"] for e in rule["normalize"]]
        self.assertEqual(indexes, ["original_log", "日志类型", "product", "log_vendor", "data_source"])

    def test_syslog_kv_entry_rule(self):
        classification = _entry_classification(
            log_format="KV",
            log_format_detail="日志头+KV",
            feature_field="type",
            feature_identifier=r"HOST-\s+(.*)",
        )
        rule = rule_gen.generate_entry_rule(classification, rule_source_fields=_source_fields())
        self.assertEqual(rule["parser"]["name"], "orgRegex")
        self.assertEqual(rule["parser"]["value"], r"HOST-\s+(.*)")
        filters = rule["parser"]["filter"]
        self.assertEqual([f["name"] for f in filters], ["addFields", "conditionMatch", "addFields"])
        self.assertEqual(
            [case["value"] for case in filters[1]["cases"]],
            ["original_log like '登录'", "original_log like '登出'"],
        )
        indexes = [e["index"] for e in rule["normalize"]]
        self.assertEqual(indexes, ["original_log", "product", "log_vendor", "data_source"])

    def test_default_branch_redirect_filter(self):
        rule = rule_gen.generate_entry_rule(
            _entry_classification(log_format="", log_format_detail="", feature_identifier=r"(?<host>.*)"),
        )
        self.assertEqual(rule["parser"]["name"], "orgRegex")
        filters = rule["parser"]["filter"]
        self.assertEqual([f["name"] for f in filters], ["addFields", "redirect"])
        self.assertEqual(filters[1]["name"], "redirect")
        self.assertEqual(len(filters[1]["cases"]), 2)
        self.assertEqual(filters[1]["cases"][0]["rule"]["name"], "removeFields")
        self.assertTrue(rule["name"].startswith("入口规则_"))

    def test_without_source_fields(self):
        rule = rule_gen.generate_entry_rule(_entry_classification())
        self.assertTrue(rule["name"].startswith("入口规则_"))
        self.assertEqual([f["name"] for f in rule["parser"]["filter"]], ["addFields", "conditionMatch", "addFields"])
        self.assertEqual([p["key"] for p in rule["properties"]], ["log_type", "rule_name_list"])
        indexes = [e["index"] for e in rule["normalize"]]
        self.assertEqual(indexes, ["original_log", "日志类型"])


if __name__ == "__main__":
    unittest.main()
