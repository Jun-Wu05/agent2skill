"""threat_policy 纯策略测试：白名单 / 威胁子规则圈定 / 覆盖校验 / 三态探测与条目构造。

接缝：_shared/threat_policy.py 的纯函数族（设计裁决见 #4 票面
2026-11-23 九问）。夹具为合成 entities 与目录桩。
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

from _shared import report as skill_report  # noqa: E402
from _shared.enum_table import normalize_pair  # noqa: E402
from _shared.standard_catalog import load_catalog  # noqa: E402
from _shared.threat_policy import (  # noqa: E402
    THREAT_FIELD_ABSENT,
    THREAT_FIELD_CHAIN,
    THREAT_FIELD_EXISTING,
    THREAT_TYPE_FIELD,
    ThreatPolicyError,
    append_threat_type_binding,
    collect_threat_rule_names,
    find_threat_type_entries,
    inspect_threat_field_state,
    is_code_only_value,
    make_threat_type_normalize_entry,
    remove_threat_type_writings,
    row_covers_value,
    rule_sample_count,
    threat_field_pools,
    threat_whitelist,
    validate_group_assignment,
    validate_threat_coverage,
)


def make_entry(index, field=None, mappings=None, result=None):
    return {
        "mappings": mappings if mappings is not None else [],
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


def make_entity(name="规则A", entries=(), filters=(), event_name=None):
    filters = list(filters)
    if event_name is not None:
        filters.append(
            {"name": "addFields", "id": "", "fields": {"事件名称": event_name}}
        )
    return {
        "name": name,
        "parser": {"name": "kv", "tab": "=", "delimit": "\\s", "filter": filters},
        "normalize": list(entries),
        "sample": "",
    }


def make_addfields(fields):
    return {"name": "addFields", "id": "", "fields": dict(fields)}


class ThreatWhitelistTest(unittest.TestCase):
    def test_whitelist_from_real_catalog(self):
        whitelist = threat_whitelist(load_catalog())
        self.assertGreater(len(whitelist), 100)
        self.assertIn("其他", whitelist)
        self.assertIn("挖矿木马", whitelist)
        self.assertIn("勒索病毒", whitelist)

    def test_missing_field_raises(self):
        class StubCatalog:
            def lookup(self, name):
                return None

        with self.assertRaises(ThreatPolicyError) as ctx:
            threat_whitelist(StubCatalog())
        self.assertEqual(ctx.exception.code, "threat_mapping_reference_unavailable")

    def test_non_enum_field_raises(self):
        class StubField:
            data_type = "字符"
            enum_values = ""

        class StubCatalog:
            def lookup(self, name):
                return StubField()

        with self.assertRaises(ThreatPolicyError) as ctx:
            threat_whitelist(StubCatalog())
        self.assertEqual(ctx.exception.code, "threat_mapping_reference_unavailable")

    def test_empty_enum_values_raise(self):
        class StubField:
            data_type = "枚举"
            enum_values = " , ,"

        class StubCatalog:
            def lookup(self, name):
                return StubField()

        with self.assertRaises(ThreatPolicyError) as ctx:
            threat_whitelist(StubCatalog())
        self.assertEqual(ctx.exception.code, "threat_mapping_reference_unavailable")


class CollectThreatRulesTest(unittest.TestCase):
    def test_threat_group_only(self):
        config = [
            make_entity("威胁规则", event_name="网络攻击"),
            make_entity("普通规则", event_name="登录事件"),
            make_entity("未标注规则"),
        ]
        self.assertEqual(collect_threat_rule_names(config), ["威胁规则"])

    def test_no_annotation_raises(self):
        with self.assertRaises(ThreatPolicyError) as ctx:
            collect_threat_rule_names([make_entity("规则A")])
        self.assertEqual(ctx.exception.code, "event_annotation_required")

    def test_no_threat_member_raises(self):
        config = [make_entity("普通规则", event_name="登录事件")]
        with self.assertRaises(ThreatPolicyError) as ctx:
            collect_threat_rule_names(config)
        self.assertEqual(ctx.exception.code, "rule_name_not_found")


class FieldPoolsTest(unittest.TestCase):
    def test_excludes_meta_and_threat_fields(self):
        config = [
            make_entity(
                "威胁规则",
                entries=[
                    make_entry("original_log"),
                    make_entry("日志类型"),
                    make_entry("事件名称"),
                    make_entry("事件级别"),
                    make_entry(THREAT_TYPE_FIELD),
                    make_entry("threat_name"),
                    make_entry("threat_name"),  # 去重
                    make_entry(""),
                ],
            )
        ]
        pools = threat_field_pools(config, ["威胁规则"])
        self.assertEqual(pools, {"威胁规则": ["threat_name"]})

    def test_missing_rule_absent(self):
        pools = threat_field_pools([make_entity("规则A")], ["不存在"])
        self.assertEqual(pools, {})


class CodeOnlyValueTest(unittest.TestCase):
    def test_code_only(self):
        for value in ("123", "4457", "1.2.3.4", "01-02", "1_2", "3:4/5"):
            self.assertTrue(is_code_only_value(value), value)

    def test_semantic_values(self):
        for value in ("挖矿", "web-01", "SQL注入", "", "  ", None):
            self.assertFalse(is_code_only_value(value), repr(value))


class RowCoversValueTest(unittest.TestCase):
    def test_equal_literal(self):
        pair = {"mappingType": "EQUAL", "orgValue": "挖矿", "mappingValue": "挖矿木马"}
        self.assertTrue(row_covers_value(pair, "挖矿"))
        self.assertFalse(row_covers_value(pair, "挖矿行为"))

    def test_regular_wrapped(self):
        pair = {"mappingType": "REGULAR", "orgValue": ".*挖矿.*", "mappingValue": "挖矿木马"}
        self.assertTrue(row_covers_value(pair, "检测到挖矿行为"))
        self.assertFalse(row_covers_value(pair, "勒索"))

    def test_regular_case_insensitive_flag(self):
        pair = {
            "mappingType": "REGULAR",
            "orgValue": "(?i).*Webshell.*",
            "mappingValue": "Webshell",
        }
        self.assertTrue(row_covers_value(pair, "detected webshell upload"))
        self.assertFalse(row_covers_value(pair, "rootkit"))

    def test_invalid_regex_is_no_match(self):
        pair = {"mappingType": "REGULAR", "orgValue": "(?i)*[挖*", "mappingValue": "其他"}
        self.assertFalse(row_covers_value(pair, "挖矿"))

    def test_empty_org_value(self):
        pair = {"mappingType": "EQUAL", "orgValue": "", "mappingValue": "其他"}
        self.assertFalse(row_covers_value(pair, "x"))


class ValidateThreatCoverageTest(unittest.TestCase):
    WHITELIST = ("挖矿木马", "勒索病毒", "其他")

    def test_pass(self):
        pairs = [
            {"mappingType": "REGULAR", "orgValue": ".*挖矿.*", "mappingValue": "挖矿木马"},
            {"mappingType": "EQUAL", "orgValue": "Locky", "mappingValue": "勒索病毒"},
        ]
        result = validate_threat_coverage(["挖矿行为", "Locky"], pairs, self.WHITELIST)
        self.assertIsNone(result)

    def test_one_regex_covers_many_values(self):
        pairs = [
            {"mappingType": "REGULAR", "orgValue": ".*挖矿.*", "mappingValue": "挖矿木马"}
        ]
        result = validate_threat_coverage(["挖矿A", "挖矿B"], pairs, self.WHITELIST)
        self.assertIsNone(result)

    def test_mapping_value_out_of_enum(self):
        pairs = [
            {"mappingType": "EQUAL", "orgValue": "x", "mappingValue": "网络入侵"}
        ]
        result = validate_threat_coverage(["x"], pairs, self.WHITELIST)
        self.assertEqual(result["rule"], "mapping_value_out_of_enum")
        self.assertIn("网络入侵", result["message"])

    def test_declared_input_uncovered(self):
        pairs = [
            {"mappingType": "EQUAL", "orgValue": "a", "mappingValue": "挖矿木马"}
        ]
        result = validate_threat_coverage(["a", "漏掉的我"], pairs, self.WHITELIST)
        self.assertEqual(result["rule"], "declared_input_uncovered")
        self.assertIn("漏掉的我", result["message"])

    def test_declared_input_multi_matched(self):
        pairs = [
            {"mappingType": "REGULAR", "orgValue": ".*端口.*", "mappingValue": "端口扫描"},
            {"mappingType": "REGULAR", "orgValue": ".*扫描.*", "mappingValue": "服务扫描"},
        ]
        result = validate_threat_coverage(["端口扫描"], pairs, self.WHITELIST + ("端口扫描", "服务扫描"))
        self.assertEqual(result["rule"], "declared_input_multi_matched")
        self.assertIn("端口扫描", result["message"])

    def test_row_out_of_source(self):
        pairs = [
            {"mappingType": "EQUAL", "orgValue": "a", "mappingValue": "挖矿木马"},
            {"mappingType": "EQUAL", "orgValue": "多余行", "mappingValue": "勒索病毒"},
        ]
        result = validate_threat_coverage(["a"], pairs, self.WHITELIST)
        self.assertEqual(result["rule"], "row_out_of_source")
        self.assertIn("多余行", result["message"])


class ValidateGroupAssignmentTest(unittest.TestCase):
    def test_pass(self):
        groups = [
            {"source_field": "threat_name", "rules": ["规则A", "规则B"]},
            {"source_field": "threat_info", "rules": ["规则C"]},
        ]
        result = validate_group_assignment(["规则A", "规则B", "规则C"], groups, [])
        self.assertIsNone(result)

    def test_pass_with_skipped(self):
        groups = [{"source_field": "threat_name", "rules": ["规则A"]}]
        result = validate_group_assignment(["规则A", "规则C"], groups, ["规则C"])
        self.assertIsNone(result)

    def test_rule_not_in_threat_group(self):
        groups = [{"source_field": "x", "rules": ["普通规则"]}]
        result = validate_group_assignment(["威胁规则"], groups, [])
        self.assertEqual(result["rule"], "rule_not_in_threat_group")

    def test_rule_assigned_twice_across_groups(self):
        groups = [
            {"source_field": "x", "rules": ["规则A"]},
            {"source_field": "y", "rules": ["规则A"]},
        ]
        result = validate_group_assignment(["规则A"], groups, [])
        self.assertEqual(result["rule"], "rule_assigned_twice")

    def test_rule_assigned_twice_group_and_skipped(self):
        groups = [{"source_field": "x", "rules": ["规则A"]}]
        result = validate_group_assignment(["规则A"], groups, ["规则A"])
        self.assertEqual(result["rule"], "rule_assigned_twice")

    def test_rule_unassigned(self):
        groups = [{"source_field": "x", "rules": ["规则A"]}]
        result = validate_group_assignment(["规则A", "规则B", "规则C"], groups, [])
        self.assertEqual(result["rule"], "rule_unassigned")
        self.assertIn("规则B", result["message"])


class InspectThreatFieldStateTest(unittest.TestCase):
    def test_chain_state(self):
        entity = make_entity(
            "规则A",
            entries=[make_entry(THREAT_TYPE_FIELD)],
            filters=[make_addfields({THREAT_TYPE_FIELD: "%{threat_name}"})],
        )
        self.assertEqual(inspect_threat_field_state(entity), THREAT_FIELD_CHAIN)

    def test_chain_beats_existing(self):
        entity = make_entity(
            "规则A",
            entries=[make_entry(THREAT_TYPE_FIELD, mappings=[])],
            filters=[make_addfields({THREAT_TYPE_FIELD: "%{threat_name}"})],
        )
        self.assertEqual(inspect_threat_field_state(entity), THREAT_FIELD_CHAIN)

    def test_existing_state(self):
        entity = make_entity(
            "规则A",
            entries=[make_entry(THREAT_TYPE_FIELD, mappings=[
                {"mappingType": "EQUAL", "orgValue": "a", "mappingValue": "挖矿木马"}
            ])],
            filters=[make_addfields({THREAT_TYPE_FIELD: "固定值"})],
        )
        self.assertEqual(inspect_threat_field_state(entity), THREAT_FIELD_EXISTING)

    def test_existing_by_field_key(self):
        entity = make_entity(
            "规则A",
            entries=[make_entry("别名", field=THREAT_TYPE_FIELD)],
        )
        self.assertEqual(inspect_threat_field_state(entity), THREAT_FIELD_EXISTING)

    def test_absent_state(self):
        entity = make_entity("规则A", entries=[make_entry("threat_name")])
        self.assertEqual(inspect_threat_field_state(entity), THREAT_FIELD_ABSENT)


class ThreatEntryConstructionTest(unittest.TestCase):
    PAIRS = [
        {"mappingType": "EQUAL", "orgValue": "a", "mappingValue": "挖矿木马"},
    ]

    def test_entry_shape(self):
        entry = make_threat_type_normalize_entry("threat_name", self.PAIRS, sample_count=3)
        self.assertEqual(entry["index"], THREAT_TYPE_FIELD)
        self.assertEqual(entry["field"], "threat_type")
        self.assertEqual(entry["entity"], "威胁")
        self.assertTrue(entry["sim"])
        self.assertFalse(entry["core"])
        self.assertEqual(entry["result"], ["%{threat_name}"] * 3)
        self.assertEqual(entry["mappings"], self.PAIRS)
        self.assertIsNot(entry["mappings"][0], self.PAIRS[0])  # 深拷贝保护

    def test_append_binding(self):
        entity = make_entity("规则A", filters=[{"name": "removeFields", "id": "", "fields": ["x"]}])
        append_threat_type_binding(entity, "threat_name")
        addfields = [f for f in entity["parser"]["filter"] if f["name"] == "addFields"]
        self.assertEqual(len(addfields), 1)
        self.assertEqual(addfields[0]["fields"], {THREAT_TYPE_FIELD: "%{threat_name}"})
        # 既有过滤器保持在前
        self.assertEqual(entity["parser"]["filter"][0]["name"], "removeFields")

    def test_remove_writings(self):
        pair = {"mappingType": "EQUAL", "orgValue": "a", "mappingValue": "挖矿木马"}
        entity = make_entity(
            "规则A",
            entries=[
                make_entry("threat_name"),
                make_entry(THREAT_TYPE_FIELD, mappings=[pair]),
                make_entry("别名", field=THREAT_TYPE_FIELD),
            ],
            filters=[
                make_addfields({THREAT_TYPE_FIELD: "%{threat_name}", "别的字段": "1"}),
                make_addfields({THREAT_TYPE_FIELD: "旧固定值"}),
                {"name": "removeFields", "id": "", "fields": ["x"]},
            ],
        )
        counts = remove_threat_type_writings(entity)
        self.assertEqual(counts, {"entries_removed": 2, "bindings_removed": 2})
        self.assertEqual(
            [e["index"] for e in entity["normalize"]],
            ["threat_name"],
        )
        filters = entity["parser"]["filter"]
        self.assertEqual(len(filters), 2)
        self.assertEqual(filters[0]["fields"], {"别的字段": "1"})
        self.assertEqual(filters[1]["name"], "removeFields")

    def test_remove_writings_skips_identified_addfields(self):
        """id 非空的 addFields 不是链路自产载体，整体替换不动它（与三态探测的 id 守卫对称）。"""
        entity = make_entity(
            "规则A",
            entries=[make_entry(THREAT_TYPE_FIELD)],
            filters=[
                {"name": "addFields", "id": "x", "fields": {THREAT_TYPE_FIELD: "别人的绑定"}},
                make_addfields({THREAT_TYPE_FIELD: "%{threat_name}"}),
            ],
        )
        counts = remove_threat_type_writings(entity)
        self.assertEqual(counts, {"entries_removed": 1, "bindings_removed": 1})
        identified = entity["parser"]["filter"][0]
        self.assertEqual(identified["fields"], {THREAT_TYPE_FIELD: "别人的绑定"})

    def test_find_threat_type_entries(self):
        entity = make_entity(
            "规则A",
            entries=[
                make_entry("threat_name"),
                make_entry(THREAT_TYPE_FIELD, mappings=[]),
            ],
        )
        entries = find_threat_type_entries(entity)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["index"], THREAT_TYPE_FIELD)

    def test_rule_sample_count(self):
        entity = make_entity(
            "规则A",
            entries=[make_entry("x", result=[]), make_entry("y", result=["1", "2", "3"])],
        )
        self.assertEqual(rule_sample_count(entity), 3)
        self.assertEqual(rule_sample_count(make_entity("空")), 1)


class ReportTemplateTest(unittest.TestCase):
    def test_threatmapping_config_key(self):
        name = skill_report.download_filename("threatmapping_config", "20261123_0000")
        self.assertEqual(name, "threatmapping_config_20261123_0000.txt")


class EnumTableCaseInsensitiveTest(unittest.TestCase):
    def test_regular_with_flag_prefix_wraps_after_flag(self):
        pair = normalize_pair("REGULAR", "(?i)Webshell", "Webshell")
        self.assertEqual(pair["orgValue"], "(?i).*Webshell.*")

    def test_regular_with_flag_already_wrapped_unchanged(self):
        pair = normalize_pair("REGULAR", "(?i).*Webshell.*", "Webshell")
        self.assertEqual(pair["orgValue"], "(?i).*Webshell.*")

    def test_regular_without_flag_wraps(self):
        pair = normalize_pair("REGULAR", "挖矿", "挖矿木马")
        self.assertEqual(pair["orgValue"], ".*挖矿.*")

    def test_equal_keeps_literal(self):
        pair = normalize_pair("EQUAL", "(?i)Webshell", "Webshell")
        self.assertEqual(pair["orgValue"], "(?i)Webshell")


if __name__ == "__main__":
    unittest.main()
