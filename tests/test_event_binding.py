"""event_binding 单元测试：事件名称读取与事件字段写入。

read_entity_event_name：addFields 固定值优先、normalize 兜底、非法值视为
未标注。make_event_*_normalize_entry / apply_event_fields_to_sub_rules：
事件名称/级别的确定性写入（21 名单校验、级别查表绑定、宁缺勿错）。
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILLS = ROOT / "skills" / "parser-skills"
for path in (str(ROOT), str(SKILLS)):
    if path not in sys.path:
        sys.path.insert(0, path)

from _shared.event_binding import (  # noqa: E402
    EVENT_LEVEL_FIELD,
    EVENT_NAME_FIELD,
    apply_event_fields_to_sub_rules,
    make_event_level_normalize_entry,
    make_event_name_normalize_entry,
    read_entity_event_name,
)


def make_entity(*, addfields=None, normalize=None) -> dict:
    filters = None
    if addfields is not None:
        filters = [{"name": "addFields", "id": "", "fields": addfields}]
    return {
        "name": "rule_a",
        "parser": {"name": "json", "filter": filters},
        "normalize": normalize or [],
    }


def norm_entry(index: str, result) -> dict:
    return {"index": index, "result": result, "mappings": []}


class ReadEntityEventNameTest(unittest.TestCase):
    """read_entity_event_name() 读取逻辑。"""

    def test_reads_from_addfields_fixed_value(self):
        entity = make_entity(addfields={EVENT_NAME_FIELD: "终端告警"})
        self.assertEqual(read_entity_event_name(entity), "终端告警")

    def test_reads_from_normalize_fallback(self):
        entity = make_entity(normalize=[norm_entry(EVENT_NAME_FIELD, ["登录事件"])])
        self.assertEqual(read_entity_event_name(entity), "登录事件")

    def test_addfields_takes_priority_over_normalize(self):
        entity = make_entity(
            addfields={EVENT_NAME_FIELD: "网络攻击"},
            normalize=[norm_entry(EVENT_NAME_FIELD, ["登录事件"])],
        )
        self.assertEqual(read_entity_event_name(entity), "网络攻击")

    def test_invalid_addfields_value_falls_back_to_normalize(self):
        entity = make_entity(
            addfields={EVENT_NAME_FIELD: "自造分类"},
            normalize=[norm_entry(EVENT_NAME_FIELD, ["dns查询"])],
        )
        self.assertEqual(read_entity_event_name(entity), "dns查询")

    def test_unannotated_entity_returns_none(self):
        self.assertIsNone(read_entity_event_name(make_entity()))

    def test_value_outside_binding_table_returns_none(self):
        entity = make_entity(normalize=[norm_entry(EVENT_NAME_FIELD, ["不存在的分类"])])
        self.assertIsNone(read_entity_event_name(entity))


class EventNormalizeEntryTest(unittest.TestCase):
    def test_event_name_entry_shape(self):
        entry = make_event_name_normalize_entry("网络攻击", sample_count=3)
        self.assertEqual(entry["index"], EVENT_NAME_FIELD)
        self.assertEqual(entry["field"], "event_name")
        self.assertEqual(entry["entity"], "事件")
        self.assertEqual(entry["result"], ["网络攻击", "网络攻击", "网络攻击"])
        self.assertEqual(entry["value"], "网络攻击")
        self.assertEqual(
            entry["mappings"],
            [{"mappingType": "EQUAL", "mappingValue": "网络攻击", "orgValue": "网络攻击"}],
        )
        self.assertFalse(entry["core"])

    def test_event_level_entry_uses_code_value(self):
        entry = make_event_level_normalize_entry("提醒", sample_count=2)
        self.assertEqual(entry["index"], EVENT_LEVEL_FIELD)
        self.assertEqual(entry["field"], "event_level")
        self.assertEqual(entry["value"], "1")
        self.assertEqual(entry["result"], ["提醒", "提醒"])
        self.assertEqual(
            entry["mappings"],
            [{"mappingType": "EQUAL", "mappingValue": "1", "orgValue": "提醒"}],
        )

    def test_info_level_uses_code_zero(self):
        entry = make_event_level_normalize_entry("信息")
        self.assertEqual(entry["value"], "0")


def _sub_rule(name, normalize=None, filters=None):
    return {
        "name": name,
        "parser": {"name": "json", "filter": filters},
        "normalize": normalize if normalize is not None else [],
        "sample": "",
    }


class ApplyEventFieldsTest(unittest.TestCase):
    def test_threat_event_writes_name_and_level(self):
        rules = [
            _sub_rule(
                "登录_json_子规则",
                normalize=[{"index": "user", "result": ["a", "b", "c"]}],
            )
        ]
        updated = apply_event_fields_to_sub_rules(
            rules, {"登录_json_子规则": "网络攻击"}
        )
        rule = updated[0]
        filters = rule["parser"]["filter"]
        self.assertEqual(len(filters), 1)
        self.assertEqual(filters[0]["name"], "addFields")
        self.assertEqual(filters[0]["id"], "")
        self.assertEqual(
            filters[0]["fields"],
            {EVENT_NAME_FIELD: "网络攻击", EVENT_LEVEL_FIELD: "提醒"},
        )
        entries = rule["normalize"]
        self.assertEqual(len(entries), 3)
        self.assertEqual(entries[1]["index"], EVENT_NAME_FIELD)
        self.assertEqual(entries[1]["result"], ["网络攻击", "网络攻击", "网络攻击"])
        self.assertEqual(entries[2]["index"], EVENT_LEVEL_FIELD)
        self.assertEqual(entries[2]["value"], "1")

    def test_non_threat_event_binds_info_level(self):
        rules = [_sub_rule("op_json_子规则")]
        updated = apply_event_fields_to_sub_rules(rules, {"op_json_子规则": "进程操作"})
        fields = updated[0]["parser"]["filter"][0]["fields"]
        self.assertEqual(fields[EVENT_LEVEL_FIELD], "信息")
        self.assertEqual(updated[0]["normalize"][1]["value"], "0")

    def test_unjudged_and_invalid_rules_unchanged(self):
        rules = [
            _sub_rule("a_子规则", normalize=[{"index": "user", "result": ["a"]}]),
            _sub_rule("b_子规则"),
        ]
        updated = apply_event_fields_to_sub_rules(
            rules, {"b_子规则": "不存在的分类", "c_子规则": "登录事件"}
        )
        self.assertEqual(updated[0]["normalize"], [{"index": "user", "result": ["a"]}])
        self.assertEqual(updated[1]["normalize"], [])
        self.assertIsNone(updated[1]["parser"]["filter"])

    def test_original_input_not_mutated(self):
        rules = [_sub_rule("a_子规则")]
        apply_event_fields_to_sub_rules(rules, {"a_子规则": "登录事件"})
        self.assertEqual(rules[0]["normalize"], [])
        self.assertIsNone(rules[0]["parser"]["filter"])

    def test_sample_count_falls_back_to_one(self):
        rules = [_sub_rule("a_子规则", normalize=[{"index": "user", "result": []}])]
        updated = apply_event_fields_to_sub_rules(rules, {"a_子规则": "登录事件"})
        self.assertEqual(updated[0]["normalize"][1]["result"], ["登录事件"])


if __name__ == "__main__":
    unittest.main()
