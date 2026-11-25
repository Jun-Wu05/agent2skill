"""mapping_apply 单元测试：映射判定的 sanitize、占用裁决与写回。

接缝：_shared.mapping_apply 的公开 API——sanitize_decisions /
collect_existing_occupants / resolve_occupancy_conflicts /
apply_decisions_to_subrules / apply_decisions_to_config。目录相关断言用
真实资产，边界用合成目录。
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for path in (str(ROOT), str(ROOT / "skills" / "parser-skills")):
    if path not in sys.path:
        sys.path.insert(0, path)

from _shared import standard_catalog  # noqa: E402
from _shared.candidate_retrieval import CandidateRetriever  # noqa: E402
from _shared.mapping_apply import (  # noqa: E402
    apply_decisions_to_config,
    apply_decisions_to_subrules,
    collect_existing_occupants,
    resolve_occupancy_conflicts,
    sanitize_decisions,
)


def _entry(index, field=None, result=None):
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


class SanitizeDecisionsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog = standard_catalog.load_catalog()
        cls.retriever = CandidateRetriever(cls.catalog)

    def _sanitize(self, raw, expected):
        return sanitize_decisions(raw, expected, self.catalog, self.retriever)

    def test_valid_decision_resolves(self):
        expected = ["dst_ip"]
        decisions, report = self._sanitize(
            [{"field": "dst_ip", "standard": "目的地址"}], expected
        )
        self.assertEqual(decisions["dst_ip"].system_property_name, "目的地址")
        self.assertEqual(report["trimmed"], [])
        self.assertEqual(report["backfilled"], [])
        self.assertEqual(report["degraded"], [])

    def test_unmatched_literal_stays_unmatched(self):
        decisions, report = self._sanitize(
            [{"field": "dst_ip", "standard": "未匹配"}], ["dst_ip"]
        )
        self.assertIsNone(decisions["dst_ip"])
        self.assertEqual(report["degraded"], [])

    def test_unknown_field_trimmed(self):
        decisions, report = self._sanitize(
            [{"field": "臆造字段", "standard": "目的地址"}], ["dst_ip"]
        )
        self.assertNotIn("臆造字段", decisions)
        self.assertEqual(report["trimmed"], ["臆造字段"])

    def test_missing_field_backfilled_unmatched(self):
        decisions, report = self._sanitize([], ["dst_ip", "src_ip"])
        self.assertIsNone(decisions["dst_ip"])
        self.assertIsNone(decisions["src_ip"])
        self.assertEqual(report["backfilled"], ["dst_ip", "src_ip"])

    def test_blacklist_standard_degrades(self):
        decisions, report = self._sanitize(
            [{"field": "dst_ip", "standard": "事件名称"}], ["dst_ip"]
        )
        self.assertIsNone(decisions["dst_ip"])
        self.assertEqual(
            report["degraded"],
            [{"field": "dst_ip", "standard": "事件名称", "reason": "映射目标黑名单"}],
        )

    def test_out_of_catalog_standard_degrades(self):
        decisions, report = self._sanitize(
            [{"field": "dst_ip", "standard": "自造标准字段"}], ["dst_ip"]
        )
        self.assertIsNone(decisions["dst_ip"])
        self.assertEqual(
            report["degraded"],
            [{"field": "dst_ip", "standard": "自造标准字段", "reason": "目录外名称"}],
        )

    def test_out_of_candidates_standard_degrades(self):
        # 目录内合法但不在该字段候选 Top-K 内 → 降级（占用裁决证据链完整）
        decisions, report = self._sanitize(
            [{"field": "dst_ip", "standard": "源进程MD5"}], ["dst_ip"]
        )
        self.assertIsNone(decisions["dst_ip"])
        self.assertEqual(
            report["degraded"],
            [{"field": "dst_ip", "standard": "源进程MD5", "reason": "候选外"}],
        )

    def test_duplicate_field_first_wins(self):
        decisions, report = self._sanitize(
            [
                {"field": "dst_ip", "standard": "目的地址"},
                {"field": "dst_ip", "standard": "源地址"},
            ],
            ["dst_ip"],
        )
        self.assertEqual(decisions["dst_ip"].system_property_name, "目的地址")
        self.assertEqual(report["duplicates"], ["dst_ip"])

    def test_empty_standard_treated_unmatched(self):
        decisions, _ = self._sanitize([{"field": "dst_ip", "standard": ""}], ["dst_ip"])
        self.assertIsNone(decisions["dst_ip"])


class OccupancyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog = standard_catalog.load_catalog()
        cls.retriever = CandidateRetriever(cls.catalog)

    def _decision(self, standard_name):
        record = self.catalog.lookup(standard_name)
        assert record is not None, standard_name
        return record

    def test_existing_occupant_always_wins(self):
        decisions = {"new_field": self._decision("目的地址")}
        decisions, conflicts = resolve_occupancy_conflicts(
            decisions, ["new_field"], {"目的地址": "old_field"}, self.retriever
        )
        self.assertIsNone(decisions["new_field"])
        self.assertEqual(len(conflicts), 1)
        self.assertEqual(conflicts[0]["winner"], "old_field")
        self.assertEqual(conflicts[0]["winner_source"], "existing")
        self.assertEqual(conflicts[0]["losers"], ["new_field"])

    def test_same_original_field_not_a_conflict(self):
        decisions = {"src_ip": self._decision("源地址")}
        decisions, conflicts = resolve_occupancy_conflicts(
            decisions, ["src_ip"], {"源地址": "src_ip"}, self.retriever
        )
        self.assertEqual(decisions["src_ip"].system_property_name, "源地址")
        self.assertEqual(conflicts, [])

    def test_score_beats_zero_score_then_row_order(self):
        # dst_ip 对目的地址有词法分；client_ip 零分 → dst_ip 胜
        decisions = {
            "client_ip": self._decision("目的地址"),
            "dst_ip": self._decision("目的地址"),
        }
        decisions, conflicts = resolve_occupancy_conflicts(
            decisions, ["client_ip", "dst_ip"], {}, self.retriever
        )
        self.assertEqual(decisions["dst_ip"].system_property_name, "目的地址")
        self.assertIsNone(decisions["client_ip"])
        self.assertEqual(conflicts[0]["winner"], "dst_ip")
        self.assertEqual(conflicts[0]["winner_source"], "candidate")

    def test_exact_layer_beats_full_jaccard_lexical(self):
        # 回归：词法层 jaccard 满分的候选分数同为 1.0，精确层标志（exact）
        # 必须压过它——按分数反推会把两者都判成精确层、退化成行序裁决
        catalog = standard_catalog.StandardFieldCatalog(
            [
                standard_catalog.StandardField(
                    system_property_name="源地址",
                    category="基础属性",
                    field_name="src_address",
                    data_type="IP",
                    description="",
                    enum_values="",
                    objects="流量",
                )
            ],
            {},
            {},
        )
        retriever = CandidateRetriever(catalog)
        decisions = {
            "address_src": catalog.lookup("源地址"),  # 词法 jaccard=1.0，非精确层
            "src_address": catalog.lookup("源地址"),  # 精确层命中
        }
        decisions, conflicts = resolve_occupancy_conflicts(
            decisions, ["address_src", "src_address"], {}, retriever
        )
        self.assertEqual(conflicts[0]["winner"], "src_address")
        self.assertEqual(conflicts[0]["losers"], ["address_src"])
        self.assertEqual(decisions["src_address"].system_property_name, "源地址")
        self.assertIsNone(decisions["address_src"])

    def test_row_order_breaks_score_tie(self):
        # 两个都非精确的弱命中同分 → 原行序（expected 顺序）先者胜
        decisions = {
            "field_a": self._decision("源地址"),
            "field_b": self._decision("源地址"),
        }
        decisions, conflicts = resolve_occupancy_conflicts(
            decisions, ["field_a", "field_b"], {}, self.retriever
        )
        self.assertEqual(conflicts[0]["winner"], "field_a")

    def test_no_conflict_untouched(self):
        decisions = {
            "dst_ip": self._decision("目的地址"),
            "src_ip": self._decision("源地址"),
        }
        decisions, conflicts = resolve_occupancy_conflicts(
            decisions, ["dst_ip", "src_ip"], {}, self.retriever
        )
        self.assertEqual(conflicts, [])
        self.assertEqual(decisions["dst_ip"].system_property_name, "目的地址")


class ExistingOccupantsTest(unittest.TestCase):
    def test_collects_non_empty_field_entries_first_wins(self):
        entities = [
            {
                "name": "a",
                "normalize": [
                    _entry("src_ip", field="源地址"),
                    _entry("dst_ip"),
                ],
            },
            {
                "name": "b",
                "normalize": [
                    _entry("other", field="源地址"),
                    _entry("user", field="源用户名"),
                ],
            },
        ]
        occupants = collect_existing_occupants(entities)
        self.assertEqual(occupants, {"源地址": "src_ip", "源用户名": "user"})

    def test_catalog_normalizes_alias_keys(self):
        # 占用键经目录归一：英文别名 host_name → 规范名 主机名称；
        # 目录外的外部映射名保留原文
        entities = [
            {
                "name": "a",
                "normalize": [
                    _entry("computerName", field="host_name"),
                    _entry("src_ip", field="外部映射名"),
                ],
            },
        ]
        occupants = collect_existing_occupants(entities, self.catalog)
        self.assertEqual(occupants, {"主机名称": "computerName", "外部映射名": "src_ip"})

    @classmethod
    def setUpClass(cls):
        cls.catalog = standard_catalog.load_catalog()


class ApplyToSubrulesTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog = standard_catalog.load_catalog()

    def test_write_and_clear(self):
        record = self.catalog.lookup("目的地址")
        rules = [
            {
                "name": "a_子规则",
                "parser": {"name": "json", "filter": []},
                "normalize": [
                    _entry("dst_ip"),
                    _entry("user"),
                    _entry("日志类型", field="log_type"),
                    _entry("original_log", field="original_log"),
                ],
            }
        ]
        decisions = {"dst_ip": record, "user": None}
        updated = apply_decisions_to_subrules(rules, decisions, self.catalog)
        dst = updated[0]["normalize"][0]
        self.assertEqual(dst["field"], "dst_address")
        self.assertEqual(dst["entity"], "流量,登录".split(",")[0])  # 目录首个对象
        self.assertTrue(dst["sim"])
        self.assertFalse(dst["core"])
        user = updated[0]["normalize"][1]
        self.assertIsNone(user["field"])
        self.assertIsNone(user["entity"])
        self.assertIsNone(user["sim"])
        self.assertIsNone(user["core"])
        # 排除索引不动
        self.assertEqual(updated[0]["normalize"][2]["field"], "log_type")
        self.assertEqual(updated[0]["normalize"][3]["field"], "original_log")
        # 原输入不被修改
        self.assertIsNone(rules[0]["normalize"][0]["field"])

    def test_unknown_index_untouched(self):
        rules = [{"name": "a", "normalize": [_entry("mystery")]}]
        updated = apply_decisions_to_subrules(rules, {}, self.catalog)
        self.assertEqual(updated[0]["normalize"][0]["field"], None)


class ApplyToConfigTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog = standard_catalog.load_catalog()

    def test_writes_only_empty_field_entries(self):
        record = self.catalog.lookup("目的地址")
        config = [
            {
                "name": "a",
                "normalize": [
                    _entry("dst_ip"),
                    _entry("src_ip", field="外部映射名"),
                ],
            }
        ]
        decisions = {"dst_ip": record, "src_ip": record}
        updated = apply_decisions_to_config(config, decisions, self.catalog)
        self.assertEqual(updated[0]["normalize"][0]["field"], "dst_address")
        # 既有映射保留不动
        self.assertEqual(updated[0]["normalize"][1]["field"], "外部映射名")
        self.assertIsNone(config[0]["normalize"][0]["field"])

    def test_unmatched_leaves_entry_as_is(self):
        config = [{"name": "a", "normalize": [_entry("dst_ip")]}]
        updated = apply_decisions_to_config(config, {"dst_ip": None}, self.catalog)
        self.assertIsNone(updated[0]["normalize"][0]["field"])


if __name__ == "__main__":
    unittest.main()
