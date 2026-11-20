"""candidate_retrieval 单元测试：词法打分候选检索（Top-K 附元数据）。

接缝：_shared.candidate_retrieval 的公开 API——Candidate /
CandidateRetriever（retrieve）/ retrieve_candidates。召回断言用技能 assets/
真实资产（625 条目录），边界断言用合成目录（StandardFieldCatalog
公开构造）。
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
from _shared.candidate_retrieval import (  # noqa: E402
    Candidate,
    CandidateRetriever,
    retrieve_candidates,
)


def _field(name, field_name, data_type="字符", description="", enum_values="", objects=""):
    return standard_catalog.StandardField(
        system_property_name=name,
        category="基础属性",
        field_name=field_name,
        data_type=data_type,
        description=description,
        enum_values=enum_values,
        objects=objects,
    )


def _catalog(fields, synonyms=None, tag_rules=None):
    return standard_catalog.StandardFieldCatalog(
        fields, synonyms or {}, tag_rules or {}
    )


class ExactLayerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog = standard_catalog.load_catalog()

    def _names(self, field_name, top_k=10):
        return [c.name for c in retrieve_candidates(field_name, self.catalog, top_k)]

    def test_exact_hit_by_normalized_name(self):
        names = self._names("src_address")
        self.assertEqual(names[0], "源地址")
        first = retrieve_candidates("src_address", self.catalog)[0]
        self.assertEqual(first.score, 1.0)
        self.assertEqual(first.field_name, "src_address")
        self.assertEqual(first.by_stripped, "")

    def test_exact_hit_by_compact_name(self):
        self.assertEqual(self._names("srcaddress")[0], "源地址")

    def test_exact_hit_by_system_name(self):
        self.assertEqual(self._names("源地址")[0], "源地址")

    def test_exact_hit_by_zh_alias(self):
        # 「结果」是 synonyms 键 result 的 zh 别名，注册指向「事件结果」行
        self.assertEqual(self._names("结果")[0], "事件结果")

    def test_blacklist_never_in_candidates(self):
        for query in ("事件名称", "event_name", "event_level", "log_type", "threat_type"):
            with self.subTest(query=query):
                names = self._names(query)
                self.assertNotIn("事件名称", names)
                self.assertNotIn("事件级别", names)
                self.assertNotIn("日志类型", names)
                self.assertNotIn("威胁类型", names)


class LexicalLayerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog = standard_catalog.load_catalog()

    def test_english_query_recalls_by_synonym_bridge(self):
        # 方案 A 核心命题：src_ip 经同义词表（src→source + zh 源/源地址）召回「源地址」
        names = [c.name for c in retrieve_candidates("src_ip", self.catalog)]
        self.assertIn("源地址", names)

    def test_english_query_recalls_destination(self):
        names = [c.name for c in retrieve_candidates("dst_ip", self.catalog)]
        self.assertIn("目的地址", names)

    def test_zh_query_recalls_by_char_similarity(self):
        names = [c.name for c in retrieve_candidates("源IP", self.catalog)]
        self.assertIn("源地址", names)

    def test_top_k_truncation(self):
        self.assertLessEqual(len(retrieve_candidates("user", self.catalog)), 10)
        self.assertLessEqual(len(retrieve_candidates("user", self.catalog, top_k=3)), 3)

    def test_candidate_metadata_enriched(self):
        candidates = retrieve_candidates("http_method", self.catalog)
        first = candidates[0]
        self.assertEqual(first.name, "HTTP请求方法")
        self.assertEqual(first.data_type, "枚举")
        self.assertEqual(first.object, "http协议")
        self.assertIn("GET", first.enum_whitelist)

    def test_gibberish_query_never_exact_hits(self):
        # 阈值下丢弃的行为由合成目录测试钉死；真实目录只保证乱串永不精确命中
        for candidate in retrieve_candidates("zzzqqq123xyz", self.catalog):
            self.assertLess(candidate.score, 1.0)


class SyntheticCatalogTest(unittest.TestCase):
    def test_stripped_prefix_exact_hit(self):
        catalog = _catalog([_field("严重级别", "severity")])
        candidates = retrieve_candidates("data.severity", catalog)
        self.assertEqual(candidates[0].name, "严重级别")
        self.assertEqual(candidates[0].score, 1.0)
        self.assertEqual(candidates[0].by_stripped, "severity")

    def test_exact_tier_beats_equal_score_lexical(self):
        # src_ip 精确命中 A（tier 0）；ip_src 词法 jaccard 满分（tier 1）→ A 置顶
        catalog = _catalog(
            [_field("源地址", "src_ip"), _field("对端地址", "ip_src")]
        )
        candidates = retrieve_candidates("src_ip", catalog)
        self.assertEqual(candidates[0].name, "源地址")
        self.assertEqual(candidates[0].score, 1.0)
        self.assertEqual(candidates[1].name, "对端地址")

    def test_two_level_stripped_prefix(self):
        catalog = _catalog([_field("源地址", "sip")])
        candidates = retrieve_candidates("original_log_1.origin.sip", catalog)
        self.assertEqual(candidates[0].name, "源地址")
        self.assertEqual(candidates[0].by_stripped, "sip")

    def test_dedupe_exact_overrides_lexical(self):
        # 同一记录既被精确层命中又有词法分：只出现一次且取 1.0
        catalog = _catalog(
            [_field("源地址", "src_ip"), _field("干扰项", "src_ip_backup")]
        )
        candidates = retrieve_candidates("src_ip", catalog)
        names = [c.name for c in candidates]
        self.assertEqual(names.count("源地址"), 1)
        self.assertEqual(candidates[0].score, 1.0)

    def test_below_threshold_dropped(self):
        catalog = _catalog([_field("无关字段", "unrelated_thing")])
        self.assertEqual(retrieve_candidates("zzz", catalog), [])

    def test_empty_query_returns_empty(self):
        catalog = _catalog([_field("源地址", "src_ip")])
        self.assertEqual(retrieve_candidates("", catalog), [])

    def test_no_blacklist_hit_even_in_synthetic(self):
        catalog = _catalog(
            [_field("事件名称", "event_name"), _field("源地址", "src_ip")]
        )
        names = [c.name for c in retrieve_candidates("event_name", catalog)]
        self.assertNotIn("事件名称", names)

    def test_description_keywords_are_only_signal(self):
        # lessee 只出现在描述里；字段名与查询零字符重叠，无描述则该查询零命中
        catalog = _catalog(
            [_field("租户名称", "org_unit", description="lessee identifier 租户标识")]
        )
        candidates = retrieve_candidates("lessee_id", catalog)
        self.assertEqual([c.name for c in candidates], ["租户名称"])
        without_desc = _catalog([_field("租户名称", "org_unit")])
        self.assertEqual(retrieve_candidates("lessee_id", without_desc), [])


class RetrieverBatchTest(unittest.TestCase):
    def test_retriever_reuses_catalog_and_matches_convenience(self):
        catalog = standard_catalog.load_catalog()
        retriever = CandidateRetriever(catalog)
        via_retriever = retriever.retrieve("dst_ip")
        via_function = retrieve_candidates("dst_ip", catalog)
        self.assertEqual(
            [c.name for c in via_retriever], [c.name for c in via_function]
        )

    def test_candidate_as_dict_shape(self):
        catalog = standard_catalog.load_catalog()
        first = retrieve_candidates("http_method", catalog)[0]
        payload = first.as_dict()
        self.assertEqual(
            sorted(payload),
            sorted(
                [
                    "name",
                    "score",
                    "field_name",
                    "by_stripped",
                    "object",
                    "type",
                    "description",
                    "enum_whitelist",
                ]
            ),
        )
        self.assertEqual(payload["name"], "HTTP请求方法")
        self.assertIsInstance(payload["enum_whitelist"], list)


if __name__ == "__main__":
    unittest.main()
