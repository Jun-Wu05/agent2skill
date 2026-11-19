"""log_extract 单元测试：数据族确定性提取与聚合。

接缝：extract_json_value / strip_header / KvValueExtractor /
aggregate_by_field / kv_key_line_coverage / derive_separator_candidates。
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

from _shared import log_extract  # noqa: E402


class ExtractJsonValueTest(unittest.TestCase):
    def test_top_level_key(self):
        self.assertEqual(
            log_extract.extract_json_value('{"type": "attack"}', "type"), "attack"
        )

    def test_nested_dotted_path(self):
        line = '{"event": {"action": "login"}, "user": "u1"}'
        self.assertEqual(log_extract.extract_json_value(line, "event.action"), "login")

    def test_syslog_header_plus_json(self):
        line = '<189>Jan 01 00:00:00 host app[1]: {"type": "attack"}'
        self.assertEqual(log_extract.extract_json_value(line, "type"), "attack")

    def test_missing_key_returns_none(self):
        self.assertIsNone(log_extract.extract_json_value('{"a": 1}', "b"))

    def test_bad_json_returns_none(self):
        self.assertIsNone(log_extract.extract_json_value("not json at all", "a"))

    def test_non_dict_path_segment_returns_none(self):
        self.assertIsNone(log_extract.extract_json_value('{"a": 1}', "a.b"))


class StripHeaderTest(unittest.TestCase):
    def test_json_prefers_braces_over_marker(self):
        line = 'Jan 01 host app: {"type": 1}'
        self.assertEqual(
            log_extract.strip_header(line, "app: ", is_json=True), '{"type": 1}'
        )

    def test_json_no_braces_falls_back_to_marker(self):
        line = "Jan 01 host app: type=attack"
        self.assertEqual(
            log_extract.strip_header(line, "app: ", is_json=True), "type=attack"
        )

    def test_kv_splits_at_first_marker(self):
        line = "Jan 01 host app: type=attack"
        self.assertEqual(
            log_extract.strip_header(line, "app: ", is_json=False), "type=attack"
        )

    def test_marker_missing_returns_original(self):
        line = "type=attack"
        self.assertEqual(log_extract.strip_header(line, "app: ", is_json=False), line)

    def test_empty_marker_returns_original(self):
        line = "Jan 01 host app: type=attack"
        self.assertEqual(log_extract.strip_header(line, "", is_json=False), line)


class KvValueExtractorTest(unittest.TestCase):
    def test_space_equals(self):
        extractor = log_extract.KvValueExtractor(" ", "=")
        line = "type=attack src=1.1.1.1"
        self.assertEqual(extractor.extract_value(line, "type"), "attack")
        self.assertEqual(extractor.extract_value(line, "src"), "1.1.1.1")

    def test_quoted_value_with_spaces(self):
        extractor = log_extract.KvValueExtractor(" ", "=")
        line = 'msg="failed login attempt" type=block'
        self.assertEqual(extractor.extract_value(line, "msg"), "failed login attempt")
        self.assertEqual(extractor.extract_value(line, "type"), "block")

    def test_pipe_field_colon_kv(self):
        extractor = log_extract.KvValueExtractor("||", ":")
        line = "type:attack||src:1.1.1.1||act:block"
        self.assertEqual(extractor.extract_value(line, "type"), "attack")
        self.assertEqual(extractor.extract_value(line, "act"), "block")

    def test_tab_normalized_to_space_mode(self):
        extractor = log_extract.KvValueExtractor("\t", "=")
        line = "type=attack\tsrc=1.1.1.1"
        self.assertEqual(extractor.extract_value(line, "type"), "attack")

    def test_missing_key_returns_none(self):
        extractor = log_extract.KvValueExtractor(" ", "=")
        self.assertIsNone(extractor.extract_value("type=attack", "level"))

    def test_key_not_swallowing_field_delimiter(self):
        # 2026-07-28 修复回归：单字符分隔符不得被键名贪婪吞掉
        extractor = log_extract.KvValueExtractor("|", "=")
        line = "key1=val1|key2=val2"
        self.assertEqual(extractor.extract_value(line, "key1"), "val1")
        self.assertEqual(extractor.extract_value(line, "key2"), "val2")

    def test_zero_width_chars_cleaned_from_value(self):
        extractor = log_extract.KvValueExtractor(" ", "=")
        line = "type=att\u200back"
        self.assertEqual(extractor.extract_value(line, "type"), "attack")


class AggregateByFieldTest(unittest.TestCase):
    def _extractor(self):
        return log_extract.KvValueExtractor(" ", "=")

    def test_counts_and_values(self):
        logs = "type=a\nother line\ntype=a\ntype=b\nanother"
        result = log_extract.aggregate_by_field(
            logs, "type", self._extractor().extract_value
        )
        self.assertEqual(result["total_lines"], 5)
        self.assertEqual(result["matched_lines"], 3)
        self.assertEqual(result["unmatched_lines"], 2)
        self.assertEqual(result["value_count"], 2)
        self.assertEqual(result["values"]["a"]["count"], 2)
        self.assertEqual(result["values"]["b"]["count"], 1)
        self.assertEqual(result["top_values"], ["a", "b"])

    def test_unmatched_samples_kept(self):
        logs = "type=a\nnope\ntype=a"
        result = log_extract.aggregate_by_field(
            logs, "type", self._extractor().extract_value
        )
        self.assertEqual(result["unmatched_samples"], ["nope"])

    def test_sample_limit_three(self):
        logs = "\n".join([f"type=a src={i}" for i in range(5)])
        result = log_extract.aggregate_by_field(
            logs, "type", self._extractor().extract_value
        )
        self.assertEqual(len(result["values"]["a"]["samples"]), 3)

    def test_identical_lines_deduped_in_samples(self):
        # 参照行为：相同样本行只保留一份
        logs = "\n".join(["type=a"] * 5)
        result = log_extract.aggregate_by_field(
            logs, "type", self._extractor().extract_value
        )
        self.assertEqual(result["values"]["a"]["samples"], ["type=a"])

    def test_sample_truncated_to_300_chars(self):
        logs = f"type={'x' * 500}"
        result = log_extract.aggregate_by_field(
            logs, "type", self._extractor().extract_value
        )
        sample = result["values"]["x" * 500]["samples"][0]
        self.assertLessEqual(len(sample), 300)

    def test_blank_lines_skipped(self):
        logs = "type=a\n\n   \ntype=a"
        result = log_extract.aggregate_by_field(
            logs, "type", self._extractor().extract_value
        )
        self.assertEqual(result["total_lines"], 2)


class ExtractKvKeysTest(unittest.TestCase):
    def test_basic_keys_deduped_in_order(self):
        keys = log_extract.extract_kv_keys("type=a src=1.1.1.1 type=a port=22", " ", "=")
        self.assertEqual(keys, ["type", "src", "port"])

    def test_quoted_value_not_split(self):
        keys = log_extract.extract_kv_keys('msg="failed login" type=block', " ", "=")
        self.assertEqual(keys, ["msg", "type"])

    def test_bracket_content_not_split(self):
        keys = log_extract.extract_kv_keys("tree=[{a=1 b=2}] src=1.1.1.1", " ", "=")
        self.assertEqual(keys, ["tree", "src"])

    def test_custom_delimiters(self):
        keys = log_extract.extract_kv_keys("type:attack||src:1.1.1.1||port:22", "||", ":")
        self.assertEqual(keys, ["type", "src", "port"])

    def test_segment_without_tab_skipped(self):
        keys = log_extract.extract_kv_keys("bare_word type=a", " ", "=")
        self.assertEqual(keys, ["type"])


class CoverageProbeTest(unittest.TestCase):
    def test_kv_key_line_coverage(self):
        logs = "\n".join(["type=a", "type=b", "type=c", "type=d", "other"])
        coverage = log_extract.kv_key_line_coverage(logs, "type", " ", "=")
        self.assertAlmostEqual(coverage, 0.8)

    def test_derive_separator_candidates(self):
        logs = "\n".join(["a:1||b:2||c:3"] * 4)
        candidates = log_extract.derive_separator_candidates(logs)
        self.assertIn("|", candidates)


if __name__ == "__main__":
    unittest.main()
