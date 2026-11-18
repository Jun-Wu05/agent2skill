"""decode_fields 单元与端到端测试。

覆盖 decode_fields 核心行为（运行时 OGNL 原地覆盖）、解码守卫链与
文件契约端到端。
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
for path in (str(ROOT), str(ROOT / "tests"), str(SKILLS), str(SKILLS / "field-adjust" / "scripts")):
    if path not in sys.path:
        sys.path.insert(0, path)

import decode_fields  # noqa: E402
from _shared.event_binding import EVENT_LEVEL_FIELD, EVENT_NAME_FIELD  # noqa: E402
from field_adjust_helpers import make_entity, norm_entry  # noqa: E402


def decode_ognl(field_name: str) -> str:
    """与实现共享的 OGNL 模板（独立字面量，防实现漂移时测试静默通过）。"""
    return f"<%@com.hansight.dataviewer.utils.Base64@Base64Decode({field_name})%>"


class DecodeFieldCoreTest(unittest.TestCase):
    """decode_fields() 纯函数核心行为：OGNL 写入 / 原地覆盖 / 幂等 / 自适应跳过。"""

    def setUp(self):
        self.data = [
            make_entity(
                "rule_a",
                normalize=[
                    norm_entry("req_header", ["aGVsbG8="]),
                    norm_entry("req_body", ["d29ybGQ="]),
                ],
            ),
            make_entity(
                "rule_b",
                normalize=[
                    norm_entry("req_header", ["eHg="]),
                ],
            ),
            make_entity("rule_empty"),
        ]

    def _ok(self, result):
        self.assertEqual(result["status"], "success")
        return result["data"]

    def test_decode_writes_ognl_into_add_fields_filter(self):
        updated = self._ok(decode_fields.decode_fields(self.data, ["req_header", "req_body"]))
        decode_filter = updated[0]["parser"]["filter"][-1]
        self.assertEqual(decode_filter["name"], "addFields")
        self.assertEqual(decode_filter["id"], "")
        self.assertEqual(
            decode_filter["fields"],
            {
                "req_header": decode_ognl("req_header"),
                "req_body": decode_ognl("req_body"),
            },
        )

    def test_in_place_overwrite_no_normalize_write(self):
        updated = self._ok(decode_fields.decode_fields(self.data, ["req_header", "req_body"]))
        rule_a = updated[0]
        # 不双写 normalize：条目数与顺序不变，无新增字段
        self.assertEqual(
            [e["index"] for e in rule_a["normalize"]], ["req_header", "req_body"]
        )

    def test_idempotent_merge_into_existing_decode_filter(self):
        data = [
            make_entity(
                "rule_a",
                normalize=[norm_entry("req_header", [""]), norm_entry("req_body", [""])],
                filters=[
                    {
                        "fields": {"req_header": decode_ognl("req_header")},
                        "name": "addFields",
                        "id": "",
                    }
                ],
            )
        ]
        updated = self._ok(decode_fields.decode_fields(data, ["req_header", "req_body"]))
        filters = updated[0]["parser"]["filter"]
        # 合并进已有解码过滤器，不重复追加
        self.assertEqual(len(filters), 1)
        self.assertEqual(
            filters[0]["fields"],
            {
                "req_header": decode_ognl("req_header"),
                "req_body": decode_ognl("req_body"),
            },
        )

    def test_mixed_add_fields_filter_not_recognized_new_filter_created(self):
        data = [
            make_entity(
                "rule_a",
                normalize=[norm_entry("req_header", [""]), norm_entry("req_body", [""])],
                filters=[
                    {
                        # 固定值 + 解码 OGNL 混合：不是解码过滤器
                        "fields": {"备注": "固定值", "req_header": decode_ognl("req_header")},
                        "name": "addFields",
                        "id": "",
                    }
                ],
            )
        ]
        updated = self._ok(decode_fields.decode_fields(data, ["req_body"]))
        filters = updated[0]["parser"]["filter"]
        self.assertEqual(len(filters), 2)
        self.assertEqual(filters[-1]["fields"], {"req_body": decode_ognl("req_body")})
        # 原混合过滤器原样保留
        self.assertIn("备注", filters[0]["fields"])

    def test_missing_field_skips_entity_and_reports(self):
        result = decode_fields.decode_fields(self.data, ["req_header", "req_body"])
        self.assertEqual(result["status"], "success")
        self.assertIn("成功为 1 个 entity", result["message"])
        self.assertIn("rule_b（缺 req_body）", result["message"])
        # 缺字段的 rule_b 原样保留，未写入解码过滤器
        self.assertEqual(result["data"][1]["parser"]["filter"], None)

    def test_all_missing_reports_field_not_found_with_union_preview(self):
        result = decode_fields.decode_fields(self.data, ["req_header", "不存在字段"])
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["code"], "field_not_found")
        # 只点名真正缺失的字段（req_header 存在，不背锅）
        self.assertIn("不存在字段", result["message"])
        self.assertNotIn("req_header 不存在", result["message"])
        # 附全部子规则字段并集预览，帮助定位名字错误
        self.assertIn("并集", result["message"])
        self.assertIn("req_header", result["message"])
        self.assertIn("req_body", result["message"])

    def test_target_scope_and_passthrough(self):
        result = decode_fields.decode_fields(self.data, ["req_header"], ["rule_a"])
        self.assertIn("目标 1 个", result["message"])
        updated = result["data"]
        self.assertEqual(updated[0]["parser"]["filter"][-1]["name"], "addFields")
        # 名单外 entity 原样透传
        self.assertEqual(updated[1]["parser"]["filter"], None)

    def test_entity_without_normalize_skipped_and_counted(self):
        result = decode_fields.decode_fields(self.data, ["req_header"])
        self.assertIn("跳过 1 个无 normalize 的 entity", result["message"])
        self.assertEqual(result["data"][2]["normalize"], [])

    def test_input_not_mutated(self):
        snapshot = json.dumps(self.data, ensure_ascii=False)
        decode_fields.decode_fields(self.data, ["req_header", "req_body"])
        self.assertEqual(json.dumps(self.data, ensure_ascii=False), snapshot)

    def test_null_filter_initialized(self):
        data = [make_entity("rule_a", normalize=[norm_entry("req_header", [""])])]
        updated = self._ok(decode_fields.decode_fields(data, ["req_header"]))
        filters = updated[0]["parser"]["filter"]
        self.assertEqual(len(filters), 1)
        self.assertEqual(filters[0]["name"], "addFields")

    def test_empty_data_error(self):
        result = decode_fields.decode_fields([], ["req_header"])
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["code"], "invalid_input")

    def test_empty_fields_error(self):
        result = decode_fields.decode_fields(self.data, [])
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["code"], "invalid_input")


if __name__ == "__main__":
    unittest.main()
