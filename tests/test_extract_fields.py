"""extract_fields 单元与端到端测试。

覆盖 extract_field 核心行为（customFunction + normalize 双写、全匹配样本
校验、缺省命名链、幂等覆盖、per-entity 自适应）、提取守卫链与文件契约
端到端。切片1：纯函数核心行为。
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILLS = ROOT / "skills" / "parser-skills"
for path in (str(ROOT), str(ROOT / "tests"), str(SKILLS), str(SKILLS / "field-adjust" / "scripts")):
    if path not in sys.path:
        sys.path.insert(0, path)

import extract_fields  # noqa: E402
from _shared.event_binding import EVENT_LEVEL_FIELD, EVENT_NAME_FIELD  # noqa: E402
from field_adjust_helpers import make_entity, norm_entry  # noqa: E402


def regex_ognl() -> str:
    """运行时 OGNL 提取语句（独立字面量，防实现漂移时测试静默通过）。"""
    return '<%@com.hansight.dataviewer.utils.ognl.OgnlUtils@regexExtraction(arg2,"arg3")%>'


def function_item(new_field: str, source_field: str, pattern: str) -> dict:
    """extractRegexField 函数条目的期望形态（独立字面量）。"""
    return {
        "functionName": "extractRegexField",
        "ognl": regex_ognl(),
        "functionViewName": "正则提取",
        "fieldName": "",
        "args": [
            {
                "name": "新增字段",
                "args": "arg1",
                "detail": "新增字段名称",
                "type": "field",
                "value": new_field,
            },
            {
                "name": "被提取字段",
                "args": "arg2",
                "detail": "字符格式字段",
                "type": "args",
                "value": source_field,
            },
            {
                "name": "正则表达式",
                "args": "arg3",
                "detail": "只提取第一个匹配项",
                "type": "args",
                "value": pattern,
            },
        ],
    }


def expected_norm_entry(index: str, result_value: str) -> dict:
    """正则提取新增字段的 normalize 条目期望形态（独立字面量）。"""
    return {
        "mappings": [],
        "field": None,
        "sim": None,
        "result": [result_value] if result_value else [],
        "info": None,
        "entity": None,
        "required": False,
        "core": None,
        "value": None,
        "index": index,
    }


class ExtractFieldCoreTest(unittest.TestCase):
    """extract_field() 纯函数核心行为：双写 / 全匹配校验 / 命名链 / 幂等 / 自适应。"""

    def setUp(self):
        # 「原始日志里的 client」主用例样本：original_log 两个子规则都有，
        # req_header 只有 rule_a 有（验证 per-entity 自适应）
        self.pattern = r'[\S\s]*client="(.*?)"[\S\s]*'
        self.data = [
            make_entity(
                "rule_a",
                normalize=[
                    norm_entry("original_log", ['start client="nexus" end']),
                    norm_entry("req_header", ['client="edge"']),
                ],
            ),
            make_entity(
                "rule_b",
                normalize=[
                    norm_entry("original_log", ['start client="beta" end']),
                ],
            ),
            make_entity("rule_empty"),
        ]

    def _ok(self, result):
        self.assertEqual(result["status"], "success")
        return result["data"]

    def _err(self, result, code):
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["code"], code)
        return result

    # ---- 双写结构 ----

    def test_extract_writes_custom_function_filter(self):
        updated = self._ok(
            extract_fields.extract_field(
                self.data, "newclient", "original_log", self.pattern
            )
        )
        self.assertEqual(
            updated[0]["parser"]["filter"],
            [{
                "custom_name": "extractRegexField",
                "fields": [function_item("newclient", "original_log", self.pattern)],
                "name": "customFunction",
                "id": "",
            }],
        )
        # rule_b 同样写入（original_log 两子规则都有）
        self.assertEqual(
            updated[1]["parser"]["filter"][0]["name"], "customFunction"
        )

    def test_normalize_preview_first_capture_group(self):
        updated = self._ok(
            extract_fields.extract_field(
                self.data, "newclient", "original_log", self.pattern
            )
        )
        # rule_a / rule_b 各追加一条预览条目，取第一个捕获组
        self.assertEqual(
            updated[0]["normalize"][-1], expected_norm_entry("newclient", "nexus")
        )
        self.assertEqual(
            updated[1]["normalize"][-1], expected_norm_entry("newclient", "beta")
        )

    def test_preview_without_capture_group_whole_match(self):
        data = [
            make_entity(
                "rule_a",
                normalize=[norm_entry("code", ["abc123"])],
            )
        ]
        updated = self._ok(
            extract_fields.extract_field(
                data, "plain", "code", r"[a-z]+[0-9]+"
            )
        )
        # 无捕获组：预览值取整条匹配
        self.assertEqual(
            updated[0]["normalize"][-1], expected_norm_entry("plain", "abc123")
        )

    # ---- 样本校验 ----

    def test_partial_match_rejected_whole_error(self):
        # 正则只匹配子串、无法全匹配整条样本 → 整体报错，不静默写入
        result = extract_fields.extract_field(
            self.data, "newclient", "original_log", r'client="(.*?)"'
        )
        self._err(result, "pattern_mismatch")
        self.assertIn("无法全匹配", result["message"])

    def test_no_sample_skips_validation_empty_preview(self):
        data = [
            make_entity(
                "rule_a",
                normalize=[norm_entry("req_header", [])],
            )
        ]
        updated = self._ok(
            extract_fields.extract_field(
                data, "newclient", "req_header", self.pattern
            )
        )
        # 无样本：跳过校验照写，预览值为空
        self.assertEqual(
            updated[0]["normalize"][-1], expected_norm_entry("newclient", "")
        )

    def test_invalid_pattern_rejected(self):
        result = extract_fields.extract_field(
            self.data, "newclient", "original_log", "(["
        )
        self._err(result, "invalid_pattern")
        self.assertIn("不合法", result["message"])

    # ---- per-entity 自适应 ----

    def test_missing_source_per_entity_skip_reported(self):
        # req_header 只有 rule_a 有：rule_b 跳过按名报告，整体仍 success
        result = extract_fields.extract_field(
            self.data, "newclient", "req_header", self.pattern
        )
        updated = self._ok(result)
        self.assertIn("rule_b（缺 req_header）", result["message"])
        # rule_b 原样透传（filter 未动）
        self.assertIsNone(updated[1]["parser"]["filter"])
        self.assertEqual(len(updated[0]["normalize"]), 3)

    def test_all_missing_source_field_not_found_with_union_preview(self):
        result = extract_fields.extract_field(
            self.data, "newclient", "absent_field", self.pattern
        )
        self._err(result, "field_not_found")
        self.assertIn("absent_field 不存在于任何（目标）子规则", result["message"])
        self.assertIn("并集", result["message"])
        self.assertIn("original_log", result["message"])

    def test_empty_normalize_skipped_counted(self):
        result = extract_fields.extract_field(
            self.data, "newclient", "original_log", self.pattern
        )
        self._ok(result)
        self.assertIn("跳过 1 个无 normalize 的 entity", result["message"])

    # ---- 命名链 ----

    def test_explicit_name_exists_field_conflict_whole_error(self):
        result = extract_fields.extract_field(
            self.data, "req_header", "original_log", self.pattern
        )
        self._err(result, "field_conflict")
        self.assertIn("已存在", result["message"])

    def test_auto_naming_keyword(self):
        result = extract_fields.extract_field(
            self.data, None, "original_log", self.pattern, keyword="client"
        )
        updated = self._ok(result)
        self.assertEqual(updated[0]["normalize"][-1]["index"], "client")

    def test_auto_naming_keyword_conflict_new_prefix(self):
        # 关键词撞已有字段：加 new 前缀消解
        result = extract_fields.extract_field(
            self.data, None, "original_log", self.pattern, keyword="original_log"
        )
        updated = self._ok(result)
        self.assertEqual(updated[0]["normalize"][-1]["index"], "neworiginal_log")
        self.assertEqual(updated[0]["normalize"][-1]["result"], ["nexus"])

    def test_auto_naming_fallback_source_tail(self):
        data = [
            make_entity(
                "rule_a",
                normalize=[norm_entry("payload.client", ['client="x"'])],
            )
        ]
        result = extract_fields.extract_field(
            data, None, "payload.client", r'client="([a-z]+)"'
        )
        updated = self._ok(result)
        # 无关键词：退回源字段名尾段
        self.assertEqual(updated[0]["normalize"][-1]["index"], "client")
        self.assertEqual(updated[0]["normalize"][-1]["result"], ["x"])

    # ---- 幂等与透传 ----

    def test_existing_arg1_overwritten_no_normalize_append(self):
        old_pattern = r"[\S\s]*"
        data = [
            make_entity(
                "rule_a",
                normalize=[norm_entry("original_log", ['start client="nexus" end'])],
                filters=[{
                    "custom_name": "extractRegexField",
                    "fields": [function_item("newclient", "original_log", old_pattern)],
                    "name": "customFunction",
                    "id": "",
                }],
            )
        ]
        updated = self._ok(
            extract_fields.extract_field(
                data, "newclient", "original_log", self.pattern
            )
        )
        filters = updated[0]["parser"]["filter"]
        # 同名函数条目原地覆盖（新正则生效），不重复追加
        self.assertEqual(len(filters), 1)
        self.assertEqual(len(filters[0]["fields"]), 1)
        self.assertEqual(
            filters[0]["fields"][0],
            function_item("newclient", "original_log", self.pattern),
        )
        # normalize 不再追加同名条目
        self.assertEqual(
            [e["index"] for e in updated[0]["normalize"]], ["original_log"]
        )

    def test_target_names_passthrough(self):
        result = extract_fields.extract_field(
            self.data, "newclient", "original_log", self.pattern,
            target_names=["rule_a"],
        )
        updated = self._ok(result)
        self.assertIn("（目标 1 个）", result["message"])
        # 名单外 entity 原样透传
        self.assertIsNone(updated[1]["parser"]["filter"])
        self.assertEqual(len(updated[1]["normalize"]), 1)
        self.assertIsNone(updated[2]["parser"]["filter"])

    def test_input_not_mutated(self):
        extract_fields.extract_field(
            self.data, "newclient", "original_log", self.pattern
        )
        # 深拷贝：入参数据不被修改
        self.assertIsNone(self.data[0]["parser"]["filter"])
        self.assertEqual(len(self.data[0]["normalize"]), 2)
        self.assertEqual(len(self.data[1]["normalize"]), 1)

    # ---- 输入校验 ----

    def test_empty_data_invalid_input(self):
        result = extract_fields.extract_field(
            [], "newclient", "original_log", self.pattern
        )
        self._err(result, "invalid_input")

    def test_missing_source_arg_invalid_input(self):
        result = extract_fields.extract_field(
            self.data, "newclient", "", self.pattern
        )
        self._err(result, "invalid_input")

    def test_missing_pattern_arg_invalid_input(self):
        result = extract_fields.extract_field(
            self.data, "newclient", "original_log", ""
        )
        self._err(result, "invalid_input")


class ExtractFieldGuardedTest(unittest.TestCase):
    """extract_field_guarded() 守卫链：寻址 / 新名保留字段 / 新名事件字段。"""

    def setUp(self):
        self.pattern = r'[\S\s]*client="(.*?)"[\S\s]*'
        self.data = [
            make_entity(
                "rule_threat",
                normalize=[
                    norm_entry("original_log", ['start client="nexus" end']),
                    norm_entry(EVENT_NAME_FIELD, ["终端告警"]),
                    norm_entry(EVENT_LEVEL_FIELD, ["提醒"]),
                ],
            ),
            make_entity(
                "rule_normal",
                normalize=[
                    norm_entry("original_log", ['start client="beta" end']),
                    norm_entry(EVENT_NAME_FIELD, ["登录事件"]),
                ],
            ),
            make_entity(
                "rule_plain",
                normalize=[norm_entry("original_log", ['start client="gamma" end'])],
            ),
        ]

    def _ok(self, result):
        self.assertEqual(result["status"], "success")
        return result

    def _err(self, result, code):
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["code"], code)
        return result

    def test_guarded_extract_applies_to_all(self):
        result = self._ok(
            extract_fields.extract_field_guarded(
                self.data, "newclient", "original_log", self.pattern
            )
        )
        # original_log 三个子规则都有：全部写入提取过滤器
        for rule in result["data"]:
            self.assertEqual(
                rule["parser"]["filter"][-1]["name"], "customFunction"
            )
        self.assertEqual(result["data"][0]["normalize"][-1]["result"], ["nexus"])

    # ---- 新增字段名守卫 ----

    def test_reserved_new_field_rejected(self):
        for reserved in ("original_log", "rule_name_list", "日志类型"):
            result = extract_fields.extract_field_guarded(
                self.data, reserved, "original_log", self.pattern
            )
            self._err(result, "reserved_field_rejected")
            self.assertIn("系统保留字段", result["message"])

    def test_reserved_keyword_base_rejected(self):
        # 缺省命名基准（关键词）撞保留字段：同样拦截
        result = extract_fields.extract_field_guarded(
            self.data, None, "original_log", self.pattern,
            keyword="rule_name_list",
        )
        self._err(result, "reserved_field_rejected")

    def test_reserved_source_tail_base_rejected(self):
        # 缺省命名退回源字段尾段撞保留字段：同样拦截
        data = [
            make_entity(
                "rule_a",
                normalize=[norm_entry("payload.original_log", ['client="x"'])],
            )
        ]
        result = extract_fields.extract_field_guarded(
            data, None, "payload.original_log", self.pattern
        )
        self._err(result, "reserved_field_rejected")

    def test_source_original_log_not_restricted(self):
        # 被提取字段不受保留字段限制：「原始日志里的 X」是主用例
        result = self._ok(
            extract_fields.extract_field_guarded(
                self.data, "newclient", "original_log", self.pattern
            )
        )
        self.assertIn("来源: original_log", result["message"])

    def test_event_name_new_field_rejected(self):
        result = extract_fields.extract_field_guarded(
            self.data, EVENT_NAME_FIELD, "original_log", self.pattern
        )
        self._err(result, "invalid_event_name")
        self.assertIn("添加字段", result["message"])

    def test_event_level_new_field_rejected(self):
        result = extract_fields.extract_field_guarded(
            self.data, EVENT_LEVEL_FIELD, "original_log", self.pattern
        )
        self._err(result, "invalid_event_name")

    # ---- 寻址守卫 ----

    def test_unknown_target_rejected(self):
        result = extract_fields.extract_field_guarded(
            self.data, "newclient", "original_log", self.pattern,
            target_names=["rule_z"],
        )
        self._err(result, "rule_name_not_found")
        self.assertIn("未找到子规则: rule_z", result["message"])
        self.assertIn(
            "可用子规则: rule_threat、rule_normal、rule_plain", result["message"]
        )

    def test_group_threat_selects_annotated_threat_only(self):
        result = self._ok(
            extract_fields.extract_field_guarded(
                self.data, "newclient", "original_log", self.pattern,
                group="threat",
            )
        )
        self.assertIn("目标 1 个", result["message"])
        self.assertEqual(
            result["data"][0]["parser"]["filter"][-1]["name"], "customFunction"
        )
        # 非威胁组与未标注的子规则原样透传
        self.assertIsNone(result["data"][1]["parser"]["filter"])
        self.assertIsNone(result["data"][2]["parser"]["filter"])

    def test_group_non_threat_selects_annotated_non_threat_only(self):
        result = self._ok(
            extract_fields.extract_field_guarded(
                self.data, "newclient", "original_log", self.pattern,
                group="non-threat",
            )
        )
        self.assertIn("目标 1 个", result["message"])
        self.assertEqual(
            result["data"][1]["parser"]["filter"][-1]["name"], "customFunction"
        )
        self.assertIsNone(result["data"][0]["parser"]["filter"])

    def test_group_without_annotation_reports_event_annotation_required(self):
        data = [
            make_entity(
                "rule_a", normalize=[norm_entry("original_log", ['client="x"'])]
            )
        ]
        result = extract_fields.extract_field_guarded(
            data, "newclient", "original_log", self.pattern, group="threat"
        )
        self._err(result, "event_annotation_required")
        self.assertIn("添加字段", result["message"])

    def test_group_without_match_reports_rule_name_not_found(self):
        data = [
            make_entity(
                "rule_normal",
                normalize=[
                    norm_entry("original_log", ['client="x"']),
                    norm_entry(EVENT_NAME_FIELD, ["登录事件"]),
                ],
            )
        ]
        result = extract_fields.extract_field_guarded(
            data, "newclient", "original_log", self.pattern, group="threat"
        )
        self._err(result, "rule_name_not_found")
        self.assertIn("没有属于威胁组的子规则", result["message"])

    def test_target_takes_precedence_over_group(self):
        # target 指向威胁组规则而 group 选非威胁组：target 优先
        result = self._ok(
            extract_fields.extract_field_guarded(
                self.data, "newclient", "original_log", self.pattern,
                target_names=["rule_threat"], group="non-threat",
            )
        )
        self.assertIn("目标 1 个", result["message"])
        self.assertEqual(
            result["data"][0]["parser"]["filter"][-1]["name"], "customFunction"
        )

    # ---- 校验透传 ----

    def test_invalid_pattern_passthrough(self):
        result = extract_fields.extract_field_guarded(
            self.data, "newclient", "original_log", "(["
        )
        self._err(result, "invalid_pattern")

    def test_empty_data_invalid_input(self):
        result = extract_fields.extract_field_guarded(
            [], "newclient", "original_log", self.pattern
        )
        self._err(result, "invalid_input")


if __name__ == "__main__":
    unittest.main()
