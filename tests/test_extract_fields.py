"""extract_fields 单元与端到端测试。

覆盖 extract_field 核心行为（customFunction + normalize 双写、全匹配样本
校验、缺省命名链、幂等覆盖、per-entity 自适应）、提取守卫链与文件契约
端到端。
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

    def test_auto_naming_keyword_reserved_but_resolved_passes(self):
        # 关键词撞保留字段但将消解为 new 前缀名：不误拦（review 修复回归）
        result = self._ok(
            extract_fields.extract_field_guarded(
                self.data, None, "original_log", self.pattern,
                keyword="original_log",
            )
        )
        self.assertEqual(
            result["data"][0]["normalize"][-1]["index"], "neworiginal_log"
        )

    def test_source_tail_main_use_case_resolved_passes(self):
        # 主用例调用形态：source=original_log 且不带 --field/--keyword，
        # 消解为 neworiginal_log，守卫不得以保留字段误拦（review 修复回归）
        result = self._ok(
            extract_fields.extract_field_guarded(
                self.data, None, "original_log", self.pattern
            )
        )
        self.assertEqual(
            result["data"][0]["normalize"][-1]["index"], "neworiginal_log"
        )
        self.assertEqual(result["data"][0]["normalize"][-1]["result"], ["nexus"])

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


class CliEndToEndTest(unittest.TestCase):
    """文件契约端到端：Base64 输入 → 修改后 JSON + 平台可导入 Base64 输出。

    以进程内调用 main() + stdout 重定向实现，避免子进程管道
    （受限环境下 EPERM），任何环境可跑；真实 CLI 演示见 SKILL.md。
    """

    FIXTURE = ROOT / "testdata" / "sample_config.json"

    def setUp(self):
        (ROOT / ".tmp_tests").mkdir(exist_ok=True)
        self._tmp = Path(tempfile.mkdtemp(dir=str(ROOT / ".tmp_tests")))
        self.addCleanup(self._cleanup)

    def _cleanup(self):
        import shutil

        shutil.rmtree(self._tmp, ignore_errors=True)
        tmp_root = ROOT / ".tmp_tests"
        if tmp_root.is_dir() and not any(tmp_root.iterdir()):
            tmp_root.rmdir()

    def _run(self, *argv):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = extract_fields.main([*argv])
        return code, buf.getvalue()

    def _b64_copy(self) -> Path:
        payload = json.loads(self.FIXTURE.read_text(encoding="utf-8"))
        b64_file = self._tmp / "config.b64.txt"
        b64_file.write_text(
            base64.b64encode(
                json.dumps(payload, ensure_ascii=False).encode("utf-8")
            ).decode("ascii"),
            encoding="utf-8",
        )
        return b64_file

    def test_e2e_extract_on_base64_input(self):
        b64_file = self._b64_copy()
        output = self._tmp / "out.modified.json"
        code, stdout = self._run(
            "--input", str(b64_file),
            "--source-field", "original_log",
            "--pattern", r'[\S\s]*"user":"(.*?)"[\S\s]*',
            "--field", "提取用户",
            "--target", "某厂_AUDIT_json_子规则",
            "--output", str(output),
        )
        self.assertEqual(code, 0, stdout)
        report = json.loads(stdout)
        self.assertEqual(report["status"], "success")
        self.assertIn(
            "成功为 1 个 entity 添加正则提取字段 '提取用户'（来源: original_log）",
            report["message"],
        )
        self.assertIn("目标 1 个", report["message"])
        # 修改后 JSON：AUDIT 子规则追加 customFunction 过滤器（原有
        # additional_fields_filter 原样保留），normalize 双写预览条目
        updated = json.loads(output.read_text(encoding="utf-8"))
        filters = updated[0]["parser"]["filter"]
        self.assertEqual(len(filters), 2)
        self.assertEqual(filters[0]["id"], "additional_fields_filter")
        custom_filter = filters[1]
        self.assertEqual(custom_filter["name"], "customFunction")
        self.assertEqual(custom_filter["id"], "")
        self.assertEqual(
            custom_filter["fields"],
            [function_item("提取用户", "original_log", r'[\S\s]*"user":"(.*?)"[\S\s]*')],
        )
        self.assertEqual(
            updated[0]["normalize"][-1], expected_norm_entry("提取用户", "admin")
        )
        # 名单外子规则原样透传
        self.assertIsNone(updated[1]["parser"]["filter"])
        # 平台可导入 Base64 导出文件
        export = Path(report["export"])
        self.assertTrue(export.exists())
        self.assertRegex(export.name, r"^fieldadjusted_config_\d{8}_\d{4}\.txt$")
        decoded = json.loads(base64.b64decode(export.read_text(encoding="utf-8")))
        self.assertEqual(decoded, updated)

    def test_e2e_auto_naming_from_keyword(self):
        output = self._tmp / "out.modified.json"
        code, stdout = self._run(
            "--input", str(self.FIXTURE),
            "--source-field", "original_log",
            "--pattern", r'[\S\s]*"user":"(.*?)"[\S\s]*',
            "--keyword", "user",
            "--target", "某厂_AUDIT_json_子规则",
            "--output", str(output),
        )
        self.assertEqual(code, 0, stdout)
        updated = json.loads(output.read_text(encoding="utf-8"))
        # 缺省命名：关键词 user 不与已有字段冲突 → 直接命名 user
        self.assertEqual(
            updated[0]["normalize"][-1], expected_norm_entry("user", "admin")
        )

    def test_e2e_default_output_path(self):
        code, stdout = self._run(
            "--input", str(self.FIXTURE),
            "--source-field", "original_log",
            "--pattern", r'[\S\s]*"user":"(.*?)"[\S\s]*',
            "--field", "提取用户",
            "--target", "某厂_AUDIT_json_子规则",
        )
        self.assertEqual(code, 0, stdout)
        report = json.loads(stdout)
        # 缺省输出路径 = <输入名>.modified.json，与输入同目录
        self.assertEqual(
            report["output"],
            str(self.FIXTURE.with_name(self.FIXTURE.stem + ".modified.json")),
        )
        default_output = Path(report["output"])
        self.addCleanup(lambda: default_output.unlink(missing_ok=True))
        self.assertTrue(default_output.exists())
        # 导出文件也落在输入同目录，测试后清理
        export = Path(report["export"])
        self.addCleanup(lambda: export.unlink(missing_ok=True))
        self.assertEqual(export.parent, self.FIXTURE.parent)

    def test_e2e_pattern_mismatch_exit_code(self):
        # 正则无法全匹配 IPS 子规则的样本（缺 "user" 键）→ 整体拒绝
        code, stdout = self._run(
            "--input", str(self.FIXTURE),
            "--source-field", "original_log",
            "--pattern", r'[\S\s]*"user":"(.*?)"[\S\s]*',
            "--field", "提取用户",
        )
        self.assertEqual(code, 1)
        report = json.loads(stdout)
        self.assertEqual(report["code"], "pattern_mismatch")
        self.assertIn("无法全匹配", report["message"])

    def test_e2e_invalid_pattern_exit_code(self):
        code, stdout = self._run(
            "--input", str(self.FIXTURE),
            "--source-field", "original_log",
            "--pattern", "([",
            "--field", "提取用户",
        )
        self.assertEqual(code, 1)
        report = json.loads(stdout)
        self.assertEqual(report["code"], "invalid_pattern")

    def test_e2e_field_conflict_exit_code(self):
        code, stdout = self._run(
            "--input", str(self.FIXTURE),
            "--source-field", "original_log",
            "--pattern", r'[\S\s]*',
            "--field", "src_ip",
            "--target", "某厂_AUDIT_json_子规则",
        )
        self.assertEqual(code, 1)
        report = json.loads(stdout)
        self.assertEqual(report["code"], "field_conflict")
        self.assertIn("已存在", report["message"])

    def test_e2e_missing_source_field_not_found(self):
        code, stdout = self._run(
            "--input", str(self.FIXTURE),
            "--source-field", "不存在字段",
            "--pattern", r"[\S\s]*",
            "--field", "提取结果",
        )
        self.assertEqual(code, 1)
        report = json.loads(stdout)
        self.assertEqual(report["code"], "field_not_found")
        self.assertIn("并集", report["message"])

    def test_e2e_reserved_new_field_exit_code(self):
        code, stdout = self._run(
            "--input", str(self.FIXTURE),
            "--source-field", "original_log",
            "--pattern", r'[\S\s]*',
            "--field", "original_log",
        )
        self.assertEqual(code, 1)
        report = json.loads(stdout)
        self.assertEqual(report["code"], "reserved_field_rejected")

    def test_e2e_missing_input_reports_config_required(self):
        code, stdout = self._run(
            "--input", str(self._tmp / "nope.txt"),
            "--source-field", "original_log",
            "--pattern", r"[\S\s]*",
            "--field", "提取结果",
        )
        self.assertEqual(code, 1)
        report = json.loads(stdout)
        self.assertEqual(report["code"], "config_required")

    def test_e2e_no_export_flag(self):
        output = self._tmp / "out.modified.json"
        code, stdout = self._run(
            "--input", str(self.FIXTURE),
            "--source-field", "original_log",
            "--pattern", r'[\S\s]*"user":"(.*?)"[\S\s]*',
            "--field", "提取用户",
            "--target", "某厂_AUDIT_json_子规则",
            "--output", str(output),
            "--no-export",
        )
        self.assertEqual(code, 0, stdout)
        report = json.loads(stdout)
        self.assertIsNone(report["export"])
        # 只有修改后 JSON 落盘
        self.assertTrue(output.exists())
        exports = list(self._tmp.glob("fieldadjusted_config_*.txt"))
        self.assertEqual(exports, [])


if __name__ == "__main__":
    unittest.main()
