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

    def test_skipped_reasons_truncated_after_five(self):
        # 7 个 entity，6 个缺 req_body：跳过原因只详列前 5 条，其余计总数
        data = [
            make_entity(
                f"rule_{i}",
                normalize=[norm_entry("req_header", [""])],
            )
            for i in range(7)
        ]
        data[0]["normalize"].append(norm_entry("req_body", [""]))
        result = decode_fields.decode_fields(data, ["req_header", "req_body"])
        self.assertEqual(result["status"], "success")
        self.assertIn("等 6 条", result["message"])
        # 前 5 条逐名报告
        for i in range(1, 6):
            self.assertIn(f"rule_{i}（缺 req_body）", result["message"])
        # 第 6 条不逐名展开
        self.assertNotIn("rule_6（缺 req_body）", result["message"])

    def test_union_preview_capped_at_thirty(self):
        # 31 个字段的并集：预览按字典序只列前 30 个并加「等」（零填充使序号序=字典序）
        data = [
            make_entity(
                "rule_a",
                normalize=[norm_entry(f"f{i:02d}", [""]) for i in range(31)],
            )
        ]
        result = decode_fields.decode_fields(data, ["不存在字段"])
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["code"], "field_not_found")
        self.assertIn("并集: f00、f01", result["message"])
        self.assertTrue(result["message"].rstrip().endswith("等"))
        self.assertIn("f29", result["message"])
        self.assertNotIn("f30", result["message"])


class DecodeFieldGuardedTest(unittest.TestCase):
    """decode_fields_guarded() 守卫链：寻址、保留字段、事件字段。"""

    def setUp(self):
        self.data = [
            make_entity(
                "rule_threat",
                normalize=[
                    norm_entry("req_header", [""]),
                    norm_entry("req_body", [""]),
                    norm_entry(EVENT_NAME_FIELD, ["终端告警"]),
                    norm_entry(EVENT_LEVEL_FIELD, ["提醒"]),
                ],
            ),
            make_entity(
                "rule_normal",
                normalize=[
                    norm_entry("req_header", [""]),
                    norm_entry("req_body", [""]),
                    norm_entry(EVENT_NAME_FIELD, ["登录事件"]),
                ],
            ),
            make_entity("rule_plain", normalize=[norm_entry("req_header", [""])]),
        ]

    def _ok(self, result):
        self.assertEqual(result["status"], "success")
        return result

    def test_guarded_decode_applies_to_all(self):
        result = self._ok(
            decode_fields.decode_fields_guarded(self.data, ["req_header", "req_body"])
        )
        for rule in result["data"][:2]:
            self.assertEqual(rule["parser"]["filter"][-1]["name"], "addFields")
        # rule_plain 缺 req_body，跳过并报告
        self.assertIn("rule_plain（缺 req_body）", result["message"])

    def test_reserved_field_rejected(self):
        for reserved in ("original_log", "rule_name_list", "日志类型"):
            result = decode_fields.decode_fields_guarded(self.data, [reserved])
            self.assertEqual(result["status"], "error")
            self.assertEqual(result["code"], "reserved_field_rejected")
            self.assertIn("系统保留字段", result["message"])

    def test_event_name_field_rejected(self):
        result = decode_fields.decode_fields_guarded(self.data, [EVENT_NAME_FIELD])
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["code"], "invalid_event_name")
        self.assertIn("添加字段", result["message"])

    def test_event_level_field_rejected(self):
        result = decode_fields.decode_fields_guarded(self.data, [EVENT_LEVEL_FIELD])
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["code"], "invalid_event_name")
        self.assertIn("添加字段", result["message"])

    def test_partially_reserved_fields_rejected(self):
        # 混合普通字段与保留字段：整单拒绝，不做部分应用
        result = decode_fields.decode_fields_guarded(
            self.data, ["req_header", "original_log"]
        )
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["code"], "reserved_field_rejected")

    def test_empty_data_invalid_input(self):
        result = decode_fields.decode_fields_guarded([], ["req_header"])
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["code"], "invalid_input")

    def test_empty_fields_invalid_input(self):
        result = decode_fields.decode_fields_guarded(self.data, [])
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["code"], "invalid_input")

    def test_unknown_target_rejected(self):
        result = decode_fields.decode_fields_guarded(
            self.data, ["req_header"], target_names=["rule_z"]
        )
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["code"], "rule_name_not_found")
        self.assertIn("未找到子规则: rule_z", result["message"])
        self.assertIn(
            "可用子规则: rule_threat、rule_normal、rule_plain", result["message"]
        )

    def test_group_threat_selects_annotated_threat_only(self):
        result = self._ok(
            decode_fields.decode_fields_guarded(
                self.data, ["req_header"], group="threat"
            )
        )
        self.assertIn("目标 1 个", result["message"])
        # 威胁组 rule_threat 启用解码，未标注的 rule_plain 原样透传
        self.assertEqual(result["data"][0]["parser"]["filter"][-1]["name"], "addFields")
        self.assertEqual(result["data"][2]["parser"]["filter"], None)

    def test_group_non_threat_selects_annotated_non_threat_only(self):
        result = self._ok(
            decode_fields.decode_fields_guarded(
                self.data, ["req_header"], group="non-threat"
            )
        )
        self.assertIn("目标 1 个", result["message"])
        self.assertEqual(result["data"][1]["parser"]["filter"][-1]["name"], "addFields")
        self.assertEqual(result["data"][0]["parser"]["filter"], None)

    def test_group_without_annotation_reports_event_annotation_required(self):
        data = [
            make_entity(
                "rule_a", normalize=[norm_entry("req_header", [""])]
            )
        ]
        result = decode_fields.decode_fields_guarded(
            data, ["req_header"], group="threat"
        )
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["code"], "event_annotation_required")
        self.assertIn("添加字段", result["message"])

    def test_group_without_match_reports_rule_name_not_found(self):
        data = [
            make_entity(
                "rule_normal",
                normalize=[
                    norm_entry("req_header", [""]),
                    norm_entry(EVENT_NAME_FIELD, ["登录事件"]),
                ],
            )
        ]
        result = decode_fields.decode_fields_guarded(
            data, ["req_header"], group="threat"
        )
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["code"], "rule_name_not_found")
        self.assertIn("没有属于威胁组的子规则", result["message"])

    def test_target_takes_precedence_over_group(self):
        # target 指向威胁组规则而 group 选非威胁组：target 优先
        result = self._ok(
            decode_fields.decode_fields_guarded(
                self.data, ["req_header"], target_names=["rule_threat"],
                group="non-threat",
            )
        )
        self.assertIn("目标 1 个", result["message"])
        self.assertEqual(result["data"][0]["parser"]["filter"][-1]["name"], "addFields")


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
            code = decode_fields.main([*argv])
        return code, buf.getvalue()

    def test_e2e_decode_on_base64_input(self):
        payload = json.loads(self.FIXTURE.read_text(encoding="utf-8"))
        b64_file = self._tmp / "config.b64.txt"
        b64_file.write_text(
            base64.b64encode(
                json.dumps(payload, ensure_ascii=False).encode("utf-8")
            ).decode("ascii"),
            encoding="utf-8",
        )
        output = self._tmp / "out.modified.json"
        code, stdout = self._run(
            "--input", str(b64_file),
            "--fields", "src_ip",
            "--output", str(output),
        )
        self.assertEqual(code, 0, stdout)
        report = json.loads(stdout)
        self.assertEqual(report["status"], "success")
        self.assertIn("成功为 1 个 entity 启用 base64 解码: src_ip", report["message"])
        # 缺 src_ip 的 IPS 子规则按名报告跳过；无 normalize 的入口规则计数
        self.assertIn("某厂_IPS_json_子规则（缺 src_ip）", report["message"])
        self.assertIn("跳过 1 个无 normalize 的 entity", report["message"])
        # 修改后 JSON：AUDIT 子规则追加解码过滤器（原有 addFields 过滤器原样保留）
        updated = json.loads(output.read_text(encoding="utf-8"))
        filters = updated[0]["parser"]["filter"]
        self.assertEqual(len(filters), 2)
        self.assertEqual(filters[0]["id"], "additional_fields_filter")
        decode_filter = filters[1]
        self.assertEqual(decode_filter["name"], "addFields")
        self.assertEqual(decode_filter["id"], "")
        self.assertEqual(decode_filter["fields"], {"src_ip": decode_ognl("src_ip")})
        # 原地覆盖：normalize 不变（不双写）
        self.assertEqual(len(updated[0]["normalize"]), 2)
        # 平台可导入 Base64 导出文件
        export = Path(report["export"])
        self.assertTrue(export.exists())
        self.assertRegex(export.name, r"^fieldadjusted_config_\d{8}_\d{4}\.txt$")
        decoded = json.loads(base64.b64decode(export.read_text(encoding="utf-8")))
        self.assertEqual(decoded, updated)

    def test_e2e_reserved_field_exit_code(self):
        code, stdout = self._run(
            "--input", str(self.FIXTURE),
            "--fields", "original_log",
            "--output", str(self._tmp / "o.json"),
        )
        self.assertEqual(code, 1)
        report = json.loads(stdout)
        self.assertEqual(report["code"], "reserved_field_rejected")

    def test_e2e_field_not_found_exit_code(self):
        code, stdout = self._run(
            "--input", str(self.FIXTURE),
            "--fields", "不存在字段",
        )
        self.assertEqual(code, 1)
        report = json.loads(stdout)
        self.assertEqual(report["code"], "field_not_found")
        self.assertIn("并集", report["message"])

    def test_e2e_unknown_target_exit_code(self):
        code, stdout = self._run(
            "--input", str(self.FIXTURE),
            "--fields", "src_ip",
            "--target", "不存在的规则",
        )
        self.assertEqual(code, 1)
        report = json.loads(stdout)
        self.assertEqual(report["code"], "rule_name_not_found")

    def test_e2e_missing_input_reports_config_required(self):
        code, stdout = self._run(
            "--input", str(self._tmp / "nope.txt"),
            "--fields", "src_ip",
        )
        self.assertEqual(code, 1)
        report = json.loads(stdout)
        self.assertEqual(report["code"], "config_required")

    def test_e2e_no_export_flag(self):
        output = self._tmp / "out.modified.json"
        code, stdout = self._run(
            "--input", str(self.FIXTURE),
            "--fields", "dst_ip",
            "--target", "某厂_IPS_json_子规则",
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
