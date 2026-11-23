"""mapping_candidates 单元测试：候选开单（字段收集 + 值画像 + Top-K 候选 + CLI）。

接缝：field-mapping/scripts/mapping_candidates.py 的公开函数——
mappable_indexes / collect_subrule_rules / collect_config_rules /
build_excel_profiles / build_sample_profiles / build_config_profiles /
build_candidates_document / main（进程内调用，文件契约）。
"""

from __future__ import annotations

import contextlib
import io
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for path in (
    str(ROOT),
    str(ROOT / "skills" / "parser-skills"),
    str(ROOT / "skills" / "parser-skills" / "field-mapping" / "scripts"),
    str(ROOT / "tests"),
):
    if path not in sys.path:
        sys.path.insert(0, path)

import mapping_candidates as mc  # noqa: E402
from excel_helpers import make_xlsx  # noqa: E402
from field_adjust_helpers import norm_entry  # noqa: E402
from _shared import standard_catalog  # noqa: E402


def _subrule(
    name,
    *,
    parser_name="json",
    tab="=",
    delimit=" ",
    normalize=None,
    sample="",
):
    return {
        "name": name,
        "parser": {"name": parser_name, "tab": tab, "delimit": delimit},
        "normalize": normalize if normalize is not None else [],
        "sample": sample,
    }


class MappableIndexesTest(unittest.TestCase):
    def test_mapped_entry_excluded(self):
        entity = {
            "normalize": [
                norm_entry("src_ip", ["1.1.1.1"], field="源地址"),
                norm_entry("user_name", ["admin"]),
            ]
        }
        self.assertEqual(mc.mappable_indexes(entity), ["user_name"])

    def test_excluded_indices_skipped(self):
        entity = {
            "normalize": [
                norm_entry("日志类型", ["登录"]),
                norm_entry("事件名称", ["x"]),
                norm_entry("事件级别", ["1"]),
                norm_entry("original_log", ["raw"]),
                norm_entry("user_name", ["admin"]),
            ]
        }
        self.assertEqual(mc.mappable_indexes(entity), ["user_name"])

    def test_empty_index_skipped_and_dedup(self):
        entity = {
            "normalize": [
                norm_entry("", []),
                norm_entry("user_name", ["admin"]),
                norm_entry("user_name", ["root"]),
            ]
        }
        self.assertEqual(mc.mappable_indexes(entity), ["user_name"])


class CollectRulesTest(unittest.TestCase):
    def test_subrule_rules_parser_info(self):
        entities = [
            _subrule(
                "主机登录_kv_子规则",
                parser_name="delimitWithKeyMap",
                tab=":",
                delimit="\\s",
                normalize=[norm_entry("user", ["admin"])],
                sample="user: admin",
            ),
            {"name": "空规则", "parser": {"name": "json"}, "normalize": []},
        ]
        rules = mc.collect_subrule_rules(entities)
        self.assertEqual(len(rules), 1)
        rule = rules[0]
        self.assertEqual(rule["owner"], "主机登录_kv_子规则")
        self.assertEqual(rule["fields"], ["user"])
        self.assertEqual(rule["parser_name"], "delimitWithKeyMap")
        self.assertEqual(rule["tab"], ":")
        self.assertEqual(rule["delimit"], " ")  # \s 语义转义还原
        self.assertEqual(rule["sample"], "user: admin")

    def test_config_rules_results(self):
        entities = [
            {
                "name": "某厂_AUDIT_json_子规则",
                "normalize": [
                    norm_entry("dst_ip", ["192.168.1.20", "192.168.1.21"]),
                    norm_entry("src_ip", ["10.1.1.5"], field="源地址"),
                ],
            }
        ]
        rules = mc.collect_config_rules(entities)
        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0]["fields"], ["dst_ip"])
        self.assertEqual(
            rules[0]["results"], {"dst_ip": ["192.168.1.20", "192.168.1.21"]}
        )


class ExcelProfilesTest(unittest.TestCase):
    def _profiles(self, entities, lines):
        return mc.build_excel_profiles(mc.collect_subrule_rules(entities), lines)

    def test_json_profiles_counts(self):
        rules = [
            _subrule("a_子规则", normalize=[norm_entry("a"), norm_entry("b")], sample="{}")
        ]
        lines = [
            '{"a": "1", "b": "x"}',
            '{"a": "", "b": "y"}',
            '{"b": "z"}',
            "not json",
        ]
        profiles = self._profiles(rules, lines)
        a = profiles["a"][0]
        self.assertEqual(a["owner"], "a_子规则")
        self.assertEqual(a["source"], "excel")
        self.assertEqual(a["scanned_lines"], 4)
        self.assertEqual(a["hit_lines"], 2)
        self.assertEqual(a["empty_count"], 1)
        self.assertEqual(dict(a["values"]), {"1": 1})
        self.assertEqual(len(a["values"]), 1)

    def test_json_nested_path(self):
        rules = [_subrule("a_子规则", normalize=[norm_entry("event.action")])]
        profiles = self._profiles(rules, ['{"event": {"action": "block"}}'])
        self.assertEqual(profiles["event.action"][0]["values"], {"block": 1})

    def test_kv_profiles(self):
        rules = [
            _subrule(
                "kv_子规则",
                parser_name="delimitWithKeyMap",
                tab="=",
                delimit=" ",
                normalize=[norm_entry("user"), norm_entry("result")],
            )
        ]
        lines = ["user=admin result=ok", "user=root result=fail", "result=ok"]
        profiles = self._profiles(rules, lines)
        user = profiles["user"][0]
        self.assertEqual(user["hit_lines"], 2)
        self.assertEqual(dict(user["values"]), {"admin": 1, "root": 1})
        result = profiles["result"][0]
        self.assertEqual(dict(result["values"]), {"ok": 2, "fail": 1})

    def test_kv_custom_delimiters(self):
        rules = [
            _subrule(
                "kv_子规则",
                parser_name="delimitWithKeyMap",
                tab=":",
                delimit=",",
                normalize=[norm_entry("user")],
            )
        ]
        profiles = self._profiles(rules, ["user:admin,act:login"])
        self.assertEqual(dict(profiles["user"][0]["values"]), {"admin": 1})

    def test_unsupported_parser_skipped_in_excel_profiles(self):
        rules = [
            _subrule(
                "legacy_子规则",
                parser_name="orgRegex",
                normalize=[norm_entry("user")],
                sample="user=admin",
            )
        ]
        profiles = self._profiles(rules, ["user=admin"])
        self.assertEqual(profiles, {})

    def test_profile_values_capped_and_sorted(self):
        rules = [_subrule("a_子规则", normalize=[norm_entry("v")])]
        lines = [json.dumps({"v": str(i)}) for i in range(12)]
        lines.append('{"v": "7"}')
        profiles = self._profiles(rules, lines)
        payload = mc._profile_payload(profiles["v"][0])
        self.assertEqual(len(payload["values"]), 10)
        self.assertEqual(payload["distinct_count"], 12)
        # 计数降序：7 出现两次排最前
        self.assertEqual(next(iter(payload["values"])), "7")
        self.assertEqual(payload["values"]["7"], 2)


class SampleProfilesTest(unittest.TestCase):
    def _profiles(self, entities):
        return mc.build_sample_profiles(mc.collect_subrule_rules(entities))

    def test_sample_json_profile(self):
        entities = [
            _subrule(
                "a_子规则",
                normalize=[norm_entry("user")],
                sample='{"user": "admin", "act": "login"}',
            )
        ]
        profiles = self._profiles(entities)
        user = profiles["user"][0]
        self.assertEqual(user["source"], "sample")
        self.assertEqual(user["scanned_lines"], 1)
        self.assertEqual(user["hit_lines"], 1)
        self.assertEqual(dict(user["values"]), {"admin": 1})

    def test_sample_kv_profile(self):
        entities = [
            _subrule(
                "kv_子规则",
                parser_name="delimitWithKeyMap",
                tab="=",
                delimit=" ",
                normalize=[norm_entry("user")],
                sample="user=admin act=login",
            )
        ]
        profiles = self._profiles(entities)
        self.assertEqual(dict(profiles["user"][0]["values"]), {"admin": 1})

    def test_empty_sample_no_profile(self):
        entities = [_subrule("a_子规则", normalize=[norm_entry("user")], sample="")]
        self.assertEqual(self._profiles(entities), {})


class ConfigProfilesTest(unittest.TestCase):
    def test_config_preview_profiles(self):
        rules = [
            {
                "owner": "某厂_AUDIT_json_子规则",
                "fields": ["dst_ip", "user"],
                "results": {
                    "dst_ip": ["192.168.1.20", "192.168.1.21", ""],
                    "user": ["admin"],
                },
            }
        ]
        profiles = mc.build_config_profiles(rules)
        dst = profiles["dst_ip"][0]
        self.assertEqual(dst["source"], "config_preview")
        self.assertEqual(dst["scanned_lines"], 3)
        self.assertEqual(dst["hit_lines"], 3)
        self.assertEqual(dst["empty_count"], 1)
        self.assertEqual(len(dst["values"]), 2)


class DocumentTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog = standard_catalog.load_catalog()

    def _document(self, entities):
        rules = mc.collect_subrule_rules(entities)
        return mc.build_candidates_document(
            rules, mc.build_sample_profiles(rules), self.catalog
        )

    def test_enum_short_circuit_marked(self):
        document, short_circuited = self._document(
            [
                _subrule(
                    "a_子规则",
                    normalize=[norm_entry("http_method"), norm_entry("user_name")],
                    sample='{"http_method": "GET", "user_name": "admin"}',
                )
            ]
        )
        self.assertEqual(short_circuited, 1)
        by_field = {f["field"]: f for f in document["fields"]}
        self.assertEqual(
            by_field["http_method"]["enum_short_circuit"],
            {"standard": "HTTP请求方法", "source": "exact"},
        )
        self.assertEqual(by_field["http_method"]["candidates"], [])
        self.assertIsNone(by_field["user_name"]["enum_short_circuit"])
        self.assertTrue(by_field["user_name"]["candidates"])

    def test_field_order_first_seen_with_profiles(self):
        document, _ = self._document(
            [
                _subrule(
                    "a_子规则",
                    normalize=[norm_entry("user"), norm_entry("dst_ip")],
                    sample='{"user": "admin", "dst_ip": "1.1.1.1"}',
                ),
                _subrule(
                    "b_子规则",
                    normalize=[norm_entry("user")],
                    sample='{"user": "root"}',
                ),
            ]
        )
        self.assertEqual(
            [f["field"] for f in document["fields"]], ["user", "dst_ip"]
        )
        user = next(f for f in document["fields"] if f["field"] == "user")
        self.assertEqual(len(user["value_profiles"]), 2)

    def test_dst_ip_candidates_include_destination(self):
        document, _ = self._document(
            [
                _subrule(
                    "a_子规则",
                    normalize=[norm_entry("dst_ip")],
                    sample='{"dst_ip": "1.1.1.1"}',
                )
            ]
        )
        names = [c["name"] for c in document["fields"][0]["candidates"]]
        self.assertIn("目的地址", names)
        first = document["fields"][0]["candidates"][0]
        self.assertEqual(
            sorted(first),
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


class CliTest(unittest.TestCase):
    def setUp(self):
        self._tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self._tmp, ignore_errors=True)

    def _run(self, argv):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = mc.main(argv)
        return code, stdout.getvalue()

    def _write_subrules(self, entities, name="whiteboard_subrules.json"):
        path = self._tmp / name
        path.write_text(json.dumps(entities, ensure_ascii=False), encoding="utf-8")
        return path

    def test_b2_e2e_with_excel(self):
        subrules = self._write_subrules(
            [
                _subrule(
                    "登录_json_子规则",
                    normalize=[norm_entry("dst_ip"), norm_entry("user_name")],
                    sample='{"dst_ip": "1.1.1.1", "user_name": "admin"}',
                ),
                _subrule(
                    "操作_kv_子规则",
                    parser_name="delimitWithKeyMap",
                    tab="=",
                    delimit=" ",
                    normalize=[norm_entry("act")],
                    sample="act=login",
                ),
            ]
        )
        excel = self._tmp / "logs.xlsx"
        make_xlsx(
            excel,
            [
                ["原始日志", "备注"],
                ['{"dst_ip": "1.1.1.1", "user_name": "admin"}', "r1"],
                ['{"dst_ip": "2.2.2.2", "user_name": ""}', "r2"],
                ["act=login", "r3"],
            ],
        )
        code, stdout = self._run(
            ["--subrules", str(subrules), "--excel", str(excel)]
        )
        self.assertEqual(code, 0)
        payload = json.loads(stdout)
        self.assertEqual(payload["status"], "success")
        self.assertEqual(payload["field_count"], 3)
        output = Path(payload["output"])
        self.assertEqual(output, self._tmp / "whiteboard_subrules_candidates.json")
        document = json.loads(output.read_text(encoding="utf-8"))
        by_field = {f["field"]: f for f in document["fields"]}
        self.assertIn("目的地址", [c["name"] for c in by_field["dst_ip"]["candidates"]])
        dst_profile = by_field["dst_ip"]["value_profiles"][0]
        self.assertEqual(dst_profile["source"], "excel")
        self.assertEqual(dst_profile["hit_lines"], 2)
        self.assertEqual(dst_profile["empty_count"], 0)
        act_profile = by_field["act"]["value_profiles"][0]
        self.assertEqual(act_profile["source"], "excel")
        self.assertEqual(dict(act_profile["values"]), {"login": 1})

    def test_b2_sample_fallback_e2e(self):
        subrules = self._write_subrules(
            [
                _subrule(
                    "登录_json_子规则",
                    normalize=[norm_entry("dst_ip")],
                    sample='{"dst_ip": "1.1.1.1"}',
                )
            ]
        )
        code, stdout = self._run(["--subrules", str(subrules)])
        self.assertEqual(code, 0)
        document = json.loads(Path(json.loads(stdout)["output"]).read_text(encoding="utf-8"))
        profile = document["fields"][0]["value_profiles"][0]
        self.assertEqual(profile["source"], "sample")

    def test_a6_e2e(self):
        config = self._tmp / "config.json"
        config.write_text(
            json.dumps(
                [
                    {
                        "name": "某厂_AUDIT_json_子规则",
                        "normalize": [
                            norm_entry("dst_ip", ["192.168.1.20", ""]),
                            norm_entry("src_ip", ["10.1.1.5"], field="源地址"),
                        ],
                    }
                ],
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )
        code, stdout = self._run(["--config", str(config)])
        self.assertEqual(code, 0)
        document = json.loads(
            Path(json.loads(stdout)["output"]).read_text(encoding="utf-8")
        )
        self.assertEqual([f["field"] for f in document["fields"]], ["dst_ip"])
        profile = document["fields"][0]["value_profiles"][0]
        self.assertEqual(profile["source"], "config_preview")
        self.assertEqual(profile["empty_count"], 1)
        self.assertIn(
            "目的地址",
            [c["name"] for c in document["fields"][0]["candidates"]],
        )

    def test_all_mapped_config_skips_with_empty_document(self):
        # 全映射跳过守卫：成功跳过（空候选单），既有映射保留——幂等重跑友好
        sample = ROOT / "testdata" / "sample_config.json"
        code, stdout = self._run(
            ["--config", str(sample), "--output", str(self._tmp / "out_candidates.json")]
        )
        self.assertEqual(code, 0)
        payload = json.loads(stdout)
        self.assertEqual(payload["status"], "success")
        self.assertEqual(payload["field_count"], 0)
        document = json.loads(
            Path(payload["output"]).read_text(encoding="utf-8")
        )
        self.assertEqual(document, {"fields": []})

    def test_missing_mode_invalid_input(self):
        code, stdout = self._run([])
        self.assertEqual(code, 1)
        self.assertIn("invalid_input", stdout)

    def test_both_modes_invalid_input(self):
        code, stdout = self._run(["--subrules", "a.json", "--config", "b.txt"])
        self.assertEqual(code, 1)
        self.assertIn("invalid_input", stdout)

    def test_missing_subrules_file_config_required(self):
        code, stdout = self._run(["--subrules", str(self._tmp / "nope.json")])
        self.assertEqual(code, 1)
        self.assertIn("config_required", stdout)

    def test_missing_excel_passthrough_error(self):
        subrules = self._write_subrules(
            [
                _subrule(
                    "a_子规则", normalize=[norm_entry("user")], sample='{"user": "a"}'
                )
            ]
        )
        code, stdout = self._run(
            ["--subrules", str(subrules), "--excel", str(self._tmp / "nope.xlsx")]
        )
        self.assertEqual(code, 1)
        self.assertNotEqual(code, 0)


if __name__ == "__main__":
    unittest.main()
