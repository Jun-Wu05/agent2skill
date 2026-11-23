"""threat_finalize CLI 端到端测试：配置 + 工作单 + 分组判定 → 原子写回文件契约。

接缝：threat-type/scripts/threat_finalize.py 的 main(argv)——
stdout JSON（status/message/output/export/groups/skipped_rules 或
status/error/code/message）+ <输入名>.threatfilled.json 产物 +
threatmapping_config Base64 导出 + 退出码。守卫链与三态写回语义见脚本
docstring（设计裁决 #4 票面 2026-11-23）；夹具为合成 entities、工作单
与分组判定 JSON。
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
SKILLS = ROOT / "skills" / "parser-skills"
SCRIPTS = SKILLS / "threat-type" / "scripts"
for path in (str(ROOT), str(ROOT / "tests"), str(SKILLS), str(SCRIPTS)):
    if path not in sys.path:
        sys.path.insert(0, path)

import threat_finalize  # noqa: E402
from _shared.config_io import decode_config_text  # noqa: E402


def make_entry(index, field=None, mappings=None, result=None, entity=None, sim=None, core=None):
    return {
        "mappings": mappings if mappings is not None else [],
        "field": field,
        "sim": sim,
        "result": result if result is not None else [],
        "info": None,
        "entity": entity,
        "required": False,
        "core": core,
        "value": None,
        "index": index,
    }


def make_entity(name="规则A", entries=(), filters=(), event_name=None, sample_result=None):
    filters = list(filters)
    if event_name is not None:
        filters.append(
            {"name": "addFields", "id": "", "fields": {"事件名称": event_name}}
        )
    entries = list(entries)
    if sample_result:
        entries.insert(0, make_entry("src", result=sample_result))
    return {
        "name": name,
        "parser": {"name": "json", "filter": filters},
        "normalize": entries,
        "sample": "",
    }


def make_addfields(fields):
    return {"name": "addFields", "id": "", "fields": dict(fields)}


def threat_entry(mappings, source_field="threat_name", sample_count=1):
    return {
        "mappings": [dict(m) for m in mappings],
        "field": "threat_type",
        "sim": True,
        "result": [f"%{{{source_field}}}"] * sample_count,
        "info": None,
        "entity": "威胁",
        "required": False,
        "core": False,
        "value": None,
        "index": "威胁类型",
    }


def make_workload(path, threat_rules, candidates):
    """合成工作单 JSON：threat_rules + candidates[{field, value_counts}]。"""
    payload = {
        "threat_rules": threat_rules,
        "candidates": [
            {"field": field, "value_counts": counts} for field, counts in candidates
        ],
    }
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def make_judgment_file(path, groups, skipped_rules=()):
    payload = {"groups": groups, "skipped_rules": list(skipped_rules)}
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def pair(org, mapped, mapping_type="REGULAR"):
    return {"mappingType": mapping_type, "orgValue": org, "mappingValue": mapped}


class ThreatFinalizeCliTest(unittest.TestCase):
    def setUp(self):
        tmp_root = ROOT / ".tmp_tests"
        tmp_root.mkdir(exist_ok=True)
        self._tmp = Path(tempfile.mkdtemp(dir=str(tmp_root)))
        self.addCleanup(self._cleanup)

    def _cleanup(self):
        shutil.rmtree(self._tmp, ignore_errors=True)
        tmp_root = ROOT / ".tmp_tests"
        if tmp_root.is_dir() and not any(tmp_root.iterdir()):
            tmp_root.rmdir()

    def _config(self, entities, name="config.json"):
        path = self._tmp / name
        path.write_text(
            json.dumps(entities, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        return path

    def _run(self, *argv):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = threat_finalize.main(list(argv))
        return code, json.loads(stdout.getvalue())

    def _base_config(self):
        """两条威胁子规则（threat_name 同名，可归一组）+ 一条非威胁。"""
        return [
            make_entity(
                "恶意软件规则",
                entries=[make_entry("threat_name"), make_entry("sev_code")],
                event_name="病毒检测",
                sample_result=["s1", "s2"],
            ),
            make_entity(
                "Web攻击规则",
                entries=[make_entry("threat_name")],
                event_name="网络攻击",
                sample_result=["s1"],
            ),
            make_entity("登录规则", entries=[make_entry("user")], event_name="登录事件"),
        ]

    def _base_worklist(self, name="worklist.json"):
        return make_workload(
            self._tmp / name,
            ["恶意软件规则", "Web攻击规则"],
            [
                ("threat_name", {"挖矿行为": 2, "勒索病毒Locky": 1}),
                ("sev_code", {"1": 2, "2": 1}),
            ],
        )

    def _base_judgments(self, name="judgments.json"):
        groups = [
            {
                "source_field": "threat_name",
                "rules": ["恶意软件规则", "Web攻击规则"],
                "pairs": [
                    pair("挖矿", "挖矿木马"),
                    pair("勒索病毒Locky", "勒索病毒", "EQUAL"),
                ],
            }
        ]
        return make_judgment_file(self._tmp / name, groups)

    # -- 成功路径 -----------------------------------------------------------

    def test_absent_state_adds_entry_and_binding(self):
        code, payload = self._run(
            "--input", str(self._config(self._base_config())),
            "--worklist", str(self._base_worklist()),
            "--judgments", str(self._base_judgments()),
        )
        self.assertEqual(code, 0)
        self.assertEqual(payload["status"], "success")

        result = json.loads(Path(payload["output"]).read_text(encoding="utf-8"))
        by_name = {e["name"]: e for e in result}
        for rule in ("恶意软件规则", "Web攻击规则"):
            entries = [e for e in by_name[rule]["normalize"] if e["index"] == "威胁类型"]
            self.assertEqual(len(entries), 1)
            entry = entries[0]
            self.assertEqual(entry["field"], "threat_type")
            self.assertEqual(entry["entity"], "威胁")
            self.assertTrue(entry["sim"])
            self.assertFalse(entry["core"])
            expected_count = 2 if rule == "恶意软件规则" else 1
            self.assertEqual(entry["result"], ["%{threat_name}"] * expected_count)
            self.assertEqual(
                entry["mappings"],
                [
                    {"mappingType": "REGULAR", "orgValue": ".*挖矿.*", "mappingValue": "挖矿木马"},
                    {"mappingType": "EQUAL", "orgValue": "勒索病毒Locky", "mappingValue": "勒索病毒"},
                ],
            )
            bindings = [
                f
                for f in by_name[rule]["parser"]["filter"]
                if f.get("name") == "addFields" and "威胁类型" in f.get("fields", {})
            ]
            self.assertEqual(len(bindings), 1)
            self.assertEqual(bindings[0]["fields"]["威胁类型"], "%{threat_name}")

        # 非威胁子规则不写
        self.assertFalse(
            any(e["index"] == "威胁类型" for e in by_name["登录规则"]["normalize"])
        )
        # Base64 导出可回解
        export = Path(payload["export"])
        self.assertIn("threatmapping_config_", export.name)
        decoded = decode_config_text(export.read_text(encoding="utf-8"))
        self.assertEqual(len(decoded), 3)

    def test_chain_state_rebuilds(self):
        entities = self._base_config()
        old_pair = {"mappingType": "EQUAL", "orgValue": "旧值", "mappingValue": "其他"}
        entities[0]["normalize"].append(threat_entry([old_pair], sample_count=2))
        entities[0]["parser"]["filter"].append(
            make_addfields({"威胁类型": "%{threat_name}", "备注": "keep"})
        )
        code, payload = self._run(
            "--input", str(self._config(entities)),
            "--worklist", str(self._base_worklist()),
            "--judgments", str(self._base_judgments()),
        )
        self.assertEqual(code, 0)
        result = json.loads(Path(payload["output"]).read_text(encoding="utf-8"))
        rule = {e["name"]: e for e in result}["恶意软件规则"]
        entries = [e for e in rule["normalize"] if e["index"] == "威胁类型"]
        self.assertEqual(len(entries), 1)  # 旧条目被替换，不双写
        org_values = [m["orgValue"] for m in entries[0]["mappings"]]
        self.assertNotIn("旧值", org_values)
        self.assertIn(".*挖矿.*", org_values)
        # 唯一新绑定；无关绑定保留
        threat_bindings = [
            f for f in rule["parser"]["filter"]
            if f.get("name") == "addFields" and "威胁类型" in f.get("fields", {})
        ]
        self.assertEqual(len(threat_bindings), 1)
        kept = [f for f in rule["parser"]["filter"] if "备注" in f.get("fields", {})]
        self.assertEqual(len(kept), 1)

    def test_existing_state_merges_and_unbinds_fixed(self):
        entities = self._base_config()
        user_pair = {"mappingType": "EQUAL", "orgValue": "手工值", "mappingValue": "弱口令"}
        entities[0]["normalize"].append(
            make_entry("威胁类型", field=None, mappings=[user_pair], result=["固定值"])
        )
        entities[0]["parser"]["filter"].append(
            make_addfields({"威胁类型": "固定值"})
        )
        code, payload = self._run(
            "--input", str(self._config(entities)),
            "--worklist", str(self._base_worklist()),
            "--judgments", str(self._base_judgments()),
        )
        self.assertEqual(code, 0)
        result = json.loads(Path(payload["output"]).read_text(encoding="utf-8"))
        rule = {e["name"]: e for e in result}["恶意软件规则"]
        entries = [e for e in rule["normalize"] if e["index"] == "威胁类型"]
        self.assertEqual(len(entries), 1)
        org_values = [m["orgValue"] for m in entries[0]["mappings"]]
        # 既有映射保留（orgValue 合并），新映射追加
        self.assertIn("手工值", org_values)
        self.assertIn(".*挖矿.*", org_values)
        # result 原状保留（existing 不改条目外层）
        self.assertEqual(entries[0]["result"], ["固定值"])
        # 固定值绑定被解绑
        bindings = [
            f for f in rule["parser"]["filter"]
            if f.get("name") == "addFields" and "威胁类型" in f.get("fields", {})
        ]
        self.assertEqual(bindings, [])
        group_report = payload["groups"][0]
        self.assertEqual(group_report["rules"][0]["state"], "existing")
        self.assertEqual(group_report["rules"][0]["unbound"], 1)

    def test_existing_state_rerun_is_idempotent(self):
        entities = self._base_config()
        for index in (0, 1):
            entities[index]["normalize"].append(
                make_entry("威胁类型", mappings=[
                    {"mappingType": "REGULAR", "orgValue": ".*挖矿.*", "mappingValue": "挖矿木马"},
                    {"mappingType": "EQUAL", "orgValue": "勒索病毒Locky", "mappingValue": "勒索病毒"},
                ])
            )
        code, payload = self._run(
            "--input", str(self._config(entities)),
            "--worklist", str(self._base_worklist()),
            "--judgments", str(self._base_judgments()),
        )
        self.assertEqual(code, 0)
        self.assertIn("无变更", payload["message"])

    def test_chain_rerun_produces_identical_output(self):
        """链路自产重跑＝整体替换：内容幂等（产物逐字等同），报告如实记重建。"""
        first_config = self._config(self._base_config(), name="config.json")
        code1, payload1 = self._run(
            "--input", str(first_config),
            "--worklist", str(self._base_worklist()),
            "--judgments", str(self._base_judgments()),
        )
        self.assertEqual(code1, 0)
        out1 = Path(payload1["output"])
        code2, payload2 = self._run(
            "--input", str(out1),
            "--worklist", str(self._base_worklist()),
            "--judgments", str(self._base_judgments()),
        )
        self.assertEqual(code2, 0)
        out2 = Path(payload2["output"])
        self.assertEqual(
            json.loads(out1.read_text(encoding="utf-8")),
            json.loads(out2.read_text(encoding="utf-8")),
        )
        self.assertIn("整体重建", payload2["message"])

    def test_heterogeneous_groups_write_own_pairs(self):
        """异构场景（Q3 归组裁决）：A 规则源=threat_name，B 规则源=threat_info。"""
        entities = [
            make_entity(
                "恶意软件规则", entries=[make_entry("threat_name")],
                event_name="病毒检测", sample_result=["s1"],
            ),
            make_entity(
                "Web攻击规则", entries=[make_entry("threat_info")],
                event_name="网络攻击", sample_result=["s1"],
            ),
        ]
        worklist = make_workload(
            self._tmp / "wl.json",
            ["恶意软件规则", "Web攻击规则"],
            [
                ("threat_name", {"挖矿行为": 1}),
                ("threat_info", {"Webshell上传": 1}),
            ],
        )
        judgments = make_judgment_file(
            self._tmp / "jd.json",
            [
                {
                    "source_field": "threat_name",
                    "rules": ["恶意软件规则"],
                    "pairs": [pair("挖矿", "挖矿木马")],
                },
                {
                    "source_field": "threat_info",
                    "rules": ["Web攻击规则"],
                    "pairs": [pair("Webshell", "Webshell")],
                },
            ],
        )
        code, payload = self._run(
            "--input", str(self._config(entities)),
            "--worklist", str(worklist),
            "--judgments", str(judgments),
        )
        self.assertEqual(code, 0)
        result = json.loads(Path(payload["output"]).read_text(encoding="utf-8"))
        by_name = {e["name"]: e for e in result}
        a_entry = next(e for e in by_name["恶意软件规则"]["normalize"] if e["index"] == "威胁类型")
        b_entry = next(e for e in by_name["Web攻击规则"]["normalize"] if e["index"] == "威胁类型")
        self.assertEqual(a_entry["result"], ["%{threat_name}"])
        self.assertEqual(b_entry["result"], ["%{threat_info}"])
        self.assertEqual([m["orgValue"] for m in a_entry["mappings"]], [".*挖矿.*"])
        self.assertEqual([m["orgValue"] for m in b_entry["mappings"]], [".*Webshell.*"])

    def test_skipped_rules_allowed(self):
        entities = self._base_config() + [
            make_entity("无源规则", entries=[make_entry("only_field")], event_name="其他告警"),
        ]
        worklist = make_workload(
            self._tmp / "wl.json",
            ["恶意软件规则", "Web攻击规则", "无源规则"],
            [("threat_name", {"挖矿行为": 2, "勒索病毒Locky": 1}), ("only_field", {})],
        )
        judgments = make_judgment_file(
            self._tmp / "jd.json",
            [
                {
                    "source_field": "threat_name",
                    "rules": ["恶意软件规则", "Web攻击规则"],
                    "pairs": [pair("挖矿", "挖矿木马"), pair("勒索病毒Locky", "勒索病毒", "EQUAL")],
                }
            ],
            skipped_rules=["无源规则"],
        )
        code, payload = self._run(
            "--input", str(self._config(entities)),
            "--worklist", str(worklist),
            "--judgments", str(judgments),
        )
        self.assertEqual(code, 0)
        self.assertEqual(payload["skipped_rules"], ["无源规则"])
        result = json.loads(Path(payload["output"]).read_text(encoding="utf-8"))
        skipped = {e["name"]: e for e in result}["无源规则"]
        self.assertFalse(any(e["index"] == "威胁类型" for e in skipped["normalize"]))

    def test_cross_group_inconsistent_mapping_rejected(self):
        """跨组同值归类一致（Q3 裁决）：同一值在两组映射到不同威胁类型 → 整单拒绝。"""
        entities = [
            make_entity(
                "恶意软件规则", entries=[make_entry("threat_name")],
                event_name="病毒检测", sample_result=["s1"],
            ),
            make_entity(
                "Web攻击规则", entries=[make_entry("threat_info")],
                event_name="网络攻击", sample_result=["s1"],
            ),
        ]
        worklist = make_workload(
            self._tmp / "wl.json",
            ["恶意软件规则", "Web攻击规则"],
            [
                ("threat_name", {"挖矿行为": 1}),
                ("threat_info", {"挖矿行为": 1, "Webshell上传": 1}),
            ],
        )
        judgments = make_judgment_file(
            self._tmp / "jd.json",
            [
                {
                    "source_field": "threat_name",
                    "rules": ["恶意软件规则"],
                    "pairs": [pair("挖矿", "挖矿木马")],
                },
                {
                    "source_field": "threat_info",
                    "rules": ["Web攻击规则"],
                    "pairs": [pair("挖矿", "勒索病毒"), pair("Webshell", "Webshell")],
                },
            ],
        )
        code, payload = self._run(
            "--input", str(self._config(entities)),
            "--worklist", str(worklist),
            "--judgments", str(judgments),
        )
        self.assertEqual(code, 1)
        self.assertEqual(payload["code"], "invalid_input")
        self.assertIn("value_mapped_inconsistently", payload["message"])
        self.assertIn("挖矿行为", payload["message"])

    def test_cross_group_consistent_mapping_passes(self):
        entities = [
            make_entity(
                "恶意软件规则", entries=[make_entry("threat_name")],
                event_name="病毒检测", sample_result=["s1"],
            ),
            make_entity(
                "Web攻击规则", entries=[make_entry("threat_info")],
                event_name="网络攻击", sample_result=["s1"],
            ),
        ]
        worklist = make_workload(
            self._tmp / "wl.json",
            ["恶意软件规则", "Web攻击规则"],
            [
                ("threat_name", {"挖矿行为": 1}),
                ("threat_info", {"挖矿行为": 1, "Webshell上传": 1}),
            ],
        )
        judgments = make_judgment_file(
            self._tmp / "jd.json",
            [
                {
                    "source_field": "threat_name",
                    "rules": ["恶意软件规则"],
                    "pairs": [pair("挖矿", "挖矿木马")],
                },
                {
                    "source_field": "threat_info",
                    "rules": ["Web攻击规则"],
                    "pairs": [pair("挖矿", "挖矿木马"), pair("Webshell", "Webshell")],
                },
            ],
        )
        code, payload = self._run(
            "--input", str(self._config(entities)),
            "--worklist", str(worklist),
            "--judgments", str(judgments),
        )
        self.assertEqual(code, 0)
        result = json.loads(Path(payload["output"]).read_text(encoding="utf-8"))
        by_name = {e["name"]: e for e in result}
        for rule, field in (("恶意软件规则", "threat_name"), ("Web攻击规则", "threat_info")):
            entry = next(
                e for e in by_name[rule]["normalize"] if e["index"] == "威胁类型"
            )
            self.assertIn("挖矿木马", [m["mappingValue"] for m in entry["mappings"]])

    # -- 守卫链 -------------------------------------------------------------

    def test_group_assignment_unassigned_rejected(self):
        judgments = make_judgment_file(
            self._tmp / "jd.json",
            [{"source_field": "threat_name", "rules": ["恶意软件规则"],
              "pairs": [pair("挖矿", "挖矿木马")]}],
        )
        code, payload = self._run(
            "--input", str(self._config(self._base_config())),
            "--worklist", str(self._base_worklist()),
            "--judgments", str(judgments),
        )
        self.assertEqual(code, 1)
        self.assertEqual(payload["code"], "invalid_input")
        self.assertIn("rule_unassigned", payload["message"])
        self.assertIn("Web攻击规则", payload["message"])

    def test_source_field_not_in_worklist_rejected(self):
        judgments = make_judgment_file(
            self._tmp / "jd.json",
            [{"source_field": "不存在字段", "rules": ["恶意软件规则", "Web攻击规则"],
              "pairs": [pair("挖矿", "挖矿木马")]}],
        )
        code, payload = self._run(
            "--input", str(self._config(self._base_config())),
            "--worklist", str(self._base_worklist()),
            "--judgments", str(judgments),
        )
        self.assertEqual(code, 1)
        self.assertEqual(payload["code"], "invalid_input")
        self.assertIn("不在工作单候选", payload["message"])

    def test_source_field_not_in_rule_pool_rejected(self):
        entities = self._base_config()
        entities[1]["normalize"] = [make_entry("threat_info")]  # Web攻击规则无 threat_name
        worklist = make_workload(
            self._tmp / "wl.json",
            ["恶意软件规则", "Web攻击规则"],
            [("threat_name", {"挖矿行为": 2, "勒索病毒Locky": 1}), ("threat_info", {"x": 1})],
        )
        judgments = make_judgment_file(
            self._tmp / "jd.json",
            [{"source_field": "threat_name",
              "rules": ["恶意软件规则", "Web攻击规则"],
              "pairs": [pair("挖矿", "挖矿木马"), pair("勒索病毒Locky", "勒索病毒", "EQUAL")]}],
        )
        code, payload = self._run(
            "--input", str(self._config(entities)),
            "--worklist", str(worklist),
            "--judgments", str(judgments),
        )
        self.assertEqual(code, 1)
        self.assertEqual(payload["code"], "invalid_input")
        self.assertIn("字段池", payload["message"])

    def test_coverage_out_of_enum_rejected(self):
        judgments = make_judgment_file(
            self._tmp / "jd.json",
            [{"source_field": "threat_name", "rules": ["恶意软件规则", "Web攻击规则"],
              "pairs": [pair("挖矿", "网络入侵"), pair("勒索病毒Locky", "勒索病毒", "EQUAL")]}],
        )
        code, payload = self._run(
            "--input", str(self._config(self._base_config())),
            "--worklist", str(self._base_worklist()),
            "--judgments", str(judgments),
        )
        self.assertEqual(code, 1)
        self.assertEqual(payload["code"], "threat_mapping_coverage_rejected")
        self.assertIn("mapping_value_out_of_enum", payload["message"])
        self.assertIn("网络入侵", payload["message"])

    def test_coverage_uncovered_rejected(self):
        judgments = make_judgment_file(
            self._tmp / "jd.json",
            [{"source_field": "threat_name", "rules": ["恶意软件规则", "Web攻击规则"],
              "pairs": [pair("挖矿", "挖矿木马")]}],
        )
        code, payload = self._run(
            "--input", str(self._config(self._base_config())),
            "--worklist", str(self._base_worklist()),
            "--judgments", str(judgments),
        )
        self.assertEqual(code, 1)
        self.assertEqual(payload["code"], "threat_mapping_coverage_rejected")
        self.assertIn("declared_input_uncovered", payload["message"])
        self.assertIn("勒索病毒Locky", payload["message"])

    def test_coverage_multi_matched_rejected(self):
        worklist = make_workload(
            self._tmp / "wl.json",
            ["恶意软件规则", "Web攻击规则"],
            [("threat_name", {"端口扫描": 1}), ("sev_code", {})],
        )
        judgments = make_judgment_file(
            self._tmp / "jd.json",
            [{"source_field": "threat_name", "rules": ["恶意软件规则", "Web攻击规则"],
              "pairs": [pair("端口", "端口扫描"), pair("扫描", "服务扫描")]}],
        )
        code, payload = self._run(
            "--input", str(self._config(self._base_config())),
            "--worklist", str(worklist),
            "--judgments", str(judgments),
        )
        self.assertEqual(code, 1)
        self.assertEqual(payload["code"], "threat_mapping_coverage_rejected")
        self.assertIn("declared_input_multi_matched", payload["message"])

    def test_coverage_row_out_of_source_rejected(self):
        judgments = make_judgment_file(
            self._tmp / "jd.json",
            [{"source_field": "threat_name", "rules": ["恶意软件规则", "Web攻击规则"],
              "pairs": [pair("挖矿", "挖矿木马"), pair("勒索病毒Locky", "勒索病毒", "EQUAL"),
                        pair("多余", "其他")]}],
        )
        code, payload = self._run(
            "--input", str(self._config(self._base_config())),
            "--worklist", str(self._base_worklist()),
            "--judgments", str(judgments),
        )
        self.assertEqual(code, 1)
        self.assertEqual(payload["code"], "threat_mapping_coverage_rejected")
        self.assertIn("row_out_of_source", payload["message"])
        self.assertIn("多余", payload["message"])

    def test_all_code_only_source_rejected(self):
        entities = self._base_config()
        entities[1]["normalize"].append(make_entry("sev_code"))  # 两组都有 sev_code
        worklist = make_workload(
            self._tmp / "wl.json",
            ["恶意软件规则", "Web攻击规则"],
            [("threat_name", {"挖矿行为": 2}), ("sev_code", {"1": 2, "2": 1})],
        )
        judgments = make_judgment_file(
            self._tmp / "jd.json",
            [{"source_field": "sev_code", "rules": ["恶意软件规则", "Web攻击规则"],
              "pairs": [pair("1", "其他", "EQUAL"), pair("2", "其他", "EQUAL")]}],
        )
        code, payload = self._run(
            "--input", str(self._config(entities)),
            "--worklist", str(worklist),
            "--judgments", str(judgments),
        )
        self.assertEqual(code, 1)
        self.assertEqual(payload["code"], "threat_mapping_source_context_required")
        self.assertIn("无语义数字代码", payload["message"])

    def test_worklist_config_mismatch_rejected(self):
        worklist = make_workload(
            self._tmp / "wl.json",
            ["别的规则"],
            [("threat_name", {"挖矿行为": 1})],
        )
        code, payload = self._run(
            "--input", str(self._config(self._base_config())),
            "--worklist", str(worklist),
            "--judgments", str(self._base_judgments()),
        )
        self.assertEqual(code, 1)
        self.assertEqual(payload["code"], "invalid_input")
        self.assertIn("不一致", payload["message"])

    def test_missing_judgments_file_rejected(self):
        code, payload = self._run(
            "--input", str(self._config(self._base_config())),
            "--worklist", str(self._base_worklist()),
            "--judgments", str(self._tmp / "不存在.json"),
        )
        self.assertEqual(code, 1)
        self.assertEqual(payload["code"], "invalid_input")
        self.assertIn("找不到分组判定文件", payload["message"])

    def test_empty_groups_rejected(self):
        judgments = make_judgment_file(self._tmp / "jd.json", [])
        code, payload = self._run(
            "--input", str(self._config(self._base_config())),
            "--worklist", str(self._base_worklist()),
            "--judgments", str(judgments),
        )
        self.assertEqual(code, 1)
        self.assertEqual(payload["code"], "invalid_input")

    def test_no_annotation_rejected(self):
        config = self._config([make_entity("规则A", [make_entry("x")])])
        code, payload = self._run(
            "--input", str(config),
            "--worklist", str(self._base_worklist()),
            "--judgments", str(self._base_judgments()),
        )
        self.assertEqual(code, 1)
        self.assertEqual(payload["code"], "event_annotation_required")


if __name__ == "__main__":
    unittest.main()
