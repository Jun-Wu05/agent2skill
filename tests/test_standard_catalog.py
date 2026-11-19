"""standard_catalog 单元测试：标准字段目录的加载、索引与确定性查找。

接缝：_shared.standard_catalog 的公开 API——normalize_field_name /
compact_field_name / StandardField / StandardFieldCatalog（from_resources、
lookup、name_index）/ load_catalog / default_assets_dir /
MAPPING_EXCLUDED_STANDARD_FIELDS / 枚举字段短路（enum_auto_mapping_policies、
resolve_enum_field）。断言字面量取自仓库根 assets/ 真实资产与合成夹具。
"""

from __future__ import annotations

import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for path in (str(ROOT), str(ROOT / "skills" / "parser-skills")):
    if path not in sys.path:
        sys.path.insert(0, path)

from _shared import standard_catalog  # noqa: E402

HEADER_LINE = "系统属性名称\t属性分类\t字段名称\t属性类型\t描述\t枚举值\t对象"


def _write_assets(
    directory: Path,
    tsv_text: str,
    synonyms_text: str = "{}",
    tags_text: str = '{"rules": {}}',
    tsv_encoding: str = "utf-8",
) -> tuple[Path, Path, Path]:
    """在临时目录合成一套三件资产，返回三个文件路径。"""
    tsv_path = directory / "标准字段.txt"
    tsv_path.write_text(tsv_text, encoding=tsv_encoding)
    synonyms_path = directory / "field_synonyms.json"
    synonyms_path.write_text(synonyms_text, encoding="utf-8")
    tags_path = directory / "tag_rules.json"
    tags_path.write_text(tags_text, encoding="utf-8")
    return tsv_path, synonyms_path, tags_path


class DefaultAssetsDirTest(unittest.TestCase):
    def test_default_assets_dir_contains_standard_fields(self):
        assets_dir = standard_catalog.default_assets_dir()
        self.assertTrue((assets_dir / "标准字段.txt").is_file())
        self.assertTrue((assets_dir / "field_synonyms.json").is_file())
        self.assertTrue((assets_dir / "tag_rules.json").is_file())


class LoadCatalogTest(unittest.TestCase):
    def setUp(self):
        self.catalog = standard_catalog.load_catalog()

    def test_load_catalog_returns_625_fields(self):
        self.assertEqual(len(self.catalog.fields), 625)

    def test_first_row_shape(self):
        first = self.catalog.fields[0]
        self.assertEqual(first.system_property_name, "AptGUID")
        self.assertEqual(first.category, "基础属性")
        self.assertEqual(first.field_name, "apt_GUID")
        self.assertEqual(first.data_type, "字符")
        self.assertEqual(first.description, "apt组织唯一标识特征")
        self.assertEqual(first.enum_values, "")
        self.assertEqual(first.objects, "APT")

    def test_real_row_shape(self):
        row = next(
            f for f in self.catalog.fields if f.system_property_name == "源地址"
        )
        self.assertEqual(row.field_name, "src_address")
        self.assertEqual(row.data_type, "IP")
        self.assertEqual(row.objects, "流量,登录")

    def test_as_record_uses_historical_columns(self):
        record = self.catalog.fields[0].as_record()
        self.assertEqual(
            sorted(record),
            sorted(standard_catalog.STANDARD_FIELD_COLUMNS),
        )
        self.assertEqual(record["系统属性名称"], "AptGUID")
        self.assertEqual(record["字段名称"], "apt_GUID")


class ParseStandardFieldsTest(unittest.TestCase):
    def setUp(self):
        self._tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self._tmp, ignore_errors=True)

    def test_header_mismatch_raises(self):
        tsv_path, synonyms_path, tags_path = _write_assets(
            self._tmp, "列一\t列二\t列三\na\tb\tc"
        )
        with self.assertRaises(ValueError):
            standard_catalog.StandardFieldCatalog.from_resources(
                tsv_path, synonyms_path, tags_path
            )

    def test_short_row_padded_with_empty_strings(self):
        tsv = HEADER_LINE + "\n短字段\t基础属性\tshort\t字符"
        tsv_path, synonyms_path, tags_path = _write_assets(self._tmp, tsv)
        catalog = standard_catalog.StandardFieldCatalog.from_resources(
            tsv_path, synonyms_path, tags_path
        )
        row = catalog.fields[0]
        self.assertEqual(row.data_type, "字符")
        self.assertEqual(row.description, "")
        self.assertEqual(row.enum_values, "")
        self.assertEqual(row.objects, "")

    def test_bom_in_header_tolerated(self):
        tsv = HEADER_LINE + "\n字段A\t基础属性\ta_field\t字符\t\t\t"
        tsv_path, synonyms_path, tags_path = _write_assets(
            self._tmp, tsv, tsv_encoding="utf-8-sig"
        )
        catalog = standard_catalog.StandardFieldCatalog.from_resources(
            tsv_path, synonyms_path, tags_path
        )
        self.assertEqual(len(catalog.fields), 1)
        self.assertEqual(catalog.fields[0].system_property_name, "字段A")

    def test_missing_synonyms_file_tolerated_as_empty(self):
        tsv = HEADER_LINE + "\n字段A\t基础属性\ta_field\t字符\t\t\t"
        tsv_path, _, tags_path = _write_assets(
            self._tmp, tsv, tags_text='{"rules": {}}'
        )
        (self._tmp / "field_synonyms.json").unlink()
        catalog = standard_catalog.StandardFieldCatalog.from_resources(
            tsv_path, self._tmp / "field_synonyms.json", tags_path
        )
        self.assertEqual(dict(catalog.synonyms), {})


class NameKeyTest(unittest.TestCase):
    def test_normalize_field_name(self):
        self.assertEqual(
            standard_catalog.normalize_field_name("srcAddress"), "src_address"
        )
        self.assertEqual(
            standard_catalog.normalize_field_name("src-address"), "src_address"
        )
        self.assertEqual(
            standard_catalog.normalize_field_name("HTTPServerName"),
            "http_server_name",
        )
        self.assertEqual(standard_catalog.normalize_field_name("a_b"), "a_b")

    def test_compact_field_name(self):
        self.assertEqual(standard_catalog.compact_field_name("src_address"), "srcaddress")
        self.assertEqual(standard_catalog.compact_field_name("SRC-Address"), "srcaddress")
        self.assertEqual(standard_catalog.compact_field_name("a b"), "ab")


class LookupTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog = standard_catalog.load_catalog()

    def test_lookup_by_system_property_name(self):
        hit = self.catalog.lookup("源地址")
        self.assertIsNotNone(hit)
        self.assertEqual(hit.field_name, "src_address")

    def test_lookup_by_field_name(self):
        hit = self.catalog.lookup("event_name")
        self.assertIsNotNone(hit)
        self.assertEqual(hit.system_property_name, "事件名称")

    def test_lookup_by_normalized_alias(self):
        hit = self.catalog.lookup("EventName")
        self.assertIsNotNone(hit)
        self.assertEqual(hit.system_property_name, "事件名称")

    def test_lookup_by_compact_alias(self):
        hit = self.catalog.lookup("eventname")
        self.assertIsNotNone(hit)
        self.assertEqual(hit.system_property_name, "事件名称")

    def test_lookup_by_zh_alias(self):
        # field_synonyms 键 result 恰为某行字段名称，其 zh 别名「结果」注册指向该行
        hit = self.catalog.lookup("结果")
        self.assertIsNotNone(hit)
        self.assertEqual(hit.system_property_name, "事件结果")

    def test_lookup_miss_returns_none(self):
        self.assertIsNone(self.catalog.lookup("不存在的字段XYZ"))

    def test_lookup_first_wins_on_duplicate_keys(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        tsv = (
            HEADER_LINE
            + "\n字段A\t基础属性\tdup\t字符\tfirst\t\t"
            + "\n字段B\t基础属性\tdup\t字符\tsecond\t\t"
        )
        tsv_path, synonyms_path, tags_path = _write_assets(tmp, tsv)
        catalog = standard_catalog.StandardFieldCatalog.from_resources(
            tsv_path, synonyms_path, tags_path
        )
        hit = catalog.lookup("dup")
        self.assertIsNotNone(hit)
        self.assertEqual(hit.description, "first")


class MappingExcludedTest(unittest.TestCase):
    def test_blacklist_contains_four_fields(self):
        self.assertEqual(
            set(standard_catalog.MAPPING_EXCLUDED_STANDARD_FIELDS),
            {"事件名称", "事件级别", "日志类型", "威胁类型"},
        )

    def test_blacklist_names_resolve_in_catalog(self):
        # 黑名单成员本身是目录内合法字段：目录解析通过 ≠ 允许映射，收口必须另查黑名单
        catalog = standard_catalog.load_catalog()
        for name in standard_catalog.MAPPING_EXCLUDED_STANDARD_FIELDS:
            self.assertIsNotNone(catalog.lookup(name), name)


class EnumShortCircuitTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog = standard_catalog.load_catalog()

    def test_policies_resolve_eight_targets(self):
        policies = standard_catalog.enum_auto_mapping_policies(self.catalog)
        self.assertEqual(len(policies), 8)
        http = policies["HTTP请求方法"]
        self.assertEqual(http.field_name, "http_method")
        self.assertEqual(http.default_value, "其他")
        self.assertEqual(http.whitelist[0], "CONNECT")
        self.assertIn("TRACE", http.whitelist)
        os_policy = policies["操作系统平台"]
        self.assertEqual(os_policy.field_name, "os")

    def test_resolve_enum_field_exact(self):
        self.assertEqual(
            standard_catalog.resolve_enum_field("http_method", self.catalog),
            ("HTTP请求方法", "exact"),
        )
        self.assertEqual(
            standard_catalog.resolve_enum_field("os", self.catalog),
            ("操作系统平台", "exact"),
        )

    def test_resolve_enum_field_synonym(self):
        # 「结果」经 zh 别名命中「事件结果」，但与目标英文名不同源 → synonym
        self.assertEqual(
            standard_catalog.resolve_enum_field("结果", self.catalog),
            ("事件结果", "synonym"),
        )

    def test_resolve_enum_field_miss_returns_none(self):
        # 目录内命中但非枚举目标 → None（继续走候选检索主路径）
        self.assertIsNone(
            standard_catalog.resolve_enum_field("src_address", self.catalog)
        )
        self.assertIsNone(
            standard_catalog.resolve_enum_field("不存在的字段XYZ", self.catalog)
        )

    def test_policies_raise_when_target_missing(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        tsv = HEADER_LINE + "\n字段A\t基础属性\ta_field\t字符\t\t\t"
        tsv_path, synonyms_path, tags_path = _write_assets(tmp, tsv)
        catalog = standard_catalog.StandardFieldCatalog.from_resources(
            tsv_path, synonyms_path, tags_path
        )
        with self.assertRaises(ValueError):
            standard_catalog.enum_auto_mapping_policies(catalog)


class TagRulesTest(unittest.TestCase):
    def test_tag_rules_unwrapped_from_rules_key(self):
        catalog = standard_catalog.load_catalog()
        rules = catalog.tag_rules
        self.assertEqual(len(rules), 22)
        self.assertIn("source", rules)
        self.assertEqual(tuple(rules["source"]), ("src", "source", "sip"))


if __name__ == "__main__":
    unittest.main()
