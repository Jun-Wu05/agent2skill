"""default_output_path 缺省产物命名帮手（report.py 收口 #18）。

单一事实源：DEFAULT_OUTPUT_SUFFIXES 总表 + default_output_path 拼装。
既有产物名一字不变；未知语义键拒绝。
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILLS = ROOT / "skills" / "parser-skills"
for path in (str(ROOT), str(SKILLS)):
    if path not in sys.path:
        sys.path.insert(0, path)

import pytest  # noqa: E402

from _shared.report import (  # noqa: E402
    DEFAULT_OUTPUT_SUFFIXES,
    default_output_path,
)


class TestDefaultOutputPath:
    def test_normal_stem(self):
        path = default_output_path(Path("testdata/天擎.json"), "classified")
        assert path == Path("testdata/天擎_classified.json")

    def test_stem_keeps_inner_dots(self):
        # stem 含点号原样保留：sample_config.base64 → sample_config.base64_modified
        path = default_output_path(Path("in/sample_config.base64.json"), "modified")
        assert path == Path("in/sample_config.base64_modified.json")

    def test_base_override(self):
        # mapping_finalize 白板路径：基名由脚本算好传入（剥 _subrules）
        path = default_output_path(
            Path("out/天擎_subrules.json"), "mapped_subrules", base="天擎"
        )
        assert path == Path("out/天擎_mapped_subrules.json")

    def test_unknown_kind_rejected(self):
        with pytest.raises(ValueError):
            default_output_path(Path("x.json"), "no_such_kind")

    def test_catalog_covers_all_call_sites(self):
        expected = {
            "modified", "adjusted", "candidates", "mapped_subrules",
            "entry_rules", "mapped_config", "classified", "subrules",
            "stats", "enum_values", "enumfilled", "enumunmapped",
            "threat_worklist", "threatfilled",
        }
        assert expected == set(DEFAULT_OUTPUT_SUFFIXES)
