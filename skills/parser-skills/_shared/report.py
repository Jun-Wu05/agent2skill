"""统一结果输出：修改后配置 JSON + 平台可导入的 Base64 导出文件。

导出文件名遵循下载命名契约：前缀/扩展名/时间戳格式（%Y%m%d_%H%M）为
跨入口兼容接口，不得漂移。每个修改类技能运行后即通过 write_result 产出
这两个文件（修改后 JSON 供技能间衔接，Base64 供平台导入）。
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from _shared.config_io import encode_config_b64, save_entities

DOWNLOAD_NAME_TEMPLATES: dict[str, str] = {
    # 产物类型 → 文件名模板（{timestamp} 占位），随增量扩充
    "current_config": "current_config_{timestamp}.txt",
    "field_adjusted_config": "fieldadjusted_config_{timestamp}.txt",
    "unmappedconfig_subrules": "unmappedconfig_subrules_{timestamp}.txt",
    "mappedconfig_subrules": "mappedconfig_subrules_{timestamp}.txt",
    "mappedconfig_mainrules": "mappedconfig_mainrules_{timestamp}.txt",
    "fieldmapped_config": "fieldmapped_config_{timestamp}.txt",
    "enummapping_config": "enummapping_config_{timestamp}.txt",
    "enumvalues_table": "enumvalues_{timestamp}.xlsx",
    "threatmapping_config": "threatmapping_config_{timestamp}.txt",
    "mappingadjusted_config": "mappingadjusted_config_{timestamp}.txt",
}

_TIMESTAMP_FORMAT = "%Y%m%d_%H%M"

# 缺省产物后缀总表：语义键 → 文件名后缀（含 .json）。
# 各脚本缺省产物路径与 argparse help 文本一律从这张表取值，
# 改名只改此处一行（对齐 DOWNLOAD_NAME_TEMPLATES 的收口先例）。
DEFAULT_OUTPUT_SUFFIXES: dict[str, str] = {
    "modified": "_modified.json",               # field-adjust 五子命令（cli.py）
    "adjusted": "_adjusted.json",               # field-mapping 手动调整
    "candidates": "_candidates.json",           # field-mapping 候选开单
    "mapped_subrules": "_mapped_subrules.json", # field-mapping 收口（白板路径）
    "entry_rules": "_entry_rules.json",         # field-mapping 收口（入口规则）
    "mapped_config": "_mapped_config.json",     # field-mapping 收口（配置路径）
    "classified": "_classified.json",           # log-classification 收口
    "subrules": "_subrules.json",               # log-classification 收口（白板子规则）
    "stats": "_stats.json",                     # log-classification 统计
    "enum_values": "_enum_values.json",         # enum-mapping 提取
    "enumfilled": "_enumfilled.json",           # enum-mapping 填充
    "enumunmapped": "_enumunmapped.json",       # enum-mapping 取消映射
    "threat_worklist": "_threat_worklist.json", # threat-type 工作单
    "threatfilled": "_threatfilled.json",       # threat-type 收口
}


def default_output_path(
    input_path: str | Path, kind: str, *, base: str | None = None
) -> Path:
    """按语义键拼装缺省产物路径：<输入同目录>/<基名><后缀>。

    kind 从 DEFAULT_OUTPUT_SUFFIXES 取后缀，未知键抛 ValueError；
    base 缺省取输入文件 stem（含内部点号），脚本可传自己算好的基名
    （如 mapping_finalize 白板路径剥掉 _subrules 后的基名）。
    """
    suffix = DEFAULT_OUTPUT_SUFFIXES.get(kind)
    if suffix is None:
        raise ValueError(f"不支持的缺省产物类型: {kind}")
    base_stem = input_path.stem if base is None else base
    return Path(input_path).with_name(base_stem + suffix)



def print_error(code: str, message: str) -> int:
    """打印稳定错误码 JSON 到 stdout，返回失败退出码 1。"""
    print(
        json.dumps(
            {"status": "error", "code": code, "message": message},
            ensure_ascii=False,
            indent=2,
        )
    )
    return 1


def download_filename(kind: str, timestamp: str | None = None) -> str:
    """按产物语义生成导出文件名；未知类型抛 ValueError。"""
    template = DOWNLOAD_NAME_TEMPLATES.get(kind)
    if template is None:
        raise ValueError(f"不支持的下载产物类型: {kind}")
    if timestamp is None:
        timestamp = datetime.now().strftime(_TIMESTAMP_FORMAT)
    return template.format(timestamp=timestamp)


def write_result(
    entities: list,
    output: str | Path,
    export_path: str | Path | None = None,
    kind: str = "field_adjusted_config",
    make_export: bool = True,
) -> dict:
    """写出修改后配置 JSON 与 Base64 导出文件，返回两个落盘路径。

    output     : 修改后配置 JSON（技能间文件衔接的产物形态）。
    export_path: 平台可导入的 Base64 文件；缺省写到 output 同目录，文件名
                 按下载命名契约（如 fieldadjusted_config_20261117_0830.txt）。
    """
    json_path = save_entities(entities, output)
    export_written: Path | None = None
    if make_export:
        export_target = (
            Path(export_path)
            if export_path is not None
            else json_path.parent / download_filename(kind)
        )
        export_target.parent.mkdir(parents=True, exist_ok=True)
        export_target.write_text(encode_config_b64(entities) + "\n", encoding="utf-8")
        export_written = export_target
    return {"json_path": json_path, "export_path": export_written}
