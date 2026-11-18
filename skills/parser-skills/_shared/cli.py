"""field-adjust 子命令 CLI 骨架（文件契约 main() 的单一事实源）。

五个子命令脚本 main() 的同形部分收口于此：公共参数追加（--input /
--output / --target / --group / --no-export）、配置加载与 ConfigIOError
报告、target 逗号解析与空名单拒绝（用户 2026-11-18 裁决：解析后空名单
整单拒绝，不再静默全量）、守卫结果打印退出 1、write_result 落盘与
成功 payload。各子命令通过 CliSpec 声明差异（prog / 描述 / 专属参数
表 / 适配器 / 是否带 --group）；守卫链本体留在各子命令脚本，本模块
不涉足领域规则。子模块脚本共用本模块，禁止复制。
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, List, Optional, Tuple

from _shared import report as skill_report
from _shared.config_io import ConfigIOError, load_entities

# 适配器签名：(解析后的参数, 加载后的 entities, target 名单) -> 守卫结果
Execute = Callable[[argparse.Namespace, list, Optional[List[str]]], dict]

# 专属参数表条目：(flags 元组, argparse 其余 kwargs)
Argument = Tuple[Tuple[str, ...], dict]


@dataclass(frozen=True, slots=True)
class CliSpec:
    """子命令差异声明：骨架之外的一切。

    arguments 里的专属参数先注册，公共参数由骨架统一追加在后，
    与五子命令原有 --help 输出顺序一致。
    """

    prog: str
    description: str
    arguments: Tuple[Argument, ...]
    execute: Execute
    with_group: bool = True


def parse_csv(value: Optional[str]) -> Optional[List[str]]:
    """逗号分隔名单 → 去空白列表；None/空串 → None（表示未提供）。

    注意全为分隔符/空白时返回 [] 而非 None——由 run_cli 的空名单
    拒绝统一拦截，适配器不会见到空名单。
    """
    if not value:
        return None
    return [item.strip() for item in value.split(",") if item.strip()]


def _build_parser(spec: CliSpec) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog=spec.prog, description=spec.description)
    for flags, kwargs in spec.arguments:
        parser.add_argument(*flags, **kwargs)
    parser.add_argument(
        "--input", "-i", required=True,
        help="配置文件路径（Base64 txt / 原生 JSON / TXT，内容为 JSON 数组）",
    )
    parser.add_argument(
        "--output", "-o", default=None,
        help="修改后配置 JSON 输出路径（缺省 <输入名>.modified.json）",
    )
    parser.add_argument(
        "--target", default=None,
        help="目标子规则名（按 name 精确寻址），逗号分隔；缺省全部 entity",
    )
    if spec.with_group:
        parser.add_argument(
            "--group", default="all", choices=["all", "threat", "non-threat"],
            help="按已标注事件名称分组寻址（threat=威胁组 / non-threat=非威胁组）；"
                 "与 --target 并存时 target 优先",
        )
    parser.add_argument(
        "--no-export", action="store_true",
        help="不产出 Base64 导出文件（缺省会一并产出）",
    )
    return parser


def run_cli(spec: CliSpec, argv: Optional[List[str]] = None) -> int:
    """按 CliSpec 执行子命令的文件契约，返回进程退出码。"""
    parser = _build_parser(spec)
    args = parser.parse_args(argv)

    try:
        data = load_entities(args.input)
    except ConfigIOError as exc:
        print(
            json.dumps(
                {"status": "error", "code": exc.code, "message": exc.message},
                ensure_ascii=False,
            )
        )
        return 1

    target_names = parse_csv(args.target)
    if args.target and not target_names:
        print(
            json.dumps(
                {
                    "status": "error",
                    "code": "invalid_input",
                    "message": (
                        "--target 解析后为空名单：请提供有效子规则名，"
                        "或省略该参数表示全部子规则"
                    ),
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return 1

    result = spec.execute(args, data, target_names)
    if result.get("status") != "success":
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 1

    input_path = Path(args.input)
    output = (
        Path(args.output)
        if args.output
        else input_path.with_name(input_path.stem + ".modified.json")
    )
    written = skill_report.write_result(
        result["data"], output, make_export=not args.no_export
    )
    payload = {
        "status": "success",
        "message": result["message"],
        "output": str(written["json_path"]),
        "export": str(written["export_path"]) if written["export_path"] else None,
    }
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0
