---
name: parser-skills
description: 解析规则技能集 - 日志解析规则（Base64 配置/JSON/TXT）与日志数据的统一处理入口，涵盖字段调整（添加/删除/合并/base64 解码/正则提取字段）、日志类型提取、标准字段映射、枚举提取与填充、威胁类型映射。当用户说"添加字段、新增字段、删除字段、移除字段、合并字段、base64 解码、解码字段、正则提取、从某字段提取X、字段映射、映射到标准字段、日志类型、把X当作日志类型、区分日志类型、提取枚举值、枚举填充、威胁类型、导出Base64配置"等解析规则操作时使用。当前已实现【字段调整五子命令】【日志类型提取】，其余功能按计划交付中。
license: MIT
metadata:
  version: "0.8.0"
  status: 字段调整-添加/删除/合并/base64 解码/正则提取字段、日志类型提取已实现；其余子模块交付中
---

# 解析规则技能集（parser-skills）

一个统一技能，覆盖解析规则（安全日志字段映射产物）与日志数据的全部处理功能。各功能按领域概念组织为子模块；本文件是唯一入口与路由，**DSH 只注册这一个技能**。被路由到子模块后，先读该子模块的 guide.md 再动手。

## 子模块路由

| 用户意图关键词 | 子模块 | 状态 | 指南与脚本 |
|---|---|---|---|
| 添加字段 / 新增字段 / 插入字段；设置事件名称；删除字段 / 移除字段；合并字段 / 把 X 和 Y 合并；base64 解码 / 解码字段；正则提取 / 从某字段提取 X | **field-adjust**（字段调整） | ✅ 添加/删除/合并/base64 解码/正则提取可用 | [field-adjust/guide.md](field-adjust/guide.md)，脚本 `field-adjust/scripts/` |
| 日志类型 / 把 X 当作日志类型 / 区分日志类型 / 从日志数据生成解析规则 | **log-classification**（日志类型提取） | ✅ 特征统计 + 分类收口 + 白板子规则可用 | [log-classification/guide.md](log-classification/guide.md)，脚本 `log-classification/scripts/` |
| 字段映射 / 映射到标准字段 / X 映射到 Y（填白板、生成完整规则） | field-mapping（标准字段映射） | 交付中（以 log-classification 白板产物为输入） | — |
| 提取 X 的枚举值 / 填充 / 取消映射 | enum-mapping（枚举提取与填充） | 交付中 | — |
| 威胁类型 / 映射到威胁类型 | threat-type（威胁类型链路） | 交付中 | — |

**消歧边界**（不得互换）：
- 「删除字段 X」＝移除整个字段（field-adjust）；「取消/删除 X 的映射」＝只清值映射、字段保留（enum-mapping）
- 「正则提取 / 从某字段提取 X」＝按正则生成新字段（field-adjust）；「提取 X 的枚举值」＝枚举提取（enum-mapping）
- 带「作为/当作/设为日志类型」短语、或输入是日志数据 Excel → log-classification；无该短语的「提取 X 的枚举值」→ enum-mapping
- 「把 Excel 日志做成解析规则」→ 先 log-classification（分类出白板子规则），再 field-mapping（填标准字段映射）
- 【事件名称】设置走 field-adjust 的添加字段（自动联动【事件级别】）；不支持单独添加事件级别

## 通用约定（所有子模块一致）

- **输入**：配置族文件（Base64 txt / 原生 JSON / TXT，内容为 mapping entities 的 JSON 数组，自动识别解码）或日志数据文件（Excel，第一张工作表须含「原始日志」列）
- **输出**：修改/生成类操作运行后即产出——①结果 JSON（子模块间文件衔接的产物，如 `<输入名>.modified.json` / `.subrules.json`）②平台可导入的 Base64 文件（命名兼容平台下载契约，如 `fieldadjusted_config_YYYYMMDD_HHMM.txt` / `unmappedconfig_subrules_YYYYMMDD_HHMM.txt`）③stdout JSON 摘要（`status` / `message` / 产物路径）
- **不原地覆盖输入文件**；错误码稳定（`config_required` / `input_required` / `invalid_config` / `invalid_input` / `field_conflict` / `invalid_event_name` / `event_level_conflict` / `reserved_field_rejected` / `rule_name_not_found` / `event_annotation_required` / `field_reference_conflict` / `field_not_found` / `invalid_pattern` / `pattern_mismatch` 等），失败退出码 1
- **共享底座 `_shared/`**：config_io.py（配置族解码/编码）、log_input.py（Excel 数据族读取）、log_extract.py（JSON/KV 特征提取与聚合）、rule_gen.py（规则骨架与装配）、report.py（统一输出与导出命名）、event_binding.py（事件名称 21 分类绑定表）、entity_scope.py（target/group 寻址解析）、field_policy.py（系统保留字段）、cli.py（field-adjust 子命令 CLI 骨架）——子模块脚本共用，禁止复制
- 脚本路径相对本技能基目录 `<parser-skills>` 书写（agent 加载本技能时已知；在源仓库内即 `skills/parser-skills`），不依赖会话 cwd

## 子模块速览

- **field-adjust**：对解析规则配置做字段增删改（五子命令共用 CLI 骨架，守卫链拦截危险操作，支持按子规则名/威胁组寻址）。用法、参数、守卫与示例见 [field-adjust/guide.md](field-adjust/guide.md)。
- **log-classification**：Excel 日志表 → agent 判格式与特征字段 → 脚本①全量统计 → agent 语义归类 → 脚本②收口出分类结果 + 白板子规则 + Base64 导出。标准流程五步与判定清单见 [log-classification/guide.md](log-classification/guide.md)。
