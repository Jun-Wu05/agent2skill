---
name: parser-skills
description: 解析规则技能集 - 日志解析规则（Base64 配置/JSON/TXT）与日志数据的统一处理入口，涵盖字段调整（添加/删除/合并/base64 解码/正则提取字段）、标准字段映射、日志类型提取、枚举提取与填充、威胁类型映射。当用户说"添加字段、新增字段、删除字段、移除字段、合并字段、base64 解码、解码字段、字段映射、映射到标准字段、日志类型、把X当作日志类型、提取枚举值、枚举填充、威胁类型、导出Base64配置"等解析规则操作时使用。当前已实现【添加字段】【删除字段】【合并字段】【base64 解码】子命令，其余功能按计划交付中。
license: MIT
metadata:
  version: "0.4.0"
  status: 字段调整-添加/删除/合并/base64 解码字段已实现；其余子模块交付中
---

# 解析规则技能集（parser-skills）

一个统一技能，覆盖解析规则（安全日志字段映射产物）与日志数据的全部处理功能。各功能按领域概念组织为子模块；本文件是唯一入口与路由，**DSH 只注册这一个技能**。

## 子模块路由

| 用户意图关键词 | 子模块 | 状态 | 指南与脚本 |
|---|---|---|---|
| 添加字段 / 新增字段 / 插入字段；设置事件名称；删除字段 / 移除字段；合并字段 / 把 X 和 Y 合并；base64 解码 / 解码字段 | **field-adjust**（字段调整） | ✅ 添加/删除/合并/base64 解码字段可用；正则提取交付中 | [field-adjust/guide.md](field-adjust/guide.md)，脚本 `field-adjust/scripts/` |
| 字段映射 / 映射到标准字段 / X 映射到 Y | field-mapping（标准字段映射） | 交付中 | — |
| 日志类型 / 把 X 当作日志类型 / 区分日志类型 | log-classification（日志类型提取） | 交付中 | — |
| 提取 X 的枚举值 / 填充 / 取消映射 | enum-mapping（枚举提取与填充） | 交付中 | — |
| 威胁类型 / 映射到威胁类型 | threat-type（威胁类型链路） | 交付中 | — |

**消歧边界**（不得互换）：
- 「删除字段 X」＝移除整个字段（field-adjust）；「取消/删除 X 的映射」＝只清值映射、字段保留（enum-mapping）
- 带「作为/当作/设为日志类型」短语 → log-classification；无该短语的「提取 X 的枚举值」→ enum-mapping
- 【事件名称】设置走 field-adjust 的添加字段（自动联动【事件级别】）；不支持单独添加事件级别

## 通用约定（所有子模块一致）

- **输入**：配置族文件（Base64 txt / 原生 JSON / TXT，内容为 mapping entities 的 JSON 数组，自动识别解码）或日志数据文件（Excel，须含「原始日志」列）
- **输出**：每次修改后立即产出——①修改后配置 JSON（默认 `<输入名>.modified.json`，子模块间文件衔接的产物）②平台可导入的 Base64 文件（命名如 `fieldadjusted_config_YYYYMMDD_HHMM.txt`，与输出 JSON 同目录）③stdout JSON 摘要报告（`status` / `message` / `output` / `export`）
- **不原地覆盖输入文件**；错误码稳定（`config_required` / `invalid_config` / `field_conflict` / `invalid_event_name` / `event_level_conflict` / `reserved_field_rejected` / `rule_name_not_found` / `event_annotation_required` / `field_reference_conflict` / `field_not_found` / `invalid_input` 等），失败退出码 1
- **共享底座 `_shared/`**：config_io.py（配置族解码/编码）、report.py（统一输出与导出命名）、event_binding.py（事件名称 21 分类绑定表）、entity_scope.py（target/group 寻址解析）、field_policy.py（系统保留字段）——子模块脚本共用，禁止复制
- 脚本路径相对本技能基目录书写，不依赖会话 cwd

## 当前可用功能

### 添加字段（field-adjust · add）

对解析规则的每个目标 entity：normalize 追加字段条目 + parser.filter 追加 addFields 绑定；支持固定值与 `%{index}` 引用（原样存储，运行时由解析器替换）；【事件名称】受 21 分类确定性守卫约束并自动联动写入绑定的【事件级别】。完整规则、参数与示例见 [field-adjust/guide.md](field-adjust/guide.md)。

```bash
# 示例：为 Base64 配置添加固定值字段
python <parser-skills>/field-adjust/scripts/add_fields.py \
  --input <配置文件> --field 主机ip --value 1.1.1.1

# 示例：设置事件名称（自动联动写入绑定的【事件级别】）
python <parser-skills>/field-adjust/scripts/add_fields.py \
  --input <配置文件> --field 事件名称 --value 终端告警

# 示例：按子规则名寻址 + 已存在跳过
python <parser-skills>/field-adjust/scripts/add_fields.py \
  --input <配置文件> --field 主机ip --value 1.1.1.1 \
  --target "规则A,规则B" --skip-existing
```

### 删除字段（field-adjust · delete）

对解析规则的每个目标 entity：移除 normalize 字段条目 + 清理同名 addFields 绑定 + 写入 removeFields 过滤器（已有则合并）；系统保留字段（original_log / rule_name_list / 日志类型）拒绝删除；删【事件名称】或【事件级别】任一自动联动删除两者；被 merger 源字段或 `%{字段}` 占位引用的字段删除前拦截；支持按子规则名（`--target`）或威胁/非威胁组（`--group`）寻址，并存时 target 优先。完整规则、参数与示例见 [field-adjust/guide.md](field-adjust/guide.md)。

```bash
# 示例：一次删除多个字段
python <parser-skills>/field-adjust/scripts/delete_fields.py \
  --input <配置文件> --fields "主机ip,备注"

# 示例：按威胁组批量删除（按已标注【事件名称】分组）
python <parser-skills>/field-adjust/scripts/delete_fields.py \
  --input <配置文件> --fields 威胁等级 --group threat

# 示例：删除事件名称（自动联动删除绑定的【事件级别】）
python <parser-skills>/field-adjust/scripts/delete_fields.py \
  --input <配置文件> --fields 事件名称
```

### 合并字段（field-adjust · merge）

把至少 2 个源字段的值合并为一个新字段：对每个目标 entity 写入 merger 过滤器（运行时按分隔符拼接源字段值）并追加 normalize 预览条目；源字段保留不删。per-entity 自适应：缺任一源或目标已存在的子规则跳过并按名报告；所有目标子规则都缺源字段时返回 `field_not_found`（附全部子规则字段并集预览）。合并目标为系统保留字段或【事件名称】/【事件级别】时拒绝；自引用（目标字段 ∈ 源字段）拒绝；支持按子规则名（`--target`）或威胁/非威胁组（`--group`）寻址，并存时 target 优先。完整规则、参数与示例见 [field-adjust/guide.md](field-adjust/guide.md)。

```bash
# 示例：把两个字段用 - 拼接为新字段
python <parser-skills>/field-adjust/scripts/merge_fields.py \
  --input <配置文件> --sources "源字段A,源字段B" \
  --target-field 合并结果 --sep "-"

# 示例：按子规则名寻址合并
python <parser-skills>/field-adjust/scripts/merge_fields.py \
  --input <配置文件> --sources "源字段A,源字段B" \
  --target-field 合并结果 --target "规则A,规则B"

# 示例：按威胁组批量合并
python <parser-skills>/field-adjust/scripts/merge_fields.py \
  --input <配置文件> --sources "源字段A,源字段B" \
  --target-field 合并结果 --group threat
```

### base64 解码（field-adjust · base64-decode）

对解析规则的每个目标 entity：在（或新建的）解码 addFields 过滤器中写入 `{字段名: Base64Decode OGNL}`，运行时由解析器**原地覆盖**字段值——不新增字段、不双写 normalize（与添加字段的双写语义不同）；重复调用幂等合并。系统保留字段与【事件名称】/【事件级别】拒绝解码；所有目标子规则都缺该字段时返回 `field_not_found`（只点名真正缺失的字段 + 并集预览）；per-entity 自适应跳过缺字段子规则；支持按子规则名（`--target`）或威胁/非威胁组（`--group`）寻址，并存时 target 优先。完整规则、参数与示例见 [field-adjust/guide.md](field-adjust/guide.md)。

```bash
# 示例：对已有字段启用运行时 base64 解码（原地覆盖其值）
python <parser-skills>/field-adjust/scripts/decode_fields.py \
  --input <配置文件> --fields "req_header,req_body"

# 示例：按子规则名寻址解码
python <parser-skills>/field-adjust/scripts/decode_fields.py \
  --input <配置文件> --fields req_header --target "规则A,规则B"

# 示例：按威胁组批量解码
python <parser-skills>/field-adjust/scripts/decode_fields.py \
  --input <配置文件> --fields req_header --group threat
```

`<parser-skills>` 为本技能基目录（agent 加载本技能时已知；在源仓库内即 `skills/parser-skills`）。
