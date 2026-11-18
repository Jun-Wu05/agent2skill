# 字段调整（field-adjust）子模块指南

> parser-skills 的子模块：对解析规则（Base64 配置或映射生成的子规则）执行字段级操作——添加、删除、合并、base64 解码、正则提取。当前已实现【添加字段】（`scripts/add_fields.py`）与【删除字段】（`scripts/delete_fields.py`）两个子命令，其余三个按计划交付中。

## 何时使用

- 用户说「添加字段」「新增字段」「增加字段」「插入字段」时 → **add 子命令**
- 用户指定新字段的名称和值来源：固定值（如 `1.1.1.1`）或引用已有字段（如 `%{reqheader}`）
- 用户要求设置/修改某子规则的【事件名称】时 → add 子命令自动联动写入绑定的【事件级别】
- 用户说「删除字段」「移除字段」「删掉某字段」时 → **delete 子命令**（支持一次删多个、按子规则名或威胁/非威胁组寻址）
- **消歧边界**（不得互换）：
  - 「删除字段 X」是字段调整（移除整个字段）→ 本模块 delete 子命令
  - 「取消/删除 X 的映射」是取消映射（只清 mappings，字段保留）→ enum-mapping 子模块（未实现）
  - 「把 X 当作日志类型」是日志类型提取 → log-classification 子模块（未实现）

## 前置条件

- 存在**配置族输入文件**：Base64 txt / 原生 JSON / TXT，内容为 mapping entities 的 JSON 数组（含 normalize 数组结构）
- add：用户指定了新字段名；值来源缺省为空字符串
- delete：用户指定了要删除的字段名（一个或多个，逗号分隔）

## 输入/输出契约

- **输入**：`--input` 一个本地配置文件，自动识别（先按原生 JSON 解析，失败再按 Base64→JSON 解码）
- **输出**（每次修改后立即产出，不原地覆盖输入）：
  1. 修改后配置 JSON（默认 `<输入名>.modified.json`）——子模块间文件衔接的产物，可作为下一个操作的输入
  2. 平台可导入的 Base64 文件（`fieldadjusted_config_YYYYMMDD_HHMM.txt`，与输出 JSON 同目录）
  3. stdout 打印 JSON 摘要报告（`status` / `message` / `output` / `export`）
- **错误码**（稳定，脚本退出码 1）：
  - `config_required`：找不到配置文件
  - `invalid_config`：无法解码为 JSON 数组
  - `field_conflict`：字段已存在（除非 `--skip-existing`）
  - `invalid_event_name`：【事件名称】非法或不支持引用型值
  - `event_level_conflict`：目标内已存在【事件级别】
  - `event_level_direct_add_rejected`：不允许单独添加【事件级别】
  - `reserved_field_rejected`：删除系统保留字段（original_log / rule_name_list / 日志类型）
  - `rule_name_not_found`：`--target` 未知名，或 `--group` 组内无匹配
  - `event_annotation_required`：按威胁/非威胁分组时配置内无任何【事件名称】标注
  - `field_reference_conflict`：被删字段仍被 merger 源字段或 `%{字段}` 占位引用
  - `invalid_input`：数据为空 / 字段名为空

## 调用方式

脚本位于本子模块：`<parser-skills>/field-adjust/scripts/add_fields.py`（`<parser-skills>` 为 parser-skills 技能基目录，agent 加载技能时已知；在源仓库内即 `skills/parser-skills`）。

```bash
# 基本用法（固定值）
python <parser-skills>/field-adjust/scripts/add_fields.py \
  --input <配置文件> \
  --field 主机ip --value 1.1.1.1

# 引用已有字段（%{index} 原样存储，运行时由解析器替换）
python <parser-skills>/field-adjust/scripts/add_fields.py \
  --input config.txt --field 请求头 --value "%{reqheader}"

# 按子规则名寻址 + 已存在跳过
python <parser-skills>/field-adjust/scripts/add_fields.py \
  --input config.txt --field 主机ip --value 1.1.1.1 \
  --target "某厂_AUDIT_json_子规则,某厂_IPS_json_子规则" --skip-existing

# 设置事件名称（自动联动写入事件级别，无需也不应单独添加事件级别）
python <parser-skills>/field-adjust/scripts/add_fields.py \
  --input config.txt --field 事件名称 --value 终端告警
```

## 数据操作（scripts/add_fields.py）

对每个目标 entity 执行：

1. **验证字段不存在**（`--skip-existing` 时跳过并计数）
2. **撤销同字段的 removeFields 标记**（删除后重新添加时避免同时声明「删除」和「添加」）
3. **追加 addFields filter**（filter 为 null 的入口规则会先初始化为空数组）：
   `{"name": "addFields", "id": "", "fields": {"<字段名>": "<值>"}}`
4. **追加 normalize 条目**（值引用 `%{index}` 原样保留）：
   `{"mappings": [], "field": null, "sim": null, "result": ["<值>"], "info": null, "entity": null, "required": false, "core": null, "value": null, "index": "<字段名>"}`

无 normalize 的 entity 被跳过且计数如实报告；名单外（`--target`）的 entity 原样透传。
数据结构细节见 [references/data_structure.md](references/data_structure.md)。

## 【事件名称】绑定守卫

手动添加【事件名称】时执行确定性守卫（分类表单一事实源：`_shared/event_binding.py`）：

- 值必须是 **21 个合法分类名**之一——威胁组（事件级别=提醒）：网络攻击、病毒检测、邮件告警、终端告警、蜜罐告警、其他告警；非威胁组（事件级别=信息）：登录事件、审计事件、会话操作、进程操作、用户操作、资源监控、邮件操作、dns查询、dns响应、数据库操作、ssh连接、认证事件、telnet连接、网络连接、web访问
- 不支持引用型值（`%{...}`）；非法值返回 `invalid_event_name`
- 添加【事件名称】后**自动联动写入**绑定的【事件级别】（同目标范围），事件名称/事件级别条目带标准元数据（`field=event_name/event_level`、`entity=事件`、`sim=true`、`core=false`、EQUAL mappings + value）
- 【事件级别】已存在时返回 `event_level_conflict`，需先删除两个字段再重新添加
- 单独添加【事件级别】被拒绝：请添加【事件名称】，级别自动联动

## 删除字段（delete 子命令）

脚本位于本子模块：`<parser-skills>/field-adjust/scripts/delete_fields.py`。输出契约与 add 一致（修改后 JSON + Base64 导出 + stdout 报告，不原地覆盖输入）。

```bash
# 基本用法（一次删多个字段，逗号分隔）
python <parser-skills>/field-adjust/scripts/delete_fields.py \
  --input <配置文件> \
  --fields "主机ip,备注"

# 按子规则名寻址（名单外原样透传）
python <parser-skills>/field-adjust/scripts/delete_fields.py \
  --input config.txt --fields src_ip \
  --target "某厂_AUDIT_json_子规则,某厂_IPS_json_子规则"

# 按已标注【事件名称】分组寻址（threat=威胁组 / non-threat=非威胁组）
python <parser-skills>/field-adjust/scripts/delete_fields.py \
  --input config.txt --fields 威胁等级 --group threat

# 删除事件名称（自动联动删除绑定的【事件级别】）
python <parser-skills>/field-adjust/scripts/delete_fields.py \
  --input config.txt --fields 事件名称
```

`--target` 与 `--group` 并存时 **target 优先**。

### 数据操作（scripts/delete_fields.py）

对每个目标 entity 执行（深拷贝，不改入参）：

1. **清理同名 addFields 绑定**：过滤器还有其他键时只删目标键；`fields` 清空时删除整个空 addFields 过滤器
2. **写入 removeFields 过滤器**（filter 为 null 的入口规则先初始化为空数组）：已有 removeFields 则合并（去重追加），否则新建 `{"name": "removeFields", "id": "", "fields": ["<字段名>", ...]}`
3. **移除对应的 normalize 条目**

无 normalize 的 entity 跳过且计数如实报告；字段在所有目标 entity 都不存在时报告 `not_found` 但仍为 success；`--target` 名单外与 `--group` 组外的 entity 原样透传。

### 删除守卫链（任一命中即拒绝，退出码 1）

1. **寻址校验**：`--target` 未知名 → `rule_name_not_found`（附可用子规则提示）；`--group` 分组时配置内无任何【事件名称】标注 → `event_annotation_required`，组内无匹配 → `rule_name_not_found`
2. **保留字段拦截**：`original_log` / `rule_name_list` / `日志类型` → `reserved_field_rejected`
3. **绑定对联动删除**：删【事件名称】或【事件级别】任一时自动扩展为两者（避免留下绑定残缺），消息注明「已联动删除绑定对（事件名称+事件级别）」
4. **悬空引用守卫**（只查目标范围内 entity）：被删字段是 merger 过滤器的源字段、或被任一过滤器 `fields` 值中的 `%{字段}` 占位引用 → `field_reference_conflict`，需先解除引用再删

修改【事件名称】的标准流程是 delete + add 两步：先删绑定对，再用 add 重新标注。

## 约束与边界

- add 字段名已存在且未开 `--skip-existing`：返回 `field_conflict`，建议更换名称或先删除原有字段
- add 值为空时：normalize 的 `result` 为空数组 `[]`，filter 中 value 为空字符串 `""`
- 引用格式 `%{index}` 中的 index 指向已有字段的 normalize index
- delete 只接受配置内真实存在的字段名/normalize index；标准字段名解析由 field-mapping 子模块承担
- 无可用配置（文件缺失/无法解码）：`config_required` / `invalid_config`

## 完整示例

输入 `testdata/sample_config.base64.txt`（3 个 entity：2 个子规则 + 1 个空入口规则），执行：

```bash
python <parser-skills>/field-adjust/scripts/add_fields.py \
  --input testdata/sample_config.base64.txt --field 主机ip --value 1.1.1.1
```

stdout 报告：
```json
{
  "status": "success",
  "message": "成功为 2 个 entity 添加字段 '主机ip'（跳过 1 个无 normalize 的 entity）",
  "output": "testdata/sample_config.base64.modified.json",
  "export": "testdata/fieldadjusted_config_20261117_0830.txt"
}
```

两个有 normalize 的子规则各新增一条 normalize 条目（`index=主机ip`、`result=["1.1.1.1"]`）和一个 addFields filter（`{"主机ip": "1.1.1.1"}`）；空入口规则如实跳过。

执行「删除字段 src_ip」时：

```bash
python <parser-skills>/field-adjust/scripts/delete_fields.py \
  --input testdata/sample_config.base64.txt --fields src_ip
```

stdout 报告：
```json
{
  "status": "success",
  "message": "成功从 1 个 entity 删除 1 个字段；跳过：某厂_IPS_json_子规则（缺 src_ip）（跳过 1 个无 normalize 的 entity）",
  "output": "testdata/sample_config.base64.modified.json",
  "export": "testdata/fieldadjusted_config_20261118_0924.txt"
}
```

AUDIT 子规则的 normalize 中 `src_ip` 条目消失、filter 追加 `{"name": "removeFields", "id": "", "fields": ["src_ip"]}`（系统保留的 `additional_fields_filter` 不动）；IPS 子规则缺该字段如实跳过；空入口规则计数跳过。

执行「把事件名称改成终端告警」时分解为 delete + add 两步（先删绑定对再重新标注），最终写入：
```json
{"fields": {"事件名称": "终端告警", "事件级别": "提醒"}, "name": "addFields", "id": ""}
```
