# 字段调整（field-adjust）子模块指南

> parser-skills 的子模块：对解析规则（Base64 配置或映射生成的子规则）执行字段级操作——添加、删除、合并、base64 解码、正则提取。当前已实现【添加字段】（`scripts/add_fields.py`）、【删除字段】（`scripts/delete_fields.py`）、【合并字段】（`scripts/merge_fields.py`）、【base64 解码】（`scripts/decode_fields.py`）与【正则提取】（`scripts/extract_fields.py`）五个子命令，field-adjust 子模块全部交付。

## 何时使用

- 用户说「添加字段」「新增字段」「增加字段」「插入字段」时 → **add 子命令**
- 用户指定新字段的名称和值来源：固定值（如 `1.1.1.1`）或引用已有字段（如 `%{reqheader}`）
- 用户要求设置/修改某子规则的【事件名称】时 → add 子命令自动联动写入绑定的【事件级别】
- 用户说「删除字段」「移除字段」「删掉某字段」时 → **delete 子命令**（支持一次删多个、按子规则名或威胁/非威胁组寻址）
- 用户说「合并字段」「把 X 和 Y 合并成 Z」时 → **merge 子命令**（至少 2 个源字段 + 1 个合并目标字段，支持分隔符）
- 用户说「base64 解码 X」「解码字段 X / Y」「还原 X 的明文」且 X 是**已有字段**时 → **base64-decode 子命令**（原地覆盖字段值，不新增字段）
- 用户说「正则提取」「从原始日志/某字段里提取 X」且能给出（或由 agent 按样本生成）正则时 → **regex-extract 子命令**（从已有字段提取新字段）。「原始日志里的 X」指 original_log、「请求头里的 X」指 req_header
- **消歧边界**（不得互换）：
  - 「删除字段 X」是字段调整（移除整个字段）→ 本模块 delete 子命令
  - 「取消/删除 X 的映射」是取消映射（只清 mappings，字段保留）→ enum-mapping 子模块（未实现）
  - 「把 X 当作日志类型」是日志类型提取 → log-classification 子模块（未实现）
  - 「正则提取 X」是按正则生成新字段 → 本模块 regex-extract 子命令；「提取 X 的枚举值」是枚举提取 → enum-mapping 子模块（未实现）

## 前置条件

- 存在**配置族输入文件**：Base64 txt / 原生 JSON / TXT，内容为 mapping entities 的 JSON 数组（含 normalize 数组结构）
- add：用户指定了新字段名；值来源缺省为空字符串
- delete：用户指定了要删除的字段名（一个或多个，逗号分隔）
- merge：用户指定了至少 2 个源字段名（逗号分隔）与合并产出的目标字段名；分隔符缺省为空字符串
- base64-decode：用户指定了要解码的**已有字段**名（一个或多个，逗号分隔）；解码只写运行时覆盖指令，值由解析器在运行时还原
- regex-extract：用户指定了被提取的**已有字段**名与正则表达式（正则可由 agent 按该字段的样本值生成后传入，但必须全匹配样本整条）；新字段名可缺省（按关键词自动命名）

## 输入/输出契约

- **输入**：`--input` 一个本地配置文件，自动识别（先按原生 JSON 解析，失败再按 Base64→JSON 解码）
- **输出**（每次修改后立即产出，不原地覆盖输入）：
  1. 修改后配置 JSON（默认 `<输入名>_modified.json`）——子模块间文件衔接的产物，可作为下一个操作的输入
  2. 平台可导入的 Base64 文件（`fieldadjusted_config_YYYYMMDD_HHMM.txt`，与输出 JSON 同目录）
  3. stdout 打印 JSON 摘要报告（`status` / `message` / `output` / `export`）
- **错误码**（稳定，脚本退出码 1）：
  - `config_required`：找不到配置文件
  - `invalid_config`：无法解码为 JSON 数组
  - `field_conflict`：字段已存在（除非 `--skip-existing`）
  - `invalid_event_name`：【事件名称】非法或不支持引用型值；对事件绑定字段合并或解码
  - `event_level_conflict`：目标内已存在【事件级别】
  - `event_level_direct_add_rejected`：不允许单独添加【事件级别】
  - `reserved_field_rejected`：删除系统保留字段（original_log / rule_name_list / 日志类型）、以其为合并目标、或对其启用 base64 解码
  - `rule_name_not_found`：`--target` 未知名，或 `--group` 组内无匹配
  - `event_annotation_required`：按威胁/非威胁分组时配置内无任何【事件名称】标注
  - `field_reference_conflict`：被删字段仍被 merger 源字段或 `%{字段}` 占位引用
  - `field_not_found`：合并的源字段、要解码的字段或正则提取的被提取字段不存在于任何（目标）子规则（附字段并集预览）
  - `invalid_pattern`：正则表达式不合法（无法编译）
  - `pattern_mismatch`：正则无法全匹配被提取字段的样本整条（必须整条匹配才能生效）
  - `invalid_input`：数据为空 / 字段名为空 / 源字段少于 2 个 / 合并目标自引用 / 未指定被提取字段或正则 / `--target` 解析后为空名单（全为分隔符/空白/空字符串时不静默全量，整单拒绝）

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

## 添加守卫链（任一命中即拒绝，退出码 1）

1. **空校验**：数据为空 / 字段名为空 → `invalid_input`（对齐其余四子命令的校验层结构）
2. **寻址校验**：`--target` 未知名（含混合名单中个别未名）→ `rule_name_not_found`（附可用子规则提示，前 20 个 + 「等」），整单拒绝——与其他子命令行为一致，防止名字打错静默零生效
3. 事件字段守卫见下节【事件名称】绑定守卫

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

## 合并字段（merge 子命令）

脚本位于本子模块：`<parser-skills>/field-adjust/scripts/merge_fields.py`。输出契约与 add / delete 一致（修改后 JSON + Base64 导出 + stdout 报告，不原地覆盖输入）。

```bash
# 基本用法（把两个源字段用分隔符拼接为新字段）
python <parser-skills>/field-adjust/scripts/merge_fields.py \
  --input <配置文件> \
  --sources "源字段A,源字段B" --target-field 合并结果 --sep "-"

# 按子规则名寻址（名单外原样透传）
python <parser-skills>/field-adjust/scripts/merge_fields.py \
  --input config.txt --sources "源字段A,源字段B" --target-field 合并结果 \
  --target "某厂_AUDIT_json_子规则,某厂_IPS_json_子规则"

# 按已标注【事件名称】分组寻址（threat=威胁组 / non-threat=非威胁组）
python <parser-skills>/field-adjust/scripts/merge_fields.py \
  --input config.txt --sources "源字段A,源字段B" --target-field 合并结果 \
  --group threat
```

`--target` 与 `--group` 并存时 **target 优先**；`--sep` 可省略（默认空字符串）。

### 数据操作（scripts/merge_fields.py）

对每个目标 entity 执行（深拷贝，不改入参）：

1. **写入 merger 过滤器**（filter 为 null 的入口规则先初始化空数组）：已有同目标的 merger 则原地更新（新源字段列表与分隔符覆盖旧值），否则新建 `{"name": "merger", "field": "<目标字段>", "sep": "<分隔符>", "id": "", "fields": ["<源字段>", ...]}`
2. **追加 normalize 预览条目**：`result` 为各源字段样本值（normalize `result[0]`）按源字段顺序用分隔符拼接的预览值，`index` 为目标字段名，其余元数据与 add 的普通字段一致
3. **源字段条目保留不删**——merger 在运行时读取源字段现场拼接出目标字段的值，删除源字段会破坏合并

per-entity 自适应：子规则字段集互不相同（映射表展示的是并集），缺任一源字段或目标字段已存在的子规则**跳过并按名报告**，整体仍为 success；无 normalize 的 entity 跳过且计数如实报告；`--target` 名单外与 `--group` 组外的 entity 原样透传。

### 合并守卫链（任一命中即拒绝，退出码 1）

1. **输入校验**：数据为空 / 源字段为空 / 目标字段名为空 / 源字段少于 2 个 → `invalid_input`
2. **寻址校验**：`--target` 未知名 → `rule_name_not_found`（附可用子规则提示）；`--group` 分组时配置内无任何【事件名称】标注 → `event_annotation_required`，组内无匹配 → `rule_name_not_found`
3. **保留字段拦截**：合并目标为 `original_log` / `rule_name_list` / `日志类型` → `reserved_field_rejected`
4. **事件绑定字段拦截**：合并目标为【事件名称】或【事件级别】→ `invalid_event_name`（事件字段请走添加字段，自动联动绑定对）
5. **自引用拦截**：目标字段名出现在源字段列表中 → `invalid_input`（请为合并结果另取字段名）
6. **全缺源校验**：所有目标子规则都缺某个源字段 → `field_not_found`，消息附全部子规则字段并集预览（前 30 个），帮助定位字段名笔误

## base64 解码（base64-decode 子命令）

脚本位于本子模块：`<parser-skills>/field-adjust/scripts/decode_fields.py`。输出契约与 add / delete / merge 一致（修改后 JSON + Base64 导出 + stdout 报告，不原地覆盖输入）。

```bash
# 基本用法（对已有字段启用运行时 base64 解码，原地覆盖其值）
python <parser-skills>/field-adjust/scripts/decode_fields.py \
  --input <配置文件> \
  --fields "req_header,req_body"

# 按子规则名寻址（名单外原样透传）
python <parser-skills>/field-adjust/scripts/decode_fields.py \
  --input config.txt --fields req_header \
  --target "某厂_AUDIT_json_子规则,某厂_IPS_json_子规则"

# 按已标注【事件名称】分组寻址（threat=威胁组 / non-threat=非威胁组）
python <parser-skills>/field-adjust/scripts/decode_fields.py \
  --input config.txt --fields req_header --group threat
```

`--target` 与 `--group` 并存时 **target 优先**。

### 数据操作（scripts/decode_fields.py）

对每个目标 entity 执行（深拷贝，不改入参）：

1. **在（或新建的）解码 addFields 过滤器中写入 OGNL 覆盖指令**（filter 为 null 的入口规则先初始化空数组）：
   `{"fields": {"<字段名>": "<%@com.hansight.dataviewer.utils.Base64@Base64Decode(<字段名>)%>"}, "name": "addFields", "id": ""}`
2. **原地覆盖，不新增字段**：key = 原字段名，运行时由解析器解码后覆盖该字段的值；normalize **不动**（与添加字段的双写语义不同）
3. **幂等**：重复调用合并进已有解码过滤器（识别条件：addFields 且全部值含 `Base64Decode(`），不重复追加；固定值与 OGNL 混合的 addFields 过滤器不算解码过滤器，会另建新的

per-entity 自适应：子规则字段集互不相同（映射表展示的是并集），缺任一要解码字段的子规则**跳过并按名报告**，整体仍为 success；无 normalize 的 entity 跳过且计数如实报告；`--target` 名单外与 `--group` 组外的 entity 原样透传。

### 解码守卫链（任一命中即拒绝，退出码 1）

1. **输入校验**：数据为空 / 字段列表为空 → `invalid_input`
2. **寻址校验**：`--target` 未知名 → `rule_name_not_found`（附可用子规则提示）；`--group` 分组时配置内无任何【事件名称】标注 → `event_annotation_required`，组内无匹配 → `rule_name_not_found`
3. **保留字段拦截**：`original_log` / `rule_name_list` / `日志类型` → `reserved_field_rejected`（original_log 是原始日志审计锚点，运行时被覆盖会断审计链）；字段列表混合保留字段时整单拒绝
4. **事件绑定字段拦截**：【事件名称】或【事件级别】→ `invalid_event_name`（解码会破坏 21 分类绑定，事件字段请走添加字段）
5. **全缺字段校验**：所有目标子规则都缺某个要解码的字段 → `field_not_found`，消息只点名真正缺失的字段并附全部子规则字段并集预览（前 30 个）

## 正则提取（regex-extract 子命令）

脚本位于本子模块：`<parser-skills>/field-adjust/scripts/extract_fields.py`。输出契约与 add / delete / merge / base64-decode 一致（修改后 JSON + Base64 导出 + stdout 报告，不原地覆盖输入）。

```bash
# 基本用法（从原始日志提取用户名，正则由 agent 按样本生成）
python <parser-skills>/field-adjust/scripts/extract_fields.py \
  --input <配置文件> --source-field original_log \
  --pattern '[\S\s]*"user":"(.*?)"[\S\s]*' --field 提取用户

# 缺省命名（按关键词 user 命名新字段，冲突加 new 前缀）+ 按子规则名寻址
python <parser-skills>/field-adjust/scripts/extract_fields.py \
  --input config.txt --source-field original_log \
  --pattern '<正则>' --keyword user --target "某厂_AUDIT_json_子规则"

# 按已标注【事件名称】分组寻址（threat=威胁组 / non-threat=非威胁组）
python <parser-skills>/field-adjust/scripts/extract_fields.py \
  --input config.txt --source-field original_log \
  --pattern '<正则>' --keyword user --group threat
```

`--field` 与 `--keyword` 均可省略；`--target` 与 `--group` 并存时 **target 优先**。

**正则的来源与校验**：正则表达式由宿主 agent 按被提取字段的样本值（normalize `result[0]`）生成后经 `--pattern` 传入，脚本零生成逻辑；脚本只做确定性校验——必须可编译（否则 `invalid_pattern`），被提取字段有样本值时必须 `re.fullmatch` **全匹配整条样本**（否则 `pattern_mismatch` 整体拒绝，非全匹配不生效）；无样本的子规则跳过校验照写（预览值为空）。

### 数据操作（scripts/extract_fields.py）

对每个目标 entity 执行（深拷贝，不改入参）：

1. **追加（或合并进）customFunction 过滤器**（filter 为 null 的入口规则先初始化空数组）：`{"custom_name": "extractRegexField", "fields": [<函数条目>], "name": "customFunction", "id": ""}`，函数条目含固定 OGNL 与 args 三元组（arg1=新增字段 / arg2=被提取字段 / arg3=正则），运行时由解析器按正则提取第一个匹配项写入新字段
2. **追加 normalize 预览条目**：`result` 为样本值经正则全匹配后的第一个捕获组（无捕获组取整条匹配），`index` 为新字段名
3. **幂等**：customFunction 过滤器中已有 arg1 同名的函数条目时原地覆盖（新正则生效），不重复追加 normalize 条目

**缺省命名链**：`--field` 缺省时按 `--keyword` 命名（关键词已存在于该子规则字段集时加 `new` 前缀）；`--keyword` 也缺省时退回被提取字段名尾段（按最后一个 `.` 切分）。

per-entity 自适应：缺被提取字段的子规则**跳过并按名报告**，整体仍为 success；所有目标子规则都缺被提取字段时报 `field_not_found`（附全部子规则字段并集预览前 30 个）；无 normalize 的 entity 跳过且计数如实报告；`--target` 名单外与 `--group` 组外的 entity 原样透传。

### 提取守卫链（任一命中即拒绝，退出码 1）

1. **输入校验**：数据为空 / 未指定被提取字段或正则 → `invalid_input`；正则无法编译 → `invalid_pattern`
2. **寻址校验**：`--target` 未知名 → `rule_name_not_found`（附可用子规则提示）；`--group` 分组时配置内无任何【事件名称】标注 → `event_annotation_required`，组内无匹配 → `rule_name_not_found`
3. **新增字段名保留字段拦截**：新增字段名（含缺省命名基准 = 关键词或源字段尾段）为 `original_log` / `rule_name_list` / `日志类型` → `reserved_field_rejected`。**只拦新增字段名**——被提取字段不受限，original_log 是「原始日志里的 X」主用例
4. **新增字段名事件字段拦截**：新增字段名为【事件名称】或【事件级别】→ `invalid_event_name`（提取值无 21 分类保证，事件字段请走添加字段）
5. **样本全匹配校验**：任一有样本的目标子规则无法全匹配 → `pattern_mismatch` 整体拒绝（正则是全域输入，静默写入即静默失败）
6. **新字段名冲突**：显式指定的新字段名在任一目标子规则已存在 → `field_conflict`（请先删除或更换名称；自动命名的 new 前缀会自行消解冲突）

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
  "output": "testdata/sample_config.base64_modified.json",
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
  "output": "testdata/sample_config.base64_modified.json",
  "export": "testdata/fieldadjusted_config_20261118_0924.txt"
}
```

AUDIT 子规则的 normalize 中 `src_ip` 条目消失、filter 追加 `{"name": "removeFields", "id": "", "fields": ["src_ip"]}`（系统保留的 `additional_fields_filter` 不动）；IPS 子规则缺该字段如实跳过；空入口规则计数跳过。

执行「把事件名称改成终端告警」时分解为 delete + add 两步（先删绑定对再重新标注），最终写入：
```json
{"fields": {"事件名称": "终端告警", "事件级别": "提醒"}, "name": "addFields", "id": ""}
```

执行「把 src_ip 和 original_log 用 - 合并成 合并字段」时：

```bash
python <parser-skills>/field-adjust/scripts/merge_fields.py \
  --input testdata/sample_config.base64.txt \
  --sources "src_ip,original_log" --target-field 合并字段 --sep "-"
```

stdout 报告：
```json
{
  "status": "success",
  "message": "成功合并 1 个 entity 的字段为 '合并字段'；跳过：某厂_IPS_json_子规则（缺 src_ip）（跳过 1 个无 normalize 的 entity）",
  "output": "testdata/sample_config.base64_modified.json",
  "export": "testdata/fieldadjusted_config_20261118_1430.txt"
}
```

AUDIT 子规则写入 merger 过滤器 `{"name": "merger", "field": "合并字段", "sep": "-", "id": "", "fields": ["src_ip", "original_log"]}` 并追加 normalize 预览条目（`index=合并字段`，`result` 为两源样本值用 `-` 拼接）；IPS 子规则缺 `src_ip` 如实跳过；空入口规则计数跳过。

执行「base64 解码 src_ip」时：

```bash
python <parser-skills>/field-adjust/scripts/decode_fields.py \
  --input testdata/sample_config.base64.txt --fields src_ip
```

stdout 报告：
```json
{
  "status": "success",
  "message": "成功为 1 个 entity 启用 base64 解码: src_ip；跳过：某厂_IPS_json_子规则（缺 src_ip）（跳过 1 个无 normalize 的 entity）",
  "output": "testdata/sample_config.base64_modified.json",
  "export": "testdata/fieldadjusted_config_20261118_1538.txt"
}
```

AUDIT 子规则在原有 `additional_fields_filter` 之后追加解码过滤器 `{"fields": {"src_ip": "<%@com.hansight.dataviewer.utils.Base64@Base64Decode(src_ip)%>"}, "name": "addFields", "id": ""}`，normalize 保持 2 条不变（原地覆盖、不双写）；IPS 子规则缺 `src_ip` 如实跳过；空入口规则计数跳过。

执行「从原始日志里提取 user」时（正则由 agent 按样本生成）：

```bash
python <parser-skills>/field-adjust/scripts/extract_fields.py \
  --input testdata/sample_config.base64.txt --source-field original_log \
  --pattern '[\S\s]*"user":"(.*?)"[\S\s]*' --keyword user \
  --target 某厂_AUDIT_json_子规则
```

stdout 报告：
```json
{
  "status": "success",
  "message": "成功为 1 个 entity 添加正则提取字段 'user'（来源: original_log）（目标 1 个）",
  "output": "testdata/sample_config.base64_modified.json",
  "export": "testdata/fieldadjusted_config_20261118_1630.txt"
}
```

AUDIT 子规则在原有 `additional_fields_filter` 之后追加 customFunction 过滤器（函数条目 arg1=user / arg2=original_log / arg3=正则），normalize 末尾追加预览条目（`index=user`，`result=["admin"]`——第一个捕获组）；IPS 子规则的 original_log 样本不含 `"user":"..."`，全匹配校验会整体拒绝（`pattern_mismatch`），故示例用 `--target` 限定 AUDIT 子规则；空入口规则计数跳过。
