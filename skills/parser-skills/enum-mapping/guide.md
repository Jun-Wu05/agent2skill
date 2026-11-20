# 枚举提取与填充（enum-mapping）子模块指南

把字段值的枚举映射写进解析规则：你（宿主 agent）负责格式识别与映射归类（每个原始值挑一个标准值），脚本负责提取、校验、写回与导出。三个脚本各管一事：

- **提取**（enum_extract.py）：日志数据表 + 目标字段 → 枚举值列表与计数
- **填充**（enum_fill.py）：映射对 → 写入 `normalize[].mappings`
- **取消映射**（enum_unmap.py）：置空目标字段的值映射（条目与字段标注保留）

## 何时使用

- 用户说「提取 X 的枚举值 / X 有哪些不同值」→ 提取
- 用户给映射对或映射表，说「填充 / 枚举值填充 / 写入解析规则」→ 填充
- 用户说「取消/删除 X 的映射 / 清空 X 的值映射」→ 取消映射——只清 mappings、字段保留；「删除字段 X」（移除整个字段）是 field-adjust 的 delete，两者不可互换

## 前置条件

- **提取**：日志数据 Excel（第一张工作表须含「原始日志」列）；你先看样本判日志体格式与分隔符
- **填充**：配置族文件（Base64 txt / 原生 JSON / TXT，规则数组）+ 映射对二选一——JSON 判定产物（第 3 步）或用户手工映射表 Excel（Sheet 名=目标字段、三列 mappingType/orgValue/mappingValue）
- **取消**：配置族文件 + 目标字段名单

## 标准流程（四步，每步有完成判据）

### 第 1 步：确认目标字段与格式

从日志样本判格式（判定规则同日志类型提取指南第 1 步）：纯 JSON / syslog 头+JSON / 纯 KV / syslog 头+KV，KV 另判字段与键值分隔符。目标字段名须与日志里的键名逐字一致（JSON 支持点分隔嵌套路径）。

**完成判据**：格式与分隔符结论明确；目标字段名已从用户指令或样本确认。

### 第 2 步：跑提取（脚本①）

```bash
python <parser-skills>/enum-mapping/scripts/enum_extract.py \
  --input <日志表.xlsx> --field <字段名> --format json|kv \
  [--field-delimit <字段分隔符>] [--kv-delimit <键值分隔符>] \
  [--header-end-marker <日志头标记>] [--max-values 100] [--template]
```

产出 `<输入名>.enum_values.json`：值列表（首现序，`--max-values` 缺省 100 只截列表与样本）、每值计数（全量）、每值首条日志样本、唯一值数、匹配统计。`--template` 另产映射表模板 `enumvalues_{时间戳}.xlsx`（orgValue 与 EQUAL 预填、mappingValue 留空），可直接交给用户或自己补完映射值。

**完成判据**：stdout `status: success`。零命中报 `enum_extract_empty`——回第 1 步核对格式与分隔符判定。

### 第 3 步：语义归类，产出映射对

读 enum_values.json，**每个原始值写一行判定**（`orgValue` + `mappingValue`）：

```json
{"mappings": [
    {"field": "event_type",
     "pairs": [
        {"orgValue": "login", "mappingValue": "登录"},
        {"orgValue": "unknown_code_42", "mappingValue": "未知"}
     ]}
  ]}
```

**归类硬约束**：

- `orgValue` 填提取出的原值本身（**逐字保留**，不翻译、不改大小写、不去空格）
- `mappingValue` 只能取目标标准字段的**枚举值白名单**（标准字段目录「枚举值」列，经 `_shared/standard_catalog.py` 加载），严禁自造值
- 语义兼容但无法可靠归类的值选该标准字段的**默认值**（8 类枚举短路目标的默认值见 `standard_catalog.ENUM_AUTO_MAPPING_TARGETS`）；数值型或语义不明的值必须选默认值——禁止按通用编程惯例（如 0=成功）或直觉猜测
- 值域与目标标准字段整体不兼容时，如实告知用户并全部留空 `mappingValue`（回退 orgValue）
- 输出值集合与提取值集合**一致**：不新增、不遗漏、不合并
- `mappingType` 可省（缺省 EQUAL 精确匹配）；正则匹配写 REGULAR，未以 `.*` 开头会自动加通配包裹

**完成判据**：值清单全覆盖；每个 `mappingValue` 都在白名单内或明确走了默认值。

### 第 4 步：跑填充（脚本②）

```bash
python <parser-skills>/enum-mapping/scripts/enum_fill.py \
  --input <配置文件> --mappings <映射对.json>      # 或 --excel <映射表.xlsx>
```

产出 `<输入名>.enumfilled.json` + Base64 导出 `enummapping_config_{时间戳}.txt`。

**完成判据**：stdout `status: success`；核对 `fields` 摘要（added / updated / unchanged / duplicates 与 targets 命中条目数）与 `unbound`（填充时自动解绑的固定值绑定数）是否符合预期。

## 取消映射

```bash
python <parser-skills>/enum-mapping/scripts/enum_unmap.py \
  --input <配置文件> --fields <字段A,字段B>
```

产出 `<输入名>.enumunmapped.json` + 同名 Base64 导出。目标命中的全部条目（index 或 field 同名，含同一原始字段跨多条目）一并置空 `mappings`，条目本身与 field 标注原样保留。

## 约束与边界

- **目标寻址**：填充/取消都按 normalize 条目 index 或 field 同名命中；同一原始字段跨多条目一并生效
- **合并更新**：填充对同 orgValue 原地更新、新值追加、未提及的既有映射保留（幂等重跑友好）；要删除映射用取消映射（整字段置空），不支持删单对
- **守卫整单拒绝**（一行不写）：任一目标字段在配置中不存在 → `enum_target_field_mismatch`（附可用字段提示）；取消时标准名歧义（一个标准字段名对应多个原始字段）→ `field_name_ambiguous`（改用原始字段名）；目标没有可取消的映射 → `mapping_not_found`（禁止静默成功）
- **不做目标黑名单**（用户裁决）：任何字段都可经枚举填充/取消维护值映射，包括威胁类型等链路持有字段——各链路与手工填充共用 orgValue 合并语义，可共存
- **填充即解绑**：addFields 过滤器里目标字段的固定值绑定自动删除（`%{}` 引用绑定保留）——固定值与值映射不能并存
- 枚举**字段**归属判定（某原始字段映射到哪个标准枚举字段）是 field-mapping 的范围（8 类枚举字段短路）；本子模块只做**值**映射
- 威胁类型的**自动分类**（内置分类表 + REGULAR 正则映射）走威胁类型子模块；手工值映射表经本流程填充，两者共用 orgValue 合并语义
- 产物同名直接覆盖；不原地覆盖输入文件

**完整 JSON 契约**（enum_values.json / 映射对 JSON / 映射表 Excel / 两产物 / stdout 摘要的字段说明）见 [references/enum_schema.md](references/enum_schema.md)。

## 错误码

`config_required`（配置文件缺失）/ `input_required`（数据表或映射表缺失）/ `invalid_config`（配置非数组）/ `invalid_input`（路径互斥、契约不符、空名单）/ `enum_extract_empty`（零命中）/ `enum_target_field_mismatch`（目标字段不存在）/ `field_not_found`（取消目标未找到）/ `field_name_ambiguous`（标准名歧义）/ `mapping_not_found`（无可取消映射），失败退出码 1，stdout JSON 报告。
