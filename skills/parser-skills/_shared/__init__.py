"""agent2skill 跨技能共享底座。

- config_io: 配置族（Base64 txt / 原生 JSON / TXT）确定性解码与编码
- report:    统一结果输出与平台兼容的导出文件命名
- event_binding: 事件名称/事件级别确定性绑定规则（21 分类单一事实源）

所有技能脚本共用本包，禁止在技能内复制这些逻辑。
"""
