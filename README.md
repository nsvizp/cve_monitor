# cve-monitor
cve监控推送，支持tg，钉钉，微信，飞书等并实现cve描述翻译功能
### 实时监控github上新增的cve和安全工具更新，多渠道推送通知

每3分钟检测一次github是否有新的cve漏洞提交或者安全工具更新记录，若有则通过配置的渠道通知用户
1、使用帮助
`tools_list.yaml` 监控的工具列表，新添加按照已有的格式写

`config.yaml` 推送token 设置
效果
![image](https://github.com/user-attachments/assets/db0bb777-b057-4665-9e33-8a0b20f8b76b)
# 鸣谢
 yhy0 提供初始代码
