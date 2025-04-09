## cve-monitor
cve监控推送，自定义关键词、仓库等，支持钉钉，飞书等并实现cve描述翻译功能
### 实时监控github上新增的cve和安全工具更新，多渠道推送通知
DES版本具有原文描述和译文描述
普通版本默认翻译，不翻译可在cofig.yaml中关闭

每3分钟检测一次github是否有新的cve漏洞提交或者安全工具更新记录，若有则通过配置的渠道通知用户
1、使用帮助
`tools_list.yaml` 监控的工具列表，新添加按照已有的格式写

`config.yaml` 推送token 设置
效果
![image](https://github.com/user-attachments/assets/db0bb777-b057-4665-9e33-8a0b20f8b76b)

DES版本效果：
![image](https://github.com/user-attachments/assets/0748d68b-b788-483b-b255-591d14863b77)


## 推送设置

## 钉钉

1.   建立群聊（可以单人建群）
 
![image](https://github.com/user-attachments/assets/db64e077-39e8-48ca-a89b-937922852396)

2.   智能群助手添加自定义机器人
![image](https://github.com/user-attachments/assets/d3f2578e-3b53-4485-8d1e-4f58a16fbdfb)

​			选择加签


![image](https://github.com/user-attachments/assets/aeb3f74c-0a86-4db1-8ee6-e2caee583fcd)


建立机器人，之后在`config.yaml`中配置，将webhook和秘钥secretKey填入对应的字段，`enable`设置为`1`表示使用该通知

效果：

![image](https://github.com/user-attachments/assets/0d0f6c1a-9f93-4358-8b32-2a9508fbac5c)


DES版本效果：
![image](https://github.com/user-attachments/assets/4c5b43da-16e4-48ba-8b6a-c5522bef8150)



##  飞书推送

方法与钉钉添加群机器人类似


效果：

![image](https://github.com/user-attachments/assets/e8f0a2e6-85b3-4e53-a75f-22dd029623db)


## Telegram Bot推送支持
@[atsud0](https://github.com/atsud0) 师傅添加了 Telegram 推送
安装telegram bot

```
pip install python-telegram-bot
```

生成bot 获得群组或用户聊天ID
创建bot详情谷歌

### 获得ID
将bot加入群组后，发送几条消息。访问https://api.telegram.org/bot{TOKEN}/getUpdates
用户ID同理，


`config.yaml`中配置`tgbot`的`token`等信息,`enable`设置为 `1`表示推送


## Server 酱
ps：因微信的原因，server酱的旧版将在2021年4月后下线，新版以企业微信为主，这里使用的是旧版，想改新版的话，搞个企业微信，从新配置server酱，使用新链接 sctapi.ftqq.com

具体查看server酱官方，https://sct.ftqq.com/，配置简单，只需要将脚本中的uri换掉即可

[server酱新版]((https://sct.ftqq.com/))支持多通道（微信、客户端、群机器人、邮件和短信）

`config.yaml`中配置`server`的`token`等信息,`enable`设置为 `1`表示推送

## 推送加【Mac 版微信可用】

免费的微信模板消息通知，支持在 Mac 版微信查看

具体配置方法见 pushplus 公众号文章：https://mp.weixin.qq.com/s/YRYb04PUFNVZejzV2G-k4w

## Github 访问限制

监控工具更新 请求次数过多，超过了每小时请求，添加gihtub token

>   对于未经身份验证的请求，github 速率限制允许每小时最多 60 个请求
>
>   而通过使用基本身份验证的 API 请求，每小时最多可以发出 5,000 个请求
>
>   https://github.com/settings/tokens/new 创建token，时间的话选无限制的，毕竟要一直跑![image](https://github.com/user-attachments/assets/3bb2db6f-1cc8-47bd-be96-c6213afc023c)


`config.yaml`中配置github_token

## 使用systemd方法稳定后台运行

注意要更改 run_python_forever.sh 里面的脚本路径、运行路径和运行用户名并给sh脚本权限，
chmod +x run_python_forever.sh
更改完成后运行以下几个步骤

1、创建systemd服务
sudo vi /etc/systemd/system/run_python_forever.service
2、写入

[Unit]
Description=Run Python script forever
After=network.target

[Service]
ExecStart=/path/to/run_python_forever.sh
Restart=always
User=your_username
WorkingDirectory=/path/to/working/directory

[Install]
WantedBy=multi-user.target


---------------------------------------------------------

替换 /path/to/run_python_forever.sh 为脚本的绝对路径。
替换 your_username 为运行脚本的用户。
替换 /path/to/working/directory 为脚本的工作目录

3、重新加载systemd服务
sudo systemctl daemon-reload

4、启动
sudo systemctl start run_python_forever.service

5、开机自启
sudo systemctl enable run_python_forever.service




# 鸣谢
 借鉴 yhy0 代码 并进行修改，优化，复活添加翻译，飞书。
