#!/usr/bin/python3
# -*- coding:utf-8 -*-
# @Author : myxfc
# 每3分钟检测一次github

import base64
import datetime
import hashlib
import json
import re
import sqlite3
import time
from collections import OrderedDict
from functools import lru_cache
import Crypto.Cipher.AES as AES
import dingtalkchatbot.chatbot as cb
import requests
import yaml
from Crypto.Util.Padding import unpad
from lxml import etree
import threading
# cve 仓库拥有者计数器(也就是黑名单，不过每天会清空重新计数)，每天最多推送一个人名下的三个 cve 仓库
counter = {}

#读取配置文件(config.yaml)
def load_config():
    try:
        with open('config.yaml', 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)  # 使用 safe_load 更安全
            all_config = config['all_config']
            github_token = all_config['github_token']
            translate = int(all_config['translate'][0]['enable']) == 1

            # 存储所有启用的配置
            enabled_configs = []

            # 检查并添加 DingDing 配置
            if int(all_config['dingding'][0]['enable']) == 1:
                dingding_config = {
                    "type": "dingding",
                    "app_name": all_config['dingding'][3]['app_name'],
                    "dingding_webhook": all_config['dingding'][1]['webhook'],
                    "dingding_secretKey": all_config['dingding'][2]['secretKey'],
                }
                enabled_configs.append(dingding_config)

            # 检查并添加 Feishu 配置
            if int(all_config['feishu'][0]['enable']) == 1:
                feishu_config = {
                    "type": "feishu",
                    "app_name": all_config['feishu'][2]['app_name'],
                    "feishu_webhook": all_config['feishu'][1]['webhook'],
                }
                enabled_configs.append(feishu_config)

            # 检查并添加 Server 酱 配置
            if int(all_config['server'][0]['enable']) == 1:
                server_config = {
                    "type": "server",
                    "app_name": all_config['server'][2]['app_name'],
                    "server_sckey": all_config['server'][1]['sckey'],
                }
                enabled_configs.append(server_config)

            # 检查并添加 Pushplus 配置
            if int(all_config['pushplus'][0]['enable']) == 1:
                pushplus_config = {
                    "type": "pushplus",
                    "app_name": all_config['pushplus'][2]['app_name'],
                    "pushplus_token": all_config['pushplus'][1]['token'],
                }
                enabled_configs.append(pushplus_config)

            # 检查并添加 Tgbot 配置
            if int(all_config['tgbot'][0]['enable']) == 1:
                tgbot_config = {
                    "type": "tgbot",
                    "app_name": all_config['tgbot'][3]['app_name'],
                    "tgbot_token": all_config['tgbot'][1]['token'],
                    "tgbot_group_id": all_config['tgbot'][2]['group_id'],
                }
                enabled_configs.append(tgbot_config)

            # 如果没有启用任何配置，则抛出异常
            if not enabled_configs:
                raise ValueError("[-] 配置文件有误, 至少需要启用一个社交软件的 enable")

            return enabled_configs, github_token, translate  # 返回所有配置和 github_token

    except FileNotFoundError:
        print("[-] 配置文件 config.yaml 不存在")
        exit()  # 退出程序
    except yaml.YAMLError as e:
        print(f"[-] 配置文件 config.yaml 解析错误: {e}")
        exit()  # 退出程序
    except KeyError as e:
        print(f"[-] 配置文件 config.yaml 缺少必要的键: {e}")
        exit()  # 退出程序
    except ValueError as e:
        print(e)  # 输出错误信息
        exit()  # 退出程序
    except Exception as e:
        print(f"[-] 读取配置文件时发生未知错误: {e}")
        exit()  # 退出程序



github_headers = {
    'Authorization': "token {}".format(load_config()[1])
}

#读取黑名单用户
def black_user():
    with open('config.yaml', 'r', encoding='utf-8') as f:
        config = yaml.load(f, Loader=yaml.FullLoader)
        black_user = config['all_config']['black_user']
        return black_user

#初始化创建数据库
def create_database():
    conn = sqlite3.connect('data.db')
    # print("[]create_database 函数 连接数据库成功！")
    # logging.info("create_database 函数 连接数据库成功！")
    cur = conn.cursor()
    try:
        cur.execute('''CREATE TABLE IF NOT EXISTS cve_monitor
                   (cve_name varchar(255),
                    pushed_at varchar(255),
                    cve_url varchar(255));''')
        print("成功创建CVE监控表")
        cur.execute('''CREATE TABLE IF NOT EXISTS keyword_monitor
                   (keyword_name varchar(255),
                    pushed_at varchar(255),
                    keyword_url varchar(255));''')
        print("成功创建关键字监控表")
        cur.execute('''CREATE TABLE IF NOT EXISTS redteam_tools_monitor
                   (tools_name varchar(255),
                    pushed_at varchar(255),
                    tag_name varchar(255));''')
        print("成功创建红队工具监控表")
        cur.execute('''CREATE TABLE IF NOT EXISTS user_monitor
                   (repo_name varchar(255));''')
        print("成功创建大佬仓库监控表")
    except Exception as e:
        print("创建监控表失败！报错：{}".format(e))
    conn.commit()  # 数据库存储在硬盘上需要commit  存储在内存中的数据库不需要
    conn.close()
    if load_config()[0] == "dingding":
        dingding("test", "连接成功", load_config()[2], load_config()[3])
    elif load_config()[0] == "server":
        server("test", "连接成功", load_config()[2])
    elif load_config()[0] == "pushplus":
        pushplus("test", "连接成功", load_config()[2])        
    elif load_config()[0] == "tgbot":
        tgbot("test", "连接成功", load_config()[2], load_config()[3])
#根据排序获取本年前20条CVE
def getNews():
    today_cve_info_tmp = []
    try:
        # 抓取本年的
        year = datetime.datetime.now().year
        api = "https://api.github.com/search/repositories?q=CVE-{}&sort=updated".format(year)
        json_str = requests.get(api, headers=github_headers, timeout=10).json()
        # cve_total_count = json_str['total_count']
        # cve_description = json_str['items'][0]['description']
        today_date = datetime.date.today()
        n = len(json_str['items'])
        if n > 30:
            n = 30
        for i in range(0, n):
            cve_url = json_str['items'][i]['html_url']
            if cve_url.split("/")[-2] not in black_user():
                try:
                    cve_name_tmp = json_str['items'][i]['name'].upper()
                    cve_name = re.findall('(CVE\-\d+\-\d+)', cve_name_tmp)[0].upper()
                    pushed_at_tmp = json_str['items'][i]['created_at']
                    pushed_at = re.findall('\d{4}-\d{2}-\d{2}', pushed_at_tmp)[0]
                    if pushed_at == str(today_date):
                        today_cve_info_tmp.append({"cve_name": cve_name, "cve_url": cve_url, "pushed_at": pushed_at})
                    else:
                        print("[-] 该{}的更新时间为{}, 不属于今天的CVE".format(cve_name, pushed_at))
                except Exception as e:
                    pass
            else:
                pass
        today_cve_info = OrderedDict()
        for item in today_cve_info_tmp:
            user_name = item['cve_url'].split("/")[-2]
            if user_name in counter:
                if counter[user_name] < 3:
                    counter[user_name] +=1
                    today_cve_info.setdefault(item['cve_name'], {**item, })
            else:
                counter[user_name] = 0
                today_cve_info.setdefault(item['cve_name'], {**item, })
        today_cve_info = list(today_cve_info.values())

        return today_cve_info
        # return cve_total_count, cve_description, cve_url, cve_name
        #\d{4}-\d{2}-\d{2}

    except Exception as e:
        print(e, "github链接不通")
        return '', '', ''



def getKeywordNews(keyword):
    today_keyword_info_tmp = []
    try:
        now = datetime.datetime.utcnow()
        # 计算24小时前的时间
        since_time = (now - datetime.timedelta(hours=24)).strftime('%Y-%m-%dT%H:%M:%SZ')

        # GitHub API 查询
        api = f"https://api.github.com/search/repositories?q={keyword}+pushed:>{since_time}&sort=updated"
        response = requests.get(api, headers=github_headers, timeout=10)
        if response.status_code != 200:
            print(f"GitHub API 请求失败，状态码: {response.status_code}")
            return []
        json_str = response.json()
        if not json_str or 'items' not in json_str:
            print("GitHub API 返回空数据或格式错误")
            return today_keyword_info_tmp

        today_date = datetime.date.today()
        items = json_str['items']
        n = min(len(items), 20)

        # 统一关键字判断（不区分大小写）
        keyword_upper = keyword.strip().upper()
        is_cnvd_or_cnnvd = keyword_upper in ('CNVD', 'CNNVD')

        for i in range(n):
            keyword_url = items[i]['html_url']
            if keyword_url.split("/")[-2] in black_user():
                continue

            try:
                keyword_name = items[i]['name']
                pushed_at_tmp = items[i]['created_at']
                pushed_at = re.findall(r'\d{4}-\d{2}-\d{2}', pushed_at_tmp)[0]

                # 如果传入的关键字是CNVD/CNNVD，或者仓库名称包含CNVD/CNNVD，则跳过CVE检查
                if is_cnvd_or_cnnvd or 'CNVD' in keyword_name.upper() or 'CNNVD' in keyword_name.upper():
                    if pushed_at == str(today_date):
                        today_keyword_info_tmp.append({
                            "keyword_name": keyword_name,
                            "keyword_url": keyword_url,
                            "pushed_at": pushed_at
                        })
                        print(f"[+] CNVD/CNNVD关键字或仓库匹配: {keyword_name}")
                    else:
                        print(f"[-] 仓库 {keyword_name} 的更新时间 {pushed_at} 不属于今天")
                    continue  # 跳过后续所有检查

                # 非CNVD/CNNVD关键字：检查CVE编号
                keyword_description = items[i].get('description', '') or ''
                keyword_topics = items[i].get('topics', []) or []
                cve_pattern = re.compile(r'CVE\-\d+\-\d+', re.IGNORECASE)

                # 检查名称、描述或主题中是否包含CVE
                has_cve = (cve_pattern.search(keyword_name) or
                           cve_pattern.search(keyword_description) or
                           any(cve_pattern.search(topic) for topic in keyword_topics))

                if not has_cve:
                    # 检查README文件
                    owner, repo = keyword_url.split('/')[-2], keyword_url.split('/')[-1]
                    readme_url = f"https://api.github.com/repos/{owner}/{repo}/readme"
                    readme_response = requests.get(readme_url, headers=github_headers, timeout=10)

                    if readme_response.status_code == 200:
                        readme_json = readme_response.json()
                        readme_content = readme_json.get('content', '')
                        if readme_content:
                            try:
                                readme_text = base64.b64decode(readme_content).decode('utf-8')
                                if not cve_pattern.search(readme_text):
                                    print(f"[-] 仓库 {keyword_name} 不包含CVE编号，跳过")
                                    continue
                            except (base64.binascii.Error, UnicodeDecodeError) as e:
                                print(f"解码README失败: {e}")
                                continue
                    else:
                        print(f"[-] 无法获取仓库 {keyword_name} 的README文件，跳过")
                        continue

                # 检查日期
                if pushed_at == str(today_date):
                    today_keyword_info_tmp.append({
                        "keyword_name": keyword_name,
                        "keyword_url": keyword_url,
                        "pushed_at": pushed_at
                    })
                    print(f"[+] 关键字 {keyword} 匹配的仓库: {keyword_name}")
                else:
                    print(f"[-] 仓库 {keyword_name} 的更新时间 {pushed_at} 不属于今天")

            except Exception as e:
                print(f"处理仓库 {keyword_name} 时出错: {e}")
                continue

        # 去重逻辑
        today_keyword_info = OrderedDict()
        for item in today_keyword_info_tmp:
            user_name = item['keyword_url'].split("/")[-2]
            if user_name in counter:
                if counter[user_name] < 3:
                    counter[user_name] += 1
                    today_keyword_info.setdefault(item['keyword_name'], item)
            else:
                counter[user_name] = 1
                today_keyword_info.setdefault(item['keyword_name'], item)

        return list(today_keyword_info.values())

    except Exception as e:
        print(f"发生未知错误: {e}")
        return today_keyword_info_tmp


def get_today_keyword_info(today_keyword_info_data):
    today_all_keyword_info = []
    for i in range(len(today_keyword_info_data)):
        try:
            today_keyword_name = today_keyword_info_data[i]['keyword_name']
            # 双重检查确保包含CVE编号
            today_cve_name = re.findall('(CVE\-\d+\-\d+)', today_keyword_info_data[i]['keyword_name'].upper())
            if not today_cve_name:
                continue

            Verify = query_keyword_info_database(today_keyword_name)
            if Verify == 0:
                print("[+] 数据库里不存在{}".format(today_keyword_name))
                today_all_keyword_info.append(today_keyword_info_data[i])
            else:
                print("[-] 数据库里存在{}".format(today_keyword_name))
        except Exception as e:
            pass
    return today_all_keyword_info


#获取到的关键字仓库信息插入到数据库
def keyword_insert_into_sqlite3(data):
    conn = sqlite3.connect('data.db')
    print("keyword_insert_into_sqlite3 函数 打开数据库成功！")
    print(data)
    cur = conn.cursor()
    for i in range(len(data)):
        try:
            keyword_name = data[i]['keyword_name']
            cur.execute("INSERT INTO keyword_monitor (keyword_name,pushed_at,keyword_url) VALUES ('{}', '{}', '{}')".format(keyword_name, data[i]['pushed_at'], data[i]['keyword_url']))
            print("keyword_insert_into_sqlite3 函数: {}插入数据成功！".format(keyword_name))
        except Exception as e:
            print("keyword_insert_into_sqlite3 error {}".format(e))
            pass
    conn.commit()
    conn.close()
#查询数据库里是否存在该关键字仓库的方法
def query_keyword_info_database(keyword_name):
    conn = sqlite3.connect('data.db')
    cur = conn.cursor()
    sql_grammar = "SELECT keyword_name FROM keyword_monitor WHERE keyword_name = '{}';".format(keyword_name)
    cursor = cur.execute(sql_grammar)
    return len(list(cursor))

#获取不存在数据库里的关键字信息
def get_today_keyword_info(today_keyword_info_data):
    today_all_keyword_info = []
    for i in range(len(today_keyword_info_data)):
        try:
            today_keyword_name = today_keyword_info_data[i]['keyword_name']
            today_cve_name = re.findall('(CVE\-\d+\-\d+)', today_keyword_info_data[i]['keyword_name'].upper())
            # 如果仓库名字带有 cve-xxx-xxx, 先查询看看 cve 监控中是否存在, 防止重复推送
            if len(today_cve_name) > 0 and query_cve_info_database(today_cve_name.upper()) == 1: 
                pass
            Verify = query_keyword_info_database(today_keyword_name)
            if Verify == 0:
                print("[+] 数据库里不存在{}".format(today_keyword_name))
                today_all_keyword_info.append(today_keyword_info_data[i])
            else:
                print("[-] 数据库里存在{}".format(today_keyword_name))
        except Exception as e:
            pass
    return today_all_keyword_info


#获取到的CVE信息插入到数据库
def cve_insert_into_sqlite3(data):
    conn = sqlite3.connect('data.db')
    print("cve_insert_into_sqlite3 函数 打开数据库成功！")
    cur = conn.cursor()
    for i in range(len(data)):
        try:
            cve_name = re.findall('(CVE\-\d+\-\d+)', data[i]['cve_name'])[0].upper()
            cur.execute("INSERT INTO cve_monitor (cve_name,pushed_at,cve_url) VALUES ('{}', '{}', '{}')".format(cve_name, data[i]['pushed_at'], data[i]['cve_url']))
            print("cve_insert_into_sqlite3 函数: {}插入数据成功！".format(cve_name))
        except Exception as e:
            pass
    conn.commit()
    conn.close()
#查询数据库里是否存在该CVE的方法
def query_cve_info_database(cve_name):
    conn = sqlite3.connect('data.db')
    cur = conn.cursor()
    sql_grammar = "SELECT cve_name FROM cve_monitor WHERE cve_name = '{}';".format(cve_name)
    cursor = cur.execute(sql_grammar)
    return len(list(cursor))
#查询数据库里是否存在该tools工具名字的方法
def query_tools_info_database(tools_name):
    conn = sqlite3.connect('data.db')
    cur = conn.cursor()
    sql_grammar = "SELECT tools_name FROM redteam_tools_monitor WHERE tools_name = '{}';".format(tools_name)
    cursor = cur.execute(sql_grammar)
    return len(list(cursor))
#获取不存在数据库里的CVE信息
def get_today_cve_info(today_cve_info_data):
    today_all_cve_info = []
    # today_cve_info_data = getNews()
    for i in range(len(today_cve_info_data)):
        try:
            today_cve_name = re.findall('(CVE\-\d+\-\d+)', today_cve_info_data[i]['cve_name'])[0].upper()
            if exist_cve(today_cve_name) == 1:
                Verify = query_cve_info_database(today_cve_name.upper())
                if Verify == 0:
                    print("[+] 数据库里不存在{}".format(today_cve_name.upper()))
                    today_all_cve_info.append(today_cve_info_data[i])
                else:
                    print("[-] 数据库里存在{}".format(today_cve_name.upper()))
        except Exception as e:
            pass
    return today_all_cve_info
#获取红队工具信息插入到数据库
def tools_insert_into_sqlite3(data):
    conn = sqlite3.connect('data.db')
    print("tools_insert_into_sqlite3 函数 打开数据库成功！")
    cur = conn.cursor()
    for i in range(len(data)):
        Verify = query_tools_info_database(data[i]['tools_name'])
        if Verify == 0:
            print("[+] 红队工具表数据库里不存在{}".format(data[i]['tools_name']))
            cur.execute("INSERT INTO redteam_tools_monitor (tools_name,pushed_at,tag_name) VALUES ('{}', '{}','{}')".format(data[i]['tools_name'], data[i]['pushed_at'], data[i]['tag_name']))
            print("tools_insert_into_sqlite3 函数: {}插入数据成功！".format(format(data[i]['tools_name'])))
        else:
            print("[-] 红队工具表数据库里存在{}".format(data[i]['tools_name']))
    conn.commit()
    conn.close()
#读取本地红队工具链接文件转换成list
def load_tools_list():
    with open('tools_list.yaml', 'r',  encoding='utf-8') as f:
        list = yaml.load(f,Loader=yaml.FullLoader)
        return list['tools_list'], list['keyword_list'], list['user_list']
#获取红队工具的名称，更新时间，版本名称信息
def get_pushed_at_time(tools_list):
    tools_info_list = []
    for url in tools_list:
        try:
            tools_json = requests.get(url, headers=github_headers, timeout=10).json()
            pushed_at_tmp = tools_json['pushed_at']
            pushed_at = re.findall('\d{4}-\d{2}-\d{2}', pushed_at_tmp)[0] #获取的是API上的时间
            tools_name = tools_json['name']
            api_url = tools_json['url']
            try:
                releases_json = requests.get(url+"/releases", headers=github_headers, timeout=10).json()
                tag_name = releases_json[0]['tag_name']
            except Exception as e:
                tag_name = "no releases"
            tools_info_list.append({"tools_name":tools_name,"pushed_at":pushed_at,"api_url":api_url,"tag_name":tag_name})
        except Exception as e:
            print("get_pushed_at_time ", e)
            pass

    return tools_info_list
#根据红队名名称查询数据库红队工具的更新时间以及版本名称并返回
def tools_query_sqlite3(tools_name):
    result_list = []
    conn = sqlite3.connect('data.db')
    cur = conn.cursor()
    sql_grammar = "SELECT pushed_at,tag_name FROM redteam_tools_monitor WHERE tools_name = '{}';".format(tools_name)
    cursor = cur.execute(sql_grammar)
    for result in cursor:
        result_list.append({"pushed_at":result[0],"tag_name":result[1]})
    conn.close()
    print("[###########]  tools_query_sqlite3 函数内 result_list 的值 为 - > {}".format(result_list))
    return result_list
#获取更新了的红队工具在数据库里面的时间和版本
def get_tools_update_list(data):
    tools_update_list = []
    for dist in data:
        print("dist 变量 ->{}".format(dist))
        query_result = tools_query_sqlite3(dist['tools_name'])
        if len(query_result) > 0:
            today_tools_pushed_at = query_result[0]['pushed_at']
            # print("[!!] 今日获取时间: ", dist['pushed_at'], "获取数据库时间: ", today_tools_pushed_at, dist['tools_name'])
            if dist['pushed_at'] != today_tools_pushed_at:
                print("今日获取时间: ",dist['pushed_at'],"获取数据库时间: ",today_tools_pushed_at,dist['tools_name'],"update!!!!")
                #返回数据库里面的时间和版本
                tools_update_list.append({"api_url":dist['api_url'],"pushed_at":today_tools_pushed_at,"tag_name":query_result[0]['tag_name']})
            else:
                print("今日获取时间: ",dist['pushed_at'],"获取数据库时间: ",today_tools_pushed_at,dist['tools_name'],"   no update")
    return tools_update_list


# 监控用户是否新增仓库，不是 fork 的
def getUserRepos(user):
    try:
        api = "https://api.github.com/users/{}/repos".format(user)
        json_str = requests.get(api, headers=github_headers, timeout=10).json()
        today_date = datetime.date.today()

        for i in range(0, len(json_str)):
            created_at = re.findall('\d{4}-\d{2}-\d{2}', json_str[i]['created_at'])[0]
            if json_str[i]['fork'] == False and created_at == str(today_date):
                Verify = user_insert_into_sqlite3(json_str[i]['full_name'])
                print(json_str[i]['full_name'], Verify)
                if Verify == 0:
                    name = json_str[i]['name']
                    try:
                        description = json_str[i]['description']
                    except Exception as e:
                        description = "作者未写描述"
                    download_url = json_str[i]['html_url']
                    text = r'大佬' + r'** ' + user + r' ** ' + r'又分享了一款工具! '+"\r\n监控机器人Author：MYXFC 公众号：密雾九尾"
                    body = "工具名称: " + name + " \r\n" + "工具地址: " + download_url + " \r\n" + "工具描述: " + "" + description
                    if load_config()[0] == "dingding":
                        dingding(text, body,load_config()[2],load_config()[3])
                    if load_config()[0] == "server":
                        server(text, body,load_config()[2])
                    if load_config()[0] == "pushplus":
                        pushplus(text, body,load_config()[2])
                    if load_config()[0] == "tgbot":
                        tgbot(text,body,load_config()[2],load_config()[3])
    except Exception as e:
        print(e, "github链接不通")

#获取用户或者组织信息插入到数据库
def user_insert_into_sqlite3(repo_name):
    conn = sqlite3.connect('data.db')
    cur = conn.cursor()
    sql_grammar = "SELECT repo_name FROM user_monitor WHERE repo_name = '{}';".format(repo_name)
    Verify = len(list(cur.execute(sql_grammar)))
    if Verify == 0:
        print("[+] 用户仓库表数据库里不存在{}".format(repo_name))
        cur.execute("INSERT INTO user_monitor (repo_name) VALUES ('{}')".format(repo_name))
        print("user_insert_into_sqlite3 函数: {}插入数据成功！".format(repo_name))
    else:
        print("[-] 用户仓库表数据库里存在{}".format(repo_name))
    conn.commit()
    conn.close()
    return Verify

#获取更新信息并发送到对应社交软件
def send_body(url,query_pushed_at,query_tag_name):
    # 考虑到有的工具没有 releases, 则通过 commits 记录获取更新描述
    # 判断是否有 releases 记录
    json_str = requests.get(url + '/releases', headers=github_headers, timeout=10).json()
    new_pushed_at = re.findall('\d{4}-\d{2}-\d{2}', requests.get(url, headers=github_headers, timeout=10).json()['pushed_at'])[0]
    if len(json_str) != 0:
        tag_name = json_str[0]['tag_name']
        if query_pushed_at < new_pushed_at :
            print("[*] 数据库里的pushed_at -->", query_pushed_at, ";;;; api的pushed_at -->", new_pushed_at)
            if tag_name != query_tag_name:
                try:
                    update_log = json_str[0]['body']
                except Exception as e:
                    update_log = "作者未写更新内容"
                download_url = json_str[0]['html_url']
                tools_name = url.split('/')[-1]
                text = r'** ' + tools_name + r' ** 工具,版本更新啦!'+"\r\n监控机器人Author：MYXFC 公众号：密雾九尾"
                body = "工具名称：" + tools_name + "\r\n" + "工具地址：" + download_url + "\r\n" + "工具更新日志：" + "\r\n" + update_log
                if load_config()[0] == "dingding":
                    dingding(text, body,load_config()[2],load_config()[3])
                if load_config()[0] == "server":
                    server(text, body,load_config()[2])
                if load_config()[0] == "pushplus":
                    pushplus(text, body,load_config()[2])                    
                if load_config()[0] == "tgbot":
                    tgbot(text,body,load_config()[2],load_config()[3])
                conn = sqlite3.connect('data.db')
                cur = conn.cursor()
                sql_grammar = "UPDATE redteam_tools_monitor SET tag_name = '{}' WHERE tools_name='{}'".format(tag_name,tools_name)
                sql_grammar1 = "UPDATE redteam_tools_monitor SET pushed_at = '{}' WHERE tools_name='{}'".format(new_pushed_at, tools_name)
                cur.execute(sql_grammar)
                cur.execute(sql_grammar1)
                conn.commit()
                conn.close()
                print("[+] tools_name -->", tools_name, "pushed_at 已更新，现在pushed_at 为 -->", new_pushed_at,"tag_name 已更新，现在tag_name为 -->",tag_name)
            elif tag_name == query_tag_name:
                commits_url = url + "/commits"
                commits_url_response_json = requests.get(commits_url).text
                commits_json = json.loads(commits_url_response_json)
                tools_name = url.split('/')[-1]
                download_url = commits_json[0]['html_url']
                try:
                    update_log = commits_json[0]['commit']['message']
                except Exception as e:
                    update_log = "作者未写更新内容，具体点击更新详情地址的URL进行查看"
                text = r'** ' + tools_name + r' ** 工具小更新了一波!'+"\r\n监控机器人Author：MYXFC 公众号：密雾九尾"
                body = "工具名称：" + tools_name + "\r\n" + "更新详情地址：" + download_url + "\r\n" + "commit更新日志：" + "\r\n" + update_log
                if load_config()[0] == "dingding":
                    dingding(text, body,load_config()[2],load_config()[3])
                if load_config()[0] == "feishu":
                    feishu(text,body,load_config()[2])
                if load_config()[0] == "server":
                    server(text, body,load_config()[2])
                if load_config()[0] == "pushplus":
                    pushplus(text, body,load_config()[2])                       
                if load_config()[0] == "tgbot":
                    tgbot(text,body,load_config()[2],load_config()[3])
                conn = sqlite3.connect('data.db')
                cur = conn.cursor()
                sql_grammar = "UPDATE redteam_tools_monitor SET pushed_at = '{}' WHERE tools_name='{}'".format(new_pushed_at,tools_name)
                cur.execute(sql_grammar)
                conn.commit()
                conn.close()
                print("[+] tools_name -->",tools_name,"pushed_at 已更新，现在pushed_at 为 -->",new_pushed_at)

        # return update_log, download_url, tools_version
    else:
        if query_pushed_at != new_pushed_at:
            print("[*] 数据库里的pushed_at -->", query_pushed_at, ";;;; api的pushed_at -->", new_pushed_at)
            json_str = requests.get(url + '/commits', headers=github_headers, timeout=10).json()
            update_log = json_str[0]['commit']['message']
            download_url = json_str[0]['html_url']
            tools_name = url.split('/')[-1]
            text = r'** ' + tools_name + r' ** 工具更新啦!'
            body = "工具名称：" + tools_name + "\r\n" + "工具地址：" + download_url + "\r\n" + "commit更新日志：" + "\r\n" + update_log
            if load_config()[0] == "dingding":
                dingding(text, body, load_config()[2], load_config()[3])
            if load_config()[0] == "feishu":
                feishu(text,body,load_config[2])
            if load_config()[0] == "server":
                server(text, body, load_config()[2])
            if load_config()[0] == "pushplus":
                pushplus(text, body,load_config()[2])                   
            if load_config()[0] == "tgbot":
                tgbot(text, body, load_config()[2], load_config()[3])
            conn = sqlite3.connect('data.db')
            cur = conn.cursor()
            sql_grammar = "UPDATE redteam_tools_monitor SET pushed_at = '{}' WHERE tools_name='{}'".format(new_pushed_at,tools_name)
            cur.execute(sql_grammar)
            conn.commit()
            conn.close()
            print("[+] tools_name -->", tools_name, "pushed_at 已更新，现在pushed_at 为 -->", new_pushed_at)
            # return update_log, download_url

#有道翻译
# 生成Key和IV时修正
def md5_hash(s):
    md5 = hashlib.md5()
    md5.update(s.encode('utf-8'))
    return md5.digest()  # 确保返回bytes类型

secretKey_param = "Vy4EQ1uwPkUoqvcP1nIu6WiAjxFeA3Y3"  # 翻译失败很可能是三个key值的改变
aes_iv_str = "ydsecret://query/iv/C@lZe2YzHtZ2CYgaXKSVfsb7Y4QWHjITPPZ0nQp87fBeJ!Iv6v^6fvi2WN@bYpJ4"
aes_key_str = "ydsecret://query/key/B*RGygVywfNBwpmBaZg*WT7SIOUP2T0C9WHMZN39j^DAdaZhAnxvGcCY6VYFwnHl"
# secretKey = secretKey_str
iv = md5_hash(aes_iv_str)
key = md5_hash(aes_key_str)

# 解密函数
def decrypt(ciphertext):
    # 处理URL安全的Base64并移除干扰字符
    ciphertext = ciphertext.replace('-', '+').replace('_', '/').replace(' ', '')
    try:
        cipher_bytes = base64.b64decode(ciphertext, validate=True)
        aes_cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = aes_cipher.decrypt(cipher_bytes)
        return unpad(decrypted, AES.block_size).decode('utf-8')
    except (ValueError, TypeError) as e:
        print(f"解密失败: {str(e)}")
        return None

@lru_cache(maxsize=100)
# 请求参数
def translate(des):
    try:
        url = 'https://dict.youdao.com/webtranslate'
        headers = {
            "Accept": "application/json, text/plain, */*", "accept-encoding": "gzip, deflate, br, zstd",
            "accept-language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
            "connection": "keep-alive",
            # "content-length": "322",
            # "content-type":"application/x-www-form-urlencoded",
            "Cookie": "OUTFOX_SEARCH_USER_ID=-57891657@125.86.188.112; OUTFOX_SEARCH_USER_ID_NCOO=118049373.81209917; _uetsid=54ad8ce0060011f0a15787a3554a5b20; _uetvid=54ade1c0060011f09c2211cd64baad7a; DICT_DOCTRANS_SESSION_ID=ZDlmNTMyNDYtOTdjZS00Y2MzLTkwZDktN2IzY2Q4NjM5MDVj",
            "host": "dict.youdao.com",
            "origin": "https://fanyi.youdao.com",
            "referer": "https://fanyi.youdao.com/",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36 Edg/135.0.0.0"
        }
        # 时间戳
        mystic_time = str(int(time.time() * 1000))
        # mystic_time = time.time()
        # key_param = "Vy4EQ1uwPkUoqvcP1nIu6WiAjxFeA3Y3"
        # 签名生成修正
        # sign_str = f"client=fanyideskweb&mysticTime={mystic_time}&product=webfanyi&key={key_param}"
        sign_str = f"client=fanyideskweb&mysticTime={mystic_time}&product=webfanyi&key={secretKey_param}"
        # sign_str = f'client=fanyideskweb&mysticTime={mystic_time}&product=webfanyi&key=Vy4EQ1uwPkUoqvcP1nIu6WiAjxFeA3Y3'
        sign = hashlib.md5(sign_str.encode()).hexdigest()
        # def get_sign():
        #     e = f'client=fanyideskweb&mysticTime={timestamp}&product=webfanyi&key=Vy4EQ1uwPkUoqvcP1nIu6WiAjxFeA3Y3'
        #     sign = hashlib.md5(e.encode()).hexdigest()
        #     return sign
        data = {
            "i": des,
            "from": "auto",
            "to": "",
            "useTerm": "false",
            "dictResult": "true",
            "keyid": "webfanyi",
            "sign": sign,
            "client": "fanyideskweb",
            "product": "webfanyi",
            "appVersion": "1.0.0",
            "vendor": "web",
            "pointParam": "client,mysticTime,product",
            "mysticTime": mystic_time,
            "keyfrom": "fanyi.web",
            "mid": "1",
            "screen": "1",
            "model": "1",
            "network": "wifi",
            "abtest": "0",
            "yduuid": "abcdefg"
        }
        response = requests.post(url, headers=headers, data=data, timeout=10)
        response.raise_for_status()  # 自动处理HTTP错误
        encrypted_data = response.text.strip()
        # print("原始响应:", encrypted_data)

        # 直接解密原始响应
        decrypted_text = decrypt(encrypted_data)

        # if decrypted_text:
        # print("\n翻译结果:")
        # print(json.dumps(json.loads(decrypted_text), indent=2, ensure_ascii=False))
        #     print(['translateResult'][f0]['tgt'])
        # print(decrypted_text)
        # print("=============================================")
        result_dict = json.loads(decrypted_text)
        # 提取所有tgt字段并合并
        # tgt_segments = []
        # try:
        #     # 遍历外层列表（处理多段落情况）
        #     for paragraph in result_dict.get("translateResult", []):
        #         # 遍历内层列表（处理每段多个句子）
        #         for item in paragraph:
        #             if isinstance(item, dict) and item.get("tgt"):
        #                 tgt_segments.append(item["tgt"])
        # except Exception as e:
        #     print(f"解析翻译结果失败: {str(e)}")


       # 改为生成器降低内存
        tgt_segments = (
            item["tgt"]
            for paragraph in result_dict.get("translateResult", [])
            for item in paragraph
            if isinstance(item, dict) and item.get("tgt")
        )
        # 合并为单个字符串（保留原有标点）
        return "".join(tgt_segments) if tgt_segments else "翻译结果为空"
        # return result_dict['translateResult'][0][0]['tgt']
   # except:
   #      return "翻译出问题++++++++++++++++++++++++++++++++++++++++++++++++++++"
    except Exception as e:
        print(f"翻译过程出错: {str(e)}")
        return "翻译失败"


# 钉钉
def dingding(text, msg, webhook, secretKey):
    ding = cb.DingtalkChatbot(webhook, secret=secretKey)
    ding.send_text(msg='{}\r\n{}'.format(text, msg), is_at_all=False)
# 飞书
def feishu(title, content, webhook):  # 移除 secret 参数
    try:
        data = {
            "msg_type": "text",
            "content": {
                "text": title + "\n" + content
            }
        }
        headers = {'Content-Type': 'application/json'}

        response = requests.post(webhook, data=json.dumps(data), headers=headers)
        response.raise_for_status()  # 抛出 HTTPError 异常 (如果状态码不是 200)
        print(f"飞书消息发送成功 (无签名校验): {response.text}")

    except requests.exceptions.RequestException as e:
        print(f"飞书消息发送失败 (无签名校验): {e}")
    except Exception as e:
        print(f"飞书消息发送时发生未知错误 (无签名校验): {e}")

# 疑似飞书sign时间戳服务器错误，移除 gen_sign 函数
# def gen_sign(timestamp, secret):
#     string_to_sign = '{}\n{}'.format(timestamp, secret)
#     hmac_code = hmac.new(secret.encode("utf-8"), string_to_sign.encode("utf-8"), digestmod=hashlib.sha256).digest()
#     sign = base64.b64encode(hmac_code).decode('utf-8')
#     return sign
# 飞书发送，有签名版本代码
# def feishu(title, content, webhook, secret):
#     try:
#         timestamp = str(int(time.time()))
#         sign = gen_sign(timestamp, secret)
#
#         data = {
#             "msg_type": "text",
#             "content": {
#                 "text": title + "\n" + content
#             },
#             "timestamp": timestamp,
#             "sign": sign
#         }
#         headers = {'Content-Type': 'application/json'}
#
#         # 打印调试信息
#         print(f"飞书时间戳: {timestamp}")
#         print(f"飞书签名字符串: {timestamp}\\n{secret}")
#         print(f"飞书签名: {sign}")
#         print(f"飞书请求体: {json.dumps(data)}")
#
#         response = requests.post(webhook, data=json.dumps(data), headers=headers)
#         response.raise_for_status()  # 抛出 HTTPError 异常 (如果状态码不是 200)
#         print(f"飞书消息发送成功 (签名校验): {response.text}")
#
#     except requests.exceptions.RequestException as e:
#         print(f"飞书消息发送失败 (签名校验): {e}")
#         if "sign match fail or timestamp is not within one hour from current time" in str(e):
#             print("错误：飞书机器人签名校验失败，请检查 secretKey 和服务器时间！")
#         else:
#             print(f"其他错误: {e}")
#     except Exception as e:
#         print(f"飞书消息发送时发生未知错误 (签名校验): {e}")



# server酱  http://sc.ftqq.com/?c=code
def server(text, msg,sckey):
    try:
        uri = 'https://sc.ftqq.com/{}.send?text={}&desp={}'.format(sckey,text, msg)# 将 xxxx 换成自己的server SCKEY
        requests.get(uri, timeout=10)
    except Exception as e:
        pass
# pushplus  https://www.pushplus.plus/push1.html
def pushplus(text, msg,token):
    try:
        uri = 'https://www.pushplus.plus/send?token={}&title={}&content={}'.format(token,text, msg)# 将 xxxx 换成自己的pushplus的 token
        requests.get(uri, timeout=10)
    except Exception as e:
        pass
# 添加Telegram Bot推送支持
def tgbot(text, msg,token,group_id):
    import telegram
    try:
        bot = telegram.Bot(token='{}'.format(token))# Your Telegram Bot Token
        bot.send_message(chat_id=group_id, text='{}\r\n{}'.format(text, msg))
    except Exception as e:
        pass

#判断是否存在该CVE
def exist_cve(cve):
    try:
        query_cve_url = "https://cve.mitre.org/cgi-bin/cvename.cgi?name=" + cve
        response = requests.get(query_cve_url, timeout=10)
        html = etree.HTML(response.text)
        des = html.xpath('//*[@id="GeneratedTable"]/table//tr[4]/td/text()')[0].strip()
        return 1
    except Exception as e:
        return 0

# 根据cve 名字，获取描述，并翻译
def get_cve_des_zh(cve):
    try:
        query_cve_url = "https://cve.mitre.org/cgi-bin/cvename.cgi?name=" + cve
        response = requests.get(query_cve_url, timeout=10)
        html = etree.HTML(response.text)
        # 获取cve
        des = html.xpath('//*[@id="GeneratedTable"]/table//tr[4]/td/text()')[0].strip()
        cve_time = html.xpath('//*[@id="GeneratedTable"]/table//tr[11]/td[1]/b/text()')[0].strip()
        # 添加默认返回值
        if load_config()[-1]:
            translated = translate(des)
            # return translated or "翻译失败", cve_time  # 处理翻译返回None的情况
            return des,translated,cve_time
        else:
            return des, "",cve_time
    except Exception as e:
        print(f"获取CVE描述失败: {str(e)}")
        return "描述获取失败", "未知时间"  # 返回默认值

# 发送函数
def send_message(platform, text, body, config):
    try:
        if platform == "dingding":
            dingding(text, body, config.get("dingding_webhook"), config.get("dingding_secretKey"))
            print("钉钉 发送 CVE 成功")
        elif platform == "feishu":
            feishu(text, body, config.get("feishu_webhook")) #, config.get("dingding_secretKey"))  # 移除 secret 参数
            print("飞书 发送 CVE 成功")
        elif platform == "server":
            server(text, body, config.get("server_sckey"))
            print("server酱 发送 CVE 成功")
        elif platform == "pushplus":
            pushplus(text, body, config.get("pushplus_token"))
            print("pushplus 发送 CVE 成功")
        elif platform == "tgbot":
            tgbot(text, body, config.get("tgbot_token"), config.get("tgbot_group_id"))
            print("tgbot 发送 CVE 成功")
        else:
            print(f"不支持的平台: {platform}")
    except Exception as e:
        print(f"{platform} 发送消息失败: {e}")

# 发送CVE监控
def sendNews(data):
    try:
        text = '有新的CVE送达! \r\n** 请自行分辨是否为红队钓鱼!!! **\r\n** 有道翻译可能存在误差!!! **\r\n**监控机器人Author：MYXFC 公众号：密雾九尾 **'
        # 获取 cve 名字 ，根据cve 名字，获取描述，并翻译
        for i in range(len(data)):
            try:
                cve_name = re.findall(r'(CVE-\d+-\d+)', data[i]['cve_name'])[0].upper()
                # 接收三个返回值
                raw_des, translated_des, cve_time = get_cve_des_zh(cve_name)
                print(translated_des)
                body = (
                    f"CVE编号: {cve_name}  --- 收录时间 {cve_time} \r\n"
                    f"Github地址: {data[i]['cve_url']} \r\n"
                    f"CVE原文描述:\r\n{raw_des}\r\n"
                    f"CVE译文描述:\r\n{translated_des}"
                )

                # 获取所有配置
                configs, github_token, translate = load_config() # 获取全部配置和 github_token
                threads = []

                # 循环所有配置，并发发送
                for config in configs:
                    platform = config["type"]  # 获取平台类型
                    thread = threading.Thread(target=send_message, args=(platform, text, body, config))
                    threads.append(thread)
                    thread.start()

                # 等待所有线程执行完成
                for thread in threads:
                    thread.join()

            except IndexError:
                pass
    except Exception as e:
        print("sendNews 函数 error:{}".format(e))

# 发送关键字监控信息
def sendKeywordNews(keyword, data):
    try:
        text = '有新的关键字监控 - {} - 送达! \r\n** 请自行分辨是否为红队钓鱼!!!\r\n**监控机器人Author：MYXFC 公众号：密雾九尾 **'.format(keyword)
        # 获取 cve 名字 ，根据cve 名字，获取描述，并翻译
        for i in range(len(data)):
            try:
                keyword_name =  data[i]['keyword_name']
                body = "项目名称: " + keyword_name + "\r\n" + "Github地址: " + str(data[i]['keyword_url']) + "\r\n"

                # 获取所有配置
                configs, github_token, translate = load_config()
                threads = []

                # 循环所有配置，并发发送
                for config in configs:
                    platform = config["type"]  # 获取平台类型
                    thread = threading.Thread(target=send_message, args=(platform, text, body, config))
                    threads.append(thread)
                    thread.start()

                # 等待所有线程执行完成
                for thread in threads:
                    thread.join()

            except IndexError:
                pass
    except Exception as e:
        print("sendKeywordNews 函数 error:{}".format(e))

#main函数
if __name__ == '__main__':


    print("cve 、github 工具 和 大佬仓库 监控中 ...")
    #初始化部分
    create_database()

    while True:
        # 判断是否达到设定时间
        now = datetime.datetime.now()
        # 到达设定时间，结束内循环
        if now.hour == 23 and now.minute > 50:
            counter = {}    # 每天初始化黑名单

        tools_list, keyword_list, user_list = load_tools_list()
        tools_data = get_pushed_at_time(tools_list)
        tools_insert_into_sqlite3(tools_data)   # 获取文件中的工具列表，并从 github 获取相关信息，存储下来

        print("\r\n\t\t  用户仓库监控 \t\t\r\n")
        for user in user_list:
            getUserRepos(user)
        #CVE部分
        print("\r\n\t\t  CVE 监控 \t\t\r\n")
        cve_data = getNews()
        if len(cve_data) > 0 :
            today_cve_data = get_today_cve_info(cve_data)
            sendNews(today_cve_data)
            cve_insert_into_sqlite3(today_cve_data)

        print("\r\n\t\t  关键字监控 \t\t\r\n")
        # 关键字监控 , 最好不要太多关键字，防止 github 次要速率限制  https://docs.github.com/en/rest/overview/resources-in-the-rest-api#secondary-rate-limits=
        for keyword in keyword_list:
             time.sleep(1)  # 每个关键字停 1s ，防止关键字过多导致速率限制
             keyword_data = getKeywordNews(keyword)

             if len(keyword_data) > 0:
                today_keyword_data = get_today_keyword_info(keyword_data)
                if len(today_keyword_data) > 0:
                    sendKeywordNews(keyword, today_keyword_data)
                    keyword_insert_into_sqlite3(today_keyword_data)

        print("\r\n\t\t  红队工具监控 \t\t\r\n")
        time.sleep(5*60)
        tools_list_new, keyword_list, user_list = load_tools_list()
        data2 = get_pushed_at_time(tools_list_new)      # 再次从文件中获取工具列表，并从 github 获取相关信息,
        data3 = get_tools_update_list(data2)        # 与 3 分钟前数据进行对比，如果在三分钟内有新增工具清单或者工具有更新则通知一下用户
        for i in range(len(data3)):
            try:
                send_body(data3[i]['api_url'],data3[i]['pushed_at'],data3[i]['tag_name'])
            except Exception as e:
                print("main函数 try循环 遇到错误-->{}".format(e))
