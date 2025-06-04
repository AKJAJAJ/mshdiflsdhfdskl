"""网络相关函数"""
import IPy
import random
import requests
from xml import etree # This is lxml.etree, used in scrapy_useragent
import json # For loading user agents from JSON
import os   # For path manipulation
from loguru import logger # For logging errors during UA loading


# Module-level cache for user agents
_cached_user_agents = None
_DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.84 Safari/537.36"
_MINIMAL_USER_AGENTS = {
    "random": [_DEFAULT_USER_AGENT],
    "Chrome": [_DEFAULT_USER_AGENT],
    "Firefox": ["Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:99.0) Gecko/20100101 Firefox/99.0"],
    # Add other specific fallbacks if necessary
}


def _load_user_agents():
    """
    Loads user agents from the JSON file.
    Caches them in _cached_user_agents.
    Returns the loaded dictionary or a minimal default if loading fails.
    """
    global _cached_user_agents
    if _cached_user_agents is not None:
        return _cached_user_agents

    try:
        # Construct path relative to this file's package (Ingram)
        # Ingram/utils/net.py -> Ingram/
        package_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        json_path = os.path.join(package_dir, 'data', 'user_agents.json')

        if not os.path.exists(json_path):
            logger.error(f"User agents file not found: {json_path}")
            _cached_user_agents = _MINIMAL_USER_AGENTS.copy() # Use a copy
            return _cached_user_agents

        with open(json_path, 'r', encoding='utf-8') as f:
            loaded_agents = json.load(f)
            # Ensure 'random' key exists if not explicitly in JSON, by merging all UAs
            if 'random' not in loaded_agents:
                all_uas = []
                for uas in loaded_agents.values():
                    all_uas.extend(uas)
                if all_uas: # only if there are any UAs at all
                    loaded_agents['random'] = list(set(all_uas)) # Use set to remove duplicates
                else: # if no UAs were loaded at all, add a default random
                    loaded_agents['random'] = _MINIMAL_USER_AGENTS['random']

            _cached_user_agents = loaded_agents
            logger.debug(f"User agents loaded successfully from {json_path}")

    except json.JSONDecodeError as e:
        logger.error(f"Error decoding user_agents.json: {e}")
        _cached_user_agents = _MINIMAL_USER_AGENTS.copy()
    except FileNotFoundError: # Should be caught by os.path.exists, but as a fallback
        logger.error(f"User agents file not found (FileNotFoundError): {json_path}")
        _cached_user_agents = _MINIMAL_USER_AGENTS.copy()
    except Exception as e:
        logger.error(f"An unexpected error occurred while loading user agents: {e}", exc_info=True)
        _cached_user_agents = _MINIMAL_USER_AGENTS.copy()

    return _cached_user_agents


def get_ip_segment(start: str, end: str) -> str:
    """根据 IP 获取 IP 段"""
    return IPy.IP(f"{start}-{end}", make_net=True).strNormal()


def get_ip_seg_len(ip_seg: str) -> int:
    """获取一个 IP 段内的 IP 数目"""
    if '-' in ip_seg or '/' in ip_seg:
        return IPy.IP(ip_seg, make_net=True).len()
    else:
        return 1


def get_all_ip(ip_seg: str) -> list:
    """获取一个 IP 段内的所有 IP"""
    if '-' in ip_seg or '/' in ip_seg:
        return [i.strNormal() for i in IPy.IP(ip_seg, make_net=True)]
    else:
        return [ip_seg]


def scrapy_useragent() -> None:
    """
    User-Agent 爬虫.
    此函数用于从 useragentstring.com 网站爬取 User-Agent 字符串，
    并打印出 Python 字典格式的结果。其输出可用于生成 user_agents.json 文件的内容。
    注意: 直接运行此函数会将结果打印到控制台。
    """
    base_url = 'https://useragentstring.com/pages/'
    browsers = ['Chrome', 'Firefox', 'Edge', 'Safari', 'Opera']
    res = {i:[] for i in browsers}
    for browser in browsers:
        url = f"{base_url}{browser}/"
        page = requests.get(url)
        tree = etree.HTML(page.text)
        items = tree.xpath('/html/body/div[2]/div[2]/div/ul')
        # 拿取前 100 条，因为后面的都是比较老旧的浏览器版本
        for i in items[:100]:  
            res[browser].append(i.xpath('li/a')[0].text)
    print(res)


def get_user_agent(name='random') -> str:
    """
    获取一个 User-Agent 字符串。
    数据从 Ingram/data/user_agents.json 文件加载。
    name: 'random' (默认) 或指定浏览器名称 (如 'Chrome', 'Firefox')。
    """
    agents_dict = _load_user_agents() # 加载 (可能从缓存) User-Agent 数据

    if not agents_dict: # 如果加载失败或数据为空
        logger.warning("User-Agent 数据为空或加载失败，返回默认 UA。")
        return _DEFAULT_USER_AGENT

    selected_uas = None
    if name in agents_dict:
        selected_uas = agents_dict[name]
    elif name == 'random': # 'random' key should exist due to _load_user_agents logic
        selected_uas = agents_dict.get('random')

    if not selected_uas: # Fallback if specific name not found or 'random' list is empty
        logger.warning(f"名为 '{name}' 的 User-Agent 列表未找到或为空，尝试从所有 User-Agent 中随机选择。")
        # Fallback to a truly random choice from all available UAs if 'random' list is somehow empty
        all_uas = []
        for uas_list in agents_dict.values():
            if isinstance(uas_list, list): # Ensure it's a list
                 all_uas.extend(uas_list)
        if all_uas:
            selected_uas = all_uas # random.choice will pick one from this flat list
        else: # Ultimate fallback if everything is empty
            logger.error("所有 User-Agent 列表均为空，返回硬编码的默认 UA。")
            return _DEFAULT_USER_AGENT

    return random.choice(selected_uas) if selected_uas else _DEFAULT_USER_AGENT


if __name__ == '__main__':
    # print(get_ip_segment('2.56.8.0', '2.56.9.255'))
    # print(get_all_ip('192.168.0.1/31'))
    # print(get_all_ip('2.56.8.0-2.56.9.255'))
    print(get_user_agent('random'))
    # scrapy_useragent()