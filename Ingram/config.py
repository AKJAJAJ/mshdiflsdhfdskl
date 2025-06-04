"""全局配置项"""
import os
import sys # 导入 sys 模块以使用 sys.exit
from collections import namedtuple
from loguru import logger # 导入 loguru 日志记录器

from .utils import net # 用于获取 User-Agent

# _config 字典存储了应用的默认配置。
# 这些配置项可以在程序运行时通过命令行参数进行覆盖。
_config = {
    # --- 认证相关 ---
    'users': ['admin'],  # 默认尝试的用户名列表
    'passwords': ['admin', 'admin12345', 'asdf1234', 'abc12345', '12345admin', '12345abc'],  # 默认尝试的密码列表

    # --- HTTP 请求相关 ---
    'user_agent': net.get_user_agent(),  # 默认 User-Agent, 通过 net.py 获取 (在模块加载时获取一次以节省时间)
    'ports': [80, 81, 82, 83, 84, 85, 88, 8000, 8001, 8080, 8081, 8085, 8086, 8088, 8090, 8181, 2051, 9000, 37777, 49152, 55555],  # 默认扫描的端口列表

    # --- 指纹规则 (从 rules.csv 加载) ---
    'product': {},  # 用于存储从 rules.csv 中提取的所有产品名称 (product: product)
    'rules': set(), # 用于存储从 rules.csv 中加载的指纹规则对象 (Rule namedtuple)

    # --- 输出文件和目录名 ---
    'log': 'log.txt',  # 日志文件名
    'not_vulnerable': 'not_vulnerable.csv',  # 未发现漏洞的目标列表文件名
    'vulnerable': 'results.csv',  # 发现漏洞的结果文件名 (易受攻击列表)
    'snapshots': 'snapshots',  # 漏洞快照 (截图) 存储的子目录名

    # --- 微信通知 (可选功能) ---
    'wxuid': '',   # 微信用户ID，用于接收通知
    'wxtoken': '', # 微信应用Token，用于发送通知
}


def get_config(args=None):
    # get_config 函数负责加载和整合应用的配置。
    # 它首先加载默认配置 (定义在全局 _config 字典中)，
    # 然后从 rules.csv 文件加载指纹规则，
    # 接着合并传入的命令行参数 (args)，
    # 最后返回一个不可变的 namedtuple 对象，方便以属性方式访问配置项。

    # --- 加载指纹规则 ---
    Rule = namedtuple('Rule', ['product', 'path', 'val']) # 定义规则的数据结构
    # 定位 rules.csv 文件，假设它与 config.py 在同一目录下 (即 Ingram 目录中)
    rules_file_path = os.path.join(os.path.dirname(__file__), 'rules.csv')

    # 确保 _config['rules'] 和 _config['product'] 在多次调用或重试时被正确初始化
    # (注意: _config 是模块级全局变量，此函数通常只在启动时调用一次。
    #  如果确实需要多次调用并重新加载规则，则此重置是必要的。)
    _config['rules'] = set()
    _config['product'] = {}

    try:
        # 以 UTF-8 编码读取规则文件
        with open(rules_file_path, 'r', encoding='utf-8') as f:
            logger.info(f"正在从 {rules_file_path} 加载指纹规则...")
            for line_num, line_content in enumerate(f, 1):
                stripped_line = line_content.strip()
                # 跳过空行和以 '#' 开头的注释行
                if not stripped_line or stripped_line.startswith('#'):
                    continue

                try:
                    # 按逗号分割规则行，最多分割两次 (product, path, val)
                    # 这样允许 'val' 部分本身包含逗号
                    product, path, val = stripped_line.split(',', 2)
                    # 去除各部分可能存在的多余空格
                    product = product.strip()
                    path = path.strip()
                    val = val.strip()

                    _config['rules'].add(Rule(product, path, val))
                    _config['product'][product] = product # 存储产品名称，用于后续查找
                except ValueError:
                    # 如果行内容无法按期望分割（例如，逗号数量不足2个）
                    logger.warning(f"规则文件 {rules_file_path} 第 {line_num} 行格式错误 (应为 'product,path,value')，已跳过: '{stripped_line}'")
            logger.info(f"成功加载 {len(_config['rules'])} 条指纹规则。")
    except FileNotFoundError:
        logger.critical(f"关键规则文件 {rules_file_path} 未找到！程序无法继续。")
        sys.exit(1) # 终止程序执行
    except IOError as e:
        logger.critical(f"读取规则文件 {rules_file_path} 时发生IO错误: {e}！程序无法继续。", exc_info=True)
        sys.exit(1) # 终止程序执行
    except Exception as e:
        logger.critical(f"加载规则文件 {rules_file_path} 时发生未知错误: {e}！程序将终止。", exc_info=True)
        sys.exit(1) # 对于其他未知关键错误也终止

    # --- 合并命令行参数 ---
    # args 是通过 argparse 解析后的命令行参数对象 (通常是一个 Namespace 实例)
    if args:
        logger.debug(f"开始合并命令行参数: {vars(args)}")
        # vars(args) 将 argparse 的 Namespace 对象转换为字典，方便遍历
        for arg_name, arg_value in vars(args).items():
            # 只有当命令行参数被实际提供时 (其值不为 None)，才用它覆盖 _config 中的默认值。
            # 这确保了 argparse 中定义的默认值 (如果用户未指定参数) 不会错误地覆盖 _config 中的初始设置，
            # 特别是当 _config 中的默认值与 argparse 的默认值不同时。
            if arg_value is not None:
                _config[arg_name] = arg_value
                logger.debug(f"配置项 '{arg_name}' 从命令行更新为: '{arg_value}'")

    # --- 创建并返回不可变的配置对象 ---
    # 使用 _config 字典的键创建一个名为 'config' 的 namedtuple 类
    # namedtuple 实例是轻量级的，并且可以通过属性名访问其元素，代码更易读。
    ConfigTuple = namedtuple('config', _config.keys())
    # 使用 _config 字典的值实例化这个 namedtuple
    final_config = ConfigTuple(**_config)

    logger.info(f"配置加载完成。最终生效配置 (部分摘要): ports={final_config.ports}, th_num={getattr(final_config, 'th_num', 'N/A')}, timeout={final_config.timeout}")
    return final_config