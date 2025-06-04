import os
import requests
from collections import namedtuple

from loguru import logger

# PoC (Proof of Concept) 模板类
# 所有具体的 PoC 脚本都应继承自此类。
# 它提供了 PoC 的基本结构、注册机制以及一些辅助方法。
class POCTemplate:
    # 定义漏洞等级常量，方便 PoC 脚本引用。
    # level.high: 高危
    # level.medium: 中危
    # level.low: 低危
    level = namedtuple('level', 'high medium low')('高', '中', '低')

    # poc_classes 用于存储所有已注册的 PoC 类。
    # PoC 脚本通过调用 register_poc 方法将自身注册到这个列表中。
    poc_classes = []

    @staticmethod
    def register_poc(poc_class_to_register): # 参数名从 self 改为 poc_class_to_register 以明确其含义
        # 静态方法，用于将 PoC 类注册到 POCTemplate 的 poc_classes 列表中。
        # poc_class_to_register: 需要注册的 PoC 类本身。
        # 每个 PoC 脚本文件末尾会调用此方法来注册自己。
        POCTemplate.poc_classes.append(poc_class_to_register)

    def __init__(self, config):
        # 初始化 PoC 实例。
        # config: 全局配置对象，包含输出目录、超时时间、User-Agent 等信息。
        self.config = config

        # poc 名称: 默认使用当前 PoC 脚本的文件名 (不含扩展名)。
        # 子类可以覆盖此属性以指定一个更友好的名称。
        self.name = self.get_file_name(__file__)

        # poc 所针对的应用/产品名称。
        # 子类必须覆盖此属性，指明 PoC 适用的具体产品 (例如 'hikvision', 'dahua-dvr')。
        self.product = 'base' # 默认为 'base'，子类应具体指定

        # poc 所针对的应用/产品版本范围。
        # 例如 "1.0-2.5", "all", "<3.0"。默认为空字符串。
        self.product_version = ''

        # 漏洞相关信息的参考链接 (例如 CVE 编号、漏洞分析文章等)。
        self.ref = ''

        # 漏洞等级: 默认为低危。
        # 子类应根据实际漏洞的危害程度设置此属性 (例如 self.level.high)。
        self.level = self.level.low

        # 漏洞描述: 对漏洞的简要说明。
        self.desc = """""" # 子类应填充此描述

    def get_file_name(self, file_path: str) -> str:
        # 工具方法，从给定的文件路径中提取文件名 (不含扩展名)。
        # file_path: 文件的完整路径或相对路径。
        return os.path.basename(file_path).split('.')[0]

    def verify(self, ip: str, port: str) -> tuple or None:
        # 验证目标是否存在指定漏洞的核心方法。
        # 此方法必须由每个具体的 PoC 子类覆盖并实现。
        # ip: 目标 IP 地址 (字符串)。
        # port: 目标端口号 (字符串或数字，建议 PoC 内部处理好类型)。
        # 返回值:
        #   - 如果验证成功 (漏洞存在)，应返回一个包含多个元素的元组，
        #     通常格式为 (ip, port, self.product, user, password, self.name, other_info...)。
        #     这些信息会被记录到结果文件中。至少应包含前三个元素。
        #   - 如果验证失败 (漏洞不存在或无法确认)，应返回 None。
        pass # 子类必须实现此方法

    def _snapshot(self, url: str, img_file_name: str, auth=None) -> int:
        # 内部辅助方法，用于从指定的 URL 下载图片并保存到快照目录。
        # url: 要下载图片的完整 URL。
        # img_file_name: 图片保存时的文件名 (不含路径)。
        # auth: 可选的 requests 认证对象 (例如 HTTPDigestAuth)。
        # 返回值: 1 表示成功下载并保存图片，0 表示失败。

        # 构建图片在快照目录中的完整路径
        img_path = os.path.join(self.config.out_dir, self.config.snapshots, img_file_name)
        # 设置请求头，包括 User-Agent 和 Connection: close (避免保持长连接)
        headers = {'Connection': 'close', 'User-Agent': self.config.user_agent}
        try:
            # 根据是否提供了 auth 对象，发送 GET 请求
            # stream=True: 允许流式下载，适用于大文件，避免一次性将所有内容读入内存。
            # verify=False: 忽略 SSL/TLS 证书验证 (在安全测试工具中常见，但需注意风险)。
            # timeout: 使用配置中定义的超时时间。
            if auth:
                res = requests.get(url, auth=auth, timeout=self.config.timeout, verify=False, headers=headers, stream=True)
            else:
                res = requests.get(url, timeout=self.config.timeout, verify=False, headers=headers, stream=True)

            # 检查响应状态码是否为 200 (OK)
            # 'head' not in res.text: 一个简单的检查，尝试排除返回HTML错误页面的情况 (假设图片内容不含'head')。
            # 注意: 这个检查可能不够健壮，更可靠的方式是检查 Content-Type header (e.g., 'image/jpeg').
            # 另外，对于 stream=True 的响应，直接访问 res.text 可能会消耗整个流，应谨慎使用。
            # 更好的做法是先检查 res.status_code，然后直接处理 res.content 或 res.iter_content。
            # 考虑到原始逻辑，我们暂时保留，但标记为潜在改进点。
            if res.status_code == 200:
                # 检查 Content-Type 是否表明是图片，避免保存错误页面为图片
                content_type = res.headers.get('Content-Type', '').lower()
                if 'image' in content_type or ('application/octet-stream' in content_type and img_file_name.lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.bmp'))): # application/octet-stream for some cameras
                    with open(img_path, 'wb') as f: # 以二进制写模式打开文件
                        # 迭代读取响应内容，每次读取 10KB (10240 bytes)
                        for content in res.iter_content(10240):
                            f.write(content) # 将读取到的内容块写入文件
                    logger.info(f"快照已成功保存到: {img_path}")
                    return 1 # 返回1表示成功
                else:
                    logger.warning(f"下载快照 ({url}) 失败：响应的内容类型 ({content_type}) 不是预期的图片类型。")
                    # 尝试读取少量文本内容以记录可能存在的错误信息 (仅当非图片时)
                    try:
                        error_text_snippet = res.text[:200] if not res.is_closed else "<response closed>"
                        logger.debug(f"快照URL ({url}) 响应内容片段: {error_text_snippet}")
                    except Exception: # res.text might fail if content is binary and large
                        logger.debug(f"快照URL ({url}) 响应内容片段无法读取为文本。")
            else:
                logger.warning(f"下载快照 ({url}) 失败：HTTP 状态码 {res.status_code}。")

        except requests.exceptions.Timeout:
            logger.warning(f"下载快照超时: {url} (超时时间: {self.config.timeout}s)")
        except requests.exceptions.ConnectionError as e_conn:
            logger.warning(f"下载快照时发生连接错误 ({url}): {e_conn}")
        except requests.exceptions.RequestException as e_req: # 其他 requests 异常
            logger.warning(f"下载快照时发生请求错误 ({url}): {e_req}")
        except IOError as e_io:
            logger.error(f"保存快照到文件时发生IO错误 ({img_path}): {e_io}")
        except Exception as e:
            # 捕获其他所有未知异常
            logger.error(f"下载或保存快照 ({url}) 时发生未知错误: {e}", exc_info=True)

        # logger.warning(f"快照获取失败: {url}") # 此日志可能冗余，因为具体错误已记录
        return 0 # 返回0表示失败

    def exploit(self, results: tuple) -> int:
        # 默认的 exploit 实现。
        # 在 Ingram 项目中，exploit 方法主要用于获取漏洞的快照 (snapshot)。
        # 如果具体的 PoC 脚本没有覆盖此方法，则默认不执行任何操作或不获取快照。
        # results: self.verify 方法成功时的返回结果元组。
        # 返回值: 整数，代表获取的快照数量 (或其他利用成果的度量)。
        #         默认返回0，表示没有获取到快照。
        # 子类应根据实际漏洞利用情况覆盖此方法。
        # 例如，如果漏洞可以用于获取截图，则调用 self._snapshot(...)。
        return 0 # 默认不执行任何利用操作