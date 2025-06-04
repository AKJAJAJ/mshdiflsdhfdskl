"""主机存活检测"""
import os
import subprocess
from .common import os_check # Assuming os_check is here
from loguru import logger # Assuming logger is standard

def _ping(target: str, nums: int, timeout: int) -> bool:
    # _ping 函数通过执行系统 ping 命令来检测目标主机的存活状态。
    # target: 目标主机名或 IP 地址。
    # nums: 发送 ping 请求的次数。
    # timeout: ping 命令的超时时间 (秒)。注意，Windows的ping -w参数单位是毫秒。
    #          此处的timeout也用于 subprocess.communicate 的超时。
    # 返回值: True 如果检测到存活 (通过输出中是否包含 'ttl')，否则 False。

    current_os = os_check()
    command = []

    if current_os == 'windows':
        # Windows: -n 是次数, -w 是超时时间 (毫秒)
        command = ['ping', '-n', str(nums), '-w', str(timeout * 1000), target]
    elif current_os == 'linux':
        # Linux: -c 是次数, -W 是每次回复的超时时间 (秒), -w 是总超时时间 (deadline)
        # Using -W for per-packet timeout and -c for count is common.
        # Using -w for overall deadline. Choose one that best fits the 'timeout' semantic.
        # Let's use -w for overall deadline for consistency with desired behavior.
        command = ['ping', '-c', str(nums), '-w', str(timeout), target]
    elif current_os == 'mac':
        # macOS: -c 是次数, -t 是总超时时间 (秒)
        command = ['ping', '-c', str(nums), '-t', str(timeout), target]
    else:
        logger.warning(f"操作系统 '{current_os}' 的 ping 命令参数未知，存活检测可能不准确或失败。")
        # 对于未知操作系统，可以尝试一个通用格式或直接返回 False
        # Defaulting to a common syntax, but this might fail or behave unexpectedly.
        command = ['ping', '-c', str(nums), target]

    if not command: # Should ideally not happen if os_check covers common cases or has a fallback.
        logger.error("Ping command list could not be constructed.")
        return False

    try:
        # 打开 os.devnull 以重定向 ping 命令的 stderr，避免错误信息污染控制台
        with open(os.devnull, 'w') as dev_null:
            # 执行 ping 命令，不使用 shell=True
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=dev_null)

            # 等待命令完成或超时 (communicate 的超时应该是整体操作的超时)
            # 设置 communicate 的超时，确保 Python 脚本不会无限期等待。
            # This timeout should ideally be slightly larger than the ping command's own total timeout,
            # if the ping command's timeout mechanism is reliable.
            # Given ping's -w (deadline on Linux) or -t (total timeout on Mac),
            # `timeout` param for `_ping` should be the primary timeout control.
            # `communicate` timeout is a safeguard for the Popen call.
            stdout_data, _ = process.communicate(timeout=timeout + 2) # Adding a small buffer

        # 解码标准输出。忽略解码错误，以防出现意外的字符编码。
        output_str = stdout_data.decode('utf-8', errors='ignore').lower()

        # 通过检查输出中是否包含 'ttl' (Time To Live) 来判断主机是否存活。
        # 这是一个常用的启发式方法，因为存活主机的 ping 回复通常包含 TTL 信息。
        # 同时检查返回码，0 通常表示成功。
        if process.returncode == 0 and 'ttl' in output_str:
            logger.debug(f"主机 {target} 存活 (响应包含 TTL，返回码 0)。")
            return True
        else:
            logger.debug(f"主机 {target} 可能不存活。返回码: {process.returncode}, TTL检测: {'ttl' in output_str}。输出: {output_str[:200]}...") # Log snippet of output
            return False

    except subprocess.TimeoutExpired:
        # 此异常由 process.communicate(timeout=...) 抛出
        logger.debug(f"对主机 {target} 的 ping 操作 (subprocess.communicate) 超时。")
        if 'process' in locals() and process.poll() is None: # Check if process exists and is running
            try:
                process.kill() # 尝试终止进程
                logger.debug(f"已终止超时的 ping 进程 {process.pid} for {target}。")
            except Exception as kill_e:
                logger.error(f"终止超时的 ping 进程 {target} 时出错: {kill_e}")
        return False
    except FileNotFoundError:
        # 如果系统中找不到 ping 命令 (例如，未安装或不在 PATH 环境变量中)
        logger.error("Ping 命令未找到。请确保 ICMP 工具已安装并在系统 PATH 中。")
        return False
    except Exception as e:
        # 捕获其他在执行 ping 命令过程中可能发生的未知异常
        logger.error(f"对主机 {target} 执行 ping 时发生错误: {e}", exc_info=True)
        return False

def alive_check(target: str, timeout: int=2) -> bool:
    # alive_check 是一个公开接口，用于检测目标主机是否存活。
    # target: 目标主机名或 IP 地址。
    # timeout: 超时时间 (秒)，将传递给 _ping 函数。默认为2秒。
    # 它调用内部的 _ping 函数，默认发送2个 ping 包进行检测。
    return _ping(target, 2, timeout)