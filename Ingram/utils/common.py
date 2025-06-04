"""通用工具"""
import os
import platform
import queue
import signal
import subprocess
from concurrent.futures import ThreadPoolExecutor
from loguru import logger # Added for logging


def os_check() -> str:
    """当前机器操作系统检测"""
    _os = platform.system().lower()
    if _os == 'windows': return 'windows'
    elif _os == 'linux': return 'linux'
    elif _os == 'darwin': return 'mac'
    else: return 'other'


def singleton(cls, *args, **kwargs):
    """单例模式"""
    instance = {}
    def wrapper(*args, **kwargs):
        if cls not in instance:
            instance[cls] = cls(*args, **kwargs)
        return instance[cls]
    return wrapper


class IngramThreadPool(ThreadPoolExecutor):
    """
    修改线程池的队列, 默认为无界队列, 当数据量大的时候会占满内存
    """

    def __init__(self, max_workers=None, thread_name_prefix=''):
        super().__init__(max_workers, thread_name_prefix)
        self._work_queue = queue.Queue(self._max_workers * 2)


def run_cmd(cmd_string, timeout=60):
    p = subprocess.Popen(cmd_string, stderr=subprocess.STDOUT, stdout=subprocess.PIPE, shell=True, close_fds=True,
                         start_new_session=True)
 
    if os_check() == 'windows': format = 'gbk'
    else: format = 'utf-8'
 
    try:
        (msg, errs) = p.communicate(timeout=timeout)
        ret_code = p.poll()
        if ret_code:
            code = 1
            msg = "[Error]Called Error: " + str(msg.decode(format))
        else:
            code = 0
            msg = str(msg.decode(format))
    except subprocess.TimeoutExpired:
        # 注意：不能只使用p.kill和p.terminate，无法杀干净所有的子进程，需要使用os.killpg
        p.kill()
        p.terminate()
        os.killpg(p.pid, signal.SIGTERM)
 
        # 注意：如果开启下面这两行的话，会等到执行完成才报超时错误，但是可以输出执行结果
        # 注意：如果开启下面这两行的话，会等到执行完成才报超时错误，但是可以输出执行结果
        # (outs, errs) = p.communicate() # Removed this unreliable post-kill communicate
        # msg = str(outs.decode(format)) # Removed

        logger.warning(f"Command '{cmd_string}' timed out after {timeout} seconds. Attempting to kill process group.")
        # p.kill() # kill() sends SIGKILL. terminate() sends SIGTERM.
        # p.terminate() # SIGTERM is usually preferred for graceful shutdown.
        # The os.killpg below should be sufficient if start_new_session=True was effective.
        # However, calling terminate first is a good practice.
        p.terminate()
        try:
            # For start_new_session=True, p.pid is the process group leader (PGID).
            # os.killpg sends the signal to the entire process group.
            os.killpg(p.pid, signal.SIGTERM) # Try SIGTERM first
            logger.info(f"Successfully sent SIGTERM to process group {p.pid} for command '{cmd_string}'.")
            # Optionally, wait a very short period and then send SIGKILL if still alive
            # p.wait(timeout=1) # This might hang if process doesn't die from SIGTERM
            # if p.poll() is None: # Check if process is still alive
            #    logger.warning(f"Process group {p.pid} for '{cmd_string}' did not terminate with SIGTERM, sending SIGKILL.")
            #    os.killpg(p.pid, signal.SIGKILL)
        except ProcessLookupError as ple:
            logger.warning(f"Failed to kill process group {p.pid} for '{cmd_string}': {ple}. Process might have already exited.")
        except Exception as e_kill:
            logger.error(f"Error during process group kill for command '{cmd_string}': {e_kill}")

        # Ensure p.kill() is called as a final attempt if the process is still there,
        # though os.killpg should handle children of the shell too.
        # If the shell itself (p.pid) is the only process, p.kill() might be needed if os.killpg fails.
        if p.poll() is None: # Check if process (shell) is still alive
             p.kill() # SIGKILL to the shell process
             logger.warning(f"Sent SIGKILL to main process {p.pid} for '{cmd_string}' as it was still alive after group kill attempts.")


        code = 1 # Indicate error due to timeout
        msg = f"[ERROR]Timeout Error: Command '{cmd_string}' timed out after {timeout} seconds"
    except Exception as e:
        code = 1
        msg = f"[ERROR]Unknown Error : {str(e)}" # Use f-string for consistency
 
    return code, msg