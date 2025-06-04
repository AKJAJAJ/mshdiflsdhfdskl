"""状态栏"""
import random
import time
# from Ingram.core import Core # 可选，用于类型提示 (Core passed as arg)
from loguru import logger # 导入 logger

from threading import Thread # Added for StatusBarManager
from . import timer
from .color import color


# _bar remains a helper function, internal to this module or could be part of the class
def _bar_display_logic(): # Renamed to avoid conflict if StatusBarManager also has _bar
    cidx=[0]
    icon_list = random.choice([
        '⇐⇖⇑⇗⇒⇘⇓⇙',
        '⣾⣷⣯⣟⡿⢿⣻⣽',
        '⠁⠉⠙⠛⠚⠒⠂⠃⠋⠛⠙⠘⠐⠒⠓⠛⠋⠉⠈⠘⠚⠛⠓⠃',
        '⠿⠷⠯⠟⠻⠽⠾⠿⠷⠧⠇⠃⠁ ⠁⠉⠙⠹⠽',
        '▁▂▃▅▆▇▆▅▃▂▁ ',
        '➩➫➬',
        '😶😶😕😕😦😦😧😧😨😨😀😀😃😃😄😄😆😆😊😊😉😉',
        '🧍🧍🚶🚶🤾🤾🏃🏃🤾🤾🚶🚶',
        '🕛🕐🕑🕒🕓🕔🕕🕖🕗🕘🕙🕚',
    ])

    def wrapper(total, done, found, snapshot, time_used):
        # icon - 动态图标选择与更新
        icon = color.green(icon_list[cidx[0]], 'bright')
        cidx[0] = (cidx[0] + 1) % len(icon_list)
        icon = f"[{icon}]"

        # time - 计算并格式化已用时间和预计总时间
        time_pred = time_used * (total / (done + 0.001))  # 预计总时间 (避免除以零)
        time_used_f = color.cyan(timer.time_formatter(time_used), 'bright') # 已用时间格式化
        time_pred_f = color.white(timer.time_formatter(time_pred), 'bright') # 预计总时间格式化
        _time = f"Time: {time_used_f}/{time_pred_f}"

        # count - 格式化显示扫描进度、已发现漏洞数、已完成快照数
        _total = color.blue(total, 'bright')
        _done = color.blue(done, 'bright')
        _percent = color.yellow(f"{round(done / (total + 0.001) * 100, 1)}%", 'bright') # 完成百分比
        _found = 'Found ' + color.red(found, 'bright') if found else '' # 已发现数
        _snapshot = 'Snapshot ' + color.red(snapshot, 'bright') if snapshot else '' # 快照数
        count = f"{_done}/{_total}({_percent}) {_found} {_snapshot}"

        # 最终打印状态栏字符串
        print(f"\r{icon} {count} {_time}        ", end='')
    return wrapper


class StatusBarManager:
    def __init__(self, core_instance):
        self.core_instance = core_instance # Core 类的实例
        self.thread = None # 状态栏显示线程
        self._bar_calculator = _bar_display_logic() # 获取实际的打印函数 (wrapper)

    def _get_current_bar_string_lambda(self):
        # 定义一个 lambda 函数 print_bar，用于方便地调用 _bar_calculator 并传递所需参数
        # 这些参数从 core_instance 中获取，反映了当前的扫描进度和状态
        return lambda: self._bar_calculator(
            self.core_instance.data.total,                            # 目标总数
            self.core_instance.data.done,                             # 已完成目标数
            self.core_instance.data.found,                            # 已发现漏洞/目标数
            self.core_instance.snapshot_pipeline.get_done(),          # 已完成快照数
            timer.get_time_stamp() - self.core_instance.data.create_time + self.core_instance.data.runned_time  # 总运行时间
        )

    def _run_status_display(self):
        """根据 core_instance 中的数据持续绘制状态栏 (线程执行体)"""
        print_bar_lambda = self._get_current_bar_string_lambda()

        # 状态栏主循环
        # 持续更新状态，直到核心任务完成 (core_instance.finish() 为 True)
        # 或收到关闭信号 (core_instance.shutdown_event.is_set() 为 True)
        while not self.core_instance.finish() and not self.core_instance.shutdown_event.is_set():
            print_bar_lambda() # 调用 lambda 函数更新并打印状态栏
            time.sleep(.1) # 每隔 0.1 秒更新一次状态栏, 避免CPU占用过高

        # 循环结束后（任务完成或收到关闭信号），最后打印一次状态条以显示最终状态
        print_bar_lambda()

        # 根据退出原因记录不同的日志信息
        if self.core_instance.shutdown_event.is_set():
            logger.info("状态栏线程因收到关闭信号而退出。")
        else:
            logger.info("状态栏线程因所有任务完成而正常退出。")

    def start(self):
        """启动状态栏显示线程"""
        if self.thread is None or not self.thread.is_alive():
            self.thread = Thread(target=self._run_status_display, daemon=True)
            self.thread.start()
            logger.info("StatusBarManager 线程已启动。")
        else:
            logger.info("StatusBarManager 线程已经在运行。")

    def join_thread(self, timeout=None):
        """等待状态栏显示线程结束"""
        if self.thread and self.thread.is_alive():
            logger.info(f"等待 StatusBarManager 线程结束 (超时时间: {timeout}s)...")
            self.thread.join(timeout)
            if self.thread.is_alive():
                logger.warning(f"StatusBarManager 线程在超时 ({timeout}s) 后未能结束。")
            else:
                logger.info("StatusBarManager 线程已成功结束。")
        else:
            logger.info("StatusBarManager 线程未运行或已结束，无需等待。")