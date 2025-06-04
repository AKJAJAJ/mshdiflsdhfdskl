#! /usr/bin/env python3
# coding  : utf-8
# @Author : Jor<jorhelp@qq.com>
# @Date   : Wed Apr 20 00:17:30 HKT 2022
# @Desc   : Webcam vulnerability scanning tool

#=================== 需放置于最开头 ====================
# 导入 gevent.monkey 并执行 patch_all 来使标准库非阻塞，thread=False 表示不修补 threading 模块
import warnings; warnings.filterwarnings("ignore")
from gevent import monkey; monkey.patch_all(thread=False)
#======================================================

import os
import sys
# import signal -> No longer needed here, Core handles its own
import gevent # gevent is still used by monkey_patch_all

from loguru import logger

from Ingram import get_config
from Ingram import Core
from Ingram.utils import color
from Ingram.utils import common
from Ingram.utils import get_parse
from Ingram.utils import log
from Ingram.utils import logo


# Removed handle_exit function as Core now manages SIGINT

def run():
    # Signal handlers are now registered within Core.run()

    try:
        # 打印应用 Logo
        for icon, font in zip(*logo):
            print(f"{color.yellow(icon, 'bright')}  {color.magenta(font, 'bright')}")

        # 加载和处理命令行参数及配置文件
        config = get_config(get_parse())
        # 如果输出目录不存在，则创建它
        if not os.path.isdir(config.out_dir):
            os.mkdir(config.out_dir)
            # 同时创建快照子目录
            os.mkdir(os.path.join(config.out_dir, config.snapshots))
        # 检查输入文件是否存在
        if not os.path.isfile(config.in_file):
            print(f"{color.red('the input file')} {color.yellow(config.in_file)} {color.red('does not exists!')}")
            sys.exit()

        # 配置 loguru 日志记录器
        log.config_logger(os.path.join(config.out_dir, config.log), config.debug)

        # 实例化核心扫描逻辑类 Core 并调用其 run 方法开始执行任务
        Core(config).run()

    except KeyboardInterrupt:
        # 处理用户通过 Ctrl+C 中断程序的情况
        # Core 类内部的信号处理器会首先尝试优雅关闭
        # 如果程序执行到此处，表示可能是 Core 未完全处理或作为最终的保障措施
        logger.warning('Ctrl + C pressed in run_ingram.py. Exiting...')
        sys.exit(1) # 以错误码1退出，表明非正常关闭

    except Exception as e:
        # 捕获其他所有未预料到的异常
        logger.error(e)
        print(f"{color.red('error occurred, see the')} {color.yellow(config.log)} "
              f"{color.red('for more information.')}")
        sys.exit(1) # 以错误码1退出


if __name__ == '__main__':
    run()
