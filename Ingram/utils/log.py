"""日志相关"""
from loguru import logger

def no_debug(record):
    # 日志过滤函数：当配置为非 debug 模式时，此过滤器用于排除 'ERROR' 和 'DEBUG' 级别的日志记录。
    # record: loguru 传递的日志记录对象。
    # 返回值: 布尔值，True 表示该记录应被处理，False 表示应被忽略。
    # 因此，当级别不是 ERROR 也不是 DEBUG 时，返回 True (允许记录)。
    return record['level'].name != 'ERROR' and record['level'].name != 'DEBUG'


def config_logger(log_file, debug=False):
    # 配置 loguru 日志记录器。
    # log_file: 日志文件的完整路径。
    # debug: 布尔值，如果为 True，则记录所有级别的日志 (包括 DEBUG 和 ERROR)；
    #        如果为 False，则通过 no_debug 过滤器排除 DEBUG 和 ERROR 级别的日志。

    # 移除所有先前可能已添加的 loguru 处理器 (handler)，
    # 以确保从一个干净的状态开始配置，避免重复输出或不期望的日志行为。
    # handler_id=None 表示移除所有处理器。
    logger.remove(handler_id=None)

    # 定义日志记录的格式字符串。
    # {time:YYYY-MM-DD HH:mm:ss}: 时间戳，格式化为年-月-日 时:分:秒。
    # {level}: 日志级别 (例如 INFO, WARNING, ERROR)。
    # {module}.{function}: 记录日志的模块名和函数名。
    # {message}: 实际的日志消息内容。
    _format = "[{time:YYYY-MM-DD HH:mm:ss}][{level}][{module}.{function}] {message}"

    # 根据 debug 参数的值来决定是否应用日志过滤器。
    log_filter_func = None # 默认为不过滤
    if not debug:
        # 如果不是 debug 模式，则设置过滤器为 no_debug 函数，
        # 该函数会阻止 'ERROR' 和 'DEBUG' 级别的消息被写入文件。
        log_filter_func = no_debug

    # 添加一个新的日志处理器 (sink)，用于将日志消息写入指定的日志文件。
    logger.add(
        log_file,             # 日志文件的路径。
        format=_format,       # 应用上面定义的日志格式。
        filter=log_filter_func, # 应用条件过滤器 (如果 debug=False，则为 no_debug；否则为 None)。
        rotation="200 MB",    # 日志轮转设置：当日志文件达到 200MB 大小时，会自动创建新的日志文件。
        encoding="utf-8",     # 明确指定日志文件的编码为 UTF-8，确保兼容性。
        level="DEBUG" if debug else "INFO" # 如果是debug模式，文件日志级别从DEBUG开始，否则从INFO开始
                                            # 注意: no_debug 过滤器是在此级别之上再进行过滤的。
                                            # 例如，非debug模式下，INFO级别的ERROR日志仍会被no_debug过滤掉。
                                            # (因为 no_debug 显式排除了 'ERROR')
                                            # 如果希望非debug模式记录ERROR，no_debug应为: record['level'].name != 'DEBUG'
                                            # 这里我们保持原始 no_debug 过滤逻辑，仅通过注释阐明其行为。
    )
    logger.info(f"日志已配置。Debug 模式: {debug}。日志文件: {log_file}")