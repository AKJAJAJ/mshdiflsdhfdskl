"""logo生成与资源加载"""
import os
import random
from loguru import logger

# 确定资源文件相对于当前包 (Ingram) 的路径
# Ingram/utils/logo.py -> Ingram/utils/ -> Ingram/
_INGRAM_PACKAGE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_ASSETS_DIR = os.path.join(_INGRAM_PACKAGE_DIR, "assets")
_ICON_FILE = os.path.join(_ASSETS_DIR, "ingram_icon.txt")
_FONTS_DIR = os.path.join(_ASSETS_DIR, "fonts")

# 默认的最小化艺术字，以防文件加载失败
_DEFAULT_ICON_STR = " I " # Added spaces for some width
_DEFAULT_FONT_STR = " Ingram " # Added spaces for some width
_DEFAULT_ICON_LINES = [_DEFAULT_ICON_STR]
_DEFAULT_FONT_LINES = [_DEFAULT_FONT_STR]


def _load_art_from_file(filepath: str) -> str:
    """
    从指定文件路径加载艺术字文本。
    filepath: 艺术字文件的完整路径。
    返回: 文件内容字符串；如果加载失败，则返回空字符串。
    """
    # 从指定文件路径加载 ASCII Art 文本。
    # filepath: ASCII art 文件的路径。
    # 返回: 文件内容 (字符串) 或在失败时返回空字符串。
    if not os.path.exists(filepath): # Explicit check before opening
        logger.error(f"艺术字文件路径不存在: {filepath}")
        return ""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return f.read()
    except FileNotFoundError: # Should be caught by os.path.exists, but as a safeguard
        logger.error(f"艺术字文件未找到: {filepath}")
        return ""
    except IOError as e:
        logger.error(f"读取艺术字文件时发生IO错误 ({filepath}): {e}")
        return ""
    except Exception as e:
        logger.error(f"加载艺术字文件时发生未知错误 ({filepath}): {e}", exc_info=True)
        return ""


def _load_random_font() -> str:
    """
    从字体资源目录中随机加载一个字体文件。
    返回: 随机选择的字体文件内容字符串；如果失败，则返回空字符串。
    """
    # 从字体目录随机加载一个字体。
    # 返回: 字体字符串或在失败时返回空字符串。
    try:
        if not os.path.isdir(_FONTS_DIR):
            logger.error(f"字体目录未找到: {_FONTS_DIR}")
            return ""

        font_files = [f for f in os.listdir(_FONTS_DIR) if f.endswith(".txt") and os.path.isfile(os.path.join(_FONTS_DIR, f))]
        if not font_files:
            logger.error(f"字体目录 {_FONTS_DIR} 中没有找到 .txt 字体文件。")
            return ""

        random_font_file = random.choice(font_files)
        font_path = os.path.join(_FONTS_DIR, random_font_file)
        logger.debug(f"随机选择字体文件: {font_path}")
        return _load_art_from_file(font_path)
    except Exception as e:
        logger.error(f"加载随机字体时发生未知错误: {e}", exc_info=True)
        return ""


def _pad_art_vertically(art_lines: list, target_height: int, art_width: int) -> list:
    """
    在垂直方向上填充艺术字线条列表，使其达到目标高度。
    art_lines: 代表艺术字的字符串列表 (每行一个字符串)。
    target_height: 期望的总高度 (行数)。
    art_width: 艺术字原始宽度，用于生成空白填充行。
    返回: 经过垂直填充的艺术字线条列表。
    """
    # 垂直填充 ASCII art 线条列表以达到目标高度。
    current_height = len(art_lines)
    delta_height = target_height - current_height

    if delta_height <= 0: # 如果当前高度已满足或超过目标高度，则无需填充
        return art_lines

    pad_top = delta_height // 2
    pad_bottom = delta_height - pad_top

    # 创建一个适当宽度的空白行, 如果 art_width 为0, 则空白行为空字符串
    empty_line = ' ' * art_width if art_width > 0 else ''

    # 执行填充
    padded_art = ([empty_line] * pad_top) + art_lines + ([empty_line] * pad_bottom)
    return padded_art


def generate_logo() -> list:
    """
    加载图标和随机字体，处理尺寸和对齐，然后返回准备打印的logo组件。
    返回: 一个包含两个元素的列表：[处理后的图标线条列表, 处理后的字体线条列表]。
    """
    # 加载图标和字体字符串
    icon_str = _load_art_from_file(_ICON_FILE)
    font_str = _load_random_font()

    # 如果加载失败或内容为空，使用内置的最小默认值
    if not icon_str or not icon_str.strip():
        logger.warning("图标文件加载失败或为空，使用默认图标。")
        icon_lines = list(_DEFAULT_ICON_LINES)
    else:
        # 移除字符串首尾可能存在的空行，然后按行分割，并过滤掉完全是空白（或回车）的行
        icon_lines = [line for line in icon_str.strip('\r\n').split('\n') if line.strip('\r\n')]
        if not icon_lines : icon_lines = list(_DEFAULT_ICON_LINES)


    if not font_str or not font_str.strip():
        logger.warning("字体文件加载失败或为空，使用默认字体。")
        font_lines = list(_DEFAULT_FONT_LINES)
    else:
        font_lines = [line for line in font_str.strip('\r\n').split('\n') if line.strip('\r\n')]
        if not font_lines : font_lines = list(_DEFAULT_FONT_LINES)

    # 计算原始尺寸
    icon_width = max(len(line) for line in icon_lines) if icon_lines else 0
    icon_height = len(icon_lines)
    font_width = max(len(line) for line in font_lines) if font_lines else 0
    font_height = len(font_lines)

    # 检查终端宽度 (简化版)
    terminal_width = 80 # 默认终端宽度
    try:
        terminal_width = os.get_terminal_size().columns
    except OSError:
        logger.debug(f"无法获取终端尺寸，假定宽度为 {terminal_width}。")

    if icon_width + font_width + 2 > terminal_width: # +2 for spacing
        logger.warning(f"Logo (组合宽度: {icon_width + font_width + 2}) 可能太宽而无法适应终端 (当前宽度: {terminal_width})。")

    # 确定目标对齐高度 (取两者中较高者)
    # 并为每个部分增加顶部和底部的空白边距（各1行）以提供呼吸空间
    # effective_icon_height = icon_height + 2 if icon_height > 0 else 0
    # effective_font_height = font_height + 2 if font_height > 0 else 0
    # target_height = max(effective_icon_height, effective_font_height, 1) # 确保至少有1行高度

    # 调整：原始逻辑在比较高度后才给较矮的一方添加边距，这里先给icon固定加边距，然后对齐
    if icon_height > 0 and icon_lines != _DEFAULT_ICON_LINES: # 只给非默认且非空的图标加额外空白
        icon_lines = [' ' * icon_width] + icon_lines + [' ' * icon_width]
        icon_height = len(icon_lines)

    target_height = max(icon_height, font_height, 1)

    padded_icon_lines = _pad_art_vertically(icon_lines, target_height, icon_width)
    padded_font_lines = _pad_art_vertically(font_lines, target_height, font_width)
    
    return [padded_icon_lines, padded_font_lines]


# 在模块加载时生成 logo，以便其他模块可以直接导入 `logo` 变量
logo = generate_logo()


if __name__ == '__main__':
    # 测试打印 logo
    # 确保 logo 是期望的结构: [[icon_line1, ...], [font_line1, ...]]
    if logo and len(logo) == 2:
        icon_part, font_part = logo
        # 确保 icon_part 和 font_part 是列表
        if isinstance(icon_part, list) and isinstance(font_part, list):
            for left, right in zip(icon_part, font_part):
                print(f"{left}  {right}")
        else:
            print("Logo parts are not lists:", logo)
    else:
        print("Generated logo has unexpected structure:", logo)
