import os
from collections import defaultdict
from .utils import color # Assuming color.py is in Ingram/utils
from loguru import logger # Added for logging malformed lines or other issues if needed

class ReportGenerator:
    def __init__(self, config):
        self.config = config # Store config for access to out_dir, vulnerable file name, etc.

    def generate_console_report(self):
        # This method will contain the logic moved from Core.report()
        results_file = os.path.join(self.config.out_dir, self.config.vulnerable)
        if not os.path.exists(results_file):
            logger.info(f"结果文件 {results_file} 未找到，跳过生成报告。")
            print(f"\n结果文件 {results_file} 未找到，跳过生成报告。\n") # Keep console message for user
            return

        with open(results_file, 'r', encoding='utf-8') as f: # Added encoding
            items = [line.strip().split(',') for line in f if line.strip()]

        if not items:
            logger.info(f"结果文件 {results_file} 为空，无需生成报告。")
            print("\n结果文件为空，无需生成报告。\n") # Keep console message for user
            return

        results = defaultdict(lambda: defaultdict(lambda: 0))
        malformed_lines = 0
        for i in items:
            # Basic validation for item structure
            # Example item: ['1.2.3.4', '80', 'hikvision-dvr', 'CVE-XXXX-XXXX', 'admin', '12345']
            # We expect at least 6 elements, with index 2 being dev_type_full and last being vul_name
            if len(i) >= 4 and '-' in i[2]: # Adjusted condition: need at least product (i[2]) and vul_name (i[-1])
                                           # and product should contain '-'
                dev_type_full = i[2]
                dev_type = dev_type_full.split('-')[0]
                vul_name = i[-1]
                results[dev_type][vul_name] += 1
            else:
                malformed_lines += 1
                logger.warning(f"跳过结果文件中的格式错误行: {','.join(i)}")

        if malformed_lines > 0:
            logger.warning(f"结果文件中有 {malformed_lines} 行格式错误被跳过。")

        if not results:
             logger.info("没有有效的已处理数据用于生成报告。")
             print("\n没有有效的已处理数据用于生成报告。\n") # Keep console message for user
             return

        results_sum = sum(sum(dev.values()) for dev in results.values())

        all_counts = [count for dev_vulns in results.values() for count in dev_vulns.values()]
        results_max = max(all_counts) if all_counts else 1

        # Console Output
        print('\n')
        print('-' * 19, 'REPORT', '-' * 19)
        for dev_type, vuls_dict in results.items():
            dev_sum = sum(vuls_dict.values())
            print(color.red(f"{dev_type} {dev_sum}", 'bright'))
            for vul_name, vul_count in vuls_dict.items():
                block_num = int(vul_count / results_max * 25) if results_max > 0 else 0
                print(color.green(f"{vul_name:>18} | {'▥' * block_num} {vul_count}"))
        print(color.yellow(f"{'sum: ' + str(results_sum):>46}", 'bright'), flush=True)
        print('-' * 46)
        print('\n')
