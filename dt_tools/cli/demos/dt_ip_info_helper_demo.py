import time

import dt_tools.logger.logging_helper as lh
import dt_tools.net.net_helper as helper
from dt_tools.console.console_helper import ColorFG, ConsoleHelper
from dt_tools.net.ip_info_helper import IpHelper


def demo():
    ConsoleHelper.print('')
    ConsoleHelper.print_line_separator('', 80)
    ConsoleHelper.print_line_separator('dt_ip_info_helper_demo', 80)
    ConsoleHelper.print('')

    local_ip = helper.get_local_ip()
    wan_ip = helper.get_wan_ip()
    google_ip = helper.get_ip_from_hostname('google.com')

    ip_dict = {"Local IP": local_ip, "WAN IP": wan_ip, "Google IP": google_ip, "Bad Address": "999.999.999.999"}
    for ip_name, ip in ip_dict.items():
        ip_dict = IpHelper.get_ip_info(ip)
        ConsoleHelper.print('')
        ConsoleHelper.print_line_separator(f'{ip_name} Info', 40)
        if 'error' in ip_dict.keys():
            ConsoleHelper.print(f'IP Address      : {ConsoleHelper.cwrap(ip, ColorFG.YELLOW)}')
        for key, val in ip_dict.items():
            ConsoleHelper.print(f'{key:15} : {ConsoleHelper.cwrap(val, ColorFG.YELLOW)}')
        time.sleep(2)


if __name__ == '__main__':
    lh.configure_logger()
    demo()
    