from loguru import logger as LOGGER

import dt_tools.logger.logging_helper as lh
import dt_tools.net.net_helper as nh
from dt_tools.console.console_helper import ColorFG, ConsoleHelper, ConsoleInputHelper
from dt_tools.console.spinner import Spinner, SpinnerType
from dt_tools.net.ip_info_helper import IpHelper


def display_LAN_report():
    ch = ConsoleHelper()
    ch.print_line_seperator('Local IPs', 40)
    
    spinner = Spinner("Retrieve ARP Entries", SpinnerType.ARC, show_elapsed=True)

    spinner.start_spinner('via ARP Cache')
    c_clients = nh.get_lan_clients_from_ARP_cache(include_hostname=True, include_mac_vendor=True)
    spinner.stop_spinner()
    LOGGER.info(f'ARP Cache     returns {len(c_clients)} devices.')

    spinner.start_spinner('via ARP Broadcast')
    b_clients = nh.get_lan_clients_ARP_broadcast(include_hostname=True, include_mac_vendor=True)
    spinner.stop_spinner()
    LOGGER.info(f'ARP Broadcast returns {len(b_clients)} devices.')
    LOGGER.info('')
    
    b_idx = 0
    b_done = False
    c_idx = 0
    c_done = False
    # Sort lists so we can match results
    sb_clients = sorted(b_clients, key=lambda x: x.mac)
    sc_clients = sorted(c_clients, key=lambda x: x.mac)
    
    print(f'{"ARP Broadcast":17}  {"ARP Cache":17}  {"ip":15} {"Hostname":33} {"Vendor":25}')
    print(f'{"-"*17}  {"-"*17}  {"-"*15} {"-"*33} {"-"*25}')
    while not b_done and not c_done:
        broadcast_entry = sb_clients[b_idx]
        cache_entry = sc_clients[c_idx]
        if broadcast_entry.mac == cache_entry.mac:
            b_mac = broadcast_entry.mac
            c_mac = cache_entry.mac
            ip = broadcast_entry.ip
            hostname = broadcast_entry.hostname
            vendor = broadcast_entry.vendor
            b_idx += 1
            c_idx += 1
        elif broadcast_entry.mac < cache_entry.mac:
            b_mac = broadcast_entry.mac
            c_mac = ""
            ip = broadcast_entry.ip
            hostname = broadcast_entry.hostname
            vendor = broadcast_entry.vendor
            b_idx += 1
        else:
            b_mac = ""
            c_mac = cache_entry.mac
            ip = cache_entry.ip
            hostname = cache_entry.hostname
            vendor = cache_entry.vendor
            c_idx += 1
        print(f'{b_mac:17}  {c_mac:17}  {ip:15} {hostname:33} {vendor}')
        if b_idx == len(sb_clients):
            b_done = True
        if c_idx == len(sc_clients):
            c_done = True
        b_idx = min(b_idx, len(sb_clients)-1)
        c_idx = min(c_idx, len(sc_clients)-1)


def demo():
    ch = ConsoleHelper()
    cih = ConsoleInputHelper()
    ip_helper = IpHelper()

    # ch.clear_screen()
    ch.print_line_seperator('dt_net Demo', 80)
    wan_ip = nh.get_wan_ip()
    local_ip = nh.get_local_ip()
    host_name = nh.get_hostname_from_ip(local_ip)
    mac = nh.get_mac_address(host_name)
    vendor = nh.get_vendor_from_mac(mac)
    ch.print('')
    ch.print_line_seperator('Local IP Info', 40)
    LOGGER.info(f'WAN   IP    : {ch.cwrap(wan_ip, ColorFG.YELLOW2)}')
    LOGGER.info(f'Local IP    : {ch.cwrap(local_ip, ColorFG.YELLOW2)}')
    LOGGER.info(f'Hostname    : {ch.cwrap(host_name, ColorFG.YELLOW2)}')
    LOGGER.info(f'MAC         : {ch.cwrap(mac, ColorFG.YELLOW2)}')
    LOGGER.info(f'Vendor      : {ch.cwrap(vendor, ColorFG.YELLOW2)}')
    LOGGER.info('')
    cih.wait_with_bypass(5)

    host_name = "google.com"
    ip = nh.get_ip_from_hostname(host_name)
    host_info: dict = ip_helper.get_ip_info(ip)
    ch.print_line_seperator('Target host info (google.com)', 40)
    LOGGER.info(f'Host        : {ch.cwrap(host_name, ColorFG.YELLOW2)}')
    for k, v in host_info.items():
        LOGGER.info(f'{k:12}: {ch.cwrap(v, ColorFG.YELLOW2)}')
    LOGGER.info('')
    
    cih.wait_with_bypass(5)
    display_LAN_report()

if __name__ == "__main__":
    lh.configure_logger(log_format=lh.DEFAULT_CONSOLE_LOGFMT)
    demo()
