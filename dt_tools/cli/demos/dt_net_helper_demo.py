from typing import List

from loguru import logger as LOGGER

import dt_tools.console.console_helper as ch
import dt_tools.logger.logging_helper as lh
import dt_tools.net.net_helper as helper
from dt_tools.console.console_helper import ColorFG, ConsoleHelper
from dt_tools.console.console_helper import ConsoleInputHelper as con_input
from dt_tools.console.spinner import Spinner, SpinnerType
from dt_tools.net.net_helper import LAN_Client

# COMMON_PORTS = {
#     "Echo service": 7,
#     "FTP-data": 20,
#     "FTP": 21,
#     "SSH": 22,
#     "Telnet": 23,
#     "SMTP": 25,
#     "DNS": 53,
#     "TFTP": 69,
#     "HTTP": 80,
#     "Kerberos": 88,
#     "Iso-tsap": 102,
#     "POP3": 110,
#     "MS EPMAP": 135,
#     "NetBIOS-ns": 137,
#     "NetBIOS-ssn": 139,
#     "IMAP4": 143,
#     "HP Openview (alarm)": 381,
#     "HP Openview (data)": 383,
#     "HTTPS": 443,
#     "Kerberos (pwd)": 464,
#     "SMTP TLS/SSL": 465,
#     "SMTP (submission)": 587,
#     "MS DCOM": 593,
#     "LDAP TLS/SSL": 636,
#     "MS Exchange": 691,
#     "VMWare": 902,
#     "FTP SSL (data)": 989,
#     "FTP SSL (control)": 990,
#     "IMAP4 SSL": 993,
#     "POP3 SSL": 995,
#     "MS RPC": 1025,
#     "OpenVPN": 1194,
#     "WASTE": 1337,
#     "Cisco VQP": 1589,
#     "Steam": 1725,
#     "cPanel": 2082,
#     "radsec": 2083,
#     "Oracle DB": 2483,
#     "Oracle DB SSL": 2484,
#     "Semantec AV": 2967,
#     "XBOX Live": 3074,
#     "MySQL": 3306,
#     "World of Warcraft": 3724,
#     "Google Desktop": 4664,
#     "PostgresSQL": 5432,
#     "RFB/VNC": 5900,
#     "IRC1": 6665,
#     "IRC2": 6666,
#     "IRC3": 6667,
#     "IRC4": 6668,
#     "IRC5": 6669,
#     "BitTorrent": 6881,
#     "Quicktime": 6970,
#     "BitTorrent2": 6999,
#     "Kaspersky CC": 8086,
#     "Kaspersky": 8087,
#     "VMWare Server": 8222,
#     "PDL": 9100,
#     "BackupExec": 10000,
#     "NetBus": 12345,
#     "Sub7": 27374,
#     "Back Orifice": 31337,
# }

def display_LAN_report():
    ch = ConsoleHelper()
    ch.print_line_separator('LAN Client Report', 40)
    
    spinner = Spinner("Retrieve ARP Entries", SpinnerType.ARC, show_elapsed=True)

    spinner.start_spinner('via ARP Cache')
    c_clients = helper.get_lan_clients_from_ARP_cache(include_hostname=True, include_mac_vendor=True)
    spinner.stop_spinner()
    LOGGER.info(f'ARP Cache     returns {len(c_clients)} devices.')

    spinner.start_spinner('via ARP Broadcast')
    b_clients = helper.get_lan_clients_ARP_broadcast(include_hostname=True, include_mac_vendor=True)
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
            hostname = cache_entry.hostname if cache_entry.hostname is not None else '?'
            vendor = cache_entry.vendor if cache_entry.vendor is not None else '?'
            c_idx += 1
        try:
            print(f'{b_mac:17}  {c_mac:17}  {ip:15} {hostname:33} {vendor}')
        except TypeError:
            print(f'{b_mac    =}')
            print(f'{c_mac    =}')
            print(f'{ip       =}')
            print(f'{hostname =}')
            print(f'{vendor   =}')
        if b_idx == len(sb_clients):
            b_done = True
        if c_idx == len(sc_clients):
            c_done = True
        b_idx = min(b_idx, len(sb_clients)-1)
        c_idx = min(c_idx, len(sc_clients)-1)

def demo():
    ConsoleHelper.print('')
    ConsoleHelper.print_line_separator('', 80)
    ConsoleHelper.print_line_separator('dt_net_helper_demo', 80)
    ConsoleHelper.print('')

    # Get local machines internal IP
    local_ip = helper.get_local_ip()
    # Get local machines External IP
    wan_ip = helper.get_wan_ip()
    # Get list of client machines on LAN
    lan_list: List[LAN_Client] = helper.get_lan_clients_from_ARP_cache()
    ip_dict = {"Local IP": local_ip, "WAN IP": wan_ip, "Bad IP": "192.168.1.0" }
    if len(lan_list) > 3:
        # Choose two clients
        ip_dict['Client1'] = lan_list[0].ip
        ip_dict['Client2'] = lan_list[len(lan_list)-1].ip

    # Display information for each client (machine) in list
    for ip_name, ip in ip_dict.items():
        is_valid = ConsoleHelper.cwrap('Valid', ColorFG.GREEN2) if helper.is_valid_host(ip) else ConsoleHelper.cwrap('Invalid', ColorFG.RED2)
        ip_type = 'Unknown'
        if helper.is_ipv4_address(ip):
            ip_type = "IPv4"
        elif helper.is_ipv6_address(ip):
            ip_type = "IPv6"

        if is_valid == 'Valid':
            hostname = helper.get_hostname_from_ip(ip)
            mac = helper.get_mac_address(ip)
            vendor = helper.get_vendor_from_mac(mac) if mac is not None else 'unknown'
            is_alive = helper.ping(ip)

        ConsoleHelper.print_line_separator(f'{ip_name} Info', 40)
        ConsoleHelper.print(f'IP         : {ConsoleHelper.cwrap(ip,ColorFG.YELLOW)} {is_valid}')
        ConsoleHelper.print(f'IP Type    : {ConsoleHelper.cwrap(ip_type,ColorFG.YELLOW)}')
        if is_valid == 'Valid':
            ConsoleHelper.print(f'hostname   : {ConsoleHelper.cwrap(hostname,ColorFG.YELLOW)}')
            ConsoleHelper.print(f'mac        : {ConsoleHelper.cwrap(mac,ColorFG.YELLOW)}')
            ConsoleHelper.print(f'mac vendor : {ConsoleHelper.cwrap(vendor,ColorFG.YELLOW)}')
            ConsoleHelper.print(f'is alive   : {ConsoleHelper.cwrap(is_alive,ColorFG.YELLOW)}')
            if is_alive:
                resp = con_input.get_input_with_timeout('Perform a port scan (y/n)? ', ['y', 'n'], default='n', timeout_secs=5)
                ConsoleHelper.cursor_up()
                ConsoleHelper.clear_line()
                if resp == 'y':
                    ConsoleHelper.print_line_separator('Scan for open Ports: ', 27)
                    ConsoleHelper.print('  .', eol='')
                    for port_use, port in helper.COMMON_PORTS.items():
                        if helper.is_port_open(ip, port):
                            ConsoleHelper.cursor_move(column=1)
                            ConsoleHelper.clear_to_EOL()
                            ConsoleHelper.print(f'  {port_use:12} : {port} open')
                            ConsoleHelper.print('  .', eol='')
                        else:
                            ConsoleHelper.print('.',eol='')
                    ConsoleHelper.cursor_move(column=1)
                    ConsoleHelper.clear_to_EOL()
        ConsoleHelper.print('')

    display_LAN_report()

if __name__ == '__main__':
    ch.enable_ctrl_c_handler()
    lh.configure_logger()
    demo()
    