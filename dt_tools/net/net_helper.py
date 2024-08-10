"""
Network utilities helper class.

Functions to assist with network related information and tasks.


- ping
- local IP address
- get ip for given hostname
- get hostname for given ip
- get mac address for given hostname or ip
- get mac vendor
- get local client info on LAN

"""
import ipaddress
import platform
import random
import socket
import subprocess
import uuid
from dataclasses import dataclass
from time import sleep
from typing import List, Union

import requests
import scapy.all as scapy
from loguru import logger as LOGGER

from dt_tools.os.os_helper import OSHelper

_UNKNOWN = 'unknown'

@dataclass
class LAN_Client():
    """
    Data class to hold Lan Client information.

    Members:
        ip: IP address.
        mac: MAC address.
        hostname: Hostname
        vendor: MAC vendor.
    """
    ip: str
    mac: str
    hostname: str = None
    vendor: str = None

    def to_dict(self):
        """
        Return LAN_Client as a dictionary.
        """
        LAN_Client_dict = {}
        for attr in self.__dict__:
            LAN_Client_dict[attr] = self.__dict__[attr]

        return LAN_Client_dict        

# ===============================================================================================
def _get_ipaddress_obj(ip: str) -> Union[ipaddress.IPv4Address, ipaddress.IPv6Address]:
    """
    get ip_address object

    Args:
        ip (str): String representation of IPv4 or IPv6 address.

    Returns:
        Union[ipaddress.IPv4Address, ipaddress.IPv6Address]: ipaddress object
    """
    ip_obj = None
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        pass

    return ip_obj

def is_valid_ipaddress(ip: str) -> bool:
    return _get_ipaddress_obj(ip) is not None

def is_ipv4_address(ip: str) -> bool:
    """
    Valid IPv4 address in dotted-quad notation.
    
    Args:
        ip_address: (str) in format 999.999.999.999

    Example::

        >>> is_ipv4_address("1.2.3.4")
        True
        >>> is_ipv4_address("127.0.0.1/8")
        False
        >>> is_ipv4_address("1.2.3.4.5")
        False
    """
    ip_obj = _get_ipaddress_obj(ip)
    return ip_obj is not None and isinstance(ip_obj, ipaddress.IPv4Address)

def is_ipv6_address(ip: str) -> bool:
    ip_obj = _get_ipaddress_obj(ip)
    return ip_obj is not None and isinstance(ip_obj, ipaddress.IPv6Address)

# def is_ipv4_address(ip_address: str) -> bool:
#     """
#     Valid IPv4 address in dotted-quad notation.
    
#     Args:
#         ip_address: (str) in format 999.999.999.999

#     Example::

#         >>> is_ipv4_address("1.2.3.4")
#         True
#         >>> is_ipv4_address("127.0.0.1/8")
#         False
#         >>> is_ipv4_address("1.2.3.4.5")
#         False
#     """
#     octets = ip_address.split(".")

#     return len(octets) == 4 and \
#         all(o.isdigit() and 0 <= int(o) < 256 for o in octets)

def is_port_open(host_name: str, port: int, timeout:float=1.0) -> bool:
    """
    Check if port is open on target host.

    Args:
        host_name (str): Target host name
        port (int): Port number to test
        timeout (float, optional): Seconds to wait for connection. Defaults to 1.0.

    Returns:
        bool: True if port is open else False
    """
    port_is_open = False
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        LOGGER.debug(f'is_port_open() - attempting to connect to {host_name}:{port}')
        s.connect((host_name, int(port)))
        s.shutdown(socket.SHUT_WR)
        s.close()
        LOGGER.debug('is_port_open() - connection successful.')
        port_is_open = True
    except:  # noqa: E722
        LOGGER.debug(f'is_port_open() - unable to connect to {host_name}:{port}')

    return port_is_open

def is_valid_host(host_name: str) -> bool:
    """
    Check if hos_tname is valid.  
    
    Args:
        host (str): Host name or IP address.

    Returns:
        bool: True if hostname is resolvable else False
    """
    ip_addr = None
    valid_host = False
    try:
        ip_addr = ipaddress.ip_address(host_name)
    except ValueError as ve:
        LOGGER.debug(f'host_name: {host_name} is NOT a valid IP address. [{ve}]')

    try:
        if ip_addr is not None:
            LOGGER.debug(f'is_valid_host() - gethostbyaddr({host_name})')
            _ = socket.gethostbyaddr(host_name)
        else:
            LOGGER.debug(f'is_valid_host() - gethostbyname({host_name})')
            _ = socket.gethostbyname(host_name)
        valid_host = True

    except (socket.gaierror, socket.herror):
        valid_host = False

    return valid_host
    

# == get hostname, ip, MAC, vendor routins ======================================================
def get_hostname_from_ip(ip: str) -> str:
    """
    Get hostname from IP address.

    Arguments:
        ip: IP address to get hostname for.

    Returns:
        Hostname if found else 'unknown' if not found or error.
    """
    try:
        host = socket.gethostbyaddr(ip)
        hostname = host[0]
    except:  # noqa: E722
        hostname = _UNKNOWN
    return hostname

def get_ip_from_hostname(host_name: str) -> str:
    """
    Get IP address from hostname.

    Arguments:
        host_name: Name of target host.

    Returns:
        IP address if found or '' if not found or error.

    """
    try:
        ip = socket.gethostbyname(host_name)
    except socket.gaierror:
        ip = ''
    return ip

def get_ip_from_mac(mac: str) -> str:
    """
    Get IP address based on MAC (via ARP)

    Args:
        mac (str): MAC address

    Raises:
        ValueError: Unknown MAC address format
        ValueError: Unable to determine IP from MAC address

    Returns:
        str: IP address
    """
    LOGGER.debug(f"get_ip_from_mac('{mac}')")
    if len(mac) == 17:
        sep = mac[2]
        mac = mac.replace(sep, _mac_separator()).lower()
    elif len(mac) == 12:
        # sep = _mac_platform_separator()
        mac_byte_list = [mac[i:i+2] for i in range(0, 12, 2) ]
        mac = OSHelper.mac_separator.join(mac_byte_list).lower()
    else:
        raise ValueError(f'MAC invalid format: {mac}')
    
    # arp_cmd = cls._get_arp_cmd()
    process_rslt = subprocess.run(_arp_entries_command(), capture_output=True)
    rslt = process_rslt.stdout.decode('utf-8').splitlines()
    LOGGER.critical(f'MAC: {mac}\nRESULT: {rslt}')
    arp = [token for token in rslt if mac in token]
    LOGGER.critical(f'  arp line: {arp}')
    ip = None
    if platform.system() == "Windows":
        ip = " ".join(arp.split()).split()[0]
    else:
        ip = " ".join(arp.split()).split()[2]
    
    if ip is not None:
        LOGGER.debug(f'  MAC {mac} resolves to {ip}')
        return ip
    
    raise ValueError(f'Can not determine IP for mac {mac}')

def get_wan_ip() -> str:
    from dt_tools.net.ip_info_helper import IpHelper as ih

    ip_info, _ = ih.get_wan_ip_info()
    return ip_info.get('ip', _UNKNOWN)

def get_local_ip() -> str:
    """
    Get local IP address

    Returns:
        Local machine IP address, or '127.0.0.1' if not found or error
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # doesn't even have to be reachable
        s.connect(('192.255.255.255', 1))
        ip = s.getsockname()[0]
    except:  # noqa: E722
        ip = '127.0.0.1'
    finally:
        s.close()

    return ip
 
def get_mac_address(hostname_or_ip: str) -> str:
    """
    Get MAC address of target Hostname (or IP).

    Process uses ARP to discover data.

    Arguments:
        hostname_or_ip: target host

    Returns:
        MAC address if found, else None
    """
    local_ip = get_local_ip()
    if is_ipv4_address(hostname_or_ip):
        ip = hostname_or_ip
    else:
        try:
            ip = socket.gethostbyname(hostname_or_ip)
        except socket.gaierror as sge:
            LOGGER.debug(f'Unable to resolve IP for {hostname_or_ip} [{sge}]')
            return None
    mac = None
    if ip == local_ip:
        mac = (':'.join(['{:02x}'.format((uuid.getnode() >> ele) & 0xff) for ele in range(0,8*6,8)][::-1]))
    else:
        process_rslt = subprocess.run(_arp_entries_command(), capture_output=True)
        rslt = process_rslt.stdout.decode('utf-8')
        mac = None
        arp_list = rslt.split('\n')
        try:
            arp = [token for token in arp_list if ip in token][0]
            if arp.endswith('no entry'):
                LOGGER.debug(f'no entry in ARP for {ip}')
            else:
                if OSHelper().is_windows():
                    mac = " ".join(arp.split()).split()[1]
                else:
                    mac = " ".join(arp.split()).split()[2]
                mac = mac.replace('-',':').upper()
        except IndexError:  # no arp entry found
            LOGGER.debug(f'Can not resolve MAC for {hostname_or_ip}')

    return mac

def get_vendor_from_mac(mac: str) -> str:
    """
    Return the vendor name for specified MAC address

    Arguments:
        mac: Target MAC address

    Returns:
        Vendor name if found, else 'unknown'
    """
    vendor = _UNKNOWN
    url = f'https://api.maclookup.app/v2/macs/{mac}'
    retry = 0
    RETRY_MAX = 15
    try:
        while retry < RETRY_MAX and vendor == _UNKNOWN:
            resp = requests.get(url)
            if resp.status_code == 200:
                vendor = resp.json()['company']      # api.maclookup
                if len(vendor) == 0:
                    LOGGER.debug(f'  ERROR: Vendor not found, {url}, {resp.text}')
                    vendor = "Not Found"
                if retry > 0:
                    LOGGER.debug(f'  SUCCESS. Retry succeeded, {vendor}, {url}')    
            elif resp.status_code == 429:
                retry += 1
                sleep_secs = random.uniform(.25,2.5)
                LOGGER.debug(f'  WARNING: Throttle [{retry}]... {sleep_secs:1.2} {url}')
                sleep(sleep_secs) # Throttle (limit = 2 requests/second)
            else:
                LOGGER.debug(f'  ERROR: MAC Lookup resp: {resp.status_code}, {url}, {resp.text}')
                retry = RETRY_MAX

    except Exception as ex:
        LOGGER.debug(f'  ERROR: MAC Lookup error {url}: {repr(ex)}')
        vendor = _UNKNOWN
        
    if vendor == _UNKNOWN:
        LOGGER.debug(f'  ERROR: Unable to resolve, {mac}')

    return vendor


# == ARP Calls ===============================================================================================
def get_lan_clients_ARP_broadcast(include_hostname: bool = False, include_mac_vendor: bool = False) -> List[LAN_Client]:
    """
    Retrieve a list of LAN_Clients from the local network.

    The list of clients are retrieved via a Scapy ARP broadcast

    Note:
        including hostname and/or vendor will slow down process due to additional calls

    Keyword Arguments:
        include_hostname: Include hostname information (default: {False})
        include_mac_vendor: Include MAC vendor name (default: {False})

    Raises:
        PermissionError: Linux requires this call to be run as ROOT

    Returns:
        A list of :class:`~LAN_Client` entries 
    
    """
    if OSHelper.is_linux() and not OSHelper.is_linux_root():
        LOGGER.critical('You must be root on linux for ARP_Broadcast to work')
        raise PermissionError('Must be root')

    request = scapy.ARP()
    request.pdst = _get_target_protocol_address_pdst() # '192.168.1.1/24'
    broadcast = scapy.Ether() 
    
    broadcast.dst = 'ff:ff:ff:ff:ff:ff'    
    request_broadcast = broadcast / request 
    clients = scapy.srp(request_broadcast, timeout=3, verbose=False)[0] 

    lan_client_list: List[LAN_Client] = []
    for element in clients: 
        ip = element[1].psrc
        if _trackable_ip(ip):
            mac = element[1].hwsrc
            entry = LAN_Client(ip, mac.upper())
            lan_client_list.append(entry)
    
    if include_hostname or include_mac_vendor:
        lan_client_list = _get_hostname_and_or_vendor(lan_client_list, include_hostname, include_mac_vendor)

    return lan_client_list        

def get_lan_clients_from_ARP_cache(include_hostname: bool = False, include_mac_vendor: bool = False) -> List[LAN_Client]:
    """     
    Retrieve a list of LAN_Clients from the local network.

    The list of clients are retrieved via the ARP cache.

    Note:
        including hostname and/or vendor will slow down process due to additional calls

    Keyword Arguments:
        include_hostname: Include hostname information (default: {False})
        include_mac_vendor: Include MAC vendor name (default: {False})

    Returns:
        A list of :class:`~LAN_Client` entries 
    """
    arp_cmd = ["arp", "-a"] if OSHelper().is_windows() else ["arp", "-n"]
    LOGGER.debug(f'ARP command: {arp_cmd}')
    process_rslt = subprocess.run(arp_cmd, capture_output=True)
    result = process_rslt.stdout.decode('utf-8').splitlines()
    # Remove lines that are not IPs
    tokens =  [ line.strip() for line in result if line.count('.')==3 and not line.startswith('Interface')]

    lan_client_list = []
    for arp_entry in tokens:
        # If windows, response will be IP MAC TYPE, else IP TYPE MAC
        arp_field = arp_entry.split()
        ip = arp_field[0]
        if _trackable_ip(ip):
            mac = arp_field[1] if OSHelper().is_windows() else arp_field[2]
            mac = mac.replace('-',':').upper()
            entry = LAN_Client(ip, mac)
            lan_client_list.append(entry)

    if include_hostname or include_mac_vendor:
        lan_client_list = _get_hostname_and_or_vendor(lan_client_list, include_hostname, include_mac_vendor)

    return lan_client_list

# ===========================================================================================================
def ping(host_name: str, wait_secs: int = 1) -> bool:
    """
    Ping target host (ip or name).

    Arguments:
        host_name: Target hostname (or ip address)

    Keyword Arguments:
        wait_secs: Number of seconds to wait for a reply (default: {1}).

    Returns:
        True if host responds, False if timeout or error.
    """
    # Token can be an IP or a hostname
    if OSHelper().is_windows():
        ping_cmd = ['ping', '-n', '1', '-w', str(wait_secs * 1000), host_name]
    else:
        ping_cmd = ['ping', '-c', '1', '-W', str(wait_secs), host_name]

    online_state = False
    ping_result = subprocess.run(ping_cmd, capture_output=True)
    if ping_result.returncode == 0 and 'unreachable' not in ping_result.stdout.decode('utf-8'):
        online_state = True
            
    return online_state

# == Private Methods ==========================================================================
def _trackable_ip(ip: str) -> bool:
    trackable = True
    if ip.startswith('224.') or \
        ip.startswith('239.255.250.250') or \
        ip.startswith('239.255.255.250') or \
        ip.endswith('.255'):
        trackable = False
    
    return trackable

def _get_hostname_and_or_vendor(client_list: list, include_hostname: bool, include_mac_vendor: bool) -> List[LAN_Client]:

    updated_list: List[LAN_Client] = []
    from dt_tools.net.ip_info_helper import IpHelper
    ip_info = IpHelper()
    arp_entry: LAN_Client = None

    for arp_entry in client_list:
        ip_data = ip_info.get_ip_info(arp_entry.ip)
        if include_hostname:
            arp_entry.hostname = ip_data.get('hostname')
        if include_mac_vendor:
            arp_entry.vendor = ip_data.get('vendor')
        updated_list.append(arp_entry)

    return updated_list

def _get_target_protocol_address_pdst() -> str:
    """
    _summary_

    Returns:
        str: _description_
    """
    ip = get_local_ip()
    octet = ip.split('.')
    octet[3] = '1'
    network = '.'.join(octet) + "/24"

    return network

def _ipv4_mask_len(dotquad) -> int:
    """
    Finds the number of bits set in the netmask.

    >>> ipv4_mask_len("255.255.255.0")
    24
    >>> ipv4_mask_len("0.0.0.0")
    0
    >>> ipv4_mask_len("255.255.255.255")
    32
    >>> ipv4_mask_len("127.0.0.0")
    Traceback (most recent call last):
    ...
    ValueError: Invalid netmask: 127.0.0.0
    """
    if not is_ipv4_address(dotquad):
        raise ValueError("Invalid netmask: {0}".format(dotquad))
    a, b, c, d = (int(octet) for octet in dotquad.split("."))
    mask = a << 24 | b << 16 | c << 8 | d

    if mask == 0:
            return 0

    # Count the number of consecutive 0 bits at the right.
    # https://wiki.python.org/moin/BitManipulation#lowestSet.28.29
    m = mask & -mask
    right0bits = -1
    while m:
        m >>= 1
        right0bits += 1

    # Verify that all the bits to the left are 1's
    if mask | ((1 << right0bits) - 1) != 0xffffffff:
        raise ValueError("Invalid netmask: {0}".format(dotquad))
    return 32 - right0bits

def _arp_entries_command() -> str:
    return "arp -a" if OSHelper().is_windows() else "arp -n"

def _mac_separator() -> str:
    return '-' if OSHelper.is_windows() else ":"



if __name__ == "__main__":
    import dt_tools.cli.dt_net_demo as cli
    cli.demo()
