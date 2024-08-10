"""
Wake-on-LAN utility

This package can be used to send WOL packet to target machines via IP or Hostname.

Raises:
    ex: Invalid MAC address
    ValueError: When MAC address does not conform to expected format
"""
import socket
import struct
import time

from loguru import logger as LOGGER

import dt_tools.logger.logging_helper as lh
import dt_tools.net.net_helper as nh

# from dt_tools.console.progress_bar import ProgressBar

LOGLEVEL="INFO"

class WOL():
    '''
    Send WOL request to target device via MAC address, hostname or IP
    and optionally, wait for device to come online.

    Example::

        from dt_tools.net.wol import WOL
        from loguru import logger as LOGGER

        wol = WOL()
        try:
            wol.send_wol_to_host('somehost', wait_secs=20)
        except Exception as ex:
            LOGGER.error(repr(ex))
            raise ex    
    '''
    BROADCAST_IP = "255.255.255.255"
    DEFAULT_PORT = 9
    
    _status_message: str = ''

    def __init__(cls):
        LOGGER.debug('WOL class created.')

    @property
    def status_message(cls) -> str:
        return cls._status_message
    
    def send_wol_to_host(cls, host_name: str, wait_secs: int = 0) -> bool:
        '''
        Send WOL to target hostname or IP
        host:       either hostname or IP address
        wait_secs:  number of secs to wait for host to come online (0=no wait, fire-forget)
        '''
        return_status = False
        if nh.is_valid_ipaddress(host_name):
            _ip = host_name
            _host = nh.get_hostname_from_ip(_ip)
        else:
            _ip = nh.get_ip_from_hostname(host_name)
            _host = host_name
        LOGGER.debug(f'  _ip: {_ip}  _host: {_host}')
        if not nh.is_valid_host(host_name):
            host_type = 'ip address' if _host == nh._UNKNOWN else 'hostname'
            cls._status_message = f'Invalid {host_type} [{host_name}]'
        else:
            mac = nh.get_mac_address(_ip)
            if mac:
                return cls._send_wol_via_mac(mac, wait_secs=wait_secs, ip=_ip)  
            cls._status_message = f"Unable to determine MAC address for {host_name}"
            LOGGER.debug(cls._status_message)
        
        return return_status
    
    # === Private functions ==============================================================
    def _send_wol_via_mac(cls, mac: str, wait_secs: int = 0, ip: str = None) -> bool:
        macAddress = mac
        # Check macaddress format and try to compensate.
        if len(macAddress) == 12:
            pass
        elif len(macAddress) == 12 + 5:
            sep = macAddress[2]
            macAddress = macAddress.replace(sep, "")
        else:
            cls._status_message = f"Incorrect MAC address format: {macAddress}"
            return False

        # Pad the synchronization stream.
        data = b"FFFFFFFFFFFF" + (macAddress * 20).encode()
        send_data = b""

        # Split up the hex values and pack.
        for i in range(0, len(data), 2):
            send_data += struct.pack("B", int(data[i : i + 2], 16))

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        LOGGER.debug(f'Sending WOL to {mac}')
        sock.sendto(send_data, ("<broadcast>", 9))  # 7

        if wait_secs == 0:
            cls._status_message = "Packet sent."
            return True

        if ip is None:
            ip = nh.get_ip_from_mac(mac)
            if ip is None:
                LOGGER.debug(f'ERROR: Unable to resolve IP from MAC {mac}')
                cls._status_message = "Packet sent, no wait, could not resolve IP."
                return True

        is_online = cls._wait_for_device_to_come_online(ip, wait_secs)
        hostname = nh.get_hostname_from_ip(ip)
        if hostname:
            LOGGER.debug(f'Host: {hostname} | MAC: {mac} | {ip} - is online {is_online}')
        else:
            LOGGER.debug(f'MAC: {mac} | {ip} - is online {is_online}')
        
        cls._status_message = "Packet sent.  Host online." if is_online else f"Packet sent. Host NOT online after waiting {wait_secs} seconds."
        return is_online

    def _create_magic_packet(cls, mac: str) -> bytes:
        if len(mac) == 17:
            sep = mac[2]
            mac = mac.replace(sep, "")
        elif len(mac) != 12:
            raise ValueError("Incorrect MAC address format")

        return bytes.fromhex("F" * 12 + mac * 16)
                    
    def _wait_for_device_to_come_online(cls, ip: str, wait_secs: int) -> bool:
        is_online = nh.ping(ip)
        if not is_online:
            # pbar = ProgressBar("Waiting for device to come online", 50, wait_secs, show_elapsed=True)
            LOGGER.debug(f'Waiting for {wait_secs} seconds for device to come online.')
            start = time.time()
            elapsed = 0
            while elapsed < wait_secs and not is_online:
                # pbar.display_progress(elapsed)                
                # if LOGLEVEL == "DEBUG":
                #     print('.', end='', flush=True)
                time.sleep(1)
                is_online = nh.ping(ip)
                elapsed = time.time() - start
            # pbar.cancel_progress()

        return is_online


if __name__ == "__main__":
    lh.configure_logger(log_level=LOGLEVEL, log_format=lh.DEFAULT_CONSOLE_LOGFMT)
    wol = WOL()
    hostname = 'nirvana'
    LOGGER.info(f'Sending WOL to {hostname}...')
    try:
        if wol.send_wol_to_host(hostname, wait_secs=20):
            LOGGER.success(f'  {wol.status_message}')
        else:
            LOGGER.warning(f'  {wol.status_message}')
    except Exception as ex:
        LOGGER.error(repr(ex))
