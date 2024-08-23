from dataclasses import dataclass
from dt_tools.os.os_helper import OSHelper
from dt_tools.net.wifi_scanner import ScannerBase
from typing import List
from dt_tools.net.wifi_scanner import CONSTANTS
import dt_tools.logger.logging_helper as lh

from loguru import logger as LOGGER
from dt_tools.misc.helpers import ObjectHelper as o_helper


# == Adapter Object ==========================================================================================================   
@dataclass 
class WifiAdapterInfo:
    name: str
    desc: str = ''
    mac: str = ''
    connected: bool = False
    SSID: str = 'Not Associated'
    BSSID: str = ''
    radio_type: str = ''
    Authentication: str = ''
    cipher: str = ''
    band: str = ''
    channel: int = -1
    receive_rate: float = -1.0
    transmit_rate: float = -1.0
    signal: int = -1

    def __post_init__(self):
        if OSHelper.is_windows():
            if not self._get_windows_wifi_adapter():
                raise NameError(f'Unable to identify wifi adapter "{self.name}"')
        elif OSHelper.is_linux():
            if not self._get_linux_wifi_adapter():
                raise NameError(f'Unable to identify wifi adapter "{self.name}"')
        else:
            raise RuntimeError(f'Unsupported OS.')
        
    def _get_linux_wifi_adapter(self) -> bool:
        # iw wlan0 info = channel, mhz, mac
        iwconfig_output, _ = ScannerBase._execute_process('iwconfig', show_feedback=False)
        adapter_found = False
        for line in iwconfig_output:
            line = line.strip()
            if 'ESSID' in line:
                if adapter_found:
                    # done, bail
                    break
                adapter_found = True
                self.SSID = line.split('ESSID:')[1].strip()
                continue
            if "Frequency:" in line:
                token = line.split('Frequency:')[1].strip()
                if token.startswith('2'):
                    self.radio_type = "2.4 GHz"
                elif token.startswith('5'):
                    self.radio_type = '5 GHz'
            if "Access Point:" in line:
                self.BSSID = line.split('Access Point:')[1].strip()
            if "Bit Rate=" in line:
                self.receive_rate = line.split('Bit Rate=')[1].split()[0]
                self.transmit_rate = self.receive_rate
            if "Link Quality=" in line:
                txt_sig = line.split('=')[1].split()[0]
                signals = txt_sig.split('/')
                self.signal = int(int(signals[0]) / int(signals[1]) * 100)
            # self.Authentication
            # self.channel
            # self.band
            # self.cipher
            # self.connected
            # self.desc
            # self.mac
            # self.radio_type

        return adapter_found
    
    def _get_windows_wifi_adapter(self) -> bool:
        netsh_output, _ = ScannerBase._execute_process('netsh wlan show interfaces', show_feedback=False)
        adapter_found = self._process_netsh_adapter_output(netsh_output)
        # if not adapter_found:
        #     netsh_output, _ = ScannerBase._execute_process('netsh lan show interfaces', show_feedback=False)
        #     adapter_found = self._process_netsh_adapter_output(netsh_output)

        return adapter_found
    
    def _process_netsh_adapter_output(self, netsh_output: List[str]) -> bool:
        name_found = False
        adapter_found = False
        for line in netsh_output:
            line = line.strip()
            value = '' if len(line.split(':',1)) == 1 else line.split(':',1)[1].strip()
            if line.startswith('Name'):
                if adapter_found:
                    # Fully processed target name, quit
                    break
                elif self.name == value:
                    adapter_found = True
                    name_found = True
                    continue
                else:
                    # Wrong adapter, keep going
                    continue
            if not name_found:
                continue
            # value = '' if len(line.split(':',1)) == 1 else line.split(':',1)[1].strip()
            if line.startswith('Description'):
                self.desc = value
                continue
            if line.startswith('Physical address'):
                self.mac = value
                continue
            if line.startswith('State'):
                self.connected = value == 'connected'
                continue
            if line.startswith('SSID'):
                self.SSID = value
                continue
            if line.startswith('BSSID'):
                self.BSSID = value
                continue
            if line.startswith('Radio type'):
                self.radio_type = value
                continue
            if line.startswith('Authentication'):
                self.Authentication = value
                continue
            if line.startswith('Cipher'):
                self.cipher = value
                continue
            if line.startswith('Channel'):
                self.channel = int(value)
                continue
            if line.startswith('Band'):
                self.band = value
                continue
            if line.startswith('Receive rate'):
                self.receive_rate = float(value)
                continue
            if line.startswith('Transmit rate'):
                self.transmit_rate = float(value)
                continue
            if line.startswith('Signal'):
                self.signal = int(value.replace('%',''))
                continue

        return adapter_found
    

# ====================================================================================================
def identify_wifi_adapters() -> List[str]:
    """Return list of installed wifi adapers, None if not found"""
    adapters: List[str] = []
    if OSHelper.is_linux():
        cmd_output, ret_cd = ScannerBase._execute_process(CONSTANTS.IWCONFIG, show_feedback=False)
        if ret_cd == 0:
            for line in cmd_output:
                if 'ESSID' in line:
                    adapters.append(line.split()[0].strip())
    elif OSHelper.is_windows():
        cmd_output, ret_cd = ScannerBase._execute_process('netsh wlan show interfaces', show_feedback=False)
        if ret_cd == 0:
            for line in cmd_output:
                if line.strip().startswith('Name'):
                    adapters.append(line.split(':')[1].strip())

    if len(adapters) > 0:
        return adapters
    
    return None

def identify_all_adapters() -> List[str]:
    """Return list of ALL installed network adapters"""
    # TODO: Build interface list
    adapters = []
    if OSHelper.is_linux():
        lines, _ = ScannerBase._execute_process(f'{CONSTANTS.IFCONFIG} -a', False)
        for line in lines:
             if 'flags' in line:
                 iface_name = line.split(':',1)[0].strip()
                 adapters.append(iface_name)
                 
    elif OSHelper.is_windows():
        lines, _ = ScannerBase._execute_process('ipconfig /all', False)
        for line in lines:
            if 'adapter' in line and '* ' not in line:
                iface_name = line.split('adapter')[1].replace(':','').strip()
                adapters.append(iface_name)
    else:   
        pass # Unsupported OS

    LOGGER.debug(f'- adapters: {", ".join(adapters)}')
    return adapters

if __name__ == "__main__":
    lh.configure_logger(log_level="INFO", log_format=lh.DEFAULT_CONSOLE_LOGFMT)
    import json

    adapter_list = identify_all_adapters()
    LOGGER.info (f'All  Adapters: {adapter_list}')
    wifi_adapter_list = identify_wifi_adapters()
    LOGGER.info(f'WiFi Adapters: {wifi_adapter_list}')

    for adapter_name in adapter_list:
        try:
            LOGGER.info('')
            LOGGER.info(f"Getting info for '{adapter_name}'")
            adapter = WifiAdapterInfo(adapter_name)
            LOGGER.success(f'{json.dumps(o_helper.to_dict(adapter), indent=2)}')
        except NameError  as ne:
            LOGGER.error(f'- {repr(ne)}.  Are you sure its a WiFi adapter?')

