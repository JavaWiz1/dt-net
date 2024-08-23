import pathlib
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from time import sleep
from typing import Dict, List, Tuple

from loguru import logger as LOGGER

# from dt_tools.os.os_helper import OSHelper
from dt_tools.console.console_helper import ConsoleInputHelper as console_input

# ============================================================================================================================
# == Module Variables ========================================================================================================   
class CONSTANTS:
    UNKNOWN = 'Unknown'
    HIDDEN = "**hidden**"
    BAND24 = '2.4 MHz'
    BAND5  = '5 MHz'
    WINDOWS = "Windows"
    LINUX = "Linux"
    FILE_LOGFORMAT = "<green>{time:MM/DD/YY HH:mm:ss}</green> |<level>{level: <8}</level>|<cyan>{name:10}</cyan>|<cyan>{line:3}</cyan>| <level>{message}</level>"
    CONSOLE_LOGFORMAT = "<level>{message}</level>"
    NMCLI = '/usr/bin/nmcli'
    IW = '/usr/sbin/iw'
    IWLIST = '/usr/sbin/iwlist'
    IWCONFIG = '/usr/sbin/iwconfig'
    IFCONFIG = '/usr/sbin/ifconfig'

AUTH_MAP = {
    "PSK": "WPA2-Personal",
    "WPA2": "WPA2-Personal",
    "IEEE 802.1X": "WPA2-Enterprise",
    "802.1x": "WPA2-Enterprise",
    "WPA1 WPA2 802.1X": "WPA2-Enterprise"
}


# ============================================================================================================================
# == Data Objects ============================================================================================================   
@dataclass
class BSSID:
    mac: str
    signal: int = -1
    radio_type: str = CONSTANTS.UNKNOWN
    band: str = CONSTANTS.UNKNOWN
    channel: int = -1

@dataclass
class SSID:
    name: str
    net_type: str = CONSTANTS.UNKNOWN
    auth: str = 'Open'
    encryption: str = 'None'

@dataclass
class AccessPoint:
    """AccessPoint/Network definition, SSID and list of associated BSSIDs"""
    ssid: SSID
    bssid: List[BSSID] = field(default_factory=list)


# ============================================================================================================================
# == Scanner Objects =========================================================================================================   
@dataclass
class ScannerBase(ABC):
    interface: str = 'wlan0'
    test_datafile: pathlib.Path = None
    output_datafile: pathlib.Path = None
    logging_level ="INFO"

    @abstractmethod
    def scanner_supported_os(self) -> str:
        LOGGER.warning(f'- Rescan NOT supported for {self.__class__.__name__}')

    @abstractmethod
    def rescan(self) -> bool:
        LOGGER.error(f'Rescan is not supported in {self.__class__.__name__}')
        return False

    @abstractmethod
    def _process_output(self) -> str:
        """Function to process command output based on Scanner"""
        pass

    def scan_for_access_points(self) -> List[AccessPoint]:
        LOGGER.info('')
        LOGGER.info(f'Scan for access points ({self.__class__.__name__})')
        cmd_output = self._scan()
        LOGGER.info('')
        LOGGER.info('Process results of scan')
        return self._process_output(cmd_output)
    
    def _scan(self) -> List[AccessPoint]:
        if self.test_datafile is not None:
            cmd_output = self._get_raw_data()
        else:
            cmd = self.scan_cmd.replace('%interface%', self.interface)
            cmd_output, ret_cd = self._execute_process(cmd)
            if self.output_datafile and ret_cd == 0:
                try:
                    self.output_datafile.write_text('\n'.join(cmd_output))
                    LOGGER.success(f'- Output saved to: {self.output_datafile}')
                except Exception as ex:
                    LOGGER.error(f'- Unable to save output to {self.output_datafile}: {repr(ex)}')
        
        return cmd_output

    def set_output_capture_file(self, filenm: str):
        self.output_datafile = pathlib.Path(filenm)
        if self.output_datafile.is_file():
            LOGGER.debug(f"- Output saved to '{filenm}'")
        else:
            LOGGER.warning(f"- Output file: '{filenm}' not valid, will NOT save output")
            self.output_datafile = ''

    def set_test_datafile(self, filenm: str) -> bool:
        """Set test data filename"""
        self.test_datafile = pathlib.Path(filenm)
        if self.test_datafile.exists():
            LOGGER.debug(f"- Test data file '{self.test_datafile}' exists ")
        else:
            self.test_datafile = None
            LOGGER.error(f"- TEST MODE: test data file: '{filenm}' not found.")
            return False
        return True
    
    @classmethod
    def _get_ap_ssid_entry(cls, ssid_name: str, mac: str, ap_list: List[AccessPoint]) -> Tuple[int, AccessPoint]:
        ap_entry: AccessPoint = None
        tgt_idx = -1
        found = False
        for idx in range(len(ap_list)):
            if ap_list[idx].ssid.name == ssid_name:
                found = True

            if found:
                ap_entry = ap_list[idx]
                tgt_idx = idx
                break

        return tgt_idx, ap_entry
        
    @classmethod
    def _execute_process(cls, cmd: str, show_feedback: bool = True) -> Tuple[List[str], int]:
        """Run the (scan) command and return output as a list of strings"""
        return_code = 0
        cmd_list = cmd.split()
        try:
            if show_feedback:
                LOGGER.debug(f'- Executing: {cmd}')
            else:
                LOGGER.debug(f'- Executing: {cmd}')
            # TODO: How to handle bad return codes and capture output?
            cmd_output = subprocess.check_output(cmd_list, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as cpe:
            #print (netsh_output)
            cmd_output = bytes(f'retCde: {cpe.returncode} output: {cpe.output}', 'ascii')
            return_code = cpe.returncode

        # decode it to strings
        lines = cmd_output.decode('ascii').replace('\r', '').splitlines()
        if ScannerBase.logging_level == "TRACE":
            LOGGER.trace(f'  RetCd: {return_code}')
            for line in lines:
                LOGGER.trace(f'  {line}')
        return lines, return_code
    
    def _get_raw_data(self) -> List[str]:
        data_file = pathlib.Path(self.test_datafile)
        result = ''
        if not data_file.exists():
            LOGGER.error(f'- TEST MODE: data file does not exist. {data_file}')
            raise FileNotFoundError(data_file)
        else:
            LOGGER.warning(f'- TEST MODE: data read from {data_file}')
            result = data_file.read_text()
          
        return result.splitlines()
    

# ===========================================================================================================================   
class WindowsWiFiScanner(ScannerBase):
    scan_cmd = 'netsh wlan show network mode=bssid'

    cmd_force_rescan = 'netsh wlan disconnect'
    interface = None

    def scanner_supported_os(self) -> str:
        return "Windows"
    
    def rescan(self) -> bool:
        LOGGER.info('')
        LOGGER.info('Rescan requested')
        connections_dict = self._connected_to_profiles()
        autoconnect_enabled = False
        for profile, ap in connections_dict.items():
            if self._profile_autoconnect(profile):
                LOGGER.info(f'- Autoconnect enabled for {profile}')
                autoconnect_enabled = True
        
        if not autoconnect_enabled:
            LOGGER.warning('  There are no wifi autoconnections enabled, you will have to manually recoonect to network.')
            if console_input.get_input_with_timeout('  continue (y/n)? ',['y','n']) == 'n':
                return False
            
        LOGGER.info('- Disconnect to trigger re-scan of network')
        netsh_output, ret_cd = self._execute_process(self.cmd_force_rescan, show_feedback=False)
        if ret_cd != 0:
            return False
        
        sleep(5)
        return True
    
    def _process_output(self, netsh_lines: list) -> List[AccessPoint]:
        ap = None
        ap_list = []
        bssid_list = []
        ssid_info: SSID = SSID(CONSTANTS.UNKNOWN)
        bssid_info: BSSID = BSSID(CONSTANTS.UNKNOWN)
        for line in netsh_lines:
            line = line.strip()            
            tokens = line.split(":", maxsplit=1)
            keyword = tokens[0].strip()
            value = '' if len(tokens) == 1 else tokens[1].strip()
            if keyword.startswith("SSID"):
                if ssid_info.name != CONSTANTS.UNKNOWN:
                    # Output last access point definition
                    if bssid_info.mac != CONSTANTS.UNKNOWN:
                        bssid_list.append(bssid_info)
                    ap = AccessPoint(ssid_info, bssid_list)
                    ap_list.append(ap)
                    LOGGER.debug(f'  Adding ssid: {ssid_info} with {len(bssid_list)} bssids')
                name = value if len(value) > 0 else CONSTANTS.HIDDEN
                ssid_info = SSID(name)
                bssid_info = BSSID(CONSTANTS.UNKNOWN)
                bssid_list = []
            elif keyword.startswith("Network type"):
                ssid_info.net_type = value
            elif keyword.startswith("Authentication"):
                ssid_info.auth = value
            elif keyword.startswith("Encryption"):
                ssid_info.encryption = value
            elif keyword.startswith("BSSID"):
                if bssid_info.mac != CONSTANTS.UNKNOWN:
                    bssid_list.append(bssid_info)
                bssid_info = BSSID(value)
            elif keyword.startswith("Signal"):
                bssid_info.signal = int(value.replace('%',''))
            elif keyword.startswith("Radio type"):
                bssid_info.radio_type = value
            elif keyword.startswith("Band"):
                bssid_info.band = value
            elif keyword.startswith("Channel"):
                try:
                    bssid_info.channel = int(value)
                except ValueError:
                    bssid_info.channel = value
        if ssid_info.name != CONSTANTS.UNKNOWN:
            # Append the last access point
            if bssid_info.mac != CONSTANTS.UNKNOWN:
                bssid_list.append(bssid_info)
            ap = AccessPoint(ssid_info, bssid_list)
            ap_list.append(ap)        
            LOGGER.debug(f'  Adding ssid: {ssid_info} with {len(bssid_list)} bssids')

        return ap_list

    def _profiles(self) -> List[str]:
        profiles = []
        netsh_output, _ = self._execute_process('netsh wlan show profiles', False)
        for line in netsh_output:
            line = line.strip()
            if line.startswith("All User Profile"):
                profile_name = line.split(':')[1].strip()
                profiles.append(profile_name)
                LOGGER.trace(f'  found profile: {profile_name}')
        
        return profiles

    def _profile_autoconnect(self, profile: str) -> bool:
        auto_connect = False
        cmd = f'netsh wlan show profile {profile}'
        netsh_output, _ = self._execute_process(cmd, False)
        for line in netsh_output:
            line = line.strip()
            if line.startswith('Connection mode'):
                if "Connect automatically" in line:
                    auto_connect = True
                break
        LOGGER.trace(f'  profile autoconnect is: {auto_connect}')
        return auto_connect
    
    def _connected_to_profiles(self) -> Dict[str, AccessPoint]:
        """
        Return a dictionary of connections, listing wlan profile and associated access point info in format
        {"ProfileName": AccessPoint, ...}
        """
        connected_profiles = {}
        iface = ''
        connected = False
        profile = ''
        # ap_list = List[AccessPoint]
        ssid_info = SSID(CONSTANTS.UNKNOWN)
        bssid_info = BSSID(CONSTANTS.UNKNOWN)                
        netsh_output, _ = self._execute_process('netsh wlan show interfaces', False)
        for line in netsh_output:
            line = line.strip()
            value = '' if ':' not in line else line.split(':', 1)[1].strip()
            if line.startswith('Name'):
                if iface != '':
                    if connected:
                        ap = AccessPoint(ssid_info, [bssid_info])
                        connected_profiles[profile] = ap
                iface = value
                connected = False
                profile = ''
                ssid_info = SSID(CONSTANTS.UNKNOWN)
                bssid_info = BSSID(CONSTANTS.UNKNOWN)                
            elif line.startswith('SSID'):
                ssid_info.name = value
            elif line.startswith('BSSID'):
                bssid_info.mac = value
            elif line.startswith('Radio'):
                bssid_info.radio_type = value
            elif line.startswith('Authentication'):
                ssid_info.auth = value
            elif line.startswith('Cipher'):
                ssid_info.encryption = value
            elif line.startswith('Channel'):
                bssid_info.channel = value
            elif line.startswith('Signam'):
                bssid_info.signal = value.replace('%','')
            elif line.startswith('State'):
                connected = True if value == 'connected' else False
            elif line.startswith('Profile'):
                profile = value

        if iface != '':
            if connected:
                ap = AccessPoint(ssid_info, [bssid_info])
                connected_profiles[profile] = ap

        if ScannerBase.logging_level == "TRACE":
            LOGGER.trace('  connected profiles:')
            for profile in connected_profiles:
                LOGGER.trace(f'    {profile}')

        return connected_profiles


# ===========================================================================================================================   
class IwWiFiScanner(ScannerBase):
    scan_cmd = f'sudo {CONSTANTS.IW} dev %interface% scan'
    
    def scanner_supported_os(self) -> str:
        return "Linux"

    def rescan(self) -> bool:
        return super().rescan()
    
    def _process_output(self, data_list: List[str]) -> List[AccessPoint]:
        results: List[AccessPoint] = []

        ssid_info: SSID = SSID(CONSTANTS.UNKNOWN)
        bssid_info: BSSID = BSSID(CONSTANTS.UNKNOWN)
        bssid_list = []
        for line in data_list:
            line = line.strip()
            value = CONSTANTS.UNKNOWN if ':' not in line else line.split(':',1)[1].strip()
            if line.startswith('BSS') and line != 'BSS Load:':
                if ssid_info.name != CONSTANTS.UNKNOWN:
                    # New entry, append/update list
                    idx, ap = self._get_ap_ssid_entry(ssid_info.name, bssid_info.mac, results)
                    if ap is not None and ap.ssid.name != CONSTANTS.HIDDEN:
                        ap.bssid.append(bssid_info)
                        results[idx] = ap
                        LOGGER.debug(f'  Updating ssid: {ssid_info} with {len(bssid_list)} bssids')
                    else:
                        bssid_list.append(bssid_info)
                        ap = AccessPoint(ssid_info, bssid_list)
                        results.append(ap)
                        LOGGER.debug(f'  Adding ssid: {ssid_info} with {len(bssid_list)} bssids')
                    ssid_info = SSID(CONSTANTS.UNKNOWN)
                    bssid_info = BSSID(CONSTANTS.UNKNOWN)
                    bssid_list = []
                mac = line.replace('BSS ','').split('(')[0].strip()
                bssid_info.mac = mac
            elif line.startswith('freq'):
                bssid_info.band = self._resolve_band(value)
            elif line.startswith('signal'):
                bssid_info.signal = self._resolve_signal_strength(value.split()[0])
            elif line.startswith('SSID'):
                ssid_info.name = value
                if ssid_info.name == '':
                    ssid_info.name = CONSTANTS.HIDDEN # last_ssid_name
            elif line.startswith('* primary channel'):
                bssid_info.channel = int(value)
            elif line.startswith('* Group cipher'):
                ssid_info.encryption = value
            elif line.startswith('* Authentication'):
                ssid_info.auth = AUTH_MAP.get(value, value)

        if ssid_info.name != CONSTANTS.UNKNOWN:
            # New entry, append/update list
            idx, ap = self._get_ap_ssid_entry(ssid_info.name, bssid_info.mac, results)
            if ap is not None:
                ap.bssid.append(bssid_info)
                results[idx] = ap
                LOGGER.debug(f'  Updating ssid: {ssid_info} with {len(bssid_list)} bssids')
            else:
                bssid_list.append(bssid_info)
                ap = AccessPoint(ssid_info, bssid_list)
                results.append(ap)
                LOGGER.debug(f'  Adding ssid: {ssid_info} with {len(bssid_list)} bssids')

        return results
    
    def _resolve_signal_strength(self, freq) -> int:
        i_freq = float(freq)
        sig_strength = int((-33 / i_freq) * 100)
        sig_strength = min(100, sig_strength)
        sig_strength = max(0, sig_strength)
        return sig_strength

    def _resolve_band(self, freq_str: str) -> str:
        if freq_str.startswith('24'):
            return CONSTANTS.BAND24
        elif freq_str.startswith('5'):
            return CONSTANTS.BAND5

        return ''
    
    
# ===========================================================================================================================   
class NetworkManagerWiFiScanner(ScannerBase):
    scan_cmd = f'{CONSTANTS.NMCLI} -t -f ssid,bssid,chan,freq,signal,security,rsn-flags device wifi list'

    def scanner_supported_os(self) -> str:
        return "Linux"

    def rescan(self) -> bool:
        return super().rescan()

    def _process_output(self, data_list: List[str]) -> List[AccessPoint]:
        results: List[AccessPoint] = []

        ssid_info: SSID = None
        bssid_info: BSSID = None
        bssid_list = []
        last_ssid = None
        ssid = None
        for line in data_list:
            line = line.replace("\\:", "-")
            tokens = line.split(':')
            ssid = CONSTANTS.HIDDEN if len(tokens[0]) == 0 else tokens[0]
            mac = tokens[1]
            if len(ssid) > 0 and last_ssid is not None:
                # We have full definition, append to list
                ap = AccessPoint(ssid_info, bssid_list)
                results.append(ap)
                LOGGER.debug(f'  Adding ssid: {ssid_info} with {len(bssid_list)} bssids')
            if len(ssid) > 0:
                last_ssid = ssid
                # Start creating new entry
                ssid_info = SSID(ssid)
                value = tokens[5] if len(tokens[5]) > 0 else 'Open'
                ssid_info.auth = AUTH_MAP.get(value, value)
                ssid_info.net_type = CONSTANTS.UNKNOWN
                ssid_info.encryption = 'CCMP' if 'ccmp' in tokens[6] else 'None'
                bssid_list = []
            bssid_info = BSSID(mac)
            bssid_info.channel = int(tokens[2])
            bssid_info.radio_type = CONSTANTS.UNKNOWN
            bssid_info.signal = int(tokens[4])
            bssid_info.band = self._resolve_band(tokens[3])
            bssid_list.append(bssid_info)

        if ssid is not None:
            # Append last entry
            ap = AccessPoint(ssid_info, bssid_list)
            results.append(ap)
            LOGGER.debug(f'  Adding ssid: {ssid_info} with {len(bssid_list)} bssids')

        return results
    
    @classmethod
    def is_available(cls) -> bool:
        nmcli_output, ret_cd = cls._execute_process(CONSTANTS.NMCLI, show_feedback=False)
        if ret_cd != 0:
            LOGGER.debug(f'- nmcli failure ({ret_cd}) output: {nmcli_output}')
            return False
        for line in nmcli_output:
            if "is not running" in line:
                LOGGER.info('- nmcli is NOT available')
                return False
        LOGGER.debug('- nmcli IS available')
        return True
    
    def _resolve_band(self, freq_str: str) -> str:
        band = ''
        if freq_str.startswith('24'):
            band = CONSTANTS.BAND24
        elif freq_str.startswith('5'):
            band =  CONSTANTS.BAND5

        # LOGGER.trace(f'{freq_str} resolves to {band}')
        return band
    

# ===========================================================================================================================   
class IwlistWiFiScanner(ScannerBase):
    scan_cmd = f'sudo {CONSTANTS.IWLIST} %interface% scanning'

    def scanner_supported_os(self) -> str:
        return "Linux"    

    def rescan(self) -> bool:
        return super().rescan()

    def _process_output(self, data_list: List[str]) -> List[AccessPoint]:
        results: List[AccessPoint] = []
        bssid_list: List[BSSID] = []
        ssid_info = SSID(CONSTANTS.UNKNOWN)
        bssid_info = BSSID(CONSTANTS.UNKNOWN)
        for line in data_list:
            line = line.strip()
            value = CONSTANTS.UNKNOWN if ':' not in line else line.split(':',1)[1].strip()
            if line.startswith('IE') and value.startswith(CONSTANTS.UNKNOWN):
                pass
            else:
                if line.startswith('Cell'):
                    if ssid_info.name != CONSTANTS.UNKNOWN:
                        # New entry, append/update list
                        idx, ap = self._get_ap_ssid_entry(ssid_info.name, bssid_info.mac, results)
                        if ap is not None and ssid_info.name != CONSTANTS.HIDDEN:
                            ap.bssid.append(bssid_info)
                            results[idx] = ap
                            LOGGER.debug(f'  Updating ssid: {ssid_info} with {len(bssid_list)} bssids')
                        else:
                            bssid_list.append(bssid_info)
                            ap = AccessPoint(ssid_info, bssid_list)
                            results.append(ap)
                            LOGGER.debug(f'  Adding ssid: {ssid_info} with {len(bssid_list)} bssids')
                        ssid_info = SSID(CONSTANTS.UNKNOWN)
                        bssid_info = BSSID(CONSTANTS.UNKNOWN)
                        bssid_list = []
                    bssid_info.mac = value
                elif line.startswith('Channel'):
                    bssid_info.channel = int(value.replace('-',":"))
                elif line.startswith('Frequency'):
                    bssid_info.band = self._resolve_band(value)
                elif line.startswith('Quality'):
                    txt_sig = line.split('=')[1].split()[0]
                    signals = txt_sig.split('/')
                    bssid_info.signal = int(int(signals[0]) / int(signals[1]) * 100)
                elif line.startswith('ESSID'):
                    ssid_info.name = value.replace('"','')
                    if ssid_info.name == '':
                        ssid_info.name = CONSTANTS.HIDDEN # last_ssid_name
                elif line.startswith('Group Cipher'):
                    ssid_info.encryption = value
                elif line.startswith('Authentication Suites'):
                    ssid_info.auth = AUTH_MAP.get(value, value)
        
        if ssid_info.name is not None:
            # Last entry
            idx, ap = self._get_ap_ssid_entry(ssid_info.name, bssid_info.mac, results)
            if ap is not None and ssid_info.name != CONSTANTS.HIDDEN:
                ap.bssid.append(bssid_info)
                results[idx] = ap
                LOGGER.debug(f'  Updating ssid: {ssid_info} with {len(bssid_list)} bssids')
            else:
                bssid_list.append(bssid_info)
                ap = AccessPoint(ssid_info, bssid_list)
                results.append(ap)            
                LOGGER.debug(f'  Adding ssid: {ssid_info} with {len(bssid_list)} bssids')

        return results

    @classmethod
    def is_available(cls) -> bool:
        iwlist_output, ret_cd = cls._execute_process(CONSTANTS.IWLIST)
        if "Usage: " not in iwlist_output[0]:
            LOGGER.info(f'- iwlist failure ({ret_cd}) output: {"/n".join(iwlist_output)}')
            return False
        for line in iwlist_output:
            if "doesn't support scanning" in line:
                LOGGER.info('- iwlist is NOT available')
                return False
        
        LOGGER.debug('- iwlist IS available')
        return True

    def _resolve_band(self, freq_str: str) -> str:
        band = ''
        if freq_str.startswith('2.4'):
            band = CONSTANTS.BAND24
        elif freq_str.startswith('5.'):
            band = CONSTANTS.BAND5

        # LOGGER.trace(f'  {freq_str} resolves to {band}')
        return band
    
