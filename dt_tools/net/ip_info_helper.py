"""
Helper tools for IP related information.

Uses ipinfo.io API to retrive IP related information.
- A free **API token** is required to call the API
- Tokens can be aquired by going to https://ipinfo.io/signup
- To integrate **token** with this package, run  
```python -m dt_tools.cli.set_iphelper_token```  
or (with poetry)  
```poetry run python -m dt_tools.cli.set_iphelper_token```

To minimize API calls (and response time):
- IP Data is cached locally in ~/.IpHelper/cache.json
- MAC Data is cached locally in ~/.IpHelper/mac_info.json

For devices that are only identified by their IP and MAC address (no hostname),
if hostname known, you may 'force' by manually updating ~/.IpHelper/mac_info.json, 
which is keyed by mac address.
format:
    {
        "XX:XX:XX:XX:XX:XX": {
            "vendor": "Ring LLC",
            "hostname": "Ring.Doorbell"
        },
    }
"""

import json
import pathlib
from datetime import datetime, timedelta
from typing import Dict, List, Tuple
from threading import Semaphore

import requests
import urllib3

from dateutil import parser
from loguru import logger as LOGGER

from dt_tools.net import net_helper as nh
import dt_tools.net.ip_info_helper as ih

BASE_URL='https://ipinfo.io'
TOKEN="NOT SET"

IP_INFO_TOKEN_LOCATION=pathlib.Path('~').expanduser().absolute() / ".IpHelper" / "ipinfo_token.json"
IP_INFO_CACHE_LOCATION=pathlib.Path('~').expanduser().absolute() / ".IpHelper" / "cache.json"
MAC_INFO_LOCATION=pathlib.Path('~').expanduser().absolute() / ".IpHelper" / "mac_info.json"

_SECONDS_IN_MINUTE = 60
_SECONDS_IN_HOUR = 60 * _SECONDS_IN_MINUTE
_CACHE_TTL_HOURS = 48 
_CACHE_SEMAPHORE = Semaphore()
_UNKNOWN = 'unknown'

class IpHelper():
    """
    IP Information helper class.

    This class provides information about an IP address.  
    
    It interfaces with ipinfo.io .
    - Requires a user token which is free.
    - See 'setting up user token' in docs.

    In order to minimize API calls and improve performance, a cache
      for IP and MAC information is created and stored locally.
      
    The local data will be refresed if it is > 48 hours old. It can also
    be manually refreshed/cleared from cache.
    
    Returns:

        For WAN IPs:
            ip         : xxx.xxx.xxx.xxx
            hostname   : hostname.domain
            city       : Atlanta
            region     : Georgia
            country    : US
            loc        : 33.7490,-84.3880
            org        : XXXXXXXXXXXX
            postal     : 30302
            timezone   : America/New_York

        For LAN IPs:
            ip         : xxx.xxx.xxx.xxx
            hostname   : hostname.domain[or workgroup]
            bogon      : True
            mac        : XX:XX:XX:XX:XX:XX
            vendor     : Raspberry Pi Trading Ltd

    """
    # Class variables
    _cache_mtime: float = 0.0
    _cache: Dict[str, dict] = None
    _mac_info: Dict[str, dict] = None  # Manually maintained.
    _token_initialized: bool = False

    @classmethod
    def __init__(cls, purge_stale_entries: bool = True, no_token:bool = False):
        if not no_token:
            cls._validate_token()        
        cls._load_cache(purge_stale_entries)

    @classmethod
    def _validate_token(cls) -> bool:
        LOGGER.debug('Token validation in progress...')
        rc = -1
        if not cls._token_initialized:
            if not IP_INFO_TOKEN_LOCATION.exists():
                LOGGER.error('Cached token NOT found.')
                cls._raise_token_error()            
            token_dict: dict = json.loads(IP_INFO_TOKEN_LOCATION.read_text())
            ih.TOKEN = token_dict.get('token', 'NOT VALID')
            cls._token_initialized = True
            ip_info, rc = cls.get_wan_ip_info()
            if rc != 200:
                LOGGER.error(f'Token check returns: {(ip_info)}')
                cls._raise_token_error()

        return True

    @classmethod
    def _raise_token_error(cls):
        LOGGER.warning('A token is required for IpHelper to function.')
        LOGGER.warning('Tokens are free, to get your token, go to "https://ipinfo.io/missingauth')
        LOGGER.warning('When you have a token run dt_set_iptoken to set the token for IpHelper.')
        raise RuntimeError('Invalid token for ipinfo.io.  See log and https://ipinfo.io/missingauth')

    @classmethod        
    def _load_cache(cls, purge_stale: bool = False):
        _CACHE_SEMAPHORE.acquire(timeout=15.0)
        if cls._refresh_required:
            IpHelper._cache = {}
            if not IP_INFO_CACHE_LOCATION.exists():
                cls.clear_cache()
            try:
                buffer = IP_INFO_CACHE_LOCATION.read_text()
                if buffer == "":
                    buffer = "{}"
                IpHelper._cache = json.loads(buffer)
                LOGGER.debug(f'{len(IpHelper._cache)} IpHelper cache entries loaded.')
                if purge_stale:
                    dropped = cls._drop_stale_entries()
                    LOGGER.debug(f'{dropped} IpHelper cache stale entries dropped.')
                IpHelper._cache_mtime = IP_INFO_CACHE_LOCATION.stat().st_mtime
            except Exception as ex:
                LOGGER.error(f'Unable to load IP Info Cache: {IP_INFO_CACHE_LOCATION}')
                LOGGER.warning(f'  {repr(ex)}')

        if IpHelper._mac_info is None:
            MAC_INFO_LOCATION.parent.mkdir(exist_ok=True)
            MAC_INFO_LOCATION.touch(exist_ok=True)
            buffer = MAC_INFO_LOCATION.read_text()
            if buffer == "":
                buffer = "{}"
            IpHelper._mac_info = json.loads(buffer)

        _CACHE_SEMAPHORE.release()

    @property
    def _refresh_required(cls) -> bool:
        refresh = False
        if IP_INFO_CACHE_LOCATION.exists():
            last_update = IP_INFO_CACHE_LOCATION.stat().st_mtime
            if last_update > IpHelper._cache_mtime:
                # Cache has been updated
                refresh = True
        elif IpHelper._cache is None:
            refresh = True

        # LOGGER.debug(f'refresh_required(): {refresh},')
        return refresh

    @classmethod
    def _stale(self, ip_address: str) -> bool:
        """Return true if cached entry is stale"""
        ip_info = IpHelper._cache.get(ip_address, None)
        if ip_info:
            cached_time = ip_info.get('_cached', None)
            if cached_time:
                created = parser.parse(cached_time)
                delta = datetime.now() - created
                age_in_hours = delta.total_seconds() / _SECONDS_IN_HOUR
                # LOGGER.debug(f'{ip_info["hostname"]} age in hours {age_in_hours}')
                if age_in_hours > _CACHE_TTL_HOURS:
                    return True
            
        return False

    @classmethod
    def _age(cls, entry: dict) -> str:
        cached_time =  entry.get('_cached', None)
        age = 'N/A'
        if cached_time:
            created = parser.parse(cached_time)
            td = datetime.now() - created
            age = f'{td.days} days, {td.seconds//3600} hours, {(td.seconds//60)%60} minutes'
        return age

    @classmethod
    def _expires(cls, entry: dict) -> str:
        cached_time =  entry.get('_cached', None)
        expires = "Unknown"
        ttl = 'N/A'
        if cached_time:
            created = parser.parse(cached_time)
            expire_time = created + timedelta(hours=_CACHE_TTL_HOURS)
            ttl = expire_time - datetime.now()
            if ttl.seconds < 0:
                expires = "expired."
            else:
                expires = f'{ttl.days} days, {ttl.seconds//3600} hours, {(ttl.seconds//60)%60} minutes'
        return expires

    @classmethod
    def _drop_stale_entries(self) -> int:
        dropped = 0
        del_list = []
        for ip_address in IpHelper._cache.keys():
            # Create list of IPs to be removed
            if self._stale(ip_address):
                del_list.append(ip_address)
        for ip_address in del_list:
            # Remove identified IPs
            self.clear_cache(ip_address)
            dropped += 1
        return dropped 
    
    @property
    def cache_dict(cls) -> dict:
        """
        The IP Info cache dictionary.
        """
        return IpHelper._cache
            
    @classmethod            
    def clear_cache(cls, ip_address: str = None):
        """
        Clear the IP Info cache.

        Keyword Arguments:
            ip_address -- IP address to be cleared (default: {None})
              If None, all entries will be removed.
        """
        IP_INFO_CACHE_LOCATION.parent.mkdir(exist_ok=True)
        IP_INFO_CACHE_LOCATION.touch(exist_ok=True)
        cls._load_cache()
        initial_cache_len = len(IpHelper._cache)
        if ip_address:
            if ip_address in IpHelper._cache.keys():
                del IpHelper._cache[ip_address]
                _CACHE_SEMAPHORE.acquire(timeout=2.0)
                IP_INFO_CACHE_LOCATION.write_text(json.dumps(IpHelper._cache))
                _CACHE_SEMAPHORE.release()
                IpHelper._cache_mtime = IP_INFO_CACHE_LOCATION.stat().st_mtime
                LOGGER.info(f'{ip_address} removed from cache')
            else:
                LOGGER.warning(f'{ip_address} does NOT exist in cache')
        else:
            _CACHE_SEMAPHORE.acquire(timeout=2.0)
            IP_INFO_CACHE_LOCATION.write_text("{}")
            _CACHE_SEMAPHORE.release()
            IpHelper._cache = {}
            IpHelper._cache_mtime = IP_INFO_CACHE_LOCATION.stat().st_mtime
        
        cur_len = len(IpHelper._cache)
        removed_cnt = initial_cache_len - cur_len
        LOGGER.debug(f'IpHelper Cache cleared.  {removed_cnt} entries removed. {cur_len} entries remaining.')

    @classmethod
    def is_cached(cls, ip_address: str) -> bool:
        """
        Check if IP address is in cache.

        Arguments:
            ip_address -- Ip address to be checked.

        Returns:
            True if found else False.
        """
        cls._load_cache()  # Load cache if needed
        ip_info = IpHelper._cache.get(ip_address, None)
        if ip_info:
            return ip_info.get('_cached', False)
    
        return False
    
    @classmethod
    def get_ip_info(cls, ip_address: str, 
                    include_unknown_fields: bool = False, 
                    include_private_fields: bool = False,
                    bypass_cache: bool = False) -> dict:
        """
        Get all information related to IP Address

        Arguments:
            ip_address: Target IP address.

        Keyword Arguments:
            bypass_cache: If true, force API call and refresh (default: {False}).

        Returns:
            JSON dictionary of all data related to target IP address.
        """
        urllib3.disable_warnings()
        cls._load_cache() 
        entry_updated = False
        if not nh.is_ipv4_address(ip_address):
            ip_info = {'ip': ip_address, "title": "Not IPv4 address", "error": "Only IPv4 addresses supported"}
            return ip_info
            
        if bypass_cache:
            LOGGER.debug('Bypassing cache lookup')
            ip_info = None
        else:
            ip_info = IpHelper._cache.get(ip_address, None)
            if ip_info and cls._stale(ip_address):
                LOGGER.debug(f'{ip_address} stale, will re-fresh')
                ip_info = None

        if ip_info is None:
            LOGGER.debug(f'{ip_address} NOT in cache or stale')
            url=f'{BASE_URL}/{ip_address}?token={TOKEN}'
            try:
                resp = requests.get(url, verify=False)
                ip_info = resp.json()
                entry_updated = True
            except Exception as ex:
                resp = ""
                LOGGER.debug(f'ERROR- url: {url} ex: {repr(ex)}')
                ip_info = {'ip': {ip_address}, "title": "Error in API call", 'error': f'Exception: {url}- {repr(ex)}'}

        if 'error' in ip_info.keys():
            LOGGER.warning(f'ERROR - url: {url}  resp: {ip_info}')
            return ip_info

        ip = ip_info['ip']
        mac = ip_info.get('mac', _UNKNOWN)
        if ip_info.get('hostname', None) is None:
            LOGGER.debug(f'get hostname from ip {ip}')
            ip_info['hostname'] = nh.get_hostname_from_ip(ip)
            if _UNKNOWN not in ip_info['hostname']:        
                entry_updated = True

        if _UNKNOWN in mac:
            LOGGER.debug(f'get mac address for ip {ip}')
            mac = nh.get_mac_address(ip)
            if mac is None:
                mac = nh.get_mac_address(ip, via_ARP_broadcast=True)
            if mac is not None:
                ip_info['vendor'] = nh.get_vendor_from_mac(mac)
                entry_updated = True
            else:
                mac = _UNKNOWN

        if _UNKNOWN not in mac:
            ip_info['mac'] = mac
            if _UNKNOWN in ip_info['hostname']:
                hostname = IpHelper._mac_info.get(mac,{'hostname': _UNKNOWN})['hostname']
                ip_info['hostname'] = f'-> {hostname}'
                if _UNKNOWN not in hostname:
                    entry_updated = True
            if _UNKNOWN in ip_info['vendor']:
                vendor = IpHelper._mac_info.get(mac,{'vendor': _UNKNOWN})['vendor']
                ip_info['vendor'] = f'-> {vendor}'
                if _UNKNOWN not in vendor:
                    entry_updated = True

        if entry_updated:
            ip_info["_cached"] = datetime.now().isoformat() 
            cls._load_cache() 
            _CACHE_SEMAPHORE.acquire(timeout=5.0)
            IpHelper._cache[ip_address] = ip_info
            # TODO: Performance, ONLY write new entry
            LOGGER.debug(f'SUCCESS: cache updated: {ip}/{ip_info["hostname"]}/{mac}')
            IP_INFO_CACHE_LOCATION.write_text(json.dumps(IpHelper._cache))
            _CACHE_SEMAPHORE.release()
            IpHelper._cache_mtime = IP_INFO_CACHE_LOCATION.stat().st_mtime
        
        if not include_private_fields or not include_unknown_fields:
            new_dict = {}
            for key, value in ip_info.items():
                if not include_private_fields and key.startswith('_'):
                    continue
                if not include_unknown_fields and value == _UNKNOWN:
                    continue
                new_dict[key] = value
            ip_info = new_dict

        return ip_info

    @classmethod
    def get_wan_ip_info(cls) -> Tuple[dict, int]:
        urllib3.disable_warnings()
        cls._validate_token()
        ip_info = None
        url=f'{BASE_URL}?token={TOKEN}'
        resp = ""
        rc = -1
        try:
            resp = requests.get(url, verify=False)
            ip_info = resp.json()
            rc = resp.status_code
        except Exception as ex:
            ip_info = {'error': f'Exception: {repr(ex)}'}

        if 'error' in ip_info:
            LOGGER.warning(f'ERROR- url: {url}  resp: {ip_info}')

        return (ip_info, rc)
        
    @classmethod        
    def find_in_cache(cls, search_token: str) -> List[str]:
        """
        TODO: NEEDS Work


        Arguments:
            search_token: _description_

        Returns:
            _description_
        """
        cls._load_cache() # update memory with any changes
        found_keys = []
        for key, entry in IpHelper._cache.items():
            for field_val in entry.values():
                if search_token.lower() in str(field_val).lower():
                    found_keys.append(key)
                    LOGGER.debug(f'- found {key} in {field_val}')
                    continue

        found = len(found_keys)
        if found == 0:
            LOGGER.warning(f'- Search key [{search_token}] NOT found')
        else:
            for key in found_keys:
                cls.list_cache(key)
            LOGGER.success(f'- {found} entries found.')

        return found_keys
        
    @classmethod
    def list_cache(cls, ip: str = None):
        """
        Print formatted contents of cache to console.

        Keyword Arguments:
            ip: Target IP Address (default: {None}).
              If None, all entries will be output.
        """
        cls._load_cache() # Update memory with any changes
        if len(IpHelper._cache) == 0:
            LOGGER.warning('Sorry, cache is empty')
        elif ip is not None:
            entry = IpHelper._cache.get(ip, None)
            if entry:
                LOGGER.success(f'-- {ip} ---------------------------------------')
                cls._print_entry(entry)
            else:
                LOGGER.warning(f'{ip} does NOT exist in cache.')
        else:
            for key, entry in IpHelper._cache.items():
                LOGGER.success(f'-- {key} ---------------------------------------')
                cls._print_entry(entry)
                LOGGER.info('')
            LOGGER.info(f'IP Info cache contains {len(IpHelper._cache)} entries')

    @classmethod
    def _print_entry(cls, entry: dict, show_all: bool = True):
        entry['_cache_age'] = cls._age(entry)
        entry['_expires'] = cls._expires(entry)
        entry['_stale'] = cls._stale(entry['ip'])
        for k,v in entry.items():
            if not show_all and k.startswith('_'):
                pass
            else:
                LOGGER.info(f'  {k:10} : {v}')

