# dt-net

dt-net is a Python library to simplify network interactions.  It has been tested in both Windows and Linux.

Features include:
<ul>
    <li><b>ip_info_helper</b> - Retrieve info for local and internet IP addresses.</li>
    <ul>
        <li>Uses ipinfo.io API to retrive IP related information.</li>
        <li>Has local cache for performance and minimizing API calls.</li>
        <li>For WAN IPs:</li>
        <ul>
            <li>ip, hostname, city, region, country, GPS location, zip-code, timezone
        </ul>
        <li>For LAN IPs:</li>
        <ul>
            <li>ip, hostname, bogon (identifies as local IP), mac, mac vendor</li>
        </ul>
        <li>A free **API token** is required to call the API</li>
        <li>Tokens can be aquired by going to https://ipinfo.io/signup</li>
        <li>Register token via dt_tools.cli.set_api_tokens.py (from [dt-foundation package](https://github.com/JavaWiz1/dt-foundation) 
            or [dt-cli-tools package](https://github.com/JavaWiz1/dt-cli-tools))</li>
    </ul>
    <li><b>net_helper</b> - Helper methods for</li>
    <ul>
        <li>IP routines: check validity, type (IPv4/IPv6), wan IP, LAN IP,...</li>
        <li>Lookup routines: ip to hostname, ip to mac,...</li>
        <li>LAN Scan: list of LAN clients.</li>
    </ul>
    <li><b>wifi_scanner</b> - Identify wifi access points and their attributes.</li>
    <li><b>wol</b> - Send WOL packets to target hosts.</li>
</ul>


## Installation

### Download source code from githup via git
```bash
git clone https://github.com/JavaWiz1/dt-net.git
```
Note, when downloading source, [Poetry](https://python-poetry.org/docs/) was used as the package manager.  Poetry
handles creating the virtual environment and all dependent packages installs with proper versions.

To setup virtual environment with required production __AND__ dev ([sphinx](https://www.sphinx-doc.org/en/master/)) dependencies:
```bash
poetry install
```

with ONLY production packages (no sphinx):
```bash
poetry install --without dev
```

### use the package manager [pip](https://pip.pypa.io/en/stable/) to install dt-net.

```bash
pip install dt-net [--user]
```

## Usage
A demo cli has been included to show how these modules can be used.  The demo showcases how to use the
many functions in each of the modules.

See [dt_tools.cli.demos.dt_net_demos.py](https://github.com/JavaWiz1/dt-net/blob/develop/dt_tools/cli/demos/dt_net_demos.py) for detailed demo examples (runnable demo)

To run the demo type:
```bash
python -m dt_tools.cli.demo.dt_net_demos

# or if via source (and poetry)
poetry run python -m dt_tools.cli.demos.dt_net_demos
```

Developer package documentation contains details on all classes and supporting code (i.e. constant namespaces and enums) use for method calls.  Docs can be found [here](https://htmlpreview.github.io/?https://github.com/JavaWiz1/dt-net/blob/develop/docs/html/index.html).


## Main classes/modules Overview

### IpHelper (class)
This class provides information about an IP address.  

It interfaces with the free **ipinfo.io** site.  The ipinfo.io site
requires a user token which is free.

- See 'setting up user token' in docs for information on aquiring and setting up token.

In order to minimize API calls and improve performance, a cache
for IP and MAC information is created and stored locally.
    
The local data will be refresed if it is > 48 hours old. It can also
be manually refreshed/cleared from cache.

The class provides the following information:

For WAN IPs:

- ip         : xxx.xxx.xxx.xxx
- hostname   : hostname.domain
- city       : Atlanta
- region     : Georgia
- country    : US
- loc        : 33.7490,-84.3880
- org        : XXXXXXXXXXXX
- postal     : 30302
- timezone   : America/New_York

For LAN IPs:

- ip         : xxx.xxx.xxx.xxx
- hostname   : hostname.domain[or workgroup]
- bogon      : True (identifies this as a local IP)
- mac        : XX:XX:XX:XX:XX:XX
- vendor     : Raspberry Pi Trading Ltd

```python
    from dt_tools.net.ip_info_helper import IpHelper as helper
    import time

    local_ip = helper.get_local_ip()
    wan_ip = helper.get_wan_ip()
    google_ip = helper.get_ip_from_hostname('google.com')

    ip_dict = {"Local IP": local_ip, "WAN IP": wan_ip, "Google IP": google_ip, "Bad Address": "999.999.999.999"}
    for ip_name, ip in ip_dict.items():
        ip_dict = IpHelper.get_ip_info(ip)
        print('-----------------------------------------------')
        if 'error' in ip_dict.keys():
            print(f'IP Address      : {ip} ERROR')
        for key, val in ip_dict.items():
            print(f'{key:15} : {val}')
        time.sleep(2)

```

---

### net_helper.py (module)

Network utilities helper module.

Functions to assist with network related information and tasks.

- ping
- local IP address
- get ip for given hostname
- get hostname for given ip
- get mac address for given hostname or ip
- get mac vendor
- get local client info on LAN

---

### WiFiAdapterInfo (class) / nic.py (module)

Class and function to identify and report on Network cards (nic) and specifically WiFi cards and capabilities.

Information includes:

    - Adapter Name
    - MAC address
    - SSID/BSSIDs
    - Radio type
    - Authentication method
    - Cipher used for encryption
    - Frequence Band of radio
    - Broadcast channel
    - Speed Transmit/Recieve
    - Signal strength
  
---

### wifi_scanner.py (module)

Scan for local access points and capture AP information.

Module contains classes -

- **SSID**: WiFi Network id information.
- **BSSID**: Unique access point id information.
- **AccessPoint**: Defines the WiFi network SSID and assocated BSSID's.
- **Scanners**: Scanners for Windows and Linux that gather WiFi network information.


```python

    from dt_tools.os.os_helper import OSHelper
    import dt_tools.net.nic as nic_helper

    wifi_adapter_list = nic_helper.identify_wifi_adapters()
    if len(wifi_adapter_list) == 0:
        print('No WiFi adapters available.')
    else:
        scanner = None
        nic_name = wifi_adapter_list[0]
        if OSHelper.is_windows():
            scanner = WindowsWiFiScanner(nic_name)
        elif OSHelper.is_linux():
            scanner = IwlistWiFiScanner(nic_name)
        else:
            print('un-supported OS.')
        if scanner is not None:
            ap_list = scanner.scan_for_access_points()
            print(f'{len(ap_list)} access points identified.')
            names = [x.ssid.name for x in ap_list]
            print(','.join(names))
```

---

### WOL (class)

Wake-on-LAN utility class

This class can be used to send WOL packet to target machines via IP or Hostname.

The wol function can optionally wait for the host to 'wake-up' and provide a
status message indicating success or failure.


```python

    from dt_tools.net.wol import WOL

    wol = WOL()
    wol.send_wol_to_host(myTargetHost, wait_secs=60)
    print(wol.status_message)

```

## License
[MIT](https://choosealicense.com/licenses/mit/)
