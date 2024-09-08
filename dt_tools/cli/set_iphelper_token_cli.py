"""
This module creates the token file and stores the token used for interface with ipinfo.io.

To get your token, go to https:/ipinfo.io/missingauth

```
poetry run python -m dt_tools.cli.set_iphelper_token_cli
```

"""
import json

import dt_tools.logger.logging_helper as lh
from dt_tools.console.console_helper import (ColorFG, TextStyle,
                                             ConsoleHelper, ConsoleInputHelper)
from loguru import logger as LOGGER 

import dt_tools.net.ip_info_helper as ih


def manage_token():
    console = ConsoleHelper()
    console_input = ConsoleInputHelper()

    ip_helper = console.cwrap("IpHelper", fg=ColorFG.WHITE2, style=TextStyle.BOLD)
    note = console.cwrap('NOTE:', fg=ColorFG.YELLOW2, style=[TextStyle.BOLD, TextStyle.ITALIC])
    token_file = console.cwrap(ih.IP_INFO_TOKEN_LOCATION, fg=ColorFG.WHITE2, style=TextStyle.BOLD)

    console.print('')
    console.print_line_separator('', 90)
    console.print_line_separator(' IpHelper Token Manager', 90)
    console.print('')
    console.print(f'The {ip_helper} tools and packages (dt-cli-tools, dt-net) need a valid token from ipinfo.io.')
    console.print('  (see https://ipinfo.io/missingauth)')
    console.print('')
    console.print('To enable the tools and packages, a one-time process is necessary to acquire the API token, then')
    console.print('save it locally for future use.')
    console.print('')
    console.print('Once you have aquired a valid token, it may be entered via this script. The token will')
    console.print('saved and made available for the IpHelper routines.')
    console.print('')
    console.print('If you already have a token, but forget what it is, you may log back into ipinfo.io')
    console.print('and retrieve your token.')
    console.print('')
    console.print(f'{note}  The token is stored locally in {token_file}. x')
    console.print( '         format: {"token": "xxxxxxxxxxxxxx"}')
    console.print('')

    if console_input.get_input_with_timeout('Continue (y/n) > ', ['y', 'n']) == 'y':
        token = console_input.get_input_with_timeout('Token > ')
        if len(token.strip()) == 0:
            LOGGER.warning('Empty token, did not save.')
        else:
            token_dict = json.dumps({"token": token})
            ih.IP_INFO_TOKEN_LOCATION.parent.mkdir(parents=True, exist_ok=True)
            ih.IP_INFO_TOKEN_LOCATION.write_text(token_dict)
            LOGGER.success('Token saved.')
        LOGGER.info('')
    
    print('Process complete.')

if __name__ == "__main__":
    lh.configure_logger()
    manage_token()
