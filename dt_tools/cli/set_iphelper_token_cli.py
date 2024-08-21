import json

import dt_tools.logger.logging_helper as lh
from dt_tools.console.console_helper import (ColorFG, ColorStyle,
                                             ConsoleHelper, ConsoleInputHelper)
from loguru import logger as LOGGER

import dt_tools.net.ip_info_helper as ih


def manage_token():
    console = ConsoleHelper()
    console_input = ConsoleInputHelper()

    ip_helper = console.cwrap("IpHelper", ColorFG.WHITE, ColorStyle.BOLD)
    note = console.cwrap('NOTE:', color=ColorFG.YELLOW)
    token_file = console.cwrap(ih.IP_INFO_TOKEN_LOCATION, ColorFG.WHITE, ColorStyle.BOLD)

    console.print('')
    console.print_line_seperator('', 90)
    console.print_line_seperator(' IpHelper Token Manager', 90)
    console.print('')
    console.print(f'{ip_helper} needs a valid token from ipinfo.io.  (see https://ipinfo.io/missingauth)')
    console.print('')
    console.print('This is a one-time process to acquire the API token, then to save it locally')
    console.print('for future use.')
    console.print('')
    console.print('Once you have aquired a valid token, it may be entered via this script and will')
    console.print('be made available to the IpHelper routines.')
    console.print('')
    console.print('If you already have a token, but forget what it is, you may log back into ipinfo.io')
    console.print('and retrieve your token.')
    console.print('')
    console.print(f'{note}  The token is stored locally in {token_file}.')
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
