import dt_tools.logger.logging_helper as lh
from dt_tools.console.console_helper import ConsoleHelper as console
from dt_tools.console.console_helper import ConsoleInputHelper as console_input

from dt_tools.cli.demos.dt_net_helper_demo import demo as net_helper_demo
from dt_tools.cli.demos.dt_ip_info_helper_demo import demo as ip_info_helper_demo
from dt_tools.os.os_helper import OSHelper


if __name__ == "__main__":
    OSHelper.enable_ctrl_c_handler()
    lh.configure_logger(log_format=lh.DEFAULT_CONSOLE_LOGFMT)
    console.clear_screen()
    console.print_line_separator('', 80)
    console.print_line_separator('dt_net Tools Demo', 80)
    console.print('')
    console.print('This demo will show how dt-net tools can be used to get network information')
    console.print('for local and internet addresses.')
    console.print('')
    if console_input.get_input_with_timeout('Run net_helper demo (y/n)? ', ['y','n']) == 'y':
        net_helper_demo()
        console.print('')

    if console_input.get_input_with_timeout('Run ip_info_helper demo (y/n)? ', ['y','n']) == 'y':
        ip_info_helper_demo()
    
    console.print('')
    console.print('Demo complete.')