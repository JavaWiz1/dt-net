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
        <li>Register token via dt_tools.cli.set_iphelper_token.py</li>
    </ul>
    <li><b>net_helper</b> - Helper methods for</li>
    <ul>
        <li>IP routines: check validity, type (IPv4/IPv6), wan IP, LAN IP,...</li>
        <li>Lookup routines: ip to hostname, ip to mac,...</li>
        <li>LAN Scan: list of LAN clients.</li>
    </ul>
    <li><b>wol</b> - Send WOL packets to target hosts</li>
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

### use the package manager [pip](https://pip.pypa.io/en/stable/) to install dt-console.

```bash
pip install dt-net [--user]
```

## Usage
A demo cli has been included to show how these modules can be used.  The demo showcases how to use the
many functions in each of the modules.

See [dt_tools.cli.dt_net_demos.py](https://github.com/JavaWiz1/dt-console/blob/develop/dt_tools/cli/dt_net_demos.py) for detailed demo examples (runnable demo)

To run the demo type:
```bash
python -m dt_tools.cli.dt_net_demos

# or if via source (and poetry)
poetry run python -m dt_tools.cli.dt_net_demos
```

Developer package documentation contains details on all classes and supporting code (i.e. constant namespaces and enums) use for method calls.  Docs can be found [here](https://htmlpreview.github.io/?https://github.com/JavaWiz1/dt-console/blob/develop/docs/html/index.html).


### Main classes/modules Overview

#### ConsoleHelper
ConsoleHelper provides methods for managing the console windows.

```python
    from dt_tools.console.console_helper import ConsoleHelper
    import time

    console.clear_screen(cursor_home=True)

    console_size = console.get_console_size()
    row, col = console.cursor_current_position()
    print(f'Console size: {console_size}, cur pos: {row},{col}')

    console.print_at(row=3, col=5, msg="Here we are at row 3, column 5", eol='\n\n')
    time.sleep(.5)

    blue = console.cwrap('blue', cc.CBLUE)
    brown = console.cwrap('brown', cc.CBEIGE)
    green = console.cwrap('green', cc.CGREEN)
    text = f"The {blue} skies and the {brown} bear look wonderful in the {green} forest!"
    print(text)

    row, col = console.cursor_current_position()
    print(f'         at ({row},{col})', flush=True)
    time.sleep(2)
    console.print_at(row,col,'Finished')
```

#### ConsoleInputHelper
ConsoleInputHelper provides a customizable input prompt.

```python
    from dt_tools.console.console_helper import ConsoleInputHelper

    console_input = ConsoleInputHelper()

    resp = console_input.get_input_with_timeout(prompt='Do you want to continue (y/n) > ',
                                                valid_responses=console_input.YES_NO_RESPONSE,
                                                default='y',
                                                timeout_secs=5)
    print(f'  returns: {resp}')

```

#### MessageBox
Message box implements Alert, Confirmation, Input Prompt, Password Prompt message boxes.

```python
    import dt_tools.console.msgbox as msgbox

    resp = msgbox.alert(text='This is an alert box', title='ALERT no timeout')
    print(f'  mxgbox returns: {resp}')

    resp = msgbox.alert(text='This is an alert box', title='ALERT w/Timeout', timeout=3000)
    print(f'  mxgbox returns: {resp}')

```

#### ProgressBar
ProgressBar is an easy to use, customizable console ProgressBar which displays percentage complete and elapsed time.

```python
    from dt_tools.console.progress_bar import ProgressBar
    import time

    print('Progress bar...')
    pbar = ProgressBar(caption="Test bar 1", bar_length=40, max_increments=50, show_elapsed=False)
    for incr in range(1,51):
        pbar.display_progress(incr, f'incr [{incr}]')
        time.sleep(.15)

    print('\nProgress bar with elapsed time...')
    pbar = ProgressBar(caption="Test bar 2", bar_length=40, max_increments=50, show_elapsed=True)
    for incr in range(1,51):
        pbar.display_progress(incr, f'incr [{incr}]')
        time.sleep(.15)
```

#### Spinner
Spinner is an easy to use, customizable console Spinner control which displays spinning icon and elapsed time.

```python
    from dt_tools.console.spinner import Spinner, SpinnerType
    import time

    # Example to display all spinner types for approx 5 sec. apiece
    for spinner_type in SpinnerType:
        spinner = Spinner(caption=spinner_type, spinner=spinner_type, show_elapsed=True)
        spinner.start_spinner()

        # Do long task...
        for cnt in range(1,20):
            time.sleep(.25)

        spinner.stop_spinner()
```


## License
[MIT](https://choosealicense.com/licenses/mit/)
