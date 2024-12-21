# Serial commands (not echoed):
REBOOT              : Soft Reboot
RESCAN              : Force a BLE rescan
LIST                : List known conections
LOG 0/1/2/3         : Set Log Level DEBUG/INFO/WARN/ERROR (1=INFO is the defaut)
SHOWALL 1/0         : Enable/Disable sending of unknown BLE devices (with ADV data) (default=0)
D aa:bb:cc:dd:ee:ff : Delete connections with specified address
G aa:bb:cc:dd:ee:ff E aabbccddeeffgghh GVH5086XXYY : Define Govee connection
  ^                 ^ ^                ^------------ Device name
  |                 | +----------------------------- Auth code
  |                 + ------------------------------ Enable Energy monitor (1=Yes, 0=No)
  +------------------------------------------------- BLE address
S aa:bb:cc:dd:ee:ff # : Set a devie-specific parameter

G 60:74:f4:aa:bb:cc 1 41e3d7c3431cd175 GVH5086XXXX

02 0105
0c 094756483530383636364333
09 ff0388ec0001010100

# Output:
*** <string> : Boot string
DBG <string> : Debug message
INF <string> : Info message
WRN <string> : Warning message
ERR <string> : Error message
RSP <string> : Response to console query.  Will end with 'RSP DONE'
ADV <address> <rssi (hex)> <Advertising data (hex)>                     : Advertisement packet
GOV <address> <rssi (hex)> <name> <power-state (1/0)> <power inf (hex)> : Govee info`

# Getting Govee Authentication code
Use https://github.com/egold555/Govee-Reverse-Engineering (See Products/H5080/pair.py)

# Building for Seeed XIAO-BLE
make build TARGET=xiao_ble
make flash_uf2 TARGET=xiao_ble

# Building for Nice! Nano
make build TARGET=nicenano
make flash_uf2 TARGET=nicenano

# Building for nrf52832_dk -- See below for enabling USB device in podman
make build TARGET=nrf52832_dk
make flash_jlink TARGET=nicenano

# access gdb via:
west debug TARGET=xxxx
enable 'CONFIG_DEBUG_THREAD_INFO' to access thread info in gdb

Building Zephyr Podman Image
make image
The Nordic image can be tested via:
dpodman pull docker.io/nordicplayground/nrfconnect-sdk:v2.6-branch

# Enabling JLink support in podman
1st locate the USB device of JSEGGER from 'lsusb'
2nd chmod +ow /dev/bus/usb/00x/0yy
Note: J-Link does not proved power to the board.  the 'Vcc' pin is actually a reference Vcc
podman run --rm -it -v $PWD/boards/nrf52832_dk:/zephyr/zephyr/boards/nordic/nrf52832_dk -v $PWD:/zephyr/project -w /zephyr/project zephyr:3.7.0-rc2 west flash

# Connecting E73 breakout board
The pinout of the programming header is
1 - GND
2 - Vcc
3 - SWDIO
4 - SWDCLK
5 - RESET (should not be needed)
6 - empty (often connected to P.06 for serial debug at 115200

# Flash XIAO_BLE with segger:
  * Connect SDIO and SCLK to Segger (or DK board)
  * On DK board attach Vdd to VTG.  On Segger Mini atatch Vdd to Vdd
  * Either attach GND to GND or ensure XIAO_BLE has a common ground
  * Program with:
    podman run --privileged --rm -it -v $PWD:/zephyr/project -w /zephyr/project zephyr:3.7.0-rc2 west -v flash --runner openocd --config interface/jlink.cfg --cmd-pre-init 'transport select swd' --cmd-pre-init 'source [find target/nrf52.cfg]'


# via nrf connect:
see: https://devzone.nordicsemi.com/f/nordic-q-a/112591/nordic-zephyr-sdk-scan-behaves-differently-than-upstream-zephyr/491501
The NRF Connect fork uses the Nordic SoftDevice stack which has a different scanning behavior

podman run --rm -v ${PWD}:/workdir/project nordicplayground/nrfconnect-sdk:v2.6-branch west build project -p always -b xiao_ble --build-dir /workdir/project/build
## NOTE: the 'nrfconnect-sdk' has a patched 'zephyr' which can behave slightly differently.  For instance it can do continuous scanning, as opposed
to needing to be stopped/restarted to clear the list of 'seen' addresses

Using openocd to dump firmware with NRF52DK:
set write permission to USB device (/dev/bus/usb/...)
podman run --privileged --rm -it -v $PWD/boards/nrf52832_dk:/zephyr/zephyr/boards/nordic/nrf52832_dk -v $PWD:/zephyr/project -w /zephyr/project zephyr:3.7.0-rc2 openocd -f interface/jlink.cfg -c "transport select swd" -f target/nrf52.cfg
in a 2nd window:
podman exec -it <conatainer> bash
telnet localhost 4444
flash banks
flash read_bank 0 flash-bank0.bin


# This is the cmdline used by 'west debug' when using the nrf52832_dk (example of needed openocd arguments)
/usr/bin/openocd -s /opt/zephyr-sdk/sysroots/x86_64-pokysdk-linux/usr/share/openocd/scripts -c 'tcl_port 6333' -c 'telnet_port 4444' -c 'gdb_port 3333' -c 'set WORKAREASIZE 0x4000' -c 'source [find interface/jlink.cfg]' -c 'transport select swd' -c 'source [find target/nrf52.cfg]' -c '$_TARGETNAME configure -rtos Zephyr' '-c init' '-c targets' '-c halt'
