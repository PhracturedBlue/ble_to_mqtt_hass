# Lua decoder
This is the recommended decoder for using the NRF BLE-to-serial module.
It controlls an NFR52 BLE deice via a serial port, to handle a range of sensors:

 * BTHome: These sensors are transmit-only and will be autodetected and decoded
 * Engbird temperature sensors: These sensors are transmit-only and will be autodetected and decoded
 * Govee 5086 smart switch: These can be passively monitored for on/off state, or can be actively monitored
   for power usage and to switch devices on/off.  These must be configured in the config file.

Additionally, there is a network receiver that can decode AlarmDecoder signals from a Vista panel (using
and AD2USB and ser2sock installed separately)

The entire directory can be copied and used as is, or the code can be minified and installed as a single fie at the destination

Note that multipe instances can be running in different locations.  Each instance will claim a set of BLE sensors, such
that duplicate messages are not sent to Home Assistant.  There is no attempt to arrbitrate based on RSSI, so this can result in
a device being claimed by a farther instance which can result in less reliability.  This should generlaly not be a problem though
unless the host devices are too close together.

## Building the minified version

### Requirements
 * Docker or podman
 * make

### Building
 * `podman build --tag lua docker/`
 * `make lint` : verify there are no code issues
 * `make minify` : create `_combined.lua` and `_minify.lua`
   * **NOTE: the `minify.lua` is currently not running properly**


## Installing

### Requirements
  * a linux system with the following packages installed:
    * stty
    * lua 5.1
    * luasockets with the serial.so module (see below for OpenWRT)
    * the lua '`bit` or `bitop` module
    * either a copy of this directory, or the `_combined.lua` file renamed to gateway.lua
    * a configured config.json (if using the Govee5086 or AlarmDecoder sensors)
  * a Seeed XIIAO nrf52840 (or equivalent) board with the ble-to-serial code in this repo installed

### Running
  * `./gateway.lua --list` - This should identify the NRF device with something like:
    `/dev/ttyACM1 :  2fe3:0100:ZEPHYR:USB-DEV: 2.00:C9F14BFE611AB1E9`
  * `./gateway.lua --serial "2fe3:0100:ZEPHYR:USB-DEV: 2.00:C9F14BFE611AB1E9" --mqtt "mqtt://<mqtt host>" --logfile ble_gateway.log`
    * see `./gateway.lua --help` for more options

## Config file
If you want to use Govee 5086 smart switches or Ademco sensors with AlarmDecoder, you must configure them 1st in a JSON file

### Govee 5086

You must 1st pair each 5086 device to determine its authentication credentials.  That is beyond the scope of this document, but more
informatino can be found at [Govee-Reverse-Engineering](https://github.com/egold555/Govee-Reverse-Engineering).  Specifically, using
the scan.py and pair.py scripts [here](2fe3:0100:ZEPHYR:USB-DEV: 2.00:C9F14BFE611AB1E9)

The json syntax then looks like:
```
{
  "ble_serial": {
    "GOVEE_5086": {
      "GVH5086XXYY": { "auth": "xxxxxxxxxxxxxxxx", "energy": true, "switch": true },
      ...
    }
  }
}
```
and should be added to the `gateway.lua` cmdline via `--config conf.json`

### Alarm Decoder

The AlarmDecoer device is no longer manufactured, and all code is abandonware.  However, if you have an AD2USB or equivalent, 
you can user the [ser2sock](https://github.com/nutechsoftware/ser2sock) utility to make your devices visible on the network.
In theory an Envisalink could be used instead, although a new receiver would need to be written.  This code is specifically
designed to monitor 5800 series wireless devices.  I do NOT recommend using this code as a primary way to interact with
an alarm system.  It is only recommended for use with automations and to monitor device battery health.

The json syntax for the AlarmDecoder looks like:
```
{
  "alarmdecoder": {
    "HONEYWELL": {
      "0xxxxxx": {"type": "door", "name": "Front Door"},
      ...
    }
  }
}

where `xxxxxx` is the device code (usually found on a sticker on the device).

The valid 'types' are:
 * `door`: a door sensor usually mounted inside the door/fame that has only a single open/close sensor
 * `door_reed`: a door/window sensor usually mounted on the frame which contains a magnetic sensor as well as a wired reed sensor
 * `smoke`: a smoke detector
 * `motion`: a PIR motion detector

## Running on an OpenWRT device

**NOTE: OpenWRT prior to 2024.10 does not ship the needed sserial.so module in the 'luasocket' package (this is fixed in 2024.10).**

### Requirements:
 * Install the followinging packages on OpenWRT
   * kmod-usb-acm
   * coreutils-stty
   * lua
   * luabitop
   * luasocket (>= 3.1.0-2 see the openwrt/ subdir for instructions)

### Installation:
  * ssh root@<host>
    * mkdir /etc/ble_gateway
    * echo "/etc/ble_gateway" >> /etc/sysupgrade.conf
    * edit `/etc/rc.local` and add something like:
      `lua /etc/ble_gateway/gateway.lua -m mqtt://<mqtthost> -o /tmp/log/ble_gateway.log > /dev/null 2>/dev/null &`
  * from host system:
    * cat _combined.lua | ssh root@<host> tee /etc/ble_gateway/gateway.lua
