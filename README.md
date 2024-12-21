# BLE to MQTT for Home Assistant
## Overview
This repository includes code to support various Bluetooth Low Energy (BLE) sensors in HomeAssistant
via a MQTT gateway.

There are 2 code-streams:
 * A python script that will use a bluetooth radio on the host system
 * A Lua script that will use a dedicated NRF52 dongle

In my home I have about a half-dozen always-on devices that could act as a BLE gateway.  These either
have a builtin bluetooth radio or a USB port that could take a bluetooth dongle.  Originally, I developed
the python code for these devices.  However, despite many attempts using internal or external bluetooth
dongles, only a single one of my systems could maintain reliable bluetooth communication for > 2 weeks
without intervention (and that was a cheap STB).  I spent a lot of time working with bluez to try to
improve reliability, and eventually gave up and decided to use a dedicated ble-to-serial solution.

I recommend using a Seeed XIAO nrf52840 or a nice!Nano (or clone).  They are:
 * extremely easy to program (double-tap RESET to put in programming mode, and upload firmware)
 * extremely reliable
 * very low power
 * very cheap
 * need no soldering
 * use USB-C for power and serial

The host controller for the ble-to-serial device is written in lua because I prefer to have an interpreted
language for decoders, and my preferred host devices are OpenWRT routers which have very limited resources
(often not enough space for a python stack).  Lua is tiny and can be easily fit on all of my devices.

## Rationale
There are many similar projects to do BLE to MQTT, but most seem to have one or more limitations:
* Need to be able to establish and maintain > 10 BLE connections, and provide bi-directional control
  * many solutions provide receive only support
  * many BLE adapters can only support a small number of active connections
* Needs to be extremely reliable
  * Linux BLE dongles and builtin BLE receivers use bluez.  My experience is that many of those are not
    reliable for very-long uptimes when doing continuous scanning (BLE receivers stop responding and need
    to be reset after several days for example)
* Needs to be either a standalone appliance, or very low footprint
  * My personal options were a fully-standalone device (ex ESP32) or to be able to run on an OpenWRT
    router.  I initially started with an ESP32 based solution, but found that I could not maintain
    a sufficient number of connections, and sharing the bandwidth with the Wifi radio may have resulted
    in lost packets.
