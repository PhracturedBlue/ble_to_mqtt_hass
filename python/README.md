# Bluetooth to HomeAssistant gateway
This code will use an onboard bluetooth radio or dongle to scan for BLE sensors
and transmit their state to Home Assistant via MQTT.
It is not currently under development as the Lua based approach is now my preferred solution

I ran this code for ~2 years on a S905X3 based STB and it worked very well.  Unfortunately,
I had a lot of reliability issues when trying to use it on different STBs or on general-purpose
Linux hosts (using either internal radios or bluetoothg dongles).  In the end, I gave up and
migrated to using NRF52 based devices as I needed more than one receiver for full coverage in my home.

This code can be run on multipe devices concurrently and each instance will claim a device so duplicate
packets are not sent to Home Assistant.

As it was originally used on a CoreElec based STB, the autostart.sh and venv.sh scripts are specific to
that.

## Install and run
* python3 -m venv .venv
* .venv/bin/pip install -r requirements.txt
* .venv/bin/python3 ble_gateway.py 2> ble_gateway.err

## CoreElec setup

* rsync -a ./ root@<coreelec>:ble-gateway/
* ssh root@<corelec>
* cd ble-gateway/
* ./venv.sh .venc-aarch64
* .venv-aarch64/bin/pip install -r requirements.txt
* ln -s autostart.sh ~/.config/

On CoreElec, python is compiled with --disable-pyc-build which breaks 'wheel'.
See: https://bugs.python.org/issue42446
The fix is to patch wheel after install
use venv.sh to automate this

Manual steps:
python -m venv .venv <- this will fail to install pip
.venv/bin/python3 -m ensurepip --upgrade <- this will install wheel and partially install pip 
edit .venv/lib/python3.8/site-packages/pip/_internal/operations/install/wheel.py
  * modify install_wheel() to force pycompile = False
  * sed -i -e 's/if pycompile:/if False and pycompile:/' .venv/lib/python3.11/site-packages/pip/_internal/operations/install/wheel.py
.venv/bin/python -m pip install --force-reinstall pip
Need to redo the wheel fix for pip:
edit .venv/lib/python3.8/site-packages/pip/_internal/operations/install/wheel.py
  * modify install_wheel() to force pycompile = False

