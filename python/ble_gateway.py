#!/bin/bash
''''/bin/true
SCRIPTDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" > /dev/null && pwd )"
exec $SCRIPTDIR/python/bin/python3 $0 "$@"
exit
''' # Python starts here '''

import os
import sys
import json
import time
import re
import asyncio
import socket
import hashlib
import logging
import logging.handlers
from collections import deque
from contextlib import AsyncExitStack
from datetime import datetime
from struct import unpack

import aiomqtt
from bleak import BleakScanner, BleakClient, BleakError

# pylint: disable=too-few-public-methods
# pylint: disable=too-many-instance-attributes
# pylint: disable=broad-exception-caught

VERSION = " ".join([
    os.path.basename(__file__).rsplit('.', 1)[0],
    hashlib.md5(open(__file__,'rb').read()).hexdigest()[:12], # pylint: disable=consider-using-with
    datetime.fromtimestamp(os.stat(__file__).st_mtime).isoformat()])

MQTT_HOST = "<mqtt host>"
MQTT_PORT = 1883
GOVEE_5086 = {
    'GVH5086XXXX': 'yyyyyyyyyyyyyyyy',
}
CONNECTABLE = GOVEE_5086

REPEAT_TIME = 120
ERROR_SLEEP = 10
HOSTNAME = socket.gethostname().split('.')[0]

BASE_TOPIC = f"/ble/{HOSTNAME}"
AVAILABILITY_TOPIC = f"/ble/{HOSTNAME}/status"

class Connect(Exception):
    """Trigger a BLE connection"""

class HexJsonEncoder(json.JSONEncoder):
    """convert byte-arrays to hex during json encoding"""
    def default(self, obj):  # pylint: disable=arguments-renamed
        if isinstance(obj, (bytearray, bytes)):
            return "".join([f"{_:02X}" for _ in obj])
        return super().default(obj)

class HassDiscovery:
    """Hass Discovery"""
    def __init__(self, component, sensor_name, name, topic, availability_topic, **kwargs):
        # pylint: disable=too-many-arguments
        self.unique_id = f"{sensor_name}_{name}".replace(' ', '_').lower()
        self.topic = f"homeassistant/{component}/{self.unique_id}/config"
        self.availability_topic = availability_topic
        self.payload = {
          "name": name,
          "uniq_id": self.unique_id,
          "stat_t": topic, # "esphome/leak-detect-laundry/sensor/laundry_temperature/state",
          "avty": [
             {'topic': AVAILABILITY_TOPIC},
             {'topic': self.availability_topic},
             ],
          "avty_mode": "all",
          }
        if component == "sensor":
            self.payload.update({
                "dev_cla": kwargs['device_class'],
                "unit_of_meas": kwargs['units'],
                "stat_cla": "measurement"
                })
        self.payload.update({
            "dev": {
                "ids": sensor_name,
                "name": sensor_name,
                "sw": VERSION,
                }
            })
    async def publish(self, mqtt):
        """Publish discovery topic"""
        await mqtt.publish(self.topic, payload=json.dumps(self.payload), retain=True)

class Entity:
    """Basic Entity"""
    def __init__(self, device, *, detect_duplicates=True):
        self.address = device.address
        self.detect_duplicates = detect_duplicates
        self.topic = f"{BASE_TOPIC}/{self.address}"

    async def publish(self, mqtt, payload):
        """Publish update to MQTT"""
        await mqtt.publish(self.topic, payload=payload)

class Sensor(Entity):
    """Sensor"""
    def __init__(self, device, device_name, value_name,
                 availability_topic, device_class, units, *,
                 discover=True, detect_duplicates=True):
        # pylint: disable=too-many-arguments
        super().__init__(device, detect_duplicates=detect_duplicates)
        self.topic = f"{BASE_TOPIC}/{device_name}/{value_name}/state"
        self.value = None
        self.name = value_name
        self.sent_discovery = False
        if discover:
            self.hass = HassDiscovery("sensor", device_name, value_name, self.topic,
                                      availability_topic,
                                      device_class=device_class, units=units)
        else:
            self.hass = None

    async def publish(self, mqtt, _payload=None):
        if not self.sent_discovery and self.hass:
            await self.hass.publish(mqtt)
            self.sent_discovery = True
        await super().publish(mqtt, str(self.value))

class BinarySensor(Sensor):
    """Binary Sensor"""
    def __init__(self, device, device_name, value_name,
                 availability_topic, *,
                 discover=True, detect_duplicates=True):
        # pylint: disable=too-many-arguments
        super().__init__(device, device_name, value_name, None, None, None,
                         discover=False, detect_duplicates=detect_duplicates)
        if discover:
            self.hass = HassDiscovery("binary_sensor", device_name, value_name, self.topic,
                                      availability_topic)

class Device:
    """Base Device"""
    def __init__(self, device, name=None, timeout=0):
        self.device = device
        base = self.__class__.__name__.replace('Device', '').lower()
        if base:
            base += "_"
        self.name = (base + (name or device.address)).replace(':','').replace(' ', '')
        self.address = device.address
        self.availability_topic = f"{AVAILABILITY_TOPIC}/{self.name}"
        self.timeout = timeout
        self.next_timeout = None
        self.entities = {}
        self.connections = []
        self.mfg_data_fix = None
        self.seen = {}
        self.is_online = False

    def update_timeout(self):
        """Update timeout time"""
        if self.timeout:
            self.next_timeout = time.time() + self.timeout

    async def set_offline(self, mqtt):
        """Set device as offline"""
        await mqtt.publish(self.availability_topic, "offline", retain=True)
        self.is_online = False

    async def set_online(self, mqtt):
        """Set device as online"""
        if not self.is_online:
            await mqtt.publish(self.availability_topic, "online", retain=True)
            self.is_online = True

    def pre_process(self, data, advertisement_data):
        """Begin parsing advertisement_data"""
        if advertisement_data.local_name:
            data['Name'] = advertisement_data.local_name
            data['Connected'] = data['Name'] in self.connections
        if advertisement_data.service_uuids:
            data['UUIDs'] = [re.sub(r'0000(\S{4})-0000-1000-8000-00805f9b34fb', r'\1', _)
                             for _ in advertisement_data.service_uuids]
        if advertisement_data.service_data:
            data['ServiceData'] = {
                re.sub(r'0000(\S{4})-0000-1000-8000-00805f9b34fb', r'\1', _k): _v
                for _k, _v in advertisement_data.service_data.items()}
        if advertisement_data.manufacturer_data:
            mfg_data = []
            for _k, _v in advertisement_data.manufacturer_data.items():
                mfg_data.append(f"{_k& 0xff:02X}{(_k>>8)&0xff:02X}" +
                               "".join([f"{_:02X}" for _ in _v]))
            if not mfg_data:
                data['ManufacturerData'] = ''
            elif self.mfg_data_fix:
                pruned_data = [_ for _ in mfg_data if _ not in self.mfg_data_fix]
                if pruned_data:
                    data['ManufacturerData'] = pruned_data[-1]
                else:
                    data['ManufacturerData'] = mfg_data[-1]
                self.mfg_data_fix = mfg_data
            else:
                data['ManufacturerData'] = mfg_data[-1]
                self.mfg_data_fix = mfg_data

    def post_process(self, data, advertisement_data):
        """Finish parsing advertisement_data"""
        if advertisement_data.tx_power is not None:
            data['TxPower'] = advertisement_data.tx_power
        data['RSSI'] = advertisement_data.rssi

    def is_seen(self, data):
        """Check if device has been seen with the same adv data within a given timeframe"""
        now = time.time()
        data = data.copy()
        data.pop('RSSI', None)
        data.pop('TxPower', None)
        key = json.dumps(data, cls=HexJsonEncoder)
        if key not in self.seen or now - self.seen[key] > REPEAT_TIME:
            self.seen[key] = now
            for key, seen_time in self.seen.copy().items():
                if now - seen_time > REPEAT_TIME:
                    del self.seen[key]
            return None
        return time.time()-self.seen[key]

    async def process(self, advertisement_data, mqtt):
        """Process advertisement data"""
        self.update_timeout()
        if not self.entities:
            self.entities['default'] = Entity(self.device)
        data = {}
        self.pre_process(data, advertisement_data)
        self.post_process(data, advertisement_data)

        #print(data)
        try:
            mqtt_data = json.dumps(data, cls=HexJsonEncoder)
        except Exception as _e:
            logging.error("Failed to parse json data: %s", data)
            return
        if last_seen := self.is_seen(data):
            logging.debug("Not Sending: %s (%ss left)", self.address,
                          REPEAT_TIME - last_seen)
        else:
            logging.info("%s    Sending: %s", datetime.now().isoformat(), self.address)
            await self.entities['default'].publish(mqtt, mqtt_data)

    def update_sensor(self, name, value, device_class=None, units=None):
        """Create a new Sensor if needed and set its value"""
        if name not in self.entities:
            self.entities[name] = Sensor(self.device, self.name, name,
                                         self.availability_topic, device_class, units)
        self.entities[name].value = value

    def update_binary_sensor(self, name, value):
        """Create a new BinarySensor if needed and set its value"""
        if name not in self.entities:
            self.entities[name] = BinarySensor(self.device, self.name, name,
                                               self.availability_topic)
        self.entities[name].value = "ON" if value else "OFF"


class BTHomeDevice(Device):
    """BTHome Device"""
    async def process(self, advertisement_data, mqtt):
        data = {}
        self.update_timeout()
        await self.set_online(mqtt)
        self.pre_process(data, advertisement_data)
        self.update_sensor('rssi', advertisement_data.rssi, "signal_strength" , "dBm")
        self.decode(data['ServiceData']['fcd2'])
        for entity in self.entities.values():
            await entity.publish(mqtt)

    def decode(self, svc_data):
        """ Process BTHome sensor """
        # pylint: disable=too-many-branches
        seen_names = {}
        def _name(name):
            if name not in seen_names:
                seen_names[name] = 1
                return name
            newname = name + str(seen_names[name])
            seen_names[name] += 1
            return newname

        def extract(num_bytes, signed = False):
            nonlocal pos
            data = svc_data[pos+1:pos+num_bytes+1]
            if signed:
                assert num_bytes in (2, 4)
                if num_bytes == 2:
                    fmt = "<h"
                elif num_bytes == 4:
                    fmt = "<i"
            else:
                assert num_bytes <= 8
                fmt = "<Q"
                data = data.ljust(8, b'\0')
            pos += num_bytes+1
            return unpack(fmt, data)[0]

        if svc_data[0] & 0x01:
            # Encryption not supported
            return None
        try:
            pos = 1
            while pos < len(svc_data):
                if svc_data[pos] == 0x01:
                    self.update_sensor(_name('battery'), extract(1), "battery" , "%")
                elif svc_data[pos] == 0x02:
                    self.update_sensor(_name('temperature_C'), extract(2) / 100,
                                       "temperature" , "°C")
                elif svc_data[pos] == 0x09:
                    self.update_sensor(_name('count'), extract(1))
                elif svc_data[pos] == 0x0a:
                    self.update_sensor(_name('energy_Wh'), extract(3), "enery", "Wh")
                elif svc_data[pos] == 0x0b:
                    self.update_sensor(_name('power_W'), extract(3) / 100, "power", "W")
                elif svc_data[pos] == 0x10:
                    self.update_binary_sensor(_name('switch'), bool(extract(1)))
                elif svc_data[pos] == 0x3D:
                    self.update_sensor(_name('count'), extract(2))
                elif svc_data[pos] == 0x3E:
                    self.update_sensor(_name('count'), extract(4))
                elif svc_data[pos] == 0x40:
                    self.update_sensor(_name('distance_mm'), extract(2), "distance", "mm")
                elif svc_data[pos] == 0x43:
                    self.update_sensor(_name('current'), extract(2) / 1000, "current", "A")
                elif svc_data[pos] == 0x4a:
                    self.update_sensor(_name('voltage'), extract(2) / 10, "voltage", "V")
                else:
                    logging.error("Unhandled BTHome ID: %02x", svc_data[pos])
                    break
        except Exception as _e:
            logging.error("Failed to parse BTHome: %s", _e)

class EngbirdDevice(Device):
    """Engbird Temperature Sensor"""
    async def process(self, advertisement_data, mqtt):
        data = {}
        self.pre_process(data, advertisement_data)
        if 'ManufacturerData' not in data:
            return
        self.update_timeout()
        await self.set_online(mqtt)
        self.update_sensor('rssi', advertisement_data.rssi, "signal_strength" , "dBm")
        self.decode(data['ManufacturerData'])
        for entity in self.entities.values():
            await entity.publish(mqtt)

    def decode(self, mfg_data):
        """ Process Engbird temp sensor """
        try:
            mfg_data = bytes.fromhex(mfg_data)
            #if not modbus_crc.check_crc(mfg_data[0:7]):
            #    # invalid crc
            #    return None
            (temp, hum, probe, _modbus, bat) = unpack("<hHBHB", mfg_data[0:8])
            self.update_sensor('temperature_C', temp / 100, "temperature" , "°C")
            self.update_sensor('battery', bat, "battery", "%")
            if hum != 0:
                self.update_sensor('humidity', hum, "humidity" , "%")
            if probe != 0:
                self.update_sensor('probe', probe)
        except Exception as _e:
            logging.error("Failed to parse engbird: %s", _e)

class Govee5086Device(Device):
    """Manage connection to Govee 5086"""
    SEND_CHARACTERISTIC_UUID = "00010203-0405-0607-0809-0a0b0c0d2b11"
    RECV_CHARACTERISTIC_UUID = "00010203-0405-0607-0809-0a0b0c0d2b10"
    COMPANY_IDENTIFIER = 0x8803
    def __init__(self, device, name, auth_key):
        super().__init__(device)
        self.name = name
        self.auth_key = auth_key
        self.data = None
        self.mqtt = None
        self.need_connection = asyncio.Event()
        self.need_connection.set()
        self.data_ready = asyncio.Event()
        self.auth_ready = asyncio.Event()
        self.disconnected = asyncio.Event()
        self._poll_time = 60

    async def process(self, advertisement_data, mqtt):
        """an advertisement packet indicates we're not connected"""
        self.update_timeout()
        self.mqtt = mqtt
        # Cause scanning to stop and connection to start
        if self.need_connection.is_set():
            self.need_connection.clear()
            self.auth_ready.clear()
            self.disconnected.clear()
            self.data_ready.clear()
            raise Connect()

    async def start(self):
        """Connect to BT client and start loop sending status"""
        dev = self.device
        try:
            async with BleakClient(dev, disconnected_callback=self._disconnect_handler) as client:
                await client.start_notify(self.RECV_CHARACTERISTIC_UUID, self._recv_handler)
                if not await self._authenticate(client):
                    logging.error("Authentication failed for %s", self.name)
                    return
                await self._send(client, "AA01")
                powered_on = True
                while True:
                    try:
                        await asyncio.wait_for(self.data_ready.wait(), 2)
                    except asyncio.exceptions.TimeoutError:
                        # need to prevent diconnect timeout
                        if self.disconnected.is_set():
                            break
                        await self._send(client, "AA01")
                    if self.disconnected.is_set():
                        break
                    if self.data_ready.is_set():
                        self.data_ready.clear()
                        self.update_timeout()
                        await self.set_online(self.mqtt)
                        if self.data[0] ==0xee and self.data[1] == 0x19:
                            # power state
                            self._parse_power(self.data, powered_on)
                            for entity in self.entities.values():
                                await entity.publish(self.mqtt)
                        elif self.data[0] == 0xaa and self.data[1] == 0x01:
                            powered_on = bool(self.data[2])
                            await self._send(client, "AA00")

        except BleakError as _e:
            logging.error("%s client error: %s", dev.address, _e)
        except Exception as _e:  # pylint: disable=broad-except
            logging.exception("%s unexpected error: %s", dev.address, _e)
        # if waiting for authentication, allow process to proceed
        await self.set_offline(self.mqtt)
        self.auth_ready.set()
        self.need_connection.set()

    async def disconect(self):
        """Force disconnect"""
        if not self.need_connection.is_set():
            self.disconnected.set()
            await self.need_connection.wait()

    async def _recv_handler(self, _sender, data):
        self.data = data.copy()
        self.data_ready.set()

    def _disconnect_handler(self, _client):
        logging.error("%s disconnected", self.name)
        self.disconnected.set()

    async def _authenticate(self, client):
        logging.info("Authenticating %s", self.name)
        count = 5
        while count:
            # Create the message
            await self._send(client, "33B2" + self.auth_key)
            now = time.time()
            while time.time() - now < 5:
                try:
                    await asyncio.wait_for(self.data_ready.wait(), 5)
                except asyncio.exceptions.TimeoutError:
                    break
                if self.data_ready.is_set():
                    self.data_ready.clear()
                    if self.data[0] == 0x33 and self.data[1] == 0xB2:
                        self.auth_ready.set()
                        return True
        self.auth_ready.set()
        return False

    async def _send(self, client, data):
        ba = bytearray.fromhex(data).ljust(19, b'\0')
        ba.append(self._compute_xor(ba))
        logging.debug("SEND %s", ba.hex())
        await client.write_gatt_char(self.SEND_CHARACTERISTIC_UUID, ba)

    def _parse_power(self, data, powered_on):
        elapsed_s = int.from_bytes(data[2:5], "big")
        total_wh = int.from_bytes(data[5:8], "big") / 10.0
        volts = int.from_bytes(data[8:10], "big") / 100.0
        amps = int.from_bytes(data[10:12], "big") / 100.0
        watts = int.from_bytes(data[12:15], "big") / 100.0
        pwrfctr_pct = data[15]
        self.update_sensor('elapsed_s', elapsed_s, "duration", "s")
        self.update_sensor('total_Wh', total_wh, "energy", "Wh")
        self.update_sensor('voltage', volts, "voltage", "V")
        self.update_sensor('current', amps, "current", "A")
        self.update_sensor('power', watts, "power", "W")
        self.update_sensor('power_factor', pwrfctr_pct, "power_factor", "%")
        self.update_binary_sensor('switch', powered_on)

    @staticmethod
    def _compute_xor(data):
        res = 0
        for _b in data:
            res = res ^ _b
        return res


class MyScanner:
    """ BLE scanner"""
    def __init__(self):
        # pylint: disable=too-many-instance-attributes
        self.mqtt = None
        self.seen = {}
        self.unknown_devices = deque([], maxlen=50)
        self.devices = {}

    async def process_device(self, device, advertisement_data):
        """Convert advertisement packet to MQTT"""
        dev = None
        if dev := self.devices.get(device.address):
            pass
        elif dev := next((_ for _ in self.unknown_devices if device.address == _.address), None):
            pass
        else:
            if dev := self.check_device(device, advertisement_data):
                self.devices[device.address] = dev
            else:
                dev = Device(device)
                self.unknown_devices.append(dev)
        await dev.process(advertisement_data, self.mqtt)

    @staticmethod
    def check_device(device, advertisement_data):
        """Check if device is of a known type"""
        # pylint: disable=line-too-long
        # {"Address": "72:DF:A2:48:54:0A", "AddressType": "random", "Alias": "72-DF-A2-48-54-0A",
        #  "Paired": false, "Trusted": false, "Blocked": false, "LegacyPairing": false, "RSSI": -70,
        #  "Connected": false, "UUIDs": [], "Adapter": "/org/bluez/hci0",
        #  "ManufacturerData": "06000109200288656405C345067B9B4E0C75D9117951E630C060A6C668",
        #  "ServicesResolved": false}

        # {"AddressType": "random", "Name": "Oil Tank", "Connected": false, "UUIDs": [],
        #  "ServiceData": {"0000fcd2-0000-1000-8000-00805f9b34fb": "40010302B7073DA600400000"}, "RSSI": -86}
        # pylint: enable=line-too-long
        #print(f"{device!r} with {advertisement_data!r}")
        if advertisement_data.local_name in CONNECTABLE:
            return Govee5086Device(device, advertisement_data.local_name,
                                   CONNECTABLE[advertisement_data.local_name])
        dev = Device(device)
        data = {}
        dev.pre_process(data, advertisement_data)
        if 'ServiceData' in data and 'fcd2' in data['ServiceData']:
            return BTHomeDevice(device, advertisement_data.local_name)
        if data.get('Name') == "tps" and data.get('UUIDs', []) == ["fff0"]:
            return EngbirdDevice(device) # Don't pass local name because they are all 'tps'
        return None

    async def connect(self, device):
        """Connect to device"""
        dev = self.devices[device.address]
        asyncio.create_task(dev.start())
        await dev.auth_ready.wait()

    async def device_timeout(self, addr, dev):
        """Cleanup timed-out device"""
        if hasattr(dev, 'disconnect'):
            await dev.disconnect()
        else:
            await dev.set_offline(self.mqtt)
        del dev
        del self.devices[addr]

    async def scan(self):
        """BLE Scanner loop"""
        # pylint: disable=too-many-locals too-many-branches too-many-statements
        start_time = time.time()
        count = 0
        for _dev in self.devices.values():
            await _dev.set_offline(self.mqtt)
        self.devices.clear()
        self.unknown_devices.clear()
        retries = 5
        online = False
        while True:
            # print("(re)starting scanner")
            maxtime = time.time() + 5
            try:
                async with BleakScanner() as scanner:
                    # pylint: disable=unnecessary-dunder-call
                    dev_iter = scanner.advertisement_data().__aiter__()
                    while True:
                        timeout = maxtime - time.time()
                        if timeout <= 0:
                            break
                        try:
                            dev, ad_ = await asyncio.wait_for(dev_iter.__anext__(), timeout=timeout)
                        except StopAsyncIteration:
                            break
                        except asyncio.exceptions.TimeoutError:
                            break
                        # except asyncio.exceptions.CancelledError:
                        #     break
                        if not online:
                            await self.mqtt.publish(AVAILABILITY_TOPIC,
                                                    payload="online", retain=True)
                            online = True
                        await self.process_device(dev, ad_)
                        count += 1
                        now = time.time()
                        tasks = []
                        for addr, _dev in self.devices.items():
                            if _dev.next_timeout and now > _dev.next_timeout:
                                tasks.append(asyncio.create_task(self.device_timeout(addr, _dev)))
                        if tasks:
                            await asyncio.gather(tasks)
                        if now - start_time > 60:
                            logging.info("Packets per min: %.2f", 60 * count / (now - start_time))
                            start_time = now
                            count = 0
            except BleakError as _e:
                if online:
                    retries = 5
                    await self.mqtt.publish(AVAILABILITY_TOPIC, payload="offline", retain=True)
                    online = False
                retries -= 1
                if retries == 0:
                    for _dev in self.devices.values():
                        await _dev.set_offline(self.mqtt)
                    self.devices.clear()
                logging.error("Scanning error: %s.  Retrying in %d seconds", _e, ERROR_SLEEP)
                await asyncio.sleep(ERROR_SLEEP)
            except Connect:
                await self.connect(dev)

    async def set_offline(self):
        """Mark all previously-seen devices as offline"""
        await self.mqtt.subscribe(f"{AVAILABILITY_TOPIC}/#")
        await self.mqtt.publish(AVAILABILITY_TOPIC, payload="offline", retain=True)
        async for message in self.mqtt.messages:
            topic = str(message.topic)
            if topic == AVAILABILITY_TOPIC:
                break
            await self.mqtt.publish(topic, "offline", retain=True)
        await self.mqtt.unsubscribe(f"{AVAILABILITY_TOPIC}/#")
        try:
            self.mqtt._queue.get_nowait()  # pylint: disable=protected-access
        except asyncio.QueueEmpty:
            pass

    async def run(self):
        """Main loop"""
        will = aiomqtt.Will(AVAILABILITY_TOPIC, payload="offline", retain=True)
        while True:
            try:
                async with AsyncExitStack() as stack:
                    self.mqtt = aiomqtt.Client(MQTT_HOST, MQTT_PORT, will=will)
                    await stack.enter_async_context(self.mqtt)
                    stack.push_async_callback(self.mqtt.publish, AVAILABILITY_TOPIC,
                                              "offline", retain=True)
                    await self.set_offline()
                    try:
                        await self.scan()
                    except aiomqtt.MqttError as _e:
                        raise
                    except Exception:
                        logging.error("offline")
                        await self.mqtt.publish(AVAILABILITY_TOPIC, payload="offline", retain=True)
                        raise
            except aiomqtt.MqttError as _e:
                logging.error("MQTT Error: %s.  Retrying in %s seconds", _e, ERROR_SLEEP)
            except Exception as _e:  # pylint: disable=broad-except
                logging.exception("Unexpected error %s.  Retrying in %s seconds", _e, ERROR_SLEEP)
            await asyncio.sleep(ERROR_SLEEP)

async def main():
    """Entrypoint"""
    logfile="/var/log/ble_gateway.log"
    # logfile="./log"
    log = logging.getLogger()
    log.setLevel(logging.INFO)
    handler = logging.handlers.RotatingFileHandler(logfile,
          maxBytes=1_000_000, backupCount=1)
    formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s')
    handler.setFormatter(formatter)
    log.addHandler(handler)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)
    #log.addHandler(handler)
    logging.info("Starting: %s", VERSION)

    my_scanner = MyScanner()
    await my_scanner.run()

if __name__ == '__main__':
    asyncio.run(main())
