#!/bin/bash
''''/bin/true
SCRIPTDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" > /dev/null && pwd )"
exec $SCRIPTDIR/.venv/bin/python3 $0 "$@"
exit
''' # Python starts here '''

import asyncio
import argparse
import hashlib
import json
import logging
import os
import socket
import time
from datetime import datetime
from struct import unpack
from serial import SerialException
from collections import OrderedDict

import aiomqtt
import aioserial
#from serial_asyncio import open_serial_connection


# pylint: disable=broad-except
# pylint: disable=too-few-public-methods

VERSION = " ".join([
    os.path.basename(__file__).rsplit('.', 1)[0],
    hashlib.md5(open(__file__,'rb').read()).hexdigest()[:12], # pylint: disable=consider-using-with
    datetime.fromtimestamp(os.stat(__file__).st_mtime).isoformat()])
HOSTNAME = socket.gethostname().split('.')[0]

BASE_TOPIC = "/ble"
AVAILABILITY_TOPIC_TOP = f"{BASE_TOPIC}/status"
AVAILABILITY_TOPIC = f"{AVAILABILITY_TOPIC_TOP}/{HOSTNAME}"
DEFAULT_MQTT_HOST = "<mqtt_host>"
DEFAULT_MQTT_PORT = 1883
ERROR_SLEEP = 10
REPEAT_TIME = 120

GOVEE_5086 = {
    #'GVH5086XXXX': 'yyyyyyyyyyyyyyyy',
}

def to_signed(val, size=8):
    """Convert unsigned integer to a signed one"""
    return ((val & ((1 << size) - 1)) ^ (1 << (size - 1))) - (1 << (size - 1))

class HexJsonEncoder(json.JSONEncoder):
    """convert byte-arrays to hex during json encoding"""
    def default(self, obj):  # pylint: disable=arguments-renamed
        if isinstance(obj, (bytearray, bytes)):
            return "".join([f"{_:02X}" for _ in obj])
        return super().default(obj)

class LRUCache:
    """Simple LRU Cache"""
    def __init__(self, capacity: int):
        self.cache = OrderedDict()
        self.capacity = capacity
 
    def get(self, key: str) -> bool:
        if key not in self.cache:
            return False
        else:
            self.cache.move_to_end(key)
            return True
 
    def put(self, key: str) -> None:
        self.cache[key] = True
        self.cache.move_to_end(key)
        if len(self.cache) > self.capacity:
            self.cache.popitem(last = False)

class Timer:
    """Watchdog timer"""
    def __init__(self, timeout, callback):
        self.timeout = timeout
        self.callback = callback
        self.last_update = None
        self.event = asyncio.Event()
        self.task = asyncio.create_task(self.run())

    def __del__(self):
        self.task.cancel()

    def update(self):
        """Reset timer"""
        self.last_update = time.time()
        self.event.set()

    async def run(self):
        """Timer loop"""
        while True:
            await self.event.wait()
            delta = self.last_update + self.timeout - time.time()
            if delta > 0:
                await asyncio.sleep(delta)
                continue
            await self.callback()
            self.event.clear()

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
          "owner": HOSTNAME,
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
    async def publish(self, mqtt_que):
        """Publish discovery topic"""
        await mqtt_que.put((self.topic, json.dumps(self.payload), True))

class Entity:
    """Basic Entity"""
    def __init__(self, addr, *, detect_duplicates=True):
        self.address = addr
        self.detect_duplicates = detect_duplicates
        self.topic = f"{BASE_TOPIC}/{self.address}"

    async def publish(self, mqtt_que, payload):
        """Publish update to MQTT"""
        await mqtt_que.put((self.topic, payload, False))

class Sensor(Entity):
    """Sensor"""
    def __init__(self, addr, device_name, value_name,
                 availability_topic, device_class, units, *,
                 discover=True, detect_duplicates=True):
        # pylint: disable=too-many-arguments
        super().__init__(addr, detect_duplicates=detect_duplicates)
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

    async def publish(self, mqtt_que, _payload=None):
        if not self.sent_discovery and self.hass:
            await self.hass.publish(mqtt_que)
            self.sent_discovery = True
        await super().publish(mqtt_que, str(self.value))

class BinarySensor(Sensor):
    """Binary Sensor"""
    def __init__(self, addr, device_name, value_name,
                 availability_topic, *,
                 discover=True, detect_duplicates=True):
        # pylint: disable=too-many-arguments
        super().__init__(addr, device_name, value_name, None, None, None,
                         discover=False, detect_duplicates=detect_duplicates)
        if discover:
            self.hass = HassDiscovery("binary_sensor", device_name, value_name, self.topic,
                                      availability_topic)

class Device:
    """Base Device"""
    # pylint: disable=too-many-instance-attributes
    def __init__(self, addr, mqtt_que, name=None, timeout=600):
        self.mqtt_que = mqtt_que
        base = self.__class__.__name__.replace('Device', '').lower()
        if base:
            base += "_"
        self.name = (base + (name or addr)).replace(':','').replace(' ', '')
        self.addr = addr
        self.availability_topic = f"{AVAILABILITY_TOPIC}/{self.addr}"
        self.entities = {}
        self.seen = {}
        self.is_online = False
        self.status = []
        self.tx_count = 0
        self.timer = Timer(timeout, self.set_offline)

    async def set_offline(self):
        """Set device as offline"""
        await self.mqtt_que.put((self.availability_topic, "offline", True))
        self.is_online = False

    async def set_online(self):
        """Set device as online"""
        if not self.is_online:
            await self.mqtt_que.put((self.availability_topic, "online", True))
            self.is_online = True

    async def process(self, advertisement_data):
        """Process advertisement data"""
        raise NotImplementedError

    def update_sensor(self, name, value, device_class=None, units=None):
        """Create a new Sensor if needed and set its value"""
        if name not in self.entities:
            self.entities[name] = Sensor(self.addr, self.name, name,
                                         self.availability_topic, device_class, units)
        self.entities[name].value = value

    def update_binary_sensor(self, name, value):
        """Create a new BinarySensor if needed and set its value"""
        if name not in self.entities:
            self.entities[name] = BinarySensor(self.addr, self.name, name,
                                               self.availability_topic)
        self.entities[name].value = "ON" if value else "OFF"


class BTHomeDevice(Device):
    """BTHome Device"""
    async def process(self, advertisement_data):
        await self.set_online()
        try:
            self.update_sensor('rssi', advertisement_data['rssi'], "signal_strength" , "dBm")
            self.decode(advertisement_data['service_data']['fcd2'])
        except Exception as _e:
            logging.error("%s: Failed to parse AD: %s", self.name, _e)
            return
        self.timer.update()
        self.tx_count += 1
        for entity in self.entities.values():
            await entity.publish(self.mqtt_que)

    def decode(self, svc_data):
        """ Process BTHome sensor """
        # pylint: disable=too-many-branches
        # 'f2dc': 40016c0279093d9ce3404d01
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
    async def process(self, advertisement_data):
        if 'mfg_data' not in advertisement_data:
            logging.debug("No data for %s", self.name)
            return
        logging.debug("Got data for %s: %s", self.addr, advertisement_data['mfg_data'])
        await self.set_online()
        try:
            self.update_sensor('rssi', advertisement_data['rssi'], "signal_strength" , "dBm")
            self.decode(advertisement_data['mfg_data'])
        except Exception as _e:
            logging.error("%s: Failed to parse AD: %s", self.name, _e)
            return
        self.timer.update()
        self.tx_count += 1
        for entity in self.entities.values():
            await entity.publish(self.mqtt_que)

    def decode(self, mfg_data):
        """ Process Engbird temp sensor """
        try:
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
    def __init__(self, addr, mqtt_que, name=None):
        # Don't pass name for backwards compatibility
        super().__init__(addr, mqtt_que)
        self.name = name

    async def process(self, advertisement_data):
        """an advertisement packet indicates we're not connected"""
        if advertisement_data.get('type') != 'GOV':
            # this is advertisement data...not connected yet
            return
        await self.set_online()
        try:
            self.update_sensor('rssi', advertisement_data['rssi'], "signal_strength" , "dBm")
            self.update_binary_sensor('switch', advertisement_data['state'])
            self.decode(advertisement_data['power'])
        except Exception as _e:
            logging.error("%s: Failed to parse: %s", self.name, _e)
            return
        self.timer.update()
        for entity in self.entities.values():
            await entity.publish(self.mqtt_que)

    def decode(self, data):
        """ Process Govee sensor """
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

class SerialScanner:
    """Serial port manager"""
    def __init__(self, serial_port, mqtt_que, ignore_name):
        self.serial = None
        self.write_stream = None
        self.read_stream = None
        self.mqtt_que = mqtt_que
        self.ready = False
        self.serial_port = serial_port
        self.ignore_names = ignore_name

    async def parse_adv(self, addr, adv):
        """Parse advertising data"""
        if adv.get('name', '').startswith('GVH') and \
                adv.get('mfg_data', '').startswith(b'\x03\x88'):
            # 60:74:f4:aa:bb:cc d2 020105 0c094756483530383636364333 09ff0388ec0001010100
            if adv['name'] in GOVEE_5086:
                await self._write(f"G {addr} {GOVEE_5086[adv['name']]} {adv['name']}")
                return Govee5086Device(addr, self.mqtt_que, adv['name'])
        elif adv.get('name') and adv.get('service_data', {}).get('fcd2'):
            dev = BTHomeDevice(addr, self.mqtt_que, adv['name'])
            return dev
        elif adv.get('name') == 'tps' and adv.get('mfg_data'):
            dev = EngbirdDevice(addr, self.mqtt_que)
            return dev
        elif adv.get(0x02) == b'\xf0\xff':
            # This is a TPS ADV before active scanning. Skip this one in favor of the active response
            return None
        return False

    @staticmethod
    def adv_to_dict(adv_data, rssi=None):
        """Convert bytes to adv K/V"""
        adv = {"type": "ADV"}
        pos = 0
        while pos < len(adv_data):
            ad_len = adv_data[pos]
            ad_type = adv_data[pos+1]
            data = adv_data[pos+2:pos+1+ad_len]
            pos += ad_len + 1
            if ad_type == 0x01:
                adv['flags'] = data
            elif ad_type == 0x09:
                adv['name'] = data.decode()
            elif ad_type == 0x16:
                if 'service_data' not in adv:
                    adv['service_data'] = {}
                adv['service_data'][bytes([data[1], data[0]]).hex()] = data[2:]
            elif ad_type == 0xff:
                adv['mfg_data'] = data
            else:
                adv[ad_type] = data
        if rssi:
            adv['rssi'] = rssi
        return adv

    async def _reader(self):
        ignore_addrs = LRUCache(1024)
        devices = {}
        online = False
        while True:
            line = await self.serial.readline_async(-1)
            #line = await self.read_stream.readline()
            line = line.decode().strip()
            logging.debug("--> (%s) %s", self.ready, line)
            if not self.ready:
                if line == "RSP DONE":
                    self.ready = True
                continue
            if line.startswith('GOV '):
                # GOV 60:74:f4:aa:bb:cc cf GVH5086XXXX 1 ee1904d2410000002e3700000000000000000079
                _, addr, rssi, _name, power_on, power = line.strip().split()
                addr = addr.upper()  # for backwards compatiblity
                if addr not in devices:
                    logging.error("Found unknown connected device: %s", line)
                    continue
                rssi = to_signed(int(rssi, 16), 8)
                power_on = int(power_on)
                power = bytes.fromhex(power)
                await devices[addr].process(
                        {'type': 'GOV', 'state': power_on, 'power': power, 'rssi': rssi})
            elif line.startswith('ADV '):
                # ADV 8c:de:52:7f:2a:3c bc 02010207094245444a4554 BEDJET
                if not online:
                    await self.mqtt_que.put((AVAILABILITY_TOPIC, "online", True))
                    online = True
                _, addr, rssi, data, *_name  = line.strip().split()
                addr = addr.upper()  # for backwards compatiblity
                if addr in self.ignore_names or ignore_addrs.get(addr):
                    continue
                rssi = to_signed(int(rssi, 16), 8)
                adv = self.adv_to_dict(bytes.fromhex(data), rssi)
                if addr in devices:
                    await devices[addr].process(adv)
                    continue
                dev = await self.parse_adv(addr, adv)
                # can be device, False, or None
                if dev:
                    devices[addr] = dev
                    await devices[addr].process(adv)
                    continue
                elif dev == False:
                    logging.info("Ignoring %s", line)
                    ignore_addrs.put(addr)
            else:
                print(line.strip())

    async def _write(self, item):
        logging.debug("<-- %s", item)
        await self.serial.write_async(f"{item}\n".encode())
        #self.write_stream.write(f"{item}\n".encode())
        #await self.write_stream.drain()

    async def run(self):
        """Serial connection communication"""
        while True:
            try:
                self.ready = True
                self.serial = aioserial.AioSerial(port=self.serial_port, baudrate=115200)
                #self.read_stream, self.write_stream = await open_serial_connection(
                #        url=self.serial_port, baudrate=115200)
                self.serial.reset_input_buffer()
                await self._write("CLOSEALL")
                await self._reader()
            except SerialException as _e:
                logging.error("Issues with Serial port.  Retrying in %d seconds: %s",
                        ERROR_SLEEP, _e)
                await asyncio.sleep(ERROR_SLEEP)
            except Exception as _e:
                logging.error("Unexpected error.  Aborting: %s", _e)
                raise
            finally:
                await self.mqtt_que.put((AVAILABILITY_TOPIC, "offline", True))

class Gateway:
    """Gateway"""
    def __init__(self, args):
        self.mqtt_host = args.mqtt_host
        self.mqtt_port = args.mqtt_port
        self.serial = args.serial
        self.mqtt = None
        self.ignore_name = []

    async def set_offline(self):
        """Mark all previously-seen devices as offline"""
        await self.mqtt.subscribe(f"{AVAILABILITY_TOPIC_TOP}/#")
        await self.publish(AVAILABILITY_TOPIC, payload="offline", retain=True)
        # Can't use wrapper here, otherwise the loop may not end
        await self.mqtt.publish(f"{AVAILABILITY_TOPIC}/done", payload="true")
        ignore_name = []

        async for message in self.mqtt.messages:
            topic = str(message.topic)
            if topic == f"{AVAILABILITY_TOPIC}/done":
                break
            if topic.startswith(AVAILABILITY_TOPIC):
                await self.publish(topic, "offline", retain=True)
            else:
                name = topic[len(AVAILABILITY_TOPIC_TOP)+1:].rsplit('/')[-1]
                logging.info("Ignoring %s from %s", name, topic)
                ignore_name.append(name)
        await self.mqtt.unsubscribe(f"{AVAILABILITY_TOPIC_TOP}/#")
        try:
            # Empty all messages from MQTT queue now that we are  no longer subscribed
            while self.mqtt._queue.get_nowait():  # pylint: disable=protected-access
                pass
        except asyncio.QueueEmpty:
            pass
        return ignore_name

    async def publish(self, topic, payload=None, retain=None):
        """Wrapper to allow testing"""
        #print(f"MQTT {topic} : {payload} (retain: {retain})")
        await self.mqtt.publish(topic, payload=payload, retain=retain)

    async def mqtt_writer(self, mqtt_que):
        """wrte MQTT messages from the queue"""
        try:
            while True:
                (topic, payload, retain) = await mqtt_que.get()
                await self.publish(topic, payload=payload, retain=retain)
                mqtt_que.task_done()
        except asyncio.CancelledError:
            return
        except Exception as _e:
            logging.error("Failed to read from queue: %s", _e)
            raise

    async def run(self):
        """Main loop"""
        will = aiomqtt.Will(AVAILABILITY_TOPIC, payload="offline", retain=True)
        while True:
            try:
                async with aiomqtt.Client(self.mqtt_host, self.mqtt_port, will=will) as self.mqtt:
                    ignore_name = await self.set_offline()
                    mqtt_que = asyncio.Queue()
                    scanner = SerialScanner(self.serial, mqtt_que, ignore_name)
                    try:
                        await asyncio.gather(scanner.run(), self.mqtt_writer(mqtt_que))
                    except aiomqtt.MqttError as _e:
                        raise
                    except Exception:
                        logging.error("offline")
                        await self.publish(AVAILABILITY_TOPIC, payload="offline", retain=True)
                        raise
            except aiomqtt.MqttError as _e:
                logging.error("MQTT Error: %s.  Retrying in %s seconds", _e, ERROR_SLEEP)
            except asyncio.CancelledError:
                break
            except Exception as _e:  # pylint: disable=broad-except
                logging.exception("Unexpected error %s.  Retrying in %s seconds", _e, ERROR_SLEEP)
            await asyncio.sleep(ERROR_SLEEP)

async def amain():
    """Entrypoint"""
    parser = argparse.ArgumentParser()
    parser.add_argument("--serial", required=True, help="Serial port to use")
    parser.add_argument("--baud", type=int, default=115200, help="Baud rate")
    parser.add_argument("--mqtt-host", default=DEFAULT_MQTT_HOST, help="MQTT server address")
    parser.add_argument("--mqtt-port", default=DEFAULT_MQTT_PORT, help="MQTT port")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")

    args = parser.parse_args()
    log = logging.getLogger()
    log.setLevel(logging.DEBUG if args.debug else logging.INFO)

    gateway = Gateway(args)
    await gateway.run()

asyncio.run(amain())
