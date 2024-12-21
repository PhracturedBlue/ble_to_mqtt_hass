local Class = require("class")
local const = require("const")
local json = require("json")
local utils = require("utils")

local HassDiscovery = Class:inherit()

local AVAILABILITY_TOPIC = const.AVAILABILITY_TOPIC
local HOSTNAME = const.HOSTNAME
local VERSION = const.VERSION_STR
local BASE_TOPIC = const.BASE_TOPIC

function HassDiscovery:initialize(component, sensor_name, name, topic, availability_topic, opt_args)
        local device_class = opt_args.device_class
        local units        = opt_args.units
        local cmd_topic    = opt_args.cmd_topic
	self.unique_id = (sensor_name .. "_" .. name):gsub(' ', '_'):lower()
	self.topic = "homeassistant/" .. component .. "/" .. self.unique_id .. "/config"
	self.availability_topic = availability_topic
	self.payload = {
		name = name,
		uniq_id = self.unique_id,
		stat_t = topic,
		avty = {
			{ topic = AVAILABILITY_TOPIC },
			{ topic = self.availability_topic },
		},
		avty_mode = "all",
		owner = HOSTNAME,
		dev = {
			ids = sensor_name,
			name = sensor_name,
			sw = VERSION,
		}
	}
	if device_class then
		self.payload.dev_cla = device_class
	end
	if component == "sensor" then
		self.payload.unit_of_meas = units
		self.payload.stat_cla = "measurement"
	end
	if component == "switch" then
		self.payload.cmd_t = cmd_topic
	end
end

function HassDiscovery:publish(mqtt_que)
	mqtt_que:push({topic = self.topic, payload = json.encode(self.payload), retain=false})
end


local Entity = Class:inherit()

function Entity:initialize(name, device_name, availability_topic, opt_args)
	assert(name, "Must specify 'name'")
	assert(device_name, "Must specify 'device_name'")
	self.topic = BASE_TOPIC .. "/" .. device_name .. "/" .. name .. "/state"
	self.value = nil
	self.name = name
	self.sent_discovery = false
	if availability_topic then
		self.hass = HassDiscovery:new(self.class, device_name, name, self.topic,
			availability_topic, opt_args)
	else
		self.hass = nil
	end
end

function Entity:publish(mqtt_que, send_discovery)
	if send_discovery or (not self.sent_discovery and self.hass) then
		self.hass:publish(mqtt_que)
		self.sent_discovery = true
	end
	mqtt_que:push({topic = self.topic, payload=tostring(self.value), retain=false})
end

local Sensor = Entity:inherit()
function Sensor:initialize(...)
	utils.set_class(self, "sensor")
	Entity.initialize(self, ...)
end

local BinarySensor = Entity:inherit()

function BinarySensor:initialize(...)
	utils.set_class(self, "binary_sensor")
	Entity.initialize(self, ...)
end

local Switch = Entity:inherit()

function Switch:initialize(...)
	utils.set_class(self, "switch")
	Entity.initialize(self, ...)
end

return {Sensor = Sensor, BinarySensor = BinarySensor, Switch = Switch}
