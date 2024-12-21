local log = require("log")
local entities = require("entities")
local copas = require("copas")
local const = require("const")
local socket = require("socket")

local Sensor = entities.Sensor
local BinarySensor = entities.BinarySensor
local Switch = entities.Switch

local Class = require("class")

local Timer = Class:inherit()

local AVAILABILITY_TOPIC = const.AVAILABILITY_TOPIC
local DEFAULT_TIMEOUT = const.DEFAULT_TIMEOUT
local COMMAND_TOPIC = const.COMMAND_TOPIC

function Timer:initialize(timeout, callback, cb_params)
	assert(timeout, "Must specify timer timeout")
	assert(callback, "Must specify timer callback")
	self.timeout = timeout
	self.callback = callback
	self.cb_params = cb_params
	self.last_update = nil
	self.running = false
end

function Timer:update()
	self.last_update = socket.gettime()
	if not self.running then
		self.running = copas.addthread(function()
			while true do
				local delta = self.last_update + self.timeout - socket.gettime()
				if delta > 0 then
					copas.pause(delta)
				else
					self.callback(self.cb_params)
					self.running = false
					return
				end
			end
		end)
	end
end

function Timer:stop()
	if self.running then
		copas.removethread(self.running)
		self.running = nil
	end
end

local Device = Class:inherit()

function Device:initialize(addr, mqtt_que, name, timeout)
	assert(addr, "addr not set")
	assert(mqtt_que, "mqtt_que not set")

	self.mqtt_que = mqtt_que
	if self.class then
		self.name = self.class:lower() .. "_" .. (name or addr):gsub("[: ]+", "")
	else
		self.name = (name or addr):gsub("[: ]+", "")
	end
	self.addr = addr
	self.availability_topic = AVAILABILITY_TOPIC .. "/" .. self.addr
	self.entities = {}
	self.seen = {}
	self.is_online = false
	self.status = {}
	self.timer = Timer:new(timeout or DEFAULT_TIMEOUT, self.set_offline, self)
end

function Device:set_offline()
	log:info("Setting %s offline (%s)", self.availability_topic, self.name)
	self.mqtt_que:push({topic=self.availability_topic, payload="offline", retain=true})
	self.is_online = false
end

function Device:set_online()
	if not self.is_online then
		log:info("Setting %s online (%s)", self.availability_topic, self.name)
		self.mqtt_que:push({topic=self.availability_topic, payload="online", retain=true})
		self.is_online = true
	end
end

function Device:send_discovery()
	if not self.is_online then
		return
	end
	for _, entity in pairs(self.entities) do
		entity:publish(self.mqtt_que, true)
	end
end

function Device.process()
	error("Not implemented")
end

function Device:update_sensor(name, value, device_class, units)
	if self.entities[name] == nil then
		self.entities[name] = Sensor:new(name, self.name, self.availability_topic,
			{device_class = device_class, units = units})
	end
	self.entities[name].value = value
end

function Device:update_binary_sensor(name, value, device_class)
	if self.entities[name] == nil then
		self.entities[name] = BinarySensor:new(name, self.name, self.availability_topic,
			{device_class = device_class})
	end
	local val = "OFF"
	if value == true or value == 1 or (type(value) == "string" and value:lower() == "on") then
		val = "ON"
	end
	self.entities[name].value = val
end

function Device:update_switch(name, value, device_class)
	if self.entities[name] == nil then
		local cmd_topic = COMMAND_TOPIC .. "/" .. self.addr .. "/" .. name
		self.entities[name] = Switch:new(name, self.name, self.availability_topic,
			{device_class = device_class, cmd_topic = cmd_topic})
	end
	local val = "OFF"
	if value == true or value == 1 or (type(value) == "string" and value:lower() == "on") then
		val = "ON"
	end
	self.entities[name].value = val
end


return Device
