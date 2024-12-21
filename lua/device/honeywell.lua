local log = require('log')
local bit = require('mqtt.bitwrap')
local const = require('const')
local utils = require('utils')
local Device = require("device")
local HoneywellDevice = Device:inherit()

local b_and = bit.band
local b_not = bit.bnot
local DEFAULT_TIMEOUT = const.DEFAULT_HONEYWELL_TIMEOUT

function HoneywellDevice:initialize(addr, mqtt_que, opts)
	utils.set_class(self, "Honeywell")
	if opts.timeout == nil then
		opts.timeout = DEFAULT_TIMEOUT
	end
	Device.initialize(self, addr, mqtt_que, opts.name, opts.timeout)
	self.dev_type = opts.type
	self.seen_unhandled = false
	self.ignore = opts.ignore
end

function HoneywellDevice:process(data)
	self:set_online()
	local ok, err = pcall(function()
		self:decode(data)
	end)
	if not ok then
		log:error("(%s): Failed to parse AD: %s", self.name, tostring(err))
		return
	end
	self.timer:update()
	for _, entity in pairs(self.entities) do
		entity:publish(self.mqtt_que)
	end
	if self.entities.unhandled_state and not self.seen_unhandled then
		-- unhandled_state cleared, remove it from entry
		self.entities.unhandled_state = nil
	end
end

function HoneywellDevice:decode(data)
	local state = tonumber(data, 16)
	local contact   = b_and(state, 0x80) > 0 and true or false
	local tamper    = b_and(state, 0x40) > 0 and true or false
	local reed      = b_and(state, 0x20) > 0 and true or false
	-- local alarm     = b_and(state, 0x10) > 0 and true or false
	local lowbat    = b_and(state, 0x08) > 0 and true or false
	-- local heartbeat = b_and(state, 0x04) > 0 and true or false
	-- local unknown2  = b_and(state, 0x02) > 0 and true or false
	-- local unknown1  = b_and(state, 0x01) > 0 and true or false
	local unhandled_state

	-- self:update_binary_sensor('heartbeat', heartbeat)
	self:update_binary_sensor('tamper', tamper, 'tamper')
	self:update_binary_sensor('low_battery', lowbat, 'battery')
	if self.dev_type == "motion" then
		self:update_binary_sensor('motion', contact)
		unhandled_state = b_and(state, 0x33)
	elseif self.dev_type == "door" then
		self:update_binary_sensor('door', contact, 'door')
		unhandled_state = b_and(state, 0x33)
	elseif self.dev_type == "door_reed" then
		-- Some door switches keep 'contact' set all the time, and trigger with 'reed'
		self:update_binary_sensor('door', reed, 'door')
		unhandled_state = b_and(state, 0x13)
	elseif self.dev_type == "smoke" then
		self:update_binary_sensor('smoke', reed, 'smoke')
		unhandled_state = b_and(state, 0x93)
	else
		unhandled_state = b_and(state, 0xb3)
	end
	if self.ignore then
		unhandled_state = b_and(unhandled_state, b_not(self.ignore))
	end
	if unhandled_state ~= 0 then
		self.seen_unhandled = true
		self:update_sensor('unhandled_state', unhandled_state)
	elseif self.seen_unhandled then
		self.seen_unhandled = false
		self:update_sensor('unhandled_state', unhandled_state)
	end
end

return HoneywellDevice
