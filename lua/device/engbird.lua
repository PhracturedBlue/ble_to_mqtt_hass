local log = require("log")
local struct = require("struct")

local utils = require("utils")

local Device = require("device")
local EngbirdDevice = Device:inherit()

function EngbirdDevice:initialize(...)
	utils.set_class(self, "Engbird")
	Device.initialize(self, ...)
end

function EngbirdDevice:process(advertisement_data)
	if not advertisement_data.mfg_data then
		log:debug("No data for" .. self.name)
		return
	end
	log:debug("(%s): Found data: %s", self.name, utils.dump(advertisement_data.mfg_data))
	self:set_online()
	local ok, err = pcall(function()
		self:update_sensor('rssi', advertisement_data.rssi, "signal_strength" , "dBm")
		self:decode(advertisement_data.mfg_data)
	end)
	if not ok then
		log:error("(%s): Failed to parse AD: %s", self.name, tostring(err))
		return
	end
	self.timer:update()
	for _, entity in pairs(self.entities) do
		entity:publish(self.mqtt_que)
	end
end

function EngbirdDevice:decode(mfg_data)
	local ok, err = pcall(function()
		local temp, hum, probe, _, bat = struct.unpack("<hHBHB", mfg_data:sub(1, 8))
		self:update_sensor('temperature_C', temp / 100, "temperature" , "°C")
		self:update_sensor('battery', bat, "battery", "%")
		if hum ~= 0 then
			self:update_sensor('humidity', hum, "humidity" , "%")
		end
		if probe ~= 0 then
			self:update_sensor('probe', probe)
		end
	end)
	if not ok then
		log:error("(%s): Failed to parse engbird: %s", self.name, tostring(err))
	end
end

return EngbirdDevice
