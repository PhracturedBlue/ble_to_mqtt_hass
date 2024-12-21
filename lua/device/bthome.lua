local log = require("log")
local struct = require("struct")

local utils = require("utils")

local Device = require("device")
local BTHomeDevice = Device:inherit()

function BTHomeDevice:initialize(...)
	utils.set_class(self, "BTHome")
	Device.initialize(self, ...)
end

function BTHomeDevice:process(advertisement_data)
	self:set_online()
	local ok, err = pcall(function()
		self:update_sensor('rssi', advertisement_data.rssi, "signal_strength" , "dBm")
		self:decode(advertisement_data.service_data["fcd2"])
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

function BTHomeDevice:decode(svc_data)
	-- 'f2dc': 40016c0279093d9ce3404d01
	local seen_names = {}
	local pos = 2
	local function _name(name)
		if not seen_names[name] then
			seen_names[name] = 1
			return name
		end
		local newname = name .. tostring(seen_names[name])
		seen_names[name] = seen_names[name] + 1
		return newname
	end
	local function extract(num_bytes, signed)
		local data = svc_data:sub(pos+1, pos+num_bytes+1-1)
		local fmt
		if signed then
			assert(num_bytes == 2 or num_bytes == 4)
			if num_bytes == 2 then
				fmt = "<h"
			elseif num_bytes == 4 then
				fmt = "<i"
			end
		else
			assert(num_bytes <= 8)
			fmt = "<L"
			data = data .. string.rep('\0', 8-data:len())  -- pad to 8 bytes
		end
		pos = pos + num_bytes + 1
		return struct.unpack(fmt, data)
	end
	if svc_data:byte(1) % 1 == 1 then
		log:error("(" .. self.name .. "): BTHome encryption not supported")
		return nil
	end
	while pos <= #svc_data do
		local ok, err = pcall(function()
			local _type = svc_data:byte(pos)
			if _type == 0x01 then
				self:update_sensor(_name('battery'), extract(1), "battery" , "%")
			elseif _type == 0x02 then
				self:update_sensor(_name('temperature_C'), extract(2) / 100, "temperature" , "°C")
			elseif _type == 0x09 then
				self:update_sensor(_name('count'), extract(1))
			elseif _type == 0x0a then
				self:update_sensor(_name('energy_Wh'), extract(3), "enery", "Wh")
			elseif _type == 0x0b then
				self:update_sensor(_name('power_W'), extract(3) / 100, "power", "W")
			elseif _type == 0x0c then
				self:update_sensor(_name('voltage'), extract(2) / 1000, "voltage", "V")
			elseif _type == 0x10 then
				self:update_binary_sensor(_name('switch'), extract(1))
			elseif _type == 0x3D then
				self:update_sensor(_name('count'), extract(2))
			elseif _type == 0x3E then
				self:update_sensor(_name('count'), extract(4))
			elseif _type == 0x40 then
				self:update_sensor(_name('distance_mm'), extract(2), "distance", "mm")
			elseif _type == 0x43 then
				self:update_sensor(_name('current'), utils.tosigned(extract(2), 16) / 1000, "current", "A")
			elseif _type == 0x4a then
				self:update_sensor(_name('voltage'), extract(2) / 10, "voltage", "V")
			else
				error({code=_type})
			end
		end)
		if not ok then
			log:error("(%s): Unhandled BTHome ID: %02x", self.name, err.code)
			return
		end
	end
end

return BTHomeDevice
