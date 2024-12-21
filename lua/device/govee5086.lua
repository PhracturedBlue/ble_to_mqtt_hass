local log = require("log")
local struct = require("struct")

local utils = require("utils")

local Device = require("device")
local Govee5086Device = Device:inherit()

function Govee5086Device:initialize(addr, mqtt_que, name, switch)
	utils.set_class(self, "Govee")
	Device.initialize(self, addr, mqtt_que)
	self.name = name
	self.switch = switch
end

function Govee5086Device:process(advertisement_data)
	self:set_online()
	if advertisement_data.advtype == 'ADV' and not advertisement_data.mfg_data then
		-- Alternate ADV packet
		return
	end
	local ok, err = pcall(function()
		if advertisement_data.advtype ~= 'GOV' then
			-- this is advertisement data...not connected yet, or power is off
			-- mfg_dafa = 0388ec0001010100
			-- log:debug(utils.dump(advertisement_data))
			advertisement_data.state = advertisement_data.mfg_data:byte(7)
			log:debug("Govee Power State: %d", advertisement_data.state)
		else
			self:decode(advertisement_data.power)
		end
		self:update_sensor('rssi', advertisement_data.rssi, "signal_strength" , "dBm")
		if self.switch then
			self:update_switch('switch', advertisement_data.state, "outlet")
		else
			self:update_binary_sensor('switch', advertisement_data.state, "power")
		end
	end)
	if not ok then
		log:error("(%s): Failed to parse: %s", self.name, tostring(err))
		return
	end
	self.timer:update()
	for _, entity in pairs(self.entities) do
		entity:publish(self.mqtt_que)
	end
end

function Govee5086Device:decode(data)
	local elapsed_s = struct.unpack(">I", '\0' .. data:sub(3, 5))
	local total_wh = struct.unpack(">I", '\0' .. data:sub(6, 8)) / 10.0
	local volts = struct.unpack(">H", data:sub(9,10)) / 100.0
	local amps = struct.unpack(">H", data:sub(11, 12)) / 100.0
	local watts = struct.unpack(">H", '\0' .. data:sub(13, 15)) / 100.0
	local pwrfctr_pct = data:byte(16)
	self:update_sensor('elapsed_s', elapsed_s, "duration", "s")
	self:update_sensor('total_Wh', total_wh, "energy", "Wh")
	self:update_sensor('voltage', volts, "voltage", "V")
	self:update_sensor('current', amps, "current", "A")
	self:update_sensor('power', watts, "power", "W")
	self:update_sensor('power_factor', pwrfctr_pct, "power_factor", "%")
end

function Govee5086Device:cmd(addr, entity, value)
	if self.entities[entity] and self.entities[entity].class == "switch" then
		local str_value = (value == "1" or value:lower() == "on") and "1" or "0"
		return "S " .. addr .. " " .. str_value
	end
	return nil
end

return Govee5086Device
