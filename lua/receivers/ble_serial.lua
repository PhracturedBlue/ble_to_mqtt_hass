local log = require("log")
local copas = require("copas")
local serial = require("socket.serial")
local lru = require("lru")

local gw_mqtt = require("gw_mqtt")
local utils = require("utils")
local ttyctrl = require("ttyctrl")
local cmdline = require("cmdline")

local BTHomeDevice = require("device.bthome")
local Govee5086Device = require("device.govee5086")
local EngbirdDevice = require("device.engbird")

local TTY_DEVICE             = nil
local TTY_DEVICE_PATTERN     = cmdline.serial_pat
local tty_dev_id             = cmdline.serial
local GOVEE_5086             = cmdline.get_config("ble_serial").GOVEE_5086

local mqtt_que = gw_mqtt.mqtt_que
local device = gw_mqtt.device
local ignore =gw_mqtt.ignore
local ignore_parse_done = gw_mqtt.ignore_parse_done

local ignore_lru = lru.new(1000) -- These are recently seen

local tty = nil
local tty_writer_co = nil
local tty_reader_co = nil
local serial_reader  -- forward definition
local input_que = copas.queue.new({name = "serial_parser"})

-- Write to serial port via queue
local output_que = copas.queue.new({name = "serial_write_queue"})

local function check_args()
	if cmdline.list then
		io.write("Available serial devices:\n")
		local res = ttyctrl.list(TTY_DEVICE_PATTERN)
		for key, val in pairs(res) do
			io.write(key .. " :  " .. ttyctrl.to_string(val) .. "\n")
		end
		os.exit()
	end
	if not tty_dev_id then
		log:error("--serial is a required parameter")
		os.exit(1)
	end
	if tty_dev_id:find("/", nil, true) == 1 then
		tty_dev_id = ttyctrl.get_serial_id(tty_dev_id)
	end
	if tty_dev_id == nil then
		io.write("Couldn't find serial ID: " .. ttyctrl.to_string(cmdline.serial) .. "\n")
		os.exit()
	end
	if ttyctrl.find_serial(TTY_DEVICE_PATTERN, tty_dev_id) == nil then
		io.write("Couldn't find TTY device '" .. ttyctrl.to_string(tty_dev_id)
			 .. "'.  Check the pattern and device-id\n")
		os.exit()
	end
end

local function output_que_handler(item)
	if not tty then
		log:error("Tried to write to closed TTY: %s", tostring(item))
		return
	end
	log:info("Sending: %s", item)
	local ok, err = pcall(function()
		tty:send(item .. "\n")
	end)
	if not ok then
		log:error("Failed to write '%s' to TTY: %s", tostring(item), tostring(err))
	end
end

local function stop_tty(close)
	log:warn("Shutting down tty")
	if close and tty then
		pcall(function() tty:close() end)
	end
	tty = nil
	if tty_writer_co then
		copas.removethread(tty_writer_co)
		tty_writer_co = nil
	end
	local val
	repeat
		val = output_que:pop(0)
	until not val
	if tty_reader_co then
		copas.removethread(tty_reader_co)
		tty_reader_co = nil
	end
end

local function connect_tty()
	if tty_dev_id == nil then
		tty_dev_id = ttyctrl.get_serial_id(TTY_DEVICE)
		if tty_dev_id == nil then
			error("Could not find Serial device" .. TTY_DEVICE)
		end
		log:info("Found TTY Device: %s", ttyctrl.to_string(tty_dev_id))
	end
	while true do
		local dev = ttyctrl.find_serial(TTY_DEVICE_PATTERN, tty_dev_id)
		if dev == nil then
			log:error("Failed to find TTY: %s waiting 1 second...", TTY_DEVICE_PATTERN)
			copas.pause(1)
		else
			local tty_s, err = serial(dev)
			if tty_s then
				err = os.execute("stty -F " .. dev .. " speed 115200 cs8 -cstopb -parenb -ixon -icrnl -opost -echo")
				if err ~= 0 then
					error("stty failed with exit code: %s", tostring(err))
				end
				tty = copas.wrap(tty_s)
				log:info("Serial connected")
				return
			end
			log:error("Failed to open TTY: %s waiting 1 second...", tostring(err))
			copas.pause(1)
		end
	end
end

local function start_tty()
	local l, e
	assert(copas.running, "start_tty must be called from a copas thread")
	if tty then
		return
	end
	while true do
		connect_tty()
		log:info("Serial connected...clearing buffer")
		local now = os.time()
		tty:send("\nECHO " .. tostring(now) .. "\n")
		l, e = tty:receivepartial()
		while not e do
			print(">", l, e)
			if l:find('RSP ' .. tostring(now), nil, true) then
				break
			end
			l, e = tty:receivepartial()
		end
		if e then
			log:error("Unexpected issue: %s.  Retrying", tostring(e))
			stop_tty(true)
		else
			break
		end
	end
	log:info("Serial connected...resetting")
	tty:send("\nREBOOT\n")
	-- tty:send("\nCLOSEALL\n")
	while true do
		l, e = tty:receivepartial()
		while not e do
			print(">", l, e)
			if l:find('*** READY', nil, true) then
				tty_reader_co = copas.addnamedthread("serial_reader", serial_reader)
				tty_writer_co = output_que:add_worker(output_que_handler)
				log:info("Serial initialized")
				-- tty:send("\nLEVEL 0\n")
				return
			end
			l, e = tty:receivepartial()
		end
		log:info("Serial stopped: %s", tostring(e))
		stop_tty(true)
		connect_tty()
	end
end

local function parse_adv(data, rssi)
	local adv = {advtype = "ADV"}
	if rssi then
		adv.rssi = rssi
	end
	local pos = 1
	local adv_data = utils.hexToChars(data)
	while pos <= #adv_data do
		local ad_len = adv_data:byte(pos)
		local ad_type = adv_data:byte(pos+1)
		if ad_type == nil then
			return
		end
		local ad_data = adv_data:sub(pos+2, (pos+2)+(ad_len-1)-1)
		pos = pos + 1 + ad_len
		if ad_type == 0x01 then
			adv["flags"] = ad_data
		elseif ad_type == 0x09 then
			adv["name"] = ad_data
		elseif ad_type == 0x16 then
			if not adv.service_data then
				adv.service_data = {}
			end
			adv.service_data[string.format("%02x%02x", ad_data:byte(2), ad_data:byte(1))] = ad_data:sub(3)
		elseif ad_type == 0xff then
			adv.mfg_data = ad_data
		else
			adv[ad_type] = ad_data
		end
	end
	return adv
end

local function get_device(addr, adv)
	log:debug(utils.dump(adv))
	if adv.name and adv.name:sub(1,3) == "GVH" and adv.mfg_data and
			adv.mfg_data:byte(1) == 0x03 and adv.mfg_data:byte(2) == 0x88 then
		if GOVEE_5086[adv.name] then
			log:info("Found Govee 5086 device")
			local energy = GOVEE_5086[adv.name].energy and "1" or "0"
			output_que:push("G " .. addr .. " " .. energy .. " " .. GOVEE_5086[adv.name].auth .. " " .. adv.name)
			return Govee5086Device:new(addr, mqtt_que, adv.name, GOVEE_5086[adv.name].switch)
		end
		-- Don't add unknown Govee devices to the ignore list
		return nil
	elseif adv.name and adv.service_data and adv.service_data['fcd2'] then
		log:info("Found BTHome device")
		local dev = BTHomeDevice:new(addr, mqtt_que, adv.name)
		return dev
	elseif adv.name == "tps" and adv.mfg_data then
		log:info("Found Engbird device")
		local dev = EngbirdDevice:new(addr, mqtt_que)
		return dev
	elseif adv[0x02] and adv[0x02]:byte(1) == 0xf0 and adv[0x02]:byte(2) == 0xff then
		-- This is a TPS ADV before active scanning. Skip this one in favor of the active response
		return nil
	end
	return false
end

input_que:add_worker(function(item)
	log:debug(">" .. item)
	if item:sub(1, 4) == "ADV " then
		-- ADV 8c:de:52:7f:2a:3c bc 02010207094245444a4554 BEDJET
		local _, addr, rssi, data, _ = utils.split(item)
		addr = addr:upper()
		if ignore[addr] or ignore_lru:get(addr) then
			return
		end
		rssi = utils.tosigned(tonumber(rssi, 16))
		local adv = parse_adv(data, rssi)
		if adv == nil then
			return
		end
		if device[addr] then
			device[addr]:process(adv)
			return
		end
		local dev = get_device(addr, adv)
		if dev == nil then
			log:info("skipping: " .. item)
			return
		end
		if dev == false then
			ignore_lru:set(addr, true)
			log:info("ignoring: %s (%s)", item, tostring(ignore_lru:get(addr)))
			return
		end
		log:info("Found device %s:%s %s", dev.class, dev.name, addr)
		device[addr] = dev
		dev:process(adv)
	elseif item:sub(1, 4) == "GOV " then
		-- GOV 60:74:f4:ab:66:c3 cf GVH5086XXXX 1 ee1904d2410000002e3700000000000000000079
		local _, addr, rssi, _, power_on, power = utils.split(item)
                addr = addr:upper()    -- for backwards compatiblity
		if device[addr] == nil then
			log:warn("Found unknown connected Govee device: " .. item)
			return
		end
		rssi = utils.tosigned(tonumber(rssi, 16))
		power_on = tonumber(power_on)
	        power = utils.hexToChars(power)
		device[addr]:process(
                        {advtype = 'GOV', state = power_on, power = power, rssi = rssi})
	else
		log:info(">" .. item)
	end
end)


function serial_reader()
	if not ignore_parse_done then
		copas.pauseforever()  -- wait until initial wakeup
	end
	local l, e = tty:receivepartial()
	while not e do
		-- log:debug(">" .. l)
		l = l:gsub("[\n\r]", "")
		input_que:push(l)
		l, e = tty:receivepartial()
	end
	log:error("Failed to read from tty: %s", tostring(e))
	stop_tty(true)
	-- restart tty
	copas.addthread(start_tty)
end

gw_mqtt.add_callbacks{
	done_callback = function()
			if tty_reader_co then
				copas.wakeup(tty_reader_co)
			end
		end,
	cmd_callback = function(res)
			output_que:push(res)
		end
	}

check_args()

copas.addthread(start_tty)
