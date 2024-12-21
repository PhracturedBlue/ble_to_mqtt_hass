
local log = require("log")
local copas = require("copas")
local socket = require("socket")
local gw_mqtt = require("gw_mqtt")
local const = require("const")
local cmdline = require("cmdline")
local utils = require("utils")

local HoneywellDevice = require("device.honeywell")

local AD_HOST                = cmdline.ad_host
local AD_PORT                = cmdline.ad_port
local HONEYWELL              = cmdline.get_config("alarmdecoder").HONEYWELL

local mqtt_que = gw_mqtt.mqtt_que
local device = gw_mqtt.device
local ignore =gw_mqtt.ignore
local ignore_parse_done = gw_mqtt.ignore_parse_done

local input_que = copas.queue.new({name = "honeywell_parser"})

local function get_device(addr)
	if HONEYWELL[addr] then
		log:info("Found Honeywell 5800 device")
		return HoneywellDevice:new(addr, mqtt_que, HONEYWELL[addr])
	end
	log:info("Ignoring unknown Honeywell device: " .. addr)
	return nil
end

input_que:add_worker(function(item)
	if not ignore_parse_done then
		return
	end
	log:debug(">" .. item)
	if not item:find("^!RFX:") then
		return
	end
	-- !RFX:0147527,80
        local addr, data = utils.split(string.sub(item, 6, -1), ",")
	if ignore[addr] then
		return
	end
	if device[addr] then
		device[addr]:process(data)
		return
	end
	local dev = get_device(addr)
	if not dev then
		log:info("ignoring: (" .. addr .. ") " .. item)
		ignore[addr] = true
		return
	end
	log:info("Found device %s:%s %s", dev.class, dev.name, addr)
	device[addr] = dev
	dev:process(data)
end)

copas.addthread(function()
    local port = AD_PORT
    local host = AD_HOST

    while true do
        local sock = copas.wrap(socket.tcp())
        copas.setsocketname("AD2USB_TCP_client", sock)
        assert(sock:connect(host, port))
        local l, e = sock:receive("*l")
        while not e do
		l = l:gsub("[\n\r]", "")
		input_que:push(l)
		l, e = sock:receive("*l")
	end
	log:error("Loop failed: " .. tostring(e))
    end
end)
