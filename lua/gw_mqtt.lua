
local log = require("log")
local copas = require("copas")
local mqtt = require("mqtt")
local utils = require("utils")
local const = require("const")
local cmdline = require("cmdline")
local add_client = require("mqtt.loop").add

local _M = {}

local MQTT_URL               = cmdline.mqtt
local AVAILABILITY_TOPIC     = const.AVAILABILITY_TOPIC
local AVAILABILITY_TOPIC_TOP = const.AVAILABILITY_TOPIC_TOP
local COMMAND_TOPIC          = const.COMMAND_TOPIC
local HASS_TOPIC             = const.HASS_TOPIC

-- All device objects
local device = {}
_M.device = device

-- These are used by another runner
local ignore = {}
_M.ignore = ignore

-- Publish to MQTT via queue
local mqtt_que = copas.queue.new({name = "mqtt_writer"})
_M.mqtt_que = mqtt_que

-- Receive command from MQTT
local cmd_que = copas.queue.new({name = "command_queue"})

-- We've finished determining devices to ignore
local ignore_parse_done = false
function _M.ignore_parse_done()
	return ignore_parse_done
end

-- Alow caller to hook into process loop
local done_callback = {}
local cmd_callback = {}
function _M.add_callbacks(arg)
	for k, v in pairs(arg) do
		if k == "done_callback" then
			table.insert(done_callback, v)
		elseif k == "cmd_callback" then
			table.insert(cmd_callback, v)
		end
	end
end

local function resend_discovery()
	-- need to resend all discovery messages
	for _, dev in pairs(device) do
		log:info("Sending discovery for %s", tostring(dev))
		dev:send_discovery()
	end
end

local mqtt_client = mqtt.client{
	uri = MQTT_URL,
	clean = true,
	reconnect = true,
	will = { topic = AVAILABILITY_TOPIC, payload = "offline", retain = true },

	-- create event handlers
	on = {
		connect = function(connack, self)
			if connack.rc ~= 0 then
				log:error("MQTT connection to broker failed:", connack:reason_string(), connack)
				return
			end
			log:info("MQTT connected: %s", utils.dump(connack)) -- successful connection

			assert(self:subscribe{ topic=AVAILABILITY_TOPIC_TOP .. "/#", callback=function(suback)
				log:info("MQTT subscribed:", tostring(suback))
				self:publish({topic=AVAILABILITY_TOPIC .. "/done", payload=nil, retain=false})
			end})
			assert(self:subscribe{ topic=COMMAND_TOPIC .. "/#", callback=function(suback)
				log:info("MQTT subscribed: %s", tostring(suback))
			end})
			assert(self:subscribe{ topic=HASS_TOPIC, callback=function(suback)
				log:info("MQTT subscribed: %s", tostring(suback))
			end})
		end,

		message = function(msg)
			log:debug("received: %s", utils.dump(msg))
			if msg.topic == AVAILABILITY_TOPIC .. "/done" then
				ignore_parse_done = true
				for _, cb in ipairs(done_callback) do
					cb()
				end
				mqtt_que:push({topic = AVAILABILITY_TOPIC, payload = "online", retain = true})
				resend_discovery()
				return
			end
			if msg.topic == AVAILABILITY_TOPIC then
				if not ignore_parse_done and msg.payload ~= "offline" then
					log:info("Setting %s offline", AVAILABILITY_TOPIC)
					mqtt_que:push({topic=AVAILABILITY_TOPIC, payload="offline", retain=true})
				end
				return
			end
			if msg.topic == HASS_TOPIC then
				cmd_que:push({hass = msg.payload})
				return
			end

			-- Handle input command
			local cmd_match = (COMMAND_TOPIC .. '/([^/]+)/([^/]+)$'):gsub("%-", "%%-")
			local dev_addr, entity = msg.topic:match(cmd_match)
			if dev_addr and entity then
				log:info("Got MQTT command: %s, %s, %s", dev_addr, entity, msg.payload)
				cmd_que:push({device = dev_addr, entity = entity, value = msg.payload})
				return
			end

			local dev = msg.topic:match(AVAILABILITY_TOPIC_TOP .. '/[^/]+/([^/]+)$')
			if not dev then
				return
			end
			if msg.topic:find(AVAILABILITY_TOPIC .. "/", nil, true)  == 1 then
				if not ignore_parse_done and msg.payload ~= "offline" then
					log:info("Setting %s offline", msg.topic)
					mqtt_que:push({topic=msg.topic, payload="offline", retain=true})
				end
				return
			end

			-- fallthrough
			if msg.payload == nil then
				log:info("forgetting ignored device: " .. msg.topic)
				ignore[dev] = nil
			else
				log:info("ignoring device " .. dev .. " from " .. msg.topic)
				ignore[dev] = true
			end
		end,

		error = function(err)
			log:info("MQTT client error:", err)
		end,

		close = function()
			log:info("MQTT conn closed")
		end
	}, -- close 'on', event handlers
}
log:info("created MQTT client: %s", tostring(mqtt_client))
mqtt_que:add_worker(function(item)
	mqtt_client:publish({topic = item.topic, payload = item.payload, retain = item.retain})
	-- log:info("MQTT topic: %s payload: %s retain: %s", item.topic, item.payload, tostring(item.retain))
end)

cmd_que:add_worker(function(item)
	log:debug("!" .. utils.dump(item))
	local addr = item.device
	local entity = item.entity
	local value = item.value
	local hass = item.hass

	if hass then
		if hass == "online" then
			resend_discovery()
		end
		return
	end

	if not addr or not entity or not value then
		return
	end
	if device[addr] and type(device[addr].cmd) == "function" then
		local ret = device[addr]:cmd(addr, entity, value)
		if ret then
			for _, cb in ipairs(cmd_callback) do
				cb(ret)
			end
		end
	else
		log:warn("Device " .. addr .. "/" .. entity .. " does not support commands")
	end
end)

add_client(mqtt_client)

return _M
