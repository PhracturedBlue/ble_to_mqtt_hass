local utils = require("utils")
local _M = {}
_M.VERSION = require("version")

_M.CMDLINE = {
	utils.create_arg("config", "c", "file", "config file to read (json format)"),
	utils.create_arg("mqtt", "m", "url", "MQTT url (e.g. mqtt://127.0.0.1)", "mqtt://localhost"),
	utils.create_arg("logfile", "o", "logfile", "Logfile name (Default: stderr)"),
	utils.create_arg("logsize", nil, "size", "Max logfile size", 1024 * 1024),
	utils.create_arg("logcount", nil, "count", "Max old logfiles to keep size", 1),
	utils.create_arg("receivers", nil, "rcv", "Comma separated list of seceivers", "ble_serial"),
	utils.create_boolean_arg("debug", "d", "Enable debug"),
	ble_serial = {
		utils.create_boolean_arg("list", "l", "List available serial-ids"),
		utils.create_arg("serial", nil, "id", "Serial identifier to use (from --list)"),
		utils.create_arg("serial_pat", nil, "pattern", "Serial device pattern to search", "/dev/ttyACM*"),
	},
	alarm_decoder = {
		utils.create_arg("ad_host", nil, "host", "Hostname/IP of AlarmDecoder", "localhost"),
		utils.create_arg("ad_port", nil, "port", "Port number of AlarmDecoder", 10000),
	}
}

_M.HOSTNAME = utils.getHostname()
_M.VERSION_STR = "lua gateway " .. _M.VERSION
_M.BASE_TOPIC = "/ble"
_M.AVAILABILITY_TOPIC_TOP = _M.BASE_TOPIC .. "/status"
_M.AVAILABILITY_TOPIC = _M.AVAILABILITY_TOPIC_TOP .. "/" .. _M.HOSTNAME
_M.COMMAND_TOPIC = _M.BASE_TOPIC .. "/command/" .. _M.HOSTNAME
_M.HASS_TOPIC = "homeassistant/status"

_M.DEFAULT_TIMEOUT = 600
_M.DEFAULT_HONEYWELL_TIMEOUT = 6 * 3600

return _M
