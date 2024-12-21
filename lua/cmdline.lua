local alt_getopt = require("alt_getopt")
local const = require("const")
local utils = require('utils')
local json = require('json')

local VERSION = const.VERSION
local _M = {}
_M.args = {}

function _M.args.get_config(rcvr)
	if not _M.args.config or type(_M.args.config) ~= "table" then
		return {}
	end
	if not _M.args.config[rcvr] then
		return {}
	end
	return _M.args.config[rcvr]
end

local function build_opts(opts, long, short)
	if not long then
		long = {help = "h"}
		short = "h"
	end
	for idx, item in pairs(opts) do
		if type(idx) ~= "number" then
			short = build_opts(item, long, short)
		else
			if item.param then
				if item.short then
					short = short .. item.short .. ":"
					long[item.long] = item.short
				else
					long[item.long] = 1
				end
			else
				if item.short then
					short = short .. item.short
					long[item.long] = item.short
				else
					long[item.long] = 0
				end
			end
		end
	end
	return short, long
end

local function build_help(items)
	local help = {}
	local max_key = 0
	for _, item in ipairs(items) do
		local key = "    "
		if item.short then
			key = key .. "-" .. item.short .. ", "
		end
		key = key .. "--" .. item.long
		if item.param then
			key = key .. " <" .. item.param .. ">"
		end
		if string.len(key) > max_key then
			max_key = string.len(key)
		end
		local desc = item.msg
		if item.default then
			desc = desc .. "\n" .. "(Default: " .. tostring(item.default) .. ")"
		end
		table.insert(help, {key = key, desc = desc})
	end
	local msg = ""
	local default_offset = string.format("    %-" .. tostring(max_key + 3) .. "s", "")
	for _, item in ipairs(help) do
		local key = item.key
		local arg = item.desc
		msg = msg .. string.format("    %-" .. tostring(max_key) .. "s : " ..
			arg:gsub("\n", "\n" .. default_offset) .. "\n", key)
	end
	return msg
end

local function parse_opts(user_values, opts)
	for name, opt in pairs(opts) do
		if type(name) == "string" then
			parse_opts(user_values, opt)
		else
			local val = opt.short and user_values[opt.short] or user_values[opt.long]
			if val and type(opt.default) == "number" then
				val = tonumber(val)
			end
			_M.args[opt.long] = val or opt.default
		end
	end
end

local function parse_cmdline()
	local opts
	local optarg

	local short_opts, long_opts = build_opts(const.CMDLINE)
	opts,optarg = alt_getopt.get_opts (arg, short_opts, long_opts)

	if opts.h or optarg < #arg then
		io.write("gateway.lua - BLE to MQTT gateway using a serial NRF52 module\n")
		io.write("Version: " .. VERSION .. "\n\n")
		io.write("\n  gateway.lua [-h] <...>\n\n")
		io.write(build_help({ utils.create_boolean_arg("help", "h", "This help message"), unpack(const.CMDLINE)}))
		for name, rcvr in pairs(const.CMDLINE) do
			if type(name) == "string" then
				io.write("\n" .. name .. " options:\n")
				io.write(build_help(rcvr))
			end
		end
		os.exit()
	end
	io.write("gateway.lua - version: " .. VERSION .. "\n")
	parse_opts(opts, const.CMDLINE)
	if _M.args.config then
		local base = arg[0]:find("/") and arg[0]:gsub("/[^/]*$", "/") or "./"
		local f = io.open(_M.args.config, "r")
		if not f and not _M.args.config:find('/', nil, true) then
			f = io.open(base .. _M.args.config, "r")
		end
		if not f then
			io.write("Could not read config file: " .. _M.args.config .. "\n")
			os.exit(1)
		end
		local ok, data = pcall(function()
			return json.decode(f:read("*all"))
			end)
		io.close(f)
		if not ok then
			io.write("Failed to read " .. _M.args.config .. ": " .. tostring(data) .. "\n")
			os.exit(1)
		end
		for rcvr, _ in pairs(data) do
			f = io.open(base .. "receivers/" .. rcvr .. ".lua", "r")
			if not f then
				io.write("Found config for invalid receiver: " .. rcvr .. "\n")
				os.exit(1)
			end
			io.close(f)
		end
		_M.args.config = data
	end
end

parse_cmdline()

return _M.args
