-- This is a very Linux specific way of finding a USB UART device if it reconnects under a different name
local _M = {}
local utils = require("utils")

local function get_id(usbpath, match)
	local id = {}
	if type(match) == 'string' then
		local idVendor, idProduct, manufacturer, product, version, serial = utils.split(match, ':')
		match = {idVendor, idProduct, manufacturer, product, version, serial}
	end
	for idx, fname in ipairs({"idVendor", "idProduct", "manufacturer", "product", "version", "serial"}) do
		local handle = io.popen("cat " .. usbpath .. "/" ..fname .. " 2> /dev/null")
		local res = handle:read("*a")
		res = res:gsub("[\r\n]", "")
		if not res  or res == "" then
			return nil
		end
		if match and match[idx] ~= res then
			return nil
		end
		table.insert(id, res)
	end
	if match then
		return true
	end
	return id
end

local function get_major_minor(line)
	return line:match('^%S+ +%S+ +%S+ +%S+ +(%d+), +(%d) .* (%S+)')
end

local function get_char_syspath(major, minor)
	return "/sys/dev/char/" .. major .. ":" .. minor .. "/device/.."
end

function _M.to_string(devid)
	if type(devid) == "table" then
		return string.format("%s:%s:%s:%s:%s:%s",
			tostring(devid[1]), tostring(devid[2]), tostring(devid[3]),
			tostring(devid[4]), tostring(devid[5]), tostring(devid[6]))
	end
	return devid
end

function _M.get_serial_id(dev)
	local handle = io.popen("ls -l " .. dev .. " 2>&1")
	local res = handle:read("*a")
	if res:find("c", nil, true) == 1 then
		-- crw-rw---- 1 root dialout 166, 0 Jul  9 09:13 /dev/ttyACM0
		local major, minor = get_major_minor(res)
		if major and minor then
			local path = "/sys/dev/char/" .. major .. ":" .. minor .. "/device/.."
			return get_id(path)
		end
	end
end
function _M.find_serial(pat, match)
	assert(match, "match must be specified")
	local handle = io.popen("ls -l " .. pat .. " 2>&1")
	for line in handle:lines() do
		local major, minor, path = get_major_minor(line)
		if major and minor and path then
			local syspath = get_char_syspath(major, minor)
			if get_id(syspath, match) then
				return path
			end
		end
	end
end

function _M.list(pat)
	local res = {}
	local handle = io.popen("ls -l " .. pat .. " 2>&1")
	for line in handle:lines() do
		local major, minor, path = get_major_minor(line)
		if major and minor and path then
			local syspath = get_char_syspath(major, minor)
			res[path] = get_id(syspath)
		end
	end
	return res
end
-- _origid = _M.get_serial_id("/dev/ttyACM0")
-- print(_M.find_serial("/dev/ttyACM*", _origid))

return _M
