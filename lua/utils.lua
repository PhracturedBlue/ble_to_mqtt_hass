local _M = {}
local socket = require("socket")

-- Ensure ssed is randomized for docker containers (modulo is for 32bit lua)
math.randomseed(math.floor(socket.gettime()*1000) % 0x80000000)

function _M.set_class(self, name)
	if self.class == nil then
		self.class = name
	end
end

function _M.getHostname()
    local hostname = socket.dns.gethostname()
    return hostname
end

function _M.hexToChars(hex)
	local t = {}
	for val in hex:gmatch("(%x%x)") do
		table.insert(t, string.char(tonumber(val, 16)))
	end
	return table.concat(t)
end

function _M.bytesToString(bytes)
  local s = {}
  for i = 1, #bytes do
    s[i] = string.char(bytes[i])
  end
  return table.concat(s)
end

function _M.split(str, sep)
	if sep == nil then
		sep = "%s"
	end
	local r = {}
	for item in str:gmatch("([^"..sep.."]+)") do
		table.insert(r, item)
	end
	return unpack(r)
end

function _M.slice(tbl, first, last, step)
  local sliced = {}

  for i = first or 1, last or #tbl, step or 1 do
    sliced[#sliced+1] = tbl[i]
  end

  return sliced
end

function _M.tosigned(val, size)
	if size == nil then
		size = 8
	end
	local max_signed = 2^(size-1)
	if val >= max_signed then
		return val - (2^size)
	end
	return val
end

function _M.try(f, catch_f)
	local status, exception = pcall(f)
	if not status then
		catch_f(exception)
	end
end

function _M.reverse(t)
	local reversedTable = {}
	local itemCount = #t
	for k, v in ipairs(t) do
		reversedTable[itemCount + 1 - k] = v
	end
	return reversedTable
end

-- https://stackoverflow.com/a/27028488
function _M.dump(o)
	if type(o) == 'table' then
		local s = ''
		for k,v in pairs(o) do
			if type(k) ~= 'number' then k = '"'..k..'"' end
			s = s .. '['..k..'] = ' .. _M.dump(v) .. ','
		end
		return '{ ' .. s:sub(1, -3) .. '} '
	elseif type(o) == 'string' then
		local s = o:gsub('\t', '\\t'):gsub('\n','\\n'):gsub('\r','\\r')
		s = s:gsub('[^\32-\126]', function(c) return string.format('\\x%02x', c:byte()) end)
		return '"' .. s .. '"'
	else
		return tostring(o)
	end
end

function _M.create_arg(long, short, param, msg, default)
	return {long = long, short = short, param = param, msg = msg, default = default}
end
function _M.create_boolean_arg(long, short, msg)
	return _M.create_arg(long, short, nil, msg, nil)
end

return _M
