local function get_version()
	local _base = arg[0]:find("/") and arg[0]:gsub("/[^/]*$", "/") or "./"
	local f = io.popen("git describe --abbrev=12 --always --tags 2>/dev/null")
	if not f then
		return "unknown"
	end
	local ver = f:read('*a'):gsub("[\r\n]*", "")
	f:close()
	if ver == "" then
		return "unknown"
	end
	f = io.popen("git status --porcelain " .. _base .. " 2>/dev/null", "r")
	local s = f:read('*a'):gsub("[\r\n]*", "")
	f:close()
	if s == "" then
		return ver
	end
	return ver .. "-dirty"
end
local VERSION
if not pcall(function() VERSION = require("_version") end) then
	VERSION = get_version()
end

-- Print version when run as: lua version.lua
pcall(function()
	if arg[0]:find("version.lua") then
		print(VERSION)
	end
end)
return VERSION
