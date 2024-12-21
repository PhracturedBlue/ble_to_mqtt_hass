#!/usr/bin/env lua5.1
-- load packages from local 'lib' dir
local _base = arg[0]:find("/") and arg[0]:gsub("/[^/]*$", "/") or "./"
package.path = _base .. "/?.lua;" .. _base .. "lib/?.lua;" .. _base .. "/lib/?/init.lua;" .. package.path

local cmdline = require("cmdline")  -- Put this early
local copas = require("copas")
local log = require("log")
local utils = require("utils")

for _, receiver in ipairs({utils.split(cmdline.receivers, ",")}) do
	local f = io.open(_base .. 'receivers/' .. receiver .. ".lua", "r")
	if f== nil then
		log:error("Invalid receiver: " .. receiver)
		os.exit()
	end
	io.close(f)
	log:info("loading receiver: " .. receiver)
	require("receivers." .. receiver)
end

copas()
