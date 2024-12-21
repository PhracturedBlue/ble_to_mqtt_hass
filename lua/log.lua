local logging = require("logging")
local cmdline = require("cmdline")
local logger
if cmdline.logfilE then
	logger = require("logging.rolling_file") {
		filename = cmdline.logfile,
		maxFileSize = cmdline.logsize,
		maxBackupIndex = cmdline.logcount }
end
local log = logging.defaultLogger(logger)
if cmdline.debug then
    log:setLevel(logging.DEBUG)
else
    log:setLevel(logging.INFO)
end
return log
