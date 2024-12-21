.PHONY: lint minify

LIB_MODULES = $(shell find lib -name "*.lua" |sed -e 's/^lib.//' -e 's/.lua$$//' -e 's|/|.|g' -e 's/\.init$$//' | grep -v mqtt.bit53 | sort)
MODULES = $(shell ls -1d *.lua device/*.lua receivers/*.lua | grep -v '^_.*.lua' | sed -e 's/.lua$$//' | sed -e 's|/|.|g' | sort)
PODMAN = podman run -it --rm -v $$PWD:/app lua
lint:
	$(PODMAN) luacheck $$(ls -1 *.lua | grep -v ^_) device/*.lua receivers/*.lua
# MINIFY = luasrcdiet
MINIFY = dumbluaparser
# amalg seems to corrupt the output if the stages are combined, so we run each stage individually
minify:	
	rm -f _version.lua
	echo -n "return '`lua5.1 version.lua`'" > _version.lua
	$(PODMAN) amalg.lua -o _combined.lua -s gateway.lua $(MODULES) $(LIB_MODULES) _version; export R=$$?; rm -f _version.lua; exit $$R
	$(PODMAN) sh -c 'cp _combined.lua /tmp/gateway.lua && amalg.lua -o _minify.lua -s /tmp/gateway.lua -t $(MINIFY)'
	$(PODMAN) sh -c 'cp _minify.lua /tmp/gateway.lua && amalg.lua -o _minify.lua -s /tmp/gateway.lua -z brieflz'
	chmod +x _minify.lua _combined.lua

