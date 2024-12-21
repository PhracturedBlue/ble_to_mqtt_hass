ZEPHYR_VERSION = 3.7.0
ifeq ($(TARGET),)
	TARGET = $(shell test -f build/CMakeCache.txt && grep ^BOARD:STRING= build/CMakeCache.txt | sed -e 's/.*=//')
ifeq ($(TARGET),)
	TARGET = xiao_ble
endif
endif

WEST = podman run --privileged --rm -it -v $(PWD)/boards:/zephyr/zephyr/boards/custom -v $(PWD):/zephyr/project zephyr:$(ZEPHYR_VERSION) west

JLINK_OCD = --runner openocd --config interface/jlink.cfg --cmd-pre-init 'transport select swd' --cmd-pre-init 'source [find target/nrf52.cfg]'

GIT_VER = git describe --abbrev=12 --always --tags --dirty
.PHONY: build flash_jlink flash_uf2 debug test

DISK_LABEL =
ifeq ($(TARGET),xiao_ble)
	DISK_LABEL = XIAO-SENSE
else ifeq ($(TARGET),nicenano)
	DISK_LABEL = NICENANO
endif

test:
	echo $(TARGET)

build:
	if [ ! -f src/_appversion.h ] || ! echo '#define APP_VERSION "'`$(GIT_VER)`'"' | diff -q src/_appversion.h -; then echo '#define APP_VERSION "'`$(GIT_VER)`'"' > src/_appversion.h; fi
	$(WEST) build -b $(TARGET)

flash_jlink:
	$(WEST) flash $(JLINK_OCD)

flash_uf2:
	ls -l /dev/disk/by-label/$(DISK_LABEL) && sudo mount /dev/disk/by-label/$(DISK_LABEL) /media/ && sudo cp build/zephyr/zephyr.uf2 /media/ && sudo umount /media


debug:
	$(WEST) debug $(JLINK_OCD)

image:
	podman build --squash --tag zephyr:$(ZEPHYR_VERSION) --build-arg ZEPHYR_VERSION=v$(ZEPHYR_VERSION) .
