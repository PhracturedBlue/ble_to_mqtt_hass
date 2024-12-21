openwrt 23.05 builds luasocket.serial, but does not include it in the final package.
This has been addressed in the 24.10 release (which is still in development at this time)

In the meantime, use the following steps to build the fixed luasocket.ipk.
Based on https://siliconlabs.my.site.com/community/s/article/Cross-Compiling-ZIP-Gateway-for-OpenWRT-and-other-platforms?language=en_US

For a new router, 'ARCH' and 'TARGET' are found in /etc/openwrt_release
The ABI is found by going to: https://downloads.openwrt.org/releases/<VERSION>/targets/<TARGET>/ and findion opewrt-sdk and the string after the gcc version and before .Linux (e.g. 'musl' or 'musl_eabi')

* For TP-Link TL-WDR4300 v1:
  * podman build --tag openwrt:23.05.3-WDR4300 --network=host --build-arg TARGET=ath79/generic --build-arg ARCH=mips_24kc .
  * podman run --rm -it -v $PWD:/app openwrt:23.05.2-WDR4300 sh -c 'cp -p bin/packages/*/packages/luasocket*.ipk /app'
* For Linksys EA8500:
  * podman build --tag openwrt:23.05.3-EA8500 --network=host --build-arg TARGET=ipq806x/generic --build-arg ARCH=arm_cortex-a15+neon-vfpv4 --build-arg ABI=musl_eabi .
  * podman run --rm -it -v $PWD:/app openwrt:23.05.3-EA8500 sh -c 'cp -p bin/packages/*/packages/luasocket*.ipk /app'
* For DL-WRX36
  * podman build --tag openwrt:23.05.3-DL-WRX36 --network=host --build-arg TARGET=ipq807x/generic --build-arg ARCH=aarch64_cortex-a53 .
  * podman run --rm -it -v $PWD:/app openwrt:23.05.3-DL-WRX36 sh -c 'cp -p bin/packages/*/packages/luasocket*.ipk /app'
