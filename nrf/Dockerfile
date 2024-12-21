FROM debian:bookworm-slim AS base

ARG ZEPHYR_VERSION=v3.7.0
ENV ZEPHYR_VERSION=${ZEPHYR_VERSION}

RUN \
  apt-get update && apt install -y \
  python3-dev \
  python3-pip \
  python3-wheel \
  git \
  device-tree-compiler \
  ninja-build \
  openocd \
  wget \
  vim-tiny \
  xz-utils && \
  rm -rf /var/lib/apt/lists/*


RUN pip3 install --break-system-packages west cmake
RUN pip3 install --break-system-packages -r https://raw.githubusercontent.com/zephyrproject-rtos/zephyr/${ZEPHYR_VERSION}/scripts/requirements-base.txt

ARG ARCHITECTURE=x86_64
ARG ZEPHYR_SDK_VERSION=0.16.8
ARG ZEPHYR_SDK_INSTALL_DIR=/opt/zephyr-sdk
ARG TOOLCHAIN=arm-zephyr-eabi

RUN \
  export sdk_file_name="zephyr-sdk-${ZEPHYR_SDK_VERSION}_linux-$(uname -m)_minimal.tar.xz" \
  && wget -q "https://github.com/zephyrproject-rtos/sdk-ng/releases/download/v${ZEPHYR_SDK_VERSION}/${sdk_file_name}" \
  && mkdir -p ${ZEPHYR_SDK_INSTALL_DIR} \
  && tar -xvf ${sdk_file_name} -C ${ZEPHYR_SDK_INSTALL_DIR} --strip-components=1 \
  && ${ZEPHYR_SDK_INSTALL_DIR}/setup.sh -t ${TOOLCHAIN} \
  && rm ${sdk_file_name}

WORKDIR /zephyr

RUN wget https://github.com/zephyrproject-rtos/zephyr/archive/refs/tags/${ZEPHYR_VERSION}.tar.gz && \
	tar -xf ${ZEPHYR_VERSION}.tar.gz && \
	rm ${ZEPHYR_VERSION}.tar.gz && \
	ln -s zephyr-* zephyr

RUN mkdir -p .west && echo "[manifest]\npath = zephyr\nfile = west.yml\n" > .west/config
RUN cd zephyr && west update || west update || west update
WORKDIR /zephyr/project
