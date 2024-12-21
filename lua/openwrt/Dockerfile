FROM ubuntu:18.04 as base

ARG UID=1000
ARG GID=1000

################################################################################
# Install the host build system prerequisites                                  #
################################################################################

RUN apt-get update \
&& apt-get install -y curl zip git cmake bison flex pkg-config ninja-build \
python xsltproc build-essential libncurses5-dev libncursesw5-dev \
zlib1g-dev sudo gawk gettext libssl-dev wget unzip file python2.7 python3 \
python3-distutils rsync subversion swig time \
&& rm -rf /var/lib/apt/lists/*

RUN groupadd -g $GID -o build
RUN useradd -m -u $UID -g $GID -G sudo -p -o -s /bin/bash build
RUN chmod a+rw /opt
# USER build

################################################################################
# Download the OpenWRT toolchain files and set PATH and STAGING_DIR            #
################################################################################
ARG TARGET=ath79/generic
ARG VERSION=23.05.3
ARG GCC_VER=12.3.0
ARG ABI=musl
# Set the working directory to /opt/ in the new docker image
WORKDIR /opt
# Download and extract the OpenWRT SDK
RUN echo curl -O https://downloads.openwrt.org/releases/${VERSION}/targets/${TARGET}/openwrt-sdk-${VERSION}-$(echo $TARGET | sed -e 's|/|-|g')_gcc-${GCC_VER}_${ABI}.Linux-x86_64.tar.xz
RUN \
	curl -O https://downloads.openwrt.org/releases/${VERSION}/targets/${TARGET}/openwrt-sdk-${VERSION}-$(echo $TARGET | sed -e 's|/|-|g')_gcc-${GCC_VER}_${ABI}.Linux-x86_64.tar.xz && \
	tar -xf openwrt-sdk* && \
	rm openwrt-sdk-*.tar.xz

ARG ARCH=mips_24kc
ENV ARCH=mips_24kc
# Create links to make accessing them easier
RUN ln -s openwrt-sdk*/ openwrt-sdk \
    && ln -s openwrt-sdk/staging_dir/toolchain-${ARCH}*/ toolchain-${ARCH}-gcc

FROM base as sdk
ARG ARCH=mips_24kc
ENV ARCH=mips_24kc
ENV STAGING_DIR=/opt/openwrt-sdk/staging_dir
ENV PATH=$PATH:/opt/toolchain-${ARCH}-gcc/bin

WORKDIR /opt/openwrt-sdk
RUN mkdir host
RUN yes "" | make oldconfig
RUN \
	grep ' base ' feeds.conf.default | sed -e 's/src-git-full/src-git/' > feeds.conf.new && \
	grep ' packages ' feeds.conf.default | sed -e 's/src-git-full/src-git/' >> feeds.conf.new && \
	mv feeds.conf.new feeds.conf.default
RUN ./scripts/feeds update -a

From sdk
RUN ./scripts/feeds install luasocket
COPY luasocket.patch /tmp
RUN cd feeds/packages && patch -p1 < /tmp/luasocket.patch

RUN make package/luasocket/download
RUN make package/luasocket/prepare
RUN make package/luasocket/compile
