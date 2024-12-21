FROM alpine
#RUN apk add lua5.1 lua5.1-lanes lua5.1-mosquitto --repository=http://dl-cdn.alpinelinux.org/alpine/edge/testing/
#RUN apk add lua5.1 lua-luv lua-bitop --repository=http://dl-cdn.alpinelinux.org/alpine/edge/testing/
#RUN apk add lua5.1 lua5.1-mosquitto luarocks --repository=http://dl-cdn.alpinelinux.org/alpine/edge/testing/
#RUN apk add git gcc make
RUN apk add lua5.1 lua5.1-socket lua5.1-bitop luarocks lua-brieflz luacheck --repository=http://dl-cdn.alpinelinux.org/alpine/edge/testing/
RUN mkdir -p /usr/local/share/lua/5.1
ARG AMALG_VER=670aff73923aa72e6539cf4259c7f2930bc65cce
RUN cd /tmp && \
	wget https://github.com/siffiejoe/lua-amalg/archive/${AMALG_VER}.tar.gz && \
	tar -xf ${AMALG_VER}.tar.gz && \
	mv lua-amalg-${AMALG_VER}/src/* /usr/local/share/lua/5.1/ && \
	ln -s /usr/local/share/lua/5.1/amalg.lua /usr/local/bin/ && \
	rm -rf lua-amalg-${AMALG_VER} ${AMALG_VER}.tar.gz
RUN luarocks-5.1 install amalg
ARG SRCDIET_VER=e9ceefdd1b3a03bc6c444e8fbb41c506adbbf25f
RUN cd /tmp && \
	wget https://github.com/jirutka/luasrcdiet/archive/${SRCDIET_VER}.tar.gz && \
	tar -xf ${SRCDIET_VER}.tar.gz && \
	mv luasrcdiet-${SRCDIET_VER}/luasrcdiet /usr/local/share/lua/5.1/ && \
	mv luasrcdiet-${SRCDIET_VER}/bin/luasrcdiet /usr/local/bin && \
	rm -rf luasrcdiet-${SRCDIET_VER} ${SRCDIET_VER}.tar.gz
#RUN luarocks-5.1 install luasrcdiet
#COPY e9ceefdd.diff /tmp
#COPY 367a32aa.diff /tmp
#RUN cd /usr/local/share/lua/5.1/ && patch -p1 < /tmp/e9ceefdd.diff
#RUN cd /usr/local/share/lua/5.1/ && patch -p1 < /tmp/367a32aa.diff
ARG DUMBPARSE_VER=a14fbbefb47e28c7e29a4721be236e25f4c686f4
RUN wget -O /usr/local/share/lua/5.1/dumbParser.lua https://raw.githubusercontent.com/ReFreezed/DumbLuaParser/${DUMBPARSE_VER}/dumbParser.lua
ENV LUA_PATH='/app/?.lua;/app/lib/?.lua;lib/?/init.lua;;'
WORKDIR /app
