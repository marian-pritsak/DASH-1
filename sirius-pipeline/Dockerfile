FROM ubuntu:16.04

RUN apt update && \
    apt install -y g++ gcc git make automake sudo && \
    apt install -y cmake automake libjudy-dev libgmp-dev libpcap-dev \
    libboost-dev libboost-test-dev libboost-program-options-dev libboost-system-dev \
    libboost-filesystem-dev libboost-thread-dev libevent-dev libtool flex bison pkg-config g++ libssl-dev && \
    apt-get install -y cmake g++ git automake libtool libgc-dev bison flex \
	    libfl-dev libgmp-dev libboost-dev libboost-iostreams-dev \
	    libboost-graph-dev llvm pkg-config python python-scapy python-ipaddr python-ply python3-pip \
	    tcpdump && \
    pip3 install  scapy ply && \
    apt-get install -y autoconf automake libtool curl make g++ unzip

RUN git clone https://github.com/protocolbuffers/protobuf.git && \
    cd protobuf && \
	git checkout v3.6.1 && \
	git submodule update --init --recursive && \
	./autogen.sh && \
	./configure && \
	make && \
        make install && ldconfig && \
        cd .. && rm -rf protobuf

RUN git clone --recursive https://github.com/p4lang/p4c.git && \
    cd p4c && \
	git submodule update --init --recursive && \
	mkdir build && \
	cd build && \
	cmake .. && \
	make && \
	make install && \
        cd / && \
        rm -rf p4lang

RUN pip3 install six

RUN apt-get update && apt-get install -y lsb-release

RUN pip3 install ipaddr

RUN apt-get install -y libreadline-dev libnanomsg-dev

RUN git clone https://github.com/marian-pritsak/behavioral-model && \
        cd behavioral-model && \
	bash install_deps.sh && \
        ./autogen.sh && \
        ./configure --with-thrift && \
        make && \
        make install && \
        cd .. && \
        rm -rf behavioral-model
# Build gRPC.
# The gRPC build system should detect that a version of protobuf is already
# installed and should not try to install the third-party one included as a
# submodule in the grpc repository.
ENV GRPC_DEPS build-essential \
              autoconf \
              libtool
RUN git clone https://github.com/google/grpc.git
WORKDIR /grpc/
RUN git checkout tags/v1.3.2 && \
    git submodule update --init --recursive

RUN apt-get update && \
    apt-get install -y --no-install-recommends $GRPC_DEPS libgflags-dev && \
    export LDFLAGS="-Wl,-s" && \
    make && \
    make grpc_cli && \
    make install && \
    ldconfig && \
    cp /grpc/bins/opt/grpc_cli /usr/bin/ && \
    apt-get purge -y $GRPC_DEPS && apt-get autoremove --purge -y && \
    rm -rf /grpc /var/cache/apt/* /var/lib/apt/lists/* /var/cache/debconf/* /var/lib/dpkg/*-old /var/log/*

WORKDIR /

ENV BM_DEPS automake \
            build-essential \
            libjudy-dev \
            libgmp-dev \
            libpcap-dev \
            libboost-dev \
            libboost-program-options-dev \
            libboost-system-dev \
            libboost-filesystem-dev \
            libboost-thread-dev \
            libtool \
            pkg-config

RUN apt-get update && \
    apt-get install -y --no-install-recommends $BM_DEPS

ADD https://api.github.com/repos/p4lang/PI/git/refs/heads/master .PI.head.json

RUN git clone https://github.com/p4lang/PI/

WORKDIR /PI

RUN git submodule update --init --recursive

RUN export CFLAGS="-O0" && \
    export CXXFLAGS="-O0" && \
    ./autogen.sh && \
    ./configure --with-proto --without-cli --without-internal-rpc && \
    make && \
    make install && ldconfig && \
    rm -rf /PI/

RUN git clone https://github.com/marian-pritsak/behavioral-model && \
        cd behavioral-model && \
	bash install_deps.sh && \
        ./autogen.sh && \
        ./configure --with-pi --with-thrift && \
        make && \
        make install && \
        cd .. && \
        rm -rf behavioral-model

ARG user
ARG uid
ARG guid
ARG hostname

ENV BUILD_HOSTNAME $hostname
ENV USER $user

RUN groupadd -f -r -g $guid g$user

RUN useradd $user -l -u $uid -g $guid -d /var/$user -m -s /bin/bash

RUN echo "$user ALL=(ALL) NOPASSWD:ALL" >>/etc/sudoers

USER $user
