FROM ubuntu:18.04
MAINTAINER Chengbin Pang

RUN apt-get -y update && apt-get -y install build-essential \
	bison \
	zlib1g-dev \
	libtool \
	cmake \
	linux-libc-dev-i386-cross \
	gcc-multilib \
	g++-multilib \
	libc6-dev-i386 \
	autoconf \
	automake \
	curl \
	wget \
	git \
	make \
	unzip \
	pkg-config \
	python \
	python-dev \
	python-pip \
        gawk \
	sudo

COPY . /gt_x86
WORKDIR /gt_x86
RUN bash ./docker_build.sh
