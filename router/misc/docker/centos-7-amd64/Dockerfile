# SAVOP downstream publication snapshot: imported modifications, 2026-11-10. Original notices retained; see docs/upstream.md.
FROM centos:7
RUN yum -y upgrade
RUN yum -y install \
	gcc \
	make \
	flex \
	bison \
	autoconf \
	libssh-devel \
	ncurses-devel \
	readline-devel
RUN yum -y install \
	rpm-build \
	systemd \
	python3 \
	python3-pip \
	python3-setuptools
