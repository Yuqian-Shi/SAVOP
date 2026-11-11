# SAVOP downstream publication snapshot: imported modifications, 2026-11-10. Original notices retained; see docs/upstream.md.
FROM opensuse/leap:15.1
RUN zypper -n up
RUN zypper -n install \
	gcc \
	make \
	flex \
	bison \
	autoconf \
	libssh-devel \
	ncurses-devel \
	readline-devel
RUN zypper -n install \
	rpm-build \
	systemd \
	systemd-rpm-macros \
	python3 \
	python3-pip \
	python3-setuptools
