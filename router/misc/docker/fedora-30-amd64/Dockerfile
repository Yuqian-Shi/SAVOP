# SAVOP downstream publication snapshot: imported modifications, 2026-11-10. Original notices retained; see docs/upstream.md.
FROM fedora:30
RUN dnf -y update
RUN dnf -y install \
	gcc \
	make \
	flex \
	bison \
	autoconf \
	libssh-devel \
	ncurses-devel \
	readline-devel
RUN dnf -y install \
	rpm-build \
	systemd-rpm-macros \
	python3 \
	python3-pip \
	python3-setuptools
