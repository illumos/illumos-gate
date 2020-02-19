#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#

#
# Copyright 2020 Joyent, Inc.
#

LIBRARY =	libvarpd_svp.a
VERS =		.1
OBJECTS =	libvarpd_svp.o \
		libvarpd_svp_conn.o \
		libvarpd_svp_crc.o \
		libvarpd_svp_host.o \
		libvarpd_svp_loop.o \
		libvarpd_svp_remote.o \
		libvarpd_svp_shootdown.o \
		libvarpd_svp_timer.o

include ../../../Makefile.lib
include ../../Makefile.plugin

LIBS =		$(DYNLIB)

#
# Yes, this isn't a command, but libcmdutils does have the list(9F)
# functions and better to use that then compile list.o yet again
# ourselves... probably.
#
LDLIBS +=	-lc -lumem -lnvpair -lsocket -lavl \
		-lcmdutils -lidspace -lbunyan
CPPFLAGS +=	-I../common

LINTFLAGS +=	-erroff=E_BAD_PTR_CAST_ALIGN
LINTFLAGS64 +=	-erroff=E_BAD_PTR_CAST_ALIGN
SRCDIR =	../common

C99MODE=	-xc99=%all
C99LMODE=	-Xc99=%all

.KEEP_STATE:

all:	$(LIBS)

lint:	lintcheck

include ../../../Makefile.targ
