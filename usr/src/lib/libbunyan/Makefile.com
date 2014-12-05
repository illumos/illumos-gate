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
# Copyright (c) 2014 Joyent, Inc. All rights reserved.
#

LIBRARY =	libbunyan.a
VERS =		.1
OBJECTS =	bunyan.o
USDT_PROVIDERS =	bunyan_provider.d

include ../../Makefile.lib

LIBS =		$(DYNLIB) $(LINTLIB)
LDLIBS +=	-lc -lumem -lnvpair -lnsl
CPPFLAGS +=	-I../common -I. -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64

SRCDIR =	../common

.KEEP_STATE:

all:	$(LIBS)

lint:	lintcheck

include ../../Makefile.targ
include ../../Makefile.usdt
