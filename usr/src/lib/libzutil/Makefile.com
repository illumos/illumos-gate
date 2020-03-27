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

LIBRARY= libzutil.a
VERS= .1

OBJECTS=			\
	zutil_import.o		\
	zutil_nicenum.o		\
	zutil_pool.o

include ../../Makefile.lib

# libzutil must be installed in the root filesystem for mount(1M)
include ../../Makefile.rootfs

LIBS=	$(DYNLIB)

SRCDIR =	../common

INCS += -I$(SRCDIR)
INCS += -I../../../uts/common/fs/zfs
INCS += -I../../libc/inc

CSTD=		$(CSTD_GNU99)
LDLIBS +=	-lc -lm -ldevid -lnvpair -ladm -lavl -lefi
CPPFLAGS +=	$(INCS) -D_LARGEFILE64_SOURCE=1 -D_REENTRANT
$(NOT_RELEASE_BUILD)CPPFLAGS += -DDEBUG

SRCS=	$(OBJECTS:%.o=$(SRCDIR)/%.c)

.KEEP_STATE:

all: $(LIBS)

include ../../Makefile.targ
