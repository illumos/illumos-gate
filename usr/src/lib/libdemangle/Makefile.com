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
# Copyright 2018 Jason King
# Copyright 2018, Joyent, Inc.
#

LIBRARY = libdemangle-sys.a
VERS    = .1
OBJECTS = str.o strview.o util.o cxx_util.o cxx.o demangle.o rust.o

include ../../Makefile.lib

LIBS =		$(DYNLIB) $(LINTLIB)
LDLIBS +=	-lc -lcustr

SRCDIR =	../common
$(LINTLIB) :=	SRCS = $(SRCDIR)/$(LINTSRC)

CSTD =		$(CSTD_GNU99)
CFLAGS +=	$(CCVERBOSE)
CPPFLAGS +=	-I$(SRCDIR) -D_REENTRANT -D__EXTENSIONS__

LINTFLAGS +=	-erroff=E_BAD_FORMAT_ARG_TYPE2
LINTFLAGS64 +=	-erroff=E_BAD_FORMAT_ARG_TYPE2
C99LMODE =	-Xc99=%all

.KEEP_STATE:

all:		$(LIBS)

lint:		lintcheck

include $(SRC)/lib/Makefile.targ
