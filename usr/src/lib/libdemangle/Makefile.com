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
# Copyright 2019 Joyent, Inc.
#

LIBRARY = libdemangle-sys.a
VERS    = .1
OBJECTS =		\
	cxx.o		\
	cxx_util.o	\
	demangle.o	\
	rust.o		\
	rust-legacy.o	\
	rust-v0puny.o	\
	rust-v0.o	\
	str.o		\
	strview.o	\
	util.o

include ../../Makefile.lib

LIBS =		$(DYNLIB)
LDLIBS +=	-lc -lcustr

SRCDIR =	../common

CSTD =		$(CSTD_GNU99)
CFLAGS +=	$(CCVERBOSE)
CPPFLAGS +=	-I$(SRCDIR) -D_REENTRANT -D__EXTENSIONS__

.KEEP_STATE:

all:		$(LIBS)

include $(SRC)/lib/Makefile.targ
