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
# Copyright 2020 Oxide Computer Company
#

LIBRARY =	libssp_ns.a
VERS =		.1
OBJECTS =	ssp_ns.o

include ../../Makefile.lib

#
# We need to build an archive file; however, this is going to show up
# and be used in libraries and otherwise. So we need to still build it
# as position independent code. The Makefile system doesn't want to
# build a PIC file that's going into a .a file by default, so we have to
# do a little bit here.
#
LIBS =		$(LIBRARY)
SRCDIR =	../common
CFLAGS +=	$($(MACH)_C_PICFLAGS)

CLOBBERFILES +=	$(LIBRARY)

.KEEP_STATE:

all:	$(LIBS)


include ../../Makefile.targ
