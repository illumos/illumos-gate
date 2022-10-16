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
# Copyright 2022 Oxide Computer Company
#

LIBRARY =	libxpio.a
VERS =		.1
OBJECTS =	libxpio.o libxpio_attr.o libxpio_dpio.o

include ../../Makefile.lib

SRCDIR =	../common
LIBS =		$(DYNLIB)
CSTD =		$(CSTD_GNU99)
LDLIBS +=	-lc -ldevinfo -lnvpair

.KEEP_STATE:

all: $(LIBS)

include ../../Makefile.targ
