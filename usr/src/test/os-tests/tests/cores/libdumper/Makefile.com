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
# Copyright 2021 Oxide Computer Company
#

LIBRARY =	libdumper.a
VERS =		.1
OBJECTS =	libdumper.o

include $(SRC)/lib/Makefile.lib
include ../../Makefile.com

ROOTLIBDIR = $(ROOTOPTCORE)
ROOTLIBDIR64 = $(ROOTOPTCORE)/$(MACH64)

LIBS =		$(DYNLIB)
LDLIBS +=	-lc
SRCDIR =	../common

#
# This program needs to deliver DWARF data for debug purposes. Therefore
# we override the strip to make sure that we can get that.
#
STRIP_STABS = /bin/true

$(ROOTOPTDIR):
	$(INS.dir)

$(ROOTLIBDIR): $(ROOTOPTDIR)
	$(INS.dir)

$(ROOTLIBDIR64): $(ROOTLIBDIR)
	$(INS.dir)

.KEEP_STATE:

all:	$(LIBS)

include $(SRC)/lib/Makefile.targ
