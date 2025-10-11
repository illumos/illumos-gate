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
# Copyright 2025 Oxide Computer Company
#

LIBRARY =	libi2c.a
VERS =		.1
OBJECTS =	libi2c.o \
		libi2c_ctrl.o \
		libi2c_device.o \
		libi2c_error.o \
		libi2c_io.o \
		libi2c_mux.o \
		libi2c_port.o

OBJECTS +=	ilstr.o

include ../../Makefile.lib

SRCDIR =	../common
LIBS =		$(DYNLIB)
CSTD =		$(CSTD_GNU17)
LDLIBS +=	-lc -ldevinfo -lnvpair

.KEEP_STATE:

all: $(LIBS)

pics/%.o: $(SRC)/common/ilstr/%.c
	$(COMPILE.c) $< -o $@
	$(POST_PROCESS_O)

include ../../Makefile.targ
