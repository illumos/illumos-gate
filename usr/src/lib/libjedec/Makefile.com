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
# Copyright 2024 Oxide Computer Company
#

LIBRARY =	libjedec.a
VERS =		.1
OBJECTS =	libjedec.o \
		libjedec_spd.o \
		libjedec_spd_ddr3.o \
		libjedec_spd_ddr4.o \
		libjedec_spd_ddr5.o \
		libjedec_spd_lp4.o \
		libjedec_spd_lp5.o \
		libjedec_temp.o \
		bitext.o

include ../../Makefile.lib

LIBS =		$(DYNLIB)
CPPFLAGS +=	-I../common
LDLIBS +=	-lc -lnvpair
CSTD =		$(CSTD_GNU99)

SRCDIR =	../common

.KEEP_STATE:

all:	$(LIBS)

pics/%.o: $(SRC)/common/bitext/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

include ../../Makefile.targ

