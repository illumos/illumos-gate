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
# Copyright 2016 Joyent, Inc.
#

#
# This Makefile is shared between both libc and other consumers
#

COMMPAGE_OBJS = \
	cp_subr.o \
	cp_main.o

COMMPAGE_OFFSETS_SRC = $(SRC)/lib/commpage/common/offsets.in
COMMPAGE_OFFSETS_H = cp_offsets.h

CLEANFILES += $(COMMPAGE_OFFSETS_H)

pics/cp_main.o := CPPFLAGS += -I$(SRC)/uts/i86pc
pics/cp_subr.o := ASFLAGS += -I$(SRC)/uts/i86pc -I./
$(COMMPAGE_OFFSETS_H) := CPPFLAGS += -I$(SRC)/uts/i86pc

COMMPAGE_CPPFLAGS = -I$(SRC)/lib/commpage/common
