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

PROG= i2cadm
OBJS =	i2cadm.o \
	i2cadm_controller.o \
	i2cadm_device.o \
	i2cadm_io.o \
	i2cadm_mux.o \
	i2cadm_port.o \
	i2cadm_scan.o \
	$(HEXDUMP_OBJS)

include ../Makefile.cmd
include ../Makefile.cmd.64
include ../Makefile.ctf
include $(SRC)/common/hexdump/Makefile.com

CFLAGS += $(CCVERBOSE)
CSTD = $(CSTD_GNU17)
LDLIBS += -li2c -ldevinfo -lofmt
CTF_MODE = link

.KEEP_STATE:

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

all: $(PROG)

install: all $(ROOTUSRSBINPROG)

clean:
	$(RM) $(OBJS)

include $(SRC)/common/hexdump/Makefile.targ
include ../Makefile.targ
