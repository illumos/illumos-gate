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

PROG= gpioadm

include ../Makefile.cmd
include ../Makefile.cmd.64
include ../Makefile.ctf

CFLAGS += $(CCVERBOSE)
CSTD = $(CSTD_GNU99)
OBJS = gpioadm.o gpioadm_controller.o gpioadm_dpio.o gpioadm_gpio.o
LDLIBS += -ldevinfo -lofmt -lxpio

.KEEP_STATE:

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

all: $(PROG)

install: all $(ROOTUSRSBINPROG)

clean:
	$(RM) $(OBJS)

include ../Makefile.targ
