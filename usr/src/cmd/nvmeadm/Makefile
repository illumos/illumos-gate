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
# Copyright (c) 2018, Joyent, Inc.
# Copyright 2021 Oxide Computer Company
# Copyright 2022 Tintri by DDN, Inc. All rights reserved.
#


PROG= nvmeadm

OBJS= nvmeadm.o nvmeadm_dev.o nvmeadm_ofmt.o nvmeadm_print.o
SRCS= $(OBJS:%.o=%.c)

include ../Makefile.cmd
include ../Makefile.ctf

.KEEP_STATE:

CFLAGS +=	$(CCVERBOSE) -I$(SRC)/uts/common/io/nvme
LDLIBS +=	-ldevinfo -lofmt -lcmdutils
CSTD=	$(CSTD_GNU99)

#
# nvme_print_uint128() uses VLAs which understandably confuses smatch.
# It should probably be rewritten so we can smatch the file.
#
nvmeadm_print.o := SMATCH=off

all: $(PROG)

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

%.o: %.c
	$(COMPILE.c) $<
	$(POST_PROCESS_O)

install: all $(ROOTUSRSBINPROG)

clean:
	$(RM) $(OBJS) $(PROG)

lint:	lint_SRCS

include ../Makefile.targ
