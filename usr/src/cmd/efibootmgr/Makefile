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
# Copyright 2026 Argo Technology East
#

PROG = efibootmgr
OBJS = efibootmgr.o
SRCS = $(OBJS:%.o=%.c)

include ../Makefile.cmd
include ../Makefile.cmd.64

CFLAGS += $(CCVERBOSE)
CPPFLAGS += -I$(SRC)/lib/libefivar/common
LDLIBS += -lefivar -lefi

FILEMODE = 0555
ROOTCMDDIR = $(ROOTUSRSBIN)

.KEEP_STATE:

all: $(PROG)

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

clean:
	$(RM) $(OBJS)

install: $(ROOTUSRSBINPROG)

include ../Makefile.targ
