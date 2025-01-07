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
# Copyright (c) 2017, Joyent, Inc.
# Copyright 2024 Oxide Computer Company
#

PROG= dltraninfo dlsend dlrecv dlled
DLTRANINFO_OBJS = dltraninfo.o $(HEXDUMP_OBJS)

include ../Makefile.cmd
include $(SRC)/common/hexdump/Makefile.com

ROOTCMDDIR = $(ROOTLIB)/dl
CFLAGS += $(CCVERBOSE)

dltraninfo :=   LDLIBS += -ldladm -lsff -lnvpair
dlled :=	LDLIBS += -ldladm
dlsend :=	LDLIBS += -ldlpi -lsocket
dlrecv :=	LDLIBS += -ldlpi

ROOTLIBDLFILES = $(PROG:%=$(ROOTLIB)/dl/%)

.KEEP_STATE:

all: $(PROG)

install: all $(ROOTCMD)

clean:
	$(RM) $(DLTRANINFO_OBJS)

dltraninfo: $(DLTRANINFO_OBJS)
	$(LINK.c) -o $@ $(DLTRANINFO_OBJS) $(LDLIBS)
	$(POST_PROCESS)

include $(SRC)/common/hexdump/Makefile.targ
include ../Makefile.targ
