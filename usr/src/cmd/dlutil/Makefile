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
#

PROG= dltraninfo dlsend dlrecv dlled
LINTPROGS= $(PROG:%=%.ln)

include ../Makefile.cmd

ROOTCMDDIR = $(ROOTLIB)/dl
CFLAGS += $(CCVERBOSE)

dltraninfo :=   LDLIBS += -ldladm -lsff -lnvpair
dlled :=	LDLIBS += -ldladm
dlsend :=	LDLIBS += -ldlpi -lsocket
dlrecv :=	LDLIBS += -ldlpi

dltraninfo.ln :=   LDLIBS += -ldladm -lsff -lnvpair
dlled.ln :=	LDLIBS += -ldladm
dlsend.ln :=	LDLIBS += -ldlpi -lsocket
dlrecv.ln :=	LDLIBS += -ldlpi

ROOTLIBDLFILES = $(PROG:%=$(ROOTLIB)/dl/%)

.KEEP_STATE:

all: $(PROG)

install: all $(ROOTCMD)

clean:

%.ln: %.c
	$(LINT.c) $< $(LDLIBS)

lint:	$(LINTPROGS)

include ../Makefile.targ
