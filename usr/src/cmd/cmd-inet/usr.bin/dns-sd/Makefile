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
# Copyright 2016 Toomas Soome <tsoome@me.com>
#

# cmd/cmd-inet/usr.bin/dns-sd/Makefile

PROG=		dns-sd

include ../../../Makefile.cmd
include ../../Makefile.cmd-inet

OBJS=		ClientCommon.o dns-sd.o
SRCS=		ClientCommon.c dns-sd.c

CFLAGS += $(C99_ENABLE)
CPPFLAGS += -DMDNS_VERSIONSTR_NODTS
LDLIBS += -lsocket -ldns_sd

.KEEP_STATE:

all: $(PROG)

ROOTPROG=   $(PROG:%=$(ROOTBIN)/%)

$(PROG): $(OBJS)
	$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

install: all $(ROOTPROG)

clean:
	$(RM) $(OBJS)

lint:  lint_SRCS

include ../../../Makefile.targ
