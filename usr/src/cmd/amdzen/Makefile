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
# Copyright 2026 Oxide Computer Company
#

PROG= usmn udf

include ../Makefile.cmd

ROOTCMDDIR = $(ROOTLIB)
CPPFLAGS += -I$(SRC)/uts/intel/io/amdzen
CFLAGS += $(CCVERBOSE)
CSTD = $(CSTD_GNU17)
COMMON_OBJS = amdzen_common.o
LDLIBS += -ldevinfo

.KEEP_STATE:

all: $(PROG)

$(PROG): $(COMMON_OBJS)

%: %.o
	$(LINK.c) -o $@ $< $(COMMON_OBJS) $(LDLIBS)
	$(POST_PROCESS)

install: all $(ROOTCMD)

clean:
	$(RM) $(COMMON_OBJS) $(PROG:%=%.o)

include ../Makefile.targ
