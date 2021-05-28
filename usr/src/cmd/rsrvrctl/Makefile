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
# Copyright 2021 Oxide Computer Company
#

PROG =		rsrvrctl

include ../Makefile.cmd
include ../Makefile.cmd.64
include ../Makefile.ctf

SRCS =		rsrvrctl.c
OBJS =		$(SRCS:.c=.o)

CLEANFILES =	$(PROG)
CLOBBERFILES +=	$(ROOTUSRSBINPROG)

.KEEP_STATE:

CFLAGS +=	$(CCVERBOSE)
CPPFLAGS =	-I$(COMPAT)/bhyve -I$(CONTRIB)/bhyve \
		-I$(COMPAT)/bhyve/amd64 -I$(CONTRIB)/bhyve/amd64 \
		$(CPPFLAGS.master) \
		-I$(SRC)/uts/i86pc/io/vmm \
		-I$(SRC)/uts/i86pc

all: $(PROG)

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDFLAGS) $(LDLIBS)
	$(POST_PROCESS)

install: all $(ROOTLIBPROG)

clean:
	$(RM) $(OBJS) $(CLEANFILES)

include ../Makefile.targ
