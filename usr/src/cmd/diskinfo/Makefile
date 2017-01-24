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
# Copyright 2016 Nexenta Systems, Inc.
#

PROG=		diskinfo
OBJS=		diskinfo.o
SRCS=		$(OBJS:%.o=%.c)

include		$(SRC)/cmd/Makefile.cmd
include		$(SRC)/cmd/Makefile.ctf

C99MODE=	$(C99_ENABLE)

CPPFLAGS +=	-I$(SRC)/lib/fm/topo

LDLIBS +=	-L$(ROOT)/usr/lib/fm -R/usr/lib/fm -ldiskmgt -lnvpair -ltopo

.KEEP_STATE:

all:		$(PROG)

$(PROG):	$(OBJS)
		$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
		$(POST_PROCESS)

clean:
		$(RM) $(OBJS)

install:	all $(ROOTPROG)

include		$(SRC)/cmd/Makefile.targ
