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
# Copyright 2010 Nexenta Systems, Inc.  All rights reserved.
#
PROG=		od
XPG4PROG=	$(PROG)

OBJS=		od.o
SRCS=	 	$(OBJS:%.o=%.c)

include ../Makefile.cmd

CLOBBERFILES=	$(PROG)


CSTD=	$(CSTD_GNU99)
C99LMODE=	-Xc99=%all
CPPFLAGS +=	-D__EXTENSIONS__ -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64
LINTFLAGS +=	-D__EXTENSIONS__

# install rules
$(ROOTINC)/% : %
	$(INS.file)

.KEEP_STATE:

.PARALLEL: $(OBJS)

all:		$(PROG) 

$(PROG):	$(OBJS)
	$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

install: all .WAIT $(ROOTPROG) $(ROOTXPG4PROG)

$(ROOTXPG4PROG):
	-$(RM) $@
	-$(LN) -s ../../bin/$(PROG) $@

lint: 	lint_SRCS

clean:
	$(RM) $(OBJS)

include ../Makefile.targ
