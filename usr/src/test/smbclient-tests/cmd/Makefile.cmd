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
# Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
# Copyright (c) 2018, Joyent, Inc.
#

include		$(SRC)/test/Makefile.com

OBJS=		$(PROG:%=%.o)

ROOTPROG=	$(PROG:%=$(ROOTBINDIR)/%)
$(ROOTPROG) :=	FILEMODE = 0555

CPPFLAGS +=	-D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64

# needs work
SMOFF += all_func_returns,leaks

all:		$(PROG)

$(PROG):	$(OBJS)
		$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
		$(POST_PROCESS)

%.o:		%.c
		$(COMPILE.c) $<
		$(POST_PROCESS_O)

install:	all $(ROOTPROG)

clobber:	clean
		-$(RM) $(PROG)

clean:
		-$(RM) $(OBJS)

$(ROOTPROG):	$(ROOTBINDIR) $(PROG)

$(ROOTBINDIR):
		$(INS.dir)

$(ROOTBINDIR)/%: %
		$(INS.file)
