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
# Copyright 2017 Nexenta Systems, Inc.
# Copyright 2011 EveryCity Ltd. All rights reserved.
# Copyright 2013 DEY Storage Systems, Inc.
# Copyright 2016 Joyent, Inc.
#

CMDDIR=		$(SRC)/cmd/localedef

include		$(SRC)/tools/Makefile.tools
include		$(CMDDIR)/Makefile.common

OBJS +=		avl.o \
		mkdirp.o

CPPFLAGS +=	-I$(CMDDIR) -I.

.KEEP_STATE:

all:		$(PROG)

parser.tab.c parser.tab.h: $(CMDDIR)/parser.y $(CMDDIR)/localedef.h
		$(YACC) $(YFLAGS) $(CMDDIR)/parser.y

$(OBJS):	parser.tab.h

$(PROG):	$(OBJS)
		$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
		$(POST_PROCESS)

%.o:		$(CMDDIR)/%.c
		$(COMPILE.c) -o $@ $<

avl.o:		$(SRC)/common/avl/avl.c
		$(COMPILE.c) -o $@ $(SRC)/common/avl/avl.c

mkdirp.o:	$(SRC)/lib/libgen/common/mkdirp.c
		$(COMPILE.c) -o $@ $(SRC)/lib/libgen/common/mkdirp.c

install:	all $(ROOTONBLDMACHPROG)

clean:
		$(RM) $(PROG) $(CLEANFILES)

include		$(SRC)/tools/Makefile.targ
