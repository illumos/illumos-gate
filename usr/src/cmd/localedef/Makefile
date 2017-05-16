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
# Copyright 2017 RackTop Systems.
#

include		$(SRC)/cmd/Makefile.cmd
include		$(SRC)/cmd/Makefile.ctf
include		$(SRC)/cmd/localedef/Makefile.common

LDLIBS +=	-lavl -lgen

.KEEP_STATE:

all:		$(PROG)

parser.tab.c parser.tab.h: parser.y localedef.h
		$(YACC) $(YFLAGS) parser.y

$(OBJS):	parser.tab.h

$(PROG):	$(OBJS)
		$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
		$(POST_PROCESS)

$(POFILE):	$(PIFILES)
		$(RM) $@
		$(RM) messages.po
		$(XGETTEXT) -s $(PIFILES)
		$(SED) -e '/domain/d' messages.po > $@
		$(RM) $(PIFILES) messages.po

install:	all $(ROOTPROG)

lint:		lint_SRCS

clean:
		$(RM) $(CLEANFILES)

include		$(SRC)/cmd/Makefile.targ
