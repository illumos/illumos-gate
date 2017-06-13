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
#

include		$(SRC)/Makefile.master

ROOTOPTPKG=	$(ROOT)/opt/libc-tests
TESTDIR=	$(ROOTOPTPKG)/tests/regex
DATADIR=	$(TESTDIR)/data

PROG=		h_regex
OBJS=		main.o \
		split.o

SHPROG=		t_regex

DATA=		anchor.in \
		backref.in \
		basic.in \
		bracket.in \
		c_comments.in \
		complex.in \
		error.in \
		meta.in \
		nospec.in \
		paren.in \
		regress.in \
		repet_bounded.in \
		repet_multi.in \
		repet_ordinary.in \
		startend.in \
		subexp.in \
		subtle.in \
		word_bound.in \
		zero.in

include		$(SRC)/cmd/Makefile.cmd

CMDS=		$(PROG:%=$(TESTDIR)/%) $(SHPROG:%=$(TESTDIR)/%)
$(CMDS):=	FILEMODE=0555
TESTDATA=	$(DATA:%=$(DATADIR)/%)
$(TESTDATA):=	FILEMODE=0444

CPPFLAGS +=	-I$(SRC)/lib/libc/port/regex

.KEEP_STATE:

all:		$(PROG)

$(PROG):	$(OBJS)
		$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
		$(POST_PROCESS)

$(CMDS):	$(TESTDIR)

$(TESTDATA):	$(DATADIR)

install:	all $(CMDS) $(TESTDATA)

clean:
		$(RM) $(OBJS)

lint:

$(TESTDIR) $(DATADIR):
		$(INS.dir)

$(TESTDIR)/%:	%
		$(INS.file)

$(TESTDIR)/%:	%.sh
		$(INS.rename)

$(DATADIR)/%:	data/%
		$(INS.file)

include		$(SRC)/cmd/Makefile.targ
