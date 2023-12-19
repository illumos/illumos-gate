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
# Copyright 2018 Nexenta Systems, Inc.
# Copyright 2023 Bill Sommerfeld <sommerfeld@hamachi.org>
#

include		$(SRC)/Makefile.master

ROOTOPTPKG=	$(ROOT)/opt/libc-tests
TESTDIR=	$(ROOTOPTPKG)/tests/regex
DATADIR=	$(TESTDIR)/data

PROG=		testregex

SHPROG=		regex_test

DATA=		basic.dat basic.out \
		bug16127.dat bug16127.out \
		categorize.dat categorize.out \
		forcedassoc.dat forcedassoc.out \
		leftassoc.dat leftassoc.out \
		nullsubexpr.dat nullsubexpr.out \
		repetition.dat repetition.out \
		rightassoc.dat rightassoc.out

include		$(SRC)/cmd/Makefile.cmd

CERRWARN +=	-_gcc=-Wno-parentheses
CERRWARN +=	$(CNOWARN_UNINIT)
CERRWARN +=	-_gcc=-Wno-clobbered

# needs work
SMOFF += all_func_returns,testing_index_after_use

CMDS=		$(PROG:%=$(TESTDIR)/%) $(SHPROG:%=$(TESTDIR)/%)
$(CMDS):=	FILEMODE=0555
TESTDATA=	$(DATA:%=$(DATADIR)/%)
$(TESTDATA):=	FILEMODE=0444

.KEEP_STATE:

all:		$(PROG)

$(CMDS):	$(TESTDIR)

$(TESTDATA):	$(DATADIR)

install:	all $(CMDS) $(TESTDATA)

clean lint:

$(TESTDIR) $(DATADIR):
		$(INS.dir)

$(TESTDIR)/%:	%
		$(INS.file)

$(TESTDIR)/%:	%.sh
		$(INS.rename)

$(DATADIR)/%:	data/%
		$(INS.file)

include		$(SRC)/cmd/Makefile.targ
