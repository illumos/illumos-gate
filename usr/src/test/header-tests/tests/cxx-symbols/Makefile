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
# Copyright 2014 Garrett D'Amore <garrett@damore.org>
# Copyright 2018, Joyent, Inc.
# Copyright 2026 Gordon W. Ross
#

include $(SRC)/Makefile.master

TESTSUBDIR = cxx-symbols

include ../Makefile.com

KSHPROG = setup

LINKS = \
	cmath_h \
	cstdio_h \
	cstdlib_h \
	cstring_h \
	ctime_h \
	cwchar_h

CMDS =	$(LINKS:%=$(TESTDIR)/%) \
	$(KSHPROG:%=$(TESTDIR)/%)

all: $(KSHPROG)

install:  $(TESTDIR) $(CMDS)

clobber: clean
	-$(RM) $(KSHPROG)

clean:

$(KSHPROG): $(KSHPROG).ksh
	$(RM) $@
	$(CP) $(KSHPROG).ksh $(@)
	$(CHMOD) +x $@

$(LINKS:%=$(TESTDIR)/%): $(TESTDIR)/setup
	-$(RM) $@
	$(LN) $(TESTDIR)/setup $@
