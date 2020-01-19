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
#

include $(SRC)/Makefile.master

TESTSUBDIR = symbols
PROG = symbols_test
KSHPROG = setup
SYMTESTS = \
	assert_h \
	ctype_h \
	dirent_h \
	fcntl_h \
	locale_h \
	math_h \
	netdb_h \
	pthread_h \
	stdalign_h \
	stddef_h \
	signal_h \
	stdio_h \
	stdlib_h \
	stdnoreturn_h \
	string_h \
	strings_h \
	sys_stat_h \
	sys_time_h \
	sys_timeb_h \
	time_h \
	threads_h \
	ucontext_h \
	unistd_h \
	wchar_h \
	wctype_h

EXTRAPROG += $(SYMTESTS)

include ../Makefile.com

LDLIBS += -lcustr
LDLIBS64 += -lcustr

$(SYMTESTS:%=$(TESTDIR)/%): $(TESTDIR)/setup
	-$(RM) $@
	$(LN) $(TESTDIR)/setup $@
