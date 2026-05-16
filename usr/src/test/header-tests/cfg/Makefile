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
# Copyright 2015 Garrett D'Amore <garrett@damore.org>
# Copyright (c) 2012 by Delphix. All rights reserved.
#

include $(SRC)/Makefile.master

CFGS = README \
	c-symbols-env.cfg \
	c-symbols/README \
	c-symbols/assert_h.cfg \
	c-symbols/ctype_h.cfg \
	c-symbols/dirent_h.cfg \
	c-symbols/fcntl_h.cfg \
	c-symbols/locale_h.cfg \
	c-symbols/math_h.cfg \
	c-symbols/netdb_h.cfg \
	c-symbols/pthread_h.cfg \
	c-symbols/signal_h.cfg \
	c-symbols/stdalign_h.cfg \
	c-symbols/stddef_h.cfg \
	c-symbols/stdio_h.cfg \
	c-symbols/stdlib_h.cfg \
	c-symbols/stdnoreturn_h.cfg \
	c-symbols/string_h.cfg \
	c-symbols/strings_h.cfg \
	c-symbols/sys_atomic_h.cfg \
	c-symbols/sys_mman_h.cfg \
	c-symbols/sys_stat_h.cfg \
	c-symbols/sys_time_h.cfg \
	c-symbols/sys_timeb_h.cfg \
	c-symbols/time_h.cfg \
	c-symbols/threads_h.cfg \
	c-symbols/ucontext_h.cfg \
	c-symbols/unistd_h.cfg \
	c-symbols/wchar_h.cfg \
	c-symbols/wctype_h.cfg

ROOTOPTPKG = $(ROOT)/opt/header-tests
ROOTOPTPKGCFG = $(ROOT)/opt/header-tests/cfg
ROOTOPTPKGDIRS = $(ROOTOPTPKG) \
	$(ROOTOPTPKGCFG) \
	$(ROOTOPTPKGCFG)/c-symbols

FILES = $(CFGS:%=$(ROOTOPTPKGCFG)/%)
$(FILES) := FILEMODE = 0444

all: $(CFGS)

install: $(ROOTOPTPKG) $(ROOTOPTPKGCFG) $(FILES)

clean lint clobber:

$(ROOTOPTPKGDIRS):
	$(INS.dir)

$(ROOTOPTPKGCFG)/%: % $(ROOTOPTPKGDIRS)
	$(INS.file)
