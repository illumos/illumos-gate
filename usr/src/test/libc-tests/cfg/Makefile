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
	compilation.cfg \
	symbols/README \
	symbols/ctype_h.cfg \
	symbols/dirent_h.cfg \
	symbols/fcntl_h.cfg \
	symbols/locale_h.cfg \
	symbols/math_h.cfg \
	symbols/netdb_h.cfg \
	symbols/pthread_h.cfg \
	symbols/signal_h.cfg \
	symbols/stdio_h.cfg \
	symbols/stdlib_h.cfg \
	symbols/strings_h.cfg \
	symbols/sys_stat_h.cfg \
	symbols/sys_time_h.cfg \
	symbols/sys_timeb_h.cfg \
	symbols/ucontext_h.cfg \
	symbols/unistd_h.cfg \
	symbols/wchar_h.cfg \
	symbols/wctype_h.cfg

ROOTOPTPKG = $(ROOT)/opt/libc-tests
ROOTOPTPKGCFG = $(ROOT)/opt/libc-tests/cfg
ROOTOPTPKGDIRS = $(ROOTOPTPKG) \
	$(ROOTOPTPKGCFG) \
	$(ROOTOPTPKGCFG)/symbols

FILES = $(CFGS:%=$(ROOTOPTPKGCFG)/%)
$(FILES) := FILEMODE = 0444

all: $(CFGS)

install: $(ROOTOPTPKG) $(ROOTOPTPKGCFG) $(FILES)

clean lint clobber:

$(ROOTOPTPKGDIRS):
	$(INS.dir)

$(ROOTOPTPKGCFG)/%: % $(ROOTOPTPKGDIRS)
	$(INS.file)
