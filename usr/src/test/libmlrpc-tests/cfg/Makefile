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
# Copyright 2019 Joyent, Inc.
# Copyright 2020 Tintri by DDN, Inc. All rights reserved.
#

include $(SRC)/Makefile.master

CFGS = samlogon.config krb5_pac.config
ROOTOPTPKG = $(ROOT)/opt/libmlrpc-tests
ROOTOPTPKGCFG = $(ROOT)/opt/libmlrpc-tests/cfg
ROOTOPTPKGDIRS = $(ROOTOPTPKG) $(ROOTOPTPKGCFG)
FILES = $(CFGS:%=$(ROOTOPTPKGCFG)/%)
$(FILES) := FILEMODE = 0644

include $(SRC)/test/Makefile.com

all: $(CFGS)

install: $(ROOTOPTPKG) $(ROOTOPTPKGCFG) $(FILES)

clobber: clean
	$(RM) $(FILES)

$(ROOTOPTPKGDIRS):
	$(INS.dir)

$(ROOTOPTPKGCFG)/%: % $(ROOTOPTPKGDIRS)
	$(INS.file)
