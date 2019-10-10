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
# Copyright (c) 2012 by Delphix. All rights reserved.
# Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
# Copyright 2019 Joyent, Inc.
#

include $(SRC)/Makefile.master
include $(SRC)/test/Makefile.com

ROOTOPTPKG = $(ROOT)/opt/crypto-tests
ROOTAES = $(ROOTOPTPKG)/tests/aes/kcf
ROOTDIGEST = $(ROOTOPTPKG)/tests/digest/kcf
ROOTHMAC = $(ROOTOPTPKG)/tests/hmac/kcf

ROOTDIRS = $(ROOTAES) $(ROOTDIGEST) $(ROOTHMAC)

PROGS = cleanup setup

CMDS = \
	$(PROGS:%=$(ROOTAES)/%)  \
	$(PROGS:%=$(ROOTDIGEST)/%) \
	$(PROGS:%=$(ROOTHMAC)/%)

$(CMDS) := FILEMODE = 0555

all lint clean clobber:

install: $(CMDS)

$(CMDS): $(ROOTDIRS)

$(ROOTDIRS):
	$(INS.dir)

$(ROOTAES)/%: %.ksh
	$(INS.rename)
$(ROOTDIGEST)/%: %.ksh
	$(INS.rename)
$(ROOTHMAC)/%: %.ksh
	$(INS.rename)

