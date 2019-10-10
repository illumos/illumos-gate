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
#

include		$(SRC)/Makefile.master
include		../Makefile.com

PROGS=		smartos-test
FILES=		README

ROOTOPTPKG = $(ROOT)/opt/smartos-test
ROOTBIN = $(ROOTOPTPKG)/bin

ROOTPROGS=	$(PROGS:%=$(ROOTBIN)/%)
$(ROOTPROGS) :=	FILEMODE = 0555

ROOTFILES=	$(FILES:%=$(ROOTOPTPKG)/%)
$(ROOTFILES) := FILEMODE = 0444

all clean clobber:

install:	$(ROOTPROGS) $(ROOTFILES)

$(ROOTPROGS):	$(ROOTBIN)

$(ROOTFILES):	$(ROOTOPTPKG)

$(ROOTBIN):
		$(INS.dir)

$(ROOTOPTPKG):
		$(INS.dir)

$(ROOTOPTPKG)/%: %
		$(INS.file)

$(ROOTBIN)/%: %.sh
		$(INS.rename)
