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

include $(SRC)/lib/Makefile.lib

SUBDIRS = $(MACH) $(BUILD64) $(MACH64)

HDRS = libppt.h
HDRDIR = common

ETCFILES=	ppt_matches
ROOTETC=	$(ROOT)/etc
IETCFILES=	$(ETCFILES:%=$(ROOTETC)/%)

$(IETCFILES) :=	FILEMODE = 0444

all :=		TARGET= all
clean :=	TARGET= clean
clobber :=	TARGET= clobber
install :=	TARGET= install

.KEEP_STATE:

all clean clobber install: $(SUBDIRS)

install_h: $(ROOTHDRS)

all install: install_h

install: $(IETCFILES)

check: $(CHECKHDRS)

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

$(ROOTETC)/%:	%
	$(INS.file)

FRC:

include	$(SRC)/lib/Makefile.targ
