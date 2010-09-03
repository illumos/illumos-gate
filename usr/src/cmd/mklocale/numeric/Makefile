#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy is of the CDDL is also available via the Internet
# at http://www.illumos.org/license/CDDL.
#

#
# Copyright 2010 Nexenta Systems, Inc.  All rights reserved.
#

CATEGORY=LC_NUMERIC

include ../Makefile.common

en_COMMON =	en_AU en_CA en_GB en_NZ en_US

en_ASCII =	$(en_COMMON:%=%.US-ASCII)
en_LATIN1 =	$(en_COMMON:%=%.ISO8859-1)
en_LATIN15 =	$(en_COMMON:%=%.ISO8859-15)
en_UTF8 =	$(en_COMMON:%=%.UTF-8) en_IE.UTF-8
en_LOCALES =	$(en_ASCII) $(en_LATIN1) $(en_LATIN15) $(en_UTF8)

.KEEP_STATE:

all: $(MACH) .WAIT $(MACHLOCALES)

$(ASCII:%=$(MACH)/%):	$(MACH)/US-ASCII
	$(RM) $@
	$(LN) $(MACH)/US-ASCII $@

$(en_LOCALES:%=$(MACH)/%):	$(MACH)/en
	$(RM) $@
	$(LN) $(MACH)/en $@

clean:
	$(RM) $(OBJS) $(CLEANFILES)
	$(RM) -r $(MACH)

lint:
check:


#
# Rules for building encoding data files.
#
$(MACH)/%:	data/%.src $(MACH)
	$(INS.nohash)

include ../Makefile.targ
