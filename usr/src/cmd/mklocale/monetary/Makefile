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

CATEGORY=LC_MONETARY

include ../Makefile.common

en_AU =		en_AU.ISO8859-1 en_AU.ISO8859-15 en_AU.US-ASCII en_AU.UTF-8
en_CA =		en_CA.ISO8859-1 en_CA.ISO8859-15 en_CA.US-ASCII en_CA.UTF-8
en_GB =		en_GB.ISO8859-1 en_GB.ISO8859-15 en_GB.US-ASCII en_GB.UTF-8
en_IE =		en_IE.UTF-8
en_NZ =		en_NZ.ISO8859-1 en_NZ.ISO8859-15 en_NZ.US-ASCII en_NZ.UTF-8
en_US =		en_US.ISO8859-1 en_US.ISO8859-15 en_US.US-ASCII en_US.UTF-8

.KEEP_STATE:

all: $(MACH) .WAIT $(MACHLOCALES)

clean:
	$(RM) $(OBJS) $(CLEANFILES)
	$(RM) -r $(MACH)

lint:
check:

#
# Rules for building encoding data files.
#

$(en_AU:%=$(MACH)/%):	data/en_AU.src
	$(RM) $@; $(HASHSTRIP) data/en_AU.src > $@

$(en_CA:%=$(MACH)/%):	data/en_CA.src
	$(RM) $@; $(HASHSTRIP) data/en_CA.src > $@

$(en_NZ:%=$(MACH)/%):	data/en_NZ.src
	$(RM) $@; $(HASHSTRIP) data/en_NZ.src > $@

$(en_US:%=$(MACH)/%):	data/en_US.src
	$(RM) $@; $(HASHSTRIP) data/en_US.src > $@

$(MACH)/en_IE.UTF-8:	data/en_IE.UTF-8.src
	$(RM) $@; $(HASHSTRIP) data/en_IE.UTF-8.src > $@

$(MACH)/en_GB.UTF-8:	data/en_GB.UTF-8.src
	$(RM) $@; $(HASHSTRIP) data/en_GB.UTF-8.src > $@

$(MACH)/en_GB.ISO8859-1 $(MACH)/en_GB.ISO8859-15:	data/en_GB.LATIN.src
	$(RM) $@; $(HASHSTRIP) data/en_GB.LATIN.src > $@

$(MACH)/en_GB.US-ASCII	data/en_GB.ASCII.src:
	$(RM) $@; $(HASHSTRIP) data/en_GB.ASCII.src > $@

include ../Makefile.targ
