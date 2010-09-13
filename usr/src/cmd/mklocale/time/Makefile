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

CATEGORY=LC_TIME

include ../Makefile.common

# Apparently only the US uses month/day/year.  Other English speaking
# countries place day/month/year.
en_GB = en_AU.ISO8859-1 en_AU.ISO8859-15 en_AU.US-ASCII en_AU.UTF-8 \
	en_CA.ISO8859-1 en_CA.ISO8859-15 en_CA.US-ASCII en_CA.UTF-8 \
	en_GB.ISO8859-1 en_GB.ISO8859-15 en_GB.US-ASCII en_GB.UTF-8 \
	en_IE.UTF-8 \
	en_NZ.ISO8859-1 en_NZ.ISO8859-15 en_NZ.US-ASCII en_NZ.UTF-8
en_US =	en_US.ISO8859-1 en_US.ISO8859-15 en_US.US-ASCII en_US.UTF-8

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

$(en_GB:%=$(MACH)/%):	data/en_GB.src
	$(RM) $@; $(HASHSTRIP) data/en_GB.src > $@

$(en_US:%=$(MACH)/%):	data/en_US.src
	$(RM) $@; $(HASHSTRIP) data/en_US.src > $@

include ../Makefile.targ
