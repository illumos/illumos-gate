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
# Copyright (c) 2014 Racktop Systems.
# Copyright 2014, OmniTI Computer Consulting, Inc. All rights reserved.
#

MODULE = _BSMparse

include $(SRC)/cmd/perl/Makefile.perl

# Install module into arch independent directory
ROOTPERLMODDIR = $(ROOTPERLDIR)/lib/Sun/Solaris/BSM

include $(SRC)/cmd/perl/Makefile.targ

.KEEP_STATE:

all: $(PERLMOD)

install: $(ROOTPERLMOD)

clean clobber:
	$(RM) -r $(MACH) $(MACH64)
