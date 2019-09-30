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
# Copyright 2014, OmniTI Computer Consulting, Inc. All rights reserved.
# Copyright 2016 RackTop Systems.
#

MODULE = Task

include $(SRC)/cmd/perl/Makefile.perl

XSUBPPFLAGS = -typemap typemap

MAPFILES = mapfile-vers

include $(SRC)/cmd/perl/Makefile.targ

.KEEP_STATE:

$(BUILDPERL32)all: $(PERLEXT) $(PERLMOD)
$(BUILDPERL64)all: $(PERLEXT64) $(PERLMOD)

$(BUILDPERL32)install: $(ROOTPERLEXT) $(ROOTPERLMOD)
$(BUILDPERL64)install: $(ROOTPERLEXT64) $(ROOTPERLMOD64)

clean clobber:
	$(RM) -r $(MACH) $(MACH64)
