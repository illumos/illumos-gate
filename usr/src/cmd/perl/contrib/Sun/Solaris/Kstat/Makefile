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
#

MODULE = Kstat

include $(SRC)/cmd/perl/Makefile.perl

LDLIBS += -lkstat

CERRWARN += -_gcc=-Wno-unused-value
CERRWARN += -_gcc=-Wno-unused-variable

MAPFILES = mapfile-vers

include $(SRC)/cmd/perl/Makefile.targ

.KEEP_STATE:

all: $(PERLEXT) $(PERLMOD)

install: $(ROOTPERLEXT) $(ROOTPERLMOD)

clean clobber:
	$(RM) -r $(MACH)
