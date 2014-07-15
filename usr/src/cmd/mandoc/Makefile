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
# Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
# Copyright 2014 Garrett D'Amore <garrett@damore.org>
#

PROGS=		mandoc mandoc_preconv

# We place preconv in /usr/lib.  This is done to avoid conflicting with
# GNU groff, which puts it into /usr/bin.  We also rename it so that it
# will only be seen by mandoc -- it isn't intended for general end-user use.

ROOTPROGS =	$(ROOTBIN)/mandoc $(ROOTLIB)/mandoc_preconv

OBJS=		$(preconv_OBJS) $(mandoc_OBJS)

include		$(SRC)/cmd/Makefile.cmd
include		$(SRC)/cmd/mandoc/Makefile.common

.KEEP_STATE:

all:		$(PROGS)

mandoc_preconv:	$(preconv_OBJS)
		$(LINK.c) $(preconv_OBJS) -o $@ $(LDLIBS)
		$(POST_PROCESS)

mandoc:		$(mandoc_OBJS)
		$(LINK.c) $(mandoc_OBJS) -o $@ $(LDLIBS)
		$(POST_PROCESS)

clean:
		$(RM) $(OBJS)

install:	all $(ROOTPROGS)

include		$(SRC)/cmd/Makefile.targ
