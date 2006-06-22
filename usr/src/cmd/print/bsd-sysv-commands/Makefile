#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#
#
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

UCBPROGS =	lpr lpq lprm lpc
BINPROGS =	lp lpstat cancel enable disable $(UCBPROGS)

SBINPROGS =	accept reject lpmove


OBJS =	$(BINPROGS:=.o) $(SBINPROGS:=.o) common.o

ROOTBINPROGS =		$(BINPROGS:%=$(ROOTBIN)/%)
ROOTUSRSBINPROGS =	$(SBINPROGS:%=$(ROOTUSRSBIN)/%)


FILEMODE =	0555
OWNER =		root

include ../../Makefile.cmd

CFLAGS +=	$(CCVERBOSE)
CPPFLAGS +=	-I.
CPPFLAGS +=	-I../../../lib/print/libpapi-common/common
LDLIBS +=	-lpapi -lc

#	each program needs common.o as well
$(BINPROGS) $(SBINPROGS):	$(BINPROGS:%=%.c) $(SBINPROGS:%=%.c) common.o
	$(LINK.c) -o $@ $@.c common.o $(LDLIBS)
	$(POST_PROCESS)

#	ucb links (lptest is handled in usr/src/cmd/lp/cmd/Makefile)
ROOTUSRUCB =		$(ROOT)/usr/ucb
ROOTUCBSYMLINKS =	$(UCBPROGS:%=$(ROOTUSRUCB)/%)
$(ROOTUSRUCB)/%:	$(ROOTUSRUCB) %

$(ROOTUCBSYMLINKS):	
	$(RM) $@; $(SYMLINK) ../bin/$(@F) $@

#	usr/lib links
ROOTUSRLIBSYMLINKS =	$(SBINPROGS:%=$(ROOTLIB)/%)
$(ROOTLIB)/%:	$(ROOTLIB) %

$(ROOTUSRLIBSYMLINKS):	
	$(RM) $@; $(SYMLINK) ../sbin/$(@F) $@

.KEEP_STATE:

all:	$(BINPROGS) $(SBINPROGS)

install:	$(BINPROGS) $(SBINPROGS) $(ROOTBINPROGS) $(ROOTUSRSBINPROGS) \
		$(ROOTUCBSYMLINKS) $(ROOTUSRLIBSYMLINKS)

clean:
	$(RM) $(OBJS) 

CLOBBERFILES += $(BINPROGS) $(SBINPROGS)

lint:

include ../../Makefile.targ
