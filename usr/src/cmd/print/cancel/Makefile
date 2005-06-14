#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
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
# ident	"%Z%%M%	%I%	%E% SMI"
#
# Copyright (c) 1994 by Sun Microsystems, Inc.
# All Rights Reserved
#
# cmd/lp/client/cancel/Makefile
#

include 	../Makefile.sp

PROG=		cancel

SRCS= 		cancel.c cancel_list.c

OBJS=		$(SRCS:.c=.o)

ROOTBINPROG=	$(PROG:%=$(ROOTBIN)/%)
ROOTUSRBINSYMLINK=	$(ROOTUSRUCB)/lprm

FILEMODE=	04511
OWNER=		root

CPPFLAGS +=	-I. -I$(NPRTINC) #$(CPPFLAGS.master)
LDLIBS +=	$(LIBNPRT)

.KEEP_STATE:

all:		$(PROG)

$(PROG):	$(OBJS)
		$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
		$(POST_PROCESS)

install:	all $(ROOTBIN) $(ROOTBINPROG) $(ROOTUSRBINSYMLINK)

$(ROOTBIN):
	$(INS.dir)

$(ROOTUSRBINSYMLINK):
	$(RM) $@; $(SYMLINK) ../bin/$(PROG) $@

strip:
	$(STRIP) $(PROG)

lint:
	$(LINT.c) $(SRCS) $(LDLIBS)

cstyle:
	cstyle $(SRCS)

_msg:
	@echo "Messages are made in usr/src/cmd/print"

clean:
	$(RM) $(OBJS)

clobber: clean
	-$(RM) $(PROG) $(CLOBBERFILES)

