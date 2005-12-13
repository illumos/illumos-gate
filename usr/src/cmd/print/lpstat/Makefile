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
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# cmd/lp/client/lpstat/Makefile
#

include 	../Makefile.sp

PROG=		lpstat

SRCS= 		lpstat.c sysv-functions.c bsd-functions.c parse_bsd.c

OBJS=		$(SRCS:.c=.o)

ROOTBINPROG=	$(PROG:%=$(ROOTBIN)/%)
ROOTUSRBINSYMLINK=	$(ROOTBIN)/lpq
ROOTUSRUCBSYMLINK=	$(ROOTUSRUCB)/lpq

FILEMODE=	04511
OWNER=		root

CPPFLAGS +=	-I. -I$(NPRTINC)
LDLIBS +=	$(LIBNPRT)

.KEEP_STATE:

all:		$(PROG)

$(PROG):	$(OBJS)
		$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
		$(POST_PROCESS)

install:	all $(ROOTBIN) $(ROOTBINPROG) $(ROOTUSRBINSYMLINK) \
		$(ROOTUSRUCBSYMLINK)

$(ROOTBIN):
	$(INS.dir)

$(ROOTUSRBINSYMLINK):
	$(RM) $@; $(SYMLINK) $(PROG) $@

$(ROOTUSRUCBSYMLINK):
	$(RM) $@; $(SYMLINK) ../bin/lpq $@

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
