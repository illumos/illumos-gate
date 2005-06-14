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
#ident	"%Z%%M%	%I%	%E% SMI"
#
# Copyright (c) 1997 by Sun Microsystems, Inc.
#
# Copyright (c) 1989,1996 by Sun Microsystems, Inc.
# All rights reserved.
#
# cmd/fs.d/ufs/fsck/Makefile

FSTYPE=		ufs
LIBPROG=	fsck
ATTMK=		$(LIBPROG)

include		../../Makefile.fstype
include		../Makefile.roll

FSCKOBJS=	main.o dir.o inode.o pass1.o pass1b.o pass2.o \
		pass3.o pass3b.o pass4.o pass5.o setup.o \
		utilities.o
FSCKSRCS=	$(FSCKOBJS:%.o=%.c)

UFSDIR=		../../../../uts/common/fs/ufs
UFSOBJS=	ufs_subr.o ufs_tables.o
UFSSRCS=	$(UFSOBJS:%.o=%.c)
ROLLDIR=	../roll_log

OBJS=		$(FSCKOBJS) $(UFSOBJS) $(ROLLOBJS)
SRCS=		$(FSCKSRCS) $(UFSSRCS) $(ROLLSRCS)

CPPFLAGS +=	-D_LARGEFILE64_SOURCE
$(LIBPROG):	$(OBJS)
		$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
		$(POST_PROCESS)

%.o:	$(UFSDIR)/%.c
	$(COMPILE.c) $<

lint:	lint_SRCS

clean:     
	$(RM) $(FSCKOBJS) $(UFSOBJS)
