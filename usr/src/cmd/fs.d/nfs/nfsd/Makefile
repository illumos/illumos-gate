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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

FSTYPE=		nfs
TYPEPROG=	nfsd
ATTMK=		$(TYPEPROG)

include		../../Makefile.fstype

LDLIBS +=	-lnsl -lnvpair

LOCAL=		nfsd.o
OBJS=		$(LOCAL) nfs_tbind.o thrpool.o daemon.o
SRCS=		$(LOCAL:%.o=%.c) ../lib/nfs_tbind.c ../lib/thrpool.c ../lib/daemon.c
CPPFLAGS +=	-I../lib

$(TYPEPROG):	$(OBJS)
		$(CC) -o $@ $(OBJS) $(LDFLAGS) $(LDLIBS)
		$(POST_PROCESS)

nfs_tbind.o:	../lib/nfs_tbind.c
		$(COMPILE.c) ../lib/nfs_tbind.c

thrpool.o:	../lib/thrpool.c
		$(COMPILE.c) ../lib/thrpool.c

daemon.o:	../lib/daemon.c
		$(COMPILE.c) ../lib/daemon.c

clean:
		$(RM) $(OBJS)

lint:		$(SRCS) lint_SRCS
