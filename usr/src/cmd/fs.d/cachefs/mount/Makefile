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
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# cmd/fs.d/cachefs/mount
#

FSTYPE=		cachefs
LIBPROG=	mount
ATTMK=		$(LIBPROG)

include		../../Makefile.fstype

PROGOBJS=	mount.o $(FSLIB)

include		../Makefile.cachefs

CPPFLAGS +=	-D_LARGEFILE64_SOURCE -I../..
LDLIBS +=	-lnsl -lkstat

#
# uncomment to use cachefs pass through with NFSv3 (for debugging)
#
#CFLAGS +=	-DCFS_NFSV3_PASSTHROUGH

$(LIBPROG) :	$(CFSLIB)

$(PROGOBJS) :	$(CACHEFSDIR)/subr.h $(CACHEFSDIR)/cachefsd.h
