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

FSTYPE=		nfs
LIBPROG=	unshare
ATTMK=		$(LIBPROG)

include		../../Makefile.fstype

COMMON=		sharetab.o nfslogtab.o
OBJS= 		$(LIBPROG).o $(COMMON) 
SRCS=		$(LIBPROG).c ../lib/sharetab.c ../lib/nfslogtab.c

$(LIBPROG):	$(OBJS)
		$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
		$(POST_PROCESS)

sharetab.o:	../lib/sharetab.c
		$(COMPILE.c) ../lib/sharetab.c

nfslogtab.o:	../lib/nfslogtab.c
		$(COMPILE.c) ../lib/nfslogtab.c

lint:	lint_SRCS

clean:     
	$(RM) $(OBJS)
