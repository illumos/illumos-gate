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
# Copyright (c) 1999,2001 by Sun Microsystems, Inc.
# All rights reserved.
#
# Copyright (c) 2018, Joyent, Inc.

FSTYPE=		udfs
LIBPROG=	mkfs
ATTMK=		$(LIBPROG)

include		../../Makefile.fstype

# for messaging catalog
#
POFILE= mkfs.po

catalog:        $(POFILE)


LDLIBS += -ladm

MKFSOBJS=	mkfs.o udfslib.o

UDFSDIR=	../../../../uts/common/fs/ufs
#UDFSOBJS=	ufs_subr.o ufs_tables.o
UDFSOBJS=

CERRWARN +=	-_gcc=-Wno-parentheses
CERRWARN +=	-_gcc=-Wno-uninitialized

# not linted
SMATCH=off

OBJS=		$(MKFSOBJS) $(UDFSOBJS)
SRCS=		$(OBJS:%.o=%.c)

$(LIBPROG):	$(OBJS)
		$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
		$(POST_PROCESS)

%.o:	$(UDFSDIR)/%.c
	$(COMPILE.c) $<

lint:
	$(LINT.c) -mu $(SRCS)

clean:     
	$(RM) $(OBJS)

putback:
	-cstyle -p mkfs.c
	-cstyle -p udfslib.c
	-keywords mkfs.c
	-keywords udfslib.c
	-keywords Makefile
