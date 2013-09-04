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
# Copyright (c) 1998 by Sun Microsystems, Inc.
# All rights reserved.
#

FSTYPE=		pcfs
LIBPROG=	mkfs
ATTMK=		$(LIBPROG)

include		../../Makefile.fstype

OBJS=		$(LIBPROG).o
SRCS=		$(LIBPROG).c

# for messaging catalog
#
POFILE= mkfs.po

catalog:        $(POFILE)

CPPFLAGS +=	-D_LARGEFILE64_SOURCE
CERRWARN +=	-_gcc=-Wno-parentheses

$(LIBPROG):	$(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

lint:		lint_SRCS

clean:
	$(RM) $(OBJS)
