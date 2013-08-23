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
# Copyright (c) 1989,1996 by Sun Microsystems, Inc.
# All rights reserved.
#

FSTYPE=		ufs
LIBPROG=	ff
ATTMK=		$(LIBPROG)

include		../../Makefile.fstype
include		../Makefile.roll

OBJS=           $(LIBPROG).o $(ROLLOBJS)
SRCS=           $(LIBPROG).c $(ROLLSRCS)

# No msg catalog here.
POFILE=

CPPFLAGS +=	-D_LARGEFILE64_SOURCE

CERRWARN +=	-_gcc=-Wno-uninitialized

$(LIBPROG):	$(OBJS)
		$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
		$(POST_PROCESS)

clean:
		$(RM) $(LIBPROG).o

lint:		lint_SRCS
