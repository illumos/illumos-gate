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
# Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright (c) 2018, Joyent, Inc.

FSTYPE=		ufs
LIBPROG=	quotacheck
ATTMK=		$(LIBPROG)

OTHERINSTALL=	$(ROOTUSRSBIN)/$(LIBPROG)
LINKVALUE=	../lib/fs/$(FSTYPE)/$(LIBPROG)

include		../../Makefile.fstype
CPPFLAGS +=	-D_LARGEFILE64_SOURCE
LDLIBS	+=	-ladm
OBJS=		quotacheck.o
FSOBJS=		preenlib.o
FSSRCS=		../../preenlib.c
SRCS=		$(OBJS:.o=.c)

CERRWARN +=	-_gcc=-Wno-implicit-function-declaration
CERRWARN +=	-_gcc=-Wno-type-limits

# not linted
SMATCH=off

lint:		lint_PROG

$(FSOBJS): $(FSSRCS)
	$(COMPILE.c) -o $@ $(FSSRCS)

$(LIBPROG):	$(OBJS) $(FSOBJS)
		$(LINK.c) -o $@ $(OBJS) $(FSOBJS) $(LDLIBS)
		$(POST_PROCESS)

clean:
	-$(RM) $(OBJS) $(FSOBJS)

$(ROOTUSRSBIN)/$(LIBPROG):
		-$(RM) $@; $(SYMLINK) $(LINKVALUE) $@
