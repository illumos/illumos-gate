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
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

PROG=	abi_audit
OBJS=	abi_audit.o util.o verschk.o
SRCS=	$(OBJS:%.o=%.c)
CLEANFILES=	$(OBJS)
CLOBBERFILES+=	$(PROG)

include $(SRC)/tools/Makefile.tools

CPPFLAGS	+=	$(CCVERBOSE)

.KEEP_STATE:

all: $(PROG)

install: all .WAIT $(ROOTONBLDMACHPROG)

$(PROG):	$(OBJS)
	$(LINK.c) $(LDLIBS) $(OBJS) -o $@
	$(POST_PROCESS)

clean:
	$(RM) $(CLEANFILES)

lint:	lint_SRCS

include $(SRC)/tools/Makefile.targ
