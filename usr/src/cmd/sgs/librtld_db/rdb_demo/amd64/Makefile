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

include		../Makefile.com

CPPFLAGS +=	-D_SYSCALL32

# DEMO DELETE START
CCVERBOSE=

LDFLAGS=	-L ../../$(MACH64) \
		-L ../../../libelf/$(MACH64)

LINTFLAGS64 +=	$(VAR_LIBRTLD_DB_LINTFLAGS64)
# DEMO DELETE END

DEMOCFLAGS=	-xarch=generic64

.KEEP_STATE:

all:		$(OBJDIR) .WAIT $(PROG)

test: $(TESTS)


# DEMO DELETE START
DEMOCFLAGS=

install:	all $(ROOTONLDBINPROG64)

lint:		$(LINTOUT)
# DEMO DELETE END

include		../Makefile.targ

$(OBJDIR)/%.o:	../i386/%.c
		$(COMPILE.c) $< -o $@
		$(POST_PROCESS_O)


# DEMO DELETE START
include		../../../../../Makefile.master.64
# DEMO DELETE END
