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
# Copyright (c) 1998, 2010, Oracle and/or its affiliates. All rights reserved.
# Copyright 2019 OmniOS Community Edition (OmniOSce) Association.
#

include		../Makefile.com

CPPFLAGS +=	-D_SYSCALL32

# DEMO DELETE START
CCVERBOSE=

LDFLAGS=	-L ../../$(MACH64) \
		-L ../../../libelf/$(MACH64)

# DEMO DELETE END

# Change -m64 to -xarch=generic64 for use with older Sun compilers.
DEMOCFLAGS=	-m64

.KEEP_STATE:

all:		$(OBJDIR) .WAIT $(PROG)

test:		$(TESTS)

# DEMO DELETE START
DEMOCFLAGS=

catalog:

install:	all $(ROOTONLDBINPROG64)
# DEMO DELETE END

include		../Makefile.targ

# DEMO DELETE START
include		../../../../../Makefile.master.64
# DEMO DELETE END
