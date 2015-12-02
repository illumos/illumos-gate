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
# Copyright (c) 1997-2000 by Sun Microsystems, Inc.
# All rights reserved.
#
# Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
#

include		$(SRC)/cmd/Makefile.cmd

PROG = static_prof
SRCS = $(PROG:%=../%.c)

CERRWARN +=	-_gcc=-Wno-unused-value
CERRWARN +=	-_gcc=-Wno-parentheses

LDLIBS +=	-lelf

LINTFLAGS =	-nmxsuF -errtags=yes
LINTLIBS +=	$(LDLIBS)

CLEANFILES +=	$(PROG)
CLOBBERFILES +=	$(PROG)

#
# Installed items
#
ROOTLIB_APPCERT=	$(ROOT)/usr/lib/abi/appcert
ROOTLIB_APPCERT_PROG=	$(PROG:%=$(ROOTLIB_APPCERT)/%)

