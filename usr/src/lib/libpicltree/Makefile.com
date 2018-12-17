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
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright (c) 2018, Joyent, Inc.

LIBRARY=	libpicltree.a
VERS=		.1
OBJECTS=	picltree.o

include $(SRC)/lib/Makefile.lib

LIBS =		$(DYNLIB) $(LINTLIB)
LDLIBS +=	-lc
$(LINTLIB) :=	SRCS = $(SRCDIR)/$(LINTSRC)

CPPFLAGS +=	-D_REENTRANT -I.. -I../../libpicl -I$(SRC)/cmd/picl/plugins/inc
CFLAGS +=	$(CCVERBOSE)

CERRWARN +=	-_gcc=-Wno-uninitialized

# not linted
SMATCH=off

.KEEP_STATE:

all : $(LIBS)

lint: lintcheck

include $(SRC)/lib/Makefile.targ
