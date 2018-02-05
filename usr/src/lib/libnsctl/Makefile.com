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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# lib/libnsctl/Makefile.com

LIBRARY= libnsctl.a
VERS= .1

OBJECTS= cache.o machdep.o hash.o

# include library definitions
include ../../Makefile.lib

LIBS=		$(DYNLIB) $(LINTLIB)

SRCDIR=	../common

INCS += -I$(SRCDIR)

CSTD=	$(CSTD_GNU99)
C99LMODE=	-Xc99=%all

LDLIBS +=	-lc
CPPFLAGS +=	$(INCS)
LINTFLAGS += -erroff=E_FUNC_RET_MAYBE_IGNORED2
LINTFLAGS += -erroff=E_FUNC_RET_ALWAYS_IGNOR2

$(LINTLIB) :=	SRCS = $(SRCDIR)/$(LINTSRC)

.KEEP_STATE:

all: $(LIBS)

lint: lintcheck

include ../../Makefile.targ
