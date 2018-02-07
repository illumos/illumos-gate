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
# Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
#

LIBRARY =	libsrpt.a
VERS =		.1
OBJECTS =	libsrpt.o

include ../../Makefile.lib

LIBS =		$(DYNLIB) $(LINTLIB)

SRCDIR =	../common
$(LINTLIB):=	SRCS = $(SRCDIR)/$(LINTSRC)

SRPTMODDIR =	../../../uts/common/io/comstar/port/srpt

INCS +=		-I$(SRCDIR) -I$(SRPTMODDIR)

CSTD =	$(CSTD_GNU99)
C99LMODE =	-Xc99=%all
LDLIBS +=	-lc -lnvpair -lstmf
CPPFLAGS +=	$(INCS) -D_REENTRANT

.KEEP_STATE:

all: $(LIBS)

lint: lintcheck

include ../../Makefile.targ
