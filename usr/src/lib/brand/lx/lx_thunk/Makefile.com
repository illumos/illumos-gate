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
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

LIBRARY	=	lx_thunk.a
VERS =		.1

COBJS =		lx_thunk.o
OBJECTS =	$(COBJS)

include ../../../../Makefile.lib
include ../../Makefile.lx

#
# Since our name doesn't start with "lib", Makefile.lib incorrectly
# calculates LIBNAME. Therefore, we set it here.
#
LIBNAME =	lx_thunk

MAPFILES =	../common/mapfile-vers
MAPOPTS =	$(MAPFILES:%=-M%)

CSRCS =		$(COBJS:%o=../common/%c)
SRCS =		$(CSRCS)

SRCDIR =	../common
UTSBASE	=	../../../../../uts

ASFLAGS	+=	-P -D_ASM
LDLIBS +=	-lc
CFLAGS +=	$(CCVERBOSE)
CPPFLAGS +=	-D_REENTRANT -I../ -I ../../lx_brand \
			-I$(UTSBASE)/common/brand/lx

# lx_think.so.1 interposes on a number of libc.so.1 routines.
DYNFLAGS +=	$(MAPOPTS) $(ZINTERPOSE)

LIBS =		$(DYNLIB)

CLEANFILES =	$(DYNLIB)
ROOTLIBDIR =	$(ROOT)/usr/lib/brand/lx
ROOTLIBDIR64 =	$(ROOT)/usr/lib/brand/lx/$(MACH64)

.KEEP_STATE:

all: $(DYNLIB)

lint: $(LINTLIB) lintcheck

include ../../../../Makefile.targ
