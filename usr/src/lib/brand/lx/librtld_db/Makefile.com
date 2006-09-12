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
# ident	"%Z%%M%	%I%	%E% SMI"
#

LIBRARY =	lx_librtld_db.a
VERS	=	.1
COBJS	=	lx_librtld_db.o
OBJECTS	=	$(COBJS)

include ../../../../Makefile.lib
include ../../Makefile.lx

CSRCS =       $(COBJS:%o=../common/%c)
SRCS  =       $(CSRCS)

SRCDIR =	../common
UTSBASE	=	../../../../../uts

LIBS =		$(DYNLIB)
LDLIBS +=	-lc -lproc
CFLAGS +=	$(CCVERBOSE)
CPPFLAGS +=	-D_REENTRANT -I../ -I$(UTSBASE)/common/brand/lx \
			-I../../../../../cmd/sgs/librtld_db/common \
			-I../../../../../cmd/sgs/include \
			-I../../../../../cmd/sgs/include/$(MACH)

ROOTLIBDIR =	$(ROOT)/usr/lib/brand/lx
ROOTLIBDIR64 =	$(ROOT)/usr/lib/brand/lx/$(MACH64)

.KEEP_STATE:

all: $(LIBS)

lint: lintcheck

include ../../../../Makefile.targ
