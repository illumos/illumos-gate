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
# Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

LIBRARY=	libldmake.a
VERS=		.1
OBJECTS=	ld_file.o lock.o

include		$(SRC)/lib/Makefile.lib
include		$(SRC)/cmd/sgs/Makefile.com

ROOTLIBDIR=	$(ROOT)/opt/SUNWonld/lib
ROOTLIBDIR64=	$(ROOT)/opt/SUNWonld/lib/$(MACH64)

SRCDIR =	../common

DYNFLAGS +=	$(CC_USE_PROTO)

CFLAGS +=	$(C_PICFLAGS)
CFLAGS64 +=	$(C_PICFLAGS64)

LINTFLAGS +=	-erroff=E_NAME_DECL_NOT_USED_DEF2 \
		-erroff=E_NAME_DEF_NOT_USED2 \
		-erroff=E_NAME_USED_NOT_DEF2
LINTFLAGS64 +=	-erroff=E_NAME_DECL_NOT_USED_DEF2 \
		-erroff=E_NAME_DEF_NOT_USED2 \
		-erroff=E_NAME_USED_NOT_DEF2
LINTSRCS =	$(SRCS)

SRCS=		$(OBJECTS:%.o=../common/%.c)
LDLIBS +=	-lc

CLEANFILES +=
CLOBBERFILES +=	$(DYNLIB) $(LINTLIB) $(LINTOUTS)

ROOTDYNLIB=	$(DYNLIB:%=$(ROOTLIBDIR)/%)
ROOTDYNLIB64=	$(DYNLIB:%=$(ROOTLIBDIR64)/%)
