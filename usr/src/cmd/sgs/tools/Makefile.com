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

#
# Makefile to support tools used for linker development:
#
#  o	sgsmsg creates message headers/arrays/catalogs (a native tool).
#
# Note, these tools are not part of the product.
#
# cmd/sgs/tools/Makefile.com

include		$(SRC)/cmd/Makefile.cmd

include		$(SRC)/cmd/sgs/Makefile.com

SGSPROTO=	../../proto/$(MACH)

COMOBJS=

NATOBJS=	piglatin.o

OBJECTS=	$(COMOBJS)  $(NATOBJS)

AVLOBJ=		avl.o
TOOL_OBJS=	sgsmsg.o string_table.o findprime.o assfail.o
SGSMSG_OBJS=	$(TOOL_OBJS) $(AVLOBJ)
SGSMSG_SRCS=	$(TOOL_OBJS:%.o=../common/%.c) \
		$(AVLOBJ:%.o=$(VAR_AVLDIR)/%.c)

$(SGSMSG_OBJS) := NATIVE_CFLAGS += -I../../include $(VAR_TOOLS_CPPFLAGS)

PROGS=		$(COMOBJS:%.o=%)
NATIVE=		$(NATOBJS:%.o=%) sgsmsg
SRCS=		$(COMOBJS:%.o=../common/%.c)  $(NATOBJS:%.o=../common/%.c)

CPPFLAGS +=	$(VAR_TOOLS_CPPFLAGS)
LDFLAGS +=	$(CC_USE_PROTO)
CLEANFILES +=	$(LINTOUT) $(SGSMSG_OBJS)
LINTFLAGS=	-ax

ROOTDIR=	$(ROOT)/opt/SUNWonld
ROOTPROGS=	$(PROGS:%=$(ROOTDIR)/bin/%)

FILEMODE=	0755
