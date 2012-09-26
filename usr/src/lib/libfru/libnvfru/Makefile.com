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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

LIBRARY=	libnvfru.a
VERS=		.1

OBJECTS=	nvfru.o

# include library definitions
include $(SRC)/lib/Makefile.lib

CLOBBERFILES += $(LIBLINKS)

LIBS =		$(DYNLIB)

LINTFLAGS =	-uxn
LINTFLAGS64 =	$(LINTFLAGS) -m64
LINTOUT=	lint.out
LINTSRC =       $(LINTLIB:%.ln=%)
ROOTLINTDIR =   $(ROOTLIBDIR)
ROOTLINT =      $(LINTSRC:%=$(ROOTLINTDIR)/%)

CLEANFILES=	$(LINTOUT)

CPPFLAGS +=	-I.. \
		-I$(SRC)/lib/libfru/include \
		-I$(SRC)/lib/libfruutils
CPPFLAGS += 	-D_REENTRANT
CFLAGS +=	$(CCVERBOSE)

CERRWARN +=	-_gcc=-Wno-switch

$(LINTLIB) :=	LINTFLAGS = -nvx -I..
$(LINTLIB) :=	LINTFLAGS64 = -nvx -m64 -I..

XGETFLAGS += -a

.KEEP_STATE:

all : $(LIBS)

lint :	lintcheck

# include library targets
include $(SRC)/lib/Makefile.targ

pics/%.o:	../%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

$(ROOTLINTDIR)/%: ../%
	$(INS.file)
