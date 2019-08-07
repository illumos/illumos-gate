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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright (c) 2018, Joyent, Inc.

LIBRARY=	libpicld_pluginutil.a
VERS=		.1

OBJECTS=	picld_pluginutil.o

# include library definitions
include $(SRC)/lib/Makefile.lib

SRCS=		$(OBJECTS:%.o=../%.c)

CLOBBERFILES +=	$(LIBLINKS)

LIBS =		$(DYNLIB) $(LINTLIB)

LINTFLAGS =	-uxmn -I.. -I$(SRC)/lib/libpicl -I$(SRC)/lib/libpicltree
LINTFLAGS +=	-D_REENTRANT
LINTOUT=	lint.out

LINTSRC =       $(LINTLIB:%.ln=%)
ROOTLINTDIR =   $(ROOTLIBDIR)
ROOTLINT =      $(LINTSRC:%=$(ROOTLINTDIR)/%)

CLEANFILES=	$(LINTOUT) $(LINTLIB)

XGETFLAGS += -a
POFILE=	picld_pluginutil.po

CPPFLAGS +=	-I.. -I$(SRC)/lib/libpicl -I$(SRC)/lib/libpicltree
CFLAGS +=	$(CCVERBOSE)
CERRWARN +=	$(CNOWARN_UNINIT)

SMOFF += all_func_returns

CPPFLAGS +=	-D_REENTRANT
DYNFLAGS +=	$(ZNOLAZYLOAD)
LDLIBS +=	-L$(SRC)/lib/libpicltree/$(MACH)
LDLIBS +=	-lc -lpicltree

$(LINTLIB) :=	SRCS = ../llib-lpicld_pluginutil
$(LINTLIB) :=	LINTFLAGS = -nvx -I..

.KEEP_STATE:

all : $(LIBS)

lint :
	$(LINT.c) $(SRCS)

%.po:	../%.c
	$(CP) $< $<.i
	$(BUILD.po)

_msg:	$(MSGDOMAIN) $(POFILE)
	$(RM) $(MSGDOMAIN)/$(POFILE)
	$(CP) $(POFILE) $(MSGDOMAIN)

$(MSGDOMAIN):
	$(INS.dir)

# include library targets
include $(SRC)/lib/Makefile.targ

pics/%.o:	../%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

$(ROOTLINTDIR)/%: ../%
	$(INS.file)
