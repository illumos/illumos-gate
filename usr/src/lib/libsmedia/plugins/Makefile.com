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

LIBS =		$(DYNLIB)

CPPFLAGS +=	-I../inc -I$(SRC)/cmd/smserverd/
LDLIBS +=	-lc $(PLUGIN_SPECIFIC_LIB)

LINTPLUGIN  = llib-$(LIBNAME).ln
PLUGINDIR = $(ROOTLIBDIR)/smedia
PLUGINDIR64 = $(ROOTLIBDIR)/smedia/$(MACH64)
FILEMODE = 555

SOFILES	= $(LIBRARY:%.a=%.so)
PLUGINS  = $(LIBS:%=$(PLUGINDIR)/%)
PLUGINS64  = $(LIBS:%=$(PLUGINDIR64)/%)

CLEANFILES=	$(LINTOUT) $(LINTPLUGIN)

SRCDIR =	../common

# not linted
SMATCH=off

LINTFLAGS += -xu
LINTFLAGS64 += -xu
$(LINTPLUGIN) :=	SRCS=$(OBJECTS:%.o=../common/%.c)
$(LINTPLUGIN) :=	LINTFLAGS=-nvx
$(LINTPLUGIN) :=	TARGET_ARCH=

LINTSRC=	$(LINTPLUGIN:%.ln=%)
ROOTLINTDIR=	$(ROOTLIBDIR)
ROOTLINT=	$(LINTSRC:%=$(ROOTLINTDIR)/%)

.KEEP_STATE:

lint:	lintcheck

objs/%.o pics/%.o: ../common/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

$(PLUGINDIR) :
	${INS.dir}

$(PLUGINDIR64) :
	${INS.dir}

$(PLUGINDIR)/% : %
	${INS.file}

$(PLUGINDIR64)/% : %
	${INS.file}

