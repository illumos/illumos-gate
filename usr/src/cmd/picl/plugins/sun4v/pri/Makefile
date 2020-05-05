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

LIBRARY=	libpriplugin.a
VERS=		.1

OBJS_DIR=	pics

OBJECTS=	priplugin.o init.o \
		mem_prop_update.o io_dev_label.o \
		mdesc_findname.o mdesc_findnodeprop.o \
		mdesc_fini.o mdesc_getpropstr.o \
		mdesc_getpropval.o mdesc_init_intern.o \
		mdesc_nodecount.o mdesc_rootnode.o \
		mdesc_scandag.o mdesc_getpropdata.o

# include library definitions
include $(SRC)/lib/Makefile.lib
include $(SRC)/Makefile.psm

include $(SRC)/cmd/picl/plugins/Makefile.com

SRCS=		$(OBJECTS:%.o=%.c)

$(OBJS_DIR)/%.o:		$(SRC)/common/mdesc/%.c
	$(COMPILE.c) -o $@ $<
	$(CTFCONVERT_O)

LIBS =		$(DYNLIB)

ROOT_PLATFORM =		$(USR_PLAT_DIR)/sun4v
DYNFLAGS_PLAT =		/usr/platform/\$$PLATFORM/lib/picl/plugins
DYNFLAGS_SUN4V =	/usr/platform/sun4v/lib/picl/plugins
DYNFLAGS_COM =		/usr/lib/picl/plugins

ROOTLIBDIR =	$(ROOT_PLAT_PLUGINDIR)

CPPFLAGS +=	-I$(SRC)/common/mdesc
CPPFLAGS +=	-I$(SRC)/uts/common/sys
CPPFLAGS +=	-I$(SRC)/lib/libpri/common
CPPFLAGS +=	-D_REENTRANT

CFLAGS +=	$(CCVERBOSE)
LDLIBS +=	-L$(SRC)/lib/libpicl/$(MACH) -L$(SRC)/lib/libpicltree/$(MACH)
LDLIBS +=	-L$(ROOT)/usr/lib/picl/plugins -L$(ROOT)/usr/lib/sparcv9
LDLIBS +=	-L$(ROOT)/usr/lib/libpri
LDLIBS +=	-L$(ROOT_PLATFORM)/lib -L$(ROOT_PLATFORM)/lib/picl/plugins

LDLIBS +=	-lc -lpicl -lpicltree -lpicldevtree -lpri

# No interfaces from libsnmpplugin.so directly used here, but we need the
# snmp plugin to load and init before libpriplugin.so.
#
LDLIBS +=	-lsnmpplugin

#DYNFLAGS +=	-R$(DYNFLAGS_COM)
$(SPARC_BLD)LDLIBS +=	-R$(DYNFLAGS_PLAT) \
			-R$(DYNFLAGS_SUN4V)
LDLIBS +=	-R$(DYNFLAGS_COM)

.KEEP_STATE:

all: $(LIBS) $(LIBLINKS)

install:	all $(ROOTLIBDIR) $(ROOTLIBS) $(ROOTLINKS)

$(LIBLINKS):	FRC
	$(RM) $(LIBLINKS); $(SYMLINK) $(DYNLIB) $(LIBLINKS)

# include library targets
include $(SRC)/cmd/picl/plugins/Makefile.targ
include $(SRC)/lib/Makefile.targ

lint :

FRC:
