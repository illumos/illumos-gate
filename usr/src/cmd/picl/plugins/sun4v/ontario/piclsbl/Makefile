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
# cmd/picl/plugins/sun4v/ontario/piclsbl/Makefile

LIBRARY=	libpiclsbl.a
VERS=		.1

OBJECTS=	piclsbl.o

# include library definitions
include $(SRC)/lib/Makefile.lib
include $(SRC)/Makefile.psm

include $(SRC)/cmd/picl/plugins/Makefile.com

SRCS=		$(OBJECTS:%.o=%.c)

LINT_SRC=	$(LINTLIB:%.ln=%)	

$(OBJS_DIR)/%.o:		$(SRC)/sun4v/ontario/piclsbl/%.c
	$(COMPILE.c) -o $@ $<
	$(CTFCONVERT_O)

$(LINTS_DIR)/%.ln:              $(SRC)/sun4v/ontario/piclsbl/%.c
	@($(LHEAD) $(LINT.c) $< $(LTAIL))


LIBS =		$(DYNLIB)

PLATFORM      =		SUNW,Sun-Fire-T200
ROOT_PLATFORM =		$(USR_PLAT_DIR)/$(PLATFORM)
DYNFLAGS_PLAT =		/usr/platform/\$$PLATFORM/lib/picl/plugins 
DYNFLAGS_SUN4V =	/usr/platform/sun4v/lib/picl/plugins
DYNFLAGS_COM =		/usr/lib/picl/plugins

ROOTLIBDIR =	$(ROOT_PLAT_PLUGINDIR)

CLEANFILES=	$(LINTOUT) $(LINTLIB)

CPPFLAGS +=	-I$(SRC)/sun4v/ontario/piclsbl
CPPFLAGS +=	-I$(SRC)/uts/common/sys
CPPFLAGS +=	-I$(SRC)/lib/libpcp/common
CPPFLAGS +=	-D_REENTRANT

CFLAGS +=	$(CCVERBOSE)
LDLIBS +=	-L$(SRC)/lib/libpicl/$(MACH) -L$(SRC)/lib/libpicltree/$(MACH)
LDLIBS +=	-L$(ROOT)/usr/lib/picl/plugins
DYNFLAGS +=	-R$(DYNFLAGS_COM)

LDLIBS +=	-lc -lpicltree -lumem -lnvpair

LINTFLAGS +=	-erroff=E_BAD_PTR_CAST_ALIGN -v

LINKED_PLATFORMS	= SUNW,Sun-Blade-T6300 SUNW,T5140
LINKED_PLATFORMS	+= SUNW,Sun-Blade-T6320
LINKED_PLATFORMS	+= SUNW,SPARC-Enterprise-T5120
LINKED_PLATFORMS	+= SUNW,Netra-T5220

LINKED_DIRS		= $(LINKED_PLATFORMS:%=$(USR_PLAT_DIR)/%)
LINKED_LIB_DIRS		= $(LINKED_PLATFORMS:%=$(USR_PLAT_DIR)/%/lib)
LINKED_PICL_DIRS	= $(LINKED_PLATFORMS:%=$(USR_PLAT_DIR)/%/lib/picl)
LINKED_PLUGIN_DIRS	= $(LINKED_PLATFORMS:%=$(USR_PLAT_DIR)/%/lib/picl/plugins)

LINKED_PLUGINS_DYNLIBS = $(LINKED_PLUGIN_DIRS:%=%/$(DYNLIB))
LINKED_PLUGINS_LIBLINKS = $(LINKED_PLUGIN_DIRS:%=%/$(LIBLINKS))

ONTARIO_DYNLIB_DIR = ../../../../$(PLATFORM)/lib/picl/plugins

.KEEP_STATE:

all: $(LIBS) $(LIBLINKS)

install:	all $(ROOTLIBDIR) $(ROOTLIBS) $(ROOTLINKS) \
	$(LINKED_PLUGIN_DIRS) $(LINKED_PLUGINS_DYNLIBS) \
	$(LINKED_PLUGINS_LIBLINKS)

$(LIBLINKS):	FRC
	$(RM) $(LIBLINKS); $(SYMLINK) $(DYNLIB) $(LIBLINKS)

# Linked platforms directory hierarchy
$(LINKED_DIRS):
	$(INS.dir)
$(LINKED_LIB_DIRS): $(LINKED_DIRS)
	$(INS.dir)
$(LINKED_PICL_DIRS): $(LINKED_LIB_DIRS)
	$(INS.dir)
$(LINKED_PLUGIN_DIRS): $(LINKED_PICL_DIRS)
	$(INS.dir)

# Linked platforms links 
$(LINKED_PLUGINS_DYNLIBS): $(LINKED_PLUGIN_DIRS)
	$(RM) -r $@ ;\
	$(SYMLINK) $(ONTARIO_DYNLIB_DIR)/$(DYNLIB) $@

$(LINKED_PLUGINS_LIBLINKS): $(LINKED_PLUGIN_DIRS)
	$(RM) -r $@ ;\
	$(SYMLINK) $(ONTARIO_DYNLIB_DIR)/$(DYNLIB) $@

# include library targets
include $(SRC)/cmd/picl/plugins/Makefile.targ
include $(SRC)/lib/Makefile.targ

lint :
	$(LINT.c) $(SRCS)

FRC:
