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

include		$(SRC)/Makefile.psm

LIBRARY=	libpiclmemcfg.a
VERS=		.1

OBJECTS=	piclmemcfg.o

# include library definitions
include	$(SRC)/lib/Makefile.lib

ROOT_PLATFORM = $(USR_PLAT_DIR)/SUNW,Sun-Blade-100

include	$(SRC)/cmd/picl/plugins/Makefile.com

SRCS=		$(OBJECTS:%.o=%.c)

LIBS =		$(DYNLIB)

ROOTLIBDIR	= $(ROOT_PLAT_PLUGINDIR)

LINTSRC =       $(LINTLIB:%.ln=%)
ROOTLINTDIR =   $(ROOTLIBDIR)
ROOTLINT =      $(LINTSRC:%=$(ROOTLINTDIR)/%)

CLEANFILES=	$(LINTOUT) $(LINTLIB)

CPPFLAGS +=	-I$(SRC)/cmd/picl/plugins/common/memcfg
CFLAGS +=	$(CCVERBOSE)
LDLIBS +=	-L$(SRC)/lib/libpicltree/$(MACH)
LDLIBS +=	-L$(SRC)/cmd/picl/plugins/common/devtree
LDLIBS +=	-L$(ROOT)/usr/lib/picl/plugins
LDLIBS +=	-lc -lpicltree -lpicldevtree
LDLIBS +=	-R/usr/platform/\$$PLATFORM/lib/picl/plugins:/usr/platform/sun4u/lib/picl/plugins:/usr/lib/picl/plugins


LINKED_PLATFORMS	= SUNW,Serverblade1

LINKED_DIRS		= $(LINKED_PLATFORMS:%=$(USR_PLAT_DIR)/%)
LINKED_LIB_DIRS		= $(LINKED_PLATFORMS:%=$(USR_PLAT_DIR)/%/lib)
LINKED_PICL_DIRS	= $(LINKED_PLATFORMS:%=$(USR_PLAT_DIR)/%/lib/picl)
LINKED_PLUGIN_DIRS	= $(LINKED_PLATFORMS:%=$(USR_PLAT_DIR)/%/lib/picl/plugins)

LINKED_PLUGINS_DYNLIBS = $(LINKED_PLUGIN_DIRS:%=%/$(DYNLIB))
LINKED_PLUGINS_LIBLINKS = $(LINKED_PLUGIN_DIRS:%=%/$(LIBLINKS))

GROVER_DYNLIB_DIR = ../../../../SUNW,Sun-Blade-100/lib/picl/plugins

PLATFORM=	SUNW,Sun-Blade-100

.KEEP_STATE:

SUBDIRS=

all :=		TARGET= all
install :=	TARGET= install
clean :=	TARGET= clean
clobber :=	TARGET= clobber
lint :=		TARGET= lint
_msg :=		TARGET= _msg

POFILE=	piclmemcfg.po

all: $(LIBS) $(LIBLINKS)

install:	$(ROOTLIBDIR) all $(ROOTLIBS) $(ROOTLINKS) \
	$(LINKED_PLUGIN_DIRS) $(LINKED_PLUGINS_DYNLIBS) \
	$(LINKED_PLUGINS_LIBLINKS)

_msg:	$(MSGDOMAIN) $(POFILE)
	$(RM) $(MSGDOMAIN)/$(POFILE)
	$(CP) $(POFILE) $(MSGDOMAIN)

$(MSGDOMAIN):
	$(INS.dir)

$(LIBLINKS):	FRC
	$(RM) $@; $(SYMLINK) $(DYNLIB) $@

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
	$(SYMLINK) $(GROVER_DYNLIB_DIR)/$(DYNLIB) $@

$(LINKED_PLUGINS_LIBLINKS): $(LINKED_PLUGIN_DIRS)
	$(RM) -r $@ ;\
	$(SYMLINK) $(GROVER_DYNLIB_DIR)/$(DYNLIB) $@

# include library targets
include	$(SRC)/cmd/picl/plugins/Makefile.targ
include	$(SRC)/lib/Makefile.targ

$(ROOTLINTDIR)/%: ../%
	$(INS.file)

lint :
	$(LINT.c) $(SRCS)

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:
