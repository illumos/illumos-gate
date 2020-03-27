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
# cmd/picl/plugins/sun4u/psvc/psvcplugin/Makefile
#
LIBRARY=	libpsvcplugin.a
VERS=		.1

OBJECTS=	psvcplugin.o

# include library definitions
include $(SRC)/lib/Makefile.lib
include $(SRC)/Makefile.psm

include $(SRC)/cmd/picl/plugins/Makefile.com

SRCS=		$(OBJECTS:%.o=%.c)

LIBS =		$(DYNLIB)

ROOT_PLATFORM = $(USR_PLAT_DIR)/SUNW,Sun-Fire-280R

USR_PLAT_PLUGINS_LNECK = $(LIBS:%=$(ROOT_PLAT_PLUGINDIR)/%)

PLAT_PLATFORM = $(USR_PLAT_DIR)/SUNW,Sun-Fire-880
PLAT_PLATFORM += $(USR_PLAT_DIR)/SUNW,Sun-Fire-480R
PLAT_PLATFORM += $(USR_PLAT_DIR)/SUNW,Sun-Fire-V490
PLAT_PLATFORM += $(USR_PLAT_DIR)/SUNW,Sun-Fire-V890

PLAT_LIB_DIR = $(PLAT_PLATFORM:%=%/lib)

PLAT_PICL_DIR = $(PLAT_LIB_DIR:%=%/picl)

PLAT_PLUGINS_DIRS = $(PLAT_PICL_DIR:%=%/plugins)

USR_PLAT_PLUGINS_DYNLIBS = $(PLAT_PLUGINS_DIRS:%=%/$(DYNLIB))
USR_PLAT_PLUGINS_LIBLINKS = $(PLAT_PLUGINS_DIRS:%=%/$(LIBLINKS))
LNECK_DYNLIB_DIR = ../../../../SUNW,Sun-Fire-280R/lib/picl/plugins

CPPFLAGS +=	-I$(SRC)/uts/sun4u
CPPFLAGS +=	-I$(SRC)/cmd/picl/plugins/sun4u/psvc/psvcobj

CFLAGS +=	$(CCVERBOSE)
LDLIBS +=	-L$(SRC)/lib/libpicl/$(MACH) -L$(SRC)/lib/libpicltree/$(MACH)
LDLIBS +=	-L $(ROOT)/usr/platform/$(PLATFORM)/lib
LDLIBS +=	-L$(SRC)/cmd/picl/plugins/sun4u/psvc/psvcobj
LDLIBS +=	-R/usr/platform/sun4u/lib
LDLIBS +=	-lc -lpicltree -lpicl -lpsvcobj

DYNFLAGS +=	-Wl,-f/usr/platform/\$$PLATFORM/lib/$(DYNLIBPSR)

.KEEP_STATE:

SUBDIRS=

POFILE=	psvcplugin.po

all :=		TARGET= all
install :=	TARGET= install
clean :=	TARGET= clean
clobber :=	TARGET= clobber
_msg :=		TARGET= _msg

all: $(LIBS) $(LIBLINKS)

install:	all $(USR_PLAT_PLUGINS_LNECK) \
	$(PLAT_PLATFORM) $(PLAT_LIB_DIR) $(PLAT_PICL_DIR) \
	$(USR_PLAT_PLUGINS_DYNLIBS) $(USR_PLAT_PLUGINS_LIBLINKS)

$(LIBLINKS):	FRC
	$(RM) $(LIBLINKS); $(SYMLINK) $(DYNLIB) $(LIBLINKS)

_msg:	$(MSGDOMAIN) $(POFILE)
	$(RM) $(MSGDOMAIN)/$(POFILE)
	$(CP) $(POFILE) $(MSGDOMAIN)/$(POFILE)

$(MSGDOMAIN):
	$(INS.dir)


# include library targets
include $(SRC)/cmd/picl/plugins/Makefile.targ
include $(SRC)/lib/Makefile.targ

$(ROOT_PLAT_PLUGINDIR)/%: % $(ROOT_PLAT_PLUGINDIR)
	$(INS.file) ;\
	$(RM) -r $(ROOT_PLAT_PLUGINDIR)/$(LIBLINKS) ;\
	$(SYMLINK) ./$(DYNLIB) $(ROOT_PLAT_PLUGINDIR)/$(LIBLINKS)

$(PLAT_PLATFORM):
	$(INS.dir)
$(PLAT_LIB_DIR):
	$(INS.dir)
$(PLAT_PICL_DIR):
	$(INS.dir)

$(PLAT_PLUGINS_DIRS):
	$(INS.dir)

$(USR_PLAT_PLUGINS_DYNLIBS): $(PLAT_PLUGINS_DIRS)
	$(RM) -r $@ ;\
	$(SYMLINK) $(LNECK_DYNLIB_DIR)/$(DYNLIB) $@

$(USR_PLAT_PLUGINS_LIBLINKS): $(PLAT_PLUGINS_DIRS)
	$(RM) -r $@ ;\
	$(SYMLINK) $(LNECK_DYNLIB_DIR)/$(DYNLIB) $@

lint :

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:
