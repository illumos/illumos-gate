#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
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
# ident	"%Z%%M%	%I%	%E% SMI"
#
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# cmd/picl/plugins/sun4v/mdesc/Makefile
#
LIBRARY=	libmdescplugin.a
VERS=		.1

OBJS_DIR=	pics

OBJECTS=	mdescplugin.o init.o \
		cpu_prop_update.o disk_discovery.o \
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

LINT_SRC=	./mdescplugin.c ./init.c \
		./cpu_prop_update.c ./disk_discovery.c \
		$(SRC)/common/mdesc/mdesc_findname.c \
		$(SRC)/common/mdesc/mdesc_findnodeprop.c \
		$(SRC)/common/mdesc/mdesc_fini.c \
		$(SRC)/common/mdesc/mdesc_getpropdata.c \
		$(SRC)/common/mdesc/mdesc_getpropstr.c \
		$(SRC)/common/mdesc/mdesc_getpropval.c \
		$(SRC)/common/mdesc/mdesc_init_intern.c \
		$(SRC)/common/mdesc/mdesc_nodecount.c \
		$(SRC)/common/mdesc/mdesc_rootnode.c \
		$(SRC)/common/mdesc/mdesc_scandag.c

$(OBJS_DIR)/%.o:		$(SRC)/common/mdesc/%.c
	$(COMPILE.c) -o $@ $<
	$(CTFCONVERT_O)

LIBS =		$(DYNLIB)

ROOT_PLATFORM =		$(USR_PLAT_DIR)/sun4v
DYNFLAGS_PLAT =		/usr/platform/\$$PLATFORM/lib/picl/plugins
DYNFLAGS_SUN4V =	/usr/platform/sun4v/lib/picl/plugins
DYNFLAGS_COM =		/usr/lib/picl/plugins

ROOTLIBDIR =	$(ROOT_PLAT_PLUGINDIR)

CLEANFILES=	$(LINTOUT) $(LINTLIB)

CPPFLAGS +=	-I$(SRC)/common/mdesc
CPPFLAGS +=	-I$(SRC)/uts/common/sys
CPPFLAGS +=	-D_REENTRANT

CFLAGS +=	$(CCVERBOSE)
LDLIBS +=	-L$(SRC)/lib/libpicl/$(MACH) -L$(SRC)/lib/libpicltree/$(MACH)
LDLIBS +=	-L$(ROOT)/usr/lib/picl/plugins -L$(ROOT)/usr/lib/sparcv9
DYNFLAGS +=	-R$(DYNFLAGS_COM)

LDLIBS +=	-lc -lpicltree -lrt -lpicldevtree -lcfgadm -lnvpair

LINTFLAGS +=	-erroff=E_BAD_PTR_CAST_ALIGN -v

.KEEP_STATE:

SUBDIRS=

POFILE=	mdescplugin.po
POFILE_RENAME=	mdescplugin_sun4v.po

all :=		TARGET= all
install :=	TARGET= install
clean :=	TARGET= clean
clobber :=	TARGET= clobber
lint :=		TARGET= lint
_msg :=		TARGET= _msg

all: $(LIBS) $(LIBLINKS)

install:	all $(ROOTLIBDIR) $(ROOTLIBS) $(ROOTLINKS)

_msg:	$(MSGDOMAIN) $(POFILE)
	$(RM) $(MSGDOMAIN)/$(POFILE)
	$(CP) $(POFILE) $(MSGDOMAIN)/$(POFILE_RENAME)

$(MSGDOMAIN):
	$(INS.dir)

$(LIBLINKS):	FRC
	$(RM) $(LIBLINKS); $(SYMLINK) $(DYNLIB) $(LIBLINKS)

# include library targets
include $(SRC)/cmd/picl/plugins/Makefile.targ
include $(SRC)/lib/Makefile.targ

lint :
	$(LINT.c) $(LINT_SRC)

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:
