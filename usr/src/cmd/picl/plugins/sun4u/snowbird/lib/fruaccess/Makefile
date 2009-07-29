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
# cmd/picl/plugins/sun4u/snowbird/lib/fruaccess/Makefile
#

LIBRARY=	libfruaccess.a
VERS=		.1

OBJECTS=	libfruaccess.o piclsmc.o piclsdr.o piclfruaccess_platmod.o \
		crcutils.o crcmodel.o

# include library definitions
include $(SRC)/lib/Makefile.lib
include $(SRC)/Makefile.psm
include	$(SRC)/cmd/picl/plugins/Makefile.com

ROOT_PLATFORM = $(USR_PLAT_DIR)/SUNW,Netra-CP2300

SRCS= libfruaccess.c piclsmc.c piclsdr.c piclfruaccess_platmod.c\
		../../../lib/fruaccess/crcutils.c \
		../../../lib/fruaccess/crcmodel.c

SRCDIR= ../../../lib/fruaccess/.

LIBS =		$(DYNLIB)

CLEANFILES=	$(LINTOUT) $(LINTLIB)

ROOTLIBDIR	= $(ROOT_PLAT_LIBDIR)

LINTSRC =	$(LINTLIB:%.ln=%)
ROOTLINTDIR =	$(ROOTLIBDIR)
ROOTLINT =	$(LINTSRC:%=$(ROOTLINTDIR)/%)

CFLAGS +=	$(CCVERBOSE)
CPPFLAGS +=	-I$(SRC)/uts/sun4u/sys
CPPFLAGS +=	-I$(SRC)/cmd/picl/plugins/sun4u/lib/fruaccess
CPPFLAGS +=	-I$(SRC)/lib/libfruutils
CPPFLAGS +=	-I$(SRC)/lib/libfru/include
CPPFLAGS +=	-I$(SRC)/cmd/picl/plugins/sun4u/snowbird/lib/libctsmc

LDLIBS +=	-L$(SRC)/lib/libpicl/$(MACH) -L$(SRC)/lib/libpicltree/$(MACH)
LDLIBS +=	-L $(ROOT)/usr/platform/SUNW,Netra-CP2300/lib
LDLIBS +=	-L$(SRC)/cmd/picl/plugins/sun4u/snowbird/lib/libctsmc
LDLIBS +=	-R/usr/platform/sun4u/lib
LDLIBS +=	-R/usr/platform/SUNW,Netra-CP2300/lib
LDLIBS +=	-lc -lpicltree -lfruutils -lctsmc

.KEEP_STATE:

SUBDIRS=

all :=		TARGET= all
install :=	TARGET= install
clean :=	TARGET= clean
clobber :=	TARGET= clobber
lint :=		TARGET= lint
_msg :=		TARGET= _msg

all: $(LIBS) $(LIBLINKS)

install:$(ROOTLIBDIR) all  $(ROOTLIBS) $(ROOTLINKS)

$(LIBLINKS):	FRC
	$(RM) $(LIBLINKS); $(SYMLINK) $(DYNLIB) $(LIBLINKS)

_msg:

# include library targets
include $(SRC)/cmd/picl/plugins/Makefile.targ
include $(SRC)/lib/Makefile.targ

$(ROOTLINTDIR)/%: ../%
	$(INS.file)

lint :
	$(LINT.c) $(SRCS)

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:
