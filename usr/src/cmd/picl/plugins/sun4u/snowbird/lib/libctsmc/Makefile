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
# cmd/picl/plugins/sun4u/snowbird/lib/smc_util/Makefile
#

LIBRARY =	libctsmc.a
VERS =		.1
PLATFORM =	SUNW,Netra-CP2300

OBJECTS=	libctsmc.o

# include library definitions
include $(SRC)/lib/Makefile.lib
include $(SRC)/Makefile.psm
include	$(SRC)/cmd/picl/plugins/Makefile.com

ROOT_PLATFORM = $(USR_PLAT_DIR)/$(PLATFORM)

SRCS=		$(OBJECTS:%.o=%.c)

LIBS =		$(DYNLIB)

CLEANFILES=	$(LINTOUT) $(LINTLIB)

ROOTLIBDIR	= $(ROOT_PLAT_LIBDIR)

LINTSRC =	$(LINTLIB:%.ln=%)
ROOTLINTDIR =	$(ROOTLIBDIR)
ROOTLINT =	$(LINTSRC:%=$(ROOTLINTDIR)/%)

CFLAGS +=	$(CCVERBOSE)
CPPFLAGS +=	-D_REENTRANT -D_SNOWBIRD -I$(SRC)/uts/sun4u/sys
LDLIBS +=	-L $(ROOT)/usr/platform/$(PLATFORM)/lib
LDLIBS +=	-R/usr/platform/sun4u/lib
LDLIBS +=	-lc

.KEEP_STATE:

SUBDIRS=

all :=		TARGET= all
install :=	TARGET= install
clean :=	TARGET= clean
clobber :=	TARGET= clobber
lint :=		TARGET= lint
_msg :=		TARGET= _msg

all:$(LIBS) $(LIBLINKS)

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
