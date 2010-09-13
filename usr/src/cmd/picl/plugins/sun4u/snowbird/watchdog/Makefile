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

LIBRARY=	libpiclwd.a
VERS=		.1

OBJECTS=	piclwatchdog.o piclwd_platmod.o

# include library definitions
include $(SRC)/lib/Makefile.lib
include $(SRC)/Makefile.psm
include	$(SRC)/cmd/picl/plugins/Makefile.com

SRCS=		$(OBJECTS:%.o=%.c)

LIBS =		$(DYNLIB)

ROOT_PLATFORM = $(USR_PLAT_DIR)/SUNW,Netra-CP2300

CLEANFILES=	$(LINTOUT) $(LINTLIB)

ROOTLIBDIR	= $(ROOT_PLAT_PLUGINDIR)

CFLAGS +=	$(CCVERBOSE)
CPPFLAGS +=	-I$(SRC)/uts/sun4u/sys -I$(SRC)/uts/common
CPPFLAGS +=	-I$(SRC)/cmd/picl/plugins/sun4u/snowbird/lib/libctsmc
CPPFLAGS +=	-I$(SRC)/uts/common

LDLIBS +=	-R/usr/platform/SUNW,Netra-CP2300/lib/picl/plugins
LDLIBS +=	-R/usr/platform/SUNW,Netra-CP2300/lib
LDLIBS +=	-R/usr/platform/sun4u/lib
LDLIBS +=	-L$(SRC)/lib/libpicl/$(MACH) -L$(SRC)/lib/libpicltree/$(MACH)
LDLIBS +=	-L $(ROOT)/usr/platform/$(PLATFORM)/lib
LDLIBS +=	-L$(ROOT_PLATFORM)/lib/picl/plugins
LDLIBS +=	-L$(SRC)/cmd/picl/plugins/sun4u/snowbird/lib/libctsmc
LDLIBS +=	-L$(ROOT)/usr/lib/picl/plugins -lnvpair -lpicltree
LDLIBS +=	-ldevinfo -lctsmc -lpiclfrutree -lc

.KEEP_STATE:

SUBDIRS=

POFILE= snowbird_piclwatchdog.po
POFILES= $(SRCS:%.c=%.po)

all :=		TARGET= all
install :=	TARGET= install
clean :=	TARGET= clean
clobber :=	TARGET= clobber
lint :=		TARGET= lint
_msg :=		TARGET= _msg

all: $(LIBS) $(LIBLINKS)

install:	$(ROOTLIBDIR) all $(ROOTLIBS) $(ROOTLINKS)

$(LIBLINKS):	FRC
	$(RM) $@; $(SYMLINK) $(DYNLIB) $@

_msg:	$(MSGDOMAIN) $(POFILE)
	$(RM) $(MSGDOMAIN)/$(POFILE)
	$(CP) $(POFILE) $(MSGDOMAIN)/$(POFILE)

$(POFILE):	$(POFILES)
		$(CAT) $(POFILES) > $(POFILE)

$(MSGDOMAIN):
	$(INS.dir)

# include library targets
include $(SRC)/cmd/picl/plugins/Makefile.targ
include $(SRC)/lib/Makefile.targ

lint :
	$(LINT.c) $(SRCS)

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:
