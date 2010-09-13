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

include	$(SRC)/Makefile.psm

LIBRARY =	libpiclenvmond.a
VERS =		.1
PLATFORM =	SUNW,Netra-CP2300

OBJECTS=	piclenvmond.o piclsensors.o picldr.o piclplatmod.o

# include library definitions
include $(SRC)/lib/Makefile.lib

ROOT_PLATFORM = $(USR_PLAT_DIR)/$(PLATFORM)

include	$(SRC)/cmd/picl/plugins/Makefile.com

CFLAGS +=	$(CCVERBOSE)
CPPFLAGS +=	-D_REENTRANT -D_SNOWBIRD \
		-I$(USR_PSM_INCL_DIR) \
		-I$(SRC)/uts/sun4u/sys \
		-I$(SRC)/cmd/picl/plugins/inc \
		-I$(SRC)/cmd/picl/plugins/sun4u/snowbird/lib/libctsmc

SRCS=		$(OBJECTS:%.o=%.c)

LIBS =		$(DYNLIB)

ROOTLIBDIR =	$(ROOT_PLAT_PLUGINDIR)

CLEANFILES =	$(LINTOUT) $(LINTLIB)

LDLIBS +=	-L$(SRC)/lib/libptree/$(MACH)
LDLIBS +=	-L$(SRC)/cmd/picl/plugins/sun4u/snowbird/lib/libctsmc
LDLIBS +=	-L$(ROOT)/usr/lib/picl/plugins -lc -lpicltree \
		-lpicl -lnvpair -lm -ldevinfo -lcfgadm	\
		-lpiclfrutree -lrcm -lctsmc
LDLIBS +=	-R/usr/platform/$(PLATFORM)/lib
LDLIBS +=	-R/usr/platform/$(PLATFORM)/lib/picl/plugins
LDLIBS +=	-R/usr/platform/sun4u/lib/picl/plugins:/usr/lib/picl/plugins

.KEEP_STATE:

SUBDIRS=

POFILE= snowbird_piclenvmond.po
POFILES= $(SRCS:%.c=%.po)

all	:=	TARGET= all
install :=	TARGET= install
clean	:=	TARGET= clean
clobber	:=	TARGET= clobber
lint	:=	TARGET= lint
_msg	:=	TARGET= _msg

all: $(LIBS) $(LIBLINKS)

install:	$(ROOTLIBDIR) all $(ROOTLIBS) $(ROOTLINKS)

$(LIBLINKS):	FRC
	$(RM) $@; $(SYMLINK) ./$(DYNLIB) $@

_msg:	$(MSGDOMAIN) $(POFILE)
	$(RM) $(MSGDOMAIN)/$(POFILE)
	$(CP) $(POFILE) $(MSGDOMAIN)/$(POFILE)

$(POFILE):	$(POFILES)
		$(CAT) $(POFILES) > $(POFILE)

$(MSGDOMAIN):
	$(INS.dir)

# include library targets
include $(SRC)/lib/Makefile.targ
include	$(SRC)/cmd/picl/plugins/Makefile.targ

lint :
	$(LINT.c) $(SRCS)

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:
