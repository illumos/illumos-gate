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

LIBRARY =	libpiclfrutree.a
VERS =		.1

OBJECTS =	piclfrutree.o

# include library definitions
include $(SRC)/lib/Makefile.lib

ROOT_PLATFORM = $(USR_PLAT_DIR)/SUNW,Netra-T12

include	$(SRC)/cmd/picl/plugins/Makefile.com

CPPFLAGS +=	-D_REENTRANT -I$(SRC)/uts/sun4u/serengeti
CPPFLAGS +=	-I$(SRC)/uts/sun4u/serengeti
CPPFLAGS +=	-I$(SRC)/uts/sun4u/lw8
CPPFLAGS +=	-I$(SRC)/uts/sun4u -I$(CLOSED)/uts/sun4u
CPPFLAGS +=	-I$(SRC)/uts/common -I$(CLOSED)/uts/common

SRCS =		$(OBJECTS:%.o=%.c)

LIBS =		$(DYNLIB)

ROOTLIBDIR	= $(ROOT_PLAT_PLUGINDIR)

CPPFLAGS +=	-D_SGFRU
CFLAGS +=	$(CCVERBOSE)
DYNFLAGS +=	-R/usr/platform/\$$PLATFORM/lib/picl/plugins:/usr/platform/sun4u/lib/picl/plugins:/usr/lib/picl/plugins
LDLIBS +=	-L$(DEVTREE_SRC_DIR)
LDLIBS +=	-L$(SRC)/lib/libpicltree/$(MACH)
LDLIBS +=	-L$(SRC)/cmd/picl/plugins/common/devtree
LDLIBS +=	-L$(ROOT)/usr/lib/picl/plugins
LDLIBS +=	-lc -lpicldevtree -lpiclmemcfg
LDLIBS +=	-lpicltree -lnvpair -lkstat -ldevice

.KEEP_STATE:

SUBDIRS =

POFILE = piclfrutree.po

all :=		TARGET= all
install :=	TARGET= install
clean :=	TARGET= clean
clobber :=	TARGET= clobber
_msg :=		TARGET= _msg

all: $(LIBS) $(LIBLINKS)

install:	$(ROOTLIBDIR) all $(ROOTLIBS) $(ROOTLINKS)

_msg:	$(MSGDOMAIN) $(POFILE)
	$(RM) $(MSGDOMAIN)/$(POFILE)
	$(CP) $(POFILE) $(MSGDOMAIN)/lw8_$(POFILE)

$(MSGDOMAIN):
	$(INS.dir)

$(LIBLINKS):	FRC
	$(RM) $@; $(SYMLINK) $(DYNLIB) $@

# include library targets
include $(SRC)/lib/Makefile.targ
include	$(SRC)/cmd/picl/plugins/Makefile.targ

lint:

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:
