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
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

LIBRARY=	libpiclfrutree.a
VERS=		.1

OBJECTS=	piclfrutree.o

include $(SRC)/Makefile.psm

# include library definitions
include $(SRC)/lib/Makefile.lib

include $(SRC)/cmd/picl/plugins/Makefile.com

SRCS=		$(OBJECTS:%.o=%.c)

LIBS =		$(DYNLIB)

ROOT_PLATFORM = $(USR_PLAT_DIR)/SUNW,Sun-Fire-280R

ROOTLIBDIR =	$(ROOT_PLAT_PLUGINDIR)

CONF=		piclfrutree.conf
ROOTCONF=	$(CONF:%=$(ROOTLIBDIR)/%)
$(ROOTCONF)	:= FILEMODE = 0644
INFOS=		$(CONF:%.conf=%.info)

CLOBBERFILES += $(LIBLINKS)

CPPFLAGS +=	-I$(SRC)/lib/libdevfsevent -I$(SRC)/uts/common
CPPFLAGS +=	-D_REENTRANT

CFLAGS +=	$(CCVERBOSE)
DEVTREE_SRC_DIR = $(SRC)/cmd/picl/plugins/common/devtree
LDLIBS +=       -L$(DEVTREE_SRC_DIR)
LDLIBS +=       -L$(ROOT)/usr/lib/picl/plugins
LDLIBS +=	-L$(SRC)/lib/libptree/$(MACH)
LDLIBS +=       -lc -lpicltree -lpicldevtree
DYNFLAGS +=	-R/usr/platform/\$$PLATFORM/lib/picl/plugins:/usr/platform/sun4u/lib/picl/plugins:/usr/lib/picl/plugins

.KEEP_STATE:

SUBDIRS=

POFILE=	piclfrutree.po
POFILE_RENAME=	piclfrutree_lneck.po

all :=		TARGET= all
install :=	TARGET= install
clean :=	TARGET= clean
clobber :=	TARGET= clobber
_msg :=		TARGET= _msg

all: $(LIBS) $(LIBLINKS) $(CONF)

install:	all $(ROOTLIBDIR) $(ROOTLIBS) $(ROOTLINKS) $(ROOTCONF)

_msg:	$(MSGDOMAIN) $(POFILE)
	$(RM) $(MSGDOMAIN)/$(POFILE)
	$(CP) $(POFILE) $(MSGDOMAIN)/$(POFILE_RENAME)

$(MSGDOMAIN):
	$(INS.dir)

$(LIBLINKS):	FRC
	$(RM) $@; $(SYMLINK) $(DYNLIB) $@

# include library targets
include $(SRC)/cmd/picl/plugins/Makefile.targ
include $(SRC)/lib/Makefile.targ

lint :

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

$(CONF): $(INFOS)
	$(RM) $@
	$(CPP) piclfrutree.info >$@

FRC:
