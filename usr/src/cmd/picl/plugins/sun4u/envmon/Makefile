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
# cmd/picl/plugins/sun4u/envmon/Makefile
#
include	$(SRC)/Makefile.psm

LIBRARY=	libpiclenvmon.a
VERS=		.1

OBJECTS=	piclenvmon.o

# include library definitions
include $(SRC)/lib/Makefile.lib

ROOT_PLATFORM = $(USR_PLAT_DIR)/sun4u

include	$(SRC)/cmd/picl/plugins/Makefile.com

SRCS=		$(OBJECTS:%.o=%.c)

LIBS =		$(DYNLIB)

ROOTLIBDIR	= $(ROOT_PLAT_PLUGINDIR)

CPPFLAGS +=	-I$(SRC)/uts/sun4u/ -I$(SRC)/uts/common/
CPPFLAGS +=	-I$(SRC)/cmd/picl/plugins/lib/picld_pluginutil
CPPFLAGS +=	-D_REENTRANT
CFLAGS +=	$(CCVERBOSE)
DYNFLAGS +=	-R/usr/platform/sun4u/lib/picl/plugins:/usr/lib/picl/plugins
LDLIBS +=	-L$(SRC)/cmd/picl/plugins/lib/picld_pluginutil/$(MACH)
LDLIBS +=	-L$(SRC)/lib/libpicltree/$(MACH)
LDLIBS +=	-L$(SRC)/cmd/picl/plugins/common/piclevent
LDLIBS +=	-L$(SRC)/cmd/picl/plugins/common/memcfg
LDLIBS +=	-L$(SRC)/cmd/picl/plugins/common/devtree
LDLIBS +=	-lnvpair -ldevinfo -lc
LDLIBS +=	-lpicltree -lpicld_pluginutil -lpiclevent -lpicldevtree

.KEEP_STATE:

SUBDIRS=

all :=		TARGET= all
install :=	TARGET= install
clean :=	TARGET= clean
clobber :=	TARGET= clobber
_msg :=		TARGET= _msg

POFILE =	piclenvmon_sun4u.po
POFILES =	$(SRCS:%.c=%.po)

all: $(LIBS) $(LIBLINKS)

install:	$(ROOTLIBDIR) all $(ROOTLIBS) $(ROOTLINKS)

$(POFILE):	$(POFILES)
	$(CAT) $(POFILES) > $(POFILE)

_msg:	$(MSGDOMAIN) $(POFILE)
	$(RM) $(MSGDOMAIN)/$(POFILE)
	$(CP) $(POFILE) $(MSGDOMAIN)/$(POFILE)

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

