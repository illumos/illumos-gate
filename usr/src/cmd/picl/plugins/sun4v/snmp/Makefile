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
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

LIBRARY=	libsnmpplugin.a
VERS=		.1

OBJS_DIR=	pics
OBJECTS=	snmpplugin.o

# Include library definitions
include $(SRC)/lib/Makefile.lib
include $(SRC)/Makefile.psm
include $(SRC)/cmd/picl/plugins/Makefile.com

SRCS=		$(OBJECTS:%.o=%.c)
LIBS =		$(DYNLIB)

ROOT_PLATFORM =	$(USR_PLAT_DIR)/sun4v
ROOTLIBDIR =	$(ROOT_PLAT_PLUGINDIR)

CPPFLAGS +=	-I. -I../include -I$(SRC)/uts/common/sys
CPPFLAGS +=	-D_REENTRANT

#
# Be careful when enabling SNMPPLUGIN_DEBUG. The debug log can quickly
# grow too large. NEVER stress/cycle test picl with SNMPPLUGIN_DEBUG
# enabled
#
#CPPFLAGS +=	-DSNMPPLUGIN_DEBUG

CFLAGS +=	$(CCVERBOSE)
LDLIBS +=	-L$(SRC)/lib/libpicltree/$(MACH)
LDLIBS +=	-L$(SRC)/cmd/picl/plugins/sun4v/lib/snmp
LDLIBS +=	-L$(ROOT)/usr/lib/sparcv9
LDLIBS +=	-lc -lpicltree -lpiclsnmp
DYNFLAGS +=	-R/usr/platform/sun4v/lib

POFILE =	snmpplugin_sun4v.po
POFILES =	$(SRCS:%.c=%.po)

.KEEP_STATE:

all: $(LIBS) $(LIBLINKS)

install:	all $(ROOTLIBDIR) $(ROOTLIBS) $(ROOTLINKS)

$(LIBLINKS):	FRC
	$(RM) $(LIBLINKS); $(SYMLINK) $(DYNLIB) $(LIBLINKS)

# Messages
_msg:	$(MSGDOMAIN) $(POFILE)
	$(RM) $(MSGDOMAIN)/$(POFILE)
	$(CP) $(POFILE) $(MSGDOMAIN)/$(POFILE)

$(MSGDOMAIN):
	$(INS.dir)

$(POFILE):	$(POFILES)
	$(CAT) $(POFILES) > $(POFILE)

# Include library targets
include $(SRC)/cmd/picl/plugins/Makefile.targ
include $(SRC)/lib/Makefile.targ

lint :

FRC:
