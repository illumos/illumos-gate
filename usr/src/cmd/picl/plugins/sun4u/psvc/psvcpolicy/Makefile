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

LIBRARY=	libpsvcpolicy.a
VERS=		.1

OBJECTS=	psvcpolicy.o

# include library definitions
include $(SRC)/lib/Makefile.lib
include $(SRC)/Makefile.psm

include $(SRC)/cmd/picl/plugins/Makefile.com

SRCS=		$(OBJECTS:%.o=%.c)

LIBS =		$(DYNLIB)

PLATFORM = sun4u

USR_PLAT_PSVCPOL = $(LIBS:%=$(USR_PSM_LIB_DIR)/%)

CPPFLAGS +=	-I$(SRC)/uts/sun4u
CPPFLAGS +=	-I$(SRC)/cmd/picl/plugins/sun4u/psvc/psvcobj

ZDEFS =
CFLAGS +=	$(CCVERBOSE)
LDLIBS +=	$(ZNODEFS)
LDLIBS +=	-L$(SRC)/lib/libpicl/$(MACH) -L$(SRC)/lib/libpicltree/$(MACH)
LDLIBS +=	-L$(SRC)/cmd/picl/plugins/sun4u/psvc/psvcobj
LDLIBS +=	-L$(SRC)/cmd/picl/plugins/sun4u/psvc/psvcplugin
LDLIBS +=	-lc -lpsvcobj -lpsvcplugin -lpicltree

DYNFLAGS +=	-Wl,-f/usr/platform/\$$PLATFORM/lib/$(DYNLIBPSR)
DYNFLAGS +=	-R/usr/platform/\$$PLATFORM/lib/picl/plugins:/usr/platform/sun4u/lib/picl/plugins:/usr/lib/picl/plugins:/usr/platform/sun4u/lib

.KEEP_STATE:

SUBDIRS=

POFILE=	psvcpolicy.po

all :=		TARGET= all
install :=	TARGET= install
clean :=	TARGET= clean
clobber :=	TARGET= clobber
_msg :=		TARGET= _msg

all: $(LIBS) $(LIBLINKS)

install:	all $(USR_PLAT_PSVCPOL)

$(LIBLINKS):	FRC
	$(RM) $(LIBLINKS); $(SYMLINK) $(DYNLIB) $(LIBLINKS)


# include library targets
include $(SRC)/cmd/picl/plugins/Makefile.targ
include $(SRC)/lib/Makefile.targ

_msg:	$(MSGDOMAIN) $(POFILE)
	$(RM) $(MSGDOMAIN)/$(POFILE)
	$(CP) $(POFILE) $(MSGDOMAIN)/$(POFILE)

$(MSGDOMAIN):
	$(INS.dir)

$(USR_PSM_LIB_DIR)/%: % $(USR_PSM_LIB_DIR)
	$(INS.file) ;\
	$(RM) -r $(USR_PSM_LIB_DIR)/libpsvcpolicy.so; \
	$(SYMLINK) ./libpsvcpolicy.so$(VERS) $(USR_PSM_LIB_DIR)/libpsvcpolicy.so

lint :

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:
