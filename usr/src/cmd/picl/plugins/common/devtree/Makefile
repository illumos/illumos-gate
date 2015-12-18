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
# Copyright 2015 RackTop Systems.
#

LIBRARY=	libpicldevtree.a
VERS=		.1

OBJECTS=	picldevtree.o

# include library definitions
include $(SRC)/lib/Makefile.lib

include $(SRC)/cmd/picl/plugins/Makefile.com

SRCS=		$(OBJECTS:%.o=%.c)

LIBS =		$(DYNLIB)

ROOTLIBDIR =	$(USR_LIB_PLUGINDIR)
ROOTETC	=	$(ROOT)/etc
ROOTLIB =	$(ROOT)/usr/lib

CLEANFILES=	$(LINTOUT) $(LINTLIB)
CLOBBERFILES += $(LIBLINKS)

CPPFLAGS +=	-I$(SRC)/lib/libsysevent -I$(SRC)/uts/common

CFLAGS +=	$(CCVERBOSE) $(C_PICFLAGS)
CPPFLAGS +=	-D_REENTRANT
LDLIBS +=	-L$(SRC)/lib/libsysevent -L$(SRC)/lib/libpicltree/$(MACH)
LDLIBS +=	-lc -lkstat -ldevinfo -lpicltree -lnvpair
LDLIBS +=	-L../piclevent -L$(ROOT)/usr/lib/picl/plugins -lpiclevent
LDLIBS +=	-R/usr/platform/\$$PLATFORM/lib/picl/plugins
LDLIBS +=	-R/usr/platform/sun4u/lib/picl/plugins
LDLIBS +=	-R/usr/lib/picl/plugins

LINTFLAGS +=	-L$(SRC)/lib/libpicltree/$(MACH) -lpicltree

.KEEP_STATE:

SUBDIRS=

POFILE=	picldevtree.po

all :=		TARGET= all
install :=	TARGET= install
clean :=	TARGET= clean
clobber :=	TARGET= clobber
lint :=		TARGET= lint
_msg :=		TARGET= _msg

all: $(LIBS) $(LIBLINKS)

install:	$(ROOTLIBDIR) all $(ROOTLIBS) $(ROOTLINKS) 

_msg:	$(MSGDOMAIN) $(POFILE)
	$(RM) $(MSGDOMAIN)/$(POFILE)
	$(CP) $(POFILE) $(MSGDOMAIN)


$(MSGDOMAIN):
	$(INS.dir)

$(LIBLINKS):	FRC
	$(RM) $@; $(SYMLINK) $(DYNLIB) $@

# include library targets
include $(SRC)/cmd/picl/plugins/Makefile.targ
include $(SRC)/lib/Makefile.targ

lint :
	$(LINT.c) $(SRCS)

%.so: %.o
	$(LINK.c) -o $@ $(GSHARED) -h $@ $< $(LDLIBS)

%.o: %.c
	$(COMPILE.c) -o $@ $<

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:
