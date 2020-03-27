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
# Copyright 2019 Peter Tribble.
#

include		$(SRC)/Makefile.psm

LIBRARY=	libpiclmemcfg.a
VERS=		.1

OBJECTS=	piclmemcfg.o

# include library definitions
include	$(SRC)/lib/Makefile.lib

ROOT_PLATFORM = $(USR_PLAT_DIR)/SUNW,Sun-Blade-100

include	$(SRC)/cmd/picl/plugins/Makefile.com

SRCS=		$(OBJECTS:%.o=%.c)

LIBS =		$(DYNLIB)

ROOTLIBDIR	= $(ROOT_PLAT_PLUGINDIR)

CPPFLAGS +=	-I$(SRC)/cmd/picl/plugins/common/memcfg
CFLAGS +=	$(CCVERBOSE)
LDLIBS +=	-L$(SRC)/lib/libpicltree/$(MACH)
LDLIBS +=	-L$(SRC)/cmd/picl/plugins/common/devtree
LDLIBS +=	-L$(ROOT)/usr/lib/picl/plugins
LDLIBS +=	-lc -lpicltree -lpicldevtree
LDLIBS +=	-R/usr/platform/\$$PLATFORM/lib/picl/plugins:/usr/platform/sun4u/lib/picl/plugins:/usr/lib/picl/plugins

PLATFORM=	SUNW,Sun-Blade-100

.KEEP_STATE:

SUBDIRS=

all :=		TARGET= all
install :=	TARGET= install
clean :=	TARGET= clean
clobber :=	TARGET= clobber
_msg :=		TARGET= _msg

POFILE=	piclmemcfg.po

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
include	$(SRC)/cmd/picl/plugins/Makefile.targ
include	$(SRC)/lib/Makefile.targ

lint :

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:
