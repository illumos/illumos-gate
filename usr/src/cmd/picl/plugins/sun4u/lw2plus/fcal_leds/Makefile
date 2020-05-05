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

LIBRARY=	libfcal_leds.a
VERS=		.1

OBJECTS=	fcal_leds.o fc_led_parse.o fcal_leds_thread.o

# include library definitions
include $(SRC)/lib/Makefile.lib

ROOT_PLATFORM = $(USR_PLAT_DIR)/SUNW,Netra-T4

include	$(SRC)/cmd/picl/plugins/Makefile.com

SRCS=		$(OBJECTS:%.o=%.c)

LIBS =		$(DYNLIB)

ROOTLIBDIR	= $(ROOT_PLAT_PLUGINDIR)

CONF=		fcal_leds.conf
ROOTCONF=	$(CONF:%=$(ROOTLIBDIR)/%)
$(ROOTCONF)	:= FILEMODE = 0644

CPPFLAGS +=	-I$(SRC)/uts/sun4u/ -I$(SRC)/uts/common/
CPPFLAGS +=	-D_POSIX_PTHREAD_SEMANTICS
CPPFLAGS +=	-D_REENTRANT

# Components of load time linker path.
# These paths start at / on the target machine, so don't use $(ROOT).
# However, to silence makestyle use empty string $(RUNTIMEROOT)
RUNTIMEROOT =
PICLPLATDYN =	$(RUNTIMEROOT)/usr/platform/\$$PLATFORM/lib/picl/plugins
PICLARCHDYN =	$(RUNTIMEROOT)/usr/platform/sun4u/lib/picl/plugins
PICLGENDYN =	$(RUNTIMEROOT)/usr/lib/picl/plugins

DYNFLAGS +=	-R$(PICLPLATDYN):$(PICLARCHDYN):$(PICLGENDYN)
LDLIBS +=	-L$(SRC)/lib/libpicltree/$(MACH)
LDLIBS +=	-L$(SRC)/cmd/picl/plugins/common/devtree
LDLIBS +=	-L$(SRC)/cmd/picl/plugins/common/piclevent
LDLIBS +=	-L$(SRC)/cmd/picl/plugins/common/frutree
LDLIBS +=	-L$(SRC)/cmd/picl/plugins/common/memcfg
LDLIBS +=	-lpicltree -lpicldevtree -lpiclfrutree -lnvpair
LDLIBS +=	-ldevinfo -lc

.KEEP_STATE:

SUBDIRS=

all :=		TARGET= all
install :=	TARGET= install
clean :=	TARGET= clean
clobber :=	TARGET= clobber
_msg :=		TARGET= _msg

POFILE =	piclfcal_leds_lw2plus.po
POFILES =	$(SRCS:%.c=%.po)

all:		$(LIBS) $(LIBLINKS)

install:	$(ROOTLIBDIR) all $(ROOTLIBS) $(ROOTLINKS) $(ROOTCONF)

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
