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
# lib/libprtdiag_psr/sparc/desktop/picl/Makefile

UTSBASE = $(SRC)/uts

PLATFORM_OBJECTS= picldiag.o

objs/%.o pics/%.o: ../common/%.c
	$(COMPILE.c) $(IFLAGS) -o $@ $<
	$(POST_PROCESS_O)

include $(SRC)/lib/libprtdiag_psr/sparc/Makefile.com

SRCS=	$(OBJECTS:%.o=../common/%.c)

LDLIBS += -lpicl

IFLAGS += -I$(USR_PLAT_DIR)/sun4u/include -I ../../../../libprtdiag/inc
IFLAGS += -I$(SRC)/cmd/picl/plugins/inc

#
# links in /usr/platform
#
LINKED_PLATFORMS	= SUNW,Sun-Blade-1000 SUNW,Netra-T4
LINKED_PLATFORMS	+= SUNW,Sun-Blade-1500
LINKED_PLATFORMS	+= SUNW,Sun-Blade-2500
LINKED_PLATFORMS	+= SUNW,A70
LINKED_PLATFORMS	+= SUNW,Sun-Fire-V445
LINKED_PLATFORMS	+= SUNW,Sun-Fire-V215
LINKED_PLATFORMS	+= SUNW,Sun-Fire-V240
LINKED_PLATFORMS	+= SUNW,Sun-Fire-V250
LINKED_PLATFORMS	+= SUNW,Sun-Fire-V440

LINKED_DIRS		= $(LINKED_PLATFORMS:%=$(USR_PLAT_DIR)/%)
LINKED_LIB_DIRS		= $(LINKED_PLATFORMS:%=$(USR_PLAT_DIR)/%/lib)
LINKED_PRTDIAG_DIRS	= \
	$(LINKED_PLATFORMS:%=$(USR_PLAT_DIR)/%/lib/libprtdiag_psr.so.1)

#
# Sun-Blade-100 and Sun-Blade-1000 platform library should install into
# SUNW,Sun-Blade-100. Sun-Blade-100 platforms can
# link to /usr/platform/SUNW,Sun-Blade-100/lib/libprtdiag_psr.so
#
PLATFORM=	SUNW,Sun-Blade-100

$(USR_PLAT_DIR)/$(PLATFORM)/lib/libprtdiag_psr.so.1 := FILEMODE= 0755

.KEEP_STATE:

PLATLIBS=	$(PLATFORM:%=$(USR_PLAT_DIR)/%/lib/)

install:	all $(PLATLIBS) $(USR_PSM_LIBS) \
		$(LINKED_PRTDIAG_DIRS)

#
# install rules for SUNW,Sun-Blade-100/lib/libprtdiag_psr.so.1
#
$(PLATLIBS):
	$(INS.dir)

$(USR_PSM_LIB_DIR)/%: % $(USR_PSM_LIB_DIR)
	$(INS.file)

$(USR_PSM_LIB_DIR):
	$(INS.dir)

$(LINKED_DIRS):	$(USR_PLAT_DIR)
	-$(INS.dir)

$(LINKED_LIB_DIRS):	$(LINKED_DIRS)
	-$(INS.dir)

$(LINKED_PRTDIAG_DIRS):	$(LINKED_LIB_DIRS)
	-$(INS.slink6)

#
# Rules for making message files
#
POFILE=		libprtdiag_psr_desktop_picl.po
POFILES=	desktop.po

_msg:	$(MSGDOMAIN) $(POFILE)
	$(RM) $(MSGDOMAIN)/$(POFILE)
	$(CP) $(POFILE) $(MSGDOMAIN)

$(POFILE):	$(POFILES)
	$(RM) $@
	$(CAT) $(POFILES) > $@

$(POFILES):
	$(RM) messages.po
	$(XGETTEXT) $(XGETFLAGS) `$(GREP) -l gettext ../common/picldiag.c`
	$(SED) -e '/^# msg/d' -e '/^domain/d' messages.po > $@
	$(RM) messages.po

