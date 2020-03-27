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
# lib/libprtdiag_psr/sparc/desktop/nonpicl/Makefile

UTSBASE = $(SRC)/uts

PLATFORM_OBJECTS= desktop.o

objs/%.o pics/%.o: ../common/%.c
	$(COMPILE.c) $(IFLAGS) -o $@ $<
	$(POST_PROCESS_O)

include $(SRC)/lib/libprtdiag_psr/sparc/Makefile.com

SRCS=	$(OBJECTS:%.o=../common/%.c)

IFLAGS += -I$(USR_PLAT_DIR)/sun4u/include -I ../../../../libprtdiag/inc

#
# desktop platform library should install into SUNW,Ultra-2. All other desktop
# platforms can link to /usr/platform/SUNW,Ultra-2/lib/libprtdiag_psr.so
#
PLATFORM=SUNW,Ultra-2

#
# For all other sun4u platforms NOT delivered by ON (ie. delivered by SME or
# external hardware vendors) we add a default library in
# /usr/platform/sun4u/lib so that prtdiag will default to using the desktop
# library for any of these platforms. (this will be a link to
# ../../SUNW,Ultra-2/lib
#
DEF_PLATFORM=sun4u
USR_DEF_PSM_LIB_DIR=$(USR_PLAT_DIR)/$(DEF_PLATFORM)/lib
USR_DEF_PSM_LIBS=$(LIBS:%=$(USR_DEF_PSM_LIB_DIR)/%)

$(USR_PLAT_DIR)/$(PLATFORM)/lib/libprtdiag_psr.so.1 := FILEMODE= 0755

.KEEP_STATE:

PLATLIBS= $(USR_PLAT_DIR)/$(PLATFORM)/lib/

install:	all $(USR_PSM_LIBS) $(USR_DEF_PSM_LIBS)

#
# install rules for SUNW,Ultra-2/lib/libprtdiag_psr.so.1
#
$(USR_PSM_LIB_DIR)/%: % $(USR_PSM_LIB_DIR)
	$(INS.file)

$(USR_PSM_LIB_DIR):
	cd $(UTSBASE)/sun4u; $(MAKE) $(USR_PSM_LIB_DIR)

#
# install rules for sun4u/lib/libprtdiag_psr.so.1
#
$(USR_DEF_PSM_LIB_DIR)/%: % $(USR_DEF_PSM_LIB_DIR)
	$(RM) -r $@; \
	$(SYMLINK) ../../$(PLATFORM)/lib/libprtdiag_psr.so.1 $@

$(USR_DEF_PSM_LIB_DIR):
	cd $(UTSBASE)/sun4u; $(MAKE) $(USR_DEF_PSM_LIB_DIR)


#
# Rules for making message files
#
POFILE=		libprtdiag_psr_desktop.po
POFILES=	desktop.po

_msg:	$(MSGDOMAIN) $(POFILE)
	$(RM) $(MSGDOMAIN)/$(POFILE)
	$(CP) $(POFILE) $(MSGDOMAIN)

$(POFILE):	$(POFILES)
	$(RM) $@
	$(CAT) $(POFILES) > $@

$(POFILES):
	$(RM) messages.po
	$(XGETTEXT) $(XGETFLAGS) `$(GREP) -l gettext ../common/desktop.c`
	$(SED) -e '/^# msg/d' -e '/^domain/d' messages.po > $@
	$(RM) messages.po

