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
# lib/libprtdiag_psr/sparc/snowbird/Makefile
#
# Need to make libctsmc library first.
#
LIBCTSMC = ../../../../../src/cmd/picl/plugins/sun4u/snowbird/lib/libctsmc
all: ctsmclib
ctsmclib: $(LIBCTSMC)/libctsmc.c $(LIBCTSMC)/smclib.h
	cd $(LIBCTSMC); $(MAKE)

LIBBASE   = ../../../../../src/lib
UTSBASE   = ../../../../uts
SUN4U_INC_BASE = $(UTSBASE)/sun4u/sys
SB_INC_BASE =  $(UTSBASE)/sun4u/snowbird/sys

PLATFORM_OBJECTS= snowbird.o

include ../Makefile.com

IFLAGS = -I$(USR_PLAT_DIR)/sun4u/include -I../../../libprtdiag/inc -I$(LIBBASE)/libdevinfo
IFLAGS += -I$(SUN4U_INC_BASE) -I$(SB_INC_BASE) -I$(SRC)/cmd/picl/plugins/inc
IFLAGS += -I$(LIBCTSMC)
LINTFLAGS += $(IFLAGS)
LDLIBS += -L$(LIBCTSMC)
LDLIBS += -L$(LIBBASE)/libdevinfo -ldevinfo -L$(LIBBASE)/libcfgadm \
		 -lcfgadm -lpicl -lctsmc
DYNFLAGS += -R/usr/platform/SUNW,Netra-CP2300/lib


#
# SUNW,Netra-CP2300 platform can link to
# /usr/platform/SUNW,Netra-CP2300/lib/libprtdiag_psr.so
#
PLATFORM=SUNW,Netra-CP2300

$(USR_PLAT_DIR)/$(PLATFORM)/lib/libprtdiag_psr.so.1 := FILEMODE= 0755

.KEEP_STATE:

PLATLIBS= $(PLATFORM:%=$(USR_PLAT_DIR)/%/lib/)

install:	all $(PLATLIBS) $(USR_PSM_LIBS)

#
# install rules for SUNW,Netra-CP2300/lib/libprtdiag_psr.so
#
$(PLATLIBS):
	$(INS.dir)

$(USR_PSM_LIB_DIR):
	cd $(UTSBASE)/sun4u/snowbird; $(MAKE) $(USR_PSM_LIB_DIR)

$(USR_PSM_LIB_DIR)/%: % $(USR_PSM_LIB_DIR)
	$(INS.file)

# New additions to generate msg file
POFILE =	libprtdiag_psr_snowbird.po
POFILES =	snowbird.po

_msg:	$(MSGDOMAIN) $(POFILE)
	$(RM) $(MSGDOMAIN)/$(POFILE)
	$(CP) $(POFILE) $(MSGDOMAIN)

$(POFILE):	$(POFILES)
		$(RM) $@
		$(CAT) $(POFILES) > $@
 
$(POFILES):
	$(RM) messages.po
	$(XGETTEXT) $(XGETFLAGS) `$(GREP) -l gettext common/snowbird.c`
	$(SED) -e '/^# msg/d' -e '/^domain/d' messages.po > $@
	$(RM) messages.po
