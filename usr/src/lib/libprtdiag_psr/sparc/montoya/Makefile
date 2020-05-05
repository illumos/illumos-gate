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
# lib/libprtdiag_psr/sparc/montoya/Makefile

UTSCLOSED = ../../../../uts
UTSBASE   = ../../../../../src/uts

PLATFORM_OBJECTS= montoya.o

include ../Makefile.com

#
# Override the PSR_MACH variable to use sun4v libraries
#
PSR_MACH=sun4v

IFLAGS +=  -I ../../../libprtdiag/inc
IFLAGS += -I$(SRC)/cmd/picl/plugins/inc
LDLIBS += -lpicl


PLATFORM=SUNW,Netra-CP3060

$(USR_PLAT_DIR)/$(PLATFORM)/lib/libprtdiag_psr.so.1 := FILEMODE= 0755

.KEEP_STATE:

PLATLIBS= $(USR_PLAT_DIR)/$(PLATFORM)/lib

install:	all $(USR_PSM_LIBS) $(LINKED_PRTDIAG_DIRS)

#
# install rules
#

$(USR_PSM_LIB_DIR)/%: % $(USR_PSM_LIB_DIR)
	$(INS.file)

$(USR_PSM_LIB_DIR):
	$(INS.dir)

$(LINKED_DIRS):	$(USR_PLAT_DIR)
	-$(INS.dir)

$(LINKED_LIB_DIRS):	$(LINKED_DIRS)
	-$(INS.dir)

$(LINKED_PRTDIAG_DIRS):	$(USR_PLAT_DIR)
	-$(INS.slink6)

#
# used for message files
#
POFILE=		libprtdiag_psr_monto.po
POFILES=	monto.po


_msg:	$(MSGDOMAIN) $(POFILE)
	$(RM) $(MSGDOMAIN)/$(POFILE)
	$(CP) $(POFILE) $(MSGDOMAIN)

$(POFILE):	$(POFILES)
	$(RM) $@
	$(CAT) $(POFILES) > $@

$(POFILES):
	$(RM) messages.po
	$(XGETTEXT) $(XGETFLAGS) `$(GREP) -l gettext common/montoya.c`
	$(SED) -e '/^# msg/d' -e '/^domain/d' messages.po > $@
	$(RM) messages.po
