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
# lib/libprtdiag_psr/sparc/serengeti/Makefile

UTSBASE   = ../../../../uts

PLATFORM_OBJECTS= serengeti.o

include ../Makefile.com

IFLAGS += -I$(USR_PLAT_DIR)/sun4u/include -I ../../../libprtdiag/inc
IFLAGS += -I$(UTSBASE)/sun4u/serengeti
IFLAGS += -I$(UTSBASE)/sun4u

LDLIBS += -lcfgadm

PLATFORM=SUNW,Sun-Fire


$(USR_PLAT_DIR)/$(PLATFORM)/lib/libprtdiag_psr.so.1 := FILEMODE= 0755

.KEEP_STATE:

PLATLIBS= $(USR_PLAT_DIR)/$(PLATFORM)/lib/

install:	all $(USR_PSM_LIBS)

$(USR_PSM_LIB_DIR):
	cd $(UTSBASE)/sun4u/serengeti; $(MAKE) $(USR_PSM_LIB_DIR)
#
# install rule
#
$(USR_PSM_LIB_DIR)/%: % $(USR_PSM_LIB_DIR)
	$(INS.file)

#
# used for message files
#
POFILE=		libprtdiag_psr_serengeti.po
POFILES=	serengeti.po


_msg:	$(MSGDOMAIN) $(POFILE)
	$(RM) $(MSGDOMAIN)/$(POFILE)
	$(CP) $(POFILE) $(MSGDOMAIN)

$(POFILE):	$(POFILES)
	$(RM) $@
	$(CAT) $(POFILES) > $@

$(POFILES):
	$(RM) messages.po
	$(XGETTEXT) $(XGETFLAGS) `$(GREP) -l gettext common/serengeti.c`
	$(SED) -e '/^# msg/d' -e '/^domain/d' messages.po > $@
	$(RM) messages.po
