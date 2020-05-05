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
#

include	../Makefile.lib
HDRS=		libgrubmgmt.h
HDRDIR=		common

POFILE =	libgrubmgmt.po
POFILES =	common/libgrub_errno.po

SUBDIRS =	$(MACH)

# conditional assignments
all :=		TARGET= all
install :=      TARGET= install
clean :=        TARGET= clean
clobber :=      TARGET= clobber
test :=         TARGET= test

.KEEP_STATE:

all install clean clobber: $(SUBDIRS)

install_h: $(ROOTHDRS)

check: $(CHECKHDRS)

$(POFILE): $(POFILES)
	$(RM) $@
	$(CAT) $(POFILES) > $@

_msg: $(MSGDOMAINPOFILE)

$(SUBDIRS):	FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

include ../Makefile.targ
include ../../Makefile.msg.targ

common/libgrub_errno.po := XGETFLAGS += -a

FRC:
