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
# Copyright 1996, Sun Microsystems
# All rights reserved.
#
# Makefile definitions for volume management
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# cmd/volmgt/Makefile
#

include ../Makefile.cmd

SUBDIRS1 = util vold rmm
SUBDIRS2 = etc
SUBDIRS	= $(SUBDIRS1) $(SUBDIRS2)

CAT=	cat

#
# for messaging catalog
#
POFILE= volmgt.po
POFILES= $(SUBDIRS1:%=%/%.po)

all :=		TARGET= all
install :=	TARGET= install
clean :=	TARGET= clean
clobber :=	TARGET= clobber
lint :=		TARGET= lint
cstyle :=	TARGET= cstyle
_msg :=		TARGET= catalog

.KEEP_STATE:

all install cstyle lint clean clobber: $(SUBDIRS)

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

_msg: $(SUBDIRS1)
	$(RM) $(POFILE)
	$(CAT) $(POFILES) > $(POFILE)
	$(RM) $(MSGDOMAIN)/$(POFILE)
	$(CP) $(POFILE) $(MSGDOMAIN)/$(POFILE)

FRC:
