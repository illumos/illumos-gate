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
# Copyright (c) 1990, 2010, Oracle and/or its affiliates. All rights reserved.
# Copyright 2014 Garrett D'Amore <garrett@damore.org>
#

include		../Makefile.cmd

SUBDIRS=	etc lib sbin usr.bin usr.sbin usr.lib usr.sadm
MSGSUBDIRS=	usr.bin usr.sbin usr.lib
POFILES=	usr.bin/usr.bin.po usr.sbin/usr.sbin.po
POFILE=		cmd-inet.po

all:=		TARGET= all
install:=	TARGET= install
clean:=		TARGET= clean
clobber:=	TARGET= clobber
lint:=		TARGET= lint
_msg:=          TARGET= _msg

.KEEP_STATE:

.PARALLEL:	$(SUBDIRS)

all clean install lint: $(SUBDIRS)

clobber:	$(SUBDIRS) local_clobber

local_clobber:
	$(RM) $(CLOBBERFILES)

_msg: $(MSGSUBDIRS)
	$(RM) $(POFILE)
	$(CAT) $(POFILES) > $(POFILE)
	$(RM)  $(MSGDOMAIN)/$(POFILE)
	$(CP) $(POFILE) $(MSGDOMAIN)

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:
