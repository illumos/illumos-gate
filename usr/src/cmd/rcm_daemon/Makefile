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
# Copyright (c) 1999-2001 by Sun Microsystems, Inc.
# All rights reserved.
#
# cmd/rcm_daemon/Makefile
#

include ../Makefile.cmd

#
# One for each ISA.
#
SUBDIRS=	$(MACH)

all	:=	TARGET= all
install	:=	TARGET= install
clean	:=	TARGET= clean
clobber	:=	TARGET= clobber
_msg	:=	TARGET= _msg
install_h :=	TARGET= install_h

#definitions for install_h target
HDRS=		rcm_module.h
ROOTHDRDIR=	$(ROOT)/usr/include
ROOTHDRS=	$(HDRS:%=$(ROOTHDRDIR)/%)
CHECKHDRS=	$(HDRS:%.h=common/%.check)
$(ROOTHDRS) := FILEMODE = 644

.KEEP_STATE:

install:	install_h $(SUBDIRS)

all _msg:	install_h $(SUBDIRS)
clean clobber:	$(SUBDIRS)

$(SUBDIRS):	FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

install_h:	$(ROOTHDRS)

check:		$(CHECKHDRS)

$(ROOTHDRDIR)/%: common/%
	$(INS.file)

$(ROOTHDRDIR):
	$(INS.dir)

common/%.check:	common/%.h
	$(DOT_H_CHECK)

FRC:

#include ../Makefile.targ
