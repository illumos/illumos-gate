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
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

include ../Makefile.lib

HDRS =		libdiskmgt.h
ROOTHDRDIR=	$(ROOT)/usr/include
ROOTHDRS=	$(HDRS:%=$(ROOTHDRDIR)/%)
CHECKDIRS=	$(HDRS:%.h=%.check)
HDRDIR =	common

SUBDIRS =	$(MACH)
$(BUILD64)SUBDIRS += $(MACH64)

$(ROOTHDRDIR)/%: %
	$(INS.file)

all :=		TARGET = all
clean :=	TARGET = clean
clobber	:=	TARGET = clobber
install	:=	TARGET = install
install_h:=	TARGET = install_h

POFILE =        libdiskmgt.po
MSGFILES =      `$(GREP) -l gettext common/*.[ch]`

.KEEP_STATE:

all clean clobber install: $(SUBDIRS)

$(POFILE):      pofile_MSGFILES

install_h: $(ROOTHDRS)

check:		$(CHECKHDRS)

_msg: $(MSGDOMAINPOFILE)

$(SUBDIRS):	FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:

include ../Makefile.targ
include ../../Makefile.msg.targ
