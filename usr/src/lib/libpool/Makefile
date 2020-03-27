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

include ../Makefile.lib

SUBDIRS=	$(MACH)
$(BUILD64)SUBDIRS += $(MACH64)

all :=		TARGET = all
clean :=	TARGET = clean
clobber :=	TARGET = clobber
debug :=	TARGET = debug
delete :=	TARGET = delete
install :=	TARGET = install

#
# Definitions for header files
#

HDRS =		pool.h
ROOTHDRDIR =	$(ROOT)/usr/include
ROOTHDRS =	$(HDRS:%=$(ROOTHDRDIR)/%)
CHECKHDRS =	$(HDRS:%.h=common/%.check)
$(ROOTHDRS) :=	FILEMODE= 644

$(ROOTHDRDIR)/%: common/%
	$(INS.file)

#
# Definitions for message catalogue
#
MSGFILES =	`$(GREP) -l gettext common/*.[ch]`
POFILE =	libpool.po

#
# Definitions for DTDs
#
DTDS =		dtd/rm_pool.dtd.1
XMLDIR =	$(ROOT)/usr/share/lib/xml
ROOTDTDS=	$(DTDS:%=$(XMLDIR)/%)

$(ROOTDTDS) :=	FILEMODE = 444

$(XMLDIR)/%: %
	$(INS.file)

.KEEP_STATE:

all clean clobber install: $(SUBDIRS)

$(POFILE):	pofile_MSGFILES

install:	$(ROOTDTDS)

install_h:	$(ROOTHDRS)

check:		$(CHECKHDRS)

_msg:		$(MSGDOMAINPOFILE)

$(SUBDIRS):	FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:

include ../Makefile.targ
include ../../Makefile.msg.targ
