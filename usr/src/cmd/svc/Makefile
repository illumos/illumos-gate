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
# Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

include ../Makefile.cmd

SUBDIR_CMD=		\
	lsvcrun		\
	mfstscan	\
	rootisramdisk	\
	servinfo	\
	svcadm		\
	svccfg		\
	svcprop		\
	svcs

SUBDIRS=		\
	configd		\
	milestone	\
	profile		\
	seed		\
	shell		\
	startd		\
	$(SUBDIR_CMD)

all :=		TARGET = all
install :=	TARGET = install
clean :=	TARGET = clean
clobber :=	TARGET = clobber
_msg :=		TARGET = _msg

.KEEP_STATE:

#
# Definitions for DTDs
#
DTDS =		dtd/service_bundle.dtd.1
XMLDIR =	$(ROOT)/usr/share/lib/xml
ROOTDTDS =	$(DTDS:%=$(XMLDIR)/%)

$(ROOTDTDS) :=	FILEMODE = 444

#
# Definitions for class action scripts
#

CLASSACTIONS = i.manifest r.manifest
ROOTCLASSACTIONS = $(CLASSACTIONS:%=$(ROOT)/usr/sadm/install/scripts/%)

install: $(ROOTDTDS) $(ROOTCLASSACTIONS)

all install clean clobber: $(SUBDIRS)

_msg: $(SUBDIR_CMD) startd

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

$(XMLDIR)/%: %
	$(INS.file)

$(ROOT)/usr/sadm/install/scripts/%: common/%
	$(INS.file)

FRC:
