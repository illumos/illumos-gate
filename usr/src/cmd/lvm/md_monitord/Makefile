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
#pragma ident	"%Z%%M%	%I%	%E% SMI"
#
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

#
# Makefile for logical volume management
#
#
# cmd/lvm/md_monitord/Makefile

PROG= mdmonitord
MANIFEST= mdmonitor.xml
SVCMETHOD= svc-mdmonitor

include ../../Makefile.cmd
include ../Makefile.lvm

SUBDIRS=	$(MACH)

SRCS=	probedev.c md_monitord.c

CLOBBERFILES += $(SVCMETHOD)

#
# i18n: For catalog we need to put messages from $(SRCS) and $(SVCMETHOD).sh
# into "`basename $PWD`p.po" = md_monitordp.po = $(POFILE) (that's what
# ../Makefile expects).  We'll use $(BUILDPO.pofiles) to build $(POFILE) from
# $(MDPO) and $(SVCMETHODPO), and we'll use $(BUILDPO.msgfiles) to build
# $(MDPO) from $(SRCS).  The catch is that $(BUILDPO.msgfiles) is defined to
# produce $(POFILE).  Fortunately we can conditionally define POFILE = MDPO
# when building MDPO.  make complains when this conditional definition is
# before we include Makefile.msg.targ, so it must lie at the end.
#
MSGFILES= $(SRCS:%.c=%.i)
MDPO= $(PROG:%=%.po)
SVCMETHODPO= $(SVCMETHOD:%=%.po)
POFILES= $(MDPO) $(SVCMETHODPO)
POFILE= md_monitordp.po

ROOTMANIFESTDIR=	$(ROOTSVCSYSTEM)

$(ROOTSVCMETHOD):	$(SVCMETHOD)

all     :=      TARGET = all
install :=      TARGET = install
clean   :=      TARGET = clean
clobber :=      TARGET = clobber
lint    :=      TARGET = lint

.KEEP_STATE:

all clobber lint:    $(SUBDIRS)

$(MDPO):	$(MSGFILES)
	$(BUILDPO.msgfiles)

$(POFILE):	$(POFILES)
	$(BUILDPO.pofiles)

catalog:	$(POFILE)

check:	$(CHKMANIFEST)

clean: $(SUBDIRS)
	$(RM) $(MSGFILES)

install:	$(SUBDIRS) $(ROOTMANIFEST) $(ROOTSVCMETHOD)

$(SUBDIRS):	FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:

include ../../Makefile.targ
include $(SRC)/Makefile.msg.targ

$(MDPO) :=	POFILE = $(MDPO)
