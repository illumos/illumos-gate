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
#ident	"%Z%%M%	%I%	%E% SMI"
#
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# cmd/consadm/Makefile
#

PROG=		consadm
MANIFEST=	consadm.xml

include ../Makefile.cmd

SUBDIRS=	$(MACH)

ROOTMANIFESTDIR=	$(ROOTSVCSYSTEM)
ROOTMETHOD=		$(ROOTLIBSVCMETHOD)/svc-consadm

all	:=	TARGET = all
install	:=	TARGET = install
clean	:=	TARGET = clean
clobber	:=	TARGET = clobber
lint	:=	TARGET = lint

$(ROOTMANIFEST)	:=	FILEMODE = 444

$(ROOTMETHOD) :=	OWNER = root
$(ROOTMETHOD) :=	GROUP = bin
$(ROOTMETHOD) :=	FILEMODE = 0555

.KEEP_STATE:

all clean clobber lint:	$(SUBDIRS)

install: $(SUBDIRS) $(ROOTMANIFEST) $(ROOTMETHOD)

check:	$(CHKMANIFEST)

$(SUBDIRS):	FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

$(ROOTMANIFESTDIR)/%: %
	$(INS.file)

FRC:

include ../Makefile.targ
