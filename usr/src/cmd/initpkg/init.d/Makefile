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
# Copyright 2015 Nexenta Systems, Inc. All rights reserved.
#

include		../../Makefile.cmd

sparc_PROG=
i386_PROG=

PROG=		\
	README		\
	sysetup		\
	uucp		\
	$($(MACH)_PROG)


OTHERPROG=	README.rcS README.rc2 README.rc3

ROOTETCINITD=		$(ROOTETC)/init.d
ROOTETCRCSD=		$(ROOTETC)/rcS.d
ROOTETCRC0D=		$(ROOTETC)/rc0.d
ROOTETCRC1D=		$(ROOTETC)/rc1.d
ROOTETCRC2D=		$(ROOTETC)/rc2.d
ROOTETCRC3D=		$(ROOTETC)/rc3.d

DIRS=	$(ROOTETCINITD) \
	$(ROOTETCRCSD) \
	$(ROOTETCRC0D) \
	$(ROOTETCRC1D) \
	$(ROOTETCRC2D) \
	$(ROOTETCRC3D)

ROOTETCINITDPROG=	$(PROG:%=$(ROOTETCINITD)/%)

DIRMODE = 0755
FILEMODE = 0744
$(ROOTETCINITD)/README :=	FILEMODE = 0644
$(ROOTETCRCSD)/README :=	FILEMODE = 0644
$(ROOTETCRC2D)/README :=	FILEMODE = 0644
$(ROOTETCRC3D)/README :=	FILEMODE = 0644

.KEEP_STATE:

all:		$(PROG)

# Don't re-install directories already installed by Targetdirs
#$(DIRS):
#		$(INS.dir)

$(ROOTETCINITD)/%:	%
		$(INS.file)

$(ROOTETCRCSD)/%:	%.rcS
		$(INS.rename)

$(ROOTETCRC2D)/%:	%.rc2
		$(INS.rename)

$(ROOTETCRC3D)/%:	%.rc3
		$(INS.rename)

install:	all $(ROOTETCINITDPROG) \
		$(ROOTETCRCSD)/README \
		$(ROOTETCRC2D)/README \
		$(ROOTETCRC3D)/README

lint:

clean:

clobber:
