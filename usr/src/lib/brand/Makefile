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
# Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.
# Copyright (c) 2018, Joyent, Inc.
#
# lib/brand/Makefile
#
# include global definitions
include ../../Makefile.master

#
# Build everything in parallel; use .WAIT for dependencies
.PARALLEL:

i386_SUBDIRS= lx bhyve
i386_MSGSUBDIRS= lx

SUBDIRS= shared .WAIT sn1 solaris10 ipkg labeled $($(MACH)_SUBDIRS)
MSGSUBDIRS= solaris10 shared $($(MACH)_MSGSUBDIRS)

all :=		TARGET= all
install :=	TARGET= install
clean :=	TARGET= clean
clobber :=	TARGET= clobber
lint :=		TARGET= lint
_msg :=		TARGET= _msg

.KEEP_STATE:

all install clean clobber lint: $(SUBDIRS)

_msg: $(MSGSUBDIRS)

$(SUBDIRS): FRC
	@cd $@; pwd; $(MAKE) $(TARGET)

FRC:
