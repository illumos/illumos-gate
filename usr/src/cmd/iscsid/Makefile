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
# Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
# Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
#
PROG= 		iscsid
MANIFEST=	iscsi-initiator.xml
SVCMETHOD=	iscsi-initiator	iscsid

include ../Makefile.cmd

CFLAGS +=	$(CCVERBOSE)
LDLIBS +=	-lnsl

ROOTMANIFESTDIR=	$(ROOTSVCNETWORKISCSI)
$(ROOTSVCNETWORKISCSI)/iscsi-initiator.xml := FILEMODE = 0444

.KEEP_STATE:

LINTFLAGS +=	-erroff=E_BAD_PTR_CAST_ALIGN

all:		$(PROG)

check:		$(CHKMANIFEST)

clean:

install: 	all $(ROOTMANIFEST) $(ROOTSVCMETHOD)

lint:		lint_PROG

include ../Makefile.targ
