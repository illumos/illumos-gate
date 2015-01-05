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
# Copyright 2014 Shruti V Sampat <shrutisampat@gmail.com>
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

PROG= utmpd
DEFAULTFILES= utmpd.dfl
MANIFEST= utmp.xml
SVCMETHOD= svc-utmpd

include ../Makefile.cmd

ROOTMANIFESTDIR = $(ROOTSVCSYSTEM)

FILEMODE = 555

.KEEP_STATE:

all: $(PROG)

install: all $(DIRS) $(ROOTLIBPROG) $(ROOTETCDEFAULTFILES) $(ROOTMANIFEST) \
	$(ROOTSVCMETHOD)

check:	$(CHKMANIFEST)

clean:

lint:	lint_PROG

include ../Makefile.targ
