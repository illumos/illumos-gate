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
# Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
#
# Makefile for the pfexec daemon.
#

PROG=		pfexecd
MANIFEST=	pfexecd.xml
SRCS=		$(PROG:%=%.c)

include ../Makefile.cmd

TARGET=	all

ROOTMANIFESTDIR=	$(ROOTSVCSYSTEM)

LDLIBS += -lsecdb

# install macros and rule
#
GROUP=		bin
ROOTPROG=	$(ROOTLIB)/$(PROG)
$(ROOTPROG)	:= FILEMODE= 555

.KEEP_STATE:

all: $(PROG)

install: all .WAIT $(ROOTPROG) $(ROOTMANIFEST) $(ROOTSVCMETHOD)

clean:

check:	$(CHKMANIFEST)

${ROOTLIB}/%: %
	${INS.file}

lint: lint_SRCS

include ../Makefile.targ
