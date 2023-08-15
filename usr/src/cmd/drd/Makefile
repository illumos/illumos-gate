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
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

#
# Makefile definitions for sun4v DR Daemon (drd)
#

PROG=		drd
MANIFEST=	drd.xml
SVCMETHOD=	svc-drd

include ../Makefile.cmd
include ../../Makefile.psm

CLASS=		32

PLATFORM=	sun4v

SRCS=		drd.c		\
		drd_log.c	\
		drd_rcm.c

HDRS=		drd.h

OBJS=		$(SRCS:%.c=%.o)

LINT_SRCS=	$(SRCS)
LINT_FILES=	$(LINT_SRCS:%.c=%.ln)

ROOTCMDDIR=		$(ROOTLIB)/ldoms
ROOTMANIFESTDIR=	$(ROOTSVCPLATFORMSUN4V)
$(ROOTMANIFEST)		:= FILEMODE= 444

#
# FLAGS:
#
CPPFLAGS= 	-I$(SRC)/uts/sun4v $(CPPFLAGS.master) -D_REENTRANT

LINT_FLAGS=	-c -Nlevel=4 -Ncheck

XGETFLAGS +=	-a -s -x $(PROG).xcl

CERRWARN += -_gcc=-Wno-parentheses


#
# LIBRARIES:
#
LDLIBS +=	-lkstat		\
		-lnvpair	\
		-lrcm

.KEEP_STATE:


all: $(PROG)

$(PROG): $(OBJS) $(HDRS)
	$(CC) -o $@ $(OBJS) $(LDFLAGS) $(LDLIBS)
	$(POST_PROCESS)

install: all .WAIT $(ROOTCMD) $(ROOTMANIFEST) $(ROOTSVCMETHOD)

check:	$(CHKMANIFEST)

lint:
	$(LINT) $(LINT_FLAGS) $(CPPFLAGS) $(LINT_SRCS)

clean:
	$(RM) $(PROG) $(OBJS) $(LINT_FILES)

include ../Makefile.targ
include ../../Makefile.psm.targ
