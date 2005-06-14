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
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

PROG = auditd

include ../Makefile.cmd

MANIFEST = auditd.xml
ROOTMANIFESTDIR = $(ROOTSVCSYSTEM)
ROOTMETHOD = $(ROOTLIBSVCMETHOD)/svc-auditd

LIBBSM = $(SRC)/lib/libbsm/common

CPPFLAGS += -D_REENTRANT
CPPFLAGS += -I$(LIBBSM)

LINTFLAGS += -erroff=E_NAME_USED_NOT_DEF2
LINTFLAGS += -m

TEXT_DOMAIN=SUNW_OST_OSCMD

LDLIBS += -lbsm -lnsl -lsecdb -lsocket

OBJS= auditd.o doorway.o queue.o
SRCS= $(OBJS:%.o=%.c)

$(ROOTSVCSYSTEM)/auditd.xml := OWNER = root
$(ROOTSVCSYSTEM)/auditd.xml := GROUP = sys
$(ROOTSVCSYSTEM)/auditd.xml := FILEMODE = 0444

$(ROOTLIBSVCMETHOD)/svc-auditd := OWNER = root
$(ROOTLIBSVCMETHOD)/svc-auditd := GROUP = bin
$(ROOTLIBSVCMETHOD)/svc-auditd := FILEMODE = 0555

.KEEP_STATE:

all:		$(PROG) $(SUBDIRS)

install:	all $(ROOTUSRSBINPROG) $(SUBDIRS) \
		$(ROOTMANIFEST) $(ROOTMETHOD)

$(PROG):	$(OBJS)
		$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
		$(POST_PROCESS)

lint:		lint_SRCS

clean:		$(SUBDIRS)

clobber:	$(SUBDIRS) local_clobber

local_clobber:
		rm -f $(OBJS) $(PROG).po 

check:		$(CHKMANIFEST)

$(SUBDIRS):	FRC
		@cd $@; pwd; $(MAKE) $(TARGET)

FRC:

include ../Makefile.targ
