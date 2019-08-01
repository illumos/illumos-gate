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
# Copyright (c) 1998, 2010, Oracle and/or its affiliates. All rights reserved.
# Copyright 2019 Joyent, Inc.
#

PROG = dumpadm
MANIFEST = dumpadm.xml
SVCMETHOD= svc-dumpadm
ETCFILES= dumpadm.conf

OBJS = main.o dconf.o minfree.o utils.o swap.o
SRCS = $(OBJS:.o=.c)

ROOTETCFILES= $(ETCFILES:%=$(ROOTETC)/%)

include ../Makefile.cmd

CFLAGS += $(CCVERBOSE)

FILEMODE = 0555

ROOTMANIFESTDIR = $(ROOTSVCSYSTEM)

LDLIBS +=	-ldiskmgt -lzfs -luuid

.KEEP_STATE:

all: $(PROG)

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

install: all $(ROOTUSRSBINPROG) $(ROOTMANIFEST) $(ROOTSVCMETHOD) $(ROOTETCFILES)

check: $(CHKMANIFEST)

clean:
	$(RM) $(OBJS)

include ../Makefile.targ
