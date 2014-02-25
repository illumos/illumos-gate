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
# Copyright 2014 Nexenta Systems, Inc. All rights reserved.
#

PROG= zoneadmd

include ../Makefile.cmd

ROOTCMDDIR=	$(ROOTLIB)/zones

OBJS= zoneadmd.o zcons.o vplat.o
SRCS = $(OBJS:.o=.c)
POFILE=zoneadmd_all.po
POFILES= $(OBJS:%.o=%.po)

CFLAGS += $(CCVERBOSE)
CERRWARN += -_gcc=-Wno-switch
CERRWARN += -_gcc=-Wno-parentheses
CERRWARN += -_gcc=-Wno-uninitialized

LDLIBS += -lsocket -lzonecfg -lnsl -ldevinfo -ldevice -lnvpair \
	-lgen -lbsm -lcontract -lzfs -luuid -lbrand -ldladm -ltsnet -ltsol \
	-linetutil -lscf
XGETFLAGS += -a -x zoneadmd.xcl

.KEEP_STATE:

.PARALLEL:

all: $(PROG)

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

install: all $(ROOTCMD)

$(POFILE): $(POFILES)
	$(RM) $@
	$(CAT) $(POFILES) > $@

clean:
	$(RM) $(OBJS)

lint:	lint_SRCS

check:
	$(CSTYLE) -p -P $(SRCS:%=%)

include ../Makefile.targ
