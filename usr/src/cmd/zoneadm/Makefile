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
# Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
#

PROG=		zoneadm
MANIFEST=	zones.xml resource-mgmt.xml
SVCMETHOD=	svc-zones svc-resource-mgmt

include ../Makefile.cmd

ROOTMANIFESTDIR=        $(ROOTSVCSYSTEM)

OBJS= zoneadm.o zfs.o
SRCS = $(OBJS:.o=.c)
POFILE=zoneadm_all.po
POFILES= $(OBJS:%.o=%.po)

LDLIBS += -lzonecfg -lsocket -lgen -lpool -lzfs -luuid -lnvpair -lbrand -ldladm -lsecdb

INCS += -I../../common/zfs

CERRWARN += -_gcc=-Wno-uninitialized

.KEEP_STATE:

all: $(PROG)

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

install: all $(ROOTUSRSBINPROG) $(ROOTMANIFEST) $(ROOTSVCMETHOD)

check:	$(PROG).c $(CHKMANIFEST)
	$(CSTYLE) -pP $(SRCS:%=%)

$(POFILE): $(POFILES)
	$(RM) $@
	$(CAT) $(POFILES) > $@

clean:
	$(RM) $(OBJS) $(POFILES)

lint:	lint_SRCS

include ../Makefile.targ
