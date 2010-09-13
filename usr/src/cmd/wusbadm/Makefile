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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#

PROG=		wusbadm
MANIFEST=	wusb.xml
SVCMETHOD=	svc-wusb

include ../Makefile.cmd

ROOTMANIFESTDIR=        $(ROOTSVCSYSTEM)

OBJS= wusbadm.o wusbd.o crypto_util.o
SRCS= $(OBJS:%.o=%.c)
POFILE= wusbadm_all.po
POFILES=$(OBJS:%.o=%.po)


CPPFLAGS += -I$(SRC)/uts/common
LDLIBS += -lpkcs11 -lkmf -lsysevent -lnvpair -lsecdb

.KEEP_STATE:

all: $(PROG)

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

install: all $(ROOTSBINPROG) $(ROOTMANIFEST) $(ROOTSVCMETHOD)
	$(RM) $(ROOTUSRSBINPROG)
	-$(SYMLINK) ../../sbin/$(PROG) $(ROOTUSRSBINPROG)
	$(RM) $(ROOTLIB)/wusbd
	-$(SYMLINK) ../../sbin/$(PROG) $(ROOTLIB)/wusbd

check:	$(PROG).c $(CHKMANIFEST)
	$(CSTYLE) -pP $(SRCS:%=%)

$(POFILE): $(POFILES)
	$(RM) $@
	$(CAT) $(POFILES) > $@

clean:
	$(RM) $(PROG) $(OBJS) $(POFILES)

lint:	lint_SRCS

include ../Makefile.targ
