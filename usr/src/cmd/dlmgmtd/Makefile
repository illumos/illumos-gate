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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

PROG=		dlmgmtd
OBJS=		dlmgmt_main.o dlmgmt_door.o dlmgmt_util.o dlmgmt_db.o
SRCS=		$(OBJS:.o=.c)
SVCMETHOD=	svc-dlmgmtd
MANIFEST=	dlmgmt.xml
CFGFILES=	datalink.conf

include ../Makefile.cmd

ROOTMANIFESTDIR=	$(ROOTSVCNETWORK)
ROOTCFGDIR=		$(ROOTETC)/dladm
ROOTCFGFILES=		$(CFGFILES:%=$(ROOTCFGDIR)/%)

$(ROOTCFGFILES)	:= OWNER= dladm
$(ROOTCFGFILES)	:= GROUP= sys
$(ROOTCFGDIR)/datalink.conf	:= FILEMODE= 644

LDLIBS += -ldladm -ldlpi -lavl

.KEEP_STATE:

all: $(PROG)

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

install: all $(ROOTSBINPROG) $(ROOTMANIFEST) $(ROOTSVCMETHOD) $(ROOTCFGDIR) \
	$(ROOTCFGFILES)

check:	$(CHKMANIFEST)

clean:
	$(RM) $(OBJS)

lint:	lint_SRCS

$(ROOTCFGDIR):
	$(INS.dir)

$(ROOTCFGDIR)/%: $(ROOTCFGDIR) %
	$(INS.file)

include ../Makefile.targ
