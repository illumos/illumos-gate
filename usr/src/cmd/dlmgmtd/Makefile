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

$(ROOTCFGDIR)/datalink.conf	:= FILEMODE= 644

LDLIBS += -ldladm -ldlpi -lavl -lnvpair -lsysevent -lcontract

CERRWARN += $(CNOWARN_UNINIT)

#
# Instrument dlmgmtd with CTF data to ease debugging.
#
CTFCONVERT_HOOK = && $(CTFCONVERT_O)
CTFMERGE_HOOK = && $(CTFMERGE) -L VERSION -o $@ $(OBJS)
$(OBJS) := CFLAGS += $(CTF_FLAGS)


.KEEP_STATE:

all: $(PROG)

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS) $(CTFMERGE_HOOK)
	$(POST_PROCESS)

install: all $(ROOTSBINPROG) $(ROOTMANIFEST) $(ROOTSVCMETHOD) $(ROOTCFGDIR) \
	$(ROOTCFGFILES)

check:	$(CHKMANIFEST)

clean:
	$(RM) $(OBJS)

$(ROOTCFGDIR):
	$(INS.dir)

$(ROOTCFGDIR)/%: $(ROOTCFGDIR) %
	$(INS.file)

include ../Makefile.targ
