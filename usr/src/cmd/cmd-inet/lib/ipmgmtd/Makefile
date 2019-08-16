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
# Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
# Copyright 2015 Joyent, Inc.
#

# Needed for ROOTFS_LIBDIR definition
include		../../../../lib/Makefile.lib

PROG=		ipmgmtd
OBJS=		ipmgmt_main.o ipmgmt_door.o ipmgmt_persist.o ipmgmt_util.o \
		ipmgmt_path.o
SRCS=		$(OBJS:.o=.c)
SVCMETHOD=	net-ipmgmt
MANIFEST=	network-ipmgmt.xml
CFGFILES=	ipadm.conf

# Needed for ROOTETC definition
include		../../../Makefile.cmd

ROOTCFGDIR=		$(ROOTETC)/ipadm
ROOTCFGFILES=		$(CFGFILES:%=$(ROOTCFGDIR)/%)
ROOTMANIFESTDIR=	$(ROOTSVCNETWORK)

CERRWARN += -_gcc=-Wno-switch
CERRWARN += $(CNOWARN_UNINIT)

$(ROOTCFGFILES)	:= OWNER= ipadm
$(ROOTCFGFILES)	:= GROUP= sys
$(ROOTCFGFILES)	:= FILEMODE= 644

ROOTCMDDIR=	$(ROOTFS_LIBDIR)/inet

LDLIBS += -lipadm -lnvpair -lsecdb -lnsl -lumem -lscf

#
# Instrument ipmgmtd with CTF data to ease debugging.
#
CTFCONVERT_HOOK = && $(CTFCONVERT_O)
CTFMERGE_HOOK = && $(CTFMERGE) -L VERSION -o $@ $(OBJS)
$(OBJS) := CFLAGS += $(CTF_FLAGS)

.KEEP_STATE:

.PARALLEL:

all: $(PROG)

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS) $(CTFMERGE_HOOK)
	$(POST_PROCESS)

install: $(ROOTCMD) $(ROOTMANIFEST) $(ROOTSVCMETHOD) $(ROOTCFGDIR) \
	$(ROOTCFGFILES)

check:  $(SRCS) $(HEADERS) $(CHKMANIFEST)
	$(CSTYLE) -cpP $(SRCS) $(HEADERS)

$(ROOTCMD): $(PROG)

clean:
	$(RM) $(OBJS)

lint:	lint_SRCS

$(ROOTCFGDIR):
	$(INS.dir)

$(ROOTCFGDIR)/%: $(ROOTCFGDIR) %
	$(INS.file)

include 	../../../Makefile.targ
