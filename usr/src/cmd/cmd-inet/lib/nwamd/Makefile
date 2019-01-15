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
# Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
#
# Copyright (c) 2018, Joyent, Inc.

# Needed for ROOTFS_LIBDIR definition
include		../../../../lib/Makefile.lib

PROG=		nwamd
OBJS=		conditions.o dlpi_events.o door_if.o enm.o\
		events.o known_wlans.o llp.o loc.o logging.o\
		main.o ncp.o ncu.o ncu_phys.o ncu_ip.o objects.o\
		routing_events.o sysevent_events.o util.o
SRCS=		$(OBJS:%.o=%.c)
HEADERS=	conditions.h events.h known_wlans.h llp.h ncp.h ncu.h\
		objects.h
LOCFILES=	create_loc_auto create_loc_nonet
NONETLOCFILES=	ipf.conf.dfl ipf6.conf.dfl

ROOTCFGDIR=	$(ROOTETC)/nwam
ROOTLOCDIR=	$(ROOTCFGDIR)/loc
NONETLOCDIR=	$(ROOTLOCDIR)/NoNet
LOCDIRS=	$(NONETLOCDIR)
ROOTCFGFILES=	$(LOCFILES:%=$(ROOTLOCDIR)/%) \
		$(NONETLOCFILES:%=$(NONETLOCDIR)/%)

include		../../../Makefile.cmd

$(ROOTCFGFILES) := FILEMODE= 644

ROOTCMDDIR=	$(ROOTFS_LIBDIR)/inet

LDLIBS +=	-ldhcpagent -ldhcputil -ldladm -ldlpi -lgen \
		-linetutil -lipadm -lkstat -lnsl -lnvpair -lnwam \
		-lsecdb -lscf -lsocket -lsysevent -lumem -luutil

CERRWARN +=	-_gcc=-Wno-uninitialized
CERRWARN +=	-_gcc=-Wno-parentheses
CERRWARN +=	-_gcc=-Wno-switch
CERRWARN +=	-_gcc=-Wno-unused-label

# not linted
SMATCH=off

#
# Instrument with CTF data to ease debugging.
#
CTFCONVERT_HOOK = && $(CTFCONVERT_O)
CTFMERGE_HOOK = && $(CTFMERGE) -L VERSION -o $@ $(OBJS)
$(OBJS) := CFLAGS += $(CTF_FLAGS)

.KEEP_STATE:

.PARALLEL:

all: $(PROG)

$(PROG): $(OBJS)
	$(LINK.c) $(OBJS) -o $@ $(LDLIBS) $(CTFMERGE_HOOK)
	$(POST_PROCESS)

install: $(ROOTCMD) $(ROOTLOCDIR) $(ROOTCFGFILES)

check:  $(SRCS) $(HEADERS)
	$(CSTYLE) -cpP $(SRCS) $(HEADERS)

$(ROOTCMD): all

clean:
	$(RM) $(OBJS)

lint:	lint_SRCS

$(ROOTCFGDIR):
	$(INS.dir)

$(ROOTLOCDIR): $(ROOTCFGDIR)
	$(INS.dir)

$(LOCDIRS): $(ROOTLOCDIR)
	$(INS.dir) 

$(ROOTLOCDIR)/%: $(ROOTLOCDIR) %
	$(INS.file)

$(NONETLOCDIR)/%: $(NONETLOCDIR) %
	$(INS.file)

include		../../../Makefile.targ
