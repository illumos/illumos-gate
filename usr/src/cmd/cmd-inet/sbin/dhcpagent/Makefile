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
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

PROG    = dhcpagent
ROOTFS_PROG = $(PROG)
LOCOBJS = adopt.o agent.o arp_check.o async.o bound.o class_id.o defaults.o \
	  dlpi_io.o dlprims.o inform.o init_reboot.o \
	  interface.o ipc_action.o packet.o release.o renew.o request.o \
	  script_handler.o select.o util.o
COMDIR  = $(SRC)/common/net/dhcp
COMOBJS = ipv4_sum.o udp_sum.o
INETDIR = $(SRC)/cmd/cmd-inet/common

include ../../../Makefile.cmd

DFLTD   = $(ROOTETC)/default
ETCDFLTPROG = $(PROG:%=$(DFLTD)/%)
$(ETCDFLTPROG) := FILEMODE = 0444
$(ETCDFLTPROG) := OWNER = root
$(ETCDFLTPROG) := GROUP = sys

OBJS    = $(COMOBJS) $(LOCOBJS)
SRCS    = $(COMOBJS:%.o=$(COMDIR)/%.c) $(LOCOBJS:%.o=%.c)

POFILES = $(LOCOBJS:%.o=%.po)
XGETFLAGS += -a -x dhcpagent.xcl

#
# to compile a debug version, do a `make COPTFLAG="-g -XO0"'
#

CPPFLAGS  += -I$(COMDIR) -I$(INETDIR)
LDLIBS    += -lsocket -lnvpair -lnsl -ldhcpagent -ldhcputil -linetutil -ldevinfo

.KEEP_STATE:

all:		$(ROOTFS_PROG) $(PROG).dfl

install:	all $(ROOTSBINPROG) $(ETCDFLTPROG)

$(PROG):	$(OBJS)
		$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
		$(POST_PROCESS)

%.o:		$(COMDIR)/%.c
		$(COMPILE.c) $(OUTPUT_OPTION) $<
		$(POST_PROCESS_O)

%.o:		$(INETDIR)/%.c
		$(COMPILE.c) $(OUTPUT_OPTION) $<
		$(POST_PROCESS_O)

$(DFLTD)/%:	%.dfl
		$(INS.rename)

$(POFILE):	$(POFILES)
		$(RM) $@; $(CAT) $(POFILES) > $@; $(RM) $(POFILES)

clean:
		$(RM) $(OBJS)

lint:		lint_SRCS

include ../../../Makefile.targ
