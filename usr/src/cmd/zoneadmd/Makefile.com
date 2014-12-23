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
# Copyright 2014, Joyent, Inc. All rights reserved.
#

PROG= zoneadmd

include ../../Makefile.cmd
include ../../Makefile.ctf

ROOTCMDDIR=	$(ROOTLIB)/zones

OBJS= zoneadmd.o zcons.o zfd.o vplat.o mcap.o

CFLAGS += $(CCVERBOSE)
LDLIBS += -lsocket -lzonecfg -lnsl -ldevinfo -ldevice -lnvpair \
	-lgen -lbsm -lcontract -lzfs -luuid -lbrand -ldladm -ltsnet -ltsol \
	-linetutil -lproc -lscf

.KEEP_STATE:

%.o:    ../%.c
	$(COMPILE.c) $<
	$(POST_PROCESS_O)

ROOTUSRLIBZONES			= $(ROOT)/usr/lib/zones
ROOTUSRLIBZONES32		= $(ROOTUSRLIBZONES)/$(MACH32)
ROOTUSRLIBZONES64		= $(ROOTUSRLIBZONES)/$(MACH64)
ROOTUSRLIBZONESPROG32		= $(ROOTUSRLIBZONES32)/$(PROG)
ROOTUSRLIBZONESPROG64		= $(ROOTUSRLIBZONES64)/$(PROG)
$(ROOTUSRLIBZONES32)/%: $(ROOTUSRLIBZONES32) %
	$(INS.file)
$(ROOTUSRLIBZONES64)/%: $(ROOTUSRLIBZONES64) %
	$(INS.file)
$(ROOTUSRLIBZONES32):
	$(INS.dir)

all: $(PROG)

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

clean:
	$(RM) $(OBJS)

lint:
	$(LINT.c) ../*.c $(LDLIBS)

include ../../Makefile.targ
