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

PROG=		lms
MANIFEST=	lms.xml

include	../Makefile.cmd

LMSOBJS=	ConfigConnection.o     Protocol.o             main.o \
		LMEConnection.o        ProtocolCompat.o \
		LMEConnectionCompat.o  glue.o \
		SyncLib/src/EventUnix.o SyncLib/src/RWLock.o \
		SyncLib/src/SemaphoreUnix.o SyncLib/src/ThreadUnix.o \
		heci/FWULCommand.o heci/HECIUnix.o \
		heci/MNGCommand.o heci/PTHICommand.o \
		tools/ATNetworkTool.o tools/ATVersion.o \
		tools/daemonize.o

ROOTMANIFESTDIR=	$(ROOTSVCNETWORK)
ROOTMETHOD=		$(ROOTLIBSVCMETHOD)/svc-lms
$(ROOTMANIFEST)		:= FILEMODE= 444

SYNCLIB_SRCDIR=SyncLib/src
SYNCLIB_HDRDIR=SyncLib/Include
HECI_DIR=heci
TOOLS_DIR=tools

CPPFLAGS=	-DBSD_COMP -D_REMOTE_SUPPORT \
		-I. -I$(SYNCLIB_HDRDIR) -I$(HECI_DIR) -I$(TOOLS_DIR)
CCFLAGS +=	-compat=5 -features=zla
$(__SUNC)CCNEEDED=	$(CCEXTNEEDED)
LDFLAGS += $(ZIGNORE) -norunpath
LDLIBS += -lsocket -lnsl

.KEEP_STATE:

all:		$(PROG)

$(PROG):	$(LMSOBJS)
		$(LINK.cc) -o $@ $(LMSOBJS) $(LDLIBS) -lc
		$(POST_PROCESS)

%.o:		%.cpp
		$(COMPILE.cc) $(OUTPUT_OPTION) -o $@ $<
		$(POST_PROCESS_O)

install:	all $(ROOTLIBPROG) $(ROOTMANIFEST) $(ROOTMETHOD)

check:		$(CHKMANIFEST)

clean:
		$(RM) $(OBJS) $(LMSOBJS)

include ../Makefile.targ

#
# we're not linting lms.  it's all C++.
#

lint:
