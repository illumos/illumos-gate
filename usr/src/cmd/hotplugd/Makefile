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
# cmd/hotplugd/Makefile
#

PROG= 		hotplugd
OBJS=		hotplugd.o \
		hotplugd_impl.o \
		hotplugd_door.o \
		hotplugd_info.o \
		hotplugd_rcm.o
SRCS=		$(OBJS:.o=.c)
SVCMETHOD=	svc-hotplug
MANIFEST=	hotplug.xml

include ../Makefile.cmd

ROOTCMDDIR=		$(ROOTLIB)
ROOTMANIFESTDIR=	$(ROOTSVCSYSTEM)
$(ROOTMANIFEST)		:= FILEMODE= 444

CPPFLAGS += -I$(SRC)/lib/libhotplug/common
CERRWARN += -_gcc=-Wno-parentheses
CERRWARN += $(CNOWARN_UNINIT)
LDLIBS += -ldevinfo -lhotplug -lnvpair -lsecdb -lrcm -lbsm

.KEEP_STATE:

all:	$(PROG)

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

.PARALLEL: $(OBJS)

install: all $(ROOTCMD) $(ROOTMANIFEST) $(ROOTSVCMETHOD)

clean:
	$(RM) $(PROG) $(OBJS) $(LLOBJS)

check: $(CHKMANIFEST)
	$(CSTYLE) -pP $(SRCS:%=%)

lint:	lint_SRCS

include ../Makefile.targ
