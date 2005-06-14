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
#ident	"%Z%%M%	%I%	%E% SMI"
#
# Copyright (c) 2001 by Sun Microsystems, Inc.
# All rights reserved.
#

PLATFORM	= sun4u
SCRIPT		= wrsm_lastwci
RCM_SCRIPT	= SUNW,wrsm_lastwci
ROOTRCM_D	= $(ROOT)/usr/platform/sun4u/lib/rcm
ROOTRCM_SCR_D	= $(ROOTRCM_D)/scripts
ROOTRCM_PROG	= $(ROOTRCM_SCR_D)/$(RCM_SCRIPT)
PROG		= wrsmstat
OBJS		= wrsmstat.o

include ../Makefile.cmd
include ../../Makefile.psm

ROOTBIN= $(ROOT)/usr/platform/sun4u/sbin
INS.root.sys = install -s -m 755 -f
$(CH)INS.root.sys = install -s -m 755 -u root -g sys -f

CLOBBERFILES += $(RCM_SCRIPT)

#
# Include path for rsm header files
#
CPPFLAGS += -I$(ROOT)/usr/platform/sun4u/include
CCFLAGS = -xarch=v9 -I$(INCLUDE)
LDLIBS += -lkstat
FILEMODE= 0555
GROUP= bin

.KEEP_STATE:

all: $(PROG)

install: all $(ROOTPROG) $(ROOTRCM_PROG)

$(ROOTRCM_D):
	$(INS.dir.root.sys)

$(ROOTRCM_SCR_D): $(ROOTRCM_D)
	$(INS.dir.root.sys)

$(RCM_SCRIPT): $(SCRIPT)
	$(CP) $(SCRIPT) $(RCM_SCRIPT)
	$(CHMOD) 0755 $(RCM_SCRIPT)

$(ROOTRCM_PROG): $(RCM_SCRIPT) $(ROOTRCM_SCR_D)
	$(INS.root.sys) $(ROOTRCM_SCR_D) $(RCM_SCRIPT)

$(ROOTBIN):
	$(INS.dir.root.sys)

$(ROOTPROG): $(ROOTBIN) $(PROG)
	$(INS.root.sys) $(ROOTBIN) $(PROG)

$(PROG):	$(OBJS)
	$(LINK.c) -o $(PROG) $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

clean:
	-$(RM) $(OBJS)

lint: $(MACH)_lint

i386_lint:

sparc_lint:
	$(LINT.c) -u $(PROG).c $(LDLIBS)

include ../Makefile.targ
