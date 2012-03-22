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
# Copyright (c) 2012 Joyent, Inc.  All rights reserved.
#

PROG= ipdadm
OBJS = ipdadm.o
SRCS = $(OBJS:%.o=../%.c)


include ../Makefile.cmd
include ../Makefile.ctf

#
# The ipd.h interface is currently private and not shipped with the system. As
# such it is only useful for building this command and so we manually set
# cpppath to include it, just as we do for cpuid_drv.h.
#
CPPFLAGS += -I../../uts/common

CLEANFILES += $(OBJS)
CFLAGS += $(CCVERBOSE)

.KEEP_STATE:

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(CTFCONVERT_O)

clean:
	-$(RM) $(CLEANFILES)

lint: lint_PROG

%.o: ../%.c
	$(COMPILE.c) $<

install: $(PROG) $(ROOTUSRSBINPROG)

include ../Makefile.targ
