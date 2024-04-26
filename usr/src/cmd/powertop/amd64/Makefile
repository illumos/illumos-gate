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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

include ../Makefile.com
include ../../Makefile.cmd.64

MACH_OBJS	= pt_amd64.o
SRCS		+= $(MACH_OBJS:%.o=%.c)

.KEEP_STATE:

CLEANFILES	+= $(MACH_OBJS)

all: $(PROG)

$(PROG): $(MACH_OBJS) $(COMMON_OBJS)
	$(LINK.c) -o $@ $(MACH_OBJS) $(COMMON_OBJS) $(LDLIBS)
	$(POST_PROCESS)

%.o: ../common/%.c
	$(COMPILE.c) -o $@ $<

install: all $(ROOTPROG)
