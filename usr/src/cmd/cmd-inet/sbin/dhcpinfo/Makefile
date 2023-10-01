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
# Copyright 1999-2003 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# cmd/cmd-inet/sbin/dhcpinfo/Makefile
#

PROG    = dhcpinfo
ROOTFS_PROG = $(PROG)
OBJS    = $(PROG).o

include ../../../Makefile.cmd
include ../../../Makefile.ctf

LDLIBS  += -ldhcpagent -ldhcputil
LINTFLAGS += -u	# due to problems with libgen

.KEEP_STATE:

all:		$(ROOTFS_PROG)

$(PROG):	$(OBJS)
		$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
		$(POST_PROCESS)

install:	all $(ROOTSBINPROG)

clean:
		$(RM) $(OBJS)

lint:		lint_PROG

include ../../../Makefile.targ
