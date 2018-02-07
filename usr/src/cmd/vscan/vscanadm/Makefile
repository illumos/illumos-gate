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
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

PROG = vscanadm
SRCS = vscanadm.c
OBJS = $(SRCS:%.c=%.o)

include ../../Makefile.cmd

LDLIBS += -L$(ROOT)/usr/lib/vscan -lvscan
LDFLAGS += -R/usr/lib/vscan
CFLAGS += $(CCVERBOSE)

CSTD =       $(CSTD_GNU99)
C99LMODE =      -Xc99=%all

.KEEP_STATE:

all: $(PROG)

clean:
	$(RM) $(OBJS)

lint:	lint_SRCS

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

include ../../Makefile.targ

install: all .WAIT $(ROOTUSRSBINPROG)
