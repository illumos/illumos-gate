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
# Copyright 2018, Joyent, Inc.
#
# cmd/prstat/Makefile.com
#

PROG = prstat
OBJS = prstat.o prfile.o prtable.o prsort.o prutil.o
SRCS = $(OBJS:%.o=../%.c)

include ../../Makefile.cmd

CSTD = $(CSTD_GNU99)
CFLAGS += $(CCVERBOSE)
CERRWARN += -_gcc=-Wno-parentheses
LDLIBS += -lcurses -lproject
LINTFLAGS += -u
LINTFLAGS64 += -u

FILEMODE = 0555

.KEEP_STATE:

.PARALLEL : $(OBJS)

all: $(PROG)

clean:
	$(RM) $(OBJS)

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

%.o:	../%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

lint:
	$(LINT.c) $(SRCS) $(LDLIBS)

include ../../Makefile.targ
