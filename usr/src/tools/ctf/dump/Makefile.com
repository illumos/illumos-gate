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

.KEEP_STATE:
.SUFFIXES:

PROG = ctfdump
SRCS = dump.c utils.c symbol.c

include ../../Makefile.ctf

LDFLAGS += -L$(NATIVE_ADJUNCT)/lib
LDLIBS += -lelf -lz

OBJS = $(SRCS:%.c=%.o)
LINTFILES = $(SRCS:%.c=%.ln)

CERRWARN += -_gcc=-Wno-uninitialized

.NO_PARALLEL:
.PARALLEL: $(OBJS) $(LINTFILES)

all: $(PROG)

$(PROG): $(OBJS)
	$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

%.o: ../%.c
	$(COMPILE.c) $<

$(ROOTONBLDMACHPROG): $(PROG)

install: $(ROOTONBLDMACHPROG)

clean:
	$(RM) $(OBJS) $(LINTFILES)

%.ln: ../%.c
	$(LINT.c) -c $<

lint: $(LINTFILES)
	$(LINT) $(LINTFLAGS) $(LINTFILES) $(LDLIBS)

include ../../Makefile.ctf.targ
