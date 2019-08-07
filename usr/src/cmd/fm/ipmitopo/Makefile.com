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
# Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

.KEEP_STATE:
.SUFFIXES:

SRCS += ipmitopo.c
OBJS = $(SRCS:%.c=%.o)
LINTFILES = $(SRCS:%.c=%.ln)

PROG = ipmitopo
ROOTLIBFM = $(ROOT)/usr/lib/fm
ROOTLIBFMD = $(ROOT)/usr/lib/fm/fmd
ROOTPROG = $(ROOTLIBFMD)/$(PROG)

$(NOT_RELEASE_BUILD)CPPFLAGS += -DDEBUG
CPPFLAGS += -I. -I../common
CFLAGS += $(CTF_FLAGS) $(CCVERBOSE) $(XSTRCONST)
LDLIBS += -lipmi -lnvpair
LINTFLAGS += -mnu

CERRWARN += $(CNOWARN_UNINIT)

.NO_PARALLEL:
.PARALLEL: $(OBJS) $(LINTFILES)

all: $(PROG)

$(PROG): $(OBJS)
	$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
	$(CTFMERGE) -L VERSION -o $@ $(OBJS)
	$(POST_PROCESS)

%.o: ../common/%.c
	$(COMPILE.c) $<
	$(CTFCONVERT_O)

%.o: %.c
	$(COMPILE.c) $<
	$(CTFCONVERT_O)

clean:
	$(RM) $(OBJS) $(LINTFILES)

clobber: clean
	$(RM) $(PROG)

%.ln: ../common/%.c
	$(LINT.c) -c $<

%.ln: %.c
	$(LINT.c) -c $<

lint: $(LINTFILES)
	$(LINT) $(LINTFLAGS) $(LINTFILES)

$(ROOTLIBFMD)/%: %
	$(INS.file)

install_h:

install: all $(ROOTPROG)
