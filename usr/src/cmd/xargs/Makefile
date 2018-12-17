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
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright (c) 2018, Joyent, Inc.

PROG= 			xargs
# /usr/xpg6/bin/xargs is a symlink to /usr/bin/xargs
ROOTXPG6SYMLINK= 	$(ROOTXPG6BIN)/xargs

OBJS1=			xargs.o
OBJS=			$(OBJS1) getresponse.o
SRCS=			$(OBJS1:%.o=%.c) $(SRC)/common/util/getresponse.c

include ../Makefile.cmd

CPPFLAGS += -I $(SRC)/common/util
LINTFLAGS += -u

CERRWARN += -_gcc=-Wno-parentheses

# not linted
SMATCH=off

.KEEP_STATE:

all: $(PROG)

install: all $(ROOTPROG) $(ROOTXPG6SYMLINK)

$(PROG):	$(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

%.o:	$(SRC)/common/util/%.c
	$(COMPILE.c) $(OUTPUT_OPTION) $<
	$(POST_PROCESS_O)

$(ROOTXPG6SYMLINK):	$(ROOTPROG)
	-$(RM)	$@
	-$(SYMLINK)	../../bin/$(PROG) $@

clean:
	$(RM) $(OBJS)

lint:	lint_SRCS

include ../Makefile.targ
