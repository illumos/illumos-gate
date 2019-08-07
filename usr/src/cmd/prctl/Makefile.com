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
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright (c) 2018, Joyent, Inc.

PROG=	prctl

OBJS=	prctl.o utils.o

SRCS=	../prctl.c ../utils.c

include ../../Makefile.cmd

CFLAGS	+= $(CCVERBOSE)
CERRWARN += -_gcc=-Wno-parentheses
CERRWARN += $(CNOWARN_UNINIT)

# not linted
SMATCH=off

LDLIBS	+= -lproc -lproject

# Adding this flag to LINTFLAGS did not do anything.  I'm adding this flag
# because there are some lint errors due to private functions in libproject.
# I do not want to add these functions to /usr/lib/llib-project because we
# ship it.  usr/src/cmd/newtask has similar lint errors, but I do not wish
# to introduce more.
lint:=	CPPFLAGS += -erroff=E_NAME_USED_NOT_DEF2 -u

CPPFLAGS += -D_LARGEFILE64_SOURCE=1

.KEEP_STATE:

all: $(PROG)

$(PROG): $(OBJS)
	$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

clean:
	$(RM) $(OBJS)

lint:
	$(LINT.c) $(SRCS) $(LDLIBS)

%.o:	../%.c
	$(COMPILE.c) $<
	$(POST_PROCESS_O)

include ../../Makefile.targ

