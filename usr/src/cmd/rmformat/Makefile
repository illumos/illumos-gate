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
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright (c) 2018, Joyent, Inc.

PROG= rmformat

OBJS=	rmf_main.o rmf_menu.o rmf_misc.o rmf_slice.o

include ../Makefile.cmd

SRCS= $(OBJS:.o=.c)

LDLIBS +=	-lsmedia -lvolmgt -ladm -lefi

CERRWARN += -_gcc=-Wno-uninitialized

# not linted
SMATCH=off

LINTFLAGS += -u
CPPFLAGS += -D_FILE_OFFSET_BITS=64

$(ROOTBIN)/rmformat := FILEMODE = 04555

.KEEP_STATE:

all: $(PROG)

$(PROG): $(OBJS)
	$(LINK.c) -o $(PROG) $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

install: all $(ROOTPROG)

clean:
	$(RM) $(OBJS)

lint: lint_SRCS

$(POFILE) : $(SRCS)
	$(RM) $@
	$(COMPILE.cpp) $(SRCS) | $(XGETTEXT) $(XGETFLAGS) -
	$(SED) -e '/^domain/d' messages.po > $@
	$(RM) messages.po

sb: $(SRCS)
	$(COMPILE.c) -xsbfast $(SRCS)

include ../Makefile.targ
