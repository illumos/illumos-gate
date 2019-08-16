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

PROG= mkdir
OBJS= $(PROG).o common.o
SRCS= mkdir.c ../chmod/common.c

include ../Makefile.cmd

CFLAGS += $(CCVERBOSE)
CERRWARN += $(CNOWARN_UNINIT)
CERRWARN += -_gcc=-Wno-parentheses
LDLIBS += -lgen

%.o: ../chmod/%.c
	$(COMPILE.c) -o $@ $<

#  The following was derived from the default .c.po rule in the master
#  makefile.  It had to be adapted to avoid writing the intermediate (.i)
#  file in ../chmod.

%.po: ../chmod/%.c
	$(COMPILE.cpp) $< > $*.c.i
	$(XGETTEXT) $(XGETFLAGS) $*.c.i ;\
	$(RM)	$@ ;\
	sed "/^domain/d" < messages.po  > $@ ;\
	$(RM) messages.po $*.c.i

POFILES= $(OBJS:%.o=%.po)
POFILE= $(PROG)_cmd.po

LINTFLAGS += -erroff=E_GLOBAL_COULD_BE_STATIC2

.KEEP_STATE:

all: $(PROG)

$(PROG): $(OBJS)
	$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

$(POFILE): $(POFILES)
	$(RM) $@
	cat $(POFILES) > $@

install: all $(ROOTPROG)

clean:
	$(RM) $(OBJS)

lint:	lint_SRCS

include ../Makefile.targ
