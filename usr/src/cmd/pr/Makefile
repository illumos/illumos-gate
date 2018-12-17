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
# Copyright (c) 1989 by Sun Microsystems, Inc.
#
# Copyright (c) 2018, Joyent, Inc.

PROG= pr
XPG4PROG= pr

include ../Makefile.cmd

SED = sed
DCFILE = $(PROG).dc

CERRWARN += -_gcc=-Wno-parentheses

SMOFF += indenting

$(XPG4):= CPPFLAGS += -DXPG4
$(POFILE) := XGETFLAGS += -a -x pr.xcl

.KEEP_STATE:

all: $(PROG) $(XPG4)

install: all $(ROOTPROG) $(ROOTXPG4PROG)

clean:

lint:	lint_PROG

$(DCFILE):
	$(RM) messages.po
	$(COMPILE.cpp) $(PROG).c | \
	$(XGETTEXT) $(XGETFLAGS) -t -
	$(SED) -e '/^domain/d' messages.po > $@
	$(RM) messages.po

include ../Makefile.targ
