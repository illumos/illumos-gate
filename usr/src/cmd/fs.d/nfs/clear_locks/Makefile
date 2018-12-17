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

PROG= clear_locks

include         ../../../Makefile.cmd

LDLIBS		+=	-lrpcsvc -lnsl

#
# Message catalog
#
POFILE= clear_locks.po

#
# message catalog
#
catalog:        $(POFILE)

$(POFILE):      clear_locks.c
	$(RM) $@
	$(COMPILE.cpp) clear_locks.c   > $(POFILE).i
	$(XGETTEXT) $(XGETFLAGS)        $(POFILE).i
	sed "/^domain/d"        messages.po     > $@
	$(RM) messages.po $(POFILE).i


CFLAGS		+=	$(CCVERBOSE)

# not linted
SMATCH=off

.KEEP_STATE:

all: $(PROG)

install: all $(ROOTUSRSBINPROG)

clean:

lint:	lint_PROG

include ../../../Makefile.targ
