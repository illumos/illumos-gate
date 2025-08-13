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

PROG=du
XPG4PROG= du

include ../Makefile.cmd
include ../Makefile.cmd.64

CFLAGS += $(CCVERBOSE)
$(XPG4) := CFLAGS += -DXPG4
POFILE = du_cmd.po
POFILES = du.po
POFILES_XPG4 = du.po.xpg4
$(POFILES_XPG4)	:= CFLAGS += -DXPG4
CLOBBERFILES += $(POFILES_XPG4)
LDLIBS += -lcmdutils

.KEEP_STATE:

all: $(PROG) $(XPG4)

install: all $(ROOTPROG) $(ROOTXPG4PROG)

$(POFILE):	$(POFILES) $(POFILES_XPG4)
	$(RM) $@; cat $(POFILES) $(POFILES_XPG4) > $@

%.po.xpg4:	%.c
	$(COMPILE.cpp) $< > $<.i
	$(BUILD.po)

clean:

lint:	lint_PROG

include ../Makefile.targ
