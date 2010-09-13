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
#ident	"%Z%%M%	%I%	%E% SMI"
#
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

PROG= chown
XPG4PROG= chown
XD= exobjs.xpg4
EXOBJS= chown.o
XPG4EXOBJS= exobjs.xpg4/chown.o

include ../Makefile.cmd

$(XPG4) :=	CFLAGS += -DXPG4
CPPFLAGS += -D_FILE_OFFSET_BITS=64
LDLIBS += -lcmdutils -lsec

.KEEP_STATE:

all: $(PROG) $(XPG4)

$(PROG):	$(EXOBJS)
	$(LINK.c) -o $@ $(EXOBJS) $(LDLIBS)
	$(POST_PROCESS)

$(XPG4):	$(XD) $(XPG4EXOBJS)
	$(LINK.c) -o $@ $(XPG4EXOBJS) $(LDLIBS)
	$(POST_PROCESS)


install: all $(ROOTPROG) $(ROOTXPG4PROG)

clean:
	-@rm -rf $(EXOBJS) $(XD)

lint:	lint_PROG

$(XPG4EXOBJS):	$(XD)

$(XD)/%.o:	%.c
	$(COMPILE.c) -o $@ $<

$(XD):
	-@mkdir -p $@

include ../Makefile.targ
