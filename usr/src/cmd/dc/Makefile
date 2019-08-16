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

PROG= dc
XPG6PROG= dc
XD= exobjs.xpg6
EXOBJS= dc.o
XPG6EXOBJS= exobjs.xpg6/dc.o 

include ../Makefile.cmd

LDFLAGS += $(MAPFILE.NGB:%=-M%)
CERRWARN += -_gcc=-Wno-implicit-function-declaration
CERRWARN += -_gcc=-Wno-unused-value
CERRWARN += -_gcc=-Wno-parentheses
CERRWARN += $(CNOWARN_UNINIT)

# not linted
SMATCH=off

.KEEP_STATE:

all: $(MAPFILE.NGB) $(PROG) $(XPG6)

$(PROG): $(EXOBJS)
	$(LINK.c) -o $@ $(EXOBJS) $(LDLIBS)
	$(POST_PROCESS)


$(XPG6): $(XD) $(XPG6EXOBJS)
	$(LINK.c) -o $@ $(XPG6EXOBJS) $(LDLIBS)
	$(POST_PROCESS)


install: all $(ROOTPROG) $(ROOTXPG6PROG)

clean:
	-@rm -rf $(EXOBJS) $(XD) $(PROG) $(XPG6)

lint:	lint_PROG

$(XPG6EXOBJS): $(XD)

$(XD)/%.o:	%.c
	$(COMPILE.c) -o $@ $<

$(XD):
	-@mkdir -p $@


include ../Makefile.targ

$(XPG6) := CFLAGS += -DXPG6
