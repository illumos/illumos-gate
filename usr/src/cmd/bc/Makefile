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
# Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright (c) 2018, Joyent, Inc.

PROG= bc
XPG6PROG= bc
XD= exobjs.xpg6
EXOBJS= bc.o
XPG6EXOBJS= exobjs.xpg6/bc.o

LIBB= lib.b
CLOBBERFILES= $(LIBB)

include ../Makefile.cmd

CERRWARN += -_gcc=-Wno-implicit-function-declaration
CERRWARN += -_gcc=-Wno-parentheses
CERRWARN += -_gcc=-Wno-unused-label

# nothing lintable
SMATCH=off

$(XPG6EXOBJS) := CFLAGS += -DXPG6
ROOTLIBB= $(LIBB:%=$(ROOTLIB)/%)
$(ROOTLIBB) :=	FILEMODE =	$(LIBFILEMODE)

.KEEP_STATE:

all: $(PROG) $(XPG6) $(LIBB) 

$(PROG): $(EXOBJS)
	$(LINK.c) -o $@ $(EXOBJS) $(LDLIBS)
	$(POST_PROCESS)


$(XPG6): $(XD) $(XPG6EXOBJS)
	$(LINK.c) -o $@ $(XPG6EXOBJS) $(LDLIBS)
	$(POST_PROCESS)


$(LIBB): $(LIBB).data
	-$(RM) $(LIBB)
	$(CP) $(LIBB).data $(LIBB)

install: all $(ROOTPROG) $(ROOTXPG6PROG) $(ROOTLIBB)

clean:
	-@rm -rf $(PROG).c $(PROG).x $(EXOBJS) $(XD) $(PROG) $(XPG6)

lint:

$(XPG6EXOBJS): $(XD)

$(XD)/bc.o:	bc.y
	$(YACC.y) bc.y
	$(COMPILE.c) -o $@ y.tab.c
	$(POST_PROCESS_O)
	$(RM) y.tab.c

$(XD):
	-@mkdir -p $@


include ../Makefile.targ
