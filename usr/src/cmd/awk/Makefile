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
#
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright 2020 Joyent, Inc.

# NOTE: awk is now nawk.

PROG= nawk
LINKPROG= awk

OBJ1= b.o lib.o main.o parse.o proctab.o run.o tran.o lex.o
OBJ2= awk.g.o
OBJS= $(OBJ2) $(OBJ1)
SRCS= $(OBJ1:%.o=%.c)

include ../Makefile.cmd

ROOTLINK =	$(LINKPROG:%=$(ROOTBIN)/%)

CERRWARN += -_gcc=-Wno-parentheses
CERRWARN += -_gcc=-Wno-unused-variable
CERRWARN += $(CNOWARN_UNINIT)

# because of labels from yacc
awk.g.o := CERRWARN += -_gcc=-Wno-unused-label

# not linted
SMATCH=off

#
# Message catalog
#
POFILES= $(OBJS:%.o=%.po)
POFILE= awk.po
XGETFLAGS += -a -x awk.xcl
#

CPPFLAGS += -D_FILE_OFFSET_BITS=64
YFLAGS += -d
LDLIBS += -lm -lumem
CLEANFILES= maketab proctab.c awk.g.c y.tab.h

.KEEP_STATE:

all: $(PROG) $(ROOTLINK)

$(PROG): $(OBJS)
	$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

$(ROOTLINK):	$(ROOTPROG)
	$(RM) $@; $(LN) $(ROOTPROG) $@

#
# message catalog
#

$(POFILE):  y.tab.h $(POFILES)
	$(RM) $@
	cat $(POFILES) > $@
#

proctab.c: maketab
	rm -f $@; ./maketab > $@

maketab: maketab.c
	$(NATIVECC) $(NATIVE_CFLAGS) maketab.c -o $@ $(LDLIBS)

install: all $(ROOTPROG) $(ROOTLINK)

clean:
	$(RM) $(OBJS) $(CLEANFILES)

awk.g.c + y.tab.h: awk.g.y

awk.g.o: awk.g.c

proctab.o: proctab.c
	$(COMPILE.c) proctab.c
	$(POST_PROCESS_O)

include ../Makefile.targ
