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
# cmd/awk_xpg4/Makefile
#

# NOTE: this is nawk in usr/src/cmd/awk_xpg4 to reside as /usr/xpg4/bin/awk

PROG= awk
XPG4PROG= awk

OBJ1= awk0.o awk1.o awk2.o awk3.o awk4.o
OBJ2= awk.o
XPG4AWKOBJ= values-xpg4.o
OBJS= $(OBJ2) $(OBJ1) $(XPG4AWKOBJ)
SRCS= $(OBJ1:%.o=%.c)

include ../Makefile.cmd

CPPFLAGS += -D_FILE_OFFSET_BITS=64
CFLAGS += $(CCVERBOSE)
CERRWARN += -_gcc=-Wno-unused-label
CERRWARN += -_gcc=-Wno-parentheses
CERRWARN += -_gcc=-Wno-uninitialized
YFLAGS += -d
LDLIBS += -lm
CLEANFILES= awk.c y.tab.h

# for messaging catalog

POFILE= awk_xpg4.po
POFILES= $(OBJ1:%.o=%.po) $(OBJ2:%.o=%.po)

.KEEP_STATE:

.PARALLEL:	$(OBJS)

all: $(XPG4)

$(XPG4): $(OBJS)
	$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

$(POFILE): $(POFILES)
	$(RM) $@
	cat $(POFILES) > $@
#

install: all $(ROOTXPG4PROG)

values-xpg4.o: ../../lib/crt/common/values-xpg4.c
	$(COMPILE.c) -o $@ ../../lib/crt/common/values-xpg4.c

clean:
	$(RM) $(OBJS) $(XPG4) $(CLEANFILES)

lint: lint_SRCS

awk.c + y.tab.h: awk.y

awk.o: awk.c y.tab.h

awk0.c: awk.c y.tab.h

awk1.c: awk.c y.tab.h

awk2.c: awk.c y.tab.h

awk3.c: awk.c y.tab.h

awk4.c: awk.c y.tab.h

include ../Makefile.targ
