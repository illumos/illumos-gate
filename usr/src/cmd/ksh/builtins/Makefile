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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright 2010 Nexenta Systems, Inc.  All rights reserved.
#
# Copyright (c) 2018, Joyent, Inc.
#

PROG= alias
ALIASPROG= \
	bg \
	cd \
	cksum \
	cmp \
	comm \
	command \
	cut \
	fc \
	fg \
	getopts \
	hash \
	jobs \
	join \
	kill \
	logname \
	paste \
	print \
	read \
	rev \
	sleep \
	sum \
	tee \
	test \
	type \
	ulimit \
	umask \
	unalias \
	uniq \
	wait \
	wc

XPG4ALIASPROG= \
	alias \
	bg \
	cd \
	command \
	fc \
	fg \
	getopts \
	hash \
	jobs \
	kill \
	read \
	test \
	type \
	ulimit \
	umask \
	unalias \
	wait

XPG4SH= \
	sh

ROOTXPG4ALIAS= \
	$(XPG4SH:%=$(ROOTXPG4BIN)/%) $(XPG4ALIASPROG:%=$(ROOTXPG4BIN)/%)
ROOTALIASPROG= $(ALIASPROG:%=$(ROOTBIN)/%)

include ../../Makefile.cmd
$(SPARC_BLD)include ../../Makefile.cmd.64

FILEMODE= 555
CERRWARN += -_gcc=-Wno-parentheses

# not linted
SMATCH=off

.KEEP_STATE:

all: $(PROG)

$(XPG4ALIASPROG:%=$(ROOTXPG4BIN)/%):
	$(RM) $@; $(SYMLINK) ../../bin/alias $@

$(XPG4SH:%=$(ROOTXPG4BIN)/%):
	$(RM) $@; $(SYMLINK) ../../bin/ksh93 $@

$(ALIASPROG:%=$(ROOTBIN)/%): $(ROOTPROG)
	$(RM) $@; $(LN) $(ROOTPROG) $@

.KEEP_STATE:

# Set common AST build flags (e.g., needed to support the math stuff).
include ../../../Makefile.ast

OBJECTS= \
        alias.o

SRCS=	$(OBJECTS:%.o=%.c)

LDLIBS += -lshell -lcmd -last

CPPFLAGS = \
	$(DTEXTDOM) $(DTS_ERRNO) \
	-I$(ROOT)/usr/include/ast \
	-I$(ROOT)/usr/include

# Enable workaround for a crash in /usr/bin/alias when invalid
# options are passed (e.g. $ /usr/bin/alias -c #). The shell
# code will call an error handler which does a |longjmp()| but
# somehow the code failed to do the |setjmp()| before this point.
CPPFLAGS += -DWORKAROUND_FOR_ALIAS_CRASH

CFLAGS += \
	$(ASTCFLAGS)
CFLAGS64 += \
	$(ASTCFLAGS64)

ROOTCMDDIR=$(ROOT)/usr/bin

install: all $(ROOTPROG) $(ROOTXPG4PROG) $(ROOTALIASPROG) $(ROOTXPG4ALIAS)

$(PROG):	$(OBJECTS)
	$(RM) alias
	$(LINK.c) $(OBJECTS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

clean clobber:
	rm -f $(PROG) $(OBJECTS)

lint _msg:
