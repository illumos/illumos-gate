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
# Copyright (c) 2018, Joyent, Inc.

SHELL=/usr/bin/ksh93

include ../../Makefile.cmd

.KEEP_STATE:

# Set common AST build flags (e.g., needed to support the math stuff).
include ../../../Makefile.ast

# build rules
CPPFLAGS = \
        $(DTEXTDOM) $(DTS_ERRNO) \
        -I$(ROOT)/usr/include/ast \
	-I$(ROOT)/usr/include \
	-D_PACKAGE_ast \
	'-DUSAGE_LICENSE=\
		"[-author?Glenn Fowler <gsf@research.att.com>]"\
		"[-copyright?Copyright (c) 1986-2009 AT&T Intellectual Property]"\
		"[-license?http://www.opensource.org/licenses/cpl1.0.txt]"\
		"[--catalog?msgcc]"'

CFLAGS += \
	$(ASTCFLAGS)

CERRWARN += -_gcc=-Wno-parentheses
CERRWARN += -_gcc=-Wno-empty-body
CERRWARN += -_gcc=-Wno-uninitialized

# not linted
SMATCH=off

LDLIBS += -last
msgcpp   := LDLIBS += -lpp

# This target should use "shcomp" in the future
msgcc:	msgcc.sh
	rm -f msgcc ; \
	{ \
		print "#!/usr/bin/ksh93" ; \
		print "export PATH=/usr/ast/bin:/usr/xpg6/bin:/usr/xpg4/bin:/usr/bin:\$${PATH}" ; \
		print "builtin date" ; \
		cat "msgcc.sh" ; \
	} >msgcc ; \
	chmod a+rx msgcc

ROOTCMDDIR=$(ROOT)/usr/ast/bin

PROG= msgcvt msggen msgget msgcpp msgcc

all: $(PROG)

install: all $(ROOTCMD)

clean lint:

include ../../Makefile.targ
