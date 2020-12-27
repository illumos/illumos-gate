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
# Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
#
# Copyright (c) 2018, Joyent, Inc.
# Copyright 2021 OmniOS Community Edition (OmniOSce) Association.

SHELL= /usr/bin/ksh93

LIBRARY= libcmd.a
VERS= .1

include ../Makefile.defs

OBJECTS += $(LIBOBJS)

include $(SRC)/lib/Makefile.lib
include ../../Makefile.ast

MAPFILES= ../mapfile-vers

LIBS= $(DYNLIB)

LDLIBS += -lsum -last -lsocket -lnsl -lc

# We use "=" here since using $(CPPFLAGS.master) is very tricky in our
# case - it MUST come as the last element but future changes in -D options
# may then cause silent breakage in the AST sources because the last -D
# option specified overrides previous -D options so we prefer the current
# way to explicitly list each single flag.
CPPFLAGS= \
	$(DTEXTDOM) $(DTS_ERRNO) \
	-I$(ASTSRC) \
	-Iast -I. \
	-I$(ROOT)/usr/include/ast \
	-I$(ROOT)/usr/include \
	-D_BLD_cmd \
	-D_PACKAGE_ast \
	-D_BLD_DLL \
	'-DERROR_CATALOG="libcmd"' \
	'-DUSAGE_LICENSE=\
	    "[-author?Glenn Fowler <gsf@research.att.com>]"\
	    "[-author?David Korn <dgk@research.att.com>]"\
	    "[-copyright?Copyright (c) 1992-2012 AT&T Intellectual Property]"\
	    "[-license?http://www.eclipse.org/org/documents/epl-v10.html]"\
	    "[--catalog?libcmd]"'

CFLAGS += $(ASTCFLAGS)
CFLAGS64 += $(ASTCFLAGS64)

CERRWARN	+= -_gcc=-Wno-unused-value
CERRWARN	+= -_gcc=-Wno-parentheses
CERRWARN	+= $(CNOWARN_UNINIT)
CERRWARN	+= -_gcc=-Wno-unused-variable
CERRWARN	+= -_gcc=-Wno-implicit-function-declaration

# not linted
SMATCH=off

all: install_h .WAIT $(LIBS)

include $(SRC)/lib/Makefile.targ

pics/%.o: $(ASTSRC)/%.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<
	$(POST_PROCESS_O)

######################################################################
# Header file generation

$(HEADERSRC:%=ast/%): FRC
	$(MKDIR) -p $(@D)
	$(CP) $(ASTSRC)/$(@F) $@

# This rule is derived from $(CONTRIB)/ast/src/lib/libcmd/Makefile
ast/cmdext.h:
	$(MKDIR) -p $(@D)
	echo '#include <shcmd.h>' > $@.tmp
	$(SED) \
	    -e '/^b_[a-z_][a-z_0-9]*(/!d' \
	    -e 's/^b_//' \
	    -e 's/(.*//' \
	    -e 's/.*/extern int     b_&(int, char**, Shbltin_t*);/' \
	    $(OBJECTS:%.o=$(ASTSRC)/%.c) | \
	    $(SORT) -u \
	    >> $@.tmp
	$(AST_PROTO) -f $@.tmp >> $@
	rm -f $@.tmp
	$(POST_PROCESS_AST) $@

CLOBBERFILES += ast/*

install_h: $(HEADERSRC:%=ast/%) $(HEADERGEN:%=ast/%)

.PARALLEL: $(HEADERSRC:%=ast/%) $(HEADERGEN:%=ast/%)

_feature: FRC
	$(MAKE) -f Makefile.iffe generate

include ../../Makefile.astmsg

FRC:
