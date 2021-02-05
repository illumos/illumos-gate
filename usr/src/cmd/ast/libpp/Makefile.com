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
# Copyright (c) 2019, Joyent, Inc.
# Copyright 2021 OmniOS Community Edition (OmniOSce) Association.

SHELL= /usr/bin/ksh93

LIBRARY= libpp.a
VERS= .1

include ../Makefile.defs

OBJECTS += $(LIBOBJS)

include $(SRC)/lib/Makefile.lib
include ../../Makefile.ast

MAPFILES=       ../mapfile-vers

LIBS=		$(DYNLIB)

LDLIBS += -last -lc

# We use "=" here since using $(CPPFLAGS.master) is very tricky in our
# case - it MUST come as the last element but future changes in -D options
# may then cause silent breakage in the AST sources because the last -D
# option specified overrides previous -D options so we prefer the current
# way to explicitly list each single flag.
CPPFLAGS= \
	$(DTEXTDOM) $(DTS_ERRNO) \
	-I. \
	-I$(ROOT)/usr/include/ast \
	-I$(ROOT)/usr/include \
	-D_PACKAGE_ast \
	'-DUSAGE_LICENSE=\
	    "[-author?Glenn Fowler <gsf@research.att.com>]"\
	    "[-copyright?Copyright (c) 1986-2012 AT&T Intellectual Property]"\
	    "[-license?http://www.eclipse.org/org/documents/epl-v10.html]"\
	    "[--catalog?libpp]"'

CFLAGS += $(ASTCFLAGS)
CFLAGS64 += $(ASTCFLAGS64)

CERRWARN	+= -_gcc=-Wno-parentheses
CERRWARN	+= $(CNOWARN_UNINIT)
CERRWARN	+= -_gcc=-Wno-char-subscripts
CERRWARN	+= -_gcc=-Wno-empty-body
CERRWARN	+= -_gcc=-Wno-unused-value

# "pplex() parse error: turning off implications after 60 seconds"
SMATCH		= off

.KEEP_STATE:

all: $(LIBS)

include $(SRC)/lib/Makefile.targ

ppdef.h: $(ASTSRC)/pp.tab
	$(AST_TOOLS)/gentab -d $(ASTSRC)/pp.tab > $@

pptab.h: $(ASTSRC)/pp.tab
	$(AST_TOOLS)/gentab -t $(ASTSRC)/pp.tab > $@

pics/%.o: $(ASTSRC)/%.c ppdef.h pptab.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<
	$(POST_PROCESS_O)

CLOBBERFILES += pptab.h ppdef.h

include ../../Makefile.astmsg
