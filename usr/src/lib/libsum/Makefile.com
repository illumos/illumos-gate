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

LIBRARY=	libsum.a
VERS=		.1

OBJECTS= \
	sumlib.o

include ../../Makefile.astmsg

include ../../Makefile.lib

# mapfile-vers does not live with the sources in in common/ to make
# automated code updates easier.
MAPFILES=       ../mapfile-vers

# Set common AST build flags (e.g. C99/XPG6, needed to support the math stuff)
include ../../../Makefile.ast

LIBS =		$(DYNLIB) $(LINTLIB)

LDLIBS += \
		-last \
		-lmd \
		-lc

$(LINTLIB) :=	SRCS = $(SRCDIR)/$(LINTSRC)

SRCDIR =	../common

# We use "=" here since using $(CPPFLAGS.master) is very tricky in our
# case - it MUST come as the last element but future changes in -D options
# may then cause silent breakage in the AST sources because the last -D
# option specified overrides previous -D options so we prefer the current
# way to explicitly list each single flag.
# Notes:
#   - "-D_BLD_DLL" comes from ${mam_cc_DLL} in Mamfile
CPPFLAGS = \
	$(DTEXTDOM) $(DTS_ERRNO) \
	-Isrc/lib/libsum \
	-I$(ROOT)/usr/include/ast \
	-I$(ROOT)/usr/include \
	-D_PACKAGE_ast \
	-D_BLD_DLL

CFLAGS += \
	$(ASTCFLAGS)
CFLAGS64 += \
	$(ASTCFLAGS64)

CERRWARN	+= -_gcc=-Wno-parentheses

SMOFF += all_func_returns

# This codepath is performance-critical
sparc_COPTFLAG=-xO5 -_cc=-xprefetch=auto,explicit
sparcv9_COPTFLAG=-xO5 -_cc=-xprefetch=auto,explicit
i386_COPTFLAG=-_cc=-xO5 -_cc=-xprefetch=auto,explicit
amd64_COPTFLAG=-_cc=-xO5  -_cc=-xprefetch=auto,explicit

# Suppress this one warning as the fix would break old gcc, which upstream
# still supports. This needs a better fix (later).
pics/sumlib.o	:= CERRWARN += -erroff=E_CONST_PROMOTED_UNSIGNED_LONG

.KEEP_STATE:

all: $(LIBS)

#
# libsum is not lint-clean yet; fake up a target.  (You can use
# "make lintcheck" to actually run lint; please send all lint fixes
# upstream (to AT&T) so the next update will pull them into ON.)
#
lint:
	@ print "usr/src/lib/libsum is not lint-clean: skipping"

include ../../Makefile.targ
