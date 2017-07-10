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

SHELL=/usr/bin/ksh93

LIBRARY=	libpp.a
VERS=		.1

OBJECTS= \
	ppargs.o \
	ppbuiltin.o \
	ppcall.o \
	ppcomment.o \
	ppcontext.o \
	ppcontrol.o \
	ppcpp.o \
	ppdata.o \
	pperror.o \
	ppexpr.o \
	ppfsm.o \
	ppincref.o \
	ppinput.o \
	ppkey.o \
	pplex.o \
	ppline.o \
	ppmacref.o \
	ppmisc.o \
	ppop.o \
	pppragma.o \
	ppprintf.o \
	ppproto.o \
	ppsearch.o \
	pptrace.o

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
	-lc

$(LINTLIB) :=	SRCS = $(SRCDIR)/$(LINTSRC)

SRCDIR =	../common

# We use "=" here since using $(CPPFLAGS.master) is very tricky in our
# case - it MUST come as the last element but future changes in -D options
# may then cause silent breakage in the AST sources because the last -D
# option specified overrides previous -D options so we prefer the current
# way to explicitly list each single flag.
CPPFLAGS = \
	$(DTEXTDOM) $(DTS_ERRNO) \
	-I. \
	-I$(ROOT)/usr/include/ast \
	-I$(ROOT)/usr/include \
	-D_PACKAGE_ast \
	'-DUSAGE_LICENSE=\
		"[-author?Glenn Fowler <gsf@research.att.com>]"\
		"[-copyright?Copyright (c) 1986-2009 AT&T Intellectual Property]"\
		"[-license?http://www.opensource.org/licenses/cpl1.0.txt]"\
		"[--catalog?libpp]"'


CFLAGS += \
	$(ASTCFLAGS)
CFLAGS64 += \
	$(ASTCFLAGS64)

CERRWARN	+= -_gcc=-Wno-parentheses
CERRWARN	+= -_gcc=-Wno-uninitialized
CERRWARN	+= -_gcc=-Wno-char-subscripts
CERRWARN	+= -_gcc=-Wno-empty-body
CERRWARN	+= -_gcc=-Wno-unused-value

pics/ppcall.o 		:= CERRWARN += -erroff=E_INTEGER_OVERFLOW_DETECTED
pics/ppcontrol.o 	:= CERRWARN += -erroff=E_INTEGER_OVERFLOW_DETECTED
pics/ppcpp.o		:= CERRWARN += -erroff=E_INTEGER_OVERFLOW_DETECTED
pics/ppexpr.o		:= CERRWARN += -erroff=E_INTEGER_OVERFLOW_DETECTED
pics/pplex.o		:= CERRWARN += -erroff=E_INTEGER_OVERFLOW_DETECTED
pics/ppop.o 		:= CERRWARN += -erroff=E_INTEGER_OVERFLOW_DETECTED
pics/ppsearch.o 	:= CERRWARN += -erroff=E_INTEGER_OVERFLOW_DETECTED
pics/ppsearch.o 	:= CERRWARN += -_gcc=-Wno-sequence-point
pics/pplex.o		:= CERRWARN += -_gcc=-Wno-implicit-fallthrough
pics/ppcpp.o		:= CERRWARN += -_gcc=-Wno-implicit-fallthrough
pics/ppproto.o		:= CERRWARN += -_gcc=-Wno-implicit-fallthrough

.KEEP_STATE:

all: $(LIBS)

#
# libpp is not lint-clean yet; fake up a target.  (You can use
# "make lintcheck" to actually run lint; please send all lint fixes
# upstream (to AT&T) so the next update will pull them into ON.)
#
lint:
	@ print "usr/src/lib/libpp is not lint-clean: skipping"

include ../../Makefile.targ
