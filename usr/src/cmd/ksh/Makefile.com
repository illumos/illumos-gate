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

SHELL=/usr/bin/ksh93

PROG= ksh

USRKSH_ALIAS_LIST=ksh ksh93 rksh rksh93

OBJECTS= \
	pmain.o

LIBSHELLBASE=../../../lib/libshell
LIBSHELLSRC=$(LIBSHELLBASE)/common/sh

SRCS=	$(OBJECTS:%.o=$(LIBSHELLSRC)/%.c)

LDLIBS += -lshell

# Set common AST build flags (e.g., needed to support the math stuff).
include ../../../Makefile.ast

# 1. Make sure that the -D/-U defines in CFLAGS below are in sync
# with usr/src/lib/libshell/Makefile.com
# 2. We use "=" here since using $(CPPFLAGS.master) is very tricky in our
# case - it MUST come as the last element but future changes in -D options
# may then cause silent breakage in the AST sources because the last -D
# option specified overrides previous -D options so we prefer the current
# way to explicitly list each single flag.
CPPFLAGS = \
	$(DTEXTDOM) $(DTS_ERRNO) \
	$(LIBSHELLCPPFLAGS)

CFLAGS += \
	$(ASTCFLAGS)
CFLAGS64 += \
	$(ASTCFLAGS64)

# Workaround for CR#6628728 ("|memcntl()| prototype not available for C99/XPG6")
pmain.o	:= CERRWARN += -_gcc=-Wno-implicit-function-declaration
pmain.o	:= CERRWARN += -erroff=E_NO_IMPLICIT_DECL_ALLOWED

# not linted
SMATCH=off

.KEEP_STATE:

%.o:	$(LIBSHELLSRC)/%.c
	$(COMPILE.c) -c -o $@ $<
	$(POST_PROCESS_O)

all:	$(PROG)

# We explicitly delete "ksh" and "ksh93" to catch changes in
# BUILD_KSH93_AS_BINKSH (see Makefile.ksh93switch)
# and soft-link $(PROG) to ksh/ksh93 below because ksh93 test
# suite seems to require that ksh93 is available as "ksh" in
# ${PATH} (see comment about "io.sh" in Makefile.testshell).
$(PROG):	$(OBJECTS)
	$(RM) ksh ksh93
	$(LINK.c) $(OBJECTS) -o $@ $(LDLIBS)
	$(POST_PROCESS)
	(set +o errexit ; \
	[[ ! -x ksh93 ]] && ln $(PROG) ksh93 ; \
	[[ ! -x ksh   ]] && ln $(PROG) ksh   ; \
	true \
	)

clean:
	$(RM) $(OBJECTS)

# We explicitly delete "ksh" and "ksh93" to catch changes in
# BUILD_KSH93_AS_BINKSH (see Makefile.ksh93switch)
CLOBBERFILES += \
	ksh \
	ksh93

# Install rule for $(MACH)/Makefile (32bit)
INSTALL.ksh.32bit=@ \
	(print "$(POUND_SIGN) Installing 32bit $(PROG) aliases $(USRKSH_ALIAS_LIST)" ; \
	set -o xtrace ; \
	for i in $(USRKSH_ALIAS_LIST) ; do \
		[[ "$$i" == "$(PROG)" ]] && continue ; \
		$(RM) "$(ROOTBIN32)/$$i" ; \
		$(LN) "$(ROOTBIN32)/$(PROG)" "$(ROOTBIN32)/$$i" ; \
	done \
	)

# Install rule for $(MACH64)/Makefile (64bit)
INSTALL.ksh.64bit=@ \
	(print "$(POUND_SIGN) Installing 64bit $(PROG) aliases $(USRKSH_ALIAS_LIST)" ; \
	set -o xtrace ; \
	for i in $(USRKSH_ALIAS_LIST) ; do \
		[[ "$$i" == "$(PROG)" ]] && continue ; \
		$(RM) "$(ROOTBIN64)/$$i" ; \
		$(LN) "$(ROOTBIN64)/$(PROG)" "$(ROOTBIN64)/$$i" ; \
	done \
	)

#
# ksh is not lint-clean yet; fake up a target.  (You can use
# "make lintcheck" to actually run lint; please send all lint fixes
# upstream (to AT&T) so the next update will pull them into ON.)
#
lint:
	@ print "usr/src/cmd/ksh is not lint-clean: skipping"

include ../Makefile.testshell
