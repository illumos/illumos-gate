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
# Copyright (c) 2019, Joyent, Inc.
#

SHELL=/usr/bin/ksh93

LIBRARY=	libshell.a
VERS=		.1

OBJECTS= \
	bltins/alarm.o \
	bltins/cd_pwd.o \
	bltins/cflow.o \
	bltins/enum.o \
	bltins/getopts.o \
	bltins/hist.o \
	bltins/misc.o \
	bltins/poll_solaris.o \
	bltins/print.o \
	bltins/read.o \
	bltins/regress.o \
	bltins/shiocmd_solaris.o \
	bltins/sleep.o \
	bltins/test.o \
	bltins/trap.o \
	bltins/typeset.o \
	bltins/ulimit.o \
	bltins/umask.o \
	bltins/whence.o \
	data/aliases.o \
	data/builtins.o \
	data/keywords.o \
	data/lexstates.o \
	data/limits.o \
	data/msg.o \
	data/options.o \
	data/signals.o \
	data/strdata.o \
	data/testops.o \
	data/variables.o \
	edit/completion.o \
	edit/edit.o \
	edit/emacs.o \
	edit/hexpand.o \
	edit/history.o \
	edit/vi.o \
	sh/args.o \
	sh/arith.o \
	sh/array.o \
	sh/defs.o \
	sh/deparse.o \
	sh/expand.o \
	sh/fault.o \
	sh/fcin.o \
	sh/init.o \
	sh/io.o \
	sh/jobs.o \
	sh/lex.o \
	sh/macro.o \
	sh/main.o \
	sh/name.o \
	sh/nvdisc.o \
	sh/nvtree.o \
	sh/nvtype.o \
	sh/parse.o \
	sh/path.o \
	sh/streval.o \
	sh/string.o \
	sh/subshell.o \
	sh/tdump.o \
	sh/timers.o \
	sh/trestore.o \
	sh/waitevent.o \
	sh/xec.o

# We are storing the object files into subdirs avoid the
# confusion with having too many object files in the toplevel pics/
# directory (this matches the way how the original AST build system
# deals with this "logistic" issue) - the rules below ensure that
# the destination directory is available.
OBJDIRS =  \
	bltins \
	data \
	edit \
	sh
PICSDIRS= $(OBJDIRS:%=pics/%)
mkpicdirs:
	@mkdir -p $(PICSDIRS)

# Specify the MACH we currently use to build and test ksh
LIBSHELLMACH= $(TARGETMACH)
LIBSHELLBASE=..

include ../../Makefile.astmsg

include ../../Makefile.lib

# mapfile-vers does not live with the sources in in common/ to make
# automated code updates easier.
MAPFILES=       ../mapfile-vers

# Set common AST build flags (e.g. C99/XPG6, needed to support the math stuff)
include ../../../Makefile.ast

LIBS =		$(DYNLIB)

LDLIBS += \
	-lcmd \
	-ldll \
	-last \
	-lsocket \
	-lm \
	-lc


SRCDIR =	../common

# 1. Make sure that the -D/-U defines in CPPFLAGS below are in sync
# with usr/src/cmd/ksh/Makefile.com
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

CERRWARN	+= -_gcc=-Wno-parentheses
CERRWARN	+= -_gcc=-Wno-unused-value
CERRWARN	+= -_gcc=-Wno-unused-variable
CERRWARN	+= -_gcc=-Wno-unused-function
CERRWARN	+= $(CNOWARN_UNINIT)
CERRWARN	+= -_gcc=-Wno-clobbered
CERRWARN	+= -_gcc=-Wno-char-subscripts

# smatch gets out of memory on common/sh/macro.c
SMATCH		= off

pics/sh/macro.o		:= CERRWARN += -erroff=E_NO_IMPLICIT_DECL_ALLOWED
pics/sh/nvdisc.o	:= CERRWARN += -erroff=E_END_OF_LOOP_CODE_NOT_REACHED

.KEEP_STATE:

all: mkpicdirs .WAIT $(LIBS)

include ../../Makefile.targ
