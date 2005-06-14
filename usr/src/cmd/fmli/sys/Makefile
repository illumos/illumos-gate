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
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# cmd/fmli/sys/Makefile
#
LIBRARY = libsys.a

OBJECTS = actrec.o ar_mfuncs.o backslash.o chgenv.o chgepenv.o \
	compile.o coproc.o copyfile.o estrtok.o evfuncs.o eval.o \
	evalstr.o exit.o expand.o expr.o filename.o genfind.o \
	getaltenv.o getepenv.o grep.o io.o itoa.o memshift.o \
	mencmds.o cut.o nstrcat.o onexit.o parent.o putaltenv.o \
	readfile.o scrclean.o spawn.o strappend.o strCcmp.o stream.o \
	strsave.o tempfiles.o terrmess.o terror.o test.o varappend.o \
	varchkapnd.o varcreate.o vardelete.o vargrow.o varinsert.o \
	varshrink.o watch.o

# include library definitions
include ../../../lib/Makefile.lib

C99MODE=	$(C99_DISABLE)

# Specifically request the construction of a static library.
# This library is not installed in the proto area.
LIBS = $(LIBRARY)

# inc must be first.
CPPFLAGS = -I../inc $(CPPFLAGS.master)

.KEEP_STATE:

all: $(LIBS)

install: all
	@echo "$(LIBRARY) is not installed."

# include library targets
include ../../../lib/Makefile.targ
