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
# Copyright 1990-2003 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# cmd/face/src/proc/Makefile
#
LIBRARY = libproc.a

OBJECTS = suspend.o suspendcheck.o

# include library definitions
include ../../../../lib/Makefile.lib

# Specifically request the construction of a static library.
# This library is not installed in the proto area.
LIBS = $(LIBRARY)

SRCS = suspend.c


# inc must be first.
CPPFLAGS = -I../filecab/inc $(CPPFLAGS.master)

#
ARFLAGS = rv

#two objects from one source.
%/suspendcheck.o := CPPFLAGS += -DJUSTCHECK

.KEEP_STATE:

all: $(LIBS)

%/suspendcheck.o: suspend.c
	$(COMPILE.c) -o $@ suspend.c

install: all
	@echo "$(LIBRARY) is not installed."

# include library targets
include ../../../../lib/Makefile.targ
