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
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

LIBRARY =	apptrace.a
VERS =		.1
OBJECTS =	apptrace.o interceptlib.o abienv.o apptraceutil.o

include ../../Makefile.abi

LIBS =		$(DYNLIB)
CPPFLAGS =      -I. $(CPPFLAGS.master)

CERRWARN +=	$(CNOWARN_UNINIT)

# No mapfile here
MAPFILES =

# Because we are compiling native, amd64/Makefile wants us to suppress
# linking with any 64-bit libraries unless the build machine is able
# to run amd64 64-bit executables:
ZDEFS =
$(SUPPRESS_LIBS)LDLIBS += -lmapmalloc -lproc -lctf -lc
$(SUPPRESS_LIBS)ZDEFS = -zdefs

all:	$(LIBS)

lint:	lintcheck

include	../../../Makefile.targ
