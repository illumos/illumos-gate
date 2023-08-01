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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

LIBRARY = libfmd_agent.a
VERS = .1

LIBSRCS = fmd_agent.c fmd_agent_$(MACH).c
OBJECTS = $(LIBSRCS:%.c=%.o)

include ../../../Makefile.lib
include ../../Makefile.lib

SRCS = ../common/fmd_agent.c ../$(MACH)/fmd_agent_$(MACH).c
LIBS = $(DYNLIB)

SRCDIR =	../common

CPPFLAGS += -I../common -I.
CFLAGS += $(CCVERBOSE) $(C_BIGPICFLAGS)
CFLAGS64 += $(CCVERBOSE) $(C_BIGPICFLAGS)
LDLIBS += -lnvpair -lumem -lc
CSTD =		$(CSTD_GNU99)


.KEEP_STATE:

pics/%.o: ../$(MACH)/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

all: $(LIBS)

include ../../../Makefile.targ
include ../../Makefile.targ
