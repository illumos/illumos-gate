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
# Copyright (c) 2018, Joyent, Inc.

#
# Debugging targets
#   sort provides a number of debugging options to simplify failure analysis.
#
#   debug		provides symbol information and sets DEBUG; includes
#			convert, invoke
#   stats		builds binaries with statistics reporting enabled
#   convert		builds convert binaries (converts input to collation
#			vectors)
#   invoke		builds invoke binaries (allows inspection of options
#			parser outcome)
#
# Debugging #defines
#   DEBUG		activate assertions; allow wider range of memory
#			settings (-S)
#   DEBUG_FORCE_WIDE	force all i/o through wide streams
#   DEBUG_DISALLOW_MMAP	force all i/o through stdio or wide streams
#   DEBUG_NO_CACHE_TEMP	do not cache last sorted portion in memory; write all
#			data to temporary files before merge
#

PROG = sort
XPG4PROG = sort

BASE_OBJS = \
	check.o \
	fields.o \
	initialize.o \
	internal.o \
	merge.o \
	options.o \
	streams.o \
	streams_array.o \
	streams_mmap.o \
	streams_stdio.o \
	streams_wide.o \
	utility.o
OBJS =	main.o $(BASE_OBJS)
INVOKE_OBJS = invoke.o $(BASE_OBJS)
CONVERT_OBJS = convert.o $(BASE_OBJS)
STATS_OBJS = main.o statistics.o $(BASE_OBJS)

XPG4OBJS = $(OBJS:%.o=xpg4_%.o)
SRCS =  $(OBJS:%.o=../common/%.c)
LNTS =	$(OBJS:%.o=%.ln)
CLEANFILES = $(OBJS) $(XPG4OBJS) $(LNTS)

include ../../Makefile.cmd

DCFILE =	$(PROG).dc

CFLAGS +=	$(CCVERBOSE) $(SORT_DEBUG)
CFLAGS64 +=	$(CCVERBOSE) $(SORT_DEBUG)
CPPFLAGS +=	-D_FILE_OFFSET_BITS=64
LINTFLAGS +=	-U_FILE_OFFSET_BITS

CERRWARN +=	-_gcc=-Wno-parentheses
CERRWARN +=	$(CNOWARN_UNINIT)
CERRWARN +=	-_gcc=-Wno-unused-function

# not linted
SMATCH=off

$(XPG4)	:=	CFLAGS += -DXPG4

debug :=	SORT_DEBUG = $(CCGDEBUG) -DDEBUG
debug :=	COPTFLAG =
debug :=	COPTFLAG64 =
stats	:=	SORT_DEBUG = $(CCGDEBUG) -DSTATS -DDEBUG
stats	:=	COPTFLAG =
stats	:=	COPTFLAG64 =

.KEEP_STATE :

.PARALLEL : $(OBJS) $(XPG4OBJS) $(LNTS)

all : $(PROG) $(XPG4)

debug : $(PROG) convert invoke

lint : $(LNTS)
	$(LINT.c) $(LINTFLAGS) $(LNTS) $(LDLIBS)

clean :
	$(RM) $(CLEANFILES)

include ../../Makefile.targ

# rules for $(PROG) and $(XPG4)

$(PROG) : $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

$(XPG4) : $(XPG4OBJS)
	$(LINK.c) -o $@ $(XPG4OBJS) $(LDLIBS)
	$(POST_PROCESS)

invoke: $(INVOKE_OBJS)
	$(LINK.c) -o $@ $(INVOKE_OBJS) $(LDLIBS)

convert: $(CONVERT_OBJS)
	$(LINK.c) -o $@ $(CONVERT_OBJS) $(LDLIBS)

stats: $(STATS_OBJS)
	$(LINK.c) -o $@ $(STATS_OBJS) $(LDLIBS)

%.o : ../common/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

xpg4_%.o : ../common/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

%.o : ../common/%.h types.h

xpg4_%.o : ../common/%.h types.h

%.ln: ../common/%.c
	$(LINT.c) $(LINTFLAGS) -c $<
