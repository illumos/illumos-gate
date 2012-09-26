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

.KEEP_STATE:

include ../../Makefile.cmd
include ../../Makefile.targ

SRCS = \
	auto_comp.c \
        eventgen.c \
	fb_avl.c \
	fb_localfs.c \
	fb_random.c \
        fileset.c \
        flowop.c \
        flowop_library.c \
	gamma_dist.c \
        ipc.c \
        misc.c \
	multi_client_sync.c \
        procflow.c \
        stats.c \
        threadflow.c \
        utils.c \
        vars.c

PROG = go_filebench
ROOTFBBINDIR = $(ROOT)/usr/benchmarks/filebench/bin
OBJS = $(SRCS:%.c=%.o) parser_gram.o parser_lex.o
LINTFLAGS += -erroff=E_FUNC_ARG_UNUSED -erroff=E_NAME_DEF_NOT_USED2 \
	-erroff=E_NAME_USED_NOT_DEF2 -erroff=E_INCONS_ARG_DECL2
LINTFLAGS64 += -erroff=E_FUNC_ARG_UNUSED -erroff=E_NAME_DEF_NOT_USED2 \
	-erroff=E_NAME_USED_NOT_DEF2 -erroff=E_INCONS_ARG_DECL2

CERRWARN += -_gcc=-Wno-parentheses
CERRWARN += -_gcc=-Wno-unused-variable
CERRWARN += -_gcc=-Wno-uninitialized
CERRWARN += -_gcc=-Wno-unused-label
CERRWARN += -_gcc=-Wno-unused-function

LINTFILES = $(SRCS:%.c=%.ln)
CLEANFILES += parser_gram.c parser_gram.h parser_lex.c y.tab.h y.tab.c

CPPFLAGS += -I. -I../common
CFLAGS += $(CCVERBOSE) $(CTF_FLAGS)
CFLAGS64 += $(CCVERBOSE) $(CTF_FLAGS)
LDLIBS += -lkstat -lm -ltecla -lsocket -lnsl

LFLAGS = -t -v
YFLAGS = -d

.PARALLEL: $(OBJS) $(LINTFILES)

all: $(PROG)

$(PROG): $(OBJS)
	$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
	$(CTFMERGE) -L VERSION -o $@ $(OBJS)
	$(POST_PROCESS)

parser_lex.c: ../common/parser_lex.l
	$(FLEX) $(LFLAGS) ../common/parser_lex.l > $@

parser_gram.c: ../common/parser_gram.y
	$(YACC) $(YFLAGS) ../common/parser_gram.y
	$(MV) y.tab.c parser_gram.c
	$(MV) y.tab.h parser_gram.h

%.o: %.c
	$(COMPILE.c) $<
	$(CTFCONVERT_O)

%.o: ../common/%.c
	$(COMPILE.c) $<
	$(CTFCONVERT_O)

clean:
	$(RM) $(OBJS) $(LINTFILES) $(CLEANFILES)

%.ln: ../common/%.c
	$(LINT.c) -c $<

lint: $(LINTFILES)
	$(LINT.c) $(LINTFILES) $(LDLIBS)
