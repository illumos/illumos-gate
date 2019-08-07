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
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

.KEEP_STATE:
.SUFFIXES:

SRCS += \
	inj_cmds.c \
	inj_decl.c \
	inj_defn.c \
	inj_err.c \
	inj_hash.c \
	inj_list.c \
	inj_log.c \
	inj_main.c \
	inj_string.c \
	inj_umem.c \
	inj_util.c

PROG = fminject
ROOTPDIR = $(ROOT)/usr/lib/fm/fmd
ROOTPROG = $(ROOTPDIR)/$(PROG)
OBJS = $(SRCS:%.c=%.o) inj_grammar.o inj_lex.o
LINTFILES = $(SRCS:%.c=%.ln)
CLEANFILES += inj_grammar.c inj_grammar.h inj_lex.c y.tab.h y.tab.c

CPPFLAGS += -I. -I../common
CFLAGS += $(CCVERBOSE) $(CTF_FLAGS)
CERRWARN += -_gcc=-Wno-switch
CERRWARN += $(CNOWARN_UNINIT)
CERRWARN += -_gcc=-Wno-type-limits
CERRWARN += -_gcc=-Wno-unused-label
CERRWARN += -_gcc=-Wno-unused-variable
LDLIBS += -L$(ROOT)/usr/lib/fm -lfmd_log -lsysevent -lnvpair -lumem
LDFLAGS += -R/usr/lib/fm
LINTFLAGS = -mnux
STRIPFLAG =

LFLAGS = -t -v
YFLAGS = -d

.PARALLEL: $(OBJS) $(LINTFILES)

all: $(PROG)

$(PROG): $(OBJS)
	$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
	$(CTFMERGE) -L VERSION -o $@ $(OBJS)
	$(POST_PROCESS)

inj_lex.c: ../common/inj_lex.l inj_grammar.c
	$(LEX) $(LFLAGS) ../common/inj_lex.l > $@

inj_grammar.c: ../common/inj_grammar.y
	$(YACC) $(YFLAGS) ../common/inj_grammar.y
	$(MV) y.tab.c inj_grammar.c
	$(MV) y.tab.h inj_grammar.h

%.o: %.c
	$(COMPILE.c) $<
	$(CTFCONVERT_O)

%.o: ../common/%.c
	$(COMPILE.c) $<
	$(CTFCONVERT_O)

clean:
	$(RM) $(OBJS) $(LINTFILES) $(CLEANFILES)

clobber: clean
	$(RM) $(PROG)

%.ln: %.c
	$(LINT.c) -c $<

%.ln: ../common/%.c
	$(LINT.c) -c $<

lint: $(LINTFILES)
	$(LINT.c) $(LINTFILES) $(LDLIBS)

$(ROOT)/usr/lib/fm:
	$(INS.dir)

$(ROOTPDIR): $(ROOT)/usr/lib/fm
	$(INS.dir)

$(ROOTPDIR)/%: %
	$(INS.file)

install_h:

install: all $(ROOTPDIR) $(ROOTPROG)
