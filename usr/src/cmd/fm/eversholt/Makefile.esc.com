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
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright 2018 RackTop Systems.
#

FMADIR = $(SRC)/cmd/fm
EVERDIR = $(FMADIR)/eversholt
EVERCMNSRC = $(EVERDIR)/common

EFTCLASS = reader
writer_WRTOBJ = eftwrite.o
reader_WRTOBJ =

CMNOBJS = alloc.o check.o eftread.o esclex.o io.o literals.o lut.o \
	out.o ptree.o stable.o stats.o tree.o $($(EFTCLASS)_WRTOBJ)

COMMONOBJS = escparse.o $(CMNOBJS)
COMMONSRCS = $(COMMONOBJS:%.o=$(EVERCMNSRC)/%.c)

LINTSRCS = $(CMNOBJS:%.o=$(EVERCMNSRC)/%.c)
LINTFLAGS = -mnux

$(NOT_RELEASE_BUILD)CPPFLAGS += -DDEBUG

CPPFLAGS += -I$(EVERCMNSRC) -I.
CFLAGS += $(CCVERBOSE)
CERRWARN += -_gcc=-Wno-uninitialized
CERRWARN += -_gcc=-Wno-unused-label
CERRWARN += -_gcc=-Wno-parentheses
CERRWARN += -_gcc=-Wno-switch

CTFCONVO = $(CTFCONVERT_O)
CTFMRG = $(CTFMERGE) -L VERSION -o $@ $(OBJS)

debug := COPTFLAG =
debug := COPTFLAG64 =

ROOTPDIR = $(ROOT)/usr/lib/fm
ROOTPROG = $(ROOTPDIR)/$(PROG)

install: $(PROG) $(ROOTPROG)

install_h: $(ROOTHDIR) $(ROOTHDRS)

lint:	$(LINTSRCS)
	$(LINT.c) $(LINTSRCS) $(LDLIBS)

%.o: %.c
	$(COMPILE.c) $<
	$(CTFCONVO)

%.o: $(EVERCMNSRC)/%.c
	$(COMPILE.c) $<
	$(CTFCONVO)

escparse.o: $(EVERCMNSRC)/escparse.y
	$(YACC) -dtv $(EVERCMNSRC)/escparse.y
	$(COMPILE.c) -DYYDEBUG -c -o $@ y.tab.c
	$(CTFCONVO)

$(ROOTPDIR):
	$(INS.dir)

$(ROOTPDIR)/%: % $(ROOTPDIR)
	$(INS.file)

