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
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright (c) 2019, Joyent, Inc.
#

LIB	= geniconvtbl.so
PROG	= geniconvtbl

SRCDIR  = $(SRC)/cmd/geniconvtbl

MAPFILE	= $(SRCDIR)/mapfile

OBJS    = itmcomp.o assemble.o disassemble.o itm_util.o y.tab.o lex.yy.o
MSGFILES = itmcomp.i assemble.i disassemble.i itm_util.i y.tab.i lex.yy.i geniconvtbl.i

include $(SRC)/cmd/Makefile.cmd

POFILE	= geniconvtbl_.po

ROOTDIRS32=	$(ROOTLIB)/iconv
ROOTDIRS64=	$(ROOTLIB)/iconv/$(MACH64)
ROOTLIB32 =	$(ROOTDIRS32)/$(LIB)
ROOTLIB64 =	$(ROOTDIRS64)/$(LIB)

CLOBBERFILES=	$(LIB)
CLEANFILES =	$(OBJS) y.tab.c y.tab.h lex.yy.c \
		$(POFILE)

CPPFLAGS	+= -I. -I$(SRCDIR)
CERRWARN	+= $(CNOWARN_UNINIT)
CERRWARN	+= -_gcc=-Wno-unused-label
CERRWARN	+= -_gcc=-Wno-switch
CERRWARN	+= -_gcc=-Wno-unused-variable
CERRWARN	+= -_gcc=-Wno-implicit-function-declaration
YFLAGS		+= -d
CFLAGS		+= -D_FILE_OFFSET_BITS=64

# dump_expr() is too hairy
SMATCH=off

$(LIB) :=	LDFLAGS += $(GSHARED) -Wl,-h$@ $(ZTEXT) $(ZDEFS) $(BDIRECT) \
		$(C_PICFLAGS) $(MAPFILE:%=-Wl,-M%)			\
		$(MAPFILE.PGA:%=-Wl,-M%) $(MAPFILE.NED:%=-Wl,-M%)
$(LIB) :=	CPPFLAGS += -D_REENTRANT
$(LIB) :=	LDLIBS += -lc

$(PROG) :=	LDLIBS += -lgen

.KEEP_STATE:

.PARALLEL: $(LIB) $(OBJS)

$(PROG): $(OBJS)
	$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

$(LIB): $(SRCDIR)/geniconvtbl.c
	$(LINK.c) -o $@ $(SRCDIR)/geniconvtbl.c $(LDLIBS)
	$(POST_PROCESS_SO)

y.tab.c + y.tab.h: $(SRCDIR)/itm_comp.y
	$(YACC) $(YFLAGS) $(SRCDIR)/itm_comp.y
	@ $(MV) y.tab.c y.tab.c~
	@ $(SED) -f  $(SRCDIR)/yacc.sed y.tab.c~ > y.tab.c
	@ $(RM) y.tab.c~

lex.yy.c: $(SRCDIR)/itm_comp.l y.tab.h
	$(LEX) -t $(SRCDIR)/itm_comp.l | $(SED) -f $(SRCDIR)/lex.sed > $(@)

clean:
	$(RM) $(CLEANFILES)

$(POFILE): $(MSGFILES)
	$(BUILDPO.msgfiles)

%.o:	%.c
	$(COMPILE.c) $<

%.o:	$(SRCDIR)/%.c
	$(COMPILE.c) $<

%.i:	$(SRCDIR)/%.c
	$(CPPFORPO) $< > $@

# install rule
$(ROOTDIRS32)/%: $(ROOTDIRS32) %
	$(INS.file)

$(ROOTDIRS64)/%: $(ROOTDIRS64) %
	$(INS.file)

$(ROOTDIRS32): $(ROOTLIB)
	$(INS.dir)

$(ROOTDIRS64): $(ROOTDIRS32)
	$(INS.dir)

include $(SRC)/cmd/Makefile.targ
include $(SRC)/Makefile.msg.targ
