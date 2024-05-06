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
# Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
# Copyright 2020 Joyent, Inc.
#

MYPROG =	svccfg
PROG =		$(MYPROG)

SRCS  =		svccfg_main.c \
		svccfg_engine.c \
		svccfg_internal.c \
		svccfg_libscf.c \
		svccfg_tmpl.c \
		svccfg_xml.c \
		svccfg_help.c


MYOBJS =	$(SRCS:%.c=%.o) \
		svccfg_grammar.o \
		svccfg_lex.o \
		manifest_find.o \
		manifest_hash.o \
		notify_params.o
OBJS =		$(MYOBJS)

POFILES =	$(SRCS:%.c=%.po) \
		svccfg_grammar.po \
		svccfg_lex.po \
		../common/manifest_find.po \
		../common/manifest_hash.po

include ../../Makefile.cmd
include ../../Makefile.ctf

POFILE =	$(PROG)_all.po

NATIVE_BUILD=$(POUND_SIGN)
$(NATIVE_BUILD)NOT_NATIVE=$(POUND_SIGN)

$(NATIVE_BUILD)PROG = $(MYPROG:%=%-native)
$(NATIVE_BUILD)OBJS = $(MYOBJS:%.o=%-native.o)

# svccfg has a name clash with main() and libl.so.1.  However, svccfg must
# still export a number of "yy*" (libl) interfaces.  Reduce all other symbols
# to local scope.
MAPFILES +=	$(MAPFILE.LEX) $(MAPFILE.NGB)
MAPOPTS =	$(MAPFILES:%=-Wl,-M%)

$(NOT_NATIVE)MYCPPFLAGS =	-I ../common -I$(ADJUNCT_PROTO)/usr/include/libxml2
$(NATIVE_BUILD)MYCPPFLAGS =	-I ../common -I$(NATIVE_ADJUNCT)/include/libxml2
CPPFLAGS +=	$(MYCPPFLAGS)
LDFLAGS +=	$(MAPOPTS)

# These are because of bugs in lex(1)/yacc(1) generated code
CERRWARN +=	-_gcc=-Wno-unused-label
CERRWARN +=	-_gcc=-Wno-unused-variable

CERRWARN +=	-_gcc=-Wno-switch
CERRWARN +=	$(CNOWARN_UNINIT)

# not linted
SMATCH=off

LFLAGS = -t
YFLAGS = -d

CLOBBERFILES += svccfg_lex.c svccfg_grammar.c svccfg_grammar.h \
    $(MYPROG:%=%-native)

SVCCFG_EXTRA_LIBS = -lxml2 -lscf -ll -luutil -lumem -lmd -lnvpair
$(NOT_NATIVE)SVCCFG_EXTRA_LIBS += -ltecla
#
# If no adjunct, then we'll already find /usr/lib via LDLIBS below.
#
NATIVE_LIBS += libxml2.so libl.so libumem.so libmd.so libnvpair.so libc.so \
		libscf.so libuutil.so

LIBSCF		= $(SRC)/lib/libscf
LIBTECLA	= $(SRC)/lib/libtecla		# just for the header
LIBUUTIL	= $(SRC)/lib/libuutil

LDLIBS += $(SVCCFG_EXTRA_LIBS)

$(NATIVE_BUILD)CC =	$(NATIVECC64)
$(NATIVE_BUILD)LD =	$(NATIVELD64)
# Add the -g debug flag in spite of being native so ctfconvert won't whine.
$(NATIVE_BUILD)CFLAGS =	$(NATIVE_CFLAGS64) -g
$(NATIVE_BUILD)CPPFLAGS = \
	-DNATIVE_BUILD \
	$(MYCPPFLAGS) \
	-I$(LIBSCF)/inc \
	-I$(LIBTECLA) \
	-I$(LIBUUTIL)/common
$(NATIVE_BUILD)LDFLAGS = $(BDIRECT)
$(NATIVE_BUILD)LDLIBS = \
	-L$(LIBUUTIL)/native -R $(LIBUUTIL)/native \
	-L$(LIBSCF)/native -R $(LIBSCF)/native \
	-L$(NATIVE_ADJUNCT)/lib -R$(NATIVE_ADJUNCT)/lib \
	$(SVCCFG_EXTRA_LIBS)

svccfg_lex.o svccfg_grammar.o := CCVERBOSE =

svccfg_help.po := XGETFLAGS =	-a

.KEEP_STATE:
.PARALLEL: $(OBJS)

all debug: $(PROG)

native: FRC
	@cd $(LIBUUTIL)/native; pwd; $(MAKE) install
	@cd $(LIBSCF)/native; pwd; $(MAKE) install
	@NATIVE_BUILD= $(MAKE) all

$(PROG): $(OBJS) $(MAPFILES)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

$(POFILES): svccfg_grammar.h

$(POFILE): $(POFILES)
	cat $(POFILES) > $(POFILE)

install: all $(ROOTUSRSBINPROG)

svccfg_lex.c: svccfg.l svccfg_grammar.h
	$(LEX) $(LFLAGS) svccfg.l > $@

svccfg_help.o: svccfg_grammar.h
svccfg_help-native.o: svccfg_grammar.h

svccfg_grammar.h svccfg_grammar.c: svccfg.y
	$(YACC) $(YFLAGS) svccfg.y
	@$(MV) y.tab.h svccfg_grammar.h
	@$(MV) y.tab.c svccfg_grammar.c

clean: FRC
	$(RM) $(MYOBJS) $(MYOBJS:%.o=%-native.o)

%-native.o: %.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

%-native.o: ../common/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

%.o: ../common/%.c
	$(COMPILE.c) $(OUTPUT_OPTION) $<
	$(POST_PROCESS_O)

include ../../Makefile.targ

FRC:
