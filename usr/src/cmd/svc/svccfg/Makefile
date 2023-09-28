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

include Makefile.shared.com
include $(SRC)/cmd/Makefile.ctf

POFILES =				\
	$(SRCS:%.c=%.po)		\
	svccfg_grammar.po		\
	svccfg_lex.po			\
	../common/manifest_find.po	\
	../common/manifest_hash.po

SRCDIR = .
COMDIR = ../common

POFILE =	$(PROG)_all.po

# svccfg has a name clash with main() and libl.so.1.  However, svccfg must
# still export a number of "yy*" (libl) interfaces.  Reduce all other symbols
# to local scope.
MAPFILES +=	$(MAPFILE.LEX) $(MAPFILE.NGB)
MAPOPTS =	$(MAPFILES:%=-Wl,-M%)

CPPFLAGS +=	-I ../common -I$(ADJUNCT_PROTO)/usr/include/libxml2
LDFLAGS +=	$(MAPOPTS)

LDLIBS += -lxml2 -lscf -ll -luutil -lumem -lmd -lnvpair -ltecla
NATIVE_LIBS += libxml2.so

# because of labels from yacc
svccfg_lex.o svccfg_grammar.o := CCVERBOSE =
svccfg_lex.o svccfg_grammar.o := CERRWARN += -_gcc=-Wno-unused-label
svccfg_lex-native.o := CERRWARN += -_gcc=-Wno-unused-label
svccfg_grammar-native.o := CERRWARN += -_gcc=-Wno-unused-label

svccfg_help.po := XGETFLAGS =	-a

.KEEP_STATE:
.PARALLEL: $(OBJS)

all debug: $(PROG)

$(PROG): $(OBJS) $(MAPFILES)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

$(POFILES): svccfg_grammar.h

$(POFILE): $(POFILES)
	cat $(POFILES) > $(POFILE)

install: all $(ROOTUSRSBINPROG)

clean:
	$(RM) $(OBJS)

include ../../Makefile.targ
include Makefile.shared.targ

