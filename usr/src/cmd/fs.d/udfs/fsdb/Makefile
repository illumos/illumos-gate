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

FSTYPE=		udfs
LIBPROG=	fsdb

include		../../Makefile.fstype

# fsdb has a name clash with main() and libl.so.1.  However, fsdb must
# still export a number of "yy*" (libl) interfaces.  Reduce all other symbols
# to local scope.
MAPFILES +=	$(MAPFILE.INT) $(MAPFILE.LEX) $(MAPFILE.NGB)
MAPOPTS =	$(MAPFILES:%=-M%)

CPPFLAGS +=	-D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64
LDLIBS +=	-lmalloc -ll -ladm
LDFLAGS +=	$(MAPOPTS)
YFLAGS =	"-d"

LINTFLAGS +=	-erroff=E_STATIC_UNUSED
LINTFLAGS64 +=	-erroff=E_STATIC_UNUSED

CERRWARN +=	-_gcc=-Wno-implicit-function-declaration
CERRWARN +=	-_gcc=-Wno-unused-label
CERRWARN +=	-_gcc=-Wno-unused-variable
CERRWARN +=	-_gcc=-Wno-uninitialized
CERRWARN +=	-_gcc=-Wno-unused-value
CERRWARN +=	-_gcc=-Wno-unused-function

SRCS=	fsdb.c ud_lib.c

fsdb : fsdb_yacc.o fsdb_lex.o ud_lib.o fsdb.o $(MAPFILES)
	$(LINK.c) -o $@ fsdb.o fsdb_yacc.o fsdb_lex.o \
			ud_lib.o $(LDLIBS)
	$(POST_PROCESS)

fsdb.o : fsdb.c
	$(COMPILE.c) -o $@ fsdb.c
	$(POST_PROCESS_O)

ud_lib.o : ud_lib.c ud_lib.h
	$(COMPILE.c) -o $@ ud_lib.c
	$(POST_PROCESS_O)

ud_lib.c : ../fstyp/ud_lib.c
	$(RM) $@
	$(CP) ../fstyp/ud_lib.c $@

ud_lib.h : ../fstyp/ud_lib.h
	$(RM) $@
	$(CP) ../fstyp/ud_lib.h $@

y.tab.c : fsdb_yacc.y
	$(YACC.y) fsdb_yacc.y

fsdb_yacc.o : y.tab.c
	$(COMPILE.c) -o $@ y.tab.c
	$(POST_PROCESS_O)

lex.yy.c : fsdb_lex.l
	$(LEX) -e fsdb_lex.l

fsdb_lex.o : lex.yy.c
	$(COMPILE.c) -o $@ lex.yy.c
	$(POST_PROCESS_O)

clean :
	$(RM) ud_lib.c ud_lib.h fsdb.o ud_lib.o fsdb_yacc.o fsdb_lex.o
	$(RM) fsdb_yacc.c fsdb_lex.c y.tab.c y.tab.h lex.yy.c

# for messaging catalog
#
POFILE= fsdb.po

# for messaging catalog
#
catalog:        $(POFILE)

CATSRCS=	$(SRCS) lex.yy.c y.tab.c

$(POFILE):      $(CATSRCS)
	$(RM) $@
	$(COMPILE.cpp) $(CATSRCS)   > $(POFILE).i
	$(XGETTEXT) $(XGETFLAGS)        $(POFILE).i
	$(SED) "/^domain/d" messages.po >  $@
	$(RM) $(POFILE).i messages.po

lint: y.tab.c lex.yy.c ud_lib.c ud_lib.h
	$(LINT.c) -mu $(SRCS)

putback :
	-cstyle -p fsdb.c
	-keywords fsdb.c
	-keywords Makefile

