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
# Copyright (c) 2018, Joyent, Inc.

LIBRARY= libdb2.a
VERS= .1

# btree
BTREE_OBJS= \
	bt_close.o \
	bt_conv.o \
	bt_debug.o \
	bt_delete.o \
	bt_get.o \
	bt_open.o \
        bt_overflow.o \
	bt_page.o \
	bt_put.o \
	bt_search.o \
	bt_seq.o \
	bt_split.o \
        bt_utils.o

# db
DB_OBJS= db.o

# hash
HASH_OBJS= \
	hash.o \
	hash_bigkey.o \
	hash_func.o \
	hash_log2.o \
	hash_page.o \
	hsearch.o \
	dbm.o

# mpool
MPOOL_OBJS= mpool.o

# recno
RECNO_OBJS= \
	rec_close.o \
	rec_delete.o \
	rec_get.o \
	rec_open.o \
	rec_put.o \
	rec_search.o \
	rec_seq.o \
	rec_utils.o

OBJECTS= \
	$(BTREE_OBJS) $(DB_OBJS) $(HASH_OBJS) $(MPOOL_OBJS) $(RECNO_OBJS)

# include library definitions
include $(SRC)/lib/krb5/Makefile.lib

SRCS=	$(BTREE_OBJS:%.o=../btree/%.c) \
	$(DB_OBJS:%.o=../db/%.c) \
	$(HASH_OBJS:%.o=../hash/%.c) \
	$(MPOOL_OBJS:%.o=../mpool/%.c) \
	$(RECNO_OBJS:%.o=../recno/%.c)

LIBS=		$(DYNLIB)

include $(SRC)/lib/gss_mechs/mech_krb5/Makefile.mech_krb5

POFILE = $(LIBRARY:%.a=%.po)
POFILES = generic.po

#override liblink
INS.liblink=	-$(RM) $@; $(SYMLINK) $(LIBLINKS)$(VERS) $@

CPPFLAGS +=	-DHAVE_CONFIG_H \
		-I$(SRC)/lib/krb5/plugins/kdb/db2/libdb2/mpool \
		-I$(SRC)/lib/krb5/plugins/kdb/db2/libdb2/db \
		-I$(SRC)/lib/krb5/plugins/kdb/db2/libdb2/hash \
		-I$(SRC)/lib/krb5/plugins/kdb/db2/libdb2/btree \
		-I$(SRC)/lib/krb5/plugins/kdb/db2/libdb2/recno \
		-I$(SRC)/lib/krb5/plugins/kdb/db2/libdb2/include \
		-I$(SRC)/lib/gss_mechs/mech_krb5/include  #for db-ndbm.h

CFLAGS +=	$(CCVERBOSE) -I..
CERRWARN +=	$(CNOWARN_UNINIT)

# not linted
SMATCH=off

LDLIBS +=	-lc

# Identify that this library is an interposer (on dbm_ routines from libc.so.1).
# This identification insures runtime symbol lookup resolves to this library
# (before libc.so.1) regardless of dependency link order.
DYNFLAGS +=	$(ZINTERPOSE)

.KEEP_STATE:

all:	$(LIBS)


# include library targets
include $(SRC)/lib/krb5/Makefile.targ

pics/%.o: ../btree/%.c
	$(COMPILE.c)  -o $@ $<
	$(POST_PROCESS_O)

pics/%.o: ../db/%.c
	$(COMPILE.c)  -o $@ $<
	$(POST_PROCESS_O)

pics/%.o: ../hash/%.c
	$(COMPILE.c)  -o $@ $<
	$(POST_PROCESS_O)

pics/%.o: ../mpool/%.c
	$(COMPILE.c)  -o $@ $<
	$(POST_PROCESS_O)

pics/%.o: ../recno/%.c
	$(COMPILE.c)  -o $@ $<
	$(POST_PROCESS_O)

FRC:

generic.po: FRC
	$(RM) messages.po
	$(XGETTEXT) $(XGETFLAGS) `$(GREP) -l gettext ../hash/*.[ch]`
	$(SED) "/^domain/d" messages.po > $@
	$(RM) messages.po
