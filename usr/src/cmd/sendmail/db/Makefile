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
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# cmd/sendmail/db/Makefile
#

include		../../Makefile.cmd
include		../Makefile.cmd

srcdir=	.

CPPFLAGS = -I. -I$(srcdir)/include -D_REENTRANT $(CPPFLAGS.sm)

ARFLAGS=cq

OBJS=	bt_compare.o bt_conv.o bt_curadj.o bt_cursor.o bt_delete.o bt_open.o \
	bt_page.o bt_put.o bt_rec.o bt_recno.o bt_rsearch.o bt_search.o \
	bt_split.o bt_stat.o btree_auto.o db.o db_appinit.o db_am.o \
	db_apprec.o db_auto.o db_byteorder.o db_conv.o db_dispatch.o db_dup.o \
	db_err.o db_iface.o db_join.o db_log2.o db_overflow.o db_pr.o \
	db_rec.o db_region.o db_ret.o db_salloc.o db_shash.o dbm.o hash.o \
	hash_auto.o hash_conv.o hash_dup.o hash_func.o hash_page.o hash_rec.o \
	hash_stat.o hsearch.o lock.o lock_conflict.o lock_deadlock.o \
	lock_util.o lock_region.o log.o log_archive.o log_auto.o \
	log_compare.o log_findckp.o log_get.o log_put.o log_rec.o \
	log_register.o mp_bh.o mp_fget.o mp_fopen.o mp_fput.o mp_fset.o \
	mp_open.o mp_pr.o mp_region.o mp_sync.o mutex.o os_abs.o os_alloc.o \
	os_config.o os_dir.o os_fid.o os_fsync.o os_map.o os_oflags.o \
	os_open.o os_rpath.o os_rw.o os_seek.o os_sleep.o os_spin.o os_stat.o \
	os_tmpdir.o os_unlink.o txn.o txn_auto.o txn_rec.o xa.o xa_db.o \
	xa_map.o strsep.o

SRCS=	$(OBJS:%.o=$(srcdir)/*/%.c)

libdb=	libdb.a

.KEEP_STATE:
all: $(libdb)

.PARALLEL:	$(OBJS)

$(libdb): db.h $(OBJS)
	$(RM) $@
	$(AR) $(ARFLAGS) $@ $(OBJS)

clean:
	$(RM) $(OBJS) $(libdb)

depend obj:

install: all

lint:
	$(LINT.c) $(SRCS) $(LDLIBS)

# DB files.
db%.o: $(srcdir)/db/db%.c
	$(COMPILE.c) $<
	$(POST_PROCESS_O)

# Btree source files.
bt%.o: $(srcdir)/btree/bt%.c
	$(COMPILE.c) $<
	$(POST_PROCESS_O)

# Hash source files.
hash%.o: $(srcdir)/hash/hash%.c
	$(COMPILE.c) $<
	$(POST_PROCESS_O)

# Lock source files.
lock%.o: $(srcdir)/lock/lock%.c
	$(COMPILE.c) $<
	$(POST_PROCESS_O)

# Log source files.
log%.o: $(srcdir)/log/log%.c
	$(COMPILE.c) $<
	$(POST_PROCESS_O)

# Mpool source files.
mp_%.o: $(srcdir)/mp/mp_%.c
	$(COMPILE.c) $<
	$(POST_PROCESS_O)

# Mutex source files.
mutex%.o: $(srcdir)/mutex/mutex%.c
	$(COMPILE.c) $<
	$(POST_PROCESS_O)

# Transaction source files.
txn%.o: $(srcdir)/txn/txn%.c
	$(COMPILE.c) $<
	$(POST_PROCESS_O)

# Transaction manager source files.
xa%.o: $(srcdir)/xa/xa%.c
	$(COMPILE.c) $<
	$(POST_PROCESS_O)

# Historic interfaces.
hsearch%.o: $(srcdir)/hsearch/hsearch%.c
	$(COMPILE.c) $<
	$(POST_PROCESS_O)
dbm%.o: $(srcdir)/dbm/dbm%.c
	$(COMPILE.c) $<
	$(POST_PROCESS_O)

# OS specific source files.
os_%.o: $(srcdir)/os/os_%.c
	$(COMPILE.c) $<
	$(POST_PROCESS_O)

# Replacement source files.
strsep%.o: $(srcdir)/clib/strsep%.c
	$(COMPILE.c) $<
	$(POST_PROCESS_O)

include		../../Makefile.targ
