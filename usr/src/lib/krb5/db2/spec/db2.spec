#
# Copyright 1997-2002 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#pragma ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/krb5/db2/spec/db2.spec

function	kdb2_dbm_clearerr
include		"db-ndbm.h"
declaration	int kdb2_dbm_clearerr(DBM *db)
version		SUNWprivate_1.1
end

function	kdb2_dbm_close
include		"db-ndbm.h"
declaration	void kdb2_dbm_close(DBM *db)
version		SUNWprivate_1.1
end

function	kdb2_dbm_delete
include		"db-ndbm.h"
declaration	int kdb2_dbm_delete(DBM *db, datum key)
version		SUNWprivate_1.1
end

function	kdb2_dbm_dirfno
include		"db-ndbm.h"
declaration	int kdb2_dbm_dirfno(DBM *db)
version		SUNWprivate_1.1
end

function	kdb2_dbm_error
include		"db-ndbm.h"
declaration	int kdb2_dbm_error(DBM *db)
version		SUNWprivate_1.1
end

function	kdb2_dbm_fetch
include		"db-ndbm.h"
declaration	datum kdb2_dbm_fetch(DBM *db, datum key)
version		SUNWprivate_1.1
end

function	kdb2_dbm_firstkey
include		"db-ndbm.h"
declaration	datum kdb2_dbm_firstkey(DBM *db)
version		SUNWprivate_1.1
end

function	kdb2_dbm_nextkey
include		"db-ndbm.h"
declaration	datum kdb2_dbm_nextkey(DBM *db)
version		SUNWprivate_1.1
end

function	kdb2_dbm_open
include		"db-ndbm.h"
declaration	DBM * kdb2_dbm_open(const char *file, int flags, int mode)
version		SUNWprivate_1.1
end

function	kdb2_dbm_store
include		"db-ndbm.h"
declaration	int kdb2_dbm_store(DBM *db, datum key, datum content, int flags)
version		SUNWprivate_1.1
end

function	kdb2_dbminit
declaration	int kdb2_dbminit(char *file)
version		SUNWprivate_1.1
end

function	kdb2_dbopen
include		"db-int.h"
declaration	DB * kdb2_dbopen(const char *fname, int flags, int mode, \
					DBTYPE type, const void *openinfo)
version		SUNWprivate_1.1
end

function	kdb2_delete
include		"db-ndbm.h"
declaration	int kdb2_delete(datum key)
version		SUNWprivate_1.1
end

function	kdb2_fetch
include		"db-ndbm.h"
declaration	datum kdb2_fetch(datum key)
version		SUNWprivate_1.1
end

function	kdb2_firstkey
include		"db-ndbm.h"
declaration	datum kdb2_firstkey()
version		SUNWprivate_1.1
end

function	debugDisplayDB
declaration	void debugDisplayDB(int onOff)
version		SUNWprivate_1.1
end

function	kdb2_hcreate
include		<sys/types.h>
declaration	int kdb2_hcreate(u_int nel)
version		SUNWprivate_1.1
end

function	kdb2_hdestroy
declaration	void kdb2_hdestroy()
version		SUNWprivate_1.1
end

function	kdb2_hsearch
include		"search.h"
declaration	ENTRY *kdb2_hsearch(ENTRY item, SEARCH_ACTION action)
version		SUNWprivate_1.1
end

function	mpool_close
include		"mpool.h"
declaration	int mpool_close(MPOOL *mp)
version		SUNWprivate_1.1
end

function	mpool_delete
include		"mpool.h"
declaration	int mpool_delete(MPOOL *mp, void *page)
version		SUNWprivate_1.1
end

function	mpool_filter
include		"db-int.h" "mpool.h"
declaration	void mpool_filter(MPOOL *mp, \
			void (*pgin)(void *, db_pgno_t, void *), \
			void (*pgout)(void *, db_pgno_t, void *), \
			void *pgcookie)
version		SUNWprivate_1.1
end

function	mpool_get
include		<sys/types.h> "db-int.h" "mpool.h"
declaration	void *mpool_get(MPOOL *mp, db_pgno_t pgno, u_int flags)
version		SUNWprivate_1.1
end

function	mpool_new
include		<sys/types.h> "db-int.h" "mpool.h"
declaration	void *mpool_new(MPOOL *mp, db_pgno_t *pgnoaddr, u_int flags)
version		SUNWprivate_1.1
end

function	mpool_open
include		"db-int.h" "mpool.h"
declaration	MPOOL *mpool_open(void *key, int fd, db_pgno_t pagesize, \
					db_pgno_t maxcache)
version		SUNWprivate_1.1
end

function	mpool_put
include		<sys/types.h> "mpool.h"
declaration	int mpool_put(MPOOL *mp, void *page, u_int flags)
version		SUNWprivate_1.1
end

function	mpool_sync
include		"mpool.h"
declaration	int mpool_sync(MPOOL *mp)
version		SUNWprivate_1.1
end

function	kdb2_nextkey
include		"db-ndbm.h"
declaration	datum kdb2_nextkey(datum key)
version		SUNWprivate_1.1
end

function	kdb2_store
include		"db-ndbm.h"
declaration	int kdb2_store(datum key, datum dat)
version		SUNWprivate_1.1
end

