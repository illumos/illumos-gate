/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/systm.h>
#include <sys/cmn_err.h>
#include <sys/kmem.h>
#include <sys/disp.h>
#include <sys/id_space.h>
#include <sys/atomic.h>
#include <rpc/rpc.h>
#include <nfs/nfs4.h>
#include <nfs/nfs4_db_impl.h>

static int rfs4_reap_interval = RFS4_REAP_INTERVAL;

static void rfs4_dbe_reap(rfs4_table_t *, time_t, uint32_t);
static void rfs4_dbe_destroy(rfs4_dbe_t *);
static rfs4_dbe_t *rfs4_dbe_create(rfs4_table_t *, rfs4_entry_t);
static void rfs4_start_reaper(rfs4_table_t *);

id_t
rfs4_dbe_getid(rfs4_dbe_t *e)
{
	return (e->id);
}

void
rfs4_dbe_hold(rfs4_dbe_t *e)
{
	atomic_add_32(&e->refcnt, 1);
}

/*
 * rfs4_dbe_rele_nolock only decrements the reference count of the entry.
 */
void
rfs4_dbe_rele_nolock(rfs4_dbe_t *e)
{
	atomic_add_32(&e->refcnt, -1);
}


uint32_t
rfs4_dbe_refcnt(rfs4_dbe_t *e)
{
	return (e->refcnt);
}

/*
 * Mark an entry such that the dbsearch will skip it.
 * Caller does not want this entry to be found any longer
 */
void
rfs4_dbe_invalidate(rfs4_dbe_t *e)
{
	e->invalid = TRUE;
	e->skipsearch = TRUE;
}

/*
 * Is this entry invalid?
 */
bool_t
rfs4_dbe_is_invalid(rfs4_dbe_t *e)
{
	return (e->invalid);
}

time_t
rfs4_dbe_get_timerele(rfs4_dbe_t *e)
{
	return (e->time_rele);
}

/*
 * Use these to temporarily hide/unhide a db entry.
 */
void
rfs4_dbe_hide(rfs4_dbe_t *e)
{
	rfs4_dbe_lock(e);
	e->skipsearch = TRUE;
	rfs4_dbe_unlock(e);
}

void
rfs4_dbe_unhide(rfs4_dbe_t *e)
{
	rfs4_dbe_lock(e);
	e->skipsearch = FALSE;
	rfs4_dbe_unlock(e);
}

void
rfs4_dbe_rele(rfs4_dbe_t *e)
{
	mutex_enter(e->lock);
	ASSERT(e->refcnt > 1);
	atomic_add_32(&e->refcnt, -1);
	e->time_rele = gethrestime_sec();
	mutex_exit(e->lock);
}

void
rfs4_dbe_lock(rfs4_dbe_t *e)
{
	mutex_enter(e->lock);
}

void
rfs4_dbe_unlock(rfs4_dbe_t *e)
{
	mutex_exit(e->lock);
}

bool_t
rfs4_dbe_islocked(rfs4_dbe_t *e)
{
	return (mutex_owned(e->lock));
}

clock_t
rfs4_dbe_twait(rfs4_dbe_t *e, clock_t timeout)
{
	return (cv_timedwait(e->cv, e->lock, timeout));
}

void
rfs4_dbe_cv_broadcast(rfs4_dbe_t *e)
{
	cv_broadcast(e->cv);
}

/* ARGSUSED */
static int
rfs4_dbe_kmem_constructor(void *obj, void *private, int kmflag)
{
	rfs4_dbe_t *entry = obj;

	mutex_init(entry->lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(entry->cv, NULL, CV_DEFAULT, NULL);

	return (0);
}

static void
rfs4_dbe_kmem_destructor(void *obj, void *private)
{
	rfs4_dbe_t *entry = obj;
	/*LINTED*/
	rfs4_table_t *table = private;

	mutex_destroy(entry->lock);
	cv_destroy(entry->cv);
}

rfs4_database_t *
rfs4_database_create(uint32_t flags)
{
	rfs4_database_t *db;

	db = kmem_alloc(sizeof (rfs4_database_t), KM_SLEEP);
	mutex_init(db->lock, NULL, MUTEX_DEFAULT, NULL);
	db->tables = NULL;
	db->debug_flags = flags;
	db->shutdown_count = 0;
	cv_init(&db->shutdown_wait, NULL, CV_DEFAULT, NULL);
	return (db);
}


/*
 * The reaper threads that have been created for the tables in this
 * database must be stopped and the entries in the tables released.
 * Each table will be marked as "shutdown" and the reaper threads
 * poked and they will see that a shutdown is in progress and cleanup
 * and exit.  This function waits for all reaper threads to stop
 * before returning to the caller.
 */
void
rfs4_database_shutdown(rfs4_database_t *db)
{
	rfs4_table_t *table;

	mutex_enter(db->lock);
	for (table = db->tables; table; table = table->tnext) {
		table->reaper_shutdown = TRUE;
		mutex_enter(&table->reaper_cv_lock);
		cv_broadcast(&table->reaper_wait);
		db->shutdown_count++;
		mutex_exit(&table->reaper_cv_lock);
	}
	while (db->shutdown_count > 0) {
		cv_wait(&db->shutdown_wait, db->lock);
	}
	mutex_exit(db->lock);
}

/*
 * Given a database that has been "shutdown" by the function above all
 * of the table tables are destroyed and then the database itself
 * freed.
 */
void
rfs4_database_destroy(rfs4_database_t *db)
{
	rfs4_table_t *next, *tmp;

	for (next = db->tables; next; ) {
		tmp = next;
		next = tmp->tnext;
		rfs4_table_destroy(db, tmp);
	}

	mutex_destroy(db->lock);
	kmem_free(db, sizeof (rfs4_database_t));
}

rfs4_table_t *
rfs4_table_create(rfs4_database_t *dbp, char *tabname, time_t max_cache_time,
		uint32_t idxcnt, bool_t (*create)(rfs4_entry_t, void *),
		void (*destroy)(rfs4_entry_t),
		bool_t (*expiry)(rfs4_entry_t),
		uint32_t size, uint32_t hashsize,
		uint32_t maxentries, id_t start)
{
	rfs4_table_t *table;
	int len;
	char *cache_name;
	char *id_name;

	table = kmem_alloc(sizeof (rfs4_table_t), KM_SLEEP);
	table->dbp = dbp;
	rw_init(table->t_lock, NULL, RW_DEFAULT, NULL);
	mutex_init(table->lock, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&table->reaper_cv_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&table->reaper_wait, NULL, CV_DEFAULT, NULL);

	len = strlen(tabname);
	table->name = kmem_alloc(len+1, KM_SLEEP);
	cache_name = kmem_alloc(len + 12 /* "_entry_cache" */ + 1, KM_SLEEP);
	(void) strcpy(table->name, tabname);
	(void) sprintf(cache_name, "%s_entry_cache", table->name);
	table->max_cache_time = max_cache_time;
	table->usize = size;
	table->len = hashsize;
	table->count = 0;
	table->idxcnt = 0;
	table->ccnt = 0;
	table->maxcnt = idxcnt;
	table->indices = NULL;
	table->id_space = NULL;
	table->reaper_shutdown = FALSE;

	if (start >= 0) {
		if (maxentries + (uint32_t)start > (uint32_t)INT32_MAX)
			maxentries = INT32_MAX - start;
		id_name = kmem_alloc(len + 9 /* "_id_space" */ + 1, KM_SLEEP);
		(void) sprintf(id_name, "%s_id_space", table->name);
		table->id_space = id_space_create(id_name, start,
						maxentries + start);
		kmem_free(id_name, len + 10);
	}
	table->maxentries = maxentries;
	table->create = create;
	table->destroy = destroy;
	table->expiry = expiry;

	table->mem_cache = kmem_cache_create(cache_name,
					    sizeof (rfs4_dbe_t) +
					    idxcnt * sizeof (rfs4_link) +
					    size,
					    0,
					    rfs4_dbe_kmem_constructor,
					    rfs4_dbe_kmem_destructor,
					    NULL,
					    table,
					    NULL,
					    0);
	kmem_free(cache_name, len+13);

	table->debug = dbp->debug_flags;

	mutex_enter(dbp->lock);
	table->tnext = dbp->tables;
	dbp->tables = table;
	mutex_exit(dbp->lock);

	rfs4_start_reaper(table);

	return (table);
}

void
rfs4_table_destroy(rfs4_database_t *dbp, rfs4_table_t *table)
{
	rfs4_table_t *p;
	rfs4_index_t *t;

	ASSERT(table->count == 0);

	mutex_enter(dbp->lock);
	if (table == dbp->tables)
		dbp->tables = table->tnext;
	else {
		for (p = dbp->tables; p; p = p->tnext)
			if (p->tnext == table) {
				p->tnext = table->tnext;
				table->tnext = NULL;
				break;
			}
		ASSERT(p != NULL);
	}
	mutex_exit(dbp->lock);

	/* Destroy indices */
	while (table->indices) {
		t = table->indices;
		table->indices = t->inext;
		rfs4_index_destroy(t);
	}

	rw_destroy(table->t_lock);
	mutex_destroy(table->lock);
	mutex_destroy(&table->reaper_cv_lock);
	cv_destroy(&table->reaper_wait);

	kmem_free(table->name, strlen(table->name) + 1);
	if (table->id_space)
		id_space_destroy(table->id_space);
	kmem_cache_destroy(table->mem_cache);
	kmem_free(table, sizeof (rfs4_table_t));
}

rfs4_index_t *
rfs4_index_create(rfs4_table_t *table, char *keyname,
	uint32_t (*hash)(void *),
	bool_t (compare)(rfs4_entry_t, void *),
	void *(*mkkey)(rfs4_entry_t),
	bool_t createable)
{
	rfs4_index_t *idx;

	ASSERT(table->idxcnt < table->maxcnt);

	idx = kmem_alloc(sizeof (rfs4_index_t), KM_SLEEP);

	idx->table = table;
	idx->keyname = kmem_alloc(strlen(keyname) + 1, KM_SLEEP);
	(void) strcpy(idx->keyname, keyname);
	idx->hash = hash;
	idx->compare = compare;
	idx->mkkey = mkkey;
	idx->tblidx = table->idxcnt;
	table->idxcnt++;
	if (createable) {
		table->ccnt++;
		if (table->ccnt > 1)
			panic("Table %s currently can have only have one "
			    "index that will allow creation of entries",
			    table->name);
		idx->createable = TRUE;
	} else {
		idx->createable = FALSE;
	}

	idx->inext = table->indices;
	table->indices = idx;
	idx->buckets = kmem_zalloc(sizeof (rfs4_bucket) * table->len, KM_SLEEP);

	return (idx);
}

void
rfs4_index_destroy(rfs4_index_t *idx)
{
	kmem_free(idx->keyname, strlen(idx->keyname) + 1);
	kmem_free(idx->buckets, sizeof (rfs4_bucket) * idx->table->len);
	kmem_free(idx, sizeof (rfs4_index_t));
}

static void
rfs4_dbe_destroy(rfs4_dbe_t *entry)
{
	rfs4_index_t *ip;
	void *key;
	int i;
	rfs4_bucket *bp;
	rfs4_table_t *table = entry->table;
	rfs4_link *l;

	NFS4_DEBUG(table->debug & DESTROY_DEBUG,
		(CE_NOTE, "Destroying entry %p from %s",
		(void*)entry, table->name));

	mutex_enter(entry->lock);
	ASSERT(entry->refcnt == 0);
	mutex_exit(entry->lock);

	/* Unlink from all indices */
	for (ip = table->indices; ip; ip = ip->inext) {
		l = &entry->indices[ip->tblidx];
		/* check and see if we were ever linked in to the index */
		if (INVALID_LINK(l)) {
			ASSERT(l->next == NULL && l->prev == NULL);
			continue;
		}
		key = ip->mkkey(entry->data);
		i = HASH(ip, key);
		bp = &ip->buckets[i];
		ASSERT(bp->head != NULL);
		DEQUEUE_IDX(bp, &entry->indices[ip->tblidx]);
	}

	/* Destroy user data */
	if (table->destroy)
		(*table->destroy)(entry->data);

	if (table->id_space)
		id_free(table->id_space, entry->id);

	mutex_enter(table->lock);
	table->count--;
	mutex_exit(table->lock);

	/* Destroy the entry itself */
	kmem_cache_free(table->mem_cache, entry);
}


static rfs4_dbe_t *
rfs4_dbe_create(rfs4_table_t *table, rfs4_entry_t data)
{
	rfs4_dbe_t *entry;
	int i;


	NFS4_DEBUG(table->debug & CREATE_DEBUG,
		(CE_NOTE, "Creating entry in table %s", table->name));

	entry = kmem_cache_alloc(table->mem_cache, KM_SLEEP);

	entry->refcnt = 1;
	entry->invalid = FALSE;
	entry->skipsearch = FALSE;
	entry->time_rele = 0;
	entry->id = 0;

	if (table->id_space)
		entry->id = id_alloc(table->id_space);
	entry->table = table;

	for (i = 0; i < table->maxcnt; i++) {
		entry->indices[i].next = entry->indices[i].prev = NULL;
		entry->indices[i].entry = entry;
		/*
		 * We mark the entry as not indexed by setting the low
		 * order bit, since address are word aligned. This has
		 * the advantage of causeing a trap if the address is
		 * used. After the entry is linked in to the
		 * corresponding index the bit will be cleared.
		 */
		INVALIDATE_ADDR(entry->indices[i].entry);
	}

	entry->data = (rfs4_entry_t)&entry->indices[table->maxcnt];
	bzero(entry->data, table->usize);
	entry->data->dbe = entry;

	if (!(*table->create)(entry->data, data)) {
		kmem_cache_free(table->mem_cache, entry);
		return (NULL);
	}

	mutex_enter(table->lock);
	table->count++;
	mutex_exit(table->lock);

	return (entry);
}

rfs4_entry_t
rfs4_dbsearch(rfs4_index_t *idx, void *key, bool_t *create, void *arg,
		rfs4_dbsearch_type_t dbsearch_type)
{
	int already_done;
	uint32_t i;
	rfs4_table_t *table = idx->table;
	rfs4_index_t *ip;
	rfs4_bucket *bp;
	rfs4_link *l;
	rfs4_dbe_t *entry = NULL;

	i = HASH(idx, key);
	bp = &idx->buckets[i];

	NFS4_DEBUG(table->debug & SEARCH_DEBUG,
		(CE_NOTE, "Searching for key %p in table %s by %s",
		key, table->name, idx->keyname));

	rw_enter(bp->lock, RW_READER);
retry:
	for (l = bp->head; l; l = l->next) {
		if (l->entry->refcnt > 0 &&
			(l->entry->skipsearch == FALSE ||
			(l->entry->skipsearch == TRUE &&
				dbsearch_type == RFS4_DBS_INVALID)) &&
			(*idx->compare)(l->entry->data, key)) {
			mutex_enter(l->entry->lock);
			if (l->entry->refcnt == 0) {
				mutex_exit(l->entry->lock);
				continue;
			}

			/* place an additional hold since we are returning */
			rfs4_dbe_hold(l->entry);

			mutex_exit(l->entry->lock);
			rw_exit(bp->lock);

			if (entry) {
				/*
				 * The entry has not been placed in a
				 * table so go ahead and drop the ref
				 * count and destroy the entry.
				 */
				entry->refcnt--;
				rfs4_dbe_destroy(entry);
			}
			*create = FALSE;

			NFS4_DEBUG((table->debug & SEARCH_DEBUG),
				(CE_NOTE, "Found entry %p for %p in table %s",
					(void *)l->entry, key, table->name));

			return (l->entry->data);
		}
	}

	if (!*create || table->create == NULL || !idx->createable ||
		table->maxentries == table->count) {
		*create = FALSE;

		NFS4_DEBUG(table->debug & SEARCH_DEBUG,
			(CE_NOTE, "Entry for %p in %s not found",
			key, table->name));

		rw_exit(bp->lock);

		return (NULL);
	}

	/* Create data before grabing an exclusive lock if needed */
	if (entry == NULL) {
		entry = rfs4_dbe_create(table, arg);
		if (entry == NULL) {
			rw_exit(bp->lock);

			NFS4_DEBUG(table->debug & CREATE_DEBUG,
				(CE_NOTE, "Constructor for table %s failed",
				table->name));
			return (NULL);
		}
	}

	/* Now that we've allocated  */
	if (rw_read_locked(bp->lock) && !rw_tryupgrade(bp->lock)) {

		NFS4_DEBUG(table->debug & OTHER_DEBUG,
			(CE_NOTE, "Trying to upgrade lock for entry %p on "
			"hash chain %d (%p) for  %s by %s",
			(void*)entry, i, (void*)bp,
			table->name, idx->keyname));

		rw_exit(bp->lock);
		rw_enter(bp->lock, RW_WRITER);

		goto retry;
	}

	/*
	 * Add one ref for entry into table's hash - only one
	 * reference added evn though there may be multiple indices
	 */
	rfs4_dbe_hold(entry);
	ENQUEUE(bp->head, &entry->indices[idx->tblidx]);
	VALIDATE_ADDR(entry->indices[idx->tblidx].entry);

	already_done = idx->tblidx;
	rw_exit(bp->lock);

	for (ip = table->indices; ip; ip = ip->inext) {
		if (ip->tblidx == already_done)
			continue;
		l = &entry->indices[ip->tblidx];
		i = HASH(ip, ip->mkkey(entry->data));
		ASSERT(i < ip->table->len);
		bp = &ip->buckets[i];
		ENQUEUE_IDX(bp, l);
	}

	NFS4_DEBUG(table->debug & SEARCH_DEBUG || table->debug & CREATE_DEBUG,
		(CE_NOTE, "Entry %p created for %s = %p in table %s",
		(void*)entry, idx->keyname, (void*)key, table->name));

	return (entry->data);
}

/*ARGSUSED*/
boolean_t
rfs4_cpr_callb(void *arg, int code)
{
	rfs4_table_t *tbl = rfs4_client_tab;
	rfs4_bucket *buckets, *bp;
	rfs4_link *l;
	rfs4_client_t *cl;
	int i;

	/*
	 * We get called for Suspend and Resume events.
	 * For the suspend case we simply don't care!  Nor do we care if
	 * there are no clients.
	 */
	if (code == CB_CODE_CPR_CHKPT || tbl == NULL) {
		return (B_TRUE);
	}

	buckets = tbl->indices->buckets;

	/*
	 * When we get this far we are in the process of
	 * resuming the system from a previous suspend.
	 *
	 * We are going to blast through and update the
	 * last_access time for all the clients and in
	 * doing so extend them by one lease period.
	 */
	for (i = 0; i < tbl->len; i++) {
		bp = &buckets[i];
		for (l = bp->head; l; l = l->next) {
			cl = (rfs4_client_t *)l->entry->data;
			cl->last_access = gethrestime_sec();
		}
	}

	return (B_TRUE);
}

/*
 * Given a table, lock each of the buckets and walk all entries (in
 * turn locking those) and calling the provided "callout" function
 * with the provided parameter.  Obviously used to iterate across all
 * entries in a particular table via the database locking hierarchy.
 * Obviously the caller must not hold locks on any of the entries in
 * the specified table.
 */
void
rfs4_dbe_walk(rfs4_table_t *table,
		void (*callout)(rfs4_entry_t, void *),
		void *data)
{
	rfs4_bucket *buckets = table->indices->buckets, *bp;
	rfs4_link *l;
	rfs4_dbe_t *e;
	int i;

	NFS4_DEBUG(table->debug & WALK_DEBUG,
		(CE_NOTE, "Walking entries in %s", table->name));

	/* Walk the buckets looking for entries to release/destroy */
	for (i = 0; i < table->len; i++) {
		bp = &buckets[i];
		rw_enter(bp->lock, RW_READER);
		for (l = bp->head; l; l = l->next) {
			e = l->entry;
			mutex_enter(e->lock);
			(*callout)(e->data, data);
			mutex_exit(e->lock);
		}
		rw_exit(bp->lock);
	}

	NFS4_DEBUG(table->debug & WALK_DEBUG,
		(CE_NOTE, "Walking entries complete %s", table->name));
}


static void
rfs4_dbe_reap(rfs4_table_t *table, time_t cache_time, uint32_t desired)
{
	rfs4_index_t *ip = table->indices;
	rfs4_bucket *buckets = ip->buckets, *bp;
	rfs4_link *l, *t;
	rfs4_dbe_t *e;
	bool_t found;
	int i;
	int count = 0;

	NFS4_DEBUG(table->debug & REAP_DEBUG,
		(CE_NOTE,
		"Reaping %d entries older than %ld seconds in table %s",
		desired, cache_time, table->name));

	/* Walk the buckets looking for entries to release/destroy */
	for (i = 0; i < table->len; i++) {
		bp = &buckets[i];
		do {
			found = FALSE;
			rw_enter(bp->lock, RW_READER);
			for (l = bp->head; l; l = l->next) {
				e = l->entry;
				/*
				 * Examine an entry.  Ref count of 1 means
				 * that the only reference is for the hash
				 * table reference.
				 */
				if (e->refcnt == 1) {
					mutex_enter(e->lock);
					if (e->refcnt == 1) {
						if (table->reaper_shutdown ||
						    table->expiry == NULL ||
						    (*table->expiry)(e->data)) {
							e->refcnt--;
							count++;
							found = TRUE;
						}
					}
					mutex_exit(e->lock);
				}
			}
			if (found) {
				if (!rw_tryupgrade(bp->lock)) {
					rw_exit(bp->lock);
					rw_enter(bp->lock, RW_WRITER);
				}

				l = bp->head;
				while (l) {
					t = l;
					e = t->entry;
					l = l->next;
					if (e->refcnt == 0) {
						DEQUEUE(bp->head, t);
						t->next = NULL;
						t->prev = NULL;
						INVALIDATE_ADDR(t->entry);
						rfs4_dbe_destroy(e);
					}
				}
			}
			rw_exit(bp->lock);
			/*
			 * delay slightly if there is more work to do
			 * with the expectation that other reaper
			 * threads are freeing data structures as well
			 * and in turn will reduce ref counts on
			 * entries in this table allowing them to be
			 * released.  This is only done in the
			 * instance that the tables are being shut down.
			 */
			if (table->reaper_shutdown && bp->head != NULL)
				delay(hz/100);
		/*
		 * If this is a table shutdown, keep going until
		 * everything is gone
		 */
		} while (table->reaper_shutdown && bp->head != NULL);

		if (!table->reaper_shutdown && desired && count >= desired)
			break;
	}

	NFS4_DEBUG(table->debug & REAP_DEBUG,
		(CE_NOTE,
		"Reaped %d entries older than %ld seconds in table %s",
		count, cache_time, table->name));
}


static void
reaper_thread(caddr_t *arg)
{
	rfs4_table_t *table = (rfs4_table_t *)arg;
	clock_t rc, time;

	NFS4_DEBUG(table->debug,
		(CE_NOTE, "rfs4_reaper_thread starting for %s", table->name));

	CALLB_CPR_INIT(&table->reaper_cpr_info, &table->reaper_cv_lock,
		callb_generic_cpr, "nfsv4Reaper");

	time = MIN(rfs4_reap_interval, table->max_cache_time);
	mutex_enter(&table->reaper_cv_lock);
	do {
		CALLB_CPR_SAFE_BEGIN(&table->reaper_cpr_info);
		rc = cv_timedwait_sig(&table->reaper_wait,
					&table->reaper_cv_lock,
					lbolt + SEC_TO_TICK(time));
		CALLB_CPR_SAFE_END(&table->reaper_cpr_info,
					&table->reaper_cv_lock);
		rfs4_dbe_reap(table, table->max_cache_time, 0);
	} while (rc != 0 && table->reaper_shutdown == FALSE);

	CALLB_CPR_EXIT(&table->reaper_cpr_info);

	NFS4_DEBUG(table->debug,
		(CE_NOTE, "rfs4_reaper_thread exiting for %s", table->name));

	/* Notify the database shutdown processing that the table is shutdown */
	mutex_enter(table->dbp->lock);
	table->dbp->shutdown_count--;
	cv_signal(&table->dbp->shutdown_wait);
	mutex_exit(table->dbp->lock);
}

static void
rfs4_start_reaper(rfs4_table_t *table)
{
	if (table->max_cache_time == 0)
		return;

	(void) thread_create(NULL, 0, reaper_thread, table, 0, &p0, TS_RUN,
			    minclsyspri);
}

#ifdef DEBUG
void
rfs4_dbe_debug(rfs4_dbe_t *e)
{
	cmn_err(CE_NOTE, "Entry %p from table %s", (void *)e, e->table->name);
	cmn_err(CE_CONT, "\trefcnt = %d id = %d", e->refcnt, e->id);
}
#endif
