/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/systm.h>
#include <sys/cmn_err.h>
#include <sys/kmem.h>
#include <sys/disp.h>
#include <sys/id_space.h>
#include <sys/atomic.h>
#include <rpc/rpc.h>
#include <nfs/nfs4.h>
#include <nfs/nfs4_db_impl.h>
#include <sys/sdt.h>

static int rfs4_reap_interval = RFS4_REAP_INTERVAL;

static void rfs4_dbe_reap(rfs4_table_t *, time_t, uint32_t);
static void rfs4_dbe_destroy(rfs4_dbe_t *);
static rfs4_dbe_t *rfs4_dbe_create(rfs4_table_t *, id_t, rfs4_entry_t);
static void rfs4_start_reaper(rfs4_table_t *);

/*
 * t_lowat - integer percentage of table entries	/etc/system only
 * t_hiwat - integer percentage of table entries	/etc/system only
 * t_lreap - integer percentage of table reap time	mdb or /etc/system
 * t_hreap - integer percentage of table reap time	mdb or /etc/system
 */
uint32_t	t_lowat = 50;	/* reap at t_lreap when id's in use hit 50% */
uint32_t	t_hiwat = 75;	/* reap at t_hreap when id's in use hit 75% */
time_t		t_lreap = 50;	/* default to 50% of table's reap interval */
time_t		t_hreap = 10;	/* default to 10% of table's reap interval */

id_t
rfs4_dbe_getid(rfs4_dbe_t *entry)
{
	return (entry->dbe_id);
}

void
rfs4_dbe_hold(rfs4_dbe_t *entry)
{
	atomic_inc_32(&entry->dbe_refcnt);
}

/*
 * rfs4_dbe_rele_nolock only decrements the reference count of the entry.
 */
void
rfs4_dbe_rele_nolock(rfs4_dbe_t *entry)
{
	atomic_dec_32(&entry->dbe_refcnt);
}


uint32_t
rfs4_dbe_refcnt(rfs4_dbe_t *entry)
{
	return (entry->dbe_refcnt);
}

/*
 * Mark an entry such that the dbsearch will skip it.
 * Caller does not want this entry to be found any longer
 */
void
rfs4_dbe_invalidate(rfs4_dbe_t *entry)
{
	entry->dbe_invalid = TRUE;
	entry->dbe_skipsearch = TRUE;
}

/*
 * Is this entry invalid?
 */
bool_t
rfs4_dbe_is_invalid(rfs4_dbe_t *entry)
{
	return (entry->dbe_invalid);
}

time_t
rfs4_dbe_get_timerele(rfs4_dbe_t *entry)
{
	return (entry->dbe_time_rele);
}

/*
 * Use these to temporarily hide/unhide a db entry.
 */
void
rfs4_dbe_hide(rfs4_dbe_t *entry)
{
	rfs4_dbe_lock(entry);
	entry->dbe_skipsearch = TRUE;
	rfs4_dbe_unlock(entry);
}

void
rfs4_dbe_unhide(rfs4_dbe_t *entry)
{
	rfs4_dbe_lock(entry);
	entry->dbe_skipsearch = FALSE;
	rfs4_dbe_unlock(entry);
}

void
rfs4_dbe_rele(rfs4_dbe_t *entry)
{
	mutex_enter(entry->dbe_lock);
	ASSERT(entry->dbe_refcnt > 1);
	atomic_dec_32(&entry->dbe_refcnt);
	entry->dbe_time_rele = gethrestime_sec();
	mutex_exit(entry->dbe_lock);
}

void
rfs4_dbe_lock(rfs4_dbe_t *entry)
{
	mutex_enter(entry->dbe_lock);
}

void
rfs4_dbe_unlock(rfs4_dbe_t *entry)
{
	mutex_exit(entry->dbe_lock);
}

bool_t
rfs4_dbe_islocked(rfs4_dbe_t *entry)
{
	return (mutex_owned(entry->dbe_lock));
}

clock_t
rfs4_dbe_twait(rfs4_dbe_t *entry, clock_t timeout)
{
	return (cv_timedwait(entry->dbe_cv, entry->dbe_lock, timeout));
}

void
rfs4_dbe_cv_broadcast(rfs4_dbe_t *entry)
{
	cv_broadcast(entry->dbe_cv);
}

/* ARGSUSED */
static int
rfs4_dbe_kmem_constructor(void *obj, void *private, int kmflag)
{
	rfs4_dbe_t *entry = obj;

	mutex_init(entry->dbe_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(entry->dbe_cv, NULL, CV_DEFAULT, NULL);

	return (0);
}

static void
rfs4_dbe_kmem_destructor(void *obj, void *private)
{
	rfs4_dbe_t *entry = obj;
	/*LINTED*/
	rfs4_table_t *table = private;

	mutex_destroy(entry->dbe_lock);
	cv_destroy(entry->dbe_cv);
}

rfs4_database_t *
rfs4_database_create(uint32_t flags)
{
	rfs4_database_t *db;

	db = kmem_alloc(sizeof (rfs4_database_t), KM_SLEEP);
	mutex_init(db->db_lock, NULL, MUTEX_DEFAULT, NULL);
	db->db_tables = NULL;
	db->db_debug_flags = flags;
	db->db_shutdown_count = 0;
	cv_init(&db->db_shutdown_wait, NULL, CV_DEFAULT, NULL);
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

	mutex_enter(db->db_lock);
	for (table = db->db_tables; table; table = table->dbt_tnext) {
		mutex_enter(&table->dbt_reaper_cv_lock);
		table->dbt_reaper_shutdown = TRUE;
		cv_broadcast(&table->dbt_reaper_wait);
		db->db_shutdown_count++;
		mutex_exit(&table->dbt_reaper_cv_lock);
	}
	while (db->db_shutdown_count > 0) {
		cv_wait(&db->db_shutdown_wait, db->db_lock);
	}
	mutex_exit(db->db_lock);
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

	for (next = db->db_tables; next; ) {
		tmp = next;
		next = tmp->dbt_tnext;
		rfs4_table_destroy(db, tmp);
	}

	mutex_destroy(db->db_lock);
	kmem_free(db, sizeof (rfs4_database_t));
}

rfs4_table_t *
rfs4_table_create(rfs4_database_t *db, char *tabname, time_t max_cache_time,
    uint32_t idxcnt, bool_t (*create)(rfs4_entry_t, void *),
    void (*destroy)(rfs4_entry_t),
    bool_t (*expiry)(rfs4_entry_t),
    uint32_t size, uint32_t hashsize,
    uint32_t maxentries, id_t start)
{
	rfs4_table_t	*table;
	int		 len;
	char		*cache_name;
	char		*id_name;

	table = kmem_alloc(sizeof (rfs4_table_t), KM_SLEEP);
	table->dbt_db = db;
	rw_init(table->dbt_t_lock, NULL, RW_DEFAULT, NULL);
	mutex_init(table->dbt_lock, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&table->dbt_reaper_cv_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&table->dbt_reaper_wait, NULL, CV_DEFAULT, NULL);

	len = strlen(tabname);
	table->dbt_name = kmem_alloc(len+1, KM_SLEEP);
	cache_name = kmem_alloc(len + 12 /* "_entry_cache" */ + 1, KM_SLEEP);
	(void) strcpy(table->dbt_name, tabname);
	(void) sprintf(cache_name, "%s_entry_cache", table->dbt_name);
	table->dbt_max_cache_time = max_cache_time;
	table->dbt_usize = size;
	table->dbt_len = hashsize;
	table->dbt_count = 0;
	table->dbt_idxcnt = 0;
	table->dbt_ccnt = 0;
	table->dbt_maxcnt = idxcnt;
	table->dbt_indices = NULL;
	table->dbt_id_space = NULL;
	table->dbt_reaper_shutdown = FALSE;

	if (start >= 0) {
		if (maxentries + (uint32_t)start > (uint32_t)INT32_MAX)
			maxentries = INT32_MAX - start;
		id_name = kmem_alloc(len + 9 /* "_id_space" */ + 1, KM_SLEEP);
		(void) sprintf(id_name, "%s_id_space", table->dbt_name);
		table->dbt_id_space = id_space_create(id_name, start,
		    maxentries + start);
		kmem_free(id_name, len + 10);
	}
	ASSERT(t_lowat != 0);
	table->dbt_id_lwat = (maxentries * t_lowat) / 100;
	ASSERT(t_hiwat != 0);
	table->dbt_id_hwat = (maxentries * t_hiwat) / 100;
	table->dbt_id_reap = MIN(rfs4_reap_interval, max_cache_time);
	table->dbt_maxentries = maxentries;
	table->dbt_create = create;
	table->dbt_destroy = destroy;
	table->dbt_expiry = expiry;

	table->dbt_mem_cache = kmem_cache_create(cache_name,
	    sizeof (rfs4_dbe_t) + idxcnt * sizeof (rfs4_link_t) + size,
	    0,
	    rfs4_dbe_kmem_constructor,
	    rfs4_dbe_kmem_destructor,
	    NULL,
	    table,
	    NULL,
	    0);
	kmem_free(cache_name, len+13);

	table->dbt_debug = db->db_debug_flags;

	mutex_enter(db->db_lock);
	table->dbt_tnext = db->db_tables;
	db->db_tables = table;
	mutex_exit(db->db_lock);

	rfs4_start_reaper(table);

	return (table);
}

void
rfs4_table_destroy(rfs4_database_t *db, rfs4_table_t *table)
{
	rfs4_table_t *p;
	rfs4_index_t *idx;

	ASSERT(table->dbt_count == 0);

	mutex_enter(db->db_lock);
	if (table == db->db_tables)
		db->db_tables = table->dbt_tnext;
	else {
		for (p = db->db_tables; p; p = p->dbt_tnext)
			if (p->dbt_tnext == table) {
				p->dbt_tnext = table->dbt_tnext;
				table->dbt_tnext = NULL;
				break;
			}
		ASSERT(p != NULL);
	}
	mutex_exit(db->db_lock);

	/* Destroy indices */
	while (table->dbt_indices) {
		idx = table->dbt_indices;
		table->dbt_indices = idx->dbi_inext;
		rfs4_index_destroy(idx);
	}

	rw_destroy(table->dbt_t_lock);
	mutex_destroy(table->dbt_lock);
	mutex_destroy(&table->dbt_reaper_cv_lock);
	cv_destroy(&table->dbt_reaper_wait);

	kmem_free(table->dbt_name, strlen(table->dbt_name) + 1);
	if (table->dbt_id_space)
		id_space_destroy(table->dbt_id_space);
	kmem_cache_destroy(table->dbt_mem_cache);
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

	ASSERT(table->dbt_idxcnt < table->dbt_maxcnt);

	idx = kmem_alloc(sizeof (rfs4_index_t), KM_SLEEP);

	idx->dbi_table = table;
	idx->dbi_keyname = kmem_alloc(strlen(keyname) + 1, KM_SLEEP);
	(void) strcpy(idx->dbi_keyname, keyname);
	idx->dbi_hash = hash;
	idx->dbi_compare = compare;
	idx->dbi_mkkey = mkkey;
	idx->dbi_tblidx = table->dbt_idxcnt;
	table->dbt_idxcnt++;
	if (createable) {
		table->dbt_ccnt++;
		if (table->dbt_ccnt > 1)
			panic("Table %s currently can have only have one "
			    "index that will allow creation of entries",
			    table->dbt_name);
		idx->dbi_createable = TRUE;
	} else {
		idx->dbi_createable = FALSE;
	}

	idx->dbi_inext = table->dbt_indices;
	table->dbt_indices = idx;
	idx->dbi_buckets = kmem_zalloc(sizeof (rfs4_bucket_t) * table->dbt_len,
	    KM_SLEEP);

	return (idx);
}

void
rfs4_index_destroy(rfs4_index_t *idx)
{
	kmem_free(idx->dbi_keyname, strlen(idx->dbi_keyname) + 1);
	kmem_free(idx->dbi_buckets,
	    sizeof (rfs4_bucket_t) * idx->dbi_table->dbt_len);
	kmem_free(idx, sizeof (rfs4_index_t));
}

static void
rfs4_dbe_destroy(rfs4_dbe_t *entry)
{
	rfs4_index_t *idx;
	void *key;
	int i;
	rfs4_bucket_t *bp;
	rfs4_table_t *table = entry->dbe_table;
	rfs4_link_t *l;

	NFS4_DEBUG(table->dbt_debug & DESTROY_DEBUG,
	    (CE_NOTE, "Destroying entry %p from %s",
	    (void*)entry, table->dbt_name));

	mutex_enter(entry->dbe_lock);
	ASSERT(entry->dbe_refcnt == 0);
	mutex_exit(entry->dbe_lock);

	/* Unlink from all indices */
	for (idx = table->dbt_indices; idx; idx = idx->dbi_inext) {
		l = &entry->dbe_indices[idx->dbi_tblidx];
		/* check and see if we were ever linked in to the index */
		if (INVALID_LINK(l)) {
			ASSERT(l->next == NULL && l->prev == NULL);
			continue;
		}
		key = idx->dbi_mkkey(entry->dbe_data);
		i = HASH(idx, key);
		bp = &idx->dbi_buckets[i];
		ASSERT(bp->dbk_head != NULL);
		DEQUEUE_IDX(bp, &entry->dbe_indices[idx->dbi_tblidx]);
	}

	/* Destroy user data */
	if (table->dbt_destroy)
		(*table->dbt_destroy)(entry->dbe_data);

	if (table->dbt_id_space)
		id_free(table->dbt_id_space, entry->dbe_id);

	mutex_enter(table->dbt_lock);
	table->dbt_count--;
	mutex_exit(table->dbt_lock);

	/* Destroy the entry itself */
	kmem_cache_free(table->dbt_mem_cache, entry);
}


static rfs4_dbe_t *
rfs4_dbe_create(rfs4_table_t *table, id_t id, rfs4_entry_t data)
{
	rfs4_dbe_t *entry;
	int i;

	NFS4_DEBUG(table->dbt_debug & CREATE_DEBUG,
	    (CE_NOTE, "Creating entry in table %s", table->dbt_name));

	entry = kmem_cache_alloc(table->dbt_mem_cache, KM_SLEEP);

	entry->dbe_refcnt = 1;
	entry->dbe_invalid = FALSE;
	entry->dbe_skipsearch = FALSE;
	entry->dbe_time_rele = 0;
	entry->dbe_id = 0;

	if (table->dbt_id_space)
		entry->dbe_id = id;
	entry->dbe_table = table;

	for (i = 0; i < table->dbt_maxcnt; i++) {
		entry->dbe_indices[i].next = entry->dbe_indices[i].prev = NULL;
		entry->dbe_indices[i].entry = entry;
		/*
		 * We mark the entry as not indexed by setting the low
		 * order bit, since address are word aligned. This has
		 * the advantage of causeing a trap if the address is
		 * used. After the entry is linked in to the
		 * corresponding index the bit will be cleared.
		 */
		INVALIDATE_ADDR(entry->dbe_indices[i].entry);
	}

	entry->dbe_data = (rfs4_entry_t)&entry->dbe_indices[table->dbt_maxcnt];
	bzero(entry->dbe_data, table->dbt_usize);
	entry->dbe_data->dbe = entry;

	if (!(*table->dbt_create)(entry->dbe_data, data)) {
		kmem_cache_free(table->dbt_mem_cache, entry);
		return (NULL);
	}

	mutex_enter(table->dbt_lock);
	table->dbt_count++;
	mutex_exit(table->dbt_lock);

	return (entry);
}

static void
rfs4_dbe_tabreap_adjust(rfs4_table_t *table)
{
	clock_t		tabreap;
	clock_t		reap_int;
	uint32_t	in_use;

	/*
	 * Adjust the table's reap interval based on the
	 * number of id's currently in use. Each table's
	 * default remains the same if id usage subsides.
	 */
	ASSERT(MUTEX_HELD(&table->dbt_reaper_cv_lock));
	tabreap = MIN(rfs4_reap_interval, table->dbt_max_cache_time);

	in_use = table->dbt_count + 1;	/* see rfs4_dbe_create */
	if (in_use >= table->dbt_id_hwat) {
		ASSERT(t_hreap != 0);
		reap_int = (tabreap * t_hreap) / 100;
	} else if (in_use >= table->dbt_id_lwat) {
		ASSERT(t_lreap != 0);
		reap_int = (tabreap * t_lreap) / 100;
	} else {
		reap_int = tabreap;
	}
	table->dbt_id_reap = reap_int;
	DTRACE_PROBE2(table__reap__interval, char *,
	    table->dbt_name, time_t, table->dbt_id_reap);
}

rfs4_entry_t
rfs4_dbsearch(rfs4_index_t *idx, void *key, bool_t *create, void *arg,
    rfs4_dbsearch_type_t dbsearch_type)
{
	int		 already_done;
	uint32_t	 i;
	rfs4_table_t	*table = idx->dbi_table;
	rfs4_index_t	*ip;
	rfs4_bucket_t	*bp;
	rfs4_link_t	*l;
	rfs4_dbe_t	*entry;
	id_t		 id = -1;

	i = HASH(idx, key);
	bp = &idx->dbi_buckets[i];

	NFS4_DEBUG(table->dbt_debug & SEARCH_DEBUG,
	    (CE_NOTE, "Searching for key %p in table %s by %s",
	    key, table->dbt_name, idx->dbi_keyname));

	rw_enter(bp->dbk_lock, RW_READER);
retry:
	for (l = bp->dbk_head; l; l = l->next) {
		if (l->entry->dbe_refcnt > 0 &&
		    (l->entry->dbe_skipsearch == FALSE ||
		    (l->entry->dbe_skipsearch == TRUE &&
		    dbsearch_type == RFS4_DBS_INVALID)) &&
		    (*idx->dbi_compare)(l->entry->dbe_data, key)) {
			mutex_enter(l->entry->dbe_lock);
			if (l->entry->dbe_refcnt == 0) {
				mutex_exit(l->entry->dbe_lock);
				continue;
			}

			/* place an additional hold since we are returning */
			rfs4_dbe_hold(l->entry);

			mutex_exit(l->entry->dbe_lock);
			rw_exit(bp->dbk_lock);

			*create = FALSE;

			NFS4_DEBUG((table->dbt_debug & SEARCH_DEBUG),
			    (CE_NOTE, "Found entry %p for %p in table %s",
			    (void *)l->entry, key, table->dbt_name));

			if (id != -1)
				id_free(table->dbt_id_space, id);
			return (l->entry->dbe_data);
		}
	}

	if (!*create || table->dbt_create == NULL || !idx->dbi_createable ||
	    table->dbt_maxentries == table->dbt_count) {
		NFS4_DEBUG(table->dbt_debug & SEARCH_DEBUG,
		    (CE_NOTE, "Entry for %p in %s not found",
		    key, table->dbt_name));

		rw_exit(bp->dbk_lock);
		if (id != -1)
			id_free(table->dbt_id_space, id);
		return (NULL);
	}

	if (table->dbt_id_space && id == -1) {
		rw_exit(bp->dbk_lock);

		/* get an id, ok to sleep for it here */
		id = id_alloc(table->dbt_id_space);
		ASSERT(id != -1);

		mutex_enter(&table->dbt_reaper_cv_lock);
		rfs4_dbe_tabreap_adjust(table);
		mutex_exit(&table->dbt_reaper_cv_lock);

		rw_enter(bp->dbk_lock, RW_WRITER);
		goto retry;
	}

	/* get an exclusive lock on the bucket */
	if (rw_read_locked(bp->dbk_lock) && !rw_tryupgrade(bp->dbk_lock)) {
		NFS4_DEBUG(table->dbt_debug & OTHER_DEBUG,
		    (CE_NOTE, "Trying to upgrade lock on "
		    "hash chain %d (%p) for  %s by %s",
		    i, (void*)bp, table->dbt_name, idx->dbi_keyname));

		rw_exit(bp->dbk_lock);
		rw_enter(bp->dbk_lock, RW_WRITER);
		goto retry;
	}

	/* create entry */
	entry = rfs4_dbe_create(table, id, arg);
	if (entry == NULL) {
		rw_exit(bp->dbk_lock);
		if (id != -1)
			id_free(table->dbt_id_space, id);

		NFS4_DEBUG(table->dbt_debug & CREATE_DEBUG,
		    (CE_NOTE, "Constructor for table %s failed",
		    table->dbt_name));
		return (NULL);
	}

	/*
	 * Add one ref for entry into table's hash - only one
	 * reference added even though there may be multiple indices
	 */
	rfs4_dbe_hold(entry);
	ENQUEUE(bp->dbk_head, &entry->dbe_indices[idx->dbi_tblidx]);
	VALIDATE_ADDR(entry->dbe_indices[idx->dbi_tblidx].entry);

	already_done = idx->dbi_tblidx;
	rw_exit(bp->dbk_lock);

	for (ip = table->dbt_indices; ip; ip = ip->dbi_inext) {
		if (ip->dbi_tblidx == already_done)
			continue;
		l = &entry->dbe_indices[ip->dbi_tblidx];
		i = HASH(ip, ip->dbi_mkkey(entry->dbe_data));
		ASSERT(i < ip->dbi_table->dbt_len);
		bp = &ip->dbi_buckets[i];
		ENQUEUE_IDX(bp, l);
	}

	NFS4_DEBUG(
	    table->dbt_debug & SEARCH_DEBUG || table->dbt_debug & CREATE_DEBUG,
	    (CE_NOTE, "Entry %p created for %s = %p in table %s",
	    (void*)entry, idx->dbi_keyname, (void*)key, table->dbt_name));

	return (entry->dbe_data);
}

/*ARGSUSED*/
boolean_t
rfs4_cpr_callb(void *arg, int code)
{
	rfs4_table_t *table = rfs4_client_tab;
	rfs4_bucket_t *buckets, *bp;
	rfs4_link_t *l;
	rfs4_client_t *cp;
	int i;

	/*
	 * We get called for Suspend and Resume events.
	 * For the suspend case we simply don't care!  Nor do we care if
	 * there are no clients.
	 */
	if (code == CB_CODE_CPR_CHKPT || table == NULL) {
		return (B_TRUE);
	}

	buckets = table->dbt_indices->dbi_buckets;

	/*
	 * When we get this far we are in the process of
	 * resuming the system from a previous suspend.
	 *
	 * We are going to blast through and update the
	 * last_access time for all the clients and in
	 * doing so extend them by one lease period.
	 */
	for (i = 0; i < table->dbt_len; i++) {
		bp = &buckets[i];
		for (l = bp->dbk_head; l; l = l->next) {
			cp = (rfs4_client_t *)l->entry->dbe_data;
			cp->rc_last_access = gethrestime_sec();
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
	rfs4_bucket_t *buckets = table->dbt_indices->dbi_buckets, *bp;
	rfs4_link_t *l;
	rfs4_dbe_t *entry;
	int i;

	NFS4_DEBUG(table->dbt_debug & WALK_DEBUG,
	    (CE_NOTE, "Walking entries in %s", table->dbt_name));

	/* Walk the buckets looking for entries to release/destroy */
	for (i = 0; i < table->dbt_len; i++) {
		bp = &buckets[i];
		rw_enter(bp->dbk_lock, RW_READER);
		for (l = bp->dbk_head; l; l = l->next) {
			entry = l->entry;
			mutex_enter(entry->dbe_lock);
			(*callout)(entry->dbe_data, data);
			mutex_exit(entry->dbe_lock);
		}
		rw_exit(bp->dbk_lock);
	}

	NFS4_DEBUG(table->dbt_debug & WALK_DEBUG,
	    (CE_NOTE, "Walking entries complete %s", table->dbt_name));
}


static void
rfs4_dbe_reap(rfs4_table_t *table, time_t cache_time, uint32_t desired)
{
	rfs4_index_t *idx = table->dbt_indices;
	rfs4_bucket_t *buckets = idx->dbi_buckets, *bp;
	rfs4_link_t *l, *t;
	rfs4_dbe_t *entry;
	bool_t found;
	int i;
	int count = 0;

	NFS4_DEBUG(table->dbt_debug & REAP_DEBUG,
	    (CE_NOTE, "Reaping %d entries older than %ld seconds in table %s",
	    desired, cache_time, table->dbt_name));

	/* Walk the buckets looking for entries to release/destroy */
	for (i = 0; i < table->dbt_len; i++) {
		bp = &buckets[i];
		do {
			found = FALSE;
			rw_enter(bp->dbk_lock, RW_READER);
			for (l = bp->dbk_head; l; l = l->next) {
				entry = l->entry;
				/*
				 * Examine an entry.  Ref count of 1 means
				 * that the only reference is for the hash
				 * table reference.
				 */
				if (entry->dbe_refcnt != 1)
					continue;
				mutex_enter(entry->dbe_lock);
				if ((entry->dbe_refcnt == 1) &&
				    (table->dbt_reaper_shutdown ||
				    table->dbt_expiry == NULL ||
				    (*table->dbt_expiry)(entry->dbe_data))) {
					entry->dbe_refcnt--;
					count++;
					found = TRUE;
				}
				mutex_exit(entry->dbe_lock);
			}
			if (found) {
				if (!rw_tryupgrade(bp->dbk_lock)) {
					rw_exit(bp->dbk_lock);
					rw_enter(bp->dbk_lock, RW_WRITER);
				}

				l = bp->dbk_head;
				while (l) {
					t = l;
					entry = t->entry;
					l = l->next;
					if (entry->dbe_refcnt == 0) {
						DEQUEUE(bp->dbk_head, t);
						t->next = NULL;
						t->prev = NULL;
						INVALIDATE_ADDR(t->entry);
						rfs4_dbe_destroy(entry);
					}
				}
			}
			rw_exit(bp->dbk_lock);
			/*
			 * delay slightly if there is more work to do
			 * with the expectation that other reaper
			 * threads are freeing data structures as well
			 * and in turn will reduce ref counts on
			 * entries in this table allowing them to be
			 * released.  This is only done in the
			 * instance that the tables are being shut down.
			 */
			if (table->dbt_reaper_shutdown && bp->dbk_head != NULL)
				delay(hz/100);
		/*
		 * If this is a table shutdown, keep going until
		 * everything is gone
		 */
		} while (table->dbt_reaper_shutdown && bp->dbk_head != NULL);

		if (!table->dbt_reaper_shutdown && desired && count >= desired)
			break;
	}

	NFS4_DEBUG(table->dbt_debug & REAP_DEBUG,
	    (CE_NOTE, "Reaped %d entries older than %ld seconds in table %s",
	    count, cache_time, table->dbt_name));
}

static void
reaper_thread(caddr_t *arg)
{
	rfs4_table_t	*table = (rfs4_table_t *)arg;
	clock_t		 rc;

	NFS4_DEBUG(table->dbt_debug,
	    (CE_NOTE, "rfs4_reaper_thread starting for %s", table->dbt_name));

	CALLB_CPR_INIT(&table->dbt_reaper_cpr_info, &table->dbt_reaper_cv_lock,
	    callb_generic_cpr, "nfsv4Reaper");

	mutex_enter(&table->dbt_reaper_cv_lock);
	do {
		CALLB_CPR_SAFE_BEGIN(&table->dbt_reaper_cpr_info);
		rc = cv_reltimedwait_sig(&table->dbt_reaper_wait,
		    &table->dbt_reaper_cv_lock,
		    SEC_TO_TICK(table->dbt_id_reap), TR_CLOCK_TICK);
		CALLB_CPR_SAFE_END(&table->dbt_reaper_cpr_info,
		    &table->dbt_reaper_cv_lock);
		rfs4_dbe_reap(table, table->dbt_max_cache_time, 0);
	} while (rc != 0 && table->dbt_reaper_shutdown == FALSE);

	CALLB_CPR_EXIT(&table->dbt_reaper_cpr_info);

	NFS4_DEBUG(table->dbt_debug,
	    (CE_NOTE, "rfs4_reaper_thread exiting for %s", table->dbt_name));

	/* Notify the database shutdown processing that the table is shutdown */
	mutex_enter(table->dbt_db->db_lock);
	table->dbt_db->db_shutdown_count--;
	cv_signal(&table->dbt_db->db_shutdown_wait);
	mutex_exit(table->dbt_db->db_lock);
}

static void
rfs4_start_reaper(rfs4_table_t *table)
{
	if (table->dbt_max_cache_time == 0)
		return;

	(void) thread_create(NULL, 0, reaper_thread, table, 0, &p0, TS_RUN,
	    minclsyspri);
}

#ifdef DEBUG
void
rfs4_dbe_debug(rfs4_dbe_t *entry)
{
	cmn_err(CE_NOTE, "Entry %p from table %s",
	    (void *)entry, entry->dbe_table->dbt_name);
	cmn_err(CE_CONT, "\trefcnt = %d id = %d",
	    entry->dbe_refcnt, entry->dbe_id);
}
#endif
