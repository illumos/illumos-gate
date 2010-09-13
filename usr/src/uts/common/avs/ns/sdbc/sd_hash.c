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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/ksynch.h>
#include <sys/cmn_err.h>
#include <sys/kmem.h>
#include <sys/ddi.h>
#include <sys/nsc_thread.h>
#include <sys/nsctl/nsctl.h>

#include <sys/sdt.h>		/* dtrace is S10 or later */

#include "sd_bcache.h"
#include "sd_hash.h"

#if defined(_SD_DEBUG)
int _sd_hash_max_inlist = 0;
#endif


#define	_SD_HB_LOCKS 32
static kmutex_t _sd_hb_locks[_SD_HB_LOCKS];


/*
 * _sdbc_hash_load - allocate all the locks for buckets.
 *
 *
 */
int
_sdbc_hash_load(void)
{
	int i;
	for (i = 0; i < _SD_HB_LOCKS; i++) {
		mutex_init(&_sd_hb_locks[i], NULL, MUTEX_DRIVER, NULL);
	}
	return (0);
}

/*
 * _sdbc_hash_unload - free all the locks for buckets.
 *
 *
 */
void
_sdbc_hash_unload(void)
{
	int i;
	for (i = 0; i < _SD_HB_LOCKS; i++) {
		mutex_destroy(&_sd_hb_locks[i]);
	}
}


/*
 * _sdbc_hash_configure - create a hash table
 *
 * ARGUMENTS:
 *	num_ents - Number of entries (or hash buckets)
 *	htype    - Type of memory to allocate.
 *
 * RETURNS:
 *	The address of the hash table just created
 *	or zero in the event of failure.
 *
 * USAGE:
 *	This routine rounds of the number of entries to the next higher
 *	power of 2. Allocate the hash buckets and initializes the locks
 *	and returns the hash table that is created.
 *	It is the caller's responsibility to save the hash_table and pass
 *	it as a key for future accesses to the hash.
 *	It is also the caller's responsibility to destroy the hash table
 *	when appropriate.
 */


_sd_hash_table_t *
_sdbc_hash_configure(int num_ents)
{
	_sd_hash_table_t *hash_table;
	_sd_hash_bucket_t *bucket;
	int i;
	int get_high_bit(int);

	if ((hash_table = (_sd_hash_table_t *)
		nsc_kmem_zalloc(sizeof (_sd_hash_table_t),
				KM_SLEEP, sdbc_hash_mem)) == NULL)
		return (NULL);

	hash_table->ht_bits = get_high_bit(num_ents);
	hash_table->ht_size = (1 << hash_table->ht_bits);

	/*
	 * this is where we compute the mask used in the hash function
	 * the ht_nmask is basically an not of ht_mask used in hash
	 * function.
	 */
	hash_table->ht_mask = (hash_table->ht_size - 1);
	hash_table->ht_nmask = (~0 & ~(hash_table->ht_mask));

	if ((hash_table->ht_buckets = (_sd_hash_bucket_t *)
		nsc_kmem_zalloc(hash_table->ht_size *
				sizeof (_sd_hash_bucket_t), KM_SLEEP,
				sdbc_hash_mem)) == NULL)
		return (NULL);

	for (i = 0; i < (hash_table->ht_size); i++) {
		bucket = (hash_table->ht_buckets + i);

		bucket->hb_lock = &_sd_hb_locks[i % _SD_HB_LOCKS];
		bucket->hb_head = bucket->hb_tail = NULL;
		bucket->hb_inlist = 0;
	}

	return (hash_table);
}


/*
 * _sdbc_hash_deconfigure - deconfigure a hash table
 *
 * ARGUMENTS:
 *	hash_table - hash table that was created earlier on.
 *
 * RETURNS:
 *	None.
 *
 * USAGE:
 *	this routine deallocates memory that was allocated during the
 *	hash create.
 */

void
_sdbc_hash_deconfigure(_sd_hash_table_t *hash_table)
{
	if (!hash_table)
		return;

	nsc_kmem_free(hash_table->ht_buckets,
			hash_table->ht_size * sizeof (_sd_hash_bucket_t));

	nsc_kmem_free(hash_table, sizeof (_sd_hash_table_t));
}

static int _sd_forced_hash_miss;
static int _sd_hash_collision;


/*
 * _sd_hash_search - search the hash table for an entry
 *
 * ARGUMENTS:
 *	cd	   - device that we are interested in.
 *	block_num  - block number we are interested in.
 *	hash_table - hash table to search in.
 *
 * RETURNS:
 *	returns a hash header if a match was found in the hash table
 *	for the device & block_num.
 *	Else returns 0.
 *
 * USAGE:
 *	This routine is called to check if a block already exists for
 *	the device, block_num combination. If the block does not exist,
 *	then a new block needs to be allocated and inserted into the hash
 *	table for future references.
 */

_sd_hash_hd_t *
_sd_hash_search(int cd, nsc_off_t block_num, _sd_hash_table_t *table)
{
	int i;
	_sd_hash_bucket_t *bucket;
	_sd_hash_hd_t *hptr;
#if defined(_SD_HASH_OPTIMIZE)
#define	MAX_HSEARCH_RETRIES	30
	int tries = 0;
	_sd_hash_hd_t *hnext;
	unsigned int seq;

	i = HASH(cd, block_num, table);
	bucket = (table->ht_buckets + i);
retry_search:
	seq = bucket->hb_seq;
	for (hptr = bucket->hb_head; hptr; hptr = hnext) {
		/*
		 * Save pointer for next before checking the seq counter.
		 */
		hnext = hptr->hh_next;
		/*
		 * enforce ordering of load of hptr->hh_next
		 * above and bucket->hb_seq below
		 */
		sd_serialize();
		if (bucket->hb_seq != seq) {
			/*
			 * To avoid looping forever, break out if a certain
			 * limit is reached. Its okay to return miss
			 * since the insert will do a proper search.
			 */
			if (++tries < MAX_HSEARCH_RETRIES) goto retry_search;
			else {
				_sd_forced_hash_miss++;
				DTRACE_PROBE1(_sd_hash_search_end,
						int, _sd_forced_hash_miss);
				return (NULL);
			}
		}
		if ((hptr->hh_cd == cd) && (hptr->hh_blk_num == block_num))
			break;
		if (hptr->hh_blk_num > block_num) {
			DTRACE_PROBE1(_sd_hash_search_end,
					_sd_hash_hd_t *, hptr);
			return (NULL);
		}
	}

	DTRACE_PROBE1(_sd_hash_search_end,
			_sd_hash_hd_t *, hptr);
	return (hptr);
#else

	i = HASH(cd, block_num, table);
	bucket = (table->ht_buckets + i);

	mutex_enter(bucket->hb_lock);

	for (hptr = bucket->hb_head; hptr; hptr = hptr->hh_next) {
		if ((hptr->hh_cd == cd) && (hptr->hh_blk_num == block_num))
			break;
		/*
		 * the list is ordered. If we go beyond our block, no
		 * point searching
		 */
		if (hptr->hh_blk_num > block_num) {
			hptr = NULL;
			break;
		}
	}
	mutex_exit(bucket->hb_lock);

	return (hptr);
#endif
}


/*
 * _sd_hash_insert - insert an entry into the hash table
 *
 * ARGUMENTS:
 *	cd	   - device that we are interested in.
 *	block_num  - block number we are interested in.
 *      hptr       - pointer to block that we are inserting.
 *	table	   - hash table to search in.
 *
 * RETURNS:
 *	Pointer to block that was passed in, except if the cd, block_num
 *	already exists in the hash.  Caller must check for return
 *	not equal hptr.
 *
 * USAGE:
 *	this routine inserts the hptr into the appropriate hash bucket and
 *	sets the cd, block_num in the block for future references.
 */

_sd_hash_hd_t *
_sd_hash_insert(int cd,
		nsc_off_t block_num,
		_sd_hash_hd_t *hptr,
		_sd_hash_table_t *table)
{
	int i;
	_sd_hash_hd_t *p;
	_sd_hash_bucket_t *bucket;

	i = HASH(cd, block_num, table);
	bucket = (table->ht_buckets + i);

#if defined(_SD_DEBUG)
	if (hptr->hh_hashed) {
		cmn_err(CE_WARN, "_sd_err: hptr %p bucket %p already hashed",
			hptr, bucket);
	}
#endif
	hptr->hh_cd = (ushort_t)cd;
	hptr->hh_blk_num = block_num;

	mutex_enter(bucket->hb_lock);

	for (p = bucket->hb_head; (p && (p->hh_blk_num <= block_num));
							p = p->hh_next) {
		if ((p->hh_cd == cd) && (p->hh_blk_num == block_num)) {
			mutex_exit(bucket->hb_lock);
			_sd_hash_collision++;
			DTRACE_PROBE2(_sd_hash_insert_end,
					_sd_hash_hd_t *, p,
					int, _sd_hash_collision);

			return (p);
		}
	}
	hptr->hh_hashed = 1;
	/*
	 * At this point, (p) points to the next higher block number or is
	 * NULL. If it is NULL, we are queueing to the tail of list.
	 * Else, insert just before p
	 */
	if (p) {
		hptr->hh_next = p;
		if ((hptr->hh_prev = p->hh_prev) != NULL)
			p->hh_prev->hh_next = hptr;
		else
			bucket->hb_head = hptr;
		p->hh_prev = hptr;
	} else {
		hptr->hh_next = NULL;
		hptr->hh_prev = bucket->hb_tail;
		if (bucket->hb_head)
			bucket->hb_tail->hh_next = hptr;
		else
			bucket->hb_head = hptr;
		bucket->hb_tail = hptr;
	}
#if defined(_SD_HASH_OPTIMIZE)
	bucket->hb_seq++;
#endif
#if defined(_SD_DEBUG)
	if (_sd_hash_max_inlist < (int)++(bucket->hb_inlist))
		_sd_hash_max_inlist = bucket->hb_inlist;
#endif
	mutex_exit(bucket->hb_lock);

	return (hptr);
}



/*
 * _sd_hash_delete - delete an entry from the hash table
 *
 * ARGUMENTS:
 *	hptr	   - pointer to delete from hash table.
 *	hash_table - hash table that was created earlier on.
 *
 * RETURNS:
 *	0 on success.  -1 on errors.
 *
 * USAGE:
 *	this routine deletes a hash entry from the hash table.
 */

int
_sd_hash_delete(_sd_hash_hd_t *hptr, _sd_hash_table_t *table)
{
	int i;
	_sd_hash_bucket_t *bucket;

	if (hptr->hh_hashed == 0) {
		DTRACE_PROBE(_sd_hash_delete_end1);
		return (-1);
	}

	i = HASH(hptr->hh_cd, hptr->hh_blk_num, table);
	bucket = (table->ht_buckets + i);

	/* was FAST */
	mutex_enter(bucket->hb_lock);
	if (hptr->hh_hashed == 0) {
		/* was FAST */
		mutex_exit(bucket->hb_lock);
		DTRACE_PROBE(_sd_hash_delete_end2);
		return (-1);
	}
	hptr->hh_hashed = 0;
#if defined(_SD_HASH_OPTIMIZE)
	/*
	 * Increment sequence counter on bucket. This will signal a lookup
	 * to redo the lookup since we might have broken the link used
	 * during the lookup.
	 */
	bucket->hb_seq++;
#endif

	if (hptr->hh_prev)
		hptr->hh_prev->hh_next = hptr->hh_next;
	else
		bucket->hb_head = hptr->hh_next;
	if (hptr->hh_next)
		hptr->hh_next->hh_prev = hptr->hh_prev;
	else
		bucket->hb_tail = hptr->hh_prev;
#if defined(_SD_DEBUG)
	bucket->hb_inlist--;
#endif
	/* was FAST */
	mutex_exit(bucket->hb_lock);

	return (0);
}

/*
 * _sd_hash_replace - replace 'old' with 'new' entry.
 *
 * ARGUMENTS:
 *      old   - pointer to block being deleted (to be anonymous)
 *      new   - pointer to block inserting in place.
 *	table - hash table to search in.
 *
 * RETURNS:
 *	pointer to inserted block.
 *
 * USAGE:
 *	expects old & new to refer to same block.
 *	new must not be already hashed.
 */

_sd_hash_hd_t *
_sd_hash_replace(_sd_hash_hd_t *old, _sd_hash_hd_t *new,
			_sd_hash_table_t *table)
{
	int i;
	_sd_hash_bucket_t *bucket;

	if ((old->hh_cd != new->hh_cd) || (old->hh_blk_num != new->hh_blk_num))
		cmn_err(CE_PANIC, "_sd_hash_replace: mismatch %p %p",
		    (void *)old, (void *)new);
	if (new->hh_hashed)
		cmn_err(CE_PANIC, "_sd_hash_replace: new %p already hashed",
		    (void *)new);
	if (old->hh_hashed == 0) {
		_sd_hash_hd_t *hptr;
		hptr = _sd_hash_insert(new->hh_cd, new->hh_blk_num, new, table);

		DTRACE_PROBE1(_sd_hash_replace_end,
				_sd_hash_hd_t *, hptr);

		return (hptr);
	}

	i = HASH(old->hh_cd, old->hh_blk_num, table);
	bucket = (table->ht_buckets + i);

	/* was FAST */
	mutex_enter(bucket->hb_lock);
	if (old->hh_hashed == 0) {
		_sd_hash_hd_t *hptr;
		/* was FAST */
		mutex_exit(bucket->hb_lock);

		hptr = _sd_hash_insert(new->hh_cd, new->hh_blk_num, new, table);

		DTRACE_PROBE1(_sd_hash_replace_end,
				_sd_hash_hd_t *, hptr);
		return (hptr);
	}
	old->hh_hashed = 0;
	new->hh_hashed = 1;
	new->hh_prev = old->hh_prev;
	new->hh_next = old->hh_next;

	if (new->hh_prev)
		new->hh_prev->hh_next = new;
	else
		bucket->hb_head = new;
	if (new->hh_next)
		new->hh_next->hh_prev = new;
	else
		bucket->hb_tail = new;
#if defined(_SD_HASH_OPTIMIZE)
	bucket->hb_seq++;
#endif
	/* was FAST */
	mutex_exit(bucket->hb_lock);

	return (new);
}
