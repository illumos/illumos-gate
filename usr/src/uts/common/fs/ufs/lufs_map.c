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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2012 Milan Jurik. All rights reserved.
 */

#include <sys/systm.h>
#include <sys/types.h>
#include <sys/vnode.h>
#include <sys/errno.h>
#include <sys/sysmacros.h>
#include <sys/debug.h>
#include <sys/kmem.h>
#include <sys/conf.h>
#include <sys/proc.h>
#include <sys/cmn_err.h>
#include <sys/fs/ufs_inode.h>
#include <sys/fs/ufs_filio.h>
#include <sys/fs/ufs_log.h>
#include <sys/inttypes.h>
#include <sys/atomic.h>
#include <sys/tuneable.h>

/*
 * externs
 */
extern pri_t minclsyspri;
extern struct kmem_cache *lufs_bp;
extern int ufs_trans_push_quota(ufsvfs_t *, delta_t, struct dquot *);

/*
 * globals
 */
kmem_cache_t *mapentry_cache;

/*
 * logmap tuning constants
 */
long	logmap_maxnme_commit	= 2048;
long	logmap_maxnme_async	= 4096;
long	logmap_maxnme_sync	= 6144;
long	logmap_maxcfrag_commit	= 4;	/* Max canceled fragments per moby */


uint64_t ufs_crb_size = 0;		/* current size of all crb buffers */
uint64_t ufs_crb_max_size = 0;		/* highest crb buffer use so far */
size_t ufs_crb_limit;			/* max allowable size for crbs */
uint64_t ufs_crb_alloc_fails = 0;	/* crb allocation failures stat */
#define	UFS_MAX_CRB_DEFAULT_DIVISOR 10	/* max 1/10 kmem_maxavail() */
int ufs_max_crb_divisor = UFS_MAX_CRB_DEFAULT_DIVISOR; /* tunable */
void handle_dquot(mapentry_t *);

/*
 * GENERIC MAP ROUTINES
 */

#define	CRB_FREE(crb, me) \
	kmem_free(crb->c_buf, crb->c_nb); \
	atomic_add_64(&ufs_crb_size, -(uint64_t)crb->c_nb); \
	kmem_free(crb, sizeof (crb_t)); \
	(me)->me_crb = NULL;

#define	CRB_RELE(me) { \
	crb_t *crb = (me)->me_crb; \
	if (crb && (--crb->c_refcnt == 0)) { \
		CRB_FREE(crb, me) \
	} \
}

/*
 * Check that the old delta has an argument and a push function of
 * ufs_trans_push_quota(), then check that the old and new deltas differ.
 * If so we clean up with handle_dquot() before replacing the old delta.
 */
#define	HANDLE_DQUOT(me, melist) { \
	if ((me->me_arg) && \
	    (me->me_func == ufs_trans_push_quota)) { \
		if (!((me->me_dt == melist->me_dt) && \
		    (me->me_arg == melist->me_arg) && \
		    (me->me_func == melist->me_func))) { \
			handle_dquot(me); \
		} \
	} \
}

/*
 * free up all the mapentries for a map
 */
void
map_free_entries(mt_map_t *mtm)
{
	int		i;
	mapentry_t	*me;

	while ((me = mtm->mtm_next) != (mapentry_t *)mtm) {
		me->me_next->me_prev = me->me_prev;
		me->me_prev->me_next = me->me_next;
		CRB_RELE(me);
		kmem_cache_free(mapentry_cache, me);
	}
	for (i = 0; i < mtm->mtm_nhash; i++)
		mtm->mtm_hash[i] = NULL;
	mtm->mtm_nme = 0;
	mtm->mtm_nmet = 0;
}

/*
 * done with map; free if necessary
 */
mt_map_t *
map_put(mt_map_t *mtm)
{
	/*
	 * free up the map's memory
	 */
	map_free_entries(mtm);
	ASSERT(map_put_debug(mtm));
	kmem_free(mtm->mtm_hash,
	    (size_t) (sizeof (mapentry_t *) * mtm->mtm_nhash));
	mutex_destroy(&mtm->mtm_mutex);
	mutex_destroy(&mtm->mtm_scan_mutex);
	cv_destroy(&mtm->mtm_to_roll_cv);
	cv_destroy(&mtm->mtm_from_roll_cv);
	rw_destroy(&mtm->mtm_rwlock);
	mutex_destroy(&mtm->mtm_lock);
	cv_destroy(&mtm->mtm_cv_commit);
	cv_destroy(&mtm->mtm_cv_next);
	cv_destroy(&mtm->mtm_cv_eot);
	cv_destroy(&mtm->mtm_cv);
	kmem_free(mtm, sizeof (mt_map_t));
	return (NULL);
}
/*
 * Allocate a map;
 */
mt_map_t *
map_get(ml_unit_t *ul, enum maptypes maptype, int nh)
{
	mt_map_t	*mtm;

	/*
	 * assume the map is not here and allocate the necessary structs
	 */
	mtm = kmem_zalloc(sizeof (mt_map_t), KM_SLEEP);
	mutex_init(&mtm->mtm_mutex, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&mtm->mtm_scan_mutex, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&mtm->mtm_to_roll_cv, NULL, CV_DEFAULT, NULL);
	cv_init(&mtm->mtm_from_roll_cv, NULL, CV_DEFAULT, NULL);
	rw_init(&mtm->mtm_rwlock, NULL, RW_DEFAULT, NULL);
	mtm->mtm_next = (mapentry_t *)mtm;
	mtm->mtm_prev = (mapentry_t *)mtm;
	mtm->mtm_hash = kmem_zalloc((size_t) (sizeof (mapentry_t *) * nh),
	    KM_SLEEP);
	mtm->mtm_nhash = nh;
	mtm->mtm_debug = ul->un_debug;
	mtm->mtm_type = maptype;

	mtm->mtm_cfrags = 0;
	mtm->mtm_cfragmax = logmap_maxcfrag_commit;

	/*
	 * for scan test
	 */
	mtm->mtm_ul = ul;

	/*
	 * Initialize locks
	 */
	mutex_init(&mtm->mtm_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&mtm->mtm_cv_commit, NULL, CV_DEFAULT, NULL);
	cv_init(&mtm->mtm_cv_next, NULL, CV_DEFAULT, NULL);
	cv_init(&mtm->mtm_cv_eot, NULL, CV_DEFAULT, NULL);
	cv_init(&mtm->mtm_cv, NULL, CV_DEFAULT, NULL);
	ASSERT(map_get_debug(ul, mtm));

	return (mtm);
}

/*
 * DELTAMAP ROUTINES
 */
/*
 * deltamap tuning constants
 */
long	deltamap_maxnme	= 1024;	/* global so it can be set */

int
deltamap_need_commit(mt_map_t *mtm)
{
	return (mtm->mtm_nme > deltamap_maxnme);
}

/*
 * put a delta into a deltamap; may sleep on memory
 */
void
deltamap_add(
	mt_map_t *mtm,
	offset_t mof,
	off_t nb,
	delta_t dtyp,
	int (*func)(),
	ulong_t arg,
	threadtrans_t *tp)
{
	int32_t		hnb;
	mapentry_t	*me;
	mapentry_t	**mep;

	ASSERT(((mtm->mtm_debug & MT_CHECK_MAP) == 0) ||
	    map_check_linkage(mtm));

	mutex_enter(&mtm->mtm_mutex);

	for (hnb = 0; nb; nb -= hnb, mof += hnb) {
		hnb = MAPBLOCKSIZE - (mof & MAPBLOCKOFF);
		if (hnb > nb)
			hnb = nb;
		/*
		 * Search for dup entry. We need to ensure that we don't
		 * replace a map entry which carries quota information
		 * with a map entry which doesn't. In that case we lose
		 * reference the the dquot structure which will not be
		 * cleaned up by the push function me->me_func as this will
		 * never be called.
		 * The stray dquot would be found later by invalidatedq()
		 * causing a panic when the filesystem is unmounted.
		 */
		mep = MAP_HASH(mof, mtm);
		for (me = *mep; me; me = me->me_hash) {
			if (DATAwithinME(mof, hnb, me)) {
				/*
				 * Don't remove quota entries which have
				 * incremented the ref count (those with a
				 * ufs_trans_push_quota push function).
				 * Let logmap_add[_buf] clean them up.
				 */
				if (me->me_func == ufs_trans_push_quota) {
					continue;
				}
				break;
			}
			ASSERT((dtyp == DT_CANCEL) ||
			    (!DATAoverlapME(mof, hnb, me)) ||
			    MEwithinDATA(me, mof, hnb));
		}

		if (me) {
			/* already in map */
			continue;
		}

		/*
		 * Add up all the delta map deltas so we can compute
		 * an upper bound on the log size used.
		 * Note, some deltas get removed from the deltamap
		 * before the deltamap_push by lufs_write_strategy
		 * and so multiple deltas to the same mof offset
		 * don't get cancelled here but in the logmap.
		 * Thus we can't easily get a accurate count of
		 * the log space used - only an upper bound.
		 */
		if (tp && (mtm->mtm_ul->un_deltamap == mtm)) {
			ASSERT(dtyp != DT_CANCEL);
			if (dtyp == DT_ABZERO) {
				tp->deltas_size += sizeof (struct delta);
			} else {
				tp->deltas_size +=
				    (hnb + sizeof (struct delta));
			}
		}

		delta_stats[dtyp]++;

		/*
		 * get a mapentry
		 * May need to drop & re-grab the mtm_mutex
		 * and then recheck for a duplicate
		 */
		me = kmem_cache_alloc(mapentry_cache, KM_NOSLEEP);
		if (me == NULL) {
			mutex_exit(&mtm->mtm_mutex);
			me = kmem_cache_alloc(mapentry_cache, KM_SLEEP);
			mutex_enter(&mtm->mtm_mutex);
		}
		bzero(me, sizeof (mapentry_t));

		/*
		 * initialize and put in deltamap
		 */
		me->me_mof = mof;
		me->me_nb = hnb;
		me->me_func = func;
		me->me_arg = arg;
		me->me_dt = dtyp;
		me->me_flags = ME_HASH;
		me->me_tid = mtm->mtm_tid;

		me->me_hash = *mep;
		*mep = me;
		me->me_next = (mapentry_t *)mtm;
		me->me_prev = mtm->mtm_prev;
		mtm->mtm_prev->me_next = me;
		mtm->mtm_prev = me;
		mtm->mtm_nme++;
	}
	mutex_exit(&mtm->mtm_mutex);

	ASSERT(((mtm->mtm_debug & MT_CHECK_MAP) == 0) ||
	    map_check_linkage(mtm));
}

/*
 * remove deltas within (mof, nb) and return as linked list
 */
mapentry_t *
deltamap_remove(mt_map_t *mtm, offset_t mof, off_t nb)
{
	off_t		hnb;
	mapentry_t	*me;
	mapentry_t	**mep;
	mapentry_t	*mer;

	if (mtm == NULL)
		return (NULL);

	ASSERT(((mtm->mtm_debug & MT_CHECK_MAP) == 0) ||
	    map_check_linkage(mtm));

	mutex_enter(&mtm->mtm_mutex);
	for (mer = NULL, hnb = 0; nb; nb -= hnb, mof += hnb) {
		hnb = MAPBLOCKSIZE - (mof & MAPBLOCKOFF);
		if (hnb > nb)
			hnb = nb;
		/*
		 * remove entries from hash and return as a aged linked list
		 */
		mep = MAP_HASH(mof, mtm);
		while ((me = *mep) != 0) {
			if (MEwithinDATA(me, mof, hnb)) {
				*mep = me->me_hash;
				me->me_next->me_prev = me->me_prev;
				me->me_prev->me_next = me->me_next;
				me->me_hash = mer;
				mer = me;
				me->me_flags |= ME_LIST;
				me->me_flags &= ~ME_HASH;
				mtm->mtm_nme--;
			} else
				mep = &me->me_hash;
		}
	}
	mutex_exit(&mtm->mtm_mutex);

	ASSERT(((mtm->mtm_debug & MT_CHECK_MAP) == 0) ||
	    map_check_linkage(mtm));

	return (mer);
}

/*
 * delete entries within (mof, nb)
 */
void
deltamap_del(mt_map_t *mtm, offset_t mof, off_t nb)
{
	mapentry_t	*me;
	mapentry_t	*menext;

	menext = deltamap_remove(mtm, mof, nb);
	while ((me = menext) != 0) {
		menext = me->me_hash;
		kmem_cache_free(mapentry_cache, me);
	}
}

/*
 * Call the indicated function to cause deltas to move to the logmap.
 * top_end_sync() is the only caller of this function and
 * it has waited for the completion of all threads, so there can
 * be no other activity in the deltamap. Therefore we don't need to
 * hold the deltamap lock.
 */
void
deltamap_push(ml_unit_t *ul)
{
	delta_t		dtyp;
	int		(*func)();
	ulong_t		arg;
	mapentry_t	*me;
	offset_t	mof;
	off_t		nb;
	mt_map_t	*mtm	= ul->un_deltamap;

	ASSERT(((mtm->mtm_debug & MT_CHECK_MAP) == 0) ||
	    map_check_linkage(mtm));

	/*
	 * for every entry in the deltamap
	 */
	while ((me = mtm->mtm_next) != (mapentry_t *)mtm) {
		ASSERT(me->me_func);
		func = me->me_func;
		dtyp = me->me_dt;
		arg = me->me_arg;
		mof = me->me_mof;
		nb = me->me_nb;
		if ((ul->un_flags & LDL_ERROR) ||
		    (*func)(ul->un_ufsvfs, dtyp, arg))
			deltamap_del(mtm, mof, nb);
	}

	ASSERT(((mtm->mtm_debug & MT_CHECK_MAP) == 0) ||
	    map_check_linkage(mtm));
}

/*
 * LOGMAP ROUTINES
 */

int
logmap_need_commit(mt_map_t *mtm)
{
	return ((mtm->mtm_nmet > logmap_maxnme_commit) ||
	    (mtm->mtm_cfrags >= mtm->mtm_cfragmax));
}

int
logmap_need_roll_async(mt_map_t *mtm)
{
	return (mtm->mtm_nme > logmap_maxnme_async);
}

int
logmap_need_roll_sync(mt_map_t *mtm)
{
	return (mtm->mtm_nme > logmap_maxnme_sync);
}

void
logmap_start_roll(ml_unit_t *ul)
{
	mt_map_t	*logmap	= ul->un_logmap;

	logmap_settail(logmap, ul);
	ASSERT(!(ul->un_flags & LDL_NOROLL));
	mutex_enter(&logmap->mtm_mutex);
	if ((logmap->mtm_flags & MTM_ROLL_RUNNING) == 0) {
		logmap->mtm_flags |= MTM_ROLL_RUNNING;
		logmap->mtm_flags &= ~(MTM_FORCE_ROLL | MTM_ROLL_EXIT);
		(void) thread_create(NULL, 0, trans_roll, ul, 0, &p0,
		    TS_RUN, minclsyspri);
	}
	mutex_exit(&logmap->mtm_mutex);
}

void
logmap_kill_roll(ml_unit_t *ul)
{
	mt_map_t	*mtm	= ul->un_logmap;

	if (mtm == NULL)
		return;

	mutex_enter(&mtm->mtm_mutex);

	while (mtm->mtm_flags & MTM_ROLL_RUNNING) {
		mtm->mtm_flags |= MTM_ROLL_EXIT;
		cv_signal(&mtm->mtm_to_roll_cv);
		cv_wait(&mtm->mtm_from_roll_cv, &mtm->mtm_mutex);
	}
	mutex_exit(&mtm->mtm_mutex);
}

/*
 * kick the roll thread if it's not doing anything
 */
void
logmap_forceroll_nowait(mt_map_t *logmap)
{
	/*
	 * Don't need to lock mtm_mutex to read mtm_flags here as we
	 * don't care in the rare case when we get a transitional value
	 * of mtm_flags. Just by signalling the thread it will wakeup
	 * and notice it has too many logmap entries.
	 */
	ASSERT(!(logmap->mtm_ul->un_flags & LDL_NOROLL));
	if ((logmap->mtm_flags & MTM_ROLLING) == 0) {
		cv_signal(&logmap->mtm_to_roll_cv);
	}
}

/*
 * kick the roll thread and wait for it to finish a cycle
 */
void
logmap_forceroll(mt_map_t *mtm)
{
	mutex_enter(&mtm->mtm_mutex);
	if ((mtm->mtm_flags & MTM_FORCE_ROLL) == 0) {
		mtm->mtm_flags |= MTM_FORCE_ROLL;
		cv_signal(&mtm->mtm_to_roll_cv);
	}
	do {
		if ((mtm->mtm_flags & MTM_ROLL_RUNNING) == 0) {
			mtm->mtm_flags &= ~MTM_FORCE_ROLL;
			goto out;
		}
		cv_wait(&mtm->mtm_from_roll_cv, &mtm->mtm_mutex);
	} while (mtm->mtm_flags & MTM_FORCE_ROLL);
out:
	mutex_exit(&mtm->mtm_mutex);
}

/*
 * remove rolled deltas within (mof, nb) and free them
 */
void
logmap_remove_roll(mt_map_t *mtm, offset_t mof, off_t nb)
{
	int		dolock = 0;
	off_t		hnb;
	mapentry_t	*me;
	mapentry_t	**mep;
	offset_t	savmof	= mof;
	off_t		savnb	= nb;

	ASSERT(((mtm->mtm_debug & MT_CHECK_MAP) == 0) ||
	    map_check_linkage(mtm));

again:
	if (dolock)
		rw_enter(&mtm->mtm_rwlock, RW_WRITER);
	mutex_enter(&mtm->mtm_mutex);
	for (hnb = 0; nb; nb -= hnb, mof += hnb) {
		hnb = MAPBLOCKSIZE - (mof & MAPBLOCKOFF);
		if (hnb > nb)
			hnb = nb;
		/*
		 * remove and free the rolled entries
		 */
		mep = MAP_HASH(mof, mtm);
		while ((me = *mep) != 0) {
			if ((me->me_flags & ME_ROLL) &&
			    (MEwithinDATA(me, mof, hnb))) {
				if (me->me_flags & ME_AGE) {
					ASSERT(dolock == 0);
					dolock = 1;
					mutex_exit(&mtm->mtm_mutex);
					mof = savmof;
					nb = savnb;
					goto again;
				}
				*mep = me->me_hash;
				me->me_next->me_prev = me->me_prev;
				me->me_prev->me_next = me->me_next;
				me->me_flags &= ~(ME_HASH|ME_ROLL);
				ASSERT(!(me->me_flags & ME_USER));
				mtm->mtm_nme--;
				/*
				 * cancelled entries are handled by someone else
				 */
				if ((me->me_flags & ME_CANCEL) == 0) {
					roll_stats[me->me_dt]++;
					CRB_RELE(me);
					kmem_cache_free(mapentry_cache, me);
				}
			} else
				mep = &me->me_hash;
		}
	}
	mutex_exit(&mtm->mtm_mutex);

	ASSERT(((mtm->mtm_debug & MT_CHECK_MAP) == 0) ||
	    map_check_linkage(mtm));

	if (dolock)
		rw_exit(&mtm->mtm_rwlock);
}

/*
 * Find the disk offset of the next delta to roll.
 * Returns 0: no more deltas to roll or a transaction is being committed
 *	   1: a delta to roll has been found and *mofp points
 *	      to the master file disk offset
 */
int
logmap_next_roll(mt_map_t *logmap, offset_t *mofp)
{
	mapentry_t *me;

	ASSERT(((logmap->mtm_debug & MT_CHECK_MAP) == 0) ||
	    map_check_linkage(logmap));

	mutex_enter(&logmap->mtm_mutex);
	for (me = logmap->mtm_next; me != (mapentry_t *)logmap;
	    me = me->me_next) {
		/* already rolled */
		if (me->me_flags & ME_ROLL) {
			continue;
		}

		/* part of currently busy transaction; stop */
		if (me->me_tid == logmap->mtm_tid) {
			break;
		}

		/* part of commit-in-progress transaction; stop */
		if (me->me_tid == logmap->mtm_committid) {
			break;
		}

		/*
		 * We shouldn't see a DT_CANCEL mapentry whose
		 * tid != mtm_committid, or != mtm_tid since
		 * these are removed at the end of each committed
		 * transaction.
		 */
		ASSERT(!(me->me_dt == DT_CANCEL));

		*mofp = me->me_mof;
		mutex_exit(&logmap->mtm_mutex);
		return (1);
	}
	mutex_exit(&logmap->mtm_mutex);
	return (0);
}

/*
 * put mapentry on sorted age list
 */
static void
logmap_list_age(mapentry_t **age, mapentry_t *meadd)
{
	mapentry_t	*me;

	ASSERT(!(meadd->me_flags & (ME_AGE|ME_LIST)));

	for (me = *age; me; age = &me->me_agenext, me = *age) {
		if (me->me_age > meadd->me_age)
			break;
	}
	meadd->me_agenext = me;
	meadd->me_flags |= ME_AGE;
	*age = meadd;
}

/*
 * get a list of deltas within <mof, mof+nb>
 *	returns with mtm_rwlock held
 *	return value says whether the entire mof range is covered by deltas
 */
int
logmap_list_get(
	mt_map_t *mtm,
	offset_t mof,
	off_t nb,
	mapentry_t **age)
{
	off_t		hnb;
	mapentry_t	*me;
	mapentry_t	**mep;
	int		rwtype	= RW_READER;
	offset_t	savmof	= mof;
	off_t		savnb	= nb;
	int		entire	= 0;
	crb_t		*crb;

	mtm->mtm_ref = 1;
again:

	ASSERT(((mtm->mtm_debug & MT_CHECK_MAP) == 0) ||
	    map_check_linkage(mtm));

	rw_enter(&mtm->mtm_rwlock, rwtype);
	*age = NULL;
	mutex_enter(&mtm->mtm_mutex);
	for (hnb = 0; nb; nb -= hnb, mof += hnb) {
		hnb = MAPBLOCKSIZE - (mof & MAPBLOCKOFF);
		if (hnb > nb)
			hnb = nb;
		/*
		 * find overlapping entries
		 */
		mep = MAP_HASH(mof, mtm);
		for (me = *mep; me; me = me->me_hash) {
			if (me->me_dt == DT_CANCEL)
				continue;
			if (!DATAoverlapME(mof, hnb, me))
				continue;
			/*
			 * check if map entry is in use
			 * (about to be rolled).
			 */
			if (me->me_flags & ME_AGE) {
				/*
				 * reset the age bit in the list,
				 * upgrade the lock, and try again
				 */
				for (me = *age; me; me = *age) {
					*age = me->me_agenext;
					me->me_flags &= ~ME_AGE;
				}
				mutex_exit(&mtm->mtm_mutex);
				rw_exit(&mtm->mtm_rwlock);
				rwtype = RW_WRITER;
				mof = savmof;
				nb = savnb;
				entire = 0;
				goto again;
			} else {
				/* add mapentry to age ordered list */
				logmap_list_age(age, me);
				crb = me->me_crb;
				if (crb) {
					if (DATAwithinCRB(savmof, savnb, crb)) {
						entire = 1;
					}
				} else {
					if (DATAwithinME(savmof, savnb, me)) {
						entire = 1;
					}
				}
			}
		}
	}
	mutex_exit(&mtm->mtm_mutex);

	ASSERT(RW_LOCK_HELD(&mtm->mtm_rwlock));
	return (entire);
}

/*
 * Get a list of deltas for rolling - returns sucess or failure.
 * Also return the cached roll buffer if all deltas point to it.
 */
int
logmap_list_get_roll(mt_map_t *logmap, offset_t mof, rollbuf_t *rbp)
{
	mapentry_t	*me, **mep, *age = NULL;
	crb_t		*crb = NULL;

	ASSERT(RW_LOCK_HELD(&logmap->mtm_rwlock));
	ASSERT(((logmap->mtm_debug & MT_CHECK_MAP) == 0) ||
	    map_check_linkage(logmap));
	ASSERT((mof & MAPBLOCKOFF) == 0);

	rbp->rb_crb = NULL;

	/*
	 * find overlapping entries
	 */
	mutex_enter(&logmap->mtm_mutex);
	mep = MAP_HASH(mof, logmap);
	for (me = *mep; me; me = me->me_hash) {
		if (!DATAoverlapME(mof, MAPBLOCKSIZE, me))
			continue;
		if (me->me_tid == logmap->mtm_tid)
			continue;
		if (me->me_tid == logmap->mtm_committid)
			continue;
		if (me->me_dt == DT_CANCEL)
			continue;

		/*
		 * Check if map entry is in use (by lufs_read_strategy())
		 * and if so reset the age bit in the list,
		 * upgrade the lock, and try again
		 */
		if (me->me_flags & ME_AGE) {
			for (me = age; me; me = age) {
				age = me->me_agenext;
				me->me_flags &= ~ME_AGE;
			}
			mutex_exit(&logmap->mtm_mutex);
			return (1); /* failure */
		} else {
			/* add mapentry to age ordered list */
			logmap_list_age(&age, me);
		}
	}
	if (!age) {
		goto out;
	}

	/*
	 * Mark the deltas as being rolled.
	 */
	for (me = age; me; me = me->me_agenext) {
		me->me_flags |= ME_ROLL;
	}

	/*
	 * Test if all deltas are covered by one valid roll buffer
	 */
	crb = age->me_crb;
	if (crb && !(crb->c_invalid)) {
		for (me = age; me; me = me->me_agenext) {
			if (me->me_crb != crb) {
				crb = NULL;
				break;
			}
		}
		rbp->rb_crb = crb;
	}
out:
	rbp->rb_age = age;

	mutex_exit(&logmap->mtm_mutex);

	ASSERT(((logmap->mtm_debug & MT_SCAN) == 0) ||
	    logmap_logscan_debug(logmap, age));
	ASSERT(RW_LOCK_HELD(&logmap->mtm_rwlock));
	return (0); /* success */
}

void
logmap_list_put_roll(mt_map_t *mtm, mapentry_t *age)
{
	mapentry_t	*me;

	ASSERT(RW_LOCK_HELD(&mtm->mtm_rwlock));
	mutex_enter(&mtm->mtm_mutex);
	for (me = age; me; me = age) {
		age = me->me_agenext;
		me->me_flags &= ~ME_AGE;
	}
	mutex_exit(&mtm->mtm_mutex);
}

void
logmap_list_put(mt_map_t *mtm, mapentry_t *age)
{
	mapentry_t	*me;

	ASSERT(RW_LOCK_HELD(&mtm->mtm_rwlock));
	mutex_enter(&mtm->mtm_mutex);
	for (me = age; me; me = age) {
		age = me->me_agenext;
		me->me_flags &= ~ME_AGE;
	}
	mutex_exit(&mtm->mtm_mutex);
	rw_exit(&mtm->mtm_rwlock);
}

#define	UFS_RW_BALANCE 2
int ufs_rw_balance = UFS_RW_BALANCE;

/*
 * Check if we need to read the master.
 * The master does not need to be read if the log deltas to the
 * block are for one contiguous set of full disk sectors.
 * Both cylinder group bit maps DT_CG (8K); directory entries (512B);
 * and possibly others should not require master disk reads.
 * Calculate the sector map for writing later.
 */
int
logmap_setup_read(mapentry_t *age, rollbuf_t *rbp)
{
	offset_t mof;
	crb_t *crb;
	mapentry_t *me;
	int32_t nb;
	int i;
	int start_sec, end_sec;
	int read_needed = 0;
	int all_inodes = 1;
	int first_sec = INT_MAX;
	int last_sec = -1;
	rbsecmap_t secmap = 0;

	/* LINTED: warning: logical expression always true: op "||" */
	ASSERT((MAPBLOCKSIZE / DEV_BSIZE) == (sizeof (secmap) * NBBY));

	for (me = age; me; me = me->me_agenext) {
		crb = me->me_crb;
		if (crb) {
			nb = crb->c_nb;
			mof = crb->c_mof;
		} else {
			nb = me->me_nb;
			mof = me->me_mof;
		}

		/*
		 * If the delta is not sector aligned then
		 * read the whole block.
		 */
		if ((nb & DEV_BMASK) || (mof & DEV_BMASK)) {
			read_needed = 1;
		}

		/* Set sector map used in the MAPBLOCKSIZE block.  */
		start_sec = (mof & MAPBLOCKOFF) >> DEV_BSHIFT;
		end_sec = start_sec + ((nb - 1) >> DEV_BSHIFT);
		for (i = start_sec; i <= end_sec; i++) {
			secmap |= UINT16_C(1) << i;
		}

		if (me->me_dt != DT_INODE) {
			all_inodes = 0;
		}
		if (start_sec < first_sec) {
			first_sec = start_sec;
		}
		if (end_sec > last_sec) {
			last_sec = end_sec;
		}
	}

	ASSERT(secmap);
	ASSERT(first_sec != INT_MAX);
	ASSERT(last_sec != -1);

	if (all_inodes) {
		/*
		 * Here we have a tradeoff choice. It must be better to
		 * do 2 writes * in the same MAPBLOCKSIZE chunk, than a
		 * read and a write. But what about 3 or more writes, versus
		 * a read+write? * Where is the cut over? It will depend on
		 * the track caching, scsi driver and other activity.
		 * A unpublished tunable is defined (ufs_rw_balance) that
		 * currently defaults to 2.
		 */
		if (!read_needed) {
			int count = 0, gap = 0;
			int sector_set; /* write needed to this sector */

			/* Count the gaps (every 1 to 0 transation) */
			for (i = first_sec + 1; i < last_sec; i++) {
				sector_set = secmap & (UINT16_C(1) << i);
				if (!gap && !sector_set) {
					gap = 1;
					count++;
					if (count > ufs_rw_balance) {
						read_needed = 1;
						break;
					}
				} else if (gap && sector_set) {
					gap = 0;
				}
			}
		}

		/*
		 * Inodes commonly make up the majority (~85%) of deltas.
		 * They cannot contain embedded user data, so its safe to
		 * read and write them all in one IO.
		 * But for directory entries, shadow inode data, and
		 * quota record data the user data fragments can be embedded
		 * betwen those metadata, and so its not safe to read, modify
		 * then write the entire range as user asynchronous user data
		 * writes could get overwritten with old data.
		 * Thus we have to create a segment map of meta data that
		 * needs to get written.
		 *
		 * If user data was logged then this issue would go away.
		 */
		if (read_needed) {
			for (i = first_sec + 1; i < last_sec; i++) {
				secmap |= (UINT16_C(1) << i);
			}
		}
	}
	rbp->rb_secmap = secmap;
	return (read_needed);
}

/*
 * Abort the load of a set of log map delta's.
 * ie,
 * Clear out all mapentries on this unit's log map
 * which have a tid (transaction id) equal to the
 * parameter tid.   Walk the cancel list, taking everything
 * off it, too.
 */
static void
logmap_abort(ml_unit_t *ul, uint32_t tid)
{
	struct mt_map	*mtm = ul->un_logmap;	/* Log map */
	mapentry_t	*me, **mep;
	int		i;

	ASSERT(((mtm->mtm_debug & MT_CHECK_MAP) == 0) ||
	    map_check_linkage(mtm));

	/*
	 * wait for any outstanding reads to finish; lock out future reads
	 */
	rw_enter(&mtm->mtm_rwlock, RW_WRITER);

	mutex_enter(&mtm->mtm_mutex);
	/* Take everything off cancel list */
	while ((me = mtm->mtm_cancel) != NULL) {
		mtm->mtm_cancel = me->me_cancel;
		me->me_flags &= ~ME_CANCEL;
		me->me_cancel = NULL;
	}

	/*
	 * Now take out all mapentries with current tid, and committid
	 * as this function is called from logmap_logscan and logmap_commit
	 * When it is called from logmap_logscan mtm_tid == mtm_committid
	 * But when logmap_abort is called from logmap_commit it is
	 * because the log errored when trying to write the commit record,
	 * after the async ops have been allowed to start in top_end_sync.
	 * So we also need to remove all mapentries from the transaction whose
	 * commit failed.
	 */
	for (i = 0; i < mtm->mtm_nhash; i++) {
		mep = &mtm->mtm_hash[i];
		while ((me = *mep) != NULL) {
			if (me->me_tid == tid ||
			    me->me_tid == mtm->mtm_committid) {
				*mep = me->me_hash;
				me->me_next->me_prev = me->me_prev;
				me->me_prev->me_next = me->me_next;
				if (!(me->me_flags & ME_USER)) {
					mtm->mtm_nme--;
				}
				CRB_RELE(me);
				kmem_cache_free(mapentry_cache, me);
				continue;
			}
			mep = &me->me_hash;
		}
	}

	if (!(ul->un_flags & LDL_SCAN))
		mtm->mtm_flags |= MTM_CANCELED;
	mutex_exit(&mtm->mtm_mutex);
	mtm->mtm_dirty = 0;
	mtm->mtm_nmet = 0;
	rw_exit(&mtm->mtm_rwlock);

	ASSERT(((mtm->mtm_debug & MT_CHECK_MAP) == 0) ||
	    map_check_linkage(mtm));
}

static void
logmap_wait_space(mt_map_t *mtm, ml_unit_t *ul, mapentry_t *me)
{
	ASSERT(MUTEX_HELD(&ul->un_log_mutex));

	while (!ldl_has_space(ul, me)) {
		ASSERT(!(ul->un_flags & LDL_NOROLL));
		mutex_exit(&ul->un_log_mutex);
		logmap_forceroll(mtm);
		mutex_enter(&ul->un_log_mutex);
		if (ul->un_flags & LDL_ERROR)
			break;
	}

	ASSERT(MUTEX_HELD(&ul->un_log_mutex));
}

/*
 * put a list of deltas into a logmap
 * If va == NULL, don't write to the log.
 */
void
logmap_add(
	ml_unit_t *ul,
	char *va,			/* Ptr to buf w/deltas & data */
	offset_t vamof,			/* Offset on master of buf start */
	mapentry_t *melist)		/* Entries to add */
{
	offset_t	mof;
	off_t		nb;
	mapentry_t	*me;
	mapentry_t	**mep;
	mapentry_t	**savmep;
	uint32_t	tid;
	mt_map_t	*mtm	= ul->un_logmap;

	mutex_enter(&ul->un_log_mutex);
	if (va)
		logmap_wait_space(mtm, ul, melist);

	ASSERT(((mtm->mtm_debug & MT_CHECK_MAP) == 0) ||
	    map_check_linkage(mtm));

	mtm->mtm_ref = 1;
	mtm->mtm_dirty++;
	tid = mtm->mtm_tid;
	while (melist) {
		mof = melist->me_mof;
		nb  = melist->me_nb;

		/*
		 * search for overlaping entries
		 */
		savmep = mep = MAP_HASH(mof, mtm);
		mutex_enter(&mtm->mtm_mutex);
		while ((me = *mep) != 0) {
			/*
			 * Data consumes old map entry; cancel map entry.
			 * Take care when we replace an old map entry
			 * which carries quota information with a newer entry
			 * which does not. In that case the push function
			 * would not be called to clean up the dquot structure.
			 * This would be found later by invalidatedq() causing
			 * a panic when the filesystem in unmounted.
			 * We clean up the dquot manually and then replace
			 * the map entry.
			 */
			if (MEwithinDATA(me, mof, nb) &&
			    ((me->me_flags & (ME_ROLL|ME_CANCEL)) == 0)) {
				if (tid == me->me_tid &&
				    ((me->me_flags & ME_AGE) == 0)) {
					*mep = me->me_hash;
					me->me_next->me_prev = me->me_prev;
					me->me_prev->me_next = me->me_next;
					ASSERT(!(me->me_flags & ME_USER));
					mtm->mtm_nme--;
					/*
					 * Special case if the mapentry
					 * carries a dquot and a push function.
					 * We have to clean up the quota info
					 * before replacing the mapentry.
					 */
					if (me->me_dt == DT_QR)
						HANDLE_DQUOT(me, melist);

					kmem_cache_free(mapentry_cache, me);
					continue;
				}
				me->me_cancel = mtm->mtm_cancel;
				mtm->mtm_cancel = me;
				me->me_flags |= ME_CANCEL;
			}
			mep = &(*mep)->me_hash;
		}
		mutex_exit(&mtm->mtm_mutex);

		/*
		 * remove from list
		 */
		me = melist;
		melist = melist->me_hash;
		me->me_flags &= ~ME_LIST;
		/*
		 * If va != NULL, put in the log.
		 */
		if (va)
			ldl_write(ul, va, vamof, me);
		if (ul->un_flags & LDL_ERROR) {
			kmem_cache_free(mapentry_cache, me);
			continue;
		}
		ASSERT((va == NULL) ||
		    ((mtm->mtm_debug & MT_LOG_WRITE_CHECK) == 0) ||
		    map_check_ldl_write(ul, va, vamof, me));

		/*
		 * put on hash
		 */
		mutex_enter(&mtm->mtm_mutex);
		me->me_hash = *savmep;
		*savmep = me;
		me->me_next = (mapentry_t *)mtm;
		me->me_prev = mtm->mtm_prev;
		mtm->mtm_prev->me_next = me;
		mtm->mtm_prev = me;
		me->me_flags |= ME_HASH;
		me->me_tid = tid;
		me->me_age = mtm->mtm_age++;
		mtm->mtm_nme++;
		mtm->mtm_nmet++;
		mutex_exit(&mtm->mtm_mutex);
	}

	ASSERT(((mtm->mtm_debug & MT_CHECK_MAP) == 0) ||
	    map_check_linkage(mtm));
	mutex_exit(&ul->un_log_mutex);
}

/*
 * Add the delta(s) into the log.
 * Create one cached roll buffer logmap entry, and reference count the
 * number of mapentries refering to it.
 * Cancel previous logmap entries.
 * logmap_add is tolerant of failure to allocate a cached roll buffer.
 */
void
logmap_add_buf(
	ml_unit_t *ul,
	char *va,			/* Ptr to buf w/deltas & data */
	offset_t bufmof,		/* Offset on master of buf start */
	mapentry_t *melist,		/* Entries to add */
	caddr_t	buf,			/* Buffer containing delta(s) */
	uint32_t bufsz)			/* Size of buf */
{
	offset_t	mof;
	offset_t	vamof = bufmof + (va - buf);
	off_t		nb;
	mapentry_t	*me;
	mapentry_t	**mep;
	mapentry_t	**savmep;
	uint32_t	tid;
	mt_map_t	*mtm	= ul->un_logmap;
	crb_t		*crb;
	crb_t		*crbsav = NULL;

	ASSERT((bufsz & DEV_BMASK) == 0);
	mutex_enter(&ul->un_log_mutex);
	logmap_wait_space(mtm, ul, melist);

	ASSERT(((mtm->mtm_debug & MT_CHECK_MAP) == 0) ||
	    map_check_linkage(mtm));

	mtm->mtm_ref = 1;
	mtm->mtm_dirty++;
	tid = mtm->mtm_tid;
	while (melist) {
		mof = melist->me_mof;
		nb  = melist->me_nb;

		/*
		 * search for overlapping entries
		 */
		savmep = mep = MAP_HASH(mof, mtm);
		mutex_enter(&mtm->mtm_mutex);
		while ((me = *mep) != 0) {
			/*
			 * Data consumes old map entry; cancel map entry.
			 * Take care when we replace an old map entry
			 * which carries quota information with a newer entry
			 * which does not. In that case the push function
			 * would not be called to clean up the dquot structure.
			 * This would be found later by invalidatedq() causing
			 * a panic when the filesystem in unmounted.
			 * We clean up the dquot manually and then replace
			 * the map entry.
			 */
			crb = me->me_crb;
			if (MEwithinDATA(me, mof, nb) &&
			    ((me->me_flags & (ME_ROLL|ME_CANCEL)) == 0)) {
				if (tid == me->me_tid &&
				    ((me->me_flags & ME_AGE) == 0)) {
					*mep = me->me_hash;
					me->me_next->me_prev = me->me_prev;
					me->me_prev->me_next = me->me_next;
					ASSERT(!(me->me_flags & ME_USER));
					mtm->mtm_nme--;
					/*
					 * Special case if the mapentry
					 * carries a dquot and a push function.
					 * We have to clean up the quota info
					 * before replacing the mapentry.
					 */
					if (me->me_dt == DT_QR)
						HANDLE_DQUOT(me, melist);

					/*
					 * If this soon to be deleted mapentry
					 * has a suitable roll buffer then
					 * re-use it.
					 */
					if (crb && (--crb->c_refcnt == 0)) {
						if (crbsav ||
						    (crb->c_nb != bufsz)) {
							CRB_FREE(crb, me);
						} else {
							bcopy(buf, crb->c_buf,
							    bufsz);
							crb->c_invalid = 0;
							crb->c_mof = bufmof;
							crbsav = crb;
							me->me_crb = NULL;
						}
					}
					kmem_cache_free(mapentry_cache, me);
					continue;
				}
				me->me_cancel = mtm->mtm_cancel;
				mtm->mtm_cancel = me;
				me->me_flags |= ME_CANCEL;
			}

			/*
			 * Inode deltas within the same fs block come
			 * in individually as separate calls to logmap_add().
			 * All others come in as one call. So check for an
			 * existing entry where we can re-use the crb.
			 */
			if ((me->me_dt == DT_INODE) && (tid == me->me_tid) &&
			    !crbsav && crb &&
			    WITHIN(mof, nb, crb->c_mof, crb->c_nb)) {
				ASSERT(crb->c_mof == bufmof);
				ASSERT(crb->c_nb == bufsz);
				bcopy(buf, crb->c_buf, bufsz);
				crbsav = crb;
			}
			mep = &(*mep)->me_hash;
		}
		mutex_exit(&mtm->mtm_mutex);

		/*
		 * If we don't already have a crb then allocate one
		 * and copy the incoming buffer. Only do this once
		 * for all the incoming deltas.
		 */
		if ((crbsav == NULL) && (melist->me_dt != DT_ABZERO)) {
			/*
			 * Only use a cached roll buffer if we
			 * have enough memory, and check for failures.
			 */
			if (((ufs_crb_size + bufsz) < ufs_crb_limit) &&
			    (kmem_avail() > bufsz)) {
				crbsav = kmem_alloc(sizeof (crb_t), KM_NOSLEEP);
			} else {
				ufs_crb_alloc_fails++;
			}
			if (crbsav) {
				crbsav->c_buf = kmem_alloc(bufsz, KM_NOSLEEP);
				if (crbsav->c_buf) {
					atomic_add_64(&ufs_crb_size,
					    (uint64_t)bufsz);
					if (ufs_crb_size > ufs_crb_max_size) {
						ufs_crb_max_size = ufs_crb_size;
					}
					bcopy(buf, crbsav->c_buf, bufsz);
					crbsav->c_nb = bufsz;
					crbsav->c_refcnt = 0;
					crbsav->c_invalid = 0;
					ASSERT((bufmof & DEV_BMASK) == 0);
					crbsav->c_mof = bufmof;
				} else {
					kmem_free(crbsav, sizeof (crb_t));
					crbsav = NULL;
				}
			}
		}

		/*
		 * remove from list
		 */
		me = melist;
		melist = melist->me_hash;
		me->me_flags &= ~ME_LIST;
		me->me_crb = crbsav;
		if (crbsav) {
			crbsav->c_refcnt++;
		}
		crbsav = NULL;

		ASSERT(va);
		ldl_write(ul, va, vamof, me); /* add to on-disk log */
		if (ul->un_flags & LDL_ERROR) {
			CRB_RELE(me);
			kmem_cache_free(mapentry_cache, me);
			continue;
		}
		ASSERT(((mtm->mtm_debug & MT_LOG_WRITE_CHECK) == 0) ||
		    map_check_ldl_write(ul, va, vamof, me));

		/*
		 * put on hash
		 */
		mutex_enter(&mtm->mtm_mutex);
		me->me_hash = *savmep;
		*savmep = me;
		me->me_next = (mapentry_t *)mtm;
		me->me_prev = mtm->mtm_prev;
		mtm->mtm_prev->me_next = me;
		mtm->mtm_prev = me;
		me->me_flags |= ME_HASH;
		me->me_tid = tid;
		me->me_age = mtm->mtm_age++;
		mtm->mtm_nme++;
		mtm->mtm_nmet++;
		mutex_exit(&mtm->mtm_mutex);
	}

	ASSERT(((mtm->mtm_debug & MT_CHECK_MAP) == 0) ||
	    map_check_linkage(mtm));
	mutex_exit(&ul->un_log_mutex);
}

/*
 * free up any cancelled deltas
 */
void
logmap_free_cancel(mt_map_t *mtm, mapentry_t **cancelhead)
{
	int		dolock	= 0;
	mapentry_t	*me;
	mapentry_t	**mep;

	ASSERT(((mtm->mtm_debug & MT_CHECK_MAP) == 0) ||
	    map_check_linkage(mtm));

again:
	if (dolock)
		rw_enter(&mtm->mtm_rwlock, RW_WRITER);

	/*
	 * At EOT, cancel the indicated deltas
	 */
	mutex_enter(&mtm->mtm_mutex);
	if (mtm->mtm_flags & MTM_CANCELED) {
		mtm->mtm_flags &= ~MTM_CANCELED;
		ASSERT(dolock == 0);
		mutex_exit(&mtm->mtm_mutex);
		return;
	}

	while ((me = *cancelhead) != NULL) {
		/*
		 * roll forward or read collision; wait and try again
		 */
		if (me->me_flags & ME_AGE) {
			ASSERT(dolock == 0);
			mutex_exit(&mtm->mtm_mutex);
			dolock = 1;
			goto again;
		}
		/*
		 * remove from cancel list
		 */
		*cancelhead = me->me_cancel;
		me->me_cancel = NULL;
		me->me_flags &= ~(ME_CANCEL);

		/*
		 * logmap_remove_roll handles ME_ROLL entries later
		 *	we leave them around for logmap_iscancel
		 *	XXX is this necessary?
		 */
		if (me->me_flags & ME_ROLL)
			continue;

		/*
		 * remove from hash (if necessary)
		 */
		if (me->me_flags & ME_HASH) {
			mep = MAP_HASH(me->me_mof, mtm);
			while (*mep) {
				if (*mep == me) {
					*mep = me->me_hash;
					me->me_next->me_prev = me->me_prev;
					me->me_prev->me_next = me->me_next;
					me->me_flags &= ~(ME_HASH);
					if (!(me->me_flags & ME_USER)) {
						mtm->mtm_nme--;
					}
					break;
				} else
					mep = &(*mep)->me_hash;
			}
		}
		/*
		 * put the entry on the free list
		 */
		CRB_RELE(me);
		kmem_cache_free(mapentry_cache, me);
	}
	mutex_exit(&mtm->mtm_mutex);
	if (dolock)
		rw_exit(&mtm->mtm_rwlock);

	ASSERT(((mtm->mtm_debug & MT_CHECK_MAP) == 0) ||
	    map_check_linkage(mtm));
}


void
logmap_commit(ml_unit_t *ul, uint32_t tid)
{
	mapentry_t	me;
	mt_map_t	*mtm	= ul->un_logmap;


	ASSERT(MUTEX_HELD(&ul->un_log_mutex));

	/*
	 * async'ly write a commit rec into the log
	 */
	if (mtm->mtm_dirty) {
		/*
		 * put commit record into log
		 */
		me.me_mof = mtm->mtm_tid;
		me.me_dt = DT_COMMIT;
		me.me_nb = 0;
		me.me_hash = NULL;
		logmap_wait_space(mtm, ul, &me);
		ldl_write(ul, NULL, (offset_t)0, &me);
		ldl_round_commit(ul);

		/*
		 * abort on error; else reset dirty flag
		 */
		if (ul->un_flags & LDL_ERROR)
			logmap_abort(ul, tid);
		else {
			mtm->mtm_dirty = 0;
			mtm->mtm_nmet = 0;
			mtm->mtm_cfrags = 0;
		}
		/* push commit */
		ldl_push_commit(ul);
	}
}

void
logmap_sethead(mt_map_t *mtm, ml_unit_t *ul)
{
	off_t		lof;
	uint32_t	tid;
	mapentry_t	*me;

	/*
	 * move the head forward so the log knows how full it is
	 * Make sure to skip any mapentry whose me_lof is 0, these
	 * are just place holders for DT_CANCELED freed user blocks
	 * for the current moby.
	 */
	mutex_enter(&ul->un_log_mutex);
	mutex_enter(&mtm->mtm_mutex);
	me = mtm->mtm_next;
	while (me != (mapentry_t *)mtm && me->me_lof == 0) {
		me = me->me_next;
	}

	if (me == (mapentry_t *)mtm)
		lof = -1;
	else {
		lof = me->me_lof;
		tid = me->me_tid;
	}
	mutex_exit(&mtm->mtm_mutex);
	ldl_sethead(ul, lof, tid);
	if (lof == -1)
		mtm->mtm_age = 0;
	mutex_exit(&ul->un_log_mutex);
}

void
logmap_settail(mt_map_t *mtm, ml_unit_t *ul)
{
	off_t		lof;
	size_t		nb;

	/*
	 * set the tail after the logmap_abort
	 */
	mutex_enter(&ul->un_log_mutex);
	mutex_enter(&mtm->mtm_mutex);
	if (mtm->mtm_prev == (mapentry_t *)mtm)
		lof = -1;
	else {
		/*
		 * set the tail to the end of the last commit
		 */
		lof = mtm->mtm_tail_lof;
		nb = mtm->mtm_tail_nb;
	}
	mutex_exit(&mtm->mtm_mutex);
	ldl_settail(ul, lof, nb);
	mutex_exit(&ul->un_log_mutex);
}

/*
 * when reseting a device; roll the log until every
 * delta has been rolled forward
 */
void
logmap_roll_dev(ml_unit_t *ul)
{
	mt_map_t	*mtm	= ul->un_logmap;
	mapentry_t	*me;
	ufsvfs_t	*ufsvfsp = ul->un_ufsvfs;

again:
	ASSERT(((mtm->mtm_debug & MT_CHECK_MAP) == 0) ||
	    map_check_linkage(mtm));
	if (ul->un_flags & (LDL_ERROR|LDL_NOROLL))
		return;

	/*
	 * look for deltas
	 */
	mutex_enter(&mtm->mtm_mutex);
	for (me = mtm->mtm_next; me != (mapentry_t *)mtm; me = me->me_next) {
		if (me->me_flags & ME_ROLL)
			break;
		if (me->me_tid == mtm->mtm_tid)
			continue;
		if (me->me_tid == mtm->mtm_committid)
			continue;
		break;
	}

	/*
	 * found a delta; kick the roll thread
	 * but only if the thread is running... (jmh)
	 */
	if (me != (mapentry_t *)mtm) {
		mutex_exit(&mtm->mtm_mutex);
		logmap_forceroll(mtm);
		goto again;
	}

	/*
	 * no more deltas, return
	 */
	mutex_exit(&mtm->mtm_mutex);
	(void) ufs_putsummaryinfo(ul->un_dev, ufsvfsp, ufsvfsp->vfs_fs);

	ASSERT(((mtm->mtm_debug & MT_CHECK_MAP) == 0) ||
	    map_check_linkage(mtm));
}

static void
logmap_cancel_delta(ml_unit_t *ul, offset_t mof, int32_t nb, int metadata)
{
	mapentry_t	*me;
	mapentry_t	**mep;
	mt_map_t	*mtm	= ul->un_logmap;
	int		frags;

	/*
	 * map has been referenced and is dirty
	 */
	mtm->mtm_ref = 1;
	mtm->mtm_dirty++;

	/*
	 * get a mapentry
	 */
	me = kmem_cache_alloc(mapentry_cache, KM_SLEEP);
	bzero(me, sizeof (mapentry_t));

	/*
	 * initialize cancel record and put in logmap
	 */
	me->me_mof = mof;
	me->me_nb = nb;
	me->me_dt = DT_CANCEL;
	me->me_tid = mtm->mtm_tid;
	me->me_hash = NULL;

	/*
	 * Write delta to log if this delta is for metadata.  If this is not
	 * metadata it is user data and we are just putting a cancel
	 * mapentry into the hash to cancel a user block deletion
	 * in which we do not want the block to be allocated
	 * within this moby.  This cancel entry will prevent the block from
	 * being allocated within the moby and prevent user data corruption
	 * if we happen to crash before this moby is committed.
	 */
	mutex_enter(&ul->un_log_mutex);
	if (metadata) {
		logmap_wait_space(mtm, ul, me);
		ldl_write(ul, NULL, (offset_t)0, me);
		if (ul->un_flags & LDL_ERROR) {
			kmem_cache_free(mapentry_cache, me);
			mutex_exit(&ul->un_log_mutex);
			return;
		}
	}

	/*
	 * put in hash and on cancel list
	 */
	mep = MAP_HASH(mof, mtm);
	mutex_enter(&mtm->mtm_mutex);
	me->me_age = mtm->mtm_age++;
	me->me_hash = *mep;
	*mep = me;
	me->me_next = (mapentry_t *)mtm;
	me->me_prev = mtm->mtm_prev;
	mtm->mtm_prev->me_next = me;
	mtm->mtm_prev = me;
	me->me_cancel = mtm->mtm_cancel;
	mtm->mtm_cancel = me;
	if (metadata) {
		mtm->mtm_nme++;
		mtm->mtm_nmet++;
	} else {
		me->me_flags = ME_USER;
	}
	me->me_flags |= (ME_HASH|ME_CANCEL);
	if (!(metadata)) {
		frags = blkoff(ul->un_ufsvfs->vfs_fs, nb);
		if (frags)
			mtm->mtm_cfrags +=
			    numfrags(ul->un_ufsvfs->vfs_fs, frags);
	}
	mutex_exit(&mtm->mtm_mutex);

	mutex_exit(&ul->un_log_mutex);
}

/*
 * cancel entries in a logmap (entries are freed at EOT)
 */
void
logmap_cancel(ml_unit_t *ul, offset_t mof, off_t nb, int metadata)
{
	int32_t		hnb;
	mapentry_t	*me;
	mapentry_t	**mep;
	mt_map_t	*mtm	= ul->un_logmap;
	crb_t		*crb;

	ASSERT(((mtm->mtm_debug & MT_CHECK_MAP) == 0) ||
	    map_check_linkage(mtm));

	for (hnb = 0; nb; nb -= hnb, mof += hnb) {
		hnb = MAPBLOCKSIZE - (mof & MAPBLOCKOFF);
		if (hnb > nb)
			hnb = nb;
		/*
		 * Find overlapping metadata entries.  Don't search through
		 * the hash chains if this is user data because it is only
		 * possible to have overlapping map entries for metadata,
		 * and the search can become expensive for large files.
		 */
		if (metadata) {
			mep = MAP_HASH(mof, mtm);
			mutex_enter(&mtm->mtm_mutex);
			for (me = *mep; me; me = me->me_hash) {
				if (!DATAoverlapME(mof, hnb, me))
					continue;

				ASSERT(MEwithinDATA(me, mof, hnb));

				if ((me->me_flags & ME_CANCEL) == 0) {
					me->me_cancel = mtm->mtm_cancel;
					mtm->mtm_cancel = me;
					me->me_flags |= ME_CANCEL;
					crb = me->me_crb;
					if (crb) {
						crb->c_invalid = 1;
					}
				}
			}
			mutex_exit(&mtm->mtm_mutex);
		}

		/*
		 * put a cancel record into the log
		 */
		logmap_cancel_delta(ul, mof, hnb, metadata);
	}

	ASSERT(((mtm->mtm_debug & MT_CHECK_MAP) == 0) ||
	    map_check_linkage(mtm));
}

/*
 * check for overlap w/cancel delta
 */
int
logmap_iscancel(mt_map_t *mtm, offset_t mof, off_t nb)
{
	off_t		hnb;
	mapentry_t	*me;
	mapentry_t	**mep;

	mutex_enter(&mtm->mtm_mutex);
	for (hnb = 0; nb; nb -= hnb, mof += hnb) {
		hnb = MAPBLOCKSIZE - (mof & MAPBLOCKOFF);
		if (hnb > nb)
			hnb = nb;
		/*
		 * search for dup entry
		 */
		mep = MAP_HASH(mof, mtm);
		for (me = *mep; me; me = me->me_hash) {
			if (((me->me_flags & ME_ROLL) == 0) &&
			    (me->me_dt != DT_CANCEL))
				continue;
			if (DATAoverlapME(mof, hnb, me))
				break;
		}

		/*
		 * overlap detected
		 */
		if (me) {
			mutex_exit(&mtm->mtm_mutex);
			return (1);
		}
	}
	mutex_exit(&mtm->mtm_mutex);
	return (0);
}

static int
logmap_logscan_add(ml_unit_t *ul, struct delta *dp, off_t lof, size_t *nbp)
{
	mapentry_t	*me;
	int		error;
	mt_map_t	*mtm	= ul->un_logmap;

	/*
	 * verify delta header; failure == mediafail
	 */
	error = 0;
	/* delta type */
	if ((dp->d_typ <= DT_NONE) || (dp->d_typ >= DT_MAX))
		error = EINVAL;
	if (dp->d_typ == DT_COMMIT) {
		if (dp->d_nb != INT32_C(0) && dp->d_nb != INT32_C(-1))
			error = EINVAL;
	} else {
		/* length of delta */
		if ((dp->d_nb < INT32_C(0)) ||
		    (dp->d_nb > INT32_C(MAPBLOCKSIZE)))
			error = EINVAL;

		/* offset on master device */
		if (dp->d_mof < INT64_C(0))
			error = EINVAL;
	}

	if (error) {
		ldl_seterror(ul, "Error processing ufs log data during scan");
		return (error);
	}

	/*
	 * process commit record
	 */
	if (dp->d_typ == DT_COMMIT) {
		if (mtm->mtm_dirty) {
			ASSERT(dp->d_nb == INT32_C(0));
			logmap_free_cancel(mtm, &mtm->mtm_cancel);
			mtm->mtm_dirty = 0;
			mtm->mtm_nmet = 0;
			mtm->mtm_tid++;
			mtm->mtm_committid = mtm->mtm_tid;
			ASSERT(((mtm->mtm_debug & MT_SCAN) == 0) ||
			    logmap_logscan_commit_debug(lof, mtm));
		}
		/*
		 * return #bytes to next sector (next delta header)
		 */
		*nbp = ldl_logscan_nbcommit(lof);
		mtm->mtm_tail_lof = lof;
		mtm->mtm_tail_nb = *nbp;
		return (0);
	}

	/*
	 * add delta to logmap
	 */
	me = kmem_cache_alloc(mapentry_cache, KM_SLEEP);
	bzero(me, sizeof (mapentry_t));
	me->me_lof = lof;
	me->me_mof = dp->d_mof;
	me->me_nb = dp->d_nb;
	me->me_tid = mtm->mtm_tid;
	me->me_dt = dp->d_typ;
	me->me_hash = NULL;
	me->me_flags = (ME_LIST | ME_SCAN);
	logmap_add(ul, NULL, 0, me);
	switch (dp->d_typ) {
	case DT_CANCEL:
		me->me_flags |= ME_CANCEL;
		me->me_cancel = mtm->mtm_cancel;
		mtm->mtm_cancel = me;
		break;
	default:
		ASSERT(((mtm->mtm_debug & MT_SCAN) == 0) ||
		    logmap_logscan_add_debug(dp, mtm));
		break;
	}

sizeofdelta:
	/*
	 * return #bytes till next delta header
	 */
	if ((dp->d_typ == DT_CANCEL) || (dp->d_typ == DT_ABZERO))
		*nbp = 0;
	else
		*nbp = dp->d_nb;
	return (0);
}

void
logmap_logscan(ml_unit_t *ul)
{
	size_t		nb, nbd;
	off_t		lof;
	struct delta	delta;
	mt_map_t	*logmap	= ul->un_logmap;

	ASSERT(ul->un_deltamap->mtm_next == (mapentry_t *)ul->un_deltamap);

	/*
	 * prepare the log for a logscan
	 */
	ldl_logscan_begin(ul);

	/*
	 * prepare the logmap for a logscan
	 */
	(void) map_free_entries(logmap);
	logmap->mtm_tid = 0;
	logmap->mtm_committid = UINT32_C(0);
	logmap->mtm_age = 0;
	logmap->mtm_dirty = 0;
	logmap->mtm_ref = 0;

	/*
	 * while not at end of log
	 *	read delta header
	 *	add to logmap
	 *	seek to beginning of next delta
	 */
	lof = ul->un_head_lof;
	nbd = sizeof (delta);
	while (lof != ul->un_tail_lof) {

		/* read delta header */
		if (ldl_logscan_read(ul, &lof, nbd, (caddr_t)&delta))
			break;

		/* add to logmap */
		if (logmap_logscan_add(ul, &delta, lof, &nb))
			break;

		/* seek to next header (skip data) */
		if (ldl_logscan_read(ul, &lof, nb, NULL))
			break;
	}

	/*
	 * remove the last partial transaction from the logmap
	 */
	logmap_abort(ul, logmap->mtm_tid);

	ldl_logscan_end(ul);
}

void
_init_map(void)
{
	/*
	 * Initialise the mapentry cache. No constructor or deconstructor
	 * is needed. Also no reclaim function is supplied as reclaiming
	 * current entries is not possible.
	 */
	mapentry_cache = kmem_cache_create("lufs_mapentry_cache",
	    sizeof (mapentry_t), 0, NULL, NULL, NULL, NULL, NULL, 0);
}

/*
 * Special case when we replace an old map entry which carries quota
 * information with a newer entry which does not.
 * In that case the push function would not be called to clean up the
 * dquot structure. This would be found later by invalidatedq() causing
 * a panic when the filesystem in unmounted.
 * We clean up the dquot manually before replacing the map entry.
 */
void
handle_dquot(mapentry_t *me)
{
	int dolock = 0;
	int domutex = 0;
	struct dquot *dqp;

	dqp = (struct dquot *)me->me_arg;

	/*
	 * We need vfs_dqrwlock to call dqput()
	 */
	dolock = (!RW_LOCK_HELD(&dqp->dq_ufsvfsp->vfs_dqrwlock));
	if (dolock)
		rw_enter(&dqp->dq_ufsvfsp->vfs_dqrwlock, RW_READER);

	domutex = (!MUTEX_HELD(&dqp->dq_lock));
	if (domutex)
		mutex_enter(&dqp->dq_lock);

	/*
	 * Only clean up if the dquot is referenced
	 */
	if (dqp->dq_cnt == 0) {
		if (domutex)
			mutex_exit(&dqp->dq_lock);
		if (dolock)
			rw_exit(&dqp->dq_ufsvfsp->vfs_dqrwlock);
		return;
	}

	dqp->dq_flags &= ~(DQ_MOD|DQ_TRANS);
	dqput(dqp);

	if (domutex)
		mutex_exit(&dqp->dq_lock);

	if (dolock)
		rw_exit(&dqp->dq_ufsvfsp->vfs_dqrwlock);

}
