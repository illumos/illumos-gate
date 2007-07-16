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
#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/systm.h>
#include <sys/types.h>
#include <sys/vnode.h>
#include <sys/buf.h>
#include <sys/ddi.h>
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


#ifdef	DEBUG

/*
 * DEBUG ROUTINES
 *	THESE ROUTINES ARE ONLY USED WHEN ASSERTS ARE ENABLED
 */

static	kmutex_t	toptracelock;
static	int		toptraceindex;
int			toptracemax	= 1024;	/* global so it can be set */
struct toptrace {
	enum delta_type	dtyp;
	kthread_t	*thread;
	dev_t		dev;
	long		arg2;
	long		arg3;
	long long	arg1;
} *toptrace;

static void
top_trace(enum delta_type dtyp, dev_t dev, long long arg1, long arg2, long arg3)
{
	if (toptrace == NULL) {
		toptraceindex = 0;
		toptrace = kmem_zalloc((size_t)
		    (sizeof (struct toptrace) * toptracemax), KM_SLEEP);
	}
	mutex_enter(&toptracelock);
	toptrace[toptraceindex].dtyp = dtyp;
	toptrace[toptraceindex].thread = curthread;
	toptrace[toptraceindex].dev = dev;
	toptrace[toptraceindex].arg1 = arg1;
	toptrace[toptraceindex].arg2 = arg2;
	toptrace[toptraceindex].arg3 = arg3;
	if (++toptraceindex == toptracemax)
		toptraceindex = 0;
	else {
		toptrace[toptraceindex].dtyp = (enum delta_type)-1;
		toptrace[toptraceindex].thread = (kthread_t *)-1;
		toptrace[toptraceindex].dev = (dev_t)-1;
		toptrace[toptraceindex].arg1 = -1;
		toptrace[toptraceindex].arg2 = -1;
	}

	mutex_exit(&toptracelock);
}

/*
 * add a range into the metadata map
 */
void
top_mataadd(ufsvfs_t *ufsvfsp, offset_t mof, off_t nb)
{
	ml_unit_t	*ul	= ufsvfsp->vfs_log;

	ASSERT(ufsvfsp->vfs_dev == ul->un_dev);
	deltamap_add(ul->un_matamap, mof, nb, 0, 0, 0, NULL);
}

/*
 * delete a range from the metadata map
 */
void
top_matadel(ufsvfs_t *ufsvfsp, offset_t mof, off_t nb)
{
	ml_unit_t	*ul	= ufsvfsp->vfs_log;

	ASSERT(ufsvfsp->vfs_dev == ul->un_dev);
	ASSERT(!matamap_overlap(ul->un_deltamap, mof, nb));
	deltamap_del(ul->un_matamap, mof, nb);
}

/*
 * clear the entries from the metadata map
 */
void
top_mataclr(ufsvfs_t *ufsvfsp)
{
	ml_unit_t	*ul	= ufsvfsp->vfs_log;

	ASSERT(ufsvfsp->vfs_dev == ul->un_dev);
	map_free_entries(ul->un_matamap);
	map_free_entries(ul->un_deltamap);
}

int
top_begin_debug(ml_unit_t *ul, top_t topid, ulong_t size)
{
	threadtrans_t *tp;

	if (ul->un_debug & MT_TRACE)
		top_trace(DT_BOT, ul->un_dev,
		    (long long)topid, (long)size, (long)0);

	ASSERT(curthread->t_flag & T_DONTBLOCK);

	tp = tsd_get(topkey);
	if (tp == NULL) {
		tp = kmem_zalloc(sizeof (threadtrans_t), KM_SLEEP);
		(void) tsd_set(topkey, tp);
	}
	tp->topid  = topid;
	tp->esize  = size;
	tp->rsize  = 0;
	tp->dev    = ul->un_dev;
	return (1);
}

int
top_end_debug(ml_unit_t *ul, mt_map_t *mtm, top_t topid, ulong_t size)
{
	threadtrans_t *tp;

	ASSERT(curthread->t_flag & T_DONTBLOCK);

	ASSERT((tp = (threadtrans_t *)tsd_get(topkey)) != NULL);

	ASSERT((tp->dev == ul->un_dev) && (tp->topid == topid) &&
	    (tp->esize == size));

	ASSERT(((ul->un_debug & MT_SIZE) == 0) || (tp->rsize <= tp->esize));

	mtm->mtm_tops->mtm_top_num[topid]++;
	mtm->mtm_tops->mtm_top_size_etot[topid] += tp->esize;
	mtm->mtm_tops->mtm_top_size_rtot[topid] += tp->rsize;

	if (tp->rsize > mtm->mtm_tops->mtm_top_size_max[topid])
		mtm->mtm_tops->mtm_top_size_max[topid] = tp->rsize;
	if (mtm->mtm_tops->mtm_top_size_min[topid] == 0)
			mtm->mtm_tops->mtm_top_size_min[topid] =
			    tp->rsize;
	else
		if (tp->rsize < mtm->mtm_tops->mtm_top_size_min[topid])
			mtm->mtm_tops->mtm_top_size_min[topid] =
			    tp->rsize;

	if (ul->un_debug & MT_TRACE)
		top_trace(DT_EOT, ul->un_dev, (long long)topid,
		    (long)tp->rsize, (long)0);

	return (1);
}

int
top_delta_debug(
	ml_unit_t *ul,
	offset_t mof,
	off_t nb,
	delta_t dtyp)
{
	struct threadtrans	*tp;

	ASSERT(curthread->t_flag & T_DONTBLOCK);

	/*
	 * check for delta contained fully within matamap
	 */
	ASSERT((ul->un_matamap == NULL) ||
	    matamap_within(ul->un_matamap, mof, nb));

	/*
	 * maintain transaction info
	 */
	if (ul->un_debug & MT_TRANSACT)
		ul->un_logmap->mtm_tops->mtm_delta_num[dtyp]++;

	/*
	 * check transaction stuff
	 */
	if (ul->un_debug & MT_TRANSACT) {
		tp = (struct threadtrans *)tsd_get(topkey);
		ASSERT(tp);
		switch (dtyp) {
		case DT_CANCEL:
		case DT_ABZERO:
			if (!matamap_within(ul->un_deltamap, mof, nb))
				tp->rsize += sizeof (struct delta);
			break;
		default:
			if (!matamap_within(ul->un_deltamap, mof, nb))
				tp->rsize += nb + sizeof (struct delta);
			break;
		}
	} else
		return (1);

	if (ul->un_debug & MT_TRACE)
		top_trace(dtyp, ul->un_dev, mof, (long)nb, (long)0);

	return (1);
}

int
top_roll_debug(ml_unit_t *ul)
{
	logmap_roll_dev(ul);
	return (1);
}

int
top_init_debug(void)
{
	mutex_init(&toptracelock, NULL, MUTEX_DEFAULT, NULL);
	return (1);
}

struct topstats_link {
	struct topstats_link	*ts_next;
	dev_t			ts_dev;
	struct topstats		ts_stats;
};
struct topstats_link *topstats_anchor = NULL;

/*
 * DEBUG ROUTINES
 *	from debug portion of *_map.c
 */
/*
 * scan test support
 */
int
logmap_logscan_debug(mt_map_t *mtm, mapentry_t *age)
{
	mapentry_t	*me;
	ml_unit_t	*ul;
	off_t		head, trimroll, lof;

	/*
	 * remember location of youngest rolled delta
	 */
	mutex_enter(&mtm->mtm_mutex);
	ul = mtm->mtm_ul;
	head = ul->un_head_lof;
	trimroll = mtm->mtm_trimrlof;
	for (me = age; me; me = me->me_agenext) {
		lof = me->me_lof;
		if (trimroll == 0)
			trimroll = lof;
		if (lof >= head) {
			if (trimroll >= head && trimroll <= lof)
				trimroll = lof;
		} else {
			if (trimroll <= lof || trimroll >= head)
				trimroll = lof;
		}
	}
	mtm->mtm_trimrlof = trimroll;
	mutex_exit(&mtm->mtm_mutex);
	return (1);
}

/*
 * scan test support
 */
int
logmap_logscan_commit_debug(off_t lof, mt_map_t *mtm)
{
	off_t	oldtrimc, newtrimc, trimroll;

	trimroll = mtm->mtm_trimrlof;
	oldtrimc = mtm->mtm_trimclof;
	newtrimc = mtm->mtm_trimclof = dbtob(btod(lof));

	/*
	 * can't trim prior to transaction w/rolled delta
	 */
	if (trimroll)
		if (newtrimc >= oldtrimc) {
			if (trimroll <= newtrimc && trimroll >= oldtrimc)
				mtm->mtm_trimalof = newtrimc;
		} else {
			if (trimroll >= oldtrimc || trimroll <= newtrimc)
				mtm->mtm_trimalof = newtrimc;
		}
	return (1);
}

int
logmap_logscan_add_debug(struct delta *dp, mt_map_t *mtm)
{
	if ((dp->d_typ == DT_AB) || (dp->d_typ == DT_INODE))
		mtm->mtm_trimalof = mtm->mtm_trimclof;
	return (1);
}

/*
 * log-read after log-write
 */
int
map_check_ldl_write(ml_unit_t *ul, caddr_t va, offset_t vamof, mapentry_t *me)
{
	caddr_t		bufp;

	ASSERT(me->me_nb);
	ASSERT((me->me_flags & ME_AGE) == 0);

	/* Alloc a buf */
	bufp = kmem_alloc(me->me_nb, KM_SLEEP);

	/* Do the read */
	me->me_agenext = NULL;
	if (ldl_read(ul, bufp, me->me_mof, me->me_nb, me) == 0) {
		ASSERT(bcmp(bufp, va + (me->me_mof - vamof), me->me_nb) == 0);
	}

	kmem_free(bufp, me->me_nb);
	return (1);
}

/*
 * Cleanup a map struct
 */
int
map_put_debug(mt_map_t *mtm)
{
	struct topstats_link	*tsl, **ptsl;

	if (mtm->mtm_tops == NULL)
		return (1);

	/* Don't free this, cause the next snarf will want it */
	if ((lufs_debug & MT_TRANSACT) != 0)
		return (1);

	ptsl = &topstats_anchor;
	tsl = topstats_anchor;
	while (tsl) {
		if (mtm->mtm_tops == &tsl->ts_stats) {
			mtm->mtm_tops = NULL;
			*ptsl = tsl->ts_next;
			kmem_free(tsl, sizeof (*tsl));
			return (1);
		}
		ptsl = &tsl->ts_next;
		tsl = tsl->ts_next;
	}

	return (1);
}

int
map_get_debug(ml_unit_t *ul, mt_map_t *mtm)
{
	struct topstats_link	*tsl;

	if ((ul->un_debug & MT_TRANSACT) == 0)
		return (1);

	if (mtm->mtm_type != logmaptype)
		return (1);

	tsl = topstats_anchor;
	while (tsl) {
		if (tsl->ts_dev == ul->un_dev) {
			mtm->mtm_tops = &(tsl->ts_stats);
			return (1);
		}
		tsl = tsl->ts_next;
	}

	tsl = kmem_zalloc(sizeof (*tsl), KM_SLEEP);
	tsl->ts_dev = ul->un_dev;
	tsl->ts_next = topstats_anchor;
	topstats_anchor = tsl;
	mtm->mtm_tops = &tsl->ts_stats;
	return (1);
}

/*
 * check a map's list
 */
int
map_check_linkage(mt_map_t *mtm)
{
	int		i;
	int		hashed;
	int		nexted;
	int		preved;
	int		ncancel;
	mapentry_t	*me;
	off_t		olof;
	off_t		firstlof;
	int		wrapped;

	mutex_enter(&mtm->mtm_mutex);

	ASSERT(mtm->mtm_nme >= 0);

	/*
	 * verify the entries on the hash
	 */
	hashed = 0;
	for (i = 0; i < mtm->mtm_nhash; ++i) {
		for (me = *(mtm->mtm_hash+i); me; me = me->me_hash) {
			++hashed;
			ASSERT(me->me_flags & ME_HASH);
			ASSERT((me->me_flags & ME_LIST) == 0);
		}
	}
	ASSERT(hashed >= mtm->mtm_nme);
	/*
	 * verify the doubly linked list of all entries
	 */
	nexted = 0;
	for (me = mtm->mtm_next; me != (mapentry_t *)mtm; me = me->me_next)
		nexted++;
	preved = 0;
	for (me = mtm->mtm_prev; me != (mapentry_t *)mtm; me = me->me_prev)
		preved++;
	ASSERT(nexted == preved);
	ASSERT(nexted == hashed);

	/*
	 * verify the cancel list
	 */
	ncancel = 0;
	for (me = mtm->mtm_cancel; me; me = me->me_cancel) {
		++ncancel;
		ASSERT(me->me_flags & ME_CANCEL);
	}
	/*
	 * verify the logmap's log offsets
	 */
	if (mtm->mtm_type == logmaptype) {
		olof = mtm->mtm_next->me_lof;
		firstlof = olof;
		wrapped = 0;
		/*
		 * Make sure to skip any mapentries whose me_lof = 0
		 * and me_type == DT_CANCEL, these are mapentries
		 * in place just to mark user block deletions as not
		 * available for allocate within the same moby transaction
		 * in case we crash before it is comitted.  Skip these
		 * entries in the checks below as they are not applicable.
		 */
		for (me = mtm->mtm_next->me_next;
		    me != (mapentry_t *)mtm;
		    me = me->me_next) {

			if (me->me_lof == 0 && me->me_dt == DT_CANCEL)
				continue;
			if (firstlof == 0) {
				olof = me->me_lof;
				firstlof = olof;
				if (me->me_next != (mapentry_t *)mtm)
					me = me->me_next;
				continue;
			}
			ASSERT(me->me_lof != olof);

			if (wrapped) {
				ASSERT(me->me_lof > olof);
				ASSERT(me->me_lof < firstlof);
				olof = me->me_lof;
				continue;
			}
			if (me->me_lof < olof) {
				ASSERT(me->me_lof < firstlof);
				wrapped = 1;
				olof = me->me_lof;
				continue;
			}
			ASSERT(me->me_lof > firstlof);
			ASSERT(me->me_lof < mtm->mtm_ul->un_eol_lof);
			olof = me->me_lof;
		}
	}

	mutex_exit(&mtm->mtm_mutex);
	return (1);
}

/*
 * check for overlap
 */
int
matamap_overlap(mt_map_t *mtm, offset_t mof, off_t nb)
{
	off_t		hnb;
	mapentry_t	*me;
	mapentry_t	**mep;

	for (hnb = 0; nb; nb -= hnb, mof += hnb) {

		hnb = MAPBLOCKSIZE - (mof & MAPBLOCKOFF);
		if (hnb > nb)
			hnb = nb;
		/*
		 * search for dup entry
		 */
		mep = MAP_HASH(mof, mtm);
		mutex_enter(&mtm->mtm_mutex);
		for (me = *mep; me; me = me->me_hash)
			if (DATAoverlapME(mof, hnb, me))
				break;
		mutex_exit(&mtm->mtm_mutex);

		/*
		 * overlap detected
		 */
		if (me)
			return (1);
	}
	return (0);
}
/*
 * check for within
 */
int
matamap_within(mt_map_t *mtm, offset_t mof, off_t nb)
{
	off_t		hnb;
	mapentry_t	*me;
	mapentry_t	**mep;
	int		scans	= 0;
	int		withins	= 0;

	for (hnb = 0; nb && scans == withins; nb -= hnb, mof += hnb) {
		scans++;

		hnb = MAPBLOCKSIZE - (mof & MAPBLOCKOFF);
		if (hnb > nb)
			hnb = nb;
		/*
		 * search for within entry
		 */
		mep = MAP_HASH(mof, mtm);
		mutex_enter(&mtm->mtm_mutex);
		for (me = *mep; me; me = me->me_hash)
			if (DATAwithinME(mof, hnb, me)) {
				withins++;
				break;
			}
		mutex_exit(&mtm->mtm_mutex);
	}
	return (scans == withins);
}

int
ldl_sethead_debug(ml_unit_t *ul)
{
	mt_map_t	*mtm	= ul->un_logmap;
	off_t		trimr	= mtm->mtm_trimrlof;
	off_t		head	= ul->un_head_lof;
	off_t		tail	= ul->un_tail_lof;

	if (head <= tail) {
		if (trimr < head || trimr >= tail)
			mtm->mtm_trimrlof = 0;
	} else {
		if (trimr >= tail && trimr < head)
			mtm->mtm_trimrlof = 0;
	}
	return (1);
}

int
lufs_initialize_debug(ml_odunit_t *ud)
{
	ud->od_debug = lufs_debug;
	return (1);
}

#endif	/* DEBUG */

/*
 * lufs_debug controls the debug level for TSufs, and is only used
 * for a debug kernel. It's referenced by ufs_ioctl() and so is
 * not under #ifdef DEBUG compilation.
 */
uint_t lufs_debug;
