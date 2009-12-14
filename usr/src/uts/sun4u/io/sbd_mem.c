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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * memory support routines for sbd.
 */

#include <sys/debug.h>
#include <sys/types.h>
#include <sys/errno.h>
#include <sys/param.h>
#include <sys/dditypes.h>
#include <sys/kmem.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/ddi_impldefs.h>
#include <sys/sysmacros.h>
#include <sys/machsystm.h>
#include <sys/spitregs.h>
#include <sys/cpuvar.h>
#include <sys/cpu_module.h>
#include <sys/promif.h>
#include <sys/memlist_impl.h>
#include <sys/mem_cage.h>
#include <sys/lgrp.h>
#include <sys/platform_module.h>
#include <vm/seg_kmem.h>

#include <sys/sbdpriv.h>

#define	_ptob64(p) ((uint64_t)(p) << PAGESHIFT)
#define	_b64top(b) ((pgcnt_t)((b) >> PAGESHIFT))

static int		sbd_post_detach_mem_unit(sbd_mem_unit_t *mp,
				sbderror_t *ep);
static int		sbd_reserve_mem_spans(memhandle_t *mhp,
					struct memlist *mlist);
static int		sbd_check_boundaries(struct memlist *orig_memlist,
					sbd_mem_unit_t *s_mp,
					sbd_mem_unit_t *t_mp);
static int		sbd_select_mem_target(sbd_handle_t *hp,
				sbd_mem_unit_t *mp, struct memlist *ml);
static void		sbd_init_mem_unit_data(sbd_mem_unit_t *mp, sbderror_t
					*ep);
static int		memlist_canfit(struct memlist *s_mlist,
					struct memlist *t_mlist);
static void		sbd_mem_cleanup(sbd_mem_unit_t *s_mp,
				sbd_mem_unit_t *t_mp, sbderror_t *ep);
static void		sbd_flush_ecache(uint64_t a, uint64_t b);

struct memlist *
sbd_get_memlist(sbd_mem_unit_t *mp, sbderror_t *ep)
{
	struct memlist	*mlist;
	static fn_t	f = "sbd_get_memlist";
	sbd_board_t 	*sbp = (sbd_board_t *)mp->sbm_cm.sbdev_sbp;
	sbdp_handle_t	*hdp;
	sbd_handle_t	*hp = MACHBD2HD(sbp);

	PR_MEM("%s...\n", f);

	/*
	 * Return cached memlist, if present.
	 * This memlist will be present following an
	 * unconfigure (a.k.a: detach) of this memunit.
	 * It should only be used in the case were a configure
	 * is bringing this memunit back in without going
	 * through the disconnect and connect states.
	 */
	if (mp->sbm_mlist) {
		PR_MEM("%s: found cached memlist\n", f);

		mlist = memlist_dup(mp->sbm_mlist);
	} else {
		/* attempt to construct a memlist using phys_install */

		/*
		 * NOTE: this code block assumes only one memunit per
		 * board.  This is currently safe because the function
		 * sbd_init_mem_devlist() forces this assumption to be
		 * valid.
		 */

		/* round down to slice base address */
		/* build mlist from the lower layer */
		hdp = sbd_get_sbdp_handle(sbp, hp);
		mlist = sbdp_get_memlist(hdp, mp->sbm_cm.sbdev_dip);
		if (mlist == NULL) {
			SBD_GET_PERR(hdp->h_err, ep);
			PR_MEM("sbd:%s: failed to get memlist for "
				"dip (0x%p) ecode %d errno %d", f,
				(void *)mp->sbm_cm.sbdev_dip,
				ep->e_code, ep->e_errno);
			sbd_release_sbdp_handle(hdp);
			return (NULL);
		}
		sbd_release_sbdp_handle(hdp);
	}

	PR_MEM("%s: memlist for mem-unit (%d.%d), dip 0x%p:\n",
		f, sbp->sb_num,
		mp->sbm_cm.sbdev_unum,
		(void *)mp->sbm_cm.sbdev_dip);
	SBD_MEMLIST_DUMP(mlist);

	return (mlist);
}

int
sbd_pre_attach_mem(sbd_handle_t *hp, sbd_devlist_t devlist[], int devnum)
{
	int		err_flag = 0;
	sbderror_t	*ep = SBD_HD2ERR(hp);
	sbd_board_t	*sbp = SBDH2BD(hp->h_sbd);
	int		d, i;
	sbdp_handle_t	*hdp;
	static fn_t	f = "sbd_pre_attach_mem";

	PR_MEM("%s...\n", f);

	SBD_SET_ERR(ep, 0);
	hdp = sbd_get_sbdp_handle(sbp, hp);

	for (d = 0; d < devnum; d++) {
		sbd_mem_unit_t	*mp;
		int		unit;
		dev_info_t	*dip;
		sbd_istate_t	state;
		int		rv;

		/* sbd_get_devlist will not devlist element w/ dip of 0 */
		ASSERT(devlist[d].dv_dip != NULL);

		dip = devlist[d].dv_dip;
		unit = sbdp_get_unit_num(hdp, dip);
		if (unit == -1) {
			if (hp->h_flags & SBD_IOCTL_FLAG_FORCE)
				continue;
			else {
				SBD_GET_PERR(hdp->h_err, ep);
				err_flag = 1;
				break;
			}
		}

		mp = SBD_GET_BOARD_MEMUNIT(sbp, unit);

		ASSERT(mp->sbm_cm.sbdev_sbp == sbp);
		ASSERT(unit == mp->sbm_cm.sbdev_unum);

		PR_MEM("sbd: OS attach mem-unit (%d.%d)\n",
			sbp->sb_num,
			mp->sbm_cm.sbdev_unum);

		state = mp->sbm_cm.sbdev_state;
		switch (state) {
		case SBD_STATE_UNCONFIGURED:
			/* use memlist cached by sbd_post_detach_mem_unit */
			if (mp->sbm_mlist != NULL) {
				PR_MEM("%s: recovering from UNCONFIG"
					" mem-unit (%d.%d)\n",
					f, sbp->sb_num,
					mp->sbm_cm.sbdev_unum);

				PR_MEM("%s: re-configure cached memlist:\n", f);
				SBD_MEMLIST_DUMP(mp->sbm_mlist);

				/*
				 * kphysm del handle should have been freed
				 */
				ASSERT((mp->sbm_flags & SBD_MFLAG_RELOWNER)
					== 0);
			} else {
				if (hp->h_flags & SBD_IOCTL_FLAG_FORCE)
					continue;
				else {
					SBD_GET_PERR(hdp->h_err, ep);
					err_flag = 1;
					PR_MEM("%s: mem-unit (%d.%d)"
						" unusable\n",
						f, sbp->sb_num,
						mp->sbm_cm.sbdev_unum);
					break;
				}
			}

			/*FALLTHROUGH*/

		case SBD_STATE_CONNECTED:
			PR_MEM("%s: reprogramming mem hardware (board %d)\n",
				f, sbp->sb_num);

			for (i = 0; i < SBD_NUM_MC_PER_BOARD; i++) {
				if (mp->sbm_dip[i] == NULL)
					continue;
				dip = mp->sbm_dip[i];

				PR_MEM("%s: enabling mc 0x%p on board %d\n",
					f, (void *)dip, sbp->sb_num);

				rv = sbdphw_enable_memctrl(hdp, dip);
				if (rv < 0) {
					SBD_GET_PERR(hdp->h_err, ep);
					cmn_err(CE_WARN,
					"%s: failed to program mem ctrlr %p on "
					"board %d", f, (void *)mp->sbm_dip[i],
					sbp->sb_num);
					err_flag = 1;
				}
			}
			break;

		default:
			cmn_err(CE_WARN,
				"%s: unexpected state (%d) for mem-unit "
				"(%d.%d)", f, state, sbp->sb_num,
				mp->sbm_cm.sbdev_unum);
			if (SBD_GET_ERR(ep) == 0) {
				SBD_SET_ERR(ep, ESBD_STATE);
				err_flag = 1;
			}
			break;
		}

		/* exit for loop if error encountered */
		if (err_flag) {
			SBD_SET_ERRSTR(ep,
			    sbp->sb_mempath[mp->sbm_cm.sbdev_unum]);
			break;
		}
	}
	sbd_release_sbdp_handle(hdp);

	return (err_flag ? -1 : 0);
}

int
sbd_post_attach_mem(sbd_handle_t *hp, sbd_devlist_t devlist[], int devnum)
{
	int		d;
	sbdp_handle_t	*hdp;
	sbd_board_t	*sbp = SBDH2BD(hp->h_sbd);
	sbderror_t	*ep = SBD_HD2ERR(hp);
	static fn_t	f = "sbd_post_attach_mem";

	PR_MEM("%s...\n", f);
	hdp = sbd_get_sbdp_handle(sbp, hp);

	for (d = 0; d < devnum; d++) {
		sbd_mem_unit_t	*mp;
		dev_info_t	*dip;
		int		unit;
		struct memlist	*mlist, *ml;

		/* sbd_get_devlist will not devlist element w/ dip of 0 */
		ASSERT(devlist[d].dv_dip != NULL);

		dip = devlist[d].dv_dip;
		unit = sbdp_get_unit_num(hdp, dip);
		if (unit == -1) {
			if (hp->h_flags & SBD_IOCTL_FLAG_FORCE)
				continue;
			else {
				SBD_GET_PERR(hdp->h_err, ep);
				break;
			}
		}

		mp = SBD_GET_BOARD_MEMUNIT(sbp, unit);

		mlist = sbd_get_memlist(mp, ep);
		if (mlist == NULL) {
			cmn_err(CE_WARN,
				"%s: no memlist for mem-unit (%d.%d)",
				f,
				sbp->sb_num,
				mp->sbm_cm.sbdev_unum);

			if (SBD_GET_ERR(ep) == 0) {
				SBD_SET_ERR(ep, ESBD_MEMFAIL);
				SBD_SET_ERRSTR(ep, sbp->sb_mempath[unit]);
			}

			continue;
		}

		/*
		 * Verify the memory really did successfully attach
		 * by checking for its existence in phys_install.
		 */

		memlist_read_lock();
		if (memlist_intersect(phys_install, mlist) == 0) {
			memlist_read_unlock();

			cmn_err(CE_WARN,
				"%s: mem-unit (%d.%d) memlist not in"
				" phys_install", f, sbp->sb_num,
				mp->sbm_cm.sbdev_unum);

			if (SBD_GET_ERR(ep) == 0) {
				SBD_SET_ERR(ep, ESBD_INTERNAL);
				SBD_SET_ERRSTR(ep, sbp->sb_mempath[unit]);
			}

			memlist_delete(mlist);
			continue;
		}
		memlist_read_unlock();

		for (ml = mlist; ml != NULL; ml = ml->next) {
			(void) sbdp_mem_add_span(hdp, ml->address, ml->size);
		}

		memlist_delete(mlist);

		/*
		 * Destroy cached memlist, if any.
		 * There will be a cached memlist in sbm_mlist if
		 * this board is being configured directly after
		 * an unconfigure.
		 * To support this transition, sbd_post_detach_mem
		 * left a copy of the last known memlist in sbm_mlist.
		 * This memlist could differ from any derived from
		 * hardware if while this memunit was last configured
		 * the system detected and deleted bad pages from
		 * phys_install.  The location of those bad pages
		 * will be reflected in the cached memlist.
		 */
		if (mp->sbm_mlist) {
			memlist_delete(mp->sbm_mlist);
			mp->sbm_mlist = NULL;
		}
		sbd_init_mem_unit_data(mp, ep);
	}

	sbd_release_sbdp_handle(hdp);
	return (0);
}

int
sbd_pre_detach_mem(sbd_handle_t *hp, sbd_devlist_t devlist[], int devnum)
{
	int		d;
	int		unit;
	sbdp_handle_t	*hdp;
	sbderror_t	*ep = SBD_HD2ERR(hp);
	sbd_board_t	*sbp = SBDH2BD(hp->h_sbd);
	dev_info_t	*dip;

	hdp = sbd_get_sbdp_handle(sbp, hp);

	for (d = 0; d < devnum; d++) {
		sbd_mem_unit_t *mp;

		/* sbd_get_devlist will not devlist element w/ dip of 0 */
		ASSERT(devlist[d].dv_dip != NULL);

		dip = devlist[d].dv_dip;
		unit = sbdp_get_unit_num(hdp, dip);
		if (unit == -1) {
			if (hp->h_flags & SBD_IOCTL_FLAG_FORCE)
				continue;
			else {
				SBD_GET_PERR(hdp->h_err, ep);
				sbd_release_sbdp_handle(hdp);
				return (-1);
			}
		}

		mp = SBD_GET_BOARD_MEMUNIT(sbp, unit);

		/* sanity check */
		ASSERT(mp->sbm_cm.sbdev_sbp == sbp);
		ASSERT(unit == mp->sbm_cm.sbdev_unum);

		PR_MEM("sbd: OS detach mem-unit (%d.%d)\n",
			sbp->sb_num, mp->sbm_cm.sbdev_unum);
	}

	sbd_release_sbdp_handle(hdp);
	return (0);
}

int
sbd_post_detach_mem(sbd_handle_t *hp, sbd_devlist_t devlist[], int devnum)
{
	int		d, rv;
	sbdp_handle_t	*hdp;
	sbd_board_t	*sbp;
	sbd_mem_unit_t	*s_mp, *t_mp;
	static fn_t	f = "sbd_post_detach_mem";

	PR_MEM("%s...\n", f);

	sbp = SBDH2BD(hp->h_sbd);

	hdp = sbd_get_sbdp_handle(sbp, hp);


	rv = 0;
	for (d = 0; d < devnum; d++) {
		sbderror_t	*ep;
		dev_info_t	*dip;
		int		unit;

		/* sbd_get_devlist will not devlist element w/ dip of 0 */
		ASSERT(devlist[d].dv_dip != NULL);

		ep = &devlist[d].dv_error;
		if ((SBD_GET_ERR(SBD_HD2ERR(hp)) != 0) ||
		    (sbd_set_err_in_hdl(hp, ep) == 0)) {
			rv = -1;
		}

		dip = devlist[d].dv_dip;
		unit = sbdp_get_unit_num(hdp, dip);
		if (unit == -1) {
			if (hp->h_flags & SBD_IOCTL_FLAG_FORCE)
				continue;
			else {
				if (rv != -1)
					SBD_GET_PERR(hdp->h_err, ep);
				break;
			}
		}

		s_mp = SBD_GET_BOARD_MEMUNIT(sbp, unit);

		ASSERT(s_mp->sbm_cm.sbdev_sbp == sbp);

		if (rv == -1) {
			if (s_mp->sbm_flags & SBD_MFLAG_SOURCE) {
				t_mp = s_mp->sbm_peer;
			} else {
				/* this is no target unit */
				t_mp = NULL;
			}

			sbd_mem_cleanup(s_mp, t_mp, ep);
		} else if (sbd_post_detach_mem_unit(s_mp, ep))
			rv = -1;
	}

	sbd_release_sbdp_handle(hdp);
	return (rv);
}

static void
sbd_add_memory_spans(sbd_board_t *sbp, struct memlist *ml)
{
	sbdp_handle_t	*hdp;
	static fn_t	f = "sbd_add_memory_spans";

	PR_MEM("%s...", f);
	SBD_MEMLIST_DUMP(ml);

#ifdef DEBUG
	memlist_read_lock();
	if (memlist_intersect(phys_install, ml)) {
		PR_MEM("%s:WARNING: memlist intersects with phys_install\n", f);
	}
	memlist_read_unlock();
#endif
	hdp = sbd_get_sbdp_handle(NULL, NULL);

	for (; ml; ml = ml->next) {
		update_membounds_t umb;
		pfn_t	base;
		pgcnt_t	npgs;
		int	rv;

		base = _b64top(ml->address);
		npgs = _b64top(ml->size);

		umb.u_board = sbp->sb_num;
		umb.u_base = (uint64_t)base << MMU_PAGESHIFT;
		umb.u_len = (uint64_t)npgs << MMU_PAGESHIFT;

		lgrp_plat_config(LGRP_CONFIG_MEM_ADD, (uintptr_t)&umb);
		rv = kphysm_add_memory_dynamic(base, npgs);

		(void) sbdp_mem_add_span(hdp, ml->address, ml->size);

		if (rv != KPHYSM_OK) {
			cmn_err(CE_WARN, "sbd:%s:"
				" unexpected kphysm_add_memory_dynamic"
				" return value %d;"
				" basepfn=0x%lx, npages=%ld\n",
				f, rv, base, npgs);

			continue;
		}
		rv = kcage_range_add(base, npgs, KCAGE_DOWN);
		if (rv != 0)
			continue;
	}
	sbd_release_sbdp_handle(hdp);
}

/* hack for test scripts.  *** remove before code finalized *** */
int sbd_last_target;

static int
sbd_post_detach_mem_unit(sbd_mem_unit_t *s_mp, sbderror_t *ep)
{
	uint64_t	sz;
	uint64_t	sm;
	uint64_t	t_basepa;
	uint64_t	tmp_basepa;
	uint64_t	s_basepa;
	sbd_board_t 	*sbp;
	sbdp_handle_t	*hdp;
	uint64_t	s_nbytes;
	uint64_t	s_new_basepa;
	sbd_mem_unit_t	*t_mp, *x_mp;
	struct memlist	*ml;
	int		rv;
	static fn_t	f = "sbd_post_detach_mem_unit";
	sbd_handle_t	*hp;

	PR_MEM("%s...\n", f);

	sbp = (sbd_board_t *)s_mp->sbm_cm.sbdev_sbp;
	hp = MACHBD2HD(sbp);
	hdp = sbd_get_sbdp_handle(sbp, hp);

	if (sbdp_get_mem_alignment(hdp, s_mp->sbm_cm.sbdev_dip, &sz)) {
		cmn_err(CE_WARN,
			"sbd:%s: no alignment for mem-unit (%d.%d)",
			f, sbp->sb_num, s_mp->sbm_cm.sbdev_unum);
		SBD_GET_PERR(hdp->h_err, ep);
		sbd_release_sbdp_handle(hdp);
		return (-1);
	}
	sm = sz - 1;

	/* s_mp->sbm_del_mlist could be NULL, meaning no deleted spans */
	PR_MEM("%s: brd %d: deleted memlist (EMPTY maybe okay):\n",
		f, sbp->sb_num);
	SBD_MEMLIST_DUMP(s_mp->sbm_del_mlist);

	/* sanity check */
	ASSERT(s_mp->sbm_del_mlist == NULL ||
		(s_mp->sbm_flags & SBD_MFLAG_RELDONE) != 0);

	if (s_mp->sbm_flags & SBD_MFLAG_SOURCE) {
		t_mp = s_mp->sbm_peer;

		ASSERT(t_mp != NULL);
		ASSERT(t_mp->sbm_flags & SBD_MFLAG_TARGET);
		ASSERT(t_mp->sbm_peer == s_mp);

		ASSERT(t_mp->sbm_flags & SBD_MFLAG_RELDONE);
		ASSERT(t_mp->sbm_del_mlist);

		sbp = (sbd_board_t *)t_mp->sbm_cm.sbdev_sbp;
		PR_MEM("%s: target brd %d: deleted memlist:\n",
			f, sbp->sb_num);
		SBD_MEMLIST_DUMP(t_mp->sbm_del_mlist);
	} else {
		/* this is no target unit */
		t_mp = NULL;
	}

	/*
	 * Verify the memory really did successfully detach
	 * by checking for its non-existence in phys_install.
	 */
	rv = 0;
	memlist_read_lock();
	if (s_mp->sbm_flags & SBD_MFLAG_RELDONE) {
		x_mp = s_mp;
		rv = memlist_intersect(phys_install, x_mp->sbm_del_mlist);
	}
	if (rv == 0 && t_mp && (t_mp->sbm_flags & SBD_MFLAG_RELDONE)) {
		x_mp = t_mp;
		rv = memlist_intersect(phys_install, x_mp->sbm_del_mlist);
	}
	memlist_read_unlock();

	if (rv) {
		sbp = (sbd_board_t *)x_mp->sbm_cm.sbdev_sbp;

		cmn_err(CE_WARN,
			"%s: %smem-unit (%d.%d) memlist still in phys_install",
			f,
			x_mp == t_mp ? "target " : "",
			sbp->sb_num,
			x_mp->sbm_cm.sbdev_unum);
		SBD_SET_ERR(ep, ESBD_INTERNAL);
		SBD_SET_ERRSTR(ep, sbp->sb_mempath[x_mp->sbm_cm.sbdev_unum]);
		sbd_release_sbdp_handle(hdp);
		return (-1);
	}

	s_basepa	= _ptob64(s_mp->sbm_basepfn);
	s_nbytes	= _ptob64(s_mp->sbm_npages);

	if (t_mp != NULL) {
		t_basepa	= _ptob64(t_mp->sbm_basepfn);
		s_new_basepa	= (s_basepa & ~ sm) +
					_ptob64(t_mp->sbm_slice_offset);

		/*
		 * We had to swap mem-units, so update
		 * memlists accordingly with new base
		 * addresses.
		 */
		for (ml = t_mp->sbm_mlist; ml; ml = ml->next) {
			ml->address -= t_basepa;
			ml->address += s_new_basepa;
		}

		/*
		 * There is no need to explicitly rename the target delete
		 * memlist, because sbm_del_mlist and sbm_mlist always
		 * point to the same memlist for a copy/rename operation.
		 */
		ASSERT(t_mp->sbm_del_mlist == t_mp->sbm_mlist);

		PR_MEM("%s: renamed target memlist and delete memlist", f);
		SBD_MEMLIST_DUMP(t_mp->sbm_mlist);

		for (ml = s_mp->sbm_mlist; ml; ml = ml->next) {
			ml->address -= s_basepa;
			ml->address += t_basepa;
		}

		PR_MEM("%s: renamed source memlist", f);
		SBD_MEMLIST_DUMP(s_mp->sbm_mlist);

#ifdef DEBUG
		ASSERT(s_mp->sbm_mlist != s_mp->sbm_del_mlist);
		/*
		 * Renaming s_mp->sbm_del_mlist is not necessary.  This
		 * list is not used beyond this point, and in fact, is
		 *  disposed of at the end of this function.
		 */
		for (ml = s_mp->sbm_del_mlist; ml; ml = ml->next) {
			ml->address -= s_basepa;
			ml->address += t_basepa;
		}

		PR_MEM("%s: renamed source delete memlist", f);
		SBD_MEMLIST_DUMP(s_mp->sbm_del_mlist);
#endif

		if (s_mp->sbm_flags & SBD_MFLAG_MEMUPSIZE) {
			struct memlist	*nl;
			int mlret;

			/*
			 * We had to perform a copy-rename from a
			 * small memory node to a big memory node.
			 * Need to add back the remaining memory on
			 * the big board that wasn't used by that
			 * from the small board during the copy.
			 * Subtract out the portion of the target memory
			 * node that was taken over by the source memory
			 * node.
			 */
			nl = memlist_dup(t_mp->sbm_mlist);
			mlret = memlist_delete_span(s_basepa, s_nbytes, &nl);
			PR_MEM("%s: mlret = %d\n", f, mlret);

			sbp = (sbd_board_t *)t_mp->sbm_cm.sbdev_sbp;
			PR_MEM("%s: adding back remaining portion"
				" of mem-unit (%d.%d), memlist:\n",
				f, sbp->sb_num,
				t_mp->sbm_cm.sbdev_unum);

			SBD_MEMLIST_DUMP(nl);

			sbd_add_memory_spans(sbp, nl);

			memlist_delete(nl);
		}
	}


	if (t_mp != NULL) {
		sbp = (sbd_board_t *)t_mp->sbm_cm.sbdev_sbp;
		hdp->h_board = sbp->sb_num;
		/* delete target's entire address space */
		tmp_basepa = t_basepa & ~ sm;
		rv = sbdp_mem_del_span(hdp, tmp_basepa, sz);
		ASSERT(rv == 0);

		sbp = (sbd_board_t *)s_mp->sbm_cm.sbdev_sbp;
		hdp->h_board = sbp->sb_num;
		tmp_basepa = s_basepa & ~ sm;
		sz = s_new_basepa & sm;
		/* delete source board's vacant address space */
		rv = sbdp_mem_del_span(hdp, tmp_basepa, sz);
		ASSERT(rv == 0);
	} else {
		sbp = (sbd_board_t *)s_mp->sbm_cm.sbdev_sbp;
		hdp->h_board = sbp->sb_num;
		tmp_basepa = s_basepa & ~ sm;
		/* delete board's entire address space */
		rv = sbdp_mem_del_span(hdp, tmp_basepa, sz);
		ASSERT(rv == 0);
	}

#ifdef LINT
	rv = rv;
#endif

	sbd_mem_cleanup(s_mp, t_mp, ep);

	sbp = (sbd_board_t *)s_mp->sbm_cm.sbdev_sbp;
	PR_MEM("%s: board %d's memlist:", f, sbp->sb_num);
	SBD_MEMLIST_DUMP(s_mp->sbm_mlist);

	sbd_release_sbdp_handle(hdp);
	return (0);
}

static void
sbd_mem_cleanup(sbd_mem_unit_t *s_mp, sbd_mem_unit_t *t_mp, sbderror_t *ep)
{
	sbd_board_t *sbp;

	/* clean up target mem unit */
	if (t_mp != NULL) {
		sbp = (sbd_board_t *)t_mp->sbm_cm.sbdev_sbp;

		ASSERT(t_mp->sbm_del_mlist == t_mp->sbm_mlist);
		/*
		 * sbm_del_mlist and sbm_mlist point at the same list
		 * We only need to delete one and then set both pointers
		 * to NULL
		 */
		memlist_delete(t_mp->sbm_del_mlist);

		t_mp->sbm_del_mlist = NULL;
		t_mp->sbm_mlist = NULL;
		t_mp->sbm_peer = NULL;
		t_mp->sbm_flags = 0;
		t_mp->sbm_cm.sbdev_busy = 0;
		sbd_init_mem_unit_data(t_mp, ep);

		/*
		 * now that copy/rename has completed, undo this
		 * work that was done in sbd_release_mem_done.
		 */
		/*
		 * If error don't set the target to configured
		 */
		if (SBD_GET_ERR(ep) == 0) {
			SBD_DEV_CLR_UNREFERENCED(sbp, SBD_COMP_MEM, 0);
			SBD_DEV_CLR_RELEASED(sbp, SBD_COMP_MEM, 0);
			SBD_DEVICE_TRANSITION(sbp, SBD_COMP_MEM, 0,
				SBD_STATE_CONFIGURED);
		}

/* hack for test scripts.  *** remove before code finalized *** */
sbd_last_target = sbp->sb_num;
	}

	/*
	 * clean up (source) board's mem unit structure.
	 * NOTE: sbm_mlist is retained.  It is referred to as the
	 * cached memlist.  The cached memlist is used to re-attach
	 * (configure back in) this memunit from the unconfigured
	 * state.
	 */
	if (s_mp != NULL) {
		sbp = (sbd_board_t *)s_mp->sbm_cm.sbdev_sbp;

		/*
		 * Don't want to call memlist_delete for sbm_del_mlist,
		 * since that list points to the sbm_list
		 */
		s_mp->sbm_del_mlist = NULL;
		s_mp->sbm_peer = NULL;
		s_mp->sbm_flags = 0;
		s_mp->sbm_cm.sbdev_busy = 0;
		sbd_init_mem_unit_data(s_mp, ep);
	}
}

/*
 * Successful return from this function will have the memory
 * handle in sbp->sb_dev[..mem-unit...].sbm_memhandle allocated
 * and waiting.  This routine's job is to select the memory that
 * actually has to be released (detached) which may not necessarily
 * be the same memory node that came in in devlist[],
 * i.e. a copy-rename is needed.
 */
int
sbd_pre_release_mem(sbd_handle_t *hp, sbd_devlist_t devlist[], int devnum)
{
	extern int	kcage_on;
	int		d;
	int		err_flag = 0;
	sbd_board_t	*sbp = SBDH2BD(hp->h_sbd);
	sbderror_t	*ep = SBD_HD2ERR(hp);
	sbderror_t	*lep;
	static fn_t	f = "sbd_pre_release_mem";

	PR_MEM("%s...\n", f);

	if (kcage_on == 0) {
		/*
		 * Can't Detach memory if Cage is OFF.
		 */
		cmn_err(CE_WARN, "%s: kernel cage is disabled", f);
		SBD_SET_ERR(ep, ESBD_KCAGE_OFF);
		return (-1);
	}

	for (d = 0; d < devnum; d++) {
		int		rv;
		memquery_t	mq;
		sbd_mem_unit_t	*mp;
		struct memlist	*ml;

		/* sbd_get_devlist will not devlist element w/ dip of 0 */
		ASSERT(devlist[d].dv_dip != NULL);

		mp = SBD_GET_BOARD_MEMUNIT(sbp, d);

		/*
		 * If all the mem unit is marked as failed then don't allow the
		 * operation
		 */
		if (mp->sbm_cm.sbdev_cond == SBD_COND_FAILED) {
			SBD_SET_ERR(ep, ESBD_STATE);
			SBD_SET_ERRSTR(ep, sbp->sb_mempath[d]);
			err_flag = -1;
			break;
		}

		ASSERT(d == mp->sbm_cm.sbdev_unum);

		/*
		 * if interleave is set to across boards fail the op
		 */
		if (mp->sbm_interleave) {
			SBD_SET_ERR(ep, ESBD_MEMINTLV);
			SBD_SET_ERRSTR(ep, sbp->sb_mempath[d]);
			err_flag = -1;
			break;
		}

		lep = &devlist[d].dv_error;
		if (SBD_GET_ERR(lep) != 0) {
			err_flag = -1;
			(void) sbd_set_err_in_hdl(hp, lep);
			break;
		}

		if (mp->sbm_flags & SBD_MFLAG_RESERVED) {
			/*
			 * Board is currently involved in a delete
			 * memory operation. Can't detach this guy until
			 * that operation completes.
			 */
			cmn_err(CE_WARN,
				"%s: ineligible mem-unit (%d.%d) for detach",
				f, sbp->sb_num,
				mp->sbm_cm.sbdev_unum);

			SBD_SET_ERR(lep, ESBD_INVAL);
			SBD_SET_ERRSTR(lep, sbp->sb_mempath[d]);
			(void) sbd_set_err_in_hdl(hp, lep);
			err_flag = -1;
			break;
		}

		/*
		 * Check whether the detaching memory requires a
		 * copy-rename.
		 */
		ASSERT(mp->sbm_npages != 0);
		rv = kphysm_del_span_query(
			mp->sbm_basepfn, mp->sbm_npages, &mq);
		if (rv != KPHYSM_OK) {
			cmn_err(CE_WARN,
				"%s: unexpected kphysm_del_span_query"
				" return value %d;"
				" basepfn 0x%lx, npages 0x%lx,"
				" mem-unit (%d.%d), dip 0x%p",
				f,
				rv,
				mp->sbm_basepfn,
				mp->sbm_npages,
				sbp->sb_num,
				mp->sbm_cm.sbdev_unum,
				(void *)mp->sbm_cm.sbdev_dip);

			SBD_SET_ERR(lep, ESBD_INTERNAL);
			SBD_SET_ERRSTR(lep, sbp->sb_mempath[d]);
			(void) sbd_set_err_in_hdl(hp, lep);
			err_flag = -1;
			break;
		}

		if (mq.nonrelocatable != 0) {
			if (!(hp->h_iap->i_flags & SBD_FLAG_QUIESCE_OKAY)) {
				/* caller wasn't prompted for a suspend */
					SBD_SET_ERR(lep, ESBD_QUIESCE_REQD);
					SBD_SET_ERRSTR(lep, sbp->sb_mempath[d]);
					(void) sbd_set_err_in_hdl(hp, lep);
					err_flag = 1;
					break;
			}
		}

		/* flags should be clean at this time */
		ASSERT(mp->sbm_flags == 0);

		ASSERT(mp->sbm_del_mlist == NULL);	/* should be null */

		if (mp->sbm_mlist != NULL) {
			memlist_delete(mp->sbm_mlist);
			mp->sbm_mlist = NULL;
		}

		ml = sbd_get_memlist(mp, lep);
		(void) sbd_set_err_in_hdl(hp, lep);
		if (ml == NULL) {
			PR_MEM("%s: no memlist found for board %d\n",
				f, sbp->sb_num);
			err_flag = -1;
			break;
		}

		/* allocate a kphysm handle */
		rv = kphysm_del_gethandle(&mp->sbm_memhandle);
		if (rv != KPHYSM_OK) {
			memlist_delete(ml);

			cmn_err(CE_WARN,
				"%s: unexpected kphysm_del_gethandle"
				" return value %d", f, rv);

			SBD_SET_ERR(lep, ESBD_INTERNAL);
			SBD_SET_ERRSTR(lep, sbp->sb_mempath[d]);
			(void) sbd_set_err_in_hdl(hp, lep);
			err_flag = -1;
			break;
		}
		mp->sbm_flags |= SBD_MFLAG_RELOWNER;

		if ((mq.nonrelocatable != 0) ||
			sbd_reserve_mem_spans(&mp->sbm_memhandle, ml)) {
			/*
			 * Either the detaching memory node contains
			 * non-reloc memory or we failed to reserve the
			 * detaching memory node (which did _not_ have
			 * any non-reloc memory, i.e. some non-reloc mem
			 * got onboard).
			 */

			if (sbd_select_mem_target(hp, mp, ml)) {
				int rv;

				/*
				 * We had no luck locating a target
				 * memory node to be the recipient of
				 * the non-reloc memory on the node
				 * we're trying to detach.
				 * Clean up be disposing the mem handle
				 * and the mem list.
				 */
				rv = kphysm_del_release(mp->sbm_memhandle);
				if (rv != KPHYSM_OK) {
					/*
					 * can do nothing but complain
					 * and hope helpful for debug
					 */
					cmn_err(CE_WARN, "sbd:%s: unexpected"
						" kphysm_del_release return"
						" value %d",
						f, rv);
				}
				mp->sbm_flags &= ~SBD_MFLAG_RELOWNER;

				memlist_delete(ml);

				/* make sure sbm_flags is clean */
				ASSERT(mp->sbm_flags == 0);

				cmn_err(CE_WARN,
					"%s: no available target for "
					"mem-unit (%d.%d)",
					f, sbp->sb_num,
					mp->sbm_cm.sbdev_unum);

				SBD_SET_ERR(lep, ESBD_NO_TARGET);
				SBD_SET_ERRSTR(lep,
					sbp->sb_mempath[mp->sbm_cm.sbdev_unum]);
				(void) sbd_set_err_in_hdl(hp, lep);

				err_flag = -1;
				break;
			}

			/*
			 * ml is not memlist_deleted here because
			 * it has been assigned to mp->sbm_mlist
			 * by sbd_select_mem_target.
			 */
		} else {
			/* no target needed to detach this board */
			mp->sbm_flags |= SBD_MFLAG_RESERVED;
			mp->sbm_peer = NULL;
			mp->sbm_del_mlist = ml;
			mp->sbm_mlist = ml;
			mp->sbm_cm.sbdev_busy = 1;
		}
#ifdef DEBUG
		ASSERT(mp->sbm_mlist != NULL);

		if (mp->sbm_flags & SBD_MFLAG_SOURCE) {
			int src, targ;

			sbp = (sbd_board_t *)
				mp->sbm_peer->sbm_cm.sbdev_sbp;
			targ = sbp->sb_num;
			sbp = (sbd_board_t *)mp->sbm_cm.sbdev_sbp;
			src = sbp->sb_num;
			PR_MEM("%s: release of board %d requires copy/rename;"
				" selected target board %d\n",
				f, src, targ);
		} else {
			sbp = (sbd_board_t *)mp->sbm_cm.sbdev_sbp;
			PR_MEM("%s: copy/rename not required to release"
				" board %d\n", f, sbp->sb_num);
		}

		ASSERT(mp->sbm_flags & SBD_MFLAG_RELOWNER);
		ASSERT(mp->sbm_flags & SBD_MFLAG_RESERVED);
#endif
	}

	return (err_flag);
}

void
sbd_release_mem_done(sbd_handle_t *hp, int unit)
{
	sbd_mem_unit_t	*s_mp, *t_mp, *mp;
	sbderror_t	*ep = SBD_HD2ERR(hp);
	sbd_board_t	*sbp = SBDH2BD(hp->h_sbd);
	int		rv;
	static fn_t	f = "sbd_release_mem_done";

	s_mp = SBD_GET_BOARD_MEMUNIT(sbp, unit);
	sbp = (sbd_board_t *)s_mp->sbm_cm.sbdev_sbp;

	/*
	 * This unit will be flagged with SBD_MFLAG_SOURCE, if it
	 * has a target unit.
	 */
	if (s_mp->sbm_flags & SBD_MFLAG_SOURCE) {
		t_mp = s_mp->sbm_peer;
		ASSERT(t_mp != NULL);
		ASSERT(t_mp->sbm_peer == s_mp);
		ASSERT(t_mp->sbm_flags & SBD_MFLAG_TARGET);
		ASSERT(t_mp->sbm_flags & SBD_MFLAG_RESERVED);
	} else {
		/* this is no target unit */
		t_mp = NULL;
	}

	/* free delete handle */
	ASSERT(s_mp->sbm_flags & SBD_MFLAG_RELOWNER);
	ASSERT(s_mp->sbm_flags & SBD_MFLAG_RESERVED);

	rv = kphysm_del_release(s_mp->sbm_memhandle);
	if (rv != KPHYSM_OK) {
		/*
		 * can do nothing but complain
		 * and hope helpful for debug
		 */
		cmn_err(CE_WARN, "sbd:%s: unexpected kphysm_del_release"
			" return value %d", f, rv);
	}
	s_mp->sbm_flags &= ~SBD_MFLAG_RELOWNER;

	/*
	 * If an error was encountered during release, clean up
	 * the source (and target, if present) unit data.
	 */
	if (SBD_GET_ERR(ep) != 0) {

		PR_MEM("%s: unit %d.%d: error %d noted\n",
			f, sbp->sb_num,
			s_mp->sbm_cm.sbdev_unum,
			SBD_GET_ERR(ep));

		sbd_mem_cleanup(s_mp, t_mp, ep);

		/* bail out */
		return;
	}

	SBD_DEV_SET_RELEASED(sbp, SBD_COMP_MEM, unit);
	SBD_DEVICE_TRANSITION(sbp, SBD_COMP_MEM, unit, SBD_STATE_RELEASE);

	if (t_mp != NULL) {
		sbp = (sbd_board_t *)t_mp->sbm_cm.sbdev_sbp;
		/*
		 * the kphysm delete operation that drained the source
		 * board also drained this target board.  Since the source
		 * board drain is now known to have succeeded, we know this
		 * target board is drained too.
		 */
		SBD_DEV_SET_RELEASED(sbp, SBD_COMP_MEM,
			t_mp->sbm_cm.sbdev_unum);
		SBD_DEVICE_TRANSITION(sbp, SBD_COMP_MEM,
			t_mp->sbm_cm.sbdev_unum,
			SBD_STATE_RELEASE);

		/*
		 * NOTE: do not transition target's board state,
		 * even if the mem-unit was the last configure
		 * unit of the board.  When copy/rename completes
		 * this mem-unit will transitioned back to
		 * the configured state.  In the meantime, the
		 * board's must remain as is.
		 */
	}

	/* if board(s) had deleted memory, verify it is gone */
	rv = 0;
	memlist_read_lock();
	if (s_mp->sbm_del_mlist != NULL) {
		sbp = (sbd_board_t *)s_mp->sbm_cm.sbdev_sbp;
		mp = s_mp;
		rv = memlist_intersect(phys_install, mp->sbm_del_mlist);
	}
	if (rv == 0 && t_mp && t_mp->sbm_del_mlist != NULL) {
		sbp = (sbd_board_t *)t_mp->sbm_cm.sbdev_sbp;
		mp = t_mp;
		rv = memlist_intersect(phys_install, mp->sbm_del_mlist);
	}
	memlist_read_unlock();
	if (rv) {
		cmn_err(CE_WARN, "sbd:%s: %smem-unit (%d.%d): "
			"deleted memory still found in phys_install",
			f,
			(mp == t_mp ? "target " : ""),
			sbp->sb_num,
			mp->sbm_cm.sbdev_unum);

		SBD_SET_ERR(ep, ESBD_INTERNAL);
		SBD_SET_ERRSTR(ep, sbp->sb_mempath[mp->sbm_cm.sbdev_unum]);
		return;
	}

	s_mp->sbm_flags |= SBD_MFLAG_RELDONE;
	if (t_mp != NULL) {
		t_mp->sbm_flags &= ~SBD_MFLAG_RESERVED;
		t_mp->sbm_flags |= SBD_MFLAG_RELDONE;
	}

	sbp = (sbd_board_t *)s_mp->sbm_cm.sbdev_sbp;

	SBD_DEV_SET_UNREFERENCED(sbp, SBD_COMP_MEM, unit);
	SBD_DEVICE_TRANSITION(sbp, SBD_COMP_MEM, unit, SBD_STATE_UNREFERENCED);

	PR_MEM("%s: marking mem-unit (%d.%d) release DONE\n",
		f, sbp->sb_num,
		s_mp->sbm_cm.sbdev_unum);

	s_mp->sbm_cm.sbdev_ostate = SBD_STAT_UNCONFIGURED;

	if (t_mp != NULL) {
		sbp = (sbd_board_t *)t_mp->sbm_cm.sbdev_sbp;

		SBD_DEV_SET_UNREFERENCED(sbp, SBD_COMP_MEM,
			t_mp->sbm_cm.sbdev_unum);
		SBD_DEVICE_TRANSITION(sbp, SBD_COMP_MEM,
			t_mp->sbm_cm.sbdev_unum,
			SBD_STATE_UNREFERENCED);

		sbp = (sbd_board_t *)s_mp->sbm_cm.sbdev_sbp;

		PR_MEM("%s: marking mem-unit (%d.%d) release DONE\n",
			f, sbp->sb_num,
			t_mp->sbm_cm.sbdev_unum);

		t_mp->sbm_cm.sbdev_ostate = SBD_STAT_UNCONFIGURED;
	}
}

int
sbd_disconnect_mem(sbd_handle_t *hp, int unit)
{
	static fn_t	f = "sbd_disconnect_mem";
	sbd_mem_unit_t	*mp;
	sbd_board_t	*sbp = SBDH2BD(hp->h_sbd);

	mp = SBD_GET_BOARD_MEMUNIT(sbp, unit);

	ASSERT(mp->sbm_cm.sbdev_state == SBD_STATE_CONNECTED ||
	    mp->sbm_cm.sbdev_state == SBD_STATE_UNCONFIGURED);

	PR_MEM("%s...\n", f);

	if (mp->sbm_del_mlist && mp->sbm_del_mlist != mp->sbm_mlist)
		memlist_delete(mp->sbm_del_mlist);
	mp->sbm_del_mlist = NULL;

	if (mp->sbm_mlist) {
		memlist_delete(mp->sbm_mlist);
		mp->sbm_mlist = NULL;
	}

	return (0);
}

int
sbd_cancel_mem(sbd_handle_t *hp, int unit)
{
	sbd_mem_unit_t	*s_mp, *t_mp;
	sbd_istate_t	state;
	sbd_board_t	*sbp = SBDH2BD(hp->h_sbd);
	sbd_board_t	*tsbp;
	static fn_t	f = "sbd_cancel_mem";
	sbderror_t	*ep = SBD_HD2ERR(hp);

	s_mp = SBD_GET_BOARD_MEMUNIT(sbp, unit);

	state = s_mp->sbm_cm.sbdev_state;

	if (s_mp->sbm_flags & SBD_MFLAG_TARGET) {
		/* must cancel source board, not target board */
		SBD_SET_ERR(ep, ESBD_INTERNAL);
		SBD_SET_ERRSTR(ep, sbp->sb_mempath[unit]);
		return (-1);
	} else if (s_mp->sbm_flags & SBD_MFLAG_SOURCE) {
		t_mp = s_mp->sbm_peer;
		tsbp = t_mp->sbm_cm.sbdev_sbp;
		ASSERT(t_mp != NULL);
		ASSERT(t_mp->sbm_peer == s_mp);

		/* must always match the source board's state */
		ASSERT(t_mp->sbm_cm.sbdev_state == state);
	} else {
		/* this is no target unit */
		t_mp = NULL;
	}

	switch (state) {
	case SBD_STATE_UNREFERENCED:	/* state set by sbd_release_mem_done */
		ASSERT((s_mp->sbm_flags & SBD_MFLAG_RELOWNER) == 0);

		if (t_mp != NULL && t_mp->sbm_del_mlist != NULL) {
			PR_MEM("%s: undoing target board %d memory delete\n",
				f, tsbp->sb_num);
			sbd_add_memory_spans(tsbp, t_mp->sbm_del_mlist);
			SBD_DEV_CLR_UNREFERENCED(tsbp, SBD_COMP_MEM,
				t_mp->sbm_cm.sbdev_unum);
		}

		if (s_mp->sbm_del_mlist != NULL) {
			PR_MEM("%s: undoing board %d memory delete\n",
				f, sbp->sb_num);
			sbd_add_memory_spans(sbp, s_mp->sbm_del_mlist);
		}

		/*FALLTHROUGH*/

	case SBD_STATE_CONFIGURED:
		/*
		 * we got here because of an error early in the release process
		 * Just leave the memory as is and report the error
		 */

		ASSERT((s_mp->sbm_flags & SBD_MFLAG_RELOWNER) == 0);

		if (t_mp != NULL) {
			ASSERT(t_mp->sbm_del_mlist == t_mp->sbm_mlist);
			t_mp->sbm_del_mlist = NULL;

			if (t_mp->sbm_mlist != NULL) {
				memlist_delete(t_mp->sbm_mlist);
				t_mp->sbm_mlist = NULL;
			}

			t_mp->sbm_peer = NULL;
			t_mp->sbm_flags = 0;
			t_mp->sbm_cm.sbdev_busy = 0;
			sbd_init_mem_unit_data(t_mp, ep);

			SBD_DEV_CLR_RELEASED(tsbp, SBD_COMP_MEM,
				t_mp->sbm_cm.sbdev_unum);

			SBD_DEVICE_TRANSITION(tsbp, SBD_COMP_MEM,
				t_mp->sbm_cm.sbdev_unum,
				SBD_STATE_CONFIGURED);
		}

		if (s_mp->sbm_del_mlist != s_mp->sbm_mlist)
			memlist_delete(s_mp->sbm_del_mlist);
		s_mp->sbm_del_mlist = NULL;

		if (s_mp->sbm_mlist != NULL) {
			memlist_delete(s_mp->sbm_mlist);
			s_mp->sbm_mlist = NULL;
		}

		s_mp->sbm_peer = NULL;
		s_mp->sbm_flags = 0;
		s_mp->sbm_cm.sbdev_busy = 0;
		sbd_init_mem_unit_data(s_mp, ep);

		return (0);
	default:
		PR_MEM("%s: WARNING unexpected state (%d) for "
			"mem-unit %d.%d\n",
			f,
			(int)state,
			sbp->sb_num,
			s_mp->sbm_cm.sbdev_unum);

		return (-1);
	}
	/*NOTREACHED*/
}

void
sbd_init_mem_unit(sbd_board_t *sbp, int unit, sbderror_t *ep)
{
	sbd_istate_t	new_state;
	sbd_mem_unit_t	*mp;
	dev_info_t	*cur_mc_dip;
	int		failed_mcs = 0, present_mcs = 0;
	sbd_cond_t	mc_cond;
	int		i;

	mp = SBD_GET_BOARD_MEMUNIT(sbp, unit);

	if (SBD_DEV_IS_ATTACHED(sbp, SBD_COMP_MEM, unit)) {
		new_state = SBD_STATE_CONFIGURED;
	} else if (SBD_DEV_IS_PRESENT(sbp, SBD_COMP_MEM, unit)) {
		new_state = SBD_STATE_CONNECTED;
	} else if (mp->sbm_cm.sbdev_dip != NULL) {
		new_state = SBD_STATE_OCCUPIED;
	} else {
		new_state = SBD_STATE_EMPTY;
	}

	/*
	 * Check all the possible memory nodes on the board.  If all of them
	 * have a failed status mark memory as failed. Otherwise mem is ok
	 */
	if (!sbp->sb_memaccess_ok) {
		mp->sbm_cm.sbdev_cond = SBD_COND_UNKNOWN;
		return;
	}

	for (i = 0; i < SBD_NUM_MC_PER_BOARD; i++) {
		cur_mc_dip = mp->sbm_dip[i];

		if (cur_mc_dip == NULL)
			continue;

		present_mcs |= (1 << i);

		mc_cond = sbd_get_comp_cond(cur_mc_dip);
		if (mc_cond == SBD_COND_FAILED) {
			failed_mcs |= (1 << i);
		}
	}

	if (failed_mcs == present_mcs) {
		/*
		 * All mem nodes failed, therefore mark all mem
		 * as failed
		 */
		mp->sbm_cm.sbdev_cond = SBD_COND_FAILED;
	} else {
		mp->sbm_cm.sbdev_cond = SBD_COND_OK;
	}

	sbd_init_mem_unit_data(mp, ep);

	/*
	 * Any changes to this memory unit should be performed above
	 * this call to ensure the unit is fully initialized
	 * before transitioning to the new state.
	 */
	SBD_DEVICE_TRANSITION(sbp, SBD_COMP_MEM, unit, new_state);

}

static void
sbd_init_mem_unit_data(sbd_mem_unit_t *mp, sbderror_t *ep)
{
	uint64_t	basepa;
	uint64_t	sz;
	sbd_board_t	*sbp = mp->sbm_cm.sbdev_sbp;
	sbdp_handle_t	*hdp;
	static fn_t	f = "sbd_init_mem_unit_data";
	sbd_handle_t	*hp = MACHBD2HD(sbp);

	PR_MEM("%s...\n", f);

	/* a little sanity checking */
	ASSERT(mp->sbm_peer == NULL);
	ASSERT(mp->sbm_flags == 0);

	hdp = sbd_get_sbdp_handle(sbp, hp);

	/* get basepfn of mem unit */
	if (sbdphw_get_base_physaddr(hdp, mp->sbm_cm.sbdev_dip, &basepa)) {
		cmn_err(CE_WARN, "sbd:%s: failed to get physaddr"
			" for mem-unit (%d.%d)",
			f,
			sbp->sb_num,
			mp->sbm_cm.sbdev_unum);
		SBD_GET_PERR(hdp->h_err, ep);
		sbd_release_sbdp_handle(hdp);
		return;
	}
	mp->sbm_basepfn = _b64top(basepa);

	/* attempt to get number of pages from PDA */
	mp->sbm_npages = sbdp_get_mem_size(hdp);

	/* if didn't work, calculate using memlist */
	if (mp->sbm_npages == 0) {
		struct memlist	*ml, *mlist;
		mlist = sbd_get_memlist(mp, ep);
		for (ml = mlist; ml; ml = ml->next)
			mp->sbm_npages += btop(ml->size);
		memlist_delete(mlist);
	}


	if (sbdp_get_mem_alignment(hdp, mp->sbm_cm.sbdev_dip, &sz)) {
		cmn_err(CE_WARN,
			"sbd:%s: no alignment for mem-unit (%d.%d)",
			f, sbp->sb_num, mp->sbm_cm.sbdev_unum);
		SBD_GET_PERR(hdp->h_err, ep);
		sbd_release_sbdp_handle(hdp);
		return;
	}
	mp->sbm_alignment_mask = _b64top(sz);


	mp->sbm_interleave = sbdp_isinterleaved(hdp,
	    mp->sbm_cm.sbdev_dip);

	PR_MEM("%s: board %d (basepfn = 0x%lx, npgs = 0x%lx interleave %d)\n",
		f, sbp->sb_num,
		mp->sbm_basepfn,
		mp->sbm_npages,
		mp->sbm_interleave);

	sbd_release_sbdp_handle(hdp);
}

static int
sbd_reserve_mem_spans(memhandle_t *mhp, struct memlist *ml)
{
	int		err;
	pfn_t		base;
	pgcnt_t		npgs;
	struct memlist	*mc;
	static fn_t	f = "sbd_reserve_mem_spans";

	PR_MEM("%s...\n", f);

	/*
	 * Walk the supplied memlist scheduling each span for removal
	 * with kphysm_del_span.  It is possible that a span may intersect
	 * an area occupied by the cage.
	 */
	for (mc = ml; mc != NULL; mc = mc->next) {
		base = _b64top(mc->address);
		npgs = _b64top(mc->size);

		err = kphysm_del_span(*mhp, base, npgs);
		if (err != KPHYSM_OK) {
			cmn_err(CE_WARN, "sbd:%s memory reserve failed."
				" unexpected kphysm_del_span return value %d;"
				" basepfn=0x%lx npages=%ld",
				f, err, base, npgs);
			return (-1);
		}
	}
	return (0);
}

/* debug counters */
int sbd_smt_realigned;
int sbd_smt_preference[4];

#ifdef DEBUG
uint_t sbd_ignore_board; /* if bit[bnum-1] set, board won't be candidate */
#endif

/*
 * Verify that there is no memory overlapping if copy-rename is
 * done with the selected target board.
 *
 * Returns 0 if OK, -1 otherwise.
 */
static int
sbd_check_boundaries(struct memlist *orig_memlist, sbd_mem_unit_t *s_mp,
	sbd_mem_unit_t *t_mp)
{
	struct memlist	*new_memlist;
	int mlret;
	static fn_t	f = "sbd_check_boundaries";

	new_memlist = memlist_dup(orig_memlist);
	if (new_memlist == NULL) {
		PR_MEM("%s: can't dup original memlist\n", f);
		return (-1);
	}

	mlret = memlist_delete_span(
		_ptob64(s_mp->sbm_basepfn),
		_ptob64(s_mp->sbm_npages),
		&new_memlist);
	if (mlret != MEML_SPANOP_OK) {
		PR_MEM("%s: del s/s mlret = %d\n", f, mlret);
		goto check_done;
	}

	mlret = memlist_delete_span(
		_ptob64(t_mp->sbm_basepfn),
		_ptob64(t_mp->sbm_npages),
		&new_memlist);
	if (mlret != MEML_SPANOP_OK) {
		PR_MEM("%s: del t/t mlret = %d\n", f, mlret);
		goto check_done;
	}

	mlret = memlist_add_span(
		_ptob64(t_mp->sbm_basepfn),
		_ptob64(s_mp->sbm_npages),
		&new_memlist);
	if (mlret != MEML_SPANOP_OK) {
		PR_MEM("%s: add t/s mlret = %d\n", f, mlret);
		goto check_done;
	}

	mlret = memlist_add_span(
		_ptob64(s_mp->sbm_basepfn),
		_ptob64(t_mp->sbm_npages),
		&new_memlist);
	if (mlret != MEML_SPANOP_OK) {
		PR_MEM("%s: add s/t mlret = %d\n", f, mlret);
	}

check_done:
	memlist_delete(new_memlist);

	if (mlret == MEML_SPANOP_OK)
		return (0);
	else
		return (-1);
}

/*
 * Find and reserve a copy/rename target board suitable for the
 * given source board.
 * All boards in the system are examined and categorized in relation to
 * their memory size versus the source board's memory size.  Order of
 * preference is:
 *	1st: board has same memory size
 * 	2nd: board has larger memory size
 *	3rd: board has smaller memory size
 *	4th: board has smaller memory size, available memory will be reduced.
 * Boards in category 3 and 4 will have their MC's reprogrammed to locate the
 * span to which the MC responds to address span that appropriately covers
 * the nonrelocatable span of the source board.
 */
static int
sbd_select_mem_target(sbd_handle_t *hp,
	sbd_mem_unit_t *s_mp, struct memlist *s_ml)
{
	uint64_t	sz;
	pgcnt_t		sm;
	int		n_sets = 4; /* same, larger, smaller, clipped */
	int		preference; /* lower value is higher preference */
	int		n_units_per_set;
	int		idx;
	sbd_mem_unit_t	**sets;
	sbdp_handle_t	*hdp;
	int		t_bd;
	sbd_softstate_t	*softsp;
	int		t_unit;
	int		max_boards;
	int		rv;
	sbd_board_t	*s_sbp, *t_sbp;
	sbd_mem_unit_t	*t_mp, *c_mp;
	struct memlist	*d_ml, *t_ml, *x_ml;
	memquery_t	s_mq = {0};
	static fn_t	f = "sbd_select_mem_target";

	PR_MEM("%s...\n", f);

	ASSERT(s_ml != NULL);

	s_sbp = s_mp->sbm_cm.sbdev_sbp;

	hdp = sbd_get_sbdp_handle(s_sbp, hp);

	if (sbdp_get_mem_alignment(hdp, s_mp->sbm_cm.sbdev_dip, &sz)) {
		sbderror_t	*ep = SBD_HD2ERR(hp);
		cmn_err(CE_WARN,
			"sbd:%s: no alignment for mem-unit (%d.%d)",
			f, s_sbp->sb_num, s_mp->sbm_cm.sbdev_unum);
		SBD_GET_PERR(hdp->h_err, ep);
		sbd_release_sbdp_handle(hdp);
		return (-1);
	}
	sm = sz - 1;
	sbd_release_sbdp_handle(hdp);

	softsp = (sbd_softstate_t *)s_sbp->sb_softsp;

	max_boards = softsp->max_boards;
	n_units_per_set = max_boards * MAX_MEM_UNITS_PER_BOARD;
	sets = GETSTRUCT(sbd_mem_unit_t *, n_units_per_set * n_sets);

	/*
	 * Make one pass through all memory units on all boards
	 * and categorize them with respect to the source board.
	 */
	for (t_bd = 0; t_bd < max_boards; t_bd++) {
		/*
		 * The board structs are a contiguous array
		 * so we take advantage of that to find the
		 * correct board struct pointer for a given
		 * board number.
		 */
		t_sbp = (sbd_board_t *)softsp->sbd_boardlist;
		t_sbp += t_bd;

		/* source board can not be its own target */
		if (s_sbp->sb_num == t_sbp->sb_num)
			continue;

		for (t_unit = 0; t_unit < MAX_MEM_UNITS_PER_BOARD; t_unit++) {

			t_mp = SBD_GET_BOARD_MEMUNIT(t_sbp, t_unit);

			/* this memory node must be attached */
			if (!SBD_DEV_IS_ATTACHED(t_sbp, SBD_COMP_MEM, t_unit))
				continue;

			/* source unit can not be its own target */
			if (s_mp == t_mp) {
				/* catch this in debug kernels */
				ASSERT(0);
				continue;
			}

			/*
			 * this memory node must not already be reserved
			 * by some other memory delete operation.
			 */
			if (t_mp->sbm_flags & SBD_MFLAG_RESERVED)
				continue;

			/*
			 * categorize the memory node
			 * If this is a smaller memory node, create a
			 * temporary, edited copy of the source board's
			 * memlist containing only the span of the non-
			 * relocatable pages.
			 */
			if (t_mp->sbm_npages == s_mp->sbm_npages) {
				preference = 0;
				t_mp->sbm_slice_offset = 0;
			} else if (t_mp->sbm_npages > s_mp->sbm_npages) {
				preference = 1;
				t_mp->sbm_slice_offset = 0;
			} else {
				/*
				 * We do not allow other options right now
				 */
				continue;
			}

			sbd_smt_preference[preference]++;

			/* calculate index to start of preference set */
			idx  = n_units_per_set * preference;
			/* calculate offset to respective element */
			idx += t_bd * MAX_MEM_UNITS_PER_BOARD + t_unit;

			ASSERT(idx < n_units_per_set * n_sets);
			sets[idx] = t_mp;
		}
	}

	/*
	 * NOTE: this would be a good place to sort each candidate
	 * set in to some desired order, e.g. memory size in ascending
	 * order.  Without an additional sorting step here, the order
	 * within a set is ascending board number order.
	 */

	c_mp = NULL;
	x_ml = NULL;
	t_ml = NULL;
	for (idx = 0; idx < n_units_per_set * n_sets; idx++) {
		memquery_t mq;

		/* cleanup t_ml after previous pass */
		if (t_ml != NULL) {
			memlist_delete(t_ml);
			t_ml = NULL;
		}

		/* get candidate target board mem unit */
		t_mp = sets[idx];
		if (t_mp == NULL)
			continue;

		t_sbp = t_mp->sbm_cm.sbdev_sbp;

		/* get target board memlist */
		t_ml = sbd_get_memlist(t_mp, SBD_HD2ERR(hp));
		if (t_ml == NULL) {
			cmn_err(CE_WARN, "sbd:%s: no memlist for"
				" mem-unit %d, board %d",
				f,
				t_sbp->sb_num,
				t_mp->sbm_cm.sbdev_unum);

			continue;
		}

		/* get appropriate source board memlist */
		if (t_mp->sbm_npages < s_mp->sbm_npages) {
			spgcnt_t excess;

			/*
			 * make a copy of the source board memlist
			 * then edit it to remove the spans that
			 * are outside the calculated span of
			 * [pfn..s_mq.last_nonrelocatable].
			 */
			if (x_ml != NULL)
				memlist_delete(x_ml);

			x_ml = memlist_dup(s_ml);
			if (x_ml == NULL) {
				PR_MEM("%s: memlist_dup failed\n", f);
				/* TODO: should abort */
				continue;
			}

			/* trim off lower portion */
			excess = t_mp->sbm_slice_offset;
			if (excess > 0) {
				int mlret;

				mlret = memlist_delete_span(
					_ptob64(s_mp->sbm_basepfn),
					_ptob64(excess),
					&x_ml);
				PR_MEM("%s: mlret = %d\n", f, mlret);
			}

			/*
			 * Since this candidate target board is smaller
			 * than the source board, s_mq must have been
			 * initialized in previous loop while processing
			 * this or some other candidate board.
			 * FIXME: this is weak.
			 */
			ASSERT(s_mq.phys_pages != 0);

			/* trim off upper portion */
			excess = (s_mp->sbm_basepfn + s_mp->sbm_npages)
				- (s_mq.last_nonrelocatable + 1);
			if (excess > 0) {
				pfn_t p;
				int mlret;

				p  = s_mq.last_nonrelocatable + 1;
				p -= excess;

				mlret = memlist_delete_span(
					_ptob64(p),
					_ptob64(excess),
					&x_ml);
				PR_MEM("%s: mlret = %d\n", f, mlret);
			}

			PR_MEM("%s: brd %d: edited source memlist:\n",
				f, s_sbp->sb_num);
			SBD_MEMLIST_DUMP(x_ml);

#ifdef DEBUG
			/* sanity check memlist */
			d_ml = x_ml;
			while (d_ml->next != NULL)
				d_ml = d_ml->next;
			ASSERT(x_ml->address == _ptob64(s_mp->sbm_basepfn) +
				_ptob64(t_mp->sbm_slice_offset));
			ASSERT(d_ml->address + d_ml->size ==
				_ptob64(s_mq.last_nonrelocatable + 1));
#endif

			/*
			 * x_ml now describes only the portion of the
			 * source board that will be moved during the
			 * copy/rename operation.
			 */
			d_ml = x_ml;
		} else {
			/* use original memlist; all spans will be moved */
			d_ml = s_ml;
		}

		/* verify target can support source memory spans. */
		if (memlist_canfit(d_ml, t_ml) == 0) {
			PR_MEM("%s: source memlist won't"
				" fit in target memlist\n", f);
			PR_MEM("%s: source memlist:\n", f);
			SBD_MEMLIST_DUMP(d_ml);
			PR_MEM("%s: target memlist:\n", f);
			SBD_MEMLIST_DUMP(t_ml);

			continue;
		}

		/* NOTE: the value of d_ml is not used beyond this point */

		PR_MEM("%s: checking for no-reloc on board %d, "
			" basepfn=0x%lx, npages=%ld\n",
			f,
			t_sbp->sb_num,
			t_mp->sbm_basepfn,
			t_mp->sbm_npages);

		rv = kphysm_del_span_query(
			t_mp->sbm_basepfn, t_mp->sbm_npages, &mq);
		if (rv != KPHYSM_OK) {
			PR_MEM("%s: kphysm_del_span_query:"
				" unexpected return value %d\n", f, rv);

			continue;
		}

		if (mq.nonrelocatable != 0) {
			PR_MEM("%s: candidate board %d has"
				" nonrelocatable span [0x%lx..0x%lx]\n",
				f,
				t_sbp->sb_num,
				mq.first_nonrelocatable,
				mq.last_nonrelocatable);

			continue;
		}

#ifdef DEBUG
		/*
		 * This is a debug tool for excluding certain boards
		 * from being selected as a target board candidate.
		 * sbd_ignore_board is only tested by this driver.
		 * It must be set with adb, obp, /etc/system or your
		 * favorite debugger.
		 */
		if (sbd_ignore_board &
			(1 << (t_sbp->sb_num - 1))) {
			PR_MEM("%s: sbd_ignore_board flag set,"
				" ignoring board %d as candidate\n",
				f, t_sbp->sb_num);
			continue;
		}
#endif

		/*
		 * Make sure there is no memory overlap if this
		 * target board is used for copy-rename.
		 */
		if (sbd_check_boundaries(phys_install, s_mp, t_mp) != 0)
			continue;

		/*
		 * Reserve excess source board memory, if any.
		 *
		 * When the number of pages on the candidate target
		 * board is less than the number of pages on the source,
		 * then some spans (clearly) of the source board's address
		 * space will not be covered by physical memory after the
		 * copy/rename completes.  The following code block
		 * schedules those spans to be deleted.
		 */
		if (t_mp->sbm_npages < s_mp->sbm_npages) {
			pfn_t pfn;
			int mlret;

			d_ml = memlist_dup(s_ml);
			if (d_ml == NULL) {
				PR_MEM("%s: cant dup src brd memlist\n", f);
				/* TODO: should abort */
				continue;
			}

			/* calculate base pfn relative to target board */
			pfn  = s_mp->sbm_basepfn & ~sm;
			pfn += t_mp->sbm_slice_offset;

			/* remove span that will reside on candidate board */
			mlret = memlist_delete_span(
				_ptob64(pfn),
				_ptob64(t_mp->sbm_npages),
				&d_ml);
			PR_MEM("%s: mlret = %d\n", f, mlret);

			PR_MEM("%s: brd %d: reserving src brd memlist:\n",
				f, s_sbp->sb_num);
			SBD_MEMLIST_DUMP(d_ml);

			/* reserve excess spans */
			if (sbd_reserve_mem_spans(
				&s_mp->sbm_memhandle, d_ml) != 0) {

				/* likely more non-reloc pages appeared */
				/* TODO: restart from top? */
				continue;
			}
		} else {
			/* no excess source board memory */
			d_ml = NULL;
		}

		s_mp->sbm_flags |= SBD_MFLAG_RESERVED;

		/*
		 * reserve all memory on target board.
		 * NOTE: source board's memhandle is used.
		 *
		 * If this succeeds (eq 0), then target selection is
		 * complete and all unwanted memory spans, both source and
		 * target, have been reserved.  Loop is terminated.
		 */
		if (sbd_reserve_mem_spans(&s_mp->sbm_memhandle, t_ml) == 0) {
			PR_MEM("%s: brd %d: target board memory reserved\n",
				f, t_sbp->sb_num);

			/* a candidate target board is now reserved */
			t_mp->sbm_flags |= SBD_MFLAG_RESERVED;
			c_mp = t_mp;

			/* *** EXITING LOOP *** */
			break;
		}

		/* did not successfully reserve the target board. */
		PR_MEM("%s: could not reserve target board %d\n",
			f, t_sbp->sb_num);

		/*
		 * NOTE: an undo of the sbd_reserve_mem_span work
		 * will happen automatically when the memhandle
		 * (s_mp->sbm_memhandle) is kphysm_del_release'd.
		 */

		s_mp->sbm_flags &= ~SBD_MFLAG_RESERVED;
	}

	/* clean up after memlist editing logic */
	if (x_ml != NULL)
		memlist_delete(x_ml);

	FREESTRUCT(sets, sbd_mem_unit_t *, n_units_per_set * n_sets);

	/*
	 * c_mp will be NULL when the entire sets[] array
	 * has been searched without reserving a target board.
	 */
	if (c_mp == NULL) {
		PR_MEM("%s: brd %d: target selection failed.\n",
			f, s_sbp->sb_num);

		if (t_ml != NULL)
			memlist_delete(t_ml);

		return (-1);
	}

	PR_MEM("%s: found target board %d for source board %d\n",
		f,
		t_sbp->sb_num,
		s_sbp->sb_num);

	s_mp->sbm_peer = c_mp;
	s_mp->sbm_flags |= SBD_MFLAG_SOURCE;
	s_mp->sbm_del_mlist = d_ml;	/* spans to be deleted, if any */
	s_mp->sbm_mlist = s_ml;
	s_mp->sbm_cm.sbdev_busy = 1;

	c_mp->sbm_peer = s_mp;
	c_mp->sbm_flags |= SBD_MFLAG_TARGET;
	c_mp->sbm_del_mlist = t_ml;	/* spans to be deleted */
	c_mp->sbm_mlist = t_ml;
	c_mp->sbm_cm.sbdev_busy = 1;

	s_mp->sbm_flags &= ~SBD_MFLAG_MEMRESIZE;
	if (c_mp->sbm_npages > s_mp->sbm_npages) {
		s_mp->sbm_flags |= SBD_MFLAG_MEMUPSIZE;
		PR_MEM("%s: upsize (source pgs 0x%lx < target pgs 0x%lx)\n",
			f, s_mp->sbm_npages, c_mp->sbm_npages);
	} else if (c_mp->sbm_npages < s_mp->sbm_npages) {
		s_mp->sbm_flags |= SBD_MFLAG_MEMDOWNSIZE;
		PR_MEM("%s: downsize (source pgs 0x%lx > target pgs 0x%lx)\n",
			f, s_mp->sbm_npages, c_mp->sbm_npages);
	}

	return (0);
}

int
sbd_move_memory(sbd_handle_t *hp, sbd_board_t *s_bp, sbd_board_t *t_bp)
{
	int	ret;
	sbdp_handle_t	*hdp;
	sbderror_t	*ep = SBD_HD2ERR(hp);

	hdp = sbd_get_sbdp_handle(s_bp, hp);

	ret = sbdp_move_memory(hdp, t_bp->sb_num);
	if (ret != 0)
		SBD_GET_PERR(hdp->h_err, ep);

	sbd_release_sbdp_handle(hdp);

	return (ret);
}

/*
 * Memlist support.
 */
void
memlist_delete(struct memlist *mlist)
{
	sbdp_handle_t	*hdp;

	hdp = sbd_get_sbdp_handle(NULL, NULL);

	(void) sbdp_del_memlist(hdp, mlist);

	sbd_release_sbdp_handle(hdp);
}

struct memlist *
memlist_dup(struct memlist *mlist)
{
	struct memlist *hl, *prev;

	if (mlist == NULL)
		return (NULL);

	prev = NULL;
	hl = NULL;
	for (; mlist; mlist = mlist->next) {
		struct memlist *mp;

		mp = memlist_get_one();
		if (mp == NULL) {
			if (hl != NULL)
				memlist_free_list(hl);
			hl = NULL;
			break;
		}
		mp->address = mlist->address;
		mp->size = mlist->size;
		mp->next = NULL;
		mp->prev = prev;

		if (prev == NULL)
			hl = mp;
		else
			prev->next = mp;
		prev = mp;
	}

	return (hl);
}

void
memlist_dump(struct memlist *mlist)
{
	register struct memlist *ml;

	if (mlist == NULL) {
		PR_MEM("memlist> EMPTY\n");
	} else {
		for (ml = mlist; ml; ml = ml->next)
			PR_MEM("memlist> 0x%" PRIx64 " "
				"0x%" PRIx64 " \n",
				ml->address, ml->size);
	}
}

int
memlist_intersect(struct memlist *al, struct memlist *bl)
{
	uint64_t	astart, aend, bstart, bend;

	if ((al == NULL) || (bl == NULL))
		return (0);

	aend = al->address + al->size;
	bstart = bl->address;
	bend = bl->address + bl->size;

	while (al && bl) {
		while (al && (aend <= bstart))
			if ((al = al->next) != NULL)
				aend = al->address + al->size;
		if (al == NULL)
			return (0);

		if ((astart = al->address) <= bstart)
			return (1);

		while (bl && (bend <= astart))
			if ((bl = bl->next) != NULL)
				bend = bl->address + bl->size;
		if (bl == NULL)
			return (0);

		if ((bstart = bl->address) <= astart)
			return (1);
	}

	return (0);
}

/*
 * Determine whether the source memlist (s_mlist) will
 * fit into the target memlist (t_mlist) in terms of
 * size and holes (i.e. based on same relative base address).
 */
static int
memlist_canfit(struct memlist *s_mlist, struct memlist *t_mlist)
{
	int		rv = 0;
	uint64_t	s_basepa, t_basepa;
	struct memlist	*s_ml, *t_ml;

	if ((s_mlist == NULL) || (t_mlist == NULL))
		return (0);

	/*
	 * Base both memlists on common base address (0).
	 */
	s_basepa = s_mlist->address;
	t_basepa = t_mlist->address;

	for (s_ml = s_mlist; s_ml; s_ml = s_ml->next)
		s_ml->address -= s_basepa;

	for (t_ml = t_mlist; t_ml; t_ml = t_ml->next)
		t_ml->address -= t_basepa;

	s_ml = s_mlist;
	for (t_ml = t_mlist; t_ml && s_ml; t_ml = t_ml->next) {
		uint64_t	s_start, s_end;
		uint64_t	t_start, t_end;

		t_start = t_ml->address;
		t_end = t_start + t_ml->size;

		for (; s_ml; s_ml = s_ml->next) {
			s_start = s_ml->address;
			s_end = s_start + s_ml->size;

			if ((s_start < t_start) || (s_end > t_end))
				break;
		}
	}
	/*
	 * If we ran out of source memlist chunks that mean
	 * we found a home for all of them.
	 */
	if (s_ml == NULL)
		rv = 1;

	/*
	 * Need to add base addresses back since memlists
	 * are probably in use by caller.
	 */
	for (s_ml = s_mlist; s_ml; s_ml = s_ml->next)
		s_ml->address += s_basepa;

	for (t_ml = t_mlist; t_ml; t_ml = t_ml->next)
		t_ml->address += t_basepa;

	return (rv);
}

void
sbd_attach_mem(sbd_handle_t *hp, sbderror_t *ep)
{
	sbd_mem_unit_t	*mp;
	dev_info_t	*dip;
	sbd_board_t	*sbp = SBDH2BD(hp->h_sbd);
	sbdp_handle_t	*hdp;
	int		err, unit;
	struct memlist	*ml, *mc;
	static fn_t	f = "sbd_attach_mem";
	int		i;

	PR_MEM("%s...\n", f);

	/*
	 * all four cpus have to be attached before
	 * configuring mem
	 */
	for (i = 0; i < MAX_CPU_UNITS_PER_BOARD; i++) {
		sbd_cpu_unit_t	*cpup;
		struct cpu	*cp;

		if (!SBD_DEV_IS_PRESENT(sbp, SBD_COMP_CPU, i))
			continue;

		if (!SBD_DEV_IS_ATTACHED(sbp, SBD_COMP_CPU, i))
			goto error;

		cpup = SBD_GET_BOARD_CPUUNIT(sbp, i);

		if (cpup == NULL)
			goto error;

		mutex_enter(&cpu_lock);
		cp = cpu_get(cpup->sbc_cpu_id);
		if (cp == NULL) {
			mutex_exit(&cpu_lock);
			cmn_err(CE_WARN,
			    "sbd:%s: cpu_get failed for cpu %d",
			    f, cpup->sbc_cpu_id);
			goto error;
		}
		if (cpu_is_poweredoff(cp)) {
			mutex_exit(&cpu_lock);
			goto error;
		}
		mutex_exit(&cpu_lock);
		continue;

error:
		SBD_SET_ERR(ep, ESBD_CPUONLINE);
		SBD_SET_ERRSTR(ep, sbp->sb_mempath[i]);
		(void) sbd_set_err_in_hdl(hp, ep);
		return;
	}

	dip = *(sbp->sb_devlist[NIX(SBD_COMP_MEM)]);

	hdp = sbd_get_sbdp_handle(sbp, hp);
	unit = sbdp_get_unit_num(hdp, dip);
	if (unit < 0) {
		SBD_GET_PERR(hdp->h_err, ep);
		sbd_release_sbdp_handle(hdp);
		return;
	}

	ASSERT(sbp->sb_mempath[unit] != NULL);
	ASSERT(e_ddi_branch_held(dip));

	(void) ddi_pathname(dip, sbp->sb_mempath[unit]);

	mp = SBD_GET_BOARD_MEMUNIT(sbp, unit);

	ml = sbd_get_memlist(mp, ep);
	if (ml == NULL) {
		cmn_err(CE_WARN,
			"sbd:%s: failed to get memlist for "
			"board %d", f, sbp->sb_num);
		/*
		 * Need to record an error and return.
		 */
		SBD_SET_ERR(ep, ESBD_MEMFAIL);
		SBD_SET_ERRSTR(ep, sbp->sb_mempath[unit]);
		sbd_release_sbdp_handle(hdp);
		return;
	}

	SBD_MEMLIST_DUMP(ml);
	err = 0;
	for (mc = ml; mc; mc = mc->next) {
		update_membounds_t umb;
		pfn_t	base;
		pgcnt_t npgs;

		base = (pfn_t)(mc->address >> PAGESHIFT);
		npgs = (pgcnt_t)(mc->size >> PAGESHIFT);

		umb.u_board = sbp->sb_num;
		umb.u_base = (uint64_t)base << MMU_PAGESHIFT;
		umb.u_len = (uint64_t)npgs << MMU_PAGESHIFT;

		lgrp_plat_config(LGRP_CONFIG_MEM_ADD, (uintptr_t)&umb);
		err = kphysm_add_memory_dynamic(base, npgs);

		if (err != KPHYSM_OK) {
			cmn_err(CE_WARN,
			    "%s: kphysm_add_memory_dynamic fail %d", f, err);

			/* translate kphysm error */
			switch (err) {
			case KPHYSM_ERESOURCE:
				err = ESBD_NOMEM;
				break;

			case KPHYSM_EFAULT:
				err = ESBD_FAULT;
				break;

			default:
				err = ESBD_INVAL;
				break;
			}
			break;
		}

		err = kcage_range_add(base, npgs, KCAGE_DOWN);
		if (err != 0) {
			cmn_err(CE_WARN,
			    "%s: kcage_range_add fail %d", f, err);

			/* Translate kcage error. */
			switch (err) {
			case ENOMEM:
				err = ESBD_NOMEM;
				break;
			default:
				err = ESBD_INVAL;
				break;
			}
			break;
		}
		(void) sbdp_mem_add_span(hdp, mc->address, mc->size);
	}

	if (err != 0) {
		SBD_SET_ERR(ep, err);
		SBD_SET_ERRSTR(ep, sbp->sb_mempath[unit]);
	}

	memlist_delete(ml);
	sbd_release_sbdp_handle(hdp);

	/*
	 * Now attach all mem devinfo nodes to the device tree.
	 */
	for (i = 0; i < SBD_NUM_MC_PER_BOARD; i++) {
		if (mp->sbm_dip[i] == NULL)
			continue;
		ASSERT(e_ddi_branch_held(mp->sbm_dip[i]));
		if (e_ddi_branch_configure(mp->sbm_dip[i], NULL, 0) &&
		    SBD_GET_ERR(ep) == 0) {
			SBD_SET_ERR(ep, ESBD_INVAL);
			SBD_SET_ERRSTR(ep, sbp->sb_mempath[unit]);
		}
	}
}

typedef struct {
	kcondvar_t cond;
	kmutex_t lock;
	int error;
	int done;
} sbd_release_mem_sync_t;

/*
 * When we reach here the memory being drained should have
 * already been reserved in sbd_pre_release_mem().
 * Our only task here is to kick off the "drain".
 * Returns -1 when error encountered or zero for success.
 */
int
sbd_release_mem(sbd_handle_t *hp, dev_info_t *dip, int unit)
{
	memhandle_t	mh;
	int		err;
	int		cancel_flag = 0;
	int		e_code = 0;
	sbd_board_t	*sbp = SBDH2BD(hp->h_sbd);
	sbd_release_mem_sync_t rms;
	static fn_t	f = "sbd_release_mem";

	/*
	 * If this node has a scheduled memory delete operation,
	 * it will have a memhandle.  If it does have a memhandle (the
	 * return value of sbd_get_memhandle is zero when true),
	 * then perform the delete.
	 */

	if ((cancel_flag = sbd_get_memhandle(hp, dip, &mh)) != 0) {
		cmn_err(CE_WARN, "%s: couldn't get the memhandle\n", f);
		return (cancel_flag);
	}

	bzero((void *) &rms, sizeof (rms));

	mutex_init(&rms.lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&rms.cond, NULL, CV_DRIVER, NULL);

	mutex_enter(&rms.lock);
	err = kphysm_del_start(mh, sbd_release_memory_done, (void *) &rms);
	if (err == KPHYSM_OK) {
		/* wait for completion */
		while (!rms.done) {
			if (cancel_flag) {
				/* previously canceled */
				cv_wait(&rms.cond, &rms.lock);
			} else if (cv_wait_sig(&rms.cond, &rms.lock) == 0) {
				/* interrupted: cancel and wait */
				cancel_flag = -1;
				(void) kphysm_del_cancel(mh);
			}
		}
		/* get the result of the memory delete operation */
		err = rms.error;
	} else {
		(void) kphysm_del_release(mh);
	}

	mutex_exit(&rms.lock);

	cv_destroy(&rms.cond);
	mutex_destroy(&rms.lock);

	if (err != KPHYSM_OK) {
		switch (err) {
			case KPHYSM_ENOWORK:
				e_code = ESBD_NOERROR;
				break;

			case KPHYSM_EHANDLE:
			case KPHYSM_ESEQUENCE:
				e_code = ESBD_INTERNAL;
				break;

			case KPHYSM_ENOTVIABLE:
				e_code = ESBD_MEM_NOTVIABLE;
				break;

			case KPHYSM_EREFUSED:
				e_code = ESBD_MEM_REFUSED;
				break;

			case KPHYSM_ENONRELOC:
				e_code = ESBD_MEM_NONRELOC;
				break;

			case KPHYSM_ECANCELLED:
				e_code = ESBD_MEM_CANCELLED;
				break;

			case KPHYSM_ERESOURCE:
				e_code = ESBD_MEMFAIL;
				break;

			default:
				cmn_err(CE_WARN, "sbd:%s:"
					" unexpected kphysm error code %d,"
					" dip 0x%p",
					f, err, (void *)dip);

				e_code = ESBD_IO;
				break;
		}

		if (e_code != 0) {
			cancel_flag = -1;
			SBD_SET_ERR(SBD_HD2ERR(hp), e_code);
			SBD_SET_ERRSTR(SBD_HD2ERR(hp), sbp->sb_mempath[unit]);
		}
	}

	return (cancel_flag);
}

/*
 * Memory has been logically removed by the time this routine is called.
 */
void
sbd_release_memory_done(void *arg, int error)
{
	sbd_release_mem_sync_t *ds = arg;

	mutex_enter(&ds->lock);
	ds->error = error;
	ds->done = 1;
	cv_signal(&ds->cond);
	mutex_exit(&ds->lock);
}

/*
 * If detaching node contains memory that is "non-permanent"
 * then the memory adr's are simply cleared.  If the memory
 * is non-relocatable, then do a copy-rename.
 */
int
sbd_detach_memory(sbd_handle_t *hp, sbderror_t *ep, sbd_mem_unit_t *s_mp,
	int unit)
{
	int			rv;
	sbd_mem_unit_t		*t_mp;
	sbd_istate_t		state;
	sbdp_handle_t		*hdp;
	sbd_board_t 		*sbp = (sbd_board_t *)s_mp->sbm_cm.sbdev_sbp;
	sbd_board_t		*tbp;
	static fn_t		f = "sbd_detach_memory";

	PR_MEM("%s...\n", f);

	/* lookup target mem unit and target board structure, if any */
	if (s_mp->sbm_flags & SBD_MFLAG_SOURCE) {
		t_mp = s_mp->sbm_peer;
		ASSERT(t_mp != NULL);
		ASSERT(t_mp->sbm_peer == s_mp);
		tbp = (sbd_board_t *)t_mp->sbm_cm.sbdev_sbp;
	} else {
		t_mp = NULL;
	}

	/* verify mem unit's state is UNREFERENCED */
	state = s_mp->sbm_cm.sbdev_state;
	if (state != SBD_STATE_UNREFERENCED) {
		cmn_err(CE_WARN, "%s: invalid state transition for"
			" mem-unit (%d.%d)",
			f,
			sbp->sb_num,
			s_mp->sbm_cm.sbdev_unum);
		SBD_SET_ERR(ep, ESBD_STATE);
		SBD_SET_ERRSTR(ep, sbp->sb_mempath[unit]);
		return (-1);
	}

	/* verify target mem unit's state is UNREFERENCED, if any */
	if (t_mp != NULL) {
		state = t_mp->sbm_cm.sbdev_state;
		if (state != SBD_STATE_UNREFERENCED) {
			cmn_err(CE_WARN, "%s: invalid state transition for"
				" target mem-unit (%d.%d)",
				f,
				tbp->sb_num,
				t_mp->sbm_cm.sbdev_unum);
			SBD_SET_ERR(ep, ESBD_STATE);
			SBD_SET_ERRSTR(ep, sbp->sb_mempath[unit]);
			return (-1);
		}
	}

	/*
	 * Displacement flush all ecaches in the system.
	 * That's the fastest way to remove all cache references
	 * to the detaching memory.
	 */
	xc_all(sbd_flush_ecache, 0, 0);

	hdp = sbd_get_sbdp_handle(sbp, hp);

	/*
	 * If there is no target board (no copy/rename was needed), then
	 * we're done!
	 */
	if (t_mp == NULL) {
		/*
		 * Reprogram interconnect hardware and disable
		 * memory controllers for memory node that's going away.
		 */

		rv = sbdphw_disable_memctrl(hdp, s_mp->sbm_cm.sbdev_dip);
		if (rv) {
			cmn_err(CE_WARN,
				"%s: failed to deprogram mem-unit (%d.%d),"
				" dip 0x%p",
				f,
				sbp->sb_num,
				s_mp->sbm_cm.sbdev_unum,
				(void *)s_mp->sbm_cm.sbdev_dip);
			/*
			 * Make sure we don't rewrite an sbdp error
			 */
			if (SBD_GET_ERR(ep) != 0) {
				SBD_SET_ERR(ep, ESBD_HW_PROGRAM);
				SBD_SET_ERRSTR(ep, sbp->sb_mempath[unit]);
			}
		}
	} else {
		rv = sbd_move_memory(hp, sbp, tbp);
		if (rv) {
			int i;

			cmn_err(CE_WARN, "%s: failed to move memory"
				" from board %d to board %d",
				f,
				sbp->sb_num,
				tbp->sb_num);
			/*
			 * Make sure we don't rewrite an sbdp error
			 */
			if (SBD_GET_ERR(ep) != 0) {
				SBD_SET_ERR(ep, ESBD_INTERNAL);
				SBD_SET_ERRSTR(ep, sbp->sb_mempath[unit]);
			}
			/*
			 * If we failed here, it means that the target board's
			 * memory has been unconfigured.  We need to configure
			 * it back
			 */
			for (i = 0; i < MAX_MEM_UNITS_PER_BOARD; i++) {
				int		unit;
				dev_info_t	*dip;
				dev_info_t	**devlist;


				devlist = tbp->sb_devlist[NIX(SBD_COMP_MEM)];
				dip = devlist[i];
				sbd_reset_error_sbdph(hdp);
				unit = sbdp_get_unit_num(hdp, dip);

				/*
				 * We already saved the error that created
				 * this mess.  If we fail, make sure not
				 * to overwrite the original error
				 */
				if (unit == -1) {
					continue;
				}
				if (sbd_cancel_mem(hp, unit) != 0)
					continue;

				t_mp->sbm_flags = 0;
				/*
				 * clean up
				 */
				sbd_mem_cleanup(s_mp, t_mp, ep);
				if (s_mp->sbm_mlist) {
					memlist_delete(s_mp->sbm_mlist);
					s_mp->sbm_mlist = NULL;
				}

				SBD_DEVICE_TRANSITION(tbp, SBD_COMP_MEM,
				    unit, SBD_STATE_CONFIGURED);
			}
		}

		PR_MEM("%s: %s memory COPY-RENAME (board %d -> %d)\n",
			f,
			rv ? "FAILED" : "COMPLETED",
			sbp->sb_num,
			tbp->sb_num);
	}

	if (rv == 0) {
		update_membounds_t umb;

		umb.u_board = sbp->sb_num;
		umb.u_base = (uint64_t)-1;
		umb.u_len = (uint64_t)-1;

		lgrp_plat_config(LGRP_CONFIG_MEM_DEL, (uintptr_t)&umb);
	}

	sbd_release_sbdp_handle(hdp);
	return (rv);
}

/*ARGSUSED*/
static void
sbd_flush_ecache(uint64_t a, uint64_t b)
{
	cpu_flush_ecache();
}
