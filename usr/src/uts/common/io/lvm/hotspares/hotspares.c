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
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/file.h>
#include <sys/user.h>
#include <sys/uio.h>
#include <sys/t_lock.h>
#include <sys/kmem.h>
#include <vm/page.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/mkdev.h>
#include <sys/stat.h>
#include <sys/open.h>
#include <sys/modctl.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/debug.h>

#include <sys/lvm/md_hotspares.h>
#include <sys/lvm/md_convert.h>

#include <sys/sysevent/eventdefs.h>
#include <sys/sysevent/svm.h>

md_ops_t		hotspares_md_ops;
#ifndef	lint
char			_depends_on[] = "drv/md";
md_ops_t		*md_interface_ops = &hotspares_md_ops;
#endif

extern md_ops_t		**md_ops;
extern md_ops_t		*md_opslist;
extern md_set_t		md_set[];

extern kmutex_t		md_mx;		/* used to md global stuff */
extern kcondvar_t	md_cv;		/* md_status events */
extern int		md_status;

extern void		md_clear_hot_spare_interface();

static void
set_hot_spare_state(hot_spare_t *hs, hotspare_states_t newstate)
{
	hs->hs_state = newstate;
	uniqtime32(&hs->hs_timestamp);
}

static hot_spare_t *
lookup_hot_spare(set_t setno, mddb_recid_t hs_id, int must_exist)
{
	hot_spare_t *hs;

	for (hs = (hot_spare_t *)md_set[setno].s_hs; hs; hs = hs->hs_next) {
		if (hs->hs_record_id == hs_id)
			return (hs);
	}
	if (must_exist)
		ASSERT(0);

	return ((hot_spare_t *)NULL);
}


static int
seths_create_hsp(set_hs_params_t *shs)
{
	hot_spare_pool_t	*hsp;
	mddb_recid_t		recid;
	set_t			setno;
	mddb_type_t		typ1;

	setno = HSP_SET(shs->shs_hot_spare_pool);

	/* Scan the hot spare pool list */
	hsp = find_hot_spare_pool(setno, shs->shs_hot_spare_pool);
	if (hsp != (hot_spare_pool_t *)0)
		return (0);

	typ1 = (mddb_type_t)md_getshared_key(setno,
	    hotspares_md_ops.md_driver.md_drivername);

	/* create a hot spare pool record */
	if (shs->shs_options & MD_CRO_64BIT) {
#if defined(_ILP32)
		return (mdhsperror(&shs->mde, MDE_HSP_UNIT_TOO_LARGE,
		    shs->shs_hot_spare_pool));
#else
		recid = mddb_createrec(sizeof (hot_spare_pool_ond_t), typ1,
		    HSP_REC, MD_CRO_64BIT | MD_CRO_HOTSPARE_POOL | MD_CRO_FN,
		    setno);
#endif
	} else {
		recid = mddb_createrec(sizeof (hot_spare_pool_ond_t), typ1,
		    HSP_REC, MD_CRO_32BIT | MD_CRO_HOTSPARE_POOL | MD_CRO_FN,
		    setno);
	}

	if (recid < 0) {
		return (mdhsperror(&shs->mde, MDE_HSP_CREATE_FAILURE,
		    shs->shs_hot_spare_pool));
	}

	/* get the record addr */
	hsp = (hot_spare_pool_t *)mddb_getrecaddr_resize(recid, sizeof (*hsp),
		HSP_ONDSK_STR_OFF);

	hsp->hsp_self_id = shs->shs_hot_spare_pool;
	hsp->hsp_record_id = recid;
	hsp->hsp_next = (hot_spare_pool_t *)md_set[setno].s_hsp;
	hsp->hsp_refcount = 0;
	hsp->hsp_nhotspares = 0;
	hsp->hsp_revision |= MD_FN_META_DEV;

	md_set[setno].s_hsp = (void *) hsp;

	mddb_commitrec_wrapper(recid);
	SE_NOTIFY(EC_SVM_CONFIG, ESC_SVM_CREATE, SVM_TAG_HSP, setno,
	    md_expldev(hsp->hsp_self_id));

	rw_enter(&hotspares_md_ops.md_link_rw.lock, RW_WRITER);
	hsp->hsp_link.ln_next = hotspares_md_ops.md_head;
	hsp->hsp_link.ln_setno = setno;
	hsp->hsp_link.ln_id = hsp->hsp_self_id;
	hotspares_md_ops.md_head = &hsp->hsp_link;
	rw_exit(&hotspares_md_ops.md_link_rw.lock);

	return (0);
}


static int
seths_add(set_hs_params_t *shs)
{
	hot_spare_t		*hs;
	hot_spare_pool_t	*hsp;
	hot_spare_pool_t	*prev_hsp;
	hot_spare_pool_t	*new_hsp;
	hot_spare_pool_t	*old_hsp;
	md_create_rec_option_t	options;
	mddb_recid_t		recid;
	mddb_recid_t		recids[5];
	size_t			new_size;
	int			i;
	int			delete_hsp = 0;
	int			irecid;
	set_t			setno;
	mddb_type_t		typ1;
	int			hsp_created = 0;
	mdkey_t			key_old;
	int			num_keys_old = 0;

	/* Not much to do here in case of a dryrun */
	if (shs->shs_options & HS_OPT_DRYRUN) {
		return (0);
	}

	/* create an empty hot spare pool */
	if (shs->shs_options & HS_OPT_POOL) {
		return (seths_create_hsp(shs));
	}

	setno = HSP_SET(shs->shs_hot_spare_pool);
	typ1 = (mddb_type_t)md_getshared_key(setno,
	    hotspares_md_ops.md_driver.md_drivername);

	/* Scan the hot spare list */
	hs = (hot_spare_t *)md_set[setno].s_hs;
	while (hs) {
		if (hs->hs_devnum == shs->shs_component_old) {
			break;
		}
		hs = hs->hs_next;
	}

	if (hs == NULL) {
		/*
		 * Did not find match for device using devnum so use
		 * key associated with shs_component_old just
		 * in case there is a match but the match's dev is NODEV.
		 * If unable to find a unique key for shs_component_old
		 * then fail since namespace has multiple entries
		 * for this old component and we shouldn't allow
		 * an addition of a hotspare in this case.
		 */
		if (md_getkeyfromdev(setno, mddb_getsidenum(setno),
		    shs->shs_component_old, &key_old, &num_keys_old) != 0) {
			return (mddeverror(&shs->mde, MDE_NAME_SPACE,
			    shs->shs_component_old));
		}

		/*
		 * If more than one key matches given old_dev - fail command
		 * since shouldn't add new hotspare if namespace has
		 * multiple entries.
		 */
		if (num_keys_old > 1) {
			return (mddeverror(&shs->mde, MDE_MULTNM,
			    shs->shs_component_old));
		}
		/*
		 * If there is no key for this entry then fail since
		 * a key for this entry should exist.
		 */
		if (num_keys_old == 0) {
			return (mddeverror(&shs->mde, MDE_INVAL_HS,
			    shs->shs_component_old));
		}
		/* Scan the hot spare list again */
		hs = (hot_spare_t *)md_set[setno].s_hs;
		while (hs) {
			/*
			 * Only need to compare keys when hs_devnum is NODEV.
			 */
			if ((hs->hs_devnum == NODEV64) &&
			    (hs->hs_key == key_old)) {
				break;
			}
			hs = hs->hs_next;
		}
	}

	if (hs == NULL) {
		/* create a hot spare record */
		if (shs->shs_size_option & MD_CRO_64BIT) {
#if defined(_ILP32)
			return (mdhserror(&shs->mde, MDE_HS_UNIT_TOO_LARGE,
			    shs->shs_hot_spare_pool, shs->shs_component_old));
#else
			recid = mddb_createrec(HS_ONDSK_STR_SIZE, typ1, HS_REC,
				MD_CRO_64BIT | MD_CRO_HOTSPARE, setno);
#endif
		} else {
			recid = mddb_createrec(HS_ONDSK_STR_SIZE, typ1, HS_REC,
				MD_CRO_32BIT | MD_CRO_HOTSPARE, setno);
		}

		if (recid < 0) {
			return (mdhserror(&shs->mde, MDE_HS_CREATE_FAILURE,
			    shs->shs_hot_spare_pool,
			    shs->shs_component_old));
		}

		/* get the addr */
		hs = (hot_spare_t *)mddb_getrecaddr_resize(recid, sizeof (*hs),
			0);

		hs->hs_record_id = recid;

		hs->hs_devnum = shs->shs_component_old;
		hs->hs_key = shs->shs_key_old;
		hs->hs_start_blk = shs->shs_start_blk;
		hs->hs_has_label = shs->shs_has_label;
		hs->hs_number_blks = shs->shs_number_blks;
		set_hot_spare_state(hs, HSS_AVAILABLE);
		hs->hs_refcount = 0;
		hs->hs_next = (hot_spare_t *)md_set[setno].s_hs;
		md_set[setno].s_hs = (void *) hs;
	}

	/* Scan the hot spare pool list */
	hsp = (hot_spare_pool_t *)md_set[setno].s_hsp;
	prev_hsp = (hot_spare_pool_t *)0;
	while (hsp) {
		if (hsp->hsp_self_id == shs->shs_hot_spare_pool) {
			break;
		}
		prev_hsp = hsp;
		hsp = hsp->hsp_next;
	}

	if (hsp == NULL) {
		/* create a hot spare pool record */
		recid = mddb_createrec(sizeof (hot_spare_pool_ond_t),
		    typ1, HSP_REC,
		    MD_CRO_32BIT | MD_CRO_HOTSPARE_POOL | MD_CRO_FN, setno);

		if (recid < 0) {
			return (mdhsperror(&shs->mde, MDE_HSP_CREATE_FAILURE,
			    shs->shs_hot_spare_pool));
		}

		/* get the record addr */
		hsp = (hot_spare_pool_t *)mddb_getrecaddr_resize(recid,
			sizeof (*hsp), HSP_ONDSK_STR_OFF);

		hsp->hsp_self_id = shs->shs_hot_spare_pool;
		hsp->hsp_record_id = recid;
		hsp->hsp_next = (hot_spare_pool_t *)md_set[setno].s_hsp;
		hsp->hsp_refcount = 0;
		hsp->hsp_nhotspares = 0;
		hsp->hsp_revision |= MD_FN_META_DEV;

		/* force prev_hsp to NULL, this will cause hsp to be linked */
		prev_hsp = (hot_spare_pool_t *)0;

		rw_enter(&hotspares_md_ops.md_link_rw.lock, RW_WRITER);
		hsp->hsp_link.ln_next = hotspares_md_ops.md_head;
		hsp->hsp_link.ln_setno = setno;
		hsp->hsp_link.ln_id = hsp->hsp_self_id;
		hotspares_md_ops.md_head = &hsp->hsp_link;
		rw_exit(&hotspares_md_ops.md_link_rw.lock);
		hsp_created = 1;
	} else {

		/*
		 * Make sure the hot spare is not already in the pool.
		 */
		for (i = 0; i < hsp->hsp_nhotspares; i++)
			if (hsp->hsp_hotspares[i] == hs->hs_record_id) {
				return (mdhserror(&shs->mde, MDE_HS_INUSE,
					shs->shs_hot_spare_pool,
					hs->hs_devnum));
			}
		/*
		 * Create a new hot spare pool record
		 * This gives us the one extra hs slot,
		 * because there is one slot in the
		 * hot_spare_pool struct
		 */
		new_size = sizeof (hot_spare_pool_ond_t) +
			(sizeof (mddb_recid_t) * hsp->hsp_nhotspares);

		/*
		 * The Friendly Name status of the new HSP should duplicate
		 * the status of the existing one.
		 */
		if (hsp->hsp_revision & MD_FN_META_DEV) {
			options =
				MD_CRO_32BIT | MD_CRO_HOTSPARE_POOL | MD_CRO_FN;
		} else {
			options = MD_CRO_32BIT | MD_CRO_HOTSPARE_POOL;
		}
		recid = mddb_createrec(new_size, typ1, HSP_REC, options, setno);

		if (recid < 0) {
			return (mdhsperror(&shs->mde, MDE_HSP_CREATE_FAILURE,
			    hsp->hsp_self_id));
		}
		new_size = sizeof (hot_spare_pool_t) +
			(sizeof (mddb_recid_t) * hsp->hsp_nhotspares);

		/* get the record addr */
		new_hsp = (hot_spare_pool_t *)mddb_getrecaddr_resize(recid,
			new_size, HSP_ONDSK_STR_OFF);

		/* copy the old record into the new one */
		bcopy((caddr_t)hsp, (caddr_t)new_hsp,
		    (size_t)((sizeof (hot_spare_pool_t) +
		    (sizeof (mddb_recid_t) * hsp->hsp_nhotspares)
		    - sizeof (mddb_recid_t))));
		new_hsp->hsp_record_id = recid;

		md_rem_link(setno, hsp->hsp_self_id,
		    &hotspares_md_ops.md_link_rw.lock,
		    &hotspares_md_ops.md_head);

		rw_enter(&hotspares_md_ops.md_link_rw.lock, RW_WRITER);
		new_hsp->hsp_link.ln_next = hotspares_md_ops.md_head;
		new_hsp->hsp_link.ln_setno = setno;
		new_hsp->hsp_link.ln_id = new_hsp->hsp_self_id;
		hotspares_md_ops.md_head = &new_hsp->hsp_link;
		rw_exit(&hotspares_md_ops.md_link_rw.lock);

		/* mark the old hsp to be deleted */
		delete_hsp = 1;
		old_hsp = hsp;
		hsp = new_hsp;
	}

	if (shs->shs_size_option & MD_CRO_64BIT) {
		hs->hs_revision |= MD_64BIT_META_DEV;
	} else {
		hs->hs_revision &= ~MD_64BIT_META_DEV;
	}

	/* lock the db records */
	recids[0] = hs->hs_record_id;
	recids[1] = hsp->hsp_record_id;
	irecid = 2;
	if (delete_hsp)
		recids[irecid++] = old_hsp->hsp_record_id;
	recids[irecid] = 0;

	/* increment the reference count */
	hs->hs_refcount++;

	/* add the hs at the end of the hot spare pool */
	hsp->hsp_hotspares[hsp->hsp_nhotspares] = hs->hs_record_id;
	hsp->hsp_nhotspares++;

	/*
	 * NOTE: We do not commit the previous hot spare pool record.
	 *	 There is no need, the link gets rebuilt at boot time.
	 */
	if (prev_hsp)
		prev_hsp->hsp_next = hsp;
	else
		md_set[setno].s_hsp = (void *) hsp;

	if (delete_hsp)
		old_hsp->hsp_self_id = MD_HSP_NONE;

	/* commit the db records */
	mddb_commitrecs_wrapper(recids);

	if (delete_hsp) {
		/* delete the old hot spare pool record */
		mddb_deleterec_wrapper(old_hsp->hsp_record_id);
	}

	if (hsp_created) {
		SE_NOTIFY(EC_SVM_CONFIG, ESC_SVM_CREATE, SVM_TAG_HSP, setno,
		    md_expldev(hsp->hsp_self_id));
	}
	SE_NOTIFY(EC_SVM_CONFIG, ESC_SVM_ADD, SVM_TAG_HSP, setno,
	    md_expldev(hsp->hsp_self_id));

	return (0);
}


static int
seths_delete_hsp(set_hs_params_t *shs)
{

	hot_spare_pool_t	*prev_hsp;
	hot_spare_pool_t	*hsp;
	set_t			setno;
	hsp_t			hspid;

	setno = HSP_SET(shs->shs_hot_spare_pool);

	/* Scan the hot spare pool list */
	prev_hsp = (hot_spare_pool_t *)0;
	hsp = (hot_spare_pool_t *)md_set[setno].s_hsp;
	while (hsp) {
		if (hsp->hsp_self_id == shs->shs_hot_spare_pool) {
			break;
		}
		prev_hsp = hsp;
		hsp = hsp->hsp_next;
	}

	if (hsp == NULL) {
		return (mdhsperror(&shs->mde, MDE_INVAL_HSP,
		    shs->shs_hot_spare_pool));
	}

	if (hsp->hsp_nhotspares != 0) {
		return (mdhsperror(&shs->mde, MDE_HSP_BUSY,
		    shs->shs_hot_spare_pool));
	}

	if (hsp->hsp_refcount != 0) {
		return (mdhsperror(&shs->mde, MDE_HSP_REF,
		    shs->shs_hot_spare_pool));
	}

	/* In case of a dryrun, we're done here */
	if (shs->shs_options & HS_OPT_DRYRUN) {
		return (0);
	}
	/*
	 * NOTE: We do not commit the previous hot spare pool record.
	 *	 There is no need, the link gets rebuilt at boot time.
	 */
	if (prev_hsp)
		prev_hsp->hsp_next = hsp->hsp_next;
	else
		md_set[setno].s_hsp = (void *) hsp->hsp_next;

	hspid = hsp->hsp_self_id;

	md_rem_link(setno, hsp->hsp_self_id,
	    &hotspares_md_ops.md_link_rw.lock,
	    &hotspares_md_ops.md_head);

	mddb_deleterec_wrapper(hsp->hsp_record_id);

	SE_NOTIFY(EC_SVM_CONFIG, ESC_SVM_DELETE, SVM_TAG_HSP, setno,
	    md_expldev(hspid));
	return (0);
}


static int
seths_delete(set_hs_params_t *shs)
{
	hot_spare_t		*hs;
	hot_spare_t		*prev_hs;
	hot_spare_pool_t	*hsp;
	mddb_recid_t		recids[4];
	int			i;
	set_t			setno;
	sv_dev_t		sv;
	int			delete_hs = 0;
	mdkey_t			key_old;
	int			num_keys_old = 0;

	/* delete the hot spare pool */
	if (shs->shs_options & HS_OPT_POOL) {
		return (seths_delete_hsp(shs));
	}

	setno = HSP_SET(shs->shs_hot_spare_pool);

	/* Scan the hot spare list */
	hs = (hot_spare_t *)md_set[setno].s_hs;
	prev_hs = (hot_spare_t *)0;
	while (hs) {
		if (hs->hs_devnum == shs->shs_component_old) {
			break;
		}
		prev_hs = hs;
		hs = hs->hs_next;
	}

	if (hs == NULL) {
		/*
		 * Unable to find device using devnum so use
		 * key associated with shs_component_old instead.
		 * If unable to find a unique key for shs_component_old
		 * then fail since namespace has multiple entries
		 * for this old component and we're unable to determine
		 * which key is the valid match for shs_component_old.
		 *
		 * Only need to compare keys when hs_devnum is NODEV.
		 */
		if (md_getkeyfromdev(setno, mddb_getsidenum(setno),
		    shs->shs_component_old, &key_old, &num_keys_old) != 0) {
			return (mddeverror(&shs->mde, MDE_NAME_SPACE,
			    shs->shs_component_old));
		}

		/*
		 * If more than one key matches given old_dev - fail command
		 * since shouldn't add new hotspare if namespace has
		 * multiple entries.
		 */
		if (num_keys_old > 1) {
			return (mddeverror(&shs->mde, MDE_MULTNM,
			    shs->shs_component_old));
		}
		/*
		 * If there is no key for this entry then fail since
		 * a key for this entry should exist.
		 */
		if (num_keys_old == 0) {
			return (mddeverror(&shs->mde, MDE_INVAL_HS,
			    shs->shs_component_old));
		}
		/* Scan the hot spare list again */
		hs = (hot_spare_t *)md_set[setno].s_hs;
		prev_hs = (hot_spare_t *)0;
		while (hs) {
			/*
			 * Only need to compare keys when hs_devnum is NODEV.
			 */
			if ((hs->hs_devnum == NODEV64) &&
			    (hs->hs_key == key_old)) {
				break;
			}
			prev_hs = hs;
			hs = hs->hs_next;
		}
	}

	if (hs == NULL) {
		return (mddeverror(&shs->mde, MDE_INVAL_HS,
		    shs->shs_component_old));
	}

	/* Scan the hot spare pool list */
	hsp = find_hot_spare_pool(setno, shs->shs_hot_spare_pool);
	if (hsp == (hot_spare_pool_t *)0) {
		return (mdhsperror(&shs->mde, MDE_INVAL_HSP,
		    shs->shs_hot_spare_pool));
	}

	/* check for force flag and state of hot spare */
	if (((shs->shs_options & HS_OPT_FORCE) == 0) &&
	    (hs->hs_state == HSS_RESERVED)) {
		return (mdhserror(&shs->mde, MDE_HS_RESVD,
		    shs->shs_hot_spare_pool, shs->shs_component_old));
	}

	if (hsp->hsp_refcount && (hs->hs_state == HSS_RESERVED)) {
		return (mdhserror(&shs->mde, MDE_HS_RESVD,
		    shs->shs_hot_spare_pool, shs->shs_component_old));
	}

	/*
	 * Make sure the device is in the pool.
	 */
	for (i = 0; i < hsp->hsp_nhotspares; i++) {
		if (hsp->hsp_hotspares[i] == hs->hs_record_id) {
			break;
		}
	}

	if (i >= hsp->hsp_nhotspares) {
		return (mddeverror(&shs->mde, MDE_INVAL_HS,
		    hs->hs_devnum));
	}

	/* In case of a dryrun, we're done here */
	if (shs->shs_options & HS_OPT_DRYRUN) {
		return (0);
	}

	/* lock the db records */
	recids[0] = hs->hs_record_id;
	recids[1] = hsp->hsp_record_id;
	recids[2] = 0;

	sv.setno = setno;
	sv.key = hs->hs_key;

	hs->hs_refcount--;
	if (hs->hs_refcount == 0) {
		/*
		 * NOTE: We do not commit the previous hot spare record.
		 *	 There is no need, the link we get rebuilt at boot time.
		 */
		if (prev_hs) {
			prev_hs->hs_next = hs->hs_next;
		} else
			md_set[setno].s_hs = (void *) hs->hs_next;

		/* mark the hot spare to be deleted */
		delete_hs = 1;
		recids[0] = hsp->hsp_record_id;
		recids[1] = 0;
	}

	/* find the location of the hs in the hsp */
	for (i = 0; i < hsp->hsp_nhotspares; i++) {
		if (hsp->hsp_hotspares[i] == hs->hs_record_id)
			break;
	}

	/* remove the hs from the hsp */
	for (i++; i < hsp->hsp_nhotspares; i++)
		hsp->hsp_hotspares[i - 1] = hsp->hsp_hotspares[i];

	hsp->hsp_nhotspares--;

	/* commit the db records */
	mddb_commitrecs_wrapper(recids);

	if (delete_hs)
		mddb_deleterec_wrapper(hs->hs_record_id);

	md_rem_names(&sv, 1);

	SE_NOTIFY(EC_SVM_CONFIG, ESC_SVM_REMOVE, SVM_TAG_HSP, setno,
	    md_expldev(hsp->hsp_self_id));

	return (0);
}

static int
seths_replace(set_hs_params_t *shs)
{
	hot_spare_t		*hs;
	hot_spare_t		*prev_hs;
	hot_spare_t		*new_hs;
	hot_spare_pool_t	*hsp;
	int			new_found = 0;
	mddb_recid_t		recid;
	mddb_recid_t		recids[5];
	int			i;
	sv_dev_t		sv;
	int			delete_hs = 0;
	set_t			setno;
	mddb_type_t		typ1;
	mdkey_t			key_old;
	int			num_keys_old = 0;

	setno = HSP_SET(shs->shs_hot_spare_pool);
	typ1 = (mddb_type_t)md_getshared_key(setno,
	    hotspares_md_ops.md_driver.md_drivername);

	/* Scan the hot spare list */
	hs = (hot_spare_t *)md_set[setno].s_hs;
	prev_hs = (hot_spare_t *)0;
	while (hs) {
		if (hs->hs_devnum == shs->shs_component_old) {
			break;
		}
		prev_hs = hs;
		hs = hs->hs_next;
	}

	if (hs == NULL) {
		/*
		 * Unable to find device using devnum so use
		 * key associated with shs_component_old instead.
		 * If unable to find a unique key for shs_component_old
		 * then fail since namespace has multiple entries
		 * for this old component and we're unable to determine
		 * which key is the valid match for shs_component_old.
		 *
		 * Only need to compare keys when hs_devnum is NODEV.
		 */
		if (md_getkeyfromdev(setno, mddb_getsidenum(setno),
		    shs->shs_component_old, &key_old, &num_keys_old) != 0) {
			return (mddeverror(&shs->mde, MDE_NAME_SPACE,
			    shs->shs_component_old));
		}

		/*
		 * If more than one key matches given old_dev - fail command
		 * since unable to determine which key is correct.
		 */
		if (num_keys_old > 1) {
			return (mddeverror(&shs->mde, MDE_MULTNM,
			    shs->shs_component_old));
		}
		/*
		 * If there is no key for this entry then fail since
		 * a key for this entry should exist.
		 */
		if (num_keys_old == 0) {
			return (mddeverror(&shs->mde, MDE_INVAL_HS,
			    shs->shs_component_old));
		}
		/* Scan the hot spare list again */
		hs = (hot_spare_t *)md_set[setno].s_hs;
		prev_hs = (hot_spare_t *)0;
		while (hs) {
			/*
			 * Only need to compare keys when hs_devnum is NODEV.
			 */
			if ((hs->hs_devnum == NODEV64) &&
			    (hs->hs_key == key_old)) {
				break;
			}
			prev_hs = hs;
			hs = hs->hs_next;
		}
	}

	if (hs == NULL) {
		return (mddeverror(&shs->mde, MDE_INVAL_HS,
		    shs->shs_component_old));
	}

	/* check the force flag and the state of the hot spare */
	if (((shs->shs_options & HS_OPT_FORCE) == 0) &&
	    (hs->hs_state == HSS_RESERVED)) {
		return (mdhserror(&shs->mde, MDE_HS_RESVD,
		    shs->shs_hot_spare_pool,
		    hs->hs_devnum));
	}

	/* Scan the hot spare pool list */
	hsp = find_hot_spare_pool(setno, shs->shs_hot_spare_pool);
	if (hsp == (hot_spare_pool_t *)0) {
		return (mdhsperror(&shs->mde, MDE_INVAL_HSP,
		    shs->shs_hot_spare_pool));
	}

	/*
	 * Make sure the old device is in the pool.
	 */
	for (i = 0; i < hsp->hsp_nhotspares; i++) {
		if (hsp->hsp_hotspares[i] == hs->hs_record_id) {
			break;
		}
	}
	if (i >= hsp->hsp_nhotspares) {
		return (mddeverror(&shs->mde, MDE_INVAL_HS,
		    hs->hs_devnum));
	}

	/* Scan the hot spare list for the new hs */
	new_hs = (hot_spare_t *)md_set[setno].s_hs;
	new_found = 0;
	while (new_hs) {
		if (new_hs->hs_devnum == shs->shs_component_new) {
			new_found = 1;
			break;
		}
		new_hs = new_hs->hs_next;
	}

	/*
	 * Make sure the new device is not already in the pool.
	 * We don't have to search the hs in this hsp, if the
	 * new hs was just created. Only if the hot spare was found.
	 */
	if (new_found) {
		for (i = 0; i < hsp->hsp_nhotspares; i++)
			if (hsp->hsp_hotspares[i] == new_hs->hs_record_id) {
				return (mdhserror(&shs->mde, MDE_HS_INUSE,
				    shs->shs_hot_spare_pool,
				    new_hs->hs_devnum));
			}
	}

	/* In case of a dryrun, we're done here */
	if (shs->shs_options & HS_OPT_DRYRUN) {
		return (0);
	}

	/*
	 * Create the new hotspare
	 */
	if (!new_found) {
		/* create a hot spare record */
		if (shs->shs_size_option & MD_CRO_64BIT) {
#if defined(_ILP32)
			return (mdhserror(&shs->mde, MDE_HS_UNIT_TOO_LARGE,
			    shs->shs_hot_spare_pool, shs->shs_component_new));
#else
			recid = mddb_createrec(HS_ONDSK_STR_SIZE, typ1, HS_REC,
				MD_CRO_64BIT | MD_CRO_HOTSPARE, setno);
#endif
		} else {
			recid = mddb_createrec(HS_ONDSK_STR_SIZE, typ1, HS_REC,
				MD_CRO_32BIT | MD_CRO_HOTSPARE, setno);
		}

		if (recid < 0) {
			return (mdhserror(&shs->mde, MDE_HS_CREATE_FAILURE,
			    shs->shs_hot_spare_pool,
			    shs->shs_component_new));
		}

		/* get the addr */
		new_hs = (hot_spare_t *)mddb_getrecaddr_resize(recid,
			sizeof (*new_hs), 0);

		new_hs->hs_record_id = recid;
		new_hs->hs_devnum = shs->shs_component_new;
		new_hs->hs_key = shs->shs_key_new;
		new_hs->hs_start_blk = shs->shs_start_blk;
		new_hs->hs_has_label = shs->shs_has_label;
		new_hs->hs_number_blks = shs->shs_number_blks;
		set_hot_spare_state(new_hs, HSS_AVAILABLE);
		new_hs->hs_refcount = 0;
		new_hs->hs_isopen = 1;
	}

	/* lock the db records */
	recids[0] = hs->hs_record_id;
	recids[1] = new_hs->hs_record_id;
	recids[2] = hsp->hsp_record_id;
	recids[3] = 0;

	sv.setno = setno;
	sv.key = hs->hs_key;

	hs->hs_refcount--;
	if (hs->hs_refcount == 0) {
		/*
		 * NOTE: We do not commit the previous hot spare record.
		 *	 There is no need, the link we get rebuilt at boot time.
		 */
		if (prev_hs) {
			prev_hs->hs_next = hs->hs_next;
		} else
			md_set[setno].s_hs = (void *) hs->hs_next;

		/* mark hs to be deleted in the correct order */
		delete_hs = 1;

		recids[0] = new_hs->hs_record_id;
		recids[1] = hsp->hsp_record_id;
		recids[2] = 0;
	}

	/* link into the hs list */
	new_hs->hs_refcount++;
	if (!new_found) {
		/* do this AFTER the old dev is possibly removed */
		new_hs->hs_next = (hot_spare_t *)md_set[setno].s_hs;
		md_set[setno].s_hs = (void *) new_hs;
	}

	/* find the location of the old hs in the hsp */
	for (i = 0; i < hsp->hsp_nhotspares; i++) {
		if (hsp->hsp_hotspares[i] == hs->hs_record_id) {
			hsp->hsp_hotspares[i] = new_hs->hs_record_id;
			break;
		}
	}

	if (shs->shs_size_option & MD_CRO_64BIT) {
		new_hs->hs_revision |= MD_64BIT_META_DEV;
	} else {
		new_hs->hs_revision &= ~MD_64BIT_META_DEV;
	}

	/* commit the db records */
	mddb_commitrecs_wrapper(recids);

	if (delete_hs)
		mddb_deleterec_wrapper(hs->hs_record_id);

	md_rem_names(&sv, 1);

	SE_NOTIFY(EC_SVM_CONFIG, ESC_SVM_REPLACE, SVM_TAG_HSP, setno,
	    md_expldev(hsp->hsp_self_id));
	return (0);
}

static int
seths_enable(set_hs_params_t *shs)
{
	hot_spare_t	*hs;
	mddb_recid_t	recids[2];
	set_t		setno = shs->md_driver.md_setno;
	mdkey_t		key_old;
	int		num_keys_old = 0;


	/*
	 * Find device by using key associated with shs_component_old.
	 * If unable to find a unique key for shs_component_old
	 * then fail since namespace has multiple entries
	 * for this old component and we're unable to determine
	 * which key is the valid match for shs_component_old.
	 * This failure keeps a hotspare from being enabled on a slice
	 * that may already be in use by another metadevice.
	 */
	if (md_getkeyfromdev(setno, mddb_getsidenum(setno),
	    shs->shs_component_old, &key_old, &num_keys_old) != 0) {
		return (mddeverror(&shs->mde, MDE_NAME_SPACE,
		    shs->shs_component_old));
	}

	/*
	 * If more than one key matches given old_dev - fail command
	 * since unable to determine which key is correct.
	 */
	if (num_keys_old > 1) {
		return (mddeverror(&shs->mde, MDE_MULTNM,
		    shs->shs_component_old));
	}
	/*
	 * If there is no key for this entry then fail since
	 * a key for this entry should exist.
	 */
	if (num_keys_old == 0) {
		return (mddeverror(&shs->mde, MDE_INVAL_HS,
		    shs->shs_component_old));
	}

	/* Scan the hot spare list for the hs */
	hs = (hot_spare_t *)md_set[setno].s_hs;
	while (hs) {
		/*
		 * Since component may or may not be currently in the system,
		 * use the keys to find a match (not the devt).
		 */
		if (hs->hs_key == key_old) {
			break;
		}
		hs = hs->hs_next;
	}

	if (hs == NULL) {
		return (mddeverror(&shs->mde, MDE_INVAL_HS,
			shs->shs_component_old));
	}

	/* make sure it's broken */
	if (hs->hs_state != HSS_BROKEN) {
		return (mddeverror(&shs->mde, MDE_FIX_INVAL_HS_STATE,
		    hs->hs_devnum));
	}

	/* In case of a dryrun, we're done here */
	if (shs->shs_options & HS_OPT_DRYRUN) {
		return (0);
	}

	/* fix it */
	set_hot_spare_state(hs, HSS_AVAILABLE);
	hs->hs_start_blk = shs->shs_start_blk;
	hs->hs_has_label = shs->shs_has_label;
	hs->hs_number_blks = shs->shs_number_blks;

	/* commit the db records */
	recids[0] = hs->hs_record_id;
	recids[1] = 0;
	mddb_commitrecs_wrapper(recids);
	SE_NOTIFY(EC_SVM_STATE, ESC_SVM_ENABLE, SVM_TAG_HS, setno,
	    shs->shs_component_old);

	return (0);
}

static int
get_hs(
	get_hs_params_t	*ghs
)
{
	hot_spare_t	*hs;
	set_t		setno = ghs->md_driver.md_setno;

	mdclrerror(&ghs->mde);

	/* Scan the hot spare list for the hs */
	hs = (hot_spare_t *)md_set[setno].s_hs;
	while (hs) {
		if (hs->hs_key == ghs->ghs_key) {
			break;
		}
		hs = hs->hs_next;
	}

	if (hs == NULL) {
		return (mddeverror(&ghs->mde, MDE_INVAL_HS,
		    ghs->ghs_devnum));
	}

	ghs->ghs_start_blk = hs->hs_start_blk;
	ghs->ghs_number_blks = hs->hs_number_blks;
	ghs->ghs_state = hs->hs_state;
	ghs->ghs_timestamp = hs->hs_timestamp;
	ghs->ghs_revision = hs->hs_revision;
	return (0);
}

static void
build_key_list(set_t setno, hot_spare_pool_t *hsp, mdkey_t *list)
{
	int	i;

	for (i = 0; i < hsp->hsp_nhotspares; i++) {
		hot_spare_t *hs;
		hs = lookup_hot_spare(setno, hsp->hsp_hotspares[i], 1);
		list[i] = hs->hs_key;
	}
}

static int
get_hsp(
	void			*d,
	int			mode
)
{
	hot_spare_pool_t	*hsp;
	get_hsp_t		*ghsp;
	size_t			size;
	set_t			setno;
	int			err = 0;
	md_i_get_t		*migp = (md_i_get_t *)d;


	setno = migp->md_driver.md_setno;

	mdclrerror(&migp->mde);

	/* Scan the hot spare pool list */
	hsp = find_hot_spare_pool(setno, migp->id);
	if (hsp == NULL) {
		return (mdhsperror(&migp->mde, MDE_INVAL_HSP,
			migp->id));
	}

	size = (sizeof (ghsp->ghsp_hs_keys[0]) * (hsp->hsp_nhotspares - 1)) +
	    sizeof (get_hsp_t);

	if (migp->size == 0) {
		migp->size = (int)size;
		return (0);
	}

	if (migp->size < size)
		return (EFAULT);

	ghsp = kmem_alloc(size, KM_SLEEP);

	ghsp->ghsp_id = hsp->hsp_self_id;
	ghsp->ghsp_refcount = hsp->hsp_refcount;
	ghsp->ghsp_nhotspares = hsp->hsp_nhotspares;
	build_key_list(setno, hsp, ghsp->ghsp_hs_keys);
	if (ddi_copyout(ghsp, (caddr_t)(uintptr_t)migp->mdp, size, mode))
		err = EFAULT;
	kmem_free(ghsp, size);
	return (err);
}

static int
set_hs(
	set_hs_params_t	*shs
)
{
	mdclrerror(&shs->mde);

	if (md_get_setstatus(shs->md_driver.md_setno) & MD_SET_STALE)
		return (mdmddberror(&shs->mde, MDE_DB_STALE, NODEV32,
		    shs->md_driver.md_setno));

	switch (shs->shs_cmd) {
	case ADD_HOT_SPARE:
		return (seths_add(shs));
	case DELETE_HOT_SPARE:
		return (seths_delete(shs));
	case REPLACE_HOT_SPARE:
		return (seths_replace(shs));
	case FIX_HOT_SPARE:
		return (seths_enable(shs));
	default:
		return (mderror(&shs->mde, MDE_INVAL_HSOP));
	}
}

static void
hotspares_poke_hotspares(void)
{
	intptr_t	(*poke_hs)();
	int		i;

	for (i = 0; i < MD_NOPS; i++) {
		/* handle change */
		poke_hs = md_get_named_service(NODEV64, i, "poke hotspares", 0);
		if (poke_hs)
			(void) (*poke_hs)();
	}
}


/*ARGSUSED4*/
static int
hotspares_ioctl(
	dev_t	dev,
	int	cmd,
	void	*data,
	int	mode,
	IOLOCK	*lockp
)
{
	size_t	sz = 0;
	void	*d = NULL;
	int	err = 0;

	/* single thread */
	if (getminor(dev) != MD_ADM_MINOR)
		return (ENOTTY);

	/* We can only handle 32-bit clients for internal commands */
	if ((mode & DATAMODEL_MASK) != DATAMODEL_ILP32) {
		return (EINVAL);
	}

	mutex_enter(&md_mx);
	while (md_status & MD_GBL_HS_LOCK)
		cv_wait(&md_cv, &md_mx);
	md_status |= MD_GBL_HS_LOCK;
	mutex_exit(&md_mx);

	/* dispatch ioctl */
	switch (cmd) {

	case MD_IOCSET_HS:	/* setup hot spares and pools */
	{
		if (! (mode & FWRITE)) {
			err = EACCES;
			break;
		}

		sz = sizeof (set_hs_params_t);
		d = kmem_alloc(sz, KM_SLEEP);

		if (ddi_copyin(data, d, sz, mode)) {
			err = EFAULT;
			break;
		}

		err = set_hs(d);
		break;
	}

	case MD_IOCGET_HS:	/* get hot spare info */
	{
		if (! (mode & FREAD)) {
			err = EACCES;
			break;
		}

		sz = sizeof (get_hs_params_t);
		d = kmem_alloc(sz, KM_SLEEP);

		if (ddi_copyin(data, d, sz, mode)) {
			err = EFAULT;
			break;
		}

		err = get_hs(d);
		break;
	}

	case MD_IOCGET:		/* get hot spare pool info */
	{
		if (! (mode & FREAD)) {
			err = EACCES;
			break;
		}

		sz = sizeof (md_i_get_t);
		d = kmem_alloc(sz, KM_SLEEP);

		if (ddi_copyin(data, d, sz, mode)) {
			err = EFAULT;
			break;
		}

		err = get_hsp(d, mode);
		break;
	}

	default:
		err = ENOTTY;
	}

	/*
	 * copyout and free any args
	 */
	if (sz != 0) {
		if (err == 0) {
			if (ddi_copyout(d, data, sz, mode) != 0) {
				err = EFAULT;
			}
		}
		kmem_free(d, sz);
	}

	/* un single thread */
	mutex_enter(&md_mx);
	md_status &= ~MD_GBL_HS_LOCK;
	cv_broadcast(&md_cv);
	mutex_exit(&md_mx);

	/* handle change */
	hotspares_poke_hotspares();

	/* return success */
	return (err);
}


static void
load_hotspare(set_t setno, mddb_recid_t recid)
{
	hot_spare_t	*hs;
	mddb_de_ic_t	*dep;
	mddb_rb32_t	*rbp;
	size_t		newreqsize;
	hot_spare_t	*b_hs;
	hot_spare32_od_t *s_hs;

	mddb_setrecprivate(recid, MD_PRV_GOTIT);

	dep = mddb_getrecdep(recid);
	dep->de_flags = MDDB_F_HOTSPARE;
	rbp = dep->de_rb;
	switch (rbp->rb_revision) {
	case MDDB_REV_RB:
	case MDDB_REV_RBFN:
		/*
		 * Needs to convert to internal 64 bit
		 */
		s_hs = (hot_spare32_od_t *)mddb_getrecaddr(recid);
		newreqsize = sizeof (hot_spare_t);
		b_hs = (hot_spare_t *)kmem_zalloc(newreqsize, KM_SLEEP);
		hs_convert((caddr_t)s_hs, (caddr_t)b_hs, SMALL_2_BIG);
		kmem_free(s_hs, dep->de_reqsize);
		dep->de_rb_userdata = b_hs;
		dep->de_reqsize = newreqsize;
		hs = b_hs;
		break;
	case MDDB_REV_RB64:
	case MDDB_REV_RB64FN:
		hs = (hot_spare_t *)mddb_getrecaddr_resize
			(recid, sizeof (*hs), 0);
		break;
	}
	MDDB_NOTE_FN(rbp->rb_revision, hs->hs_revision);

#if defined(_ILP32)
	if (hs->hs_revision & MD_64BIT_META_DEV) {
		char	devname[MD_MAX_CTDLEN];

		set_hot_spare_state(hs, HSS_BROKEN);
		(void) md_devname(setno, hs->hs_devnum, devname,
		    sizeof (devname));
		cmn_err(CE_NOTE, "%s is unavailable because 64 bit hotspares "
		    "are not accessible on a 32 bit kernel\n", devname);
	}
#endif

	ASSERT(hs != NULL);

	if (hs->hs_refcount == 0) {
		mddb_setrecprivate(recid, MD_PRV_PENDDEL);
		return;
	}

	hs->hs_next = (hot_spare_t *)md_set[setno].s_hs;
	md_set[setno].s_hs = (void *)hs;

	hs->hs_isopen = 0;

	hs->hs_devnum = md_getdevnum(setno, mddb_getsidenum(setno),
		hs->hs_key, MD_NOTRUST_DEVT);
}


static void
load_hotsparepool(set_t setno, mddb_recid_t recid)
{
	hot_spare_pool_t *hsp;
	hot_spare_pool_ond_t *hsp_ond;
	size_t hsp_icsize;

	mddb_setrecprivate(recid, MD_PRV_GOTIT);

	hsp_ond = (hot_spare_pool_ond_t *)mddb_getrecaddr(recid);
	ASSERT(hsp_ond != NULL);

	if (hsp_ond->hsp_self_id == MD_HSP_NONE) {
		mddb_setrecprivate(recid, MD_PRV_PENDDEL);
		return;
	}

	hsp_icsize =  HSP_ONDSK_STR_OFF + mddb_getrecsize(recid);

	hsp = (hot_spare_pool_t *)mddb_getrecaddr_resize(recid, hsp_icsize,
		HSP_ONDSK_STR_OFF);
	hsp->hsp_next = (hot_spare_pool_t *)md_set[setno].s_hsp;
	md_set[setno].s_hsp = (void *) hsp;

	rw_enter(&hotspares_md_ops.md_link_rw.lock, RW_WRITER);
	hsp->hsp_link.ln_next = hotspares_md_ops.md_head;
	hsp->hsp_link.ln_setno = setno;
	hsp->hsp_link.ln_id = hsp->hsp_self_id;
	hotspares_md_ops.md_head = &hsp->hsp_link;
	rw_exit(&hotspares_md_ops.md_link_rw.lock);
}

static int
hotspares_snarf(md_snarfcmd_t cmd, set_t setno)
{
	mddb_recid_t	recid;
	int		gotsomething;
	mddb_type_t	typ1;

	if (cmd == MD_SNARF_CLEANUP)
		return (0);

	gotsomething = 0;

	typ1 = (mddb_type_t)md_getshared_key(setno,
	    hotspares_md_ops.md_driver.md_drivername);
	recid = mddb_makerecid(setno, 0);
	while ((recid = mddb_getnextrec(recid, typ1, 0)) > 0) {
		if (mddb_getrecprivate(recid) & MD_PRV_GOTIT)
			continue;

		switch (mddb_getrectype2(recid)) {
		case HSP_REC:
			load_hotsparepool(setno, recid);
			gotsomething = 1;
			break;
		case HS_REC:
			load_hotspare(setno, recid);
			gotsomething = 1;
			break;
		default:
			ASSERT(0);
		}
	}

	if (gotsomething)
		return (gotsomething);

	recid = mddb_makerecid(setno, 0);
	while ((recid = mddb_getnextrec(recid, typ1, 0)) > 0)
		if (!(mddb_getrecprivate(recid) & MD_PRV_GOTIT))
			mddb_setrecprivate(recid, MD_PRV_PENDDEL);

	return (0);
}

static int
hotspares_halt(md_haltcmd_t cmd, set_t setno)
{
	hot_spare_t		*hs, **p_hs;
	hot_spare_pool_t	*hsp, **p_hsp;

	if (cmd == MD_HALT_CLOSE)
		return (0);

	if (cmd == MD_HALT_OPEN)
		return (0);

	if (cmd == MD_HALT_CHECK)
		return (0);

	if (cmd == MD_HALT_UNLOAD)
		return (0);

	if (cmd != MD_HALT_DOIT)
		return (1);
	/*
	 * Find all the hotspares for set "setno"
	 *   and remove them from the hot_spare_list.
	 */
	p_hs = (hot_spare_t **)&md_set[setno].s_hs;
	hs = (hot_spare_t *)md_set[setno].s_hs;
	for (; hs != NULL; hs = *p_hs)
		*p_hs = hs->hs_next;

	/*
	 * Find all the hotspare pools for set "setno"
	 *   and remove them from the hot_spare_pools list.
	 * Also remove from the get_next list.
	 */
	p_hsp = (hot_spare_pool_t **)&md_set[setno].s_hsp;
	hsp = (hot_spare_pool_t *)md_set[setno].s_hsp;
	for (; hsp != NULL; hsp = *p_hsp) {
		md_rem_link(setno, hsp->hsp_self_id,
		    &hotspares_md_ops.md_link_rw.lock,
		    &hotspares_md_ops.md_head);
		*p_hsp = hsp->hsp_next;
	}

	return (0);
}

static hot_spare_t *
usable_hs(
	set_t		setno,
	mddb_recid_t	hs_id,
	diskaddr_t	nblks,
	int		labeled,
	diskaddr_t	*start)
{
	hot_spare_t	*hs;

	hs = lookup_hot_spare(setno, hs_id, 1);

	if (hs->hs_state != HSS_AVAILABLE)
		return ((hot_spare_t *)0);

	if (labeled && hs->hs_has_label && (hs->hs_number_blks >= nblks)) {
		*start = 0;
		return (hs);
	} else if ((hs->hs_number_blks - hs->hs_start_blk) >= nblks) {
		*start = hs->hs_start_blk;
		return (hs);
	}
	return ((hot_spare_t *)0);
}

static int
reserve_a_hs(
	set_t		setno,
	mddb_recid_t	id,
	uint64_t	size,
	int		labeled,
	mddb_recid_t	*hs_id,
	mdkey_t		*key,
	md_dev64_t	*dev,
	diskaddr_t	*sblock)
{
	hot_spare_pool_t	*hsp;
	hot_spare_t		*hs;
	int			i;

	*hs_id = 0;

	hsp = find_hot_spare_pool(setno, id);
	if (hsp == NULL)
		return (-1);

	for (i = 0; i < hsp->hsp_nhotspares; i++) {
		hs = usable_hs(setno, hsp->hsp_hotspares[i],
		    size, labeled, sblock);
		if (hs == NULL)
			continue;

		set_hot_spare_state(hs, HSS_RESERVED);
		*hs_id = hs->hs_record_id;
		*key = hs->hs_key;
		*dev = hs->hs_devnum;
		/* NOTE: Mirror code commits the hs record */
		return (0);
	}

	return (-1);
}


/* ARGSUSED3 */
static int
return_a_hs(
	set_t			setno,
	mddb_recid_t		id,
	mddb_recid_t		*hs_id,
	mdkey_t			key,
	diskaddr_t		sblock,
	uint64_t		size,
	hotspare_states_t	new_state)
{
	hot_spare_pool_t	*hsp;
	hot_spare_t		*hs;
	int			i;

	/*
	 * NOTE: sblock/size are not currently being used.
	 *	 That is because we always allocate the whole hs.
	 *	 Later if we choose to allocate only what is needed
	 *	 then the sblock/size can be used to determine
	 *	 which part is being unreseved.
	 */
	*hs_id = 0;

	hsp = find_hot_spare_pool(setno, id);
	if (hsp == NULL)
		return (-1);

	for (i = 0; i < hsp->hsp_nhotspares; i++) {
		hs = lookup_hot_spare(setno, hsp->hsp_hotspares[i], 1);
		if (hs->hs_key != key)
			continue;

		set_hot_spare_state(hs, new_state);
		*hs_id = hs->hs_record_id;
		if (new_state == HSS_BROKEN) {
			SE_NOTIFY(EC_SVM_STATE, ESC_SVM_ERRED, SVM_TAG_HS,
			    setno, hs->hs_devnum);
		}
		if (new_state == HSS_AVAILABLE) {
			SE_NOTIFY(EC_SVM_STATE, ESC_SVM_HS_FREED, SVM_TAG_HS,
			    setno, hs->hs_devnum);
		}

		/* NOTE: Mirror/Raid code commits the hs record */
		return (0);
	}

	return (-1);
}


static int
modify_hsp_ref(set_t setno, mddb_recid_t id, int incref,  mddb_recid_t *hsp_id)
{
	hot_spare_pool_t	*hsp;

	*hsp_id = 0;

	if (id  < 0)
		return (0);

	hsp = find_hot_spare_pool(setno, id);
	if (hsp == NULL)
		return (-1);

	if (incref)
		hsp->hsp_refcount++;
	else
		hsp->hsp_refcount--;

	*hsp_id = hsp->hsp_record_id;

	/* NOTE: Stripe code commits the hsp record */
	return (0);
}


static int
mkdev_for_a_hs(mddb_recid_t hs_id, md_dev64_t *dev)
{
	hot_spare_t	*hs;

	hs = lookup_hot_spare(mddb_getsetnum(hs_id), hs_id, 0);
	if (hs == NULL)
		return (0);

	*dev = hs->hs_devnum;
	return (0);
}

static intptr_t
hotspares_interface(
	hs_cmds_t	cmd,
	mddb_recid_t	id,
	uint64_t	size,
	int		bool,
	mddb_recid_t	*hs_id,
	mdkey_t		*key,
	md_dev64_t	*dev,
	diskaddr_t	*sblock)
{
	set_t	setno;
	int	err = -1;

	mutex_enter(&md_mx);
	while (md_status & MD_GBL_HS_LOCK)
		cv_wait(&md_cv, &md_mx);

	/* If md_halt has been run do not continue */
	if (md_status & (MD_GBL_HALTED | MD_GBL_DAEMONS_DIE)) {
		mutex_exit(&md_mx);
		return (ENXIO);
	}

	md_status |= MD_GBL_HS_LOCK;
	mutex_exit(&md_mx);

	setno = mddb_getsetnum(id);

	switch (cmd) {
	case HS_GET:
		err = reserve_a_hs(setno, id, size, bool, hs_id,
		    key, dev, sblock);
		break;
	case HS_FREE:
		err = return_a_hs(setno, id, hs_id, *key, 0, 0, HSS_AVAILABLE);
		hotspares_poke_hotspares();
		break;
	case HS_BAD:
		err = return_a_hs(setno, id, hs_id, *key, 0, 0, HSS_BROKEN);
		break;
	case HSP_INCREF:
		err = modify_hsp_ref(setno, id, 1, hs_id);
		break;
	case HSP_DECREF:
		err = modify_hsp_ref(setno, id, 0, hs_id);
		break;
	case HS_MKDEV:
		err = mkdev_for_a_hs(*hs_id, dev);
		break;
	}

	mutex_enter(&md_mx);
	md_status &= ~MD_GBL_HS_LOCK;
	cv_broadcast(&md_cv);
	mutex_exit(&md_mx);

	return (err);
}

static void
imp_hotsparepool(
	set_t	setno,
	mddb_recid_t	recid
)
{
	hot_spare_pool_ond_t	*hsp_ond;
	mddb_recid_t		*hsp_recid, *hs_recid;
	int			i;
	uint_t			*hsp_selfid;

	mddb_setrecprivate(recid, MD_PRV_GOTIT);

	hsp_ond = (hot_spare_pool_ond_t *)mddb_getrecaddr(recid);
	hsp_recid = &(hsp_ond->hsp_record_id);
	hsp_selfid = &(hsp_ond->hsp_self_id);
	/*
	 * Fixup the pool and hotspares
	 */
	*hsp_recid = MAKERECID(setno, DBID(*hsp_recid));
	*hsp_selfid = MAKERECID(setno, DBID(*hsp_selfid));

	for (i = 0; i < hsp_ond->hsp_nhotspares; i++) {
		hs_recid = &(hsp_ond->hsp_hotspares[i]);
		*hs_recid = MAKERECID(setno, DBID(*hs_recid));
	}
}

static void
imp_hotspare(
	set_t	setno,
	mddb_recid_t	recid
)
{
	mddb_de_ic_t	*dep;
	mddb_rb32_t	*rbp;
	hot_spare_t	*hs64;
	hot_spare32_od_t	*hs32;
	mddb_recid_t	*hs_recid;

	mddb_setrecprivate(recid, MD_PRV_GOTIT);

	dep = mddb_getrecdep(recid);
	rbp = dep->de_rb;
	switch (rbp->rb_revision) {
	case MDDB_REV_RB:
	case MDDB_REV_RBFN:
		/*
		 * 32 bit hotspare
		 */
		hs32 = (hot_spare32_od_t *)mddb_getrecaddr(recid);
		hs_recid = &(hs32->hs_record_id);
		break;
	case MDDB_REV_RB64:
	case MDDB_REV_RB64FN:
		hs64 = (hot_spare_t *)mddb_getrecaddr(recid);
		hs_recid = &(hs64->hs_record_id);
		break;
	}

	/*
	 * Fixup the setno
	 */
	*hs_recid = MAKERECID(setno, DBID(*hs_recid));
}

static int
hotspares_imp_set(
	set_t	setno
)
{
	mddb_recid_t	recid;
	int		gotsomething;
	mddb_type_t	typ1;


	gotsomething = 0;

	typ1 = (mddb_type_t)md_getshared_key(setno,
	    hotspares_md_ops.md_driver.md_drivername);
	recid = mddb_makerecid(setno, 0);
	while ((recid = mddb_getnextrec(recid, typ1, 0)) > 0) {
		if (mddb_getrecprivate(recid) & MD_PRV_GOTIT)
			continue;

		switch (mddb_getrectype2(recid)) {
		case HSP_REC:
			imp_hotsparepool(setno, recid);
			gotsomething = 1;
			break;
		case HS_REC:
			imp_hotspare(setno, recid);
			gotsomething = 1;
			break;
		default:
			ASSERT(0);
		}
	}

	return (gotsomething);
}

static md_named_services_t hotspares_named_services[] = {
	{hotspares_interface,	"hot spare interface"},
	{NULL,			0}
};

md_ops_t hotspares_md_ops = {
	NULL,			/* open */
	NULL,			/* close */
	NULL,			/* strategy */
	NULL,			/* print */
	NULL,			/* dump */
	NULL,			/* read */
	NULL,			/* write */
	hotspares_ioctl,	/* hotspares_ioctl, */
	hotspares_snarf,	/* hotspares_snarf */
	hotspares_halt,		/* halt */
	NULL,			/* aread */
	NULL,			/* awrite */
	hotspares_imp_set,	/* import set */
	hotspares_named_services /* named_services */
};

static void
fini_uninit()
{
	/* prevent access to services that may have been imported */
	md_clear_hot_spare_interface();
}

/* define the module linkage */
MD_PLUGIN_MISC_MODULE("hot spares module", md_noop, fini_uninit())
