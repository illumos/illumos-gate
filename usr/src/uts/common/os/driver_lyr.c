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
 * Copyright (c) 1994, 2010, Oracle and/or its affiliates. All rights reserved.
 */
/*
 * Copyright (c) 2013, Joyent, Inc.  All rights reserved.
 */

/*
 * Layered driver support.
 */

#include <sys/atomic.h>
#include <sys/types.h>
#include <sys/t_lock.h>
#include <sys/param.h>
#include <sys/conf.h>
#include <sys/systm.h>
#include <sys/sysmacros.h>
#include <sys/buf.h>
#include <sys/cred.h>
#include <sys/uio.h>
#include <sys/vnode.h>
#include <sys/fs/snode.h>
#include <sys/open.h>
#include <sys/kmem.h>
#include <sys/file.h>
#include <sys/bootconf.h>
#include <sys/pathname.h>
#include <sys/bitmap.h>
#include <sys/stat.h>
#include <sys/dditypes.h>
#include <sys/ddi_impldefs.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/esunddi.h>
#include <sys/autoconf.h>
#include <sys/sunldi.h>
#include <sys/sunldi_impl.h>
#include <sys/errno.h>
#include <sys/debug.h>
#include <sys/modctl.h>
#include <sys/var.h>
#include <vm/seg_vn.h>

#include <sys/stropts.h>
#include <sys/strsubr.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/kstr.h>

/*
 * Device contract related
 */
#include <sys/contract_impl.h>
#include <sys/contract/device_impl.h>

/*
 * Define macros to manipulate snode, vnode, and open device flags
 */
#define	VTYP_VALID(i)	(((i) == VCHR) || ((i) == VBLK))
#define	VTYP_TO_OTYP(i)	(((i) == VCHR) ? OTYP_CHR : OTYP_BLK)
#define	VTYP_TO_STYP(i)	(((i) == VCHR) ? S_IFCHR : S_IFBLK)

#define	OTYP_VALID(i)	(((i) == OTYP_CHR) || ((i) == OTYP_BLK))
#define	OTYP_TO_VTYP(i)	(((i) == OTYP_CHR) ? VCHR : VBLK)
#define	OTYP_TO_STYP(i)	(((i) == OTYP_CHR) ? S_IFCHR : S_IFBLK)

#define	STYP_VALID(i)	(((i) == S_IFCHR) || ((i) == S_IFBLK))
#define	STYP_TO_VTYP(i)	(((i) == S_IFCHR) ? VCHR : VBLK)

/*
 * Define macros for accessing layered driver hash structures
 */
#define	LH_HASH(vp)		(handle_hash_func(vp) % LH_HASH_SZ)
#define	LI_HASH(mid, dip, dev)	(ident_hash_func(mid, dip, dev) % LI_HASH_SZ)

/*
 * Define layered handle flags used in the lh_type field
 */
#define	LH_STREAM	(0x1)	/* handle to a streams device */
#define	LH_CBDEV	(0x2)	/* handle to a char/block device */

/*
 * Define macro for devid property lookups
 */
#define	DEVID_PROP_FLAGS	(DDI_PROP_DONTPASS | \
				DDI_PROP_TYPE_STRING|DDI_PROP_CANSLEEP)

/*
 * Dummy string for NDI events
 */
#define	NDI_EVENT_SERVICE	"NDI_EVENT_SERVICE"

static void ldi_ev_lock(void);
static void ldi_ev_unlock(void);

#ifdef	LDI_OBSOLETE_EVENT
int ldi_remove_event_handler(ldi_handle_t lh, ldi_callback_id_t id);
#endif


/*
 * globals
 */
static kmutex_t			ldi_ident_hash_lock[LI_HASH_SZ];
static struct ldi_ident		*ldi_ident_hash[LI_HASH_SZ];

static kmutex_t			ldi_handle_hash_lock[LH_HASH_SZ];
static struct ldi_handle	*ldi_handle_hash[LH_HASH_SZ];
static size_t			ldi_handle_hash_count;

/*
 * Use of "ldi_ev_callback_list" must be protected by ldi_ev_lock()
 * and ldi_ev_unlock().
 */
static struct ldi_ev_callback_list ldi_ev_callback_list;

static uint32_t ldi_ev_id_pool = 0;

struct ldi_ev_cookie {
	char *ck_evname;
	uint_t ck_sync;
	uint_t ck_ctype;
};

static struct ldi_ev_cookie ldi_ev_cookies[] = {
	{ LDI_EV_OFFLINE, 1, CT_DEV_EV_OFFLINE},
	{ LDI_EV_DEGRADE, 0, CT_DEV_EV_DEGRADED},
	{ LDI_EV_DEVICE_REMOVE, 0, 0},
	{ NULL}			/* must terminate list */
};

void
ldi_init(void)
{
	int i;

	ldi_handle_hash_count = 0;
	for (i = 0; i < LH_HASH_SZ; i++) {
		mutex_init(&ldi_handle_hash_lock[i], NULL, MUTEX_DEFAULT, NULL);
		ldi_handle_hash[i] = NULL;
	}
	for (i = 0; i < LI_HASH_SZ; i++) {
		mutex_init(&ldi_ident_hash_lock[i], NULL, MUTEX_DEFAULT, NULL);
		ldi_ident_hash[i] = NULL;
	}

	/*
	 * Initialize the LDI event subsystem
	 */
	mutex_init(&ldi_ev_callback_list.le_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&ldi_ev_callback_list.le_cv, NULL, CV_DEFAULT, NULL);
	ldi_ev_callback_list.le_busy = 0;
	ldi_ev_callback_list.le_thread = NULL;
	ldi_ev_callback_list.le_walker_next = NULL;
	ldi_ev_callback_list.le_walker_prev = NULL;
	list_create(&ldi_ev_callback_list.le_head,
	    sizeof (ldi_ev_callback_impl_t),
	    offsetof(ldi_ev_callback_impl_t, lec_list));
}

/*
 * LDI ident manipulation functions
 */
static uint_t
ident_hash_func(modid_t modid, dev_info_t *dip, dev_t dev)
{
	if (dip != NULL) {
		uintptr_t k = (uintptr_t)dip;
		k >>= (int)highbit(sizeof (struct dev_info));
		return ((uint_t)k);
	} else if (dev != DDI_DEV_T_NONE) {
		return (modid + getminor(dev) + getmajor(dev));
	} else {
		return (modid);
	}
}

static struct ldi_ident **
ident_find_ref_nolock(modid_t modid, dev_info_t *dip, dev_t dev, major_t major)
{
	struct ldi_ident	**lipp = NULL;
	uint_t			index = LI_HASH(modid, dip, dev);

	ASSERT(MUTEX_HELD(&ldi_ident_hash_lock[index]));

	for (lipp = &(ldi_ident_hash[index]);
	    (*lipp != NULL);
	    lipp = &((*lipp)->li_next)) {
		if (((*lipp)->li_modid == modid) &&
		    ((*lipp)->li_major == major) &&
		    ((*lipp)->li_dip == dip) &&
		    ((*lipp)->li_dev == dev))
			break;
	}

	ASSERT(lipp != NULL);
	return (lipp);
}

static struct ldi_ident *
ident_alloc(char *mod_name, dev_info_t *dip, dev_t dev, major_t major)
{
	struct ldi_ident	*lip, **lipp, *retlip;
	modid_t			modid;
	uint_t			index;

	ASSERT(mod_name != NULL);

	/* get the module id */
	modid = mod_name_to_modid(mod_name);
	ASSERT(modid != -1);

	/* allocate a new ident in case we need it */
	lip = kmem_zalloc(sizeof (*lip), KM_SLEEP);

	/* search the hash for a matching ident */
	index = LI_HASH(modid, dip, dev);
	mutex_enter(&ldi_ident_hash_lock[index]);
	lipp = ident_find_ref_nolock(modid, dip, dev, major);

	if (*lipp != NULL) {
		/* we found an ident in the hash */
		ASSERT(strcmp((*lipp)->li_modname, mod_name) == 0);
		(*lipp)->li_ref++;
		retlip = *lipp;
		mutex_exit(&ldi_ident_hash_lock[index]);
		kmem_free(lip, sizeof (struct ldi_ident));
		return (retlip);
	}

	/* initialize the new ident */
	lip->li_next = NULL;
	lip->li_ref = 1;
	lip->li_modid = modid;
	lip->li_major = major;
	lip->li_dip = dip;
	lip->li_dev = dev;
	(void) strncpy(lip->li_modname, mod_name, sizeof (lip->li_modname) - 1);

	/* add it to the ident hash */
	lip->li_next = ldi_ident_hash[index];
	ldi_ident_hash[index] = lip;

	mutex_exit(&ldi_ident_hash_lock[index]);
	return (lip);
}

static void
ident_hold(struct ldi_ident *lip)
{
	uint_t			index;

	ASSERT(lip != NULL);
	index = LI_HASH(lip->li_modid, lip->li_dip, lip->li_dev);
	mutex_enter(&ldi_ident_hash_lock[index]);
	ASSERT(lip->li_ref > 0);
	lip->li_ref++;
	mutex_exit(&ldi_ident_hash_lock[index]);
}

static void
ident_release(struct ldi_ident *lip)
{
	struct ldi_ident	**lipp;
	uint_t			index;

	ASSERT(lip != NULL);
	index = LI_HASH(lip->li_modid, lip->li_dip, lip->li_dev);
	mutex_enter(&ldi_ident_hash_lock[index]);

	ASSERT(lip->li_ref > 0);
	if (--lip->li_ref > 0) {
		/* there are more references to this ident */
		mutex_exit(&ldi_ident_hash_lock[index]);
		return;
	}

	/* this was the last reference/open for this ident.  free it. */
	lipp = ident_find_ref_nolock(
	    lip->li_modid, lip->li_dip, lip->li_dev, lip->li_major);

	ASSERT((lipp != NULL) && (*lipp != NULL));
	*lipp = lip->li_next;
	mutex_exit(&ldi_ident_hash_lock[index]);
	kmem_free(lip, sizeof (struct ldi_ident));
}

/*
 * LDI handle manipulation functions
 */
static uint_t
handle_hash_func(void *vp)
{
	uintptr_t k = (uintptr_t)vp;
	k >>= (int)highbit(sizeof (vnode_t));
	return ((uint_t)k);
}

static struct ldi_handle **
handle_find_ref_nolock(vnode_t *vp, struct ldi_ident *ident)
{
	struct ldi_handle	**lhpp = NULL;
	uint_t			index = LH_HASH(vp);

	ASSERT(MUTEX_HELD(&ldi_handle_hash_lock[index]));

	for (lhpp = &(ldi_handle_hash[index]);
	    (*lhpp != NULL);
	    lhpp = &((*lhpp)->lh_next)) {
		if (((*lhpp)->lh_ident == ident) &&
		    ((*lhpp)->lh_vp == vp))
			break;
	}

	ASSERT(lhpp != NULL);
	return (lhpp);
}

static struct ldi_handle *
handle_find(vnode_t *vp, struct ldi_ident *ident)
{
	struct ldi_handle	**lhpp, *retlhp;
	int			index = LH_HASH(vp);

	mutex_enter(&ldi_handle_hash_lock[index]);
	lhpp = handle_find_ref_nolock(vp, ident);
	retlhp = *lhpp;
	mutex_exit(&ldi_handle_hash_lock[index]);
	return (retlhp);
}

static struct ldi_handle *
handle_alloc(vnode_t *vp, struct ldi_ident *ident)
{
	struct ldi_handle	*lhp, **lhpp, *retlhp;
	uint_t			index;

	ASSERT((vp != NULL) && (ident != NULL));

	/* allocate a new handle in case we need it */
	lhp = kmem_zalloc(sizeof (*lhp), KM_SLEEP);

	/* search the hash for a matching handle */
	index = LH_HASH(vp);
	mutex_enter(&ldi_handle_hash_lock[index]);
	lhpp = handle_find_ref_nolock(vp, ident);

	if (*lhpp != NULL) {
		/* we found a handle in the hash */
		(*lhpp)->lh_ref++;
		retlhp = *lhpp;
		mutex_exit(&ldi_handle_hash_lock[index]);

		LDI_ALLOCFREE((CE_WARN, "ldi handle alloc: dup "
		    "lh=0x%p, ident=0x%p, vp=0x%p, drv=%s, minor=0x%x",
		    (void *)retlhp, (void *)ident, (void *)vp,
		    mod_major_to_name(getmajor(vp->v_rdev)),
		    getminor(vp->v_rdev)));

		kmem_free(lhp, sizeof (struct ldi_handle));
		return (retlhp);
	}

	/* initialize the new handle */
	lhp->lh_ref = 1;
	lhp->lh_vp = vp;
	lhp->lh_ident = ident;
#ifdef	LDI_OBSOLETE_EVENT
	mutex_init(lhp->lh_lock, NULL, MUTEX_DEFAULT, NULL);
#endif

	/* set the device type for this handle */
	lhp->lh_type = 0;
	if (vp->v_stream) {
		ASSERT(vp->v_type == VCHR);
		lhp->lh_type |= LH_STREAM;
	} else {
		lhp->lh_type |= LH_CBDEV;
	}

	/* get holds on other objects */
	ident_hold(ident);
	ASSERT(vp->v_count >= 1);
	VN_HOLD(vp);

	/* add it to the handle hash */
	lhp->lh_next = ldi_handle_hash[index];
	ldi_handle_hash[index] = lhp;
	atomic_inc_ulong(&ldi_handle_hash_count);

	LDI_ALLOCFREE((CE_WARN, "ldi handle alloc: new "
	    "lh=0x%p, ident=0x%p, vp=0x%p, drv=%s, minor=0x%x",
	    (void *)lhp, (void *)ident, (void *)vp,
	    mod_major_to_name(getmajor(vp->v_rdev)),
	    getminor(vp->v_rdev)));

	mutex_exit(&ldi_handle_hash_lock[index]);
	return (lhp);
}

static void
handle_release(struct ldi_handle *lhp)
{
	struct ldi_handle	**lhpp;
	uint_t			index;

	ASSERT(lhp != NULL);

	index = LH_HASH(lhp->lh_vp);
	mutex_enter(&ldi_handle_hash_lock[index]);

	LDI_ALLOCFREE((CE_WARN, "ldi handle release: "
	    "lh=0x%p, ident=0x%p, vp=0x%p, drv=%s, minor=0x%x",
	    (void *)lhp, (void *)lhp->lh_ident, (void *)lhp->lh_vp,
	    mod_major_to_name(getmajor(lhp->lh_vp->v_rdev)),
	    getminor(lhp->lh_vp->v_rdev)));

	ASSERT(lhp->lh_ref > 0);
	if (--lhp->lh_ref > 0) {
		/* there are more references to this handle */
		mutex_exit(&ldi_handle_hash_lock[index]);
		return;
	}

	/* this was the last reference/open for this handle.  free it. */
	lhpp = handle_find_ref_nolock(lhp->lh_vp, lhp->lh_ident);
	ASSERT((lhpp != NULL) && (*lhpp != NULL));
	*lhpp = lhp->lh_next;
	atomic_dec_ulong(&ldi_handle_hash_count);
	mutex_exit(&ldi_handle_hash_lock[index]);

	VN_RELE(lhp->lh_vp);
	ident_release(lhp->lh_ident);
#ifdef	LDI_OBSOLETE_EVENT
	mutex_destroy(lhp->lh_lock);
#endif
	kmem_free(lhp, sizeof (struct ldi_handle));
}

#ifdef	LDI_OBSOLETE_EVENT
/*
 * LDI event manipulation functions
 */
static void
handle_event_add(ldi_event_t *lep)
{
	struct ldi_handle *lhp = lep->le_lhp;

	ASSERT(lhp != NULL);

	mutex_enter(lhp->lh_lock);
	if (lhp->lh_events == NULL) {
		lhp->lh_events = lep;
		mutex_exit(lhp->lh_lock);
		return;
	}

	lep->le_next = lhp->lh_events;
	lhp->lh_events->le_prev = lep;
	lhp->lh_events = lep;
	mutex_exit(lhp->lh_lock);
}

static void
handle_event_remove(ldi_event_t *lep)
{
	struct ldi_handle *lhp = lep->le_lhp;

	ASSERT(lhp != NULL);

	mutex_enter(lhp->lh_lock);
	if (lep->le_prev)
		lep->le_prev->le_next = lep->le_next;
	if (lep->le_next)
		lep->le_next->le_prev = lep->le_prev;
	if (lhp->lh_events == lep)
		lhp->lh_events = lep->le_next;
	mutex_exit(lhp->lh_lock);

}

static void
i_ldi_callback(dev_info_t *dip, ddi_eventcookie_t event_cookie,
    void *arg, void *bus_impldata)
{
	ldi_event_t *lep = (ldi_event_t *)arg;

	ASSERT(lep != NULL);

	LDI_EVENTCB((CE_NOTE, "%s: dip=0x%p, "
	    "event_cookie=0x%p, ldi_eventp=0x%p", "i_ldi_callback",
	    (void *)dip, (void *)event_cookie, (void *)lep));

	lep->le_handler(lep->le_lhp, event_cookie, lep->le_arg, bus_impldata);
}
#endif

/*
 * LDI open helper functions
 */

/* get a vnode to a device by dev_t and otyp */
static int
ldi_vp_from_dev(dev_t dev, int otyp, vnode_t **vpp)
{
	dev_info_t		*dip;
	vnode_t			*vp;

	/* sanity check required input parameters */
	if ((dev == DDI_DEV_T_NONE) || (!OTYP_VALID(otyp)) || (vpp == NULL))
		return (EINVAL);

	if ((dip = e_ddi_hold_devi_by_dev(dev, 0)) == NULL)
		return (ENODEV);

	vp = makespecvp(dev, OTYP_TO_VTYP(otyp));
	spec_assoc_vp_with_devi(vp, dip);
	ddi_release_devi(dip);  /* from e_ddi_hold_devi_by_dev */

	*vpp = vp;
	return (0);
}

/* get a vnode to a device by pathname */
int
ldi_vp_from_name(char *path, vnode_t **vpp)
{
	vnode_t			*vp = NULL;
	int			ret;

	/* sanity check required input parameters */
	if ((path == NULL) || (vpp == NULL))
		return (EINVAL);

	if (modrootloaded) {
		cred_t *saved_cred = curthread->t_cred;

		/* we don't want lookupname to fail because of credentials */
		curthread->t_cred = kcred;

		/*
		 * all lookups should be done in the global zone.  but
		 * lookupnameat() won't actually do this if an absolute
		 * path is passed in.  since the ldi interfaces require an
		 * absolute path we pass lookupnameat() a pointer to
		 * the character after the leading '/' and tell it to
		 * start searching at the current system root directory.
		 */
		ASSERT(*path == '/');
		ret = lookupnameat(path + 1, UIO_SYSSPACE, FOLLOW, NULLVPP,
		    &vp, rootdir);

		/* restore this threads credentials */
		curthread->t_cred = saved_cred;

		if (ret == 0) {
			if (!vn_matchops(vp, spec_getvnodeops()) ||
			    !VTYP_VALID(vp->v_type)) {
				VN_RELE(vp);
				return (ENXIO);
			}
		}
	}

	if (vp == NULL) {
		dev_info_t	*dip;
		dev_t		dev;
		int		spec_type;

		/*
		 * Root is not mounted, the minor node is not specified,
		 * or an OBP path has been specified.
		 */

		/*
		 * Determine if path can be pruned to produce an
		 * OBP or devfs path for resolve_pathname.
		 */
		if (strncmp(path, "/devices/", 9) == 0)
			path += strlen("/devices");

		/*
		 * if no minor node was specified the DEFAULT minor node
		 * will be returned.  if there is no DEFAULT minor node
		 * one will be fabricated of type S_IFCHR with the minor
		 * number equal to the instance number.
		 */
		ret = resolve_pathname(path, &dip, &dev, &spec_type);
		if (ret != 0)
			return (ENODEV);

		ASSERT(STYP_VALID(spec_type));
		vp = makespecvp(dev, STYP_TO_VTYP(spec_type));
		spec_assoc_vp_with_devi(vp, dip);
		ddi_release_devi(dip);
	}

	*vpp = vp;
	return (0);
}

static int
ldi_devid_match(ddi_devid_t devid, dev_info_t *dip, dev_t dev)
{
	char		*devidstr;
	ddi_prop_t	*propp;

	/* convert devid as a string property */
	if ((devidstr = ddi_devid_str_encode(devid, NULL)) == NULL)
		return (0);

	/*
	 * Search for the devid.  For speed and ease in locking this
	 * code directly uses the property implementation.  See
	 * ddi_common_devid_to_devlist() for a comment as to why.
	 */
	mutex_enter(&(DEVI(dip)->devi_lock));

	/* check if there is a DDI_DEV_T_NONE devid property */
	propp = i_ddi_prop_search(DDI_DEV_T_NONE,
	    DEVID_PROP_NAME, DEVID_PROP_FLAGS, &DEVI(dip)->devi_hw_prop_ptr);
	if (propp != NULL) {
		if (ddi_devid_str_compare(propp->prop_val, devidstr) == 0) {
			/* a DDI_DEV_T_NONE devid exists and matchs */
			mutex_exit(&(DEVI(dip)->devi_lock));
			ddi_devid_str_free(devidstr);
			return (1);
		} else {
			/* a DDI_DEV_T_NONE devid exists and doesn't match */
			mutex_exit(&(DEVI(dip)->devi_lock));
			ddi_devid_str_free(devidstr);
			return (0);
		}
	}

	/* check if there is a devt specific devid property */
	propp = i_ddi_prop_search(dev,
	    DEVID_PROP_NAME, DEVID_PROP_FLAGS, &(DEVI(dip)->devi_hw_prop_ptr));
	if (propp != NULL) {
		if (ddi_devid_str_compare(propp->prop_val, devidstr) == 0) {
			/* a devt specific devid exists and matchs */
			mutex_exit(&(DEVI(dip)->devi_lock));
			ddi_devid_str_free(devidstr);
			return (1);
		} else {
			/* a devt specific devid exists and doesn't match */
			mutex_exit(&(DEVI(dip)->devi_lock));
			ddi_devid_str_free(devidstr);
			return (0);
		}
	}

	/* we didn't find any devids associated with the device */
	mutex_exit(&(DEVI(dip)->devi_lock));
	ddi_devid_str_free(devidstr);
	return (0);
}

/* get a handle to a device by devid and minor name */
int
ldi_vp_from_devid(ddi_devid_t devid, char *minor_name, vnode_t **vpp)
{
	dev_info_t		*dip;
	vnode_t			*vp;
	int			ret, i, ndevs, styp;
	dev_t			dev, *devs;

	/* sanity check required input parameters */
	if ((devid == NULL) || (minor_name == NULL) || (vpp == NULL))
		return (EINVAL);

	ret = ddi_lyr_devid_to_devlist(devid, minor_name, &ndevs, &devs);
	if ((ret != DDI_SUCCESS) || (ndevs <= 0))
		return (ENODEV);

	for (i = 0; i < ndevs; i++) {
		dev = devs[i];

		if ((dip = e_ddi_hold_devi_by_dev(dev, 0)) == NULL)
			continue;

		/*
		 * now we have to verify that the devid of the disk
		 * still matches what was requested.
		 *
		 * we have to do this because the devid could have
		 * changed between the call to ddi_lyr_devid_to_devlist()
		 * and e_ddi_hold_devi_by_dev().  this is because when
		 * ddi_lyr_devid_to_devlist() returns a list of devts
		 * there is no kind of hold on those devts so a device
		 * could have been replaced out from under us in the
		 * interim.
		 */
		if ((i_ddi_minorname_to_devtspectype(dip, minor_name,
		    NULL, &styp) == DDI_SUCCESS) &&
		    ldi_devid_match(devid, dip, dev))
			break;

		ddi_release_devi(dip);	/* from e_ddi_hold_devi_by_dev() */
	}

	ddi_lyr_free_devlist(devs, ndevs);

	if (i == ndevs)
		return (ENODEV);

	ASSERT(STYP_VALID(styp));
	vp = makespecvp(dev, STYP_TO_VTYP(styp));
	spec_assoc_vp_with_devi(vp, dip);
	ddi_release_devi(dip);		/* from e_ddi_hold_devi_by_dev */

	*vpp = vp;
	return (0);
}

/* given a vnode, open a device */
static int
ldi_open_by_vp(vnode_t **vpp, int flag, cred_t *cr,
    ldi_handle_t *lhp, struct ldi_ident *li)
{
	struct ldi_handle	*nlhp;
	vnode_t			*vp;
	int			err;

	ASSERT((vpp != NULL) && (*vpp != NULL));
	ASSERT((lhp != NULL) && (li != NULL));

	vp = *vpp;
	/* if the vnode passed in is not a device, then bail */
	if (!vn_matchops(vp, spec_getvnodeops()) || !VTYP_VALID(vp->v_type))
		return (ENXIO);

	/*
	 * the caller may have specified a node that
	 * doesn't have cb_ops defined.  the ldi doesn't yet
	 * support opening devices without a valid cb_ops.
	 */
	if (devopsp[getmajor(vp->v_rdev)]->devo_cb_ops == NULL)
		return (ENXIO);

	/* open the device */
	if ((err = VOP_OPEN(&vp, flag | FKLYR, cr, NULL)) != 0)
		return (err);

	/* possible clone open, make sure that we still have a spec node */
	ASSERT(vn_matchops(vp, spec_getvnodeops()));

	nlhp = handle_alloc(vp, li);

	if (vp != *vpp) {
		/*
		 * allocating the layered handle took a new hold on the vnode
		 * so we can release the hold that was returned by the clone
		 * open
		 */
		LDI_OPENCLOSE((CE_WARN, "%s: lh=0x%p",
		    "ldi clone open", (void *)nlhp));
	} else {
		LDI_OPENCLOSE((CE_WARN, "%s: lh=0x%p",
		    "ldi open", (void *)nlhp));
	}

	*vpp = vp;
	*lhp = (ldi_handle_t)nlhp;
	return (0);
}

/* Call a drivers prop_op(9E) interface */
static int
i_ldi_prop_op(dev_t dev, dev_info_t *dip, ddi_prop_op_t prop_op,
    int flags, char *name, caddr_t valuep, int *lengthp)
{
	struct dev_ops	*ops = NULL;
	int		res;

	ASSERT((dip != NULL) && (name != NULL));
	ASSERT((prop_op == PROP_LEN) || (valuep != NULL));
	ASSERT(lengthp != NULL);

	/*
	 * we can only be invoked after a driver has been opened and
	 * someone has a layered handle to it, so there had better be
	 * a valid ops vector.
	 */
	ops = DEVI(dip)->devi_ops;
	ASSERT(ops && ops->devo_cb_ops);

	/*
	 * Some nexus drivers incorrectly set cb_prop_op to nodev,
	 * nulldev or even NULL.
	 */
	if ((ops->devo_cb_ops->cb_prop_op == nodev) ||
	    (ops->devo_cb_ops->cb_prop_op == nulldev) ||
	    (ops->devo_cb_ops->cb_prop_op == NULL)) {
		return (DDI_PROP_NOT_FOUND);
	}

	/* check if this is actually DDI_DEV_T_ANY query */
	if (flags & LDI_DEV_T_ANY) {
		flags &= ~LDI_DEV_T_ANY;
		dev = DDI_DEV_T_ANY;
	}

	res = cdev_prop_op(dev, dip, prop_op, flags, name, valuep, lengthp);
	return (res);
}

static void
i_ldi_prop_op_free(struct prop_driver_data *pdd)
{
	kmem_free(pdd, pdd->pdd_size);
}

static caddr_t
i_ldi_prop_op_alloc(int prop_len)
{
	struct prop_driver_data	*pdd;
	int			pdd_size;

	pdd_size = sizeof (struct prop_driver_data) + prop_len;
	pdd = kmem_alloc(pdd_size, KM_SLEEP);
	pdd->pdd_size = pdd_size;
	pdd->pdd_prop_free = i_ldi_prop_op_free;
	return ((caddr_t)&pdd[1]);
}

/*
 * i_ldi_prop_op_typed() is a wrapper for i_ldi_prop_op that is used
 * by the typed ldi property lookup interfaces.
 */
static int
i_ldi_prop_op_typed(dev_t dev, dev_info_t *dip, int flags, char *name,
    caddr_t *datap, int *lengthp, int elem_size)
{
	caddr_t	prop_val;
	int	prop_len, res;

	ASSERT((dip != NULL) && (name != NULL));
	ASSERT((datap != NULL) && (lengthp != NULL));

	/*
	 * first call the drivers prop_op() interface to allow it
	 * it to override default property values.
	 */
	res = i_ldi_prop_op(dev, dip, PROP_LEN,
	    flags | DDI_PROP_DYNAMIC, name, NULL, &prop_len);
	if (res != DDI_PROP_SUCCESS)
		return (DDI_PROP_NOT_FOUND);

	/* sanity check the property length */
	if (prop_len == 0) {
		/*
		 * the ddi typed interfaces don't allow a drivers to
		 * create properties with a length of 0.  so we should
		 * prevent drivers from returning 0 length dynamic
		 * properties for typed property lookups.
		 */
		return (DDI_PROP_NOT_FOUND);
	}

	/* sanity check the property length against the element size */
	if (elem_size && ((prop_len % elem_size) != 0))
		return (DDI_PROP_NOT_FOUND);

	/*
	 * got it.  now allocate a prop_driver_data struct so that the
	 * user can free the property via ddi_prop_free().
	 */
	prop_val = i_ldi_prop_op_alloc(prop_len);

	/* lookup the property again, this time get the value */
	res = i_ldi_prop_op(dev, dip, PROP_LEN_AND_VAL_BUF,
	    flags | DDI_PROP_DYNAMIC, name, prop_val, &prop_len);
	if (res != DDI_PROP_SUCCESS) {
		ddi_prop_free(prop_val);
		return (DDI_PROP_NOT_FOUND);
	}

	/* sanity check the property length */
	if (prop_len == 0) {
		ddi_prop_free(prop_val);
		return (DDI_PROP_NOT_FOUND);
	}

	/* sanity check the property length against the element size */
	if (elem_size && ((prop_len % elem_size) != 0)) {
		ddi_prop_free(prop_val);
		return (DDI_PROP_NOT_FOUND);
	}

	/*
	 * return the prop_driver_data struct and, optionally, the length
	 * of the data.
	 */
	*datap = prop_val;
	*lengthp = prop_len;

	return (DDI_PROP_SUCCESS);
}

/*
 * i_check_string looks at a string property and makes sure its
 * a valid null terminated string
 */
static int
i_check_string(char *str, int prop_len)
{
	int i;

	ASSERT(str != NULL);

	for (i = 0; i < prop_len; i++) {
		if (str[i] == '\0')
			return (0);
	}
	return (1);
}

/*
 * i_pack_string_array takes a a string array property that is represented
 * as a concatenation of strings (with the NULL character included for
 * each string) and converts it into a format that can be returned by
 * ldi_prop_lookup_string_array.
 */
static int
i_pack_string_array(char *str_concat, int prop_len,
    char ***str_arrayp, int *nelemp)
{
	int i, nelem, pack_size;
	char **str_array, *strptr;

	/*
	 * first we need to sanity check the input string array.
	 * in essence this can be done my making sure that the last
	 * character of the array passed in is null.  (meaning the last
	 * string in the array is NULL terminated.
	 */
	if (str_concat[prop_len - 1] != '\0')
		return (1);

	/* now let's count the number of strings in the array */
	for (nelem = i = 0; i < prop_len; i++)
		if (str_concat[i] == '\0')
			nelem++;
	ASSERT(nelem >= 1);

	/* now let's allocate memory for the new packed property */
	pack_size = (sizeof (char *) * (nelem + 1)) + prop_len;
	str_array = (char **)i_ldi_prop_op_alloc(pack_size);

	/* let's copy the actual string data into the new property */
	strptr = (char *)&(str_array[nelem + 1]);
	bcopy(str_concat, strptr, prop_len);

	/* now initialize the string array pointers */
	for (i = 0; i < nelem; i++) {
		str_array[i] = strptr;
		strptr += strlen(strptr) + 1;
	}
	str_array[nelem] = NULL;

	/* set the return values */
	*str_arrayp = str_array;
	*nelemp = nelem;

	return (0);
}


/*
 * LDI Project private device usage interfaces
 */

/*
 * Get a count of how many devices are currentl open by different consumers
 */
int
ldi_usage_count()
{
	return (ldi_handle_hash_count);
}

static void
ldi_usage_walker_tgt_helper(ldi_usage_t *ldi_usage, vnode_t *vp)
{
	dev_info_t	*dip;
	dev_t		dev;

	ASSERT(STYP_VALID(VTYP_TO_STYP(vp->v_type)));

	/* get the target devt */
	dev = vp->v_rdev;

	/* try to get the target dip */
	dip = VTOCS(vp)->s_dip;
	if (dip != NULL) {
		e_ddi_hold_devi(dip);
	} else if (dev != DDI_DEV_T_NONE) {
		dip = e_ddi_hold_devi_by_dev(dev, 0);
	}

	/* set the target information */
	ldi_usage->tgt_name = mod_major_to_name(getmajor(dev));
	ldi_usage->tgt_modid = mod_name_to_modid(ldi_usage->tgt_name);
	ldi_usage->tgt_devt = dev;
	ldi_usage->tgt_spec_type = VTYP_TO_STYP(vp->v_type);
	ldi_usage->tgt_dip = dip;
}


static int
ldi_usage_walker_helper(struct ldi_ident *lip, vnode_t *vp,
    void *arg, int (*callback)(const ldi_usage_t *, void *))
{
	ldi_usage_t	ldi_usage;
	struct devnames	*dnp;
	dev_info_t	*dip;
	major_t		major;
	dev_t		dev;
	int		ret = LDI_USAGE_CONTINUE;

	/* set the target device information */
	ldi_usage_walker_tgt_helper(&ldi_usage, vp);

	/* get the source devt */
	dev = lip->li_dev;

	/* try to get the source dip */
	dip = lip->li_dip;
	if (dip != NULL) {
		e_ddi_hold_devi(dip);
	} else if (dev != DDI_DEV_T_NONE) {
		dip = e_ddi_hold_devi_by_dev(dev, 0);
	}

	/* set the valid source information */
	ldi_usage.src_modid = lip->li_modid;
	ldi_usage.src_name = lip->li_modname;
	ldi_usage.src_devt = dev;
	ldi_usage.src_dip = dip;

	/*
	 * if the source ident represents either:
	 *
	 * - a kernel module (and not a device or device driver)
	 * - a device node
	 *
	 * then we currently have all the info we need to report the
	 * usage information so invoke the callback function.
	 */
	if (((lip->li_major == -1) && (dev == DDI_DEV_T_NONE)) ||
	    (dip != NULL)) {
		ret = callback(&ldi_usage, arg);
		if (dip != NULL)
			ddi_release_devi(dip);
		if (ldi_usage.tgt_dip != NULL)
			ddi_release_devi(ldi_usage.tgt_dip);
		return (ret);
	}

	/*
	 * now this is kinda gross.
	 *
	 * what we do here is attempt to associate every device instance
	 * of the source driver on the system with the open target driver.
	 * we do this because we don't know which instance of the device
	 * could potentially access the lower device so we assume that all
	 * the instances could access it.
	 *
	 * there are two ways we could have gotten here:
	 *
	 * 1) this layered ident represents one created using only a
	 *    major number or a driver module name.  this means that when
	 *    it was created we could not associate it with a particular
	 *    dev_t or device instance.
	 *
	 *    when could this possibly happen you ask?
	 *
	 *    a perfect example of this is streams persistent links.
	 *    when a persistant streams link is formed we can't associate
	 *    the lower device stream with any particular upper device
	 *    stream or instance.  this is because any particular upper
	 *    device stream could be closed, then another could be
	 *    opened with a different dev_t and device instance, and it
	 *    would still have access to the lower linked stream.
	 *
	 *    since any instance of the upper streams driver could
	 *    potentially access the lower stream whenever it wants,
	 *    we represent that here by associating the opened lower
	 *    device with every existing device instance of the upper
	 *    streams driver.
	 *
	 * 2) This case should really never happen but we'll include it
	 *    for completeness.
	 *
	 *    it's possible that we could have gotten here because we
	 *    have a dev_t for the upper device but we couldn't find a
	 *    dip associated with that dev_t.
	 *
	 *    the only types of devices that have dev_t without an
	 *    associated dip are unbound DLPIv2 network devices.  These
	 *    types of devices exist to be able to attach a stream to any
	 *    instance of a hardware network device.  since these types of
	 *    devices are usually hardware devices they should never
	 *    really have other devices open.
	 */
	if (dev != DDI_DEV_T_NONE)
		major = getmajor(dev);
	else
		major = lip->li_major;

	ASSERT((major >= 0) && (major < devcnt));

	dnp = &devnamesp[major];
	LOCK_DEV_OPS(&dnp->dn_lock);
	dip = dnp->dn_head;
	while ((dip) && (ret == LDI_USAGE_CONTINUE)) {
		e_ddi_hold_devi(dip);
		UNLOCK_DEV_OPS(&dnp->dn_lock);

		/* set the source dip */
		ldi_usage.src_dip = dip;

		/* invoke the callback function */
		ret = callback(&ldi_usage, arg);

		LOCK_DEV_OPS(&dnp->dn_lock);
		ddi_release_devi(dip);
		dip = ddi_get_next(dip);
	}
	UNLOCK_DEV_OPS(&dnp->dn_lock);

	/* if there was a target dip, release it */
	if (ldi_usage.tgt_dip != NULL)
		ddi_release_devi(ldi_usage.tgt_dip);

	return (ret);
}

/*
 * ldi_usage_walker() - this walker reports LDI kernel device usage
 * information via the callback() callback function.  the LDI keeps track
 * of what devices are being accessed in its own internal data structures.
 * this function walks those data structures to determine device usage.
 */
void
ldi_usage_walker(void *arg, int (*callback)(const ldi_usage_t *, void *))
{
	struct ldi_handle	*lhp;
	struct ldi_ident	*lip;
	vnode_t			*vp;
	int			i;
	int			ret = LDI_USAGE_CONTINUE;

	for (i = 0; i < LH_HASH_SZ; i++) {
		mutex_enter(&ldi_handle_hash_lock[i]);

		lhp = ldi_handle_hash[i];
		while ((lhp != NULL) && (ret == LDI_USAGE_CONTINUE)) {
			lip = lhp->lh_ident;
			vp = lhp->lh_vp;

			/* invoke the devinfo callback function */
			ret = ldi_usage_walker_helper(lip, vp, arg, callback);

			lhp = lhp->lh_next;
		}
		mutex_exit(&ldi_handle_hash_lock[i]);

		if (ret != LDI_USAGE_CONTINUE)
			break;
	}
}

/*
 * LDI Project private interfaces (streams linking interfaces)
 *
 * Streams supports a type of built in device layering via linking.
 * Certain types of streams drivers can be streams multiplexors.
 * A streams multiplexor supports the I_LINK/I_PLINK operation.
 * These operations allows other streams devices to be linked under the
 * multiplexor.  By definition all streams multiplexors are devices
 * so this linking is a type of device layering where the multiplexor
 * device is layered on top of the device linked below it.
 */

/*
 * ldi_mlink_lh() is invoked when streams are linked using LDI handles.
 * It is not used for normal I_LINKs and I_PLINKs using file descriptors.
 *
 * The streams framework keeps track of links via the file_t of the lower
 * stream.  The LDI keeps track of devices using a vnode.  In the case
 * of a streams link created via an LDI handle, fnk_lh() allocates
 * a file_t that the streams framework can use to track the linkage.
 */
int
ldi_mlink_lh(vnode_t *vp, int cmd, intptr_t arg, cred_t *crp, int *rvalp)
{
	struct ldi_handle	*lhp = (struct ldi_handle *)arg;
	vnode_t			*vpdown;
	file_t			*fpdown;
	int			err;

	if (lhp == NULL)
		return (EINVAL);

	vpdown = lhp->lh_vp;
	ASSERT(vn_matchops(vpdown, spec_getvnodeops()));
	ASSERT(cmd == _I_PLINK_LH);

	/*
	 * create a new lower vnode and a file_t that points to it,
	 * streams linking requires a file_t.  falloc() returns with
	 * fpdown locked.
	 */
	VN_HOLD(vpdown);
	(void) falloc(vpdown, FREAD|FWRITE, &fpdown, NULL);
	mutex_exit(&fpdown->f_tlock);

	/* try to establish the link */
	err = mlink_file(vp, I_PLINK, fpdown, crp, rvalp, 1);

	if (err != 0) {
		/* the link failed, free the file_t and release the vnode */
		mutex_enter(&fpdown->f_tlock);
		unfalloc(fpdown);
		VN_RELE(vpdown);
	}

	return (err);
}

/*
 * ldi_mlink_fp() is invoked for all successful streams linkages created
 * via I_LINK and I_PLINK.  ldi_mlink_fp() records the linkage information
 * in its internal state so that the devinfo snapshot code has some
 * observability into streams device linkage information.
 */
void
ldi_mlink_fp(struct stdata *stp, file_t *fpdown, int lhlink, int type)
{
	vnode_t			*vp = fpdown->f_vnode;
	struct snode		*sp, *csp;
	ldi_ident_t		li;
	major_t			major;
	int			ret;

	/* if the lower stream is not a device then return */
	if (!vn_matchops(vp, spec_getvnodeops()))
		return;

	ASSERT(!servicing_interrupt());

	LDI_STREAMS_LNK((CE_NOTE, "%s: linking streams "
	    "stp=0x%p, fpdown=0x%p", "ldi_mlink_fp",
	    (void *)stp, (void *)fpdown));

	sp = VTOS(vp);
	csp = VTOS(sp->s_commonvp);

	/* check if this was a plink via a layered handle */
	if (lhlink) {
		/*
		 * increment the common snode s_count.
		 *
		 * this is done because after the link operation there
		 * are two ways that s_count can be decremented.
		 *
		 * when the layered handle used to create the link is
		 * closed, spec_close() is called and it will decrement
		 * s_count in the common snode.  if we don't increment
		 * s_count here then this could cause spec_close() to
		 * actually close the device while it's still linked
		 * under a multiplexer.
		 *
		 * also, when the lower stream is unlinked, closef() is
		 * called for the file_t associated with this snode.
		 * closef() will call spec_close(), which will decrement
		 * s_count.  if we dont't increment s_count here then this
		 * could cause spec_close() to actually close the device
		 * while there may still be valid layered handles
		 * pointing to it.
		 */
		mutex_enter(&csp->s_lock);
		ASSERT(csp->s_count >= 1);
		csp->s_count++;
		mutex_exit(&csp->s_lock);

		/*
		 * decrement the f_count.
		 * this is done because the layered driver framework does
		 * not actually cache a copy of the file_t allocated to
		 * do the link.  this is done here instead of in ldi_mlink_lh()
		 * because there is a window in ldi_mlink_lh() between where
		 * milnk_file() returns and we would decrement the f_count
		 * when the stream could be unlinked.
		 */
		mutex_enter(&fpdown->f_tlock);
		fpdown->f_count--;
		mutex_exit(&fpdown->f_tlock);
	}

	/*
	 * NOTE: here we rely on the streams subsystem not allowing
	 * a stream to be multiplexed more than once.  if this
	 * changes, we break.
	 *
	 * mark the snode/stream as multiplexed
	 */
	mutex_enter(&sp->s_lock);
	ASSERT(!(sp->s_flag & SMUXED));
	sp->s_flag |= SMUXED;
	mutex_exit(&sp->s_lock);

	/* get a layered ident for the upper stream */
	if (type == LINKNORMAL) {
		/*
		 * if the link is not persistant then we can associate
		 * the upper stream with a dev_t.  this is because the
		 * upper stream is associated with a vnode, which is
		 * associated with a dev_t and this binding can't change
		 * during the life of the stream.  since the link isn't
		 * persistant once the stream is destroyed the link is
		 * destroyed.  so the dev_t will be valid for the life
		 * of the link.
		 */
		ret = ldi_ident_from_stream(getendq(stp->sd_wrq), &li);
	} else {
		/*
		 * if the link is persistant we can only associate the
		 * link with a driver (and not a dev_t.)  this is
		 * because subsequent opens of the upper device may result
		 * in a different stream (and dev_t) having access to
		 * the lower stream.
		 *
		 * for example, if the upper stream is closed after the
		 * persistant link operation is compleated, a subsequent
		 * open of the upper device will create a new stream which
		 * may have a different dev_t and an unlink operation
		 * can be performed using this new upper stream.
		 */
		ASSERT(type == LINKPERSIST);
		major = getmajor(stp->sd_vnode->v_rdev);
		ret = ldi_ident_from_major(major, &li);
	}

	ASSERT(ret == 0);
	(void) handle_alloc(vp, (struct ldi_ident *)li);
	ldi_ident_release(li);
}

void
ldi_munlink_fp(struct stdata *stp, file_t *fpdown, int type)
{
	struct ldi_handle	*lhp;
	vnode_t			*vp = (vnode_t *)fpdown->f_vnode;
	struct snode		*sp;
	ldi_ident_t		li;
	major_t			major;
	int			ret;

	/* if the lower stream is not a device then return */
	if (!vn_matchops(vp, spec_getvnodeops()))
		return;

	ASSERT(!servicing_interrupt());
	ASSERT((type == LINKNORMAL) || (type == LINKPERSIST));

	LDI_STREAMS_LNK((CE_NOTE, "%s: unlinking streams "
	    "stp=0x%p, fpdown=0x%p", "ldi_munlink_fp",
	    (void *)stp, (void *)fpdown));

	/*
	 * NOTE: here we rely on the streams subsystem not allowing
	 * a stream to be multiplexed more than once.  if this
	 * changes, we break.
	 *
	 * mark the snode/stream as not multiplexed
	 */
	sp = VTOS(vp);
	mutex_enter(&sp->s_lock);
	ASSERT(sp->s_flag & SMUXED);
	sp->s_flag &= ~SMUXED;
	mutex_exit(&sp->s_lock);

	/*
	 * clear the owner for this snode
	 * see the comment in ldi_mlink_fp() for information about how
	 * the ident is allocated
	 */
	if (type == LINKNORMAL) {
		ret = ldi_ident_from_stream(getendq(stp->sd_wrq), &li);
	} else {
		ASSERT(type == LINKPERSIST);
		major = getmajor(stp->sd_vnode->v_rdev);
		ret = ldi_ident_from_major(major, &li);
	}

	ASSERT(ret == 0);
	lhp = handle_find(vp, (struct ldi_ident *)li);
	handle_release(lhp);
	ldi_ident_release(li);
}

/*
 * LDI Consolidation private interfaces
 */
int
ldi_ident_from_mod(struct modlinkage *modlp, ldi_ident_t *lip)
{
	struct modctl		*modp;
	major_t			major;
	char			*name;

	if ((modlp == NULL) || (lip == NULL))
		return (EINVAL);

	ASSERT(!servicing_interrupt());

	modp = mod_getctl(modlp);
	if (modp == NULL)
		return (EINVAL);
	name = modp->mod_modname;
	if (name == NULL)
		return (EINVAL);
	major = mod_name_to_major(name);

	*lip = (ldi_ident_t)ident_alloc(name, NULL, DDI_DEV_T_NONE, major);

	LDI_ALLOCFREE((CE_WARN, "%s: li=0x%p, mod=%s",
	    "ldi_ident_from_mod", (void *)*lip, name));

	return (0);
}

ldi_ident_t
ldi_ident_from_anon()
{
	ldi_ident_t	lip;

	ASSERT(!servicing_interrupt());

	lip = (ldi_ident_t)ident_alloc("genunix", NULL, DDI_DEV_T_NONE, -1);

	LDI_ALLOCFREE((CE_WARN, "%s: li=0x%p, mod=%s",
	    "ldi_ident_from_anon", (void *)lip, "genunix"));

	return (lip);
}


/*
 * LDI Public interfaces
 */
int
ldi_ident_from_stream(struct queue *sq, ldi_ident_t *lip)
{
	struct stdata		*stp;
	dev_t			dev;
	char			*name;

	if ((sq == NULL) || (lip == NULL))
		return (EINVAL);

	ASSERT(!servicing_interrupt());

	stp = sq->q_stream;
	if (!vn_matchops(stp->sd_vnode, spec_getvnodeops()))
		return (EINVAL);

	dev = stp->sd_vnode->v_rdev;
	name = mod_major_to_name(getmajor(dev));
	if (name == NULL)
		return (EINVAL);
	*lip = (ldi_ident_t)ident_alloc(name, NULL, dev, -1);

	LDI_ALLOCFREE((CE_WARN,
	    "%s: li=0x%p, mod=%s, minor=0x%x, stp=0x%p",
	    "ldi_ident_from_stream", (void *)*lip, name, getminor(dev),
	    (void *)stp));

	return (0);
}

int
ldi_ident_from_dev(dev_t dev, ldi_ident_t *lip)
{
	char			*name;

	if (lip == NULL)
		return (EINVAL);

	ASSERT(!servicing_interrupt());

	name = mod_major_to_name(getmajor(dev));
	if (name == NULL)
		return (EINVAL);
	*lip = (ldi_ident_t)ident_alloc(name, NULL, dev, -1);

	LDI_ALLOCFREE((CE_WARN,
	    "%s: li=0x%p, mod=%s, minor=0x%x",
	    "ldi_ident_from_dev", (void *)*lip, name, getminor(dev)));

	return (0);
}

int
ldi_ident_from_dip(dev_info_t *dip, ldi_ident_t *lip)
{
	struct dev_info		*devi = (struct dev_info *)dip;
	char			*name;

	if ((dip == NULL) || (lip == NULL))
		return (EINVAL);

	ASSERT(!servicing_interrupt());

	name = mod_major_to_name(devi->devi_major);
	if (name == NULL)
		return (EINVAL);
	*lip = (ldi_ident_t)ident_alloc(name, dip, DDI_DEV_T_NONE, -1);

	LDI_ALLOCFREE((CE_WARN,
	    "%s: li=0x%p, mod=%s, dip=0x%p",
	    "ldi_ident_from_dip", (void *)*lip, name, (void *)devi));

	return (0);
}

int
ldi_ident_from_major(major_t major, ldi_ident_t *lip)
{
	char			*name;

	if (lip == NULL)
		return (EINVAL);

	ASSERT(!servicing_interrupt());

	name = mod_major_to_name(major);
	if (name == NULL)
		return (EINVAL);
	*lip = (ldi_ident_t)ident_alloc(name, NULL, DDI_DEV_T_NONE, major);

	LDI_ALLOCFREE((CE_WARN,
	    "%s: li=0x%p, mod=%s",
	    "ldi_ident_from_major", (void *)*lip, name));

	return (0);
}

void
ldi_ident_release(ldi_ident_t li)
{
	struct ldi_ident	*ident = (struct ldi_ident *)li;
	char			*name;

	if (li == NULL)
		return;

	ASSERT(!servicing_interrupt());

	name = ident->li_modname;

	LDI_ALLOCFREE((CE_WARN,
	    "%s: li=0x%p, mod=%s",
	    "ldi_ident_release", (void *)li, name));

	ident_release((struct ldi_ident *)li);
}

/* get a handle to a device by dev_t and otyp */
int
ldi_open_by_dev(dev_t *devp, int otyp, int flag, cred_t *cr,
    ldi_handle_t *lhp, ldi_ident_t li)
{
	struct ldi_ident	*lip = (struct ldi_ident *)li;
	int			ret;
	vnode_t			*vp;

	/* sanity check required input parameters */
	if ((devp == NULL) || (!OTYP_VALID(otyp)) || (cr == NULL) ||
	    (lhp == NULL) || (lip == NULL))
		return (EINVAL);

	ASSERT(!servicing_interrupt());

	if ((ret = ldi_vp_from_dev(*devp, otyp, &vp)) != 0)
		return (ret);

	if ((ret = ldi_open_by_vp(&vp, flag, cr, lhp, lip)) == 0) {
		*devp = vp->v_rdev;
	}
	VN_RELE(vp);

	return (ret);
}

/* get a handle to a device by pathname */
int
ldi_open_by_name(char *pathname, int flag, cred_t *cr,
    ldi_handle_t *lhp, ldi_ident_t li)
{
	struct ldi_ident	*lip = (struct ldi_ident *)li;
	int			ret;
	vnode_t			*vp;

	/* sanity check required input parameters */
	if ((pathname == NULL) || (*pathname != '/') ||
	    (cr == NULL) || (lhp == NULL) || (lip == NULL))
		return (EINVAL);

	ASSERT(!servicing_interrupt());

	if ((ret = ldi_vp_from_name(pathname, &vp)) != 0)
		return (ret);

	ret = ldi_open_by_vp(&vp, flag, cr, lhp, lip);
	VN_RELE(vp);

	return (ret);
}

/* get a handle to a device by devid and minor_name */
int
ldi_open_by_devid(ddi_devid_t devid, char *minor_name,
    int flag, cred_t *cr, ldi_handle_t *lhp, ldi_ident_t li)
{
	struct ldi_ident	*lip = (struct ldi_ident *)li;
	int			ret;
	vnode_t			*vp;

	/* sanity check required input parameters */
	if ((minor_name == NULL) || (cr == NULL) ||
	    (lhp == NULL) || (lip == NULL))
		return (EINVAL);

	ASSERT(!servicing_interrupt());

	if ((ret = ldi_vp_from_devid(devid, minor_name, &vp)) != 0)
		return (ret);

	ret = ldi_open_by_vp(&vp, flag, cr, lhp, lip);
	VN_RELE(vp);

	return (ret);
}

int
ldi_close(ldi_handle_t lh, int flag, cred_t *cr)
{
	struct ldi_handle	*handlep = (struct ldi_handle *)lh;
	struct ldi_event	*lep;
	int			err = 0;
	int			notify = 0;
	list_t			*listp;
	ldi_ev_callback_impl_t	*lecp;

	if (lh == NULL)
		return (EINVAL);

	ASSERT(!servicing_interrupt());

#ifdef	LDI_OBSOLETE_EVENT

	/*
	 * Any event handlers should have been unregistered by the
	 * time ldi_close() is called.  If they haven't then it's a
	 * bug.
	 *
	 * In a debug kernel we'll panic to make the problem obvious.
	 */
	ASSERT(handlep->lh_events == NULL);

	/*
	 * On a production kernel we'll "do the right thing" (unregister
	 * the event handlers) and then complain about having to do the
	 * work ourselves.
	 */
	while ((lep = handlep->lh_events) != NULL) {
		err = 1;
		(void) ldi_remove_event_handler(lh, (ldi_callback_id_t)lep);
	}
	if (err) {
		struct ldi_ident *lip = handlep->lh_ident;
		ASSERT(lip != NULL);
		cmn_err(CE_NOTE, "ldi err: %s "
		    "failed to unregister layered event handlers before "
		    "closing devices", lip->li_modname);
	}
#endif

	/* do a layered close on the device */
	err = VOP_CLOSE(handlep->lh_vp, flag | FKLYR, 1, (offset_t)0, cr, NULL);

	LDI_OPENCLOSE((CE_WARN, "%s: lh=0x%p", "ldi close", (void *)lh));

	/*
	 * Search the event callback list for callbacks with this
	 * handle. There are 2 cases
	 * 1. Called in the context of a notify. The handle consumer
	 *    is releasing its hold on the device to allow a reconfiguration
	 *    of the device. Simply NULL out the handle and the notify callback.
	 *    The finalize callback is still available so that the consumer
	 *    knows of the final disposition of the device.
	 * 2. Not called in the context of notify. NULL out the handle as well
	 *    as the notify and finalize callbacks. Since the consumer has
	 *    closed the handle, we assume it is not interested in the
	 *    notify and finalize callbacks.
	 */
	ldi_ev_lock();

	if (handlep->lh_flags & LH_FLAGS_NOTIFY)
		notify = 1;
	listp = &ldi_ev_callback_list.le_head;
	for (lecp = list_head(listp); lecp; lecp = list_next(listp, lecp)) {
		if (lecp->lec_lhp != handlep)
			continue;
		lecp->lec_lhp = NULL;
		lecp->lec_notify = NULL;
		LDI_EVDBG((CE_NOTE, "ldi_close: NULLed lh and notify"));
		if (!notify) {
			LDI_EVDBG((CE_NOTE, "ldi_close: NULLed finalize"));
			lecp->lec_finalize = NULL;
		}
	}

	if (notify)
		handlep->lh_flags &= ~LH_FLAGS_NOTIFY;
	ldi_ev_unlock();

	/*
	 * Free the handle even if the device close failed.  why?
	 *
	 * If the device close failed we can't really make assumptions
	 * about the devices state so we shouldn't allow access to the
	 * device via this handle any more.  If the device consumer wants
	 * to access the device again they should open it again.
	 *
	 * This is the same way file/device close failures are handled
	 * in other places like spec_close() and closeandsetf().
	 */
	handle_release(handlep);
	return (err);
}

int
ldi_read(ldi_handle_t lh, struct uio *uiop, cred_t *credp)
{
	struct ldi_handle	*handlep = (struct ldi_handle *)lh;
	vnode_t			*vp;
	dev_t			dev;
	int			ret;

	if (lh == NULL)
		return (EINVAL);

	vp = handlep->lh_vp;
	dev = vp->v_rdev;
	if (handlep->lh_type & LH_CBDEV) {
		ret = cdev_read(dev, uiop, credp);
	} else if (handlep->lh_type & LH_STREAM) {
		ret = strread(vp, uiop, credp);
	} else {
		return (ENOTSUP);
	}
	return (ret);
}

int
ldi_write(ldi_handle_t lh, struct uio *uiop, cred_t *credp)
{
	struct ldi_handle	*handlep = (struct ldi_handle *)lh;
	vnode_t			*vp;
	dev_t			dev;
	int			ret;

	if (lh == NULL)
		return (EINVAL);

	vp = handlep->lh_vp;
	dev = vp->v_rdev;
	if (handlep->lh_type & LH_CBDEV) {
		ret = cdev_write(dev, uiop, credp);
	} else if (handlep->lh_type & LH_STREAM) {
		ret = strwrite(vp, uiop, credp);
	} else {
		return (ENOTSUP);
	}
	return (ret);
}

int
ldi_get_size(ldi_handle_t lh, uint64_t *sizep)
{
	int			otyp;
	uint_t			value;
	int64_t			drv_prop64;
	struct ldi_handle	*handlep = (struct ldi_handle *)lh;
	uint_t			blksize;
	int			blkshift;


	if ((lh == NULL) || (sizep == NULL))
		return (DDI_FAILURE);

	if (handlep->lh_type & LH_STREAM)
		return (DDI_FAILURE);

	/*
	 * Determine device type (char or block).
	 * Character devices support Size/size
	 * property value. Block devices may support
	 * Nblocks/nblocks or Size/size property value.
	 */
	if ((ldi_get_otyp(lh, &otyp)) != 0)
		return (DDI_FAILURE);

	if (otyp == OTYP_BLK) {
		if (ldi_prop_exists(lh,
		    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, "Nblocks")) {

			drv_prop64 = ldi_prop_get_int64(lh,
			    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM,
			    "Nblocks", 0);
			blksize = ldi_prop_get_int(lh,
			    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM,
			    "blksize", DEV_BSIZE);
			if (blksize == DEV_BSIZE)
				blksize = ldi_prop_get_int(lh, LDI_DEV_T_ANY |
				    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM,
				    "device-blksize", DEV_BSIZE);

			/* blksize must be a power of two */
			ASSERT(BIT_ONLYONESET(blksize));
			blkshift = highbit(blksize) - 1;

			/*
			 * We don't support Nblocks values that don't have
			 * an accurate uint64_t byte count representation.
			 */
			if ((uint64_t)drv_prop64 >= (UINT64_MAX >> blkshift))
				return (DDI_FAILURE);

			*sizep = (uint64_t)
			    (((u_offset_t)drv_prop64) << blkshift);
			return (DDI_SUCCESS);
		}

		if (ldi_prop_exists(lh,
		    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, "nblocks")) {

			value = ldi_prop_get_int(lh,
			    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM,
			    "nblocks", 0);
			blksize = ldi_prop_get_int(lh,
			    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM,
			    "blksize", DEV_BSIZE);
			if (blksize == DEV_BSIZE)
				blksize = ldi_prop_get_int(lh, LDI_DEV_T_ANY |
				    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM,
				    "device-blksize", DEV_BSIZE);

			/* blksize must be a power of two */
			ASSERT(BIT_ONLYONESET(blksize));
			blkshift = highbit(blksize) - 1;

			/*
			 * We don't support nblocks values that don't have an
			 * accurate uint64_t byte count representation.
			 */
			if ((uint64_t)value >= (UINT64_MAX >> blkshift))
				return (DDI_FAILURE);

			*sizep = (uint64_t)
			    (((u_offset_t)value) << blkshift);
			return (DDI_SUCCESS);
		}
	}

	if (ldi_prop_exists(lh,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, "Size")) {

		drv_prop64 = ldi_prop_get_int64(lh,
		    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, "Size", 0);
		*sizep = (uint64_t)drv_prop64;
		return (DDI_SUCCESS);
	}

	if (ldi_prop_exists(lh,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, "size")) {

		value = ldi_prop_get_int(lh,
		    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, "size", 0);
		*sizep = (uint64_t)value;
		return (DDI_SUCCESS);
	}

	/* unable to determine device size */
	return (DDI_FAILURE);
}

int
ldi_ioctl(ldi_handle_t lh, int cmd, intptr_t arg, int mode,
	cred_t *cr, int *rvalp)
{
	struct ldi_handle	*handlep = (struct ldi_handle *)lh;
	vnode_t			*vp;
	dev_t			dev;
	int			ret, copymode, unused;

	if (lh == NULL)
		return (EINVAL);

	/*
	 * if the data pointed to by arg is located in the kernel then
	 * make sure the FNATIVE flag is set.
	 */
	if (mode & FKIOCTL)
		mode = (mode & ~FMODELS) | FNATIVE | FKIOCTL;

	/*
	 * Some drivers assume that rvalp will always be non-NULL, so in
	 * an attempt to avoid panics if the caller passed in a NULL
	 * value, update rvalp to point to a temporary variable.
	 */
	if (rvalp == NULL)
		rvalp = &unused;
	vp = handlep->lh_vp;
	dev = vp->v_rdev;
	if (handlep->lh_type & LH_CBDEV) {
		ret = cdev_ioctl(dev, cmd, arg, mode, cr, rvalp);
	} else if (handlep->lh_type & LH_STREAM) {
		copymode = (mode & FKIOCTL) ? K_TO_K : U_TO_K;

		/*
		 * if we get an I_PLINK from within the kernel the
		 * arg is a layered handle pointer instead of
		 * a file descriptor, so we translate this ioctl
		 * into a private one that can handle this.
		 */
		if ((mode & FKIOCTL) && (cmd == I_PLINK))
			cmd = _I_PLINK_LH;

		ret = strioctl(vp, cmd, arg, mode, copymode, cr, rvalp);
	} else {
		return (ENOTSUP);
	}

	return (ret);
}

int
ldi_poll(ldi_handle_t lh, short events, int anyyet, short *reventsp,
    struct pollhead **phpp)
{
	struct ldi_handle	*handlep = (struct ldi_handle *)lh;
	vnode_t			*vp;
	dev_t			dev;
	int			ret;

	if (lh == NULL)
		return (EINVAL);

	vp = handlep->lh_vp;
	dev = vp->v_rdev;
	if (handlep->lh_type & LH_CBDEV) {
		ret = cdev_poll(dev, events, anyyet, reventsp, phpp);
	} else if (handlep->lh_type & LH_STREAM) {
		ret = strpoll(vp->v_stream, events, anyyet, reventsp, phpp);
	} else {
		return (ENOTSUP);
	}

	return (ret);
}

int
ldi_prop_op(ldi_handle_t lh, ddi_prop_op_t prop_op,
	int flags, char *name, caddr_t valuep, int *length)
{
	struct ldi_handle	*handlep = (struct ldi_handle *)lh;
	dev_t			dev;
	dev_info_t		*dip;
	int			ret;
	struct snode		*csp;

	if ((lh == NULL) || (name == NULL) || (strlen(name) == 0))
		return (DDI_PROP_INVAL_ARG);

	if ((prop_op != PROP_LEN) && (valuep == NULL))
		return (DDI_PROP_INVAL_ARG);

	if (length == NULL)
		return (DDI_PROP_INVAL_ARG);

	/*
	 * try to find the associated dip,
	 * this places a hold on the driver
	 */
	dev = handlep->lh_vp->v_rdev;

	csp = VTOCS(handlep->lh_vp);
	mutex_enter(&csp->s_lock);
	if ((dip = csp->s_dip) != NULL)
		e_ddi_hold_devi(dip);
	mutex_exit(&csp->s_lock);
	if (dip == NULL)
		dip = e_ddi_hold_devi_by_dev(dev, 0);

	if (dip == NULL)
		return (DDI_PROP_NOT_FOUND);

	ret = i_ldi_prop_op(dev, dip, prop_op, flags, name, valuep, length);
	ddi_release_devi(dip);

	return (ret);
}

int
ldi_strategy(ldi_handle_t lh, struct buf *bp)
{
	struct ldi_handle	*handlep = (struct ldi_handle *)lh;
	dev_t			dev;

	if ((lh == NULL) || (bp == NULL))
		return (EINVAL);

	/* this entry point is only supported for cb devices */
	dev = handlep->lh_vp->v_rdev;
	if (!(handlep->lh_type & LH_CBDEV))
		return (ENOTSUP);

	bp->b_edev = dev;
	bp->b_dev = cmpdev(dev);
	return (bdev_strategy(bp));
}

int
ldi_dump(ldi_handle_t lh, caddr_t addr, daddr_t blkno, int nblk)
{
	struct ldi_handle	*handlep = (struct ldi_handle *)lh;
	dev_t			dev;

	if (lh == NULL)
		return (EINVAL);

	/* this entry point is only supported for cb devices */
	dev = handlep->lh_vp->v_rdev;
	if (!(handlep->lh_type & LH_CBDEV))
		return (ENOTSUP);

	return (bdev_dump(dev, addr, blkno, nblk));
}

int
ldi_devmap(ldi_handle_t lh, devmap_cookie_t dhp, offset_t off,
    size_t len, size_t *maplen, uint_t model)
{
	struct ldi_handle	*handlep = (struct ldi_handle *)lh;
	dev_t			dev;

	if (lh == NULL)
		return (EINVAL);

	/* this entry point is only supported for cb devices */
	dev = handlep->lh_vp->v_rdev;
	if (!(handlep->lh_type & LH_CBDEV))
		return (ENOTSUP);

	return (cdev_devmap(dev, dhp, off, len, maplen, model));
}

int
ldi_aread(ldi_handle_t lh, struct aio_req *aio_reqp, cred_t *cr)
{
	struct ldi_handle	*handlep = (struct ldi_handle *)lh;
	dev_t			dev;
	struct cb_ops		*cb;

	if (lh == NULL)
		return (EINVAL);

	/* this entry point is only supported for cb devices */
	if (!(handlep->lh_type & LH_CBDEV))
		return (ENOTSUP);

	/*
	 * Kaio is only supported on block devices.
	 */
	dev = handlep->lh_vp->v_rdev;
	cb = devopsp[getmajor(dev)]->devo_cb_ops;
	if (cb->cb_strategy == nodev || cb->cb_strategy == NULL)
		return (ENOTSUP);

	if (cb->cb_aread == NULL)
		return (ENOTSUP);

	return (cb->cb_aread(dev, aio_reqp, cr));
}

int
ldi_awrite(ldi_handle_t lh, struct aio_req *aio_reqp, cred_t *cr)
{
	struct ldi_handle	*handlep = (struct ldi_handle *)lh;
	struct cb_ops		*cb;
	dev_t			dev;

	if (lh == NULL)
		return (EINVAL);

	/* this entry point is only supported for cb devices */
	if (!(handlep->lh_type & LH_CBDEV))
		return (ENOTSUP);

	/*
	 * Kaio is only supported on block devices.
	 */
	dev = handlep->lh_vp->v_rdev;
	cb = devopsp[getmajor(dev)]->devo_cb_ops;
	if (cb->cb_strategy == nodev || cb->cb_strategy == NULL)
		return (ENOTSUP);

	if (cb->cb_awrite == NULL)
		return (ENOTSUP);

	return (cb->cb_awrite(dev, aio_reqp, cr));
}

int
ldi_putmsg(ldi_handle_t lh, mblk_t *smp)
{
	struct ldi_handle	*handlep = (struct ldi_handle *)lh;
	int			ret;

	if ((lh == NULL) || (smp == NULL))
		return (EINVAL);

	if (!(handlep->lh_type & LH_STREAM)) {
		freemsg(smp);
		return (ENOTSUP);
	}

	/*
	 * If we don't have db_credp, set it. Note that we can not be called
	 * from interrupt context.
	 */
	if (msg_getcred(smp, NULL) == NULL)
		mblk_setcred(smp, CRED(), curproc->p_pid);

	/* Send message while honoring flow control */
	ret = kstrputmsg(handlep->lh_vp, smp, NULL, 0, 0,
	    MSG_BAND | MSG_HOLDSIG | MSG_IGNERROR, 0);

	return (ret);
}

int
ldi_getmsg(ldi_handle_t lh, mblk_t **rmp, timestruc_t *timeo)
{
	struct ldi_handle	*handlep = (struct ldi_handle *)lh;
	clock_t			timout; /* milliseconds */
	uchar_t			pri;
	rval_t			rval;
	int			ret, pflag;


	if (lh == NULL)
		return (EINVAL);

	if (!(handlep->lh_type & LH_STREAM))
		return (ENOTSUP);

	/* Convert from nanoseconds to milliseconds */
	if (timeo != NULL) {
		timout = timeo->tv_sec * 1000 + timeo->tv_nsec / 1000000;
		if (timout > INT_MAX)
			return (EINVAL);
	} else
		timout = -1;

	/* Wait for timeout millseconds for a message */
	pflag = MSG_ANY;
	pri = 0;
	*rmp = NULL;
	ret = kstrgetmsg(handlep->lh_vp,
	    rmp, NULL, &pri, &pflag, timout, &rval);
	return (ret);
}

int
ldi_get_dev(ldi_handle_t lh, dev_t *devp)
{
	struct ldi_handle	*handlep = (struct ldi_handle *)lh;

	if ((lh == NULL) || (devp == NULL))
		return (EINVAL);

	*devp = handlep->lh_vp->v_rdev;
	return (0);
}

int
ldi_get_otyp(ldi_handle_t lh, int *otyp)
{
	struct ldi_handle	*handlep = (struct ldi_handle *)lh;

	if ((lh == NULL) || (otyp == NULL))
		return (EINVAL);

	*otyp = VTYP_TO_OTYP(handlep->lh_vp->v_type);
	return (0);
}

int
ldi_get_devid(ldi_handle_t lh, ddi_devid_t *devid)
{
	struct ldi_handle	*handlep = (struct ldi_handle *)lh;
	int			ret;
	dev_t			dev;

	if ((lh == NULL) || (devid == NULL))
		return (EINVAL);

	dev = handlep->lh_vp->v_rdev;

	ret = ddi_lyr_get_devid(dev, devid);
	if (ret != DDI_SUCCESS)
		return (ENOTSUP);

	return (0);
}

int
ldi_get_minor_name(ldi_handle_t lh, char **minor_name)
{
	struct ldi_handle	*handlep = (struct ldi_handle *)lh;
	int			ret, otyp;
	dev_t			dev;

	if ((lh == NULL) || (minor_name == NULL))
		return (EINVAL);

	dev = handlep->lh_vp->v_rdev;
	otyp = VTYP_TO_OTYP(handlep->lh_vp->v_type);

	ret = ddi_lyr_get_minor_name(dev, OTYP_TO_STYP(otyp), minor_name);
	if (ret != DDI_SUCCESS)
		return (ENOTSUP);

	return (0);
}

int
ldi_prop_lookup_int_array(ldi_handle_t lh,
    uint_t flags, char *name, int **data, uint_t *nelements)
{
	struct ldi_handle	*handlep = (struct ldi_handle *)lh;
	dev_info_t		*dip;
	dev_t			dev;
	int			res;
	struct snode		*csp;

	if ((lh == NULL) || (name == NULL) || (strlen(name) == 0))
		return (DDI_PROP_INVAL_ARG);

	dev = handlep->lh_vp->v_rdev;

	csp = VTOCS(handlep->lh_vp);
	mutex_enter(&csp->s_lock);
	if ((dip = csp->s_dip) != NULL)
		e_ddi_hold_devi(dip);
	mutex_exit(&csp->s_lock);
	if (dip == NULL)
		dip = e_ddi_hold_devi_by_dev(dev, 0);

	if (dip == NULL) {
		flags |= DDI_UNBND_DLPI2;
	} else if (flags & LDI_DEV_T_ANY) {
		flags &= ~LDI_DEV_T_ANY;
		dev = DDI_DEV_T_ANY;
	}

	if (dip != NULL) {
		int *prop_val, prop_len;

		res = i_ldi_prop_op_typed(dev, dip, flags, name,
		    (caddr_t *)&prop_val, &prop_len, sizeof (int));

		/* if we got it then return it */
		if (res == DDI_PROP_SUCCESS) {
			*nelements = prop_len / sizeof (int);
			*data = prop_val;

			ddi_release_devi(dip);
			return (res);
		}
	}

	/* call the normal property interfaces */
	res = ddi_prop_lookup_int_array(dev, dip, flags,
	    name, data, nelements);

	if (dip != NULL)
		ddi_release_devi(dip);

	return (res);
}

int
ldi_prop_lookup_int64_array(ldi_handle_t lh,
    uint_t flags, char *name, int64_t **data, uint_t *nelements)
{
	struct ldi_handle	*handlep = (struct ldi_handle *)lh;
	dev_info_t		*dip;
	dev_t			dev;
	int			res;
	struct snode		*csp;

	if ((lh == NULL) || (name == NULL) || (strlen(name) == 0))
		return (DDI_PROP_INVAL_ARG);

	dev = handlep->lh_vp->v_rdev;

	csp = VTOCS(handlep->lh_vp);
	mutex_enter(&csp->s_lock);
	if ((dip = csp->s_dip) != NULL)
		e_ddi_hold_devi(dip);
	mutex_exit(&csp->s_lock);
	if (dip == NULL)
		dip = e_ddi_hold_devi_by_dev(dev, 0);

	if (dip == NULL) {
		flags |= DDI_UNBND_DLPI2;
	} else if (flags & LDI_DEV_T_ANY) {
		flags &= ~LDI_DEV_T_ANY;
		dev = DDI_DEV_T_ANY;
	}

	if (dip != NULL) {
		int64_t	*prop_val;
		int	prop_len;

		res = i_ldi_prop_op_typed(dev, dip, flags, name,
		    (caddr_t *)&prop_val, &prop_len, sizeof (int64_t));

		/* if we got it then return it */
		if (res == DDI_PROP_SUCCESS) {
			*nelements = prop_len / sizeof (int64_t);
			*data = prop_val;

			ddi_release_devi(dip);
			return (res);
		}
	}

	/* call the normal property interfaces */
	res = ddi_prop_lookup_int64_array(dev, dip, flags,
	    name, data, nelements);

	if (dip != NULL)
		ddi_release_devi(dip);

	return (res);
}

int
ldi_prop_lookup_string_array(ldi_handle_t lh,
    uint_t flags, char *name, char ***data, uint_t *nelements)
{
	struct ldi_handle	*handlep = (struct ldi_handle *)lh;
	dev_info_t		*dip;
	dev_t			dev;
	int			res;
	struct snode		*csp;

	if ((lh == NULL) || (name == NULL) || (strlen(name) == 0))
		return (DDI_PROP_INVAL_ARG);

	dev = handlep->lh_vp->v_rdev;

	csp = VTOCS(handlep->lh_vp);
	mutex_enter(&csp->s_lock);
	if ((dip = csp->s_dip) != NULL)
		e_ddi_hold_devi(dip);
	mutex_exit(&csp->s_lock);
	if (dip == NULL)
		dip = e_ddi_hold_devi_by_dev(dev, 0);

	if (dip == NULL) {
		flags |= DDI_UNBND_DLPI2;
	} else if (flags & LDI_DEV_T_ANY) {
		flags &= ~LDI_DEV_T_ANY;
		dev = DDI_DEV_T_ANY;
	}

	if (dip != NULL) {
		char	*prop_val;
		int	prop_len;

		res = i_ldi_prop_op_typed(dev, dip, flags, name,
		    (caddr_t *)&prop_val, &prop_len, 0);

		/* if we got it then return it */
		if (res == DDI_PROP_SUCCESS) {
			char	**str_array;
			int	nelem;

			/*
			 * pack the returned string array into the format
			 * our callers expect
			 */
			if (i_pack_string_array(prop_val, prop_len,
			    &str_array, &nelem) == 0) {

				*data = str_array;
				*nelements = nelem;

				ddi_prop_free(prop_val);
				ddi_release_devi(dip);
				return (res);
			}

			/*
			 * the format of the returned property must have
			 * been bad so throw it out
			 */
			ddi_prop_free(prop_val);
		}
	}

	/* call the normal property interfaces */
	res = ddi_prop_lookup_string_array(dev, dip, flags,
	    name, data, nelements);

	if (dip != NULL)
		ddi_release_devi(dip);

	return (res);
}

int
ldi_prop_lookup_string(ldi_handle_t lh,
    uint_t flags, char *name, char **data)
{
	struct ldi_handle	*handlep = (struct ldi_handle *)lh;
	dev_info_t		*dip;
	dev_t			dev;
	int			res;
	struct snode		*csp;

	if ((lh == NULL) || (name == NULL) || (strlen(name) == 0))
		return (DDI_PROP_INVAL_ARG);

	dev = handlep->lh_vp->v_rdev;

	csp = VTOCS(handlep->lh_vp);
	mutex_enter(&csp->s_lock);
	if ((dip = csp->s_dip) != NULL)
		e_ddi_hold_devi(dip);
	mutex_exit(&csp->s_lock);
	if (dip == NULL)
		dip = e_ddi_hold_devi_by_dev(dev, 0);

	if (dip == NULL) {
		flags |= DDI_UNBND_DLPI2;
	} else if (flags & LDI_DEV_T_ANY) {
		flags &= ~LDI_DEV_T_ANY;
		dev = DDI_DEV_T_ANY;
	}

	if (dip != NULL) {
		char	*prop_val;
		int	prop_len;

		res = i_ldi_prop_op_typed(dev, dip, flags, name,
		    (caddr_t *)&prop_val, &prop_len, 0);

		/* if we got it then return it */
		if (res == DDI_PROP_SUCCESS) {
			/*
			 * sanity check the vaule returned.
			 */
			if (i_check_string(prop_val, prop_len)) {
				ddi_prop_free(prop_val);
			} else {
				*data = prop_val;
				ddi_release_devi(dip);
				return (res);
			}
		}
	}

	/* call the normal property interfaces */
	res = ddi_prop_lookup_string(dev, dip, flags, name, data);

	if (dip != NULL)
		ddi_release_devi(dip);

#ifdef DEBUG
	if (res == DDI_PROP_SUCCESS) {
		/*
		 * keep ourselves honest
		 * make sure the framework returns strings in the
		 * same format as we're demanding from drivers.
		 */
		struct prop_driver_data	*pdd;
		int			pdd_prop_size;

		pdd = ((struct prop_driver_data *)(*data)) - 1;
		pdd_prop_size = pdd->pdd_size -
		    sizeof (struct prop_driver_data);
		ASSERT(i_check_string(*data, pdd_prop_size) == 0);
	}
#endif /* DEBUG */

	return (res);
}

int
ldi_prop_lookup_byte_array(ldi_handle_t lh,
    uint_t flags, char *name, uchar_t **data, uint_t *nelements)
{
	struct ldi_handle	*handlep = (struct ldi_handle *)lh;
	dev_info_t		*dip;
	dev_t			dev;
	int			res;
	struct snode		*csp;

	if ((lh == NULL) || (name == NULL) || (strlen(name) == 0))
		return (DDI_PROP_INVAL_ARG);

	dev = handlep->lh_vp->v_rdev;

	csp = VTOCS(handlep->lh_vp);
	mutex_enter(&csp->s_lock);
	if ((dip = csp->s_dip) != NULL)
		e_ddi_hold_devi(dip);
	mutex_exit(&csp->s_lock);
	if (dip == NULL)
		dip = e_ddi_hold_devi_by_dev(dev, 0);

	if (dip == NULL) {
		flags |= DDI_UNBND_DLPI2;
	} else if (flags & LDI_DEV_T_ANY) {
		flags &= ~LDI_DEV_T_ANY;
		dev = DDI_DEV_T_ANY;
	}

	if (dip != NULL) {
		uchar_t	*prop_val;
		int	prop_len;

		res = i_ldi_prop_op_typed(dev, dip, flags, name,
		    (caddr_t *)&prop_val, &prop_len, sizeof (uchar_t));

		/* if we got it then return it */
		if (res == DDI_PROP_SUCCESS) {
			*nelements = prop_len / sizeof (uchar_t);
			*data = prop_val;

			ddi_release_devi(dip);
			return (res);
		}
	}

	/* call the normal property interfaces */
	res = ddi_prop_lookup_byte_array(dev, dip, flags,
	    name, data, nelements);

	if (dip != NULL)
		ddi_release_devi(dip);

	return (res);
}

int
ldi_prop_get_int(ldi_handle_t lh,
    uint_t flags, char *name, int defvalue)
{
	struct ldi_handle	*handlep = (struct ldi_handle *)lh;
	dev_info_t		*dip;
	dev_t			dev;
	int			res;
	struct snode		*csp;

	if ((lh == NULL) || (name == NULL) || (strlen(name) == 0))
		return (defvalue);

	dev = handlep->lh_vp->v_rdev;

	csp = VTOCS(handlep->lh_vp);
	mutex_enter(&csp->s_lock);
	if ((dip = csp->s_dip) != NULL)
		e_ddi_hold_devi(dip);
	mutex_exit(&csp->s_lock);
	if (dip == NULL)
		dip = e_ddi_hold_devi_by_dev(dev, 0);

	if (dip == NULL) {
		flags |= DDI_UNBND_DLPI2;
	} else if (flags & LDI_DEV_T_ANY) {
		flags &= ~LDI_DEV_T_ANY;
		dev = DDI_DEV_T_ANY;
	}

	if (dip != NULL) {
		int	prop_val;
		int	prop_len;

		/*
		 * first call the drivers prop_op interface to allow it
		 * it to override default property values.
		 */
		prop_len = sizeof (int);
		res = i_ldi_prop_op(dev, dip, PROP_LEN_AND_VAL_BUF,
		    flags | DDI_PROP_DYNAMIC, name,
		    (caddr_t)&prop_val, &prop_len);

		/* if we got it then return it */
		if ((res == DDI_PROP_SUCCESS) &&
		    (prop_len == sizeof (int))) {
			res = prop_val;
			ddi_release_devi(dip);
			return (res);
		}
	}

	/* call the normal property interfaces */
	res = ddi_prop_get_int(dev, dip, flags, name, defvalue);

	if (dip != NULL)
		ddi_release_devi(dip);

	return (res);
}

int64_t
ldi_prop_get_int64(ldi_handle_t lh,
    uint_t flags, char *name, int64_t defvalue)
{
	struct ldi_handle	*handlep = (struct ldi_handle *)lh;
	dev_info_t		*dip;
	dev_t			dev;
	int64_t			res;
	struct snode		*csp;

	if ((lh == NULL) || (name == NULL) || (strlen(name) == 0))
		return (defvalue);

	dev = handlep->lh_vp->v_rdev;

	csp = VTOCS(handlep->lh_vp);
	mutex_enter(&csp->s_lock);
	if ((dip = csp->s_dip) != NULL)
		e_ddi_hold_devi(dip);
	mutex_exit(&csp->s_lock);
	if (dip == NULL)
		dip = e_ddi_hold_devi_by_dev(dev, 0);

	if (dip == NULL) {
		flags |= DDI_UNBND_DLPI2;
	} else if (flags & LDI_DEV_T_ANY) {
		flags &= ~LDI_DEV_T_ANY;
		dev = DDI_DEV_T_ANY;
	}

	if (dip != NULL) {
		int64_t	prop_val;
		int	prop_len;

		/*
		 * first call the drivers prop_op interface to allow it
		 * it to override default property values.
		 */
		prop_len = sizeof (int64_t);
		res = i_ldi_prop_op(dev, dip, PROP_LEN_AND_VAL_BUF,
		    flags | DDI_PROP_DYNAMIC, name,
		    (caddr_t)&prop_val, &prop_len);

		/* if we got it then return it */
		if ((res == DDI_PROP_SUCCESS) &&
		    (prop_len == sizeof (int64_t))) {
			res = prop_val;
			ddi_release_devi(dip);
			return (res);
		}
	}

	/* call the normal property interfaces */
	res = ddi_prop_get_int64(dev, dip, flags, name, defvalue);

	if (dip != NULL)
		ddi_release_devi(dip);

	return (res);
}

int
ldi_prop_exists(ldi_handle_t lh, uint_t flags, char *name)
{
	struct ldi_handle	*handlep = (struct ldi_handle *)lh;
	dev_info_t		*dip;
	dev_t			dev;
	int			res, prop_len;
	struct snode		*csp;

	if ((lh == NULL) || (name == NULL) || (strlen(name) == 0))
		return (0);

	dev = handlep->lh_vp->v_rdev;

	csp = VTOCS(handlep->lh_vp);
	mutex_enter(&csp->s_lock);
	if ((dip = csp->s_dip) != NULL)
		e_ddi_hold_devi(dip);
	mutex_exit(&csp->s_lock);
	if (dip == NULL)
		dip = e_ddi_hold_devi_by_dev(dev, 0);

	/* if NULL dip, prop does NOT exist */
	if (dip == NULL)
		return (0);

	if (flags & LDI_DEV_T_ANY) {
		flags &= ~LDI_DEV_T_ANY;
		dev = DDI_DEV_T_ANY;
	}

	/*
	 * first call the drivers prop_op interface to allow it
	 * it to override default property values.
	 */
	res = i_ldi_prop_op(dev, dip, PROP_LEN,
	    flags | DDI_PROP_DYNAMIC, name, NULL, &prop_len);

	if (res == DDI_PROP_SUCCESS) {
		ddi_release_devi(dip);
		return (1);
	}

	/* call the normal property interfaces */
	res = ddi_prop_exists(dev, dip, flags, name);

	ddi_release_devi(dip);
	return (res);
}

#ifdef	LDI_OBSOLETE_EVENT

int
ldi_get_eventcookie(ldi_handle_t lh, char *name, ddi_eventcookie_t *ecp)
{
	struct ldi_handle	*handlep = (struct ldi_handle *)lh;
	dev_info_t		*dip;
	dev_t			dev;
	int			res;
	struct snode		*csp;

	if ((lh == NULL) || (name == NULL) ||
	    (strlen(name) == 0) || (ecp == NULL)) {
		return (DDI_FAILURE);
	}

	ASSERT(!servicing_interrupt());

	dev = handlep->lh_vp->v_rdev;

	csp = VTOCS(handlep->lh_vp);
	mutex_enter(&csp->s_lock);
	if ((dip = csp->s_dip) != NULL)
		e_ddi_hold_devi(dip);
	mutex_exit(&csp->s_lock);
	if (dip == NULL)
		dip = e_ddi_hold_devi_by_dev(dev, 0);

	if (dip == NULL)
		return (DDI_FAILURE);

	LDI_EVENTCB((CE_NOTE, "%s: event_name=%s, "
	    "dip=0x%p, event_cookiep=0x%p", "ldi_get_eventcookie",
	    name, (void *)dip, (void *)ecp));

	res = ddi_get_eventcookie(dip, name, ecp);

	ddi_release_devi(dip);
	return (res);
}

int
ldi_add_event_handler(ldi_handle_t lh, ddi_eventcookie_t ec,
    void (*handler)(ldi_handle_t, ddi_eventcookie_t, void *, void *),
    void *arg, ldi_callback_id_t *id)
{
	struct ldi_handle	*handlep = (struct ldi_handle *)lh;
	struct ldi_event	*lep;
	dev_info_t		*dip;
	dev_t			dev;
	int			res;
	struct snode		*csp;

	if ((lh == NULL) || (ec == NULL) || (handler == NULL) || (id == NULL))
		return (DDI_FAILURE);

	ASSERT(!servicing_interrupt());

	dev = handlep->lh_vp->v_rdev;

	csp = VTOCS(handlep->lh_vp);
	mutex_enter(&csp->s_lock);
	if ((dip = csp->s_dip) != NULL)
		e_ddi_hold_devi(dip);
	mutex_exit(&csp->s_lock);
	if (dip == NULL)
		dip = e_ddi_hold_devi_by_dev(dev, 0);

	if (dip == NULL)
		return (DDI_FAILURE);

	lep = kmem_zalloc(sizeof (struct ldi_event), KM_SLEEP);
	lep->le_lhp = handlep;
	lep->le_arg = arg;
	lep->le_handler = handler;

	if ((res = ddi_add_event_handler(dip, ec, i_ldi_callback,
	    (void *)lep, &lep->le_id)) != DDI_SUCCESS) {
		LDI_EVENTCB((CE_WARN, "%s: unable to add"
		    "event callback", "ldi_add_event_handler"));
		ddi_release_devi(dip);
		kmem_free(lep, sizeof (struct ldi_event));
		return (res);
	}

	*id = (ldi_callback_id_t)lep;

	LDI_EVENTCB((CE_NOTE, "%s: dip=0x%p, event=0x%p, "
	    "ldi_eventp=0x%p, cb_id=0x%p", "ldi_add_event_handler",
	    (void *)dip, (void *)ec, (void *)lep, (void *)id));

	handle_event_add(lep);
	ddi_release_devi(dip);
	return (res);
}

int
ldi_remove_event_handler(ldi_handle_t lh, ldi_callback_id_t id)
{
	ldi_event_t		*lep = (ldi_event_t *)id;
	int			res;

	if ((lh == NULL) || (id == NULL))
		return (DDI_FAILURE);

	ASSERT(!servicing_interrupt());

	if ((res = ddi_remove_event_handler(lep->le_id))
	    != DDI_SUCCESS) {
		LDI_EVENTCB((CE_WARN, "%s: unable to remove "
		    "event callback", "ldi_remove_event_handler"));
		return (res);
	}

	handle_event_remove(lep);
	kmem_free(lep, sizeof (struct ldi_event));
	return (res);
}

#endif

/*
 * Here are some definitions of terms used in the following LDI events
 * code:
 *
 * "LDI events" AKA "native events": These are events defined by the
 * "new" LDI event framework. These events are serviced by the LDI event
 * framework itself and thus are native to it.
 *
 * "LDI contract events": These are contract events that correspond to the
 *  LDI events. This mapping of LDI events to contract events is defined by
 * the ldi_ev_cookies[] array above.
 *
 * NDI events: These are events which are serviced by the NDI event subsystem.
 * LDI subsystem just provides a thin wrapper around the NDI event interfaces
 * These events are therefore *not* native events.
 */

static int
ldi_native_event(const char *evname)
{
	int i;

	LDI_EVTRC((CE_NOTE, "ldi_native_event: entered: ev=%s", evname));

	for (i = 0; ldi_ev_cookies[i].ck_evname != NULL; i++) {
		if (strcmp(ldi_ev_cookies[i].ck_evname, evname) == 0)
			return (1);
	}

	return (0);
}

static uint_t
ldi_ev_sync_event(const char *evname)
{
	int i;

	ASSERT(ldi_native_event(evname));

	LDI_EVTRC((CE_NOTE, "ldi_ev_sync_event: entered: %s", evname));

	for (i = 0; ldi_ev_cookies[i].ck_evname != NULL; i++) {
		if (strcmp(ldi_ev_cookies[i].ck_evname, evname) == 0)
			return (ldi_ev_cookies[i].ck_sync);
	}

	/*
	 * This should never happen until non-contract based
	 * LDI events are introduced. If that happens, we will
	 * use a "special" token to indicate that there are no
	 * contracts corresponding to this LDI event.
	 */
	cmn_err(CE_PANIC, "Unknown LDI event: %s", evname);

	return (0);
}

static uint_t
ldi_contract_event(const char *evname)
{
	int i;

	ASSERT(ldi_native_event(evname));

	LDI_EVTRC((CE_NOTE, "ldi_contract_event: entered: %s", evname));

	for (i = 0; ldi_ev_cookies[i].ck_evname != NULL; i++) {
		if (strcmp(ldi_ev_cookies[i].ck_evname, evname) == 0)
			return (ldi_ev_cookies[i].ck_ctype);
	}

	/*
	 * This should never happen until non-contract based
	 * LDI events are introduced. If that happens, we will
	 * use a "special" token to indicate that there are no
	 * contracts corresponding to this LDI event.
	 */
	cmn_err(CE_PANIC, "Unknown LDI event: %s", evname);

	return (0);
}

char *
ldi_ev_get_type(ldi_ev_cookie_t cookie)
{
	int i;
	struct ldi_ev_cookie *cookie_impl = (struct ldi_ev_cookie *)cookie;

	for (i = 0; ldi_ev_cookies[i].ck_evname != NULL; i++) {
		if (&ldi_ev_cookies[i] == cookie_impl) {
			LDI_EVTRC((CE_NOTE, "ldi_ev_get_type: LDI: %s",
			    ldi_ev_cookies[i].ck_evname));
			return (ldi_ev_cookies[i].ck_evname);
		}
	}

	/*
	 * Not an LDI native event. Must be NDI event service.
	 * Just return a generic string
	 */
	LDI_EVTRC((CE_NOTE, "ldi_ev_get_type: is NDI"));
	return (NDI_EVENT_SERVICE);
}

static int
ldi_native_cookie(ldi_ev_cookie_t cookie)
{
	int i;
	struct ldi_ev_cookie *cookie_impl = (struct ldi_ev_cookie *)cookie;

	for (i = 0; ldi_ev_cookies[i].ck_evname != NULL; i++) {
		if (&ldi_ev_cookies[i] == cookie_impl) {
			LDI_EVTRC((CE_NOTE, "ldi_native_cookie: native LDI"));
			return (1);
		}
	}

	LDI_EVTRC((CE_NOTE, "ldi_native_cookie: is NDI"));
	return (0);
}

static ldi_ev_cookie_t
ldi_get_native_cookie(const char *evname)
{
	int i;

	for (i = 0; ldi_ev_cookies[i].ck_evname != NULL; i++) {
		if (strcmp(ldi_ev_cookies[i].ck_evname, evname) == 0) {
			LDI_EVTRC((CE_NOTE, "ldi_get_native_cookie: found"));
			return ((ldi_ev_cookie_t)&ldi_ev_cookies[i]);
		}
	}

	LDI_EVTRC((CE_NOTE, "ldi_get_native_cookie: NOT found"));
	return (NULL);
}

/*
 * ldi_ev_lock() needs to be recursive, since layered drivers may call
 * other LDI interfaces (such as ldi_close() from within the context of
 * a notify callback. Since the notify callback is called with the
 * ldi_ev_lock() held and ldi_close() also grabs ldi_ev_lock, the lock needs
 * to be recursive.
 */
static void
ldi_ev_lock(void)
{
	LDI_EVTRC((CE_NOTE, "ldi_ev_lock: entered"));

	mutex_enter(&ldi_ev_callback_list.le_lock);
	if (ldi_ev_callback_list.le_thread == curthread) {
		ASSERT(ldi_ev_callback_list.le_busy >= 1);
		ldi_ev_callback_list.le_busy++;
	} else {
		while (ldi_ev_callback_list.le_busy)
			cv_wait(&ldi_ev_callback_list.le_cv,
			    &ldi_ev_callback_list.le_lock);
		ASSERT(ldi_ev_callback_list.le_thread == NULL);
		ldi_ev_callback_list.le_busy = 1;
		ldi_ev_callback_list.le_thread = curthread;
	}
	mutex_exit(&ldi_ev_callback_list.le_lock);

	LDI_EVTRC((CE_NOTE, "ldi_ev_lock: exit"));
}

static void
ldi_ev_unlock(void)
{
	LDI_EVTRC((CE_NOTE, "ldi_ev_unlock: entered"));
	mutex_enter(&ldi_ev_callback_list.le_lock);
	ASSERT(ldi_ev_callback_list.le_thread == curthread);
	ASSERT(ldi_ev_callback_list.le_busy >= 1);

	ldi_ev_callback_list.le_busy--;
	if (ldi_ev_callback_list.le_busy == 0) {
		ldi_ev_callback_list.le_thread = NULL;
		cv_signal(&ldi_ev_callback_list.le_cv);
	}
	mutex_exit(&ldi_ev_callback_list.le_lock);
	LDI_EVTRC((CE_NOTE, "ldi_ev_unlock: exit"));
}

int
ldi_ev_get_cookie(ldi_handle_t lh, char *evname, ldi_ev_cookie_t *cookiep)
{
	struct ldi_handle	*handlep = (struct ldi_handle *)lh;
	dev_info_t		*dip;
	dev_t			dev;
	int			res;
	struct snode		*csp;
	ddi_eventcookie_t	ddi_cookie;
	ldi_ev_cookie_t		tcookie;

	LDI_EVDBG((CE_NOTE, "ldi_ev_get_cookie: entered: evname=%s",
	    evname ? evname : "<NULL>"));

	if (lh == NULL || evname == NULL ||
	    strlen(evname) == 0 || cookiep == NULL) {
		LDI_EVDBG((CE_NOTE, "ldi_ev_get_cookie: invalid args"));
		return (LDI_EV_FAILURE);
	}

	*cookiep = NULL;

	/*
	 * First check if it is a LDI native event
	 */
	tcookie = ldi_get_native_cookie(evname);
	if (tcookie) {
		LDI_EVDBG((CE_NOTE, "ldi_ev_get_cookie: got native cookie"));
		*cookiep = tcookie;
		return (LDI_EV_SUCCESS);
	}

	/*
	 * Not a LDI native event. Try NDI event services
	 */

	dev = handlep->lh_vp->v_rdev;

	csp = VTOCS(handlep->lh_vp);
	mutex_enter(&csp->s_lock);
	if ((dip = csp->s_dip) != NULL)
		e_ddi_hold_devi(dip);
	mutex_exit(&csp->s_lock);
	if (dip == NULL)
		dip = e_ddi_hold_devi_by_dev(dev, 0);

	if (dip == NULL) {
		cmn_err(CE_WARN, "ldi_ev_get_cookie: No devinfo node for LDI "
		    "handle: %p", (void *)handlep);
		return (LDI_EV_FAILURE);
	}

	LDI_EVDBG((CE_NOTE, "Calling ddi_get_eventcookie: dip=%p, ev=%s",
	    (void *)dip, evname));

	res = ddi_get_eventcookie(dip, evname, &ddi_cookie);

	ddi_release_devi(dip);

	if (res == DDI_SUCCESS) {
		LDI_EVDBG((CE_NOTE, "ldi_ev_get_cookie: NDI cookie found"));
		*cookiep = (ldi_ev_cookie_t)ddi_cookie;
		return (LDI_EV_SUCCESS);
	} else {
		LDI_EVDBG((CE_WARN, "ldi_ev_get_cookie: NDI cookie: failed"));
		return (LDI_EV_FAILURE);
	}
}

/*ARGSUSED*/
static void
i_ldi_ev_callback(dev_info_t *dip, ddi_eventcookie_t event_cookie,
    void *arg, void *ev_data)
{
	ldi_ev_callback_impl_t *lecp = (ldi_ev_callback_impl_t *)arg;

	ASSERT(lecp != NULL);
	ASSERT(!ldi_native_cookie(lecp->lec_cookie));
	ASSERT(lecp->lec_lhp);
	ASSERT(lecp->lec_notify == NULL);
	ASSERT(lecp->lec_finalize);

	LDI_EVDBG((CE_NOTE, "i_ldi_ev_callback: ldh=%p, cookie=%p, arg=%p, "
	    "ev_data=%p", (void *)lecp->lec_lhp, (void *)event_cookie,
	    (void *)lecp->lec_arg, (void *)ev_data));

	lecp->lec_finalize(lecp->lec_lhp, (ldi_ev_cookie_t)event_cookie,
	    lecp->lec_arg, ev_data);
}

int
ldi_ev_register_callbacks(ldi_handle_t lh, ldi_ev_cookie_t cookie,
    ldi_ev_callback_t *callb, void *arg, ldi_callback_id_t *id)
{
	struct ldi_handle	*lhp = (struct ldi_handle *)lh;
	ldi_ev_callback_impl_t	*lecp;
	dev_t			dev;
	struct snode		*csp;
	dev_info_t		*dip;
	int			ddi_event;

	ASSERT(!servicing_interrupt());

	if (lh == NULL || cookie == NULL || callb == NULL || id == NULL) {
		LDI_EVDBG((CE_NOTE, "ldi_ev_register_callbacks: Invalid args"));
		return (LDI_EV_FAILURE);
	}

	if (callb->cb_vers != LDI_EV_CB_VERS) {
		LDI_EVDBG((CE_NOTE, "ldi_ev_register_callbacks: Invalid vers"));
		return (LDI_EV_FAILURE);
	}

	if (callb->cb_notify == NULL && callb->cb_finalize == NULL) {
		LDI_EVDBG((CE_NOTE, "ldi_ev_register_callbacks: NULL callb"));
		return (LDI_EV_FAILURE);
	}

	*id = 0;

	dev = lhp->lh_vp->v_rdev;
	csp = VTOCS(lhp->lh_vp);
	mutex_enter(&csp->s_lock);
	if ((dip = csp->s_dip) != NULL)
		e_ddi_hold_devi(dip);
	mutex_exit(&csp->s_lock);
	if (dip == NULL)
		dip = e_ddi_hold_devi_by_dev(dev, 0);

	if (dip == NULL) {
		cmn_err(CE_WARN, "ldi_ev_register: No devinfo node for "
		    "LDI handle: %p", (void *)lhp);
		return (LDI_EV_FAILURE);
	}

	lecp = kmem_zalloc(sizeof (ldi_ev_callback_impl_t), KM_SLEEP);

	ddi_event = 0;
	if (!ldi_native_cookie(cookie)) {
		if (callb->cb_notify || callb->cb_finalize == NULL) {
			/*
			 * NDI event services only accept finalize
			 */
			cmn_err(CE_WARN, "%s: module: %s: NDI event cookie. "
			    "Only finalize"
			    " callback supported with this cookie",
			    "ldi_ev_register_callbacks",
			    lhp->lh_ident->li_modname);
			kmem_free(lecp, sizeof (ldi_ev_callback_impl_t));
			ddi_release_devi(dip);
			return (LDI_EV_FAILURE);
		}

		if (ddi_add_event_handler(dip, (ddi_eventcookie_t)cookie,
		    i_ldi_ev_callback, (void *)lecp,
		    (ddi_callback_id_t *)&lecp->lec_id)
		    != DDI_SUCCESS) {
			kmem_free(lecp, sizeof (ldi_ev_callback_impl_t));
			ddi_release_devi(dip);
			LDI_EVDBG((CE_NOTE, "ldi_ev_register_callbacks(): "
			    "ddi_add_event_handler failed"));
			return (LDI_EV_FAILURE);
		}
		ddi_event = 1;
		LDI_EVDBG((CE_NOTE, "ldi_ev_register_callbacks(): "
		    "ddi_add_event_handler success"));
	}



	ldi_ev_lock();

	/*
	 * Add the notify/finalize callback to the LDI's list of callbacks.
	 */
	lecp->lec_lhp = lhp;
	lecp->lec_dev = lhp->lh_vp->v_rdev;
	lecp->lec_spec = VTYP_TO_STYP(lhp->lh_vp->v_type);
	lecp->lec_notify = callb->cb_notify;
	lecp->lec_finalize = callb->cb_finalize;
	lecp->lec_arg = arg;
	lecp->lec_cookie = cookie;
	if (!ddi_event)
		lecp->lec_id = (void *)(uintptr_t)(++ldi_ev_id_pool);
	else
		ASSERT(lecp->lec_id);
	lecp->lec_dip = dip;
	list_insert_tail(&ldi_ev_callback_list.le_head, lecp);

	*id = (ldi_callback_id_t)lecp->lec_id;

	ldi_ev_unlock();

	ddi_release_devi(dip);

	LDI_EVDBG((CE_NOTE, "ldi_ev_register_callbacks: registered "
	    "notify/finalize"));

	return (LDI_EV_SUCCESS);
}

static int
ldi_ev_device_match(ldi_ev_callback_impl_t *lecp, dev_info_t *dip,
    dev_t dev, int spec_type)
{
	ASSERT(lecp);
	ASSERT(dip);
	ASSERT(dev != DDI_DEV_T_NONE);
	ASSERT(dev != NODEV);
	ASSERT((dev == DDI_DEV_T_ANY && spec_type == 0) ||
	    (spec_type == S_IFCHR || spec_type == S_IFBLK));
	ASSERT(lecp->lec_dip);
	ASSERT(lecp->lec_spec == S_IFCHR || lecp->lec_spec == S_IFBLK);
	ASSERT(lecp->lec_dev != DDI_DEV_T_ANY);
	ASSERT(lecp->lec_dev != DDI_DEV_T_NONE);
	ASSERT(lecp->lec_dev != NODEV);

	if (dip != lecp->lec_dip)
		return (0);

	if (dev != DDI_DEV_T_ANY) {
		if (dev != lecp->lec_dev || spec_type != lecp->lec_spec)
			return (0);
	}

	LDI_EVTRC((CE_NOTE, "ldi_ev_device_match: MATCH dip=%p", (void *)dip));

	return (1);
}

/*
 * LDI framework function to post a "notify" event to all layered drivers
 * that have registered for that event
 *
 * Returns:
 *		LDI_EV_SUCCESS - registered callbacks allow event
 *		LDI_EV_FAILURE - registered callbacks block event
 *		LDI_EV_NONE    - No matching LDI callbacks
 *
 * This function is *not* to be called by layered drivers. It is for I/O
 * framework code in Solaris, such as the I/O retire code and DR code
 * to call while servicing a device event such as offline or degraded.
 */
int
ldi_invoke_notify(dev_info_t *dip, dev_t dev, int spec_type, char *event,
    void *ev_data)
{
	ldi_ev_callback_impl_t *lecp;
	list_t	*listp;
	int	ret;
	char	*lec_event;

	ASSERT(dip);
	ASSERT(dev != DDI_DEV_T_NONE);
	ASSERT(dev != NODEV);
	ASSERT((dev == DDI_DEV_T_ANY && spec_type == 0) ||
	    (spec_type == S_IFCHR || spec_type == S_IFBLK));
	ASSERT(event);
	ASSERT(ldi_native_event(event));
	ASSERT(ldi_ev_sync_event(event));

	LDI_EVDBG((CE_NOTE, "ldi_invoke_notify(): entered: dip=%p, ev=%s",
	    (void *)dip, event));

	ret = LDI_EV_NONE;
	ldi_ev_lock();

	VERIFY(ldi_ev_callback_list.le_walker_next == NULL);
	listp = &ldi_ev_callback_list.le_head;
	for (lecp = list_head(listp); lecp; lecp =
	    ldi_ev_callback_list.le_walker_next) {
		ldi_ev_callback_list.le_walker_next = list_next(listp, lecp);

		/* Check if matching device */
		if (!ldi_ev_device_match(lecp, dip, dev, spec_type))
			continue;

		if (lecp->lec_lhp == NULL) {
			/*
			 * Consumer has unregistered the handle and so
			 * is no longer interested in notify events.
			 */
			LDI_EVDBG((CE_NOTE, "ldi_invoke_notify(): No LDI "
			    "handle, skipping"));
			continue;
		}

		if (lecp->lec_notify == NULL) {
			LDI_EVDBG((CE_NOTE, "ldi_invoke_notify(): No notify "
			    "callback. skipping"));
			continue;	/* not interested in notify */
		}

		/*
		 * Check if matching event
		 */
		lec_event = ldi_ev_get_type(lecp->lec_cookie);
		if (strcmp(event, lec_event) != 0) {
			LDI_EVDBG((CE_NOTE, "ldi_invoke_notify(): Not matching"
			    " event {%s,%s}. skipping", event, lec_event));
			continue;
		}

		lecp->lec_lhp->lh_flags |= LH_FLAGS_NOTIFY;
		if (lecp->lec_notify(lecp->lec_lhp, lecp->lec_cookie,
		    lecp->lec_arg, ev_data) != LDI_EV_SUCCESS) {
			ret = LDI_EV_FAILURE;
			LDI_EVDBG((CE_NOTE, "ldi_invoke_notify(): notify"
			    " FAILURE"));
			break;
		}

		/* We have a matching callback that allows the event to occur */
		ret = LDI_EV_SUCCESS;

		LDI_EVDBG((CE_NOTE, "ldi_invoke_notify(): 1 consumer success"));
	}

	if (ret != LDI_EV_FAILURE)
		goto out;

	LDI_EVDBG((CE_NOTE, "ldi_invoke_notify(): undoing notify"));

	/*
	 * Undo notifies already sent
	 */
	lecp = list_prev(listp, lecp);
	VERIFY(ldi_ev_callback_list.le_walker_prev == NULL);
	for (; lecp; lecp = ldi_ev_callback_list.le_walker_prev) {
		ldi_ev_callback_list.le_walker_prev = list_prev(listp, lecp);

		/*
		 * Check if matching device
		 */
		if (!ldi_ev_device_match(lecp, dip, dev, spec_type))
			continue;


		if (lecp->lec_finalize == NULL) {
			LDI_EVDBG((CE_NOTE, "ldi_invoke_notify(): no finalize, "
			    "skipping"));
			continue;	/* not interested in finalize */
		}

		/*
		 * it is possible that in response to a notify event a
		 * layered driver closed its LDI handle so it is ok
		 * to have a NULL LDI handle for finalize. The layered
		 * driver is expected to maintain state in its "arg"
		 * parameter to keep track of the closed device.
		 */

		/* Check if matching event */
		lec_event = ldi_ev_get_type(lecp->lec_cookie);
		if (strcmp(event, lec_event) != 0) {
			LDI_EVDBG((CE_NOTE, "ldi_invoke_notify(): not matching "
			    "event: %s,%s, skipping", event, lec_event));
			continue;
		}

		LDI_EVDBG((CE_NOTE, "ldi_invoke_notify(): calling finalize"));

		lecp->lec_finalize(lecp->lec_lhp, lecp->lec_cookie,
		    LDI_EV_FAILURE, lecp->lec_arg, ev_data);

		/*
		 * If LDI native event and LDI handle closed in context
		 * of notify, NULL out the finalize callback as we have
		 * already called the 1 finalize above allowed in this situation
		 */
		if (lecp->lec_lhp == NULL &&
		    ldi_native_cookie(lecp->lec_cookie)) {
			LDI_EVDBG((CE_NOTE,
			    "ldi_invoke_notify(): NULL-ing finalize after "
			    "calling 1 finalize following ldi_close"));
			lecp->lec_finalize = NULL;
		}
	}

out:
	ldi_ev_callback_list.le_walker_next = NULL;
	ldi_ev_callback_list.le_walker_prev = NULL;
	ldi_ev_unlock();

	if (ret == LDI_EV_NONE) {
		LDI_EVDBG((CE_NOTE, "ldi_invoke_notify(): no matching "
		    "LDI callbacks"));
	}

	return (ret);
}

/*
 * Framework function to be called from a layered driver to propagate
 * LDI "notify" events to exported minors.
 *
 * This function is a public interface exported by the LDI framework
 * for use by layered drivers to propagate device events up the software
 * stack.
 */
int
ldi_ev_notify(dev_info_t *dip, minor_t minor, int spec_type,
    ldi_ev_cookie_t cookie, void *ev_data)
{
	char		*evname = ldi_ev_get_type(cookie);
	uint_t		ct_evtype;
	dev_t		dev;
	major_t		major;
	int		retc;
	int		retl;

	ASSERT(spec_type == S_IFBLK || spec_type == S_IFCHR);
	ASSERT(dip);
	ASSERT(ldi_native_cookie(cookie));

	LDI_EVDBG((CE_NOTE, "ldi_ev_notify(): entered: event=%s, dip=%p",
	    evname, (void *)dip));

	if (!ldi_ev_sync_event(evname)) {
		cmn_err(CE_PANIC, "ldi_ev_notify(): %s not a "
		    "negotiatable event", evname);
		return (LDI_EV_SUCCESS);
	}

	major = ddi_driver_major(dip);
	if (major == DDI_MAJOR_T_NONE) {
		char *path = kmem_alloc(MAXPATHLEN, KM_SLEEP);
		(void) ddi_pathname(dip, path);
		cmn_err(CE_WARN, "ldi_ev_notify: cannot derive major number "
		    "for device %s", path);
		kmem_free(path, MAXPATHLEN);
		return (LDI_EV_FAILURE);
	}
	dev = makedevice(major, minor);

	/*
	 * Generate negotiation contract events on contracts (if any) associated
	 * with this minor.
	 */
	LDI_EVDBG((CE_NOTE, "ldi_ev_notify(): calling contract nego."));
	ct_evtype = ldi_contract_event(evname);
	retc = contract_device_negotiate(dip, dev, spec_type, ct_evtype);
	if (retc == CT_NACK) {
		LDI_EVDBG((CE_NOTE, "ldi_ev_notify(): contract neg. NACK"));
		return (LDI_EV_FAILURE);
	}

	LDI_EVDBG((CE_NOTE, "ldi_ev_notify(): LDI invoke notify"));
	retl = ldi_invoke_notify(dip, dev, spec_type, evname, ev_data);
	if (retl == LDI_EV_FAILURE) {
		LDI_EVDBG((CE_NOTE, "ldi_ev_notify(): ldi_invoke_notify "
		    "returned FAILURE. Calling contract negend"));
		contract_device_negend(dip, dev, spec_type, CT_EV_FAILURE);
		return (LDI_EV_FAILURE);
	}

	/*
	 * The very fact that we are here indicates that there is a
	 * LDI callback (and hence a constraint) for the retire of the
	 * HW device. So we just return success even if there are no
	 * contracts or LDI callbacks against the minors layered on top
	 * of the HW minors
	 */
	LDI_EVDBG((CE_NOTE, "ldi_ev_notify(): returning SUCCESS"));
	return (LDI_EV_SUCCESS);
}

/*
 * LDI framework function to invoke "finalize" callbacks for all layered
 * drivers that have registered callbacks for that event.
 *
 * This function is *not* to be called by layered drivers. It is for I/O
 * framework code in Solaris, such as the I/O retire code and DR code
 * to call while servicing a device event such as offline or degraded.
 */
void
ldi_invoke_finalize(dev_info_t *dip, dev_t dev, int spec_type, char *event,
    int ldi_result, void *ev_data)
{
	ldi_ev_callback_impl_t *lecp;
	list_t	*listp;
	char	*lec_event;
	int	found = 0;

	ASSERT(dip);
	ASSERT(dev != DDI_DEV_T_NONE);
	ASSERT(dev != NODEV);
	ASSERT((dev == DDI_DEV_T_ANY && spec_type == 0) ||
	    (spec_type == S_IFCHR || spec_type == S_IFBLK));
	ASSERT(event);
	ASSERT(ldi_native_event(event));
	ASSERT(ldi_result == LDI_EV_SUCCESS || ldi_result == LDI_EV_FAILURE);

	LDI_EVDBG((CE_NOTE, "ldi_invoke_finalize(): entered: dip=%p, result=%d"
	    " event=%s", (void *)dip, ldi_result, event));

	ldi_ev_lock();
	VERIFY(ldi_ev_callback_list.le_walker_next == NULL);
	listp = &ldi_ev_callback_list.le_head;
	for (lecp = list_head(listp); lecp; lecp =
	    ldi_ev_callback_list.le_walker_next) {
		ldi_ev_callback_list.le_walker_next = list_next(listp, lecp);

		if (lecp->lec_finalize == NULL) {
			LDI_EVDBG((CE_NOTE, "ldi_invoke_finalize(): No "
			    "finalize. Skipping"));
			continue;	/* Not interested in finalize */
		}

		/*
		 * Check if matching device
		 */
		if (!ldi_ev_device_match(lecp, dip, dev, spec_type))
			continue;

		/*
		 * It is valid for the LDI handle to be NULL during finalize.
		 * The layered driver may have done an LDI close in the notify
		 * callback.
		 */

		/*
		 * Check if matching event
		 */
		lec_event = ldi_ev_get_type(lecp->lec_cookie);
		if (strcmp(event, lec_event) != 0) {
			LDI_EVDBG((CE_NOTE, "ldi_invoke_finalize(): Not "
			    "matching event {%s,%s}. Skipping",
			    event, lec_event));
			continue;
		}

		LDI_EVDBG((CE_NOTE, "ldi_invoke_finalize(): calling finalize"));

		found = 1;

		lecp->lec_finalize(lecp->lec_lhp, lecp->lec_cookie,
		    ldi_result, lecp->lec_arg, ev_data);

		/*
		 * If LDI native event and LDI handle closed in context
		 * of notify, NULL out the finalize callback as we have
		 * already called the 1 finalize above allowed in this situation
		 */
		if (lecp->lec_lhp == NULL &&
		    ldi_native_cookie(lecp->lec_cookie)) {
			LDI_EVDBG((CE_NOTE,
			    "ldi_invoke_finalize(): NULLing finalize after "
			    "calling 1 finalize following ldi_close"));
			lecp->lec_finalize = NULL;
		}
	}
	ldi_ev_callback_list.le_walker_next = NULL;
	ldi_ev_unlock();

	if (found)
		return;

	LDI_EVDBG((CE_NOTE, "ldi_invoke_finalize(): no matching callbacks"));
}

/*
 * Framework function to be called from a layered driver to propagate
 * LDI "finalize" events to exported minors.
 *
 * This function is a public interface exported by the LDI framework
 * for use by layered drivers to propagate device events up the software
 * stack.
 */
void
ldi_ev_finalize(dev_info_t *dip, minor_t minor, int spec_type, int ldi_result,
    ldi_ev_cookie_t cookie, void *ev_data)
{
	dev_t dev;
	major_t major;
	char *evname;
	int ct_result = (ldi_result == LDI_EV_SUCCESS) ?
	    CT_EV_SUCCESS : CT_EV_FAILURE;
	uint_t ct_evtype;

	ASSERT(dip);
	ASSERT(spec_type == S_IFBLK || spec_type == S_IFCHR);
	ASSERT(ldi_result == LDI_EV_SUCCESS || ldi_result == LDI_EV_FAILURE);
	ASSERT(ldi_native_cookie(cookie));

	LDI_EVDBG((CE_NOTE, "ldi_ev_finalize: entered: dip=%p", (void *)dip));

	major = ddi_driver_major(dip);
	if (major == DDI_MAJOR_T_NONE) {
		char *path = kmem_alloc(MAXPATHLEN, KM_SLEEP);
		(void) ddi_pathname(dip, path);
		cmn_err(CE_WARN, "ldi_ev_finalize: cannot derive major number "
		    "for device %s", path);
		kmem_free(path, MAXPATHLEN);
		return;
	}
	dev = makedevice(major, minor);

	evname = ldi_ev_get_type(cookie);

	LDI_EVDBG((CE_NOTE, "ldi_ev_finalize: calling contracts"));
	ct_evtype = ldi_contract_event(evname);
	contract_device_finalize(dip, dev, spec_type, ct_evtype, ct_result);

	LDI_EVDBG((CE_NOTE, "ldi_ev_finalize: calling ldi_invoke_finalize"));
	ldi_invoke_finalize(dip, dev, spec_type, evname, ldi_result, ev_data);
}

int
ldi_ev_remove_callbacks(ldi_callback_id_t id)
{
	ldi_ev_callback_impl_t	*lecp;
	ldi_ev_callback_impl_t	*next;
	ldi_ev_callback_impl_t	*found;
	list_t			*listp;

	ASSERT(!servicing_interrupt());

	if (id == 0) {
		cmn_err(CE_WARN, "ldi_ev_remove_callbacks: Invalid ID 0");
		return (LDI_EV_FAILURE);
	}

	LDI_EVDBG((CE_NOTE, "ldi_ev_remove_callbacks: entered: id=%p",
	    (void *)id));

	ldi_ev_lock();

	listp = &ldi_ev_callback_list.le_head;
	next = found = NULL;
	for (lecp = list_head(listp); lecp; lecp = next) {
		next = list_next(listp, lecp);
		if (lecp->lec_id == id) {
			VERIFY(found == NULL);

			/*
			 * If there is a walk in progress, shift that walk
			 * along to the next element so that we can remove
			 * this one.  This allows us to unregister an arbitrary
			 * number of callbacks from within a callback.
			 *
			 * See the struct definition (in sunldi_impl.h) for
			 * more information.
			 */
			if (ldi_ev_callback_list.le_walker_next == lecp)
				ldi_ev_callback_list.le_walker_next = next;
			if (ldi_ev_callback_list.le_walker_prev == lecp)
				ldi_ev_callback_list.le_walker_prev = list_prev(
				    listp, ldi_ev_callback_list.le_walker_prev);

			list_remove(listp, lecp);
			found = lecp;
		}
	}
	ldi_ev_unlock();

	if (found == NULL) {
		cmn_err(CE_WARN, "No LDI event handler for id (%p)",
		    (void *)id);
		return (LDI_EV_SUCCESS);
	}

	if (!ldi_native_cookie(found->lec_cookie)) {
		ASSERT(found->lec_notify == NULL);
		if (ddi_remove_event_handler((ddi_callback_id_t)id)
		    != DDI_SUCCESS) {
			cmn_err(CE_WARN, "failed to remove NDI event handler "
			    "for id (%p)", (void *)id);
			ldi_ev_lock();
			list_insert_tail(listp, found);
			ldi_ev_unlock();
			return (LDI_EV_FAILURE);
		}
		LDI_EVDBG((CE_NOTE, "ldi_ev_remove_callbacks: NDI event "
		    "service removal succeeded"));
	} else {
		LDI_EVDBG((CE_NOTE, "ldi_ev_remove_callbacks: removed "
		    "LDI native callbacks"));
	}
	kmem_free(found, sizeof (ldi_ev_callback_impl_t));

	return (LDI_EV_SUCCESS);
}
