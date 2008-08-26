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

/*
 * Data-Link Driver
 */

#include	<sys/conf.h>
#include	<sys/mkdev.h>
#include	<sys/modctl.h>
#include	<sys/stat.h>
#include	<sys/vlan.h>
#include	<sys/mac.h>
#include	<sys/dld_impl.h>
#include	<sys/dls_impl.h>
#include	<sys/softmac.h>
#include 	<sys/vlan.h>
#include	<sys/policy.h>
#include	<inet/common.h>

static void	drv_init(void);
static int	drv_fini(void);

static int	drv_getinfo(dev_info_t	*, ddi_info_cmd_t, void *, void **);
static int	drv_attach(dev_info_t *, ddi_attach_cmd_t);
static int	drv_detach(dev_info_t *, ddi_detach_cmd_t);

/*
 * Secure objects declarations
 */
#define	SECOBJ_WEP_HASHSZ	67
static krwlock_t	drv_secobj_lock;
static kmem_cache_t	*drv_secobj_cachep;
static mod_hash_t	*drv_secobj_hash;
static void		drv_secobj_init(void);
static void		drv_secobj_fini(void);
static int		drv_ioc_setap(datalink_id_t, struct dlautopush *);
static int		drv_ioc_getap(datalink_id_t, struct dlautopush *);
static int		drv_ioc_clrap(datalink_id_t);


/*
 * The following entry points are private to dld and are used for control
 * operations only. The entry points exported to mac drivers are defined
 * in dld_str.c. Refer to the comment on top of dld_str.c for details.
 */
static int	drv_open(dev_t *, int, int, cred_t *);
static int	drv_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);

static dev_info_t	*dld_dip;	/* dev_info_t for the driver */
uint32_t		dld_opt = 0;	/* Global options */

#define	NAUTOPUSH 32
static mod_hash_t *dld_ap_hashp;
static krwlock_t dld_ap_hash_lock;

static struct cb_ops drv_cb_ops = {
	drv_open,		/* open */
	nulldev,		/* close */
	nulldev,		/* strategy */
	nulldev,		/* print */
	nodev,			/* dump */
	nodev,			/* read */
	nodev,			/* write */
	drv_ioctl,		/* ioctl */
	nodev,			/* devmap */
	nodev,			/* mmap */
	nodev,			/* segmap */
	nochpoll,		/* poll */
	ddi_prop_op,		/* cb_prop_op */
	0,			/* streamtab  */
	D_MP			/* Driver compatibility flag */
};

static struct dev_ops drv_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* refcnt */
	drv_getinfo,		/* get_dev_info */
	nulldev,		/* identify */
	nulldev,		/* probe */
	drv_attach,		/* attach */
	drv_detach,		/* detach */
	nodev,			/* reset */
	&drv_cb_ops,		/* driver operations */
	NULL,			/* bus operations */
	nodev			/* dev power */
};

/*
 * Module linkage information for the kernel.
 */
static	struct modldrv		drv_modldrv = {
	&mod_driverops,
	DLD_INFO,
	&drv_ops
};

static	struct modlinkage	drv_modlinkage = {
	MODREV_1,
	&drv_modldrv,
	NULL
};

int
_init(void)
{
	return (mod_install(&drv_modlinkage));
}

int
_fini(void)
{
	return (mod_remove(&drv_modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&drv_modlinkage, modinfop));
}

/*
 * Initialize component modules.
 */
static void
drv_init(void)
{
	drv_secobj_init();
	dld_str_init();
	/*
	 * Create a hash table for autopush configuration.
	 */
	dld_ap_hashp = mod_hash_create_idhash("dld_autopush_hash",
	    NAUTOPUSH, mod_hash_null_valdtor);

	ASSERT(dld_ap_hashp != NULL);
	rw_init(&dld_ap_hash_lock, NULL, RW_DRIVER, NULL);
}

/* ARGSUSED */
static uint_t
drv_ap_exist(mod_hash_key_t key, mod_hash_val_t *val, void *arg)
{
	boolean_t *pexist = arg;

	*pexist = B_TRUE;
	return (MH_WALK_TERMINATE);
}

static int
drv_fini(void)
{
	int		err;
	boolean_t	exist = B_FALSE;

	rw_enter(&dld_ap_hash_lock, RW_READER);
	mod_hash_walk(dld_ap_hashp, drv_ap_exist, &exist);
	rw_exit(&dld_ap_hash_lock);

	if (exist)
		return (EBUSY);

	if ((err = dld_str_fini()) != 0)
		return (err);

	drv_secobj_fini();
	mod_hash_destroy_idhash(dld_ap_hashp);
	rw_destroy(&dld_ap_hash_lock);
	return (0);
}

/*
 * devo_getinfo: getinfo(9e)
 */
/*ARGSUSED*/
static int
drv_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **resp)
{
	if (dld_dip == NULL)
		return (DDI_FAILURE);

	switch (cmd) {
	case DDI_INFO_DEVT2INSTANCE:
		*resp = 0;
		break;
	case DDI_INFO_DEVT2DEVINFO:
		*resp = dld_dip;
		break;
	default:
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/*
 * Check properties to set options. (See dld.h for property definitions).
 */
static void
drv_set_opt(dev_info_t *dip)
{
	if (ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    DLD_PROP_NO_FASTPATH, 0) != 0) {
		dld_opt |= DLD_OPT_NO_FASTPATH;
	}

	if (ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    DLD_PROP_NO_POLL, 0) != 0) {
		dld_opt |= DLD_OPT_NO_POLL;
	}

	if (ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    DLD_PROP_NO_ZEROCOPY, 0) != 0) {
		dld_opt |= DLD_OPT_NO_ZEROCOPY;
	}

	if (ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    DLD_PROP_NO_SOFTRING, 0) != 0) {
		dld_opt |= DLD_OPT_NO_SOFTRING;
	}
}

/*
 * devo_attach: attach(9e)
 */
static int
drv_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);

	ASSERT(ddi_get_instance(dip) == 0);
	drv_init();
	drv_set_opt(dip);

	/*
	 * Create control node. DLPI provider nodes will be created on demand.
	 */
	if (ddi_create_minor_node(dip, DLD_CONTROL_MINOR_NAME, S_IFCHR,
	    DLD_CONTROL_MINOR, DDI_PSEUDO, 0) != DDI_SUCCESS)
		return (DDI_FAILURE);

	dld_dip = dip;

	/*
	 * Log the fact that the driver is now attached.
	 */
	ddi_report_dev(dip);
	return (DDI_SUCCESS);
}

/*
 * devo_detach: detach(9e)
 */
static int
drv_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);

	ASSERT(dld_dip == dip);
	if (drv_fini() != 0)
		return (DDI_FAILURE);

	/*
	 * Remove the control node.
	 */
	ddi_remove_minor_node(dip, DLD_CONTROL_MINOR_NAME);
	dld_dip = NULL;

	return (DDI_SUCCESS);
}

/*
 * dld control node open procedure.
 */
/*ARGSUSED*/
static int
drv_open(dev_t *devp, int flag, int sflag, cred_t *credp)
{
	/*
	 * Only the control node can be opened.
	 */
	if (getminor(*devp) != DLD_CONTROL_MINOR)
		return (ENODEV);
	return (0);
}

/*
 * DLDIOC_ATTR
 */
/* ARGSUSED */
static int
drv_ioc_attr(void *karg, intptr_t arg, int mode, cred_t *cred)
{
	dld_ioc_attr_t		*diap = karg;
	dls_dl_handle_t		dlh;
	dls_vlan_t		*dvp;
	int			err;

	if ((err = dls_devnet_hold_tmp(diap->dia_linkid, &dlh)) != 0)
		return (err);

	if ((err = dls_vlan_hold(dls_devnet_mac(dlh),
	    dls_devnet_vid(dlh), &dvp, B_FALSE, B_FALSE)) != 0) {
		dls_devnet_rele_tmp(dlh);
		return (err);
	}
	mac_sdu_get(dvp->dv_dlp->dl_mh, NULL, &diap->dia_max_sdu);

	dls_vlan_rele(dvp);
	dls_devnet_rele_tmp(dlh);

	return (0);
}

/*
 * DLDIOC_PHYS_ATTR
 */
/* ARGSUSED */
static int
drv_ioc_phys_attr(void *karg, intptr_t arg, int mode, cred_t *cred)
{
	dld_ioc_phys_attr_t	*dipp = karg;
	int			err;
	dls_dl_handle_t		dlh;
	dls_dev_handle_t	ddh;
	dev_t			phydev;

	/*
	 * Every physical link should have its physical dev_t kept in the
	 * daemon. If not, it is not a valid physical link.
	 */
	if (dls_mgmt_get_phydev(dipp->dip_linkid, &phydev) != 0)
		return (EINVAL);

	/*
	 * Although this is a valid physical link, it might already be removed
	 * by DR or during system shutdown. softmac_hold_device() would return
	 * ENOENT in this case.
	 */
	if ((err = softmac_hold_device(phydev, &ddh)) != 0)
		return (err);

	if (dls_devnet_hold_tmp(dipp->dip_linkid, &dlh) != 0) {
		/*
		 * Although this is an active physical link, its link type is
		 * not supported by GLDv3, and therefore it does not have
		 * vanity naming support.
		 */
		dipp->dip_novanity = B_TRUE;
	} else {
		dipp->dip_novanity = B_FALSE;
		dls_devnet_rele_tmp(dlh);
	}
	/*
	 * Get the physical device name from the major number and the instance
	 * number derived from phydev.
	 */
	(void) snprintf(dipp->dip_dev, MAXLINKNAMELEN, "%s%d",
	    ddi_major_to_name(getmajor(phydev)), getminor(phydev) - 1);

	softmac_rele_device(ddh);
	return (0);
}

/*
 * DLDIOC_SETPROP
 */
static int
drv_ioc_prop_common(dld_ioc_macprop_t *dipp, intptr_t arg, boolean_t set,
    int mode)
{
	int		err = EINVAL;
	size_t		dsize;
	dld_ioc_macprop_t	*kdipp;
	dls_dl_handle_t		dlh;
	dls_vlan_t		*dvp;
	datalink_id_t 		linkid;
	mac_prop_t		macprop;
	uchar_t			*cp;
	struct dlautopush	*dlap;
	dld_ioc_zid_t		*dzp;

	/*
	 * We only use pr_valsize from dipp, as the caller only did a
	 * copyin() for sizeof (dld_ioc_prop_t), which doesn't cover
	 * the property data.  We copyin the full dld_ioc_prop_t
	 * including the data into kdipp down below.
	 */
	dsize = sizeof (dld_ioc_macprop_t) + dipp->pr_valsize - 1;
	if (dsize < dipp->pr_valsize)
		return (EINVAL);

	/*
	 * The property data is variable size, so we need to allocate
	 * a buffer for kernel use as this data was not part of the
	 * dipp allocation and copyin() done by the framework.
	 */
	if ((kdipp = kmem_alloc(dsize, KM_NOSLEEP)) == NULL)
		return (ENOMEM);
	if (ddi_copyin((void *)arg, kdipp, dsize, mode) != 0) {
		err = EFAULT;
		goto done;
	}

	linkid = kdipp->pr_linkid;

	switch (dipp->pr_num) {
	case MAC_PROP_ZONE:
		if (set) {
			dzp = (dld_ioc_zid_t *)kdipp->pr_val;
			err = dls_devnet_setzid(dzp->diz_link, dzp->diz_zid);
			goto done;
		} else {
			cp = (uchar_t *)kdipp->pr_val;
			err = dls_devnet_getzid(linkid, (zoneid_t *)cp);
			goto done;
		}
	case MAC_PROP_AUTOPUSH:
		if (set) {
			if (dipp->pr_valsize != 0) {
				dlap = (struct dlautopush *)kdipp->pr_val;
				err = drv_ioc_setap(linkid, dlap);
				goto done;
			} else {
				err = drv_ioc_clrap(linkid);
				goto done;
			}
		} else {
			dlap = (struct dlautopush *)kdipp->pr_val;
			err = drv_ioc_getap(linkid, dlap);
			goto done;
		}

	default:
		break;
	}

	if ((err = dls_devnet_hold_tmp(linkid, &dlh)) != 0)
		goto done;

	if ((err = dls_vlan_hold(dls_devnet_mac(dlh),
	    dls_devnet_vid(dlh), &dvp, B_FALSE, B_FALSE)) != 0) {
		dls_devnet_rele_tmp(dlh);
		goto done;
	}

	macprop.mp_name = kdipp->pr_name;
	macprop.mp_id = kdipp->pr_num;
	macprop.mp_flags = kdipp->pr_flags;

	if (set) {
		err = mac_set_prop(dvp->dv_dlp->dl_mh, &macprop,
		    kdipp->pr_val, kdipp->pr_valsize);
	} else {
		err = mac_get_prop(dvp->dv_dlp->dl_mh, &macprop,
		    kdipp->pr_val, kdipp->pr_valsize);
	}

	dls_vlan_rele(dvp);
	dls_devnet_rele_tmp(dlh);
done:
	if (!set && err == 0 &&
	    ddi_copyout(kdipp, (void *)arg, dsize, mode) != 0)
		err = EFAULT;
	kmem_free(kdipp, dsize);
	return (err);
}

/* ARGSUSED */
static int
drv_ioc_setprop(void *karg, intptr_t arg, int mode, cred_t *cred)
{
	return (drv_ioc_prop_common(karg, arg, B_TRUE, mode));
}

/* ARGSUSED */
static int
drv_ioc_getprop(void *karg, intptr_t arg, int mode, cred_t *cred)
{
	return (drv_ioc_prop_common(karg, arg, B_FALSE, mode));
}

/*
 * DLDIOC_CREATE_VLAN
 */
/* ARGSUSED */
static int
drv_ioc_create_vlan(void *karg, intptr_t arg, int mode, cred_t *cred)
{
	dld_ioc_create_vlan_t	*dicp = karg;

	return (dls_devnet_create_vlan(dicp->dic_vlanid, dicp->dic_linkid,
	    dicp->dic_vid, dicp->dic_force));
}

/*
 * DLDIOC_DELETE_VLAN
 */
/* ARGSUSED */
static int
drv_ioc_delete_vlan(void *karg, intptr_t arg, int mode, cred_t *cred)
{
	dld_ioc_delete_vlan_t	*didp = karg;

	return (dls_devnet_destroy_vlan(didp->did_linkid));
}

/*
 * DLDIOC_VLAN_ATTR
 */
/* ARGSUSED */
static int
drv_ioc_vlan_attr(void *karg, intptr_t arg, int mode, cred_t *cred)
{
	dld_ioc_vlan_attr_t	*divp = karg;
	dls_dl_handle_t		dlh;
	uint16_t		vid;
	dls_vlan_t		*dvp;
	int			err;

	/*
	 * Hold this link to prevent it from being deleted.
	 */
	if ((err = dls_devnet_hold_tmp(divp->div_vlanid, &dlh)) != 0)
		return (err);

	if ((vid = dls_devnet_vid(dlh)) == VLAN_ID_NONE) {
		dls_devnet_rele_tmp(dlh);
		return (EINVAL);
	}

	err = dls_vlan_hold(dls_devnet_mac(dlh), vid, &dvp, B_FALSE, B_FALSE);
	if (err != 0) {
		dls_devnet_rele_tmp(dlh);
		return (err);
	}

	divp->div_linkid = dls_devnet_linkid(dlh);
	divp->div_implicit = !dls_devnet_is_explicit(dlh);
	divp->div_vid = vid;
	divp->div_force = dvp->dv_force;

	dls_vlan_rele(dvp);
	dls_devnet_rele_tmp(dlh);
	return (0);
}

/*
 * DLDIOC_RENAME.
 *
 * This function handles two cases of link renaming. See more in comments above
 * dls_datalink_rename().
 */
/* ARGSUSED */
static int
drv_ioc_rename(void *karg, intptr_t arg, int mode, cred_t *cred)
{
	dld_ioc_rename_t	*dir = karg;
	mod_hash_key_t		key;
	mod_hash_val_t		val;
	int			err;

	if ((err = dls_devnet_rename(dir->dir_linkid1, dir->dir_linkid2,
	    dir->dir_link)) != 0)
		return (err);

	if (dir->dir_linkid2 == DATALINK_INVALID_LINKID)
		return (0);

	/*
	 * if dir_linkid2 is not DATALINK_INVALID_LINKID, it means this
	 * renaming request is to rename a valid physical link (dir_linkid1)
	 * to a "removed" physical link (dir_linkid2, which is removed by DR
	 * or during system shutdown). In this case, the link (specified by
	 * dir_linkid1) would inherit all the configuration of dir_linkid2,
	 * and dir_linkid1 and its configuration would be lost.
	 *
	 * Remove per-link autopush configuration of dir_linkid1 in this case.
	 */
	key = (mod_hash_key_t)(uintptr_t)dir->dir_linkid1;
	rw_enter(&dld_ap_hash_lock, RW_WRITER);
	if (mod_hash_find(dld_ap_hashp, key, &val) != 0) {
		rw_exit(&dld_ap_hash_lock);
		return (0);
	}

	VERIFY(mod_hash_remove(dld_ap_hashp, key, &val) == 0);
	kmem_free(val, sizeof (dld_ap_t));
	rw_exit(&dld_ap_hash_lock);
	return (0);
}

static int
drv_ioc_setap(datalink_id_t linkid, struct dlautopush *dlap)
{
	dld_ap_t	*dap;
	int		i;
	mod_hash_key_t	key;

	if (dlap->dap_npush == 0 || dlap->dap_npush > MAXAPUSH)
		return (EINVAL);

	/*
	 * Validate that the specified list of modules exist.
	 */
	for (i = 0; i < dlap->dap_npush; i++) {
		if (fmodsw_find(dlap->dap_aplist[i], FMODSW_LOAD) == NULL)
			return (EINVAL);
	}


	key = (mod_hash_key_t)(uintptr_t)linkid;

	rw_enter(&dld_ap_hash_lock, RW_WRITER);
	if (mod_hash_find(dld_ap_hashp, key, (mod_hash_val_t *)&dap) != 0) {
		dap = kmem_zalloc(sizeof (dld_ap_t), KM_NOSLEEP);
		if (dap == NULL) {
			rw_exit(&dld_ap_hash_lock);
			return (ENOMEM);
		}

		dap->da_linkid = linkid;
		VERIFY(mod_hash_insert(dld_ap_hashp, key,
		    (mod_hash_val_t)dap) == 0);
	}

	/*
	 * Update the configuration.
	 */
	dap->da_anchor = dlap->dap_anchor;
	dap->da_npush = dlap->dap_npush;
	for (i = 0; i < dlap->dap_npush; i++) {
		(void) strlcpy(dap->da_aplist[i], dlap->dap_aplist[i],
		    FMNAMESZ + 1);
	}
	rw_exit(&dld_ap_hash_lock);

	return (0);
}

static int
drv_ioc_getap(datalink_id_t linkid, struct dlautopush *dlap)
{
	dld_ap_t	*dap;
	int		i;

	rw_enter(&dld_ap_hash_lock, RW_READER);
	if (mod_hash_find(dld_ap_hashp,
	    (mod_hash_key_t)(uintptr_t)linkid,
	    (mod_hash_val_t *)&dap) != 0) {
		rw_exit(&dld_ap_hash_lock);
		return (ENOENT);
	}

	/*
	 * Retrieve the configuration.
	 */
	dlap->dap_anchor = dap->da_anchor;
	dlap->dap_npush = dap->da_npush;
	for (i = 0; i < dap->da_npush; i++) {
		(void) strlcpy(dlap->dap_aplist[i], dap->da_aplist[i],
		    FMNAMESZ + 1);
	}
	rw_exit(&dld_ap_hash_lock);

	return (0);
}

static int
drv_ioc_clrap(datalink_id_t linkid)
{
	mod_hash_val_t	val;
	mod_hash_key_t	key;

	key = (mod_hash_key_t)(uintptr_t)linkid;

	rw_enter(&dld_ap_hash_lock, RW_WRITER);
	if (mod_hash_find(dld_ap_hashp, key, &val) != 0) {
		rw_exit(&dld_ap_hash_lock);
		return (0);
	}

	VERIFY(mod_hash_remove(dld_ap_hashp, key, &val) == 0);
	kmem_free(val, sizeof (dld_ap_t));
	rw_exit(&dld_ap_hash_lock);
	return (0);
}

/*
 * DLDIOC_DOORSERVER
 */
/* ARGSUSED */
static int
drv_ioc_doorserver(void *karg, intptr_t arg, int mode, cred_t *cred)
{
	dld_ioc_door_t	*did = karg;

	return (dls_mgmt_door_set(did->did_start_door));
}

/*
 * Check for GLDv3 autopush information.  There are three cases:
 *
 *   1. If devp points to a GLDv3 datalink and it has autopush configuration,
 *	fill dlap in with that information and return 0.
 *
 *   2. If devp points to a GLDv3 datalink but it doesn't have autopush
 *	configuration, then replace devp with the physical device (if one
 *	exists) and return 1.  This allows stropen() to find the old-school
 *	per-driver autopush configuration.  (For softmac, the result is that
 *	the softmac dev_t is replaced with the legacy device's dev_t).
 *
 *   3. If neither of the above apply, don't touch the args and return -1.
 */
int
dld_autopush(dev_t *devp, struct dlautopush *dlap)
{
	dld_ap_t	*dap;
	datalink_id_t	linkid;
	dev_t		phydev;

	if (!GLDV3_DRV(getmajor(*devp)))
		return (-1);

	/*
	 * Find the linkid by the link's dev_t.
	 */
	if (dls_devnet_dev2linkid(*devp, &linkid) != 0)
		return (-1);

	/*
	 * Find the autopush configuration associated with the linkid.
	 */
	rw_enter(&dld_ap_hash_lock, RW_READER);
	if (mod_hash_find(dld_ap_hashp, (mod_hash_key_t)(uintptr_t)linkid,
	    (mod_hash_val_t *)&dap) == 0) {
		*dlap = dap->da_ap;
		rw_exit(&dld_ap_hash_lock);
		return (0);
	}
	rw_exit(&dld_ap_hash_lock);

	if (dls_devnet_phydev(linkid, &phydev) != 0)
		return (-1);

	*devp = phydev;
	return (1);
}

/*
 * Secure objects implementation
 */

/* ARGSUSED */
static int
drv_secobj_ctor(void *buf, void *arg, int kmflag)
{
	bzero(buf, sizeof (dld_secobj_t));
	return (0);
}

static void
drv_secobj_init(void)
{
	rw_init(&drv_secobj_lock, NULL, RW_DEFAULT, NULL);
	drv_secobj_cachep = kmem_cache_create("drv_secobj_cache",
	    sizeof (dld_secobj_t), 0, drv_secobj_ctor, NULL,
	    NULL, NULL, NULL, 0);
	drv_secobj_hash = mod_hash_create_extended("drv_secobj_hash",
	    SECOBJ_WEP_HASHSZ, mod_hash_null_keydtor, mod_hash_null_valdtor,
	    mod_hash_bystr, NULL, mod_hash_strkey_cmp, KM_SLEEP);
}

static void
drv_secobj_fini(void)
{
	mod_hash_destroy_hash(drv_secobj_hash);
	kmem_cache_destroy(drv_secobj_cachep);
	rw_destroy(&drv_secobj_lock);
}

/* ARGSUSED */
static int
drv_ioc_secobj_set(void *karg, intptr_t arg, int mode, cred_t *cred)
{
	dld_ioc_secobj_set_t	*ssp = karg;
	dld_secobj_t		*sobjp, *objp;
	int			err;

	sobjp = &ssp->ss_obj;

	if (sobjp->so_class != DLD_SECOBJ_CLASS_WEP &&
	    sobjp->so_class != DLD_SECOBJ_CLASS_WPA)
		return (EINVAL);

	if (sobjp->so_name[DLD_SECOBJ_NAME_MAX - 1] != '\0' ||
	    sobjp->so_len > DLD_SECOBJ_VAL_MAX)
		return (EINVAL);

	rw_enter(&drv_secobj_lock, RW_WRITER);
	err = mod_hash_find(drv_secobj_hash, (mod_hash_key_t)sobjp->so_name,
	    (mod_hash_val_t *)&objp);
	if (err == 0) {
		if ((ssp->ss_flags & DLD_SECOBJ_OPT_CREATE) != 0) {
			rw_exit(&drv_secobj_lock);
			return (EEXIST);
		}
	} else {
		ASSERT(err == MH_ERR_NOTFOUND);
		if ((ssp->ss_flags & DLD_SECOBJ_OPT_CREATE) == 0) {
			rw_exit(&drv_secobj_lock);
			return (ENOENT);
		}
		objp = kmem_cache_alloc(drv_secobj_cachep, KM_SLEEP);
		(void) strlcpy(objp->so_name, sobjp->so_name,
		    DLD_SECOBJ_NAME_MAX);

		VERIFY(mod_hash_insert(drv_secobj_hash,
		    (mod_hash_key_t)objp->so_name, (mod_hash_val_t)objp) == 0);
	}
	bcopy(sobjp->so_val, objp->so_val, sobjp->so_len);
	objp->so_len = sobjp->so_len;
	objp->so_class = sobjp->so_class;
	rw_exit(&drv_secobj_lock);
	return (0);
}

typedef struct dld_secobj_state {
	uint_t		ss_free;
	uint_t		ss_count;
	int		ss_rc;
	int		ss_mode;
	dld_secobj_t	*ss_objp;
} dld_secobj_state_t;

/* ARGSUSED */
static uint_t
drv_secobj_walker(mod_hash_key_t key, mod_hash_val_t *val, void *arg)
{
	dld_secobj_state_t	*statep = arg;
	dld_secobj_t		*sobjp = (dld_secobj_t *)val;

	if (statep->ss_free < sizeof (dld_secobj_t)) {
		statep->ss_rc = ENOSPC;
		return (MH_WALK_TERMINATE);
	}
	if (ddi_copyout(sobjp, statep->ss_objp, sizeof (*sobjp),
	    statep->ss_mode) != 0) {
		statep->ss_rc = EFAULT;
		return (MH_WALK_TERMINATE);
	}
	statep->ss_objp++;
	statep->ss_free -= sizeof (dld_secobj_t);
	statep->ss_count++;
	return (MH_WALK_CONTINUE);
}

/* ARGSUSED */
static int
drv_ioc_secobj_get(void *karg, intptr_t arg, int mode, cred_t *cred)
{
	dld_ioc_secobj_get_t	*sgp = karg;
	dld_secobj_t		*sobjp, *objp;
	int			err;

	sobjp = &sgp->sg_obj;

	if (sobjp->so_name[DLD_SECOBJ_NAME_MAX - 1] != '\0')
		return (EINVAL);

	rw_enter(&drv_secobj_lock, RW_READER);
	if (sobjp->so_name[0] != '\0') {
		err = mod_hash_find(drv_secobj_hash,
		    (mod_hash_key_t)sobjp->so_name, (mod_hash_val_t *)&objp);
		if (err != 0) {
			ASSERT(err == MH_ERR_NOTFOUND);
			rw_exit(&drv_secobj_lock);
			return (ENOENT);
		}
		bcopy(objp->so_val, sobjp->so_val, objp->so_len);
		sobjp->so_len = objp->so_len;
		sobjp->so_class = objp->so_class;
		sgp->sg_count = 1;
	} else {
		dld_secobj_state_t	state;

		state.ss_free = sgp->sg_size - sizeof (dld_ioc_secobj_get_t);
		state.ss_count = 0;
		state.ss_rc = 0;
		state.ss_mode = mode;
		state.ss_objp = (dld_secobj_t *)((uchar_t *)arg +
		    sizeof (dld_ioc_secobj_get_t));

		mod_hash_walk(drv_secobj_hash, drv_secobj_walker, &state);
		if (state.ss_rc != 0) {
			rw_exit(&drv_secobj_lock);
			return (state.ss_rc);
		}
		sgp->sg_count = state.ss_count;
	}
	rw_exit(&drv_secobj_lock);
	return (0);
}

/* ARGSUSED */
static int
drv_ioc_secobj_unset(void *karg, intptr_t arg, int mode, cred_t *cred)
{
	dld_ioc_secobj_unset_t	*sup = karg;
	dld_secobj_t		*objp;
	mod_hash_val_t		val;
	int			err;

	if (sup->su_name[DLD_SECOBJ_NAME_MAX - 1] != '\0')
		return (EINVAL);

	rw_enter(&drv_secobj_lock, RW_WRITER);
	err = mod_hash_find(drv_secobj_hash, (mod_hash_key_t)sup->su_name,
	    (mod_hash_val_t *)&objp);
	if (err != 0) {
		ASSERT(err == MH_ERR_NOTFOUND);
		rw_exit(&drv_secobj_lock);
		return (ENOENT);
	}
	VERIFY(mod_hash_remove(drv_secobj_hash, (mod_hash_key_t)sup->su_name,
	    (mod_hash_val_t *)&val) == 0);
	ASSERT(objp == (dld_secobj_t *)val);

	kmem_cache_free(drv_secobj_cachep, objp);
	rw_exit(&drv_secobj_lock);
	return (0);
}

static dld_ioc_info_t drv_ioc_list[] = {
	{DLDIOC_ATTR, DLDCOPYINOUT, sizeof (dld_ioc_attr_t),
	    drv_ioc_attr},
	{DLDIOC_PHYS_ATTR, DLDCOPYINOUT, sizeof (dld_ioc_phys_attr_t),
	    drv_ioc_phys_attr},
	{DLDIOC_SECOBJ_SET, DLDCOPYIN | DLDDLCONFIG,
	    sizeof (dld_ioc_secobj_set_t), drv_ioc_secobj_set},
	{DLDIOC_SECOBJ_GET, DLDCOPYINOUT | DLDDLCONFIG,
	    sizeof (dld_ioc_secobj_get_t), drv_ioc_secobj_get},
	{DLDIOC_SECOBJ_UNSET, DLDCOPYIN | DLDDLCONFIG,
	    sizeof (dld_ioc_secobj_unset_t), drv_ioc_secobj_unset},
	{DLDIOC_CREATE_VLAN, DLDCOPYIN | DLDDLCONFIG,
	    sizeof (dld_ioc_create_vlan_t), drv_ioc_create_vlan},
	{DLDIOC_DELETE_VLAN, DLDCOPYIN | DLDDLCONFIG,
	    sizeof (dld_ioc_delete_vlan_t),
	    drv_ioc_delete_vlan},
	{DLDIOC_VLAN_ATTR, DLDCOPYINOUT, sizeof (dld_ioc_vlan_attr_t),
	    drv_ioc_vlan_attr},
	{DLDIOC_DOORSERVER, DLDCOPYIN | DLDDLCONFIG, sizeof (dld_ioc_door_t),
	    drv_ioc_doorserver},
	{DLDIOC_RENAME, DLDCOPYIN | DLDDLCONFIG, sizeof (dld_ioc_rename_t),
	    drv_ioc_rename},
	{DLDIOC_GETMACPROP, DLDCOPYIN, sizeof (dld_ioc_macprop_t),
	    drv_ioc_getprop},
	{DLDIOC_SETMACPROP, DLDCOPYIN | DLDDLCONFIG, sizeof (dld_ioc_macprop_t),
	    drv_ioc_setprop}
};

typedef struct dld_ioc_modentry {
	uint16_t	dim_modid;	/* Top 16 bits of ioctl command */
	char		*dim_modname;	/* Module to be loaded */
	dld_ioc_info_t	*dim_list;	/* array of ioctl structures */
	uint_t		dim_count;	/* number of elements in dim_list */
} dld_ioc_modentry_t;

/*
 * For all modules except for dld, dim_list and dim_count are assigned
 * when the modules register their ioctls in dld_ioc_register().  We
 * can statically initialize dld's ioctls in-line here; there's no
 * need for it to call dld_ioc_register() itself.
 */
static dld_ioc_modentry_t dld_ioc_modtable[] = {
	{DLD_IOC,	"dld",	drv_ioc_list, DLDIOCCNT(drv_ioc_list)},
	{AGGR_IOC,	"aggr",	NULL, 0},
	{VNIC_IOC,	"vnic",	NULL, 0}
};
#define	DLDIOC_CNT	\
	(sizeof (dld_ioc_modtable) / sizeof (dld_ioc_modentry_t))

static dld_ioc_modentry_t *
dld_ioc_findmod(uint16_t modid)
{
	int	i;

	for (i = 0; i < DLDIOC_CNT; i++) {
		if (modid == dld_ioc_modtable[i].dim_modid)
			return (&dld_ioc_modtable[i]);
	}
	return (NULL);
}

int
dld_ioc_register(uint16_t modid, dld_ioc_info_t *list, uint_t count)
{
	dld_ioc_modentry_t *dim = dld_ioc_findmod(modid);

	if (dim == NULL)
		return (ENOENT);

	dim->dim_list = list;
	dim->dim_count = count;
	return (0);
}

void
dld_ioc_unregister(uint16_t modid)
{
	VERIFY(dld_ioc_register(modid, NULL, 0) == 0);
}

/*
 * The general design with GLDv3 ioctls is that all ioctls issued
 * through /dev/dld go through this drv_ioctl() function.  This
 * function handles all ioctls on behalf of modules listed in
 * dld_ioc_modtable.
 *
 * When an ioctl is received, this function looks for the associated
 * module-id-specific ioctl information using dld_ioc_findmod().  The
 * call to ddi_hold_devi_by_instance() on the associated device will
 * cause the kernel module responsible for the ioctl to be loaded if
 * it's not already loaded, which should result in that module calling
 * dld_ioc_register(), thereby filling in the dim_list containing the
 * details for the ioctl being processed.
 *
 * This function can then perform operations such as copyin() data and
 * do credential checks based on the registered ioctl information,
 * then issue the callback function di_func() registered by the
 * responsible module.  Upon return, the appropriate copyout()
 * operation can be performed and the operation completes.
 */
/* ARGSUSED */
static int
drv_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *cred, int *rvalp)
{
	dld_ioc_modentry_t *dim;
	dld_ioc_info_t	*info;
	dev_info_t	*dip = NULL;
	void		*buf = NULL;
	size_t		sz;
	int		i, err;

	if ((dim = dld_ioc_findmod(DLD_IOC_MODID(cmd))) == NULL)
		return (ENOTSUP);

	dip = ddi_hold_devi_by_instance(ddi_name_to_major(dim->dim_modname),
	    0, 0);
	if (dip == NULL || dim->dim_list == NULL) {
		err = ENODEV;
		goto done;
	}

	for (i = 0; i < dim->dim_count; i++) {
		if (cmd == dim->dim_list[i].di_cmd)
			break;
	}
	if (i == dim->dim_count) {
		err = ENOTSUP;
		goto done;
	}

	info = &dim->dim_list[i];

	if ((info->di_flags & DLDDLCONFIG) && secpolicy_dl_config(cred) != 0) {
		err = EPERM;
		goto done;
	}

	sz = info->di_argsize;
	if ((buf = kmem_zalloc(sz, KM_NOSLEEP)) == NULL) {
		err = ENOMEM;
		goto done;
	}

	if ((info->di_flags & DLDCOPYIN) &&
	    ddi_copyin((void *)arg, buf, sz, mode) != 0) {
		err = EFAULT;
		goto done;
	}

	err = info->di_func(buf, arg, mode, cred);

	if ((info->di_flags & DLDCOPYOUT) &&
	    ddi_copyout(buf, (void *)arg, sz, mode) != 0 && err == 0)
		err = EFAULT;

done:
	if (buf != NULL)
		kmem_free(buf, sz);
	if (dip != NULL)
		ddi_release_devi(dip);
	return (err);
}
