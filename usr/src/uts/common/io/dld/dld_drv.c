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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Data-Link Driver
 */

#include	<sys/conf.h>
#include	<sys/mkdev.h>
#include	<sys/modctl.h>
#include	<sys/stat.h>
#include	<sys/strsun.h>
#include	<sys/vlan.h>
#include	<sys/mac.h>
#include	<sys/dld_impl.h>
#include	<sys/dls_impl.h>
#include	<sys/softmac.h>
#include 	<sys/vlan.h>
#include	<inet/common.h>

/*
 * dld control node state, one per open control node session.
 */
typedef struct dld_ctl_str_s {
	minor_t cs_minor;
	queue_t *cs_wq;
} dld_ctl_str_t;

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
static void		drv_ioc_secobj_set(dld_ctl_str_t *, mblk_t *);
static void		drv_ioc_secobj_get(dld_ctl_str_t *, mblk_t *);
static void		drv_ioc_secobj_unset(dld_ctl_str_t *, mblk_t *);

/*
 * The following entry points are private to dld and are used for control
 * operations only. The entry points exported to mac drivers are defined
 * in dld_str.c. Refer to the comment on top of dld_str.c for details.
 */
static int	drv_open(queue_t *, dev_t *, int, int, cred_t *);
static int	drv_close(queue_t *);

static void	drv_uw_put(queue_t *, mblk_t *);
static void	drv_uw_srv(queue_t *);

dev_info_t	*dld_dip;		/* dev_info_t for the driver */
uint32_t	dld_opt = 0;		/* Global options */
static vmem_t	*dld_ctl_vmem;		/* for control minor numbers */

#define	NAUTOPUSH 32
static mod_hash_t *dld_ap_hashp;
static krwlock_t dld_ap_hash_lock;

static	struct	module_info	drv_info = {
	0,			/* mi_idnum */
	DLD_DRIVER_NAME,	/* mi_idname */
	0,			/* mi_minpsz */
	(64 * 1024),		/* mi_maxpsz */
	1,			/* mi_hiwat */
	0			/* mi_lowat */
};

static	struct qinit		drv_ur_init = {
	NULL,			/* qi_putp */
	NULL,			/* qi_srvp */
	drv_open,		/* qi_qopen */
	drv_close,		/* qi_qclose */
	NULL,			/* qi_qadmin */
	&drv_info,		/* qi_minfo */
	NULL			/* qi_mstat */
};

static	struct qinit		drv_uw_init = {
	(pfi_t)drv_uw_put,	/* qi_putp */
	(pfi_t)drv_uw_srv,	/* qi_srvp */
	NULL,			/* qi_qopen */
	NULL,			/* qi_qclose */
	NULL,			/* qi_qadmin */
	&drv_info,		/* qi_minfo */
	NULL			/* qi_mstat */
};

static	struct streamtab	drv_stream = {
	&drv_ur_init,		/* st_rdinit */
	&drv_uw_init,		/* st_wrinit */
	NULL,			/* st_muxrinit */
	NULL			/* st_muxwinit */
};

DDI_DEFINE_STREAM_OPS(drv_ops, nulldev, nulldev, drv_attach, drv_detach,
    nodev, drv_getinfo, D_MP, &drv_stream);

/*
 * Module linkage information for the kernel.
 */

extern	struct mod_ops		mod_driverops;

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
	int	err;

	drv_init();

	if ((err = mod_install(&drv_modlinkage)) != 0)
		return (err);

	return (0);
}

int
_fini(void)
{
	int	err;

	if ((err = mod_remove(&drv_modlinkage)) != 0)
		return (err);

	if (drv_fini() != 0) {
		(void) mod_install(&drv_modlinkage);
		return (DDI_FAILURE);
	}

	return (err);
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
	dld_ctl_vmem = vmem_create("dld_ctl", (void *)1, MAXMIN, 1,
	    NULL, NULL, NULL, 1, VM_SLEEP | VMC_IDENTIFIER);
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
	vmem_destroy(dld_ctl_vmem);
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
		*resp = (void *)0;
		break;
	case DDI_INFO_DEVT2DEVINFO:
		*resp = (void *)dld_dip;
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
drv_open(queue_t *rq, dev_t *devp, int flag, int sflag, cred_t *credp)
{
	dld_ctl_str_t	*ctls;
	minor_t		minor;
	queue_t *oq =	OTHERQ(rq);

	if (sflag == MODOPEN)
		return (ENOTSUP);

	/*
	 * This is a cloning driver and therefore each queue should only
	 * ever get opened once.
	 */
	if (rq->q_ptr != NULL)
		return (EBUSY);

	minor = (minor_t)(uintptr_t)vmem_alloc(dld_ctl_vmem, 1, VM_NOSLEEP);
	if (minor == 0)
		return (ENOMEM);

	ctls = kmem_zalloc(sizeof (dld_ctl_str_t), KM_NOSLEEP);
	if (ctls == NULL) {
		vmem_free(dld_ctl_vmem, (void *)(uintptr_t)minor, 1);
		return (ENOMEM);
	}

	ctls->cs_minor = minor;
	ctls->cs_wq = WR(rq);

	rq->q_ptr = ctls;
	oq->q_ptr = ctls;

	/*
	 * Enable the queue srv(9e) routine.
	 */
	qprocson(rq);

	/*
	 * Construct a cloned dev_t to hand back.
	 */
	*devp = makedevice(getmajor(*devp), ctls->cs_minor);
	return (0);
}

/*
 * dld control node close procedure.
 */
static int
drv_close(queue_t *rq)
{
	dld_ctl_str_t	*ctls;

	ctls = rq->q_ptr;
	ASSERT(ctls != NULL);

	/*
	 * Disable the queue srv(9e) routine.
	 */
	qprocsoff(rq);

	vmem_free(dld_ctl_vmem, (void *)(uintptr_t)ctls->cs_minor, 1);

	kmem_free(ctls, sizeof (dld_ctl_str_t));

	return (0);
}

/*
 * DLDIOC_ATTR
 */
static void
drv_ioc_attr(dld_ctl_str_t *ctls, mblk_t *mp)
{
	dld_ioc_attr_t		*diap;
	dls_dl_handle_t		dlh;
	dls_vlan_t		*dvp;
	int			err;
	queue_t			*q = ctls->cs_wq;

	if ((err = miocpullup(mp, sizeof (dld_ioc_attr_t))) != 0)
		goto failed;

	diap = (dld_ioc_attr_t *)mp->b_cont->b_rptr;

	if ((err = dls_devnet_hold_tmp(diap->dia_linkid, &dlh)) != 0)
		goto failed;

	if ((err = dls_vlan_hold(dls_devnet_mac(dlh),
	    dls_devnet_vid(dlh), &dvp, B_FALSE, B_FALSE)) != 0) {
		dls_devnet_rele_tmp(dlh);
		goto failed;
	}
	mac_sdu_get(dvp->dv_dlp->dl_mh, NULL, &diap->dia_max_sdu);

	dls_vlan_rele(dvp);
	dls_devnet_rele_tmp(dlh);

	miocack(q, mp, sizeof (dld_ioc_attr_t), 0);
	return;

failed:
	ASSERT(err != 0);
	miocnak(q, mp, 0, err);
}

/*
 * DLDIOC_PHYS_ATTR
 */
static void
drv_ioc_phys_attr(dld_ctl_str_t *ctls, mblk_t *mp)
{
	dld_ioc_phys_attr_t	*dipp;
	int			err;
	dls_dl_handle_t		dlh;
	dls_dev_handle_t	ddh;
	dev_t			phydev;
	queue_t			*q = ctls->cs_wq;

	if ((err = miocpullup(mp, sizeof (dld_ioc_phys_attr_t))) != 0)
		goto failed;

	dipp = (dld_ioc_phys_attr_t *)mp->b_cont->b_rptr;

	/*
	 * Every physical link should have its physical dev_t kept in the
	 * daemon. If not, it is not a valid physical link.
	 */
	if (dls_mgmt_get_phydev(dipp->dip_linkid, &phydev) != 0) {
		err = EINVAL;
		goto failed;
	}

	/*
	 * Although this is a valid physical link, it might already be removed
	 * by DR or during system shutdown. softmac_hold_device() would return
	 * ENOENT in this case.
	 */
	if ((err = softmac_hold_device(phydev, &ddh)) != 0)
		goto failed;

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

	miocack(q, mp, sizeof (dld_ioc_phys_attr_t), 0);
	return;

failed:
	miocnak(q, mp, 0, err);
}

/*
 * DLDIOC_SETPROP
 */
static void
drv_ioc_prop_common(dld_ctl_str_t *ctls, mblk_t *mp, boolean_t set)
{
	int		err = EINVAL, dsize;
	queue_t		*q = ctls->cs_wq;
	dld_ioc_macprop_t	*dipp;
	dls_dl_handle_t 	dlh;
	dls_vlan_t		*dvp;
	datalink_id_t 		linkid;
	mac_prop_t		macprop;

	if ((err = miocpullup(mp, sizeof (dld_ioc_macprop_t))) != 0)
		goto done;
	dipp = (dld_ioc_macprop_t *)mp->b_cont->b_rptr;

	dsize = sizeof (dld_ioc_macprop_t) + dipp->pr_valsize - 1;
	if ((err = miocpullup(mp, dsize)) != 0)
		goto done;
	dipp = (dld_ioc_macprop_t *)mp->b_cont->b_rptr;

	linkid = dipp->pr_linkid;

	if ((err = dls_devnet_hold_tmp(linkid, &dlh)) != 0)
		goto done;

	if ((err = dls_vlan_hold(dls_devnet_mac(dlh),
	    dls_devnet_vid(dlh), &dvp, B_FALSE, B_FALSE)) != 0) {
		dls_devnet_rele_tmp(dlh);
		goto done;
	}

	macprop.mp_name = dipp->pr_name;
	macprop.mp_id = dipp->pr_num;
	macprop.mp_flags = dipp->pr_flags;

	if (set)
		err = mac_set_prop(dvp->dv_dlp->dl_mh, &macprop,
		    dipp->pr_val, dipp->pr_valsize);
	else
		err = mac_get_prop(dvp->dv_dlp->dl_mh, &macprop,
		    dipp->pr_val, dipp->pr_valsize);

	dls_vlan_rele(dvp);
	dls_devnet_rele_tmp(dlh);
done:
	if (err == 0)
		miocack(q, mp, dsize, 0);
	else
		miocnak(q, mp, 0, err);
}

static void
drv_ioc_setprop(dld_ctl_str_t *ctls, mblk_t *mp)
{
	drv_ioc_prop_common(ctls, mp, B_TRUE);
}

static void
drv_ioc_getprop(dld_ctl_str_t *ctls, mblk_t *mp)
{
	drv_ioc_prop_common(ctls, mp, B_FALSE);
}

/*
 * DLDIOC_CREATE_VLAN
 */
static void
drv_ioc_create_vlan(dld_ctl_str_t *ctls, mblk_t *mp)
{
	dld_ioc_create_vlan_t	*dicp;
	int			err;
	queue_t			*q = ctls->cs_wq;

	if ((err = miocpullup(mp, sizeof (dld_ioc_create_vlan_t))) != 0)
		goto failed;

	dicp = (dld_ioc_create_vlan_t *)mp->b_cont->b_rptr;

	if ((err = dls_devnet_create_vlan(dicp->dic_vlanid,
	    dicp->dic_linkid, dicp->dic_vid, dicp->dic_force)) != 0) {
		goto failed;
	}

	miocack(q, mp, 0, 0);
	return;

failed:
	miocnak(q, mp, 0, err);
}

/*
 * DLDIOC_DELETE_VLAN
 */
static void
drv_ioc_delete_vlan(dld_ctl_str_t *ctls, mblk_t *mp)
{
	dld_ioc_delete_vlan_t	*didp;
	int			err;
	queue_t			*q = ctls->cs_wq;

	if ((err = miocpullup(mp, sizeof (dld_ioc_delete_vlan_t))) != 0)
		goto done;

	didp = (dld_ioc_delete_vlan_t *)mp->b_cont->b_rptr;
	err = dls_devnet_destroy_vlan(didp->did_linkid);

done:
	if (err == 0)
		miocack(q, mp, 0, 0);
	else
		miocnak(q, mp, 0, err);
}

/*
 * DLDIOC_VLAN_ATTR
 */
static void
drv_ioc_vlan_attr(dld_ctl_str_t *ctls, mblk_t *mp)
{
	dld_ioc_vlan_attr_t	*divp;
	dls_dl_handle_t		dlh;
	uint16_t		vid;
	dls_vlan_t		*dvp;
	int			err;
	queue_t			*q = ctls->cs_wq;

	if ((err = miocpullup(mp, sizeof (dld_ioc_vlan_attr_t))) != 0)
		goto failed;

	divp = (dld_ioc_vlan_attr_t *)mp->b_cont->b_rptr;

	/*
	 * Hold this link to prevent it from being deleted.
	 */
	err = dls_devnet_hold_tmp(divp->div_vlanid, &dlh);
	if (err != 0)
		goto failed;

	if ((vid = dls_devnet_vid(dlh)) == VLAN_ID_NONE) {
		dls_devnet_rele_tmp(dlh);
		err = EINVAL;
		goto failed;
	}

	err = dls_vlan_hold(dls_devnet_mac(dlh), vid, &dvp, B_FALSE, B_FALSE);
	if (err != 0) {
		dls_devnet_rele_tmp(dlh);
		err = EINVAL;
		goto failed;
	}

	divp->div_linkid = dls_devnet_linkid(dlh);
	divp->div_implicit = !dls_devnet_is_explicit(dlh);
	divp->div_vid = vid;
	divp->div_force = dvp->dv_force;

	dls_vlan_rele(dvp);
	dls_devnet_rele_tmp(dlh);
	miocack(q, mp, sizeof (dld_ioc_vlan_attr_t), 0);
	return;

failed:
	miocnak(q, mp, 0, err);
}

/*
 * DLDIOC_RENAME.
 *
 * This function handles two cases of link renaming. See more in comments above
 * dls_datalink_rename().
 */
static void
drv_ioc_rename(dld_ctl_str_t *ctls, mblk_t *mp)
{
	dld_ioc_rename_t	*dir;
	mod_hash_key_t		key;
	mod_hash_val_t		val;
	int			err;
	queue_t			*q = ctls->cs_wq;

	if ((err = miocpullup(mp, sizeof (dld_ioc_rename_t))) != 0)
		goto done;

	dir = (dld_ioc_rename_t *)mp->b_cont->b_rptr;
	if ((err = dls_devnet_rename(dir->dir_linkid1, dir->dir_linkid2,
	    dir->dir_link)) != 0) {
		goto done;
	}

	if (dir->dir_linkid2 == DATALINK_INVALID_LINKID)
		goto done;

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
		goto done;
	}

	VERIFY(mod_hash_remove(dld_ap_hashp, key, &val) == 0);
	kmem_free(val, sizeof (dld_ap_t));
	rw_exit(&dld_ap_hash_lock);

done:
	if (err == 0)
		miocack(q, mp, 0, 0);
	else
		miocnak(q, mp, 0, err);
}

/*
 * DLDIOC_SETAUTOPUSH
 */
static void
drv_ioc_setap(dld_ctl_str_t *ctls, mblk_t *mp)
{
	dld_ioc_ap_t	*diap;
	dld_ap_t	*dap;
	int		i, err;
	queue_t		*q = ctls->cs_wq;
	mod_hash_key_t	key;

	if ((err = miocpullup(mp, sizeof (dld_ioc_ap_t))) != 0)
		goto failed;

	diap = (dld_ioc_ap_t *)mp->b_cont->b_rptr;
	if (diap->dia_npush == 0 || diap->dia_npush > MAXAPUSH) {
		err = EINVAL;
		goto failed;
	}

	/*
	 * Validate that the specified list of modules exist.
	 */
	for (i = 0; i < diap->dia_npush; i++) {
		if (fmodsw_find(diap->dia_aplist[i], FMODSW_LOAD) == NULL) {
			err = EINVAL;
			goto failed;
		}
	}

	key = (mod_hash_key_t)(uintptr_t)diap->dia_linkid;

	rw_enter(&dld_ap_hash_lock, RW_WRITER);
	if (mod_hash_find(dld_ap_hashp, key, (mod_hash_val_t *)&dap) != 0) {
		dap = kmem_zalloc(sizeof (dld_ap_t), KM_NOSLEEP);
		if (dap == NULL) {
			rw_exit(&dld_ap_hash_lock);
			err = ENOMEM;
			goto failed;
		}

		dap->da_linkid = diap->dia_linkid;
		err = mod_hash_insert(dld_ap_hashp, key, (mod_hash_val_t)dap);
		ASSERT(err == 0);
	}

	/*
	 * Update the configuration.
	 */
	dap->da_anchor = diap->dia_anchor;
	dap->da_npush = diap->dia_npush;
	for (i = 0; i < diap->dia_npush; i++) {
		(void) strlcpy(dap->da_aplist[i], diap->dia_aplist[i],
		    FMNAMESZ + 1);
	}
	rw_exit(&dld_ap_hash_lock);

	miocack(q, mp, 0, 0);
	return;

failed:
	miocnak(q, mp, 0, err);
}

/*
 * DLDIOC_GETAUTOPUSH
 */
static void
drv_ioc_getap(dld_ctl_str_t *ctls, mblk_t *mp)
{
	dld_ioc_ap_t	*diap;
	dld_ap_t	*dap;
	int		i, err;
	queue_t		*q = ctls->cs_wq;

	if ((err = miocpullup(mp, sizeof (dld_ioc_ap_t))) != 0)
		goto failed;

	diap = (dld_ioc_ap_t *)mp->b_cont->b_rptr;

	rw_enter(&dld_ap_hash_lock, RW_READER);
	if (mod_hash_find(dld_ap_hashp,
	    (mod_hash_key_t)(uintptr_t)diap->dia_linkid,
	    (mod_hash_val_t *)&dap) != 0) {
		err = ENOENT;
		rw_exit(&dld_ap_hash_lock);
		goto failed;
	}

	/*
	 * Retrieve the configuration.
	 */
	diap->dia_anchor = dap->da_anchor;
	diap->dia_npush = dap->da_npush;
	for (i = 0; i < dap->da_npush; i++) {
		(void) strlcpy(diap->dia_aplist[i], dap->da_aplist[i],
		    FMNAMESZ + 1);
	}
	rw_exit(&dld_ap_hash_lock);

	miocack(q, mp, sizeof (dld_ioc_ap_t), 0);
	return;

failed:
	miocnak(q, mp, 0, err);
}

/*
 * DLDIOC_CLRAUTOPUSH
 */
static void
drv_ioc_clrap(dld_ctl_str_t *ctls, mblk_t *mp)
{
	dld_ioc_ap_t	*diap;
	mod_hash_val_t	val;
	mod_hash_key_t	key;
	int		err;
	queue_t		*q = ctls->cs_wq;

	if ((err = miocpullup(mp, sizeof (dld_ioc_ap_t))) != 0)
		goto done;

	diap = (dld_ioc_ap_t *)mp->b_cont->b_rptr;
	key = (mod_hash_key_t)(uintptr_t)diap->dia_linkid;

	rw_enter(&dld_ap_hash_lock, RW_WRITER);
	if (mod_hash_find(dld_ap_hashp, key, &val) != 0) {
		rw_exit(&dld_ap_hash_lock);
		goto done;
	}

	VERIFY(mod_hash_remove(dld_ap_hashp, key, &val) == 0);
	kmem_free(val, sizeof (dld_ap_t));
	rw_exit(&dld_ap_hash_lock);

done:
	if (err == 0)
		miocack(q, mp, 0, 0);
	else
		miocnak(q, mp, 0, err);
}

/*
 * DLDIOC_DOORSERVER
 */
static void
drv_ioc_doorserver(dld_ctl_str_t *ctls, mblk_t *mp)
{
	queue_t		*q = ctls->cs_wq;
	dld_ioc_door_t	*did;
	int		err;

	if ((err = miocpullup(mp, sizeof (dld_ioc_door_t))) != 0)
		goto done;

	did = (dld_ioc_door_t *)mp->b_cont->b_rptr;
	err = dls_mgmt_door_set(did->did_start_door);

done:
	if (err == 0)
		miocack(q, mp, 0, 0);
	else
		miocnak(q, mp, 0, err);
}

/*
 * DLDIOC_SETZID
 */
static void
drv_ioc_setzid(dld_ctl_str_t *ctls, mblk_t *mp)
{
	queue_t			*q = ctls->cs_wq;
	dld_ioc_setzid_t	*dis;
	int			err;

	if ((err = miocpullup(mp, sizeof (dld_ioc_setzid_t))) != 0)
		goto done;

	dis = (dld_ioc_setzid_t *)mp->b_cont->b_rptr;
	err = dls_devnet_setzid(dis->dis_link, dis->dis_zid);

done:
	if (err == 0)
		miocack(q, mp, 0, 0);
	else
		miocnak(q, mp, 0, err);
}

/*
 * DLDIOC_GETZID
 */
static void
drv_ioc_getzid(dld_ctl_str_t *ctls, mblk_t *mp)
{
	queue_t			*q = ctls->cs_wq;
	dld_ioc_getzid_t	*dig;
	int			err;

	if ((err = miocpullup(mp, sizeof (dld_ioc_getzid_t))) != 0)
		goto done;

	dig = (dld_ioc_getzid_t *)mp->b_cont->b_rptr;
	err = dls_devnet_getzid(dig->dig_linkid, &dig->dig_zid);

done:
	if (err == 0)
		miocack(q, mp, sizeof (dld_ioc_getzid_t), 0);
	else
		miocnak(q, mp, 0, err);
}

/*
 * Process an IOCTL message received by the control node.
 */
static void
drv_ioc(dld_ctl_str_t *ctls, mblk_t *mp)
{
	uint_t	cmd;

	cmd = ((struct iocblk *)mp->b_rptr)->ioc_cmd;
	switch (cmd) {
	case DLDIOC_ATTR:
		drv_ioc_attr(ctls, mp);
		return;
	case DLDIOC_PHYS_ATTR:
		drv_ioc_phys_attr(ctls, mp);
		return;
	case DLDIOC_SECOBJ_SET:
		drv_ioc_secobj_set(ctls, mp);
		return;
	case DLDIOC_SECOBJ_GET:
		drv_ioc_secobj_get(ctls, mp);
		return;
	case DLDIOC_SECOBJ_UNSET:
		drv_ioc_secobj_unset(ctls, mp);
		return;
	case DLDIOC_SETMACPROP:
		drv_ioc_setprop(ctls, mp);
		return;
	case DLDIOC_GETMACPROP:
		drv_ioc_getprop(ctls, mp);
		return;
	case DLDIOC_CREATE_VLAN:
		drv_ioc_create_vlan(ctls, mp);
		return;
	case DLDIOC_DELETE_VLAN:
		drv_ioc_delete_vlan(ctls, mp);
		return;
	case DLDIOC_VLAN_ATTR:
		drv_ioc_vlan_attr(ctls, mp);
		return;
	case DLDIOC_SETAUTOPUSH:
		drv_ioc_setap(ctls, mp);
		return;
	case DLDIOC_GETAUTOPUSH:
		drv_ioc_getap(ctls, mp);
		return;
	case DLDIOC_CLRAUTOPUSH:
		drv_ioc_clrap(ctls, mp);
		return;
	case DLDIOC_DOORSERVER:
		drv_ioc_doorserver(ctls, mp);
		return;
	case DLDIOC_SETZID:
		drv_ioc_setzid(ctls, mp);
		return;
	case DLDIOC_GETZID:
		drv_ioc_getzid(ctls, mp);
		return;
	case DLDIOC_RENAME:
		drv_ioc_rename(ctls, mp);
		return;
	default:
		miocnak(ctls->cs_wq, mp, 0, ENOTSUP);
		return;
	}
}

/*
 * Write side put routine of the dld control node.
 */
static void
drv_uw_put(queue_t *q, mblk_t *mp)
{
	dld_ctl_str_t *ctls = q->q_ptr;

	switch (mp->b_datap->db_type) {
	case M_IOCTL:
		drv_ioc(ctls, mp);
		break;
	default:
		freemsg(mp);
		break;
	}
}

/*
 * Write-side service procedure.
 */
void
drv_uw_srv(queue_t *q)
{
	mblk_t *mp;

	while (mp = getq(q))
		drv_uw_put(q, mp);
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

static void
drv_ioc_secobj_set(dld_ctl_str_t *ctls, mblk_t *mp)
{
	dld_ioc_secobj_set_t	*ssp;
	dld_secobj_t		*sobjp, *objp;
	int			err = EINVAL;
	queue_t			*q = ctls->cs_wq;

	if ((err = miocpullup(mp, sizeof (dld_ioc_secobj_set_t))) != 0)
		goto failed;

	ssp = (dld_ioc_secobj_set_t *)mp->b_cont->b_rptr;
	sobjp = &ssp->ss_obj;

	if (sobjp->so_class != DLD_SECOBJ_CLASS_WEP &&
	    sobjp->so_class != DLD_SECOBJ_CLASS_WPA)
		goto failed;

	if (sobjp->so_name[DLD_SECOBJ_NAME_MAX - 1] != '\0' ||
	    sobjp->so_len > DLD_SECOBJ_VAL_MAX)
		goto failed;

	rw_enter(&drv_secobj_lock, RW_WRITER);
	err = mod_hash_find(drv_secobj_hash, (mod_hash_key_t)sobjp->so_name,
	    (mod_hash_val_t *)&objp);
	if (err == 0) {
		if ((ssp->ss_flags & DLD_SECOBJ_OPT_CREATE) != 0) {
			err = EEXIST;
			rw_exit(&drv_secobj_lock);
			goto failed;
		}
	} else {
		ASSERT(err == MH_ERR_NOTFOUND);
		if ((ssp->ss_flags & DLD_SECOBJ_OPT_CREATE) == 0) {
			err = ENOENT;
			rw_exit(&drv_secobj_lock);
			goto failed;
		}
		objp = kmem_cache_alloc(drv_secobj_cachep, KM_SLEEP);
		(void) strlcpy(objp->so_name, sobjp->so_name,
		    DLD_SECOBJ_NAME_MAX);

		err = mod_hash_insert(drv_secobj_hash,
		    (mod_hash_key_t)objp->so_name, (mod_hash_val_t)objp);
		ASSERT(err == 0);
	}
	bcopy(sobjp->so_val, objp->so_val, sobjp->so_len);
	objp->so_len = sobjp->so_len;
	objp->so_class = sobjp->so_class;
	rw_exit(&drv_secobj_lock);
	miocack(q, mp, 0, 0);
	return;

failed:
	ASSERT(err != 0);
	miocnak(q, mp, 0, err);
}

typedef struct dld_secobj_state {
	uint_t		ss_free;
	uint_t		ss_count;
	int		ss_rc;
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
	bcopy(sobjp, statep->ss_objp, sizeof (dld_secobj_t));
	statep->ss_objp++;
	statep->ss_free -= sizeof (dld_secobj_t);
	statep->ss_count++;
	return (MH_WALK_CONTINUE);
}

static void
drv_ioc_secobj_get(dld_ctl_str_t *ctls, mblk_t *mp)
{
	dld_ioc_secobj_get_t	*sgp;
	dld_secobj_t		*sobjp, *objp;
	int			err = EINVAL;
	uint_t			extra = 0;
	queue_t			*q = ctls->cs_wq;
	mblk_t			*bp;

	if ((err = miocpullup(mp, sizeof (dld_ioc_secobj_get_t))) != 0)
		goto failed;

	if ((bp = msgpullup(mp->b_cont, -1)) == NULL)
		goto failed;

	freemsg(mp->b_cont);
	mp->b_cont = bp;
	sgp = (dld_ioc_secobj_get_t *)bp->b_rptr;
	sobjp = &sgp->sg_obj;

	if (sobjp->so_name[DLD_SECOBJ_NAME_MAX - 1] != '\0')
		goto failed;

	rw_enter(&drv_secobj_lock, RW_READER);
	if (sobjp->so_name[0] != '\0') {
		err = mod_hash_find(drv_secobj_hash,
		    (mod_hash_key_t)sobjp->so_name, (mod_hash_val_t *)&objp);
		if (err != 0) {
			ASSERT(err == MH_ERR_NOTFOUND);
			err = ENOENT;
			rw_exit(&drv_secobj_lock);
			goto failed;
		}
		bcopy(objp->so_val, sobjp->so_val, objp->so_len);
		sobjp->so_len = objp->so_len;
		sobjp->so_class = objp->so_class;
		sgp->sg_count = 1;
	} else {
		dld_secobj_state_t	state;

		state.ss_free = MBLKL(bp) - sizeof (dld_ioc_secobj_get_t);
		state.ss_count = 0;
		state.ss_rc = 0;
		state.ss_objp = (dld_secobj_t *)(sgp + 1);
		mod_hash_walk(drv_secobj_hash, drv_secobj_walker, &state);
		if (state.ss_rc != 0) {
			err = state.ss_rc;
			rw_exit(&drv_secobj_lock);
			goto failed;
		}
		sgp->sg_count = state.ss_count;
		extra = state.ss_count * sizeof (dld_secobj_t);
	}
	rw_exit(&drv_secobj_lock);
	miocack(q, mp, sizeof (dld_ioc_secobj_get_t) + extra, 0);
	return;

failed:
	ASSERT(err != 0);
	miocnak(q, mp, 0, err);

}

static void
drv_ioc_secobj_unset(dld_ctl_str_t *ctls, mblk_t *mp)
{
	dld_ioc_secobj_unset_t	*sup;
	dld_secobj_t		*objp;
	mod_hash_val_t		val;
	int			err = EINVAL;
	queue_t			*q = ctls->cs_wq;

	if ((err = miocpullup(mp, sizeof (dld_ioc_secobj_unset_t))) != 0)
		goto failed;

	sup = (dld_ioc_secobj_unset_t *)mp->b_cont->b_rptr;
	if (sup->su_name[DLD_SECOBJ_NAME_MAX - 1] != '\0')
		goto failed;

	rw_enter(&drv_secobj_lock, RW_WRITER);
	err = mod_hash_find(drv_secobj_hash, (mod_hash_key_t)sup->su_name,
	    (mod_hash_val_t *)&objp);
	if (err != 0) {
		ASSERT(err == MH_ERR_NOTFOUND);
		err = ENOENT;
		rw_exit(&drv_secobj_lock);
		goto failed;
	}
	err = mod_hash_remove(drv_secobj_hash, (mod_hash_key_t)sup->su_name,
	    (mod_hash_val_t *)&val);
	ASSERT(err == 0);
	ASSERT(objp == (dld_secobj_t *)val);

	kmem_cache_free(drv_secobj_cachep, objp);
	rw_exit(&drv_secobj_lock);
	miocack(q, mp, 0, 0);
	return;

failed:
	ASSERT(err != 0);
	miocnak(q, mp, 0, err);
}
