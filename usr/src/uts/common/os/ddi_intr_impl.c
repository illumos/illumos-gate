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
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/note.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kmem.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/avintr.h>
#include <sys/autoconf.h>
#include <sys/sunndi.h>
#include <sys/ndi_impldefs.h>	/* include prototypes */

#if defined(__i386) || defined(__amd64)
/*
 * MSI-X allocation limit.
 */
uint_t		ddi_msix_alloc_limit = DDI_DEFAULT_MSIX_ALLOC;
#endif

/*
 * New DDI interrupt framework
 */
void
i_ddi_intr_devi_init(dev_info_t *dip)
{
	int	supported_types;

	DDI_INTR_APIDBG((CE_CONT, "i_ddi_intr_devi_init: dip %p\n",
	    (void *)dip));

	if (DEVI(dip)->devi_intr_p)
		return;

	DEVI(dip)->devi_intr_p = kmem_zalloc(sizeof (devinfo_intr_t), KM_SLEEP);

	supported_types = i_ddi_intr_get_supported_types(dip);

	/* Save supported interrupt types information */
	i_ddi_intr_set_supported_types(dip, supported_types);
}

void
i_ddi_intr_devi_fini(dev_info_t *dip)
{
	devinfo_intr_t	*intr_p = DEVI(dip)->devi_intr_p;

	DDI_INTR_APIDBG((CE_CONT, "i_ddi_intr_devi_fini: dip %p\n",
	    (void *)dip));

	if ((intr_p == NULL) || i_ddi_intr_get_current_nintrs(dip))
		return;

	/*
	 * devi_intr_handle_p will only be used for devices
	 * which are using the legacy DDI Interrupt interfaces.
	 */
	if (intr_p->devi_intr_handle_p) {
		/* nintrs could be zero; so check for it first */
		if (intr_p->devi_intr_sup_nintrs) {
			kmem_free(intr_p->devi_intr_handle_p,
			    intr_p->devi_intr_sup_nintrs *
			    sizeof (ddi_intr_handle_t));
		}
	}

	/*
	 * devi_irm_req_p will only be used for devices which
	 * are mapped to an Interrupt Resource Management pool.
	 */
	if (intr_p->devi_irm_req_p)
		(void) i_ddi_irm_remove(dip);

	kmem_free(DEVI(dip)->devi_intr_p, sizeof (devinfo_intr_t));
	DEVI(dip)->devi_intr_p = NULL;
}

uint_t
i_ddi_intr_get_supported_types(dev_info_t *dip)
{
	devinfo_intr_t		*intr_p = DEVI(dip)->devi_intr_p;
	ddi_intr_handle_impl_t	hdl;
	int			ret, intr_types;

	if ((intr_p) && (intr_p->devi_intr_sup_types))
		return (intr_p->devi_intr_sup_types);

	bzero(&hdl, sizeof (ddi_intr_handle_impl_t));
	hdl.ih_dip = dip;

	ret = i_ddi_intr_ops(dip, dip, DDI_INTROP_SUPPORTED_TYPES, &hdl,
	    (void *)&intr_types);

	return ((ret == DDI_SUCCESS) ? intr_types : 0);
}

/*
 * NOTE: This function is only called by i_ddi_dev_init().
 */
void
i_ddi_intr_set_supported_types(dev_info_t *dip, int intr_types)
{
	devinfo_intr_t		*intr_p = DEVI(dip)->devi_intr_p;

	if (intr_p)
		intr_p->devi_intr_sup_types = intr_types;
}

uint_t
i_ddi_intr_get_supported_nintrs(dev_info_t *dip, int intr_type)
{
	devinfo_intr_t		*intr_p = DEVI(dip)->devi_intr_p;
	ddi_intr_handle_impl_t	hdl;
	int			ret, nintrs;

	if ((intr_p) && (intr_p->devi_intr_curr_type == intr_type) &&
	    (intr_p->devi_intr_sup_nintrs))
		return (intr_p->devi_intr_sup_nintrs);

	bzero(&hdl, sizeof (ddi_intr_handle_impl_t));
	hdl.ih_dip = dip;
	hdl.ih_type = intr_type;

	ret = i_ddi_intr_ops(dip, dip, DDI_INTROP_NINTRS, &hdl,
	    (void *)&nintrs);

	return ((ret == DDI_SUCCESS) ? nintrs : 0);
}

/*
 * NOTE: This function is only called by ddi_intr_alloc().
 */
void
i_ddi_intr_set_supported_nintrs(dev_info_t *dip, int nintrs)
{
	devinfo_intr_t *intr_p = DEVI(dip)->devi_intr_p;

	if (intr_p)
		intr_p->devi_intr_sup_nintrs = nintrs;
}

uint_t
i_ddi_intr_get_current_type(dev_info_t *dip)
{
	devinfo_intr_t *intr_p = DEVI(dip)->devi_intr_p;

	return (intr_p ? intr_p->devi_intr_curr_type : 0);
}

/*
 * NOTE: This function is only called by
 *       ddi_intr_alloc() and ddi_intr_free().
 */
void
i_ddi_intr_set_current_type(dev_info_t *dip, int intr_type)
{
	devinfo_intr_t *intr_p = DEVI(dip)->devi_intr_p;

	if (intr_p)
		intr_p->devi_intr_curr_type = intr_type;
}

uint_t
i_ddi_intr_get_current_nintrs(dev_info_t *dip)
{
	devinfo_intr_t *intr_p = DEVI(dip)->devi_intr_p;

	return (intr_p ? intr_p->devi_intr_curr_nintrs : 0);
}

/*
 * NOTE: This function is only called by
 *       ddi_intr_alloc() and ddi_intr_free().
 */
void
i_ddi_intr_set_current_nintrs(dev_info_t *dip, int nintrs)
{
	devinfo_intr_t *intr_p = DEVI(dip)->devi_intr_p;

	if (intr_p)
		intr_p->devi_intr_curr_nintrs = nintrs;
}

uint_t
i_ddi_intr_get_current_nenables(dev_info_t *dip)
{
	devinfo_intr_t *intr_p = DEVI(dip)->devi_intr_p;

	return (intr_p ? intr_p->devi_intr_curr_nenables : 0);
}

void
i_ddi_intr_set_current_nenables(dev_info_t *dip, int nintrs)
{
	devinfo_intr_t *intr_p = DEVI(dip)->devi_intr_p;

	if (intr_p)
		intr_p->devi_intr_curr_nenables = nintrs;
}

/*
 * i_ddi_intr_get_current_navail:
 *
 *	Return the number of interrupts currently available.
 *	If a precise number set by IRM is not available, then
 *	return the limit determined by i_ddi_intr_get_limit().
 */
uint_t
i_ddi_intr_get_current_navail(dev_info_t *dip, int type)
{
	devinfo_intr_t		*intr_p;
	ddi_irm_pool_t		*pool_p;
	ddi_irm_req_t		*req_p;
	uint_t			navail;

	/* Check for a precise number from IRM */
	if (((intr_p = DEVI(dip)->devi_intr_p) != NULL) &&
	    ((req_p = intr_p->devi_irm_req_p) != NULL) &&
	    (type == req_p->ireq_type) &&
	    ((pool_p = req_p->ireq_pool_p) != NULL)) {
		/*
		 * Lock to be sure a rebalance is not in progress.
		 * (Should be changed to a rwlock.)
		 */
		mutex_enter(&pool_p->ipool_navail_lock);
		navail = req_p->ireq_navail;
		mutex_exit(&pool_p->ipool_navail_lock);
		return (navail);
	}

	/* Otherwise, return the limit */
	return (i_ddi_intr_get_limit(dip, type, NULL));
}

/*
 * i_ddi_intr_get_limit:
 *
 *	Return the limit of how many interrupts a driver can allocate.
 */
uint_t
i_ddi_intr_get_limit(dev_info_t *dip, int type, ddi_irm_pool_t *pool_p)
{
	ddi_intr_handle_impl_t	hdl;
	uint_t			limit, nintrs;

	/* Check for interrupt pool */
	if (pool_p == NULL)
		pool_p = i_ddi_intr_get_pool(dip, type);

	/* Get default limit, from interrupt pool or by INTROP method */
	if (pool_p != NULL) {
		limit = pool_p->ipool_defsz;
	} else {
		bzero(&hdl, sizeof (ddi_intr_handle_impl_t));
		hdl.ih_dip = dip;
		hdl.ih_type = type;
		if (i_ddi_intr_ops(dip, dip, DDI_INTROP_NAVAIL, &hdl,
		    (void *)&limit) != DDI_SUCCESS)
			return (0);
	}

	/* Get maximum supported by the device */
	nintrs = i_ddi_intr_get_supported_nintrs(dip, type);

	/* No limit if device and system both support IRM */
	if ((pool_p != NULL) && (i_ddi_irm_supported(dip, type) == DDI_SUCCESS))
		return (nintrs);

	/* Limit cannot exceed what device supports */
	limit = MIN(limit, nintrs);

	/* Impose a global MSI-X limit on x86 */
#if defined(__i386) || defined(__amd64)
	if (type == DDI_INTR_TYPE_MSIX)
		limit = MIN(limit, ddi_msix_alloc_limit);
#endif

	/* Impose a global MSI limit on all platforms */
	if (type == DDI_INTR_TYPE_MSI)
		limit = MIN(limit, DDI_MAX_MSI_ALLOC);

	return (limit);
}

ddi_intr_msix_t *
i_ddi_get_msix(dev_info_t *dip)
{
	devinfo_intr_t *intr_p = DEVI(dip)->devi_intr_p;

	return (intr_p ? intr_p->devi_msix_p : NULL);
}

void
i_ddi_set_msix(dev_info_t *dip, ddi_intr_msix_t *msix_p)
{
	devinfo_intr_t *intr_p = DEVI(dip)->devi_intr_p;

	if (intr_p)
		intr_p->devi_msix_p = msix_p;
}

ddi_intr_handle_t
i_ddi_get_intr_handle(dev_info_t *dip, int inum)
{
	devinfo_intr_t *intr_p = DEVI(dip)->devi_intr_p;

	if (intr_p == NULL)
		return (NULL);

	/*
	 * Changed this to a check and return NULL if an invalid inum
	 * is passed to retrieve a handle
	 */
	if ((inum < 0) || (inum >= intr_p->devi_intr_sup_nintrs))
		return (NULL);

	return ((intr_p->devi_intr_handle_p) ?
	    intr_p->devi_intr_handle_p[inum] : NULL);
}

void
i_ddi_set_intr_handle(dev_info_t *dip, int inum, ddi_intr_handle_t intr_hdl)
{
	devinfo_intr_t	*intr_p = DEVI(dip)->devi_intr_p;

	if (intr_p == NULL)
		return;

	/*
	 * Changed this to a check and return if an invalid inum
	 * is passed to set a handle
	 */
	if ((inum < 0) || (inum >= intr_p->devi_intr_sup_nintrs))
		return;

	if (intr_hdl && (intr_p->devi_intr_handle_p == NULL)) {
		/* nintrs could be zero; so check for it first */
		if (intr_p->devi_intr_sup_nintrs)
			intr_p->devi_intr_handle_p = kmem_zalloc(
			    sizeof (ddi_intr_handle_t) *
			    intr_p->devi_intr_sup_nintrs, KM_SLEEP);
	}

	if (intr_p->devi_intr_handle_p)
		intr_p->devi_intr_handle_p[inum] = intr_hdl;
}

/*
 * The "ddi-intr-weight" property contains the weight of each interrupt
 * associated with a dev_info node. For devices with multiple interrupts per
 * dev_info node, the total load of the device is "devi_intr_weight * nintr",
 * possibly spread out over multiple CPUs.
 *
 * Maintaining this as a property permits possible tweaking in the product
 * in response to customer problems via driver.conf property definitions at
 * the driver or the instance level.  This does not mean that "ddi-intr_weight"
 * is a formal or committed interface.
 */
int32_t
i_ddi_get_intr_weight(dev_info_t *dip)
{
	int32_t	weight;

	weight = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, "ddi-intr-weight", -1);
	if (weight < -1)
		weight = -1;			/* undefined */
	return (weight);
}

int32_t
i_ddi_set_intr_weight(dev_info_t *dip, int32_t weight)
{
	int32_t oweight;

	oweight = i_ddi_get_intr_weight(dip);
	if ((weight > 0) && (oweight != weight))
		(void) ndi_prop_update_int(DDI_DEV_T_NONE, dip,
		    "ddi-intr-weight", weight);
	return (oweight);
}

/*
 * Old DDI interrupt framework
 *
 * NOTE:
 *	The following 4 busops entry points are obsoleted with version
 *	9 or greater. Use i_ddi_intr_op interface in place of these
 *	obsolete interfaces.
 *
 *	Remove these busops entry points and all related data structures
 *	in future major/minor solaris release.
 */

/* ARGSUSED */
ddi_intrspec_t
i_ddi_get_intrspec(dev_info_t *dip, dev_info_t *rdip, uint_t inumber)
{
	dev_info_t	*pdip = ddi_get_parent(dip);

	cmn_err(CE_WARN, "Failed to process interrupt "
	    "for %s%d due to down-rev nexus driver %s%d",
	    ddi_driver_name(rdip), ddi_get_instance(rdip),
	    ddi_driver_name(pdip), ddi_get_instance(pdip));

	return (NULL);
}

/* ARGSUSED */
int
i_ddi_add_intrspec(dev_info_t *dip, dev_info_t *rdip, ddi_intrspec_t intrspec,
    ddi_iblock_cookie_t *iblock_cookiep,
    ddi_idevice_cookie_t *idevice_cookiep,
    uint_t (*int_handler)(caddr_t int_handler_arg),
    caddr_t int_handler_arg, int kind)
{
	dev_info_t	*pdip = ddi_get_parent(dip);

	cmn_err(CE_WARN, "Failed to process interrupt "
	    "for %s%d due to down-rev nexus driver %s%d",
	    ddi_driver_name(rdip), ddi_get_instance(rdip),
	    ddi_driver_name(pdip), ddi_get_instance(pdip));

	return (DDI_ENOTSUP);
}

/* ARGSUSED */
void
i_ddi_remove_intrspec(dev_info_t *dip, dev_info_t *rdip,
    ddi_intrspec_t intrspec, ddi_iblock_cookie_t iblock_cookie)
{
	dev_info_t	*pdip = ddi_get_parent(dip);

	cmn_err(CE_WARN, "Failed to process interrupt "
	    "for %s%d due to down-rev nexus driver %s%d",
	    ddi_driver_name(rdip), ddi_get_instance(rdip),
	    ddi_driver_name(pdip), ddi_get_instance(pdip));
}

/* ARGSUSED */
int
i_ddi_intr_ctlops(dev_info_t *dip, dev_info_t *rdip, ddi_intr_ctlop_t op,
    void *arg, void *val)
{
	dev_info_t	*pdip = ddi_get_parent(dip);

	cmn_err(CE_WARN, "Failed to process interrupt "
	    "for %s%d due to down-rev nexus driver %s%d",
	    ddi_driver_name(rdip), ddi_get_instance(rdip),
	    ddi_driver_name(pdip), ddi_get_instance(pdip));

	return (DDI_ENOTSUP);
}

/*
 * Interrupt target get/set functions
 */
int
get_intr_affinity(ddi_intr_handle_t h, processorid_t *tgt_p)
{
	ddi_intr_handle_impl_t	*hdlp = (ddi_intr_handle_impl_t *)h;
	int			ret;

	DDI_INTR_APIDBG((CE_CONT, "get_intr_affinity: hdlp = %p\n",
	    (void *)hdlp));

	if ((hdlp == NULL) || (tgt_p == NULL))
		return (DDI_EINVAL);

	rw_enter(&hdlp->ih_rwlock, RW_READER);
	if (hdlp->ih_state != DDI_IHDL_STATE_ENABLE) {
		rw_exit(&hdlp->ih_rwlock);
		return (DDI_EINVAL);
	}

	ret = i_ddi_intr_ops(hdlp->ih_dip, hdlp->ih_dip,
	    DDI_INTROP_GETTARGET, hdlp, (void *)tgt_p);

	DDI_INTR_APIDBG((CE_CONT, "get_intr_affinity: target %x\n",
	    *tgt_p));

	if (ret == DDI_SUCCESS)
		hdlp->ih_target = *tgt_p;

	rw_exit(&hdlp->ih_rwlock);
	return (ret);
}

int
set_intr_affinity(ddi_intr_handle_t h, processorid_t tgt)
{
	ddi_intr_handle_impl_t	*hdlp = (ddi_intr_handle_impl_t *)h;
	int			ret;

	DDI_INTR_APIDBG((CE_CONT, "set_intr_affinity: hdlp = %p "
	    "target %x\n", (void *)hdlp, tgt));

	if (hdlp == NULL)
		return (DDI_EINVAL);

	rw_enter(&hdlp->ih_rwlock, RW_WRITER);
	if ((hdlp->ih_state != DDI_IHDL_STATE_ENABLE) ||
	    (hdlp->ih_type != DDI_INTR_TYPE_MSIX)) {
		rw_exit(&hdlp->ih_rwlock);
		return (DDI_EINVAL);
	}

	ret = i_ddi_intr_ops(hdlp->ih_dip, hdlp->ih_dip,
	    DDI_INTROP_SETTARGET, hdlp, &tgt);

	if (ret == DDI_SUCCESS)
		hdlp->ih_target = tgt;

	rw_exit(&hdlp->ih_rwlock);
	return (ret);
}

#if defined(__i386) || defined(__amd64)
ddi_acc_handle_t
i_ddi_get_pci_config_handle(dev_info_t *dip)
{
	devinfo_intr_t *intr_p = DEVI(dip)->devi_intr_p;

	return (intr_p ? intr_p->devi_cfg_handle : NULL);
}

void
i_ddi_set_pci_config_handle(dev_info_t *dip, ddi_acc_handle_t handle)
{
	devinfo_intr_t *intr_p = DEVI(dip)->devi_intr_p;

	if (intr_p)
		intr_p->devi_cfg_handle = handle;
}


int
i_ddi_get_msi_msix_cap_ptr(dev_info_t *dip)
{
	devinfo_intr_t *intr_p = DEVI(dip)->devi_intr_p;

	return (intr_p ? intr_p->devi_cap_ptr : 0);
}

void
i_ddi_set_msi_msix_cap_ptr(dev_info_t *dip, int cap_ptr)
{
	devinfo_intr_t *intr_p = DEVI(dip)->devi_intr_p;

	if (intr_p)
		intr_p->devi_cap_ptr = cap_ptr;
}
#endif
