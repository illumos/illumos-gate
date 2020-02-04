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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * PCI nexus driver interface
 */

/*
 * Copyright 2019 Peter Tribble.
 */

#include <sys/types.h>
#include <sys/conf.h>		/* nulldev */
#include <sys/stat.h>		/* devctl */
#include <sys/kmem.h>
#include <sys/async.h>		/* ecc_flt for pci_ecc.h */
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/ndifm.h>
#include <sys/ontrap.h>
#include <sys/ddi_impldefs.h>
#include <sys/ddi_subrdefs.h>
#include <sys/epm.h>
#include <sys/hotplug/pci/pcihp.h>
#include <sys/pci/pci_tools_ext.h>
#include <sys/spl.h>
#include <sys/pci/pci_obj.h>

/*LINTLIBRARY*/

/*
 * function prototype for hotplug routine:
 */
static void
pci_init_hotplug(struct pci *);

/*
 * function prototypes for dev ops routines:
 */
static int pci_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int pci_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);
static int pci_info(dev_info_t *dip, ddi_info_cmd_t infocmd,
	void *arg, void **result);
static int pci_ctlops_poke(pci_t *pci_p, peekpoke_ctlops_t *in_args);
static int pci_ctlops_peek(pci_t *pci_p, peekpoke_ctlops_t *in_args,
    void *result);
static off_t get_reg_set_size(dev_info_t *child, int rnumber);

/*
 * bus ops and dev ops structures:
 */
static struct bus_ops pci_bus_ops = {
	BUSO_REV,
	pci_map,
	0,
	0,
	0,
	i_ddi_map_fault,
	pci_dma_setup,
	pci_dma_allochdl,
	pci_dma_freehdl,
	pci_dma_bindhdl,
	pci_dma_unbindhdl,
	pci_dma_sync,
	pci_dma_win,
	pci_dma_ctlops,
	pci_ctlops,
	ddi_bus_prop_op,
	ndi_busop_get_eventcookie,	/* (*bus_get_eventcookie)(); */
	ndi_busop_add_eventcall,	/* (*bus_add_eventcall)(); */
	ndi_busop_remove_eventcall,	/* (*bus_remove_eventcall)(); */
	ndi_post_event,			/* (*bus_post_event)(); */
	NULL,				/* (*bus_intr_ctl)(); */
	NULL,				/* (*bus_config)(); */
	NULL,				/* (*bus_unconfig)(); */
	pci_fm_init_child,		/* (*bus_fm_init)(); */
	NULL,				/* (*bus_fm_fini)(); */
	pci_bus_enter,			/* (*bus_fm_access_enter)(); */
	pci_bus_exit,			/* (*bus_fm_access_fini)(); */
	NULL,				/* (*bus_power)(); */
	pci_intr_ops			/* (*bus_intr_op)(); */
};

extern struct cb_ops pci_cb_ops;

static struct dev_ops pci_ops = {
	DEVO_REV,
	0,
	pci_info,
	nulldev,
	0,
	pci_attach,
	pci_detach,
	nodev,
	&pci_cb_ops,
	&pci_bus_ops,
	0,
	ddi_quiesce_not_supported,	/* devo_quiesce */
};

/*
 * module definitions:
 */
#include <sys/modctl.h>
extern struct mod_ops mod_driverops;

static struct modldrv modldrv = {
	&mod_driverops,				/* Type of module - driver */
	"Sun4u Host to PCI nexus driver",	/* Name of module. */
	&pci_ops,				/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modldrv, NULL
};

/*
 * driver global data:
 */
void *per_pci_state;		/* per-pbm soft state pointer */
void *per_pci_common_state;	/* per-psycho soft state pointer */
kmutex_t pci_global_mutex;	/* attach/detach common struct lock */
errorq_t *pci_ecc_queue = NULL;	/* per-system ecc handling queue */
extern errorq_t *pci_target_queue;
struct cb_ops *pcihp_ops = NULL;	/* hotplug module cb ops */

extern void pci_child_cfg_save(dev_info_t *dip);
extern void pci_child_cfg_restore(dev_info_t *dip);

int
_init(void)
{
	int e;

	/*
	 * Initialize per-pci bus soft state pointer.
	 */
	e = ddi_soft_state_init(&per_pci_state, sizeof (pci_t), 1);
	if (e != 0)
		return (e);

	/*
	 * Initialize per-psycho soft state pointer.
	 */
	e = ddi_soft_state_init(&per_pci_common_state,
	    sizeof (pci_common_t), 1);
	if (e != 0) {
		ddi_soft_state_fini(&per_pci_state);
		return (e);
	}

	/*
	 * Initialize global mutexes.
	 */
	mutex_init(&pci_global_mutex, NULL, MUTEX_DRIVER, NULL);
	pci_reloc_init();

	/*
	 * Create the performance kstats.
	 */
	pci_kstat_init();

	/*
	 * Install the module.
	 */
	e = mod_install(&modlinkage);
	if (e != 0) {
		ddi_soft_state_fini(&per_pci_state);
		ddi_soft_state_fini(&per_pci_common_state);
		mutex_destroy(&pci_global_mutex);
	}
	return (e);
}

int
_fini(void)
{
	int e;

	/*
	 * Remove the module.
	 */
	e = mod_remove(&modlinkage);
	if (e != 0)
		return (e);

	/*
	 * Destroy pci_ecc_queue, and set it to NULL.
	 */
	if (pci_ecc_queue)
		errorq_destroy(pci_ecc_queue);

	pci_ecc_queue = NULL;

	/*
	 * Destroy pci_target_queue, and set it to NULL.
	 */
	if (pci_target_queue)
		errorq_destroy(pci_target_queue);

	pci_target_queue = NULL;

	/*
	 * Destroy the performance kstats.
	 */
	pci_kstat_fini();

	/*
	 * Free the per-pci and per-psycho soft state info and destroy
	 * mutex for per-psycho soft state.
	 */
	ddi_soft_state_fini(&per_pci_state);
	ddi_soft_state_fini(&per_pci_common_state);
	mutex_destroy(&pci_global_mutex);
	pci_reloc_fini();
	return (e);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*ARGSUSED*/
static int
pci_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	int	instance = PCIHP_AP_MINOR_NUM_TO_INSTANCE(getminor((dev_t)arg));
	pci_t	*pci_p = get_pci_soft_state(instance);

	/* allow hotplug to deal with ones it manages */
	if (pci_p && (pci_p->hotplug_capable == B_TRUE))
		return (pcihp_info(dip, infocmd, arg, result));

	/* non-hotplug or not attached */
	switch (infocmd) {
	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)(uintptr_t)instance;
		return (DDI_SUCCESS);

	case DDI_INFO_DEVT2DEVINFO:
		if (pci_p == NULL)
			return (DDI_FAILURE);
		*result = (void *)pci_p->pci_dip;
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}
}


/* device driver entry points */
/*
 * attach entry point:
 */
static int
pci_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	pci_t *pci_p;			/* per bus state pointer */
	int instance = ddi_get_instance(dip);

	switch (cmd) {
	case DDI_ATTACH:
		DEBUG0(DBG_ATTACH, dip, "DDI_ATTACH\n");

		/*
		 * Allocate and get the per-pci soft state structure.
		 */
		if (alloc_pci_soft_state(instance) != DDI_SUCCESS) {
			cmn_err(CE_WARN, "%s%d: can't allocate pci state",
			    ddi_driver_name(dip), instance);
			goto err_bad_pci_softstate;
		}
		pci_p = get_pci_soft_state(instance);
		pci_p->pci_dip = dip;
		mutex_init(&pci_p->pci_mutex, NULL, MUTEX_DRIVER, NULL);
		pci_p->pci_soft_state = PCI_SOFT_STATE_CLOSED;

		/*
		 * Get key properties of the pci bridge node and
		 * determine it's type (psycho, schizo, etc ...).
		 */
		if (get_pci_properties(pci_p, dip) == DDI_FAILURE)
			goto err_bad_pci_prop;

		/*
		 * Map in the registers.
		 */
		if (map_pci_registers(pci_p, dip) == DDI_FAILURE)
			goto err_bad_reg_prop;

		if (pci_obj_setup(pci_p) != DDI_SUCCESS)
			goto err_bad_objs;

		/*
		 * If this PCI leaf has hotplug and this platform
		 * loads hotplug modules then initialize the
		 * hotplug framework.
		 */
		pci_init_hotplug(pci_p);

		/*
		 * Create the "devctl" node for hotplug support.
		 * For non-hotplug bus, we still need ":devctl" to
		 * support DEVCTL_DEVICE_* and DEVCTL_BUS_* ioctls.
		 */
		if (pci_p->hotplug_capable == B_FALSE) {
			if (ddi_create_minor_node(dip, "devctl", S_IFCHR,
			    PCIHP_AP_MINOR_NUM(instance, PCIHP_DEVCTL_MINOR),
			    DDI_NT_NEXUS, 0) != DDI_SUCCESS)
				goto err_bad_devctl_node;
		}

		/*
		 * Create pcitool nodes for register access and interrupt
		 * routing.
		 */
		if (pcitool_init(dip) != DDI_SUCCESS) {
			goto err_bad_pcitool_nodes;
		}
		ddi_report_dev(dip);

		pci_p->pci_state = PCI_ATTACHED;
		DEBUG0(DBG_ATTACH, dip, "attach success\n");
		break;

err_bad_pcitool_nodes:
		if (pci_p->hotplug_capable == B_FALSE)
			ddi_remove_minor_node(dip, "devctl");
		else
			(void) pcihp_uninit(dip);
err_bad_devctl_node:
		pci_obj_destroy(pci_p);
err_bad_objs:
		unmap_pci_registers(pci_p);
err_bad_reg_prop:
		free_pci_properties(pci_p);
err_bad_pci_prop:
		mutex_destroy(&pci_p->pci_mutex);
		free_pci_soft_state(instance);
err_bad_pci_softstate:
		return (DDI_FAILURE);

	case DDI_RESUME:
		DEBUG0(DBG_ATTACH, dip, "DDI_RESUME\n");

		/*
		 * Make sure the Psycho control registers and IOMMU
		 * are configured properly.
		 */
		pci_p = get_pci_soft_state(instance);
		mutex_enter(&pci_p->pci_mutex);

		/*
		 * Make sure this instance has been suspended.
		 */
		if (pci_p->pci_state != PCI_SUSPENDED) {
			DEBUG0(DBG_ATTACH, dip, "instance NOT suspended\n");
			mutex_exit(&pci_p->pci_mutex);
			return (DDI_FAILURE);
		}
		pci_obj_resume(pci_p);
		pci_p->pci_state = PCI_ATTACHED;

		pci_child_cfg_restore(dip);

		mutex_exit(&pci_p->pci_mutex);
		break;

	default:
		DEBUG0(DBG_ATTACH, dip, "unsupported attach op\n");
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/*
 * detach entry point:
 */
static int
pci_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int instance = ddi_get_instance(dip);
	pci_t *pci_p = get_pci_soft_state(instance);

	/*
	 * Make sure we are currently attached
	 */
	if (pci_p->pci_state != PCI_ATTACHED) {
		DEBUG0(DBG_ATTACH, dip, "failed - instance not attached\n");
		return (DDI_FAILURE);
	}

	mutex_enter(&pci_p->pci_mutex);

	switch (cmd) {
	case DDI_DETACH:
		DEBUG0(DBG_DETACH, dip, "DDI_DETACH\n");

		if (pci_p->hotplug_capable == B_TRUE)
			if (pcihp_uninit(dip) == DDI_FAILURE) {
				mutex_exit(&pci_p->pci_mutex);
				return (DDI_FAILURE);
			}

		pcitool_uninit(dip);

		pci_obj_destroy(pci_p);

		/*
		 * Free the pci soft state structure and the rest of the
		 * resources it's using.
		 */
		free_pci_properties(pci_p);
		unmap_pci_registers(pci_p);
		mutex_exit(&pci_p->pci_mutex);
		mutex_destroy(&pci_p->pci_mutex);
		free_pci_soft_state(instance);

		/* Free the interrupt-priorities prop if we created it. */
		{
			int len;

			if (ddi_getproplen(DDI_DEV_T_ANY, dip,
			    DDI_PROP_NOTPROM | DDI_PROP_DONTPASS,
			    "interrupt-priorities", &len) == DDI_PROP_SUCCESS)
				(void) ddi_prop_remove(DDI_DEV_T_NONE, dip,
				    "interrupt-priorities");
		}
		return (DDI_SUCCESS);

	case DDI_SUSPEND:
		pci_child_cfg_save(dip);
		pci_obj_suspend(pci_p);
		pci_p->pci_state = PCI_SUSPENDED;

		mutex_exit(&pci_p->pci_mutex);
		return (DDI_SUCCESS);

	default:
		DEBUG0(DBG_DETACH, dip, "unsupported detach op\n");
		mutex_exit(&pci_p->pci_mutex);
		return (DDI_FAILURE);
	}
}


/* bus driver entry points */

/*
 * bus map entry point:
 *
 *	if map request is for an rnumber
 *		get the corresponding regspec from device node
 *	build a new regspec in our parent's format
 *	build a new map_req with the new regspec
 *	call up the tree to complete the mapping
 */
int
pci_map(dev_info_t *dip, dev_info_t *rdip, ddi_map_req_t *mp,
    off_t off, off_t len, caddr_t *addrp)
{
	pci_t *pci_p = get_pci_soft_state(ddi_get_instance(dip));
	struct regspec p_regspec;
	ddi_map_req_t p_mapreq;
	int reglen, rval, r_no;
	pci_regspec_t reloc_reg, *rp = &reloc_reg;

	DEBUG2(DBG_MAP, dip, "rdip=%s%d:",
	    ddi_driver_name(rdip), ddi_get_instance(rdip));

	if (mp->map_flags & DDI_MF_USER_MAPPING)
		return (DDI_ME_UNIMPLEMENTED);

	switch (mp->map_type) {
	case DDI_MT_REGSPEC:
		reloc_reg = *(pci_regspec_t *)mp->map_obj.rp;	/* dup whole */
		break;

	case DDI_MT_RNUMBER:
		r_no = mp->map_obj.rnumber;
		DEBUG1(DBG_MAP | DBG_CONT, dip, " r#=%x", r_no);

		if (ddi_getlongprop(DDI_DEV_T_ANY, rdip, DDI_PROP_DONTPASS,
		    "reg", (caddr_t)&rp, &reglen) != DDI_SUCCESS)
				return (DDI_ME_RNUMBER_RANGE);

		if (r_no < 0 || r_no >= reglen / sizeof (pci_regspec_t)) {
			kmem_free(rp, reglen);
			return (DDI_ME_RNUMBER_RANGE);
		}
		rp += r_no;
		break;

	default:
		return (DDI_ME_INVAL);
	}
	DEBUG0(DBG_MAP | DBG_CONT, dip, "\n");

	/* use "assigned-addresses" to relocate regspec within pci space */
	if (rval = pci_reloc_reg(dip, rdip, pci_p, rp))
		goto done;

	if (len)	/* adjust regspec according to mapping request */
		rp->pci_size_low = len;
	rp->pci_phys_low += off;

	/* use "ranges" to translate relocated pci regspec into parent space */
	if (rval = pci_xlate_reg(pci_p, rp, &p_regspec))
		goto done;

	p_mapreq = *mp;		/* dup the whole structure */
	p_mapreq.map_type = DDI_MT_REGSPEC;
	p_mapreq.map_obj.rp = &p_regspec;
	rval = ddi_map(dip, &p_mapreq, 0, 0, addrp);

	if (rval == DDI_SUCCESS) {
		/*
		 * Set-up access functions for FM access error capable drivers.
		 */
		if (DDI_FM_ACC_ERR_CAP(pci_p->pci_fm_cap) &&
		    DDI_FM_ACC_ERR_CAP(ddi_fm_capable(rdip)) &&
		    mp->map_handlep->ah_acc.devacc_attr_access !=
		    DDI_DEFAULT_ACC)
			pci_fm_acc_setup(mp, rdip);
	}

done:
	if (mp->map_type == DDI_MT_RNUMBER)
		kmem_free(rp - r_no, reglen);

	return (rval);
}

/*
 * bus dma map entry point
 * return value:
 *	DDI_DMA_PARTIAL_MAP	 1
 *	DDI_DMA_MAPOK		 0
 *	DDI_DMA_MAPPED		 0
 *	DDI_DMA_NORESOURCES	-1
 *	DDI_DMA_NOMAPPING	-2
 *	DDI_DMA_TOOBIG		-3
 */
int
pci_dma_setup(dev_info_t *dip, dev_info_t *rdip, ddi_dma_req_t *dmareq,
    ddi_dma_handle_t *handlep)
{
	pci_t *pci_p = get_pci_soft_state(ddi_get_instance(dip));
	iommu_t *iommu_p = pci_p->pci_iommu_p;
	ddi_dma_impl_t *mp;
	int ret;

	DEBUG3(DBG_DMA_MAP, dip, "mapping - rdip=%s%d type=%s\n",
	    ddi_driver_name(rdip), ddi_get_instance(rdip),
	    handlep ? "alloc" : "advisory");

	if (!(mp = pci_dma_lmts2hdl(dip, rdip, iommu_p, dmareq)))
		return (DDI_DMA_NORESOURCES);
	if (mp == (ddi_dma_impl_t *)DDI_DMA_NOMAPPING)
		return (DDI_DMA_NOMAPPING);
	if (ret = pci_dma_type(pci_p, dmareq, mp))
		goto freehandle;
	if (ret = pci_dma_pfn(pci_p, dmareq, mp))
		goto freehandle;

	switch (PCI_DMA_TYPE(mp)) {
	case DMAI_FLAGS_DVMA:	/* LINTED E_EQUALITY_NOT_ASSIGNMENT */
		if ((ret = pci_dvma_win(pci_p, dmareq, mp)) || !handlep)
			goto freehandle;
		if (!PCI_DMA_CANCACHE(mp)) {	/* try fast track */
			if (PCI_DMA_CANFAST(mp)) {
				if (!pci_dvma_map_fast(iommu_p, mp))
					break;
			/* LINTED E_NOP_ELSE_STMT */
			} else {
				PCI_DVMA_FASTTRAK_PROF(mp);
			}
		}
		if (ret = pci_dvma_map(mp, dmareq, iommu_p))
			goto freehandle;
		break;
	case DMAI_FLAGS_PEER_TO_PEER:	/* LINTED E_EQUALITY_NOT_ASSIGNMENT */
		if ((ret = pci_dma_physwin(pci_p, dmareq, mp)) || !handlep)
			goto freehandle;
		break;
	case DMAI_FLAGS_BYPASS:
	default:
		panic("%s%d: pci_dma_setup: bad dma type 0x%x",
		    ddi_driver_name(rdip), ddi_get_instance(rdip),
		    PCI_DMA_TYPE(mp));
		/*NOTREACHED*/
	}
	*handlep = (ddi_dma_handle_t)mp;
	mp->dmai_flags |= (DMAI_FLAGS_INUSE | DMAI_FLAGS_MAPPED);
	dump_dma_handle(DBG_DMA_MAP, dip, mp);

	return ((mp->dmai_nwin == 1) ? DDI_DMA_MAPPED : DDI_DMA_PARTIAL_MAP);
freehandle:
	if (ret == DDI_DMA_NORESOURCES)
		pci_dma_freemp(mp); /* don't run_callback() */
	else
		(void) pci_dma_freehdl(dip, rdip, (ddi_dma_handle_t)mp);
	return (ret);
}


/*
 * bus dma alloc handle entry point:
 */
int
pci_dma_allochdl(dev_info_t *dip, dev_info_t *rdip, ddi_dma_attr_t *attrp,
    int (*waitfp)(caddr_t), caddr_t arg, ddi_dma_handle_t *handlep)
{
	pci_t *pci_p = get_pci_soft_state(ddi_get_instance(dip));
	ddi_dma_impl_t *mp;
	int rval;

	DEBUG2(DBG_DMA_ALLOCH, dip, "rdip=%s%d\n",
	    ddi_driver_name(rdip), ddi_get_instance(rdip));

	if (attrp->dma_attr_version != DMA_ATTR_V0)
		return (DDI_DMA_BADATTR);

	if (!(mp = pci_dma_allocmp(dip, rdip, waitfp, arg)))
		return (DDI_DMA_NORESOURCES);

	/*
	 * Save requestor's information
	 */
	mp->dmai_attr	= *attrp; /* whole object - augmented later  */
	*DEV_ATTR(mp)	= *attrp; /* whole object - device orig attr */
	DEBUG1(DBG_DMA_ALLOCH, dip, "mp=%p\n", mp);

	/* check and convert dma attributes to handle parameters */
	if (rval = pci_dma_attr2hdl(pci_p, mp)) {
		pci_dma_freehdl(dip, rdip, (ddi_dma_handle_t)mp);
		*handlep = NULL;
		return (rval);
	}
	*handlep = (ddi_dma_handle_t)mp;
	return (DDI_SUCCESS);
}


/*
 * bus dma free handle entry point:
 */
/*ARGSUSED*/
int
pci_dma_freehdl(dev_info_t *dip, dev_info_t *rdip, ddi_dma_handle_t handle)
{
	DEBUG3(DBG_DMA_FREEH, dip, "rdip=%s%d mp=%p\n",
	    ddi_driver_name(rdip), ddi_get_instance(rdip), handle);
	pci_dma_freemp((ddi_dma_impl_t *)handle);

	if (pci_kmem_clid) {
		DEBUG0(DBG_DMA_FREEH, dip, "run handle callback\n");
		ddi_run_callback(&pci_kmem_clid);
	}
	return (DDI_SUCCESS);
}


/*
 * bus dma bind handle entry point:
 */
int
pci_dma_bindhdl(dev_info_t *dip, dev_info_t *rdip,
    ddi_dma_handle_t handle, ddi_dma_req_t *dmareq,
    ddi_dma_cookie_t *cookiep, uint_t *ccountp)
{
	pci_t *pci_p = get_pci_soft_state(ddi_get_instance(dip));
	iommu_t *iommu_p = pci_p->pci_iommu_p;
	ddi_dma_impl_t *mp = (ddi_dma_impl_t *)handle;
	int ret;

	DEBUG4(DBG_DMA_BINDH, dip, "rdip=%s%d mp=%p dmareq=%p\n",
	    ddi_driver_name(rdip), ddi_get_instance(rdip), mp, dmareq);

	if (mp->dmai_flags & DMAI_FLAGS_INUSE)
		return (DDI_DMA_INUSE);

	ASSERT((mp->dmai_flags & ~DMAI_FLAGS_PRESERVE) == 0);
	mp->dmai_flags |= DMAI_FLAGS_INUSE;

	if (ret = pci_dma_type(pci_p, dmareq, mp))
		goto err;
	if (ret = pci_dma_pfn(pci_p, dmareq, mp))
		goto err;

	switch (PCI_DMA_TYPE(mp)) {
	case DMAI_FLAGS_DVMA:
		if (ret = pci_dvma_win(pci_p, dmareq, mp))
			goto map_err;
		if (!PCI_DMA_CANCACHE(mp)) {	/* try fast track */
			if (PCI_DMA_CANFAST(mp)) {
				if (!pci_dvma_map_fast(iommu_p, mp))
					goto mapped; /*LINTED E_NOP_ELSE_STMT*/
			} else {
				PCI_DVMA_FASTTRAK_PROF(mp);
			}
		}
		if (ret = pci_dvma_map(mp, dmareq, iommu_p))
			goto map_err;
mapped:
		*ccountp = 1;
		MAKE_DMA_COOKIE(cookiep, mp->dmai_mapping, mp->dmai_size);
		mp->dmai_ncookies = 1;
		mp->dmai_curcookie = 1;
		break;
	case DMAI_FLAGS_BYPASS:
	case DMAI_FLAGS_PEER_TO_PEER:
		if (ret = pci_dma_physwin(pci_p, dmareq, mp))
			goto map_err;
		*ccountp = WINLST(mp)->win_ncookies;
		*cookiep = *(ddi_dma_cookie_t *)(WINLST(mp) + 1); /* wholeobj */
		/*
		 * mp->dmai_ncookies and mp->dmai_curcookie are set by
		 * pci_dma_physwin().
		 */
		break;
	default:
		panic("%s%d: pci_dma_bindhdl(%p): bad dma type",
		    ddi_driver_name(rdip), ddi_get_instance(rdip), mp);
		/*NOTREACHED*/
	}
	DEBUG2(DBG_DMA_BINDH, dip, "cookie %x+%x\n", cookiep->dmac_address,
	    cookiep->dmac_size);
	dump_dma_handle(DBG_DMA_MAP, dip, mp);

	if (mp->dmai_attr.dma_attr_flags & DDI_DMA_FLAGERR)
		mp->dmai_error.err_cf = impl_dma_check;

	mp->dmai_flags |= DMAI_FLAGS_MAPPED;
	return (mp->dmai_nwin == 1 ? DDI_DMA_MAPPED : DDI_DMA_PARTIAL_MAP);
map_err:
	pci_dvma_unregister_callbacks(pci_p, mp);
	pci_dma_freepfn(mp);
err:
	mp->dmai_flags &= DMAI_FLAGS_PRESERVE;
	return (ret);
}

/*
 * bus dma unbind handle entry point:
 */
/*ARGSUSED*/
int
pci_dma_unbindhdl(dev_info_t *dip, dev_info_t *rdip, ddi_dma_handle_t handle)
{
	ddi_dma_impl_t *mp = (ddi_dma_impl_t *)handle;
	pci_t *pci_p = get_pci_soft_state(ddi_get_instance(dip));
	iommu_t *iommu_p = pci_p->pci_iommu_p;

	DEBUG3(DBG_DMA_UNBINDH, dip, "rdip=%s%d, mp=%p\n",
	    ddi_driver_name(rdip), ddi_get_instance(rdip), handle);
	if ((mp->dmai_flags & DMAI_FLAGS_INUSE) == 0) {
		DEBUG0(DBG_DMA_UNBINDH, dip, "handle not in use\n");
		return (DDI_FAILURE);
	}

	mp->dmai_flags &= ~DMAI_FLAGS_MAPPED;

	switch (PCI_DMA_TYPE(mp)) {
	case DMAI_FLAGS_DVMA:
		pci_dvma_unregister_callbacks(pci_p, mp);
		pci_dma_sync_unmap(dip, rdip, mp);
		pci_dvma_unmap(iommu_p, mp);
		pci_dma_freepfn(mp);
		break;
	case DMAI_FLAGS_BYPASS:
	case DMAI_FLAGS_PEER_TO_PEER:
		pci_dma_freewin(mp);
		break;
	default:
		panic("%s%d: pci_dma_unbindhdl:bad dma type %p",
		    ddi_driver_name(rdip), ddi_get_instance(rdip), mp);
		/*NOTREACHED*/
	}
	if (iommu_p->iommu_dvma_clid != 0) {
		DEBUG0(DBG_DMA_UNBINDH, dip, "run dvma callback\n");
		ddi_run_callback(&iommu_p->iommu_dvma_clid);
	}
	if (pci_kmem_clid) {
		DEBUG0(DBG_DMA_UNBINDH, dip, "run handle callback\n");
		ddi_run_callback(&pci_kmem_clid);
	}
	mp->dmai_flags &= DMAI_FLAGS_PRESERVE;
	SYNC_BUF_PA(mp) = 0;

	mp->dmai_error.err_cf = NULL;
	mp->dmai_ncookies = 0;
	mp->dmai_curcookie = 0;

	return (DDI_SUCCESS);
}


/*
 * bus dma win entry point:
 */
int
pci_dma_win(dev_info_t *dip, dev_info_t *rdip,
    ddi_dma_handle_t handle, uint_t win, off_t *offp,
    size_t *lenp, ddi_dma_cookie_t *cookiep, uint_t *ccountp)
{
	ddi_dma_impl_t *mp = (ddi_dma_impl_t *)handle;
	DEBUG2(DBG_DMA_WIN, dip, "rdip=%s%d\n",
	    ddi_driver_name(rdip), ddi_get_instance(rdip));
	dump_dma_handle(DBG_DMA_WIN, dip, mp);
	if (win >= mp->dmai_nwin) {
		DEBUG1(DBG_DMA_WIN, dip, "%x out of range\n", win);
		return (DDI_FAILURE);
	}

	switch (PCI_DMA_TYPE(mp)) {
	case DMAI_FLAGS_DVMA:
		if (win != PCI_DMA_CURWIN(mp)) {
			pci_t *pci_p =
			    get_pci_soft_state(ddi_get_instance(dip));
			pci_dma_sync_unmap(dip, rdip, mp);
			/* map_window sets dmai_mapping/size/offset */
			iommu_map_window(pci_p->pci_iommu_p, mp, win);
		}
		if (cookiep)
			MAKE_DMA_COOKIE(cookiep, mp->dmai_mapping,
			    mp->dmai_size);
		if (ccountp)
			*ccountp = 1;
		mp->dmai_ncookies = 1;
		mp->dmai_curcookie = 1;
		break;
	case DMAI_FLAGS_PEER_TO_PEER:
	case DMAI_FLAGS_BYPASS: {
		int i;
		ddi_dma_cookie_t *ck_p;
		pci_dma_win_t *win_p = mp->dmai_winlst;

		for (i = 0; i < win; win_p = win_p->win_next, i++)
			;
		ck_p = (ddi_dma_cookie_t *)(win_p + 1);
		*cookiep = *ck_p;
		mp->dmai_offset = win_p->win_offset;
		mp->dmai_size   = win_p->win_size;
		mp->dmai_mapping = ck_p->dmac_laddress;
		mp->dmai_cookie = ck_p + 1;
		win_p->win_curseg = 0;
		if (ccountp)
			*ccountp = win_p->win_ncookies;
		mp->dmai_ncookies = win_p->win_ncookies;
		mp->dmai_curcookie = 1;
		}
		break;
	default:
		cmn_err(CE_WARN, "%s%d: pci_dma_win:bad dma type 0x%x",
		    ddi_driver_name(rdip), ddi_get_instance(rdip),
		    PCI_DMA_TYPE(mp));
		return (DDI_FAILURE);
	}
	if (cookiep)
		DEBUG2(DBG_DMA_WIN, dip,
		    "cookie - dmac_address=%x dmac_size=%x\n",
		    cookiep->dmac_address, cookiep->dmac_size);
	if (offp)
		*offp = (off_t)mp->dmai_offset;
	if (lenp)
		*lenp = mp->dmai_size;
	return (DDI_SUCCESS);
}

#ifdef DEBUG
static char *pci_dmactl_str[] = {
	"DDI_DMA_FREE",
	"DDI_DMA_SYNC",
	"DDI_DMA_HTOC",
	"DDI_DMA_KVADDR",
	"DDI_DMA_MOVWIN",
	"DDI_DMA_REPWIN",
	"DDI_DMA_GETERR",
	"DDI_DMA_COFF",
	"DDI_DMA_NEXTWIN",
	"DDI_DMA_NEXTSEG",
	"DDI_DMA_SEGTOC",
	"DDI_DMA_RESERVE",
	"DDI_DMA_RELEASE",
	"DDI_DMA_RESETH",
	"DDI_DMA_CKSYNC",
	"DDI_DMA_IOPB_ALLOC",
	"DDI_DMA_IOPB_FREE",
	"DDI_DMA_SMEM_ALLOC",
	"DDI_DMA_SMEM_FREE",
	"DDI_DMA_SET_SBUS64",
	"DDI_DMA_REMAP"
};
#endif

/*
 * bus dma control entry point:
 */
int
pci_dma_ctlops(dev_info_t *dip, dev_info_t *rdip, ddi_dma_handle_t handle,
    enum ddi_dma_ctlops cmd, off_t *offp, size_t *lenp, caddr_t *objp,
    uint_t cache_flags)
{
	ddi_dma_impl_t *mp = (ddi_dma_impl_t *)handle;
	DEBUG3(DBG_DMA_CTL, dip, "%s: rdip=%s%d\n", pci_dmactl_str[cmd],
	    ddi_driver_name(rdip), ddi_get_instance(rdip));

	switch (cmd) {
	case DDI_DMA_FREE:
		(void) pci_dma_unbindhdl(dip, rdip, handle);
		(void) pci_dma_freehdl(dip, rdip, handle);
		return (DDI_SUCCESS);
	case DDI_DMA_RESERVE: {
		pci_t *pci_p = get_pci_soft_state(ddi_get_instance(dip));
		return (pci_fdvma_reserve(dip, rdip, pci_p,
		    (ddi_dma_req_t *)offp, (ddi_dma_handle_t *)objp));
		}
	case DDI_DMA_RELEASE: {
		pci_t *pci_p = get_pci_soft_state(ddi_get_instance(dip));
		return (pci_fdvma_release(dip, pci_p, mp));
		}
	default:
		break;
	}

	switch (PCI_DMA_TYPE(mp)) {
	case DMAI_FLAGS_DVMA:
		return (pci_dvma_ctl(dip, rdip, mp, cmd, offp, lenp, objp,
		    cache_flags));
	case DMAI_FLAGS_PEER_TO_PEER:
	case DMAI_FLAGS_BYPASS:
		return (pci_dma_ctl(dip, rdip, mp, cmd, offp, lenp, objp,
		    cache_flags));
	default:
		panic("%s%d: pci_dma_ctlops(%x):bad dma type %x",
		    ddi_driver_name(rdip), ddi_get_instance(rdip), cmd,
		    mp->dmai_flags);
		/*NOTREACHED*/
	}
}

#ifdef  DEBUG
int	pci_peekfault_cnt = 0;
int	pci_pokefault_cnt = 0;
#endif  /* DEBUG */

static int
pci_do_poke(pci_t *pci_p, peekpoke_ctlops_t *in_args)
{
	pbm_t *pbm_p = pci_p->pci_pbm_p;
	int err = DDI_SUCCESS;
	on_trap_data_t otd;

	mutex_enter(&pbm_p->pbm_pokefault_mutex);
	pbm_p->pbm_ontrap_data = &otd;

	/* Set up protected environment. */
	if (!on_trap(&otd, OT_DATA_ACCESS)) {
		uintptr_t tramp = otd.ot_trampoline;

		otd.ot_trampoline = (uintptr_t)&poke_fault;
		err = do_poke(in_args->size, (void *)in_args->dev_addr,
		    (void *)in_args->host_addr);
		otd.ot_trampoline = tramp;
	} else
		err = DDI_FAILURE;

	/*
	 * Read the async fault register for the PBM to see it sees
	 * a master-abort.
	 */
	pbm_clear_error(pbm_p);

	if (otd.ot_trap & OT_DATA_ACCESS)
		err = DDI_FAILURE;

	/* Take down protected environment. */
	no_trap();

	pbm_p->pbm_ontrap_data = NULL;
	mutex_exit(&pbm_p->pbm_pokefault_mutex);

#ifdef  DEBUG
	if (err == DDI_FAILURE)
		pci_pokefault_cnt++;
#endif
	return (err);
}


static int
pci_do_caut_put(pci_t *pci_p, peekpoke_ctlops_t *cautacc_ctlops_arg)
{
	size_t size = cautacc_ctlops_arg->size;
	uintptr_t dev_addr = cautacc_ctlops_arg->dev_addr;
	uintptr_t host_addr = cautacc_ctlops_arg->host_addr;
	ddi_acc_impl_t *hp = (ddi_acc_impl_t *)cautacc_ctlops_arg->handle;
	size_t repcount = cautacc_ctlops_arg->repcount;
	uint_t flags = cautacc_ctlops_arg->flags;

	hp->ahi_err->err_expected = DDI_FM_ERR_EXPECTED;

	/*
	 * Note that i_ndi_busop_access_enter ends up grabbing the pokefault
	 * mutex.
	 */
	i_ndi_busop_access_enter(hp->ahi_common.ah_dip, (ddi_acc_handle_t)hp);

	if (!i_ddi_ontrap((ddi_acc_handle_t)hp)) {
		for (; repcount; repcount--) {
			switch (size) {

			case sizeof (uint8_t):
				i_ddi_put8(hp, (uint8_t *)dev_addr,
				    *(uint8_t *)host_addr);
				break;

			case sizeof (uint16_t):
				i_ddi_put16(hp, (uint16_t *)dev_addr,
				    *(uint16_t *)host_addr);
				break;

			case sizeof (uint32_t):
				i_ddi_put32(hp, (uint32_t *)dev_addr,
				    *(uint32_t *)host_addr);
				break;

			case sizeof (uint64_t):
				i_ddi_put64(hp, (uint64_t *)dev_addr,
				    *(uint64_t *)host_addr);
				break;
			}

			host_addr += size;

			if (flags == DDI_DEV_AUTOINCR)
				dev_addr += size;

		}
	}

	i_ddi_notrap((ddi_acc_handle_t)hp);
	i_ndi_busop_access_exit(hp->ahi_common.ah_dip, (ddi_acc_handle_t)hp);
	hp->ahi_err->err_expected = DDI_FM_ERR_UNEXPECTED;

	if (hp->ahi_err->err_status != DDI_FM_OK) {
		/* Clear the expected fault from the handle before returning */
		hp->ahi_err->err_status = DDI_FM_OK;
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}


static int
pci_ctlops_poke(pci_t *pci_p, peekpoke_ctlops_t *in_args)
{
	return (in_args->handle ? pci_do_caut_put(pci_p, in_args) :
	    pci_do_poke(pci_p, in_args));
}


static int
pci_do_peek(pci_t *pci_p, peekpoke_ctlops_t *in_args)
{
	int err = DDI_SUCCESS;
	on_trap_data_t otd;

	if (!on_trap(&otd, OT_DATA_ACCESS)) {
		uintptr_t tramp = otd.ot_trampoline;

		otd.ot_trampoline = (uintptr_t)&peek_fault;
		err = do_peek(in_args->size, (void *)in_args->dev_addr,
		    (void *)in_args->host_addr);
		otd.ot_trampoline = tramp;
	} else
		err = DDI_FAILURE;

	no_trap();

#ifdef  DEBUG
	if (err == DDI_FAILURE)
		pci_peekfault_cnt++;
#endif
	return (err);
}

static int
pci_do_caut_get(pci_t *pci_p, peekpoke_ctlops_t *cautacc_ctlops_arg)
{
	size_t size = cautacc_ctlops_arg->size;
	uintptr_t dev_addr = cautacc_ctlops_arg->dev_addr;
	uintptr_t host_addr = cautacc_ctlops_arg->host_addr;
	ddi_acc_impl_t *hp = (ddi_acc_impl_t *)cautacc_ctlops_arg->handle;
	size_t repcount = cautacc_ctlops_arg->repcount;
	uint_t flags = cautacc_ctlops_arg->flags;

	int err = DDI_SUCCESS;

	hp->ahi_err->err_expected = DDI_FM_ERR_EXPECTED;
	i_ndi_busop_access_enter(hp->ahi_common.ah_dip, (ddi_acc_handle_t)hp);

	if (!i_ddi_ontrap((ddi_acc_handle_t)hp)) {
		for (; repcount; repcount--) {
			i_ddi_caut_get(size, (void *)dev_addr,
			    (void *)host_addr);

			host_addr += size;

			if (flags == DDI_DEV_AUTOINCR)
				dev_addr += size;
		}
	} else {
		int i;
		uint8_t *ff_addr = (uint8_t *)host_addr;
		for (i = 0; i < size; i++)
			*ff_addr++ = 0xff;

		err = DDI_FAILURE;
	}

	i_ddi_notrap((ddi_acc_handle_t)hp);
	i_ndi_busop_access_exit(hp->ahi_common.ah_dip, (ddi_acc_handle_t)hp);
	hp->ahi_err->err_expected = DDI_FM_ERR_UNEXPECTED;

	return (err);
}


static int
pci_ctlops_peek(pci_t *pci_p, peekpoke_ctlops_t *in_args, void *result)
{
	result = (void *)in_args->host_addr;
	return (in_args->handle ? pci_do_caut_get(pci_p, in_args) :
	    pci_do_peek(pci_p, in_args));
}

/*
 * get_reg_set_size
 *
 * Given a dev info pointer to a pci child and a register number, this
 * routine returns the size element of that reg set property.
 * return value: size of reg set on success, -1 on error
 */
static off_t
get_reg_set_size(dev_info_t *child, int rnumber)
{
	pci_regspec_t *pci_rp;
	off_t size;
	int i;

	if (rnumber < 0)
		return (-1);

	/*
	 * Get the reg property for the device.
	 */
	if (ddi_getlongprop(DDI_DEV_T_ANY, child, DDI_PROP_DONTPASS, "reg",
	    (caddr_t)&pci_rp, &i) != DDI_SUCCESS)
		return (-1);

	if (rnumber >= (i / (int)sizeof (pci_regspec_t))) {
		kmem_free(pci_rp, i);
		return (-1);
	}

	size = pci_rp[rnumber].pci_size_low |
	    ((uint64_t)pci_rp[rnumber].pci_size_hi << 32);
	kmem_free(pci_rp, i);
	return (size);
}


/*
 * control ops entry point:
 *
 * Requests handled completely:
 *	DDI_CTLOPS_INITCHILD	see init_child() for details
 *	DDI_CTLOPS_UNINITCHILD
 *	DDI_CTLOPS_REPORTDEV	see report_dev() for details
 *	DDI_CTLOPS_IOMIN	cache line size if streaming otherwise 1
 *	DDI_CTLOPS_REGSIZE
 *	DDI_CTLOPS_NREGS
 *	DDI_CTLOPS_DVMAPAGESIZE
 *	DDI_CTLOPS_POKE
 *	DDI_CTLOPS_PEEK
 *	DDI_CTLOPS_QUIESCE
 *	DDI_CTLOPS_UNQUIESCE
 *
 * All others passed to parent.
 */
int
pci_ctlops(dev_info_t *dip, dev_info_t *rdip,
    ddi_ctl_enum_t op, void *arg, void *result)
{
	pci_t *pci_p = get_pci_soft_state(ddi_get_instance(dip));

	switch (op) {
	case DDI_CTLOPS_INITCHILD:
		return (init_child(pci_p, (dev_info_t *)arg));

	case DDI_CTLOPS_UNINITCHILD:
		return (uninit_child(pci_p, (dev_info_t *)arg));

	case DDI_CTLOPS_REPORTDEV:
		return (report_dev(rdip));

	case DDI_CTLOPS_IOMIN:

		/*
		 * If we are using the streaming cache, align at
		 * least on a cache line boundary. Otherwise use
		 * whatever alignment is passed in.
		 */

		if ((uintptr_t)arg) {
			int val = *((int *)result);

			val = maxbit(val, PCI_SBUF_LINE_SIZE);
			*((int *)result) = val;
		}
		return (DDI_SUCCESS);

	case DDI_CTLOPS_REGSIZE:
		*((off_t *)result) = get_reg_set_size(rdip, *((int *)arg));
		return (*((off_t *)result) == -1 ? DDI_FAILURE : DDI_SUCCESS);

	case DDI_CTLOPS_NREGS:
		*((uint_t *)result) = get_nreg_set(rdip);
		return (DDI_SUCCESS);

	case DDI_CTLOPS_DVMAPAGESIZE:
		*((ulong_t *)result) = IOMMU_PAGE_SIZE;
		return (DDI_SUCCESS);

	case DDI_CTLOPS_POKE:
		return (pci_ctlops_poke(pci_p, (peekpoke_ctlops_t *)arg));

	case DDI_CTLOPS_PEEK:
		return (pci_ctlops_peek(pci_p, (peekpoke_ctlops_t *)arg,
		    result));

	case DDI_CTLOPS_AFFINITY:
		break;

	case DDI_CTLOPS_QUIESCE:
		return (pci_bus_quiesce(pci_p, rdip, result));

	case DDI_CTLOPS_UNQUIESCE:
		return (pci_bus_unquiesce(pci_p, rdip, result));

	default:
		break;
	}

	/*
	 * Now pass the request up to our parent.
	 */
	DEBUG2(DBG_CTLOPS, dip, "passing request to parent: rdip=%s%d\n",
	    ddi_driver_name(rdip), ddi_get_instance(rdip));
	return (ddi_ctlops(dip, rdip, op, arg, result));
}


/* ARGSUSED */
int
pci_intr_ops(dev_info_t *dip, dev_info_t *rdip, ddi_intr_op_t intr_op,
    ddi_intr_handle_impl_t *hdlp, void *result)
{
	pci_t		*pci_p = get_pci_soft_state(ddi_get_instance(dip));
	ib_ino_t	ino;
	int		ret = DDI_SUCCESS;

	switch (intr_op) {
	case DDI_INTROP_GETCAP:
		/* GetCap will always fail for all non PCI devices */
		(void) pci_intx_get_cap(rdip, (int *)result);
		break;
	case DDI_INTROP_SETCAP:
		ret = DDI_ENOTSUP;
		break;
	case DDI_INTROP_ALLOC:
		*(int *)result = hdlp->ih_scratch1;
		break;
	case DDI_INTROP_FREE:
		break;
	case DDI_INTROP_GETPRI:
		*(int *)result = hdlp->ih_pri ?
		    hdlp->ih_pri : pci_class_to_pil(rdip);
		break;
	case DDI_INTROP_SETPRI:
		break;
	case DDI_INTROP_ADDISR:
		ret = pci_add_intr(dip, rdip, hdlp);
		break;
	case DDI_INTROP_REMISR:
		ret = pci_remove_intr(dip, rdip, hdlp);
		break;
	case DDI_INTROP_GETTARGET:
		ino = IB_MONDO_TO_INO(pci_xlate_intr(dip, rdip,
		    pci_p->pci_ib_p, IB_MONDO_TO_INO(hdlp->ih_vector)));
		ret = ib_get_intr_target(pci_p, ino, (int *)result);
		break;
	case DDI_INTROP_SETTARGET:
		ret = DDI_ENOTSUP;
		break;
	case DDI_INTROP_ENABLE:
		ret = ib_update_intr_state(pci_p, rdip, hdlp,
		    PCI_INTR_STATE_ENABLE);
		break;
	case DDI_INTROP_DISABLE:
		ret = ib_update_intr_state(pci_p, rdip, hdlp,
		    PCI_INTR_STATE_DISABLE);
		break;
	case DDI_INTROP_SETMASK:
		ret = pci_intx_set_mask(rdip);
		break;
	case DDI_INTROP_CLRMASK:
		ret = pci_intx_clr_mask(rdip);
		break;
	case DDI_INTROP_GETPENDING:
		ret = pci_intx_get_pending(rdip, (int *)result);
		break;
	case DDI_INTROP_NINTRS:
	case DDI_INTROP_NAVAIL:
		*(int *)result = i_ddi_get_intx_nintrs(rdip);
		break;
	case DDI_INTROP_SUPPORTED_TYPES:
		/* PCI nexus driver supports only fixed interrupts */
		*(int *)result = i_ddi_get_intx_nintrs(rdip) ?
		    DDI_INTR_TYPE_FIXED : 0;
		break;
	default:
		ret = DDI_ENOTSUP;
		break;
	}

	return (ret);
}

static void
pci_init_hotplug(struct pci *pci_p)
{
	pci_bus_range_t bus_range;
	dev_info_t *dip;

	/*
	 * Before initializing hotplug - open up
	 * bus range.  The busra module will
	 * initialize its pool of bus numbers from
	 * this. "busra" will be the agent that keeps
	 * track of them during hotplug.  Also, note,
	 * that busra will remove any bus numbers
	 * already in use from boot time.
	 */
	bus_range.lo = 0x0;
	bus_range.hi = 0xff;
	dip = pci_p->pci_dip;
	pci_p->hotplug_capable = B_FALSE;

	/*
	 * If this property exists, this nexus has hot-plug
	 * slots.
	 */
	if (ddi_prop_exists(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "hotplug-capable")) {
		if (ndi_prop_update_int_array(DDI_DEV_T_NONE,
		    dip, "bus-range",
		    (int *)&bus_range,
		    2) != DDI_PROP_SUCCESS) {
			return;
		}

		if (pcihp_init(dip) != DDI_SUCCESS) {
			return;
		}

		if ((pcihp_ops = pcihp_get_cb_ops()) != NULL) {
			DEBUG2(DBG_ATTACH, dip, "%s%d hotplug enabled",
			    ddi_driver_name(dip), ddi_get_instance(dip));
			pci_p->hotplug_capable = B_TRUE;
		}
	}
}
