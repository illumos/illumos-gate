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


/* from 4.1.1 sbusdev/dmaga.c 1.14 */

/*
 * SBus DMA gate array 'driver'
 */

#include <sys/debug.h>
#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/modctl.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/ddi_impldefs.h>
#include <sys/ddi_subrdefs.h>
#include <sys/dmaga.h>

typedef struct dma_softc {
	struct dma_softc *dma_next;	/* next in a linked list */
	struct dmaga *dma_regs;		/* pointer to mapped in registers */
	dev_info_t *dma_dev;		/* backpointer to dev structure */
	int dma_use;			/* use count */
} dma_softc_t;

static dma_softc_t *dma_softc;

static int dmaattach(dev_info_t *dev, ddi_attach_cmd_t cmd);
static int dmadetach(dev_info_t *dev, ddi_detach_cmd_t cmd);

/*
 * Configuration data structures
 */
static struct cb_ops dma_cb_ops = {
	nodev,			/* open */
	nodev,			/* close */
	nodev,			/* strategy */
	nodev,			/* print */
	nodev,			/* dump */
	nodev,			/* read */
	nodev,			/* write */
	nodev,			/* ioctl */
	nodev,			/* devmap */
	nodev,			/* mmap */
	nodev,			/* segmap */
	nochpoll,		/* poll */
	ddi_prop_op,		/* cb_prop_op */
	0,			/* streamtab */
	D_MP | D_HOTPLUG,	/* Driver compatibility flag */
	CB_REV,			/* rev */
	nodev,			/* int (*cb_aread)() */
	nodev			/* int (*cb_awrite)() */
};

static struct bus_ops dma_bus_ops = {
	BUSO_REV,
	i_ddi_bus_map,
	0,
	0,
	0,
	i_ddi_map_fault,
	ddi_dma_map,
	ddi_dma_allochdl,
	ddi_dma_freehdl,
	ddi_dma_bindhdl,
	ddi_dma_unbindhdl,
	ddi_dma_flush,
	ddi_dma_win,
	ddi_dma_mctl,
	ddi_ctlops,
	ddi_bus_prop_op,
	0,			/* (*bus_get_eventcookie)();	*/
	0,			/* (*bus_add_eventcall)();	*/
	0,			/* (*bus_remove_eventcall)();	*/
	0,			/* (*bus_post_event)();		*/
	0,			/* bus_intr_ctl		*/
	0,			/* bus_config		*/
	0,			/* bus_unconfig		*/
	0,			/* bus_fm_init		*/
	0,			/* bus_fm_fini		*/
	0,			/* bus_fm_access_enter	*/
	0,			/* bus_fm_access_exit	*/
	0,			/* bus_power		*/
	i_ddi_intr_ops		/* bus_intr_op		*/
};

static struct dev_ops dma_ops = {

	DEVO_REV,		/* devo_rev, */
	0,			/* refcnt  */
	ddi_no_info,		/* info */
	nulldev,		/* identify */
	nulldev,		/* probe */
	dmaattach,		/* attach */
	dmadetach,		/* detach */
	nodev,			/* reset */
	&dma_cb_ops,		/* driver operations */
	&dma_bus_ops,		/* bus operations */
	nulldev,		/* power */
	ddi_quiesce_not_supported,	/* devo_quiesce */
};

static struct modldrv modldrv = {
	&mod_driverops,	/* Type of module. This one is a driver */
	"Direct Memory Access driver",	/* Name and version */
	&dma_ops,	/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modldrv, 0
};

static	kmutex_t	dmaautolock;

int
_init(void)
{
	int status;

	mutex_init(&dmaautolock, NULL, MUTEX_DRIVER, NULL);
	status = mod_install(&modlinkage);
	if (status != 0) {
		mutex_destroy(&dmaautolock);
	}
	return (status);
}

int
_fini(void)
{
	int status;

	status = mod_remove(&modlinkage);
	if (status == 0) {
		mutex_destroy(&dmaautolock);
	}
	return (status);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*ARGSUSED1*/
static int
dmaattach(dev_info_t *dev, ddi_attach_cmd_t cmd)
{
	dma_softc_t *dp;

	switch (cmd) {
	case DDI_ATTACH:
		break;

	case DDI_RESUME:
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}

	dp = (dma_softc_t *)kmem_zalloc(sizeof (dma_softc_t), KM_SLEEP);

	/*
	 * map in the device registers
	 */
	if (ddi_map_regs(dev, 0, (caddr_t *)&dp->dma_regs, 0, 0)) {
		cmn_err(CE_WARN, "dma%d: unable to map registers",
		    ddi_get_instance(dev));
		kmem_free(dp, sizeof (dma_softc_t));
		return (DDI_FAILURE);
	}

	ddi_set_driver_private(dev, dp);

	dp->dma_dev = dev;
	mutex_enter(&dmaautolock);
	dp->dma_next = dma_softc;
	dma_softc = dp;
	mutex_exit(&dmaautolock);
	ddi_report_dev(dev);
	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
dmadetach(dev_info_t *devi, ddi_detach_cmd_t cmd)
{
	dma_softc_t *dp, *pdp = NULL;

	switch (cmd) {
	case DDI_SUSPEND:
		return (DDI_SUCCESS);

	case DDI_DETACH:
		mutex_enter(&dmaautolock);
		for (dp = dma_softc; dp; pdp = dp, dp = dp->dma_next) {
			if (dp->dma_dev == devi)
				break;
		}
		ASSERT(dp != NULL);
		if (dp->dma_use) {
			mutex_exit(&dmaautolock);
			return (DDI_FAILURE);
		}
		if (dma_softc == dp) {
			dma_softc = dp->dma_next;
		} else if (dp->dma_next == NULL) {
			pdp->dma_next = NULL;
		} else {
			pdp->dma_next = dp->dma_next;
		}
		mutex_exit(&dmaautolock);
		ddi_unmap_regs(devi, 0, (caddr_t *)(&dp->dma_regs), 0, 0);
		kmem_free(dp, sizeof (dma_softc_t));
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}
}

/*
 * For DMA debugging:
 *
 * #define DMA_ALLOC_DEBUG
 */

#ifdef	DMA_ALLOC_DEBUG
int dma_alloc_debug = 1;
#endif	/* DMA_ALLOC_DEBUG */

struct dmaga *
dma_alloc(dev_info_t *cdev)
{
	dma_softc_t *dp;

	/*
	 * What we need to do is 'find' the dma gate array
	 * 'associated' with the caller.
	 *
	 * We first try to find a dma gate array which is the
	 * parent of the caller.
	 */
	for (dp = dma_softc; dp; dp = dp->dma_next) {
		if (ddi_get_parent(cdev) == dp->dma_dev) {
			dp->dma_use++;
#ifdef	DMA_ALLOC_DEBUG
			if (dma_alloc_debug) {
				cmn_err(CE_CONT,
				    "?dma_alloc %s esp%d -> %s dma%d (dp %x)",
				    ddi_get_name(cdev), ddi_get_instance(cdev),
				    ddi_get_name(dp->dma_dev),
				    ddi_get_instance(dp->dma_dev), dp);
			}
#endif	/* DMA_ALLOC_DEBUG */
			return (dp->dma_regs);
		}
	}

	/*
	 * Next we try to find a dma gate array by checking the
	 * 'reg' property
	 */
	for (dp = dma_softc; dp; dp = dp->dma_next) {
		if (dma_affinity(dp->dma_dev, cdev) == DDI_SUCCESS) {
			dp->dma_use++;
#ifdef	DMA_ALLOC_DEBUG
			if (dma_alloc_debug) {
				cmn_err(CE_CONT,
				    "?dma_alloc %s esp%d -> %s dma%d (dp %x)",
				    ddi_get_name(cdev), ddi_get_instance(cdev),
				    ddi_get_name(dp->dma_dev),
				    ddi_get_instance(dp->dma_dev), dp);
			}
#endif	/* DMA_ALLOC_DEBUG */
			return (dp->dma_regs);
		}
	}

	/*
	 * Next we try to find a dma gate array which claims 'affinity'
	 */
	for (dp = dma_softc; dp; dp = dp->dma_next) {
		if (ddi_dev_affinity(dp->dma_dev, cdev) == DDI_SUCCESS) {
			dp->dma_use++;
#ifdef	DMA_ALLOC_DEBUG
			if (dma_alloc_debug) {
				cmn_err(CE_CONT,
				    "?dma_alloc %s esp%d -> %s dma%d (dp %x)",
				    ddi_get_name(cdev), ddi_get_instance(cdev),
				    ddi_get_name(dp->dma_dev),
				    ddi_get_instance(dp->dma_dev), dp);
			}
#endif	/* DMA_ALLOC_DEBUG */
			return (dp->dma_regs);
		}
	}

#ifdef	DMA_ALLOC_DEBUG
	if (dma_alloc_debug)
		cmn_err(CE_CONT, "?dma_alloc returns 0");
#endif	/* DMA_ALLOC_DEBUG */

	return ((struct dmaga *)0);
}

void
dma_free(struct dmaga *regs)
{
	dma_softc_t *dp;

	/*
	 * We used to lock exclusive access upon the mapped
	 * in registers for the DMA gate array, but this has
	 * not been actually ever needed. If we end up needing
	 * it, then this routine becomes useful for that.
	 *
	 * Barring that, this routine is useful for tracking
	 * who might still be using a dma gate array's registers.
	 *
	 * XXX  We should probably complain if the dma_use count
	 *	goes negative.
	 */
	for (dp = dma_softc; dp; dp = dp->dma_next) {
		if (dp->dma_regs == regs) {
			dp->dma_use--;
			if (dp->dma_use <= 0)
				dp->dma_use = 0;
			break;
		}
	}
}

/*
 * this is a workaround for 1149413. If multiple scsi cards show
 * up in one SBus slot we have a problem. If we can't figure out the
 * correct dma engine by looking at the parent and if we don't have
 * a nexus driver that handles affinity we 'guess' the right dma
 * engine by looking at the 'reg' property of dma engine and scsi
 * card. If they have the right 'distance' we assume we got the
 * right one. This turns out to be only a problem for third party
 * SBus expansion boxes with missing nexus driver and sport8 scsi
 * cards where esp and dma are siblings.
 */

/*
 * 'distance' between esp and dma reg property if esp and dma
 * are siblings in the device tree.
 */
static int restrict_affinity = 1;
static uint_t restrict_affinity_delta = 0x100000;

int
dma_affinity(dev_info_t *dma, dev_info_t *cdev)
{
	uint_t delta;

	if (strcmp(ddi_get_name(cdev), "esp") != 0) {
		return (DDI_FAILURE);
	} else if ((DEVI_PD(dma) && sparc_pd_getnreg(dma) > 0) &&
	    (DEVI_PD(cdev) && sparc_pd_getnreg(cdev) > 0)) {
		uint_t slot = sparc_pd_getreg(dma, 0)->regspec_bustype;
		uint_t slot_b =
		    sparc_pd_getreg(cdev, 0)->regspec_bustype;
		uint_t addr = sparc_pd_getreg(dma, 0)->regspec_addr;
		uint_t addr_b =
		    sparc_pd_getreg(cdev, 0)->regspec_addr;
		if (addr > addr_b) {
			delta = addr - addr_b;
		} else {
			delta = addr_b - addr;
		}
		if ((slot == slot_b) && (!restrict_affinity ||
		    (restrict_affinity_delta == delta)))
			return (DDI_SUCCESS);
	}
	return (DDI_FAILURE);
}
