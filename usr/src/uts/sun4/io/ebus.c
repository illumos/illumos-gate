/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/ddi_impldefs.h>
#include <sys/ddi_subrdefs.h>
#include <sys/pci.h>
#include <sys/autoconf.h>
#include <sys/cmn_err.h>
#include <sys/errno.h>
#include <sys/kmem.h>
#include <sys/debug.h>
#include <sys/sysmacros.h>
#include <sys/ebus.h>
#include <sys/open.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/sunndi.h>

#ifdef DEBUG
uint64_t ebus_debug_flags = 0;
#endif

/*
 * The values of the following variables are used to initialize
 * the cache line size and latency timer registers in the ebus
 * configuration header.  Variables are used instead of constants
 * to allow tuning from the /etc/system file.
 */
static uint8_t ebus_cache_line_size = 0x10;	/* 64 bytes */
static uint8_t ebus_latency_timer = 0x40;	/* 64 PCI cycles */

/*
 * function prototypes for bus ops routines:
 */
static int
ebus_map(dev_info_t *dip, dev_info_t *rdip, ddi_map_req_t *mp,
	off_t offset, off_t len, caddr_t *addrp);
static int
ebus_ctlops(dev_info_t *dip, dev_info_t *rdip,
	ddi_ctl_enum_t op, void *arg, void *result);
static int
ebus_intr_ops(dev_info_t *dip, dev_info_t *rdip, ddi_intr_op_t intr_op,
    ddi_intr_handle_impl_t *hdlp, void *result);

/*
 * function prototypes for dev ops routines:
 */
static int ebus_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int ebus_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);
static int ebus_info(dev_info_t *dip, ddi_info_cmd_t infocmd,
	void *arg, void **result);

/*
 * general function prototypes:
 */
static int ebus_config(ebus_devstate_t *ebus_p);
static int ebus_apply_range(ebus_devstate_t *ebus_p, dev_info_t *rdip,
    ebus_regspec_t *ebus_rp, pci_regspec_t *rp);
static int febus_apply_range(ebus_devstate_t *ebus_p, dev_info_t *rdip,
    ebus_regspec_t *ebus_rp, struct regspec *rp);
int get_ranges_prop(ebus_devstate_t *ebus_p);

#define	getprop(dip, name, addr, intp)		\
		ddi_getlongprop(DDI_DEV_T_NONE, (dip), DDI_PROP_DONTPASS, \
				(name), (caddr_t)(addr), (intp))

static int ebus_open(dev_t *devp, int flags, int otyp, cred_t *credp);
static int ebus_close(dev_t dev, int flags, int otyp, cred_t *credp);
static int ebus_ioctl(dev_t dev, int cmd, intptr_t arg, int mode,
						cred_t *credp, int *rvalp);
struct cb_ops ebus_cb_ops = {
	ebus_open,			/* open */
	ebus_close,			/* close */
	nodev,				/* strategy */
	nodev,				/* print */
	nodev,				/* dump */
	nodev,				/* read */
	nodev,				/* write */
	ebus_ioctl,			/* ioctl */
	nodev,				/* devmap */
	nodev,				/* mmap */
	nodev,				/* segmap */
	nochpoll,			/* poll */
	ddi_prop_op,			/* cb_prop_op */
	NULL,				/* streamtab */
	D_NEW | D_MP | D_HOTPLUG,	/* Driver compatibility flag */
	CB_REV,				/* rev */
	nodev,				/* int (*cb_aread)() */
	nodev				/* int (*cb_awrite)() */
};

/*
 * bus ops and dev ops structures:
 */
static struct bus_ops ebus_bus_ops = {
	BUSO_REV,
	ebus_map,
	NULL,
	NULL,
	NULL,
	i_ddi_map_fault,
	ddi_dma_map,
	ddi_dma_allochdl,
	ddi_dma_freehdl,
	ddi_dma_bindhdl,
	ddi_dma_unbindhdl,
	ddi_dma_flush,
	ddi_dma_win,
	ddi_dma_mctl,
	ebus_ctlops,
	ddi_bus_prop_op,
	ndi_busop_get_eventcookie,
	ndi_busop_add_eventcall,
	ndi_busop_remove_eventcall,
	ndi_post_event,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	ebus_intr_ops
};

static struct dev_ops ebus_ops = {
	DEVO_REV,
	0,
	ebus_info,
	nulldev,
	nulldev,
	ebus_attach,
	ebus_detach,
	nodev,
	&ebus_cb_ops,
	&ebus_bus_ops
};

/*
 * module definitions:
 */
#include <sys/modctl.h>
extern struct mod_ops mod_driverops;

static struct modldrv modldrv = {
	&mod_driverops, 	/* Type of module.  This one is a driver */
	"ebus nexus driver %I%", /* Name of module. */
	&ebus_ops,		/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modldrv, NULL
};

/*
 * driver global data:
 */
static void *per_ebus_state;		/* per-ebus soft state pointer */


int
_init(void)
{
	int e;

	/*
	 * Initialize per-ebus soft state pointer.
	 */
	e = ddi_soft_state_init(&per_ebus_state, sizeof (ebus_devstate_t), 1);
	if (e != 0)
		return (e);

	/*
	 * Install the module.
	 */
	e = mod_install(&modlinkage);
	if (e != 0)
		ddi_soft_state_fini(&per_ebus_state);
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
	 * Free the soft state info.
	 */
	ddi_soft_state_fini(&per_ebus_state);
	return (e);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/* device driver entry points */

/*ARGSUSED*/
static int
ebus_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	ebus_devstate_t *ebus_p;	/* per ebus state pointer */
	int instance;

	instance = getminor((dev_t)arg);
	ebus_p = get_ebus_soft_state(instance);

	switch (infocmd) {
	default:
		return (DDI_FAILURE);

	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)instance;
		return (DDI_SUCCESS);

	case DDI_INFO_DEVT2DEVINFO:
		if (ebus_p == NULL)
			return (DDI_FAILURE);
		*result = (void *)ebus_p->dip;
		return (DDI_SUCCESS);
	}
}

/*
 * attach entry point:
 *
 * normal attach:
 *
 *	create soft state structure (dip, reg, nreg and state fields)
 *	map in configuration header
 *	make sure device is properly configured
 *	report device
 */
static int
ebus_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	ebus_devstate_t *ebus_p;	/* per ebus state pointer */
	int instance;

	DBG1(D_ATTACH, NULL, "dip=%p\n", dip);

	switch (cmd) {
	case DDI_ATTACH:

		/*
		 * Allocate soft state for this instance.
		 */
		instance = ddi_get_instance(dip);
		if (ddi_soft_state_zalloc(per_ebus_state, instance)
				!= DDI_SUCCESS) {
			DBG(D_ATTACH, NULL, "failed to alloc soft state\n");
			return (DDI_FAILURE);
		}
		ebus_p = get_ebus_soft_state(instance);
		ebus_p->dip = dip;
		mutex_init(&ebus_p->ebus_mutex, NULL, MUTEX_DRIVER, NULL);
		ebus_p->ebus_soft_state = EBUS_SOFT_STATE_CLOSED;

		/* Set ebus type field based on ddi name info */
		if (strcmp(ddi_get_name(dip), "jbus-ebus") == 0) {
			ebus_p->type = FEBUS_TYPE;
		} else {
			ebus_p->type = EBUS_TYPE;
		}

		(void) ddi_prop_create(DDI_DEV_T_NONE, dip,
			DDI_PROP_CANSLEEP, "no-dma-interrupt-sync", NULL, 0);
		/* Get our ranges property for mapping child registers. */
		if (get_ranges_prop(ebus_p) != DDI_SUCCESS) {
			mutex_destroy(&ebus_p->ebus_mutex);
			free_ebus_soft_state(instance);
			return (DDI_FAILURE);
		}

		/*
		 * create minor node for devctl interfaces
		 */
		if (ddi_create_minor_node(dip, "devctl", S_IFCHR, instance,
		    DDI_NT_NEXUS, 0) != DDI_SUCCESS) {
			mutex_destroy(&ebus_p->ebus_mutex);
			free_ebus_soft_state(instance);
			return (DDI_FAILURE);
		}
		/*
		 * Make sure the master enable and memory access enable
		 * bits are set in the config command register.
		 */
		if (ebus_p->type == EBUS_TYPE) {
			if (!ebus_config(ebus_p)) {
				ddi_remove_minor_node(dip, "devctl");
				mutex_destroy(&ebus_p->ebus_mutex);
				free_ebus_soft_state(instance);
				return (DDI_FAILURE);
			}
		}

		/*
		 * Make the pci_report_pmcap() call only for RIO
		 * implementations.
		 */
		if (IS_RIO(dip)) {
			(void) pci_report_pmcap(dip, PCI_PM_IDLESPEED,
			    (void *)EBUS_4MHZ);
		}

		/*
		 * Make the state as attached and report the device.
		 */
		ebus_p->state = ATTACHED;
		ddi_report_dev(dip);
		DBG(D_ATTACH, ebus_p, "returning\n");

		return (DDI_SUCCESS);

	case DDI_RESUME:

		instance = ddi_get_instance(dip);
		ebus_p = get_ebus_soft_state(instance);

		/*
		 * Make sure the master enable and memory access enable
		 * bits are set in the config command register.
		 */
		if (ebus_p->type == EBUS_TYPE) {
			if (!ebus_config(ebus_p)) {
				free_ebus_soft_state(instance);
				return (DDI_FAILURE);
			}
		}

		ebus_p->state = RESUMED;
		return (DDI_SUCCESS);
	}
	return (DDI_FAILURE);
}

/*
 * detach entry point:
 */
static int
ebus_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int instance = ddi_get_instance(dip);
	ebus_devstate_t *ebus_p = get_ebus_soft_state(instance);

	switch (cmd) {
	case DDI_DETACH:
		DBG1(D_DETACH, ebus_p, "DDI_DETACH dip=%p\n", dip);

		switch (ebus_p->type) {
		case EBUS_TYPE:
			kmem_free(ebus_p->rangespec.rangep, ebus_p->range_cnt *
				sizeof (struct ebus_pci_rangespec));
			break;
		case FEBUS_TYPE:
			kmem_free(ebus_p->rangespec.ferangep,
				ebus_p->range_cnt *
				sizeof (struct febus_rangespec));
			break;
		default:
			DBG(D_ATTACH, NULL, "failed to recognize ebus type\n");
			return (DDI_FAILURE);
		}

		ddi_remove_minor_node(dip, "devctl");
		mutex_destroy(&ebus_p->ebus_mutex);
		free_ebus_soft_state(instance);
		return (DDI_SUCCESS);

	case DDI_SUSPEND:
		DBG1(D_DETACH, ebus_p, "DDI_SUSPEND dip=%p\n", dip);
		ebus_p->state = SUSPENDED;
		return (DDI_SUCCESS);
	}
	DBG(D_ATTACH, NULL, "failed to recognize ebus detach command\n");
	return (DDI_FAILURE);
}


int
get_ranges_prop(ebus_devstate_t *ebus_p)
{
	int nrange, range_len;
	struct ebus_pci_rangespec *rangep;
	struct febus_rangespec *ferangep;

	switch (ebus_p->type) {
	case EBUS_TYPE:
		if (ddi_getlongprop(DDI_DEV_T_ANY,
			ebus_p->dip, DDI_PROP_DONTPASS,
			"ranges", (caddr_t)&rangep,
			&range_len) != DDI_SUCCESS) {
				cmn_err(CE_WARN, "Can't get %s ranges property",
					ddi_get_name(ebus_p->dip));
				return (DDI_ME_REGSPEC_RANGE);
		}

		nrange = range_len / sizeof (struct ebus_pci_rangespec);

		if (nrange == 0)  {
			kmem_free(rangep, range_len);
			DBG(D_ATTACH, NULL, "range is equal to zero\n");
			return (DDI_FAILURE);
		}

#ifdef DEBUG
		{
			int i;

			for (i = 0; i < nrange; i++) {
				DBG5(D_MAP, ebus_p,
					"ebus range addr 0x%x.0x%x PCI range "
					"addr 0x%x.0x%x.0x%x ",
					rangep[i].ebus_phys_hi,
					rangep[i].ebus_phys_low,
					rangep[i].pci_phys_hi,
					rangep[i].pci_phys_mid,
					rangep[i].pci_phys_low);
				DBG1(D_MAP, ebus_p,
					"Size 0x%x\n", rangep[i].rng_size);
			}
		}
#endif /* DEBUG */

		ebus_p->rangespec.rangep = rangep;
		ebus_p->range_cnt = nrange;
		return (DDI_SUCCESS);

	case FEBUS_TYPE:
		if (ddi_getlongprop(DDI_DEV_T_ANY, ebus_p->dip,
			DDI_PROP_DONTPASS, "ranges",
			(caddr_t)&ferangep, &range_len) != DDI_SUCCESS) {
			cmn_err(CE_WARN, "Can't get %s ranges property",
				ddi_get_name(ebus_p->dip));
				return (DDI_ME_REGSPEC_RANGE);
		}

		nrange = range_len / sizeof (struct febus_rangespec);

		if (nrange == 0)  {
			kmem_free(ferangep, range_len);
			return (DDI_FAILURE);
		}

#ifdef	DEBUG
		{
			int i;

			for (i = 0; i < nrange; i++) {
				DBG4(D_MAP, ebus_p,
					"ebus range addr 0x%x.0x%x"
					" Parent range "
					"addr 0x%x.0x%x ",
					ferangep[i].febus_phys_hi,
					ferangep[i].febus_phys_low,
					ferangep[i].parent_phys_hi,
					ferangep[i].parent_phys_low);
				DBG1(D_MAP, ebus_p, "Size 0x%x\n",
					ferangep[i].rng_size);
			}
		}
#endif /* DEBUG */
		ebus_p->rangespec.ferangep = ferangep;
		ebus_p->range_cnt = nrange;
		return (DDI_SUCCESS);

	default:
		DBG(D_MAP, NULL, "failed to recognize ebus type\n");
		return (DDI_FAILURE);
	}
}

/* bus driver entry points */

/*
 * bus map entry point:
 *
 * 	if map request is for an rnumber
 *		get the corresponding regspec from device node
 * 	build a new regspec in our parent's format
 *	build a new map_req with the new regspec
 *	call up the tree to complete the mapping
 */
static int
ebus_map(dev_info_t *dip, dev_info_t *rdip, ddi_map_req_t *mp,
	off_t off, off_t len, caddr_t *addrp)
{
	ebus_devstate_t *ebus_p = get_ebus_soft_state(ddi_get_instance(dip));
	ebus_regspec_t *ebus_rp, *ebus_regs;
	struct regspec reg;
	pci_regspec_t pci_reg;
	ddi_map_req_t p_map_request;
	int rnumber, i, n;
	int rval = DDI_SUCCESS;

	/*
	 * Handle the mapping according to its type.
	 */
	DBG4(D_MAP, ebus_p, "rdip=%s%d: off=%x len=%x\n",
	    ddi_get_name(rdip), ddi_get_instance(rdip), off, len);
	switch (mp->map_type) {
	case DDI_MT_REGSPEC:

		/*
		 * We assume the register specification is in ebus format.
		 * We must convert it into a PCI format regspec and pass
		 * the request to our parent.
		 */
		DBG3(D_MAP, ebus_p, "rdip=%s%d: REGSPEC - handlep=%p\n",
			ddi_get_name(rdip), ddi_get_instance(rdip),
			mp->map_handlep);
		ebus_rp = (ebus_regspec_t *)mp->map_obj.rp;
		break;

	case DDI_MT_RNUMBER:

		/*
		 * Get the "reg" property from the device node and convert
		 * it to our parent's format.
		 */
		rnumber = mp->map_obj.rnumber;
		DBG4(D_MAP, ebus_p, "rdip=%s%d: rnumber=%x handlep=%p\n",
			ddi_get_name(rdip), ddi_get_instance(rdip),
			rnumber, mp->map_handlep);

		if (getprop(rdip, "reg", &ebus_regs, &i) != DDI_SUCCESS) {
			DBG(D_MAP, ebus_p, "can't get reg property\n");
			return (DDI_ME_RNUMBER_RANGE);
		}
		n = i / sizeof (ebus_regspec_t);

		if (rnumber < 0 || rnumber >= n) {
			DBG(D_MAP, ebus_p, "rnumber out of range\n");
			return (DDI_ME_RNUMBER_RANGE);
		}
		ebus_rp = &ebus_regs[rnumber];
		break;

	default:
		return (DDI_ME_INVAL);

	}

	/* Adjust our reg property with offset and length */
	ebus_rp->addr_low += off;
	if (len)
		ebus_rp->size = len;

	/*
	 * Now we have a copy the "reg" entry we're attempting to map.
	 * Translate this into our parents PCI address using the ranges
	 * property.
	 */
	switch (ebus_p->type) {
	case EBUS_TYPE:
		rval = ebus_apply_range(ebus_p, rdip, ebus_rp, &pci_reg);
		break;
	case FEBUS_TYPE:
		rval = febus_apply_range(ebus_p, rdip, ebus_rp, &reg);
		break;
	default:
		DBG(D_MAP, NULL, "failed to recognize ebus type\n");
		rval = DDI_FAILURE;
	}

	if (mp->map_type == DDI_MT_RNUMBER)
		kmem_free(ebus_regs, i);

	if (rval != DDI_SUCCESS)
		return (rval);

#ifdef DEBUG
	switch (ebus_p->type) {
	case EBUS_TYPE:
		DBG5(D_MAP, ebus_p, "(%x,%x,%x)(%x,%x)\n",
			pci_reg.pci_phys_hi,
			pci_reg.pci_phys_mid,
			pci_reg.pci_phys_low,
			pci_reg.pci_size_hi,
			pci_reg.pci_size_low);
		break;

	case FEBUS_TYPE:
		DBG3(D_MAP, ebus_p, "%x,%x,%x\n",
			reg.regspec_bustype,
			reg.regspec_addr,
			reg.regspec_size);
		break;
	}
#endif

	p_map_request = *mp;
	p_map_request.map_type = DDI_MT_REGSPEC;

	switch (ebus_p->type) {
	case EBUS_TYPE:
		p_map_request.map_obj.rp = (struct regspec *)&pci_reg;
		break;
	case FEBUS_TYPE:
		p_map_request.map_obj.rp = &reg;
		break;
	default:
		DBG(D_MAP, NULL, "failed to recognize ebus type\n");
		return (DDI_FAILURE);
	}

	rval = ddi_map(dip, &p_map_request, 0, 0, addrp);
	DBG1(D_MAP, ebus_p, "parent returned %x\n", rval);
	return (rval);
}


static int
ebus_apply_range(ebus_devstate_t *ebus_p, dev_info_t *rdip,
    ebus_regspec_t *ebus_rp, pci_regspec_t *rp)
{
	int b;
	int rval = DDI_SUCCESS;
	struct ebus_pci_rangespec *rangep = ebus_p->rangespec.rangep;
	int nrange = ebus_p->range_cnt;
	static char out_of_range[] =
	    "Out of range register specification from device node <%s>";

	DBG3(D_MAP, ebus_p, "Range Matching Addr 0x%x.%x size 0x%x\n",
	    ebus_rp->addr_hi, ebus_rp->addr_low, ebus_rp->size);

	for (b = 0; b < nrange; ++b, ++rangep) {

		/* Check for the correct space */
		if (ebus_rp->addr_hi == rangep->ebus_phys_hi)
			/* See if we fit in this range */
			if ((ebus_rp->addr_low >=
			    rangep->ebus_phys_low) &&
			    ((ebus_rp->addr_low + ebus_rp->size - 1)
				<= (rangep->ebus_phys_low +
				    rangep->rng_size - 1))) {
				uint_t addr_offset = ebus_rp->addr_low -
				    rangep->ebus_phys_low;
				/*
				 * Use the range entry to translate
				 * the EBUS physical address into the
				 * parents PCI space.
				 */
				rp->pci_phys_hi =
				rangep->pci_phys_hi;
				rp->pci_phys_mid = rangep->pci_phys_mid;
				rp->pci_phys_low =
					rangep->pci_phys_low + addr_offset;
				rp->pci_size_hi = 0;
				rp->pci_size_low =
					min(ebus_rp->size, (rangep->rng_size -
					addr_offset));

				DBG2(D_MAP, ebus_p, "Child hi0x%x lo0x%x ",
					rangep->ebus_phys_hi,
					rangep->ebus_phys_low);
				DBG4(D_MAP, ebus_p, "Parent hi0x%x "
					"mid0x%x lo0x%x size 0x%x\n",
					rangep->pci_phys_hi,
					rangep->pci_phys_mid,
					rangep->pci_phys_low,
					rangep->rng_size);

				break;
			}
	}

	if (b == nrange)  {
		cmn_err(CE_WARN, out_of_range, ddi_get_name(rdip));
		return (DDI_ME_REGSPEC_RANGE);
	}

	return (rval);
}

static int
febus_apply_range(ebus_devstate_t *ebus_p, dev_info_t *rdip,
		ebus_regspec_t *ebus_rp, struct regspec *rp) {
	int b;
	int rval = DDI_SUCCESS;
	struct febus_rangespec *rangep = ebus_p->rangespec.ferangep;
	int nrange = ebus_p->range_cnt;
	static char out_of_range[] =
		"Out of range register specification from device node <%s>";

	DBG3(D_MAP, ebus_p, "Range Matching Addr 0x%x.%x size 0x%x\n",
	ebus_rp->addr_hi, ebus_rp->addr_low, ebus_rp->size);

	for (b = 0; b < nrange; ++b, ++rangep) {
		/* Check for the correct space */
		if (ebus_rp->addr_hi == rangep->febus_phys_hi)
			/* See if we fit in this range */
			if ((ebus_rp->addr_low >=
				rangep->febus_phys_low) &&
				((ebus_rp->addr_low + ebus_rp->size - 1)
				<= (rangep->febus_phys_low +
				rangep->rng_size - 1))) {
					uint_t addr_offset = ebus_rp->addr_low -
					rangep->febus_phys_low;

				/*
				 * Use the range entry to translate
				 * the FEBUS physical address into the
				 * parents space.
				 */
				rp->regspec_bustype =
					rangep->parent_phys_hi;
				rp->regspec_addr =
				rangep->parent_phys_low + addr_offset;
				rp->regspec_size =
					min(ebus_rp->size, (rangep->rng_size -
					addr_offset));

				DBG2(D_MAP, ebus_p, "Child hi0x%x lo0x%x ",
					rangep->febus_phys_hi,
					rangep->febus_phys_low);
				DBG3(D_MAP, ebus_p, "Parent hi0x%x "
					"lo0x%x size 0x%x\n",
					rangep->parent_phys_hi,
					rangep->parent_phys_low,
					rangep->rng_size);

				break;
			}
	}

	if (b == nrange)  {
		cmn_err(CE_WARN, out_of_range, ddi_get_name(rdip));
		return (DDI_ME_REGSPEC_RANGE);
	}

	return (rval);
}


static int
ebus_name_child(dev_info_t *child, char *name, int namelen)
{
	ebus_regspec_t *ebus_rp;
	int reglen;

	/*
	 * Get the address portion of the node name based on the
	 * address/offset.
	 */
	if (ddi_getlongprop(DDI_DEV_T_NONE, child, DDI_PROP_DONTPASS,
	    "reg", (caddr_t)&ebus_rp, &reglen) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	(void) snprintf(name, namelen, "%x,%x", ebus_rp->addr_hi,
	    ebus_rp->addr_low);
	kmem_free(ebus_rp, reglen);

	return (DDI_SUCCESS);
}

/*
 * control ops entry point:
 *
 * Requests handled completely:
 *	DDI_CTLOPS_INITCHILD
 *	DDI_CTLOPS_UNINITCHILD
 *	DDI_CTLOPS_REPORTDEV
 *	DDI_CTLOPS_REGSIZE
 *	DDI_CTLOPS_NREGS
 *
 * All others passed to parent.
 */
static int
ebus_ctlops(dev_info_t *dip, dev_info_t *rdip,
	ddi_ctl_enum_t op, void *arg, void *result)
{
#ifdef DEBUG
	ebus_devstate_t *ebus_p = get_ebus_soft_state(ddi_get_instance(dip));
#endif
	ebus_regspec_t *ebus_rp;
	int i, n;
	char name[10];

	switch (op) {
	case DDI_CTLOPS_INITCHILD: {
		dev_info_t *child = (dev_info_t *)arg;
		/*
		 * Set the address portion of the node name based on the
		 * address/offset.
		 */
		DBG2(D_CTLOPS, ebus_p, "DDI_CTLOPS_INITCHILD: rdip=%s%d\n",
		    ddi_get_name(child), ddi_get_instance(child));

		if (ebus_name_child(child, name, 10) != DDI_SUCCESS) {
			DBG(D_CTLOPS, ebus_p, "can't name child\n");
			return (DDI_FAILURE);
		}

		ddi_set_name_addr(child, name);
		ddi_set_parent_data(child, NULL);
		return (DDI_SUCCESS);
	}

	case DDI_CTLOPS_UNINITCHILD:
		DBG2(D_CTLOPS, ebus_p, "DDI_CTLOPS_UNINITCHILD: rdip=%s%d\n",
			ddi_get_name((dev_info_t *)arg),
			ddi_get_instance((dev_info_t *)arg));
		ddi_set_name_addr((dev_info_t *)arg, NULL);
		ddi_remove_minor_node((dev_info_t *)arg, NULL);
		impl_rem_dev_props((dev_info_t *)arg);
		return (DDI_SUCCESS);

	case DDI_CTLOPS_REPORTDEV:

		DBG2(D_CTLOPS, ebus_p, "DDI_CTLOPS_REPORTDEV: rdip=%s%d\n",
			ddi_get_name(rdip), ddi_get_instance(rdip));
		cmn_err(CE_CONT, "?%s%d at %s%d: offset %s\n",
			ddi_driver_name(rdip), ddi_get_instance(rdip),
			ddi_driver_name(dip), ddi_get_instance(dip),
			ddi_get_name_addr(rdip));
		return (DDI_SUCCESS);

	case DDI_CTLOPS_REGSIZE:

		DBG2(D_CTLOPS, ebus_p, "DDI_CTLOPS_REGSIZE: rdip=%s%d\n",
			ddi_get_name(rdip), ddi_get_instance(rdip));
		if (getprop(rdip, "reg", &ebus_rp, &i) != DDI_SUCCESS) {
			DBG(D_CTLOPS, ebus_p, "can't get reg property\n");
			return (DDI_FAILURE);
		}
		n = i / sizeof (ebus_regspec_t);
		if (*(int *)arg < 0 || *(int *)arg >= n) {
			DBG(D_MAP, ebus_p, "rnumber out of range\n");
			kmem_free(ebus_rp, i);
			return (DDI_FAILURE);
		}
		*((off_t *)result) = ebus_rp[*(int *)arg].size;
		kmem_free(ebus_rp, i);
		return (DDI_SUCCESS);

	case DDI_CTLOPS_NREGS:

		DBG2(D_CTLOPS, ebus_p, "DDI_CTLOPS_NREGS: rdip=%s%d\n",
			ddi_get_name(rdip), ddi_get_instance(rdip));
		if (getprop(rdip, "reg", &ebus_rp, &i) != DDI_SUCCESS) {
			DBG(D_CTLOPS, ebus_p, "can't get reg property\n");
			return (DDI_FAILURE);
		}
		*((uint_t *)result) = i / sizeof (ebus_regspec_t);
		kmem_free(ebus_rp, i);
		return (DDI_SUCCESS);
	}

	/*
	 * Now pass the request up to our parent.
	 */
	DBG2(D_CTLOPS, ebus_p, "passing request to parent: rdip=%s%d\n",
		ddi_get_name(rdip), ddi_get_instance(rdip));
	return (ddi_ctlops(dip, rdip, op, arg, result));
}

struct ebus_string_to_pil {
	int8_t *string;
	uint32_t pil;
};

static struct ebus_string_to_pil ebus_name_to_pil[] = {{"SUNW,CS4231", 9},
							{"audio", 9},
							{"fdthree", 8},
							{"floppy", 8},
							{"ecpp", 3},
							{"parallel", 3},
							{"su", 12},
							{"se", 12},
							{"serial", 12},
							{"power", 14}};

static struct ebus_string_to_pil ebus_device_type_to_pil[] = {{"serial", 12},
								{"block", 8}};

static int
ebus_intr_ops(dev_info_t *dip, dev_info_t *rdip, ddi_intr_op_t intr_op,
    ddi_intr_handle_impl_t *hdlp, void *result)
{
#ifdef DEBUG
	ebus_devstate_t *ebus_p = get_ebus_soft_state(ddi_get_instance(dip));
#endif
	ddi_ispec_t		*ip = (ddi_ispec_t *)hdlp->ih_private;
	int32_t			i, max_children, max_device_types, len;
	char			*name_p, *device_type_p;

	DBG1(D_INTR, ebus_p, "ip 0x%p\n", ip);

	/*
	 * NOTE: These ops below will never be supported in this nexus
	 * driver, hence they always return immediately.
	 */
	switch (intr_op) {
	case DDI_INTROP_GETCAP:
		*(int *)result = 0;
		return (DDI_SUCCESS);
	case DDI_INTROP_SETCAP:
	case DDI_INTROP_SETMASK:
	case DDI_INTROP_CLRMASK:
	case DDI_INTROP_GETPENDING:
		return (DDI_ENOTSUP);
	default:
		break;
	}

	if ((intr_op == DDI_INTROP_SUPPORTED_TYPES) || ip->is_pil)
		goto done;

	/*
	 * This is a hack to set the PIL for the devices under ebus.
	 * We first look up a device by it's specific name, if we can't
	 * match the name, we try and match it's device_type property.
	 * Lastly we default a PIL level of 1.
	 */
	name_p = ddi_node_name(rdip);
	max_children = sizeof (ebus_name_to_pil) /
	    sizeof (struct ebus_string_to_pil);

	for (i = 0; i < max_children; i++) {
		if (strcmp(ebus_name_to_pil[i].string, name_p) == 0) {
			DBG2(D_INTR, ebus_p, "child name %s; match PIL %d\n",
			    ebus_name_to_pil[i].string,
			    ebus_name_to_pil[i].pil);

			ip->is_pil = ebus_name_to_pil[i].pil;
			goto done;
		}
	}

	if (ddi_getlongprop(DDI_DEV_T_NONE, rdip, DDI_PROP_DONTPASS,
	    "device_type", (caddr_t)&device_type_p, &len) == DDI_SUCCESS) {

		max_device_types = sizeof (ebus_device_type_to_pil) /
		    sizeof (struct ebus_string_to_pil);

		for (i = 0; i < max_device_types; i++) {
			if (strcmp(ebus_device_type_to_pil[i].string,
			    device_type_p) == 0) {
				DBG2(D_INTR, ebus_p, "Device type %s; match "
				    "PIL %d\n", ebus_device_type_to_pil[i].
				    string, ebus_device_type_to_pil[i].pil);

				ip->is_pil = ebus_device_type_to_pil[i].pil;
				break;
			}
		}

		kmem_free(device_type_p, len);
	}

	/*
	 * If we get here, we need to set a default value
	 * for the PIL.
	 */
	if (ip->is_pil == 0) {
		ip->is_pil = 1;

		cmn_err(CE_WARN, "%s%d assigning default interrupt level %d "
		    "for device %s%d", ddi_get_name(dip), ddi_get_instance(dip),
		    ip->is_pil, ddi_get_name(rdip), ddi_get_instance(rdip));
	}

done:
	/* Pass up the request to our parent. */
	return (i_ddi_intr_ops(dip, rdip, intr_op, hdlp, result));
}


static int
ebus_config(ebus_devstate_t *ebus_p)
{
	ddi_acc_handle_t conf_handle;
	uint16_t comm;

	/*
	 * Make sure the master enable and memory access enable
	 * bits are set in the config command register.
	 */
	if (pci_config_setup(ebus_p->dip, &conf_handle) != DDI_SUCCESS)
		return (0);

	comm = pci_config_get16(conf_handle, PCI_CONF_COMM),
#ifdef DEBUG
	    DBG1(D_MAP, ebus_p, "command register was 0x%x\n", comm);
#endif
	comm |= (PCI_COMM_ME|PCI_COMM_MAE|PCI_COMM_SERR_ENABLE|
	    PCI_COMM_PARITY_DETECT);
	pci_config_put16(conf_handle, PCI_CONF_COMM, comm),
#ifdef DEBUG
	    DBG1(D_MAP, ebus_p, "command register is now 0x%x\n", comm);
#endif
	pci_config_put8(conf_handle, PCI_CONF_CACHE_LINESZ,
	    (uchar_t)ebus_cache_line_size);
	pci_config_put8(conf_handle, PCI_CONF_LATENCY_TIMER,
	    (uchar_t)ebus_latency_timer);
	pci_config_teardown(&conf_handle);
	return (1);
}

#ifdef DEBUG
extern void prom_printf(const char *, ...);

static void
ebus_debug(uint_t flag, ebus_devstate_t *ebus_p, char *fmt,
	uintptr_t a1, uintptr_t a2, uintptr_t a3, uintptr_t a4, uintptr_t a5)
{
	char *s;

	if (ebus_debug_flags & flag) {
		switch (flag) {
		case D_ATTACH:
			s = "attach"; break;
		case D_DETACH:
			s = "detach"; break;
		case D_MAP:
			s = "map"; break;
		case D_CTLOPS:
			s = "ctlops"; break;
		case D_INTR:
			s = "intr"; break;
		}
		if (ebus_p)
			cmn_err(CE_CONT, "%s%d: %s: ",
				ddi_get_name(ebus_p->dip),
				ddi_get_instance(ebus_p->dip), s);
		else
			cmn_err(CE_CONT, "ebus: ");
		cmn_err(CE_CONT, fmt, a1, a2, a3, a4, a5);
	}
}
#endif

/* ARGSUSED3 */
static int
ebus_open(dev_t *devp, int flags, int otyp, cred_t *credp)
{
	ebus_devstate_t *ebus_p;

	/*
	 * Make sure the open is for the right file type.
	 */
	if (otyp != OTYP_CHR)
		return (EINVAL);

	/*
	 * Get the soft state structure for the device.
	 */
	ebus_p = get_ebus_soft_state(getminor(*devp));
	if (ebus_p == NULL)
		return (ENXIO);

	/*
	 * Handle the open by tracking the device state.
	 */
	mutex_enter(&ebus_p->ebus_mutex);
	if (flags & FEXCL) {
		if (ebus_p->ebus_soft_state != EBUS_SOFT_STATE_CLOSED) {
			mutex_exit(&ebus_p->ebus_mutex);
			return (EBUSY);
		}
		ebus_p->ebus_soft_state = EBUS_SOFT_STATE_OPEN_EXCL;
	} else {
		if (ebus_p->ebus_soft_state == EBUS_SOFT_STATE_OPEN_EXCL) {
			mutex_exit(&ebus_p->ebus_mutex);
			return (EBUSY);
		}
		ebus_p->ebus_soft_state = EBUS_SOFT_STATE_OPEN;
	}
	mutex_exit(&ebus_p->ebus_mutex);
	return (0);
}


/* ARGSUSED */
static int
ebus_close(dev_t dev, int flags, int otyp, cred_t *credp)
{
	ebus_devstate_t *ebus_p;

	if (otyp != OTYP_CHR)
		return (EINVAL);

	ebus_p = get_ebus_soft_state(getminor(dev));
	if (ebus_p == NULL)
		return (ENXIO);

	mutex_enter(&ebus_p->ebus_mutex);
	ebus_p->ebus_soft_state = EBUS_SOFT_STATE_CLOSED;
	mutex_exit(&ebus_p->ebus_mutex);
	return (0);
}


/*
 * ebus_ioctl: devctl hotplug controls
 */
/* ARGSUSED */
static int
ebus_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
	int *rvalp)
{
	ebus_devstate_t *ebus_p;
	dev_info_t *self;
	struct devctl_iocdata *dcp;
	uint_t bus_state;
	int rv = 0;

	ebus_p = get_ebus_soft_state(getminor(dev));
	if (ebus_p == NULL)
		return (ENXIO);

	self = ebus_p->dip;

	/*
	 * We can use the generic implementation for these ioctls
	 */
	switch (cmd) {
	case DEVCTL_DEVICE_GETSTATE:
	case DEVCTL_DEVICE_ONLINE:
	case DEVCTL_DEVICE_OFFLINE:
	case DEVCTL_BUS_GETSTATE:
		return (ndi_devctl_ioctl(self, cmd, arg, mode, 0));
	}

	/*
	 * read devctl ioctl data
	 */
	if (ndi_dc_allochdl((void *)arg, &dcp) != NDI_SUCCESS)
		return (EFAULT);

	switch (cmd) {

	case DEVCTL_DEVICE_RESET:
		rv = ENOTSUP;
		break;

	case DEVCTL_BUS_QUIESCE:
		if (ndi_get_bus_state(self, &bus_state) == NDI_SUCCESS)
			if (bus_state == BUS_QUIESCED)
				break;
		(void) ndi_set_bus_state(self, BUS_QUIESCED);
		break;

	case DEVCTL_BUS_UNQUIESCE:
		if (ndi_get_bus_state(self, &bus_state) == NDI_SUCCESS)
			if (bus_state == BUS_ACTIVE)
				break;
		(void) ndi_set_bus_state(self, BUS_ACTIVE);
		break;

	case DEVCTL_BUS_RESET:
		rv = ENOTSUP;
		break;

	case DEVCTL_BUS_RESETALL:
		rv = ENOTSUP;
		break;

	default:
		rv = ENOTTY;
	}

	ndi_dc_freehdl(dcp);
	return (rv);
}
