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
 * Copyright 2012 Garrett D'Amore <garrett@damore.org>.  All rights reserved.
 */


#include <sys/types.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/ddi_impldefs.h>
#include <sys/ddi_subrdefs.h>
#include <sys/pci.h>
#include <sys/pci/pci_nexus.h>
#include <sys/autoconf.h>
#include <sys/cmn_err.h>
#include <sys/errno.h>
#include <sys/kmem.h>
#include <sys/debug.h>
#include <sys/sysmacros.h>
#include <sys/acebus.h>

#ifdef DEBUG
static uint_t acebus_debug_flags = 0;
#endif

/*
 * The values of the following variables are used to initialize
 * the cache line size and latency timer registers in the ebus
 * configuration header.  Variables are used instead of constants
 * to allow tuning from the /etc/system file.
 */
static uint8_t acebus_cache_line_size = 0x10;	/* 64 bytes */
static uint8_t acebus_latency_timer = 0x40;	/* 64 PCI cycles */

/*
 * function prototypes for bus ops routines:
 */
static int
acebus_map(dev_info_t *dip, dev_info_t *rdip, ddi_map_req_t *mp,
	off_t offset, off_t len, caddr_t *addrp);
static int
acebus_ctlops(dev_info_t *dip, dev_info_t *rdip,
	ddi_ctl_enum_t op, void *arg, void *result);
static int
acebus_intr_ops(dev_info_t *dip, dev_info_t *rdip, ddi_intr_op_t intr_op,
    ddi_intr_handle_impl_t *hdlp, void *result);

/*
 * function prototypes for dev ops routines:
 */
static int acebus_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int acebus_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);

/*
 * general function prototypes:
 */
static int acebus_config(ebus_devstate_t *ebus_p);
static int acebus_apply_range(ebus_devstate_t *ebus_p, dev_info_t *rdip,
    ebus_regspec_t *ebus_rp, pci_regspec_t *rp);
static int acebus_get_ranges_prop(ebus_devstate_t *ebus_p);
#ifdef	ACEBUS_HOTPLUG
static int acebus_update_props(ebus_devstate_t *ebus_p);
static int acebus_set_imap(dev_info_t *dip);
#endif

#define	getprop(dip, name, addr, intp)		\
		ddi_getlongprop(DDI_DEV_T_ANY, (dip), DDI_PROP_DONTPASS, \
				(name), (caddr_t)(addr), (intp))

/*
 * bus ops and dev ops structures:
 */
static struct bus_ops acebus_bus_ops = {
	BUSO_REV,
	acebus_map,
	NULL,
	NULL,
	NULL,
	i_ddi_map_fault,
	NULL,
	ddi_dma_allochdl,
	ddi_dma_freehdl,
	ddi_dma_bindhdl,
	ddi_dma_unbindhdl,
	ddi_dma_flush,
	ddi_dma_win,
	ddi_dma_mctl,
	acebus_ctlops,
	ddi_bus_prop_op,
	0,				/* (*bus_get_eventcookie)();	*/
	0,				/* (*bus_add_eventcall)();	*/
	0,				/* (*bus_remove_eventcall)();	*/
	0,				/* (*bus_post_event)();		*/
	0,				/* (*bus_intr_ctl)();		*/
	NULL,				/* (*bus_config)();		*/
	NULL,				/* (*bus_unconfig)();		*/
	NULL,				/* (*bus_fm_init)();		*/
	NULL,				/* (*bus_fm_fini)();		*/
	NULL,				/* (*bus_fm_access_enter)();	*/
	NULL,				/* (*bus_fm_access_fini)();	*/
	NULL,				/* (*bus_power)();		*/
	acebus_intr_ops			/* (*bus_intr_op)();		*/
};

static struct dev_ops acebus_ops = {
	DEVO_REV,
	0,
	ddi_no_info,
	nulldev,
	nulldev,
	acebus_attach,
	acebus_detach,
	nodev,
	(struct cb_ops *)0,
	&acebus_bus_ops,
	NULL,
	ddi_quiesce_not_supported,	/* devo_quiesce */
};

/*
 * module definitions:
 */
#include <sys/modctl.h>
extern struct mod_ops mod_driverops;

static struct modldrv modldrv = {
	&mod_driverops, 	/* Type of module.  This one is a driver */
	"Alarm Card ebus nexus",	/* Name of module. */
	&acebus_ops,		/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modldrv, NULL
};

/*
 * driver global data:
 */
static void *per_acebus_state;		/* per-ebus soft state pointer */


int
_init(void)
{
	int e;

	/*
	 * Initialize per-ebus soft state pointer.
	 */
	e = ddi_soft_state_init(&per_acebus_state, sizeof (ebus_devstate_t), 1);
	if (e != 0)
		return (e);

	/*
	 * Install the module.
	 */
	e = mod_install(&modlinkage);
	if (e != 0)
		ddi_soft_state_fini(&per_acebus_state);
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
	ddi_soft_state_fini(&per_acebus_state);
	return (e);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/* device driver entry points */

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
acebus_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	ebus_devstate_t *ebus_p;	/* per ebus state pointer */
	int instance;

	DBG1(D_ATTACH, NULL, "dip=%x\n", dip);
	switch (cmd) {
	case DDI_ATTACH:

		/*
		 * Allocate soft state for this instance.
		 */
		instance = ddi_get_instance(dip);
		if (ddi_soft_state_zalloc(per_acebus_state, instance)
		    != DDI_SUCCESS) {
			DBG(D_ATTACH, NULL, "failed to alloc soft state\n");
			return (DDI_FAILURE);
		}
		ebus_p = get_acebus_soft_state(instance);
		ebus_p->dip = dip;

		/*
		 * Make sure the master enable and memory access enable
		 * bits are set in the config command register.
		 */
		if (!acebus_config(ebus_p)) {
			free_acebus_soft_state(instance);
			return (DDI_FAILURE);
		}

		(void) ddi_prop_create(DDI_DEV_T_NONE, dip,
		    DDI_PROP_CANSLEEP, "no-dma-interrupt-sync", NULL, 0);
		/* Get our ranges property for mapping child registers. */
		if (acebus_get_ranges_prop(ebus_p) != DDI_SUCCESS) {
			free_acebus_soft_state(instance);
			return (DDI_FAILURE);
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
		ebus_p = get_acebus_soft_state(instance);

		/*
		 * Make sure the master enable and memory access enable
		 * bits are set in the config command register.
		 */
		if (!acebus_config(ebus_p)) {
			free_acebus_soft_state(instance);
			return (DDI_FAILURE);
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
acebus_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int instance = ddi_get_instance(dip);
	ebus_devstate_t *ebus_p = get_acebus_soft_state(instance);

	switch (cmd) {
	case DDI_DETACH:
		DBG1(D_DETACH, ebus_p, "DDI_DETACH dip=%p\n", dip);
		ddi_prop_remove_all(dip);
		kmem_free(ebus_p->rangep, ebus_p->range_cnt *
		    sizeof (struct ebus_pci_rangespec));
		free_acebus_soft_state(instance);
		return (DDI_SUCCESS);

	case DDI_SUSPEND:
		DBG1(D_DETACH, ebus_p, "DDI_SUSPEND dip=%p\n", dip);
		ebus_p->state = SUSPENDED;
		return (DDI_SUCCESS);
	}
	return (DDI_FAILURE);
}


static int
acebus_get_ranges_prop(ebus_devstate_t *ebus_p)
{
	struct ebus_pci_rangespec *rangep;
	int nrange, range_len;

	if (ddi_getlongprop(DDI_DEV_T_ANY, ebus_p->dip, DDI_PROP_DONTPASS,
	    "ranges", (caddr_t)&rangep, &range_len) != DDI_SUCCESS) {

		cmn_err(CE_WARN, "%s%d: can't get ranges property",
		    ddi_get_name(ebus_p->dip), ddi_get_instance(ebus_p->dip));
		return (DDI_ME_REGSPEC_RANGE);
	}

	nrange = range_len / sizeof (struct ebus_pci_rangespec);

	if (nrange == 0)  {
		kmem_free(rangep, range_len);
		return (DDI_FAILURE);
	}

#ifdef	DEBUG
	{
		int i;

		for (i = 0; i < nrange; i++) {
			DBG5(D_MAP, ebus_p,
			    "ebus range addr 0x%x.0x%x PCI range "
			    "addr 0x%x.0x%x.0x%x ", rangep[i].ebus_phys_hi,
			    rangep[i].ebus_phys_low, rangep[i].pci_phys_hi,
			    rangep[i].pci_phys_mid, rangep[i].pci_phys_low);
			DBG1(D_MAP, ebus_p, "Size 0x%x\n", rangep[i].rng_size);
		}
	}
#endif /* DEBUG */

	ebus_p->rangep = rangep;
	ebus_p->range_cnt = nrange;

	return (DDI_SUCCESS);
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
acebus_map(dev_info_t *dip, dev_info_t *rdip, ddi_map_req_t *mp,
	off_t off, off_t len, caddr_t *addrp)
{
	ebus_devstate_t *ebus_p = get_acebus_soft_state(ddi_get_instance(dip));
	ebus_regspec_t *ebus_rp, *ebus_regs;
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
		DBG3(D_MAP, ebus_p, "rdip=%s%d: REGSPEC - handlep=%x\n",
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
		DBG4(D_MAP, ebus_p, "rdip=%s%d: rnumber=%x handlep=%x\n",
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
	rval = acebus_apply_range(ebus_p, rdip, ebus_rp, &pci_reg);

	if (mp->map_type == DDI_MT_RNUMBER)
		kmem_free((caddr_t)ebus_regs, i);

	if (rval != DDI_SUCCESS)
		return (rval);

#ifdef	ACEBUS_HOTPLUG
	/*
	 * The map operation provides a translated (not a re-assigned, or
	 * relocated) ebus address for the child in its address space(range).
	 * Ebus address space is relocatible but its child address space
	 * is not. As specified by their 'reg' properties, they reside
	 * at a fixed offset in their parent's (ebus's) space.
	 *
	 * By setting this bit, we will not run into HostPCI nexus
	 * trying to relocate a translated ebus address (which is already
	 * relocated) and failing the operation.
	 * The reason for doing this here is that the PCI hotplug configurator
	 * always marks the ebus space as relocatible (unlike OBP) and that
	 * information is implied for the child too, which is wrong.
	 */
	pci_reg.pci_phys_hi |= PCI_RELOCAT_B;
#endif
#ifdef DEBUG
	DBG5(D_MAP, ebus_p, "(%x,%x,%x)(%x,%x)\n",
	    pci_reg.pci_phys_hi,
	    pci_reg.pci_phys_mid,
	    pci_reg.pci_phys_low,
	    pci_reg.pci_size_hi,
	    pci_reg.pci_size_low);
#endif

	p_map_request = *mp;
	p_map_request.map_type = DDI_MT_REGSPEC;
	p_map_request.map_obj.rp = (struct regspec *)&pci_reg;
	rval = ddi_map(dip, &p_map_request, 0, 0, addrp);
	DBG1(D_MAP, ebus_p, "parent returned %x\n", rval);
	return (rval);
}


static int
acebus_apply_range(ebus_devstate_t *ebus_p, dev_info_t *rdip,
    ebus_regspec_t *ebus_rp, pci_regspec_t *rp)
{
	int b;
	int rval = DDI_SUCCESS;
	struct ebus_pci_rangespec *rangep = ebus_p->rangep;
	int nrange = ebus_p->range_cnt;
	static const char out_of_range[] =
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
acebus_ctlops(dev_info_t *dip, dev_info_t *rdip,
	ddi_ctl_enum_t op, void *arg, void *result)
{
#ifdef DEBUG
	ebus_devstate_t *ebus_p = get_acebus_soft_state(ddi_get_instance(dip));
#endif
	ebus_regspec_t *ebus_rp;
	int32_t reglen;
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

		if (ddi_getlongprop(DDI_DEV_T_ANY, child, DDI_PROP_DONTPASS,
		    "reg", (caddr_t)&ebus_rp, &reglen) != DDI_SUCCESS) {

			DBG(D_CTLOPS, ebus_p, "can't get reg property\n");
			return (DDI_FAILURE);

		}

		(void) sprintf(name, "%x,%x", ebus_rp->addr_hi,
		    ebus_rp->addr_low);
		ddi_set_name_addr(child, name);
		kmem_free((caddr_t)ebus_rp, reglen);

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
			kmem_free((caddr_t)ebus_rp, i);
			return (DDI_FAILURE);
		}
		*((off_t *)result) = ebus_rp[*(int *)arg].size;
		kmem_free((caddr_t)ebus_rp, i);
		return (DDI_SUCCESS);

	case DDI_CTLOPS_NREGS:

		DBG2(D_CTLOPS, ebus_p, "DDI_CTLOPS_NREGS: rdip=%s%d\n",
		    ddi_get_name(rdip), ddi_get_instance(rdip));
		if (getprop(rdip, "reg", &ebus_rp, &i) != DDI_SUCCESS) {
			DBG(D_CTLOPS, ebus_p, "can't get reg property\n");
			return (DDI_FAILURE);
		}
		*((uint_t *)result) = i / sizeof (ebus_regspec_t);
		kmem_free((caddr_t)ebus_rp, i);
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

static struct ebus_string_to_pil acebus_name_to_pil[] = {{"SUNW,CS4231", 9},
						    {"fdthree", 8},
						    {"ecpp", 3},
						    {"su", 12},
						    {"se", 12},
						    {"power", 14}};

static struct ebus_string_to_pil acebus_device_type_to_pil[] = {{"serial", 12},
								{"block", 8}};

static int
acebus_intr_ops(dev_info_t *dip, dev_info_t *rdip, ddi_intr_op_t intr_op,
    ddi_intr_handle_impl_t *hdlp, void *result)
{
#ifdef DEBUG
	ebus_devstate_t *ebus_p = get_acebus_soft_state(ddi_get_instance(dip));
#endif
	int8_t		*name, *device_type;
	int32_t		i, max_children, max_device_types, len;

	/*
	 * NOTE: These ops below will never be supported in this nexus
	 * driver, hence they always return immediately.
	 */
	switch (intr_op) {
	case DDI_INTROP_GETCAP:
		*(int *)result = DDI_INTR_FLAG_LEVEL;
		return (DDI_SUCCESS);
	case DDI_INTROP_SUPPORTED_TYPES:
		*(int *)result = i_ddi_get_intx_nintrs(rdip) ?
		    DDI_INTR_TYPE_FIXED : 0;
		return (DDI_SUCCESS);
	case DDI_INTROP_SETCAP:
	case DDI_INTROP_SETMASK:
	case DDI_INTROP_CLRMASK:
	case DDI_INTROP_GETPENDING:
		return (DDI_ENOTSUP);
	default:
		break;
	}

	if (hdlp->ih_pri)
		goto done;

	/*
	 * This is a hack to set the PIL for the devices under ebus.
	 * We first look up a device by it's specific name, if we can't
	 * match the name, we try and match it's device_type property.
	 * Lastly we default a PIL level of 1.
	 */
	DBG1(D_INTR, ebus_p, "ebus_p %p\n", ebus_p);

	name = ddi_get_name(rdip);
	max_children = sizeof (acebus_name_to_pil) /
	    sizeof (struct ebus_string_to_pil);

	for (i = 0; i < max_children; i++) {
		if (strcmp(acebus_name_to_pil[i].string, name) == 0) {
			DBG2(D_INTR, ebus_p, "child name %s; match PIL %d\n",
			    acebus_name_to_pil[i].string,
			    acebus_name_to_pil[i].pil);

			hdlp->ih_pri = acebus_name_to_pil[i].pil;
			goto done;
		}
	}

	if (ddi_getlongprop(DDI_DEV_T_ANY, rdip, DDI_PROP_DONTPASS,
	    "device_type", (caddr_t)&device_type, &len) == DDI_SUCCESS) {

		max_device_types = sizeof (acebus_device_type_to_pil) /
		    sizeof (struct ebus_string_to_pil);

		for (i = 0; i < max_device_types; i++) {
			if (strcmp(acebus_device_type_to_pil[i].string,
			    device_type) == 0) {
				DBG2(D_INTR, ebus_p,
				    "Device type %s; match PIL %d\n",
				    acebus_device_type_to_pil[i].string,
				    acebus_device_type_to_pil[i].pil);

				hdlp->ih_pri = acebus_device_type_to_pil[i].pil;
				break;
			}
		}

		kmem_free(device_type, len);
	}

	/*
	 * If we get here, we need to set a default value
	 * for the PIL.
	 */
	if (hdlp->ih_pri == 0) {
		hdlp->ih_pri = 1;
		cmn_err(CE_WARN, "%s%d assigning default interrupt level %d "
		    "for device %s%d", ddi_driver_name(dip),
		    ddi_get_instance(dip), hdlp->ih_pri, ddi_driver_name(rdip),
		    ddi_get_instance(rdip));
	}

done:
	/* Pass up the request to our parent. */
	return (i_ddi_intr_ops(dip, rdip, intr_op, hdlp, result));
}


static int
acebus_config(ebus_devstate_t *ebus_p)
{
	ddi_acc_handle_t conf_handle;
	uint16_t comm;
#ifdef	ACEBUS_HOTPLUG
	int tcr_reg;
	caddr_t csr_io;
	ddi_device_acc_attr_t csr_attr = {   /* CSR map attributes */
		DDI_DEVICE_ATTR_V0,
		DDI_STRUCTURE_LE_ACC,
		DDI_STRICTORDER_ACC
	};
	ddi_acc_handle_t csr_handle;
#endif

	/*
	 * Make sure the master enable and memory access enable
	 * bits are set in the config command register.
	 */
	if (pci_config_setup(ebus_p->dip, &conf_handle) != DDI_SUCCESS)
		return (0);

	comm = pci_config_get16(conf_handle, PCI_CONF_COMM),
#ifdef DEBUG
	    DBG1(D_ATTACH, ebus_p, "command register was 0x%x\n", comm);
#endif
	comm |= (PCI_COMM_ME|PCI_COMM_MAE|PCI_COMM_SERR_ENABLE|
	    PCI_COMM_PARITY_DETECT);
	pci_config_put16(conf_handle, PCI_CONF_COMM, comm),
#ifdef DEBUG
	    DBG1(D_MAP, ebus_p, "command register is now 0x%x\n",
	    pci_config_get16(conf_handle, PCI_CONF_COMM));
#endif
	pci_config_put8(conf_handle, PCI_CONF_CACHE_LINESZ,
	    (uchar_t)acebus_cache_line_size);
	pci_config_put8(conf_handle, PCI_CONF_LATENCY_TIMER,
	    (uchar_t)acebus_latency_timer);
	pci_config_teardown(&conf_handle);

#ifdef	ACEBUS_HOTPLUG
	if (acebus_update_props(ebus_p) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s%d: Could not update special properties.",
		    ddi_driver_name(ebus_p->dip),
		    ddi_get_instance(ebus_p->dip));
		return (0);
	}

	if (ddi_regs_map_setup(ebus_p->dip, CSR_IO_RINDEX,
	    (caddr_t *)&csr_io, 0, CSR_SIZE, &csr_attr,
	    &csr_handle) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s%d: Could not map Ebus CSR.",
		    ddi_driver_name(ebus_p->dip),
		    ddi_get_instance(ebus_p->dip));
	}
#ifdef	DEBUG
	if (acebus_debug_flags) {
		DBG3(D_ATTACH, ebus_p, "tcr[123] = %x,%x,%x\n",
		    ddi_get32(csr_handle, (uint32_t *)((caddr_t)csr_io +
		    TCR1_OFF)),
		    ddi_get32(csr_handle, (uint32_t *)((caddr_t)csr_io +
		    TCR2_OFF)),
		    ddi_get32(csr_handle, (uint32_t *)((caddr_t)csr_io +
		    TCR3_OFF)));
		DBG2(D_ATTACH, ebus_p, "pmd-aux=%x, freq-aux=%x\n",
		    ddi_get32(csr_handle, (uint32_t *)((caddr_t)csr_io +
		    PMD_AUX_OFF)),
		    ddi_get32(csr_handle, (uint32_t *)((caddr_t)csr_io +
		    FREQ_AUX_OFF)));
#ifdef ACEBUS_DEBUG
		for (comm = 0; comm < 4; comm++)
			prom_printf("dcsr%d=%x, dacr%d=%x, dbcr%d=%x\n", comm,
			    ddi_get32(csr_handle, (uint32_t *)((caddr_t)csr_io +
			    0x700000+(0x2000*comm))), comm,
			    ddi_get32(csr_handle, (uint32_t *)((caddr_t)csr_io +
			    0x700000+(0x2000*comm)+4)), comm,
			    ddi_get32(csr_handle, (uint32_t *)((caddr_t)csr_io +
			    0x700000+(0x2000*comm)+8)));
#endif
	} /* acebus_debug_flags */
#endif
	/* If TCR registers are not initialized, initialize them here */
	tcr_reg = ddi_get32(csr_handle, (uint32_t *)((caddr_t)csr_io +
	    TCR1_OFF));
	if ((tcr_reg == 0) || (tcr_reg == -1))
		ddi_put32(csr_handle, (uint32_t *)((caddr_t)csr_io + TCR1_OFF),
		    TCR1_REGVAL);
	tcr_reg = ddi_get32(csr_handle, (uint32_t *)((caddr_t)csr_io +
	    TCR2_OFF));
	if ((tcr_reg == 0) || (tcr_reg == -1))
		ddi_put32(csr_handle, (uint32_t *)((caddr_t)csr_io + TCR2_OFF),
		    TCR2_REGVAL);
	tcr_reg = ddi_get32(csr_handle, (uint32_t *)((caddr_t)csr_io +
	    TCR3_OFF));
	if ((tcr_reg == 0) || (tcr_reg == -1))
		ddi_put32(csr_handle, (uint32_t *)((caddr_t)csr_io + TCR3_OFF),
		    TCR3_REGVAL);
#ifdef	DEBUG
	if (acebus_debug_flags) {
		DBG3(D_ATTACH, ebus_p, "wrote tcr[123] = %x,%x,%x\n",
		    ddi_get32(csr_handle, (uint32_t *)((caddr_t)csr_io +
		    TCR1_OFF)),
		    ddi_get32(csr_handle, (uint32_t *)((caddr_t)csr_io +
		    TCR2_OFF)),
		    ddi_get32(csr_handle, (uint32_t *)((caddr_t)csr_io +
		    TCR3_OFF)));
	}
#endif

	ddi_regs_map_free(&csr_handle);
#endif	/* ACEBUS_HOTPLUG */
	return (1);	/* return success */
}

#ifdef DEBUG
extern void prom_printf(const char *, ...);

static void
acebus_debug(uint_t flag, ebus_devstate_t *ebus_p, char *fmt,
	uintptr_t a1, uintptr_t a2, uintptr_t a3, uintptr_t a4, uintptr_t a5)
{
	char *s;

	if (acebus_debug_flags & flag) {
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

#ifdef	ACEBUS_HOTPLUG
#define	EBUS_CHILD_PHYS_LOW_RANGE	0x10
#define	EBUS_CHILD_PHYS_HI_RANGE	0x14

static int
acebus_update_props(ebus_devstate_t *ebus_p)
{
	dev_info_t *dip = ebus_p->dip;
	struct ebus_pci_rangespec er[2], *erp;
	pci_regspec_t *pci_rp, *prp;
	int length, rnums, imask[3], i, found = 0;

	/*
	 * If "ranges" property is found, then the device is initialized
	 * by OBP, hence simply return.
	 * Otherwise we create all the properties here.
	 */
	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "ranges", (int **)&erp, (uint_t *)&length) == DDI_PROP_SUCCESS) {
		ddi_prop_free(erp);
		return (DDI_SUCCESS);
	}

	/*
	 * interrupt-map is the only property that comes from a .conf file.
	 * Since it doesn't have the nodeid field set, it must be done here.
	 * Other properties can come from OBP or created here.
	 */
	if (acebus_set_imap(dip) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	/*
	 * Create the "ranges" property.
	 * Ebus has BAR0 and BAR1 allocated (both in memory space).
	 * Other BARs are 0.
	 * Hence there are 2 memory ranges it operates in. (one for each BAR).
	 * ie. there are 2 entries in its ranges property.
	 */
	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "assigned-addresses",
	    (int **)&pci_rp, (uint_t *)&length) != DDI_PROP_SUCCESS) {
		cmn_err(CE_WARN, "%s%d: Could not get assigned-addresses",
		    ddi_driver_name(dip), ddi_get_instance(dip));
		return (DDI_FAILURE);
	}
	/*
	 * Create the 1st mem range in which it operates corresponding
	 * to BAR0
	 */
	er[0].ebus_phys_hi = EBUS_CHILD_PHYS_LOW_RANGE;
	rnums = (length * sizeof (int))/sizeof (pci_regspec_t);
	for (i = 0; i < rnums; i++) {
		prp = pci_rp + i;
		if (PCI_REG_REG_G(prp->pci_phys_hi) == er[0].ebus_phys_hi) {
			found = 1;
			break;
		}
	}
	if (!found) {
		cmn_err(CE_WARN, "No assigned space for memory range 0.");
		ddi_prop_free(pci_rp);
		return (DDI_FAILURE);
	}
	found = 0;
	er[0].ebus_phys_low = 0;
	er[0].pci_phys_hi = prp->pci_phys_hi;
	er[0].pci_phys_mid = prp->pci_phys_mid;
	er[0].pci_phys_low = prp->pci_phys_low;
	er[0].rng_size = prp->pci_size_low;

	/*
	 * Create the 2nd mem range in which it operates corresponding
	 * to BAR1
	 */
	er[1].ebus_phys_hi = EBUS_CHILD_PHYS_HI_RANGE;
	for (i = 0; i < rnums; i++) {
		prp = pci_rp + i;
		if (PCI_REG_REG_G(prp->pci_phys_hi) == er[1].ebus_phys_hi) {
			found = 1;
			break;
		}
	}
	if (!found) {
		cmn_err(CE_WARN, "No assigned space for memory range 1.");
		ddi_prop_free(pci_rp);
		return (DDI_FAILURE);
	}
	er[1].ebus_phys_low = 0;
	er[1].pci_phys_hi = prp->pci_phys_hi;
	er[1].pci_phys_mid = prp->pci_phys_mid;
	er[1].pci_phys_low = prp->pci_phys_low;
	er[1].rng_size = prp->pci_size_low;

	ddi_prop_free(pci_rp);
	length = sizeof (er) / sizeof (int);
	if (ddi_prop_update_int_array(DDI_DEV_T_NONE, dip,
	    "ranges", (int *)er, length) != DDI_PROP_SUCCESS) {
		cmn_err(CE_WARN, "%s%d: Could not create ranges property",
		    ddi_driver_name(dip), ddi_get_instance(dip));
		return (DDI_FAILURE);
	}
	/* The following properties are as defined by PCI 1275 bindings. */
	if (ddi_prop_update_int(DDI_DEV_T_NONE, dip,
	    "#address-cells", 2) != DDI_PROP_SUCCESS)
			return (DDI_FAILURE);
	if (ddi_prop_update_int(DDI_DEV_T_NONE, dip,
	    "#size-cells", 1) != DDI_PROP_SUCCESS)
			return (DDI_FAILURE);
	if (ddi_prop_update_int(DDI_DEV_T_NONE, dip,
	    "#interrupt-cells", 1) != DDI_PROP_SUCCESS)
			return (DDI_FAILURE);

	imask[0] = 0x1f;
	imask[1] = 0x00ffffff;
	imask[2] = 0x00000003;
	length = sizeof (imask) / sizeof (int);
	if (ddi_prop_update_int_array(DDI_DEV_T_NONE, dip,
	    "interrupt-map-mask", (int *)imask, length) != DDI_PROP_SUCCESS) {
		cmn_err(CE_WARN, "%s%d: Could not update imap mask property",
		    ddi_driver_name(dip), ddi_get_instance(dip));
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/*
 * This function takes in the ac-interrupt-map property from the .conf file,
 * fills in the 'nodeid' information and then creates the 'interrupt-map'
 * property.
 */
static int
acebus_set_imap(dev_info_t *dip)
{
	int *imapp, *timapp, length, num, i, default_ival = 0;
	dev_info_t *tdip = dip;
	int *port_id, imap_ok = 1;
	int ilength;
	int acebus_default_se_imap[5];

	/*
	 * interrupt-map is specified via .conf file in hotplug mode,
	 * since the child configuration is static.
	 * It could even be hardcoded in the driver.
	 */
	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "ac-interrupt-map", (int **)&imapp, (uint_t *)&ilength) !=
	    DDI_PROP_SUCCESS) {
		/* assume default implementation */
		acebus_default_se_imap[0] = 0x14;
		acebus_default_se_imap[1] = 0x400000;
		acebus_default_se_imap[2] = 1;
		acebus_default_se_imap[3] = 0;
		acebus_default_se_imap[4] = 2;
		imapp = acebus_default_se_imap;
		ilength = 5;
		default_ival = 1;
	}
	num = ilength / 5;	/* there are 5 integer cells in our property */
	timapp = imapp;
	for (i = 0; i < num; i++) {
		if (*(timapp+i*5+3) == 0)
			imap_ok = 0;
	}
	if (imap_ok) {
		if (!default_ival)
			ddi_prop_free(imapp);
		return (DDI_SUCCESS);
	}

	while (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, tdip,
	    DDI_PROP_DONTPASS, "upa-portid", (int **)&port_id,
	    (uint_t *)&length) != DDI_PROP_SUCCESS) {
		tdip = ddi_get_parent(tdip);
		if (tdip == NULL) {
			cmn_err(CE_WARN, "%s%d: Could not get imap parent",
			    ddi_driver_name(dip), ddi_get_instance(dip));
			if (!default_ival)
				ddi_prop_free(imapp);
			return (DDI_FAILURE);
		}
	}
	timapp = imapp;
	for (i = 0; i < num; i++) {
		*(timapp+i*5+3) = ddi_get_nodeid(tdip);
	}

	if (ddi_prop_update_int_array(DDI_DEV_T_NONE, dip,
	    "interrupt-map", imapp, ilength) != DDI_PROP_SUCCESS) {
		cmn_err(CE_WARN, "%s%d: Could not update AC imap property",
		    ddi_driver_name(dip), ddi_get_instance(dip));
		if (!default_ival)
			ddi_prop_free(imapp);
		return (DDI_FAILURE);
	}
	if (!default_ival)
		ddi_prop_free(imapp);
	return (DDI_SUCCESS);
}
#endif	/* ACEBUS_HOTPLUG */
