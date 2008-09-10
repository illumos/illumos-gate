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
 *	ISA bus nexus driver
 */

#include <sys/types.h>
#include <sys/cmn_err.h>
#include <sys/conf.h>
#include <sys/modctl.h>
#include <sys/autoconf.h>
#include <sys/errno.h>
#include <sys/debug.h>
#include <sys/kmem.h>
#include <sys/psm.h>
#include <sys/ddidmareq.h>
#include <sys/ddi_impldefs.h>
#include <sys/dma_engine.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/acpi/acpi_enum.h>
#if defined(__xpv)
#include <sys/hypervisor.h>
#include <sys/evtchn_impl.h>
#endif


extern int isa_resource_setup(void);
static char USED_RESOURCES[] = "used-resources";
static void isa_alloc_nodes(dev_info_t *);
static void enumerate_BIOS_serial(dev_info_t *);

#define	BIOS_DATA_AREA	0x400
/*
 * #define ISA_DEBUG 1
 */

/*
 *      Local data
 */
static ddi_dma_lim_t ISA_dma_limits = {
	0,		/* address low				*/
	0x00ffffff,	/* address high				*/
	0,		/* counter max				*/
	1,		/* burstsize				*/
	DMA_UNIT_8,	/* minimum xfer				*/
	0,		/* dma speed				*/
	(uint_t)DMALIM_VER0, /* version				*/
	0x0000ffff,	/* address register			*/
	0x0000ffff,	/* counter register			*/
	1,		/* sector size				*/
	0x00000001,	/* scatter/gather list length		*/
	(uint_t)0xffffffff /* request size			*/
};

static ddi_dma_attr_t ISA_dma_attr = {
	DMA_ATTR_V0,
	(unsigned long long)0,
	(unsigned long long)0x00ffffff,
	0x0000ffff,
	1,
	1,
	1,
	(unsigned long long)0xffffffff,
	(unsigned long long)0x0000ffff,
	1,
	1,
	0
};


/*
 * Config information
 */

static int
isa_dma_allochdl(dev_info_t *, dev_info_t *, ddi_dma_attr_t *,
    int (*waitfp)(caddr_t), caddr_t arg, ddi_dma_handle_t *);

static int
isa_dma_mctl(dev_info_t *, dev_info_t *, ddi_dma_handle_t, enum ddi_dma_ctlops,
    off_t *, size_t *, caddr_t *, uint_t);

static int
isa_ctlops(dev_info_t *, dev_info_t *, ddi_ctl_enum_t, void *, void *);

struct bus_ops isa_bus_ops = {
	BUSO_REV,
	i_ddi_bus_map,
	NULL,
	NULL,
	NULL,
	i_ddi_map_fault,
	ddi_dma_map,
	isa_dma_allochdl,
	ddi_dma_freehdl,
	ddi_dma_bindhdl,
	ddi_dma_unbindhdl,
	ddi_dma_flush,
	ddi_dma_win,
	isa_dma_mctl,
	isa_ctlops,
	ddi_bus_prop_op,
	NULL,		/* (*bus_get_eventcookie)();	*/
	NULL,		/* (*bus_add_eventcall)();	*/
	NULL,		/* (*bus_remove_eventcall)();	*/
	NULL,		/* (*bus_post_event)();		*/
	NULL,		/* (*bus_intr_ctl)(); */
	NULL,		/* (*bus_config)(); */
	NULL,		/* (*bus_unconfig)(); */
	NULL,		/* (*bus_fm_init)(); */
	NULL,		/* (*bus_fm_fini)(); */
	NULL,		/* (*bus_fm_access_enter)(); */
	NULL,		/* (*bus_fm_access_exit)(); */
	NULL,		/* (*bus_power)(); */
	i_ddi_intr_ops	/* (*bus_intr_op)(); */
};


static int isa_attach(dev_info_t *devi, ddi_attach_cmd_t cmd);

/*
 * Internal isa ctlops support routines
 */
static int isa_initchild(dev_info_t *child);

struct dev_ops isa_ops = {
	DEVO_REV,		/* devo_rev, */
	0,			/* refcnt  */
	ddi_no_info,		/* info */
	nulldev,		/* identify */
	nulldev,		/* probe */
	isa_attach,		/* attach */
	nodev,			/* detach */
	nodev,			/* reset */
	(struct cb_ops *)0,	/* driver operations */
	&isa_bus_ops	/* bus operations */

};

/*
 * Module linkage information for the kernel.
 */

static struct modldrv modldrv = {
	&mod_driverops, /* Type of module.  This is ISA bus driver */
	"isa nexus driver for 'ISA'",
	&isa_ops,	/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&modldrv,
	NULL
};

int
_init(void)
{
	return (mod_install(&modlinkage));
}

int
_fini(void)
{
	return (mod_remove(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

static int
isa_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	int rval;

#if defined(__xpv)
	/*
	 * don't allow isa to attach in domU. this can happen if someone sets
	 * the console wrong, etc. ISA devices assume the H/W is there and
	 * will cause the domU to panic.
	 */
	if (!DOMAIN_IS_INITDOMAIN(xen_info)) {
		return (DDI_FAILURE);
	}
#endif

	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);

	if ((rval = i_dmae_init(devi)) == DDI_SUCCESS) {
		ddi_report_dev(devi);
		/*
		 * Enumerate children -- invoking ACPICA
		 * This is normally in bus_config(), but we need this
		 * to happen earlier to boot.
		 */
		isa_alloc_nodes(devi);
	}
	return (rval);
}

static int
isa_dma_allochdl(dev_info_t *dip, dev_info_t *rdip, ddi_dma_attr_t *dma_attr,
    int (*waitfp)(caddr_t), caddr_t arg, ddi_dma_handle_t *handlep)
{
	ddi_dma_attr_merge(dma_attr, &ISA_dma_attr);
	return (ddi_dma_allochdl(dip, rdip, dma_attr, waitfp, arg, handlep));
}

static int
isa_dma_mctl(dev_info_t *dip, dev_info_t *rdip,
    ddi_dma_handle_t handle, enum ddi_dma_ctlops request,
    off_t *offp, size_t *lenp, caddr_t *objp, uint_t flags)
{
	int rval;
	ddi_dma_lim_t defalt;
	int arg = (int)(uintptr_t)objp;

	switch (request) {

	case DDI_DMA_E_PROG:
		return (i_dmae_prog(rdip, (struct ddi_dmae_req *)offp,
		    (ddi_dma_cookie_t *)lenp, arg));

	case DDI_DMA_E_ACQUIRE:
		return (i_dmae_acquire(rdip, arg, (int(*)(caddr_t))offp,
		    (caddr_t)lenp));

	case DDI_DMA_E_FREE:
		return (i_dmae_free(rdip, arg));

	case DDI_DMA_E_STOP:
		i_dmae_stop(rdip, arg);
		return (DDI_SUCCESS);

	case DDI_DMA_E_ENABLE:
		i_dmae_enable(rdip, arg);
		return (DDI_SUCCESS);

	case DDI_DMA_E_DISABLE:
		i_dmae_disable(rdip, arg);
		return (DDI_SUCCESS);

	case DDI_DMA_E_GETCNT:
		i_dmae_get_chan_stat(rdip, arg, NULL, (int *)lenp);
		return (DDI_SUCCESS);

	case DDI_DMA_E_SWSETUP:
		return (i_dmae_swsetup(rdip, (struct ddi_dmae_req *)offp,
		    (ddi_dma_cookie_t *)lenp, arg));

	case DDI_DMA_E_SWSTART:
		i_dmae_swstart(rdip, arg);
		return (DDI_SUCCESS);

	case DDI_DMA_E_GETLIM:
		bcopy(&ISA_dma_limits, objp, sizeof (ddi_dma_lim_t));
		return (DDI_SUCCESS);

	case DDI_DMA_E_GETATTR:
		bcopy(&ISA_dma_attr, objp, sizeof (ddi_dma_attr_t));
		return (DDI_SUCCESS);

	case DDI_DMA_E_1STPTY:
		{
			struct ddi_dmae_req req1stpty =
			    { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
			if (arg == 0) {
				req1stpty.der_command = DMAE_CMD_TRAN;
				req1stpty.der_trans = DMAE_TRANS_DMND;
			} else {
				req1stpty.der_trans = DMAE_TRANS_CSCD;
			}
			return (i_dmae_prog(rdip, &req1stpty, NULL, arg));
		}

	case DDI_DMA_IOPB_ALLOC:	/* get contiguous DMA-able memory */
	case DDI_DMA_SMEM_ALLOC:
		if (!offp) {
			defalt = ISA_dma_limits;
			offp = (off_t *)&defalt;
		}
		/*FALLTHROUGH*/
	default:
		rval = ddi_dma_mctl(dip, rdip, handle, request, offp,
		    lenp, objp, flags);
	}
	return (rval);
}

/*
 * Check if driver should be treated as an old pre 2.6 driver
 */
static int
old_driver(dev_info_t *dip)
{
	extern int ignore_hardware_nodes;	/* force flag from ddi_impl.c */

	if (ndi_dev_is_persistent_node(dip)) {
		if (ignore_hardware_nodes)
			return (1);
		if (ddi_getprop(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
		    "ignore-hardware-nodes", -1) != -1)
			return (1);
	}
	return (0);
}

typedef struct {
	uint32_t phys_hi;
	uint32_t phys_lo;
	uint32_t size;
} isa_regs_t;

/*
 * Return non-zero if device in tree is a PnP isa device
 */
static int
is_pnpisa(dev_info_t *dip)
{
	isa_regs_t *isa_regs;
	int proplen, pnpisa;

	if (ndi_dev_is_persistent_node(dip) == 0)
		return (0);
	if (ddi_getlongprop(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS, "reg",
	    (caddr_t)&isa_regs, &proplen) != DDI_PROP_SUCCESS) {
		return (0);
	}
	pnpisa = isa_regs[0].phys_hi & 0x80000000;
	/*
	 * free the memory allocated by ddi_getlongprop().
	 */
	kmem_free(isa_regs, proplen);
	if (pnpisa)
		return (1);
	else
		return (0);
}

/*ARGSUSED*/
static int
isa_ctlops(dev_info_t *dip, dev_info_t *rdip,
	ddi_ctl_enum_t ctlop, void *arg, void *result)
{
	switch (ctlop) {
	case DDI_CTLOPS_REPORTDEV:
		if (rdip == (dev_info_t *)0)
			return (DDI_FAILURE);
		cmn_err(CE_CONT, "?ISA-device: %s%d\n",
		    ddi_driver_name(rdip), ddi_get_instance(rdip));
		return (DDI_SUCCESS);

	case DDI_CTLOPS_INITCHILD:
		/*
		 * older drivers aren't expecting the "standard" device
		 * node format used by the hardware nodes.  these drivers
		 * only expect their own properties set in their driver.conf
		 * files.  so they tell us not to call them with hardware
		 * nodes by setting the property "ignore-hardware-nodes".
		 */
		if (old_driver((dev_info_t *)arg)) {
			return (DDI_NOT_WELL_FORMED);
		}

		return (isa_initchild((dev_info_t *)arg));

	case DDI_CTLOPS_UNINITCHILD:
		impl_ddi_sunbus_removechild((dev_info_t *)arg);
		return (DDI_SUCCESS);

	case DDI_CTLOPS_SIDDEV:
		/*
		 * All ISA devices need to do confirming probes
		 * unless they are PnP ISA.
		 */
		if (is_pnpisa(dip))
			return (DDI_SUCCESS);
		else
			return (DDI_FAILURE);

	default:
		return (ddi_ctlops(dip, rdip, ctlop, arg, result));
	}
}

static void
isa_vendor(uint32_t id, char *vendor)
{
	vendor[0] = '@' + ((id >> 26) & 0x1f);
	vendor[1] = '@' + ((id >> 21) & 0x1f);
	vendor[2] = '@' + ((id >> 16) & 0x1f);
	vendor[3] = 0;
}

/*
 * Name a child
 */
static int
isa_name_child(dev_info_t *child, char *name, int namelen)
{
	char vendor[8];
	int device;
	uint32_t serial;
	int func;
	int bustype;
	uint32_t base;
	int proplen;
	int pnpisa = 0;
	isa_regs_t *isa_regs;

	void make_ddi_ppd(dev_info_t *, struct ddi_parent_private_data **);

	/*
	 * older drivers aren't expecting the "standard" device
	 * node format used by the hardware nodes.  these drivers
	 * only expect their own properties set in their driver.conf
	 * files.  so they tell us not to call them with hardware
	 * nodes by setting the property "ignore-hardware-nodes".
	 */
	if (old_driver(child))
		return (DDI_FAILURE);

	/*
	 * Fill in parent-private data
	 */
	if (ddi_get_parent_data(child) == NULL) {
		struct ddi_parent_private_data *pdptr;
		make_ddi_ppd(child, &pdptr);
		ddi_set_parent_data(child, pdptr);
	}

	if (ndi_dev_is_persistent_node(child) == 0) {
		/*
		 * For .conf nodes, generate name from parent private data
		 */
		name[0] = '\0';
		if (sparc_pd_getnreg(child) > 0) {
			(void) snprintf(name, namelen, "%x,%x",
			    (uint_t)sparc_pd_getreg(child, 0)->regspec_bustype,
			    (uint_t)sparc_pd_getreg(child, 0)->regspec_addr);
		}
		return (DDI_SUCCESS);
	}

	/*
	 * For hw nodes, look up "reg" property
	 */
	if (ddi_getlongprop(DDI_DEV_T_ANY, child, DDI_PROP_DONTPASS, "reg",
	    (caddr_t)&isa_regs, &proplen) != DDI_PROP_SUCCESS) {
		return (DDI_FAILURE);
	}

	/*
	 * extract the device identifications
	 */
	pnpisa = isa_regs[0].phys_hi & 0x80000000;
	if (pnpisa) {
		isa_vendor(isa_regs[0].phys_hi, vendor);
		device = isa_regs[0].phys_hi & 0xffff;
		serial = isa_regs[0].phys_lo;
		func = (isa_regs[0].size >> 24) & 0xff;
		if (func != 0)
			(void) snprintf(name, namelen, "pnp%s,%04x,%x,%x",
			    vendor, device, serial, func);
		else
			(void) snprintf(name, namelen, "pnp%s,%04x,%x",
			    vendor, device, serial);
	} else {
		bustype = isa_regs[0].phys_hi;
		base = isa_regs[0].phys_lo;
		(void) sprintf(name, "%x,%x", bustype, base);
	}

	/*
	 * free the memory allocated by ddi_getlongprop().
	 */
	kmem_free(isa_regs, proplen);

	return (DDI_SUCCESS);
}

static int
isa_initchild(dev_info_t *child)
{
	char name[80];

	if (isa_name_child(child, name, 80) != DDI_SUCCESS)
		return (DDI_FAILURE);
	ddi_set_name_addr(child, name);

	if (ndi_dev_is_persistent_node(child) != 0)
		return (DDI_SUCCESS);

	/*
	 * This is a .conf node, try merge properties onto a
	 * hw node with the same name.
	 */
	if (ndi_merge_node(child, isa_name_child) == DDI_SUCCESS) {
		/*
		 * Return failure to remove node
		 */
		impl_ddi_sunbus_removechild(child);
		return (DDI_FAILURE);
	}
	/*
	 * Cannot merge node, permit pseudo children
	 */
	return (DDI_SUCCESS);
}

/*
 * called when ACPI enumeration is not used
 */
static void
add_known_used_resources(void)
{
	/* needs to be in increasing order */
	int intr[] = {0x1, 0x3, 0x4, 0x6, 0x7, 0xc};
	int dma[] = {0x2};
	int io[] = {0x60, 0x1, 0x64, 0x1, 0x2f8, 0x8, 0x378, 0x8, 0x3f0, 0x10,
	    0x778, 0x4};
	dev_info_t *usedrdip;

	usedrdip = ddi_find_devinfo(USED_RESOURCES, -1, 0);

	if (usedrdip == NULL) {
		(void) ndi_devi_alloc_sleep(ddi_root_node(), USED_RESOURCES,
		    (pnode_t)DEVI_SID_NODEID, &usedrdip);
	}

	(void) ndi_prop_update_int_array(DDI_DEV_T_NONE, usedrdip,
	    "interrupts", (int *)intr, (int)(sizeof (intr) / sizeof (int)));
	(void) ndi_prop_update_int_array(DDI_DEV_T_NONE, usedrdip,
	    "io-space", (int *)io, (int)(sizeof (io) / sizeof (int)));
	(void) ndi_prop_update_int_array(DDI_DEV_T_NONE, usedrdip,
	    "dma-channels", (int *)dma, (int)(sizeof (dma) / sizeof (int)));
	(void) ndi_devi_bind_driver(usedrdip, 0);

}

static void
isa_alloc_nodes(dev_info_t *isa_dip)
{
	static int alloced = 0;
	int circ, i;
	dev_info_t *xdip;

	/* hard coded isa stuff */
	struct regspec asy_regs[] = {
		{1, 0x3f8, 0x8},
		{1, 0x2f8, 0x8}
	};
	int asy_intrs[] = {0x4, 0x3};

	struct regspec i8042_regs[] = {
		{1, 0x60, 0x1},
		{1, 0x64, 0x1}
	};
	int i8042_intrs[] = {0x1, 0xc};
	char *acpi_prop;
	int acpi_enum = 1; /* ACPI is default to be on */

	if (alloced)
		return;

	ndi_devi_enter(isa_dip, &circ);
	if (alloced) {	/* just in case we are multi-threaded */
		ndi_devi_exit(isa_dip, circ);
		return;
	}
	alloced = 1;

	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, ddi_root_node(),
	    DDI_PROP_DONTPASS, "acpi-enum", &acpi_prop) == DDI_PROP_SUCCESS) {
		acpi_enum = strcmp("off", acpi_prop);
		ddi_prop_free(acpi_prop);
	}

	if (acpi_enum) {
		if (acpi_isa_device_enum(isa_dip)) {
			ndi_devi_exit(isa_dip, circ);
			if (isa_resource_setup() != NDI_SUCCESS) {
				cmn_err(CE_WARN, "isa nexus: isa "
				    "resource setup failed");
			}

			/* serial ports? */
			enumerate_BIOS_serial(isa_dip);
			return;
		}
		cmn_err(CE_NOTE, "!Solaris did not detect ACPI BIOS");
	}
	cmn_err(CE_NOTE, "!ACPI is off");

	/* serial ports */
	for (i = 0; i < 2; i++) {
#if defined(__xpv)
		/*
		 * the hypervisor may be reserving the serial ports for console
		 * and/or debug use.  Probe the irqs to see if they are
		 * available.
		 */
		if (ec_probe_pirq(asy_intrs[i]) == 0)
			continue; /* in use */
#endif
		ndi_devi_alloc_sleep(isa_dip, "asy",
		    (pnode_t)DEVI_SID_NODEID, &xdip);
		(void) ndi_prop_update_int_array(DDI_DEV_T_NONE, xdip,
		    "reg", (int *)&asy_regs[i], 3);
		(void) ndi_prop_update_int(DDI_DEV_T_NONE, xdip,
		    "interrupts", asy_intrs[i]);
		(void) ndi_devi_bind_driver(xdip, 0);
	}

	/* i8042 node */
	ndi_devi_alloc_sleep(isa_dip, "i8042",
	    (pnode_t)DEVI_SID_NODEID, &xdip);
	(void) ndi_prop_update_int_array(DDI_DEV_T_NONE, xdip,
	    "reg", (int *)i8042_regs, 6);
	(void) ndi_prop_update_int_array(DDI_DEV_T_NONE, xdip,
	    "interrupts", (int *)i8042_intrs, 2);
	(void) ndi_prop_update_string(DDI_DEV_T_NONE, xdip,
	    "unit-address", "1,60");
	(void) ndi_devi_bind_driver(xdip, 0);

	add_known_used_resources();

	ndi_devi_exit(isa_dip, circ);

}

/*
 * On some machines, serial port 2 isn't listed in the ACPI table.
 * This function goes through the BIOS data area and makes sure all
 * the serial ports there are in the dev_info tree.  If any are missing,
 * this function will add them.
 */

static int num_BIOS_serial = 2;	/* number of BIOS serial ports to look at */

static void
enumerate_BIOS_serial(dev_info_t *isa_dip)
{
	ushort_t *bios_data;
	int i;
	dev_info_t *xdip;
	int found;
	int ret;
	struct regspec *tmpregs;
	int tmpregs_len;
	static struct regspec tmp_asy_regs[] = {
		{1, 0x3f8, 0x8},
	};
	static int default_asy_intrs[] = { 4, 3, 4, 3 };
	static size_t size = 4;

	/*
	 * The first four 2-byte quantities of the BIOS data area contain
	 * the base I/O addresses of the first four serial ports.
	 */
	bios_data = (ushort_t *)psm_map_new((paddr_t)BIOS_DATA_AREA, size,
	    PSM_PROT_READ);
	for (i = 0; i < num_BIOS_serial; i++) {
		if (bios_data[i] == 0) {
			/* no COM[i]: port */
			continue;
		}

		/* Look for it in the dev_info tree */
		found = 0;
		for (xdip = ddi_get_child(isa_dip); xdip != NULL;
		    xdip = ddi_get_next_sibling(xdip)) {
			if (strncmp(ddi_node_name(xdip), "asy", 3) != 0) {
				/* skip non asy */
				continue;
			}

			/* Match by addr */
			ret = ddi_prop_lookup_int_array(DDI_DEV_T_ANY, xdip,
			    DDI_PROP_DONTPASS, "reg", (int **)&tmpregs,
			    (uint_t *)&tmpregs_len);
			if (ret != DDI_PROP_SUCCESS) {
				/* error */
				continue;
			}

			if (tmpregs->regspec_addr == bios_data[i])
				found = 1;
			/*
			 * Free the memory allocated by
			 * ddi_prop_lookup_int_array().
			 */
			ddi_prop_free(tmpregs);

		}

		/* If not found, then add it */
		if (!found) {
			ndi_devi_alloc_sleep(isa_dip, "asy",
			    (pnode_t)DEVI_SID_NODEID, &xdip);
			(void) ndi_prop_update_string(DDI_DEV_T_NONE, xdip,
			    "compatible", "PNP0500");
			/* This should be gotten from master file: */
			(void) ndi_prop_update_string(DDI_DEV_T_NONE, xdip,
			    "model", "Standard PC COM port");
			tmp_asy_regs[0].regspec_addr = bios_data[i];
			(void) ndi_prop_update_int_array(DDI_DEV_T_NONE, xdip,
			    "reg", (int *)&tmp_asy_regs[0], 3);
			(void) ndi_prop_update_int(DDI_DEV_T_NONE, xdip,
			    "interrupts", default_asy_intrs[i]);
			(void) ndi_devi_bind_driver(xdip, 0);
		}
	}
#if defined(__xpv)
	/*
	 * Check each serial port to see if it is in use by the hypervisor.
	 * If it is in use, then remove the node from the device tree.
	 */
	i = 0;
	for (xdip = ddi_get_child(isa_dip); xdip != NULL; ) {
		int asy_intr;
		dev_info_t *curdip;

		curdip = xdip;
		xdip = ddi_get_next_sibling(xdip);
		if (strncmp(ddi_node_name(curdip), "asy", 3) != 0) {
			/* skip non asy */
			continue;
		}
		/*
		 * Check if the hypervisor is using the serial port by probing
		 * the irq and if it is using it remove the node
		 * from the device tree
		 */
		asy_intr = ddi_prop_get_int(DDI_DEV_T_ANY, curdip,
		    DDI_PROP_DONTPASS, "interrupts", -1);
		if (asy_intr == -1) {
			/* error */
			continue;
		}

		if (ec_probe_pirq(asy_intr)) {
			continue;
		}
		ret = ndi_devi_free(curdip);
		if (ret != DDI_SUCCESS)
			cmn_err(CE_WARN,
			    "could not remove asy%d node", i);
		else
			cmn_err(CE_NOTE, "!asy%d unavailable, reserved"
			    " to hypervisor", i);
		i++;
	}
#endif	/* __xpv */

	psm_unmap((caddr_t)bios_data, size);
}
