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
#include <sys/autoconf.h>
#include <sys/cmn_err.h>
#include <sys/errno.h>
#include <sys/kmem.h>
#include <sys/debug.h>
#include <sys/sysmacros.h>
#include <sys/pmubus.h>

#include <sys/nexusdebug.h>
/* Bitfield debugging definitions for this file */
#define	PMUBUS_MAP_DEBUG	0x1
#define	PMUBUS_REGACCESS_DEBUG	0x2
#define	PMUBUS_RW_DEBUG		0x4

/*
 * The pmubus nexus is used to manage a shared register space.  Rather
 * than having several driver's physically alias register mappings and
 * have potential problems with register collisions, this nexus will
 * serialize the access to this space.
 *
 * There are two types of sharing going on here:
 * 1) Registers within the address space may be shared, however the registers
 * themselves are unique.  The upper bit of the child's high address being zero
 * signifies this register type.
 *
 * 2) The second type of register is one where a device may only own a few
 * bits in the register.  I'll term this as "bit lane" access.  This is a more
 * complicated scenario.  The drivers themselves are responsible for knowing
 * which bit lanes in the register they own.  The read of a register only
 * guarantees that those bits the driver is interested in are valid.  If a
 * driver needs to set bits in a register, a read must be done first to
 * identify the state of the drivers bits.  Depending on which way a bit needs
 * to be driven, the driver will write a 1 to the bit to toggle it.  If a bit
 * is to remain unchanged, a 0 is written to the bit.  So the access to the
 * bit lane is an xor operation.
 */
/*
 * Function prototypes for busops routines:
 */
static int pmubus_map(dev_info_t *dip, dev_info_t *rdip, ddi_map_req_t *mp,
    off_t off, off_t len, caddr_t *addrp);
static int pmubus_ctlops(dev_info_t *dip, dev_info_t *rdip,
    ddi_ctl_enum_t op, void *arg, void *result);

/*
 * function prototypes for dev ops routines:
 */
static int pmubus_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int pmubus_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);

/*
 * general function prototypes:
 */

/*
 * bus ops and dev ops structures:
 */
static struct bus_ops pmubus_bus_ops = {
	BUSO_REV,
	pmubus_map,
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
	pmubus_ctlops,
	ddi_bus_prop_op,
	0,			/* (*bus_get_eventcookie)();	*/
	0,			/* (*bus_add_eventcall)();	*/
	0,			/* (*bus_remove_eventcall)();	*/
	0,			/* (*bus_post_event)();		*/
	0,			/* interrupt control		*/
	0,			/* bus_config			*/
	0,			/* bus_unconfig			*/
	0,			/* bus_fm_init			*/
	0,			/* bus_fm_fini			*/
	0,			/* bus_fm_access_enter		*/
	0,			/* bus_fm_access_exit		*/
	0,			/* bus_power			*/
	i_ddi_intr_ops		/* bus_intr_op			*/
};

static struct dev_ops pmubus_ops = {
	DEVO_REV,
	0,
	ddi_no_info,
	nulldev,
	0,
	pmubus_attach,
	pmubus_detach,
	nodev,
	(struct cb_ops *)0,
	&pmubus_bus_ops,
	NULL,
	ddi_quiesce_not_needed,		/* quiesce */
};

/*
 * module definitions:
 */
#include <sys/modctl.h>
extern struct mod_ops mod_driverops;

static struct modldrv modldrv = {
	&mod_driverops, 	/* Type of module.  This one is a driver */
	"pmubus nexus driver",	/* Name of module. */
	&pmubus_ops,		/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modldrv, NULL
};

/*
 * driver global data:
 */
static void *per_pmubus_state;		/* per-pmubus soft state pointer */

int
_init(void)
{
	int e;

	/*
	 * Initialize per-pmubus soft state pointer.
	 */
	e = ddi_soft_state_init(&per_pmubus_state,
	    sizeof (pmubus_devstate_t), 1);
	if (e != 0)
		return (e);

	/*
	 * Install the module.
	 */
	e = mod_install(&modlinkage);
	if (e != 0)
		ddi_soft_state_fini(&per_pmubus_state);

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
	ddi_soft_state_fini(&per_pmubus_state);
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
pmubus_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	pmubus_devstate_t *pmubusp;	/* per pmubus state pointer */
	int32_t instance;

	switch (cmd) {
	case DDI_ATTACH:
		/*
		 * Allocate soft state for this instance.
		 */
		instance = ddi_get_instance(dip);
		if (ddi_soft_state_zalloc(per_pmubus_state, instance) !=
		    DDI_SUCCESS) {
			cmn_err(CE_WARN, "pmubus_attach: Can't allocate soft "
			    "state.\n");
			goto fail_exit;
		}

		pmubusp = ddi_get_soft_state(per_pmubus_state, instance);
		pmubusp->pmubus_dip = dip;

		/* Cache our register property */
		if (ddi_getlongprop(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
		    "reg", (caddr_t)&pmubusp->pmubus_regp,
		    &pmubusp->pmubus_reglen) != DDI_SUCCESS) {
			cmn_err(CE_WARN, "pmubus_attach: Can't acquire reg "
			    "property.\n");
			goto fail_get_regs;
		}

		/* Cache our ranges property */
		if (ddi_getlongprop(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
		    "ranges", (caddr_t)&pmubusp->pmubus_rangep,
		    &pmubusp->pmubus_rnglen) != DDI_SUCCESS) {
			cmn_err(CE_WARN, "pmubus_attach: Can't acquire the "
			    "ranges property.\n");
			goto fail_get_ranges;

		}

		/* Calculate the number of ranges */
		pmubusp->pmubus_nranges =
		    pmubusp->pmubus_rnglen / sizeof (pmu_rangespec_t);

		/* Set up the mapping to our registers */
		if (pci_config_setup(dip, &pmubusp->pmubus_reghdl) !=
		    DDI_SUCCESS) {
			cmn_err(CE_WARN, "pmubus_attach: Can't map in "
			    "register space.\n");
			goto fail_map_regs;
		}

		/* Initialize our register access mutex */
		mutex_init(&pmubusp->pmubus_reg_access_lock, NULL,
		    MUTEX_DRIVER, NULL);

		ddi_report_dev(dip);
		return (DDI_SUCCESS);

	case DDI_RESUME:
		return (DDI_SUCCESS);
	}

fail_map_regs:
	kmem_free(pmubusp->pmubus_rangep, pmubusp->pmubus_rnglen);

fail_get_ranges:
	kmem_free(pmubusp->pmubus_regp, pmubusp->pmubus_reglen);

fail_get_regs:
	ddi_soft_state_free(per_pmubus_state, instance);

fail_exit:
	return (DDI_FAILURE);
}

/*
 * detach entry point:
 */
static int
pmubus_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int instance = ddi_get_instance(dip);
	pmubus_devstate_t *pmubusp = ddi_get_soft_state(per_pmubus_state,
	    instance);

	switch (cmd) {
	case DDI_DETACH:
		mutex_destroy(&pmubusp->pmubus_reg_access_lock);

		/* Tear down our register mappings */
		pci_config_teardown(&pmubusp->pmubus_reghdl);

		/* Free our ranges property */
		kmem_free(pmubusp->pmubus_rangep, pmubusp->pmubus_rnglen);

		/* Free the register property */
		kmem_free(pmubusp->pmubus_regp, pmubusp->pmubus_reglen);

		ddi_soft_state_free(per_pmubus_state, instance);
		break;

	case DDI_SUSPEND:
	default:
		break;
	}

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
void
pmubus_norep_get8(ddi_acc_impl_t *handle, uint8_t *host_addr,
    uint8_t *dev_addr, size_t repcount, uint_t flags)
{
}

/*ARGSUSED*/
void
pmubus_norep_get16(ddi_acc_impl_t *handle, uint16_t *host_addr,
    uint16_t *dev_addr, size_t repcount, uint_t flags)
{
}

/*ARGSUSED*/
void
pmubus_norep_get32(ddi_acc_impl_t *handle, uint32_t *host_addr,
    uint32_t *dev_addr, size_t repcount, uint_t flags)
{
}

/*ARGSUSED*/
void
pmubus_norep_get64(ddi_acc_impl_t *handle, uint64_t *host_addr,
    uint64_t *dev_addr, size_t repcount, uint_t flags)
{
}

/*ARGSUSED*/
void
pmubus_norep_put8(ddi_acc_impl_t *handle, uint8_t *host_addr,
    uint8_t *dev_addr, size_t repcount, uint_t flags)
{
}

/*ARGSUSED*/
void
pmubus_norep_put16(ddi_acc_impl_t *handle, uint16_t *host_addr,
    uint16_t *dev_addr, size_t repcount, uint_t flags)
{
}

/*ARGSUSED*/
void
pmubus_norep_put32(ddi_acc_impl_t *handle, uint32_t *host_addr,
    uint32_t *dev_addr, size_t repcount, uint_t flags)
{
}

/*ARGSUSED*/
void
pmubus_norep_put64(ddi_acc_impl_t *handle, uint64_t *host_addr,
    uint64_t *dev_addr, size_t repcount, uint_t flags)
{
}

/*ARGSUSED*/
uint8_t
pmubus_get8(ddi_acc_impl_t *hdlp, uint8_t *addr)
{
	ddi_acc_hdl_t *hp = (ddi_acc_hdl_t *)hdlp;
	pmubus_mapreq_t *pmubus_mapreqp = hp->ah_bus_private;
	pmubus_devstate_t *softsp = pmubus_mapreqp->mapreq_softsp;
	off_t offset;
	uint8_t value;
	uint8_t mask;

	offset = pmubus_mapreqp->mapreq_addr + (uintptr_t)addr;
	offset &= PMUBUS_REGOFFSET;

	if ((pmubus_mapreqp->mapreq_flags) & MAPREQ_SHARED_BITS) {
		if (addr != 0 ||
		    pmubus_mapreqp->mapreq_size != sizeof (value)) {
			cmn_err(CE_WARN, "pmubus_get8: load discarded, "
			    "incorrect access addr/size");
			return ((uint8_t)-1);
		}
		mask = pmubus_mapreqp->mapreq_mask;
	} else {
		mask = (uint8_t)-1;
	}

	/* gets are simple, we just issue them no locking necessary */
	value = pci_config_get8(softsp->pmubus_reghdl, offset) & mask;

	DPRINTF(PMUBUS_RW_DEBUG, ("pmubus_get8: addr=%p offset=%lx value=%x "
	    "mask=%x\n", (void *)addr, offset, value, mask));

	return (value);
}


/*ARGSUSED*/
uint16_t
pmubus_noget16(ddi_acc_impl_t *hdlp, uint16_t *addr)
{
	return ((uint16_t)-1);
}

/*ARGSUSED*/
uint32_t
pmubus_get32(ddi_acc_impl_t *hdlp, uint32_t *addr)
{
	ddi_acc_hdl_t *hp = (ddi_acc_hdl_t *)hdlp;
	pmubus_mapreq_t *pmubus_mapreqp = hp->ah_bus_private;
	pmubus_devstate_t *softsp = pmubus_mapreqp->mapreq_softsp;
	off_t offset = (uintptr_t)addr & PMUBUS_REGOFFSET;
	uint32_t value;
	uint32_t mask;

	offset = pmubus_mapreqp->mapreq_addr + (uintptr_t)addr;
	offset &= PMUBUS_REGOFFSET;

	if ((pmubus_mapreqp->mapreq_flags) & MAPREQ_SHARED_BITS) {
		if (addr != 0 ||
		    pmubus_mapreqp->mapreq_size != sizeof (value)) {
			cmn_err(CE_WARN, "pmubus_get32: load discarded, "
			    "incorrect access addr/size");
			return ((uint32_t)-1);
		}
		mask = pmubus_mapreqp->mapreq_mask;
	} else {
		mask = (uint32_t)-1;
	}

	/* gets are simple, we just issue them no locking necessary */
	value = pci_config_get32(softsp->pmubus_reghdl, offset) & mask;

	DPRINTF(PMUBUS_RW_DEBUG, ("pmubus_get32: addr=%p offset=%lx value=%x "
	    "mask=%x\n", (void *)addr, offset, value, mask));

	return (value);
}

/*ARGSUSED*/
uint64_t
pmubus_noget64(ddi_acc_impl_t *hdlp, uint64_t *addr)
{
	return ((uint64_t)-1);
}

/*ARGSUSED*/
void
pmubus_put8(ddi_acc_impl_t *hdlp, uint8_t *addr, uint8_t value)
{
	ddi_acc_hdl_t *hp = (ddi_acc_hdl_t *)hdlp;
	pmubus_mapreq_t *pmubus_mapreqp = hp->ah_bus_private;
	pmubus_devstate_t *softsp = pmubus_mapreqp->mapreq_softsp;
	off_t offset;
	uint8_t tmp;

	offset = pmubus_mapreqp->mapreq_addr + (uintptr_t)addr;
	offset &= PMUBUS_REGOFFSET;

	if ((pmubus_mapreqp->mapreq_flags) & MAPREQ_SHARED_BITS) {
		/*
		 * Process "bit lane" register
		 */
		DPRINTF(PMUBUS_RW_DEBUG, ("pmubus_put8: addr=%p offset=%lx "
		    "value=%x mask=%lx\n", (void *)addr, offset, value,
		    pmubus_mapreqp->mapreq_mask));

		if (addr != 0 ||
		    pmubus_mapreqp->mapreq_size != sizeof (value)) {
			cmn_err(CE_WARN, "pmubus_put8: store discarded, "
			    "incorrect access addr/size");
			return;
		}

		mutex_enter(&softsp->pmubus_reg_access_lock);
		tmp = pci_config_get8(softsp->pmubus_reghdl, offset);
		tmp &= ~pmubus_mapreqp->mapreq_mask;
		value &= pmubus_mapreqp->mapreq_mask;
		tmp |= value;
		pci_config_put8(softsp->pmubus_reghdl, offset, tmp);
		mutex_exit(&softsp->pmubus_reg_access_lock);
	} else {
		/*
		 * Process shared register
		 */
		DPRINTF(PMUBUS_RW_DEBUG, ("pmubus_put8: addr=%p offset=%lx "
		    "value=%x\n", (void *)addr, offset, value));
		pci_config_put8(softsp->pmubus_reghdl, offset, value);
	}

	/* Flush store buffers XXX Should let drivers do this. */
	tmp = pci_config_get8(softsp->pmubus_reghdl, offset);
}

/*ARGSUSED*/
void
pmubus_noput16(ddi_acc_impl_t *hdlp, uint16_t *addr, uint16_t value)
{
}

/*ARGSUSED*/
void
pmubus_put32(ddi_acc_impl_t *hdlp, uint32_t *addr, uint32_t value)
{
	ddi_acc_hdl_t *hp = (ddi_acc_hdl_t *)hdlp;
	pmubus_mapreq_t *pmubus_mapreqp = hp->ah_bus_private;
	pmubus_devstate_t *softsp = pmubus_mapreqp->mapreq_softsp;
	off_t offset;
	uint32_t tmp;

	offset = pmubus_mapreqp->mapreq_addr + (uintptr_t)addr;
	offset &= PMUBUS_REGOFFSET;

	if ((pmubus_mapreqp->mapreq_flags) & MAPREQ_SHARED_BITS) {
		/*
		 * Process "bit lane" register
		 */
		DPRINTF(PMUBUS_RW_DEBUG, ("pmubus_put32: addr=%p offset=%lx "
		    "value=%x mask=%lx\n", (void *)addr, offset, value,
		    pmubus_mapreqp->mapreq_mask));

		if (addr != 0 ||
		    pmubus_mapreqp->mapreq_size != sizeof (value)) {
			cmn_err(CE_WARN, "pmubus_put32: store discarded, "
			    "incorrect access addr/size");
			return;
		}

		mutex_enter(&softsp->pmubus_reg_access_lock);
		tmp = pci_config_get32(softsp->pmubus_reghdl, offset);
		tmp &= ~pmubus_mapreqp->mapreq_mask;
		value &= pmubus_mapreqp->mapreq_mask;
		tmp |= value;
		pci_config_put32(softsp->pmubus_reghdl, offset, tmp);
		mutex_exit(&softsp->pmubus_reg_access_lock);
	} else {
		/*
		 * Process shared register
		 */
		DPRINTF(PMUBUS_RW_DEBUG, ("pmubus_put32: addr=%p offset=%lx "
		    "value=%x\n", (void *)addr, offset, value));
		pci_config_put32(softsp->pmubus_reghdl, offset, value);
	}

	/* Flush store buffers XXX Should let drivers do this. */
	tmp = pci_config_get32(softsp->pmubus_reghdl, offset);
}

/*ARGSUSED*/
void
pmubus_noput64(ddi_acc_impl_t *hdlp, uint64_t *addr, uint64_t value)
{
}

/*
 * This routine is used to translate our children's register properties.
 * The return value specifies which type of register has been translated.
 */
/*ARGSUSED*/
int
pmubus_apply_range(pmubus_devstate_t *pmubusp, dev_info_t *rdip,
    pmubus_regspec_t *regp, pci_regspec_t *pci_regp)
{
	pmu_rangespec_t *rangep;
	int nranges = pmubusp->pmubus_nranges;
	int i;
	off_t offset;
	int ret = DDI_ME_REGSPEC_RANGE;
	uint64_t addr;

	addr = regp->reg_addr & ~MAPPING_SHARED_BITS_MASK;

	/* Scan the ranges for a match */
	for (i = 0, rangep = pmubusp->pmubus_rangep; i < nranges; i++, rangep++)
		if ((rangep->rng_child <= addr) &&
		    ((addr + regp->reg_size) <=
		    (rangep->rng_child + rangep->rng_size))) {
			ret = DDI_SUCCESS;
			break;
		}

	if (ret != DDI_SUCCESS)
		return (ret);

	/* Get the translated register */
	offset = addr - rangep->rng_child;
	pci_regp->pci_phys_hi = rangep->rng_parent_hi;
	pci_regp->pci_phys_mid = rangep->rng_parent_mid;
	pci_regp->pci_phys_low = rangep->rng_parent_low + offset;
	pci_regp->pci_size_hi = 0;
	pci_regp->pci_size_low = MIN(regp->reg_size, rangep->rng_size);

	/* Figure out the type of reg space we have */
	if (pci_regp->pci_phys_hi == pmubusp->pmubus_regp->pci_phys_hi) {
		ret = MAPREQ_SHARED_REG;
		if (regp->reg_addr & MAPPING_SHARED_BITS_MASK)
			ret |= MAPREQ_SHARED_BITS;
	}

	return (ret);
}

static uint64_t
pmubus_mask(pmubus_obpregspec_t *regs, int32_t rnumber,
    uint64_t *masks)
{
	int i;
	long n = -1;

	for (i = 0; i <= rnumber; i++)
		if (regs[i].reg_addr_hi & 0x80000000)
			n++;

	if (n == -1) {
		cmn_err(CE_WARN, "pmubus_mask: missing mask");
		return (0);
	}

	return (masks[n]);
}

/*
 * The pmubus_map routine determines if it's child is attempting to map a
 * shared reg.  If it is, it installs it's own vectors and bus private pointer.
 */
static int
pmubus_map(dev_info_t *dip, dev_info_t *rdip, ddi_map_req_t *mp,
	off_t off, off_t len, caddr_t *addrp)
{
	pmubus_devstate_t *pmubusp = ddi_get_soft_state(per_pmubus_state,
	    ddi_get_instance(dip));
	dev_info_t *pdip = (dev_info_t *)DEVI(dip)->devi_parent;
	pmubus_regspec_t pmubus_rp;
	pmubus_obpregspec_t *pmubus_regs = NULL;
	int pmubus_regs_size;
	uint64_t *pmubus_regmask = NULL;
	int pmubus_regmask_size;
	pci_regspec_t pci_reg;
	int32_t rnumber = mp->map_obj.rnumber;
	pmubus_mapreq_t *pmubus_mapreqp;
	int ret = DDI_SUCCESS;
	char *map_fail1 = "Map Type Unknown";
	char *map_fail2 = "DDI_MT_REGSPEC";
	char *s = map_fail1;

	*addrp = NULL;

	/*
	 * Handle the mapping according to its type.
	 */
	DPRINTF(PMUBUS_MAP_DEBUG, ("rdip=%s%d: off=%lx len=%lx\n",
	    ddi_get_name(rdip), ddi_get_instance(rdip), off, len));
	switch (mp->map_type) {
	case DDI_MT_RNUMBER: {
		int n;

		/*
		 * Get the "reg" property from the device node and convert
		 * it to our parent's format.
		 */
		rnumber = mp->map_obj.rnumber;
		DPRINTF(PMUBUS_MAP_DEBUG, ("rdip=%s%d: rnumber=%x "
		    "handlep=%p\n", ddi_get_name(rdip), ddi_get_instance(rdip),
		    rnumber, (void *)mp->map_handlep));

		if (ddi_getlongprop(DDI_DEV_T_ANY, rdip, DDI_PROP_DONTPASS,
		    "reg", (caddr_t)&pmubus_regs, &pmubus_regs_size) !=
		    DDI_SUCCESS) {
			DPRINTF(PMUBUS_MAP_DEBUG, ("can't get reg "
			    "property\n"));
			ret = DDI_ME_RNUMBER_RANGE;
			goto done;
		}
		n = pmubus_regs_size / sizeof (pmubus_obpregspec_t);

		if (rnumber < 0 || rnumber >= n) {
			DPRINTF(PMUBUS_MAP_DEBUG, ("rnumber out of range\n"));
			ret = DDI_ME_RNUMBER_RANGE;
			goto done;
		}

		pmubus_rp.reg_addr = ((uint64_t)
		    pmubus_regs[rnumber].reg_addr_hi << 32) |
		    (uint64_t)pmubus_regs[rnumber].reg_addr_lo;
		pmubus_rp.reg_size = pmubus_regs[rnumber].reg_size;

		(void) ddi_getlongprop(DDI_DEV_T_ANY, rdip, DDI_PROP_DONTPASS,
		    "register-mask", (caddr_t)&pmubus_regmask,
		    &pmubus_regmask_size);

		/* Create our own mapping private structure */
		break;

	}
	case DDI_MT_REGSPEC:
		/*
		 * This bus has no bus children that have to map in an address
		 * space, so we can assume that we'll never see an
		 * DDI_MT_REGSPEC request
		 */
		s = map_fail2;
		ret = DDI_ME_REGSPEC_RANGE;
		/*FALLTHROUGH*/

	default:
		if (ret == DDI_SUCCESS)
			ret = DDI_ME_INVAL;
		DPRINTF(PMUBUS_MAP_DEBUG, ("rdip=%s%d: pmubus_map: "
		    "%s is an invalid map type.\nmap request handlep=0x%p\n",
		    ddi_get_name(rdip), ddi_get_instance(rdip), s, (void *)mp));

		ret = DDI_ME_RNUMBER_RANGE;
		goto done;
	}

	/* Adjust our reg property with offset and length */
	if ((pmubus_rp.reg_addr + off) >
	    (pmubus_rp.reg_addr + pmubus_rp.reg_size)) {
		ret = DDI_ME_INVAL;
		goto done;
	}

	pmubus_rp.reg_addr += off;
	if (len && (len < pmubus_rp.reg_size))
		pmubus_rp.reg_size = len;

	/* Translate our child regspec into our parents address domain */
	ret = pmubus_apply_range(pmubusp, rdip, &pmubus_rp, &pci_reg);

	/* Check if the apply range failed */
	if (ret < DDI_SUCCESS)
		goto done;

	/*
	 * If our childs xlated address falls into our shared address range,
	 * setup our mapping handle.
	 */
	if (ret > DDI_SUCCESS) {
		/* Figure out if we're mapping or unmapping */
		switch (mp->map_op) {
		case DDI_MO_MAP_LOCKED: {
			ddi_acc_impl_t *hp = (ddi_acc_impl_t *)mp->map_handlep;

			pmubus_mapreqp = kmem_alloc(sizeof (*pmubus_mapreqp),
			    KM_SLEEP);

			pmubus_mapreqp->mapreq_flags = ret;
			pmubus_mapreqp->mapreq_softsp = pmubusp;
			pmubus_mapreqp->mapreq_addr = pmubus_rp.reg_addr;
			pmubus_mapreqp->mapreq_size = pmubus_rp.reg_size;

			if (ret & MAPREQ_SHARED_BITS) {
				pmubus_mapreqp->mapreq_mask =
				    pmubus_mask(pmubus_regs, rnumber,
				    pmubus_regmask);
				DPRINTF(PMUBUS_MAP_DEBUG, ("rnumber=%d "
				    "mask=%lx\n", rnumber,
				    pmubus_mapreqp->mapreq_mask));
				if (pmubus_mapreqp->mapreq_mask == 0) {
					kmem_free(pmubus_mapreqp,
					    sizeof (pmubus_mapreq_t));
					ret = DDI_ME_INVAL;
					break;
				}
			}

			hp->ahi_common.ah_bus_private = pmubus_mapreqp;

			/* Initialize the access vectors */
			hp->ahi_get8 = pmubus_get8;
			hp->ahi_get16 = pmubus_noget16;
			hp->ahi_get32 = pmubus_get32;
			hp->ahi_get64 = pmubus_noget64;
			hp->ahi_put8 = pmubus_put8;
			hp->ahi_put16 = pmubus_noput16;
			hp->ahi_put32 = pmubus_put32;
			hp->ahi_put64 = pmubus_noput64;
			hp->ahi_rep_get8 = pmubus_norep_get8;
			hp->ahi_rep_get16 = pmubus_norep_get16;
			hp->ahi_rep_get32 = pmubus_norep_get32;
			hp->ahi_rep_get64 = pmubus_norep_get64;
			hp->ahi_rep_put8 = pmubus_norep_put8;
			hp->ahi_rep_put16 = pmubus_norep_put16;
			hp->ahi_rep_put32 = pmubus_norep_put32;
			hp->ahi_rep_put64 = pmubus_norep_put64;

			ret = DDI_SUCCESS;
			break;
		}

		case DDI_MO_UNMAP: {
			ddi_acc_impl_t *hp = (ddi_acc_impl_t *)mp->map_handlep;

			pmubus_mapreqp = hp->ahi_common.ah_bus_private;

			/* Free the our map request struct */
			kmem_free(pmubus_mapreqp, sizeof (pmubus_mapreq_t));

			ret = DDI_SUCCESS;
			break;
		}

		default:
			ret = DDI_ME_UNSUPPORTED;
		}
	} else {
		/* Prepare the map request struct for a call to our parent */
		mp->map_type = DDI_MT_REGSPEC;
		mp->map_obj.rp = (struct regspec *)&pci_reg;

		/* Pass the mapping operation up the device tree */
		ret = (DEVI(pdip)->devi_ops->devo_bus_ops->bus_map)
		    (pdip, rdip, mp, off, len, addrp);
	}

done:
	if (pmubus_regs != NULL)
		kmem_free(pmubus_regs, pmubus_regs_size);
	if (pmubus_regmask != NULL)
		kmem_free(pmubus_regmask, pmubus_regmask_size);
	return (ret);
}

static int
pmubus_ctlops(dev_info_t *dip, dev_info_t *rdip,
    ddi_ctl_enum_t op, void *arg, void *result)
{
	dev_info_t *child = (dev_info_t *)arg;
	pmubus_obpregspec_t *pmubus_rp;
	char name[9];
	int reglen;

	switch (op) {
	case DDI_CTLOPS_INITCHILD:

		if (ddi_getlongprop(DDI_DEV_T_ANY, child,
		    DDI_PROP_DONTPASS, "reg", (caddr_t)&pmubus_rp,
		    &reglen) != DDI_SUCCESS) {

			return (DDI_FAILURE);
		}

		if ((reglen % sizeof (pmubus_obpregspec_t)) != 0) {
			cmn_err(CE_WARN,
			    "pmubus: reg property not well-formed for "
			    "%s size=%d\n", ddi_node_name(child), reglen);
			kmem_free(pmubus_rp, reglen);

			return (DDI_FAILURE);
		}
		(void) snprintf(name, sizeof (name), "%x,%x",
		    pmubus_rp->reg_addr_hi, pmubus_rp->reg_addr_lo);
		ddi_set_name_addr(child, name);
		kmem_free(pmubus_rp, reglen);

		return (DDI_SUCCESS);

	case DDI_CTLOPS_UNINITCHILD:

		ddi_set_name_addr(child, NULL);
		ddi_remove_minor_node(child, NULL);
		impl_rem_dev_props(child);

		return (DDI_SUCCESS);
	default:
		break;
	}

	return (ddi_ctlops(dip, rdip, op, arg, result));
}
