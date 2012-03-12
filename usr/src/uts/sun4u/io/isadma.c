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


#include <sys/conf.h>
#include <sys/sunddi.h>
#include <sys/ddi_impldefs.h>
#include <sys/kmem.h>
#include <sys/dma_i8237A.h>
#include <sys/isadma.h>
#include <sys/nexusdebug.h>

/* Bitfield debugging definitions for this file */
#define	ISADMA_MAP_DEBUG	0x1
#define	ISADMA_REGACCESS_DEBUG	0x2

/*
 * The isadam nexus serves two functions.  The first is to represent a
 * a placeholder in the device tree for a shared dma controller register
 * for the SuperIO floppy and parallel ports.
 * The second function is to virtualize the shared dma controller register
 * for those two drivers.  Rather than creating new ddi routines to manage
 * the shared register, we will use the ddi register mapping functions to
 * do this.  The two child devices will use ddi_regs_map_setup to map in
 * their device registers.  The isadma nexus will have an aliased entry in
 * it's own registers property for the shared dma controller register.  When
 * the isadma detects the fact that it's children are trying to map the shared
 * register, it will intercept this mapping and provide it's own register
 * access routine to be used to access the register when the child devices
 * use the ddi_{get,put} calls.
 *
 * Sigh, the 82C37 has a weird quirk (BUG?) where when DMA is active on the
 * the bus, PIO's cannot happen.  If they do, they generate bus faults and
 * cause the system to panic.  On PC's, the Intel processor has special
 * req/grnt lines that prevent PIO's from occuring while DMA is in flight,
 * unfortunately, hummingbird doesn't support this special req/grnt pair.
 * I'm going to try and work around this by implementing a cv to stop PIO's
 * from occuring while DMA is in flight.  When each child wants to do DMA,
 * they need to mask out all other channels using the allmask register.
 * This nexus keys on this access and locks down the hardware using a cv.
 * Once the driver's interrupt handler is called it needs to clear
 * the allmask register.  The nexus keys off of this an issues cv wakeups
 * if necessary.
 */
/*
 * Function prototypes for busops routines:
 */
static int isadma_map(dev_info_t *dip, dev_info_t *rdip, ddi_map_req_t *mp,
    off_t off, off_t len, caddr_t *addrp);

/*
 * function prototypes for dev ops routines:
 */
static int isadma_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int isadma_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);

/*
 * general function prototypes:
 */

/*
 * bus ops and dev ops structures:
 */
static struct bus_ops isadma_bus_ops = {
	BUSO_REV,
	isadma_map,
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
	ddi_ctlops,
	ddi_bus_prop_op,
	0,			/* (*bus_get_eventcookie)();	*/
	0,			/* (*bus_add_eventcall)();	*/
	0,			/* (*bus_remove_eventcall)();	*/
	0,			/* (*bus_post_event)();		*/
	0,			/* (*bus_intr_control)();	*/
	0,			/* (*bus_config)();		*/
	0,			/* (*bus_unconfig)();		*/
	0,			/* (*bus_fm_init)();		*/
	0,			/* (*bus_fm_fini)();		*/
	0,			/* (*bus_fm_access_enter)();	*/
	0,			/* (*bus_fm_access_exit)();	*/
	0,			/* (*bus_power)();		*/
	i_ddi_intr_ops		/* (*bus_intr_op();		*/
};

static struct dev_ops isadma_ops = {
	DEVO_REV,
	0,
	ddi_no_info,
	nulldev,
	0,
	isadma_attach,
	isadma_detach,
	nodev,
	(struct cb_ops *)0,
	&isadma_bus_ops,
	NULL,
	ddi_quiesce_not_needed,		/* quiesce */
};

/*
 * module definitions:
 */
#include <sys/modctl.h>

static struct modldrv modldrv = {
	&mod_driverops, 	/* Type of module.  This one is a driver */
	"isadma nexus driver",	/* Name of module. */
	&isadma_ops,		/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modldrv, NULL
};

/*
 * driver global data:
 */
static void *per_isadma_state;		/* per-isadma soft state pointer */

/* Global debug data */
uint64_t isadma_sleep_cnt = 0;
uint64_t isadma_wakeup_cnt = 0;
#ifdef DEBUG
int64_t isadma_max_waiter = 0;
int64_t isadma_min_waiter = 0xffffll;
uint64_t isadma_punt = 0;
uint64_t isadma_setting_wdip = 0;
uint64_t isadma_clearing_wdip = 0;
#endif

int
_init(void)
{
	int e;

	/*
	 * Initialize per-isadma soft state pointer.
	 */
	e = ddi_soft_state_init(&per_isadma_state,
	    sizeof (isadma_devstate_t), 1);
	if (e != 0)
		return (e);

	/*
	 * Install the module.
	 */
	e = mod_install(&modlinkage);
	if (e != 0)
		ddi_soft_state_fini(&per_isadma_state);
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
	ddi_soft_state_fini(&per_isadma_state);
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
 */
static int
isadma_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	isadma_devstate_t *isadmap;	/* per isadma state pointer */
	int32_t instance;
	int ret = DDI_SUCCESS;

#ifdef DEBUG
	debug_print_level = 0;
	debug_info = 1;
#endif
	switch (cmd) {
	case DDI_ATTACH: {
		/*
		 * Allocate soft state for this instance.
		 */
		instance = ddi_get_instance(dip);
		if (ddi_soft_state_zalloc(per_isadma_state, instance)
		    != DDI_SUCCESS) {
			ret = DDI_FAILURE;
			goto exit;
		}
		isadmap = ddi_get_soft_state(per_isadma_state, instance);
		isadmap->isadma_dip = dip;

		/* Cache our register property */
		if (ddi_getlongprop(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
		    "reg", (caddr_t)&isadmap->isadma_regp,
		    &isadmap->isadma_reglen) != DDI_SUCCESS) {
			ret = DDI_FAILURE;
			goto fail_get_prop;
		}

		/* Initialize our mutex */
		mutex_init(&isadmap->isadma_access_lock, NULL, MUTEX_DRIVER,
		    NULL);

		/* Initialize our condition variable */
		cv_init(&isadmap->isadma_access_cv, NULL, CV_DRIVER, NULL);

		ddi_report_dev(dip);
		goto exit;

	}
	case DDI_RESUME:
	default:
		goto exit;
	}

fail_get_prop:
	ddi_soft_state_free(per_isadma_state, instance);

exit:
	return (ret);
}

/*
 * detach entry point:
 */
static int
isadma_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int instance = ddi_get_instance(dip);
	isadma_devstate_t *isadmap =
	    ddi_get_soft_state(per_isadma_state, instance);

	switch (cmd) {
	case DDI_DETACH:
		cv_destroy(&isadmap->isadma_access_cv);

		mutex_destroy(&isadmap->isadma_access_lock);

		/* free the cached register property */
		kmem_free(isadmap->isadma_regp, isadmap->isadma_reglen);

		ddi_soft_state_free(per_isadma_state, instance);
		return (DDI_SUCCESS);

	case DDI_SUSPEND:
		return (DDI_SUCCESS);
	}
	return (DDI_FAILURE);
}


#ifdef DEBUG
static void
isadma_check_waiters(isadma_devstate_t *isadmap)
{
	if (isadmap->isadma_want > isadma_max_waiter)
		isadma_max_waiter = isadmap->isadma_want;

	if (isadmap->isadma_want < isadma_min_waiter)
		isadma_min_waiter = isadmap->isadma_want;
}
#endif

static void
isadma_dmawait(isadma_devstate_t *isadmap)
{

	ASSERT(mutex_owned(&isadmap->isadma_access_lock));

	/* Wait loop, if the locking dip is set, we wait. */
	while (isadmap->isadma_ldip != NULL) {

		isadmap->isadma_want++;
		cv_wait(&isadmap->isadma_access_cv,
		    &isadmap->isadma_access_lock);
		isadmap->isadma_want--;
		isadma_sleep_cnt++;
	}
}

static void
isadma_wakeup(isadma_devstate_t *isadmap)
{

	ASSERT(mutex_owned(&isadmap->isadma_access_lock));

	/*
	 * If somebody wants register access and the lock dip is not set
	 * signal the waiters.
	 */
	if (isadmap->isadma_want > 0 && isadmap->isadma_ldip == NULL) {
		cv_signal(&isadmap->isadma_access_cv);
		isadma_wakeup_cnt++;
	}

}

/*
 * Register access vectors
 */

/*ARGSUSED*/
void
isadma_norep_get8(ddi_acc_impl_t *handle, uint8_t *host_addr,
    uint8_t *dev_addr, size_t repcount, uint_t flags)
{
}

/*ARGSUSED*/
void
isadma_norep_get16(ddi_acc_impl_t *handle, uint16_t *host_addr,
    uint16_t *dev_addr, size_t repcount, uint_t flags)
{
}

/*ARGSUSED*/
void
isadma_norep_get32(ddi_acc_impl_t *handle, uint32_t *host_addr,
    uint32_t *dev_addr, size_t repcount, uint_t flags)
{
}

/*ARGSUSED*/
void
isadma_norep_get64(ddi_acc_impl_t *handle, uint64_t *host_addr,
    uint64_t *dev_addr, size_t repcount, uint_t flags)
{
}

/*ARGSUSED*/
void
isadma_norep_put8(ddi_acc_impl_t *handle, uint8_t *host_addr,
    uint8_t *dev_addr, size_t repcount, uint_t flags)
{
}

/*ARGSUSED*/
void
isadma_norep_put16(ddi_acc_impl_t *handle, uint16_t *host_addr,
    uint16_t *dev_addr, size_t repcount, uint_t flags)
{
}

/*ARGSUSED*/
void
isadma_norep_put32(ddi_acc_impl_t *handle, uint32_t *host_addr,
    uint32_t *dev_addr, size_t repcount, uint_t flags)
{
}

/*ARGSUSED*/
void
isadma_norep_put64(ddi_acc_impl_t *handle, uint64_t *host_addr,
    uint64_t *dev_addr, size_t repcount, uint_t flags)
{
}

/*ARGSUSED*/
uint8_t
isadma_get8(ddi_acc_impl_t *hdlp, uint8_t *addr)
{
	ddi_acc_handle_t phdl = hdlp->ahi_common.ah_platform_private;
	isadma_devstate_t *isadmap = hdlp->ahi_common.ah_bus_private;
	off_t offset = (caddr_t)addr - hdlp->ahi_common.ah_addr;
	uint8_t ret = 0xff;

	if (IN_CHILD_SPACE(offset)) {	/* Pass to parent */
#ifdef DEBUG
		isadma_punt++;
#endif
		return (ddi_get8(phdl, addr));
	}
#ifdef DEBUG
	isadma_check_waiters(isadmap);
#endif
	mutex_enter(&isadmap->isadma_access_lock);
	isadma_dmawait(isadmap);	/* wait until on-going dma completes */

	/* No 8 bit access to 16 bit address or count registers */
	if (IN_16BIT_SPACE(offset))
		goto exit;

	/* No 8 bit access to first/last flip-flop registers */
	if (IS_SEQREG(offset))
		goto exit;

	ret = ddi_get8(phdl, addr);	/* Pass to parent */
exit:
	isadma_wakeup(isadmap);
	mutex_exit(&isadmap->isadma_access_lock);
	return (ret);
}

/*
 * Allow child devices to access this shared register set as if it were
 * a real 16 bit register.  The ISA bridge defines the access to this
 * 16 bit dma controller & count register by programming an 8 byte register.
 */
/*ARGSUSED*/
uint16_t
isadma_get16(ddi_acc_impl_t *hdlp, uint16_t *addr)
{
	ddi_acc_handle_t phdl = hdlp->ahi_common.ah_platform_private;
	isadma_devstate_t *isadmap = hdlp->ahi_common.ah_bus_private;
	off_t offset = (caddr_t)addr - hdlp->ahi_common.ah_addr;
	uint16_t ret = 0xffff;

	if (IN_CHILD_SPACE(offset)) {	/* Pass to parent */
#ifdef DEBUG
		isadma_punt++;
#endif
		return (ddi_get16(phdl, addr));
	}
#ifdef DEBUG
	isadma_check_waiters(isadmap);
#endif
	mutex_enter(&isadmap->isadma_access_lock);
	isadma_dmawait(isadmap);	/* wait until on-going dma completes */

	/* Only Allow access to the 16 bit count and address registers */
	if (!IN_16BIT_SPACE(offset))
		goto exit;

	/* Set the sequencing register to the low byte */
	ddi_put8(phdl, (uint8_t *)HDL_TO_SEQREG_ADDR(hdlp, offset), 0);

	/* Read the low byte, then high byte */
	ret = ddi_get8(phdl, (uint8_t *)addr);
	ret = (ddi_get8(phdl, (uint8_t *)addr) << 8) | ret;
exit:
	isadma_wakeup(isadmap);
	mutex_exit(&isadmap->isadma_access_lock);
	return (ret);
}

/*ARGSUSED*/
uint32_t
isadma_noget32(ddi_acc_impl_t *hdlp, uint32_t *addr)
{
	return (UINT32_MAX);
}

/*ARGSUSED*/
uint64_t
isadma_noget64(ddi_acc_impl_t *hdlp, uint64_t *addr)
{
	return (UINT64_MAX);
}

/*
 * Here's where we do our locking magic.  The dma all mask register is an 8
 * bit register in the dma space, so we look for the access to the
 * DMAC1_ALLMASK register.  When somebody is masking out the dma channels
 * we lock down the dma engine from further PIO accesses.  When the driver
 * calls back into this routine to clear the allmask register, we wakeup
 * any blocked threads.
 */
/*ARGSUSED*/
void
isadma_put8(ddi_acc_impl_t *hdlp, uint8_t *addr, uint8_t value)
{
	ddi_acc_handle_t phdl = hdlp->ahi_common.ah_platform_private;
	isadma_devstate_t *isadmap = hdlp->ahi_common.ah_bus_private;
	off_t offset = (caddr_t)addr - hdlp->ahi_common.ah_addr;

	if (IN_CHILD_SPACE(offset)) {	/* Pass to parent */
#ifdef DEBUG
		isadma_punt++;
#endif
		ddi_put8(phdl, addr, value);
		return;
	}
#ifdef DEBUG
	isadma_check_waiters(isadmap);
#endif
	mutex_enter(&isadmap->isadma_access_lock);

	if (isadmap->isadma_ldip == hdlp->ahi_common.ah_dip) { /* owned lock? */
		if (END_ISADMA(offset, value)) {
			isadmap->isadma_ldip = NULL;	/* reset lock owner */
#ifdef DEBUG
			isadma_clearing_wdip++;
#endif
		}
	} else	{	/* we don't own the lock */
		/* wait until on-going dma completes */
		isadma_dmawait(isadmap);

		if (BEGIN_ISADMA(offset, value)) {
			isadmap->isadma_ldip = hdlp->ahi_common.ah_dip;
#ifdef DEBUG
			isadma_setting_wdip++;
#endif
		}
	}

	/* No 8 bit access to 16 bit address or count registers */
	if (IN_16BIT_SPACE(offset))
		goto exit;

	/* No 8 bit access to first/last flip-flop registers */
	if (IS_SEQREG(offset))
		goto exit;

	ddi_put8(phdl, addr, value);	/* Pass to parent */
exit:
	isadma_wakeup(isadmap);
	mutex_exit(&isadmap->isadma_access_lock);
}

/*
 * Allow child devices to access this shared register set as if it were
 * a real 16 bit register.  The ISA bridge defines the access to this
 * 16 bit dma controller & count register by programming an 8 byte register.
 */
/*ARGSUSED*/
void
isadma_put16(ddi_acc_impl_t *hdlp, uint16_t *addr, uint16_t value)
{
	ddi_acc_handle_t phdl = hdlp->ahi_common.ah_platform_private;
	isadma_devstate_t *isadmap = hdlp->ahi_common.ah_bus_private;
	off_t offset = (caddr_t)addr - hdlp->ahi_common.ah_addr;

	if (IN_CHILD_SPACE(offset)) {	/* Pass to parent */
#ifdef DEBUG
		isadma_punt++;
#endif
		ddi_put16(phdl, addr, value);
		return;
	}
#ifdef DEBUG
	isadma_check_waiters(isadmap);
#endif
	mutex_enter(&isadmap->isadma_access_lock);
	isadma_dmawait(isadmap);	/* wait until on-going dma completes */

	/* Only Allow access to the 16 bit count and address registers */
	if (!IN_16BIT_SPACE(offset))
		goto exit;

	/* Set the sequencing register to the low byte */
	ddi_put8(phdl, (uint8_t *)HDL_TO_SEQREG_ADDR(hdlp, offset), 0);

	/* Write the low byte, then the high byte */
	ddi_put8(phdl, (uint8_t *)addr, value & 0xff);
	ddi_put8(phdl, (uint8_t *)addr, (value >> 8) & 0xff);
exit:
	isadma_wakeup(isadmap);
	mutex_exit(&isadmap->isadma_access_lock);
}

/*ARGSUSED*/
void
isadma_noput32(ddi_acc_impl_t *hdlp, uint32_t *addr, uint32_t value) {}

/*ARGSUSED*/
void
isadma_noput64(ddi_acc_impl_t *hdlp, uint64_t *addr, uint64_t value) {}

#define	IS_SAME_REG(r1, r2) (((r1)->ebus_addr_hi == (r2)->ebus_addr_hi) && \
	((r1)->ebus_addr_low == (r2)->ebus_addr_low))

/*
 * The isadma_map routine determines if it's child is attempting to map a
 * shared reg.  If it is, it installs it's own vectors and bus private pointer
 * and stacks those ops that were already defined.
 */
static int
isadma_map(dev_info_t *dip, dev_info_t *rdip, ddi_map_req_t *mp,
	off_t off, off_t len, caddr_t *addrp)
{
	isadma_devstate_t *isadmap = ddi_get_soft_state(per_isadma_state,
	    ddi_get_instance(dip));
	dev_info_t *pdip = (dev_info_t *)DEVI(dip)->devi_parent;
	ebus_regspec_t *child_regp, *regp;
	int32_t rnumber = mp->map_obj.rnumber;
	int32_t reglen;
	int ret;
	ddi_acc_impl_t *hp;

	/*
	 * Get child regspec since the mapping struct may not have it yet
	 */
	if (ddi_getlongprop(DDI_DEV_T_ANY, rdip, DDI_PROP_DONTPASS,
	    "reg", (caddr_t)&regp, &reglen) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	child_regp = regp + rnumber;

	DPRINTF(ISADMA_MAP_DEBUG, ("isadma_map: child regp %p "
	    "parent regp %p Child reg array %p\n", (void *)child_regp,
	    (void *)isadmap->isadma_regp, (void *)regp));

	/* Figure out if we're mapping or unmapping */
	switch (mp->map_op) {
	case DDI_MO_MAP_LOCKED:
		/* Call up device tree to establish mapping */
		ret = (DEVI(pdip)->devi_ops->devo_bus_ops->bus_map)
		    (pdip, rdip, mp, off, len, addrp);

		if ((ret != DDI_SUCCESS) ||
		    !IS_SAME_REG(child_regp, isadmap->isadma_regp))
			break;

		/* Post-process the mapping request. */
		hp = kmem_alloc(sizeof (ddi_acc_impl_t), KM_SLEEP);
		*hp = *(ddi_acc_impl_t *)mp->map_handlep;
		impl_acc_hdl_get((ddi_acc_handle_t)mp->map_handlep)->
		    ah_platform_private = hp;
		hp = (ddi_acc_impl_t *)mp->map_handlep;
		hp->ahi_common.ah_bus_private = isadmap;
		hp->ahi_get8 = isadma_get8;
		hp->ahi_get16 = isadma_get16;
		hp->ahi_get32 = isadma_noget32;
		hp->ahi_get64 = isadma_noget64;
		hp->ahi_put8 = isadma_put8;
		hp->ahi_put16 = isadma_put16;
		hp->ahi_put32 = isadma_noput32;
		hp->ahi_put64 = isadma_noput64;
		hp->ahi_rep_get8 = isadma_norep_get8;
		hp->ahi_rep_get16 = isadma_norep_get16;
		hp->ahi_rep_get32 = isadma_norep_get32;
		hp->ahi_rep_get64 = isadma_norep_get64;
		hp->ahi_rep_put8 = isadma_norep_put8;
		hp->ahi_rep_put16 = isadma_norep_put16;
		hp->ahi_rep_put32 = isadma_norep_put32;
		hp->ahi_rep_put64 = isadma_norep_put64;
		break;

	case DDI_MO_UNMAP:
		if (IS_SAME_REG(child_regp, isadmap->isadma_regp)) {
			hp = impl_acc_hdl_get(
			    (ddi_acc_handle_t)mp->map_handlep)->
			    ah_platform_private;
			*(ddi_acc_impl_t *)mp->map_handlep = *hp;
			kmem_free(hp, sizeof (ddi_acc_impl_t));
		}

		/* Call up tree to tear down mapping */
		ret = (DEVI(pdip)->devi_ops->devo_bus_ops->bus_map)
		    (pdip, rdip, mp, off, len, addrp);
		break;

	default:
		ret = DDI_FAILURE;
		break;
	}

	kmem_free(regp, reglen);
	return (ret);
}
