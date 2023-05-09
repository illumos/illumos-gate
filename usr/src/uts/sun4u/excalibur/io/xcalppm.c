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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright 2023 Oxide Computer Company
 */

/*
 * Platform Power Management driver for SUNW,Sun-Blade-1000
 */
#include <sys/modctl.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/ddi_impldefs.h>
#include <sys/ppmvar.h>
#include <sys/ppmio.h>
#include <sys/xcalppm_reg.h>
#include <sys/xcalppm_var.h>
#include <sys/stat.h>
#include <sys/epm.h>
#include <sys/archsystm.h>
#include <sys/cpuvar.h>
#include <sys/cheetahregs.h>
#include <sys/us3_module.h>

/*
 * Locking Considerations
 *
 * To look at and/or modify xcppm_domain fields or elements of its list of
 * xcppm_dev structures the domain_lock for the affected domain must be held.
 *
 * When the autopm framework needs to change the power of a component of a
 * device, it needs to hold the associated power lock (see discussion at
 * top of uts/common/os/sunpm.c).
 *
 * If the framework needs to lock a dev/cmpt for a device which this ppm
 * has claimed, xcppm_ctlops will be called with PMR_PPM_LOCK_POWER.  Ppm
 * needs to be involved because, due to platform constraints, changing the
 * power of one device may require that other devices be changed in the same
 * operation.
 *
 * In some domains (e.g., cpus) the power lock must be acquired for all the
 * affected devices to avoid possible corruption of the power states.  The
 * joint change must be an atomic operation.  Ppm handles this by acquiring
 * the domain lock, then walking the list of affected devices and acquiring
 * the power lock for each of them.  To unlock, the list is traversed and
 * each of the power locks is freed, followed by freeing the domain lock.
 *
 * For other domains ppm will only be changing the power of a single device
 * that is known to the framework.  In these cases, the locking is done by
 * acquiring the domain lock and directly calling the framework routine for
 * getting a single power lock.
 */

static int	xcppm_attach(dev_info_t *, ddi_attach_cmd_t);
static int	xcppm_detach(dev_info_t *, ddi_detach_cmd_t);
static int	xcppm_ctlops(dev_info_t *, dev_info_t *,
		    ddi_ctl_enum_t, void *, void *);
static void	xcppm_dev_init(ppm_dev_t *);
static void	xcppm_dev_fini(ppm_dev_t *);
static void	xcppm_iocset(uint8_t);
static uint8_t	xcppm_iocget(void);

/*
 * Note: 1394 and pciupa were originally required to be LOCK_ALL domains.
 * However, the underlying nexus drivers aren't able to do power mgmt
 * (because of hw implementation issues).  The locking protocol for these
 * domains is changed to LOCK_ONE to simplify other code.  The domain
 * code itself will be removed in the future.
 */
static ppm_domain_t xcppm_1394 = { "domain_1394",	PPMD_LOCK_ONE };
static ppm_domain_t xcppm_cpu  = { "domain_cpu",	PPMD_LOCK_ALL };
static ppm_domain_t xcppm_fet  = { "domain_powerfet",	PPMD_LOCK_ONE };
static ppm_domain_t xcppm_upa  = { "domain_pciupa",	PPMD_LOCK_ONE };

ppm_domain_t *ppm_domains[] = {
	&xcppm_1394,
	&xcppm_cpu,
	&xcppm_fet,
	&xcppm_upa,
	NULL
};


struct ppm_funcs ppmf = {
	xcppm_dev_init,			/* dev_init */
	xcppm_dev_fini,			/* dev_fini */
	xcppm_iocset,			/* iocset */
	xcppm_iocget,			/* iocget */
};


/*
 * The order of entries must be from slowest to fastest and in
 * one-to-one correspondence with the cpu_level array.
 */
static const uint16_t bbc_estar_control_masks[] = {
	BBC_ESTAR_SLOW, BBC_ESTAR_MEDIUM, BBC_ESTAR_FAST
};

int bbc_delay = 10;			/* microsec */


/*
 * Configuration data structures
 */
static struct cb_ops xcppm_cb_ops = {
	ppm_open,		/* open */
	ppm_close,		/* close */
	nodev,			/* strategy */
	nodev,			/* print */
	nodev,			/* dump */
	nodev,			/* read */
	nodev,			/* write */
	ppm_ioctl,		/* ioctl */
	nodev,			/* devmap */
	nodev,			/* mmap */
	nodev,			/* segmap */
	nochpoll,		/* poll */
	ddi_prop_op,		/* prop_op */
	NULL,			/* streamtab */
	D_MP | D_NEW,		/* driver compatibility flag */
	CB_REV,			/* cb_ops revision */
	nodev,			/* async read */
	nodev			/* async write */
};

static struct bus_ops xcppm_bus_ops = {
	BUSO_REV,
	0,
	0,
	0,
	0,
	0,
	ddi_no_dma_map,
	ddi_no_dma_allochdl,
	ddi_no_dma_freehdl,
	ddi_no_dma_bindhdl,
	ddi_no_dma_unbindhdl,
	ddi_no_dma_flush,
	ddi_no_dma_win,
	ddi_no_dma_mctl,
	xcppm_ctlops,
	0,
	0,			/* (*bus_get_eventcookie)();	*/
	0,			/* (*bus_add_eventcall)();	*/
	0,			/* (*bus_remove_eventcall)();	*/
	0			/* (*bus_post_event)();		*/
};

static struct dev_ops xcppm_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* refcnt */
	ppm_getinfo,		/* info */
	nulldev,		/* identify */
	nulldev,		/* probe */
	xcppm_attach,		/* attach */
	xcppm_detach,		/* detach */
	nodev,			/* reset */
	&xcppm_cb_ops,		/* driver operations */
	&xcppm_bus_ops,		/* bus operations */
	NULL,			/* power */
	ddi_quiesce_not_supported,	/* devo_quiesce */
};

extern struct mod_ops mod_driverops;

static struct modldrv modldrv = {
	&mod_driverops,		/* type of module - pseudo */
	"platform pm driver",
	&xcppm_ops
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&modldrv,
	NULL
};


int
_init(void)
{
	return (ppm_init(&modlinkage, sizeof (xcppm_unit_t), "xc"));
}


int
_fini(void)
{
	return (EBUSY);
}


int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}


static int
xcppm_map_all_regs(dev_info_t *dip)
{
	ddi_device_acc_attr_t attr_be, attr_le;
	int rv0, rv1, rv2, rv3;
	xcppm_unit_t *unitp;
	caddr_t base_addr;
	uint8_t data8;

	unitp = ddi_get_soft_state(ppm_statep, ppm_inst);
	attr_be.devacc_attr_version = DDI_DEVICE_ATTR_V0;
	attr_be.devacc_attr_endian_flags  = DDI_STRUCTURE_BE_ACC;
	attr_be.devacc_attr_dataorder = DDI_STRICTORDER_ACC;

	attr_le.devacc_attr_version = DDI_DEVICE_ATTR_V0;
	attr_le.devacc_attr_endian_flags  = DDI_STRUCTURE_LE_ACC;
	attr_le.devacc_attr_dataorder = DDI_STRICTORDER_ACC;

	rv0 = ddi_regs_map_setup(dip, 0, &base_addr, 0, 0, &attr_be,
	    &unitp->hndls.bbc_estar_ctrl);

	unitp->regs.bbc_estar_ctrl = (uint16_t *)(base_addr +
	    BBC_ESTAR_CTRL_OFFSET);
	unitp->regs.bbc_assert_change = (uint32_t *)(base_addr +
	    BBC_ASSERT_CHANGE_OFFSET);
	unitp->regs.bbc_pll_settle = (uint32_t *)(base_addr +
	    BBC_PLL_SETTLE_OFFSET);

	rv1 = ddi_regs_map_setup(dip, 1,
	    (caddr_t *)&unitp->regs.rio_mode_auxio,
	    0, 0, &attr_le, &unitp->hndls.rio_mode_auxio);

	rv2 = ddi_regs_map_setup(dip, 2, &base_addr,
	    0, 0, &attr_le, &unitp->hndls.gpio_bank_select);

	unitp->regs.gpio_bank_sel_index = (uint8_t *)(base_addr +
	    GPIO_BANK_SEL_INDEX_OFFSET);
	unitp->regs.gpio_bank_sel_data = (uint8_t *)(base_addr +
	    GPIO_BANK_SEL_DATA_OFFSET);

	rv3 = ddi_regs_map_setup(dip, 3, &base_addr, 0, 0, &attr_le,
	    &unitp->hndls.gpio_data_ports);

	unitp->regs.gpio_port1_data = (uint8_t *)(base_addr +
	    GPIO_PORT1_DATA_OFFSET);
	unitp->regs.gpio_port2_data = (uint8_t *)(base_addr +
	    GPIO_PORT2_DATA_OFFSET);

	if (rv0 != DDI_SUCCESS || rv1 != DDI_SUCCESS ||
	    rv2 != DDI_SUCCESS || rv3 != DDI_SUCCESS) {
		if (rv0 == DDI_SUCCESS)
			ddi_regs_map_free(&unitp->hndls.bbc_estar_ctrl);
		if (rv1 == DDI_SUCCESS)
			ddi_regs_map_free(&unitp->hndls.rio_mode_auxio);
		if (rv2 == DDI_SUCCESS)
			ddi_regs_map_free(&unitp->hndls.gpio_bank_select);
		if (rv3 == DDI_SUCCESS)
			ddi_regs_map_free(&unitp->hndls.gpio_data_ports);
		return (DDI_FAILURE);
	}

	/*
	 * Ppm uses GPIO bits in Bank 0.  Make sure Bank 0 is selected.
	 */
	data8 = SIO_CONFIG2_INDEX;
	XCPPM_SETGET8(unitp->hndls.gpio_bank_select,
	    unitp->regs.gpio_bank_sel_index, data8);
	data8 = XCPPM_GET8(unitp->hndls.gpio_bank_select,
	    unitp->regs.gpio_bank_sel_data);

	data8 &= 0x7f;	/* Set Bit7 to zero */
	XCPPM_SETGET8(unitp->hndls.gpio_bank_select,
	    unitp->regs.gpio_bank_sel_data, data8);

	return (DDI_SUCCESS);
}


static int
xcppm_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
#ifdef DEBUG
	char *str = "xcppm_attach";
#endif
	xcppm_unit_t *unitp;
	ppm_domain_t **dompp;
	int retval;

	DPRINTF(D_ATTACH, ("%s: attach cmd %d\n", str, cmd));
	retval = DDI_SUCCESS;

	switch (cmd) {
	case DDI_ATTACH:
		if (ppm_inst != -1) {
			DPRINTF(D_ERROR,
			    ("%s: instance already attached\n", str));
			return (DDI_FAILURE);
		}
		ppm_inst = ddi_get_instance(dip);

		/*
		 * Allocate and initialize soft state structure
		 */
		if (ddi_soft_state_zalloc(ppm_statep, ppm_inst) != 0)
			return (DDI_FAILURE);
		unitp = ddi_get_soft_state(ppm_statep, ppm_inst);
		mutex_init(&unitp->unit_lock, NULL, MUTEX_DRIVER, NULL);
		mutex_init(&unitp->creator_lock, NULL, MUTEX_DRIVER, NULL);

		if (ddi_create_minor_node(dip, "ppm", S_IFCHR,
		    ppm_inst, "ddi_ppm", 0) == DDI_FAILURE) {
			ddi_soft_state_free(ppm_statep, ppm_inst);
			DPRINTF(D_ERROR,
			    ("%s: Can't create minor for 0x%p\n", str,
			    (void *)dip));
			return (DDI_FAILURE);
		}
		ddi_report_dev(dip);
		unitp->dip = dip;

		if (retval = ppm_create_db(dip))
			return (retval);

		/*
		 * Map all of the registers under the ppm node.
		 */
		if (xcppm_map_all_regs(dip) != DDI_SUCCESS)
			return (DDI_FAILURE);

		if ((retval =
		    pm_register_ppm(ppm_claim_dev, dip)) != DDI_SUCCESS) {
			DPRINTF(D_ERROR,
			    ("%s: can't register ppm handler\n", str));
			return (retval);
		}

		for (dompp = ppm_domains; *dompp; dompp++)
			mutex_init(&(*dompp)->lock, NULL, MUTEX_DRIVER, NULL);

		break;

	case DDI_RESUME:
		unitp = ddi_get_soft_state(ppm_statep, ppm_inst);
		mutex_enter(&unitp->unit_lock);
		unitp->state &= ~XCPPM_ST_SUSPENDED;
		mutex_exit(&unitp->unit_lock);
		break;

	default:
		cmn_err(CE_CONT, "xcppm_attach: unknown "
		    "attach command %d, dip 0x%p\n", cmd, (void *)dip);
		retval = DDI_FAILURE;
	}

	return (retval);
}


/*
 * set the front panel LED:
 * PPM_LEDON turns it on, PPM_LEDOFF turns it off.
 * for GPIO register: 0x0 means led-on, 0x2 means led-off.
 */
static void
xcppm_set_led(int action)
{
	xcppm_unit_t *unitp;
	uint8_t	reg;

	ASSERT(action == PPM_LEDON || action == PPM_LEDOFF);
	DPRINTF(D_LED, ("xcppm_set_led: Turn LED %s\n",
	    (action == PPM_LEDON) ? "on" : "off"));

	unitp = ddi_get_soft_state(ppm_statep, ppm_inst);
	reg = XCPPM_GET8(unitp->hndls.gpio_data_ports,
	    unitp->regs.gpio_port1_data);
	if (action == PPM_LEDON)
		reg &= ~LED;
	else
		reg |= LED;
	XCPPM_SETGET8(unitp->hndls.gpio_data_ports,
	    unitp->regs.gpio_port1_data, reg);
}


static void
xcppm_blink_led(void *action)
{
	xcppm_unit_t *unitp;
	int new_action;
	clock_t intvl;

	unitp = ddi_get_soft_state(ppm_statep, ppm_inst);
	mutex_enter(&unitp->unit_lock);
	if (unitp->led_tid == 0) {
		mutex_exit(&unitp->unit_lock);
		return;
	}

	if ((int)(uintptr_t)action == PPM_LEDON) {
		new_action = PPM_LEDOFF;
		intvl = PPM_LEDOFF_INTERVAL;
	} else {
		ASSERT((int)(uintptr_t)action == PPM_LEDOFF);
		new_action = PPM_LEDON;
		intvl = PPM_LEDON_INTERVAL;
	}

	xcppm_set_led(new_action);
	unitp->led_tid = timeout(xcppm_blink_led, (void *)(uintptr_t)new_action,
	    intvl);
	mutex_exit(&unitp->unit_lock);
}


static void
xcppm_freeze_led(void *action)
{
	xcppm_unit_t *unitp;
	timeout_id_t tid;

	DPRINTF(D_LOWEST, ("xcppm_freeze_led: action %d\n",
	    (int)(uintptr_t)action));
	unitp = ddi_get_soft_state(ppm_statep, ppm_inst);
	mutex_enter(&unitp->unit_lock);
	tid = unitp->led_tid;
	unitp->led_tid = 0;
	mutex_exit(&unitp->unit_lock);
	(void) untimeout(tid);
	mutex_enter(&unitp->unit_lock);
	xcppm_set_led((int)(uintptr_t)action);
	mutex_exit(&unitp->unit_lock);
}


/* ARGSUSED */
static int
xcppm_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	xcppm_unit_t *unitp;

	unitp = ddi_get_soft_state(ppm_statep, ppm_inst);
	DPRINTF(D_DETACH, ("xcppm_detach: cmd %d\n", cmd));

	switch (cmd) {
	case DDI_DETACH:
		return (DDI_FAILURE);

	case DDI_SUSPEND:
		mutex_enter(&unitp->unit_lock);
		unitp->state |= XCPPM_ST_SUSPENDED;
		mutex_exit(&unitp->unit_lock);

		/*
		 * Suspend requires that timeout callouts to be canceled.
		 * Turning off the LED blinking will cancel the timeout.
		 */
		xcppm_freeze_led((void *)PPM_LEDON);
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}
}


/*
 * Device we claimed has detached.  We must get rid of
 * our state which was used to track this device.
 */
static void
xcppm_detach_ctlop(dev_info_t *dip, power_req_t *reqp)
{
	ppm_dev_t *ppmd;

	ppmd = PPM_GET_PRIVATE(dip);
	if (ppmd == NULL || reqp->req.ppm_config_req.result != DDI_SUCCESS)
		return;

	ppm_rem_dev(dip);
}


/*
 * The system is being resumed from a cpr suspend operation and this
 * device's attach entry will be called shortly.  The driver will set
 * the device's power to a conventional starting value, and we need to
 * stay in sync and set our private copy to the same value.
 */
/* ARGSUSED */
static void
xcppm_resume_ctlop(dev_info_t *dip, power_req_t *reqp)
{
	ppm_domain_t *domp;
	ppm_dev_t *ppmd;
	int powered;

	ppmd = PPM_GET_PRIVATE(dip);
	if (ppmd == NULL)
		return;

	/*
	 * Maintain correct powered count for domain which cares
	 */
	powered = 0;
	domp = ppmd->domp;
	mutex_enter(&domp->lock);
	if (domp == &xcppm_fet) {
		for (ppmd = domp->devlist; ppmd; ppmd = ppmd->next) {
			if (ppmd->dip == dip && ppmd->level)
				powered++;
		}

		/*
		 * If this device was powered off when the system was
		 * suspended, this resume acts like a power-on transition,
		 * so we adjust the count.
		 */
		if (powered == 0)
			domp->pwr_cnt++;
	}

	for (ppmd = domp->devlist; ppmd; ppmd = ppmd->next) {
		if (ppmd->dip == dip)
			ppmd->level = ppmd->rplvl = PM_LEVEL_UNKNOWN;
	}
	mutex_exit(&domp->lock);
}


/*
 * Change the power level for a component of a device.  If the change
 * arg is true, we call the framework to actually change the device's
 * power; otherwise, we just update our own copy of the power level.
 */
static int
xcppm_set_level(ppm_dev_t *ppmd, int cmpt, int level, boolean_t change)
{
#ifdef DEBUG
	char *str = "xcppm_set_level";
#endif
	int ret;

	ret = DDI_SUCCESS;
	if (change)
		ret = pm_power(ppmd->dip, cmpt, level);

	DPRINTF(D_SETLVL, ("%s: \"%s\" change=%d, old %d, new %d, ret %d\n",
	    str, ppmd->path, change, ppmd->level, level, ret));

	if (ret == DDI_SUCCESS) {
		ppmd->level = level;
		ppmd->rplvl = PM_LEVEL_UNKNOWN;
	}

	return (ret);
}


static int
xcppm_change_power_level(ppm_dev_t *ppmd, int cmpt, int level)
{
	return (xcppm_set_level(ppmd, cmpt, level, B_TRUE));
}


static int
xcppm_record_level_change(ppm_dev_t *ppmd, int cmpt, int level)
{
	return (xcppm_set_level(ppmd, cmpt, level, B_FALSE));
}


static uint8_t
xcppm_gpio_port2(int action, uint8_t pos)
{
#ifdef DEBUG
	char *str = "xcppm_gpio_port2";
#endif
	xcppm_unit_t *unitp;
	uint8_t data8, buf8;
	uint8_t	ret;

	unitp = ddi_get_soft_state(ppm_statep, ppm_inst);
	mutex_enter(&unitp->gpio_lock);

	data8 = buf8 = XCPPM_GET8(unitp->hndls.gpio_data_ports,
	    unitp->regs.gpio_port2_data);

	switch (action) {
	case XCPPM_GETBIT:
		ret = data8 & pos;
		DPRINTF(D_GPIO, ("%s: READ: GPIO Bank2 value 0x%x\n",
		    str, buf8));
		break;

	case XCPPM_SETBIT:
	case XCPPM_CLRBIT:
		if (action == XCPPM_SETBIT)
			data8 |= pos;
		else
			data8 &= ~pos;
		XCPPM_SETGET8(unitp->hndls.gpio_data_ports,
		    unitp->regs.gpio_port2_data, data8);
		ret = data8 & pos;
		DPRINTF(D_GPIO, ("%s: %s: GPIO Bank2 "
		    "bit 0x%x changed from 0x%x to 0x%x\n",
		    str, (action == XCPPM_SETBIT) ? "UP" : "DOWN",
		    pos, buf8, data8));
		break;

	default:
		cmn_err(CE_PANIC, "xcalppm: unrecognized register "
		    "IO command %d\n", action);
		break;
	}
	mutex_exit(&unitp->gpio_lock);

	return (ret);
}


/*
 * Raise the power level of a subrange of cpus.  Used when cpu driver
 * failed an attempt to lower the power of a cpu (probably because
 * it got busy).  Need to revert the ones we already changed.
 *
 * ecpup = the ppm_dev_t for the cpu which failed to lower power
 * level = power level to reset prior cpus to
 */
static void
xcppm_revert_cpu_power(ppm_dev_t *ecpup, int level)
{
	ppm_dev_t *cpup;

	for (cpup = xcppm_cpu.devlist; cpup != ecpup; cpup = cpup->next) {
		DPRINTF(D_CPU, ("xrcp: \"%s\", revert to level %d\n",
		    cpup->path, level));
		(void) xcppm_change_power_level(cpup, 0, level);
	}
}

/*
 * Switch the DC/DC converter.  Clearing the GPIO bit in SuperI/O puts
 * the converter in low power mode and setting the bit puts it back in
 * normal mode.
 */
static void
xcppm_switch_dcdc_converter(int action)
{
	int tries = XCPPM_VCL_TRIES;
	uint_t spl;
	uint64_t stick_begin, stick_end;
	uint64_t tick_begin, tick_end;
	uint64_t cur_speed_ratio, full_speed_ratio;
	static int xcppm_dcdc_lpm;

	switch (action) {
	case XCPPM_SETBIT:
		if (xcppm_dcdc_lpm) {
			DPRINTF(D_CPU, ("xcppm_switch_dcdc_converter: "
			    "switch to normal power mode.\n"));
			(void) xcppm_gpio_port2(action, HIGHPWR);
			xcppm_dcdc_lpm = 0;
		}
		break;
	case XCPPM_CLRBIT:
		/*
		 * In some fast CPU configurations, DC/DC converter was
		 * put in low power mode before CPUs made the transition
		 * to 1/32 of clock speed.  In those cases, system was
		 * shut down by hardware for protection.  To resolve that
		 * problem, we make sure CPUs have made the clock transition
		 * before the DC/DC converter has been put to low power mode.
		 */
		ASSERT(xcppm_dcdc_lpm == 0);
		kpreempt_disable();
		full_speed_ratio = cpunodes[CPU->cpu_id].clock_freq /
		    sys_tick_freq;
		while (tries) {
			spl = ddi_enter_critical();
			tick_begin = gettick_counter();
			stick_timestamp((int64_t *)&stick_begin);
			ddi_exit_critical(spl);
			drv_usecwait(XCPPM_VCL_DELAY);
			spl = ddi_enter_critical();
			tick_end = gettick_counter();
			stick_timestamp((int64_t *)&stick_end);
			ddi_exit_critical(spl);
			cur_speed_ratio = (tick_end - tick_begin) /
			    (stick_end - stick_begin);

			/*
			 * tick/stick at current speed should at most be
			 * equal to full-speed tick/stick, adjusted with
			 * full/lowest clock speed ratio.  If not, speed
			 * transition has not happened yet.
			 */
			if (cur_speed_ratio <= ((full_speed_ratio /
			    XCPPM_VCL_DIVISOR) + 1)) {
				DPRINTF(D_CPU, ("xcppm_switch_dcdc_converter: "
				    "switch to low power mode.\n"));
				(void) xcppm_gpio_port2(action, HIGHPWR);
				xcppm_dcdc_lpm = 1;
				break;
			}
			DPRINTF(D_CPU, ("xcppm_switch_dcdc_converter: CPU "
			    "has not made transition to lowest speed yet "
			    "(%d)\n", tries));
			tries--;
		}
		kpreempt_enable();
		break;
	}
}

static void
xcppm_rio_mode(xcppm_unit_t *unitp, int mode)
{
	uint32_t data32, buf32;

	mutex_enter(&unitp->gpio_lock);
	data32 = buf32 = XCPPM_GET32(unitp->hndls.rio_mode_auxio,
	    unitp->regs.rio_mode_auxio);
	if (mode == XCPPM_SETBIT)
		data32 |= RIO_BBC_ESTAR_MODE;
	else
		data32 &= ~RIO_BBC_ESTAR_MODE;
	XCPPM_SETGET32(unitp->hndls.rio_mode_auxio,
	    unitp->regs.rio_mode_auxio, data32);
	mutex_exit(&unitp->gpio_lock);

	DPRINTF(D_CPU, ("xcppm_rio_mode: %s: change from 0x%x to 0x%x\n",
	    (mode == XCPPM_SETBIT) ? "DOWN" : "UP", buf32, data32));
}


/*
 * change the power level of all cpus to the arg value;
 * the caller needs to ensure that a legal transition is requested.
 */
static int
xcppm_change_cpu_power(int newlevel)
{
#ifdef DEBUG
	char *str = "xcppm_ccp";
#endif
	int index, level, oldlevel;
	int lowest, highest;
	int undo_flag, ret;
	int speedup, incr;
	uint32_t data32;
	uint16_t data16;
	xcppm_unit_t *unitp;
	ppm_dev_t *cpup;
	dev_info_t *dip;
	char *chstr;

	unitp = ddi_get_soft_state(ppm_statep, ppm_inst);
	ASSERT(unitp);
	cpup = xcppm_cpu.devlist;
	lowest = cpup->lowest;
	highest = cpup->highest;

	/*
	 * not all cpus may have transitioned to a known level by this time
	 */
	oldlevel = (cpup->level == PM_LEVEL_UNKNOWN) ? highest : cpup->level;
	dip = cpup->dip;
	ASSERT(dip);

	DPRINTF(D_CPU, ("%s: old %d, new %d, highest %d, lowest %d\n",
	    str, oldlevel, newlevel, highest, lowest));

	if (newlevel > oldlevel) {
		chstr = "UP";
		speedup = 1;
		incr = 1;
	} else if (newlevel < oldlevel) {
		chstr = "DOWN";
		speedup = 0;
		incr = -1;
	} else
		return (DDI_SUCCESS);

	undo_flag = 0;
	if (speedup) {
		/*
		 * If coming up from lowest power level, set the E*
		 * mode bit in GPIO to make power supply efficient
		 * at normal power.
		 */
		if (oldlevel == cpup->lowest) {
			xcppm_switch_dcdc_converter(XCPPM_SETBIT);
			undo_flag = 1;
		}
	} else {
		/*
		 * set BBC Estar mode bit in RIO AUXIO register
		 */
		if (oldlevel == highest) {
			xcppm_rio_mode(unitp, XCPPM_SETBIT);
			undo_flag = 1;
		}
	}

	/*
	 * this loop will execute 1x or 2x depending on
	 * number of times we need to change clock rates
	 */
	for (level = oldlevel+incr; level != newlevel+incr; level += incr) {
		for (cpup = xcppm_cpu.devlist; cpup; cpup = cpup->next) {
			if (cpup->level == level)
				continue;
			ret = xcppm_change_power_level(cpup, 0, level);
			DPRINTF(D_CPU, ("%s: \"%s\", %s to level %d, ret %d\n",
			    str, cpup->path, chstr, cpup->level, ret));
			if (ret == DDI_SUCCESS)
				continue;

			/*
			 * if the driver was unable to lower cpu speed,
			 * the cpu probably got busy; set the previous
			 * cpus back to the original level
			 */
			if (speedup == 0)
				xcppm_revert_cpu_power(cpup, level + 1);

			if (undo_flag) {
				if (speedup)
					xcppm_switch_dcdc_converter(
					    XCPPM_CLRBIT);
				else
					xcppm_rio_mode(unitp, XCPPM_CLRBIT);
			}
			return (ret);
		}

		index = level - 1;
		spm_change_schizo_speed(index);
		DPRINTF(D_CPU, ("%s: safari config reg changed\n", str));

		/*
		 * set the delay times for changing to this rate
		 */
		data32 = XCPPM_BBC_DELAY(index);
		XCPPM_SETGET32(unitp->hndls.bbc_estar_ctrl,
		    (caddr_t)unitp->regs.bbc_assert_change, data32);
		DPRINTF(D_CPU, ("%s: %s: Wrote E* Assert Change Time "
		    "(t1) = 0x%x\n", str, chstr, data32));

		data32 = XCPPM_BBC_DELAY(index);
		XCPPM_SETGET32(unitp->hndls.bbc_estar_ctrl,
		    (caddr_t)unitp->regs.bbc_pll_settle, data32);
		DPRINTF(D_CPU, ("%s: %s: Wrote E* PLL Settle Time "
		    "(t4) = 0x%x\n", str, chstr, data32));

		data16 = bbc_estar_control_masks[index];
		XCPPM_SETGET16(unitp->hndls.bbc_estar_ctrl,
		    (caddr_t)unitp->regs.bbc_estar_ctrl, data16);
		DPRINTF(D_CPU, ("%s: %s: Wrote BCC E* Control = 0x%x\n",
		    str, chstr, data16));
	}

	/*
	 * clear CPU Estar Mode bit in the gpio register
	 */
	if (speedup) {
		if (newlevel == highest)
			xcppm_rio_mode(unitp, XCPPM_CLRBIT);
	} else {
		if (newlevel == lowest)
			xcppm_switch_dcdc_converter(XCPPM_CLRBIT);
	}

	return (DDI_SUCCESS);
}


/*
 * Process a request to change the power level of a cpu.  If all cpus
 * don't want to be at the same power yet, or if we are currently
 * refusing slowdown requests due to thermal stress, just cache the
 * request.  Otherwise, make the change for all cpus.
 */
/* ARGSUSED */
static int
xcppm_manage_cpus(dev_info_t *dip, power_req_t *reqp, int *result)
{
#ifdef DEBUG
	char *str = "xcppm_manage_cpus";
#endif
	int old, new, ret, kmflag;
	ppm_dev_t *ppmd;
	pm_ppm_devlist_t *devlist = NULL, *p;
	int		do_rescan = 0;
	dev_info_t	*rescan_dip;

	*result = DDI_SUCCESS;
	switch (reqp->request_type) {
	case PMR_PPM_SET_POWER:
		break;
	case PMR_PPM_POWER_CHANGE_NOTIFY:
		/* cpu driver can`t change cpu power level by itself */
	default:
		return (DDI_FAILURE);
	}

	ppmd = PPM_GET_PRIVATE(dip);
	ASSERT(MUTEX_HELD(&ppmd->domp->lock));
	old = reqp->req.ppm_set_power_req.old_level;
	new = reqp->req.ppm_set_power_req.new_level;

	/*
	 * At power on, the cpus are at full speed.  There is no hardware
	 * transition needed for going from unknown to full.  However, the
	 * state of the pm framework and cpu driver needs to be adjusted.
	 */
	if (ppmd->level == PM_LEVEL_UNKNOWN && new == ppmd->highest) {
		*result = ret = xcppm_change_power_level(ppmd, 0, new);
		if (ret != DDI_SUCCESS) {
			DPRINTF(D_CPU, ("%s: Failed to change "
			    "power level to %d\n", str, new));
		}
		return (ret);
	}

	if (new == ppmd->level) {
		DPRINTF(D_CPU, ("%s: already at power level %d\n", str, new));
		return (DDI_SUCCESS);
	}

	ppmd->rplvl = new;

	/*
	 * A request from lower to higher level transition is granted and
	 * made effective on both cpus. For more than two cpu platform model,
	 * the following code needs to be modified to remember the rest of
	 * the unsoliciting cpus to be rescan'ed.
	 * A request from higher to lower must be agreed by all cpus.
	 */
	for (ppmd = xcppm_cpu.devlist; ppmd; ppmd = ppmd->next) {
		if (ppmd->rplvl == new)
			continue;

		if (new < old) {
			DPRINTF(D_SOME, ("%s: not all cpus want to go down to "
			    "level %d yet\n", str, new));
			return (DDI_SUCCESS);
		}

		/*
		 * If a single cpu requests power up, honor the request
		 * by powering up both cpus.
		 */
		if (new > old) {
			DPRINTF(D_SOME, ("%s: powering up device(%s@%s, %p) "
			    "because of request from dip(%s@%s, %p), "
			    "need pm_rescan\n", str, PM_NAME(ppmd->dip),
			    PM_ADDR(ppmd->dip), (void *)ppmd->dip,
			    PM_NAME(dip), PM_ADDR(dip), (void *)dip))
			do_rescan++;
			rescan_dip = ppmd->dip;
			break;
		}
	}

	ret = xcppm_change_cpu_power(new);
	*result = ret;

	if (ret == DDI_SUCCESS) {
		if (reqp->req.ppm_set_power_req.canblock == PM_CANBLOCK_BLOCK)
			kmflag = KM_SLEEP;
		else
			kmflag = KM_NOSLEEP;

		for (ppmd = xcppm_cpu.devlist; ppmd; ppmd = ppmd->next) {
			if (ppmd->dip == dip)
				continue;

			if ((p = kmem_zalloc(sizeof (pm_ppm_devlist_t),
			    kmflag)) == NULL) {
				break;
			}
			p->ppd_who = ppmd->dip;
			p->ppd_cmpt = ppmd->cmpt;
			p->ppd_old_level = old;
			p->ppd_new_level = new;
			p->ppd_next = devlist;

			devlist = p;
		}
		reqp->req.ppm_set_power_req.cookie = (void *) devlist;

		if (do_rescan > 0)
			pm_rescan(rescan_dip);
	}

	return (ret);
}


/*
 * If powering off and all devices in this domain will now be off,
 * shut off common power.  If powering up and no devices up yet,
 * turn on common power.  Always make the requested power level
 * change for the target device.
 */
static int
xcppm_manage_fet(dev_info_t *dip, power_req_t *reqp, int *result)
{
#ifdef DEBUG
	char *str = "xcppm_manage_fet";
#endif
	int (*pwr_func)(ppm_dev_t *, int, int);
	int new, old, cmpt, incr = 0;
	ppm_dev_t *ppmd;

	ppmd = PPM_GET_PRIVATE(dip);
	DPRINTF(D_FET, ("%s: \"%s\", req %s\n", str,
	    ppmd->path, ppm_get_ctlstr(reqp->request_type, ~0)));

	*result = DDI_SUCCESS;	/* change later for failures */
	switch (reqp->request_type) {
	case PMR_PPM_SET_POWER:
		pwr_func = xcppm_change_power_level;
		old = reqp->req.ppm_set_power_req.old_level;
		new = reqp->req.ppm_set_power_req.new_level;
		cmpt = reqp->req.ppm_set_power_req.cmpt;
		break;
	case PMR_PPM_POWER_CHANGE_NOTIFY:
		pwr_func = xcppm_record_level_change;
		old = reqp->req.ppm_notify_level_req.old_level;
		new = reqp->req.ppm_notify_level_req.new_level;
		cmpt = reqp->req.ppm_notify_level_req.cmpt;
		break;
	default:
		return (*result = DDI_FAILURE);

	}

	/* This is common code for SET_POWER and POWER_CHANGE_NOTIFY cases */
	DPRINTF(D_FET, ("%s: \"%s\", old %d, new %d\n",
	    str, ppmd->path, old, new));

	ASSERT(old == ppmd->level);
	if (new == ppmd->level)
		return (DDI_SUCCESS);

	PPM_LOCK_DOMAIN(ppmd->domp);
	/*
	 * Devices in this domain are known to have 0 (off) as their
	 * lowest power level.  We use this fact to simplify the logic.
	 */
	if (new > 0) {
		if (ppmd->domp->pwr_cnt == 0)
			(void) xcppm_gpio_port2(XCPPM_SETBIT, DRVON);
		if (old == 0) {
			ppmd->domp->pwr_cnt++;
			incr = 1;
			DPRINTF(D_FET, ("%s: UP cnt = %d\n",
			    str, ppmd->domp->pwr_cnt));
		}
	}

	PPM_UNLOCK_DOMAIN(ppmd->domp);

	ASSERT(ppmd->domp->pwr_cnt > 0);

	if ((*result = (*pwr_func)(ppmd, cmpt, new)) != DDI_SUCCESS) {
		DPRINTF(D_FET, ("%s: \"%s\" power change failed \n",
		    str, ppmd->path));
	}

	PPM_LOCK_DOMAIN(ppmd->domp);

	/*
	 * Decr the power count in two cases:
	 *
	 *   1) request was to power device down and was successful
	 *   2) request was to power up (we pre-incremented count), but failed.
	 */
	if ((*result == DDI_SUCCESS && ppmd->level == 0) ||
	    (*result != DDI_SUCCESS && incr)) {
		ASSERT(ppmd->domp->pwr_cnt > 0);
		ppmd->domp->pwr_cnt--;
		DPRINTF(D_FET, ("%s: DN cnt = %d\n", str, ppmd->domp->pwr_cnt));
		if (ppmd->domp->pwr_cnt == 0)
			(void) xcppm_gpio_port2(XCPPM_CLRBIT, DRVON);
	}

	PPM_UNLOCK_DOMAIN(ppmd->domp);
	ASSERT(ppmd->domp->pwr_cnt >= 0);
	return (*result == DDI_SUCCESS ? DDI_SUCCESS : DDI_FAILURE);
}


/*
 * Since UPA64S relies on PCI B staying at nominal 33MHz in order to
 * have its interrupt pulse function properly, we ensure
 * - Lowering PCI B only if UPA64S is at low power, otherwise defer
 *   the action until UPA64S goes down; hence right after UPA64S goes
 *   down, perform the deferred action for PCI B;
 * - Always raise PCI B power prior to raising UPA64S power.
 *
 * Both UPA64S and PCI B devices are considered each other's dependency
 * device whenever actual power transition is handled (PMR_PPM_SET_POWER).
 */
static int
xcppm_manage_pciupa(dev_info_t *dip, power_req_t *reqp, int *result)
{
#ifdef DEBUG
	char *str = "xcppm_manage_pciupa";
#endif
	int (*pwr_func)(ppm_dev_t *, int, int);
	uint_t flags = 0, co_flags = 0;
	ppm_dev_t *ppmd, *codev;
	int new, cmpt, retval;

	ppmd = PPM_GET_PRIVATE(dip);
	DPRINTF(D_PCIUPA, ("%s: \"%s\", req %s\n", str,
	    ppmd->path, ppm_get_ctlstr(reqp->request_type, ~0)));

	*result = DDI_SUCCESS;

	switch (reqp->request_type) {
	case PMR_PPM_SET_POWER:
		pwr_func = xcppm_change_power_level;
		new = reqp->req.ppm_set_power_req.new_level;
		cmpt = reqp->req.ppm_set_power_req.cmpt;
		break;
	case PMR_PPM_POWER_CHANGE_NOTIFY:
		pwr_func = xcppm_record_level_change;
		new = reqp->req.ppm_notify_level_req.new_level;
		cmpt = reqp->req.ppm_notify_level_req.cmpt;
		break;
	default:
		*result = DDI_FAILURE;
		return (DDI_FAILURE);
	}

	/* Common code for SET_POWER and POWER_CHANGE_NOTIFY cases */
	ASSERT(ppmd);	/* since it should be locked already */

	if (new == ppmd->level)
		return (DDI_SUCCESS);

	DPRINTF(D_PCIUPA, ("%s: \"%s\", levels: current %d, new %d\n",
	    str, ppmd->path, ppmd->level, new));

	/*
	 * find power-wise co-related device
	 */
	flags =  ppmd->flags;

#ifdef DEBUG
	if (flags & ~(XCPPMF_PCIB|XCPPMF_UPA))
		DPRINTF(D_ERROR, ("%s: invalid ppmd->flags value 0x%x\n", str,
		    ppmd->flags));
#endif

	if (flags == XCPPMF_UPA)
		co_flags = XCPPMF_PCIB;
	else if (flags == XCPPMF_PCIB)
		co_flags = XCPPMF_UPA;

	for (codev = ppmd->domp->devlist; codev; codev = codev->next)
		if ((codev->cmpt == 0) && (codev->flags == co_flags))
			break;

	if (new > ppmd->level) {
		/*
		 * Raise power level -
		 * pre-raising: upa ensure pci is powered up.
		 */
		if ((flags == XCPPMF_UPA) && codev &&
		    (codev->level != codev->highest)) {
			if ((retval = xcppm_change_power_level(codev,
			    0, codev->highest)) != DDI_SUCCESS &&
			    codev->level != codev->highest) {
				*result = retval;
				return (DDI_FAILURE);
			}
		}
		if ((retval = (*pwr_func)(ppmd, 0, new)) != DDI_SUCCESS) {
			*result = retval;
			return (DDI_FAILURE);
		}
	} else if (new < ppmd->level) {
		/*
		 * Lower power level
		 *
		 * once upa is attached, pci checks upa level:
		 * if upa is at high level, defer the request and return.
		 * otherwise, set power level then check and lower pci level.
		 */
		if ((flags == XCPPMF_PCIB) && codev &&
		    (codev->level != codev->lowest)) {
			ppmd->rplvl = new;
			return (DDI_SUCCESS);
		}
		if ((retval = (*pwr_func)(ppmd, cmpt, new)) != DDI_SUCCESS &&
		    ppmd->level != new) {
			*result = retval;
			return (DDI_FAILURE);
		}

		if (flags == XCPPMF_UPA) {
			if (codev && (codev->rplvl != PM_LEVEL_UNKNOWN) &&
			    (codev->rplvl < codev->level)) {
				DPRINTF(D_PCIUPA, ("%s: codev \"%s\" "
				    "rplvl %d level %d\n", str, codev->path,
				    codev->rplvl, codev->level));
				if ((retval = xcppm_change_power_level(
				    codev, 0, codev->rplvl)) != DDI_SUCCESS) {
					*result = retval;
					return (DDI_FAILURE);
				}
			}
		}
	}

	return (DDI_SUCCESS);
}


/*
 * When all of the children of the 1394 nexus are idle, a call will be
 * made to the nexus driver's own power entry point to lower power.  Ppm
 * intercepts this and kills 1394 cable power (since the driver doesn't
 * have access to the required register).  Similar logic applies when
 * coming up from the state where all the children were off.
 */
static int
xcppm_manage_1394(dev_info_t *dip, power_req_t *reqp, int *result)
{
#ifdef DEBUG
	char *str = "xcppm_manage_1394";
#endif
	int (*pwr_func)(ppm_dev_t *, int, int);
	int new, old, cmpt;
	ppm_dev_t *ppmd;

	ppmd = PPM_GET_PRIVATE(dip);
	DPRINTF(D_1394, ("%s: \"%s\", req %s\n", str,
	    ppmd->path, ppm_get_ctlstr(reqp->request_type, ~0)));

	switch (reqp->request_type) {
	case PMR_PPM_SET_POWER:
		pwr_func = xcppm_change_power_level;
		old = reqp->req.ppm_set_power_req.old_level;
		new = reqp->req.ppm_set_power_req.new_level;
		cmpt = reqp->req.ppm_set_power_req.cmpt;
		break;
	case PMR_PPM_POWER_CHANGE_NOTIFY:
		pwr_func = xcppm_record_level_change;
		old = reqp->req.ppm_notify_level_req.old_level;
		new = reqp->req.ppm_notify_level_req.new_level;
		cmpt = reqp->req.ppm_notify_level_req.cmpt;
		break;
	default:
		return (*result = DDI_FAILURE);
	}


	/* Common code for SET_POWER and POWER_CHANGE_NOTIFY cases */
	DPRINTF(D_1394, ("%s: dev %s@%s, old %d new %d\n", str,
	    ddi_binding_name(dip), ddi_get_name_addr(dip), old, new));

	ASSERT(ppmd);	/* since it must already be locked */
	ASSERT(old == ppmd->level);

	if (new == ppmd->level)
		return (*result = DDI_SUCCESS);

	/* the reduce power case */
	if (cmpt == 0 && new < ppmd->level) {
		if ((*result =
		    (*pwr_func)(ppmd, cmpt, new)) != DDI_SUCCESS) {
			return (DDI_FAILURE);
		}
		if (new == ppmd->lowest)
			(void) xcppm_gpio_port2(XCPPM_CLRBIT, CPEN);
		ppmd->level = new;
		return (DDI_SUCCESS);
	}

	/* the increase power case */
	if (cmpt == 0 && new > ppmd->level) {
		if (ppmd->level == ppmd->lowest) {
			(void) xcppm_gpio_port2(XCPPM_SETBIT, CPEN);
			delay(1);
		}
		/*
		 * Even if pwr_func fails we need to check current level again
		 * because it could have been changed by an intervening
		 * POWER_CHANGE_NOTIFY operation.
		 */
		if ((*result =
		    (*pwr_func)(ppmd, cmpt, new)) != DDI_SUCCESS &&
		    ppmd->level == ppmd->lowest) {
			(void) xcppm_gpio_port2(XCPPM_CLRBIT, CPEN);
		} else {
			ppmd->level = new;
		}

		return (*result == DDI_SUCCESS ? DDI_SUCCESS : DDI_FAILURE);
	}

	/*
	 * We get here if component was non-zero.  This is not what we
	 * expect.  Let the device deal with it and just pass back the
	 * result.
	 */
	*result = xcppm_change_power_level(ppmd, cmpt, new);
	return (*result == DDI_SUCCESS ? DDI_SUCCESS : DDI_FAILURE);
}


/*
 * lock, unlock, or trylock for one power mutex
 */
static void
xcppm_lock_one(ppm_dev_t *ppmd, power_req_t *reqp, int *iresp)
{
	switch (reqp->request_type) {
	case PMR_PPM_LOCK_POWER:
		pm_lock_power_single(ppmd->dip);
		break;

	case PMR_PPM_UNLOCK_POWER:
		pm_unlock_power_single(ppmd->dip);
		break;

	case PMR_PPM_TRY_LOCK_POWER:
		*iresp = pm_try_locking_power_single(ppmd->dip);
		break;
	}
}


/*
 * lock, unlock, or trylock all devices within a domain.
 */
static void
xcppm_lock_all(ppm_domain_t *domp, power_req_t *reqp, int *iresp)
{
	/*
	 * To simplify the implementation we let all the devices
	 * in the domain be represented by a single device (dip).
	 * We use the first device in the domain's devlist.  This
	 * is safe because we return with the domain lock held
	 * which prevents the list from changing.
	 */
	if (reqp->request_type == PMR_PPM_LOCK_POWER) {
		if (!MUTEX_HELD(&domp->lock))
			mutex_enter(&domp->lock);
		domp->refcnt++;
		ASSERT(domp->devlist != NULL);
		pm_lock_power_single(domp->devlist->dip);
		/* domain lock remains held */
		return;
	} else if (reqp->request_type == PMR_PPM_UNLOCK_POWER) {
		ASSERT(MUTEX_HELD(&domp->lock));
		ASSERT(domp->devlist != NULL);
		pm_unlock_power_single(domp->devlist->dip);
		if (--domp->refcnt == 0)
			mutex_exit(&domp->lock);
		return;
	}

	ASSERT(reqp->request_type == PMR_PPM_TRY_LOCK_POWER);
	if (!MUTEX_HELD(&domp->lock))
		if (!mutex_tryenter(&domp->lock)) {
			*iresp = 0;
			return;
		}
	*iresp = pm_try_locking_power_single(domp->devlist->dip);
	if (*iresp)
		domp->refcnt++;
	else
		mutex_exit(&domp->lock);
}


/*
 * The pm framework calls us here to manage power for a device.
 * We maintain state which tells us whether we need to turn off/on
 * system board power components based on the status of all the devices
 * sharing a component.
 *
 */
/* ARGSUSED */
static int
xcppm_ctlops(dev_info_t *dip, dev_info_t *rdip,
    ddi_ctl_enum_t ctlop, void *arg, void *result)
{
	power_req_t *reqp = arg;
	xcppm_unit_t *unitp;
	ppm_domain_t *domp;
	ppm_dev_t *ppmd;

#ifdef DEBUG
	char path[MAXPATHLEN], *ctlstr, *str = "xcppm_ctlops";
	uint_t mask = ppm_debug & (D_CTLOPS1 | D_CTLOPS2);
	if (mask && (ctlstr = ppm_get_ctlstr(reqp->request_type, mask))) {
		prom_printf("%s: \"%s\", %s\n", str,
		    ddi_pathname(rdip, path), ctlstr);
	}
#endif

	if (ctlop != DDI_CTLOPS_POWER)
		return (DDI_FAILURE);

	switch (reqp->request_type) {
	case PMR_PPM_UNMANAGE:
	case PMR_PPM_PRE_PROBE:
	case PMR_PPM_POST_PROBE:
	case PMR_PPM_PRE_ATTACH:
	case PMR_PPM_PRE_DETACH:
		return (DDI_SUCCESS);

	/*
	 * There is no hardware configuration required to be done on this
	 * platform prior to installing drivers.
	 */
	case PMR_PPM_INIT_CHILD:
	case PMR_PPM_UNINIT_CHILD:
		return (DDI_SUCCESS);

	case PMR_PPM_ALL_LOWEST:
		DPRINTF(D_LOWEST, ("%s: all devices at lowest power = %d\n",
		    str, reqp->req.ppm_all_lowest_req.mode));
		if (reqp->req.ppm_all_lowest_req.mode == PM_ALL_LOWEST) {
			unitp = ddi_get_soft_state(ppm_statep, ppm_inst);
			mutex_enter(&unitp->unit_lock);
			if (unitp->state & XCPPM_ST_SUSPENDED) {
				mutex_exit(&unitp->unit_lock);
				return (DDI_SUCCESS);
			}

			xcppm_set_led(PPM_LEDON);
			unitp->led_tid = timeout(xcppm_blink_led,
			    (void *)PPM_LEDON, PPM_LEDON_INTERVAL);
			mutex_exit(&unitp->unit_lock);
			DPRINTF(D_LOWEST, ("%s: LED blink started\n", str));
		} else {
			xcppm_freeze_led((void *)PPM_LEDON);
			DPRINTF(D_LOWEST, ("%s: LED freeze ON\n", str));
		}
		return (DDI_SUCCESS);

	case PMR_PPM_POST_ATTACH:
		/*
		 * After a successful attach, if we haven't already created
		 * our private data structure for this device, ppm_get_dev()
		 * will force it to be created.
		 */
		ppmd = PPM_GET_PRIVATE(rdip);
		if (reqp->req.ppm_config_req.result != DDI_SUCCESS) {
			if (ppmd)
				ppm_rem_dev(rdip);
		} else if (!ppmd) {
			domp = ppm_lookup_dev(rdip);
			ASSERT(domp);
			(void) ppm_get_dev(rdip, domp);
		}
		return (DDI_SUCCESS);

	case PMR_PPM_POST_DETACH:
		xcppm_detach_ctlop(rdip, reqp);
		*(int *)result = DDI_SUCCESS;
		return (DDI_SUCCESS);

	case PMR_PPM_PRE_RESUME:
		xcppm_resume_ctlop(rdip, reqp);
		return (DDI_SUCCESS);

	case PMR_PPM_UNLOCK_POWER:
	case PMR_PPM_TRY_LOCK_POWER:
	case PMR_PPM_LOCK_POWER:
		ppmd = PPM_GET_PRIVATE(rdip);
		if (ppmd)
			domp = ppmd->domp;
		else if (reqp->request_type != PMR_PPM_UNLOCK_POWER) {
			domp = ppm_lookup_dev(rdip);
			ASSERT(domp);
			ppmd = ppm_get_dev(rdip, domp);
		}

		ASSERT(domp->dflags == PPMD_LOCK_ALL ||
		    domp->dflags == PPMD_LOCK_ONE);
		DPRINTF(D_LOCKS, ("xcppm_lock_%s: \"%s\", %s\n",
		    (domp->dflags == PPMD_LOCK_ALL) ? "all" : "one",
		    ppmd->path, ppm_get_ctlstr(reqp->request_type, D_LOCKS)));

		if (domp->dflags == PPMD_LOCK_ALL)
			xcppm_lock_all(domp, reqp, result);
		else
			xcppm_lock_one(ppmd, reqp, result);
		return (DDI_SUCCESS);

	case PMR_PPM_POWER_LOCK_OWNER:
		ASSERT(reqp->req.ppm_power_lock_owner_req.who == rdip);
		ppmd = PPM_GET_PRIVATE(rdip);
		if (ppmd)
			domp = ppmd->domp;
		else {
			domp = ppm_lookup_dev(rdip);
			ASSERT(domp);
			ppmd = ppm_get_dev(rdip, domp);
		}

		/*
		 * In case of LOCK_ALL, effective owner of the power lock
		 * is the owner of the domain lock. otherwise, it is the owner
		 * of the power lock.
		 */
		if (domp->dflags & PPMD_LOCK_ALL)
			reqp->req.ppm_power_lock_owner_req.owner =
			    mutex_owner(&domp->lock);
		else {
			reqp->req.ppm_power_lock_owner_req.owner =
			    DEVI(rdip)->devi_busy_thread;
		}
		return (DDI_SUCCESS);

	default:
		ppmd = PPM_GET_PRIVATE(rdip);
		if (ppmd == NULL) {
			domp = ppm_lookup_dev(rdip);
			ASSERT(domp);
			ppmd = ppm_get_dev(rdip, domp);
		}

#ifdef DEBUG
		if ((reqp->request_type == PMR_PPM_SET_POWER) &&
		    (ppm_debug & D_SETPWR)) {
			prom_printf("%s: \"%s\", PMR_PPM_SET_POWER\n",
			    str, ppmd->path);
		}
#endif

		if (ppmd->domp == &xcppm_cpu)
			return (xcppm_manage_cpus(rdip, reqp, result));
		else if (ppmd->domp == &xcppm_fet)
			return (xcppm_manage_fet(rdip, reqp, result));
		else if (ppmd->domp == &xcppm_upa)
			return (xcppm_manage_pciupa(rdip, reqp, result));
		else {
			ASSERT(ppmd->domp == &xcppm_1394);
			return (xcppm_manage_1394(rdip, reqp, result));
		}
	}
}


/*
 * Initialize our private version of real power level
 * as well as lowest and highest levels the device supports;
 * see ppmf and ppm_add_dev
 */
static void
xcppm_dev_init(ppm_dev_t *ppmd)
{
	struct pm_component *dcomps;
	struct pm_comp *pm_comp;
	dev_info_t *dip;
	int maxi;

	ASSERT(MUTEX_HELD(&ppmd->domp->lock));
	ppmd->level = PM_LEVEL_UNKNOWN;
	ppmd->rplvl = PM_LEVEL_UNKNOWN;

	dip = ppmd->dip;
	/*
	 * ppm exists to handle power-manageable devices which require
	 * special handling on the current platform.  However, a
	 * driver for such a device may choose not to support power
	 * management on a particular load/attach.  In this case we
	 * we create a structure to represent a single-component device
	 * for which "level" = PM_LEVEL_UNKNOWN and "lowest" = 0
	 * are effectively constant.
	 */
	if (PM_GET_PM_INFO(dip)) {
		dcomps = DEVI(dip)->devi_pm_components;
		pm_comp = &dcomps[ppmd->cmpt].pmc_comp;

		ppmd->lowest = pm_comp->pmc_lvals[0];
		ASSERT(ppmd->lowest >= 0);
		maxi = pm_comp->pmc_numlevels - 1;
		ppmd->highest = pm_comp->pmc_lvals[maxi];
	}

	/*
	 * add any domain-specific initialization here
	 */
	if (ppmd->domp == &xcppm_fet) {
		/*
		 * when a new device is added to domain_powefet
		 * it is counted here as being powered up.
		 */
		ppmd->domp->pwr_cnt++;
		DPRINTF(D_FET, ("xcppm_dev_init: UP cnt = %d\n",
		    ppmd->domp->pwr_cnt));
	} else if (ppmd->domp == &xcppm_upa) {
		/*
		 * There may be a better way to determine the device type
		 * instead of comparing to hard coded string names.
		 */
		if (strstr(ppmd->path, "pci@8,700000"))
			ppmd->flags = XCPPMF_PCIB;
		else if (strstr(ppmd->path, "upa@8,480000"))
			ppmd->flags = XCPPMF_UPA;
	}
}


/*
 * see ppmf and ppm_rem_dev
 */
static void
xcppm_dev_fini(ppm_dev_t *ppmd)
{
	ASSERT(MUTEX_HELD(&ppmd->domp->lock));
	if (ppmd->domp == &xcppm_fet) {
		if (ppmd->level != ppmd->lowest) {
			ppmd->domp->pwr_cnt--;
			DPRINTF(D_FET, ("xcppm_dev_fini: DN cnt = %d\n",
			    ppmd->domp->pwr_cnt));
		};
	}
}


/*
 * see ppmf and ppm_ioctl, PPMIOCSET
 */
static void
xcppm_iocset(uint8_t value)
{
	int action;

	if (value == PPM_IDEV_POWER_ON)
		action = XCPPM_SETBIT;
	else if (value == PPM_IDEV_POWER_OFF)
		action = XCPPM_CLRBIT;
	(void) xcppm_gpio_port2(action, DRVON);
}


/*
 * see ppmf and ppm_ioctl, PPMIOCGET
 */
static uint8_t
xcppm_iocget(void)
{
	uint8_t bit;

	bit = xcppm_gpio_port2(XCPPM_GETBIT, DRVON);
	return ((bit == DRVON) ? PPM_IDEV_POWER_ON : PPM_IDEV_POWER_OFF);
}
