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
 *	The "todds1287" module has implementation for both tod
 *	and power button (pbio) interfaces.  This driver controls
 *	RTC & APC units of National Semiconductor's 87317 SuperI/O
 *	chip.  The tod interface accesses the RTC unit and pbio
 *	interface accesses the APC unit of SuperI/O.  Since both
 *	units are implemented in the same Logical Device, registers
 *	for both units are accessible through a common set of index
 *	address & data registers.  That is why both interfaces are
 *	implemented in a same driver.
 *
 *	The APC unit is used to implement the power button.  When the
 *	button momentarily is pressed, an interrupt is generated and
 *	at the same time a Fail-safe timer starts to run.  If the
 *	timer is not stopped in 21 seconds, the power to system is
 *	turned off.  So the first task in the interrupt handler is to
 *	reset the Fail-safe timer.  Note that OBP is not clearing
 *	the Fail-safe timer due to limitation in handling interrupts,
 *	so when OBP is running, the power button should be pressed
 *	and held for 4 seconds for the power to go off, otherwise
 *	a momentarily press will delay the power-off for 21 seconds.
 *
 *	PSARC/1999/393 describes the pbio(7I) interface.
 */

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/kmem.h>
#include <sys/open.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#include <sys/todds1287.h>
#include <sys/modctl.h>
#include <sys/stat.h>
#include <sys/clock.h>
#include <sys/reboot.h>
#include <sys/machsystm.h>
#include <sys/poll.h>
#include <sys/pbio.h>

#define	ABORT_INCREMENT_DELAY	10

static timestruc_t todds_get(void);
static void todds_set(timestruc_t);
static uint_t todds_set_watchdog_timer(uint_t);
static uint_t todds_clear_watchdog_timer(void);
static void todds_set_power_alarm(timestruc_t);
static void todds_clear_power_alarm(void);
static uint64_t todds_get_cpufrequency(void);

extern uint64_t find_cpufrequency(volatile uint8_t *);

/*
 * External variables
 */
extern int	watchdog_activated;
extern uint_t	watchdog_timeout_seconds;
extern volatile uint8_t	*v_pmc_addr_reg;

/*
 * Global variables
 */
int ds1287_debug_flags;
int ds1287_caddr_warn;

/*
 * cb ops
 */
static int ds1287_open(dev_t *, int, int, cred_t *);
static int ds1287_close(dev_t, int, int, cred_t *);
static int ds1287_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);
static int ds1287_chpoll(dev_t, short, int, short *, struct pollhead **);

static void read_rtc(struct rtc_t *);
static void write_rtc_time(struct rtc_t *);
static void write_rtc_alarm(struct rtc_t *);
static void select_bank(int bank);
static uint_t ds1287_intr(caddr_t);
static uint_t ds1287_softintr(caddr_t);
static void ds1287_timeout(caddr_t);
static uint_t ds1287_issue_shutdown(caddr_t);
static void ds1287_log_message(void);

static struct cb_ops ds1287_cbops = {
	ds1287_open,			/* open */
	ds1287_close,			/* close */
	nodev,				/* strategy */
	nodev,				/* print */
	nodev,				/* dump */
	nodev,				/* read */
	nodev,				/* write */
	ds1287_ioctl,			/* ioctl */
	nodev,				/* devmap */
	nodev,				/* mmap */
	nodev,				/* segmap */
	ds1287_chpoll,			/* poll */
	ddi_prop_op,			/* cb_prop_op */
	NULL,				/* streamtab */
	D_NEW | D_MP,			/* Driver compatibility flag */
	CB_REV,				/* rev */
	nodev,				/* int (*cb_aread)() */
	nodev				/* int (*cb_awrite)() */
};

/*
 * dev ops
 */
static int ds1287_getinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int ds1287_attach(dev_info_t *, ddi_attach_cmd_t);
static int ds1287_detach(dev_info_t *, ddi_detach_cmd_t);

static struct dev_ops ds1287_ops = {
	DEVO_REV,			/* devo_rev */
	0,				/* refcnt */
	ds1287_getinfo,			/* getinfo */
	nulldev,			/* identify */
	nulldev,			/* probe */
	ds1287_attach,			/* attach */
	ds1287_detach,			/* detach */
	nodev,				/* reset */
	&ds1287_cbops,			/* cb_ops */
	(struct bus_ops *)NULL,		/* bus_ops */
	NULL,				/* power */
	ddi_quiesce_not_supported,	/* devo_quiesce */
};


static void	*ds1287_state;
static int	instance = -1;

/* Driver Tunables */
static int	ds1287_interrupt_priority = 15;
static int	ds1287_softint_priority = 2;
static hrtime_t power_button_debounce = MSEC2NSEC(10);
static hrtime_t power_button_abort_interval = 1.5 * NANOSEC;
static int	power_button_abort_presses = 3;
static int	power_button_abort_enable = 1;
static int	power_button_enable = 1;

static int	power_button_pressed = 0;
static int	power_button_cancel = 0;
static int	power_button_timeouts = 0;
static int	timeout_cancel = 0;
static int	additional_presses = 0;

static ddi_iblock_cookie_t ds1287_lo_iblock;
static ddi_iblock_cookie_t ds1287_hi_iblock;
static ddi_softintr_t	ds1287_softintr_id;
static kmutex_t ds1287_reg_mutex;	/* Protects ds1287 Registers */

static struct modldrv modldrv = {
	&mod_driverops, 	/* Type of module. This one is a driver */
	"ds1287 clock driver",	/* Name of the module. */
	&ds1287_ops,		/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1, &modldrv, NULL
};


int
_init(void)
{
	int status;

	status = ddi_soft_state_init(&ds1287_state, sizeof (struct ds1287), 0);
	if (status != 0) {
		return (status);
	}

	if ((status = mod_install(&modlinkage)) != 0) {
		ddi_soft_state_fini(&ds1287_state);
		return (status);
	}


	ds1287_hi_iblock = (ddi_iblock_cookie_t)(uintptr_t)
	    ipltospl(ds1287_interrupt_priority);
	mutex_init(&ds1287_reg_mutex, NULL, MUTEX_DRIVER, ds1287_hi_iblock);

	mutex_enter(&ds1287_reg_mutex);
	/* Select Bank 1 */
	select_bank(1);
	DS1287_ADDR_REG = RTC_B;
	DS1287_DATA_REG = (RTC_DM | RTC_HM);
	mutex_exit(&ds1287_reg_mutex);

	tod_ops.tod_get = todds_get;
	tod_ops.tod_set = todds_set;

	/*
	 * If v_pmc_addr_reg isn't set, it's because it wasn't set in
	 * sun4u/os/fillsysinfo.c:have_pmc(). This means the real (pmc)
	 * watchdog routines (sun4u/io/pmc.c) will not be used. If the
	 * user were to set watchdog_enable in /etc/system, we'll need to
	 * use our own NOP routines.
	 */
	if (v_pmc_addr_reg == NULL) {
		tod_ops.tod_set_watchdog_timer = todds_set_watchdog_timer;
		tod_ops.tod_clear_watchdog_timer = todds_clear_watchdog_timer;
	}
	tod_ops.tod_set_power_alarm = todds_set_power_alarm;
	tod_ops.tod_clear_power_alarm = todds_clear_power_alarm;
	tod_ops.tod_get_cpufrequency = todds_get_cpufrequency;

	return (status);
}

int
_fini(void)
{
	if (strcmp(tod_module_name, "todds1287") == 0)
		return (EBUSY);

	return (mod_remove(&modlinkage));
}

/*
 * The loadable-module _info(9E) entry point
 */
int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*ARGSUSED*/
static int
ds1287_getinfo(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg,
    void **result)
{
	struct ds1287 *softsp;

	if (instance == -1)
		return (DDI_FAILURE);

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		if ((softsp = ddi_get_soft_state(ds1287_state, instance))
		    == NULL)
			return (DDI_FAILURE);
		*result = (void *)softsp->dip;
		return (DDI_SUCCESS);

	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)(uintptr_t)instance;
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}
}

static int
ds1287_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	struct ds1287 *softsp;

	DPRINTF("ds1287_attach\n");
	switch (cmd) {
	case DDI_ATTACH:
		break;
	case DDI_RESUME:
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	if (instance != -1) {
		cmn_err(CE_WARN, "ds1287_attach: Another instance is already "
		    "attached.");
		return (DDI_FAILURE);
	}

	instance = ddi_get_instance(dip);

	if (v_rtc_addr_reg == NULL) {
		cmn_err(CE_WARN, "ds1287_attach: v_rtc_addr_reg is NULL");
		return (DDI_FAILURE);
	}

	/*
	 * Allocate softc information.
	 */
	if (ddi_soft_state_zalloc(ds1287_state, instance) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "ds1287_attach: Failed to allocate "
		    "soft states.");
		return (DDI_FAILURE);
	}

	softsp = ddi_get_soft_state(ds1287_state, instance);
	DPRINTF("ds1287_attach: instance=%d softsp=0x%p\n", instance,
	    (void *)softsp);

	softsp->dip = dip;

	if (ddi_prop_create(DDI_DEV_T_NONE, dip, DDI_PROP_CANSLEEP,
	    "interrupt-priorities", (caddr_t)&ds1287_interrupt_priority,
	    sizeof (int)) != DDI_PROP_SUCCESS) {
		cmn_err(CE_WARN, "ds1287_attach: Failed to create \""
		    "interrupt-priorities\" property.");
		goto error;
	}

	/* add the softint */
	ds1287_lo_iblock = (ddi_iblock_cookie_t)(uintptr_t)
	    ipltospl(ds1287_softint_priority);

	if (ddi_add_softintr(dip, DDI_SOFTINT_FIXED, &ds1287_softintr_id,
	    &ds1287_lo_iblock, NULL, ds1287_softintr, (caddr_t)softsp) !=
	    DDI_SUCCESS) {
		cmn_err(CE_WARN, "ds1287_attach: Failed to add low interrupt.");
		goto error1;
	}

	/* add the hi interrupt */
	if (ddi_add_intr(dip, 0, NULL, (ddi_idevice_cookie_t *)
	    &ds1287_hi_iblock, ds1287_intr, NULL) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "ds1287_attach: Failed to add high "
		    "interrupt.");
		goto error2;
	}

	/*
	 * Combination of instance number and clone number 0 is used for
	 * creating the minor node.
	 */
	if (ddi_create_minor_node(dip, "power_button", S_IFCHR,
	    (instance << 8) + 0, "ddi_power_button", NULL) == DDI_FAILURE) {
		cmn_err(CE_WARN, "ds1287_attach: Failed to create minor node");
		goto error3;
	}

	ddi_report_dev(dip);

	return (DDI_SUCCESS);

error3:
	ddi_remove_intr(dip, 0, NULL);
error2:
	ddi_remove_softintr(ds1287_softintr_id);
error1:
	(void) ddi_prop_remove(DDI_DEV_T_NONE, dip, "interrupt-priorities");
error:
	ddi_soft_state_free(ds1287_state, instance);
	return (DDI_FAILURE);
}

/*ARGSUSED*/
static int
ds1287_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	DPRINTF("ds1287_detach\n");
	switch (cmd) {
	case DDI_DETACH:
		/*
		 * Since it needs to always handle the power button, fail
		 * to detach.
		 */
		return (DDI_FAILURE);
	case DDI_SUSPEND:
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}
}

/*ARGSUSED1*/
static int
ds1287_open(dev_t *devp, int flags, int otyp, cred_t *credp)
{
	struct ds1287 *softsp;
	int clone;

	if (otyp != OTYP_CHR)
		return (EINVAL);

	if ((softsp = ddi_get_soft_state(ds1287_state, instance)) ==
	    NULL)
		return (ENXIO);

	mutex_enter(&softsp->ds1287_mutex);
	for (clone = 1; clone < DS1287_MAX_CLONE; clone++)
		if (!softsp->clones[clone])
			break;

	if (clone == DS1287_MAX_CLONE) {
		cmn_err(CE_WARN, "ds1287_open: No more allocation left "
		    "to clone a minor.");
		mutex_exit(&softsp->ds1287_mutex);
		return (ENXIO);
	}

	*devp = makedevice(getmajor(*devp), (instance << 8) + clone);
	softsp->clones[clone] = 1;
	mutex_exit(&softsp->ds1287_mutex);

	return (0);
}

/*ARGSUSED*/
static int
ds1287_close(dev_t dev, int flags, int otyp, cred_t *credp)
{
	struct ds1287 *softsp;
	int clone;

	if (otyp != OTYP_CHR)
		return (EINVAL);

	if ((softsp = ddi_get_soft_state(ds1287_state, instance)) ==
	    NULL)
		return (ENXIO);

	clone = DS1287_MINOR_TO_CLONE(getminor(dev));
	mutex_enter(&softsp->ds1287_mutex);
	if (softsp->monitor_on == clone)
		softsp->monitor_on = 0;
	softsp->clones[clone] = 0;
	mutex_exit(&softsp->ds1287_mutex);

	return (0);
}

/*ARGSUSED4*/
static int
ds1287_ioctl(dev_t dev, int cmd, intptr_t arg, int mode,
	cred_t *credp, int *rvalp)
{
	struct ds1287 *softsp;
	int clone;

	if ((softsp = ddi_get_soft_state(ds1287_state, instance)) ==
	    NULL)
		return (ENXIO);

	clone = DS1287_MINOR_TO_CLONE(getminor(dev));
	switch (cmd) {
	case PB_BEGIN_MONITOR:
		DPRINTF("ds1287_ioctl: PB_BEGIN_MONITOR is called.\n");
		mutex_enter(&softsp->ds1287_mutex);
		if (softsp->monitor_on) {
			mutex_exit(&softsp->ds1287_mutex);
			return (EBUSY);
		}
		softsp->monitor_on = clone;
		mutex_exit(&softsp->ds1287_mutex);
		return (0);

	case PB_END_MONITOR:
		DPRINTF("ds1287_ioctl: PB_END_MONITOR is called.\n");
		mutex_enter(&softsp->ds1287_mutex);

		/*
		 * If PB_END_MONITOR is called without first
		 * calling PB_BEGIN_MONITOR, an error will be
		 * returned.
		 */
		if (!softsp->monitor_on) {
			mutex_exit(&softsp->ds1287_mutex);
			return (ENXIO);
		}

		/*
		 * This clone is not monitoring the button.
		 */
		if (softsp->monitor_on != clone) {
			mutex_exit(&softsp->ds1287_mutex);
			return (EINVAL);
		}
		softsp->monitor_on = 0;
		mutex_exit(&softsp->ds1287_mutex);
		return (0);

	case PB_GET_EVENTS:
		DPRINTF("ds1287_ioctl: PB_GET_EVENTS is called.\n");
		mutex_enter(&softsp->ds1287_mutex);
		if (ddi_copyout((void *)&softsp->events, (void *)arg,
		    sizeof (int), mode) != 0) {
			mutex_exit(&softsp->ds1287_mutex);
			return (EFAULT);
		}

		/*
		 * This ioctl returned the events detected since last
		 * call.  Note that any application can get the events
		 * and clear the event register.
		 */
		softsp->events = 0;
		mutex_exit(&softsp->ds1287_mutex);
		return (0);

	/*
	 * This ioctl is used by the test suite.
	 */
	case PB_CREATE_BUTTON_EVENT:
		DPRINTF("ds1287_ioctl: PB_CREATE_BUTTON_EVENT is called.\n");
		(void) ds1287_intr(NULL);
		return (0);

	default:
		return (ENOTTY);
	}
}

/*ARGSUSED*/
static int
ds1287_chpoll(dev_t dev, short events, int anyyet,
    short *reventsp, struct pollhead **phpp)
{
	struct ds1287 *softsp;

	if ((softsp = ddi_get_soft_state(ds1287_state, instance)) == NULL)
		return (ENXIO);

	mutex_enter(&softsp->ds1287_mutex);
	*reventsp = 0;
	if (softsp->events)
		*reventsp = POLLRDNORM|POLLIN;
	else {
		if (!anyyet)
			*phpp = &softsp->pollhd;
	}
	mutex_exit(&softsp->ds1287_mutex);

	return (0);
}

static void
ds1287_log_message(void)
{
	struct ds1287 *softsp;

	if ((softsp = ddi_get_soft_state(ds1287_state, instance)) == NULL) {
		cmn_err(CE_WARN, "ds1287: Failed to get internal state!");
		return;
	}

	mutex_enter(&softsp->ds1287_mutex);
	softsp->shutdown_pending = 0;
	cmn_err(CE_WARN, "ds1287: Failed to shut down the system!");
	mutex_exit(&softsp->ds1287_mutex);
}

/*
 * To facilitate a power button abort, ds1287_intr() now posts
 * a softint (calling ds1287_softintr()) for all power button presses and
 * counts the number of button presses. An abort is issued if the desired
 * number of button presses within the given time interval.
 *
 * Two variables are used to synchronize between the high level intr;
 * the softint handler and timeout handler
 *
 * power_button_cancel  - Indicates that an abort happened and the number
 *                        of outstanding timeouts that have to be cancelled
 *
 * power_button_pressed - Indicates the number of button presses outstanding
 *                        which have not been serviced
 */
/*ARGSUSED*/
static uint_t
ds1287_intr(caddr_t ignore)
{
	hrtime_t tstamp;
	static hrtime_t o_tstamp = 0;
	static hrtime_t power_button_tstamp = 0;
	static int power_button_cnt;
	uint8_t	apcr1;

	/*
	 * Stop the Fail-safe timer that starts running
	 * after power button is pressed.  If it is not
	 * stopped in 21 seconds, system powers off.
	 */
	mutex_enter(&ds1287_reg_mutex);
	select_bank(2);
	DS1287_ADDR_REG = APC_APCR1;
	apcr1 = DS1287_DATA_REG;
	apcr1 |= APC_FSTRC;
	DS1287_DATA_REG = apcr1;
	select_bank(1);
	mutex_exit(&ds1287_reg_mutex);

	tstamp = gethrtime();

	/* need to deal with power button debounce */
	if (o_tstamp && (tstamp - o_tstamp) < power_button_debounce) {
		o_tstamp = tstamp;
		return (DDI_INTR_CLAIMED);
	}
	o_tstamp = tstamp;

	power_button_cnt++;

	mutex_enter(&ds1287_reg_mutex);
	power_button_pressed++;
	mutex_exit(&ds1287_reg_mutex);

	/*
	 * If power button abort is enabled and power button was pressed
	 * power_button_abort_presses times within power_button_abort_interval
	 * then call abort_sequence_enter();
	 */
	if (power_button_abort_enable) {
		if (power_button_abort_presses == 1 ||
		    tstamp < (power_button_tstamp +
		    power_button_abort_interval)) {
			if (power_button_cnt == power_button_abort_presses) {
				mutex_enter(&ds1287_reg_mutex);
				power_button_cancel += power_button_timeouts;
				power_button_pressed = 0;
				mutex_exit(&ds1287_reg_mutex);
				power_button_cnt = 0;
				abort_sequence_enter("Power Button Abort");
				return (DDI_INTR_CLAIMED);
			}
		} else {
			power_button_cnt = 1;
			power_button_tstamp = tstamp;
		}
	}

	if (!power_button_enable)
		return (DDI_INTR_CLAIMED);

	/* post softint to issue timeout for power button action */
	ddi_trigger_softintr(ds1287_softintr_id);

	return (DDI_INTR_CLAIMED);
}

/*
 * Handle the softints....
 *
 * If only one softint is posted for several button presses, record
 * the number of additional presses just incase this was actually not quite
 * an Abort sequence so that we can log this event later.
 *
 * Issue a timeout with a duration being a fraction larger than
 * the specified Abort interval inorder to perform a power down if required.
 */
static uint_t
ds1287_softintr(caddr_t arg)
{
	struct ds1287 *softsp = (struct ds1287 *)arg;

	DPRINTF("ds1287_softintr\n");

	if (!power_button_abort_enable)
		return (ds1287_issue_shutdown(arg));

	mutex_enter(&ds1287_reg_mutex);
	if (!power_button_pressed) {
		mutex_exit(&ds1287_reg_mutex);
		return (DDI_INTR_CLAIMED);
	}

	/*
	 * Schedule a timeout to do the necessary
	 * work for shutdown, only one timeout for
	 * n presses if power button was pressed
	 * more than once before softint fired
	 */
	if (power_button_pressed > 1)
		additional_presses += power_button_pressed - 1;

	timeout_cancel = 0;
	power_button_pressed = 0;
	power_button_timeouts++;
	mutex_exit(&ds1287_reg_mutex);
	(void) timeout((void(*)(void *))ds1287_timeout,
	    softsp, NSEC_TO_TICK(power_button_abort_interval) +
	    ABORT_INCREMENT_DELAY);

	return (DDI_INTR_CLAIMED);
}

/*
 * Upon receiving a timeout the following is determined:
 *
 * If an  Abort sequence was issued, then we cancel all outstanding timeouts
 * and additional presses prior to the Abort sequence.
 *
 * If we had multiple timeouts issued and the abort sequence was not met,
 * then we had more than one button press to power down the machine. We
 * were probably trying to issue an abort. So log a message indicating this
 * and cancel all outstanding timeouts.
 *
 * If we had just one timeout and the abort sequence was not met then
 * we really did want to power down the machine, so call ds1287_issue_shutdown()
 * to do the work and schedule a power down
 */
static void
ds1287_timeout(caddr_t arg)
{
	static int first = 0;

	DPRINTF("ds1287_timeout\n");

	/*
	 * Abort was generated cancel all outstanding power
	 * button timeouts
	 */
	mutex_enter(&ds1287_reg_mutex);
	if (power_button_cancel) {
		power_button_cancel--;
		power_button_timeouts--;
		if (!first) {
			first++;
			additional_presses = 0;
		}
		mutex_exit(&ds1287_reg_mutex);
		return;
	}
	first = 0;

	/*
	 * We get here if the timeout(s) have fired and they were
	 * not issued prior to an abort.
	 *
	 * If we had more than one press in the interval we were
	 * probably trying to issue an abort, but didnt press the
	 * required number within the interval. Hence cancel all
	 * timeouts and do not continue towards shutdown.
	 */
	if (!timeout_cancel) {
		timeout_cancel = power_button_timeouts +
		    additional_presses;

		power_button_timeouts--;
		if (!power_button_timeouts)
			additional_presses = 0;

		if (timeout_cancel > 1) {
			mutex_exit(&ds1287_reg_mutex);
			cmn_err(CE_NOTE, "Power Button pressed "
			    "%d times, cancelling all requests",
			    timeout_cancel);
			return;
		}
		mutex_exit(&ds1287_reg_mutex);

		/* Go and do the work to request shutdown */
		(void) ds1287_issue_shutdown(arg);
		return;
	}

	power_button_timeouts--;
	if (!power_button_timeouts)
		additional_presses = 0;
	mutex_exit(&ds1287_reg_mutex);
}

static uint_t
ds1287_issue_shutdown(caddr_t arg)
{
	struct ds1287 *softsp = (struct ds1287 *)arg;

	DPRINTF("ds1287_issue_shutdown\n");

	mutex_enter(&softsp->ds1287_mutex);
	softsp->events |= PB_BUTTON_PRESS;
	if (softsp->monitor_on != 0) {
		mutex_exit(&softsp->ds1287_mutex);
		pollwakeup(&softsp->pollhd, POLLRDNORM);
		pollwakeup(&softsp->pollhd, POLLIN);
		return (DDI_INTR_CLAIMED);
	}

	if (!softsp->shutdown_pending) {
		cmn_err(CE_WARN, "Power button is pressed, powering down "
		    "the system!");
		softsp->shutdown_pending = 1;
		do_shutdown();

		/*
		 * Wait a while for "do_shutdown()" to shut down the system
		 * before logging an error message.
		 */
		(void) timeout((void(*)(void *))ds1287_log_message, NULL,
		    100 * hz);
	}
	mutex_exit(&softsp->ds1287_mutex);

	return (DDI_INTR_CLAIMED);
}

/*
 * Read the current time from the clock chip and convert to UNIX form.
 * Assumes that the year in the clock chip is valid.
 * Must be called with tod_lock held.
 */
static timestruc_t
todds_get(void)
{
	timestruc_t ts;
	todinfo_t tod;
	struct rtc_t rtc;

	ASSERT(MUTEX_HELD(&tod_lock));

	read_rtc(&rtc);
	DPRINTF("todds_get: century=%d year=%d dom=%d hrs=%d\n",
	    rtc.rtc_century, rtc.rtc_year, rtc.rtc_dom, rtc.rtc_hrs);

	/*
	 * tod_year is base 1900 so this code needs to adjust the true
	 * year retrieved from the rtc's century and year fields.
	 */
	tod.tod_year	= rtc.rtc_year + (rtc.rtc_century * 100) - 1900;
	tod.tod_month	= rtc.rtc_mon;
	tod.tod_day	= rtc.rtc_dom;
	tod.tod_dow	= rtc.rtc_dow;
	tod.tod_hour	= rtc.rtc_hrs;
	tod.tod_min	= rtc.rtc_min;
	tod.tod_sec	= rtc.rtc_sec;

	ts.tv_sec = tod_to_utc(tod);
	ts.tv_nsec = 0;

	/* set the hw watchdog timer if it's been activated */
	if (watchdog_activated) {
		int ret = 0;
		ret = tod_ops.tod_set_watchdog_timer(watchdog_timeout_seconds);
		if (ret == 0)
			cmn_err(CE_WARN, "ds1287: failed to set hardware "
			    "watchdog timer.");
	}

	return (ts);
}

void
read_rtc(struct rtc_t *rtc)
{
	uint8_t regb;

	/*
	 * Some SuperIO tod devices don't seem to properly initialize
	 * the CADDR register to place the Century register at bank 1
	 * address 0x48.
	 */
	mutex_enter(&ds1287_reg_mutex);

	select_bank(2);
	DS1287_ADDR_REG = RTC_CADDR;
	regb = DS1287_DATA_REG;
	if (regb != 0xc8) {
		if (!ds1287_caddr_warn) {
			ds1287_caddr_warn = 1;
			cmn_err(CE_WARN, "ds1287: century address register "
			    "incorrect (exp 0xc8, obs %x)", regb);
		}
		DS1287_DATA_REG = 0xc8;
	}

	select_bank(1);
	/*
	 * Freeze clock update
	 */
	DS1287_ADDR_REG = RTC_B;
	regb = DS1287_DATA_REG;
	DS1287_DATA_REG = (regb | RTC_SET);

	DS1287_ADDR_REG = RTC_SEC;
	rtc->rtc_sec = DS1287_DATA_REG;
	DS1287_ADDR_REG = RTC_ASEC;
	rtc->rtc_asec = DS1287_DATA_REG;
	DS1287_ADDR_REG = RTC_MIN;
	rtc->rtc_min = DS1287_DATA_REG;
	DS1287_ADDR_REG = RTC_AMIN;
	rtc->rtc_amin = DS1287_DATA_REG;
	DS1287_ADDR_REG = RTC_HRS;
	rtc->rtc_hrs = DS1287_DATA_REG;
	DS1287_ADDR_REG = RTC_AHRS;
	rtc->rtc_ahrs = DS1287_DATA_REG;
	DS1287_ADDR_REG = RTC_DOW;
	rtc->rtc_dow = DS1287_DATA_REG;
	DS1287_ADDR_REG = RTC_DOM;
	rtc->rtc_dom = DS1287_DATA_REG;
	DS1287_ADDR_REG = RTC_MON;
	rtc->rtc_mon = DS1287_DATA_REG;
	DS1287_ADDR_REG = RTC_YEAR;
	rtc->rtc_year = DS1287_DATA_REG;
	DS1287_ADDR_REG = RTC_CENTURY;
	rtc->rtc_century = DS1287_DATA_REG;

	/* Read date alarm */
	DS1287_ADDR_REG = RTC_ADOM;
	rtc->rtc_adom = DS1287_DATA_REG;
	DS1287_ADDR_REG = RTC_AMON;
	rtc->rtc_amon = DS1287_DATA_REG;

	/* Read wakeup data */
	select_bank(2);
	DS1287_ADDR_REG = APC_WDWR;
	rtc->apc_wdwr = DS1287_DATA_REG;
	DS1287_ADDR_REG = APC_WDMR;
	rtc->apc_wdmr = DS1287_DATA_REG;
	DS1287_ADDR_REG = APC_WMR;
	rtc->apc_wmr = DS1287_DATA_REG;
	DS1287_ADDR_REG = APC_WYR;
	rtc->apc_wyr = DS1287_DATA_REG;
	DS1287_ADDR_REG = APC_WCR;
	rtc->apc_wcr = DS1287_DATA_REG;

	/*
	 * Unfreeze clock update
	 */
	DS1287_ADDR_REG = RTC_B;
	DS1287_DATA_REG = regb;

	mutex_exit(&ds1287_reg_mutex);
}

/*
 * Write the specified time into the clock chip.
 * Must be called with tod_lock held.
 */
static void
todds_set(timestruc_t ts)
{
	struct rtc_t	rtc;
	todinfo_t tod = utc_to_tod(ts.tv_sec);
	int year;

	ASSERT(MUTEX_HELD(&tod_lock));

	/* tod_year is base 1900 so this code needs to adjust */
	year = 1900 + tod.tod_year;
	rtc.rtc_year	= year % 100;
	rtc.rtc_century = year / 100;
	rtc.rtc_mon	= (uint8_t)tod.tod_month;
	rtc.rtc_dom	= (uint8_t)tod.tod_day;
	rtc.rtc_dow	= (uint8_t)tod.tod_dow;
	rtc.rtc_hrs	= (uint8_t)tod.tod_hour;
	rtc.rtc_min	= (uint8_t)tod.tod_min;
	rtc.rtc_sec	= (uint8_t)tod.tod_sec;
	DPRINTF("todds_set: century=%d year=%d dom=%d hrs=%d\n",
	    rtc.rtc_century, rtc.rtc_year, rtc.rtc_dom, rtc.rtc_hrs);

	write_rtc_time(&rtc);
}

void
write_rtc_time(struct rtc_t *rtc)
{
	uint8_t	regb;

	/*
	 * Some SuperIO tod devices don't seem to properly initialize
	 * the CADDR register to place the Century register at bank 1
	 * address 0x48.
	 */
	mutex_enter(&ds1287_reg_mutex);

	select_bank(2);
	DS1287_ADDR_REG = RTC_CADDR;
	regb = DS1287_DATA_REG;
	if (regb != 0xc8) {
		if (!ds1287_caddr_warn) {
			ds1287_caddr_warn = 1;
			cmn_err(CE_WARN, "ds1287: century address register "
			    "incorrect (exp 0xc8, obs %x)", regb);
		}
		DS1287_DATA_REG = 0xc8;
	}

	select_bank(1);

	/*
	 * Freeze
	 */
	DS1287_ADDR_REG = RTC_B;
	regb = DS1287_DATA_REG;

	DS1287_DATA_REG = (regb | RTC_SET);

	DS1287_ADDR_REG = RTC_SEC;
	DS1287_DATA_REG = rtc->rtc_sec;
	DS1287_ADDR_REG = RTC_MIN;
	DS1287_DATA_REG = rtc->rtc_min;
	DS1287_ADDR_REG = RTC_HRS;
	DS1287_DATA_REG = rtc->rtc_hrs;
	DS1287_ADDR_REG = RTC_DOW;
	DS1287_DATA_REG = rtc->rtc_dow;
	DS1287_ADDR_REG = RTC_DOM;
	DS1287_DATA_REG = rtc->rtc_dom;
	DS1287_ADDR_REG = RTC_MON;
	DS1287_DATA_REG = rtc->rtc_mon;
	DS1287_ADDR_REG = RTC_YEAR;
	DS1287_DATA_REG = rtc->rtc_year;
	DS1287_ADDR_REG = RTC_CENTURY;
	DS1287_DATA_REG = rtc->rtc_century;

	/*
	 * Unfreeze
	 */
	DS1287_ADDR_REG = RTC_B;
	DS1287_DATA_REG = regb;

	mutex_exit(&ds1287_reg_mutex);
}

void
write_rtc_alarm(struct rtc_t *rtc)
{
	mutex_enter(&ds1287_reg_mutex);

	select_bank(1);
	DS1287_ADDR_REG = RTC_ASEC;
	DS1287_DATA_REG = rtc->rtc_asec;
	DS1287_ADDR_REG = RTC_AMIN;
	DS1287_DATA_REG = rtc->rtc_amin;
	DS1287_ADDR_REG = RTC_AHRS;
	DS1287_DATA_REG = rtc->rtc_ahrs;
	DS1287_ADDR_REG = RTC_ADOM;
	DS1287_DATA_REG = rtc->rtc_adom;
	DS1287_ADDR_REG = RTC_AMON;
	DS1287_DATA_REG = rtc->rtc_amon;

	select_bank(2);
	DS1287_ADDR_REG = APC_WDWR;
	DS1287_DATA_REG = rtc->apc_wdwr;
	DS1287_ADDR_REG = APC_WDMR;
	DS1287_DATA_REG = rtc->apc_wdmr;
	DS1287_ADDR_REG = APC_WMR;
	DS1287_DATA_REG = rtc->apc_wmr;
	DS1287_ADDR_REG = APC_WYR;
	DS1287_DATA_REG = rtc->apc_wyr;
	DS1287_ADDR_REG = APC_WCR;
	DS1287_DATA_REG = rtc->apc_wcr;

	mutex_exit(&ds1287_reg_mutex);
}

/*
 * program the rtc registers for alarm to go off at the specified time
 */
static void
todds_set_power_alarm(timestruc_t ts)
{
	todinfo_t	tod;
	uint8_t		apcr2;
	struct rtc_t	rtc;

	ASSERT(MUTEX_HELD(&tod_lock));
	tod = utc_to_tod(ts.tv_sec);
	mutex_enter(&ds1287_reg_mutex);

	/* Clear Time Match Detect */
	select_bank(2);
	DS1287_ADDR_REG = APC_APSR;
	apcr2 = DS1287_DATA_REG;

	/* Disable Time Match Enable */
	DS1287_ADDR_REG = APC_APCR2;
	apcr2 = DS1287_DATA_REG;
	DS1287_DATA_REG = (apcr2 & (~APC_TME));

	mutex_exit(&ds1287_reg_mutex);

	rtc.rtc_asec = (uint8_t)tod.tod_sec;
	rtc.rtc_amin = (uint8_t)tod.tod_min;
	rtc.rtc_ahrs = (uint8_t)tod.tod_hour;
	rtc.rtc_adom = (uint8_t)tod.tod_day;
	rtc.rtc_amon = (uint8_t)tod.tod_month;

	rtc.apc_wdwr = (uint8_t)tod.tod_dow;
	rtc.apc_wdmr = (uint8_t)tod.tod_day;
	rtc.apc_wmr = (uint8_t)tod.tod_month;
	rtc.apc_wyr = tod.tod_year % 100;
	rtc.apc_wcr = (tod.tod_year / 100) + 19;

	write_rtc_alarm(&rtc);

	mutex_enter(&ds1287_reg_mutex);
	/* Enable Time Match enable */
	select_bank(2);
	DS1287_ADDR_REG = APC_APCR2;
	DS1287_DATA_REG = (apcr2 | APC_TME);

	mutex_exit(&ds1287_reg_mutex);
}

/*
 * clear alarm interrupt
 */
static void
todds_clear_power_alarm(void)
{
	uint8_t	apcr2;

	ASSERT(MUTEX_HELD(&tod_lock));

	mutex_enter(&ds1287_reg_mutex);

	/* Clear Time Match Detect */
	select_bank(2);
	DS1287_ADDR_REG = APC_APSR;
	apcr2 = DS1287_DATA_REG;

	/* Disable Time Match Enable */
	DS1287_ADDR_REG = APC_APCR2;
	apcr2 = DS1287_DATA_REG;
	DS1287_DATA_REG = (apcr2 & (~APC_TME));

	mutex_exit(&ds1287_reg_mutex);
}

/*
 * Determine the cpu frequency by watching the TOD chip rollover twice.
 * Cpu clock rate is determined by computing the ticks added (in tick register)
 * during one second interval on TOD.
 */
uint64_t
todds_get_cpufrequency(void)
{
	uint64_t cpu_freq;

	ASSERT(MUTEX_HELD(&tod_lock));
	mutex_enter(&ds1287_reg_mutex);

	select_bank(1);
	DS1287_ADDR_REG = RTC_SEC;
	cpu_freq = find_cpufrequency(v_rtc_data_reg);

	mutex_exit(&ds1287_reg_mutex);
	return (cpu_freq);
}

static void
select_bank(int bank)
{
	uint8_t	rega;
	int banksel;

	/* Select Bank 1 */
	DS1287_ADDR_REG = RTC_A;
	rega = DS1287_DATA_REG;
	rega = rega & ~(RTC_DIV0 | RTC_DIV1 | RTC_DIV2);
	switch (bank) {
	case 0:
		banksel = RTC_DIV1;
		break;
	case 1:
		banksel = RTC_DIV0 | RTC_DIV1;
		break;
	case 2:
		banksel = RTC_DIV2;
		break;
	}
	rega |= banksel;
	DS1287_DATA_REG = rega;
}

/*ARGSUSED*/
static uint_t
todds_set_watchdog_timer(uint_t timeoutval)
{
	ASSERT(MUTEX_HELD(&tod_lock));
	return (0);
}

static uint_t
todds_clear_watchdog_timer(void)
{
	ASSERT(MUTEX_HELD(&tod_lock));
	return (0);
}
