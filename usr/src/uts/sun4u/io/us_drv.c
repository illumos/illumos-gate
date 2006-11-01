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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Device driver for UltraSPARC CPU. The driver is not DDI-compliant.
 *
 * The driver supports following features:
 *	- Power management.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/errno.h>
#include <sys/modctl.h>
#include <sys/kmem.h>
#include <sys/conf.h>
#include <sys/cmn_err.h>
#include <sys/stat.h>
#include <sys/debug.h>
#include <sys/systm.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#include <sys/cpu_module.h>
#include <sys/machsystm.h>
#include <sys/x_call.h>
#include <sys/us_drv.h>
#include <sys/msacct.h>

/*
 * UltraSPARC CPU power management
 *
 * The supported power saving model is to slow down the CPU by dividing the
 * CPU clock. Periodically we determine the amount of time the CPU is running
 * idle thread and threads in user mode during the last quantum.  If the idle
 * thread was running less than its low water mark for current speed for
 * number of consecutive sampling periods, or number of running threads in
 * user mode are above its high water mark, we arrange to go to the higher
 * speed.  If the idle thread was running more than its high water mark without
 * dropping a number of consecutive times below the mark, and number of threads
 * running in user mode are below its low water mark, we arrange to go to the
 * next lower speed.  While going down, we go through all the speeds.  While
 * going up we go to the maximum speed to minimize impact on the user, but have
 * provisions in the driver to go to other speeds.
 *
 * The driver does not have knowledge of a particular implementation of this
 * scheme and will work with all CPUs supporting this model. The driver
 * determines supported speeds by looking at 'clock-divisors' property
 * created by OBP.
 */

/*
 * Configuration function prototypes and data structures
 */
static int us_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int us_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);
static int us_power(dev_info_t *dip, int comp, int level);

struct dev_ops us_ops = {
	DEVO_REV,		/* rev */
	0,			/* refcnt */
	nodev,			/* getinfo */
	nulldev,		/* identify */
	nulldev,		/* probe */
	us_attach,		/* attach */
	us_detach,		/* detach */
	nodev,			/* reset */
	(struct cb_ops *)NULL,	/* cb_ops */
	(struct bus_ops *)NULL,	/* bus_ops */
	us_power		/* power */
};

static struct modldrv modldrv = {
	&mod_driverops,			/* modops */
	"UltraSPARC CPU Driver %I%",	/* linkinfo */
	&us_ops,			/* dev_ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,		/* rev */
	&modldrv,		/* linkage */
	NULL
};

/*
 * Function prototypes
 */
static int us_pm_init(us_devstate_t *usdsp);
static void us_pm_free(us_devstate_t *usdsp);
static int us_pm_comp_create(us_devstate_t *usdsp);
static void us_pm_monitor_disp(void *arg);
static void us_pm_monitor(void *arg);

/*
 * Driver global variables
 */
uint_t us_drv_debug = 0;
static void *us_state;
static uint_t us_pm_idle_hwm = US_PM_IDLE_HWM;
static uint_t us_pm_idle_lwm = US_PM_IDLE_LWM;
static uint_t us_pm_idle_buf_zone = US_PM_IDLE_BUF_ZONE;
static uint_t us_pm_idle_bhwm_cnt_max = US_PM_IDLE_BHWM_CNT_MAX;
static uint_t us_pm_idle_blwm_cnt_max = US_PM_IDLE_BLWM_CNT_MAX;
static uint_t us_pm_user_hwm = US_PM_USER_HWM;

/*
 * us_direct_pm allows user applications to directly control the
 * power state transitions (direct pm) without following the normal
 * direct pm protocol. This is needed because the normal protocol
 * requires that a device only be lowered when it is idle, and be
 * brought up when it request to do so by calling pm_raise_power().
 * Ignoring this protocol is harmless for CPU (other than speed).
 * Moreover it might be the case that CPU is never idle or wants
 * to be at higher speed because of the addition CPU cycles required
 * to run the user application.
 *
 * The driver will still report idle/busy status to the framework. Although
 * framework will ignore this information for direct pm devices and not
 * try to bring them down when idle, user applications can still use this
 * information if they wants.
 *
 * In future, provide an ioctl to control setting of this mode. In
 * that case, this variable should move to the state structure and
 * protected by the lock in state strcuture.
 */
static int us_direct_pm = 0;

/*
 * Arranges for the handler function to be called at the interval suitable
 * for current speed.
 */
#define	US_PM_MONITOR_INIT(usdsp) { \
	ASSERT(mutex_owned(&(usdsp)->lock)); \
	(usdsp)->us_pm.timeout_id = timeout(us_pm_monitor_disp, (usdsp), \
	    (((usdsp)->us_pm.cur_spd == NULL) ? US_PM_QUANT_CNT_OTHR : \
	    (usdsp)->us_pm.cur_spd->quant_cnt)); \
}

/*
 * Arranges for the handler function not to be called back.
 */
#define	US_PM_MONITOR_FINI(usdsp) { \
	timeout_id_t tmp_tid; \
	ASSERT(mutex_owned(&(usdsp)->lock)); \
	ASSERT((usdsp)->us_pm.timeout_id); \
	tmp_tid = (usdsp)->us_pm.timeout_id; \
	(usdsp)->us_pm.timeout_id = 0; \
	mutex_exit(&(usdsp)->lock); \
	(void) untimeout(tmp_tid); \
	mutex_enter(&(usdsp)->us_pm.timeout_lock); \
	while ((usdsp)->us_pm.timeout_count != 0) \
		cv_wait(&(usdsp)->us_pm.timeout_cv, \
		    &(usdsp)->us_pm.timeout_lock); \
	mutex_exit(&(usdsp)->us_pm.timeout_lock); \
	mutex_enter(&(usdsp)->lock); \
}

int
_init(void)
{
	int 		error;

	DPRINTF(D_INIT, ("us: _init: function called\n"));
	if ((error = ddi_soft_state_init(&us_state,
	    sizeof (us_devstate_t), 0)) != 0) {
		return (error);
	}

	if ((error = mod_install(&modlinkage)) != 0)  {
		ddi_soft_state_fini(&us_state);
	}

	return (error);
}

int
_fini(void)
{
	int		error;

	DPRINTF(D_FINI, ("us: _fini: function called\n"));
	if ((error = mod_remove(&modlinkage)) == 0) {
		ddi_soft_state_fini(&us_state);
	}

	return (error);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}



/*
 * Driver attach(9e) entry point.
 */
static int
us_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int		instance;
	us_devstate_t	*usdsp;
	extern pri_t	maxclsyspri;

	instance = ddi_get_instance(dip);

	switch (cmd) {
	case DDI_ATTACH:
		DPRINTF(D_ATTACH, ("us_attach: instance %d: "
		    "DDI_ATTACH called\n", instance));
		if (ddi_soft_state_zalloc(us_state, instance) != DDI_SUCCESS) {
			cmn_err(CE_WARN, "us_attach: instance %d: "
			    "can't allocate state", instance);
			return (DDI_FAILURE);
		}
		if ((usdsp = ddi_get_soft_state(us_state, instance)) == NULL) {
			cmn_err(CE_WARN, "us_attach: instance %d: "
			    "can't get state", instance);
			return (DDI_FAILURE);
		}
		usdsp->dip = dip;

		if (us_pm_init(usdsp) != DDI_SUCCESS) {
			ddi_soft_state_free(us_state, instance);
			return (DDI_FAILURE);
		}

		/*
		 * Find CPU number for this dev_info node.
		 */
		if (dip_to_cpu_id(dip, &(usdsp->cpu_id)) != DDI_SUCCESS) {
			us_pm_free(usdsp);
			ddi_soft_state_free(us_state, instance);
			cmn_err(CE_WARN, "us_attach: instance %d: "
			    "can't convert dip to cpu_id", instance);
			return (DDI_FAILURE);
		}

		if (us_pm_comp_create(usdsp) != DDI_SUCCESS) {
			us_pm_free(usdsp);
			ddi_soft_state_free(us_state, instance);
			return (DDI_FAILURE);
		}

		if (ddi_prop_update_string(DDI_DEV_T_NONE,
		    usdsp->dip, "pm-class", "CPU") != DDI_PROP_SUCCESS) {
			us_pm_free(usdsp);
			ddi_soft_state_free(us_state, instance);
			return (DDI_FAILURE);
		}

		/*
		 * Taskq is used to dispatch routine to monitor CPU activities.
		 */
		usdsp->us_pm.tq = taskq_create_instance("us_pm_monitor",
		    ddi_get_instance(dip),
		    US_PM_TASKQ_THREADS, (maxclsyspri - 1), US_PM_TASKQ_MIN,
		    US_PM_TASKQ_MAX, TASKQ_PREPOPULATE|TASKQ_CPR_SAFE);

		mutex_init(&usdsp->lock, NULL, MUTEX_DRIVER, NULL);
		mutex_init(&usdsp->us_pm.timeout_lock, NULL, MUTEX_DRIVER,
		    NULL);
		cv_init(&usdsp->us_pm.timeout_cv, NULL, CV_DEFAULT, NULL);

		/*
		 * Driver needs to assume that CPU is running at unknown speed
		 * at DDI_ATTACH and switch it to the needed speed. We assume
		 * that initial needed speed is full speed for us.
		 */
		/*
		 * We need to take the lock because us_pm_monitor()
		 * will start running in parallel with attach().
		 */
		mutex_enter(&usdsp->lock);
		usdsp->us_pm.cur_spd = NULL;
		usdsp->us_pm.targ_spd = usdsp->us_pm.head_spd;
		/*
		 * We don't call pm_raise_power() directly from attach beacuse
		 * driver attach for a slave CPU node can happen before the
		 * CPU is even initialized. We just start the monitoring
		 * system which understands unknown speed and moves CPU
		 * to targ_spd when it have been initialized.
		 */
		US_PM_MONITOR_INIT(usdsp);
		mutex_exit(&usdsp->lock);

		ddi_report_dev(dip);
		return (DDI_SUCCESS);

	case DDI_RESUME:
		DPRINTF(D_ATTACH, ("us_attach: instance %d: "
		    "DDI_RESUME called\n", instance));
		if ((usdsp = ddi_get_soft_state(us_state, instance)) == NULL) {
			cmn_err(CE_WARN, "us_attach: instance %d: "
			    "can't get state", instance);
			return (DDI_FAILURE);
		}
		mutex_enter(&usdsp->lock);
		/*
		 * Driver needs to assume that CPU is running at unknown speed
		 * at DDI_RESUME and switch it to the needed speed. We assume
		 * that the needed speed is full speed for us.
		 */
		usdsp->us_pm.cur_spd = NULL;
		usdsp->us_pm.targ_spd = usdsp->us_pm.head_spd;
		US_PM_MONITOR_INIT(usdsp);
		mutex_exit(&usdsp->lock);

		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}
}

/*
 * Driver detach(9e) entry point.
 */
static int
us_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int		instance;
	us_devstate_t	*usdsp;
	us_pm_t		*upm;

	instance = ddi_get_instance(dip);

	switch (cmd) {
	case DDI_DETACH:
		DPRINTF(D_DETACH, ("us_detach: instance %d: "
		    "DDI_DETACH called\n", instance));
		/*
		 * If the only thing supported by the driver is power
		 * management, we can in future enhance the driver and
		 * framework that loads it to unload the driver when
		 * user has disabled CPU power management.
		 */
		return (DDI_FAILURE);

	case DDI_SUSPEND:
		DPRINTF(D_DETACH, ("us_detach: instance %d: "
		    "DDI_SUSPEND called\n", instance));
		if ((usdsp = ddi_get_soft_state(us_state, instance)) == NULL) {
			cmn_err(CE_WARN, "us_detach: instance %d: "
			    "can't get state", instance);
			return (DDI_FAILURE);
		}
		/*
		 * During a checkpoint-resume sequence, framework will
		 * stop interrupts to quiesce kernel activity. This will
		 * leave our monitoring system ineffective. Handle this
		 * by stopping our monitoring system and bringing CPU
		 * to full speed. In case we are in special direct pm
		 * mode, we leave the CPU at whatever speed it is. This
		 * is harmless other than speed.
		 */
		mutex_enter(&usdsp->lock);
		upm = &(usdsp->us_pm);

		DPRINTF(D_DETACH, ("us_detach: instance %d: DDI_SUSPEND - "
		    "cur_spd %d, head_spd %d\n", instance,
		    upm->cur_spd->pm_level, upm->head_spd->pm_level));

		US_PM_MONITOR_FINI(usdsp);

		if (!us_direct_pm && (upm->cur_spd != upm->head_spd)) {
			if (upm->pm_busycnt < 1) {
				if ((pm_busy_component(dip, US_PM_COMP_NUM) ==
				    DDI_SUCCESS)) {
					upm->pm_busycnt++;
				} else {
					US_PM_MONITOR_INIT(usdsp);
					mutex_exit(&usdsp->lock);
					cmn_err(CE_WARN, "us_detach: instance "
					    "%d: can't busy CPU component",
					    instance);
					return (DDI_FAILURE);
				}
			}
			mutex_exit(&usdsp->lock);
			if (pm_raise_power(dip, US_PM_COMP_NUM,
			    upm->head_spd->pm_level) != DDI_SUCCESS) {
				mutex_enter(&usdsp->lock);
				US_PM_MONITOR_INIT(usdsp);
				mutex_exit(&usdsp->lock);
				cmn_err(CE_WARN, "us_detach: instance %d: "
				    "can't raise CPU power level", instance);
				return (DDI_FAILURE);
			} else {
				return (DDI_SUCCESS);
			}
		} else {
			mutex_exit(&usdsp->lock);
			return (DDI_SUCCESS);
		}

	default:
		return (DDI_FAILURE);
	}
}

/*
 * Driver power(9e) entry point.
 *
 * Driver's notion of current power is set *only* in power(9e) entry point
 * after actual power change operation has been successfully completed.
 */
/* ARGSUSED */
static int
us_power(dev_info_t *dip, int comp, int level)
{
	int		instance;
	us_devstate_t	*usdsp;
	us_pm_t 	*upm;
	us_pm_spd_t	*new_spd;

	instance = ddi_get_instance(dip);

	DPRINTF(D_POWER, ("us_power: instance %d: level %d\n",
	    instance, level));
	if ((usdsp = ddi_get_soft_state(us_state, instance)) == NULL) {
		cmn_err(CE_WARN, "us_power: instance %d: can't get state",
		    instance);
		return (DDI_FAILURE);
	}

	mutex_enter(&usdsp->lock);
	upm = &(usdsp->us_pm);

	/*
	 * In normal operation, we fail if we are busy and request is
	 * to lower the power level. We let this go through if the driver
	 * is in special direct pm mode.
	 */
	if (!us_direct_pm && (upm->pm_busycnt >= 1)) {
		if ((upm->cur_spd != NULL) &&
		    (level < upm->cur_spd->pm_level)) {
			mutex_exit(&usdsp->lock);
			return (DDI_FAILURE);
		}
	}

	for (new_spd = upm->head_spd; new_spd; new_spd = new_spd->down_spd) {
		if (new_spd->pm_level == level)
			break;
	}
	if (!new_spd) {
		mutex_exit(&usdsp->lock);
		cmn_err(CE_WARN, "us_power: instance %d: "
		    "can't locate new CPU speed", instance);
		return (DDI_FAILURE);
	}

	/*
	 * We currently refuse to power manage if the CPU in not ready to
	 * take cross calls (cross calls fail silently if CPU is not ready
	 * for it).
	 */
	if (!(CPU_XCALL_READY(usdsp->cpu_id))) {
		mutex_exit(&usdsp->lock);
		DPRINTF(D_POWER, ("us_power: instance %d: "
		    "CPU not ready for x-calls\n", instance));
		return (DDI_FAILURE);
	}
	/*
	 * Execute CPU specific routine on the requested CPU to change its
	 * speed to normal-speed/divisor.
	 */
	xc_one(usdsp->cpu_id, (xcfunc_t *)cpu_change_speed,
	    (uint64_t)new_spd->divisor, 0);

	/*
	 * Reset idle threshold time for the new power level.
	 */
	if ((upm->cur_spd != NULL) && (level < upm->cur_spd->pm_level)) {
		if (pm_idle_component(dip, US_PM_COMP_NUM) == DDI_SUCCESS) {
			if (upm->pm_busycnt >= 1)
				upm->pm_busycnt--;
		} else
			cmn_err(CE_WARN, "us_power: instance %d: can't "
			    "idle CPU component", ddi_get_instance(dip));
	}
	/*
	 * Reset various parameters because we are now running at new speed.
	 */
	upm->lastquan_idle = 0;
	upm->lastquan_user = 0;
	upm->lastquan_lbolt = 0;
	upm->cur_spd = new_spd;
	mutex_exit(&usdsp->lock);
	return (DDI_SUCCESS);
}

/*
 * Initialize power management data.
 */
static int
us_pm_init(us_devstate_t *usdsp)
{
	us_pm_t 	*upm = &(usdsp->us_pm);
	us_pm_spd_t	*cur_spd;
	us_pm_spd_t	*prev_spd = NULL;
	int		*divisors;
	uint_t		ndivisors;
	int		idle_cnt_percent;
	int		user_cnt_percent;
	int		i;

	/*
	 * clock-divisors property tells the supported speeds
	 * as divisors of the normal speed. Divisors are in increasing
	 * order starting with 1 (for normal speed). For example, a
	 * property value of "1, 2, 32" represents full, 1/2 and 1/32
	 * speeds.
	 */
	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, usdsp->dip,
	    DDI_PROP_DONTPASS, "clock-divisors", &divisors,
	    &ndivisors) != DDI_PROP_SUCCESS) {
		DPRINTF(D_PM_INIT, ("us_pm_init: instance %d: "
		    "clock-divisors property not defined\n",
		    ddi_get_instance(usdsp->dip)));
		return (DDI_FAILURE);
	}
	if (ndivisors < 2) {
		/* Need at least two speeds to power manage */
		ddi_prop_free(divisors);
		return (DDI_FAILURE);
	}
	upm->num_spd = ndivisors;

	/*
	 * Calculate the watermarks and other parameters based on the
	 * supplied divisors.
	 *
	 * One of the basic assumption is that for X amount of CPU work,
	 * if CPU is slowed down by a factor of N, the time it takes to
	 * do the same work will be N * X.
	 *
	 * The driver declares that a CPU is idle and ready for slowed down,
	 * if amount of idle thread is more than the current speed idle_hwm
	 * without dropping below idle_hwm a number of consecutive sampling
	 * intervals and number of running threads in user mode are below
	 * user_lwm.  We want to set the current user_lwm such that if we
	 * just switched to the next slower speed with no change in real work
	 * load, the amount of user threads at the slower speed will be such
	 * that it falls below the slower speed's user_hwm.  If we didn't do
	 * that then we will just come back to the higher speed as soon as we
	 * go down even with no change in work load.
	 * The user_hwm is a fixed precentage and not calculated dynamically.
	 *
	 * We bring the CPU up if idle thread at current speed is less than
	 * the current speed idle_lwm for a number of consecutive sampling
	 * intervals or user threads are above the user_hwm for the current
	 * speed.
	 */
	for (i = 0; i < ndivisors; i++) {
		cur_spd = kmem_zalloc(sizeof (us_pm_spd_t), KM_SLEEP);
		cur_spd->divisor = divisors[i];
		if (i == 0) {	/* normal speed */
			upm->head_spd = cur_spd;
			cur_spd->quant_cnt = US_PM_QUANT_CNT_NORMAL;
			cur_spd->idle_hwm =
			    (us_pm_idle_hwm * cur_spd->quant_cnt) / 100;
			/* can't speed anymore */
			cur_spd->idle_lwm = 0;
			cur_spd->user_hwm = UINT_MAX;
		} else {
			cur_spd->quant_cnt = US_PM_QUANT_CNT_OTHR;
			ASSERT(prev_spd != NULL);
			prev_spd->down_spd = cur_spd;
			cur_spd->up_spd = upm->head_spd;

			/*
			 * Let's assume CPU is considered idle at full speed
			 * when it is spending I% of time in running the idle
			 * thread.  At full speed, CPU will be busy (100 - I) %
			 * of times.  This % of busyness increases by factor of
			 * N as CPU slows down.  CPU that is idle I% of times
			 * in full speed, it is idle (100 - ((100 - I) * N)) %
			 * of times in N speed.  The idle_lwm is a fixed
			 * percentage.  A large value of N may result in
			 * idle_hwm to go below idle_lwm.  We need to make sure
			 * that there is at least a buffer zone seperation
			 * between the idle_lwm and idle_hwm values.
			 */
			idle_cnt_percent = 100 -
			    ((100 - us_pm_idle_hwm) * cur_spd->divisor);
			idle_cnt_percent = max(idle_cnt_percent,
			    (us_pm_idle_lwm + us_pm_idle_buf_zone));
			cur_spd->idle_hwm =
			    (idle_cnt_percent * cur_spd->quant_cnt) / 100;
			cur_spd->idle_lwm =
			    (us_pm_idle_lwm * cur_spd->quant_cnt) / 100;

			/*
			 * The lwm for user threads are determined such that
			 * if CPU slows down, the load of work in the
			 * new speed would still keep the CPU at or below the
			 * user_hwm in the new speed.  This is to prevent
			 * the quick jump back up to higher speed.
			 */
			cur_spd->user_hwm =
			    (us_pm_user_hwm * cur_spd->quant_cnt) / 100;
			user_cnt_percent =
			    (us_pm_user_hwm * prev_spd->divisor) /
			    cur_spd->divisor;
			prev_spd->user_lwm =
			    (user_cnt_percent * prev_spd->quant_cnt) / 100;
		}
		prev_spd = cur_spd;
	}
	/* Slowest speed. Can't slow down anymore */
	cur_spd->idle_hwm = UINT_MAX;
	cur_spd->user_lwm = -1;
#ifdef	DEBUG
	DPRINTF(D_PM_INIT, ("us_pm_init: instance %d: head_spd div %d, "
	    "num_spd %d\n", ddi_get_instance(usdsp->dip),
	    upm->head_spd->divisor, upm->num_spd));
	for (cur_spd = upm->head_spd; cur_spd; cur_spd = cur_spd->down_spd) {
		DPRINTF(D_PM_INIT, ("us_pm_init: instance %d: divisor %d, "
		    "down_spd div %d, idle_hwm %d, user_lwm %d, "
		    "up_spd div %d, idle_lwm %d, user_hwm %d, "
		    "quant_cnt %d\n", ddi_get_instance(usdsp->dip),
		    cur_spd->divisor,
		    (cur_spd->down_spd ? cur_spd->down_spd->divisor : 0),
		    cur_spd->idle_hwm, cur_spd->user_lwm,
		    (cur_spd->up_spd ? cur_spd->up_spd->divisor : 0),
		    cur_spd->idle_lwm, cur_spd->user_hwm,
		    cur_spd->quant_cnt));
	}
#endif	/* DEBUG */
	ddi_prop_free(divisors);
	return (DDI_SUCCESS);
}

/*
 * Free CPU power management data.
 */
static void
us_pm_free(us_devstate_t *usdsp)
{
	us_pm_t 	*upm = &(usdsp->us_pm);
	us_pm_spd_t	*cur_spd, *next_spd;

	cur_spd = upm->head_spd;
	while (cur_spd) {
		next_spd = cur_spd->down_spd;
		kmem_free(cur_spd, sizeof (us_pm_spd_t));
		cur_spd = next_spd;
	}
	bzero(upm, sizeof (us_pm_t));
}



/*
 * Create pm-components property.
 */
static int
us_pm_comp_create(us_devstate_t *usdsp)
{
	us_pm_t 	*upm = &(usdsp->us_pm);
	us_pm_spd_t	*cur_spd;
	char		**pmc;
	int		size;
	char		name[] = "NAME=CPU Speed";
	char		norm[] = "Normal";
	char		othr[] = " of Normal";
	int		i, j;
	int		result = DDI_FAILURE;

	pmc = kmem_zalloc((upm->num_spd + 1) * sizeof (char *), KM_SLEEP);
	/*
	 * The amount of memory needed for each string is:
	 * 	digits for power level + '=' + '1/' + digits for divisor +
	 *	description text + '\0'
	 */
	size = US_PM_COMP_MAX_DIG + 1 + 2 + US_PM_COMP_MAX_DIG +
	    sizeof (othr) + 1;
	if (upm->num_spd > US_PM_COMP_MAX_VAL) {
		cmn_err(CE_WARN, "us_pm_comp_create: instance %d: "
		    "number of speeds exceeded limits",
		    ddi_get_instance(usdsp->dip));
		kmem_free(pmc, (upm->num_spd + 1) * sizeof (char *));
		return (result);
	}

	for (i = upm->num_spd, cur_spd = upm->head_spd; i > 0;
	    i--, cur_spd = cur_spd->down_spd) {
		cur_spd->pm_level = i;
		pmc[i] = kmem_zalloc((size * sizeof (char)), KM_SLEEP);
		if (cur_spd == upm->head_spd) {
			(void) sprintf(pmc[i], "%d=%s", cur_spd->pm_level,
			    norm);
		} else {
			if (cur_spd->divisor > US_PM_COMP_MAX_VAL) {
				cmn_err(CE_WARN, "us_pm_comp_create: "
				    "instance %d: divisor exceeded limits",
				    ddi_get_instance(usdsp->dip));
				for (j = upm->num_spd; j >= i; j--) {
					kmem_free(pmc[j], size * sizeof (char));
				}
				kmem_free(pmc, (upm->num_spd + 1) *
				    sizeof (char *));
				return (result);
			}
			(void) sprintf(pmc[i], "%d=1/%d%s", cur_spd->pm_level,
			    cur_spd->divisor, othr);
		}
		DPRINTF(D_PM_COMP_CREATE, ("us_pm_comp_create: instance %d: "
		    "pm-components power level %d string '%s'\n",
		    ddi_get_instance(usdsp->dip), i, pmc[i]));
	}
	pmc[0] = kmem_zalloc(sizeof (name), KM_SLEEP);
	(void) strcat(pmc[0], name);
	DPRINTF(D_PM_COMP_CREATE, ("us_pm_comp_create: instance %d: "
	    "pm-components component name '%s'\n",
	    ddi_get_instance(usdsp->dip), pmc[0]));

	if (ddi_prop_update_string_array(DDI_DEV_T_NONE, usdsp->dip,
	    "pm-components", pmc, upm->num_spd + 1) == DDI_PROP_SUCCESS) {
		result = DDI_SUCCESS;
	} else {
		cmn_err(CE_WARN, "us_pm_comp_create: instance %d: "
		    "can't create pm-components property",
		    ddi_get_instance(usdsp->dip));
	}

	for (i = upm->num_spd; i > 0; i--) {
		kmem_free(pmc[i], size * sizeof (char));
	}
	kmem_free(pmc[0], sizeof (name));
	kmem_free(pmc, (upm->num_spd + 1) * sizeof (char *));
	return (result);
}

/*
 * Mark a component idle.
 */
#define	US_PM_MONITOR_PM_IDLE_COMP(dip, upm) { \
	if ((upm)->pm_busycnt >= 1) { \
		if (pm_idle_component((dip), US_PM_COMP_NUM) == DDI_SUCCESS) { \
			DPRINTF(D_PM_MONITOR, ("us_pm_monitor: instance %d: " \
			    "pm_idle_component called\n", \
			    ddi_get_instance((dip)))); \
			(upm)->pm_busycnt--; \
		} else { \
			cmn_err(CE_WARN, "us_pm_monitor: instance %d: can't " \
			    "idle CPU component", ddi_get_instance((dip))); \
		} \
	} \
}

/*
 * Marks a component busy in both PM framework and driver state structure.
 */
#define	US_PM_MONITOR_PM_BUSY_COMP(dip, upm) { \
	if ((upm)->pm_busycnt < 1) { \
		if (pm_busy_component((dip), US_PM_COMP_NUM) == DDI_SUCCESS) { \
			DPRINTF(D_PM_MONITOR, ("us_pm_monitor: instance %d: " \
			    "pm_busy_component called\n", \
			    ddi_get_instance((dip)))); \
			(upm)->pm_busycnt++; \
		} else { \
			cmn_err(CE_WARN, "us_pm_monitor: instance %d: " \
			    "can't busy CPU component", \
			    ddi_get_instance((dip))); \
		} \
	} \
}

/*
 * Marks a component busy and calls pm_raise_power().
 */
#define	US_PM_MONITOR_PM_BUSY_AND_RAISE(dip, usdsp, upm, new_level) { \
	/* \
	 * Mark driver and PM framework busy first so framework doesn't try \
	 * to bring CPU to lower speed when we need to be at higher speed. \
	 */ \
	US_PM_MONITOR_PM_BUSY_COMP((dip), (upm)); \
	mutex_exit(&(usdsp)->lock); \
	DPRINTF(D_PM_MONITOR, ("us_pm_monitor: instance %d: pm_raise_power " \
	    "called to %d\n", ddi_get_instance((dip)), (new_level))); \
	if (pm_raise_power((dip), US_PM_COMP_NUM, (new_level)) != \
	    DDI_SUCCESS) { \
		cmn_err(CE_WARN, "us_pm_monitor: instance %d: can't " \
		    "raise CPU power level", ddi_get_instance((dip))); \
	} \
	mutex_enter(&(usdsp)->lock); \
}

/*
 * In order to monitor a CPU, we need to hold cpu_lock to access CPU statistics.
 * Holding cpu_lock is not allowed from a callout routine.  We dispatch a
 * taskq to do that job.
 */
static void
us_pm_monitor_disp(void *arg)
{
	us_devstate_t	*usdsp = (us_devstate_t *)arg;

	/*
	 * We are here because the last task has scheduled a timeout.
	 * The queue should be empty at this time.
	 */
	mutex_enter(&usdsp->us_pm.timeout_lock);
	if (!taskq_dispatch(usdsp->us_pm.tq, us_pm_monitor, arg, TQ_NOSLEEP)) {
		mutex_exit(&usdsp->us_pm.timeout_lock);
		DPRINTF(D_PM_MONITOR, ("us_pm_monitor_disp: failed to dispatch "
		    "the us_pm_monitor taskq\n"));
		mutex_enter(&usdsp->lock);
		US_PM_MONITOR_INIT(usdsp);
		mutex_exit(&usdsp->lock);
		return;
	}
	usdsp->us_pm.timeout_count++;
	mutex_exit(&usdsp->us_pm.timeout_lock);
}

/*
 * Monitors each CPU for the amount of time idle thread was running in the
 * last quantum and arranges for the CPU to go to the lower or higher speed.
 * Called at the time interval appropriate for the current speed. The
 * time interval for normal speed is US_PM_QUANT_CNT_NORMAL. The time interval
 * for other speeds (including unknown speed) is US_PM_QUANT_CNT_OTHR.
 */
static void
us_pm_monitor(void *arg)
{
	us_devstate_t	*usdsp = (us_devstate_t *)arg;
	us_pm_t		*upm;
	us_pm_spd_t	*cur_spd, *new_spd;
	cpu_t		*cp;
	dev_info_t	*dip;
	uint_t		idle_cnt, user_cnt;
	clock_t		lbolt_cnt, user_ticks, idle_ticks;
	hrtime_t	cphrt;

#define	GET_CPU_DATA(c, t, o) cphrt = c->cpu_acct[t];			\
			scalehrtime((hrtime_t *)&cphrt);		\
			o = NSEC_TO_TICK(cphrt)

	mutex_enter(&usdsp->lock);
	upm = &(usdsp->us_pm);
	if (upm->timeout_id == 0) {
		mutex_exit(&usdsp->lock);
		goto do_return;
	}
	cur_spd = upm->cur_spd;
	dip = usdsp->dip;

	/*
	 * It is possible that we are monitoring a CPU which hasn't
	 * been initialized yet. We just come back under the assumption
	 * that this situation is temporary and rare.  If in future this
	 * is not true (e.g. we are running on really big machines which
	 * has many CPUs going in and out of service), we might need to
	 * revisit this and have this routine called only when corresponding
	 * CPU is initialized.
	 */
	/*
	 * We assume that a CPU is initialized and has a valid cpu_t
	 * structure, if it is ready for cross calls. If this changes,
	 * additional checks might be needed.
	 */
	if (!(CPU_XCALL_READY(usdsp->cpu_id))) {
		DPRINTF(D_PM_MONITOR, ("us_pm_monitor: instance %d: "
		    "CPU not ready for x-calls\n", ddi_get_instance(dip)));
		/*
		 * Make sure that we are busy so that framework doesn't
		 * try to bring us down in this situation.
		 */
		US_PM_MONITOR_PM_BUSY_COMP(dip, upm);
		US_PM_MONITOR_INIT(usdsp);
		mutex_exit(&usdsp->lock);
		goto do_return;
	}

	/*
	 * Make sure that we are still not at unknown power level.
	 */
	if (cur_spd == NULL) {
		DPRINTF(D_PM_MONITOR, ("us_pm_monitor: instance %d: "
		    "cur_spd is unknown\n", ddi_get_instance(dip)));
		US_PM_MONITOR_PM_BUSY_AND_RAISE(dip, usdsp, upm,
		    upm->targ_spd->pm_level);
		/*
		 * We just changed the speed. Wait till at least next
		 * call to this routine before proceeding ahead.
		 */
		US_PM_MONITOR_INIT(usdsp);
		mutex_exit(&usdsp->lock);
		goto do_return;
	}

	mutex_enter(&cpu_lock);
	if ((cp = cpu_get(usdsp->cpu_id)) == NULL) {
		mutex_exit(&cpu_lock);
		US_PM_MONITOR_INIT(usdsp);
		mutex_exit(&usdsp->lock);
		cmn_err(CE_WARN, "us_pm_monitor: instance %d: can't get cpu_t",
		    ddi_get_instance(dip));
		goto do_return;
	}
	GET_CPU_DATA(cp, CMS_USER, user_ticks);
	GET_CPU_DATA(cp, CMS_IDLE, idle_ticks);

	/*
	 * We can't do anything when we have just switched to a state
	 * because there is no valid timestamp.
	 */
	if (upm->lastquan_idle == 0) {
		upm->lastquan_idle = idle_ticks;
		upm->lastquan_user = user_ticks;
		upm->lastquan_lbolt = lbolt;
		mutex_exit(&cpu_lock);
		US_PM_MONITOR_INIT(usdsp);
		mutex_exit(&usdsp->lock);
		goto do_return;
	}

	idle_cnt = idle_ticks - upm->lastquan_idle;
	upm->lastquan_idle = idle_ticks;
	user_cnt = user_ticks - upm->lastquan_user;
	upm->lastquan_user = user_ticks;
	/*
	 * Various watermarks are based on this routine being called back
	 * exactly at the requested period. This is not guaranteed
	 * because this routine is called from a taskq that is dispatched
	 * from a timeout routine.  Handle this by finding out how many
	 * ticks have elapsed since the last call (lbolt_cnt) and adjusting
	 * the idle_cnt based on the delay added to the requested period
	 * by timeout and taskq.
	 */
	lbolt_cnt = lbolt - upm->lastquan_lbolt;
	upm->lastquan_lbolt = lbolt;
	mutex_exit(&cpu_lock);
	/*
	 * Time taken between recording the current counts and
	 * arranging the next call of this routine is an error in our
	 * calculation. We minimize the error by calling
	 * US_PM_MONITOR_INIT() here instead of end of this routine.
	 */
	US_PM_MONITOR_INIT(usdsp);
	DPRINTF(D_PM_MONITOR_VERBOSE, ("us_pm_monitor: instance %d: "
	    "idle count %d, user count %d, pm_level %d, pm_busycnt %d\n",
	    ddi_get_instance(dip), idle_cnt, user_cnt, cur_spd->pm_level,
	    upm->pm_busycnt));

#ifdef	DEBUG
	/*
	 * Notify that timeout and taskq has caused delays and we need to
	 * scale our parameters accordingly.
	 *
	 * To get accurate result, don't turn on other DPRINTFs with
	 * the following DPRINTF. PROM calls generated by other
	 * DPRINTFs changes the timing.
	 */
	if (lbolt_cnt > cur_spd->quant_cnt) {
		DPRINTF(D_PM_MONITOR_DELAY, ("us_pm_monitor: instance %d: "
		    "lbolt count %ld > quantum_count %u\n",
		    ddi_get_instance(dip), lbolt_cnt, cur_spd->quant_cnt));
	}
#endif	/* DEBUG */

	/*
	 * Adjust counts based on the delay added by timeout and taskq.
	 */
	idle_cnt = (idle_cnt * cur_spd->quant_cnt) / lbolt_cnt;
	user_cnt = (user_cnt * cur_spd->quant_cnt) / lbolt_cnt;
	if ((user_cnt > cur_spd->user_hwm) || (idle_cnt < cur_spd->idle_lwm &&
	    cur_spd->idle_blwm_cnt >= us_pm_idle_blwm_cnt_max)) {
		cur_spd->idle_blwm_cnt = 0;
		cur_spd->idle_bhwm_cnt = 0;
		/*
		 * In normal situation, arrange to go to next higher speed.
		 * If we are running in special direct pm mode, we just stay
		 * at the current speed.
		 */
		if (us_direct_pm) {
			US_PM_MONITOR_PM_BUSY_COMP(dip, upm);
		} else {
			new_spd = cur_spd->up_spd;
			ASSERT(new_spd != cur_spd);
			US_PM_MONITOR_PM_BUSY_AND_RAISE(dip, usdsp, upm,
			    new_spd->pm_level);
		}
	} else if ((user_cnt <= cur_spd->user_lwm) &&
		    (idle_cnt >= cur_spd->idle_hwm)) {
		cur_spd->idle_blwm_cnt = 0;
		cur_spd->idle_bhwm_cnt = 0;
		/*
		 * Arrange to go to next lower speed by informing our idle
		 * status to the power management framework.
		 */
		US_PM_MONITOR_PM_IDLE_COMP(dip, upm);
	} else {
		/*
		 * If we are between the idle water marks and have not
		 * been here enough consecutive times to be considered
		 * busy, just increment the count and return.
		 */
		if ((idle_cnt < cur_spd->idle_hwm) &&
		    (idle_cnt >= cur_spd->idle_lwm) &&
		    (cur_spd->idle_bhwm_cnt < us_pm_idle_bhwm_cnt_max)) {
			cur_spd->idle_blwm_cnt = 0;
			cur_spd->idle_bhwm_cnt++;
			mutex_exit(&usdsp->lock);
			goto do_return;
		}
		if (idle_cnt < cur_spd->idle_lwm) {
			cur_spd->idle_blwm_cnt++;
			cur_spd->idle_bhwm_cnt = 0;
		}
		/*
		 * Arranges to stay at the current speed.
		 */
		US_PM_MONITOR_PM_BUSY_COMP(dip, upm);
	}
	mutex_exit(&usdsp->lock);
do_return:
	mutex_enter(&upm->timeout_lock);
	ASSERT(upm->timeout_count > 0);
	upm->timeout_count--;
	cv_signal(&upm->timeout_cv);
	mutex_exit(&upm->timeout_lock);
}
