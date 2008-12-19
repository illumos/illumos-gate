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
 * CPU Device driver. The driver is not DDI-compliant.
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
#include <sys/sdt.h>

#include <sys/machsystm.h>
#include <sys/x_call.h>
#include <sys/cpudrv_mach.h>
#include <sys/msacct.h>

/*
 * CPU power management
 *
 * The supported power saving model is to slow down the CPU (on SPARC by
 * dividing the CPU clock and on x86 by dropping down a P-state).
 * Periodically we determine the amount of time the CPU is running
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
 * scheme and will work with all CPUs supporting this model. On SPARC, the
 * driver determines supported speeds by looking at 'clock-divisors' property
 * created by OBP. On x86, the driver retrieves the supported speeds from
 * ACPI.
 */

/*
 * Configuration function prototypes and data structures
 */
static int cpudrv_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int cpudrv_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);
static int cpudrv_power(dev_info_t *dip, int comp, int level);

struct dev_ops cpudrv_ops = {
	DEVO_REV,		/* rev */
	0,			/* refcnt */
	nodev,			/* getinfo */
	nulldev,		/* identify */
	nulldev,		/* probe */
	cpudrv_attach,		/* attach */
	cpudrv_detach,		/* detach */
	nodev,			/* reset */
	(struct cb_ops *)NULL,	/* cb_ops */
	(struct bus_ops *)NULL,	/* bus_ops */
	cpudrv_power,		/* power */
	ddi_quiesce_not_needed,		/* quiesce */
};

static struct modldrv modldrv = {
	&mod_driverops,			/* modops */
	"CPU Driver",			/* linkinfo */
	&cpudrv_ops,			/* dev_ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,		/* rev */
	&modldrv,		/* linkage */
	NULL
};

/*
 * Function prototypes
 */
static int cpudrv_pm_init_power(cpudrv_devstate_t *cpudsp);
static void cpudrv_pm_free(cpudrv_devstate_t *cpudsp);
static int cpudrv_pm_comp_create(cpudrv_devstate_t *cpudsp);
static void cpudrv_pm_monitor_disp(void *arg);
static void cpudrv_pm_monitor(void *arg);

/*
 * Driver global variables
 */
uint_t cpudrv_debug = 0;
void *cpudrv_state;
static uint_t cpudrv_pm_idle_hwm = CPUDRV_PM_IDLE_HWM;
static uint_t cpudrv_pm_idle_lwm = CPUDRV_PM_IDLE_LWM;
static uint_t cpudrv_pm_idle_buf_zone = CPUDRV_PM_IDLE_BUF_ZONE;
static uint_t cpudrv_pm_idle_bhwm_cnt_max = CPUDRV_PM_IDLE_BHWM_CNT_MAX;
static uint_t cpudrv_pm_idle_blwm_cnt_max = CPUDRV_PM_IDLE_BLWM_CNT_MAX;
static uint_t cpudrv_pm_user_hwm = CPUDRV_PM_USER_HWM;

/*
 * cpudrv_direct_pm allows user applications to directly control the
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
 * In the future, provide an ioctl to control setting of this mode. In
 * that case, this variable should move to the state structure and
 * be protected by the lock in the state structure.
 */
int cpudrv_direct_pm = 0;

/*
 * Arranges for the handler function to be called at the interval suitable
 * for current speed.
 */
#define	CPUDRV_PM_MONITOR_INIT(cpudsp) { \
	if (CPUDRV_PM_POWER_ENABLED(cpudsp)) { \
		ASSERT(mutex_owned(&(cpudsp)->lock)); \
		(cpudsp)->cpudrv_pm.timeout_id = \
		    timeout(cpudrv_pm_monitor_disp, \
		    (cpudsp), (((cpudsp)->cpudrv_pm.cur_spd == NULL) ? \
		    CPUDRV_PM_QUANT_CNT_OTHR : \
		    (cpudsp)->cpudrv_pm.cur_spd->quant_cnt)); \
	} \
}

/*
 * Arranges for the handler function not to be called back.
 */
#define	CPUDRV_PM_MONITOR_FINI(cpudsp) { \
	timeout_id_t tmp_tid; \
	ASSERT(mutex_owned(&(cpudsp)->lock)); \
	tmp_tid = (cpudsp)->cpudrv_pm.timeout_id; \
	(cpudsp)->cpudrv_pm.timeout_id = 0; \
	mutex_exit(&(cpudsp)->lock); \
	if (tmp_tid != 0) { \
		(void) untimeout(tmp_tid); \
		mutex_enter(&(cpudsp)->cpudrv_pm.timeout_lock); \
		while ((cpudsp)->cpudrv_pm.timeout_count != 0) \
			cv_wait(&(cpudsp)->cpudrv_pm.timeout_cv, \
			    &(cpudsp)->cpudrv_pm.timeout_lock); \
		mutex_exit(&(cpudsp)->cpudrv_pm.timeout_lock); \
	} \
	mutex_enter(&(cpudsp)->lock); \
}

int
_init(void)
{
	int	error;

	DPRINTF(D_INIT, (" _init: function called\n"));
	if ((error = ddi_soft_state_init(&cpudrv_state,
	    sizeof (cpudrv_devstate_t), 0)) != 0) {
		return (error);
	}

	if ((error = mod_install(&modlinkage)) != 0)  {
		ddi_soft_state_fini(&cpudrv_state);
	}

	/*
	 * Callbacks used by the PPM driver.
	 */
	CPUDRV_PM_SET_PPM_CALLBACKS();
	return (error);
}

int
_fini(void)
{
	int	error;

	DPRINTF(D_FINI, (" _fini: function called\n"));
	if ((error = mod_remove(&modlinkage)) == 0) {
		ddi_soft_state_fini(&cpudrv_state);
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
cpudrv_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int			instance;
	cpudrv_devstate_t	*cpudsp;
	extern pri_t		maxclsyspri;

	instance = ddi_get_instance(dip);

	switch (cmd) {
	case DDI_ATTACH:
		DPRINTF(D_ATTACH, ("cpudrv_attach: instance %d: "
		    "DDI_ATTACH called\n", instance));
		if (CPUDRV_PM_DISABLED())
			return (DDI_FAILURE);
		if (ddi_soft_state_zalloc(cpudrv_state, instance) !=
		    DDI_SUCCESS) {
			cmn_err(CE_WARN, "cpudrv_attach: instance %d: "
			    "can't allocate state", instance);
			CPUDRV_PM_DISABLE();
			return (DDI_FAILURE);
		}
		if ((cpudsp = ddi_get_soft_state(cpudrv_state, instance)) ==
		    NULL) {
			cmn_err(CE_WARN, "cpudrv_attach: instance %d: "
			    "can't get state", instance);
			ddi_soft_state_free(cpudrv_state, instance);
			CPUDRV_PM_DISABLE();
			return (DDI_FAILURE);
		}
		cpudsp->dip = dip;

		/*
		 * Find CPU number for this dev_info node.
		 */
		if (!cpudrv_pm_get_cpu_id(dip, &(cpudsp->cpu_id))) {
			cmn_err(CE_WARN, "cpudrv_attach: instance %d: "
			    "can't convert dip to cpu_id", instance);
			ddi_soft_state_free(cpudrv_state, instance);
			CPUDRV_PM_DISABLE();
			return (DDI_FAILURE);
		}
		if (!cpudrv_mach_pm_init(cpudsp)) {
			ddi_soft_state_free(cpudrv_state, instance);
			CPUDRV_PM_DISABLE();
			return (DDI_FAILURE);
		}
		mutex_init(&cpudsp->lock, NULL, MUTEX_DRIVER, NULL);
		if (CPUDRV_PM_POWER_ENABLED(cpudsp)) {
			if (cpudrv_pm_init_power(cpudsp) != DDI_SUCCESS) {
				CPUDRV_PM_DISABLE();
				cpudrv_pm_free(cpudsp);
				ddi_soft_state_free(cpudrv_state, instance);
				return (DDI_FAILURE);
			}
			if (cpudrv_pm_comp_create(cpudsp) != DDI_SUCCESS) {
				CPUDRV_PM_DISABLE();
				cpudrv_pm_free(cpudsp);
				ddi_soft_state_free(cpudrv_state, instance);
				return (DDI_FAILURE);
			}
			if (ddi_prop_update_string(DDI_DEV_T_NONE,
			    dip, "pm-class", "CPU") != DDI_PROP_SUCCESS) {
				CPUDRV_PM_DISABLE();
				cpudrv_pm_free(cpudsp);
				ddi_soft_state_free(cpudrv_state, instance);
				return (DDI_FAILURE);
			}

			/*
			 * Taskq is used to dispatch routine to monitor CPU
			 * activities.
			 */
			cpudsp->cpudrv_pm.tq = taskq_create_instance(
			    "cpudrv_pm_monitor",
			    ddi_get_instance(dip), CPUDRV_PM_TASKQ_THREADS,
			    (maxclsyspri - 1), CPUDRV_PM_TASKQ_MIN,
			    CPUDRV_PM_TASKQ_MAX,
			    TASKQ_PREPOPULATE|TASKQ_CPR_SAFE);

			mutex_init(&cpudsp->cpudrv_pm.timeout_lock, NULL,
			    MUTEX_DRIVER, NULL);
			cv_init(&cpudsp->cpudrv_pm.timeout_cv, NULL,
			    CV_DEFAULT, NULL);

			/*
			 * Driver needs to assume that CPU is running at
			 * unknown speed at DDI_ATTACH and switch it to the
			 * needed speed. We assume that initial needed speed
			 * is full speed for us.
			 */
			/*
			 * We need to take the lock because cpudrv_pm_monitor()
			 * will start running in parallel with attach().
			 */
			mutex_enter(&cpudsp->lock);
			cpudsp->cpudrv_pm.cur_spd = NULL;
			cpudsp->cpudrv_pm.pm_started = B_FALSE;
			/*
			 * We don't call pm_raise_power() directly from attach
			 * because driver attach for a slave CPU node can
			 * happen before the CPU is even initialized. We just
			 * start the monitoring system which understands
			 * unknown speed and moves CPU to top speed when it
			 * has been initialized.
			 */
			CPUDRV_PM_MONITOR_INIT(cpudsp);
			mutex_exit(&cpudsp->lock);

		}

		CPUDRV_PM_INSTALL_MAX_CHANGE_HANDLER(cpudsp, dip);

		ddi_report_dev(dip);
		return (DDI_SUCCESS);

	case DDI_RESUME:
		DPRINTF(D_ATTACH, ("cpudrv_attach: instance %d: "
		    "DDI_RESUME called\n", instance));

		cpudsp = ddi_get_soft_state(cpudrv_state, instance);
		ASSERT(cpudsp != NULL);

		/*
		 * Nothing to do for resume, if not doing active PM.
		 */
		if (!CPUDRV_PM_POWER_ENABLED(cpudsp))
			return (DDI_SUCCESS);

		mutex_enter(&cpudsp->lock);
		/*
		 * Driver needs to assume that CPU is running at unknown speed
		 * at DDI_RESUME and switch it to the needed speed. We assume
		 * that the needed speed is full speed for us.
		 */
		cpudsp->cpudrv_pm.cur_spd = NULL;
		CPUDRV_PM_MONITOR_INIT(cpudsp);
		mutex_exit(&cpudsp->lock);
		CPUDRV_PM_REDEFINE_TOPSPEED(dip);
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}
}

/*
 * Driver detach(9e) entry point.
 */
static int
cpudrv_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int			instance;
	cpudrv_devstate_t	*cpudsp;
	cpudrv_pm_t		*cpupm;

	instance = ddi_get_instance(dip);

	switch (cmd) {
	case DDI_DETACH:
		DPRINTF(D_DETACH, ("cpudrv_detach: instance %d: "
		    "DDI_DETACH called\n", instance));
		/*
		 * If the only thing supported by the driver is power
		 * management, we can in future enhance the driver and
		 * framework that loads it to unload the driver when
		 * user has disabled CPU power management.
		 */
		return (DDI_FAILURE);

	case DDI_SUSPEND:
		DPRINTF(D_DETACH, ("cpudrv_detach: instance %d: "
		    "DDI_SUSPEND called\n", instance));

		cpudsp = ddi_get_soft_state(cpudrv_state, instance);
		ASSERT(cpudsp != NULL);

		/*
		 * Nothing to do for suspend, if not doing active PM.
		 */
		if (!CPUDRV_PM_POWER_ENABLED(cpudsp))
			return (DDI_SUCCESS);

		/*
		 * During a checkpoint-resume sequence, framework will
		 * stop interrupts to quiesce kernel activity. This will
		 * leave our monitoring system ineffective. Handle this
		 * by stopping our monitoring system and bringing CPU
		 * to full speed. In case we are in special direct pm
		 * mode, we leave the CPU at whatever speed it is. This
		 * is harmless other than speed.
		 */
		mutex_enter(&cpudsp->lock);
		cpupm = &(cpudsp->cpudrv_pm);

		DPRINTF(D_DETACH, ("cpudrv_detach: instance %d: DDI_SUSPEND - "
		    "cur_spd %d, topspeed %d\n", instance,
		    cpupm->cur_spd->pm_level,
		    CPUDRV_PM_TOPSPEED(cpupm)->pm_level));

		CPUDRV_PM_MONITOR_FINI(cpudsp);

		if (!cpudrv_direct_pm && (cpupm->cur_spd !=
		    CPUDRV_PM_TOPSPEED(cpupm))) {
			if (cpupm->pm_busycnt < 1) {
				if ((pm_busy_component(dip, CPUDRV_PM_COMP_NUM)
				    == DDI_SUCCESS)) {
					cpupm->pm_busycnt++;
				} else {
					CPUDRV_PM_MONITOR_INIT(cpudsp);
					mutex_exit(&cpudsp->lock);
					cmn_err(CE_WARN, "cpudrv_detach: "
					    "instance %d: can't busy CPU "
					    "component", instance);
					return (DDI_FAILURE);
				}
			}
			mutex_exit(&cpudsp->lock);
			if (pm_raise_power(dip, CPUDRV_PM_COMP_NUM,
			    CPUDRV_PM_TOPSPEED(cpupm)->pm_level) !=
			    DDI_SUCCESS) {
				mutex_enter(&cpudsp->lock);
				CPUDRV_PM_MONITOR_INIT(cpudsp);
				mutex_exit(&cpudsp->lock);
				cmn_err(CE_WARN, "cpudrv_detach: instance %d: "
				    "can't raise CPU power level to %d",
				    instance,
				    CPUDRV_PM_TOPSPEED(cpupm)->pm_level);
				return (DDI_FAILURE);
			} else {
				return (DDI_SUCCESS);
			}
		} else {
			mutex_exit(&cpudsp->lock);
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
cpudrv_power(dev_info_t *dip, int comp, int level)
{
	int			instance;
	cpudrv_devstate_t	*cpudsp;
	cpudrv_pm_t 		*cpupm;
	cpudrv_pm_spd_t		*new_spd;
	boolean_t		is_ready;
	int			ret;

	instance = ddi_get_instance(dip);

	DPRINTF(D_POWER, ("cpudrv_power: instance %d: level %d\n",
	    instance, level));
	if ((cpudsp = ddi_get_soft_state(cpudrv_state, instance)) == NULL) {
		cmn_err(CE_WARN, "cpudrv_power: instance %d: can't get state",
		    instance);
		return (DDI_FAILURE);
	}

	mutex_enter(&cpudsp->lock);
	cpupm = &(cpudsp->cpudrv_pm);

	/*
	 * In normal operation, we fail if we are busy and request is
	 * to lower the power level. We let this go through if the driver
	 * is in special direct pm mode. On x86, we also let this through
	 * if the change is due to a request to govern the max speed.
	 */
	if (!cpudrv_direct_pm && (cpupm->pm_busycnt >= 1) &&
	    !cpudrv_pm_is_governor_thread(cpupm)) {
		if ((cpupm->cur_spd != NULL) &&
		    (level < cpupm->cur_spd->pm_level)) {
			mutex_exit(&cpudsp->lock);
			return (DDI_FAILURE);
		}
	}

	for (new_spd = cpupm->head_spd; new_spd; new_spd = new_spd->down_spd) {
		if (new_spd->pm_level == level)
			break;
	}
	if (!new_spd) {
		CPUDRV_PM_RESET_GOVERNOR_THREAD(cpupm);
		mutex_exit(&cpudsp->lock);
		cmn_err(CE_WARN, "cpudrv_power: instance %d: "
		    "can't locate new CPU speed", instance);
		return (DDI_FAILURE);
	}

	/*
	 * We currently refuse to power manage if the CPU is not ready to
	 * take cross calls (cross calls fail silently if CPU is not ready
	 * for it).
	 *
	 * Additionally, for x86 platforms we cannot power manage
	 * any one instance, until all instances have been initialized.
	 * That's because we don't know what the CPU domains look like
	 * until all instances have been initialized.
	 */
	is_ready = CPUDRV_PM_XCALL_IS_READY(cpudsp->cpu_id);
	if (!is_ready) {
		DPRINTF(D_POWER, ("cpudrv_power: instance %d: "
		    "CPU not ready for x-calls\n", instance));
	} else if (!(is_ready = cpudrv_pm_power_ready())) {
		DPRINTF(D_POWER, ("cpudrv_power: instance %d: "
		    "waiting for all CPUs to be power manageable\n", instance));
	}
	if (!is_ready) {
		CPUDRV_PM_RESET_GOVERNOR_THREAD(cpupm);
		mutex_exit(&cpudsp->lock);
		return (DDI_FAILURE);
	}

	/*
	 * Execute CPU specific routine on the requested CPU to change its
	 * speed to normal-speed/divisor.
	 */
	if ((ret = cpudrv_pm_change_speed(cpudsp, new_spd)) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "cpudrv_power: cpudrv_pm_change_speed() "
		    "return = %d", ret);
		mutex_exit(&cpudsp->lock);
		return (DDI_FAILURE);
	}

	/*
	 * DTrace probe point for CPU speed change transition
	 */
	DTRACE_PROBE3(cpu__change__speed, cpudrv_devstate_t *, cpudsp,
	    cpudrv_pm_t *, cpupm, cpudrv_pm_spd_t *, new_spd);

	/*
	 * Reset idle threshold time for the new power level.
	 */
	if ((cpupm->cur_spd != NULL) && (level < cpupm->cur_spd->pm_level)) {
		if (pm_idle_component(dip, CPUDRV_PM_COMP_NUM) ==
		    DDI_SUCCESS) {
			if (cpupm->pm_busycnt >= 1)
				cpupm->pm_busycnt--;
		} else
			cmn_err(CE_WARN, "cpudrv_power: instance %d: can't "
			    "idle CPU component", ddi_get_instance(dip));
	}
	/*
	 * Reset various parameters because we are now running at new speed.
	 */
	cpupm->lastquan_mstate[CMS_IDLE] = 0;
	cpupm->lastquan_mstate[CMS_SYSTEM] = 0;
	cpupm->lastquan_mstate[CMS_USER] = 0;
	cpupm->lastquan_lbolt = 0;
	cpupm->cur_spd = new_spd;
	CPUDRV_PM_RESET_GOVERNOR_THREAD(cpupm);
	mutex_exit(&cpudsp->lock);

	return (DDI_SUCCESS);
}

/*
 * Initialize the field that will be used for reporting
 * the supported_frequencies_Hz cpu_info kstat.
 */
static void
set_supp_freqs(cpu_t *cp, cpudrv_pm_t *cpupm)
{
	char		*supp_freqs;
	char		*sfptr;
	uint64_t	*speeds;
	cpudrv_pm_spd_t	*spd;
	int		i;
#define	UINT64_MAX_STRING (sizeof ("18446744073709551615"))

	speeds = kmem_zalloc(cpupm->num_spd * sizeof (uint64_t), KM_SLEEP);
	for (i = cpupm->num_spd - 1, spd = cpupm->head_spd; spd;
	    i--, spd = spd->down_spd) {
		speeds[i] =
		    CPUDRV_PM_SPEED_HZ(cp->cpu_type_info.pi_clock, spd->speed);
	}

	supp_freqs = kmem_zalloc((UINT64_MAX_STRING * cpupm->num_spd),
	    KM_SLEEP);
	sfptr = supp_freqs;
	for (i = 0; i < cpupm->num_spd; i++) {
		if (i == cpupm->num_spd - 1) {
			(void) sprintf(sfptr, "%"PRIu64, speeds[i]);
		} else {
			(void) sprintf(sfptr, "%"PRIu64":", speeds[i]);
			sfptr = supp_freqs + strlen(supp_freqs);
		}
	}
	cpu_set_supp_freqs(cp, supp_freqs);
	kmem_free(supp_freqs, (UINT64_MAX_STRING * cpupm->num_spd));
	kmem_free(speeds, cpupm->num_spd * sizeof (uint64_t));
}

/*
 * Initialize power management data.
 */
static int
cpudrv_pm_init_power(cpudrv_devstate_t *cpudsp)
{
	cpudrv_pm_t 	*cpupm = &(cpudsp->cpudrv_pm);
	cpudrv_pm_spd_t	*cur_spd;
	cpudrv_pm_spd_t	*prev_spd = NULL;
	int		*speeds;
	uint_t		nspeeds;
	int		idle_cnt_percent;
	int		user_cnt_percent;
	int		i;

	CPUDRV_PM_GET_SPEEDS(cpudsp, speeds, nspeeds);
	if (nspeeds < 2) {
		/* Need at least two speeds to power manage */
		CPUDRV_PM_FREE_SPEEDS(speeds, nspeeds);
		return (DDI_FAILURE);
	}
	cpupm->num_spd = nspeeds;

	/*
	 * Calculate the watermarks and other parameters based on the
	 * supplied speeds.
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
	for (i = 0; i < nspeeds; i++) {
		cur_spd = kmem_zalloc(sizeof (cpudrv_pm_spd_t), KM_SLEEP);
		cur_spd->speed = speeds[i];
		if (i == 0) {	/* normal speed */
			cpupm->head_spd = cur_spd;
			CPUDRV_PM_TOPSPEED(cpupm) = cur_spd;
			cur_spd->quant_cnt = CPUDRV_PM_QUANT_CNT_NORMAL;
			cur_spd->idle_hwm =
			    (cpudrv_pm_idle_hwm * cur_spd->quant_cnt) / 100;
			/* can't speed anymore */
			cur_spd->idle_lwm = 0;
			cur_spd->user_hwm = UINT_MAX;
		} else {
			cur_spd->quant_cnt = CPUDRV_PM_QUANT_CNT_OTHR;
			ASSERT(prev_spd != NULL);
			prev_spd->down_spd = cur_spd;
			cur_spd->up_spd = cpupm->head_spd;

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
			idle_cnt_percent = CPUDRV_PM_IDLE_CNT_PERCENT(
			    cpudrv_pm_idle_hwm, speeds, i);
			idle_cnt_percent = max(idle_cnt_percent,
			    (cpudrv_pm_idle_lwm + cpudrv_pm_idle_buf_zone));
			cur_spd->idle_hwm =
			    (idle_cnt_percent * cur_spd->quant_cnt) / 100;
			cur_spd->idle_lwm =
			    (cpudrv_pm_idle_lwm * cur_spd->quant_cnt) / 100;

			/*
			 * The lwm for user threads are determined such that
			 * if CPU slows down, the load of work in the
			 * new speed would still keep the CPU at or below the
			 * user_hwm in the new speed.  This is to prevent
			 * the quick jump back up to higher speed.
			 */
			cur_spd->user_hwm = (cpudrv_pm_user_hwm *
			    cur_spd->quant_cnt) / 100;
			user_cnt_percent = CPUDRV_PM_USER_CNT_PERCENT(
			    cpudrv_pm_user_hwm, speeds, i);
			prev_spd->user_lwm =
			    (user_cnt_percent * prev_spd->quant_cnt) / 100;
		}
		prev_spd = cur_spd;
	}
	/* Slowest speed. Can't slow down anymore */
	cur_spd->idle_hwm = UINT_MAX;
	cur_spd->user_lwm = -1;
#ifdef	DEBUG
	DPRINTF(D_PM_INIT, ("cpudrv_pm_init: instance %d: head_spd spd %d, "
	    "num_spd %d\n", ddi_get_instance(cpudsp->dip),
	    cpupm->head_spd->speed, cpupm->num_spd));
	for (cur_spd = cpupm->head_spd; cur_spd; cur_spd = cur_spd->down_spd) {
		DPRINTF(D_PM_INIT, ("cpudrv_pm_init: instance %d: speed %d, "
		    "down_spd spd %d, idle_hwm %d, user_lwm %d, "
		    "up_spd spd %d, idle_lwm %d, user_hwm %d, "
		    "quant_cnt %d\n", ddi_get_instance(cpudsp->dip),
		    cur_spd->speed,
		    (cur_spd->down_spd ? cur_spd->down_spd->speed : 0),
		    cur_spd->idle_hwm, cur_spd->user_lwm,
		    (cur_spd->up_spd ? cur_spd->up_spd->speed : 0),
		    cur_spd->idle_lwm, cur_spd->user_hwm,
		    cur_spd->quant_cnt));
	}
#endif	/* DEBUG */
	CPUDRV_PM_FREE_SPEEDS(speeds, nspeeds);
	return (DDI_SUCCESS);
}

/*
 * Free CPU power management data.
 */
static void
cpudrv_pm_free(cpudrv_devstate_t *cpudsp)
{
	cpudrv_pm_t 	*cpupm = &(cpudsp->cpudrv_pm);
	cpudrv_pm_spd_t	*cur_spd, *next_spd;

	cur_spd = cpupm->head_spd;
	while (cur_spd) {
		next_spd = cur_spd->down_spd;
		kmem_free(cur_spd, sizeof (cpudrv_pm_spd_t));
		cur_spd = next_spd;
	}
	bzero(cpupm, sizeof (cpudrv_pm_t));
	cpudrv_mach_pm_free(cpudsp);
}

/*
 * Create pm-components property.
 */
static int
cpudrv_pm_comp_create(cpudrv_devstate_t *cpudsp)
{
	cpudrv_pm_t 	*cpupm = &(cpudsp->cpudrv_pm);
	cpudrv_pm_spd_t	*cur_spd;
	char		**pmc;
	int		size;
	char		name[] = "NAME=CPU Speed";
	int		i, j;
	uint_t		comp_spd;
	int		result = DDI_FAILURE;

	pmc = kmem_zalloc((cpupm->num_spd + 1) * sizeof (char *), KM_SLEEP);
	size = CPUDRV_PM_COMP_SIZE();
	if (cpupm->num_spd > CPUDRV_PM_COMP_MAX_VAL) {
		cmn_err(CE_WARN, "cpudrv_pm_comp_create: instance %d: "
		    "number of speeds exceeded limits",
		    ddi_get_instance(cpudsp->dip));
		kmem_free(pmc, (cpupm->num_spd + 1) * sizeof (char *));
		return (result);
	}

	for (i = cpupm->num_spd, cur_spd = cpupm->head_spd; i > 0;
	    i--, cur_spd = cur_spd->down_spd) {
		cur_spd->pm_level = i;
		pmc[i] = kmem_zalloc((size * sizeof (char)), KM_SLEEP);
		comp_spd = CPUDRV_PM_COMP_SPEED(cpupm, cur_spd);
		if (comp_spd > CPUDRV_PM_COMP_MAX_VAL) {
			cmn_err(CE_WARN, "cpudrv_pm_comp_create: "
			    "instance %d: speed exceeded limits",
			    ddi_get_instance(cpudsp->dip));
			for (j = cpupm->num_spd; j >= i; j--) {
				kmem_free(pmc[j], size * sizeof (char));
			}
			kmem_free(pmc, (cpupm->num_spd + 1) *
			    sizeof (char *));
			return (result);
		}
		CPUDRV_PM_COMP_SPRINT(pmc[i], cpupm, cur_spd, comp_spd)
		DPRINTF(D_PM_COMP_CREATE, ("cpudrv_pm_comp_create: "
		    "instance %d: pm-components power level %d string '%s'\n",
		    ddi_get_instance(cpudsp->dip), i, pmc[i]));
	}
	pmc[0] = kmem_zalloc(sizeof (name), KM_SLEEP);
	(void) strcat(pmc[0], name);
	DPRINTF(D_PM_COMP_CREATE, ("cpudrv_pm_comp_create: instance %d: "
	    "pm-components component name '%s'\n",
	    ddi_get_instance(cpudsp->dip), pmc[0]));

	if (ddi_prop_update_string_array(DDI_DEV_T_NONE, cpudsp->dip,
	    "pm-components", pmc, cpupm->num_spd + 1) == DDI_PROP_SUCCESS) {
		result = DDI_SUCCESS;
	} else {
		cmn_err(CE_WARN, "cpudrv_pm_comp_create: instance %d: "
		    "can't create pm-components property",
		    ddi_get_instance(cpudsp->dip));
	}

	for (i = cpupm->num_spd; i > 0; i--) {
		kmem_free(pmc[i], size * sizeof (char));
	}
	kmem_free(pmc[0], sizeof (name));
	kmem_free(pmc, (cpupm->num_spd + 1) * sizeof (char *));
	return (result);
}

/*
 * Mark a component idle.
 */
#define	CPUDRV_PM_MONITOR_PM_IDLE_COMP(dip, cpupm) { \
	if ((cpupm)->pm_busycnt >= 1) { \
		if (pm_idle_component((dip), CPUDRV_PM_COMP_NUM) == \
		    DDI_SUCCESS) { \
			DPRINTF(D_PM_MONITOR, ("cpudrv_pm_monitor: " \
			    "instance %d: pm_idle_component called\n", \
			    ddi_get_instance((dip)))); \
			(cpupm)->pm_busycnt--; \
		} else { \
			cmn_err(CE_WARN, "cpudrv_pm_monitor: instance %d: " \
			    "can't idle CPU component", \
			    ddi_get_instance((dip))); \
		} \
	} \
}

/*
 * Marks a component busy in both PM framework and driver state structure.
 */
#define	CPUDRV_PM_MONITOR_PM_BUSY_COMP(dip, cpupm) { \
	if ((cpupm)->pm_busycnt < 1) { \
		if (pm_busy_component((dip), CPUDRV_PM_COMP_NUM) == \
		    DDI_SUCCESS) { \
			DPRINTF(D_PM_MONITOR, ("cpudrv_pm_monitor: " \
			    "instance %d: pm_busy_component called\n", \
			    ddi_get_instance((dip)))); \
			(cpupm)->pm_busycnt++; \
		} else { \
			cmn_err(CE_WARN, "cpudrv_pm_monitor: instance %d: " \
			    "can't busy CPU component", \
			    ddi_get_instance((dip))); \
		} \
	} \
}

/*
 * Marks a component busy and calls pm_raise_power().
 */
#define	CPUDRV_PM_MONITOR_PM_BUSY_AND_RAISE(dip, cpudsp, cpupm, new_level) { \
	/* \
	 * Mark driver and PM framework busy first so framework doesn't try \
	 * to bring CPU to lower speed when we need to be at higher speed. \
	 */ \
	CPUDRV_PM_MONITOR_PM_BUSY_COMP((dip), (cpupm)); \
	mutex_exit(&(cpudsp)->lock); \
	DPRINTF(D_PM_MONITOR, ("cpudrv_pm_monitor: instance %d: " \
	    "pm_raise_power called to %d\n", ddi_get_instance((dip)), \
		(new_level))); \
	if (pm_raise_power((dip), CPUDRV_PM_COMP_NUM, (new_level)) != \
	    DDI_SUCCESS) { \
		cmn_err(CE_WARN, "cpudrv_pm_monitor: instance %d: can't " \
		    "raise CPU power level", ddi_get_instance((dip))); \
	} \
	mutex_enter(&(cpudsp)->lock); \
}

/*
 * In order to monitor a CPU, we need to hold cpu_lock to access CPU
 * statistics. Holding cpu_lock is not allowed from a callout routine.
 * We dispatch a taskq to do that job.
 */
static void
cpudrv_pm_monitor_disp(void *arg)
{
	cpudrv_devstate_t	*cpudsp = (cpudrv_devstate_t *)arg;

	/*
	 * We are here because the last task has scheduled a timeout.
	 * The queue should be empty at this time.
	 */
	mutex_enter(&cpudsp->cpudrv_pm.timeout_lock);
	if (!taskq_dispatch(cpudsp->cpudrv_pm.tq, cpudrv_pm_monitor, arg,
	    TQ_NOSLEEP)) {
		mutex_exit(&cpudsp->cpudrv_pm.timeout_lock);
		DPRINTF(D_PM_MONITOR, ("cpudrv_pm_monitor_disp: failed to "
		    "dispatch the cpudrv_pm_monitor taskq\n"));
		mutex_enter(&cpudsp->lock);
		CPUDRV_PM_MONITOR_INIT(cpudsp);
		mutex_exit(&cpudsp->lock);
		return;
	}
	cpudsp->cpudrv_pm.timeout_count++;
	mutex_exit(&cpudsp->cpudrv_pm.timeout_lock);
}

/*
 * Monitors each CPU for the amount of time idle thread was running in the
 * last quantum and arranges for the CPU to go to the lower or higher speed.
 * Called at the time interval appropriate for the current speed. The
 * time interval for normal speed is CPUDRV_PM_QUANT_CNT_NORMAL. The time
 * interval for other speeds (including unknown speed) is
 * CPUDRV_PM_QUANT_CNT_OTHR.
 */
static void
cpudrv_pm_monitor(void *arg)
{
	cpudrv_devstate_t	*cpudsp = (cpudrv_devstate_t *)arg;
	cpudrv_pm_t		*cpupm;
	cpudrv_pm_spd_t		*cur_spd, *new_spd;
	cpu_t			*cp;
	dev_info_t		*dip;
	uint_t			idle_cnt, user_cnt, system_cnt;
	clock_t			lbolt_cnt;
	hrtime_t		msnsecs[NCMSTATES];
	boolean_t		is_ready;

#define	GET_CPU_MSTATE_CNT(state, cnt) \
	msnsecs[state] = NSEC_TO_TICK(msnsecs[state]); \
	if (cpupm->lastquan_mstate[state] > msnsecs[state]) \
		msnsecs[state] = cpupm->lastquan_mstate[state]; \
	cnt = msnsecs[state] - cpupm->lastquan_mstate[state]; \
	cpupm->lastquan_mstate[state] = msnsecs[state]

	mutex_enter(&cpudsp->lock);
	cpupm = &(cpudsp->cpudrv_pm);
	if (cpupm->timeout_id == 0) {
		mutex_exit(&cpudsp->lock);
		goto do_return;
	}
	cur_spd = cpupm->cur_spd;
	dip = cpudsp->dip;

	/*
	 * We assume that a CPU is initialized and has a valid cpu_t
	 * structure, if it is ready for cross calls. If this changes,
	 * additional checks might be needed.
	 *
	 * Additionally, for x86 platforms we cannot power manage
	 * any one instance, until all instances have been initialized.
	 * That's because we don't know what the CPU domains look like
	 * until all instances have been initialized.
	 */
	is_ready = CPUDRV_PM_XCALL_IS_READY(cpudsp->cpu_id);
	if (!is_ready) {
		DPRINTF(D_PM_MONITOR, ("cpudrv_pm_monitor: instance %d: "
		    "CPU not ready for x-calls\n", ddi_get_instance(dip)));
	} else if (!(is_ready = cpudrv_pm_power_ready())) {
		DPRINTF(D_PM_MONITOR, ("cpudrv_pm_monitor: instance %d: "
		    "waiting for all CPUs to be power manageable\n",
		    ddi_get_instance(dip)));
	}
	if (!is_ready) {
		/*
		 * Make sure that we are busy so that framework doesn't
		 * try to bring us down in this situation.
		 */
		CPUDRV_PM_MONITOR_PM_BUSY_COMP(dip, cpupm);
		CPUDRV_PM_MONITOR_INIT(cpudsp);
		mutex_exit(&cpudsp->lock);
		goto do_return;
	}

	/*
	 * Make sure that we are still not at unknown power level.
	 */
	if (cur_spd == NULL) {
		DPRINTF(D_PM_MONITOR, ("cpudrv_pm_monitor: instance %d: "
		    "cur_spd is unknown\n", ddi_get_instance(dip)));
		CPUDRV_PM_MONITOR_PM_BUSY_AND_RAISE(dip, cpudsp, cpupm,
		    CPUDRV_PM_TOPSPEED(cpupm)->pm_level);
		/*
		 * We just changed the speed. Wait till at least next
		 * call to this routine before proceeding ahead.
		 */
		CPUDRV_PM_MONITOR_INIT(cpudsp);
		mutex_exit(&cpudsp->lock);
		goto do_return;
	}

	mutex_enter(&cpu_lock);
	if ((cp = cpu_get(cpudsp->cpu_id)) == NULL) {
		mutex_exit(&cpu_lock);
		CPUDRV_PM_MONITOR_INIT(cpudsp);
		mutex_exit(&cpudsp->lock);
		cmn_err(CE_WARN, "cpudrv_pm_monitor: instance %d: can't get "
		    "cpu_t", ddi_get_instance(dip));
		goto do_return;
	}

	if (!cpupm->pm_started) {
		cpupm->pm_started = B_TRUE;
		set_supp_freqs(cp, cpupm);
	}

	get_cpu_mstate(cp, msnsecs);
	GET_CPU_MSTATE_CNT(CMS_IDLE, idle_cnt);
	GET_CPU_MSTATE_CNT(CMS_USER, user_cnt);
	GET_CPU_MSTATE_CNT(CMS_SYSTEM, system_cnt);

	/*
	 * We can't do anything when we have just switched to a state
	 * because there is no valid timestamp.
	 */
	if (cpupm->lastquan_lbolt == 0) {
		cpupm->lastquan_lbolt = lbolt;
		mutex_exit(&cpu_lock);
		CPUDRV_PM_MONITOR_INIT(cpudsp);
		mutex_exit(&cpudsp->lock);
		goto do_return;
	}

	/*
	 * Various watermarks are based on this routine being called back
	 * exactly at the requested period. This is not guaranteed
	 * because this routine is called from a taskq that is dispatched
	 * from a timeout routine.  Handle this by finding out how many
	 * ticks have elapsed since the last call (lbolt_cnt) and adjusting
	 * the idle_cnt based on the delay added to the requested period
	 * by timeout and taskq.
	 */
	lbolt_cnt = lbolt - cpupm->lastquan_lbolt;
	cpupm->lastquan_lbolt = lbolt;
	mutex_exit(&cpu_lock);
	/*
	 * Time taken between recording the current counts and
	 * arranging the next call of this routine is an error in our
	 * calculation. We minimize the error by calling
	 * CPUDRV_PM_MONITOR_INIT() here instead of end of this routine.
	 */
	CPUDRV_PM_MONITOR_INIT(cpudsp);
	DPRINTF(D_PM_MONITOR_VERBOSE, ("cpudrv_pm_monitor: instance %d: "
	    "idle count %d, user count %d, system count %d, pm_level %d, "
	    "pm_busycnt %d\n", ddi_get_instance(dip), idle_cnt, user_cnt,
	    system_cnt, cur_spd->pm_level, cpupm->pm_busycnt));

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
		DPRINTF(D_PM_MONITOR_DELAY, ("cpudrv_pm_monitor: instance %d: "
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
	    cur_spd->idle_blwm_cnt >= cpudrv_pm_idle_blwm_cnt_max)) {
		cur_spd->idle_blwm_cnt = 0;
		cur_spd->idle_bhwm_cnt = 0;
		/*
		 * In normal situation, arrange to go to next higher speed.
		 * If we are running in special direct pm mode, we just stay
		 * at the current speed.
		 */
		if (cur_spd == cur_spd->up_spd || cpudrv_direct_pm) {
			CPUDRV_PM_MONITOR_PM_BUSY_COMP(dip, cpupm);
		} else {
			new_spd = cur_spd->up_spd;
			CPUDRV_PM_MONITOR_PM_BUSY_AND_RAISE(dip, cpudsp, cpupm,
			    new_spd->pm_level);
		}
	} else if ((user_cnt <= cur_spd->user_lwm) &&
	    (idle_cnt >= cur_spd->idle_hwm) || !CPU_ACTIVE(cp)) {
		cur_spd->idle_blwm_cnt = 0;
		cur_spd->idle_bhwm_cnt = 0;
		/*
		 * Arrange to go to next lower speed by informing our idle
		 * status to the power management framework.
		 */
		CPUDRV_PM_MONITOR_PM_IDLE_COMP(dip, cpupm);
	} else {
		/*
		 * If we are between the idle water marks and have not
		 * been here enough consecutive times to be considered
		 * busy, just increment the count and return.
		 */
		if ((idle_cnt < cur_spd->idle_hwm) &&
		    (idle_cnt >= cur_spd->idle_lwm) &&
		    (cur_spd->idle_bhwm_cnt < cpudrv_pm_idle_bhwm_cnt_max)) {
			cur_spd->idle_blwm_cnt = 0;
			cur_spd->idle_bhwm_cnt++;
			mutex_exit(&cpudsp->lock);
			goto do_return;
		}
		if (idle_cnt < cur_spd->idle_lwm) {
			cur_spd->idle_blwm_cnt++;
			cur_spd->idle_bhwm_cnt = 0;
		}
		/*
		 * Arranges to stay at the current speed.
		 */
		CPUDRV_PM_MONITOR_PM_BUSY_COMP(dip, cpupm);
	}
	mutex_exit(&cpudsp->lock);
do_return:
	mutex_enter(&cpupm->timeout_lock);
	ASSERT(cpupm->timeout_count > 0);
	cpupm->timeout_count--;
	cv_signal(&cpupm->timeout_cv);
	mutex_exit(&cpupm->timeout_lock);
}
