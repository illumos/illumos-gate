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
 * sun4v application watchdog driver
 */

#include <sys/types.h>
#include <sys/file.h>
#include <sys/errno.h>
#include <sys/open.h>
#include <sys/callb.h>
#include <sys/cred.h>
#include <sys/cyclic.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <sys/ksynch.h>
#include <sys/modctl.h>
#include <sys/conf.h>
#include <sys/devops.h>
#include <sys/debug.h>
#include <sys/cmn_err.h>
#include <sys/ddi.h>
#include <sys/reboot.h>
#include <sys/sunddi.h>
#include <sys/signal.h>
#include <sys/ntwdt.h>
#include <sys/note.h>

/*
 * tunables
 */
int ntwdt_disable_timeout_action = 0;

#ifdef DEBUG

int ntwdt_debug = 0;		/* ntwdt debug flag, dbg all for now. */

/*
 * Flags to set in ntwdt_debug.
 */
#define	NTWDT_DBG_ENTRY	0x00000001	/* drv entry points */
#define	NTWDT_DBG_IOCTL	0x00000002	/* ioctl's */
#define	NTWDT_DBG_NTWDT	0x00000004	/* other ntwdt debug */

#define	NTWDT_DBG(flag, msg) \
	{ if ((ntwdt_debug) & (flag)) (void) printf msg; }
#else	/* DEBUG */
#define	NTWDT_DBG(flag, msg)
#endif	/* DEBUG */

#define	NTWDT_MINOR_NODE	"awdt"
#define	getstate(minor)	\
	((ntwdt_state_t *)ddi_get_soft_state(ntwdt_statep, (minor)))

/*
 * The ntwdt cyclic interval in nanosecond unit as cyclic subsystem supports
 * nanosecond resolution.
 */
#define	NTWDT_CYCLIC_INTERVAL	NANOSEC	/* 1 seconds */

/*
 * The ntwdt decrement interval in 1 second resolution.
 */
#define	NTWDT_DECREMENT_INTERVAL	1	/* 1 second */

/*
 * ntwdt_watchdog_flags and macros to set/clear one bit in it.
 */
#define	NTWDT_FLAG_SKIP_CYCLIC	0x1	/* skip next cyclic */

#define	NTWDT_MAX_TIMEOUT	(3 * 60 * 60)	/* 3 hours */

#define	WDT_MIN_COREAPI_MAJOR	1
#define	WDT_MIN_COREAPI_MINOR	1

/*
 * Application watchdog state.
 */
typedef struct ntwdt_runstate {
	kmutex_t		ntwdt_runstate_mutex;
	ddi_iblock_cookie_t	ntwdt_runstate_mtx_cookie;
	int			ntwdt_watchdog_enabled;	/* wdog enabled ? */
	int			ntwdt_reset_enabled;	/* reset enabled ? */
	int			ntwdt_timer_running;	/* wdog running ? */
	int			ntwdt_watchdog_expired;	/* wdog expired ? */
	uint32_t		ntwdt_time_remaining;	/* expiration timer */
	uint32_t		ntwdt_watchdog_timeout;	/* timeout in seconds */
	hrtime_t		ntwdt_cyclic_interval;	/* cyclic interval */
	cyc_handler_t		ntwdt_cycl_hdlr;
	cyc_time_t		ntwdt_cycl_time;
	uint32_t		ntwdt_watchdog_flags;
} ntwdt_runstate_t;

/*
 * softstate of NTWDT
 */
typedef struct {
	kmutex_t		ntwdt_mutex;
	dev_info_t		*ntwdt_dip;		/* dip */
	int			ntwdt_open_flag;	/* file open ? */
	ntwdt_runstate_t	*ntwdt_run_state;	/* wdog state */
	cyclic_id_t		ntwdt_cycl_id;
} ntwdt_state_t;

static void *ntwdt_statep;	/* softstate */
static dev_info_t *ntwdt_dip;

static ddi_softintr_t	ntwdt_cyclic_softint_id;

static int ntwdt_info(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int ntwdt_attach(dev_info_t *, ddi_attach_cmd_t);
static int ntwdt_detach(dev_info_t *, ddi_detach_cmd_t);
static int ntwdt_open(dev_t *, int, int, cred_t *);
static int ntwdt_close(dev_t, int, int, cred_t *);
static int ntwdt_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);

static int ntwdt_chk_watchdog_support();
static void ntwdt_arm_watchdog(ntwdt_runstate_t *ntwdt_state);
static void ntwdt_cyclic_pat(void);
static uint_t ntwdt_cyclic_softint(caddr_t arg);
static void ntwdt_start_timer(ntwdt_state_t *ntwdt_ptr);
static void ntwdt_stop_timer_lock(void *arg);
static void ntwdt_stop_timer(void *arg);
static void ntwdt_enforce_timeout();

static struct cb_ops ntwdt_cb_ops = {
	ntwdt_open,		/* cb_open */
	ntwdt_close,		/* cb_close */
	nodev,			/* cb_strategy */
	nodev,			/* cb_print */
	nodev,			/* cb_dump */
	nodev,			/* cb_read */
	nodev,			/* cb_write */
	ntwdt_ioctl,		/* cb_ioctl */
	nodev,			/* cb_devmap */
	nodev,			/* cb_mmap */
	nodev,			/* cb_segmap */
	nochpoll,		/* cb_chpoll */
	ddi_prop_op,		/* cb_prop_op */
	NULL,			/* cb_str */
	D_NEW | D_MP		/* cb_flag */
};

static struct dev_ops ntwdt_dev_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* devo_refcnt */
	ntwdt_info,		/* devo_info */
	nulldev,		/* devo_identify */
	nulldev,		/* devo_probe */
	ntwdt_attach,		/* devo_attach */
	ntwdt_detach,		/* devo_detach */
	nodev,			/* devo_reset */
	&ntwdt_cb_ops,		/* devo_cb_ops */
	NULL,			/* devo_bus_ops */
	nulldev,		/* devo_power */
	ddi_quiesce_not_supported,	/* devo_quiesce */
};

static struct modldrv modldrv = {
	&mod_driverops,
	"Application Watchdog Driver",
	&ntwdt_dev_ops
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modldrv,
	NULL
};

int
_init(void)
{
	int error = 0;

	NTWDT_DBG(NTWDT_DBG_ENTRY, ("_init"));

	/* Initialize the soft state structures */
	if ((error = ddi_soft_state_init(&ntwdt_statep,
	    sizeof (ntwdt_state_t), 1)) != 0) {
		return (error);
	}

	/* Install the loadable module */
	if ((error = mod_install(&modlinkage)) != 0) {
		ddi_soft_state_fini(&ntwdt_statep);
	}
	return (error);
}

int
_info(struct modinfo *modinfop)
{
	NTWDT_DBG(NTWDT_DBG_ENTRY, ("_info"));

	return (mod_info(&modlinkage, modinfop));
}

int
_fini(void)
{
	int retval;

	NTWDT_DBG(NTWDT_DBG_ENTRY, ("_fini"));

	if ((retval = mod_remove(&modlinkage)) == 0) {
		ddi_soft_state_fini(&ntwdt_statep);
	}

	return (retval);
}

static int
ntwdt_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int instance;
	ntwdt_state_t *ntwdt_ptr = NULL;	/* pointer to ntwdt_runstatep */
	ntwdt_runstate_t *ntwdt_runstatep = NULL;
	cyc_handler_t *hdlr = NULL;

	switch (cmd) {
	case DDI_ATTACH:
		break;

	case DDI_RESUME:
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}

	if (ntwdt_chk_watchdog_support() != 0) {
		return (DDI_FAILURE);
	}

	instance = ddi_get_instance(dip);
	ASSERT(instance == 0);

	if (ddi_soft_state_zalloc(ntwdt_statep, instance) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}
	ntwdt_ptr = ddi_get_soft_state(ntwdt_statep, instance);
	ASSERT(ntwdt_ptr != NULL);

	ntwdt_dip = dip;

	ntwdt_ptr->ntwdt_dip = dip;
	ntwdt_ptr->ntwdt_cycl_id = CYCLIC_NONE;
	mutex_init(&ntwdt_ptr->ntwdt_mutex, NULL,
	    MUTEX_DRIVER, NULL);

	/*
	 * Initialize the watchdog structure
	 */
	ntwdt_ptr->ntwdt_run_state =
	    kmem_zalloc(sizeof (ntwdt_runstate_t), KM_SLEEP);
	ntwdt_runstatep = ntwdt_ptr->ntwdt_run_state;

	if (ddi_get_soft_iblock_cookie(dip, DDI_SOFTINT_LOW,
	    &ntwdt_runstatep->ntwdt_runstate_mtx_cookie) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "init of iblock cookie failed "
		    "for ntwdt_runstate_mutex");
		goto err1;
	} else {
		mutex_init(&ntwdt_runstatep->ntwdt_runstate_mutex,
		    NULL,
		    MUTEX_DRIVER,
		    (void *)ntwdt_runstatep->ntwdt_runstate_mtx_cookie);
	}

	/* Cyclic fires once per second: */
	ntwdt_runstatep->ntwdt_cyclic_interval = NTWDT_CYCLIC_INTERVAL;

	/* init the Cyclic that drives the NTWDT */
	hdlr = &ntwdt_runstatep->ntwdt_cycl_hdlr;
	hdlr->cyh_level = CY_LOCK_LEVEL;
	hdlr->cyh_func = (cyc_func_t)ntwdt_cyclic_pat;
	hdlr->cyh_arg = NULL;

	/* Softint that will be triggered by Cyclic that drives NTWDT */
	if (ddi_add_softintr(dip, DDI_SOFTINT_LOW, &ntwdt_cyclic_softint_id,
	    NULL, NULL, ntwdt_cyclic_softint, (caddr_t)ntwdt_ptr)
	    != DDI_SUCCESS) {
		cmn_err(CE_WARN, "failed to add cyclic softintr");
		goto err2;
	}

	/*
	 * Create Minor Node as last activity.  This prevents
	 * application from accessing our implementation until it
	 * is initialized.
	 */
	if (ddi_create_minor_node(dip, NTWDT_MINOR_NODE, S_IFCHR, 0,
	    DDI_PSEUDO, 0) == DDI_FAILURE) {
		cmn_err(CE_WARN, "failed to create Minor Node: %s",
		    NTWDT_MINOR_NODE);
		goto err3;
	}

	/* Display our driver info in the banner */
	ddi_report_dev(dip);

	return (DDI_SUCCESS);

err3:
	ddi_remove_softintr(ntwdt_cyclic_softint_id);
err2:
	mutex_destroy(&ntwdt_runstatep->ntwdt_runstate_mutex);
err1:
	/* clean up the driver stuff here */
	kmem_free(ntwdt_runstatep, sizeof (ntwdt_runstate_t));
	ntwdt_ptr->ntwdt_run_state = NULL;
	mutex_destroy(&ntwdt_ptr->ntwdt_mutex);
	ddi_soft_state_free(ntwdt_statep, instance);
	ntwdt_dip = NULL;

	return (DDI_FAILURE);
}

/*ARGSUSED*/
static int
ntwdt_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	dev_t dev;
	int instance;
	int error = DDI_SUCCESS;

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		dev = (dev_t)arg;
		if (getminor(dev) == 0) {
			*result = (void *)ntwdt_dip;
		} else {
			error = DDI_FAILURE;
		}
		break;

	case DDI_INFO_DEVT2INSTANCE:
		dev = (dev_t)arg;
		instance = getminor(dev);
		*result = (void *)(uintptr_t)instance;
		break;

	default:
		error = DDI_FAILURE;

	}

	return (error);
}

/*ARGSUSED*/
static int
ntwdt_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int instance = ddi_get_instance(dip);
	ntwdt_state_t *ntwdt_ptr = NULL;

	ntwdt_ptr = ddi_get_soft_state(ntwdt_statep, instance);
	if (ntwdt_ptr == NULL) {
		return (DDI_FAILURE);
	}

	switch (cmd) {
	case DDI_SUSPEND:
		return (DDI_SUCCESS);

	case DDI_DETACH:
		/*
		 * release resources in opposite (LIFO) order as
		 * were allocated in attach.
		 */
		ddi_remove_minor_node(dip, NULL);
		ntwdt_stop_timer_lock((void *)ntwdt_ptr);
		ddi_remove_softintr(ntwdt_cyclic_softint_id);

		mutex_destroy(
		    &ntwdt_ptr->ntwdt_run_state->ntwdt_runstate_mutex);
		kmem_free(ntwdt_ptr->ntwdt_run_state,
		    sizeof (ntwdt_runstate_t));
		ntwdt_ptr->ntwdt_run_state = NULL;

		mutex_destroy(&ntwdt_ptr->ntwdt_mutex);

		ddi_soft_state_free(ntwdt_statep, instance);

		ntwdt_dip = NULL;
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}
}

/*ARGSUSED*/
static int
ntwdt_open(dev_t *devp, int flag, int otyp, cred_t *credp)
{
	int instance = getminor(*devp);
	int retval = 0;
	ntwdt_state_t *ntwdt_ptr = getstate(instance);

	if (ntwdt_ptr == NULL) {
		return (ENXIO);
	}

	/*
	 * ensure caller is a priviledged process.
	 */
	if (drv_priv(credp) != 0) {
		return (EPERM);
	}

	mutex_enter(&ntwdt_ptr->ntwdt_mutex);
	if (ntwdt_ptr->ntwdt_open_flag) {
		retval = EAGAIN;
	} else {
		ntwdt_ptr->ntwdt_open_flag = 1;
	}
	mutex_exit(&ntwdt_ptr->ntwdt_mutex);

	return (retval);
}

/*ARGSUSED*/
static int
ntwdt_close(dev_t dev, int flag, int otyp, cred_t *credp)
{
	int instance = getminor(dev);
	ntwdt_state_t *ntwdt_ptr = getstate(instance);

	if (ntwdt_ptr == NULL) {
		return (ENXIO);
	}

	mutex_enter(&ntwdt_ptr->ntwdt_mutex);
	ntwdt_ptr->ntwdt_open_flag = 0;
	mutex_exit(&ntwdt_ptr->ntwdt_mutex);

	return (0);
}

/*ARGSUSED*/
static int
ntwdt_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
    int *rvalp)
{
	int instance = getminor(dev);
	int retval = 0;
	ntwdt_state_t *ntwdt_ptr = NULL;
	ntwdt_runstate_t *ntwdt_state;
	lom_dogstate_t lom_dogstate;
	lom_dogctl_t lom_dogctl;
	uint32_t lom_dogtime;

	if ((ntwdt_ptr = getstate(instance)) == NULL) {
		return (ENXIO);
	}

	ntwdt_state = ntwdt_ptr->ntwdt_run_state;

	switch (cmd) {
	case LOMIOCDOGSTATE:
		mutex_enter(&ntwdt_state->ntwdt_runstate_mutex);
		lom_dogstate.reset_enable = ntwdt_state->ntwdt_reset_enabled;
		lom_dogstate.dog_enable = ntwdt_state->ntwdt_watchdog_enabled;
		lom_dogstate.dog_timeout = ntwdt_state->ntwdt_watchdog_timeout;
		mutex_exit(&ntwdt_state->ntwdt_runstate_mutex);

		if (ddi_copyout((caddr_t)&lom_dogstate, (caddr_t)arg,
		    sizeof (lom_dogstate_t), mode) != 0) {
			retval = EFAULT;
		}
		break;

	case LOMIOCDOGCTL:
		if (ddi_copyin((caddr_t)arg, (caddr_t)&lom_dogctl,
		    sizeof (lom_dogctl_t), mode) != 0) {
			retval = EFAULT;
			break;
		}

		NTWDT_DBG(NTWDT_DBG_IOCTL, ("reset_enable: %d, and dog_enable: "
		    "%d, watchdog_timeout %d", lom_dogctl.reset_enable,
		    lom_dogctl.dog_enable,
		    ntwdt_state->ntwdt_watchdog_timeout));
		/*
		 * ignore request to enable reset while disabling watchdog.
		 */
		if (!lom_dogctl.dog_enable && lom_dogctl.reset_enable) {
			NTWDT_DBG(NTWDT_DBG_IOCTL, ("invalid combination of "
			    "reset_enable: %d, and dog_enable: %d",
			    lom_dogctl.reset_enable,
			    lom_dogctl.dog_enable));
			retval = EINVAL;
			break;
		}

		mutex_enter(&ntwdt_state->ntwdt_runstate_mutex);

		if (ntwdt_state->ntwdt_watchdog_timeout == 0) {
			/*
			 * the LOMIOCDOGTIME has never been used to setup
			 * a valid timeout.
			 */
			NTWDT_DBG(NTWDT_DBG_IOCTL, ("timeout has not been set"
			    "watchdog_timeout: %d",
			    ntwdt_state->ntwdt_watchdog_timeout));
			retval = EINVAL;
			goto end;
		}

		/*
		 * Store the user specified state in the softstate.
		 */
		ntwdt_state->ntwdt_reset_enabled = lom_dogctl.reset_enable;
		ntwdt_state->ntwdt_watchdog_enabled = lom_dogctl.dog_enable;

		if (ntwdt_state->ntwdt_watchdog_enabled != 0) {
			/*
			 * The user wants to enable the watchdog.
			 * Arm the watchdog and start the cyclic.
			 */
			ntwdt_arm_watchdog(ntwdt_state);

			if (ntwdt_state->ntwdt_timer_running == 0) {
				ntwdt_start_timer(ntwdt_ptr);
			}

			NTWDT_DBG(NTWDT_DBG_IOCTL, ("AWDT is enabled"));
		} else {
			/*
			 * The user wants to disable the watchdog.
			 */
			if (ntwdt_state->ntwdt_timer_running != 0) {
				ntwdt_stop_timer(ntwdt_ptr);
			}
			NTWDT_DBG(NTWDT_DBG_IOCTL, ("AWDT is disabled"));
		}

		mutex_exit(&ntwdt_state->ntwdt_runstate_mutex);
		break;

	case LOMIOCDOGTIME:
		if (ddi_copyin((caddr_t)arg, (caddr_t)&lom_dogtime,
		    sizeof (uint32_t), mode) != 0) {
			retval = EFAULT;
			break;
		}

		NTWDT_DBG(NTWDT_DBG_IOCTL, ("user set timeout: %d",
		    lom_dogtime));

		/*
		 * Ensure specified timeout is valid.
		 */
		if ((lom_dogtime == 0) ||
		    (lom_dogtime > (uint32_t)NTWDT_MAX_TIMEOUT)) {
			retval = EINVAL;
			NTWDT_DBG(NTWDT_DBG_IOCTL, ("user set invalid "
			    "timeout: %d", (int)TICK_TO_MSEC(lom_dogtime)));
			break;
		}

		mutex_enter(&ntwdt_state->ntwdt_runstate_mutex);

		ntwdt_state->ntwdt_watchdog_timeout = lom_dogtime;

		/*
		 * If awdt is currently running, re-arm it with the
		 * newly-specified timeout value.
		 */
		if (ntwdt_state->ntwdt_timer_running != 0) {
			ntwdt_arm_watchdog(ntwdt_state);
		}
		mutex_exit(&ntwdt_state->ntwdt_runstate_mutex);
		break;

	case LOMIOCDOGPAT:
		/*
		 * Allow user to pat the watchdog timer.
		 */
		NTWDT_DBG(NTWDT_DBG_IOCTL, ("DOGPAT is invoked"));
		mutex_enter(&ntwdt_state->ntwdt_runstate_mutex);

		/*
		 * If awdt is not enabled or underlying cyclic is not
		 * running, exit.
		 */
		if (!(ntwdt_state->ntwdt_watchdog_enabled &&
		    ntwdt_state->ntwdt_timer_running)) {
			NTWDT_DBG(NTWDT_DBG_IOCTL, ("PAT: AWDT not enabled"));
			goto end;
		}

		if (ntwdt_state->ntwdt_watchdog_expired == 0) {
			/*
			 * re-arm the awdt.
			 */
			ntwdt_arm_watchdog(ntwdt_state);
			NTWDT_DBG(NTWDT_DBG_IOCTL, ("AWDT patted, "
			    "remainning seconds: %d",
			    ntwdt_state->ntwdt_time_remaining));
		}

		mutex_exit(&ntwdt_state->ntwdt_runstate_mutex);
		break;

	default:
		retval = EINVAL;
		break;
	}
	return (retval);
end:
	mutex_exit(&ntwdt_state->ntwdt_runstate_mutex);
	return (retval);
}

static void
ntwdt_cyclic_pat(void)
{
	ddi_trigger_softintr(ntwdt_cyclic_softint_id);
}

static uint_t
ntwdt_cyclic_softint(caddr_t arg)
{
	/*LINTED E_BAD_PTR_CAST_ALIGN*/
	ntwdt_state_t *ntwdt_ptr = (ntwdt_state_t *)arg;
	ntwdt_runstate_t *ntwdt_state;

	ntwdt_state = ntwdt_ptr->ntwdt_run_state;

	mutex_enter(&ntwdt_state->ntwdt_runstate_mutex);

	if ((ntwdt_state->ntwdt_watchdog_flags & NTWDT_FLAG_SKIP_CYCLIC) != 0) {
		ntwdt_state->ntwdt_watchdog_flags &= ~NTWDT_FLAG_SKIP_CYCLIC;
		goto end;
	}

	if ((ntwdt_state->ntwdt_timer_running == 0) ||
	    (ntwdt_ptr->ntwdt_cycl_id == CYCLIC_NONE) ||
	    (ntwdt_state->ntwdt_watchdog_enabled == 0)) {
		goto end;
	}

	NTWDT_DBG(NTWDT_DBG_IOCTL, ("cyclic_softint: %d"
	    "ddi_get_lbolt64(): %d\n", ntwdt_state->ntwdt_watchdog_timeout,
	    (int)TICK_TO_MSEC(ddi_get_lbolt64())));

	/*
	 * Decrement the virtual watchdog timer and check if it has expired.
	 */
	ntwdt_state->ntwdt_time_remaining -= NTWDT_DECREMENT_INTERVAL;

	if (ntwdt_state->ntwdt_time_remaining == 0) {
		cmn_err(CE_WARN, "application-watchdog expired");
		ntwdt_state->ntwdt_watchdog_expired = 1;

		if (ntwdt_state->ntwdt_reset_enabled != 0) {
			/*
			 * The user wants to reset the system.
			 */
			mutex_exit(&ntwdt_state->ntwdt_runstate_mutex);

			NTWDT_DBG(NTWDT_DBG_NTWDT, ("recovery being done"));
			ntwdt_enforce_timeout();
		} else {
			NTWDT_DBG(NTWDT_DBG_NTWDT, ("no recovery being done"));
			ntwdt_state->ntwdt_watchdog_enabled = 0;
		}

		/*
		 * Schedule Callout to stop the cyclic.
		 */
		(void) timeout(ntwdt_stop_timer_lock, ntwdt_ptr, 0);
	} else {
		_NOTE(EMPTY)
		NTWDT_DBG(NTWDT_DBG_NTWDT, ("time remaining in AWDT: %d secs",
		    (int)TICK_TO_MSEC(ntwdt_state->ntwdt_time_remaining)));
	}

end:
	mutex_exit(&ntwdt_state->ntwdt_runstate_mutex);
	return (DDI_INTR_CLAIMED);
}

static void
ntwdt_arm_watchdog(ntwdt_runstate_t *ntwdt_state)
{
	ntwdt_state->ntwdt_time_remaining = ntwdt_state->ntwdt_watchdog_timeout;

	if (ntwdt_state->ntwdt_timer_running != 0) {
		ntwdt_state->ntwdt_watchdog_flags |= NTWDT_FLAG_SKIP_CYCLIC;
	} else {
		ntwdt_state->ntwdt_watchdog_flags &= ~NTWDT_FLAG_SKIP_CYCLIC;
	}
}

static void
ntwdt_start_timer(ntwdt_state_t *ntwdt_ptr)
{
	ntwdt_runstate_t	*ntwdt_state = ntwdt_ptr->ntwdt_run_state;
	cyc_handler_t		*hdlr = &ntwdt_state->ntwdt_cycl_hdlr;
	cyc_time_t		*when = &ntwdt_state->ntwdt_cycl_time;

	/*
	 * Init the cyclic.
	 */
	when->cyt_interval = ntwdt_state->ntwdt_cyclic_interval;
	when->cyt_when = gethrtime() + when->cyt_interval;

	ntwdt_state->ntwdt_watchdog_expired = 0;
	ntwdt_state->ntwdt_timer_running = 1;

	mutex_enter(&cpu_lock);
	if (ntwdt_ptr->ntwdt_cycl_id == CYCLIC_NONE) {
		ntwdt_ptr->ntwdt_cycl_id = cyclic_add(hdlr, when);
	}
	mutex_exit(&cpu_lock);

	NTWDT_DBG(NTWDT_DBG_NTWDT, ("cyclic-driven timer is started"));
}

static void
ntwdt_stop_timer(void *arg)
{
	ntwdt_state_t *ntwdt_ptr = (ntwdt_state_t *)arg;
	ntwdt_runstate_t *ntwdt_state = ntwdt_ptr->ntwdt_run_state;

	mutex_enter(&cpu_lock);
	if (ntwdt_ptr->ntwdt_cycl_id != CYCLIC_NONE) {
		cyclic_remove(ntwdt_ptr->ntwdt_cycl_id);
	}
	mutex_exit(&cpu_lock);

	ntwdt_state->ntwdt_watchdog_flags = 0;
	ntwdt_state->ntwdt_timer_running = 0;
	ntwdt_ptr->ntwdt_cycl_id = CYCLIC_NONE;

	NTWDT_DBG(NTWDT_DBG_NTWDT, ("cyclic-driven timer is stopped"));
}

/*
 * This is a wrapper function for ntwdt_stop_timer as some callers
 * will already have the appropriate mutex locked, and others not.
 */
static void
ntwdt_stop_timer_lock(void *arg)
{
	ntwdt_state_t *ntwdt_ptr = (ntwdt_state_t *)arg;

	mutex_enter(&ntwdt_ptr->ntwdt_run_state->ntwdt_runstate_mutex);
	ntwdt_stop_timer(arg);
	mutex_exit(&ntwdt_ptr->ntwdt_run_state->ntwdt_runstate_mutex);
}

static void
ntwdt_enforce_timeout()
{
	if (ntwdt_disable_timeout_action != 0) {
		cmn_err(CE_NOTE, "Appication watchdog timer expired, "
		    "taking no action");
		return;
	}

	NTWDT_DBG(NTWDT_DBG_NTWDT, ("dump cores and rebooting ..."));

	(void) kadmin(A_DUMP, AD_BOOT, NULL, kcred);
	cmn_err(CE_PANIC, "kadmin(A_DUMP, AD_BOOT) failed");
	_NOTE(NOTREACHED);
}

static int
ntwdt_chk_watchdog_support()
{
	int	retval = 0;

	if ((boothowto & RB_DEBUG) != 0) {
		cmn_err(CE_WARN, "kernel debugger was booted; "
		    "application watchdog is not available.");
		retval = ENOTSUP;
	}
	return (retval);
}
