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
 * Driver for the Power Management Controller (logical unit 8) of the
 * PC87317 SuperI/O chip. The PMC contains the hardware watchdog timer.
 */

#include <sys/types.h>
#include <sys/time.h>
#include <sys/cmn_err.h>
#include <sys/param.h>
#include <sys/modctl.h>
#include <sys/conf.h>
#include <sys/stat.h>
#include <sys/clock.h>
#include <sys/reboot.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/file.h>
#include <sys/note.h>

#ifdef	DEBUG
int pmc_debug_flag = 0;
#define	DPRINTF(ARGLIST) if (pmc_debug_flag) printf ARGLIST;
#else
#define	DPRINTF(ARGLIST)
#endif /* DEBUG */

/* Driver soft state structure */
typedef struct pmc {
	dev_info_t		*dip;
	ddi_acc_handle_t	pmc_handle;
} pmc_t;

static void *pmc_soft_state;
static int instance = -1;

/* dev_ops and cb_ops entry point function declarations */
static int pmc_attach(dev_info_t *, ddi_attach_cmd_t);
static int pmc_detach(dev_info_t *, ddi_detach_cmd_t);
static int pmc_getinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);

/* hardware watchdog parameters */
static uint_t pmc_set_watchdog_timer(uint_t);
static uint_t pmc_clear_watchdog_timer(void);

extern volatile uint8_t	*v_pmc_addr_reg;
extern volatile uint8_t	*v_pmc_data_reg;
extern int		watchdog_enable;
extern int		watchdog_available;
extern int		watchdog_activated;
extern int		boothowto;
extern uint_t		watchdog_timeout_seconds;

/*
 * Power Management Registers and values
 */
#define	PMC_WDTO	0x05	/* Watchdog Time Out */
#define	PMC_CLEAR_WDTO	0x00

struct cb_ops pmc_cb_ops = {
	nodev,
	nodev,
	nodev,
	nodev,
	nodev,			/* dump */
	nodev,
	nodev,
	nodev,
	nodev,			/* devmap */
	nodev,
	nodev,
	nochpoll,
	ddi_prop_op,
	NULL,			/* for STREAMS drivers */
	D_NEW | D_MP,		/* driver compatibility flag */
	CB_REV,
	nodev,
	nodev
};

static struct dev_ops pmc_dev_ops = {
	DEVO_REV,			/* driver build version */
	0,				/* device reference count */
	pmc_getinfo,
	nulldev,
	nulldev,			/* probe */
	pmc_attach,
	pmc_detach,
	nulldev,			/* reset */
	&pmc_cb_ops,
	(struct bus_ops *)NULL,
	nulldev				/* power */
};

/* module configuration stuff */
extern struct mod_ops mod_driverops;
static struct modldrv modldrv = {
	&mod_driverops,
	"pmc driver",
	&pmc_dev_ops
};
static struct modlinkage modlinkage = {
	MODREV_1,
	&modldrv,
	0
};


int
_init(void)
{
	int e;

	e = ddi_soft_state_init(&pmc_soft_state, sizeof (pmc_t), 1);
	if (e != 0) {
		DPRINTF(("_init: ddi_soft_state_init failed\n"));
		return (e);
	}

	e = mod_install(&modlinkage);
	if (e != 0) {
		DPRINTF(("_init: mod_install failed\n"));
		ddi_soft_state_fini(&pmc_soft_state);
		return (e);
	}

	if (v_pmc_addr_reg != NULL) {
		tod_ops.tod_set_watchdog_timer = pmc_set_watchdog_timer;
		tod_ops.tod_clear_watchdog_timer = pmc_clear_watchdog_timer;

		/*
		 * See if the user has enabled the watchdog timer, and if
		 * it's available.
		 */
		if (watchdog_enable) {
			if (!watchdog_available) {
				cmn_err(CE_WARN, "pmc: Hardware watchdog "
					"unavailable");
			} else if (boothowto & RB_DEBUG) {
				watchdog_available = 0;
				cmn_err(CE_WARN, "pmc: kernel debugger "
					"detected: hardware watchdog disabled");
			}
		}
	}
	return (e);
}

int
_fini(void)
{
	int e;

	if (v_pmc_addr_reg != NULL)
		return (DDI_FAILURE);
	else {
		e = mod_remove(&modlinkage);
		if (e != 0)
			return (e);

		ddi_soft_state_fini(&pmc_soft_state);
		return (DDI_SUCCESS);
	}
}


int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

static int
pmc_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **result)
{
	_NOTE(ARGUNUSED(dip))

	pmc_t	*pmcp;
	int	instance;

	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		instance = getminor((dev_t)arg);
		pmcp = (pmc_t *)ddi_get_soft_state(pmc_soft_state, instance);
		if (pmcp == NULL) {
			*result = (void *)NULL;
			return (DDI_FAILURE);
		}
		*result = (void *)pmcp->dip;
		return (DDI_SUCCESS);

	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)(uintptr_t)getminor((dev_t)arg);
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}
}


static int
pmc_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	pmc_t	*pmcp;
	uint_t	wd_timout;

	switch (cmd) {
	case DDI_ATTACH:
		break;
	case DDI_RESUME:
		if (v_pmc_addr_reg != NULL && watchdog_enable) {
			int ret = 0;
			wd_timout = watchdog_timeout_seconds;
			mutex_enter(&tod_lock);
			ret = tod_ops.tod_set_watchdog_timer(wd_timout);
			mutex_exit(&tod_lock);
			if (ret == 0)
				return (DDI_FAILURE);
		}
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	if (instance != -1) {
		DPRINTF(("pmc_attach: Another instance is already attached."));
		return (DDI_FAILURE);
	}

	instance = ddi_get_instance(dip);

	if (ddi_soft_state_zalloc(pmc_soft_state, instance) != DDI_SUCCESS) {
		DPRINTF(("pmc_attach: Failed to allocate soft state."));
		return (DDI_FAILURE);
	}

	pmcp = (pmc_t *)ddi_get_soft_state(pmc_soft_state, instance);
	pmcp->dip = dip;

	return (DDI_SUCCESS);
}

static int
pmc_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	_NOTE(ARGUNUSED(dip))

	pmc_t	*pmcp;

	switch (cmd) {
	case DDI_DETACH:
		/* allow detach if no hardware watchdog */
		if (v_pmc_addr_reg == NULL || !watchdog_activated) {
			pmcp = (pmc_t *)ddi_get_soft_state(pmc_soft_state,
				instance);
			if (pmcp == NULL)
				return (ENXIO);
			ddi_soft_state_free(pmc_soft_state, instance);
			return (DDI_SUCCESS);
		} else
			return (DDI_FAILURE);
	case DDI_SUSPEND:
		if (v_pmc_addr_reg != NULL && watchdog_activated) {
			mutex_enter(&tod_lock);
			(void) tod_ops.tod_clear_watchdog_timer();
			mutex_exit(&tod_lock);
		}
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

}

/*
 * Set the hardware watchdog timer; returning what we set it to.
 */
static uint_t
pmc_set_watchdog_timer(uint_t timeoutval)
{
	uint_t timeoutval_minutes;
	ASSERT(MUTEX_HELD(&tod_lock));

	/* sanity checks */
	if (watchdog_enable == 0 || watchdog_available == 0 ||
	    timeoutval == 0)
		return (0);

	/*
	 * Historically the timer has been counted out in seconds.
	 * The PC87317 counts the timeout in minutes. The default
	 * timeout is 10 seconds; the least we can do is one minute.
	 */
	timeoutval_minutes = (timeoutval + 59) / 60;
	if (timeoutval_minutes > UINT8_MAX)
		return (0);

	*v_pmc_addr_reg = (uint8_t)PMC_WDTO;
	*v_pmc_data_reg = (uint8_t)timeoutval_minutes;
	watchdog_activated = 1;

	/* we'll still return seconds */
	return (timeoutval_minutes * 60);
}

/*
 * Clear the hardware watchdog timer; returning what it was set to.
 */
static uint_t
pmc_clear_watchdog_timer(void)
{
	uint_t	wd_timeout;

	ASSERT(MUTEX_HELD(&tod_lock));
	if (watchdog_activated == 0)
		return (0);

	*v_pmc_addr_reg = (uint8_t)PMC_WDTO;
	wd_timeout = (uint_t)*v_pmc_data_reg;
	*v_pmc_data_reg = (uint8_t)PMC_CLEAR_WDTO;
	watchdog_activated = 0;

	/* return seconds */
	return (wd_timeout * 60);
}
