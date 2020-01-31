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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/devops.h>
#include <sys/kmem.h>
#include <sys/open.h>
#include <sys/file.h>
#include <sys/note.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#include <sys/modctl.h>
#include <sys/stat.h>
#include <sys/clock.h>
#include <sys/reboot.h>
#include <sys/machsystm.h>
#include <sys/poll.h>
#include <sys/pbio.h>
#include <sys/sysmacros.h>

/* Added for prom interface */
#include <sys/promif.h>
#include <sys/promimpl.h>

#include <sys/i2c/misc/i2c_svc.h>
#include <sys/todds1337.h>

#define	DS1337_DEVICE_TYPE	"rtc"

/*
 * Driver entry routines
 */
static int todds1337_attach(dev_info_t *, ddi_attach_cmd_t);
static int todds1337_detach(dev_info_t *, ddi_detach_cmd_t);
static int todds1337_getinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);

/*
 * tod_ops entry routines
 */
static timestruc_t	todds1337_get(void);
static void		todds1337_set(timestruc_t);
static uint_t		todds1337_set_watchdog_timer(uint_t);
static uint_t		todds1337_clear_watchdog_timer(void);
static void		todds1337_set_power_alarm(timestruc_t);
static void		todds1337_clear_power_alarm(void);
static int		todds1337_setup_prom(void);
static void		todds1337_rele_prom(void);
static int		todds1337_prom_getdate(struct rtc_t *rtc);
static int		todds1337_prom_setdate(struct rtc_t *rtc);

/*
 * Local functions
 */
static int		todds1337_read_rtc(struct rtc_t *);
static int		todds1337_write_rtc(struct rtc_t *);

/* Anchor for soft state structure */
static void	*ds1337_statep;
static int	instance = -1;
static int	todds1337_attach_done = 0;
static kmutex_t	todds1337_rd_lock;
static kmutex_t	todds1337_alarm_lock;
static ihandle_t todds1337_ihandle = 0;

/* one second time out */
#define	I2C_CYCLIC_TIMEOUT	1000000000
uint_t i2c_cyclic_timeout = I2C_CYCLIC_TIMEOUT;
static int sync_clock_once = 1;
static struct	rtc_t	 soft_rtc;

/*
 * cp_ops structure
 */
static struct cb_ops ds1337_cbops = {
	nodev,				/* open */
	nodev,				/* close */
	nodev,				/* strategy */
	nodev,				/* print */
	nodev,				/* dump */
	nodev,				/* read */
	nodev,				/* write */
	nodev,				/* ioctl */
	nodev,				/* devmap */
	nodev,				/* mmap */
	nodev,				/* segmap */
	NULL,				/* poll */
	ddi_prop_op,			/* cb_prop_op */
	NULL,				/* streamtab */
	D_NEW | D_MP,			/* Driver compatibility flag */
	CB_REV,				/* rev */
	nodev,				/* int (*cb_aread)() */
	nodev				/* int (*cb_awrite)() */
};

/*
 * dev_ops structure
 */
static struct dev_ops ds1337_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* refcnt - reference cnt always set to 0 */
	todds1337_getinfo,	/* getinfo - Maybe requred */
	nulldev,		/* identify */
	nulldev,		/* probe */
	todds1337_attach,	/* attach */
	todds1337_detach,	/* detach */
	nodev,			/* reset */
	&ds1337_cbops,		/* cb_ops - ds1337 does not need this(?) */
	NULL,			/* bus_ops */
	NULL,			/* power */
	ddi_quiesce_not_needed,		/* quiesce */
};

static struct modldrv todds1337_modldrv = {
	&mod_driverops,		/* Type of module. This one is a driver */
	"tod driver for DS1337",	/* Name of the module. */
	&ds1337_ops,			/* Pointer to dev_ops */
};

/*
 * Module linkage structure
 */
static struct modlinkage todds1337_modlinkage = {
	MODREV_1,
	&todds1337_modldrv,
	0
};

int
_init(void)
{
	int error;

	if (strcmp(tod_module_name, "todds1337") == 0) {
		if ((error = ddi_soft_state_init(&ds1337_statep,
		    sizeof (ds1337_state_t), 0)) != DDI_SUCCESS) {
			return (error);
		}

		tod_ops.tod_get = todds1337_get;
		tod_ops.tod_set = todds1337_set;
		tod_ops.tod_set_watchdog_timer = todds1337_set_watchdog_timer;
		tod_ops.tod_clear_watchdog_timer =
		    todds1337_clear_watchdog_timer;
		tod_ops.tod_set_power_alarm = todds1337_set_power_alarm;
		tod_ops.tod_clear_power_alarm = todds1337_clear_power_alarm;
	}

	(void) todds1337_setup_prom();

	/*
	 * Install the module
	 */
	if ((error = mod_install(&todds1337_modlinkage)) != 0) {
		if (strcmp(tod_module_name, "todds1337") == 0) {
			ddi_soft_state_fini(&ds1337_statep);
		}
		todds1337_rele_prom();
		return (error);
	}
	mutex_init(&todds1337_rd_lock, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&todds1337_alarm_lock, NULL, MUTEX_DEFAULT, NULL);

	return (0);
}

int
_fini(void)
{
	int error = 0;

	if (strcmp(tod_module_name, "todds1337") == 0) {
		error = EBUSY;
	} else {
		if ((error = mod_remove(&todds1337_modlinkage)) == 0) {
			mutex_destroy(&todds1337_rd_lock);
			mutex_destroy(&todds1337_alarm_lock);
			todds1337_rele_prom();
		}
	}

	return (error);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&todds1337_modlinkage, modinfop));
}

/*
 * cyclical call to get tod.
 */
static void
todds1337_cyclic(void *arg)
{

	(void) todds1337_read_rtc((struct rtc_t *)arg);

}

/*
 * register ds1337 client device with i2c services, and
 * allocate & initialize soft state structure.
 */
static int
todds1337_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	static ds1337_state_t	*statep = NULL;
	i2c_transfer_t	*i2c_tp = NULL;
	uint8_t tempVal = (uint8_t)0;
	switch (cmd) {
	case DDI_ATTACH:
		break;
	case DDI_RESUME:
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	if (instance != -1) {
		cmn_err(CE_WARN, "todds1337_attach: wrong instance");
		return (DDI_FAILURE);
	}

	instance = ddi_get_instance(dip);

	/*
	 * Allocate soft state structure
	 */
	if (ddi_soft_state_zalloc(ds1337_statep, instance) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "todds1337_attach: cannot allocate soft "
		    "state");
		instance = -1;
		return (DDI_FAILURE);
	}

	statep = ddi_get_soft_state(ds1337_statep, instance);
	if (statep == NULL) {
		cmn_err(CE_WARN, "todds1337_attach: cannot acquire soft "
		    "state");
		instance = -1;
		return (DDI_FAILURE);
	}

	statep->dip = dip;

	if (i2c_client_register(dip, &statep->ds1337_i2c_hdl) != I2C_SUCCESS) {
		ddi_soft_state_free(ds1337_statep, instance);
		cmn_err(CE_WARN, "todds1337_attach: cannot register i2c "
		    "client");
		instance = -1;
		return (DDI_FAILURE);
	}

	/* check and initialize the oscillator */

	(void) i2c_transfer_alloc(statep->ds1337_i2c_hdl,
	    &i2c_tp, 1, 1, I2C_SLEEP);
	i2c_tp->i2c_version = I2C_XFER_REV;
	i2c_tp->i2c_flags = I2C_WR_RD;
	i2c_tp->i2c_wbuf[0] = (uchar_t)RTC_STATUS; /* Read Status register */
	i2c_tp->i2c_wlen = 1;
	i2c_tp->i2c_rlen = 1;

	if ((i2c_transfer(statep->ds1337_i2c_hdl, i2c_tp)) != I2C_SUCCESS) {
		(void) i2c_transfer_free(statep->ds1337_i2c_hdl, i2c_tp);
		i2c_client_unregister(statep->ds1337_i2c_hdl);
		ddi_soft_state_free(ds1337_statep, instance);
		cmn_err(CE_WARN, "todds1337_attach: failed to read DS1337 "
		    "status register");
		instance = -1;
		return (DDI_FAILURE);
	}

	tempVal = i2c_tp->i2c_rbuf[0];

	(void) i2c_transfer_free(statep->ds1337_i2c_hdl, i2c_tp);

	/*
	 * Check Oscillator and initialize chip if OBP failed to do it
	 */

	if (tempVal & RTC_CTL_EOSC) {
		(void) i2c_transfer_alloc(statep->ds1337_i2c_hdl, &i2c_tp,
		    2, 0, I2C_SLEEP);
		i2c_tp->i2c_version = I2C_XFER_REV;
		i2c_tp->i2c_flags = I2C_WR;
		i2c_tp->i2c_wbuf[0] = RTC_CTL; /* Write Control register */
		i2c_tp->i2c_wbuf[1] = (uchar_t)(RTC_CTL_RS2 | RTC_CTL_RS1 |
		    RTC_CTL_INTCN);
		if ((i2c_transfer(statep->ds1337_i2c_hdl, i2c_tp))
		    != I2C_SUCCESS) {
			(void) i2c_transfer_free(statep->ds1337_i2c_hdl,
			    i2c_tp);
			i2c_client_unregister(statep->ds1337_i2c_hdl);
			ddi_soft_state_free(ds1337_statep, instance);
			cmn_err(CE_WARN, "todds1337_attach: failed to write "
			    "DS1337 control register");
			instance = -1;
			return (DDI_FAILURE);
		}

		(void) i2c_transfer_free(statep->ds1337_i2c_hdl, i2c_tp);

		/*
		 * Now reset the OSF flag in the Status register
		 */
		(void) i2c_transfer_alloc(statep->ds1337_i2c_hdl, &i2c_tp,
		    2, 0, I2C_SLEEP);
		i2c_tp->i2c_version = I2C_XFER_REV;
		i2c_tp->i2c_flags = I2C_WR;
		i2c_tp->i2c_wbuf[0] = RTC_STATUS;
		i2c_tp->i2c_wbuf[1] = (uchar_t)0;
		if ((i2c_transfer(statep->ds1337_i2c_hdl, i2c_tp))
		    != I2C_SUCCESS) {
			(void) i2c_transfer_free(statep->ds1337_i2c_hdl,
			    i2c_tp);
			i2c_client_unregister(statep->ds1337_i2c_hdl);
			ddi_soft_state_free(ds1337_statep, instance);
			cmn_err(CE_WARN, "todds1337_attach: failed to write "
			    "DS1337 status register");
			instance = -1;
			return (DDI_FAILURE);
		}

		(void) i2c_transfer_free(statep->ds1337_i2c_hdl, i2c_tp);
	}

	/*
	 * Create a periodical handler to read TOD.
	 */
	ASSERT(statep->cycid == NULL);
	statep->cycid = ddi_periodic_add(todds1337_cyclic, &soft_rtc,
	    i2c_cyclic_timeout, DDI_IPL_1);
	statep->state = TOD_ATTACHED;
	todds1337_attach_done = 1;
	ddi_report_dev(dip);

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
todds1337_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	/*
	 * Once attached, do not allow detach because the system constantly
	 * calling todds1337_get() to get the time.  If the driver is detached
	 * and the system try to get the time, the system will have memory
	 * problem.
	 *
	 */
	switch (cmd) {
	case DDI_SUSPEND:
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}
}

/* *********************** tod_ops entry points ******************** */

/*
 * Read the current time from the DS1337 chip and convert to UNIX form.
 * Should be called with tod_lock held.
 */

static timestruc_t
todds1337_get(void)
{
	timestruc_t	ts;
	todinfo_t	tod;
	struct	rtc_t	rtc;

	ASSERT(MUTEX_HELD(&tod_lock));

	if (sync_clock_once) {
		(void) todds1337_read_rtc(&soft_rtc);
		sync_clock_once = 0;
	} else {
		tod_status_set(TOD_GET_FAILED);
		return (hrestime);
	}

	bcopy(&soft_rtc, &rtc, sizeof (rtc));

	/*
	 * 00 - 68 = 2000 thru 2068
	 * 69-99 = 1969 thru 1999
	 */
	tod.tod_year    = rtc.rtc_year;
	if (rtc.rtc_year <= 68)
		tod.tod_year += 100;
	tod.tod_month	= rtc.rtc_mon;
	tod.tod_day	= rtc.rtc_dom;
	tod.tod_dow	= rtc.rtc_dow;
	tod.tod_hour	= rtc.rtc_hrs;
	tod.tod_min	= rtc.rtc_min;
	tod.tod_sec	= rtc.rtc_sec;

	/* read was successful so ensure failure flag is clear */
	tod_status_clear(TOD_GET_FAILED);

	ts.tv_sec = tod_to_utc(tod);
	ts.tv_nsec = 0;
	return (ts);
}

/*
 * Program DS1337 with the specified time.
 * Must be called with tod_lock held. The TOD
 * chip supports date from 1969-2068 only. We must
 * reject requests to set date below 1969.
 */
static void
todds1337_set(timestruc_t ts)
{
	struct rtc_t	rtc;
	todinfo_t	tod = utc_to_tod(ts.tv_sec);
	int		year;


	ASSERT(MUTEX_HELD(&tod_lock));

	/*
	 * Year is base 1900, valid year range 1969-2068
	 */
	if ((tod.tod_year < 69) || (tod.tod_year > 168))
		return;

	year = tod.tod_year;
	if (year >= 100)
		year -= 100;

	rtc.rtc_year	= (uint8_t)year;
	rtc.rtc_mon	= (uint8_t)tod.tod_month;
	rtc.rtc_dom	= (uint8_t)tod.tod_day;
	rtc.rtc_dow	= (uint8_t)tod.tod_dow;
	rtc.rtc_hrs	= (uint8_t)tod.tod_hour;
	rtc.rtc_min	= (uint8_t)tod.tod_min;
	rtc.rtc_sec	= (uint8_t)tod.tod_sec;

	(void) todds1337_write_rtc(&rtc);
}

/*
 * Program ds1337 registers for alarm to go off at the specified time.
 * Alarm #1 is used (Alarm #2 stays idle)
 */
/* ARGSUSED */
static void
todds1337_set_power_alarm(timestruc_t ts)
{
	todinfo_t	tod;
	ds1337_state_t	*statep = NULL;
	i2c_transfer_t	*i2c_tp = NULL;
	uint8_t tmpval;

	ASSERT(MUTEX_HELD(&tod_lock));

	if (!todds1337_attach_done) {
		cmn_err(CE_WARN, "todds1337: driver not attached");
		return;
	}

	statep = ddi_get_soft_state(ds1337_statep, instance);
	if (statep == NULL) {
		cmn_err(CE_WARN, "todds1337: ddi_get_soft_state failed");
		return;
	}

	tod = utc_to_tod(ts.tv_sec);

	/*
	 * i2c_transfe() may block; to avoid locking clock() which
	 * is running in interrupt context at PIL10 we temporarely exit
	 * the tod_mutex and enter alarm lock. Time/date and alarm hardware
	 * have non-interlsecting registers, it is safe to use different locks.
	 */
	mutex_exit(&tod_lock);
	mutex_enter(&todds1337_alarm_lock);

	/*
	 * Disable Power Alarm (A1IE)
	 */
	(void) i2c_transfer_alloc(statep->ds1337_i2c_hdl,
	    &i2c_tp, 1, 1, I2C_SLEEP);
	i2c_tp->i2c_version = I2C_XFER_REV;
	i2c_tp->i2c_flags = I2C_WR_RD;
	i2c_tp->i2c_wbuf[0] = (uchar_t)RTC_CTL; /* Read Control register */

	if ((i2c_transfer(statep->ds1337_i2c_hdl, i2c_tp)) != I2C_SUCCESS) {
		(void) i2c_transfer_free(statep->ds1337_i2c_hdl, i2c_tp);
		cmn_err(CE_WARN, "todds1337_set_power_alarm: failed to read "
		    "DS1337 control register");
		mutex_exit(&todds1337_alarm_lock);
		mutex_enter(&tod_lock);
		return;
	}

	tmpval = i2c_tp->i2c_rbuf[0];

	(void) i2c_transfer_free(statep->ds1337_i2c_hdl, i2c_tp);

	(void) i2c_transfer_alloc(statep->ds1337_i2c_hdl,
	    &i2c_tp, 2, 0, I2C_SLEEP);
	i2c_tp->i2c_version = I2C_XFER_REV;
	i2c_tp->i2c_flags = I2C_WR;
	i2c_tp->i2c_wbuf[0] = (uchar_t)RTC_CTL; /* Write Control register */
	i2c_tp->i2c_wbuf[1] = tmpval & ~RTC_CTL_A1IE;

	if ((i2c_transfer(statep->ds1337_i2c_hdl, i2c_tp)) != I2C_SUCCESS) {
		(void) i2c_transfer_free(statep->ds1337_i2c_hdl, i2c_tp);
		cmn_err(CE_WARN, "todds1337_set_power_alarm: failed to write "
		    "DS1337control register");
		mutex_exit(&todds1337_alarm_lock);
		mutex_enter(&tod_lock);
		return;
	}

	(void) i2c_transfer_free(statep->ds1337_i2c_hdl, i2c_tp);


	/*
	 * Write Alarm #1 registers
	 */

	(void) i2c_transfer_alloc(statep->ds1337_i2c_hdl,
	    &i2c_tp, 5, 0, I2C_SLEEP);
	i2c_tp->i2c_version = I2C_XFER_REV;
	i2c_tp->i2c_flags = I2C_WR;
	i2c_tp->i2c_wbuf[0] = (uchar_t)RTC_ALARM_SEC; /* Alarm #1 Seconds */
	i2c_tp->i2c_wbuf[1] = BYTE_TO_BCD(tod.tod_sec);
	i2c_tp->i2c_wbuf[2] = BYTE_TO_BCD(tod.tod_min);
	i2c_tp->i2c_wbuf[3] = BYTE_TO_BCD(tod.tod_hour);
	i2c_tp->i2c_wbuf[4] = BYTE_TO_BCD(tod.tod_day);

	if ((i2c_transfer(statep->ds1337_i2c_hdl, i2c_tp)) != I2C_SUCCESS) {
		(void) i2c_transfer_free(statep->ds1337_i2c_hdl, i2c_tp);
		cmn_err(CE_WARN, "todds1337_set_power_alarm: failed to write "
		    "DS1337 alarm registers");
		mutex_exit(&todds1337_alarm_lock);
		mutex_enter(&tod_lock);
		return;
	}

	(void) i2c_transfer_free(statep->ds1337_i2c_hdl, i2c_tp);


	/*
	 * Enable Power Alarm
	 */
	(void) i2c_transfer_alloc(statep->ds1337_i2c_hdl,
	    &i2c_tp, 2, 0, I2C_SLEEP);
	i2c_tp->i2c_version = I2C_XFER_REV;
	i2c_tp->i2c_flags = I2C_WR;
	i2c_tp->i2c_wbuf[0] = (uchar_t)RTC_CTL; /* Write Control register */
	i2c_tp->i2c_wbuf[1] = tmpval | RTC_CTL_A1IE;

	if ((i2c_transfer(statep->ds1337_i2c_hdl, i2c_tp)) != I2C_SUCCESS) {
		(void) i2c_transfer_free(statep->ds1337_i2c_hdl, i2c_tp);
		cmn_err(CE_WARN, "todds1337_set_power_alarm: failed to enable "
		    "DS1337 alarm");
		mutex_exit(&todds1337_alarm_lock);
		mutex_enter(&tod_lock);
		return;
	}

	(void) i2c_transfer_free(statep->ds1337_i2c_hdl, i2c_tp);

	mutex_exit(&todds1337_alarm_lock);
	mutex_enter(&tod_lock);
}

/* ARGSUSED */
static void
todds1337_clear_power_alarm(void)
{
	ds1337_state_t	*statep = NULL;
	i2c_transfer_t	*i2c_tp = NULL;
	uint8_t tmpval;

	ASSERT(MUTEX_HELD(&tod_lock));

	if (!todds1337_attach_done) {
		cmn_err(CE_WARN, "todds1337: driver was not attached");
		return;
	}

	statep = ddi_get_soft_state(ds1337_statep, instance);
	if (statep == NULL) {
		cmn_err(CE_WARN, "todds1337: ddi_get_soft_state has failed");
		return;
	}

	/*
	 * i2c_transfe() may block; to avoid locking clock() which
	 * is running in interrupt context at PIL10 we temporarely exit
	 * the tod_mutex and enter alarm lock. Time/date and alarm hardware
	 * have non-interlsecting registers, it is safe to use different locks.
	 */
	mutex_exit(&tod_lock);
	mutex_enter(&todds1337_alarm_lock);

	/*
	 * Disable Alarm #1 Interrupt
	 */
	(void) i2c_transfer_alloc(statep->ds1337_i2c_hdl,
	    &i2c_tp, 1, 1, I2C_SLEEP);
	i2c_tp->i2c_version = I2C_XFER_REV;
	i2c_tp->i2c_flags = I2C_WR_RD;
	i2c_tp->i2c_wbuf[0] = (uchar_t)RTC_CTL; /* Read Control register */

	if ((i2c_transfer(statep->ds1337_i2c_hdl, i2c_tp)) != I2C_SUCCESS) {
		(void) i2c_transfer_free(statep->ds1337_i2c_hdl, i2c_tp);
		cmn_err(CE_WARN, "todds1337_clear_power_alarm: failed to read "
		    "DS1337 control register");
		mutex_exit(&todds1337_alarm_lock);
		mutex_enter(&tod_lock);
		return;
	}

	tmpval = i2c_tp->i2c_rbuf[0];

	(void) i2c_transfer_free(statep->ds1337_i2c_hdl, i2c_tp);

	(void) i2c_transfer_alloc(statep->ds1337_i2c_hdl,
	    &i2c_tp, 2, 0, I2C_SLEEP);
	i2c_tp->i2c_version = I2C_XFER_REV;
	i2c_tp->i2c_flags = I2C_WR;
	i2c_tp->i2c_wbuf[0] = (uchar_t)RTC_CTL; /* Write Control register */
	i2c_tp->i2c_wbuf[1] = tmpval & ~RTC_CTL_A1IE;

	if ((i2c_transfer(statep->ds1337_i2c_hdl, i2c_tp)) != I2C_SUCCESS) {
		(void) i2c_transfer_free(statep->ds1337_i2c_hdl, i2c_tp);
		cmn_err(CE_WARN, "todds1337_clear_power_alarm: failed to write "
		    "DS1337 control register");
		mutex_exit(&todds1337_alarm_lock);
		mutex_enter(&tod_lock);
		return;
	}

	(void) i2c_transfer_free(statep->ds1337_i2c_hdl, i2c_tp);

	/*
	 * Reset Alarm #1 Flag
	 */
	(void) i2c_transfer_alloc(statep->ds1337_i2c_hdl,
	    &i2c_tp, 1, 1, I2C_SLEEP);
	i2c_tp->i2c_version = I2C_XFER_REV;
	i2c_tp->i2c_flags = I2C_WR_RD;
	i2c_tp->i2c_wbuf[0] = (uchar_t)RTC_STATUS; /* Read Status register */

	if ((i2c_transfer(statep->ds1337_i2c_hdl, i2c_tp)) != I2C_SUCCESS) {
		(void) i2c_transfer_free(statep->ds1337_i2c_hdl, i2c_tp);
		cmn_err(CE_WARN, "todds1337_clear_power_alarm: failed to read "
		    "DS1337 status register");
		mutex_exit(&todds1337_alarm_lock);
		mutex_enter(&tod_lock);
		return;
	}

	tmpval = i2c_tp->i2c_rbuf[0];

	(void) i2c_transfer_free(statep->ds1337_i2c_hdl, i2c_tp);

	(void) i2c_transfer_alloc(statep->ds1337_i2c_hdl,
	    &i2c_tp, 2, 0, I2C_SLEEP);
	i2c_tp->i2c_version = I2C_XFER_REV;
	i2c_tp->i2c_flags = I2C_WR;
	i2c_tp->i2c_wbuf[0] = (uchar_t)RTC_STATUS; /* Write Status register */
	i2c_tp->i2c_wbuf[1] = tmpval & ~RTC_STATUS_A1F;

	if ((i2c_transfer(statep->ds1337_i2c_hdl, i2c_tp)) != I2C_SUCCESS) {
		(void) i2c_transfer_free(statep->ds1337_i2c_hdl, i2c_tp);
		cmn_err(CE_WARN, "todds1337_clear_power_alarm: failed to write "
		    "DS1337 status register");
		mutex_exit(&todds1337_alarm_lock);
		mutex_enter(&tod_lock);
		return;
	}

	(void) i2c_transfer_free(statep->ds1337_i2c_hdl, i2c_tp);

	mutex_exit(&todds1337_alarm_lock);
	mutex_enter(&tod_lock);
}

/* ARGSUSED */
static uint_t
todds1337_set_watchdog_timer(uint_t timeoutval)
{
	ASSERT(MUTEX_HELD(&tod_lock));
	return (0);
}

/* ARGSUSED */
static uint_t
todds1337_clear_watchdog_timer(void)
{
	ASSERT(MUTEX_HELD(&tod_lock));
	return (0);
}

/* ********************** Local functions ***************************** */

static char tod_read[7] = {-1, -1, -1, -1, -1, -1, -1};
static int
todds1337_read_rtc(struct rtc_t *rtc)
{
	static	ds1337_state_t	*statep = NULL;
	i2c_transfer_t	*i2c_tp = NULL;
	int i2c_cmd_status = I2C_FAILURE;
	int counter = 4;

	if (!todds1337_attach_done) {
		return (todds1337_prom_getdate(rtc));
	}

	statep = ddi_get_soft_state(ds1337_statep, instance);
	if (statep == NULL) {
		cmn_err(CE_WARN, "todds1337: ddi_get_soft_state failing");
		return (DDI_FAILURE);
	}

	mutex_enter(&todds1337_rd_lock);

	/*
	 * Allocate 1 byte for write buffer and 7 bytes for read buffer to
	 * to accomodate sec, min, hrs, dayOfWeek, dayOfMonth, year
	 */
	if ((i2c_transfer_alloc(statep->ds1337_i2c_hdl, &i2c_tp, 1,
	    7, I2C_SLEEP)) != I2C_SUCCESS) {
		mutex_exit(&todds1337_rd_lock);
		return (DDI_FAILURE);
	}

	do {
		i2c_tp->i2c_version = I2C_XFER_REV;
		i2c_tp->i2c_flags = I2C_WR_RD;
		i2c_tp->i2c_wbuf[0] = (uchar_t)RTC_SEC; /* Start from 0x00 */
		i2c_tp->i2c_wlen = 1;	/* Write one byte address */
		i2c_tp->i2c_rlen = 7;	/* Read 7 regs */

		if ((i2c_cmd_status = i2c_transfer(statep->ds1337_i2c_hdl,
		    i2c_tp)) != I2C_SUCCESS) {
			goto done;
		}
		/* for first read, need to get valid data */
		while (tod_read[0] == -1 && counter > 0) {
		/* move data to static buffer */
		bcopy(i2c_tp->i2c_rbuf, tod_read, 7);

		/* now read again */
		/* Start reading reg from 0x00 */
		i2c_tp->i2c_wbuf[0] = (uchar_t)0x00;
		i2c_tp->i2c_wlen = 1;	/* Write one byte address */
		i2c_tp->i2c_rlen = 7;	/* Read 7 regs */
		if ((i2c_cmd_status = i2c_transfer(statep->ds1337_i2c_hdl,
		    i2c_tp)) != I2C_SUCCESS) {
			goto done;
		}
		/* if they are not the same, then read again */
		if (bcmp(tod_read, i2c_tp->i2c_rbuf, 7) != 0) {
			tod_read[0] = -1;
			counter--;
		}
	}

	} while (i2c_tp->i2c_rbuf[0] == 0x59 &&
	    /* if seconds register is 0x59 (BCD), add data should match */
	    bcmp(&tod_read[1], &i2c_tp->i2c_rbuf[1], 6) != 0 &&
	    counter-- > 0);

	if (counter < 0)
		cmn_err(CE_WARN, "i2ctod: TOD Chip failed ??");

	/* move data to static buffer */
	bcopy(i2c_tp->i2c_rbuf, tod_read, 7);


	rtc->rtc_year	= BCD_TO_BYTE(i2c_tp->i2c_rbuf[6]);
	rtc->rtc_mon	= BCD_TO_BYTE(i2c_tp->i2c_rbuf[5]);
	rtc->rtc_dom	= BCD_TO_BYTE(i2c_tp->i2c_rbuf[4]);
	rtc->rtc_dow	= BCD_TO_BYTE(i2c_tp->i2c_rbuf[3]);
	rtc->rtc_hrs	= BCD_TO_BYTE(i2c_tp->i2c_rbuf[2]);
	rtc->rtc_min	= BCD_TO_BYTE(i2c_tp->i2c_rbuf[1]);
	rtc->rtc_sec	= BCD_TO_BYTE(i2c_tp->i2c_rbuf[0]);

done:
	(void) i2c_transfer_free(statep->ds1337_i2c_hdl, i2c_tp);

	mutex_exit(&todds1337_rd_lock);
	return (i2c_cmd_status);
}


static int
todds1337_write_rtc(struct rtc_t *rtc)
{
	ds1337_state_t	*statep = NULL;
	i2c_transfer_t	*i2c_tp = NULL;
	int i2c_cmd_status = I2C_SUCCESS;


	if (!todds1337_attach_done) {
		return (todds1337_prom_setdate(rtc));
	}

	statep = ddi_get_soft_state(ds1337_statep, instance);
	if (statep == NULL) {
		return (DDI_FAILURE);
	}

	if ((i2c_cmd_status = i2c_transfer_alloc(statep->ds1337_i2c_hdl,
	    &i2c_tp, 8, 0, I2C_SLEEP)) != I2C_SUCCESS) {
		return (i2c_cmd_status);
	}

	i2c_tp->i2c_version = I2C_XFER_REV;
	i2c_tp->i2c_flags = I2C_WR;
	i2c_tp->i2c_wbuf[0] = (uchar_t)RTC_SEC;
	i2c_tp->i2c_wbuf[1] = BYTE_TO_BCD(rtc->rtc_sec);
	i2c_tp->i2c_wbuf[2] = BYTE_TO_BCD(rtc->rtc_min);
	i2c_tp->i2c_wbuf[3] = BYTE_TO_BCD(rtc->rtc_hrs);
	i2c_tp->i2c_wbuf[4] = BYTE_TO_BCD(rtc->rtc_dow);
	i2c_tp->i2c_wbuf[5] = BYTE_TO_BCD(rtc->rtc_dom);
	i2c_tp->i2c_wbuf[6] = BYTE_TO_BCD(rtc->rtc_mon);
	i2c_tp->i2c_wbuf[7] = BYTE_TO_BCD(rtc->rtc_year);
	i2c_tp->i2c_wlen = 8;

	if ((i2c_cmd_status = i2c_transfer(statep->ds1337_i2c_hdl,
	    i2c_tp)) != I2C_SUCCESS) {
		(void) i2c_transfer_free(statep->ds1337_i2c_hdl, i2c_tp);
		return (i2c_cmd_status);
	}

	tod_read[0] = -1;  /* invalidate saved data from read routine */

	(void) i2c_transfer_free(statep->ds1337_i2c_hdl, i2c_tp);

	return (i2c_cmd_status);
}


/*ARGSUSED*/
static int
todds1337_getinfo(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg,
    void **result)
{
	ds1337_state_t *softsp;

	if (instance == -1) {
		return (DDI_FAILURE);
	}

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		if ((softsp = ddi_get_soft_state(ds1337_statep, instance)) ==
		    NULL)
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

/*
 * Finds the device node with device_type "rtc" and opens it to
 * execute the get-time method
 */
static int
todds1337_setup_prom(void)
{
	pnode_t todnode;
	char tod1337_devpath[MAXNAMELEN];

	if ((todnode = prom_findnode_bydevtype(prom_rootnode(),
	    DS1337_DEVICE_TYPE)) == OBP_NONODE)
		return (DDI_FAILURE);

	/*
	 * We now have the phandle of the rtc node, we need to open the
	 * node and get the ihandle
	 */
	if (prom_phandle_to_path(todnode, tod1337_devpath,
	    sizeof (tod1337_devpath)) < 0) {
		cmn_err(CE_WARN, "prom_phandle_to_path failed");
		return (DDI_FAILURE);
	}

	/*
	 * Now open the node and store it's ihandle
	 */
	if ((todds1337_ihandle = prom_open(tod1337_devpath)) == 0) {
		cmn_err(CE_WARN, "prom_open failed");
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/*
 * Closes the prom interface
 */
static void
todds1337_rele_prom(void)
{
	(void) prom_close(todds1337_ihandle);
}

/*
 * Read the date using "get-time" method in rtc node
 * PROM returns 1969-1999 when reading 69-99 and
 * 2000-2068 when reading 00-68
 */
static int
todds1337_prom_getdate(struct rtc_t *rtc)
{
	int year;
	cell_t ci[12];

	ci[0] = p1275_ptr2cell("call-method");  /* Service name */
	ci[1] = 2; /* # of arguments */
	ci[2] = 7; /* # of result cells */
	ci[3] = p1275_ptr2cell("get-time");
	ci[4] = p1275_ihandle2cell(todds1337_ihandle);

	promif_preprom();
	(void) p1275_cif_handler(&ci);
	promif_postprom();

	year		= p1275_cell2int(ci[6]);
	rtc->rtc_mon	= p1275_cell2int(ci[7]);
	rtc->rtc_dom	= p1275_cell2int(ci[8]);
	rtc->rtc_dow	= 0;
	rtc->rtc_hrs	= p1275_cell2int(ci[9]);
	rtc->rtc_min	= p1275_cell2int(ci[10]);
	rtc->rtc_sec	= p1275_cell2int(ci[11]);
	if (year >= 2000)
		year -= 2000;
	else
		year -= 1900;
	rtc->rtc_year	= year;

	return (DDI_SUCCESS);
}

/*
 * Read the date using "set-time" method in rtc node
 * For values 00 - 68, write 2000-2068, and for 69-99,
 * write 1969-1999
 */
static int
todds1337_prom_setdate(struct rtc_t *rtc)
{
	int year;
	cell_t ci[12];

	year = rtc->rtc_year;

	if ((year < 0) || (year > 99))
		return (DDI_FAILURE);

	if (year <= 68)
		year = rtc->rtc_year + 2000;
	else
		year = rtc->rtc_year + 1900;

	ci[0] = p1275_ptr2cell("call-method");  /* Service name */
	ci[1] = 8; /* # of arguments */
	ci[2] = 0; /* # of result cells */
	ci[3] = p1275_ptr2cell("set-time");
	ci[4] = p1275_ihandle2cell(todds1337_ihandle);
	ci[5] = p1275_int2cell(year);
	ci[6] = p1275_int2cell(rtc->rtc_mon);
	ci[7] = p1275_int2cell(rtc->rtc_dom);
	ci[8] = p1275_int2cell(rtc->rtc_hrs);
	ci[9] = p1275_int2cell(rtc->rtc_min);
	ci[10] = p1275_int2cell(rtc->rtc_sec);

	promif_preprom();
	(void) p1275_cif_handler(&ci);
	promif_postprom();

	return (DDI_SUCCESS);
}
