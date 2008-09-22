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
#include <sys/todds1307.h>

#define	I2C_DELAY	20000
#define	DS1307_DEVICE_TYPE	"rtc"

/*
 * Driver enrty routines
 */
static int todds1307_attach(dev_info_t *, ddi_attach_cmd_t);
static int todds1307_detach(dev_info_t *, ddi_detach_cmd_t);
static int todds1307_getinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);

/*
 * tod_ops entry routines
 */
static timestruc_t	todds1307_get(void);
static void		todds1307_set(timestruc_t);
static uint_t		todds1307_set_watchdog_timer(uint_t);
static uint_t		todds1307_clear_watchdog_timer(void);
static void		todds1307_set_power_alarm(timestruc_t);
static void		todds1307_clear_power_alarm(void);
static int todds1307_setup_prom();
static void todds1307_rele_prom();
static int todds1307_prom_getdate(struct rtc_t *rtc);
static int todds1307_prom_setdate(struct rtc_t *rtc);

/*
 * Local functions
 */
static int	todds1307_read_rtc(struct rtc_t *);
static int	todds1307_write_rtc(struct rtc_t *);

/* Anchor for soft state structure */
static void	*ds1307_statep;
static int	instance = -1;
static int	todds1307_attach_done = 0;
static kmutex_t	todds1307_rd_lock;
static ihandle_t todds1307_ihandle = 0;

/* one second time out */
#define	I2c_CYCLIC_TIMEOUT	1000000000
uint_t i2c_cyclic_timeout = I2c_CYCLIC_TIMEOUT;
static int sync_clock_once = 1;
static 	struct	rtc_t	 soft_rtc;

/*
 * For debugging only
 */
static unsigned char int2bcd(int num);
static int bcd2int(unsigned char num);

/*
 * cp_ops structure
 */
static struct cb_ops ds1307_cbops = {
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
static struct dev_ops ds1307_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* refcnt - reference cnt always set to 0 */
	todds1307_getinfo,	/* getinfo - Maybe requred */
	nulldev,		/* identify */
	nulldev,		/* probe */
	todds1307_attach,	/* attach */
	todds1307_detach,	/* detach */
	nodev,			/* reset */
	&ds1307_cbops,		/* cb_ops - ds1307 does not need this(?) */
	NULL,			/* bus_ops */
	NULL,			/* power */
	ddi_quiesce_not_needed,		/* quiesce */
};

static struct modldrv todds1307_modldrv = {
	&mod_driverops,		/* Type of module. This one is a driver */
	"tod driver for DS1307 v1.12",	/* Name of the module */
	&ds1307_ops,			/* Pointer to dev_ops */
};

/*
 * Module linkage structure
 */
static struct modlinkage todds1307_modlinkage = {
	MODREV_1,
	&todds1307_modldrv,
	0
};

int
_init(void)
{
	int error;

	if (strcmp(tod_module_name, "todds1307") == 0) {
		if ((error = ddi_soft_state_init(&ds1307_statep,
		    sizeof (ds1307_state_t), 0)) != DDI_SUCCESS) {
			return (error);
		}

		tod_ops.tod_get = todds1307_get;
		tod_ops.tod_set = todds1307_set;
		tod_ops.tod_set_watchdog_timer = todds1307_set_watchdog_timer;
		tod_ops.tod_clear_watchdog_timer =
		    todds1307_clear_watchdog_timer;
		tod_ops.tod_set_power_alarm = todds1307_set_power_alarm;
		tod_ops.tod_clear_power_alarm = todds1307_clear_power_alarm;
	}

	(void) todds1307_setup_prom();

	/*
	 * Install the module
	 */
	if ((error = mod_install(&todds1307_modlinkage)) != 0) {
		ddi_soft_state_fini(&ds1307_statep);
		return (error);
	}
	mutex_init(&todds1307_rd_lock, NULL, MUTEX_DEFAULT, NULL);

	return (0);
}

int
_fini(void)
{
	int error = 0;

	if (strcmp(tod_module_name, "todds1307") == 0) {
		error = EBUSY;
	} else {
		if ((error = mod_remove(&todds1307_modlinkage)) == 0) {
			ddi_soft_state_fini(&ds1307_statep);
			mutex_destroy(&todds1307_rd_lock);
			todds1307_rele_prom();
		}
	}

	return (error);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&todds1307_modlinkage, modinfop));
}

/*
 * cyclical call to get tod.
 */
static void
todds1307_cyclic(void *arg)
{

	todds1307_read_rtc((struct rtc_t *)arg);

}

/*
 * register ds1307 client device with i2c services, and
 * allocate & initialize soft state structure.
 */
static int
todds1307_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	static ds1307_state_t	*statep = NULL;
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
		return (DDI_FAILURE);
	}

	instance = ddi_get_instance(dip);

	/*
	 * Allocate soft state structure
	 */
	if (ddi_soft_state_zalloc(ds1307_statep, instance) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	statep = ddi_get_soft_state(ds1307_statep, instance);
	if (statep == NULL) {
		return (DDI_FAILURE);
	}

	statep->dip = dip;

	if (i2c_client_register(dip, &statep->ds1307_i2c_hdl) != I2C_SUCCESS) {
		ddi_soft_state_free(ds1307_statep, instance);
		delay(drv_usectohz(I2C_DELAY));
		return (DDI_FAILURE);
	}

	/* check and initialize the oscillator */

	(void) i2c_transfer_alloc(statep->ds1307_i2c_hdl,
	    &i2c_tp, 1, 1, I2C_SLEEP);
	i2c_tp->i2c_version = I2C_XFER_REV;
	i2c_tp->i2c_flags = I2C_WR_RD;
	i2c_tp->i2c_wbuf[0] = (uchar_t)0x00; /* Read 00h */
	i2c_tp->i2c_wlen = 1;
	i2c_tp->i2c_rlen = 1;

	if ((i2c_transfer(statep->ds1307_i2c_hdl, i2c_tp)) != I2C_SUCCESS) {
		(void) i2c_transfer_free(statep->ds1307_i2c_hdl, i2c_tp);
		ddi_soft_state_free(ds1307_statep, instance);
		delay(drv_usectohz(I2C_DELAY));
		return (DDI_FAILURE);
	}

	tempVal = i2c_tp->i2c_rbuf[0];

	(void) i2c_transfer_free(statep->ds1307_i2c_hdl, i2c_tp);

	if (tempVal & 0x80) {			 /* check Oscillator */
		(void) i2c_transfer_alloc(statep->ds1307_i2c_hdl, &i2c_tp,
		    2, 1, I2C_SLEEP);
		i2c_tp->i2c_version = I2C_XFER_REV;
		i2c_tp->i2c_flags = I2C_WR;
		i2c_tp->i2c_wbuf[0] = 0x00;
		i2c_tp->i2c_wbuf[1] =
		    (uchar_t)(i2c_tp->i2c_rbuf[0]& 0x7f);
		i2c_tp->i2c_wlen = 2;
					/* Enable oscillator */
		if ((i2c_transfer(statep->ds1307_i2c_hdl, i2c_tp))
		    != I2C_SUCCESS) {
			(void) i2c_transfer_free(statep->ds1307_i2c_hdl,
			    i2c_tp);
			ddi_soft_state_free(ds1307_statep, instance);
			return (DDI_FAILURE);
		}
		(void) i2c_transfer_free(statep->ds1307_i2c_hdl, i2c_tp);
	}

	/*
	 * Create a periodical handler to read TOD.
	 */
	ASSERT(statep->cycid == NULL);
	statep->cycid = ddi_periodic_add(todds1307_cyclic, &soft_rtc,
	    i2c_cyclic_timeout, DDI_IPL_1);

	statep->state = TOD_ATTACHED;
	todds1307_attach_done = 1;
	ddi_report_dev(dip);

	return (DDI_SUCCESS);
}

/*
 * Unregister ds1307 client device with i2c services and free
 * soft state structure.
 */
/*ARGSUSED*/
static int
todds1307_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	switch (cmd) {

	/*
	 * Once attached, do not allow detach because the system constantly
	 * calling todds1307_get() to get the time.  If the driver is detached
	 * and the system try to get the time, the system will have memory
	 * problem.
	 *
	 *	ds1307_state_t	*statep = NULL;
	 *	case DDI_DETACH:
	 *		if ((statep = ddi_get_soft_state(ds1307_statep,
	 *					instance)) == NULL) {
	 *			return (ENOMEM);
	 *		}
	 *		i2c_client_unregister(statep->ds1307_i2c_hdl);
	 *		ddi_soft_state_free(ds1307_statep, instance);
	 *		return (DDI_SUCCESS);
	 */
		case DDI_SUSPEND:
			return (DDI_SUCCESS);

		default:
			return (DDI_FAILURE);
	}
}

/* *********************** tod_ops entry points ******************** */

/*
 * Read the current time from the DS1307 chip and convert to UNIX form.
 * Should be called with tod_clock held.
 */

static timestruc_t
todds1307_get(void)
{
	timestruc_t	ts;
	todinfo_t	tod;
	struct	rtc_t	rtc;

	ASSERT(MUTEX_HELD(&tod_lock));

	if (sync_clock_once) {
		todds1307_read_rtc(&soft_rtc);
		sync_clock_once = 0;
	} else {
		tod_fault_reset();
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

	ts.tv_sec = tod_to_utc(tod);
	ts.tv_nsec = 0;
	return (ts);
}

/*
 * Program DS1307 with the specified time.
 * Must be called with tod_lock held. The TOD
 * chip supports date from 1969-2068 only. We must
 * reject requests to set date below 2000.
 */
static void
todds1307_set(timestruc_t ts)
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

	rtc.rtc_year	= int2bcd(year);
	rtc.rtc_mon	= int2bcd(tod.tod_month);
	rtc.rtc_dom	= int2bcd(tod.tod_day);
	rtc.rtc_dow	= int2bcd(tod.tod_dow);
	rtc.rtc_hrs	= int2bcd(tod.tod_hour);
	rtc.rtc_min	= int2bcd(tod.tod_min);
	rtc.rtc_sec	= int2bcd(tod.tod_sec);

	todds1307_write_rtc(&rtc);
}

/* ARGSUSED */
static void
todds1307_set_power_alarm(timestruc_t ts)
{
	ASSERT(MUTEX_HELD(&tod_lock));
}

/* ARGSUSED */
static void
todds1307_clear_power_alarm(void)
{
	ASSERT(MUTEX_HELD(&tod_lock));
}

/* ARGSUSED */
static uint_t
todds1307_set_watchdog_timer(uint_t timeoutval)
{
	ASSERT(MUTEX_HELD(&tod_lock));
	return (0);
}

/* ARGSUSED */
static uint_t
todds1307_clear_watchdog_timer(void)
{
	ASSERT(MUTEX_HELD(&tod_lock));
	return (0);
}

/* ********************** Local functions ***************************** */

static char tod_read[7] = {-1, -1, -1, -1, -1, -1, -1};
static int
todds1307_read_rtc(struct rtc_t *rtc)
{
	static	ds1307_state_t	*statep = NULL;
	i2c_transfer_t	*i2c_tp = NULL;
	int i2c_cmd_status = I2C_FAILURE;
	int counter = 4;

	if (!todds1307_attach_done) {
		return (todds1307_prom_getdate(rtc));
	}

	statep = ddi_get_soft_state(ds1307_statep, instance);
	if (statep == NULL) {
		cmn_err(CE_WARN, "todds1307: ddi_get_soft_state failed");
		return (DDI_FAILURE);
	}

	mutex_enter(&todds1307_rd_lock);

	/*
	 * Allocate 1 byte for write buffer and 7 bytes for read buffer to
	 * to accomodate sec, min, hrs, dayOfWeek, dayOfMonth, year
	 */
	if ((i2c_transfer_alloc(statep->ds1307_i2c_hdl, &i2c_tp, 1,
	    7, I2C_SLEEP)) != I2C_SUCCESS) {
		mutex_exit(&todds1307_rd_lock);
		return (DDI_FAILURE);
	}

	do {
		i2c_tp->i2c_version = I2C_XFER_REV;
		i2c_tp->i2c_flags = I2C_WR_RD;
		i2c_tp->i2c_wbuf[0] = (uchar_t)0x00; /* Start from reg 0x00 */
		i2c_tp->i2c_wlen = 1;	/* Write one byte address */
		i2c_tp->i2c_rlen = 7;	/* Read 7 regs */

		if ((i2c_cmd_status = i2c_transfer(statep->ds1307_i2c_hdl,
		    i2c_tp)) != I2C_SUCCESS) {
			drv_usecwait(I2C_DELAY);
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
		if ((i2c_cmd_status = i2c_transfer(statep->ds1307_i2c_hdl,
		    i2c_tp)) != I2C_SUCCESS) {
			drv_usecwait(I2C_DELAY);
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


	rtc->rtc_year	= bcd2int(i2c_tp->i2c_rbuf[6]);
	rtc->rtc_mon	= bcd2int(i2c_tp->i2c_rbuf[5]);
	rtc->rtc_dom	= bcd2int(i2c_tp->i2c_rbuf[4]);
	rtc->rtc_dow	= bcd2int(i2c_tp->i2c_rbuf[3]);
	rtc->rtc_hrs	= bcd2int(i2c_tp->i2c_rbuf[2]);
	rtc->rtc_min	= bcd2int(i2c_tp->i2c_rbuf[1]);
	rtc->rtc_sec	= bcd2int(i2c_tp->i2c_rbuf[0]);

done:
	(void) i2c_transfer_free(statep->ds1307_i2c_hdl, i2c_tp);

	mutex_exit(&todds1307_rd_lock);
	return (i2c_cmd_status);
}


static int
todds1307_write_rtc(struct rtc_t *rtc)
{
	ds1307_state_t	*statep = NULL;
	i2c_transfer_t	*i2c_tp = NULL;
	int i2c_cmd_status = I2C_SUCCESS;


	if (!todds1307_attach_done) {
		return (todds1307_prom_setdate(rtc));
	}

	statep = ddi_get_soft_state(ds1307_statep, instance);
	if (statep == NULL) {
		return (DDI_FAILURE);
	}

	if ((i2c_cmd_status = i2c_transfer_alloc(statep->ds1307_i2c_hdl,
	    &i2c_tp, 8, 0, I2C_SLEEP)) != I2C_SUCCESS) {
		return (i2c_cmd_status);
	}

	i2c_tp->i2c_version = I2C_XFER_REV;
	i2c_tp->i2c_flags = I2C_WR;
	i2c_tp->i2c_wbuf[0] = (uchar_t)0x00;
	i2c_tp->i2c_wbuf[1] = rtc->rtc_sec;
	i2c_tp->i2c_wbuf[2] = rtc->rtc_min;
	i2c_tp->i2c_wbuf[3] = rtc->rtc_hrs;
	i2c_tp->i2c_wbuf[4] = rtc->rtc_dow;
	i2c_tp->i2c_wbuf[5] = rtc->rtc_dom;
	i2c_tp->i2c_wbuf[6] = rtc->rtc_mon;
	i2c_tp->i2c_wbuf[7] = rtc->rtc_year;
	i2c_tp->i2c_wlen = 8;

	if ((i2c_cmd_status = i2c_transfer(statep->ds1307_i2c_hdl,
	    i2c_tp)) != I2C_SUCCESS) {
		(void) i2c_transfer_free(statep->ds1307_i2c_hdl, i2c_tp);
		/* delay(drv_usectohz(I2C_DELAY)); */
		drv_usecwait(I2C_DELAY);
		return (i2c_cmd_status);
	}

	tod_read[0] = -1;  /* invalidate saved data from read routine */

	(void) i2c_transfer_free(statep->ds1307_i2c_hdl, i2c_tp);

	return (i2c_cmd_status);
}


/*ARGSUSED*/
static int
todds1307_getinfo(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg,
    void **result)
{
	ds1307_state_t *softsp;

	if (instance == -1) {
		return (DDI_FAILURE);
	}

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		if ((softsp = ddi_get_soft_state(ds1307_statep, instance))
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

/*
 * Conversion functions
 */
static unsigned char
int2bcd(int num) {
	return (((num / 10) << 4)	/* tens BCD digit in high four bits */
	+ (num % 10));		/* units digit goes in low four bits */
}

static int
bcd2int(unsigned char num) {
	return (((num >> 4) * 10)	/* 10 times high-order four bits */
	+ (num & 0x0f));		/* plus low-order four bits */
}

/*
 * Finds the device node with device_type "rtc" and opens it to
 * execute the get-time method
 */
static int
todds1307_setup_prom()
{
	pnode_t todnode;
	char tod1307_devpath[MAXNAMELEN];

	if ((todnode = prom_findnode_bydevtype(prom_rootnode(),
	    DS1307_DEVICE_TYPE)) == OBP_NONODE)
		return (DDI_FAILURE);

	/*
	 * We now have the phandle of the rtc node, we need to open the
	 * node and get the ihandle
	 */
	if (prom_phandle_to_path(todnode, tod1307_devpath,
	    sizeof (tod1307_devpath)) < 0) {
		cmn_err(CE_WARN, "prom_phandle_to_path failed");
		return (DDI_FAILURE);
	}

	/*
	 * Now open the node and store it's ihandle
	 */
	if ((todds1307_ihandle = prom_open(tod1307_devpath)) == NULL) {
		cmn_err(CE_WARN, "prom_open failed");
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/*
 * Closes the prom interface
 */
static void
todds1307_rele_prom()
{
	(void) prom_close(todds1307_ihandle);
}

/*
 * Read the date using "get-time" method in rtc node
 * PROM returns 1969-1999 when reading 69-99 and
 * 2000-2068 when reading 00-68
 */
static int
todds1307_prom_getdate(struct rtc_t *rtc)
{
	int year;
	cell_t ci[12];

	ci[0] = p1275_ptr2cell("call-method");  /* Service name */
	ci[1] = 2; /* # of arguments */
	ci[2] = 7; /* # of result cells */
	ci[3] = p1275_ptr2cell("get-time");
	ci[4] = p1275_ihandle2cell(todds1307_ihandle);

	promif_preprom();
	(void) p1275_cif_handler(&ci);
	promif_postprom();

	year 		= p1275_cell2int(ci[6]);
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
todds1307_prom_setdate(struct rtc_t *rtc)
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
	ci[4] = p1275_ihandle2cell(todds1307_ihandle);
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
