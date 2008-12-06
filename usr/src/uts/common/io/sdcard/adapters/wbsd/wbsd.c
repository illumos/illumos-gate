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
#include <sys/sdcard/sda.h>
#include <sys/note.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include "wbsd.h"

typedef enum wbsd_direction { READ, WRITE } wbsd_direction_t;

/*
 * Soft state.
 */
typedef struct wbsd {
	dev_info_t		*w_dip;
	sda_host_t		*w_host;
	ddi_intr_handle_t	w_ihandle;
	ddi_softint_handle_t	w_shandle;
	ddi_acc_handle_t	w_acch;
	uint8_t			*w_regs;
	kmutex_t		w_lock;
	boolean_t		w_suspended;
	uint8_t			w_width;	/* data bus width */
	uint32_t		w_resid;	/* bytes remaining to xfer */
	uint32_t		w_nblks;	/* blocks remaining to xfer */
	uint32_t		w_blksz;	/* block size */
	uint8_t			*w_data;	/* data pointer */
	wbsd_direction_t	w_direction;
	sda_err_t		w_cmd_err;
	sda_err_t		w_dat_err;
	boolean_t		w_done;
	boolean_t		w_detect;
	boolean_t		w_acmd12;
	boolean_t		w_do_soft;
	uint16_t		w_ctime;	/* command timeout (us) */
} wbsd_t;

_NOTE(DATA_READABLE_WITHOUT_LOCK(wbsd::w_ctime))

#define	GETREG(wp, r)		ddi_get8(wp->w_acch, wp->w_regs + r)
#define	PUTREG(wp, r, v)	ddi_put8(wp->w_acch, wp->w_regs + r, v)
#define	SETREG(wp, r, b)	PUTREG(wp, r, GETREG(wp, r) | b)
#define	CLRREG(wp, r, b)	PUTREG(wp, r, GETREG(wp, r) & ~b)
#define	GETIDX(wp, i, v)	\
	{ PUTREG(wp, REG_IDXR, i); v = GETREG(wp, REG_DATAR); }
#define	PUTIDX(wp, i, v)	\
	{ PUTREG(wp, REG_IDXR, i); PUTREG(wp, REG_DATAR, v); }

static int wbsd_ddi_attach(dev_info_t *, ddi_attach_cmd_t);
static int wbsd_ddi_detach(dev_info_t *, ddi_detach_cmd_t);

static int wbsd_attach(dev_info_t *);
static int wbsd_detach(dev_info_t *);
static int wbsd_resume(dev_info_t *);
static int wbsd_suspend(dev_info_t *);

static sda_err_t wbsd_cmd(void *, sda_cmd_t *);
static sda_err_t wbsd_getprop(void *, sda_prop_t, uint32_t *);
static sda_err_t wbsd_setprop(void *, sda_prop_t, uint32_t);
static sda_err_t wbsd_reset(void *);
static sda_err_t wbsd_halt(void *);
static sda_err_t wbsd_poll(void *);

static uint_t wbsd_hard_intr(caddr_t, caddr_t);
static uint_t wbsd_soft_intr(caddr_t, caddr_t);
static int wbsd_setup_interrupts(wbsd_t *);
static void wbsd_teardown_interrupts(wbsd_t *);
static void wbsd_fifo_read(wbsd_t *);
static void wbsd_fifo_write(wbsd_t *);
static void wbsd_reset_hw(wbsd_t *);
static void wbsd_halt_hw(wbsd_t *);
static void wbsd_send_stop(wbsd_t *);
static void wbsd_busy_end(wbsd_t *);
static void wbsd_prog_end(wbsd_t *);
static void wbsd_detect(wbsd_t *);
static void wbsd_error(wbsd_t *, sda_err_t);

static struct dev_ops wbsd_dev_ops = {
	DEVO_REV,			/* devo_rev */
	0,				/* devo_refcnt */
	ddi_no_info,			/* devo_getinfo */
	nulldev,			/* devo_identify */
	nulldev,			/* devo_probe */
	wbsd_ddi_attach,		/* devo_attach */
	wbsd_ddi_detach,		/* devo_detach */
	nodev,				/* devo_reset */
	NULL,				/* devo_cb_ops */
	NULL,				/* devo_bus_ops */
	NULL,				/* devo_power */
	ddi_quiesce_not_supported,	/* devo_quiesce */
};

static struct modldrv wbsd_modldrv = {
	&mod_driverops,			/* drv_modops */
	"Winbond W83L519D SD Host",	/* drv_linkinfo */
	&wbsd_dev_ops			/* drv_dev_ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,			/* ml_rev */
	{ &wbsd_modldrv, NULL }		/* ml_linkage */
};

static struct sda_ops wbsd_sda_ops = {
	SDA_OPS_VERSION,
	wbsd_cmd,			/* so_cmd */
	wbsd_getprop,			/* so_getprop */
	wbsd_setprop,			/* so_setprop */
	wbsd_poll,			/* so_poll */
	wbsd_reset,			/* so_reset */
	wbsd_halt,			/* so_halt */
};

static ddi_device_acc_attr_t wbsd_regattr = {
	DDI_DEVICE_ATTR_V0,	/* devacc_attr_version */
	DDI_NEVERSWAP_ACC,	/* devacc_attr_endian_flags */
	DDI_STRICTORDER_ACC,	/* devacc_attr_dataorder */
	DDI_DEFAULT_ACC,	/* devacc_attr_access */
};

int
_init(void)
{
	int rv;

	sda_host_init_ops(&wbsd_dev_ops);

	if ((rv = mod_install(&modlinkage)) != 0) {
		sda_host_fini_ops(&wbsd_dev_ops);
	}

	return (rv);
}

int
_fini(void)
{
	int rv;

	if ((rv = mod_remove(&modlinkage)) == 0) {
		sda_host_fini_ops(&wbsd_dev_ops);
	}

	return (rv);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

int
wbsd_ddi_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_ATTACH:
		return (wbsd_attach(dip));
	case DDI_RESUME:
		return (wbsd_resume(dip));
	default:
		return (DDI_FAILURE);
	}
}

int
wbsd_ddi_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_DETACH:
		return (wbsd_detach(dip));
	case DDI_SUSPEND:
		return (wbsd_suspend(dip));
	default:
		return (DDI_FAILURE);
	}
}

int
wbsd_attach(dev_info_t *dip)
{
	wbsd_t	*wp;

	wp = kmem_zalloc(sizeof (*wp), KM_SLEEP);

	wp->w_host = sda_host_alloc(dip, 1, &wbsd_sda_ops, NULL);
	if (wp->w_host == NULL) {
		cmn_err(CE_WARN, "Unable to allocate SDA host structure");
		goto failed;
	}
	ddi_set_driver_private(dip, wp);
	sda_host_set_private(wp->w_host, 0, wp);

	wp->w_dip = dip;

	if (ddi_regs_map_setup(dip, 0, (caddr_t *)&wp->w_regs, 0, 0,
	    &wbsd_regattr, &wp->w_acch) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "Unable to map registers");
		goto failed;
	}

	/* make sure interrupts are disabled */
	PUTREG(wp, REG_EIR, 0);

	/* setup interrupts, also initializes locks */
	if (wbsd_setup_interrupts(wp) != DDI_SUCCESS)
		goto failed;

	ddi_report_dev(dip);

	/* enable device interrupts in DDI */
	(void) ddi_intr_enable(wp->w_ihandle);

	/* attach to the framework */
	if (sda_host_attach(wp->w_host) != DDI_SUCCESS) {
		goto failed;
	}

	return (DDI_SUCCESS);

failed:
	/* tear down interrupts */
	if (wp->w_ihandle != NULL) {
		PUTREG(wp, REG_EIR, 0);
		(void) GETREG(wp, REG_ISR);

		wbsd_teardown_interrupts(wp);
	}

	/* toss register map */
	if (wp->w_regs != NULL) {
		ddi_regs_map_free(&wp->w_acch);
	}

	/* free host resources */
	if (wp->w_host != NULL) {
		sda_host_free(wp->w_host);
	}

	kmem_free(wp, sizeof (*wp));
	return (DDI_FAILURE);
}

int
wbsd_detach(dev_info_t *dip)
{
	wbsd_t	*wp;

	wp = ddi_get_driver_private(dip);

	sda_host_detach(wp->w_host);

	/* disable interrupts */
	PUTREG(wp, REG_EIR, 0);
	(void) GETREG(wp, REG_ISR);

	/* remove power from the socket */
	SETREG(wp, REG_CSR,  CSR_POWER_N);

	wbsd_teardown_interrupts(wp);
	ddi_regs_map_free(&wp->w_acch);
	kmem_free(wp, sizeof (*wp));
	return (DDI_SUCCESS);
}

int
wbsd_suspend(dev_info_t *dip)
{
	wbsd_t	*wp;

	wp = ddi_get_driver_private(dip);

	sda_host_suspend(wp->w_host);

	mutex_enter(&wp->w_lock);
	wp->w_suspended = B_TRUE;
	wbsd_halt_hw(wp);
	mutex_exit(&wp->w_lock);

	return (DDI_SUCCESS);
}

int
wbsd_resume(dev_info_t *dip)
{
	wbsd_t	*wp;

	wp = ddi_get_driver_private(dip);

	mutex_enter(&wp->w_lock);
	wp->w_suspended = B_FALSE;
	wbsd_reset_hw(wp);
	mutex_exit(&wp->w_lock);

	sda_host_resume(wp->w_host);

	return (DDI_SUCCESS);
}

int
wbsd_setup_interrupts(wbsd_t *wp)
{
	uint_t			ipri;
	int			actual;
	ddi_intr_handle_t	ih;
	ddi_softint_handle_t	sh;

	/*
	 * Setup interrupt.  Note that these are ISA devices, and only have
	 * a single fixed interrupt.
	 */
	if (ddi_intr_alloc(wp->w_dip, &ih, DDI_INTR_TYPE_FIXED, 0,
	    1, &actual, DDI_INTR_ALLOC_STRICT) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "Unable to allocate interrupt");
		return (DDI_FAILURE);
	}
	if (ddi_intr_get_pri(ih, &ipri) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "Unable to get interrupt priority");
		(void) ddi_intr_free(ih);
		return (DDI_FAILURE);
	}
	if (ddi_intr_add_handler(ih, wbsd_hard_intr, wp, NULL) !=
	    DDI_SUCCESS) {
		cmn_err(CE_WARN, "Unable to add interrupt handler");
		(void) ddi_intr_free(ih);
		return (DDI_FAILURE);
	}
	mutex_init(&wp->w_lock, NULL, MUTEX_DRIVER, DDI_INTR_PRI(ipri));

	/*
	 * Soft interrupt is next.
	 */
	if (ddi_intr_add_softint(wp->w_dip, &sh, DDI_INTR_SOFTPRI_MIN,
	    wbsd_soft_intr, wp) != DDI_SUCCESS) {
		(void) ddi_intr_remove_handler(ih);
		(void) ddi_intr_free(ih);
		mutex_destroy(&wp->w_lock);
		return (DDI_FAILURE);
	}

	wp->w_ihandle = ih;
	wp->w_shandle = sh;

	return (DDI_SUCCESS);
}

void
wbsd_teardown_interrupts(wbsd_t *wp)
{
	(void) ddi_intr_disable(wp->w_ihandle);

	/*
	 * These are here to ensure that any previously
	 * running interrupts (hard or soft) have completed.
	 */
	mutex_enter(&wp->w_lock);
	mutex_exit(&wp->w_lock);

	(void) ddi_intr_remove_handler(wp->w_ihandle);
	(void) ddi_intr_free(wp->w_ihandle);
	(void) ddi_intr_remove_softint(wp->w_shandle);

	mutex_destroy(&wp->w_lock);
}


void
wbsd_detect(wbsd_t *wp)
{
	wp->w_detect = B_TRUE;
	wp->w_done = B_TRUE;
	wp->w_cmd_err = wp->w_dat_err = SDA_ENODEV;
	wp->w_do_soft = B_TRUE;
}

void
wbsd_error(wbsd_t *wp, sda_err_t err)
{
	wp->w_done = B_TRUE;
	wp->w_cmd_err = wp->w_dat_err = err;
	wp->w_do_soft = B_TRUE;
}

void
wbsd_busy_end(wbsd_t *wp)
{
	wp->w_done = B_TRUE;
	wp->w_do_soft = B_TRUE;
}

void
wbsd_prog_end(wbsd_t *wp)
{
	ASSERT(wp->w_direction == WRITE);
	if (wp->w_nblks > 0) {
		wp->w_nblks--;
		if (wp->w_nblks > 0) {

			/*
			 * Start transferring the next block.
			 */
			wp->w_resid = wp->w_blksz;
			wbsd_fifo_write(wp);

		} else {
			/*
			 * If we needed auto terminate, then do it now.
			 */
			if (wp->w_acmd12) {
				wbsd_send_stop(wp);

			/*
			 * Otherwise its a single block write completion, so
			 * just complete the transfer.
			 */
			} else {
				wp->w_done = B_TRUE;
				wp->w_do_soft = B_TRUE;
			}
		}
	}
}

uint_t
wbsd_hard_intr(caddr_t arg1, caddr_t arg2)
{
	wbsd_t		*wp = (void *)arg1;
	uint8_t		isr;
	uint_t		rv = DDI_INTR_UNCLAIMED;
	boolean_t	do_soft = B_FALSE;
	int		i;

	mutex_enter(&wp->w_lock);
	if (wp->w_suspended) {
		mutex_exit(&wp->w_lock);
		return (rv);
	}

	for (i = 0; i < 100000; i++) {
		isr = GETREG(wp, REG_ISR);

		if ((isr == 0xff) || ((isr & ISR_WANTED) == 0))
			break;

		rv = DDI_INTR_CLAIMED;

		if (isr & ISR_CARD) {
			/*
			 * Make sure that the chip is fully reset after
			 * a card interrupt occurs.
			 */
			wbsd_reset_hw(wp);
			wbsd_detect(wp);
			break;
		}

		if (isr & ISR_FIFO) {
			/*
			 * FIFO data ready.  Process this as quickly as
			 * possible.
			 */
			if (wp->w_direction == WRITE) {
				wbsd_fifo_write(wp);
			} else {
				wbsd_fifo_read(wp);
			}
		}

		if (isr & ISR_BUSY_END) {
			wbsd_busy_end(wp);
		}

		if (isr & ISR_PROG_END) {
			wbsd_prog_end(wp);
		}

		if (isr & ISR_TIMEOUT) {
			wbsd_error(wp, SDA_ETIME);
		}

		if (isr & ISR_CRC_ERR) {
			wbsd_error(wp, SDA_ECRC7);
		}
	}

	if (i >= 100000) {
		PUTREG(wp, REG_EIR, 0);
		sda_host_log(wp->w_host, 0,
		    "Stuck interrupt detected (isr %x)", isr);
		sda_host_fault(wp->w_host, 0, SDA_FAULT_HOST);
	}

	/*
	 * If arg2 is NULL, then we are running as an ordinary interrupt.
	 * Otherwise we are running from polled context, and cannot trigger
	 * soft interrupts.
	 */
	if (wp->w_do_soft && (arg2 == NULL)) {
		wp->w_do_soft = B_FALSE;
		do_soft = B_TRUE;
	}
	mutex_exit(&wp->w_lock);

	if (do_soft)
		(void) ddi_intr_trigger_softint(wp->w_shandle, NULL);

	return (rv);
}

/*ARGSUSED1*/
uint_t
wbsd_soft_intr(caddr_t arg1, caddr_t arg2)
{
	wbsd_t 		*wp = (void *)arg1;
	boolean_t	detect = B_FALSE;
	boolean_t	done = B_FALSE;
	sda_err_t	err = SDA_EOK;

	mutex_enter(&wp->w_lock);

	detect = wp->w_detect;
	done = wp->w_done;
	err = wp->w_dat_err;

	wp->w_done = B_FALSE;
	wp->w_detect = B_FALSE;
	wp->w_dat_err = SDA_EOK;

	mutex_exit(&wp->w_lock);

	if (detect) {
		sda_host_detect(wp->w_host, 0);
	}

	if (done) {
		sda_host_transfer(wp->w_host, 0, err);
	}

	return (DDI_INTR_CLAIMED);
}

sda_err_t
wbsd_poll(void *arg)
{
	/* 2nd argument indicates running from poll */
	(void) wbsd_hard_intr(arg, (void *)wbsd_poll);
	(void) wbsd_soft_intr(arg, (void *)wbsd_poll);
	return (SDA_EOK);
}

sda_err_t
wbsd_getprop(void *arg, sda_prop_t prop, uint32_t *val)
{
	wbsd_t		*wp = arg;
	sda_err_t	rv = SDA_EOK;
	uint8_t		clock;

	mutex_enter(&wp->w_lock);
	if (wp->w_suspended) {
		mutex_exit(&wp->w_lock);
		return (SDA_ESUSPENDED);
	}

	switch (prop) {
	case SDA_PROP_INSERTED:
		*val = (GETREG(wp, REG_CSR) & CSR_PRESENT) ? B_TRUE : B_FALSE;
		break;

	case SDA_PROP_WPROTECT:
		/* switch signal select */
		SETREG(wp, REG_CSR, CSR_MSLED);

		drv_usecwait(1000);
		*val = (GETREG(wp, REG_CSR) & CSR_WPROTECT) ? B_TRUE : B_FALSE;
		CLRREG(wp, REG_CSR, CSR_MSLED);
		break;

	case SDA_PROP_OCR:
		*val = OCR_32_33V;
		break;

	case SDA_PROP_CLOCK:
		GETIDX(wp, IDX_CLOCK, clock)
		switch (clock) {
		case IDX_CLOCK_24M:
			*val = 24000000;
			break;
		case IDX_CLOCK_16M:
			*val = 16000000;
			break;
		case IDX_CLOCK_12M:
			*val = 12000000;
			break;
		case IDX_CLOCK_375K:
			*val = 375000;
			break;
		default:
			*val = 0;
			break;
		}
		break;

	case SDA_PROP_CAP_4BITS:
		/*
		 * On Tadpole SPARCLE hardware, the card detect uses
		 * DAT3, which causes all kinds of problems.  It is quite
		 * troublesome to support card detection events properly with
		 * this configuration, so we fall back to supporting only
		 * single bit mode.  It is possible to correct this, but
		 * it requires changes in the framework, particularly to
		 * note that the DAT3 pin is used this way.
		 *
		 * In particular, this would require separate commands to
		 * the card to connect/disconnect the card internal pullup
		 * resistor, as well as to manipulate the interrupt register,
		 * and then poll card status on command completion.
		 *
		 * The Winbond part is so slow, that it is doubtful that the
		 * trouble would be worth it.  On x86 hardware where we can
		 * make use of GPIO pin detection, the situation might be
		 * quite different.
		 */
		*val = B_FALSE;
		break;

	case SDA_PROP_CAP_NOPIO:
	case SDA_PROP_CAP_INTR:
	case SDA_PROP_CAP_8BITS:
		*val = B_FALSE;
		break;

	default:
		rv = SDA_ENOTSUP;
		break;
	}

	mutex_exit(&wp->w_lock);

	return (rv);
}

sda_err_t
wbsd_setprop(void *arg, sda_prop_t prop, uint32_t val)
{
	wbsd_t		*wp = arg;
	sda_err_t	rv = SDA_EOK;
	uint8_t		clock;

	mutex_enter(&wp->w_lock);
	if (wp->w_suspended) {
		mutex_exit(&wp->w_lock);
		return (SDA_ESUSPENDED);
	}

	switch (prop) {

	case SDA_PROP_LED:
		break;
	case SDA_PROP_CLOCK:
		/*
		 * Note that the "worst case" command timeouts are 16.7us for
		 * the "slow" 12MHz clock.  So a 20us timeout is enough for
		 * everything faster.
		 */
		wp->w_ctime = 20;
		if (val >= 24000000) {
			clock = IDX_CLOCK_24M;
		} else if (val >= 16000000) {
			clock = IDX_CLOCK_16M;
		} else if (val >= 12000000) {
			clock = IDX_CLOCK_12M;
		} else {
			/*
			 * Worst case command timeout is 533.3 usec.  Just
			 * pick a big enough value to force it.  If we choose
			 * a value of 2 msec, it is enough even if the clock
			 * runs as low as 100KHz.
			 */
			clock = IDX_CLOCK_375K;
			wp->w_ctime = 2000;
		}
		PUTIDX(wp, IDX_CLOCK, clock);
		break;

	case SDA_PROP_BUSWIDTH:
		/*
		 * See the comment in SDA_PROP_CAP_4BITS, though.
		 */
		if ((val == 4) || (val == 1)) {
			wp->w_width = (uint8_t)val;
		} else {
			rv = SDA_EINVAL;
		}
		break;

	case SDA_PROP_OCR:
		if ((val == OCR_32_33V) &&
		    ((GETREG(wp, REG_CSR) & CSR_PRESENT) != 0)) {
			/* apply power */
			CLRREG(wp, REG_CSR, CSR_POWER_N);
			/* activate the various other interrupts on the chip */
			PUTREG(wp, REG_EIR, EIR_CARD | EIR_FIFO | EIR_CRC_ERR |
			    EIR_TIMEOUT | EIR_PROG_END | EIR_BUSY_END);
		} else {
			/* power down and reset */
			wbsd_reset_hw(wp);
			if (val != 0) {
				rv = SDA_EINVAL;
			}
		}
		break;

	default:
		break;
	}

	mutex_exit(&wp->w_lock);

	return (rv);
}

void
wbsd_fifo_read(wbsd_t *wp)
{
	uint8_t	fsr;
	uint8_t	cnt;

	ASSERT(mutex_owned(&wp->w_lock));

	while ((((fsr = GETREG(wp, REG_FSR)) & FSR_EMPTY) == 0) &&
	    (wp->w_resid != 0)) {
		/*
		 * The point of this logic is to avoid extra reads of
		 * the fifo status register.  We are throughput
		 * limited by the number of PIOs.
		 */
		if ((fsr & FSR_FULL) != 0) {
			cnt = 16;
		} else if ((fsr & FSR_FULL_THRE) != 0) {
			cnt = 8;
		} else {
			cnt = 1;
		}
		while ((cnt != 0) && (wp->w_resid != 0)) {
			cnt--;
			wp->w_resid--;
			*wp->w_data++ = GETREG(wp, REG_DFR);
		}
	}

	if (wp->w_resid != 0) {
		PUTIDX(wp, IDX_THRESH, IDX_THRESH_FULL | min(wp->w_resid, 8));
	} else {
		PUTIDX(wp, IDX_THRESH, 0);

		if (wp->w_acmd12) {
			wbsd_send_stop(wp);
		} else {
			wbsd_busy_end(wp);
		}
	}
}

void
wbsd_fifo_write(wbsd_t *wp)
{
	uint8_t	fsr;
	uint8_t	cnt;

	ASSERT(mutex_owned(&wp->w_lock));

	while ((((fsr = GETREG(wp, REG_FSR)) & FSR_FULL) == 0) &&
	    (wp->w_resid != 0)) {
		if ((fsr & FSR_EMPTY) != 0) {
			cnt = 16;
		} else if ((fsr & FSR_EMPTY_THRE) != 0) {
			cnt = 8;
		} else {
			cnt = 1;
		}
		while ((cnt != 0) && (wp->w_resid != 0)) {
			cnt--;
			wp->w_resid--;
			PUTREG(wp, REG_DFR, *wp->w_data++);
		}
	}
	if (wp->w_resid != 0) {
		PUTIDX(wp, IDX_THRESH, IDX_THRESH_EMPTY | min(wp->w_resid, 8));
	} else {
		PUTIDX(wp, IDX_THRESH, 0);
		/* wait for PROG interrupt */
	}
}

void
wbsd_send_stop(wbsd_t *wp)
{
	wp->w_acmd12 = B_FALSE;

	PUTREG(wp, REG_CMDR, CMD_STOP_TRANSMIT);
	PUTREG(wp, REG_CMDR, 0);
	PUTREG(wp, REG_CMDR, 0);
	PUTREG(wp, REG_CMDR, 0);
	PUTREG(wp, REG_CMDR, 0);
}

sda_err_t
wbsd_cmd(void *arg, sda_cmd_t *cmdp)
{
	wbsd_t		*wp = arg;
	boolean_t	checkcrc;
	uint8_t		rstart;
	uint8_t		rwords;
	sda_err_t	rv = SDA_EOK;

	checkcrc = B_TRUE;
	rstart = IDX_RESP_12;
	rwords = 1;

	switch (cmdp->sc_rtype) {
	case R0:
		rwords = 0;
		break;
	case R1:
	case R5:
	case R6:
	case R7:
	case R1b:
	case R5b:
		break;
	case R2:
		rstart = IDX_RESP_1;
		rwords = 4;
		checkcrc = B_FALSE;
		break;
	case R3:
	case R4:
		checkcrc = B_FALSE;
		break;
	}

	mutex_enter(&wp->w_lock);
	if (wp->w_suspended) {
		mutex_exit(&wp->w_lock);
		return (SDA_ESUSPENDED);
	}

	if (cmdp->sc_nblks != 0) {
		uint16_t	sz;
		uint8_t		v;

		wp->w_blksz = cmdp->sc_blksz;
		wp->w_nblks = cmdp->sc_nblks;

		/* save a few things for completion */
		wp->w_data = (uint8_t *)cmdp->sc_kvaddr;

		wp->w_acmd12 = (cmdp->sc_flags & SDA_CMDF_AUTO_CMD12) ?
		    B_TRUE : B_FALSE;

		/* maximum timeouts, 127 msec and 25500 cycles */
		PUTIDX(wp, IDX_TAAC, 127);
		PUTIDX(wp, IDX_NSAC, 255);

		/* set data width */
		sz = cmdp->sc_blksz + ((wp->w_width == 4) ? 8 : 2);
		PUTIDX(wp, IDX_BLKSZMSB, ((sz >> 4) & 0xf0) |
		    ((wp->w_width == 4) ? 1 : 0));
		PUTIDX(wp, IDX_BLKSZLSB, sz & 0xff);

		/* make sure start the fifo with a clean slate */
		GETIDX(wp, IDX_RESET, v);
		v |= IDX_RESET_FIFO;
		PUTIDX(wp, IDX_RESET, v);

		/* we don't use DMA, period */
		PUTIDX(wp, IDX_DMA, 0);

		if ((cmdp->sc_flags & SDA_CMDF_READ) != 0) {
			/*
			 * Reading... we arrange to wait for the full
			 * transfer, than doing a block at a time.
			 * Simpler that way.
			 */

			wp->w_direction = READ;
			wp->w_resid = wp->w_blksz * wp->w_nblks;
			PUTIDX(wp, IDX_THRESH, IDX_THRESH_FULL |
			    min(wp->w_resid, 8));
		} else {
			/*
			 * Writing... go ahead and prefill the fifo.
			 * We write a block at a time, because we need
			 * the PROG interrupts in the block gaps.
			 */

			wp->w_direction = WRITE;
			wp->w_resid = wp->w_blksz;
			PUTIDX(wp, IDX_THRESH, IDX_THRESH_EMPTY |
			    min(wp->w_blksz, 8));
			wbsd_fifo_write(wp);
		}
	}

	/*
	 * This chip is a bit simple minded.  It cannot distinguish
	 * between errors that occur on the data line, and those that
	 * occur on the CMD line.
	 */

	/* make sure we clear any preexisting error condition */
	wp->w_cmd_err = SDA_EOK;

	PUTREG(wp, REG_CMDR, cmdp->sc_index);
	PUTREG(wp, REG_CMDR, (cmdp->sc_argument >> 24) & 0xff);
	PUTREG(wp, REG_CMDR, (cmdp->sc_argument >> 16) & 0xff);
	PUTREG(wp, REG_CMDR, (cmdp->sc_argument >> 8) & 0xff);
	PUTREG(wp, REG_CMDR, (cmdp->sc_argument) & 0xff);

	/*
	 * Note that while we are waiting for the timer to run out (which
	 * is really short), a timeout or other error interrupt can occur.
	 * We want to know about such error indications, so we have to drop
	 * to the lock so that the interrupt service routine can post the
	 * appropriate error in the w_cmd_err variable.
	 */
	mutex_exit(&wp->w_lock);
	drv_usecwait(wp->w_ctime);
	mutex_enter(&wp->w_lock);

	if ((rv = wp->w_cmd_err) == SDA_EOK) {
		uint8_t	stat;
		GETIDX(wp, IDX_STATUS, stat);
		if ((stat & IDX_STATUS_TRAFFIC) != 0) {
			rv = SDA_ETIME;
		}
	}

	/* some commands don't use valid CRC */
	if ((rv == SDA_ECRC7) && !checkcrc) {
		rv = SDA_EOK;
	}

	PUTIDX(wp, IDX_RESET, IDX_RESET_AUTO_INC);
	PUTREG(wp, REG_IDXR, rstart);
	while (rwords != 0) {
		uint32_t	v;
		v = GETREG(wp, REG_DATAR);
		v <<= 8;
		v |= GETREG(wp, REG_DATAR);
		v <<= 8;
		v |= GETREG(wp, REG_DATAR);
		v <<= 8;
		v |= GETREG(wp, REG_DATAR);
		rwords--;
		cmdp->sc_response[rwords] = v;
	}
	PUTIDX(wp, IDX_RESET, IDX_RESET_AUTO_INC);

	mutex_exit(&wp->w_lock);


	return (rv);
}

void
wbsd_halt_hw(wbsd_t *wp)
{
	/* reset chip and fifo */
	PUTIDX(wp, IDX_RESET, IDX_RESET_SOFT | IDX_RESET_FIFO);

	/* disable interrupts */
	PUTREG(wp, REG_EIR, 0);

	/* remove power */
	SETREG(wp, REG_CSR, CSR_POWER_N);
}

void
wbsd_reset_hw(wbsd_t *wp)
{
	/* remove power from slot, set LED enable */
	PUTREG(wp, REG_CSR, CSR_POWER_N);

	/* reset chip and fifo */
	PUTIDX(wp, IDX_RESET, IDX_RESET_SOFT | IDX_RESET_FIFO);

	/* clear any pending interrupts */
	(void) GETREG(wp, REG_ISR);

	/* enable card interrupt */
	PUTREG(wp, REG_EIR, EIR_CARD);
}

sda_err_t
wbsd_reset(void *arg)
{
	wbsd_t	*wp = arg;

	mutex_enter(&wp->w_lock);
	wp->w_acmd12 = B_FALSE;
	wp->w_resid = 0;
	wp->w_data = NULL;
	wp->w_width = 1;

	if (!wp->w_suspended) {
		/* reset occurred when we suspended */
		wbsd_reset_hw(wp);
	}
	mutex_exit(&wp->w_lock);

	return (SDA_EOK);
}

sda_err_t
wbsd_halt(void *arg)
{
	wbsd_t	*wp = arg;

	mutex_enter(&wp->w_lock);
	if (!wp->w_suspended) {
		wbsd_halt_hw(wp);
	}
	mutex_exit(&wp->w_lock);

	return (SDA_EOK);
}
