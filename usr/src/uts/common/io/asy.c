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

/*	Copyright (c) 1990, 1991 UNIX System Laboratories, Inc.	*/
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989, 1990 AT&T	*/
/*	  All Rights Reserved					*/

/*
 * Copyright (c) 1992, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2012 Milan Jurik. All rights reserved.
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */


/*
 * Serial I/O driver for 8250/16450/16550A/16650/16750 chips.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/signal.h>
#include <sys/stream.h>
#include <sys/termio.h>
#include <sys/errno.h>
#include <sys/file.h>
#include <sys/cmn_err.h>
#include <sys/stropts.h>
#include <sys/strsubr.h>
#include <sys/strtty.h>
#include <sys/debug.h>
#include <sys/kbio.h>
#include <sys/cred.h>
#include <sys/stat.h>
#include <sys/consdev.h>
#include <sys/mkdev.h>
#include <sys/kmem.h>
#include <sys/cred.h>
#include <sys/strsun.h>
#ifdef DEBUG
#include <sys/promif.h>
#endif
#include <sys/modctl.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/pci.h>
#include <sys/asy.h>
#include <sys/policy.h>

/*
 * set the RX FIFO trigger_level to half the RX FIFO size for now
 * we may want to make this configurable later.
 */
static	int asy_trig_level = FIFO_TRIG_8;

int asy_drain_check = 15000000;		/* tunable: exit drain check time */
int asy_min_dtr_low = 500000;		/* tunable: minimum DTR down time */
int asy_min_utbrk = 100000;		/* tunable: minumum untimed brk time */

int asymaxchip = ASY16750;	/* tunable: limit chip support we look for */

/*
 * Just in case someone has a chip with broken loopback mode, we provide a
 * means to disable the loopback test. By default, we only loopback test
 * UARTs which look like they have FIFOs bigger than 16 bytes.
 * Set to 0 to suppress test, or to 2 to enable test on any size FIFO.
 */
int asy_fifo_test = 1;		/* tunable: set to 0, 1, or 2 */

/*
 * Allow ability to switch off testing of the scratch register.
 * Some UART emulators might not have it. This will also disable the test
 * for Exar/Startech ST16C650, as that requires use of the SCR register.
 */
int asy_scr_test = 1;		/* tunable: set to 0 to disable SCR reg test */

/*
 * As we don't yet support on-chip flow control, it's a bad idea to put a
 * large number of characters in the TX FIFO, since if other end tells us
 * to stop transmitting, we can only stop filling the TX FIFO, but it will
 * still carry on draining by itself, so remote end still gets what's left
 * in the FIFO.
 */
int asy_max_tx_fifo = 16;	/* tunable: max fill of TX FIFO */

#define	async_stopc	async_ttycommon.t_stopc
#define	async_startc	async_ttycommon.t_startc

#define	ASY_INIT	1
#define	ASY_NOINIT	0

/* enum value for sw and hw flow control action */
typedef enum {
	FLOW_CHECK,
	FLOW_STOP,
	FLOW_START
} async_flowc_action;

#ifdef DEBUG
#define	ASY_DEBUG_INIT	0x0001	/* Output msgs during driver initialization. */
#define	ASY_DEBUG_INPUT	0x0002	/* Report characters received during int. */
#define	ASY_DEBUG_EOT	0x0004	/* Output msgs when wait for xmit to finish. */
#define	ASY_DEBUG_CLOSE	0x0008	/* Output msgs when driver open/close called */
#define	ASY_DEBUG_HFLOW	0x0010	/* Output msgs when H/W flowcontrol is active */
#define	ASY_DEBUG_PROCS	0x0020	/* Output each proc name as it is entered. */
#define	ASY_DEBUG_STATE	0x0040	/* Output value of Interrupt Service Reg. */
#define	ASY_DEBUG_INTR	0x0080	/* Output value of Interrupt Service Reg. */
#define	ASY_DEBUG_OUT	0x0100	/* Output msgs about output events. */
#define	ASY_DEBUG_BUSY	0x0200	/* Output msgs when xmit is enabled/disabled */
#define	ASY_DEBUG_MODEM	0x0400	/* Output msgs about modem status & control. */
#define	ASY_DEBUG_MODM2	0x0800	/* Output msgs about modem status & control. */
#define	ASY_DEBUG_IOCTL	0x1000	/* Output msgs about ioctl messages. */
#define	ASY_DEBUG_CHIP	0x2000	/* Output msgs about chip identification. */
#define	ASY_DEBUG_SFLOW	0x4000	/* Output msgs when S/W flowcontrol is active */
#define	ASY_DEBUG(x) (debug & (x))
static	int debug  = 0;
#else
#define	ASY_DEBUG(x) B_FALSE
#endif

/* pnpISA compressed device ids */
#define	pnpMTS0219 0xb6930219	/* Multitech MT5634ZTX modem */

/*
 * PPS (Pulse Per Second) support.
 */
void ddi_hardpps(struct timeval *, int);
/*
 * This is protected by the asy_excl_hi of the port on which PPS event
 * handling is enabled.  Note that only one port should have this enabled at
 * any one time.  Enabling PPS handling on multiple ports will result in
 * unpredictable (but benign) results.
 */
static struct ppsclockev asy_ppsev;

#ifdef PPSCLOCKLED
/* XXX Use these to observe PPS latencies and jitter on a scope */
#define	LED_ON
#define	LED_OFF
#else
#define	LED_ON
#define	LED_OFF
#endif

static	int max_asy_instance = -1;

static	uint_t	asysoftintr(caddr_t intarg);
static	uint_t	asyintr(caddr_t argasy);

static boolean_t abort_charseq_recognize(uchar_t ch);

/* The async interrupt entry points */
static void	async_txint(struct asycom *asy);
static void	async_rxint(struct asycom *asy, uchar_t lsr);
static void	async_msint(struct asycom *asy);
static void	async_softint(struct asycom *asy);

static void	async_ioctl(struct asyncline *async, queue_t *q, mblk_t *mp);
static void	async_reioctl(void *unit);
static void	async_iocdata(queue_t *q, mblk_t *mp);
static void	async_restart(void *arg);
static void	async_start(struct asyncline *async);
static void	async_nstart(struct asyncline *async, int mode);
static void	async_resume(struct asyncline *async);
static void	asy_program(struct asycom *asy, int mode);
static void	asyinit(struct asycom *asy);
static void	asy_waiteot(struct asycom *asy);
static void	asyputchar(cons_polledio_arg_t, uchar_t c);
static int	asygetchar(cons_polledio_arg_t);
static boolean_t	asyischar(cons_polledio_arg_t);

static int	asymctl(struct asycom *, int, int);
static int	asytodm(int, int);
static int	dmtoasy(int);
/*PRINTFLIKE2*/
static void	asyerror(int level, const char *fmt, ...) __KPRINTFLIKE(2);
static void	asy_parse_mode(dev_info_t *devi, struct asycom *asy);
static void	asy_soft_state_free(struct asycom *);
static char	*asy_hw_name(struct asycom *asy);
static void	async_hold_utbrk(void *arg);
static void	async_resume_utbrk(struct asyncline *async);
static void	async_dtr_free(struct asyncline *async);
static int	asy_identify_chip(dev_info_t *devi, struct asycom *asy);
static void	asy_reset_fifo(struct asycom *asy, uchar_t flags);
static int	asy_getproperty(dev_info_t *devi, struct asycom *asy,
		    const char *property);
static boolean_t	async_flowcontrol_sw_input(struct asycom *asy,
			    async_flowc_action onoff, int type);
static void	async_flowcontrol_sw_output(struct asycom *asy,
		    async_flowc_action onoff);
static void	async_flowcontrol_hw_input(struct asycom *asy,
		    async_flowc_action onoff, int type);
static void	async_flowcontrol_hw_output(struct asycom *asy,
		    async_flowc_action onoff);

#define	GET_PROP(devi, pname, pflag, pval, plen) \
		(ddi_prop_op(DDI_DEV_T_ANY, (devi), PROP_LEN_AND_VAL_BUF, \
		(pflag), (pname), (caddr_t)(pval), (plen)))

kmutex_t asy_glob_lock; /* lock protecting global data manipulation */
void *asy_soft_state;

/* Standard COM port I/O addresses */
static const int standard_com_ports[] = {
	COM1_IOADDR, COM2_IOADDR, COM3_IOADDR, COM4_IOADDR
};

static int *com_ports;
static uint_t num_com_ports;

#ifdef	DEBUG
/*
 * Set this to true to make the driver pretend to do a suspend.  Useful
 * for debugging suspend/resume code with a serial debugger.
 */
boolean_t	asy_nosuspend = B_FALSE;
#endif


/*
 * Baud rate table. Indexed by #defines found in sys/termios.h
 */
ushort_t asyspdtab[] = {
	0,	/* 0 baud rate */
	0x900,	/* 50 baud rate */
	0x600,	/* 75 baud rate */
	0x417,	/* 110 baud rate (%0.026) */
	0x359,	/* 134 baud rate (%0.058) */
	0x300,	/* 150 baud rate */
	0x240,	/* 200 baud rate */
	0x180,	/* 300 baud rate */
	0x0c0,	/* 600 baud rate */
	0x060,	/* 1200 baud rate */
	0x040,	/* 1800 baud rate */
	0x030,	/* 2400 baud rate */
	0x018,	/* 4800 baud rate */
	0x00c,	/* 9600 baud rate */
	0x006,	/* 19200 baud rate */
	0x003,	/* 38400 baud rate */

	0x002,	/* 57600 baud rate */
	0x0,	/* 76800 baud rate not supported */
	0x001,	/* 115200 baud rate */
	0x0,	/* 153600 baud rate not supported */
	0x0,	/* 0x8002 (SMC chip) 230400 baud rate not supported */
	0x0,	/* 307200 baud rate not supported */
	0x0,	/* 0x8001 (SMC chip) 460800 baud rate not supported */
	0x0,	/* unused */
	0x0,	/* unused */
	0x0,	/* unused */
	0x0,	/* unused */
	0x0,	/* unused */
	0x0,	/* unused */
	0x0,	/* unused */
	0x0,	/* unused */
	0x0,	/* unused */
};

static int asyrsrv(queue_t *q);
static int asyopen(queue_t *rq, dev_t *dev, int flag, int sflag, cred_t *cr);
static int asyclose(queue_t *q, int flag, cred_t *credp);
static int asywputdo(queue_t *q, mblk_t *mp, boolean_t);
static int asywput(queue_t *q, mblk_t *mp);

struct module_info asy_info = {
	0,
	"asy",
	0,
	INFPSZ,
	4096,
	128
};

static struct qinit asy_rint = {
	putq,
	asyrsrv,
	asyopen,
	asyclose,
	NULL,
	&asy_info,
	NULL
};

static struct qinit asy_wint = {
	asywput,
	NULL,
	NULL,
	NULL,
	NULL,
	&asy_info,
	NULL
};

struct streamtab asy_str_info = {
	&asy_rint,
	&asy_wint,
	NULL,
	NULL
};

static int asyinfo(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg,
		void **result);
static int asyprobe(dev_info_t *);
static int asyattach(dev_info_t *, ddi_attach_cmd_t);
static int asydetach(dev_info_t *, ddi_detach_cmd_t);
static int asyquiesce(dev_info_t *);

static 	struct cb_ops cb_asy_ops = {
	nodev,			/* cb_open */
	nodev,			/* cb_close */
	nodev,			/* cb_strategy */
	nodev,			/* cb_print */
	nodev,			/* cb_dump */
	nodev,			/* cb_read */
	nodev,			/* cb_write */
	nodev,			/* cb_ioctl */
	nodev,			/* cb_devmap */
	nodev,			/* cb_mmap */
	nodev,			/* cb_segmap */
	nochpoll,		/* cb_chpoll */
	ddi_prop_op,		/* cb_prop_op */
	&asy_str_info,		/* cb_stream */
	D_MP			/* cb_flag */
};

struct dev_ops asy_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* devo_refcnt */
	asyinfo,		/* devo_getinfo */
	nulldev,		/* devo_identify */
	asyprobe,		/* devo_probe */
	asyattach,		/* devo_attach */
	asydetach,		/* devo_detach */
	nodev,			/* devo_reset */
	&cb_asy_ops,		/* devo_cb_ops */
	NULL,			/* devo_bus_ops */
	NULL,			/* power */
	asyquiesce,		/* quiesce */
};

static struct modldrv modldrv = {
	&mod_driverops, /* Type of module.  This one is a driver */
	"ASY driver",
	&asy_ops,	/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modldrv,
	NULL
};

int
_init(void)
{
	int i;

	i = ddi_soft_state_init(&asy_soft_state, sizeof (struct asycom), 2);
	if (i == 0) {
		mutex_init(&asy_glob_lock, NULL, MUTEX_DRIVER, NULL);
		if ((i = mod_install(&modlinkage)) != 0) {
			mutex_destroy(&asy_glob_lock);
			ddi_soft_state_fini(&asy_soft_state);
		} else {
			DEBUGCONT2(ASY_DEBUG_INIT, "%s, debug = %x\n",
			    modldrv.drv_linkinfo, debug);
		}
	}
	return (i);
}

int
_fini(void)
{
	int i;

	if ((i = mod_remove(&modlinkage)) == 0) {
		DEBUGCONT1(ASY_DEBUG_INIT, "%s unloading\n",
		    modldrv.drv_linkinfo);
		ASSERT(max_asy_instance == -1);
		mutex_destroy(&asy_glob_lock);
		/* free "motherboard-serial-ports" property if allocated */
		if (com_ports != NULL && com_ports != (int *)standard_com_ports)
			ddi_prop_free(com_ports);
		com_ports = NULL;
		ddi_soft_state_fini(&asy_soft_state);
	}
	return (i);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

void
async_put_suspq(struct asycom *asy, mblk_t *mp)
{
	struct asyncline *async = asy->asy_priv;

	ASSERT(mutex_owned(&asy->asy_excl));

	if (async->async_suspqf == NULL)
		async->async_suspqf = mp;
	else
		async->async_suspqb->b_next = mp;

	async->async_suspqb = mp;
}

static mblk_t *
async_get_suspq(struct asycom *asy)
{
	struct asyncline *async = asy->asy_priv;
	mblk_t *mp;

	ASSERT(mutex_owned(&asy->asy_excl));

	if ((mp = async->async_suspqf) != NULL) {
		async->async_suspqf = mp->b_next;
		mp->b_next = NULL;
	} else {
		async->async_suspqb = NULL;
	}
	return (mp);
}

static void
async_process_suspq(struct asycom *asy)
{
	struct asyncline *async = asy->asy_priv;
	mblk_t *mp;

	ASSERT(mutex_owned(&asy->asy_excl));

	while ((mp = async_get_suspq(asy)) != NULL) {
		queue_t *q;

		q = async->async_ttycommon.t_writeq;
		ASSERT(q != NULL);
		mutex_exit(&asy->asy_excl);
		(void) asywputdo(q, mp, B_FALSE);
		mutex_enter(&asy->asy_excl);
	}
	async->async_flags &= ~ASYNC_DDI_SUSPENDED;
	cv_broadcast(&async->async_flags_cv);
}

static int
asy_get_bus_type(dev_info_t *devinfo)
{
	char	parent_type[16];
	int	parentlen;

	parentlen = sizeof (parent_type);

	if (ddi_prop_op(DDI_DEV_T_ANY, devinfo, PROP_LEN_AND_VAL_BUF, 0,
	    "device_type", (caddr_t)parent_type, &parentlen)
	    != DDI_PROP_SUCCESS && ddi_prop_op(DDI_DEV_T_ANY, devinfo,
	    PROP_LEN_AND_VAL_BUF, 0, "bus-type", (caddr_t)parent_type,
	    &parentlen) != DDI_PROP_SUCCESS) {
			cmn_err(CE_WARN,
			    "asy: can't figure out device type for"
			    " parent \"%s\"",
			    ddi_get_name(ddi_get_parent(devinfo)));
			return (ASY_BUS_UNKNOWN);
	}
	if (strcmp(parent_type, "isa") == 0)
		return (ASY_BUS_ISA);
	else if (strcmp(parent_type, "pci") == 0)
		return (ASY_BUS_PCI);
	else
		return (ASY_BUS_UNKNOWN);
}

static int
asy_get_io_regnum_pci(dev_info_t *devi, struct asycom *asy)
{
	int reglen, nregs;
	int regnum, i;
	uint64_t size;
	struct pci_phys_spec *reglist;

	if (ddi_getlongprop(DDI_DEV_T_ANY, devi, DDI_PROP_DONTPASS,
	    "reg", (caddr_t)&reglist, &reglen) != DDI_PROP_SUCCESS) {
		cmn_err(CE_WARN, "asy_get_io_regnum_pci: reg property"
		    " not found in devices property list");
		return (-1);
	}

	/*
	 * PCI devices are assumed to not have broken FIFOs;
	 * Agere/Lucent Venus PCI modem chipsets are an example
	 */
	if (asy)
		asy->asy_flags2 |= ASY2_NO_LOOPBACK;

	regnum = -1;
	nregs = reglen / sizeof (*reglist);
	for (i = 0; i < nregs; i++) {
		switch (reglist[i].pci_phys_hi & PCI_ADDR_MASK) {
		case PCI_ADDR_IO:		/* I/O bus reg property */
			if (regnum == -1) /* use only the first one */
				regnum = i;
			break;

		default:
			break;
		}
	}

	/* check for valid count of registers */
	if (regnum >= 0) {
		size = ((uint64_t)reglist[regnum].pci_size_low) |
		    ((uint64_t)reglist[regnum].pci_size_hi) << 32;
		if (size < 8)
			regnum = -1;
	}
	kmem_free(reglist, reglen);
	return (regnum);
}

static int
asy_get_io_regnum_isa(dev_info_t *devi, struct asycom *asy)
{
	int reglen, nregs;
	int regnum, i;
	struct {
		uint_t bustype;
		int base;
		int size;
	} *reglist;

	if (ddi_getlongprop(DDI_DEV_T_ANY, devi, DDI_PROP_DONTPASS,
	    "reg", (caddr_t)&reglist, &reglen) != DDI_PROP_SUCCESS) {
		cmn_err(CE_WARN, "asy_get_io_regnum: reg property not found "
		    "in devices property list");
		return (-1);
	}

	regnum = -1;
	nregs = reglen / sizeof (*reglist);
	for (i = 0; i < nregs; i++) {
		switch (reglist[i].bustype) {
		case 1:			/* I/O bus reg property */
			if (regnum == -1) /* only use the first one */
				regnum = i;
			break;

		case pnpMTS0219:	/* Multitech MT5634ZTX modem */
			/* Venus chipset can't do loopback test */
			if (asy)
				asy->asy_flags2 |= ASY2_NO_LOOPBACK;
			break;

		default:
			break;
		}
	}

	/* check for valid count of registers */
	if ((regnum < 0) || (reglist[regnum].size < 8))
		regnum = -1;
	kmem_free(reglist, reglen);
	return (regnum);
}

static int
asy_get_io_regnum(dev_info_t *devinfo, struct asycom *asy)
{
	switch (asy_get_bus_type(devinfo)) {
	case ASY_BUS_ISA:
		return (asy_get_io_regnum_isa(devinfo, asy));
	case ASY_BUS_PCI:
		return (asy_get_io_regnum_pci(devinfo, asy));
	default:
		return (-1);
	}
}

static int
asydetach(dev_info_t *devi, ddi_detach_cmd_t cmd)
{
	int instance;
	struct asycom *asy;
	struct asyncline *async;

	instance = ddi_get_instance(devi);	/* find out which unit */

	asy = ddi_get_soft_state(asy_soft_state, instance);
	if (asy == NULL)
		return (DDI_FAILURE);
	async = asy->asy_priv;

	switch (cmd) {
	case DDI_DETACH:
		DEBUGNOTE2(ASY_DEBUG_INIT, "asy%d: %s shutdown.",
		    instance, asy_hw_name(asy));

		/* cancel DTR hold timeout */
		if (async->async_dtrtid != 0) {
			(void) untimeout(async->async_dtrtid);
			async->async_dtrtid = 0;
		}

		/* remove all minor device node(s) for this device */
		ddi_remove_minor_node(devi, NULL);

		mutex_destroy(&asy->asy_excl);
		mutex_destroy(&asy->asy_excl_hi);
		cv_destroy(&async->async_flags_cv);
		ddi_remove_intr(devi, 0, asy->asy_iblock);
		ddi_regs_map_free(&asy->asy_iohandle);
		ddi_remove_softintr(asy->asy_softintr_id);
		mutex_destroy(&asy->asy_soft_lock);
		asy_soft_state_free(asy);
		DEBUGNOTE1(ASY_DEBUG_INIT, "asy%d: shutdown complete",
		    instance);
		break;
	case DDI_SUSPEND:
		{
		unsigned i;
		uchar_t lsr;

#ifdef	DEBUG
		if (asy_nosuspend)
			return (DDI_SUCCESS);
#endif
		mutex_enter(&asy->asy_excl);

		ASSERT(async->async_ops >= 0);
		while (async->async_ops > 0)
			cv_wait(&async->async_ops_cv, &asy->asy_excl);

		async->async_flags |= ASYNC_DDI_SUSPENDED;

		/* Wait for timed break and delay to complete */
		while ((async->async_flags & (ASYNC_BREAK|ASYNC_DELAY))) {
			if (cv_wait_sig(&async->async_flags_cv, &asy->asy_excl)
			    == 0) {
				async_process_suspq(asy);
				mutex_exit(&asy->asy_excl);
				return (DDI_FAILURE);
			}
		}

		/* Clear untimed break */
		if (async->async_flags & ASYNC_OUT_SUSPEND)
			async_resume_utbrk(async);

		mutex_exit(&asy->asy_excl);

		mutex_enter(&asy->asy_soft_sr);
		mutex_enter(&asy->asy_excl);
		if (async->async_wbufcid != 0) {
			bufcall_id_t bcid = async->async_wbufcid;
			async->async_wbufcid = 0;
			async->async_flags |= ASYNC_RESUME_BUFCALL;
			mutex_exit(&asy->asy_excl);
			unbufcall(bcid);
			mutex_enter(&asy->asy_excl);
		}
		mutex_enter(&asy->asy_excl_hi);

		/* Disable interrupts from chip */
		ddi_put8(asy->asy_iohandle, asy->asy_ioaddr + ICR, 0);
		asy->asy_flags |= ASY_DDI_SUSPENDED;

		/*
		 * Hardware interrupts are disabled we can drop our high level
		 * lock and proceed.
		 */
		mutex_exit(&asy->asy_excl_hi);

		/* Process remaining RX characters and RX errors, if any */
		lsr = ddi_get8(asy->asy_iohandle, asy->asy_ioaddr + LSR);
		async_rxint(asy, lsr);

		/* Wait for TX to drain */
		for (i = 1000; i > 0; i--) {
			lsr = ddi_get8(asy->asy_iohandle,
			    asy->asy_ioaddr + LSR);
			if ((lsr & (XSRE | XHRE)) == (XSRE | XHRE))
				break;
			delay(drv_usectohz(10000));
		}
		if (i == 0)
			cmn_err(CE_WARN,
			    "asy: transmitter wasn't drained before "
			    "driver was suspended");

		mutex_exit(&asy->asy_excl);
		mutex_exit(&asy->asy_soft_sr);
		break;
	}
	default:
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/*
 * asyprobe
 * We don't bother probing for the hardware, as since Solaris 2.6, device
 * nodes are only created for auto-detected hardware or nodes explicitly
 * created by the user, e.g. via the DCA. However, we should check the
 * device node is at least vaguely usable, i.e. we have a block of 8 i/o
 * ports. This prevents attempting to attach to bogus serial ports which
 * some BIOSs still partially report when they are disabled in the BIOS.
 */
static int
asyprobe(dev_info_t *devi)
{
	return ((asy_get_io_regnum(devi, NULL) < 0) ?
	    DDI_PROBE_FAILURE : DDI_PROBE_DONTCARE);
}

static int
asyattach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	int instance;
	int mcr;
	int ret;
	int regnum = 0;
	int i;
	struct asycom *asy;
	char name[ASY_MINOR_LEN];
	int status;
	static ddi_device_acc_attr_t ioattr = {
		DDI_DEVICE_ATTR_V0,
		DDI_NEVERSWAP_ACC,
		DDI_STRICTORDER_ACC,
	};

	instance = ddi_get_instance(devi);	/* find out which unit */

	switch (cmd) {
	case DDI_ATTACH:
		break;
	case DDI_RESUME:
	{
		struct asyncline *async;

#ifdef	DEBUG
		if (asy_nosuspend)
			return (DDI_SUCCESS);
#endif
		asy = ddi_get_soft_state(asy_soft_state, instance);
		if (asy == NULL)
			return (DDI_FAILURE);

		mutex_enter(&asy->asy_soft_sr);
		mutex_enter(&asy->asy_excl);
		mutex_enter(&asy->asy_excl_hi);

		async = asy->asy_priv;
		/* Disable interrupts */
		ddi_put8(asy->asy_iohandle, asy->asy_ioaddr + ICR, 0);
		if (asy_identify_chip(devi, asy) != DDI_SUCCESS) {
			mutex_exit(&asy->asy_excl_hi);
			mutex_exit(&asy->asy_excl);
			mutex_exit(&asy->asy_soft_sr);
			cmn_err(CE_WARN, "!Cannot identify UART chip at %p\n",
			    (void *)asy->asy_ioaddr);
			return (DDI_FAILURE);
		}
		asy->asy_flags &= ~ASY_DDI_SUSPENDED;
		if (async->async_flags & ASYNC_ISOPEN) {
			asy_program(asy, ASY_INIT);
			/* Kick off output */
			if (async->async_ocnt > 0) {
				async_resume(async);
			} else {
				mutex_exit(&asy->asy_excl_hi);
				if (async->async_xmitblk)
					freeb(async->async_xmitblk);
				async->async_xmitblk = NULL;
				async_start(async);
				mutex_enter(&asy->asy_excl_hi);
			}
			ASYSETSOFT(asy);
		}
		mutex_exit(&asy->asy_excl_hi);
		mutex_exit(&asy->asy_excl);
		mutex_exit(&asy->asy_soft_sr);

		mutex_enter(&asy->asy_excl);
		if (async->async_flags & ASYNC_RESUME_BUFCALL) {
			async->async_wbufcid = bufcall(async->async_wbufcds,
			    BPRI_HI, (void (*)(void *)) async_reioctl,
			    (void *)(intptr_t)async->async_common->asy_unit);
			async->async_flags &= ~ASYNC_RESUME_BUFCALL;
		}
		async_process_suspq(asy);
		mutex_exit(&asy->asy_excl);
		return (DDI_SUCCESS);
	}
	default:
		return (DDI_FAILURE);
	}

	ret = ddi_soft_state_zalloc(asy_soft_state, instance);
	if (ret != DDI_SUCCESS)
		return (DDI_FAILURE);
	asy = ddi_get_soft_state(asy_soft_state, instance);
	ASSERT(asy != NULL);	/* can't fail - we only just allocated it */
	asy->asy_unit = instance;
	mutex_enter(&asy_glob_lock);
	if (instance > max_asy_instance)
		max_asy_instance = instance;
	mutex_exit(&asy_glob_lock);

	regnum = asy_get_io_regnum(devi, asy);

	if (regnum < 0 ||
	    ddi_regs_map_setup(devi, regnum, (caddr_t *)&asy->asy_ioaddr,
	    (offset_t)0, (offset_t)0, &ioattr, &asy->asy_iohandle)
	    != DDI_SUCCESS) {
		cmn_err(CE_WARN, "asy%d: could not map UART registers @ %p",
		    instance, (void *)asy->asy_ioaddr);

		asy_soft_state_free(asy);
		return (DDI_FAILURE);
	}

	DEBUGCONT2(ASY_DEBUG_INIT, "asy%dattach: UART @ %p\n",
	    instance, (void *)asy->asy_ioaddr);

	mutex_enter(&asy_glob_lock);
	if (com_ports == NULL) {	/* need to initialize com_ports */
		if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, devi, 0,
		    "motherboard-serial-ports", &com_ports, &num_com_ports) !=
		    DDI_PROP_SUCCESS) {
			/* Use our built-in COM[1234] values */
			com_ports = (int *)standard_com_ports;
			num_com_ports = sizeof (standard_com_ports) /
			    sizeof (standard_com_ports[0]);
		}
		if (num_com_ports > 10) {
			/* We run out of single digits for device properties */
			num_com_ports = 10;
			cmn_err(CE_WARN,
			    "More than %d motherboard-serial-ports",
			    num_com_ports);
		}
	}
	mutex_exit(&asy_glob_lock);

	/*
	 * Lookup the i/o address to see if this is a standard COM port
	 * in which case we assign it the correct tty[a-d] to match the
	 * COM port number, or some other i/o address in which case it
	 * will be assigned /dev/term/[0123...] in some rather arbitrary
	 * fashion.
	 */

	for (i = 0; i < num_com_ports; i++) {
		if (asy->asy_ioaddr == (uint8_t *)(uintptr_t)com_ports[i]) {
			asy->asy_com_port = i + 1;
			break;
		}
	}

	/*
	 * It appears that there was async hardware that on reset
	 * did not clear ICR.  Hence when we get to
	 * ddi_get_iblock_cookie below, this hardware would cause
	 * the system to hang if there was input available.
	 */

	ddi_put8(asy->asy_iohandle, asy->asy_ioaddr + ICR, 0x00);

	/* establish default usage */
	asy->asy_mcr |= RTS|DTR;		/* do use RTS/DTR after open */
	asy->asy_lcr = STOP1|BITS8;		/* default to 1 stop 8 bits */
	asy->asy_bidx = B9600;			/* default to 9600  */
#ifdef DEBUG
	asy->asy_msint_cnt = 0;			/* # of times in async_msint */
#endif
	mcr = 0;				/* don't enable until open */

	if (asy->asy_com_port != 0) {
		/*
		 * For motherboard ports, emulate tty eeprom properties.
		 * Actually, we can't tell if a port is motherboard or not,
		 * so for "motherboard ports", read standard DOS COM ports.
		 */
		switch (asy_getproperty(devi, asy, "ignore-cd")) {
		case 0:				/* *-ignore-cd=False */
			DEBUGCONT1(ASY_DEBUG_MODEM,
			    "asy%dattach: clear ASY_IGNORE_CD\n", instance);
			asy->asy_flags &= ~ASY_IGNORE_CD; /* wait for cd */
			break;
		case 1:				/* *-ignore-cd=True */
			/*FALLTHRU*/
		default:			/* *-ignore-cd not defined */
			/*
			 * We set rather silly defaults of soft carrier on
			 * and DTR/RTS raised here because it might be that
			 * one of the motherboard ports is the system console.
			 */
			DEBUGCONT1(ASY_DEBUG_MODEM,
			    "asy%dattach: set ASY_IGNORE_CD, set RTS & DTR\n",
			    instance);
			mcr = asy->asy_mcr;		/* rts/dtr on */
			asy->asy_flags |= ASY_IGNORE_CD;	/* ignore cd */
			break;
		}

		/* Property for not raising DTR/RTS */
		switch (asy_getproperty(devi, asy, "rts-dtr-off")) {
		case 0:				/* *-rts-dtr-off=False */
			asy->asy_flags |= ASY_RTS_DTR_OFF;	/* OFF */
			mcr = asy->asy_mcr;		/* rts/dtr on */
			DEBUGCONT1(ASY_DEBUG_MODEM, "asy%dattach: "
			    "ASY_RTS_DTR_OFF set and DTR & RTS set\n",
			    instance);
			break;
		case 1:				/* *-rts-dtr-off=True */
			/*FALLTHRU*/
		default:			/* *-rts-dtr-off undefined */
			break;
		}

		/* Parse property for tty modes */
		asy_parse_mode(devi, asy);
	} else {
		DEBUGCONT1(ASY_DEBUG_MODEM,
		    "asy%dattach: clear ASY_IGNORE_CD, clear RTS & DTR\n",
		    instance);
		asy->asy_flags &= ~ASY_IGNORE_CD;	/* wait for cd */
	}

	/*
	 * Initialize the port with default settings.
	 */

	asy->asy_fifo_buf = 1;
	asy->asy_use_fifo = FIFO_OFF;

	/*
	 * Get icookie for mutexes initialization
	 */
	if ((ddi_get_iblock_cookie(devi, 0, &asy->asy_iblock) !=
	    DDI_SUCCESS) ||
	    (ddi_get_soft_iblock_cookie(devi, DDI_SOFTINT_MED,
	    &asy->asy_soft_iblock) != DDI_SUCCESS)) {
		ddi_regs_map_free(&asy->asy_iohandle);
		cmn_err(CE_CONT,
		    "asy%d: could not hook interrupt for UART @ %p\n",
		    instance, (void *)asy->asy_ioaddr);
		asy_soft_state_free(asy);
		return (DDI_FAILURE);
	}

	/*
	 * Initialize mutexes before accessing the hardware
	 */
	mutex_init(&asy->asy_soft_lock, NULL, MUTEX_DRIVER,
	    (void *)asy->asy_soft_iblock);
	mutex_init(&asy->asy_excl, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&asy->asy_excl_hi, NULL, MUTEX_DRIVER,
	    (void *)asy->asy_iblock);
	mutex_init(&asy->asy_soft_sr, NULL, MUTEX_DRIVER,
	    (void *)asy->asy_soft_iblock);
	mutex_enter(&asy->asy_excl);
	mutex_enter(&asy->asy_excl_hi);

	if (asy_identify_chip(devi, asy) != DDI_SUCCESS) {
		mutex_exit(&asy->asy_excl_hi);
		mutex_exit(&asy->asy_excl);
		mutex_destroy(&asy->asy_soft_lock);
		mutex_destroy(&asy->asy_excl);
		mutex_destroy(&asy->asy_excl_hi);
		mutex_destroy(&asy->asy_soft_sr);
		ddi_regs_map_free(&asy->asy_iohandle);
		cmn_err(CE_CONT, "!Cannot identify UART chip at %p\n",
		    (void *)asy->asy_ioaddr);
		asy_soft_state_free(asy);
		return (DDI_FAILURE);
	}

	/* disable all interrupts */
	ddi_put8(asy->asy_iohandle, asy->asy_ioaddr + ICR, 0);
	/* select baud rate generator */
	ddi_put8(asy->asy_iohandle, asy->asy_ioaddr + LCR, DLAB);
	/* Set the baud rate to 9600 */
	ddi_put8(asy->asy_iohandle, asy->asy_ioaddr + (DAT+DLL),
	    asyspdtab[asy->asy_bidx] & 0xff);
	ddi_put8(asy->asy_iohandle, asy->asy_ioaddr + (DAT+DLH),
	    (asyspdtab[asy->asy_bidx] >> 8) & 0xff);
	ddi_put8(asy->asy_iohandle, asy->asy_ioaddr + LCR, asy->asy_lcr);
	ddi_put8(asy->asy_iohandle, asy->asy_ioaddr + MCR, mcr);

	mutex_exit(&asy->asy_excl_hi);
	mutex_exit(&asy->asy_excl);

	/*
	 * Set up the other components of the asycom structure for this port.
	 */
	asy->asy_dip = devi;

	/*
	 * Install per instance software interrupt handler.
	 */
	if (ddi_add_softintr(devi, DDI_SOFTINT_MED,
	    &(asy->asy_softintr_id), NULL, 0, asysoftintr,
	    (caddr_t)asy) != DDI_SUCCESS) {
		mutex_destroy(&asy->asy_soft_lock);
		mutex_destroy(&asy->asy_excl);
		mutex_destroy(&asy->asy_excl_hi);
		ddi_regs_map_free(&asy->asy_iohandle);
		cmn_err(CE_CONT,
		    "Can not set soft interrupt for ASY driver\n");
		asy_soft_state_free(asy);
		return (DDI_FAILURE);
	}

	mutex_enter(&asy->asy_excl);
	mutex_enter(&asy->asy_excl_hi);

	/*
	 * Install interrupt handler for this device.
	 */
	if (ddi_add_intr(devi, 0, NULL, 0, asyintr,
	    (caddr_t)asy) != DDI_SUCCESS) {
		mutex_exit(&asy->asy_excl_hi);
		mutex_exit(&asy->asy_excl);
		ddi_remove_softintr(asy->asy_softintr_id);
		mutex_destroy(&asy->asy_soft_lock);
		mutex_destroy(&asy->asy_excl);
		mutex_destroy(&asy->asy_excl_hi);
		ddi_regs_map_free(&asy->asy_iohandle);
		cmn_err(CE_CONT,
		    "Can not set device interrupt for ASY driver\n");
		asy_soft_state_free(asy);
		return (DDI_FAILURE);
	}

	mutex_exit(&asy->asy_excl_hi);
	mutex_exit(&asy->asy_excl);

	asyinit(asy);	/* initialize the asyncline structure */

	/* create minor device nodes for this device */
	if (asy->asy_com_port != 0) {
		/*
		 * For DOS COM ports, add letter suffix so
		 * devfsadm can create correct link names.
		 */
		name[0] = asy->asy_com_port + 'a' - 1;
		name[1] = '\0';
	} else {
		/*
		 * asy port which isn't a standard DOS COM
		 * port gets a numeric name based on instance
		 */
		(void) snprintf(name, ASY_MINOR_LEN, "%d", instance);
	}
	status = ddi_create_minor_node(devi, name, S_IFCHR, instance,
	    asy->asy_com_port != 0 ? DDI_NT_SERIAL_MB : DDI_NT_SERIAL, NULL);
	if (status == DDI_SUCCESS) {
		(void) strcat(name, ",cu");
		status = ddi_create_minor_node(devi, name, S_IFCHR,
		    OUTLINE | instance,
		    asy->asy_com_port != 0 ? DDI_NT_SERIAL_MB_DO :
		    DDI_NT_SERIAL_DO, NULL);
	}

	if (status != DDI_SUCCESS) {
		struct asyncline *async = asy->asy_priv;

		ddi_remove_minor_node(devi, NULL);
		ddi_remove_intr(devi, 0, asy->asy_iblock);
		ddi_remove_softintr(asy->asy_softintr_id);
		mutex_destroy(&asy->asy_soft_lock);
		mutex_destroy(&asy->asy_excl);
		mutex_destroy(&asy->asy_excl_hi);
		cv_destroy(&async->async_flags_cv);
		ddi_regs_map_free(&asy->asy_iohandle);
		asy_soft_state_free(asy);
		return (DDI_FAILURE);
	}

	/*
	 * Fill in the polled I/O structure.
	 */
	asy->polledio.cons_polledio_version = CONSPOLLEDIO_V0;
	asy->polledio.cons_polledio_argument = (cons_polledio_arg_t)asy;
	asy->polledio.cons_polledio_putchar = asyputchar;
	asy->polledio.cons_polledio_getchar = asygetchar;
	asy->polledio.cons_polledio_ischar = asyischar;
	asy->polledio.cons_polledio_enter = NULL;
	asy->polledio.cons_polledio_exit = NULL;

	ddi_report_dev(devi);
	DEBUGCONT1(ASY_DEBUG_INIT, "asy%dattach: done\n", instance);
	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
asyinfo(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg,
    void **result)
{
	dev_t dev = (dev_t)arg;
	int instance, error;
	struct asycom *asy;

	instance = UNIT(dev);

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		asy = ddi_get_soft_state(asy_soft_state, instance);
		if ((asy == NULL) || (asy->asy_dip == NULL))
			error = DDI_FAILURE;
		else {
			*result = (void *) asy->asy_dip;
			error = DDI_SUCCESS;
		}
		break;
	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)(intptr_t)instance;
		error = DDI_SUCCESS;
		break;
	default:
		error = DDI_FAILURE;
	}
	return (error);
}

/* asy_getproperty -- walk through all name variants until we find a match */

static int
asy_getproperty(dev_info_t *devi, struct asycom *asy, const char *property)
{
	int len;
	int ret;
	char letter = asy->asy_com_port + 'a' - 1;	/* for ttya */
	char number = asy->asy_com_port + '0';		/* for COM1 */
	char val[40];
	char name[40];

	/* Property for ignoring DCD */
	(void) sprintf(name, "tty%c-%s", letter, property);
	len = sizeof (val);
	ret = GET_PROP(devi, name, DDI_PROP_CANSLEEP, val, &len);
	if (ret != DDI_PROP_SUCCESS) {
		(void) sprintf(name, "com%c-%s", number, property);
		len = sizeof (val);
		ret = GET_PROP(devi, name, DDI_PROP_CANSLEEP, val, &len);
	}
	if (ret != DDI_PROP_SUCCESS) {
		(void) sprintf(name, "tty0%c-%s", number, property);
		len = sizeof (val);
		ret = GET_PROP(devi, name, DDI_PROP_CANSLEEP, val, &len);
	}
	if (ret != DDI_PROP_SUCCESS) {
		(void) sprintf(name, "port-%c-%s", letter, property);
		len = sizeof (val);
		ret = GET_PROP(devi, name, DDI_PROP_CANSLEEP, val, &len);
	}
	if (ret != DDI_PROP_SUCCESS)
		return (-1);		/* property non-existant */
	if (val[0] == 'f' || val[0] == 'F' || val[0] == '0')
		return (0);		/* property false/0 */
	return (1);			/* property true/!0 */
}

/* asy_soft_state_free - local wrapper for ddi_soft_state_free(9F) */

static void
asy_soft_state_free(struct asycom *asy)
{
	mutex_enter(&asy_glob_lock);
	/* If we were the max_asy_instance, work out new value */
	if (asy->asy_unit == max_asy_instance) {
		while (--max_asy_instance >= 0) {
			if (ddi_get_soft_state(asy_soft_state,
			    max_asy_instance) != NULL)
				break;
		}
	}
	mutex_exit(&asy_glob_lock);

	if (asy->asy_priv != NULL) {
		kmem_free(asy->asy_priv, sizeof (struct asyncline));
		asy->asy_priv = NULL;
	}
	ddi_soft_state_free(asy_soft_state, asy->asy_unit);
}

static char *
asy_hw_name(struct asycom *asy)
{
	switch (asy->asy_hwtype) {
	case ASY8250A:
		return ("8250A/16450");
	case ASY16550:
		return ("16550");
	case ASY16550A:
		return ("16550A");
	case ASY16650:
		return ("16650");
	case ASY16750:
		return ("16750");
	default:
		DEBUGNOTE2(ASY_DEBUG_INIT,
		    "asy%d: asy_hw_name: unknown asy_hwtype: %d",
		    asy->asy_unit, asy->asy_hwtype);
		return ("?");
	}
}

static int
asy_identify_chip(dev_info_t *devi, struct asycom *asy)
{
	int ret;
	int mcr;
	dev_t dev;
	uint_t hwtype;

	if (asy_scr_test) {
		/* Check scratch register works. */

		/* write to scratch register */
		ddi_put8(asy->asy_iohandle, asy->asy_ioaddr + SCR, SCRTEST);
		/* make sure that pattern doesn't just linger on the bus */
		ddi_put8(asy->asy_iohandle, asy->asy_ioaddr + FIFOR, 0x00);
		/* read data back from scratch register */
		ret = ddi_get8(asy->asy_iohandle, asy->asy_ioaddr + SCR);
		if (ret != SCRTEST) {
			/*
			 * Scratch register not working.
			 * Probably not an async chip.
			 * 8250 and 8250B don't have scratch registers,
			 * but only worked in ancient PC XT's anyway.
			 */
			cmn_err(CE_CONT, "!asy%d: UART @ %p "
			    "scratch register: expected 0x5a, got 0x%02x\n",
			    asy->asy_unit, (void *)asy->asy_ioaddr, ret);
			return (DDI_FAILURE);
		}
	}
	/*
	 * Use 16550 fifo reset sequence specified in NS application
	 * note. Disable fifos until chip is initialized.
	 */
	ddi_put8(asy->asy_iohandle,
	    asy->asy_ioaddr + FIFOR, 0x00);	/* clear */
	ddi_put8(asy->asy_iohandle,
	    asy->asy_ioaddr + FIFOR, FIFO_ON);	/* enable */
	ddi_put8(asy->asy_iohandle,
	    asy->asy_ioaddr + FIFOR, FIFO_ON | FIFORXFLSH);
						/* reset */
	if (asymaxchip >= ASY16650 && asy_scr_test) {
		/*
		 * Reset 16650 enhanced regs also, in case we have one of these
		 */
		ddi_put8(asy->asy_iohandle, asy->asy_ioaddr + LCR,
		    EFRACCESS);
		ddi_put8(asy->asy_iohandle, asy->asy_ioaddr + EFR,
		    0);
		ddi_put8(asy->asy_iohandle, asy->asy_ioaddr + LCR,
		    STOP1|BITS8);
	}

	/*
	 * See what sort of FIFO we have.
	 * Try enabling it and see what chip makes of this.
	 */

	asy->asy_fifor = 0;
	asy->asy_hwtype = asymaxchip; /* just for asy_reset_fifo() */
	if (asymaxchip >= ASY16550A)
		asy->asy_fifor |=
		    FIFO_ON | FIFODMA | (asy_trig_level & 0xff);
	if (asymaxchip >= ASY16650)
		asy->asy_fifor |= FIFOEXTRA1 | FIFOEXTRA2;

	asy_reset_fifo(asy, FIFOTXFLSH | FIFORXFLSH);

	mcr = ddi_get8(asy->asy_iohandle, asy->asy_ioaddr + MCR);
	ret = ddi_get8(asy->asy_iohandle, asy->asy_ioaddr + ISR);
	DEBUGCONT4(ASY_DEBUG_CHIP,
	    "asy%d: probe fifo FIFOR=0x%02x ISR=0x%02x MCR=0x%02x\n",
	    asy->asy_unit, asy->asy_fifor | FIFOTXFLSH | FIFORXFLSH,
	    ret, mcr);
	switch (ret & 0xf0) {
	case 0x40:
		hwtype = ASY16550; /* 16550 with broken FIFO */
		asy->asy_fifor = 0;
		break;
	case 0xc0:
		hwtype = ASY16550A;
		asy->asy_fifo_buf = 16;
		asy->asy_use_fifo = FIFO_ON;
		asy->asy_fifor &= ~(FIFOEXTRA1 | FIFOEXTRA2);
		break;
	case 0xe0:
		hwtype = ASY16650;
		asy->asy_fifo_buf = 32;
		asy->asy_use_fifo = FIFO_ON;
		asy->asy_fifor &= ~(FIFOEXTRA1);
		break;
	case 0xf0:
		/*
		 * Note we get 0xff if chip didn't return us anything,
		 * e.g. if there's no chip there.
		 */
		if (ret == 0xff) {
			cmn_err(CE_CONT, "asy%d: UART @ %p "
			    "interrupt register: got 0xff\n",
			    asy->asy_unit, (void *)asy->asy_ioaddr);
			return (DDI_FAILURE);
		}
		/*FALLTHRU*/
	case 0xd0:
		hwtype = ASY16750;
		asy->asy_fifo_buf = 64;
		asy->asy_use_fifo = FIFO_ON;
		break;
	default:
		hwtype = ASY8250A; /* No FIFO */
		asy->asy_fifor = 0;
	}

	if (hwtype > asymaxchip) {
		cmn_err(CE_CONT, "asy%d: UART @ %p "
		    "unexpected probe result: "
		    "FIFOR=0x%02x ISR=0x%02x MCR=0x%02x\n",
		    asy->asy_unit, (void *)asy->asy_ioaddr,
		    asy->asy_fifor | FIFOTXFLSH | FIFORXFLSH, ret, mcr);
		return (DDI_FAILURE);
	}

	/*
	 * Now reset the FIFO operation appropriate for the chip type.
	 * Note we must call asy_reset_fifo() before any possible
	 * downgrade of the asy->asy_hwtype, or it may not disable
	 * the more advanced features we specifically want downgraded.
	 */
	asy_reset_fifo(asy, 0);
	asy->asy_hwtype = hwtype;

	/*
	 * Check for Exar/Startech ST16C650, which will still look like a
	 * 16550A until we enable its enhanced mode.
	 */
	if (asy->asy_hwtype == ASY16550A && asymaxchip >= ASY16650 &&
	    asy_scr_test) {
		/* Enable enhanced mode register access */
		ddi_put8(asy->asy_iohandle, asy->asy_ioaddr + LCR,
		    EFRACCESS);
		/* zero scratch register (not scratch register if enhanced) */
		ddi_put8(asy->asy_iohandle, asy->asy_ioaddr + SCR, 0);
		/* Disable enhanced mode register access */
		ddi_put8(asy->asy_iohandle, asy->asy_ioaddr + LCR,
		    STOP1|BITS8);
		/* read back scratch register */
		ret = ddi_get8(asy->asy_iohandle, asy->asy_ioaddr + SCR);
		if (ret == SCRTEST) {
			/* looks like we have an ST16650 -- enable it */
			ddi_put8(asy->asy_iohandle, asy->asy_ioaddr + LCR,
			    EFRACCESS);
			ddi_put8(asy->asy_iohandle, asy->asy_ioaddr + EFR,
			    ENHENABLE);
			ddi_put8(asy->asy_iohandle, asy->asy_ioaddr + LCR,
			    STOP1|BITS8);
			asy->asy_hwtype = ASY16650;
			asy->asy_fifo_buf = 32;
			asy->asy_fifor |= 0x10; /* 24 byte txfifo trigger */
			asy_reset_fifo(asy, 0);
		}
	}

	/*
	 * If we think we might have a FIFO larger than 16 characters,
	 * measure FIFO size and check it against expected.
	 */
	if (asy_fifo_test > 0 &&
	    !(asy->asy_flags2 & ASY2_NO_LOOPBACK) &&
	    (asy->asy_fifo_buf > 16 ||
	    (asy_fifo_test > 1 && asy->asy_use_fifo == FIFO_ON) ||
	    ASY_DEBUG(ASY_DEBUG_CHIP))) {
		int i;

		/* Set baud rate to 57600 (fairly arbitrary choice) */
		ddi_put8(asy->asy_iohandle, asy->asy_ioaddr + LCR,
		    DLAB);
		ddi_put8(asy->asy_iohandle, asy->asy_ioaddr + DAT,
		    asyspdtab[B57600] & 0xff);
		ddi_put8(asy->asy_iohandle, asy->asy_ioaddr + ICR,
		    (asyspdtab[B57600] >> 8) & 0xff);
		/* Set 8 bits, 1 stop bit */
		ddi_put8(asy->asy_iohandle, asy->asy_ioaddr + LCR,
		    STOP1|BITS8);
		/* Set loopback mode */
		ddi_put8(asy->asy_iohandle, asy->asy_ioaddr + MCR,
		    DTR | RTS | ASY_LOOP | OUT1 | OUT2);

		/* Overfill fifo */
		for (i = 0; i < asy->asy_fifo_buf * 2; i++) {
			ddi_put8(asy->asy_iohandle,
			    asy->asy_ioaddr + DAT, i);
		}
		/*
		 * Now there's an interesting question here about which
		 * FIFO we're testing the size of, RX or TX. We just
		 * filled the TX FIFO much faster than it can empty,
		 * although it is possible one or two characters may
		 * have gone from it to the TX shift register.
		 * We wait for enough time for all the characters to
		 * move into the RX FIFO and any excess characters to
		 * have been lost, and then read all the RX FIFO. So
		 * the answer we finally get will be the size which is
		 * the MIN(RX FIFO,(TX FIFO + 1 or 2)). The critical
		 * one is actually the TX FIFO, because if we overfill
		 * it in normal operation, the excess characters are
		 * lost with no warning.
		 */
		/*
		 * Wait for characters to move into RX FIFO.
		 * In theory, 200 * asy->asy_fifo_buf * 2 should be
		 * enough. However, in practice it isn't always, so we
		 * increase to 400 so some slow 16550A's finish, and we
		 * increase to 3 so we spot more characters coming back
		 * than we sent, in case that should ever happen.
		 */
		delay(drv_usectohz(400 * asy->asy_fifo_buf * 3));

		/* Now see how many characters we can read back */
		for (i = 0; i < asy->asy_fifo_buf * 3; i++) {
			ret = ddi_get8(asy->asy_iohandle,
			    asy->asy_ioaddr + LSR);
			if (!(ret & RCA))
				break;	/* FIFO emptied */
			(void) ddi_get8(asy->asy_iohandle,
			    asy->asy_ioaddr + DAT); /* lose another */
		}

		DEBUGCONT3(ASY_DEBUG_CHIP,
		    "asy%d FIFO size: expected=%d, measured=%d\n",
		    asy->asy_unit, asy->asy_fifo_buf, i);

		hwtype = asy->asy_hwtype;
		if (i < asy->asy_fifo_buf) {
			/*
			 * FIFO is somewhat smaller than we anticipated.
			 * If we have 16 characters usable, then this
			 * UART will probably work well enough in
			 * 16550A mode. If less than 16 characters,
			 * then we'd better not use it at all.
			 * UARTs with busted FIFOs do crop up.
			 */
			if (i >= 16 && asy->asy_fifo_buf >= 16) {
				/* fall back to a 16550A */
				hwtype = ASY16550A;
				asy->asy_fifo_buf = 16;
				asy->asy_fifor &= ~(FIFOEXTRA1 | FIFOEXTRA2);
			} else {
				/* fall back to no FIFO at all */
				hwtype = ASY16550;
				asy->asy_fifo_buf = 1;
				asy->asy_use_fifo = FIFO_OFF;
				asy->asy_fifor &=
				    ~(FIFO_ON | FIFOEXTRA1 | FIFOEXTRA2);
			}
		}
		/*
		 * We will need to reprogram the FIFO if we changed
		 * our mind about how to drive it above, and in any
		 * case, it would be a good idea to flush any garbage
		 * out incase the loopback test left anything behind.
		 * Again as earlier above, we must call asy_reset_fifo()
		 * before any possible downgrade of asy->asy_hwtype.
		 */
		if (asy->asy_hwtype >= ASY16650 && hwtype < ASY16650) {
			/* Disable 16650 enhanced mode */
			ddi_put8(asy->asy_iohandle, asy->asy_ioaddr + LCR,
			    EFRACCESS);
			ddi_put8(asy->asy_iohandle, asy->asy_ioaddr + EFR,
			    0);
			ddi_put8(asy->asy_iohandle, asy->asy_ioaddr + LCR,
			    STOP1|BITS8);
		}
		asy_reset_fifo(asy, FIFOTXFLSH | FIFORXFLSH);
		asy->asy_hwtype = hwtype;

		/* Clear loopback mode and restore DTR/RTS */
		ddi_put8(asy->asy_iohandle, asy->asy_ioaddr + MCR, mcr);
	}

	DEBUGNOTE3(ASY_DEBUG_CHIP, "asy%d %s @ %p",
	    asy->asy_unit, asy_hw_name(asy), (void *)asy->asy_ioaddr);

	/* Make UART type visible in device tree for prtconf, etc */
	dev = makedevice(DDI_MAJOR_T_UNKNOWN, asy->asy_unit);
	(void) ddi_prop_update_string(dev, devi, "uart", asy_hw_name(asy));

	if (asy->asy_hwtype == ASY16550)	/* for broken 16550's, */
		asy->asy_hwtype = ASY8250A;	/* drive them as 8250A */

	return (DDI_SUCCESS);
}

/*
 * asyinit() initializes the TTY protocol-private data for this channel
 * before enabling the interrupts.
 */
static void
asyinit(struct asycom *asy)
{
	struct asyncline *async;

	asy->asy_priv = kmem_zalloc(sizeof (struct asyncline), KM_SLEEP);
	async = asy->asy_priv;
	mutex_enter(&asy->asy_excl);
	async->async_common = asy;
	cv_init(&async->async_flags_cv, NULL, CV_DRIVER, NULL);
	mutex_exit(&asy->asy_excl);
}

/*ARGSUSED3*/
static int
asyopen(queue_t *rq, dev_t *dev, int flag, int sflag, cred_t *cr)
{
	struct asycom	*asy;
	struct asyncline *async;
	int		mcr;
	int		unit;
	int 		len;
	struct termios 	*termiosp;

	unit = UNIT(*dev);
	DEBUGCONT1(ASY_DEBUG_CLOSE, "asy%dopen\n", unit);
	asy = ddi_get_soft_state(asy_soft_state, unit);
	if (asy == NULL)
		return (ENXIO);		/* unit not configured */
	async = asy->asy_priv;
	mutex_enter(&asy->asy_excl);

again:
	mutex_enter(&asy->asy_excl_hi);

	/*
	 * Block waiting for carrier to come up, unless this is a no-delay open.
	 */
	if (!(async->async_flags & ASYNC_ISOPEN)) {
		/*
		 * Set the default termios settings (cflag).
		 * Others are set in ldterm.
		 */
		mutex_exit(&asy->asy_excl_hi);

		if (ddi_getlongprop(DDI_DEV_T_ANY, ddi_root_node(),
		    0, "ttymodes",
		    (caddr_t)&termiosp, &len) == DDI_PROP_SUCCESS &&
		    len == sizeof (struct termios)) {
			async->async_ttycommon.t_cflag = termiosp->c_cflag;
			kmem_free(termiosp, len);
		} else
			cmn_err(CE_WARN,
			    "asy: couldn't get ttymodes property!");
		mutex_enter(&asy->asy_excl_hi);

		/* eeprom mode support - respect properties */
		if (asy->asy_cflag)
			async->async_ttycommon.t_cflag = asy->asy_cflag;

		async->async_ttycommon.t_iflag = 0;
		async->async_ttycommon.t_iocpending = NULL;
		async->async_ttycommon.t_size.ws_row = 0;
		async->async_ttycommon.t_size.ws_col = 0;
		async->async_ttycommon.t_size.ws_xpixel = 0;
		async->async_ttycommon.t_size.ws_ypixel = 0;
		async->async_dev = *dev;
		async->async_wbufcid = 0;

		async->async_startc = CSTART;
		async->async_stopc = CSTOP;
		asy_program(asy, ASY_INIT);
	} else
		if ((async->async_ttycommon.t_flags & TS_XCLUDE) &&
		    secpolicy_excl_open(cr) != 0) {
		mutex_exit(&asy->asy_excl_hi);
		mutex_exit(&asy->asy_excl);
		return (EBUSY);
	} else if ((*dev & OUTLINE) && !(async->async_flags & ASYNC_OUT)) {
		mutex_exit(&asy->asy_excl_hi);
		mutex_exit(&asy->asy_excl);
		return (EBUSY);
	}

	if (*dev & OUTLINE)
		async->async_flags |= ASYNC_OUT;

	/* Raise DTR on every open, but delay if it was just lowered. */
	while (async->async_flags & ASYNC_DTR_DELAY) {
		DEBUGCONT1(ASY_DEBUG_MODEM,
		    "asy%dopen: waiting for the ASYNC_DTR_DELAY to be clear\n",
		    unit);
		mutex_exit(&asy->asy_excl_hi);
		if (cv_wait_sig(&async->async_flags_cv,
		    &asy->asy_excl) == 0) {
			DEBUGCONT1(ASY_DEBUG_MODEM,
			    "asy%dopen: interrupted by signal, exiting\n",
			    unit);
			mutex_exit(&asy->asy_excl);
			return (EINTR);
		}
		mutex_enter(&asy->asy_excl_hi);
	}

	mcr = ddi_get8(asy->asy_iohandle, asy->asy_ioaddr + MCR);
	ddi_put8(asy->asy_iohandle, asy->asy_ioaddr + MCR,
	    mcr|(asy->asy_mcr&DTR));

	DEBUGCONT3(ASY_DEBUG_INIT,
	    "asy%dopen: \"Raise DTR on every open\": make mcr = %x, "
	    "make TS_SOFTCAR = %s\n",
	    unit, mcr|(asy->asy_mcr&DTR),
	    (asy->asy_flags & ASY_IGNORE_CD) ? "ON" : "OFF");

	if (asy->asy_flags & ASY_IGNORE_CD) {
		DEBUGCONT1(ASY_DEBUG_MODEM,
		    "asy%dopen: ASY_IGNORE_CD set, set TS_SOFTCAR\n",
		    unit);
		async->async_ttycommon.t_flags |= TS_SOFTCAR;
	}
	else
		async->async_ttycommon.t_flags &= ~TS_SOFTCAR;

	/*
	 * Check carrier.
	 */
	asy->asy_msr = ddi_get8(asy->asy_iohandle, asy->asy_ioaddr + MSR);
	DEBUGCONT3(ASY_DEBUG_INIT, "asy%dopen: TS_SOFTCAR is %s, "
	    "MSR & DCD is %s\n",
	    unit,
	    (async->async_ttycommon.t_flags & TS_SOFTCAR) ? "set" : "clear",
	    (asy->asy_msr & DCD) ? "set" : "clear");

	if (asy->asy_msr & DCD)
		async->async_flags |= ASYNC_CARR_ON;
	else
		async->async_flags &= ~ASYNC_CARR_ON;
	mutex_exit(&asy->asy_excl_hi);

	/*
	 * If FNDELAY and FNONBLOCK are clear, block until carrier up.
	 * Quit on interrupt.
	 */
	if (!(flag & (FNDELAY|FNONBLOCK)) &&
	    !(async->async_ttycommon.t_cflag & CLOCAL)) {
		if ((!(async->async_flags & (ASYNC_CARR_ON|ASYNC_OUT)) &&
		    !(async->async_ttycommon.t_flags & TS_SOFTCAR)) ||
		    ((async->async_flags & ASYNC_OUT) &&
		    !(*dev & OUTLINE))) {
			async->async_flags |= ASYNC_WOPEN;
			if (cv_wait_sig(&async->async_flags_cv,
			    &asy->asy_excl) == B_FALSE) {
				async->async_flags &= ~ASYNC_WOPEN;
				mutex_exit(&asy->asy_excl);
				return (EINTR);
			}
			async->async_flags &= ~ASYNC_WOPEN;
			goto again;
		}
	} else if ((async->async_flags & ASYNC_OUT) && !(*dev & OUTLINE)) {
		mutex_exit(&asy->asy_excl);
		return (EBUSY);
	}

	async->async_ttycommon.t_readq = rq;
	async->async_ttycommon.t_writeq = WR(rq);
	rq->q_ptr = WR(rq)->q_ptr = (caddr_t)async;
	mutex_exit(&asy->asy_excl);
	/*
	 * Caution here -- qprocson sets the pointers that are used by canput
	 * called by async_softint.  ASYNC_ISOPEN must *not* be set until those
	 * pointers are valid.
	 */
	qprocson(rq);
	async->async_flags |= ASYNC_ISOPEN;
	async->async_polltid = 0;
	DEBUGCONT1(ASY_DEBUG_INIT, "asy%dopen: done\n", unit);
	return (0);
}

static void
async_progress_check(void *arg)
{
	struct asyncline *async = arg;
	struct asycom	 *asy = async->async_common;
	mblk_t *bp;

	/*
	 * We define "progress" as either waiting on a timed break or delay, or
	 * having had at least one transmitter interrupt.  If none of these are
	 * true, then just terminate the output and wake up that close thread.
	 */
	mutex_enter(&asy->asy_excl);
	mutex_enter(&asy->asy_excl_hi);
	if (!(async->async_flags & (ASYNC_BREAK|ASYNC_DELAY|ASYNC_PROGRESS))) {
		async->async_ocnt = 0;
		async->async_flags &= ~ASYNC_BUSY;
		async->async_timer = 0;
		bp = async->async_xmitblk;
		async->async_xmitblk = NULL;
		mutex_exit(&asy->asy_excl_hi);
		if (bp != NULL)
			freeb(bp);
		/*
		 * Since this timer is running, we know that we're in exit(2).
		 * That means that the user can't possibly be waiting on any
		 * valid ioctl(2) completion anymore, and we should just flush
		 * everything.
		 */
		flushq(async->async_ttycommon.t_writeq, FLUSHALL);
		cv_broadcast(&async->async_flags_cv);
	} else {
		async->async_flags &= ~ASYNC_PROGRESS;
		async->async_timer = timeout(async_progress_check, async,
		    drv_usectohz(asy_drain_check));
		mutex_exit(&asy->asy_excl_hi);
	}
	mutex_exit(&asy->asy_excl);
}

/*
 * Release DTR so that asyopen() can raise it.
 */
static void
async_dtr_free(struct asyncline *async)
{
	struct asycom *asy = async->async_common;

	DEBUGCONT0(ASY_DEBUG_MODEM,
	    "async_dtr_free, clearing ASYNC_DTR_DELAY\n");
	mutex_enter(&asy->asy_excl);
	async->async_flags &= ~ASYNC_DTR_DELAY;
	async->async_dtrtid = 0;
	cv_broadcast(&async->async_flags_cv);
	mutex_exit(&asy->asy_excl);
}

/*
 * Close routine.
 */
/*ARGSUSED2*/
static int
asyclose(queue_t *q, int flag, cred_t *credp)
{
	struct asyncline *async;
	struct asycom	 *asy;
	int icr, lcr;
#ifdef DEBUG
	int instance;
#endif

	async = (struct asyncline *)q->q_ptr;
	ASSERT(async != NULL);
#ifdef DEBUG
	instance = UNIT(async->async_dev);
	DEBUGCONT1(ASY_DEBUG_CLOSE, "asy%dclose\n", instance);
#endif
	asy = async->async_common;

	mutex_enter(&asy->asy_excl);
	async->async_flags |= ASYNC_CLOSING;

	/*
	 * Turn off PPS handling early to avoid events occuring during
	 * close.  Also reset the DCD edge monitoring bit.
	 */
	mutex_enter(&asy->asy_excl_hi);
	asy->asy_flags &= ~(ASY_PPS | ASY_PPS_EDGE);
	mutex_exit(&asy->asy_excl_hi);

	/*
	 * There are two flavors of break -- timed (M_BREAK or TCSBRK) and
	 * untimed (TIOCSBRK).  For the timed case, these are enqueued on our
	 * write queue and there's a timer running, so we don't have to worry
	 * about them.  For the untimed case, though, the user obviously made a
	 * mistake, because these are handled immediately.  We'll terminate the
	 * break now and honor their implicit request by discarding the rest of
	 * the data.
	 */
	if (async->async_flags & ASYNC_OUT_SUSPEND) {
		if (async->async_utbrktid != 0) {
			(void) untimeout(async->async_utbrktid);
			async->async_utbrktid = 0;
		}
		mutex_enter(&asy->asy_excl_hi);
		lcr = ddi_get8(asy->asy_iohandle, asy->asy_ioaddr + LCR);
		ddi_put8(asy->asy_iohandle,
		    asy->asy_ioaddr + LCR, (lcr & ~SETBREAK));
		mutex_exit(&asy->asy_excl_hi);
		async->async_flags &= ~ASYNC_OUT_SUSPEND;
		goto nodrain;
	}

	/*
	 * If the user told us not to delay the close ("non-blocking"), then
	 * don't bother trying to drain.
	 *
	 * If the user did M_STOP (ASYNC_STOPPED), there's no hope of ever
	 * getting an M_START (since these messages aren't enqueued), and the
	 * only other way to clear the stop condition is by loss of DCD, which
	 * would discard the queue data.  Thus, we drop the output data if
	 * ASYNC_STOPPED is set.
	 */
	if ((flag & (FNDELAY|FNONBLOCK)) ||
	    (async->async_flags & ASYNC_STOPPED)) {
		goto nodrain;
	}

	/*
	 * If there's any pending output, then we have to try to drain it.
	 * There are two main cases to be handled:
	 *	- called by close(2): need to drain until done or until
	 *	  a signal is received.  No timeout.
	 *	- called by exit(2): need to drain while making progress
	 *	  or until a timeout occurs.  No signals.
	 *
	 * If we can't rely on receiving a signal to get us out of a hung
	 * session, then we have to use a timer.  In this case, we set a timer
	 * to check for progress in sending the output data -- all that we ask
	 * (at each interval) is that there's been some progress made.  Since
	 * the interrupt routine grabs buffers from the write queue, we can't
	 * trust changes in async_ocnt.  Instead, we use a progress flag.
	 *
	 * Note that loss of carrier will cause the output queue to be flushed,
	 * and we'll wake up again and finish normally.
	 */
	if (!ddi_can_receive_sig() && asy_drain_check != 0) {
		async->async_flags &= ~ASYNC_PROGRESS;
		async->async_timer = timeout(async_progress_check, async,
		    drv_usectohz(asy_drain_check));
	}
	while (async->async_ocnt > 0 ||
	    async->async_ttycommon.t_writeq->q_first != NULL ||
	    (async->async_flags & (ASYNC_BUSY|ASYNC_BREAK|ASYNC_DELAY))) {
		if (cv_wait_sig(&async->async_flags_cv, &asy->asy_excl) == 0)
			break;
	}
	if (async->async_timer != 0) {
		(void) untimeout(async->async_timer);
		async->async_timer = 0;
	}

nodrain:
	async->async_ocnt = 0;
	if (async->async_xmitblk != NULL)
		freeb(async->async_xmitblk);
	async->async_xmitblk = NULL;

	/*
	 * If line has HUPCL set or is incompletely opened fix up the modem
	 * lines.
	 */
	DEBUGCONT1(ASY_DEBUG_MODEM, "asy%dclose: next check HUPCL flag\n",
	    instance);
	mutex_enter(&asy->asy_excl_hi);
	if ((async->async_ttycommon.t_cflag & HUPCL) ||
	    (async->async_flags & ASYNC_WOPEN)) {
		DEBUGCONT3(ASY_DEBUG_MODEM,
		    "asy%dclose: HUPCL flag = %x, ASYNC_WOPEN flag = %x\n",
		    instance,
		    async->async_ttycommon.t_cflag & HUPCL,
		    async->async_ttycommon.t_cflag & ASYNC_WOPEN);
		async->async_flags |= ASYNC_DTR_DELAY;

		/* turn off DTR, RTS but NOT interrupt to 386 */
		if (asy->asy_flags & (ASY_IGNORE_CD|ASY_RTS_DTR_OFF)) {
			DEBUGCONT3(ASY_DEBUG_MODEM,
			    "asy%dclose: ASY_IGNORE_CD flag = %x, "
			    "ASY_RTS_DTR_OFF flag = %x\n",
			    instance,
			    asy->asy_flags & ASY_IGNORE_CD,
			    asy->asy_flags & ASY_RTS_DTR_OFF);

			ddi_put8(asy->asy_iohandle, asy->asy_ioaddr + MCR,
			    asy->asy_mcr|OUT2);
		} else {
			DEBUGCONT1(ASY_DEBUG_MODEM,
			    "asy%dclose: Dropping DTR and RTS\n", instance);
			ddi_put8(asy->asy_iohandle, asy->asy_ioaddr + MCR,
			    OUT2);
		}
		async->async_dtrtid =
		    timeout((void (*)())async_dtr_free,
		    (caddr_t)async, drv_usectohz(asy_min_dtr_low));
	}
	/*
	 * If nobody's using it now, turn off receiver interrupts.
	 */
	if ((async->async_flags & (ASYNC_WOPEN|ASYNC_ISOPEN)) == 0) {
		icr = ddi_get8(asy->asy_iohandle, asy->asy_ioaddr + ICR);
		ddi_put8(asy->asy_iohandle, asy->asy_ioaddr + ICR,
		    (icr & ~RIEN));
	}
	mutex_exit(&asy->asy_excl_hi);
out:
	ttycommon_close(&async->async_ttycommon);

	/*
	 * Cancel outstanding "bufcall" request.
	 */
	if (async->async_wbufcid != 0) {
		unbufcall(async->async_wbufcid);
		async->async_wbufcid = 0;
	}

	/* Note that qprocsoff can't be done until after interrupts are off */
	qprocsoff(q);
	q->q_ptr = WR(q)->q_ptr = NULL;
	async->async_ttycommon.t_readq = NULL;
	async->async_ttycommon.t_writeq = NULL;

	/*
	 * Clear out device state, except persistant device property flags.
	 */
	async->async_flags &= (ASYNC_DTR_DELAY|ASY_RTS_DTR_OFF);
	cv_broadcast(&async->async_flags_cv);
	mutex_exit(&asy->asy_excl);

	DEBUGCONT1(ASY_DEBUG_CLOSE, "asy%dclose: done\n", instance);
	return (0);
}

static boolean_t
asy_isbusy(struct asycom *asy)
{
	struct asyncline *async;

	DEBUGCONT0(ASY_DEBUG_EOT, "asy_isbusy\n");
	async = asy->asy_priv;
	ASSERT(mutex_owned(&asy->asy_excl));
	ASSERT(mutex_owned(&asy->asy_excl_hi));
/*
 * XXXX this should be recoded
 */
	return ((async->async_ocnt > 0) ||
	    ((ddi_get8(asy->asy_iohandle,
	    asy->asy_ioaddr + LSR) & (XSRE|XHRE)) == 0));
}

static void
asy_waiteot(struct asycom *asy)
{
	/*
	 * Wait for the current transmission block and the
	 * current fifo data to transmit. Once this is done
	 * we may go on.
	 */
	DEBUGCONT0(ASY_DEBUG_EOT, "asy_waiteot\n");
	ASSERT(mutex_owned(&asy->asy_excl));
	ASSERT(mutex_owned(&asy->asy_excl_hi));
	while (asy_isbusy(asy)) {
		mutex_exit(&asy->asy_excl_hi);
		mutex_exit(&asy->asy_excl);
		drv_usecwait(10000);		/* wait .01 */
		mutex_enter(&asy->asy_excl);
		mutex_enter(&asy->asy_excl_hi);
	}
}

/* asy_reset_fifo -- flush fifos and [re]program fifo control register */
static void
asy_reset_fifo(struct asycom *asy, uchar_t flush)
{
	uchar_t lcr;

	/* On a 16750, we have to set DLAB in order to set FIFOEXTRA. */

	if (asy->asy_hwtype >= ASY16750) {
		lcr = ddi_get8(asy->asy_iohandle, asy->asy_ioaddr + LCR);
		ddi_put8(asy->asy_iohandle, asy->asy_ioaddr + LCR,
		    lcr | DLAB);
	}

	ddi_put8(asy->asy_iohandle, asy->asy_ioaddr + FIFOR,
	    asy->asy_fifor | flush);

	/* Clear DLAB */

	if (asy->asy_hwtype >= ASY16750) {
		ddi_put8(asy->asy_iohandle, asy->asy_ioaddr + LCR, lcr);
	}
}

/*
 * Program the ASY port. Most of the async operation is based on the values
 * of 'c_iflag' and 'c_cflag'.
 */

#define	BAUDINDEX(cflg)	(((cflg) & CBAUDEXT) ? \
			(((cflg) & CBAUD) + CBAUD + 1) : ((cflg) & CBAUD))

static void
asy_program(struct asycom *asy, int mode)
{
	struct asyncline *async;
	int baudrate, c_flag;
	int icr, lcr;
	int flush_reg;
	int ocflags;
#ifdef DEBUG
	int instance;
#endif

	ASSERT(mutex_owned(&asy->asy_excl));
	ASSERT(mutex_owned(&asy->asy_excl_hi));

	async = asy->asy_priv;
#ifdef DEBUG
	instance = UNIT(async->async_dev);
	DEBUGCONT2(ASY_DEBUG_PROCS,
	    "asy%d_program: mode = 0x%08X, enter\n", instance, mode);
#endif

	baudrate = BAUDINDEX(async->async_ttycommon.t_cflag);

	async->async_ttycommon.t_cflag &= ~(CIBAUD);

	if (baudrate > CBAUD) {
		async->async_ttycommon.t_cflag |= CIBAUDEXT;
		async->async_ttycommon.t_cflag |=
		    (((baudrate - CBAUD - 1) << IBSHIFT) & CIBAUD);
	} else {
		async->async_ttycommon.t_cflag &= ~CIBAUDEXT;
		async->async_ttycommon.t_cflag |=
		    ((baudrate << IBSHIFT) & CIBAUD);
	}

	c_flag = async->async_ttycommon.t_cflag &
	    (CLOCAL|CREAD|CSTOPB|CSIZE|PARENB|PARODD|CBAUD|CBAUDEXT);

	/* disable interrupts */
	ddi_put8(asy->asy_iohandle, asy->asy_ioaddr + ICR, 0);

	ocflags = asy->asy_ocflag;

	/* flush/reset the status registers */
	(void) ddi_get8(asy->asy_iohandle, asy->asy_ioaddr + ISR);
	(void) ddi_get8(asy->asy_iohandle, asy->asy_ioaddr + LSR);
	asy->asy_msr = flush_reg = ddi_get8(asy->asy_iohandle,
	    asy->asy_ioaddr + MSR);
	/*
	 * The device is programmed in the open sequence, if we
	 * have to hardware handshake, then this is a good time
	 * to check if the device can receive any data.
	 */

	if ((CRTSCTS & async->async_ttycommon.t_cflag) && !(flush_reg & CTS)) {
		async_flowcontrol_hw_output(asy, FLOW_STOP);
	} else {
		/*
		 * We can not use async_flowcontrol_hw_output(asy, FLOW_START)
		 * here, because if CRTSCTS is clear, we need clear
		 * ASYNC_HW_OUT_FLW bit.
		 */
		async->async_flags &= ~ASYNC_HW_OUT_FLW;
	}

	/*
	 * If IXON is not set, clear ASYNC_SW_OUT_FLW;
	 * If IXON is set, no matter what IXON flag is before this
	 * function call to asy_program,
	 * we will use the old ASYNC_SW_OUT_FLW status.
	 * Because of handling IXON in the driver, we also should re-calculate
	 * the value of ASYNC_OUT_FLW_RESUME bit, but in fact,
	 * the TCSET* commands which call asy_program
	 * are put into the write queue, so there is no output needed to
	 * be resumed at this point.
	 */
	if (!(IXON & async->async_ttycommon.t_iflag))
		async->async_flags &= ~ASYNC_SW_OUT_FLW;

	/* manually flush receive buffer or fifo (workaround for buggy fifos) */
	if (mode == ASY_INIT)
		if (asy->asy_use_fifo == FIFO_ON) {
			for (flush_reg = asy->asy_fifo_buf; flush_reg-- > 0; ) {
				(void) ddi_get8(asy->asy_iohandle,
				    asy->asy_ioaddr + DAT);
			}
		} else {
			flush_reg = ddi_get8(asy->asy_iohandle,
			    asy->asy_ioaddr + DAT);
		}

	if (ocflags != (c_flag & ~CLOCAL) || mode == ASY_INIT) {
		/* Set line control */
		lcr = ddi_get8(asy->asy_iohandle, asy->asy_ioaddr + LCR);
		lcr &= ~(WLS0|WLS1|STB|PEN|EPS);

		if (c_flag & CSTOPB)
			lcr |= STB;	/* 2 stop bits */

		if (c_flag & PARENB)
			lcr |= PEN;

		if ((c_flag & PARODD) == 0)
			lcr |= EPS;

		switch (c_flag & CSIZE) {
		case CS5:
			lcr |= BITS5;
			break;
		case CS6:
			lcr |= BITS6;
			break;
		case CS7:
			lcr |= BITS7;
			break;
		case CS8:
			lcr |= BITS8;
			break;
		}

		/* set the baud rate, unless it is "0" */
		ddi_put8(asy->asy_iohandle, asy->asy_ioaddr + LCR, DLAB);

		if (baudrate != 0) {
			ddi_put8(asy->asy_iohandle, asy->asy_ioaddr + DAT,
			    asyspdtab[baudrate] & 0xff);
			ddi_put8(asy->asy_iohandle, asy->asy_ioaddr + ICR,
			    (asyspdtab[baudrate] >> 8) & 0xff);
		}
		/* set the line control modes */
		ddi_put8(asy->asy_iohandle, asy->asy_ioaddr + LCR, lcr);

		/*
		 * If we have a FIFO buffer, enable/flush
		 * at intialize time, flush if transitioning from
		 * CREAD off to CREAD on.
		 */
		if ((ocflags & CREAD) == 0 && (c_flag & CREAD) ||
		    mode == ASY_INIT)
			if (asy->asy_use_fifo == FIFO_ON)
				asy_reset_fifo(asy, FIFORXFLSH);

		/* remember the new cflags */
		asy->asy_ocflag = c_flag & ~CLOCAL;
	}

	if (baudrate == 0)
		ddi_put8(asy->asy_iohandle, asy->asy_ioaddr + MCR,
		    (asy->asy_mcr & RTS) | OUT2);
	else
		ddi_put8(asy->asy_iohandle, asy->asy_ioaddr + MCR,
		    asy->asy_mcr | OUT2);

	/*
	 * Call the modem status interrupt handler to check for the carrier
	 * in case CLOCAL was turned off after the carrier came on.
	 * (Note: Modem status interrupt is not enabled if CLOCAL is ON.)
	 */
	async_msint(asy);

	/* Set interrupt control */
	DEBUGCONT3(ASY_DEBUG_MODM2,
	    "asy%d_program: c_flag & CLOCAL = %x t_cflag & CRTSCTS = %x\n",
	    instance, c_flag & CLOCAL,
	    async->async_ttycommon.t_cflag & CRTSCTS);

	if ((c_flag & CLOCAL) && !(async->async_ttycommon.t_cflag & CRTSCTS))
		/*
		 * direct-wired line ignores DCD, so we don't enable modem
		 * status interrupts.
		 */
		icr = (TIEN | SIEN);
	else
		icr = (TIEN | SIEN | MIEN);

	if (c_flag & CREAD)
		icr |= RIEN;

	ddi_put8(asy->asy_iohandle, asy->asy_ioaddr + ICR, icr);
	DEBUGCONT1(ASY_DEBUG_PROCS, "asy%d_program: done\n", instance);
}

static boolean_t
asy_baudok(struct asycom *asy)
{
	struct asyncline *async = asy->asy_priv;
	int baudrate;


	baudrate = BAUDINDEX(async->async_ttycommon.t_cflag);

	if (baudrate >= sizeof (asyspdtab)/sizeof (*asyspdtab))
		return (0);

	return (baudrate == 0 || asyspdtab[baudrate]);
}

/*
 * asyintr() is the High Level Interrupt Handler.
 *
 * There are four different interrupt types indexed by ISR register values:
 *		0: modem
 *		1: Tx holding register is empty, ready for next char
 *		2: Rx register now holds a char to be picked up
 *		3: error or break on line
 * This routine checks the Bit 0 (interrupt-not-pending) to determine if
 * the interrupt is from this port.
 */
uint_t
asyintr(caddr_t argasy)
{
	struct asycom		*asy = (struct asycom *)argasy;
	struct asyncline	*async;
	int			ret_status = DDI_INTR_UNCLAIMED;
	uchar_t			interrupt_id, lsr;

	interrupt_id = ddi_get8(asy->asy_iohandle,
	    asy->asy_ioaddr + ISR) & 0x0F;
	async = asy->asy_priv;

	if ((async == NULL) ||
	    !(async->async_flags & (ASYNC_ISOPEN|ASYNC_WOPEN))) {
		if (interrupt_id & NOINTERRUPT)
			return (DDI_INTR_UNCLAIMED);
		else {
			/*
			 * reset the device by:
			 *	reading line status
			 *	reading any data from data status register
			 *	reading modem status
			 */
			(void) ddi_get8(asy->asy_iohandle,
			    asy->asy_ioaddr + LSR);
			(void) ddi_get8(asy->asy_iohandle,
			    asy->asy_ioaddr + DAT);
			asy->asy_msr = ddi_get8(asy->asy_iohandle,
			    asy->asy_ioaddr + MSR);
			return (DDI_INTR_CLAIMED);
		}
	}

	mutex_enter(&asy->asy_excl_hi);

	if (asy->asy_flags & ASY_DDI_SUSPENDED) {
		mutex_exit(&asy->asy_excl_hi);
		return (DDI_INTR_CLAIMED);
	}

	/*
	 * We will loop until the interrupt line is pulled low. asy
	 * interrupt is edge triggered.
	 */
	/* CSTYLED */
	for (;; interrupt_id =
	    (ddi_get8(asy->asy_iohandle, asy->asy_ioaddr + ISR) & 0x0F)) {

		if (interrupt_id & NOINTERRUPT)
			break;
		ret_status = DDI_INTR_CLAIMED;

		DEBUGCONT1(ASY_DEBUG_INTR, "asyintr: interrupt_id = 0x%d\n",
		    interrupt_id);
		lsr = ddi_get8(asy->asy_iohandle, asy->asy_ioaddr + LSR);
		switch (interrupt_id) {
		case RxRDY:
		case RSTATUS:
		case FFTMOUT:
			/* receiver interrupt or receiver errors */
			async_rxint(asy, lsr);
			break;
		case TxRDY:
			/* transmit interrupt */
			async_txint(asy);
			continue;
		case MSTATUS:
			/* modem status interrupt */
			async_msint(asy);
			break;
		}
		if ((lsr & XHRE) && (async->async_flags & ASYNC_BUSY) &&
		    (async->async_ocnt > 0))
			async_txint(asy);
	}
	mutex_exit(&asy->asy_excl_hi);
	return (ret_status);
}

/*
 * Transmitter interrupt service routine.
 * If there is more data to transmit in the current pseudo-DMA block,
 * send the next character if output is not stopped or draining.
 * Otherwise, queue up a soft interrupt.
 *
 * XXX -  Needs review for HW FIFOs.
 */
static void
async_txint(struct asycom *asy)
{
	struct asyncline *async = asy->asy_priv;
	int		fifo_len;

	/*
	 * If ASYNC_BREAK or ASYNC_OUT_SUSPEND has been set, return to
	 * asyintr()'s context to claim the interrupt without performing
	 * any action. No character will be loaded into FIFO/THR until
	 * timed or untimed break is removed
	 */
	if (async->async_flags & (ASYNC_BREAK|ASYNC_OUT_SUSPEND))
		return;

	fifo_len = asy->asy_fifo_buf; /* with FIFO buffers */
	if (fifo_len > asy_max_tx_fifo)
		fifo_len = asy_max_tx_fifo;

	if (async_flowcontrol_sw_input(asy, FLOW_CHECK, IN_FLOW_NULL))
		fifo_len--;

	if (async->async_ocnt > 0 && fifo_len > 0 &&
	    !(async->async_flags &
	    (ASYNC_HW_OUT_FLW|ASYNC_SW_OUT_FLW|ASYNC_STOPPED))) {
		while (fifo_len-- > 0 && async->async_ocnt-- > 0) {
			ddi_put8(asy->asy_iohandle,
			    asy->asy_ioaddr + DAT, *async->async_optr++);
		}
		async->async_flags |= ASYNC_PROGRESS;
	}

	if (fifo_len <= 0)
		return;

	ASYSETSOFT(asy);
}

/*
 * Interrupt on port: handle PPS event.  This function is only called
 * for a port on which PPS event handling has been enabled.
 */
static void
asy_ppsevent(struct asycom *asy, int msr)
{
	if (asy->asy_flags & ASY_PPS_EDGE) {
		/* Have seen leading edge, now look for and record drop */
		if ((msr & DCD) == 0)
			asy->asy_flags &= ~ASY_PPS_EDGE;
		/*
		 * Waiting for leading edge, look for rise; stamp event and
		 * calibrate kernel clock.
		 */
	} else if (msr & DCD) {
			/*
			 * This code captures a timestamp at the designated
			 * transition of the PPS signal (DCD asserted).  The
			 * code provides a pointer to the timestamp, as well
			 * as the hardware counter value at the capture.
			 *
			 * Note: the kernel has nano based time values while
			 * NTP requires micro based, an in-line fast algorithm
			 * to convert nsec to usec is used here -- see hrt2ts()
			 * in common/os/timers.c for a full description.
			 */
			struct timeval *tvp = &asy_ppsev.tv;
			timestruc_t ts;
			long nsec, usec;

			asy->asy_flags |= ASY_PPS_EDGE;
			LED_OFF;
			gethrestime(&ts);
			LED_ON;
			nsec = ts.tv_nsec;
			usec = nsec + (nsec >> 2);
			usec = nsec + (usec >> 1);
			usec = nsec + (usec >> 2);
			usec = nsec + (usec >> 4);
			usec = nsec - (usec >> 3);
			usec = nsec + (usec >> 2);
			usec = nsec + (usec >> 3);
			usec = nsec + (usec >> 4);
			usec = nsec + (usec >> 1);
			usec = nsec + (usec >> 6);
			tvp->tv_usec = usec >> 10;
			tvp->tv_sec = ts.tv_sec;

			++asy_ppsev.serial;

			/*
			 * Because the kernel keeps a high-resolution time,
			 * pass the current highres timestamp in tvp and zero
			 * in usec.
			 */
			ddi_hardpps(tvp, 0);
	}
}

/*
 * Receiver interrupt: RxRDY interrupt, FIFO timeout interrupt or receive
 * error interrupt.
 * Try to put the character into the circular buffer for this line; if it
 * overflows, indicate a circular buffer overrun. If this port is always
 * to be serviced immediately, or the character is a STOP character, or
 * more than 15 characters have arrived, queue up a soft interrupt to
 * drain the circular buffer.
 * XXX - needs review for hw FIFOs support.
 */

static void
async_rxint(struct asycom *asy, uchar_t lsr)
{
	struct asyncline *async = asy->asy_priv;
	uchar_t c;
	uint_t s, needsoft = 0;
	tty_common_t *tp;
	int looplim = asy->asy_fifo_buf * 2;

	tp = &async->async_ttycommon;
	if (!(tp->t_cflag & CREAD)) {
		while (lsr & (RCA|PARERR|FRMERR|BRKDET|OVRRUN)) {
			(void) (ddi_get8(asy->asy_iohandle,
			    asy->asy_ioaddr + DAT) & 0xff);
			lsr = ddi_get8(asy->asy_iohandle,
			    asy->asy_ioaddr + LSR);
			if (looplim-- < 0)		/* limit loop */
				break;
		}
		return; /* line is not open for read? */
	}

	while (lsr & (RCA|PARERR|FRMERR|BRKDET|OVRRUN)) {
		c = 0;
		s = 0;				/* reset error status */
		if (lsr & RCA) {
			c = ddi_get8(asy->asy_iohandle,
			    asy->asy_ioaddr + DAT) & 0xff;

			/*
			 * We handle XON/XOFF char if IXON is set,
			 * but if received char is _POSIX_VDISABLE,
			 * we left it to the up level module.
			 */
			if (tp->t_iflag & IXON) {
				if ((c == async->async_stopc) &&
				    (c != _POSIX_VDISABLE)) {
					async_flowcontrol_sw_output(asy,
					    FLOW_STOP);
					goto check_looplim;
				} else if ((c == async->async_startc) &&
				    (c != _POSIX_VDISABLE)) {
					async_flowcontrol_sw_output(asy,
					    FLOW_START);
					needsoft = 1;
					goto check_looplim;
				}
				if ((tp->t_iflag & IXANY) &&
				    (async->async_flags & ASYNC_SW_OUT_FLW)) {
					async_flowcontrol_sw_output(asy,
					    FLOW_START);
					needsoft = 1;
				}
			}
		}

		/*
		 * Check for character break sequence
		 */
		if ((abort_enable == KIOCABORTALTERNATE) &&
		    (asy->asy_flags & ASY_CONSOLE)) {
			if (abort_charseq_recognize(c))
				abort_sequence_enter((char *)NULL);
		}

		/* Handle framing errors */
		if (lsr & (PARERR|FRMERR|BRKDET|OVRRUN)) {
			if (lsr & PARERR) {
				if (tp->t_iflag & INPCK) /* parity enabled */
					s |= PERROR;
			}

			if (lsr & (FRMERR|BRKDET))
				s |= FRERROR;
			if (lsr & OVRRUN) {
				async->async_hw_overrun = 1;
				s |= OVERRUN;
			}
		}

		if (s == 0)
			if ((tp->t_iflag & PARMRK) &&
			    !(tp->t_iflag & (IGNPAR|ISTRIP)) &&
			    (c == 0377))
				if (RING_POK(async, 2)) {
					RING_PUT(async, 0377);
					RING_PUT(async, c);
				} else
					async->async_sw_overrun = 1;
			else
				if (RING_POK(async, 1))
					RING_PUT(async, c);
				else
					async->async_sw_overrun = 1;
		else
			if (s & FRERROR) /* Handle framing errors */
				if (c == 0)
					if ((asy->asy_flags & ASY_CONSOLE) &&
					    (abort_enable !=
					    KIOCABORTALTERNATE))
						abort_sequence_enter((char *)0);
					else
						async->async_break++;
				else
					if (RING_POK(async, 1))
						RING_MARK(async, c, s);
					else
						async->async_sw_overrun = 1;
			else /* Parity errors are handled by ldterm */
				if (RING_POK(async, 1))
					RING_MARK(async, c, s);
				else
					async->async_sw_overrun = 1;
check_looplim:
		lsr = ddi_get8(asy->asy_iohandle, asy->asy_ioaddr + LSR);
		if (looplim-- < 0)		/* limit loop */
			break;
	}
	if ((RING_CNT(async) > (RINGSIZE * 3)/4) &&
	    !(async->async_inflow_source & IN_FLOW_RINGBUFF)) {
		async_flowcontrol_hw_input(asy, FLOW_STOP, IN_FLOW_RINGBUFF);
		(void) async_flowcontrol_sw_input(asy, FLOW_STOP,
		    IN_FLOW_RINGBUFF);
	}

	if ((async->async_flags & ASYNC_SERVICEIMM) || needsoft ||
	    (RING_FRAC(async)) || (async->async_polltid == 0))
		ASYSETSOFT(asy);	/* need a soft interrupt */
}

/*
 * Modem status interrupt.
 *
 * (Note: It is assumed that the MSR hasn't been read by asyintr().)
 */

static void
async_msint(struct asycom *asy)
{
	struct asyncline *async = asy->asy_priv;
	int msr, t_cflag = async->async_ttycommon.t_cflag;
#ifdef DEBUG
	int instance = UNIT(async->async_dev);
#endif

async_msint_retry:
	/* this resets the interrupt */
	msr = ddi_get8(asy->asy_iohandle, asy->asy_ioaddr + MSR);
	DEBUGCONT10(ASY_DEBUG_STATE,
	    "async%d_msint call #%d:\n"
	    "   transition: %3s %3s %3s %3s\n"
	    "current state: %3s %3s %3s %3s\n",
	    instance,
	    ++(asy->asy_msint_cnt),
	    (msr & DCTS) ? "DCTS" : "    ",
	    (msr & DDSR) ? "DDSR" : "    ",
	    (msr & DRI)  ? "DRI " : "    ",
	    (msr & DDCD) ? "DDCD" : "    ",
	    (msr & CTS)  ? "CTS " : "    ",
	    (msr & DSR)  ? "DSR " : "    ",
	    (msr & RI)   ? "RI  " : "    ",
	    (msr & DCD)  ? "DCD " : "    ");

	/* If CTS status is changed, do H/W output flow control */
	if ((t_cflag & CRTSCTS) && (((asy->asy_msr ^ msr) & CTS) != 0))
		async_flowcontrol_hw_output(asy,
		    msr & CTS ? FLOW_START : FLOW_STOP);
	/*
	 * Reading MSR resets the interrupt, we save the
	 * value of msr so that other functions could examine MSR by
	 * looking at asy_msr.
	 */
	asy->asy_msr = (uchar_t)msr;

	/* Handle PPS event */
	if (asy->asy_flags & ASY_PPS)
		asy_ppsevent(asy, msr);

	async->async_ext++;
	ASYSETSOFT(asy);
	/*
	 * We will make sure that the modem status presented to us
	 * during the previous read has not changed. If the chip samples
	 * the modem status on the falling edge of the interrupt line,
	 * and uses this state as the base for detecting change of modem
	 * status, we would miss a change of modem status event that occured
	 * after we initiated a read MSR operation.
	 */
	msr = ddi_get8(asy->asy_iohandle, asy->asy_ioaddr + MSR);
	if (STATES(msr) != STATES(asy->asy_msr))
		goto	async_msint_retry;
}

/*
 * Handle a second-stage interrupt.
 */
/*ARGSUSED*/
uint_t
asysoftintr(caddr_t intarg)
{
	struct asycom *asy = (struct asycom *)intarg;
	struct asyncline *async;
	int rv;
	uint_t cc;

	/*
	 * Test and clear soft interrupt.
	 */
	mutex_enter(&asy->asy_soft_lock);
	DEBUGCONT0(ASY_DEBUG_PROCS, "asysoftintr: enter\n");
	rv = asy->asysoftpend;
	if (rv != 0)
		asy->asysoftpend = 0;
	mutex_exit(&asy->asy_soft_lock);

	if (rv) {
		if (asy->asy_priv == NULL)
			return (rv ? DDI_INTR_CLAIMED : DDI_INTR_UNCLAIMED);
		async = (struct asyncline *)asy->asy_priv;
		mutex_enter(&asy->asy_excl_hi);
		if (asy->asy_flags & ASY_NEEDSOFT) {
			asy->asy_flags &= ~ASY_NEEDSOFT;
			mutex_exit(&asy->asy_excl_hi);
			async_softint(asy);
			mutex_enter(&asy->asy_excl_hi);
		}

		/*
		 * There are some instances where the softintr is not
		 * scheduled and hence not called. It so happens that
		 * causes the last few characters to be stuck in the
		 * ringbuffer. Hence, call the handler once again so
		 * the last few characters are cleared.
		 */
		cc = RING_CNT(async);
		mutex_exit(&asy->asy_excl_hi);
		if (cc > 0)
			(void) async_softint(asy);
	}
	return (rv ? DDI_INTR_CLAIMED : DDI_INTR_UNCLAIMED);
}

/*
 * Handle a software interrupt.
 */
static void
async_softint(struct asycom *asy)
{
	struct asyncline *async = asy->asy_priv;
	uint_t	cc;
	mblk_t	*bp;
	queue_t	*q;
	uchar_t	val;
	uchar_t	c;
	tty_common_t	*tp;
	int nb;
	int instance = UNIT(async->async_dev);

	DEBUGCONT1(ASY_DEBUG_PROCS, "async%d_softint\n", instance);
	mutex_enter(&asy->asy_excl_hi);
	if (asy->asy_flags & ASY_DOINGSOFT) {
		asy->asy_flags |= ASY_DOINGSOFT_RETRY;
		mutex_exit(&asy->asy_excl_hi);
		return;
	}
	asy->asy_flags |= ASY_DOINGSOFT;
begin:
	asy->asy_flags &= ~ASY_DOINGSOFT_RETRY;
	mutex_exit(&asy->asy_excl_hi);
	mutex_enter(&asy->asy_excl);
	tp = &async->async_ttycommon;
	q = tp->t_readq;
	if (async->async_flags & ASYNC_OUT_FLW_RESUME) {
		if (async->async_ocnt > 0) {
			mutex_enter(&asy->asy_excl_hi);
			async_resume(async);
			mutex_exit(&asy->asy_excl_hi);
		} else {
			if (async->async_xmitblk)
				freeb(async->async_xmitblk);
			async->async_xmitblk = NULL;
			async_start(async);
		}
		async->async_flags &= ~ASYNC_OUT_FLW_RESUME;
	}
	mutex_enter(&asy->asy_excl_hi);
	if (async->async_ext) {
		async->async_ext = 0;
		/* check for carrier up */
		DEBUGCONT3(ASY_DEBUG_MODM2,
		    "async%d_softint: asy_msr & DCD = %x, "
		    "tp->t_flags & TS_SOFTCAR = %x\n",
		    instance, asy->asy_msr & DCD, tp->t_flags & TS_SOFTCAR);

		if (asy->asy_msr & DCD) {
			/* carrier present */
			if ((async->async_flags & ASYNC_CARR_ON) == 0) {
				DEBUGCONT1(ASY_DEBUG_MODM2,
				    "async%d_softint: set ASYNC_CARR_ON\n",
				    instance);
				async->async_flags |= ASYNC_CARR_ON;
				if (async->async_flags & ASYNC_ISOPEN) {
					mutex_exit(&asy->asy_excl_hi);
					mutex_exit(&asy->asy_excl);
					(void) putctl(q, M_UNHANGUP);
					mutex_enter(&asy->asy_excl);
					mutex_enter(&asy->asy_excl_hi);
				}
				cv_broadcast(&async->async_flags_cv);
			}
		} else {
			if ((async->async_flags & ASYNC_CARR_ON) &&
			    !(tp->t_cflag & CLOCAL) &&
			    !(tp->t_flags & TS_SOFTCAR)) {
				int flushflag;

				DEBUGCONT1(ASY_DEBUG_MODEM,
				    "async%d_softint: carrier dropped, "
				    "so drop DTR\n",
				    instance);
				/*
				 * Carrier went away.
				 * Drop DTR, abort any output in
				 * progress, indicate that output is
				 * not stopped, and send a hangup
				 * notification upstream.
				 */
				val = ddi_get8(asy->asy_iohandle,
				    asy->asy_ioaddr + MCR);
				ddi_put8(asy->asy_iohandle,
				    asy->asy_ioaddr + MCR, (val & ~DTR));

				if (async->async_flags & ASYNC_BUSY) {
					DEBUGCONT0(ASY_DEBUG_BUSY,
					    "async_softint: "
					    "Carrier dropped.  "
					    "Clearing async_ocnt\n");
					async->async_ocnt = 0;
				}	/* if */

				async->async_flags &= ~ASYNC_STOPPED;
				if (async->async_flags & ASYNC_ISOPEN) {
					mutex_exit(&asy->asy_excl_hi);
					mutex_exit(&asy->asy_excl);
					(void) putctl(q, M_HANGUP);
					mutex_enter(&asy->asy_excl);
					DEBUGCONT1(ASY_DEBUG_MODEM,
					    "async%d_softint: "
					    "putctl(q, M_HANGUP)\n",
					    instance);
					/*
					 * Flush FIFO buffers
					 * Any data left in there is invalid now
					 */
					if (asy->asy_use_fifo == FIFO_ON)
						asy_reset_fifo(asy, FIFOTXFLSH);
					/*
					 * Flush our write queue if we have one.
					 * If we're in the midst of close, then
					 * flush everything. Don't leave stale
					 * ioctls lying about.
					 */
					flushflag = (async->async_flags &
					    ASYNC_CLOSING) ? FLUSHALL :
					    FLUSHDATA;
					flushq(tp->t_writeq, flushflag);

					/* active msg */
					bp = async->async_xmitblk;
					if (bp != NULL) {
						freeb(bp);
						async->async_xmitblk = NULL;
					}

					mutex_enter(&asy->asy_excl_hi);
					async->async_flags &= ~ASYNC_BUSY;
					/*
					 * This message warns of Carrier loss
					 * with data left to transmit can hang
					 * the system.
					 */
					DEBUGCONT0(ASY_DEBUG_MODEM,
					    "async_softint: Flushing to "
					    "prevent HUPCL hanging\n");
				}	/* if (ASYNC_ISOPEN) */
			}	/* if (ASYNC_CARR_ON && CLOCAL) */
			async->async_flags &= ~ASYNC_CARR_ON;
			cv_broadcast(&async->async_flags_cv);
		}	/* else */
	}	/* if (async->async_ext) */

	mutex_exit(&asy->asy_excl_hi);

	/*
	 * If data has been added to the circular buffer, remove
	 * it from the buffer, and send it up the stream if there's
	 * somebody listening. Try to do it 16 bytes at a time. If we
	 * have more than 16 bytes to move, move 16 byte chunks and
	 * leave the rest for next time around (maybe it will grow).
	 */
	mutex_enter(&asy->asy_excl_hi);
	if (!(async->async_flags & ASYNC_ISOPEN)) {
		RING_INIT(async);
		goto rv;
	}
	if ((cc = RING_CNT(async)) == 0)
		goto rv;
	mutex_exit(&asy->asy_excl_hi);

	if (!canput(q)) {
		mutex_enter(&asy->asy_excl_hi);
		if (!(async->async_inflow_source & IN_FLOW_STREAMS)) {
			async_flowcontrol_hw_input(asy, FLOW_STOP,
			    IN_FLOW_STREAMS);
			(void) async_flowcontrol_sw_input(asy, FLOW_STOP,
			    IN_FLOW_STREAMS);
		}
		goto rv;
	}
	if (async->async_inflow_source & IN_FLOW_STREAMS) {
		mutex_enter(&asy->asy_excl_hi);
		async_flowcontrol_hw_input(asy, FLOW_START,
		    IN_FLOW_STREAMS);
		(void) async_flowcontrol_sw_input(asy, FLOW_START,
		    IN_FLOW_STREAMS);
		mutex_exit(&asy->asy_excl_hi);
	}

	DEBUGCONT2(ASY_DEBUG_INPUT, "async%d_softint: %d char(s) in queue.\n",
	    instance, cc);

	if (!(bp = allocb(cc, BPRI_MED))) {
		mutex_exit(&asy->asy_excl);
		ttycommon_qfull(&async->async_ttycommon, q);
		mutex_enter(&asy->asy_excl);
		mutex_enter(&asy->asy_excl_hi);
		goto rv;
	}
	mutex_enter(&asy->asy_excl_hi);
	do {
		if (RING_ERR(async, S_ERRORS)) {
			RING_UNMARK(async);
			c = RING_GET(async);
			break;
		} else
			*bp->b_wptr++ = RING_GET(async);
	} while (--cc);
	mutex_exit(&asy->asy_excl_hi);
	mutex_exit(&asy->asy_excl);
	if (bp->b_wptr > bp->b_rptr) {
			if (!canput(q)) {
				asyerror(CE_NOTE, "asy%d: local queue full",
				    instance);
				freemsg(bp);
			} else
				(void) putq(q, bp);
	} else
		freemsg(bp);
	/*
	 * If we have a parity error, then send
	 * up an M_BREAK with the "bad"
	 * character as an argument. Let ldterm
	 * figure out what to do with the error.
	 */
	if (cc) {
		(void) putctl1(q, M_BREAK, c);
		ASYSETSOFT(async->async_common);	/* finish cc chars */
	}
	mutex_enter(&asy->asy_excl);
	mutex_enter(&asy->asy_excl_hi);
rv:
	if ((RING_CNT(async) < (RINGSIZE/4)) &&
	    (async->async_inflow_source & IN_FLOW_RINGBUFF)) {
		async_flowcontrol_hw_input(asy, FLOW_START, IN_FLOW_RINGBUFF);
		(void) async_flowcontrol_sw_input(asy, FLOW_START,
		    IN_FLOW_RINGBUFF);
	}

	/*
	 * If a transmission has finished, indicate that it's finished,
	 * and start that line up again.
	 */
	if (async->async_break > 0) {
		nb = async->async_break;
		async->async_break = 0;
		if (async->async_flags & ASYNC_ISOPEN) {
			mutex_exit(&asy->asy_excl_hi);
			mutex_exit(&asy->asy_excl);
			for (; nb > 0; nb--)
				(void) putctl(q, M_BREAK);
			mutex_enter(&asy->asy_excl);
			mutex_enter(&asy->asy_excl_hi);
		}
	}
	if (async->async_ocnt <= 0 && (async->async_flags & ASYNC_BUSY)) {
		DEBUGCONT2(ASY_DEBUG_BUSY,
		    "async%d_softint: Clearing ASYNC_BUSY.  async_ocnt=%d\n",
		    instance,
		    async->async_ocnt);
		async->async_flags &= ~ASYNC_BUSY;
		mutex_exit(&asy->asy_excl_hi);
		if (async->async_xmitblk)
			freeb(async->async_xmitblk);
		async->async_xmitblk = NULL;
		async_start(async);
		/*
		 * If the flag isn't set after doing the async_start above, we
		 * may have finished all the queued output.  Signal any thread
		 * stuck in close.
		 */
		if (!(async->async_flags & ASYNC_BUSY))
			cv_broadcast(&async->async_flags_cv);
		mutex_enter(&asy->asy_excl_hi);
	}
	/*
	 * A note about these overrun bits: all they do is *tell* someone
	 * about an error- They do not track multiple errors. In fact,
	 * you could consider them latched register bits if you like.
	 * We are only interested in printing the error message once for
	 * any cluster of overrun errors.
	 */
	if (async->async_hw_overrun) {
		if (async->async_flags & ASYNC_ISOPEN) {
			mutex_exit(&asy->asy_excl_hi);
			mutex_exit(&asy->asy_excl);
			asyerror(CE_NOTE, "asy%d: silo overflow", instance);
			mutex_enter(&asy->asy_excl);
			mutex_enter(&asy->asy_excl_hi);
		}
		async->async_hw_overrun = 0;
	}
	if (async->async_sw_overrun) {
		if (async->async_flags & ASYNC_ISOPEN) {
			mutex_exit(&asy->asy_excl_hi);
			mutex_exit(&asy->asy_excl);
			asyerror(CE_NOTE, "asy%d: ring buffer overflow",
			    instance);
			mutex_enter(&asy->asy_excl);
			mutex_enter(&asy->asy_excl_hi);
		}
		async->async_sw_overrun = 0;
	}
	if (asy->asy_flags & ASY_DOINGSOFT_RETRY) {
		mutex_exit(&asy->asy_excl);
		goto begin;
	}
	asy->asy_flags &= ~ASY_DOINGSOFT;
	mutex_exit(&asy->asy_excl_hi);
	mutex_exit(&asy->asy_excl);
	DEBUGCONT1(ASY_DEBUG_PROCS, "async%d_softint: done\n", instance);
}

/*
 * Restart output on a line after a delay or break timer expired.
 */
static void
async_restart(void *arg)
{
	struct asyncline *async = (struct asyncline *)arg;
	struct asycom *asy = async->async_common;
	uchar_t lcr;

	/*
	 * If break timer expired, turn off the break bit.
	 */
#ifdef DEBUG
	int instance = UNIT(async->async_dev);

	DEBUGCONT1(ASY_DEBUG_PROCS, "async%d_restart\n", instance);
#endif
	mutex_enter(&asy->asy_excl);
	/*
	 * If ASYNC_OUT_SUSPEND is also set, we don't really
	 * clean the HW break, TIOCCBRK is responsible for this.
	 */
	if ((async->async_flags & ASYNC_BREAK) &&
	    !(async->async_flags & ASYNC_OUT_SUSPEND)) {
		mutex_enter(&asy->asy_excl_hi);
		lcr = ddi_get8(asy->asy_iohandle, asy->asy_ioaddr + LCR);
		ddi_put8(asy->asy_iohandle, asy->asy_ioaddr + LCR,
		    (lcr & ~SETBREAK));
		mutex_exit(&asy->asy_excl_hi);
	}
	async->async_flags &= ~(ASYNC_DELAY|ASYNC_BREAK);
	cv_broadcast(&async->async_flags_cv);
	async_start(async);

	mutex_exit(&asy->asy_excl);
}

static void
async_start(struct asyncline *async)
{
	async_nstart(async, 0);
}

/*
 * Start output on a line, unless it's busy, frozen, or otherwise.
 */
/*ARGSUSED*/
static void
async_nstart(struct asyncline *async, int mode)
{
	struct asycom *asy = async->async_common;
	int cc;
	queue_t *q;
	mblk_t *bp;
	uchar_t *xmit_addr;
	uchar_t	val;
	int	fifo_len = 1;
	boolean_t didsome;
	mblk_t *nbp;

#ifdef DEBUG
	int instance = UNIT(async->async_dev);

	DEBUGCONT1(ASY_DEBUG_PROCS, "async%d_nstart\n", instance);
#endif
	if (asy->asy_use_fifo == FIFO_ON) {
		fifo_len = asy->asy_fifo_buf; /* with FIFO buffers */
		if (fifo_len > asy_max_tx_fifo)
			fifo_len = asy_max_tx_fifo;
	}

	ASSERT(mutex_owned(&asy->asy_excl));

	/*
	 * If the chip is busy (i.e., we're waiting for a break timeout
	 * to expire, or for the current transmission to finish, or for
	 * output to finish draining from chip), don't grab anything new.
	 */
	if (async->async_flags & (ASYNC_BREAK|ASYNC_BUSY)) {
		DEBUGCONT2((mode? ASY_DEBUG_OUT : 0),
		    "async%d_nstart: start %s.\n",
		    instance,
		    async->async_flags & ASYNC_BREAK ? "break" : "busy");
		return;
	}

	/*
	 * Check only pended sw input flow control.
	 */
	mutex_enter(&asy->asy_excl_hi);
	if (async_flowcontrol_sw_input(asy, FLOW_CHECK, IN_FLOW_NULL))
		fifo_len--;
	mutex_exit(&asy->asy_excl_hi);

	/*
	 * If we're waiting for a delay timeout to expire, don't grab
	 * anything new.
	 */
	if (async->async_flags & ASYNC_DELAY) {
		DEBUGCONT1((mode? ASY_DEBUG_OUT : 0),
		    "async%d_nstart: start ASYNC_DELAY.\n", instance);
		return;
	}

	if ((q = async->async_ttycommon.t_writeq) == NULL) {
		DEBUGCONT1((mode? ASY_DEBUG_OUT : 0),
		    "async%d_nstart: start writeq is null.\n", instance);
		return;	/* not attached to a stream */
	}

	for (;;) {
		if ((bp = getq(q)) == NULL)
			return;	/* no data to transmit */

		/*
		 * We have a message block to work on.
		 * Check whether it's a break, a delay, or an ioctl (the latter
		 * occurs if the ioctl in question was waiting for the output
		 * to drain).  If it's one of those, process it immediately.
		 */
		switch (bp->b_datap->db_type) {

		case M_BREAK:
			/*
			 * Set the break bit, and arrange for "async_restart"
			 * to be called in 1/4 second; it will turn the
			 * break bit off, and call "async_start" to grab
			 * the next message.
			 */
			mutex_enter(&asy->asy_excl_hi);
			val = ddi_get8(asy->asy_iohandle,
			    asy->asy_ioaddr + LCR);
			ddi_put8(asy->asy_iohandle, asy->asy_ioaddr + LCR,
			    (val | SETBREAK));
			mutex_exit(&asy->asy_excl_hi);
			async->async_flags |= ASYNC_BREAK;
			(void) timeout(async_restart, (caddr_t)async,
			    drv_usectohz(1000000)/4);
			freemsg(bp);
			return;	/* wait for this to finish */

		case M_DELAY:
			/*
			 * Arrange for "async_restart" to be called when the
			 * delay expires; it will turn ASYNC_DELAY off,
			 * and call "async_start" to grab the next message.
			 */
			(void) timeout(async_restart, (caddr_t)async,
			    (int)(*(unsigned char *)bp->b_rptr + 6));
			async->async_flags |= ASYNC_DELAY;
			freemsg(bp);
			return;	/* wait for this to finish */

		case M_IOCTL:
			/*
			 * This ioctl was waiting for the output ahead of
			 * it to drain; obviously, it has.  Do it, and
			 * then grab the next message after it.
			 */
			mutex_exit(&asy->asy_excl);
			async_ioctl(async, q, bp);
			mutex_enter(&asy->asy_excl);
			continue;
		}

		while (bp != NULL && ((cc = MBLKL(bp)) == 0)) {
			nbp = bp->b_cont;
			freeb(bp);
			bp = nbp;
		}
		if (bp != NULL)
			break;
	}

	/*
	 * We have data to transmit.  If output is stopped, put
	 * it back and try again later.
	 */
	if (async->async_flags & (ASYNC_HW_OUT_FLW | ASYNC_SW_OUT_FLW |
	    ASYNC_STOPPED | ASYNC_OUT_SUSPEND)) {
		(void) putbq(q, bp);
		return;
	}

	async->async_xmitblk = bp;
	xmit_addr = bp->b_rptr;
	bp = bp->b_cont;
	if (bp != NULL)
		(void) putbq(q, bp);	/* not done with this message yet */

	/*
	 * In 5-bit mode, the high order bits are used
	 * to indicate character sizes less than five,
	 * so we need to explicitly mask before transmitting
	 */
	if ((async->async_ttycommon.t_cflag & CSIZE) == CS5) {
		unsigned char *p = xmit_addr;
		int cnt = cc;

		while (cnt--)
			*p++ &= (unsigned char) 0x1f;
	}

	/*
	 * Set up this block for pseudo-DMA.
	 */
	mutex_enter(&asy->asy_excl_hi);
	/*
	 * If the transmitter is ready, shove the first
	 * character out.
	 */
	didsome = B_FALSE;
	while (--fifo_len >= 0 && cc > 0) {
		if (!(ddi_get8(asy->asy_iohandle, asy->asy_ioaddr + LSR) &
		    XHRE))
			break;
		ddi_put8(asy->asy_iohandle, asy->asy_ioaddr + DAT,
		    *xmit_addr++);
		cc--;
		didsome = B_TRUE;
	}
	async->async_optr = xmit_addr;
	async->async_ocnt = cc;
	if (didsome)
		async->async_flags |= ASYNC_PROGRESS;
	DEBUGCONT2(ASY_DEBUG_BUSY,
	    "async%d_nstart: Set ASYNC_BUSY.  async_ocnt=%d\n",
	    instance, async->async_ocnt);
	async->async_flags |= ASYNC_BUSY;
	mutex_exit(&asy->asy_excl_hi);
}

/*
 * Resume output by poking the transmitter.
 */
static void
async_resume(struct asyncline *async)
{
	struct asycom *asy = async->async_common;
#ifdef DEBUG
	int instance;
#endif

	ASSERT(mutex_owned(&asy->asy_excl_hi));
#ifdef DEBUG
	instance = UNIT(async->async_dev);
	DEBUGCONT1(ASY_DEBUG_PROCS, "async%d_resume\n", instance);
#endif

	if (ddi_get8(asy->asy_iohandle, asy->asy_ioaddr + LSR) & XHRE) {
		if (async_flowcontrol_sw_input(asy, FLOW_CHECK, IN_FLOW_NULL))
			return;
		if (async->async_ocnt > 0 &&
		    !(async->async_flags &
		    (ASYNC_HW_OUT_FLW|ASYNC_SW_OUT_FLW|ASYNC_OUT_SUSPEND))) {
			ddi_put8(asy->asy_iohandle,
			    asy->asy_ioaddr + DAT, *async->async_optr++);
			async->async_ocnt--;
			async->async_flags |= ASYNC_PROGRESS;
		}
	}
}

/*
 * Hold the untimed break to last the minimum time.
 */
static void
async_hold_utbrk(void *arg)
{
	struct asyncline *async = arg;
	struct asycom *asy = async->async_common;

	mutex_enter(&asy->asy_excl);
	async->async_flags &= ~ASYNC_HOLD_UTBRK;
	cv_broadcast(&async->async_flags_cv);
	async->async_utbrktid = 0;
	mutex_exit(&asy->asy_excl);
}

/*
 * Resume the untimed break.
 */
static void
async_resume_utbrk(struct asyncline *async)
{
	uchar_t	val;
	struct asycom *asy = async->async_common;
	ASSERT(mutex_owned(&asy->asy_excl));

	/*
	 * Because the wait time is very short,
	 * so we use uninterruptably wait.
	 */
	while (async->async_flags & ASYNC_HOLD_UTBRK) {
		cv_wait(&async->async_flags_cv, &asy->asy_excl);
	}
	mutex_enter(&asy->asy_excl_hi);
	/*
	 * Timed break and untimed break can exist simultaneously,
	 * if ASYNC_BREAK is also set at here, we don't
	 * really clean the HW break.
	 */
	if (!(async->async_flags & ASYNC_BREAK)) {
		val = ddi_get8(asy->asy_iohandle, asy->asy_ioaddr + LCR);
		ddi_put8(asy->asy_iohandle, asy->asy_ioaddr + LCR,
		    (val & ~SETBREAK));
	}
	async->async_flags &= ~ASYNC_OUT_SUSPEND;
	cv_broadcast(&async->async_flags_cv);
	if (async->async_ocnt > 0) {
		async_resume(async);
		mutex_exit(&asy->asy_excl_hi);
	} else {
		async->async_flags &= ~ASYNC_BUSY;
		mutex_exit(&asy->asy_excl_hi);
		if (async->async_xmitblk != NULL) {
			freeb(async->async_xmitblk);
			async->async_xmitblk = NULL;
		}
		async_start(async);
	}
}

/*
 * Process an "ioctl" message sent down to us.
 * Note that we don't need to get any locks until we are ready to access
 * the hardware.  Nothing we access until then is going to be altered
 * outside of the STREAMS framework, so we should be safe.
 */
int asydelay = 10000;
static void
async_ioctl(struct asyncline *async, queue_t *wq, mblk_t *mp)
{
	struct asycom *asy = async->async_common;
	tty_common_t  *tp = &async->async_ttycommon;
	struct iocblk *iocp;
	unsigned datasize;
	int error = 0;
	uchar_t val;
	mblk_t *datamp;
	unsigned int index;

#ifdef DEBUG
	int instance = UNIT(async->async_dev);

	DEBUGCONT1(ASY_DEBUG_PROCS, "async%d_ioctl\n", instance);
#endif

	if (tp->t_iocpending != NULL) {
		/*
		 * We were holding an "ioctl" response pending the
		 * availability of an "mblk" to hold data to be passed up;
		 * another "ioctl" came through, which means that "ioctl"
		 * must have timed out or been aborted.
		 */
		freemsg(async->async_ttycommon.t_iocpending);
		async->async_ttycommon.t_iocpending = NULL;
	}

	iocp = (struct iocblk *)mp->b_rptr;

	/*
	 * For TIOCMGET and the PPS ioctls, do NOT call ttycommon_ioctl()
	 * because this function frees up the message block (mp->b_cont) that
	 * contains the user location where we pass back the results.
	 *
	 * Similarly, CONSOPENPOLLEDIO needs ioc_count, which ttycommon_ioctl
	 * zaps.  We know that ttycommon_ioctl doesn't know any CONS*
	 * ioctls, so keep the others safe too.
	 */
	DEBUGCONT2(ASY_DEBUG_IOCTL, "async%d_ioctl: %s\n",
	    instance,
	    iocp->ioc_cmd == TIOCMGET ? "TIOCMGET" :
	    iocp->ioc_cmd == TIOCMSET ? "TIOCMSET" :
	    iocp->ioc_cmd == TIOCMBIS ? "TIOCMBIS" :
	    iocp->ioc_cmd == TIOCMBIC ? "TIOCMBIC" :
	    "other");

	switch (iocp->ioc_cmd) {
	case TIOCMGET:
	case TIOCGPPS:
	case TIOCSPPS:
	case TIOCGPPSEV:
	case CONSOPENPOLLEDIO:
	case CONSCLOSEPOLLEDIO:
	case CONSSETABORTENABLE:
	case CONSGETABORTENABLE:
		error = -1; /* Do Nothing */
		break;
	default:

		/*
		 * The only way in which "ttycommon_ioctl" can fail is if the
		 * "ioctl" requires a response containing data to be returned
		 * to the user, and no mblk could be allocated for the data.
		 * No such "ioctl" alters our state.  Thus, we always go ahead
		 * and do any state-changes the "ioctl" calls for.  If we
		 * couldn't allocate the data, "ttycommon_ioctl" has stashed
		 * the "ioctl" away safely, so we just call "bufcall" to
		 * request that we be called back when we stand a better
		 * chance of allocating the data.
		 */
		if ((datasize = ttycommon_ioctl(tp, wq, mp, &error)) != 0) {
			if (async->async_wbufcid)
				unbufcall(async->async_wbufcid);
			async->async_wbufcid = bufcall(datasize, BPRI_HI,
			    (void (*)(void *)) async_reioctl,
			    (void *)(intptr_t)async->async_common->asy_unit);
			return;
		}
	}

	mutex_enter(&asy->asy_excl);

	if (error == 0) {
		/*
		 * "ttycommon_ioctl" did most of the work; we just use the
		 * data it set up.
		 */
		switch (iocp->ioc_cmd) {

		case TCSETS:
			mutex_enter(&asy->asy_excl_hi);
			if (asy_baudok(asy))
				asy_program(asy, ASY_NOINIT);
			else
				error = EINVAL;
			mutex_exit(&asy->asy_excl_hi);
			break;
		case TCSETSF:
		case TCSETSW:
		case TCSETA:
		case TCSETAW:
		case TCSETAF:
			mutex_enter(&asy->asy_excl_hi);
			if (!asy_baudok(asy))
				error = EINVAL;
			else {
				if (asy_isbusy(asy))
					asy_waiteot(asy);
				asy_program(asy, ASY_NOINIT);
			}
			mutex_exit(&asy->asy_excl_hi);
			break;
		}
	} else if (error < 0) {
		/*
		 * "ttycommon_ioctl" didn't do anything; we process it here.
		 */
		error = 0;
		switch (iocp->ioc_cmd) {

		case TIOCGPPS:
			/*
			 * Get PPS on/off.
			 */
			if (mp->b_cont != NULL)
				freemsg(mp->b_cont);

			mp->b_cont = allocb(sizeof (int), BPRI_HI);
			if (mp->b_cont == NULL) {
				error = ENOMEM;
				break;
			}
			if (asy->asy_flags & ASY_PPS)
				*(int *)mp->b_cont->b_wptr = 1;
			else
				*(int *)mp->b_cont->b_wptr = 0;
			mp->b_cont->b_wptr += sizeof (int);
			mp->b_datap->db_type = M_IOCACK;
			iocp->ioc_count = sizeof (int);
			break;

		case TIOCSPPS:
			/*
			 * Set PPS on/off.
			 */
			error = miocpullup(mp, sizeof (int));
			if (error != 0)
				break;

			mutex_enter(&asy->asy_excl_hi);
			if (*(int *)mp->b_cont->b_rptr)
				asy->asy_flags |= ASY_PPS;
			else
				asy->asy_flags &= ~ASY_PPS;
			/* Reset edge sense */
			asy->asy_flags &= ~ASY_PPS_EDGE;
			mutex_exit(&asy->asy_excl_hi);
			mp->b_datap->db_type = M_IOCACK;
			break;

		case TIOCGPPSEV:
		{
			/*
			 * Get PPS event data.
			 */
			mblk_t *bp;
			void *buf;
#ifdef _SYSCALL32_IMPL
			struct ppsclockev32 p32;
#endif
			struct ppsclockev ppsclockev;

			if (mp->b_cont != NULL) {
				freemsg(mp->b_cont);
				mp->b_cont = NULL;
			}

			if ((asy->asy_flags & ASY_PPS) == 0) {
				error = ENXIO;
				break;
			}

			/* Protect from incomplete asy_ppsev */
			mutex_enter(&asy->asy_excl_hi);
			ppsclockev = asy_ppsev;
			mutex_exit(&asy->asy_excl_hi);

#ifdef _SYSCALL32_IMPL
			if ((iocp->ioc_flag & IOC_MODELS) != IOC_NATIVE) {
				TIMEVAL_TO_TIMEVAL32(&p32.tv, &ppsclockev.tv);
				p32.serial = ppsclockev.serial;
				buf = &p32;
				iocp->ioc_count = sizeof (struct ppsclockev32);
			} else
#endif
			{
				buf = &ppsclockev;
				iocp->ioc_count = sizeof (struct ppsclockev);
			}

			if ((bp = allocb(iocp->ioc_count, BPRI_HI)) == NULL) {
				error = ENOMEM;
				break;
			}
			mp->b_cont = bp;

			bcopy(buf, bp->b_wptr, iocp->ioc_count);
			bp->b_wptr += iocp->ioc_count;
			mp->b_datap->db_type = M_IOCACK;
			break;
		}

		case TCSBRK:
			error = miocpullup(mp, sizeof (int));
			if (error != 0)
				break;

			if (*(int *)mp->b_cont->b_rptr == 0) {

				/*
				 * XXX Arrangements to ensure that a break
				 * isn't in progress should be sufficient.
				 * This ugly delay() is the only thing
				 * that seems to work on the NCR Worldmark.
				 * It should be replaced. Note that an
				 * asy_waiteot() also does not work.
				 */
				if (asydelay)
					delay(drv_usectohz(asydelay));

				while (async->async_flags & ASYNC_BREAK) {
					cv_wait(&async->async_flags_cv,
					    &asy->asy_excl);
				}
				mutex_enter(&asy->asy_excl_hi);
				/*
				 * We loop until the TSR is empty and then
				 * set the break.  ASYNC_BREAK has been set
				 * to ensure that no characters are
				 * transmitted while the TSR is being
				 * flushed and SOUT is being used for the
				 * break signal.
				 *
				 * The wait period is equal to
				 * clock / (baud * 16) * 16 * 2.
				 */
				index = BAUDINDEX(
				    async->async_ttycommon.t_cflag);
				async->async_flags |= ASYNC_BREAK;

				while ((ddi_get8(asy->asy_iohandle,
				    asy->asy_ioaddr + LSR) & XSRE) == 0) {
					mutex_exit(&asy->asy_excl_hi);
					mutex_exit(&asy->asy_excl);
					drv_usecwait(
					    32*asyspdtab[index] & 0xfff);
					mutex_enter(&asy->asy_excl);
					mutex_enter(&asy->asy_excl_hi);
				}
				/*
				 * Arrange for "async_restart"
				 * to be called in 1/4 second;
				 * it will turn the break bit off, and call
				 * "async_start" to grab the next message.
				 */
				val = ddi_get8(asy->asy_iohandle,
				    asy->asy_ioaddr + LCR);
				ddi_put8(asy->asy_iohandle,
				    asy->asy_ioaddr + LCR,
				    (val | SETBREAK));
				mutex_exit(&asy->asy_excl_hi);
				(void) timeout(async_restart, (caddr_t)async,
				    drv_usectohz(1000000)/4);
			} else {
				DEBUGCONT1(ASY_DEBUG_OUT,
				    "async%d_ioctl: wait for flush.\n",
				    instance);
				mutex_enter(&asy->asy_excl_hi);
				asy_waiteot(asy);
				mutex_exit(&asy->asy_excl_hi);
				DEBUGCONT1(ASY_DEBUG_OUT,
				    "async%d_ioctl: ldterm satisfied.\n",
				    instance);
			}
			break;

		case TIOCSBRK:
			if (!(async->async_flags & ASYNC_OUT_SUSPEND)) {
				mutex_enter(&asy->asy_excl_hi);
				async->async_flags |= ASYNC_OUT_SUSPEND;
				async->async_flags |= ASYNC_HOLD_UTBRK;
				index = BAUDINDEX(
				    async->async_ttycommon.t_cflag);
				while ((ddi_get8(asy->asy_iohandle,
				    asy->asy_ioaddr + LSR) & XSRE) == 0) {
					mutex_exit(&asy->asy_excl_hi);
					mutex_exit(&asy->asy_excl);
					drv_usecwait(
					    32*asyspdtab[index] & 0xfff);
					mutex_enter(&asy->asy_excl);
					mutex_enter(&asy->asy_excl_hi);
				}
				val = ddi_get8(asy->asy_iohandle,
				    asy->asy_ioaddr + LCR);
				ddi_put8(asy->asy_iohandle,
				    asy->asy_ioaddr + LCR, (val | SETBREAK));
				mutex_exit(&asy->asy_excl_hi);
				/* wait for 100ms to hold BREAK */
				async->async_utbrktid =
				    timeout((void (*)())async_hold_utbrk,
				    (caddr_t)async,
				    drv_usectohz(asy_min_utbrk));
			}
			mioc2ack(mp, NULL, 0, 0);
			break;

		case TIOCCBRK:
			if (async->async_flags & ASYNC_OUT_SUSPEND)
				async_resume_utbrk(async);
			mioc2ack(mp, NULL, 0, 0);
			break;

		case TIOCMSET:
		case TIOCMBIS:
		case TIOCMBIC:
			if (iocp->ioc_count != TRANSPARENT) {
				DEBUGCONT1(ASY_DEBUG_IOCTL, "async%d_ioctl: "
				    "non-transparent\n", instance);

				error = miocpullup(mp, sizeof (int));
				if (error != 0)
					break;

				mutex_enter(&asy->asy_excl_hi);
				(void) asymctl(asy,
				    dmtoasy(*(int *)mp->b_cont->b_rptr),
				    iocp->ioc_cmd);
				mutex_exit(&asy->asy_excl_hi);
				iocp->ioc_error = 0;
				mp->b_datap->db_type = M_IOCACK;
			} else {
				DEBUGCONT1(ASY_DEBUG_IOCTL, "async%d_ioctl: "
				    "transparent\n", instance);
				mcopyin(mp, NULL, sizeof (int), NULL);
			}
			break;

		case TIOCMGET:
			datamp = allocb(sizeof (int), BPRI_MED);
			if (datamp == NULL) {
				error = EAGAIN;
				break;
			}

			mutex_enter(&asy->asy_excl_hi);
			*(int *)datamp->b_rptr = asymctl(asy, 0, TIOCMGET);
			mutex_exit(&asy->asy_excl_hi);

			if (iocp->ioc_count == TRANSPARENT) {
				DEBUGCONT1(ASY_DEBUG_IOCTL, "async%d_ioctl: "
				    "transparent\n", instance);
				mcopyout(mp, NULL, sizeof (int), NULL, datamp);
			} else {
				DEBUGCONT1(ASY_DEBUG_IOCTL, "async%d_ioctl: "
				    "non-transparent\n", instance);
				mioc2ack(mp, datamp, sizeof (int), 0);
			}
			break;

		case CONSOPENPOLLEDIO:
			error = miocpullup(mp, sizeof (struct cons_polledio *));
			if (error != 0)
				break;

			*(struct cons_polledio **)mp->b_cont->b_rptr =
			    &asy->polledio;

			mp->b_datap->db_type = M_IOCACK;
			break;

		case CONSCLOSEPOLLEDIO:
			mp->b_datap->db_type = M_IOCACK;
			iocp->ioc_error = 0;
			iocp->ioc_rval = 0;
			break;

		case CONSSETABORTENABLE:
			error = secpolicy_console(iocp->ioc_cr);
			if (error != 0)
				break;

			if (iocp->ioc_count != TRANSPARENT) {
				error = EINVAL;
				break;
			}

			if (*(intptr_t *)mp->b_cont->b_rptr)
				asy->asy_flags |= ASY_CONSOLE;
			else
				asy->asy_flags &= ~ASY_CONSOLE;

			mp->b_datap->db_type = M_IOCACK;
			iocp->ioc_error = 0;
			iocp->ioc_rval = 0;
			break;

		case CONSGETABORTENABLE:
			/*CONSTANTCONDITION*/
			ASSERT(sizeof (boolean_t) <= sizeof (boolean_t *));
			/*
			 * Store the return value right in the payload
			 * we were passed.  Crude.
			 */
			mcopyout(mp, NULL, sizeof (boolean_t), NULL, NULL);
			*(boolean_t *)mp->b_cont->b_rptr =
			    (asy->asy_flags & ASY_CONSOLE) != 0;
			break;

		default:
			/*
			 * If we don't understand it, it's an error.  NAK it.
			 */
			error = EINVAL;
			break;
		}
	}
	if (error != 0) {
		iocp->ioc_error = error;
		mp->b_datap->db_type = M_IOCNAK;
	}
	mutex_exit(&asy->asy_excl);
	qreply(wq, mp);
	DEBUGCONT1(ASY_DEBUG_PROCS, "async%d_ioctl: done\n", instance);
}

static int
asyrsrv(queue_t *q)
{
	mblk_t *bp;
	struct asyncline *async;

	async = (struct asyncline *)q->q_ptr;

	while (canputnext(q) && (bp = getq(q)))
		putnext(q, bp);
	ASYSETSOFT(async->async_common);
	async->async_polltid = 0;
	return (0);
}

/*
 * The ASYWPUTDO_NOT_SUSP macro indicates to asywputdo() whether it should
 * handle messages as though the driver is operating normally or is
 * suspended.  In the suspended case, some or all of the processing may have
 * to be delayed until the driver is resumed.
 */
#define	ASYWPUTDO_NOT_SUSP(async, wput) \
	!((wput) && ((async)->async_flags & ASYNC_DDI_SUSPENDED))

/*
 * Processing for write queue put procedure.
 * Respond to M_STOP, M_START, M_IOCTL, and M_FLUSH messages here;
 * set the flow control character for M_STOPI and M_STARTI messages;
 * queue up M_BREAK, M_DELAY, and M_DATA messages for processing
 * by the start routine, and then call the start routine; discard
 * everything else.  Note that this driver does not incorporate any
 * mechanism to negotiate to handle the canonicalization process.
 * It expects that these functions are handled in upper module(s),
 * as we do in ldterm.
 */
static int
asywputdo(queue_t *q, mblk_t *mp, boolean_t wput)
{
	struct asyncline *async;
	struct asycom *asy;
#ifdef DEBUG
	int instance;
#endif
	int error;

	async = (struct asyncline *)q->q_ptr;

#ifdef DEBUG
	instance = UNIT(async->async_dev);
#endif
	asy = async->async_common;

	switch (mp->b_datap->db_type) {

	case M_STOP:
		/*
		 * Since we don't do real DMA, we can just let the
		 * chip coast to a stop after applying the brakes.
		 */
		mutex_enter(&asy->asy_excl);
		async->async_flags |= ASYNC_STOPPED;
		mutex_exit(&asy->asy_excl);
		freemsg(mp);
		break;

	case M_START:
		mutex_enter(&asy->asy_excl);
		if (async->async_flags & ASYNC_STOPPED) {
			async->async_flags &= ~ASYNC_STOPPED;
			if (ASYWPUTDO_NOT_SUSP(async, wput)) {
				/*
				 * If an output operation is in progress,
				 * resume it.  Otherwise, prod the start
				 * routine.
				 */
				if (async->async_ocnt > 0) {
					mutex_enter(&asy->asy_excl_hi);
					async_resume(async);
					mutex_exit(&asy->asy_excl_hi);
				} else {
					async_start(async);
				}
			}
		}
		mutex_exit(&asy->asy_excl);
		freemsg(mp);
		break;

	case M_IOCTL:
		switch (((struct iocblk *)mp->b_rptr)->ioc_cmd) {

		case TCSBRK:
			error = miocpullup(mp, sizeof (int));
			if (error != 0) {
				miocnak(q, mp, 0, error);
				return (0);
			}

			if (*(int *)mp->b_cont->b_rptr != 0) {
				DEBUGCONT1(ASY_DEBUG_OUT,
				    "async%d_ioctl: flush request.\n",
				    instance);
				(void) putq(q, mp);

				mutex_enter(&asy->asy_excl);
				if (ASYWPUTDO_NOT_SUSP(async, wput)) {
					/*
					 * If an TIOCSBRK is in progress,
					 * clean it as TIOCCBRK does,
					 * then kick off output.
					 * If TIOCSBRK is not in progress,
					 * just kick off output.
					 */
					async_resume_utbrk(async);
				}
				mutex_exit(&asy->asy_excl);
				break;
			}
			/*FALLTHROUGH*/
		case TCSETSW:
		case TCSETSF:
		case TCSETAW:
		case TCSETAF:
			/*
			 * The changes do not take effect until all
			 * output queued before them is drained.
			 * Put this message on the queue, so that
			 * "async_start" will see it when it's done
			 * with the output before it.  Poke the
			 * start routine, just in case.
			 */
			(void) putq(q, mp);

			mutex_enter(&asy->asy_excl);
			if (ASYWPUTDO_NOT_SUSP(async, wput)) {
				/*
				 * If an TIOCSBRK is in progress,
				 * clean it as TIOCCBRK does.
				 * then kick off output.
				 * If TIOCSBRK is not in progress,
				 * just kick off output.
				 */
				async_resume_utbrk(async);
			}
			mutex_exit(&asy->asy_excl);
			break;

		default:
			/*
			 * Do it now.
			 */
			mutex_enter(&asy->asy_excl);
			if (ASYWPUTDO_NOT_SUSP(async, wput)) {
				mutex_exit(&asy->asy_excl);
				async_ioctl(async, q, mp);
				break;
			}
			async_put_suspq(asy, mp);
			mutex_exit(&asy->asy_excl);
			break;
		}
		break;

	case M_FLUSH:
		if (*mp->b_rptr & FLUSHW) {
			mutex_enter(&asy->asy_excl);

			/*
			 * Abort any output in progress.
			 */
			mutex_enter(&asy->asy_excl_hi);
			if (async->async_flags & ASYNC_BUSY) {
				DEBUGCONT1(ASY_DEBUG_BUSY, "asy%dwput: "
				    "Clearing async_ocnt, "
				    "leaving ASYNC_BUSY set\n",
				    instance);
				async->async_ocnt = 0;
				async->async_flags &= ~ASYNC_BUSY;
			} /* if */

			if (ASYWPUTDO_NOT_SUSP(async, wput)) {
				/* Flush FIFO buffers */
				if (asy->asy_use_fifo == FIFO_ON) {
					asy_reset_fifo(asy, FIFOTXFLSH);
				}
			}
			mutex_exit(&asy->asy_excl_hi);

			/* Flush FIFO buffers */
			if (asy->asy_use_fifo == FIFO_ON) {
				asy_reset_fifo(asy, FIFOTXFLSH);
			}

			/*
			 * Flush our write queue.
			 */
			flushq(q, FLUSHDATA);	/* XXX doesn't flush M_DELAY */
			if (async->async_xmitblk != NULL) {
				freeb(async->async_xmitblk);
				async->async_xmitblk = NULL;
			}
			mutex_exit(&asy->asy_excl);
			*mp->b_rptr &= ~FLUSHW;	/* it has been flushed */
		}
		if (*mp->b_rptr & FLUSHR) {
			if (ASYWPUTDO_NOT_SUSP(async, wput)) {
				/* Flush FIFO buffers */
				if (asy->asy_use_fifo == FIFO_ON) {
					asy_reset_fifo(asy, FIFORXFLSH);
				}
			}
			flushq(RD(q), FLUSHDATA);
			qreply(q, mp);	/* give the read queues a crack at it */
		} else {
			freemsg(mp);
		}

		/*
		 * We must make sure we process messages that survive the
		 * write-side flush.
		 */
		if (ASYWPUTDO_NOT_SUSP(async, wput)) {
			mutex_enter(&asy->asy_excl);
			async_start(async);
			mutex_exit(&asy->asy_excl);
		}
		break;

	case M_BREAK:
	case M_DELAY:
	case M_DATA:
		/*
		 * Queue the message up to be transmitted,
		 * and poke the start routine.
		 */
		(void) putq(q, mp);
		if (ASYWPUTDO_NOT_SUSP(async, wput)) {
			mutex_enter(&asy->asy_excl);
			async_start(async);
			mutex_exit(&asy->asy_excl);
		}
		break;

	case M_STOPI:
		mutex_enter(&asy->asy_excl);
		if (ASYWPUTDO_NOT_SUSP(async, wput)) {
			mutex_enter(&asy->asy_excl_hi);
			if (!(async->async_inflow_source & IN_FLOW_USER)) {
				async_flowcontrol_hw_input(asy, FLOW_STOP,
				    IN_FLOW_USER);
				(void) async_flowcontrol_sw_input(asy,
				    FLOW_STOP, IN_FLOW_USER);
			}
			mutex_exit(&asy->asy_excl_hi);
			mutex_exit(&asy->asy_excl);
			freemsg(mp);
			break;
		}
		async_put_suspq(asy, mp);
		mutex_exit(&asy->asy_excl);
		break;

	case M_STARTI:
		mutex_enter(&asy->asy_excl);
		if (ASYWPUTDO_NOT_SUSP(async, wput)) {
			mutex_enter(&asy->asy_excl_hi);
			if (async->async_inflow_source & IN_FLOW_USER) {
				async_flowcontrol_hw_input(asy, FLOW_START,
				    IN_FLOW_USER);
				(void) async_flowcontrol_sw_input(asy,
				    FLOW_START, IN_FLOW_USER);
			}
			mutex_exit(&asy->asy_excl_hi);
			mutex_exit(&asy->asy_excl);
			freemsg(mp);
			break;
		}
		async_put_suspq(asy, mp);
		mutex_exit(&asy->asy_excl);
		break;

	case M_CTL:
		if (MBLKL(mp) >= sizeof (struct iocblk) &&
		    ((struct iocblk *)mp->b_rptr)->ioc_cmd == MC_POSIXQUERY) {
			mutex_enter(&asy->asy_excl);
			if (ASYWPUTDO_NOT_SUSP(async, wput)) {
				((struct iocblk *)mp->b_rptr)->ioc_cmd =
				    MC_HAS_POSIX;
				mutex_exit(&asy->asy_excl);
				qreply(q, mp);
				break;
			} else {
				async_put_suspq(asy, mp);
			}
		} else {
			/*
			 * These MC_SERVICE type messages are used by upper
			 * modules to tell this driver to send input up
			 * immediately, or that it can wait for normal
			 * processing that may or may not be done.  Sun
			 * requires these for the mouse module.
			 * (XXX - for x86?)
			 */
			mutex_enter(&asy->asy_excl);
			switch (*mp->b_rptr) {

			case MC_SERVICEIMM:
				async->async_flags |= ASYNC_SERVICEIMM;
				break;

			case MC_SERVICEDEF:
				async->async_flags &= ~ASYNC_SERVICEIMM;
				break;
			}
			mutex_exit(&asy->asy_excl);
			freemsg(mp);
		}
		break;

	case M_IOCDATA:
		mutex_enter(&asy->asy_excl);
		if (ASYWPUTDO_NOT_SUSP(async, wput)) {
			mutex_exit(&asy->asy_excl);
			async_iocdata(q, mp);
			break;
		}
		async_put_suspq(asy, mp);
		mutex_exit(&asy->asy_excl);
		break;

	default:
		freemsg(mp);
		break;
	}
	return (0);
}

static int
asywput(queue_t *q, mblk_t *mp)
{
	return (asywputdo(q, mp, B_TRUE));
}

/*
 * Retry an "ioctl", now that "bufcall" claims we may be able to allocate
 * the buffer we need.
 */
static void
async_reioctl(void *unit)
{
	int instance = (uintptr_t)unit;
	struct asyncline *async;
	struct asycom *asy;
	queue_t	*q;
	mblk_t	*mp;

	asy = ddi_get_soft_state(asy_soft_state, instance);
	ASSERT(asy != NULL);
	async = asy->asy_priv;

	/*
	 * The bufcall is no longer pending.
	 */
	mutex_enter(&asy->asy_excl);
	async->async_wbufcid = 0;
	if ((q = async->async_ttycommon.t_writeq) == NULL) {
		mutex_exit(&asy->asy_excl);
		return;
	}
	if ((mp = async->async_ttycommon.t_iocpending) != NULL) {
		/* not pending any more */
		async->async_ttycommon.t_iocpending = NULL;
		mutex_exit(&asy->asy_excl);
		async_ioctl(async, q, mp);
	} else
		mutex_exit(&asy->asy_excl);
}

static void
async_iocdata(queue_t *q, mblk_t *mp)
{
	struct asyncline	*async = (struct asyncline *)q->q_ptr;
	struct asycom		*asy;
	struct iocblk *ip;
	struct copyresp *csp;
#ifdef DEBUG
	int instance = UNIT(async->async_dev);
#endif

	asy = async->async_common;
	ip = (struct iocblk *)mp->b_rptr;
	csp = (struct copyresp *)mp->b_rptr;

	if (csp->cp_rval != 0) {
		if (csp->cp_private)
			freemsg(csp->cp_private);
		freemsg(mp);
		return;
	}

	mutex_enter(&asy->asy_excl);
	DEBUGCONT2(ASY_DEBUG_MODEM, "async%d_iocdata: case %s\n",
	    instance,
	    csp->cp_cmd == TIOCMGET ? "TIOCMGET" :
	    csp->cp_cmd == TIOCMSET ? "TIOCMSET" :
	    csp->cp_cmd == TIOCMBIS ? "TIOCMBIS" :
	    "TIOCMBIC");
	switch (csp->cp_cmd) {

	case TIOCMGET:
		if (mp->b_cont) {
			freemsg(mp->b_cont);
			mp->b_cont = NULL;
		}
		mp->b_datap->db_type = M_IOCACK;
		ip->ioc_error = 0;
		ip->ioc_count = 0;
		ip->ioc_rval = 0;
		mp->b_wptr = mp->b_rptr + sizeof (struct iocblk);
		break;

	case TIOCMSET:
	case TIOCMBIS:
	case TIOCMBIC:
		mutex_enter(&asy->asy_excl_hi);
		(void) asymctl(asy, dmtoasy(*(int *)mp->b_cont->b_rptr),
		    csp->cp_cmd);
		mutex_exit(&asy->asy_excl_hi);
		mioc2ack(mp, NULL, 0, 0);
		break;

	default:
		mp->b_datap->db_type = M_IOCNAK;
		ip->ioc_error = EINVAL;
		break;
	}
	qreply(q, mp);
	mutex_exit(&asy->asy_excl);
}

/*
 * debugger/console support routines.
 */

/*
 * put a character out
 * Do not use interrupts.  If char is LF, put out CR, LF.
 */
static void
asyputchar(cons_polledio_arg_t arg, uchar_t c)
{
	struct asycom *asy = (struct asycom *)arg;

	if (c == '\n')
		asyputchar(arg, '\r');

	while ((ddi_get8(asy->asy_iohandle,
	    asy->asy_ioaddr + LSR) & XHRE) == 0) {
		/* wait for xmit to finish */
		drv_usecwait(10);
	}

	/* put the character out */
	ddi_put8(asy->asy_iohandle, asy->asy_ioaddr + DAT, c);
}

/*
 * See if there's a character available. If no character is
 * available, return 0. Run in polled mode, no interrupts.
 */
static boolean_t
asyischar(cons_polledio_arg_t arg)
{
	struct asycom *asy = (struct asycom *)arg;

	return ((ddi_get8(asy->asy_iohandle, asy->asy_ioaddr + LSR) & RCA)
	    != 0);
}

/*
 * Get a character. Run in polled mode, no interrupts.
 */
static int
asygetchar(cons_polledio_arg_t arg)
{
	struct asycom *asy = (struct asycom *)arg;

	while (!asyischar(arg))
		drv_usecwait(10);
	return (ddi_get8(asy->asy_iohandle, asy->asy_ioaddr + DAT));
}

/*
 * Set or get the modem control status.
 */
static int
asymctl(struct asycom *asy, int bits, int how)
{
	int mcr_r, msr_r;
	int instance = asy->asy_unit;

	ASSERT(mutex_owned(&asy->asy_excl_hi));
	ASSERT(mutex_owned(&asy->asy_excl));

	/* Read Modem Control Registers */
	mcr_r = ddi_get8(asy->asy_iohandle, asy->asy_ioaddr + MCR);

	switch (how) {

	case TIOCMSET:
		DEBUGCONT2(ASY_DEBUG_MODEM,
		    "asy%dmctl: TIOCMSET, bits = %x\n", instance, bits);
		mcr_r = bits;		/* Set bits	*/
		break;

	case TIOCMBIS:
		DEBUGCONT2(ASY_DEBUG_MODEM, "asy%dmctl: TIOCMBIS, bits = %x\n",
		    instance, bits);
		mcr_r |= bits;		/* Mask in bits	*/
		break;

	case TIOCMBIC:
		DEBUGCONT2(ASY_DEBUG_MODEM, "asy%dmctl: TIOCMBIC, bits = %x\n",
		    instance, bits);
		mcr_r &= ~bits;		/* Mask out bits */
		break;

	case TIOCMGET:
		/* Read Modem Status Registers */
		/*
		 * If modem interrupts are enabled, we return the
		 * saved value of msr. We read MSR only in async_msint()
		 */
		if (ddi_get8(asy->asy_iohandle,
		    asy->asy_ioaddr + ICR) & MIEN) {
			msr_r = asy->asy_msr;
			DEBUGCONT2(ASY_DEBUG_MODEM,
			    "asy%dmctl: TIOCMGET, read msr_r = %x\n",
			    instance, msr_r);
		} else {
			msr_r = ddi_get8(asy->asy_iohandle,
			    asy->asy_ioaddr + MSR);
			DEBUGCONT2(ASY_DEBUG_MODEM,
			    "asy%dmctl: TIOCMGET, read MSR = %x\n",
			    instance, msr_r);
		}
		DEBUGCONT2(ASY_DEBUG_MODEM, "asy%dtodm: modem_lines = %x\n",
		    instance, asytodm(mcr_r, msr_r));
		return (asytodm(mcr_r, msr_r));
	}

	ddi_put8(asy->asy_iohandle, asy->asy_ioaddr + MCR, mcr_r);

	return (mcr_r);
}

static int
asytodm(int mcr_r, int msr_r)
{
	int b = 0;

	/* MCR registers */
	if (mcr_r & RTS)
		b |= TIOCM_RTS;

	if (mcr_r & DTR)
		b |= TIOCM_DTR;

	/* MSR registers */
	if (msr_r & DCD)
		b |= TIOCM_CAR;

	if (msr_r & CTS)
		b |= TIOCM_CTS;

	if (msr_r & DSR)
		b |= TIOCM_DSR;

	if (msr_r & RI)
		b |= TIOCM_RNG;
	return (b);
}

static int
dmtoasy(int bits)
{
	int b = 0;

	DEBUGCONT1(ASY_DEBUG_MODEM, "dmtoasy: bits = %x\n", bits);
#ifdef	CAN_NOT_SET	/* only DTR and RTS can be set */
	if (bits & TIOCM_CAR)
		b |= DCD;
	if (bits & TIOCM_CTS)
		b |= CTS;
	if (bits & TIOCM_DSR)
		b |= DSR;
	if (bits & TIOCM_RNG)
		b |= RI;
#endif

	if (bits & TIOCM_RTS) {
		DEBUGCONT0(ASY_DEBUG_MODEM, "dmtoasy: set b & RTS\n");
		b |= RTS;
	}
	if (bits & TIOCM_DTR) {
		DEBUGCONT0(ASY_DEBUG_MODEM, "dmtoasy: set b & DTR\n");
		b |= DTR;
	}

	return (b);
}

static void
asyerror(int level, const char *fmt, ...)
{
	va_list adx;
	static	time_t	last;
	static	const char *lastfmt;
	time_t	now;

	/*
	 * Don't print the same error message too often.
	 * Print the message only if we have not printed the
	 * message within the last second.
	 * Note: that fmt cannot be a pointer to a string
	 * stored on the stack. The fmt pointer
	 * must be in the data segment otherwise lastfmt would point
	 * to non-sense.
	 */
	now = gethrestime_sec();
	if (last == now && lastfmt == fmt)
		return;

	last = now;
	lastfmt = fmt;

	va_start(adx, fmt);
	vcmn_err(level, fmt, adx);
	va_end(adx);
}

/*
 * asy_parse_mode(dev_info_t *devi, struct asycom *asy)
 * The value of this property is in the form of "9600,8,n,1,-"
 * 1) speed: 9600, 4800, ...
 * 2) data bits
 * 3) parity: n(none), e(even), o(odd)
 * 4) stop bits
 * 5) handshake: -(none), h(hardware: rts/cts), s(software: xon/off)
 *
 * This parsing came from a SPARCstation eeprom.
 */
static void
asy_parse_mode(dev_info_t *devi, struct asycom *asy)
{
	char		name[40];
	char		val[40];
	int		len;
	int		ret;
	char		*p;
	char		*p1;

	ASSERT(asy->asy_com_port != 0);

	/*
	 * Parse the ttyx-mode property
	 */
	(void) sprintf(name, "tty%c-mode", asy->asy_com_port + 'a' - 1);
	len = sizeof (val);
	ret = GET_PROP(devi, name, DDI_PROP_CANSLEEP, val, &len);
	if (ret != DDI_PROP_SUCCESS) {
		(void) sprintf(name, "com%c-mode", asy->asy_com_port + '0');
		len = sizeof (val);
		ret = GET_PROP(devi, name, DDI_PROP_CANSLEEP, val, &len);
	}

	/* no property to parse */
	asy->asy_cflag = 0;
	if (ret != DDI_PROP_SUCCESS)
		return;

	p = val;
	/* ---- baud rate ---- */
	asy->asy_cflag = CREAD|B9600;		/* initial default */
	if (p && (p1 = strchr(p, ',')) != 0) {
		*p1++ = '\0';
	} else {
		asy->asy_cflag |= BITS8;	/* add default bits */
		return;
	}

	if (strcmp(p, "110") == 0)
		asy->asy_bidx = B110;
	else if (strcmp(p, "150") == 0)
		asy->asy_bidx = B150;
	else if (strcmp(p, "300") == 0)
		asy->asy_bidx = B300;
	else if (strcmp(p, "600") == 0)
		asy->asy_bidx = B600;
	else if (strcmp(p, "1200") == 0)
		asy->asy_bidx = B1200;
	else if (strcmp(p, "2400") == 0)
		asy->asy_bidx = B2400;
	else if (strcmp(p, "4800") == 0)
		asy->asy_bidx = B4800;
	else if (strcmp(p, "9600") == 0)
		asy->asy_bidx = B9600;
	else if (strcmp(p, "19200") == 0)
		asy->asy_bidx = B19200;
	else if (strcmp(p, "38400") == 0)
		asy->asy_bidx = B38400;
	else if (strcmp(p, "57600") == 0)
		asy->asy_bidx = B57600;
	else if (strcmp(p, "115200") == 0)
		asy->asy_bidx = B115200;
	else
		asy->asy_bidx = B9600;

	asy->asy_cflag &= ~CBAUD;
	if (asy->asy_bidx > CBAUD) {	/* > 38400 uses the CBAUDEXT bit */
		asy->asy_cflag |= CBAUDEXT;
		asy->asy_cflag |= asy->asy_bidx - CBAUD - 1;
	} else {
		asy->asy_cflag |= asy->asy_bidx;
	}

	ASSERT(asy->asy_bidx == BAUDINDEX(asy->asy_cflag));

	/* ---- Next item is data bits ---- */
	p = p1;
	if (p && (p1 = strchr(p, ',')) != 0)  {
		*p1++ = '\0';
	} else {
		asy->asy_cflag |= BITS8;	/* add default bits */
		return;
	}
	switch (*p) {
		default:
		case '8':
			asy->asy_cflag |= CS8;
			asy->asy_lcr = BITS8;
			break;
		case '7':
			asy->asy_cflag |= CS7;
			asy->asy_lcr = BITS7;
			break;
		case '6':
			asy->asy_cflag |= CS6;
			asy->asy_lcr = BITS6;
			break;
		case '5':
			/* LINTED: CS5 is currently zero (but might change) */
			asy->asy_cflag |= CS5;
			asy->asy_lcr = BITS5;
			break;
	}

	/* ---- Parity info ---- */
	p = p1;
	if (p && (p1 = strchr(p, ',')) != 0)  {
		*p1++ = '\0';
	} else {
		return;
	}
	switch (*p)  {
		default:
		case 'n':
			break;
		case 'e':
			asy->asy_cflag |= PARENB;
			asy->asy_lcr |= PEN; break;
		case 'o':
			asy->asy_cflag |= PARENB|PARODD;
			asy->asy_lcr |= PEN|EPS;
			break;
	}

	/* ---- Find stop bits ---- */
	p = p1;
	if (p && (p1 = strchr(p, ',')) != 0)  {
		*p1++ = '\0';
	} else {
		return;
	}
	if (*p == '2') {
		asy->asy_cflag |= CSTOPB;
		asy->asy_lcr |= STB;
	}

	/* ---- handshake is next ---- */
	p = p1;
	if (p) {
		if ((p1 = strchr(p, ',')) != 0)
			*p1++ = '\0';

		if (*p == 'h')
			asy->asy_cflag |= CRTSCTS;
		else if (*p == 's')
			asy->asy_cflag |= CRTSXOFF;
	}
}

/*
 * Check for abort character sequence
 */
static boolean_t
abort_charseq_recognize(uchar_t ch)
{
	static int state = 0;
#define	CNTRL(c) ((c)&037)
	static char sequence[] = { '\r', '~', CNTRL('b') };

	if (ch == sequence[state]) {
		if (++state >= sizeof (sequence)) {
			state = 0;
			return (B_TRUE);
		}
	} else {
		state = (ch == sequence[0]) ? 1 : 0;
	}
	return (B_FALSE);
}

/*
 * Flow control functions
 */
/*
 * Software input flow control
 * This function can execute software input flow control sucessfully
 * at most of situations except that the line is in BREAK status
 * (timed and untimed break).
 * INPUT VALUE of onoff:
 *               FLOW_START means to send out a XON char
 *                          and clear SW input flow control flag.
 *               FLOW_STOP means to send out a XOFF char
 *                          and set SW input flow control flag.
 *               FLOW_CHECK means to check whether there is pending XON/XOFF
 *                          if it is true, send it out.
 * INPUT VALUE of type:
 *		 IN_FLOW_RINGBUFF means flow control is due to RING BUFFER
 *		 IN_FLOW_STREAMS means flow control is due to STREAMS
 *		 IN_FLOW_USER means flow control is due to user's commands
 * RETURN VALUE: B_FALSE means no flow control char is sent
 *               B_TRUE means one flow control char is sent
 */
static boolean_t
async_flowcontrol_sw_input(struct asycom *asy, async_flowc_action onoff,
    int type)
{
	struct asyncline *async = asy->asy_priv;
	int instance = UNIT(async->async_dev);
	int rval = B_FALSE;

	ASSERT(mutex_owned(&asy->asy_excl_hi));

	if (!(async->async_ttycommon.t_iflag & IXOFF))
		return (rval);

	/*
	 * If we get this far, then we know IXOFF is set.
	 */
	switch (onoff) {
	case FLOW_STOP:
		async->async_inflow_source |= type;

		/*
		 * We'll send an XOFF character for each of up to
		 * three different input flow control attempts to stop input.
		 * If we already send out one XOFF, but FLOW_STOP comes again,
		 * it seems that input flow control becomes more serious,
		 * then send XOFF again.
		 */
		if (async->async_inflow_source & (IN_FLOW_RINGBUFF |
		    IN_FLOW_STREAMS | IN_FLOW_USER))
			async->async_flags |= ASYNC_SW_IN_FLOW |
			    ASYNC_SW_IN_NEEDED;
		DEBUGCONT2(ASY_DEBUG_SFLOW, "async%d: input sflow stop, "
		    "type = %x\n", instance, async->async_inflow_source);
		break;
	case FLOW_START:
		async->async_inflow_source &= ~type;
		if (async->async_inflow_source == 0) {
			async->async_flags = (async->async_flags &
			    ~ASYNC_SW_IN_FLOW) | ASYNC_SW_IN_NEEDED;
			DEBUGCONT1(ASY_DEBUG_SFLOW, "async%d: "
			    "input sflow start\n", instance);
		}
		break;
	default:
		break;
	}

	if (((async->async_flags & (ASYNC_SW_IN_NEEDED | ASYNC_BREAK |
	    ASYNC_OUT_SUSPEND)) == ASYNC_SW_IN_NEEDED) &&
	    (ddi_get8(asy->asy_iohandle, asy->asy_ioaddr + LSR) & XHRE)) {
		/*
		 * If we get this far, then we know we need to send out
		 * XON or XOFF char.
		 */
		async->async_flags = (async->async_flags &
		    ~ASYNC_SW_IN_NEEDED) | ASYNC_BUSY;
		ddi_put8(asy->asy_iohandle, asy->asy_ioaddr + DAT,
		    async->async_flags & ASYNC_SW_IN_FLOW ?
		    async->async_stopc : async->async_startc);
		rval = B_TRUE;
	}
	return (rval);
}

/*
 * Software output flow control
 * This function can be executed sucessfully at any situation.
 * It does not handle HW, and just change the SW output flow control flag.
 * INPUT VALUE of onoff:
 *                 FLOW_START means to clear SW output flow control flag,
 *			also combine with HW output flow control status to
 *			determine if we need to set ASYNC_OUT_FLW_RESUME.
 *                 FLOW_STOP means to set SW output flow control flag,
 *			also clear ASYNC_OUT_FLW_RESUME.
 */
static void
async_flowcontrol_sw_output(struct asycom *asy, async_flowc_action onoff)
{
	struct asyncline *async = asy->asy_priv;
	int instance = UNIT(async->async_dev);

	ASSERT(mutex_owned(&asy->asy_excl_hi));

	if (!(async->async_ttycommon.t_iflag & IXON))
		return;

	switch (onoff) {
	case FLOW_STOP:
		async->async_flags |= ASYNC_SW_OUT_FLW;
		async->async_flags &= ~ASYNC_OUT_FLW_RESUME;
		DEBUGCONT1(ASY_DEBUG_SFLOW, "async%d: output sflow stop\n",
		    instance);
		break;
	case FLOW_START:
		async->async_flags &= ~ASYNC_SW_OUT_FLW;
		if (!(async->async_flags & ASYNC_HW_OUT_FLW))
			async->async_flags |= ASYNC_OUT_FLW_RESUME;
		DEBUGCONT1(ASY_DEBUG_SFLOW, "async%d: output sflow start\n",
		    instance);
		break;
	default:
		break;
	}
}

/*
 * Hardware input flow control
 * This function can be executed sucessfully at any situation.
 * It directly changes RTS depending on input parameter onoff.
 * INPUT VALUE of onoff:
 *       FLOW_START means to clear HW input flow control flag,
 *                  and pull up RTS if it is low.
 *       FLOW_STOP means to set HW input flow control flag,
 *                  and low RTS if it is high.
 * INPUT VALUE of type:
 *		 IN_FLOW_RINGBUFF means flow control is due to RING BUFFER
 *		 IN_FLOW_STREAMS means flow control is due to STREAMS
 *		 IN_FLOW_USER means flow control is due to user's commands
 */
static void
async_flowcontrol_hw_input(struct asycom *asy, async_flowc_action onoff,
    int type)
{
	uchar_t	mcr;
	uchar_t	flag;
	struct asyncline *async = asy->asy_priv;
	int instance = UNIT(async->async_dev);

	ASSERT(mutex_owned(&asy->asy_excl_hi));

	if (!(async->async_ttycommon.t_cflag & CRTSXOFF))
		return;

	switch (onoff) {
	case FLOW_STOP:
		async->async_inflow_source |= type;
		if (async->async_inflow_source & (IN_FLOW_RINGBUFF |
		    IN_FLOW_STREAMS | IN_FLOW_USER))
			async->async_flags |= ASYNC_HW_IN_FLOW;
		DEBUGCONT2(ASY_DEBUG_HFLOW, "async%d: input hflow stop, "
		    "type = %x\n", instance, async->async_inflow_source);
		break;
	case FLOW_START:
		async->async_inflow_source &= ~type;
		if (async->async_inflow_source == 0) {
			async->async_flags &= ~ASYNC_HW_IN_FLOW;
			DEBUGCONT1(ASY_DEBUG_HFLOW, "async%d: "
			    "input hflow start\n", instance);
		}
		break;
	default:
		break;
	}
	mcr = ddi_get8(asy->asy_iohandle, asy->asy_ioaddr + MCR);
	flag = (async->async_flags & ASYNC_HW_IN_FLOW) ? 0 : RTS;

	if (((mcr ^ flag) & RTS) != 0) {
		ddi_put8(asy->asy_iohandle,
		    asy->asy_ioaddr + MCR, (mcr ^ RTS));
	}
}

/*
 * Hardware output flow control
 * This function can execute HW output flow control sucessfully
 * at any situation.
 * It doesn't really change RTS, and just change
 * HW output flow control flag depending on CTS status.
 * INPUT VALUE of onoff:
 *                FLOW_START means to clear HW output flow control flag.
 *			also combine with SW output flow control status to
 *			determine if we need to set ASYNC_OUT_FLW_RESUME.
 *                FLOW_STOP means to set HW output flow control flag.
 *			also clear ASYNC_OUT_FLW_RESUME.
 */
static void
async_flowcontrol_hw_output(struct asycom *asy, async_flowc_action onoff)
{
	struct asyncline *async = asy->asy_priv;
	int instance = UNIT(async->async_dev);

	ASSERT(mutex_owned(&asy->asy_excl_hi));

	if (!(async->async_ttycommon.t_cflag & CRTSCTS))
		return;

	switch (onoff) {
	case FLOW_STOP:
		async->async_flags |= ASYNC_HW_OUT_FLW;
		async->async_flags &= ~ASYNC_OUT_FLW_RESUME;
		DEBUGCONT1(ASY_DEBUG_HFLOW, "async%d: output hflow stop\n",
		    instance);
		break;
	case FLOW_START:
		async->async_flags &= ~ASYNC_HW_OUT_FLW;
		if (!(async->async_flags & ASYNC_SW_OUT_FLW))
			async->async_flags |= ASYNC_OUT_FLW_RESUME;
		DEBUGCONT1(ASY_DEBUG_HFLOW, "async%d: output hflow start\n",
		    instance);
		break;
	default:
		break;
	}
}


/*
 * quiesce(9E) entry point.
 *
 * This function is called when the system is single-threaded at high
 * PIL with preemption disabled. Therefore, this function must not be
 * blocked.
 *
 * This function returns DDI_SUCCESS on success, or DDI_FAILURE on failure.
 * DDI_FAILURE indicates an error condition and should almost never happen.
 */
static int
asyquiesce(dev_info_t *devi)
{
	int instance;
	struct asycom *asy;

	instance = ddi_get_instance(devi);	/* find out which unit */

	asy = ddi_get_soft_state(asy_soft_state, instance);
	if (asy == NULL)
		return (DDI_FAILURE);

	/* disable all interrupts */
	ddi_put8(asy->asy_iohandle, asy->asy_ioaddr + ICR, 0);

	/* reset the FIFO */
	asy_reset_fifo(asy, FIFOTXFLSH | FIFORXFLSH);

	return (DDI_SUCCESS);
}
