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
 * Copyright 2023 Oxide Computer Company
 * Copyright 2024 Hans Rosenfeld
 */


/*
 * Serial I/O driver for 8250/16450/16550A/16650/16750/16950 chips.
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
#include <sys/sysmacros.h>

/*
 * set the RX FIFO trigger_level to half the RX FIFO size for now
 * we may want to make this configurable later.
 */
static	int asy_trig_level = ASY_FCR_RHR_TRIG_8;

int asy_drain_check = 15000000;		/* tunable: exit drain check time */
int asy_min_dtr_low = 500000;		/* tunable: minimum DTR down time */
int asy_min_utbrk = 100000;		/* tunable: minumum untimed brk time */

int asymaxchip = ASY_MAXCHIP;	/* tunable: limit chip support we look for */

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

static	int debug  = 0;

#define	ASY_DEBUG(asy, x) (asy->asy_debug & (x))
#define	ASY_DPRINTF(asy, fac, format, ...) \
	if (ASY_DEBUG(asy, fac)) \
		asyerror(asy, CE_CONT, "!%s: " format, __func__, ##__VA_ARGS__)
#else
#define	ASY_DEBUG(asy, x) B_FALSE
#define	ASY_DPRINTF(asy, fac, format, ...)
#endif

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

static void	asy_put_idx(const struct asycom *, asy_reg_t, uint8_t);
static uint8_t	asy_get_idx(const struct asycom *, asy_reg_t);

static void	asy_put_add(const struct asycom *, asy_reg_t, uint8_t);
static uint8_t	asy_get_add(const struct asycom *, asy_reg_t);

static void	asy_put_ext(const struct asycom *, asy_reg_t, uint8_t);
static uint8_t	asy_get_ext(const struct asycom *, asy_reg_t);

static void	asy_put_reg(const struct asycom *, asy_reg_t, uint8_t);
static uint8_t	asy_get_reg(const struct asycom *, asy_reg_t);

static void	asy_put(const struct asycom *, asy_reg_t, uint8_t);
static uint8_t	asy_get(const struct asycom *, asy_reg_t);

static void	asy_set(const struct asycom *, asy_reg_t, uint8_t);
static void	asy_clr(const struct asycom *, asy_reg_t, uint8_t);

static void	asy_enable_interrupts(const struct asycom *, uint8_t);
static void	asy_disable_interrupts(const struct asycom *, uint8_t);
static void	asy_set_baudrate(const struct asycom *, int);

static void	asysetsoft(struct asycom *);
static uint_t	asysoftintr(caddr_t, caddr_t);
static uint_t	asyintr(caddr_t, caddr_t);

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
static void	async_resume(struct asyncline *async);
static void	asy_program(struct asycom *asy, int mode);
static void	asyinit(struct asycom *asy);
static void	asy_waiteot(struct asycom *asy);
static void	asyputchar(cons_polledio_arg_t, uchar_t c);
static int	asygetchar(cons_polledio_arg_t);
static boolean_t	asyischar(cons_polledio_arg_t);

static int	asymctl(struct asycom *, int, int);
static int	asytodm(int, int);
static int	dmtoasy(struct asycom *, int);
static void	asyerror(struct asycom *, int, const char *, ...)
	__KPRINTFLIKE(3);
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
	0x0,	/* 921600 baud rate not supported */
	0x0,	/* 1000000 baud rate not supported */
	0x0,	/* 1152000 baud rate not supported */
	0x0,	/* 1500000 baud rate not supported */
	0x0,	/* 2000000 baud rate not supported */
	0x0,	/* 2500000 baud rate not supported */
	0x0,	/* 3000000 baud rate not supported */
	0x0,	/* 3500000 baud rate not supported */
	0x0,	/* 4000000 baud rate not supported */
};

/*
 * Register table. For each logical register, we define the minimum hwtype, the
 * register offset, and function pointers for reading and writing the register.
 * A NULL pointer indicates the register cannot be read from or written to,
 * respectively.
 */
static struct {
	int asy_min_hwtype;
	int8_t asy_reg_off;
	uint8_t (*asy_get_reg)(const struct asycom *, asy_reg_t);
	void (*asy_put_reg)(const struct asycom *, asy_reg_t, uint8_t);
} asy_reg_table[] = {
	[ASY_ILLEGAL] = { 0, -1, NULL, NULL },
	/* 8250 / 16450 / 16550 registers */
	[ASY_THR] =   { ASY_8250A,  0, NULL,	    asy_put_reg },
	[ASY_RHR] =   { ASY_8250A,  0, asy_get_reg, NULL },
	[ASY_IER] =   { ASY_8250A,  1, asy_get_reg, asy_put_reg },
	[ASY_FCR] =   { ASY_16550,  2, NULL,	    asy_put_reg },
	[ASY_ISR] =   { ASY_8250A,  2, asy_get_reg, NULL },
	[ASY_LCR] =   { ASY_8250A,  3, asy_get_reg, asy_put_reg },
	[ASY_MCR] =   { ASY_8250A,  4, asy_get_reg, asy_put_reg },
	[ASY_LSR] =   { ASY_8250A,  5, asy_get_reg, NULL },
	[ASY_MSR] =   { ASY_8250A,  6, asy_get_reg, NULL },
	[ASY_SPR] =   { ASY_8250A,  7, asy_get_reg, asy_put_reg },
	[ASY_DLL] =   { ASY_8250A,  0, asy_get_reg, asy_put_reg },
	[ASY_DLH] =   { ASY_8250A,  1, asy_get_reg, asy_put_reg },
	/* 16750 extended register */
	[ASY_EFR] =   { ASY_16750,  2, asy_get_ext, asy_put_ext },
	/* 16650 extended registers */
	[ASY_XON1] =  { ASY_16650,  4, asy_get_ext, asy_put_ext },
	[ASY_XON2] =  { ASY_16650,  5, asy_get_ext, asy_put_ext },
	[ASY_XOFF1] = { ASY_16650,  6, asy_get_ext, asy_put_ext },
	[ASY_XOFF2] = { ASY_16650,  7, asy_get_ext, asy_put_ext },
	/* 16950 additional registers */
	[ASY_ASR] =   { ASY_16950,  1, asy_get_add, asy_put_add },
	[ASY_RFL] =   { ASY_16950,  3, asy_get_add, NULL },
	[ASY_TFL] =   { ASY_16950,  4, asy_get_add, NULL },
	[ASY_ICR] =   { ASY_16950,  5, asy_get_reg, asy_put_reg },
	/* 16950 indexed registers */
	[ASY_ACR] =   { ASY_16950,  0, asy_get_idx, asy_put_idx },
	[ASY_CPR] =   { ASY_16950,  1, asy_get_idx, asy_put_idx },
	[ASY_TCR] =   { ASY_16950,  2, asy_get_idx, asy_put_idx },
	[ASY_CKS] =   { ASY_16950,  3, asy_get_idx, asy_put_idx },
	[ASY_TTL] =   { ASY_16950,  4, asy_get_idx, asy_put_idx },
	[ASY_RTL] =   { ASY_16950,  5, asy_get_idx, asy_put_idx },
	[ASY_FCL] =   { ASY_16950,  6, asy_get_idx, asy_put_idx },
	[ASY_FCH] =   { ASY_16950,  7, asy_get_idx, asy_put_idx },
	[ASY_ID1] =   { ASY_16950,  8, asy_get_idx, NULL },
	[ASY_ID2] =   { ASY_16950,  9, asy_get_idx, NULL },
	[ASY_ID3] =   { ASY_16950, 10, asy_get_idx, NULL },
	[ASY_REV] =   { ASY_16950, 11, asy_get_idx, NULL },
	[ASY_CSR] =   { ASY_16950, 12, NULL,	    asy_put_idx },
	[ASY_NMR] =   { ASY_16950, 13, asy_get_idx, asy_put_idx },
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

static void asy_intr_free(struct asycom *);
static int asy_intr_setup(struct asycom *, int);

static void asy_softintr_free(struct asycom *);
static int asy_softintr_setup(struct asycom *);

static int asy_suspend(struct asycom *);
static int asy_resume(dev_info_t *);

static int asyinfo(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg,
		void **result);
static int asyprobe(dev_info_t *);
static int asyattach(dev_info_t *, ddi_attach_cmd_t);
static int asydetach(dev_info_t *, ddi_detach_cmd_t);
static int asyquiesce(dev_info_t *);

static struct cb_ops cb_asy_ops = {
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
#ifdef DEBUG
		} else {
			if (debug & ASY_DEBUG_INIT)
				cmn_err(CE_NOTE, "!%s, debug = %x",
				    modldrv.drv_linkinfo, debug);
#endif
		}
	}
	return (i);
}

int
_fini(void)
{
	int i;

	if ((i = mod_remove(&modlinkage)) == 0) {
#ifdef DEBUG
		if (debug & ASY_DEBUG_INIT)
			cmn_err(CE_NOTE, "!%s unloading",
			    modldrv.drv_linkinfo);
#endif
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
static void
asy_put_idx(const struct asycom *asy, asy_reg_t reg, uint8_t val)
{
	ASSERT(asy->asy_hwtype >= ASY_16950);

	ASSERT(reg >= ASY_ACR);
	ASSERT(reg <= ASY_NREG);

	/*
	 * The last value written to LCR must not have been the magic value for
	 * EFR access. Every time the driver writes that magic value to access
	 * EFR, XON1, XON2, XOFF1, and XOFF2, the driver restores the original
	 * value of LCR, so we should be good here.
	 *
	 * I'd prefer to ASSERT this, but I'm not sure it's worth the hassle.
	 */

	/* Write indexed register offset to SPR. */
	asy_put(asy, ASY_SPR, asy_reg_table[reg].asy_reg_off);

	/* Write value to ICR. */
	asy_put(asy, ASY_ICR, val);
}

static uint8_t
asy_get_idx(const struct asycom *asy, asy_reg_t reg)
{
	uint8_t val;

	ASSERT(asy->asy_hwtype >= ASY_16950);

	ASSERT(reg >= ASY_ACR);
	ASSERT(reg <= ASY_NREG);

	/* Enable access to ICR in ACR. */
	asy_put(asy, ASY_ACR, ASY_ACR_ICR | asy->asy_acr);

	/* Write indexed register offset to SPR. */
	asy_put(asy, ASY_SPR, asy_reg_table[reg].asy_reg_off);

	/* Read value from ICR. */
	val = asy_get(asy, ASY_ICR);

	/* Restore ACR. */
	asy_put(asy, ASY_ACR, asy->asy_acr);

	return (val);
}

static void
asy_put_add(const struct asycom *asy, asy_reg_t reg, uint8_t val)
{
	ASSERT(asy->asy_hwtype >= ASY_16950);

	/* Only ASR is writable, RFL and TFL are read-only. */
	ASSERT(reg == ASY_ASR);

	/*
	 * Only ASR[0] (Transmitter Disabled) and ASR[1] (Remote Transmitter
	 * Disabled) are writable.
	 */
	ASSERT((val & ~(ASY_ASR_TD | ASY_ASR_RTD)) == 0);

	/* Enable access to ASR in ACR. */
	asy_put(asy, ASY_ACR, ASY_ACR_ASR | asy->asy_acr);

	/* Write value to ASR. */
	asy_put_reg(asy, reg, val);

	/* Restore ACR. */
	asy_put(asy, ASY_ACR, asy->asy_acr);
}

static uint8_t
asy_get_add(const struct asycom *asy, asy_reg_t reg)
{
	uint8_t val;

	ASSERT(asy->asy_hwtype >= ASY_16950);

	ASSERT(reg >= ASY_ASR);
	ASSERT(reg <= ASY_TFL);

	/*
	 * The last value written to LCR must not have been the magic value for
	 * EFR access. Every time the driver writes that magic value to access
	 * EFR, XON1, XON2, XOFF1, and XOFF2, the driver restores the original
	 * value of LCR, so we should be good here.
	 *
	 * I'd prefer to ASSERT this, but I'm not sure it's worth the hassle.
	 */

	/* Enable access to ASR in ACR. */
	asy_put(asy, ASY_ACR, ASY_ACR_ASR | asy->asy_acr);

	/* Read value from register. */
	val = asy_get_reg(asy, reg);

	/* Restore ACR. */
	asy_put(asy, ASY_ACR, 0 | asy->asy_acr);

	return (val);
}

static void
asy_put_ext(const struct asycom *asy, asy_reg_t reg, uint8_t val)
{
	uint8_t lcr;

	/*
	 * On the 16750, EFR can be accessed when LCR[7]=1 (DLAB).
	 * Only two bits are assigned for auto RTS/CTS, which we don't support
	 * yet.
	 *
	 * So insist we have a 16650 or up.
	 */
	ASSERT(asy->asy_hwtype >= ASY_16650);

	ASSERT(reg >= ASY_EFR);
	ASSERT(reg <= ASY_XOFF2);

	/* Save LCR contents. */
	lcr = asy_get(asy, ASY_LCR);

	/* Enable extended register access. */
	asy_put(asy, ASY_LCR, ASY_LCR_EFRACCESS);

	/* Write extended register */
	asy_put_reg(asy, reg, val);

	/* Restore previous LCR contents, disabling extended register access. */
	asy_put(asy, ASY_LCR, lcr);
}

static uint8_t
asy_get_ext(const struct asycom *asy, asy_reg_t reg)
{
	uint8_t lcr, val;

	/*
	 * On the 16750, EFR can be accessed when LCR[7]=1 (DLAB).
	 * Only two bits are assigned for auto RTS/CTS, which we don't support
	 * yet.
	 *
	 * So insist we have a 16650 or up.
	 */
	ASSERT(asy->asy_hwtype >= ASY_16650);

	ASSERT(reg >= ASY_EFR);
	ASSERT(reg <= ASY_XOFF2);

	/* Save LCR contents. */
	lcr = asy_get(asy, ASY_LCR);

	/* Enable extended register access. */
	asy_put(asy, ASY_LCR, ASY_LCR_EFRACCESS);

	/* Read extended register */
	val = asy_get_reg(asy, reg);

	/* Restore previous LCR contents, disabling extended register access. */
	asy_put(asy, ASY_LCR, lcr);

	return (val);
}

static void
asy_put_reg(const struct asycom *asy, asy_reg_t reg, uint8_t val)
{
	ASSERT(asy->asy_hwtype >= asy_reg_table[reg].asy_min_hwtype);

	ddi_put8(asy->asy_iohandle,
	    asy->asy_ioaddr + asy_reg_table[reg].asy_reg_off, val);
}

static uint8_t
asy_get_reg(const struct asycom *asy, asy_reg_t reg)
{
	ASSERT(asy->asy_hwtype >= asy_reg_table[reg].asy_min_hwtype);

	return (ddi_get8(asy->asy_iohandle,
	    asy->asy_ioaddr + asy_reg_table[reg].asy_reg_off));
}

static void
asy_put(const struct asycom *asy, asy_reg_t reg, uint8_t val)
{
	ASSERT(mutex_owned(&asy->asy_excl_hi));

	ASSERT(reg > ASY_ILLEGAL);
	ASSERT(reg < ASY_NREG);

	ASSERT(asy->asy_hwtype >= asy_reg_table[reg].asy_min_hwtype);
	ASSERT(asy_reg_table[reg].asy_put_reg != NULL);

	asy_reg_table[reg].asy_put_reg(asy, reg, val);
}

static uint8_t
asy_get(const struct asycom *asy, asy_reg_t reg)
{
	uint8_t val;

	ASSERT(mutex_owned(&asy->asy_excl_hi));

	ASSERT(reg > ASY_ILLEGAL);
	ASSERT(reg < ASY_NREG);

	ASSERT(asy->asy_hwtype >= asy_reg_table[reg].asy_min_hwtype);
	ASSERT(asy_reg_table[reg].asy_get_reg != NULL);

	val = asy_reg_table[reg].asy_get_reg(asy, reg);

	return (val);
}

static void
asy_set(const struct asycom *asy, asy_reg_t reg, uint8_t bits)
{
	uint8_t val = asy_get(asy, reg);

	asy_put(asy, reg, val | bits);
}

static void
asy_clr(const struct asycom *asy, asy_reg_t reg, uint8_t bits)
{
	uint8_t val = asy_get(asy, reg);

	asy_put(asy, reg, val & ~bits);
}

static void
asy_enable_interrupts(const struct asycom *asy, uint8_t intr)
{
	/* Don't touch any IER bits we don't support. */
	intr &= ASY_IER_ALL;

	asy_set(asy, ASY_IER, intr);
}

static void
asy_disable_interrupts(const struct asycom *asy, uint8_t intr)
{
	/* Don't touch any IER bits we don't support. */
	intr &= ASY_IER_ALL;

	asy_clr(asy, ASY_IER, intr);
}

static void
asy_set_baudrate(const struct asycom *asy, int baudrate)
{
	if (baudrate == 0)
		return;

	asy_set(asy, ASY_LCR, ASY_LCR_DLAB);

	asy_put(asy, ASY_DLL, asyspdtab[baudrate] & 0xff);
	asy_put(asy, ASY_DLH, (asyspdtab[baudrate] >> 8) & 0xff);

	asy_clr(asy, ASY_LCR, ASY_LCR_DLAB);
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
	char *prop;
	int bustype;

	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, devinfo, 0, "device_type",
	    &prop) != DDI_PROP_SUCCESS &&
	    ddi_prop_lookup_string(DDI_DEV_T_ANY, devinfo, 0, "bus-type",
	    &prop) != DDI_PROP_SUCCESS) {
		dev_err(devinfo, CE_WARN,
		    "!%s: can't figure out device type for parent \"%s\"",
		    __func__, ddi_get_name(ddi_get_parent(devinfo)));
		return (ASY_BUS_UNKNOWN);
	}

	if (strcmp(prop, "isa") == 0)
		bustype = ASY_BUS_ISA;
	else if (strcmp(prop, "pci") == 0)
		bustype = ASY_BUS_PCI;
	else if (strcmp(prop, "pciex") == 0)
		return (ASY_BUS_PCI);
	else
		bustype = ASY_BUS_UNKNOWN;

	ddi_prop_free(prop);
	return (bustype);
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
		dev_err(devi, CE_WARN, "!%s: reg property"
		    " not found in devices property list", __func__);
		return (-1);
	}

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
	int regnum = -1;
	int reglen, nregs;
	struct {
		uint_t bustype;
		int base;
		int size;
	} *reglist;

	if (ddi_getlongprop(DDI_DEV_T_ANY, devi, DDI_PROP_DONTPASS,
	    "reg", (caddr_t)&reglist, &reglen) != DDI_PROP_SUCCESS) {
		dev_err(devi, CE_WARN, "!%s: reg property not found "
		    "in devices property list", __func__);
		return (-1);
	}

	nregs = reglen / sizeof (*reglist);

	/*
	 * Find the first I/O bus in the "reg" property.
	 */
	for (int i = 0; i < nregs && regnum == -1; i++) {
		if (reglist[i].bustype == 1) {
			regnum = i;
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

static void
asy_intr_free(struct asycom *asy)
{
	int i;

	for (i = 0; i < asy->asy_intr_cnt; i++) {
		if (asy->asy_inth[i] == NULL)
			break;

		if ((asy->asy_intr_cap & DDI_INTR_FLAG_BLOCK) != 0)
			(void) ddi_intr_block_disable(&asy->asy_inth[i], 1);
		else
			(void) ddi_intr_disable(asy->asy_inth[i]);

		(void) ddi_intr_remove_handler(asy->asy_inth[i]);
		(void) ddi_intr_free(asy->asy_inth[i]);
	}

	kmem_free(asy->asy_inth, asy->asy_inth_sz);
	asy->asy_inth = NULL;
	asy->asy_inth_sz = 0;
}

static int
asy_intr_setup(struct asycom *asy, int intr_type)
{
	int nintrs, navail, count;
	int ret;
	int i;

	if (asy->asy_intr_types == 0) {
		ret = ddi_intr_get_supported_types(asy->asy_dip,
		    &asy->asy_intr_types);
		if (ret != DDI_SUCCESS) {
			asyerror(asy, CE_WARN,
			    "ddi_intr_get_supported_types failed");
			return (ret);
		}
	}

	if ((asy->asy_intr_types & intr_type) == 0)
		return (DDI_FAILURE);

	ret = ddi_intr_get_nintrs(asy->asy_dip, intr_type, &nintrs);
	if (ret != DDI_SUCCESS) {
		asyerror(asy, CE_WARN, "ddi_intr_get_nintrs failed, type %d",
		    intr_type);
		return (ret);
	}

	if (nintrs < 1) {
		asyerror(asy, CE_WARN, "no interrupts of type %d", intr_type);
		return (DDI_FAILURE);
	}

	ret = ddi_intr_get_navail(asy->asy_dip, intr_type, &navail);
	if (ret != DDI_SUCCESS) {
		asyerror(asy, CE_WARN, "ddi_intr_get_navail failed, type %d",
		    intr_type);
		return (ret);
	}

	if (navail < 1) {
		asyerror(asy, CE_WARN, "no available interrupts, type %d",
		    intr_type);
		return (DDI_FAILURE);
	}

	/*
	 * Some PCI(e) RS232 adapters seem to support more than one interrupt,
	 * but the asy driver really doesn't.
	 */
	asy->asy_inth_sz = sizeof (ddi_intr_handle_t);
	asy->asy_inth = kmem_zalloc(asy->asy_inth_sz, KM_SLEEP);
	ret = ddi_intr_alloc(asy->asy_dip, asy->asy_inth, intr_type, 0, 1,
	    &count, 0);
	if (ret != DDI_SUCCESS) {
		asyerror(asy, CE_WARN, "ddi_intr_alloc failed, count %d, "
		    "type %d", navail, intr_type);
		goto fail;
	}

	if (count != 1) {
		asyerror(asy, CE_WARN, "ddi_intr_alloc returned not 1 but %d "
		    "interrupts of type %d", count, intr_type);
		goto fail;
	}

	asy->asy_intr_cnt = count;

	ret = ddi_intr_get_pri(asy->asy_inth[0], &asy->asy_intr_pri);
	if (ret != DDI_SUCCESS) {
		asyerror(asy, CE_WARN, "ddi_intr_get_pri failed, type %d",
		    intr_type);
		goto fail;
	}

	for (i = 0; i < count; i++) {
		ret = ddi_intr_add_handler(asy->asy_inth[i], asyintr,
		    (void *)asy, (void *)(uintptr_t)i);
		if (ret != DDI_SUCCESS) {
			asyerror(asy, CE_WARN, "ddi_intr_add_handler failed, "
			    "int %d, type %d", i, intr_type);
			goto fail;
		}
	}

	(void) ddi_intr_get_cap(asy->asy_inth[0], &asy->asy_intr_cap);

	for (i = 0; i < count; i++) {
		if (asy->asy_intr_cap & DDI_INTR_FLAG_BLOCK)
			ret = ddi_intr_block_enable(&asy->asy_inth[i], 1);
		else
			ret = ddi_intr_enable(asy->asy_inth[i]);

		if (ret != DDI_SUCCESS) {
			asyerror(asy, CE_WARN,
			    "enabling interrupt %d failed, type %d",
			    i, intr_type);
			goto fail;
		}
	}

	asy->asy_intr_type = intr_type;
	return (DDI_SUCCESS);

fail:
	asy_intr_free(asy);
	return (ret);
}

static void
asy_softintr_free(struct asycom *asy)
{
	(void) ddi_intr_remove_softint(asy->asy_soft_inth);
}

static int
asy_softintr_setup(struct asycom *asy)
{
	int ret;

	ret = ddi_intr_add_softint(asy->asy_dip, &asy->asy_soft_inth,
	    ASY_SOFT_INT_PRI, asysoftintr, asy);
	if (ret != DDI_SUCCESS) {
		asyerror(asy, CE_WARN, "ddi_intr_add_softint failed");
		return (ret);
	}

	/*
	 * This may seem pointless since we specified ASY_SOFT_INT_PRI above,
	 * but then it's probably a good idea to consider the soft interrupt
	 * priority an opaque value and don't hardcode any assumptions about
	 * its actual value here.
	 */
	ret = ddi_intr_get_softint_pri(asy->asy_soft_inth,
	    &asy->asy_soft_intr_pri);
	if (ret != DDI_SUCCESS) {
		asyerror(asy, CE_WARN, "ddi_intr_get_softint_pri failed");
		return (ret);
	}

	return (DDI_SUCCESS);
}


static int
asy_resume(dev_info_t *devi)
{
	struct asyncline *async;
	struct asycom *asy;
	int instance = ddi_get_instance(devi);	/* find out which unit */

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
	asy_disable_interrupts(asy, ASY_IER_ALL);
	if (asy_identify_chip(devi, asy) != DDI_SUCCESS) {
		mutex_exit(&asy->asy_excl_hi);
		mutex_exit(&asy->asy_excl);
		mutex_exit(&asy->asy_soft_sr);
		asyerror(asy, CE_WARN, "Cannot identify UART chip at %p",
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
		asysetsoft(asy);
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

static int
asy_suspend(struct asycom *asy)
{
	struct asyncline *async = asy->asy_priv;
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
		if (cv_wait_sig(&async->async_flags_cv, &asy->asy_excl) == 0) {
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

	asy_disable_interrupts(asy, ASY_IER_ALL);
	asy->asy_flags |= ASY_DDI_SUSPENDED;

	/*
	 * Hardware interrupts are disabled we can drop our high level
	 * lock and proceed.
	 */
	mutex_exit(&asy->asy_excl_hi);

	/* Process remaining RX characters and RX errors, if any */
	lsr = asy_get(asy, ASY_LSR);
	async_rxint(asy, lsr);

	/* Wait for TX to drain */
	for (i = 1000; i > 0; i--) {
		lsr = asy_get(asy, ASY_LSR);
		if ((lsr & (ASY_LSR_TEMT | ASY_LSR_THRE)) ==
		    (ASY_LSR_TEMT | ASY_LSR_THRE))
			break;
		delay(drv_usectohz(10000));
	}
	if (i == 0)
		asyerror(asy, CE_WARN, "transmitter wasn't drained before "
		    "driver was suspended");

	mutex_exit(&asy->asy_excl);
	mutex_exit(&asy->asy_soft_sr);

	return (DDI_SUCCESS);
}

static int
asydetach(dev_info_t *devi, ddi_detach_cmd_t cmd)
{
	int instance;
	struct asycom *asy;

	instance = ddi_get_instance(devi);	/* find out which unit */

	asy = ddi_get_soft_state(asy_soft_state, instance);
	if (asy == NULL)
		return (DDI_FAILURE);

	switch (cmd) {
	case DDI_DETACH:
		break;

	case DDI_SUSPEND:
		return (asy_suspend(asy));

	default:
		return (DDI_FAILURE);
	}

	ASY_DPRINTF(asy, ASY_DEBUG_INIT, "%s shutdown", asy_hw_name(asy));

	if ((asy->asy_progress & ASY_PROGRESS_ASYNC) != 0) {
		struct asyncline *async = asy->asy_priv;

		/* cancel DTR hold timeout */
		if (async->async_dtrtid != 0) {
			(void) untimeout(async->async_dtrtid);
			async->async_dtrtid = 0;
		}
		cv_destroy(&async->async_flags_cv);
		kmem_free(async, sizeof (struct asyncline));
		asy->asy_priv = NULL;
	}

	if ((asy->asy_progress & ASY_PROGRESS_MINOR) != 0)
		ddi_remove_minor_node(devi, NULL);

	if ((asy->asy_progress & ASY_PROGRESS_MUTEX) != 0) {
		mutex_destroy(&asy->asy_excl);
		mutex_destroy(&asy->asy_excl_hi);
		mutex_destroy(&asy->asy_soft_lock);
	}

	if ((asy->asy_progress & ASY_PROGRESS_INT) != 0)
		asy_intr_free(asy);

	if ((asy->asy_progress & ASY_PROGRESS_SOFTINT) != 0)
		asy_softintr_free(asy);

	if ((asy->asy_progress & ASY_PROGRESS_REGS) != 0)
		ddi_regs_map_free(&asy->asy_iohandle);

	ASY_DPRINTF(asy, ASY_DEBUG_INIT, "shutdown complete");
	asy_soft_state_free(asy);

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

	switch (cmd) {
	case DDI_ATTACH:
		break;

	case DDI_RESUME:
		return (asy_resume(devi));

	default:
		return (DDI_FAILURE);
	}

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
			asyerror(asy, CE_WARN,
			    "More than %d motherboard-serial-ports",
			    num_com_ports);
		}
	}
	mutex_exit(&asy_glob_lock);


	instance = ddi_get_instance(devi);	/* find out which unit */
	ret = ddi_soft_state_zalloc(asy_soft_state, instance);
	if (ret != DDI_SUCCESS)
		return (DDI_FAILURE);
	asy = ddi_get_soft_state(asy_soft_state, instance);

	asy->asy_dip = devi;
#ifdef DEBUG
	asy->asy_debug = debug;
#endif
	asy->asy_unit = instance;

	regnum = asy_get_io_regnum(devi, asy);

	if (regnum < 0 ||
	    ddi_regs_map_setup(devi, regnum, (caddr_t *)&asy->asy_ioaddr,
	    (offset_t)0, (offset_t)0, &ioattr, &asy->asy_iohandle)
	    != DDI_SUCCESS) {
		asyerror(asy, CE_WARN, "could not map UART registers @ %p",
		    (void *)asy->asy_ioaddr);
		goto fail;
	}

	asy->asy_progress |= ASY_PROGRESS_REGS;

	ASY_DPRINTF(asy, ASY_DEBUG_INIT, "UART @ %p", (void *)asy->asy_ioaddr);

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
	 * It appears that there was async hardware that on reset did not clear
	 * IER.  Hence when we enable interrupts, this hardware would cause the
	 * system to hang if there was input available.
	 *
	 * Don't use asy_disable_interrupts() as the mutexes haven't been
	 * initialized yet.
	 */
	ddi_put8(asy->asy_iohandle, asy->asy_ioaddr + ASY_IER, 0);


	/*
	 * Establish default settings:
	 * - use RTS/DTR after open
	 * - 8N1 data format
	 * - 9600 baud
	 */
	asy->asy_mcr |= ASY_MCR_RTS | ASY_MCR_DTR;
	asy->asy_lcr = ASY_LCR_STOP1 | ASY_LCR_BITS8;
	asy->asy_bidx = B9600;
	asy->asy_fifo_buf = 1;
	asy->asy_use_fifo = ASY_FCR_FIFO_OFF;

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
			ASY_DPRINTF(asy, ASY_DEBUG_MODEM,
			    "clear ASY_IGNORE_CD");
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
			ASY_DPRINTF(asy, ASY_DEBUG_MODEM,
			    "set ASY_IGNORE_CD, set RTS & DTR");
			mcr = asy->asy_mcr;		/* rts/dtr on */
			asy->asy_flags |= ASY_IGNORE_CD;	/* ignore cd */
			break;
		}

		/* Property for not raising DTR/RTS */
		switch (asy_getproperty(devi, asy, "rts-dtr-off")) {
		case 0:				/* *-rts-dtr-off=False */
			asy->asy_flags |= ASY_RTS_DTR_OFF;	/* OFF */
			mcr = asy->asy_mcr;		/* rts/dtr on */
			ASY_DPRINTF(asy, ASY_DEBUG_MODEM,
			    "ASY_RTS_DTR_OFF set and DTR & RTS set");
			break;
		case 1:				/* *-rts-dtr-off=True */
			/*FALLTHRU*/
		default:			/* *-rts-dtr-off undefined */
			break;
		}

		/* Parse property for tty modes */
		asy_parse_mode(devi, asy);
	} else {
		ASY_DPRINTF(asy, ASY_DEBUG_MODEM,
		    "clear ASY_IGNORE_CD, clear RTS & DTR");
		asy->asy_flags &= ~ASY_IGNORE_CD;	/* wait for cd */
	}

	/*
	 * Install per instance software interrupt handler.
	 */
	if (asy_softintr_setup(asy) != DDI_SUCCESS) {
		asyerror(asy, CE_WARN, "Cannot set soft interrupt");
		goto fail;
	}

	asy->asy_progress |= ASY_PROGRESS_SOFTINT;

	/*
	 * Install interrupt handler for this device.
	 */
	if ((asy_intr_setup(asy, DDI_INTR_TYPE_MSIX) != DDI_SUCCESS) &&
	    (asy_intr_setup(asy, DDI_INTR_TYPE_MSI) != DDI_SUCCESS) &&
	    (asy_intr_setup(asy, DDI_INTR_TYPE_FIXED) != DDI_SUCCESS)) {
		asyerror(asy, CE_WARN, "Cannot set device interrupt");
		goto fail;
	}

	asy->asy_progress |= ASY_PROGRESS_INT;

	/*
	 * Initialize mutexes before accessing the hardware
	 */
	mutex_init(&asy->asy_soft_lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(asy->asy_soft_intr_pri));
	mutex_init(&asy->asy_soft_sr, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(asy->asy_soft_intr_pri));

	mutex_init(&asy->asy_excl, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&asy->asy_excl_hi, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(asy->asy_intr_pri));

	asy->asy_progress |= ASY_PROGRESS_MUTEX;

	mutex_enter(&asy->asy_excl);
	mutex_enter(&asy->asy_excl_hi);

	if (asy_identify_chip(devi, asy) != DDI_SUCCESS) {
		asyerror(asy, CE_WARN, "Cannot identify UART chip at %p",
		    (void *)asy->asy_ioaddr);
		goto fail;
	}

	asy_disable_interrupts(asy, ASY_IER_ALL);
	asy_put(asy, ASY_LCR, asy->asy_lcr);
	asy_set_baudrate(asy, asy->asy_bidx);
	asy_put(asy, ASY_MCR, mcr);

	mutex_exit(&asy->asy_excl_hi);
	mutex_exit(&asy->asy_excl);

	asyinit(asy);	/* initialize the asyncline structure */
	asy->asy_progress |= ASY_PROGRESS_ASYNC;

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
	    asy->asy_com_port != 0 ? DDI_NT_SERIAL_MB : DDI_NT_SERIAL, 0);
	if (status == DDI_SUCCESS) {
		(void) strcat(name, ",cu");
		status = ddi_create_minor_node(devi, name, S_IFCHR,
		    OUTLINE | instance,
		    asy->asy_com_port != 0 ? DDI_NT_SERIAL_MB_DO :
		    DDI_NT_SERIAL_DO, 0);
	}

	if (status != DDI_SUCCESS)
		goto fail;

	asy->asy_progress |= ASY_PROGRESS_MINOR;

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
	ASY_DPRINTF(asy, ASY_DEBUG_INIT, "done");
	return (DDI_SUCCESS);

fail:
	(void) asydetach(devi, DDI_DETACH);
	return (DDI_FAILURE);
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
	case ASY_8250A:
		return ("8250A/16450");
	case ASY_16550:
		return ("16550");
	case ASY_16550A:
		return ("16550A");
	case ASY_16650:
		return ("16650");
	case ASY_16750:
		return ("16750");
	case ASY_16950:
		return ("16950");
	}

	ASY_DPRINTF(asy, ASY_DEBUG_INIT, "unknown asy_hwtype: %d",
	    asy->asy_hwtype);
	return ("?");
}

static boolean_t
asy_is_devid(struct asycom *asy, char *venprop, char *devprop,
    int venid, int devid)
{
	int id;

	if (ddi_prop_get_int(DDI_DEV_T_ANY, asy->asy_dip, DDI_PROP_DONTPASS,
	    venprop, 0) != venid) {
		return (B_FALSE);
	}

	if (ddi_prop_get_int(DDI_DEV_T_ANY, asy->asy_dip, DDI_PROP_DONTPASS,
	    devprop, 0) != devid) {
		return (B_FALSE);
	}

	return (B_FALSE);
}

static void
asy_check_loopback(struct asycom *asy)
{
	if (asy_get_bus_type(asy->asy_dip) != ASY_BUS_PCI)
		return;

	/* Check if this is a Agere/Lucent Venus PCI modem chipset. */
	if (asy_is_devid(asy, "vendor-id", "device-id", 0x11c1, 0x0480) ||
	    asy_is_devid(asy, "subsystem-vendor-id", "subsystem-id", 0x11c1,
	    0x0480))
		asy->asy_flags2 |= ASY2_NO_LOOPBACK;
}

static int
asy_identify_chip(dev_info_t *devi, struct asycom *asy)
{
	int isr, lsr, mcr, spr;
	dev_t dev;
	uint_t hwtype;

	/*
	 * Initially, we'll assume we have the highest supported chip model
	 * until we find out what we actually have.
	 */
	asy->asy_hwtype = ASY_MAXCHIP;

	/*
	 * First, see if we can even do the loopback check, which may not work
	 * on certain hardware.
	 */
	asy_check_loopback(asy);

	if (asy_scr_test) {
		/* Check that the scratch register works. */

		/* write to scratch register */
		asy_put(asy, ASY_SPR, ASY_SPR_TEST);
		/* make sure that pattern doesn't just linger on the bus */
		asy_put(asy, ASY_FCR, 0x00);
		/* read data back from scratch register */
		spr = asy_get(asy, ASY_SPR);
		if (spr != ASY_SPR_TEST) {
			/*
			 * Scratch register not working.
			 * Probably not an async chip.
			 * 8250 and 8250B don't have scratch registers,
			 * but only worked in ancient PC XT's anyway.
			 */
			asyerror(asy, CE_WARN, "UART @ %p "
			    "scratch register: expected 0x5a, got 0x%02x",
			    (void *)asy->asy_ioaddr, spr);
			return (DDI_FAILURE);
		}
	}
	/*
	 * Use 16550 fifo reset sequence specified in NS application
	 * note. Disable fifos until chip is initialized.
	 */
	asy_put(asy, ASY_FCR, 0x00);				 /* disable */
	asy_put(asy, ASY_FCR, ASY_FCR_FIFO_EN);			 /* enable */
	asy_put(asy, ASY_FCR, ASY_FCR_FIFO_EN | ASY_FCR_RHR_FL); /* reset */
	if (asymaxchip >= ASY_16650 && asy_scr_test) {
		/*
		 * Reset 16650 enhanced regs also, in case we have one of these
		 */
		asy_put(asy, ASY_EFR, 0);
	}

	/*
	 * See what sort of FIFO we have.
	 * Try enabling it and see what chip makes of this.
	 */

	asy->asy_fifor = 0;
	if (asymaxchip >= ASY_16550A)
		asy->asy_fifor |=
		    ASY_FCR_FIFO_EN | ASY_FCR_DMA | (asy_trig_level & 0xff);

	/*
	 * On the 16750, FCR[5] enables the 64 byte FIFO. FCR[5] can only be set
	 * while LCR[7] = 1 (DLAB), which is taken care of by asy_reset_fifo().
	 */
	if (asymaxchip >= ASY_16750)
		asy->asy_fifor |= ASY_FCR_FIFO64;

	asy_reset_fifo(asy, ASY_FCR_THR_FL | ASY_FCR_RHR_FL);

	mcr = asy_get(asy, ASY_MCR);
	isr = asy_get(asy, ASY_ISR);

	/*
	 * Note we get 0xff if chip didn't return us anything,
	 * e.g. if there's no chip there.
	 */
	if (isr == 0xff) {
		asyerror(asy, CE_WARN, "UART @ %p interrupt register: got 0xff",
		    (void *)asy->asy_ioaddr);
		return (DDI_FAILURE);
	}

	ASY_DPRINTF(asy, ASY_DEBUG_CHIP,
	    "probe fifo FIFOR=0x%02x ISR=0x%02x MCR=0x%02x",
	    asy->asy_fifor | ASY_FCR_THR_FL | ASY_FCR_RHR_FL, isr, mcr);

	/*
	 * Detect the chip type by comparing ISR[7,6] and ISR[5].
	 *
	 * When the FIFOs are enabled by setting FCR[0], ISR[7,6] read as 1.
	 * Additionally on a 16750, the 64 byte FIFOs are enabled by setting
	 * FCR[5], and ISR[5] will read as 1, too.
	 *
	 * We will check later whether we have a 16650, which requires EFR[4]=1
	 * to enable its deeper FIFOs and extra features. It does not use FCR[5]
	 * and ISR[5] to enable deeper FIFOs like the 16750 does.
	 */
	switch (isr & (ASY_ISR_FIFOEN | ASY_ISR_FIFO64)) {
	case 0x40:				/* 16550 with broken FIFOs */
		hwtype = ASY_16550;
		asy->asy_fifor = 0;
		break;

	case ASY_ISR_FIFOEN:			/* 16550A with working FIFOs */
		hwtype = ASY_16550A;
		asy->asy_fifo_buf = 16;
		asy->asy_use_fifo = ASY_FCR_FIFO_EN;
		asy->asy_fifor &= ~ASY_FCR_FIFO64;
		break;

	case ASY_ISR_FIFOEN | ASY_ISR_FIFO64:	/* 16750 with 64byte FIFOs */
		hwtype = ASY_16750;
		asy->asy_fifo_buf = 64;
		asy->asy_use_fifo = ASY_FCR_FIFO_EN;
		break;

	default:				/* 8250A/16450 without FIFOs */
		hwtype = ASY_8250A;
		asy->asy_fifor = 0;
	}

	if (hwtype > asymaxchip) {
		asyerror(asy, CE_WARN, "UART @ %p "
		    "unexpected probe result: "
		    "FCR=0x%02x ISR=0x%02x MCR=0x%02x",
		    (void *)asy->asy_ioaddr,
		    asy->asy_fifor | ASY_FCR_THR_FL | ASY_FCR_RHR_FL, isr, mcr);
		return (DDI_FAILURE);
	}

	/*
	 * Now reset the FIFO operation appropriate for the chip type.
	 * Note we must call asy_reset_fifo() before any possible
	 * downgrade of the asy->asy_hwtype, or it may not disable
	 * the more advanced features we specifically want downgraded.
	 */
	asy_reset_fifo(asy, 0);

	/*
	 * Check for Exar/Startech ST16C650 or newer, which will still look like
	 * a 16550A until we enable its enhanced mode.
	 */
	if (hwtype >= ASY_16550A && asymaxchip >= ASY_16650 &&
	    asy_scr_test) {
		/*
		 * Write the XOFF2 register, which shadows SPR on the 16650.
		 * On other chips, SPR will be overwritten.
		 */
		asy_put(asy, ASY_XOFF2, 0);

		/* read back scratch register */
		spr = asy_get(asy, ASY_SPR);

		if (spr == ASY_SPR_TEST) {
			/* looks like we have an ST16650 -- enable it */
			hwtype = ASY_16650;
			asy_put(asy, ASY_EFR, ASY_EFR_ENH_EN);

			/*
			 * Some 16650-compatible chips are also compatible with
			 * the 16750 and have deeper FIFOs, which we may have
			 * detected above. Don't downgrade the FIFO size.
			 */
			if (asy->asy_fifo_buf < 32)
				asy->asy_fifo_buf = 32;

			/*
			 * Use a 24 byte transmit FIFO trigger only if were
			 * allowed to use >16 transmit FIFO depth by the
			 * global tunable.
			 */
			if (asy_max_tx_fifo >= asy->asy_fifo_buf)
				asy->asy_fifor |= ASY_FCR_THR_TRIG_24;
			asy_reset_fifo(asy, 0);
		}
	}

	/*
	 * If we think we got a 16650, we may actually have a 16950, so check
	 * for that.
	 */
	if (hwtype >= ASY_16650 && asymaxchip >= ASY_16950) {
		uint8_t ier, asr;

		/*
		 * First, clear IER and read it back. That should be a no-op as
		 * either asyattach() or asy_resume() disabled all interrupts
		 * before we were called.
		 */
		asy_put(asy, ASY_IER, 0);
		ier = asy_get(asy, ASY_IER);
		if (ier != 0) {
			dev_err(asy->asy_dip, CE_WARN, "!%s: UART @ %p "
			    "interrupt enable register: got 0x%02x", __func__,
			    (void *)asy->asy_ioaddr, ier);
			return (DDI_FAILURE);
		}

		/*
		 * Next, try to read ASR, which shares the register offset with
		 * IER. ASR can only be read if the ASR enable bit is set in
		 * ACR, which itself is an indexed registers. This is taken care
		 * of by asy_get().
		 *
		 * There are a few bits in ASR which should be 1 at this point,
		 * definitely the TX idle bit (ASR[7]) and also the FIFO size
		 * bit (ASR[6]) since we've done everything we can to enable any
		 * deeper FIFO support.
		 *
		 * Thus if we read back ASR as 0, we failed to read it, and this
		 * isn't the chip we're looking for.
		 */
		asr = asy_get(asy, ASY_ASR);

		if (asr != ier) {
			hwtype = ASY_16950;

			if ((asr & ASY_ASR_FIFOSZ) != 0)
				asy->asy_fifo_buf = 128;
			else
				asy->asy_fifo_buf = 16;

			asy_reset_fifo(asy, 0);

			/*
			 * Enable 16950 specific trigger level registers. Set
			 * DTR pin to be compatible to 16450, 16550, and 16750.
			 */
			asy->asy_acr = ASY_ACR_TRIG | ASY_ACR_DTR_NORM;
			asy_put(asy, ASY_ACR, asy->asy_acr);

			/* Set half the FIFO size as receive trigger level. */
			asy_put(asy, ASY_RTL, asy->asy_fifo_buf/2);

			/*
			 * Set the transmit trigger level to 1.
			 *
			 * While one would expect that any transmit trigger
			 * level would work (the 16550 uses a hardwired level
			 * of 16), in my tests with a 16950 compatible chip
			 * (MosChip 9912) I would never see a TX interrupt
			 * on any transmit trigger level > 1.
			 */
			asy_put(asy, ASY_TTL, 1);

			ASY_DPRINTF(asy, ASY_DEBUG_CHIP, "ASR 0x%02x", asr);
			ASY_DPRINTF(asy, ASY_DEBUG_CHIP, "RFL 0x%02x",
			    asy_get(asy, ASY_RFL));
			ASY_DPRINTF(asy, ASY_DEBUG_CHIP, "TFL 0x%02x",
			    asy_get(asy, ASY_TFL));

			ASY_DPRINTF(asy, ASY_DEBUG_CHIP, "ACR 0x%02x",
			    asy_get(asy, ASY_ACR));
			ASY_DPRINTF(asy, ASY_DEBUG_CHIP, "CPR 0x%02x",
			    asy_get(asy, ASY_CPR));
			ASY_DPRINTF(asy, ASY_DEBUG_CHIP, "TCR 0x%02x",
			    asy_get(asy, ASY_TCR));
			ASY_DPRINTF(asy, ASY_DEBUG_CHIP, "CKS 0x%02x",
			    asy_get(asy, ASY_CKS));
			ASY_DPRINTF(asy, ASY_DEBUG_CHIP, "TTL 0x%02x",
			    asy_get(asy, ASY_TTL));
			ASY_DPRINTF(asy, ASY_DEBUG_CHIP, "RTL 0x%02x",
			    asy_get(asy, ASY_RTL));
			ASY_DPRINTF(asy, ASY_DEBUG_CHIP, "FCL 0x%02x",
			    asy_get(asy, ASY_FCL));
			ASY_DPRINTF(asy, ASY_DEBUG_CHIP, "FCH 0x%02x",
			    asy_get(asy, ASY_FCH));

			ASY_DPRINTF(asy, ASY_DEBUG_CHIP,
			    "Chip ID: %02x%02x%02x,%02x",
			    asy_get(asy, ASY_ID1), asy_get(asy, ASY_ID2),
			    asy_get(asy, ASY_ID3), asy_get(asy, ASY_REV));

		}
	}

	asy->asy_hwtype = hwtype;

	/*
	 * If we think we might have a FIFO larger than 16 characters,
	 * measure FIFO size and check it against expected.
	 */
	if (asy_fifo_test > 0 &&
	    !(asy->asy_flags2 & ASY2_NO_LOOPBACK) &&
	    (asy->asy_fifo_buf > 16 ||
	    (asy_fifo_test > 1 && asy->asy_use_fifo == ASY_FCR_FIFO_EN) ||
	    ASY_DEBUG(asy, ASY_DEBUG_CHIP))) {
		int i;

		/* Set baud rate to 57600 (fairly arbitrary choice) */
		asy_set_baudrate(asy, B57600);
		/* Set 8 bits, 1 stop bit */
		asy_put(asy, ASY_LCR, ASY_LCR_STOP1 | ASY_LCR_BITS8);
		/* Set loopback mode */
		asy_put(asy, ASY_MCR, ASY_MCR_LOOPBACK);

		/* Overfill fifo */
		for (i = 0; i < asy->asy_fifo_buf * 2; i++) {
			asy_put(asy, ASY_THR, i);
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
			lsr = asy_get(asy, ASY_LSR);
			if (!(lsr & ASY_LSR_DR))
				break;	/* FIFO emptied */
			(void) asy_get(asy, ASY_RHR); /* lose another */
		}

		ASY_DPRINTF(asy, ASY_DEBUG_CHIP,
		    "FIFO size: expected=%d, measured=%d",
		    asy->asy_fifo_buf, i);

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
				hwtype = ASY_16550A;
				asy->asy_fifo_buf = 16;
				asy->asy_fifor &=
				    ~(ASY_FCR_THR_TR0 | ASY_FCR_THR_TR1);
			} else {
				/* fall back to no FIFO at all */
				hwtype = ASY_16550;
				asy->asy_fifo_buf = 1;
				asy->asy_use_fifo = ASY_FCR_FIFO_OFF;
				asy->asy_fifor = 0;
			}
		} else if (i > asy->asy_fifo_buf) {
			/*
			 * The FIFO is larger than expected. Use it if it is
			 * a power of 2.
			 */
			if (ISP2(i))
				asy->asy_fifo_buf = i;
		}

		/*
		 * We will need to reprogram the FIFO if we changed
		 * our mind about how to drive it above, and in any
		 * case, it would be a good idea to flush any garbage
		 * out incase the loopback test left anything behind.
		 * Again as earlier above, we must call asy_reset_fifo()
		 * before any possible downgrade of asy->asy_hwtype.
		 */
		if (asy->asy_hwtype >= ASY_16650 && hwtype < ASY_16650) {
			/* Disable 16650 enhanced mode */
			asy_put(asy, ASY_EFR, 0);
		}
		asy_reset_fifo(asy, ASY_FCR_THR_FL | ASY_FCR_RHR_FL);
		asy->asy_hwtype = hwtype;

		/* Clear loopback mode and restore DTR/RTS */
		asy_put(asy, ASY_MCR, mcr);
	}

	ASY_DPRINTF(asy, ASY_DEBUG_CHIP, "%s @ %p",
	    asy_hw_name(asy), (void *)asy->asy_ioaddr);

	/* Make UART type visible in device tree for prtconf, etc */
	dev = makedevice(DDI_MAJOR_T_UNKNOWN, asy->asy_unit);
	(void) ddi_prop_update_string(dev, devi, "uart", asy_hw_name(asy));

	if (asy->asy_hwtype == ASY_16550)	/* for broken 16550's, */
		asy->asy_hwtype = ASY_8250A;	/* drive them as 8250A */

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
	int		len;
	struct termios	*termiosp;

	unit = UNIT(*dev);
	asy = ddi_get_soft_state(asy_soft_state, unit);
	if (asy == NULL)
		return (ENXIO);		/* unit not configured */
	ASY_DPRINTF(asy, ASY_DEBUG_CLOSE, "enter");
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
		} else {
			asyerror(asy, CE_WARN,
			    "couldn't get ttymodes property");
		}
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
	} else if ((async->async_ttycommon.t_flags & TS_XCLUDE) &&
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
		ASY_DPRINTF(asy, ASY_DEBUG_MODEM,
		    "waiting for the ASYNC_DTR_DELAY to be clear");
		mutex_exit(&asy->asy_excl_hi);
		if (cv_wait_sig(&async->async_flags_cv,
		    &asy->asy_excl) == 0) {
			ASY_DPRINTF(asy, ASY_DEBUG_MODEM,
			    "interrupted by signal, exiting");
			mutex_exit(&asy->asy_excl);
			return (EINTR);
		}
		mutex_enter(&asy->asy_excl_hi);
	}

	asy_set(asy, ASY_MCR, asy->asy_mcr & ASY_MCR_DTR);

	ASY_DPRINTF(asy, ASY_DEBUG_INIT, "\"Raise DTR on every open\": "
	    "make mcr = %x, make TS_SOFTCAR = %s", asy_get(asy, ASY_MCR),
	    (asy->asy_flags & ASY_IGNORE_CD) ? "ON" : "OFF");

	if (asy->asy_flags & ASY_IGNORE_CD) {
		ASY_DPRINTF(asy, ASY_DEBUG_MODEM,
		    "ASY_IGNORE_CD set, set TS_SOFTCAR");
		async->async_ttycommon.t_flags |= TS_SOFTCAR;
	}
	else
		async->async_ttycommon.t_flags &= ~TS_SOFTCAR;

	/*
	 * Check carrier.
	 */
	asy->asy_msr = asy_get(asy, ASY_MSR);
	ASY_DPRINTF(asy, ASY_DEBUG_INIT, "TS_SOFTCAR is %s, MSR & DCD is %s",
	    (async->async_ttycommon.t_flags & TS_SOFTCAR) ? "set" : "clear",
	    (asy->asy_msr & ASY_MSR_DCD) ? "set" : "clear");

	if (asy->asy_msr & ASY_MSR_DCD)
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
	ASY_DPRINTF(asy, ASY_DEBUG_INIT, "done");
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

	ASY_DPRINTF(asy, ASY_DEBUG_MODEM,
	    "async_dtr_free, clearing ASYNC_DTR_DELAY");
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
	int ier, lcr;

	async = (struct asyncline *)q->q_ptr;
	ASSERT(async != NULL);

	asy = async->async_common;

	ASY_DPRINTF(asy, ASY_DEBUG_CLOSE, "enter");

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
		(void) asy_clr(asy, ASY_LCR, ASY_LCR_SETBRK);
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
	ASY_DPRINTF(asy, ASY_DEBUG_MODEM, "next check HUPCL flag");
	mutex_enter(&asy->asy_excl_hi);
	if ((async->async_ttycommon.t_cflag & HUPCL) ||
	    (async->async_flags & ASYNC_WOPEN)) {
		ASY_DPRINTF(asy, ASY_DEBUG_MODEM,
		    "HUPCL flag = %x, ASYNC_WOPEN flag = %x",
		    async->async_ttycommon.t_cflag & HUPCL,
		    async->async_ttycommon.t_cflag & ASYNC_WOPEN);
		async->async_flags |= ASYNC_DTR_DELAY;

		/* turn off DTR, RTS but NOT interrupt to 386 */
		if (asy->asy_flags & (ASY_IGNORE_CD|ASY_RTS_DTR_OFF)) {
			ASY_DPRINTF(asy, ASY_DEBUG_MODEM,
			    "ASY_IGNORE_CD flag = %x, "
			    "ASY_RTS_DTR_OFF flag = %x",
			    asy->asy_flags & ASY_IGNORE_CD,
			    asy->asy_flags & ASY_RTS_DTR_OFF);

			asy_put(asy, ASY_MCR, asy->asy_mcr | ASY_MCR_OUT2);
		} else {
			ASY_DPRINTF(asy, ASY_DEBUG_MODEM,
			    "Dropping DTR and RTS");
			asy_put(asy, ASY_MCR, ASY_MCR_OUT2);
		}
		async->async_dtrtid =
		    timeout((void (*)())async_dtr_free,
		    (caddr_t)async, drv_usectohz(asy_min_dtr_low));
	}
	/*
	 * If nobody's using it now, turn off receiver interrupts.
	 */
	if ((async->async_flags & (ASYNC_WOPEN|ASYNC_ISOPEN)) == 0)
		asy_disable_interrupts(asy, ASY_IER_RIEN);

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

	ASY_DPRINTF(asy, ASY_DEBUG_CLOSE, "done");
	return (0);
}

static boolean_t
asy_isbusy(struct asycom *asy)
{
	struct asyncline *async;

	ASY_DPRINTF(asy, ASY_DEBUG_EOT, "enter");
	async = asy->asy_priv;
	ASSERT(mutex_owned(&asy->asy_excl));
	ASSERT(mutex_owned(&asy->asy_excl_hi));
/*
 * XXXX this should be recoded
 */
	return ((async->async_ocnt > 0) ||
	    ((asy_get(asy, ASY_LSR) & (ASY_LSR_TEMT | ASY_LSR_THRE)) == 0));
}

static void
asy_waiteot(struct asycom *asy)
{
	/*
	 * Wait for the current transmission block and the
	 * current fifo data to transmit. Once this is done
	 * we may go on.
	 */
	ASY_DPRINTF(asy, ASY_DEBUG_EOT, "enter");
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
	uchar_t lcr = 0;

	ASSERT(mutex_owned(&asy->asy_excl_hi));

	/* On a 16750, we have to set DLAB in order to set ASY_FCR_FIFO64. */
	if (asy->asy_hwtype >= ASY_16750)
		asy_set(asy, ASY_LCR, ASY_LCR_DLAB);

	asy_put(asy, ASY_FCR, asy->asy_fifor | flush);

	/* Clear DLAB */
	if (asy->asy_hwtype >= ASY_16750)
		asy_clr(asy, ASY_LCR, ASY_LCR_DLAB);
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
	uint8_t ier;
	int flush_reg;
	int ocflags;

	ASSERT(mutex_owned(&asy->asy_excl));
	ASSERT(mutex_owned(&asy->asy_excl_hi));

	async = asy->asy_priv;
	ASY_DPRINTF(asy, ASY_DEBUG_PROCS, "mode = 0x%08X, enter", mode);

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

	asy_disable_interrupts(asy, ASY_IER_ALL);

	ocflags = asy->asy_ocflag;

	/* flush/reset the status registers */
	(void) asy_get(asy, ASY_ISR);
	(void) asy_get(asy, ASY_LSR);
	asy->asy_msr = flush_reg = asy_get(asy, ASY_MSR);
	/*
	 * The device is programmed in the open sequence, if we
	 * have to hardware handshake, then this is a good time
	 * to check if the device can receive any data.
	 */

	if ((CRTSCTS & async->async_ttycommon.t_cflag) &&
	    !(flush_reg & ASY_MSR_CTS)) {
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
		if (asy->asy_use_fifo == ASY_FCR_FIFO_EN) {
			for (flush_reg = asy->asy_fifo_buf; flush_reg-- > 0; ) {
				(void) asy_get(asy, ASY_RHR);
			}
		} else {
			flush_reg = asy_get(asy, ASY_RHR);
		}

	if (ocflags != (c_flag & ~CLOCAL) || mode == ASY_INIT) {
		/* Set line control */
		uint8_t lcr = 0;

		if (c_flag & CSTOPB)
			lcr |= ASY_LCR_STOP2;	/* 2 stop bits */

		if (c_flag & PARENB)
			lcr |= ASY_LCR_PEN;

		if ((c_flag & PARODD) == 0)
			lcr |= ASY_LCR_EPS;

		switch (c_flag & CSIZE) {
		case CS5:
			lcr |= ASY_LCR_BITS5;
			break;
		case CS6:
			lcr |= ASY_LCR_BITS6;
			break;
		case CS7:
			lcr |= ASY_LCR_BITS7;
			break;
		case CS8:
			lcr |= ASY_LCR_BITS8;
			break;
		}

		asy_clr(asy, ASY_LCR, ASY_LCR_WLS0 | ASY_LCR_WLS1 |
		    ASY_LCR_STB | ASY_LCR_PEN | ASY_LCR_EPS);
		asy_set(asy, ASY_LCR, lcr);
		asy_set_baudrate(asy, baudrate);

		/*
		 * If we have a FIFO buffer, enable/flush
		 * at intialize time, flush if transitioning from
		 * CREAD off to CREAD on.
		 */
		if ((ocflags & CREAD) == 0 && (c_flag & CREAD) ||
		    mode == ASY_INIT)
			if (asy->asy_use_fifo == ASY_FCR_FIFO_EN)
				asy_reset_fifo(asy, ASY_FCR_RHR_FL);

		/* remember the new cflags */
		asy->asy_ocflag = c_flag & ~CLOCAL;
	}

	if (baudrate == 0)
		asy_put(asy, ASY_MCR,
		    (asy->asy_mcr & ASY_MCR_RTS) | ASY_MCR_OUT2);
	else
		asy_put(asy, ASY_MCR, asy->asy_mcr | ASY_MCR_OUT2);

	/*
	 * Call the modem status interrupt handler to check for the carrier
	 * in case CLOCAL was turned off after the carrier came on.
	 * (Note: Modem status interrupt is not enabled if CLOCAL is ON.)
	 */
	async_msint(asy);

	/* Set interrupt control */
	ASY_DPRINTF(asy, ASY_DEBUG_MODM2,
	    "c_flag & CLOCAL = %x t_cflag & CRTSCTS = %x",
	    c_flag & CLOCAL, async->async_ttycommon.t_cflag & CRTSCTS);


	/* Always enable transmit and line status interrupts. */
	ier = ASY_IER_TIEN | ASY_IER_SIEN;

	/*
	 * Enable Modem status interrupt if hardware flow control is enabled or
	 * this isn't a direct-wired (local) line, which ignores DCD.
	 */
	if (((c_flag & CLOCAL) == 0) ||
	    (async->async_ttycommon.t_cflag & CRTSCTS))
		ier |= ASY_IER_MIEN;

	if (c_flag & CREAD)
		ier |= ASY_IER_RIEN;

	asy_enable_interrupts(asy, ier);
	ASY_DPRINTF(asy, ASY_DEBUG_PROCS, "done");
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
asyintr(caddr_t argasy, caddr_t argunused __unused)
{
	struct asycom		*asy = (struct asycom *)argasy;
	struct asyncline	*async = asy->asy_priv;
	int			ret_status = DDI_INTR_UNCLAIMED;

	mutex_enter(&asy->asy_excl_hi);
	if ((async == NULL) ||
	    !(async->async_flags & (ASYNC_ISOPEN|ASYNC_WOPEN))) {
		const uint8_t intr_id = asy_get(asy, ASY_ISR);

		if ((intr_id & ASY_ISR_NOINTR) == 0) {
			/*
			 * reset the device by:
			 *	reading line status
			 *	reading any data from data status register
			 *	reading modem status
			 */
			(void) asy_get(asy, ASY_LSR);
			(void) asy_get(asy, ASY_RHR);
			asy->asy_msr = asy_get(asy, ASY_MSR);
			ret_status = DDI_INTR_CLAIMED;
		}
		mutex_exit(&asy->asy_excl_hi);
		return (ret_status);
	}

	/* By this point we're sure this is for us. */
	ret_status = DDI_INTR_CLAIMED;

	/*
	 * Before this flag was set, interrupts were disabled. We may still get
	 * here if asyintr() waited on the mutex.
	 */
	if (asy->asy_flags & ASY_DDI_SUSPENDED) {
		mutex_exit(&asy->asy_excl_hi);
		return (ret_status);
	}

	/*
	 * We will loop until the interrupt line is pulled low. asy
	 * interrupt is edge triggered.
	 */
	for (;;) {
		const uint8_t intr_id = asy_get(asy, ASY_ISR);

		if (intr_id & ASY_ISR_NOINTR)
			break;

		ASY_DPRINTF(asy, ASY_DEBUG_INTR, "interrupt_id = 0x%x",
		    intr_id);

		const uint8_t lsr = asy_get(asy, ASY_LSR);

		switch (intr_id & ASY_ISR_MASK) {
		case ASY_ISR_ID_RLST:
		case ASY_ISR_ID_RDA:
		case ASY_ISR_ID_TMO:
			/* receiver interrupt or receiver errors */
			async_rxint(asy, lsr);
			break;

		case ASY_ISR_ID_THRE:
			/*
			 * The transmit-ready interrupt implies an empty
			 * transmit-hold register (or FIFO).  Check that it is
			 * present before attempting to transmit more data.
			 */
			if ((lsr & ASY_LSR_THRE) == 0) {
				/*
				 * Taking a THRE interrupt only to find THRE
				 * absent would be a surprise, except for a
				 * racing asyputchar(), which ignores the
				 * excl_hi mutex when writing to the device.
				 */
				continue;
			}
			async_txint(asy);
			/*
			 * Unlike the other interrupts which fall through to
			 * attempting to fill the output register/FIFO, THRE
			 * has no need having just done so.
			 */
			continue;

		case ASY_ISR_ID_MST:
			/* modem status interrupt */
			async_msint(asy);
			break;
		}

		/* Refill the output FIFO if it has gone empty */
		if ((lsr & ASY_LSR_THRE) && (async->async_flags & ASYNC_BUSY) &&
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

	ASSERT(MUTEX_HELD(&asy->asy_excl_hi));

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
			asy_put(asy, ASY_THR, *async->async_optr++);
		}
		async->async_flags |= ASYNC_PROGRESS;
	}

	if (fifo_len <= 0)
		return;

	asysetsoft(asy);
}

/*
 * Interrupt on port: handle PPS event.  This function is only called
 * for a port on which PPS event handling has been enabled.
 */
static void
asy_ppsevent(struct asycom *asy, int msr)
{
	ASSERT(MUTEX_HELD(&asy->asy_excl_hi));

	if (asy->asy_flags & ASY_PPS_EDGE) {
		/* Have seen leading edge, now look for and record drop */
		if ((msr & ASY_MSR_DCD) == 0)
			asy->asy_flags &= ~ASY_PPS_EDGE;
		/*
		 * Waiting for leading edge, look for rise; stamp event and
		 * calibrate kernel clock.
		 */
	} else if (msr & ASY_MSR_DCD) {
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
 * Receiver interrupt: RDA interrupt, FIFO timeout interrupt or receive
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

	ASSERT(MUTEX_HELD(&asy->asy_excl_hi));

	tp = &async->async_ttycommon;
	if (!(tp->t_cflag & CREAD)) {
		/* Line is not open for reading. Flush receiver FIFO. */
		while ((lsr & (ASY_LSR_DR | ASY_LSR_ERRORS)) != 0) {
			(void) asy_get(asy, ASY_RHR);
			lsr = asy_get(asy, ASY_LSR);
			if (looplim-- < 0)		/* limit loop */
				break;
		}
		return;
	}

	while ((lsr & (ASY_LSR_DR | ASY_LSR_ERRORS)) != 0) {
		c = 0;
		s = 0;				/* reset error status */
		if (lsr & ASY_LSR_DR) {
			c = asy_get(asy, ASY_RHR);

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
		if (lsr & ASY_LSR_ERRORS) {
			if (lsr & ASY_LSR_PE) {
				if (tp->t_iflag & INPCK) /* parity enabled */
					s |= PERROR;
			}

			if (lsr & (ASY_LSR_FE | ASY_LSR_BI))
				s |= FRERROR;
			if (lsr & ASY_LSR_OE) {
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
		lsr = asy_get(asy, ASY_LSR);
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
	    (RING_FRAC(async)) || (async->async_polltid == 0)) {
		asysetsoft(asy);	/* need a soft interrupt */
	}
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

	ASSERT(MUTEX_HELD(&asy->asy_excl_hi));

async_msint_retry:
	/* this resets the interrupt */
	msr = asy_get(asy, ASY_MSR);
	ASY_DPRINTF(asy, ASY_DEBUG_STATE, "call #%d:",
	    ++(asy->asy_msint_cnt));
	ASY_DPRINTF(asy, ASY_DEBUG_STATE, "   transition: %3s %3s %3s %3s",
	    (msr & ASY_MSR_DCTS) ? "DCTS" : "    ",
	    (msr & ASY_MSR_DDSR) ? "DDSR" : "    ",
	    (msr & ASY_MSR_TERI) ? "TERI" : "    ",
	    (msr & ASY_MSR_DDCD) ? "DDCD" : "    ");
	ASY_DPRINTF(asy, ASY_DEBUG_STATE, "current state: %3s %3s %3s %3s",
	    (msr & ASY_MSR_CTS)  ? "CTS " : "    ",
	    (msr & ASY_MSR_DSR)  ? "DSR " : "    ",
	    (msr & ASY_MSR_RI)   ? "RI  " : "    ",
	    (msr & ASY_MSR_DCD)  ? "DCD " : "    ");

	/* If CTS status is changed, do H/W output flow control */
	if ((t_cflag & CRTSCTS) && (((asy->asy_msr ^ msr) & ASY_MSR_CTS) != 0))
		async_flowcontrol_hw_output(asy,
		    msr & ASY_MSR_CTS ? FLOW_START : FLOW_STOP);
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
	asysetsoft(asy);
	/*
	 * We will make sure that the modem status presented to us
	 * during the previous read has not changed. If the chip samples
	 * the modem status on the falling edge of the interrupt line,
	 * and uses this state as the base for detecting change of modem
	 * status, we would miss a change of modem status event that occured
	 * after we initiated a read MSR operation.
	 */
	msr = asy_get(asy, ASY_MSR);
	if (ASY_MSR_STATES(msr) != ASY_MSR_STATES(asy->asy_msr))
		goto	async_msint_retry;
}

/*
 * Pend a soft interrupt if one isn't already pending.
 */
static void
asysetsoft(struct asycom *asy)
{
	ASSERT(MUTEX_HELD(&asy->asy_excl_hi));

	if (mutex_tryenter(&asy->asy_soft_lock) == 0)
		return;

	asy->asy_flags |= ASY_NEEDSOFT;
	if (!asy->asysoftpend) {
		asy->asysoftpend = 1;
		mutex_exit(&asy->asy_soft_lock);
		(void) ddi_intr_trigger_softint(asy->asy_soft_inth, NULL);
	} else {
		mutex_exit(&asy->asy_soft_lock);
	}
}

/*
 * Handle a second-stage interrupt.
 */
/*ARGSUSED*/
uint_t
asysoftintr(caddr_t intarg, caddr_t unusedarg __unused)
{
	struct asycom *asy = (struct asycom *)intarg;
	struct asyncline *async;
	int rv;
	uint_t cc;

	/*
	 * Test and clear soft interrupt.
	 */
	mutex_enter(&asy->asy_soft_lock);
	ASY_DPRINTF(asy, ASY_DEBUG_PROCS, "enter");
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

	ASY_DPRINTF(asy, ASY_DEBUG_PROCS, "enter");
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
		ASY_DPRINTF(asy, ASY_DEBUG_MODM2,
		    "asy_msr & DCD = %x, tp->t_flags & TS_SOFTCAR = %x",
		    asy->asy_msr & ASY_MSR_DCD, tp->t_flags & TS_SOFTCAR);

		if (asy->asy_msr & ASY_MSR_DCD) {
			/* carrier present */
			if ((async->async_flags & ASYNC_CARR_ON) == 0) {
				ASY_DPRINTF(asy, ASY_DEBUG_MODM2,
				    "set ASYNC_CARR_ON");
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

				ASY_DPRINTF(asy, ASY_DEBUG_MODEM,
				    "carrier dropped, so drop DTR");
				/*
				 * Carrier went away.
				 * Drop DTR, abort any output in
				 * progress, indicate that output is
				 * not stopped, and send a hangup
				 * notification upstream.
				 */
				asy_clr(asy, ASY_MCR, ASY_MCR_DTR);

				if (async->async_flags & ASYNC_BUSY) {
					ASY_DPRINTF(asy, ASY_DEBUG_BUSY,
					    "Carrier dropped.  "
					    "Clearing async_ocnt");
					async->async_ocnt = 0;
				}	/* if */

				async->async_flags &= ~ASYNC_STOPPED;
				if (async->async_flags & ASYNC_ISOPEN) {
					mutex_exit(&asy->asy_excl_hi);
					mutex_exit(&asy->asy_excl);
					(void) putctl(q, M_HANGUP);
					mutex_enter(&asy->asy_excl);
					ASY_DPRINTF(asy, ASY_DEBUG_MODEM,
					    "putctl(q, M_HANGUP)");
					/*
					 * Flush FIFO buffers
					 * Any data left in there is invalid now
					 */
					if (asy->asy_use_fifo ==
					    ASY_FCR_FIFO_EN) {
						mutex_enter(&asy->asy_excl_hi);
						asy_reset_fifo(asy,
						    ASY_FCR_THR_FL);
						mutex_exit(&asy->asy_excl_hi);
					}
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
					ASY_DPRINTF(asy, ASY_DEBUG_MODEM,
					    "Flushing to prevent HUPCL "
					    "hanging");
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

	ASY_DPRINTF(asy, ASY_DEBUG_INPUT, "%d char(s) in queue", cc);

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
				asyerror(asy, CE_WARN, "local queue full");
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
	if (cc)
		(void) putctl1(q, M_BREAK, c);
	mutex_enter(&asy->asy_excl);
	mutex_enter(&asy->asy_excl_hi);
	if (cc) {
		asysetsoft(asy);	/* finish cc chars */
	}
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
		ASY_DPRINTF(asy, ASY_DEBUG_BUSY,
		    "Clearing ASYNC_BUSY, async_ocnt=%d", async->async_ocnt);
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
			asyerror(asy, CE_WARN, "silo overflow");
			mutex_enter(&asy->asy_excl);
			mutex_enter(&asy->asy_excl_hi);
		}
		async->async_hw_overrun = 0;
	}
	if (async->async_sw_overrun) {
		if (async->async_flags & ASYNC_ISOPEN) {
			mutex_exit(&asy->asy_excl_hi);
			mutex_exit(&asy->asy_excl);
			asyerror(asy, CE_WARN, "ring buffer overflow");
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
	ASY_DPRINTF(asy, ASY_DEBUG_PROCS, "done");
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

	ASY_DPRINTF(asy, ASY_DEBUG_PROCS, "enter");

	/*
	 * If break timer expired, turn off the break bit.
	 */

	mutex_enter(&asy->asy_excl);
	/*
	 * If ASYNC_OUT_SUSPEND is also set, we don't really
	 * clean the HW break, TIOCCBRK is responsible for this.
	 */
	if ((async->async_flags & ASYNC_BREAK) &&
	    !(async->async_flags & ASYNC_OUT_SUSPEND)) {
		mutex_enter(&asy->asy_excl_hi);
		asy_clr(asy, ASY_LCR, ASY_LCR_SETBRK);
		mutex_exit(&asy->asy_excl_hi);
	}
	async->async_flags &= ~(ASYNC_DELAY|ASYNC_BREAK);
	cv_broadcast(&async->async_flags_cv);
	async_start(async);

	mutex_exit(&asy->asy_excl);
}

/*
 * Start output on a line, unless it's busy, frozen, or otherwise.
 */
static void
async_start(struct asyncline *async)
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

	ASY_DPRINTF(asy, ASY_DEBUG_PROCS, "enter");
#endif
	if (asy->asy_use_fifo == ASY_FCR_FIFO_EN) {
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
		ASY_DPRINTF(asy, ASY_DEBUG_OUT, "%s",
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
		ASY_DPRINTF(asy, ASY_DEBUG_OUT, "start ASYNC_DELAY");
		return;
	}

	if ((q = async->async_ttycommon.t_writeq) == NULL) {
		ASY_DPRINTF(asy, ASY_DEBUG_OUT, "start writeq is null");
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
			asy_set(asy, ASY_LCR, ASY_LCR_SETBRK);
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
		if (!(asy_get(asy, ASY_LSR) & ASY_LSR_THRE))
			break;
		asy_put(asy, ASY_THR, *xmit_addr++);
		cc--;
		didsome = B_TRUE;
	}
	async->async_optr = xmit_addr;
	async->async_ocnt = cc;
	if (didsome)
		async->async_flags |= ASYNC_PROGRESS;
	ASY_DPRINTF(asy, ASY_DEBUG_BUSY, "Set ASYNC_BUSY, async_ocnt=%d",
	    async->async_ocnt);
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

	ASY_DPRINTF(asy, ASY_DEBUG_PROCS, "enter");
	ASSERT(mutex_owned(&asy->asy_excl_hi));

	if (asy_get(asy, ASY_LSR) & ASY_LSR_THRE) {
		if (async_flowcontrol_sw_input(asy, FLOW_CHECK, IN_FLOW_NULL))
			return;
		if (async->async_ocnt > 0 &&
		    !(async->async_flags &
		    (ASYNC_HW_OUT_FLW|ASYNC_SW_OUT_FLW|ASYNC_OUT_SUSPEND))) {
			asy_put(asy, ASY_THR, *async->async_optr++);
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
	if (!(async->async_flags & ASYNC_BREAK))
		asy_clr(asy, ASY_LCR, ASY_LCR_SETBRK);

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

	ASY_DPRINTF(asy, ASY_DEBUG_PROCS, "enter");

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
	ASY_DPRINTF(asy, ASY_DEBUG_IOCTL, "%s",
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

				while ((asy_get(asy, ASY_LSR) & ASY_LSR_TEMT)
				    == 0) {
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
				asy_set(asy, ASY_LCR, ASY_LCR_SETBRK);
				mutex_exit(&asy->asy_excl_hi);
				(void) timeout(async_restart, (caddr_t)async,
				    drv_usectohz(1000000)/4);
			} else {
				ASY_DPRINTF(asy, ASY_DEBUG_OUT,
				    "wait for flush");
				mutex_enter(&asy->asy_excl_hi);
				asy_waiteot(asy);
				mutex_exit(&asy->asy_excl_hi);
				ASY_DPRINTF(asy, ASY_DEBUG_OUT,
				    "ldterm satisfied");
			}
			break;

		case TIOCSBRK:
			if (!(async->async_flags & ASYNC_OUT_SUSPEND)) {
				mutex_enter(&asy->asy_excl_hi);
				async->async_flags |= ASYNC_OUT_SUSPEND;
				async->async_flags |= ASYNC_HOLD_UTBRK;
				index = BAUDINDEX(
				    async->async_ttycommon.t_cflag);
				while ((asy_get(asy, ASY_LSR) & ASY_LSR_TEMT)
				    == 0) {
					mutex_exit(&asy->asy_excl_hi);
					mutex_exit(&asy->asy_excl);
					drv_usecwait(
					    32*asyspdtab[index] & 0xfff);
					mutex_enter(&asy->asy_excl);
					mutex_enter(&asy->asy_excl_hi);
				}
				asy_set(asy, ASY_LCR, ASY_LCR_SETBRK);
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
				ASY_DPRINTF(asy, ASY_DEBUG_IOCTL,
				    "non-transparent");

				error = miocpullup(mp, sizeof (int));
				if (error != 0)
					break;

				mutex_enter(&asy->asy_excl_hi);
				(void) asymctl(asy,
				    dmtoasy(asy, *(int *)mp->b_cont->b_rptr),
				    iocp->ioc_cmd);
				mutex_exit(&asy->asy_excl_hi);
				iocp->ioc_error = 0;
				mp->b_datap->db_type = M_IOCACK;
			} else {
				ASY_DPRINTF(asy, ASY_DEBUG_IOCTL,
				    "transparent");
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
				ASY_DPRINTF(asy, ASY_DEBUG_IOCTL,
				    "transparent");
				mcopyout(mp, NULL, sizeof (int), NULL, datamp);
			} else {
				ASY_DPRINTF(asy, ASY_DEBUG_IOCTL,
				    "non-transparent");
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

			mutex_enter(&asy->asy_excl_hi);
			if (*(intptr_t *)mp->b_cont->b_rptr)
				asy->asy_flags |= ASY_CONSOLE;
			else
				asy->asy_flags &= ~ASY_CONSOLE;
			mutex_exit(&asy->asy_excl_hi);

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
	ASY_DPRINTF(asy, ASY_DEBUG_PROCS, "done");
}

static int
asyrsrv(queue_t *q)
{
	mblk_t *bp;
	struct asyncline *async;
	struct asycom *asy;

	async = (struct asyncline *)q->q_ptr;
	asy = (struct asycom *)async->async_common;

	while (canputnext(q) && (bp = getq(q)))
		putnext(q, bp);
	mutex_enter(&asy->asy_excl_hi);
	asysetsoft(asy);
	mutex_exit(&asy->asy_excl_hi);
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
	int error;

	async = (struct asyncline *)q->q_ptr;
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
				ASY_DPRINTF(asy, ASY_DEBUG_OUT,
				    "flush request");
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
				ASY_DPRINTF(asy, ASY_DEBUG_BUSY,
				    "Clearing async_ocnt, "
				    "leaving ASYNC_BUSY set");
				async->async_ocnt = 0;
				async->async_flags &= ~ASYNC_BUSY;
			} /* if */

			if (ASYWPUTDO_NOT_SUSP(async, wput)) {
				/* Flush FIFO buffers */
				if (asy->asy_use_fifo == ASY_FCR_FIFO_EN) {
					asy_reset_fifo(asy, ASY_FCR_THR_FL);
				}
			}
			mutex_exit(&asy->asy_excl_hi);

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
				mutex_enter(&asy->asy_excl);
				mutex_enter(&asy->asy_excl_hi);
				/* Flush FIFO buffers */
				if (asy->asy_use_fifo == ASY_FCR_FIFO_EN) {
					asy_reset_fifo(asy, ASY_FCR_RHR_FL);
				}
				mutex_exit(&asy->asy_excl_hi);
				mutex_exit(&asy->asy_excl);
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
	ASY_DPRINTF(asy, ASY_DEBUG_MODEM, "case %s",
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
		(void) asymctl(asy, dmtoasy(asy, *(int *)mp->b_cont->b_rptr),
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

	while ((asy_get_reg(asy, ASY_LSR) & ASY_LSR_THRE) == 0) {
		/* wait for xmit to finish */
		drv_usecwait(10);
	}

	/* put the character out */
	asy_put_reg(asy, ASY_THR, c);
}

/*
 * See if there's a character available. If no character is
 * available, return 0. Run in polled mode, no interrupts.
 */
static boolean_t
asyischar(cons_polledio_arg_t arg)
{
	struct asycom *asy = (struct asycom *)arg;

	return ((asy_get_reg(asy, ASY_LSR) & ASY_LSR_DR) != 0);
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
	return (asy_get_reg(asy, ASY_RHR));
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
	mcr_r = asy_get(asy, ASY_MCR);

	switch (how) {

	case TIOCMSET:
		ASY_DPRINTF(asy, ASY_DEBUG_MODEM, "TIOCMSET, bits = %x", bits);
		mcr_r = bits;		/* Set bits	*/
		break;

	case TIOCMBIS:
		ASY_DPRINTF(asy, ASY_DEBUG_MODEM, "TIOCMBIS, bits = %x", bits);
		mcr_r |= bits;		/* Mask in bits	*/
		break;

	case TIOCMBIC:
		ASY_DPRINTF(asy, ASY_DEBUG_MODEM, "TIOCMBIC, bits = %x", bits);
		mcr_r &= ~bits;		/* Mask out bits */
		break;

	case TIOCMGET:
		/* Read Modem Status Registers */
		/*
		 * If modem interrupts are enabled, we return the
		 * saved value of msr. We read MSR only in async_msint()
		 */
		if (asy_get(asy, ASY_IER) & ASY_IER_MIEN) {
			msr_r = asy->asy_msr;
			ASY_DPRINTF(asy, ASY_DEBUG_MODEM,
			    "TIOCMGET, read msr_r = %x", msr_r);
		} else {
			msr_r = asy_get(asy, ASY_MSR);
			ASY_DPRINTF(asy, ASY_DEBUG_MODEM,
			    "TIOCMGET, read MSR = %x", msr_r);
		}
		ASY_DPRINTF(asy, ASY_DEBUG_MODEM, "modem_lines = %x",
		    asytodm(mcr_r, msr_r));
		return (asytodm(mcr_r, msr_r));
	}

	asy_put(asy, ASY_MCR, mcr_r);

	return (mcr_r);
}

static int
asytodm(int mcr_r, int msr_r)
{
	int b = 0;

	/* MCR registers */
	if (mcr_r & ASY_MCR_RTS)
		b |= TIOCM_RTS;

	if (mcr_r & ASY_MCR_DTR)
		b |= TIOCM_DTR;

	/* MSR registers */
	if (msr_r & ASY_MSR_DCD)
		b |= TIOCM_CAR;

	if (msr_r & ASY_MSR_CTS)
		b |= TIOCM_CTS;

	if (msr_r & ASY_MSR_DSR)
		b |= TIOCM_DSR;

	if (msr_r & ASY_MSR_RI)
		b |= TIOCM_RNG;
	return (b);
}

static int
dmtoasy(struct asycom *asy, int bits)
{
	int b = 0;

	ASY_DPRINTF(asy, ASY_DEBUG_MODEM, "bits = %x", bits);
#ifdef	CAN_NOT_SET	/* only DTR and RTS can be set */
	if (bits & TIOCM_CAR)
		b |= ASY_MSR_DCD;
	if (bits & TIOCM_CTS)
		b |= ASY_MSR_CTS;
	if (bits & TIOCM_DSR)
		b |= ASY_MSR_DSR;
	if (bits & TIOCM_RNG)
		b |= ASY_MSR_RI;
#endif

	if (bits & TIOCM_RTS) {
		ASY_DPRINTF(asy, ASY_DEBUG_MODEM, "set b & RTS");
		b |= ASY_MCR_RTS;
	}
	if (bits & TIOCM_DTR) {
		ASY_DPRINTF(asy, ASY_DEBUG_MODEM, "set b & DTR");
		b |= ASY_MCR_DTR;
	}

	return (b);
}

static void
asyerror(struct asycom *asy, int level, const char *fmt, ...)
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
	vdev_err(asy->asy_dip, level, fmt, adx);
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
		asy->asy_cflag |= ASY_LCR_BITS8;	/* add default bits */
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
		asy->asy_cflag |= ASY_LCR_BITS8;	/* add default bits */
		return;
	}
	switch (*p) {
		default:
		case '8':
			asy->asy_cflag |= CS8;
			asy->asy_lcr = ASY_LCR_BITS8;
			break;
		case '7':
			asy->asy_cflag |= CS7;
			asy->asy_lcr = ASY_LCR_BITS7;
			break;
		case '6':
			asy->asy_cflag |= CS6;
			asy->asy_lcr = ASY_LCR_BITS6;
			break;
		case '5':
			/* LINTED: CS5 is currently zero (but might change) */
			asy->asy_cflag |= CS5;
			asy->asy_lcr = ASY_LCR_BITS5;
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
			asy->asy_lcr |= ASY_LCR_PEN;
			break;
		case 'o':
			asy->asy_cflag |= PARENB|PARODD;
			asy->asy_lcr |= ASY_LCR_PEN | ASY_LCR_EPS;
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
		asy->asy_lcr |= ASY_LCR_STB;
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
		ASY_DPRINTF(asy, ASY_DEBUG_SFLOW, "input sflow stop, type = %x",
		    async->async_inflow_source);
		break;
	case FLOW_START:
		async->async_inflow_source &= ~type;
		if (async->async_inflow_source == 0) {
			async->async_flags = (async->async_flags &
			    ~ASYNC_SW_IN_FLOW) | ASYNC_SW_IN_NEEDED;
			ASY_DPRINTF(asy, ASY_DEBUG_SFLOW, "input sflow start");
		}
		break;
	default:
		break;
	}

	if (((async->async_flags & (ASYNC_SW_IN_NEEDED | ASYNC_BREAK |
	    ASYNC_OUT_SUSPEND)) == ASYNC_SW_IN_NEEDED) &&
	    (asy_get(asy, ASY_LSR) & ASY_LSR_THRE)) {
		/*
		 * If we get this far, then we know we need to send out
		 * XON or XOFF char.
		 */
		async->async_flags = (async->async_flags &
		    ~ASYNC_SW_IN_NEEDED) | ASYNC_BUSY;
		asy_put(asy, ASY_THR,
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
		ASY_DPRINTF(asy, ASY_DEBUG_SFLOW, "output sflow stop");
		break;
	case FLOW_START:
		async->async_flags &= ~ASYNC_SW_OUT_FLW;
		if (!(async->async_flags & ASYNC_HW_OUT_FLW))
			async->async_flags |= ASYNC_OUT_FLW_RESUME;
		ASY_DPRINTF(asy, ASY_DEBUG_SFLOW, "output sflow start");
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
		ASY_DPRINTF(asy, ASY_DEBUG_HFLOW, "input hflow stop, type = %x",
		    async->async_inflow_source);
		break;
	case FLOW_START:
		async->async_inflow_source &= ~type;
		if (async->async_inflow_source == 0) {
			async->async_flags &= ~ASYNC_HW_IN_FLOW;
			ASY_DPRINTF(asy, ASY_DEBUG_HFLOW, "input hflow start");
		}
		break;
	default:
		break;
	}
	mcr = asy_get(asy, ASY_MCR);
	flag = (async->async_flags & ASYNC_HW_IN_FLOW) ? 0 : ASY_MCR_RTS;

	if (((mcr ^ flag) & ASY_MCR_RTS) != 0) {
		asy_put(asy, ASY_MCR, (mcr ^ ASY_MCR_RTS));
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
		ASY_DPRINTF(asy, ASY_DEBUG_HFLOW, "output hflow stop");
		break;
	case FLOW_START:
		async->async_flags &= ~ASYNC_HW_OUT_FLW;
		if (!(async->async_flags & ASYNC_SW_OUT_FLW))
			async->async_flags |= ASYNC_OUT_FLW_RESUME;
		ASY_DPRINTF(asy, ASY_DEBUG_HFLOW, "output hflow start");
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

	asy_disable_interrupts(asy, ASY_IER_ALL);

	/* Flush the FIFOs */
	asy_reset_fifo(asy, ASY_FCR_THR_FL | ASY_FCR_RHR_FL);

	return (DDI_SUCCESS);
}
