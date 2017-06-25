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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */


/*
 *	Serial I/O driver for 82510/8250/16450/16550AF/16C554D chips.
 *	Modified as sparc keyboard/mouse driver.
 */
#define	SU_REGISTER_FILE_NO 0
#define	SU_REGOFFSET 0
#define	SU_REGISTER_LEN 8

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
#include <sys/strsun.h>
#include <sys/strtty.h>
#include <sys/debug.h>
#include <sys/kbio.h>
#include <sys/cred.h>
#include <sys/modctl.h>
#include <sys/stat.h>
#include <sys/consdev.h>
#include <sys/mkdev.h>
#include <sys/kmem.h>
#include <sys/cred.h>
#ifdef DEBUG
#include <sys/promif.h>
#endif
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sudev.h>
#include <sys/note.h>
#include <sys/timex.h>
#include <sys/policy.h>

#define	async_stopc	async_ttycommon.t_stopc
#define	async_startc	async_ttycommon.t_startc

#define	ASY_INIT	1
#define	ASY_NOINIT	0

#ifdef DEBUG
#define	ASY_DEBUG_INIT	0x001
#define	ASY_DEBUG_INPUT	0x002
#define	ASY_DEBUG_EOT	0x004
#define	ASY_DEBUG_CLOSE	0x008
#define	ASY_DEBUG_HFLOW	0x010
#define	ASY_DEBUG_PROCS	0x020
#define	ASY_DEBUG_STATE	0x040
#define	ASY_DEBUG_INTR	0x080
static	int asydebug = 0;
#endif
static	int su_log = 0;

int su_drain_check = 15000000;		/* tunable: exit drain check time */

static	struct ppsclockev asy_ppsev;

static	int max_asy_instance = -1;
static	void	*su_asycom;	/* soft state asycom pointer */
static	void	*su_asyncline;	/* soft state asyncline pointer */
static	boolean_t abort_charseq_recognize(uchar_t ch);

static	uint_t	asysoftintr(caddr_t intarg);
static	uint_t	asyintr(caddr_t argasy);

/* The async interrupt entry points */
static void	async_txint(struct asycom *asy, uchar_t lsr);
static void	async_rxint(struct asycom *asy, uchar_t lsr);
static void	async_msint(struct asycom *asy);
static int	async_softint(struct asycom *asy);

static void	async_ioctl(struct asyncline *async, queue_t *q, mblk_t *mp,
    boolean_t iswput);
static void	async_reioctl(void *);
static void	async_iocdata(queue_t *q, mblk_t *mp);
static void	async_restart(void *);
static void	async_start(struct asyncline *async);
static void	async_nstart(struct asyncline *async, int mode);
static void	async_resume(struct asyncline *async);
static int	asy_program(struct asycom *asy, int mode);

/* Polled mode functions */
static void	asyputchar(cons_polledio_arg_t, uchar_t c);
static int	asygetchar(cons_polledio_arg_t);
static boolean_t	asyischar(cons_polledio_arg_t);
static void	asy_polled_enter(cons_polledio_arg_t);
static void	asy_polled_exit(cons_polledio_arg_t);

static int	asymctl(struct asycom *, int, int);
static int	asytodm(int, int);
static int	dmtoasy(int);
static void	asycheckflowcontrol_hw(struct asycom *asy);
static boolean_t asycheckflowcontrol_sw(struct asycom *asy);
static void	asy_ppsevent(struct asycom *asy, int msr);

extern kcondvar_t lbolt_cv;
extern int ddi_create_internal_pathname(dev_info_t *dip, char *name,
		int spec_type, minor_t minor_num);


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
	0,	/* 76800 baud rate - not supported */
	0x001,	/* 115200 baud rate */
	0,	/* 153600 baud rate - not supported */
	0x8002,	/* 230400 baud rate - supported on specific platforms */
	0,	/* 307200 baud rate - not supported */
	0x8001	/* 460800 baud rate - supported on specific platforms */
};

/*
 * Number of speeds supported is the number of entries in
 * the above table.
 */
#define	N_SU_SPEEDS	(sizeof (asyspdtab)/sizeof (ushort_t))

/*
 * Human-readable baud rate table.
 * Indexed by #defines found in sys/termios.h
 */
int baudtable[] = {
	0,	/* 0 baud rate */
	50,	/* 50 baud rate */
	75,	/* 75 baud rate */
	110,	/* 110 baud rate */
	134,	/* 134 baud rate */
	150,	/* 150 baud rate */
	200,	/* 200 baud rate */
	300,	/* 300 baud rate */
	600,	/* 600 baud rate */
	1200,	/* 1200 baud rate */
	1800,	/* 1800 baud rate */
	2400,	/* 2400 baud rate */
	4800,	/* 4800 baud rate */
	9600,	/* 9600 baud rate */
	19200,	/* 19200 baud rate */
	38400,	/* 38400 baud rate */
	57600,	/* 57600 baud rate */
	76800,	/* 76800 baud rate */
	115200,	/* 115200 baud rate */
	153600,	/* 153600 baud rate */
	230400,	/* 230400 baud rate */
	307200,	/* 307200 baud rate */
	460800	/* 460800 baud rate */
};

static int asyopen(queue_t *rq, dev_t *dev, int flag, int sflag, cred_t *cr);
static int asyclose(queue_t *q, int flag);
static void asywput(queue_t *q, mblk_t *mp);
static void asyrsrv(queue_t *q);

struct module_info asy_info = {
	0,
	"su",
	0,
	INFPSZ,
	32*4096,
	4096
};

static struct qinit asy_rint = {
	putq,
	(int (*)())asyrsrv,
	asyopen,
	asyclose,
	NULL,
	&asy_info,
	NULL
};

static struct qinit asy_wint = {
	(int (*)())asywput,
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
	NULL,			/* devo_power */
	ddi_quiesce_not_supported,	/* devo_quiesce */
};

/*
 * Module linkage information for the kernel.
 */

static struct modldrv modldrv = {
	&mod_driverops, /* Type of module.  This one is a driver */
	"su driver",
	&asy_ops,	/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&modldrv,
	NULL
};

int
_init(void)
{
	int status;

	status = ddi_soft_state_init(&su_asycom, sizeof (struct asycom),
	    SU_INITIAL_SOFT_ITEMS);
	if (status != 0)
		return (status);
	status = ddi_soft_state_init(&su_asyncline, sizeof (struct asyncline),
	    SU_INITIAL_SOFT_ITEMS);
	if (status != 0) {
		ddi_soft_state_fini(&su_asycom);
		return (status);
	}

	if ((status = mod_install(&modlinkage)) != 0) {
		ddi_soft_state_fini(&su_asycom);
		ddi_soft_state_fini(&su_asyncline);
	}

	return (status);
}

int
_fini(void)
{
	int i;

	i = mod_remove(&modlinkage);
	if (i == 0) {
		ddi_soft_state_fini(&su_asycom);
		ddi_soft_state_fini(&su_asyncline);
	}

	return (i);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

static int
asyprobe(dev_info_t *devi)
{
	int		instance;
	ddi_acc_handle_t handle;
	uchar_t *addr;
	ddi_device_acc_attr_t attr;

	attr.devacc_attr_version = DDI_DEVICE_ATTR_V0;
	attr.devacc_attr_endian_flags = DDI_STRUCTURE_LE_ACC;
	attr.devacc_attr_dataorder = DDI_STRICTORDER_ACC;
	if (ddi_regs_map_setup(devi, SU_REGISTER_FILE_NO, (caddr_t *)&addr,
	    SU_REGOFFSET, SU_REGISTER_LEN, &attr, &handle) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "asyprobe regs map setup failed");
		return (DDI_PROBE_FAILURE);
	}
#ifdef DEBUG
	if (asydebug)
		printf("Probe address mapped %p\n", (void *)addr);
#endif

	/*
	 * Probe for the device:
	 * 	Ser. int. uses bits 0,1,2; FIFO uses 3,6,7; 4,5 wired low.
	 * 	If bit 4 or 5 appears on inb() ISR, board is not there.
	 */
	if (ddi_get8(handle, addr+ISR) & 0x30) {
		ddi_regs_map_free(&handle);
		return (DDI_PROBE_FAILURE);
	}

	instance = ddi_get_instance(devi);
	if (max_asy_instance < instance)
		max_asy_instance = instance;
	ddi_regs_map_free(&handle);

	return (DDI_PROBE_SUCCESS); /* hw is present */
}

static int
asydetach(dev_info_t *devi, ddi_detach_cmd_t cmd)
{
	register int	instance;
	struct asycom	*asy;
	struct asyncline *async;
	char		name[16];

	instance = ddi_get_instance(devi);	/* find out which unit */

	asy = (struct asycom *)ddi_get_soft_state(su_asycom, instance);
	async = (struct asyncline *)ddi_get_soft_state(su_asyncline, instance);

	switch (cmd) {
		case DDI_DETACH:
			break;
		case DDI_SUSPEND:
			/* grab both mutex locks */
			mutex_enter(asy->asy_excl);
			mutex_enter(asy->asy_excl_hi);
			if (asy->suspended) {
				mutex_exit(asy->asy_excl_hi);
				mutex_exit(asy->asy_excl);
				return (DDI_SUCCESS);
			}
			asy->suspended = B_TRUE;

			/*
			 * The quad UART ST16C554D, version D2 (made by EXAR)
			 * has an anomaly of generating spurious interrupts
			 * when the ICR is loaded with zero. The workaround
			 * would be to read/write any register with DATA1 bit
			 * set to 0 before such write.
			 */
			if (asy->asy_hwtype == ASY16C554D)
				OUTB(SPR, 0);

			/* Disable further interrupts */
			OUTB(ICR, 0);
			mutex_exit(asy->asy_excl_hi);
			mutex_exit(asy->asy_excl);
			return (DDI_SUCCESS);

		default:
			return (DDI_FAILURE);
	}

#ifdef DEBUG
	if (asydebug & ASY_DEBUG_INIT)
		cmn_err(CE_NOTE, "su%d: ASY%s shutdown.", instance,
		    asy->asy_hwtype == ASY82510 ? "82510" :
		    asy->asy_hwtype == ASY16550AF ? "16550AF" :
		    asy->asy_hwtype == ASY16C554D ? "16C554D" :
		    "8250");
#endif
	/*
	 * Before removing interrupts it is always better to disable
	 * interrupts if the chip gives a provision to disable the
	 * serial port interrupts.
	 */
	mutex_enter(asy->asy_excl);
	mutex_enter(asy->asy_excl_hi);
	/* disable interrupts, see EXAR bug */
	if (asy->asy_hwtype == ASY16C554D)
		OUTB(SPR, 0);
	OUTB(ICR, 0);
	mutex_exit(asy->asy_excl_hi);
	mutex_exit(asy->asy_excl);

	/* remove minor device node(s) for this device */
	(void) sprintf(name, "%c", (instance+'a'));	/* serial-port */
	ddi_remove_minor_node(devi, name);
	(void) sprintf(name, "%c,cu", (instance+'a')); /* serial-port:dailout */
	ddi_remove_minor_node(devi, name);

	mutex_destroy(asy->asy_excl);
	mutex_destroy(asy->asy_excl_hi);
	kmem_free(asy->asy_excl, sizeof (kmutex_t));
	kmem_free(asy->asy_excl_hi, sizeof (kmutex_t));
	cv_destroy(&async->async_flags_cv);
	kstat_delete(asy->sukstat);
	ddi_remove_intr(devi, 0, asy->asy_iblock);
	ddi_regs_map_free(&asy->asy_handle);
	ddi_remove_softintr(asy->asy_softintr_id);
	mutex_destroy(asy->asy_soft_lock);
	kmem_free(asy->asy_soft_lock, sizeof (kmutex_t));
	ddi_soft_state_free(su_asycom, instance);
	ddi_soft_state_free(su_asyncline, instance);
	return (DDI_SUCCESS);
}

static int
asyattach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	register int	instance;
	struct asycom	*asy;
	struct asyncline *async;
	char		name[40];
	ddi_device_acc_attr_t attr;
	enum states { EMPTY, SOFTSTATE, REGSMAP, MUTEXES, ADDINTR,
	    SOFTINTR, ASYINIT, KSTAT, MINORNODE };
	enum states state = EMPTY;
	char *hwtype;

	instance = ddi_get_instance(devi);	/* find out which unit */

	/* cannot attach a device that has not been probed first */
	if (instance > max_asy_instance)
		return (DDI_FAILURE);

	if (cmd != DDI_RESUME) {
		/* Allocate soft state space */
		if (ddi_soft_state_zalloc(su_asycom, instance) != DDI_SUCCESS) {
			cmn_err(CE_WARN, "su%d: cannot allocate soft state",
			    instance);
			goto error;
		}
	}
	state = SOFTSTATE;

	asy = (struct asycom *)ddi_get_soft_state(su_asycom, instance);

	if (asy == NULL) {
		cmn_err(CE_WARN, "su%d: cannot get soft state", instance);
		goto error;
	}

	switch (cmd) {
		case DDI_ATTACH:
			break;
		case DDI_RESUME: {
			struct asyncline *async;

			/* grab both mutex locks */
			mutex_enter(asy->asy_excl);
			mutex_enter(asy->asy_excl_hi);
			if (!asy->suspended) {
				mutex_exit(asy->asy_excl_hi);
				mutex_exit(asy->asy_excl);
				return (DDI_SUCCESS);
			}
			/*
			 * re-setup all the registers and enable interrupts if
			 * needed
			 */
			async = (struct asyncline *)asy->asy_priv;
			if ((async) && (async->async_flags & ASYNC_ISOPEN))
				(void) asy_program(asy, ASY_INIT);
			asy->suspended = B_FALSE;
			mutex_exit(asy->asy_excl_hi);
			mutex_exit(asy->asy_excl);
			return (DDI_SUCCESS);
		}
		default:
			goto error;
	}

	attr.devacc_attr_version = DDI_DEVICE_ATTR_V0;
	attr.devacc_attr_endian_flags = DDI_STRUCTURE_LE_ACC;
	attr.devacc_attr_dataorder = DDI_STRICTORDER_ACC;

	if (ddi_regs_map_setup(devi, SU_REGISTER_FILE_NO,
	    (caddr_t *)&asy->asy_ioaddr, SU_REGOFFSET, SU_REGISTER_LEN,
	    &attr, &asy->asy_handle) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "asyprobe regs map setup failed");
		goto error;
	}
	state = REGSMAP;

#ifdef DEBUG
	if (asydebug)
		printf("su attach mapped %p\n", (void *)asy->asy_ioaddr);
#endif

	/*
	 * Initialize the port with default settings.
	 */
	asy->asy_fifo_buf = 1;
	asy->asy_use_fifo = FIFO_OFF;

	/*
	 * Check for baudrate generator's "baud-divisor-factor" property setup
	 * by OBP, since different UART chips might have different baudrate
	 * generator divisor. e.g., in case of NSPG's Sputnik platform, the
	 * baud-divisor-factor is 13, it uses dedicated 16552 "DUART" chip
	 * instead of SuperIO. Since the baud-divisor-factor must be a positive
	 * integer, the divisors will always be at least as large as the values
	 * in asyspdtab[].  Make the default factor 1.
	 */
	asy->asy_baud_divisor_factor = ddi_prop_get_int(DDI_DEV_T_ANY, devi,
	    DDI_PROP_DONTPASS, "baud-divisor-factor", 1);

	/* set speed cap */
	asy->asy_speed_cap = ddi_prop_get_int(DDI_DEV_T_ANY, devi,
	    DDI_PROP_DONTPASS, "serial-speed-cap", 115200);

	/* check for ASY82510 chip */
	OUTB(ISR, 0x20);
	if (INB(ISR) & 0x20) { /* 82510 chip is present */
		/*
		 * Since most of the general operation of the 82510 chip
		 * can be done from BANK 0 (8250A/16450 compatable mode)
		 * we will default to BANK 0.
		 */
		asy->asy_hwtype = ASY82510;
		OUTB(DAT+7, 0x04); /* clear status */
		OUTB(ISR, 0x40); /* set to bank 2 */
		OUTB(MCR, 0x08); /* IMD */
		OUTB(DAT, 0x21); /* FMD */
		OUTB(ISR, 0x00); /* set to bank 0 */
		asy->asy_trig_level = 0;
	} else { /* Set the UART in FIFO mode if it has FIFO buffers */
		asy->asy_hwtype = ASY16550AF;
		OUTB(FIFOR, 0x00); /* clear fifo register */
		asy->asy_trig_level = 0x00; /* sets the fifo Threshold to 1 */

		/* set/Enable FIFO */
		OUTB(FIFOR, FIFO_ON | FIFODMA | FIFOTXFLSH | FIFORXFLSH |
		    (asy->asy_trig_level & 0xff));

		if ((INB(ISR) & 0xc0) == 0xc0)
			asy->asy_use_fifo = FIFO_ON;
		else {
			asy->asy_hwtype = ASY8250;
			OUTB(FIFOR, 0x00); /* NO FIFOs */
			asy->asy_trig_level = 0;
		}
	}

	/* check for ST16C554D chip */
	if ((ddi_prop_lookup_string(DDI_DEV_T_ANY, devi, DDI_PROP_NOTPROM |
	    DDI_PROP_DONTPASS, "hwtype", &hwtype)) == DDI_PROP_SUCCESS) {
		if (strcmp(hwtype, "ST16C554D") == 0)
			asy->asy_hwtype = ASY16C554D;
		ddi_prop_free(hwtype);
	}

	/* disable interrupts, see EXAR bug */
	if (asy->asy_hwtype == ASY16C554D)
		OUTB(SPR, 0);
	OUTB(ICR, 0);
	OUTB(LCR, DLAB); /* select baud rate generator */
	/* Set the baud rate to 9600 */
	OUTB(DAT+DLL, (ASY9600*asy->asy_baud_divisor_factor) & 0xff);
	OUTB(DAT+DLH, ((ASY9600*asy->asy_baud_divisor_factor) >> 8) & 0xff);
	OUTB(LCR, STOP1|BITS8);
	OUTB(MCR, (DTR | RTS| OUT2));

	/*
	 * Set up the other components of the asycom structure for this port.
	 */
	asy->asy_excl = (kmutex_t *)
	    kmem_zalloc(sizeof (kmutex_t), KM_SLEEP);
	asy->asy_excl_hi = (kmutex_t *)
	    kmem_zalloc(sizeof (kmutex_t), KM_SLEEP);
	asy->asy_soft_lock = (kmutex_t *)
	    kmem_zalloc(sizeof (kmutex_t), KM_SLEEP);
	asy->asy_unit = instance;
	asy->asy_dip = devi;

	if (ddi_get_iblock_cookie(devi, 0, &asy->asy_iblock) != DDI_SUCCESS) {
		cmn_err(CE_NOTE,
		    "Get iblock_cookie failed-Device interrupt%x\n", instance);
		goto error;
	}

	if (ddi_get_soft_iblock_cookie(devi, DDI_SOFTINT_HIGH,
	    &asy->asy_soft_iblock) != DDI_SUCCESS) {
		cmn_err(CE_NOTE, "Get iblock_cookie failed -soft interrupt%x\n",
		    instance);
		goto error;
	}

	mutex_init(asy->asy_soft_lock, NULL, MUTEX_DRIVER,
	    (void *)asy->asy_soft_iblock);
	mutex_init(asy->asy_excl, NULL, MUTEX_DRIVER, NULL);
	mutex_init(asy->asy_excl_hi, NULL, MUTEX_DRIVER,
	    (void *)asy->asy_iblock);
	state = MUTEXES;

	/*
	 * Install interrupt handlers for this device.
	 */
	if (ddi_add_intr(devi, 0, &(asy->asy_iblock), 0, asyintr,
	    (caddr_t)asy) != DDI_SUCCESS) {
		cmn_err(CE_CONT,
		    "Cannot set device interrupt for su driver\n");
		goto error;
	}
	state = ADDINTR;

	if (ddi_add_softintr(devi, DDI_SOFTINT_HIGH, &(asy->asy_softintr_id),
	    &asy->asy_soft_iblock, 0, asysoftintr, (caddr_t)asy)
	    != DDI_SUCCESS) {
		cmn_err(CE_CONT, "Cannot set soft interrupt for su driver\n");
		goto error;
	}
	state = SOFTINTR;

	/* initialize the asyncline structure */
	if (ddi_soft_state_zalloc(su_asyncline, instance) != DDI_SUCCESS) {
		cmn_err(CE_CONT, "su%d: cannot allocate soft state", instance);
		goto error;
	}
	state = ASYINIT;

	async = (struct asyncline *)ddi_get_soft_state(su_asyncline, instance);

	mutex_enter(asy->asy_excl);
	async->async_common = asy;
	cv_init(&async->async_flags_cv, NULL, CV_DEFAULT, NULL);
	mutex_exit(asy->asy_excl);

	if ((asy->sukstat = kstat_create("su", instance, "serialstat",
	    "misc", KSTAT_TYPE_NAMED, 2, KSTAT_FLAG_VIRTUAL)) != NULL) {
		asy->sukstat->ks_data = &asy->kstats;
		kstat_named_init(&asy->kstats.ringover, "ring buffer overflow",
		    KSTAT_DATA_UINT64);
		kstat_named_init(&asy->kstats.siloover, "silo overflow",
		    KSTAT_DATA_UINT64);
		kstat_install(asy->sukstat);
	}
	state = KSTAT;

	if (strcmp(ddi_node_name(devi), "rsc-console") == 0) {
		/*
		 * If the device is configured as the 'rsc-console'
		 * create the minor device for this node.
		 */
		if (ddi_create_minor_node(devi, "ssp", S_IFCHR,
		    asy->asy_unit | RSC_DEVICE, DDI_PSEUDO, NULL)
		    == DDI_FAILURE) {
			cmn_err(CE_WARN,
			    "%s%d: Failed to create node rsc-console",
			    ddi_get_name(devi), ddi_get_instance(devi));
			goto error;
		}

		asy->asy_lom_console = 0;
		asy->asy_rsc_console = 1;
		asy->asy_rsc_control = 0;
		asy->asy_device_type = ASY_SERIAL;
		asy->asy_flags |= ASY_IGNORE_CD;

	} else if (strcmp(ddi_node_name(devi), "lom-console") == 0) {
		/*
		 * If the device is configured as the 'lom-console'
		 * create the minor device for this node.
		 * Do not create a dialout device.
		 * Use the same minor numbers as would be used for standard
		 * serial instances.
		 */
		if (ddi_create_minor_node(devi, "lom-console", S_IFCHR,
		    instance, DDI_NT_SERIAL_LOMCON, NULL) == DDI_FAILURE) {
			cmn_err(CE_WARN,
			    "%s%d: Failed to create node lom-console",
			    ddi_get_name(devi), ddi_get_instance(devi));
			goto error;
		}
		asy->asy_lom_console = 1;
		asy->asy_rsc_console = 0;
		asy->asy_rsc_control = 0;
		asy->asy_device_type = ASY_SERIAL;
		asy->asy_flags |= ASY_IGNORE_CD;

	} else if (strcmp(ddi_node_name(devi), "rsc-control") == 0) {
		/*
		 * If the device is configured as the 'rsc-control'
		 * create the minor device for this node.
		 */
		if (ddi_create_minor_node(devi, "sspctl", S_IFCHR,
		    asy->asy_unit | RSC_DEVICE, DDI_PSEUDO, NULL)
		    == DDI_FAILURE) {
			cmn_err(CE_WARN, "%s%d: Failed to create rsc-control",
			    ddi_get_name(devi), ddi_get_instance(devi));
			goto error;
		}

		asy->asy_lom_console = 0;
		asy->asy_rsc_console = 0;
		asy->asy_rsc_control = 1;
		asy->asy_device_type = ASY_SERIAL;
		asy->asy_flags |= ASY_IGNORE_CD;

	} else if (ddi_getprop(DDI_DEV_T_ANY, devi, DDI_PROP_DONTPASS,
	    "keyboard", 0)) {
		/*
		 * If the device is a keyboard, then create an internal
		 * pathname so that the dacf code will link the node into
		 * the keyboard console stream.  See dacf.conf.
		 */
		if (ddi_create_internal_pathname(devi, "keyboard",
		    S_IFCHR, instance) == DDI_FAILURE) {
			goto error;
		}
		asy->asy_flags |= ASY_IGNORE_CD;	/* ignore cd */
		asy->asy_device_type = ASY_KEYBOARD; 	/* Device type */
	} else if (ddi_getprop(DDI_DEV_T_ANY, devi, DDI_PROP_DONTPASS,
	    "mouse", 0)) {
		/*
		 * If the device is a mouse, then create an internal
		 * pathname so that the dacf code will link the node into
		 * the mouse stream.  See dacf.conf.
		 */
		if (ddi_create_internal_pathname(devi, "mouse", S_IFCHR,
		    instance) == DDI_FAILURE) {
			goto error;
		}
		asy->asy_flags |= ASY_IGNORE_CD;	/* ignore cd */
		asy->asy_device_type = ASY_MOUSE;
	} else {
		/*
		 * If not used for keyboard/mouse, create minor devices nodes
		 * for this device
		 */
		/* serial-port */
		(void) sprintf(name, "%c", (instance+'a'));
		if (ddi_create_minor_node(devi, name, S_IFCHR, instance,
		    DDI_NT_SERIAL_MB, NULL) == DDI_FAILURE) {
			goto error;
		}
		state = MINORNODE;
		/* serial-port:dailout */
		(void) sprintf(name, "%c,cu", (instance+'a'));
		if (ddi_create_minor_node(devi, name, S_IFCHR, instance|OUTLINE,
		    DDI_NT_SERIAL_MB_DO, NULL) == DDI_FAILURE) {
			goto error;
		}
		/* Property for ignoring DCD */
		if (ddi_getprop(DDI_DEV_T_ANY, devi, DDI_PROP_DONTPASS,
		    "ignore-cd", 0)) {
			asy->asy_flags |= ASY_IGNORE_CD;  /* ignore cd */
		} else {
			asy->asy_flags &= ~ASY_IGNORE_CD;
			/*
			 * if ignore-cd is not available it could be
			 * some old legacy platform, try to see
			 * whether the old legacy property exists
			 */
			(void) sprintf(name,
			    "port-%c-ignore-cd", (instance+ 'a'));
			if (ddi_getprop(DDI_DEV_T_ANY, devi,
			    DDI_PROP_DONTPASS, name, 0))
				asy->asy_flags |= ASY_IGNORE_CD;
		}
		asy->asy_device_type = ASY_SERIAL;
	}

	/*
	 * Fill in the polled I/O structure
	 */
	asy->polledio.cons_polledio_version = CONSPOLLEDIO_V0;
	asy->polledio.cons_polledio_argument = (cons_polledio_arg_t)asy;
	asy->polledio.cons_polledio_putchar =  asyputchar;
	asy->polledio.cons_polledio_getchar = asygetchar;
	asy->polledio.cons_polledio_ischar = asyischar;
	asy->polledio.cons_polledio_enter = asy_polled_enter;
	asy->polledio.cons_polledio_exit = asy_polled_exit;

	/* Initialize saved ICR and polled_enter */
	asy->polled_icr = 0;
	asy->polled_enter = B_FALSE;

	ddi_report_dev(devi);
	return (DDI_SUCCESS);

error:
	if (state == MINORNODE) {
		(void) sprintf(name, "%c", (instance+'a'));
		ddi_remove_minor_node(devi, name);
	}
	if (state >= KSTAT)
		kstat_delete(asy->sukstat);
	if (state >= ASYINIT) {
		cv_destroy(&async->async_flags_cv);
		ddi_soft_state_free(su_asyncline, instance);
	}
	if (state >= SOFTINTR)
		ddi_remove_softintr(asy->asy_softintr_id);
	if (state >= ADDINTR)
		ddi_remove_intr(devi, 0, asy->asy_iblock);
	if (state >= MUTEXES) {
		mutex_destroy(asy->asy_excl_hi);
		mutex_destroy(asy->asy_excl);
		mutex_destroy(asy->asy_soft_lock);
		kmem_free(asy->asy_excl_hi, sizeof (kmutex_t));
		kmem_free(asy->asy_excl, sizeof (kmutex_t));
		kmem_free(asy->asy_soft_lock, sizeof (kmutex_t));
	}
	if (state >= REGSMAP)
		ddi_regs_map_free(&asy->asy_handle);
	if (state >= SOFTSTATE)
		ddi_soft_state_free(su_asycom, instance);
	/* no action for EMPTY state */
	return (DDI_FAILURE);
}

static int
asyinfo(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg,
    void **result)
{
	_NOTE(ARGUNUSED(dip))
	register dev_t dev = (dev_t)arg;
	register int instance, error;
	struct asycom *asy;

	if ((instance = UNIT(dev)) > max_asy_instance)
		return (DDI_FAILURE);

	switch (infocmd) {
		case DDI_INFO_DEVT2DEVINFO:
			asy = (struct asycom *)ddi_get_soft_state(su_asycom,
			    instance);
			if (asy->asy_dip == NULL)
				error = DDI_FAILURE;
			else {
				*result = (void *) asy->asy_dip;
				error = DDI_SUCCESS;
			}
			break;
		case DDI_INFO_DEVT2INSTANCE:
			*result = (void *)(uintptr_t)instance;
			error = DDI_SUCCESS;
			break;
		default:
			error = DDI_FAILURE;
	}
	return (error);
}

static int
asyopen(queue_t *rq, dev_t *dev, int flag, int sflag, cred_t *cr)
{
	_NOTE(ARGUNUSED(sflag))
	struct asycom	*asy;
	struct asyncline *async;
	int		mcr;
	int		unit;
	int 		len;
	struct termios 	*termiosp;

#ifdef DEBUG
	if (asydebug & ASY_DEBUG_CLOSE)
		printf("open\n");
#endif
	unit = UNIT(*dev);
	if (unit > max_asy_instance)
		return (ENXIO);		/* unit not configured */

	async = (struct asyncline *)ddi_get_soft_state(su_asyncline, unit);
	if (async == NULL)
		return (ENXIO);

	asy = async->async_common;
	if (asy == NULL)
		return (ENXIO);		/* device not found by autoconfig */

	mutex_enter(asy->asy_excl);
	asy->asy_priv = (caddr_t)async;

again:
	mutex_enter(asy->asy_excl_hi);
	/*
	 * Block waiting for carrier to come up, unless this is a no-delay open.
	 */
	if (!(async->async_flags & ASYNC_ISOPEN)) {
		/*
		 * If this port is for a RSC console or control
		 * use the following termio info
		 */
		if (asy->asy_rsc_console || asy->asy_rsc_control) {
			async->async_ttycommon.t_cflag = CIBAUDEXT | CBAUDEXT |
			    (B115200 & CBAUD);
			async->async_ttycommon.t_cflag |= ((B115200 << IBSHIFT)
			    & CIBAUD);
			async->async_ttycommon.t_cflag |= CS8 | CREAD | CLOCAL;
		} else if (asy->asy_lom_console) {
			async->async_ttycommon.t_cflag = B9600 & CBAUD;
			async->async_ttycommon.t_cflag |= ((B9600 << IBSHIFT)
			    & CIBAUD);
			async->async_ttycommon.t_cflag |= CS8 | CREAD | CLOCAL;
		} else {

			/*
			 * Set the default termios settings (cflag).
			 * Others are set in ldterm.  Release the spin
			 * mutex as we can block here, reaquire before
			 * calling asy_program.
			 */
			mutex_exit(asy->asy_excl_hi);
			if (ddi_getlongprop(DDI_DEV_T_ANY, ddi_root_node(),
			    0, "ttymodes", (caddr_t)&termiosp, &len)
			    == DDI_PROP_SUCCESS &&
			    len == sizeof (struct termios)) {
				async->async_ttycommon.t_cflag =
				    termiosp->c_cflag;
				kmem_free(termiosp, len);
			} else {
				cmn_err(CE_WARN,
					"su: couldn't get ttymodes property!");
			}
			mutex_enter(asy->asy_excl_hi);
		}
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
		(void) asy_program(asy, ASY_INIT);
	} else if ((async->async_ttycommon.t_flags & TS_XCLUDE) &&
	    secpolicy_excl_open(cr) != 0) {
		mutex_exit(asy->asy_excl_hi);
		mutex_exit(asy->asy_excl);
		return (EBUSY);
	} else if ((*dev & OUTLINE) && !(async->async_flags & ASYNC_OUT)) {
		mutex_exit(asy->asy_excl_hi);
		mutex_exit(asy->asy_excl);
		return (EBUSY);
	}

	if (*dev & OUTLINE)
		async->async_flags |= ASYNC_OUT;

	/* Raise DTR on every open */
	mcr = INB(MCR);
	OUTB(MCR, mcr|DTR);

	/*
	 * Check carrier.
	 */
	if (asy->asy_flags & ASY_IGNORE_CD)
		async->async_ttycommon.t_flags |= TS_SOFTCAR;
	if ((async->async_ttycommon.t_flags & TS_SOFTCAR) ||
	    (INB(MSR) & DCD))
		async->async_flags |= ASYNC_CARR_ON;
	else
		async->async_flags &= ~ASYNC_CARR_ON;
	mutex_exit(asy->asy_excl_hi);

	/*
	 * If FNDELAY and FNONBLOCK are clear, block until carrier up.
	 * Quit on interrupt.
	 */
	if (!(flag & (FNDELAY|FNONBLOCK)) &&
	    !(async->async_ttycommon.t_cflag & CLOCAL)) {
		if (!(async->async_flags & (ASYNC_CARR_ON|ASYNC_OUT)) ||
		    ((async->async_flags & ASYNC_OUT) &&
		    !(*dev & OUTLINE))) {
				async->async_flags |= ASYNC_WOPEN;
				if (cv_wait_sig(&async->async_flags_cv,
				    asy->asy_excl) == 0) {
					async->async_flags &= ~ASYNC_WOPEN;
					mutex_exit(asy->asy_excl);
					return (EINTR);
				}
				async->async_flags &= ~ASYNC_WOPEN;
				goto again;
		}
	} else if ((async->async_flags & ASYNC_OUT) && !(*dev & OUTLINE)) {
		mutex_exit(asy->asy_excl);
		return (EBUSY);
	}

	if (asy->suspended) {
		mutex_exit(asy->asy_excl);
		(void) ddi_dev_is_needed(asy->asy_dip, 0, 1);
		mutex_enter(asy->asy_excl);
	}

	async->async_ttycommon.t_readq = rq;
	async->async_ttycommon.t_writeq = WR(rq);
	rq->q_ptr = WR(rq)->q_ptr = (caddr_t)async;
	mutex_exit(asy->asy_excl);
	qprocson(rq);
	async->async_flags |= ASYNC_ISOPEN;
	async->async_polltid = 0;
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
	mutex_enter(asy->asy_excl);
	mutex_enter(asy->asy_excl_hi);
	if (!(async->async_flags & (ASYNC_BREAK|ASYNC_DELAY|ASYNC_PROGRESS))) {
		async->async_ocnt = 0;
		async->async_flags &= ~ASYNC_BUSY;
		async->async_timer = 0;
		bp = async->async_xmitblk;
		async->async_xmitblk = NULL;
		mutex_exit(asy->asy_excl_hi);
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
		    drv_usectohz(su_drain_check));
		mutex_exit(asy->asy_excl_hi);
	}
	mutex_exit(asy->asy_excl);
}

/*
 * Close routine.
 */
static int
asyclose(queue_t *q, int flag)
{
	struct asyncline *async;
	struct asycom	 *asy;
	int icr, lcr;
	int		nohupcl;


#ifdef DEBUG
	if (asydebug & ASY_DEBUG_CLOSE)
		printf("close\n");
#endif
	async = q->q_ptr;
	ASSERT(async != NULL);
	asy = async->async_common;

	/* get the nohupcl OBP property of this device */
	nohupcl = ddi_getprop(DDI_DEV_T_ANY, asy->asy_dip, DDI_PROP_DONTPASS,
	    "nohupcl", 0);

	mutex_enter(asy->asy_excl);
	async->async_flags |= ASYNC_CLOSING;

	/*
	 * Turn off PPS handling early to avoid events occuring during
	 * close.  Also reset the DCD edge monitoring bit.
	 */
	mutex_enter(asy->asy_excl_hi);
	asy->asy_flags &= ~(ASY_PPS | ASY_PPS_EDGE);
	mutex_exit(asy->asy_excl_hi);

	/*
	 * There are two flavors of break -- timed (M_BREAK or TCSBRK) and
	 * untimed (TIOCSBRK).  For the timed case, these are enqueued on our
	 * write queue and there's a timer running, so we don't have to worry
	 * about them.  For the untimed case, though, the user obviously made a
	 * mistake, because these are handled immediately.  We'll terminate the
	 * break now and honor their implicit request by discarding the rest of
	 * the data.
	 */
	if (!(async->async_flags & ASYNC_BREAK)) {
		mutex_enter(asy->asy_excl_hi);
		lcr = INB(LCR);
		if (lcr & SETBREAK) {
			OUTB(LCR, (lcr & ~SETBREAK));
		}
		mutex_exit(asy->asy_excl_hi);
		if (lcr & SETBREAK)
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
	 * trust async_ocnt.  Instead, we use a flag.
	 *
	 * Note that loss of carrier will cause the output queue to be flushed,
	 * and we'll wake up again and finish normally.
	 */
	if (!ddi_can_receive_sig() && su_drain_check != 0) {
		async->async_flags &= ~ASYNC_PROGRESS;
		async->async_timer = timeout(async_progress_check, async,
		    drv_usectohz(su_drain_check));
	}

	while (async->async_ocnt > 0 ||
	    async->async_ttycommon.t_writeq->q_first != NULL ||
	    (async->async_flags & (ASYNC_BUSY|ASYNC_BREAK|ASYNC_DELAY))) {
		if (cv_wait_sig(&async->async_flags_cv, asy->asy_excl) == 0)
			break;
	}
	if (async->async_timer != 0) {
		(void) untimeout(async->async_timer);
		async->async_timer = 0;
	}

nodrain:
	mutex_enter(asy->asy_excl_hi);

	/* turn off the loopback mode */
	if ((async->async_dev != rconsdev) &&
	    (async->async_dev != kbddev) &&
	    (async->async_dev != stdindev)) {
		OUTB(MCR, INB(MCR) & ~ ASY_LOOP);
	}

	async->async_ocnt = 0;
	if (async->async_xmitblk != NULL)
		freeb(async->async_xmitblk);
	async->async_xmitblk = NULL;

	/*
	 * If the "nohupcl" OBP property is set for this device, do
	 * not turn off DTR and RTS no matter what.  Otherwise, if the
	 * line has HUPCL set or is incompletely opened, turn off DTR
	 * and RTS to fix the modem line.
	 */
	if (!nohupcl && ((async->async_ttycommon.t_cflag & HUPCL) ||
	    (async->async_flags & ASYNC_WOPEN))) {
		/* turn off DTR, RTS but NOT interrupt to 386 */
		OUTB(MCR, OUT2);
		mutex_exit(asy->asy_excl_hi);
		/*
		 * Don't let an interrupt in the middle of close
		 * bounce us back to the top; just continue closing
		 * as if nothing had happened.
		 */
		if (cv_wait_sig(&lbolt_cv, asy->asy_excl) == 0)
			goto out;
		mutex_enter(asy->asy_excl_hi);
	}

	/*
	 * If nobody's using it now, turn off receiver interrupts.
	 */
	if ((async->async_flags & (ASYNC_WOPEN|ASYNC_ISOPEN)) == 0) {
		icr = INB(ICR);
		OUTB(ICR, (icr & ~RIEN));
	}
	mutex_exit(asy->asy_excl_hi);
out:
	/*
	 * Clear out device state.
	 */
	async->async_flags = 0;
	ttycommon_close(&async->async_ttycommon);
	cv_broadcast(&async->async_flags_cv);

	/*
	 * Clear ASY_DOINGSOFT and ASY_NEEDSOFT in case we were in
	 * async_softint or an interrupt was pending when the process
	 * using the port exited.
	 */
	asy->asy_flags &= ~ASY_DOINGSOFT & ~ASY_NEEDSOFT;

	/*
	 * Cancel outstanding "bufcall" request.
	 */
	if (async->async_wbufcid) {
		unbufcall(async->async_wbufcid);
		async->async_wbufcid = 0;
	}

	/*
	 * If inperim is true, it means the port is closing while there's
	 * a pending software interrupt.  async_flags has been zeroed out,
	 * so this instance of leaveq() needs to be called before we call
	 * qprocsoff() to disable services on the q.  If inperim is false,
	 * leaveq() has already been called or we're not in a perimeter.
	 */
	if (asy->inperim == B_TRUE) {
		asy->inperim = B_FALSE;
		mutex_exit(asy->asy_excl);
		leaveq(q);
	} else {
		mutex_exit(asy->asy_excl);
	}

	/* Note that qprocsoff can't be done until after interrupts are off */
	qprocsoff(q);
	q->q_ptr = WR(q)->q_ptr = NULL;
	async->async_ttycommon.t_readq = NULL;
	async->async_ttycommon.t_writeq = NULL;

	return (0);
}

/*
 * Checks to see if the serial port is still transmitting
 * characters.  It returns true when there are characters
 * queued to transmit,  when the holding register contains
 * a byte, or when the shifting register still contains
 * data to send.
 *
 */
static boolean_t
asy_isbusy(struct asycom *asy)
{
	struct asyncline *async;

#ifdef DEBUG
	if (asydebug & ASY_DEBUG_EOT)
		printf("isbusy\n");
#endif
	async = (struct asyncline *)asy->asy_priv;
	ASSERT(mutex_owned(asy->asy_excl));
	ASSERT(mutex_owned(asy->asy_excl_hi));
	return ((async->async_ocnt > 0) ||
	    ((INB(LSR) & XSRE) == 0));
}

/*
 * Program the ASY port. Most of the async operation is based on the values
 * of 'c_iflag' and 'c_cflag'.
 */
static int
asy_program(struct asycom *asy, int mode)
{
	struct asyncline *async;
	int baudrate, c_flag;
	int icr, lcr;
	int ocflags;
	int error = 0;

	ASSERT(mutex_owned(asy->asy_excl));
	ASSERT(mutex_owned(asy->asy_excl_hi));

#ifdef DEBUG
	if (asydebug & ASY_DEBUG_PROCS)
		printf("program\n");
#endif
	async = (struct asyncline *)asy->asy_priv;

	baudrate = async->async_ttycommon.t_cflag & CBAUD;
	if (async->async_ttycommon.t_cflag & CBAUDEXT)
		baudrate += 16;

	/* Limit baudrate so it can't index out of baudtable */
	if (baudrate >= N_SU_SPEEDS) baudrate = B9600;

	/*
	 * If baud rate requested is greater than the speed cap
	 * or is an unsupported baud rate then reset t_cflag baud
	 * to the last valid baud rate.  If this is the initial
	 * pass through asy_program then set it to 9600.
	 */
	if (((baudrate > 0) && (asyspdtab[baudrate] == 0)) ||
	    (baudtable[baudrate] > asy->asy_speed_cap)) {
		async->async_ttycommon.t_cflag &= ~CBAUD & ~CBAUDEXT &
		    ~CIBAUD & ~CIBAUDEXT;
		if (mode == ASY_INIT) {
			async->async_ttycommon.t_cflag |= B9600;
			async->async_ttycommon.t_cflag |= B9600 << IBSHIFT;
			baudrate = B9600;
		} else {
			async->async_ttycommon.t_cflag |=
			    (asy->asy_ocflags & (CBAUD | CBAUDEXT |
			    CIBAUD | CIBAUDEXT));
			error = EINVAL;
			goto end;
		}
	}

	/*
	 * If CIBAUD and CIBAUDEXT are zero then we should set them to
	 * the equivelant output baud bits.  Else, if CIBAUD and CIBAUDEXT
	 * don't match CBAUD and CBAUDEXT respectively then we should
	 * notify the requestor that we do not support split speeds.
	 */
	if ((async->async_ttycommon.t_cflag  & (CIBAUD|CIBAUDEXT)) == 0) {
		async->async_ttycommon.t_cflag |=
		    (async->async_ttycommon.t_cflag & CBAUD) << IBSHIFT;
		if (async->async_ttycommon.t_cflag & CBAUDEXT)
			async->async_ttycommon.t_cflag |= CIBAUDEXT;
	} else {
		if ((((async->async_ttycommon.t_cflag & CBAUD) << IBSHIFT) !=
		    (async->async_ttycommon.t_cflag & CIBAUD)) ||
		    !(((async->async_ttycommon.t_cflag & (CBAUDEXT |
		    CIBAUDEXT)) == (CBAUDEXT | CIBAUDEXT)) ||
		    ((async->async_ttycommon.t_cflag & (CBAUDEXT |
		    CIBAUDEXT)) == 0))) {
			async->async_ttycommon.t_cflag &= ~CBAUD & ~CBAUDEXT &
			    ~CIBAUD & ~CIBAUDEXT;
			async->async_ttycommon.t_cflag |=
			    (asy->asy_ocflags & (CBAUD | CBAUDEXT |
			    CIBAUD | CIBAUDEXT));
			error = EINVAL;
			goto end;
		}
	}

	c_flag = async->async_ttycommon.t_cflag &
	    (CLOCAL | CREAD | CSTOPB | CSIZE | PARENB | PARODD | CBAUD |
	    CBAUDEXT | CIBAUD | CIBAUDEXT);

	/* disable interrupts, see EXAR bug */
	if (asy->asy_hwtype == ASY16C554D)
		OUTB(SPR, 0);
	OUTB(ICR, 0);

	ocflags = asy->asy_ocflags;

	/* flush/reset the status registers */
	if (mode == ASY_INIT) {
		(void) INB(DAT);
		(void) INB(ISR);
		(void) INB(LSR);
		(void) INB(MSR);
	}

	if (ocflags != (c_flag & ~CLOCAL) || mode == ASY_INIT) {
		/* Set line control */
		lcr = INB(LCR);
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

		/* set the baud rate when the rate is NOT B0 */
		if (baudrate != 0) {
			OUTB(LCR, DLAB);
			OUTB(DAT, (asyspdtab[baudrate] *
			    asy->asy_baud_divisor_factor) & 0xff);
			OUTB(ICR, ((asyspdtab[baudrate] *
			    asy->asy_baud_divisor_factor) >> 8) & 0xff);
		}
		/* set the line control modes */
		OUTB(LCR, lcr);

		/*
		 * if transitioning from CREAD off to CREAD on,
		 * flush the FIFO buffer if we have one.
		 */
		if ((ocflags & CREAD) == 0 && (c_flag & CREAD)) {
			if (asy->asy_use_fifo == FIFO_ON) {
				OUTB(FIFOR, FIFO_ON | FIFODMA | FIFORXFLSH |
				    (asy->asy_trig_level & 0xff));
			}
		}

		/* remember the new cflags */
		asy->asy_ocflags = c_flag & ~CLOCAL;
	}

	/* whether or not CLOCAL is set, modify the modem control lines */
	if (baudrate == 0)
		/* B0 has been issued, lower DTR */
		OUTB(MCR, RTS|OUT2);
	else
		/* raise DTR */
		OUTB(MCR, DTR|RTS|OUT2);

	/*
	 * Call the modem status interrupt handler to check for the carrier
	 * in case CLOCAL was turned off after the carrier came on.
	 * (Note: Modem status interrupt is not enabled if CLOCAL is ON.)
	 */
	async_msint(asy);

	/* Set interrupt control */
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

	OUTB(ICR, icr);
end:
	return (error);
}

/*
 * Polled mode support -- all functions called with interrupts
 * disabled.
 */

static void
asyputchar(cons_polledio_arg_t arg, uchar_t c)
{
	struct asycom *asy = (struct asycom *)arg;

	/*
	 * If we see a line feed make sure to also
	 * put out a carriage return.
	 */
	if (c == '\n')
		asyputchar(arg, '\r');

	while ((INB(LSR) & XHRE) == 0) {
		/* wait for the transmission to complete */
		drv_usecwait(10);
	}

	/* ouput the character */
	OUTB(DAT, c);
}

/*
 * Determines if there is a character avaialable for
 * reading.
 */
static boolean_t
asyischar(cons_polledio_arg_t arg)
{
	struct asycom *asy = (struct asycom *)arg;
	return ((INB(LSR) & RCA) != 0);
}

static int
asygetchar(cons_polledio_arg_t arg)
{
	struct asycom *asy = (struct asycom *)arg;

	/*
	 * Spin waiting for a character to be
	 * available to read.
	 */
	while (!asyischar(arg))
		drv_usecwait(10);

	return (INB(DAT));
}

/*
 * Called when machine is transitioning to polled mode
 */
static void
asy_polled_enter(cons_polledio_arg_t arg)
{
	struct asycom *asy = (struct asycom *)arg;

	mutex_enter(asy->asy_excl);
	mutex_enter(asy->asy_excl_hi);

	/*
	 * If this is the first time that asy_polled_enter()
	 * has been called, during this transition request,
	 * save the ICR. Clear the software interrupt
	 * flags since we won't be able to handle these when
	 * we are in polled mode.
	 */
	if (!asy->polled_enter) {
		asy->polled_enter = B_TRUE;
		asy->polled_icr = INB(ICR);

		/* Disable HW interrupts */
		if (asy->asy_hwtype == ASY16C554D)
			OUTB(SPR, 0);
		OUTB(ICR, 0);

		asy->asy_flags &= ~ASY_DOINGSOFT & ~ASY_NEEDSOFT;
	}
	mutex_exit(asy->asy_excl_hi);
	mutex_exit(asy->asy_excl);
}

/*
 * Called when machine is transitioning from polled mode.
 */
static void
asy_polled_exit(cons_polledio_arg_t arg)
{
	struct asycom *asy = (struct asycom *)arg;

	mutex_enter(asy->asy_excl);
	mutex_enter(asy->asy_excl_hi);

	/* Restore the ICR */
	OUTB(ICR, asy->polled_icr);

	/*
	 * We have finished this polled IO transition.
	 * Set polled_enter to B_FALSE to note this.
	 */
	asy->polled_enter = B_FALSE;
	mutex_exit(asy->asy_excl_hi);
	mutex_exit(asy->asy_excl);
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

	interrupt_id = INB(ISR) & 0x0F;
	async = (struct asyncline *)asy->asy_priv;
	if ((async == NULL) ||
	    !(async->async_flags & (ASYNC_ISOPEN|ASYNC_WOPEN))) {
		if (interrupt_id & NOINTERRUPT)  {
			return (DDI_INTR_UNCLAIMED);
		} else {
			lsr = INB(LSR);
			if ((lsr & BRKDET) &&
			    ((abort_enable == KIOCABORTENABLE) &&
			    (async->async_dev == rconsdev)))
				abort_sequence_enter((char *)NULL);
			else {
				/* reset line status */
				(void) INB(LSR);
				/* discard any data */
				(void) INB(DAT);
				/* reset modem status */
				(void) INB(MSR);
				return (DDI_INTR_CLAIMED);
			}
		}
	}
	/*
	 * Spurious interrupts happen in this driver
	 * because of the transmission on serial port not handled
	 * properly.
	 *
	 * The reasons for Spurious interrupts are:
	 *    1. There is a path in async_nstart which transmits
	 *	 characters without going through interrupt services routine
	 *	 which causes spurious interrupts to happen.
	 *    2. In the async_txint more than one character is sent
	 *	 in one interrupt service.
	 *    3. In async_rxint more than one characters are received in
	 *	 in one interrupt service.
	 *
	 * Hence we have flags to indicate that such scenerio has happened.
	 * and claim only such interrupts and others we donot claim it
	 * as it could be a indicator of some hardware problem.
	 *
	 */
	if (interrupt_id & NOINTERRUPT) {
		mutex_enter(asy->asy_excl_hi);
		if ((asy->asy_xmit_count > 1) ||
		    (asy->asy_out_of_band_xmit > 0) ||
		    (asy->asy_rx_count > 1)) {
			asy->asy_xmit_count = 0;
			asy->asy_out_of_band_xmit = 0;
			asy->asy_rx_count = 0;
			mutex_exit(asy->asy_excl_hi);
			return (DDI_INTR_CLAIMED);
		} else {
			mutex_exit(asy->asy_excl_hi);
			return (DDI_INTR_UNCLAIMED);
		}
	}
	ret_status = DDI_INTR_CLAIMED;
	mutex_enter(asy->asy_excl_hi);
	if (asy->asy_hwtype == ASY82510)
		OUTB(ISR, 0x00); /* set bank 0 */

#ifdef DEBUG
	if (asydebug & ASY_DEBUG_INTR)
		prom_printf("l");
#endif
	lsr = INB(LSR);
	switch (interrupt_id) {
	case RxRDY:
	case RSTATUS:
	case FFTMOUT:
		/* receiver interrupt or receiver errors */
		async_rxint(asy, lsr);
		break;
	case TxRDY:
		/* transmit interrupt */
		async_txint(asy, lsr);
		break;
	case MSTATUS:
		/* modem status interrupt */
		async_msint(asy);
		break;
	}
	mutex_exit(asy->asy_excl_hi);
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
async_txint(struct asycom *asy, uchar_t lsr)
{
	struct asyncline *async = (struct asyncline *)asy->asy_priv;
	int		fifo_len;
	int		xmit_progress;

	asycheckflowcontrol_hw(asy);

	/*
	 * If ASYNC_BREAK has been set, return to asyintr()'s context to
	 * claim the interrupt without performing any action.
	 */
	if (async->async_flags & ASYNC_BREAK)
		return;

	fifo_len = asy->asy_fifo_buf; /* with FIFO buffers */

	/*
	 * Check for flow control and do the needed action.
	 */
	if (asycheckflowcontrol_sw(asy)) {
		return;
	}

	if (async->async_ocnt > 0 &&
	    !(async->async_flags & (ASYNC_HW_OUT_FLW|ASYNC_STOPPED))) {
		xmit_progress = 0;
		while (fifo_len > 0 && async->async_ocnt > 0) {
			if (lsr & XHRE) {
				OUTB(DAT, *async->async_optr++);
				fifo_len--;
				async->async_ocnt--;
				xmit_progress++;
			}
			/*
			 * Reading the lsr, (moved reading at the end of
			 * while loop) as already we have read once at
			 * the beginning of interrupt service
			 */
			lsr = INB(LSR);
		}
		asy->asy_xmit_count = xmit_progress;
		if (xmit_progress > 0)
			async->async_flags |= ASYNC_PROGRESS;
	}

	if (fifo_len == 0) {
		return;
	}


	ASYSETSOFT(asy);
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
	struct asyncline *async = (struct asyncline *)asy->asy_priv;
	uchar_t c = 0;
	uint_t s = 0, needsoft = 0;
	register tty_common_t *tp;

	tp = &async->async_ttycommon;
	if (!(tp->t_cflag & CREAD)) {
		if (lsr & (RCA|PARERR|FRMERR|BRKDET|OVRRUN)) {
			(void) (INB(DAT) & 0xff);
		}
		return; /* line is not open for read? */
	}
	asy->asy_rx_count = 0;
	while (lsr & (RCA|PARERR|FRMERR|BRKDET|OVRRUN)) {
		c = 0;
		s = 0;
		asy->asy_rx_count++;
		if (lsr & RCA) {
			c = INB(DAT) & 0xff;
			/*
			 * Even a single character is received
			 * we need Soft interrupt to pass it to
			 * higher layers.
			 */
			needsoft = 1;
		}

		/* Check for character break sequence */
		if ((abort_enable == KIOCABORTALTERNATE) &&
		    (async->async_dev == rconsdev)) {
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
			if (s & FRERROR) { /* Handle framing errors */
				if (c == 0)  {
		/* Look for break on kbd, stdin, or rconsdev */
					if ((async->async_dev == kbddev) ||
					    ((async->async_dev == rconsdev) ||
					    (async->async_dev == stdindev)) &&
					    (abort_enable !=
					    KIOCABORTALTERNATE))
						abort_sequence_enter((char *)0);
					else
						async->async_break++;
				} else {
					if (RING_POK(async, 1))
						RING_MARK(async, c, s);
					else
						async->async_sw_overrun = 1;
				}
			} else  { /* Parity errors  handled by ldterm */
				if (RING_POK(async, 1))
					RING_MARK(async, c, s);
				else
					async->async_sw_overrun = 1;
			}
		lsr = INB(LSR);
		if (asy->asy_rx_count > 16) break;
	}
	/* Check whether there is a request for hw/sw inbound/input flow ctrl */
	if ((async->async_ttycommon.t_cflag & CRTSXOFF) ||
	    (async->async_ttycommon.t_iflag & IXOFF))
		if ((int)(RING_CNT(async)) > (RINGSIZE * 3)/4) {
#ifdef DEBUG
			if (asydebug & ASY_DEBUG_HFLOW)
				printf("asy%d: hardware flow stop input.\n",
				    UNIT(async->async_dev));
#endif
			async->async_flags |= ASYNC_HW_IN_FLOW;
			async->async_flowc = async->async_stopc;
			async->async_ringbuf_overflow = 1;
		}

	if ((async->async_flags & ASYNC_SERVICEIMM) || needsoft ||
	    (RING_FRAC(async)) || (async->async_polltid == 0))
		ASYSETSOFT(asy);	/* need a soft interrupt */
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
		gethrestime(&ts);
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
 * Modem status interrupt.
 *
 * (Note: It is assumed that the MSR hasn't been read by asyintr().)
 */

static void
async_msint(struct asycom *asy)
{
	struct asyncline *async = (struct asyncline *)asy->asy_priv;
	int msr;

	msr = INB(MSR);	/* this resets the interrupt */
	asy->asy_cached_msr = msr;
#ifdef DEBUG
	if (asydebug & ASY_DEBUG_STATE) {
		printf("   transition: %3s %3s %3s %3s\n"
		    "current state: %3s %3s %3s %3s\n",
		    (msr & DCTS) ? "CTS" : "   ",
		    (msr & DDSR) ? "DSR" : "   ",
		    (msr & DRI) ?  "RI " : "   ",
		    (msr & DDCD) ? "DCD" : "   ",
		    (msr & CTS) ?  "CTS" : "   ",
		    (msr & DSR) ?  "DSR" : "   ",
		    (msr & RI) ?   "RI " : "   ",
		    (msr & DCD) ?  "DCD" : "   ");
	}
#endif
	if (async->async_ttycommon.t_cflag & CRTSCTS && !(msr & CTS)) {
#ifdef DEBUG
		if (asydebug & ASY_DEBUG_HFLOW)
			printf("asy%d: hflow start\n",
			    UNIT(async->async_dev));
#endif
		async->async_flags |= ASYNC_HW_OUT_FLW;
	}
	if (asy->asy_hwtype == ASY82510)
		OUTB(MSR, (msr & 0xF0));

	/* Handle PPS event */
	if (asy->asy_flags & ASY_PPS)
		asy_ppsevent(asy, msr);

	async->async_ext++;
	ASYSETSOFT(asy);
}

/*
 * Handle a second-stage interrupt.
 */
uint_t
asysoftintr(caddr_t intarg)
{
	struct asycom *asy = (struct asycom *)intarg;
	struct asyncline *async;
	int rv;
	int cc;
	/*
	 * Test and clear soft interrupt.
	 */
	mutex_enter(asy->asy_soft_lock);
#ifdef DEBUG
	if (asydebug & ASY_DEBUG_PROCS)
		printf("softintr\n");
#endif
	rv = asy->asysoftpend;
	if (rv != 0)
		asy->asysoftpend = 0;
	mutex_exit(asy->asy_soft_lock);

	if (rv) {
		if (asy->asy_priv == NULL)
			return (rv);
		async = (struct asyncline *)asy->asy_priv;
		mutex_enter(asy->asy_excl_hi);
		if (asy->asy_flags & ASY_NEEDSOFT) {
			asy->asy_flags &= ~ASY_NEEDSOFT;
			mutex_exit(asy->asy_excl_hi);
			(void) async_softint(asy);
			mutex_enter(asy->asy_excl_hi);
		}
		/*
		 * There are some instances where the softintr is not
		 * scheduled and hence not called. It so happened that makes
		 * the last few characters to be stuck in ringbuffer.
		 * Hence, call once again the  handler so that the last few
		 * characters are cleared.
		 */
		cc = RING_CNT(async);
		mutex_exit(asy->asy_excl_hi);
		if (cc > 0) {
			(void) async_softint(asy);
		}
	}
	return (rv);
}

/*
 * Handle a software interrupt.
 */
static int
async_softint(struct asycom *asy)
{
	struct asyncline *async = (struct asyncline *)asy->asy_priv;
	uint_t	cc;
	mblk_t	*bp;
	queue_t	*q;
	uchar_t	val;
	uchar_t	c;
	tty_common_t	*tp;

#ifdef DEBUG
	if (asydebug & ASY_DEBUG_PROCS)
		printf("process\n");
#endif
	mutex_enter(asy->asy_excl);
	if (asy->asy_flags & ASY_DOINGSOFT) {
		mutex_exit(asy->asy_excl);
		return (0);
	}
	tp = &async->async_ttycommon;
	q = tp->t_readq;
	if (q != NULL) {
		mutex_exit(asy->asy_excl);
		enterq(q);
		mutex_enter(asy->asy_excl);
	}
	mutex_enter(asy->asy_excl_hi);
	asy->asy_flags |= ASY_DOINGSOFT;

	if (INB(ICR) & MIEN)
		val = asy->asy_cached_msr & 0xFF;
	else
		val = INB(MSR) & 0xFF;

	if (async->async_ttycommon.t_cflag & CRTSCTS) {
		if ((val & CTS) && (async->async_flags & ASYNC_HW_OUT_FLW)) {
#ifdef DEBUG
			if (asydebug & ASY_DEBUG_HFLOW)
				printf("asy%d: hflow start\n",
				    UNIT(async->async_dev));
#endif
			async->async_flags &= ~ASYNC_HW_OUT_FLW;
			mutex_exit(asy->asy_excl_hi);
			if (async->async_ocnt > 0) {
				mutex_enter(asy->asy_excl_hi);
				async_resume(async);
				mutex_exit(asy->asy_excl_hi);
			} else {
				async_start(async);
			}
			mutex_enter(asy->asy_excl_hi);
		}
	}
	if (async->async_ext) {
		async->async_ext = 0;
		/* check for carrier up */
		if ((val & DCD) || (tp->t_flags & TS_SOFTCAR)) {
			/* carrier present */
			if ((async->async_flags & ASYNC_CARR_ON) == 0) {
				async->async_flags |= ASYNC_CARR_ON;
				mutex_exit(asy->asy_excl_hi);
				mutex_exit(asy->asy_excl);
				if (async->async_flags & ASYNC_ISOPEN)
					(void) putctl(q, M_UNHANGUP);
				cv_broadcast(&async->async_flags_cv);
				mutex_enter(asy->asy_excl);
				mutex_enter(asy->asy_excl_hi);
			}
		} else {
			if ((async->async_flags & ASYNC_CARR_ON) &&
			    !(tp->t_cflag & CLOCAL)) {
				int flushflag;

				/*
				 * Carrier went away.
				 * Drop DTR, abort any output in
				 * progress, indicate that output is
				 * not stopped, and send a hangup
				 * notification upstream.
				 *
				 * If we're in the midst of close, then flush
				 * everything.  Don't leave stale ioctls lying
				 * about.
				 */
				val = INB(MCR);
				OUTB(MCR, (val & ~DTR));
				flushflag = (async->async_flags &
				    ASYNC_CLOSING) ? FLUSHALL : FLUSHDATA;
				if (tp->t_writeq != NULL) {
					flushq(tp->t_writeq, flushflag);
				}
				if (async->async_xmitblk != NULL) {
					freeb(async->async_xmitblk);
					async->async_xmitblk = NULL;
				}
				if (async->async_flags & ASYNC_BUSY) {
					async->async_ocnt = 0;
					async->async_flags &= ~ASYNC_BUSY;
				}
				async->async_flags &= ~ASYNC_STOPPED;
				if (async->async_flags & ASYNC_ISOPEN) {
					mutex_exit(asy->asy_excl_hi);
					mutex_exit(asy->asy_excl);
					(void) putctl(q, M_HANGUP);
					mutex_enter(asy->asy_excl);
					mutex_enter(asy->asy_excl_hi);
				}
				async->async_flags &= ~ASYNC_CARR_ON;
				mutex_exit(asy->asy_excl_hi);
				cv_broadcast(&async->async_flags_cv);
				mutex_enter(asy->asy_excl_hi);
			}
		}
	}

	/*
	 * If data has been added to the circular buffer, remove
	 * it from the buffer, and send it up the stream if there's
	 * somebody listening. Try to do it 16 bytes at a time. If we
	 * have more than 16 bytes to move, move 16 byte chunks and
	 * leave the rest for next time around (maybe it will grow).
	 */
	if (!(async->async_flags & ASYNC_ISOPEN)) {
		RING_INIT(async);
		goto rv;
	}
	if ((cc = RING_CNT(async)) == 0) {
		goto rv;
	}
	mutex_exit(asy->asy_excl_hi);

	if (!canput(q)) {
		if ((async->async_flags & ASYNC_HW_IN_FLOW) == 0) {
#ifdef DEBUG
			if (!(asydebug & ASY_DEBUG_HFLOW)) {
				printf("asy%d: hflow stop input.\n",
				    UNIT(async->async_dev));
				if (canputnext(q))
					printf("asy%d: next queue is "
					    "ready\n",
					    UNIT(async->async_dev));
			}
#endif
			mutex_enter(asy->asy_excl_hi);
			async->async_flags |= ASYNC_HW_IN_FLOW;
			async->async_flowc = async->async_stopc;
		} else mutex_enter(asy->asy_excl_hi);
		goto rv;
	}

	if (async->async_ringbuf_overflow) {
		if ((async->async_flags & ASYNC_HW_IN_FLOW) &&
		    ((int)(RING_CNT(async)) < (RINGSIZE/4))) {
#ifdef DEBUG
			if (asydebug & ASY_DEBUG_HFLOW)
				printf("asy%d: hflow start input.\n",
				    UNIT(async->async_dev));
#endif
			mutex_enter(asy->asy_excl_hi);
			async->async_flags &= ~ASYNC_HW_IN_FLOW;
			async->async_flowc = async->async_startc;
			async->async_ringbuf_overflow = 0;
			goto rv;
		}
	}
#ifdef DEBUG
	if (asydebug & ASY_DEBUG_INPUT)
		printf("asy%d: %d char(s) in queue.\n",
		    UNIT(async->async_dev), cc);
#endif
	/*
	 * Before you pull the characters from the RING BUF
	 * Check whether you can put into the queue again
	 */
	if ((!canputnext(q)) || (!canput(q))) {
		mutex_enter(asy->asy_excl_hi);
		if ((async->async_flags & ASYNC_HW_IN_FLOW) == 0) {
			async->async_flags |= ASYNC_HW_IN_FLOW;
			async->async_flowc = async->async_stopc;
			async->async_queue_full = 1;
		}
		goto rv;
	}
	mutex_enter(asy->asy_excl_hi);
	if (async->async_queue_full) {
		/*
		 * Last time the Stream queue didnot allow
		 * now it allows so, relax, the flow control
		 */
		if (async->async_flags & ASYNC_HW_IN_FLOW) {
			async->async_flags &= ~ASYNC_HW_IN_FLOW;
			async->async_queue_full = 0;
			async->async_flowc = async->async_startc;
			goto rv;
		} else
			async->async_queue_full = 0;
	}
	mutex_exit(asy->asy_excl_hi);
	if (!(bp = allocb(cc, BPRI_MED))) {
		ttycommon_qfull(&async->async_ttycommon, q);
		mutex_enter(asy->asy_excl_hi);
		goto rv;
	}
	mutex_enter(asy->asy_excl_hi);
	do {
		if (RING_ERR(async, S_ERRORS)) {
			RING_UNMARK(async);
			c = RING_GET(async);
			break;
		} else {
			*bp->b_wptr++ = RING_GET(async);
		}
	} while (--cc);

	mutex_exit(asy->asy_excl_hi);
	mutex_exit(asy->asy_excl);
	if (bp->b_wptr > bp->b_rptr) {
		if (!canputnext(q)) {
			if (!canput(q)) {
				/*
				 * Even after taking all precautions that
				 * Still we are unable to queue, then we
				 * cannot do anything, just drop the block
				 */
				cmn_err(CE_NOTE,
				    "su%d: local queue full\n",
				    UNIT(async->async_dev));
				freemsg(bp);
				mutex_enter(asy->asy_excl_hi);
				if ((async->async_flags &
				    ASYNC_HW_IN_FLOW) == 0) {
					async->async_flags |=
					    ASYNC_HW_IN_FLOW;
					async->async_flowc =
					    async->async_stopc;
					async->async_queue_full = 1;
				}
				mutex_exit(asy->asy_excl_hi);
			} else {
				(void) putq(q, bp);
			}
		} else {
			putnext(q, bp);
		}
	} else {
		freemsg(bp);
	}
	/*
	 * If we have a parity error, then send
	 * up an M_BREAK with the "bad"
	 * character as an argument. Let ldterm
	 * figure out what to do with the error.
	 */
	if (cc)
		(void) putctl1(q, M_BREAK, c);
	mutex_enter(asy->asy_excl);
	mutex_enter(asy->asy_excl_hi);
rv:
	/*
	 * If a transmission has finished, indicate that it's finished,
	 * and start that line up again.
	 */
	if (async->async_break) {
		async->async_break = 0;
		if (async->async_flags & ASYNC_ISOPEN) {
			mutex_exit(asy->asy_excl_hi);
			mutex_exit(asy->asy_excl);
			(void) putctl(q, M_BREAK);
			mutex_enter(asy->asy_excl);
			mutex_enter(asy->asy_excl_hi);
		}
	}
	if ((async->async_ocnt <= 0 && (async->async_flags & ASYNC_BUSY)) ||
	    (async->async_flowc != '\0')) {
		async->async_flags &= ~ASYNC_BUSY;
		mutex_exit(asy->asy_excl_hi);
		if (async->async_xmitblk)
			freeb(async->async_xmitblk);
		async->async_xmitblk = NULL;
		if (async->async_flags & ASYNC_ISOPEN) {
			asy->inperim = B_TRUE;
			mutex_exit(asy->asy_excl);
			enterq(async->async_ttycommon.t_writeq);
			mutex_enter(asy->asy_excl);
		}
		async_start(async);
		/*
		 * We need to check for inperim and ISOPEN due to
		 * multi-threading implications; it's possible to close the
		 * port and nullify async_flags while completing the software
		 * interrupt.  If the port is closed, leaveq() will have already
		 * been called.  We don't want to call it twice.
		 */
		if ((asy->inperim) && (async->async_flags & ASYNC_ISOPEN)) {
			mutex_exit(asy->asy_excl);
			leaveq(async->async_ttycommon.t_writeq);
			mutex_enter(asy->asy_excl);
			asy->inperim = B_FALSE;
		}
		if (!(async->async_flags & ASYNC_BUSY))
			cv_broadcast(&async->async_flags_cv);
		mutex_enter(asy->asy_excl_hi);
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
			if (su_log > 0) {
				mutex_exit(asy->asy_excl_hi);
				mutex_exit(asy->asy_excl);
				cmn_err(CE_NOTE, "su%d: silo overflow\n",
				    UNIT(async->async_dev));
				mutex_enter(asy->asy_excl);
				mutex_enter(asy->asy_excl_hi);
			}
			INC64_KSTAT(asy, siloover);
		}
		async->async_hw_overrun = 0;
	}
	if (async->async_sw_overrun) {
		if (async->async_flags & ASYNC_ISOPEN) {
			if (su_log > 0) {
				mutex_exit(asy->asy_excl_hi);
				mutex_exit(asy->asy_excl);
				cmn_err(CE_NOTE, "su%d: ring buffer overflow\n",
				    UNIT(async->async_dev));
				mutex_enter(asy->asy_excl);
				mutex_enter(asy->asy_excl_hi);
			}
			INC64_KSTAT(asy, ringover);
		}
		async->async_sw_overrun = 0;
	}
	asy->asy_flags &= ~ASY_DOINGSOFT;
	mutex_exit(asy->asy_excl_hi);
	mutex_exit(asy->asy_excl);
	if (q != NULL)
		leaveq(q);
	return (0);
}

/*
 * Restart output on a line after a delay or break timer expired.
 */
static void
async_restart(void *arg)
{
	struct asyncline *async = arg;
	struct asycom *asy = async->async_common;
	queue_t *q;
	uchar_t lcr;

	/*
	 * If break timer expired, turn off the break bit.
	 */
#ifdef DEBUG
	if (asydebug & ASY_DEBUG_PROCS)
		printf("restart\n");
#endif
	mutex_enter(asy->asy_excl);
	if (async->async_flags & ASYNC_BREAK) {
		unsigned int rate;

		mutex_enter(asy->asy_excl_hi);
		lcr = INB(LCR);
		OUTB(LCR, (lcr & ~SETBREAK));

		/*
		 * Go to sleep for the time it takes for at least one
		 * stop bit to be received by the device at the other
		 * end of the line as stated in the RS-232 specification.
		 * The wait period is equal to:
		 * 2 clock cycles * (1 MICROSEC / baud rate)
		 */
		rate = async->async_ttycommon.t_cflag & CBAUD;
		if (async->async_ttycommon.t_cflag & CBAUDEXT)
			rate += 16;
		if (rate >= N_SU_SPEEDS || rate == B0) {
			rate = B9600;
		}

		mutex_exit(asy->asy_excl_hi);
		mutex_exit(asy->asy_excl);
		drv_usecwait(2 * MICROSEC / baudtable[rate]);
		mutex_enter(asy->asy_excl);
	}
	async->async_flags &= ~(ASYNC_DELAY|ASYNC_BREAK|ASYNC_DRAINING);
	if ((q = async->async_ttycommon.t_writeq) != NULL) {
		mutex_exit(asy->asy_excl);
		enterq(q);
		mutex_enter(asy->asy_excl);
	}
	async_start(async);
	mutex_exit(asy->asy_excl);
	if (q != NULL)
		leaveq(q);

	/* cleared break or delay flag; may have made some output progress */
	cv_broadcast(&async->async_flags_cv);
}

static void
async_start(struct asyncline *async)
{
	async_nstart(async, 0);
}

/*
 * Start output on a line, unless it's busy, frozen, or otherwise.
 */
static void
async_nstart(struct asyncline *async, int mode)
{
	register struct asycom *asy = async->async_common;
	register int cc;
	register queue_t *q;
	mblk_t *bp, *nbp;
	uchar_t *xmit_addr;
	uchar_t	val;
	int	fifo_len = 1;
	int	xmit_progress;

#ifdef DEBUG
	if (asydebug & ASY_DEBUG_PROCS)
		printf("start\n");
#endif
	if (asy->asy_use_fifo == FIFO_ON)
		fifo_len = asy->asy_fifo_buf; /* with FIFO buffers */

	ASSERT(mutex_owned(asy->asy_excl));
	mutex_enter(asy->asy_excl_hi);
	asycheckflowcontrol_hw(asy);

	/*
	 * If the chip is busy (i.e., we're waiting for a break timeout
	 * to expire, or for the current transmission to finish, or for
	 * output to finish draining from chip), don't grab anything new.
	 */
	if (async->async_flags & (ASYNC_BREAK|ASYNC_BUSY|ASYNC_DRAINING)) {
		mutex_exit(asy->asy_excl_hi);
#ifdef DEBUG
		if (mode && asydebug & ASY_DEBUG_CLOSE)
			printf("asy%d: start %s.\n",
			    UNIT(async->async_dev),
			    async->async_flags & ASYNC_BREAK
			    ? "break" : "busy");
#endif
		return;
	}

	/*
	 * If we have a flow-control character to transmit, do it now.
	 */
	if (asycheckflowcontrol_sw(asy)) {
		mutex_exit(asy->asy_excl_hi);
		return;
	}
	mutex_exit(asy->asy_excl_hi);
	/*
	 * If we're waiting for a delay timeout to expire, don't grab
	 * anything new.
	 */
	if (async->async_flags & ASYNC_DELAY) {
#ifdef DEBUG
		if (mode && asydebug & ASY_DEBUG_CLOSE)
			printf("asy%d: start ASYNC_DELAY.\n",
			    UNIT(async->async_dev));
#endif
		return;
	}

	if ((q = async->async_ttycommon.t_writeq) == NULL) {
#ifdef DEBUG
		if (mode && asydebug & ASY_DEBUG_CLOSE)
			printf("asy%d: start writeq is null.\n",
			    UNIT(async->async_dev));
#endif
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
			mutex_enter(asy->asy_excl_hi);
			val = INB(LCR);
			OUTB(LCR, (val | SETBREAK));
			mutex_exit(asy->asy_excl_hi);
			async->async_flags |= ASYNC_BREAK;
			(void) timeout(async_restart, async, hz / 4);
			freemsg(bp);
			return;	/* wait for this to finish */

		case M_DELAY:
			/*
			 * Arrange for "async_restart" to be called when the
			 * delay expires; it will turn ASYNC_DELAY off,
			 * and call "async_start" to grab the next message.
			 */
			(void) timeout(async_restart, async,
			    (clock_t)(*(unsigned char *)bp->b_rptr + 6));
			async->async_flags |= ASYNC_DELAY;
			freemsg(bp);
			return;	/* wait for this to finish */

		case M_IOCTL:
			/*
			 * This ioctl needs to wait for the output ahead of
			 * it to drain.  Try to do it, and then either
			 * redo the ioctl at a later time or grab the next
			 * message after it.
			 */

			mutex_enter(asy->asy_excl_hi);
			if (asy_isbusy(asy)) {
				/*
				 * Get the divisor by calculating the rate
				 */
				unsigned int rate;

				mutex_exit(asy->asy_excl_hi);
				rate = async->async_ttycommon.t_cflag & CBAUD;
				if (async->async_ttycommon.t_cflag & CBAUDEXT)
					rate += 16;
				if (rate >= N_SU_SPEEDS || rate == B0) {
					rate = B9600;
				}

				/*
				 * We need to do a callback as the port will
				 * be set to drain
				 */
				async->async_flags |= ASYNC_DRAINING;

				/*
				 * Put the message we just processed back onto
				 * the end of the queue
				 */
				if (putq(q, bp) == 0)
					freemsg(bp);

				/*
				 * We need to delay until the TSR and THR
				 * have been exhausted.  We base the delay on
				 * the amount of time it takes to transmit
				 * 2 chars at the current baud rate in
				 * microseconds.
				 *
				 * Therefore, the wait period is:
				 *
				 * (#TSR bits + #THR bits) *
				 * 	1 MICROSEC / baud rate
				 */
				(void) timeout(async_restart, async,
				    drv_usectohz(16 * MICROSEC /
				    baudtable[rate]));
				return;
			}
			mutex_exit(asy->asy_excl_hi);
			mutex_exit(asy->asy_excl);
			async_ioctl(async, q, bp, B_FALSE);
			mutex_enter(asy->asy_excl);
			continue;
		}

		while (bp != NULL && (cc = bp->b_wptr - bp->b_rptr) == 0) {
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
	if (async->async_flags & (ASYNC_HW_OUT_FLW|ASYNC_STOPPED)) {
#ifdef DEBUG
		if (asydebug & ASY_DEBUG_HFLOW &&
		    async->async_flags & ASYNC_HW_OUT_FLW)
			printf("asy%d: output hflow in effect.\n",
			    UNIT(async->async_dev));
#endif
		mutex_exit(asy->asy_excl);
		(void) putbq(q, bp);
		/*
		 * We entered the routine owning the lock, we need to
		 * exit the routine owning the lock.
		 */
		mutex_enter(asy->asy_excl);
		return;
	}

	async->async_xmitblk = bp;
	xmit_addr = bp->b_rptr;
	bp = bp->b_cont;
	if (bp != NULL) {
		mutex_exit(asy->asy_excl);
		(void) putbq(q, bp);	/* not done with this message yet */
		mutex_enter(asy->asy_excl);
	}

	/*
	 * In 5-bit mode, the high order bits are used
	 * to indicate character sizes less than five,
	 * so we need to explicitly mask before transmitting
	 */
	if ((async->async_ttycommon.t_cflag & CSIZE) == CS5) {
		register unsigned char *p = xmit_addr;
		register int cnt = cc;

		while (cnt--)
			*p++ &= (unsigned char) 0x1f;
	}

	/*
	 * Set up this block for pseudo-DMA.
	 */
	mutex_enter(asy->asy_excl_hi);
	async->async_optr = xmit_addr;
	async->async_ocnt = cc;
	/*
	 * If the transmitter is ready, shove some
	 * characters out.
	 */
	xmit_progress = 0;
	while (fifo_len-- && async->async_ocnt) {
		if (INB(LSR) & XHRE) {
			OUTB(DAT, *async->async_optr++);
			async->async_ocnt--;
			xmit_progress++;
		}
	}
	asy->asy_out_of_band_xmit = xmit_progress;
	if (xmit_progress > 0)
		async->async_flags |= ASYNC_PROGRESS;
	async->async_flags |= ASYNC_BUSY;
	mutex_exit(asy->asy_excl_hi);
}

/*
 * Resume output by poking the transmitter.
 */
static void
async_resume(struct asyncline *async)
{
	register struct asycom *asy = async->async_common;

	ASSERT(mutex_owned(asy->asy_excl_hi));
#ifdef DEBUG
	if (asydebug & ASY_DEBUG_PROCS)
		printf("resume\n");
#endif

	asycheckflowcontrol_hw(asy);

	if (INB(LSR) & XHRE) {
		if (asycheckflowcontrol_sw(asy)) {
			return;
		} else if (async->async_ocnt > 0) {
			OUTB(DAT, *async->async_optr++);
			async->async_ocnt--;
			async->async_flags |= ASYNC_PROGRESS;
		}
	}
}

/*
 * Process an "ioctl" message sent down to us.
 * Note that we don't need to get any locks until we are ready to access
 * the hardware.  Nothing we access until then is going to be altered
 * outside of the STREAMS framework, so we should be safe.
 */
static void
async_ioctl(struct asyncline *async, queue_t *wq, mblk_t *mp, boolean_t iswput)
{
	register struct asycom *asy = async->async_common;
	register tty_common_t  *tp = &async->async_ttycommon;
	register struct iocblk *iocp;
	register unsigned datasize;
	size_t ioc_count;
	mblk_t *datamp;
	int error = 0;
	uchar_t val, icr;
#ifdef DEBUG
	if (asydebug & ASY_DEBUG_PROCS)
		printf("ioctl\n");
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
	 * Save off the ioc count in case we need to restore it
	 * because we are queuing a message block.
	 */
	ioc_count = iocp->ioc_count;

	/*
	 * For TIOCMGET, TIOCMBIC, TIOCMBIS, TIOCMSET, and PPS, do NOT call
	 * ttycommon_ioctl() because this function frees up the message block
	 * (mp->b_cont) that contains the address of the user variable where
	 * we need to pass back the bit array.
	 *
	 * Similarly, ttycommon_ioctl() does not know about CONSOPENPOLLEDIO
	 * and CONSCLOSEPOLLEDIO, so don't let ttycommon_ioctl() touch them.
	 */
	if (iocp->ioc_cmd == TIOCMGET ||
	    iocp->ioc_cmd == TIOCMBIC ||
	    iocp->ioc_cmd == TIOCMBIS ||
	    iocp->ioc_cmd == TIOCMSET ||
	    iocp->ioc_cmd == TIOCGPPS ||
	    iocp->ioc_cmd == TIOCSPPS ||
	    iocp->ioc_cmd == TIOCGPPSEV ||
	    iocp->ioc_cmd == CONSOPENPOLLEDIO ||
	    iocp->ioc_cmd == CONSCLOSEPOLLEDIO)
		error = -1; /* Do Nothing */
	else

	/*
	 * The only way in which "ttycommon_ioctl" can fail is if the "ioctl"
	 * requires a response containing data to be returned to the user,
	 * and no mblk could be allocated for the data.
	 * No such "ioctl" alters our state.  Thus, we always go ahead and
	 * do any state-changes the "ioctl" calls for.  If we couldn't allocate
	 * the data, "ttycommon_ioctl" has stashed the "ioctl" away safely, so
	 * we just call "bufcall" to request that we be called back when we
	 * stand a better chance of allocating the data.
	 */
	if ((datasize = ttycommon_ioctl(tp, wq, mp, &error)) != 0) {
		if (async->async_wbufcid)
			unbufcall(async->async_wbufcid);
		async->async_wbufcid = bufcall(datasize, BPRI_HI, async_reioctl,
		    async);
		return;
	}

	mutex_enter(asy->asy_excl);

	if (error == 0) {
		/*
		 * "ttycommon_ioctl" did most of the work; we just use the
		 * data it set up.
		 */
		switch (iocp->ioc_cmd) {

		case TCSETS:
			if (!(asy->asy_rsc_console || asy->asy_rsc_control ||
			    asy->asy_lom_console)) {
				mutex_enter(asy->asy_excl_hi);
				error = asy_program(asy, ASY_NOINIT);
				mutex_exit(asy->asy_excl_hi);
			}
			break;
		case TCSETSF:
		case TCSETSW:
		case TCSETA:
		case TCSETAW:
		case TCSETAF:
			if (!(asy->asy_rsc_console || asy->asy_rsc_control ||
			    asy->asy_lom_console)) {
				mutex_enter(asy->asy_excl_hi);
				if (iswput && asy_isbusy(asy)) {
					/*
					 * ttycommon_ioctl sets the db_type to
					 * M_IOCACK and ioc_count to zero
					 * we need to undo this when we
					 * queue a control message. This will
					 * allow the control messages to be
					 * processed again when the chip
					 * becomes available.
					 */
					mp->b_datap->db_type = M_IOCTL;
					iocp->ioc_count = ioc_count;

					if (putq(wq, mp) == 0)
						freemsg(mp);
					mutex_exit(asy->asy_excl_hi);
					mutex_exit(asy->asy_excl);
					return;
				}

				/*
				 * TCSETA, TCSETAW, and TCSETAF make use of
				 * the termio structure and therefore have
				 * no concept of any speed except what can
				 * be represented by CBAUD. This is because
				 * of legacy SVR4 code. Therefore, if we see
				 * one of the aforementioned IOCTL commands
				 * we should zero out CBAUDEXT, CIBAUD, and
				 * CIBAUDEXT as to not break legacy
				 * functionality. This is because CBAUDEXT,
				 * CIBAUD, and CIBAUDEXT can't be stored in
				 * an unsigned short. By zeroing out CBAUDEXT,
				 * CIBAUD, and CIBAUDEXT in the t_cflag of the
				 * termios structure asy_program() will set the
				 * input baud rate to the output baud rate.
				 */
				if (iocp->ioc_cmd == TCSETA ||
				    iocp->ioc_cmd == TCSETAW ||
				    iocp->ioc_cmd == TCSETAF)
					tp->t_cflag &= ~(CIBAUD |
					    CIBAUDEXT | CBAUDEXT);

				error = asy_program(asy, ASY_NOINIT);
				mutex_exit(asy->asy_excl_hi);
			}
			break;
		case TIOCSSOFTCAR:
			/* Set the driver state appropriately */
			mutex_enter(asy->asy_excl_hi);
			if (tp->t_flags & TS_SOFTCAR)
				asy->asy_flags |= ASY_IGNORE_CD;
			else
				asy->asy_flags &= ~ASY_IGNORE_CD;
			mutex_exit(asy->asy_excl_hi);
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

			mutex_enter(asy->asy_excl_hi);
			if (*(int *)mp->b_cont->b_rptr)
				asy->asy_flags |= ASY_PPS;
			else
				asy->asy_flags &= ~ASY_PPS;
			/* Reset edge sense */
			asy->asy_flags &= ~ASY_PPS_EDGE;
			mutex_exit(asy->asy_excl_hi);
			mp->b_datap->db_type = M_IOCACK;
			break;

		case TIOCGPPSEV: {
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
			mutex_enter(asy->asy_excl_hi);
			ppsclockev = asy_ppsev;
			mutex_exit(asy->asy_excl_hi);

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

			mutex_enter(asy->asy_excl_hi);
			if (*(int *)mp->b_cont->b_rptr == 0) {
				/*
				 * Get the divisor by calculating the rate
				 */
				unsigned int rate, divisor;
				rate = async->async_ttycommon.t_cflag & CBAUD;
				if (async->async_ttycommon.t_cflag & CBAUDEXT)
					rate += 16;
				if (rate >= N_SU_SPEEDS) rate = B9600;
				divisor = asyspdtab[rate] & 0xfff;

				/*
				 * To ensure that erroneous characters are
				 * not sent out when the break is set, SB
				 * recommends three steps:
				 *
				 * 1) pad the TSR with 0 bits
				 * 2) When the TSR is full, set break
				 * 3) When the TSR has been flushed, unset
				 *    the break when transmission must be
				 *    restored.
				 *
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
				async->async_flags |= ASYNC_BREAK;
				while ((INB(LSR) & XSRE) == 0) {
					mutex_exit(asy->asy_excl_hi);
					mutex_exit(asy->asy_excl);
					drv_usecwait(32*divisor);
					mutex_enter(asy->asy_excl);
					mutex_enter(asy->asy_excl_hi);
				}

				/*
				 * Set the break bit, and arrange for
				 * "async_restart" to be called in 1/4 second;
				 * it will turn the break bit off, and call
				 * "async_start" to grab the next message.
				 */
				val = INB(LCR);
				OUTB(LCR, (val | SETBREAK));
				mutex_exit(asy->asy_excl_hi);
				(void) timeout(async_restart, async, hz / 4);
			} else {
#ifdef DEBUG
				if (asydebug & ASY_DEBUG_CLOSE)
					printf("asy%d: wait for flush.\n",
					    UNIT(async->async_dev));
#endif
				if (iswput && asy_isbusy(asy)) {
					if (putq(wq, mp) == 0)
						freemsg(mp);
					mutex_exit(asy->asy_excl_hi);
					mutex_exit(asy->asy_excl);
					return;
				}
				mutex_exit(asy->asy_excl_hi);
#ifdef DEBUG
				if (asydebug & ASY_DEBUG_CLOSE)
					printf("asy%d: ldterm satisfied.\n",
					    UNIT(async->async_dev));
#endif
			}
			break;

		case TIOCSBRK:
			mutex_enter(asy->asy_excl_hi);
			val = INB(LCR);
			OUTB(LCR, (val | SETBREAK));
			mutex_exit(asy->asy_excl_hi);
			mutex_exit(asy->asy_excl);
			miocack(wq, mp, 0, 0);
			return;

		case TIOCCBRK:
			mutex_enter(asy->asy_excl_hi);
			val = INB(LCR);
			OUTB(LCR, (val & ~SETBREAK));
			mutex_exit(asy->asy_excl_hi);
			mutex_exit(asy->asy_excl);
			miocack(wq, mp, 0, 0);
			return;

		case TIOCMSET:
		case TIOCMBIS:
		case TIOCMBIC:
			if (iocp->ioc_count == TRANSPARENT)
				mcopyin(mp, NULL, sizeof (int), NULL);
			else {
				error = miocpullup(mp, sizeof (int));
				if (error != 0)
					break;

				mutex_enter(asy->asy_excl_hi);

				(void) asymctl(asy,
				    dmtoasy(*(int *)mp->b_cont->b_rptr),
				    iocp->ioc_cmd);

				mutex_exit(asy->asy_excl_hi);
				iocp->ioc_error = 0;
				mp->b_datap->db_type = M_IOCACK;
			}
			break;

		case TIOCSILOOP:
			mutex_enter(asy->asy_excl_hi);
			/*
			 * If somebody misues this Ioctl when used for
			 * driving keyboard and mouse indicate not supported
			 */
			if ((asy->asy_device_type == ASY_KEYBOARD) ||
			    (asy->asy_device_type == ASY_MOUSE)) {
				mutex_exit(asy->asy_excl_hi);
				error = ENOTTY;
				break;
			}

			/* should not use when we're the console */
			if ((async->async_dev == kbddev) ||
			    (async->async_dev == rconsdev) ||
			    (async->async_dev == stdindev)) {
				mutex_exit(asy->asy_excl_hi);
				error = EINVAL;
				break;
			}

			val = INB(MCR);
			icr = INB(ICR);
			/*
			 * Disable the Modem Status Interrupt
			 * The reason for disabling is  the status of
			 * modem signal are in the higher 4 bits instead of
			 * lower four bits when in loopback mode,
			 * so, donot worry about Modem interrupt when
			 * you are planning to set
			 * this in loopback mode until it is cleared by
			 * another ioctl to get out of the loopback mode
			 */
			OUTB(ICR, icr & ~ MIEN);
			OUTB(MCR, val | ASY_LOOP);
			mutex_exit(asy->asy_excl_hi);
			iocp->ioc_error = 0;
			mp->b_datap->db_type = M_IOCACK;
			break;

		case TIOCMGET:
			datamp = allocb(sizeof (int), BPRI_MED);
			if (datamp == NULL) {
				error = EAGAIN;
				break;
			}

			mutex_enter(asy->asy_excl_hi);
			*(int *)datamp->b_rptr = asymctl(asy, 0, TIOCMGET);
			mutex_exit(asy->asy_excl_hi);

			if (iocp->ioc_count == TRANSPARENT) {
				mcopyout(mp, NULL, sizeof (int), NULL, datamp);
			} else {
				if (mp->b_cont != NULL)
					freemsg(mp->b_cont);
				mp->b_cont = datamp;
				mp->b_cont->b_wptr += sizeof (int);
				mp->b_datap->db_type = M_IOCACK;
				iocp->ioc_count = sizeof (int);
			}
			break;

		case CONSOPENPOLLEDIO:
			/*
			 * If we are driving a keyboard there is nothing
			 * upstream to translate the scan codes. Therefore,
			 * set the error code to ENOTSUP and NAK the request
			 */
			if (asy->asy_device_type == ASY_KEYBOARD) {
				error = ENOTSUP;
				break;
			}

			error = miocpullup(mp, sizeof (struct cons_polledio *));
			if (error != 0)
				break;

			/*
			 * send up a message block containing the
			 * cons_polledio structure. This provides
			 * handles to the putchar, getchar, ischar,
			 * polledio_enter and polledio_exit functions.
			 */
			*(struct cons_polledio **)mp->b_cont->b_rptr =
			    &asy->polledio;

			mp->b_datap->db_type = M_IOCACK;
			break;

		case CONSCLOSEPOLLEDIO:
			/*
			 * If we are driving a keyboard we never successfully
			 * called CONSOPENPOLLEDIO so set the error to
			 * ENOTSUP and NAK the request.
			 */
			if (asy->asy_device_type == ASY_KEYBOARD) {
				error = ENOTSUP;
				break;
			}

			mp->b_datap->db_type = M_IOCACK;
			iocp->ioc_error = 0;
			iocp->ioc_rval = 0;
			break;

		default: /* unexpected ioctl type */
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
	mutex_exit(asy->asy_excl);
	qreply(wq, mp);
}

static void
asyrsrv(queue_t *q)
{
	mblk_t *bp;
	struct asyncline *async;

	async = (struct asyncline *)q->q_ptr;

	while (canputnext(q) && (bp = getq(q)))
		putnext(q, bp);
	ASYSETSOFT(async->async_common);
	async->async_polltid = 0;
}

/*
 * Put procedure for write queue.
 * Respond to M_STOP, M_START, M_IOCTL, and M_FLUSH messages here;
 * set the flow control character for M_STOPI and M_STARTI messages;
 * queue up M_BREAK, M_DELAY, and M_DATA messages for processing
 * by the start routine, and then call the start routine; discard
 * everything else.  Note that this driver does not incorporate any
 * mechanism to negotiate to handle the canonicalization process.
 * It expects that these functions are handled in upper module(s),
 * as we do in ldterm.
 */
static void
asywput(queue_t *q, mblk_t *mp)
{
	register struct asyncline *async;
	register struct asycom *asy;
	int error;

	async = (struct asyncline *)q->q_ptr;
	asy = async->async_common;

	switch (mp->b_datap->db_type) {

	case M_STOP:
		/*
		 * Since we don't do real DMA, we can just let the
		 * chip coast to a stop after applying the brakes.
		 */
		mutex_enter(asy->asy_excl);
		async->async_flags |= ASYNC_STOPPED;
		mutex_exit(asy->asy_excl);
		freemsg(mp);
		break;

	case M_START:
		mutex_enter(asy->asy_excl);
		if (async->async_flags & ASYNC_STOPPED) {
			async->async_flags &= ~ASYNC_STOPPED;
			/*
			 * If an output operation is in progress,
			 * resume it.  Otherwise, prod the start
			 * routine.
			 */
			if (async->async_ocnt > 0) {
				mutex_enter(asy->asy_excl_hi);
				async_resume(async);
				mutex_exit(asy->asy_excl_hi);
			} else {
				async_start(async);
			}
		}
		mutex_exit(asy->asy_excl);
		freemsg(mp);
		break;

	case M_IOCTL:
		switch (((struct iocblk *)mp->b_rptr)->ioc_cmd) {

		case TCSBRK:
			error = miocpullup(mp, sizeof (int));
			if (error != 0) {
				miocnak(q, mp, 0, error);
				return;
			}

			if (*(int *)mp->b_cont->b_rptr != 0) {
#ifdef DEBUG
				if (asydebug & ASY_DEBUG_CLOSE)
					printf("asy%d: flush request.\n",
					    UNIT(async->async_dev));
#endif
				(void) putq(q, mp);
				mutex_enter(asy->asy_excl);
				async_nstart(async, 1);
				mutex_exit(asy->asy_excl);
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
			mutex_enter(asy->asy_excl);
			async_start(async);
			mutex_exit(asy->asy_excl);
			break;

		default:
			/*
			 * Do it now.
			 */
			async_ioctl(async, q, mp, B_TRUE);
			break;
		}
		break;

	case M_FLUSH:
		if (*mp->b_rptr & FLUSHW) {
			mutex_enter(asy->asy_excl);

			/*
			 * Abort any output in progress.
			 */
			mutex_enter(asy->asy_excl_hi);
			if (async->async_flags & ASYNC_BUSY) {
				async->async_ocnt = 0;
				async->async_flags &= ~ASYNC_BUSY;
			}
			mutex_exit(asy->asy_excl_hi);

			/* Flush FIFO buffers */
			if (asy->asy_use_fifo == FIFO_ON) {
				OUTB(FIFOR, FIFO_ON | FIFODMA | FIFOTXFLSH |
				    (asy->asy_trig_level & 0xff));
			}

			/*
			 * Flush our write queue.
			 */
			flushq(q, FLUSHDATA);	/* XXX doesn't flush M_DELAY */
			if (async->async_xmitblk != NULL) {
				freeb(async->async_xmitblk);
				async->async_xmitblk = NULL;
			}

			mutex_exit(asy->asy_excl);
			*mp->b_rptr &= ~FLUSHW;	/* it has been flushed */
		}
		if (*mp->b_rptr & FLUSHR) {
			/* Flush FIFO buffers */
			if (asy->asy_use_fifo == FIFO_ON) {
				OUTB(FIFOR, FIFO_ON | FIFODMA | FIFORXFLSH |
				    (asy->asy_trig_level & 0xff));
			}
			flushq(RD(q), FLUSHDATA);
			qreply(q, mp);	/* give the read queues a crack at it */
		} else {
			freemsg(mp);
		}

		/*
		 * We must make sure we process messages that survive the
		 * write-side flush.  Without this call, the close protocol
		 * with ldterm can hang forever.  (ldterm will have sent us a
		 * TCSBRK ioctl that it expects a response to.)
		 */
		mutex_enter(asy->asy_excl);
		async_start(async);
		mutex_exit(asy->asy_excl);
		break;
	case M_BREAK:
	case M_DELAY:
	case M_DATA:
		/*
		 * Queue the message up to be transmitted,
		 * and poke the start routine.
		 */
		(void) putq(q, mp);
		mutex_enter(asy->asy_excl);
		async_start(async);
		mutex_exit(asy->asy_excl);
		break;

	case M_STOPI:
		mutex_enter(asy->asy_excl);
		async->async_flowc = async->async_stopc;
		async_start(async);		/* poke the start routine */
		mutex_exit(asy->asy_excl);
		freemsg(mp);
		break;

	case M_STARTI:
		mutex_enter(asy->asy_excl);
		async->async_flowc = async->async_startc;
		async_start(async);		/* poke the start routine */
		mutex_exit(asy->asy_excl);
		freemsg(mp);
		break;

	case M_CTL:
		if (MBLKL(mp) >= sizeof (struct iocblk) &&
		    ((struct iocblk *)mp->b_rptr)->ioc_cmd == MC_POSIXQUERY) {
			((struct iocblk *)mp->b_rptr)->ioc_cmd = MC_HAS_POSIX;
			qreply(q, mp);
		} else {
			/*
			 * These MC_SERVICE type messages are used by upper
			 * modules to tell this driver to send input up
			 * immediately, or that it can wait for normal
			 * processing that may or may not be done.  Sun
			 * requires these for the mouse module.
			 * (XXX - for x86?)
			 */
			mutex_enter(asy->asy_excl);
			switch (*mp->b_rptr) {

			case MC_SERVICEIMM:
				async->async_flags |= ASYNC_SERVICEIMM;
				break;

			case MC_SERVICEDEF:
				async->async_flags &= ~ASYNC_SERVICEIMM;
				break;
			}
			mutex_exit(asy->asy_excl);
			freemsg(mp);
		}
		break;

	case M_IOCDATA:
		async_iocdata(q, mp);
		break;

	default:
		freemsg(mp);
		break;
	}
}

/*
 * Retry an "ioctl", now that "bufcall" claims we may be able to allocate
 * the buffer we need.
 */
static void
async_reioctl(void *arg)
{
	struct asyncline *async = arg;
	struct asycom *asy = async->async_common;
	queue_t	*q;
	mblk_t		*mp;

	/*
	 * The bufcall is no longer pending.
	 */
	mutex_enter(asy->asy_excl);
	async->async_wbufcid = 0;
	if ((q = async->async_ttycommon.t_writeq) == NULL) {
		mutex_exit(asy->asy_excl);
		return;
	}
	if ((mp = async->async_ttycommon.t_iocpending) != NULL) {
		/* not pending any more */
		async->async_ttycommon.t_iocpending = NULL;
		mutex_exit(asy->asy_excl);
		/* not in STREAMS queue; we no longer know if we're in wput */
		async_ioctl(async, q, mp, B_TRUE);
	} else
		mutex_exit(asy->asy_excl);
}

static void
async_iocdata(queue_t *q, mblk_t *mp)
{
	struct asyncline	*async = (struct asyncline *)q->q_ptr;
	struct asycom		*asy;
	struct copyresp *csp;

	asy = async->async_common;
	csp = (struct copyresp *)mp->b_rptr;

	if (csp->cp_rval != 0) {
		freemsg(mp);
		return;
	}

	mutex_enter(asy->asy_excl);

	switch (csp->cp_cmd) {
	case TIOCMSET:
	case TIOCMBIS:
	case TIOCMBIC:
		if (mp->b_cont == NULL) {
			mutex_exit(asy->asy_excl);
			miocnak(q, mp, 0, EINVAL);
			break;
		}

		mutex_enter(asy->asy_excl_hi);
		(void) asymctl(asy, dmtoasy(*(int *)mp->b_cont->b_rptr),
		    csp->cp_cmd);
		mutex_exit(asy->asy_excl_hi);

		freemsg(mp->b_cont);
		mp->b_cont = NULL;
		mutex_exit(asy->asy_excl);
		miocack(q, mp, 0, 0);
		break;

	case TIOCMGET:
		if (mp->b_cont != NULL) {
			freemsg(mp->b_cont);
			mp->b_cont = NULL;
		}
		mutex_exit(asy->asy_excl);
		miocack(q, mp, 0, 0);
		break;

	default:
		mutex_exit(asy->asy_excl);
		miocnak(q, mp, 0, EINVAL);
		break;
	}
}


/*
 * Set or get the modem control status.
 */
static int
asymctl(struct asycom *asy, int bits, int how)
{
	register int mcr_r, msr_r;

	ASSERT(mutex_owned(asy->asy_excl_hi));
	ASSERT(mutex_owned(asy->asy_excl));

	/* Read Modem Control Registers */
	mcr_r = INB(MCR);

	switch (how) {

	case TIOCMSET:
		mcr_r = bits;
		break;

	case TIOCMBIS:
		mcr_r |= bits;			/* Set bits from input	*/
		break;

	case TIOCMBIC:
		mcr_r &= ~bits;			/* Set ~bits from input	*/
		break;

	case TIOCMGET:
		/* Read Modem Status Registers */
		if (INB(ICR) & MIEN)
			msr_r = asy->asy_cached_msr;
		else
			msr_r = INB(MSR);
		return (asytodm(mcr_r, msr_r));
	}

	OUTB(MCR, mcr_r);

	return (mcr_r);
}

static int
asytodm(int mcr_r, int msr_r)
{
	register int b = 0;


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
	register int b = 0;

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

	if (bits & TIOCM_RTS)
		b |= RTS;
	if (bits & TIOCM_DTR)
		b |= DTR;

	return (b);
}

static void
asycheckflowcontrol_hw(struct asycom *asy)
{
	struct asyncline *async;
	uchar_t	mcr, flag;

	ASSERT(mutex_owned(asy->asy_excl_hi));

	async = (struct asyncline *)asy->asy_priv;
	ASSERT(async != NULL);

	if (async->async_ttycommon.t_cflag & CRTSXOFF) {
		mcr = INB(MCR);
		flag = (async->async_flags & ASYNC_HW_IN_FLOW) ? 0 : RTS;
		if (((mcr ^ flag) & RTS) != 0) {
			OUTB(MCR, (mcr ^ RTS));
		}
	}
}

static boolean_t
asycheckflowcontrol_sw(struct asycom *asy)
{
	uchar_t		ss;
	struct asyncline *async;
	int rval = B_FALSE;

	ASSERT(mutex_owned(asy->asy_excl_hi));

	async = (struct asyncline *)asy->asy_priv;
	ASSERT(async != NULL);

	if ((ss = async->async_flowc) != '\0' && (INB(LSR) & XHRE)) {
		/*
		 * If we get this far, then we know that flowc is non-zero and
		 * that there's transmit room available.  We've "handled" the
		 * request now, so clear it.  If the user didn't ask for IXOFF,
		 * then don't actually send anything, but wait for the next
		 * opportunity.
		 */
		async->async_flowc = '\0';
		if (async->async_ttycommon.t_iflag & IXOFF) {
			async->async_flags |= ASYNC_BUSY;
			OUTB(DAT, ss);
			rval = B_TRUE;
		}
	}

	return (rval);
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
