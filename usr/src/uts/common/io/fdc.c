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
 * Copyright 2012 Garrett D'Amore <garrett@damore.org>.  All rights reserved.
 */


/*
 * Floppy Disk Controller Driver
 *
 *   for the standard PC architecture using the Intel 8272A fdc.
 *   Note that motor control and drive select use a latch external
 *   to the fdc.
 *
 *   This driver is EISA capable, and uses DMA buffer chaining if available.
 *   If this driver is attached to the ISA bus nexus (or if the EISA bus driver
 *   does not support DMA buffer chaining), then the bus driver must ensure
 *   that dma mapping (breakup) and dma engine requests are properly degraded.
 */

/*
 * hack for bugid 1160621:
 * workaround compiler optimization bug by turning on DEBUG
 */
#ifndef DEBUG
#define	DEBUG	1
#endif

#include <sys/param.h>
#include <sys/buf.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <sys/open.h>
#include <sys/conf.h>
#include <sys/file.h>
#include <sys/cmn_err.h>
#include <sys/note.h>
#include <sys/debug.h>
#include <sys/kmem.h>
#include <sys/stat.h>

#include <sys/autoconf.h>
#include <sys/dkio.h>
#include <sys/vtoc.h>
#include <sys/kstat.h>

#include <sys/fdio.h>
#include <sys/fdc.h>
#include <sys/i8272A.h>
#include <sys/fd_debug.h>
#include <sys/promif.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

/*
 * bss (uninitialized data)
 */
static void *fdc_state_head;		/* opaque handle top of state structs */
static ddi_dma_attr_t fdc_dma_attr;
static ddi_device_acc_attr_t fdc_accattr = {DDI_DEVICE_ATTR_V0,
	DDI_STRUCTURE_LE_ACC, DDI_STRICTORDER_ACC};

/*
 * Local static data
 */
#define	OURUN_TRIES	12
static uchar_t rwretry = 4;
static uchar_t skretry = 3;
static uchar_t configurecmd[4] = {FO_CNFG, 0, 0x0F, 0};
static uchar_t recalcmd[2] = {FO_RECAL, 0};
static uchar_t senseintcmd = FO_SINT;

/*
 * error handling
 *
 * for debugging, set rwretry and skretry = 1
 *		set fcerrlevel to 1
 *		set fcerrmask  to 224  or 644
 *
 * after debug, set rwretry to 4, skretry to 3, and fcerrlevel to 5
 * set fcerrmask to FDEM_ALL
 * or remove the define DEBUG
 */
static uint_t fcerrmask = FDEM_ALL;
static int fcerrlevel = 6;

#define	KIOIP	KSTAT_INTR_PTR(fcp->c_intrstat)


static xlate_tbl_t drate_mfm[] = {
	{  250, 2},
	{  300, 1},
	{  417, 0},
	{  500, 0},
	{ 1000, 3},
	{    0, 0}
};

static xlate_tbl_t sector_size[] = {
	{  256, 1},
	{  512, 2},
	{ 1024, 3},
	{    0, 2}
};

static xlate_tbl_t motor_onbits[] = {
	{  0, 0x10},
	{  1, 0x20},
	{  2, 0x40},
	{  3, 0x80},
	{  0, 0x80}
};

static xlate_tbl_t step_rate[] = {
	{  10, 0xF0},		/* for 500K data rate */
	{  20, 0xE0},
	{  30, 0xD0},
	{  40, 0xC0},
	{  50, 0xB0},
	{  60, 0xA0},
	{  70, 0x90},
	{  80, 0x80},
	{  90, 0x70},
	{ 100, 0x60},
	{ 110, 0x50},
	{ 120, 0x40},
	{ 130, 0x30},
	{ 140, 0x20},
	{ 150, 0x10},
	{ 160, 0x00},
	{   0, 0x00}
};

#ifdef notdef
static xlate_tbl_t head_unld[] = {
	{  16, 0x1},		/* for 500K data rate */
	{  32, 0x2},
	{  48, 0x3},
	{  64, 0x4},
	{  80, 0x5},
	{  96, 0x6},
	{ 112, 0x7},
	{ 128, 0x8},
	{ 144, 0x9},
	{ 160, 0xA},
	{ 176, 0xB},
	{ 192, 0xC},
	{ 208, 0xD},
	{ 224, 0xE},
	{ 240, 0xF},
	{ 256, 0x0},
	{   0, 0x0}
};
#endif

static struct fdcmdinfo {
	char *cmdname;		/* command name */
	uchar_t ncmdbytes;	/* number of bytes of command */
	uchar_t nrsltbytes;	/* number of bytes in result */
	uchar_t cmdtype;		/* characteristics */
} fdcmds[] = {
	"", 0, 0, 0,			/* - */
	"", 0, 0, 0,			/* - */
	"read_track", 9, 7, 1,		/* 2 */
	"specify", 3, 0, 3,		/* 3 */
	"sense_drv_status", 2, 1, 3,	/* 4 */
	"write", 9, 7, 1,		/* 5 */
	"read", 9, 7, 1,		/* 6 */
	"recalibrate", 2, 0, 2,		/* 7 */
	"sense_int_status", 1, 2, 3,	/* 8 */
	"write_del", 9, 7, 1,		/* 9 */
	"read_id", 2, 7, 2,		/* A */
	"", 0, 0, 0,			/* - */
	"read_del", 9, 7, 1,		/* C */
	"format_track", 10, 7, 1,	/* D */
	"dump_reg", 1, 10, 4,		/* E */
	"seek", 3, 0, 2,		/* F */
	"version", 1, 1, 3,		/* 10 */
	"", 0, 0, 0,			/* - */
	"perp_mode", 2, 0, 3,		/* 12 */
	"configure", 4, 0, 4,		/* 13 */
	/* relative seek */
};


static int
fdc_bus_ctl(dev_info_t *, dev_info_t *, ddi_ctl_enum_t, void *, void *);
static int get_ioaddr(dev_info_t *dip, int *ioaddr);
static int get_unit(dev_info_t *dip, int *cntrl_num);

struct bus_ops fdc_bus_ops = {
	BUSO_REV,
	nullbusmap,
	0,	/* ddi_intrspec_t (*bus_get_intrspec)(); */
	0,	/* int 	(*bus_add_intrspec)(); */
	0,	/* void (*bus_remove_intrspec)(); */
	i_ddi_map_fault,
	0,
	ddi_dma_allochdl,
	ddi_dma_freehdl,
	ddi_dma_bindhdl,
	ddi_dma_unbindhdl,
	ddi_dma_flush,
	ddi_dma_win,
	ddi_dma_mctl,
	fdc_bus_ctl,
	ddi_bus_prop_op,
};

static int fdc_getinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int fdc_probe(dev_info_t *);
static int fdc_attach(dev_info_t *, ddi_attach_cmd_t);
static int fdc_detach(dev_info_t *, ddi_detach_cmd_t);
static int fdc_quiesce(dev_info_t *);
static int fdc_enhance_probe(struct fdcntlr *fcp);

struct dev_ops	fdc_ops = {
	DEVO_REV,		/* devo_rev, */
	0,			/* refcnt  */
	fdc_getinfo,		/* getinfo */
	nulldev,		/* identify */
	fdc_probe,		/* probe */
	fdc_attach,		/* attach */
	fdc_detach,		/* detach */
	nodev,			/* reset */
	(struct cb_ops *)0,	/* driver operations */
	&fdc_bus_ops,		/* bus operations */
	NULL,			/* power */
	fdc_quiesce,		/* quiesce */
};

/*
 * This is the loadable module wrapper.
 */
#include <sys/modctl.h>

extern struct mod_ops mod_driverops;

static struct modldrv modldrv = {
	&mod_driverops,		/* Type of module. This one is a driver */
	"Floppy Controller",	/* Name of the module. */
	&fdc_ops,		/* Driver ops vector */
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modldrv, NULL
};

int
_init(void)
{
	int retval;

	if ((retval = ddi_soft_state_init(&fdc_state_head,
	    sizeof (struct fdcntlr) + NFDUN * sizeof (struct fcu_obj), 0)) != 0)
		return (retval);

	if ((retval = mod_install(&modlinkage)) != 0)
		ddi_soft_state_fini(&fdc_state_head);
	return (retval);
}

int
_fini(void)
{
	int retval;

	if ((retval = mod_remove(&modlinkage)) != 0)
		return (retval);
	ddi_soft_state_fini(&fdc_state_head);
	return (retval);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}


int fdc_abort(struct fcu_obj *);
int fdc_dkinfo(struct fcu_obj *, struct dk_cinfo *);
int fdc_select(struct fcu_obj *, int, int);
int fdgetchng(struct fcu_obj *, int);
int fdresetchng(struct fcu_obj *, int);
int fdrecalseek(struct fcu_obj *, int, int, int);
int fdrw(struct fcu_obj *, int, int, int, int, int, caddr_t, uint_t);
int fdtrkformat(struct fcu_obj *, int, int, int, int);
int fdrawioctl(struct fcu_obj *, int, caddr_t);

static struct fcobjops fdc_iops = {
		fdc_abort,	/* controller abort */
		fdc_dkinfo,	/* get disk controller info */

		fdc_select,	/* select / deselect unit */
		fdgetchng,	/* get media change */
		fdresetchng,	/* reset media change */
		fdrecalseek,	/* recal / seek */
		NULL,		/* read /write request (UNUSED) */
		fdrw,		/* read /write sector */
		fdtrkformat,	/* format track */
		fdrawioctl	/* raw ioctl */
};


/*
 * Function prototypes
 */
void encode(xlate_tbl_t *tablep, int val, uchar_t *rcode);
int decode(xlate_tbl_t *, int, int *);
static int fdc_propinit1(struct fdcntlr *, int);
static void fdc_propinit2(struct fdcntlr *);
void fdcquiesce(struct fdcntlr *);
int fdcsense_chng(struct fdcntlr *, int);
int fdcsense_drv(struct fdcntlr *, int);
int fdcsense_int(struct fdcntlr *, int *, int *);
int fdcspecify(struct fdcntlr *, int, int, int);
int fdcspdchange(struct fdcntlr *, struct fcu_obj *, int);
static int fdc_exec(struct fdcntlr *, int, int);
int fdcheckdisk(struct fdcntlr *, int);
static uint_t fdc_intr(caddr_t arg);
static void fdwatch(void *arg);
static void fdmotort(void *arg);
static int fdrecover(struct fdcntlr *);
static int fdc_motorsm(struct fcu_obj *, int, int);
static int fdc_statemach(struct fdcntlr *);
int fdc_docmd(struct fdcntlr *, uchar_t *, uchar_t);
int fdc_result(struct fdcntlr *, uchar_t *, uchar_t);


static int
fdc_bus_ctl(dev_info_t *dip, dev_info_t *rdip, ddi_ctl_enum_t ctlop,
    void *arg, void *result)
{
	struct 	fdcntlr *fcp;
	struct	fcu_obj *fjp;

	_NOTE(ARGUNUSED(result));

	FCERRPRINT(FDEP_L0, FDEM_ATTA,
	    (CE_CONT, "fdc_bus_ctl: cmd= %x\n", ctlop));

	if ((fcp = ddi_get_driver_private(dip)) == NULL)
		return (DDI_FAILURE);

	switch (ctlop) {

	case DDI_CTLOPS_REPORTDEV:
		cmn_err(CE_CONT, "?%s%d at %s%d\n",
		    ddi_get_name(rdip), ddi_get_instance(rdip),
		    ddi_get_name(dip), ddi_get_instance(dip));
		FCERRPRINT(FDEP_L3, FDEM_ATTA,
		    (CE_WARN, "fdc_bus_ctl: report %s%d at %s%d",
		    ddi_get_name(rdip), ddi_get_instance(rdip),
		    ddi_get_name(dip), ddi_get_instance(dip)));
		return (DDI_SUCCESS);

	case DDI_CTLOPS_INITCHILD:
	{
		dev_info_t *udip = (dev_info_t *)arg;
		int cntlr;
		int len;
		int unit;
		char name[MAXNAMELEN];

		FCERRPRINT(FDEP_L3, FDEM_ATTA,
		    (CE_WARN, "fdc_bus_ctl: init child 0x%p", (void*)udip));
		cntlr = fcp->c_number;

		len = sizeof (unit);
		if (ddi_prop_op(DDI_DEV_T_ANY, udip, PROP_LEN_AND_VAL_BUF,
		    DDI_PROP_DONTPASS, "unit", (caddr_t)&unit, &len)
		    != DDI_PROP_SUCCESS ||
		    cntlr != FDCTLR(unit) ||
		    (fcp->c_unit[FDUNIT(unit)])->fj_dip)
			return (DDI_NOT_WELL_FORMED);

		(void) sprintf(name, "%d,%d", cntlr, FDUNIT(unit));
		ddi_set_name_addr(udip, name);

		fjp = fcp->c_unit[FDUNIT(unit)];
		fjp->fj_unit = unit;
		fjp->fj_dip = udip;
		fjp->fj_ops = &fdc_iops;
		fjp->fj_fdc = fcp;
		fjp->fj_iblock = &fcp->c_iblock;

		ddi_set_driver_private(udip, fjp);

		return (DDI_SUCCESS);
	}
	case DDI_CTLOPS_UNINITCHILD:
	{
		dev_info_t *udip = (dev_info_t *)arg;

		FCERRPRINT(FDEP_L3, FDEM_ATTA,
		    (CE_WARN, "fdc_bus_ctl: uninit child 0x%p", (void *)udip));
		fjp = ddi_get_driver_private(udip);
		ddi_set_driver_private(udip, NULL);
		fjp->fj_dip = NULL;
		ddi_set_name_addr(udip, NULL);
		return (DDI_SUCCESS);
	}
	default:
		return (DDI_FAILURE);
	}
}

static int
fdc_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **result)
{
	struct fdcntlr *fcp;
	int rval;

	_NOTE(ARGUNUSED(dip));

	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		if (fcp = ddi_get_soft_state(fdc_state_head, (dev_t)arg)) {
			*result = fcp->c_dip;
			rval = DDI_SUCCESS;
			break;
		} else {
			rval = DDI_FAILURE;
			break;
		}
	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)(uintptr_t)getminor((dev_t)arg);
		rval = DDI_SUCCESS;
		break;
	default:
		rval = DDI_FAILURE;
	}
	return (rval);
}

static int
fdc_probe(dev_info_t *dip)
{
	int	debug[2];
	int ioaddr;
	int	len;
	uchar_t	stat;

	len = sizeof (debug);
	if (ddi_prop_op(DDI_DEV_T_ANY, dip, PROP_LEN_AND_VAL_BUF,
	    DDI_PROP_DONTPASS, "debug", (caddr_t)debug, &len) ==
	    DDI_PROP_SUCCESS) {
		fcerrlevel = debug[0];
		fcerrmask = (uint_t)debug[1];
	}

	FCERRPRINT(FDEP_L3, FDEM_ATTA, (CE_WARN, "fdc_probe: dip %p",
	    (void*)dip));

	if (get_ioaddr(dip, &ioaddr) != DDI_SUCCESS)
		return (DDI_PROBE_FAILURE);

	stat = inb(ioaddr + FCR_MSR);
	if ((stat & (MS_RQM | MS_DIO | MS_CB)) != MS_RQM &&
	    (stat & ~MS_DIO) != MS_CB)
		return (DDI_PROBE_FAILURE);

	return (DDI_PROBE_SUCCESS);
}

static int
fdc_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	struct fdcntlr *fcp;
	struct fcu_obj *fjp;
	int cntlr_num, ctlr, unit;
	int intr_set = 0;
	int len;
	char name[MAXNAMELEN];

	FCERRPRINT(FDEP_L3, FDEM_ATTA, (CE_WARN, "fdc_attach: dip %p",
	    (void*)dip));

	switch (cmd) {
	case DDI_ATTACH:
		if (ddi_getprop
		    (DDI_DEV_T_ANY, dip, 0, "ignore-hardware-nodes", 0)) {
			len = sizeof (cntlr_num);
			if (ddi_prop_op(DDI_DEV_T_ANY, dip,
			    PROP_LEN_AND_VAL_BUF, DDI_PROP_DONTPASS, "unit",
			    (caddr_t)&cntlr_num, &len) != DDI_PROP_SUCCESS) {
				FCERRPRINT(FDEP_L3, FDEM_ATTA, (CE_WARN,
				    "fdc_attach failed: dip %p", (void*)dip));
				return (DDI_FAILURE);
			}
		} else {
			if (get_unit(dip, &cntlr_num) != DDI_SUCCESS)
				return (DDI_FAILURE);
		}

		ctlr = ddi_get_instance(dip);
		if (ddi_soft_state_zalloc(fdc_state_head, ctlr) != 0)
			return (DDI_FAILURE);
		fcp = ddi_get_soft_state(fdc_state_head, ctlr);

		for (unit = 0, fjp = (struct fcu_obj *)(fcp+1);
		    unit < NFDUN; unit++) {
			fcp->c_unit[unit] = fjp++;
		}
		fcp->c_dip = dip;

		if (fdc_propinit1(fcp, cntlr_num) != DDI_SUCCESS)
			goto no_attach;

		/* get iblock cookie to initialize mutex used in the ISR */
		if (ddi_get_iblock_cookie(dip, (uint_t)0, &fcp->c_iblock) !=
		    DDI_SUCCESS) {
			cmn_err(CE_WARN,
			    "fdc_attach: cannot get iblock cookie");
			goto no_attach;
		}
		mutex_init(&fcp->c_lock, NULL, MUTEX_DRIVER, fcp->c_iblock);
		intr_set = 1;

		/* setup interrupt handler */
		if (ddi_add_intr(dip, (uint_t)0, NULL,
		    (ddi_idevice_cookie_t *)0, fdc_intr, (caddr_t)fcp) !=
		    DDI_SUCCESS) {
			cmn_err(CE_WARN, "fdc: cannot add intr");
			goto no_attach;
		}
		intr_set++;

		/*
		 * acquire the DMA channel
		 * this assumes that the chnl is not shared; else allocate
		 * and free the chnl with each fdc request
		 */
		if (ddi_dmae_alloc(dip, fcp->c_dmachan, DDI_DMA_DONTWAIT, NULL)
		    != DDI_SUCCESS) {
			cmn_err(CE_WARN, "fdc: cannot acquire dma%d",
			    fcp->c_dmachan);
			goto no_attach;
		}
		(void) ddi_dmae_getattr(dip, &fdc_dma_attr);
		fdc_dma_attr.dma_attr_align = MMU_PAGESIZE;

		mutex_init(&fcp->c_dorlock, NULL, MUTEX_DRIVER, fcp->c_iblock);
		cv_init(&fcp->c_iocv, NULL, CV_DRIVER, fcp->c_iblock);
		sema_init(&fcp->c_selsem, 1, NULL, SEMA_DRIVER, NULL);

		(void) sprintf(name, "fdc%d", ctlr);
		fcp->c_intrstat = kstat_create("fdc", ctlr, name,
		    "controller", KSTAT_TYPE_INTR, 1, KSTAT_FLAG_PERSISTENT);
		if (fcp->c_intrstat) {
			kstat_install(fcp->c_intrstat);
		}

		ddi_set_driver_private(dip, fcp);

		/*
		 * reset the controller
		 */
		sema_p(&fcp->c_selsem);
		mutex_enter(&fcp->c_lock);
		fcp->c_csb.csb_xstate = FXS_RESET;
		fcp->c_flags |= FCFLG_WAITING;
		fdcquiesce(fcp);

		/* first test for mode == Model 30 */
		fcp->c_mode = (inb(fcp->c_regbase + FCR_SRB) & 0x1c) ?
		    FDCMODE_AT : FDCMODE_30;

		while (fcp->c_flags & FCFLG_WAITING) {
			cv_wait(&fcp->c_iocv, &fcp->c_lock);
		}
		mutex_exit(&fcp->c_lock);
		sema_v(&fcp->c_selsem);

		fdc_propinit2(fcp);

		ddi_report_dev(dip);
		return (DDI_SUCCESS);

	case DDI_RESUME:

		fcp = ddi_get_driver_private(dip);

		mutex_enter(&fcp->c_lock);
		fcp->c_suspended = B_FALSE;
		fcp->c_csb.csb_xstate = FXS_RESET;
		fcp->c_flags |= FCFLG_WAITING;
		fdcquiesce(fcp);

		while (fcp->c_flags & FCFLG_WAITING) {
			cv_wait(&fcp->c_iocv, &fcp->c_lock);
		}
		mutex_exit(&fcp->c_lock);

		/* should be good to go now */
		sema_v(&fcp->c_selsem);

		return (DDI_SUCCESS);
		/* break; */

	default:
		return (DDI_FAILURE);
	}

no_attach:
	if (intr_set) {
		if (intr_set > 1)
			ddi_remove_intr(dip, 0, fcp->c_iblock);
		mutex_destroy(&fcp->c_lock);
	}
	ddi_soft_state_free(fdc_state_head, cntlr_num);
	return (DDI_FAILURE);
}

static int
fdc_propinit1(struct fdcntlr *fcp, int cntlr)
{
	dev_info_t *dip;
	int len;
	int value;

	dip = fcp->c_dip;
	len = sizeof (value);

	if (get_ioaddr(dip, &value) != DDI_SUCCESS)
		return (DDI_FAILURE);

	fcp->c_regbase = (ushort_t)value;

	if (ddi_prop_op(DDI_DEV_T_ANY, dip, PROP_LEN_AND_VAL_BUF,
	    DDI_PROP_DONTPASS, "dma-channels", (caddr_t)&value, &len)
	    != DDI_PROP_SUCCESS) {
			cmn_err(CE_WARN,
			    "fdc_attach: Error, could not find a dma channel");
			return (DDI_FAILURE);
	}
	fcp->c_dmachan = (ushort_t)value;
	fcp->c_number = cntlr;
	return (DDI_SUCCESS);
}

static void
fdc_propinit2(struct fdcntlr *fcp)
{
	dev_info_t *dip;
	int ccr;
	int len;
	int value;

	dip = fcp->c_dip;
	len = sizeof (value);

	if (ddi_prop_op(DDI_DEV_T_ANY, dip, PROP_LEN_AND_VAL_BUF,
	    DDI_PROP_DONTPASS, "chip", (caddr_t)&value, &len)
	    == DDI_PROP_SUCCESS)
		fcp->c_chip = value;
	else {
		static uchar_t perpindcmd[2] = {FO_PERP, 0};
		static uchar_t versioncmd = FO_VRSN;
		uchar_t result;

		fcp->c_chip = i8272A;
		(void) fdc_docmd(fcp, &versioncmd, 1);
		/*
		 * Ignored return. If failed, warning was issued by fdc_docmd.
		 * fdc_results retrieves the controller/drive status
		 */
		if (!fdc_result(fcp, &result, 1) && result == 0x90) {
			/*
			 * try a perpendicular_mode cmd to ensure
			 * that we really have an enhanced controller
			 */
			if (fdc_docmd(fcp, perpindcmd, 2) ||
			    fdc_docmd(fcp, configurecmd, 4))
				/*
				 * perpindicular_mode will be rejected by
				 * older controllers; make sure we don't hang.
				 */
				(void) fdc_result(fcp, &result, 1);
				/*
				 * Ignored return. If failed, warning was
				 * issued by fdc_result.
				 */
			else
				/* enhanced type controller */

				if ((fcp->c_chip = fdc_enhance_probe(fcp)) == 0)
					/* default enhanced cntlr */
					fcp->c_chip = i82077;
		}
		(void) ddi_prop_update_int(DDI_DEV_T_NONE, dip,
		    "chip", fcp->c_chip);
		/*
		 * Ignoring return value because, for passed arguments, only
		 * DDI_SUCCESS is returned.
		 */
	}
	if (fcp->c_chip >= i82077 && fcp->c_mode == FDCMODE_30 &&
	    (inb(fcp->c_regbase + FCR_DIR) & 0x70) == 0)
		for (ccr = 0; ccr <= (FCC_NOPREC | FCC_DRATE); ccr++) {
			/*
			 * run through all the combinations of NOPREC and
			 * datarate selection, and see if they show up in the
			 * Model 30 DIR
			 */
			outb(fcp->c_regbase + FCR_CCR, ccr);
			drv_usecwait(5);
			if ((inb(fcp->c_regbase + FCR_DIR) &
			    (FCC_NOPREC | FCC_DRATE)) != ccr) {
				fcp->c_mode = FDCMODE_AT;
				break;
			}
		}
	else
		fcp->c_mode = FDCMODE_AT;
	outb(fcp->c_regbase + FCR_CCR, 0);
}

static int
fdc_enhance_probe(struct fdcntlr *fcp)
{
	static uchar_t nsccmd = FO_NSC;
	uint_t	ddic;
	int	retcode = 0;
	uchar_t	result;
	uchar_t	save;

	/*
	 * Try to identify the enhanced floppy controller.
	 * This is required so that we can program the DENSEL output to
	 * control 3D mode (1.0 MB, 1.6 MB and 2.0 MB unformatted capacity,
	 * 720 KB, 1.2 MB, and 1.44 MB formatted capacity) 3.5" dual-speed
	 * floppy drives.  Refer to bugid 1195155.
	 */

	(void) fdc_docmd(fcp, &nsccmd, 1);
	/*
	 * Ignored return. If failed, warning was issued by fdc_docmd.
	 * fdc_results retrieves the controller/drive status
	 */
	if (!fdc_result(fcp, &result, 1) && result != S0_IVCMD) {
		/*
		 * only enhanced National Semi PC8477 core
		 * should respond to this command
		 */
		if ((result & 0xf0) == 0x70) {
			/* low 4 bits may change */
			fcp->c_flags |= FCFLG_3DMODE;
			retcode = PC87322;
		} else
			cmn_err(CE_CONT,
"?fdc: unidentified, enhanced, National Semiconductor cntlr %x\n", result);
	} else {
		save = inb(fcp->c_regbase + FCR_SRA);

		do {
			/* probe for motherboard version of SMC cntlr */

			/* try to enable configuration mode */
			ddic = ddi_enter_critical();
			outb(fcp->c_regbase + FCR_SRA, FSA_ENA5);
			outb(fcp->c_regbase + FCR_SRA, FSA_ENA5);
			ddi_exit_critical(ddic);

			outb(fcp->c_regbase + FCR_SRA, 0x0F);
			if (inb(fcp->c_regbase + FCR_SRB) != 0x00)
				/* always expect 0 from config reg F */
				break;
			outb(fcp->c_regbase + FCR_SRA, 0x0D);
			if (inb(fcp->c_regbase + FCR_SRB) != 0x65)
				/* expect 0x65 from config reg D */
				break;
			outb(fcp->c_regbase + FCR_SRA, 0x0E);
			result = inb(fcp->c_regbase + FCR_SRB);
			if (result != 0x02) {
				/* expect revision level 2 from config reg E */
				cmn_err(CE_CONT,
"?fdc: unidentified, enhanced, SMC cntlr revision %x\n", result);
				/* break;	*/
			}
			fcp->c_flags |= FCFLG_3DMODE;
			retcode = FDC37C665;
		} while (retcode == 0);
		outb(fcp->c_regbase + FCR_SRA, FSA_DISB);

		while (retcode == 0) {
			/* probe for adapter version of SMC cntlr */
			ddic = ddi_enter_critical();
			outb(fcp->c_regbase + FCR_SRA, FSA_ENA6);
			outb(fcp->c_regbase + FCR_SRA, FSA_ENA6);
			ddi_exit_critical(ddic);

			outb(fcp->c_regbase + FCR_SRA, 0x0F);
			if (inb(fcp->c_regbase + FCR_SRB) != 0x00)
				/* always expect 0 from config reg F */
				break;
			outb(fcp->c_regbase + FCR_SRA, 0x0D);
			if (inb(fcp->c_regbase + FCR_SRB) != 0x66)
				/* expect 0x66 from config reg D */
				break;
			outb(fcp->c_regbase + FCR_SRA, 0x0E);
			result = inb(fcp->c_regbase + FCR_SRB);
			if (result != 0x02) {
				/* expect revision level 2 from config reg E */
				cmn_err(CE_CONT,
"?fdc: unidentified, enhanced, SMC cntlr revision %x\n", result);
				/* break;	*/
			}
			fcp->c_flags |= FCFLG_3DMODE;
			retcode = FDC37C666;
		}
		outb(fcp->c_regbase + FCR_SRA, FSA_DISB);

		drv_usecwait(10);
		outb(fcp->c_regbase + FCR_SRA, save);
	}
	return (retcode);
}

static int
fdc_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	struct fdcntlr *fcp;
	int unit;
	int rval = 0;

	FCERRPRINT(FDEP_L3, FDEM_ATTA, (CE_WARN, "fdc_detach: dip %p",
	    (void*)dip));

	fcp = ddi_get_driver_private(dip);

	switch (cmd) {
	case DDI_DETACH:
		for (unit = 0; unit < NFDUN; unit++)
			if ((fcp->c_unit[unit])->fj_dip) {
				rval = EBUSY;
				break;
			}
		kstat_delete(fcp->c_intrstat);
		fcp->c_intrstat = NULL;
		ddi_remove_intr(fcp->c_dip, 0, fcp->c_iblock);
		if (ddi_dmae_release(fcp->c_dip, fcp->c_dmachan) !=
		    DDI_SUCCESS)
			cmn_err(CE_WARN, "fdc_detach: dma release failed, "
			    "dip %p, dmachan %x",
			    (void*)fcp->c_dip, fcp->c_dmachan);
		ddi_prop_remove_all(fcp->c_dip);
		ddi_set_driver_private(fcp->c_dip, NULL);

		mutex_destroy(&fcp->c_lock);
		mutex_destroy(&fcp->c_dorlock);
		cv_destroy(&fcp->c_iocv);
		sema_destroy(&fcp->c_selsem);
		ddi_soft_state_free(fdc_state_head, ddi_get_instance(dip));
		break;

	case DDI_SUSPEND:
		/*
		 * For suspend, we just use the semaphore to
		 * keep any child devices from accessing any of our
		 * hardware routines, and then shutdown the hardware.
		 *
		 * On resume, we'll reinit the hardware and release the
		 * semaphore.
		 */
		sema_p(&fcp->c_selsem);

		if (ddi_dmae_disable(fcp->c_dip, fcp->c_dmachan) !=
		    DDI_SUCCESS) {
			cmn_err(CE_WARN, "fdc_suspend: dma disable failed, "
			    "dip %p, dmachan %x", (void *)fcp->c_dip,
			    fcp->c_dmachan);
			/* give it back on failure */
			sema_v(&fcp->c_selsem);
			return (DDI_FAILURE);
		}

		mutex_enter(&fcp->c_lock);
		fcp->c_suspended = B_TRUE;
		mutex_exit(&fcp->c_lock);

		rval = DDI_SUCCESS;
		break;

	default:
		rval = EINVAL;
		break;
	}
	return (rval);
}


int
fdc_abort(struct fcu_obj *fjp)
{
	struct fdcntlr *fcp = fjp->fj_fdc;
	int unit = fjp->fj_unit & 3;

	FCERRPRINT(FDEP_L3, FDEM_RESE, (CE_WARN, "fdc_abort"));
	if (fcp->c_curunit == unit) {
		mutex_enter(&fcp->c_lock);
		if (fcp->c_flags & FCFLG_WAITING) {
			/*
			 * this can cause data corruption !
			 */
			fdcquiesce(fcp);
			fcp->c_csb.csb_xstate = FXS_RESET;
			fcp->c_flags |= FCFLG_TIMEOUT;
			if (ddi_dmae_stop(fcp->c_dip, fcp->c_dmachan) !=
			    DDI_SUCCESS)
				cmn_err(CE_WARN,
				    "fdc_detach: dma release failed, "
				    "dip %p, dmachan %x",
				    (void*)fcp->c_dip, fcp->c_dmachan);
		}
		mutex_exit(&fcp->c_lock);
		drv_usecwait(500);
		return (DDI_SUCCESS);
	}
	return (DDI_FAILURE);
}

int
fdc_dkinfo(struct fcu_obj *fjp, struct dk_cinfo *dcp)
{
	struct fdcntlr *fcp = fjp->fj_fdc;

	(void) strncpy((char *)&dcp->dki_cname, ddi_get_name(fcp->c_dip),
	    DK_DEVLEN);
	dcp->dki_ctype = DKC_UNKNOWN; /* no code for generic PC/AT fdc */
	dcp->dki_flags = DKI_FMTTRK;
	dcp->dki_addr = fcp->c_regbase;
	dcp->dki_space = 0;
	dcp->dki_prio = fcp->c_intprio;
	dcp->dki_vec = fcp->c_intvec;
	(void) strncpy((char *)&dcp->dki_dname, ddi_driver_name(fjp->fj_dip),
	    DK_DEVLEN);
	dcp->dki_slave = fjp->fj_unit & 3;
	dcp->dki_maxtransfer = maxphys / DEV_BSIZE;
	return (DDI_SUCCESS);
}

/*
 * on=> non-zero = select, 0 = de-select
 */
int
fdc_select(struct fcu_obj *fjp, int funit, int on)
{
	struct fdcntlr *fcp = fjp->fj_fdc;
	int unit = funit & 3;

	if (on) {
		/* possess controller */
		sema_p(&fcp->c_selsem);
		FCERRPRINT(FDEP_L2, FDEM_DSEL,
		    (CE_NOTE, "fdc_select unit %d: on", funit));

		if (fcp->c_curunit != unit || !(fjp->fj_flags & FUNIT_CHAROK)) {
			fcp->c_curunit = unit;
			fjp->fj_flags |= FUNIT_CHAROK;
			if (fdcspecify(fcp,
			    fjp->fj_chars->fdc_transfer_rate,
			    fjp->fj_drive->fdd_steprate, 40))
				cmn_err(CE_WARN,
				    "fdc_select: controller setup rejected "
				    "fdcntrl %p transfer rate %x step rate %x"
				    " head load time 40", (void*)fcp,
				    fjp->fj_chars->fdc_transfer_rate,
				    fjp->fj_drive->fdd_steprate);
		}

		mutex_enter(&fcp->c_dorlock);

		/* make sure drive is not selected in case we change speed */
		fcp->c_digout = (fcp->c_digout & ~FD_DRSEL) |
		    (~unit & FD_DRSEL);
		outb(fcp->c_regbase + FCR_DOR, fcp->c_digout);

		(void) fdc_motorsm(fjp, FMI_STARTCMD,
		    fjp->fj_drive->fdd_motoron);
		/*
		 * Return value ignored - fdcmotort deals with failure.
		 */
		if (fdcspdchange(fcp, fjp, fjp->fj_attr->fda_rotatespd)) {
			/* 3D drive requires 500 ms for speed change */
			(void) fdc_motorsm(fjp, FMI_RSTARTCMD, 5);
			/*
			 * Return value ignored - fdcmotort deals with failure.
			 */
		}

		fcp->c_digout = (fcp->c_digout & ~FD_DRSEL) | (unit & FD_DRSEL);
		outb(fcp->c_regbase + FCR_DOR, fcp->c_digout);

		mutex_exit(&fcp->c_dorlock);
		fcp->c_csb.csb_drive = (uchar_t)unit;
	} else {
		FCERRPRINT(FDEP_L2, FDEM_DSEL,
		    (CE_NOTE, "fdc_select unit %d: off", funit));

		mutex_enter(&fcp->c_dorlock);

		fcp->c_digout |= FD_DRSEL;
		outb(fcp->c_regbase + FCR_DOR, fcp->c_digout);
		(void) fdc_motorsm(fjp, FMI_IDLECMD,
		    fjp->fj_drive->fdd_motoroff);
		/*
		 * Return value ignored - fdcmotort deals with failure.
		 */

		mutex_exit(&fcp->c_dorlock);

		/* give up controller */
		sema_v(&fcp->c_selsem);
	}
	return (0);
}


int
fdgetchng(struct fcu_obj *fjp, int funit)
{
	if (fdcsense_drv(fjp->fj_fdc, funit & 3))
		cmn_err(CE_WARN, "fdgetchng: write protect check failed");
	return (fdcsense_chng(fjp->fj_fdc, funit & 3));
}


int
fdresetchng(struct fcu_obj *fjp, int funit)
{
	struct fdcntlr *fcp = fjp->fj_fdc;
	int unit = funit & 3;
	int newcyl;			/* where to seek for reset of DSKCHG */

	FCERRPRINT(FDEP_L2, FDEM_CHEK, (CE_NOTE, "fdmediachng unit %d", funit));

	if (fcp->c_curpcyl[unit])
		newcyl = fcp->c_curpcyl[unit] - 1;
	else
		newcyl = 1;
	return (fdrecalseek(fjp, funit, newcyl, 0));
}


/*
 * fdrecalseek
 */
int
fdrecalseek(struct fcu_obj *fjp, int funit, int arg, int execflg)
{
	struct fdcntlr *fcp = fjp->fj_fdc;
	struct fdcsb *csb;
	int unit = funit & 3;
	int rval;

	FCERRPRINT(FDEP_L2, FDEM_RECA, (CE_NOTE, "fdrecalseek unit %d to %d",
	    funit, arg));

	csb = &fcp->c_csb;
	csb->csb_cmd[1] = (uchar_t)unit;
	if (arg < 0) {			/* is recal... */
		*csb->csb_cmd = FO_RECAL;
		csb->csb_ncmds = 2;
		csb->csb_timer = 28;
	} else {
		*csb->csb_cmd = FO_SEEK;
		csb->csb_cmd[2] = (uchar_t)arg;
		csb->csb_ncmds = 3;
		csb->csb_timer = 10;
	}
	csb->csb_nrslts = 2;	/* 2 for SENSE INTERRUPTS */
	csb->csb_opflags = CSB_OFINRPT;
	csb->csb_maxretry = skretry;
	csb->csb_dmahandle = NULL;
	csb->csb_handle_bound = 0;
	csb->csb_dmacookiecnt = 0;
	csb->csb_dmacurrcookie = 0;
	csb->csb_dmawincnt = 0;
	csb->csb_dmacurrwin = 0;

	/* send cmd off to fdc_exec */
	if (rval = fdc_exec(fcp, 1, execflg))
		goto out;

	if (!(*csb->csb_rslt & S0_SEKEND) ||
	    (*csb->csb_rslt & S0_ICMASK) ||
	    ((*csb->csb_rslt & S0_ECHK) && arg < 0) ||
	    csb->csb_cmdstat)
		rval = ENODEV;

	if (fdcsense_drv(fcp, unit))
		cmn_err(CE_WARN, "fdgetchng: write protect check failed");
out:
	return (rval);
}


/*
 * fdrw- used only for read/writing sectors into/from kernel buffers.
 */
int
fdrw(struct fcu_obj *fjp, int funit, int rw, int cyl, int head,
    int sector, caddr_t bufp, uint_t len)
{
	struct fdcntlr *fcp = fjp->fj_fdc;
	struct fdcsb *csb;
	uint_t dmar_flags = 0;
	int unit = funit & 3;
	int rval;
	ddi_acc_handle_t mem_handle = NULL;
	caddr_t aligned_buf;
	size_t real_size;

	FCERRPRINT(FDEP_L1, FDEM_RW, (CE_CONT, "fdrw unit %d\n", funit));

	csb = &fcp->c_csb;
	if (rw) {
		dmar_flags = DDI_DMA_READ;
		csb->csb_opflags = CSB_OFDMARD | CSB_OFINRPT;
		*csb->csb_cmd = FO_MT | FO_MFM | FO_SK | FO_RDDAT;
	} else { /* write */
		dmar_flags = DDI_DMA_WRITE;
		csb->csb_opflags = CSB_OFDMAWT | CSB_OFINRPT;
		*csb->csb_cmd = FO_MT | FO_MFM | FO_WRDAT;
	}
	csb->csb_cmd[1] = (uchar_t)(unit | ((head & 0x1) << 2));
	csb->csb_cmd[2] = (uchar_t)cyl;
	csb->csb_cmd[3] = (uchar_t)head;
	csb->csb_cmd[4] = (uchar_t)sector;
	encode(sector_size, fjp->fj_chars->fdc_sec_size,
	    &csb->csb_cmd[5]);
	csb->csb_cmd[6] = (uchar_t)max(fjp->fj_chars->fdc_secptrack, sector);
	csb->csb_cmd[7] = fjp->fj_attr->fda_gapl;
	csb->csb_cmd[8] = 0xFF;

	csb->csb_ncmds = 9;
	csb->csb_nrslts = 7;
	csb->csb_timer = 36;
	if (rw == FDRDONE)
		csb->csb_maxretry = 1;
	else
		csb->csb_maxretry = rwretry;

	csb->csb_dmahandle = NULL;
	csb->csb_handle_bound = 0;
	csb->csb_dmacookiecnt = 0;
	csb->csb_dmacurrcookie = 0;
	csb->csb_dmawincnt = 0;
	csb->csb_dmacurrwin = 0;
	dmar_flags |= (DDI_DMA_STREAMING | DDI_DMA_PARTIAL);

	if (ddi_dma_alloc_handle(fcp->c_dip, &fdc_dma_attr, DDI_DMA_SLEEP,
	    0, &csb->csb_dmahandle) != DDI_SUCCESS) {
		rval = EINVAL;
		goto out;
	}

	/*
	 * allocate a page aligned buffer to dma to/from. This way we can
	 * ensure the cookie is a whole multiple of granularity and avoids
	 * any alignment issues.
	 */
	rval = ddi_dma_mem_alloc(csb->csb_dmahandle, len, &fdc_accattr,
	    DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, NULL, &aligned_buf,
	    &real_size, &mem_handle);
	if (rval != DDI_SUCCESS) {
		rval = EINVAL;
		goto out;
	}

	if (dmar_flags & DDI_DMA_WRITE) {
		bcopy(bufp, aligned_buf, len);
	}

	rval = ddi_dma_addr_bind_handle(csb->csb_dmahandle, NULL, aligned_buf,
	    len, dmar_flags, DDI_DMA_SLEEP, 0, &csb->csb_dmacookie,
	    &csb->csb_dmacookiecnt);

	if (rval == DDI_DMA_MAPPED) {
		csb->csb_dmawincnt = 1;
		csb->csb_handle_bound = 1;
	} else if (rval == DDI_DMA_PARTIAL_MAP) {
		csb->csb_handle_bound = 1;
		if (ddi_dma_numwin(csb->csb_dmahandle, &csb->csb_dmawincnt) !=
		    DDI_SUCCESS) {
			cmn_err(CE_WARN, "fdrw: dma numwin failed");
			rval = EINVAL;
			goto out;
		}
	} else {
		cmn_err(CE_WARN,
		    "fdrw: dma addr bind handle failed, rval = %d", rval);
		rval = EINVAL;
		goto out;
	}
	rval = fdc_exec(fcp, 1, 1);

	if (dmar_flags & DDI_DMA_READ) {
		bcopy(aligned_buf, bufp, len);
	}

out:
	if (csb->csb_dmahandle) {
		if (csb->csb_handle_bound) {
			if (ddi_dma_unbind_handle(csb->csb_dmahandle) !=
			    DDI_SUCCESS)
				cmn_err(CE_WARN, "fdrw: "
				    "dma unbind handle failed");
			csb->csb_handle_bound = 0;
		}
		if (mem_handle != NULL) {
			ddi_dma_mem_free(&mem_handle);
		}
		ddi_dma_free_handle(&csb->csb_dmahandle);
		csb->csb_dmahandle = NULL;
	}
	return (rval);
}


int
fdtrkformat(struct fcu_obj *fjp, int funit, int cyl, int head, int filldata)
{
	struct fdcntlr *fcp = fjp->fj_fdc;
	struct fdcsb *csb;
	int unit = funit & 3;
	int fmdatlen, lsector, lstart;
	int interleave, numsctr, offset, psector;
	uchar_t *dp;
	int rval;
	ddi_acc_handle_t mem_handle = NULL;
	caddr_t aligned_buf;
	size_t real_size;

	FCERRPRINT(FDEP_L2, FDEM_FORM,
	    (CE_NOTE, "fdformattrk unit %d cyl=%d, hd=%d", funit, cyl, head));

	csb = &fcp->c_csb;

	csb->csb_opflags = CSB_OFDMAWT | CSB_OFINRPT;

	*csb->csb_cmd = FO_FRMT | FO_MFM;
	csb->csb_cmd[1] = (head << 2) | unit;
	encode(sector_size, fjp->fj_chars->fdc_sec_size,
	    &csb->csb_cmd[2]);
	csb->csb_cmd[3] = numsctr = fjp->fj_chars->fdc_secptrack;
	csb->csb_cmd[4] = fjp->fj_attr->fda_gapf;
	csb->csb_cmd[5] = (uchar_t)filldata;

	csb->csb_npcyl = (uchar_t)(cyl * fjp->fj_chars->fdc_steps);

	csb->csb_dmahandle = NULL;
	csb->csb_handle_bound = 0;
	csb->csb_dmacookiecnt = 0;
	csb->csb_dmacurrcookie = 0;
	csb->csb_dmawincnt = 0;
	csb->csb_dmacurrwin = 0;
	csb->csb_ncmds = 6;
	csb->csb_nrslts = 7;
	csb->csb_timer = 32;
	csb->csb_maxretry = rwretry;

	/*
	 * alloc space for format track cmd
	 */
	/*
	 * NOTE: have to add size of fifo also - for dummy format action
	 */
	fmdatlen = 4 * numsctr;

	if (ddi_dma_alloc_handle(fcp->c_dip, &fdc_dma_attr, DDI_DMA_SLEEP,
	    0, &csb->csb_dmahandle) != DDI_SUCCESS) {
		rval = EINVAL;
		goto out;
	}

	/*
	 * allocate a page aligned buffer to dma to/from. This way we can
	 * ensure the cookie is a whole multiple of granularity and avoids
	 * any alignment issues.
	 */
	rval = ddi_dma_mem_alloc(csb->csb_dmahandle, fmdatlen, &fdc_accattr,
	    DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, NULL, &aligned_buf,
	    &real_size, &mem_handle);
	if (rval != DDI_SUCCESS) {
		rval = EINVAL;
		goto out;
	}
	dp = (uchar_t *)aligned_buf;

	interleave = fjp->fj_attr->fda_intrlv;
	offset = (numsctr + interleave - 1) / interleave;
	for (psector = lstart = 1;
	    psector <= numsctr; psector += interleave, lstart++) {
		for (lsector = lstart; lsector <= numsctr; lsector += offset) {
			*dp++ = (uchar_t)cyl;
			*dp++ = (uchar_t)head;
			*dp++ = (uchar_t)lsector;
			*dp++ = csb->csb_cmd[2];
		}
	}

	rval = ddi_dma_addr_bind_handle(csb->csb_dmahandle, NULL, aligned_buf,
	    fmdatlen, DDI_DMA_WRITE | DDI_DMA_STREAMING | DDI_DMA_PARTIAL,
	    DDI_DMA_SLEEP, 0, &csb->csb_dmacookie, &csb->csb_dmacookiecnt);

	if (rval == DDI_DMA_MAPPED) {
		csb->csb_dmawincnt = 1;
		csb->csb_handle_bound = 1;
	} else if (rval == DDI_DMA_PARTIAL_MAP) {
		csb->csb_handle_bound = 1;
		if (ddi_dma_numwin(csb->csb_dmahandle, &csb->csb_dmawincnt) !=
		    DDI_SUCCESS) {
			cmn_err(CE_WARN, "fdtrkformat: dma numwin failed");
			rval = EINVAL;
			goto out;
		}
	} else {
		cmn_err(CE_WARN,
		    "fdtrkformat: dma buf bind handle failed, rval = %d",
		    rval);
		rval = EINVAL;
		goto out;
	}

	rval = fdc_exec(fcp, 1, 1);
out:
	if (csb->csb_dmahandle) {
		if (csb->csb_handle_bound) {
			if (ddi_dma_unbind_handle(csb->csb_dmahandle) !=
			    DDI_SUCCESS)
				cmn_err(CE_WARN, "fdtrkformat: "
				    "dma unbind handle failed");
			csb->csb_handle_bound = 0;
		}
		if (mem_handle != NULL) {
			ddi_dma_mem_free(&mem_handle);
		}
		ddi_dma_free_handle(&csb->csb_dmahandle);
		csb->csb_dmahandle = NULL;
	}
	return (rval);
}

int
fdrawioctl(struct fcu_obj *fjp, int funit, caddr_t arg)
{
	struct fdcntlr *fcp = fjp->fj_fdc;
	struct fd_raw *fdrp = (struct fd_raw *)arg;
	struct fdcsb *csb;
	uint_t dmar_flags = 0;
	int i;
	int change = 1;
	int sleep = 1;
	int rval = 0;
	int rval_exec = 0;
	ddi_acc_handle_t mem_handle = NULL;
	caddr_t aligned_buf;
	size_t real_size;

	_NOTE(ARGUNUSED(funit));

	FCERRPRINT(FDEP_L2, FDEM_RAWI,
	    (CE_NOTE, "fdrawioctl: cmd[0]=0x%x", fdrp->fdr_cmd[0]));

	csb = &fcp->c_csb;

	/* copy cmd bytes into csb */
	for (i = 0; i <= fdrp->fdr_cnum; i++)
		csb->csb_cmd[i] = fdrp->fdr_cmd[i];
	csb->csb_ncmds = (uchar_t)fdrp->fdr_cnum;

	csb->csb_maxretry = 0;	/* let the application deal with errors */
	csb->csb_opflags = CSB_OFRAWIOCTL;
	csb->csb_nrslts = 0;
	csb->csb_timer = 50;

	switch (fdrp->fdr_cmd[0] & 0x0f) {

	case FO_SEEK:
		change = 0;
		/* FALLTHROUGH */
	case FO_RECAL:
		csb->csb_opflags |= CSB_OFINRPT;
		break;

	case FO_FRMT:
		csb->csb_npcyl = *(uchar_t *)(fdrp->fdr_addr) *
		    fjp->fj_chars->fdc_steps;
		/* FALLTHROUGH */
	case FO_WRDAT:
	case FO_WRDEL:
		csb->csb_opflags |= CSB_OFDMAWT | CSB_OFRESLT | CSB_OFINRPT;
		csb->csb_nrslts = 7;
		if (fdrp->fdr_nbytes == 0)
			return (EINVAL);
		dmar_flags = DDI_DMA_WRITE;
		break;

	case FO_RDDAT:
	case FO_RDDEL:
	case FO_RDTRK:
		csb->csb_opflags |= CSB_OFDMARD | CSB_OFRESLT | CSB_OFINRPT;
		csb->csb_nrslts = 7;
		dmar_flags = DDI_DMA_READ;
		break;

	case FO_RDID:
		csb->csb_opflags |= CSB_OFRESLT | CSB_OFINRPT;
		csb->csb_nrslts = 7;
		break;

	case FO_SDRV:
		sleep = 0;
		csb->csb_nrslts = 1;
		break;

	case FO_SINT:
		sleep = 0;
		change = 0;
		csb->csb_nrslts = 2;
		break;

	case FO_SPEC:
		sleep = 0;
		change = 0;
		break;

	default:
		return (EINVAL);
	}

	csb->csb_dmahandle = NULL;
	csb->csb_handle_bound = 0;
	csb->csb_dmacookiecnt = 0;
	csb->csb_dmacurrcookie = 0;
	csb->csb_dmawincnt = 0;
	csb->csb_dmacurrwin = 0;

	if (csb->csb_opflags & (CSB_OFDMARD | CSB_OFDMAWT)) {
		if (ddi_dma_alloc_handle(fcp->c_dip, &fdc_dma_attr,
		    DDI_DMA_SLEEP, 0, &csb->csb_dmahandle) != DDI_SUCCESS) {
			rval = EINVAL;
			goto out;
		}

		/*
		 * allocate a page aligned buffer to dma to/from. This way we
		 * can ensure the cookie is a whole multiple of granularity and
		 * avoids any alignment issues.
		 */
		rval = ddi_dma_mem_alloc(csb->csb_dmahandle,
		    (uint_t)fdrp->fdr_nbytes, &fdc_accattr, DDI_DMA_CONSISTENT,
		    DDI_DMA_SLEEP, NULL, &aligned_buf, &real_size, &mem_handle);
		if (rval != DDI_SUCCESS) {
			rval = EINVAL;
			goto out;
		}

		if (dmar_flags & DDI_DMA_WRITE) {
			bcopy(fdrp->fdr_addr, aligned_buf,
			    (uint_t)fdrp->fdr_nbytes);
		}

		dmar_flags |= (DDI_DMA_STREAMING | DDI_DMA_PARTIAL);
		rval = ddi_dma_addr_bind_handle(csb->csb_dmahandle, NULL,
		    aligned_buf, (uint_t)fdrp->fdr_nbytes, dmar_flags,
		    DDI_DMA_SLEEP, 0, &csb->csb_dmacookie,
		    &csb->csb_dmacookiecnt);

		if (rval == DDI_DMA_MAPPED) {
			csb->csb_dmawincnt = 1;
			csb->csb_handle_bound = 1;
		} else if (rval == DDI_DMA_PARTIAL_MAP) {
			csb->csb_handle_bound = 1;
			if (ddi_dma_numwin(csb->csb_dmahandle,
			    &csb->csb_dmawincnt) != DDI_SUCCESS) {
				cmn_err(CE_WARN,
				    "fdrawioctl: dma numwin failed");
				rval = EINVAL;
				goto out;
			}
		} else {
			cmn_err(CE_WARN, "fdrawioctl: "
			    "dma buf bind handle failed, rval = %d", rval);
			rval = EINVAL;
			goto out;
		}
	}

	FCERRPRINT(FDEP_L1, FDEM_RAWI,
	    (CE_CONT, "cmd: %x %x %x %x %x %x %x %x %x %x\n", csb->csb_cmd[0],
	    csb->csb_cmd[1], csb->csb_cmd[2], csb->csb_cmd[3],
	    csb->csb_cmd[4], csb->csb_cmd[5], csb->csb_cmd[6],
	    csb->csb_cmd[7], csb->csb_cmd[8], csb->csb_cmd[9]));
	FCERRPRINT(FDEP_L1, FDEM_RAWI,
	    (CE_CONT, "nbytes: %x, opflags: %x, addr: %p, len: %x\n",
	    csb->csb_ncmds, csb->csb_opflags, (void *)fdrp->fdr_addr,
	    fdrp->fdr_nbytes));

	/*
	 * Note that we ignore any error returns from fdexec.
	 * This is the way the driver has been, and it may be
	 * that the raw ioctl senders simply don't want to
	 * see any errors returned in this fashion.
	 */

	/*
	 * VP/ix sense drive ioctl call checks for the error return.
	 */

	rval_exec = fdc_exec(fcp, sleep, change);

	if (dmar_flags & DDI_DMA_READ) {
		bcopy(aligned_buf, fdrp->fdr_addr, (uint_t)fdrp->fdr_nbytes);
	}

	FCERRPRINT(FDEP_L1, FDEM_RAWI,
	    (CE_CONT, "rslt: %x %x %x %x %x %x %x %x %x %x\n", csb->csb_rslt[0],
	    csb->csb_rslt[1], csb->csb_rslt[2], csb->csb_rslt[3],
	    csb->csb_rslt[4], csb->csb_rslt[5], csb->csb_rslt[6],
	    csb->csb_rslt[7], csb->csb_rslt[8], csb->csb_rslt[9]));

	/* copy results into fdr */
	for (i = 0; i <= (int)csb->csb_nrslts; i++)
		fdrp->fdr_result[i] = csb->csb_rslt[i];
/*	fdrp->fdr_nbytes = fdc->c_csb.csb_rlen;  return resid */

out:
	if (csb->csb_dmahandle) {
		if (csb->csb_handle_bound) {
			if (ddi_dma_unbind_handle(csb->csb_dmahandle) !=
			    DDI_SUCCESS)
				cmn_err(CE_WARN, "fdrawioctl: "
				    "dma unbind handle failed");
			csb->csb_handle_bound = 0;
		}
		if (mem_handle != NULL) {
			ddi_dma_mem_free(&mem_handle);
		}
		ddi_dma_free_handle(&csb->csb_dmahandle);
		csb->csb_dmahandle = NULL;
	}
	if ((fdrp->fdr_cmd[0] & 0x0f) == FO_SDRV) {
		return (rval_exec);
	}
	return (rval);
}

void
encode(xlate_tbl_t *tablep, int val, uchar_t *rcode)
{
	do {
		if (tablep->value >= val) {
			*rcode = tablep->code;
			return;
		}
	} while ((++tablep)->value);
	*rcode = tablep->code;
	cmn_err(CE_WARN, "fdc encode failed, table %p val %x code %x",
	    (void *)tablep, val, (uint_t)*rcode);
}

int
decode(xlate_tbl_t *tablep, int kode, int *rvalue)
{
	do  {
		if (tablep->code == kode) {
			*rvalue = tablep->value;
			return (0);
		}
	} while ((++tablep)->value);
	return (-1);
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
int
fdc_quiesce(dev_info_t *dip)
{
	struct fdcntlr *fcp;
	int ctlr = ddi_get_instance(dip);
	int unit;

	fcp = ddi_get_soft_state(fdc_state_head, ctlr);

	if (fcp == NULL)
		return (DDI_FAILURE);

	/*
	 * If no FD units are attached, there is no need to quiesce.
	 */
	for (unit = 0; unit < NFDUN; unit++) {
		struct fcu_obj *fjp = fcp->c_unit[unit];
		if (fjp->fj_flags & FUNIT_DRVATCH) {
			break;
		}
	}

	if (unit == NFDUN)
		return (DDI_SUCCESS);

	(void) ddi_dmae_disable(fcp->c_dip, fcp->c_dmachan);

	fcp->c_digout = (fcp->c_digout & (FD_DMTREN | FD_DRSEL)) | FD_ENABLE;
	outb(fcp->c_regbase + FCR_DOR, fcp->c_digout);
	drv_usecwait(20);
	fcp->c_digout |= FD_RSETZ;
	outb(fcp->c_regbase + FCR_DOR, fcp->c_digout);

	if (fcp->c_chip >= i82077) {
		int count = 4;
		uchar_t *oplistp = configurecmd;
		do {
			int ntries = FDC_RQM_RETRY;
			do {
				if ((inb(fcp->c_regbase + FCR_MSR) &
				    (MS_RQM|MS_DIO)) == MS_RQM)
					break;
				else
					drv_usecwait(1);
			} while (--ntries);
			if (ntries == 0) {
				break;
			}
			outb(fcp->c_regbase + FCR_DATA, *oplistp++);
			drv_usecwait(16); /* See comment in fdc_result() */
		} while (--count);
	}

	return (DDI_SUCCESS);
}

void
fdcquiesce(struct fdcntlr *fcp)
{
	int unit;

	FCERRPRINT(FDEP_L2, FDEM_RESE, (CE_NOTE, "fdcquiesce fcp %p",
	    (void*)fcp));

	ASSERT(MUTEX_HELD(&fcp->c_lock));
	mutex_enter(&fcp->c_dorlock);

	if (ddi_dmae_stop(fcp->c_dip, fcp->c_dmachan) != DDI_SUCCESS)
		cmn_err(CE_WARN, "fdcquiesce: dmae stop failed, "
		    "dip %p, dmachan %x",
		    (void*)fcp->c_dip, fcp->c_dmachan);

	fcp->c_digout = (fcp->c_digout & (FD_DMTREN | FD_DRSEL)) | FD_ENABLE;
	outb(fcp->c_regbase + FCR_DOR, fcp->c_digout);
	drv_usecwait(20);
	fcp->c_digout |= FD_RSETZ;
	outb(fcp->c_regbase + FCR_DOR, fcp->c_digout);

	mutex_exit(&fcp->c_dorlock);

	/* count resets */
	fcp->fdstats.reset++;
	fcp->c_curunit = -1;
	for (unit = 0; unit < NFDUN; unit++)
		fcp->c_curpcyl[unit] = -1;

	if (fcp->c_chip >= i82077) {
		(void) fdc_docmd(fcp, configurecmd, 4);
		/*
		 * Ignored return. If failed, warning was issued by fdc_docmd.
		 */
	}
}

void
fdcreadid(struct fdcntlr *fcp, struct fdcsb *csb)
{
	static uchar_t readidcmd[2] = {FO_RDID | FO_MFM, 0};

	readidcmd[1] = csb->csb_cmd[1];
	(void) fdc_docmd(fcp, readidcmd, 2);
}

int
fdcseek(struct fdcntlr *fcp, int unit, int cyl)
{
	static uchar_t seekabscmd[3] = {FO_SEEK, 0, 0};

	FCERRPRINT(FDEP_L0, FDEM_RECA, (CE_CONT, "fdcseek unit %d to cyl %d\n",
	    unit, cyl));
	seekabscmd[1] = (uchar_t)unit;
	seekabscmd[2] = (uchar_t)cyl;
	return (fdc_docmd(fcp, seekabscmd, 3));
}

/*
 * Returns status of disk change line of selected drive.
 *	= 0 means diskette is present
 *	!= 0 means diskette was removed and current state is unknown
 */
int
fdcsense_chng(struct fdcntlr *fcp, int unit)
{
	int digital_input;

	FCERRPRINT(FDEP_L0, FDEM_SCHG,
	    (CE_CONT, "fdcsense_chng unit %d\n", unit));
	digital_input = inb(fcp->c_regbase + FCR_DIR);
	if (fcp->c_mode == FDCMODE_30)
		digital_input ^= FDI_DKCHG;
	return (digital_input & FDI_DKCHG);
}

int
fdcsense_drv(struct fdcntlr *fcp, int unit)
{
	static uchar_t sensedrvcmd[2] = {FO_SDRV, 0};
	uchar_t senser;
	int rval;

	sensedrvcmd[1] = (uchar_t)unit;
	(void) fdc_docmd(fcp, sensedrvcmd, 2);
	/*
	 * Ignored return. If failed, warning was issued by fdc_docmd.
	 * fdc_results retrieves the controller/drive status
	 */
	if (rval = fdc_result(fcp, &senser, 1))
		goto done;
	if (senser & S3_WPROT)
		fcp->c_unit[unit]->fj_flags |= FUNIT_WPROT;
	else
		fcp->c_unit[unit]->fj_flags &= ~FUNIT_WPROT;
done:
	return (rval);
}

int
fdcsense_int(struct fdcntlr *fcp, int *unitp, int *cylp)
{
	uchar_t senser[2];
	int rval;

	(void) fdc_docmd(fcp, &senseintcmd, 1);
	/*
	 * Ignored return. If failed, warning was issued by fdc_docmd.
	 * fdc_results retrieves the controller/drive status
	 */

	if (!(rval = fdc_result(fcp, senser, 2))) {
		if ((*senser & (S0_IVCMD | S0_SEKEND | S0_ECHK)) != S0_SEKEND)
			rval = 1;
		if (unitp)
			*unitp = *senser & 3;
		if (cylp)
			*cylp = senser[1];
	}
	return (rval);
}

int
fdcspecify(struct fdcntlr *fcp, int xferrate, int steprate, int hlt)
{
	static uchar_t perpindcmd[2] = {FO_PERP, 0};
	static uchar_t specifycmd[3] = {FO_SPEC, 0, 0};

	encode(drate_mfm, xferrate, &fcp->c_config);
	outb(fcp->c_regbase + FCR_CCR, fcp->c_config);

	if (fcp->c_chip >= i82077) {
		/*
		 * Use old style perpendicular mode command of 82077.
		 */
		if (xferrate == 1000) {
			/* Set GAP and WGATE */
			perpindcmd[1] = 3;
			/* double step rate because xlate table is for 500Kb */
			steprate <<= 1;
			hlt <<= 1;
		} else
			perpindcmd[1] = 0;
		(void) fdc_docmd(fcp, perpindcmd, 2);
		/*
		 * Ignored return. If failed, warning was issued by fdc_docmd.
		 */
	}
	encode(step_rate, steprate, &fcp->c_hutsrt);
	specifycmd[1] = fcp->c_hutsrt |= 0x0F;	/* use max head unload time */
	hlt = (hlt >= 256) ? 0 : (hlt >> 1);	/* encode head load time */
	specifycmd[2] = fcp->c_hlt = hlt << 1;	/* make room for DMA bit */
	return (fdc_docmd(fcp, specifycmd, 3));
}

int
fdcspdchange(struct fdcntlr *fcp, struct fcu_obj *fjp, int rpm)
{
	int	retcode = 0;
	uint_t	ddic;
	uchar_t	deselect = 0;
	uchar_t	ds_code;
	uchar_t	enable_code;
	uchar_t	save;

	if (((fcp->c_flags & FCFLG_DSOUT) == 0 && rpm <= fjp->fj_rotspd) ||
	    ((fcp->c_flags & FCFLG_DSOUT) && (fjp->fj_flags & FUNIT_3DMODE) &&
	    rpm > fjp->fj_rotspd)) {
		return (0);
	}

	FCERRPRINT(FDEP_L1, FDEM_SCHG,
	    (CE_CONT, "fdcspdchange: %d rpm\n", rpm));
	ASSERT(MUTEX_HELD(&fcp->c_dorlock));

	switch (fcp->c_chip) {
	default:
		break;
	case i82077:
		break;

	case PC87322:
		{
		uchar_t nscmodecmd[5] = {FO_MODE, 0x02, 0x00, 0xC8, 0x00};

		if (rpm > fjp->fj_rotspd) {
			nscmodecmd[3] ^= 0xC0;
			retcode = (fcp->c_flags ^ FCFLG_DSOUT) ||
			    (fjp->fj_flags ^ FUNIT_3DMODE);
			fcp->c_flags |= FCFLG_DSOUT;
			fjp->fj_flags |= FUNIT_3DMODE;
		} else {
			/* program DENSEL to default output */
			fcp->c_flags &= ~FCFLG_DSOUT;
			retcode = fjp->fj_flags & FUNIT_3DMODE;
			fjp->fj_flags &= ~FUNIT_3DMODE;
		}
		if (retcode && (fcp->c_digout & FD_DRSEL) == fcp->c_curunit) {
			/* de-select drive while changing speed */
			deselect = fcp->c_digout ^ FD_DRSEL;
			outb(fcp->c_regbase + FCR_DOR, deselect);
		}

		(void) fdc_docmd(fcp, nscmodecmd, 5);
		/*
		 * Ignored return. If failed, warning was issued by fdc_docmd.
		 */
		break;
		}

	case FDC37C665:
		enable_code = FSA_ENA5;
		goto SMC_config;

	case FDC37C666:
		enable_code = FSA_ENA6;
SMC_config:
		if (rpm > fjp->fj_rotspd) {
			/* force DENSEL output to active LOW */
			ds_code = FSB_DSHI;
			retcode = (fcp->c_flags ^ FCFLG_DSOUT) ||
			    (fjp->fj_flags ^ FUNIT_3DMODE);
			fcp->c_flags |= FCFLG_DSOUT;
			fjp->fj_flags |= FUNIT_3DMODE;
		} else {
			/* program DENSEL to default output */
			ds_code = 0;
			fcp->c_flags &= ~FCFLG_DSOUT;
			retcode = fjp->fj_flags & FUNIT_3DMODE;
			fjp->fj_flags &= ~FUNIT_3DMODE;
		}
		if (retcode && (fcp->c_digout & FD_DRSEL) == fcp->c_curunit) {
			/* de-select drive while changing speed */
			deselect = fcp->c_digout ^ FD_DRSEL;
			outb(fcp->c_regbase + FCR_DOR, deselect);
		}
		save = inb(fcp->c_regbase + FCR_SRA);

		/* enter configuration mode */
		ddic = ddi_enter_critical();
		outb(fcp->c_regbase + FCR_SRA, enable_code);
		outb(fcp->c_regbase + FCR_SRA, enable_code);
		ddi_exit_critical(ddic);

		outb(fcp->c_regbase + FCR_SRA, FSA_CR5);
		enable_code = inb(fcp->c_regbase + FCR_SRB) & FSB_DSDEF;
		/* update DENSEL mode bits */
		outb(fcp->c_regbase + FCR_SRB, enable_code | ds_code);

		/* exit configuration mode */
		outb(fcp->c_regbase + FCR_SRA, FSA_DISB);
		drv_usecwait(10);
		outb(fcp->c_regbase + FCR_SRA, save);
		break;
	}
	if (deselect)
		/* reselect drive */
		outb(fcp->c_regbase + FCR_DOR, fcp->c_digout);
	return (retcode);
}

static int
fdc_motorsm(struct fcu_obj *fjp, int input, int timeval)
{
	struct fdcntlr *fcp = fjp->fj_fdc;
	int unit = fjp->fj_unit & 3;
	int old_mstate;
	int rval = 0;
	uchar_t motorbit;

	ASSERT(MUTEX_HELD(&fcp->c_dorlock));
	old_mstate = fcp->c_mtrstate[unit];
	encode(motor_onbits, unit, &motorbit);

	switch (input) {
	case FMI_TIMER:		/* timer expired */
		fcp->c_motort[unit] = 0;
		switch (old_mstate) {
		case FMS_START:
		case FMS_DELAY:
			fcp->c_mtrstate[unit] = FMS_ON;
			break;
		case FMS_KILLST:
			fcp->c_motort[unit] = timeout(fdmotort, (void *)fjp,
			    drv_usectohz(1000000));
			fcp->c_mtrstate[unit] = FMS_IDLE;
			break;
		case FMS_IDLE:
			fcp->c_digout &= ~motorbit;
			outb(fcp->c_regbase + FCR_DOR, fcp->c_digout);
			fcp->c_mtrstate[unit] = FMS_OFF;
			fjp->fj_flags &= ~FUNIT_3DMODE;
			break;
		case 86:
			rval = -1;
			break;
		case FMS_OFF:
		case FMS_ON:
		default:
			rval = -2;
		}
		break;

	case FMI_STARTCMD:	/* start command */
		switch (old_mstate) {
		case FMS_IDLE:
			fcp->c_mtrstate[unit] = 86;
			mutex_exit(&fcp->c_dorlock);
			(void) untimeout(fcp->c_motort[unit]);
			mutex_enter(&fcp->c_dorlock);
			fcp->c_motort[unit] = 0;
			fcp->c_mtrstate[unit] = FMS_ON;
			break;
		case FMS_OFF:
			fcp->c_digout |= motorbit;
			outb(fcp->c_regbase + FCR_DOR, fcp->c_digout);

			/* start motor_spinup_timer */
			ASSERT(timeval > 0);
			fcp->c_motort[unit] = timeout(fdmotort,  (void *)fjp,
			    drv_usectohz(100000 * timeval));
			/* FALLTHROUGH */
		case FMS_KILLST:
			fcp->c_mtrstate[unit] = FMS_START;
			break;
		default:
			rval = -2;
		}
		break;

	case FMI_RSTARTCMD:	/* restart command */
		if (fcp->c_motort[unit] != 0) {
			fcp->c_mtrstate[unit] = 86;
			mutex_exit(&fcp->c_dorlock);
			(void) untimeout(fcp->c_motort[unit]);
			mutex_enter(&fcp->c_dorlock);
		}
		ASSERT(timeval > 0);
		fcp->c_motort[unit] = timeout(fdmotort, (void *)fjp,
		    drv_usectohz(100000 * timeval));
		fcp->c_mtrstate[unit] = FMS_START;
		break;

	case FMI_DELAYCMD:	/* delay command */
		if (fcp->c_motort[unit] == 0)
			fcp->c_motort[unit] = timeout(fdmotort,  (void *)fjp,
			    drv_usectohz(15000));
		fcp->c_mtrstate[unit] = FMS_DELAY;
		break;

	case FMI_IDLECMD:	/* idle command */
		switch (old_mstate) {
		case FMS_DELAY:
			fcp->c_mtrstate[unit] = 86;
			mutex_exit(&fcp->c_dorlock);
			(void) untimeout(fcp->c_motort[unit]);
			mutex_enter(&fcp->c_dorlock);
			/* FALLTHROUGH */
		case FMS_ON:
			ASSERT(timeval > 0);
			fcp->c_motort[unit] = timeout(fdmotort, (void *)fjp,
			    drv_usectohz(100000 * timeval));
			fcp->c_mtrstate[unit] = FMS_IDLE;
			break;
		case FMS_START:
			fcp->c_mtrstate[unit] = FMS_KILLST;
			break;
		default:
			rval = -2;
		}
		break;

	default:
		rval = -3;
	}
	if (rval) {
		FCERRPRINT(FDEP_L4, FDEM_EXEC, (CE_WARN,
		    "fdc_motorsm: unit %d  bad input %d or bad state %d",
		    (int)fjp->fj_unit, input, old_mstate));
#if 0
		cmn_err(CE_WARN,
		    "fdc_motorsm: unit %d  bad input %d or bad state %d",
		    (int)fjp->fj_unit, input, old_mstate);
		fcp->c_mtrstate[unit] = FMS_OFF;
		if (fcp->c_motort[unit] != 0) {
			mutex_exit(&fcp->c_dorlock);
			(void) untimeout(fcp->c_motort[unit]);
			mutex_enter(&fcp->c_dorlock);
			fcp->c_motort[unit] = 0;
		}
#endif
	} else
		FCERRPRINT(FDEP_L0, FDEM_EXEC,
		    (CE_CONT, "fdc_motorsm unit %d: input %d,  %d -> %d\n",
		    (int)fjp->fj_unit, input, old_mstate,
		    fcp->c_mtrstate[unit]));
	return (rval);
}

/*
 * fdmotort
 *	is called from timeout() when a motor timer has expired.
 */
static void
fdmotort(void *arg)
{
	struct fcu_obj *fjp = (struct fcu_obj *)arg;
	struct fdcntlr *fcp = fjp->fj_fdc;
	struct fdcsb *csb = &fcp->c_csb;
	int unit = fjp->fj_unit & 3;
	int mval;
	int newxstate = 0;

	mutex_enter(&fcp->c_dorlock);
	mval = fdc_motorsm(fjp, FMI_TIMER, 0);
	mutex_exit(&fcp->c_dorlock);
	if (mval < 0)
		return;

	mutex_enter(&fcp->c_lock);

	if ((fcp->c_flags & FCFLG_WAITING) &&
	    fcp->c_mtrstate[unit] == FMS_ON &&
	    (csb->csb_xstate == FXS_MTRON || csb->csb_xstate == FXS_HDST ||
	    csb->csb_xstate == FXS_DKCHGX)) {
		newxstate = fdc_statemach(fcp);
		if (newxstate == -1) {
			FCERRPRINT(FDEP_L3, FDEM_EXEC,
			    (CE_WARN,
			    "fdc_motort unit %d: motor ready but bad xstate",
			    (int)fjp->fj_unit));
			fcp->c_csb.csb_cmdstat = EIO;
		}
		if (newxstate == -1 || newxstate == FXS_END) {
			fcp->c_flags ^= FCFLG_WAITING;
			cv_signal(&fcp->c_iocv);
		}
	}
	mutex_exit(&fcp->c_lock);
}

/*
 * DMA interrupt service routine
 *
 *	Called by EISA dma interrupt service routine when buffer chaining
 *	is required.
 */

ddi_dma_cookie_t *
fdc_dmae_isr(struct fdcntlr *fcp)
{
	struct fdcsb *csb = &fcp->c_csb;
	off_t off;
	size_t len;

	if (csb->csb_dmahandle && !csb->csb_cmdstat) {
		if (++csb->csb_dmacurrcookie < csb->csb_dmacookiecnt) {
			ddi_dma_nextcookie(csb->csb_dmahandle,
			    &csb->csb_dmacookie);
			return (&csb->csb_dmacookie);
		} else if (++csb->csb_dmacurrwin < csb->csb_dmawincnt) {
			if (ddi_dma_getwin(csb->csb_dmahandle,
			    csb->csb_dmacurrwin, &off, &len,
			    &csb->csb_dmacookie,
			    &csb->csb_dmacookiecnt) != DDI_SUCCESS) {
				return (NULL);
			}
			csb->csb_dmacurrcookie = 0;
			return (&csb->csb_dmacookie);
		}
	} else
		cmn_err(CE_WARN, "fdc: unsolicited DMA interrupt");
	return (NULL);
}


/*
 * returns:
 *	0 if all ok,
 *	ENXIO - diskette not in drive
 *	ETIMEDOUT - for immediate operations that timed out
 *	EBUSY - if stupid chip is locked busy???
 *	ENOEXEC - for timeout during sending cmds to chip
 *
 * to sleep: set sleep
 * to check for disk changed: set change
 */
static int
fdc_exec(struct fdcntlr *fcp, int sleep, int change)
{
	struct ddi_dmae_req dmaereq;
	struct fcu_obj *fjp;
	struct fdcsb *csb;
	off_t off;
	size_t len;
	int unit;

	mutex_enter(&fcp->c_lock);
	FCERRPRINT(FDEP_L0, FDEM_EXEC,
	    (CE_CONT, "fdc_exec: sleep %x change %x\n", sleep, change));
	csb = &fcp->c_csb;
	unit = csb->csb_drive;
	fjp = fcp->c_unit[unit];

	if (csb->csb_opflags & CSB_OFINRPT) {
		if (*csb->csb_cmd == FO_RECAL)
			csb->csb_npcyl = 0;
		else if ((*csb->csb_cmd & ~FO_MFM) != FO_FRMT)
			csb->csb_npcyl =
			    csb->csb_cmd[2] * fjp->fj_chars->fdc_steps;
		csb->csb_xstate = FXS_START;
	} else
		csb->csb_xstate = FXS_DOIT;
	csb->csb_retrys = 0;
	csb->csb_ourtrys = 0;

	if (csb->csb_dmahandle) {
		/* ensure that entire format xfer is in one cookie */
		/*
		 * The change from  ddi_dma_buf/addr_setup() to
		 * ddi_dma_buf/addr_bind_handle() has already loaded
		 * the first DMA window and cookie.
		 */
		if ((*csb->csb_cmd & ~FO_MFM) == FO_FRMT &&
		    (4 * csb->csb_cmd[3]) != csb->csb_dmacookie.dmac_size) {
			mutex_exit(&fcp->c_lock);
			return (EINVAL);
		}
	}

retry:
	if (fcp->c_curunit != unit || !(fjp->fj_flags & FUNIT_CHAROK)) {
		fcp->c_curunit = unit;
		fjp->fj_flags |= FUNIT_CHAROK;
		if (fjp->fj_chars->fdc_transfer_rate == 417) {
			/* XXX hack for fdformat */
			/* fjp->fj_chars->fdc_transfer_rate == 500;	*/
			fjp->fj_attr->fda_rotatespd = 360;
		}
		if (fdcspecify(fcp, fjp->fj_chars->fdc_transfer_rate,
		    fjp->fj_drive->fdd_steprate, 40))
			cmn_err(CE_WARN,
			    "fdc_select: controller setup rejected "
			    "fdcntrl %p transfer rate %x step rate %x "
			    "head load time 40", (void*)fcp,
			    fjp->fj_chars->fdc_transfer_rate,
			    fjp->fj_drive->fdd_steprate);

		mutex_enter(&fcp->c_dorlock);
		if (fdcspdchange(fcp, fjp, fjp->fj_attr->fda_rotatespd)) {
			/* 3D drive requires 500 ms for speed change */
			(void) fdc_motorsm(fjp, FMI_RSTARTCMD, 5);
			/*
			 * Return value ignored - fdcmotort deals with failure.
			 */
		}
		mutex_exit(&fcp->c_dorlock);
	}

	/*
	 * If checking for disk_change is enabled
	 * (i.e. not seeking in fdresetchng),
	 * we sample the DSKCHG line to see if the diskette has wandered away.
	 */
	if (change && fdcsense_chng(fcp, unit)) {
		FCERRPRINT(FDEP_L3, FDEM_EXEC,
		    (CE_WARN, "diskette %d changed!!!", csb->csb_drive));
		fcp->c_unit[unit]->fj_flags |= FUNIT_CHANGED;
		/*
		 * If the diskette is still gone... so are we, adios!
		 */
		if (fdcheckdisk(fcp, unit)) {
			mutex_exit(&fcp->c_lock);

			/* VP/ix expects an EBUSY return here */
			if (*csb->csb_cmd == FO_SDRV) {
				return (EBUSY);
			}
			return (ENXIO);
		}
		/*
		 * delay to ensure that new diskette is up to speed
		 */
		mutex_enter(&fcp->c_dorlock);
		(void) fdc_motorsm(fjp, FMI_RSTARTCMD,
		    fjp->fj_drive->fdd_motoron);
		/*
		 * Return value ignored - fdcmotort deals with failure.
		 */
		mutex_exit(&fcp->c_dorlock);
	}

	/*
	 * gather some statistics
	 */
	switch (csb->csb_cmd[0] & 0x1f) {
	case FO_RDDAT:
		fcp->fdstats.rd++;
		break;
	case FO_WRDAT:
		fcp->fdstats.wr++;
		break;
	case FO_RECAL:
		fcp->fdstats.recal++;
		break;
	case FO_FRMT:
		fcp->fdstats.form++;
		break;
	default:
		fcp->fdstats.other++;
		break;
	}

	bzero(csb->csb_rslt, 10);
	csb->csb_cmdstat = 0;

	if (csb->csb_dmahandle) {
		bzero(&dmaereq, sizeof (struct ddi_dmae_req));
		dmaereq.der_command = (csb->csb_opflags & CSB_OFDMAWT) ?
		    DMAE_CMD_WRITE : DMAE_CMD_READ;
		/*
		 * setup for dma buffer chaining regardless of bus capability
		 */
		dmaereq.der_bufprocess = DMAE_BUF_CHAIN;
		dmaereq.proc = fdc_dmae_isr;
		dmaereq.procparms = (void *)fcp;
		if (ddi_dmae_prog(fcp->c_dip, &dmaereq, &csb->csb_dmacookie,
		    fcp->c_dmachan) != DDI_SUCCESS)
			cmn_err(CE_WARN, "fdc_exec: dmae prog failed, "
			    "dip %p, dmachan %x",
			    (void*)fcp->c_dip, fcp->c_dmachan);
	}

	if ((fdc_statemach(fcp) == FXS_DOWT) && !sleep) {
		/*
		 * If the operation has no results - then just return
		 */
		if (!csb->csb_nrslts) {
			mutex_exit(&fcp->c_lock);
			return (0);
		}
		/*
		 * this operation has no interrupt and an immediate result
		 * so wait for the results and stuff them into the csb
		 */
		if (fdc_statemach(fcp) == -1) {
			mutex_exit(&fcp->c_lock);
			return (EIO);
		}
	} else {
		fcp->c_flags |= FCFLG_WAITING;
		/*
		 * wait for completion interrupt
		 */
		while (fcp->c_flags & FCFLG_WAITING) {
			cv_wait(&fcp->c_iocv, &fcp->c_lock);
		}
	}

	/*
	 * See if there was an error detected, if so, fdrecover()
	 * will check it out and say what to do.
	 *
	 * Don't do this, though, if this was the Sense Drive Status
	 * or the Dump Registers command.
	 */
	if (csb->csb_cmdstat && *csb->csb_cmd != FO_SDRV) {
		/* if it can restarted OK, then do so, else return error */
		if (fdrecover(fcp)) {
			mutex_exit(&fcp->c_lock);
			return (EIO);
		}
		/* ASSUMES that cmd is still intact in csb */
		if (csb->csb_xstate == FXS_END)
			csb->csb_xstate = FXS_START;
		if (fdc_dma_attr.dma_attr_sgllen > 1 && csb->csb_dmahandle) {
			/*
			 * restarted read/write operation requires
			 * first DMA cookie of current window
			 */
			if (ddi_dma_getwin(csb->csb_dmahandle,
			    csb->csb_dmacurrwin, &off, &len,
			    &csb->csb_dmacookie,
			    &csb->csb_dmacookiecnt) != DDI_SUCCESS) {

				mutex_exit(&fcp->c_lock);
				return (EIO);
			}
			csb->csb_dmacurrcookie = 0;
		}
		goto retry;
	}
	/* things went ok */
	mutex_exit(&fcp->c_lock);
	return (0);
}

/*
 * fdcheckdisk
 *	called by fdc_exec to check if the disk is still there - do a seek
 *	then see if DSKCHG line went away; if so, diskette is in; else
 *	it's (still) out.
 */
int
fdcheckdisk(struct fdcntlr *fcp, int unit)
{
	struct fdcsb *csb = &fcp->c_csb;
	int newcyl;			/* where to seek for reset of DSKCHG */
	int rval;
	enum fxstate save_xstate;
	uchar_t save_cmd, save_cd1, save_npcyl;

	ASSERT(MUTEX_HELD(&fcp->c_lock));
	FCERRPRINT(FDEP_L1, FDEM_CHEK,
	    (CE_CONT, "fdcheckdisk unit %d\n", unit));

	if (fcp->c_curpcyl[unit])
		newcyl = fcp->c_curpcyl[unit] - 1;
	else
		newcyl = 1;

	save_cmd = *csb->csb_cmd;
	save_cd1 = csb->csb_cmd[1];
	save_npcyl = csb->csb_npcyl;
	save_xstate = csb->csb_xstate;

	*csb->csb_cmd = FO_SEEK;
	csb->csb_cmd[1] = (uchar_t)unit;
	csb->csb_npcyl = (uchar_t)newcyl;
	fcp->c_flags |= FCFLG_WAITING;

	if (fcp->c_mtrstate[unit] != FMS_ON && fcp->c_motort[unit] != 0)
		/*
		 * wait for motor to get up to speed,
		 * and let motor_timer issue seek cmd
		 */
		csb->csb_xstate = FXS_DKCHGX;
	else {
		/*
		 * motor is up to speed; issue seek cmd now
		 */
		csb->csb_xstate = FXS_SEEK;
		if (rval = fdcseek(fcp, unit, newcyl)) {
			/*
			 * any recal/seek errors are too serious to attend to
			 */
			FCERRPRINT(FDEP_L3, FDEM_CHEK,
			    (CE_WARN, "fdcheckdisk err %d", rval));
			fcp->c_flags ^= FCFLG_WAITING;
		}
	}
	/*
	 * wait for completion interrupt
	 * XXX This should be backed up with a watchdog timer!
	 */
	while (fcp->c_flags & FCFLG_WAITING) {
		cv_wait(&fcp->c_iocv, &fcp->c_lock);
	}

	/*
	 * if disk change still asserted, no diskette in drive!
	 */
	if (rval = fdcsense_chng(fcp, unit)) {
		FCERRPRINT(FDEP_L3, FDEM_CHEK,
		    (CE_WARN, "fdcheckdisk no disk %d", unit));
	}

	*csb->csb_cmd = save_cmd;
	csb->csb_cmd[1] = save_cd1;
	csb->csb_npcyl = save_npcyl;
	csb->csb_xstate = save_xstate;
	return (rval);
}

static int
fdrecover(struct fdcntlr *fcp)
{
	struct fcu_obj *fjp;
	struct fdcsb *csb = &fcp->c_csb;
	int residual;
	int unit;
	char *failure;

	FCERRPRINT(FDEP_L2, FDEM_RECO,
	    (CE_NOTE, "fdrecover unit %d", csb->csb_drive));

	unit = csb->csb_drive;
	fjp = fcp->c_unit[unit];
	if (fcp->c_flags & FCFLG_TIMEOUT) {
		fcp->c_flags ^= FCFLG_TIMEOUT;
		csb->csb_rslt[1] |= 0x08;
		FCERRPRINT(FDEP_L3, FDEM_RECO,
		    (CE_WARN, "fd unit %d: %s timed out", csb->csb_drive,
		    fdcmds[*csb->csb_cmd & 0x1f].cmdname));
	}

	if (csb->csb_status & S0_SEKEND)
		fcp->c_curpcyl[unit] = -1;

	switch (csb->csb_oldxs) {
	case FXS_RCAL:		/* recalibrate */
	case FXS_SEEK:		/* seek */
	case FXS_RESET:		/* cntlr reset */
		FCERRPRINT(FDEP_L4, FDEM_RECO, (CE_WARN,
		    "fd unit %d: %s error: st0=0x%x pcn=%d", csb->csb_drive,
		    fdcmds[*csb->csb_cmd & 0x1f].cmdname,
		    *csb->csb_rslt, csb->csb_rslt[1]));
		if (csb->csb_retrys++ < skretry &&
		    !(csb->csb_opflags & CSB_OFRAWIOCTL))
			return (0);
		break;

	case FXS_RDID:		/* read ID */
		if (!(csb->csb_status & S0_SEKEND))
			csb->csb_xstate = FXS_HDST;
		/* FALLTHROUGH */
	case FXS_DOIT:		/* original operation */
	case FXS_DOWT:		/* waiting on operation */
		if (csb->csb_opflags & (CSB_OFDMARD | CSB_OFDMAWT)) {
			if (ddi_dmae_getcnt(fcp->c_dip, fcp->c_dmachan,
			    &residual) != DDI_SUCCESS)
				cmn_err(CE_WARN,
				    "fdc_recover: dmae getcnt failed, "
				    "dip %p dmachan %x residual %x",
				    (void*)fcp->c_dip, fcp->c_dmachan,
				    residual);
			FCERRPRINT(FDEP_L2, FDEM_RECO,
			    (CE_NOTE,
			    "fd unit %d: %s error: "
			    "dma count=0x%lx residual=0x%x",
			    csb->csb_drive,
			    fdcmds[*csb->csb_cmd & 0x1f].cmdname,
			    csb->csb_dmacookie.dmac_size, residual));
		}
		if (csb->csb_rslt[1] == S1_OVRUN)
			/*
			 * handle retries of over/underrun
			 * with a secondary retry counter
			 */
			if (++csb->csb_ourtrys <= OURUN_TRIES) {
				FCERRPRINT(FDEP_L2, FDEM_RECO,
				    (CE_NOTE,
				    "fd unit %d: %s error: over/under-run",
				    csb->csb_drive,
				    fdcmds[*csb->csb_cmd & 0x1f].cmdname));
				return (0);
			} else
				/*
				 * count 1 set of over/underruns
				 * as 1 primary retry effort
				 */
				csb->csb_ourtrys = 0;

		if ((fjp->fj_flags & (FUNIT_UNLABELED | FUNIT_LABELOK)) &&
		    !(csb->csb_opflags & CSB_OFRAWIOCTL)) {
			/*
			 * device is open so keep trying and
			 * gather statistics on errors
			 */
			if (csb->csb_rslt[1] & S1_CRCER)
				fcp->fdstats.de++;
			if (csb->csb_rslt[1] & S1_OVRUN)
				fcp->fdstats.run++;
			if (csb->csb_rslt[1] & (S1_NODATA | S1_MADMK))
				fcp->fdstats.bfmt++;
			if (csb->csb_rslt[1] & 0x08)
				fcp->fdstats.to++;

			/*
			 * if we have not run out of retries, return 0
			 */
			if (csb->csb_retrys++ < csb->csb_maxretry &&
			    (*csb->csb_cmd & ~FO_MFM) != FO_FRMT) {
				if (csb->csb_opflags &
				    (CSB_OFDMARD | CSB_OFDMAWT)) {
					FCERRPRINT(FDEP_L4, FDEM_RECO,
					    (CE_WARN,
					    "fd unit %d: %s error: "
					    "st0=0x%x st1=0x%x st2=0x%x",
					    csb->csb_drive,
					    fdcmds[*csb->csb_cmd &
					    0x1f].cmdname,
					    *csb->csb_rslt, csb->csb_rslt[1],
					    csb->csb_rslt[2]));
				}
				if ((csb->csb_retrys & 1) &&
				    csb->csb_xstate == FXS_END)
					csb->csb_xstate = FXS_DOIT;
				else if (csb->csb_retrys == 3)
					csb->csb_xstate = FXS_RESTART;
				return (0);
			}
			if (csb->csb_rslt[1] & S1_CRCER)
				failure = "crc error";
			else if (csb->csb_rslt[1] & S1_OVRUN)
				failure = "over/under-run";
			else if (csb->csb_rslt[1] & (S1_NODATA | S1_MADMK))
				failure = "bad format";
			else if (csb->csb_rslt[1] & 0x08)
				failure = "timeout";
			else
				failure = "failed";
			cmn_err(CE_NOTE, "!fd unit %d: %s %s (%x %x %x)",
			    csb->csb_drive,
			    fdcmds[*csb->csb_cmd & 0x1f].cmdname, failure,
			    *csb->csb_rslt, csb->csb_rslt[1], csb->csb_rslt[2]);
		} else {
			FCERRPRINT(FDEP_L2, FDEM_RECO,
			    (CE_NOTE, "fd unit %d: %s failed (%x %x %x)",
			    csb->csb_drive,
			    fdcmds[*csb->csb_cmd & 0x1f].cmdname,
			    *csb->csb_rslt, csb->csb_rslt[1],
			    csb->csb_rslt[2]));
		}
		break;

	default:
		FCERRPRINT(FDEP_L4, FDEM_RECO, (CE_WARN,
		    "fd unit %d: %s failed: st0=0x%x st1=0x%x st2=0x%x",
		    csb->csb_drive, fdcmds[*csb->csb_cmd & 0x1f].cmdname,
		    *csb->csb_rslt, csb->csb_rslt[1], csb->csb_rslt[2]));
		break;
	}
	return (1);
}


/*	Autovector Interrupt Entry Point	*/
static uint_t
fdc_intr(caddr_t arg)
{
	struct fdcntlr *fcp = (struct fdcntlr *)arg;
	struct fdcsb *csb;
	off_t off;
	size_t blklen;
	int drive;
	int newstate;
	int pendstate;
	int rval = DDI_DMA_DONE;
	int state;
	int maxspin = 10;

	csb = &fcp->c_csb;

	mutex_enter(&fcp->c_lock);
	if (fcp->c_suspended) {
		mutex_exit(&fcp->c_lock);
		return (DDI_INTR_UNCLAIMED);
	}

	/*
	 * Wait for the RQM bit to be set, or until we've tested it
	 * a bunch of times (which may imply this isn't our interrupt).
	 */
	state = inb(fcp->c_regbase + FCR_MSR);
	pendstate = state & (MS_RQM | MS_DIO | MS_CB);
	while (((pendstate & MS_RQM) == 0) && (maxspin-- > 0)) {
		/* Small pause in between reading the status port */
		drv_usecwait(10);
		/* Reread the status port */
		state = inb(fcp->c_regbase + FCR_MSR);
		pendstate = state & (MS_RQM | MS_DIO | MS_CB);
	}
	FCERRPRINT(FDEP_L0, FDEM_INTR,
	    (CE_CONT, "fdc_intr unit %d: xstate=%d MSR=0x%x\n",
	    csb->csb_drive, csb->csb_xstate, state));

	/*
	 * If there is an operation outstanding AND the controller is ready
	 * to receive a command or send us the result of a command (OR if the
	 * controller is ready to accept a new command), AND if
	 * someone has been waiting for a command to finish AND (if no unit
	 * is BUSY OR if the unit that we're waiting for is BUSY (i.e. it's in
	 * the middle of a seek/recalibrate)) then this interrupt is for us.
	 */
	if ((pendstate == (MS_RQM | MS_DIO | MS_CB) || pendstate == MS_RQM) &&
	    (fcp->c_flags & FCFLG_WAITING) &&
	    (!(state & 0x0f) || ((1 << csb->csb_drive) & state))) {
		/*
		 * Remove one of the conditions for entering this code.
		 * The state_machine will release the c_lock if it
		 * calls untimeout()
		 */
		fcp->c_flags ^= FCFLG_WAITING;

		if ((newstate = fdc_statemach(fcp)) == -1) {
			/* restore waiting flag */
			fcp->c_flags |= FCFLG_WAITING;
			mutex_exit(&fcp->c_lock);
			return (DDI_INTR_CLAIMED);
		}

		if (fcp->c_intrstat)
			KIOIP->intrs[KSTAT_INTR_HARD]++;
		if (newstate == FXS_END) {

			if (csb->csb_dmahandle && !csb->csb_cmdstat &&
				/*
				 * read/write operation may have multiple DMA
				 * cookies: process next one
				 */
			    ((csb->csb_dmacurrcookie <
			    (csb->csb_dmacookiecnt - 1)) ||
			    (csb->csb_dmacurrwin) < (csb->csb_dmawincnt - 1))) {
				/*
				 * read/write operation requires another
				 * DMA cookie: process next one
				 */

				if (++csb->csb_dmacurrcookie <
				    csb->csb_dmacookiecnt) {
					ddi_dma_nextcookie(csb->csb_dmahandle,
					    &csb->csb_dmacookie);
				} else if (++csb->csb_dmacurrwin <
				    csb->csb_dmawincnt) {
					if (ddi_dma_getwin(csb->csb_dmahandle,
					    csb->csb_dmacurrwin, &off, &blklen,
					    &csb->csb_dmacookie,
					    &csb->csb_dmacookiecnt) !=
					    DDI_SUCCESS) {
						cmn_err(CE_WARN,
						    "fdc_intr: "
						    "dma getwin failed");
					}
					csb->csb_dmacurrcookie = 0;
				}

				if (ddi_dmae_prog(fcp->c_dip, NULL,
				    &csb->csb_dmacookie, fcp->c_dmachan) !=
				    DDI_SUCCESS)
					cmn_err(CE_WARN,
					    "fdc_intr: dmae prog failed, "
					    "dip %p dmachannel %x",
					    (void*)fcp->c_dip,
					    fcp->c_dmachan);

				/*
				 * status of last operation has disk
				 * address for continuation
				 */
				csb->csb_cmd[2] = csb->csb_rslt[3];
				csb->csb_cmd[3] = csb->csb_rslt[4];
				csb->csb_cmd[4] = csb->csb_rslt[5];
				csb->csb_cmd[1] = (csb->csb_cmd[1] & ~0x04) |
				    (csb->csb_cmd[3] << 2);

				csb->csb_xstate = FXS_START;
				(void) fdc_statemach(fcp);
				/*
				 * Ignored return.  If failed, warning already
				 * posted.  Returned state irrelevant.
				 */
				/* restore waiting flag */
				fcp->c_flags |= FCFLG_WAITING;
				goto fi_exit;
			}
			if (rval != DDI_DMA_DONE)
				csb->csb_cmdstat = EIO;
			/*
			 * somebody's waiting for completion of fdcntlr/csb,
			 * wake them
			 */
			cv_signal(&fcp->c_iocv);
		}
		else
			/* restore waiting flag */
			fcp->c_flags |= FCFLG_WAITING;
fi_exit:
		mutex_exit(&fcp->c_lock);
		return (DDI_INTR_CLAIMED);
	}

	if (state & MS_RQM) {
		(void) fdcsense_int(fcp, &drive, NULL);
		/*
		 * Ignored return - senser state already saved
		 */
		FCERRPRINT(FDEP_L4, FDEM_INTR,
		    (CE_WARN, "fdc_intr unit %d: nobody sleeping 0x%x",
		    drive, state));
	} else {
		FCERRPRINT(FDEP_L4, FDEM_INTR,
		    (CE_WARN, "fdc_intr: nobody sleeping on %d 0x%x",
		    csb->csb_drive, state));
	}
	/*
	 * This should probably be protected, but, what the
	 * heck...the cost isn't worth the accuracy for this
	 * statistic.
	 */
	if (fcp->c_intrstat)
		KIOIP->intrs[KSTAT_INTR_SPURIOUS]++;
	mutex_exit(&fcp->c_lock);
	return (DDI_INTR_UNCLAIMED);
}

/*
 * fdwatch
 *	is called from timeout() when a floppy operation timer has expired.
 */
static void
fdwatch(void *arg)
{
	struct fdcntlr *fcp = (struct fdcntlr *)arg;
	struct fdcsb *csb;

	mutex_enter(&fcp->c_lock);

	if (fcp->c_timeid == 0) {
		/*
		 * fdc_intr got here first, ergo, no timeout condition..
		 */
		mutex_exit(&fcp->c_lock);
		return;
	}

	if (fcp->c_flags & FCFLG_WAITING) {
		if (ddi_dmae_stop(fcp->c_dip, fcp->c_dmachan) != DDI_SUCCESS)
			cmn_err(CE_WARN, "fdwatch: dmae stop failed, "
			    "dip %p, dmachan %x",
			    (void*)fcp->c_dip, fcp->c_dmachan);
		csb = &fcp->c_csb;
		FCERRPRINT(FDEP_L3, FDEM_WATC,
		    (CE_WARN, "fdcwatch unit %d: xstate = %d",
		    csb->csb_drive, csb->csb_xstate));
		drv_usecwait(50);

		if (inb(fcp->c_regbase + FCR_MSR) != MS_RQM) {
			/*
			 * cntlr is still busy, so reset it
			 */
			csb->csb_xstate = FXS_KILL;
			(void) fdc_statemach(fcp);
			/*
			 * Ignored return.  If failed, warning already
			 * posted.  Returned state irrelevant.
			 */
		} else {
			csb->csb_xstate = FXS_END;
			fcp->c_timeid = 0;
			fcp->c_flags ^= FCFLG_WAITING;
			cv_signal(&fcp->c_iocv);
		}
		csb->csb_cmdstat = EIO;
		fcp->c_flags |= FCFLG_TIMEOUT;
	} else {
		FCERRPRINT(FDEP_L4, FDEM_INTR,
		    (CE_WARN, "fdcwatch: not sleeping for unit %d",
		    fcp->c_csb.csb_drive));
	}
	if (fcp->c_intrstat)
		KIOIP->intrs[KSTAT_INTR_WATCHDOG]++;
	mutex_exit(&fcp->c_lock);
}


static int
fdc_statemach(struct fdcntlr *fcp)
{
	struct fcu_obj *fjp;
	struct fdcsb *csb = &fcp->c_csb;
	int backoff;
	clock_t time;
	int unit;

	ASSERT(MUTEX_HELD(&fcp->c_lock));

	unit = csb->csb_drive;
	fjp = fcp->c_unit[unit];

	csb->csb_oldxs = csb->csb_xstate;
	switch (csb->csb_xstate) {

	case FXS_START:		/* start of operation */
		ASSERT(fcp->c_timeid == 0);
		time = drv_usectohz(100000 * (unsigned int)csb->csb_timer);
		if (time == 0)
			time = drv_usectohz(2000000);
		fcp->c_timeid = timeout(fdwatch, (void *)fcp, time);

		if (fcp->c_mtrstate[unit] == FMS_START) {
			/*
			 * wait for motor to get up to speed
			 */
			csb->csb_xstate = FXS_MTRON;
			break;
		}
		/* FALLTHROUGH */

	case FXS_MTRON:		/* motor is at speed */
		if (fcp->c_mtrstate[unit] != FMS_ON) {
			/* how did we get here ?? */
			cmn_err(CE_WARN, "fdc: selected but motor off");
			return (-1);
		}
		if (fcp->c_curpcyl[unit] != -1 && *csb->csb_cmd != FO_RECAL)
			goto nxs_seek;
		recalcmd[1] = (uchar_t)unit;
		if (fdc_docmd(fcp, recalcmd, 2) == -1) {
			/* cntlr did not accept command bytes */
			fdcquiesce(fcp);
			csb->csb_cmdstat = EIO;
			csb->csb_xstate = FXS_RESET;
			break;
		}
		fcp->c_sekdir[unit] = 0;
		csb->csb_xstate = FXS_RCAL;
		break;

	case FXS_RCAL:		/* forced recalibrate is complete */
#if 0	/* #ifdef _VPIX */
	/* WARNING: this code breaks SPARC compatibility */
		if (csb->csb_opflags & CSB_OFRAWIOCTL &&
		    *csb->csb_cmd == FO_RECAL) {
			fcp->c_curpcyl[unit] = 0;
			csb->csb_status = 0;
			goto nxs_cmpl;
		}
#endif
		(void) fdc_docmd(fcp, &senseintcmd, 1);
		/*
		 * Ignored return. If failed, warning was issued by fdc_docmd.
		 * fdc_results retrieves the controller/drive status
		 */
		(void) fdc_result(fcp, csb->csb_rslt, 2);
		/*
		 * Ignored return. If failed, warning was issued by fdc_result.
		 * Actual results checked below
		 */
		if ((csb->csb_status = ((*csb->csb_rslt ^ S0_SEKEND) &
		    (S0_ICMASK | S0_SEKEND | S0_ECHK | S0_NOTRDY))) != 0) {
			FCERRPRINT(FDEP_L3, FDEM_EXEC,
			    (CE_WARN, "fdc_statemach unit %d: recal result %x",
			    csb->csb_drive, *csb->csb_rslt));
			fdcquiesce(fcp);
			csb->csb_cmdstat = EIO;
			csb->csb_xstate = FXS_RESET;
			break;
		}
		if (unit != (*csb->csb_rslt & 3) || csb->csb_rslt[1]) {
			csb->csb_status = S0_SEKEND;
			goto nxs_cmpl;
		}
		fcp->c_curpcyl[unit] = csb->csb_rslt[1];
		if (*csb->csb_cmd == FO_RECAL)
			goto nxs_cmpl;
nxs_seek:
		if (*csb->csb_cmd != FO_SEEK &&
		    csb->csb_npcyl == fcp->c_curpcyl[unit])
			goto nxs_doit;
		fcp->c_sekdir[unit] = csb->csb_npcyl - fcp->c_curpcyl[unit];
		/* FALLTHROUGH */

	case FXS_DKCHGX:	/* reset Disk-Change latch */
		(void) fdcseek(fcp, csb->csb_cmd[1], csb->csb_npcyl);
		/*
		 * Ignored return.  If command rejected, warnig already posted
		 * by fdc_docmd().
		 */
		csb->csb_xstate = FXS_SEEK;
		break;

	case FXS_RESTART:	/* special restart of read/write operation */
		ASSERT(fcp->c_timeid == 0);
		time = drv_usectohz(100000 * csb->csb_timer);
		if (time == 0)
			time = drv_usectohz(2000000);
		fcp->c_timeid = timeout(fdwatch, (void *)fcp, time);

		if (fcp->c_mtrstate[unit] != FMS_ON) {
			cmn_err(CE_WARN, "fdc: selected but motor off");
			return (-1);
		}
		if ((csb->csb_npcyl == 0 || fcp->c_sekdir[unit] >= 0) &&
		    (int)csb->csb_cmd[2] < (fjp->fj_chars->fdc_ncyl - 1))
			backoff = csb->csb_npcyl + 1;
		else
			backoff = csb->csb_npcyl - 1;
		(void) fdcseek(fcp, csb->csb_cmd[1], backoff);
		/*
		 * Ignored return.  If command rejected, warnig already posted
		 * by fdc_docmd().
		 */
		csb->csb_xstate = FXS_RESEEK;
		break;

	case FXS_RESEEK:	/* seek to backoff-cyl complete */
		(void) fdc_docmd(fcp, &senseintcmd, 1);
		/*
		 * Ignored return. If failed, warning was issued by fdc_docmd.
		 * fdc_results retrieves the controller/drive status
		 */
		(void) fdc_result(fcp, csb->csb_rslt, 2);
		/*
		 * Ignored return. If failed, warning was issued by fdc_result.
		 * Actual results checked below
		 */
		if ((csb->csb_status = ((*csb->csb_rslt ^ S0_SEKEND) &
		    (S0_ICMASK | S0_SEKEND | S0_ECHK | S0_NOTRDY))) != 0)
			goto nxs_cmpl;
		(void) fdcseek(fcp, csb->csb_cmd[1], csb->csb_npcyl);
		/*
		 * Ignored return.  If command rejected, warnig already posted
		 * by fdc_docmd().
		 */
		csb->csb_xstate = FXS_SEEK;
		break;

	case FXS_SEEK:		/* seek complete */
#if 0	/* #ifdef _VPIX */
	/* WARNING: this code breaks SPARC compatibility and */
	/* rawioctls in fdformat */
		if (csb->csb_opflags & CSB_OFRAWIOCTL) {
			fcp->c_curpcyl[unit] = csb->csb_npcyl;
			csb->csb_status = 0;
			goto nxs_cmpl;
		}
#endif
		(void) fdc_docmd(fcp, &senseintcmd, 1);
		/*
		 * Ignored return. If failed, warning was issued by fdc_docmd.
		 * fdc_results retrieves the controller/drive status
		 */
		(void) fdc_result(fcp, csb->csb_rslt, 2);
		/*
		 * Ignored return. If failed, warning was issued by fdc_result.
		 * Actual results checked below
		 */
		if ((csb->csb_status = ((*csb->csb_rslt ^ S0_SEKEND) &
		    (S0_ICMASK | S0_SEKEND | S0_ECHK | S0_NOTRDY))) != 0)
			goto nxs_cmpl;
		if (unit != (*csb->csb_rslt & 3) ||
		    csb->csb_rslt[1] != csb->csb_npcyl) {
			csb->csb_status = S0_SEKEND;
			goto nxs_cmpl;
		};
		fcp->c_curpcyl[unit] = csb->csb_rslt[1];
		/* use motor_timer to delay for head settle */
		mutex_enter(&fcp->c_dorlock);
		(void) fdc_motorsm(fjp, FMI_DELAYCMD,
		    fjp->fj_drive->fdd_headsettle / 1000);
		/*
		 * Return value ignored - fdcmotort deals with failure.
		 */
		mutex_exit(&fcp->c_dorlock);
		csb->csb_xstate = FXS_HDST;
		break;

	case FXS_HDST:		/* head settle */
		if (*csb->csb_cmd == FO_SEEK)
			goto nxs_cmpl;
		if ((*csb->csb_cmd & ~FO_MFM) == FO_FRMT)
			goto nxs_doit;
		fdcreadid(fcp, csb);
		csb->csb_xstate = FXS_RDID;
		break;

	case FXS_RDID:		/* read ID complete */
		(void) fdc_result(fcp, csb->csb_rslt, 7);
		/*
		 * Ignored return. If failed, warning was issued by fdc_result.
		 * Actual results checked below
		 */
		if ((csb->csb_status = (*csb->csb_rslt &
		    (S0_ICMASK | S0_ECHK | S0_NOTRDY))) != 0)
			goto nxs_cmpl;
		if (csb->csb_cmd[2] != csb->csb_rslt[3]) {
			/* at wrong logical cylinder */
			csb->csb_status = S0_SEKEND;
			goto nxs_cmpl;
		};
		goto nxs_doit;

	case FXS_DOIT:		/* do original operation */
		ASSERT(fcp->c_timeid == 0);
		time = drv_usectohz(100000 * csb->csb_timer);
		if (time == 0)
			time = drv_usectohz(2000000);
		fcp->c_timeid = timeout(fdwatch, (void *)fcp, time);
nxs_doit:
		if (fdc_docmd(fcp, csb->csb_cmd, csb->csb_ncmds) == -1) {
			/* cntlr did not accept command bytes */
			fdcquiesce(fcp);
			csb->csb_xstate = FXS_RESET;
			csb->csb_cmdstat = EIO;
			break;
		}
		csb->csb_xstate = FXS_DOWT;
		break;

	case FXS_DOWT:		/* operation complete */
		(void) fdc_result(fcp, csb->csb_rslt, csb->csb_nrslts);
		/*
		 * Ignored return. If failed, warning was issued by fdc_result.
		 * Actual results checked below.
		 */
		if (*csb->csb_cmd == FO_SDRV) {
			csb->csb_status =
			    (*csb->csb_rslt ^ (S3_DRRDY | S3_2SIDE)) &
			    ~(S3_HEAD | S3_UNIT);
		} else {
			csb->csb_status = *csb->csb_rslt &
			    (S0_ICMASK | S0_ECHK | S0_NOTRDY);
		}
nxs_cmpl:
		if (csb->csb_status)
			csb->csb_cmdstat = EIO;
		csb->csb_xstate = FXS_END;

		/*  remove watchdog timer if armed and not already triggered */
		if (fcp->c_timeid != 0) {
			timeout_id_t timeid;
			timeid = fcp->c_timeid;
			fcp->c_timeid = 0;
			mutex_exit(&fcp->c_lock);
			(void) untimeout(timeid);
			mutex_enter(&fcp->c_lock);
		}
		break;

	case FXS_KILL:		/* quiesce cntlr by reset */
		fdcquiesce(fcp);
		fcp->c_timeid = timeout(fdwatch, (void *)fcp,
		    drv_usectohz(2000000));
		csb->csb_xstate = FXS_RESET;
		break;

	case FXS_RESET:		/* int from reset */
		for (unit = 0; unit < NFDUN; unit++) {
			(void) fdcsense_int(fcp, NULL, NULL);
			fcp->c_curpcyl[unit] = -1;
		}
		if (fcp->c_timeid != 0) {
			timeout_id_t timeid;
			timeid = fcp->c_timeid;
			fcp->c_timeid = 0;
			mutex_exit(&fcp->c_lock);
			(void) untimeout(timeid);
			mutex_enter(&fcp->c_lock);
		}
		csb->csb_xstate = FXS_END;
		break;

	default:
		cmn_err(CE_WARN, "fdc: statemach, unknown state");
		return (-1);
	}
	FCERRPRINT(FDEP_L1, FDEM_EXEC,
	    (CE_CONT, "fdc_statemach unit %d: %d -> %d\n",
	    csb->csb_drive, csb->csb_oldxs, csb->csb_xstate));
	return (csb->csb_xstate);
}


/*
 * routine to program a command into the floppy disk controller.
 */
int
fdc_docmd(struct fdcntlr *fcp, uchar_t *oplistp, uchar_t count)
{
	int ntries;

	ASSERT(count >= 1);
	FCERRPRINT(FDEP_L0, FDEM_EXEC,
	    (CE_CONT, "fdc_docmd: %x %x %x %x %x %x %x %x %x\n",
	    oplistp[0], oplistp[1], oplistp[2], oplistp[3], oplistp[4],
	    oplistp[5], oplistp[6], oplistp[7], oplistp[8]));

	do {
		ntries = FDC_RQM_RETRY;
		do {
			if ((inb(fcp->c_regbase + FCR_MSR) & (MS_RQM|MS_DIO))
			    == MS_RQM)
				break;
			else
				drv_usecwait(1);
		} while (--ntries);
		if (ntries == 0) {
			FCERRPRINT(FDEP_L3, FDEM_EXEC,
			    (CE_WARN, "fdc_docmd: ctlr not ready"));
			return (-1);
		}
		outb(fcp->c_regbase + FCR_DATA, *oplistp++);
		drv_usecwait(16);	/* See comment in fdc_result() */
	} while (--count);
	return (0);
}


/*
 * Routine to return controller/drive status information.
 * The diskette-controller data-register is read the
 * requested number of times and the results are placed in
 * consecutive memory locations starting at the passed
 * address.
 */
int
fdc_result(struct fdcntlr *fcp, uchar_t *rsltp, uchar_t rcount)
{
	int ntries;
	uchar_t *abresultp = rsltp;
	uchar_t stat;
	int laxative = 7;

	ntries = 10 * FDC_RQM_RETRY;
	do {
		do {
			if ((inb(fcp->c_regbase + FCR_MSR) &
			    (MS_RQM | MS_DIO)) == (MS_RQM | MS_DIO))
				break;
			else
				drv_usecwait(10);
		} while (--ntries);
		if (!ntries) {
			FCERRPRINT(FDEP_L3, FDEM_EXEC,
			    (CE_WARN, "fdc_result: ctlr not ready"));
			return (-2);
		}
		*rsltp++ = inb(fcp->c_regbase + FCR_DATA);

		/*
		 * The PRM suggests waiting for 14.5 us.
		 * Adding a bit more to cover the case of bad calibration
		 * of drv_usecwait().
		 */
		drv_usecwait(16);
		ntries = FDC_RQM_RETRY;
	} while (--rcount);
	while ((inb(fcp->c_regbase + FCR_MSR) & MS_CB) && laxative--) {
		FCERRPRINT(FDEP_L3, FDEM_EXEC,
		    (CE_WARN, "fdc_result: ctlr still busy"));
		/*
		 * try to complete Result phase by purging
		 * result bytes queued for reading
		 */
		*abresultp = S0_IVCMD;
		do {
			stat = inb(fcp->c_regbase + FCR_MSR) &
			    (MS_RQM | MS_DIO);
			if (stat == MS_RQM) {
				/*
				 * Result phase is complete
				 * but did we get the results corresponding to
				 * the command we think we executed?
				 */
				return (-1);
			}
			if (stat == (MS_RQM | MS_DIO))
				break;
			else
				drv_usecwait(10);
		} while (--ntries);
		if (!ntries || !laxative) {
			FCERRPRINT(FDEP_L3, FDEM_EXEC,
			    (CE_WARN,
			    "fdc_result: ctlr still busy and not ready"));
			return (-3);
		}
		(void) inb(fcp->c_regbase + FCR_DATA);

		drv_usecwait(16);	/* See comment above */
		ntries = FDC_RQM_RETRY;
	}
	return (0);
}

/*
 *  Function: get_unit()
 *
 *  Assumptions:  ioaddr is either 0x3f0 or 0x370
 */
static int
get_unit(dev_info_t *dip, int *cntrl_num)
{
	int ioaddr;

	if (get_ioaddr(dip, &ioaddr) != DDI_SUCCESS)
		return (DDI_FAILURE);

	switch (ioaddr) {
	case 0x3f0:
		*cntrl_num = 0;
		break;

	case 0x370:
		*cntrl_num = 1;
		break;

	default:
		return (DDI_FAILURE);
	}
	return (DDI_SUCCESS);
}

static int
get_ioaddr(dev_info_t *dip, int *ioaddr)
{
	int reglen, nregs, i;
	int status = DDI_FAILURE;
	struct {
		int bustype;
		int base;
		int size;
	} *reglist;

	if (ddi_getlongprop(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "reg", (caddr_t)&reglist, &reglen) != DDI_PROP_SUCCESS) {
		cmn_err(CE_WARN, "fdc: reg property not found");
		return (DDI_FAILURE);
	}

	nregs = reglen / sizeof (*reglist);
	for (i = 0; i < nregs; i++) {
		if (reglist[i].bustype == 1) {
			*ioaddr = reglist[i].base;
			status = DDI_SUCCESS;
			break;
		}
	}
	kmem_free(reglist, reglen);

	if (status == DDI_SUCCESS) {
		if (*ioaddr == 0x3f2 || *ioaddr == 0x372) {
			/*
			 * Some BIOS's (ASUS is one) don't include first
			 * two IO ports in the floppy controller resources.
			 */

			*ioaddr -= 2; /* step back to 0x3f0 or 0x370 */

			/*
			 * It would be nice to update the regs property as well
			 * so device pathname contains 3f0 instead of 3f2, but
			 * updating the regs now won't have this effect as that
			 * component of the device pathname has already been
			 * constructed by the ISA nexus driver.
			 *
			 * reglist[i].base -= 2;
			 * reglist[i].size += 2;
			 * dev = makedevice(ddi_driver_major(dip), 0);
			 * ddi_prop_update_int_array(dev, dip, "reg",
			 *    (int *)reglist, reglen / sizeof (int));
			 */
		}
	}

	return (status);
}
