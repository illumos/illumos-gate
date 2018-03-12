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
 *
 * Copyright 2018 RackTop Systems.
 */

#include <sys/types.h>
#include <sys/modctl.h>
#include <sys/debug.h>
#include <sys/promif.h>
#include <sys/pci.h>
#include <sys/errno.h>
#include <sys/open.h>
#include <sys/uio.h>
#include <sys/cred.h>
#include <sys/cpu.h>
#include "ata_common.h"
#include "ata_disk.h"
#include "atapi.h"
#include "ata_blacklist.h"
#include "sil3xxx.h"

/*
 * Solaris Entry Points.
 */

static	int	ata_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static	int	ata_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);
static	int	ata_bus_ctl(dev_info_t *d, dev_info_t *r, ddi_ctl_enum_t o,
			void *a, void *v);
static	uint_t	ata_intr(caddr_t arg);

/*
 * GHD Entry points
 */

static	int	ata_get_status(void *hba_handle, void *intr_status);
static	void	ata_process_intr(void *hba_handle, void *intr_status);
static	int	ata_hba_start(void *handle, gcmd_t *gcmdp);
static	void	ata_hba_complete(void *handle, gcmd_t *gcmdp, int do_callback);
static	int	ata_timeout_func(void *hba_handle, gcmd_t  *gcmdp,
			gtgt_t *gtgtp, gact_t  action, int calltype);

/*
 * Local Function Prototypes
 */
static int ata_prop_lookup_int(dev_t match_dev, dev_info_t *dip,
		    uint_t flags, char *name, int defvalue);
static	int	ata_ctlr_fsm(uchar_t fsm_func, ata_ctl_t *ata_ctlp,
			ata_drv_t *ata_drvp, ata_pkt_t *ata_pktp,
				int *DoneFlgp);
static	void	ata_destroy_controller(dev_info_t *dip);
static	int	ata_drive_type(uchar_t drvhd,
			ddi_acc_handle_t io_hdl1, caddr_t ioaddr1,
			ddi_acc_handle_t io_hdl2, caddr_t ioaddr2,
			struct ata_id *ata_id_bufp);
static	ata_ctl_t *ata_init_controller(dev_info_t *dip);
static	ata_drv_t *ata_init_drive(ata_ctl_t *ata_ctlp,
			uchar_t targ, uchar_t lun);
static	int	ata_init_drive_pcidma(ata_ctl_t *ata_ctlp, ata_drv_t *ata_drvp,
			dev_info_t *tdip);
static	int	ata_flush_cache(ata_ctl_t *ata_ctlp, ata_drv_t *ata_drvp);
static	void	ata_init_pciide(dev_info_t *dip, ata_ctl_t *ata_ctlp);
static	int	ata_reset_bus(ata_ctl_t *ata_ctlp);
static	int	ata_setup_ioaddr(dev_info_t *dip,
			ddi_acc_handle_t *iohandle1, caddr_t *ioaddr1p,
			ddi_acc_handle_t *iohandle2, caddr_t *ioaddr2p,
			ddi_acc_handle_t *bm_hdlp, caddr_t *bm_addrp);
static	int	ata_software_reset(ata_ctl_t *ata_ctlp);
static	int	ata_start_arq(ata_ctl_t *ata_ctlp, ata_drv_t *ata_drvp,
			ata_pkt_t *ata_pktp);
static	int	ata_strncmp(char *p1, char *p2, int cnt);
static	void	ata_uninit_drive(ata_drv_t *ata_drvp);

static	int	ata_check_pciide_blacklist(dev_info_t *dip, uint_t flags);
static	int	ata_check_revert_to_defaults(ata_drv_t *ata_drvp);
static  void	ata_show_transfer_mode(ata_ctl_t *, ata_drv_t *);
static	int	ata_spec_init_controller(dev_info_t *dip);

static void	ata_init_pm(dev_info_t *);
static int	ata_suspend(dev_info_t *);
static int	ata_resume(dev_info_t *);
static int	ata_power(dev_info_t *, int, int);
static int	ata_change_power(dev_info_t *, uint8_t);
static int	ata_is_pci(dev_info_t *);
static void	ata_disable_DMA(ata_drv_t *ata_drvp);
static int	ata_check_dma_mode(ata_drv_t *ata_drvp);

/*
 * Local static data
 */
static	void	*ata_state;

static	tmr_t	ata_timer_conf; /* single timeout list for all instances */
static	int	ata_watchdog_usec = 100000; /* check timeouts every 100 ms */

int	ata_hba_start_watchdog = 1000;
int	ata_process_intr_watchdog = 1000;
int	ata_reset_bus_watchdog = 1000;


/*
 * Use local or framework power management
 */

#ifdef	ATA_USE_AUTOPM
#define	ATA_BUSY_COMPONENT(d, c)	((void)pm_busy_component(d, c))
#define	ATA_IDLE_COMPONENT(d, c)	((void)pm_idle_component(d, c))
#define	ATA_RAISE_POWER(d, c, l)	pm_raise_power(d, c, l)
#define	ATA_LOWER_POWER(d, c, l)	pm_lower_power(d, c, l)
#else
#define	ATA_BUSY_COMPONENT(d, c)
#define	ATA_IDLE_COMPONENT(d, c)
#define	ATA_RAISE_POWER(d, c, l)	ata_power(d, c, l)
#define	ATA_LOWER_POWER(d, c, l)	ata_power(d, c, l)
#endif
/*
 * number of seconds to wait during various operations
 */
int	ata_flush_delay = 5 * 1000000;
uint_t	ata_set_feature_wait = 4 * 1000000;
uint_t	ata_flush_cache_wait = 60 * 1000000;	/* may take a long time */

/*
 * Change this for SFF-8070i support. Currently SFF-8070i is
 * using a field in the IDENTIFY PACKET DEVICE response which
 * already seems to be in use by some vendor's drives. I suspect
 * SFF will either move their laslun field or provide a reliable
 * way to validate it.
 */
int	ata_enable_atapi_luns = FALSE;

/*
 * set this to disable all DMA requests
 */
int	ata_dma_disabled = FALSE;

/*
 * set this to TRUE to enable storing the IDENTIFY DEVICE result in the
 * "ata" or "atapi" property.
 */
int	ata_id_debug = FALSE;

/*
 * set this to TRUE to enable logging device-capability data
 */
int	ata_capability_data = FALSE;

/*
 * DMA selection message pointers
 */
char *ata_cntrl_DMA_sel_msg;
char *ata_dev_DMA_sel_msg;

/*
 * bus nexus operations
 */
static	struct bus_ops	 ata_bus_ops;
static	struct bus_ops	*scsa_bus_ops_p;

/* ARGSUSED */
static int
ata_open(dev_t *devp, int flag, int otyp, cred_t *cred_p)
{
	if (ddi_get_soft_state(ata_state, getminor(*devp)) == NULL)
		return (ENXIO);

	return (0);
}

/*
 * The purpose of this function is to pass the ioaddress of the controller
 * to the caller, specifically used for upgrade from pre-pciide
 * to pciide nodes
 */
/* ARGSUSED */
static int
ata_read(dev_t dev, struct uio *uio_p, cred_t *cred_p)
{
	ata_ctl_t *ata_ctlp;
	char	buf[18];
	long len;

	ata_ctlp = ddi_get_soft_state(ata_state, getminor(dev));

	if (ata_ctlp == NULL)
		return (ENXIO);

	(void) sprintf(buf, "%p\n", (void *) ata_ctlp->ac_ioaddr1);

	len = strlen(buf) - uio_p->uio_offset;
	len = min(uio_p->uio_resid,  len);
	if (len <= 0)
		return (0);

	return (uiomove((caddr_t)(buf + uio_p->uio_offset), len,
	    UIO_READ, uio_p));
}

int
ata_devo_reset(
	dev_info_t *dip,
	ddi_reset_cmd_t cmd)
{
	ata_ctl_t *ata_ctlp;
	ata_drv_t *ata_drvp;
	int	   instance;
	int	   i;
	int	   rc;
	int	   flush_okay;

	if (cmd != DDI_RESET_FORCE)
		return (0);

	instance = ddi_get_instance(dip);
	ata_ctlp = ddi_get_soft_state(ata_state, instance);

	if (!ata_ctlp)
		return (0);

	/*
	 * reset ATA drives and flush the write cache of any drives
	 */
	flush_okay = TRUE;
	for (i = 0; i < ATA_MAXTARG; i++) {
		if ((ata_drvp = CTL2DRV(ata_ctlp, i, 0)) == 0)
			continue;
		/* Don't revert to defaults for certain IBM drives */
		if ((ata_drvp->ad_flags & AD_DISK) != 0 &&
		    ((ata_drvp->ad_flags & AD_NORVRT) == 0)) {
			/* Enable revert to defaults when reset */
			(void) ata_set_feature(ata_ctlp, ata_drvp,
			    ATSF_ENA_REVPOD, 0);
		}

		/*
		 * skip flush cache if device type is cdrom
		 *
		 * notes: the structure definitions for ata_drvp->ad_id are
		 * defined for the ATA IDENTIFY_DEVICE, but if AD_ATAPI is set
		 * the struct holds data for the ATAPI IDENTIFY_PACKET_DEVICE
		 */
		if (!IS_CDROM(ata_drvp)) {

			/*
			 * Try the ATA/ATAPI flush write cache command
			 */
			rc = ata_flush_cache(ata_ctlp, ata_drvp);
			ADBG_WARN(("ata_flush_cache %s\n",
			    rc ? "okay" : "failed"));

			if (!rc)
				flush_okay = FALSE;
		}


		/*
		 * do something else if flush cache not supported
		 */
	}

	/*
	 * just busy wait if any drive doesn't support FLUSH CACHE
	 */
	if (!flush_okay)
		drv_usecwait(ata_flush_delay);
	return (0);
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
ata_quiesce(dev_info_t *dip)
{
#ifdef ATA_DEBUG
	/*
	 * Turn off debugging
	 */
	ata_debug = 0;
#endif

	return (ata_devo_reset(dip, DDI_RESET_FORCE));
}


static struct cb_ops ata_cb_ops = {
	ata_open,		/* open */
	nulldev,		/* close */
	nodev,			/* strategy */
	nodev,			/* print */
	nodev,			/* dump */
	ata_read,		/* read */
	nodev,			/* write */
	nodev,			/* ioctl */
	nodev,			/* devmap */
	nodev,			/* mmap */
	nodev,			/* segmap */
	nochpoll,		/* chpoll */
	ddi_prop_op,		/* prop_op */
	NULL,			/* stream info */
	D_MP,			/* driver compatibility flag */
	CB_REV,			/* cb_ops revision */
	nodev,			/* aread */
	nodev			/* awrite */
};

static struct dev_ops	ata_ops = {
	DEVO_REV,		/* devo_rev, */
	0,			/* refcnt  */
	ddi_getinfo_1to1,	/* info */
	nulldev,		/* identify */
	NULL,			/* probe */
	ata_attach,		/* attach */
	ata_detach,		/* detach */
	ata_devo_reset,		/* reset */
	&ata_cb_ops,		/* driver operations */
	NULL,			/* bus operations */
	ata_power,		/* power */
	ata_quiesce		/* quiesce */
};

/* driver loadable module wrapper */
static struct modldrv modldrv = {
	&mod_driverops,		/* Type of module. This one is a driver */
	"ATA AT-bus attachment disk controller Driver",	/* module name */
	&ata_ops,					/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modldrv, NULL
};

#ifdef ATA_DEBUG
int	ata_debug_init = FALSE;
int	ata_debug_attach = FALSE;

int	ata_debug = ADBG_FLAG_ERROR
		/* | ADBG_FLAG_ARQ */
		/* | ADBG_FLAG_INIT */
		/* | ADBG_FLAG_TRACE */
		/* | ADBG_FLAG_TRANSPORT */
		/* | ADBG_FLAG_WARN */
		;
#endif

int
_init(void)
{
	int err;

#ifdef ATA_DEBUG
	if (ata_debug_init)
		debug_enter("\nATA _INIT\n");
#endif

	if ((err = ddi_soft_state_init(&ata_state, sizeof (ata_ctl_t), 0)) != 0)
		return (err);

	if ((err = scsi_hba_init(&modlinkage)) != 0) {
		ddi_soft_state_fini(&ata_state);
		return (err);
	}

	/* save pointer to SCSA provided bus_ops struct */
	scsa_bus_ops_p = ata_ops.devo_bus_ops;

	/* make a copy of SCSA bus_ops */
	ata_bus_ops = *(ata_ops.devo_bus_ops);

	/*
	 * Modify our bus_ops to call our routines.  Our implementation
	 * will determine if the device is ATA or ATAPI/SCSA and react
	 * accordingly.
	 */
	ata_bus_ops.bus_ctl = ata_bus_ctl;

	/* patch our bus_ops into the dev_ops struct */
	ata_ops.devo_bus_ops = &ata_bus_ops;

	if ((err = mod_install(&modlinkage)) != 0) {
		scsi_hba_fini(&modlinkage);
		ddi_soft_state_fini(&ata_state);
	}

	/*
	 * Initialize the per driver timer info.
	 */

	ghd_timer_init(&ata_timer_conf, drv_usectohz(ata_watchdog_usec));

	return (err);
}

int
_fini(void)
{
	int err;

	if ((err = mod_remove(&modlinkage)) == 0) {
		ghd_timer_fini(&ata_timer_conf);
		scsi_hba_fini(&modlinkage);
		ddi_soft_state_fini(&ata_state);
	}

	return (err);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}


/*
 *
 * driver attach entry point
 *
 */

static int
ata_attach(
	dev_info_t *dip,
	ddi_attach_cmd_t cmd)
{
	ata_ctl_t	*ata_ctlp;
	ata_drv_t	*ata_drvp;
	ata_drv_t	*first_drvp = NULL;
	uchar_t		 targ;
	uchar_t		 lun;
	uchar_t		 lastlun;
	int		 atapi_count = 0;
	int		 disk_count = 0;

	ADBG_TRACE(("ata_attach entered\n"));
#ifdef ATA_DEBUG
	if (ata_debug_attach)
		debug_enter("\nATA_ATTACH\n\n");
#endif

	switch (cmd) {
	case DDI_ATTACH:
		break;
	case DDI_RESUME:
		return (ata_resume(dip));
	default:
		return (DDI_FAILURE);
	}

	/* initialize controller */
	ata_ctlp = ata_init_controller(dip);

	if (ata_ctlp == NULL)
		goto errout;

	mutex_enter(&ata_ctlp->ac_ccc.ccc_hba_mutex);

	/* initialize drives */

	for (targ = 0; targ < ATA_MAXTARG; targ++) {

		ata_drvp = ata_init_drive(ata_ctlp, targ, 0);
		if (ata_drvp == NULL)
			continue;

		if (first_drvp == NULL)
			first_drvp = ata_drvp;

		if (ATAPIDRV(ata_drvp)) {
			atapi_count++;
			lastlun = ata_drvp->ad_id.ai_lastlun;
		} else {
			disk_count++;
			lastlun = 0;
		}

		/*
		 * LUN support is currently disabled. Check with SFF-8070i
		 * before enabling.
		 */
		if (!ata_enable_atapi_luns)
			lastlun = 0;

		/* Initialize higher LUNs, if there are any */
		for (lun = 1; lun <= lastlun && lun < ATA_MAXLUN; lun++) {
			if ((ata_drvp =
			    ata_init_drive(ata_ctlp, targ, lun)) != NULL) {
				ata_show_transfer_mode(ata_ctlp, ata_drvp);
			}
		}
	}

	if ((atapi_count == 0) && (disk_count == 0)) {
		ADBG_WARN(("ata_attach: no drives detected\n"));
		goto errout1;
	}

	/*
	 * Always make certain that a valid drive is selected so
	 * that routines which poll the status register don't get
	 * confused by non-existent drives.
	 */
	ddi_put8(ata_ctlp->ac_iohandle1, ata_ctlp->ac_drvhd,
	    first_drvp->ad_drive_bits);
	ata_nsecwait(400);

	/*
	 * make certain the drive selected
	 */
	if (!ata_wait(ata_ctlp->ac_iohandle2, ata_ctlp->ac_ioaddr2,
	    0, ATS_BSY, 5000000)) {
		ADBG_ERROR(("ata_attach: select failed\n"));
	}

	/*
	 * initialize atapi/ata_dsk modules if we have at least
	 * one drive of that type.
	 */

	if (atapi_count) {
		if (!atapi_attach(ata_ctlp))
			goto errout1;
		ata_ctlp->ac_flags |= AC_ATAPI_INIT;
	}

	if (disk_count) {
		if (!ata_disk_attach(ata_ctlp))
			goto errout1;
		ata_ctlp->ac_flags |= AC_DISK_INIT;
	}

	/*
	 * make certain the interrupt and error latches are clear
	 */
	if (ata_ctlp->ac_pciide) {

		int instance = ddi_get_instance(dip);
		if (ddi_create_minor_node(dip, "control", S_IFCHR, instance,
		    DDI_PSEUDO, 0) != DDI_SUCCESS) {
			goto errout1;
		}

		(void) ata_pciide_status_clear(ata_ctlp);

	}

	/*
	 * enable the interrupt handler and drop the mutex
	 */
	ata_ctlp->ac_flags |= AC_ATTACHED;
	mutex_exit(&ata_ctlp->ac_ccc.ccc_hba_mutex);

	ata_init_pm(dip);

	ddi_report_dev(dip);
	return (DDI_SUCCESS);

errout1:
	mutex_exit(&ata_ctlp->ac_ccc.ccc_hba_mutex);
errout:
	(void) ata_detach(dip, DDI_DETACH);
	return (DDI_FAILURE);
}

/* driver detach entry point */

static int
ata_detach(
	dev_info_t *dip,
	ddi_detach_cmd_t cmd)
{
	ata_ctl_t *ata_ctlp;
	ata_drv_t *ata_drvp;
	int	   instance;
	int	   i;
	int	   j;

	ADBG_TRACE(("ata_detach entered\n"));

	switch (cmd) {
	case DDI_DETACH:
		break;
	case DDI_SUSPEND:
		return (ata_suspend(dip));
	default:
		return (DDI_FAILURE);
	}

	instance = ddi_get_instance(dip);
	ata_ctlp = ddi_get_soft_state(ata_state, instance);

	if (!ata_ctlp)
		return (DDI_SUCCESS);

	if (ata_ctlp->ac_pm_support) {
		ATA_BUSY_COMPONENT(dip, 0);
		if (ata_ctlp->ac_pm_level != PM_LEVEL_D0) {
			if (ATA_RAISE_POWER(dip, 0, PM_LEVEL_D0) !=
			    DDI_SUCCESS) {
				ATA_IDLE_COMPONENT(dip, 0);
				return (DDI_FAILURE);
			}
		}
		(void) ddi_prop_remove(DDI_DEV_T_NONE, dip, "pm-components");
	}
	ata_ctlp->ac_flags &= ~AC_ATTACHED;

	/* destroy ata module */
	if (ata_ctlp->ac_flags & AC_DISK_INIT)
		ata_disk_detach(ata_ctlp);

	/* destroy atapi module */
	if (ata_ctlp->ac_flags & AC_ATAPI_INIT)
		atapi_detach(ata_ctlp);

	ddi_remove_minor_node(dip, NULL);

	/* destroy drives */
	for (i = 0; i < ATA_MAXTARG; i++) {
		for (j = 0; j < ATA_MAXLUN; j++) {
			ata_drvp = CTL2DRV(ata_ctlp, i, j);
			if (ata_drvp != NULL)
				ata_uninit_drive(ata_drvp);
		}
	}

	if (ata_ctlp->ac_iohandle1)
		ddi_regs_map_free(&ata_ctlp->ac_iohandle1);
	if (ata_ctlp->ac_iohandle2)
		ddi_regs_map_free(&ata_ctlp->ac_iohandle2);
	if (ata_ctlp->ac_bmhandle)
		ddi_regs_map_free(&ata_ctlp->ac_bmhandle);

	/* destroy controller */
	ata_destroy_controller(dip);

	ddi_prop_remove_all(dip);

	return (DDI_SUCCESS);
}

/*
 * Nexus driver bus_ctl entry point
 */
/*ARGSUSED*/
static int
ata_bus_ctl(
	dev_info_t *d,
	dev_info_t *r,
	ddi_ctl_enum_t o,
	void *a,
	void *v)
{
	dev_info_t *tdip;
	int	target_type;
	int	rc;
	char	*bufp;

	ADBG_TRACE(("ata_bus_ctl entered\n"));

	switch (o) {

	case DDI_CTLOPS_SIDDEV:
		return (DDI_FAILURE);

	case DDI_CTLOPS_IOMIN:

		/*
		 * Since we use PIO, we return a minimum I/O size of
		 * one byte.  This will need to be updated when we
		 * implement DMA support
		 */

		*((int *)v) = 1;
		return (DDI_SUCCESS);

	case DDI_CTLOPS_DMAPMAPC:
	case DDI_CTLOPS_REPORTINT:
	case DDI_CTLOPS_REGSIZE:
	case DDI_CTLOPS_NREGS:
	case DDI_CTLOPS_SLAVEONLY:
	case DDI_CTLOPS_AFFINITY:
	case DDI_CTLOPS_POKE:
	case DDI_CTLOPS_PEEK:

		/* These ops shouldn't be called by a target driver */
		ADBG_ERROR(("ata_bus_ctl: %s%d: invalid op (%d) from %s%d\n",
		    ddi_driver_name(d), ddi_get_instance(d), o,
		    ddi_driver_name(r), ddi_get_instance(r)));

		return (DDI_FAILURE);

	case DDI_CTLOPS_REPORTDEV:
	case DDI_CTLOPS_INITCHILD:
	case DDI_CTLOPS_UNINITCHILD:

		/* these require special handling below */
		break;

	default:
		return (ddi_ctlops(d, r, o, a, v));
	}

	/* get targets dip */

	if (o == DDI_CTLOPS_INITCHILD || o == DDI_CTLOPS_UNINITCHILD)
		tdip = (dev_info_t *)a;
	else
		tdip = r;

	/*
	 * XXX - Get class of target
	 *   Before the "class" entry in a conf file becomes
	 *   a real property, we use an additional property
	 *   tentatively called "class_prop".  We will require that
	 *   new classes (ie. direct) export "class_prop".
	 *   SCSA target drivers will not have this property, so
	 *   no property implies SCSA.
	 */
	if ((ddi_prop_lookup_string(DDI_DEV_T_ANY, tdip, DDI_PROP_DONTPASS,
	    "class", &bufp) == DDI_PROP_SUCCESS) ||
	    (ddi_prop_lookup_string(DDI_DEV_T_ANY, tdip, DDI_PROP_DONTPASS,
	    "class_prop", &bufp) == DDI_PROP_SUCCESS)) {
		if (strcmp(bufp, "dada") == 0)
			target_type = ATA_DEV_DISK;
		else if (strcmp(bufp, "scsi") == 0)
			target_type = ATA_DEV_ATAPI;
		else {
			ADBG_WARN(("ata_bus_ctl: invalid target class %s\n",
			    bufp));
			ddi_prop_free(bufp);
			return (DDI_FAILURE);
		}
		ddi_prop_free(bufp);
	} else {
		target_type = ATA_DEV_ATAPI; /* no class prop, assume SCSI */
	}

	if (o == DDI_CTLOPS_INITCHILD) {
		int	instance = ddi_get_instance(d);
		ata_ctl_t *ata_ctlp = ddi_get_soft_state(ata_state, instance);
		ata_drv_t *ata_drvp;
		int	targ;
		int	lun;
		int	drive_type;
		char	*disk_prop;
		char	*class_prop;

		if (ata_ctlp == NULL) {
			ADBG_WARN(("ata_bus_ctl: failed to find ctl struct\n"));
			return (DDI_FAILURE);
		}

		/* get (target,lun) of child device */

		targ = ddi_prop_get_int(DDI_DEV_T_ANY, tdip, DDI_PROP_DONTPASS,
		    "target", -1);
		if (targ == -1) {
			ADBG_WARN(("ata_bus_ctl: failed to get targ num\n"));
			return (DDI_FAILURE);
		}

		lun = ddi_prop_get_int(DDI_DEV_T_ANY, tdip, DDI_PROP_DONTPASS,
		    "lun", 0);

		if ((targ < 0) || (targ >= ATA_MAXTARG) ||
		    (lun < 0) || (lun >= ATA_MAXLUN)) {
			return (DDI_FAILURE);
		}

		ata_drvp = CTL2DRV(ata_ctlp, targ, lun);

		if (ata_drvp == NULL)
			return (DDI_FAILURE);	/* no drive */

		/* get type of device */

		if (ATAPIDRV(ata_drvp))
			drive_type = ATA_DEV_ATAPI;
		else
			drive_type = ATA_DEV_DISK;

		/*
		 * Check for special handling when child driver is
		 * cmdk (which morphs to the correct interface)
		 */
		if (strcmp(ddi_get_name(tdip), "cmdk") == 0) {

			if ((target_type == ATA_DEV_DISK) &&
			    (target_type != drive_type))
				return (DDI_FAILURE);

			target_type = drive_type;

			if (drive_type == ATA_DEV_ATAPI) {
				class_prop = "scsi";
			} else {
				disk_prop = "dadk";
				class_prop = "dada";

				if (ndi_prop_update_string(DDI_DEV_T_NONE, tdip,
				    "disk", disk_prop) != DDI_PROP_SUCCESS) {
					ADBG_WARN(("ata_bus_ctl: failed to "
					    "create disk prop\n"));
					return (DDI_FAILURE);
				}
			}

			if (ndi_prop_update_string(DDI_DEV_T_NONE, tdip,
			    "class_prop", class_prop) != DDI_PROP_SUCCESS) {
				ADBG_WARN(("ata_bus_ctl: failed to "
				    "create class prop\n"));
				return (DDI_FAILURE);
			}
		}

		/* Check that target class matches the device */

		if (target_type != drive_type)
			return (DDI_FAILURE);

		/* save pointer to drive struct for ata_disk_bus_ctl */
		ddi_set_driver_private(tdip, ata_drvp);

		/*
		 * Determine whether to enable DMA support for this drive.  This
		 * check is deferred to this point so that the various dma
		 * properties could reside on the devinfo node should finer
		 * grained dma control be required.
		 */
		if (ata_drvp->ad_pciide_dma == ATA_DMA_UNINITIALIZED) {
			ata_drvp->ad_pciide_dma =
			    ata_init_drive_pcidma(ata_ctlp, ata_drvp, tdip);
			ata_show_transfer_mode(ata_ctlp, ata_drvp);
		}
	}

	if (target_type == ATA_DEV_ATAPI) {
		rc = scsa_bus_ops_p->bus_ctl(d, r, o, a, v);
	} else {
		rc = ata_disk_bus_ctl(d, r, o, a, v);
	}

	return (rc);
}

/*
 *
 * GHD ccc_hba_complete callback
 *
 */

/* ARGSUSED */
static void
ata_hba_complete(
	void *hba_handle,
	gcmd_t *gcmdp,
	int do_callback)
{
	ata_drv_t *ata_drvp;
	ata_pkt_t *ata_pktp;

	ADBG_TRACE(("ata_hba_complete entered\n"));

	ata_drvp = GCMD2DRV(gcmdp);
	ata_pktp = GCMD2APKT(gcmdp);
	if (ata_pktp->ap_complete)
		(*ata_pktp->ap_complete)(ata_drvp, ata_pktp,
		    do_callback);
}

/* GHD ccc_timeout_func callback */

/* ARGSUSED */
static int
ata_timeout_func(
	void	*hba_handle,
	gcmd_t	*gcmdp,
	gtgt_t	*gtgtp,
	gact_t	 action,
	int	 calltype)
{
	ata_ctl_t *ata_ctlp;
	ata_pkt_t *ata_pktp;
	ata_drv_t *ata_drvp;

	ADBG_TRACE(("ata_timeout_func entered\n"));

	ata_ctlp = (ata_ctl_t *)hba_handle;

	if (gcmdp != NULL)
		ata_pktp = GCMD2APKT(gcmdp);
	else
		ata_pktp = NULL;

	switch (action) {
	case GACTION_EARLY_ABORT:
		/* abort before request was started */
		if (ata_pktp != NULL) {
			ata_pktp->ap_flags |= AP_ABORT;
		}
		ghd_complete(&ata_ctlp->ac_ccc, gcmdp);
		return (TRUE);

	case GACTION_EARLY_TIMEOUT:
		/* timeout before request was started */
		if (ata_pktp != NULL) {
			ata_pktp->ap_flags |= AP_TIMEOUT;
		}
		ghd_complete(&ata_ctlp->ac_ccc, gcmdp);
		return (TRUE);

	case GACTION_RESET_TARGET:
		/*
		 * Reset a device is not supported. Resetting a specific
		 * device can't be done at all to an ATA device and if
		 * you send a RESET to an ATAPI device you have to
		 * reset the whole bus to make certain both devices
		 * on the bus stay in sync regarding which device is
		 * the currently selected one.
		 */
		return (FALSE);

	case GACTION_RESET_BUS:
		/*
		 * Issue bus reset and reinitialize both drives.
		 * But only if this is a timed-out request. Target
		 * driver reset requests are ignored because ATA
		 * and ATAPI devices shouldn't be gratuitously reset.
		 * Also disable DMA if it is a CF device.
		 */
		if (gcmdp == NULL)
			break;
		ata_drvp = GCMD2DRV(gcmdp);
		if (ata_drvp != NULL)
			if (ata_drvp->ad_id.ai_config == ATA_ID_CF_TO_ATA)
				ata_disable_DMA(ata_drvp);
		return (ata_reset_bus(ata_ctlp));
	default:
		break;
	}
	return (FALSE);
}

/*
 *
 * Initialize controller's soft-state structure
 *
 */

static ata_ctl_t *
ata_init_controller(
	dev_info_t *dip)
{
	ata_ctl_t *ata_ctlp;
	int	   instance;
	caddr_t	   ioaddr1;
	caddr_t	   ioaddr2;

	ADBG_TRACE(("ata_init_controller entered\n"));

	instance = ddi_get_instance(dip);

	/* allocate controller structure */
	if (ddi_soft_state_zalloc(ata_state, instance) != DDI_SUCCESS) {
		ADBG_WARN(("ata_init_controller: soft_state_zalloc failed\n"));
		return (NULL);
	}

	ata_ctlp = ddi_get_soft_state(ata_state, instance);

	if (ata_ctlp == NULL) {
		ADBG_WARN(("ata_init_controller: failed to find "
		    "controller struct\n"));
		return (NULL);
	}

	/*
	 * initialize per-controller data
	 */
	ata_ctlp->ac_dip = dip;
	ata_ctlp->ac_arq_pktp = kmem_zalloc(sizeof (ata_pkt_t), KM_SLEEP);

	/*
	 * map the device registers
	 */
	if (!ata_setup_ioaddr(dip, &ata_ctlp->ac_iohandle1, &ioaddr1,
	    &ata_ctlp->ac_iohandle2, &ioaddr2,
	    &ata_ctlp->ac_bmhandle, &ata_ctlp->ac_bmaddr)) {
		(void) ata_detach(dip, DDI_DETACH);
		return (NULL);
	}

	ADBG_INIT(("ata_init_controller: ioaddr1 = 0x%p, ioaddr2 = 0x%p\n",
	    ioaddr1, ioaddr2));

	/*
	 * Do ARQ setup
	 */
	atapi_init_arq(ata_ctlp);

	/*
	 * Do PCI-IDE setup
	 */
	ata_init_pciide(dip, ata_ctlp);

	/*
	 * port addresses associated with ioaddr1
	 */
	ata_ctlp->ac_ioaddr1	= ioaddr1;
	ata_ctlp->ac_data	= (ushort_t *)ioaddr1 + AT_DATA;
	ata_ctlp->ac_error	= (uchar_t *)ioaddr1 + AT_ERROR;
	ata_ctlp->ac_feature	= (uchar_t *)ioaddr1 + AT_FEATURE;
	ata_ctlp->ac_count	= (uchar_t *)ioaddr1 + AT_COUNT;
	ata_ctlp->ac_sect	= (uchar_t *)ioaddr1 + AT_SECT;
	ata_ctlp->ac_lcyl	= (uchar_t *)ioaddr1 + AT_LCYL;
	ata_ctlp->ac_hcyl	= (uchar_t *)ioaddr1 + AT_HCYL;
	ata_ctlp->ac_drvhd	= (uchar_t *)ioaddr1 + AT_DRVHD;
	ata_ctlp->ac_status	= (uchar_t *)ioaddr1 + AT_STATUS;
	ata_ctlp->ac_cmd	= (uchar_t *)ioaddr1 + AT_CMD;

	/*
	 * port addresses associated with ioaddr2
	 */
	ata_ctlp->ac_ioaddr2	= ioaddr2;
	ata_ctlp->ac_altstatus	= (uchar_t *)ioaddr2 + AT_ALTSTATUS;
	ata_ctlp->ac_devctl	= (uchar_t *)ioaddr2 + AT_DEVCTL;

	/*
	 * If AC_BSY_WAIT needs to be set  for laptops that do
	 * suspend/resume but do not correctly wait for the busy bit to
	 * drop after a resume.
	 */
	ata_ctlp->ac_timing_flags = ddi_prop_get_int(DDI_DEV_T_ANY,
	    dip, DDI_PROP_DONTPASS, "timing_flags", 0);
	/*
	 * get max transfer size, default to 256 sectors
	 */
	ata_ctlp->ac_max_transfer = ddi_prop_get_int(DDI_DEV_T_ANY,
	    dip, DDI_PROP_DONTPASS, "max_transfer", 0x100);
	if (ata_ctlp->ac_max_transfer < 1)
		ata_ctlp->ac_max_transfer = 1;
	if (ata_ctlp->ac_max_transfer > 0x100)
		ata_ctlp->ac_max_transfer = 0x100;

	/*
	 * Get the standby timer value
	 */
	ata_ctlp->ac_standby_time = ddi_prop_get_int(DDI_DEV_T_ANY,
	    dip, DDI_PROP_DONTPASS, "standby", -1);

	/*
	 * If this is a /pci/pci-ide instance check to see if
	 * it's supposed to be attached as an /isa/ata
	 */
	if (ata_ctlp->ac_pciide) {
		static char prop_buf[] = "SUNW-ata-ffff-isa";
		int addr1 = (intptr_t)ioaddr1;


		if (addr1 < 0 || addr1 > 0xffff) {
			(void) ata_detach(dip, DDI_DETACH);
			return (NULL);
		}
		(void) sprintf(prop_buf, "SUNW-ata-%04x-isa",
		    addr1);
		if (ddi_prop_exists(DDI_DEV_T_ANY, ddi_root_node(),
		    DDI_PROP_DONTPASS, prop_buf)) {
			(void) ata_detach(dip, DDI_DETACH);
			return (NULL);
		}
	}

	/* Init controller specific stuff */
	(void) ata_spec_init_controller(dip);

	/*
	 * initialize GHD
	 */

	GHD_WAITQ_INIT(&ata_ctlp->ac_ccc.ccc_waitq, NULL, 1);

	if (!ghd_register("ata", &ata_ctlp->ac_ccc, dip, 0, ata_ctlp,
	    atapi_ccballoc, atapi_ccbfree,
	    ata_pciide_dma_sg_func, ata_hba_start,
	    ata_hba_complete, ata_intr,
	    ata_get_status, ata_process_intr, ata_timeout_func,
	    &ata_timer_conf, NULL)) {
		(void) ata_detach(dip, DDI_DETACH);
		return (NULL);
	}

	ata_ctlp->ac_flags |= AC_GHD_INIT;
	return (ata_ctlp);
}

/* destroy a controller */

static void
ata_destroy_controller(
	dev_info_t *dip)
{
	ata_ctl_t *ata_ctlp;
	int	instance;

	ADBG_TRACE(("ata_destroy_controller entered\n"));

	instance = ddi_get_instance(dip);
	ata_ctlp = ddi_get_soft_state(ata_state, instance);

	if (ata_ctlp == NULL)
		return;

	/* destroy ghd */
	if (ata_ctlp->ac_flags & AC_GHD_INIT)
		ghd_unregister(&ata_ctlp->ac_ccc);

	/* free the pciide buffer (if any) */
	ata_pciide_free(ata_ctlp);

	/* destroy controller struct */
	kmem_free(ata_ctlp->ac_arq_pktp, sizeof (ata_pkt_t));
	ddi_soft_state_free(ata_state, instance);

}


/*
 *
 * initialize a drive
 *
 */

static ata_drv_t *
ata_init_drive(
	ata_ctl_t	*ata_ctlp,
	uchar_t		targ,
	uchar_t		lun)
{
	static	char	 nec_260[]	= "NEC CD-ROM DRIVE";
	ata_drv_t *ata_drvp;
	struct ata_id	*aidp;
	char	buf[80];
	int	drive_type;
	int	i;
	int	valid_version = 0;

	ADBG_TRACE(("ata_init_drive entered, targ = %d, lun = %d\n",
	    targ, lun));

	/* check if device already exists */

	ata_drvp = CTL2DRV(ata_ctlp, targ, lun);

	if (ata_drvp != NULL)
		return (ata_drvp);

	/* allocate new device structure */

	ata_drvp = kmem_zalloc(sizeof (ata_drv_t), KM_SLEEP);
	aidp = &ata_drvp->ad_id;

	/*
	 * set up drive struct
	 */
	ata_drvp->ad_ctlp = ata_ctlp;
	ata_drvp->ad_pciide_dma = ATA_DMA_UNINITIALIZED;
	ata_drvp->ad_targ = targ;
	ata_drvp->ad_drive_bits =
	    (ata_drvp->ad_targ == 0 ? ATDH_DRIVE0 : ATDH_DRIVE1);
	/*
	 * Add the LUN for SFF-8070i support
	 */
	ata_drvp->ad_lun = lun;
	ata_drvp->ad_drive_bits |= ata_drvp->ad_lun;

	/*
	 * get drive type, side effect is to collect
	 * IDENTIFY DRIVE data
	 */

	drive_type = ata_drive_type(ata_drvp->ad_drive_bits,
	    ata_ctlp->ac_iohandle1,
	    ata_ctlp->ac_ioaddr1,
	    ata_ctlp->ac_iohandle2,
	    ata_ctlp->ac_ioaddr2,
	    aidp);

	switch (drive_type) {
	case ATA_DEV_NONE:
		/* no drive found */
		goto errout;
	case ATA_DEV_ATAPI:
		ata_drvp->ad_flags |= AD_ATAPI;
		break;
	case ATA_DEV_DISK:
		ata_drvp->ad_flags |= AD_DISK;
		break;
	}

	/*
	 * swap bytes of all text fields
	 */
	if (!ata_strncmp(nec_260, aidp->ai_model, sizeof (aidp->ai_model))) {
		swab(aidp->ai_drvser, aidp->ai_drvser,
		    sizeof (aidp->ai_drvser));
		swab(aidp->ai_fw, aidp->ai_fw,
		    sizeof (aidp->ai_fw));
		swab(aidp->ai_model, aidp->ai_model,
		    sizeof (aidp->ai_model));
	}

	/*
	 * Check if this drive has the Single Sector bug
	 */

	if (ata_check_drive_blacklist(&ata_drvp->ad_id, ATA_BL_1SECTOR))
		ata_drvp->ad_flags |= AD_1SECTOR;
	else
		ata_drvp->ad_flags &= ~AD_1SECTOR;

	if (ata_check_drive_blacklist(&ata_drvp->ad_id, ATA_BL_LBA48))
		ata_drvp->ad_flags |= AD_BLLBA48;
	else
		ata_drvp->ad_flags &= ~AD_BLLBA48;

	/* Check if this drive has the "revert to defaults" bug */
	if (!ata_check_revert_to_defaults(ata_drvp))
		ata_drvp->ad_flags |= AD_NORVRT;

	/* Dump the drive info */
	(void) strncpy(buf, aidp->ai_model, sizeof (aidp->ai_model));
	buf[sizeof (aidp->ai_model)-1] = '\0';
	for (i = sizeof (aidp->ai_model) - 2; buf[i] == ' '; i--)
		buf[i] = '\0';

	ATAPRT(("?\t%s device at targ %d, lun %d lastlun 0x%x\n",
	    (ATAPIDRV(ata_drvp) ? "ATAPI":"IDE"),
	    ata_drvp->ad_targ, ata_drvp->ad_lun, aidp->ai_lastlun));

	ATAPRT(("?\tmodel %s\n", buf));

	if (aidp->ai_majorversion != 0 && aidp->ai_majorversion != 0xffff) {
		for (i = 14; i >= 2; i--) {
			if (aidp->ai_majorversion & (1 << i)) {
				valid_version = i;
				break;
			}
		}
		ATAPRT((
		    "?\tATA/ATAPI-%d supported, majver 0x%x minver 0x%x\n",
		    valid_version,
		    aidp->ai_majorversion,
		    aidp->ai_minorversion));
	}

	if (ata_capability_data) {

		ATAPRT(("?\t\tstat %x, err %x\n",
		    ddi_get8(ata_ctlp->ac_iohandle2,
		    ata_ctlp->ac_altstatus),
		    ddi_get8(ata_ctlp->ac_iohandle1, ata_ctlp->ac_error)));

		ATAPRT(("?\t\tcfg 0x%x, cap 0x%x\n",
		    aidp->ai_config,
		    aidp->ai_cap));

		/*
		 * Be aware that ATA-6 and later drives may not provide valid
		 * geometry information and other obsoleted info.
		 * Select what is printed based on supported ATA model (skip
		 * anything below ATA/ATAPI-3)
		 */

		if (valid_version == 0 || aidp->ai_majorversion <
		    ATAC_MAJVER_6) {
			/*
			 * Supported version less then ATA-6
			 */
			ATAPRT(("?\t\tcyl %d, hd %d, sec/trk %d\n",
			    aidp->ai_fixcyls,
			    aidp->ai_heads,
			    aidp->ai_sectors));
		}
		ATAPRT(("?\t\tmult1 0x%x, mult2 0x%x\n",
		    aidp->ai_mult1,
		    aidp->ai_mult2));
		if (valid_version && aidp->ai_majorversion < ATAC_MAJVER_4) {
			ATAPRT((
			"?\t\tpiomode 0x%x, dmamode 0x%x, advpiomode 0x%x\n",
			    aidp->ai_piomode,
			    aidp->ai_dmamode,
			    aidp->ai_advpiomode));
		} else {
			ATAPRT(("?\t\tadvpiomode 0x%x\n",
			    aidp->ai_advpiomode));
		}
		ATAPRT(("?\t\tminpio %d, minpioflow %d\n",
		    aidp->ai_minpio,
		    aidp->ai_minpioflow));
		if (valid_version && aidp->ai_majorversion >= ATAC_MAJVER_4 &&
		    (aidp->ai_validinfo & ATAC_VALIDINFO_83)) {
			ATAPRT(("?\t\tdwdma 0x%x, ultradma 0x%x\n",
			    aidp->ai_dworddma,
			    aidp->ai_ultradma));
		} else {
			ATAPRT(("?\t\tdwdma 0x%x\n",
			    aidp->ai_dworddma));
		}
	}

	if (ATAPIDRV(ata_drvp)) {
		if (!atapi_init_drive(ata_drvp))
			goto errout;
	} else {
		if (!ata_disk_init_drive(ata_drvp))
			goto errout;
	}

	/*
	 * store pointer in controller struct
	 */
	CTL2DRV(ata_ctlp, targ, lun) = ata_drvp;

	/*
	 * lock the drive's current settings in case I have to
	 * reset the drive due to some sort of error
	 */
	(void) ata_set_feature(ata_ctlp, ata_drvp, ATSF_DIS_REVPOD, 0);

	return (ata_drvp);

errout:
	ata_uninit_drive(ata_drvp);
	return (NULL);
}

/* destroy a drive */

static void
ata_uninit_drive(
	ata_drv_t *ata_drvp)
{
#if 0
	ata_ctl_t *ata_ctlp = ata_drvp->ad_ctlp;
#endif

	ADBG_TRACE(("ata_uninit_drive entered\n"));

#if 0
	/*
	 * DON'T DO THIS. disabling interrupts floats the IRQ line
	 * which generates spurious interrupts
	 */

	/*
	 * Select the correct drive
	 */
	ddi_put8(ata_ctlp->ac_iohandle1, ata_ctlp->ac_drvhd,
	    ata_drvp->ad_drive_bits);
	ata_nsecwait(400);

	/*
	 * Disable interrupts from the drive
	 */
	ddi_put8(ata_ctlp->ac_iohandle2, ata_ctlp->ac_devctl,
	    (ATDC_D3 | ATDC_NIEN));
#endif

	/* interface specific clean-ups */

	if (ata_drvp->ad_flags & AD_ATAPI)
		atapi_uninit_drive(ata_drvp);
	else if (ata_drvp->ad_flags & AD_DISK)
		ata_disk_uninit_drive(ata_drvp);

	/* free drive struct */

	kmem_free(ata_drvp, sizeof (ata_drv_t));
}


/*
 * ata_drive_type()
 *
 * The timeout values and exact sequence of checking is critical
 * especially for atapi device detection, and should not be changed lightly.
 *
 */
static int
ata_drive_type(
	uchar_t		 drvhd,
	ddi_acc_handle_t io_hdl1,
	caddr_t		 ioaddr1,
	ddi_acc_handle_t io_hdl2,
	caddr_t		 ioaddr2,
	struct ata_id	*ata_id_bufp)
{
	uchar_t	status;

	ADBG_TRACE(("ata_drive_type entered\n"));

	/*
	 * select the appropriate drive and LUN
	 */
	ddi_put8(io_hdl1, (uchar_t *)ioaddr1 + AT_DRVHD, drvhd);
	ata_nsecwait(400);

	/*
	 * make certain the drive is selected, and wait for not busy
	 */
	(void) ata_wait3(io_hdl2, ioaddr2, 0, ATS_BSY, 0x7f, 0, 0x7f, 0,
	    5 * 1000000);

	status = ddi_get8(io_hdl2, (uchar_t *)ioaddr2 + AT_ALTSTATUS);

	if (status & ATS_BSY) {
		ADBG_TRACE(("ata_drive_type 0x%p 0x%x\n", ioaddr1, status));
		return (ATA_DEV_NONE);
	}

	if (ata_disk_id(io_hdl1, ioaddr1, io_hdl2, ioaddr2, ata_id_bufp))
		return (ATA_DEV_DISK);

	/*
	 * No disk, check for atapi unit.
	 */
	if (!atapi_signature(io_hdl1, ioaddr1)) {
#ifndef ATA_DISABLE_ATAPI_1_7
		/*
		 * Check for old (but prevalent) atapi 1.7B
		 * spec device, the only known example is the
		 * NEC CDR-260 (not 260R which is (mostly) ATAPI 1.2
		 * compliant). This device has no signature
		 * and requires conversion from hex to BCD
		 * for some scsi audio commands.
		 */
		if (atapi_id(io_hdl1, ioaddr1, io_hdl2, ioaddr2, ata_id_bufp)) {
			return (ATA_DEV_ATAPI);
		}
#endif
		return (ATA_DEV_NONE);
	}

	if (atapi_id(io_hdl1, ioaddr1, io_hdl2, ioaddr2, ata_id_bufp)) {
		return (ATA_DEV_ATAPI);
	}

	return (ATA_DEV_NONE);

}

/*
 * nsec-granularity time delay function
 */
void
ata_nsecwait(clock_t count)
{
	extern int tsc_gethrtime_initted;

	if (tsc_gethrtime_initted) {
		hrtime_t end = gethrtime() + count;

		while (gethrtime() < end) {
			SMT_PAUSE();
		}
	} else {
		drv_usecwait(1 + (count / 1000));
	}
}


/*
 * Wait for a register of a controller to achieve a specific state.
 * To return normally, all the bits in the first sub-mask must be ON,
 * all the bits in the second sub-mask must be OFF.
 * If timeout_usec microseconds pass without the controller achieving
 * the desired bit configuration, we return TRUE, else FALSE.
 */

int ata_usec_delay = 10;

int
ata_wait(
	ddi_acc_handle_t io_hdl,
	caddr_t		ioaddr,
	uchar_t		onbits,
	uchar_t		offbits,
	uint_t		timeout_usec)
{
	ushort_t val;
	hrtime_t deadline = gethrtime() +
	    (hrtime_t)timeout_usec * (NANOSEC / MICROSEC);


	do  {
		val = ddi_get8(io_hdl, (uchar_t *)ioaddr + AT_ALTSTATUS);
		if ((val & onbits) == onbits && (val & offbits) == 0)
			return (TRUE);
		drv_usecwait(ata_usec_delay);
	} while (gethrtime() < deadline);

	return (FALSE);
}


/*
 *
 * This is a slightly more complicated version that checks
 * for error conditions and bails-out rather than looping
 * until the timeout expires
 */
int
ata_wait3(
	ddi_acc_handle_t io_hdl,
	caddr_t		ioaddr,
	uchar_t		onbits1,
	uchar_t		offbits1,
	uchar_t		failure_onbits2,
	uchar_t		failure_offbits2,
	uchar_t		failure_onbits3,
	uchar_t		failure_offbits3,
	uint_t		timeout_usec)
{
	ushort_t val;
	hrtime_t deadline = gethrtime() +
	    (hrtime_t)timeout_usec * (NANOSEC / MICROSEC);

	do  {
		val = ddi_get8(io_hdl, (uchar_t *)ioaddr + AT_ALTSTATUS);

		/*
		 * check for expected condition
		 */
		if ((val & onbits1) == onbits1 && (val & offbits1) == 0)
			return (TRUE);

		/*
		 * check for error conditions
		 */
		if ((val & failure_onbits2) == failure_onbits2 &&
		    (val & failure_offbits2) == 0) {
			return (FALSE);
		}

		if ((val & failure_onbits3) == failure_onbits3 &&
		    (val & failure_offbits3) == 0) {
			return (FALSE);
		}

		drv_usecwait(ata_usec_delay);
	} while (gethrtime() < deadline);

	return (FALSE);
}


/*
 *
 * low level routine for ata_disk_id() and atapi_id()
 *
 */

int
ata_id_common(
	uchar_t		 id_cmd,
	int		 expect_drdy,
	ddi_acc_handle_t io_hdl1,
	caddr_t		 ioaddr1,
	ddi_acc_handle_t io_hdl2,
	caddr_t		 ioaddr2,
	struct ata_id	*aidp)
{
	uchar_t	status;

	ADBG_TRACE(("ata_id_common entered\n"));

	bzero(aidp, sizeof (struct ata_id));

	/*
	 * clear the features register
	 */
	ddi_put8(io_hdl1, (uchar_t *)ioaddr1 + AT_FEATURE, 0);

	/*
	 * Disable interrupts from the device.  When the ata
	 * hardware is sharing its interrupt with another
	 * device, the shared interrupt might have already been
	 * unmasked in the interrupt controller and
	 * triggering ata device interrupts will result in an
	 * interrupt storm and a hung system.
	 */
	ddi_put8(io_hdl2, (uchar_t *)ioaddr2 + AT_DEVCTL, ATDC_D3 | ATDC_NIEN);

	/*
	 * issue IDENTIFY DEVICE or IDENTIFY PACKET DEVICE command
	 */
	ddi_put8(io_hdl1, (uchar_t *)ioaddr1 + AT_CMD, id_cmd);

	/* wait for the busy bit to settle */
	ata_nsecwait(400);

	/*
	 * read alternate status and check for conditions which
	 * may indicate the drive is not present, to prevent getting
	 * stuck in ata_wait3() below.
	 */
	status = ddi_get8(io_hdl2, (uchar_t *)ioaddr2 + AT_ALTSTATUS);

	/*
	 * 0x0, 0x7f, or ATS_DF can happen when no drive is present
	 */
	if ((status == 0x0) || (status == 0x7f) ||
	    ((status & (ATS_BSY|ATS_DF)) == ATS_DF)) {
		/* invalid status, can't be an ATA or ATAPI device */
		return (FALSE);
	}

	/*
	 * According to the ATA specification, some drives may have
	 * to read the media to complete this command.  We need to
	 * make sure we give them enough time to respond.
	 */
	(void) ata_wait3(io_hdl2, ioaddr2, 0, ATS_BSY,
	    ATS_ERR, ATS_BSY, 0x7f, 0, 5 * 1000000);

	/*
	 * read the status byte and clear the pending interrupt
	 */
	status = ddi_get8(io_hdl1, (uchar_t *)ioaddr1 + AT_STATUS);

	/*
	 * this happens if there's no drive present
	 */
	if (status == 0xff || status == 0x7f) {
		/* invalid status, can't be an ATA or ATAPI device */
		return (FALSE);
	}

	if (status & ATS_BSY) {
		ADBG_ERROR(("ata_id_common: BUSY status 0x%x error 0x%x\n",
		    ddi_get8(io_hdl2, (uchar_t *)ioaddr2 +AT_ALTSTATUS),
		    ddi_get8(io_hdl1, (uchar_t *)ioaddr1 + AT_ERROR)));
		return (FALSE);
	}

	if (!(status & ATS_DRQ)) {
		if (status & (ATS_ERR | ATS_DF)) {
			return (FALSE);
		}
		/*
		 * Give the drive another second to assert DRQ. Some older
		 * drives de-assert BSY before asserting DRQ. Bail out
		 * immediately if the status becomes 0x7f, which is invalid
		 * value. It can happen when no drive is present.
		 */
		if (!ata_wait3(io_hdl2, ioaddr2, ATS_DRQ, ATS_BSY, 0x7f,
		    ATS_BSY, 0x7f, ATS_BSY, 1000000)) {
			ADBG_WARN(("ata_id_common: "
			    "!DRQ status 0x%x error 0x%x\n",
			    ddi_get8(io_hdl2, (uchar_t *)ioaddr2 +AT_ALTSTATUS),
			    ddi_get8(io_hdl1, (uchar_t *)ioaddr1 + AT_ERROR)));
			return (FALSE);
		}
	}

	/*
	 * transfer the data
	 */
	ddi_rep_get16(io_hdl1, (ushort_t *)aidp, (ushort_t *)ioaddr1 + AT_DATA,
	    NBPSCTR >> 1, DDI_DEV_NO_AUTOINCR);

	/* wait for the busy bit to settle */
	ata_nsecwait(400);


	/*
	 * Wait for the drive to recognize I've read all the data.
	 * Some drives have been observed to take as much as 3msec to
	 * deassert DRQ after reading the data; allow 1 sec just in case.
	 *
	 * Note: some non-compliant ATAPI drives (e.g., NEC Multispin 6V,
	 * CDR-1350A) don't assert DRDY. If we've made it this far we can
	 * safely ignore the DRDY bit since the ATAPI Packet command
	 * actually doesn't require it to ever be asserted.
	 *
	 * Bail out immediately if the status becomes 0x7f, which is invalid
	 * value. It can happen when no drive is present.
	 *
	 */
	if (!ata_wait3(io_hdl2, ioaddr2, (uchar_t)(expect_drdy ? ATS_DRDY : 0),
	    (ATS_BSY | ATS_DRQ), 0x7f, ATS_BSY, 0x7f, ATS_BSY, 1000000)) {
		ADBG_WARN(("ata_id_common: bad status 0x%x error 0x%x\n",
		    ddi_get8(io_hdl2, (uchar_t *)ioaddr2 + AT_ALTSTATUS),
		    ddi_get8(io_hdl1, (uchar_t *)ioaddr1 + AT_ERROR)));
		return (FALSE);
	}

	/*
	 * Check to see if the command aborted. This happens if
	 * an IDENTIFY DEVICE command is issued to an ATAPI PACKET device,
	 * or if an IDENTIFY PACKET DEVICE command is issued to an ATA
	 * (non-PACKET) device.
	 */
	if (status & (ATS_DF | ATS_ERR)) {
		ADBG_WARN(("ata_id_common: status 0x%x error 0x%x \n",
		    ddi_get8(io_hdl2, (uchar_t *)ioaddr2 + AT_ALTSTATUS),
		    ddi_get8(io_hdl1, (uchar_t *)ioaddr1 + AT_ERROR)));
		return (FALSE);
	}
	return (TRUE);
}


/*
 * Low level routine to issue a non-data command and busy wait for
 * the completion status.
 */

int
ata_command(
	ata_ctl_t *ata_ctlp,
	ata_drv_t *ata_drvp,
	int		 expect_drdy,
	int		 silent,
	uint_t		 busy_wait,
	uchar_t		 cmd,
	uchar_t		 feature,
	uchar_t		 count,
	uchar_t		 sector,
	uchar_t		 head,
	uchar_t		 cyl_low,
	uchar_t		 cyl_hi)
{
	ddi_acc_handle_t io_hdl1 = ata_ctlp->ac_iohandle1;
	ddi_acc_handle_t io_hdl2 = ata_ctlp->ac_iohandle2;
	uchar_t		 status;

	/* select the drive */
	ddi_put8(io_hdl1, ata_ctlp->ac_drvhd, ata_drvp->ad_drive_bits);
	ata_nsecwait(400);

	/* make certain the drive selected */
	if (!ata_wait(io_hdl2, ata_ctlp->ac_ioaddr2,
	    (uchar_t)(expect_drdy ? ATS_DRDY : 0),
	    ATS_BSY, busy_wait)) {
		ADBG_ERROR(("ata_command: select failed "
		    "DRDY 0x%x CMD 0x%x F 0x%x N 0x%x  "
		    "S 0x%x H 0x%x CL 0x%x CH 0x%x\n",
		    expect_drdy, cmd, feature, count,
		    sector, head, cyl_low, cyl_hi));
		return (FALSE);
	}

	/*
	 * set all the regs
	 */
	ddi_put8(io_hdl1, ata_ctlp->ac_drvhd, (head | ata_drvp->ad_drive_bits));
	ddi_put8(io_hdl1, ata_ctlp->ac_sect, sector);
	ddi_put8(io_hdl1, ata_ctlp->ac_count, count);
	ddi_put8(io_hdl1, ata_ctlp->ac_lcyl, cyl_low);
	ddi_put8(io_hdl1, ata_ctlp->ac_hcyl, cyl_hi);
	ddi_put8(io_hdl1, ata_ctlp->ac_feature, feature);

	/* send the command */
	ddi_put8(io_hdl1, ata_ctlp->ac_cmd, cmd);

	/* wait for the busy bit to settle */
	ata_nsecwait(400);

	/* wait for not busy */
	if (!ata_wait(io_hdl2, ata_ctlp->ac_ioaddr2, 0, ATS_BSY, busy_wait)) {
		ADBG_ERROR(("ata_command: BSY too long!"
		    "DRDY 0x%x CMD 0x%x F 0x%x N 0x%x  "
		    "S 0x%x H 0x%x CL 0x%x CH 0x%x\n",
		    expect_drdy, cmd, feature, count,
		    sector, head, cyl_low, cyl_hi));
		return (FALSE);
	}

	/*
	 * wait for DRDY before continuing
	 */
	(void) ata_wait3(io_hdl2, ata_ctlp->ac_ioaddr2,
	    ATS_DRDY, ATS_BSY, /* okay */
	    ATS_ERR, ATS_BSY, /* cmd failed */
	    ATS_DF, ATS_BSY, /* drive failed */
	    busy_wait);

	/* read status to clear IRQ, and check for error */
	status =  ddi_get8(io_hdl1, ata_ctlp->ac_status);

	if ((status & (ATS_BSY | ATS_DF | ATS_ERR)) == 0)
		return (TRUE);

	if (!silent) {
		ADBG_ERROR(("ata_command status 0x%x error 0x%x "
		    "DRDY 0x%x CMD 0x%x F 0x%x N 0x%x  "
		    "S 0x%x H 0x%x CL 0x%x CH 0x%x\n",
		    ddi_get8(io_hdl1, ata_ctlp->ac_status),
		    ddi_get8(io_hdl1, ata_ctlp->ac_error),
		    expect_drdy, cmd, feature, count,
		    sector, head, cyl_low, cyl_hi));
	}
	return (FALSE);
}



/*
 *
 * Issue a SET FEATURES command
 *
 */

int
ata_set_feature(
	ata_ctl_t *ata_ctlp,
	ata_drv_t *ata_drvp,
	uchar_t    feature,
	uchar_t    value)
{
	int		 rc;

	rc = ata_command(ata_ctlp, ata_drvp, TRUE, TRUE, ata_set_feature_wait,
	    ATC_SET_FEAT, feature, value, 0, 0, 0, 0);
	/* feature, count, sector, head, cyl_low, cyl_hi */

	if (rc) {
		return (TRUE);
	}

	ADBG_ERROR(("?ata_set_feature: (0x%x,0x%x) failed\n", feature, value));
	return (FALSE);
}



/*
 *
 * Issue a FLUSH CACHE command
 *
 */

static int
ata_flush_cache(
	ata_ctl_t *ata_ctlp,
	ata_drv_t *ata_drvp)
{
	/* this command is optional so fail silently */
	return (ata_command(ata_ctlp, ata_drvp, TRUE, TRUE,
	    ata_flush_cache_wait,
	    ATC_FLUSH_CACHE, 0, 0, 0, 0, 0, 0));
}

/*
 * ata_setup_ioaddr()
 *
 * Map the device registers and return the handles.
 *
 * If this is a ISA-ATA controller then only two handles are
 * initialized and returned.
 *
 * If this is a PCI-IDE controller than a third handle (for the
 * PCI-IDE Bus Mastering registers) is initialized and returned.
 *
 */

static int
ata_setup_ioaddr(
	dev_info_t	 *dip,
	ddi_acc_handle_t *handle1p,
	caddr_t		 *addr1p,
	ddi_acc_handle_t *handle2p,
	caddr_t		 *addr2p,
	ddi_acc_handle_t *bm_hdlp,
	caddr_t		 *bm_addrp)
{
	ddi_device_acc_attr_t dev_attr;
	int	 rnumber;
	int	 rc;
	off_t	 regsize;

	/*
	 * Make certain the controller is enabled and its regs are map-able
	 *
	 */
	rc = ddi_dev_regsize(dip, 0, &regsize);
	if (rc != DDI_SUCCESS || regsize <= AT_CMD) {
		ADBG_INIT(("ata_setup_ioaddr(1): rc %d regsize %lld\n",
		    rc, (long long)regsize));
		return (FALSE);
	}

	rc = ddi_dev_regsize(dip, 1, &regsize);
	if (rc != DDI_SUCCESS || regsize <= AT_ALTSTATUS) {
		ADBG_INIT(("ata_setup_ioaddr(2): rc %d regsize %lld\n",
		    rc, (long long)regsize));
		return (FALSE);
	}

	/*
	 * setup the device attribute structure for little-endian,
	 * strict ordering access.
	 */
	dev_attr.devacc_attr_version = DDI_DEVICE_ATTR_V0;
	dev_attr.devacc_attr_endian_flags = DDI_STRUCTURE_LE_ACC;
	dev_attr.devacc_attr_dataorder = DDI_STRICTORDER_ACC;

	*handle1p = NULL;
	*handle2p = NULL;
	*bm_hdlp = NULL;

	/*
	 * Determine whether this is a ISA, PNP-ISA, or PCI-IDE device
	 */
	if (ddi_prop_exists(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS, "pnp-csn")) {
		/* it's PNP-ISA, skip over the extra reg tuple */
		rnumber = 1;
		goto not_pciide;
	}

	/* else, it's ISA or PCI-IDE, check further */
	rnumber = 0;

	if (!ata_is_pci(dip)) {
		/*
		 * If it's not a PCI-IDE, there are only two reg tuples
		 * and the first one contains the I/O base (170 or 1f0)
		 * rather than the controller instance number.
		 */
		ADBG_TRACE(("ata_setup_ioaddr !pci-ide\n"));
		goto not_pciide;
	}


	/*
	 * Map the correct half of the PCI-IDE Bus Master registers.
	 * There's a single BAR that maps these registers for both
	 * controller's in a dual-controller chip and it's upto my
	 * parent nexus, pciide, to adjust which (based on my instance
	 * number) half this call maps.
	 */
	rc = ddi_dev_regsize(dip, 2, &regsize);
	if (rc != DDI_SUCCESS || regsize < 8) {
		ADBG_INIT(("ata_setup_ioaddr(3): rc %d regsize %lld\n",
		    rc, (long long)regsize));
		goto not_pciide;
	}

	rc = ddi_regs_map_setup(dip, 2, bm_addrp, 0, 0, &dev_attr, bm_hdlp);

	if (rc != DDI_SUCCESS) {
		/* map failed, try to use in non-pci-ide mode */
		ADBG_WARN(("ata_setup_ioaddr bus master map failed, rc=0x%x\n",
		    rc));
		*bm_hdlp = NULL;
	}

not_pciide:
	/*
	 * map the lower command block registers
	 */

	rc = ddi_regs_map_setup(dip, rnumber, addr1p, 0, 0, &dev_attr,
	    handle1p);

	if (rc != DDI_SUCCESS) {
		cmn_err(CE_WARN, "ata: reg tuple 0 map failed, rc=0x%x\n", rc);
		goto out1;
	}

	/*
	 * If the controller is being used in compatibility mode
	 * via /devices/isa/ata@1,{1f0,1f0}/..., the reg property
	 * will specify zeros for the I/O ports for the PCI
	 * instance.
	 */
	if (*addr1p == 0) {
		ADBG_TRACE(("ata_setup_ioaddr ioaddr1 0\n"));
		goto out2;
	}

	/*
	 * map the upper control block registers
	 */
	rc = ddi_regs_map_setup(dip, rnumber + 1, addr2p, 0, 0, &dev_attr,
	    handle2p);
	if (rc == DDI_SUCCESS)
		return (TRUE);

	cmn_err(CE_WARN, "ata: reg tuple 1 map failed, rc=0x%x", rc);

out2:
	if (*handle1p != NULL) {
		ddi_regs_map_free(handle1p);
		*handle1p = NULL;
	}

out1:
	if (*bm_hdlp != NULL) {
		ddi_regs_map_free(bm_hdlp);
		*bm_hdlp = NULL;
	}
	return (FALSE);

}

/*
 *
 * Currently, the only supported controllers are ones which
 * support the SFF-8038 Bus Mastering spec.
 *
 * Check the parent node's IEEE 1275 class-code property to
 * determine if it's an PCI-IDE instance which supports SFF-8038
 * Bus Mastering. It's perfectly valid to have a PCI-IDE controller
 * that doesn't do Bus Mastering. In that case, my interrupt handler
 * only uses the interrupt latch bit in PCI-IDE status register.
 * The assumption is that the programming interface byte of the
 * class-code property reflects the bus master DMA capability of
 * the controller.
 *
 * Whether the drive support supports the DMA option still needs
 * to be checked later. Each individual request also has to be
 * checked for alignment and size to decide whether to use the
 * DMA transfer mode.
 */

static void
ata_init_pciide(
	dev_info_t	 *dip,
	ata_ctl_t *ata_ctlp)
{
	uint_t	 class_code;
	uchar_t	 status;

	ata_cntrl_DMA_sel_msg = NULL;

	if (ata_ctlp->ac_bmhandle == NULL) {
		ata_ctlp->ac_pciide = FALSE;
		ata_ctlp->ac_pciide_bm = FALSE;
		ata_cntrl_DMA_sel_msg = "cntrl not Bus Master DMA capable";
		return;
	}

	/*
	 * check if it's a known bogus PCI-IDE chip
	 */
	if (ata_check_pciide_blacklist(dip, ATA_BL_BOGUS)) {
		ADBG_WARN(("ata_setup_ioaddr pci-ide blacklist\n"));
		ata_ctlp->ac_pciide = FALSE;
		ata_ctlp->ac_pciide_bm = FALSE;
		ata_cntrl_DMA_sel_msg = "cntrl blacklisted";
		return;
	}
	ata_ctlp->ac_pciide = TRUE;

	if (ata_check_pciide_blacklist(dip, ATA_BL_BMSTATREG_PIO_BROKEN)) {
		ata_ctlp->ac_flags |= AC_BMSTATREG_PIO_BROKEN;
	}

	/*
	 * check for a PCI-IDE chip with a broken DMA engine
	 */
	if (ata_check_pciide_blacklist(dip, ATA_BL_NODMA)) {
		ata_ctlp->ac_pciide_bm = FALSE;
		ata_cntrl_DMA_sel_msg =
		    "cntrl blacklisted/DMA engine broken";
		return;
	}

	/*
	 * Check the Programming Interface register to determine
	 * if this device supports PCI-IDE Bus Mastering. Some PCI-IDE
	 * devices don't support Bus Mastering or DMA.
	 * Since we are dealing with pre-qualified pci-ide controller,
	 * check programming interface byte only.
	 */

	class_code = ddi_prop_get_int(DDI_DEV_T_ANY, ddi_get_parent(dip),
	    DDI_PROP_DONTPASS, "class-code", 0);
	if ((class_code & PCIIDE_BM_CAP_MASK) != PCIIDE_BM_CAP_MASK) {
		ata_ctlp->ac_pciide_bm = FALSE;
		ata_cntrl_DMA_sel_msg =
		    "cntrl not Bus Master DMA capable";
		return;
	}

	/*
	 * Avoid doing DMA on "simplex" chips which share hardware
	 * between channels
	 */
	status = ddi_get8(ata_ctlp->ac_bmhandle,
	    (uchar_t *)ata_ctlp->ac_bmaddr + PCIIDE_BMISX_REG);
	/*
	 * Some motherboards have CSB5's that are wired "to emulate CSB4 mode".
	 * In such a mode, the simplex bit is asserted,  but in fact testing
	 * on such a motherboard has shown that the devices are not simplex
	 * -- DMA can be used on both channels concurrently with no special
	 * considerations.  For chips like this, we have the ATA_BL_NO_SIMPLEX
	 * flag set to indicate that the value of the simplex bit can be
	 * ignored.
	 */

	if (status & PCIIDE_BMISX_SIMPLEX) {
		if (ata_check_pciide_blacklist(dip, ATA_BL_NO_SIMPLEX)) {
			cmn_err(CE_WARN, "Ignoring false simplex bit \n");

		} else {

			int simplex_dma_channel, *rp, proplen, channel;
			int dma_on = FALSE;

			/*
			 * By default,use DMA on channel 0 and PIO on channel
			 * 1.  This can be switched by setting
			 * ata-simplex-dma-channel to:
			 *	0  DMA on channel 0 (default without this
			 *			    property)
			 *	1  DMA on channel 1
			 *	any other value: DMA off on both channels.
			 */
			simplex_dma_channel = ata_prop_lookup_int(DDI_DEV_T_ANY,
			    ata_ctlp->ac_dip, 0, "ata-simplex-dma-channel", 0);

			if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY,
			    ata_ctlp->ac_dip, DDI_PROP_DONTPASS, "reg", &rp,
			    (uint_t *)&proplen) == DDI_PROP_SUCCESS) {

				channel = *rp;
				ddi_prop_free(rp);

				if (simplex_dma_channel == channel) {
					cmn_err(CE_CONT, "?ata: simplex "
					    "controller.  DMA on channel"
					    "  %d PIO on channel %d",
					    channel, channel ? 0:1);
					dma_on = TRUE;
				} else {
					ata_cntrl_DMA_sel_msg =
					    "simplex controller";
				}
			}

			if (dma_on == FALSE) {
				ata_ctlp->ac_pciide_bm = FALSE;

				return;
			}
		}
	}

	/*
	 * It's a compatible PCI-IDE Bus Mastering controller,
	 * allocate and map the DMA Scatter/Gather list (PRDE table).
	 */
	if (ata_pciide_alloc(dip, ata_ctlp))
		ata_ctlp->ac_pciide_bm = TRUE;
	else {
		ata_ctlp->ac_pciide_bm = FALSE;
		ata_cntrl_DMA_sel_msg = "unable to init DMA S/G list";
	}
}

/*
 *
 * Determine whether to enable DMA support for this drive.
 * The controller and the drive both have to support DMA.
 * The controller's capabilities were already checked in
 * ata_init_pciide(), now just check the drive's capabilities.
 *
 */

static int
ata_init_drive_pcidma(
	ata_ctl_t *ata_ctlp,
	ata_drv_t *ata_drvp,
	dev_info_t *tdip)
{
	boolean_t dma;
	boolean_t cd_dma;
	boolean_t disk_dma;
	boolean_t atapi_dma;
	int ata_options;

	ata_dev_DMA_sel_msg = NULL;

	if (ata_ctlp->ac_pciide_bm != TRUE) {
		ata_dev_DMA_sel_msg =
		    "controller is not Bus Master capable";

		return (ATA_DMA_OFF);
	}

	ata_options = ddi_prop_get_int(DDI_DEV_T_ANY, ata_ctlp->ac_dip,
	    0, "ata-options", 0);

	if (!(ata_options & ATA_OPTIONS_DMA)) {
		/*
		 * Either the ata-options property was not found or
		 * DMA is not enabled by this property
		 */
		ata_dev_DMA_sel_msg =
		    "disabled by \"ata-options\" property";

		return (ATA_DMA_OFF);
	}

	if (ata_check_drive_blacklist(&ata_drvp->ad_id, ATA_BL_NODMA)) {
		ata_dev_DMA_sel_msg = "device not DMA capable; blacklisted";

		return (ATA_DMA_OFF);
	}

	/*
	 * DMA mode is mandatory on ATA-3 (or newer) drives but is
	 * optional on ATA-2 (or older) drives.
	 *
	 * On ATA-2 drives the ai_majorversion word will probably
	 * be 0xffff or 0x0000, check the (now obsolete) DMA bit in
	 * the capabilities word instead. The order of these tests
	 * is important since an ATA-3 drive doesn't have to set
	 * the DMA bit in the capabilities word.
	 *
	 */

	if (!((ata_drvp->ad_id.ai_majorversion & 0x8000) == 0 &&
	    ata_drvp->ad_id.ai_majorversion >= (1 << 2)) &&
	    !(ata_drvp->ad_id.ai_cap & ATAC_DMA_SUPPORT)) {
		ata_dev_DMA_sel_msg = "device not DMA capable";

		return (ATA_DMA_OFF);
	}

	/*
	 * Disable DMA for ATAPI devices on controllers known to
	 * have trouble with ATAPI DMA
	 */

	if (ATAPIDRV(ata_drvp)) {
		if (ata_check_pciide_blacklist(ata_ctlp->ac_dip,
		    ATA_BL_ATAPI_NODMA)) {
			ata_dev_DMA_sel_msg =
			    "controller incapable of DMA for ATAPI device";

			return (ATA_DMA_OFF);
		}
	}
	dma = ata_prop_lookup_int(DDI_DEV_T_ANY, tdip,
	    0, "ata-dma-enabled", TRUE);
	disk_dma = ata_prop_lookup_int(DDI_DEV_T_ANY, tdip,
	    0, "ata-disk-dma-enabled", TRUE);
	cd_dma = ata_prop_lookup_int(DDI_DEV_T_ANY, tdip,
	    0, "atapi-cd-dma-enabled", FALSE);
	atapi_dma = ata_prop_lookup_int(DDI_DEV_T_ANY, tdip,
	    0, "atapi-other-dma-enabled", TRUE);

	if (dma == FALSE) {
		cmn_err(CE_CONT, "?ata_init_drive_pcidma: "
		    "DMA disabled by \"ata-dma-enabled\" property");
		ata_dev_DMA_sel_msg = "disabled by prop ata-dma-enabled";

		return (ATA_DMA_OFF);
	}

	if (IS_CDROM(ata_drvp) == TRUE) {
		if (cd_dma == FALSE) {
			ata_dev_DMA_sel_msg =
			    "disabled.  Control with \"atapi-cd-dma-enabled\""
			    " property";

			return (ATA_DMA_OFF);
		}

	} else if (ATAPIDRV(ata_drvp) == FALSE) {
		if (disk_dma == FALSE) {
			ata_dev_DMA_sel_msg =
			    "disabled by \"ata-disk-dma-enabled\" property";

			return (ATA_DMA_OFF);
		}

	} else if (atapi_dma == FALSE) {
			ata_dev_DMA_sel_msg =
			    "disabled by \"atapi-other-dma-enabled\" property";

			return (ATA_DMA_OFF);
	}

	return (ATA_DMA_ON);
}



/*
 * this compare routine squeezes out extra blanks and
 * returns TRUE if p1 matches the leftmost substring of p2
 */

static int
ata_strncmp(
	char *p1,
	char *p2,
	int cnt)
{

	for (;;) {
		/*
		 * skip over any extra blanks in both strings
		 */
		while (*p1 != '\0' && *p1 == ' ')
			p1++;

		while (cnt != 0 && *p2 == ' ') {
			p2++;
			cnt--;
		}

		/*
		 * compare the two strings
		 */

		if (cnt == 0 || *p1 != *p2)
			break;

		while (cnt > 0 && *p1 == *p2) {
			p1++;
			p2++;
			cnt--;
		}

	}

	/* return TRUE if both strings ended at same point */
	return ((*p1 == '\0') ? TRUE : FALSE);
}

/*
 * Per PSARC/1997/281 create variant="atapi" property (if necessary)
 * on the target's dev_info node. Currently, the sd target driver
 * is the only driver which refers to this property.
 *
 * If the flag ata_id_debug is set also create the
 * the "ata" or "atapi" property on the target's dev_info node
 *
 */

int
ata_prop_create(
	dev_info_t *tgt_dip,
	ata_drv_t  *ata_drvp,
	char	   *name)
{
	int	rc;

	ADBG_TRACE(("ata_prop_create 0x%p 0x%p %s\n", tgt_dip, ata_drvp, name));

	if (strcmp("atapi", name) == 0) {
		rc =  ndi_prop_update_string(DDI_DEV_T_NONE, tgt_dip,
		    "variant", name);
		if (rc != DDI_PROP_SUCCESS)
			return (FALSE);
	}

	if (!ata_id_debug)
		return (TRUE);

	rc =  ndi_prop_update_byte_array(DDI_DEV_T_NONE, tgt_dip, name,
	    (uchar_t *)&ata_drvp->ad_id, sizeof (ata_drvp->ad_id));
	if (rc != DDI_PROP_SUCCESS) {
		ADBG_ERROR(("ata_prop_create failed, rc=%d\n", rc));
	}
	return (TRUE);
}


/* *********************************************************************** */
/* *********************************************************************** */
/* *********************************************************************** */

/*
 * This state machine doesn't implement the ATAPI Optional Overlap
 * feature. You need that feature to efficiently support ATAPI
 * tape drives. See the 1394-ATA Tailgate spec (D97107), Figure 24,
 * for an example of how to add the necessary additional NextActions
 * and NextStates to this FSM and the atapi_fsm, in order to support
 * the Overlap Feature.
 */


uchar_t ata_ctlr_fsm_NextAction[ATA_CTLR_NSTATES][ATA_CTLR_NFUNCS] = {
/* --------------------- next action --------------------- | - current - */
/* start0 --- start1 ---- intr ------ fini --- reset --- */
{ AC_START,   AC_START,	  AC_NADA,    AC_NADA, AC_RESET_I }, /* idle	 */
{ AC_BUSY,    AC_BUSY,	  AC_INTR,    AC_FINI, AC_RESET_A }, /* active0  */
{ AC_BUSY,    AC_BUSY,	  AC_INTR,    AC_FINI, AC_RESET_A }, /* active1  */
};

uchar_t ata_ctlr_fsm_NextState[ATA_CTLR_NSTATES][ATA_CTLR_NFUNCS] = {

/* --------------------- next state --------------------- | - current - */
/* start0 --- start1 ---- intr ------ fini --- reset --- */
{ AS_ACTIVE0, AS_ACTIVE1, AS_IDLE,    AS_IDLE, AS_IDLE	  }, /* idle    */
{ AS_ACTIVE0, AS_ACTIVE0, AS_ACTIVE0, AS_IDLE, AS_ACTIVE0 }, /* active0 */
{ AS_ACTIVE1, AS_ACTIVE1, AS_ACTIVE1, AS_IDLE, AS_ACTIVE1 }, /* active1 */
};


static int
ata_ctlr_fsm(
	uchar_t		 fsm_func,
	ata_ctl_t	*ata_ctlp,
	ata_drv_t	*ata_drvp,
	ata_pkt_t	*ata_pktp,
	int		*DoneFlgp)
{
	uchar_t	   action;
	uchar_t	   current_state;
	uchar_t	   next_state;
	int	   rc;

	current_state = ata_ctlp->ac_state;
	action = ata_ctlr_fsm_NextAction[current_state][fsm_func];
	next_state = ata_ctlr_fsm_NextState[current_state][fsm_func];

	/*
	 * Set the controller's new state
	 */
	ata_ctlp->ac_state = next_state;
	switch (action) {

	case AC_BUSY:
		return (ATA_FSM_RC_BUSY);

	case AC_NADA:
		return (ATA_FSM_RC_OKAY);

	case AC_START:
		ASSERT(ata_ctlp->ac_active_pktp == NULL);
		ASSERT(ata_ctlp->ac_active_drvp == NULL);

		ata_ctlp->ac_active_pktp = ata_pktp;
		ata_ctlp->ac_active_drvp = ata_drvp;

		rc = (*ata_pktp->ap_start)(ata_ctlp, ata_drvp, ata_pktp);

		if (rc == ATA_FSM_RC_BUSY) {
			/* the request didn't start, GHD will requeue it */
			ata_ctlp->ac_state = AS_IDLE;
			ata_ctlp->ac_active_pktp = NULL;
			ata_ctlp->ac_active_drvp = NULL;
		}
		return (rc);

	case AC_INTR:
		ASSERT(ata_ctlp->ac_active_pktp != NULL);
		ASSERT(ata_ctlp->ac_active_drvp != NULL);

		ata_drvp = ata_ctlp->ac_active_drvp;
		ata_pktp = ata_ctlp->ac_active_pktp;
		return ((*ata_pktp->ap_intr)(ata_ctlp, ata_drvp, ata_pktp));

	case AC_RESET_A: /* Reset, controller active */
		ASSERT(ata_ctlp->ac_active_pktp != NULL);
		ASSERT(ata_ctlp->ac_active_drvp != NULL);

		/* clean up the active request */
		ata_pktp = ata_ctlp->ac_active_pktp;
		ata_pktp->ap_flags |= AP_DEV_RESET | AP_BUS_RESET;

		/* halt the DMA engine */
		if (ata_pktp->ap_pciide_dma) {
			ata_pciide_dma_stop(ata_ctlp);
			(void) ata_pciide_status_clear(ata_ctlp);
		}

		/* Do a Software Reset to unwedge the bus */
		if (!ata_software_reset(ata_ctlp)) {
			return (ATA_FSM_RC_BUSY);
		}

		/* Then send a DEVICE RESET cmd to each ATAPI device */
		atapi_fsm_reset(ata_ctlp);
		return (ATA_FSM_RC_FINI);

	case AC_RESET_I: /* Reset, controller idle */
		/* Do a Software Reset to unwedge the bus */
		if (!ata_software_reset(ata_ctlp)) {
			return (ATA_FSM_RC_BUSY);
		}

		/* Then send a DEVICE RESET cmd to each ATAPI device */
		atapi_fsm_reset(ata_ctlp);
		return (ATA_FSM_RC_OKAY);

	case AC_FINI:
		break;
	}

	/*
	 * AC_FINI, check ARQ needs to be started or finished
	 */

	ASSERT(action == AC_FINI);
	ASSERT(ata_ctlp->ac_active_pktp != NULL);
	ASSERT(ata_ctlp->ac_active_drvp != NULL);

	/*
	 * The active request is done now.
	 * Disconnect the request from the controller and
	 * add it to the done queue.
	 */
	ata_drvp = ata_ctlp->ac_active_drvp;
	ata_pktp = ata_ctlp->ac_active_pktp;

	/*
	 * If ARQ pkt is done, get ptr to original pkt and wrap it up.
	 */
	if (ata_pktp == ata_ctlp->ac_arq_pktp) {
		ata_pkt_t *arq_pktp;

		ADBG_ARQ(("ata_ctlr_fsm 0x%p ARQ done\n", ata_ctlp));

		arq_pktp = ata_pktp;
		ata_pktp = ata_ctlp->ac_fault_pktp;
		ata_ctlp->ac_fault_pktp = NULL;
		if (arq_pktp->ap_flags & (AP_ERROR | AP_BUS_RESET))
			ata_pktp->ap_flags |= AP_ARQ_ERROR;
		else
			ata_pktp->ap_flags |= AP_ARQ_OKAY;
		goto all_done;
	}


#define	AP_ARQ_NEEDED	(AP_ARQ_ON_ERROR | AP_GOT_STATUS | AP_ERROR)

	/*
	 * Start ARQ pkt if necessary
	 */
	if ((ata_pktp->ap_flags & AP_ARQ_NEEDED) == AP_ARQ_NEEDED &&
	    (ata_pktp->ap_status & ATS_ERR)) {

		/* set controller state back to active */
		ata_ctlp->ac_state = current_state;

		/* try to start the ARQ pkt */
		rc = ata_start_arq(ata_ctlp, ata_drvp, ata_pktp);

		if (rc == ATA_FSM_RC_BUSY) {
			ADBG_ARQ(("ata_ctlr_fsm 0x%p ARQ BUSY\n", ata_ctlp));
			/* let the target driver handle the problem */
			ata_ctlp->ac_state = AS_IDLE;
			ata_ctlp->ac_active_pktp = NULL;
			ata_ctlp->ac_active_drvp = NULL;
			ata_ctlp->ac_fault_pktp = NULL;
			goto all_done;
		}

		ADBG_ARQ(("ata_ctlr_fsm 0x%p ARQ started\n", ata_ctlp));
		return (rc);
	}

	/*
	 * Normal completion, no error status, and not an ARQ pkt,
	 * just fall through.
	 */

all_done:

	/*
	 * wrap everything up and tie a ribbon around it
	 */
	ata_ctlp->ac_active_pktp = NULL;
	ata_ctlp->ac_active_drvp = NULL;
	if (APKT2GCMD(ata_pktp) != (gcmd_t *)0) {
		ghd_complete(&ata_ctlp->ac_ccc, APKT2GCMD(ata_pktp));
		if (DoneFlgp)
			*DoneFlgp = TRUE;
	}

	return (ATA_FSM_RC_OKAY);
}


static int
ata_start_arq(
	ata_ctl_t *ata_ctlp,
	ata_drv_t *ata_drvp,
	ata_pkt_t *ata_pktp)
{
	ata_pkt_t		*arq_pktp;
	int			 bytes;
	uint_t			 senselen;

	ADBG_ARQ(("ata_start_arq 0x%p ARQ needed\n", ata_ctlp));

	/*
	 * Determine just the size of the Request Sense Data buffer within
	 * the scsi_arq_status structure.
	 */
#define	SIZEOF_ARQ_HEADER	(sizeof (struct scsi_arq_status)	\
				- sizeof (struct scsi_extended_sense))
	senselen = ata_pktp->ap_statuslen - SIZEOF_ARQ_HEADER;
	ASSERT(senselen > 0);


	/* save ptr to original pkt */
	ata_ctlp->ac_fault_pktp = ata_pktp;

	/* switch the controller's active pkt to the ARQ pkt */
	arq_pktp = ata_ctlp->ac_arq_pktp;
	ata_ctlp->ac_active_pktp = arq_pktp;

	/* finish initializing the ARQ CDB */
	ata_ctlp->ac_arq_cdb[1] = ata_drvp->ad_lun << 4;
	ata_ctlp->ac_arq_cdb[4] = (uchar_t)senselen;

	/* finish initializing the ARQ pkt */
	arq_pktp->ap_v_addr = (caddr_t)&ata_pktp->ap_scbp->sts_sensedata;

	arq_pktp->ap_resid = senselen;
	arq_pktp->ap_flags = AP_ATAPI | AP_READ;
	arq_pktp->ap_cdb_pad =
	    ((unsigned)(ata_drvp->ad_cdb_len - arq_pktp->ap_cdb_len)) >> 1;

	bytes = min(senselen, ATAPI_MAX_BYTES_PER_DRQ);
	arq_pktp->ap_hicyl = (uchar_t)(bytes >> 8);
	arq_pktp->ap_lwcyl = (uchar_t)bytes;

	/*
	 * This packet is shared by all drives on this controller
	 * therefore we need to init the drive number on every ARQ.
	 */
	arq_pktp->ap_hd = ata_drvp->ad_drive_bits;

	/* start it up */
	return ((*arq_pktp->ap_start)(ata_ctlp, ata_drvp, arq_pktp));
}

/*
 *
 * reset the bus
 *
 */

static int
ata_reset_bus(
	ata_ctl_t *ata_ctlp)
{
	int	watchdog;
	uchar_t	drive;
	int	rc = FALSE;
	uchar_t	fsm_func;
	int	DoneFlg = FALSE;

	/*
	 * Do a Software Reset to unwedge the bus, and send
	 * ATAPI DEVICE RESET to each ATAPI drive.
	 */
	fsm_func = ATA_FSM_RESET;
	for (watchdog = ata_reset_bus_watchdog; watchdog > 0; watchdog--) {
		switch (ata_ctlr_fsm(fsm_func, ata_ctlp, NULL, NULL,
		    &DoneFlg)) {
		case ATA_FSM_RC_OKAY:
			rc = TRUE;
			goto fsm_done;

		case ATA_FSM_RC_BUSY:
			return (FALSE);

		case ATA_FSM_RC_INTR:
			fsm_func = ATA_FSM_INTR;
			rc = TRUE;
			continue;

		case ATA_FSM_RC_FINI:
			fsm_func = ATA_FSM_FINI;
			rc = TRUE;
			continue;
		}
	}
	ADBG_WARN(("ata_reset_bus: watchdog\n"));

fsm_done:

	/*
	 * Reinitialize the ATA drives
	 */
	for (drive = 0; drive < ATA_MAXTARG; drive++) {
		ata_drv_t *ata_drvp;

		if ((ata_drvp = CTL2DRV(ata_ctlp, drive, 0)) == NULL)
			continue;

		if (ATAPIDRV(ata_drvp))
			continue;

		/*
		 * Reprogram the Read/Write Multiple block factor
		 * and current geometry into the drive.
		 */
		if (!ata_disk_setup_parms(ata_ctlp, ata_drvp))
			rc = FALSE;
	}

	/* If DoneFlg is TRUE, it means that ghd_complete() function */
	/* has been already called. In this case ignore any errors and */
	/* return TRUE to the caller, otherwise return the value of rc */
	/* to the caller */
	if (DoneFlg)
		return (TRUE);
	else
		return (rc);
}


/*
 *
 * Low level routine to toggle the Software Reset bit
 *
 */

static int
ata_software_reset(
	ata_ctl_t *ata_ctlp)
{
	ddi_acc_handle_t io_hdl1 = ata_ctlp->ac_iohandle1;
	ddi_acc_handle_t io_hdl2 = ata_ctlp->ac_iohandle2;
	hrtime_t deadline;
	uint_t usecs_left;

	ADBG_TRACE(("ata_reset_bus entered\n"));

	/* disable interrupts and turn the software reset bit on */
	ddi_put8(io_hdl2, ata_ctlp->ac_devctl, (ATDC_D3 | ATDC_SRST));

	/* why 30 milliseconds, the ATA/ATAPI-4 spec says 5 usec. */
	drv_usecwait(30000);

	/* turn the software reset bit back off */
	ddi_put8(io_hdl2, ata_ctlp->ac_devctl, ATDC_D3);

	/*
	 * Wait for the controller to assert BUSY status.
	 * I don't think 300 msecs is correct. The ATA/ATAPI-4
	 * spec says 400 nsecs, (and 2 msecs if device
	 * was in sleep mode; but we don't put drives to sleep
	 * so it probably doesn't matter).
	 */
	drv_usecwait(300000);

	/*
	 * If drive 0 exists the test for completion is simple
	 */
	deadline = gethrtime() + ((hrtime_t)31 * NANOSEC);

	if (CTL2DRV(ata_ctlp, 0, 0)) {
		goto wait_for_not_busy;
	}

	ASSERT(CTL2DRV(ata_ctlp, 1, 0) != NULL);

	/*
	 * This must be a single device configuration, with drive 1
	 * only. This complicates the test for completion because
	 * issuing the software reset just caused drive 1 to
	 * deselect. With drive 1 deselected, if I just read the
	 * status register to test the BSY bit I get garbage, but
	 * I can't re-select drive 1 until I'm certain the BSY bit
	 * is de-asserted. Catch-22.
	 *
	 * In ATA/ATAPI-4, rev 15, section 9.16.2, it says to handle
	 * this situation like this:
	 */

	/* give up if the drive doesn't settle within 31 seconds */
	while (gethrtime() < deadline) {
		/*
		 * delay 10msec each time around the loop
		 */
		drv_usecwait(10000);

		/*
		 * try to select drive 1
		 */
		ddi_put8(io_hdl1, ata_ctlp->ac_drvhd, ATDH_DRIVE1);

		ddi_put8(io_hdl1, ata_ctlp->ac_sect, 0x55);
		ddi_put8(io_hdl1, ata_ctlp->ac_sect, 0xaa);
		if (ddi_get8(io_hdl1, ata_ctlp->ac_sect) != 0xaa)
			continue;

		ddi_put8(io_hdl1, ata_ctlp->ac_count, 0x55);
		ddi_put8(io_hdl1, ata_ctlp->ac_count, 0xaa);
		if (ddi_get8(io_hdl1, ata_ctlp->ac_count) != 0xaa)
			continue;

		goto wait_for_not_busy;
	}
	return (FALSE);

wait_for_not_busy:

	/*
	 * Now wait up to 31 seconds for BUSY to clear.
	 */
	usecs_left = (deadline - gethrtime()) / 1000;
	(void) ata_wait3(io_hdl2, ata_ctlp->ac_ioaddr2, 0, ATS_BSY,
	    ATS_ERR, ATS_BSY, ATS_DF, ATS_BSY, usecs_left);

	return (TRUE);
}

/*
 *
 * DDI interrupt handler
 *
 */

static uint_t
ata_intr(
	caddr_t arg)
{
	ata_ctl_t *ata_ctlp;
	int	   one_shot = 1;

	ata_ctlp = (ata_ctl_t *)arg;

	return (ghd_intr(&ata_ctlp->ac_ccc, (void *)&one_shot));
}


/*
 *
 * GHD ccc_get_status callback
 *
 */

static int
ata_get_status(
	void *hba_handle,
	void *intr_status)
{
	ata_ctl_t *ata_ctlp = (ata_ctl_t *)hba_handle;
	uchar_t	   status;

	ADBG_TRACE(("ata_get_status entered\n"));

	/*
	 * ignore interrupts before ata_attach completes
	 */
	if (!(ata_ctlp->ac_flags & AC_ATTACHED))
		return (FALSE);

	/*
	 * can't be interrupt pending if nothing active
	 */
	switch (ata_ctlp->ac_state) {
	case AS_IDLE:
		return (FALSE);
	case AS_ACTIVE0:
	case AS_ACTIVE1:
		ASSERT(ata_ctlp->ac_active_drvp != NULL);
		ASSERT(ata_ctlp->ac_active_pktp != NULL);
		break;
	}

	/*
	 * If this is a PCI-IDE controller, check the PCI-IDE controller's
	 * interrupt status latch. But don't clear it yet.
	 *
	 * AC_BMSTATREG_PIO_BROKEN flag is used currently for
	 * CMD chips with device id 0x646. Since the interrupt bit on
	 * Bus master IDE register is not usable when in PIO mode,
	 * this chip is treated as a legacy device for interrupt
	 * indication.  The following code for CMD
	 * chips may need to be revisited when we enable support for dma.
	 *
	 * CHANGE: DMA is not disabled for these devices. BM intr bit is
	 * checked only if there was DMA used or BM intr is useable on PIO,
	 * else treat it as before - as legacy device.
	 */

	if ((ata_ctlp->ac_pciide) &&
	    ((ata_ctlp->ac_pciide_bm != FALSE) &&
	    ((ata_ctlp->ac_active_pktp->ap_pciide_dma == TRUE) ||
	    !(ata_ctlp->ac_flags & AC_BMSTATREG_PIO_BROKEN)))) {

		if (!ata_pciide_status_pending(ata_ctlp))
			return (FALSE);
	} else {
		/*
		 * Interrupts from legacy ATA/IDE controllers are
		 * edge-triggered but the dumb legacy ATA/IDE controllers
		 * and drives don't have an interrupt status bit.
		 *
		 * Use a one_shot variable to make sure we only return
		 * one status per interrupt.
		 */
		if (intr_status != NULL) {
			int *one_shot = (int *)intr_status;

			if (*one_shot == 1)
				*one_shot = 0;
			else
				return (FALSE);
		}
	}

	/* check if device is still busy */

	status = ddi_get8(ata_ctlp->ac_iohandle2, ata_ctlp->ac_altstatus);
	if (status & ATS_BSY)
		return (FALSE);
	return (TRUE);
}


/*
 *
 * get the current status and clear the IRQ
 *
 */

int
ata_get_status_clear_intr(
	ata_ctl_t *ata_ctlp,
	ata_pkt_t *ata_pktp)
{
	uchar_t	status;

	/*
	 * Here's where we clear the PCI-IDE interrupt latch. If this
	 * request used DMA mode then we also have to check and clear
	 * the DMA error latch at the same time.
	 */

	if (ata_pktp->ap_pciide_dma) {
		if (ata_pciide_status_dmacheck_clear(ata_ctlp))
			ata_pktp->ap_flags |= AP_ERROR | AP_TRAN_ERROR;
	} else if ((ata_ctlp->ac_pciide) &&
	    !(ata_ctlp->ac_flags & AC_BMSTATREG_PIO_BROKEN)) {
		/*
		 * Some requests don't use DMA mode and therefore won't
		 * set the DMA error latch, but we still have to clear
		 * the interrupt latch.
		 * Controllers with broken BM intr in PIO mode do not go
		 * through this path.
		 */
		(void) ata_pciide_status_clear(ata_ctlp);
	}

	/*
	 * this clears the drive's interrupt
	 */
	status = ddi_get8(ata_ctlp->ac_iohandle1, ata_ctlp->ac_status);
	ADBG_TRACE(("ata_get_status_clear_intr: 0x%x\n", status));
	return (status);
}



/*
 *
 * GHD interrupt handler
 *
 */

/* ARGSUSED */
static void
ata_process_intr(
	void *hba_handle,
	void *intr_status)
{
	ata_ctl_t *ata_ctlp = (ata_ctl_t *)hba_handle;
	int	   watchdog;
	uchar_t	   fsm_func;
	int	   rc;

	ADBG_TRACE(("ata_process_intr entered\n"));

	/*
	 * process the ATA or ATAPI interrupt
	 */

	fsm_func = ATA_FSM_INTR;
	for (watchdog = ata_process_intr_watchdog; watchdog > 0; watchdog--) {
		rc =  ata_ctlr_fsm(fsm_func, ata_ctlp, NULL, NULL, NULL);

		switch (rc) {
		case ATA_FSM_RC_OKAY:
			return;

		case ATA_FSM_RC_BUSY:	/* wait for the next interrupt */
			return;

		case ATA_FSM_RC_INTR:	/* re-invoke the FSM */
			fsm_func = ATA_FSM_INTR;
			break;

		case ATA_FSM_RC_FINI:	/* move a request to done Q */
			fsm_func = ATA_FSM_FINI;
			break;
		}
	}
	ADBG_WARN(("ata_process_intr: watchdog\n"));
}



/*
 *
 * GHD ccc_hba_start callback
 *
 */

static int
ata_hba_start(
	void *hba_handle,
	gcmd_t *gcmdp)
{
	ata_ctl_t *ata_ctlp;
	ata_drv_t *ata_drvp;
	ata_pkt_t *ata_pktp;
	uchar_t	   fsm_func;
	int	   request_started;
	int	   watchdog;

	ADBG_TRACE(("ata_hba_start entered\n"));

	ata_ctlp = (ata_ctl_t *)hba_handle;

	if (ata_ctlp->ac_active_drvp != NULL) {
		ADBG_WARN(("ata_hba_start drvp not null\n"));
		return (FALSE);
	}
	if (ata_ctlp->ac_active_pktp != NULL) {
		ADBG_WARN(("ata_hba_start pktp not null\n"));
		return (FALSE);
	}

	ata_pktp = GCMD2APKT(gcmdp);
	ata_drvp = GCMD2DRV(gcmdp);

	/*
	 * which drive?
	 */
	if (ata_drvp->ad_targ == 0)
		fsm_func = ATA_FSM_START0;
	else
		fsm_func = ATA_FSM_START1;

	/*
	 * start the request
	 */
	request_started = FALSE;
	for (watchdog = ata_hba_start_watchdog; watchdog > 0; watchdog--) {
		switch (ata_ctlr_fsm(fsm_func, ata_ctlp, ata_drvp, ata_pktp,
		    NULL)) {
		case ATA_FSM_RC_OKAY:
			request_started = TRUE;
			goto fsm_done;

		case ATA_FSM_RC_BUSY:
			/* if first time, tell GHD to requeue the request */
			goto fsm_done;

		case ATA_FSM_RC_INTR:
			/*
			 * The start function polled for the next
			 * bus phase, now fake an interrupt to process
			 * the next action.
			 */
			request_started = TRUE;
			fsm_func = ATA_FSM_INTR;
			ata_drvp = NULL;
			ata_pktp = NULL;
			break;

		case ATA_FSM_RC_FINI: /* move request to the done queue */
			request_started = TRUE;
			fsm_func = ATA_FSM_FINI;
			ata_drvp = NULL;
			ata_pktp = NULL;
			break;
		}
	}
	ADBG_WARN(("ata_hba_start: watchdog\n"));

fsm_done:
	return (request_started);

}

static int
ata_check_pciide_blacklist(
	dev_info_t *dip,
	uint_t flags)
{
	ushort_t vendorid;
	ushort_t deviceid;
	pcibl_t	*blp;
	int	*propp;
	uint_t	 count;
	int	 rc;


	vendorid = ddi_prop_get_int(DDI_DEV_T_ANY, ddi_get_parent(dip),
	    DDI_PROP_DONTPASS, "vendor-id", 0);
	deviceid = ddi_prop_get_int(DDI_DEV_T_ANY, ddi_get_parent(dip),
	    DDI_PROP_DONTPASS, "device-id", 0);

	/*
	 * first check for a match in the "pci-ide-blacklist" property
	 */
	rc = ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip, 0,
	    "pci-ide-blacklist", &propp, &count);

	if (rc == DDI_PROP_SUCCESS) {
		count = (count * sizeof (uint_t)) / sizeof (pcibl_t);
		blp = (pcibl_t *)propp;
		while (count--) {
			/* check for matching ID */
			if ((vendorid & blp->b_vmask)
			    != (blp->b_vendorid & blp->b_vmask)) {
				blp++;
				continue;
			}
			if ((deviceid & blp->b_dmask)
			    != (blp->b_deviceid & blp->b_dmask)) {
				blp++;
				continue;
			}

			/* got a match */
			if (blp->b_flags & flags) {
				ddi_prop_free(propp);
				return (TRUE);
			} else {
				ddi_prop_free(propp);
				return (FALSE);
			}
		}
		ddi_prop_free(propp);
	}

	/*
	 * then check the built-in blacklist
	 */
	for (blp = ata_pciide_blacklist; blp->b_vendorid; blp++) {
		if ((vendorid & blp->b_vmask) != blp->b_vendorid)
			continue;
		if ((deviceid & blp->b_dmask) != blp->b_deviceid)
			continue;
		if (!(blp->b_flags & flags))
			continue;
		return (TRUE);
	}
	return (FALSE);
}

int
ata_check_drive_blacklist(
	struct ata_id *aidp,
	uint_t flags)
{
	atabl_t	*blp;

	for (blp = ata_drive_blacklist; blp->b_model != NULL; blp++) {
		if (!ata_strncmp(blp->b_model, aidp->ai_model,
		    sizeof (aidp->ai_model)))
			continue;
		if (blp->b_fw != NULL) {
			if (!ata_strncmp(blp->b_fw, aidp->ai_fw,
			    sizeof (aidp->ai_fw)))
				continue;
		}
		if (blp->b_flags & flags)
			return (TRUE);
		return (FALSE);
	}
	return (FALSE);
}

/*
 * Queue a request to perform some sort of internally
 * generated command. When this request packet reaches
 * the front of the queue (*func)() is invoked.
 *
 */

int
ata_queue_cmd(
	int	  (*func)(ata_ctl_t *, ata_drv_t *, ata_pkt_t *),
	void	  *arg,
	ata_ctl_t *ata_ctlp,
	ata_drv_t *ata_drvp,
	gtgt_t	  *gtgtp)
{
	ata_pkt_t	*ata_pktp;
	gcmd_t		*gcmdp;
	int		 rc;

	if (!(gcmdp = ghd_gcmd_alloc(gtgtp, sizeof (*ata_pktp), TRUE))) {
		ADBG_ERROR(("atapi_id_update alloc failed\n"));
		return (FALSE);
	}


	/* set the back ptr from the ata_pkt to the gcmd_t */
	ata_pktp = GCMD2APKT(gcmdp);
	ata_pktp->ap_gcmdp = gcmdp;
	ata_pktp->ap_hd = ata_drvp->ad_drive_bits;
	ata_pktp->ap_bytes_per_block = ata_drvp->ad_bytes_per_block;

	/*
	 * over-ride the default start function
	 */
	ata_pktp = GCMD2APKT(gcmdp);
	ata_pktp->ap_start = func;
	ata_pktp->ap_complete = NULL;
	ata_pktp->ap_v_addr = (caddr_t)arg;

	/*
	 * add it to the queue, when it gets to the front the
	 * ap_start function is called.
	 */
	rc = ghd_transport(&ata_ctlp->ac_ccc, gcmdp, gcmdp->cmd_gtgtp,
	    0, TRUE, NULL);

	if (rc != TRAN_ACCEPT) {
		/* this should never, ever happen */
		return (FALSE);
	}

	if (ata_pktp->ap_flags & AP_ERROR)
		return (FALSE);
	return (TRUE);
}

/*
 * Check if this drive has the "revert to defaults" bug
 * PSARC 2001/500 and 2001/xxx - check for the properties
 * ata-revert-to-defaults and atarvrt-<diskmodel> before
 * examining the blacklist.
 * <diskmodel> is made from the model number reported by Identify Drive
 * with uppercase letters converted to lowercase and all characters
 * except letters, digits, ".", "_", and "-" deleted.
 * Return value:
 *	TRUE:	enable revert to defaults
 *	FALSE:	disable revert to defaults
 *
 * NOTE: revert to power on defaults that includes reverting to MDMA
 * mode is allowed by ATA-6 & ATA-7 specs.
 * Therefore drives exhibiting this behaviour are not violating the spec.
 * Furthermore, the spec explicitly says that after the soft reset
 * host should check the current setting of the device features.
 * Correctly working BIOS would therefore reprogram either the drive
 * and/or the host controller to match transfer modes.
 * Devices with ATA_BL_NORVRT flag will be removed from
 * the ata_blacklist.
 * The default behaviour will be - no revert to power-on defaults
 * for all devices. The property is retained in case the user
 * explicitly requests revert-to-defaults before reboot.
 */

#define	ATA_REVERT_PROP_PREFIX "revert-"
#define	ATA_REVERT_PROP_GLOBAL	"ata-revert-to-defaults"
/* room for prefix + model number + terminating NUL character */
#define	PROP_BUF_SIZE	(sizeof (ATA_REVERT_PROP_PREFIX) + \
				sizeof (aidp->ai_model) + 1)
#define	PROP_LEN_MAX	(31)

static int
ata_check_revert_to_defaults(
	ata_drv_t *ata_drvp)
{
	struct ata_id	*aidp = &ata_drvp->ad_id;
	ata_ctl_t	*ata_ctlp = ata_drvp->ad_ctlp;
	char	 prop_buf[PROP_BUF_SIZE];
	int	 i, j;
	int	 propval;

	/* put prefix into the buffer */
	(void) strcpy(prop_buf, ATA_REVERT_PROP_PREFIX);
	j = strlen(prop_buf);

	/* append the model number, leaving out invalid characters */
	for (i = 0;  i < sizeof (aidp->ai_model);  ++i) {
		char c = aidp->ai_model[i];
		if (c >= 'A' && c <= 'Z')	/* uppercase -> lower */
			c = c - 'A' + 'a';
		if (c >= 'a' && c <= 'z' || c >= '0' && c <= '9' ||
		    c == '.' || c == '_' || c == '-')
			prop_buf[j++] = c;
		if (c == '\0')
			break;
	}

	/* make sure there's a terminating NUL character */
	if (j >= PROP_LEN_MAX)
		j =  PROP_LEN_MAX;
	prop_buf[j] = '\0';

	/* look for a disk-specific "revert" property" */
	propval = ddi_getprop(DDI_DEV_T_ANY, ata_ctlp->ac_dip,
	    DDI_PROP_DONTPASS, prop_buf, -1);
	if (propval == 0)
		return (FALSE);
	else if (propval != -1)
		return (TRUE);

	/* look for a global "revert" property" */
	propval = ddi_getprop(DDI_DEV_T_ANY, ata_ctlp->ac_dip,
	    0, ATA_REVERT_PROP_GLOBAL, -1);
	if (propval == 0)
		return (FALSE);
	else if (propval != -1)
		return (TRUE);

	return (FALSE);
}

void
ata_show_transfer_mode(ata_ctl_t *ata_ctlp, ata_drv_t *ata_drvp)
{
	int i;

	if (ata_ctlp->ac_pciide_bm == FALSE ||
	    ata_drvp->ad_pciide_dma != ATA_DMA_ON) {
		if (ata_cntrl_DMA_sel_msg) {
			ATAPRT((
			    "?\tATA DMA off: %s\n", ata_cntrl_DMA_sel_msg));
		} else if (ata_dev_DMA_sel_msg) {
			ATAPRT(("?\tATA DMA off: %s\n", ata_dev_DMA_sel_msg));
		}
		ATAPRT(("?\tPIO mode %d selected\n",
		    (ata_drvp->ad_id.ai_advpiomode & ATAC_ADVPIO_4_SUP) ==
		    ATAC_ADVPIO_4_SUP ? 4 : 3));
	} else {
		/* Using DMA */
		if (ata_drvp->ad_id.ai_dworddma & ATAC_MDMA_SEL_MASK) {
			/*
			 * Rely on the fact that either dwdma or udma is
			 * selected, not both.
			 */
			ATAPRT(("?\tMultiwordDMA mode %d selected\n",
			    (ata_drvp->ad_id.ai_dworddma & ATAC_MDMA_2_SEL) ==
			    ATAC_MDMA_2_SEL ? 2 :
			    (ata_drvp->ad_id.ai_dworddma & ATAC_MDMA_1_SEL) ==
			    ATAC_MDMA_1_SEL ? 1 : 0));
		} else {
			for (i = 0; i <= 6; i++) {
				if (ata_drvp->ad_id.ai_ultradma &
				    (1 << (i + 8))) {
					ATAPRT((
					    "?\tUltraDMA mode %d selected\n",
					    i));
					break;
				}
			}
		}
	}
}

/*
 * Controller-specific operation pointers.
 * Should be extended as needed - init only for now
 */
struct ata_ctl_spec_ops {
	uint_t	(*cs_init)(dev_info_t *, ushort_t, ushort_t); /* ctlr init */
};


struct ata_ctl_spec {
	ushort_t		cs_vendor_id;
	ushort_t		cs_device_id;
	struct ata_ctl_spec_ops	*cs_ops;
};

/* Sil3XXX-specific functions (init only for now) */
struct ata_ctl_spec_ops sil3xxx_ops = {
	&sil3xxx_init_controller	/* Sil3XXX cntrl initialization */
};


struct ata_ctl_spec ata_cntrls_spec[] = {
	{0x1095, 0x3114, &sil3xxx_ops},
	{0x1095, 0x3512, &sil3xxx_ops},
	{0x1095, 0x3112, &sil3xxx_ops},
	{0, 0, NULL}		/* List must end with cs_ops set to NULL */
};

/*
 * Do controller specific initialization if necessary.
 * Pick-up controller specific functions.
 */

int
ata_spec_init_controller(dev_info_t *dip)
{
	ushort_t		vendor_id;
	ushort_t		device_id;
	struct ata_ctl_spec	*ctlsp;

	vendor_id = ddi_prop_get_int(DDI_DEV_T_ANY, ddi_get_parent(dip),
	    DDI_PROP_DONTPASS, "vendor-id", 0);
	device_id = ddi_prop_get_int(DDI_DEV_T_ANY, ddi_get_parent(dip),
	    DDI_PROP_DONTPASS, "device-id", 0);

	/* Locate controller specific ops, if they exist */
	ctlsp = ata_cntrls_spec;
	while (ctlsp->cs_ops != NULL) {
		if (ctlsp->cs_vendor_id == vendor_id &&
		    ctlsp->cs_device_id == device_id)
			break;
		ctlsp++;
	}

	if (ctlsp->cs_ops != NULL) {
		if (ctlsp->cs_ops->cs_init != NULL) {
			/* Initialize controller */
			if ((*(ctlsp->cs_ops->cs_init))
			    (dip, vendor_id, device_id) != TRUE) {
				cmn_err(CE_WARN,
				    "pci%4x,%4x cntrl specific "
				    "initialization failed",
				    vendor_id, device_id);
				return (FALSE);
			}
		}
	}
	return (TRUE);
}

/*
 * this routine works like ddi_prop_get_int, except that it works on
 * a string property that contains ascii representations
 * of an integer.
 * If the property is not found, the default value is returned.
 */
static int
ata_prop_lookup_int(dev_t match_dev, dev_info_t *dip,
    uint_t flags, char *name, int defvalue)
{

	char *bufp, *cp;
	int rc = defvalue;
	int proprc;

	proprc = ddi_prop_lookup_string(match_dev, dip,
	    flags, name, &bufp);

	if (proprc == DDI_PROP_SUCCESS) {
		cp = bufp;
		rc = stoi(&cp);
		ddi_prop_free(bufp);
	} else {
		/*
		 * see if property is encoded as an int instead of string.
		 */
		rc = ddi_prop_get_int(match_dev, dip, flags, name, defvalue);
	}

	return (rc);
}

/*
 * Initialize the power management components
 */
static void
ata_init_pm(dev_info_t *dip)
{
	int		instance;
	ata_ctl_t 	*ata_ctlp;
#ifdef	ATA_USE_AUTOPM
	char		pmc_name[16];
	char		*pmc[] = {
				NULL,
				"0=Sleep (PCI D3 State)",
				"3=PowerOn (PCI D0 State)",
				NULL
			};
#endif


	instance = ddi_get_instance(dip);
	ata_ctlp = ddi_get_soft_state(ata_state, instance);
	ata_ctlp->ac_pm_support = 0;

	/* check PCI capabilities */
	if (!ata_is_pci(dip))
		return;

#ifdef	ATA_USE_AUTOPM
	(void) sprintf(pmc_name, "NAME=ata%d", instance);
	pmc[0] = pmc_name;

	if (ddi_prop_update_string_array(DDI_DEV_T_NONE, dip,
	    "pm-components", pmc, 3) != DDI_PROP_SUCCESS) {
		return;
	}
#endif

	ata_ctlp->ac_pm_support = 1;
	ata_ctlp->ac_pm_level = PM_LEVEL_D0;

	ATA_BUSY_COMPONENT(dip, 0);
	if (ATA_RAISE_POWER(dip, 0, PM_LEVEL_D0) != DDI_SUCCESS) {
		(void) ddi_prop_remove(DDI_DEV_T_NONE, dip, "pm-components");
	}
	ATA_IDLE_COMPONENT(dip, 0);
}

/*
 * resume the hard drive
 */
static void
ata_resume_drive(ata_drv_t *ata_drvp)
{
	ata_ctl_t *ata_ctlp = ata_drvp->ad_ctlp;
	int drive_type;
	struct ata_id id;

	ADBG_TRACE(("ata_resume_drive entered\n"));

	drive_type = ata_drive_type(ata_drvp->ad_drive_bits,
	    ata_ctlp->ac_iohandle1, ata_ctlp->ac_ioaddr1,
	    ata_ctlp->ac_iohandle2, ata_ctlp->ac_ioaddr2,
	    &id);
	if (drive_type == ATA_DEV_NONE)
		return;

	if (!ATAPIDRV(ata_drvp)) {
		/* Reset Ultra DMA mode */
		ata_reset_dma_mode(ata_drvp);
		if (!ata_disk_setup_parms(ata_ctlp, ata_drvp))
			return;
	} else {
		(void) atapi_init_drive(ata_drvp);
		if (ata_drvp->ad_dma_mode != 0) {
			(void) atapi_reset_dma_mode(ata_drvp, FALSE);
			if (!ata_check_dma_mode(ata_drvp))
				atapi_reset_dma_mode(ata_drvp, TRUE);
			if (ata_drvp->ad_id.ai_ultradma !=
			    ata_drvp->ad_dma_mode) {
				ata_drvp->ad_pciide_dma = ATA_DMA_OFF;
			} else {
				ata_drvp->ad_pciide_dma = ATA_DMA_ON;
			}
		}
	}
	(void) ata_set_feature(ata_ctlp, ata_drvp, ATSF_DIS_REVPOD, 0);

}

/*
 * resume routine, it will be run when get the command
 * DDI_RESUME at attach(9E) from system power management
 */
static int
ata_resume(dev_info_t *dip)
{
	int		instance;
	ata_ctl_t 	*ata_ctlp;
	ddi_acc_handle_t io_hdl2;
	caddr_t		ioaddr2;

	instance = ddi_get_instance(dip);
	ata_ctlp = ddi_get_soft_state(ata_state, instance);

	if (!ata_ctlp->ac_pm_support)
		return (DDI_FAILURE);
	if (ata_ctlp->ac_pm_level == PM_LEVEL_D0)
		return (DDI_SUCCESS);

	ATA_BUSY_COMPONENT(dip, 0);
	if (ATA_RAISE_POWER(dip, 0, PM_LEVEL_D0) == DDI_FAILURE)
		return (DDI_FAILURE);
	ATA_IDLE_COMPONENT(dip, 0);

	/* enable interrupts from the device */
	io_hdl2 = ata_ctlp->ac_iohandle2;
	ioaddr2 = ata_ctlp->ac_ioaddr2;
	ddi_put8(io_hdl2, (uchar_t *)ioaddr2 + AT_DEVCTL, ATDC_D3);
	ata_ctlp->ac_pm_level = PM_LEVEL_D0;

	return (DDI_SUCCESS);
}

/*
 * suspend routine, it will be run when get the command
 * DDI_SUSPEND at detach(9E) from system power management
 */
static int
ata_suspend(dev_info_t *dip)
{
	int		instance;
	ata_ctl_t 	*ata_ctlp;
	ddi_acc_handle_t io_hdl2;

	instance = ddi_get_instance(dip);
	ata_ctlp = ddi_get_soft_state(ata_state, instance);

	if (!ata_ctlp->ac_pm_support)
		return (DDI_FAILURE);
	if (ata_ctlp->ac_pm_level == PM_LEVEL_D3)
		return (DDI_SUCCESS);

	/* disable interrupts and turn the software reset bit on */
	io_hdl2 = ata_ctlp->ac_iohandle2;
	ddi_put8(io_hdl2, ata_ctlp->ac_devctl, (ATDC_D3 | ATDC_SRST));

	(void) ata_reset_bus(ata_ctlp);
	(void) ata_change_power(dip, ATC_SLEEP);
	ata_ctlp->ac_pm_level = PM_LEVEL_D3;
	return (DDI_SUCCESS);
}

int ata_save_pci_config = 0;
/*
 * ata specific power management entry point, it was
 * used to change the power management component
 */
static int
ata_power(dev_info_t *dip, int component, int level)
{
	int		instance;
	ata_ctl_t 	*ata_ctlp;
	uint8_t		cmd;

	ADBG_TRACE(("ata_power entered, component = %d, level = %d\n",
	    component, level));

	instance = ddi_get_instance(dip);
	ata_ctlp = ddi_get_soft_state(ata_state, instance);
	if (ata_ctlp == NULL || component != 0)
		return (DDI_FAILURE);

	if (!ata_ctlp->ac_pm_support)
		return (DDI_FAILURE);

	if (ata_ctlp->ac_pm_level == level)
		return (DDI_SUCCESS);

	switch (level) {
	case PM_LEVEL_D0:
		if (ata_save_pci_config)
			(void) pci_restore_config_regs(dip);
		ata_ctlp->ac_pm_level = PM_LEVEL_D0;
		cmd = ATC_IDLE_IMMED;
		break;
	case PM_LEVEL_D3:
		if (ata_save_pci_config)
			(void) pci_save_config_regs(dip);
		ata_ctlp->ac_pm_level = PM_LEVEL_D3;
		cmd = ATC_SLEEP;
		break;
	default:
		return (DDI_FAILURE);
	}
	return (ata_change_power(dip, cmd));
}

/*
 * sent commands to ata controller to change the power level
 */
static int
ata_change_power(dev_info_t *dip, uint8_t cmd)
{
	int		instance;
	ata_ctl_t	*ata_ctlp;
	ata_drv_t	*ata_drvp;
	uchar_t		targ;
	struct ata_id	id;
	uchar_t		lun;
	uchar_t		lastlun;
	struct ata_id	*aidp;

	ADBG_TRACE(("ata_change_power entered, cmd = %d\n", cmd));

	instance = ddi_get_instance(dip);
	ata_ctlp = ddi_get_soft_state(ata_state, instance);

	/*
	 * Issue command on each disk device on the bus.
	 */
	if (cmd == ATC_SLEEP) {
		for (targ = 0; targ < ATA_MAXTARG; targ++) {
			ata_drvp = CTL2DRV(ata_ctlp, targ, 0);
			if (ata_drvp == NULL)
				continue;
			if (ata_drvp->ad_dma_cap == 0 &&
			    ata_drvp->ad_pciide_dma == ATA_DMA_ON) {
				aidp = &ata_drvp->ad_id;
				if ((aidp->ai_validinfo & ATAC_VALIDINFO_83) &&
				    (aidp->ai_ultradma & ATAC_UDMA_SEL_MASK)) {
					ata_drvp->ad_dma_cap =
					    ATA_DMA_ULTRAMODE;
					ata_drvp->ad_dma_mode =
					    aidp->ai_ultradma;
				} else if (aidp->ai_dworddma &
				    ATAC_MDMA_SEL_MASK) {
					ata_drvp->ad_dma_cap =
					    ATA_DMA_MWORDMODE;
					ata_drvp->ad_dma_mode =
					    aidp->ai_dworddma;
				}
			}
			if (ata_drive_type(ata_drvp->ad_drive_bits,
			    ata_ctlp->ac_iohandle1, ata_ctlp->ac_ioaddr1,
			    ata_ctlp->ac_iohandle2, ata_ctlp->ac_ioaddr2,
			    &id) != ATA_DEV_DISK)
				continue;
			(void) ata_flush_cache(ata_ctlp, ata_drvp);
			if (!ata_command(ata_ctlp, ata_drvp, TRUE, TRUE,
			    5 * 1000000, cmd, 0, 0, 0, 0, 0, 0)) {
				cmn_err(CE_WARN, "!ata_controller - Can not "
				    "put drive %d in to power mode %u",
				    targ, cmd);
				(void) ata_devo_reset(dip, DDI_RESET_FORCE);
				return (DDI_FAILURE);
			}
		}
		return (DDI_SUCCESS);
	}

	(void) ata_software_reset(ata_ctlp);
	for (targ = 0; targ < ATA_MAXTARG; targ++) {
		ata_drvp = CTL2DRV(ata_ctlp, targ, 0);
		if (ata_drvp == NULL)
			continue;
		ata_resume_drive(ata_drvp);

		if (ATAPIDRV(ata_drvp))
			lastlun = ata_drvp->ad_id.ai_lastlun;
		else
			lastlun = 0;
		if (!ata_enable_atapi_luns)
			lastlun = 0;
		for (lun = 1; lun <= lastlun && lun < ATA_MAXLUN; lun++) {
			ata_drvp = CTL2DRV(ata_ctlp, targ, lun);
			if (ata_drvp != NULL)
				ata_resume_drive(ata_drvp);
		}
	}

	return (DDI_SUCCESS);
}

/*
 * return 1 when ata controller is a pci device,
 * otherwise return 0
 */
static int
ata_is_pci(dev_info_t *dip)
{
	int rc;
	char *bufp;
	int ispci;

	rc = ddi_prop_lookup_string(DDI_DEV_T_ANY, ddi_get_parent(dip),
	    DDI_PROP_DONTPASS, "device_type", &bufp);

	if (rc != DDI_PROP_SUCCESS) {
		ADBG_ERROR(("ata_is_pci !device_type\n"));
		return (0);
	}

	ispci = (strcmp(bufp, "pci-ide") == 0);

	ddi_prop_free(bufp);

	return (ispci);
}

/*
 * Disable DMA for this drive
 */
static void
ata_disable_DMA(ata_drv_t *ata_drvp)
{
	struct ata_id *aidp;
	char buf[sizeof (aidp->ai_model) +2];
	int i;

	if (ata_drvp == NULL)
		return;

	if (ata_drvp->ad_pciide_dma == ATA_DMA_OFF)
		return;

	ata_drvp->ad_pciide_dma = ATA_DMA_OFF;

	/* Print the message */
	buf[0] = '\0';
	aidp = &ata_drvp->ad_id;
	if (aidp != NULL) {
		(void) strncpy(buf, aidp->ai_model, sizeof (aidp->ai_model));
		buf[sizeof (aidp->ai_model) -1] = '\0';
		for (i = sizeof (aidp->ai_model) - 2; buf[i] == ' '; i--)
			buf[i] = '\0';
	}
	cmn_err(CE_CONT,
	    "?DMA disabled on %s target=%d, lun=%d due to DMA errors,",
	    buf, ata_drvp->ad_targ, ata_drvp->ad_lun);
	cmn_err(CE_CONT, "?most likely due to the CF-to-IDE adapter.");
}

/*
 * Check and select DMA mode
 *
 * TRUE is returned when set feature is called successfully,
 * otherwise return FALSE
 */
int
ata_set_dma_mode(ata_ctl_t *ata_ctlp, ata_drv_t *ata_drvp)
{
	struct ata_id *aidp;
	int mode, rval = FALSE;
	uint8_t subcmd;

	aidp = &ata_drvp->ad_id;

	/* Return directly if DMA is not supported */
	if (!(aidp->ai_cap & ATAC_DMA_SUPPORT))
		return (rval);

	/* Return if DMA mode is already selected */
	if (((aidp->ai_validinfo & ATAC_VALIDINFO_83) &&
	    (aidp->ai_ultradma & ATAC_UDMA_SEL_MASK)) ||
	    (aidp->ai_dworddma & ATAC_MDMA_SEL_MASK))
		return (rval);

	/* First check Ultra DMA mode if no DMA is selected */
	if ((aidp->ai_validinfo & ATAC_VALIDINFO_83) &&
	    (aidp->ai_ultradma & ATAC_UDMA_SUP_MASK)) {
		for (mode = 6; mode >= 0; --mode) {
			if (aidp->ai_ultradma & (1 << mode))
				break;
		}
		subcmd = ATF_XFRMOD_UDMA;

	} else if (aidp->ai_dworddma & ATAC_MDMA_SUP_MASK) {
		/* Then check multi-word DMA mode */
		for (mode = 2; mode >= 0; --mode) {
			if (aidp->ai_dworddma & (1 << mode))
				break;
		}
		subcmd = ATF_XFRMOD_MDMA;

	} else {
		return (rval);
	}

	rval = ata_set_feature(ata_ctlp, ata_drvp, ATSF_SET_XFRMOD,
	    subcmd|mode);

	return (rval);
}

/*
 * Reset Ultra DMA mode / MWDMA mode
 */
void
ata_reset_dma_mode(ata_drv_t *ata_drvp)
{
	uint8_t	subcmd;
	int	mode;
	ata_ctl_t *ata_ctlp = ata_drvp->ad_ctlp;

	switch (ata_drvp->ad_dma_cap) {
	case ATA_DMA_ULTRAMODE:
		subcmd = ATF_XFRMOD_UDMA;
		for (mode = 0; mode <= 6; mode++) {
			if (ata_drvp->ad_dma_mode & (1 << (mode + 8)))
				break;
		}
		break;
	case ATA_DMA_MWORDMODE:
		subcmd = ATF_XFRMOD_MDMA;
		mode = ((ata_drvp->ad_dma_mode & ATAC_MDMA_2_SEL) ==
		    ATAC_MDMA_2_SEL ? 2 :
		    (ata_drvp->ad_dma_mode & ATAC_MDMA_1_SEL) ==
		    ATAC_MDMA_1_SEL ? 1 : 0);
		break;
	default:
		return;
	}

	(void) ata_set_feature(ata_ctlp, ata_drvp, ATSF_SET_XFRMOD,
	    (subcmd | mode));
}

/*
 * Check DMA mode is the same with saved info
 * return value: 0 - not same
 *		 1 - same
 */
static int
ata_check_dma_mode(ata_drv_t *ata_drvp)
{
	struct ata_id	*aidp;

	aidp = &ata_drvp->ad_id;
	switch (ata_drvp->ad_dma_cap) {
	case ATA_DMA_ULTRAMODE:
		if ((aidp->ai_validinfo & ATAC_VALIDINFO_83) &&
		    (aidp->ai_ultradma & ATAC_UDMA_SEL_MASK) &&
		    (aidp->ai_ultradma == ata_drvp->ad_dma_mode))
			break;
		else
			return (0);
	case ATA_DMA_MWORDMODE:
		if ((aidp->ai_dworddma & ATAC_MDMA_SEL_MASK) &&
		    (aidp->ai_dworddma == ata_drvp->ad_dma_mode))
			break;
		else
			return (0);
	default:
		return (0);
	}
	return (1);
}
