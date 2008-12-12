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
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#include <sys/devops.h>			/* used by dev_ops */
#include <sys/conf.h>			/* used by dev_ops and cb_ops */
#include <sys/modctl.h>			/* used by modlinkage, modldrv, */
					/* _init, _info, and _fini */
#include <sys/types.h>			/* used by open, close, read, write, */
					/* prop_op, and ddi_prop_op */
#include <sys/file.h>			/* used by open, close */
#include <sys/errno.h>			/* used by open, close, read, write */
#include <sys/open.h>			/* used by open, close, read, write */
#include <sys/cred.h>			/* used by open, close, read */
#include <sys/uio.h>			/* used by read */
#include <sys/stat.h>			/* defines S_IFCHR used by */
					/* ddi_create_minor_node */
#include <sys/cmn_err.h>		/* used by all entry points for */
					/* this driver */
#include <sys/mkdev.h>
#include <sys/ddi.h>			/* used by all entry points for */
					/* this driver also used by cb_ops, */
					/* ddi_get_instance, and ddi_prop_op */
#include <sys/sunddi.h>			/* used by all entry points for */
					/* this driver also used by cb_ops, */
					/* ddi_create_minor_node, */
					/* ddi_get_instance, and ddi_prop_op */
#include <sys/sunldi.h>
#include <sys/scsi/impl/uscsi.h>
#include <sys/signal.h>
#include <sys/kmem.h>
#include <sys/ksynch.h>
#include <sys/int_types.h>
#include <sys/scsi/scsi_ctl.h>
#include <sys/scsi/scsi_pkt.h>
#include <sys/scsi/generic/sense.h>
#include <sys/scsi/generic/status.h>
#include <sys/scsi/generic/commands.h>
#include <sys/scsi/targets/stdef.h>
#include <sys/mtio.h>
#include <mms_dmd.h>
#include <dmd_impl.h>

typedef	struct	dmd_sym {
	char	*dmd_sym;
	int	dmd_code;
}	dmd_sym_t;

static	dmd_sym_t	dmd_scsi_cmd_tab[] = {
	"test unit ready",	SCMD_TEST_UNIT_READY,
	"request sense",	SCMD_REQUEST_SENSE,
	"read",			SCMD_READ,
	"write",		SCMD_WRITE,
	"inquiry",		SCMD_INQUIRY,
	"mode select",		SCMD_MODE_SELECT,
	"reserve",		SCMD_RESERVE,
	"release",		SCMD_RELEASE,
	"mode sense",		SCMD_MODE_SENSE,
	"rewind",		SCMD_REWIND,
	"read block limit",	SCMD_READ_BLKLIM,
	"write tapemark",	SCMD_WRITE_FILE_MARK,
	"space",		SCMD_SPACE,
	"erase",		SCMD_ERASE,
	"mode sense",		SCMD_MODE_SENSE,
	"load",			SCMD_LOAD,
	"persistent reserve in", SCMD_PRIN,
	"persistent reserve out", SCMD_PROUT,
	"locate",		SCMD_LOCATE,
	"read position",	SCMD_READ_POSITION,
	"report density",	SCMD_REPORT_DENSITIES,
	"log select",		SCMD_LOG_SELECT_G1,
	"log sense",		SCMD_LOG_SENSE_G1,
	NULL, 0,
};

static	dmd_sym_t	dmd_mtop_tab[] = {
	"MTSEEK",		MTSEEK,
	"MTTELL",		MTTELL,
	"MTWEOF",		MTWEOF,
	"MTFSF",		MTFSF,
	"MTBSF",		MTBSF,
	"MTFSR",		MTFSR,
	"MTBSR",		MTBSR,
	"MTREW",		MTREW,
	"MTOFFL",		MTOFFL,
	"MTNOP",		MTNOP,
	"MTRETEN",		MTRETEN,
	"MTERASE",		MTERASE,
	"MTEOM",		MTEOM,
	"MTNBSF",		MTNBSF,
	"MTSRSZ",		MTSRSZ,
	"MTGRSZ",		MTGRSZ,
	"MTLOAD",		MTLOAD,
	NULL,			0,			/* Must be last entry */
};

static	dmd_sym_t	dmd_ioctl_tab[] = {
	"MTIOCTOP",		MTIOCTOP,
	"MTIOCGET",		MTIOCGET,
	"MTIOCGETDRIVETYPE",	MTIOCGETDRIVETYPE,
	"MTIOCPERSISTENT",	MTIOCPERSISTENT,
	"MTIOCPERSISTENTSTATUS", MTIOCPERSISTENTSTATUS,
	"MTIOCLRERR",		MTIOCLRERR,
	"MTIOCGUARANTEEDORDER",	MTIOCGUARANTEEDORDER,
	"MTIOCRESERVE",		MTIOCRESERVE,
	"MTIOCRELEASE",		MTIOCRELEASE,
	"MTIOCFORCERESERVE",	MTIOCFORCERESERVE,
	"MTIOCGETERROR",	MTIOCGETERROR,
	"MTIOCSTATE",		MTIOCSTATE,
	"MTIOCREADIGNOREILI",	MTIOCREADIGNOREILI,
	"MTIOCREADIGNOREEOFS",	MTIOCREADIGNOREEOFS,
	"MTIOCSHORTFMK",	MTIOCSHORTFMK,
	"MTIOCGETPOS",		MTIOCGETPOS,
	"MTIOCRESTPOS",		MTIOCRESTPOS,
	"MTIOCLTOP",		MTIOCLTOP,
	NULL,			0,
};

/*
 * dmd.conf
 * name="dmd" parent="pseudo" ;
 */

static	void		*dmd_soft_statep;
static	dmd_wcr_t	*dmd_wcr_p;
static	dmd_stat_t	*dmd_stat_p;
static	major_t		dmd_major;
static	int		dmd_next_ord = DMD_FIRST_DEV_ORDINAL;

/*
 * To turn dmd_debug messages on, set dmd_debug to 1 by doing:
 * echo 'dmd_debug/W 1' | mdb -kw
 * or add the following to /etc/system and reboot:
 * set dmd:dmd_debug=1
 */
int		dmd_debug = 0;
/*
 * State variables
 */
static	int		dmd_state = DMD_NOT_READY;	/* Initialized to */
							/* NOT_READY. Set to */
							/* READY after the */
							/* watcher device is */
							/* opened */
static	kmutex_t	dmd_state_mutex;
static	int		dmd_busy = 0;
static	kmutex_t	dmd_busy_mutex;
static	kmutex_t	dmd_sync_mutex;	/* Synchronize DM's */

static	int dmd_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static	int dmd_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);
static	int dmd_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg,
    void **resultp);
static	int dmd_prop_op(dev_t dev, dev_info_t *dip, ddi_prop_op_t prop_op,
    int flags, char *name, caddr_t valuep, int *lengthp);
static	int dmd_open(dev_t *devp, int flags, int otyp, cred_t *cred);
static	int dmd_close(dev_t dev, int flags, int otyp, cred_t *cred);
static	int dmd_read(dev_t dev, struct uio *uiop, cred_t *credp);
static	int dmd_read_drm(dmd_drm_t *, struct uio *, cred_t *);
static	int dmd_read_tdv(dmd_tdv_t *, struct uio *, cred_t *);
static	int dmd_write(dev_t dev, struct uio *uiop, cred_t *credp);
static	int dmd_write_drm(dmd_drm_t *, struct uio *, cred_t *);
static	int dmd_write_tdv(dmd_tdv_t *, struct uio *, cred_t *);
static	int dmd_open_wcr(dmd_wcr_t *ss);
static	int dmd_open_stat(dmd_stat_t *ss);
static	int dmd_open_drm(dmd_drm_t *ss, dev_t *devp, int flags, int otyp,
    cred_t *cred);
static	int dmd_open_tdv(dmd_tdv_t *ss, dev_t *devp, int flags, int otyp,
    cred_t *cred);
static	int dmd_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
    int *rvalp);
static	int dmd_ioctl_wcr(dmd_wcr_t *ss, int cmd, intptr_t arg);
static	int dmd_ioctl_stat(dmd_stat_t *ss, int cmd, intptr_t arg, int mode);
static	int dmd_ioctl_drm(dmd_drm_t *ss, int cmd, intptr_t arg,
    int mode, cred_t *credp, int *rvalp);
static	int dmd_ioctl_tdv(dmd_tdv_t *ss, int cmd, intptr_t arg,
    int mode, int *rvalp);
static	int dmd_close_wcr(dmd_wcr_t *ss);
static	int dmd_close_stat(dmd_stat_t *ss);
static	int dmd_close_drm(dmd_drm_t *ss, dev_t dev, cred_t *cred);
static	int dmd_close_tdv(dmd_tdv_t *ss, dev_t dev);
static	int dmd_ldi_open(dmd_drm_t *ss, cred_t *cred);
static	int dmd_ldi_close(dmd_drm_t *ss, cred_t *cred);
static	int dmd_create_dev(dmd_wcr_t *wcr, char *devpfx, int inst,
    dmd_soft_state_t **rss, dev_info_t **rdip);
static	int dmd_bind_dev(dmd_drm_t *drm, drm_target_t *targ, cred_t *credp);
static	int dmd_signal_drm(dmd_drm_t *drm);
static	int dmd_mtioclrerr(dmd_tdv_t *tdv);
static	int dmd_mtioctop(dmd_tdv_t *tdv, intptr_t arg, int mode, struct mtop *);
static	int dmd_mtiocltop(dmd_tdv_t *tdv, intptr_t arg,
    int mode, struct mtlop *);
static	int dmd_chk_allowed_cmd(dmd_tdv_t *tdv, int cmd,
    intptr_t arg, int mode, int *rvalp);
static	int dmd_get_disallowed(dmd_drm_t *drm, intptr_t arg, uchar_t *mask,
    int mode);
static	int dmd_mtiocget(dmd_tdv_t *tdv, intptr_t arg, int mode);
static	int dmd_mtgetpos(dmd_tdv_t *tdv, intptr_t arg, int mode);
static	int dmd_mtrestpos(dmd_tdv_t *tdv, intptr_t arg, int mode);
static	int dmd_blk_limit(dmd_tdv_t *tdv, intptr_t arg, int mode);
static	int dmd_locate(dmd_tdv_t *tdv, intptr_t arg, int mode);
static	int dmd_get_pos(dmd_tdv_t *tdv, intptr_t arg, int mode);
static	int dmd_get_capacity(dmd_tdv_t *tdv, intptr_t arg, int mode);
static	int dmd_upt_capacity(dmd_tdv_t *tdv);
static	int dmd_set_density(dmd_tdv_t *tdv, intptr_t arg);
static	int dmd_get_density(dmd_tdv_t *tdv, intptr_t arg,
    int mode);
static	int dmd_stat_info(dmd_stat_t *stat, intptr_t arg, int mode);
static void dmd_stat_info_wcr(dmd_wcr_t *wcr, dmd_stat_dev_t *dp);
static void dmd_stat_info_drm(dmd_drm_t *drm, dmd_stat_dev_t *dp);
static void dmd_stat_info_tdv(dmd_tdv_t *tdv, dmd_stat_dev_t *dp);
static	int dmd_probe_device(dmd_drm_t *drm, drm_probe_dev_t *ino);
static void dmd_cleanup_rsv(dmd_drm_t *drm);



/* cb_ops structure */
static	struct cb_ops dmd_cb_ops = {
	dmd_open,
	dmd_close,
	nodev,			/* no strategy - nodev returns ENXIO */
	nodev,			/* no print */
	nodev,			/* no dump */
	dmd_read,
	dmd_write,
	dmd_ioctl,		/* no ioctl */
	nodev,			/* no devmap */
	nodev,			/* no mmap */
	nodev,			/* no segmap */
	nochpoll,		/* returns ENXIO for non-pollable devices */
	dmd_prop_op,
	NULL,			/* streamtab struct; if not NULL, all above */
				/* fields are ignored */
	D_NEW | D_MP,		/* compatibility flags: see conf.h */
	CB_REV,			/* cb_ops revision number */
	nodev,			/* no aread */
	nodev			/* no awrite */
};

/* dev_ops structure */
static	struct dev_ops dmd_dev_ops = {
	DEVO_REV,
	0,			/* reference count */
	dmd_getinfo,
	nulldev,		/* no identify - nulldev returns 0 */
	nulldev,		/* no probe */
	dmd_attach,
	dmd_detach,
	nodev,			/* no reset - nodev returns ENXIO */
	&dmd_cb_ops,
	(struct bus_ops *)NULL,
	nodev			/* no power */
};

/* modldrv structure */
static	struct modldrv md = {
	&mod_driverops,		/* Type of module. This is a driver. */
	"MMS Drive Manager Driver (dmd)",	/* Name of the module. */
	&dmd_dev_ops
};

/* modlinkage structure */
static	struct modlinkage ml = {
	MODREV_1,
	&md,
	NULL
};

/* dev_info structure */
dev_info_t	*dmd_dip;  /* keep track of one instance */

struct	dev_ops *dev_ops;
dev_t	st_dev;

static	pid_t	dmd_stat_opens[DMD_MAX_STAT];



minor_t
dmd_inst_to_minor(int inst)
{
	/*
	 * wcr and stat device
	 */
	if (inst <= 1) {
		return (inst);
	}

	/*
	 * Drive manager device
	 */
	if ((inst & 1) == 0) {
		return (inst / 2 + 1);
	}

	/*
	 * Target device
	 */
	return (inst / 2 + 1 + 0x100);
}

int
dmd_minor_to_inst(minor_t minor)
{
	minor = getminor(minor);

	/*
	 * Watcher device
	 */
	if (minor == 0) {
		return (0);
	}

	/*
	 * Stat device
	 */
	if (minor == 1) {
		return (1);
	}

	/*
	 * Drive manager device
	 */
	if (minor <= 0xff) {
		return (((minor & 0xff) - 1) * 2);
	}

	/*
	 * Target device
	 */
	return (((minor & 0xff) - 1) * 2 + 1);
}

static	char *
dmd_lookup(dmd_sym_t *tab, int code)
{
	dmd_sym_t	*sp;

	for (sp = tab; sp->dmd_sym != NULL; sp++) {
		if (sp->dmd_code == code) {
			return (sp->dmd_sym);
		}
	}
	return ("UNKNOWN");
}

static	int
dmd_get_uscsicmd(int *cmd, intptr_t arg, int flag)
{
	char	scsi_cmd;
	struct	uscsi_cmd	us;
#ifdef _MULTI_DATAMODEL
	/*
	 * For use when a 32 bit app makes a call into a
	 * 64 bit ioctl
	 */
	struct	uscsi_cmd32	us32;
#endif /* _MULTI_DATAMODEL */

#ifdef _MULTI_DATAMODEL
	switch (ddi_model_convert_from(flag & FMODELS)) {
	case DDI_MODEL_ILP32:
		if (ddi_copyin((void *)arg, &us32,
		    sizeof (struct uscsi_cmd32), flag)) {
			return (EFAULT);
		}
		uscsi_cmd32touscsi_cmd((&us32), (&us));
		break;
	case DDI_MODEL_NONE:
		if (ddi_copyin((void *)arg, &us,
		    sizeof (struct uscsi_cmd), flag)) {
			return (EFAULT);
		}
		break;
	}

#else /* ! _MULTI_DATAMODEL */
	if (ddi_copyin((void *)arg, &us, sizeof (struct uscsi_cmd), flag)) {
		return (EFAULT);
	}
#endif /* _MULTI_DATAMODEL */

	/*
	 * Copy the command code from scsi_cmd
	 */
	if (ddi_copyin((void *)us.uscsi_cdb, &scsi_cmd, 1, flag)) {
		return (EFAULT);
	}
	*cmd = scsi_cmd;

	return (0);
}

static	int
dmd_get_mtop(struct mtop *mtop, intptr_t arg, int flag)
{
#ifdef _MULTI_DATAMODEL
	/*
	 * For use when a 32 bit app makes a call into a
	 * 64 bit ioctl
	 */
	struct		mtop32	mtop_32_for_64;
#endif /* _MULTI_DATAMODEL */

#ifdef _MULTI_DATAMODEL
	switch (ddi_model_convert_from(flag & FMODELS)) {
	case DDI_MODEL_ILP32:
		if (ddi_copyin((void *)arg, &mtop_32_for_64,
		    sizeof (struct mtop32), flag)) {
			return (EFAULT);
		}
		mtop->mt_op = mtop_32_for_64.mt_op;
		mtop->mt_count =  (daddr_t)mtop_32_for_64.mt_count;
		break;
	case DDI_MODEL_NONE:
		if (ddi_copyin((void *)arg, mtop, sizeof (struct mtop), flag)) {
			return (EFAULT);
		}
		break;
	}

#else /* ! _MULTI_DATAMODEL */
	if (ddi_copyin((void *)arg, mtop, sizeof (struct mtop), flag)) {
		return (EFAULT);
	}
#endif /* _MULTI_DATAMODEL */
	return (0);
}

static	int
dmd_get_mtlop(struct mtlop *mtlop, intptr_t arg, int flag)
{
#ifdef _MULTI_DATAMODEL
	/*
	 * For use when a 32 bit app makes a call into a
	 * 64 bit ioctl
	 */
	struct		mtlop	mtlop_32_for_64;
#endif /* _MULTI_DATAMODEL */

#ifdef _MULTI_DATAMODEL
	switch (ddi_model_convert_from(flag & FMODELS)) {
	case DDI_MODEL_ILP32:
		if (ddi_copyin((void *)arg, &mtlop_32_for_64,
		    sizeof (struct mtlop), flag)) {
			return (EFAULT);
		}
		mtlop->mt_op = mtlop_32_for_64.mt_op;
		mtlop->mt_count =  (daddr_t)mtlop_32_for_64.mt_count;
		break;
	case DDI_MODEL_NONE:
		if (ddi_copyin((void *)arg, mtlop, sizeof (struct mtlop),
		    flag)) {
			return (EFAULT);
		}
		break;
	}

#else /* ! _MULTI_DATAMODEL */
	if (ddi_copyin((void *)arg, mtlop, sizeof (struct mtlop), flag)) {
		return (EFAULT);
	}
#endif /* _MULTI_DATAMODEL */
	return (0);
}

static	int
dmd_return_mtop(struct mtop *mtop, intptr_t arg, int flag)
{
#ifdef _MULTI_DATAMODEL
	/*
	 * For use when a 32 bit app makes a call into a
	 * 64 bit ioctl
	 */
	struct		mtop32	mtop_32_for_64;
#endif /* _MULTI_DATAMODEL */

#ifdef _MULTI_DATAMODEL
	switch (ddi_model_convert_from(flag & FMODELS)) {
	case DDI_MODEL_ILP32:
		mtop_32_for_64.mt_op = mtop->mt_op;
		mtop_32_for_64.mt_count = mtop->mt_count;
		if (ddi_copyout(&mtop_32_for_64, (void *)arg,
		    sizeof (struct mtop32), flag)) {
			return (EFAULT);
		}
		break;
	case DDI_MODEL_NONE:
		if (ddi_copyout(mtop, (void *)arg, sizeof (struct mtop),
		    flag)) {
			return (EFAULT);
		}
		break;
	}

#else /* ! _MULTI_DATAMODEL */
	if (ddi_copyout(mtop, (void *)arg, sizeof (struct mtop), flag)) {
		return (EFAULT);
	}
#endif /* _MULTI_DATAMODEL */
	return (0);
}

static	int
dmd_return_mtlop(struct mtlop *mtlop, intptr_t arg, int flag)
{
	if (ddi_copyout(mtlop, (void *)arg, sizeof (struct mtlop), flag)) {
		return (EFAULT);
	}
	return (0);
}

/* Loadable module configuration entry points */

int
_init(void)
{
	int	rc = 0;

	DMD_DEBUG((CE_CONT, "_init: enter"));
	if (rc =  ddi_soft_state_init(&dmd_soft_statep,
	    sizeof (dmd_soft_state_t), 0)) {
		cmn_err(CE_WARN, "_init: soft state init error %d", rc);
		return (rc);
	}

	if ((rc = mod_install(&ml)) != 0) {
		cmn_err(CE_WARN, "_init: mod install error %d", rc);
		ddi_soft_state_fini(&dmd_soft_statep);
	}

	mutex_init(&dmd_state_mutex, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&dmd_sync_mutex, NULL, MUTEX_DRIVER, NULL);
	dmd_busy = 0;

	return (rc);
}

int
_info(struct modinfo *modinfop)
{
	int	rc;

	DMD_DEBUG((CE_CONT, "_info: enter\n"));
	if ((rc = mod_info(&ml, modinfop)) == 0) {
		cmn_err(CE_WARN, "_info: mod info error %d", rc);
	}
	return (rc);
}

int
_fini(void)
{
	int	rc = 0;

	DMD_DEBUG((CE_CONT, "_fini: enter\n"));
	if ((rc = mod_remove(&ml)) != 0) {
		return (rc);
	}

	ddi_soft_state_fini(&dmd_soft_statep);

	return (rc);
}

/* Device autoconfiguration entry points */

static	int
dmd_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int		inst;
	int		rc = 0;
	int		i;

	inst = ddi_get_instance(dip);
	DMD_DEBUG((CE_CONT, "dmd_attach: instance = %d", inst));

	/*
	 * Only work on instance 0. Ignore all other instances.
	 */
	if (inst != 0) {
		DMD_DEBUG((CE_NOTE, "dmd_attach: instance is not 0\n"));
		return (DDI_FAILURE);
	}
	dmd_major = ddi_driver_major(dip);

	switch (cmd) {
	case DDI_ATTACH:
		/*
		 * Create the watcher device
		 */
		rc = dmd_create_dev(dmd_wcr_p, DMD_WCR_NAME, 0,
		    (dmd_soft_state_t **)(&dmd_wcr_p), &dip);
		if (rc) {
			return (DDI_FAILURE);
		}
		dmd_wcr_p->wcr_inst = 0;
		dmd_wcr_p->wcr_dip = dip;

		/*
		 * Create the stat device - instance 1
		 */
		rc = dmd_create_dev(dmd_wcr_p, DMD_STAT_NAME, 1,
		    (dmd_soft_state_t **)(&dmd_stat_p), &dip);
		if (rc) {
			ddi_soft_state_free(dmd_soft_statep, 0);
			ddi_remove_minor_node(dip, NULL);
			return (DDI_FAILURE);
		}
		dmd_stat_p->stat_inst = 1;
		dmd_stat_p->stat_dip = dip;

		for (i = 0; i < DMD_MAX_STAT; i++) {
			dmd_stat_opens[i] = (pid_t)(-1);
		}

		return (DDI_SUCCESS);
	default:
		DMD_DEBUG((CE_NOTE, "dmd_attach: attach failed, inst = %d",
		    inst));
		return (DDI_FAILURE);
	}
}

static	int
dmd_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int		inst;
	dmd_wcr_t	*wcr;
	dmd_stat_t	*stat;

	inst = ddi_get_instance(dip);
	DMD_DEBUG((CE_CONT, "dmd_detach: inst = %d", inst));
	switch (cmd) {
	case DDI_DETACH:
		/*
		 * Free the watcher device
		 */
		wcr = (dmd_wcr_t *)ddi_get_soft_state(dmd_soft_statep, inst);
		if (wcr == NULL) {
			cmn_err(CE_WARN, "dmd_detach: "
			    "can't get state struct of watcher device\n");
			return (DDI_FAILURE);
		}
		if (wcr->wcr_proc_ref) {
			proc_unref(wcr->wcr_proc_ref);
			wcr->wcr_proc_ref = NULL;
		}
		ddi_soft_state_free(dmd_soft_statep, inst);

		/*
		 * Free the stat device
		 */
		inst++;
		stat = (dmd_stat_t *)ddi_get_soft_state(dmd_soft_statep, inst);
		if (stat == NULL) {
			cmn_err(CE_WARN, "dmd_detach: "
			    "can't get state struct of stat device\n");
			return (DDI_FAILURE);
		}
		ddi_soft_state_free(dmd_soft_statep, inst);

		ddi_remove_minor_node(dip, NULL);
		return (DDI_SUCCESS);
	default:
		cmn_err(CE_WARN, "dmd_detach: failed");
		return (DDI_FAILURE);
	}
}

static	int
/* LINTED: dip not used */
dmd_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg,
    void **resultp)
{
	dmd_soft_state_t	*ss;
	minor_t			minor = getminor((dev_t)arg);
	int			inst = dmd_minor_to_inst(minor);

	DMD_DEBUG((CE_CONT, "dmd_getinfo: enter\n"));
	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		ss = ddi_get_soft_state(dmd_soft_statep, inst);
		if (ss != NULL) {
			if (DMD_WCR(inst)) {
				*resultp = ss->ss_wcr.wcr_dip;
			} else if (DMD_STAT(inst)) {
				*resultp = ss->ss_stat.stat_dip;
			} else if (DMD_DRM(inst)) {
				*resultp = ss->ss_drm.drm_dip;
			} else {
				*resultp = ss->ss_tdv.tdv_dip;
			}
			return (DDI_SUCCESS);
		} else {
			*resultp = NULL;
			cmn_err(CE_WARN, "dmd_getinfo: failed");
			return (DDI_FAILURE);
		}
	case DDI_INFO_DEVT2INSTANCE:
		*resultp = (void *)(uintptr_t)inst;
		return (DDI_SUCCESS);
	default:
		cmn_err(CE_WARN, "dmd_getinfo: failed");
		return (DDI_FAILURE);
	}
}

static	int
dmd_prop_op(dev_t dev, dev_info_t *dip, ddi_prop_op_t prop_op,
    int flags, char *name, caddr_t valuep, int *lengthp)
{
	DMD_DEBUG((CE_CONT, "dmd_prop_op: enter\n"));
	return (ddi_prop_op(dev, dip, prop_op, flags, name, valuep, lengthp));
}

/* User context entry points */

static	int
dmd_open(dev_t *devp, int flags, int otyp, cred_t *cred)
{
	int		rc = 0;
	dmd_soft_state_t	*ss;
	minor_t			minor = getminor(*devp);
	int			inst = dmd_minor_to_inst(minor);
	pid_t			pid = ddi_get_pid();
	dmd_wcr_t		*wcr;
	dmd_drm_t		*drm;
	dmd_tdv_t		*tdv;
	dmd_stat_t		*stat;

	DMD_DEBUG((CE_CONT, "[%d:%d] dmd_open, dev = %x\n", inst, pid, minor));
	ss = ddi_get_soft_state(dmd_soft_statep, inst);
	if (ss == NULL) {
		DMD_DEBUG((CE_NOTE, "[%d:%d] dmd_open: Can't get state",
		    inst, pid));
		return (ENXIO);
	}

	if (DMD_WCR(inst)) {
		if (dmd_state != DMD_NOT_READY) {
			DMD_DEBUG((CE_NOTE, "[%d:%d] dmd_open: driver is busy",
			    inst, pid));
			return (ENXIO);
		}
		wcr = &ss->ss_wcr;
		wcr->wcr_cur_pid = pid;
		wcr->wcr_inst = inst;
		rc = dmd_open_wcr(&ss->ss_wcr);
		if (rc == 0) {
			dmd_state = DMD_READY;
			dmd_busy = 0;
		}
	} else {
		/*
		 * Do not allow new opens if the driver is not ready.
		 */
		if (!DMD_STAT(inst) && dmd_state != DMD_READY) {
			DMD_DEBUG((CE_NOTE, "[%d:%d] dmd_open: "
			    "driver not ready",
			    inst, pid));
			return (ENXIO);
		}
		DMD_BUSY();
		if (DMD_STAT(inst)) {		/* drive manager open */
			stat = &ss->ss_stat;
			stat->stat_cur_pid = pid;
			stat->stat_inst = inst;
			rc = dmd_open_stat(stat);
		} else if (DMD_DRM(inst)) {		/* drive manager open */
			drm = &ss->ss_drm;
			drm->drm_cur_pid = pid;
			drm->drm_inst = inst;
			rc = dmd_open_drm(drm, devp, flags, otyp, cred);
		} else {				/* an app open */
			tdv = &ss->ss_tdv;
			tdv->tdv_cur_pid = pid;
			tdv->tdv_inst = inst;
			rc = dmd_open_tdv(tdv, devp, flags, otyp, cred);
		}
		DMD_UNBUSY();
	}
	return (rc);
}

static	int
dmd_open_wcr(dmd_wcr_t *wcr)
{
	pid_t	pid = wcr->wcr_cur_pid;
	int	inst = wcr->wcr_inst;

	/*
	 * Process wcr open
	 */
	DMD_DEBUG((CE_CONT, "[%d:%d] dmd_open_wcr: "
	    "Opening watcher device\n", inst, pid));
	mutex_enter(&dmd_wcr_p->wcr_mutex);
	if (dmd_wcr_p->wcr_pid) {			/* wcr already opened */
		DMD_DEBUG((CE_NOTE,
		    "[%d:%d] dmd_open_wcr: watcher already opened "
		    "by process %d", inst, pid, dmd_wcr_p->wcr_pid));
		mutex_exit(&dmd_wcr_p->wcr_mutex);
		return (EBUSY);
	}

	dmd_wcr_p->wcr_pid = pid;		/* save wcr pid */
	dmd_wcr_p->wcr_proc_ref = proc_ref();
	mutex_exit(&dmd_wcr_p->wcr_mutex);
	return (0);
}

static	int
dmd_open_stat(dmd_stat_t *stat)
{
	int	i;
	pid_t	pid = stat->stat_cur_pid;
	int	inst = stat->stat_inst;

	DMD_DEBUG((CE_CONT, "[%d:%d] dmd_open_stat: "
	    "Opening stat device\n", inst, pid));

	/* Add openpid to pid table */
	for (i = 0; i < DMD_MAX_STAT; i++) {
		if (dmd_stat_opens[i] == (pid_t)(-1)) {	/* a closed entry */
			dmd_stat_opens[i] = pid;
			break;
		}
	}
	if (i == DMD_MAX_STAT) {			/* too many opened */
		return (EBUSY);
	}
	return (0);
}

static	int
dmd_open_drm(dmd_drm_t *drm, dev_t *devp, int flags, int otyp, cred_t *cred)
{
	minor_t		minor = getminor(*devp);
	int		rc = 0;
	pid_t		pid = drm->drm_cur_pid;
	int		inst = drm->drm_inst;

	DMD_DEBUG((CE_CONT, "[%d:%d] dmd_open_drm: "
	    "Opening DM device, minor = %d\n", inst, pid, minor));

	/*
	 * Check to see if there is a watcher.
	 * If no watcher, error
	 */
	mutex_enter(&dmd_wcr_p->wcr_mutex);
	if (dmd_wcr_p->wcr_cur_pid == 0) {
		/* No watcher */
		DMD_DEBUG((CE_NOTE,
		    "[%d:%d] dmd_open_drm: No watcher", inst, pid));
		mutex_exit(&dmd_wcr_p->wcr_mutex);
		return (ENXIO);
	}

	DRM_BUSY(drm);
	mutex_enter(&drm->drm_shr_mutex);
	if ((drm->drm_flags & DRM_DEV_ADDED) == 0) {
		rc = ENXIO;
		goto done;
	}
	if (drm->drm_shr_pid) {
		/*
		 * Only one process can open a drive manager
		 */
		DMD_DEBUG((CE_NOTE,
		    "[%d:%d] dmd_open_drm: dm %d already opened by process %d",
		    getminor(*devp), inst, pid, drm->drm_shr_pid));
		rc = EBUSY;
		goto done;
	}
	drm->drm_shr_pid = pid;
	drm->drm_shr_oflags = flags;
	drm->drm_shr_cred = cred;
	drm->drm_shr_otyp = otyp;
	drm->drm_shr_proc_ref = proc_ref();
	if (drm->drm_shr_tdv_pid == 0) {
		/* tdv not opened by app */
		drm->drm_shr_flags &= ~DRM_SHR_WAIT_TDV_CLOSE;
	}
	DMD_INC_OPENS();
	if (drm->drm_shr_flags & DRM_SHR_WAIT_TDV_CLOSE) {
		DMD_DEBUG((CE_NOTE, "[%d:%d] dmd_open_drm: "
		    "waiting for tdv close from pid %d",
		    inst, pid, drm->drm_shr_tdv_pid));
	}
done:
	DRM_UNBUSY(drm);
	mutex_exit(&drm->drm_shr_mutex);
	mutex_exit(&dmd_wcr_p->wcr_mutex);
	return (rc);
}

static	int
dmd_open_tdv(dmd_tdv_t *tdv, dev_t *devp, int flags, int otyp, cred_t *cred)
{
	dmd_drm_t	*drm = tdv->tdv_drm;
	drm_open_t	*open_req = &drm->drm_shr_req.drm_open_req;
	minor_t		minor = getminor(*devp);
	int		rc = 0;
	uid_t		uid = crgetuid(cred);
	int		inst = tdv->tdv_inst;
	pid_t		pid = tdv->tdv_cur_pid;

	DMD_DEBUG((CE_CONT, "[%d:%d] dmd_open_tdv: "
	    "Opening target device, dev = %lx\n",
	    inst, pid, *devp));

	if (minor != tdv->tdv_minor) {
		DMD_DEBUG((CE_NOTE, "[%d:%d] dmd_open_tdv: "
		    "Mismatched dev: tdv_minor %x, "
		    "request minor %x", inst, pid,
		    tdv->tdv_minor, minor));
		return (ENXIO);
	}
	TDV_BUSY(tdv);

	/*
	 * Must have been bound to to a target device to open
	 */
	if ((tdv->tdv_flags & TDV_BOUND) == 0) {
		TDV_UNBUSY(tdv);
		return (ENXIO);
	}
	if (drm->drm_shr_tdv_pid != 0) {
		DMD_DEBUG((CE_NOTE, "[%d:%d] dmd_open_tdv: "
		    "target dev already opened "
		    "by process %d, dev %lx", inst, pid,
		    drm->drm_shr_tdv_pid, *devp));
		TDV_UNBUSY(tdv);
		return (EBUSY);
	}
	/*
	 * Init file I/O counts
	 */
	tdv->tdv_rdbytes = 0;
	tdv->tdv_wrbytes = 0;
	tdv->tdv_blkcnt = 0;

	mutex_enter(&drm->drm_shr_mutex);
	if (drm->drm_shr_lhdl == NULL) {
		DMD_DEBUG((CE_NOTE, "[%d:%d] dmd_open_tdv: "
		    "target device is not opened", inst, pid));
		TDV_UNBUSY(tdv);
		mutex_exit(&drm->drm_shr_mutex);
		return (ENXIO);
	}

	/*
	 * Signal the drive manager
	 */
	(void) memset(&drm->drm_shr_req, 0, sizeof (drm_request_t));
	drm->drm_shr_req.drm_req_type = DRM_REQ_OPEN;
	drm->drm_shr_req.drm_req_pid = pid;
	drm->drm_shr_req.drm_req_uid = uid;
	open_req->drm_open_flags = flags;
	open_req->drm_open_type = otyp;
	open_req->drm_open_minor = minor;
	if (rc = dmd_signal_drm(drm)) {
		/*
		 * Signal failed, assume open success and
		 * tell drive manager to close
		 */
		DMD_INC_OPENS();		/* increase open count */
		DMD_DEBUG((CE_NOTE,
		    "[%d:%d] dmd_open_tdv: signal failed, signal for "
		    "abnormal close", inst, pid));
		drm->drm_shr_flags |= DRM_SHR_OPEN_FAILED;
		TDV_UNBUSY(tdv);
		(void) dmd_close_tdv(tdv, *devp);
		mutex_exit(&drm->drm_shr_mutex);
		return (rc);
	}
	rc = drm->drm_shr_rep.drm_rep_rc;
	drm->drm_shr_tdv_pid = 0;
	if (rc == 0) {
		/* Open success */
		drm->drm_shr_tdv_pid = pid;
		tdv->tdv_uid = uid;
		DMD_DEBUG((CE_NOTE, "[%d:%d] dmd_open_tdv: opened by %d",
		    inst, pid, drm->drm_shr_tdv_pid));
		DMD_INC_OPENS();		/* increase open count */
	}
	TDV_UNBUSY(tdv);
	mutex_exit(&drm->drm_shr_mutex);
	return (rc);
}

static	int
/* LINTED: need all arguments */
dmd_close(dev_t dev, int flags, int otyp, cred_t *cred)
{
	int			rc = 0;
	dmd_soft_state_t	*ss;
	minor_t			minor = getminor(dev);
	int			inst = dmd_minor_to_inst(minor);
	pid_t			pid = ddi_get_pid();
	dmd_wcr_t		*wcr;
	dmd_drm_t		*drm;
	dmd_tdv_t		*tdv;
	dmd_stat_t		*stat;

	DMD_DEBUG((CE_CONT, "[%d:%d] dmd_close: Entering dmd_close, "
	    "minor = %x\n",
	    inst, pid, minor));

	ss = ddi_get_soft_state(dmd_soft_statep, inst);
	if (ss == NULL) {
		DMD_DEBUG((CE_NOTE, "[%d:%d] dmd_close: Can't get state",
		    inst, pid));
		return (ENXIO);
	}

	if (DMD_WCR(inst)) {
		wcr = &ss->ss_wcr;
		wcr->wcr_cur_pid = pid;
		wcr->wcr_inst = inst;
		rc = dmd_close_wcr(wcr);
		if (rc == 0) {
			dmd_state = DMD_NOT_READY;
		}
	} else {
		DMD_BUSY();
		if (DMD_STAT(inst)) {
			stat = &ss->ss_stat;
			stat->stat_cur_pid = pid;
			stat->stat_inst = inst;
			rc = dmd_close_stat(stat);
		} else if (DMD_DRM(inst)) {
			drm = &ss->ss_drm;
			drm->drm_cur_pid = pid;
			drm->drm_inst = inst;
			rc = dmd_close_drm(drm, dev, cred);
		} else {
			tdv = &ss->ss_tdv;
			tdv->tdv_cur_pid = pid;
			tdv->tdv_inst = inst;
			rc = dmd_close_tdv(tdv, dev);
		}
		DMD_UNBUSY();
	}
	DMD_DEBUG((CE_CONT, "[%d:%d] dmd_close: rc = %d, minor = %d\n",
	    inst, pid, rc, minor));
	return (0);
}

static	int
dmd_close_wcr(dmd_wcr_t *wcr)
{
	dmd_drm_t	*drm;
	int		inst = wcr->wcr_inst;
	pid_t		pid = wcr->wcr_cur_pid;
	int		i;
	dmd_soft_state_t	*ss;

	DMD_DEBUG((CE_CONT, "[%d:%d] dmd_close_wcr: enter\n", inst, pid));
	mutex_enter(&wcr->wcr_mutex);

	for (i = DMD_FIRST_DEV_ORDINAL; i < dmd_next_ord; i++) {
		ss = ddi_get_soft_state(dmd_soft_statep, i * 2);
		if (ss == NULL) {
			continue;
		}
		drm = &ss->ss_drm;
		mutex_enter(&drm->drm_mutex);
		if (drm->drm_shr_pid) {
			/*
			 * Signal drive manager
			 */
			if (drm->drm_shr_proc_ref != NULL) {
				DMD_DEBUG((CE_CONT, "[%d:%d] dmd_close_wcr: "
				    "sending SIGTERM to dm process %d\n",
				    inst, pid, drm->drm_shr_pid));
				(void) proc_signal(drm->drm_shr_proc_ref,
				    SIGTERM);
			}
		}
		mutex_exit(&drm->drm_mutex);
	}

	wcr->wcr_pid = 0;
	mutex_exit(&wcr->wcr_mutex);
	DMD_DEBUG((CE_CONT, "[%d:%d] dmd_close_wcr: close done\n", inst, pid));
	return (0);
}

static	int
dmd_close_stat(dmd_stat_t *stat)
{
	pid_t	pid = stat->stat_cur_pid;
	int	inst = stat->stat_inst;
	int	i;

	DMD_DEBUG((CE_NOTE, "[%d:%d] Closing stat device", inst, pid));
	for (i = 0; i < DMD_MAX_STAT; i++) {
		if (dmd_stat_opens[i] == pid) {
			dmd_stat_opens[i] = (pid_t)(-1);
			break;
		}
	}
	return (0);
}

static	int
dmd_close_drm(dmd_drm_t *drm, dev_t dev, cred_t *cred)
{
	int		inst = drm->drm_inst;
	pid_t		pid = drm->drm_cur_pid;

	DMD_DEBUG((CE_CONT, "[%d:%d] dmd_close_drm: "
	    "Closing DM device, minor = %d, tdv_pid = %d\n",
	    inst, pid, getminor(dev), drm->drm_shr_tdv_pid));
	DRM_BUSY(drm);

	/*
	 * Resume any outstanding request sent to DM
	 */
	mutex_enter(&drm->drm_shr_mutex);
	if (drm->drm_shr_flags & DRM_SHR_WAIT_RESUME) {
		DMD_DEBUG((CE_NOTE, "[%d:%d] dmd_close_drm: "
		    "canceling DM requests", inst, pid));
		drm->drm_shr_flags &=
		    ~(DRM_SHR_WAIT_RESUME | DRM_SHR_REQ_VALID);
		(void) memset(&drm->drm_shr_rep, 0, sizeof (drm_reply_t));
		drm->drm_shr_rep.drm_rep_rc = ENXIO;
		cv_broadcast(&drm->drm_shr_res_cv);
	}
	DMD_DEC_OPENS();
	if (drm->drm_shr_proc_ref) {
		proc_unref(drm->drm_shr_proc_ref);
		drm->drm_shr_proc_ref = NULL;
	}
	dmd_cleanup_rsv(drm);
	/*
	 * Close connection to target driver
	 */
	(void) dmd_ldi_close(drm, cred);
	drm->drm_shr_pid = 0;			/* DM is gone */
	if (drm->drm_shr_tdv_pid != 0) {
		drm->drm_shr_flags |= DRM_SHR_WAIT_TDV_CLOSE;
		DMD_DEBUG((CE_CONT, "[%d:%d] dmd_close_drm: "
		    "tdv still opened by %d\n",
		    inst, pid, drm->drm_shr_tdv_pid));
	}
	mutex_exit(&drm->drm_shr_mutex);

	DRM_UNBUSY(drm);
	return (0);
}

static void
dmd_cleanup_rsv(dmd_drm_t *drm)
{
	int		rval;
	struct		uscsi_cmd *sc = &drm->drm_uscsi;
	int		rc = 0;
	static	uchar_t		preempt_cmd[] =
	    { 0x5f, 0x04, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 24, 0x00 };
	static	uchar_t		reg_cmd[] =
	    { 0x5f, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 24, 0x00 };
	dmd_tdv_t	*tdv = drm->drm_tdv;
	int		inst = tdv->tdv_inst;
	pid_t		pid = drm->drm_cur_pid;

	/*
	 * Register the key
	 */
	(void) memset(sc, 0, sizeof (struct uscsi_cmd));
	(void) memset(drm->drm_prsv_buf, 0, sizeof (drm->drm_prsv_buf));
	(void) memcpy(drm->drm_prsv_buf + 8, drm->drm_prsv_key, 8);

	/*
	 * register PRSV key
	 */
	/* LINTED: Null effect */
	sc->uscsi_flags |= (USCSI_WRITE);
	sc->uscsi_cdb = (char *)reg_cmd;
	sc->uscsi_cdblen = sizeof (reg_cmd);
	sc->uscsi_bufaddr = drm->drm_prsv_buf;
	sc->uscsi_buflen = sizeof (drm->drm_prsv_buf);

	(void) memset(drm->drm_prsv_buf, 0, 24);
	rc = ldi_ioctl(drm->drm_shr_lhdl, USCSICMD, (intptr_t)sc,
	    FKIOCTL | DATAMODEL_NATIVE, drm->drm_ioctl_credp, &rval);
	if (rc != 0) {
		DMD_DEBUG((CE_NOTE, "[%d:%d] dmd_cleanup_rsv: "
		    "PRSV register returns %d",
		    inst, pid, rc));
	}

	/*
	 * Preempt to remove key
	 */
	(void) memset(sc, 0, sizeof (struct uscsi_cmd));
	(void) memset(drm->drm_prsv_buf, 0, sizeof (drm->drm_prsv_buf));
	(void) memcpy(drm->drm_prsv_buf, drm->drm_prsv_key, 8);
	(void) memcpy(drm->drm_prsv_buf + 8, drm->drm_prsv_key, 8);

	/* LINTED: Null effect */
	sc->uscsi_flags |= (USCSI_WRITE);
	sc->uscsi_cdb = (char *)preempt_cmd;
	sc->uscsi_cdblen = sizeof (preempt_cmd);
	sc->uscsi_bufaddr = drm->drm_prsv_buf;
	sc->uscsi_buflen = sizeof (drm->drm_prsv_buf);

	rc = ldi_ioctl(drm->drm_shr_lhdl, USCSICMD, (intptr_t)sc,
	    FKIOCTL | DATAMODEL_NATIVE, drm->drm_ioctl_credp, &rval);
	if (rc != 0) {
		DMD_DEBUG((CE_NOTE, "[%d:%d] dmd_cleanup_rsv: "
		    "PRSV preempt returns %d",
		    inst, pid, rc));
	}
	/*
	 * Tell st driver to resume reserve/release on open/close.
	 */
	rc = ldi_ioctl(drm->drm_shr_lhdl, MTIOCRELEASE, NULL,
	    FKIOCTL | DATAMODEL_NATIVE, drm->drm_ioctl_credp, &rval);
	if (rc != 0) {
		DMD_DEBUG((CE_NOTE, "[%d:%d] dmd_cleanup_rsv: "
		    "MTIOCRELEASE error: %d",
		    inst, pid, rc));
	}
}

static	int
dmd_close_tdv(dmd_tdv_t *tdv, dev_t dev)
{
	dmd_drm_t	*drm = tdv->tdv_drm;
	minor_t		minor = getminor(dev);
	int		inst = tdv->tdv_inst;
	pid_t		pid = tdv->tdv_cur_pid;
	int		xmutex = 0;		/* don't do mutex_exit */

	DMD_DEBUG((CE_CONT, "[%d:%d] dmd_close_tdv: "
	    "Closing target device, minor = %x\n",
	    inst, pid, minor));
	TDV_BUSY(tdv);
	/*
	 * Use tryenter because this may be called dmd_open_tdv if the
	 * open request failed.
	 */
	if (mutex_tryenter(&drm->drm_shr_mutex) != 0) {
		/* got the mutex */
		xmutex = 1;			/* do mutex_exit */
	}

	/*
	 * If no handle to target driver, then we have no associated DM
	 */
	if (drm->drm_shr_flags & DRM_SHR_WAIT_TDV_CLOSE) {
		DMD_DEBUG((CE_NOTE, "[%d:%d] dmd_close_tdv: "
		    "No assocated DM", inst, pid));
		/*
		 * Tell current DM to get ready
		 */
		if (drm->drm_shr_pid != 0) {
			DMD_DEBUG((CE_NOTE, "[%d:%d] signaling DM %d",
			    inst, pid, drm->drm_shr_pid));
			if (proc_signal(drm->drm_shr_proc_ref, SIGUSR2)) {
				DMD_DEBUG((CE_NOTE, "[%d:%d] dmd_close_tdv :"
				    "Can't signal DM %d",
				    inst, pid, drm->drm_shr_pid));
			}
		}
		drm->drm_shr_flags &= ~DRM_SHR_WAIT_TDV_CLOSE;
	} else {
		(void) memset(&drm->drm_shr_req, 0, sizeof (drm_request_t));
		drm->drm_shr_req.drm_req_type = DRM_REQ_CLOSE;
		(void) dmd_signal_drm(drm);
	}
	tdv->tdv_flags &= ~(TDV_FATAL | TDV_MOVED);
	drm->drm_shr_tdv_pid = 0;
	drm->drm_shr_flags &= ~DRM_SHR_WAIT_TDV_CLOSE;
	DMD_DEC_OPENS();
	if (xmutex) {
		mutex_exit(&drm->drm_shr_mutex);
	}
	TDV_UNBUSY(tdv);
	return (0);
}

static	int
dmd_read(dev_t dev, struct uio *uiop, cred_t *credp)
{
	int		rc = 0;
	dmd_soft_state_t	*ss;
	dmd_drm_t	*drm;
	dmd_tdv_t	*tdv;
	minor_t		minor = getminor(dev);
	int		inst = dmd_minor_to_inst(minor);
	pid_t		pid = ddi_get_pid();

	/*
	 * Only drive managers and target drives can do read/write.
	 */
	if (DMD_WCR(inst) || DMD_STAT(inst)) {
		DMD_DEBUG((CE_NOTE, "[%d:%d] dmd_read: "
		    "read not supported for watcher and stat devices",
		    inst, pid));
		return (ENOTSUP);
	}
	ss = ddi_get_soft_state(dmd_soft_statep, inst);
	if (ss == NULL) {
		DMD_DEBUG((CE_NOTE, "[%d:%d] dmd_read: "
		    "Can't get state, minor %d",
		    inst, pid, minor));
		return (ENXIO);
	}
	DMD_BUSY();
	if (DMD_DRM(inst)) {
		drm = &ss->ss_drm;
		drm->drm_cur_pid = pid;
		drm->drm_inst = inst;
		rc = dmd_read_drm(drm, uiop, credp);
	} else {
		/*
		 * tdv read
		 */
		tdv = &ss->ss_tdv;
		tdv->tdv_cur_pid = pid;
		tdv->tdv_inst = inst;
		rc = dmd_read_tdv(tdv, uiop, credp);
	}
	DMD_UNBUSY();
	return (rc);
}

static	int
dmd_read_drm(dmd_drm_t *drm, struct uio *uiop, cred_t *credp)
{
	int	rc = 0;
	int	inst = drm->drm_inst;
	pid_t	pid = drm->drm_cur_pid;

	DRM_BUSY(drm);
	if (drm->drm_shr_pid != ddi_get_pid()) {
		/*
		 * Only allow the process which opened the device
		 */
		DRM_UNBUSY(drm);
		DMD_UNBUSY();
		return (EACCES);
	}
	rc = ldi_read(drm->drm_shr_lhdl, uiop, credp);
	if (rc != 0) {
		DMD_DEBUG((CE_CONT, "[%d:%d] dmd_read_drm: "
		    "read returns %d", inst, pid, rc));
	}
	DRM_UNBUSY(drm);
	return (rc);
}

static	int
dmd_read_tdv(dmd_tdv_t *tdv, struct uio *uiop, cred_t *credp)
{
	int		rc = 0;
	dmd_drm_t	*drm = tdv->tdv_drm;
	int		inst = tdv->tdv_inst;
	pid_t		pid = tdv->tdv_cur_pid;
	int64_t		iovlen;
	int64_t		resid;
	int		reqtype = 0;

	TDV_BUSY(tdv);

	mutex_enter(&drm->drm_shr_mutex);
	if (drm->drm_shr_flags & DRM_SHR_WAIT_TDV_CLOSE) {
		/* waiting for me to close */
		DMD_DEBUG((CE_NOTE, "[%d:%d] dmd_read_tdv: "
		    "no associated DM", inst, pid));
		rc = ENXIO;
		goto done;
	}

	if (drm->drm_shr_flags & DRM_SHR_WAIT_RESUME) {
		DMD_DEBUG((CE_NOTE, "[%d:%d] dmd_read_tdv: "
		    "Waiting for resume", inst, pid));
		rc = EBUSY;
		goto done;
	}

	/*
	 * Check for MMS mode
	 */
	if ((tdv->tdv_flags & TDV_MMS_MODE) == 0) {
		/*
		 * Not in MMS mode, no processing by drive manager
		 */
		mutex_exit(&drm->drm_shr_mutex);
		rc = ldi_read(drm->drm_shr_lhdl, uiop, credp);
		mutex_enter(&drm->drm_shr_mutex);
	} else if (tdv->tdv_flags & TDV_FATAL) {
		/* Fatal error, no movement cmds */
		DMD_DEBUG((CE_NOTE, "[%d:%d] dmd_read_tdv: "
		    "FATAL set, Returning EIO", inst, pid));
		rc = EIO;
		goto done;
	} else {
		/*
		 * For fixed mode, I/O size must be multiple
		 * of max blksize.
		 * For variable mode, I/O size must be <= max blksize.
		 */
		iovlen = uiop->uio_iov->iov_len;
		if (iovlen > drm->drm_shr_max_blksize) {
			if (drm->drm_shr_flags & DRM_SHR_FIXED) {
				if (iovlen % drm->drm_shr_max_blksize) {
					DMD_DEBUG((CE_NOTE,
					    "[%d:%d] dmd_read_tdv: "
					    "read size (%lld) "
					    "not multiple of "
					    "max size (%d)",
					    inst, pid,
					    (long long)iovlen,
					    drm->drm_shr_max_blksize));
					rc = EINVAL;
					goto done;
				}
			} else {
				DMD_DEBUG((CE_NOTE, "[%d:%d] dmd_read_tdv: "
				    "read size (%lld) "
				    "greater than max size (%d)",
				    inst, pid, (long long)iovlen,
				    drm->drm_shr_max_blksize));
				rc = EINVAL;
				goto done;
			}
		}
		/*
		 * In MMS mode, need drive manager processing
		 */
		if (tdv->tdv_flags & TDV_NOTIFY_READ) {
			/* Notify read only works once */
			tdv->tdv_flags &= ~TDV_NOTIFY_READ;
			(void) memset(&drm->drm_shr_req, 0,
			    sizeof (drm_request_t));
			drm->drm_shr_req.drm_req_type = DRM_REQ_READ;
			DMD_DEBUG((CE_CONT, "[%d:%d] dmd_read_tdv: "
			    "Signal for READ\n", inst, pid));
			rc = dmd_signal_drm(drm);
			if (rc == 0) {
				rc = drm->drm_shr_rep.drm_rep_rc;
			}
		}
		if (rc == 0) {
			mutex_exit(&drm->drm_shr_mutex);
			rc = ldi_read(drm->drm_shr_lhdl, uiop, credp);
			mutex_enter(&drm->drm_shr_mutex);
			tdv->tdv_flags |= TDV_MOVED;
			resid = uiop->uio_resid;
			if (resid > 0) {
				DMD_DEBUG((CE_CONT, "[%d:%d] dmd_read_tdv: "
				    "Read returns: "
				    "len = %lld, resid = %lld, rc = %d\n",
				    inst, pid,
				    (long long)iovlen, (long long)resid, rc));
			}
			/*
			 * Count number of bytes/blks read
			 */
			tdv->tdv_rdbytes += (iovlen - uiop->uio_resid);
			if (drm->drm_shr_flags & DRM_SHR_FIXED) {
				tdv->tdv_blkcnt +=
				    ((iovlen - uiop->uio_resid) /
				    drm->drm_shr_max_blksize);
			} else if (iovlen - uiop->uio_resid) {
				/* Read a block */
				tdv->tdv_blkcnt++;
			}
			/*
			 * Signal drive manager if in MMS mode
			 */
			if (rc == 0 &&
			    uiop->uio_resid == iovlen) {
				/*
				 * If ldi_read returns 0 and did not
				 * read any bytes, then we must have
				 * read a tapemark.
				 */
				DMD_DEBUG((CE_CONT, "[%d:%d] dmd_read_tdv: "
				    "Signal for READ_TM\n", inst, pid));
				reqtype = DRM_REQ_READ_TM;
			} else if (rc != 0) {
				DMD_DEBUG((CE_NOTE, "[%d:%d] dmd_read_tdv: "
				    "Signal for READ_ERR", inst, pid));
				reqtype = DRM_REQ_READ_ERR;
			}
			if (reqtype != 0) {
				/* Notify DM */
				(void) memset(&drm->drm_shr_req, 0,
				    sizeof (drm_request_t));
				drm->drm_shr_req.drm_err_req.drm_errno = rc;
				drm->drm_shr_req.drm_err_req.drm_resid =
				    uiop->uio_resid;
				/* Read new status */
				drm->drm_shr_req.drm_req_type = reqtype;
				rc = dmd_signal_drm(drm);
				if (rc == 0) {
					rc = drm->drm_shr_rep.drm_rep_rc;
				}
			}
		}
	}
done:
	mutex_exit(&drm->drm_shr_mutex);
	if (rc != 0) {
		DMD_DEBUG((CE_CONT, "[%d:%d] dmd_read_tdv: "
		    "read returns %d", inst, pid, rc));
	}
	TDV_UNBUSY(tdv);
	return (rc);
}

static	int
dmd_write(dev_t dev, struct uio *uiop, cred_t *credp)
{
	int		rc = 0;
	dmd_soft_state_t	*ss;
	dmd_drm_t	*drm;
	dmd_tdv_t	*tdv;
	minor_t		minor = getminor(dev);
	int		inst = dmd_minor_to_inst(minor);
	pid_t		pid = ddi_get_pid();

	if (DMD_WCR(inst) || DMD_STAT(inst)) {
		return (ENOTSUP);
	}
	ss = ddi_get_soft_state(dmd_soft_statep, inst);
	if (ss == NULL) {
		DMD_DEBUG((CE_NOTE, "[%d:%d] dmd_write: Can't get state",
		    inst, pid));
		return (ENXIO);
	}
	DMD_BUSY();
	if (DMD_DRM(inst)) {
		drm = &ss->ss_drm;
		drm->drm_cur_pid = pid;
		drm->drm_inst = inst;
		rc = dmd_write_drm(drm, uiop, credp);
	} else {
		tdv = &ss->ss_tdv;
		tdv->tdv_cur_pid = pid;
		tdv->tdv_inst = inst;
		rc = dmd_write_tdv(tdv, uiop, credp);
	}
	DMD_UNBUSY();
	return (rc);
}

static	int
dmd_write_drm(dmd_drm_t *drm, struct uio *uiop, cred_t *credp)
{
	int	rc = 0;
	int	inst = drm->drm_inst;
	pid_t	pid = drm->drm_cur_pid;

	DRM_BUSY(drm);
	mutex_enter(&drm->drm_shr_mutex);
	if (drm->drm_shr_pid != drm->drm_busy) {
		/*
		 * Only allow the process which opened the device
		 */
		mutex_exit(&drm->drm_shr_mutex);
		DRM_UNBUSY(drm);
		return (EACCES);
	}
	mutex_exit(&drm->drm_shr_mutex);
	rc = ldi_write(drm->drm_shr_lhdl, uiop, credp);
	if (rc != 0) {
		DMD_DEBUG((CE_CONT, "[%d:%d] dmd_write_drm: "
		    "read returns %d", inst, pid, rc));
	}
	DRM_UNBUSY(drm);
	return (rc);
}

static	int
dmd_write_tdv(dmd_tdv_t *tdv, struct uio *uiop, cred_t *credp)
{
	int		rc = 0;
	dmd_drm_t	*drm = tdv->tdv_drm;
	int		inst = tdv->tdv_inst;
	pid_t		pid = tdv->tdv_cur_pid;
	int		reqtype;
	int64_t		iovlen;
	int64_t		resid;

	TDV_BUSY(tdv);
	mutex_enter(&drm->drm_shr_mutex);

	if (drm->drm_shr_flags & DRM_SHR_WAIT_TDV_CLOSE) {
		/* waiting for me to close */
		DMD_DEBUG((CE_NOTE, "[%d:%d] dmd_write_tdv: "
		    "no associated DM", inst, pid));
		rc = ENXIO;
		goto done;
	}

	if (drm->drm_shr_flags & DRM_SHR_WAIT_RESUME) {
		DMD_DEBUG((CE_NOTE, "[%d:%d] dmd_write_tdv: "
		    "Waiting for resume", inst, pid));
		rc = EBUSY;
		goto done;
	}

	/*
	 * Check for MMS mode
	 */
	if ((tdv->tdv_flags & TDV_MMS_MODE) == 0) {
		/*
		 * Not in MMS mode, no processing by drive manager
		 */
		mutex_exit(&drm->drm_shr_mutex);
		rc = ldi_write(drm->drm_shr_lhdl, uiop, credp);
		mutex_enter(&drm->drm_shr_mutex);
	} else if (tdv->tdv_flags & TDV_FATAL) {
		DMD_DEBUG((CE_NOTE, "[%d:%d] dmd_write_tdv: "
		    "FATAL set, Returning EIO", inst, pid));
		rc = EIO;
		goto done;
	} else {
		/*
		 * For fixed mode, I/O size must be multiple
		 * of max blksize.
		 * For variable mode, I/O size must be <= max blksize.
		 */
		iovlen = uiop->uio_iov->iov_len;
		if (iovlen > drm->drm_shr_max_blksize) {
			if (drm->drm_shr_flags & DRM_SHR_FIXED) {
				if (iovlen % drm->drm_shr_max_blksize) {
					DMD_DEBUG((CE_NOTE,
					    "[%d:%d] dmd_write_tdv: "
					    "write size (%lld) "
					    "not multiple of "
					    "max size (%d)", inst, pid,
					    (long long)iovlen,
					    drm->drm_shr_max_blksize));
					rc = EINVAL;
					goto done;
				}
			} else {
				DMD_DEBUG((CE_NOTE, "[%d:%d] dmd_write_tdv: "
				    "write size (%lld) "
				    "greater than max size (%d)", inst, pid,
				    (long long)iovlen,
				    drm->drm_shr_max_blksize));
				rc = EINVAL;
				goto done;
			}
		}
		/*
		 * MMS mode, need drive manager processing
		 */
		if (tdv->tdv_flags & TDV_NOTIFY_WRITE) {
			/* Notify write only works once */
			tdv->tdv_flags &= ~TDV_NOTIFY_WRITE;
			(void) memset(&drm->drm_shr_req, 0,
			    sizeof (drm_request_t));
			/* Read new status */
			drm->drm_shr_req.drm_req_type = DRM_REQ_WRITE;
			DMD_DEBUG((CE_CONT, "[%d:%d] dmd_write_tdv: "
			    "Signal for WRITE\n", inst, pid));
			rc = dmd_signal_drm(drm);
			if (rc == 0) {
				rc = drm->drm_shr_rep.drm_rep_rc;
			}
		}
		if (rc == 0) {
			mutex_exit(&drm->drm_shr_mutex);
			rc = ldi_write(drm->drm_shr_lhdl, uiop, credp);
			mutex_enter(&drm->drm_shr_mutex);
			tdv->tdv_flags |= TDV_MOVED;
			resid = uiop->uio_resid;
			DMD_DEBUG((CE_CONT, "[%d:%d] dmd_write_tdv: "
			    "Write returns: "
			    "len = %lld, resid = %lld, rc = %d\n", inst, pid,
			    (long long)iovlen, (long long)resid, rc));
			/*
			 * Count number of blks/bytes written
			 */
			tdv->tdv_wrbytes += (iovlen - uiop->uio_resid);
			if (drm->drm_shr_flags & DRM_SHR_FIXED) {
				tdv->tdv_blkcnt +=
				    ((iovlen - uiop->uio_resid) /
				    drm->drm_shr_max_blksize);
			} else {
				tdv->tdv_blkcnt++;
			}
			reqtype = 0;
			if (rc == 0 &&
			    uiop->uio_resid == iovlen) {
				/*
				 * ldi_write returns 0 and did not write
				 * any bytes.
				 */
				DMD_DEBUG((CE_NOTE, "[%d:%d] Signal for WRITE0",
				    inst, pid));
				reqtype = DRM_REQ_WRITE0;
			} else if (rc != 0) {
				DMD_DEBUG((CE_NOTE,
				    "[%d:%d] dmd_write_tdv: "
				    "Signal for WRITE_ERR", inst, pid));
				reqtype = DRM_REQ_WRITE_ERR;
			}
			if (reqtype != 0) {
				/* Notify DM */
				(void) memset(&drm->drm_shr_req, 0,
				    sizeof (drm_request_t));
				drm->drm_shr_req.drm_err_req.drm_errno = rc;
				drm->drm_shr_req.drm_err_req.drm_resid =
				    uiop->uio_resid;
				/* Read new status */
				drm->drm_shr_req.drm_req_type = reqtype;
				rc = dmd_signal_drm(drm);
				if (rc == 0) {
					rc = drm->drm_shr_rep.drm_rep_rc;
				}
			}
		}
	}
done:
	mutex_exit(&drm->drm_shr_mutex);
	if (rc != 0) {
		DMD_DEBUG((CE_CONT, "[%d:%d] dmd_write_tdv: "
		    "read returns %d", inst, pid, rc));
	}
	TDV_UNBUSY(tdv);
	return (rc);
}

static	int
dmd_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp, int *rvalp)
{
	dmd_soft_state_t	*ss;
	int			rc = 0;
	int			minor = getminor(dev);
	int			inst = dmd_minor_to_inst(minor);
	pid_t			pid = ddi_get_pid();
	dmd_wcr_t		*wcr;
	dmd_drm_t		*drm;
	dmd_tdv_t		*tdv;
	dmd_stat_t		*stat;

	DMD_DEBUG((CE_CONT, "[%d:%d] dmd_ioctl: minor = 0x%x\n",
	    inst, pid, minor));

	ss = ddi_get_soft_state(dmd_soft_statep, inst);
	if (ss == NULL) {
		DMD_DEBUG((CE_NOTE, "[%d:%d] dmd_ioctl: "
		    "Can't get state", inst, pid));
		return (ENXIO);
	}

	if (DMD_WCR(inst)) {
		wcr = &ss->ss_wcr;
		wcr->wcr_cur_pid = pid;
		wcr->wcr_inst = inst;
		rc = dmd_ioctl_wcr(wcr, cmd, arg);
	} else {
		DMD_BUSY();
		if (DMD_STAT(inst)) {
			stat = &ss->ss_stat;
			stat->stat_cur_pid = pid;
			stat->stat_inst = inst;
			rc = dmd_ioctl_stat(stat, cmd, arg, mode);
		} else if (DMD_DRM(inst)) {
			drm = &ss->ss_drm;
			drm->drm_cur_pid = pid;
			drm->drm_inst = inst;
			rc = dmd_ioctl_drm(drm, cmd, arg, mode,
			    credp, rvalp);
		} else {
			tdv = &ss->ss_tdv;
			tdv->tdv_cur_pid = pid;
			tdv->tdv_inst = inst;
			rc = dmd_ioctl_tdv(tdv, cmd, arg, mode, rvalp);
		}
		DMD_UNBUSY();
	}

	return (rc);
}

static	int
dmd_ioctl_wcr(dmd_wcr_t *wcr, int cmd, intptr_t arg)
{
	int			newinst;	/* for the new device */
	dev_info_t		*dip;
	char			devname[20];
	int			rc = 0;
	dmd_drm_t		*drm;
	dmd_tdv_t		*tdv;
	dmd_soft_state_t	*ss;
	int			ord = (int)arg;
	int			inst = wcr->wcr_inst;
	pid_t			pid = wcr->wcr_cur_pid;

	DMD_DEBUG((CE_CONT, "[%d:%d] dmd_ioctl_wcr: entered\n", inst, pid));
	if (wcr->wcr_pid != ddi_get_pid()) {
		/*
		 * Only allow the process which opened the device
		 */
		return (EACCES);
	}
	switch (cmd) {
	case WCR_ADD_DEV:
		/*
		 * Configure a drive manager and its target device
		 * arg - ordinal of device.
		 */

		DMD_DEBUG((CE_CONT, "[%d:%d] dmd_ioctl_wcr: WCR_ADD_DEV\n",
		    inst, pid));
		newinst = 2 * ord;
		/*
		 * Validate the ordinal
		 */
		if (ord < DMD_FIRST_DEV_ORDINAL || ord > dmd_next_ord) {
			DMD_DEBUG((CE_NOTE, "[%d:%d] dmd_ioctl_wcr: "
			    "WCR_ADD_DEV, "
			    "invalid device ordinal %d", inst, pid, ord));
			rc = EINVAL;
			goto done;
		} else if (ord < dmd_next_ord) {
			DMD_DEBUG((CE_NOTE, "[%d:%d] dmd_ioctl_wcr: "
			    "WCR_ADD_DEV, "
			    "device ordinal %d already added", inst, pid, ord));
			ss = ddi_get_soft_state(dmd_soft_statep, newinst);
			if (ss == NULL) {
				DMD_DEBUG((CE_NOTE, "[%d:%d] dmd_ioctl_wcr: "
				    "Can't get state structure, inst = %d",
				    inst, pid, newinst));
				rc = ENXIO;
				goto done;
			}
			drm = &ss->ss_drm;
			/*
			 * Ensure that the device is not bound
			 */
			if ((drm->drm_flags & DRM_DEV_ADDED) == 0) {
				rc = EEXIST;
				goto done;
			}
			drm->drm_flags |= DRM_DEV_ADDED;
			rc = 0;
			goto done;
		}
		/*
		 * Dm and target devices have their own soft state.
		 */
		dip = NULL;
		(void) DRM_DEVNAME(ord, devname);
		DMD_DEBUG((CE_NOTE, "[%d:%d] dmd_ioctl_wcr: "
		    "Creating device %s", newinst, pid, devname));
		if (rc = dmd_create_dev(wcr, devname, newinst,
		    (dmd_soft_state_t **)&drm, &dip)) {
			goto done;
		}
		drm->drm_inst = newinst;
		drm->drm_dip = dip;
		/*
		 * Create the target device soft state
		 */
		dip = NULL;
		if (rc = dmd_create_dev(wcr, NULL, newinst + 1,
		    (dmd_soft_state_t **)&tdv, &dip)) {
			ddi_soft_state_free(dmd_soft_statep, newinst);
			ddi_remove_minor_node(dip, devname);
			goto done;
		}
		tdv->tdv_inst = newinst + 1;
		tdv->tdv_dip = dip;

		tdv->tdv_drm = drm;
		drm->drm_tdv = tdv;
		dmd_next_ord++;

		drm->drm_flags |= DRM_DEV_ADDED;
		break;

default:
		DMD_DEBUG((CE_NOTE, "[%d:%d] dmd_ioctl_wcr: "
		    "invalid ioctl command: 0x%x", inst, pid, cmd));
		rc = EINVAL;
		goto done;
	}
done:
	if (rc != 0) {
		DMD_DEBUG((CE_CONT, "[%d:%d] dmd_ioctl_wcr: "
		    "ioctl returns %d", inst, pid, rc));
	}
	return (rc);
}

static	int
dmd_create_dev(dmd_wcr_t *wcr, char *devname, int inst, dmd_soft_state_t **rss,
    dev_info_t **rdip)
{
	dmd_soft_state_t	*ss;
	dev_info_t		*dip = *rdip;
	minor_t			minor = dmd_inst_to_minor(inst);
	pid_t			pid;

	*rss = NULL;
	if (wcr == NULL) {
		pid = (pid_t)(-1);
	} else {
		pid = wcr->wcr_cur_pid;
	}

	if (ddi_soft_state_zalloc(dmd_soft_statep, inst) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "[%d:%d] dmd_create_dev: "
		    "Unable to allocate dmd_soft_statep", inst, pid);
		return (ENOMEM);
	}

	ss = ddi_get_soft_state(dmd_soft_statep, inst);
	if (ss == NULL) {
		cmn_err(CE_WARN, "[%d:%d] dmd_create_dev: "
		    "Can't get state structure", inst, pid);
		ddi_soft_state_free(dmd_soft_statep, inst);
		return (ENXIO);
	}
	(void) memset(ss, 0, sizeof (dmd_soft_state_t));
	if (DMD_WCR(inst)) {
		mutex_init(&ss->ss_wcr.wcr_mutex, NULL, MUTEX_DRIVER, NULL);
	} else if (DMD_STAT(inst)) {
		mutex_init(&ss->ss_stat.stat_mutex, NULL, MUTEX_DRIVER, NULL);
	} else if (DMD_DRM(inst)) {
		mutex_init(&ss->ss_drm.drm_mutex, NULL, MUTEX_DRIVER, NULL);
		cv_init(&ss->ss_drm.drm_busy_cv, NULL, CV_DRIVER, NULL);
	} else {
		mutex_init(&ss->ss_tdv.tdv_mutex, NULL, MUTEX_DRIVER, NULL);
		cv_init(&ss->ss_tdv.tdv_busy_cv, NULL, CV_DRIVER, NULL);
	}
	if (dip == NULL) {
		dip = ddi_find_devinfo(ddi_major_to_name(dmd_major), 0, 0);
		if (dip == NULL) {
			cmn_err(CE_WARN, "[%d:%d] dmd_create_dev: "
			    "no watcher info", inst, pid);
			ddi_soft_state_free(dmd_soft_statep, inst);
			return (ENXIO);
		}
		ddi_release_devi(dip);
	}

	/*
	 * If not target device, create the device
	 */
	if (devname != NULL) {
		if (ddi_create_minor_node(dip, devname, S_IFCHR, minor,
		    DDI_PSEUDO, 0) != DDI_SUCCESS) {
			cmn_err(CE_WARN, "[%d:%d] dmd_create_dev: "
			    "Can't create minor node %d",
			    inst, pid, minor);
			ddi_soft_state_free(dmd_soft_statep, inst);
			return (ENXIO);
		}
	}
	*rss = ss;
	if (*rdip == NULL)
		*rdip = dip;
	return (0);
}

static	int
dmd_ioctl_stat(dmd_stat_t *stat, int cmd, intptr_t arg, int mode)
{
	int		rc = 0;
	int		num;
	int		inst = stat->stat_inst;
	pid_t		pid = stat->stat_cur_pid;

	switch (cmd) {
	case DMD_STAT_NDEV:
		DMD_DEBUG((CE_CONT,
		    "[%d:%d] dmd_ioctl_stat: ioctl DMD_STAT_NDEV\n",
		    inst, pid));
		/*
		 * Return number of devices. arg must be (uint32_t *)
		 */
		num = 2 * dmd_next_ord;
		if (ddi_copyout(&num, (void *)arg, sizeof (uint32_t),
		    mode)) {
			DMD_DEBUG((CE_NOTE, "[%d:%d] dmd_ioctl_stat: "
			    "copyout error", inst, pid));
			rc = EFAULT;
			goto done;
		}
		break;

	case DMD_STAT_INFO:
		DMD_DEBUG((CE_CONT, "[%d:%d] dmd_ioctl_stat: "
		    "ioctl DMD_STAT_INFO\n",
		    inst, pid));
		if ((rc = dmd_stat_info(stat, arg, mode)) != 0) {
			goto done;
		}
		break;

	case DMD_STAT_CLEAR:
		DMD_DEBUG((CE_CONT, "[%d:%d] dmd_ioctl_stat: "
		    "ioctl DMD_STAT_CLEAR\n",
		    inst, pid));
		break;
	}
done:
	if (rc != 0) {
		DMD_DEBUG((CE_CONT, "[%d:%d] dmd_ioctl_stat: "
		    "ioctl returns %d", inst, pid, rc));
	}
	return (rc);
}

static	int
dmd_stat_info(dmd_stat_t *stat, intptr_t arg, int mode)
{
	dmd_stat_dev_t		di;
	dmd_stat_info_t		ii;
	dmd_stat_dev_t		*dp;
	dmd_stat_info_t		*ip;
	dmd_stat_dev_t		*udp;
	char			*cp;
	dmd_wcr_t		*wcr;
	dmd_drm_t		*drm;
	dmd_tdv_t		*tdv;
	int			num;
	dmd_soft_state_t	*ss;
	int			inst = stat->stat_inst;
	pid_t			pid = stat->stat_cur_pid;

	ip = &ii;
	dp = &di;
	if (ddi_copyin((void *)arg, ip, sizeof (dmd_stat_info_t), mode)) {
		DMD_DEBUG((CE_NOTE, "[%d:%d] dmd_stat_info: "
		    "copyin error", inst, pid));
		return (EFAULT);
	}

	num = ip->stat_num;
	if (ip->stat_num > (dmd_next_ord * 2)) {
		num = dmd_next_ord * 2;
	}
	ip->stat_num = num;
	ip->stat_dmd_busy = dmd_busy;

	if (ddi_copyout(ip, (void *)arg, sizeof (dmd_stat_info_t), mode)) {
		DMD_DEBUG((CE_NOTE, "[%d:%d] dmd_stat_info: "
		    "copyout error", inst, pid));
		return (EFAULT);
	}

	cp = (char *)arg + ((char *)(ip->stat_dev) - (char *)ip);
	udp = (dmd_stat_dev_t *)cp;

	for (inst = 0; inst < num; inst++) {
		(void) memset(dp, 0, sizeof (dmd_stat_dev_t));
		ss = ddi_get_soft_state(dmd_soft_statep, inst);
		if (ss == NULL) {
			DMD_DEBUG((CE_NOTE, "[%d:%d] dmd_ioctl_stat: "
			    "Can't get state", inst, pid));
			return (ENXIO);
		}

		dp->stat_inst = inst;
		if (DMD_WCR(inst)) {
			wcr = &ss->ss_wcr;
			wcr->wcr_cur_pid = pid;
			wcr->wcr_inst = inst;
			dmd_stat_info_wcr(wcr, dp);
		} else if (DMD_DRM(inst)) {
			drm = &ss->ss_drm;
			drm->drm_cur_pid = pid;
			drm->drm_inst = inst;
			dmd_stat_info_drm(drm, dp);
		} else if (DMD_TDV(inst)) {
			tdv = &ss->ss_tdv;
			tdv->tdv_cur_pid = pid;
			tdv->tdv_inst = inst;
			dmd_stat_info_tdv(tdv, dp);
		} else {
			dp->stat_flags |= STAT_STAT;
		}

		if (ddi_copyout(dp, udp + inst, sizeof (dmd_stat_dev_t),
		    mode)) {
			DMD_DEBUG((CE_NOTE, "[%d:%d] dmd_stat_info: "
			    "copyout error", inst, pid));
			return (EFAULT);
		}
	}

	return (0);
}

static void
dmd_stat_info_wcr(dmd_wcr_t *wcr, dmd_stat_dev_t *dp)
{
	dp->stat_flags |= STAT_WCR;
	if (wcr->wcr_pid) {		/* watcher opened */
		dp->stat_flags |= STAT_OPENED;
		dp->stat_pid = wcr->wcr_pid;
	}
}

static void
dmd_stat_info_drm(dmd_drm_t *drm, dmd_stat_dev_t *dp)
{
	dp->stat_flags |= STAT_DRM;
	if (drm->drm_shr_pid) {		/* DM opened */
		dp->stat_flags |= STAT_OPENED;
		dp->stat_pid = drm->drm_shr_pid;
	}
	if (drm->drm_shr_lhdl) {		/* LDI opened */
		dp->stat_flags |= STAT_LDI_OPENED;
	}
	if (drm->drm_shr_flags & DRM_SHR_WAIT_RESUME) {
		dp->stat_flags |= STAT_WAIT_RESUME;
	}
	dp->stat_targ_major = getmajor(drm->drm_targ_dev);
	dp->stat_targ_minor = getminor(drm->drm_targ_dev);
	dp->stat_busy_pid = drm->drm_busy;
}

static void
dmd_stat_info_tdv(dmd_tdv_t *tdv, dmd_stat_dev_t *dp)
{
	dmd_drm_t *drm = tdv->tdv_drm;

	dp->stat_flags |= STAT_TDV;
	if (drm->drm_shr_tdv_pid) {		/* target opened */
		dp->stat_flags |= STAT_OPENED;
		dp->stat_pid = drm->drm_shr_tdv_pid;
	}
	dp->stat_targ_minor = tdv->tdv_minor;
	dp->stat_busy_pid = tdv->tdv_busy;
}

static	int
dmd_ioctl_drm(dmd_drm_t *drm, int cmd, intptr_t arg,
    int mode, cred_t *credp, int *rvalp)
{
	int		rc = 0;
	dmd_tdv_t	*tdv = drm->drm_tdv;
	drm_target_t	targ;
	drm_blksize_t	blksize;
	struct	mtop	mtop;
	struct	mtlop	mtlop;
	char		tmp[10];
	int		scsicmd;
	char		*cp;
	int		inst = drm->drm_inst;
	pid_t		pid = drm->drm_cur_pid;
	drm_probe_dev_t	ino;

	DRM_BUSY(drm);
	/*
	 * Save ioctl mode for later use
	 */
	drm->drm_ioctl_mode = mode;
	drm->drm_ioctl_credp = credp;
	mutex_enter(&drm->drm_shr_mutex);

	if (drm->drm_shr_pid != ddi_get_pid()) {
		/*
		 * Only allow the process which opened the device
		 */
		DMD_DEBUG((CE_NOTE, "[%d:%d] dmd_ioctl_drm: DM pid = %d ",
		    inst, pid, drm->drm_shr_pid));
		rc = EACCES;
		goto done;
	}
	switch (cmd) {
	case DRM_BIND_DEV :
		/*
		 * Bind a real dev to target dev
		 */
		DMD_DEBUG((CE_CONT, "[%d:%d] dmd_ioctl_drm: "
		    "DRM_BIND_DEV ioctl\n",
		    inst, pid));
		/*
		 * Error if waiting for tdv to close
		 */
		if (drm->drm_shr_flags & DRM_SHR_WAIT_TDV_CLOSE) {
			DMD_DEBUG((CE_NOTE,
			    "[%d:%d] dmd_ioctl_drm: waiting for tdv close",
			    inst, pid));
			rc = EMFILE;
			goto done;
		}
		/*
		 * Proceed if target dev is not busy
		 */
		if (drm->drm_shr_lhdl) {
			/* already bound */
			rc = EBUSY;
			goto done;
		}

		if (ddi_copyin((void *)arg, &targ, sizeof (drm_target_t), 0)) {
			DMD_DEBUG((CE_NOTE,
			    "[%d:%d] dmd_ioctl_drm: copyin error",
			    inst, pid));
			rc = EFAULT;
			goto done;
		}
		rc = dmd_bind_dev(drm, &targ, credp);
		break;
	case DRM_REBIND_DEV :
		/*
		 * Rebind a target dev
		 */
		DMD_DEBUG((CE_CONT,
		    "[%d:%d] dmd_ioctl_drm: DRM_REBIND_DEV ioctl\n",
		    inst, pid));
		/*
		 * Error if waiting for tdv to close
		 */
		if (drm->drm_shr_flags & DRM_SHR_WAIT_TDV_CLOSE) {
			DMD_DEBUG((CE_NOTE,
			    "[%d:%d] dmd_ioctl_drm: waiting for pid %d "
			    "to close",
			    inst, pid, drm->drm_shr_tdv_pid));
			rc = EMFILE;
			goto done;
		}
		/*
		 * Proceed if target dev is bound
		 */
		if (drm->drm_shr_lhdl == NULL) {
			/* Not bound */
			DMD_DEBUG((CE_NOTE,
			    "[%d:%d] dmd_ioctl_drm: "
			    "no handle to target device",
			    inst, pid));
			rc = ENXIO;
			goto done;
		}

		if (ddi_copyin((void *)arg, &targ, sizeof (drm_target_t), 0)) {
			DMD_DEBUG((CE_NOTE, "[%d:%d] dmd_ioctl_drm: "
			    "copyin error",
			    inst, pid));
			rc = EFAULT;
			goto done;
		}
		(void) dmd_ldi_close(drm, credp);
		rc = dmd_bind_dev(drm, &targ, credp);
		break;
	case DRM_REQUEST :
		DMD_DEBUG((CE_CONT, "[%d:%d] dmd_ioctl_drm: "
		    "DRM_REQUEST ioctl\n", inst, pid));
		if ((drm->drm_shr_flags & DRM_SHR_REQ_VALID) == 0) {
			DMD_DEBUG((CE_CONT, "[%d:%d] dmd_ioctl_drm: "
			    "no request\n", inst, pid));
			rc = ENOMSG;
			goto done;
		}
		if (rc = ddi_copyout(&drm->drm_shr_req, (void *)arg,
		    sizeof (drm_request_t), mode)) {
			DMD_DEBUG((CE_NOTE, "[%d:%d] dmd_ioctl_drm: "
			    "copyout error",
			    inst, pid));
			rc = EFAULT;
			goto done;
		}
		drm->drm_shr_flags &= ~DRM_SHR_REQ_VALID;
		cv_broadcast(&drm->drm_shr_res_cv);
		break;

	case DRM_RESUME :
		DMD_DEBUG((CE_CONT, "[%d:%d] dmd_ioctl_drm: DRM_RESUME ioctl\n",
		    inst, pid));
		if (drm->drm_shr_flags & DRM_SHR_WAIT_RESUME) {
			drm->drm_shr_flags &= ~DRM_SHR_WAIT_RESUME;
			if (ddi_copyin((void *)arg, &drm->drm_shr_rep,
			    sizeof (drm_reply_t), 0)) {
				DMD_DEBUG((CE_NOTE, "[%d:%d] dmd_ioctl_drm: "
				    "copyin error", inst, pid));
				rc = EFAULT;
				goto done;
			}
			cv_broadcast(&drm->drm_shr_res_cv);
		}
		break;

	case DRM_MMS_MODE :
		DMD_DEBUG((CE_NOTE, "[%d:%d] dmd_ioctl_drm: DRM_MMS_MODE ioctl",
		    inst, pid));
		/* Set/unset MMS mode */
		if (drm->drm_shr_tdv_pid != 0) {
			/* Can't set MMS mode after file is opened by user */
			DMD_DEBUG((CE_NOTE, "[%d:%d] dmd_ioctl_drm: "
			    "can't set mms mode, file opened", inst, pid));
			rc = EACCES;
			goto done;
		}

		if ((int)arg > 0) {
			tdv->tdv_flags |= TDV_MMS_MODE;
			DMD_DEBUG((CE_CONT, "[%d:%d] dmd_ioctl_drm: "
			    "MMS mode is ON\n", inst, pid));
		} else {
			tdv->tdv_flags &= ~TDV_MMS_MODE;
			DMD_DEBUG((CE_CONT, "[%d:%d] dmd_ioctl_drm: "
			    "MMS mode is OFF\n", inst, pid));
		}
		break;

	case DRM_BLKSIZE :
		DMD_DEBUG((CE_CONT, "[%d:%d] dmd_ioctl_drm: "
		    "DRM_BLKSIZE ioctl\n",
		    inst, pid));
		if (ddi_copyin((void *)arg, &blksize,
		    sizeof (drm_blksize_t), 0)) {
			DMD_DEBUG((CE_NOTE, "[%d:%d] dmd_ioctl_drm: "
			    "copyin error", inst, pid));
			rc = EFAULT;
			goto done;
		}
		if (blksize.drm_fixed) {
			drm->drm_shr_flags |= DRM_SHR_FIXED;
		} else {
			drm->drm_shr_flags &= ~DRM_SHR_FIXED;
		}
		drm->drm_shr_max_blksize = (uint32_t)blksize.drm_blksize;
		DMD_DEBUG((CE_CONT, "[%d:%d] dmd_ioctl_drm: "
		    "max blksize = %lld\n",
		    inst, pid, (long long)blksize.drm_blksize));
		break;

	case DRM_TARG_MINOR :
		DMD_DEBUG((CE_CONT, "[%d:%d] dmd_ioctl_drm: "
		    "DRM_BLKSIZE ioctl\n",
		    inst, pid));
		tdv->tdv_minor = (minor_t)arg;
		DMD_DEBUG((CE_CONT, "[%d:%d] dmd_ioctl_drm: "
		    "target minor = %x\n",
		    inst, pid, tdv->tdv_minor));
		break;

	case DRM_DM_READY :
		DMD_DEBUG((CE_CONT, "[%d:%d] dmd_ioctl_drm: "
		    "DRM_DM_READY ioctl: %s\n",
		    inst, pid, arg != 0 ? "DM ready" : "DM not ready"));
		if (arg != 0) {
			drm->drm_flags |= DRM_READY;
		} else {
			drm->drm_flags &= ~DRM_READY;
		}
		break;

	case DRM_PROBE_DEV :
		DMD_DEBUG((CE_CONT, "[%d:%d] dmd_ioctl_drm: "
		    "DRM_PROBE_DEV ioctl\n",
		    inst, pid));
		if (ddi_copyin((void *)arg, &ino,
		    sizeof (drm_probe_dev_t), 0)) {
			DMD_DEBUG((CE_NOTE, "[%d:%d] dmd_ioctl_drm: "
			    "copyin error", inst, pid));
			rc = EFAULT;
			goto done;
		}
		rc = dmd_probe_device(drm, &ino);
		break;

	case USCSICMD :
		if (rc = dmd_get_uscsicmd(&scsicmd, arg, mode)) {
			DMD_DEBUG((CE_NOTE, "[%d:%d] dmd_ioctl_drm: "
			    "USCSICMD error", inst, pid));
			return (rc);
		}
		if ((cp = dmd_lookup(dmd_scsi_cmd_tab, scsicmd)) == NULL) {
			(void) snprintf(tmp, sizeof (tmp), "0x%x", scsicmd);
			cp = tmp;
		}
		DMD_DEBUG((CE_CONT, "[%d:%d] dmd_ioctl_drm: USCSICMD, %s\n",
		    inst, pid, cp));
		mutex_exit(&drm->drm_shr_mutex);
		rc = ldi_ioctl(drm->drm_shr_lhdl, cmd, arg, mode, credp, rvalp);
		mutex_enter(&drm->drm_shr_mutex);
		if (rc != 0) {
			DMD_DEBUG((CE_CONT, "[%d:%d] ldi_ioctl_drm: "
			    "returns %d\n", inst, pid, rc));
		}
		break;

	case DRM_PRSV_KEY :
		DMD_DEBUG((CE_CONT, "[%d:%d] dmd_ioctl_drm: "
		    "DRM_PRSV_KEY ioctl\n",
		    inst, pid));
		if (ddi_copyin((char *)arg, drm->drm_prsv_key, 8, 0)) {
			DMD_DEBUG((CE_NOTE, "[%d:%d] dmd_ioctl_drm: "
			    "copyin error", inst, pid));
			rc = EFAULT;
			goto done;
		}
		break;

	case DRM_DISALLOWED_CMDS :
		DMD_DEBUG((CE_CONT, "[%d:%d] dmd_ioctl_drm: "
		    "DRM_DISALLOWED_CMDS "
		    "ioctl\n", inst, pid));
		rc = dmd_get_disallowed(drm, arg, tdv->tdv_disallowed_cmds,
		    mode);
		break;

	case DRM_DISALLOWED_IOCTLS :
		DMD_DEBUG((CE_CONT, "[%d:%d] dmd_ioctl_drm: "
		    "DRM_DISALLOWED_IOCTLS "
		    "ioctl\n", inst, pid));
		rc = dmd_get_disallowed(drm, arg, tdv->tdv_disallowed_ioctls,
		    mode);
		break;

	case DRM_TDV_PID :
		DMD_DEBUG((CE_CONT, "[%d:%d] dmd_ioctl_drm: DRM_TDV_PID "
		    "ioctl\n", inst, pid));
		if (rc = ddi_copyout(&drm->drm_shr_tdv_pid, (void *)arg,
		    sizeof (uint32_t), mode)) {
			DMD_DEBUG((CE_NOTE, "[%d:%d] dmd_ioctl_drm: "
			    "copyout error", inst, pid));
			rc = EFAULT;
			goto done;
		}
		break;

	default:
		if (cmd == MTIOCTOP) {
			if ((rc = dmd_get_mtop(&mtop, arg, mode)) != 0) {
				DMD_DEBUG((CE_NOTE, "[%d:%d] dmd_ioctl_drm: "
				    "can't get mtop", inst, pid));
				goto done;
			}
			cp = dmd_lookup(dmd_mtop_tab, mtop.mt_op);
			if (cp == NULL) {
				(void) snprintf(tmp, sizeof (tmp),
				    "0x%2x", mtop.mt_op);
				cp = tmp;
			}
			DMD_DEBUG((CE_CONT, "[%d:%d] dmd_ioctl_drm: "
			    "ioctl MTIOCTOP, %s\n", inst, pid, cp));
		} else if (cmd == MTIOCLTOP) {
			if ((rc = dmd_get_mtlop(&mtlop, arg, mode)) != 0) {
				DMD_DEBUG((CE_NOTE, "[%d:%d] dmd_ioctl_drm: "
				    "can't get mtlop", inst, pid));
				goto done;
			}
			cp = dmd_lookup(dmd_mtop_tab, mtop.mt_op);
			if (cp == NULL) {
				(void) snprintf(tmp, sizeof (tmp),
				    "0x%2x", mtlop.mt_op);
				cp = tmp;
			}
			DMD_DEBUG((CE_CONT, "[%d:%d] dmd_ioctl_drm: "
			    "ioctl MTIOCLTOP, %s\n", inst, pid, cp));
		} else {
			cp = dmd_lookup(dmd_ioctl_tab, cmd);
			if (strcmp(cp, "UNKNOWN") == 0) {
				(void) snprintf(tmp, sizeof (tmp),
				    "UNKNOWN 0x%2x", cmd);
				cp = tmp;
			}
			DMD_DEBUG((CE_CONT, "[%d:%d] dmd_ioctl_drm:ioctl %s\n",
			    inst, pid, cp));
		}
		mutex_exit(&drm->drm_shr_mutex);
		rc = ldi_ioctl(drm->drm_shr_lhdl, cmd, arg, mode, credp, rvalp);
		mutex_enter(&drm->drm_shr_mutex);
		DMD_DEBUG((CE_CONT, "[%d:%d] ldi_ioctl returns %d, rval %d\n",
		    inst, pid, rc, *rvalp));

		break;
	}

done:
	mutex_exit(&drm->drm_shr_mutex);
	if (rc != 0) {
		DMD_DEBUG((CE_CONT, "[%d:%d] dmd_ioctl_drm: "
		    "ioctl returns %d", inst, pid, rc));
	}
	DRM_UNBUSY(drm);
	return (rc);
}

static	int
dmd_ioctl_tdv(dmd_tdv_t *tdv, int cmd, intptr_t arg, int mode, int *rvalp)
{
	int		inst = tdv->tdv_inst;
	pid_t		pid = tdv->tdv_cur_pid;
	dmd_drm_t	*drm = tdv->tdv_drm;
	int		rc = 0;
	struct	mtop	mtop;
	struct	mtlop	mtlop;
	char		tmp[10];
	char		*cp;

	DMD_DEBUG((CE_CONT, "[%d:%d] dmd_ioctl_tdv: enter\n", inst, pid));
	TDV_BUSY(tdv);
	mutex_enter(&drm->drm_shr_mutex);

	if (drm->drm_shr_flags & DRM_SHR_WAIT_RESUME) {
		DMD_DEBUG((CE_NOTE, "[%d:%d] dmd_ioctl_tdv: "
		    "Waiting for resume", inst, pid));
		rc = EBUSY;
		goto done;
	}

	switch (cmd) {
		/*
		 * Check for supported ioctl for both MMS and RAW modes
		 */
	case MMS_BLK_LIMIT :
		DMD_DEBUG((CE_CONT, "[%d:%d] dmd_ioctl_tdv: MMS_BLK_LIMIT\n",
		    inst, pid));
		rc = dmd_blk_limit(tdv, arg, mode);
		break;
	case MMS_GET_POS :
		DMD_DEBUG((CE_CONT, "[%d:%d] dmd_ioctl_tdv: MMS_GET_POS\n",
		    inst, pid));
		rc = dmd_get_pos(tdv, arg, mode);
		break;
	case MMS_LOCATE :
		DMD_DEBUG((CE_CONT, "[%d:%d] dmd_ioctl_tdv: MMS_LOCATE\n",
		    inst, pid));
		rc = dmd_locate(tdv, arg, mode);
		break;
	case MMS_GET_CAPACITY :
		DMD_DEBUG((CE_CONT, "[%d:%d] dmd_ioctl_tdv: MMS_GET_CAPACITY\n",
		    inst, pid));
		rc = dmd_get_capacity(tdv, arg, mode);
		break;
	case MMS_UPDATE_CAPACITY :
		DMD_DEBUG((CE_CONT, "[%d:%d] dmd_ioctl_tdv: "
		    "MMS_UPDATE_CAPACITY\n", inst, pid));
		rc = dmd_upt_capacity(tdv);
		break;
	case MMS_GET_DENSITY :
		DMD_DEBUG((CE_CONT, "[%d:%d] dmd_ioctl_tdv: MMS_GET_DENSITY\n",
		    inst, pid));
		rc = dmd_get_density(tdv, arg, mode);
		break;
	case MMS_SET_DENSITY :
		DMD_DEBUG((CE_CONT, "[%d:%d] dmd_ioctl_tdv: MMS_SET_DENSITY\n",
		    inst, pid));
		rc = dmd_set_density(tdv, arg);
		break;

	case USCSICMD :
		/*
		 * Only some SCSI commands allowed by the DM are supported.
		 */
		DMD_DEBUG((CE_CONT, "[%d:%d] dmd_ioctl_tdv: USCSICMD ioctl\n",
		    inst, pid));
		rc = dmd_chk_allowed_cmd(tdv, cmd, arg, mode, rvalp);
		break;

	default :
		if (cmd == MTIOCTOP) {
			if ((rc = dmd_get_mtop(&mtop, arg, mode)) != 0) {
				goto done;
			}
			cp = dmd_lookup(dmd_mtop_tab, mtop.mt_op);
			if (cp == NULL) {
				(void) snprintf(tmp, sizeof (tmp),
				    "0x%2x", mtop.mt_op);
				cp = tmp;
			}
			DMD_DEBUG((CE_CONT, "[%d:%d] dmd_ioctl_tdv: "
			    "ioctl MTIOCTOP, %s\n", inst, pid, cp));
		} else if (cmd == MTIOCLTOP) {
			if ((rc = dmd_get_mtlop(&mtlop, arg, mode)) != 0) {
				goto done;
			}
			cp = dmd_lookup(dmd_mtop_tab, mtop.mt_op);
			if (cp == NULL) {
				(void) snprintf(tmp, sizeof (tmp),
				    "0x%2x", mtop.mt_op);
				cp = tmp;
			}
			DMD_DEBUG((CE_CONT, "[%d:%d] dmd_ioctl_tdv: "
			    "ioctl MTIOCLTOP, %s\n", inst, pid, cp));
		} else {
			cp = dmd_lookup(dmd_ioctl_tab, cmd);
			if (cp == NULL) {
				(void) snprintf(tmp, sizeof (tmp),
				    "0x%2x", cmd);
				cp = tmp;
			}
			DMD_DEBUG((CE_CONT, "[%d:%d] dmd_ioctl_tdv: ioctl %s\n",
			    inst, pid, cp));
		}

		/*
		 * Only forward allowed ioctl to target driver
		 */
		if (DMD_MASK_SET(tdv->tdv_disallowed_ioctls, cmd - MTIOC)) {
			DMD_DEBUG((CE_NOTE, "[%d:%d] dmd_ioctl_tdv: "
			    "ioctl %s not allowed "
			    "in raw mode", inst, pid, cp));
			rc = EACCES;
			goto done;
		}

		if ((tdv->tdv_flags & TDV_MMS_MODE) == 0) {
			/*
			 * Not in MMS mode, pass to target driver
			 */
			mutex_exit(&drm->drm_shr_mutex);
			rc = ldi_ioctl(drm->drm_shr_lhdl, cmd, arg,
			    mode, /* drm->drm_ioctl_mode, */
			    drm->drm_ioctl_credp,
			    rvalp);
			mutex_enter(&drm->drm_shr_mutex);
			DMD_DEBUG((CE_CONT, "[%d:%d] dmd_ioctl_tdv: "
			    "ldi_ioctl %s "
			    "returns %d\n", inst, pid, cp, rc));
			break;
		} else {
			/*
			 * In MMS mode, notify drive manager
			 */
			switch (cmd) {
			case MTIOCTOP :
				DMD_DEBUG((CE_CONT, "[%d:%d] dmd_ioctl_tdv: "
				    "MTIOCTOP\n", inst, pid));
				rc = dmd_mtioctop(tdv, arg, mode, &mtop);
				break;
			case MTIOCLTOP :
				DMD_DEBUG((CE_CONT, "[%d:%d] dmd_ioctl_tdv: "
				    "MTIOCLTOP\n", inst, pid));
				rc = dmd_mtiocltop(tdv, arg, mode, &mtlop);
				break;
			case MTIOCGET :
				DMD_DEBUG((CE_CONT, "[%d:%d] dmd_ioctl_tdv: "
				    "MTIOCGET\n", inst, pid));
				rc = dmd_mtiocget(tdv, arg, mode);
				break;
			case MTIOCGETPOS :
				DMD_DEBUG((CE_CONT, "[%d:%d] dmd_ioctl_tdv: "
				    "MTIOCGETPOS\n", inst, pid));
				rc = dmd_mtgetpos(tdv, arg, mode);
				break;
			case MTIOCRESTPOS :
				DMD_DEBUG((CE_CONT, "[%d:%d] dmd_ioctl_tdv: "
				    "MTIOCRESTPOS\n", inst, pid));
				rc = dmd_mtrestpos(tdv, arg, mode);
				break;
			case MTIOCLRERR :
				DMD_DEBUG((CE_CONT, "[%d:%d] dmd_ioctl_tdv: "
				    "MTIOCLRERR\n", inst, pid));
				rc = dmd_mtioclrerr(tdv);
				break;

			default:
				mutex_exit(&drm->drm_shr_mutex);
				rc = ldi_ioctl(drm->drm_shr_lhdl, cmd, arg,
				    mode, /* drm->drm_ioctl_mode, */
				    drm->drm_ioctl_credp,
				    rvalp);
				mutex_enter(&drm->drm_shr_mutex);
				DMD_DEBUG((CE_CONT, "[%d:%d] dmd_ioctl_tdv: "
				    "ldi_ioctl %s returns %d\n",
				    inst, pid, cp, rc));
				break;
			}
		}
	}
done:
	TDV_UNBUSY(tdv);
	if (rc != 0) {
		DMD_DEBUG((CE_CONT, "[%d:%d] dmd_ioctl_tdv: "
		    "ioctl returns %d", inst, pid, rc));
	}
	mutex_exit(&drm->drm_shr_mutex);
	return (rc);
}

static	int
dmd_get_disallowed(dmd_drm_t *drm, intptr_t arg, uchar_t *mask, int mode)
{
	int		inst = drm->drm_inst;
	pid_t		pid = drm->drm_cur_pid;

	if (ddi_copyin((void *)arg, mask, DMD_DISALLOWED_MASK_SIZE, mode)) {
		DMD_DEBUG((CE_NOTE, "[%d:%d] dmd_get_disallowed: "
		    "copyin error", inst, pid));
		return (EFAULT);
	}

	return (0);
}

static	int
dmd_chk_allowed_cmd(dmd_tdv_t *tdv, int cmd, intptr_t arg,
    int mode, int *rvalp)
{
	dmd_drm_t		*drm = tdv->tdv_drm;
	int			scsi_cmd;
	int			rc = 0;
	char			*cp;
	char			tmp[10];
	int			inst = tdv->tdv_inst;
	pid_t			pid = tdv->tdv_cur_pid;

	if ((rc = dmd_get_uscsicmd(&scsi_cmd, arg, mode)) != 0) {
		return (rc);
	}
	if ((cp = dmd_lookup(dmd_scsi_cmd_tab, scsi_cmd)) == NULL) {
		(void) snprintf(tmp, sizeof (tmp), "0x%x", scsi_cmd);
		cp = tmp;
	}
	DMD_DEBUG((CE_CONT, "[%d:%d] dmd_chk_allowed_cmd: "
	    "USCSI command is %s\n", inst, pid, cp));

	/*
	 * Only cmds that are allowed are forwarded to ST
	 */
	if (DMD_MASK_NOT_SET(tdv->tdv_disallowed_cmds, scsi_cmd)) {
		mutex_exit(&drm->drm_shr_mutex);
		rc = ldi_ioctl(drm->drm_shr_lhdl, cmd, arg,
		    mode, /* drm->drm_ioctl_mode, */
		    drm->drm_ioctl_credp,
		    rvalp);
		mutex_enter(&drm->drm_shr_mutex);
		DMD_DEBUG((CE_CONT, "[%d:%d] dmd_chk_allowed_cmd: "
		    "ldi_ioctl returns %d\n", inst, pid, rc));
	} else {
		/* Command not allowed */
		DMD_DEBUG((CE_NOTE, "[%d:%d] dmd_chk_allowed_cmd: "
		    "USCSI command not allowed: %s", inst, pid, cp));
		rc = EACCES;
	}

	return (rc);
}

static int
dmd_probe_device(dmd_drm_t *drm, drm_probe_dev_t *ino)
{
	int			i;
	dmd_soft_state_t	*ss;
	dmd_drm_t		*dm;

	mutex_enter(&dmd_sync_mutex);		/* get exclusive control */
	if (ino->drm_dev == 0) {
		/* Unset ino */
		drm->drm_probe_dev = 0;
	} else {
		/*
		 * Set ino - make sure no other DM has set the same ino.
		 * If another DM has set the same ino, then return EBUSY.
		 */
		for (i = DMD_FIRST_DEV_ORDINAL; i < dmd_next_ord; i++) {
			ss = ddi_get_soft_state(dmd_soft_statep, i * 2);
			if (ss == NULL) {
				continue;
			}
			dm = &ss->ss_drm;
			if (dm == drm) {		/* myself */
				continue;
			}
			if (dm->drm_shr_pid) {
				/* Only check opened DM's */
				if (dm->drm_probe_dev == ino->drm_dev) {
					mutex_exit(&dmd_sync_mutex);
					return (EBUSY);
				}
			}
		}
		/*
		 * No other DM has set the same ino
		 */
		drm->drm_probe_dev = ino->drm_dev;
	}
	mutex_exit(&dmd_sync_mutex);
	return (0);
}

static	int
dmd_mtioctop(dmd_tdv_t *tdv, intptr_t arg, int mode, struct mtop *mtop)
{
	dmd_drm_t	*drm = tdv->tdv_drm;
	int		rc = 0;
	int		inst = drm->drm_inst;
	pid_t		pid = drm->drm_cur_pid;

	(void) memset(&drm->drm_shr_req, 0, sizeof (drm_request_t));
	drm->drm_shr_req.drm_req_type = DRM_REQ_MTIOCTOP;
	drm->drm_shr_req.drm_mtop_req.drm_op = mtop->mt_op;
	drm->drm_shr_req.drm_mtop_req.drm_count = mtop->mt_count;

	DMD_DEBUG((CE_CONT, "[%d:%d] dmd_mtioctop: Signal for MTIOCTOP\n",
	    inst, pid));
	rc = dmd_signal_drm(drm);
	mtop->mt_op = drm->drm_shr_rep.drm_mtop_rep.drm_op;
	mtop->mt_count = drm->drm_shr_rep.drm_mtop_rep.drm_count;
	rc = dmd_return_mtop(mtop, arg, mode);
	if (rc == 0) {
		rc = drm->drm_shr_rep.drm_rep_rc;
	}
	return (rc);
}

static	int
dmd_mtiocltop(dmd_tdv_t *tdv, intptr_t arg, int mode, struct mtlop *mtlop)
{
	dmd_drm_t	*drm = tdv->tdv_drm;
	int		rc = 0;
	int		inst = drm->drm_inst;
	pid_t		pid = drm->drm_cur_pid;

	(void) memset(&drm->drm_shr_req, 0, sizeof (drm_request_t));
	drm->drm_shr_req.drm_req_type = DRM_REQ_MTIOCLTOP;
	drm->drm_shr_req.drm_mtop_req.drm_op = mtlop->mt_op;
	drm->drm_shr_req.drm_mtop_req.drm_count = mtlop->mt_count;

	DMD_DEBUG((CE_CONT, "[%d:%d] dmd_mtiocltop: Signal for MTIOCLTOP\n",
	    inst, pid));
	rc = dmd_signal_drm(drm);
	mtlop->mt_op = drm->drm_shr_rep.drm_mtop_rep.drm_op;
	mtlop->mt_count = drm->drm_shr_rep.drm_mtop_rep.drm_count;
	rc = dmd_return_mtlop(mtlop, arg, mode);
	if (rc == 0) {
		rc = drm->drm_shr_rep.drm_rep_rc;
	}
	return (rc);
}

static	int
dmd_mtiocget(dmd_tdv_t *tdv, intptr_t arg, int mode)
{
	dmd_drm_t	*drm = tdv->tdv_drm;
	int		rc = 0;
	int		inst = tdv->tdv_inst;
	pid_t		pid = tdv->tdv_cur_pid;
#ifdef	_MULTI_DATAMODEL
	/*
	 * For use when a 32 bit app makes a call into a
	 * 64 bit ioctl
	 */
	struct		mtget32		mtg_local32;
	struct		mtget32 		*mtget_32 = &mtg_local32;
#endif	/* _MULTI_DATAMODEL */
	struct	mtget		mtget_local;
	struct	mtget		*mtget = &mtget_local;

	(void) memset(&drm->drm_shr_req, 0, sizeof (drm_request_t));
	drm->drm_shr_req.drm_req_type = DRM_REQ_MTGET;

	DMD_DEBUG((CE_CONT, "[%d:%d] dmd_mtiocget: Signal for MTIOCGET\n",
	    inst, pid));
	rc = dmd_signal_drm(drm);
	if (rc == 0) {
		rc = drm->drm_shr_rep.drm_rep_rc;
	}

	if (rc != 0) {
		return (rc);
	}

	mtget->mt_erreg = 	drm->drm_shr_rep.drm_mtget_rep.drm_erreg;
	mtget->mt_resid = 	drm->drm_shr_rep.drm_mtget_rep.drm_resid;
	mtget->mt_dsreg = 	drm->drm_shr_rep.drm_mtget_rep.drm_dsreg;
	mtget->mt_fileno = 	drm->drm_shr_rep.drm_mtget_rep.drm_fileno;
	mtget->mt_blkno = 	drm->drm_shr_rep.drm_mtget_rep.drm_blkno;
	mtget->mt_type =  	drm->drm_shr_rep.drm_mtget_rep.drm_type;
	mtget->mt_flags = 	drm->drm_shr_rep.drm_mtget_rep.drm_mt_flags;
	mtget->mt_bf =		drm->drm_shr_rep.drm_mtget_rep.drm_mt_bf;

	if (drm->drm_shr_rep.drm_mtget_rep.drm_blkno_dir) {
		mtget->mt_blkno |= DRM_BLKNO_DIR_MASK;
	}

#ifdef _MULTI_DATAMODEL

	switch (ddi_model_convert_from(mode & FMODELS)) {
	case DDI_MODEL_ILP32:
		/*
		 * Convert 64 bit back to 32 bit before doing
		 * copyout. This is what the ILP32 app expects.
		 */
		mtget_32->mt_erreg = 	mtget->mt_erreg;
		mtget_32->mt_resid = 	mtget->mt_resid;
		mtget_32->mt_dsreg = 	mtget->mt_dsreg;
		mtget_32->mt_fileno = 	mtget->mt_fileno;
		mtget_32->mt_blkno = 	mtget->mt_blkno;
		mtget_32->mt_type =  	mtget->mt_type;
		mtget_32->mt_flags = 	mtget->mt_flags;
		mtget_32->mt_bf = 	mtget->mt_bf;

		if (drm->drm_shr_rep.drm_mtget_rep.drm_blkno_dir) {
			mtget_32->mt_blkno |= 0x80000000;
		}

		if (ddi_copyout(mtget_32, (void *)arg,
		    sizeof (struct mtget32), mode)) {
			DMD_DEBUG((CE_NOTE, "[%d:%d] dmd_mtiocget: "
			    "copyout error", inst, pid));
			rc = EFAULT;
		}
		break;

	case DDI_MODEL_NONE:
		if (ddi_copyout(mtget, (void *)arg,
		    sizeof (struct mtget), mode)) {
			DMD_DEBUG((CE_NOTE, "[%d:%d] dmd_mtiocget: "
			    "copyout error", inst, pid));
			rc = EFAULT;
		}
		break;
	}
#else /* ! _MULTI_DATAMODE */
	if (ddi_copyout(mtget, (void *)arg, sizeof (struct mtget), mode)) {
		rc = EFAULT;
	}
#endif /* _MULTI_DATAMODE */

	return (rc);
}

static	int
dmd_mtgetpos(dmd_tdv_t *tdv, intptr_t arg, int mode)
{
	dmd_drm_t	*drm = tdv->tdv_drm;
	int		rc = 0;
	int		inst = tdv->tdv_inst;
	pid_t		pid = tdv->tdv_cur_pid;

	(void) memset(&drm->drm_shr_req, 0, sizeof (drm_request_t));
	drm->drm_shr_req.drm_req_type = DRM_REQ_MTGETPOS;

	DMD_DEBUG((CE_CONT, "[%d:%d] dmd_mtgetpos:  Signal for MTIOCGETPOS\n",
	    inst, pid));
	rc = dmd_signal_drm(drm);
	if (rc == 0) {
		rc = drm->drm_shr_rep.drm_rep_rc;
	}

	if (rc != 0) {
		return (rc);
	}

	if (ddi_copyout(&drm->drm_shr_rep.drm_mtpos_rep,
	    (void *)arg, sizeof (tapepos_t), mode)) {
		DMD_DEBUG((CE_NOTE, "[%d:%d] dmd_mtgetpos: "
		    "copyout error", inst, pid));
		rc = EFAULT;
	}

	return (rc);
}

static	int
dmd_mtrestpos(dmd_tdv_t *tdv, intptr_t arg, int mode)
{
	dmd_drm_t	*drm = tdv->tdv_drm;
	int		rc = 0;
	int		inst = tdv->tdv_inst;
	pid_t		pid = tdv->tdv_cur_pid;

	(void) memset(&drm->drm_shr_req, 0, sizeof (drm_request_t));
	drm->drm_shr_req.drm_req_type = DRM_REQ_MTRESTPOS;

	if (ddi_copyin((void *)arg, &drm->drm_shr_req.drm_mtpos_req,
	    sizeof (tapepos_t), mode)) {
		DMD_DEBUG((CE_NOTE, "[%d:%d] dmd_mtrestpos: "
		    "copyin error", inst, pid));
		rc = EFAULT;
	}
	DMD_DEBUG((CE_CONT, "[%d:%d] dmd_mtrestpos: Signal for MTIOCRESTPOS\n",
	    inst, pid));
	rc = dmd_signal_drm(drm);
	if (rc == 0) {
		rc = drm->drm_shr_rep.drm_rep_rc;
	}

	if (rc != 0) {
		return (rc);
	}

	return (rc);
}

static	int
dmd_get_pos(dmd_tdv_t *tdv, intptr_t arg, int mode)
{
	dmd_drm_t	*drm = tdv->tdv_drm;
	int		rc = 0;
	int		inst = tdv->tdv_inst;
	pid_t		pid = tdv->tdv_cur_pid;

	(void) memset(&drm->drm_shr_req, 0, sizeof (drm_request_t));
	drm->drm_shr_req.drm_req_type = DRM_REQ_GET_POS;
	DMD_DEBUG((CE_CONT, "[%d:%d] dmd_get_pos: Signal for DRM_REQ_GET_POS\n",
	    inst, pid));
	rc = dmd_signal_drm(drm);
	if (rc == 0) {
		rc = drm->drm_shr_rep.drm_rep_rc;
	}

	if (rc != 0) {
		return (rc);
	}

	if (ddi_copyout(&drm->drm_shr_rep.drm_pos_rep, (mms_pos_t *)arg,
	    sizeof (mms_pos_t), mode)) {
		DMD_DEBUG((CE_NOTE, "[%d:%d] dmd_get_pos: "
		    "copyout error", inst, pid));
		rc = EFAULT;
	}

	return (rc);
}

static	int
dmd_locate(dmd_tdv_t *tdv, intptr_t arg, int mode)
{
	dmd_drm_t	*drm = tdv->tdv_drm;
	int		rc = 0;
	int		inst = tdv->tdv_inst;
	pid_t		pid = tdv->tdv_cur_pid;

	(void) memset(&drm->drm_shr_req, 0, sizeof (drm_request_t));
	drm->drm_shr_req.drm_req_type = DRM_REQ_LOCATE;

	if (ddi_copyin((mms_pos_t *)arg, &drm->drm_shr_req.drm_pos_req,
	    sizeof (mms_pos_t), mode)) {
		return (EFAULT);
	}

	DMD_DEBUG((CE_NOTE, "[%d:%d] Signal for DRM_REQ_LOCATE", inst, pid));
	rc = dmd_signal_drm(drm);
	if (rc == 0) {
		rc = drm->drm_shr_rep.drm_rep_rc;
	}

	return (rc);
}

static	int
dmd_get_capacity(dmd_tdv_t *tdv, intptr_t arg, int mode)
{
	dmd_drm_t	*drm = tdv->tdv_drm;
	int		rc = 0;
	int		inst = tdv->tdv_inst;
	pid_t		pid = tdv->tdv_cur_pid;

	(void) memset(&drm->drm_shr_req, 0, sizeof (drm_request_t));
	drm->drm_shr_req.drm_req_type = DRM_REQ_GET_CAPACITY;

	DMD_DEBUG((CE_CONT, "[%d:%d] dmd_get_capacity: "
	    "Signal for DRM_REQ_GET_CAPACITY\n", inst, pid));
	rc = dmd_signal_drm(drm);
	if (rc == 0) {
		rc = drm->drm_shr_rep.drm_rep_rc;
	}

	if (rc != 0) {
		return (rc);
	}

	if (ddi_copyout(&drm->drm_shr_rep.drm_cap_rep,
	    (mms_capacity_t *)arg, sizeof (mms_capacity_t), mode)) {
		DMD_DEBUG((CE_NOTE, "[%d:%d] dmd_get_capacity: "
		    "copyout error", inst, pid));
		rc = EFAULT;
	}

	return (rc);
}

static	int
dmd_upt_capacity(dmd_tdv_t *tdv)
{
	dmd_drm_t	*drm = tdv->tdv_drm;
	int		rc = 0;
	int		inst = tdv->tdv_inst;
	pid_t		pid = tdv->tdv_cur_pid;

	(void) memset(&drm->drm_shr_req, 0, sizeof (drm_request_t));
	drm->drm_shr_req.drm_req_type = DRM_REQ_UPT_CAPACITY;

	DMD_DEBUG((CE_NOTE, "[%d:%d] dmd_upt_capacity: "
	    "Signal for DRM_REQ_UPT_CAPACITY", inst, pid));
	rc = dmd_signal_drm(drm);
	if (rc == 0) {
		rc = drm->drm_shr_rep.drm_rep_rc;
	}

	return (rc);
}

static	int
dmd_get_density(dmd_tdv_t *tdv, intptr_t arg,
    int mode)
{
	dmd_drm_t		*drm = tdv->tdv_drm;
	int			rc = 0;
	mms_density_t		den;
	int			inst = tdv->tdv_inst;
	pid_t			pid = tdv->tdv_cur_pid;

	(void) memset(&drm->drm_shr_req, 0, sizeof (drm_request_t));
	drm->drm_shr_req.drm_req_type = DRM_REQ_GET_DENSITY;

	DMD_DEBUG((CE_NOTE, "[%d:%d] Signal for DRM_REQ_GET_DENSITY",
	    inst, pid));
	rc = dmd_signal_drm(drm);
	if (rc == 0) {
		rc = drm->drm_shr_rep.drm_rep_rc;
		den.mms_den = drm->drm_shr_rep.drm_den_rep;
		if (ddi_copyout(&den, (mms_density_t *)arg,
		    sizeof (mms_density_t), mode)) {
			rc = EFAULT;
		}
	}

	return (rc);
}

static	int
dmd_set_density(dmd_tdv_t *tdv, intptr_t arg)
{
	dmd_drm_t	*drm = tdv->tdv_drm;
	int		rc = 0;
	mms_density_t	den;
	int		inst = tdv->tdv_inst;
	pid_t		pid = tdv->tdv_cur_pid;

	if (ddi_copyin((void *)arg, &den, sizeof (mms_density_t), 0)) {
		DMD_DEBUG((CE_NOTE, "[%d:%d] dmd_set_density: "
		    "copyin error", inst, pid));
		return (EFAULT);
	}

	(void) memset(&drm->drm_shr_req, 0, sizeof (drm_request_t));
	drm->drm_shr_req.drm_req_type = DRM_REQ_SET_DENSITY;
	drm->drm_shr_req.drm_den_req = den.mms_den;

	DMD_DEBUG((CE_CONT, "[%d:%d] dmd_set_density: "
	    "Signal for DRM_REQ_SET_DENSITY (0x%llx)\n", inst, pid,
	    (long long)drm->drm_shr_req.drm_den_req));
	rc = dmd_signal_drm(drm);
	if (rc == 0) {
		rc = drm->drm_shr_rep.drm_rep_rc;
	}

	return (rc);
}





static	int
dmd_blk_limit(dmd_tdv_t *tdv, intptr_t arg, int mode)
{
	dmd_drm_t	*drm = tdv->tdv_drm;
	int		rc = 0;
	int		inst = tdv->tdv_inst;
	pid_t		pid = tdv->tdv_cur_pid;

	(void) memset(&drm->drm_shr_req, 0, sizeof (drm_request_t));
	drm->drm_shr_req.drm_req_type = DRM_REQ_BLK_LIMIT;

	DMD_DEBUG((CE_CONT, "[%d:%d] Signal for DRM_REQ_BLK_LIMIT\n",
	    inst, pid));
	rc = dmd_signal_drm(drm);
	if (rc == 0) {
		rc = drm->drm_shr_rep.drm_rep_rc;
	}

	if (rc != 0) {
		return (rc);
	}

	if (ddi_copyout(&drm->drm_shr_rep.drm_blk_limit_rep,
	    (mms_blk_limit_t *)arg, sizeof (mms_blk_limit_t), mode)) {
		DMD_DEBUG((CE_NOTE, "[%d:%d] dmd_blk_limit: "
		    "copyout error", inst, pid));
		rc = EFAULT;
	}

	return (rc);
}

static int
dmd_mtioclrerr(dmd_tdv_t *tdv)
{
	dmd_drm_t	*drm = tdv->tdv_drm;
	int		rc = 0;
	int		inst = tdv->tdv_inst;
	pid_t		pid = tdv->tdv_cur_pid;

	(void) memset(&drm->drm_shr_req, 0, sizeof (drm_request_t));
	drm->drm_shr_req.drm_req_type = DRM_REQ_CLRERR;

	DMD_DEBUG((CE_CONT, "[%d:%d] Signal for DRM_REQ_CLRERR\n", inst, pid));
	rc = dmd_signal_drm(drm);
	if (rc == 0) {
		rc = drm->drm_shr_rep.drm_rep_rc;
	}
	return (rc);
}

/*
 * Some utility functions
 */

static	int
dmd_ldi_open(dmd_drm_t *drm, cred_t *cred)
{
	/*
	 * Do layer open of the target device
	 */
	int		rc = 0;
	int		inst = drm->drm_inst;
	pid_t		pid = drm->drm_cur_pid;

	if (drm->drm_shr_lhdl == NULL) {
		rc = ldi_ident_from_dev(drm->drm_targ_dev, &drm->drm_shr_li);
		if (rc) {
			DMD_DEBUG((CE_NOTE, "[%d:%d] dmd_ldi_open: "
			    "can't get ldi ident, "
			    "target = (%d, %d)", inst, pid,
			    getmajor(drm->drm_targ_dev),
			    getminor(drm->drm_targ_dev)));
			goto out;
		}
		mutex_exit(&drm->drm_shr_mutex);
		rc = ldi_open_by_dev(&drm->drm_targ_dev, drm->drm_shr_otyp,
		    drm->drm_shr_oflags, cred, &drm->drm_shr_lhdl,
		    drm->drm_shr_li);
		mutex_enter(&drm->drm_shr_mutex);
		if (rc) {
			DMD_DEBUG((CE_NOTE, "[%d:%d] dmd_ldi_open: "
			    "can't ldi open, "
			    "target = (%d, %d)", inst, pid,
			    getmajor(drm->drm_targ_dev),
			    getminor(drm->drm_targ_dev)));
			ldi_ident_release(drm->drm_shr_li);
			goto out;
		}
		DMD_INC_OPENS();
		DMD_DEBUG((CE_CONT, "[%d:%d] dmd_ldi_open: "
		    "(%d:%d) opened\n", inst, pid,
		    getmajor(drm->drm_targ_dev),
		    getminor(drm->drm_targ_dev)));
	} else {
		rc = EBUSY;
	}
out:
	return (rc);
}

static	int
dmd_ldi_close(dmd_drm_t *drm, cred_t *cred)
{
	int	rc = 0;
	int	inst = drm->drm_inst;
	pid_t	pid = drm->drm_cur_pid;

	if (drm->drm_shr_lhdl != NULL) {
		if (rc = ldi_close(drm->drm_shr_lhdl, FREAD | FWRITE, cred)) {
			DMD_DEBUG((CE_NOTE, "[%d:%d] dmd_ldi_close: "
			    "ldi close error: "
			    "rc = %d: will continue to release ldi",
			    inst, pid, rc));
		}
		DMD_DEC_OPENS();
		ldi_ident_release(drm->drm_shr_li);
		drm->drm_shr_lhdl = NULL;
		DMD_DEBUG((CE_CONT, "[%d:%d] dmd_ldi_close: "
		    "(%d:%d) closed\n", inst, pid,
		    getmajor(drm->drm_targ_dev),
		    getminor(drm->drm_targ_dev)));
		drm->drm_targ_dev = (dev_t)0;
	}

	return (rc);
}

static	int
dmd_bind_dev(dmd_drm_t *drm, drm_target_t *targ, cred_t *credp)
{
	dmd_tdv_t	*tdv = drm->drm_tdv;
	int		minor;
	int		rc = 0;
	int		inst = drm->drm_inst;
	pid_t		pid = drm->drm_cur_pid;

	minor = targ->drm_targ_minor;
	if (drm->drm_targ_dev != 0) {
		DMD_DEBUG((CE_NOTE, "[%d:%d] dmd_bind_dev: already ldi opened, "
		    "(%lld,%d)", inst, pid,
		    (long long)targ->drm_targ_major, minor));
		return (EBUSY);
	}

	drm->drm_targ_dev = makedevice((major_t)targ->drm_targ_major, minor);
	drm->drm_shr_oflags = targ->drm_targ_oflags;
	DMD_DEBUG((CE_CONT, "[%d:%d] dmd_bind_dev: bound dev (%lld,%d)\n",
	    inst, pid,
	    (long long)targ->drm_targ_major, minor));
	rc = dmd_ldi_open(drm, credp);
	if (rc) {
		drm->drm_targ_dev = 0;
		return (rc);
	}
	/*
	 * Target dev is ready
	 */
	tdv = drm->drm_tdv;
	tdv->tdv_flags |= TDV_BOUND;
	return (0);
}

/*
 * Signal drive manager and wait for resume
 */
static	int
dmd_signal_drm(dmd_drm_t *drm)
{
	dmd_tdv_t	*tdv = drm->drm_tdv;
	drm_reply_t	*rep = &drm->drm_shr_rep;
	int		inst = drm->drm_inst;
	pid_t		pid = drm->drm_cur_pid;
	clock_t		cur_ticks;
	clock_t		to;
	int		rc = 0;

	/*
	 * Must hold drm->drm_shr_mutex on entry
	 */
	DMD_DEBUG((CE_CONT, "[%d:%d] dmd_signal_drm: Signalling drm\n",
	    inst, pid));
	if (drm->drm_shr_pid == 0) {
		DMD_DEBUG((CE_NOTE, "[%d:%d] No drive manager", inst, pid));
		return (ENXIO);
	}

	if (drm->drm_shr_flags & DRM_SHR_WAIT_RESUME) {
		/* Only one outstanding request allowed */
		DMD_DEBUG((CE_NOTE, "[%d:%d] dmd_signal_drm: "
		    "Has outstanding request", inst, pid));
		return (EBUSY);
	}

	if (tdv->tdv_flags & TDV_MOVED) {
		drm->drm_shr_req.drm_req_flags |= DRM_REQ_MOVED;
	}
	if (tdv->tdv_flags & TDV_NOTIFY_READ) {
		drm->drm_shr_req.drm_req_flags |= DRM_REQ_NOTIFY_READ;
	}
	if (tdv->tdv_flags & TDV_NOTIFY_WRITE) {
		drm->drm_shr_req.drm_req_flags |= DRM_REQ_NOTIFY_WRITE;
	}

	drm->drm_shr_req.drm_req_rdbytes = tdv->tdv_rdbytes;
	drm->drm_shr_req.drm_req_wrbytes = tdv->tdv_wrbytes;
	drm->drm_shr_req.drm_req_blkcnt = tdv->tdv_blkcnt;

	DMD_DEBUG((CE_NOTE, "[%d:%d] Set DRM_SHR_WAIT_RESUME", inst, pid));
	drm->drm_shr_flags |= (DRM_SHR_WAIT_RESUME | DRM_SHR_REQ_VALID);
	if (proc_signal(drm->drm_shr_proc_ref, SIGUSR1)) {
		DMD_DEBUG((CE_NOTE, "[%d:%d] dmd_signal_drm: "
		    "Can't signal drive manager %d",
		    inst, pid, drm->drm_shr_pid));
		drm->drm_shr_flags &=
		    ~(DRM_SHR_WAIT_RESUME | DRM_SHR_REQ_VALID);
		return (ENXIO);
	}
	/*
	 * Wait for DM to get request
	 */
	DMD_DEBUG((CE_CONT, "[%d:%d] Waiting for drive manager "
	    "to get request\n", inst, pid));
	while ((drm->drm_shr_flags & DRM_SHR_REQ_VALID) &&
	    (drm->drm_shr_flags & DRM_SHR_WAIT_RESUME))	{
		cur_ticks = ddi_get_lbolt();
		to = cur_ticks + drv_usectohz(DMD_WAIT_DM_GET_SEC * 1000000);
						/* Seconds to wait for DM */
		rc = cv_timedwait(&drm->drm_shr_res_cv,
		    &drm->drm_shr_mutex, to);
		if (rc == -1) {
			/* timedout */
			DMD_DEBUG((CE_NOTE, "[%d:%d] dmd_signal_drm: "
			    "Timedout waiting for DM "
			    "to get request", inst, pid));
			drm->drm_shr_flags &=
			    ~(DRM_SHR_WAIT_RESUME | DRM_SHR_REQ_VALID);
			return (ETIMEDOUT);
		}
	}

	/*
	 * Wait for resume
	 */
	DMD_DEBUG((CE_CONT, "[%d:%d] dmd_signal_drm: "
	    "Waiting for drive manager to resume\n",
	    inst, pid));
	drm->drm_shr_flags &= ~DRM_SHR_REQ_VALID;
	while (drm->drm_shr_flags & DRM_SHR_WAIT_RESUME) {
		cv_wait(&drm->drm_shr_res_cv, &drm->drm_shr_mutex);
	}

	/* Request resumed */
	DMD_DEBUG((CE_CONT, "[%d:%d] dmd_signal_drm: "
	    "Resumed, rc = %lld\n", inst, pid, (long long)rep->drm_rep_rc));
	tdv->tdv_flags &= ~TDV_MOVED;
	tdv->tdv_flags &= ~TDV_EOF;

	if (rep->drm_rep_flags & DRM_REP_FATAL) {
		DMD_DEBUG((CE_CONT, "[%d:%d] dmd_signal_drm: "
		    "Setting TDV_FATAL\n", inst, pid));
		tdv->tdv_flags |= TDV_FATAL;
	}
	if (rep->drm_rep_flags & DRM_REP_EOF) {
		DMD_DEBUG((CE_CONT, "[%d:%d] dmd_signal_drm: "
		    "Setting TDV_EOF\n", inst, pid));
		tdv->tdv_flags |= TDV_EOF;
	}

	tdv->tdv_flags &= ~(TDV_NOTIFY_WRITE | TDV_NOTIFY_READ);
	if (rep->drm_rep_flags & DRM_REP_NOTIFY_WRITE) {
		tdv->tdv_flags |= TDV_NOTIFY_WRITE;
		DMD_DEBUG((CE_CONT, "[%d:%d] dmd_signal_drm: "
		    "Setting TDV_NOTIFY_WRITE\n", inst, pid));
	}
	if (rep->drm_rep_flags & DRM_REP_NOTIFY_READ) {
		tdv->tdv_flags |= TDV_NOTIFY_READ;
		DMD_DEBUG((CE_CONT, "[%d:%d] dmd_signal_drm: "
		    "Setting TDV_NOTIFY_READ\n", inst, pid));
	}

	tdv->tdv_rdbytes = 0;
	tdv->tdv_wrbytes = 0;
	tdv->tdv_blkcnt = 0;

	return (0);
}
