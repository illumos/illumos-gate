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
 * Copyright (c) 2001, 2010, Oracle and/or its affiliates. All rights reserved.
 */
/*
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

/*
 * Multiplexed I/O SCSI vHCI implementation
 */

#include <sys/conf.h>
#include <sys/file.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/scsi/scsi.h>
#include <sys/scsi/impl/scsi_reset_notify.h>
#include <sys/scsi/impl/services.h>
#include <sys/sunmdi.h>
#include <sys/mdi_impldefs.h>
#include <sys/scsi/adapters/scsi_vhci.h>
#include <sys/disp.h>
#include <sys/byteorder.h>

extern uintptr_t scsi_callback_id;
extern ddi_dma_attr_t scsi_alloc_attr;

#ifdef	DEBUG
int	vhci_debug = VHCI_DEBUG_DEFAULT_VAL;
#endif

/* retry for the vhci_do_prout command when a not ready is returned */
int vhci_prout_not_ready_retry = 180;

/*
 * These values are defined to support the internal retry of
 * SCSI packets for better sense code handling.
 */
#define	VHCI_CMD_CMPLT	0
#define	VHCI_CMD_RETRY	1
#define	VHCI_CMD_ERROR	-1

#define	PROPFLAGS (DDI_PROP_DONTPASS | DDI_PROP_NOTPROM)
#define	VHCI_SCSI_PERR		0x47
#define	VHCI_PGR_ILLEGALOP	-2
#define	VHCI_NUM_UPDATE_TASKQ	8
/* changed to 132 to accomodate HDS */

/*
 * Version Macros
 */
#define	VHCI_NAME_VERSION	"SCSI VHCI Driver"
char		vhci_version_name[] = VHCI_NAME_VERSION;

int		vhci_first_time = 0;
clock_t		vhci_to_ticks = 0;
int		vhci_init_wait_timeout = VHCI_INIT_WAIT_TIMEOUT;
kcondvar_t	vhci_cv;
kmutex_t	vhci_global_mutex;
void		*vhci_softstate = NULL; /* for soft state */

/*
 * Flag to delay the retry of the reserve command
 */
int		vhci_reserve_delay = 100000;
static int	vhci_path_quiesce_timeout = 60;
static uchar_t	zero_key[MHIOC_RESV_KEY_SIZE];

/* uscsi delay for a TRAN_BUSY */
static int vhci_uscsi_delay = 100000;
static int vhci_uscsi_retry_count = 180;
/* uscsi_restart_sense timeout id in case it needs to get canceled */
static timeout_id_t vhci_restart_timeid = 0;

static int	vhci_bus_config_debug = 0;

/*
 * Bidirectional map of 'target-port' to port id <pid> for support of
 * iostat(1M) '-Xx' and '-Yx' output.
 */
static kmutex_t		vhci_targetmap_mutex;
static uint_t		vhci_targetmap_pid = 1;
static mod_hash_t	*vhci_targetmap_bypid;	/* <pid> -> 'target-port' */
static mod_hash_t	*vhci_targetmap_byport;	/* 'target-port' -> <pid> */

/*
 * functions exported by scsi_vhci struct cb_ops
 */
static int vhci_open(dev_t *, int, int, cred_t *);
static int vhci_close(dev_t, int, int, cred_t *);
static int vhci_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);

/*
 * functions exported by scsi_vhci struct dev_ops
 */
static int vhci_getinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int vhci_attach(dev_info_t *, ddi_attach_cmd_t);
static int vhci_detach(dev_info_t *, ddi_detach_cmd_t);

/*
 * functions exported by scsi_vhci scsi_hba_tran_t transport table
 */
static int vhci_scsi_tgt_init(dev_info_t *, dev_info_t *,
    scsi_hba_tran_t *, struct scsi_device *);
static void vhci_scsi_tgt_free(dev_info_t *, dev_info_t *, scsi_hba_tran_t *,
    struct scsi_device *);
static int vhci_pgr_register_start(scsi_vhci_lun_t *, struct scsi_pkt *);
static int vhci_scsi_start(struct scsi_address *, struct scsi_pkt *);
static int vhci_scsi_abort(struct scsi_address *, struct scsi_pkt *);
static int vhci_scsi_reset(struct scsi_address *, int);
static int vhci_scsi_reset_target(struct scsi_address *, int level,
    uint8_t select_path);
static int vhci_scsi_reset_bus(struct scsi_address *);
static int vhci_scsi_getcap(struct scsi_address *, char *, int);
static int vhci_scsi_setcap(struct scsi_address *, char *, int, int);
static int vhci_commoncap(struct scsi_address *, char *, int, int, int);
static int vhci_pHCI_cap(struct scsi_address *ap, char *cap, int val, int whom,
    mdi_pathinfo_t *pip);
static struct scsi_pkt *vhci_scsi_init_pkt(struct scsi_address *,
    struct scsi_pkt *, struct buf *, int, int, int, int, int (*)(), caddr_t);
static void vhci_scsi_destroy_pkt(struct scsi_address *, struct scsi_pkt *);
static void vhci_scsi_dmafree(struct scsi_address *, struct scsi_pkt *);
static void vhci_scsi_sync_pkt(struct scsi_address *, struct scsi_pkt *);
static int vhci_scsi_reset_notify(struct scsi_address *, int, void (*)(caddr_t),
    caddr_t);
static int vhci_scsi_get_bus_addr(struct scsi_device *, char *, int);
static int vhci_scsi_get_name(struct scsi_device *, char *, int);
static int vhci_scsi_bus_power(dev_info_t *, void *, pm_bus_power_op_t,
    void *, void *);
static int vhci_scsi_bus_config(dev_info_t *, uint_t, ddi_bus_config_op_t,
    void *, dev_info_t **);
static int vhci_scsi_bus_unconfig(dev_info_t *, uint_t, ddi_bus_config_op_t,
    void *);
static struct scsi_failover_ops *vhci_dev_fo(dev_info_t *, struct scsi_device *,
    void **, char **);

/*
 * functions registered with the mpxio framework via mdi_vhci_ops_t
 */
static int vhci_pathinfo_init(dev_info_t *, mdi_pathinfo_t *, int);
static int vhci_pathinfo_uninit(dev_info_t *, mdi_pathinfo_t *, int);
static int vhci_pathinfo_state_change(dev_info_t *, mdi_pathinfo_t *,
		mdi_pathinfo_state_t, uint32_t, int);
static int vhci_pathinfo_online(dev_info_t *, mdi_pathinfo_t *, int);
static int vhci_pathinfo_offline(dev_info_t *, mdi_pathinfo_t *, int);
static int vhci_failover(dev_info_t *, dev_info_t *, int);
static void vhci_client_attached(dev_info_t *);
static int vhci_is_dev_supported(dev_info_t *, dev_info_t *, void *);

static int vhci_ctl(dev_t, int, intptr_t, int, cred_t *, int *);
static int vhci_devctl(dev_t, int, intptr_t, int, cred_t *, int *);
static int vhci_ioc_get_phci_path(sv_iocdata_t *, caddr_t, int, caddr_t);
static int vhci_ioc_get_client_path(sv_iocdata_t *, caddr_t, int, caddr_t);
static int vhci_ioc_get_paddr(sv_iocdata_t *, caddr_t, int, caddr_t);
static int vhci_ioc_send_client_path(caddr_t, sv_iocdata_t *, int, caddr_t);
static void vhci_ioc_devi_to_path(dev_info_t *, caddr_t);
static int vhci_get_phci_path_list(dev_info_t *, sv_path_info_t *, uint_t);
static int vhci_get_client_path_list(dev_info_t *, sv_path_info_t *, uint_t);
static int vhci_get_iocdata(const void *, sv_iocdata_t *, int, caddr_t);
static int vhci_get_iocswitchdata(const void *, sv_switch_to_cntlr_iocdata_t *,
    int, caddr_t);
static int vhci_ioc_alloc_pathinfo(sv_path_info_t **, sv_path_info_t **,
    uint_t, sv_iocdata_t *, int, caddr_t);
static void vhci_ioc_free_pathinfo(sv_path_info_t *, sv_path_info_t *, uint_t);
static int vhci_ioc_send_pathinfo(sv_path_info_t *, sv_path_info_t *, uint_t,
    sv_iocdata_t *, int, caddr_t);
static int vhci_handle_ext_fo(struct scsi_pkt *, int);
static int vhci_efo_watch_cb(caddr_t, struct scsi_watch_result *);
static int vhci_quiesce_lun(struct scsi_vhci_lun *);
static int vhci_pgr_validate_and_register(scsi_vhci_priv_t *);
static void vhci_dispatch_scsi_start(void *);
static void vhci_efo_done(void *);
static void vhci_initiate_auto_failback(void *);
static void vhci_update_pHCI_pkt(struct vhci_pkt *, struct scsi_pkt *);
static int vhci_update_pathinfo(struct scsi_device *, mdi_pathinfo_t *,
    struct scsi_failover_ops *, scsi_vhci_lun_t *, struct scsi_vhci *);
static void vhci_kstat_create_pathinfo(mdi_pathinfo_t *);
static int vhci_quiesce_paths(dev_info_t *, dev_info_t *,
    scsi_vhci_lun_t *, char *, char *);

static char *vhci_devnm_to_guid(char *);
static int vhci_bind_transport(struct scsi_address *, struct vhci_pkt *,
    int, int (*func)(caddr_t));
static void vhci_intr(struct scsi_pkt *);
static int vhci_do_prout(scsi_vhci_priv_t *);
static void vhci_run_cmd(void *);
static int vhci_do_prin(struct vhci_pkt **);
static struct scsi_pkt *vhci_create_retry_pkt(struct vhci_pkt *);
static struct vhci_pkt *vhci_sync_retry_pkt(struct vhci_pkt *);
static struct scsi_vhci_lun *vhci_lun_lookup(dev_info_t *);
static struct scsi_vhci_lun *vhci_lun_lookup_alloc(dev_info_t *, char *, int *);
static void vhci_lun_free(struct scsi_vhci_lun *dvlp, struct scsi_device *sd);
static int vhci_recovery_reset(scsi_vhci_lun_t *, struct scsi_address *,
    uint8_t, uint8_t);
void vhci_update_pathstates(void *);

#ifdef DEBUG
static void vhci_print_prin_keys(vhci_prin_readkeys_t *, int);
static void vhci_print_cdb(dev_info_t *dip, uint_t level,
    char *title, uchar_t *cdb);
static void vhci_clean_print(dev_info_t *dev, uint_t level,
    char *title, uchar_t *data, int len);
#endif
static void vhci_print_prout_keys(scsi_vhci_lun_t *, char *);
static void vhci_uscsi_iodone(struct scsi_pkt *pkt);
static void vhci_invalidate_mpapi_lu(struct scsi_vhci *, scsi_vhci_lun_t *);

/*
 * MP-API related functions
 */
extern int vhci_mpapi_init(struct scsi_vhci *);
extern void vhci_mpapi_add_dev_prod(struct scsi_vhci *, char *);
extern int vhci_mpapi_ctl(dev_t, int, intptr_t, int, cred_t *, int *);
extern void vhci_update_mpapi_data(struct scsi_vhci *,
    scsi_vhci_lun_t *, mdi_pathinfo_t *);
extern void* vhci_get_mpapi_item(struct scsi_vhci *, mpapi_list_header_t *,
    uint8_t, void*);
extern void vhci_mpapi_set_path_state(dev_info_t *, mdi_pathinfo_t *, int);
extern int vhci_mpapi_update_tpg_acc_state_for_lu(struct scsi_vhci *,
    scsi_vhci_lun_t *);

#define	VHCI_DMA_MAX_XFER_CAP	INT_MAX

#define	VHCI_MAX_PGR_RETRIES	3

/*
 * Macros for the device-type mpxio options
 */
#define	LOAD_BALANCE_OPTIONS		"load-balance-options"
#define	LOGICAL_BLOCK_REGION_SIZE	"region-size"
#define	MPXIO_OPTIONS_LIST		"device-type-mpxio-options-list"
#define	DEVICE_TYPE_STR			"device-type"
#define	isdigit(ch)			((ch) >= '0' && (ch) <= '9')

static struct cb_ops vhci_cb_ops = {
	vhci_open,			/* open */
	vhci_close,			/* close */
	nodev,				/* strategy */
	nodev,				/* print */
	nodev,				/* dump */
	nodev,				/* read */
	nodev,				/* write */
	vhci_ioctl,			/* ioctl */
	nodev,				/* devmap */
	nodev,				/* mmap */
	nodev,				/* segmap */
	nochpoll,			/* chpoll */
	ddi_prop_op,			/* cb_prop_op */
	0,				/* streamtab */
	D_NEW | D_MP,			/* cb_flag */
	CB_REV,				/* rev */
	nodev,				/* aread */
	nodev				/* awrite */
};

static struct dev_ops vhci_ops = {
	DEVO_REV,
	0,
	vhci_getinfo,
	nulldev,		/* identify */
	nulldev,		/* probe */
	vhci_attach,		/* attach and detach are mandatory */
	vhci_detach,
	nodev,			/* reset */
	&vhci_cb_ops,		/* cb_ops */
	NULL,			/* bus_ops */
	NULL,			/* power */
	ddi_quiesce_not_needed,	/* quiesce */
};

extern struct mod_ops mod_driverops;

static struct modldrv modldrv = {
	&mod_driverops,
	vhci_version_name,	/* module name */
	&vhci_ops
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&modldrv,
	NULL
};

static mdi_vhci_ops_t vhci_opinfo = {
	MDI_VHCI_OPS_REV,
	vhci_pathinfo_init,		/* Pathinfo node init callback */
	vhci_pathinfo_uninit,		/* Pathinfo uninit callback */
	vhci_pathinfo_state_change,	/* Pathinfo node state change */
	vhci_failover,			/* failover callback */
	vhci_client_attached,		/* client attached callback	*/
	vhci_is_dev_supported		/* is device supported by mdi */
};

/*
 * The scsi_failover table defines an ordered set of 'fops' modules supported
 * by scsi_vhci.  Currently, initialize this table from the 'ddi-forceload'
 * property specified in scsi_vhci.conf.
 */
static struct scsi_failover {
	ddi_modhandle_t			sf_mod;
	struct scsi_failover_ops	*sf_sfo;
} *scsi_failover_table;
static uint_t	scsi_nfailover;

int
_init(void)
{
	int	rval;

	/*
	 * Allocate soft state and prepare to do ddi_soft_state_zalloc()
	 * before registering with the transport first.
	 */
	if ((rval = ddi_soft_state_init(&vhci_softstate,
	    sizeof (struct scsi_vhci), 1)) != 0) {
		VHCI_DEBUG(1, (CE_NOTE, NULL,
		    "!_init:soft state init failed\n"));
		return (rval);
	}

	if ((rval = scsi_hba_init(&modlinkage)) != 0) {
		VHCI_DEBUG(1, (CE_NOTE, NULL,
		    "!_init: scsi hba init failed\n"));
		ddi_soft_state_fini(&vhci_softstate);
		return (rval);
	}

	mutex_init(&vhci_global_mutex, NULL, MUTEX_DRIVER, NULL);
	cv_init(&vhci_cv, NULL, CV_DRIVER, NULL);

	mutex_init(&vhci_targetmap_mutex, NULL, MUTEX_DRIVER, NULL);
	vhci_targetmap_byport = mod_hash_create_strhash(
	    "vhci_targetmap_byport", 256, mod_hash_null_valdtor);
	vhci_targetmap_bypid = mod_hash_create_idhash(
	    "vhci_targetmap_bypid", 256, mod_hash_null_valdtor);

	if ((rval = mod_install(&modlinkage)) != 0) {
		VHCI_DEBUG(1, (CE_NOTE, NULL, "!_init: mod_install failed\n"));
		if (vhci_targetmap_bypid)
			mod_hash_destroy_idhash(vhci_targetmap_bypid);
		if (vhci_targetmap_byport)
			mod_hash_destroy_strhash(vhci_targetmap_byport);
		mutex_destroy(&vhci_targetmap_mutex);
		cv_destroy(&vhci_cv);
		mutex_destroy(&vhci_global_mutex);
		scsi_hba_fini(&modlinkage);
		ddi_soft_state_fini(&vhci_softstate);
	}
	return (rval);
}


/*
 * the system is done with us as a driver, so clean up
 */
int
_fini(void)
{
	int rval;

	/*
	 * don't start cleaning up until we know that the module remove
	 * has worked  -- if this works, then we know that each instance
	 * has successfully been DDI_DETACHed
	 */
	if ((rval = mod_remove(&modlinkage)) != 0) {
		VHCI_DEBUG(4, (CE_NOTE, NULL, "!_fini: mod_remove failed\n"));
		return (rval);
	}

	if (vhci_targetmap_bypid)
		mod_hash_destroy_idhash(vhci_targetmap_bypid);
	if (vhci_targetmap_byport)
		mod_hash_destroy_strhash(vhci_targetmap_byport);
	mutex_destroy(&vhci_targetmap_mutex);
	cv_destroy(&vhci_cv);
	mutex_destroy(&vhci_global_mutex);
	scsi_hba_fini(&modlinkage);
	ddi_soft_state_fini(&vhci_softstate);

	return (rval);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*
 * Lookup scsi_failover by "short name" of failover module.
 */
struct scsi_failover_ops *
vhci_failover_ops_by_name(char *name)
{
	struct scsi_failover	*sf;

	for (sf = scsi_failover_table; sf->sf_mod; sf++) {
		if (sf->sf_sfo == NULL)
			continue;
		if (strcmp(sf->sf_sfo->sfo_name, name) == 0)
			return (sf->sf_sfo);
	}
	return (NULL);
}

/*
 * Load all scsi_failover_ops 'fops' modules.
 */
static void
vhci_failover_modopen(struct scsi_vhci *vhci)
{
	char			**module;
	int			i;
	struct scsi_failover	*sf;
	char			**dt;
	int			e;

	if (scsi_failover_table)
		return;

	/* Get the list of modules from scsi_vhci.conf */
	if (ddi_prop_lookup_string_array(DDI_DEV_T_ANY,
	    vhci->vhci_dip, DDI_PROP_DONTPASS, "ddi-forceload",
	    &module, &scsi_nfailover) != DDI_PROP_SUCCESS) {
		cmn_err(CE_WARN, "scsi_vhci: "
		    "scsi_vhci.conf is missing 'ddi-forceload'");
		return;
	}
	if (scsi_nfailover == 0) {
		cmn_err(CE_WARN, "scsi_vhci: "
		    "scsi_vhci.conf has empty 'ddi-forceload'");
		ddi_prop_free(module);
		return;
	}

	/* allocate failover table based on number of modules */
	scsi_failover_table = (struct scsi_failover *)
	    kmem_zalloc(sizeof (struct scsi_failover) * (scsi_nfailover + 1),
	    KM_SLEEP);

	/* loop over modules specified in scsi_vhci.conf and open each module */
	for (i = 0, sf = scsi_failover_table; i < scsi_nfailover; i++) {
		if (module[i] == NULL)
			continue;

		sf->sf_mod = ddi_modopen(module[i], KRTLD_MODE_FIRST, &e);
		if (sf->sf_mod == NULL) {
			/*
			 * A module returns EEXIST if other software is
			 * supporting the intended function: for example
			 * the scsi_vhci_f_sum_emc module returns EEXIST
			 * from _init if EMC powerpath software is installed.
			 */
			if (e != EEXIST)
				cmn_err(CE_WARN, "scsi_vhci: unable to open "
				    "module '%s', error %d", module[i], e);
			continue;
		}
		sf->sf_sfo = ddi_modsym(sf->sf_mod,
		    "scsi_vhci_failover_ops", &e);
		if (sf->sf_sfo == NULL) {
			cmn_err(CE_WARN, "scsi_vhci: "
			    "unable to import 'scsi_failover_ops' from '%s', "
			    "error %d", module[i], e);
			(void) ddi_modclose(sf->sf_mod);
			sf->sf_mod = NULL;
			continue;
		}

		/* register vid/pid of devices supported with mpapi */
		for (dt = sf->sf_sfo->sfo_devices; *dt; dt++)
			vhci_mpapi_add_dev_prod(vhci, *dt);
		sf++;
	}

	/* verify that at least the "well-known" modules were there */
	if (vhci_failover_ops_by_name(SFO_NAME_SYM) == NULL)
		cmn_err(CE_WARN, "scsi_vhci: well-known module \""
		    SFO_NAME_SYM "\" not defined in scsi_vhci.conf's "
		    "'ddi-forceload'");
	if (vhci_failover_ops_by_name(SFO_NAME_TPGS) == NULL)
		cmn_err(CE_WARN, "scsi_vhci: well-known module \""
		    SFO_NAME_TPGS "\" not defined in scsi_vhci.conf's "
		    "'ddi-forceload'");

	/* call sfo_init for modules that need it */
	for (sf = scsi_failover_table; sf->sf_mod; sf++) {
		if (sf->sf_sfo && sf->sf_sfo->sfo_init)
			sf->sf_sfo->sfo_init();
	}

	ddi_prop_free(module);
}

/*
 * unload all loaded scsi_failover_ops modules
 */
static void
vhci_failover_modclose()
{
	struct scsi_failover	*sf;

	for (sf = scsi_failover_table; sf->sf_mod; sf++) {
		if ((sf->sf_mod == NULL) || (sf->sf_sfo == NULL))
			continue;
		(void) ddi_modclose(sf->sf_mod);
		sf->sf_mod = NULL;
		sf->sf_sfo = NULL;
	}

	if (scsi_failover_table && scsi_nfailover)
		kmem_free(scsi_failover_table,
		    sizeof (struct scsi_failover) * (scsi_nfailover + 1));
	scsi_failover_table = NULL;
	scsi_nfailover = 0;
}

/* ARGSUSED */
static int
vhci_open(dev_t *devp, int flag, int otype, cred_t *credp)
{
	struct scsi_vhci	*vhci;

	if (otype != OTYP_CHR) {
		return (EINVAL);
	}

	vhci = ddi_get_soft_state(vhci_softstate, MINOR2INST(getminor(*devp)));
	if (vhci == NULL) {
		VHCI_DEBUG(1, (CE_NOTE, NULL, "vhci_open: failed ENXIO\n"));
		return (ENXIO);
	}

	mutex_enter(&vhci->vhci_mutex);
	if ((flag & FEXCL) && (vhci->vhci_state & VHCI_STATE_OPEN)) {
		mutex_exit(&vhci->vhci_mutex);
		vhci_log(CE_NOTE, vhci->vhci_dip,
		    "!vhci%d: Already open\n", getminor(*devp));
		return (EBUSY);
	}

	vhci->vhci_state |= VHCI_STATE_OPEN;
	mutex_exit(&vhci->vhci_mutex);
	return (0);
}


/* ARGSUSED */
static int
vhci_close(dev_t dev, int flag, int otype, cred_t *credp)
{
	struct scsi_vhci	*vhci;

	if (otype != OTYP_CHR) {
		return (EINVAL);
	}

	vhci = ddi_get_soft_state(vhci_softstate, MINOR2INST(getminor(dev)));
	if (vhci == NULL) {
		VHCI_DEBUG(1, (CE_NOTE, NULL, "vhci_close: failed ENXIO\n"));
		return (ENXIO);
	}

	mutex_enter(&vhci->vhci_mutex);
	vhci->vhci_state &= ~VHCI_STATE_OPEN;
	mutex_exit(&vhci->vhci_mutex);

	return (0);
}

/* ARGSUSED */
static int
vhci_ioctl(dev_t dev, int cmd, intptr_t data, int mode,
	cred_t *credp, int *rval)
{
	if (IS_DEVCTL(cmd)) {
		return (vhci_devctl(dev, cmd, data, mode, credp, rval));
	} else if (cmd == MP_CMD) {
		return (vhci_mpapi_ctl(dev, cmd, data, mode, credp, rval));
	} else {
		return (vhci_ctl(dev, cmd, data, mode, credp, rval));
	}
}

/*
 * attach the module
 */
static int
vhci_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int			rval = DDI_FAILURE;
	int			scsi_hba_attached = 0;
	int			vhci_attached = 0;
	int			mutex_initted = 0;
	int			instance;
	struct scsi_vhci	*vhci;
	scsi_hba_tran_t		*tran;
	char			cache_name_buf[64];
	char			*data;

	VHCI_DEBUG(4, (CE_NOTE, NULL, "vhci_attach: cmd=0x%x\n", cmd));

	instance = ddi_get_instance(dip);

	switch (cmd) {
	case DDI_ATTACH:
		break;

	case DDI_RESUME:
	case DDI_PM_RESUME:
		VHCI_DEBUG(1, (CE_NOTE, NULL, "!vhci_attach: resume not yet"
		    "implemented\n"));
		return (rval);

	default:
		VHCI_DEBUG(1, (CE_NOTE, NULL,
		    "!vhci_attach: unknown ddi command\n"));
		return (rval);
	}

	/*
	 * Allocate vhci data structure.
	 */
	if (ddi_soft_state_zalloc(vhci_softstate, instance) != DDI_SUCCESS) {
		VHCI_DEBUG(1, (CE_NOTE, dip, "!vhci_attach:"
		    "soft state alloc failed\n"));
		return (DDI_FAILURE);
	}

	if ((vhci = ddi_get_soft_state(vhci_softstate, instance)) == NULL) {
		VHCI_DEBUG(1, (CE_NOTE, dip, "!vhci_attach:"
		    "bad soft state\n"));
		ddi_soft_state_free(vhci_softstate, instance);
		return (DDI_FAILURE);
	}

	/* Allocate packet cache */
	(void) snprintf(cache_name_buf, sizeof (cache_name_buf),
	    "vhci%d_cache", instance);

	mutex_init(&vhci->vhci_mutex, NULL, MUTEX_DRIVER, NULL);
	mutex_initted++;

	/*
	 * Allocate a transport structure
	 */
	tran = scsi_hba_tran_alloc(dip, SCSI_HBA_CANSLEEP);
	ASSERT(tran != NULL);

	vhci->vhci_tran		= tran;
	vhci->vhci_dip		= dip;
	vhci->vhci_instance	= instance;

	tran->tran_hba_private	= vhci;
	tran->tran_tgt_init	= vhci_scsi_tgt_init;
	tran->tran_tgt_probe	= NULL;
	tran->tran_tgt_free	= vhci_scsi_tgt_free;

	tran->tran_start	= vhci_scsi_start;
	tran->tran_abort	= vhci_scsi_abort;
	tran->tran_reset	= vhci_scsi_reset;
	tran->tran_getcap	= vhci_scsi_getcap;
	tran->tran_setcap	= vhci_scsi_setcap;
	tran->tran_init_pkt	= vhci_scsi_init_pkt;
	tran->tran_destroy_pkt	= vhci_scsi_destroy_pkt;
	tran->tran_dmafree	= vhci_scsi_dmafree;
	tran->tran_sync_pkt	= vhci_scsi_sync_pkt;
	tran->tran_reset_notify = vhci_scsi_reset_notify;

	tran->tran_get_bus_addr	= vhci_scsi_get_bus_addr;
	tran->tran_get_name	= vhci_scsi_get_name;
	tran->tran_bus_reset	= NULL;
	tran->tran_quiesce	= NULL;
	tran->tran_unquiesce	= NULL;

	/*
	 * register event notification routines with scsa
	 */
	tran->tran_get_eventcookie = NULL;
	tran->tran_add_eventcall = NULL;
	tran->tran_remove_eventcall = NULL;
	tran->tran_post_event	= NULL;

	tran->tran_bus_power	= vhci_scsi_bus_power;

	tran->tran_bus_config	= vhci_scsi_bus_config;
	tran->tran_bus_unconfig	= vhci_scsi_bus_unconfig;

	/*
	 * Attach this instance with the mpxio framework
	 */
	if (mdi_vhci_register(MDI_HCI_CLASS_SCSI, dip, &vhci_opinfo, 0)
	    != MDI_SUCCESS) {
		VHCI_DEBUG(1, (CE_NOTE, dip, "!vhci_attach:"
		    "mdi_vhci_register failed\n"));
		goto attach_fail;
	}
	vhci_attached++;

	/*
	 * Attach this instance of the hba.
	 *
	 * Regarding dma attributes: Since scsi_vhci is a virtual scsi HBA
	 * driver, it has nothing to do with DMA. However, when calling
	 * scsi_hba_attach_setup() we need to pass something valid in the
	 * dma attributes parameter. So we just use scsi_alloc_attr.
	 * SCSA itself seems to care only for dma_attr_minxfer and
	 * dma_attr_burstsizes fields of dma attributes structure.
	 * It expects those fileds to be non-zero.
	 */
	if (scsi_hba_attach_setup(dip, &scsi_alloc_attr, tran,
	    SCSI_HBA_ADDR_COMPLEX) != DDI_SUCCESS) {
		VHCI_DEBUG(1, (CE_NOTE, dip, "!vhci_attach:"
		    "hba attach failed\n"));
		goto attach_fail;
	}
	scsi_hba_attached++;

	if (ddi_create_minor_node(dip, "devctl", S_IFCHR,
	    INST2DEVCTL(instance), DDI_NT_SCSI_NEXUS, 0) != DDI_SUCCESS) {
		VHCI_DEBUG(1, (CE_NOTE, dip, "!vhci_attach:"
		    " ddi_create_minor_node failed\n"));
		goto attach_fail;
	}

	/*
	 * Set pm-want-child-notification property for
	 * power management of the phci and client
	 */
	if (ddi_prop_create(DDI_DEV_T_NONE, dip, DDI_PROP_CANSLEEP,
	    "pm-want-child-notification?", NULL, NULL) != DDI_PROP_SUCCESS) {
		cmn_err(CE_WARN,
		    "%s%d fail to create pm-want-child-notification? prop",
		    ddi_driver_name(dip), ddi_get_instance(dip));
		goto attach_fail;
	}

	vhci->vhci_taskq = taskq_create("vhci_taskq", 1, MINCLSYSPRI, 1, 4, 0);
	vhci->vhci_update_pathstates_taskq =
	    taskq_create("vhci_update_pathstates", VHCI_NUM_UPDATE_TASKQ,
	    MINCLSYSPRI, 1, 4, 0);
	ASSERT(vhci->vhci_taskq);
	ASSERT(vhci->vhci_update_pathstates_taskq);

	/*
	 * Set appropriate configuration flags based on options set in
	 * conf file.
	 */
	vhci->vhci_conf_flags = 0;
	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, dip, PROPFLAGS,
	    "auto-failback", &data) == DDI_SUCCESS) {
		if (strcmp(data, "enable") == 0)
			vhci->vhci_conf_flags |= VHCI_CONF_FLAGS_AUTO_FAILBACK;
		ddi_prop_free(data);
	}

	if (!(vhci->vhci_conf_flags & VHCI_CONF_FLAGS_AUTO_FAILBACK))
		vhci_log(CE_NOTE, dip, "!Auto-failback capability "
		    "disabled through scsi_vhci.conf file.");

	/*
	 * Allocate an mpapi private structure
	 */
	vhci->mp_priv = kmem_zalloc(sizeof (mpapi_priv_t), KM_SLEEP);
	if (vhci_mpapi_init(vhci) != 0) {
		VHCI_DEBUG(1, (CE_WARN, NULL, "!vhci_attach: "
		    "vhci_mpapi_init() failed"));
	}

	vhci_failover_modopen(vhci);		/* load failover modules */

	ddi_report_dev(dip);
	return (DDI_SUCCESS);

attach_fail:
	if (vhci_attached)
		(void) mdi_vhci_unregister(dip, 0);

	if (scsi_hba_attached)
		(void) scsi_hba_detach(dip);

	if (vhci->vhci_tran)
		scsi_hba_tran_free(vhci->vhci_tran);

	if (mutex_initted) {
		mutex_destroy(&vhci->vhci_mutex);
	}

	ddi_soft_state_free(vhci_softstate, instance);
	return (DDI_FAILURE);
}


/*ARGSUSED*/
static int
vhci_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int			instance = ddi_get_instance(dip);
	scsi_hba_tran_t		*tran;
	struct scsi_vhci	*vhci;

	VHCI_DEBUG(4, (CE_NOTE, NULL, "vhci_detach: cmd=0x%x\n", cmd));

	if ((tran = ddi_get_driver_private(dip)) == NULL)
		return (DDI_FAILURE);

	vhci = TRAN2HBAPRIVATE(tran);
	if (!vhci) {
		return (DDI_FAILURE);
	}

	switch (cmd) {
	case DDI_DETACH:
		break;

	case DDI_SUSPEND:
	case DDI_PM_SUSPEND:
		VHCI_DEBUG(1, (CE_NOTE, NULL, "!vhci_detach: suspend/pm not yet"
		    "implemented\n"));
		return (DDI_FAILURE);

	default:
		VHCI_DEBUG(1, (CE_NOTE, NULL,
		    "!vhci_detach: unknown ddi command\n"));
		return (DDI_FAILURE);
	}

	(void) mdi_vhci_unregister(dip, 0);
	(void) scsi_hba_detach(dip);
	scsi_hba_tran_free(tran);

	if (ddi_prop_remove(DDI_DEV_T_NONE, dip,
	    "pm-want-child-notification?") != DDI_PROP_SUCCESS) {
		cmn_err(CE_WARN,
		    "%s%d unable to remove prop pm-want_child_notification?",
		    ddi_driver_name(dip), ddi_get_instance(dip));
	}
	if (vhci_restart_timeid != 0) {
		(void) untimeout(vhci_restart_timeid);
	}
	vhci_restart_timeid = 0;

	mutex_destroy(&vhci->vhci_mutex);
	vhci->vhci_dip = NULL;
	vhci->vhci_tran = NULL;
	taskq_destroy(vhci->vhci_taskq);
	taskq_destroy(vhci->vhci_update_pathstates_taskq);
	ddi_remove_minor_node(dip, NULL);
	ddi_soft_state_free(vhci_softstate, instance);

	vhci_failover_modclose();		/* unload failover modules */
	return (DDI_SUCCESS);
}

/*
 * vhci_getinfo()
 * Given the device number, return the devinfo pointer or the
 * instance number.
 * Note: always succeed DDI_INFO_DEVT2INSTANCE, even before attach.
 */

/*ARGSUSED*/
static int
vhci_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **result)
{
	struct scsi_vhci	*vhcip;
	int			instance = MINOR2INST(getminor((dev_t)arg));

	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		vhcip = ddi_get_soft_state(vhci_softstate, instance);
		if (vhcip != NULL)
			*result = vhcip->vhci_dip;
		else {
			*result = NULL;
			return (DDI_FAILURE);
		}
		break;

	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)(uintptr_t)instance;
		break;

	default:
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
vhci_scsi_tgt_init(dev_info_t *hba_dip, dev_info_t *tgt_dip,
	scsi_hba_tran_t *hba_tran, struct scsi_device *sd)
{
	char			*guid;
	scsi_vhci_lun_t		*vlun;
	struct scsi_vhci	*vhci;
	clock_t			from_ticks;
	mdi_pathinfo_t		*pip;
	int			rval;

	ASSERT(hba_dip != NULL);
	ASSERT(tgt_dip != NULL);

	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, tgt_dip, PROPFLAGS,
	    MDI_CLIENT_GUID_PROP, &guid) != DDI_SUCCESS) {
		/*
		 * This must be the .conf node without GUID property.
		 * The node under fp already inserts a delay, so we
		 * just return from here. We rely on this delay to have
		 * all dips be posted to the ndi hotplug thread's newdev
		 * list. This is necessary for the deferred attach
		 * mechanism to work and opens() done soon after boot to
		 * succeed.
		 */
		VHCI_DEBUG(4, (CE_WARN, hba_dip, "tgt_init: lun guid "
		    "property failed"));
		return (DDI_NOT_WELL_FORMED);
	}

	if (ndi_dev_is_persistent_node(tgt_dip) == 0) {
		/*
		 * This must be .conf node with the GUID property. We don't
		 * merge property by ndi_merge_node() here  because the
		 * devi_addr_buf of .conf node is "" always according the
		 * implementation of vhci_scsi_get_name_bus_addr().
		 */
		ddi_set_name_addr(tgt_dip, NULL);
		return (DDI_FAILURE);
	}

	vhci = ddi_get_soft_state(vhci_softstate, ddi_get_instance(hba_dip));
	ASSERT(vhci != NULL);

	VHCI_DEBUG(4, (CE_NOTE, hba_dip,
	    "!tgt_init: called for %s (instance %d)\n",
	    ddi_driver_name(tgt_dip), ddi_get_instance(tgt_dip)));

	vlun = vhci_lun_lookup(tgt_dip);

	mutex_enter(&vhci_global_mutex);

	from_ticks = ddi_get_lbolt();
	if (vhci_to_ticks == 0) {
		vhci_to_ticks = from_ticks +
		    drv_usectohz(vhci_init_wait_timeout);
	}

#if DEBUG
	if (vlun) {
		VHCI_DEBUG(1, (CE_WARN, hba_dip, "tgt_init: "
		    "vhci_scsi_tgt_init: guid %s : found vlun 0x%p "
		    "from_ticks %lx to_ticks %lx",
		    guid, (void *)vlun, from_ticks, vhci_to_ticks));
	} else {
		VHCI_DEBUG(1, (CE_WARN, hba_dip, "tgt_init: "
		    "vhci_scsi_tgt_init: guid %s : vlun not found "
		    "from_ticks %lx to_ticks %lx", guid, from_ticks,
		    vhci_to_ticks));
	}
#endif

	rval = mdi_select_path(tgt_dip, NULL,
	    (MDI_SELECT_ONLINE_PATH | MDI_SELECT_STANDBY_PATH), NULL, &pip);
	if (rval == MDI_SUCCESS) {
		mdi_rele_path(pip);
	}

	/*
	 * Wait for the following conditions :
	 *	1. no vlun available yet
	 *	2. no path established
	 *	3. timer did not expire
	 */
	while ((vlun == NULL) || (mdi_client_get_path_count(tgt_dip) == 0) ||
	    (rval != MDI_SUCCESS)) {
		if (vlun && vlun->svl_not_supported) {
			VHCI_DEBUG(1, (CE_WARN, hba_dip, "tgt_init: "
			    "vlun 0x%p lun guid %s not supported!",
			    (void *)vlun, guid));
			mutex_exit(&vhci_global_mutex);
			ddi_prop_free(guid);
			return (DDI_NOT_WELL_FORMED);
		}
		if ((vhci_first_time == 0) && (from_ticks >= vhci_to_ticks)) {
			vhci_first_time = 1;
		}
		if (vhci_first_time == 1) {
			VHCI_DEBUG(1, (CE_WARN, hba_dip, "vhci_scsi_tgt_init: "
			    "no wait for %s. from_tick %lx, to_tick %lx",
			    guid, from_ticks, vhci_to_ticks));
			mutex_exit(&vhci_global_mutex);
			ddi_prop_free(guid);
			return (DDI_NOT_WELL_FORMED);
		}

		if (cv_timedwait(&vhci_cv,
		    &vhci_global_mutex, vhci_to_ticks) == -1) {
			/* Timed out */
#ifdef DEBUG
			if (vlun == NULL) {
				VHCI_DEBUG(1, (CE_WARN, hba_dip,
				    "tgt_init: no vlun for %s!", guid));
			} else if (mdi_client_get_path_count(tgt_dip) == 0) {
				VHCI_DEBUG(1, (CE_WARN, hba_dip,
				    "tgt_init: client path count is "
				    "zero for %s!", guid));
			} else {
				VHCI_DEBUG(1, (CE_WARN, hba_dip,
				    "tgt_init: client path not "
				    "available yet for %s!", guid));
			}
#endif /* DEBUG */
			mutex_exit(&vhci_global_mutex);
			ddi_prop_free(guid);
			return (DDI_NOT_WELL_FORMED);
		}
		vlun = vhci_lun_lookup(tgt_dip);
		rval = mdi_select_path(tgt_dip, NULL,
		    (MDI_SELECT_ONLINE_PATH | MDI_SELECT_STANDBY_PATH),
		    NULL, &pip);
		if (rval == MDI_SUCCESS) {
			mdi_rele_path(pip);
		}
		from_ticks = ddi_get_lbolt();
	}
	mutex_exit(&vhci_global_mutex);

	ASSERT(vlun != NULL);
	ddi_prop_free(guid);

	scsi_device_hba_private_set(sd, vlun);

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static void
vhci_scsi_tgt_free(dev_info_t *hba_dip, dev_info_t *tgt_dip,
	scsi_hba_tran_t *hba_tran, struct scsi_device *sd)
{
	struct scsi_vhci_lun *dvlp;
	ASSERT(mdi_client_get_path_count(tgt_dip) <= 0);
	dvlp = (struct scsi_vhci_lun *)scsi_device_hba_private_get(sd);
	ASSERT(dvlp != NULL);

	vhci_lun_free(dvlp, sd);
}

/*
 * a PGR register command has started; copy the info we need
 */
int
vhci_pgr_register_start(scsi_vhci_lun_t *vlun, struct scsi_pkt *pkt)
{
	struct vhci_pkt		*vpkt = TGTPKT2VHCIPKT(pkt);
	void			*addr;

	if (!vpkt->vpkt_tgt_init_bp)
		return (TRAN_BADPKT);

	addr = bp_mapin_common(vpkt->vpkt_tgt_init_bp,
	    (vpkt->vpkt_flags & CFLAG_NOWAIT) ? VM_NOSLEEP : VM_SLEEP);
	if (addr == NULL)
		return (TRAN_BUSY);

	mutex_enter(&vlun->svl_mutex);

	vhci_print_prout_keys(vlun, "v_pgr_reg_start: before bcopy:");

	bcopy(addr, &vlun->svl_prout, sizeof (vhci_prout_t) -
	    (2 * MHIOC_RESV_KEY_SIZE*sizeof (char)));
	bcopy(pkt->pkt_cdbp, vlun->svl_cdb, sizeof (vlun->svl_cdb));

	vhci_print_prout_keys(vlun, "v_pgr_reg_start: after bcopy:");

	vlun->svl_time = pkt->pkt_time;
	vlun->svl_bcount = vpkt->vpkt_tgt_init_bp->b_bcount;
	vlun->svl_first_path = vpkt->vpkt_path;
	mutex_exit(&vlun->svl_mutex);
	return (0);
}

/*
 * Function name : vhci_scsi_start()
 *
 * Return Values : TRAN_FATAL_ERROR	- vhci has been shutdown
 *					  or other fatal failure
 *					  preventing packet transportation
 *		   TRAN_BUSY		- request queue is full
 *		   TRAN_ACCEPT		- pkt has been submitted to phci
 *					  (or is held in the waitQ)
 * Description	 : Implements SCSA's tran_start() entry point for
 *		   packet transport
 *
 */
static int
vhci_scsi_start(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	int			rval = TRAN_ACCEPT;
	int			instance, held;
	struct scsi_vhci	*vhci = ADDR2VHCI(ap);
	struct scsi_vhci_lun	*vlun = ADDR2VLUN(ap);
	struct vhci_pkt		*vpkt = TGTPKT2VHCIPKT(pkt);
	int			flags = 0;
	scsi_vhci_priv_t	*svp, *svp_resrv;
	dev_info_t 		*cdip;
	client_lb_t		lbp;
	int			restore_lbp = 0;
	/* set if pkt is SCSI-II RESERVE cmd */
	int			pkt_reserve_cmd = 0;
	int			reserve_failed = 0;
	int			resrv_instance = 0;
	mdi_pathinfo_t		*pip;
	struct scsi_pkt		*rel_pkt;

	ASSERT(vhci != NULL);
	ASSERT(vpkt != NULL);
	ASSERT(vpkt->vpkt_state != VHCI_PKT_ISSUED);
	cdip = ADDR2DIP(ap);

	/*
	 * Block IOs if LUN is held or QUIESCED for IOs.
	 */
	if ((VHCI_LUN_IS_HELD(vlun)) ||
	    ((vlun->svl_flags & VLUN_QUIESCED_FLG) == VLUN_QUIESCED_FLG)) {
		return (TRAN_BUSY);
	}

	/*
	 * vhci_lun needs to be quiesced before SCSI-II RESERVE command
	 * can be issued.  This may require a cv_timedwait, which is
	 * dangerous to perform in an interrupt context.  So if this
	 * is a RESERVE command a taskq is dispatched to service it.
	 * This taskq shall again call vhci_scsi_start, but we shall be
	 * sure its not in an interrupt context.
	 */
	if ((pkt->pkt_cdbp[0] == SCMD_RESERVE) ||
	    (pkt->pkt_cdbp[0] == SCMD_RESERVE_G1)) {
		if (!(vpkt->vpkt_state & VHCI_PKT_THRU_TASKQ)) {
			if (taskq_dispatch(vhci->vhci_taskq,
			    vhci_dispatch_scsi_start, (void *) vpkt,
			    KM_NOSLEEP)) {
				return (TRAN_ACCEPT);
			} else {
				return (TRAN_BUSY);
			}
		}

		/*
		 * Here we ensure that simultaneous SCSI-II RESERVE cmds don't
		 * get serviced for a lun.
		 */
		VHCI_HOLD_LUN(vlun, VH_NOSLEEP, held);
		if (!held) {
			return (TRAN_BUSY);
		} else if ((vlun->svl_flags & VLUN_QUIESCED_FLG) ==
		    VLUN_QUIESCED_FLG) {
			VHCI_RELEASE_LUN(vlun);
			return (TRAN_BUSY);
		}

		/*
		 * To ensure that no IOs occur for this LUN for the duration
		 * of this pkt set the VLUN_QUIESCED_FLG.
		 * In case this routine needs to exit on error make sure that
		 * this flag is cleared.
		 */
		vlun->svl_flags |= VLUN_QUIESCED_FLG;
		pkt_reserve_cmd = 1;

		/*
		 * if this is a SCSI-II RESERVE command, set load balancing
		 * policy to be ALTERNATE PATH to ensure that all subsequent
		 * IOs are routed on the same path.  This is because if commands
		 * are routed across multiple paths then IOs on paths other than
		 * the one on which the RESERVE was executed will get a
		 * RESERVATION CONFLICT
		 */
		lbp = mdi_get_lb_policy(cdip);
		if (lbp != LOAD_BALANCE_NONE) {
			if (vhci_quiesce_lun(vlun) != 1) {
				vlun->svl_flags &= ~VLUN_QUIESCED_FLG;
				VHCI_RELEASE_LUN(vlun);
				return (TRAN_FATAL_ERROR);
			}
			vlun->svl_lb_policy_save = lbp;
			if (mdi_set_lb_policy(cdip, LOAD_BALANCE_NONE) !=
			    MDI_SUCCESS) {
				vlun->svl_flags &= ~VLUN_QUIESCED_FLG;
				VHCI_RELEASE_LUN(vlun);
				return (TRAN_FATAL_ERROR);
			}
			restore_lbp = 1;
		}

		VHCI_DEBUG(2, (CE_NOTE, vhci->vhci_dip,
		    "!vhci_scsi_start: sending SCSI-2 RESERVE, vlun 0x%p, "
		    "svl_resrv_pip 0x%p, svl_flags: %x, lb_policy %x",
		    (void *)vlun, (void *)vlun->svl_resrv_pip, vlun->svl_flags,
		    mdi_get_lb_policy(cdip)));

		/*
		 * See comments for VLUN_RESERVE_ACTIVE_FLG in scsi_vhci.h
		 * To narrow this window where a reserve command may be sent
		 * down an inactive path the path states first need to be
		 * updated.  Before calling vhci_update_pathstates reset
		 * VLUN_RESERVE_ACTIVE_FLG, just in case it was already set
		 * for this lun.  This shall prevent an unnecessary reset
		 * from being sent out.  Also remember currently reserved path
		 * just for a case the new reservation will go to another path.
		 */
		if (vlun->svl_flags & VLUN_RESERVE_ACTIVE_FLG) {
			resrv_instance = mdi_pi_get_path_instance(
			    vlun->svl_resrv_pip);
		}
		vlun->svl_flags &= ~VLUN_RESERVE_ACTIVE_FLG;
		vhci_update_pathstates((void *)vlun);
	}

	instance = ddi_get_instance(vhci->vhci_dip);

	/*
	 * If the command is PRIN with action of zero, then the cmd
	 * is reading PR keys which requires filtering on completion.
	 * Data cache sync must be guaranteed.
	 */
	if ((pkt->pkt_cdbp[0] == SCMD_PRIN) && (pkt->pkt_cdbp[1] == 0) &&
	    (vpkt->vpkt_org_vpkt == NULL)) {
		vpkt->vpkt_tgt_init_pkt_flags |= PKT_CONSISTENT;
	}

	/*
	 * Do not defer bind for PKT_DMA_PARTIAL
	 */
	if ((vpkt->vpkt_flags & CFLAG_DMA_PARTIAL) == 0) {

		/* This is a non pkt_dma_partial case */
		if ((rval = vhci_bind_transport(
		    ap, vpkt, vpkt->vpkt_tgt_init_pkt_flags, NULL_FUNC))
		    != TRAN_ACCEPT) {
			VHCI_DEBUG(6, (CE_WARN, vhci->vhci_dip,
			    "!vhci%d %x: failed to bind transport: "
			    "vlun 0x%p pkt_reserved %x restore_lbp %x,"
			    "lbp %x", instance, rval, (void *)vlun,
			    pkt_reserve_cmd, restore_lbp, lbp));
			if (restore_lbp)
				(void) mdi_set_lb_policy(cdip, lbp);
			if (pkt_reserve_cmd)
				vlun->svl_flags &= ~VLUN_QUIESCED_FLG;
			return (rval);
		}
		VHCI_DEBUG(8, (CE_NOTE, NULL,
		    "vhci_scsi_start: v_b_t called 0x%p\n", (void *)vpkt));
	}
	ASSERT(vpkt->vpkt_hba_pkt != NULL);
	ASSERT(vpkt->vpkt_path != NULL);

	/*
	 * This is the chance to adjust the pHCI's pkt and other information
	 * from target driver's pkt.
	 */
	VHCI_DEBUG(8, (CE_NOTE, vhci->vhci_dip, "vhci_scsi_start vpkt %p\n",
	    (void *)vpkt));
	vhci_update_pHCI_pkt(vpkt, pkt);

	if (vlun->svl_flags & VLUN_RESERVE_ACTIVE_FLG) {
		if (vpkt->vpkt_path != vlun->svl_resrv_pip) {
			VHCI_DEBUG(1, (CE_WARN, vhci->vhci_dip,
			    "!vhci_bind: reserve flag set for vlun 0x%p, but, "
			    "pktpath 0x%p resrv path 0x%p differ. lb_policy %x",
			    (void *)vlun, (void *)vpkt->vpkt_path,
			    (void *)vlun->svl_resrv_pip,
			    mdi_get_lb_policy(cdip)));
			reserve_failed = 1;
		}
	}

	svp = (scsi_vhci_priv_t *)mdi_pi_get_vhci_private(vpkt->vpkt_path);
	if (svp == NULL || reserve_failed) {
		if (pkt_reserve_cmd) {
			VHCI_DEBUG(6, (CE_WARN, vhci->vhci_dip,
			    "!vhci_bind returned null svp vlun 0x%p",
			    (void *)vlun));
			vlun->svl_flags &= ~VLUN_QUIESCED_FLG;
			if (restore_lbp)
				(void) mdi_set_lb_policy(cdip, lbp);
		}
pkt_cleanup:
		if ((vpkt->vpkt_flags & CFLAG_DMA_PARTIAL) == 0) {
			scsi_destroy_pkt(vpkt->vpkt_hba_pkt);
			vpkt->vpkt_hba_pkt = NULL;
			if (vpkt->vpkt_path) {
				mdi_rele_path(vpkt->vpkt_path);
				vpkt->vpkt_path = NULL;
			}
		}
		if ((pkt->pkt_cdbp[0] == SCMD_PROUT) &&
		    (((pkt->pkt_cdbp[1] & 0x1f) == VHCI_PROUT_REGISTER) ||
		    ((pkt->pkt_cdbp[1] & 0x1f) == VHCI_PROUT_R_AND_IGNORE))) {
			sema_v(&vlun->svl_pgr_sema);
		}
		return (TRAN_BUSY);
	}

	if ((resrv_instance != 0) && (resrv_instance !=
	    mdi_pi_get_path_instance(vpkt->vpkt_path))) {
		/*
		 * This is an attempt to reserve vpkt->vpkt_path.  But the
		 * previously reserved path referred by resrv_instance might
		 * still be reserved.  Hence we will send a release command
		 * there in order to avoid a reservation conflict.
		 */
		VHCI_DEBUG(1, (CE_NOTE, vhci->vhci_dip, "!vhci_scsi_start: "
		    "conflicting reservation on another path, vlun 0x%p, "
		    "reserved instance %d, new instance: %d, pip: 0x%p",
		    (void *)vlun, resrv_instance,
		    mdi_pi_get_path_instance(vpkt->vpkt_path),
		    (void *)vpkt->vpkt_path));

		/*
		 * In rare cases, the path referred by resrv_instance could
		 * disappear in the meantime. Calling mdi_select_path() below
		 * is an attempt to find out if the path still exists. It also
		 * ensures that the path will be held when the release is sent.
		 */
		rval = mdi_select_path(cdip, NULL, MDI_SELECT_PATH_INSTANCE,
		    (void *)(intptr_t)resrv_instance, &pip);

		if ((rval == MDI_SUCCESS) && (pip != NULL)) {
			svp_resrv = (scsi_vhci_priv_t *)
			    mdi_pi_get_vhci_private(pip);
			rel_pkt = scsi_init_pkt(&svp_resrv->svp_psd->sd_address,
			    NULL, NULL, CDB_GROUP0,
			    sizeof (struct scsi_arq_status), 0, 0, SLEEP_FUNC,
			    NULL);

			if (rel_pkt == NULL) {
				char	*p_path;

				/*
				 * This is very unlikely.
				 * scsi_init_pkt(SLEEP_FUNC) does not fail
				 * because of resources. But in theory it could
				 * fail for some other reason. There is not an
				 * easy way how to recover though. Log a warning
				 * and return.
				 */
				p_path = kmem_zalloc(MAXPATHLEN, KM_SLEEP);
				vhci_log(CE_WARN, vhci->vhci_dip, "!Sending "
				    "RELEASE(6) to %s failed, a potential "
				    "reservation conflict ahead.",
				    ddi_pathname(mdi_pi_get_phci(pip), p_path));
				kmem_free(p_path, MAXPATHLEN);

				if (restore_lbp)
					(void) mdi_set_lb_policy(cdip, lbp);

				/* no need to check pkt_reserve_cmd here */
				vlun->svl_flags &= ~VLUN_QUIESCED_FLG;
				return (TRAN_FATAL_ERROR);
			}

			rel_pkt->pkt_cdbp[0] = SCMD_RELEASE;
			rel_pkt->pkt_time = 60;

			/*
			 * Ignore the return value.  If it will fail
			 * then most likely it is no longer reserved
			 * anyway.
			 */
			(void) vhci_do_scsi_cmd(rel_pkt);
			VHCI_DEBUG(1, (CE_NOTE, NULL,
			    "!vhci_scsi_start: path 0x%p, issued SCSI-2"
			    " RELEASE\n", (void *)pip));
			scsi_destroy_pkt(rel_pkt);
			mdi_rele_path(pip);
		}
	}

	VHCI_INCR_PATH_CMDCOUNT(svp);

	/*
	 * Ensure that no other IOs raced ahead, while a RESERVE cmd was
	 * QUIESCING the same lun.
	 */
	if ((!pkt_reserve_cmd) &&
	    ((vlun->svl_flags & VLUN_QUIESCED_FLG) == VLUN_QUIESCED_FLG)) {
		VHCI_DECR_PATH_CMDCOUNT(svp);
		goto pkt_cleanup;
	}

	if ((pkt->pkt_cdbp[0] == SCMD_PRIN) ||
	    (pkt->pkt_cdbp[0] == SCMD_PROUT)) {
		/*
		 * currently this thread only handles running PGR
		 * commands, so don't bother creating it unless
		 * something interesting is going to happen (like
		 * either a PGR out, or a PGR in with enough space
		 * to hold the keys that are getting returned)
		 */
		mutex_enter(&vlun->svl_mutex);
		if (((vlun->svl_flags & VLUN_TASK_D_ALIVE_FLG) == 0) &&
		    (pkt->pkt_cdbp[0] == SCMD_PROUT)) {
			vlun->svl_taskq = taskq_create("vlun_pgr_task_daemon",
			    1, MINCLSYSPRI, 1, 4, 0);
			vlun->svl_flags |= VLUN_TASK_D_ALIVE_FLG;
		}
		mutex_exit(&vlun->svl_mutex);
		if ((pkt->pkt_cdbp[0] == SCMD_PROUT) &&
		    (((pkt->pkt_cdbp[1] & 0x1f) == VHCI_PROUT_REGISTER) ||
		    ((pkt->pkt_cdbp[1] & 0x1f) == VHCI_PROUT_R_AND_IGNORE))) {
			if (rval = vhci_pgr_register_start(vlun, pkt)) {
				/* an error */
				sema_v(&vlun->svl_pgr_sema);
				return (rval);
			}
		}
	}

	/*
	 * SCSI-II RESERVE cmd is not expected in polled mode.
	 * If this changes it needs to be handled for the polled scenario.
	 */
	flags = vpkt->vpkt_hba_pkt->pkt_flags;

	/*
	 * Set the path_instance *before* sending the scsi_pkt down the path
	 * to mpxio's pHCI so that additional path abstractions at a pHCI
	 * level (like maybe iSCSI at some point in the future) can update
	 * the path_instance.
	 */
	if (scsi_pkt_allocated_correctly(vpkt->vpkt_hba_pkt))
		vpkt->vpkt_hba_pkt->pkt_path_instance =
		    mdi_pi_get_path_instance(vpkt->vpkt_path);

	rval = scsi_transport(vpkt->vpkt_hba_pkt);
	if (rval == TRAN_ACCEPT) {
		if (flags & FLAG_NOINTR) {
			struct scsi_pkt *tpkt = vpkt->vpkt_tgt_pkt;
			struct scsi_pkt *pkt = vpkt->vpkt_hba_pkt;

			ASSERT(tpkt != NULL);
			*(tpkt->pkt_scbp) = *(pkt->pkt_scbp);
			tpkt->pkt_resid = pkt->pkt_resid;
			tpkt->pkt_state = pkt->pkt_state;
			tpkt->pkt_statistics = pkt->pkt_statistics;
			tpkt->pkt_reason = pkt->pkt_reason;

			if ((*(pkt->pkt_scbp) == STATUS_CHECK) &&
			    (pkt->pkt_state & STATE_ARQ_DONE)) {
				bcopy(pkt->pkt_scbp, tpkt->pkt_scbp,
				    vpkt->vpkt_tgt_init_scblen);
			}

			VHCI_DECR_PATH_CMDCOUNT(svp);
			if ((vpkt->vpkt_flags & CFLAG_DMA_PARTIAL) == 0) {
				scsi_destroy_pkt(vpkt->vpkt_hba_pkt);
				vpkt->vpkt_hba_pkt = NULL;
				if (vpkt->vpkt_path) {
					mdi_rele_path(vpkt->vpkt_path);
					vpkt->vpkt_path = NULL;
				}
			}
			/*
			 * This path will not automatically retry pkts
			 * internally, therefore, vpkt_org_vpkt should
			 * never be set.
			 */
			ASSERT(vpkt->vpkt_org_vpkt == NULL);
			scsi_hba_pkt_comp(tpkt);
		}
		return (rval);
	} else if ((pkt->pkt_cdbp[0] == SCMD_PROUT) &&
	    (((pkt->pkt_cdbp[1] & 0x1f) == VHCI_PROUT_REGISTER) ||
	    ((pkt->pkt_cdbp[1] & 0x1f) == VHCI_PROUT_R_AND_IGNORE))) {
		/* the command exited with bad status */
		sema_v(&vlun->svl_pgr_sema);
	} else if (vpkt->vpkt_tgt_pkt->pkt_cdbp[0] == SCMD_PRIN) {
		/* the command exited with bad status */
		sema_v(&vlun->svl_pgr_sema);
	} else if (pkt_reserve_cmd) {
		VHCI_DEBUG(6, (CE_WARN, vhci->vhci_dip,
		    "!vhci_scsi_start: reserve failed vlun 0x%p",
		    (void *)vlun));
		vlun->svl_flags &= ~VLUN_QUIESCED_FLG;
		if (restore_lbp)
			(void) mdi_set_lb_policy(cdip, lbp);
	}

	ASSERT(vpkt->vpkt_hba_pkt != NULL);
	VHCI_DECR_PATH_CMDCOUNT(svp);

	/* Do not destroy phci packet information for PKT_DMA_PARTIAL */
	if ((vpkt->vpkt_flags & CFLAG_DMA_PARTIAL) == 0) {
		scsi_destroy_pkt(vpkt->vpkt_hba_pkt);
		vpkt->vpkt_hba_pkt = NULL;
		if (vpkt->vpkt_path) {
			MDI_PI_ERRSTAT(vpkt->vpkt_path, MDI_PI_TRANSERR);
			mdi_rele_path(vpkt->vpkt_path);
			vpkt->vpkt_path = NULL;
		}
	}
	return (TRAN_BUSY);
}

/*
 * Function name : vhci_scsi_reset()
 *
 * Return Values : 0 - reset failed
 *		   1 - reset succeeded
 */

/* ARGSUSED */
static int
vhci_scsi_reset(struct scsi_address *ap, int level)
{
	int rval = 0;

	cmn_err(CE_WARN, "!vhci_scsi_reset 0x%x", level);
	if ((level == RESET_TARGET) || (level == RESET_LUN)) {
		return (vhci_scsi_reset_target(ap, level, TRUE));
	} else if (level == RESET_ALL) {
		return (vhci_scsi_reset_bus(ap));
	}

	return (rval);
}

/*
 * vhci_recovery_reset:
 *	Issues reset to the device
 * Input:
 *	vlun - vhci lun pointer of the device
 *	ap - address of the device
 *	select_path:
 *		If select_path is FALSE, then the address specified in ap is
 *		the path on which reset will be issued.
 *		If select_path is TRUE, then path is obtained by calling
 *		mdi_select_path.
 *
 *	recovery_depth:
 *		Caller can specify the level of reset.
 *		VHCI_DEPTH_LUN -
 *			Issues LUN RESET if device supports lun reset.
 *		VHCI_DEPTH_TARGET -
 *			If Lun Reset fails or the device does not support
 *			Lun Reset, issues TARGET RESET
 *		VHCI_DEPTH_ALL -
 *			If Lun Reset fails or the device does not support
 *			Lun Reset, issues TARGET RESET.
 *			If TARGET RESET does not succeed, issues Bus Reset.
 */

static int
vhci_recovery_reset(scsi_vhci_lun_t *vlun, struct scsi_address *ap,
	uint8_t select_path, uint8_t recovery_depth)
{
	int	ret = 0;

	ASSERT(ap != NULL);

	if (vlun && vlun->svl_support_lun_reset == 1) {
		ret = vhci_scsi_reset_target(ap, RESET_LUN,
		    select_path);
	}

	recovery_depth--;

	if ((ret == 0) && recovery_depth) {
		ret = vhci_scsi_reset_target(ap, RESET_TARGET,
		    select_path);
		recovery_depth--;
	}

	if ((ret == 0) && recovery_depth) {
		(void) scsi_reset(ap, RESET_ALL);
	}

	return (ret);
}

/*
 * Note: The scsi_address passed to this routine could be the scsi_address
 * for the virtual device or the physical device. No assumptions should be
 * made in this routine about the contents of the ap structure.
 * Further, note that the child dip would be the dip of the ssd node regardless
 * of the scsi_address passed in.
 */
static int
vhci_scsi_reset_target(struct scsi_address *ap, int level, uint8_t select_path)
{
	dev_info_t		*vdip, *cdip;
	mdi_pathinfo_t		*pip = NULL;
	mdi_pathinfo_t		*npip = NULL;
	int			rval = -1;
	scsi_vhci_priv_t	*svp = NULL;
	struct scsi_address	*pap = NULL;
	scsi_hba_tran_t		*hba = NULL;
	int			sps;
	struct scsi_vhci	*vhci = NULL;

	if (select_path != TRUE) {
		ASSERT(ap != NULL);
		if (level == RESET_LUN) {
			hba = ap->a_hba_tran;
			ASSERT(hba != NULL);
			return (hba->tran_reset(ap, RESET_LUN));
		}
		return (scsi_reset(ap, level));
	}

	cdip = ADDR2DIP(ap);
	ASSERT(cdip != NULL);
	vdip = ddi_get_parent(cdip);
	ASSERT(vdip != NULL);
	vhci = ddi_get_soft_state(vhci_softstate, ddi_get_instance(vdip));
	ASSERT(vhci != NULL);

	rval = mdi_select_path(cdip, NULL, MDI_SELECT_ONLINE_PATH, NULL, &pip);
	if ((rval != MDI_SUCCESS) || (pip == NULL)) {
		VHCI_DEBUG(2, (CE_WARN, NULL, "!vhci_scsi_reset_target: "
		    "Unable to get a path, dip 0x%p", (void *)cdip));
		return (0);
	}
again:
	svp = (scsi_vhci_priv_t *)mdi_pi_get_vhci_private(pip);
	if (svp == NULL) {
		VHCI_DEBUG(2, (CE_WARN, NULL, "!vhci_scsi_reset_target: "
		    "priv is NULL, pip 0x%p", (void *)pip));
		mdi_rele_path(pip);
		return (0);
	}

	if (svp->svp_psd == NULL) {
		VHCI_DEBUG(2, (CE_WARN, NULL, "!vhci_scsi_reset_target: "
		    "psd is NULL, pip 0x%p, svp 0x%p",
		    (void *)pip, (void *)svp));
		mdi_rele_path(pip);
		return (0);
	}

	pap = &svp->svp_psd->sd_address;
	hba = pap->a_hba_tran;

	ASSERT(pap != NULL);
	ASSERT(hba != NULL);

	if (hba->tran_reset != NULL) {
		if (hba->tran_reset(pap, level) == 0) {
			vhci_log(CE_WARN, vdip, "!%s%d: "
			    "path %s, reset %d failed",
			    ddi_driver_name(cdip), ddi_get_instance(cdip),
			    mdi_pi_spathname(pip), level);

			/*
			 * Select next path and issue the reset, repeat
			 * until all paths are exhausted
			 */
			sps = mdi_select_path(cdip, NULL,
			    MDI_SELECT_ONLINE_PATH, pip, &npip);
			if ((sps != MDI_SUCCESS) || (npip == NULL)) {
				mdi_rele_path(pip);
				return (0);
			}
			mdi_rele_path(pip);
			pip = npip;
			goto again;
		}
		mdi_rele_path(pip);
		mutex_enter(&vhci->vhci_mutex);
		scsi_hba_reset_notify_callback(&vhci->vhci_mutex,
		    &vhci->vhci_reset_notify_listf);
		mutex_exit(&vhci->vhci_mutex);
		VHCI_DEBUG(6, (CE_NOTE, NULL, "!vhci_scsi_reset_target: "
		    "reset %d sent down pip:%p for cdip:%p\n", level,
		    (void *)pip, (void *)cdip));
		return (1);
	}
	mdi_rele_path(pip);
	return (0);
}


/* ARGSUSED */
static int
vhci_scsi_reset_bus(struct scsi_address *ap)
{
	return (1);
}


/*
 * called by vhci_getcap and vhci_setcap to get and set (respectively)
 * SCSI capabilities
 */
/* ARGSUSED */
static int
vhci_commoncap(struct scsi_address *ap, char *cap,
    int val, int tgtonly, int doset)
{
	struct scsi_vhci		*vhci = ADDR2VHCI(ap);
	struct scsi_vhci_lun		*vlun = ADDR2VLUN(ap);
	int			cidx;
	int			rval = 0;

	if (cap == (char *)0) {
		VHCI_DEBUG(3, (CE_WARN, vhci->vhci_dip,
		    "!vhci_commoncap: invalid arg"));
		return (rval);
	}

	if (vlun == NULL) {
		VHCI_DEBUG(3, (CE_WARN, vhci->vhci_dip,
		    "!vhci_commoncap: vlun is null"));
		return (rval);
	}

	if ((cidx = scsi_hba_lookup_capstr(cap)) == -1) {
		return (UNDEFINED);
	}

	/*
	 * Process setcap request.
	 */
	if (doset) {
		/*
		 * At present, we can only set binary (0/1) values
		 */
		switch (cidx) {
		case SCSI_CAP_ARQ:
			if (val == 0) {
				rval = 0;
			} else {
				rval = 1;
			}
			break;

		case SCSI_CAP_LUN_RESET:
			if (tgtonly == 0) {
				VHCI_DEBUG(1, (CE_WARN, vhci->vhci_dip,
				    "scsi_vhci_setcap: "
				    "Returning error since whom = 0"));
				rval = -1;
				break;
			}
			/*
			 * Set the capability accordingly.
			 */
			mutex_enter(&vlun->svl_mutex);
			vlun->svl_support_lun_reset = val;
			rval = val;
			mutex_exit(&vlun->svl_mutex);
			break;

		case SCSI_CAP_SECTOR_SIZE:
			mutex_enter(&vlun->svl_mutex);
			vlun->svl_sector_size = val;
			vlun->svl_setcap_done = 1;
			mutex_exit(&vlun->svl_mutex);
			(void) vhci_pHCI_cap(ap, cap, val, tgtonly, NULL);

			/* Always return success */
			rval = 1;
			break;

		default:
			VHCI_DEBUG(6, (CE_WARN, vhci->vhci_dip,
			    "!vhci_setcap: unsupported %d", cidx));
			rval = UNDEFINED;
			break;
		}

		VHCI_DEBUG(6, (CE_NOTE, vhci->vhci_dip,
		    "!set cap: cap=%s, val/tgtonly/doset/rval = "
		    "0x%x/0x%x/0x%x/%d\n",
		    cap, val, tgtonly, doset, rval));

	} else {
		/*
		 * Process getcap request.
		 */
		switch (cidx) {
		case SCSI_CAP_DMA_MAX:
			/*
			 * For X86 this capability is caught in scsi_ifgetcap().
			 * XXX Should this be getting the value from the pHCI?
			 */
			rval = (int)VHCI_DMA_MAX_XFER_CAP;
			break;

		case SCSI_CAP_INITIATOR_ID:
			rval = 0x00;
			break;

		case SCSI_CAP_ARQ:
		case SCSI_CAP_RESET_NOTIFICATION:
		case SCSI_CAP_TAGGED_QING:
			rval = 1;
			break;

		case SCSI_CAP_SCSI_VERSION:
			rval = 3;
			break;

		case SCSI_CAP_INTERCONNECT_TYPE:
			rval = INTERCONNECT_FABRIC;
			break;

		case SCSI_CAP_LUN_RESET:
			/*
			 * scsi_vhci will always return success for LUN reset.
			 * When request for doing LUN reset comes
			 * through scsi_reset entry point, at that time attempt
			 * will be made to do reset through all the possible
			 * paths.
			 */
			mutex_enter(&vlun->svl_mutex);
			rval = vlun->svl_support_lun_reset;
			mutex_exit(&vlun->svl_mutex);
			VHCI_DEBUG(4, (CE_WARN, vhci->vhci_dip,
			    "scsi_vhci_getcap:"
			    "Getting the Lun reset capability %d", rval));
			break;

		case SCSI_CAP_SECTOR_SIZE:
			mutex_enter(&vlun->svl_mutex);
			rval = vlun->svl_sector_size;
			mutex_exit(&vlun->svl_mutex);
			break;

		case SCSI_CAP_CDB_LEN:
			rval = VHCI_SCSI_CDB_SIZE;
			break;

		case SCSI_CAP_DMA_MAX_ARCH:
			/*
			 * For X86 this capability is caught in scsi_ifgetcap().
			 * XXX Should this be getting the value from the pHCI?
			 */
			rval = 0;
			break;

		default:
			VHCI_DEBUG(6, (CE_WARN, vhci->vhci_dip,
			    "!vhci_getcap: unsupported %d", cidx));
			rval = UNDEFINED;
			break;
		}

		VHCI_DEBUG(6, (CE_NOTE, vhci->vhci_dip,
		    "!get cap: cap=%s, val/tgtonly/doset/rval = "
		    "0x%x/0x%x/0x%x/%d\n",
		    cap, val, tgtonly, doset, rval));
	}
	return (rval);
}


/*
 * Function name : vhci_scsi_getcap()
 *
 */
static int
vhci_scsi_getcap(struct scsi_address *ap, char *cap, int whom)
{
	return (vhci_commoncap(ap, cap, 0, whom, 0));
}

static int
vhci_scsi_setcap(struct scsi_address *ap, char *cap, int value, int whom)
{
	return (vhci_commoncap(ap, cap, value, whom, 1));
}

/*
 * Function name : vhci_scsi_abort()
 */
/* ARGSUSED */
static int
vhci_scsi_abort(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	return (0);
}

/*
 * Function name : vhci_scsi_init_pkt
 *
 * Return Values : pointer to scsi_pkt, or NULL
 */
/* ARGSUSED */
static struct scsi_pkt *
vhci_scsi_init_pkt(struct scsi_address *ap, struct scsi_pkt *pkt,
	struct buf *bp, int cmdlen, int statuslen, int tgtlen,
	int flags, int (*callback)(caddr_t), caddr_t arg)
{
	struct scsi_vhci	*vhci = ADDR2VHCI(ap);
	struct vhci_pkt		*vpkt;
	int			rval;
	int			newpkt = 0;
	struct scsi_pkt		*pktp;


	if (pkt == NULL) {
		if (cmdlen > VHCI_SCSI_CDB_SIZE) {
			if ((cmdlen != VHCI_SCSI_OSD_CDB_SIZE) ||
			    ((flags & VHCI_SCSI_OSD_PKT_FLAGS) !=
			    VHCI_SCSI_OSD_PKT_FLAGS)) {
				VHCI_DEBUG(1, (CE_NOTE, NULL,
				    "!init pkt: cdb size not supported\n"));
				return (NULL);
			}
		}

		pktp = scsi_hba_pkt_alloc(vhci->vhci_dip,
		    ap, cmdlen, statuslen, tgtlen, sizeof (*vpkt), callback,
		    arg);

		if (pktp == NULL) {
			return (NULL);
		}

		/* Get the vhci's private structure */
		vpkt = (struct vhci_pkt *)(pktp->pkt_ha_private);
		ASSERT(vpkt);

		/* Save the target driver's packet */
		vpkt->vpkt_tgt_pkt = pktp;

		/*
		 * Save pkt_tgt_init_pkt fields if deferred binding
		 * is needed or for other purposes.
		 */
		vpkt->vpkt_tgt_init_pkt_flags = flags;
		vpkt->vpkt_flags = (callback == NULL_FUNC) ? CFLAG_NOWAIT : 0;
		vpkt->vpkt_state = VHCI_PKT_IDLE;
		vpkt->vpkt_tgt_init_cdblen = cmdlen;
		vpkt->vpkt_tgt_init_scblen = statuslen;
		newpkt = 1;
	} else { /* pkt not NULL */
		vpkt = pkt->pkt_ha_private;
	}

	VHCI_DEBUG(8, (CE_NOTE, NULL, "vhci_scsi_init_pkt "
	    "vpkt %p flags %x\n", (void *)vpkt, flags));

	/* Clear any stale error flags */
	if (bp) {
		bioerror(bp, 0);
	}

	vpkt->vpkt_tgt_init_bp = bp;

	if (flags & PKT_DMA_PARTIAL) {

		/*
		 * Immediate binding is needed.
		 * Target driver may not set this flag in next invocation.
		 * vhci has to remember this flag was set during first
		 * invocation of vhci_scsi_init_pkt.
		 */
		vpkt->vpkt_flags |= CFLAG_DMA_PARTIAL;
	}

	if (vpkt->vpkt_flags & CFLAG_DMA_PARTIAL) {

		/*
		 * Re-initialize some of the target driver packet state
		 * information.
		 */
		vpkt->vpkt_tgt_pkt->pkt_state = 0;
		vpkt->vpkt_tgt_pkt->pkt_statistics = 0;
		vpkt->vpkt_tgt_pkt->pkt_reason = 0;

		/*
		 * Binding a vpkt->vpkt_path for this IO at init_time.
		 * If an IO error happens later, target driver will clear
		 * this vpkt->vpkt_path binding before re-init IO again.
		 */
		VHCI_DEBUG(8, (CE_NOTE, NULL,
		    "vhci_scsi_init_pkt: calling v_b_t %p, newpkt %d\n",
		    (void *)vpkt, newpkt));
		if (pkt && vpkt->vpkt_hba_pkt) {
			VHCI_DEBUG(4, (CE_NOTE, NULL,
			    "v_s_i_p calling update_pHCI_pkt resid %ld\n",
			    pkt->pkt_resid));
			vhci_update_pHCI_pkt(vpkt, pkt);
		}
		if (callback == SLEEP_FUNC) {
			rval = vhci_bind_transport(
			    ap, vpkt, flags, callback);
		} else {
			rval = vhci_bind_transport(
			    ap, vpkt, flags, NULL_FUNC);
		}
		VHCI_DEBUG(8, (CE_NOTE, NULL,
		    "vhci_scsi_init_pkt: v_b_t called 0x%p rval 0x%x\n",
		    (void *)vpkt, rval));
		if (bp) {
			if (rval == TRAN_FATAL_ERROR) {
				/*
				 * No paths available. Could not bind
				 * any pHCI. Setting EFAULT as a way
				 * to indicate no DMA is mapped.
				 */
				bioerror(bp, EFAULT);
			} else {
				/*
				 * Do not indicate any pHCI errors to
				 * target driver otherwise.
				 */
				bioerror(bp, 0);
			}
		}
		if (rval != TRAN_ACCEPT) {
			VHCI_DEBUG(8, (CE_NOTE, NULL,
			    "vhci_scsi_init_pkt: "
			    "v_b_t failed 0x%p newpkt %x\n",
			    (void *)vpkt, newpkt));
			if (newpkt) {
				scsi_hba_pkt_free(ap,
				    vpkt->vpkt_tgt_pkt);
			}
			return (NULL);
		}
		ASSERT(vpkt->vpkt_hba_pkt != NULL);
		ASSERT(vpkt->vpkt_path != NULL);

		/* Update the resid for the target driver */
		vpkt->vpkt_tgt_pkt->pkt_resid =
		    vpkt->vpkt_hba_pkt->pkt_resid;
	}

	return (vpkt->vpkt_tgt_pkt);
}

/*
 * Function name : vhci_scsi_destroy_pkt
 *
 * Return Values : none
 */
static void
vhci_scsi_destroy_pkt(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	struct vhci_pkt		*vpkt = (struct vhci_pkt *)pkt->pkt_ha_private;

	VHCI_DEBUG(8, (CE_NOTE, NULL,
	    "vhci_scsi_destroy_pkt: vpkt 0x%p\n", (void *)vpkt));

	vpkt->vpkt_tgt_init_pkt_flags = 0;
	if (vpkt->vpkt_hba_pkt) {
		scsi_destroy_pkt(vpkt->vpkt_hba_pkt);
		vpkt->vpkt_hba_pkt = NULL;
	}
	if (vpkt->vpkt_path) {
		mdi_rele_path(vpkt->vpkt_path);
		vpkt->vpkt_path = NULL;
	}

	ASSERT(vpkt->vpkt_state != VHCI_PKT_ISSUED);
	scsi_hba_pkt_free(ap, vpkt->vpkt_tgt_pkt);
}

/*
 * Function name : vhci_scsi_dmafree()
 *
 * Return Values : none
 */
/*ARGSUSED*/
static void
vhci_scsi_dmafree(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	struct vhci_pkt	*vpkt = (struct vhci_pkt *)pkt->pkt_ha_private;

	VHCI_DEBUG(6, (CE_NOTE, NULL,
	    "vhci_scsi_dmafree: vpkt 0x%p\n", (void *)vpkt));

	ASSERT(vpkt != NULL);
	if (vpkt->vpkt_hba_pkt) {
		scsi_destroy_pkt(vpkt->vpkt_hba_pkt);
		vpkt->vpkt_hba_pkt = NULL;
	}
	if (vpkt->vpkt_path) {
		mdi_rele_path(vpkt->vpkt_path);
		vpkt->vpkt_path = NULL;
	}
}

/*
 * Function name : vhci_scsi_sync_pkt()
 *
 * Return Values : none
 */
/*ARGSUSED*/
static void
vhci_scsi_sync_pkt(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	struct vhci_pkt	*vpkt = (struct vhci_pkt *)pkt->pkt_ha_private;

	ASSERT(vpkt != NULL);
	if (vpkt->vpkt_hba_pkt) {
		scsi_sync_pkt(vpkt->vpkt_hba_pkt);
	}
}

/*
 * routine for reset notification setup, to register or cancel.
 */
static int
vhci_scsi_reset_notify(struct scsi_address *ap, int flag,
    void (*callback)(caddr_t), caddr_t arg)
{
	struct scsi_vhci *vhci = ADDR2VHCI(ap);
	return (scsi_hba_reset_notify_setup(ap, flag, callback, arg,
	    &vhci->vhci_mutex, &vhci->vhci_reset_notify_listf));
}

static int
vhci_scsi_get_name_bus_addr(struct scsi_device *sd,
    char *name, int len, int bus_addr)
{
	dev_info_t		*cdip;
	char			*guid;
	scsi_vhci_lun_t		*vlun;

	ASSERT(sd != NULL);
	ASSERT(name != NULL);

	*name = 0;
	cdip = sd->sd_dev;

	ASSERT(cdip != NULL);

	if (mdi_component_is_client(cdip, NULL) != MDI_SUCCESS)
		return (1);

	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, cdip, PROPFLAGS,
	    MDI_CLIENT_GUID_PROP, &guid) != DDI_SUCCESS)
		return (1);

	/*
	 * Message is "sd# at scsi_vhci0: unit-address <guid>: <bus_addr>".
	 *	<guid>		bus_addr argument == 0
	 *	<bus_addr>	bus_addr argument != 0
	 * Since the <guid> is already provided with unit-address, we just
	 * provide failover module in <bus_addr> to keep output shorter.
	 */
	vlun = ADDR2VLUN(&sd->sd_address);
	if (bus_addr == 0) {
		/* report the guid:  */
		(void) snprintf(name, len, "g%s", guid);
	} else if (vlun && vlun->svl_fops_name) {
		/* report the name of the failover module */
		(void) snprintf(name, len, "%s", vlun->svl_fops_name);
	}

	ddi_prop_free(guid);
	return (1);
}

static int
vhci_scsi_get_bus_addr(struct scsi_device *sd, char *name, int len)
{
	return (vhci_scsi_get_name_bus_addr(sd, name, len, 1));
}

static int
vhci_scsi_get_name(struct scsi_device *sd, char *name, int len)
{
	return (vhci_scsi_get_name_bus_addr(sd, name, len, 0));
}

/*
 * Return a pointer to the guid part of the devnm.
 * devnm format is "nodename@busaddr", busaddr format is "gGUID".
 */
static char *
vhci_devnm_to_guid(char *devnm)
{
	char *cp = devnm;

	if (devnm == NULL)
		return (NULL);

	while (*cp != '\0' && *cp != '@')
		cp++;
	if (*cp == '@' && *(cp + 1) == 'g')
		return (cp + 2);
	return (NULL);
}

static int
vhci_bind_transport(struct scsi_address *ap, struct vhci_pkt *vpkt, int flags,
    int (*func)(caddr_t))
{
	struct scsi_vhci	*vhci = ADDR2VHCI(ap);
	dev_info_t		*cdip = ADDR2DIP(ap);
	mdi_pathinfo_t		*pip = NULL;
	mdi_pathinfo_t		*npip = NULL;
	scsi_vhci_priv_t	*svp = NULL;
	struct scsi_device	*psd = NULL;
	struct scsi_address	*address = NULL;
	struct scsi_pkt		*pkt = NULL;
	int			rval = -1;
	int			pgr_sema_held = 0;
	int			held;
	int			mps_flag = MDI_SELECT_ONLINE_PATH;
	struct scsi_vhci_lun	*vlun;
	int			path_instance = 0;

	vlun = ADDR2VLUN(ap);
	ASSERT(vlun != 0);

	if ((vpkt->vpkt_tgt_pkt->pkt_cdbp[0] == SCMD_PROUT) &&
	    (((vpkt->vpkt_tgt_pkt->pkt_cdbp[1] & 0x1f) ==
	    VHCI_PROUT_REGISTER) ||
	    ((vpkt->vpkt_tgt_pkt->pkt_cdbp[1] & 0x1f) ==
	    VHCI_PROUT_R_AND_IGNORE))) {
		if (!sema_tryp(&vlun->svl_pgr_sema))
			return (TRAN_BUSY);
		pgr_sema_held = 1;
		if (vlun->svl_first_path != NULL) {
			rval = mdi_select_path(cdip, NULL,
			    MDI_SELECT_ONLINE_PATH | MDI_SELECT_STANDBY_PATH,
			    NULL, &pip);
			if ((rval != MDI_SUCCESS) || (pip == NULL)) {
				VHCI_DEBUG(4, (CE_NOTE, NULL,
				    "vhci_bind_transport: path select fail\n"));
			} else {
				npip = pip;
				do {
					if (npip == vlun->svl_first_path) {
						VHCI_DEBUG(4, (CE_NOTE, NULL,
						    "vhci_bind_transport: "
						    "valid first path 0x%p\n",
						    (void *)
						    vlun->svl_first_path));
						pip = vlun->svl_first_path;
						goto bind_path;
					}
					pip = npip;
					rval = mdi_select_path(cdip, NULL,
					    MDI_SELECT_ONLINE_PATH |
					    MDI_SELECT_STANDBY_PATH,
					    pip, &npip);
					mdi_rele_path(pip);
				} while ((rval == MDI_SUCCESS) &&
				    (npip != NULL));
			}
		}

		if (vlun->svl_first_path) {
			VHCI_DEBUG(4, (CE_NOTE, NULL,
			    "vhci_bind_transport: invalid first path 0x%p\n",
			    (void *)vlun->svl_first_path));
			vlun->svl_first_path = NULL;
		}
	} else if (vpkt->vpkt_tgt_pkt->pkt_cdbp[0] == SCMD_PRIN) {
		if ((vpkt->vpkt_state & VHCI_PKT_THRU_TASKQ) == 0) {
			if (!sema_tryp(&vlun->svl_pgr_sema))
				return (TRAN_BUSY);
		}
		pgr_sema_held = 1;
	}

	/*
	 * If the path is already bound for PKT_PARTIAL_DMA case,
	 * try to use the same path.
	 */
	if ((vpkt->vpkt_flags & CFLAG_DMA_PARTIAL) && vpkt->vpkt_path) {
		VHCI_DEBUG(4, (CE_NOTE, NULL,
		    "vhci_bind_transport: PKT_PARTIAL_DMA "
		    "vpkt 0x%p, path 0x%p\n",
		    (void *)vpkt, (void *)vpkt->vpkt_path));
		pip = vpkt->vpkt_path;
		goto bind_path;
	}

	/*
	 * Get path_instance. Non-zero with FLAG_PKT_PATH_INSTANCE set
	 * indicates that mdi_select_path should be called to select a
	 * specific instance.
	 *
	 * NB: Condition pkt_path_instance reference on proper allocation.
	 */
	if ((vpkt->vpkt_tgt_pkt->pkt_flags & FLAG_PKT_PATH_INSTANCE) &&
	    scsi_pkt_allocated_correctly(vpkt->vpkt_tgt_pkt)) {
		path_instance = vpkt->vpkt_tgt_pkt->pkt_path_instance;
	}

	/*
	 * If reservation is active bind the transport directly to the pip
	 * with the reservation.
	 */
	if (vpkt->vpkt_hba_pkt == NULL) {
		if (vlun->svl_flags & VLUN_RESERVE_ACTIVE_FLG) {
			if (MDI_PI_IS_ONLINE(vlun->svl_resrv_pip)) {
				pip = vlun->svl_resrv_pip;
				mdi_hold_path(pip);
				vlun->svl_waiting_for_activepath = 0;
				rval = MDI_SUCCESS;
				goto bind_path;
			} else {
				if (pgr_sema_held) {
					sema_v(&vlun->svl_pgr_sema);
				}
				return (TRAN_BUSY);
			}
		}
try_again:
		rval = mdi_select_path(cdip, vpkt->vpkt_tgt_init_bp,
		    path_instance ? MDI_SELECT_PATH_INSTANCE : 0,
		    (void *)(intptr_t)path_instance, &pip);
		if (rval == MDI_BUSY) {
			if (pgr_sema_held) {
				sema_v(&vlun->svl_pgr_sema);
			}
			return (TRAN_BUSY);
		} else if (rval == MDI_DEVI_ONLINING) {
			/*
			 * if we are here then we are in the midst of
			 * an attach/probe of the client device.
			 * We attempt to bind to ONLINE path if available,
			 * else it is OK to bind to a STANDBY path (instead
			 * of triggering a failover) because IO associated
			 * with attach/probe (eg. INQUIRY, block 0 read)
			 * are completed by targets even on passive paths
			 * If no ONLINE paths available, it is important
			 * to set svl_waiting_for_activepath for two
			 * reasons: (1) avoid sense analysis in the
			 * "external failure detection" codepath in
			 * vhci_intr().  Failure to do so will result in
			 * infinite loop (unless an ONLINE path becomes
			 * available at some point) (2) avoid
			 * unnecessary failover (see "---Waiting For Active
			 * Path---" comment below).
			 */
			VHCI_DEBUG(1, (CE_NOTE, NULL, "!%p in onlining "
			    "state\n", (void *)cdip));
			pip = NULL;
			rval = mdi_select_path(cdip, vpkt->vpkt_tgt_init_bp,
			    mps_flag, NULL, &pip);
			if ((rval != MDI_SUCCESS) || (pip == NULL)) {
				if (vlun->svl_waiting_for_activepath == 0) {
					vlun->svl_waiting_for_activepath = 1;
					vlun->svl_wfa_time = gethrtime();
				}
				mps_flag |= MDI_SELECT_STANDBY_PATH;
				rval = mdi_select_path(cdip,
				    vpkt->vpkt_tgt_init_bp,
				    mps_flag, NULL, &pip);
				if ((rval != MDI_SUCCESS) || (pip == NULL)) {
					if (pgr_sema_held) {
						sema_v(&vlun->svl_pgr_sema);
					}
					return (TRAN_FATAL_ERROR);
				}
				goto bind_path;
			}
		} else if ((rval == MDI_FAILURE) ||
		    ((rval == MDI_NOPATH) && (path_instance))) {
			if (pgr_sema_held) {
				sema_v(&vlun->svl_pgr_sema);
			}
			return (TRAN_FATAL_ERROR);
		}

		if ((pip == NULL) || (rval == MDI_NOPATH)) {
			while (vlun->svl_waiting_for_activepath) {
				/*
				 * ---Waiting For Active Path---
				 * This device was discovered across a
				 * passive path; lets wait for a little
				 * bit, hopefully an active path will
				 * show up obviating the need for a
				 * failover
				 */
				if ((gethrtime() - vlun->svl_wfa_time) >=
				    (60 * NANOSEC)) {
					vlun->svl_waiting_for_activepath = 0;
				} else {
					drv_usecwait(1000);
					if (vlun->svl_waiting_for_activepath
					    == 0) {
						/*
						 * an active path has come
						 * online!
						 */
						goto try_again;
					}
				}
			}
			VHCI_HOLD_LUN(vlun, VH_NOSLEEP, held);
			if (!held) {
				VHCI_DEBUG(4, (CE_NOTE, NULL,
				    "!Lun not held\n"));
				if (pgr_sema_held) {
					sema_v(&vlun->svl_pgr_sema);
				}
				return (TRAN_BUSY);
			}
			/*
			 * now that the LUN is stable, one last check
			 * to make sure no other changes sneaked in
			 * (like a path coming online or a
			 * failover initiated by another thread)
			 */
			pip = NULL;
			rval = mdi_select_path(cdip, vpkt->vpkt_tgt_init_bp,
			    0, NULL, &pip);
			if (pip != NULL) {
				VHCI_RELEASE_LUN(vlun);
				vlun->svl_waiting_for_activepath = 0;
				goto bind_path;
			}

			/*
			 * Check if there is an ONLINE path OR a STANDBY path
			 * available. If none is available, do not attempt
			 * to do a failover, just return a fatal error at this
			 * point.
			 */
			npip = NULL;
			rval = mdi_select_path(cdip, NULL,
			    (MDI_SELECT_ONLINE_PATH | MDI_SELECT_STANDBY_PATH),
			    NULL, &npip);
			if ((npip == NULL) || (rval != MDI_SUCCESS)) {
				/*
				 * No paths available, jus return FATAL error.
				 */
				VHCI_RELEASE_LUN(vlun);
				if (pgr_sema_held) {
					sema_v(&vlun->svl_pgr_sema);
				}
				return (TRAN_FATAL_ERROR);
			}
			mdi_rele_path(npip);
			if (!(vpkt->vpkt_state & VHCI_PKT_IN_FAILOVER)) {
				VHCI_DEBUG(1, (CE_NOTE, NULL, "!invoking "
				    "mdi_failover\n"));
				rval = mdi_failover(vhci->vhci_dip, cdip,
				    MDI_FAILOVER_ASYNC);
			} else {
				rval = vlun->svl_failover_status;
			}
			if (rval == MDI_FAILURE) {
				VHCI_RELEASE_LUN(vlun);
				if (pgr_sema_held) {
					sema_v(&vlun->svl_pgr_sema);
				}
				return (TRAN_FATAL_ERROR);
			} else if (rval == MDI_BUSY) {
				VHCI_RELEASE_LUN(vlun);
				if (pgr_sema_held) {
					sema_v(&vlun->svl_pgr_sema);
				}
				return (TRAN_BUSY);
			} else {
				if (pgr_sema_held) {
					sema_v(&vlun->svl_pgr_sema);
				}
				vpkt->vpkt_state |= VHCI_PKT_IN_FAILOVER;
				return (TRAN_BUSY);
			}
		}
		vlun->svl_waiting_for_activepath = 0;
bind_path:
		vpkt->vpkt_path = pip;
		svp = (scsi_vhci_priv_t *)mdi_pi_get_vhci_private(pip);
		ASSERT(svp != NULL);

		psd = svp->svp_psd;
		ASSERT(psd != NULL);
		address = &psd->sd_address;
	} else {
		pkt = vpkt->vpkt_hba_pkt;
		address = &pkt->pkt_address;
	}

	/* Verify match of specified path_instance and selected path_instance */
	ASSERT((path_instance == 0) ||
	    (path_instance == mdi_pi_get_path_instance(vpkt->vpkt_path)));

	/*
	 * For PKT_PARTIAL_DMA case, call pHCI's scsi_init_pkt whenever
	 * target driver calls vhci_scsi_init_pkt.
	 */
	if ((vpkt->vpkt_flags & CFLAG_DMA_PARTIAL) &&
	    vpkt->vpkt_path && vpkt->vpkt_hba_pkt) {
		VHCI_DEBUG(4, (CE_NOTE, NULL,
		    "vhci_bind_transport: PKT_PARTIAL_DMA "
		    "vpkt 0x%p, path 0x%p hba_pkt 0x%p\n",
		    (void *)vpkt, (void *)vpkt->vpkt_path, (void *)pkt));
		pkt = vpkt->vpkt_hba_pkt;
		address = &pkt->pkt_address;
	}

	if (pkt == NULL || (vpkt->vpkt_flags & CFLAG_DMA_PARTIAL)) {
		pkt = scsi_init_pkt(address, pkt,
		    vpkt->vpkt_tgt_init_bp, vpkt->vpkt_tgt_init_cdblen,
		    vpkt->vpkt_tgt_init_scblen, 0, flags, func, NULL);

		if (pkt == NULL) {
			VHCI_DEBUG(4, (CE_NOTE, NULL,
			    "!bind transport: 0x%p 0x%p 0x%p\n",
			    (void *)vhci, (void *)psd, (void *)vpkt));
			if ((vpkt->vpkt_hba_pkt == NULL) && vpkt->vpkt_path) {
				MDI_PI_ERRSTAT(vpkt->vpkt_path,
				    MDI_PI_TRANSERR);
				mdi_rele_path(vpkt->vpkt_path);
				vpkt->vpkt_path = NULL;
			}
			if (pgr_sema_held) {
				sema_v(&vlun->svl_pgr_sema);
			}
			/*
			 * Consider it a fatal error if b_error is
			 * set as a result of DMA binding failure
			 * vs. a condition of being temporarily out of
			 * some resource
			 */
			if (vpkt->vpkt_tgt_init_bp == NULL ||
			    geterror(vpkt->vpkt_tgt_init_bp))
				return (TRAN_FATAL_ERROR);
			else
				return (TRAN_BUSY);
		}
	}

	pkt->pkt_private = vpkt;
	vpkt->vpkt_hba_pkt = pkt;
	return (TRAN_ACCEPT);
}


/*PRINTFLIKE3*/
void
vhci_log(int level, dev_info_t *dip, const char *fmt, ...)
{
	char		buf[256];
	va_list		ap;

	va_start(ap, fmt);
	(void) vsprintf(buf, fmt, ap);
	va_end(ap);

	scsi_log(dip, "scsi_vhci", level, buf);
}

/* do a PGR out with the information we've saved away */
static int
vhci_do_prout(scsi_vhci_priv_t *svp)
{

	struct scsi_pkt			*new_pkt;
	struct buf			*bp;
	scsi_vhci_lun_t			*vlun = svp->svp_svl;
	int				rval, retry, nr_retry, ua_retry;
	uint8_t				*sns, skey;

	bp = getrbuf(KM_SLEEP);
	bp->b_flags = B_WRITE;
	bp->b_resid = 0;
	bp->b_un.b_addr = (caddr_t)&vlun->svl_prout;
	bp->b_bcount = vlun->svl_bcount;

	VHCI_INCR_PATH_CMDCOUNT(svp);

	new_pkt = scsi_init_pkt(&svp->svp_psd->sd_address, NULL, bp,
	    CDB_GROUP1, sizeof (struct scsi_arq_status), 0, 0,
	    SLEEP_FUNC, NULL);
	if (new_pkt == NULL) {
		VHCI_DECR_PATH_CMDCOUNT(svp);
		freerbuf(bp);
		cmn_err(CE_WARN, "!vhci_do_prout: scsi_init_pkt failed");
		return (0);
	}
	mutex_enter(&vlun->svl_mutex);
	bp->b_un.b_addr = (caddr_t)&vlun->svl_prout;
	bp->b_bcount = vlun->svl_bcount;
	bcopy(vlun->svl_cdb, new_pkt->pkt_cdbp,
	    sizeof (vlun->svl_cdb));
	new_pkt->pkt_time = vlun->svl_time;
	mutex_exit(&vlun->svl_mutex);
	new_pkt->pkt_flags = FLAG_NOINTR;

	ua_retry = nr_retry = retry = 0;
again:
	rval = vhci_do_scsi_cmd(new_pkt);
	if (rval != 1) {
		if ((new_pkt->pkt_reason == CMD_CMPLT) &&
		    (SCBP_C(new_pkt) == STATUS_CHECK) &&
		    (new_pkt->pkt_state & STATE_ARQ_DONE)) {
			sns = (uint8_t *)
			    &(((struct scsi_arq_status *)(uintptr_t)
			    (new_pkt->pkt_scbp))->sts_sensedata);
			skey = scsi_sense_key(sns);
			if ((skey == KEY_UNIT_ATTENTION) ||
			    (skey == KEY_NOT_READY)) {
				int max_retry;
				struct scsi_failover_ops *fops;
				fops = vlun->svl_fops;
				rval = fops->sfo_analyze_sense(svp->svp_psd,
				    sns, vlun->svl_fops_ctpriv);
				if (rval == SCSI_SENSE_NOT_READY) {
					max_retry = vhci_prout_not_ready_retry;
					retry = nr_retry++;
					delay(1*drv_usectohz(1000000));
				} else {
					/* chk for state change and update */
					if (rval == SCSI_SENSE_STATE_CHANGED) {
						int held;
						VHCI_HOLD_LUN(vlun,
						    VH_NOSLEEP, held);
						if (!held) {
							rval = TRAN_BUSY;
						} else {
							/* chk for alua first */
							vhci_update_pathstates(
							    (void *)vlun);
						}
					}
					retry = ua_retry++;
					max_retry = VHCI_MAX_PGR_RETRIES;
				}
				if (retry < max_retry) {
					VHCI_DEBUG(4, (CE_WARN, NULL,
					    "!vhci_do_prout retry 0x%x "
					    "(0x%x 0x%x 0x%x)",
					    SCBP_C(new_pkt),
					    new_pkt->pkt_cdbp[0],
					    new_pkt->pkt_cdbp[1],
					    new_pkt->pkt_cdbp[2]));
					goto again;
				}
				rval = 0;
				VHCI_DEBUG(4, (CE_WARN, NULL,
				    "!vhci_do_prout 0x%x "
				    "(0x%x 0x%x 0x%x)",
				    SCBP_C(new_pkt),
				    new_pkt->pkt_cdbp[0],
				    new_pkt->pkt_cdbp[1],
				    new_pkt->pkt_cdbp[2]));
			} else if (skey == KEY_ILLEGAL_REQUEST)
				rval = VHCI_PGR_ILLEGALOP;
		}
	} else {
		rval = 1;
	}
	scsi_destroy_pkt(new_pkt);
	VHCI_DECR_PATH_CMDCOUNT(svp);
	freerbuf(bp);
	return (rval);
}

static void
vhci_run_cmd(void *arg)
{
	struct scsi_pkt		*pkt = (struct scsi_pkt *)arg;
	struct scsi_pkt		*tpkt;
	scsi_vhci_priv_t	*svp;
	mdi_pathinfo_t		*pip, *npip;
	scsi_vhci_lun_t		*vlun;
	dev_info_t		*cdip;
	scsi_vhci_priv_t	*nsvp;
	int			fail = 0;
	int			rval;
	struct vhci_pkt		*vpkt;
	uchar_t			cdb_1;
	vhci_prout_t		*prout;

	vpkt = (struct vhci_pkt *)pkt->pkt_private;
	tpkt = vpkt->vpkt_tgt_pkt;
	pip = vpkt->vpkt_path;
	svp = (scsi_vhci_priv_t *)mdi_pi_get_vhci_private(pip);
	if (svp == NULL) {
		tpkt->pkt_reason = CMD_TRAN_ERR;
		tpkt->pkt_statistics = STAT_ABORTED;
		goto done;
	}
	vlun = svp->svp_svl;
	prout = &vlun->svl_prout;
	if (SCBP_C(pkt) != STATUS_GOOD)
		fail++;
	cdip = vlun->svl_dip;
	pip = npip = NULL;
	rval = mdi_select_path(cdip, NULL,
	    MDI_SELECT_ONLINE_PATH|MDI_SELECT_STANDBY_PATH, NULL, &npip);
	if ((rval != MDI_SUCCESS) || (npip == NULL)) {
		VHCI_DEBUG(4, (CE_NOTE, NULL,
		    "vhci_run_cmd: no path! 0x%p\n", (void *)svp));
		tpkt->pkt_reason = CMD_TRAN_ERR;
		tpkt->pkt_statistics = STAT_ABORTED;
		goto done;
	}

	cdb_1 = vlun->svl_cdb[1];
	vlun->svl_cdb[1] &= 0xe0;
	vlun->svl_cdb[1] |= VHCI_PROUT_R_AND_IGNORE;

	do {
		nsvp = (scsi_vhci_priv_t *)mdi_pi_get_vhci_private(npip);
		if (nsvp == NULL) {
			VHCI_DEBUG(4, (CE_NOTE, NULL,
			    "vhci_run_cmd: no "
			    "client priv! 0x%p offlined?\n",
			    (void *)npip));
			goto next_path;
		}
		if (vlun->svl_first_path == npip) {
			goto next_path;
		} else {
			if (vhci_do_prout(nsvp) != 1)
				fail++;
		}
next_path:
		pip = npip;
		rval = mdi_select_path(cdip, NULL,
		    MDI_SELECT_ONLINE_PATH|MDI_SELECT_STANDBY_PATH,
		    pip, &npip);
		mdi_rele_path(pip);
	} while ((rval == MDI_SUCCESS) && (npip != NULL));

	vlun->svl_cdb[1] = cdb_1;

	if (fail) {
		VHCI_DEBUG(4, (CE_WARN, NULL, "%s%d: key registration failed, "
		    "couldn't be replicated on all paths",
		    ddi_driver_name(cdip), ddi_get_instance(cdip)));
		vhci_print_prout_keys(vlun, "vhci_run_cmd: ");

		if (SCBP_C(pkt) != STATUS_GOOD) {
			tpkt->pkt_reason = CMD_TRAN_ERR;
			tpkt->pkt_statistics = STAT_ABORTED;
		}
	} else {
		vlun->svl_pgr_active = 1;
		vhci_print_prout_keys(vlun, "vhci_run_cmd: before bcopy:");

		bcopy((const void *)prout->service_key,
		    (void *)prout->active_service_key, MHIOC_RESV_KEY_SIZE);
		bcopy((const void *)prout->res_key,
		    (void *)prout->active_res_key, MHIOC_RESV_KEY_SIZE);

		vhci_print_prout_keys(vlun, "vhci_run_cmd: after bcopy:");
	}
done:
	if (SCBP_C(pkt) == STATUS_GOOD)
		vlun->svl_first_path = NULL;

	if (svp)
		VHCI_DECR_PATH_CMDCOUNT(svp);

	if ((vpkt->vpkt_flags & CFLAG_DMA_PARTIAL) == 0) {
		scsi_destroy_pkt(pkt);
		vpkt->vpkt_hba_pkt = NULL;
		if (vpkt->vpkt_path) {
			mdi_rele_path(vpkt->vpkt_path);
			vpkt->vpkt_path = NULL;
		}
	}

	sema_v(&vlun->svl_pgr_sema);
	/*
	 * The PROUT commands are not included in the automatic retry
	 * mechanism, therefore, vpkt_org_vpkt should never be set here.
	 */
	ASSERT(vpkt->vpkt_org_vpkt == NULL);
	scsi_hba_pkt_comp(tpkt);
}

/*
 * Get the keys registered with this target.  Since we will have
 * registered the same key with multiple initiators, strip out
 * any duplicate keys.
 *
 * The pointers which will be used to filter the registered keys from
 * the device will be stored in filter_prin and filter_pkt.  If the
 * allocation length of the buffer was sufficient for the number of
 * parameter data bytes available to be returned by the device then the
 * key filtering will use the keylist returned from the original
 * request.  If the allocation length of the buffer was not sufficient,
 * then the filtering will use the keylist returned from the request
 * that is resent below.
 *
 * If the device returns an additional length field that is greater than
 * the allocation length of the buffer, then allocate a new buffer which
 * can accommodate the number of parameter data bytes available to be
 * returned.  Resend the scsi PRIN command, filter out the duplicate
 * keys and return as many of the unique keys found that was originally
 * requested and set the additional length field equal to the data bytes
 * of unique reservation keys available to be returned.
 *
 * If the device returns an additional length field that is less than or
 * equal to the allocation length of the buffer, then all the available
 * keys registered were returned by the device.  Filter out the
 * duplicate keys and return all of the unique keys found and set the
 * additional length field equal to the data bytes of the reservation
 * keys to be returned.
 */

#define	VHCI_PRIN_HEADER_SZ (sizeof (prin->length) + sizeof (prin->generation))

static int
vhci_do_prin(struct vhci_pkt **intr_vpkt)
{
	scsi_vhci_priv_t *svp;
	struct vhci_pkt *vpkt = *intr_vpkt;
	vhci_prin_readkeys_t *prin;
	scsi_vhci_lun_t *vlun;
	struct scsi_vhci *vhci = ADDR2VHCI(&vpkt->vpkt_tgt_pkt->pkt_address);

	struct buf		*new_bp = NULL;
	struct scsi_pkt		*new_pkt = NULL;
	struct vhci_pkt		*new_vpkt = NULL;
	uint32_t		needed_length;
	int			rval = VHCI_CMD_CMPLT;
	uint32_t		prin_length = 0;
	uint32_t		svl_prin_length = 0;

	ASSERT(vpkt->vpkt_path);
	svp = mdi_pi_get_vhci_private(vpkt->vpkt_path);
	ASSERT(svp);
	vlun = svp->svp_svl;
	ASSERT(vlun);

	/*
	 * If the caller only asked for an amount of data that would not
	 * be enough to include any key data it is likely that they will
	 * send the next command with a buffer size based on the information
	 * from this header. Doing recovery on this would be a duplication
	 * of efforts.
	 */
	if (vpkt->vpkt_tgt_init_bp->b_bcount <= VHCI_PRIN_HEADER_SZ) {
		rval = VHCI_CMD_CMPLT;
		goto exit;
	}

	if (vpkt->vpkt_org_vpkt == NULL) {
		/*
		 * Can fail as sleep is not allowed.
		 */
		prin = (vhci_prin_readkeys_t *)
		    bp_mapin_common(vpkt->vpkt_tgt_init_bp, VM_NOSLEEP);
	} else {
		/*
		 * The retry buf doesn't need to be mapped in.
		 */
		prin = (vhci_prin_readkeys_t *)
		    vpkt->vpkt_tgt_init_bp->b_un.b_daddr;
	}

	if (prin == NULL) {
		VHCI_DEBUG(5, (CE_WARN, NULL,
		    "vhci_do_prin: bp_mapin_common failed."));
		rval = VHCI_CMD_ERROR;
		goto fail;
	}

	prin_length = BE_32(prin->length);

	/*
	 * According to SPC-3r22, sec 4.3.4.6: "If the amount of
	 * information to be transferred exceeds the maximum value
	 * that the ALLOCATION LENGTH field is capable of specifying,
	 * the device server shall...terminate the command with CHECK
	 * CONDITION status".  The ALLOCATION LENGTH field of the
	 * PERSISTENT RESERVE IN command is 2 bytes. We should never
	 * get here with an ADDITIONAL LENGTH greater than 0xFFFF
	 * so if we do, then it is an error!
	 */


	if ((prin_length + VHCI_PRIN_HEADER_SZ) > 0xFFFF) {
		VHCI_DEBUG(5, (CE_NOTE, NULL,
		    "vhci_do_prin: Device returned invalid "
		    "length 0x%x\n", prin_length));
		rval = VHCI_CMD_ERROR;
		goto fail;
	}
	needed_length = prin_length + VHCI_PRIN_HEADER_SZ;

	/*
	 * If prin->length is greater than the byte count allocated in the
	 * original buffer, then resend the request with enough buffer
	 * allocated to get all of the available registered keys.
	 */
	if ((vpkt->vpkt_tgt_init_bp->b_bcount < needed_length) &&
	    (vpkt->vpkt_org_vpkt == NULL)) {

		new_pkt = vhci_create_retry_pkt(vpkt);
		if (new_pkt == NULL) {
			rval = VHCI_CMD_ERROR;
			goto fail;
		}
		new_vpkt = TGTPKT2VHCIPKT(new_pkt);

		/*
		 * This is the buf with buffer pointer
		 * where the prin readkeys will be
		 * returned from the device
		 */
		new_bp = scsi_alloc_consistent_buf(&svp->svp_psd->sd_address,
		    NULL, needed_length, B_READ, NULL_FUNC, NULL);
		if ((new_bp == NULL) || (new_bp->b_un.b_addr == NULL)) {
			if (new_bp) {
				scsi_free_consistent_buf(new_bp);
			}
			vhci_scsi_destroy_pkt(&new_pkt->pkt_address, new_pkt);
			rval = VHCI_CMD_ERROR;
			goto fail;
		}
		new_bp->b_bcount = needed_length;
		new_pkt->pkt_cdbp[7] = (uchar_t)(needed_length >> 8);
		new_pkt->pkt_cdbp[8] = (uchar_t)needed_length;

		rval = VHCI_CMD_RETRY;

		new_vpkt->vpkt_tgt_init_bp = new_bp;
	}

	if (rval == VHCI_CMD_RETRY) {

		/*
		 * There were more keys then the original request asked for.
		 */
		mdi_pathinfo_t *path_holder = vpkt->vpkt_path;

		/*
		 * Release the old path because it does not matter which path
		 * this command is sent down.  This allows the normal bind
		 * transport mechanism to be used.
		 */
		if (vpkt->vpkt_path != NULL) {
			mdi_rele_path(vpkt->vpkt_path);
			vpkt->vpkt_path = NULL;
		}

		/*
		 * Dispatch the retry command
		 */
		if (taskq_dispatch(vhci->vhci_taskq, vhci_dispatch_scsi_start,
		    (void *) new_vpkt, KM_NOSLEEP) == NULL) {
			if (path_holder) {
				vpkt->vpkt_path = path_holder;
				mdi_hold_path(path_holder);
			}
			scsi_free_consistent_buf(new_bp);
			vhci_scsi_destroy_pkt(&new_pkt->pkt_address, new_pkt);
			rval = VHCI_CMD_ERROR;
			goto fail;
		}

		/*
		 * If we return VHCI_CMD_RETRY, that means the caller
		 * is going to bail and wait for the reissued command
		 * to complete.  In that case, we need to decrement
		 * the path command count right now.  In any other
		 * case, it'll be decremented by the caller.
		 */
		VHCI_DECR_PATH_CMDCOUNT(svp);
		goto exit;

	}

	if (rval == VHCI_CMD_CMPLT) {
		/*
		 * The original request got all of the keys or the recovery
		 * packet returns.
		 */
		int new;
		int old;
		int num_keys = prin_length / MHIOC_RESV_KEY_SIZE;

		VHCI_DEBUG(4, (CE_NOTE, NULL, "vhci_do_prin: %d keys read\n",
		    num_keys));

#ifdef DEBUG
		VHCI_DEBUG(5, (CE_NOTE, NULL, "vhci_do_prin: from storage\n"));
		if (vhci_debug == 5)
			vhci_print_prin_keys(prin, num_keys);
		VHCI_DEBUG(5, (CE_NOTE, NULL,
		    "vhci_do_prin: MPxIO old keys:\n"));
		if (vhci_debug == 5)
			vhci_print_prin_keys(&vlun->svl_prin, num_keys);
#endif

		/*
		 * Filter out all duplicate keys returned from the device
		 * We know that we use a different key for every host, so we
		 * can simply strip out duplicates. Otherwise we would need to
		 * do more bookkeeping to figure out which keys to strip out.
		 */

		new = 0;

		/*
		 * If we got at least 1 key copy it.
		 */
		if (num_keys > 0) {
			vlun->svl_prin.keylist[0] = prin->keylist[0];
			new++;
		}

		/*
		 * find next unique key.
		 */
		for (old = 1; old < num_keys; old++) {
			int j;
			int match = 0;

			if (new >= VHCI_NUM_RESV_KEYS)
				break;
			for (j = 0; j < new; j++) {
				if (bcmp(&prin->keylist[old],
				    &vlun->svl_prin.keylist[j],
				    sizeof (mhioc_resv_key_t)) == 0) {
					match = 1;
					break;
				}
			}
			if (!match) {
				vlun->svl_prin.keylist[new] =
				    prin->keylist[old];
				new++;
			}
		}

		/* Stored Big Endian */
		vlun->svl_prin.generation = prin->generation;
		svl_prin_length = new * sizeof (mhioc_resv_key_t);
		/* Stored Big Endian */
		vlun->svl_prin.length = BE_32(svl_prin_length);
		svl_prin_length += VHCI_PRIN_HEADER_SZ;

		/*
		 * If we arrived at this point after issuing a retry, make sure
		 * that we put everything back the way it originally was so
		 * that the target driver can complete the command correctly.
		 */
		if (vpkt->vpkt_org_vpkt != NULL) {
			new_bp = vpkt->vpkt_tgt_init_bp;

			scsi_free_consistent_buf(new_bp);

			vpkt = vhci_sync_retry_pkt(vpkt);
			*intr_vpkt = vpkt;

			/*
			 * Make sure the original buffer is mapped into kernel
			 * space before we try to copy the filtered keys into
			 * it.
			 */
			prin = (vhci_prin_readkeys_t *)bp_mapin_common(
			    vpkt->vpkt_tgt_init_bp, VM_NOSLEEP);
		}

		/*
		 * Now copy the desired number of prin keys into the original
		 * target buffer.
		 */
		if (svl_prin_length <= vpkt->vpkt_tgt_init_bp->b_bcount) {
			/*
			 * It is safe to return all of the available unique
			 * keys
			 */
			bcopy(&vlun->svl_prin, prin, svl_prin_length);
		} else {
			/*
			 * Not all of the available keys were requested by the
			 * original command.
			 */
			bcopy(&vlun->svl_prin, prin,
			    vpkt->vpkt_tgt_init_bp->b_bcount);
		}
#ifdef DEBUG
		VHCI_DEBUG(5, (CE_NOTE, NULL,
		    "vhci_do_prin: To Application:\n"));
		if (vhci_debug == 5)
			vhci_print_prin_keys(prin, new);
		VHCI_DEBUG(5, (CE_NOTE, NULL,
		    "vhci_do_prin: MPxIO new keys:\n"));
		if (vhci_debug == 5)
			vhci_print_prin_keys(&vlun->svl_prin, new);
#endif
	}
fail:
	if (rval == VHCI_CMD_ERROR) {
		/*
		 * If we arrived at this point after issuing a
		 * retry, make sure that we put everything back
		 * the way it originally was so that ssd can
		 * complete the command correctly.
		 */

		if (vpkt->vpkt_org_vpkt != NULL) {
			new_bp = vpkt->vpkt_tgt_init_bp;
			if (new_bp != NULL) {
				scsi_free_consistent_buf(new_bp);
			}

			new_vpkt = vpkt;
			vpkt = vpkt->vpkt_org_vpkt;

			vhci_scsi_destroy_pkt(&svp->svp_psd->sd_address,
			    new_vpkt->vpkt_tgt_pkt);
		}

		/*
		 * Mark this command completion as having an error so that
		 * ssd will retry the command.
		 */

		vpkt->vpkt_tgt_pkt->pkt_reason = CMD_ABORTED;
		vpkt->vpkt_tgt_pkt->pkt_statistics |= STAT_ABORTED;

		rval = VHCI_CMD_CMPLT;
	}
exit:
	/*
	 * Make sure that the semaphore is only released once.
	 */
	if (rval == VHCI_CMD_CMPLT) {
		sema_v(&vlun->svl_pgr_sema);
	}

	return (rval);
}

static void
vhci_intr(struct scsi_pkt *pkt)
{
	struct vhci_pkt		*vpkt = (struct vhci_pkt *)pkt->pkt_private;
	struct scsi_pkt		*tpkt;
	scsi_vhci_priv_t	*svp;
	scsi_vhci_lun_t		*vlun;
	int			rval, held;
	struct scsi_failover_ops	*fops;
	uint8_t			*sns, skey, asc, ascq;
	mdi_pathinfo_t		*lpath;
	static char		*timeout_err = "Command Timeout";
	static char		*parity_err = "Parity Error";
	char			*err_str = NULL;
	dev_info_t		*vdip, *cdip;
	char			*cpath;

	ASSERT(vpkt != NULL);
	tpkt = vpkt->vpkt_tgt_pkt;
	ASSERT(tpkt != NULL);
	svp = (scsi_vhci_priv_t *)mdi_pi_get_vhci_private(vpkt->vpkt_path);
	ASSERT(svp != NULL);
	vlun = svp->svp_svl;
	ASSERT(vlun != NULL);
	lpath = vpkt->vpkt_path;

	/*
	 * sync up the target driver's pkt with the pkt that
	 * we actually used
	 */
	*(tpkt->pkt_scbp) = *(pkt->pkt_scbp);
	tpkt->pkt_resid = pkt->pkt_resid;
	tpkt->pkt_state = pkt->pkt_state;
	tpkt->pkt_statistics = pkt->pkt_statistics;
	tpkt->pkt_reason = pkt->pkt_reason;

	/* Return path_instance information back to the target driver. */
	if (scsi_pkt_allocated_correctly(tpkt)) {
		if (scsi_pkt_allocated_correctly(pkt)) {
			/*
			 * If both packets were correctly allocated,
			 * return path returned by pHCI.
			 */
			tpkt->pkt_path_instance = pkt->pkt_path_instance;
		} else {
			/* Otherwise return path of pHCI we used */
			tpkt->pkt_path_instance =
			    mdi_pi_get_path_instance(lpath);
		}
	}

	if (pkt->pkt_cdbp[0] == SCMD_PROUT &&
	    ((pkt->pkt_cdbp[1] & 0x1f) == VHCI_PROUT_REGISTER) ||
	    ((pkt->pkt_cdbp[1] & 0x1f) == VHCI_PROUT_R_AND_IGNORE)) {
		if ((SCBP_C(pkt) != STATUS_GOOD) ||
		    (pkt->pkt_reason != CMD_CMPLT)) {
			sema_v(&vlun->svl_pgr_sema);
		}
	} else if (pkt->pkt_cdbp[0] == SCMD_PRIN) {
		if (pkt->pkt_reason != CMD_CMPLT ||
		    (SCBP_C(pkt) != STATUS_GOOD)) {
			sema_v(&vlun->svl_pgr_sema);
		}
	}

	switch (pkt->pkt_reason) {
	case CMD_CMPLT:
		/*
		 * cmd completed successfully, check for scsi errors
		 */
		switch (*(pkt->pkt_scbp)) {
		case STATUS_CHECK:
			if (pkt->pkt_state & STATE_ARQ_DONE) {
				sns = (uint8_t *)
				    &(((struct scsi_arq_status *)(uintptr_t)
				    (pkt->pkt_scbp))->sts_sensedata);
				skey = scsi_sense_key(sns);
				asc = scsi_sense_asc(sns);
				ascq = scsi_sense_ascq(sns);
				fops = vlun->svl_fops;
				ASSERT(fops != NULL);
				VHCI_DEBUG(4, (CE_NOTE, NULL, "vhci_intr: "
				    "Received sns key %x  esc %x  escq %x\n",
				    skey, asc, ascq));

				if (vlun->svl_waiting_for_activepath == 1) {
					/*
					 * if we are here it means we are
					 * in the midst of a probe/attach
					 * through a passive path; this
					 * case is exempt from sense analysis
					 * for detection of ext. failover
					 * because that would unnecessarily
					 * increase attach time.
					 */
					bcopy(pkt->pkt_scbp, tpkt->pkt_scbp,
					    vpkt->vpkt_tgt_init_scblen);
					break;
				}
				if (asc == VHCI_SCSI_PERR) {
					/*
					 * parity error
					 */
					err_str = parity_err;
					bcopy(pkt->pkt_scbp, tpkt->pkt_scbp,
					    vpkt->vpkt_tgt_init_scblen);
					break;
				}
				rval = fops->sfo_analyze_sense(svp->svp_psd,
				    sns, vlun->svl_fops_ctpriv);
				if ((rval == SCSI_SENSE_NOFAILOVER) ||
				    (rval == SCSI_SENSE_UNKNOWN) ||
				    (rval == SCSI_SENSE_NOT_READY)) {
					bcopy(pkt->pkt_scbp, tpkt->pkt_scbp,
					    vpkt->vpkt_tgt_init_scblen);
					break;
				} else if (rval == SCSI_SENSE_STATE_CHANGED) {
					struct scsi_vhci	*vhci;
					vhci = ADDR2VHCI(&tpkt->pkt_address);
					VHCI_HOLD_LUN(vlun, VH_NOSLEEP, held);
					if (!held) {
						/*
						 * looks like some other thread
						 * has already detected this
						 * condition
						 */
						tpkt->pkt_state &=
						    ~STATE_ARQ_DONE;
						*(tpkt->pkt_scbp) =
						    STATUS_BUSY;
						break;
					}
					(void) taskq_dispatch(
					    vhci->vhci_update_pathstates_taskq,
					    vhci_update_pathstates,
					    (void *)vlun, KM_SLEEP);
				} else {
					/*
					 * externally initiated failover
					 * has occurred or is in progress
					 */
					VHCI_HOLD_LUN(vlun, VH_NOSLEEP, held);
					if (!held) {
						/*
						 * looks like some other thread
						 * has already detected this
						 * condition
						 */
						tpkt->pkt_state &=
						    ~STATE_ARQ_DONE;
						*(tpkt->pkt_scbp) =
						    STATUS_BUSY;
						break;
					} else {
						rval = vhci_handle_ext_fo
						    (pkt, rval);
						if (rval == BUSY_RETURN) {
							tpkt->pkt_state &=
							    ~STATE_ARQ_DONE;
							*(tpkt->pkt_scbp) =
							    STATUS_BUSY;
							break;
						}
						bcopy(pkt->pkt_scbp,
						    tpkt->pkt_scbp,
						    vpkt->vpkt_tgt_init_scblen);
						break;
					}
				}
			}
			break;

		/*
		 * If this is a good SCSI-II RELEASE cmd completion then restore
		 * the load balancing policy and reset VLUN_RESERVE_ACTIVE_FLG.
		 * If this is a good SCSI-II RESERVE cmd completion then set
		 * VLUN_RESERVE_ACTIVE_FLG.
		 */
		case STATUS_GOOD:
			if ((pkt->pkt_cdbp[0] == SCMD_RELEASE) ||
			    (pkt->pkt_cdbp[0] == SCMD_RELEASE_G1)) {
				(void) mdi_set_lb_policy(vlun->svl_dip,
				    vlun->svl_lb_policy_save);
				vlun->svl_flags &= ~VLUN_RESERVE_ACTIVE_FLG;
				VHCI_DEBUG(1, (CE_WARN, NULL,
				    "!vhci_intr: vlun 0x%p release path 0x%p",
				    (void *)vlun, (void *)vpkt->vpkt_path));
			}

			if ((pkt->pkt_cdbp[0] == SCMD_RESERVE) ||
			    (pkt->pkt_cdbp[0] == SCMD_RESERVE_G1)) {
				vlun->svl_flags |= VLUN_RESERVE_ACTIVE_FLG;
				vlun->svl_resrv_pip = vpkt->vpkt_path;
				VHCI_DEBUG(1, (CE_WARN, NULL,
				    "!vhci_intr: vlun 0x%p reserved path 0x%p",
				    (void *)vlun, (void *)vpkt->vpkt_path));
			}
			break;

		case STATUS_RESERVATION_CONFLICT:
			VHCI_DEBUG(1, (CE_WARN, NULL,
			    "!vhci_intr: vlun 0x%p "
			    "reserve conflict on path 0x%p",
			    (void *)vlun, (void *)vpkt->vpkt_path));
			/* FALLTHROUGH */
		default:
			break;
		}

		/*
		 * Update I/O completion statistics for the path
		 */
		mdi_pi_kstat_iosupdate(vpkt->vpkt_path, vpkt->vpkt_tgt_init_bp);

		/*
		 * Command completed successfully, release the dma binding and
		 * destroy the transport side of the packet.
		 */
		if ((pkt->pkt_cdbp[0] == SCMD_PROUT) &&
		    (((pkt->pkt_cdbp[1] & 0x1f) == VHCI_PROUT_REGISTER) ||
		    ((pkt->pkt_cdbp[1] & 0x1f) == VHCI_PROUT_R_AND_IGNORE))) {
			if (SCBP_C(pkt) == STATUS_GOOD) {
				ASSERT(vlun->svl_taskq);
				svp->svp_last_pkt_reason = pkt->pkt_reason;
				(void) taskq_dispatch(vlun->svl_taskq,
				    vhci_run_cmd, pkt, KM_SLEEP);
				return;
			}
		}
		if ((SCBP_C(pkt) == STATUS_GOOD) &&
		    (pkt->pkt_cdbp[0] == SCMD_PRIN) && vpkt->vpkt_tgt_init_bp) {
			/*
			 * If the action (value in byte 1 of the cdb) is zero,
			 * we're reading keys, and that's the only condition
			 * where we need to be concerned with filtering keys
			 * and potential retries.  Otherwise, we simply signal
			 * the semaphore and move on.
			 */
			if (pkt->pkt_cdbp[1] == 0) {
				/*
				 * If this is the completion of an internal
				 * retry then we need to make sure that the
				 * pkt and tpkt pointers are readjusted so
				 * the calls to scsi_destroy_pkt and pkt_comp
				 * below work * correctly.
				 */
				if (vpkt->vpkt_org_vpkt != NULL) {
					pkt = vpkt->vpkt_org_vpkt->vpkt_hba_pkt;
					tpkt = vpkt->vpkt_org_vpkt->
					    vpkt_tgt_pkt;

					/*
					 * If this command was issued through
					 * the taskq then we need to clear
					 * this flag for proper processing in
					 * the case of a retry from the target
					 * driver.
					 */
					vpkt->vpkt_state &=
					    ~VHCI_PKT_THRU_TASKQ;
				}

				/*
				 * if vhci_do_prin returns VHCI_CMD_CMPLT then
				 * vpkt will contain the address of the
				 * original vpkt
				 */
				if (vhci_do_prin(&vpkt) == VHCI_CMD_RETRY) {
					/*
					 * The command has been resent to get
					 * all the keys from the device.  Don't
					 * complete the command with ssd until
					 * the retry completes.
					 */
					return;
				}
			} else {
				sema_v(&vlun->svl_pgr_sema);
			}
		}

		break;

	case CMD_TIMEOUT:
		if ((pkt->pkt_statistics &
		    (STAT_BUS_RESET|STAT_DEV_RESET|STAT_ABORTED)) == 0) {

			VHCI_DEBUG(1, (CE_NOTE, NULL,
			    "!scsi vhci timeout invoked\n"));

			(void) vhci_recovery_reset(vlun, &pkt->pkt_address,
			    FALSE, VHCI_DEPTH_ALL);
		}
		MDI_PI_ERRSTAT(lpath, MDI_PI_TRANSERR);
		tpkt->pkt_statistics |= STAT_ABORTED;
		err_str = timeout_err;
		break;

	case CMD_TRAN_ERR:
		/*
		 * This status is returned if the transport has sent the cmd
		 * down the link to the target and then some error occurs.
		 * In case of SCSI-II RESERVE cmd, we don't know if the
		 * reservation been accepted by the target or not, so we need
		 * to clear the reservation.
		 */
		if ((pkt->pkt_cdbp[0] == SCMD_RESERVE) ||
		    (pkt->pkt_cdbp[0] == SCMD_RESERVE_G1)) {
			VHCI_DEBUG(1, (CE_NOTE, NULL, "!vhci_intr received"
			    " cmd_tran_err for scsi-2 reserve cmd\n"));
			if (!vhci_recovery_reset(vlun, &pkt->pkt_address,
			    TRUE, VHCI_DEPTH_TARGET)) {
				VHCI_DEBUG(1, (CE_WARN, NULL,
				    "!vhci_intr cmd_tran_err reset failed!"));
			}
		}
		break;

	case CMD_DEV_GONE:
		/*
		 * If this is the last path then report CMD_DEV_GONE to the
		 * target driver, otherwise report BUSY to triggger retry.
		 */
		if (vlun->svl_dip &&
		    (mdi_client_get_path_count(vlun->svl_dip) <= 1)) {
			struct scsi_vhci	*vhci;
			vhci = ADDR2VHCI(&tpkt->pkt_address);
			VHCI_DEBUG(1, (CE_NOTE, NULL, "vhci_intr received "
			    "cmd_dev_gone on last path\n"));
			(void) vhci_invalidate_mpapi_lu(vhci, vlun);
			break;
		}

		/* Report CMD_CMPLT-with-BUSY to cause retry. */
		VHCI_DEBUG(1, (CE_NOTE, NULL, "vhci_intr received "
		    "cmd_dev_gone\n"));
		tpkt->pkt_reason = CMD_CMPLT;
		tpkt->pkt_state = STATE_GOT_BUS |
		    STATE_GOT_TARGET | STATE_SENT_CMD |
		    STATE_GOT_STATUS;
		*(tpkt->pkt_scbp) = STATUS_BUSY;
		break;

	default:
		break;
	}

	/*
	 * SCSI-II RESERVE cmd has been serviced by the lower layers clear
	 * the flag so the lun is not QUIESCED any longer.
	 * Also clear the VHCI_PKT_THRU_TASKQ flag, to ensure that if this pkt
	 * is retried, a taskq shall again be dispatched to service it.  Else
	 * it may lead to a system hang if the retry is within interrupt
	 * context.
	 */
	if ((pkt->pkt_cdbp[0] == SCMD_RESERVE) ||
	    (pkt->pkt_cdbp[0] == SCMD_RESERVE_G1)) {
		vlun->svl_flags &= ~VLUN_QUIESCED_FLG;
		vpkt->vpkt_state &= ~VHCI_PKT_THRU_TASKQ;
	}

	/*
	 * vpkt_org_vpkt should always be NULL here if the retry command
	 * has been successfully processed.  If vpkt_org_vpkt != NULL at
	 * this point, it is an error so restore the original vpkt and
	 * return an error to the target driver so it can retry the
	 * command as appropriate.
	 */
	if (vpkt->vpkt_org_vpkt != NULL) {
		struct vhci_pkt *new_vpkt = vpkt;
		vpkt = vpkt->vpkt_org_vpkt;

		vhci_scsi_destroy_pkt(&svp->svp_psd->sd_address,
		    new_vpkt->vpkt_tgt_pkt);

		/*
		 * Mark this command completion as having an error so that
		 * ssd will retry the command.
		 */
		vpkt->vpkt_tgt_pkt->pkt_reason = CMD_ABORTED;
		vpkt->vpkt_tgt_pkt->pkt_statistics |= STAT_ABORTED;

		pkt = vpkt->vpkt_hba_pkt;
		tpkt = vpkt->vpkt_tgt_pkt;
	}

	if ((err_str != NULL) && (pkt->pkt_reason !=
	    svp->svp_last_pkt_reason)) {
		cdip = vlun->svl_dip;
		vdip = ddi_get_parent(cdip);
		cpath = kmem_alloc(MAXPATHLEN, KM_SLEEP);
		vhci_log(CE_WARN, vdip, "!%s (%s%d): %s on path %s",
		    ddi_pathname(cdip, cpath), ddi_driver_name(cdip),
		    ddi_get_instance(cdip), err_str,
		    mdi_pi_spathname(vpkt->vpkt_path));
		kmem_free(cpath, MAXPATHLEN);
	}
	svp->svp_last_pkt_reason = pkt->pkt_reason;
	VHCI_DECR_PATH_CMDCOUNT(svp);

	/*
	 * For PARTIAL_DMA, vhci should not free the path.
	 * Target driver will call into vhci_scsi_dmafree or
	 * destroy pkt to release this path.
	 */
	if ((vpkt->vpkt_flags & CFLAG_DMA_PARTIAL) == 0) {
		scsi_destroy_pkt(pkt);
		vpkt->vpkt_hba_pkt = NULL;
		if (vpkt->vpkt_path) {
			mdi_rele_path(vpkt->vpkt_path);
			vpkt->vpkt_path = NULL;
		}
	}

	scsi_hba_pkt_comp(tpkt);
}

/*
 * two possibilities: (1) failover has completed
 * or (2) is in progress; update our path states for
 * the former case; for the latter case,
 * initiate a scsi_watch request to
 * determine when failover completes - vlun is HELD
 * until failover completes; BUSY is returned to upper
 * layer in both the cases
 */
static int
vhci_handle_ext_fo(struct scsi_pkt *pkt, int fostat)
{
	struct vhci_pkt		*vpkt = (struct vhci_pkt *)pkt->pkt_private;
	struct scsi_pkt		*tpkt;
	scsi_vhci_priv_t	*svp;
	scsi_vhci_lun_t		*vlun;
	struct scsi_vhci	*vhci;
	scsi_vhci_swarg_t	*swarg;
	char			*path;

	ASSERT(vpkt != NULL);
	tpkt = vpkt->vpkt_tgt_pkt;
	ASSERT(tpkt != NULL);
	svp = (scsi_vhci_priv_t *)mdi_pi_get_vhci_private(vpkt->vpkt_path);
	ASSERT(svp != NULL);
	vlun = svp->svp_svl;
	ASSERT(vlun != NULL);
	ASSERT(VHCI_LUN_IS_HELD(vlun));

	vhci = ADDR2VHCI(&tpkt->pkt_address);

	if (fostat == SCSI_SENSE_INACTIVE) {
		VHCI_DEBUG(1, (CE_NOTE, NULL, "!Failover "
		    "detected for %s; updating path states...\n",
		    vlun->svl_lun_wwn));
		/*
		 * set the vlun flag to indicate to the task that the target
		 * port group needs updating
		 */
		vlun->svl_flags |= VLUN_UPDATE_TPG;
		(void) taskq_dispatch(vhci->vhci_update_pathstates_taskq,
		    vhci_update_pathstates, (void *)vlun, KM_SLEEP);
	} else {
		path = kmem_alloc(MAXPATHLEN, KM_SLEEP);
		vhci_log(CE_NOTE, ddi_get_parent(vlun->svl_dip),
		    "!%s (%s%d): Waiting for externally initiated failover "
		    "to complete", ddi_pathname(vlun->svl_dip, path),
		    ddi_driver_name(vlun->svl_dip),
		    ddi_get_instance(vlun->svl_dip));
		kmem_free(path, MAXPATHLEN);
		swarg = kmem_alloc(sizeof (*swarg), KM_NOSLEEP);
		if (swarg == NULL) {
			VHCI_DEBUG(1, (CE_NOTE, NULL, "!vhci_handle_ext_fo: "
			    "request packet allocation for %s failed....\n",
			    vlun->svl_lun_wwn));
			VHCI_RELEASE_LUN(vlun);
			return (PKT_RETURN);
		}
		swarg->svs_svp = svp;
		swarg->svs_tos = gethrtime();
		swarg->svs_pi = vpkt->vpkt_path;
		swarg->svs_release_lun = 0;
		swarg->svs_done = 0;
		/*
		 * place a hold on the path...we don't want it to
		 * vanish while scsi_watch is in progress
		 */
		mdi_hold_path(vpkt->vpkt_path);
		svp->svp_sw_token = scsi_watch_request_submit(svp->svp_psd,
		    VHCI_FOWATCH_INTERVAL, SENSE_LENGTH, vhci_efo_watch_cb,
		    (caddr_t)swarg);
	}
	return (BUSY_RETURN);
}

/*
 * vhci_efo_watch_cb:
 *	Callback from scsi_watch request to check the failover status.
 *	Completion is either due to successful failover or timeout.
 *	Upon successful completion, vhci_update_path_states is called.
 *	For timeout condition, vhci_efo_done is called.
 *	Always returns 0 to scsi_watch to keep retrying till vhci_efo_done
 *	terminates this request properly in a separate thread.
 */

static int
vhci_efo_watch_cb(caddr_t arg, struct scsi_watch_result *resultp)
{
	struct scsi_status		*statusp = resultp->statusp;
	uint8_t				*sensep = (uint8_t *)resultp->sensep;
	struct scsi_pkt			*pkt = resultp->pkt;
	scsi_vhci_swarg_t		*swarg;
	scsi_vhci_priv_t		*svp;
	scsi_vhci_lun_t			*vlun;
	struct scsi_vhci		*vhci;
	dev_info_t			*vdip;
	int				rval, updt_paths;

	swarg = (scsi_vhci_swarg_t *)(uintptr_t)arg;
	svp = swarg->svs_svp;
	if (swarg->svs_done) {
		/*
		 * Already completed failover or timedout.
		 * Waiting for vhci_efo_done to terminate this scsi_watch.
		 */
		return (0);
	}

	ASSERT(svp != NULL);
	vlun = svp->svp_svl;
	ASSERT(vlun != NULL);
	ASSERT(VHCI_LUN_IS_HELD(vlun));
	vlun->svl_efo_update_path = 0;
	vdip = ddi_get_parent(vlun->svl_dip);
	vhci = ddi_get_soft_state(vhci_softstate,
	    ddi_get_instance(vdip));

	updt_paths = 0;

	if (pkt->pkt_reason != CMD_CMPLT) {
		if ((gethrtime() - swarg->svs_tos) >= VHCI_EXTFO_TIMEOUT) {
			swarg->svs_release_lun = 1;
			goto done;
		}
		return (0);
	}
	if (*((unsigned char *)statusp) == STATUS_CHECK) {
		rval = vlun->svl_fops->sfo_analyze_sense(svp->svp_psd, sensep,
		    vlun->svl_fops_ctpriv);
		switch (rval) {
			/*
			 * Only update path states in case path is definitely
			 * inactive, or no failover occurred.  For all other
			 * check conditions continue pinging.  A unexpected
			 * check condition shouldn't cause pinging to complete
			 * prematurely.
			 */
			case SCSI_SENSE_INACTIVE:
			case SCSI_SENSE_NOFAILOVER:
				updt_paths = 1;
				break;
			default:
				if ((gethrtime() - swarg->svs_tos)
				    >= VHCI_EXTFO_TIMEOUT) {
					swarg->svs_release_lun = 1;
					goto done;
				}
				return (0);
		}
	} else if (*((unsigned char *)statusp) ==
	    STATUS_RESERVATION_CONFLICT) {
		updt_paths = 1;
	} else if ((*((unsigned char *)statusp)) &
	    (STATUS_BUSY | STATUS_QFULL)) {
		return (0);
	}
	if ((*((unsigned char *)statusp) == STATUS_GOOD) ||
	    (updt_paths == 1)) {
		/*
		 * we got here because we had detected an
		 * externally initiated failover; things
		 * have settled down now, so let's
		 * start up a task to update the
		 * path states and target port group
		 */
		vlun->svl_efo_update_path = 1;
		swarg->svs_done = 1;
		vlun->svl_swarg = swarg;
		vlun->svl_flags |= VLUN_UPDATE_TPG;
		(void) taskq_dispatch(vhci->vhci_update_pathstates_taskq,
		    vhci_update_pathstates, (void *)vlun,
		    KM_SLEEP);
		return (0);
	}
	if ((gethrtime() - swarg->svs_tos) >= VHCI_EXTFO_TIMEOUT) {
		swarg->svs_release_lun = 1;
		goto done;
	}
	return (0);
done:
	swarg->svs_done = 1;
	(void) taskq_dispatch(vhci->vhci_taskq,
	    vhci_efo_done, (void *)swarg, KM_SLEEP);
	return (0);
}

/*
 * vhci_efo_done:
 *	cleanly terminates scsi_watch and free up resources.
 *	Called as taskq function in vhci_efo_watch_cb for EFO timeout condition
 *	or by vhci_update_path_states invoked during external initiated
 *	failover completion.
 */
static void
vhci_efo_done(void *arg)
{
	scsi_vhci_lun_t			*vlun;
	scsi_vhci_swarg_t		*swarg = (scsi_vhci_swarg_t *)arg;
	scsi_vhci_priv_t		*svp = swarg->svs_svp;
	ASSERT(svp);

	vlun = svp->svp_svl;
	ASSERT(vlun);

	/* Wait for clean termination of scsi_watch */
	(void) scsi_watch_request_terminate(svp->svp_sw_token,
	    SCSI_WATCH_TERMINATE_ALL_WAIT);
	svp->svp_sw_token = NULL;

	/* release path and freeup resources to indicate failover completion */
	mdi_rele_path(swarg->svs_pi);
	if (swarg->svs_release_lun) {
		VHCI_RELEASE_LUN(vlun);
	}
	kmem_free((void *)swarg, sizeof (*swarg));
}

/*
 * Update the path states
 * vlun should be HELD when this is invoked.
 * Calls vhci_efo_done to cleanup resources allocated for EFO.
 */
void
vhci_update_pathstates(void *arg)
{
	mdi_pathinfo_t			*pip, *npip;
	dev_info_t			*dip;
	struct scsi_failover_ops	*fo;
	struct scsi_vhci_priv		*svp;
	struct scsi_device		*psd;
	struct scsi_path_opinfo		opinfo;
	char				*pclass, *tptr;
	struct scsi_vhci_lun		*vlun = (struct scsi_vhci_lun *)arg;
	int				sps; /* mdi_select_path() status */
	char				*cpath;
	struct scsi_vhci		*vhci;
	struct scsi_pkt			*pkt;
	struct buf			*bp;
	struct scsi_vhci_priv		*svp_conflict = NULL;

	ASSERT(VHCI_LUN_IS_HELD(vlun));
	dip  = vlun->svl_dip;
	pip = npip = NULL;

	vhci = ddi_get_soft_state(vhci_softstate,
	    ddi_get_instance(ddi_get_parent(dip)));

	sps = mdi_select_path(dip, NULL, (MDI_SELECT_ONLINE_PATH |
	    MDI_SELECT_STANDBY_PATH | MDI_SELECT_NO_PREFERRED), NULL, &npip);
	if ((npip == NULL) || (sps != MDI_SUCCESS)) {
		goto done;
	}

	fo = vlun->svl_fops;
	do {
		pip = npip;
		svp = (scsi_vhci_priv_t *)mdi_pi_get_vhci_private(pip);
		psd = svp->svp_psd;
		if (fo->sfo_path_get_opinfo(psd, &opinfo,
		    vlun->svl_fops_ctpriv) != 0) {
			sps = mdi_select_path(dip, NULL,
			    (MDI_SELECT_ONLINE_PATH | MDI_SELECT_STANDBY_PATH |
			    MDI_SELECT_NO_PREFERRED), pip, &npip);
			mdi_rele_path(pip);
			continue;
		}

		if (mdi_prop_lookup_string(pip, "path-class", &pclass) !=
		    MDI_SUCCESS) {
			VHCI_DEBUG(1, (CE_NOTE, NULL,
			    "!vhci_update_pathstates: prop lookup failed for "
			    "path 0x%p\n", (void *)pip));
			sps = mdi_select_path(dip, NULL,
			    (MDI_SELECT_ONLINE_PATH | MDI_SELECT_STANDBY_PATH |
			    MDI_SELECT_NO_PREFERRED), pip, &npip);
			mdi_rele_path(pip);
			continue;
		}

		/*
		 * Need to update the "path-class" property
		 * value in the device tree if different
		 * from the existing value.
		 */
		if (strcmp(pclass, opinfo.opinfo_path_attr) != 0) {
			(void) mdi_prop_update_string(pip, "path-class",
			    opinfo.opinfo_path_attr);
		}

		/*
		 * Only change the state if needed. i.e. Don't call
		 * mdi_pi_set_state to ONLINE a path if its already
		 * ONLINE. Same for STANDBY paths.
		 */

		if ((opinfo.opinfo_path_state == SCSI_PATH_ACTIVE ||
		    opinfo.opinfo_path_state == SCSI_PATH_ACTIVE_NONOPT)) {
			if (!(MDI_PI_IS_ONLINE(pip))) {
				VHCI_DEBUG(1, (CE_NOTE, NULL,
				    "!vhci_update_pathstates: marking path"
				    " 0x%p as ONLINE\n", (void *)pip));
				cpath = kmem_alloc(MAXPATHLEN, KM_SLEEP);
				vhci_log(CE_NOTE, ddi_get_parent(dip), "!%s "
				    "(%s%d): path %s "
				    "is now ONLINE because of "
				    "an externally initiated failover",
				    ddi_pathname(dip, cpath),
				    ddi_driver_name(dip),
				    ddi_get_instance(dip),
				    mdi_pi_spathname(pip));
				kmem_free(cpath, MAXPATHLEN);
				mdi_pi_set_state(pip,
				    MDI_PATHINFO_STATE_ONLINE);
				mdi_pi_set_preferred(pip,
				    opinfo.opinfo_preferred);
				tptr = kmem_alloc(strlen
				    (opinfo.opinfo_path_attr)+1, KM_SLEEP);
				(void) strlcpy(tptr, opinfo.opinfo_path_attr,
				    (strlen(opinfo.opinfo_path_attr)+1));
				mutex_enter(&vlun->svl_mutex);
				if (vlun->svl_active_pclass != NULL) {
					kmem_free(vlun->svl_active_pclass,
					    strlen(vlun->svl_active_pclass)+1);
				}
				vlun->svl_active_pclass = tptr;
				if (vlun->svl_waiting_for_activepath) {
					vlun->svl_waiting_for_activepath = 0;
				}
				mutex_exit(&vlun->svl_mutex);
			} else if (MDI_PI_IS_ONLINE(pip)) {
				if (strcmp(pclass, opinfo.opinfo_path_attr)
				    != 0) {
					mdi_pi_set_preferred(pip,
					    opinfo.opinfo_preferred);
					mutex_enter(&vlun->svl_mutex);
					if (vlun->svl_active_pclass == NULL ||
					    strcmp(opinfo.opinfo_path_attr,
					    vlun->svl_active_pclass) != 0) {
						mutex_exit(&vlun->svl_mutex);
						tptr = kmem_alloc(strlen
						    (opinfo.opinfo_path_attr)+1,
						    KM_SLEEP);
						(void) strlcpy(tptr,
						    opinfo.opinfo_path_attr,
						    (strlen
						    (opinfo.opinfo_path_attr)
						    +1));
						mutex_enter(&vlun->svl_mutex);
					} else {
						/*
						 * No need to update
						 * svl_active_pclass
						 */
						tptr = NULL;
						mutex_exit(&vlun->svl_mutex);
					}
					if (tptr) {
						if (vlun->svl_active_pclass
						    != NULL) {
							kmem_free(vlun->
							    svl_active_pclass,
							    strlen(vlun->
							    svl_active_pclass)
							    +1);
						}
						vlun->svl_active_pclass = tptr;
						mutex_exit(&vlun->svl_mutex);
					}
				}
			}

			/* Check for Reservation Conflict */
			bp = scsi_alloc_consistent_buf(
			    &svp->svp_psd->sd_address, (struct buf *)NULL,
			    DEV_BSIZE, B_READ, NULL, NULL);
			if (!bp) {
				VHCI_DEBUG(1, (CE_NOTE, NULL,
				    "!vhci_update_pathstates: No resources "
				    "(buf)\n"));
				mdi_rele_path(pip);
				goto done;
			}
			pkt = scsi_init_pkt(&svp->svp_psd->sd_address, NULL, bp,
			    CDB_GROUP1, sizeof (struct scsi_arq_status), 0,
			    PKT_CONSISTENT, NULL, NULL);
			if (pkt) {
				(void) scsi_setup_cdb((union scsi_cdb *)
				    (uintptr_t)pkt->pkt_cdbp, SCMD_READ, 1, 1,
				    0);
				pkt->pkt_time = 3*30;
				pkt->pkt_flags = FLAG_NOINTR;
				pkt->pkt_path_instance =
				    mdi_pi_get_path_instance(pip);

				if ((scsi_transport(pkt) == TRAN_ACCEPT) &&
				    (pkt->pkt_reason == CMD_CMPLT) &&
				    (SCBP_C(pkt) ==
				    STATUS_RESERVATION_CONFLICT)) {
					VHCI_DEBUG(1, (CE_NOTE, NULL,
					    "!vhci_update_pathstates: reserv. "
					    "conflict to be resolved on 0x%p\n",
					    (void *)pip));
					svp_conflict = svp;
				}
				scsi_destroy_pkt(pkt);
			}
			scsi_free_consistent_buf(bp);
		} else if ((opinfo.opinfo_path_state == SCSI_PATH_INACTIVE) &&
		    !(MDI_PI_IS_STANDBY(pip))) {
			VHCI_DEBUG(1, (CE_NOTE, NULL,
			    "!vhci_update_pathstates: marking path"
			    " 0x%p as STANDBY\n", (void *)pip));
			cpath = kmem_alloc(MAXPATHLEN, KM_SLEEP);
			vhci_log(CE_NOTE, ddi_get_parent(dip), "!%s "
			    "(%s%d): path %s "
			    "is now STANDBY because of "
			    "an externally initiated failover",
			    ddi_pathname(dip, cpath),
			    ddi_driver_name(dip),
			    ddi_get_instance(dip),
			    mdi_pi_spathname(pip));
			kmem_free(cpath, MAXPATHLEN);
			mdi_pi_set_state(pip,
			    MDI_PATHINFO_STATE_STANDBY);
			mdi_pi_set_preferred(pip,
			    opinfo.opinfo_preferred);
			mutex_enter(&vlun->svl_mutex);
			if (vlun->svl_active_pclass != NULL) {
				if (strcmp(vlun->svl_active_pclass,
				    opinfo.opinfo_path_attr) == 0) {
					kmem_free(vlun->
					    svl_active_pclass,
					    strlen(vlun->
					    svl_active_pclass)+1);
					vlun->svl_active_pclass = NULL;
				}
			}
			mutex_exit(&vlun->svl_mutex);
		}
		(void) mdi_prop_free(pclass);
		sps = mdi_select_path(dip, NULL,
		    (MDI_SELECT_ONLINE_PATH | MDI_SELECT_STANDBY_PATH |
		    MDI_SELECT_NO_PREFERRED), pip, &npip);
		mdi_rele_path(pip);

	} while ((npip != NULL) && (sps == MDI_SUCCESS));

	/*
	 * Check to see if this vlun has an active SCSI-II RESERVE.  If so
	 * clear the reservation by sending a reset, so the host doesn't
	 * receive a reservation conflict.  The reset has to be sent via a
	 * working path.  Let's use a path referred to by svp_conflict as it
	 * should be working.
	 * Reset VLUN_RESERVE_ACTIVE_FLG for this vlun.  Also notify ssd
	 * of the reset, explicitly.
	 */
	if (vlun->svl_flags & VLUN_RESERVE_ACTIVE_FLG) {
		if (svp_conflict && (vlun->svl_xlf_capable == 0)) {
			VHCI_DEBUG(1, (CE_NOTE, NULL, "!vhci_update_pathstates:"
			    " sending recovery reset on 0x%p, path_state: %x",
			    svp_conflict->svp_psd->sd_private,
			    mdi_pi_get_state((mdi_pathinfo_t *)
			    svp_conflict->svp_psd->sd_private)));

			(void) vhci_recovery_reset(vlun,
			    &svp_conflict->svp_psd->sd_address, FALSE,
			    VHCI_DEPTH_TARGET);
		}
		vlun->svl_flags &= ~VLUN_RESERVE_ACTIVE_FLG;
		mutex_enter(&vhci->vhci_mutex);
		scsi_hba_reset_notify_callback(&vhci->vhci_mutex,
		    &vhci->vhci_reset_notify_listf);
		mutex_exit(&vhci->vhci_mutex);
	}
	if (vlun->svl_flags & VLUN_UPDATE_TPG) {
		/*
		 * Update the AccessState of related MP-API TPGs
		 */
		(void) vhci_mpapi_update_tpg_acc_state_for_lu(vhci, vlun);
		vlun->svl_flags &= ~VLUN_UPDATE_TPG;
	}
done:
	if (vlun->svl_efo_update_path) {
		vlun->svl_efo_update_path = 0;
		vhci_efo_done(vlun->svl_swarg);
		vlun->svl_swarg = 0;
	}
	VHCI_RELEASE_LUN(vlun);
}

/* ARGSUSED */
static int
vhci_pathinfo_init(dev_info_t *vdip, mdi_pathinfo_t *pip, int flags)
{
	scsi_hba_tran_t		*hba = NULL;
	struct scsi_device	*psd = NULL;
	scsi_vhci_lun_t		*vlun = NULL;
	dev_info_t		*pdip = NULL;
	dev_info_t		*tgt_dip;
	struct scsi_vhci	*vhci;
	char			*guid;
	scsi_vhci_priv_t	*svp = NULL;
	int			rval = MDI_FAILURE;
	int			vlun_alloced = 0;

	ASSERT(vdip != NULL);
	ASSERT(pip != NULL);

	vhci = ddi_get_soft_state(vhci_softstate, ddi_get_instance(vdip));
	ASSERT(vhci != NULL);

	pdip = mdi_pi_get_phci(pip);
	ASSERT(pdip != NULL);

	hba = ddi_get_driver_private(pdip);
	ASSERT(hba != NULL);

	tgt_dip = mdi_pi_get_client(pip);
	ASSERT(tgt_dip != NULL);

	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, tgt_dip, PROPFLAGS,
	    MDI_CLIENT_GUID_PROP, &guid) != DDI_SUCCESS) {
		VHCI_DEBUG(1, (CE_WARN, NULL,
		    "vhci_pathinfo_init: lun guid property failed"));
		goto failure;
	}

	vlun = vhci_lun_lookup_alloc(tgt_dip, guid, &vlun_alloced);
	ddi_prop_free(guid);

	vlun->svl_dip = tgt_dip;

	svp = kmem_zalloc(sizeof (*svp), KM_SLEEP);
	svp->svp_svl = vlun;

	/*
	 * Initialize svl_lb_policy_save only for newly allocated vlun. Writing
	 * to svl_lb_policy_save later could accidentally overwrite saved lb
	 * policy.
	 */
	if (vlun_alloced) {
		vlun->svl_lb_policy_save = mdi_get_lb_policy(tgt_dip);
	}

	mutex_init(&svp->svp_mutex, NULL, MUTEX_DRIVER, NULL);
	cv_init(&svp->svp_cv, NULL, CV_DRIVER, NULL);

	psd = kmem_zalloc(sizeof (*psd), KM_SLEEP);
	mutex_init(&psd->sd_mutex, NULL, MUTEX_DRIVER, NULL);

	if (hba->tran_hba_flags & SCSI_HBA_ADDR_COMPLEX) {
		/*
		 * For a SCSI_HBA_ADDR_COMPLEX transport we store a pointer to
		 * scsi_device in the scsi_address structure.  This allows an
		 * an HBA driver to find its scsi_device(9S) and
		 * per-scsi_device(9S) HBA private data given a
		 * scsi_address(9S) by using scsi_address_device(9F) and
		 * scsi_device_hba_private_get(9F)).
		 */
		psd->sd_address.a.a_sd = psd;
	} else if (hba->tran_hba_flags & SCSI_HBA_TRAN_CLONE) {
		/*
		 * Clone transport structure if requested, so
		 * Self enumerating HBAs always need to use cloning
		 */
		scsi_hba_tran_t	*clone =
		    kmem_alloc(sizeof (scsi_hba_tran_t), KM_SLEEP);
		bcopy(hba, clone, sizeof (scsi_hba_tran_t));
		hba = clone;
		hba->tran_sd = psd;
	} else {
		/*
		 * SPI pHCI unit-address. If we ever need to support this
		 * we could set a.spi.a_target/a.spi.a_lun based on pathinfo
		 * node unit-address properties.  For now we fail...
		 */
		goto failure;
	}

	psd->sd_dev = tgt_dip;
	psd->sd_address.a_hba_tran = hba;

	/*
	 * Mark scsi_device as being associated with a pathinfo node. For
	 * a scsi_device structure associated with a devinfo node,
	 * scsi_ctlops_initchild sets this field to NULL.
	 */
	psd->sd_pathinfo = pip;

	/*
	 * LEGACY: sd_private: set for older mpxio-capable pHCI drivers with
	 * too much scsi_vhci/mdi/ndi knowledge. Remove this code when all
	 * mpxio-capable pHCI drivers use SCSA enumeration services (or at
	 * least have been changed to use sd_pathinfo instead).
	 */
	psd->sd_private = (caddr_t)pip;

	/* See scsi_hba.c for info on sd_tran_safe kludge */
	psd->sd_tran_safe = hba;

	svp->svp_psd = psd;
	mdi_pi_set_vhci_private(pip, (caddr_t)svp);

	/*
	 * call hba's target init entry point if it exists
	 */
	if (hba->tran_tgt_init != NULL) {
		psd->sd_tran_tgt_free_done = 0;
		if ((rval = (*hba->tran_tgt_init)(pdip, tgt_dip,
		    hba, psd)) != DDI_SUCCESS) {
			VHCI_DEBUG(1, (CE_WARN, pdip,
			    "!vhci_pathinfo_init: tran_tgt_init failed for "
			    "path=0x%p rval=%x", (void *)pip, rval));
			goto failure;
		}
	}

	svp->svp_new_path = 1;

	VHCI_DEBUG(4, (CE_NOTE, NULL, "!vhci_pathinfo_init: path:%p\n",
	    (void *)pip));
	return (MDI_SUCCESS);

failure:
	if (psd) {
		mutex_destroy(&psd->sd_mutex);
		kmem_free(psd, sizeof (*psd));
	}
	if (svp) {
		mdi_pi_set_vhci_private(pip, NULL);
		mutex_destroy(&svp->svp_mutex);
		cv_destroy(&svp->svp_cv);
		kmem_free(svp, sizeof (*svp));
	}
	if (hba && (hba->tran_hba_flags & SCSI_HBA_TRAN_CLONE))
		kmem_free(hba, sizeof (scsi_hba_tran_t));

	if (vlun_alloced)
		vhci_lun_free(vlun, NULL);

	return (rval);
}

/* ARGSUSED */
static int
vhci_pathinfo_uninit(dev_info_t *vdip, mdi_pathinfo_t *pip, int flags)
{
	scsi_hba_tran_t		*hba = NULL;
	struct scsi_device	*psd = NULL;
	dev_info_t		*pdip = NULL;
	dev_info_t		*cdip = NULL;
	scsi_vhci_priv_t	*svp = NULL;

	ASSERT(vdip != NULL);
	ASSERT(pip != NULL);

	pdip = mdi_pi_get_phci(pip);
	ASSERT(pdip != NULL);

	cdip = mdi_pi_get_client(pip);
	ASSERT(cdip != NULL);

	hba = ddi_get_driver_private(pdip);
	ASSERT(hba != NULL);

	vhci_mpapi_set_path_state(vdip, pip, MP_DRVR_PATH_STATE_UNINIT);
	svp = (scsi_vhci_priv_t *)mdi_pi_get_vhci_private(pip);
	if (svp == NULL) {
		/* path already freed. Nothing to do. */
		return (MDI_SUCCESS);
	}

	psd = svp->svp_psd;
	ASSERT(psd != NULL);

	if (hba->tran_hba_flags & SCSI_HBA_ADDR_COMPLEX) {
		/* Verify plumbing */
		ASSERT(psd->sd_address.a_hba_tran == hba);
		ASSERT(psd->sd_address.a.a_sd == psd);
	} else if (hba->tran_hba_flags & SCSI_HBA_TRAN_CLONE) {
		/* Switch to cloned scsi_hba_tran(9S) structure */
		hba = psd->sd_address.a_hba_tran;
		ASSERT(hba->tran_hba_flags & SCSI_HBA_TRAN_CLONE);
		ASSERT(hba->tran_sd == psd);
	}

	if ((hba->tran_tgt_free != NULL) && !psd->sd_tran_tgt_free_done) {
		(*hba->tran_tgt_free) (pdip, cdip, hba, psd);
		psd->sd_tran_tgt_free_done = 1;
	}
	mutex_destroy(&psd->sd_mutex);
	if (hba->tran_hba_flags & SCSI_HBA_TRAN_CLONE) {
		kmem_free(hba, sizeof (*hba));
	}

	mdi_pi_set_vhci_private(pip, NULL);

	/*
	 * Free the pathinfo related scsi_device inquiry data. Note that this
	 * matches what happens for scsi_hba.c devinfo case at uninitchild time.
	 */
	if (psd->sd_inq)
		kmem_free((caddr_t)psd->sd_inq, sizeof (struct scsi_inquiry));
	kmem_free((caddr_t)psd, sizeof (*psd));

	mutex_destroy(&svp->svp_mutex);
	cv_destroy(&svp->svp_cv);
	kmem_free((caddr_t)svp, sizeof (*svp));

	VHCI_DEBUG(4, (CE_NOTE, NULL, "!vhci_pathinfo_uninit: path=0x%p\n",
	    (void *)pip));
	return (MDI_SUCCESS);
}

/* ARGSUSED */
static int
vhci_pathinfo_state_change(dev_info_t *vdip, mdi_pathinfo_t *pip,
    mdi_pathinfo_state_t state, uint32_t ext_state, int flags)
{
	int			rval = MDI_SUCCESS;
	scsi_vhci_priv_t	*svp;
	scsi_vhci_lun_t		*vlun;
	int			held;
	int			op = (flags & 0xf00) >> 8;
	struct scsi_vhci	*vhci;

	vhci = ddi_get_soft_state(vhci_softstate, ddi_get_instance(vdip));

	if (flags & MDI_EXT_STATE_CHANGE) {
		/*
		 * We do not want to issue any commands down the path in case
		 * sync flag is set. Lower layers might not be ready to accept
		 * any I/O commands.
		 */
		if (op == DRIVER_DISABLE)
			return (MDI_SUCCESS);

		svp = (scsi_vhci_priv_t *)mdi_pi_get_vhci_private(pip);
		if (svp == NULL) {
			return (MDI_FAILURE);
		}
		vlun = svp->svp_svl;

		if (flags & MDI_BEFORE_STATE_CHANGE) {
			/*
			 * Hold the LUN.
			 */
			VHCI_HOLD_LUN(vlun, VH_SLEEP, held);
			if (flags & MDI_DISABLE_OP)  {
				/*
				 * Issue scsi reset if it happens to be
				 * reserved path.
				 */
				if (vlun->svl_flags & VLUN_RESERVE_ACTIVE_FLG) {
					/*
					 * if reservation pending on
					 * this path, dont' mark the
					 * path busy
					 */
					if (op == DRIVER_DISABLE_TRANSIENT) {
						VHCI_DEBUG(1, (CE_NOTE, NULL,
						    "!vhci_pathinfo"
						    "_state_change (pip:%p): "
						    " reservation: fail busy\n",
						    (void *)pip));
						return (MDI_FAILURE);
					}
					if (pip == vlun->svl_resrv_pip) {
						if (vhci_recovery_reset(
						    svp->svp_svl,
						    &svp->svp_psd->sd_address,
						    TRUE,
						    VHCI_DEPTH_TARGET) == 0) {
							VHCI_DEBUG(1,
							    (CE_NOTE, NULL,
							    "!vhci_pathinfo"
							    "_state_change "
							    " (pip:%p): "
							    "reset failed, "
							    "give up!\n",
							    (void *)pip));
						}
						vlun->svl_flags &=
						    ~VLUN_RESERVE_ACTIVE_FLG;
					}
				}
			} else if (flags & MDI_ENABLE_OP)  {
				if (((vhci->vhci_conf_flags &
				    VHCI_CONF_FLAGS_AUTO_FAILBACK) ==
				    VHCI_CONF_FLAGS_AUTO_FAILBACK) &&
				    MDI_PI_IS_USER_DISABLE(pip) &&
				    MDI_PI_IS_STANDBY(pip)) {
					struct scsi_failover_ops	*fo;
					char *best_pclass, *pclass = NULL;
					int  best_class, rv;
					/*
					 * Failback if enabling a standby path
					 * and it is the primary class or
					 * preferred class
					 */
					best_class = mdi_pi_get_preferred(pip);
					if (best_class == 0) {
						/*
						 * if not preferred - compare
						 * path-class with class
						 */
						fo = vlun->svl_fops;
						(void) fo->sfo_pathclass_next(
						    NULL, &best_pclass,
						    vlun->svl_fops_ctpriv);
						pclass = NULL;
						rv = mdi_prop_lookup_string(pip,
						    "path-class", &pclass);
						if (rv != MDI_SUCCESS ||
						    pclass == NULL) {
							vhci_log(CE_NOTE, vdip,
							    "!path-class "
							    " lookup "
							    "failed. rv: %d"
							    "class: %p", rv,
							    (void *)pclass);
						} else if (strncmp(pclass,
						    best_pclass,
						    strlen(best_pclass)) == 0) {
							best_class = 1;
						}
						if (rv == MDI_SUCCESS &&
						    pclass != NULL) {
							rv = mdi_prop_free(
							    pclass);
							if (rv !=
							    DDI_PROP_SUCCESS) {
								vhci_log(
								    CE_NOTE,
								    vdip,
								    "!path-"
								    "class"
								    " free"
								    " failed"
								    " rv: %d"
								    " class: "
								    "%p",
								    rv,
								    (void *)
								    pclass);
							}
						}
					}
					if (best_class == 1) {
						VHCI_DEBUG(1, (CE_NOTE, NULL,
						    "preferred path: %p "
						    "USER_DISABLE->USER_ENABLE "
						    "transition for lun %s\n",
						    (void *)pip,
						    vlun->svl_lun_wwn));
						(void) taskq_dispatch(
						    vhci->vhci_taskq,
						    vhci_initiate_auto_failback,
						    (void *) vlun, KM_SLEEP);
					}
				}
				/*
				 * if PGR is active, revalidate key and
				 * register on this path also, if key is
				 * still valid
				 */
				sema_p(&vlun->svl_pgr_sema);
				if (vlun->svl_pgr_active)
					(void)
					    vhci_pgr_validate_and_register(svp);
				sema_v(&vlun->svl_pgr_sema);
				/*
				 * Inform target driver about any
				 * reservations to be reinstated if target
				 * has dropped reservation during the busy
				 * period.
				 */
				mutex_enter(&vhci->vhci_mutex);
				scsi_hba_reset_notify_callback(
				    &vhci->vhci_mutex,
				    &vhci->vhci_reset_notify_listf);
				mutex_exit(&vhci->vhci_mutex);
			}
		}
		if (flags & MDI_AFTER_STATE_CHANGE) {
			if (flags & MDI_ENABLE_OP)  {
				mutex_enter(&vhci_global_mutex);
				cv_broadcast(&vhci_cv);
				mutex_exit(&vhci_global_mutex);
			}
			if (vlun->svl_setcap_done) {
				(void) vhci_pHCI_cap(&svp->svp_psd->sd_address,
				    "sector-size", vlun->svl_sector_size,
				    1, pip);
			}

			/*
			 * Release the LUN
			 */
			VHCI_RELEASE_LUN(vlun);

			/*
			 * Path transition is complete.
			 * Run callback to indicate target driver to
			 * retry to prevent IO starvation.
			 */
			if (scsi_callback_id != 0) {
				ddi_run_callback(&scsi_callback_id);
			}
		}
	} else {
		switch (state) {
		case MDI_PATHINFO_STATE_ONLINE:
			rval = vhci_pathinfo_online(vdip, pip, flags);
			break;

		case MDI_PATHINFO_STATE_OFFLINE:
			rval = vhci_pathinfo_offline(vdip, pip, flags);
			break;

		default:
			break;
		}
		/*
		 * Path transition is complete.
		 * Run callback to indicate target driver to
		 * retry to prevent IO starvation.
		 */
		if ((rval == MDI_SUCCESS) && (scsi_callback_id != 0)) {
			ddi_run_callback(&scsi_callback_id);
		}
		return (rval);
	}

	return (MDI_SUCCESS);
}

/*
 * Parse the mpxio load balancing options. The datanameptr
 * will point to a string containing the load-balance-options value.
 * The load-balance-options value will be a property that
 * defines the load-balance algorithm and any arguments to that
 * algorithm.
 * For example:
 * device-type-mpxio-options-list=
 * "device-type=SUN    SENA", "load-balance-options=logical-block-options"
 * "device-type=SUN     SE6920", "round-robin-options";
 * logical-block-options="load-balance=logical-block", "region-size=15";
 * round-robin-options="load-balance=round-robin";
 *
 * If the load-balance is not defined the load balance algorithm will
 * default to the global setting. There will be default values assigned
 * to the arguments (region-size=18) and if an argument is one
 * that is not known, it will be ignored.
 */
static void
vhci_parse_mpxio_lb_options(dev_info_t *dip, dev_info_t *cdip,
	caddr_t datanameptr)
{
	char			*dataptr, *next_entry;
	caddr_t			config_list	= NULL;
	int			config_list_len = 0, list_len = 0;
	int			region_size = -1;
	client_lb_t		load_balance;

	if (ddi_getlongprop(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS, datanameptr,
	    (caddr_t)&config_list, &config_list_len) != DDI_PROP_SUCCESS) {
		return;
	}

	list_len = config_list_len;
	next_entry = config_list;
	while (config_list_len > 0) {
		dataptr = next_entry;

		if (strncmp(mdi_load_balance, dataptr,
		    strlen(mdi_load_balance)) == 0) {
			/* get the load-balance scheme */
			dataptr += strlen(mdi_load_balance) + 1;
			if (strcmp(dataptr, LOAD_BALANCE_PROP_RR) == 0) {
				(void) mdi_set_lb_policy(cdip, LOAD_BALANCE_RR);
				load_balance = LOAD_BALANCE_RR;
			} else if (strcmp(dataptr,
			    LOAD_BALANCE_PROP_LBA) == 0) {
				(void) mdi_set_lb_policy(cdip,
				    LOAD_BALANCE_LBA);
				load_balance = LOAD_BALANCE_LBA;
			} else if (strcmp(dataptr,
			    LOAD_BALANCE_PROP_NONE) == 0) {
				(void) mdi_set_lb_policy(cdip,
				    LOAD_BALANCE_NONE);
				load_balance = LOAD_BALANCE_NONE;
			}
		} else if (strncmp(dataptr, LOGICAL_BLOCK_REGION_SIZE,
		    strlen(LOGICAL_BLOCK_REGION_SIZE)) == 0) {
			int	i = 0;
			char	*ptr;
			char	*tmp;

			tmp = dataptr + (strlen(LOGICAL_BLOCK_REGION_SIZE) + 1);
			/* check for numeric value */
			for (ptr = tmp; i < strlen(tmp); i++, ptr++) {
				if (!isdigit(*ptr)) {
					cmn_err(CE_WARN,
					    "Illegal region size: %s."
					    " Setting to default value: %d",
					    tmp,
					    LOAD_BALANCE_DEFAULT_REGION_SIZE);
					region_size =
					    LOAD_BALANCE_DEFAULT_REGION_SIZE;
					break;
				}
			}
			if (i >= strlen(tmp)) {
				region_size = stoi(&tmp);
			}
			(void) mdi_set_lb_region_size(cdip, region_size);
		}
		config_list_len -= (strlen(next_entry) + 1);
		next_entry += strlen(next_entry) + 1;
	}
#ifdef DEBUG
	if ((region_size >= 0) && (load_balance != LOAD_BALANCE_LBA)) {
		VHCI_DEBUG(1, (CE_NOTE, dip,
		    "!vhci_parse_mpxio_lb_options: region-size: %d"
		    "only valid for load-balance=logical-block\n",
		    region_size));
	}
#endif
	if ((region_size == -1) && (load_balance == LOAD_BALANCE_LBA)) {
		VHCI_DEBUG(1, (CE_NOTE, dip,
		    "!vhci_parse_mpxio_lb_options: No region-size"
		    " defined load-balance=logical-block."
		    " Default to: %d\n", LOAD_BALANCE_DEFAULT_REGION_SIZE));
		(void) mdi_set_lb_region_size(cdip,
		    LOAD_BALANCE_DEFAULT_REGION_SIZE);
	}
	if (list_len > 0) {
		kmem_free(config_list, list_len);
	}
}

/*
 * Parse the device-type-mpxio-options-list looking for the key of
 * "load-balance-options". If found, parse the load balancing options.
 * Check the comment of the vhci_get_device_type_mpxio_options()
 * for the device-type-mpxio-options-list.
 */
static void
vhci_parse_mpxio_options(dev_info_t *dip, dev_info_t *cdip,
		caddr_t datanameptr, int list_len)
{
	char		*dataptr;
	int		len;

	/*
	 * get the data list
	 */
	dataptr = datanameptr;
	len = 0;
	while (len < list_len &&
	    strncmp(dataptr, DEVICE_TYPE_STR, strlen(DEVICE_TYPE_STR))
	    != 0) {
		if (strncmp(dataptr, LOAD_BALANCE_OPTIONS,
		    strlen(LOAD_BALANCE_OPTIONS)) == 0) {
			len += strlen(LOAD_BALANCE_OPTIONS) + 1;
			dataptr += strlen(LOAD_BALANCE_OPTIONS) + 1;
			vhci_parse_mpxio_lb_options(dip, cdip, dataptr);
		}
		len += strlen(dataptr) + 1;
		dataptr += strlen(dataptr) + 1;
	}
}

/*
 * Check the inquriy string returned from the device with the device-type
 * Check for the existence of the device-type-mpxio-options-list and
 * if found parse the list checking for a match with the device-type
 * value and the inquiry string returned from the device. If a match
 * is found, parse the mpxio options list. The format of the
 * device-type-mpxio-options-list is:
 * device-type-mpxio-options-list=
 * "device-type=SUN    SENA", "load-balance-options=logical-block-options"
 * "device-type=SUN     SE6920", "round-robin-options";
 * logical-block-options="load-balance=logical-block", "region-size=15";
 * round-robin-options="load-balance=round-robin";
 */
void
vhci_get_device_type_mpxio_options(dev_info_t *dip, dev_info_t *cdip,
	struct scsi_device *devp)
{

	caddr_t			config_list	= NULL;
	caddr_t			vidptr, datanameptr;
	int			vidlen, dupletlen = 0;
	int			config_list_len = 0, len;
	struct scsi_inquiry	*inq = devp->sd_inq;

	/*
	 * look up the device-type-mpxio-options-list and walk thru
	 * the list compare the vendor ids of the earlier inquiry command and
	 * with those vids in the list if there is a match, lookup
	 * the mpxio-options value
	 */
	if (ddi_getlongprop(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    MPXIO_OPTIONS_LIST,
	    (caddr_t)&config_list, &config_list_len) == DDI_PROP_SUCCESS) {

		/*
		 * Compare vids in each duplet - if it matches,
		 * parse the mpxio options list.
		 */
		for (len = config_list_len, vidptr = config_list; len > 0;
		    len -= dupletlen) {

			dupletlen = 0;

			if (strlen(vidptr) != 0 &&
			    strncmp(vidptr, DEVICE_TYPE_STR,
			    strlen(DEVICE_TYPE_STR)) == 0) {
				/* point to next duplet */
				datanameptr = vidptr + strlen(vidptr) + 1;
				/* add len of this duplet */
				dupletlen += strlen(vidptr) + 1;
				/* get to device type */
				vidptr += strlen(DEVICE_TYPE_STR) + 1;
				vidlen = strlen(vidptr);
				if ((vidlen != 0) &&
				    bcmp(inq->inq_vid, vidptr, vidlen) == 0) {
					vhci_parse_mpxio_options(dip, cdip,
					    datanameptr, len - dupletlen);
					break;
				}
				/* get to next duplet */
				vidptr += strlen(vidptr) + 1;
			}
			/* get to the next device-type */
			while (len - dupletlen > 0 &&
			    strlen(vidptr) != 0 &&
			    strncmp(vidptr, DEVICE_TYPE_STR,
			    strlen(DEVICE_TYPE_STR)) != 0) {
				dupletlen += strlen(vidptr) + 1;
				vidptr += strlen(vidptr) + 1;
			}
		}
		if (config_list_len > 0) {
			kmem_free(config_list, config_list_len);
		}
	}
}

static int
vhci_update_pathinfo(struct scsi_device *psd,  mdi_pathinfo_t *pip,
	struct scsi_failover_ops *fo,
	scsi_vhci_lun_t		*vlun,
	struct scsi_vhci	*vhci)
{
	struct scsi_path_opinfo		opinfo;
	char				*pclass, *best_pclass;
	char				*resrv_pclass = NULL;
	int				force_rereserve = 0;
	int				update_pathinfo_done = 0;

	if (fo->sfo_path_get_opinfo(psd, &opinfo, vlun->svl_fops_ctpriv) != 0) {
		VHCI_DEBUG(1, (CE_NOTE, NULL, "!vhci_update_pathinfo: "
		    "Failed to get operation info for path:%p\n", (void *)pip));
		return (MDI_FAILURE);
	}
	/* set the xlf capable flag in the vlun for future use */
	vlun->svl_xlf_capable = opinfo.opinfo_xlf_capable;
	(void) mdi_prop_update_string(pip, "path-class",
	    opinfo.opinfo_path_attr);

	pclass = opinfo.opinfo_path_attr;
	if (opinfo.opinfo_path_state == SCSI_PATH_ACTIVE) {
		mutex_enter(&vlun->svl_mutex);
		if (vlun->svl_active_pclass != NULL) {
			if (strcmp(vlun->svl_active_pclass, pclass) != 0) {
				mutex_exit(&vlun->svl_mutex);
				/*
				 * Externally initiated failover has happened;
				 * force the path state to be STANDBY/ONLINE,
				 * next IO will trigger failover and thus
				 * sync-up the pathstates.  Reason we don't
				 * sync-up immediately by invoking
				 * vhci_update_pathstates() is because it
				 * needs a VHCI_HOLD_LUN() and we don't
				 * want to block here.
				 *
				 * Further, if the device is an ALUA device,
				 * then failure to exactly match 'pclass' and
				 * 'svl_active_pclass'(as is the case here)
				 * indicates that the currently active path
				 * is a 'non-optimized' path - which means
				 * that 'svl_active_pclass' needs to be
				 * replaced with opinfo.opinfo_path_state
				 * value.
				 */

				if (SCSI_FAILOVER_IS_TPGS(vlun->svl_fops)) {
					char	*tptr;

					/*
					 * The device is ALUA compliant. The
					 * state need to be changed to online
					 * rather than standby state which is
					 * done typically for a asymmetric
					 * device that is non ALUA compliant.
					 */
					mdi_pi_set_state(pip,
					    MDI_PATHINFO_STATE_ONLINE);
					tptr = kmem_alloc(strlen
					    (opinfo.opinfo_path_attr)+1,
					    KM_SLEEP);
					(void) strlcpy(tptr,
					    opinfo.opinfo_path_attr,
					    (strlen(opinfo.opinfo_path_attr)
					    +1));
					mutex_enter(&vlun->svl_mutex);
					kmem_free(vlun->svl_active_pclass,
					    strlen(vlun->svl_active_pclass)+1);
					vlun->svl_active_pclass = tptr;
					mutex_exit(&vlun->svl_mutex);
				} else {
					/*
					 * Non ALUA device case.
					 */
					mdi_pi_set_state(pip,
					    MDI_PATHINFO_STATE_STANDBY);
				}
				vlun->svl_fo_support = opinfo.opinfo_mode;
				mdi_pi_set_preferred(pip,
				    opinfo.opinfo_preferred);
				update_pathinfo_done = 1;
			}

			/*
			 * Find out a class of currently reserved path if there
			 * is any.
			 */
			if ((vlun->svl_flags & VLUN_RESERVE_ACTIVE_FLG) &&
			    mdi_prop_lookup_string(vlun->svl_resrv_pip,
			    "path-class", &resrv_pclass) != MDI_SUCCESS) {
				VHCI_DEBUG(1, (CE_NOTE, NULL,
				    "!vhci_update_pathinfo: prop lookup "
				    "failed for path 0x%p\n",
				    (void *)vlun->svl_resrv_pip));
				/*
				 * Something is wrong with the reserved path.
				 * We can't do much with that right here. Just
				 * force re-reservation to another path.
				 */
				force_rereserve = 1;
			}

			(void) fo->sfo_pathclass_next(NULL, &best_pclass,
			    vlun->svl_fops_ctpriv);
			if ((force_rereserve == 1) || ((resrv_pclass != NULL) &&
			    (strcmp(pclass, best_pclass) == 0) &&
			    (strcmp(resrv_pclass, best_pclass) != 0))) {
				/*
				 * Inform target driver that a reservation
				 * should be reinstated because the reserved
				 * path is not the most preferred one.
				 */
				mutex_enter(&vhci->vhci_mutex);
				scsi_hba_reset_notify_callback(
				    &vhci->vhci_mutex,
				    &vhci->vhci_reset_notify_listf);
				mutex_exit(&vhci->vhci_mutex);
			}

			if (update_pathinfo_done == 1) {
				return (MDI_SUCCESS);
			}
		} else {
			char	*tptr;

			/*
			 * lets release the mutex before we try to
			 * allocate since the potential to sleep is
			 * possible.
			 */
			mutex_exit(&vlun->svl_mutex);
			tptr = kmem_alloc(strlen(pclass)+1, KM_SLEEP);
			(void) strlcpy(tptr, pclass, (strlen(pclass)+1));
			mutex_enter(&vlun->svl_mutex);
			vlun->svl_active_pclass = tptr;
		}
		mutex_exit(&vlun->svl_mutex);
		mdi_pi_set_state(pip, MDI_PATHINFO_STATE_ONLINE);
		vlun->svl_waiting_for_activepath = 0;
	} else if (opinfo.opinfo_path_state == SCSI_PATH_ACTIVE_NONOPT) {
		mutex_enter(&vlun->svl_mutex);
		if (vlun->svl_active_pclass == NULL) {
			char	*tptr;

			mutex_exit(&vlun->svl_mutex);
			tptr = kmem_alloc(strlen(pclass)+1, KM_SLEEP);
			(void) strlcpy(tptr, pclass, (strlen(pclass)+1));
			mutex_enter(&vlun->svl_mutex);
			vlun->svl_active_pclass = tptr;
		}
		mutex_exit(&vlun->svl_mutex);
		mdi_pi_set_state(pip, MDI_PATHINFO_STATE_ONLINE);
		vlun->svl_waiting_for_activepath = 0;
	} else if (opinfo.opinfo_path_state == SCSI_PATH_INACTIVE) {
		mutex_enter(&vlun->svl_mutex);
		if (vlun->svl_active_pclass != NULL) {
			if (strcmp(vlun->svl_active_pclass, pclass) == 0) {
				mutex_exit(&vlun->svl_mutex);
				/*
				 * externally initiated failover has happened;
				 * force state to ONLINE (see comment above)
				 */
				mdi_pi_set_state(pip,
				    MDI_PATHINFO_STATE_ONLINE);
				vlun->svl_fo_support = opinfo.opinfo_mode;
				mdi_pi_set_preferred(pip,
				    opinfo.opinfo_preferred);
				return (MDI_SUCCESS);
			}
		}
		mutex_exit(&vlun->svl_mutex);
		mdi_pi_set_state(pip, MDI_PATHINFO_STATE_STANDBY);

		/*
		 * Initiate auto-failback, if enabled, for path if path-state
		 * is transitioning from OFFLINE->STANDBY and pathclass is the
		 * preferred pathclass for this storage.
		 * NOTE: In case where opinfo_path_state is SCSI_PATH_ACTIVE
		 * (above), where the pi state is set to STANDBY, we don't
		 * initiate auto-failback as the next IO shall take care of.
		 * this. See comment above.
		 */
		(void) fo->sfo_pathclass_next(NULL, &best_pclass,
		    vlun->svl_fops_ctpriv);
		if (((vhci->vhci_conf_flags & VHCI_CONF_FLAGS_AUTO_FAILBACK) ==
		    VHCI_CONF_FLAGS_AUTO_FAILBACK) &&
		    (strcmp(pclass, best_pclass) == 0) &&
		    ((MDI_PI_OLD_STATE(pip) == MDI_PATHINFO_STATE_OFFLINE)||
		    (MDI_PI_OLD_STATE(pip) == MDI_PATHINFO_STATE_INIT))) {
			VHCI_DEBUG(1, (CE_NOTE, NULL, "%s pathclass path: %p"
			    " OFFLINE->STANDBY transition for lun %s\n",
			    best_pclass, (void *)pip, vlun->svl_lun_wwn));
			(void) taskq_dispatch(vhci->vhci_taskq,
			    vhci_initiate_auto_failback, (void *) vlun,
			    KM_SLEEP);
		}
	}
	vlun->svl_fo_support = opinfo.opinfo_mode;
	mdi_pi_set_preferred(pip, opinfo.opinfo_preferred);

	VHCI_DEBUG(8, (CE_NOTE, NULL, "vhci_update_pathinfo: opinfo_rev = %x,"
	    " opinfo_path_state = %x opinfo_preferred = %x, opinfo_mode = %x\n",
	    opinfo.opinfo_rev, opinfo.opinfo_path_state,
	    opinfo.opinfo_preferred, opinfo.opinfo_mode));

	return (MDI_SUCCESS);
}

/*
 * Form the kstat name and and call mdi_pi_kstat_create()
 */
void
vhci_kstat_create_pathinfo(mdi_pathinfo_t *pip)
{
	dev_info_t	*tgt_dip;
	dev_info_t	*pdip;
	char		*guid;
	char		*target_port, *target_port_dup;
	char		ks_name[KSTAT_STRLEN];
	uint_t		pid;
	int		by_id;
	mod_hash_val_t	hv;


	/* return if we have already allocated kstats */
	if (mdi_pi_kstat_exists(pip))
		return;

	/*
	 * We need instance numbers to create a kstat name, return if we don't
	 * have instance numbers assigned yet.
	 */
	tgt_dip = mdi_pi_get_client(pip);
	pdip = mdi_pi_get_phci(pip);
	if ((ddi_get_instance(tgt_dip) == -1) || (ddi_get_instance(pdip) == -1))
		return;

	/*
	 * A path oriented kstat has a ks_name of the form:
	 *
	 * <client-driver><instance>.t<pid>.<pHCI-driver><instance>
	 *
	 * We maintain a bidirectional 'target-port' to <pid> map,
	 * called targetmap. All pathinfo nodes with the same
	 * 'target-port' map to the same <pid>. The iostat(1M) code,
	 * when parsing a path oriented kstat name, uses the <pid> as
	 * a SCSI_VHCI_GET_TARGET_LONGNAME ioctl argument in order
	 * to get the 'target-port'. For KSTAT_FLAG_PERSISTENT kstats,
	 * this ioctl needs to translate a <pid> to a 'target-port'
	 * even after all pathinfo nodes associated with the
	 * 'target-port' have been destroyed. This is needed to support
	 * consistent first-iteration activity-since-boot iostat(1M)
	 * output. Because of this requirement, the mapping can't be
	 * based on pathinfo information in a devinfo snapshot.
	 */

	/* determine 'target-port' */
	if (mdi_prop_lookup_string(pip,
	    SCSI_ADDR_PROP_TARGET_PORT, &target_port) == MDI_SUCCESS) {
		target_port_dup = i_ddi_strdup(target_port, KM_SLEEP);
		(void) mdi_prop_free(target_port);
		by_id = 1;
	} else {
		/*
		 * If the pHCI did not set up 'target-port' on this
		 * pathinfo node, assume that our client is the only
		 * one with paths to the device by using the guid
		 * value as the 'target-port'. Since no other client
		 * will have the same guid, no other client will use
		 * the same <pid>.  NOTE: a client with an instance
		 * number always has a guid.
		 */
		(void) ddi_prop_lookup_string(DDI_DEV_T_ANY, tgt_dip,
		    PROPFLAGS, MDI_CLIENT_GUID_PROP, &guid);
		target_port_dup = i_ddi_strdup(guid, KM_SLEEP);
		ddi_prop_free(guid);

		/*
		 * For this type of mapping we don't want the
		 * <id> -> 'target-port' mapping to be made.  This
		 * will cause the SCSI_VHCI_GET_TARGET_LONGNAME ioctl
		 * to fail, and the iostat(1M) long '-n' output will
		 * still use the <pid>.  We do this because we just
		 * made up the 'target-port' using the guid, and we
		 * don't want to expose that fact in iostat output.
		 */
		by_id = 0;
	}

	/* find/establish <pid> given 'target-port' */
	mutex_enter(&vhci_targetmap_mutex);
	if (mod_hash_find(vhci_targetmap_byport,
	    (mod_hash_key_t)target_port_dup, &hv) == 0) {
		pid = (int)(intptr_t)hv;	/* mapping exists */
	} else {
		pid = vhci_targetmap_pid++;	/* new mapping */

		(void) mod_hash_insert(vhci_targetmap_byport,
		    (mod_hash_key_t)target_port_dup,
		    (mod_hash_val_t)(intptr_t)pid);
		if (by_id) {
			(void) mod_hash_insert(vhci_targetmap_bypid,
			    (mod_hash_key_t)(uintptr_t)pid,
			    (mod_hash_val_t)(uintptr_t)target_port_dup);
		}
		target_port_dup = NULL;		/* owned by hash */
	}
	mutex_exit(&vhci_targetmap_mutex);

	/* form kstat name */
	(void) snprintf(ks_name, KSTAT_STRLEN, "%s%d.t%d.%s%d",
	    ddi_driver_name(tgt_dip), ddi_get_instance(tgt_dip),
	    pid, ddi_driver_name(pdip), ddi_get_instance(pdip));

	VHCI_DEBUG(1, (CE_NOTE, NULL, "!vhci_path_online: path:%p "
	    "kstat %s: pid %x <-> port %s\n", (void *)pip,
	    ks_name, pid, target_port_dup));
	if (target_port_dup)
		kmem_free(target_port_dup, strlen(target_port_dup) + 1);

	/* call mdi to create kstats with the name we built */
	(void) mdi_pi_kstat_create(pip, ks_name);
}

/* ARGSUSED */
static int
vhci_pathinfo_online(dev_info_t *vdip, mdi_pathinfo_t *pip, int flags)
{
	scsi_hba_tran_t			*hba = NULL;
	struct scsi_device		*psd = NULL;
	scsi_vhci_lun_t			*vlun = NULL;
	dev_info_t			*pdip = NULL;
	dev_info_t			*cdip;
	dev_info_t			*tgt_dip;
	struct scsi_vhci		*vhci;
	char				*guid;
	struct scsi_failover_ops	*sfo;
	scsi_vhci_priv_t		*svp = NULL;
	struct scsi_address		*ap;
	struct scsi_pkt			*pkt;
	int				rval = MDI_FAILURE;
	mpapi_item_list_t		*list_ptr;
	mpapi_lu_data_t			*ld;

	ASSERT(vdip != NULL);
	ASSERT(pip != NULL);

	vhci = ddi_get_soft_state(vhci_softstate, ddi_get_instance(vdip));
	ASSERT(vhci != NULL);

	pdip = mdi_pi_get_phci(pip);
	hba = ddi_get_driver_private(pdip);
	ASSERT(hba != NULL);

	svp = (scsi_vhci_priv_t *)mdi_pi_get_vhci_private(pip);
	ASSERT(svp != NULL);

	cdip = mdi_pi_get_client(pip);
	ASSERT(cdip != NULL);
	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, cdip, PROPFLAGS,
	    MDI_CLIENT_GUID_PROP, &guid) != DDI_SUCCESS) {
		VHCI_DEBUG(1, (CE_WARN, NULL, "vhci_path_online: lun guid "
		    "property failed"));
		goto failure;
	}

	vlun = vhci_lun_lookup(cdip);
	ASSERT(vlun != NULL);

	ddi_prop_free(guid);

	vlun->svl_dip = mdi_pi_get_client(pip);
	ASSERT(vlun->svl_dip != NULL);

	psd = svp->svp_psd;
	ASSERT(psd != NULL);

	ap = &psd->sd_address;

	/*
	 * Get inquiry data into pathinfo related scsi_device structure.
	 * Free sq_inq when pathinfo related scsi_device structure is destroyed
	 * by vhci_pathinfo_uninit(). In other words, vhci maintains its own
	 * copy of scsi_device and scsi_inquiry data on a per-path basis.
	 */
	if (scsi_probe(psd, SLEEP_FUNC) != SCSIPROBE_EXISTS) {
		VHCI_DEBUG(1, (CE_NOTE, NULL, "!vhci_pathinfo_online: "
		    "scsi_probe failed path:%p rval:%x\n", (void *)pip, rval));
		rval = MDI_FAILURE;
		goto failure;
	}

	/*
	 * See if we have a failover module to support the device.
	 *
	 * We re-probe to determine the failover ops for each path. This
	 * is done in case there are any path-specific side-effects associated
	 * with the sfo_device_probe implementation.
	 *
	 * Give the first successfull sfo_device_probe the opportunity to
	 * establish 'ctpriv', vlun/client private data. The ctpriv will
	 * then be passed into the failover module on all other sfo_device_*()
	 * operations (and must be freed by sfo_device_unprobe implementation).
	 *
	 * NOTE: While sfo_device_probe is done once per path,
	 * sfo_device_unprobe only occurs once - when the vlun is destroyed.
	 *
	 * NOTE: We don't currently support per-path fops private data
	 * mechanism.
	 */
	sfo = vhci_dev_fo(vdip, psd,
	    &vlun->svl_fops_ctpriv, &vlun->svl_fops_name);

	/* check path configuration result with current vlun state */
	if (((sfo && vlun->svl_fops) && (sfo != vlun->svl_fops)) ||
	    (sfo && vlun->svl_not_supported) ||
	    ((sfo == NULL) && vlun->svl_fops)) {
		/* Getting different results for different paths. */
		VHCI_DEBUG(1, (CE_NOTE, vhci->vhci_dip,
		    "!vhci_pathinfo_online: dev (path 0x%p) contradiction\n",
		    (void *)pip));
		cmn_err(CE_WARN, "scsi_vhci: failover contradiction: "
		    "'%s'.vs.'%s': path %s\n",
		    vlun->svl_fops ? vlun->svl_fops->sfo_name : "NULL",
		    sfo ? sfo->sfo_name : "NULL", mdi_pi_pathname(pip));
		vlun->svl_not_supported = 1;
		rval = MDI_NOT_SUPPORTED;
		goto done;
	} else if (sfo == NULL) {
		/* No failover module - device not supported under vHCI.  */
		VHCI_DEBUG(1, (CE_NOTE, vhci->vhci_dip,
		    "!vhci_pathinfo_online: dev (path 0x%p) not "
		    "supported\n", (void *)pip));

		/* XXX does this contradict vhci_is_dev_supported ? */
		vlun->svl_not_supported = 1;
		rval = MDI_NOT_SUPPORTED;
		goto done;
	}

	/* failover supported for device - save failover_ops in vlun */
	vlun->svl_fops = sfo;
	ASSERT(vlun->svl_fops_name != NULL);

	/*
	 * Obtain the device-type based mpxio options as specified in
	 * scsi_vhci.conf file.
	 *
	 * NOTE: currently, the end result is a call to
	 * mdi_set_lb_region_size().
	 */
	tgt_dip = psd->sd_dev;
	ASSERT(tgt_dip != NULL);
	vhci_get_device_type_mpxio_options(vdip, tgt_dip, psd);

	/*
	 * if PGR is active, revalidate key and register on this path also,
	 * if key is still valid
	 */
	sema_p(&vlun->svl_pgr_sema);
	if (vlun->svl_pgr_active) {
		rval = vhci_pgr_validate_and_register(svp);
		if (rval != 1) {
			rval = MDI_FAILURE;
			sema_v(&vlun->svl_pgr_sema);
			goto failure;
		}
	}
	sema_v(&vlun->svl_pgr_sema);

	if (svp->svp_new_path) {
		/*
		 * Last chance to perform any cleanup operations on this
		 * new path before making this path completely online.
		 */
		svp->svp_new_path = 0;

		/*
		 * If scsi_vhci knows the lun is alread RESERVE'd,
		 * then skip the issue of RELEASE on new path.
		 */
		if ((vlun->svl_flags & VLUN_RESERVE_ACTIVE_FLG) == 0) {
			/*
			 * Issue SCSI-2 RELEASE only for the first time on
			 * a new path just in case the host rebooted and
			 * a reservation is still pending on this path.
			 * IBM Shark storage does not clear RESERVE upon
			 * host reboot.
			 */
			pkt = scsi_init_pkt(ap, NULL, NULL, CDB_GROUP0,
			    sizeof (struct scsi_arq_status), 0, 0,
			    SLEEP_FUNC, NULL);
			if (pkt == NULL) {
				VHCI_DEBUG(1, (CE_NOTE, NULL,
				    "!vhci_pathinfo_online: "
				    "Release init_pkt failed :%p\n",
				    (void *)pip));
				rval = MDI_FAILURE;
				goto failure;
			}
			pkt->pkt_cdbp[0] = SCMD_RELEASE;
			pkt->pkt_time = 60;

			VHCI_DEBUG(1, (CE_NOTE, NULL,
			    "!vhci_path_online: path:%p "
			    "Issued SCSI-2 RELEASE\n", (void *)pip));

			/* Ignore the return value */
			(void) vhci_do_scsi_cmd(pkt);
			scsi_destroy_pkt(pkt);
		}
	}

	rval = vhci_update_pathinfo(psd, pip, sfo, vlun, vhci);
	if (rval == MDI_FAILURE) {
		goto failure;
	}

	/* Initialize MP-API data */
	vhci_update_mpapi_data(vhci, vlun, pip);

	/*
	 * MP-API also needs the Inquiry data to be maintained in the
	 * mp_vendor_prop_t structure, so find the lun and update its
	 * structure with this data.
	 */
	list_ptr = (mpapi_item_list_t *)vhci_get_mpapi_item(vhci, NULL,
	    MP_OBJECT_TYPE_MULTIPATH_LU, (void *)vlun);
	ld = (mpapi_lu_data_t *)list_ptr->item->idata;
	if (ld != NULL) {
		bcopy(psd->sd_inq->inq_vid, ld->prop.prodInfo.vendor, 8);
		bcopy(psd->sd_inq->inq_pid, ld->prop.prodInfo.product, 16);
		bcopy(psd->sd_inq->inq_revision, ld->prop.prodInfo.revision, 4);
	} else {
		VHCI_DEBUG(1, (CE_WARN, NULL, "!vhci_pathinfo_online: "
		    "mpapi_lu_data_t is NULL"));
	}

	/* create kstats for path */
	vhci_kstat_create_pathinfo(pip);

done:
	mutex_enter(&vhci_global_mutex);
	cv_broadcast(&vhci_cv);
	mutex_exit(&vhci_global_mutex);

	if (vlun->svl_setcap_done) {
		(void) vhci_pHCI_cap(ap, "sector-size",
		    vlun->svl_sector_size, 1, pip);
	}

	VHCI_DEBUG(1, (CE_NOTE, NULL, "!vhci_path_online: path:%p\n",
	    (void *)pip));

failure:
	return (rval);
}

/*
 * path offline handler.  Release all bindings that will not be
 * released by the normal packet transport/completion code path.
 * Since we don't (presently) keep any bindings alive outside of
 * the in-transport packets (which will be released on completion)
 * there is not much to do here.
 */
/* ARGSUSED */
static int
vhci_pathinfo_offline(dev_info_t *vdip, mdi_pathinfo_t *pip, int flags)
{
	scsi_hba_tran_t		*hba = NULL;
	struct scsi_device	*psd = NULL;
	dev_info_t		*pdip = NULL;
	dev_info_t		*cdip = NULL;
	scsi_vhci_priv_t	*svp = NULL;

	ASSERT(vdip != NULL);
	ASSERT(pip != NULL);

	pdip = mdi_pi_get_phci(pip);
	ASSERT(pdip != NULL);
	if (pdip == NULL) {
		VHCI_DEBUG(1, (CE_WARN, vdip, "Invalid path 0x%p: NULL "
		    "phci dip", (void *)pip));
		return (MDI_FAILURE);
	}

	cdip = mdi_pi_get_client(pip);
	ASSERT(cdip != NULL);
	if (cdip == NULL) {
		VHCI_DEBUG(1, (CE_WARN, vdip, "Invalid path 0x%p: NULL "
		    "client dip", (void *)pip));
		return (MDI_FAILURE);
	}

	hba = ddi_get_driver_private(pdip);
	ASSERT(hba != NULL);

	svp = (scsi_vhci_priv_t *)mdi_pi_get_vhci_private(pip);
	if (svp == NULL) {
		/*
		 * mdi_pathinfo node in INIT state can have vHCI private
		 * information set to null
		 */
		VHCI_DEBUG(1, (CE_NOTE, vdip, "!vhci_pathinfo_offline: "
		    "svp is NULL for pip 0x%p\n", (void *)pip));
		return (MDI_SUCCESS);
	}

	psd = svp->svp_psd;
	ASSERT(psd != NULL);

	mutex_enter(&svp->svp_mutex);

	VHCI_DEBUG(1, (CE_NOTE, vdip, "!vhci_pathinfo_offline: "
	    "%d cmds pending on path: 0x%p\n", svp->svp_cmds, (void *)pip));
	while (svp->svp_cmds != 0) {
		if (cv_reltimedwait(&svp->svp_cv, &svp->svp_mutex,
		    drv_usectohz(vhci_path_quiesce_timeout * 1000000),
		    TR_CLOCK_TICK) == -1) {
			/*
			 * The timeout time reached without the condition
			 * being signaled.
			 */
			VHCI_DEBUG(1, (CE_NOTE, vdip, "!vhci_pathinfo_offline: "
			    "Timeout reached on path 0x%p without the cond\n",
			    (void *)pip));
			VHCI_DEBUG(1, (CE_NOTE, vdip, "!vhci_pathinfo_offline: "
			    "%d cmds still pending on path: 0x%p\n",
			    svp->svp_cmds, (void *)pip));
			break;
		}
	}
	mutex_exit(&svp->svp_mutex);

	/*
	 * Check to see if this vlun has an active SCSI-II RESERVE. And this
	 * is the pip for the path that has been reserved.
	 * If so clear the reservation by sending a reset, so the host will not
	 * get a reservation conflict.  Reset the flag VLUN_RESERVE_ACTIVE_FLG
	 * for this lun.  Also a reset notify is sent to the target driver
	 * just in case the POR check condition is cleared by some other layer
	 * in the stack.
	 */
	if (svp->svp_svl->svl_flags & VLUN_RESERVE_ACTIVE_FLG) {
		if (pip == svp->svp_svl->svl_resrv_pip) {
			if (vhci_recovery_reset(svp->svp_svl,
			    &svp->svp_psd->sd_address, TRUE,
			    VHCI_DEPTH_TARGET) == 0) {
				VHCI_DEBUG(1, (CE_NOTE, NULL,
				    "!vhci_pathinfo_offline (pip:%p):"
				    "reset failed, retrying\n", (void *)pip));
				delay(1*drv_usectohz(1000000));
				if (vhci_recovery_reset(svp->svp_svl,
				    &svp->svp_psd->sd_address, TRUE,
				    VHCI_DEPTH_TARGET) == 0) {
					VHCI_DEBUG(1, (CE_NOTE, NULL,
					    "!vhci_pathinfo_offline "
					    "(pip:%p): reset failed, "
					    "giving up!\n", (void *)pip));
				}
			}
			svp->svp_svl->svl_flags &= ~VLUN_RESERVE_ACTIVE_FLG;
		}
	}

	mdi_pi_set_state(pip, MDI_PATHINFO_STATE_OFFLINE);
	vhci_mpapi_set_path_state(vdip, pip, MP_DRVR_PATH_STATE_REMOVED);

	VHCI_DEBUG(1, (CE_NOTE, NULL,
	    "!vhci_pathinfo_offline: offlined path 0x%p\n", (void *)pip));
	return (MDI_SUCCESS);
}


/*
 * routine for SCSI VHCI IOCTL implementation.
 */
/* ARGSUSED */
static int
vhci_ctl(dev_t dev, int cmd, intptr_t data, int mode, cred_t *credp, int *rval)
{
	struct scsi_vhci		*vhci;
	dev_info_t			*vdip;
	mdi_pathinfo_t			*pip;
	int				instance, held;
	int				retval = 0;
	caddr_t				phci_path = NULL, client_path = NULL;
	caddr_t				paddr = NULL;
	sv_iocdata_t			ioc;
	sv_iocdata_t			*pioc = &ioc;
	sv_switch_to_cntlr_iocdata_t	iocsc;
	sv_switch_to_cntlr_iocdata_t	*piocsc = &iocsc;
	caddr_t				s;
	scsi_vhci_lun_t			*vlun;
	struct scsi_failover_ops	*fo;
	char				*pclass;

	/* Check for validity of vhci structure */
	vhci = ddi_get_soft_state(vhci_softstate, MINOR2INST(getminor(dev)));
	if (vhci == NULL) {
		return (ENXIO);
	}

	mutex_enter(&vhci->vhci_mutex);
	if ((vhci->vhci_state & VHCI_STATE_OPEN) == 0) {
		mutex_exit(&vhci->vhci_mutex);
		return (ENXIO);
	}
	mutex_exit(&vhci->vhci_mutex);

	/* Get the vhci dip */
	vdip = vhci->vhci_dip;
	ASSERT(vdip != NULL);
	instance = ddi_get_instance(vdip);

	/* Allocate memory for getting parameters from userland */
	phci_path	= kmem_zalloc(MAXPATHLEN, KM_SLEEP);
	client_path	= kmem_zalloc(MAXPATHLEN, KM_SLEEP);
	paddr		= kmem_zalloc(MAXNAMELEN, KM_SLEEP);

	/*
	 * Set a local variable indicating the ioctl name. Used for
	 * printing debug strings.
	 */
	switch (cmd) {
	case SCSI_VHCI_GET_CLIENT_MULTIPATH_INFO:
		s = "GET_CLIENT_MULTIPATH_INFO";
		break;

	case SCSI_VHCI_GET_PHCI_MULTIPATH_INFO:
		s = "GET_PHCI_MULTIPATH_INFO";
		break;

	case SCSI_VHCI_GET_CLIENT_NAME:
		s = "GET_CLIENT_NAME";
		break;

	case SCSI_VHCI_PATH_ONLINE:
		s = "PATH_ONLINE";
		break;

	case SCSI_VHCI_PATH_OFFLINE:
		s = "PATH_OFFLINE";
		break;

	case SCSI_VHCI_PATH_STANDBY:
		s = "PATH_STANDBY";
		break;

	case SCSI_VHCI_PATH_TEST:
		s = "PATH_TEST";
		break;

	case SCSI_VHCI_SWITCH_TO_CNTLR:
		s = "SWITCH_TO_CNTLR";
		break;
	case SCSI_VHCI_PATH_DISABLE:
		s = "PATH_DISABLE";
		break;
	case SCSI_VHCI_PATH_ENABLE:
		s = "PATH_ENABLE";
		break;

	case SCSI_VHCI_GET_TARGET_LONGNAME:
		s = "GET_TARGET_LONGNAME";
		break;

#ifdef	DEBUG
	case SCSI_VHCI_CONFIGURE_PHCI:
		s = "CONFIGURE_PHCI";
		break;

	case SCSI_VHCI_UNCONFIGURE_PHCI:
		s = "UNCONFIGURE_PHCI";
		break;
#endif

	default:
		s = "Unknown";
		vhci_log(CE_NOTE, vdip,
		    "!vhci%d: ioctl %x (unsupported ioctl)", instance, cmd);
		retval = ENOTSUP;
		break;
	}
	if (retval != 0) {
		goto end;
	}

	VHCI_DEBUG(6, (CE_WARN, vdip, "!vhci%d: ioctl <%s>", instance, s));

	/*
	 * Get IOCTL parameters from userland
	 */
	switch (cmd) {
	case SCSI_VHCI_GET_CLIENT_MULTIPATH_INFO:
	case SCSI_VHCI_GET_PHCI_MULTIPATH_INFO:
	case SCSI_VHCI_GET_CLIENT_NAME:
	case SCSI_VHCI_PATH_ONLINE:
	case SCSI_VHCI_PATH_OFFLINE:
	case SCSI_VHCI_PATH_STANDBY:
	case SCSI_VHCI_PATH_TEST:
	case SCSI_VHCI_PATH_DISABLE:
	case SCSI_VHCI_PATH_ENABLE:
	case SCSI_VHCI_GET_TARGET_LONGNAME:
#ifdef	DEBUG
	case SCSI_VHCI_CONFIGURE_PHCI:
	case SCSI_VHCI_UNCONFIGURE_PHCI:
#endif
		retval = vhci_get_iocdata((const void *)data, pioc, mode, s);
		break;

	case SCSI_VHCI_SWITCH_TO_CNTLR:
		retval = vhci_get_iocswitchdata((const void *)data, piocsc,
		    mode, s);
		break;
	}
	if (retval != 0) {
		goto end;
	}


	/*
	 * Process the IOCTL
	 */
	switch (cmd) {
	case SCSI_VHCI_GET_CLIENT_MULTIPATH_INFO:
	{
		uint_t		num_paths;	/* Num paths to client dev */
		sv_path_info_t	*upibuf = NULL;	/* To keep userland values */
		sv_path_info_t	*kpibuf = NULL; /* Kernel data for ioctls */
		dev_info_t	*cdip;		/* Client device dip */

		if (pioc->ret_elem == NULL) {
			retval = EINVAL;
			break;
		}

		/* Get client device path from user land */
		if (vhci_ioc_get_client_path(pioc, client_path, mode, s)) {
			retval = EFAULT;
			break;
		}

		VHCI_DEBUG(6, (CE_WARN, vdip, "!vhci_ioctl: ioctl <%s> "
		    "client <%s>", s, client_path));

		/* Get number of paths to this client device */
		if ((cdip = mdi_client_path2devinfo(vdip, client_path))
		    == NULL) {
			retval = ENXIO;
			VHCI_DEBUG(1, (CE_WARN, NULL, "!vhci_ioctl: ioctl <%s> "
			    "client dip doesn't exist. invalid path <%s>",
			    s, client_path));
			break;
		}
		num_paths = mdi_client_get_path_count(cdip);

		if (ddi_copyout(&num_paths, pioc->ret_elem,
		    sizeof (num_paths), mode)) {
			VHCI_DEBUG(1, (CE_WARN, NULL, "!vhci_ioctl: ioctl <%s> "
			    "num_paths copyout failed", s));
			retval = EFAULT;
			break;
		}

		/* If  user just wanted num_paths, then return */
		if (pioc->buf_elem == 0 || pioc->ret_buf == NULL ||
		    num_paths == 0) {
			break;
		}

		/* Set num_paths to value as much as can be sent to userland */
		if (num_paths > pioc->buf_elem) {
			num_paths = pioc->buf_elem;
		}

		/* Allocate memory and get userland pointers */
		if (vhci_ioc_alloc_pathinfo(&upibuf, &kpibuf, num_paths,
		    pioc, mode, s) != 0) {
			retval = EFAULT;
			break;
		}
		ASSERT(upibuf != NULL);
		ASSERT(kpibuf != NULL);

		/*
		 * Get the path information and send it to userland.
		 */
		if (vhci_get_client_path_list(cdip, kpibuf, num_paths)
		    != MDI_SUCCESS) {
			retval = ENXIO;
			vhci_ioc_free_pathinfo(upibuf, kpibuf, num_paths);
			break;
		}

		if (vhci_ioc_send_pathinfo(upibuf, kpibuf, num_paths,
		    pioc, mode, s)) {
			retval = EFAULT;
			vhci_ioc_free_pathinfo(upibuf, kpibuf, num_paths);
			break;
		}

		/* Free the memory allocated for path information */
		vhci_ioc_free_pathinfo(upibuf, kpibuf, num_paths);
		break;
	}

	case SCSI_VHCI_GET_PHCI_MULTIPATH_INFO:
	{
		uint_t		num_paths;	/* Num paths to client dev */
		sv_path_info_t	*upibuf = NULL;	/* To keep userland values */
		sv_path_info_t	*kpibuf = NULL; /* Kernel data for ioctls */
		dev_info_t	*pdip;		/* PHCI device dip */

		if (pioc->ret_elem == NULL) {
			retval = EINVAL;
			break;
		}

		/* Get PHCI device path from user land */
		if (vhci_ioc_get_phci_path(pioc, phci_path, mode, s)) {
			retval = EFAULT;
			break;
		}

		VHCI_DEBUG(6, (CE_WARN, vdip,
		    "!vhci_ioctl: ioctl <%s> phci <%s>", s, phci_path));

		/* Get number of devices associated with this PHCI device */
		if ((pdip = mdi_phci_path2devinfo(vdip, phci_path)) == NULL) {
			VHCI_DEBUG(1, (CE_WARN, NULL, "!vhci_ioctl: ioctl <%s> "
			    "phci dip doesn't exist. invalid path <%s>",
			    s, phci_path));
			retval = ENXIO;
			break;
		}

		num_paths = mdi_phci_get_path_count(pdip);

		if (ddi_copyout(&num_paths, pioc->ret_elem,
		    sizeof (num_paths), mode)) {
			VHCI_DEBUG(2, (CE_WARN, NULL, "!vhci_ioctl: ioctl <%s> "
			    "num_paths copyout failed", s));
			retval = EFAULT;
			break;
		}

		/* If  user just wanted num_paths, then return */
		if (pioc->buf_elem == 0 || pioc->ret_buf == NULL ||
		    num_paths == 0) {
			break;
		}

		/* Set num_paths to value as much as can be sent to userland */
		if (num_paths > pioc->buf_elem) {
			num_paths = pioc->buf_elem;
		}

		/* Allocate memory and get userland pointers */
		if (vhci_ioc_alloc_pathinfo(&upibuf, &kpibuf, num_paths,
		    pioc, mode, s) != 0) {
			retval = EFAULT;
			break;
		}
		ASSERT(upibuf != NULL);
		ASSERT(kpibuf != NULL);

		/*
		 * Get the path information and send it to userland.
		 */
		if (vhci_get_phci_path_list(pdip, kpibuf, num_paths)
		    != MDI_SUCCESS) {
			retval = ENXIO;
			vhci_ioc_free_pathinfo(upibuf, kpibuf, num_paths);
			break;
		}

		if (vhci_ioc_send_pathinfo(upibuf, kpibuf, num_paths,
		    pioc, mode, s)) {
			retval = EFAULT;
			vhci_ioc_free_pathinfo(upibuf, kpibuf, num_paths);
			break;
		}

		/* Free the memory allocated for path information */
		vhci_ioc_free_pathinfo(upibuf, kpibuf, num_paths);
		break;
	}

	case SCSI_VHCI_GET_CLIENT_NAME:
	{
		dev_info_t		*cdip, *pdip;

		/* Get PHCI path and device address from user land */
		if (vhci_ioc_get_phci_path(pioc, phci_path, mode, s) ||
		    vhci_ioc_get_paddr(pioc, paddr, mode, s)) {
			retval = EFAULT;
			break;
		}

		VHCI_DEBUG(6, (CE_WARN, vdip, "!vhci_ioctl: ioctl <%s> "
		    "phci <%s>, paddr <%s>", s, phci_path, paddr));

		/* Get the PHCI dip */
		if ((pdip = mdi_phci_path2devinfo(vdip, phci_path)) == NULL) {
			VHCI_DEBUG(1, (CE_WARN, NULL, "!vhci_ioctl: ioctl <%s> "
			    "phci dip doesn't exist. invalid path <%s>",
			    s, phci_path));
			retval = ENXIO;
			break;
		}

		if ((pip = mdi_pi_find(pdip, NULL, paddr)) == NULL) {
			VHCI_DEBUG(1, (CE_WARN, vdip, "!vhci_ioctl: ioctl <%s> "
			    "pathinfo doesn't exist. invalid device addr", s));
			retval = ENXIO;
			break;
		}

		/* Get the client device pathname and send to userland */
		cdip = mdi_pi_get_client(pip);
		vhci_ioc_devi_to_path(cdip, client_path);

		VHCI_DEBUG(6, (CE_WARN, vdip, "!vhci_ioctl: ioctl <%s> "
		    "client <%s>", s, client_path));

		if (vhci_ioc_send_client_path(client_path, pioc, mode, s)) {
			retval = EFAULT;
			break;
		}
		break;
	}

	case SCSI_VHCI_PATH_ONLINE:
	case SCSI_VHCI_PATH_OFFLINE:
	case SCSI_VHCI_PATH_STANDBY:
	case SCSI_VHCI_PATH_TEST:
	{
		dev_info_t		*pdip;	/* PHCI dip */

		/* Get PHCI path and device address from user land */
		if (vhci_ioc_get_phci_path(pioc, phci_path, mode, s) ||
		    vhci_ioc_get_paddr(pioc, paddr, mode, s)) {
			retval = EFAULT;
			break;
		}

		VHCI_DEBUG(6, (CE_WARN, vdip, "!vhci_ioctl: ioctl <%s> "
		    "phci <%s>, paddr <%s>", s, phci_path, paddr));

		/* Get the PHCI dip */
		if ((pdip = mdi_phci_path2devinfo(vdip, phci_path)) == NULL) {
			VHCI_DEBUG(1, (CE_WARN, NULL, "!vhci_ioctl: ioctl <%s> "
			    "phci dip doesn't exist. invalid path <%s>",
			    s, phci_path));
			retval = ENXIO;
			break;
		}

		if ((pip = mdi_pi_find(pdip, NULL, paddr)) == NULL) {
			VHCI_DEBUG(1, (CE_WARN, vdip, "!vhci_ioctl: ioctl <%s> "
			    "pathinfo doesn't exist. invalid device addr", s));
			retval = ENXIO;
			break;
		}

		VHCI_DEBUG(6, (CE_WARN, vdip, "!vhci_ioctl: ioctl <%s> "
		    "Calling MDI function to change device state", s));

		switch (cmd) {
		case SCSI_VHCI_PATH_ONLINE:
			retval = mdi_pi_online(pip, 0);
			break;

		case SCSI_VHCI_PATH_OFFLINE:
			retval = mdi_pi_offline(pip, 0);
			break;

		case SCSI_VHCI_PATH_STANDBY:
			retval = mdi_pi_standby(pip, 0);
			break;

		case SCSI_VHCI_PATH_TEST:
			break;
		}
		break;
	}

	case SCSI_VHCI_SWITCH_TO_CNTLR:
	{
		dev_info_t *cdip;
		struct scsi_device *devp;

		/* Get the client device pathname */
		if (ddi_copyin(piocsc->client, client_path,
		    MAXPATHLEN, mode)) {
			VHCI_DEBUG(2, (CE_WARN, vdip, "!vhci_ioctl: ioctl <%s> "
			    "client_path copyin failed", s));
			retval = EFAULT;
			break;
		}

		/* Get the path class to which user wants to switch */
		if (ddi_copyin(piocsc->class, paddr, MAXNAMELEN, mode)) {
			VHCI_DEBUG(2, (CE_WARN, vdip, "!vhci_ioctl: ioctl <%s> "
			    "controller_class copyin failed", s));
			retval = EFAULT;
			break;
		}

		/* Perform validity checks */
		if ((cdip = mdi_client_path2devinfo(vdip,
		    client_path)) == NULL) {
			VHCI_DEBUG(1, (CE_WARN, NULL, "!vhci_ioctl: ioctl <%s> "
			    "client dip doesn't exist. invalid path <%s>",
			    s, client_path));
			retval = ENXIO;
			break;
		}

		VHCI_DEBUG(6, (CE_WARN, vdip, "!vhci_ioctl: Calling MDI func "
		    "to switch controller"));
		VHCI_DEBUG(6, (CE_WARN, vdip, "!vhci_ioctl: client <%s> "
		    "class <%s>", client_path, paddr));

		if (strcmp(paddr, PCLASS_PRIMARY) &&
		    strcmp(paddr, PCLASS_SECONDARY)) {
			VHCI_DEBUG(2, (CE_WARN, NULL, "!vhci_ioctl: ioctl <%s> "
			    "invalid path class <%s>", s, paddr));
			retval = ENXIO;
			break;
		}

		devp = ddi_get_driver_private(cdip);
		if (devp == NULL) {
			VHCI_DEBUG(2, (CE_WARN, NULL, "!vhci_ioctl: ioctl <%s> "
			    "invalid scsi device <%s>", s, client_path));
			retval = ENXIO;
			break;
		}
		vlun = ADDR2VLUN(&devp->sd_address);
		ASSERT(vlun);

		/*
		 * Checking to see if device has only one pclass, PRIMARY.
		 * If so this device doesn't support failovers.  Assumed
		 * that the devices with one pclass is PRIMARY, as thats the
		 * case today.  If this is not true and in future other
		 * symmetric devices are supported with other pclass, this
		 * IOCTL shall have to be overhauled anyways as now the only
		 * arguments it accepts are PRIMARY and SECONDARY.
		 */
		fo = vlun->svl_fops;
		if (fo->sfo_pathclass_next(PCLASS_PRIMARY, &pclass,
		    vlun->svl_fops_ctpriv)) {
			retval = ENOTSUP;
			break;
		}

		VHCI_HOLD_LUN(vlun, VH_SLEEP, held);
		mutex_enter(&vlun->svl_mutex);
		if (vlun->svl_active_pclass != NULL) {
			if (strcmp(vlun->svl_active_pclass, paddr) == 0) {
				mutex_exit(&vlun->svl_mutex);
				retval = EALREADY;
				VHCI_RELEASE_LUN(vlun);
				break;
			}
		}
		mutex_exit(&vlun->svl_mutex);
		/* Call mdi function to cause  a switch over */
		retval = mdi_failover(vdip, cdip, MDI_FAILOVER_SYNC);
		if (retval == MDI_SUCCESS) {
			retval = 0;
		} else if (retval == MDI_BUSY) {
			retval = EBUSY;
		} else {
			retval = EIO;
		}
		VHCI_RELEASE_LUN(vlun);
		break;
	}

	case SCSI_VHCI_PATH_ENABLE:
	case SCSI_VHCI_PATH_DISABLE:
	{
		dev_info_t	*cdip, *pdip;

		/*
		 * Get client device path from user land
		 */
		if (vhci_ioc_get_client_path(pioc, client_path, mode, s)) {
			retval = EFAULT;
			break;
		}

		/*
		 * Get Phci device path from user land
		 */
		if (vhci_ioc_get_phci_path(pioc, phci_path, mode, s)) {
			retval = EFAULT;
			break;
		}

		/*
		 * Get the devinfo for the Phci.
		 */
		if ((pdip = mdi_phci_path2devinfo(vdip, phci_path)) == NULL) {
			VHCI_DEBUG(1, (CE_WARN, NULL, "!vhci_ioctl: ioctl <%s> "
			    "phci dip doesn't exist. invalid path <%s>",
			    s, phci_path));
			retval = ENXIO;
			break;
		}

		/*
		 * If the client path is set to /scsi_vhci then we need
		 * to do the operation on all the clients so set cdip to NULL.
		 * Else, try to get the client dip.
		 */
		if (strcmp(client_path, "/scsi_vhci") == 0) {
			cdip = NULL;
		} else {
			if ((cdip = mdi_client_path2devinfo(vdip,
			    client_path)) == NULL) {
				retval = ENXIO;
				VHCI_DEBUG(1, (CE_WARN, NULL,
				    "!vhci_ioctl: ioctl <%s> client dip "
				    "doesn't exist. invalid path <%s>",
				    s, client_path));
				break;
			}
		}

		if (cmd == SCSI_VHCI_PATH_ENABLE)
			retval = mdi_pi_enable(cdip, pdip, USER_DISABLE);
		else
			retval = mdi_pi_disable(cdip, pdip, USER_DISABLE);

		break;
	}

	case SCSI_VHCI_GET_TARGET_LONGNAME:
	{
		uint_t		pid = pioc->buf_elem;
		char		*target_port;
		mod_hash_val_t	hv;

		/* targetmap lookup of 'target-port' by <pid> */
		if (mod_hash_find(vhci_targetmap_bypid,
		    (mod_hash_key_t)(uintptr_t)pid, &hv) != 0) {
			/*
			 * NOTE: failure to find the mapping is OK for guid
			 * based 'target-port' values.
			 */
			VHCI_DEBUG(3, (CE_WARN, NULL, "!vhci_ioctl: ioctl <%s> "
			    "targetport mapping doesn't exist: pid %d",
			    s, pid));
			retval = ENXIO;
			break;
		}

		/* copyout 'target-port' result */
		target_port = (char *)hv;
		if (copyoutstr(target_port, pioc->addr, MAXNAMELEN, NULL)) {
			VHCI_DEBUG(1, (CE_WARN, NULL, "!vhci_ioctl: ioctl <%s> "
			    "targetport copyout failed: len: %d",
			    s, (int)strlen(target_port)));
			retval = EFAULT;
		}
		break;
	}

#ifdef	DEBUG
	case SCSI_VHCI_CONFIGURE_PHCI:
	{
		dev_info_t		*pdip;

		/* Get PHCI path and device address from user land */
		if (vhci_ioc_get_phci_path(pioc, phci_path, mode, s)) {
			retval = EFAULT;
			break;
		}

		VHCI_DEBUG(6, (CE_WARN, vdip, "!vhci_ioctl: ioctl <%s> "
		    "phci <%s>", s, phci_path));

		/* Get the PHCI dip */
		if ((pdip = e_ddi_hold_devi_by_path(phci_path, 0)) == NULL) {
			VHCI_DEBUG(3, (CE_WARN, NULL, "!vhci_ioctl: ioctl <%s> "
			    "phci dip doesn't exist. invalid path <%s>",
			    s, phci_path));
			retval = ENXIO;
			break;
		}

		if (ndi_devi_config(pdip,
		    NDI_DEVFS_CLEAN|NDI_DEVI_PERSIST) != NDI_SUCCESS) {
			retval = EIO;
		}

		ddi_release_devi(pdip);
		break;
	}

	case SCSI_VHCI_UNCONFIGURE_PHCI:
	{
		dev_info_t		*pdip;

		/* Get PHCI path and device address from user land */
		if (vhci_ioc_get_phci_path(pioc, phci_path, mode, s)) {
			retval = EFAULT;
			break;
		}

		VHCI_DEBUG(6, (CE_WARN, vdip, "!vhci_ioctl: ioctl <%s> "
		    "phci <%s>", s, phci_path));

		/* Get the PHCI dip */
		if ((pdip = e_ddi_hold_devi_by_path(phci_path, 0)) == NULL) {
			VHCI_DEBUG(3, (CE_WARN, NULL, "!vhci_ioctl: ioctl <%s> "
			    "phci dip doesn't exist. invalid path <%s>",
			    s, phci_path));
			retval = ENXIO;
			break;
		}

		if (ndi_devi_unconfig(pdip,
		    NDI_DEVI_REMOVE|NDI_DEVFS_CLEAN) != NDI_SUCCESS) {
			retval = EBUSY;
		}

		ddi_release_devi(pdip);
		break;
	}
#endif
	}

end:
	/* Free the memory allocated above */
	if (phci_path != NULL) {
		kmem_free(phci_path, MAXPATHLEN);
	}
	if (client_path != NULL) {
		kmem_free(client_path, MAXPATHLEN);
	}
	if (paddr != NULL) {
		kmem_free(paddr, MAXNAMELEN);
	}
	return (retval);
}

/*
 * devctl IOCTL support for client device DR
 */
/* ARGSUSED */
int
vhci_devctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
    int *rvalp)
{
	dev_info_t *self;
	dev_info_t *child;
	scsi_hba_tran_t *hba;
	struct devctl_iocdata *dcp;
	struct scsi_vhci *vhci;
	int rv = 0;
	int retval = 0;
	scsi_vhci_priv_t *svp;
	mdi_pathinfo_t  *pip;

	if ((vhci = ddi_get_soft_state(vhci_softstate,
	    MINOR2INST(getminor(dev)))) == NULL)
		return (ENXIO);

	/*
	 * check if :devctl minor device has been opened
	 */
	mutex_enter(&vhci->vhci_mutex);
	if ((vhci->vhci_state & VHCI_STATE_OPEN) == 0) {
		mutex_exit(&vhci->vhci_mutex);
		return (ENXIO);
	}
	mutex_exit(&vhci->vhci_mutex);

	self = vhci->vhci_dip;
	hba = ddi_get_driver_private(self);
	if (hba == NULL)
		return (ENXIO);

	/*
	 * We can use the generic implementation for these ioctls
	 */
	switch (cmd) {
	case DEVCTL_DEVICE_GETSTATE:
	case DEVCTL_DEVICE_ONLINE:
	case DEVCTL_DEVICE_OFFLINE:
	case DEVCTL_DEVICE_REMOVE:
	case DEVCTL_BUS_GETSTATE:
		return (ndi_devctl_ioctl(self, cmd, arg, mode, 0));
	}

	/*
	 * read devctl ioctl data
	 */
	if (ndi_dc_allochdl((void *)arg, &dcp) != NDI_SUCCESS)
		return (EFAULT);

	switch (cmd) {

	case DEVCTL_DEVICE_RESET:
		/*
		 * lookup and hold child device
		 */
		if ((child = ndi_devi_find(self, ndi_dc_getname(dcp),
		    ndi_dc_getaddr(dcp))) == NULL) {
			rv = ENXIO;
			break;
		}
		retval = mdi_select_path(child, NULL,
		    (MDI_SELECT_ONLINE_PATH | MDI_SELECT_STANDBY_PATH),
		    NULL, &pip);
		if ((retval != MDI_SUCCESS) || (pip == NULL)) {
			VHCI_DEBUG(2, (CE_WARN, NULL, "!vhci_ioctl:"
			    "Unable to get a path, dip 0x%p", (void *)child));
			rv = ENXIO;
			break;
		}
		svp = (scsi_vhci_priv_t *)mdi_pi_get_vhci_private(pip);
		if (vhci_recovery_reset(svp->svp_svl,
		    &svp->svp_psd->sd_address, TRUE,
		    VHCI_DEPTH_TARGET) == 0) {
			VHCI_DEBUG(1, (CE_NOTE, NULL,
			    "!vhci_ioctl(pip:%p): "
			    "reset failed\n", (void *)pip));
			rv = ENXIO;
		}
		mdi_rele_path(pip);
		break;

	case DEVCTL_BUS_QUIESCE:
	case DEVCTL_BUS_UNQUIESCE:
	case DEVCTL_BUS_RESET:
	case DEVCTL_BUS_RESETALL:
#ifdef	DEBUG
	case DEVCTL_BUS_CONFIGURE:
	case DEVCTL_BUS_UNCONFIGURE:
#endif
		rv = ENOTSUP;
		break;

	default:
		rv = ENOTTY;
	} /* end of outer switch */

	ndi_dc_freehdl(dcp);
	return (rv);
}

/*
 * Routine to get the PHCI pathname from ioctl structures in userland
 */
/* ARGSUSED */
static int
vhci_ioc_get_phci_path(sv_iocdata_t *pioc, caddr_t phci_path,
	int mode, caddr_t s)
{
	int retval = 0;

	if (ddi_copyin(pioc->phci, phci_path, MAXPATHLEN, mode)) {
		VHCI_DEBUG(2, (CE_WARN, NULL, "!vhci_ioc_get_phci: ioctl <%s> "
		    "phci_path copyin failed", s));
		retval = EFAULT;
	}
	return (retval);

}


/*
 * Routine to get the Client device pathname from ioctl structures in userland
 */
/* ARGSUSED */
static int
vhci_ioc_get_client_path(sv_iocdata_t *pioc, caddr_t client_path,
	int mode, caddr_t s)
{
	int retval = 0;

	if (ddi_copyin(pioc->client, client_path, MAXPATHLEN, mode)) {
		VHCI_DEBUG(2, (CE_WARN, NULL, "!vhci_ioc_get_client: "
		    "ioctl <%s> client_path copyin failed", s));
		retval = EFAULT;
	}
	return (retval);
}


/*
 * Routine to get physical device address from ioctl structure in userland
 */
/* ARGSUSED */
static int
vhci_ioc_get_paddr(sv_iocdata_t *pioc, caddr_t paddr, int mode, caddr_t s)
{
	int retval = 0;

	if (ddi_copyin(pioc->addr, paddr, MAXNAMELEN, mode)) {
		VHCI_DEBUG(2, (CE_WARN, NULL, "!vhci_ioc_get_paddr: "
		    "ioctl <%s> device addr copyin failed", s));
		retval = EFAULT;
	}
	return (retval);
}


/*
 * Routine to send client device pathname to userland.
 */
/* ARGSUSED */
static int
vhci_ioc_send_client_path(caddr_t client_path, sv_iocdata_t *pioc,
	int mode, caddr_t s)
{
	int retval = 0;

	if (ddi_copyout(client_path, pioc->client, MAXPATHLEN, mode)) {
		VHCI_DEBUG(2, (CE_WARN, NULL, "!vhci_ioc_send_client: "
		    "ioctl <%s> client_path copyout failed", s));
		retval = EFAULT;
	}
	return (retval);
}


/*
 * Routine to translated dev_info pointer (dip) to device pathname.
 */
static void
vhci_ioc_devi_to_path(dev_info_t *dip, caddr_t path)
{
	(void) ddi_pathname(dip, path);
}


/*
 * vhci_get_phci_path_list:
 *		get information about devices associated with a
 *		given PHCI device.
 *
 * Return Values:
 *		path information elements
 */
int
vhci_get_phci_path_list(dev_info_t *pdip, sv_path_info_t *pibuf,
	uint_t num_elems)
{
	uint_t			count, done;
	mdi_pathinfo_t		*pip;
	sv_path_info_t		*ret_pip;
	int			status;
	size_t			prop_size;
	int			circular;

	/*
	 * Get the PHCI structure and retrieve the path information
	 * from the GUID hash table.
	 */

	ret_pip = pibuf;
	count = 0;

	ndi_devi_enter(pdip, &circular);

	done = (count >= num_elems);
	pip = mdi_get_next_client_path(pdip, NULL);
	while (pip && !done) {
		mdi_pi_lock(pip);
		(void) ddi_pathname(mdi_pi_get_phci(pip),
		    ret_pip->device.ret_phci);
		(void) strcpy(ret_pip->ret_addr, mdi_pi_get_addr(pip));
		(void) mdi_pi_get_state2(pip, &ret_pip->ret_state,
		    &ret_pip->ret_ext_state);

		status = mdi_prop_size(pip, &prop_size);
		if (status == MDI_SUCCESS && ret_pip->ret_prop.ret_buf_size) {
			*ret_pip->ret_prop.ret_buf_size = (uint_t)prop_size;
		}

#ifdef DEBUG
		if (status != MDI_SUCCESS) {
			VHCI_DEBUG(2, (CE_WARN, NULL,
			    "!vhci_get_phci_path_list: "
			    "phci <%s>, prop size failure 0x%x",
			    ret_pip->device.ret_phci, status));
		}
#endif /* DEBUG */


		if (status == MDI_SUCCESS && ret_pip->ret_prop.buf &&
		    prop_size && ret_pip->ret_prop.buf_size >= prop_size) {
			status = mdi_prop_pack(pip,
			    &ret_pip->ret_prop.buf,
			    ret_pip->ret_prop.buf_size);

#ifdef DEBUG
			if (status != MDI_SUCCESS) {
				VHCI_DEBUG(2, (CE_WARN, NULL,
				    "!vhci_get_phci_path_list: "
				    "phci <%s>, prop pack failure 0x%x",
				    ret_pip->device.ret_phci, status));
			}
#endif /* DEBUG */
		}

		mdi_pi_unlock(pip);
		pip = mdi_get_next_client_path(pdip, pip);
		ret_pip++;
		count++;
		done = (count >= num_elems);
	}

	ndi_devi_exit(pdip, circular);

	return (MDI_SUCCESS);
}


/*
 * vhci_get_client_path_list:
 *		get information about various paths associated with a
 *		given client device.
 *
 * Return Values:
 *		path information elements
 */
int
vhci_get_client_path_list(dev_info_t *cdip, sv_path_info_t *pibuf,
	uint_t num_elems)
{
	uint_t			count, done;
	mdi_pathinfo_t		*pip;
	sv_path_info_t		*ret_pip;
	int			status;
	size_t			prop_size;
	int			circular;

	ret_pip = pibuf;
	count = 0;

	ndi_devi_enter(cdip, &circular);

	done = (count >= num_elems);
	pip = mdi_get_next_phci_path(cdip, NULL);
	while (pip && !done) {
		mdi_pi_lock(pip);
		(void) ddi_pathname(mdi_pi_get_phci(pip),
		    ret_pip->device.ret_phci);
		(void) strcpy(ret_pip->ret_addr, mdi_pi_get_addr(pip));
		(void) mdi_pi_get_state2(pip, &ret_pip->ret_state,
		    &ret_pip->ret_ext_state);

		status = mdi_prop_size(pip, &prop_size);
		if (status == MDI_SUCCESS && ret_pip->ret_prop.ret_buf_size) {
			*ret_pip->ret_prop.ret_buf_size = (uint_t)prop_size;
		}

#ifdef DEBUG
		if (status != MDI_SUCCESS) {
			VHCI_DEBUG(2, (CE_WARN, NULL,
			    "!vhci_get_client_path_list: "
			    "phci <%s>, prop size failure 0x%x",
			    ret_pip->device.ret_phci, status));
		}
#endif /* DEBUG */


		if (status == MDI_SUCCESS && ret_pip->ret_prop.buf &&
		    prop_size && ret_pip->ret_prop.buf_size >= prop_size) {
			status = mdi_prop_pack(pip,
			    &ret_pip->ret_prop.buf,
			    ret_pip->ret_prop.buf_size);

#ifdef DEBUG
			if (status != MDI_SUCCESS) {
				VHCI_DEBUG(2, (CE_WARN, NULL,
				    "!vhci_get_client_path_list: "
				    "phci <%s>, prop pack failure 0x%x",
				    ret_pip->device.ret_phci, status));
			}
#endif /* DEBUG */
		}

		mdi_pi_unlock(pip);
		pip = mdi_get_next_phci_path(cdip, pip);
		ret_pip++;
		count++;
		done = (count >= num_elems);
	}

	ndi_devi_exit(cdip, circular);

	return (MDI_SUCCESS);
}


/*
 * Routine to get ioctl argument structure from userland.
 */
/* ARGSUSED */
static int
vhci_get_iocdata(const void *data, sv_iocdata_t *pioc, int mode, caddr_t s)
{
	int	retval = 0;

#ifdef  _MULTI_DATAMODEL
	switch (ddi_model_convert_from(mode & FMODELS)) {
	case DDI_MODEL_ILP32:
	{
		sv_iocdata32_t	ioc32;

		if (ddi_copyin(data, &ioc32, sizeof (ioc32), mode)) {
			retval = EFAULT;
			break;
		}
		pioc->client	= (caddr_t)(uintptr_t)ioc32.client;
		pioc->phci	= (caddr_t)(uintptr_t)ioc32.phci;
		pioc->addr	= (caddr_t)(uintptr_t)ioc32.addr;
		pioc->buf_elem	= (uint_t)ioc32.buf_elem;
		pioc->ret_buf	= (sv_path_info_t *)(uintptr_t)ioc32.ret_buf;
		pioc->ret_elem	= (uint_t *)(uintptr_t)ioc32.ret_elem;
		break;
	}

	case DDI_MODEL_NONE:
		if (ddi_copyin(data, pioc, sizeof (*pioc), mode)) {
			retval = EFAULT;
			break;
		}
		break;
	}
#else   /* _MULTI_DATAMODEL */
	if (ddi_copyin(data, pioc, sizeof (*pioc), mode)) {
		retval = EFAULT;
	}
#endif  /* _MULTI_DATAMODEL */

#ifdef DEBUG
	if (retval) {
		VHCI_DEBUG(2, (CE_WARN, NULL, "!vhci_get_ioc: cmd <%s> "
		    "iocdata copyin failed", s));
	}
#endif

	return (retval);
}


/*
 * Routine to get the ioctl argument for ioctl causing controller switchover.
 */
/* ARGSUSED */
static int
vhci_get_iocswitchdata(const void *data, sv_switch_to_cntlr_iocdata_t *piocsc,
    int mode, caddr_t s)
{
	int	retval = 0;

#ifdef  _MULTI_DATAMODEL
	switch (ddi_model_convert_from(mode & FMODELS)) {
	case DDI_MODEL_ILP32:
	{
		sv_switch_to_cntlr_iocdata32_t	ioc32;

		if (ddi_copyin(data, &ioc32, sizeof (ioc32), mode)) {
			retval = EFAULT;
			break;
		}
		piocsc->client	= (caddr_t)(uintptr_t)ioc32.client;
		piocsc->class	= (caddr_t)(uintptr_t)ioc32.class;
		break;
	}

	case DDI_MODEL_NONE:
		if (ddi_copyin(data, piocsc, sizeof (*piocsc), mode)) {
			retval = EFAULT;
		}
		break;
	}
#else   /* _MULTI_DATAMODEL */
	if (ddi_copyin(data, piocsc, sizeof (*piocsc), mode)) {
		retval = EFAULT;
	}
#endif  /* _MULTI_DATAMODEL */

#ifdef DEBUG
	if (retval) {
		VHCI_DEBUG(2, (CE_WARN, NULL, "!vhci_get_ioc: cmd <%s> "
		    "switch_to_cntlr_iocdata copyin failed", s));
	}
#endif

	return (retval);
}


/*
 * Routine to allocate memory for the path information structures.
 * It allocates two chunks of memory - one for keeping userland
 * pointers/values for path information and path properties, second for
 * keeping allocating kernel memory for path properties. These path
 * properties are finally copied to userland.
 */
/* ARGSUSED */
static int
vhci_ioc_alloc_pathinfo(sv_path_info_t **upibuf, sv_path_info_t **kpibuf,
    uint_t num_paths, sv_iocdata_t *pioc, int mode, caddr_t s)
{
	sv_path_info_t	*pi;
	uint_t		bufsize;
	int		retval = 0;
	int		index;

	/* Allocate memory */
	*upibuf = (sv_path_info_t *)
	    kmem_zalloc(sizeof (sv_path_info_t) * num_paths, KM_SLEEP);
	ASSERT(*upibuf != NULL);
	*kpibuf = (sv_path_info_t *)
	    kmem_zalloc(sizeof (sv_path_info_t) * num_paths, KM_SLEEP);
	ASSERT(*kpibuf != NULL);

	/*
	 * Get the path info structure from the user space.
	 * We are interested in the following fields:
	 *	- user size of buffer for per path properties.
	 *	- user address of buffer for path info properties.
	 *	- user pointer for returning actual buffer size
	 * Keep these fields in the 'upibuf' structures.
	 * Allocate buffer for per path info properties in kernel
	 * structure ('kpibuf').
	 * Size of these buffers will be equal to the size of buffers
	 * in the user space.
	 */
#ifdef  _MULTI_DATAMODEL
	switch (ddi_model_convert_from(mode & FMODELS)) {
	case DDI_MODEL_ILP32:
	{
		sv_path_info32_t	*src;
		sv_path_info32_t	pi32;

		src  = (sv_path_info32_t *)pioc->ret_buf;
		pi = (sv_path_info_t *)*upibuf;
		for (index = 0; index < num_paths; index++, src++, pi++) {
			if (ddi_copyin(src, &pi32, sizeof (pi32), mode)) {
				retval = EFAULT;
				break;
			}

			pi->ret_prop.buf_size	=
			    (uint_t)pi32.ret_prop.buf_size;
			pi->ret_prop.ret_buf_size =
			    (uint_t *)(uintptr_t)pi32.ret_prop.ret_buf_size;
			pi->ret_prop.buf	=
			    (caddr_t)(uintptr_t)pi32.ret_prop.buf;
		}
		break;
	}

	case DDI_MODEL_NONE:
		if (ddi_copyin(pioc->ret_buf, *upibuf,
		    sizeof (sv_path_info_t) * num_paths, mode)) {
			retval = EFAULT;
		}
		break;
	}
#else   /* _MULTI_DATAMODEL */
	if (ddi_copyin(pioc->ret_buf, *upibuf,
	    sizeof (sv_path_info_t) * num_paths, mode)) {
		retval = EFAULT;
	}
#endif  /* _MULTI_DATAMODEL */

	if (retval != 0) {
		VHCI_DEBUG(2, (CE_WARN, NULL, "!vhci_alloc_path_info: "
		    "ioctl <%s> normal: path_info copyin failed", s));
		kmem_free(*upibuf, sizeof (sv_path_info_t) * num_paths);
		kmem_free(*kpibuf, sizeof (sv_path_info_t) * num_paths);
		*upibuf = NULL;
		*kpibuf = NULL;
		return (retval);
	}

	/*
	 * Allocate memory for per path properties.
	 */
	for (index = 0, pi = *kpibuf; index < num_paths; index++, pi++) {
		bufsize = (*upibuf)[index].ret_prop.buf_size;

		if (bufsize && bufsize <= SV_PROP_MAX_BUF_SIZE) {
			pi->ret_prop.buf_size = bufsize;
			pi->ret_prop.buf = (caddr_t)
			    kmem_zalloc(bufsize, KM_SLEEP);
			ASSERT(pi->ret_prop.buf != NULL);
		} else {
			pi->ret_prop.buf_size = 0;
			pi->ret_prop.buf = NULL;
		}

		if ((*upibuf)[index].ret_prop.ret_buf_size != NULL) {
			pi->ret_prop.ret_buf_size = (uint_t *)kmem_zalloc(
			    sizeof (*pi->ret_prop.ret_buf_size), KM_SLEEP);
			ASSERT(pi->ret_prop.ret_buf_size != NULL);
		} else {
			pi->ret_prop.ret_buf_size = NULL;
		}
	}

	return (0);
}


/*
 * Routine to free memory for the path information structures.
 * This is the memory which was allocated earlier.
 */
/* ARGSUSED */
static void
vhci_ioc_free_pathinfo(sv_path_info_t *upibuf, sv_path_info_t *kpibuf,
    uint_t num_paths)
{
	sv_path_info_t	*pi;
	int		index;

	/* Free memory for per path properties */
	for (index = 0, pi = kpibuf; index < num_paths; index++, pi++) {
		if (pi->ret_prop.ret_buf_size != NULL) {
			kmem_free(pi->ret_prop.ret_buf_size,
			    sizeof (*pi->ret_prop.ret_buf_size));
		}

		if (pi->ret_prop.buf != NULL) {
			kmem_free(pi->ret_prop.buf, pi->ret_prop.buf_size);
		}
	}

	/* Free memory for path info structures */
	kmem_free(upibuf, sizeof (sv_path_info_t) * num_paths);
	kmem_free(kpibuf, sizeof (sv_path_info_t) * num_paths);
}


/*
 * Routine to copy path information and path properties to userland.
 */
/* ARGSUSED */
static int
vhci_ioc_send_pathinfo(sv_path_info_t *upibuf, sv_path_info_t *kpibuf,
    uint_t num_paths, sv_iocdata_t *pioc, int mode, caddr_t s)
{
	int			retval = 0, index;
	sv_path_info_t		*upi_ptr;
	sv_path_info32_t	*upi32_ptr;

#ifdef  _MULTI_DATAMODEL
	switch (ddi_model_convert_from(mode & FMODELS)) {
	case DDI_MODEL_ILP32:
		goto copy_32bit;

	case DDI_MODEL_NONE:
		goto copy_normal;
	}
#else   /* _MULTI_DATAMODEL */

	goto copy_normal;

#endif  /* _MULTI_DATAMODEL */

copy_normal:

	/*
	 * Copy path information and path properties to user land.
	 * Pointer fields inside the path property structure were
	 * saved in the 'upibuf' structure earlier.
	 */
	upi_ptr = pioc->ret_buf;
	for (index = 0; index < num_paths; index++) {
		if (ddi_copyout(kpibuf[index].device.ret_ct,
		    upi_ptr[index].device.ret_ct, MAXPATHLEN, mode)) {
			retval = EFAULT;
			break;
		}

		if (ddi_copyout(kpibuf[index].ret_addr,
		    upi_ptr[index].ret_addr, MAXNAMELEN, mode)) {
			retval = EFAULT;
			break;
		}

		if (ddi_copyout(&kpibuf[index].ret_state,
		    &upi_ptr[index].ret_state, sizeof (kpibuf[index].ret_state),
		    mode)) {
			retval = EFAULT;
			break;
		}

		if (ddi_copyout(&kpibuf[index].ret_ext_state,
		    &upi_ptr[index].ret_ext_state,
		    sizeof (kpibuf[index].ret_ext_state), mode)) {
			retval = EFAULT;
			break;
		}

		if ((kpibuf[index].ret_prop.ret_buf_size != NULL) &&
		    ddi_copyout(kpibuf[index].ret_prop.ret_buf_size,
		    upibuf[index].ret_prop.ret_buf_size,
		    sizeof (*upibuf[index].ret_prop.ret_buf_size), mode)) {
			retval = EFAULT;
			break;
		}

		if ((kpibuf[index].ret_prop.buf != NULL) &&
		    ddi_copyout(kpibuf[index].ret_prop.buf,
		    upibuf[index].ret_prop.buf,
		    upibuf[index].ret_prop.buf_size, mode)) {
			retval = EFAULT;
			break;
		}
	}

#ifdef DEBUG
	if (retval) {
		VHCI_DEBUG(2, (CE_WARN, NULL, "!vhci_get_ioc: ioctl <%s> "
		    "normal: path_info copyout failed", s));
	}
#endif

	return (retval);

copy_32bit:
	/*
	 * Copy path information and path properties to user land.
	 * Pointer fields inside the path property structure were
	 * saved in the 'upibuf' structure earlier.
	 */
	upi32_ptr = (sv_path_info32_t *)pioc->ret_buf;
	for (index = 0; index < num_paths; index++) {
		if (ddi_copyout(kpibuf[index].device.ret_ct,
		    upi32_ptr[index].device.ret_ct, MAXPATHLEN, mode)) {
			retval = EFAULT;
			break;
		}

		if (ddi_copyout(kpibuf[index].ret_addr,
		    upi32_ptr[index].ret_addr, MAXNAMELEN, mode)) {
			retval = EFAULT;
			break;
		}

		if (ddi_copyout(&kpibuf[index].ret_state,
		    &upi32_ptr[index].ret_state,
		    sizeof (kpibuf[index].ret_state), mode)) {
			retval = EFAULT;
			break;
		}

		if (ddi_copyout(&kpibuf[index].ret_ext_state,
		    &upi32_ptr[index].ret_ext_state,
		    sizeof (kpibuf[index].ret_ext_state), mode)) {
			retval = EFAULT;
			break;
		}
		if ((kpibuf[index].ret_prop.ret_buf_size != NULL) &&
		    ddi_copyout(kpibuf[index].ret_prop.ret_buf_size,
		    upibuf[index].ret_prop.ret_buf_size,
		    sizeof (*upibuf[index].ret_prop.ret_buf_size), mode)) {
			retval = EFAULT;
			break;
		}

		if ((kpibuf[index].ret_prop.buf != NULL) &&
		    ddi_copyout(kpibuf[index].ret_prop.buf,
		    upibuf[index].ret_prop.buf,
		    upibuf[index].ret_prop.buf_size, mode)) {
			retval = EFAULT;
			break;
		}
	}

#ifdef DEBUG
	if (retval) {
		VHCI_DEBUG(2, (CE_WARN, NULL, "!vhci_get_ioc: ioctl <%s> "
		    "normal: path_info copyout failed", s));
	}
#endif

	return (retval);
}


/*
 * vhci_failover()
 * This routine expects VHCI_HOLD_LUN before being invoked.  It can be invoked
 * as MDI_FAILOVER_ASYNC or MDI_FAILOVER_SYNC.  For Asynchronous failovers
 * this routine shall VHCI_RELEASE_LUN on exiting.  For synchronous failovers
 * it is the callers responsibility to release lun.
 */

/* ARGSUSED */
static int
vhci_failover(dev_info_t *vdip, dev_info_t *cdip, int flags)
{
	char			*guid;
	scsi_vhci_lun_t		*vlun = NULL;
	struct scsi_vhci	*vhci;
	mdi_pathinfo_t		*pip, *npip;
	char			*s_pclass, *pclass1, *pclass2, *pclass;
	char			active_pclass_copy[255], *active_pclass_ptr;
	char			*ptr1, *ptr2;
	mdi_pathinfo_state_t	pi_state;
	uint32_t		pi_ext_state;
	scsi_vhci_priv_t	*svp;
	struct scsi_device	*sd;
	struct scsi_failover_ops	*sfo;
	int			sps; /* mdi_select_path() status */
	int			activation_done = 0;
	int			rval, retval = MDI_FAILURE;
	int			reserve_pending, check_condition, UA_condition;
	struct scsi_pkt		*pkt;
	struct buf		*bp;

	vhci = ddi_get_soft_state(vhci_softstate, ddi_get_instance(vdip));
	sd = ddi_get_driver_private(cdip);
	vlun = ADDR2VLUN(&sd->sd_address);
	ASSERT(vlun != 0);
	ASSERT(VHCI_LUN_IS_HELD(vlun));
	guid = vlun->svl_lun_wwn;
	VHCI_DEBUG(1, (CE_NOTE, NULL, "!vhci_failover(1): guid %s\n", guid));
	vhci_log(CE_NOTE, vdip, "!Initiating failover for device %s "
	    "(GUID %s)", ddi_node_name(cdip), guid);

	/*
	 * Lets maintain a local copy of the vlun->svl_active_pclass
	 * for the rest of the processing. Accessing the field
	 * directly in the loop below causes loop logic to break
	 * especially when the field gets updated by other threads
	 * update path status etc and causes 'paths are not currently
	 * available' condition to be declared prematurely.
	 */
	mutex_enter(&vlun->svl_mutex);
	if (vlun->svl_active_pclass != NULL) {
		(void) strlcpy(active_pclass_copy, vlun->svl_active_pclass,
		    sizeof (active_pclass_copy));
		active_pclass_ptr = &active_pclass_copy[0];
		mutex_exit(&vlun->svl_mutex);
		if (vhci_quiesce_paths(vdip, cdip, vlun, guid,
		    active_pclass_ptr) != 0) {
			retval = MDI_FAILURE;
		}
	} else {
		/*
		 * can happen only when the available path to device
		 * discovered is a STANDBY path.
		 */
		mutex_exit(&vlun->svl_mutex);
		active_pclass_copy[0] = '\0';
		active_pclass_ptr = NULL;
	}

	sfo = vlun->svl_fops;
	ASSERT(sfo != NULL);
	pclass1 = s_pclass = active_pclass_ptr;
	VHCI_DEBUG(1, (CE_NOTE, NULL, "!(%s)failing over from %s\n", guid,
	    (s_pclass == NULL ? "<none>" : s_pclass)));

next_pathclass:

	rval = sfo->sfo_pathclass_next(pclass1, &pclass2,
	    vlun->svl_fops_ctpriv);
	if (rval == ENOENT) {
		if (s_pclass == NULL) {
			VHCI_DEBUG(1, (CE_NOTE, NULL, "!vhci_failover(4)(%s): "
			    "failed, no more pathclasses\n", guid));
			goto done;
		} else {
			(void) sfo->sfo_pathclass_next(NULL, &pclass2,
			    vlun->svl_fops_ctpriv);
		}
	} else if (rval == EINVAL) {
		vhci_log(CE_NOTE, vdip, "!Failover operation failed for "
		    "device %s (GUID %s): Invalid path-class %s",
		    ddi_node_name(cdip), guid,
		    ((pclass1 == NULL) ? "<none>" : pclass1));
		goto done;
	}
	if ((s_pclass != NULL) && (strcmp(pclass2, s_pclass) == 0)) {
		/*
		 * paths are not currently available
		 */
		vhci_log(CE_NOTE, vdip, "!Failover path currently unavailable"
		    " for device %s (GUID %s)",
		    ddi_node_name(cdip), guid);
		goto done;
	}
	pip = npip = NULL;
	VHCI_DEBUG(1, (CE_NOTE, NULL, "!vhci_failover(5.2)(%s): considering "
	    "%s as failover destination\n", guid, pclass2));
	sps = mdi_select_path(cdip, NULL, MDI_SELECT_STANDBY_PATH, NULL, &npip);
	if ((npip == NULL) || (sps != MDI_SUCCESS)) {
		VHCI_DEBUG(1, (CE_NOTE, NULL, "!vhci_failover(%s): no "
		    "STANDBY paths found (status:%x)!\n", guid, sps));
		pclass1 = pclass2;
		goto next_pathclass;
	}
	do {
		pclass = NULL;
		if ((mdi_prop_lookup_string(npip, "path-class",
		    &pclass) != MDI_SUCCESS) || (strcmp(pclass2,
		    pclass) != 0)) {
			VHCI_DEBUG(1, (CE_NOTE, NULL,
			    "!vhci_failover(5.5)(%s): skipping path "
			    "%p(%s)...\n", guid, (void *)npip, pclass));
			pip = npip;
			sps = mdi_select_path(cdip, NULL,
			    MDI_SELECT_STANDBY_PATH, pip, &npip);
			mdi_rele_path(pip);
			(void) mdi_prop_free(pclass);
			continue;
		}
		svp = (scsi_vhci_priv_t *)mdi_pi_get_vhci_private(npip);

		/*
		 * Issue READ at non-zer block on this STANDBY path.
		 * Purple returns
		 * 1. RESERVATION_CONFLICT if reservation is pending
		 * 2. POR check condition if it reset happened.
		 * 2. failover Check Conditions if one is already in progress.
		 */
		reserve_pending = 0;
		check_condition = 0;
		UA_condition = 0;

		bp = scsi_alloc_consistent_buf(&svp->svp_psd->sd_address,
		    (struct buf *)NULL, DEV_BSIZE, B_READ, NULL, NULL);
		if (!bp) {
			VHCI_DEBUG(1, (CE_NOTE, NULL,
			    "vhci_failover !No resources (buf)\n"));
			mdi_rele_path(npip);
			goto done;
		}
		pkt = scsi_init_pkt(&svp->svp_psd->sd_address, NULL, bp,
		    CDB_GROUP1, sizeof (struct scsi_arq_status), 0,
		    PKT_CONSISTENT, NULL, NULL);
		if (pkt) {
			(void) scsi_setup_cdb((union scsi_cdb *)(uintptr_t)
			    pkt->pkt_cdbp, SCMD_READ, 1, 1, 0);
			pkt->pkt_flags = FLAG_NOINTR;
check_path_again:
			pkt->pkt_path_instance = mdi_pi_get_path_instance(npip);
			pkt->pkt_time = 3*30;

			if (scsi_transport(pkt) == TRAN_ACCEPT) {
				switch (pkt->pkt_reason) {
				case CMD_CMPLT:
					switch (SCBP_C(pkt)) {
					case STATUS_GOOD:
						/* Already failed over */
						activation_done = 1;
						break;
					case STATUS_RESERVATION_CONFLICT:
						reserve_pending = 1;
						break;
					case STATUS_CHECK:
						check_condition = 1;
						break;
					}
				}
			}
			if (check_condition &&
			    (pkt->pkt_state & STATE_ARQ_DONE)) {
				uint8_t *sns, skey, asc, ascq;
				sns = (uint8_t *)
				    &(((struct scsi_arq_status *)(uintptr_t)
				    (pkt->pkt_scbp))->sts_sensedata);
				skey = scsi_sense_key(sns);
				asc = scsi_sense_asc(sns);
				ascq = scsi_sense_ascq(sns);
				if (skey == KEY_UNIT_ATTENTION &&
				    asc == 0x29) {
					/* Already failed over */
					VHCI_DEBUG(1, (CE_NOTE, NULL,
					    "!vhci_failover(7)(%s): "
					    "path 0x%p POR UA condition\n",
					    guid, (void *)npip));
					if (UA_condition == 0) {
						UA_condition = 1;
						goto check_path_again;
					}
				} else {
					activation_done = 0;
					VHCI_DEBUG(1, (CE_NOTE, NULL,
					    "!vhci_failover(%s): path 0x%p "
					    "unhandled chkcond %x %x %x\n",
					    guid, (void *)npip, skey,
					    asc, ascq));
				}
			}
			scsi_destroy_pkt(pkt);
		}
		scsi_free_consistent_buf(bp);

		if (activation_done) {
			mdi_rele_path(npip);
			VHCI_DEBUG(1, (CE_NOTE, NULL, "!vhci_failover(7)(%s): "
			    "path 0x%p already failedover\n", guid,
			    (void *)npip));
			break;
		}
		if (reserve_pending && (vlun->svl_xlf_capable == 0)) {
			(void) vhci_recovery_reset(vlun,
			    &svp->svp_psd->sd_address,
			    FALSE, VHCI_DEPTH_ALL);
		}
		VHCI_DEBUG(1, (CE_NOTE, NULL, "!vhci_failover(6)(%s): "
		    "activating path 0x%p(psd:%p)\n", guid, (void *)npip,
		    (void *)svp->svp_psd));
		if (sfo->sfo_path_activate(svp->svp_psd, pclass2,
		    vlun->svl_fops_ctpriv) == 0) {
			activation_done = 1;
			mdi_rele_path(npip);
			VHCI_DEBUG(1, (CE_NOTE, NULL, "!vhci_failover(7)(%s): "
			    "path 0x%p successfully activated\n", guid,
			    (void *)npip));
			break;
		}
		pip = npip;
		sps = mdi_select_path(cdip, NULL, MDI_SELECT_STANDBY_PATH,
		    pip, &npip);
		mdi_rele_path(pip);
	} while ((npip != NULL) && (sps == MDI_SUCCESS));
	if (activation_done == 0) {
		pclass1 = pclass2;
		goto next_pathclass;
	}

	/*
	 * if we are here, we have succeeded in activating path npip of
	 * pathclass pclass2; let us validate all paths of pclass2 by
	 * "ping"-ing each one and mark the good ones ONLINE
	 * Also, set the state of the paths belonging to the previously
	 * active pathclass to STANDBY
	 */
	pip = npip = NULL;
	sps = mdi_select_path(cdip, NULL, (MDI_SELECT_ONLINE_PATH |
	    MDI_SELECT_STANDBY_PATH | MDI_SELECT_USER_DISABLE_PATH),
	    NULL, &npip);
	if (npip == NULL || sps != MDI_SUCCESS) {
		VHCI_DEBUG(1, (CE_NOTE, NULL, "!Failover operation failed for "
		    "device %s (GUID %s): paths may be busy\n",
		    ddi_node_name(cdip), guid));
		goto done;
	}
	do {
		(void) mdi_pi_get_state2(npip, &pi_state, &pi_ext_state);
		if (mdi_prop_lookup_string(npip, "path-class", &pclass)
		    != MDI_SUCCESS) {
			pip = npip;
			sps = mdi_select_path(cdip, NULL,
			    (MDI_SELECT_ONLINE_PATH |
			    MDI_SELECT_STANDBY_PATH |
			    MDI_SELECT_USER_DISABLE_PATH),
			    pip, &npip);
			mdi_rele_path(pip);
			continue;
		}
		if (strcmp(pclass, pclass2) == 0) {
			if (pi_state == MDI_PATHINFO_STATE_STANDBY) {
				svp = (scsi_vhci_priv_t *)
				    mdi_pi_get_vhci_private(npip);
				VHCI_DEBUG(1, (CE_NOTE, NULL,
				    "!vhci_failover(8)(%s): "
				    "pinging path 0x%p\n",
				    guid, (void *)npip));
				if (sfo->sfo_path_ping(svp->svp_psd,
				    vlun->svl_fops_ctpriv) == 1) {
					mdi_pi_set_state(npip,
					    MDI_PATHINFO_STATE_ONLINE);
					VHCI_DEBUG(1, (CE_NOTE, NULL,
					    "!vhci_failover(9)(%s): "
					    "path 0x%p ping successful, "
					    "marked online\n", guid,
					    (void *)npip));
					MDI_PI_ERRSTAT(npip, MDI_PI_FAILTO);
				}
			}
		} else if ((s_pclass != NULL) && (strcmp(pclass, s_pclass)
		    == 0)) {
			if (pi_state == MDI_PATHINFO_STATE_ONLINE) {
				mdi_pi_set_state(npip,
				    MDI_PATHINFO_STATE_STANDBY);
				VHCI_DEBUG(1, (CE_NOTE, NULL,
				    "!vhci_failover(10)(%s): path 0x%p marked "
				    "STANDBY\n", guid, (void *)npip));
				MDI_PI_ERRSTAT(npip, MDI_PI_FAILFROM);
			}
		}
		(void) mdi_prop_free(pclass);
		pip = npip;
		sps = mdi_select_path(cdip, NULL, (MDI_SELECT_ONLINE_PATH |
		    MDI_SELECT_STANDBY_PATH|MDI_SELECT_USER_DISABLE_PATH),
		    pip, &npip);
		mdi_rele_path(pip);
	} while ((npip != NULL) && (sps == MDI_SUCCESS));

	/*
	 * Update the AccessState of related MP-API TPGs
	 */
	(void) vhci_mpapi_update_tpg_acc_state_for_lu(vhci, vlun);

	vhci_log(CE_NOTE, vdip, "!Failover operation completed successfully "
	    "for device %s (GUID %s): failed over from %s to %s",
	    ddi_node_name(cdip), guid, ((s_pclass == NULL) ? "<none>" :
	    s_pclass), pclass2);
	ptr1 = kmem_alloc(strlen(pclass2)+1, KM_SLEEP);
	(void) strlcpy(ptr1, pclass2, (strlen(pclass2)+1));
	mutex_enter(&vlun->svl_mutex);
	ptr2 = vlun->svl_active_pclass;
	vlun->svl_active_pclass = ptr1;
	mutex_exit(&vlun->svl_mutex);
	if (ptr2) {
		kmem_free(ptr2, strlen(ptr2)+1);
	}
	mutex_enter(&vhci->vhci_mutex);
	scsi_hba_reset_notify_callback(&vhci->vhci_mutex,
	    &vhci->vhci_reset_notify_listf);
	/* All reservations are cleared upon these resets. */
	vlun->svl_flags &= ~VLUN_RESERVE_ACTIVE_FLG;
	mutex_exit(&vhci->vhci_mutex);
	VHCI_DEBUG(1, (CE_NOTE, NULL, "!vhci_failover(11): DONE! Active "
	    "pathclass for %s is now %s\n", guid, pclass2));
	retval = MDI_SUCCESS;

done:
	vlun->svl_failover_status = retval;
	if (flags == MDI_FAILOVER_ASYNC) {
		VHCI_RELEASE_LUN(vlun);
		VHCI_DEBUG(6, (CE_NOTE, NULL, "!vhci_failover(12): DONE! "
		    "releasing lun, as failover was ASYNC\n"));
	} else {
		VHCI_DEBUG(6, (CE_NOTE, NULL, "!vhci_failover(12): DONE! "
		    "NOT releasing lun, as failover was SYNC\n"));
	}
	return (retval);
}

/*
 * vhci_client_attached is called after the successful attach of a
 * client devinfo node.
 */
static void
vhci_client_attached(dev_info_t *cdip)
{
	mdi_pathinfo_t	*pip;
	int		circular;

	/*
	 * At this point the client has attached and it's instance number is
	 * valid, so we can set up kstats.  We need to do this here because it
	 * is possible for paths to go online prior to client attach, in which
	 * case the call to vhci_kstat_create_pathinfo in vhci_pathinfo_online
	 * was a noop.
	 */
	ndi_devi_enter(cdip, &circular);
	for (pip = mdi_get_next_phci_path(cdip, NULL); pip;
	    pip = mdi_get_next_phci_path(cdip, pip))
		vhci_kstat_create_pathinfo(pip);
	ndi_devi_exit(cdip, circular);
}

/*
 * quiesce all of the online paths
 */
static int
vhci_quiesce_paths(dev_info_t *vdip, dev_info_t *cdip, scsi_vhci_lun_t *vlun,
	char *guid, char *active_pclass_ptr)
{
	scsi_vhci_priv_t	*svp;
	char			*s_pclass = NULL;
	mdi_pathinfo_t		*npip, *pip;
	int			sps;

	/* quiesce currently active paths */
	s_pclass = NULL;
	pip = npip = NULL;
	sps = mdi_select_path(cdip, NULL, MDI_SELECT_ONLINE_PATH, NULL, &npip);
	if ((npip == NULL) || (sps != MDI_SUCCESS)) {
		return (1);
	}
	do {
		if (mdi_prop_lookup_string(npip, "path-class",
		    &s_pclass) != MDI_SUCCESS) {
			mdi_rele_path(npip);
			vhci_log(CE_NOTE, vdip, "!Failover operation failed "
			    "for device %s (GUID %s) due to an internal "
			    "error", ddi_node_name(cdip), guid);
			return (1);
		}
		if (strcmp(s_pclass, active_pclass_ptr) == 0) {
			/*
			 * quiesce path. Free s_pclass since
			 * we don't need it anymore
			 */
			VHCI_DEBUG(1, (CE_NOTE, NULL,
			    "!vhci_failover(2)(%s): failing over "
			    "from %s; quiescing path %p\n",
			    guid, s_pclass, (void *)npip));
			(void) mdi_prop_free(s_pclass);
			svp = (scsi_vhci_priv_t *)
			    mdi_pi_get_vhci_private(npip);
			if (svp == NULL) {
				VHCI_DEBUG(1, (CE_NOTE, NULL,
				    "!vhci_failover(2.5)(%s): no "
				    "client priv! %p offlined?\n",
				    guid, (void *)npip));
				pip = npip;
				sps = mdi_select_path(cdip, NULL,
				    MDI_SELECT_ONLINE_PATH, pip, &npip);
				mdi_rele_path(pip);
				continue;
			}
			if (scsi_abort(&svp->svp_psd->sd_address, NULL)
			    == 0) {
				(void) vhci_recovery_reset(vlun,
				    &svp->svp_psd->sd_address, FALSE,
				    VHCI_DEPTH_TARGET);
			}
			mutex_enter(&svp->svp_mutex);
			if (svp->svp_cmds == 0) {
				VHCI_DEBUG(1, (CE_NOTE, NULL,
				    "!vhci_failover(3)(%s):"
				    "quiesced path %p\n", guid, (void *)npip));
			} else {
				while (svp->svp_cmds != 0) {
					cv_wait(&svp->svp_cv, &svp->svp_mutex);
					VHCI_DEBUG(1, (CE_NOTE, NULL,
					    "!vhci_failover(3.cv)(%s):"
					    "quiesced path %p\n", guid,
					    (void *)npip));
				}
			}
			mutex_exit(&svp->svp_mutex);
		} else {
			/*
			 * make sure we freeup the memory
			 */
			(void) mdi_prop_free(s_pclass);
		}
		pip = npip;
		sps = mdi_select_path(cdip, NULL, MDI_SELECT_ONLINE_PATH,
		    pip, &npip);
		mdi_rele_path(pip);
	} while ((npip != NULL) && (sps == MDI_SUCCESS));
	return (0);
}

static struct scsi_vhci_lun *
vhci_lun_lookup(dev_info_t *tgt_dip)
{
	return ((struct scsi_vhci_lun *)
	    mdi_client_get_vhci_private(tgt_dip));
}

static struct scsi_vhci_lun *
vhci_lun_lookup_alloc(dev_info_t *tgt_dip, char *guid, int *didalloc)
{
	struct scsi_vhci_lun *svl;

	if (svl = vhci_lun_lookup(tgt_dip)) {
		return (svl);
	}

	svl = kmem_zalloc(sizeof (*svl), KM_SLEEP);
	svl->svl_lun_wwn = kmem_zalloc(strlen(guid)+1, KM_SLEEP);
	(void) strcpy(svl->svl_lun_wwn,  guid);
	mutex_init(&svl->svl_mutex, NULL, MUTEX_DRIVER, NULL);
	cv_init(&svl->svl_cv, NULL, CV_DRIVER, NULL);
	sema_init(&svl->svl_pgr_sema, 1, NULL, SEMA_DRIVER, NULL);
	svl->svl_waiting_for_activepath = 1;
	svl->svl_sector_size = 1;
	mdi_client_set_vhci_private(tgt_dip, svl);
	*didalloc = 1;
	VHCI_DEBUG(1, (CE_NOTE, NULL,
	    "vhci_lun_lookup_alloc: guid %s vlun 0x%p\n",
	    guid, (void *)svl));
	return (svl);
}

static void
vhci_lun_free(struct scsi_vhci_lun *dvlp, struct scsi_device *sd)
{
	char *guid;

	guid = dvlp->svl_lun_wwn;
	ASSERT(guid != NULL);
	VHCI_DEBUG(4, (CE_NOTE, NULL, "!vhci_lun_free: %s\n", guid));

	mutex_enter(&dvlp->svl_mutex);
	if (dvlp->svl_active_pclass != NULL) {
		kmem_free(dvlp->svl_active_pclass,
		    strlen(dvlp->svl_active_pclass)+1);
	}
	dvlp->svl_active_pclass = NULL;
	mutex_exit(&dvlp->svl_mutex);

	if (dvlp->svl_lun_wwn != NULL) {
		kmem_free(dvlp->svl_lun_wwn, strlen(dvlp->svl_lun_wwn)+1);
	}
	dvlp->svl_lun_wwn = NULL;

	if (dvlp->svl_fops_name) {
		kmem_free(dvlp->svl_fops_name, strlen(dvlp->svl_fops_name)+1);
	}
	dvlp->svl_fops_name = NULL;

	if (dvlp->svl_fops_ctpriv != NULL &&
	    dvlp->svl_fops != NULL) {
		dvlp->svl_fops->sfo_device_unprobe(sd, dvlp->svl_fops_ctpriv);
	}

	if (dvlp->svl_flags & VLUN_TASK_D_ALIVE_FLG)
		taskq_destroy(dvlp->svl_taskq);

	mutex_destroy(&dvlp->svl_mutex);
	cv_destroy(&dvlp->svl_cv);
	sema_destroy(&dvlp->svl_pgr_sema);
	kmem_free(dvlp, sizeof (*dvlp));
	/*
	 * vhci_lun_free may be called before the tgt_dip
	 * initialization so check if the sd is NULL.
	 */
	if (sd != NULL)
		scsi_device_hba_private_set(sd, NULL);
}

int
vhci_do_scsi_cmd(struct scsi_pkt *pkt)
{
	int	err = 0;
	int	retry_cnt = 0;
	uint8_t	*sns, skey;

#ifdef DEBUG
	if (vhci_debug > 5) {
		vhci_print_cdb(pkt->pkt_address.a_hba_tran->tran_hba_dip,
		    CE_WARN, "Vhci command", pkt->pkt_cdbp);
	}
#endif

retry:
	err = scsi_poll(pkt);
	if (err) {
		if (pkt->pkt_cdbp[0] == SCMD_RELEASE) {
			if (SCBP_C(pkt) == STATUS_RESERVATION_CONFLICT) {
				VHCI_DEBUG(1, (CE_NOTE, NULL,
				    "!v_s_do_s_c: RELEASE conflict\n"));
				return (0);
			}
		}
		if (retry_cnt++ < 6) {
			VHCI_DEBUG(1, (CE_WARN, NULL,
			    "!v_s_do_s_c:retry packet 0x%p "
			    "status 0x%x reason %s",
			    (void *)pkt, SCBP_C(pkt),
			    scsi_rname(pkt->pkt_reason)));
			if ((pkt->pkt_reason == CMD_CMPLT) &&
			    (SCBP_C(pkt) == STATUS_CHECK) &&
			    (pkt->pkt_state & STATE_ARQ_DONE)) {
				sns = (uint8_t *)
				    &(((struct scsi_arq_status *)(uintptr_t)
				    (pkt->pkt_scbp))->sts_sensedata);
				skey = scsi_sense_key(sns);
				VHCI_DEBUG(1, (CE_WARN, NULL,
				    "!v_s_do_s_c:retry "
				    "packet 0x%p  sense data %s", (void *)pkt,
				    scsi_sname(skey)));
			}
			goto retry;
		}
		VHCI_DEBUG(1, (CE_WARN, NULL,
		    "!v_s_do_s_c: failed transport 0x%p 0x%x",
		    (void *)pkt, SCBP_C(pkt)));
		return (0);
	}

	switch (pkt->pkt_reason) {
		case CMD_TIMEOUT:
			VHCI_DEBUG(1, (CE_WARN, NULL, "!pkt timed "
			    "out (pkt 0x%p)", (void *)pkt));
			return (0);
		case CMD_CMPLT:
			switch (SCBP_C(pkt)) {
				case STATUS_GOOD:
					break;
				case STATUS_CHECK:
					if (pkt->pkt_state & STATE_ARQ_DONE) {
						sns = (uint8_t *)&(((
						    struct scsi_arq_status *)
						    (uintptr_t)
						    (pkt->pkt_scbp))->
						    sts_sensedata);
						skey = scsi_sense_key(sns);
						if ((skey ==
						    KEY_UNIT_ATTENTION) ||
						    (skey ==
						    KEY_NOT_READY)) {
							/*
							 * clear unit attn.
							 */

							VHCI_DEBUG(1,
							    (CE_WARN, NULL,
							    "!v_s_do_s_c: "
							    "retry "
							    "packet 0x%p sense "
							    "data %s",
							    (void *)pkt,
							    scsi_sname
							    (skey)));
							goto retry;
						}
						VHCI_DEBUG(4, (CE_WARN, NULL,
						    "!ARQ while "
						    "transporting "
						    "(pkt 0x%p)",
						    (void *)pkt));
						return (0);
					}
					return (0);
				default:
					VHCI_DEBUG(1, (CE_WARN, NULL,
					    "!Bad status returned "
					    "(pkt 0x%p, status %x)",
					    (void *)pkt, SCBP_C(pkt)));
					return (0);
			}
			break;
		case CMD_INCOMPLETE:
		case CMD_RESET:
		case CMD_ABORTED:
		case CMD_TRAN_ERR:
			if (retry_cnt++ < 1) {
				VHCI_DEBUG(1, (CE_WARN, NULL,
				    "!v_s_do_s_c: retry packet 0x%p %s",
				    (void *)pkt, scsi_rname(pkt->pkt_reason)));
				goto retry;
			}
			/* FALLTHROUGH */
		default:
			VHCI_DEBUG(1, (CE_WARN, NULL, "!pkt did not "
			    "complete successfully (pkt 0x%p,"
			    "reason %x)", (void *)pkt, pkt->pkt_reason));
			return (0);
	}
	return (1);
}

static int
vhci_quiesce_lun(struct scsi_vhci_lun *vlun)
{
	mdi_pathinfo_t		*pip, *spip;
	dev_info_t		*cdip;
	struct scsi_vhci_priv	*svp;
	mdi_pathinfo_state_t	pstate;
	uint32_t		p_ext_state;
	int			circular;

	cdip = vlun->svl_dip;
	pip = spip = NULL;
	ndi_devi_enter(cdip, &circular);
	pip = mdi_get_next_phci_path(cdip, NULL);
	while (pip != NULL) {
		(void) mdi_pi_get_state2(pip, &pstate, &p_ext_state);
		if (pstate != MDI_PATHINFO_STATE_ONLINE) {
			spip = pip;
			pip = mdi_get_next_phci_path(cdip, spip);
			continue;
		}
		mdi_hold_path(pip);
		ndi_devi_exit(cdip, circular);
		svp = (scsi_vhci_priv_t *)mdi_pi_get_vhci_private(pip);
		mutex_enter(&svp->svp_mutex);
		while (svp->svp_cmds != 0) {
			if (cv_reltimedwait(&svp->svp_cv, &svp->svp_mutex,
			    drv_usectohz(vhci_path_quiesce_timeout * 1000000),
			    TR_CLOCK_TICK) == -1) {
				mutex_exit(&svp->svp_mutex);
				mdi_rele_path(pip);
				VHCI_DEBUG(1, (CE_WARN, NULL,
				    "Quiesce of lun is not successful "
				    "vlun: 0x%p.", (void *)vlun));
				return (0);
			}
		}
		mutex_exit(&svp->svp_mutex);
		ndi_devi_enter(cdip, &circular);
		spip = pip;
		pip = mdi_get_next_phci_path(cdip, spip);
		mdi_rele_path(spip);
	}
	ndi_devi_exit(cdip, circular);
	return (1);
}

static int
vhci_pgr_validate_and_register(scsi_vhci_priv_t *svp)
{
	scsi_vhci_lun_t		*vlun;
	vhci_prout_t		*prout;
	int			rval, success;
	mdi_pathinfo_t		*pip, *npip;
	scsi_vhci_priv_t	*osvp;
	dev_info_t		*cdip;
	uchar_t			cdb_1;
	uchar_t			temp_res_key[MHIOC_RESV_KEY_SIZE];


	/*
	 * see if there are any other paths available; if none,
	 * then there is nothing to do.
	 */
	cdip = svp->svp_svl->svl_dip;
	rval = mdi_select_path(cdip, NULL, MDI_SELECT_ONLINE_PATH |
	    MDI_SELECT_STANDBY_PATH, NULL, &pip);
	if ((rval != MDI_SUCCESS) || (pip == NULL)) {
		VHCI_DEBUG(4, (CE_NOTE, NULL,
		    "%s%d: vhci_pgr_validate_and_register: first path\n",
		    ddi_driver_name(cdip), ddi_get_instance(cdip)));
		return (1);
	}

	vlun = svp->svp_svl;
	prout = &vlun->svl_prout;
	ASSERT(vlun->svl_pgr_active != 0);

	/*
	 * When the path was busy/offlined, some other host might have
	 * cleared this key. Validate key on some other path first.
	 * If it fails, return failure.
	 */

	npip = pip;
	pip = NULL;
	success = 0;

	/* Save the res key */
	bcopy(prout->res_key, temp_res_key, MHIOC_RESV_KEY_SIZE);

	/*
	 * Sometimes CDB from application can be a Register_And_Ignore.
	 * Instead of validation, this cdb would result in force registration.
	 * Convert it to normal cdb for validation.
	 * After that be sure to restore the cdb.
	 */
	cdb_1 = vlun->svl_cdb[1];
	vlun->svl_cdb[1] &= 0xe0;

	do {
		osvp = (scsi_vhci_priv_t *)mdi_pi_get_vhci_private(npip);
		if (osvp == NULL) {
			VHCI_DEBUG(4, (CE_NOTE, NULL,
			    "vhci_pgr_validate_and_register: no "
			    "client priv! 0x%p offlined?\n",
			    (void *)npip));
			goto next_path_1;
		}

		if (osvp == svp) {
			VHCI_DEBUG(4, (CE_NOTE, NULL,
			    "vhci_pgr_validate_and_register: same svp 0x%p"
			    " npip 0x%p vlun 0x%p\n",
			    (void *)svp, (void *)npip, (void *)vlun));
			goto next_path_1;
		}

		VHCI_DEBUG(4, (CE_NOTE, NULL,
		    "vhci_pgr_validate_and_register: First validate on"
		    " osvp 0x%p being done. vlun 0x%p thread 0x%p Before bcopy"
		    " cdb1 %x\n", (void *)osvp, (void *)vlun,
		    (void *)curthread, vlun->svl_cdb[1]));
		vhci_print_prout_keys(vlun, "v_pgr_val_reg: before bcopy:");

		bcopy(prout->service_key, prout->res_key, MHIOC_RESV_KEY_SIZE);

		VHCI_DEBUG(4, (CE_WARN, NULL, "vlun 0x%p After bcopy",
		    (void *)vlun));
		vhci_print_prout_keys(vlun, "v_pgr_val_reg: after bcopy: ");

		rval = vhci_do_prout(osvp);
		if (rval == 1) {
			VHCI_DEBUG(4, (CE_NOTE, NULL,
			    "%s%d: vhci_pgr_validate_and_register: key"
			    " validated thread 0x%p\n", ddi_driver_name(cdip),
			    ddi_get_instance(cdip), (void *)curthread));
			pip = npip;
			success = 1;
			break;
		} else {
			VHCI_DEBUG(4, (CE_NOTE, NULL,
			    "vhci_pgr_validate_and_register: First validation"
			    " on osvp 0x%p failed %x\n", (void *)osvp, rval));
			vhci_print_prout_keys(vlun, "v_pgr_val_reg: failed:");
		}

		/*
		 * Try other paths
		 */
next_path_1:
		pip = npip;
		rval = mdi_select_path(cdip, NULL,
		    MDI_SELECT_ONLINE_PATH|MDI_SELECT_STANDBY_PATH,
		    pip, &npip);
		mdi_rele_path(pip);
	} while ((rval == MDI_SUCCESS) && (npip != NULL));


	/* Be sure to restore original cdb */
	vlun->svl_cdb[1] = cdb_1;

	/* Restore the res_key */
	bcopy(temp_res_key, prout->res_key, MHIOC_RESV_KEY_SIZE);

	/*
	 * If key could not be registered on any path for the first time,
	 * return success as online should still continue.
	 */
	if (success == 0) {
		return (1);
	}

	ASSERT(pip != NULL);

	/*
	 * Force register on new path
	 */
	cdb_1 = vlun->svl_cdb[1];		/* store the cdb */

	vlun->svl_cdb[1] &= 0xe0;
	vlun->svl_cdb[1] |= VHCI_PROUT_R_AND_IGNORE;

	vhci_print_prout_keys(vlun, "v_pgr_val_reg: keys before bcopy: ");

	bcopy(prout->active_service_key, prout->service_key,
	    MHIOC_RESV_KEY_SIZE);
	bcopy(prout->active_res_key, prout->res_key, MHIOC_RESV_KEY_SIZE);

	vhci_print_prout_keys(vlun, "v_pgr_val_reg:keys after bcopy: ");

	rval = vhci_do_prout(svp);
	vlun->svl_cdb[1] = cdb_1;		/* restore the cdb */
	if (rval != 1) {
		VHCI_DEBUG(4, (CE_NOTE, NULL,
		    "vhci_pgr_validate_and_register: register on new"
		    " path 0x%p svp 0x%p failed %x\n",
		    (void *)pip, (void *)svp, rval));
		vhci_print_prout_keys(vlun, "v_pgr_val_reg: reg failed: ");
		mdi_rele_path(pip);
		return (0);
	}

	if (bcmp(prout->service_key, zero_key, MHIOC_RESV_KEY_SIZE) == 0) {
		VHCI_DEBUG(4, (CE_NOTE, NULL,
		    "vhci_pgr_validate_and_register: zero service key\n"));
		mdi_rele_path(pip);
		return (rval);
	}

	/*
	 * While the key was force registered, some other host might have
	 * cleared the key. Re-validate key on another pre-existing path
	 * before declaring success.
	 */
	npip = pip;
	pip = NULL;

	/*
	 * Sometimes CDB from application can be Register and Ignore.
	 * Instead of validation, it would result in force registration.
	 * Convert it to normal cdb for validation.
	 * After that be sure to restore the cdb.
	 */
	cdb_1 = vlun->svl_cdb[1];
	vlun->svl_cdb[1] &= 0xe0;
	success = 0;

	do {
		osvp = (scsi_vhci_priv_t *)
		    mdi_pi_get_vhci_private(npip);
		if (osvp == NULL) {
			VHCI_DEBUG(4, (CE_NOTE, NULL,
			    "vhci_pgr_validate_and_register: no "
			    "client priv! 0x%p offlined?\n",
			    (void *)npip));
			goto next_path_2;
		}

		if (osvp == svp) {
			VHCI_DEBUG(4, (CE_NOTE, NULL,
			    "vhci_pgr_validate_and_register: same osvp 0x%p"
			    " npip 0x%p vlun 0x%p\n",
			    (void *)svp, (void *)npip, (void *)vlun));
			goto next_path_2;
		}

		VHCI_DEBUG(4, (CE_NOTE, NULL,
		    "vhci_pgr_validate_and_register: Re-validation on"
		    " osvp 0x%p being done. vlun 0x%p Before bcopy cdb1 %x\n",
		    (void *)osvp, (void *)vlun, vlun->svl_cdb[1]));
		vhci_print_prout_keys(vlun, "v_pgr_val_reg: before bcopy: ");

		bcopy(prout->service_key, prout->res_key, MHIOC_RESV_KEY_SIZE);

		vhci_print_prout_keys(vlun, "v_pgr_val_reg: after bcopy: ");

		rval = vhci_do_prout(osvp);
		if (rval == 1) {
			VHCI_DEBUG(4, (CE_NOTE, NULL,
			    "%s%d: vhci_pgr_validate_and_register: key"
			    " validated thread 0x%p\n", ddi_driver_name(cdip),
			    ddi_get_instance(cdip), (void *)curthread));
			pip = npip;
			success = 1;
			break;
		} else {
			VHCI_DEBUG(4, (CE_NOTE, NULL,
			    "vhci_pgr_validate_and_register: Re-validation on"
			    " osvp 0x%p failed %x\n", (void *)osvp, rval));
			vhci_print_prout_keys(vlun,
			    "v_pgr_val_reg: reval failed: ");
		}

		/*
		 * Try other paths
		 */
next_path_2:
		pip = npip;
		rval = mdi_select_path(cdip, NULL,
		    MDI_SELECT_ONLINE_PATH|MDI_SELECT_STANDBY_PATH,
		    pip, &npip);
		mdi_rele_path(pip);
	} while ((rval == MDI_SUCCESS) && (npip != NULL));

	/* Be sure to restore original cdb */
	vlun->svl_cdb[1] = cdb_1;

	if (success == 1) {
		/* Successfully validated registration */
		mdi_rele_path(pip);
		return (1);
	}

	VHCI_DEBUG(4, (CE_WARN, NULL, "key validation failed"));

	/*
	 * key invalid, back out by registering key value of 0
	 */
	VHCI_DEBUG(4, (CE_NOTE, NULL,
	    "vhci_pgr_validate_and_register: backout on"
	    " svp 0x%p being done\n", (void *)svp));
	vhci_print_prout_keys(vlun, "v_pgr_val_reg: before bcopy: ");

	bcopy(prout->service_key, prout->res_key, MHIOC_RESV_KEY_SIZE);
	bzero(prout->service_key, MHIOC_RESV_KEY_SIZE);

	vhci_print_prout_keys(vlun, "v_pgr_val_reg: before bcopy: ");

	/*
	 * Get a new path
	 */
	rval = mdi_select_path(cdip, NULL, MDI_SELECT_ONLINE_PATH |
	    MDI_SELECT_STANDBY_PATH, NULL, &pip);
	if ((rval != MDI_SUCCESS) || (pip == NULL)) {
		VHCI_DEBUG(4, (CE_NOTE, NULL,
		    "%s%d: vhci_pgr_validate_and_register: no valid pip\n",
		    ddi_driver_name(cdip), ddi_get_instance(cdip)));
		return (0);
	}

	if ((rval = vhci_do_prout(svp)) != 1) {
		VHCI_DEBUG(4, (CE_NOTE, NULL,
		    "vhci_pgr_validate_and_register: backout on"
		    " svp 0x%p failed\n", (void *)svp));
		vhci_print_prout_keys(vlun, "backout failed");

		VHCI_DEBUG(4, (CE_WARN, NULL,
		    "%s%d: vhci_pgr_validate_and_register: key"
		    " validation and backout failed", ddi_driver_name(cdip),
		    ddi_get_instance(cdip)));
		if (rval == VHCI_PGR_ILLEGALOP) {
			VHCI_DEBUG(4, (CE_WARN, NULL,
			    "%s%d: vhci_pgr_validate_and_register: key"
			    " already cleared", ddi_driver_name(cdip),
			    ddi_get_instance(cdip)));
			rval = 1;
		} else
			rval = 0;
	} else {
		VHCI_DEBUG(4, (CE_NOTE, NULL,
		    "%s%d: vhci_pgr_validate_and_register: key"
		    " validation failed, key backed out\n",
		    ddi_driver_name(cdip), ddi_get_instance(cdip)));
		vhci_print_prout_keys(vlun, "v_pgr_val_reg: key backed out: ");
	}
	mdi_rele_path(pip);

	return (rval);
}

/*
 * taskq routine to dispatch a scsi cmd to vhci_scsi_start.  This ensures
 * that vhci_scsi_start is not called in interrupt context.
 * As the upper layer gets TRAN_ACCEPT when the command is dispatched, we
 * need to complete the command if something goes wrong.
 */
static void
vhci_dispatch_scsi_start(void *arg)
{
	struct vhci_pkt *vpkt	= (struct vhci_pkt *)arg;
	struct scsi_pkt *tpkt	= vpkt->vpkt_tgt_pkt;
	int rval		= TRAN_BUSY;

	VHCI_DEBUG(6, (CE_NOTE, NULL, "!vhci_dispatch_scsi_start: sending"
	    " scsi-2 reserve for 0x%p\n",
	    (void *)ADDR2DIP(&(vpkt->vpkt_tgt_pkt->pkt_address))));

	/*
	 * To prevent the taskq from being called recursively we set the
	 * the VHCI_PKT_THRU_TASKQ bit in the vhci_pkt_states.
	 */
	vpkt->vpkt_state |= VHCI_PKT_THRU_TASKQ;

	/*
	 * Wait for the transport to get ready to send packets
	 * and if it times out, it will return something other than
	 * TRAN_BUSY. The vhci_reserve_delay may want to
	 * get tuned for other transports and is therefore a global.
	 * Using delay since this routine is called by taskq dispatch
	 * and not called during interrupt context.
	 */
	while ((rval = vhci_scsi_start(&(vpkt->vpkt_tgt_pkt->pkt_address),
	    vpkt->vpkt_tgt_pkt)) == TRAN_BUSY) {
		delay(drv_usectohz(vhci_reserve_delay));
	}

	switch (rval) {
	case TRAN_ACCEPT:
		return;

	default:
		/*
		 * This pkt shall be retried, and to ensure another taskq
		 * is dispatched for it, clear the VHCI_PKT_THRU_TASKQ
		 * flag.
		 */
		vpkt->vpkt_state &= ~VHCI_PKT_THRU_TASKQ;

		/* Ensure that the pkt is retried without a reset */
		tpkt->pkt_reason = CMD_ABORTED;
		tpkt->pkt_statistics |= STAT_ABORTED;
		VHCI_DEBUG(1, (CE_WARN, NULL, "!vhci_dispatch_scsi_start: "
		    "TRAN_rval %d returned for dip 0x%p", rval,
		    (void *)ADDR2DIP(&(vpkt->vpkt_tgt_pkt->pkt_address))));
		break;
	}

	/*
	 * vpkt_org_vpkt should always be NULL here if the retry command
	 * has been successfully dispatched.  If vpkt_org_vpkt != NULL at
	 * this point, it is an error so restore the original vpkt and
	 * return an error to the target driver so it can retry the
	 * command as appropriate.
	 */
	if (vpkt->vpkt_org_vpkt != NULL) {
		struct vhci_pkt		*new_vpkt = vpkt;
		scsi_vhci_priv_t	*svp = (scsi_vhci_priv_t *)
		    mdi_pi_get_vhci_private(vpkt->vpkt_path);

		vpkt = vpkt->vpkt_org_vpkt;

		vpkt->vpkt_tgt_pkt->pkt_reason = tpkt->pkt_reason;
		vpkt->vpkt_tgt_pkt->pkt_statistics = tpkt->pkt_statistics;

		vhci_scsi_destroy_pkt(&svp->svp_psd->sd_address,
		    new_vpkt->vpkt_tgt_pkt);

		tpkt = vpkt->vpkt_tgt_pkt;
	}

	scsi_hba_pkt_comp(tpkt);
}

static void
vhci_initiate_auto_failback(void *arg)
{
	struct scsi_vhci_lun	*vlun = (struct scsi_vhci_lun *)arg;
	dev_info_t		*vdip, *cdip;
	int			held;

	cdip = vlun->svl_dip;
	vdip = ddi_get_parent(cdip);

	VHCI_HOLD_LUN(vlun, VH_SLEEP, held);

	/*
	 * Perform a final check to see if the active path class is indeed
	 * not the preferred path class.  As in the time the auto failback
	 * was dispatched, an external failover could have been detected.
	 * [Some other host could have detected this condition and triggered
	 *  the auto failback before].
	 * In such a case if we go ahead with failover we will be negating the
	 * whole purpose of auto failback.
	 */
	mutex_enter(&vlun->svl_mutex);
	if (vlun->svl_active_pclass != NULL) {
		char				*best_pclass;
		struct scsi_failover_ops	*fo;

		fo = vlun->svl_fops;

		(void) fo->sfo_pathclass_next(NULL, &best_pclass,
		    vlun->svl_fops_ctpriv);
		if (strcmp(vlun->svl_active_pclass, best_pclass) == 0) {
			mutex_exit(&vlun->svl_mutex);
			VHCI_RELEASE_LUN(vlun);
			VHCI_DEBUG(1, (CE_NOTE, NULL, "Not initiating "
			    "auto failback for %s as %s pathclass already "
			    "active.\n", vlun->svl_lun_wwn, best_pclass));
			return;
		}
	}
	mutex_exit(&vlun->svl_mutex);
	if (mdi_failover(vdip, vlun->svl_dip, MDI_FAILOVER_SYNC)
	    == MDI_SUCCESS) {
		vhci_log(CE_NOTE, vdip, "!Auto failback operation "
		    "succeeded for device %s (GUID %s)",
		    ddi_node_name(cdip), vlun->svl_lun_wwn);
	} else {
		vhci_log(CE_NOTE, vdip, "!Auto failback operation "
		    "failed for device %s (GUID %s)",
		    ddi_node_name(cdip), vlun->svl_lun_wwn);
	}
	VHCI_RELEASE_LUN(vlun);
}

#ifdef DEBUG
static void
vhci_print_prin_keys(vhci_prin_readkeys_t *prin, int numkeys)
{
	vhci_clean_print(NULL, 5, "Current PGR Keys",
	    (uchar_t *)prin, numkeys * 8);
}
#endif

static void
vhci_print_prout_keys(scsi_vhci_lun_t *vlun, char *msg)
{
	int			i;
	vhci_prout_t		*prout;
	char			buf1[4*MHIOC_RESV_KEY_SIZE + 1];
	char			buf2[4*MHIOC_RESV_KEY_SIZE + 1];
	char			buf3[4*MHIOC_RESV_KEY_SIZE + 1];
	char			buf4[4*MHIOC_RESV_KEY_SIZE + 1];

	prout = &vlun->svl_prout;

	for (i = 0; i < MHIOC_RESV_KEY_SIZE; i++)
		(void) sprintf(&buf1[4*i], "[%02x]", prout->res_key[i]);
	for (i = 0; i < MHIOC_RESV_KEY_SIZE; i++)
		(void) sprintf(&buf2[(4*i)], "[%02x]", prout->service_key[i]);
	for (i = 0; i < MHIOC_RESV_KEY_SIZE; i++)
		(void) sprintf(&buf3[4*i], "[%02x]", prout->active_res_key[i]);
	for (i = 0; i < MHIOC_RESV_KEY_SIZE; i++)
		(void) sprintf(&buf4[4*i], "[%02x]",
		    prout->active_service_key[i]);

	/* Printing all in one go. Otherwise it will jumble up */
	VHCI_DEBUG(5, (CE_CONT, NULL, "%s vlun 0x%p, thread 0x%p\n"
	    "res_key:          : %s\n"
	    "service_key       : %s\n"
	    "active_res_key    : %s\n"
	    "active_service_key: %s\n",
	    msg, (void *)vlun, (void *)curthread, buf1, buf2, buf3, buf4));
}

/*
 * Called from vhci_scsi_start to update the pHCI pkt with target packet.
 */
static void
vhci_update_pHCI_pkt(struct vhci_pkt *vpkt, struct scsi_pkt *pkt)
{

	ASSERT(vpkt->vpkt_hba_pkt);

	vpkt->vpkt_hba_pkt->pkt_flags = pkt->pkt_flags;
	vpkt->vpkt_hba_pkt->pkt_flags |= FLAG_NOQUEUE;

	if ((vpkt->vpkt_hba_pkt->pkt_flags & FLAG_NOINTR) ||
	    MDI_PI_IS_SUSPENDED(vpkt->vpkt_path)) {
		/*
		 * Polled Command is requested or HBA is in
		 * suspended state
		 */
		vpkt->vpkt_hba_pkt->pkt_flags |= FLAG_NOINTR;
		vpkt->vpkt_hba_pkt->pkt_comp = NULL;
	} else {
		vpkt->vpkt_hba_pkt->pkt_comp = vhci_intr;
	}
	vpkt->vpkt_hba_pkt->pkt_time = pkt->pkt_time;
	bcopy(pkt->pkt_cdbp, vpkt->vpkt_hba_pkt->pkt_cdbp,
	    vpkt->vpkt_tgt_init_cdblen);
	vpkt->vpkt_hba_pkt->pkt_resid = pkt->pkt_resid;

	/* Re-initialize the following pHCI packet state information */
	vpkt->vpkt_hba_pkt->pkt_state = 0;
	vpkt->vpkt_hba_pkt->pkt_statistics = 0;
	vpkt->vpkt_hba_pkt->pkt_reason = 0;
}

static int
vhci_scsi_bus_power(dev_info_t *parent, void *impl_arg, pm_bus_power_op_t op,
    void *arg, void *result)
{
	int ret = DDI_SUCCESS;

	/*
	 * Generic processing in MPxIO framework
	 */
	ret = mdi_bus_power(parent, impl_arg, op, arg, result);

	switch (ret) {
	case MDI_SUCCESS:
		ret = DDI_SUCCESS;
		break;
	case MDI_FAILURE:
		ret = DDI_FAILURE;
		break;
	default:
		break;
	}

	return (ret);
}

static int
vhci_pHCI_cap(struct scsi_address *ap, char *cap, int val, int whom,
    mdi_pathinfo_t *pip)
{
	dev_info_t		*cdip;
	mdi_pathinfo_t		*npip = NULL;
	scsi_vhci_priv_t	*svp = NULL;
	struct scsi_address	*pap = NULL;
	scsi_hba_tran_t		*hba = NULL;
	int			sps;
	int			mps_flag;
	int			rval = 0;

	mps_flag = (MDI_SELECT_ONLINE_PATH | MDI_SELECT_STANDBY_PATH);
	if (pip) {
		/*
		 * If the call is from vhci_pathinfo_state_change,
		 * then this path was busy and is becoming ready to accept IO.
		 */
		ASSERT(ap != NULL);
		hba = ap->a_hba_tran;
		ASSERT(hba != NULL);
		rval = scsi_ifsetcap(ap, cap, val, whom);

		VHCI_DEBUG(2, (CE_NOTE, NULL,
		    "!vhci_pHCI_cap: only on path %p, ap %p, rval %x\n",
		    (void *)pip, (void *)ap, rval));

		return (rval);
	}

	/*
	 * Set capability on all the pHCIs.
	 * If any path is busy, then the capability would be set by
	 * vhci_pathinfo_state_change.
	 */

	cdip = ADDR2DIP(ap);
	ASSERT(cdip != NULL);
	sps = mdi_select_path(cdip, NULL, mps_flag, NULL, &pip);
	if ((sps != MDI_SUCCESS) || (pip == NULL)) {
		VHCI_DEBUG(2, (CE_WARN, NULL,
		    "!vhci_pHCI_cap: Unable to get a path, dip 0x%p",
		    (void *)cdip));
		return (0);
	}

again:
	svp = (scsi_vhci_priv_t *)mdi_pi_get_vhci_private(pip);
	if (svp == NULL) {
		VHCI_DEBUG(2, (CE_WARN, NULL, "!vhci_pHCI_cap: "
		    "priv is NULL, pip 0x%p", (void *)pip));
		mdi_rele_path(pip);
		return (rval);
	}

	if (svp->svp_psd == NULL) {
		VHCI_DEBUG(2, (CE_WARN, NULL, "!vhci_pHCI_cap: "
		    "psd is NULL, pip 0x%p, svp 0x%p",
		    (void *)pip, (void *)svp));
		mdi_rele_path(pip);
		return (rval);
	}

	pap = &svp->svp_psd->sd_address;
	ASSERT(pap != NULL);
	hba = pap->a_hba_tran;
	ASSERT(hba != NULL);

	if (hba->tran_setcap != NULL) {
		rval = scsi_ifsetcap(pap, cap, val, whom);

		VHCI_DEBUG(2, (CE_NOTE, NULL,
		    "!vhci_pHCI_cap: path %p, ap %p, rval %x\n",
		    (void *)pip, (void *)ap, rval));

		/*
		 * Select next path and issue the setcap, repeat
		 * until all paths are exhausted
		 */
		sps = mdi_select_path(cdip, NULL, mps_flag, pip, &npip);
		if ((sps != MDI_SUCCESS) || (npip == NULL)) {
			mdi_rele_path(pip);
			return (1);
		}
		mdi_rele_path(pip);
		pip = npip;
		goto again;
	}
	mdi_rele_path(pip);
	return (rval);
}

static int
vhci_scsi_bus_config(dev_info_t *pdip, uint_t flags, ddi_bus_config_op_t op,
    void *arg, dev_info_t **child)
{
	char *guid;

	if (vhci_bus_config_debug)
		flags |= NDI_DEVI_DEBUG;

	if (op == BUS_CONFIG_ONE || op == BUS_UNCONFIG_ONE)
		guid = vhci_devnm_to_guid((char *)arg);
	else
		guid = NULL;

	if (mdi_vhci_bus_config(pdip, flags, op, arg, child, guid)
	    == MDI_SUCCESS)
		return (NDI_SUCCESS);
	else
		return (NDI_FAILURE);
}

static int
vhci_scsi_bus_unconfig(dev_info_t *pdip, uint_t flags, ddi_bus_config_op_t op,
    void *arg)
{
	if (vhci_bus_config_debug)
		flags |= NDI_DEVI_DEBUG;

	return (ndi_busop_bus_unconfig(pdip, flags, op, arg));
}

/*
 * Take the original vhci_pkt, create a duplicate of the pkt for resending
 * as though it originated in ssd.
 */
static struct scsi_pkt *
vhci_create_retry_pkt(struct vhci_pkt *vpkt)
{
	struct vhci_pkt *new_vpkt = NULL;
	struct scsi_pkt	*pkt = NULL;

	scsi_vhci_priv_t *svp = (scsi_vhci_priv_t *)
	    mdi_pi_get_vhci_private(vpkt->vpkt_path);

	/*
	 * Ensure consistent data at completion time by setting PKT_CONSISTENT
	 */
	pkt = vhci_scsi_init_pkt(&svp->svp_psd->sd_address, pkt,
	    vpkt->vpkt_tgt_init_bp, vpkt->vpkt_tgt_init_cdblen,
	    vpkt->vpkt_tgt_init_scblen, 0, PKT_CONSISTENT, NULL_FUNC, NULL);
	if (pkt != NULL) {
		new_vpkt = TGTPKT2VHCIPKT(pkt);

		pkt->pkt_address = vpkt->vpkt_tgt_pkt->pkt_address;
		pkt->pkt_flags = vpkt->vpkt_tgt_pkt->pkt_flags;
		pkt->pkt_time = vpkt->vpkt_tgt_pkt->pkt_time;
		pkt->pkt_comp = vpkt->vpkt_tgt_pkt->pkt_comp;

		pkt->pkt_resid = 0;
		pkt->pkt_statistics = 0;
		pkt->pkt_reason = 0;

		bcopy(vpkt->vpkt_tgt_pkt->pkt_cdbp,
		    pkt->pkt_cdbp, vpkt->vpkt_tgt_init_cdblen);

		/*
		 * Save a pointer to the original vhci_pkt
		 */
		new_vpkt->vpkt_org_vpkt = vpkt;
	}

	return (pkt);
}

/*
 * Copy the successful completion information from the hba packet into
 * the original target pkt from the upper layer.  Returns the original
 * vpkt and destroys the new vpkt from the internal retry.
 */
static struct vhci_pkt *
vhci_sync_retry_pkt(struct vhci_pkt *vpkt)
{
	struct vhci_pkt		*ret_vpkt = NULL;
	struct scsi_pkt		*tpkt = NULL;
	struct scsi_pkt		*hba_pkt = NULL;
	scsi_vhci_priv_t	*svp = (scsi_vhci_priv_t *)
	    mdi_pi_get_vhci_private(vpkt->vpkt_path);

	ASSERT(vpkt->vpkt_org_vpkt != NULL);
	VHCI_DEBUG(0, (CE_NOTE, NULL, "vhci_sync_retry_pkt: Retry pkt "
	    "completed successfully!\n"));

	ret_vpkt = vpkt->vpkt_org_vpkt;
	tpkt = ret_vpkt->vpkt_tgt_pkt;
	hba_pkt = vpkt->vpkt_hba_pkt;

	/*
	 * Copy the good status into the target driver's packet
	 */
	*(tpkt->pkt_scbp) = *(hba_pkt->pkt_scbp);
	tpkt->pkt_resid = hba_pkt->pkt_resid;
	tpkt->pkt_state = hba_pkt->pkt_state;
	tpkt->pkt_statistics = hba_pkt->pkt_statistics;
	tpkt->pkt_reason = hba_pkt->pkt_reason;

	/*
	 * Destroy the internally created vpkt for the retry
	 */
	vhci_scsi_destroy_pkt(&svp->svp_psd->sd_address,
	    vpkt->vpkt_tgt_pkt);

	return (ret_vpkt);
}

/* restart the request sense request */
static void
vhci_uscsi_restart_sense(void *arg)
{
	struct buf 	*rqbp;
	struct buf 	*bp;
	struct scsi_pkt *rqpkt = (struct scsi_pkt *)arg;
	mp_uscsi_cmd_t 	*mp_uscmdp;

	VHCI_DEBUG(4, (CE_WARN, NULL,
	    "vhci_uscsi_restart_sense: enter: rqpkt: %p", (void *)rqpkt));

	if (scsi_transport(rqpkt) != TRAN_ACCEPT) {
		/* if it fails - need to wakeup the original command */
		mp_uscmdp = rqpkt->pkt_private;
		bp = mp_uscmdp->cmdbp;
		rqbp = mp_uscmdp->rqbp;
		ASSERT(mp_uscmdp && bp && rqbp);
		scsi_free_consistent_buf(rqbp);
		scsi_destroy_pkt(rqpkt);
		bp->b_resid = bp->b_bcount;
		bioerror(bp, EIO);
		biodone(bp);
	}
}

/*
 * auto-rqsense is not enabled so we have to retrieve the request sense
 * manually.
 */
static int
vhci_uscsi_send_sense(struct scsi_pkt *pkt, mp_uscsi_cmd_t *mp_uscmdp)
{
	struct buf 		*rqbp, *cmdbp;
	struct scsi_pkt 	*rqpkt;
	int			rval = 0;

	cmdbp = mp_uscmdp->cmdbp;
	ASSERT(cmdbp != NULL);

	VHCI_DEBUG(4, (CE_WARN, NULL,
	    "vhci_uscsi_send_sense: enter: bp: %p pkt: %p scmd: %p",
	    (void *)cmdbp, (void *)pkt, (void *)mp_uscmdp));
	/* set up the packet information and cdb */
	if ((rqbp = scsi_alloc_consistent_buf(mp_uscmdp->ap, NULL,
	    SENSE_LENGTH, B_READ, NULL, NULL)) == NULL) {
		return (-1);
	}

	if ((rqpkt = scsi_init_pkt(mp_uscmdp->ap, NULL, rqbp,
	    CDB_GROUP0, 1, 0, PKT_CONSISTENT, NULL, NULL)) == NULL) {
		scsi_free_consistent_buf(rqbp);
		return (-1);
	}

	(void) scsi_setup_cdb((union scsi_cdb *)(intptr_t)rqpkt->pkt_cdbp,
	    SCMD_REQUEST_SENSE, 0, SENSE_LENGTH, 0);

	mp_uscmdp->rqbp = rqbp;
	rqbp->b_private = mp_uscmdp;
	rqpkt->pkt_flags |= FLAG_SENSING;
	rqpkt->pkt_time = 60;
	rqpkt->pkt_comp = vhci_uscsi_iodone;
	rqpkt->pkt_private = mp_uscmdp;

	/*
	 * NOTE: This code path is related to MPAPI uscsi(7I), so path
	 * selection is not based on path_instance.
	 */
	if (scsi_pkt_allocated_correctly(rqpkt))
		rqpkt->pkt_path_instance = 0;

	switch (scsi_transport(rqpkt)) {
	case TRAN_ACCEPT:
		VHCI_DEBUG(1, (CE_NOTE, NULL, "vhci_uscsi_send_sense: "
		    "transport accepted."));
		break;
	case TRAN_BUSY:
		VHCI_DEBUG(1, (CE_NOTE, NULL, "vhci_uscsi_send_sense: "
		    "transport busy, setting timeout."));
		vhci_restart_timeid = timeout(vhci_uscsi_restart_sense, rqpkt,
		    (drv_usectohz(5 * 1000000)));
		break;
	default:
		VHCI_DEBUG(1, (CE_NOTE, NULL, "vhci_uscsi_send_sense: "
		    "transport failed"));
		scsi_free_consistent_buf(rqbp);
		scsi_destroy_pkt(rqpkt);
		rval = -1;
	}

	return (rval);
}

/*
 * done routine for the mpapi uscsi command - this is behaving as though
 * FLAG_DIAGNOSE is set meaning there are no retries except for a manual
 * request sense.
 */
void
vhci_uscsi_iodone(struct scsi_pkt *pkt)
{
	struct buf 			*bp;
	mp_uscsi_cmd_t 			*mp_uscmdp;
	struct uscsi_cmd 		*uscmdp;
	struct scsi_arq_status 		*arqstat;
	int 				err;

	mp_uscmdp = (mp_uscsi_cmd_t *)pkt->pkt_private;
	uscmdp = mp_uscmdp->uscmdp;
	bp = mp_uscmdp->cmdbp;
	ASSERT(bp != NULL);
	VHCI_DEBUG(4, (CE_WARN, NULL,
	    "vhci_uscsi_iodone: enter: bp: %p pkt: %p scmd: %p",
	    (void *)bp, (void *)pkt, (void *)mp_uscmdp));
	/* Save the status and the residual into the uscsi_cmd struct */
	uscmdp->uscsi_status = ((*(pkt)->pkt_scbp) & STATUS_MASK);
	uscmdp->uscsi_resid = bp->b_resid;

	/* return on a very successful command */
	if (pkt->pkt_reason == CMD_CMPLT &&
	    SCBP_C(pkt) == 0 && ((pkt->pkt_flags & FLAG_SENSING) == 0) &&
	    pkt->pkt_resid == 0) {
		mdi_pi_kstat_iosupdate(mp_uscmdp->pip, bp);
		scsi_destroy_pkt(pkt);
		biodone(bp);
		return;
	}
	VHCI_DEBUG(4, (CE_NOTE, NULL, "iodone: reason=0x%x "
	    " pkt_resid=%ld pkt_state: 0x%x b_count: %ld b_resid: %ld",
	    pkt->pkt_reason, pkt->pkt_resid,
	    pkt->pkt_state, bp->b_bcount, bp->b_resid));

	err = EIO;

	arqstat = (struct scsi_arq_status *)(intptr_t)(pkt->pkt_scbp);
	if (pkt->pkt_reason != CMD_CMPLT) {
		/*
		 * The command did not complete.
		 */
		VHCI_DEBUG(4, (CE_NOTE, NULL,
		    "vhci_uscsi_iodone: command did not complete."
		    " reason: %x flag: %x", pkt->pkt_reason, pkt->pkt_flags));
		if (pkt->pkt_flags & FLAG_SENSING) {
			MDI_PI_ERRSTAT(mp_uscmdp->pip, MDI_PI_TRANSERR);
		} else if (pkt->pkt_reason == CMD_TIMEOUT) {
			MDI_PI_ERRSTAT(mp_uscmdp->pip, MDI_PI_HARDERR);
			err = ETIMEDOUT;
		}
	} else if (pkt->pkt_state & STATE_ARQ_DONE && mp_uscmdp->arq_enabled) {
		/*
		 * The auto-rqsense happened, and the packet has a filled-in
		 * scsi_arq_status structure, pointed to by pkt_scbp.
		 */
		VHCI_DEBUG(4, (CE_NOTE, NULL,
		    "vhci_uscsi_iodone: received auto-requested sense"));
		if (uscmdp->uscsi_flags & USCSI_RQENABLE) {
			/* get the amount of data to copy into rqbuf */
			int rqlen = SENSE_LENGTH - arqstat->sts_rqpkt_resid;
			rqlen = min(((int)uscmdp->uscsi_rqlen), rqlen);
			uscmdp->uscsi_rqresid = uscmdp->uscsi_rqlen - rqlen;
			uscmdp->uscsi_rqstatus =
			    *((char *)&arqstat->sts_rqpkt_status);
			if (uscmdp->uscsi_rqbuf && uscmdp->uscsi_rqlen &&
			    rqlen != 0) {
				bcopy(&(arqstat->sts_sensedata),
				    uscmdp->uscsi_rqbuf, rqlen);
			}
			mdi_pi_kstat_iosupdate(mp_uscmdp->pip, bp);
			VHCI_DEBUG(4, (CE_NOTE, NULL,
			    "vhci_uscsi_iodone: ARQ "
			    "uscsi_rqstatus=0x%x uscsi_rqresid=%d rqlen: %d "
			    "xfer: %d rqpkt_resid: %d\n",
			    uscmdp->uscsi_rqstatus, uscmdp->uscsi_rqresid,
			    uscmdp->uscsi_rqlen, rqlen,
			    arqstat->sts_rqpkt_resid));
		}
	} else if (pkt->pkt_flags & FLAG_SENSING) {
		struct buf *rqbp;
		struct scsi_status *rqstatus;

		rqstatus = (struct scsi_status *)pkt->pkt_scbp;
		/* a manual request sense was done - get the information */
		if (uscmdp->uscsi_flags & USCSI_RQENABLE) {
			int rqlen = SENSE_LENGTH - pkt->pkt_resid;

			rqbp = mp_uscmdp->rqbp;
			/* get the amount of data to copy into rqbuf */
			rqlen = min(((int)uscmdp->uscsi_rqlen), rqlen);
			uscmdp->uscsi_rqresid = uscmdp->uscsi_rqlen - rqlen;
			uscmdp->uscsi_rqstatus = *((char *)rqstatus);
			if (uscmdp->uscsi_rqlen && uscmdp->uscsi_rqbuf) {
				bcopy(rqbp->b_un.b_addr, uscmdp->uscsi_rqbuf,
				    rqlen);
			}
			MDI_PI_ERRSTAT(mp_uscmdp->pip, MDI_PI_TRANSERR);
			scsi_free_consistent_buf(rqbp);
		}
		VHCI_DEBUG(4, (CE_NOTE, NULL, "vhci_uscsi_iodone: FLAG_SENSING"
		    "uscsi_rqstatus=0x%x uscsi_rqresid=%d\n",
		    uscmdp->uscsi_rqstatus, uscmdp->uscsi_rqresid));
	} else {
		struct scsi_status *status =
		    (struct scsi_status *)pkt->pkt_scbp;
		/*
		 * Command completed and we're not getting sense. Check for
		 * errors and decide what to do next.
		 */
		VHCI_DEBUG(4, (CE_NOTE, NULL,
		    "vhci_uscsi_iodone: command appears complete: reason: %x",
		    pkt->pkt_reason));
		if (status->sts_chk) {
			/* need to manually get the request sense */
			if (vhci_uscsi_send_sense(pkt, mp_uscmdp) == 0) {
				scsi_destroy_pkt(pkt);
				return;
			}
		} else {
			VHCI_DEBUG(4, (CE_NOTE, NULL,
			    "vhci_chk_err: appears complete"));
			err = 0;
			mdi_pi_kstat_iosupdate(mp_uscmdp->pip, bp);
			if (pkt->pkt_resid) {
				bp->b_resid += pkt->pkt_resid;
			}
		}
	}

	if (err) {
		if (bp->b_resid == 0)
			bp->b_resid = bp->b_bcount;
		bioerror(bp, err);
		bp->b_flags |= B_ERROR;
	}

	scsi_destroy_pkt(pkt);
	biodone(bp);

	VHCI_DEBUG(4, (CE_WARN, NULL, "vhci_uscsi_iodone: exit"));
}

/*
 * start routine for the mpapi uscsi command
 */
int
vhci_uscsi_iostart(struct buf *bp)
{
	struct scsi_pkt 	*pkt;
	struct uscsi_cmd	*uscmdp;
	mp_uscsi_cmd_t 		*mp_uscmdp;
	int			stat_size, rval;
	int			retry = 0;

	ASSERT(bp->b_private != NULL);

	mp_uscmdp = (mp_uscsi_cmd_t *)bp->b_private;
	uscmdp = mp_uscmdp->uscmdp;
	if (uscmdp->uscsi_flags & USCSI_RQENABLE) {
		stat_size = SENSE_LENGTH;
	} else {
		stat_size = 1;
	}

	pkt = scsi_init_pkt(mp_uscmdp->ap, NULL, bp, uscmdp->uscsi_cdblen,
	    stat_size, 0, 0, SLEEP_FUNC, NULL);
	if (pkt == NULL) {
		VHCI_DEBUG(4, (CE_NOTE, NULL,
		    "vhci_uscsi_iostart: rval: EINVAL"));
		bp->b_resid = bp->b_bcount;
		uscmdp->uscsi_resid = bp->b_bcount;
		bioerror(bp, EINVAL);
		biodone(bp);
		return (EINVAL);
	}

	pkt->pkt_time = uscmdp->uscsi_timeout;
	bcopy(uscmdp->uscsi_cdb, pkt->pkt_cdbp, (size_t)uscmdp->uscsi_cdblen);
	pkt->pkt_comp = vhci_uscsi_iodone;
	pkt->pkt_private = mp_uscmdp;
	if (uscmdp->uscsi_flags & USCSI_SILENT)
		pkt->pkt_flags |= FLAG_SILENT;
	if (uscmdp->uscsi_flags & USCSI_ISOLATE)
		pkt->pkt_flags |= FLAG_ISOLATE;
	if (uscmdp->uscsi_flags & USCSI_DIAGNOSE)
		pkt->pkt_flags |= FLAG_DIAGNOSE;
	if (uscmdp->uscsi_flags & USCSI_RENEGOT) {
		pkt->pkt_flags |= FLAG_RENEGOTIATE_WIDE_SYNC;
	}
	VHCI_DEBUG(4, (CE_WARN, NULL,
	    "vhci_uscsi_iostart: ap: %p pkt: %p pcdbp: %p uscmdp: %p"
	    " ucdbp: %p pcdblen: %d bp: %p count: %ld pip: %p"
	    " stat_size: %d",
	    (void *)mp_uscmdp->ap, (void *)pkt, (void *)pkt->pkt_cdbp,
	    (void *)uscmdp, (void *)uscmdp->uscsi_cdb, pkt->pkt_cdblen,
	    (void *)bp, bp->b_bcount, (void *)mp_uscmdp->pip, stat_size));

	/*
	 * NOTE: This code path is related to MPAPI uscsi(7I), so path
	 * selection is not based on path_instance.
	 */
	if (scsi_pkt_allocated_correctly(pkt))
		pkt->pkt_path_instance = 0;

	while (((rval = scsi_transport(pkt)) == TRAN_BUSY) &&
	    retry < vhci_uscsi_retry_count) {
		delay(drv_usectohz(vhci_uscsi_delay));
		retry++;
	}
	if (retry >= vhci_uscsi_retry_count) {
		VHCI_DEBUG(4, (CE_NOTE, NULL,
		    "vhci_uscsi_iostart: tran_busy - retry: %d", retry));
	}
	switch (rval) {
	case TRAN_ACCEPT:
		rval =  0;
		break;

	default:
		VHCI_DEBUG(4, (CE_NOTE, NULL,
		    "vhci_uscsi_iostart: rval: %d count: %ld res: %ld",
		    rval, bp->b_bcount, bp->b_resid));
		bp->b_resid = bp->b_bcount;
		uscmdp->uscsi_resid = bp->b_bcount;
		bioerror(bp, EIO);
		scsi_destroy_pkt(pkt);
		biodone(bp);
		rval = EIO;
		MDI_PI_ERRSTAT(mp_uscmdp->pip, MDI_PI_TRANSERR);
		break;
	}
	VHCI_DEBUG(4, (CE_NOTE, NULL,
	    "vhci_uscsi_iostart: exit: rval: %d", rval));
	return (rval);
}

/* ARGSUSED */
static struct scsi_failover_ops *
vhci_dev_fo(dev_info_t *vdip, struct scsi_device *psd,
    void **ctprivp, char **fo_namep)
{
	struct scsi_failover_ops	*sfo;
	char				*sfo_name;
	char				*override;
	struct scsi_failover		*sf;

	ASSERT(psd && psd->sd_inq);
	if ((psd == NULL) || (psd->sd_inq == NULL)) {
		VHCI_DEBUG(1, (CE_NOTE, NULL,
		    "!vhci_dev_fo:return NULL no scsi_device or inquiry"));
		return (NULL);
	}

	/*
	 * Determine if device is supported under scsi_vhci, and select
	 * failover module.
	 *
	 * See if there is a scsi_vhci.conf file override for this devices's
	 * VID/PID. The following values can be returned:
	 *
	 * NULL		If the NULL is returned then there is no scsi_vhci.conf
	 *		override.  For NULL, we determine the failover_ops for
	 *		this device by checking the sfo_device_probe entry
	 *		point for each 'fops' module, in order.
	 *
	 *		NOTE: Correct operation may depend on module ordering
	 *		of 'specific' (failover modules that are completely
	 *		VID/PID table based) to 'generic' (failover modules
	 *		that based on T10 standards like TPGS).  Currently,
	 *		the value of 'ddi-forceload' in scsi_vhci.conf is used
	 *		to establish the module list and probe order.
	 *
	 * "NONE"	If value "NONE" is returned then there is a
	 *		scsi_vhci.conf VID/PID override to indicate the device
	 *		should not be supported under scsi_vhci (even if there
	 *		is an 'fops' module supporting the device).
	 *
	 * "<other>"	If another value is returned then that value is the
	 *		name of the 'fops' module that should be used.
	 */
	sfo = NULL;	/* "NONE" */
	override = scsi_get_device_type_string(
	    "scsi-vhci-failover-override", vdip, psd);
	if (override == NULL) {
		/* NULL: default: select based on sfo_device_probe results */
		for (sf = scsi_failover_table; sf->sf_mod; sf++) {
			if ((sf->sf_sfo == NULL) ||
			    sf->sf_sfo->sfo_device_probe(psd, psd->sd_inq,
			    ctprivp) == SFO_DEVICE_PROBE_PHCI)
				continue;

			/* found failover module, supported under scsi_vhci */
			sfo = sf->sf_sfo;
			if (fo_namep && (*fo_namep == NULL)) {
				sfo_name = i_ddi_strdup(sfo->sfo_name,
				    KM_SLEEP);
				*fo_namep = sfo_name;
			}
			break;
		}
	} else if (strcasecmp(override, "NONE")) {
		/* !"NONE": select based on driver.conf specified name */
		for (sf = scsi_failover_table, sfo = NULL; sf->sf_mod; sf++) {
			if ((sf->sf_sfo == NULL) ||
			    (sf->sf_sfo->sfo_name == NULL) ||
			    strcmp(override, sf->sf_sfo->sfo_name))
				continue;

			/*
			 * NOTE: If sfo_device_probe() has side-effects,
			 * including setting *ctprivp, these are not going
			 * to occur with override config.
			 */

			/* found failover module, supported under scsi_vhci */
			sfo = sf->sf_sfo;
			if (fo_namep && (*fo_namep == NULL)) {
				sfo_name = kmem_alloc(strlen("conf ") +
				    strlen(sfo->sfo_name) + 1, KM_SLEEP);
				(void) sprintf(sfo_name, "conf %s",
				    sfo->sfo_name);
				*fo_namep = sfo_name;
			}
			break;
		}
	}
	if (override)
		kmem_free(override, strlen(override) + 1);
	return (sfo);
}

/*
 * Determine the device described by cinfo should be enumerated under
 * the vHCI or the pHCI - if there is a failover ops then device is
 * supported under vHCI.  By agreement with SCSA cinfo is a pointer
 * to a scsi_device structure associated with a decorated pHCI probe node.
 */
/* ARGSUSED */
int
vhci_is_dev_supported(dev_info_t *vdip, dev_info_t *pdip, void *cinfo)
{
	struct scsi_device	*psd = (struct scsi_device *)cinfo;

	return (vhci_dev_fo(vdip, psd, NULL, NULL) ? MDI_SUCCESS : MDI_FAILURE);
}


#ifdef DEBUG
extern struct scsi_key_strings scsi_cmds[];

static char *
vhci_print_scsi_cmd(char cmd)
{
	char tmp[64];
	char *cpnt;

	cpnt = scsi_cmd_name(cmd, scsi_cmds, tmp);
	/* tmp goes out of scope on return and caller sees garbage */
	if (cpnt == tmp) {
		cpnt = "Unknown Command";
	}
	return (cpnt);
}

extern uchar_t	scsi_cdb_size[];

static void
vhci_print_cdb(dev_info_t *dip, uint_t level, char *title, uchar_t *cdb)
{
	int len = scsi_cdb_size[CDB_GROUPID(cdb[0])];
	char buf[256];

	if (level == CE_NOTE) {
		vhci_log(level, dip, "path cmd %s\n",
		    vhci_print_scsi_cmd(*cdb));
		return;
	}

	(void) sprintf(buf, "%s for cmd(%s)", title, vhci_print_scsi_cmd(*cdb));
	vhci_clean_print(dip, level, buf, cdb, len);
}

static void
vhci_clean_print(dev_info_t *dev, uint_t level, char *title, uchar_t *data,
    int len)
{
	int	i;
	int 	c;
	char	*format;
	char	buf[256];
	uchar_t	byte;

	(void) sprintf(buf, "%s:\n", title);
	vhci_log(level, dev, "%s", buf);
	level = CE_CONT;
	for (i = 0; i < len; ) {
		buf[0] = 0;
		for (c = 0; c < 8 && i < len; c++, i++) {
			byte = (uchar_t)data[i];
			if (byte < 0x10)
				format = "0x0%x ";
			else
				format = "0x%x ";
			(void) sprintf(&buf[(int)strlen(buf)], format, byte);
		}
		(void) sprintf(&buf[(int)strlen(buf)], "\n");

		vhci_log(level, dev, "%s\n", buf);
	}
}
#endif
static void
vhci_invalidate_mpapi_lu(struct scsi_vhci *vhci, scsi_vhci_lun_t *vlun)
{
	char			*svl_wwn;
	mpapi_item_list_t	*ilist;
	mpapi_lu_data_t		*ld;

	if (vlun == NULL) {
		return;
	} else {
		svl_wwn = vlun->svl_lun_wwn;
	}

	ilist = vhci->mp_priv->obj_hdr_list[MP_OBJECT_TYPE_MULTIPATH_LU]->head;

	while (ilist != NULL) {
		ld = (mpapi_lu_data_t *)(ilist->item->idata);
		if ((ld != NULL) && (strncmp(ld->prop.name, svl_wwn,
		    strlen(svl_wwn)) == 0)) {
			ld->valid = 0;
			VHCI_DEBUG(6, (CE_WARN, NULL,
			    "vhci_invalidate_mpapi_lu: "
			    "Invalidated LU(%s)", svl_wwn));
			return;
		}
		ilist = ilist->next;
	}
	VHCI_DEBUG(6, (CE_WARN, NULL, "vhci_invalidate_mpapi_lu: "
	    "Could not find LU(%s) to invalidate.", svl_wwn));
}
