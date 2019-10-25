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
 * Copyright 2000 by Cisco Systems, Inc.  All rights reserved.
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2019 Joshua M. Clulow <josh@sysmgr.org>
 *
 * iSCSI Software Initiator
 */

/*
 * Framework interface routines for iSCSI
 */

#include "iscsi.h"				/* main header */
#include <sys/iscsi_protocol.h>	/* protocol structs */
#include <sys/scsi/adapters/iscsi_if.h>		/* ioctl interfaces */
#include "iscsi_targetparam.h"
#include "persistent.h"
#include <sys/scsi/adapters/iscsi_door.h>
#include <sys/dlpi.h>
#include <sys/utsname.h>
#include "isns_client.h"
#include "isns_protocol.h"
#include <sys/bootprops.h>
#include <sys/types.h>
#include <sys/bootconf.h>

#define	ISCSI_NAME_VERSION	"iSCSI Initiator v-1.55"

#define	MAX_GET_NAME_SIZE	1024
#define	MAX_NAME_PROP_SIZE	256
#define	UNDEFINED		-1
#define	ISCSI_DISC_DELAY	2	/* seconds */

/*
 * +--------------------------------------------------------------------+
 * | iscsi globals                                                      |
 * +--------------------------------------------------------------------+
 */
void		*iscsi_state;
kmutex_t	iscsi_oid_mutex;
uint32_t	iscsi_oid;
int		iscsi_nop_delay		= ISCSI_DEFAULT_NOP_DELAY;
int		iscsi_rx_window		= ISCSI_DEFAULT_RX_WINDOW;
int		iscsi_rx_max_window	= ISCSI_DEFAULT_RX_MAX_WINDOW;
boolean_t	iscsi_logging		= B_FALSE;

extern ib_boot_prop_t	*iscsiboot_prop;
extern int		modrootloaded;
extern struct bootobj	rootfs;

/*
 * +--------------------------------------------------------------------+
 * | iscsi.c prototypes							|
 * +--------------------------------------------------------------------+
 */
static int iscsi_getinfo(dev_info_t *dip, ddi_info_cmd_t infocmd,
    void *arg, void **result);
static int iscsi_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int iscsi_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);

/* scsi_tran prototypes */
static int iscsi_tran_lun_init(dev_info_t *hba_dip, dev_info_t *lun_dip,
    scsi_hba_tran_t *hba_tran, struct scsi_device *sd);
static int iscsi_tran_lun_probe(struct scsi_device *sd, int (*callback) ());
static struct scsi_pkt *iscsi_tran_init_pkt(struct scsi_address *ap,
    struct scsi_pkt *pkt, struct buf *bp, int cmdlen, int statuslen,
    int tgtlen, int flags, int (*callback) (), caddr_t arg);
static void iscsi_tran_lun_free(dev_info_t *hba_dip, dev_info_t *lun_dip,
    scsi_hba_tran_t *hba_tran, struct scsi_device *sd);
static int iscsi_tran_start(struct scsi_address *ap, struct scsi_pkt *pkt);
static int iscsi_tran_abort(struct scsi_address *ap, struct scsi_pkt *pkt);
static int iscsi_tran_reset(struct scsi_address *ap, int level);
static int iscsi_tran_getcap(struct scsi_address *ap, char *cap, int whom);
static int iscsi_tran_setcap(struct scsi_address *ap, char *cap,
    int value, int whom);
static void iscsi_tran_destroy_pkt(struct scsi_address *ap,
    struct scsi_pkt *pkt);
static void iscsi_tran_dmafree(struct scsi_address *ap,
    struct scsi_pkt *pkt);
static void iscsi_tran_sync_pkt(struct scsi_address *ap,
    struct scsi_pkt *pkt);
static void iscsi_tran_sync_pkt(struct scsi_address *ap,
    struct scsi_pkt *pkt);
static int iscsi_tran_reset_notify(struct scsi_address *ap, int flag,
    void (*callback) (caddr_t), caddr_t arg);
static int iscsi_tran_bus_config(dev_info_t *parent, uint_t flags,
    ddi_bus_config_op_t op, void *arg, dev_info_t **childp);
static int iscsi_tran_bus_unconfig(dev_info_t *parent, uint_t flags,
    ddi_bus_config_op_t op, void *arg);
static int iscsi_tran_get_name(struct scsi_device *sd, char *name, int len);
static int iscsi_tran_get_bus_addr(struct scsi_device *sd, char *name, int len);

/* bus_ops prototypes */
/* LINTED E_STATIC_UNUSED */
static ddi_intrspec_t iscsi_get_intrspec(dev_info_t *dip, dev_info_t *rdip,
    uint_t inumber);
/* LINTED E_STATIC_UNUSED */
static int iscsi_add_intrspec(dev_info_t *dip, dev_info_t *rdip,
    ddi_intrspec_t intrspec, ddi_iblock_cookie_t *iblock_cookiep,
    ddi_idevice_cookie_t *idevice_cookiep, uint_t (*int_handler)(caddr_t
    int_handler_arg), caddr_t int_handler_arg, int kind);
/* LINTED E_STATIC_UNUSED */
static void iscsi_remove_intrspec(dev_info_t *dip, dev_info_t *rdip,
    ddi_intrspec_t intrspec, ddi_iblock_cookie_t iblock_cookie);
/* LINTED E_STATIC_UNUSED */
static int iscsi_ctl(dev_info_t *dip, dev_info_t *rdip, ddi_ctl_enum_t ctlop,
    void *arg, void *result);

/* cb_ops prototypes */
static int iscsi_open(dev_t *devp, int flags, int otyp, cred_t *credp);
static int iscsi_close(dev_t dev, int flag, int otyp, cred_t *credp);
static int iscsi_ioctl(dev_t dev, int cmd, intptr_t arg, int mode,
    cred_t *credp, int *rvalp);

int iscsi_get_persisted_param(uchar_t *name,
    iscsi_param_get_t *ipgp,
    iscsi_login_params_t *params);
static void iscsi_override_target_default(iscsi_hba_t *ihp,
    iscsi_param_get_t *ipg);

/* scsi_tran helpers */
static int iscsi_virt_lun_init(dev_info_t *hba_dip, dev_info_t *lun_dip,
    scsi_hba_tran_t *hba_tran, struct scsi_device *sd);
static int iscsi_phys_lun_init(dev_info_t *hba_dip, dev_info_t *lun_dip,
    scsi_hba_tran_t *hba_tran, struct scsi_device *sd);
static int iscsi_i_commoncap(struct scsi_address *ap, char *cap,
    int val, int lunonly, int doset);
static void iscsi_get_name_to_iqn(char *name, int name_max_len);
static void iscsi_get_name_from_iqn(char *name, int name_max_len);
static boolean_t iscsi_cmp_boot_sess_oid(iscsi_hba_t *ihp, uint32_t oid);

/* iscsi initiator service helpers */
static boolean_t iscsi_enter_service_zone(iscsi_hba_t *ihp, uint32_t status);
static void iscsi_exit_service_zone(iscsi_hba_t *ihp, uint32_t status);
static void iscsi_check_miniroot(iscsi_hba_t *ihp);
static void iscsi_get_tunable_default(iscsi_tunable_object_t *param);
static int iscsi_get_persisted_tunable_param(uchar_t *name,
    iscsi_tunable_object_t *tpsg);
static void iscsi_set_default_tunable_params(iscsi_tunable_params_t *params);

/* struct helpers prototypes */

/*
 * At this point this driver doesn't need this structure because nothing
 * is done during the open, close or ioctl. Code put in place because
 * some admin related work might be done in the ioctl routine.
 */
static struct cb_ops iscsi_cb_ops = {
	iscsi_open,			/* open */
	iscsi_close,			/* close */
	nodev,				/* strategy */
	nodev,				/* print */
	nodev,				/* dump */
	nodev,				/* read */
	nodev,				/* write */
	iscsi_ioctl,			/* ioctl */
	nodev,				/* devmap */
	nodev,				/* mmap */
	nodev,				/* segmap */
	nochpoll,			/* poll */
	ddi_prop_op,			/* prop_op */
	NULL,				/* streamtab */
	D_NEW | D_MP | D_HOTPLUG,	/* flags */
	CB_REV,				/* cb_rev */
	nodev,				/* aread */
	nodev,				/* awrite */
};

static struct dev_ops iscsi_dev_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* refcnt */
	iscsi_getinfo,		/* getinfo */
	nulldev,		/* identify */
	nulldev,		/* probe */
	iscsi_attach,		/* attach */
	iscsi_detach,		/* detach */
	nodev,			/* reset */
	&iscsi_cb_ops,		/* driver operations */
	NULL,			/* bus ops */
	NULL,			/* power management */
	ddi_quiesce_not_needed,	/* quiesce */
};

static struct modldrv modldrv = {
	&mod_driverops,		/* drv_modops */
	ISCSI_NAME_VERSION,	/* drv_linkinfo */
	&iscsi_dev_ops		/* drv_dev_ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,		/* ml_rev */
	&modldrv,		/* ml_linkage[] */
	NULL			/* NULL termination */
};

/*
 * This structure is bogus. scsi_hba_attach_setup() requires, as in the kernel
 * will panic if you don't pass this in to the routine, this information.
 * Need to determine what the actual impact to the system is by providing
 * this information if any. Since dma allocation is done in pkt_init it may
 * not have any impact. These values are straight from the Writing Device
 * Driver manual.
 */
static ddi_dma_attr_t iscsi_dma_attr = {
	DMA_ATTR_V0,	/* ddi_dma_attr version */
	0,		/* low address */
	0xffffffff,	/* high address */
	0x00ffffff,	/* counter upper bound */
	1,		/* alignment requirements */
	0x3f,		/* burst sizes */
	1,		/* minimum DMA access */
	0xffffffff,	/* maximum DMA access */
	(1 << 24) - 1,	/* segment boundary restrictions */
	1,		/* scater/gather list length */
	512,		/* device granularity */
	0		/* DMA flags */
};

/*
 * _init - General driver init entry
 */
int
_init(void)
{
	int rval = 0;

	iscsi_net_init();

	mutex_init(&iscsi_oid_mutex, NULL, MUTEX_DRIVER, NULL);
	iscsi_oid = ISCSI_INITIATOR_OID;

	/*
	 * Set up the soft state structures. If this driver is actually
	 * being attached to the system then we'll have at least one
	 * HBA/NIC used.
	 */
	rval = ddi_soft_state_init(&iscsi_state,
	    sizeof (iscsi_hba_t), 1);
	if (rval != 0) {
		iscsi_net_fini();
		goto init_done;
	}

	rval = scsi_hba_init(&modlinkage);
	if (rval != 0) {
		ddi_soft_state_fini(&iscsi_state);
		iscsi_net_fini();
		goto init_done;
	}

	rval = mod_install(&modlinkage);
	if (rval != 0) {
		ddi_soft_state_fini(&iscsi_state);
		scsi_hba_fini(&modlinkage);
		iscsi_net_fini();
		goto init_done;
	}
	(void) iscsi_door_ini();

init_done:
	return (rval);
}

/*
 * _fini - General driver destructor entry
 */
int
_fini(void)
{
	int rval = 0;

	rval = mod_remove(&modlinkage);
	if (rval == 0) {
		scsi_hba_fini(&modlinkage);
		ddi_soft_state_fini(&iscsi_state);
		mutex_destroy(&iscsi_oid_mutex);
		(void) iscsi_door_term();
		iscsi_net_fini();
	}
	return (rval);
}

/*
 * _info - General driver info entry
 */
int
_info(struct modinfo *mp)
{
	int rval = 0;

	rval = mod_info(&modlinkage, mp);

	return (rval);
}


/*
 * +--------------------------------------------------------------------+
 * | Start of dev_ops routines					  |
 * +--------------------------------------------------------------------+
 */

/*
 * iscsi_getinfo - returns general driver information
 */
/* ARGSUSED */
static int
iscsi_getinfo(dev_info_t *dip, ddi_info_cmd_t infocmd,
    void *arg, void **result)
{
	int		rval		= DDI_SUCCESS;
	int		instance	= getminor((dev_t)arg);
	iscsi_hba_t	*ip;

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		if ((ip = ddi_get_soft_state(iscsi_state, instance)) == NULL) {
			return (DDI_FAILURE);
		}
		*result = ip->hba_dip;
		if (ip->hba_dip == NULL)
			rval = DDI_FAILURE;
		else
			rval = DDI_SUCCESS;
		break;

	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)(uintptr_t)instance;
		rval = DDI_SUCCESS;
		break;

	default:
		rval = DDI_FAILURE;
		break;
	}
	return (rval);
}


/*
 * iscsi_attach -- Attach instance of an iSCSI HBA.  We
 * will attempt to create our HBA and register it with
 * scsi_vhci.  If it's not possible to create the HBA
 * or register with vhci we will fail the attach.
 */
static int
iscsi_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int			instance	= ddi_get_instance(dip);
	iscsi_hba_t		*ihp		= NULL;
	scsi_hba_tran_t		*tran		= NULL;
	char			init_port_name[MAX_NAME_PROP_SIZE];

	if (cmd == DDI_RESUME) {
		return (DDI_SUCCESS);
	} else if (cmd != DDI_ATTACH) {
		return (DDI_FAILURE);
	}

	if (!modrootloaded && iscsiboot_prop == NULL) {
		/*
		 * The root file system has not yet been mounted, and we're not
		 * trying to boot from an iSCSI device.  Fail to attach now so
		 * that we can retry after root has been mounted.
		 */
		return (DDI_FAILURE);
	}

	/* create iSCSI HBA devctl device node */
	if (ddi_create_minor_node(dip, ISCSI_DEVCTL, S_IFCHR, 0,
	    DDI_PSEUDO, 0) != DDI_SUCCESS) {
		goto iscsi_attach_failed3;
	}

	/* allocate HBA soft state */
	if (ddi_soft_state_zalloc(iscsi_state, instance) !=
	    DDI_SUCCESS) {
		ddi_remove_minor_node(dip, NULL);
		goto iscsi_attach_failed3;
	}

	/* get reference to soft state */
	if ((ihp = (iscsi_hba_t *)ddi_get_soft_state(
	    iscsi_state, instance)) == NULL) {
		ddi_remove_minor_node(dip, NULL);
		ddi_soft_state_free(iscsi_state, instance);
		goto iscsi_attach_failed3;
	}

	/* init HBA mutex used to protect discovery events */
	mutex_init(&ihp->hba_discovery_events_mutex, NULL,
	    MUTEX_DRIVER, NULL);

	VERIFY0(ldi_ident_from_dip(dip, &ihp->hba_li));

	/* init HBA mutex used to protect service status */
	mutex_init(&ihp->hba_service_lock, NULL,
	    MUTEX_DRIVER, NULL);
	cv_init(&ihp->hba_service_cv, NULL, CV_DRIVER, NULL);

	/*
	 * init SendTargets semaphore that is used to allow
	 * only one operation at a time
	 */
	sema_init(&ihp->hba_sendtgts_semaphore, 1, NULL,
	    SEMA_DRIVER, NULL);

	ihp->hba_sess_list = NULL;
	rw_init(&ihp->hba_sess_list_rwlock, NULL,
	    RW_DRIVER, NULL);

	/* allocate scsi_hba_tran */
	if ((tran = scsi_hba_tran_alloc(dip, SCSI_HBA_CANSLEEP))
	    == NULL) {
		ddi_remove_minor_node(dip, NULL);
		goto iscsi_attach_failed2;
	}

	/* soft state setup */
	ihp->hba_sig	= ISCSI_SIG_HBA;
	ihp->hba_tran	= tran;
	ihp->hba_dip	= dip;
	if (iscsiboot_prop == NULL) {
		ihp->hba_service_status =
		    ISCSI_SERVICE_DISABLED;
		ihp->hba_service_status_overwrite = B_FALSE;
	} else {
		ihp->hba_service_status =
		    ISCSI_SERVICE_ENABLED;
		ihp->hba_service_status_overwrite = B_TRUE;
	}
	ihp->hba_service_client_count = 0;

	mutex_enter(&iscsi_oid_mutex);
	ihp->hba_oid		  = iscsi_oid++;
	mutex_exit(&iscsi_oid_mutex);

	ihp->hba_name[0]	  = '\0';
	ihp->hba_name_length	  = 0;
	ihp->hba_alias_length	  = 0;
	ihp->hba_alias[0]	  = '\0';

	iscsi_net->tweaks.rcvbuf = ddi_prop_get_int(
	    DDI_DEV_T_ANY, ihp->hba_dip, 0, "so-rcvbuf",
	    ISCSI_SOCKET_RCVBUF_SIZE);

	iscsi_net->tweaks.sndbuf = ddi_prop_get_int(
	    DDI_DEV_T_ANY, ihp->hba_dip, 0, "so-sndbuf",
	    ISCSI_SOCKET_SNDBUF_SIZE);

	iscsi_net->tweaks.nodelay = ddi_prop_get_int(
	    DDI_DEV_T_ANY, ihp->hba_dip, 0, "tcp-nodelay",
	    ISCSI_TCP_NODELAY_DEFAULT);

	iscsi_net->tweaks.conn_notify_threshold =
	    ddi_prop_get_int(DDI_DEV_T_ANY,
	    ihp->hba_dip, 0, "tcp-conn-notify-threshold",
	    ISCSI_TCP_CNOTIFY_THRESHOLD_DEFAULT);

	iscsi_net->tweaks.conn_abort_threshold =
	    ddi_prop_get_int(DDI_DEV_T_ANY, ihp->hba_dip,
	    0, "tcp-conn-abort-threshold",
	    ISCSI_TCP_CABORT_THRESHOLD_DEFAULT);

	iscsi_net->tweaks.abort_threshold = ddi_prop_get_int(
	    DDI_DEV_T_ANY, ihp->hba_dip, 0,
	    "tcp-abort-threshold",
	    ISCSI_TCP_ABORT_THRESHOLD_DEFAULT);

	ihp->hba_config_storm_delay = ddi_prop_get_int(
	    DDI_DEV_T_ANY, ihp->hba_dip, 0,
	    "config-storm-delay",
	    ISCSI_CONFIG_STORM_DELAY_DEFAULT);

	(void) ddi_prop_update_int(DDI_DEV_T_NONE, ihp->hba_dip,
	    "so-rcvbuf", iscsi_net->tweaks.rcvbuf);

	(void) ddi_prop_update_int(DDI_DEV_T_NONE, ihp->hba_dip,
	    "so-sndbuf", iscsi_net->tweaks.sndbuf);

	(void) ddi_prop_update_int(DDI_DEV_T_NONE, ihp->hba_dip,
	    "tcp-nodelay", iscsi_net->tweaks.nodelay);

	(void) ddi_prop_update_int(DDI_DEV_T_NONE, ihp->hba_dip,
	    "tcp-conn-notify-threshold",
	    iscsi_net->tweaks.conn_notify_threshold);

	(void) ddi_prop_update_int(DDI_DEV_T_NONE, ihp->hba_dip,
	    "tcp-conn-abort-threshold",
	    iscsi_net->tweaks.conn_abort_threshold);

	(void) ddi_prop_update_int(DDI_DEV_T_NONE, ihp->hba_dip,
	    "tcp-abort-threshold",
	    iscsi_net->tweaks.abort_threshold);

	(void) ddi_prop_update_int(DDI_DEV_T_NONE, ihp->hba_dip,
	    "config-storm-delay",
	    ihp->hba_config_storm_delay);

	/* setup hba defaults */
	iscsi_set_default_login_params(&ihp->hba_params);
	iscsi_set_default_tunable_params(
	    &ihp->hba_tunable_params);

	/* setup minimal initiator params */
	iscsid_set_default_initiator_node_settings(ihp, B_TRUE);

	/* hba set up */
	tran->tran_hba_private  = ihp;
	tran->tran_tgt_private  = NULL;
	tran->tran_tgt_init	= iscsi_tran_lun_init;
	tran->tran_tgt_probe	= iscsi_tran_lun_probe;
	tran->tran_tgt_free	= iscsi_tran_lun_free;
	tran->tran_start	= iscsi_tran_start;
	tran->tran_abort	= iscsi_tran_abort;
	tran->tran_reset	= iscsi_tran_reset;
	tran->tran_getcap	= iscsi_tran_getcap;
	tran->tran_setcap	= iscsi_tran_setcap;
	tran->tran_init_pkt	= iscsi_tran_init_pkt;
	tran->tran_destroy_pkt	= iscsi_tran_destroy_pkt;
	tran->tran_dmafree	= iscsi_tran_dmafree;
	tran->tran_sync_pkt	= iscsi_tran_sync_pkt;
	tran->tran_reset_notify	= iscsi_tran_reset_notify;
	tran->tran_bus_config	= iscsi_tran_bus_config;
	tran->tran_bus_unconfig	= iscsi_tran_bus_unconfig;

	tran->tran_get_name	= iscsi_tran_get_name;
	tran->tran_get_bus_addr	= iscsi_tran_get_bus_addr;
	tran->tran_interconnect_type = INTERCONNECT_ISCSI;

	/* register scsi hba with scsa */
	if (scsi_hba_attach_setup(dip, &iscsi_dma_attr,
	    tran, SCSI_HBA_TRAN_CLONE) != DDI_SUCCESS) {
		goto iscsi_attach_failed1;
	}

	/* register scsi hba with mdi (MPxIO/vhci) */
	if (mdi_phci_register(MDI_HCI_CLASS_SCSI, dip, 0) !=
	    MDI_SUCCESS) {
		ihp->hba_mpxio_enabled = B_FALSE;
	} else {
		ihp->hba_mpxio_enabled = B_TRUE;
	}

	(void) iscsi_hba_kstat_init(ihp);

	/* Initialize targetparam list */
	iscsi_targetparam_init();

	/* Initialize ISID */
	ihp->hba_isid[0] = ISCSI_SUN_ISID_0;
	ihp->hba_isid[1] = ISCSI_SUN_ISID_1;
	ihp->hba_isid[2] = ISCSI_SUN_ISID_2;
	ihp->hba_isid[3] = ISCSI_SUN_ISID_3;
	ihp->hba_isid[4] = ISCSI_SUN_ISID_4;
	ihp->hba_isid[5] = ISCSI_SUN_ISID_5;

	/* Setup iSNS transport services and client */
	isns_client_init();

	/*
	 * initialize persistent store,
	 * or boot target info in case of iscsi boot
	 */
	ihp->hba_persistent_loaded = B_FALSE;
	if (iscsid_init(ihp) == B_FALSE) {
		goto iscsi_attach_failed0;
	}

	/* Setup init_port_name for MPAPI */
	(void) snprintf(init_port_name, MAX_NAME_PROP_SIZE,
	    "%s,%02x%02x%02x%02x%02x%02x",
	    (char *)ihp->hba_name, ihp->hba_isid[0],
	    ihp->hba_isid[1], ihp->hba_isid[2],
	    ihp->hba_isid[3], ihp->hba_isid[4],
	    ihp->hba_isid[5]);

	if (ddi_prop_update_string(DDI_DEV_T_NONE, dip,
	    SCSI_ADDR_PROP_INITIATOR_PORT, init_port_name) !=
	    DDI_PROP_SUCCESS) {
		cmn_err(CE_WARN, "iscsi_attach: Creating "
		    SCSI_ADDR_PROP_INITIATOR_PORT
		    " property on iSCSI "
		    "HBA(%s) with dip(%d) Failed",
		    (char *)ihp->hba_name,
		    ddi_get_instance(dip));
	}

	ddi_report_dev(dip);
	return (DDI_SUCCESS);

iscsi_attach_failed0:
	isns_client_cleanup();
	if (ihp->stats.ks) {
		(void) iscsi_hba_kstat_term(ihp);
	}
	if (ihp->hba_mpxio_enabled == B_TRUE) {
		(void) mdi_phci_unregister(dip, 0);
	}
	(void) scsi_hba_detach(ihp->hba_dip);
iscsi_attach_failed1:
	ddi_remove_minor_node(dip, NULL);
	ddi_prop_remove_all(ihp->hba_dip);
	scsi_hba_tran_free(tran);
iscsi_attach_failed2:
	cv_destroy(&ihp->hba_service_cv);
	mutex_destroy(&ihp->hba_service_lock);
	mutex_destroy(&ihp->hba_discovery_events_mutex);
	sema_destroy(&ihp->hba_sendtgts_semaphore);
	rw_destroy(&ihp->hba_sess_list_rwlock);
	ddi_soft_state_free(iscsi_state, instance);
iscsi_attach_failed3:
	cmn_err(CE_WARN, "iscsi driver unable to attach "
	    "hba instance %d", instance);
	return (DDI_FAILURE);
}

/*
 * iscsi_detach - called on unload of hba instance
 */
static int
iscsi_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int			rval		= DDI_SUCCESS;
	scsi_hba_tran_t		*tran		= NULL;
	iscsi_hba_t		*ihp		= NULL;
	iscsi_hba_t		*ihp_check	= NULL;
	int			instance;
	char			*init_node_name;

	instance = ddi_get_instance(dip);

	switch (cmd) {
	case DDI_DETACH:
		if (!(tran = (scsi_hba_tran_t *)ddi_get_driver_private(dip))) {
			rval = DDI_SUCCESS;
			break;
		}

		if ((ihp = (iscsi_hba_t *)tran->tran_hba_private) == NULL) {
			rval =  DDI_FAILURE;
			break;
		}

		/*
		 * Validate that what is stored by the DDI framework is still
		 * the same state structure referenced by the SCSI framework
		 */
		ihp_check = ddi_get_soft_state(iscsi_state, instance);
		if (ihp_check != ihp) {
			rval = DDI_FAILURE;
			break;
		}

		/* If a session exists we can't safely detach */
		rw_enter(&ihp->hba_sess_list_rwlock, RW_READER);
		if (ihp->hba_sess_list != NULL) {
			rw_exit(&ihp->hba_sess_list_rwlock);
			rval = DDI_FAILURE;
			break;
		}
		rw_exit(&ihp->hba_sess_list_rwlock);

		/* Disable all discovery services */
		if (iscsid_disable_discovery(ihp,
		    ISCSI_ALL_DISCOVERY_METHODS) == B_FALSE) {
			/* Disable failed.  Fail detach */
			rval = DDI_FAILURE;
			break;
		}

		/* Deregister from iSNS server(s). */
		init_node_name = kmem_zalloc(ISCSI_MAX_NAME_LEN, KM_SLEEP);
		if (persistent_initiator_name_get(init_node_name,
		    ISCSI_MAX_NAME_LEN) == B_TRUE) {
			if (strlen(init_node_name) > 0) {
				(void) isns_dereg(ihp->hba_isid,
				    (uint8_t *)init_node_name);
			}
		}
		kmem_free(init_node_name, ISCSI_MAX_NAME_LEN);
		init_node_name = NULL;

		/* Cleanup iSNS Client */
		isns_client_cleanup();

		iscsi_targetparam_cleanup();

		/* Cleanup iscsid resources */
		iscsid_fini();

		if (rval != DDI_SUCCESS) {
			break;
		}
		/* kstat hba. destroy */
		KSTAT_DEC_HBA_CNTR_SESS(ihp);

		if (ihp->hba_mpxio_enabled == B_TRUE) {
			(void) mdi_phci_unregister(dip, 0);
		}
		ddi_remove_minor_node(dip, NULL);

		ddi_prop_remove_all(ihp->hba_dip);

		ldi_ident_release(ihp->hba_li);

		cv_destroy(&ihp->hba_service_cv);
		mutex_destroy(&ihp->hba_service_lock);
		mutex_destroy(&ihp->hba_discovery_events_mutex);
		rw_destroy(&ihp->hba_sess_list_rwlock);
		(void) iscsi_hba_kstat_term(ihp);

		(void) scsi_hba_detach(dip);
		if (tran != NULL) {
			scsi_hba_tran_free(tran);
		}
		ddi_soft_state_free(iscsi_state, instance);
		break;
	default:
		break;
	}

	if (rval != DDI_SUCCESS) {
		cmn_err(CE_WARN, "iscsi driver unable to "
		    "detach hba instance %d", instance);
	}

	return (rval);
}

/*
 * +--------------------------------------------------------------------+
 * | End of dev_ops routines						|
 * +--------------------------------------------------------------------+
 */

/*
 * +--------------------------------------------------------------------+
 * | scsi_tran(9E) routines						|
 * +--------------------------------------------------------------------+
 */

/*
 * iscsi_tran_lun_init - Find target device based on SCSI device
 * Based on the information given (SCSI device, target dev_info) find
 * the target iSCSI device and put a pointer to that information in
 * the scsi_hba_tran_t structure.
 */
static int
iscsi_tran_lun_init(dev_info_t *hba_dip, dev_info_t *lun_dip,
    scsi_hba_tran_t *hba_tran, struct scsi_device *sd)
{
	int		rval	= 0;
	int		type	= 0;

	ASSERT(hba_tran->tran_hba_private != NULL);

	/*
	 * Child node is getting initialized.  Look at the mpxio component
	 * type on the child device to see if this device is mpxio managed
	 * or not.
	 */
	type = mdi_get_component_type(lun_dip);
	if (type != MDI_COMPONENT_CLIENT) {
		rval = iscsi_phys_lun_init(hba_dip, lun_dip, hba_tran, sd);
	} else {
		rval = iscsi_virt_lun_init(hba_dip, lun_dip, hba_tran, sd);
	}

	return (rval);
}

/*
 * iscsi_tran_lun_probe - This function didn't need to be implemented.
 * We could have left NULL in the tran table.  Since this isn't a
 * performance path this seems safe.  We are just wrappering the
 * function so we can see the call go through if we have debugging
 * enabled.
 */
static int
iscsi_tran_lun_probe(struct scsi_device *sd, int (*callback) ())
{
	int rval = 0;

	rval = scsi_hba_probe(sd, callback);

	return (rval);
}

/*
 * iscsi_init_pkt - Allocate SCSI packet and fill in required info.
 */
/* ARGSUSED */
static struct scsi_pkt *
iscsi_tran_init_pkt(struct scsi_address *ap, struct scsi_pkt *pkt,
    struct buf *bp, int cmdlen, int statuslen, int tgtlen, int flags,
    int (*callback) (), caddr_t arg)
{
	iscsi_lun_t *ilp;
	iscsi_cmd_t *icmdp;

	ASSERT(ap != NULL);
	ASSERT(callback == NULL_FUNC || callback == SLEEP_FUNC);

	/*
	 * The software stack doesn't have DMA which means the iSCSI
	 * protocol layer will be doing a bcopy from bp to outgoing
	 * streams buffers. Make sure that the buffer is mapped in
	 * so that the copy won't panic the system.
	 */
	if (bp && (bp->b_bcount != 0) &&
	    bp_mapin_common(bp, (callback == NULL_FUNC) ?
	    VM_NOSLEEP : VM_SLEEP) == NULL) {
		return (NULL);
	}

	ilp = (iscsi_lun_t *)ap->a_hba_tran->tran_tgt_private;
	ASSERT(ilp != NULL);

	if (pkt == NULL) {
		pkt = scsi_hba_pkt_alloc(ilp->lun_sess->sess_hba->hba_dip,
		    ap, cmdlen, statuslen, tgtlen, sizeof (iscsi_cmd_t),
		    callback, arg);
		if (pkt == NULL) {
			return (NULL);
		}
		icmdp = (iscsi_cmd_t *)pkt->pkt_ha_private;
		icmdp->cmd_sig			= ISCSI_SIG_CMD;
		icmdp->cmd_state		= ISCSI_CMD_STATE_FREE;
		icmdp->cmd_lun			= ilp;
		icmdp->cmd_type			= ISCSI_CMD_TYPE_SCSI;
		/* add the report lun addressing type on to the lun */
		icmdp->cmd_un.scsi.lun		= ilp->lun_addr_type << 14;
		icmdp->cmd_un.scsi.lun		= icmdp->cmd_un.scsi.lun |
		    ilp->lun_num;
		icmdp->cmd_un.scsi.pkt		= pkt;
		icmdp->cmd_un.scsi.bp		= bp;
		icmdp->cmd_un.scsi.cmdlen	= cmdlen;
		icmdp->cmd_un.scsi.statuslen	= statuslen;
		icmdp->cmd_crc_error_seen	= B_FALSE;
		icmdp->cmd_misc_flags		= 0;
		if (flags & PKT_XARQ) {
			icmdp->cmd_misc_flags |= ISCSI_CMD_MISCFLAG_XARQ;
		}


		idm_sm_audit_init(&icmdp->cmd_state_audit);

		mutex_init(&icmdp->cmd_mutex, NULL, MUTEX_DRIVER, NULL);
		cv_init(&icmdp->cmd_completion, NULL, CV_DRIVER, NULL);

		pkt->pkt_address		= *ap;
		pkt->pkt_comp			= (void (*)())NULL;
		pkt->pkt_flags			= 0;
		pkt->pkt_time			= 0;
		pkt->pkt_resid			= 0;
		pkt->pkt_statistics		= 0;
		pkt->pkt_reason			= 0;
	}
	return (pkt);
}

/*
 * iscsi_tran_lun_free - Free a SCSI LUN
 */
static void
iscsi_tran_lun_free(dev_info_t *hba_dip, dev_info_t *lun_dip,
    scsi_hba_tran_t *hba_tran, struct scsi_device *sd)
{
	iscsi_lun_t *ilp = NULL;

	ASSERT(hba_dip != NULL);
	ASSERT(lun_dip != NULL);
	ASSERT(hba_tran != NULL);
	ASSERT(sd != NULL);
	ilp = (iscsi_lun_t *)hba_tran->tran_tgt_private;
	ASSERT(ilp != NULL);

	(void) mdi_prop_remove(ilp->lun_pip, NULL);
}

/*
 * iscsi_start -- Start a SCSI transaction based on the packet
 * This will attempt to add the icmdp to the pending queue
 * for the connection and kick the queue.  If the enqueue
 * fails that means the queue is full.
 */
static int
iscsi_tran_start(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	iscsi_lun_t	*ilp		= NULL;
	iscsi_sess_t	*isp		= NULL;
	iscsi_cmd_t	*icmdp		= NULL;
	uint_t		flags;

	ASSERT(ap != NULL);
	ASSERT(pkt != NULL);
	ilp = (iscsi_lun_t *)ap->a_hba_tran->tran_tgt_private;
	isp = (iscsi_sess_t *)ilp->lun_sess;
	icmdp = (iscsi_cmd_t *)pkt->pkt_ha_private;
	flags = pkt->pkt_flags;
	ASSERT(ilp != NULL);
	ASSERT(isp != NULL);
	ASSERT(icmdp != NULL);

	/*
	 * If the session is in the FREE state then
	 * all connections are down and retries have
	 * been exhausted.  Fail command with fatal error.
	 */
	rw_enter(&isp->sess_state_rwlock, RW_READER);
	if (isp->sess_state == ISCSI_SESS_STATE_FREE) {
		rw_exit(&isp->sess_state_rwlock);
		return (TRAN_FATAL_ERROR);
	}

	/*
	 * If we haven't received data from the target in the
	 * max specified period something is wrong with the
	 * transport.  Fail IO with FATAL_ERROR.
	 */
	if (isp->sess_rx_lbolt + SEC_TO_TICK(iscsi_rx_max_window) <
	    ddi_get_lbolt()) {
		rw_exit(&isp->sess_state_rwlock);
		return (TRAN_FATAL_ERROR);
	}

	/*
	 * If the session is not in LOGGED_IN then we have
	 * no connections LOGGED_IN, but we haven't exhuasted
	 * our retries.  Fail the command with busy so the
	 * caller might try again later.  Once retries are
	 * exhausted the state machine will move us to FREE.
	 */
	if (isp->sess_state != ISCSI_SESS_STATE_LOGGED_IN) {
		rw_exit(&isp->sess_state_rwlock);
		return (TRAN_BUSY);
	}

	/*
	 * If we haven't received data from the target in the
	 * specified period something is probably wrong with
	 * the transport.  Just return back BUSY until either
	 * the problem is resolved of the transport fails.
	 */
	if (isp->sess_rx_lbolt + SEC_TO_TICK(iscsi_rx_window) <
	    ddi_get_lbolt()) {
		rw_exit(&isp->sess_state_rwlock);
		return (TRAN_BUSY);
	}


	/* reset cmd values in case upper level driver is retrying cmd */
	icmdp->cmd_prev = icmdp->cmd_next = NULL;
	icmdp->cmd_crc_error_seen = B_FALSE;
	icmdp->cmd_lbolt_pending = icmdp->cmd_lbolt_active =
	    icmdp->cmd_lbolt_aborting = icmdp->cmd_lbolt_timeout =
	    (clock_t)NULL;
	icmdp->cmd_itt = icmdp->cmd_ttt = 0;
	icmdp->cmd_un.scsi.abort_icmdp = NULL;

	mutex_enter(&isp->sess_queue_pending.mutex);
	iscsi_cmd_state_machine(icmdp, ISCSI_CMD_EVENT_E1, isp);
	mutex_exit(&isp->sess_queue_pending.mutex);
	rw_exit(&isp->sess_state_rwlock);

	/*
	 * If this packet doesn't have FLAG_NOINTR set, it could have
	 * already run to completion (and the memory freed) at this
	 * point, so check our local copy of pkt_flags.  Otherwise we
	 * have to wait for completion before returning to the caller.
	 */
	if (flags & FLAG_NOINTR) {
		mutex_enter(&icmdp->cmd_mutex);
		while ((icmdp->cmd_state != ISCSI_CMD_STATE_COMPLETED) ||
		    (icmdp->cmd_un.scsi.r2t_icmdp != NULL) ||
		    (icmdp->cmd_un.scsi.abort_icmdp != NULL) ||
		    (icmdp->cmd_un.scsi.r2t_more == B_TRUE)) {
			cv_wait(&icmdp->cmd_completion, &icmdp->cmd_mutex);
		}
		icmdp->cmd_state = ISCSI_CMD_STATE_FREE;
		mutex_exit(&icmdp->cmd_mutex);
	}

	return (TRAN_ACCEPT);
}

/*
 * iscsi_tran_abort - Called when an upper level application
 * or driver wants to kill a scsi_pkt that was already sent to
 * this driver.
 */
/* ARGSUSED */
static int
iscsi_tran_abort(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	return (0);
}

/*
 * iscsi_tran_reset - Reset target at either BUS, TARGET, or LUN
 * level.  This will require the issuing of a task management
 * command down to the target/lun.
 */
static int
iscsi_tran_reset(struct scsi_address *ap, int level)
{
	int		rval    = ISCSI_STATUS_INTERNAL_ERROR;
	iscsi_sess_t	*isp    = NULL;
	iscsi_lun_t	*ilp    = NULL;

	ilp = (iscsi_lun_t *)ap->a_hba_tran->tran_tgt_private;
	ASSERT(ilp != NULL);
	isp = ilp->lun_sess;
	ASSERT(isp != NULL);

	switch (level) {
	case RESET_LUN:
		/* reset attempt will block until attempt is complete */
		rval = iscsi_handle_reset(isp, level, ilp);
		break;
	case RESET_BUS:
		/*
		 * What are we going to realy reset the ethernet
		 * network!?  Just fall through to a target reset.
		 */
	case RESET_TARGET:
		/* reset attempt will block until attempt is complete */
		rval = iscsi_handle_reset(isp, level, NULL);
		break;
	case RESET_ALL:
	default:
		break;
	}

	return (ISCSI_SUCCESS(rval) ? 1 : 0);
}

/*
 * iscsi_tran_getcap - Get target/lun capabilities.
 */
static int
iscsi_tran_getcap(struct scsi_address *ap, char *cap, int whom)
{
	return (iscsi_i_commoncap(ap, cap, 0, whom, 0));
}


/*
 * iscsi_tran_setcap - Set target/lun capabilities.
 */
/* ARGSUSED */
static int
iscsi_tran_setcap(struct scsi_address *ap, char *cap, int value, int whom)
{
	return (iscsi_i_commoncap(ap, cap, value, whom, 1));
}


/*
 * iscsi_tran_destroy_pkt - Clean up packet
 */
static void
iscsi_tran_destroy_pkt(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	iscsi_cmd_t	*icmdp;

	icmdp = (iscsi_cmd_t *)pkt->pkt_ha_private;

	ASSERT(icmdp != NULL);
	ASSERT(icmdp->cmd_sig == ISCSI_SIG_CMD);
	ASSERT(icmdp->cmd_state == ISCSI_CMD_STATE_FREE);

	mutex_destroy(&icmdp->cmd_mutex);
	cv_destroy(&icmdp->cmd_completion);
	scsi_hba_pkt_free(ap, pkt);
}

/*
 * iscsi_tran_dmafree - This is a software driver, NO DMA
 */
/* ARGSUSED */
static void
iscsi_tran_dmafree(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	/*
	 * The iSCSI interface doesn't deal with DMA
	 */
}

/*
 * iscsi_tran_sync_pkt - This is a software driver, NO DMA
 */
/* ARGSUSED */
static void
iscsi_tran_sync_pkt(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	/*
	 * The iSCSI interface doesn't deal with DMA
	 */
}

/*
 * iscsi_tran_reset_notify - We don't support BUS_RESET so there
 * is no point in support callback.
 */
/* ARGSUSED */
static int
iscsi_tran_reset_notify(struct scsi_address *ap, int flag,
    void (*callback) (caddr_t), caddr_t arg)
{

	/*
	 * We never do BUS_RESETS so allowing this call
	 * back to register has no point?
	 */
	return (DDI_SUCCESS);
}


/*
 * iscsi_tran_bus_config - on demand device configuration
 *
 * iscsi_tran_bus_config is called by the NDI layer at the completion
 * of a dev_node creation.  There are two primary cases defined in this
 * function.  The first is BUS_CONFIG_ALL.  In this case the NDI is trying
 * to identify that targets/luns are available configured at that point
 * in time.  It is safe to just complete the process succcessfully.  The
 * second case is a new case that was defined in S10 for devfs.  BUS_CONFIG_ONE
 * this is to help driver the top down discovery instead of bottom up.  If
 * we receive a BUS_CONFIG_ONE we should check to see if the <addr> exists
 * if so complete successfull processing.  Otherwise we should call the
 * deamon and see if we can plumb the <addr>.  If it is possible to plumb the
 * <addr> block until plumbing is complete.  In both cases of being able to
 * plumb <addr> or not continue with successfull processing.
 */
static int
iscsi_tran_bus_config(dev_info_t *parent, uint_t flags,
    ddi_bus_config_op_t op, void *arg, dev_info_t **childp)
{
	int		rval	= NDI_SUCCESS;
	iscsi_hba_t	*ihp	= NULL;
	int		iflags	= flags;
	char		*name	= NULL;
	char		*ptr	= NULL;
	boolean_t	config_root = B_FALSE;

	/* get reference to soft state */
	ihp = (iscsi_hba_t *)ddi_get_soft_state(iscsi_state,
	    ddi_get_instance(parent));
	if (ihp == NULL) {
		return (NDI_FAILURE);
	}

	iscsi_check_miniroot(ihp);
	if ((modrootloaded == 0) && (iscsiboot_prop != NULL)) {
		config_root = B_TRUE;
	}

	if (config_root == B_FALSE) {
		if (iscsi_client_request_service(ihp) == B_FALSE) {
			return (NDI_FAILURE);
		}
	}

	/* lock so only one config operation occrs */
	sema_p(&iscsid_config_semaphore);

	switch (op) {
	case BUS_CONFIG_ONE:
		/* parse target name out of name given */
		if ((ptr = strchr((char *)arg, '@')) == NULL) {
			rval = NDI_FAILURE;
			break;
		}
		ptr++;		/* move past '@' */
		name = kmem_zalloc(MAX_GET_NAME_SIZE, KM_SLEEP);
		(void) strncpy(name, ptr, MAX_GET_NAME_SIZE);
		/* We need to strip the LUN */
		if ((ptr = strchr(name, ',')) == NULL) {
			rval = NDI_FAILURE;
			kmem_free(name, MAX_GET_NAME_SIZE);
			name = NULL;
			break;
		}
		/* We also need to strip the 4 bytes of hex TPGT */
		ptr -= 4;
		if (ptr <= name) {
			rval = NDI_FAILURE;
			kmem_free(name, MAX_GET_NAME_SIZE);
			name = NULL;
			break;
		}
		*ptr = '\0';		/* NULL terminate */

		/* translate name back to original iSCSI name */
		iscsi_get_name_to_iqn(name, MAX_GET_NAME_SIZE);

		/* configure target, skip 4 byte ISID */
		iscsid_config_one(ihp, (name+4), B_TRUE);

		kmem_free(name, MAX_GET_NAME_SIZE);
		name = NULL;

		/*
		 * DDI group instructed us to use this flag.
		 */
		iflags |= NDI_MDI_FALLBACK;
		break;
	case BUS_CONFIG_DRIVER:
		/* FALLTHRU */
	case BUS_CONFIG_ALL:
		iscsid_config_all(ihp, B_TRUE);
		break;
	default:
		rval = NDI_FAILURE;
		break;
	}

	if (rval == NDI_SUCCESS) {
		rval = ndi_busop_bus_config(parent, iflags,
		    op, arg, childp, 0);
	}
	sema_v(&iscsid_config_semaphore);

	if (config_root == B_FALSE) {
		iscsi_client_release_service(ihp);
	}

	return (rval);
}

/*
 * iscsi_tran_bus_unconfig - on demand device unconfiguration
 *
 * Called by the os framework under low resource situations.
 * It will attempt to unload our minor nodes (logical units
 * ndi/mdi nodes).
 */
static int
iscsi_tran_bus_unconfig(dev_info_t *parent, uint_t flag,
    ddi_bus_config_op_t op, void *arg)
{
	int		rval = NDI_SUCCESS;
	iscsi_hba_t	*ihp = NULL;

	/* get reference to soft state */
	ihp = (iscsi_hba_t *)ddi_get_soft_state(iscsi_state,
	    ddi_get_instance(parent));
	if (ihp == NULL) {
		return (NDI_FAILURE);
	}

	if (iscsi_client_request_service(ihp) == B_FALSE) {
		rw_enter(&ihp->hba_sess_list_rwlock, RW_READER);
		if (ihp->hba_sess_list != NULL) {
			rval = NDI_FAILURE;
		}
		rw_exit(&ihp->hba_sess_list_rwlock);
		return (rval);
	}

	rval = ndi_busop_bus_unconfig(parent, flag, op, arg);

	iscsi_client_release_service(ihp);

	return (rval);
}


/*
 * iscsi_tran_get_name - create private /devices name for LUN
 *
 * This creates the <addr> in /devices/iscsi/<driver>@<addr>
 * path.  For this <addr> we return the <session/target_name>,<lun num>
 * Where <target_name> is an <iqn/eui/...> as defined by the iSCSI
 * specification.  We do modify the name slightly so that it still
 * complies with the IEEE <addr> naming scheme.  This means that we
 * will substitute out the ':', '@', ... and other reserved characters
 * defined in the IEEE definition with '%<hex value of special char>'
 * This routine is indirectly called by iscsi_lun_create_xxx.  These
 * calling routines must prevent the session and lun lists from changing
 * during this routine.
 */
static int
iscsi_tran_get_name(struct scsi_device *sd, char *name, int len)
{
	int		target		= 0;
	int		lun		= 0;
	iscsi_hba_t	*ihp		= NULL;
	iscsi_sess_t	*isp		= NULL;
	iscsi_lun_t	*ilp		= NULL;
	dev_info_t	*lun_dip	= NULL;

	ASSERT(sd != NULL);
	ASSERT(name != NULL);
	lun_dip = sd->sd_dev;
	ASSERT(lun_dip != NULL);

	/* get reference to soft state */
	ihp = (iscsi_hba_t *)ddi_get_soft_state(iscsi_state,
	    ddi_get_instance(ddi_get_parent(lun_dip)));
	if (ihp == NULL) {
		name[0] = '\0';
		return (0);
	}

	/* Get the target num */
	target = ddi_prop_get_int(DDI_DEV_T_ANY, sd->sd_dev,
	    DDI_PROP_DONTPASS, TARGET_PROP, 0);

	/* Get the target num */
	lun = ddi_prop_get_int(DDI_DEV_T_ANY, sd->sd_dev,
	    DDI_PROP_DONTPASS, LUN_PROP, 0);

	/*
	 * Now we need to find our ilp by walking the lists
	 * off the ihp and isp.
	 */
	/* See if we already created this session */

	/* Walk the HBA's session list */
	for (isp = ihp->hba_sess_list; isp; isp = isp->sess_next) {
		/* compare target name as the unique identifier */
		if (target == isp->sess_oid) {
			/* found match */
			break;
		}
	}

	/* If we found matching session continue searching for tgt */
	if (isp == NULL) {
		/* sess not found */
		name[0] = '\0';
		return (0);
	}

	/*
	 * Search for the matching iscsi lun structure.  We don't
	 * need to hold the READER for the lun list at this point.
	 * because the tran_get_name is being called from the online
	 * function which is already holding a reader on the lun
	 * list.
	 */
	for (ilp = isp->sess_lun_list; ilp; ilp = ilp->lun_next) {
		if (lun == ilp->lun_num) {
			/* found match */
			break;
		}
	}

	if (ilp == NULL) {
		/* tgt not found */
		name[0] = '\0';
		return (0);
	}

	/* Ensure enough space for lun_addr is available */
	ASSERT(ilp->lun_addr != NULL);
	if ((strlen(ilp->lun_addr) + 1) > len) {
		return (0);
	}

	/* copy lun_addr name */
	(void) strcpy(name, ilp->lun_addr);

	/*
	 * Based on IEEE-1275 we can't have any ':', ' ', '@', or '/'
	 * characters in our naming.  So replace all those characters
	 * with '-'
	 */
	iscsi_get_name_from_iqn(name, len);

	return (1);
}

/*
 * iscsi_tran_get_bus_addr - This returns a human readable string
 * for the bus address.  Examining most other drivers fcp, etc.  They
 * all just return the same string as tran_get_name.  In our case
 * our tran get name is already some what usable so leave alone.
 */
static int
iscsi_tran_get_bus_addr(struct scsi_device *sd, char *name, int len)
{
	return (iscsi_tran_get_name(sd, name, len));
}


/*
 * +--------------------------------------------------------------------+
 * | End of scsi_tran routines					  |
 * +--------------------------------------------------------------------+
 */

/*
 * +--------------------------------------------------------------------+
 * | Start of cb_ops routines					   |
 * +--------------------------------------------------------------------+
 */

/*
 * iscsi_open - Driver should be made IOCTL MT safe.  Otherwise
 * this function needs updated.
 */
/* ARGSUSED */
static int
iscsi_open(dev_t *devp, int flags, int otyp, cred_t *credp)
{
	return (0);
}

/*
 * iscsi_close -
 */
/* ARGSUSED */
static int
iscsi_close(dev_t dev, int flags, int otyp, cred_t *credp)
{
	return (0);
}

/*
 * iscsi_ioctl -
 */
/* ARGSUSED */
static int
iscsi_ioctl(dev_t dev, int cmd, intptr_t arg, int mode,
    cred_t *credp, int *rvalp)
{
	int			rtn		= 0;
	int			instance	= 0;
	int			list_space	= 0;
	int			lun_sz		= 0;
	int			did;
	int			retry;
	iscsi_hba_t		*ihp		= NULL;
	iscsi_sess_t		*isp		= NULL;
	iscsi_conn_t		*icp		= NULL;
	iscsi_login_params_t	*params		= NULL;
	iscsi_login_params_t	*tmpParams	= NULL;
	uchar_t			*name		= NULL;
	dev_info_t		*lun_dip	= NULL;

	entry_t			    e;
	iscsi_oid_t		    oid;
	iscsi_property_t	    *ipp;
	iscsi_static_property_t	    *ispp;
	iscsi_param_get_t	    *ilg;
	iscsi_param_set_t	    *ils;
	iscsi_target_list_t	    idl, *idlp		= NULL;
	iscsi_addr_list_t	    ial, *ialp		= NULL;
	iscsi_chap_props_t	    *chap		= NULL;
	iscsi_radius_props_t	    *radius		= NULL;
	iscsi_auth_props_t	    *auth		= NULL;
	iscsi_lun_list_t	    *ll, *llp		= NULL;
	iscsi_lun_props_t	    *lun		= NULL;
	iscsi_lun_t		    *ilp		= NULL;
	iSCSIDiscoveryMethod_t	    method;
	iSCSIDiscoveryProperties_t  discovery_props;
	iscsi_uscsi_t		    iu;
	iscsi_uscsi_t		    iu_caller;
#ifdef _MULTI_DATAMODEL
	/* For use when a 32 bit app makes a call into a 64 bit ioctl */
	iscsi_uscsi32_t		    iu32_caller;
	model_t			    model;
#endif /* _MULTI_DATAMODEL */
	void			    *void_p;
	iscsi_sendtgts_list_t	*stl_hdr;
	iscsi_sendtgts_list_t	*istl;
	int			stl_sz;
	iscsi_target_entry_t	*target;
	uint32_t		old_oid;
	uint32_t		target_oid;
	iscsi_targetparam_entry_t *curr_entry;
	char			*initiator_node_name;
	char			*initiator_node_alias;
	isns_portal_group_list_t    *pg_list = NULL;
	isns_server_portal_group_list_t    *server_pg_list_hdr = NULL;
	isns_server_portal_group_list_t    *server_pg_list = NULL;
	int			pg_list_sz, pg_sz_copy_out, server_pg_list_sz;
	iscsi_config_sess_t	*ics;
	int			size;
	boolean_t		rval;
	char			init_port_name[MAX_NAME_PROP_SIZE];
	iscsi_sockaddr_t	addr_dsc;
	iscsi_boot_property_t	*bootProp;
	boolean_t		discovered = B_TRUE;
	iscsi_tunable_object_t	*tpsg;
	iscsi_tunable_object_t	*tpss;
	iscsi_reen_t	*reenum;

	instance = getminor(dev);
	ihp = (iscsi_hba_t *)ddi_get_soft_state(iscsi_state, instance);
	if (ihp == NULL)
		return (EFAULT);

	iscsi_check_miniroot(ihp);
	if ((cmd != ISCSI_SMF_ONLINE) && (cmd != ISCSI_SMF_OFFLINE) &&
	    (cmd != ISCSI_SMF_GET)) {
		/* other cmd needs to acquire the service */
		if (iscsi_client_request_service(ihp) == B_FALSE) {
			return (EFAULT);
		}
	}

	switch (cmd) {
	/*
	 * ISCSI_CREATE_OID - Create a Object IDentifier for a TargetName
	 */
	case ISCSI_CREATE_OID:
		if (ddi_copyin((caddr_t)arg, &oid, sizeof (oid), mode)) {
			rtn = EFAULT;
			break;
		}
		if (oid.o_vers != ISCSI_INTERFACE_VERSION) {
			rtn = EINVAL;
			break;
		}

		/* Set the target that this session is associated with */
		oid.o_oid = iscsi_targetparam_get_oid(oid.o_name);

		if (ddi_copyout(&oid, (caddr_t)arg, sizeof (oid), mode)) {
			rtn = EFAULT;
			break;
		}
		break;
	/*
	 * ISCSI_PARAM_GET - Get param for specified
	 * connection/session.
	 */
	case ISCSI_PARAM_GET:
		/* copyin user args */
		ilg = (iscsi_param_get_t *)kmem_alloc(sizeof (*ilg), KM_SLEEP);
		if (ddi_copyin((caddr_t)arg, ilg, sizeof (*ilg), mode)) {
			rtn = EFAULT;
			kmem_free(ilg, sizeof (*ilg));
			break;
		}

		if (ilg->g_vers != ISCSI_INTERFACE_VERSION) {
			rtn = EINVAL;
			kmem_free(ilg, sizeof (*ilg));
			break;
		}

		/* handle special case for Initiator name */
		if (ilg->g_param == ISCSI_LOGIN_PARAM_INITIATOR_NAME) {
			(void) strlcpy((char *)ilg->g_value.v_name,
			    (char *)ihp->hba_name, ISCSI_MAX_NAME_LEN);
		} else if (ilg->g_param == ISCSI_LOGIN_PARAM_INITIATOR_ALIAS) {
			if (ihp->hba_alias_length == 0) {
				rtn = EINVAL;
			} else {
				(void) strlcpy((char *)ilg->g_value.v_name,
				    (char *)ihp->hba_alias, ISCSI_MAX_NAME_LEN);
			}
		} else {
			/* To describe the validity of the requested param */
			boolean_t valid_flag = B_TRUE;

			name = NULL;

			/*
			 * switch login based if looking for initiator
			 * params
			 */
			rw_enter(&ihp->hba_sess_list_rwlock, RW_READER);
			if (ilg->g_oid == ihp->hba_oid) {
				/* initiator */
				params = &ihp->hba_params;
				name = ihp->hba_name;
				if (iscsi_get_persisted_param(name,
				    ilg, params) != 0) {
					valid_flag = B_FALSE;
				}
			} else {
				/*
				 * If the oid does represent a session check
				 * to see if it is a target oid.  If so,
				 * return the target's associated session.
				 */
				rtn = iscsi_sess_get(ilg->g_oid, ihp, &isp);
				if (rtn != 0) {
					rtn = iscsi_sess_get_by_target(
					    ilg->g_oid, ihp, &isp);
				}

				/*
				 * If rtn is zero then we have found an
				 * existing session.  Use the session name to
				 * do param lookup.  If rtn is non-zero then
				 * create a targetparam object and use its name
				 * for param lookup.
				 */
				if (rtn == 0) {
					name = isp->sess_name;
					params = &isp->sess_params;
				} else {
					name =
					    iscsi_targetparam_get_name(
					    ilg->g_oid);
					if (ilg->g_param_type ==
					    ISCSI_SESS_PARAM) {
						tmpParams =
						    (iscsi_login_params_t *)
						    kmem_alloc(
						    sizeof (*tmpParams),
						    KM_SLEEP);
						params = tmpParams;
					}
					rtn = 0;
				}

				if (name == NULL) {
					rw_exit(
					    &ihp->hba_sess_list_rwlock);
					rtn = EFAULT;
					kmem_free(ilg, sizeof (*ilg));
					if (tmpParams != NULL)
						kmem_free(tmpParams,
						    sizeof (*tmpParams));

					break;
				}

				if (ilg->g_param_type == ISCSI_SESS_PARAM) {
					/* session */
					/*
					 * Update sess_params with the
					 * latest params from the
					 * persistent store.
					 */
					if (iscsi_get_persisted_param(name,
					    ilg, params) != 0) {
						/*
						 * If the parameter in
						 * question is not
						 * overriden, no effect
						 * on existing session
						 * parameters. However,
						 * the parameter is
						 * marked invalid
						 * (from the standpoint
						 * of whether it is
						 * overriden).
						 */
						valid_flag = B_FALSE;
					}
				} else if (ilg->g_param_type ==
				    ISCSI_CONN_PARAM && isp != NULL) {
					/* connection */
					rw_enter(&isp->sess_conn_list_rwlock,
					    RW_READER);
					/* Assuming 1 conn per sess. */
					/*
					 * MC/S - Need to be modified to
					 * take g_conn_cid into account when
					 * we go multi-connection.
					 */
					if ((isp->sess_conn_act != NULL) &&
					    (isp->sess_conn_act->conn_state ==
					    ISCSI_CONN_STATE_LOGGED_IN)) {
						params = &(isp->
						    sess_conn_act->
						    conn_params);
					} else {
						valid_flag = B_FALSE;
					}
					rw_exit(&isp->sess_conn_list_rwlock);
				}
			}

			/* make sure we have params to get info from */
			if (params) {
				rtn = iscsi_get_param(params, valid_flag, ilg);

				/*
				 * for target parameters, check if any
				 * parameters were overridden at the initiator
				 * level. If so, then change the default value
				 * to the initiator's overridden value
				 */
				if ((rtn == 0) &&
				    (ilg->g_oid != ihp->hba_oid)) {
					iscsi_override_target_default(ihp,
					    ilg);
				}
			}
			rw_exit(&ihp->hba_sess_list_rwlock);
		}

		if (rtn == 0) {
			rtn = ddi_copyout(ilg, (caddr_t)arg,
			    sizeof (iscsi_param_get_t), mode);
		}
		kmem_free(ilg, sizeof (*ilg));
		if (tmpParams != NULL)
			kmem_free(tmpParams, sizeof (*tmpParams));
		break;

	/*
	 * ISCSI_INIT_NODE_NAME_SET - Change the initiator-node name for
	 * the specified connection/session.
	 */
	case ISCSI_INIT_NODE_NAME_SET:
		/* copyin user args */
		ils = (iscsi_param_set_t *)kmem_alloc(sizeof (*ils), KM_SLEEP);
		if (ddi_copyin((caddr_t)arg, ils, sizeof (*ils), mode)) {
			rtn = EFAULT;
			kmem_free(ils, sizeof (*ils));
			break;
		}

		if (ils->s_vers != ISCSI_INTERFACE_VERSION) {
			rtn = EINVAL;
			kmem_free(ils, sizeof (*ils));
			break;
		}

		/* saving off the old initiator-node name */
		initiator_node_name = kmem_zalloc(ISCSI_MAX_NAME_LEN, KM_SLEEP);
		rval = persistent_initiator_name_get(initiator_node_name,
		    ISCSI_MAX_NAME_LEN);

		rtn = iscsi_set_params(ils, ihp, B_TRUE);
		kmem_free(ils, sizeof (*ils));
		if (rtn != 0) {
			kmem_free(initiator_node_name, ISCSI_MAX_NAME_LEN);
			initiator_node_name = NULL;
			break;
		}

		(void) snprintf(init_port_name, MAX_NAME_PROP_SIZE,
		    "%s,%02x%02x%02x%02x%02x%02x",
		    (char *)ihp->hba_name, ihp->hba_isid[0],
		    ihp->hba_isid[1], ihp->hba_isid[2],
		    ihp->hba_isid[3], ihp->hba_isid[4],
		    ihp->hba_isid[5]);

		if (ddi_prop_update_string(DDI_DEV_T_NONE,
		    ihp->hba_dip, SCSI_ADDR_PROP_INITIATOR_PORT,
		    init_port_name) != DDI_PROP_SUCCESS) {
			cmn_err(CE_WARN, "iscsi_ioctl: Updating "
			    SCSI_ADDR_PROP_INITIATOR_PORT " property on iSCSI "
			    "HBA(%s) with dip(%d) Failed",
			    (char *)ihp->hba_name,
			    ddi_get_instance(ihp->hba_dip));
		}

		/*
		 * Deregister the old initiator-node name from the iSNS
		 * server
		 * Register the new initiator-node name with the iSNS server
		 */
		method = persistent_disc_meth_get();
		if (method & iSCSIDiscoveryMethodISNS) {
			if (rval == B_TRUE) {
				if (strlen(initiator_node_name) > 0) {
				/*
				 * we will attempt to offline the targets.
				 * if logouts fail, we will still continue
				 */
#define	STRING_INNO "initiator-node name - Offline "
#define	STRING_FFOMD "failed for one or more devices"
					if ((iscsid_del(
					    ihp, NULL, method, NULL))
					    != B_TRUE) {
						cmn_err(CE_NOTE,
						    "Attempting to change "
						    STRING_INNO
						    STRING_FFOMD);
					}
					(void) isns_dereg(ihp->hba_isid,
					    (uint8_t *)initiator_node_name);
#undef STRING_INNO
#undef STRING_FFOMD
				}
			}
			if (persistent_initiator_name_get(initiator_node_name,
			    ISCSI_MAX_NAME_LEN) != B_TRUE) {
				kmem_free(initiator_node_name,
				    ISCSI_MAX_NAME_LEN);
				initiator_node_name = NULL;
				rtn = EIO;
				break;
			}
			if (strlen(initiator_node_name) == 0) {
				kmem_free(initiator_node_name,
				    ISCSI_MAX_NAME_LEN);
				initiator_node_name = NULL;
				rtn = EIO;
				break;
			}

			initiator_node_alias = kmem_zalloc(ISCSI_MAX_NAME_LEN,
			    KM_SLEEP);
			if (persistent_alias_name_get(initiator_node_alias,
			    ISCSI_MAX_NAME_LEN) != B_TRUE) {
				initiator_node_alias[0] = '\0';
			}

			(void) isns_reg(ihp->hba_isid,
			    (uint8_t *)initiator_node_name,
			    ISCSI_MAX_NAME_LEN,
			    (uint8_t *)initiator_node_alias,
			    ISCSI_MAX_NAME_LEN,
			    ISNS_INITIATOR_NODE_TYPE,
			    isns_scn_callback);
			iscsid_do_isns_query(ihp);

			kmem_free(initiator_node_alias, ISCSI_MAX_NAME_LEN);
			initiator_node_alias = NULL;
		}

		kmem_free(initiator_node_name, ISCSI_MAX_NAME_LEN);
		initiator_node_name = NULL;
		break;

	/*
	 * ISCSI_PARAM_SET - Set param for specified connection/session.
	 */
	case ISCSI_PARAM_SET:
		/* copyin user args */
		ils = (iscsi_param_set_t *)kmem_alloc(sizeof (*ils), KM_SLEEP);
		if (ddi_copyin((caddr_t)arg, ils, sizeof (*ils), mode)) {
			rtn = EFAULT;
			kmem_free(ils, sizeof (*ils));
			break;
		}

		if (ils->s_vers != ISCSI_INTERFACE_VERSION) {
			rtn = EINVAL;
			kmem_free(ils, sizeof (*ils));
			break;
		}
		rtn = iscsi_set_params(ils, ihp, B_TRUE);
		if (iscsiboot_prop) {
			if (iscsi_cmp_boot_sess_oid(ihp, ils->s_oid)) {
				/*
				 * found active session for this object
				 * or this is initiator's object
				 * with mpxio enabled
				 */
				if (!iscsi_reconfig_boot_sess(ihp)) {
					rtn = EINVAL;
					kmem_free(ils, sizeof (*ils));
					break;
				}
			}
		}
		kmem_free(ils, sizeof (*ils));
		break;

	/*
	 * ISCSI_TARGET_PARAM_CLEAR
	 * - remove custom parameter settings for a target.
	 */
	case ISCSI_TARGET_PARAM_CLEAR:
		if (ddi_copyin((caddr_t)arg, &e, sizeof (e), mode)) {
			rtn = EFAULT;
			break;
		} else if (e.e_vers != ISCSI_INTERFACE_VERSION) {
			rtn = EINVAL;
			break;
		}

		if ((e.e_oid != ihp->hba_oid) &&
		    (e.e_oid != ISCSI_OID_NOTSET)) {
			boolean_t rval1, rval2, rval3;
			uchar_t	    *t_name;
			iscsi_sess_t *t_isp;
			boolean_t    t_rtn = B_TRUE;
			persistent_param_t  t_param;
			iscsi_config_sess_t t_ics;
			persistent_tunable_param_t t_tpsg;

			rw_enter(&ihp->hba_sess_list_rwlock, RW_READER);
			/*
			 * If the oid does represent a session check to see
			 * if it is a target oid.  If so, return the target's
			 * associated session.
			 */
			rtn = iscsi_sess_get(e.e_oid, ihp, &isp);
			if (rtn != 0) {
				rtn = iscsi_sess_get_by_target(e.e_oid, ihp,
				    &isp);
			}

			/*
			 * If rtn is zero then we have found an
			 * existing session.  Use the session name to
			 * do param lookup.  If rtn is non-zero then
			 * create a targetparam object and use its name
			 * for param lookup.
			 */
			if (rtn == 0) {
				t_name = isp->sess_name;
			} else {
				t_name = iscsi_targetparam_get_name(e.e_oid);
				rtn = 0;
			}

			if (t_name == NULL) {
				rw_exit(&ihp->hba_sess_list_rwlock);
				rtn = EFAULT;
				break;
			}

			name = kmem_zalloc(ISCSI_MAX_NAME_LEN, KM_SLEEP);
			(void) strncpy((char *)name, (char *)t_name,
			    ISCSI_MAX_NAME_LEN);

			t_ics.ics_in = 1;
			rval1 = persistent_param_get((char *)name, &t_param);
			rval2 = persistent_get_config_session((char *)name,
			    &t_ics);
			rval3 = persistent_get_tunable_param((char *)name,
			    &t_tpsg);

			if ((rval1 == B_FALSE) && (rval2 == B_FALSE) &&
			    (rval3 == B_FALSE)) {
				/* no any target parameters get */
				kmem_free(name, ISCSI_MAX_NAME_LEN);
				rw_exit(&ihp->hba_sess_list_rwlock);
				rtn = EIO;
				break;
			}

			if (persistent_param_clear((char *)name) == B_FALSE) {
				kmem_free(name, ISCSI_MAX_NAME_LEN);
				rw_exit(&ihp->hba_sess_list_rwlock);
				rtn = EIO;
				break;
			}

			ics = kmem_zalloc(sizeof (*ics), KM_SLEEP);
			ics->ics_ver = ISCSI_INTERFACE_VERSION;
			ics->ics_oid = ISCSI_INITIATOR_OID;
			ics->ics_in  = 1;

			/*
			 * We may have multiple sessions with different
			 * tpgt values.  So we need to loop through
			 * the sessions and update all sessions.
			 */
			for (isp = ihp->hba_sess_list; isp;
			    isp = t_isp) {
				t_isp = isp->sess_next;

				if (strncmp((char *)isp->sess_name,
				    (char *)name, ISCSI_MAX_NAME_LEN) == 0) {
					/*
					 * When removing target-params we need
					 * slightly different actions depending
					 * on if the session should still exist.
					 * Get the initiator-node value for
					 * MS/T.  If there is no initiator
					 * value then assume the default value
					 * of 1.  If the initiator value is
					 * less than this ISID then we need to
					 * destroy the session.  Otherwise
					 * update the session information and
					 * resync (N7 event).
					 */
					rtn = iscsi_ioctl_get_config_sess(
					    ihp, ics);
					if (((rtn != 0) &&
					    (isp->sess_isid[5] > 0)) ||
					    ((rtn == 0) &&
					    (ics->ics_out <=
					    isp->sess_isid[5]))) {

						/*
						 * This session should no
						 * longer exist.  Remove
						 * session.
						 */
						if (!ISCSI_SUCCESS(
						    iscsi_sess_destroy(isp))) {
							t_rtn = B_FALSE;
							continue;
						}
						isp = ihp->hba_sess_list;
					} else {
						uint32_t event_count;
						/*
						 * Reset the session
						 * parameters.
						 */
						bcopy(&(isp->sess_hba->
						    hba_params),
						    &(isp->sess_params),
						    sizeof (isp->sess_params));
						if (iscsiboot_prop &&
						    isp->sess_boot) {
							/*
							 * reconfig boot
							 * session later
							 */
							continue;
						}
						/*
						 * Notify the session that the
						 * login parameters have
						 * changed.
						 */
						event_count = atomic_inc_32_nv(
						    &isp->
						    sess_state_event_count);
						iscsi_sess_enter_state_zone(
						    isp);

						iscsi_sess_state_machine(isp,
						    ISCSI_SESS_EVENT_N7,
						    event_count);

						iscsi_sess_exit_state_zone(
						    isp);
					}
				}
			}
			if (t_rtn == B_FALSE) {
				boolean_t t_rval = B_TRUE;
				/* Failure!, restore target's parameters */
				if (rval1 == B_TRUE) {
					rval1 = persistent_param_set(
					    (char *)name, &t_param);
					if (rval1 == B_FALSE) {
						t_rval = B_FALSE;
					}
				}
				if (rval2 == B_TRUE) {
					rval2 = persistent_set_config_session(
					    (char *)name, &t_ics);
					if (rval2 == B_FALSE) {
						t_rval = B_FALSE;
					}
				}
				if (rval3 == B_TRUE) {
					rval3 = persistent_set_tunable_param(
					    (char *)name, &t_tpsg);
					if (rval3 == B_FALSE) {
						t_rval = B_FALSE;
					}
				}
				if (t_rval == B_FALSE) {
					cmn_err(CE_WARN, "Failed to restore "
					    "target's parameters after remove "
					    "session related to target "
					    "parameters failure.");
				}
				rtn = EBUSY;
			}
			kmem_free(ics, sizeof (*ics));
			kmem_free(name, ISCSI_MAX_NAME_LEN);
			rw_exit(&ihp->hba_sess_list_rwlock);
			if (iscsiboot_prop) {
				if (iscsi_cmp_boot_sess_oid(ihp, e.e_oid)) {
					/*
					 * found active session for this object
					 * or this is initiator object
					 * with mpxio enabled
					 */
					if (!iscsi_reconfig_boot_sess(ihp)) {
						rtn = EINVAL;
						break;
					}
				}
			}
		}
		break;

	/*
	 * ISCSI_TARGET_OID_LIST_GET -
	 */
	case ISCSI_TARGET_OID_LIST_GET:
		/* copyin user args */
		if (ddi_copyin((caddr_t)arg, &idl,
		    sizeof (idl), mode)) {
			rtn = EFAULT;
			break;
		}

		if (idl.tl_vers != ISCSI_INTERFACE_VERSION) {
			rtn = EINVAL;
			break;
		}

		list_space = sizeof (iscsi_target_list_t);
		if (idl.tl_in_cnt != 0)
			list_space += (sizeof (uint32_t) *
			    (idl.tl_in_cnt - 1));

		idlp = kmem_zalloc(list_space, KM_SLEEP);
		bcopy(&idl, idlp, sizeof (idl));
		idlp->tl_out_cnt = 0;

		/*
		 * If target list type is ISCSI_TGT_OID_LIST and discovery
		 * has not been completed or in progress, poke the discovery
		 * methods so target information is returned
		 */
		mutex_enter(&ihp->hba_discovery_events_mutex);
		method = ihp->hba_discovery_events;
		if ((idl.tl_tgt_list_type == ISCSI_TGT_OID_LIST) &&
		    (method != ISCSI_ALL_DISCOVERY_METHODS) &&
		    (ihp->hba_discovery_in_progress == B_FALSE)) {
			ihp->hba_discovery_in_progress = B_TRUE;
			mutex_exit(&ihp->hba_discovery_events_mutex);
			iscsid_poke_discovery(ihp, iSCSIDiscoveryMethodUnknown);
			mutex_enter(&ihp->hba_discovery_events_mutex);
			ihp->hba_discovery_in_progress = B_FALSE;
		}
		mutex_exit(&ihp->hba_discovery_events_mutex);

		/*
		 * Return the correct list information based on the type
		 */
		switch (idl.tl_tgt_list_type) {
		/* ISCSI_TGT_PARAM_OID_LIST - iscsiadm list target-params */
		case ISCSI_TGT_PARAM_OID_LIST:
			/* get params from persistent store */
			iscsi_targetparam_lock_list(RW_READER);
			curr_entry = iscsi_targetparam_get_next_entry(NULL);
			while (curr_entry != NULL) {
				if (idlp->tl_out_cnt < idlp->tl_in_cnt) {
					idlp->tl_oid_list[idlp->tl_out_cnt] =
					    curr_entry->target_oid;
				}
				idlp->tl_out_cnt++;
				curr_entry = iscsi_targetparam_get_next_entry(
				    curr_entry);
			}
			iscsi_targetparam_unlock_list();
			break;

		/* ISCSI_STATIC_TGT_OID_LIST - iscsiadm list static-config */
		case ISCSI_STATIC_TGT_OID_LIST:
		{
			char *target_name = NULL;
			void *v = NULL;

			/* get static-config from persistent store */
			target_name = kmem_zalloc(ISCSI_MAX_NAME_LEN, KM_SLEEP);
			persistent_static_addr_lock();
			while (persistent_static_addr_next(&v,
			    (char *)target_name, &e) == B_TRUE) {

				if (idlp->tl_out_cnt < idlp->tl_in_cnt) {
					idlp->tl_oid_list[idlp->tl_out_cnt] =
					    e.e_oid;
				}
				idlp->tl_out_cnt++;

			}

			persistent_static_addr_unlock();
			kmem_free(target_name, ISCSI_MAX_NAME_LEN);
			break;
		}

		/* ISCSI_TGT_OID_LIST - iscsiadm list target */
		case ISCSI_TGT_OID_LIST:

			/* get sessions from hba's session list */
			rw_enter(&ihp->hba_sess_list_rwlock, RW_READER);
			for (isp = ihp->hba_sess_list; isp;
			    isp = isp->sess_next) {

				if (((isp->sess_state !=
				    ISCSI_SESS_STATE_FREE) ||
				    (isp->sess_discovered_by !=
				    iSCSIDiscoveryMethodUnknown)) &&
				    (isp->sess_type ==
				    ISCSI_SESS_TYPE_NORMAL)) {
					if (idlp->tl_out_cnt <
					    idlp->tl_in_cnt) {
						idlp->tl_oid_list[
						    idlp->tl_out_cnt] =
						    isp->sess_oid;
					}
					idlp->tl_out_cnt++;
				}

			}
			rw_exit(&ihp->hba_sess_list_rwlock);
			break;

		default:
			ASSERT(FALSE);
		}

		rtn = ddi_copyout(idlp, (caddr_t)arg, list_space, mode);
		kmem_free(idlp, list_space);
		break;

	/*
	 * ISCSI_TARGET_PROPS_GET -
	 */
	case ISCSI_TARGET_PROPS_GET:
		/* ---- fall through sense the code is almost the same ---- */

	/*
	 * ISCSI_TARGET_PROPS_SET -
	 */
	case ISCSI_TARGET_PROPS_SET:
		/* copyin user args */
		ipp = (iscsi_property_t *)kmem_alloc(sizeof (*ipp),
		    KM_SLEEP);
		if (ddi_copyin((caddr_t)arg, ipp, sizeof (*ipp), mode)) {
			rtn = EFAULT;
			kmem_free(ipp, sizeof (*ipp));
			break;
		}

		if (ipp->p_vers != ISCSI_INTERFACE_VERSION) {
			rtn = EINVAL;
			kmem_free(ipp, sizeof (*ipp));
			break;
		}

		rtn = iscsi_target_prop_mod(ihp, ipp, cmd);
		if (rtn == 0)
			rtn = ddi_copyout(ipp, (caddr_t)arg,
			    sizeof (*ipp), mode);
		kmem_free(ipp, sizeof (*ipp));
		break;

	/*
	 * ISCSI_TARGET_ADDRESS_GET -
	 */
	case ISCSI_TARGET_ADDRESS_GET:
		if (ddi_copyin((caddr_t)arg, &ial, sizeof (ial), mode)) {
			rtn = EFAULT;
			break;
		}

		if (ial.al_vers != ISCSI_INTERFACE_VERSION) {
			rtn = EINVAL;
			break;
		}

		/*
		 * Find out how much space we need to malloc for the users
		 * request.
		 */
		list_space = sizeof (iscsi_addr_list_t);
		if (ial.al_in_cnt != 0) {
			list_space += (sizeof (iscsi_addr_t) *
			    (ial.al_in_cnt - 1));
		}
		ialp = (iscsi_addr_list_t *)kmem_zalloc(list_space, KM_SLEEP);

		/* Copy in the header portion */
		bcopy(&ial, ialp, sizeof (ial));

		/* session */
		rw_enter(&ihp->hba_sess_list_rwlock, RW_READER);
		rtn = iscsi_sess_get(ialp->al_oid, ihp, &isp);
		if (rtn != 0) {
			rw_exit(&ihp->hba_sess_list_rwlock);
			rtn = EFAULT;
			break;
		}

		ialp->al_out_cnt	= 0;
		ialp->al_tpgt		= isp->sess_tpgt_conf;
		rw_enter(&isp->sess_conn_list_rwlock, RW_READER);
		for (icp = isp->sess_conn_list; icp; icp = icp->conn_next) {
			if (icp->conn_state != ISCSI_CONN_STATE_LOGGED_IN) {
				continue;
			}
			if (ialp->al_out_cnt < ialp->al_in_cnt) {
				iscsi_addr_t		*ap;

				ap = &ialp->al_addrs[ialp->al_out_cnt];
				if (icp->conn_base_addr.sin.sa_family
				    == AF_INET) {

					struct sockaddr_in *addr_in =
					    (struct sockaddr_in *)&icp->
					    conn_base_addr.sin4;
					ap->a_addr.i_insize =
					    sizeof (struct in_addr);
					bcopy(&addr_in->sin_addr.s_addr,
					    &ap->a_addr.i_addr.in4.s_addr,
					    sizeof (struct in_addr));
					ap->a_port = addr_in->sin_port;

				} else {

					struct sockaddr_in6 *addr_in6 =
					    (struct sockaddr_in6 *)&icp->
					    conn_base_addr.sin6;
					ap->a_addr.i_insize =
					    sizeof (struct in6_addr);
					bcopy(&addr_in6->sin6_addr.s6_addr,
					    &ap->a_addr.i_addr.in6.s6_addr,
					    sizeof (struct in6_addr));
					ap->a_port = addr_in6->sin6_port;

				}
			}
			ialp->al_out_cnt++;
		}
		rw_exit(&isp->sess_conn_list_rwlock);
		rw_exit(&ihp->hba_sess_list_rwlock);

		rtn = ddi_copyout(ialp, (caddr_t)arg, list_space, mode);
		kmem_free(ialp, list_space);
		break;

	/*
	 * ISCSI_CHAP_SET -
	 */
	case ISCSI_CHAP_SET:
		chap = (iscsi_chap_props_t *)kmem_zalloc(sizeof (*chap),
		    KM_SLEEP);
		if (ddi_copyin((caddr_t)arg, chap, sizeof (*chap), mode)) {
			rtn = EFAULT;
			kmem_free(chap, sizeof (*chap));
			break;
		} else if (chap->c_vers != ISCSI_INTERFACE_VERSION) {
			rtn = EINVAL;
			kmem_free(chap, sizeof (*chap));
			break;
		}

		rw_enter(&ihp->hba_sess_list_rwlock, RW_READER);
		if (chap->c_oid == ihp->hba_oid)
			name = ihp->hba_name;
		else {
			rtn = iscsi_sess_get(chap->c_oid, ihp, &isp);
			if (rtn != 0) {
				rtn = iscsi_sess_get_by_target(
				    chap->c_oid, ihp, &isp);
			}

			/*
			 * If rtn is zero then we have found an
			 * existing session.  Use the session name to
			 * do param lookup.  If rtn is non-zero then
			 * create a targetparam object and use its name
			 * for param lookup.
			 */
			if (rtn == 0) {
				name = isp->sess_name;
			} else {
				name =
				    iscsi_targetparam_get_name(chap->c_oid);
				rtn = 0;
			}
		}

		if (name == NULL) {
			rw_exit(
			    &ihp->hba_sess_list_rwlock);
			rtn = EFAULT;
			kmem_free(chap, sizeof (*chap));
			break;
		}

		if (persistent_chap_set((char *)name, chap) ==
		    B_FALSE) {
			rtn = EIO;
		}
		rw_exit(&ihp->hba_sess_list_rwlock);
		kmem_free(chap, sizeof (*chap));
		break;

	/*
	 * ISCSI_CHAP_GET -
	 */
	case ISCSI_CHAP_GET:
		chap = (iscsi_chap_props_t *)kmem_zalloc(sizeof (*chap),
		    KM_SLEEP);
		if (ddi_copyin((caddr_t)arg, chap, sizeof (*chap), mode)) {
			kmem_free(chap, sizeof (*chap));
			rtn = EFAULT;
			break;
		} else if (chap->c_vers != ISCSI_INTERFACE_VERSION) {
			kmem_free(chap, sizeof (*chap));
			rtn = EINVAL;
			break;
		}

		rw_enter(&ihp->hba_sess_list_rwlock, RW_READER);
		if (chap->c_oid == ihp->hba_oid)
			name = ihp->hba_name;
		else {
			rtn = iscsi_sess_get(chap->c_oid, ihp, &isp);
			if (rtn != 0) {
				rtn = iscsi_sess_get_by_target(
				    chap->c_oid, ihp, &isp);
			}

			/*
			 * If rtn is zero then we have found an
			 * existing session.  Use the session name to
			 * do param lookup.  If rtn is non-zero then
			 * create a targetparam object and use its name
			 * for param lookup.
			 */
			if (rtn == 0) {
				name = isp->sess_name;
			} else {
				rtn = 0;
				name =
				    iscsi_targetparam_get_name(chap->c_oid);
			}

			if (name == NULL) {
				rw_exit(&ihp->hba_sess_list_rwlock);
				rtn = EFAULT;
				break;
			}
			/*
			 * Initialize the target-side chap name to the
			 * session name if no chap settings have been
			 * saved for the current session.
			 */
			if (persistent_chap_get((char *)name,
			    chap) == B_FALSE) {
				int name_len = strlen((char *)name);
				iscsi_chap_props_t *chap = NULL;
				chap = (iscsi_chap_props_t *)kmem_zalloc
				    (sizeof (iscsi_chap_props_t), KM_SLEEP);
				bcopy((char *)name, chap->c_user, name_len);
				chap->c_user_len = name_len;
				(void) (persistent_chap_set((char *)name,
				    chap));
				kmem_free(chap, sizeof (*chap));
			}
		}

		if (name == NULL) {
			rw_exit(
			    &ihp->hba_sess_list_rwlock);
			rtn = EFAULT;
			break;
		}

		if (persistent_chap_get((char *)name, chap) == B_FALSE) {
			rw_exit(&ihp->hba_sess_list_rwlock);
			rtn = EIO;
			break;
		}
		rw_exit(&ihp->hba_sess_list_rwlock);

		rtn = ddi_copyout(chap, (caddr_t)arg, sizeof (*chap), mode);
		kmem_free(chap, sizeof (*chap));
		break;

	/*
	 * ISCSI_CHAP_CLEAR -
	 */
	case ISCSI_CHAP_CLEAR:
		chap = (iscsi_chap_props_t *)kmem_zalloc(sizeof (*chap),
		    KM_SLEEP);
		if (ddi_copyin((caddr_t)arg, chap, sizeof (*chap), mode)) {
			rtn = EFAULT;
			kmem_free(chap, sizeof (*chap));
			break;
		} else if (chap->c_vers != ISCSI_INTERFACE_VERSION) {
			rtn = EINVAL;
			kmem_free(chap, sizeof (*chap));
			break;
		}

		if (chap->c_oid == ihp->hba_oid) {
			iscsi_sess_t *sessp;

			name = ihp->hba_name;

			if (persistent_chap_clear(
			    (char *)name) == B_FALSE) {
				rtn = EIO;
			}

			/*
			 * Loop through all sessions and memset their
			 * (initiator's) passwords
			 */
			rw_enter(&ihp->hba_sess_list_rwlock, RW_READER);
			for (sessp = ihp->hba_sess_list; sessp;
			    sessp = sessp->sess_next) {
				(void) memset(sessp->sess_auth.password,
				    0, iscsiAuthStringMaxLength);
				sessp->sess_auth.password_length = 0;
			}
			rw_exit(&ihp->hba_sess_list_rwlock);

		} else {
			rw_enter(&ihp->hba_sess_list_rwlock, RW_READER);
			/*
			 * If the oid does represent a session check to see
			 * if it is a target oid.  If so, return the target's
			 * associated session.
			 */
			rtn = iscsi_sess_get(chap->c_oid, ihp, &isp);
			if (rtn != 0) {
				rtn = iscsi_sess_get_by_target(chap->c_oid,
				    ihp, &isp);
			}

			rw_exit(&ihp->hba_sess_list_rwlock);

			/*
			 * If rtn is zero then we have found an
			 * existing session.  Use the session name to
			 * do param lookup.  If rtn is non-zero then
			 * create a targetparam object and use its name
			 * for param lookup.
			 */
			if (rtn == 0) {
				name = isp->sess_name;
			} else {
				name =
				    iscsi_targetparam_get_name(chap->c_oid);
				rtn = 0;
			}

			if (name == NULL) {
				rtn = EFAULT;
				break;
			}

			if (persistent_chap_clear(
			    (char *)name) == B_FALSE) {
				rtn = EIO;
			}

			/*
			 * Clear out session chap password if we found a
			 * session above.
			 */
			if (isp != NULL) {
				(void) memset(isp->sess_auth.password_in,
				    0, iscsiAuthStringMaxLength);
				isp->sess_auth.password_length_in = 0;
			}

		}

		kmem_free(chap, sizeof (*chap));
		break;

	/*
	 * ISCSI_STATIC_GET -
	 */
	case ISCSI_STATIC_GET:
		ispp = (iscsi_static_property_t *)kmem_alloc(
		    sizeof (*ispp), KM_SLEEP);

		if (ddi_copyin((caddr_t)arg, ispp, sizeof (*ispp), mode)) {
			rtn = EFAULT;
			kmem_free(ispp, sizeof (*ispp));
			break;
		}

		if (ispp->p_vers != ISCSI_INTERFACE_VERSION) {
			rtn = EINVAL;
			kmem_free(ispp, sizeof (*ispp));
			break;
		}

		{
			void *v = NULL;
			boolean_t found = B_FALSE;

			persistent_static_addr_lock();
			while (persistent_static_addr_next(&v,
			    (char *)ispp->p_name, &e) == B_TRUE) {

				if (ispp->p_oid == e.e_oid) {
					/*
					 * In case there are multiple
					 * addresses associated with the
					 * given target OID, pick the first
					 * one.
					 */
					iscsi_addr_t *ap;

					ap = &(ispp->p_addr_list.al_addrs[0]);
					ap->a_port = e.e_port;
					ap->a_addr.i_insize = e.e_insize;
					bcopy(e.e_u.u_in6.s6_addr,
					    ap->a_addr.i_addr.in6.s6_addr,
					    e.e_insize);
					ispp->p_name_len =
					    strlen((char *)ispp->p_name);
					ispp->p_addr_list.al_tpgt = e.e_tpgt;
					ispp->p_addr_list.al_out_cnt = 1;

					found = B_TRUE;
					break;
				}
			}
			persistent_static_addr_unlock();

			if (found == B_TRUE) {
				rtn = ddi_copyout(ispp, (caddr_t)arg,
				    sizeof (*ispp), mode);
			} else {
				rtn = ENOENT;
			}
		}
		kmem_free(ispp, sizeof (*ispp));

		break;

	/*
	 * ISCSI_STATIC_SET -
	 */
	case ISCSI_STATIC_SET:
		target = iscsi_ioctl_copyin((caddr_t)arg, mode,
		    sizeof (*target));
		if (target == NULL) {
			rtn = EFAULT;
			break;
		}

		if ((target->te_entry.e_vers != ISCSI_INTERFACE_VERSION) ||
		    (target->te_entry.e_insize == 0)) {
			kmem_free(target, sizeof (*target));
			rtn = EINVAL;
			break;
		}

		/* Check if the target's already been added */
		{
			boolean_t static_target_found = B_FALSE;
			void *v = NULL;

			name = kmem_zalloc(ISCSI_MAX_NAME_LEN, KM_SLEEP);
			persistent_static_addr_lock();
			while (persistent_static_addr_next(&v, (char *)name,
			    &e) == B_TRUE) {
				/*
				 * MC/S - Need to check IP address and port
				 * number as well when we support MC/S.
				 */
				if ((strncmp((char *)name,
				    (char *)target->te_name,
				    ISCSI_MAX_NAME_LEN) == 0) &&
				    (target->te_entry.e_tpgt == e.e_tpgt) &&
				    (target->te_entry.e_insize == e.e_insize) &&
				    (bcmp(&target->te_entry.e_u, &e.e_u,
				    e.e_insize) == 0)) {
					/*
					 * We don't allow MC/S for now but
					 * we do allow adding the same target
					 * with different TPGTs (hence,
					 * different sessions).
					 */
					static_target_found = B_TRUE;
					break;
				}
			}
			persistent_static_addr_unlock();
			kmem_free(name, ISCSI_MAX_NAME_LEN);

			if (static_target_found == B_TRUE) {
				/* Duplicate entry */
				kmem_free(target, sizeof (*target));
				rtn = EEXIST;
				break;
			}
		}

		if (target->te_entry.e_oid == ISCSI_OID_NOTSET) {
			mutex_enter(&iscsi_oid_mutex);
			target->te_entry.e_oid = iscsi_oid++;
			mutex_exit(&iscsi_oid_mutex);
		}

		persistent_static_addr_lock();
		if (persistent_static_addr_set((char *)target->te_name,
		    &target->te_entry) == B_FALSE) {
			persistent_static_addr_unlock();
			kmem_free(target, sizeof (*target));
			rtn = EIO;
			break;
		}
		persistent_static_addr_unlock();

		/*
		 * If Static Targets discovery is enabled, then add
		 * target to discovery queue. Otherwise, just create
		 * the session for potential future use.
		 */
		method = persistent_disc_meth_get();
		if (method & iSCSIDiscoveryMethodStatic) {
			iscsid_poke_discovery(ihp, iSCSIDiscoveryMethodStatic);
			(void) iscsid_login_tgt(ihp, (char *)target->te_name,
			    iSCSIDiscoveryMethodStatic, NULL);
		}

		rtn = iscsi_ioctl_copyout(target, sizeof (*target),
		    (caddr_t)arg, mode);
		break;

	/*
	 * ISCSI_STATIC_CLEAR -
	 */
	case ISCSI_STATIC_CLEAR:
		if (ddi_copyin((caddr_t)arg, &e, sizeof (e), mode)) {
			rtn = EFAULT;
			break;
		} else if (e.e_vers != ISCSI_INTERFACE_VERSION) {
			rtn = EINVAL;
			break;
		}

		{
			boolean_t	found = B_FALSE;
			void		*v = NULL;
			entry_t		tmp_e;
			char		*name = NULL;

			name = kmem_zalloc(ISCSI_MAX_NAME_LEN, KM_SLEEP);

			/* Find name for matching static_tgt oid */
			persistent_static_addr_lock();
			while (persistent_static_addr_next(&v,
			    (char *)name, &tmp_e) == B_TRUE) {
				if (e.e_oid == tmp_e.e_oid) {
					found = B_TRUE;
					break;
				}
			}

			/* If static_tgt found logout and remove it */
			if (found == B_TRUE) {

				iscsid_addr_to_sockaddr(tmp_e.e_insize,
				    &tmp_e.e_u, tmp_e.e_port, &addr_dsc.sin);

				persistent_static_addr_unlock();

				/*
				 * If discovery in progress, try few times
				 * before return busy
				 */
				retry = 0;
				mutex_enter(&ihp->hba_discovery_events_mutex);
				while (ihp->hba_discovery_in_progress ==
				    B_TRUE) {
					if (++retry == 5) {
						rtn = EBUSY;
						break;
					}
					mutex_exit(
					    &ihp->hba_discovery_events_mutex);
					delay(SEC_TO_TICK(
					    ISCSI_DISC_DELAY));
					mutex_enter(
					    &ihp->hba_discovery_events_mutex);
				}
				/* remove from persistent store */
				if (rtn == 0 && persistent_static_addr_clear(
				    e.e_oid) == B_FALSE) {
					rtn = EIO;
				}
				mutex_exit(&ihp->hba_discovery_events_mutex);

				if (rtn != 0) {
					kmem_free(name, ISCSI_MAX_NAME_LEN);
					break;
				}

				/* Attempt to logout of target */
				if (iscsid_del(ihp, (char *)name,
				    iSCSIDiscoveryMethodStatic, &addr_dsc.sin)
				    == B_FALSE) {
					persistent_static_addr_lock();

					/*
					 * Restore static_tgt to
					 * persistent store
					 */
					if (persistent_static_addr_set(
					    (char *)name,
					    &tmp_e) == B_FALSE) {
						cmn_err(CE_WARN, "Failed to "
						    "restore static target "
						    "address after logout "
						    "target failure.");
					}
					persistent_static_addr_unlock();
					rtn = EBUSY;
				} else {
					iscsid_poke_discovery(ihp,
					    iSCSIDiscoveryMethodStatic);
					(void) iscsid_login_tgt(ihp,
					    (char *)name,
					    iSCSIDiscoveryMethodStatic,
					    NULL);

				}
			} else {
				persistent_static_addr_unlock();
				rtn = EIO;
			}
			kmem_free(name, ISCSI_MAX_NAME_LEN);
		}
		break;

	/*
	 * ISCSI_ISNS_SERVER_ADDR_SET:
	 */
	case ISCSI_ISNS_SERVER_ADDR_SET:
		if (ddi_copyin((caddr_t)arg, &e, sizeof (e), mode)) {
			rtn = EFAULT;
			break;
		} else if (e.e_vers != ISCSI_INTERFACE_VERSION) {
			rtn = EINVAL;
			break;
		}

		if (persistent_isns_addr_set(&e) == B_FALSE) {
			rtn = EIO;
			break;
		}

		/*
		 * If iSNS server discovery is enabled, then kickoff
		 * discovery of the targets advertised by the recently
		 * added iSNS server address.
		 */
		method = persistent_disc_meth_get();
		if (method & iSCSIDiscoveryMethodISNS) {
			initiator_node_name = kmem_zalloc(ISCSI_MAX_NAME_LEN,
			    KM_SLEEP);
			if (persistent_initiator_name_get(initiator_node_name,
			    ISCSI_MAX_NAME_LEN) != B_TRUE) {
				kmem_free(initiator_node_name,
				    ISCSI_MAX_NAME_LEN);
				initiator_node_name = NULL;
				rtn = EIO;
				break;
			}
			if (strlen(initiator_node_name) == 0) {
				kmem_free(initiator_node_name,
				    ISCSI_MAX_NAME_LEN);
				initiator_node_name = NULL;
				rtn = EIO;
				break;
			}

			initiator_node_alias = kmem_zalloc(ISCSI_MAX_NAME_LEN,
			    KM_SLEEP);
			if (persistent_alias_name_get(initiator_node_alias,
			    ISCSI_MAX_NAME_LEN) != B_TRUE) {
				initiator_node_alias[0] = '\0';
			}

			/*
			 * Register this initiator node against this iSNS
			 * server.
			 */
			(void) isns_reg_one_server(&e, ihp->hba_isid,
			    (uint8_t *)initiator_node_name,
			    ISCSI_MAX_NAME_LEN,
			    (uint8_t *)initiator_node_alias,
			    ISCSI_MAX_NAME_LEN,
			    ISNS_INITIATOR_NODE_TYPE,
			    isns_scn_callback);

			iscsid_do_isns_query_one_server(ihp, &e);

			iscsid_addr_to_sockaddr(e.e_insize,
			    &e.e_u, e.e_port, &addr_dsc.sin);

			(void) iscsid_login_tgt(ihp, NULL,
			    iSCSIDiscoveryMethodISNS,
			    &addr_dsc.sin);

			/* Done using the name and alias - free them. */
			kmem_free(initiator_node_name, ISCSI_MAX_NAME_LEN);
			initiator_node_name = NULL;
			kmem_free(initiator_node_alias, ISCSI_MAX_NAME_LEN);
			initiator_node_alias = NULL;
		}
		break;

	/*
	 * ISCSI_DISCOVERY_ADDR_SET:
	 */
	case ISCSI_DISCOVERY_ADDR_SET:
		if (ddi_copyin((caddr_t)arg, &e, sizeof (e), mode)) {
			rtn = EFAULT;
			break;
		} else if (e.e_vers != ISCSI_INTERFACE_VERSION) {
			rtn = EINVAL;
			break;
		}

		if (e.e_oid == ISCSI_OID_NOTSET) {
			mutex_enter(&iscsi_oid_mutex);
			e.e_oid = iscsi_oid++;
			mutex_exit(&iscsi_oid_mutex);
		}

		if (persistent_disc_addr_set(&e) == B_FALSE) {
			rtn = EIO;
			break;
		}

		/*
		 * If Send Targets discovery is enabled, then kickoff
		 * discovery of the targets advertised by the recently
		 * added discovery address.
		 */
		method = persistent_disc_meth_get();
		if (method & iSCSIDiscoveryMethodSendTargets) {

			iscsid_addr_to_sockaddr(e.e_insize,
			    &e.e_u, e.e_port, &addr_dsc.sin);
			iscsid_do_sendtgts(&e);
			(void) iscsid_login_tgt(ihp, NULL,
			    iSCSIDiscoveryMethodSendTargets,
			    &addr_dsc.sin);

		}
		break;

	/*
	 * ISCSI_DISCOVERY_ADDR_LIST_GET
	 */
	case ISCSI_DISCOVERY_ADDR_LIST_GET:
		/* copyin user args */
		if (ddi_copyin((caddr_t)arg, &ial, sizeof (ial), mode)) {
			rtn = EFAULT;
			break;
		}

		if (ial.al_vers != ISCSI_INTERFACE_VERSION) {
			rtn = EINVAL;
			break;
		}

		list_space = sizeof (iscsi_addr_list_t);
		if (ial.al_in_cnt != 0) {
			list_space += (sizeof (iscsi_addr_t) *
			    (ial.al_in_cnt - 1));
		}

		ialp = kmem_zalloc(list_space, KM_SLEEP);
		bcopy(&ial, ialp, sizeof (iscsi_addr_list_t));

		void_p = NULL;
		ialp->al_out_cnt = 0;
		persistent_disc_addr_lock();
		while (persistent_disc_addr_next(&void_p, &e) == B_TRUE) {
			if (ialp->al_out_cnt < ialp->al_in_cnt) {
				int		i = ialp->al_out_cnt;
				iscsi_addr_t	*addr = &ialp->al_addrs[i];

				addr->a_port = e.e_port;
				addr->a_addr.i_insize = e.e_insize;
				addr->a_oid = e.e_oid;

				if (e.e_insize == sizeof (struct in_addr)) {
					/* IPv4 */
					addr->a_addr.i_addr.in4.s_addr =
					    e.e_u.u_in4.s_addr;
				} else if (e.e_insize ==
					    sizeof (struct in6_addr)) {
					/* IPv6 */
					bcopy(e.e_u.u_in6.s6_addr,
					    addr->a_addr.i_addr.in6.s6_addr,
					    16);
				}
			}
			ialp->al_out_cnt++;
		}
		persistent_disc_addr_unlock();

		rtn = ddi_copyout(ialp, (caddr_t)arg, list_space, mode);
		kmem_free(ialp, list_space);
		break;

	/*
	 * ISCSI_ISNS_SERVER_ADDR_LIST_GET
	 */
	case ISCSI_ISNS_SERVER_ADDR_LIST_GET:
		/* copyin user args */
		if (ddi_copyin((caddr_t)arg, &ial, sizeof (ial), mode)) {
			rtn = EFAULT;
			break;
		}

		if (ial.al_vers != ISCSI_INTERFACE_VERSION) {
			rtn = EINVAL;
			break;
		}

		list_space = sizeof (iscsi_addr_list_t);
		if (ial.al_in_cnt != 0) {
			list_space += (sizeof (iscsi_addr_t) *
			    (ial.al_in_cnt - 1));
		}

		ialp = kmem_zalloc(list_space, KM_SLEEP);
		bcopy(&ial, ialp, sizeof (iscsi_addr_list_t));

		void_p = NULL;
		ialp->al_out_cnt = 0;
		persistent_isns_addr_lock();
		while (persistent_isns_addr_next(&void_p, &e) == B_TRUE) {
			if (ialp->al_out_cnt < ialp->al_in_cnt) {
				int		i = ialp->al_out_cnt;
				iscsi_addr_t	*addr = &ialp->al_addrs[i];

				addr->a_port = e.e_port;
				addr->a_addr.i_insize = e.e_insize;
				if (e.e_insize == sizeof (struct in_addr)) {
					/* IPv4 */
					addr->a_addr.i_addr.in4.s_addr =
					    e.e_u.u_in4.s_addr;
				} else if (e.e_insize ==
					    sizeof (struct in6_addr)) {
					/* IPv6 */
					bcopy(e.e_u.u_in6.s6_addr,
					    addr->a_addr.i_addr.in6.s6_addr,
					    16);
				}
			}
			ialp->al_out_cnt++;
		}
		persistent_isns_addr_unlock();

		rtn = ddi_copyout(ialp, (caddr_t)arg, list_space, mode);
		kmem_free(ialp, list_space);
		break;

	/*
	 * ISCSI_DISCOVERY_ADDR_CLEAR:
	 */
	case ISCSI_DISCOVERY_ADDR_CLEAR:
		if (ddi_copyin((caddr_t)arg, &e, sizeof (e), mode)) {
			rtn = EFAULT;
			break;
		} else if (e.e_vers != ISCSI_INTERFACE_VERSION) {
			rtn = EINVAL;
			break;
		}

		iscsid_addr_to_sockaddr(e.e_insize,
		    &e.e_u, e.e_port, &addr_dsc.sin);

		/* If discovery in progress, try few times before return busy */
		retry = 0;
		mutex_enter(&ihp->hba_discovery_events_mutex);
		while (ihp->hba_discovery_in_progress == B_TRUE) {
			if (++retry == 5) {
				rtn = EBUSY;
				break;
			}
			mutex_exit(&ihp->hba_discovery_events_mutex);
			delay(SEC_TO_TICK(ISCSI_DISC_DELAY));
			mutex_enter(&ihp->hba_discovery_events_mutex);
		}

		/*
		 * Clear discovery address first, so that any bus config
		 * will ignore this discovery address
		 */
		if (rtn == 0 && persistent_disc_addr_clear(&e) == B_FALSE) {
			rtn = EIO;
		}
		mutex_exit(&ihp->hba_discovery_events_mutex);

		if (rtn != 0) {
			break;
		}
		/* Attempt to logout of associated targets */
		if (iscsid_del(ihp, NULL,
		    iSCSIDiscoveryMethodSendTargets, &addr_dsc.sin) ==
		    B_FALSE) {
			/* Failure!, restore the discovery addr. */
			if (persistent_disc_addr_set(&e) == B_FALSE) {
				cmn_err(CE_WARN, "Failed to restore sendtgt "
				    "discovery address after logout associated "
				    "targets failures.");
			}
			rtn = EBUSY;
		}
		break;

	/*
	 * ISCSI_ISNS_SERVER_CLEAR:
	 */
	case ISCSI_ISNS_SERVER_ADDR_CLEAR:
		if (ddi_copyin((caddr_t)arg, &e, sizeof (e), mode)) {
			rtn = EFAULT;
			break;
		} else if (e.e_vers != ISCSI_INTERFACE_VERSION) {
			rtn = EINVAL;
			break;
		}

		iscsid_addr_to_sockaddr(e.e_insize,
		    &e.e_u, e.e_port, &addr_dsc.sin);

		/* If discovery in progress, try few times before return busy */
		retry = 0;
		mutex_enter(&ihp->hba_discovery_events_mutex);
		while (ihp->hba_discovery_in_progress == B_TRUE) {
			if (++retry == 5) {
				rtn = EBUSY;
				break;
			}
			mutex_exit(&ihp->hba_discovery_events_mutex);
			delay(SEC_TO_TICK(ISCSI_DISC_DELAY));
			mutex_enter(&ihp->hba_discovery_events_mutex);
		}

		/*
		 * Clear isns server address first, so that any bus config
		 * will ignore any target registerd on this isns server
		 */
		if (rtn == 0 && persistent_isns_addr_clear(&e) == B_FALSE) {
			rtn = EIO;
		}
		mutex_exit(&ihp->hba_discovery_events_mutex);

		if (rtn != 0) {
			break;
		}

		/* Attempt logout of associated targets */
		if (iscsid_del(ihp, NULL, iSCSIDiscoveryMethodISNS,
		    &addr_dsc.sin) == B_FALSE) {
			/* Failure!, restore the isns server addr. */

			if (persistent_isns_addr_set(&e) == B_FALSE) {
				cmn_err(CE_WARN, "Failed to restore isns server"
				    " address after logout associated targets"
				    " failures.");
			}
			rtn = EBUSY;
		} else {
			method = persistent_disc_meth_get();
			if (method & iSCSIDiscoveryMethodISNS) {
				boolean_t is_last_isns_server_b =
				    B_FALSE;
				int isns_server_count = 0;
				void *void_p = NULL;

				/*
				 * Check if the last iSNS server's been
				 * removed.
				 */
				{
					entry_t tmp_e;
					persistent_isns_addr_lock();
					while (persistent_isns_addr_next(
					    &void_p, &tmp_e) == B_TRUE) {
						isns_server_count++;
					}
				}
				persistent_isns_addr_unlock();
				if (isns_server_count == 0) {
					is_last_isns_server_b = B_TRUE;
				}

				/*
				 * Deregister this node from this iSNS
				 * server.
				 */
				initiator_node_name = kmem_zalloc(
				    ISCSI_MAX_NAME_LEN, KM_SLEEP);
				if (persistent_initiator_name_get(
				    initiator_node_name,
				    ISCSI_MAX_NAME_LEN) == B_TRUE) {

					if (strlen(initiator_node_name) > 0) {
						(void) isns_dereg_one_server(
						    &e, (uint8_t *)
						    initiator_node_name,
						    is_last_isns_server_b);
					}
				}
				kmem_free(initiator_node_name,
				    ISCSI_MAX_NAME_LEN);
				initiator_node_name = NULL;
			}
		}
		break;

	/*
	 * ISCSI_DISCOVERY_SET -
	 */
	case ISCSI_DISCOVERY_SET:
		if (ddi_copyin((caddr_t)arg, &method, sizeof (method), mode)) {
			rtn = EFAULT;
			break;
		}

		if (persistent_disc_meth_set(method) == B_FALSE) {
			rtn = EIO;
		} else {
			(void) iscsid_enable_discovery(ihp, method, B_FALSE);
			iscsid_poke_discovery(ihp, method);
			(void) iscsid_login_tgt(ihp, NULL, method, NULL);
		}
		break;

	/*
	 * ISCSI_DISCOVERY_GET -
	 */
	case ISCSI_DISCOVERY_GET:
		method = persistent_disc_meth_get();
		rtn = ddi_copyout(&method, (caddr_t)arg,
		    sizeof (method), mode);
		break;

	/*
	 * ISCSI_DISCOVERY_CLEAR -
	 */
	case ISCSI_DISCOVERY_CLEAR:
		if (ddi_copyin((caddr_t)arg, &method, sizeof (method), mode)) {
			rtn = EFAULT;
			break;
		}

		/* If discovery in progress, try few times before return busy */
		retry = 0;
		mutex_enter(&ihp->hba_discovery_events_mutex);
		while (ihp->hba_discovery_in_progress == B_TRUE) {
			if (++retry == 5) {
				rtn = EBUSY;
				break;
			}
			mutex_exit(&ihp->hba_discovery_events_mutex);
			delay(SEC_TO_TICK(ISCSI_DISC_DELAY));
			mutex_enter(&ihp->hba_discovery_events_mutex);
		}

		/*
		 * Clear discovery first, so that any bus config or
		 * discovery requests will ignore this discovery method
		 */
		if (rtn == 0 && persistent_disc_meth_clear(method) == B_FALSE) {
			rtn = EIO;
		}
		mutex_exit(&ihp->hba_discovery_events_mutex);

		if (rtn != 0) {
			break;
		}

		/* Attempt to logout from all associated targets */
		if (iscsid_disable_discovery(ihp, method) == B_FALSE) {
			/* Failure!, reset the discovery */
			if (persistent_disc_meth_set(method) == B_FALSE) {
				cmn_err(CE_WARN, "Failed to reset discovery "
				    "method after discovery disable failure.");
			}
			rtn = EBUSY;
		}
		break;

	/*
	 * ISCSI_DISCOVERY_PROPS -
	 */
	case ISCSI_DISCOVERY_PROPS:
		iscsid_props(&discovery_props);
		if (ddi_copyout(&discovery_props, (caddr_t)arg,
		    sizeof (discovery_props), mode))
			rtn = EFAULT;
		break;

	/*
	 * ISCSI_LUN_OID_LIST --
	 */
	case ISCSI_LUN_OID_LIST_GET:
		ll = (iscsi_lun_list_t *)kmem_alloc(sizeof (*ll), KM_SLEEP);
		if (ddi_copyin((caddr_t)arg, ll, sizeof (*ll), mode)) {
			rtn = EFAULT;
			kmem_free(ll, sizeof (*ll));
			break;
		}

		if (ll->ll_vers != ISCSI_INTERFACE_VERSION) {
			rtn = EINVAL;
			kmem_free(ll, sizeof (*ll));
			break;
		}

		/*
		 * Find out how much space the user has allocated in their
		 * structure. Match the same space for our structure.
		 */
		lun_sz = sizeof (iscsi_lun_list_t);
		if (ll->ll_in_cnt > 0) {
			lun_sz += (ll->ll_in_cnt - 1) * sizeof (iscsi_if_lun_t);
		}

		llp = kmem_zalloc(lun_sz, KM_SLEEP);
		bcopy(ll, llp, sizeof (*ll));
		kmem_free(ll, sizeof (*ll));

		/*
		 * Check to see if oid references a target-param oid.  If so,
		 * find the associated  session oid before getting lu list.
		 */
		if (iscsi_targetparam_get_name(llp->ll_tgt_oid) != NULL) {
			for (isp = ihp->hba_sess_list; isp;
			    isp = isp->sess_next) {
				if (isp->sess_target_oid == llp->ll_tgt_oid) {
					target_oid  = isp->sess_oid;
					break;
				}
			}
		} else {
			target_oid = llp->ll_tgt_oid;
		}


		/*
		 * Look at the LUNs attached to the specified target. If there
		 * is space in the user structure save that information locally.
		 * Always add up the count to the total. By always adding
		 * the count this code can be used if ll_in_cnt == 0 and
		 * the user just wishes to know the appropriate size to
		 * allocate.
		 */
		rw_enter(&ihp->hba_sess_list_rwlock, RW_READER);
		for (isp = ihp->hba_sess_list; isp; isp = isp->sess_next) {
			if ((llp->ll_all_tgts == B_FALSE) &&
			    (isp->sess_oid != target_oid)) {
				continue;
			}
			rw_enter(&isp->sess_lun_list_rwlock, RW_READER);
			for (ilp = isp->sess_lun_list; ilp;
			    ilp = ilp->lun_next) {
				if ((ilp->lun_state &
				    ISCSI_LUN_STATE_ONLINE) &&
				    !(ilp->lun_state &
				    ISCSI_LUN_STATE_INVALID)) {
					if (llp->ll_out_cnt <
					    llp->ll_in_cnt) {
						iscsi_if_lun_t *lp;
						lp = &llp->ll_luns[
						    llp->ll_out_cnt];

						lp->l_tgt_oid =
						    isp->sess_oid;
						lp->l_oid = ilp->lun_oid;
						lp->l_num = ilp->lun_num;
					}
				llp->ll_out_cnt++;
				}
			}
			rw_exit(&isp->sess_lun_list_rwlock);
		}
		rw_exit(&ihp->hba_sess_list_rwlock);

		if (ddi_copyout(llp, (caddr_t)arg, lun_sz, mode)) {
			rtn = EFAULT;
		}

		kmem_free(llp, lun_sz);
		break;

	/*
	 * ISCSI_LUN_PROPS_GET --
	 */
	case ISCSI_LUN_PROPS_GET:
		lun = (iscsi_lun_props_t *)kmem_zalloc(sizeof (*lun), KM_SLEEP);
		if (ddi_copyin((caddr_t)arg, lun, sizeof (*lun), mode)) {
			rtn = EFAULT;
			kmem_free(lun, sizeof (*lun));
			break;
		}

		if (lun->lp_vers != ISCSI_INTERFACE_VERSION) {
			rtn = EINVAL;
			kmem_free(lun, sizeof (*lun));
			break;
		}

		/*
		 * For the target specified, find the LUN specified and
		 * return its properties
		 */
		rw_enter(&ihp->hba_sess_list_rwlock, RW_READER);
		rtn = iscsi_sess_get(lun->lp_tgt_oid, ihp, &isp);
		if (rtn != 0) {
			rw_exit(&ihp->hba_sess_list_rwlock);
			rtn = EFAULT;
			kmem_free(lun, sizeof (*lun));
			break;
		}
		rtn = EINVAL;	/* Set bad rtn, correct only if found */
		rw_enter(&isp->sess_lun_list_rwlock, RW_READER);
		for (ilp = isp->sess_lun_list; ilp; ilp = ilp->lun_next) {
			if (ilp->lun_oid == lun->lp_oid) {
				lun->lp_num	= ilp->lun_num;
				lun->lp_status	= LunValid;
				lun->lp_time_online = ilp->lun_time_online;

				if (ilp->lun_pip != NULL) {
					lun_dip = mdi_pi_get_client(
					    ilp->lun_pip);
				} else {
					lun_dip = ilp->lun_dip;
				}

				if (lun_dip != NULL &&
				    ((i_ddi_devi_attached(lun_dip)) ||
				    (ddi_get_devstate(lun_dip) ==
				    DDI_DEVSTATE_UP))) {
					(void) ddi_pathname(lun_dip,
					    lun->lp_pathname);
				} else {
					/*
					 * The LUN is not exported to the
					 * OS yet.  It is in the process
					 * of being added.
					 */
					lun->lp_status	= LunDoesNotExist;
				}
				bcopy(ilp->lun_vid, lun->lp_vid,
				    sizeof (lun->lp_vid));
				bcopy(ilp->lun_pid, lun->lp_pid,
				    sizeof (lun->lp_pid));
				rtn = ddi_copyout(lun, (caddr_t)arg,
				    sizeof (*lun), mode);
				if (rtn == -1) {
					rtn = EFAULT;
				}
				break;
			}
		}
		rw_exit(&isp->sess_lun_list_rwlock);
		rw_exit(&ihp->hba_sess_list_rwlock);

		kmem_free(lun, sizeof (*lun));
		break;

	/*
	 * ISCSI_CONN_OID_LIST_GET --
	 */
#define	ISCSIIOCOLGC iscsi_ioctl_conn_oid_list_get_copyout
	case ISCSI_CONN_OID_LIST_GET:
		{
			iscsi_conn_list_t	*cl;

			/* Asuume the worst */
			rtn = EFAULT;

			/* Copy the input argument into kernel world. */
			cl = iscsi_ioctl_conn_oid_list_get_copyin(
			    (caddr_t)arg,
			    mode);
			if (cl != NULL) {
				if (iscsi_ioctl_conn_oid_list_get(ihp, cl) ==
				    B_TRUE) {
					rtn =
					    ISCSIIOCOLGC(
					    cl, (caddr_t)arg, mode);
				}
			}
			break;
		}
#undef ISCSIIOCOLGC
	/*
	 * ISCSI_CONN_OID_LIST_GET --
	 */
	case ISCSI_CONN_PROPS_GET:
		{
			iscsi_conn_props_t	*cp;

			/* Asuume the worst */
			rtn = EFAULT;

			/* Copy the input argument into kernel world. */
			cp = iscsi_ioctl_copyin(
			    (caddr_t)arg,
			    mode,
			    sizeof (iscsi_conn_props_t));

			if (cp != NULL) {
				/* Get the propereties. */
				if (iscsi_ioctl_conn_props_get(ihp, cp) ==
				    B_TRUE) {
					rtn =
					    iscsi_ioctl_copyout(
					    cp,
					    sizeof (*cp),
					    (caddr_t)arg,
					    mode);
				} else {
					kmem_free(cp, sizeof (*cp));
					cp = NULL;
				}
			}
			break;
		}

	/*
	 * ISCSI_RADIUS_GET -
	 */
	case ISCSI_RADIUS_GET:
	{
		iscsi_nvfile_status_t	status;

		radius = (iscsi_radius_props_t *)kmem_zalloc(sizeof (*radius),
		    KM_SLEEP);
		if (ddi_copyin((caddr_t)arg, radius, sizeof (*radius), mode)) {
			kmem_free(radius, sizeof (*radius));
			rtn = EFAULT;
			break;
		} else if (radius->r_vers != ISCSI_INTERFACE_VERSION) {
			kmem_free(radius, sizeof (*radius));
			rtn = EINVAL;
			break;
		}

		old_oid = radius->r_oid;

		if (radius->r_oid == ihp->hba_oid) {
			name = ihp->hba_name;
		} else {
			/*
			 * RADIUS configuration should be done on a per
			 * initiator basis.
			 */
			kmem_free(radius, sizeof (*radius));
			rtn = EINVAL;
			break;
		}

		status = persistent_radius_get(radius);
		if (status == ISCSI_NVFILE_SUCCESS) {
			/*
			 * Restore the value for overridden (and bogus) oid.
			 */
			radius->r_oid = old_oid;
			rtn = ddi_copyout(radius, (caddr_t)arg,
			    sizeof (*radius), mode);
		} else if (status == ISCSI_NVFILE_NAMEVAL_NOT_FOUND) {
			rtn = ENOENT;
		} else {
			rtn = EIO;
		}
		kmem_free(radius, sizeof (*radius));
		break;
	}

	/*
	 * ISCSI_RADIUS_SET -
	 */
	case ISCSI_RADIUS_SET:
		radius = (iscsi_radius_props_t *)kmem_zalloc(sizeof (*radius),
		    KM_SLEEP);
		if (ddi_copyin((caddr_t)arg, radius, sizeof (*radius), mode)) {
			rtn = EFAULT;
			kmem_free(radius, sizeof (*radius));
			break;
		} else if (radius->r_vers != ISCSI_INTERFACE_VERSION) {
			rtn = EINVAL;
			kmem_free(radius, sizeof (*radius));
			break;
		}

		if (radius->r_oid == ihp->hba_oid) {
			name = ihp->hba_name;
		} else {
			/*
			 * RADIUS configuration should be done on a per
			 * initiator basis.
			 */
			kmem_free(radius, sizeof (*radius));
			rtn = EINVAL;
			break;
		}

		if (persistent_radius_set(radius) == B_FALSE) {
			rtn = EIO;
		}

		kmem_free(radius, sizeof (*radius));
		break;

	/*
	 *  ISCSI_AUTH_GET -
	 */
	case ISCSI_AUTH_GET:
		auth = (iscsi_auth_props_t *)kmem_zalloc(sizeof (*auth),
		    KM_SLEEP);
		if (ddi_copyin((caddr_t)arg, auth, sizeof (*auth), mode)) {
			kmem_free(auth, sizeof (*auth));
			rtn = EFAULT;
			break;
		} else if (auth->a_vers != ISCSI_INTERFACE_VERSION) {
			kmem_free(auth, sizeof (*auth));
			rtn = EINVAL;
			break;
		}

		old_oid = auth->a_oid;

		if (auth->a_oid == ihp->hba_oid) {
			name = ihp->hba_name;
		} else {

			rw_enter(&ihp->hba_sess_list_rwlock, RW_READER);
			/*
			 * If the oid does represent a session check to see
			 * if it is a target oid.  If so, return the target's
			 * associated session.
			 */
			rtn = iscsi_sess_get(auth->a_oid, ihp, &isp);
			if (rtn != 0) {
				rtn = iscsi_sess_get_by_target(auth->a_oid,
				    ihp, &isp);
			}
			rw_exit(&ihp->hba_sess_list_rwlock);

			/*
			 * If rtn is zero then we have found an
			 * existing session.  Use the session name to
			 * do param lookup.  If rtn is non-zero then
			 * create a targetparam object and use its name
			 * for param lookup.
			 */
			if (rtn == 0) {
				name = isp->sess_name;
			} else {
				name =
				    iscsi_targetparam_get_name(auth->a_oid);
			}
		}

		if (name == NULL) {
			rtn = EFAULT;
			break;
		}

		if (persistent_auth_get((char *)name, auth) == B_TRUE) {
			/*
			 * Restore the value for overridden (and bogus) oid.
			 */
			auth->a_oid = old_oid;
			rtn = ddi_copyout(auth, (caddr_t)arg,
			    sizeof (*auth), mode);
		} else {
			rtn = EIO;
		}

		kmem_free(auth, sizeof (*auth));
		break;

	/*
	 *  ISCSI_AUTH_SET -
	 */
	case ISCSI_AUTH_SET:
		auth = (iscsi_auth_props_t *)kmem_zalloc(sizeof (*auth),
		    KM_SLEEP);
		if (ddi_copyin((caddr_t)arg, auth, sizeof (*auth), mode)) {
			kmem_free(auth, sizeof (*auth));
			rtn = EFAULT;
			break;
		} else if (auth->a_vers != ISCSI_INTERFACE_VERSION) {
			kmem_free(auth, sizeof (*auth));
			rtn = EINVAL;
			break;
		}

		if (auth->a_oid == ihp->hba_oid) {
			name = ihp->hba_name;
		} else {
			rw_enter(&ihp->hba_sess_list_rwlock, RW_READER);
			/*
			 * If the oid does represent a session check to see
			 * if it is a target oid.  If so, return the target's
			 * associated session.
			 */
			rtn = iscsi_sess_get(auth->a_oid, ihp, &isp);
			if (rtn != 0) {
				rtn = iscsi_sess_get_by_target(auth->a_oid,
				    ihp, &isp);
			}
			rw_exit(&ihp->hba_sess_list_rwlock);

			/*
			 * If rtn is zero then we have found an
			 * existing session.  Use the session name to
			 * do param lookup.  If rtn is non-zero then
			 * create a targetparam object and use its name
			 * for param lookup.
			 */
			if (rtn == 0) {
				name = isp->sess_name;
			} else {
				name =
				    iscsi_targetparam_get_name(auth->a_oid);
				rtn = 0;
			}
		}

		if (name == NULL) {
			rtn = EFAULT;
		} else if (persistent_auth_set((char *)name, auth)
		    == B_FALSE) {
			rtn = EIO;
		}

		kmem_free(auth, sizeof (*auth));
		break;

	/*
	 *  ISCSI_AUTH_CLEAR -
	 */
	case ISCSI_AUTH_CLEAR:
		auth = (iscsi_auth_props_t *)kmem_alloc(sizeof (*auth),
		    KM_SLEEP);
		if (ddi_copyin((caddr_t)arg, auth, sizeof (*auth), mode)) {
			kmem_free(auth, sizeof (*auth));
			rtn = EFAULT;
			break;
		} else if (auth->a_vers != ISCSI_INTERFACE_VERSION) {
			kmem_free(auth, sizeof (*auth));
			rtn = EINVAL;
			break;
		}

		rw_enter(&ihp->hba_sess_list_rwlock, RW_READER);
		/*
		 * If the oid does represent a session check to see
		 * if it is a target oid.  If so, return the target's
		 * associated session.
		 */
		rtn = iscsi_sess_get(auth->a_oid, ihp, &isp);
		if (rtn != 0) {
			rtn = iscsi_sess_get_by_target(auth->a_oid, ihp, &isp);
		}
		rw_exit(&ihp->hba_sess_list_rwlock);

		/*
		 * If rtn is zero then we have found an
		 * existing session.  Use the session name to
		 * do param lookup.  If rtn is non-zero then
		 * create a targetparam object and use its name
		 * for param lookup.
		 */
		if (rtn == 0) {
			name = isp->sess_name;
		} else {
			name =
			    iscsi_targetparam_get_name(auth->a_oid);
			rtn = 0;
			discovered = B_FALSE;
		}

		if (name == NULL) {
			rtn = EFAULT;
			break;
		}

		if (persistent_auth_clear((char *)name) == B_FALSE) {
			rtn = EIO;
		}

		/*
		 * ISCSI_TARGET_PARAM_CLEAR, ISCSI_CHAP_CLEAR and
		 * ISCSI_AUTH_CLEAR ioctl are called sequentially to remove
		 * target parameters. Here, the target that is not discovered
		 * by initiator should be removed from the iscsi_targets list
		 * residing in the memory.
		 */
		if (discovered == B_FALSE) {
			(void) iscsi_targetparam_remove_target(auth->a_oid);
		}

		kmem_free(auth, sizeof (*auth));
		break;

	/*
	 * ISCSI_DB_DUMP -
	 */
	case ISCSI_DB_DUMP:
		persistent_dump_data();
		break;

	case ISCSI_USCSI:

#ifdef _MULTI_DATAMODEL
		model = ddi_model_convert_from(mode & FMODELS);
		switch (model) {
		case DDI_MODEL_ILP32:

			if (ddi_copyin((caddr_t)arg, &iu32_caller,
			    sizeof (iscsi_uscsi32_t), mode)) {
				rtn = EFAULT;
				break;
			}

			/* perform conversion from 32 -> 64 */
			iu_caller.iu_vers = iu32_caller.iu_vers;
			iu_caller.iu_oid = iu32_caller.iu_oid;
			iu_caller.iu_tpgt = iu32_caller.iu_tpgt;
			iu_caller.iu_len = iu32_caller.iu_len;
			iu_caller.iu_lun = iu32_caller.iu_lun;
			uscsi_cmd32touscsi_cmd((&iu32_caller.iu_ucmd),
			    (&iu_caller.iu_ucmd));

			break;
		case DDI_MODEL_NONE:
			if (ddi_copyin((caddr_t)arg, &iu_caller,
			    sizeof (iscsi_uscsi_t), mode)) {
				rtn = EFAULT;
				break;
			}
			break;
		default:
			ASSERT(FALSE);
			rtn = EINVAL;
			break;
		}
#endif /* _MULTI_DATAMODEL */

		/* If failures earlier break */
		if (rtn != 0) {
			break;
		}

		/* copy from caller to internel cmd */
		bcopy(&iu_caller, &iu, sizeof (iu));

		if (iu.iu_vers != ISCSI_INTERFACE_VERSION) {
			rtn = EINVAL;
			break;
		}
		/*
		 * Check to see if oid references a target-param oid.  If so,
		 * find the associated  session oid before getting lu list.
		 */
		if (iscsi_targetparam_get_name(iu.iu_oid) != NULL) {
			for (isp = ihp->hba_sess_list; isp; isp =
			    isp->sess_next) {
				if (isp->sess_target_oid == iu.iu_oid) {
					target_oid  = isp->sess_oid;
					break;
				}
			}
		} else {
			target_oid = iu.iu_oid;
		}

		/* make sure we have a matching session for this command */
		rw_enter(&ihp->hba_sess_list_rwlock, RW_READER);
		rtn = iscsi_sess_get(target_oid, ihp, &isp);
		if (rtn != 0) {
			rtn = iscsi_sess_get_by_target(target_oid, ihp,
			    &isp);
			if (rtn != 0) {
				rw_exit(&ihp->hba_sess_list_rwlock);
				rtn = EFAULT;
				break;
			}
		}
		/*
		 * If a caller buffer is present allocate duplicate
		 * kernel space and copyin caller memory.
		 */
		if (iu.iu_ucmd.uscsi_buflen > 0) {
			iu.iu_ucmd.uscsi_bufaddr = (caddr_t)kmem_alloc(
			    iu.iu_ucmd.uscsi_buflen, KM_SLEEP);
			if (ddi_copyin(iu_caller.iu_ucmd.uscsi_bufaddr,
			    iu.iu_ucmd.uscsi_bufaddr,
			    iu.iu_ucmd.uscsi_buflen, mode)) {
				rw_exit(&ihp->hba_sess_list_rwlock);
				rtn = EFAULT;
				break;
			}
		}

		/*
		 * If a caller cdb is present allocate duplicate
		 * kernel space and copyin caller memory.
		 */
		if (iu.iu_ucmd.uscsi_cdblen > 0) {
			iu.iu_ucmd.uscsi_cdb = (caddr_t)kmem_alloc(
			    iu_caller.iu_ucmd.uscsi_cdblen, KM_SLEEP);
			if (ddi_copyin(iu_caller.iu_ucmd.uscsi_cdb,
			    iu.iu_ucmd.uscsi_cdb,
			    iu.iu_ucmd.uscsi_cdblen, mode)) {
				if (iu.iu_ucmd.uscsi_buflen > 0) {
					kmem_free(iu.iu_ucmd.uscsi_bufaddr,
					    iu_caller.iu_ucmd.uscsi_buflen);
				}
				rw_exit(&ihp->hba_sess_list_rwlock);
				rtn = EFAULT;
				break;
			}
		}

		/*
		 * If a caller request sense is present allocate
		 * duplicate kernel space.  No need to copyin.
		 */
		if (iu.iu_ucmd.uscsi_rqlen > 0) {
			iu.iu_ucmd.uscsi_rqbuf = (caddr_t)kmem_alloc(
			    iu.iu_ucmd.uscsi_rqlen, KM_SLEEP);
		}

		/* issue passthru to io path handler */
		rtn = iscsi_handle_passthru(isp, iu.iu_lun, &iu.iu_ucmd);
		if (rtn != 0) {
			rtn = EFAULT;
		}

		/*
		 * If the caller had a buf we need to do a copyout
		 * and free the kernel memory
		 */
		if (iu.iu_ucmd.uscsi_buflen > 0) {
			if (ddi_copyout(iu.iu_ucmd.uscsi_bufaddr,
			    iu_caller.iu_ucmd.uscsi_bufaddr,
			    iu.iu_ucmd.uscsi_buflen, mode) != 0) {
				rtn = EFAULT;
			}
			kmem_free(iu.iu_ucmd.uscsi_bufaddr,
			    iu.iu_ucmd.uscsi_buflen);
		}

		/* We need to free kernel cdb, no need to copyout */
		if (iu.iu_ucmd.uscsi_cdblen > 0) {
			kmem_free(iu.iu_ucmd.uscsi_cdb,
			    iu.iu_ucmd.uscsi_cdblen);
		}

		/*
		 * If the caller had a request sense we need to
		 * do a copyout and free the kernel memory
		 */
		if (iu.iu_ucmd.uscsi_rqlen > 0) {
			if (ddi_copyout(iu.iu_ucmd.uscsi_rqbuf,
			    iu_caller.iu_ucmd.uscsi_rqbuf,
			    iu.iu_ucmd.uscsi_rqlen - iu.iu_ucmd.uscsi_rqresid,
			    mode) != 0) {
				rtn = EFAULT;
			}
			kmem_free(iu.iu_ucmd.uscsi_rqbuf,
			    iu.iu_ucmd.uscsi_rqlen);
		}

#ifdef _MULTI_DATAMODEL
		switch (model = ddi_model_convert_from(mode & FMODELS)) {
		case DDI_MODEL_ILP32:
			if (iu.iu_ucmd.uscsi_status != 0) {
				iu32_caller.iu_ucmd.uscsi_status =
				    iu.iu_ucmd.uscsi_status;
				iu32_caller.iu_ucmd.uscsi_rqresid =
				    iu.iu_ucmd.uscsi_rqresid;
			}
			iu32_caller.iu_ucmd.uscsi_resid =
			    iu.iu_ucmd.uscsi_resid;
			if (ddi_copyout((void *)&iu32_caller, (caddr_t)arg,
			    sizeof (iscsi_uscsi32_t), mode) != 0) {
				rtn = EFAULT;
			}
			break;
		case DDI_MODEL_NONE:
			if (iu.iu_ucmd.uscsi_status != 0) {
				iu_caller.iu_ucmd.uscsi_status =
				    iu.iu_ucmd.uscsi_status;
				iu_caller.iu_ucmd.uscsi_rqresid =
				    iu.iu_ucmd.uscsi_rqresid;
			}
			iu_caller.iu_ucmd.uscsi_resid = iu.iu_ucmd.uscsi_resid;
			if (ddi_copyout((void *)&iu_caller, (caddr_t)arg,
			    sizeof (iscsi_uscsi_t), mode) != 0) {
				rtn = EFAULT;
			}
			break;
		default:
			ASSERT(FALSE);
		}
#endif /* _MULTI_DATAMODEL */
		rw_exit(&ihp->hba_sess_list_rwlock);
		break;

	case ISCSI_SMF_ONLINE:
		if (ddi_copyin((caddr_t)arg, &did, sizeof (int), mode) != 0) {
			rtn = EFAULT;
			break;
		}
		/* just a theoretical case */
		if (ihp->hba_persistent_loaded == B_FALSE) {
			rtn = EFAULT;
			break;
		}

		/* doesn't need to overwrite the status anymore */
		mutex_enter(&ihp->hba_service_lock);
		if (ihp->hba_service_status_overwrite == B_TRUE) {
			ihp->hba_service_status = ISCSI_SERVICE_DISABLED;
			ihp->hba_service_status_overwrite = B_FALSE;
		}
		mutex_exit(&ihp->hba_service_lock);

		if (iscsi_enter_service_zone(ihp, ISCSI_SERVICE_ENABLED) ==
		    B_FALSE) {
			break;
		}

		rval = iscsi_door_bind(did);
		if (rval == B_TRUE) {
			rval = iscsid_start(ihp);
			if (rval == B_FALSE) {
				iscsi_door_unbind();
			}
		}

		if (rval == B_TRUE) {
			iscsi_exit_service_zone(ihp, ISCSI_SERVICE_ENABLED);
		} else {
			iscsi_exit_service_zone(ihp, ISCSI_SERVICE_DISABLED);
			rtn = EFAULT;
		}

		break;

	case ISCSI_SMF_OFFLINE:
		if (iscsi_enter_service_zone(ihp, ISCSI_SERVICE_DISABLED)
		    == B_FALSE) {
			break;
		}

		rval = iscsid_stop(ihp);
		iscsi_door_unbind();

		iscsi_exit_service_zone(ihp, ISCSI_SERVICE_DISABLED);

		if (ddi_copyout((void *)&rval, (caddr_t)arg,
		    sizeof (boolean_t), mode) != 0) {
			rtn = EFAULT;
		}

		break;

	case ISCSI_SMF_GET:
		mutex_enter(&ihp->hba_service_lock);
		while (ihp->hba_service_status ==
		    ISCSI_SERVICE_TRANSITION) {
			cv_wait(&ihp->hba_service_cv,
			    &ihp->hba_service_lock);
		}
		if (ddi_copyout((void *)&ihp->hba_service_status,
		    (caddr_t)arg, sizeof (boolean_t), mode) != 0) {
			rtn = EFAULT;
		}
		mutex_exit(&ihp->hba_service_lock);
		break;

	case ISCSI_DISCOVERY_EVENTS:
		/*
		 * If discovery has not been completed and not in progress,
		 * poke the discovery methods
		 */
		mutex_enter(&ihp->hba_discovery_events_mutex);
		method = ihp->hba_discovery_events;
		if ((method != ISCSI_ALL_DISCOVERY_METHODS) &&
		    (ihp->hba_discovery_in_progress == B_FALSE)) {
			ihp->hba_discovery_in_progress = B_TRUE;
			mutex_exit(&ihp->hba_discovery_events_mutex);
			iscsid_poke_discovery(ihp, iSCSIDiscoveryMethodUnknown);
			mutex_enter(&ihp->hba_discovery_events_mutex);
			ihp->hba_discovery_in_progress = B_FALSE;
			method = ihp->hba_discovery_events;
		}
		mutex_exit(&ihp->hba_discovery_events_mutex);

		if (ddi_copyout((void *)&method, (caddr_t)arg,
		    sizeof (method), mode) != 0)
			rtn = EFAULT;
		break;

	/*
	 * ISCSI_SENDTGTS_GET --
	 */
	case ISCSI_SENDTGTS_GET:
		stl_hdr = iscsi_ioctl_copyin((caddr_t)arg, mode,
		    sizeof (*stl_hdr));
		if (stl_hdr == NULL) {
			rtn = EFAULT;
			break;
		}

		if (stl_hdr->stl_entry.e_vers != ISCSI_INTERFACE_VERSION) {
			rtn = EINVAL;
			kmem_free(stl_hdr, sizeof (*stl_hdr));
			break;
		}

		/* calculate how much memory user allocated for SendTgts */
		stl_sz = sizeof (*stl_hdr);
		if (stl_hdr->stl_in_cnt > 0) {
			stl_sz += ((stl_hdr->stl_in_cnt - 1) *
			    sizeof (iscsi_sendtgts_entry_t));
		}

		/* allocate local SendTgts list of the same size */
		istl = kmem_zalloc(stl_sz, KM_SLEEP);
		bcopy(stl_hdr, istl, sizeof (*stl_hdr));
		kmem_free(stl_hdr, sizeof (*stl_hdr));

		/* lock interface so only one SendTargets operation occurs */
		sema_p(&ihp->hba_sendtgts_semaphore);

		rtn = iscsi_ioctl_sendtgts_get(ihp, istl);

		if (rtn == 0) {
			rtn = iscsi_ioctl_copyout(istl, stl_sz,
			    (caddr_t)arg, mode);
		}

		/* release lock to allow another SendTargets discovery */
		sema_v(&ihp->hba_sendtgts_semaphore);

		break;

		/*
		 * ISCSI_ISNS_SERVER_GET --
		 */
	case ISCSI_ISNS_SERVER_GET:
		server_pg_list_hdr = iscsi_ioctl_copyin((caddr_t)arg, mode,
		    sizeof (*server_pg_list_hdr));
		if (server_pg_list_hdr == NULL) {
			rtn = EFAULT;
			break;
		}

		/* If iSNS discovery mode is not set, return with zero entry */
		method = persistent_disc_meth_get();
		if ((method & iSCSIDiscoveryMethodISNS) == 0) {
			kmem_free(server_pg_list_hdr,
			    sizeof (*server_pg_list_hdr));
			server_pg_list_hdr = NULL;
			rtn = EACCES;
			break;
		}

		initiator_node_name = kmem_zalloc(ISCSI_MAX_NAME_LEN, KM_SLEEP);
		if (persistent_initiator_name_get(initiator_node_name,
		    ISCSI_MAX_NAME_LEN) != B_TRUE) {
			kmem_free(initiator_node_name, ISCSI_MAX_NAME_LEN);
			initiator_node_name = NULL;
			kmem_free(server_pg_list_hdr,
			    sizeof (*server_pg_list_hdr));
			server_pg_list_hdr = NULL;
			rtn = EIO;
			break;
		}
		if (strlen(initiator_node_name) == 0) {
			kmem_free(initiator_node_name, ISCSI_MAX_NAME_LEN);
			initiator_node_name = NULL;
			kmem_free(server_pg_list_hdr,
			    sizeof (*server_pg_list_hdr));
			server_pg_list_hdr = NULL;
			rtn = EIO;
			break;
		}

		initiator_node_alias = kmem_zalloc(
		    ISCSI_MAX_NAME_LEN, KM_SLEEP);
		if (persistent_alias_name_get(initiator_node_alias,
		    ISCSI_MAX_NAME_LEN) != B_TRUE) {
			initiator_node_alias[0] = '\0';
		}
		rtn = isns_query_one_server(&(server_pg_list_hdr->addr),
		    ihp->hba_isid,
		    (uint8_t *)initiator_node_name,
		    (uint8_t *)initiator_node_alias,
		    ISNS_INITIATOR_NODE_TYPE,
		    &pg_list);
		if (rtn != isns_ok || pg_list == NULL) {
			kmem_free(initiator_node_name, ISCSI_MAX_NAME_LEN);
			initiator_node_name = NULL;
			kmem_free(initiator_node_alias, ISCSI_MAX_NAME_LEN);
			initiator_node_alias = NULL;
			kmem_free(server_pg_list_hdr,
			    sizeof (*server_pg_list_hdr));
			server_pg_list_hdr = NULL;
			rtn = EIO;
			break;
		}

		/*
		 * pg_list_sz is the size of the pg_list returned from the
		 *	isns_query_all
		 *
		 * pg_sz_copy_out is the size of the pg_list we are going to
		 *	return back to the caller
		 *
		 * server_pg_list_sz is total amount of data we are returning
		 *	back to the caller
		 */
		pg_list->pg_in_cnt =
		    server_pg_list_hdr->addr_port_list.pg_in_cnt;
		pg_list_sz = sizeof (isns_portal_group_list_t);
		if (pg_list->pg_out_cnt > 0) {
			pg_list_sz += (pg_list->pg_out_cnt - 1) *
			    sizeof (isns_portal_group_t);
		}
		/*
		 * check if caller passed in a buffer with enough space
		 * if there isn't enough space, fill the caller's buffer with
		 * as much information as possible.
		 *
		 * if pg_out_cnt > pg_in_cnt, pg_out_cnt will be returned with
		 * the total number of targets found
		 *
		 * if pg_out_cnt < pg_in_cnt, pg_out_cnt will be the number
		 * of targets returned
		 */
		if (pg_list->pg_in_cnt < pg_list->pg_out_cnt) {
			pg_sz_copy_out = sizeof (isns_portal_group_list_t);
			if (pg_list->pg_in_cnt > 0) {
				pg_sz_copy_out += (pg_list->pg_in_cnt - 1) *
				    sizeof (isns_portal_group_t);
			}
			server_pg_list_sz =
			    sizeof (isns_server_portal_group_list_t);
			if (pg_list->pg_in_cnt > 0) {
				server_pg_list_sz += (pg_list->pg_in_cnt - 1) *
				    sizeof (isns_portal_group_t);
			}
		} else {
			pg_sz_copy_out = pg_list_sz;
			server_pg_list_sz =
			    sizeof (isns_server_portal_group_list_t);
			if (pg_list->pg_out_cnt > 0) {
				server_pg_list_sz += (pg_list->pg_out_cnt - 1) *
				    sizeof (isns_portal_group_t);
			}
		}

		server_pg_list = (isns_server_portal_group_list_t *)kmem_zalloc(
		    server_pg_list_sz, KM_SLEEP);

		bcopy(&(server_pg_list_hdr->addr), &(server_pg_list->addr),
		    sizeof (server_pg_list->addr));
		bcopy(pg_list, &server_pg_list->addr_port_list, pg_sz_copy_out);

		if (ddi_copyout(server_pg_list, (caddr_t)arg, server_pg_list_sz,
		    mode) != 0) {
			rtn = EFAULT;
		}
		DTRACE_PROBE1(iscsi_ioctl_iscsi_isns_server_get_pg_sz,
		    int, pg_list_sz);
		kmem_free(initiator_node_name, ISCSI_MAX_NAME_LEN);
		initiator_node_name = NULL;
		kmem_free(initiator_node_alias, ISCSI_MAX_NAME_LEN);
		initiator_node_alias = NULL;
		kmem_free(pg_list, pg_list_sz);
		pg_list = NULL;
		kmem_free(server_pg_list, server_pg_list_sz);
		server_pg_list = NULL;
		kmem_free(server_pg_list_hdr, sizeof (*server_pg_list_hdr));
		server_pg_list_hdr = NULL;
		break;

	/*
	 * ISCSI_GET_CONFIG_SESSIONS --
	 */
	case ISCSI_GET_CONFIG_SESSIONS:
		/* FALLTHRU */

	case ISCSI_SET_CONFIG_SESSIONS:
		size = sizeof (*ics);
		ics = iscsi_ioctl_copyin((caddr_t)arg, mode, size);
		if (ics == NULL) {
			rtn = EFAULT;
			break;
		}

		/* verify version infomration */
		if (ics->ics_ver != ISCSI_INTERFACE_VERSION) {
			rtn = EINVAL;
			kmem_free(ics, size);
			ics = NULL;
			break;
		}

		/* Check to see if we need to copy in more memory */
		if (ics->ics_in > 1) {
			/* record correct size */
			size = ISCSI_SESSION_CONFIG_SIZE(ics->ics_in);
			/* free old buffer */
			kmem_free(ics, sizeof (*ics));

			/* copy in complete buffer size */
			ics = iscsi_ioctl_copyin((caddr_t)arg, mode, size);
			if (ics == NULL) {
				rtn = EFAULT;
				break;
			}
		}

		/* switch action based on get or set */
		if (cmd == ISCSI_GET_CONFIG_SESSIONS) {
			/* get */
			rtn = iscsi_ioctl_get_config_sess(ihp, ics);
			if (rtn == 0) {
				/* copyout data for gets */
				rtn = iscsi_ioctl_copyout(ics, size,
				    (caddr_t)arg, mode);
			} else {
				kmem_free(ics, size);
				ics = NULL;
			}
		} else {
			/* set */
			rtn = iscsi_ioctl_set_config_sess(ihp, ics);
			if (iscsiboot_prop) {
				if (iscsi_cmp_boot_sess_oid(ihp,
				    ics->ics_oid)) {
					/*
					 * found active session for this object
					 * or this is initiator object
					 * with mpxio enabled
					 */
					if (!iscsi_reconfig_boot_sess(ihp)) {
						kmem_free(ics, size);
						ics = NULL;
						rtn = EINVAL;
						break;
					}
				}
			}
			kmem_free(ics, size);
			ics = NULL;
		}
		break;

	case ISCSI_IS_ACTIVE:
		/*
		 * dhcpagent calls here to check if there are
		 * active iSCSI sessions
		 */
		instance = 0;
		if (iscsiboot_prop) {
			instance = 1;
		}
		if (!instance) {
			rw_enter(&ihp->hba_sess_list_rwlock,
			    RW_READER);
			for (isp = ihp->hba_sess_list; isp;
			    isp = isp->sess_next) {
				if ((isp->sess_state ==
				    ISCSI_SESS_STATE_LOGGED_IN) &&
				    (isp->sess_lun_list !=
				    NULL)) {
					instance = 1;
					break;
				}
			}
			rw_exit(&ihp->hba_sess_list_rwlock);
		}
		size = sizeof (instance);
		if (ddi_copyout(&instance, (caddr_t)arg, size,
		    mode) != 0) {
			rtn = EFAULT;
		}
		break;

	case ISCSI_BOOTPROP_GET:
		size = sizeof (*bootProp);
		bootProp = iscsi_ioctl_copyin((caddr_t)arg, mode, size);
		if (bootProp == NULL) {
			rtn = EFAULT;
			break;
		}
		bootProp->hba_mpxio_enabled =
		    iscsi_chk_bootlun_mpxio(ihp);
		if (iscsiboot_prop == NULL) {
			bootProp->iscsiboot = 0;
			rtn = iscsi_ioctl_copyout(bootProp, size,
			    (caddr_t)arg, mode);
			break;
		} else {
			bootProp->iscsiboot = 1;
		}

		if (iscsiboot_prop->boot_init.ini_name != NULL) {
			(void) strncpy((char *)bootProp->ini_name.n_name,
			    (char *)iscsiboot_prop->boot_init.ini_name,
			    ISCSI_MAX_NAME_LEN);
		}
		if (iscsiboot_prop->boot_init.ini_chap_name != NULL) {
			bootProp->auth.a_auth_method = authMethodCHAP;
			(void) strncpy((char *)bootProp->ini_chap.c_user,
			    (char *)iscsiboot_prop->boot_init.ini_chap_name,
			    ISCSI_MAX_NAME_LEN);
			(void) strncpy((char *)bootProp->ini_chap.c_secret,
			    (char *)iscsiboot_prop->boot_init.ini_chap_sec,
			    ISCSI_CHAP_SECRET_LEN);
			if (iscsiboot_prop->boot_tgt.tgt_chap_name !=
			    NULL) {
				bootProp->auth.a_bi_auth = B_TRUE;
			} else {
				bootProp->auth.a_bi_auth = B_FALSE;
			}
		}
		if (iscsiboot_prop->boot_tgt.tgt_name != NULL) {
			(void) strncpy((char *)bootProp->tgt_name.n_name,
			    (char *)iscsiboot_prop->boot_tgt.tgt_name,
			    ISCSI_MAX_NAME_LEN);
		}
		if (iscsiboot_prop->boot_tgt.tgt_chap_name != NULL) {
			(void) strncpy((char *)bootProp->tgt_chap.c_user,
			    (char *)iscsiboot_prop->boot_tgt.tgt_chap_name,
			    ISCSI_MAX_NAME_LEN);
			(void) strncpy((char *)bootProp->tgt_chap.c_secret,
			    (char *)iscsiboot_prop->boot_tgt.tgt_chap_sec,
			    ISCSI_CHAP_SECRET_LEN);
		}

		rtn = iscsi_ioctl_copyout(bootProp, size, (caddr_t)arg, mode);
		break;

	case ISCSI_TARGET_REENUM:
		size = sizeof (iscsi_reen_t);
		reenum = (iscsi_reen_t *)kmem_alloc(size, KM_SLEEP);

		if (ddi_copyin((caddr_t)arg, reenum, size, mode) != 0) {
			rtn = EFAULT;
			kmem_free(reenum, size);
			break;
		}
		if (reenum->re_ver != ISCSI_INTERFACE_VERSION) {
			rtn = EINVAL;
			kmem_free(reenum, size);
			break;
		}
		rw_enter(&ihp->hba_sess_list_rwlock, RW_READER);
		rtn = iscsi_sess_get(reenum->re_oid, ihp, &isp);
		if (rtn != 0) {
			rtn = iscsi_sess_get_by_target(
			    reenum->re_oid, ihp, &isp);
		}

		if (rtn != 0) {
			rw_exit(&ihp->hba_sess_list_rwlock);
			kmem_free(reenum, size);
			break;
		}
		kmem_free(reenum, size);
		if (isp->sess_type == ISCSI_SESS_TYPE_NORMAL) {
			rw_enter(&isp->sess_state_rwlock, RW_READER);
			if ((isp->sess_state ==
			    ISCSI_SESS_STATE_LOGGED_IN) &&
			    (iscsi_sess_enum_request(isp, B_TRUE,
			    isp->sess_state_event_count)
			    == ISCSI_SESS_ENUM_SUBMITTED)) {
				(void) iscsi_sess_enum_query(isp);
			}
			rw_exit(&isp->sess_state_rwlock);
		}
		rw_exit(&ihp->hba_sess_list_rwlock);
		break;

	case ISCSI_TUNABLE_PARAM_SET:
		tpss = (iscsi_tunable_object_t *)kmem_alloc(sizeof (*tpss),
		    KM_SLEEP);
		if (ddi_copyin((caddr_t)arg, tpss, sizeof (*tpss), mode)) {
			rtn = EFAULT;
			kmem_free(tpss, sizeof (*tpss));
			break;
		}
		rtn = iscsi_ioctl_set_tunable_param(ihp, tpss);
		kmem_free(tpss, sizeof (*tpss));
		break;

	case ISCSI_TUNABLE_PARAM_GET:
		tpsg = (iscsi_tunable_object_t *)kmem_alloc(sizeof (*tpsg),
		    KM_SLEEP);
		if (ddi_copyin((caddr_t)arg, tpsg, sizeof (*tpsg), mode)) {
			rtn = EFAULT;
			kmem_free(tpsg, sizeof (*tpsg));
			break;
		}
		if (tpsg->t_oid == ihp->hba_oid) {
			/* initiator */
			name = ihp->hba_name;
			if (iscsi_get_persisted_tunable_param((uchar_t *)name,
			    tpsg) == 1) {
				/*
				 * no persisted tunable parameters found
				 * for iscsi initiator, use default tunable
				 * params for initiator node.
				 */
				iscsi_get_tunable_default(tpsg);
			}
		} else {
			/* check whether it is a target oid */
			name = iscsi_targetparam_get_name(tpsg->t_oid);
			if (name == NULL) {
				/* invalid node name */
				rtn = EINVAL;
				kmem_free(tpsg, sizeof (*tpsg));
				break;
			}
			if (iscsi_get_persisted_tunable_param((uchar_t *)name,
			    tpsg) == 1) {
				/*
				 * no persisted tunable parameters found for
				 * iscsi target, use initiator's configure.
				 */
				if (iscsi_get_persisted_tunable_param(
				    (uchar_t *)ihp->hba_name, tpsg) == -1) {
					/*
					 * No initiator tunable parameters set
					 * use default value for target
					 */
					iscsi_get_tunable_default(tpsg);
				}
			}
		}

		if (ddi_copyout(tpsg, (caddr_t)arg,
		    sizeof (iscsi_tunable_object_t), mode) != 0) {
			rtn = EFAULT;
		}
		kmem_free(tpsg, sizeof (*tpsg));
		break;

	default:
		rtn = ENOTTY;
		cmn_err(CE_NOTE, "unrecognized ioctl 0x%x", cmd);
	} /* end of ioctl type switch/cases */

	if ((cmd != ISCSI_SMF_ONLINE) && (cmd != ISCSI_SMF_OFFLINE) &&
	    (cmd != ISCSI_SMF_GET)) {
		/* other cmds need to release the service */
		iscsi_client_release_service(ihp);
	}

	return (rtn);
}

/*
 * +--------------------------------------------------------------------+
 * | End of cb_ops routines					     |
 * +--------------------------------------------------------------------+
 */


/*
 * +--------------------------------------------------------------------+
 * | Common scsi_tran support routines				  |
 * +--------------------------------------------------------------------+
 */

/*
 * iscsi_i_commoncap -- SCSA host adapter get/set capability routines.
 *
 * Need to determine if any of these can be determined through the iSCSI
 * protocol. For now just return error on most.
 */
/* ARGSUSED */
static int
iscsi_i_commoncap(struct scsi_address *ap, char *cap, int val,
    int tgtonly, int doset)
{
	int		rtn;
	int		cidx;
	iscsi_lun_t	*ilp;

	ASSERT((ap)->a_hba_tran->tran_hba_private != NULL);
	ilp	= (iscsi_lun_t *)((ap)->a_hba_tran->tran_tgt_private);
	ASSERT(ilp != NULL);

	if (cap == (char *)0) {
		return (FALSE);
	}

	cidx = scsi_hba_lookup_capstr(cap);
	if (cidx == -1) {
		return (cidx);
	}

	/*
	 * Process setcap request.
	 */
	if (doset) {
		/*
		 * At present, we can only set binary (0/1) values
		 */
		switch (cidx) {
		case SCSI_CAP_LUN_RESET:
			if (val) {
				ilp->lun_cap |= ISCSI_LUN_CAP_RESET;
			} else {
				ilp->lun_cap &= ~ISCSI_LUN_CAP_RESET;
			}
			rtn = TRUE;
			break;
		default:
			/*
			 * None of these are settable via
			 * the capability interface.
			 */
			rtn = FALSE;
			break;
		}

		/*
		 * Process getcap request.
		 */
	} else {
		switch (cidx) {
		case SCSI_CAP_DMA_MAX:
			/* no DMA, Psuedo value */
			rtn = INT32_MAX;
			break;
		case SCSI_CAP_INITIATOR_ID:
			rtn = 7;
			break;
		case SCSI_CAP_ARQ:
		case SCSI_CAP_RESET_NOTIFICATION:
		case SCSI_CAP_TAGGED_QING:
			rtn = TRUE;
			break;
		case SCSI_CAP_SCSI_VERSION:
			rtn = SCSI_VERSION_3;
			break;
		case SCSI_CAP_INTERCONNECT_TYPE:
			rtn = INTERCONNECT_FABRIC;
			break;
		case SCSI_CAP_LUN_RESET:
			rtn = ((ilp->lun_cap & ISCSI_LUN_CAP_RESET) != 0) ?
			    TRUE : FALSE;
			break;
		case SCSI_CAP_CDB_LEN:
			/*
			 * iSCSI RFC 3720 defines a default 16 byte
			 * CDB as part of the Basic Header Segment
			 * (BHS) (10.2.1) and allows for an Additional
			 * Header Segment (AHS) Length of 255 * 4
			 * (10.2.1.5).  The AHS length can be used
			 * for different purposes two of which are
			 * Extended CDB ADS (10.2.2.3) and Bidirectional
			 * Expected Read-Data Length AHS (10.2.2.4).
			 * The largest header of these consumes is
			 * 32 bytes.  So the total Max CDB Length is
			 * 16 + ((255 * 4 ) - 32) = 1004.
			 */
			rtn = 1004;
			break;
		default:
			rtn = UNDEFINED;
			break;
		}
	}
	return (rtn);
}

/*
 * iscsi_virt_lun_init - attempts to complete a mdi/scsi_vhci binding
 *
 * This routine is used to associate the tran_tgt_private to our ilp
 * structure.  This function is indirectly called from our
 * iscsi_lun_create_xxx routines.  These routines must prevent
 * the session and lun lists from changing during this call.
 */
/* ARGSUSED */
static int
iscsi_virt_lun_init(dev_info_t *hba_dip, dev_info_t *lun_dip,
    scsi_hba_tran_t *hba_tran, struct scsi_device *sd)
{
	iscsi_lun_t	*ilp		= NULL;
	iscsi_lun_t	*ilp_check	= NULL;
	iscsi_sess_t	*isp		= NULL;
	char		*lun_guid	= NULL;
	mdi_pathinfo_t	*pip		= NULL;
	iscsi_hba_t	*ihp    = (iscsi_hba_t *)hba_tran->tran_hba_private;
	char		target_port_name[MAX_NAME_PROP_SIZE];

	/*
	 * Here's a nice little piece of undocumented stuff.
	 */
	if ((pip = (mdi_pathinfo_t *)sd->sd_private) == NULL) {
		/*
		 * Very bad news if this occurs. Somehow SCSI_vhci has
		 * lost the pathinfo node for this target.
		 */
		return (DDI_NOT_WELL_FORMED);
	}

	ilp = (iscsi_lun_t *)mdi_pi_get_phci_private(pip);

	/*
	 * +----------------------------------------------------+
	 * | Looking to find the target device via the property |
	 * | is not required since the driver can easily get    |
	 * | this information from the mdi_phci_get_private()   |
	 * | call above.  This is just a consistency check	|
	 * | which can be removed.				|
	 */
	if (mdi_prop_lookup_string(pip, MDI_GUID, &lun_guid) !=
	    DDI_PROP_SUCCESS) {
		return (DDI_NOT_WELL_FORMED);
	}

	for (isp = ihp->hba_sess_list; isp; isp = isp->sess_next) {

		/* If this isn't the matching session continue */
		if (ilp->lun_sess != isp) {
			continue;
		}

		/*
		 * We are already holding the lun list rwlock
		 * for this thread on the callers side of mdi_pi_online
		 * or ndi_devi_online.  Which lead to this functions
		 * call.
		 */
		for (ilp_check = isp->sess_lun_list; ilp_check;
		    ilp_check = ilp_check->lun_next) {

			/*
			 * If this is the matching LUN and contains
			 * the same LUN GUID then break we found our
			 * match.
			 */
			if ((ilp == ilp_check) &&
			    (strcmp(lun_guid, ilp_check->lun_guid) == 0)) {
				break;
			}
		}
		if (ilp_check != NULL) {
			break;
		}
	}

	/*
	 * Free resource that's no longer required.
	 */
	if (lun_guid != NULL)
		(void) mdi_prop_free(lun_guid);

	if (ilp_check == NULL) {
		/*
		 * Failed to find iSCSI LUN in HBA chain based
		 * on the GUID that was stored as a property on
		 * the pathinfo node.
		 */
		return (DDI_NOT_WELL_FORMED);
	}

	if (ilp != ilp_check) {
		/*
		 * The iSCSI target that we found on the HBA link is
		 * different than the iSCSI target that was stored as
		 * private data on the pathinfo node.
		 */
		return (DDI_NOT_WELL_FORMED);
	}
	/*
	 * | End of consistency check				|
	 * +----------------------------------------------------+
	 */

	hba_tran->tran_tgt_private = ilp;

	target_port_name[0] = '\0';
	if (ilp->lun_sess->sess_tpgt_conf == ISCSI_DEFAULT_TPGT) {
		(void) snprintf(target_port_name, MAX_NAME_PROP_SIZE,
		    "%02x%02x%02x%02x%02x%02x,%s",
		    ilp->lun_sess->sess_isid[0], ilp->lun_sess->sess_isid[1],
		    ilp->lun_sess->sess_isid[2], ilp->lun_sess->sess_isid[3],
		    ilp->lun_sess->sess_isid[4], ilp->lun_sess->sess_isid[5],
		    ilp->lun_sess->sess_name);
	} else {
		(void) snprintf(target_port_name, MAX_NAME_PROP_SIZE,
		    "%02x%02x%02x%02x%02x%02x,%s,%d",
		    ilp->lun_sess->sess_isid[0], ilp->lun_sess->sess_isid[1],
		    ilp->lun_sess->sess_isid[2], ilp->lun_sess->sess_isid[3],
		    ilp->lun_sess->sess_isid[4], ilp->lun_sess->sess_isid[5],
		    ilp->lun_sess->sess_name, ilp->lun_sess->sess_tpgt_conf);
	}

	if (mdi_prop_update_string(pip,
	    SCSI_ADDR_PROP_TARGET_PORT, target_port_name) != DDI_PROP_SUCCESS) {
		cmn_err(CE_WARN, "iscsi_virt_lun_init: Creating '"
		    SCSI_ADDR_PROP_TARGET_PORT "' property on Path(%p) "
		    "for Target(%s), Lun(%d) Failed",
		    (void *)pip, ilp->lun_sess->sess_name, ilp->lun_num);
	}

	return (DDI_SUCCESS);
}

/*
 * iscsi_phys_lun_init - attempts to complete a ndi binding
 *
 * This routine is used to associate the tran_tgt_private to our
 * ilp structure.  This function is indirectly called from our
 * iscsi_lun_create_xxx routines.  These routines must prevent
 * the session and lun lists from changing during this call.
 */
static int
iscsi_phys_lun_init(dev_info_t *hba_dip, dev_info_t *lun_dip,
    scsi_hba_tran_t *hba_tran, struct scsi_device *sd)
{
	int		rtn	= DDI_SUCCESS;
	iscsi_hba_t	*ihp	= NULL;
	iscsi_sess_t	*isp	= NULL;
	iscsi_lun_t	*ilp	= NULL;
	char		target_port_name[MAX_NAME_PROP_SIZE];
	int		*words = NULL;
	uint_t		nwords = 0;

	ASSERT(hba_dip);
	ASSERT(lun_dip);
	ASSERT(hba_tran);
	ASSERT(sd);
	ihp = (iscsi_hba_t *)hba_tran->tran_hba_private;
	ASSERT(ihp);

	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, lun_dip,
	    DDI_PROP_DONTPASS, LUN_PROP, &words, &nwords) != DDI_PROP_SUCCESS) {
		cmn_err(CE_WARN, "iscsi_phys_lun_init: Returning DDI_FAILURE:"
		    "lun for %s (instance %d)", ddi_get_name(lun_dip),
		    ddi_get_instance(lun_dip));
		return (DDI_FAILURE);
	}

	if (nwords == 0) {
		ddi_prop_free(words);
		return (DDI_FAILURE);
	}

	ASSERT(words != NULL);

	/* See if we already created this session */

	/* Walk the HBA's session list */
	for (isp = ihp->hba_sess_list; isp; isp = isp->sess_next) {
		/* compare target name as the unique identifier */
		if (sd->sd_address.a_target == isp->sess_oid) {
			/* found match */
			break;
		}
	}

	/* If we found matching session continue searching for tgt */
	if (isp != NULL) {
		/*
		 * Search for the matching iscsi lun structure.  We don't
		 * need to hold the READER for the lun list at this point.
		 * because the tran_get_name is being called from the online
		 * function which is already holding a reader on the lun
		 * list.
		 */
		for (ilp = isp->sess_lun_list; ilp; ilp = ilp->lun_next) {
			if (*words == ilp->lun_num) {
				/* found match */
				break;
			}
		}

		if (ilp != NULL) {
			/*
			 * tgt found path it to the tran_lun_private
			 * this is used later for fast access on
			 * init_pkt and start
			 */
			hba_tran->tran_tgt_private = ilp;
		} else {
			/* tgt not found */
			ddi_prop_free(words);
			return (DDI_FAILURE);
		}
	} else {
		/* sess not found */
		ddi_prop_free(words);
		return (DDI_FAILURE);
	}
	ddi_prop_free(words);

	target_port_name[0] = '\0';
	if (ilp->lun_sess->sess_tpgt_conf == ISCSI_DEFAULT_TPGT) {
		(void) snprintf(target_port_name, MAX_NAME_PROP_SIZE,
		    "%02x%02x%02x%02x%02x%02x,%s",
		    ilp->lun_sess->sess_isid[0], ilp->lun_sess->sess_isid[1],
		    ilp->lun_sess->sess_isid[2], ilp->lun_sess->sess_isid[3],
		    ilp->lun_sess->sess_isid[4], ilp->lun_sess->sess_isid[5],
		    ilp->lun_sess->sess_name);
	} else {
		(void) snprintf(target_port_name, MAX_NAME_PROP_SIZE,
		    "%02x%02x%02x%02x%02x%02x,%s,%d",
		    ilp->lun_sess->sess_isid[0], ilp->lun_sess->sess_isid[1],
		    ilp->lun_sess->sess_isid[2], ilp->lun_sess->sess_isid[3],
		    ilp->lun_sess->sess_isid[4], ilp->lun_sess->sess_isid[5],
		    ilp->lun_sess->sess_name, ilp->lun_sess->sess_tpgt_conf);
	}

	if (ddi_prop_update_string(DDI_DEV_T_NONE, lun_dip,
	    SCSI_ADDR_PROP_TARGET_PORT, target_port_name) != DDI_PROP_SUCCESS) {
		cmn_err(CE_WARN, "iscsi_phys_lun_init: Creating '"
		    SCSI_ADDR_PROP_TARGET_PORT "' property on Target(%s), "
		    "Lun(%d) Failed", ilp->lun_sess->sess_name, ilp->lun_num);
	}

	return (rtn);
}

/*
 * +--------------------------------------------------------------------+
 * | End of scsi_tran support routines					|
 * +--------------------------------------------------------------------+
 */

/*
 * +--------------------------------------------------------------------+
 * | Begin of struct utility routines					|
 * +--------------------------------------------------------------------+
 */


/*
 * iscsi_set_default_login_params - This function sets the
 * driver default login params.  This is using during the
 * creation of our iSCSI HBA structure initialization by
 * could be used at other times to reset back to the defaults.
 */
void
iscsi_set_default_login_params(iscsi_login_params_t *params)
{
	params->immediate_data		= ISCSI_DEFAULT_IMMEDIATE_DATA;
	params->initial_r2t		= ISCSI_DEFAULT_INITIALR2T;
	params->first_burst_length	= ISCSI_DEFAULT_FIRST_BURST_LENGTH;
	params->max_burst_length	= ISCSI_DEFAULT_MAX_BURST_LENGTH;
	params->data_pdu_in_order	= ISCSI_DEFAULT_DATA_PDU_IN_ORDER;
	params->data_sequence_in_order	= ISCSI_DEFAULT_DATA_SEQUENCE_IN_ORDER;
	params->default_time_to_wait	= ISCSI_DEFAULT_TIME_TO_WAIT;
	params->default_time_to_retain	= ISCSI_DEFAULT_TIME_TO_RETAIN;
	params->header_digest		= ISCSI_DEFAULT_HEADER_DIGEST;
	params->data_digest		= ISCSI_DEFAULT_DATA_DIGEST;
	params->max_recv_data_seg_len	= ISCSI_DEFAULT_MAX_RECV_SEG_LEN;
	params->max_xmit_data_seg_len	= ISCSI_DEFAULT_MAX_XMIT_SEG_LEN;
	params->max_connections		= ISCSI_DEFAULT_MAX_CONNECTIONS;
	params->max_outstanding_r2t	= ISCSI_DEFAULT_MAX_OUT_R2T;
	params->error_recovery_level	= ISCSI_DEFAULT_ERROR_RECOVERY_LEVEL;
	params->ifmarker		= ISCSI_DEFAULT_IFMARKER;
	params->ofmarker		= ISCSI_DEFAULT_OFMARKER;
}

/* Helper function to sets the driver default tunable parameters */
static void
iscsi_set_default_tunable_params(iscsi_tunable_params_t *params)
{
	params->recv_login_rsp_timeout = ISCSI_DEFAULT_RX_TIMEOUT_VALUE;
	params->conn_login_max = ISCSI_DEFAULT_CONN_DEFAULT_LOGIN_MAX;
	params->polling_login_delay = ISCSI_DEFAULT_LOGIN_POLLING_DELAY;
}

/*
 * +--------------------------------------------------------------------+
 * | End of struct utility routines				     |
 * +--------------------------------------------------------------------+
 */

/*
 * +--------------------------------------------------------------------+
 * | Begin of ioctl utility routines				    |
 * +--------------------------------------------------------------------+
 */

/*
 * iscsi_get_param - This function is a helper to ISCSI_GET_PARAM
 * IOCTL
 */
int
iscsi_get_param(iscsi_login_params_t *params, boolean_t valid_flag,
    iscsi_param_get_t *ipgp)
{
	int rtn = 0;

	/* ---- Default to settable, possibly changed later ---- */
	ipgp->g_value.v_valid    = valid_flag;
	ipgp->g_value.v_settable = B_TRUE;

	switch (ipgp->g_param) {
	/*
	 * Boolean parameters
	 */
	case ISCSI_LOGIN_PARAM_DATA_SEQUENCE_IN_ORDER:
		ipgp->g_value.v_bool.b_current =
		    params->data_sequence_in_order;
		ipgp->g_value.v_bool.b_default =
		    ISCSI_DEFAULT_DATA_SEQUENCE_IN_ORDER;
		break;
	case ISCSI_LOGIN_PARAM_IMMEDIATE_DATA:
		ipgp->g_value.v_bool.b_current =
		    params->immediate_data;
		ipgp->g_value.v_bool.b_default =
		    ISCSI_DEFAULT_IMMEDIATE_DATA;
		break;
	case ISCSI_LOGIN_PARAM_INITIAL_R2T:
		ipgp->g_value.v_bool.b_current =
		    params->initial_r2t;
		ipgp->g_value.v_bool.b_default =
		    ISCSI_DEFAULT_IMMEDIATE_DATA;
		break;
	case ISCSI_LOGIN_PARAM_DATA_PDU_IN_ORDER:
		ipgp->g_value.v_bool.b_current =
		    params->data_pdu_in_order;
		ipgp->g_value.v_bool.b_default =
		    ISCSI_DEFAULT_DATA_PDU_IN_ORDER;
		break;

	/*
	 * Integer parameters
	 */
	case ISCSI_LOGIN_PARAM_HEADER_DIGEST:
		ipgp->g_value.v_integer.i_current = params->header_digest;
		ipgp->g_value.v_integer.i_default = ISCSI_DEFAULT_HEADER_DIGEST;
		ipgp->g_value.v_integer.i_min = 0;
		ipgp->g_value.v_integer.i_max = ISCSI_MAX_HEADER_DIGEST;
		ipgp->g_value.v_integer.i_incr = 1;
		break;
	case ISCSI_LOGIN_PARAM_DATA_DIGEST:
		ipgp->g_value.v_integer.i_current = params->data_digest;
		ipgp->g_value.v_integer.i_default = ISCSI_DEFAULT_DATA_DIGEST;
		ipgp->g_value.v_integer.i_min = 0;
		ipgp->g_value.v_integer.i_max = ISCSI_MAX_DATA_DIGEST;
		ipgp->g_value.v_integer.i_incr = 1;
		break;
	case ISCSI_LOGIN_PARAM_DEFAULT_TIME_2_RETAIN:
		ipgp->g_value.v_integer.i_current =
		    params->default_time_to_retain;
		ipgp->g_value.v_integer.i_default =
		    ISCSI_DEFAULT_TIME_TO_RETAIN;
		ipgp->g_value.v_integer.i_min = 0;
		ipgp->g_value.v_integer.i_max = ISCSI_MAX_TIME2RETAIN;
		ipgp->g_value.v_integer.i_incr = 1;
		break;
	case ISCSI_LOGIN_PARAM_DEFAULT_TIME_2_WAIT:
		ipgp->g_value.v_integer.i_current =
		    params->default_time_to_wait;
		ipgp->g_value.v_integer.i_default =
		    ISCSI_DEFAULT_TIME_TO_WAIT;
		ipgp->g_value.v_integer.i_min = 0;
		ipgp->g_value.v_integer.i_max = ISCSI_MAX_TIME2WAIT;
		ipgp->g_value.v_integer.i_incr = 1;
		break;
	case ISCSI_LOGIN_PARAM_ERROR_RECOVERY_LEVEL:
		ipgp->g_value.v_integer.i_current =
		    params->error_recovery_level;
		ipgp->g_value.v_integer.i_default =
		    ISCSI_DEFAULT_ERROR_RECOVERY_LEVEL;
		ipgp->g_value.v_integer.i_min = 0;
		ipgp->g_value.v_integer.i_max = ISCSI_MAX_ERROR_RECOVERY_LEVEL;
		ipgp->g_value.v_integer.i_incr = 1;
		ipgp->g_value.v_settable = B_FALSE;
		break;
	case ISCSI_LOGIN_PARAM_FIRST_BURST_LENGTH:
		ipgp->g_value.v_integer.i_current =
		    params->first_burst_length;
		ipgp->g_value.v_integer.i_default =
		    ISCSI_DEFAULT_FIRST_BURST_LENGTH;
		ipgp->g_value.v_integer.i_min = 512;
		ipgp->g_value.v_integer.i_max = ISCSI_MAX_FIRST_BURST_LENGTH;
		ipgp->g_value.v_integer.i_incr = 1;
		break;
	case ISCSI_LOGIN_PARAM_MAX_BURST_LENGTH:
		ipgp->g_value.v_integer.i_current =
		    params->max_burst_length;
		ipgp->g_value.v_integer.i_default =
		    ISCSI_DEFAULT_MAX_BURST_LENGTH;
		ipgp->g_value.v_integer.i_min = 512;
		ipgp->g_value.v_integer.i_max = ISCSI_MAX_BURST_LENGTH;
		ipgp->g_value.v_integer.i_incr = 1;
		break;
	case ISCSI_LOGIN_PARAM_MAX_CONNECTIONS:
		ipgp->g_value.v_integer.i_current =
		    params->max_connections;
		ipgp->g_value.v_settable = B_FALSE;
		ipgp->g_value.v_integer.i_default =
		    ISCSI_DEFAULT_MAX_CONNECTIONS;
		ipgp->g_value.v_integer.i_min = 1;
		ipgp->g_value.v_integer.i_max = ISCSI_MAX_CONNECTIONS;
		ipgp->g_value.v_integer.i_incr = 1;
		break;
	case ISCSI_LOGIN_PARAM_OUTSTANDING_R2T:
		ipgp->g_value.v_integer.i_current =
		    params->max_outstanding_r2t;
		ipgp->g_value.v_settable = B_FALSE;
		ipgp->g_value.v_integer.i_default =
		    ISCSI_DEFAULT_MAX_OUT_R2T;
		ipgp->g_value.v_integer.i_min = 1;
		ipgp->g_value.v_integer.i_max = ISCSI_MAX_OUTSTANDING_R2T;
		ipgp->g_value.v_integer.i_incr = 1;
		break;
	case ISCSI_LOGIN_PARAM_MAX_RECV_DATA_SEGMENT_LENGTH:
		ipgp->g_value.v_integer.i_current =
		    params->max_recv_data_seg_len;
		ipgp->g_value.v_integer.i_default =
		    ISCSI_DEFAULT_MAX_RECV_SEG_LEN;
		ipgp->g_value.v_integer.i_min = 512;
		ipgp->g_value.v_integer.i_max =
		    ISCSI_MAX_RECV_DATA_SEGMENT_LENGTH;
		ipgp->g_value.v_integer.i_incr = 1;
		break;
	default:
		rtn = EINVAL;
	}

	return (rtn);
}

/*
 * +--------------------------------------------------------------------+
 * | End of ioctl utility routines                                      |
 * +--------------------------------------------------------------------+
 */

/*
 * iscsi_get_name_from_iqn - Translates a normal iqn/eui into a
 * IEEE safe address.  IEEE addresses have a number of characters
 * set aside as reserved.
 */
static void
iscsi_get_name_from_iqn(char *name, int name_max_len)
{
	char	*tmp		= NULL;
	char	*oldch		= NULL;
	char	*newch		= NULL;

	tmp = kmem_zalloc(MAX_GET_NAME_SIZE, KM_SLEEP);

	for (oldch = &name[0], newch = &tmp[0]; *oldch != '\0';
	    oldch++, newch++) {
		switch (*oldch) {
		case ':':
			*newch++ = '%';
			*newch++ = '3';
			*newch = 'A';
			break;
		case ' ':
			*newch++ = '%';
			*newch++ = '2';
			*newch = '0';
			break;
		case '@':
			*newch++ = '%';
			*newch++ = '4';
			*newch = '0';
			break;
		case '/':
			*newch++ = '%';
			*newch++ = '2';
			*newch = 'F';
			break;
		default:
			*newch = *oldch;
		}
	}
	(void) strncpy(name, tmp, name_max_len);
	kmem_free(tmp, MAX_GET_NAME_SIZE);
}

/*
 * iscsi_get_name_to_iqn - Converts IEEE safe address back
 * into a iscsi iqn/eui.
 */
static void
iscsi_get_name_to_iqn(char *name, int name_max_len)
{
	char	*tmp		= NULL;
	char	*oldch		= NULL;
	char	*newch		= NULL;

	tmp = kmem_zalloc(MAX_GET_NAME_SIZE, KM_SLEEP);

	for (oldch = &name[0], newch = &tmp[0]; *oldch != '\0';
	    oldch++, newch++) {
		if (*oldch == '%') {
			switch (*(oldch+1)) {
			case '2':
				if (*(oldch+2) == '0') {
					*newch = ' ';
					oldch += 2;
				} else if (*(oldch+2) == 'F') {
					*newch = '/';
					oldch += 2;
				} else {
					*newch = *oldch;
				}
				break;
			case '3':
				if (*(oldch+2) == 'A') {
					*newch = ':';
					oldch += 2;
				} else {
					*newch = *oldch;
				}
				break;
			case '4':
				if (*(oldch+2) == '0') {
					*newch = '@';
					oldch += 2;
				} else {
					*newch = *oldch;
				}
				break;
			default:
				*newch = *oldch;
			}
		} else {
			*newch = *oldch;
		}
	}
	(void) strncpy(name, tmp, name_max_len);
	kmem_free(tmp, MAX_GET_NAME_SIZE);
}

/*
 * iscsi_get_persisted_param * - a helper to ISCSI_GET_PARAM ioctl
 *
 * On return 0 means persisted parameter found
 */
int
iscsi_get_persisted_param(uchar_t *name, iscsi_param_get_t *ipgp,
    iscsi_login_params_t *params)
{
	int rtn = 1;
	persistent_param_t *pparam;

	if (name == NULL || strlen((char *)name) == 0) {
		return (rtn);
	}

	pparam = (persistent_param_t *)kmem_zalloc(sizeof (*pparam), KM_SLEEP);

	if (persistent_param_get((char *)name, pparam) == B_TRUE) {
		if (pparam->p_bitmap & (1 << ipgp->g_param)) {
			/* Found configured parameter. */
			bcopy(&pparam->p_params, params, sizeof (*params));
			rtn = 0;
		}
	}

	kmem_free(pparam, sizeof (*pparam));

	return (rtn);
}

/*
 * iscsi_override_target_default - helper function set the target's default
 * login parameter if there is a configured initiator parameter.
 *
 */
static void
iscsi_override_target_default(iscsi_hba_t *ihp, iscsi_param_get_t *ipg)
{
	persistent_param_t *pp;
	iscsi_login_params_t *params;

	pp = (persistent_param_t *)kmem_zalloc(sizeof (*pp), KM_SLEEP);
	if (persistent_param_get((char *)ihp->hba_name, pp) == B_TRUE) {
		if (pp->p_bitmap & (1 << ipg->g_param)) {
			params = &pp->p_params;
			switch (ipg->g_param) {
			case ISCSI_LOGIN_PARAM_DATA_SEQUENCE_IN_ORDER:
				ipg->g_value.v_bool.b_default =
				    params->data_sequence_in_order;
				break;
			case ISCSI_LOGIN_PARAM_IMMEDIATE_DATA:
				ipg->g_value.v_bool.b_default =
				    params->immediate_data;
				break;
			case ISCSI_LOGIN_PARAM_INITIAL_R2T:
				ipg->g_value.v_bool.b_default =
				    params->initial_r2t;
				break;
			case ISCSI_LOGIN_PARAM_DATA_PDU_IN_ORDER:
				ipg->g_value.v_bool.b_default =
				    params->data_pdu_in_order;
				break;
			case ISCSI_LOGIN_PARAM_HEADER_DIGEST:
				ipg->g_value.v_integer.i_default =
				    params->header_digest;
				break;
			case ISCSI_LOGIN_PARAM_DATA_DIGEST:
				ipg->g_value.v_integer.i_default =
				    params->data_digest;
				break;
			case ISCSI_LOGIN_PARAM_DEFAULT_TIME_2_RETAIN:
				ipg->g_value.v_integer.i_default =
				    params->default_time_to_retain;
				break;
			case ISCSI_LOGIN_PARAM_DEFAULT_TIME_2_WAIT:
				ipg->g_value.v_integer.i_default =
				    params->default_time_to_wait;
				break;
			case ISCSI_LOGIN_PARAM_ERROR_RECOVERY_LEVEL:
				ipg->g_value.v_integer.i_default =
				    params->error_recovery_level;
				break;
			case ISCSI_LOGIN_PARAM_FIRST_BURST_LENGTH:
				ipg->g_value.v_integer.i_default =
				    params->first_burst_length;
				break;
			case ISCSI_LOGIN_PARAM_MAX_BURST_LENGTH:
				ipg->g_value.v_integer.i_default =
				    params->max_burst_length;
				break;
			case ISCSI_LOGIN_PARAM_MAX_CONNECTIONS:
				ipg->g_value.v_integer.i_default =
				    params->max_connections;
				break;
			case ISCSI_LOGIN_PARAM_OUTSTANDING_R2T:
				ipg->g_value.v_integer.i_default =
				    params->max_outstanding_r2t;
				break;
			case ISCSI_LOGIN_PARAM_MAX_RECV_DATA_SEGMENT_LENGTH:
				ipg->g_value.v_integer.i_default =
				    params->max_xmit_data_seg_len;
				break;
			default:
				break;
			}
		}
	}
	kmem_free(pp, sizeof (*pp));
}

static boolean_t
iscsi_cmp_boot_sess_oid(iscsi_hba_t *ihp, uint32_t oid)
{
	iscsi_sess_t *isp = NULL;

	if (iscsi_chk_bootlun_mpxio(ihp)) {
		for (isp = ihp->hba_sess_list; isp; isp = isp->sess_next) {
			if ((isp->sess_oid == oid) && isp->sess_boot) {
				/* oid is session object */
				break;
			}
			if ((isp->sess_target_oid == oid) && isp->sess_boot) {
				/*
				 * oid is target object while
				 * this session is boot session
				 */
				break;
			}
		}
		if (oid == ihp->hba_oid) {
			/* oid is initiator object id */
			return (B_TRUE);
		} else if ((isp != NULL) && (isp->sess_boot)) {
			/* oid is boot session object id */
			return (B_TRUE);
		}
	}
	return (B_FALSE);
}

/*
 * iscsi_client_request_service - request the iSCSI service
 *     returns true if the service is enabled and increases the count
 *     returns false if the service is disabled
 *     blocks until the service status is either enabled or disabled
 */
boolean_t
iscsi_client_request_service(iscsi_hba_t *ihp)
{
	boolean_t	rval = B_TRUE;

	mutex_enter(&ihp->hba_service_lock);
	while ((ihp->hba_service_status == ISCSI_SERVICE_TRANSITION) ||
	    (ihp->hba_service_client_count == UINT_MAX)) {
		cv_wait(&ihp->hba_service_cv, &ihp->hba_service_lock);
	}
	if (ihp->hba_service_status == ISCSI_SERVICE_ENABLED) {
		ihp->hba_service_client_count++;
	} else {
		rval = B_FALSE;
	}
	mutex_exit(&ihp->hba_service_lock);

	return (rval);
}

/*
 * iscsi_client_release_service - decrease the count and wake up
 *     blocking threads if the count reaches zero
 */
void
iscsi_client_release_service(iscsi_hba_t *ihp)
{
	mutex_enter(&ihp->hba_service_lock);
	ASSERT(ihp->hba_service_client_count > 0);
	ihp->hba_service_client_count--;
	if (ihp->hba_service_client_count == 0) {
		cv_broadcast(&ihp->hba_service_cv);
	}
	mutex_exit(&ihp->hba_service_lock);
}

/*
 * iscsi_enter_service_zone - enter the service zone, should be called
 * before doing any modifications to the service status
 * return TRUE if the zone is entered
 *	  FALSE if no need to enter the zone
 */
static boolean_t
iscsi_enter_service_zone(iscsi_hba_t *ihp, uint32_t status)
{
	if ((status != ISCSI_SERVICE_ENABLED) &&
	    (status != ISCSI_SERVICE_DISABLED)) {
		return (B_FALSE);
	}

	mutex_enter(&ihp->hba_service_lock);
	while (ihp->hba_service_status == ISCSI_SERVICE_TRANSITION) {
		cv_wait(&ihp->hba_service_cv, &ihp->hba_service_lock);
	}
	if (ihp->hba_service_status == status) {
		mutex_exit(&ihp->hba_service_lock);
		return (B_FALSE);
	}
	ihp->hba_service_status = ISCSI_SERVICE_TRANSITION;
	while (ihp->hba_service_client_count > 0) {
		cv_wait(&ihp->hba_service_cv, &ihp->hba_service_lock);
	}
	mutex_exit(&ihp->hba_service_lock);
	return (B_TRUE);
}

/*
 * iscsi_exit_service_zone - exits the service zone and wakes up waiters
 */
static void
iscsi_exit_service_zone(iscsi_hba_t *ihp, uint32_t status)
{
	if ((status != ISCSI_SERVICE_ENABLED) &&
	    (status != ISCSI_SERVICE_DISABLED)) {
		return;
	}

	mutex_enter(&ihp->hba_service_lock);
	ASSERT(ihp->hba_service_status == ISCSI_SERVICE_TRANSITION);
	ihp->hba_service_status = status;
	cv_broadcast(&ihp->hba_service_cv);
	mutex_exit(&ihp->hba_service_lock);
}

static void
iscsi_check_miniroot(iscsi_hba_t *ihp)
{
	if (strncmp(rootfs.bo_name, "/ramdisk", 8) == 0) {
		/*
		 * in miniroot we don't have the persistent store
		 * so just to need to ensure an enabled status
		 */
		ihp->hba_service_status = ISCSI_SERVICE_ENABLED;
	}
}

static void
iscsi_get_tunable_default(iscsi_tunable_object_t *param)
{
	int	param_id = 0;

	param_id = 1 << (param->t_param - 1);
	param->t_set = B_FALSE;
	switch (param_id) {
	case ISCSI_TUNABLE_PARAM_RX_TIMEOUT_VALUE:
		param->t_value.v_integer = ISCSI_DEFAULT_RX_TIMEOUT_VALUE;
		break;
	case ISCSI_TUNABLE_PARAM_LOGIN_POLLING_DELAY:
		param->t_value.v_integer = ISCSI_DEFAULT_LOGIN_POLLING_DELAY;
		break;
	case ISCSI_TUNABLE_PARAM_CONN_LOGIN_MAX:
		param->t_value.v_integer = ISCSI_DEFAULT_CONN_DEFAULT_LOGIN_MAX;
		break;
	default:
		break;
	}
}

/*
 * iscsi_get_persisted_tunable_param * - a helper to ISCSI_TUNABLE_PARAM_GET
 * ioctl
 * return:
 *    0		persisted tunable parameter found
 *    1		persisted tunable parameter not found
 */
static int
iscsi_get_persisted_tunable_param(uchar_t *name, iscsi_tunable_object_t *tpsg)
{
	int rtn = 1;
	int param_id = 0;
	persistent_tunable_param_t *pparam;

	if ((name == NULL) || strlen((char *)name) == 0) {
		return (rtn);
	}

	tpsg->t_set = B_FALSE;
	pparam = (persistent_tunable_param_t *)kmem_zalloc(sizeof (*pparam),
	    KM_SLEEP);
	if (persistent_get_tunable_param((char *)name, pparam) == B_TRUE) {
		if (pparam->p_bitmap & (1 << (tpsg->t_param - 1))) {
			tpsg->t_set = B_TRUE;
			param_id = 1 << (tpsg->t_param - 1);
			switch (param_id) {
			case ISCSI_TUNABLE_PARAM_RX_TIMEOUT_VALUE:
				tpsg->t_value.v_integer =
				    pparam->p_params.recv_login_rsp_timeout;
				break;
			case ISCSI_TUNABLE_PARAM_LOGIN_POLLING_DELAY:
				tpsg->t_value.v_integer =
				    pparam->p_params.polling_login_delay;
				break;
			case ISCSI_TUNABLE_PARAM_CONN_LOGIN_MAX:
				tpsg->t_value.v_integer =
				    pparam->p_params.conn_login_max;
				break;
			default:
				break;
			}
			rtn = 0;
		}
	}

	kmem_free(pparam, sizeof (*pparam));

	return (rtn);
}
