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
 * Copyright (c) 2011 Bayard G. Bell. All rights reserved.
 */

/*
 * sf - Solaris Fibre Channel driver
 *
 * This module implements some of the Fibre Channel FC-4 layer, converting
 * from FC frames to SCSI and back.  (Note: no sequence management is done
 * here, though.)
 */

#if defined(lint) && !defined(DEBUG)
#define	DEBUG	1
#endif

/*
 * XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
 * Need to use the ugly RAID LUN mappings in FCP Annex D
 * to prevent SCSA from barfing.  This *REALLY* needs to
 * be addressed by the standards committee.
 */
#define	RAID_LUNS	1

#ifdef DEBUG
static int sfdebug = 0;
#include <sys/debug.h>

#define	SF_DEBUG(level, args) \
	if (sfdebug >= (level)) sf_log args
#else
#define	SF_DEBUG(level, args)
#endif

static int sf_bus_config_debug = 0;

#include <sys/scsi/scsi.h>
#include <sys/fc4/fcal.h>
#include <sys/fc4/fcp.h>
#include <sys/fc4/fcal_linkapp.h>
#include <sys/socal_cq_defs.h>
#include <sys/fc4/fcal_transport.h>
#include <sys/fc4/fcio.h>
#include <sys/scsi/adapters/sfvar.h>
#include <sys/scsi/impl/scsi_reset_notify.h>
#include <sys/stat.h>
#include <sys/varargs.h>
#include <sys/var.h>
#include <sys/thread.h>
#include <sys/proc.h>
#include <sys/kstat.h>
#include <sys/devctl.h>
#include <sys/scsi/targets/ses.h>
#include <sys/callb.h>
#include <sys/sysmacros.h>

static int sf_info(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int sf_attach(dev_info_t *, ddi_attach_cmd_t);
static int sf_detach(dev_info_t *, ddi_detach_cmd_t);
static void sf_softstate_unlink(struct sf *);
static int sf_scsi_bus_config(dev_info_t *parent, uint_t flag,
    ddi_bus_config_op_t op, void *arg, dev_info_t **childp);
static int sf_scsi_bus_unconfig(dev_info_t *parent, uint_t flag,
    ddi_bus_config_op_t op, void *arg);
static int sf_scsi_tgt_init(dev_info_t *, dev_info_t *,
    scsi_hba_tran_t *, struct scsi_device *);
static void sf_scsi_tgt_free(dev_info_t *, dev_info_t *,
    scsi_hba_tran_t *, struct scsi_device *);
static int sf_pkt_alloc_extern(struct sf *, struct sf_pkt *,
    int, int, int);
static void sf_pkt_destroy_extern(struct sf *, struct sf_pkt *);
static struct scsi_pkt *sf_scsi_init_pkt(struct scsi_address *,
    struct scsi_pkt *, struct buf *, int, int, int, int, int (*)(), caddr_t);
static void sf_scsi_destroy_pkt(struct scsi_address *, struct scsi_pkt *);
static void sf_scsi_dmafree(struct scsi_address *, struct scsi_pkt *);
static void sf_scsi_sync_pkt(struct scsi_address *, struct scsi_pkt *);
static int sf_scsi_reset_notify(struct scsi_address *, int,
    void (*)(caddr_t), caddr_t);
static int sf_scsi_get_name(struct scsi_device *, char *, int);
static int sf_scsi_get_bus_addr(struct scsi_device *, char *, int);
static int sf_add_cr_pool(struct sf *);
static int sf_cr_alloc(struct sf *, struct sf_pkt *, int (*)());
static void sf_cr_free(struct sf_cr_pool *, struct sf_pkt *);
static void sf_crpool_free(struct sf *);
static int sf_kmem_cache_constructor(void *, void *, int);
static void sf_kmem_cache_destructor(void *, void *);
static void sf_statec_callback(void *, int);
static int sf_login(struct sf *, uchar_t, uchar_t, uint_t, int);
static int sf_els_transport(struct sf *, struct sf_els_hdr *);
static void sf_els_callback(struct fcal_packet *);
static int sf_do_prli(struct sf *, struct sf_els_hdr *, struct la_els_logi *);
static int sf_do_adisc(struct sf *, struct sf_els_hdr *);
static int sf_do_reportlun(struct sf *, struct sf_els_hdr *,
    struct sf_target *);
static void sf_reportlun_callback(struct fcal_packet *);
static int sf_do_inquiry(struct sf *, struct sf_els_hdr *,
    struct sf_target *);
static void sf_inq_callback(struct fcal_packet *);
static struct fcal_packet *sf_els_alloc(struct sf *, uchar_t, int, int,
    int, caddr_t *, caddr_t *);
static void sf_els_free(struct fcal_packet *);
static struct sf_target *sf_create_target(struct sf *,
    struct sf_els_hdr *, int, int64_t);
#ifdef RAID_LUNS
static struct sf_target *sf_lookup_target(struct sf *, uchar_t *, int);
#else
static struct sf_target *sf_lookup_target(struct sf *, uchar_t *, int64_t);
#endif
static void sf_finish_init(struct sf *, int);
static void sf_offline_target(struct sf *, struct sf_target *);
static void sf_create_devinfo(struct sf *, struct sf_target *, int);
static int sf_create_props(dev_info_t *, struct sf_target *, int);
static int sf_commoncap(struct scsi_address *, char *, int, int, int);
static int sf_getcap(struct scsi_address *, char *, int);
static int sf_setcap(struct scsi_address *, char *, int, int);
static int sf_abort(struct scsi_address *, struct scsi_pkt *);
static int sf_reset(struct scsi_address *, int);
static void sf_abort_all(struct sf *, struct sf_target *, int, int, int);
static int sf_start(struct scsi_address *, struct scsi_pkt *);
static int sf_start_internal(struct sf *, struct sf_pkt *);
static void sf_fill_ids(struct sf *, struct sf_pkt *, struct sf_target *);
static int sf_prepare_pkt(struct sf *, struct sf_pkt *, struct sf_target *);
static int sf_dopoll(struct sf *, struct sf_pkt *);
static void sf_cmd_callback(struct fcal_packet *);
static void sf_throttle(struct sf *);
static void sf_watch(void *);
static void sf_throttle_start(struct sf *);
static void sf_check_targets(struct sf *);
static void sf_check_reset_delay(void *);
static int sf_target_timeout(struct sf *, struct sf_pkt *);
static void sf_force_lip(struct sf *);
static void sf_unsol_els_callback(void *, soc_response_t *, caddr_t);
static struct sf_els_hdr *sf_els_timeout(struct sf *, struct sf_els_hdr *);
/*PRINTFLIKE3*/
static void sf_log(struct sf *, int, const char *, ...);
static int sf_kstat_update(kstat_t *, int);
static int sf_open(dev_t *, int, int, cred_t *);
static int sf_close(dev_t, int, int, cred_t *);
static int sf_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);
static struct sf_target *sf_get_target_from_dip(struct sf *, dev_info_t *);
static int sf_bus_get_eventcookie(dev_info_t *, dev_info_t *, char *,
    ddi_eventcookie_t *);
static int sf_bus_add_eventcall(dev_info_t *, dev_info_t *,
    ddi_eventcookie_t, void (*)(), void *, ddi_callback_id_t *cb_id);
static int sf_bus_remove_eventcall(dev_info_t *devi, ddi_callback_id_t cb_id);
static int sf_bus_post_event(dev_info_t *, dev_info_t *,
    ddi_eventcookie_t, void *);

static void sf_hp_daemon(void *);

/*
 * this is required to be able to supply a control node
 * where ioctls can be executed
 */
struct cb_ops sf_cb_ops = {
	sf_open,			/* open */
	sf_close,			/* close */
	nodev,				/* strategy */
	nodev,				/* print */
	nodev,				/* dump */
	nodev,				/* read */
	nodev,				/* write */
	sf_ioctl,			/* ioctl */
	nodev,				/* devmap */
	nodev,				/* mmap */
	nodev,				/* segmap */
	nochpoll,			/* poll */
	ddi_prop_op,			/* cb_prop_op */
	0,				/* streamtab  */
	D_MP | D_NEW | D_HOTPLUG	/* driver flags */

};

/*
 * autoconfiguration routines.
 */
static struct dev_ops sf_ops = {
	DEVO_REV,		/* devo_rev, */
	0,			/* refcnt  */
	sf_info,		/* info */
	nulldev,		/* identify */
	nulldev,		/* probe */
	sf_attach,		/* attach */
	sf_detach,		/* detach */
	nodev,			/* reset */
	&sf_cb_ops,		/* driver operations */
	NULL,			/* bus operations */
	NULL,			/* power management */
	ddi_quiesce_not_supported,	/* devo_quiesce */
};

#define	SF_NAME	"FC-AL FCP Nexus Driver"	/* Name of the module. */
static	char	sf_version[] = "1.72 08/19/2008"; /* version of the module */

static struct modldrv modldrv = {
	&mod_driverops, /* Type of module. This one is a driver */
	SF_NAME,
	&sf_ops,	/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modldrv, NULL
};

/* XXXXXX The following is here to handle broken targets -- remove it later */
static int sf_reportlun_forever = 0;
/* XXXXXX */
static int sf_lip_on_plogo = 0;
static int sf_els_retries = SF_ELS_RETRIES;
static struct sf *sf_head = NULL;
static int sf_target_scan_cnt = 4;
static int sf_pkt_scan_cnt = 5;
static int sf_pool_scan_cnt = 1800;
static void *sf_state = NULL;
static int sf_watchdog_init = 0;
static int sf_watchdog_time = 0;
static int sf_watchdog_timeout = 1;
static int sf_watchdog_tick;
static int sf_watch_running = 0;
static timeout_id_t sf_watchdog_id;
static timeout_id_t sf_reset_timeout_id;
static int sf_max_targets = SF_MAX_TARGETS;
static kmutex_t sf_global_mutex;
static int sf_core = 0;
int *sf_token = NULL; /* Must not be static or lint complains. */
static kcondvar_t sf_watch_cv;
extern pri_t minclsyspri;
static ddi_eventcookie_t	sf_insert_eid;
static ddi_eventcookie_t	sf_remove_eid;

static ndi_event_definition_t	sf_event_defs[] = {
{ SF_EVENT_TAG_INSERT, FCAL_INSERT_EVENT, EPL_KERNEL, 0 },
{ SF_EVENT_TAG_REMOVE, FCAL_REMOVE_EVENT, EPL_INTERRUPT, 0 }
};

#define	SF_N_NDI_EVENTS	\
	(sizeof (sf_event_defs) / sizeof (ndi_event_definition_t))

#ifdef DEBUG
static int sf_lip_flag = 1;		/* bool: to allow LIPs */
static int sf_reset_flag = 1;		/* bool: to allow reset after LIP */
static int sf_abort_flag = 0;		/* bool: to do just one abort */
#endif

extern int64_t ddi_get_lbolt64(void);

/*
 * for converting between target number (switch) and hard address/AL_PA
 */
static uchar_t sf_switch_to_alpa[] = {
	0xef, 0xe8, 0xe4, 0xe2, 0xe1, 0xe0, 0xdc, 0xda, 0xd9, 0xd6,
	0xd5, 0xd4, 0xd3, 0xd2, 0xd1, 0xce, 0xcd, 0xcc, 0xcb, 0xca,
	0xc9, 0xc7, 0xc6, 0xc5, 0xc3, 0xbc, 0xba, 0xb9, 0xb6, 0xb5,
	0xb4, 0xb3, 0xb2, 0xb1, 0xae, 0xad, 0xac, 0xab, 0xaa, 0xa9,
	0xa7, 0xa6, 0xa5, 0xa3, 0x9f, 0x9e, 0x9d, 0x9b, 0x98, 0x97,
	0x90, 0x8f, 0x88, 0x84, 0x82, 0x81, 0x80, 0x7c, 0x7a, 0x79,
	0x76, 0x75, 0x74, 0x73, 0x72, 0x71, 0x6e, 0x6d, 0x6c, 0x6b,
	0x6a, 0x69, 0x67, 0x66, 0x65, 0x63, 0x5c, 0x5a, 0x59, 0x56,
	0x55, 0x54, 0x53, 0x52, 0x51, 0x4e, 0x4d, 0x4c, 0x4b, 0x4a,
	0x49, 0x47, 0x46, 0x45, 0x43, 0x3c, 0x3a, 0x39, 0x36, 0x35,
	0x34, 0x33, 0x32, 0x31, 0x2e, 0x2d, 0x2c, 0x2b, 0x2a, 0x29,
	0x27, 0x26, 0x25, 0x23, 0x1f, 0x1e, 0x1d, 0x1b, 0x18, 0x17,
	0x10, 0x0f, 0x08, 0x04, 0x02, 0x01
};

static uchar_t sf_alpa_to_switch[] = {
	0x00, 0x7d, 0x7c, 0x00, 0x7b, 0x00, 0x00, 0x00, 0x7a, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x79, 0x78, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x77, 0x76, 0x00, 0x00, 0x75, 0x00, 0x74,
	0x73, 0x72, 0x00, 0x00, 0x00, 0x71, 0x00, 0x70, 0x6f, 0x6e,
	0x00, 0x6d, 0x6c, 0x6b, 0x6a, 0x69, 0x68, 0x00, 0x00, 0x67,
	0x66, 0x65, 0x64, 0x63, 0x62, 0x00, 0x00, 0x61, 0x60, 0x00,
	0x5f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x5e, 0x00, 0x5d,
	0x5c, 0x5b, 0x00, 0x5a, 0x59, 0x58, 0x57, 0x56, 0x55, 0x00,
	0x00, 0x54, 0x53, 0x52, 0x51, 0x50, 0x4f, 0x00, 0x00, 0x4e,
	0x4d, 0x00, 0x4c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4b,
	0x00, 0x4a, 0x49, 0x48, 0x00, 0x47, 0x46, 0x45, 0x44, 0x43,
	0x42, 0x00, 0x00, 0x41, 0x40, 0x3f, 0x3e, 0x3d, 0x3c, 0x00,
	0x00, 0x3b, 0x3a, 0x00, 0x39, 0x00, 0x00, 0x00, 0x38, 0x37,
	0x36, 0x00, 0x35, 0x00, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x33, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x31, 0x30, 0x00, 0x00, 0x2f, 0x00, 0x2e, 0x2d, 0x2c,
	0x00, 0x00, 0x00, 0x2b, 0x00, 0x2a, 0x29, 0x28, 0x00, 0x27,
	0x26, 0x25, 0x24, 0x23, 0x22, 0x00, 0x00, 0x21, 0x20, 0x1f,
	0x1e, 0x1d, 0x1c, 0x00, 0x00, 0x1b, 0x1a, 0x00, 0x19, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x00, 0x17, 0x16, 0x15,
	0x00, 0x14, 0x13, 0x12, 0x11, 0x10, 0x0f, 0x00, 0x00, 0x0e,
	0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x00, 0x00, 0x08, 0x07, 0x00,
	0x06, 0x00, 0x00, 0x00, 0x05, 0x04, 0x03, 0x00, 0x02, 0x00,
	0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

/*
 * these macros call the proper transport-layer function given
 * a particular transport
 */
#define	soc_transport(a, b, c, d) (*a->fcal_ops->fcal_transport)(b, c, d)
#define	soc_transport_poll(a, b, c, d)\
	(*a->fcal_ops->fcal_transport_poll)(b, c, d)
#define	soc_get_lilp_map(a, b, c, d, e)\
	(*a->fcal_ops->fcal_lilp_map)(b, c, d, e)
#define	soc_force_lip(a, b, c, d, e)\
	(*a->fcal_ops->fcal_force_lip)(b, c, d, e)
#define	soc_abort(a, b, c, d, e)\
	(*a->fcal_ops->fcal_abort_cmd)(b, c, d, e)
#define	soc_force_reset(a, b, c, d)\
	(*a->fcal_ops->fcal_force_reset)(b, c, d)
#define	soc_add_ulp(a, b, c, d, e, f, g, h)\
	(*a->fcal_ops->fcal_add_ulp)(b, c, d, e, f, g, h)
#define	soc_remove_ulp(a, b, c, d, e)\
	(*a->fcal_ops->fcal_remove_ulp)(b, c, d, e)
#define	soc_take_core(a, b) (*a->fcal_ops->fcal_take_core)(b)


/* power management property defines (should be in a common include file?) */
#define	PM_HARDWARE_STATE_PROP		"pm-hardware-state"
#define	PM_NEEDS_SUSPEND_RESUME		"needs-suspend-resume"


/* node properties */
#define	NODE_WWN_PROP			"node-wwn"
#define	PORT_WWN_PROP			"port-wwn"
#define	LIP_CNT_PROP			"lip-count"
#define	TARGET_PROP			"target"
#define	LUN_PROP			"lun"


/*
 * initialize this driver and install this module
 */
int
_init(void)
{
	int	i;

	i = ddi_soft_state_init(&sf_state, sizeof (struct sf),
	    SF_INIT_ITEMS);
	if (i != 0)
		return (i);

	if ((i = scsi_hba_init(&modlinkage)) != 0) {
		ddi_soft_state_fini(&sf_state);
		return (i);
	}

	mutex_init(&sf_global_mutex, NULL, MUTEX_DRIVER, NULL);
	sf_watch_running = 0;
	cv_init(&sf_watch_cv, NULL, CV_DRIVER, NULL);

	if ((i = mod_install(&modlinkage)) != 0) {
		mutex_destroy(&sf_global_mutex);
		cv_destroy(&sf_watch_cv);
		scsi_hba_fini(&modlinkage);
		ddi_soft_state_fini(&sf_state);
		return (i);
	}

	return (i);
}


/*
 * remove this driver module from the system
 */
int
_fini(void)
{
	int	i;

	if ((i = mod_remove(&modlinkage)) == 0) {
		scsi_hba_fini(&modlinkage);
		mutex_destroy(&sf_global_mutex);
		cv_destroy(&sf_watch_cv);
		ddi_soft_state_fini(&sf_state);
	}
	return (i);
}


int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*
 * Given the device number return the devinfo pointer or instance
 */
/*ARGSUSED*/
static int
sf_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	int		instance = SF_MINOR2INST(getminor((dev_t)arg));
	struct sf	*sf;

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		sf = ddi_get_soft_state(sf_state, instance);
		if (sf != NULL)
			*result = sf->sf_dip;
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

/*
 * either attach or resume this driver
 */
static int
sf_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int instance;
	int mutex_initted = FALSE;
	uint_t ccount;
	size_t i, real_size;
	struct fcal_transport *handle;
	char buf[64];
	struct sf *sf, *tsf;
	scsi_hba_tran_t *tran = NULL;
	int	handle_bound = FALSE;
	kthread_t *tp;


	switch ((int)cmd) {

	case DDI_RESUME:

		/*
		 * we've previously been SF_STATE_OFFLINEd by a DDI_SUSPEND,
		 * so time to undo that and get going again by forcing a
		 * lip
		 */

		instance = ddi_get_instance(dip);

		sf = ddi_get_soft_state(sf_state, instance);
		SF_DEBUG(2, (sf, CE_CONT,
		    "sf_attach: DDI_RESUME for sf%d\n", instance));
		if (sf == NULL) {
			cmn_err(CE_WARN, "sf%d: bad soft state", instance);
			return (DDI_FAILURE);
		}

		/*
		 * clear suspended flag so that normal operations can resume
		 */
		mutex_enter(&sf->sf_mutex);
		sf->sf_state &= ~SF_STATE_SUSPENDED;
		mutex_exit(&sf->sf_mutex);

		/*
		 * force a login by setting our state to offline
		 */
		sf->sf_timer = sf_watchdog_time + SF_OFFLINE_TIMEOUT;
		sf->sf_state = SF_STATE_OFFLINE;

		/*
		 * call transport routine to register state change and
		 * ELS callback routines (to register us as a ULP)
		 */
		soc_add_ulp(sf->sf_sochandle, sf->sf_socp,
		    sf->sf_sochandle->fcal_portno, TYPE_SCSI_FCP,
		    sf_statec_callback, sf_unsol_els_callback, NULL, sf);

		/*
		 * call transport routine to force loop initialization
		 */
		(void) soc_force_lip(sf->sf_sochandle, sf->sf_socp,
		    sf->sf_sochandle->fcal_portno, 0, FCAL_NO_LIP);

		/*
		 * increment watchdog init flag, setting watchdog timeout
		 * if we are the first (since somebody has to do it)
		 */
		mutex_enter(&sf_global_mutex);
		if (!sf_watchdog_init++) {
			mutex_exit(&sf_global_mutex);
			sf_watchdog_id = timeout(sf_watch,
			    (caddr_t)0, sf_watchdog_tick);
		} else {
			mutex_exit(&sf_global_mutex);
		}

		return (DDI_SUCCESS);

	case DDI_ATTACH:

		/*
		 * this instance attaching for the first time
		 */

		instance = ddi_get_instance(dip);

		if (ddi_soft_state_zalloc(sf_state, instance) !=
		    DDI_SUCCESS) {
			cmn_err(CE_WARN, "sf%d: failed to allocate soft state",
			    instance);
			return (DDI_FAILURE);
		}

		sf = ddi_get_soft_state(sf_state, instance);
		SF_DEBUG(4, (sf, CE_CONT,
		    "sf_attach: DDI_ATTACH for sf%d\n", instance));
		if (sf == NULL) {
			/* this shouldn't happen since we just allocated it */
			cmn_err(CE_WARN, "sf%d: bad soft state", instance);
			return (DDI_FAILURE);
		}

		/*
		 * from this point on, if there's an error, we must de-allocate
		 * soft state before returning DDI_FAILURE
		 */

		if ((handle = ddi_get_parent_data(dip)) == NULL) {
			cmn_err(CE_WARN,
			    "sf%d: failed to obtain transport handle",
			    instance);
			goto fail;
		}

		/* fill in our soft state structure */
		sf->sf_dip = dip;
		sf->sf_state = SF_STATE_INIT;
		sf->sf_throttle = handle->fcal_cmdmax;
		sf->sf_sochandle = handle;
		sf->sf_socp = handle->fcal_handle;
		sf->sf_check_n_close = 0;

		/* create a command/response buffer pool for this instance */
		if (sf_add_cr_pool(sf) != DDI_SUCCESS) {
			cmn_err(CE_WARN,
			    "sf%d: failed to allocate command/response pool",
			    instance);
			goto fail;
		}

		/* create a a cache for this instance */
		(void) sprintf(buf, "sf%d_cache", instance);
		sf->sf_pkt_cache = kmem_cache_create(buf,
		    sizeof (fcal_packet_t) + sizeof (struct sf_pkt) +
		    scsi_pkt_size(), 8,
		    sf_kmem_cache_constructor, sf_kmem_cache_destructor,
		    NULL, NULL, NULL, 0);
		if (sf->sf_pkt_cache == NULL) {
			cmn_err(CE_WARN, "sf%d: failed to allocate kmem cache",
			    instance);
			goto fail;
		}

		/* set up a handle and allocate memory for DMA */
		if (ddi_dma_alloc_handle(sf->sf_dip, sf->sf_sochandle->
		    fcal_dmaattr, DDI_DMA_DONTWAIT, NULL, &sf->
		    sf_lilp_dmahandle) != DDI_SUCCESS) {
			cmn_err(CE_WARN,
			    "sf%d: failed to allocate dma handle for lilp map",
			    instance);
			goto fail;
		}
		i = sizeof (struct fcal_lilp_map) + 1;
		if (ddi_dma_mem_alloc(sf->sf_lilp_dmahandle,
		    i, sf->sf_sochandle->
		    fcal_accattr, DDI_DMA_CONSISTENT, DDI_DMA_DONTWAIT, NULL,
		    (caddr_t *)&sf->sf_lilp_map, &real_size,
		    &sf->sf_lilp_acchandle) != DDI_SUCCESS) {
			cmn_err(CE_WARN, "sf%d: failed to allocate lilp map",
			    instance);
			goto fail;
		}
		if (real_size < i) {
			/* no error message ??? */
			goto fail;		/* trouble allocating memory */
		}

		/*
		 * set up the address for the DMA transfers (getting a cookie)
		 */
		if (ddi_dma_addr_bind_handle(sf->sf_lilp_dmahandle, NULL,
		    (caddr_t)sf->sf_lilp_map, real_size,
		    DDI_DMA_READ | DDI_DMA_CONSISTENT, DDI_DMA_DONTWAIT, NULL,
		    &sf->sf_lilp_dmacookie, &ccount) != DDI_DMA_MAPPED) {
			cmn_err(CE_WARN,
			    "sf%d: failed to bind dma handle for lilp map",
			    instance);
			goto fail;
		}
		handle_bound = TRUE;
		/* ensure only one cookie was allocated */
		if (ccount != 1) {
			goto fail;
		}

		/* ensure LILP map and DMA cookie addresses are even?? */
		sf->sf_lilp_map = (struct fcal_lilp_map *)(((uintptr_t)sf->
		    sf_lilp_map + 1) & ~1);
		sf->sf_lilp_dmacookie.dmac_address = (sf->
		    sf_lilp_dmacookie.dmac_address + 1) & ~1;

		/* set up all of our mutexes and condition variables */
		mutex_init(&sf->sf_mutex, NULL, MUTEX_DRIVER, NULL);
		mutex_init(&sf->sf_cmd_mutex, NULL, MUTEX_DRIVER, NULL);
		mutex_init(&sf->sf_cr_mutex, NULL, MUTEX_DRIVER, NULL);
		mutex_init(&sf->sf_hp_daemon_mutex, NULL, MUTEX_DRIVER, NULL);
		cv_init(&sf->sf_cr_cv, NULL, CV_DRIVER, NULL);
		cv_init(&sf->sf_hp_daemon_cv, NULL, CV_DRIVER, NULL);

		mutex_initted = TRUE;

		/* create our devctl minor node */
		if (ddi_create_minor_node(dip, "devctl", S_IFCHR,
		    SF_INST2DEVCTL_MINOR(instance),
		    DDI_NT_NEXUS, 0) != DDI_SUCCESS) {
			cmn_err(CE_WARN, "sf%d: ddi_create_minor_node failed"
			    " for devctl", instance);
			goto fail;
		}

		/* create fc minor node */
		if (ddi_create_minor_node(dip, "fc", S_IFCHR,
		    SF_INST2FC_MINOR(instance), DDI_NT_FC_ATTACHMENT_POINT,
		    0) != DDI_SUCCESS) {
			cmn_err(CE_WARN, "sf%d: ddi_create_minor_node failed"
			    " for fc", instance);
			goto fail;
		}
		/* allocate a SCSI transport structure */
		tran = scsi_hba_tran_alloc(dip, 0);
		if (tran == NULL) {
			/* remove all minor nodes created */
			ddi_remove_minor_node(dip, NULL);
			cmn_err(CE_WARN, "sf%d: scsi_hba_tran_alloc failed",
			    instance);
			goto fail;
		}

		/* Indicate that we are 'sizeof (scsi_*(9S))' clean. */
		scsi_size_clean(dip);		/* SCSI_SIZE_CLEAN_VERIFY ok */

		/* save ptr to new transport structure and fill it in */
		sf->sf_tran = tran;

		tran->tran_hba_private		= sf;
		tran->tran_tgt_private		= NULL;
		tran->tran_tgt_init		= sf_scsi_tgt_init;
		tran->tran_tgt_probe		= NULL;
		tran->tran_tgt_free		= sf_scsi_tgt_free;

		tran->tran_start		= sf_start;
		tran->tran_abort		= sf_abort;
		tran->tran_reset		= sf_reset;
		tran->tran_getcap		= sf_getcap;
		tran->tran_setcap		= sf_setcap;
		tran->tran_init_pkt		= sf_scsi_init_pkt;
		tran->tran_destroy_pkt		= sf_scsi_destroy_pkt;
		tran->tran_dmafree		= sf_scsi_dmafree;
		tran->tran_sync_pkt		= sf_scsi_sync_pkt;
		tran->tran_reset_notify		= sf_scsi_reset_notify;

		/*
		 * register event notification routines with scsa
		 */
		tran->tran_get_eventcookie	= sf_bus_get_eventcookie;
		tran->tran_add_eventcall	= sf_bus_add_eventcall;
		tran->tran_remove_eventcall	= sf_bus_remove_eventcall;
		tran->tran_post_event		= sf_bus_post_event;

		/*
		 * register bus configure/unconfigure
		 */
		tran->tran_bus_config		= sf_scsi_bus_config;
		tran->tran_bus_unconfig		= sf_scsi_bus_unconfig;

		/*
		 * allocate an ndi event handle
		 */
		sf->sf_event_defs = (ndi_event_definition_t *)
		    kmem_zalloc(sizeof (sf_event_defs), KM_SLEEP);

		bcopy(sf_event_defs, sf->sf_event_defs,
		    sizeof (sf_event_defs));

		(void) ndi_event_alloc_hdl(dip, NULL,
		    &sf->sf_event_hdl, NDI_SLEEP);

		sf->sf_events.ndi_events_version = NDI_EVENTS_REV1;
		sf->sf_events.ndi_n_events = SF_N_NDI_EVENTS;
		sf->sf_events.ndi_event_defs = sf->sf_event_defs;

		if (ndi_event_bind_set(sf->sf_event_hdl,
		    &sf->sf_events, NDI_SLEEP) != NDI_SUCCESS) {
			goto fail;
		}

		tran->tran_get_name		= sf_scsi_get_name;
		tran->tran_get_bus_addr		= sf_scsi_get_bus_addr;

		/* setup and attach SCSI hba transport */
		if (scsi_hba_attach_setup(dip, sf->sf_sochandle->
		    fcal_dmaattr, tran, SCSI_HBA_TRAN_CLONE) != DDI_SUCCESS) {
			cmn_err(CE_WARN, "sf%d: scsi_hba_attach_setup failed",
			    instance);
			goto fail;
		}

		/* set up kstats */
		if ((sf->sf_ksp = kstat_create("sf", instance, "statistics",
		    "controller", KSTAT_TYPE_RAW, sizeof (struct sf_stats),
		    KSTAT_FLAG_VIRTUAL)) == NULL) {
			cmn_err(CE_WARN, "sf%d: failed to create kstat",
			    instance);
		} else {
			sf->sf_stats.version = 2;
			(void) sprintf(sf->sf_stats.drvr_name,
			"%s: %s", SF_NAME, sf_version);
			sf->sf_ksp->ks_data = (void *)&sf->sf_stats;
			sf->sf_ksp->ks_private = sf;
			sf->sf_ksp->ks_update = sf_kstat_update;
			kstat_install(sf->sf_ksp);
		}

		/* create the hotplug thread */
		mutex_enter(&sf->sf_hp_daemon_mutex);
		tp = thread_create(NULL, 0,
		    (void (*)())sf_hp_daemon, sf, 0, &p0, TS_RUN, minclsyspri);
		sf->sf_hp_tid = tp->t_did;
		mutex_exit(&sf->sf_hp_daemon_mutex);

		/* add this soft state instance to the head of the list */
		mutex_enter(&sf_global_mutex);
		sf->sf_next = sf_head;
		tsf = sf_head;
		sf_head = sf;

		/*
		 * find entry in list that has the same FC-AL handle (if any)
		 */
		while (tsf != NULL) {
			if (tsf->sf_socp == sf->sf_socp) {
				break;		/* found matching entry */
			}
			tsf = tsf->sf_next;
		}

		if (tsf != NULL) {
			/* if we found a matching entry keep track of it */
			sf->sf_sibling = tsf;
		}

		/*
		 * increment watchdog init flag, setting watchdog timeout
		 * if we are the first (since somebody has to do it)
		 */
		if (!sf_watchdog_init++) {
			mutex_exit(&sf_global_mutex);
			sf_watchdog_tick = sf_watchdog_timeout *
			    drv_usectohz(1000000);
			sf_watchdog_id = timeout(sf_watch,
			    NULL, sf_watchdog_tick);
		} else {
			mutex_exit(&sf_global_mutex);
		}

		if (tsf != NULL) {
			/*
			 * set up matching entry to be our sibling
			 */
			mutex_enter(&tsf->sf_mutex);
			tsf->sf_sibling = sf;
			mutex_exit(&tsf->sf_mutex);
		}

		/*
		 * create this property so that PM code knows we want
		 * to be suspended at PM time
		 */
		(void) ddi_prop_update_string(DDI_DEV_T_NONE, dip,
		    PM_HARDWARE_STATE_PROP, PM_NEEDS_SUSPEND_RESUME);

		/* log the fact that we have a new device */
		ddi_report_dev(dip);

		/*
		 * force a login by setting our state to offline
		 */
		sf->sf_timer = sf_watchdog_time + SF_OFFLINE_TIMEOUT;
		sf->sf_state = SF_STATE_OFFLINE;

		/*
		 * call transport routine to register state change and
		 * ELS callback routines (to register us as a ULP)
		 */
		soc_add_ulp(sf->sf_sochandle, sf->sf_socp,
		    sf->sf_sochandle->fcal_portno, TYPE_SCSI_FCP,
		    sf_statec_callback, sf_unsol_els_callback, NULL, sf);

		/*
		 * call transport routine to force loop initialization
		 */
		(void) soc_force_lip(sf->sf_sochandle, sf->sf_socp,
		    sf->sf_sochandle->fcal_portno, 0, FCAL_NO_LIP);
		sf->sf_reset_time = ddi_get_lbolt64();
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}

fail:
	cmn_err(CE_WARN, "sf%d: failed to attach", instance);

	/*
	 * Unbind and free event set
	 */
	if (sf->sf_event_hdl) {
		(void) ndi_event_unbind_set(sf->sf_event_hdl,
		    &sf->sf_events, NDI_SLEEP);
		(void) ndi_event_free_hdl(sf->sf_event_hdl);
	}

	if (sf->sf_event_defs) {
		kmem_free(sf->sf_event_defs, sizeof (sf_event_defs));
	}

	if (sf->sf_tran != NULL) {
		scsi_hba_tran_free(sf->sf_tran);
	}
	while (sf->sf_cr_pool != NULL) {
		sf_crpool_free(sf);
	}
	if (sf->sf_lilp_dmahandle != NULL) {
		if (handle_bound) {
			(void) ddi_dma_unbind_handle(sf->sf_lilp_dmahandle);
		}
		ddi_dma_free_handle(&sf->sf_lilp_dmahandle);
	}
	if (sf->sf_pkt_cache != NULL) {
		kmem_cache_destroy(sf->sf_pkt_cache);
	}
	if (sf->sf_lilp_map != NULL) {
		ddi_dma_mem_free(&sf->sf_lilp_acchandle);
	}
	if (sf->sf_ksp != NULL) {
		kstat_delete(sf->sf_ksp);
	}
	if (mutex_initted) {
		mutex_destroy(&sf->sf_mutex);
		mutex_destroy(&sf->sf_cmd_mutex);
		mutex_destroy(&sf->sf_cr_mutex);
		mutex_destroy(&sf->sf_hp_daemon_mutex);
		cv_destroy(&sf->sf_cr_cv);
		cv_destroy(&sf->sf_hp_daemon_cv);
	}
	mutex_enter(&sf_global_mutex);

	/*
	 * kill off the watchdog if we are the last instance
	 */
	if (!--sf_watchdog_init) {
		timeout_id_t tid = sf_watchdog_id;
		mutex_exit(&sf_global_mutex);
		(void) untimeout(tid);
	} else {
		mutex_exit(&sf_global_mutex);
	}

	ddi_soft_state_free(sf_state, instance);

	if (tran != NULL) {
		/* remove all minor nodes */
		ddi_remove_minor_node(dip, NULL);
	}

	return (DDI_FAILURE);
}


/* ARGSUSED */
static int
sf_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	struct sf		*sf;
	int			instance;
	int			i;
	struct sf_target	*target;
	timeout_id_t		tid;



	/* NO OTHER THREADS ARE RUNNING */

	instance = ddi_get_instance(dip);

	if ((sf = ddi_get_soft_state(sf_state, instance)) == NULL) {
		cmn_err(CE_WARN, "sf_detach, sf%d: bad soft state", instance);
		return (DDI_FAILURE);
	}

	switch (cmd) {

	case DDI_SUSPEND:
		/*
		 * suspend our instance
		 */

		SF_DEBUG(2, (sf, CE_CONT,
		    "sf_detach: DDI_SUSPEND for sf%d\n", instance));
		/*
		 * There is a race condition in socal where while doing
		 * callbacks if a ULP removes it self from the callback list
		 * the for loop in socal may panic as cblist is junk and
		 * while trying to get cblist->next the system will panic.
		 */

		/* call transport to remove our unregister our callbacks */
		soc_remove_ulp(sf->sf_sochandle, sf->sf_socp,
		    sf->sf_sochandle->fcal_portno, TYPE_SCSI_FCP, sf);

		/*
		 * begin process of clearing outstanding commands
		 * by issuing a lip
		 */
		sf_force_lip(sf);

		/*
		 * toggle the device OFFLINE in order to cause
		 * outstanding commands to drain
		 */
		mutex_enter(&sf->sf_mutex);
		sf->sf_lip_cnt++;
		sf->sf_timer = sf_watchdog_time + SF_OFFLINE_TIMEOUT;
		sf->sf_state = (SF_STATE_OFFLINE | SF_STATE_SUSPENDED);
		for (i = 0; i < sf_max_targets; i++) {
			target = sf->sf_targets[i];
			if (target != NULL) {
				struct sf_target *ntarget;

				mutex_enter(&target->sft_mutex);
				if (!(target->sft_state & SF_TARGET_OFFLINE)) {
					target->sft_state |=
					    (SF_TARGET_BUSY | SF_TARGET_MARK);
				}
				/* do this for all LUNs as well */
				for (ntarget = target->sft_next_lun;
				    ntarget;
				    ntarget = ntarget->sft_next_lun) {
					mutex_enter(&ntarget->sft_mutex);
					if (!(ntarget->sft_state &
					    SF_TARGET_OFFLINE)) {
						ntarget->sft_state |=
						    (SF_TARGET_BUSY |
						    SF_TARGET_MARK);
					}
					mutex_exit(&ntarget->sft_mutex);
				}
				mutex_exit(&target->sft_mutex);
			}
		}
		mutex_exit(&sf->sf_mutex);
		mutex_enter(&sf_global_mutex);

		/*
		 * kill off the watchdog if we are the last instance
		 */
		if (!--sf_watchdog_init) {
			tid = sf_watchdog_id;
			mutex_exit(&sf_global_mutex);
			(void) untimeout(tid);
		} else {
			mutex_exit(&sf_global_mutex);
		}

		return (DDI_SUCCESS);

	case DDI_DETACH:
		/*
		 * detach this instance
		 */

		SF_DEBUG(2, (sf, CE_CONT,
		    "sf_detach: DDI_DETACH for sf%d\n", instance));

		/* remove this "sf" from the list of sf softstates */
		sf_softstate_unlink(sf);

		/*
		 * prior to taking any DDI_DETACH actions, toggle the
		 * device OFFLINE in order to cause outstanding
		 * commands to drain
		 */
		mutex_enter(&sf->sf_mutex);
		sf->sf_lip_cnt++;
		sf->sf_timer = sf_watchdog_time + SF_OFFLINE_TIMEOUT;
		sf->sf_state = SF_STATE_OFFLINE;
		for (i = 0; i < sf_max_targets; i++) {
			target = sf->sf_targets[i];
			if (target != NULL) {
				struct sf_target *ntarget;

				mutex_enter(&target->sft_mutex);
				if (!(target->sft_state & SF_TARGET_OFFLINE)) {
					target->sft_state |=
					    (SF_TARGET_BUSY | SF_TARGET_MARK);
				}
				for (ntarget = target->sft_next_lun;
				    ntarget;
				    ntarget = ntarget->sft_next_lun) {
					mutex_enter(&ntarget->sft_mutex);
					if (!(ntarget->sft_state &
					    SF_TARGET_OFFLINE)) {
						ntarget->sft_state |=
						    (SF_TARGET_BUSY |
						    SF_TARGET_MARK);
					}
					mutex_exit(&ntarget->sft_mutex);
				}
				mutex_exit(&target->sft_mutex);
			}
		}
		mutex_exit(&sf->sf_mutex);

		/* call transport to remove and unregister our callbacks */
		soc_remove_ulp(sf->sf_sochandle, sf->sf_socp,
		    sf->sf_sochandle->fcal_portno, TYPE_SCSI_FCP, sf);

		/*
		 * kill off the watchdog if we are the last instance
		 */
		mutex_enter(&sf_global_mutex);
		if (!--sf_watchdog_init) {
			tid = sf_watchdog_id;
			mutex_exit(&sf_global_mutex);
			(void) untimeout(tid);
		} else {
			mutex_exit(&sf_global_mutex);
		}

		/* signal sf_hp_daemon() to exit and wait for exit */
		mutex_enter(&sf->sf_hp_daemon_mutex);
		ASSERT(sf->sf_hp_tid);
		sf->sf_hp_exit = 1;		/* flag exit */
		cv_signal(&sf->sf_hp_daemon_cv);
		mutex_exit(&sf->sf_hp_daemon_mutex);
		thread_join(sf->sf_hp_tid);	/* wait for hotplug to exit */

		/*
		 * Unbind and free event set
		 */
		if (sf->sf_event_hdl) {
			(void) ndi_event_unbind_set(sf->sf_event_hdl,
			    &sf->sf_events, NDI_SLEEP);
			(void) ndi_event_free_hdl(sf->sf_event_hdl);
		}

		if (sf->sf_event_defs) {
			kmem_free(sf->sf_event_defs, sizeof (sf_event_defs));
		}

		/* detach this instance of the HBA driver */
		(void) scsi_hba_detach(dip);
		scsi_hba_tran_free(sf->sf_tran);

		/* deallocate/unbind DMA handle for lilp map */
		if (sf->sf_lilp_map != NULL) {
			(void) ddi_dma_unbind_handle(sf->sf_lilp_dmahandle);
			if (sf->sf_lilp_dmahandle != NULL) {
				ddi_dma_free_handle(&sf->sf_lilp_dmahandle);
			}
			ddi_dma_mem_free(&sf->sf_lilp_acchandle);
		}

		/*
		 * the kmem cache must be destroyed before free'ing
		 * up the crpools
		 *
		 * our finagle of "ntot" and "nfree"
		 * causes an ASSERT failure in "sf_cr_free()"
		 * if the kmem cache is free'd after invoking
		 * "sf_crpool_free()".
		 */
		kmem_cache_destroy(sf->sf_pkt_cache);

		SF_DEBUG(2, (sf, CE_CONT,
		    "sf_detach: sf_crpool_free() for instance 0x%x\n",
		    instance));
		while (sf->sf_cr_pool != NULL) {
			/*
			 * set ntot to nfree for this particular entry
			 *
			 * this causes sf_crpool_free() to update
			 * the cr_pool list when deallocating this entry
			 */
			sf->sf_cr_pool->ntot = sf->sf_cr_pool->nfree;
			sf_crpool_free(sf);
		}

		/*
		 * now that the cr_pool's are gone it's safe
		 * to destroy all softstate mutex's and cv's
		 */
		mutex_destroy(&sf->sf_mutex);
		mutex_destroy(&sf->sf_cmd_mutex);
		mutex_destroy(&sf->sf_cr_mutex);
		mutex_destroy(&sf->sf_hp_daemon_mutex);
		cv_destroy(&sf->sf_cr_cv);
		cv_destroy(&sf->sf_hp_daemon_cv);

		/* remove all minor nodes from the device tree */
		ddi_remove_minor_node(dip, NULL);

		/* remove properties created during attach() */
		ddi_prop_remove_all(dip);

		/* remove kstat's if present */
		if (sf->sf_ksp != NULL) {
			kstat_delete(sf->sf_ksp);
		}

		SF_DEBUG(2, (sf, CE_CONT,
		    "sf_detach: ddi_soft_state_free() for instance 0x%x\n",
		    instance));
		ddi_soft_state_free(sf_state, instance);
		return (DDI_SUCCESS);

	default:
		SF_DEBUG(2, (sf, CE_CONT, "sf_detach: sf%d unknown cmd %x\n",
		    instance, (int)cmd));
		return (DDI_FAILURE);
	}
}


/*
 * sf_softstate_unlink() - remove an sf instance from the list of softstates
 */
static void
sf_softstate_unlink(struct sf *sf)
{
	struct sf	*sf_ptr;
	struct sf	*sf_found_sibling;
	struct sf	*sf_reposition = NULL;


	mutex_enter(&sf_global_mutex);
	while (sf_watch_running) {
		/* Busy working the list -- wait */
		cv_wait(&sf_watch_cv, &sf_global_mutex);
	}
	if ((sf_found_sibling = sf->sf_sibling) != NULL) {
		/*
		 * we have a sibling so NULL out its reference to us
		 */
		mutex_enter(&sf_found_sibling->sf_mutex);
		sf_found_sibling->sf_sibling = NULL;
		mutex_exit(&sf_found_sibling->sf_mutex);
	}

	/* remove our instance from the global list */
	if (sf == sf_head) {
		/* we were at at head of the list */
		sf_head = sf->sf_next;
	} else {
		/* find us in the list */
		for (sf_ptr = sf_head;
		    sf_ptr != NULL;
		    sf_ptr = sf_ptr->sf_next) {
			if (sf_ptr == sf) {
				break;
			}
			/* remember this place */
			sf_reposition = sf_ptr;
		}
		ASSERT(sf_ptr == sf);
		ASSERT(sf_reposition != NULL);

		sf_reposition->sf_next = sf_ptr->sf_next;
	}
	mutex_exit(&sf_global_mutex);
}


static int
sf_scsi_bus_config(dev_info_t *parent, uint_t flag,
    ddi_bus_config_op_t op, void *arg, dev_info_t **childp)
{
	int64_t		reset_delay;
	struct sf	*sf;

	sf = ddi_get_soft_state(sf_state, ddi_get_instance(parent));
	ASSERT(sf);

	reset_delay = (int64_t)(USEC_TO_TICK(SF_INIT_WAIT_TIMEOUT)) -
	    (ddi_get_lbolt64() - sf->sf_reset_time);
	if (reset_delay < 0)
		reset_delay = 0;

	if (sf_bus_config_debug)
		flag |= NDI_DEVI_DEBUG;

	return (ndi_busop_bus_config(parent, flag, op,
	    arg, childp, (clock_t)reset_delay));
}

static int
sf_scsi_bus_unconfig(dev_info_t *parent, uint_t flag,
    ddi_bus_config_op_t op, void *arg)
{
	if (sf_bus_config_debug)
		flag |= NDI_DEVI_DEBUG;

	return (ndi_busop_bus_unconfig(parent, flag, op, arg));
}


/*
 * called by transport to initialize a SCSI target
 */
/* ARGSUSED */
static int
sf_scsi_tgt_init(dev_info_t *hba_dip, dev_info_t *tgt_dip,
    scsi_hba_tran_t *hba_tran, struct scsi_device *sd)
{
#ifdef RAID_LUNS
	int lun;
#else
	int64_t lun;
#endif
	struct sf_target *target;
	struct sf *sf = (struct sf *)hba_tran->tran_hba_private;
	int i, t_len;
	unsigned int lip_cnt;
	unsigned char wwn[FC_WWN_SIZE];


	/* get and validate our SCSI target ID */
	i = sd->sd_address.a_target;
	if (i >= sf_max_targets) {
		return (DDI_NOT_WELL_FORMED);
	}

	/* get our port WWN property */
	t_len = sizeof (wwn);
	if (ddi_prop_op(DDI_DEV_T_ANY, tgt_dip, PROP_LEN_AND_VAL_BUF,
	    DDI_PROP_DONTPASS | DDI_PROP_CANSLEEP, PORT_WWN_PROP,
	    (caddr_t)&wwn, &t_len) != DDI_SUCCESS) {
		/* no port WWN property - ignore the OBP stub node */
		return (DDI_NOT_WELL_FORMED);
	}

	/* get our LIP count property */
	t_len = sizeof (lip_cnt);
	if (ddi_prop_op(DDI_DEV_T_ANY, tgt_dip, PROP_LEN_AND_VAL_BUF,
	    DDI_PROP_DONTPASS | DDI_PROP_CANSLEEP, LIP_CNT_PROP,
	    (caddr_t)&lip_cnt, &t_len) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}
	/* and our LUN property */
	t_len = sizeof (lun);
	if (ddi_prop_op(DDI_DEV_T_ANY, tgt_dip, PROP_LEN_AND_VAL_BUF,
	    DDI_PROP_DONTPASS | DDI_PROP_CANSLEEP, "lun",
	    (caddr_t)&lun, &t_len) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	/* find the target structure for this instance */
	mutex_enter(&sf->sf_mutex);
	if ((target = sf_lookup_target(sf, wwn, lun)) == NULL) {
		mutex_exit(&sf->sf_mutex);
		return (DDI_FAILURE);
	}

	mutex_enter(&target->sft_mutex);
	if ((sf->sf_lip_cnt == lip_cnt) && !(target->sft_state
	    & SF_TARGET_INIT_DONE)) {
		/*
		 * set links between HBA transport and target structures
		 * and set done flag
		 */
		hba_tran->tran_tgt_private = target;
		target->sft_tran = hba_tran;
		target->sft_state |= SF_TARGET_INIT_DONE;
	} else {
		/* already initialized ?? */
		mutex_exit(&target->sft_mutex);
		mutex_exit(&sf->sf_mutex);
		return (DDI_FAILURE);
	}
	mutex_exit(&target->sft_mutex);
	mutex_exit(&sf->sf_mutex);

	return (DDI_SUCCESS);
}


/*
 * called by transport to free a target
 */
/* ARGSUSED */
static void
sf_scsi_tgt_free(dev_info_t *hba_dip, dev_info_t *tgt_dip,
    scsi_hba_tran_t *hba_tran, struct scsi_device *sd)
{
	struct sf_target *target = hba_tran->tran_tgt_private;

	if (target != NULL) {
		mutex_enter(&target->sft_mutex);
		target->sft_tran = NULL;
		target->sft_state &= ~SF_TARGET_INIT_DONE;
		mutex_exit(&target->sft_mutex);
	}
}


/*
 * allocator for non-std size cdb/pkt_private/status -- return TRUE iff
 * success, else return FALSE
 */
/*ARGSUSED*/
static int
sf_pkt_alloc_extern(struct sf *sf, struct sf_pkt *cmd,
    int tgtlen, int statuslen, int kf)
{
	caddr_t scbp, tgt;
	int failure = FALSE;
	struct scsi_pkt *pkt = CMD2PKT(cmd);


	tgt = scbp = NULL;

	if (tgtlen > PKT_PRIV_LEN) {
		if ((tgt = kmem_zalloc(tgtlen, kf)) == NULL) {
			failure = TRUE;
		} else {
			cmd->cmd_flags |= CFLAG_PRIVEXTERN;
			pkt->pkt_private = tgt;
		}
	}
	if (statuslen > EXTCMDS_STATUS_SIZE) {
		if ((scbp = kmem_zalloc((size_t)statuslen, kf)) == NULL) {
			failure = TRUE;
		} else {
			cmd->cmd_flags |= CFLAG_SCBEXTERN;
			pkt->pkt_scbp = (opaque_t)scbp;
		}
	}
	if (failure) {
		sf_pkt_destroy_extern(sf, cmd);
	}
	return (failure);
}


/*
 * deallocator for non-std size cdb/pkt_private/status
 */
static void
sf_pkt_destroy_extern(struct sf *sf, struct sf_pkt *cmd)
{
	struct scsi_pkt *pkt = CMD2PKT(cmd);

	if (cmd->cmd_flags & CFLAG_FREE) {
		cmn_err(CE_PANIC,
		    "sf_scsi_impl_pktfree: freeing free packet");
		_NOTE(NOT_REACHED)
		/* NOTREACHED */
	}
	if (cmd->cmd_flags & CFLAG_SCBEXTERN) {
		kmem_free((caddr_t)pkt->pkt_scbp,
		    (size_t)cmd->cmd_scblen);
	}
	if (cmd->cmd_flags & CFLAG_PRIVEXTERN) {
		kmem_free((caddr_t)pkt->pkt_private,
		    (size_t)cmd->cmd_privlen);
	}

	cmd->cmd_flags = CFLAG_FREE;
	kmem_cache_free(sf->sf_pkt_cache, (void *)cmd);
}


/*
 * create or initialize a SCSI packet -- called internally and
 * by the transport
 */
static struct scsi_pkt *
sf_scsi_init_pkt(struct scsi_address *ap, struct scsi_pkt *pkt,
    struct buf *bp, int cmdlen, int statuslen, int tgtlen,
    int flags, int (*callback)(), caddr_t arg)
{
	int kf;
	int failure = FALSE;
	struct sf_pkt *cmd;
	struct sf *sf = ADDR2SF(ap);
	struct sf_target *target = ADDR2TARGET(ap);
	struct sf_pkt	*new_cmd = NULL;
	struct fcal_packet	*fpkt;
	fc_frame_header_t	*hp;
	struct fcp_cmd *fcmd;


	/*
	 * If we've already allocated a pkt once,
	 * this request is for dma allocation only.
	 */
	if (pkt == NULL) {

		/*
		 * First step of sf_scsi_init_pkt:  pkt allocation
		 */
		if (cmdlen > FCP_CDB_SIZE) {
			return (NULL);
		}

		kf = (callback == SLEEP_FUNC)? KM_SLEEP: KM_NOSLEEP;

		if ((cmd = kmem_cache_alloc(sf->sf_pkt_cache, kf)) != NULL) {
			/*
			 * Selective zeroing of the pkt.
			 */

			cmd->cmd_flags = 0;
			cmd->cmd_forw = 0;
			cmd->cmd_back = 0;
			cmd->cmd_next = 0;
			cmd->cmd_pkt = (struct scsi_pkt *)((char *)cmd +
			    sizeof (struct sf_pkt) + sizeof (struct
			    fcal_packet));
			cmd->cmd_fp_pkt = (struct fcal_packet *)((char *)cmd +
			    sizeof (struct sf_pkt));
			cmd->cmd_fp_pkt->fcal_pkt_private = (opaque_t)cmd;
			cmd->cmd_state = SF_STATE_IDLE;
			cmd->cmd_pkt->pkt_ha_private = (opaque_t)cmd;
			cmd->cmd_pkt->pkt_scbp = (opaque_t)cmd->cmd_scsi_scb;
			cmd->cmd_pkt->pkt_comp	= NULL;
			cmd->cmd_pkt->pkt_flags	= 0;
			cmd->cmd_pkt->pkt_time	= 0;
			cmd->cmd_pkt->pkt_resid	= 0;
			cmd->cmd_pkt->pkt_reason = 0;
			cmd->cmd_cdblen = (uchar_t)cmdlen;
			cmd->cmd_scblen		= statuslen;
			cmd->cmd_privlen	= tgtlen;
			cmd->cmd_pkt->pkt_address = *ap;

			/* zero pkt_private */
			(int *)(cmd->cmd_pkt->pkt_private =
			    cmd->cmd_pkt_private);
			bzero((caddr_t)cmd->cmd_pkt->pkt_private,
			    PKT_PRIV_LEN);
		} else {
			failure = TRUE;
		}

		if (failure ||
		    (tgtlen > PKT_PRIV_LEN) ||
		    (statuslen > EXTCMDS_STATUS_SIZE)) {
			if (!failure) {
				/* need to allocate more space */
				failure = sf_pkt_alloc_extern(sf, cmd,
				    tgtlen, statuslen, kf);
			}
			if (failure) {
				return (NULL);
			}
		}

		fpkt = cmd->cmd_fp_pkt;
		if (cmd->cmd_block == NULL) {

			/* allocate cmd/response pool buffers */
			if (sf_cr_alloc(sf, cmd, callback) == DDI_FAILURE) {
				sf_pkt_destroy_extern(sf, cmd);
				return (NULL);
			}

			/* fill in the FC-AL packet */
			fpkt->fcal_pkt_cookie = sf->sf_socp;
			fpkt->fcal_pkt_comp = sf_cmd_callback;
			fpkt->fcal_pkt_flags = 0;
			fpkt->fcal_magic = FCALP_MAGIC;
			fpkt->fcal_socal_request.sr_soc_hdr.sh_flags =
			    (ushort_t)(SOC_FC_HEADER |
			    sf->sf_sochandle->fcal_portno);
			fpkt->fcal_socal_request.sr_soc_hdr.sh_class = 3;
			fpkt->fcal_socal_request.sr_cqhdr.cq_hdr_count = 1;
			fpkt->fcal_socal_request.sr_cqhdr.cq_hdr_flags = 0;
			fpkt->fcal_socal_request.sr_cqhdr.cq_hdr_seqno = 0;
			fpkt->fcal_socal_request.sr_dataseg[0].fc_base =
			    (uint32_t)cmd->cmd_dmac;
			fpkt->fcal_socal_request.sr_dataseg[0].fc_count =
			    sizeof (struct fcp_cmd);
			fpkt->fcal_socal_request.sr_dataseg[1].fc_base =
			    (uint32_t)cmd->cmd_rsp_dmac;
			fpkt->fcal_socal_request.sr_dataseg[1].fc_count =
			    FCP_MAX_RSP_IU_SIZE;

			/* Fill in the Fabric Channel Header */
			hp = &fpkt->fcal_socal_request.sr_fc_frame_hdr;
			hp->r_ctl = R_CTL_COMMAND;
			hp->type = TYPE_SCSI_FCP;
			hp->f_ctl = F_CTL_SEQ_INITIATIVE | F_CTL_FIRST_SEQ;
			hp->reserved1 = 0;
			hp->seq_id = 0;
			hp->df_ctl  = 0;
			hp->seq_cnt = 0;
			hp->ox_id = 0xffff;
			hp->rx_id = 0xffff;
			hp->ro = 0;

			/* Establish the LUN */
			bcopy((caddr_t)&target->sft_lun.b,
			    (caddr_t)&cmd->cmd_block->fcp_ent_addr,
			    FCP_LUN_SIZE);
			*((int32_t *)&cmd->cmd_block->fcp_cntl) = 0;
		}
		cmd->cmd_pkt->pkt_cdbp = cmd->cmd_block->fcp_cdb;

		mutex_enter(&target->sft_pkt_mutex);

		target->sft_pkt_tail->cmd_forw = cmd;
		cmd->cmd_back = target->sft_pkt_tail;
		cmd->cmd_forw = (struct sf_pkt *)&target->sft_pkt_head;
		target->sft_pkt_tail = cmd;

		mutex_exit(&target->sft_pkt_mutex);
		new_cmd = cmd;		/* for later cleanup if needed */
	} else {
		/* pkt already exists -- just a request for DMA allocation */
		cmd = PKT2CMD(pkt);
		fpkt = cmd->cmd_fp_pkt;
	}

	/* zero cdb (bzero is too slow) */
	bzero((caddr_t)cmd->cmd_pkt->pkt_cdbp, cmdlen);

	/*
	 * Second step of sf_scsi_init_pkt:  dma allocation
	 * Set up dma info
	 */
	if ((bp != NULL) && (bp->b_bcount != 0)) {
		int cmd_flags, dma_flags;
		int rval = 0;
		uint_t dmacookie_count;

		/* there is a buffer and some data to transfer */

		/* set up command and DMA flags */
		cmd_flags = cmd->cmd_flags;
		if (bp->b_flags & B_READ) {
			/* a read */
			cmd_flags &= ~CFLAG_DMASEND;
			dma_flags = DDI_DMA_READ;
		} else {
			/* a write */
			cmd_flags |= CFLAG_DMASEND;
			dma_flags = DDI_DMA_WRITE;
		}
		if (flags & PKT_CONSISTENT) {
			cmd_flags |= CFLAG_CMDIOPB;
			dma_flags |= DDI_DMA_CONSISTENT;
		}

		/* ensure we have a DMA handle */
		if (cmd->cmd_dmahandle == NULL) {
			rval = ddi_dma_alloc_handle(sf->sf_dip,
			    sf->sf_sochandle->fcal_dmaattr, callback, arg,
			    &cmd->cmd_dmahandle);
		}

		if (rval == 0) {
			/* bind our DMA handle to our buffer */
			rval = ddi_dma_buf_bind_handle(cmd->cmd_dmahandle, bp,
			    dma_flags, callback, arg, &cmd->cmd_dmacookie,
			    &dmacookie_count);
		}

		if (rval != 0) {
			/* DMA failure */
			SF_DEBUG(2, (sf, CE_CONT, "ddi_dma_buf.. failed\n"));
			switch (rval) {
			case DDI_DMA_NORESOURCES:
				bioerror(bp, 0);
				break;
			case DDI_DMA_BADATTR:
			case DDI_DMA_NOMAPPING:
				bioerror(bp, EFAULT);
				break;
			case DDI_DMA_TOOBIG:
			default:
				bioerror(bp, EINVAL);
				break;
			}
			/* clear valid flag */
			cmd->cmd_flags = cmd_flags & ~CFLAG_DMAVALID;
			if (new_cmd != NULL) {
				/* destroy packet if we just created it */
				sf_scsi_destroy_pkt(ap, new_cmd->cmd_pkt);
			}
			return (NULL);
		}

		ASSERT(dmacookie_count == 1);
		/* set up amt to transfer and set valid flag */
		cmd->cmd_dmacount = bp->b_bcount;
		cmd->cmd_flags = cmd_flags | CFLAG_DMAVALID;

		ASSERT(cmd->cmd_dmahandle != NULL);
	}

	/* set up FC-AL packet */
	fcmd = cmd->cmd_block;

	if (cmd->cmd_flags & CFLAG_DMAVALID) {
		if (cmd->cmd_flags & CFLAG_DMASEND) {
			/* DMA write */
			fcmd->fcp_cntl.cntl_read_data = 0;
			fcmd->fcp_cntl.cntl_write_data = 1;
			fpkt->fcal_socal_request.sr_cqhdr.cq_hdr_type =
			    CQ_TYPE_IO_WRITE;
		} else {
			/* DMA read */
			fcmd->fcp_cntl.cntl_read_data = 1;
			fcmd->fcp_cntl.cntl_write_data = 0;
			fpkt->fcal_socal_request.sr_cqhdr.cq_hdr_type =
			    CQ_TYPE_IO_READ;
		}
		fpkt->fcal_socal_request.sr_dataseg[2].fc_base =
		    (uint32_t)cmd->cmd_dmacookie.dmac_address;
		fpkt->fcal_socal_request.sr_dataseg[2].fc_count =
		    cmd->cmd_dmacookie.dmac_size;
		fpkt->fcal_socal_request.sr_soc_hdr.sh_seg_cnt = 3;
		fpkt->fcal_socal_request.sr_soc_hdr.sh_byte_cnt =
		    cmd->cmd_dmacookie.dmac_size;
		fcmd->fcp_data_len = cmd->cmd_dmacookie.dmac_size;
	} else {
		/* not a read or write */
		fcmd->fcp_cntl.cntl_read_data = 0;
		fcmd->fcp_cntl.cntl_write_data = 0;
		fpkt->fcal_socal_request.sr_cqhdr.cq_hdr_type = CQ_TYPE_SIMPLE;
		fpkt->fcal_socal_request.sr_soc_hdr.sh_seg_cnt = 2;
		fpkt->fcal_socal_request.sr_soc_hdr.sh_byte_cnt =
		    sizeof (struct fcp_cmd);
		fcmd->fcp_data_len = 0;
	}
	fcmd->fcp_cntl.cntl_qtype = FCP_QTYPE_SIMPLE;

	return (cmd->cmd_pkt);
}


/*
 * destroy a SCSI packet -- called internally and by the transport
 */
static void
sf_scsi_destroy_pkt(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	struct sf_pkt *cmd = PKT2CMD(pkt);
	struct sf *sf = ADDR2SF(ap);
	struct sf_target *target = ADDR2TARGET(ap);
	struct fcal_packet	*fpkt = cmd->cmd_fp_pkt;


	if (cmd->cmd_flags & CFLAG_DMAVALID) {
		/* DMA was set up -- clean up */
		(void) ddi_dma_unbind_handle(cmd->cmd_dmahandle);
		cmd->cmd_flags ^= CFLAG_DMAVALID;
	}

	/* take this packet off the doubly-linked list */
	mutex_enter(&target->sft_pkt_mutex);
	cmd->cmd_back->cmd_forw = cmd->cmd_forw;
	cmd->cmd_forw->cmd_back = cmd->cmd_back;
	mutex_exit(&target->sft_pkt_mutex);

	fpkt->fcal_pkt_flags = 0;
	/* free the packet */
	if ((cmd->cmd_flags &
	    (CFLAG_FREE | CFLAG_PRIVEXTERN | CFLAG_SCBEXTERN)) == 0) {
		/* just a regular packet */
		ASSERT(cmd->cmd_state != SF_STATE_ISSUED);
		cmd->cmd_flags = CFLAG_FREE;
		kmem_cache_free(sf->sf_pkt_cache, (void *)cmd);
	} else {
		/* a packet with extra memory */
		sf_pkt_destroy_extern(sf, cmd);
	}
}


/*
 * called by transport to unbind DMA handle
 */
/* ARGSUSED */
static void
sf_scsi_dmafree(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	struct sf_pkt *cmd = PKT2CMD(pkt);


	if (cmd->cmd_flags & CFLAG_DMAVALID) {
		(void) ddi_dma_unbind_handle(cmd->cmd_dmahandle);
		cmd->cmd_flags ^= CFLAG_DMAVALID;
	}

}


/*
 * called by transport to synchronize CPU and I/O views of memory
 */
/* ARGSUSED */
static void
sf_scsi_sync_pkt(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	struct sf_pkt *cmd = PKT2CMD(pkt);


	if (cmd->cmd_flags & CFLAG_DMAVALID) {
		if (ddi_dma_sync(cmd->cmd_dmahandle, (off_t)0, (size_t)0,
		    (cmd->cmd_flags & CFLAG_DMASEND) ?
		    DDI_DMA_SYNC_FORDEV : DDI_DMA_SYNC_FORCPU) !=
		    DDI_SUCCESS) {
			cmn_err(CE_WARN, "sf: sync pkt failed");
		}
	}
}


/*
 * routine for reset notification setup, to register or cancel. -- called
 * by transport
 */
static int
sf_scsi_reset_notify(struct scsi_address *ap, int flag,
    void (*callback)(caddr_t), caddr_t arg)
{
	struct sf	*sf = ADDR2SF(ap);

	return (scsi_hba_reset_notify_setup(ap, flag, callback, arg,
	    &sf->sf_mutex, &sf->sf_reset_notify_listf));
}


/*
 * called by transport to get port WWN property (except sun4u)
 */
/* ARGSUSED */
static int
sf_scsi_get_name(struct scsi_device *sd, char *name, int len)
{
	char tbuf[(FC_WWN_SIZE*2)+1];
	unsigned char wwn[FC_WWN_SIZE];
	int i, lun;
	dev_info_t *tgt_dip;

	tgt_dip = sd->sd_dev;
	i = sizeof (wwn);
	if (ddi_prop_op(DDI_DEV_T_ANY, tgt_dip, PROP_LEN_AND_VAL_BUF,
	    DDI_PROP_DONTPASS | DDI_PROP_CANSLEEP, PORT_WWN_PROP,
	    (caddr_t)&wwn, &i) != DDI_SUCCESS) {
		name[0] = '\0';
		return (0);
	}
	i = sizeof (lun);
	if (ddi_prop_op(DDI_DEV_T_ANY, tgt_dip, PROP_LEN_AND_VAL_BUF,
	    DDI_PROP_DONTPASS | DDI_PROP_CANSLEEP, "lun",
	    (caddr_t)&lun, &i) != DDI_SUCCESS) {
		name[0] = '\0';
		return (0);
	}
	for (i = 0; i < FC_WWN_SIZE; i++)
		(void) sprintf(&tbuf[i << 1], "%02x", wwn[i]);
	(void) sprintf(name, "w%s,%x", tbuf, lun);
	return (1);
}


/*
 * called by transport to get target soft AL-PA (except sun4u)
 */
/* ARGSUSED */
static int
sf_scsi_get_bus_addr(struct scsi_device *sd, char *name, int len)
{
	struct sf_target *target = ADDR2TARGET(&sd->sd_address);

	if (target == NULL)
		return (0);

	(void) sprintf(name, "%x", target->sft_al_pa);
	return (1);
}


/*
 * add to the command/response buffer pool for this sf instance
 */
static int
sf_add_cr_pool(struct sf *sf)
{
	int		cmd_buf_size;
	size_t		real_cmd_buf_size;
	int		rsp_buf_size;
	size_t		real_rsp_buf_size;
	uint_t		i, ccount;
	struct sf_cr_pool	*ptr;
	struct sf_cr_free_elem *cptr;
	caddr_t	dptr, eptr;
	ddi_dma_cookie_t	cmd_cookie;
	ddi_dma_cookie_t	rsp_cookie;
	int		cmd_bound = FALSE, rsp_bound = FALSE;


	/* allocate room for the pool */
	if ((ptr = kmem_zalloc(sizeof (struct sf_cr_pool), KM_NOSLEEP)) ==
	    NULL) {
		return (DDI_FAILURE);
	}

	/* allocate a DMA handle for the command pool */
	if (ddi_dma_alloc_handle(sf->sf_dip, sf->sf_sochandle->fcal_dmaattr,
	    DDI_DMA_DONTWAIT, NULL, &ptr->cmd_dma_handle) != DDI_SUCCESS) {
		goto fail;
	}

	/*
	 * Get a piece of memory in which to put commands
	 */
	cmd_buf_size = (sizeof (struct fcp_cmd) * SF_ELEMS_IN_POOL + 7) & ~7;
	if (ddi_dma_mem_alloc(ptr->cmd_dma_handle, cmd_buf_size,
	    sf->sf_sochandle->fcal_accattr, DDI_DMA_CONSISTENT,
	    DDI_DMA_DONTWAIT, NULL, (caddr_t *)&ptr->cmd_base,
	    &real_cmd_buf_size, &ptr->cmd_acc_handle) != DDI_SUCCESS) {
		goto fail;
	}

	/* bind the DMA handle to an address */
	if (ddi_dma_addr_bind_handle(ptr->cmd_dma_handle, NULL,
	    ptr->cmd_base, real_cmd_buf_size,
	    DDI_DMA_WRITE | DDI_DMA_CONSISTENT, DDI_DMA_DONTWAIT,
	    NULL, &cmd_cookie, &ccount) != DDI_DMA_MAPPED) {
		goto fail;
	}
	cmd_bound = TRUE;
	/* ensure only one cookie was allocated */
	if (ccount != 1) {
		goto fail;
	}

	/* allocate a DMA handle for the response pool */
	if (ddi_dma_alloc_handle(sf->sf_dip, sf->sf_sochandle->fcal_dmaattr,
	    DDI_DMA_DONTWAIT, NULL, &ptr->rsp_dma_handle) != DDI_SUCCESS) {
		goto fail;
	}

	/*
	 * Get a piece of memory in which to put responses
	 */
	rsp_buf_size = FCP_MAX_RSP_IU_SIZE * SF_ELEMS_IN_POOL;
	if (ddi_dma_mem_alloc(ptr->rsp_dma_handle, rsp_buf_size,
	    sf->sf_sochandle->fcal_accattr, DDI_DMA_CONSISTENT,
	    DDI_DMA_DONTWAIT, NULL, (caddr_t *)&ptr->rsp_base,
	    &real_rsp_buf_size, &ptr->rsp_acc_handle) != DDI_SUCCESS) {
		goto fail;
	}

	/* bind the DMA handle to an address */
	if (ddi_dma_addr_bind_handle(ptr->rsp_dma_handle, NULL,
	    ptr->rsp_base, real_rsp_buf_size,
	    DDI_DMA_READ | DDI_DMA_CONSISTENT, DDI_DMA_DONTWAIT,
	    NULL, &rsp_cookie, &ccount) != DDI_DMA_MAPPED) {
		goto fail;
	}
	rsp_bound = TRUE;
	/* ensure only one cookie was allocated */
	if (ccount != 1) {
		goto fail;
	}

	/*
	 * Generate a (cmd/rsp structure) free list
	 */
	/* ensure ptr points to start of long word (8-byte block) */
	dptr = (caddr_t)((uintptr_t)(ptr->cmd_base) + 7 & ~7);
	/* keep track of actual size after moving pointer */
	real_cmd_buf_size -= (dptr - ptr->cmd_base);
	eptr = ptr->rsp_base;

	/* set actual total number of entries */
	ptr->ntot = min((real_cmd_buf_size / sizeof (struct fcp_cmd)),
	    (real_rsp_buf_size / FCP_MAX_RSP_IU_SIZE));
	ptr->nfree = ptr->ntot;
	ptr->free = (struct sf_cr_free_elem *)ptr->cmd_base;
	ptr->sf = sf;

	/* set up DMA for each pair of entries */
	i = 0;
	while (i < ptr->ntot) {
		cptr = (struct sf_cr_free_elem *)dptr;
		dptr += sizeof (struct fcp_cmd);

		cptr->next = (struct sf_cr_free_elem *)dptr;
		cptr->rsp = eptr;

		cptr->cmd_dmac = cmd_cookie.dmac_address +
		    (uint32_t)((caddr_t)cptr - ptr->cmd_base);

		cptr->rsp_dmac = rsp_cookie.dmac_address +
		    (uint32_t)((caddr_t)eptr - ptr->rsp_base);

		eptr += FCP_MAX_RSP_IU_SIZE;
		i++;
	}

	/* terminate the list */
	cptr->next = NULL;

	/* add this list at front of current one */
	mutex_enter(&sf->sf_cr_mutex);
	ptr->next = sf->sf_cr_pool;
	sf->sf_cr_pool = ptr;
	sf->sf_cr_pool_cnt++;
	mutex_exit(&sf->sf_cr_mutex);

	return (DDI_SUCCESS);

fail:
	/* we failed so clean up */
	if (ptr->cmd_dma_handle != NULL) {
		if (cmd_bound) {
			(void) ddi_dma_unbind_handle(ptr->cmd_dma_handle);
		}
		ddi_dma_free_handle(&ptr->cmd_dma_handle);
	}

	if (ptr->rsp_dma_handle != NULL) {
		if (rsp_bound) {
			(void) ddi_dma_unbind_handle(ptr->rsp_dma_handle);
		}
		ddi_dma_free_handle(&ptr->rsp_dma_handle);
	}

	if (ptr->cmd_base != NULL) {
		ddi_dma_mem_free(&ptr->cmd_acc_handle);
	}

	if (ptr->rsp_base != NULL) {
		ddi_dma_mem_free(&ptr->rsp_acc_handle);
	}

	kmem_free((caddr_t)ptr, sizeof (struct sf_cr_pool));
	return (DDI_FAILURE);
}


/*
 * allocate a command/response buffer from the pool, allocating more
 * in the pool as needed
 */
static int
sf_cr_alloc(struct sf *sf, struct sf_pkt *cmd, int (*func)())
{
	struct sf_cr_pool *ptr;
	struct sf_cr_free_elem *cptr;


	mutex_enter(&sf->sf_cr_mutex);

try_again:

	/* find a free buffer in the existing pool */
	ptr = sf->sf_cr_pool;
	while (ptr != NULL) {
		if (ptr->nfree != 0) {
			ptr->nfree--;
			break;
		} else {
			ptr = ptr->next;
		}
	}

	/* did we find a free buffer ? */
	if (ptr != NULL) {
		/* we found a free buffer -- take it off the free list */
		cptr = ptr->free;
		ptr->free = cptr->next;
		mutex_exit(&sf->sf_cr_mutex);
		/* set up the command to use the buffer pair */
		cmd->cmd_block = (struct fcp_cmd *)cptr;
		cmd->cmd_dmac = cptr->cmd_dmac;
		cmd->cmd_rsp_dmac = cptr->rsp_dmac;
		cmd->cmd_rsp_block = (struct fcp_rsp *)cptr->rsp;
		cmd->cmd_cr_pool = ptr;
		return (DDI_SUCCESS);		/* success */
	}

	/* no free buffer available -- can we allocate more ? */
	if (sf->sf_cr_pool_cnt < SF_CR_POOL_MAX) {
		/* we need to allocate more buffer pairs */
		if (sf->sf_cr_flag) {
			/* somebody already allocating for this instance */
			if (func == SLEEP_FUNC) {
				/* user wants to wait */
				cv_wait(&sf->sf_cr_cv, &sf->sf_cr_mutex);
				/* we've been woken so go try again */
				goto try_again;
			}
			/* user does not want to wait */
			mutex_exit(&sf->sf_cr_mutex);
			sf->sf_stats.cralloc_failures++;
			return (DDI_FAILURE);	/* give up */
		}
		/* set flag saying we're allocating */
		sf->sf_cr_flag = 1;
		mutex_exit(&sf->sf_cr_mutex);
		/* add to our pool */
		if (sf_add_cr_pool(sf) != DDI_SUCCESS) {
			/* couldn't add to our pool for some reason */
			mutex_enter(&sf->sf_cr_mutex);
			sf->sf_cr_flag = 0;
			cv_broadcast(&sf->sf_cr_cv);
			mutex_exit(&sf->sf_cr_mutex);
			sf->sf_stats.cralloc_failures++;
			return (DDI_FAILURE);	/* give up */
		}
		/*
		 * clear flag saying we're allocating and tell all other
		 * that care
		 */
		mutex_enter(&sf->sf_cr_mutex);
		sf->sf_cr_flag = 0;
		cv_broadcast(&sf->sf_cr_cv);
		/* now that we have more buffers try again */
		goto try_again;
	}

	/* we don't have room to allocate any more buffers */
	mutex_exit(&sf->sf_cr_mutex);
	sf->sf_stats.cralloc_failures++;
	return (DDI_FAILURE);			/* give up */
}


/*
 * free a cmd/response buffer pair in our pool
 */
static void
sf_cr_free(struct sf_cr_pool *cp, struct sf_pkt *cmd)
{
	struct sf *sf = cp->sf;
	struct sf_cr_free_elem *elem;

	elem = (struct sf_cr_free_elem *)cmd->cmd_block;
	elem->rsp = (caddr_t)cmd->cmd_rsp_block;
	elem->cmd_dmac = cmd->cmd_dmac;
	elem->rsp_dmac = cmd->cmd_rsp_dmac;

	mutex_enter(&sf->sf_cr_mutex);
	cp->nfree++;
	ASSERT(cp->nfree <= cp->ntot);

	elem->next = cp->free;
	cp->free = elem;
	mutex_exit(&sf->sf_cr_mutex);
}


/*
 * free our pool of cmd/response buffers
 */
static void
sf_crpool_free(struct sf *sf)
{
	struct sf_cr_pool *cp, *prev;

	prev = NULL;
	mutex_enter(&sf->sf_cr_mutex);
	cp = sf->sf_cr_pool;
	while (cp != NULL) {
		if (cp->nfree == cp->ntot) {
			if (prev != NULL) {
				prev->next = cp->next;
			} else {
				sf->sf_cr_pool = cp->next;
			}
			sf->sf_cr_pool_cnt--;
			mutex_exit(&sf->sf_cr_mutex);

			(void) ddi_dma_unbind_handle(cp->cmd_dma_handle);
			ddi_dma_free_handle(&cp->cmd_dma_handle);
			(void) ddi_dma_unbind_handle(cp->rsp_dma_handle);
			ddi_dma_free_handle(&cp->rsp_dma_handle);
			ddi_dma_mem_free(&cp->cmd_acc_handle);
			ddi_dma_mem_free(&cp->rsp_acc_handle);
			kmem_free((caddr_t)cp, sizeof (struct sf_cr_pool));
			return;
		}
		prev = cp;
		cp = cp->next;
	}
	mutex_exit(&sf->sf_cr_mutex);
}


/* ARGSUSED */
static int
sf_kmem_cache_constructor(void *buf, void *arg, int size)
{
	struct sf_pkt *cmd = buf;

	mutex_init(&cmd->cmd_abort_mutex, NULL, MUTEX_DRIVER, NULL);
	cmd->cmd_block = NULL;
	cmd->cmd_dmahandle = NULL;
	return (0);
}


/* ARGSUSED */
static void
sf_kmem_cache_destructor(void *buf, void *size)
{
	struct sf_pkt *cmd = buf;

	if (cmd->cmd_dmahandle != NULL) {
		ddi_dma_free_handle(&cmd->cmd_dmahandle);
	}

	if (cmd->cmd_block != NULL) {
		sf_cr_free(cmd->cmd_cr_pool, cmd);
	}
	mutex_destroy(&cmd->cmd_abort_mutex);
}


/*
 * called by transport when a state change occurs
 */
static void
sf_statec_callback(void *arg, int msg)
{
	struct sf *sf = (struct sf *)arg;
	struct sf_target	*target;
	int i;
	struct sf_pkt *cmd;
	struct scsi_pkt *pkt;



	switch (msg) {

	case FCAL_STATUS_LOOP_ONLINE: {
		uchar_t		al_pa;		/* to save AL-PA */
		int		ret;		/* ret value from getmap */
		int		lip_cnt;	/* to save current count */
		int		cnt;		/* map length */

		/*
		 * the loop has gone online
		 */
		SF_DEBUG(1, (sf, CE_CONT, "sf%d: loop online\n",
		    ddi_get_instance(sf->sf_dip)));
		mutex_enter(&sf->sf_mutex);
		sf->sf_lip_cnt++;
		sf->sf_state = SF_STATE_ONLINING;
		mutex_exit(&sf->sf_mutex);

		/* scan each target hash queue */
		for (i = 0; i < SF_NUM_HASH_QUEUES; i++) {
			target = sf->sf_wwn_lists[i];
			while (target != NULL) {
				/*
				 * foreach target, if it's not offline then
				 * mark it as busy
				 */
				mutex_enter(&target->sft_mutex);
				if (!(target->sft_state & SF_TARGET_OFFLINE))
					target->sft_state |= (SF_TARGET_BUSY
					    | SF_TARGET_MARK);
#ifdef DEBUG
				/*
				 * for debugging, print out info on any
				 * pending commands (left hanging)
				 */
				cmd = target->sft_pkt_head;
				while (cmd != (struct sf_pkt *)&target->
				    sft_pkt_head) {
					if (cmd->cmd_state ==
					    SF_STATE_ISSUED) {
						SF_DEBUG(1, (sf, CE_CONT,
						    "cmd 0x%p pending "
						    "after lip\n",
						    (void *)cmd->cmd_fp_pkt));
					}
					cmd = cmd->cmd_forw;
				}
#endif
				mutex_exit(&target->sft_mutex);
				target = target->sft_next;
			}
		}

		/*
		 * since the loop has just gone online get a new map from
		 * the transport
		 */
		if ((ret = soc_get_lilp_map(sf->sf_sochandle, sf->sf_socp,
		    sf->sf_sochandle->fcal_portno, (uint32_t)sf->
		    sf_lilp_dmacookie.dmac_address, 1)) != FCAL_SUCCESS) {
			if (sf_core && (sf_core & SF_CORE_LILP_FAILED)) {
				(void) soc_take_core(sf->sf_sochandle,
				    sf->sf_socp);
				sf_core = 0;
			}
			sf_log(sf, CE_WARN,
			    "!soc lilp map failed status=0x%x\n", ret);
			mutex_enter(&sf->sf_mutex);
			sf->sf_timer = sf_watchdog_time + SF_OFFLINE_TIMEOUT;
			sf->sf_lip_cnt++;
			sf->sf_state = SF_STATE_OFFLINE;
			mutex_exit(&sf->sf_mutex);
			return;
		}

		/* ensure consistent view of DMA memory */
		(void) ddi_dma_sync(sf->sf_lilp_dmahandle, (off_t)0, (size_t)0,
		    DDI_DMA_SYNC_FORKERNEL);

		/* how many entries in map ? */
		cnt = sf->sf_lilp_map->lilp_length;
		if (cnt >= SF_MAX_LILP_ENTRIES) {
			sf_log(sf, CE_WARN, "invalid lilp map\n");
			return;
		}

		mutex_enter(&sf->sf_mutex);
		sf->sf_device_count = cnt - 1;
		sf->sf_al_pa = sf->sf_lilp_map->lilp_myalpa;
		lip_cnt = sf->sf_lip_cnt;
		al_pa = sf->sf_al_pa;

		SF_DEBUG(1, (sf, CE_CONT,
		    "!lilp map has %d entries, al_pa is %x\n", cnt, al_pa));

		/*
		 * since the last entry of the map may be mine (common) check
		 * for that, and if it is we have one less entry to look at
		 */
		if (sf->sf_lilp_map->lilp_alpalist[cnt-1] == al_pa) {
			cnt--;
		}
		/* If we didn't get a valid loop map enable all targets */
		if (sf->sf_lilp_map->lilp_magic == FCAL_BADLILP_MAGIC) {
			for (i = 0; i < sizeof (sf_switch_to_alpa); i++)
				sf->sf_lilp_map->lilp_alpalist[i] =
				    sf_switch_to_alpa[i];
			cnt = i;
			sf->sf_device_count = cnt - 1;
		}
		if (sf->sf_device_count == 0) {
			sf_finish_init(sf, lip_cnt);
			mutex_exit(&sf->sf_mutex);
			break;
		}
		mutex_exit(&sf->sf_mutex);

		SF_DEBUG(2, (sf, CE_WARN,
		    "!statec_callback: starting with %d targets\n",
		    sf->sf_device_count));

		/* scan loop map, logging into all ports (except mine) */
		for (i = 0; i < cnt; i++) {
			SF_DEBUG(1, (sf, CE_CONT,
			    "!lilp map entry %d = %x,%x\n", i,
			    sf->sf_lilp_map->lilp_alpalist[i],
			    sf_alpa_to_switch[
			    sf->sf_lilp_map->lilp_alpalist[i]]));
			/* is this entry for somebody else ? */
			if (sf->sf_lilp_map->lilp_alpalist[i] != al_pa) {
				/* do a PLOGI to this port */
				if (!sf_login(sf, LA_ELS_PLOGI,
				    sf->sf_lilp_map->lilp_alpalist[i],
				    sf->sf_lilp_map->lilp_alpalist[cnt-1],
				    lip_cnt)) {
					/* a problem logging in */
					mutex_enter(&sf->sf_mutex);
					if (lip_cnt == sf->sf_lip_cnt) {
						/*
						 * problem not from a new LIP
						 */
						sf->sf_device_count--;
						ASSERT(sf->sf_device_count
						    >= 0);
						if (sf->sf_device_count == 0) {
							sf_finish_init(sf,
							    lip_cnt);
						}
					}
					mutex_exit(&sf->sf_mutex);
				}
			}
		}
		break;
	}

	case FCAL_STATUS_ERR_OFFLINE:
		/*
		 * loop has gone offline due to an error
		 */
		SF_DEBUG(1, (sf, CE_CONT, "sf%d: loop offline\n",
		    ddi_get_instance(sf->sf_dip)));
		mutex_enter(&sf->sf_mutex);
		sf->sf_lip_cnt++;
		sf->sf_timer = sf_watchdog_time + SF_OFFLINE_TIMEOUT;
		if (!sf->sf_online_timer) {
			sf->sf_online_timer = sf_watchdog_time +
			    SF_ONLINE_TIMEOUT;
		}
		/*
		 * if we are suspended, preserve the SF_STATE_SUSPENDED flag,
		 * since throttling logic in sf_watch() depends on
		 * preservation of this flag while device is suspended
		 */
		if (sf->sf_state & SF_STATE_SUSPENDED) {
			sf->sf_state |= SF_STATE_OFFLINE;
			SF_DEBUG(1, (sf, CE_CONT,
			    "sf_statec_callback, sf%d: "
			    "got FCAL_STATE_OFFLINE during DDI_SUSPEND\n",
			    ddi_get_instance(sf->sf_dip)));
		} else {
			sf->sf_state = SF_STATE_OFFLINE;
		}

		/* scan each possible target on the loop */
		for (i = 0; i < sf_max_targets; i++) {
			target = sf->sf_targets[i];
			while (target != NULL) {
				mutex_enter(&target->sft_mutex);
				if (!(target->sft_state & SF_TARGET_OFFLINE))
					target->sft_state |= (SF_TARGET_BUSY
					    | SF_TARGET_MARK);
				mutex_exit(&target->sft_mutex);
				target = target->sft_next_lun;
			}
		}
		mutex_exit(&sf->sf_mutex);
		break;

	case FCAL_STATE_RESET: {
		struct sf_els_hdr	*privp;	/* ptr to private list */
		struct sf_els_hdr	*tmpp1;	/* tmp prev hdr ptr */
		struct sf_els_hdr	*tmpp2;	/* tmp next hdr ptr */
		struct sf_els_hdr	*head;	/* to save our private list */
		struct fcal_packet	*fpkt;	/* ptr to pkt in hdr */

		/*
		 * a transport reset
		 */
		SF_DEBUG(1, (sf, CE_CONT, "!sf%d: soc reset\n",
		    ddi_get_instance(sf->sf_dip)));
		tmpp1 = head = NULL;
		mutex_enter(&sf->sf_mutex);
		sf->sf_lip_cnt++;
		sf->sf_timer = sf_watchdog_time + SF_RESET_TIMEOUT;
		/*
		 * if we are suspended, preserve the SF_STATE_SUSPENDED flag,
		 * since throttling logic in sf_watch() depends on
		 * preservation of this flag while device is suspended
		 */
		if (sf->sf_state & SF_STATE_SUSPENDED) {
			sf->sf_state |= SF_STATE_OFFLINE;
			SF_DEBUG(1, (sf, CE_CONT,
			    "sf_statec_callback, sf%d: "
			    "got FCAL_STATE_RESET during DDI_SUSPEND\n",
			    ddi_get_instance(sf->sf_dip)));
		} else {
			sf->sf_state = SF_STATE_OFFLINE;
		}

		/*
		 * scan each possible target on the loop, looking for targets
		 * that need callbacks ran
		 */
		for (i = 0; i < sf_max_targets; i++) {
			target = sf->sf_targets[i];
			while (target != NULL) {
				if (!(target->sft_state & SF_TARGET_OFFLINE)) {
					target->sft_state |= (SF_TARGET_BUSY
					    | SF_TARGET_MARK);
					mutex_exit(&sf->sf_mutex);
					/*
					 * run remove event callbacks for lun
					 *
					 * We have a nasty race condition here
					 * 'cause we're dropping this mutex to
					 * run the callback and expect the
					 * linked list to be the same.
					 */
					(void) ndi_event_retrieve_cookie(
					    sf->sf_event_hdl, target->sft_dip,
					    FCAL_REMOVE_EVENT, &sf_remove_eid,
					    NDI_EVENT_NOPASS);
					(void) ndi_event_run_callbacks(
					    sf->sf_event_hdl,
					    target->sft_dip,
					    sf_remove_eid, NULL);
					mutex_enter(&sf->sf_mutex);
				}
				target = target->sft_next_lun;
			}
		}

		/*
		 * scan for ELS commands that are in transport, not complete,
		 * and have a valid timeout, building a private list
		 */
		privp = sf->sf_els_list;
		while (privp != NULL) {
			fpkt = privp->fpkt;
			if ((fpkt->fcal_cmd_state & FCAL_CMD_IN_TRANSPORT) &&
			    (!(fpkt->fcal_cmd_state & FCAL_CMD_COMPLETE)) &&
			    (privp->timeout != SF_INVALID_TIMEOUT)) {
				/*
				 * cmd in transport && not complete &&
				 * timeout valid
				 *
				 * move this entry from ELS input list to our
				 * private list
				 */

				tmpp2 = privp->next; /* save ptr to next */

				/* push this on private list head */
				privp->next = head;
				head = privp;

				/* remove this entry from input list */
				if (tmpp1 != NULL) {
					/*
					 * remove this entry from somewhere in
					 * the middle of the list
					 */
					tmpp1->next = tmpp2;
					if (tmpp2 != NULL) {
						tmpp2->prev = tmpp1;
					}
				} else {
					/*
					 * remove this entry from the head
					 * of the list
					 */
					sf->sf_els_list = tmpp2;
					if (tmpp2 != NULL) {
						tmpp2->prev = NULL;
					}
				}
				privp = tmpp2;	/* skip to next entry */
			} else {
				tmpp1 = privp;	/* save ptr to prev entry */
				privp = privp->next; /* skip to next entry */
			}
		}

		mutex_exit(&sf->sf_mutex);

		/*
		 * foreach cmd in our list free the ELS packet associated
		 * with it
		 */
		privp = head;
		while (privp != NULL) {
			fpkt = privp->fpkt;
			privp = privp->next;
			sf_els_free(fpkt);
		}

		/*
		 * scan for commands from each possible target
		 */
		for (i = 0; i < sf_max_targets; i++) {
			target = sf->sf_targets[i];
			while (target != NULL) {
				/*
				 * scan all active commands for this target,
				 * looking for commands that have been issued,
				 * are in transport, and are not yet complete
				 * (so we can terminate them because of the
				 * reset)
				 */
				mutex_enter(&target->sft_pkt_mutex);
				cmd = target->sft_pkt_head;
				while (cmd != (struct sf_pkt *)&target->
				    sft_pkt_head) {
					fpkt = cmd->cmd_fp_pkt;
					mutex_enter(&cmd->cmd_abort_mutex);
					if ((cmd->cmd_state ==
					    SF_STATE_ISSUED) &&
					    (fpkt->fcal_cmd_state &
					    FCAL_CMD_IN_TRANSPORT) &&
					    (!(fpkt->fcal_cmd_state &
					    FCAL_CMD_COMPLETE))) {
						/* a command to be reset */
						pkt = cmd->cmd_pkt;
						pkt->pkt_reason = CMD_RESET;
						pkt->pkt_statistics |=
						    STAT_BUS_RESET;
						cmd->cmd_state = SF_STATE_IDLE;
						mutex_exit(&cmd->
						    cmd_abort_mutex);
						mutex_exit(&target->
						    sft_pkt_mutex);
						if (pkt->pkt_comp != NULL) {
							(*pkt->pkt_comp)(pkt);
						}
						mutex_enter(&target->
						    sft_pkt_mutex);
						cmd = target->sft_pkt_head;
					} else {
						mutex_exit(&cmd->
						    cmd_abort_mutex);
						/* get next command */
						cmd = cmd->cmd_forw;
					}
				}
				mutex_exit(&target->sft_pkt_mutex);
				target = target->sft_next_lun;
			}
		}

		/*
		 * get packet queue for this target, resetting all remaining
		 * commands
		 */
		mutex_enter(&sf->sf_mutex);
		cmd = sf->sf_pkt_head;
		sf->sf_pkt_head = NULL;
		mutex_exit(&sf->sf_mutex);

		while (cmd != NULL) {
			pkt = cmd->cmd_pkt;
			cmd = cmd->cmd_next;
			pkt->pkt_reason = CMD_RESET;
			pkt->pkt_statistics |= STAT_BUS_RESET;
			if (pkt->pkt_comp != NULL) {
				(*pkt->pkt_comp)(pkt);
			}
		}
		break;
	}

	default:
		break;
	}
}


/*
 * called to send a PLOGI (N_port login) ELS request to a destination ID,
 * returning TRUE upon success, else returning FALSE
 */
static int
sf_login(struct sf *sf, uchar_t els_code, uchar_t dest_id, uint_t arg1,
    int lip_cnt)
{
	struct la_els_logi	*logi;
	struct	sf_els_hdr	*privp;


	if (sf_els_alloc(sf, dest_id, sizeof (struct sf_els_hdr),
	    sizeof (union sf_els_cmd), sizeof (union sf_els_rsp),
	    (caddr_t *)&privp, (caddr_t *)&logi) == NULL) {
		sf_log(sf, CE_WARN, "Cannot allocate PLOGI for target %x "
		    "due to DVMA shortage.\n", sf_alpa_to_switch[dest_id]);
		return (FALSE);
	}

	privp->lip_cnt = lip_cnt;
	if (els_code == LA_ELS_PLOGI) {
		bcopy((caddr_t)sf->sf_sochandle->fcal_loginparms,
		    (caddr_t)&logi->common_service, sizeof (struct la_els_logi)
		    - 4);
		bcopy((caddr_t)&sf->sf_sochandle->fcal_p_wwn,
		    (caddr_t)&logi->nport_ww_name, sizeof (la_wwn_t));
		bcopy((caddr_t)&sf->sf_sochandle->fcal_n_wwn,
		    (caddr_t)&logi->node_ww_name, sizeof (la_wwn_t));
		bzero((caddr_t)&logi->reserved, 16);
	} else if (els_code == LA_ELS_LOGO) {
		bcopy((caddr_t)&sf->sf_sochandle->fcal_p_wwn,
		    (caddr_t)&(((struct la_els_logo *)logi)->nport_ww_name), 8);
		((struct la_els_logo	*)logi)->reserved = 0;
		((struct la_els_logo	*)logi)->nport_id[0] = 0;
		((struct la_els_logo	*)logi)->nport_id[1] = 0;
		((struct la_els_logo	*)logi)->nport_id[2] = arg1;
	}

	privp->els_code = els_code;
	logi->ls_code = els_code;
	logi->mbz[0] = 0;
	logi->mbz[1] = 0;
	logi->mbz[2] = 0;

	privp->timeout = sf_watchdog_time + SF_ELS_TIMEOUT;
	return (sf_els_transport(sf, privp));
}


/*
 * send an ELS IU via the transport,
 * returning TRUE upon success, else returning FALSE
 */
static int
sf_els_transport(struct sf *sf, struct sf_els_hdr *privp)
{
	struct fcal_packet *fpkt = privp->fpkt;


	(void) ddi_dma_sync(privp->cmd_dma_handle, (off_t)0, (size_t)0,
	    DDI_DMA_SYNC_FORDEV);
	privp->prev = NULL;
	mutex_enter(&sf->sf_mutex);
	privp->next = sf->sf_els_list;
	if (sf->sf_els_list != NULL) {
		sf->sf_els_list->prev = privp;
	}
	sf->sf_els_list = privp;
	mutex_exit(&sf->sf_mutex);

	/* call the transport to send a packet */
	if (soc_transport(sf->sf_sochandle, fpkt, FCAL_NOSLEEP,
	    CQ_REQUEST_1) != FCAL_TRANSPORT_SUCCESS) {
		mutex_enter(&sf->sf_mutex);
		if (privp->prev != NULL) {
			privp->prev->next = privp->next;
		}
		if (privp->next != NULL) {
			privp->next->prev = privp->prev;
		}
		if (sf->sf_els_list == privp) {
			sf->sf_els_list = privp->next;
		}
		mutex_exit(&sf->sf_mutex);
		sf_els_free(fpkt);
		return (FALSE);			/* failure */
	}
	return (TRUE);				/* success */
}


/*
 * called as the pkt_comp routine for ELS FC packets
 */
static void
sf_els_callback(struct fcal_packet *fpkt)
{
	struct sf_els_hdr *privp = fpkt->fcal_pkt_private;
	struct sf *sf = privp->sf;
	struct sf *tsf;
	int tgt_id;
	struct la_els_logi *ptr = (struct la_els_logi *)privp->rsp;
	struct la_els_adisc *adisc = (struct la_els_adisc *)ptr;
	struct	sf_target *target;
	short	ncmds;
	short	free_pkt = TRUE;


	/*
	 * we've received an ELS callback, i.e. an ELS packet has arrived
	 */

	/* take the current packet off of the queue */
	mutex_enter(&sf->sf_mutex);
	if (privp->timeout == SF_INVALID_TIMEOUT) {
		mutex_exit(&sf->sf_mutex);
		return;
	}
	if (privp->prev != NULL) {
		privp->prev->next = privp->next;
	}
	if (privp->next != NULL) {
		privp->next->prev = privp->prev;
	}
	if (sf->sf_els_list == privp) {
		sf->sf_els_list = privp->next;
	}
	privp->prev = privp->next = NULL;
	mutex_exit(&sf->sf_mutex);

	/* get # pkts in this callback */
	ncmds = fpkt->fcal_ncmds;
	ASSERT(ncmds >= 0);
	mutex_enter(&sf->sf_cmd_mutex);
	sf->sf_ncmds = ncmds;
	mutex_exit(&sf->sf_cmd_mutex);

	/* sync idea of memory */
	(void) ddi_dma_sync(privp->rsp_dma_handle, (off_t)0, (size_t)0,
	    DDI_DMA_SYNC_FORKERNEL);

	/* was this an OK ACC msg ?? */
	if ((fpkt->fcal_pkt_status == FCAL_STATUS_OK) &&
	    (ptr->ls_code == LA_ELS_ACC)) {

		/*
		 * this was an OK ACC pkt
		 */

		switch (privp->els_code) {
		case LA_ELS_PLOGI:
			/*
			 * was able to to an N_port login
			 */
			SF_DEBUG(2, (sf, CE_CONT,
			    "!PLOGI to al_pa %x succeeded, wwn %x%x\n",
			    privp->dest_nport_id,
			    *((int *)&ptr->nport_ww_name.raw_wwn[0]),
			    *((int *)&ptr->nport_ww_name.raw_wwn[4])));
			/* try to do a process login */
			if (!sf_do_prli(sf, privp, ptr)) {
				free_pkt = FALSE;
				goto fail;	/* PRLI failed */
			}
			break;
		case LA_ELS_PRLI:
			/*
			 * was able to do a process login
			 */
			SF_DEBUG(2, (sf, CE_CONT,
			    "!PRLI to al_pa %x succeeded\n",
			    privp->dest_nport_id));
			/* try to do address discovery */
			if (sf_do_adisc(sf, privp) != 1) {
				free_pkt = FALSE;
				goto fail;	/* ADISC failed */
			}
			break;
		case LA_ELS_ADISC:
			/*
			 * found a target via ADISC
			 */

			SF_DEBUG(2, (sf, CE_CONT,
			    "!ADISC to al_pa %x succeeded\n",
			    privp->dest_nport_id));

			/* create the target info */
			if ((target = sf_create_target(sf, privp,
			    sf_alpa_to_switch[(uchar_t)adisc->hard_address],
			    (int64_t)0))
			    == NULL) {
				goto fail;	/* can't create target */
			}

			/*
			 * ensure address discovered matches what we thought
			 * it would be
			 */
			if ((uchar_t)adisc->hard_address !=
			    privp->dest_nport_id) {
				sf_log(sf, CE_WARN,
				    "target 0x%x, AL-PA 0x%x and "
				    "hard address 0x%x don't match\n",
				    sf_alpa_to_switch[
				    (uchar_t)privp->dest_nport_id],
				    privp->dest_nport_id,
				    (uchar_t)adisc->hard_address);
				mutex_enter(&sf->sf_mutex);
				sf_offline_target(sf, target);
				mutex_exit(&sf->sf_mutex);
				goto fail;	/* addr doesn't match */
			}
			/*
			 * get inquiry data from the target
			 */
			if (!sf_do_reportlun(sf, privp, target)) {
				mutex_enter(&sf->sf_mutex);
				sf_offline_target(sf, target);
				mutex_exit(&sf->sf_mutex);
				free_pkt = FALSE;
				goto fail;	/* inquiry failed */
			}
			break;
		default:
			SF_DEBUG(2, (sf, CE_CONT,
			    "!ELS %x to al_pa %x succeeded\n",
			    privp->els_code, privp->dest_nport_id));
			sf_els_free(fpkt);
			break;
		}

	} else {

		/*
		 * oh oh -- this was not an OK ACC packet
		 */

		/* get target ID from dest loop address */
		tgt_id = sf_alpa_to_switch[(uchar_t)privp->dest_nport_id];

		/* keep track of failures */
		sf->sf_stats.tstats[tgt_id].els_failures++;
		if (++(privp->retries) < sf_els_retries &&
		    fpkt->fcal_pkt_status != FCAL_STATUS_OPEN_FAIL) {
			if (fpkt->fcal_pkt_status ==
			    FCAL_STATUS_MAX_XCHG_EXCEEDED)  {
				tsf = sf->sf_sibling;
				if (tsf != NULL) {
					mutex_enter(&tsf->sf_cmd_mutex);
					tsf->sf_flag = 1;
					tsf->sf_throttle = SF_DECR_DELTA;
					mutex_exit(&tsf->sf_cmd_mutex);
				}
			}
			privp->timeout = sf_watchdog_time + SF_ELS_TIMEOUT;
			privp->prev = NULL;

			mutex_enter(&sf->sf_mutex);

			if (privp->lip_cnt == sf->sf_lip_cnt) {
				SF_DEBUG(1, (sf, CE_WARN,
				    "!ELS %x to al_pa %x failed, retrying",
				    privp->els_code, privp->dest_nport_id));
				privp->next = sf->sf_els_list;
				if (sf->sf_els_list != NULL) {
					sf->sf_els_list->prev = privp;
				}

				sf->sf_els_list = privp;

				mutex_exit(&sf->sf_mutex);
				/* device busy?  wait a bit ... */
				if (fpkt->fcal_pkt_status ==
				    FCAL_STATUS_MAX_XCHG_EXCEEDED)  {
					privp->delayed_retry = 1;
					return;
				}
				/* call the transport to send a pkt */
				if (soc_transport(sf->sf_sochandle, fpkt,
				    FCAL_NOSLEEP, CQ_REQUEST_1) !=
				    FCAL_TRANSPORT_SUCCESS) {
					mutex_enter(&sf->sf_mutex);
					if (privp->prev != NULL) {
						privp->prev->next =
						    privp->next;
					}
					if (privp->next != NULL) {
						privp->next->prev =
						    privp->prev;
					}
					if (sf->sf_els_list == privp) {
						sf->sf_els_list = privp->next;
					}
					mutex_exit(&sf->sf_mutex);
					goto fail;
				} else
					return;
			} else {
				mutex_exit(&sf->sf_mutex);
				goto fail;
			}
		} else {
#ifdef	DEBUG
			if (fpkt->fcal_pkt_status != 0x36 || sfdebug > 4) {
			SF_DEBUG(2, (sf, CE_NOTE, "ELS %x to al_pa %x failed",
			    privp->els_code, privp->dest_nport_id));
			if (fpkt->fcal_pkt_status == FCAL_STATUS_OK) {
				SF_DEBUG(2, (sf, CE_NOTE,
				    "els reply code = %x", ptr->ls_code));
				if (ptr->ls_code == LA_ELS_RJT)
					SF_DEBUG(1, (sf, CE_CONT,
					    "LS_RJT reason = %x\n",
					    *(((uint_t *)ptr) + 1)));
			} else
				SF_DEBUG(2, (sf, CE_NOTE,
				    "fc packet status = %x",
				    fpkt->fcal_pkt_status));
			}
#endif
			goto fail;
		}
	}
	return;					/* success */
fail:
	mutex_enter(&sf->sf_mutex);
	if (sf->sf_lip_cnt == privp->lip_cnt) {
		sf->sf_device_count--;
		ASSERT(sf->sf_device_count >= 0);
		if (sf->sf_device_count == 0) {
			sf_finish_init(sf, privp->lip_cnt);
		}
	}
	mutex_exit(&sf->sf_mutex);
	if (free_pkt) {
		sf_els_free(fpkt);
	}
}


/*
 * send a PRLI (process login) ELS IU via the transport,
 * returning TRUE upon success, else returning FALSE
 */
static int
sf_do_prli(struct sf *sf, struct sf_els_hdr *privp, struct la_els_logi *ptr)
{
	struct la_els_prli	*prli = (struct la_els_prli *)privp->cmd;
	struct fcp_prli		*fprli;
	struct  fcal_packet	*fpkt = privp->fpkt;


	fpkt->fcal_socal_request.sr_dataseg[0].fc_count =
	    sizeof (struct la_els_prli);
	privp->els_code = LA_ELS_PRLI;
	fprli = (struct fcp_prli *)prli->service_params;
	prli->ls_code = LA_ELS_PRLI;
	prli->page_length = 0x10;
	prli->payload_length = sizeof (struct la_els_prli);
	fprli->type = 0x08;			/* no define here? */
	fprli->resvd1 = 0;
	fprli->orig_process_assoc_valid = 0;
	fprli->resp_process_assoc_valid = 0;
	fprli->establish_image_pair = 1;
	fprli->resvd2 = 0;
	fprli->resvd3 = 0;
	fprli->data_overlay_allowed = 0;
	fprli->initiator_fn = 1;
	fprli->target_fn = 0;
	fprli->cmd_data_mixed = 0;
	fprli->data_resp_mixed = 0;
	fprli->read_xfer_rdy_disabled = 1;
	fprli->write_xfer_rdy_disabled = 0;

	bcopy((caddr_t)&ptr->nport_ww_name, (caddr_t)&privp->port_wwn,
	    sizeof (privp->port_wwn));
	bcopy((caddr_t)&ptr->node_ww_name, (caddr_t)&privp->node_wwn,
	    sizeof (privp->node_wwn));

	privp->timeout = sf_watchdog_time + SF_ELS_TIMEOUT;
	return (sf_els_transport(sf, privp));
}


/*
 * send an ADISC (address discovery) ELS IU via the transport,
 * returning TRUE upon success, else returning FALSE
 */
static int
sf_do_adisc(struct sf *sf, struct sf_els_hdr *privp)
{
	struct la_els_adisc	*adisc = (struct la_els_adisc *)privp->cmd;
	struct	fcal_packet	*fpkt = privp->fpkt;

	privp->els_code = LA_ELS_ADISC;
	adisc->ls_code = LA_ELS_ADISC;
	adisc->mbz[0] = 0;
	adisc->mbz[1] = 0;
	adisc->mbz[2] = 0;
	adisc->hard_address = 0; /* ??? */
	fpkt->fcal_socal_request.sr_dataseg[0].fc_count =
	    sizeof (struct la_els_adisc);
	bcopy((caddr_t)&sf->sf_sochandle->fcal_p_wwn,
	    (caddr_t)&adisc->port_wwn, sizeof (adisc->port_wwn));
	bcopy((caddr_t)&sf->sf_sochandle->fcal_n_wwn,
	    (caddr_t)&adisc->node_wwn, sizeof (adisc->node_wwn));
	adisc->nport_id = sf->sf_al_pa;

	privp->timeout = sf_watchdog_time + SF_ELS_TIMEOUT;
	return (sf_els_transport(sf, privp));
}


static struct fcal_packet *
sf_els_alloc(struct sf *sf, uchar_t dest_id, int priv_size, int cmd_size,
    int rsp_size, caddr_t *rprivp, caddr_t *cmd_buf)
{
	struct	fcal_packet	*fpkt;
	ddi_dma_cookie_t	pcookie;
	ddi_dma_cookie_t	rcookie;
	struct	sf_els_hdr	*privp;
	ddi_dma_handle_t	cmd_dma_handle = NULL;
	ddi_dma_handle_t	rsp_dma_handle = NULL;
	ddi_acc_handle_t	cmd_acc_handle = NULL;
	ddi_acc_handle_t	rsp_acc_handle = NULL;
	size_t			real_size;
	uint_t			ccount;
	fc_frame_header_t	*hp;
	int			cmd_bound = FALSE, rsp_bound = FALSE;
	caddr_t			cmd = NULL;
	caddr_t			rsp = NULL;

	if ((fpkt = (struct fcal_packet *)kmem_zalloc(
	    sizeof (struct fcal_packet), KM_NOSLEEP)) == NULL) {
		SF_DEBUG(1, (sf, CE_WARN,
			"Could not allocate fcal_packet for ELS\n"));
		return (NULL);
	}

	if ((privp = (struct sf_els_hdr *)kmem_zalloc(priv_size,
	    KM_NOSLEEP)) == NULL) {
		SF_DEBUG(1, (sf, CE_WARN,
		    "Could not allocate sf_els_hdr for ELS\n"));
		goto fail;
	}

	privp->size = priv_size;
	fpkt->fcal_pkt_private = (caddr_t)privp;

	if (ddi_dma_alloc_handle(sf->sf_dip, sf->sf_sochandle->fcal_dmaattr,
	    DDI_DMA_DONTWAIT, NULL, &cmd_dma_handle) != DDI_SUCCESS) {
		SF_DEBUG(1, (sf, CE_WARN,
		    "Could not allocate DMA handle for ELS\n"));
		goto fail;
	}

	if (ddi_dma_mem_alloc(cmd_dma_handle, cmd_size,
	    sf->sf_sochandle->fcal_accattr, DDI_DMA_CONSISTENT,
	    DDI_DMA_DONTWAIT, NULL, &cmd,
	    &real_size, &cmd_acc_handle) != DDI_SUCCESS) {
		SF_DEBUG(1, (sf, CE_WARN,
		    "Could not allocate DMA memory for ELS\n"));
		goto fail;
	}

	if (real_size < cmd_size) {
		SF_DEBUG(1, (sf, CE_WARN,
		    "DMA memory too small for ELS\n"));
		goto fail;
	}

	if (ddi_dma_addr_bind_handle(cmd_dma_handle, NULL,
	    cmd, real_size, DDI_DMA_WRITE | DDI_DMA_CONSISTENT,
	    DDI_DMA_DONTWAIT, NULL, &pcookie, &ccount) != DDI_DMA_MAPPED) {
		SF_DEBUG(1, (sf, CE_WARN,
		    "Could not bind DMA memory for ELS\n"));
		goto fail;
	}
	cmd_bound = TRUE;

	if (ccount != 1) {
		SF_DEBUG(1, (sf, CE_WARN,
		    "Wrong cookie count for ELS\n"));
		goto fail;
	}

	if (ddi_dma_alloc_handle(sf->sf_dip, sf->sf_sochandle->fcal_dmaattr,
	    DDI_DMA_DONTWAIT, NULL, &rsp_dma_handle) != DDI_SUCCESS) {
		SF_DEBUG(1, (sf, CE_WARN,
		    "Could not allocate DMA handle for ELS rsp\n"));
		goto fail;
	}
	if (ddi_dma_mem_alloc(rsp_dma_handle, rsp_size,
	    sf->sf_sochandle->fcal_accattr, DDI_DMA_CONSISTENT,
	    DDI_DMA_DONTWAIT, NULL, &rsp,
	    &real_size, &rsp_acc_handle) != DDI_SUCCESS) {
		SF_DEBUG(1, (sf, CE_WARN,
		    "Could not allocate DMA memory for ELS rsp\n"));
		goto fail;
	}

	if (real_size < rsp_size) {
		SF_DEBUG(1, (sf, CE_WARN,
		    "DMA memory too small for ELS rsp\n"));
		goto fail;
	}

	if (ddi_dma_addr_bind_handle(rsp_dma_handle, NULL,
	    rsp, real_size, DDI_DMA_READ | DDI_DMA_CONSISTENT,
	    DDI_DMA_DONTWAIT, NULL, &rcookie, &ccount) != DDI_DMA_MAPPED) {
		SF_DEBUG(1, (sf, CE_WARN,
		    "Could not bind DMA memory for ELS rsp\n"));
		goto fail;
	}
	rsp_bound = TRUE;

	if (ccount != 1) {
		SF_DEBUG(1, (sf, CE_WARN,
		    "Wrong cookie count for ELS rsp\n"));
		goto fail;
	}

	privp->cmd = cmd;
	privp->sf = sf;
	privp->cmd_dma_handle = cmd_dma_handle;
	privp->cmd_acc_handle = cmd_acc_handle;
	privp->rsp = rsp;
	privp->rsp_dma_handle = rsp_dma_handle;
	privp->rsp_acc_handle = rsp_acc_handle;
	privp->dest_nport_id = dest_id;
	privp->fpkt = fpkt;

	fpkt->fcal_pkt_cookie = sf->sf_socp;
	fpkt->fcal_pkt_comp = sf_els_callback;
	fpkt->fcal_magic = FCALP_MAGIC;
	fpkt->fcal_pkt_flags = 0;
	fpkt->fcal_socal_request.sr_soc_hdr.sh_flags =
	    (ushort_t)(SOC_FC_HEADER | sf->sf_sochandle->fcal_portno);
	fpkt->fcal_socal_request.sr_soc_hdr.sh_class = 3;
	fpkt->fcal_socal_request.sr_soc_hdr.sh_seg_cnt = 2;
	fpkt->fcal_socal_request.sr_soc_hdr.sh_byte_cnt = cmd_size;
	fpkt->fcal_socal_request.sr_cqhdr.cq_hdr_count = 1;
	fpkt->fcal_socal_request.sr_cqhdr.cq_hdr_flags = 0;
	fpkt->fcal_socal_request.sr_cqhdr.cq_hdr_seqno = 0;
	fpkt->fcal_socal_request.sr_cqhdr.cq_hdr_type = CQ_TYPE_SIMPLE;
	fpkt->fcal_socal_request.sr_dataseg[0].fc_base = (uint32_t)
	    pcookie.dmac_address;
	fpkt->fcal_socal_request.sr_dataseg[0].fc_count = cmd_size;
	fpkt->fcal_socal_request.sr_dataseg[1].fc_base = (uint32_t)
	    rcookie.dmac_address;
	fpkt->fcal_socal_request.sr_dataseg[1].fc_count = rsp_size;

	/* Fill in the Fabric Channel Header */
	hp = &fpkt->fcal_socal_request.sr_fc_frame_hdr;
	hp->r_ctl = R_CTL_ELS_REQ;
	hp->d_id = dest_id;
	hp->s_id = sf->sf_al_pa;
	hp->type = TYPE_EXTENDED_LS;
	hp->reserved1 = 0;
	hp->f_ctl = F_CTL_SEQ_INITIATIVE | F_CTL_FIRST_SEQ;
	hp->seq_id = 0;
	hp->df_ctl  = 0;
	hp->seq_cnt = 0;
	hp->ox_id = 0xffff;
	hp->rx_id = 0xffff;
	hp->ro = 0;

	*rprivp = (caddr_t)privp;
	*cmd_buf = cmd;
	return (fpkt);

fail:
	if (cmd_dma_handle != NULL) {
		if (cmd_bound) {
			(void) ddi_dma_unbind_handle(cmd_dma_handle);
		}
		ddi_dma_free_handle(&cmd_dma_handle);
		privp->cmd_dma_handle = NULL;
	}
	if (rsp_dma_handle != NULL) {
		if (rsp_bound) {
			(void) ddi_dma_unbind_handle(rsp_dma_handle);
		}
		ddi_dma_free_handle(&rsp_dma_handle);
		privp->rsp_dma_handle = NULL;
	}
	sf_els_free(fpkt);
	return (NULL);
}


static void
sf_els_free(struct fcal_packet *fpkt)
{
	struct	sf_els_hdr	*privp = fpkt->fcal_pkt_private;

	if (privp != NULL) {
		if (privp->cmd_dma_handle != NULL) {
			(void) ddi_dma_unbind_handle(privp->cmd_dma_handle);
			ddi_dma_free_handle(&privp->cmd_dma_handle);
		}
		if (privp->cmd != NULL) {
			ddi_dma_mem_free(&privp->cmd_acc_handle);
		}

		if (privp->rsp_dma_handle != NULL) {
			(void) ddi_dma_unbind_handle(privp->rsp_dma_handle);
			ddi_dma_free_handle(&privp->rsp_dma_handle);
		}

		if (privp->rsp != NULL) {
			ddi_dma_mem_free(&privp->rsp_acc_handle);
		}
		if (privp->data_dma_handle) {
			(void) ddi_dma_unbind_handle(privp->data_dma_handle);
			ddi_dma_free_handle(&privp->data_dma_handle);
		}
		if (privp->data_buf) {
			ddi_dma_mem_free(&privp->data_acc_handle);
		}
		kmem_free(privp, privp->size);
	}
	kmem_free(fpkt, sizeof (struct fcal_packet));
}


static struct sf_target *
sf_create_target(struct sf *sf, struct sf_els_hdr *privp, int tnum, int64_t lun)
{
	struct sf_target *target, *ntarget, *otarget, *ptarget;
	int hash;
#ifdef RAID_LUNS
	int64_t orig_lun = lun;

	/* XXXX Work around SCSA limitations. */
	lun = *((short *)&lun);
#endif
	ntarget = kmem_zalloc(sizeof (struct sf_target), KM_NOSLEEP);
	mutex_enter(&sf->sf_mutex);
	if (sf->sf_lip_cnt != privp->lip_cnt) {
		mutex_exit(&sf->sf_mutex);
		if (ntarget != NULL)
			kmem_free(ntarget, sizeof (struct sf_target));
		return (NULL);
	}

	target = sf_lookup_target(sf, privp->port_wwn, lun);
	if (lun != 0) {
		/*
		 * Since LUNs != 0 are queued up after LUN == 0, find LUN == 0
		 * and enqueue the new LUN.
		 */
		if ((ptarget = sf_lookup_target(sf, privp->port_wwn,
		    (int64_t)0)) ==	NULL) {
			/*
			 * Yeep -- no LUN 0?
			 */
			mutex_exit(&sf->sf_mutex);
			sf_log(sf, CE_WARN, "target 0x%x "
			    "lun %" PRIx64 ": No LUN 0\n", tnum, lun);
			if (ntarget != NULL)
				kmem_free(ntarget, sizeof (struct sf_target));
			return (NULL);
		}
		mutex_enter(&ptarget->sft_mutex);
		if (target != NULL && ptarget->sft_lip_cnt == sf->sf_lip_cnt &&
		    ptarget->sft_state&SF_TARGET_OFFLINE) {
			/* LUN 0 already finished, duplicate its state */
			mutex_exit(&ptarget->sft_mutex);
			sf_offline_target(sf, target);
			mutex_exit(&sf->sf_mutex);
			if (ntarget != NULL)
				kmem_free(ntarget, sizeof (struct sf_target));
			return (target);
		} else if (target != NULL) {
			/*
			 * LUN 0 online or not examined yet.
			 * Try to bring the LUN back online
			 */
			mutex_exit(&ptarget->sft_mutex);
			mutex_enter(&target->sft_mutex);
			target->sft_lip_cnt = privp->lip_cnt;
			target->sft_state |= SF_TARGET_BUSY;
			target->sft_state &= ~(SF_TARGET_OFFLINE|
			    SF_TARGET_MARK);
			target->sft_al_pa = (uchar_t)privp->dest_nport_id;
			target->sft_hard_address = sf_switch_to_alpa[tnum];
			mutex_exit(&target->sft_mutex);
			mutex_exit(&sf->sf_mutex);
			if (ntarget != NULL)
				kmem_free(ntarget, sizeof (struct sf_target));
			return (target);
		}
		mutex_exit(&ptarget->sft_mutex);
		if (ntarget == NULL) {
			mutex_exit(&sf->sf_mutex);
			return (NULL);
		}
		/* Initialize new target structure */
		bcopy((caddr_t)&privp->node_wwn,
		    (caddr_t)&ntarget->sft_node_wwn, sizeof (privp->node_wwn));
		bcopy((caddr_t)&privp->port_wwn,
		    (caddr_t)&ntarget->sft_port_wwn, sizeof (privp->port_wwn));
		ntarget->sft_lun.l = lun;
#ifdef RAID_LUNS
		ntarget->sft_lun.l = orig_lun;
		ntarget->sft_raid_lun = (uint_t)lun;
#endif
		mutex_init(&ntarget->sft_mutex, NULL, MUTEX_DRIVER, NULL);
		mutex_init(&ntarget->sft_pkt_mutex, NULL, MUTEX_DRIVER, NULL);
		/* Don't let anyone use this till we finishup init. */
		mutex_enter(&ntarget->sft_mutex);
		mutex_enter(&ntarget->sft_pkt_mutex);

		hash = SF_HASH(privp->port_wwn, lun);
		ntarget->sft_next = sf->sf_wwn_lists[hash];
		sf->sf_wwn_lists[hash] = ntarget;

		ntarget->sft_lip_cnt = privp->lip_cnt;
		ntarget->sft_al_pa = (uchar_t)privp->dest_nport_id;
		ntarget->sft_hard_address = sf_switch_to_alpa[tnum];
		ntarget->sft_device_type = DTYPE_UNKNOWN;
		ntarget->sft_state = SF_TARGET_BUSY;
		ntarget->sft_pkt_head = (struct sf_pkt *)&ntarget->
		    sft_pkt_head;
		ntarget->sft_pkt_tail = (struct sf_pkt *)&ntarget->
		    sft_pkt_head;

		mutex_enter(&ptarget->sft_mutex);
		/* Traverse the list looking for this target */
		for (target = ptarget; target->sft_next_lun;
		    target = target->sft_next_lun) {
			otarget = target->sft_next_lun;
		}
		ntarget->sft_next_lun = target->sft_next_lun;
		target->sft_next_lun = ntarget;
		mutex_exit(&ptarget->sft_mutex);
		mutex_exit(&ntarget->sft_pkt_mutex);
		mutex_exit(&ntarget->sft_mutex);
		mutex_exit(&sf->sf_mutex);
		return (ntarget);

	}
	if (target != NULL && target->sft_lip_cnt == sf->sf_lip_cnt) {
		/* It's been touched this LIP -- duplicate WWNs */
		sf_offline_target(sf, target); /* And all the baby targets */
		mutex_exit(&sf->sf_mutex);
		sf_log(sf, CE_WARN, "target 0x%x, duplicate port wwns\n",
		    tnum);
		if (ntarget != NULL) {
			kmem_free(ntarget, sizeof (struct sf_target));
		}
		return (NULL);
	}

	if ((otarget = sf->sf_targets[tnum]) != NULL) {
		/* Someone else is in our slot */
		mutex_enter(&otarget->sft_mutex);
		if (otarget->sft_lip_cnt == sf->sf_lip_cnt) {
			mutex_exit(&otarget->sft_mutex);
			sf_offline_target(sf, otarget);
			if (target != NULL)
				sf_offline_target(sf, target);
			mutex_exit(&sf->sf_mutex);
			sf_log(sf, CE_WARN,
			    "target 0x%x, duplicate switch settings\n", tnum);
			if (ntarget != NULL)
				kmem_free(ntarget, sizeof (struct sf_target));
			return (NULL);
		}
		mutex_exit(&otarget->sft_mutex);
		if (bcmp((caddr_t)&privp->port_wwn, (caddr_t)&otarget->
		    sft_port_wwn, sizeof (privp->port_wwn))) {
			sf_offline_target(sf, otarget);
			mutex_exit(&sf->sf_mutex);
			sf_log(sf, CE_WARN, "wwn changed on target 0x%x\n",
			    tnum);
			bzero((caddr_t)&sf->sf_stats.tstats[tnum],
			    sizeof (struct sf_target_stats));
			mutex_enter(&sf->sf_mutex);
		}
	}

	sf->sf_targets[tnum] = target;
	if ((target = sf->sf_targets[tnum]) == NULL) {
		if (ntarget == NULL) {
			mutex_exit(&sf->sf_mutex);
			return (NULL);
		}
		bcopy((caddr_t)&privp->node_wwn,
		    (caddr_t)&ntarget->sft_node_wwn, sizeof (privp->node_wwn));
		bcopy((caddr_t)&privp->port_wwn,
		    (caddr_t)&ntarget->sft_port_wwn, sizeof (privp->port_wwn));
		ntarget->sft_lun.l = lun;
#ifdef RAID_LUNS
		ntarget->sft_lun.l = orig_lun;
		ntarget->sft_raid_lun = (uint_t)lun;
#endif
		mutex_init(&ntarget->sft_mutex, NULL, MUTEX_DRIVER, NULL);
		mutex_init(&ntarget->sft_pkt_mutex, NULL, MUTEX_DRIVER, NULL);
		mutex_enter(&ntarget->sft_mutex);
		mutex_enter(&ntarget->sft_pkt_mutex);
		hash = SF_HASH(privp->port_wwn, lun); /* lun 0 */
		ntarget->sft_next = sf->sf_wwn_lists[hash];
		sf->sf_wwn_lists[hash] = ntarget;

		target = ntarget;
		target->sft_lip_cnt = privp->lip_cnt;
		target->sft_al_pa = (uchar_t)privp->dest_nport_id;
		target->sft_hard_address = sf_switch_to_alpa[tnum];
		target->sft_device_type = DTYPE_UNKNOWN;
		target->sft_state = SF_TARGET_BUSY;
		target->sft_pkt_head = (struct sf_pkt *)&target->
		    sft_pkt_head;
		target->sft_pkt_tail = (struct sf_pkt *)&target->
		    sft_pkt_head;
		sf->sf_targets[tnum] = target;
		mutex_exit(&ntarget->sft_mutex);
		mutex_exit(&ntarget->sft_pkt_mutex);
		mutex_exit(&sf->sf_mutex);
	} else {
		mutex_enter(&target->sft_mutex);
		target->sft_lip_cnt = privp->lip_cnt;
		target->sft_state |= SF_TARGET_BUSY;
		target->sft_state &= ~(SF_TARGET_OFFLINE|SF_TARGET_MARK);
		target->sft_al_pa = (uchar_t)privp->dest_nport_id;
		target->sft_hard_address = sf_switch_to_alpa[tnum];
		mutex_exit(&target->sft_mutex);
		mutex_exit(&sf->sf_mutex);
		if (ntarget != NULL)
			kmem_free(ntarget, sizeof (struct sf_target));
	}
	return (target);
}


/*
 * find the target for a given sf instance
 */
/* ARGSUSED */
static struct sf_target *
#ifdef RAID_LUNS
sf_lookup_target(struct sf *sf, uchar_t *wwn, int lun)
#else
sf_lookup_target(struct sf *sf, uchar_t *wwn, int64_t lun)
#endif
{
	int hash;
	struct sf_target *target;

	ASSERT(mutex_owned(&sf->sf_mutex));
	hash = SF_HASH(wwn, lun);

	target = sf->sf_wwn_lists[hash];
	while (target != NULL) {

#ifndef	RAID_LUNS
		if (bcmp((caddr_t)wwn, (caddr_t)&target->sft_port_wwn,
		    sizeof (target->sft_port_wwn)) == 0 &&
			target->sft_lun.l == lun)
			break;
#else
		if (bcmp((caddr_t)wwn, (caddr_t)&target->sft_port_wwn,
		    sizeof (target->sft_port_wwn)) == 0 &&
			target->sft_raid_lun == lun)
			break;
#endif
		target = target->sft_next;
	}

	return (target);
}


/*
 * Send out a REPORT_LUNS command.
 */
static int
sf_do_reportlun(struct sf *sf, struct sf_els_hdr *privp,
    struct sf_target *target)
{
	struct	fcal_packet	*fpkt = privp->fpkt;
	ddi_dma_cookie_t	pcookie;
	ddi_dma_handle_t	lun_dma_handle = NULL;
	ddi_acc_handle_t	lun_acc_handle;
	uint_t			ccount;
	size_t			real_size;
	caddr_t			lun_buf = NULL;
	int			handle_bound = 0;
	fc_frame_header_t	*hp = &fpkt->fcal_socal_request.sr_fc_frame_hdr;
	struct fcp_cmd		*reportlun = (struct fcp_cmd *)privp->cmd;
	char			*msg = "Transport";

	if (ddi_dma_alloc_handle(sf->sf_dip, sf->sf_sochandle->fcal_dmaattr,
	    DDI_DMA_DONTWAIT, NULL, &lun_dma_handle) != DDI_SUCCESS) {
		msg = "ddi_dma_alloc_handle()";
		goto fail;
	}

	if (ddi_dma_mem_alloc(lun_dma_handle, REPORT_LUNS_SIZE,
	    sf->sf_sochandle->fcal_accattr, DDI_DMA_CONSISTENT,
	    DDI_DMA_DONTWAIT, NULL, &lun_buf,
	    &real_size, &lun_acc_handle) != DDI_SUCCESS) {
		msg = "ddi_dma_mem_alloc()";
		goto fail;
	}

	if (real_size < REPORT_LUNS_SIZE) {
		msg = "DMA mem < REPORT_LUNS_SIZE";
		goto fail;
	}

	if (ddi_dma_addr_bind_handle(lun_dma_handle, NULL,
	    lun_buf, real_size, DDI_DMA_READ |
	    DDI_DMA_CONSISTENT, DDI_DMA_DONTWAIT,
	    NULL, &pcookie, &ccount) != DDI_DMA_MAPPED) {
		msg = "ddi_dma_addr_bind_handle()";
		goto fail;
	}
	handle_bound = 1;

	if (ccount != 1) {
		msg = "ccount != 1";
		goto fail;
	}
	privp->els_code = 0;
	privp->target = target;
	privp->data_dma_handle = lun_dma_handle;
	privp->data_acc_handle = lun_acc_handle;
	privp->data_buf = lun_buf;

	fpkt->fcal_pkt_comp = sf_reportlun_callback;
	fpkt->fcal_socal_request.sr_soc_hdr.sh_seg_cnt = 3;
	fpkt->fcal_socal_request.sr_cqhdr.cq_hdr_type = CQ_TYPE_IO_READ;
	fpkt->fcal_socal_request.sr_dataseg[0].fc_count =
	    sizeof (struct fcp_cmd);
	fpkt->fcal_socal_request.sr_dataseg[2].fc_base =
	    (uint32_t)pcookie.dmac_address;
	fpkt->fcal_socal_request.sr_dataseg[2].fc_count = pcookie.dmac_size;
	fpkt->fcal_socal_request.sr_soc_hdr.sh_byte_cnt = pcookie.dmac_size;
	hp->r_ctl = R_CTL_COMMAND;
	hp->type = TYPE_SCSI_FCP;
	bzero((caddr_t)reportlun, sizeof (struct fcp_cmd));
	((union scsi_cdb *)reportlun->fcp_cdb)->scc_cmd = SCMD_REPORT_LUNS;
	/* Now set the buffer size.  If DDI gave us extra, that's O.K. */
	((union scsi_cdb *)reportlun->fcp_cdb)->scc5_count0 =
	    (real_size&0x0ff);
	((union scsi_cdb *)reportlun->fcp_cdb)->scc5_count1 =
	    (real_size>>8)&0x0ff;
	((union scsi_cdb *)reportlun->fcp_cdb)->scc5_count2 =
	    (real_size>>16)&0x0ff;
	((union scsi_cdb *)reportlun->fcp_cdb)->scc5_count3 =
	    (real_size>>24)&0x0ff;
	reportlun->fcp_cntl.cntl_read_data = 1;
	reportlun->fcp_cntl.cntl_write_data = 0;
	reportlun->fcp_data_len = pcookie.dmac_size;
	reportlun->fcp_cntl.cntl_qtype = FCP_QTYPE_SIMPLE;

	(void) ddi_dma_sync(lun_dma_handle, 0, 0, DDI_DMA_SYNC_FORDEV);
	/* We know he's there, so this should be fast */
	privp->timeout = sf_watchdog_time + SF_FCP_TIMEOUT;
	if (sf_els_transport(sf, privp) == 1)
		return (1);

fail:
	sf_log(sf, CE_WARN,
	    "%s failure for REPORTLUN to target 0x%x\n",
	    msg, sf_alpa_to_switch[privp->dest_nport_id]);
	sf_els_free(fpkt);
	if (lun_dma_handle != NULL) {
		if (handle_bound)
			(void) ddi_dma_unbind_handle(lun_dma_handle);
		ddi_dma_free_handle(&lun_dma_handle);
	}
	if (lun_buf != NULL) {
		ddi_dma_mem_free(&lun_acc_handle);
	}
	return (0);
}

/*
 * Handle the results of a REPORT_LUNS command:
 *	Create additional targets if necessary
 *	Initiate INQUIRYs on all LUNs.
 */
static void
sf_reportlun_callback(struct fcal_packet *fpkt)
{
	struct sf_els_hdr *privp = (struct sf_els_hdr *)fpkt->
	    fcal_pkt_private;
	struct scsi_report_luns *ptr =
	    (struct scsi_report_luns *)privp->data_buf;
	struct sf *sf = privp->sf;
	struct sf_target *target = privp->target;
	struct fcp_rsp *rsp = NULL;
	int delayed_retry = 0;
	int tid = sf_alpa_to_switch[target->sft_hard_address];
	int i, free_pkt = 1;
	short	ncmds;

	mutex_enter(&sf->sf_mutex);
	/* use as temporary state variable */
	if (privp->timeout == SF_INVALID_TIMEOUT) {
		mutex_exit(&sf->sf_mutex);
		return;
	}
	if (privp->prev)
		privp->prev->next = privp->next;
	if (privp->next)
		privp->next->prev = privp->prev;
	if (sf->sf_els_list == privp)
		sf->sf_els_list = privp->next;
	privp->prev = privp->next = NULL;
	mutex_exit(&sf->sf_mutex);
	ncmds = fpkt->fcal_ncmds;
	ASSERT(ncmds >= 0);
	mutex_enter(&sf->sf_cmd_mutex);
	sf->sf_ncmds = ncmds;
	mutex_exit(&sf->sf_cmd_mutex);

	if (fpkt->fcal_pkt_status == FCAL_STATUS_OK) {
		(void) ddi_dma_sync(privp->rsp_dma_handle, 0,
		    0, DDI_DMA_SYNC_FORKERNEL);

		rsp = (struct fcp_rsp *)privp->rsp;
	}
	SF_DEBUG(1, (sf, CE_CONT,
	    "!REPORTLUN to al_pa %x pkt status %x scsi status %x\n",
	    privp->dest_nport_id,
	    fpkt->fcal_pkt_status,
	    rsp?rsp->fcp_u.fcp_status.scsi_status:0));

		/* See if target simply does not support REPORT_LUNS. */
	if (rsp && rsp->fcp_u.fcp_status.scsi_status == STATUS_CHECK &&
	    rsp->fcp_u.fcp_status.sense_len_set &&
	    rsp->fcp_sense_len >=
		offsetof(struct scsi_extended_sense, es_qual_code)) {
			struct scsi_extended_sense *sense;
			sense = (struct scsi_extended_sense *)
			((caddr_t)rsp + sizeof (struct fcp_rsp)
				+ rsp->fcp_response_len);
			if (sense->es_key == KEY_ILLEGAL_REQUEST) {
				if (sense->es_add_code == 0x20) {
					/* Fake LUN 0 */
				SF_DEBUG(1, (sf, CE_CONT,
					"!REPORTLUN Faking good "
					"completion for alpa %x\n",
					privp->dest_nport_id));
					ptr->lun_list_len = FCP_LUN_SIZE;
					ptr->lun[0] = 0;
					rsp->fcp_u.fcp_status.scsi_status =
						STATUS_GOOD;
				} else if (sense->es_add_code == 0x25) {
					SF_DEBUG(1, (sf, CE_CONT,
					    "!REPORTLUN device alpa %x "
					    "key %x code %x\n",
					    privp->dest_nport_id,
					    sense->es_key, sense->es_add_code));
					    goto fail;
				}
			} else if (sense->es_key ==
				KEY_UNIT_ATTENTION &&
				sense->es_add_code == 0x29) {
				SF_DEBUG(1, (sf, CE_CONT,
					"!REPORTLUN device alpa %x was reset\n",
					privp->dest_nport_id));
			} else {
				SF_DEBUG(1, (sf, CE_CONT,
					"!REPORTLUN device alpa %x "
					"key %x code %x\n",
					privp->dest_nport_id,
					sense->es_key, sense->es_add_code));
/* XXXXXX The following is here to handle broken targets -- remove it later */
				if (sf_reportlun_forever &&
					sense->es_key == KEY_UNIT_ATTENTION)
					goto retry;
/* XXXXXX */
				if (sense->es_key == KEY_NOT_READY)
					delayed_retry = 1;
				}
		}

	if (rsp && rsp->fcp_u.fcp_status.scsi_status == STATUS_GOOD) {
		struct fcp_rsp_info *bep;

		bep = (struct fcp_rsp_info *)(&rsp->
		    fcp_response_len + 1);
		if (!rsp->fcp_u.fcp_status.rsp_len_set ||
		    bep->rsp_code == FCP_NO_FAILURE) {
			(void) ddi_dma_sync(privp->data_dma_handle,
			    0, 0, DDI_DMA_SYNC_FORKERNEL);

			/* Convert from #bytes to #ints */
			ptr->lun_list_len = ptr->lun_list_len >> 3;
			SF_DEBUG(2, (sf, CE_CONT,
			    "!REPORTLUN to al_pa %x succeeded: %d LUNs\n",
			    privp->dest_nport_id, ptr->lun_list_len));
			if (!ptr->lun_list_len) {
				/* No LUNs? Ya gotta be kidding... */
				sf_log(sf, CE_WARN,
				    "SCSI violation -- "
				    "target 0x%x reports no LUNs\n",
				    sf_alpa_to_switch[
				    privp->dest_nport_id]);
				ptr->lun_list_len = 1;
				ptr->lun[0] = 0;
			}

			mutex_enter(&sf->sf_mutex);
			if (sf->sf_lip_cnt == privp->lip_cnt) {
				sf->sf_device_count += ptr->lun_list_len - 1;
			}

			mutex_exit(&sf->sf_mutex);
			for (i = 0; i < ptr->lun_list_len && privp->lip_cnt ==
			    sf->sf_lip_cnt; i++) {
				struct sf_els_hdr *nprivp;
				struct fcal_packet *nfpkt;

				/* LUN 0 is already in `target' */
				if (ptr->lun[i] != 0) {
					target = sf_create_target(sf,
					    privp, tid, ptr->lun[i]);
				}
				nprivp = NULL;
				nfpkt = NULL;
				if (target) {
					nfpkt = sf_els_alloc(sf,
					    target->sft_al_pa,
					    sizeof (struct sf_els_hdr),
					    sizeof (union sf_els_cmd),
					    sizeof (union sf_els_rsp),
					    (caddr_t *)&nprivp,
					    (caddr_t *)&rsp);
					if (nprivp)
						nprivp->lip_cnt =
						    privp->lip_cnt;
				}
				if (nfpkt && nprivp &&
				    (sf_do_inquiry(sf, nprivp, target) ==
				    0)) {
					mutex_enter(&sf->sf_mutex);
					if (sf->sf_lip_cnt == privp->
					    lip_cnt) {
						sf->sf_device_count --;
					}
					sf_offline_target(sf, target);
					mutex_exit(&sf->sf_mutex);
				}
			}
			sf_els_free(fpkt);
			return;
		} else {
			SF_DEBUG(1, (sf, CE_CONT,
			    "!REPORTLUN al_pa %x fcp failure, "
			    "fcp_rsp_code %x scsi status %x\n",
			    privp->dest_nport_id, bep->rsp_code,
			    rsp ? rsp->fcp_u.fcp_status.scsi_status:0));
			goto fail;
		}
	}
	if (rsp && ((rsp->fcp_u.fcp_status.scsi_status == STATUS_BUSY) ||
	    (rsp->fcp_u.fcp_status.scsi_status == STATUS_QFULL))) {
		delayed_retry = 1;
	}

	if (++(privp->retries) < sf_els_retries ||
	    (delayed_retry && privp->retries < SF_BSY_RETRIES)) {
/* XXXXXX The following is here to handle broken targets -- remove it later */
retry:
/* XXXXXX */
		if (delayed_retry) {
			privp->retries--;
			privp->timeout = sf_watchdog_time + SF_BSY_TIMEOUT;
			privp->delayed_retry = 1;
		} else {
			privp->timeout = sf_watchdog_time + SF_FCP_TIMEOUT;
		}

		privp->prev = NULL;
		mutex_enter(&sf->sf_mutex);
		if (privp->lip_cnt == sf->sf_lip_cnt) {
			if (!delayed_retry)
				SF_DEBUG(1, (sf, CE_WARN,
				    "!REPORTLUN to al_pa %x failed, retrying\n",
				    privp->dest_nport_id));
			privp->next = sf->sf_els_list;
			if (sf->sf_els_list != NULL)
				sf->sf_els_list->prev = privp;
			sf->sf_els_list = privp;
			mutex_exit(&sf->sf_mutex);
			if (!delayed_retry && soc_transport(sf->sf_sochandle,
			    fpkt, FCAL_NOSLEEP, CQ_REQUEST_1) !=
			    FCAL_TRANSPORT_SUCCESS) {
				mutex_enter(&sf->sf_mutex);
				if (privp->prev)
					privp->prev->next = privp->next;
				if (privp->next)
					privp->next->prev = privp->prev;
				if (sf->sf_els_list == privp)
					sf->sf_els_list = privp->next;
				mutex_exit(&sf->sf_mutex);
				goto fail;
			} else
				return;
		} else {
			mutex_exit(&sf->sf_mutex);
		}
	} else {
fail:

		/* REPORT_LUN failed -- try inquiry */
		if (sf_do_inquiry(sf, privp, target) != 0) {
			return;
		} else {
			free_pkt = 0;
		}
		mutex_enter(&sf->sf_mutex);
		if (sf->sf_lip_cnt == privp->lip_cnt) {
			sf_log(sf, CE_WARN,
			    "!REPORTLUN to target 0x%x failed\n",
			    sf_alpa_to_switch[privp->dest_nport_id]);
			sf_offline_target(sf, target);
			sf->sf_device_count--;
			ASSERT(sf->sf_device_count >= 0);
			if (sf->sf_device_count == 0)
			sf_finish_init(sf, privp->lip_cnt);
		}
		mutex_exit(&sf->sf_mutex);
	}
	if (free_pkt) {
		sf_els_free(fpkt);
	}
}

static int
sf_do_inquiry(struct sf *sf, struct sf_els_hdr *privp,
    struct sf_target *target)
{
	struct	fcal_packet	*fpkt = privp->fpkt;
	ddi_dma_cookie_t	pcookie;
	ddi_dma_handle_t	inq_dma_handle = NULL;
	ddi_acc_handle_t	inq_acc_handle;
	uint_t			ccount;
	size_t			real_size;
	caddr_t			inq_buf = NULL;
	int			handle_bound = FALSE;
	fc_frame_header_t *hp = &fpkt->fcal_socal_request.sr_fc_frame_hdr;
	struct fcp_cmd		*inq = (struct fcp_cmd *)privp->cmd;
	char			*msg = "Transport";


	if (ddi_dma_alloc_handle(sf->sf_dip, sf->sf_sochandle->fcal_dmaattr,
	    DDI_DMA_DONTWAIT, NULL, &inq_dma_handle) != DDI_SUCCESS) {
		msg = "ddi_dma_alloc_handle()";
		goto fail;
	}

	if (ddi_dma_mem_alloc(inq_dma_handle, SUN_INQSIZE,
	    sf->sf_sochandle->fcal_accattr, DDI_DMA_CONSISTENT,
	    DDI_DMA_DONTWAIT, NULL, &inq_buf,
	    &real_size, &inq_acc_handle) != DDI_SUCCESS) {
		msg = "ddi_dma_mem_alloc()";
		goto fail;
	}

	if (real_size < SUN_INQSIZE) {
		msg = "DMA mem < inquiry size";
		goto fail;
	}

	if (ddi_dma_addr_bind_handle(inq_dma_handle, NULL,
	    inq_buf, real_size, DDI_DMA_READ | DDI_DMA_CONSISTENT,
	    DDI_DMA_DONTWAIT, NULL, &pcookie, &ccount) != DDI_DMA_MAPPED) {
		msg = "ddi_dma_addr_bind_handle()";
		goto fail;
	}
	handle_bound = TRUE;

	if (ccount != 1) {
		msg = "ccount != 1";
		goto fail;
	}
	privp->els_code = 0;			/* not an ELS command */
	privp->target = target;
	privp->data_dma_handle = inq_dma_handle;
	privp->data_acc_handle = inq_acc_handle;
	privp->data_buf = inq_buf;
	fpkt->fcal_pkt_comp = sf_inq_callback;
	fpkt->fcal_socal_request.sr_soc_hdr.sh_seg_cnt = 3;
	fpkt->fcal_socal_request.sr_cqhdr.cq_hdr_type = CQ_TYPE_IO_READ;
	fpkt->fcal_socal_request.sr_dataseg[0].fc_count =
	    sizeof (struct fcp_cmd);
	fpkt->fcal_socal_request.sr_dataseg[2].fc_base =
	    (uint32_t)pcookie.dmac_address;
	fpkt->fcal_socal_request.sr_dataseg[2].fc_count = pcookie.dmac_size;
	fpkt->fcal_socal_request.sr_soc_hdr.sh_byte_cnt = pcookie.dmac_size;
	hp->r_ctl = R_CTL_COMMAND;
	hp->type = TYPE_SCSI_FCP;
	bzero((caddr_t)inq, sizeof (struct fcp_cmd));
	((union scsi_cdb *)inq->fcp_cdb)->scc_cmd = SCMD_INQUIRY;
	((union scsi_cdb *)inq->fcp_cdb)->g0_count0 = SUN_INQSIZE;
	bcopy((caddr_t)&target->sft_lun.b, (caddr_t)&inq->fcp_ent_addr,
	    FCP_LUN_SIZE);
	inq->fcp_cntl.cntl_read_data = 1;
	inq->fcp_cntl.cntl_write_data = 0;
	inq->fcp_data_len = pcookie.dmac_size;
	inq->fcp_cntl.cntl_qtype = FCP_QTYPE_SIMPLE;

	(void) ddi_dma_sync(inq_dma_handle, (off_t)0, (size_t)0,
	    DDI_DMA_SYNC_FORDEV);
	privp->timeout = sf_watchdog_time + SF_FCP_TIMEOUT;
	SF_DEBUG(5, (sf, CE_WARN,
	    "!Sending INQUIRY to al_pa %x lun %" PRIx64 "\n",
	    privp->dest_nport_id,
	    SCSA_LUN(target)));
	return (sf_els_transport(sf, privp));

fail:
	sf_log(sf, CE_WARN,
	    "%s failure for INQUIRY to target 0x%x\n",
	    msg, sf_alpa_to_switch[privp->dest_nport_id]);
	sf_els_free(fpkt);
	if (inq_dma_handle != NULL) {
		if (handle_bound) {
			(void) ddi_dma_unbind_handle(inq_dma_handle);
		}
		ddi_dma_free_handle(&inq_dma_handle);
	}
	if (inq_buf != NULL) {
		ddi_dma_mem_free(&inq_acc_handle);
	}
	return (FALSE);
}


/*
 * called as the pkt_comp routine for INQ packets
 */
static void
sf_inq_callback(struct fcal_packet *fpkt)
{
	struct sf_els_hdr *privp = (struct sf_els_hdr *)fpkt->
	    fcal_pkt_private;
	struct scsi_inquiry *prt = (struct scsi_inquiry *)privp->data_buf;
	struct sf *sf = privp->sf;
	struct sf *tsf;
	struct sf_target *target = privp->target;
	struct fcp_rsp *rsp;
	int delayed_retry = FALSE;
	short	ncmds;


	mutex_enter(&sf->sf_mutex);
	/* use as temporary state variable */
	if (privp->timeout == SF_INVALID_TIMEOUT) {
		mutex_exit(&sf->sf_mutex);
		return;
	}
	if (privp->prev != NULL) {
		privp->prev->next = privp->next;
	}
	if (privp->next != NULL) {
		privp->next->prev = privp->prev;
	}
	if (sf->sf_els_list == privp) {
		sf->sf_els_list = privp->next;
	}
	privp->prev = privp->next = NULL;
	mutex_exit(&sf->sf_mutex);
	ncmds = fpkt->fcal_ncmds;
	ASSERT(ncmds >= 0);
	mutex_enter(&sf->sf_cmd_mutex);
	sf->sf_ncmds = ncmds;
	mutex_exit(&sf->sf_cmd_mutex);

	if (fpkt->fcal_pkt_status == FCAL_STATUS_OK) {

		(void) ddi_dma_sync(privp->rsp_dma_handle, (off_t)0,
		    (size_t)0, DDI_DMA_SYNC_FORKERNEL);

		rsp = (struct fcp_rsp *)privp->rsp;
		SF_DEBUG(2, (sf, CE_CONT,
		    "!INQUIRY to al_pa %x scsi status %x",
		    privp->dest_nport_id, rsp->fcp_u.fcp_status.scsi_status));

		if ((rsp->fcp_u.fcp_status.scsi_status == STATUS_GOOD) &&
		    !rsp->fcp_u.fcp_status.resid_over &&
		    (!rsp->fcp_u.fcp_status.resid_under ||
		    ((SUN_INQSIZE - rsp->fcp_resid) >= SUN_MIN_INQLEN))) {
			struct fcp_rsp_info *bep;

			bep = (struct fcp_rsp_info *)(&rsp->
			    fcp_response_len + 1);

			if (!rsp->fcp_u.fcp_status.rsp_len_set ||
			    (bep->rsp_code == FCP_NO_FAILURE)) {

				SF_DEBUG(2, (sf, CE_CONT,
				    "!INQUIRY to al_pa %x lun %" PRIx64
				    " succeeded\n",
				    privp->dest_nport_id, SCSA_LUN(target)));

				(void) ddi_dma_sync(privp->data_dma_handle,
				    (off_t)0, (size_t)0,
				    DDI_DMA_SYNC_FORKERNEL);

				mutex_enter(&sf->sf_mutex);

				if (sf->sf_lip_cnt == privp->lip_cnt) {
					mutex_enter(&target->sft_mutex);
					target->sft_device_type =
					    prt->inq_dtype;
					bcopy(prt, &target->sft_inq,
					    sizeof (*prt));
					mutex_exit(&target->sft_mutex);
					sf->sf_device_count--;
					ASSERT(sf->sf_device_count >= 0);
					if (sf->sf_device_count == 0) {
						sf_finish_init(sf,
						    privp->lip_cnt);
					}
				}
				mutex_exit(&sf->sf_mutex);
				sf_els_free(fpkt);
				return;
			}
		} else if ((rsp->fcp_u.fcp_status.scsi_status ==
		    STATUS_BUSY) ||
		    (rsp->fcp_u.fcp_status.scsi_status == STATUS_QFULL) ||
		    (rsp->fcp_u.fcp_status.scsi_status == STATUS_CHECK)) {
			delayed_retry = TRUE;
		}
	} else {
		SF_DEBUG(2, (sf, CE_CONT, "!INQUIRY to al_pa %x fc status %x",
		    privp->dest_nport_id, fpkt->fcal_pkt_status));
	}

	if (++(privp->retries) < sf_els_retries ||
	    (delayed_retry && privp->retries < SF_BSY_RETRIES)) {
		if (fpkt->fcal_pkt_status == FCAL_STATUS_MAX_XCHG_EXCEEDED)  {
			tsf = sf->sf_sibling;
			if (tsf != NULL) {
				mutex_enter(&tsf->sf_cmd_mutex);
				tsf->sf_flag = 1;
				tsf->sf_throttle = SF_DECR_DELTA;
				mutex_exit(&tsf->sf_cmd_mutex);
			}
			delayed_retry = 1;
		}
		if (delayed_retry) {
			privp->retries--;
			privp->timeout = sf_watchdog_time + SF_BSY_TIMEOUT;
			privp->delayed_retry = TRUE;
		} else {
			privp->timeout = sf_watchdog_time + SF_FCP_TIMEOUT;
		}

		privp->prev = NULL;
		mutex_enter(&sf->sf_mutex);
		if (privp->lip_cnt == sf->sf_lip_cnt) {
			if (!delayed_retry) {
				SF_DEBUG(1, (sf, CE_WARN,
				    "INQUIRY to al_pa %x failed, retrying",
				    privp->dest_nport_id));
			}
			privp->next = sf->sf_els_list;
			if (sf->sf_els_list != NULL) {
				sf->sf_els_list->prev = privp;
			}
			sf->sf_els_list = privp;
			mutex_exit(&sf->sf_mutex);
			/* if not delayed call transport to send a pkt */
			if (!delayed_retry &&
			    (soc_transport(sf->sf_sochandle, fpkt,
			    FCAL_NOSLEEP, CQ_REQUEST_1) !=
			    FCAL_TRANSPORT_SUCCESS)) {
				mutex_enter(&sf->sf_mutex);
				if (privp->prev != NULL) {
					privp->prev->next = privp->next;
				}
				if (privp->next != NULL) {
					privp->next->prev = privp->prev;
				}
				if (sf->sf_els_list == privp) {
					sf->sf_els_list = privp->next;
				}
				mutex_exit(&sf->sf_mutex);
				goto fail;
			}
			return;
		}
		mutex_exit(&sf->sf_mutex);
	} else {
fail:
		mutex_enter(&sf->sf_mutex);
		if (sf->sf_lip_cnt == privp->lip_cnt) {
			sf_offline_target(sf, target);
			sf_log(sf, CE_NOTE,
			    "INQUIRY to target 0x%x lun %" PRIx64 " failed. "
			    "Retry Count: %d\n",
			    sf_alpa_to_switch[privp->dest_nport_id],
			    SCSA_LUN(target),
			    privp->retries);
			sf->sf_device_count--;
			ASSERT(sf->sf_device_count >= 0);
			if (sf->sf_device_count == 0) {
				sf_finish_init(sf, privp->lip_cnt);
			}
		}
		mutex_exit(&sf->sf_mutex);
	}
	sf_els_free(fpkt);
}


static void
sf_finish_init(struct sf *sf, int lip_cnt)
{
	int			i;		/* loop index */
	int			cflag;
	struct sf_target	*target;	/* current target */
	dev_info_t		*dip;
	struct sf_hp_elem	*elem;		/* hotplug element created */

	SF_DEBUG(1, (sf, CE_WARN, "!sf_finish_init\n"));
	ASSERT(mutex_owned(&sf->sf_mutex));

	/* scan all hash queues */
	for (i = 0; i < SF_NUM_HASH_QUEUES; i++) {
		target = sf->sf_wwn_lists[i];
		while (target != NULL) {
			mutex_enter(&target->sft_mutex);

			/* see if target is not offline */
			if ((target->sft_state & SF_TARGET_OFFLINE)) {
				/*
				 * target already offline
				 */
				mutex_exit(&target->sft_mutex);
				goto next_entry;
			}

			/*
			 * target is not already offline -- see if it has
			 * already been marked as ready to go offline
			 */
			if (target->sft_state & SF_TARGET_MARK) {
				/*
				 * target already marked, so take it offline
				 */
				mutex_exit(&target->sft_mutex);
				sf_offline_target(sf, target);
				goto next_entry;
			}

			/* clear target busy flag */
			target->sft_state &= ~SF_TARGET_BUSY;

			/* is target init not yet done ?? */
			cflag = !(target->sft_state & SF_TARGET_INIT_DONE);

			/* get pointer to target dip */
			dip = target->sft_dip;

			mutex_exit(&target->sft_mutex);
			mutex_exit(&sf->sf_mutex);

			if (cflag && (dip == NULL)) {
				/*
				 * target init not yet done &&
				 * devinfo not yet created
				 */
				sf_create_devinfo(sf, target, lip_cnt);
				mutex_enter(&sf->sf_mutex);
				goto next_entry;
			}

			/*
			 * target init already done || devinfo already created
			 */
			ASSERT(dip != NULL);
			if (!sf_create_props(dip, target, lip_cnt)) {
				/* a problem creating properties */
				mutex_enter(&sf->sf_mutex);
				goto next_entry;
			}

			/* create a new element for the hotplug list */
			if ((elem = kmem_zalloc(sizeof (struct sf_hp_elem),
			    KM_NOSLEEP)) != NULL) {

				/* fill in the new element */
				elem->dip = dip;
				elem->target = target;
				elem->what = SF_ONLINE;

				/* add the new element into the hotplug list */
				mutex_enter(&sf->sf_hp_daemon_mutex);
				if (sf->sf_hp_elem_tail != NULL) {
					sf->sf_hp_elem_tail->next = elem;
					sf->sf_hp_elem_tail = elem;
				} else {
					/* this is the first element in list */
					sf->sf_hp_elem_head =
					    sf->sf_hp_elem_tail =
					    elem;
				}
				cv_signal(&sf->sf_hp_daemon_cv);
				mutex_exit(&sf->sf_hp_daemon_mutex);
			} else {
				/* could not allocate memory for element ?? */
				(void) ndi_devi_online_async(dip, 0);
			}

			mutex_enter(&sf->sf_mutex);

next_entry:
			/* ensure no new LIPs have occurred */
			if (sf->sf_lip_cnt != lip_cnt) {
				return;
			}
			target = target->sft_next;
		}

		/* done scanning all targets in this queue */
	}

	/* done with all hash queues */

	sf->sf_state = SF_STATE_ONLINE;
	sf->sf_online_timer = 0;
}


/*
 * create devinfo node
 */
static void
sf_create_devinfo(struct sf *sf, struct sf_target *target, int lip_cnt)
{
	dev_info_t		*cdip = NULL;
	char			*nname = NULL;
	char			**compatible = NULL;
	int			ncompatible;
	struct scsi_inquiry	*inq = &target->sft_inq;
	char			*scsi_binding_set;

	/* get the 'scsi-binding-set' property */
	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, sf->sf_dip,
	    DDI_PROP_NOTPROM | DDI_PROP_DONTPASS, "scsi-binding-set",
	    &scsi_binding_set) != DDI_PROP_SUCCESS)
		scsi_binding_set = NULL;

	/* determine the node name and compatible */
	scsi_hba_nodename_compatible_get(inq, scsi_binding_set,
	    inq->inq_dtype, NULL, &nname, &compatible, &ncompatible);
	if (scsi_binding_set)
		ddi_prop_free(scsi_binding_set);

	/* if nodename can't be determined then print a message and skip it */
	if (nname == NULL) {
#ifndef	RAID_LUNS
		sf_log(sf, CE_WARN, "%s%d: no driver for device "
		    "@w%02x%02x%02x%02x%02x%02x%02x%02x,%x\n"
		    "    compatible: %s",
		    ddi_driver_name(sf->sf_dip), ddi_get_instance(sf->sf_dip),
		    target->sft_port_wwn[0], target->sft_port_wwn[1],
		    target->sft_port_wwn[2], target->sft_port_wwn[3],
		    target->sft_port_wwn[4], target->sft_port_wwn[5],
		    target->sft_port_wwn[6], target->sft_port_wwn[7],
		    target->sft_lun.l, *compatible);
#else
		sf_log(sf, CE_WARN, "%s%d: no driver for device "
		    "@w%02x%02x%02x%02x%02x%02x%02x%02x,%x\n"
		    "    compatible: %s",
		    ddi_driver_name(sf->sf_dip), ddi_get_instance(sf->sf_dip),
		    target->sft_port_wwn[0], target->sft_port_wwn[1],
		    target->sft_port_wwn[2], target->sft_port_wwn[3],
		    target->sft_port_wwn[4], target->sft_port_wwn[5],
		    target->sft_port_wwn[6], target->sft_port_wwn[7],
		    target->sft_raid_lun, *compatible);
#endif
		goto fail;
	}

	/* allocate the node */
	if (ndi_devi_alloc(sf->sf_dip, nname,
	    DEVI_SID_NODEID, &cdip) != NDI_SUCCESS) {
		goto fail;
	}

	/* decorate the node with compatible */
	if (ndi_prop_update_string_array(DDI_DEV_T_NONE, cdip,
	    "compatible", compatible, ncompatible) != DDI_PROP_SUCCESS) {
		goto fail;
	}

	/* add addressing properties to the node */
	if (sf_create_props(cdip, target, lip_cnt) != 1) {
		goto fail;
	}

	mutex_enter(&target->sft_mutex);
	if (target->sft_dip != NULL) {
		mutex_exit(&target->sft_mutex);
		goto fail;
	}
	target->sft_dip = cdip;
	mutex_exit(&target->sft_mutex);

	if (ndi_devi_online_async(cdip, 0) != DDI_SUCCESS) {
		goto fail;
	}

	scsi_hba_nodename_compatible_free(nname, compatible);
	return;

fail:
	scsi_hba_nodename_compatible_free(nname, compatible);
	if (cdip != NULL) {
		(void) ndi_prop_remove(DDI_DEV_T_NONE, cdip, NODE_WWN_PROP);
		(void) ndi_prop_remove(DDI_DEV_T_NONE, cdip, PORT_WWN_PROP);
		(void) ndi_prop_remove(DDI_DEV_T_NONE, cdip, LIP_CNT_PROP);
		(void) ndi_prop_remove(DDI_DEV_T_NONE, cdip, TARGET_PROP);
		(void) ndi_prop_remove(DDI_DEV_T_NONE, cdip, LUN_PROP);
		if (ndi_devi_free(cdip) != NDI_SUCCESS) {
			sf_log(sf, CE_WARN, "ndi_devi_free failed\n");
		} else {
			mutex_enter(&target->sft_mutex);
			if (cdip == target->sft_dip) {
				target->sft_dip = NULL;
			}
			mutex_exit(&target->sft_mutex);
		}
	}
}

/*
 * create required properties, returning TRUE iff we succeed, else
 * returning FALSE
 */
static int
sf_create_props(dev_info_t *cdip, struct sf_target *target, int lip_cnt)
{
	int tgt_id = sf_alpa_to_switch[target->sft_al_pa];


	if (ndi_prop_update_byte_array(DDI_DEV_T_NONE,
	    cdip, NODE_WWN_PROP, target->sft_node_wwn, FC_WWN_SIZE) !=
	    DDI_PROP_SUCCESS) {
		return (FALSE);
	}

	if (ndi_prop_update_byte_array(DDI_DEV_T_NONE,
	    cdip, PORT_WWN_PROP, target->sft_port_wwn, FC_WWN_SIZE) !=
	    DDI_PROP_SUCCESS) {
		return (FALSE);
	}

	if (ndi_prop_update_int(DDI_DEV_T_NONE,
	    cdip, LIP_CNT_PROP, lip_cnt) != DDI_PROP_SUCCESS) {
		return (FALSE);
	}

	if (ndi_prop_update_int(DDI_DEV_T_NONE,
	    cdip, TARGET_PROP, tgt_id) != DDI_PROP_SUCCESS) {
		return (FALSE);
	}

#ifndef	RAID_LUNS
	if (ndi_prop_update_int(DDI_DEV_T_NONE,
	    cdip, LUN_PROP, target->sft_lun.l) != DDI_PROP_SUCCESS) {
		return (0);
	}
#else
	if (ndi_prop_update_int(DDI_DEV_T_NONE,
	    cdip, LUN_PROP, target->sft_raid_lun) != DDI_PROP_SUCCESS) {
		return (0);
	}
#endif

	return (TRUE);
}


/*
 * called by the transport to offline a target
 */
/* ARGSUSED */
static void
sf_offline_target(struct sf *sf, struct sf_target *target)
{
	dev_info_t *dip;
	struct sf_target *next_target = NULL;
	struct sf_hp_elem	*elem;

	ASSERT(mutex_owned(&sf->sf_mutex));

	if (sf_core && (sf_core & SF_CORE_OFFLINE_TARGET)) {
		(void) soc_take_core(sf->sf_sochandle, sf->sf_socp);
		sf_core = 0;
	}

	while (target != NULL) {
		sf_log(sf, CE_NOTE,
		    "!target 0x%x al_pa 0x%x lun %" PRIx64 " offlined\n",
		    sf_alpa_to_switch[target->sft_al_pa],
		    target->sft_al_pa, SCSA_LUN(target));
		mutex_enter(&target->sft_mutex);
		target->sft_state &= ~(SF_TARGET_BUSY|SF_TARGET_MARK);
		target->sft_state |= SF_TARGET_OFFLINE;
		mutex_exit(&target->sft_mutex);
		mutex_exit(&sf->sf_mutex);

		/* XXXX if this is LUN 0, offline all other LUNs */
		if (next_target || target->sft_lun.l == 0)
			next_target = target->sft_next_lun;

		/* abort all cmds for this target */
		sf_abort_all(sf, target, FALSE, sf->sf_lip_cnt, FALSE);

		mutex_enter(&sf->sf_mutex);
		mutex_enter(&target->sft_mutex);
		if (target->sft_state & SF_TARGET_INIT_DONE) {
			dip = target->sft_dip;
			mutex_exit(&target->sft_mutex);
			mutex_exit(&sf->sf_mutex);
			(void) ndi_prop_remove(DDI_DEV_T_NONE, dip,
			    TARGET_PROP);
			(void) ndi_event_retrieve_cookie(sf->sf_event_hdl,
			    dip, FCAL_REMOVE_EVENT, &sf_remove_eid,
			    NDI_EVENT_NOPASS);
			(void) ndi_event_run_callbacks(sf->sf_event_hdl,
			    target->sft_dip, sf_remove_eid, NULL);

			elem = kmem_zalloc(sizeof (struct sf_hp_elem),
			    KM_NOSLEEP);
			if (elem != NULL) {
				elem->dip = dip;
				elem->target = target;
				elem->what = SF_OFFLINE;
				mutex_enter(&sf->sf_hp_daemon_mutex);
				if (sf->sf_hp_elem_tail != NULL) {
					sf->sf_hp_elem_tail->next = elem;
					sf->sf_hp_elem_tail = elem;
				} else {
					sf->sf_hp_elem_head =
					    sf->sf_hp_elem_tail =
					    elem;
				}
				cv_signal(&sf->sf_hp_daemon_cv);
				mutex_exit(&sf->sf_hp_daemon_mutex);
			} else {
				/* don't do NDI_DEVI_REMOVE for now */
				if (ndi_devi_offline(dip, 0) != NDI_SUCCESS) {
					SF_DEBUG(1, (sf, CE_WARN,
					    "target %x lun %" PRIx64 ", "
					    "device offline failed",
					    sf_alpa_to_switch[target->
					    sft_al_pa],
					    SCSA_LUN(target)));
				} else {
					SF_DEBUG(1, (sf, CE_NOTE,
					    "target %x, lun %" PRIx64 ", "
					    "device offline succeeded\n",
					    sf_alpa_to_switch[target->
					    sft_al_pa],
					    SCSA_LUN(target)));
				}
			}
			mutex_enter(&sf->sf_mutex);
		} else {
			mutex_exit(&target->sft_mutex);
		}
		target = next_target;
	}
}


/*
 * routine to get/set a capability
 *
 * returning:
 *	1 (TRUE)	boolean capability is true (on get)
 *	0 (FALSE)	invalid capability, can't set capability (on set),
 *			or boolean capability is false (on get)
 *	-1 (UNDEFINED)	can't find capability (SCSA) or unsupported capability
 *	3		when getting SCSI version number
 *	AL_PA		when getting port initiator ID
 */
static int
sf_commoncap(struct scsi_address *ap, char *cap,
    int val, int tgtonly, int doset)
{
	struct sf *sf = ADDR2SF(ap);
	int cidx;
	int rval = FALSE;


	if (cap == NULL) {
		SF_DEBUG(3, (sf, CE_WARN, "sf_commoncap: invalid arg"));
		return (rval);
	}

	/* get index of capability string */
	if ((cidx = scsi_hba_lookup_capstr(cap)) == -1) {
		/* can't find capability */
		return (UNDEFINED);
	}

	if (doset) {
		/*
		 * Process setcap request.
		 */

		/*
		 * At present, we can only set binary (0/1) values
		 */
		switch (cidx) {
		case SCSI_CAP_ARQ:	/* can't set this capability */
			break;
		default:
			SF_DEBUG(3, (sf, CE_WARN,
			    "sf_setcap: unsupported %d", cidx));
			rval = UNDEFINED;
			break;
		}

		SF_DEBUG(4, (sf, CE_NOTE,
		    "set cap: cap=%s,val=0x%x,tgtonly=0x%x"
		    ",doset=0x%x,rval=%d\n",
		    cap, val, tgtonly, doset, rval));

	} else {
		/*
		 * Process getcap request.
		 */
		switch (cidx) {
		case SCSI_CAP_DMA_MAX:
			break;		/* don't' have this capability */
		case SCSI_CAP_INITIATOR_ID:
			rval = sf->sf_al_pa;
			break;
		case SCSI_CAP_ARQ:
			rval = TRUE;	/* do have this capability */
			break;
		case SCSI_CAP_RESET_NOTIFICATION:
		case SCSI_CAP_TAGGED_QING:
			rval = TRUE;	/* do have this capability */
			break;
		case SCSI_CAP_SCSI_VERSION:
			rval = 3;
			break;
		case SCSI_CAP_INTERCONNECT_TYPE:
			rval = INTERCONNECT_FIBRE;
			break;
		default:
			SF_DEBUG(4, (sf, CE_WARN,
			    "sf_scsi_getcap: unsupported"));
			rval = UNDEFINED;
			break;
		}
		SF_DEBUG(4, (sf, CE_NOTE,
		    "get cap: cap=%s,val=0x%x,tgtonly=0x%x,"
		    "doset=0x%x,rval=%d\n",
		    cap, val, tgtonly, doset, rval));
	}

	return (rval);
}


/*
 * called by the transport to get a capability
 */
static int
sf_getcap(struct scsi_address *ap, char *cap, int whom)
{
	return (sf_commoncap(ap, cap, 0, whom, FALSE));
}


/*
 * called by the transport to set a capability
 */
static int
sf_setcap(struct scsi_address *ap, char *cap, int value, int whom)
{
	return (sf_commoncap(ap, cap, value, whom, TRUE));
}


/*
 * called by the transport to abort a target
 */
static int
sf_abort(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	struct sf *sf = ADDR2SF(ap);
	struct sf_target *target = ADDR2TARGET(ap);
	struct sf_pkt *cmd, *ncmd, *pcmd;
	struct fcal_packet *fpkt;
	int	rval = 0, t, my_rval = FALSE;
	int	old_target_state;
	int	lip_cnt;
	int	tgt_id;
	fc_frame_header_t	*hp;
	int	deferred_destroy;

	deferred_destroy = 0;

	if (pkt != NULL) {
		cmd = PKT2CMD(pkt);
		fpkt = cmd->cmd_fp_pkt;
		SF_DEBUG(2, (sf, CE_NOTE, "sf_abort packet %p\n",
		    (void *)fpkt));
		pcmd = NULL;
		mutex_enter(&sf->sf_cmd_mutex);
		ncmd = sf->sf_pkt_head;
		while (ncmd != NULL) {
			if (ncmd == cmd) {
				if (pcmd != NULL) {
					pcmd->cmd_next = cmd->cmd_next;
				} else {
					sf->sf_pkt_head = cmd->cmd_next;
				}
				cmd->cmd_flags &= ~CFLAG_IN_QUEUE;
				cmd->cmd_state = SF_STATE_IDLE;
				pkt->pkt_reason = CMD_ABORTED;
				pkt->pkt_statistics |= STAT_ABORTED;
				my_rval = TRUE;
				break;
			} else {
				pcmd = ncmd;
				ncmd = ncmd->cmd_next;
			}
		}
		mutex_exit(&sf->sf_cmd_mutex);
		if (ncmd == NULL) {
			mutex_enter(&cmd->cmd_abort_mutex);
			if (cmd->cmd_state == SF_STATE_ISSUED) {
				cmd->cmd_state = SF_STATE_ABORTING;
				cmd->cmd_timeout = sf_watchdog_time + 20;
				mutex_exit(&cmd->cmd_abort_mutex);
				/* call transport to abort command */
				if (((rval = soc_abort(sf->sf_sochandle,
				    sf->sf_socp, sf->sf_sochandle->fcal_portno,
				    fpkt, 1)) == FCAL_ABORTED) ||
				    (rval == FCAL_ABORT_FAILED)) {
					my_rval = TRUE;
					pkt->pkt_reason = CMD_ABORTED;
					pkt->pkt_statistics |= STAT_ABORTED;
					cmd->cmd_state = SF_STATE_IDLE;
				} else if (rval == FCAL_BAD_ABORT) {
					cmd->cmd_timeout = sf_watchdog_time
					    + 20;
					my_rval = FALSE;
				} else {
					SF_DEBUG(1, (sf, CE_NOTE,
					    "Command Abort failed\n"));
				}
			} else {
				mutex_exit(&cmd->cmd_abort_mutex);
			}
		}
	} else {
		SF_DEBUG(2, (sf, CE_NOTE, "sf_abort target\n"));
		mutex_enter(&sf->sf_mutex);
		lip_cnt = sf->sf_lip_cnt;
		mutex_enter(&target->sft_mutex);
		if (target->sft_state & (SF_TARGET_BUSY |
		    SF_TARGET_OFFLINE)) {
			mutex_exit(&target->sft_mutex);
			return (rval);
		}
		old_target_state = target->sft_state;
		target->sft_state |= SF_TARGET_BUSY;
		mutex_exit(&target->sft_mutex);
		mutex_exit(&sf->sf_mutex);

		if ((pkt = sf_scsi_init_pkt(ap, NULL, NULL, 0,
		    0, 0, 0, NULL, 0)) != NULL) {

			cmd = PKT2CMD(pkt);
			cmd->cmd_block->fcp_cntl.cntl_abort_tsk = 1;
			cmd->cmd_fp_pkt->fcal_pkt_comp = NULL;
			cmd->cmd_pkt->pkt_flags |= FLAG_NOINTR;

			/* prepare the packet for transport */
			if (sf_prepare_pkt(sf, cmd, target) == TRAN_ACCEPT) {

				cmd->cmd_state = SF_STATE_ISSUED;
				/*
				 * call transport to send a pkt polled
				 *
				 * if that fails call the transport to abort it
				 */
				if (soc_transport_poll(sf->sf_sochandle,
				    cmd->cmd_fp_pkt, SF_ABORT_TIMEOUT,
				    CQ_REQUEST_1) == FCAL_TRANSPORT_SUCCESS) {
					(void) ddi_dma_sync(
					    cmd->cmd_cr_pool->rsp_dma_handle,
					    (off_t)
					    ((caddr_t)cmd->cmd_rsp_block -
					    cmd->cmd_cr_pool->rsp_base),
					    FCP_MAX_RSP_IU_SIZE,
					    DDI_DMA_SYNC_FORKERNEL);
					if (((struct fcp_rsp_info *)
					    (&cmd->cmd_rsp_block->
					    fcp_response_len + 1))->
					    rsp_code == FCP_NO_FAILURE) {
						/* abort cmds for this targ */
						sf_abort_all(sf, target, TRUE,
						    lip_cnt, TRUE);
					} else {
						hp = &cmd->cmd_fp_pkt->
						    fcal_socal_request.
						    sr_fc_frame_hdr;
						tgt_id = sf_alpa_to_switch[
						    (uchar_t)hp->d_id];
						sf->sf_stats.tstats[tgt_id].
						    task_mgmt_failures++;
						SF_DEBUG(1, (sf, CE_NOTE,
						    "Target %d Abort Task "
						    "Set failed\n", hp->d_id));
					}
				} else {
					mutex_enter(&cmd->cmd_abort_mutex);
					if (cmd->cmd_state == SF_STATE_ISSUED) {
					cmd->cmd_state = SF_STATE_ABORTING;
					cmd->cmd_timeout = sf_watchdog_time
					    + 20;
					mutex_exit(&cmd->cmd_abort_mutex);
					if ((t = soc_abort(sf->sf_sochandle,
					    sf->sf_socp, sf->sf_sochandle->
					    fcal_portno, cmd->cmd_fp_pkt, 1)) !=
					    FCAL_ABORTED &&
					    (t != FCAL_ABORT_FAILED)) {
						sf_log(sf, CE_NOTE,
						    "sf_abort failed, "
						    "initiating LIP\n");
						sf_force_lip(sf);
						deferred_destroy = 1;
					}
					} else {
					mutex_exit(&cmd->cmd_abort_mutex);
					}
				}
			}
			if (!deferred_destroy) {
				cmd->cmd_fp_pkt->fcal_pkt_comp =
				    sf_cmd_callback;
				cmd->cmd_block->fcp_cntl.cntl_abort_tsk = 0;
				sf_scsi_destroy_pkt(ap, pkt);
				my_rval = TRUE;
			}
		}
		mutex_enter(&sf->sf_mutex);
		if (lip_cnt == sf->sf_lip_cnt) {
			mutex_enter(&target->sft_mutex);
			target->sft_state = old_target_state;
			mutex_exit(&target->sft_mutex);
		}
		mutex_exit(&sf->sf_mutex);
	}
	return (my_rval);
}


/*
 * called by the transport and internally to reset a target
 */
static int
sf_reset(struct scsi_address *ap, int level)
{
	struct scsi_pkt *pkt;
	struct fcal_packet *fpkt;
	struct sf *sf = ADDR2SF(ap);
	struct sf_target *target = ADDR2TARGET(ap), *ntarget;
	struct sf_pkt *cmd;
	int	rval = FALSE, t;
	int	lip_cnt;
	int	tgt_id, ret;
	fc_frame_header_t	*hp;
	int	deferred_destroy;

	/* We don't support RESET_LUN yet. */
	if (level == RESET_TARGET) {
		struct sf_reset_list *p;

		if ((p = kmem_alloc(sizeof (struct sf_reset_list), KM_NOSLEEP))
		    == NULL)
			return (rval);

		SF_DEBUG(2, (sf, CE_NOTE, "sf_reset target\n"));
		mutex_enter(&sf->sf_mutex);
		/* All target resets go to LUN 0 */
		if (target->sft_lun.l) {
			target = sf_lookup_target(sf, target->sft_port_wwn, 0);
		}
		mutex_enter(&target->sft_mutex);
		if (target->sft_state & (SF_TARGET_BUSY |
		    SF_TARGET_OFFLINE)) {
			mutex_exit(&target->sft_mutex);
			mutex_exit(&sf->sf_mutex);
			kmem_free(p, sizeof (struct sf_reset_list));
			return (rval);
		}
		lip_cnt = sf->sf_lip_cnt;
		target->sft_state |= SF_TARGET_BUSY;
		for (ntarget = target->sft_next_lun;
		    ntarget;
		    ntarget = ntarget->sft_next_lun) {
			mutex_enter(&ntarget->sft_mutex);
			/*
			 * XXXX If we supported RESET_LUN we should check here
			 * to see if any LUN were being reset and somehow fail
			 * that operation.
			 */
			ntarget->sft_state |= SF_TARGET_BUSY;
			mutex_exit(&ntarget->sft_mutex);
		}
		mutex_exit(&target->sft_mutex);
		mutex_exit(&sf->sf_mutex);

		deferred_destroy = 0;
		if ((pkt = sf_scsi_init_pkt(ap, NULL, NULL, 0,
		    0, 0, 0, NULL, 0)) != NULL) {
			cmd = PKT2CMD(pkt);
			cmd->cmd_block->fcp_cntl.cntl_reset = 1;
			cmd->cmd_fp_pkt->fcal_pkt_comp = NULL;
			cmd->cmd_pkt->pkt_flags |= FLAG_NOINTR;

			/* prepare the packet for transport */
			if (sf_prepare_pkt(sf, cmd, target) == TRAN_ACCEPT) {
				/* call transport to send a pkt polled */
				cmd->cmd_state = SF_STATE_ISSUED;
				if ((ret = soc_transport_poll(sf->sf_sochandle,
				    cmd->cmd_fp_pkt, SF_ABORT_TIMEOUT,
				    CQ_REQUEST_1)) == FCAL_TRANSPORT_SUCCESS) {
					(void) ddi_dma_sync(cmd->cmd_cr_pool->
					    rsp_dma_handle, (caddr_t)cmd->
					    cmd_rsp_block - cmd->cmd_cr_pool->
					    rsp_base, FCP_MAX_RSP_IU_SIZE,
					    DDI_DMA_SYNC_FORKERNEL);
					fpkt = cmd->cmd_fp_pkt;
					if ((fpkt->fcal_pkt_status ==
					    FCAL_STATUS_OK) &&
					    (((struct fcp_rsp_info *)
					    (&cmd->cmd_rsp_block->
					    fcp_response_len + 1))->
					    rsp_code == FCP_NO_FAILURE)) {
						sf_log(sf, CE_NOTE,
						    "!sf%d: Target 0x%x Reset "
						    "successful\n",
						    ddi_get_instance(\
						    sf->sf_dip),
						    sf_alpa_to_switch[
						    target->sft_al_pa]);
						rval = TRUE;
					} else {
						hp = &cmd->cmd_fp_pkt->
						    fcal_socal_request.
						    sr_fc_frame_hdr;
						tgt_id = sf_alpa_to_switch[
						    (uchar_t)hp->d_id];
						sf->sf_stats.tstats[tgt_id].
						    task_mgmt_failures++;
						sf_log(sf, CE_NOTE,
						    "!sf%d: Target 0x%x "
						    "Reset failed."
						    "Status code 0x%x "
						    "Resp code 0x%x\n",
						    ddi_get_instance(\
						    sf->sf_dip),
						    tgt_id,
						    fpkt->fcal_pkt_status,
						    ((struct fcp_rsp_info *)
						    (&cmd->cmd_rsp_block->
						    fcp_response_len + 1))->
						    rsp_code);
					}
				} else {
					sf_log(sf, CE_NOTE, "!sf%d: Target "
					    "0x%x Reset Failed. Ret=%x\n",
					    ddi_get_instance(sf->sf_dip),
					    sf_alpa_to_switch[
					    target->sft_al_pa], ret);
					mutex_enter(&cmd->cmd_abort_mutex);
					if (cmd->cmd_state == SF_STATE_ISSUED) {
					/* call the transport to abort a cmd */
					cmd->cmd_timeout = sf_watchdog_time
					    + 20;
					cmd->cmd_state = SF_STATE_ABORTING;
					mutex_exit(&cmd->cmd_abort_mutex);
					if (((t = soc_abort(sf->sf_sochandle,
					    sf->sf_socp,
					    sf->sf_sochandle->fcal_portno,
					    cmd->cmd_fp_pkt, 1)) !=
					    FCAL_ABORTED) &&
					    (t != FCAL_ABORT_FAILED)) {
						sf_log(sf, CE_NOTE,
						    "!sf%d: Target 0x%x Reset "
						    "failed. Abort Failed, "
						    "forcing LIP\n",
						    ddi_get_instance(
						    sf->sf_dip),
						    sf_alpa_to_switch[
						    target->sft_al_pa]);
						sf_force_lip(sf);
						rval = TRUE;
						deferred_destroy = 1;
					}
					} else {
						mutex_exit
						    (&cmd->cmd_abort_mutex);
					}
				}
			}
			/*
			 * Defer releasing the packet if we abort returned with
			 * a BAD_ABORT or timed out, because there is a
			 * possibility that the ucode might return it.
			 * We wait for at least 20s and let it be released
			 * by the sf_watch thread
			 */
			if (!deferred_destroy) {
				cmd->cmd_block->fcp_cntl.cntl_reset = 0;
				cmd->cmd_fp_pkt->fcal_pkt_comp =
				    sf_cmd_callback;
				cmd->cmd_state = SF_STATE_IDLE;
				/* for cache */
				sf_scsi_destroy_pkt(ap, pkt);
			}
		} else {
			cmn_err(CE_WARN, "!sf%d: Target 0x%x Reset Failed. "
			    "Resource allocation error.\n",
			    ddi_get_instance(sf->sf_dip),
			    sf_alpa_to_switch[target->sft_al_pa]);
		}
		mutex_enter(&sf->sf_mutex);
		if ((rval == TRUE) && (lip_cnt == sf->sf_lip_cnt)) {
			p->target = target;
			p->lip_cnt = lip_cnt;
			p->timeout = ddi_get_lbolt() +
			    drv_usectohz(SF_TARGET_RESET_DELAY);
			p->next = sf->sf_reset_list;
			sf->sf_reset_list = p;
			mutex_exit(&sf->sf_mutex);
			mutex_enter(&sf_global_mutex);
			if (sf_reset_timeout_id == 0) {
				sf_reset_timeout_id = timeout(
				    sf_check_reset_delay, NULL,
				    drv_usectohz(SF_TARGET_RESET_DELAY));
			}
			mutex_exit(&sf_global_mutex);
		} else {
			if (lip_cnt == sf->sf_lip_cnt) {
				mutex_enter(&target->sft_mutex);
				target->sft_state &= ~SF_TARGET_BUSY;
				for (ntarget = target->sft_next_lun;
				    ntarget;
				    ntarget = ntarget->sft_next_lun) {
					mutex_enter(&ntarget->sft_mutex);
					ntarget->sft_state &= ~SF_TARGET_BUSY;
					mutex_exit(&ntarget->sft_mutex);
				}
				mutex_exit(&target->sft_mutex);
			}
			mutex_exit(&sf->sf_mutex);
			kmem_free(p, sizeof (struct sf_reset_list));
		}
	} else {
		mutex_enter(&sf->sf_mutex);
		if ((sf->sf_state == SF_STATE_OFFLINE) &&
		    (sf_watchdog_time < sf->sf_timer)) {
			/*
			 * We are currently in a lip, so let this one
			 * finish before forcing another one.
			 */
			mutex_exit(&sf->sf_mutex);
			return (TRUE);
		}
		mutex_exit(&sf->sf_mutex);
		sf_log(sf, CE_NOTE, "!sf:Target driver initiated lip\n");
		sf_force_lip(sf);
		rval = TRUE;
	}
	return (rval);
}


/*
 * abort all commands for a target
 *
 * if try_abort is set then send an abort
 * if abort is set then this is abort, else this is a reset
 */
static void
sf_abort_all(struct sf *sf, struct sf_target *target, int abort, int
    lip_cnt, int try_abort)
{
	struct sf_target *ntarget;
	struct sf_pkt *cmd, *head = NULL, *tail = NULL, *pcmd = NULL, *tcmd;
	struct fcal_packet *fpkt;
	struct scsi_pkt *pkt;
	int rval = FCAL_ABORTED;

	/*
	 * First pull all commands for all LUNs on this target out of the
	 * overflow list.  We can tell it's the same target by comparing
	 * the node WWN.
	 */
	mutex_enter(&sf->sf_mutex);
	if (lip_cnt == sf->sf_lip_cnt) {
		mutex_enter(&sf->sf_cmd_mutex);
		cmd = sf->sf_pkt_head;
		while (cmd != NULL) {
			ntarget = ADDR2TARGET(&cmd->cmd_pkt->
			    pkt_address);
			if (ntarget == target) {
				if (pcmd != NULL)
					pcmd->cmd_next = cmd->cmd_next;
				else
					sf->sf_pkt_head = cmd->cmd_next;
				if (sf->sf_pkt_tail == cmd) {
					sf->sf_pkt_tail = pcmd;
					if (pcmd != NULL)
						pcmd->cmd_next = NULL;
				}
				tcmd = cmd->cmd_next;
				if (head == NULL) {
					head = cmd;
					tail = cmd;
				} else {
					tail->cmd_next = cmd;
					tail = cmd;
				}
				cmd->cmd_next = NULL;
				cmd = tcmd;
			} else {
				pcmd = cmd;
				cmd = cmd->cmd_next;
			}
		}
		mutex_exit(&sf->sf_cmd_mutex);
	}
	mutex_exit(&sf->sf_mutex);

	/*
	 * Now complete all the commands on our list.  In the process,
	 * the completion routine may take the commands off the target
	 * lists.
	 */
	cmd = head;
	while (cmd != NULL) {
		pkt = cmd->cmd_pkt;
		if (abort) {
			pkt->pkt_reason = CMD_ABORTED;
			pkt->pkt_statistics |= STAT_ABORTED;
		} else {
			pkt->pkt_reason = CMD_RESET;
			pkt->pkt_statistics |= STAT_DEV_RESET;
		}
		cmd->cmd_flags &= ~CFLAG_IN_QUEUE;
		cmd->cmd_state = SF_STATE_IDLE;
		cmd = cmd->cmd_next;
		/*
		 * call the packet completion routine only for
		 * non-polled commands. Ignore the polled commands as
		 * they timeout and will be handled differently
		 */
		if ((pkt->pkt_comp) && !(pkt->pkt_flags & FLAG_NOINTR))
			(*pkt->pkt_comp)(pkt);

	}

	/*
	 * Finally get all outstanding commands for each LUN, and abort them if
	 * they've been issued, and call the completion routine.
	 * For the case where sf_offline_target is called from sf_watch
	 * due to a Offline Timeout, it is quite possible that the soc+
	 * ucode is hosed and therefore  cannot return the commands.
	 * Clear up all the issued commands as well.
	 * Try_abort will be false only if sf_abort_all is coming from
	 * sf_target_offline.
	 */

	if (try_abort || sf->sf_state == SF_STATE_OFFLINE) {
		mutex_enter(&target->sft_pkt_mutex);
		cmd = tcmd = target->sft_pkt_head;
		while (cmd != (struct sf_pkt *)&target->sft_pkt_head) {
			fpkt = cmd->cmd_fp_pkt;
			pkt = cmd->cmd_pkt;
			mutex_enter(&cmd->cmd_abort_mutex);
			if ((cmd->cmd_state == SF_STATE_ISSUED) &&
			    (fpkt->fcal_cmd_state &
			    FCAL_CMD_IN_TRANSPORT) &&
			    ((fpkt->fcal_cmd_state & FCAL_CMD_COMPLETE) ==
			    0) && !(pkt->pkt_flags & FLAG_NOINTR)) {
				cmd->cmd_state = SF_STATE_ABORTING;
				cmd->cmd_timeout = sf_watchdog_time +
				    cmd->cmd_pkt->pkt_time + 20;
				mutex_exit(&cmd->cmd_abort_mutex);
				mutex_exit(&target->sft_pkt_mutex);
				if (try_abort) {
					/* call the transport to abort a pkt */
					rval = soc_abort(sf->sf_sochandle,
					    sf->sf_socp,
					    sf->sf_sochandle->fcal_portno,
					    fpkt, 1);
				}
				if ((rval == FCAL_ABORTED) ||
				    (rval == FCAL_ABORT_FAILED)) {
					if (abort) {
						pkt->pkt_reason = CMD_ABORTED;
						pkt->pkt_statistics |=
						    STAT_ABORTED;
					} else {
						pkt->pkt_reason = CMD_RESET;
						pkt->pkt_statistics |=
						    STAT_DEV_RESET;
					}
					cmd->cmd_state = SF_STATE_IDLE;
					if (pkt->pkt_comp)
						(*pkt->pkt_comp)(pkt);
				}
				mutex_enter(&sf->sf_mutex);
				if (lip_cnt != sf->sf_lip_cnt) {
					mutex_exit(&sf->sf_mutex);
					return;
				}
				mutex_exit(&sf->sf_mutex);
				mutex_enter(&target->sft_pkt_mutex);
				cmd = target->sft_pkt_head;
			} else {
				mutex_exit(&cmd->cmd_abort_mutex);
				cmd = cmd->cmd_forw;
			}
		}
		mutex_exit(&target->sft_pkt_mutex);
	}
}


/*
 * called by the transport to start a packet
 */
static int
sf_start(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	struct sf *sf = ADDR2SF(ap);
	struct sf_target *target = ADDR2TARGET(ap);
	struct sf_pkt *cmd = PKT2CMD(pkt);
	int rval;


	SF_DEBUG(6, (sf, CE_NOTE, "sf_start\n"));

	if (cmd->cmd_state == SF_STATE_ISSUED) {
		cmn_err(CE_PANIC, "sf: issuing packet twice 0x%p\n",
		    (void *)cmd);
	}

	/* prepare the packet for transport */
	if ((rval = sf_prepare_pkt(sf, cmd, target)) != TRAN_ACCEPT) {
		return (rval);
	}

	if (target->sft_state & (SF_TARGET_BUSY|SF_TARGET_OFFLINE)) {
		if (target->sft_state & SF_TARGET_OFFLINE) {
			return (TRAN_FATAL_ERROR);
		}
		if (pkt->pkt_flags & FLAG_NOINTR) {
			return (TRAN_BUSY);
		}
		mutex_enter(&sf->sf_cmd_mutex);
		sf->sf_use_lock = TRUE;
		goto enque;
	}


	/* if no interrupts then do polled I/O */
	if (pkt->pkt_flags & FLAG_NOINTR) {
		return (sf_dopoll(sf, cmd));
	}

	/* regular interrupt-driven I/O */

	if (!sf->sf_use_lock) {

		/* locking no needed */

		cmd->cmd_timeout = cmd->cmd_pkt->pkt_time ?
		    sf_watchdog_time + cmd->cmd_pkt->pkt_time : 0;
		cmd->cmd_state = SF_STATE_ISSUED;

		/* call the transport to send a pkt */
		if (soc_transport(sf->sf_sochandle, cmd->cmd_fp_pkt,
		    FCAL_NOSLEEP, CQ_REQUEST_1) != FCAL_TRANSPORT_SUCCESS) {
			cmd->cmd_state = SF_STATE_IDLE;
			return (TRAN_BADPKT);
		}
		return (TRAN_ACCEPT);
	}

	/* regular I/O using locking */

	mutex_enter(&sf->sf_cmd_mutex);
	if ((sf->sf_ncmds >= sf->sf_throttle) ||
	    (sf->sf_pkt_head != NULL)) {
enque:
		/*
		 * either we're throttling back or there are already commands
		 * on the queue, so enqueue this one for later
		 */
		cmd->cmd_flags |= CFLAG_IN_QUEUE;
		if (sf->sf_pkt_head != NULL) {
			/* add to the queue */
			sf->sf_pkt_tail->cmd_next = cmd;
			cmd->cmd_next = NULL;
			sf->sf_pkt_tail = cmd;
		} else {
			/* this is the first entry in the queue */
			sf->sf_pkt_head = sf->sf_pkt_tail = cmd;
			cmd->cmd_next = NULL;
		}
		mutex_exit(&sf->sf_cmd_mutex);
		return (TRAN_ACCEPT);
	}

	/*
	 * start this packet now
	 */

	/* still have cmd mutex */
	return (sf_start_internal(sf, cmd));
}


/*
 * internal routine to start a packet from the queue now
 *
 * enter with cmd mutex held and leave with it released
 */
static int
sf_start_internal(struct sf *sf, struct sf_pkt *cmd)
{
	/* we have the cmd mutex */
	sf->sf_ncmds++;
	mutex_exit(&sf->sf_cmd_mutex);

	ASSERT(cmd->cmd_state != SF_STATE_ISSUED);
	SF_DEBUG(6, (sf, CE_NOTE, "sf_start_internal\n"));

	cmd->cmd_timeout = cmd->cmd_pkt->pkt_time ? sf_watchdog_time +
	    cmd->cmd_pkt->pkt_time : 0;
	cmd->cmd_state = SF_STATE_ISSUED;

	/* call transport to send the pkt */
	if (soc_transport(sf->sf_sochandle, cmd->cmd_fp_pkt, FCAL_NOSLEEP,
	    CQ_REQUEST_1) != FCAL_TRANSPORT_SUCCESS) {
		cmd->cmd_state = SF_STATE_IDLE;
		mutex_enter(&sf->sf_cmd_mutex);
		sf->sf_ncmds--;
		mutex_exit(&sf->sf_cmd_mutex);
		return (TRAN_BADPKT);
	}
	return (TRAN_ACCEPT);
}


/*
 * prepare a packet for transport
 */
static int
sf_prepare_pkt(struct sf *sf, struct sf_pkt *cmd, struct sf_target *target)
{
	struct fcp_cmd *fcmd = cmd->cmd_block;

/* XXXX Need to set the LUN ? */
	bcopy((caddr_t)&target->sft_lun.b,
	    (caddr_t)&fcmd->fcp_ent_addr,
	    FCP_LUN_SIZE);
	cmd->cmd_pkt->pkt_reason = CMD_CMPLT;
	cmd->cmd_pkt->pkt_state = 0;
	cmd->cmd_pkt->pkt_statistics = 0;


	if ((cmd->cmd_pkt->pkt_comp == NULL) &&
	    ((cmd->cmd_pkt->pkt_flags & FLAG_NOINTR) == 0)) {
		return (TRAN_BADPKT);
	}

	/* invalidate imp field(s) of rsp block */
	cmd->cmd_rsp_block->fcp_u.i_fcp_status = SF_BAD_DMA_MAGIC;

	/* set up amt of I/O to do */
	if (cmd->cmd_flags & CFLAG_DMAVALID) {
		cmd->cmd_pkt->pkt_resid = cmd->cmd_dmacount;
		if (cmd->cmd_flags & CFLAG_CMDIOPB) {
			(void) ddi_dma_sync(cmd->cmd_dmahandle, 0, 0,
			    DDI_DMA_SYNC_FORDEV);
		}
	} else {
		cmd->cmd_pkt->pkt_resid = 0;
	}

	/* set up the Tagged Queuing type */
	if (cmd->cmd_pkt->pkt_flags & FLAG_HTAG) {
		fcmd->fcp_cntl.cntl_qtype = FCP_QTYPE_HEAD_OF_Q;
	} else if (cmd->cmd_pkt->pkt_flags & FLAG_OTAG) {
		fcmd->fcp_cntl.cntl_qtype = FCP_QTYPE_ORDERED;
	}

	/*
	 * Sync the cmd segment
	 */
	(void) ddi_dma_sync(cmd->cmd_cr_pool->cmd_dma_handle,
	    (caddr_t)fcmd - cmd->cmd_cr_pool->cmd_base,
	    sizeof (struct fcp_cmd), DDI_DMA_SYNC_FORDEV);

	sf_fill_ids(sf, cmd, target);
	return (TRAN_ACCEPT);
}


/*
 * fill in packet hdr source and destination IDs and hdr byte count
 */
static void
sf_fill_ids(struct sf *sf, struct sf_pkt *cmd, struct sf_target *target)
{
	struct fcal_packet *fpkt = cmd->cmd_fp_pkt;
	fc_frame_header_t	*hp;


	hp = &fpkt->fcal_socal_request.sr_fc_frame_hdr;
	hp->d_id = target->sft_al_pa;
	hp->s_id = sf->sf_al_pa;
	fpkt->fcal_socal_request.sr_soc_hdr.sh_byte_cnt =
	    cmd->cmd_dmacookie.dmac_size;
}


/*
 * do polled I/O using transport
 */
static int
sf_dopoll(struct sf *sf, struct sf_pkt *cmd)
{
	int timeout;
	int rval;


	mutex_enter(&sf->sf_cmd_mutex);
	sf->sf_ncmds++;
	mutex_exit(&sf->sf_cmd_mutex);

	timeout = cmd->cmd_pkt->pkt_time ? cmd->cmd_pkt->pkt_time
	    : SF_POLL_TIMEOUT;
	cmd->cmd_timeout = 0;
	cmd->cmd_fp_pkt->fcal_pkt_comp = NULL;
	cmd->cmd_state = SF_STATE_ISSUED;

	/* call transport to send a pkt polled */
	rval = soc_transport_poll(sf->sf_sochandle, cmd->cmd_fp_pkt,
	    timeout*1000000, CQ_REQUEST_1);
	mutex_enter(&cmd->cmd_abort_mutex);
	cmd->cmd_fp_pkt->fcal_pkt_comp = sf_cmd_callback;
	if (rval != FCAL_TRANSPORT_SUCCESS) {
		if (rval == FCAL_TRANSPORT_TIMEOUT) {
			cmd->cmd_state = SF_STATE_ABORTING;
			mutex_exit(&cmd->cmd_abort_mutex);
			(void) sf_target_timeout(sf, cmd);
		} else {
			mutex_exit(&cmd->cmd_abort_mutex);
		}
		cmd->cmd_state = SF_STATE_IDLE;
		cmd->cmd_fp_pkt->fcal_pkt_comp = sf_cmd_callback;
		mutex_enter(&sf->sf_cmd_mutex);
		sf->sf_ncmds--;
		mutex_exit(&sf->sf_cmd_mutex);
		return (TRAN_BADPKT);
	}
	mutex_exit(&cmd->cmd_abort_mutex);
	cmd->cmd_fp_pkt->fcal_pkt_comp = sf_cmd_callback;
	sf_cmd_callback(cmd->cmd_fp_pkt);
	return (TRAN_ACCEPT);
}


/* a shortcut for defining debug messages below */
#ifdef	DEBUG
#define	SF_DMSG1(s)		msg1 = s
#else
#define	SF_DMSG1(s)		/* do nothing */
#endif


/*
 * the pkt_comp callback for command packets
 */
static void
sf_cmd_callback(struct fcal_packet *fpkt)
{
	struct sf_pkt *cmd = (struct sf_pkt *)fpkt->fcal_pkt_private;
	struct scsi_pkt *pkt = cmd->cmd_pkt;
	struct sf *sf = ADDR2SF(&pkt->pkt_address);
	struct sf_target *target = ADDR2TARGET(&pkt->pkt_address);
	struct fcp_rsp *rsp;
	char *msg1 = NULL;
	char *msg2 = NULL;
	short ncmds;
	int tgt_id;
	int good_scsi_status = TRUE;



	if (cmd->cmd_state == SF_STATE_IDLE) {
		cmn_err(CE_PANIC, "sf: completing idle packet 0x%p\n",
		    (void *)cmd);
	}

	mutex_enter(&cmd->cmd_abort_mutex);
	if (cmd->cmd_state == SF_STATE_ABORTING) {
		/* cmd already being aborted -- nothing to do */
		mutex_exit(&cmd->cmd_abort_mutex);
		return;
	}

	cmd->cmd_state = SF_STATE_IDLE;
	mutex_exit(&cmd->cmd_abort_mutex);

	if (fpkt->fcal_pkt_status == FCAL_STATUS_OK) {

		(void) ddi_dma_sync(cmd->cmd_cr_pool->rsp_dma_handle,
		    (caddr_t)cmd->cmd_rsp_block - cmd->cmd_cr_pool->rsp_base,
		    FCP_MAX_RSP_IU_SIZE, DDI_DMA_SYNC_FORKERNEL);

		rsp = (struct fcp_rsp *)cmd->cmd_rsp_block;

		if (rsp->fcp_u.i_fcp_status == SF_BAD_DMA_MAGIC) {

			if (sf_core && (sf_core & SF_CORE_BAD_DMA)) {
				sf_token = (int *)(uintptr_t)
				    fpkt->fcal_socal_request.\
				    sr_soc_hdr.sh_request_token;
				(void) soc_take_core(sf->sf_sochandle,
				    sf->sf_socp);
			}

			pkt->pkt_reason = CMD_INCOMPLETE;
			pkt->pkt_state = STATE_GOT_BUS;
			pkt->pkt_statistics |= STAT_ABORTED;

		} else {

			pkt->pkt_state = STATE_GOT_BUS | STATE_GOT_TARGET |
			    STATE_SENT_CMD | STATE_GOT_STATUS;
			pkt->pkt_resid = 0;
			if (cmd->cmd_flags & CFLAG_DMAVALID) {
				pkt->pkt_state |= STATE_XFERRED_DATA;
			}

			if ((pkt->pkt_scbp != NULL) &&
			    ((*(pkt->pkt_scbp) =
			    rsp->fcp_u.fcp_status.scsi_status)
			    != STATUS_GOOD)) {
				good_scsi_status = FALSE;
			/*
			 * The next two checks make sure that if there
			 * is no sense data or a valid response and
			 * the command came back with check condition,
			 * the command should be retried
			 */
				if (!rsp->fcp_u.fcp_status.rsp_len_set &&
				    !rsp->fcp_u.fcp_status.sense_len_set) {
					pkt->pkt_state &= ~STATE_XFERRED_DATA;
					pkt->pkt_resid = cmd->cmd_dmacount;
				}
			}

			if ((cmd->cmd_flags & CFLAG_CMDIOPB) &&
			    (pkt->pkt_state & STATE_XFERRED_DATA)) {
				(void) ddi_dma_sync(cmd->cmd_dmahandle, 0,
				    (uint_t)0, DDI_DMA_SYNC_FORCPU);
			}
			/*
			 * Update the transfer resid, if appropriate
			 */
			if (rsp->fcp_u.fcp_status.resid_over ||
			    rsp->fcp_u.fcp_status.resid_under)
				pkt->pkt_resid = rsp->fcp_resid;

			/*
			 * Check to see if the SCSI command failed.
			 *
			 */

			/*
			 * First see if we got a FCP protocol error.
			 */
			if (rsp->fcp_u.fcp_status.rsp_len_set) {
				struct fcp_rsp_info *bep;

				bep = (struct fcp_rsp_info *)
				    (&rsp->fcp_response_len + 1);
				if (bep->rsp_code != FCP_NO_FAILURE) {
						pkt->pkt_reason = CMD_TRAN_ERR;
					tgt_id = pkt->pkt_address.a_target;
					switch (bep->rsp_code) {
					case FCP_CMND_INVALID:
						SF_DMSG1("FCP_RSP FCP_CMND "
						    "fields invalid");
						break;
					case FCP_TASK_MGMT_NOT_SUPPTD:
						SF_DMSG1("FCP_RSP Task"
						    "Management Function"
						    "Not Supported");
						break;
					case FCP_TASK_MGMT_FAILED:
						SF_DMSG1("FCP_RSP Task "
						    "Management Function"
						    "Failed");
						sf->sf_stats.tstats[tgt_id].
						    task_mgmt_failures++;
						break;
					case FCP_DATA_RO_MISMATCH:
						SF_DMSG1("FCP_RSP FCP_DATA RO "
						    "mismatch with "
						    "FCP_XFER_RDY DATA_RO");
						sf->sf_stats.tstats[tgt_id].
						    data_ro_mismatches++;
						break;
					case FCP_DL_LEN_MISMATCH:
						SF_DMSG1("FCP_RSP FCP_DATA "
						    "length "
						    "different than BURST_LEN");
						sf->sf_stats.tstats[tgt_id].
						    dl_len_mismatches++;
						break;
					default:
						SF_DMSG1("FCP_RSP invalid "
						    "RSP_CODE");
						break;
					}
				}
			}

			/*
			 * See if we got a SCSI error with sense data
			 */
			if (rsp->fcp_u.fcp_status.sense_len_set) {
				uchar_t rqlen = min(rsp->fcp_sense_len,
				    sizeof (struct scsi_extended_sense));
				caddr_t sense = (caddr_t)rsp +
				    sizeof (struct fcp_rsp) +
				    rsp->fcp_response_len;
				struct scsi_arq_status *arq;
				struct scsi_extended_sense *sensep =
				    (struct scsi_extended_sense *)sense;

				if (rsp->fcp_u.fcp_status.scsi_status !=
				    STATUS_GOOD) {
				if (rsp->fcp_u.fcp_status.scsi_status
				    == STATUS_CHECK) {
					if (sensep->es_key ==
					    KEY_RECOVERABLE_ERROR)
						good_scsi_status = 1;
					if (sensep->es_key ==
					    KEY_UNIT_ATTENTION &&
					    sensep->es_add_code == 0x3f &&
					    sensep->es_qual_code == 0x0e) {
						/* REPORT_LUNS_HAS_CHANGED */
						sf_log(sf, CE_NOTE,
						"!REPORT_LUNS_HAS_CHANGED\n");
						sf_force_lip(sf);
					}
				}
				}

				if ((pkt->pkt_scbp != NULL) &&
				    (cmd->cmd_scblen >=
					sizeof (struct scsi_arq_status))) {

				pkt->pkt_state |= STATE_ARQ_DONE;

				arq = (struct scsi_arq_status *)pkt->pkt_scbp;
				/*
				 * copy out sense information
				 */
				bcopy(sense, (caddr_t)&arq->sts_sensedata,
				    rqlen);
				arq->sts_rqpkt_resid =
				    sizeof (struct scsi_extended_sense) -
					rqlen;
				*((uchar_t *)&arq->sts_rqpkt_status) =
				    STATUS_GOOD;
				arq->sts_rqpkt_reason = 0;
				arq->sts_rqpkt_statistics = 0;
				arq->sts_rqpkt_state = STATE_GOT_BUS |
				    STATE_GOT_TARGET | STATE_SENT_CMD |
				    STATE_GOT_STATUS | STATE_ARQ_DONE |
				    STATE_XFERRED_DATA;
			    }
				target->sft_alive = TRUE;
			}

			/*
			 * The firmware returns the number of bytes actually
			 * xfered into/out of host. Compare this with what
			 * we asked and if it is different, we lost frames ?
			 */
			if ((pkt->pkt_reason == 0) && (pkt->pkt_resid == 0) &&
			    (good_scsi_status) &&
			    (pkt->pkt_state & STATE_XFERRED_DATA) &&
			    (!(cmd->cmd_flags & CFLAG_CMDIOPB)) &&
			    (target->sft_device_type != DTYPE_ESI)) {
				int byte_cnt =
				    fpkt->fcal_socal_request.
				    sr_soc_hdr.sh_byte_cnt;
				if (cmd->cmd_flags & CFLAG_DMASEND) {
					if (byte_cnt != 0) {
					sf_log(sf, CE_NOTE,
					    "!sf_cmd_callback: Lost Frame: "
					    "(write) received 0x%x expected"
					    " 0x%x target 0x%x\n",
					    byte_cnt, cmd->cmd_dmacount,
					    sf_alpa_to_switch[
					    target->sft_al_pa]);
					pkt->pkt_reason = CMD_INCOMPLETE;
					pkt->pkt_statistics |= STAT_ABORTED;
					}
				} else if (byte_cnt < cmd->cmd_dmacount) {
					sf_log(sf, CE_NOTE,
					    "!sf_cmd_callback: "
					    "Lost Frame: (read) "
					    "received 0x%x expected 0x%x "
					    "target 0x%x\n", byte_cnt,
					    cmd->cmd_dmacount,
					    sf_alpa_to_switch[
					    target->sft_al_pa]);
					pkt->pkt_reason = CMD_INCOMPLETE;
					pkt->pkt_statistics |= STAT_ABORTED;
				}
			}
		}

	} else {

		/* pkt status was not ok */

		switch (fpkt->fcal_pkt_status) {

		case FCAL_STATUS_ERR_OFFLINE:
			SF_DMSG1("Fibre Channel Offline");
			mutex_enter(&target->sft_mutex);
			if (!(target->sft_state & SF_TARGET_OFFLINE)) {
				target->sft_state |= (SF_TARGET_BUSY
				    | SF_TARGET_MARK);
			}
			mutex_exit(&target->sft_mutex);
			(void) ndi_event_retrieve_cookie(sf->sf_event_hdl,
			    target->sft_dip, FCAL_REMOVE_EVENT,
			    &sf_remove_eid, NDI_EVENT_NOPASS);
			(void) ndi_event_run_callbacks(sf->sf_event_hdl,
			    target->sft_dip, sf_remove_eid, NULL);
			pkt->pkt_reason = CMD_TRAN_ERR;
			pkt->pkt_statistics |= STAT_BUS_RESET;
			break;

		case FCAL_STATUS_MAX_XCHG_EXCEEDED:
			sf_throttle(sf);
			sf->sf_use_lock = TRUE;
			pkt->pkt_reason = CMD_TRAN_ERR;
			pkt->pkt_state = STATE_GOT_BUS;
			pkt->pkt_statistics |= STAT_ABORTED;
			break;

		case FCAL_STATUS_TIMEOUT:
			SF_DMSG1("Fibre Channel Timeout");
			pkt->pkt_reason = CMD_TIMEOUT;
			break;

		case FCAL_STATUS_ERR_OVERRUN:
			SF_DMSG1("CMD_DATA_OVR");
			pkt->pkt_reason = CMD_DATA_OVR;
			break;

		case FCAL_STATUS_UNKNOWN_CQ_TYPE:
			SF_DMSG1("Unknown CQ type");
			pkt->pkt_reason = CMD_TRAN_ERR;
			break;

		case FCAL_STATUS_BAD_SEG_CNT:
			SF_DMSG1("Bad SEG CNT");
			pkt->pkt_reason = CMD_TRAN_ERR;
			break;

		case FCAL_STATUS_BAD_XID:
			SF_DMSG1("Fibre Channel Invalid X_ID");
			pkt->pkt_reason = CMD_TRAN_ERR;
			break;

		case FCAL_STATUS_XCHG_BUSY:
			SF_DMSG1("Fibre Channel Exchange Busy");
			pkt->pkt_reason = CMD_TRAN_ERR;
			break;

		case FCAL_STATUS_INSUFFICIENT_CQES:
			SF_DMSG1("Insufficient CQEs");
			pkt->pkt_reason = CMD_TRAN_ERR;
			break;

		case FCAL_STATUS_ALLOC_FAIL:
			SF_DMSG1("ALLOC FAIL");
			pkt->pkt_reason = CMD_TRAN_ERR;
			break;

		case FCAL_STATUS_BAD_SID:
			SF_DMSG1("Fibre Channel Invalid S_ID");
			pkt->pkt_reason = CMD_TRAN_ERR;
			break;

		case FCAL_STATUS_INCOMPLETE_DMA_ERR:
			if (sf_core && (sf_core & SF_CORE_INCOMPLETE_DMA)) {
				sf_token = (int *)(uintptr_t)
				    fpkt->fcal_socal_request.\
				    sr_soc_hdr.sh_request_token;
				(void) soc_take_core(sf->sf_sochandle,
				    sf->sf_socp);
				sf_core = 0;
			}
			msg2 =
			"INCOMPLETE DMA XFER due to bad SOC+ card, replace HBA";
			pkt->pkt_reason = CMD_INCOMPLETE;
			pkt->pkt_state = STATE_GOT_BUS;
			pkt->pkt_statistics |= STAT_ABORTED;
			break;

		case FCAL_STATUS_CRC_ERR:
			msg2 = "Fibre Channel CRC Error on frames";
			pkt->pkt_reason = CMD_INCOMPLETE;
			pkt->pkt_state = STATE_GOT_BUS;
			pkt->pkt_statistics |= STAT_ABORTED;
			break;

		case FCAL_STATUS_NO_SEQ_INIT:
			SF_DMSG1("Fibre Channel Seq Init Error");
			pkt->pkt_reason = CMD_TRAN_ERR;
			break;

		case  FCAL_STATUS_OPEN_FAIL:
			pkt->pkt_reason = CMD_TRAN_ERR;
			SF_DMSG1("Fibre Channel Open Failure");
			if ((target->sft_state & (SF_TARGET_BUSY |
			    SF_TARGET_MARK | SF_TARGET_OFFLINE)) == 0) {
				sf_log(sf, CE_NOTE,
				    "!Open failure to target 0x%x "
				    "forcing LIP\n",
				    sf_alpa_to_switch[target->sft_al_pa]);
				sf_force_lip(sf);
			}
			break;


		case FCAL_STATUS_ONLINE_TIMEOUT:
			SF_DMSG1("Fibre Channel Online Timeout");
			pkt->pkt_reason = CMD_TRAN_ERR;
			break;

		default:
			SF_DMSG1("Unknown FC Status");
			pkt->pkt_reason = CMD_TRAN_ERR;
			break;
		}
	}

#ifdef	DEBUG
	/*
	 * msg1 will be non-NULL if we've detected some sort of error
	 */
	if (msg1 != NULL && sfdebug >= 4) {
		sf_log(sf, CE_WARN,
		    "!Transport error on cmd=0x%p target=0x%x:  %s\n",
		    (void *)fpkt, pkt->pkt_address.a_target, msg1);
	}
#endif

	if (msg2 != NULL) {
		sf_log(sf, CE_WARN, "!Transport error on target=0x%x:  %s\n",
		    pkt->pkt_address.a_target, msg2);
	}

	ncmds = fpkt->fcal_ncmds;
	ASSERT(ncmds >= 0);
	if (ncmds >= (sf->sf_throttle - SF_HI_CMD_DELTA)) {
#ifdef DEBUG
		if (!sf->sf_use_lock) {
			SF_DEBUG(4, (sf, CE_NOTE, "use lock flag on\n"));
		}
#endif
		sf->sf_use_lock = TRUE;
	}

	mutex_enter(&sf->sf_cmd_mutex);
	sf->sf_ncmds = ncmds;
	sf_throttle_start(sf);
	mutex_exit(&sf->sf_cmd_mutex);

	if (!msg1 && !msg2)
		SF_DEBUG(6, (sf, CE_NOTE, "Completing pkt 0x%p\n",
		    (void *)pkt));
	if (pkt->pkt_comp != NULL) {
		(*pkt->pkt_comp)(pkt);
	}
}

#undef	SF_DMSG1



/*
 * start throttling for this instance
 */
static void
sf_throttle_start(struct sf *sf)
{
	struct sf_pkt *cmd, *prev_cmd = NULL;
	struct scsi_pkt *pkt;
	struct sf_target *target;


	ASSERT(mutex_owned(&sf->sf_cmd_mutex));

	cmd = sf->sf_pkt_head;
	while ((cmd != NULL) &&
	    (sf->sf_state == SF_STATE_ONLINE) &&
	    (sf->sf_ncmds < sf->sf_throttle)) {

		pkt = CMD2PKT(cmd);

		target = ADDR2TARGET(&pkt->pkt_address);
		if (target->sft_state & SF_TARGET_BUSY) {
			/* this command is busy -- go to next */
			ASSERT(cmd->cmd_state != SF_STATE_ISSUED);
			prev_cmd = cmd;
			cmd = cmd->cmd_next;
			continue;
		}

		ASSERT(cmd->cmd_state != SF_STATE_ISSUED);

		/* this cmd not busy and not issued */

		/* remove this packet from the queue */
		if (sf->sf_pkt_head == cmd) {
			/* this was the first packet */
			sf->sf_pkt_head = cmd->cmd_next;
		} else if (sf->sf_pkt_tail == cmd) {
			/* this was the last packet */
			sf->sf_pkt_tail = prev_cmd;
			if (prev_cmd != NULL) {
				prev_cmd->cmd_next = NULL;
			}
		} else {
			/* some packet in the middle of the queue */
			ASSERT(prev_cmd != NULL);
			prev_cmd->cmd_next = cmd->cmd_next;
		}
		cmd->cmd_flags &= ~CFLAG_IN_QUEUE;

		if (target->sft_state & SF_TARGET_OFFLINE) {
			mutex_exit(&sf->sf_cmd_mutex);
			pkt->pkt_reason = CMD_TRAN_ERR;
			if (pkt->pkt_comp != NULL) {
				(*pkt->pkt_comp)(cmd->cmd_pkt);
			}
		} else {
			sf_fill_ids(sf, cmd, target);
			if (sf_start_internal(sf, cmd) != TRAN_ACCEPT) {
				pkt->pkt_reason = CMD_TRAN_ERR;
				if (pkt->pkt_comp != NULL) {
					(*pkt->pkt_comp)(cmd->cmd_pkt);
				}
			}
		}
		mutex_enter(&sf->sf_cmd_mutex);
		cmd = sf->sf_pkt_head;
		prev_cmd = NULL;
	}
}


/*
 * called when the max exchange value is exceeded to throttle back commands
 */
static void
sf_throttle(struct sf *sf)
{
	int cmdmax = sf->sf_sochandle->fcal_cmdmax;


	mutex_enter(&sf->sf_cmd_mutex);

	sf->sf_flag = TRUE;

	if (sf->sf_ncmds > (cmdmax / 2)) {
		sf->sf_throttle = cmdmax / 2;
	} else {
		if (sf->sf_ncmds > SF_DECR_DELTA) {
			sf->sf_throttle = sf->sf_ncmds - SF_DECR_DELTA;
		} else {
			/*
			 * This case is just a safeguard, should not really
			 * happen(ncmds < SF_DECR_DELTA and MAX_EXCHG exceed
			 */
			sf->sf_throttle = SF_DECR_DELTA;
		}
	}
	mutex_exit(&sf->sf_cmd_mutex);

	sf = sf->sf_sibling;
	if (sf != NULL) {
		mutex_enter(&sf->sf_cmd_mutex);
		sf->sf_flag = TRUE;
		if (sf->sf_ncmds >= (cmdmax / 2)) {
			sf->sf_throttle = cmdmax / 2;
		} else {
			if (sf->sf_ncmds > SF_DECR_DELTA) {
				sf->sf_throttle = sf->sf_ncmds - SF_DECR_DELTA;
			} else {
				sf->sf_throttle = SF_DECR_DELTA;
			}
		}

		mutex_exit(&sf->sf_cmd_mutex);
	}
}


/*
 * sf watchdog routine, called for a timeout
 */
/*ARGSUSED*/
static void
sf_watch(void *arg)
{
	struct sf *sf;
	struct sf_els_hdr	*privp;
	static int count = 0, pscan_count = 0;
	int cmdmax, i, mescount = 0;
	struct sf_target *target;


	sf_watchdog_time += sf_watchdog_timeout;
	count++;
	pscan_count++;

	mutex_enter(&sf_global_mutex);
	sf_watch_running = 1;
	for (sf = sf_head; sf != NULL; sf = sf->sf_next) {

		mutex_exit(&sf_global_mutex);

		/* disable throttling while we're suspended */
		mutex_enter(&sf->sf_mutex);
		if (sf->sf_state & SF_STATE_SUSPENDED) {
			mutex_exit(&sf->sf_mutex);
			SF_DEBUG(1, (sf, CE_CONT,
			    "sf_watch, sf%d:throttle disabled "
			    "due to DDI_SUSPEND\n",
			    ddi_get_instance(sf->sf_dip)));
			mutex_enter(&sf_global_mutex);
			continue;
		}
		mutex_exit(&sf->sf_mutex);

		cmdmax = sf->sf_sochandle->fcal_cmdmax;

		if (sf->sf_take_core) {
			(void) soc_take_core(sf->sf_sochandle, sf->sf_socp);
		}

		mutex_enter(&sf->sf_cmd_mutex);

		if (!sf->sf_flag) {
			if (sf->sf_throttle < (cmdmax / 2)) {
				sf->sf_throttle = cmdmax / 2;
			} else if ((sf->sf_throttle += SF_INCR_DELTA) >
			    cmdmax) {
				sf->sf_throttle = cmdmax;
			}
		} else {
			sf->sf_flag = FALSE;
		}

		sf->sf_ncmds_exp_avg = (sf->sf_ncmds + sf->sf_ncmds_exp_avg)
		    >> 2;
		if ((sf->sf_ncmds <= (sf->sf_throttle - SF_LO_CMD_DELTA)) &&
		    (sf->sf_pkt_head == NULL)) {
#ifdef DEBUG
			if (sf->sf_use_lock) {
				SF_DEBUG(4, (sf, CE_NOTE,
				    "use lock flag off\n"));
			}
#endif
			sf->sf_use_lock = FALSE;
		}

		if (sf->sf_state == SF_STATE_ONLINE && sf->sf_pkt_head &&
		    sf->sf_ncmds < sf->sf_throttle) {
			sf_throttle_start(sf);
		}

		mutex_exit(&sf->sf_cmd_mutex);

		if (pscan_count >= sf_pool_scan_cnt) {
			if (sf->sf_ncmds_exp_avg < (sf->sf_cr_pool_cnt <<
			    SF_LOG2_ELEMS_IN_POOL) - SF_FREE_CR_EPSILON) {
				sf_crpool_free(sf);
			}
		}
		mutex_enter(&sf->sf_mutex);

		privp = sf->sf_els_list;
		while (privp != NULL) {
			if (privp->timeout < sf_watchdog_time) {
				/* timeout this command */
				privp = sf_els_timeout(sf, privp);
			} else if ((privp->timeout == SF_INVALID_TIMEOUT) &&
			    (privp->lip_cnt != sf->sf_lip_cnt)) {
				if (privp->prev != NULL) {
					privp->prev->next = privp->next;
				}
				if (sf->sf_els_list == privp) {
					sf->sf_els_list = privp->next;
				}
				if (privp->next != NULL) {
					privp->next->prev = privp->prev;
				}
				mutex_exit(&sf->sf_mutex);
				sf_els_free(privp->fpkt);
				mutex_enter(&sf->sf_mutex);
				privp = sf->sf_els_list;
			} else {
				privp = privp->next;
			}
		}

		if (sf->sf_online_timer && sf->sf_online_timer <
		    sf_watchdog_time) {
			for (i = 0; i < sf_max_targets; i++) {
				target = sf->sf_targets[i];
				if (target != NULL) {
					if (!mescount && target->sft_state &
					    SF_TARGET_BUSY) {
						sf_log(sf, CE_WARN, "!Loop "
						    "Unstable: Failed to bring "
						    "Loop Online\n");
						mescount = 1;
					}
					target->sft_state |= SF_TARGET_MARK;
				}
			}
			sf_finish_init(sf, sf->sf_lip_cnt);
			sf->sf_state = SF_STATE_INIT;
			sf->sf_online_timer = 0;
		}

		if (sf->sf_state == SF_STATE_ONLINE) {
			mutex_exit(&sf->sf_mutex);
			if (count >= sf_pkt_scan_cnt) {
				sf_check_targets(sf);
			}
		} else if ((sf->sf_state == SF_STATE_OFFLINE) &&
		    (sf->sf_timer < sf_watchdog_time)) {
			for (i = 0; i < sf_max_targets; i++) {
				target = sf->sf_targets[i];
				if ((target != NULL) &&
				    (target->sft_state &
				    SF_TARGET_BUSY)) {
					sf_log(sf, CE_WARN,
					    "!Offline Timeout\n");
					if (sf_core && (sf_core &
					    SF_CORE_OFFLINE_TIMEOUT)) {
						(void) soc_take_core(
						    sf->sf_sochandle,
						    sf->sf_socp);
						sf_core = 0;
					}
					break;
				}
			}
			sf_finish_init(sf, sf->sf_lip_cnt);
			sf->sf_state = SF_STATE_INIT;
			mutex_exit(&sf->sf_mutex);
		} else {
			mutex_exit(&sf->sf_mutex);
		}
		mutex_enter(&sf_global_mutex);
	}
	mutex_exit(&sf_global_mutex);
	if (count >= sf_pkt_scan_cnt) {
		count = 0;
	}
	if (pscan_count >= sf_pool_scan_cnt) {
		pscan_count = 0;
	}

	/* reset timeout */
	sf_watchdog_id = timeout(sf_watch, (caddr_t)0, sf_watchdog_tick);

	/* signal waiting thread */
	mutex_enter(&sf_global_mutex);
	sf_watch_running = 0;
	cv_broadcast(&sf_watch_cv);
	mutex_exit(&sf_global_mutex);
}


/*
 * called during a timeout to check targets
 */
static void
sf_check_targets(struct sf *sf)
{
	struct sf_target *target;
	int i;
	struct sf_pkt *cmd;
	struct scsi_pkt *pkt;
	int lip_cnt;

	mutex_enter(&sf->sf_mutex);
	lip_cnt = sf->sf_lip_cnt;
	mutex_exit(&sf->sf_mutex);

	/* check scan all possible targets */
	for (i = 0; i < sf_max_targets; i++) {
		target = sf->sf_targets[i];
		while (target != NULL) {
			mutex_enter(&target->sft_pkt_mutex);
			if (target->sft_alive && target->sft_scan_count !=
			    sf_target_scan_cnt) {
				target->sft_alive = 0;
				target->sft_scan_count++;
				mutex_exit(&target->sft_pkt_mutex);
				return;
			}
			target->sft_alive = 0;
			target->sft_scan_count = 0;
			cmd = target->sft_pkt_head;
			while (cmd != (struct sf_pkt *)&target->sft_pkt_head) {
				mutex_enter(&cmd->cmd_abort_mutex);
				if (cmd->cmd_state == SF_STATE_ISSUED &&
				    ((cmd->cmd_timeout && sf_watchdog_time >
#ifdef	DEBUG
				    cmd->cmd_timeout) || sf_abort_flag)) {
					sf_abort_flag = 0;
#else
					cmd->cmd_timeout))) {
#endif
					cmd->cmd_timeout = 0;
	/* prevent reset from getting at this packet */
					cmd->cmd_state = SF_STATE_ABORTING;
					mutex_exit(&cmd->cmd_abort_mutex);
					mutex_exit(&target->sft_pkt_mutex);
					sf->sf_stats.tstats[i].timeouts++;
					if (sf_target_timeout(sf, cmd))
						return;
					else {
						if (lip_cnt != sf->sf_lip_cnt) {
							return;
						} else {
							mutex_enter(&target->
							    sft_pkt_mutex);
							cmd = target->
							    sft_pkt_head;
						}
					}
	/*
	 * if the abort and lip fail, a reset will be carried out.
	 * But the reset will ignore this packet. We have waited at least
	 * 20 seconds after the initial timeout. Now, complete it here.
	 * This also takes care of spurious bad aborts.
	 */
				} else if ((cmd->cmd_state ==
				    SF_STATE_ABORTING) && (cmd->cmd_timeout
				    <= sf_watchdog_time)) {
					cmd->cmd_state = SF_STATE_IDLE;
					mutex_exit(&cmd->cmd_abort_mutex);
					mutex_exit(&target->sft_pkt_mutex);
					SF_DEBUG(1, (sf, CE_NOTE,
					    "Command 0x%p to sft 0x%p"
					    " delayed release\n",
					    (void *)cmd, (void *)target));
					pkt = cmd->cmd_pkt;
					pkt->pkt_statistics |=
					    (STAT_TIMEOUT|STAT_ABORTED);
					pkt->pkt_reason = CMD_TIMEOUT;
					if (pkt->pkt_comp) {
						scsi_hba_pkt_comp(pkt);
					/* handle deferred_destroy case */
					} else {
						if ((cmd->cmd_block->fcp_cntl.
						    cntl_reset == 1) ||
						    (cmd->cmd_block->
						    fcp_cntl.cntl_abort_tsk ==
						    1)) {
							cmd->cmd_block->
							    fcp_cntl.
							    cntl_reset = 0;
							cmd->cmd_block->
							    fcp_cntl.
							    cntl_abort_tsk = 0;
							cmd->cmd_fp_pkt->
							    fcal_pkt_comp =
							    sf_cmd_callback;
							/* for cache */
							sf_scsi_destroy_pkt
							    (&pkt->pkt_address,
							    pkt);
						}
					}
					mutex_enter(&target->sft_pkt_mutex);
					cmd = target->sft_pkt_head;
				} else {
					mutex_exit(&cmd->cmd_abort_mutex);
					cmd = cmd->cmd_forw;
				}
			}
			mutex_exit(&target->sft_pkt_mutex);
			target = target->sft_next_lun;
		}
	}
}


/*
 * a command to a target has timed out
 * return TRUE iff cmd abort failed or timed out, else return FALSE
 */
static int
sf_target_timeout(struct sf *sf, struct sf_pkt *cmd)
{
	int rval;
	struct scsi_pkt *pkt;
	struct fcal_packet *fpkt;
	int tgt_id;
	int retval = FALSE;


	SF_DEBUG(1, (sf, CE_NOTE, "Command 0x%p to target %x timed out\n",
	    (void *)cmd->cmd_fp_pkt, cmd->cmd_pkt->pkt_address.a_target));

	fpkt = cmd->cmd_fp_pkt;

	if (sf_core && (sf_core & SF_CORE_CMD_TIMEOUT)) {
		sf_token = (int *)(uintptr_t)
		    fpkt->fcal_socal_request.sr_soc_hdr.\
		    sh_request_token;
		(void) soc_take_core(sf->sf_sochandle, sf->sf_socp);
		sf_core = 0;
	}

	/* call the transport to abort a command */
	rval = soc_abort(sf->sf_sochandle, sf->sf_socp,
	    sf->sf_sochandle->fcal_portno, fpkt, 1);

	switch (rval) {
	case FCAL_ABORTED:
		SF_DEBUG(1, (sf, CE_NOTE, "Command Abort succeeded\n"));
		pkt = cmd->cmd_pkt;
		cmd->cmd_state = SF_STATE_IDLE;
		pkt->pkt_statistics |= (STAT_TIMEOUT|STAT_ABORTED);
		pkt->pkt_reason = CMD_TIMEOUT;
		if (pkt->pkt_comp != NULL) {
			(*pkt->pkt_comp)(pkt);
		}
		break;				/* success */

	case FCAL_ABORT_FAILED:
		SF_DEBUG(1, (sf, CE_NOTE, "Command Abort failed at target\n"));
		pkt = cmd->cmd_pkt;
		cmd->cmd_state = SF_STATE_IDLE;
		pkt->pkt_reason = CMD_TIMEOUT;
		pkt->pkt_statistics |= STAT_TIMEOUT;
		tgt_id = pkt->pkt_address.a_target;
		sf->sf_stats.tstats[tgt_id].abts_failures++;
		if (pkt->pkt_comp != NULL) {
			(*pkt->pkt_comp)(pkt);
		}
		break;

	case FCAL_BAD_ABORT:
		if (sf_core && (sf_core & SF_CORE_BAD_ABORT)) {
			sf_token = (int *)(uintptr_t)fpkt->fcal_socal_request.\
			    sr_soc_hdr.sh_request_token;
			(void) soc_take_core(sf->sf_sochandle, sf->sf_socp);
			sf_core = 0;
		}
		SF_DEBUG(1, (sf, CE_NOTE, "Command Abort bad abort\n"));
		cmd->cmd_timeout = sf_watchdog_time + cmd->cmd_pkt->pkt_time
		    + 20;
		break;

	case FCAL_TIMEOUT:
		retval = TRUE;
		break;

	default:
		pkt = cmd->cmd_pkt;
		tgt_id = pkt->pkt_address.a_target;
		sf_log(sf, CE_WARN,
		"Command Abort failed target 0x%x, forcing a LIP\n", tgt_id);
		if (sf_core && (sf_core & SF_CORE_ABORT_TIMEOUT)) {
			sf_token = (int *)(uintptr_t)fpkt->fcal_socal_request.\
			    sr_soc_hdr.sh_request_token;
			(void) soc_take_core(sf->sf_sochandle, sf->sf_socp);
			sf_core = 0;
		}
		sf_force_lip(sf);
		retval = TRUE;
		break;
	}

	return (retval);
}


/*
 * an ELS command has timed out
 * return ???
 */
static struct sf_els_hdr *
sf_els_timeout(struct sf *sf, struct sf_els_hdr *privp)
{
	struct fcal_packet *fpkt;
	int rval, dflag, timeout = SF_ELS_TIMEOUT;
	uint_t lip_cnt = privp->lip_cnt;
	uchar_t els_code = privp->els_code;
	struct sf_target *target = privp->target;
	char what[64];

	fpkt = privp->fpkt;
	dflag = privp->delayed_retry;
	/* use as temporary state variable */
	privp->timeout = SF_INVALID_TIMEOUT;
	mutex_exit(&sf->sf_mutex);

	if (privp->fpkt->fcal_pkt_comp == sf_els_callback) {
		/*
		 * take socal core if required. Timeouts for IB and hosts
		 * are not very interesting, so we take socal core only
		 * if the timeout is *not* for a IB or host.
		 */
		if (sf_core && (sf_core & SF_CORE_ELS_TIMEOUT) &&
		    ((sf_alpa_to_switch[privp->dest_nport_id] &
		    0x0d) != 0x0d) && ((privp->dest_nport_id != 1) ||
		    (privp->dest_nport_id != 2) ||
		    (privp->dest_nport_id != 4) ||
		    (privp->dest_nport_id != 8) ||
		    (privp->dest_nport_id != 0xf))) {
			sf_token = (int *)(uintptr_t)fpkt->fcal_socal_request.\
			    sr_soc_hdr.sh_request_token;
			(void) soc_take_core(sf->sf_sochandle, sf->sf_socp);
			sf_core = 0;
		}
		(void) sprintf(what, "ELS 0x%x", privp->els_code);
	} else if (privp->fpkt->fcal_pkt_comp == sf_reportlun_callback) {
		if (sf_core && (sf_core & SF_CORE_REPORTLUN_TIMEOUT)) {
			sf_token = (int *)(uintptr_t)fpkt->fcal_socal_request.\
			    sr_soc_hdr.sh_request_token;
			(void) soc_take_core(sf->sf_sochandle, sf->sf_socp);
			sf_core = 0;
		}
		timeout = SF_FCP_TIMEOUT;
		(void) sprintf(what, "REPORT_LUNS");
	} else if (privp->fpkt->fcal_pkt_comp == sf_inq_callback) {
		if (sf_core && (sf_core & SF_CORE_INQUIRY_TIMEOUT)) {
			sf_token = (int *)(uintptr_t)
			    fpkt->fcal_socal_request.\
			    sr_soc_hdr.sh_request_token;
			(void) soc_take_core(sf->sf_sochandle, sf->sf_socp);
			sf_core = 0;
		}
		timeout = SF_FCP_TIMEOUT;
		(void) sprintf(what, "INQUIRY to LUN 0x%lx",
		    (long)SCSA_LUN(target));
	} else {
		(void) sprintf(what, "UNKNOWN OPERATION");
	}

	if (dflag) {
		/* delayed retry */
		SF_DEBUG(2, (sf, CE_CONT,
		    "!sf%d: %s to target %x delayed retry\n",
		    ddi_get_instance(sf->sf_dip), what,
		    sf_alpa_to_switch[privp->dest_nport_id]));
		privp->delayed_retry = FALSE;
		goto try_again;
	}

	sf_log(sf, CE_NOTE, "!%s to target 0x%x alpa 0x%x timed out\n",
	    what, sf_alpa_to_switch[privp->dest_nport_id],
	    privp->dest_nport_id);

	rval = soc_abort(sf->sf_sochandle, sf->sf_socp, sf->sf_sochandle
	    ->fcal_portno, fpkt, 1);
	if (rval == FCAL_ABORTED || rval == FCAL_ABORT_FAILED) {
	SF_DEBUG(1, (sf, CE_NOTE, "!%s abort to al_pa %x succeeded\n",
	    what, privp->dest_nport_id));
try_again:

		mutex_enter(&sf->sf_mutex);
		if (privp->prev != NULL) {
			privp->prev->next = privp->next;
		}
		if (sf->sf_els_list == privp) {
			sf->sf_els_list = privp->next;
		}
		if (privp->next != NULL) {
			privp->next->prev = privp->prev;
		}
		privp->prev = privp->next = NULL;
		if (lip_cnt == sf->sf_lip_cnt) {
			privp->timeout = sf_watchdog_time + timeout;
			if ((++(privp->retries) < sf_els_retries) ||
			    (dflag && (privp->retries < SF_BSY_RETRIES))) {
				mutex_exit(&sf->sf_mutex);
				sf_log(sf, CE_NOTE,
				    "!%s to target 0x%x retrying\n",
				    what,
				    sf_alpa_to_switch[privp->dest_nport_id]);
				if (sf_els_transport(sf, privp) == 1) {
					mutex_enter(&sf->sf_mutex);
					return (sf->sf_els_list); /* success */
				}
				mutex_enter(&sf->sf_mutex);
				fpkt = NULL;
			}
			if ((lip_cnt == sf->sf_lip_cnt) &&
			    (els_code != LA_ELS_LOGO)) {
				if (target != NULL) {
					sf_offline_target(sf, target);
				}
				if (sf->sf_lip_cnt == lip_cnt) {
					sf->sf_device_count--;
					ASSERT(sf->sf_device_count >= 0);
					if (sf->sf_device_count == 0) {
						sf_finish_init(sf,
						    sf->sf_lip_cnt);
					}
				}
			}
			privp = sf->sf_els_list;
			mutex_exit(&sf->sf_mutex);
			if (fpkt != NULL) {
				sf_els_free(fpkt);
			}
		} else {
			mutex_exit(&sf->sf_mutex);
			sf_els_free(privp->fpkt);
			privp = NULL;
		}
	} else {
		if (sf_core && (sf_core & SF_CORE_ELS_FAILED)) {
			sf_token = (int *)(uintptr_t)
			    fpkt->fcal_socal_request.\
			    sr_soc_hdr.sh_request_token;
			(void) soc_take_core(sf->sf_sochandle, sf->sf_socp);
			sf_core = 0;
		}
		sf_log(sf, CE_NOTE, "%s abort to target 0x%x failed. "
		    "status=0x%x, forcing LIP\n", what,
		    sf_alpa_to_switch[privp->dest_nport_id], rval);
		privp = NULL;
		if (sf->sf_lip_cnt == lip_cnt) {
			sf_force_lip(sf);
		}
	}

	mutex_enter(&sf->sf_mutex);
	return (privp);
}


/*
 * called by timeout when a reset times out
 */
/*ARGSUSED*/
static void
sf_check_reset_delay(void *arg)
{
	struct sf *sf;
	struct sf_target *target;
	struct sf_reset_list *rp, *tp;
	uint_t lip_cnt, reset_timeout_flag = FALSE;
	clock_t lb;

	lb = ddi_get_lbolt();

	mutex_enter(&sf_global_mutex);

	sf_reset_timeout_id = 0;

	for (sf = sf_head; sf != NULL; sf = sf->sf_next) {

		mutex_exit(&sf_global_mutex);
		mutex_enter(&sf->sf_mutex);

		/* is this type cast needed? */
		tp = (struct sf_reset_list *)&sf->sf_reset_list;

		rp = sf->sf_reset_list;
		while (rp != NULL) {
			if (((rp->timeout - lb) < 0) &&
			    (rp->lip_cnt == sf->sf_lip_cnt)) {
				tp->next = rp->next;
				mutex_exit(&sf->sf_mutex);
				target = rp->target;
				lip_cnt = rp->lip_cnt;
				kmem_free(rp, sizeof (struct sf_reset_list));
				/* abort all cmds for this target */
				while (target) {
					sf_abort_all(sf, target, FALSE,
					    lip_cnt, TRUE);
					mutex_enter(&target->sft_mutex);
					if (lip_cnt == sf->sf_lip_cnt) {
						target->sft_state &=
						    ~SF_TARGET_BUSY;
					}
					mutex_exit(&target->sft_mutex);
					target = target->sft_next_lun;
				}
				mutex_enter(&sf->sf_mutex);
				tp = (struct sf_reset_list *)
				    &sf->sf_reset_list;
				rp = sf->sf_reset_list;
				lb = ddi_get_lbolt();
			} else if (rp->lip_cnt != sf->sf_lip_cnt) {
				tp->next = rp->next;
				kmem_free(rp, sizeof (struct sf_reset_list));
				rp = tp->next;
			} else {
				reset_timeout_flag = TRUE;
				tp = rp;
				rp = rp->next;
			}
		}
		mutex_exit(&sf->sf_mutex);
		mutex_enter(&sf_global_mutex);
	}

	if (reset_timeout_flag && (sf_reset_timeout_id == 0)) {
		sf_reset_timeout_id = timeout(sf_check_reset_delay,
		    NULL, drv_usectohz(SF_TARGET_RESET_DELAY));
	}

	mutex_exit(&sf_global_mutex);
}


/*
 * called to "reset the bus", i.e. force loop initialization (and address
 * re-negotiation)
 */
static void
sf_force_lip(struct sf *sf)
{
	int i;
	struct sf_target *target;


	/* disable restart of lip if we're suspended */
	mutex_enter(&sf->sf_mutex);
	if (sf->sf_state & SF_STATE_SUSPENDED) {
		mutex_exit(&sf->sf_mutex);
		SF_DEBUG(1, (sf, CE_CONT,
		    "sf_force_lip, sf%d: lip restart disabled "
		    "due to DDI_SUSPEND\n",
		    ddi_get_instance(sf->sf_dip)));
		return;
	}

	sf_log(sf, CE_NOTE, "Forcing lip\n");

	for (i = 0; i < sf_max_targets; i++) {
		target = sf->sf_targets[i];
		while (target != NULL) {
			mutex_enter(&target->sft_mutex);
			if (!(target->sft_state & SF_TARGET_OFFLINE))
				target->sft_state |= SF_TARGET_BUSY;
			mutex_exit(&target->sft_mutex);
			target = target->sft_next_lun;
		}
	}

	sf->sf_lip_cnt++;
	sf->sf_timer = sf_watchdog_time + SF_OFFLINE_TIMEOUT;
	sf->sf_state = SF_STATE_OFFLINE;
	mutex_exit(&sf->sf_mutex);
	sf->sf_stats.lip_count++;		/* no mutex for this? */

#ifdef DEBUG
	/* are we allowing LIPs ?? */
	if (sf_lip_flag != 0) {
#endif
		/* call the transport to force loop initialization */
		if (((i = soc_force_lip(sf->sf_sochandle, sf->sf_socp,
		    sf->sf_sochandle->fcal_portno, 1,
		    FCAL_FORCE_LIP)) != FCAL_SUCCESS) &&
		    (i != FCAL_TIMEOUT)) {
			/* force LIP failed */
			if (sf_core && (sf_core & SF_CORE_LIP_FAILED)) {
				(void) soc_take_core(sf->sf_sochandle,
				    sf->sf_socp);
				sf_core = 0;
			}
#ifdef DEBUG
			/* are we allowing reset after LIP failed ?? */
			if (sf_reset_flag != 0) {
#endif
				/* restart socal after resetting it */
				sf_log(sf, CE_NOTE,
				    "!Force lip failed Status code 0x%x."
				    " Reseting\n", i);
				/* call transport to force a reset */
				soc_force_reset(sf->sf_sochandle, sf->sf_socp,
				    sf->sf_sochandle->fcal_portno, 1);
#ifdef	DEBUG
			}
#endif
		}
#ifdef	DEBUG
	}
#endif
}


/*
 * called by the transport when an unsolicited ELS is received
 */
static void
sf_unsol_els_callback(void *arg, soc_response_t *srp, caddr_t payload)
{
	struct sf *sf = (struct sf *)arg;
	els_payload_t	*els = (els_payload_t *)payload;
	struct la_els_rjt *rsp;
	int	i, tgt_id;
	uchar_t dest_id;
	struct fcal_packet *fpkt;
	fc_frame_header_t *hp;
	struct sf_els_hdr *privp;


	if ((els == NULL) || ((i = srp->sr_soc_hdr.sh_byte_cnt) == 0)) {
		return;
	}

	if (i > SOC_CQE_PAYLOAD) {
		i = SOC_CQE_PAYLOAD;
	}

	dest_id = (uchar_t)srp->sr_fc_frame_hdr.s_id;
	tgt_id = sf_alpa_to_switch[dest_id];

	switch (els->els_cmd.c.ls_command) {

	case LA_ELS_LOGO:
		/*
		 * logout received -- log the fact
		 */
		sf->sf_stats.tstats[tgt_id].logouts_recvd++;
		sf_log(sf, CE_NOTE, "!LOGO recvd from target %x, %s\n",
		    tgt_id,
		    sf_lip_on_plogo ? "Forcing LIP...." : "");
		if (sf_lip_on_plogo) {
			sf_force_lip(sf);
		}
		break;

	default:  /* includes LA_ELS_PLOGI */
		/*
		 * something besides a logout received -- we don't handle
		 * this so send back a reject saying its unsupported
		 */

		sf_log(sf, CE_NOTE, "!ELS 0x%x recvd from target 0x%x\n",
		    els->els_cmd.c.ls_command, tgt_id);


		/* allocate room for a response */
		if (sf_els_alloc(sf, dest_id, sizeof (struct sf_els_hdr),
		    sizeof (struct la_els_rjt), sizeof (union sf_els_rsp),
		    (caddr_t *)&privp, (caddr_t *)&rsp) == NULL) {
			break;
		}

		fpkt = privp->fpkt;

		/* fill in pkt header */
		hp = &fpkt->fcal_socal_request.sr_fc_frame_hdr;
		hp->r_ctl = R_CTL_ELS_RSP;
		hp->f_ctl = F_CTL_LAST_SEQ | F_CTL_XCHG_CONTEXT;
		hp->ox_id = srp->sr_fc_frame_hdr.ox_id;
		hp->rx_id = srp->sr_fc_frame_hdr.rx_id;
		fpkt->fcal_socal_request.sr_cqhdr.cq_hdr_type =
		    CQ_TYPE_OUTBOUND;

		fpkt->fcal_socal_request.sr_soc_hdr.sh_seg_cnt = 1;

		/* fill in response */
		rsp->ls_code = LA_ELS_RJT;	/* reject this ELS */
		rsp->mbz[0] = 0;
		rsp->mbz[1] = 0;
		rsp->mbz[2] = 0;
		((struct la_els_logi *)privp->rsp)->ls_code = LA_ELS_ACC;
		*((int *)&rsp->reserved) = 0;
		rsp->reason_code = RJT_UNSUPPORTED;
		privp->retries = sf_els_retries;
		privp->els_code = LA_ELS_RJT;
		privp->timeout = (unsigned)0xffffffff;
		(void) sf_els_transport(sf, privp);
		break;
	}
}


/*
 * Error logging, printing, and debug print routines
 */

/*PRINTFLIKE3*/
static void
sf_log(struct sf *sf, int level, const char *fmt, ...)
{
	char buf[256];
	dev_info_t *dip;
	va_list ap;

	if (sf != NULL) {
		dip = sf->sf_dip;
	} else {
		dip = NULL;
	}

	va_start(ap, fmt);
	(void) vsprintf(buf, fmt, ap);
	va_end(ap);
	scsi_log(dip, "sf", level, buf);
}


/*
 * called to get some sf kstats -- return 0 on success else return errno
 */
static int
sf_kstat_update(kstat_t *ksp, int rw)
{
	struct sf *sf;

	if (rw == KSTAT_WRITE) {
		/* can't write */
		return (EACCES);
	}

	sf = ksp->ks_private;
	sf->sf_stats.ncmds = sf->sf_ncmds;
	sf->sf_stats.throttle_limit = sf->sf_throttle;
	sf->sf_stats.cr_pool_size = sf->sf_cr_pool_cnt;

	return (0);				/* success */
}


/*
 * Unix Entry Points
 */

/*
 * driver entry point for opens on control device
 */
/* ARGSUSED */
static int
sf_open(dev_t *dev_p, int flag, int otyp, cred_t *cred_p)
{
	dev_t dev = *dev_p;
	struct sf *sf;


	/* just ensure soft state exists for this device */
	sf = ddi_get_soft_state(sf_state, SF_MINOR2INST(getminor(dev)));
	if (sf == NULL) {
		return (ENXIO);
	}

	++(sf->sf_check_n_close);

	return (0);
}


/*
 * driver entry point for last close on control device
 */
/* ARGSUSED */
static int
sf_close(dev_t dev, int flag, int otyp, cred_t *cred_p)
{
	struct sf *sf;

	sf = ddi_get_soft_state(sf_state, SF_MINOR2INST(getminor(dev)));
	if (sf == NULL) {
		return (ENXIO);
	}

	if (!sf->sf_check_n_close) { /* if this flag is zero */
		cmn_err(CE_WARN, "sf%d: trying to close unopened instance",
		    SF_MINOR2INST(getminor(dev)));
		return (ENODEV);
	} else {
		--(sf->sf_check_n_close);
	}
	return (0);
}


/*
 * driver entry point for sf ioctl commands
 */
/* ARGSUSED */
static int
sf_ioctl(dev_t dev,
    int cmd, intptr_t arg, int mode, cred_t *cred_p, int *rval_p)
{
	struct sf *sf;
	struct sf_target *target;
	uchar_t al_pa;
	struct sf_al_map map;
	int cnt, i;
	int	retval;				/* return value */
	struct devctl_iocdata *dcp;
	dev_info_t *cdip;
	struct scsi_address ap;
	scsi_hba_tran_t *tran;


	sf = ddi_get_soft_state(sf_state, SF_MINOR2INST(getminor(dev)));
	if (sf == NULL) {
		return (ENXIO);
	}

	/* handle all ioctls */
	switch (cmd) {

	/*
	 * We can use the generic implementation for these ioctls
	 */
	case DEVCTL_DEVICE_GETSTATE:
	case DEVCTL_DEVICE_ONLINE:
	case DEVCTL_DEVICE_OFFLINE:
	case DEVCTL_BUS_GETSTATE:
		return (ndi_devctl_ioctl(sf->sf_dip, cmd, arg, mode, 0));

	/*
	 * return FC map
	 */
	case SFIOCGMAP:
		if ((sf->sf_lilp_map->lilp_magic != FCAL_LILP_MAGIC &&
		    sf->sf_lilp_map->lilp_magic != FCAL_BADLILP_MAGIC) ||
		    sf->sf_state != SF_STATE_ONLINE) {
			retval = ENOENT;
			goto dun;
		}
		mutex_enter(&sf->sf_mutex);
		if (sf->sf_lilp_map->lilp_magic == FCAL_BADLILP_MAGIC) {
			int i, j = 0;

			/* Need to generate a fake lilp map */
			for (i = 0; i < sf_max_targets; i++) {
				if (sf->sf_targets[i])
					sf->sf_lilp_map->lilp_alpalist[j++] =
					    sf->sf_targets[i]->
					    sft_hard_address;
			}
			sf->sf_lilp_map->lilp_length = (uchar_t)j;
		}
		cnt = sf->sf_lilp_map->lilp_length;
		map.sf_count = (short)cnt;
		bcopy((caddr_t)&sf->sf_sochandle->fcal_n_wwn,
		    (caddr_t)&map.sf_hba_addr.sf_node_wwn,
		    sizeof (la_wwn_t));
		bcopy((caddr_t)&sf->sf_sochandle->fcal_p_wwn,
		    (caddr_t)&map.sf_hba_addr.sf_port_wwn,
		    sizeof (la_wwn_t));
		map.sf_hba_addr.sf_al_pa = sf->sf_al_pa;
		map.sf_hba_addr.sf_hard_address = 0;
		map.sf_hba_addr.sf_inq_dtype = DTYPE_UNKNOWN;
		for (i = 0; i < cnt; i++) {
			al_pa = sf->sf_lilp_map->lilp_alpalist[i];
			map.sf_addr_pair[i].sf_al_pa = al_pa;
			if (al_pa == sf->sf_al_pa) {
				(void) bcopy((caddr_t)&sf->sf_sochandle
				    ->fcal_n_wwn, (caddr_t)&map.
				    sf_addr_pair[i].sf_node_wwn,
				    sizeof (la_wwn_t));
				(void) bcopy((caddr_t)&sf->sf_sochandle
				    ->fcal_p_wwn, (caddr_t)&map.
				    sf_addr_pair[i].sf_port_wwn,
				    sizeof (la_wwn_t));
				map.sf_addr_pair[i].sf_hard_address =
				    al_pa;
				map.sf_addr_pair[i].sf_inq_dtype =
				    DTYPE_PROCESSOR;
				continue;
			}
			target = sf->sf_targets[sf_alpa_to_switch[
			    al_pa]];
			if (target != NULL) {
				mutex_enter(&target->sft_mutex);
				if (!(target->sft_state &
				    (SF_TARGET_OFFLINE |
				    SF_TARGET_BUSY))) {
					bcopy((caddr_t)&target->
					    sft_node_wwn,
					    (caddr_t)&map.sf_addr_pair
					    [i].sf_node_wwn,
					    sizeof (la_wwn_t));
					bcopy((caddr_t)&target->
					    sft_port_wwn,
					    (caddr_t)&map.sf_addr_pair
					    [i].sf_port_wwn,
					    sizeof (la_wwn_t));
					map.sf_addr_pair[i].
					    sf_hard_address
					    = target->sft_hard_address;
					map.sf_addr_pair[i].
					    sf_inq_dtype
					    = target->sft_device_type;
					mutex_exit(&target->sft_mutex);
					continue;
				}
				mutex_exit(&target->sft_mutex);
			}
			bzero((caddr_t)&map.sf_addr_pair[i].
			    sf_node_wwn, sizeof (la_wwn_t));
			bzero((caddr_t)&map.sf_addr_pair[i].
			    sf_port_wwn, sizeof (la_wwn_t));
			map.sf_addr_pair[i].sf_inq_dtype =
			    DTYPE_UNKNOWN;
		}
		mutex_exit(&sf->sf_mutex);
		if (ddi_copyout((caddr_t)&map, (caddr_t)arg,
		    sizeof (struct sf_al_map), mode) != 0) {
			retval = EFAULT;
			goto dun;
		}
		break;

	/*
	 * handle device control ioctls
	 */
	case DEVCTL_DEVICE_RESET:
		if (ndi_dc_allochdl((void *)arg, &dcp) != NDI_SUCCESS) {
			retval = EFAULT;
			goto dun;
		}
		if ((ndi_dc_getname(dcp) == NULL) ||
		    (ndi_dc_getaddr(dcp) == NULL)) {
			ndi_dc_freehdl(dcp);
			retval = EINVAL;
			goto dun;
		}
		cdip = ndi_devi_find(sf->sf_dip,
		    ndi_dc_getname(dcp), ndi_dc_getaddr(dcp));
		ndi_dc_freehdl(dcp);

		if (cdip == NULL) {
			retval = ENXIO;
			goto dun;
		}

		if ((target = sf_get_target_from_dip(sf, cdip)) == NULL) {
			retval = ENXIO;
			goto dun;
		}
		mutex_enter(&target->sft_mutex);
		if (!(target->sft_state & SF_TARGET_INIT_DONE)) {
			mutex_exit(&target->sft_mutex);
			retval = ENXIO;
			goto dun;
		}

		/* This is ugly */
		tran = kmem_zalloc(scsi_hba_tran_size(), KM_SLEEP);
		bcopy(target->sft_tran, tran, scsi_hba_tran_size());
		mutex_exit(&target->sft_mutex);
		ap.a_hba_tran = tran;
		ap.a_target = sf_alpa_to_switch[target->sft_al_pa];
		if (sf_reset(&ap, RESET_TARGET) == FALSE) {
			retval = EIO;
		} else {
			retval = 0;
		}
		kmem_free(tran, scsi_hba_tran_size());
		goto dun;

	case DEVCTL_BUS_QUIESCE:
	case DEVCTL_BUS_UNQUIESCE:
		retval = ENOTSUP;
		goto dun;

	case DEVCTL_BUS_RESET:
	case DEVCTL_BUS_RESETALL:
		sf_force_lip(sf);
		break;

	default:
		retval = ENOTTY;
		goto dun;
	}

	retval = 0;				/* success */

dun:
	return (retval);
}


/*
 * get the target given a DIP
 */
static struct sf_target *
sf_get_target_from_dip(struct sf *sf, dev_info_t *dip)
{
	int i;
	struct sf_target *target;


	/* scan each hash queue for the DIP in question */
	for (i = 0; i < SF_NUM_HASH_QUEUES; i++) {
		target = sf->sf_wwn_lists[i];
		while (target != NULL) {
			if (target->sft_dip == dip) {
				return (target); /* success: target found */
			}
			target = target->sft_next;
		}
	}
	return (NULL);				/* failure: target not found */
}


/*
 * called by the transport to get an event cookie
 */
static int
sf_bus_get_eventcookie(dev_info_t *dip, dev_info_t *rdip, char *name,
    ddi_eventcookie_t *event_cookiep)
{
	struct sf *sf;

	sf = ddi_get_soft_state(sf_state, ddi_get_instance(dip));
	if (sf == NULL) {
		/* can't find instance for this device */
		return (DDI_FAILURE);
	}

	return (ndi_event_retrieve_cookie(sf->sf_event_hdl, rdip, name,
	    event_cookiep, NDI_EVENT_NOPASS));

}


/*
 * called by the transport to add an event callback
 */
static int
sf_bus_add_eventcall(dev_info_t *dip, dev_info_t *rdip,
    ddi_eventcookie_t eventid, void (*callback)(dev_info_t *dip,
    ddi_eventcookie_t event, void *arg, void *impl_data), void *arg,
    ddi_callback_id_t *cb_id)
{
	struct sf *sf;

	sf = ddi_get_soft_state(sf_state, ddi_get_instance(dip));
	if (sf == NULL) {
		/* can't find instance for this device */
		return (DDI_FAILURE);
	}

	return (ndi_event_add_callback(sf->sf_event_hdl, rdip,
	    eventid, callback, arg, NDI_SLEEP, cb_id));

}


/*
 * called by the transport to remove an event callback
 */
static int
sf_bus_remove_eventcall(dev_info_t *devi, ddi_callback_id_t cb_id)
{
	struct sf *sf;

	sf = ddi_get_soft_state(sf_state, ddi_get_instance(devi));
	if (sf == NULL) {
		/* can't find instance for this device */
		return (DDI_FAILURE);
	}

	return (ndi_event_remove_callback(sf->sf_event_hdl, cb_id));
}


/*
 * called by the transport to post an event
 */
static int
sf_bus_post_event(dev_info_t *dip, dev_info_t *rdip,
    ddi_eventcookie_t eventid, void *impldata)
{
	ddi_eventcookie_t remove_cookie, cookie;

	/* is this a remove event ?? */
	struct sf *sf = ddi_get_soft_state(sf_state, ddi_get_instance(dip));
	remove_cookie = ndi_event_tag_to_cookie(sf->sf_event_hdl,
	    SF_EVENT_TAG_REMOVE);

	if (remove_cookie == eventid) {
		struct sf_target *target;

		/* handle remove event */

		if (sf == NULL) {
			/* no sf instance for this device */
			return (NDI_FAILURE);
		}

		/* get the target for this event */
		if ((target = sf_get_target_from_dip(sf, rdip)) != NULL) {
			/*
			 * clear device info for this target and mark as
			 * not done
			 */
			mutex_enter(&target->sft_mutex);
			target->sft_dip = NULL;
			target->sft_state &= ~SF_TARGET_INIT_DONE;
			mutex_exit(&target->sft_mutex);
			return (NDI_SUCCESS); /* event handled */
		}

		/* no target for this event */
		return (NDI_FAILURE);
	}

	/* an insertion event */
	if (ndi_busop_get_eventcookie(dip, rdip, FCAL_INSERT_EVENT, &cookie)
	    != NDI_SUCCESS) {
		return (NDI_FAILURE);
	}

	return (ndi_post_event(dip, rdip, cookie, impldata));
}


/*
 * the sf hotplug daemon, one thread per sf instance
 */
static void
sf_hp_daemon(void *arg)
{
	struct sf *sf = (struct sf *)arg;
	struct sf_hp_elem *elem;
	struct sf_target *target;
	int tgt_id;
	callb_cpr_t cprinfo;

	CALLB_CPR_INIT(&cprinfo, &sf->sf_hp_daemon_mutex,
	    callb_generic_cpr, "sf_hp_daemon");

	mutex_enter(&sf->sf_hp_daemon_mutex);

	do {
		while (sf->sf_hp_elem_head != NULL) {

			/* save ptr to head of list */
			elem = sf->sf_hp_elem_head;

			/* take element off of list */
			if (sf->sf_hp_elem_head == sf->sf_hp_elem_tail) {
				/* element only one in list -- list now empty */
				sf->sf_hp_elem_head = NULL;
				sf->sf_hp_elem_tail = NULL;
			} else {
				/* remove element from head of list */
				sf->sf_hp_elem_head = sf->sf_hp_elem_head->next;
			}

			mutex_exit(&sf->sf_hp_daemon_mutex);

			switch (elem->what) {
			case SF_ONLINE:
				/* online this target */
				target = elem->target;
				(void) ndi_devi_online(elem->dip, 0);
				(void) ndi_event_retrieve_cookie(
				    sf->sf_event_hdl,
				    target->sft_dip, FCAL_INSERT_EVENT,
				    &sf_insert_eid, NDI_EVENT_NOPASS);
				(void) ndi_event_run_callbacks(sf->sf_event_hdl,
				    target->sft_dip, sf_insert_eid, NULL);
				break;
			case SF_OFFLINE:
				/* offline this target */
				target = elem->target;
				tgt_id = sf_alpa_to_switch[target->sft_al_pa];
				/* don't do NDI_DEVI_REMOVE for now */
				if (ndi_devi_offline(elem->dip, 0) !=
				    NDI_SUCCESS) {
					SF_DEBUG(1, (sf, CE_WARN, "target %x, "
					    "device offline failed", tgt_id));
				} else {
					SF_DEBUG(1, (sf, CE_NOTE, "target %x, "
					    "device offline succeeded\n",
					    tgt_id));
				}
				break;
			}
			kmem_free(elem, sizeof (struct sf_hp_elem));
			mutex_enter(&sf->sf_hp_daemon_mutex);
		}

		/* if exit is not already signaled */
		if (sf->sf_hp_exit == 0) {
			/* wait to be signaled by work or exit */
			CALLB_CPR_SAFE_BEGIN(&cprinfo);
			cv_wait(&sf->sf_hp_daemon_cv, &sf->sf_hp_daemon_mutex);
			CALLB_CPR_SAFE_END(&cprinfo, &sf->sf_hp_daemon_mutex);
		}
	} while (sf->sf_hp_exit == 0);

	/* sf_hp_daemon_mutex is dropped by CALLB_CPR_EXIT */
	CALLB_CPR_EXIT(&cprinfo);
	thread_exit();			/* no more hotplug thread */
	/* NOTREACHED */
}
