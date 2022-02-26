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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * An implementation of the IPoIB standard based on PSARC 2001/289.
 */

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/stropts.h>
#include <sys/stream.h>
#include <sys/strsun.h>
#include <sys/strsubr.h>
#include <sys/dlpi.h>
#include <sys/mac_provider.h>

#include <sys/pattr.h>		/* for HCK_FULLCKSUM */
#include <sys/sysmacros.h>	/* for offsetof */
#include <sys/disp.h>		/* for async thread pri */
#include <sys/atomic.h>		/* for atomic_add*() */
#include <sys/ethernet.h>	/* for ETHERTYPE_IPV6 */
#include <netinet/in.h>		/* for netinet/ip.h below */
#include <netinet/ip.h>		/* for struct ip */
#include <netinet/udp.h>	/* for struct udphdr */
#include <inet/common.h>	/* for inet/ip.h below */
#include <inet/ip.h>		/* for ipha_t */
#include <inet/ip6.h>		/* for ip6_t */
#include <inet/tcp.h>		/* for tcph_t */
#include <netinet/icmp6.h>	/* for icmp6_t */
#include <sys/callb.h>
#include <sys/modhash.h>

#include <sys/ib/clients/ibd/ibd.h>
#include <sys/ib/mgt/sm_attr.h>	/* for SM_INIT_TYPE_* */
#include <sys/note.h>
#include <sys/multidata.h>

#include <sys/ib/mgt/ibmf/ibmf.h>	/* for ibd_get_portspeed */

#include <sys/priv_names.h>
#include <sys/dls.h>
#include <sys/dld_ioc.h>
#include <sys/policy.h>
#include <sys/ibpart.h>
#include <sys/file.h>

/*
 * The write-up below includes details on the following:
 * 1. The dladm administrative model.
 * 2. Late HCA initialization feature.
 * 3. Brussels support and its implications to the current architecture.
 *
 * 1. The dladm administrative model.
 * ------------------------------------------
 * With the dladm model, ibnex will create one ibd instance per port. These
 * instances will be created independent of the port state.
 *
 * The ibd driver is two faceted: One side of it working as the port driver and
 * the other as the partition object driver.
 *
 * The port instance is a child of the HCA, and will have an entry in the devfs.
 * A DDI attach only happens for the port driver, and its attach is
 * handled in ibd_port_attach(). Similary, a DDI detach for the port driver is
 * handled in ibd_port_unattach().
 *
 * The partition object is only a registrant to the mac layer via mac_register()
 * and does not have an entry in the device tree. There is no DDI softstate
 * managed by the DDI framework for the partition objects. However, the state is
 * managed inside the ibd driver, and every partition object hangs off the
 * "ibd_objlist_head".
 *
 * The partition object first comes into existence when a user runs the
 * 'create-part' subcommand of dladm. This is like invoking the attach entry
 * point of the partition object. The partition object goes away with the
 * 'delete-part' subcommand of dladm. This is like invoking the detach entry
 * point of the partition object.
 *
 * The create-part and delete-part subcommands result in dld ioctls that end up
 * calling ibd_create_parition() and ibd_delete_partition respectively.
 * There ioctls are registered with the dld layer in _init() via a call to
 * dld_ioc_register().
 *
 * The port instance by itself cannot be plumbed. It is only the partition
 * objects that can be plumbed and they alone participate in I/O and not the
 * port driver.
 *
 * There are some info ioctls supported in ibd which are used by dladm(8) to
 * display useful information. The info entry point for ibd is
 * ibd_get_partition_info().
 *
 * 2. Late HCA initialization feature.
 * ------------------------------------
 * As mentioned in section 1, the user creates the partition objects via
 * dladm(8). It is possible that:
 * a) The physical port itself is down and the SM cannot be reached.
 * b) The PKEY specified by the used has not been created in the SM yet.
 * c) An IPoIB broadcast group for the specified PKEY is not present.
 *
 * In all of the above cases, complete initialization of the partition object is
 * not possible. However, the new model allows the creation of partition
 * objects even in such cases but will defer the initialization for later.
 * When such a partition object is plumbed, the link state will be displayed as
 * "down".
 * The driver, at this point, is listening to events that herald the
 * availability of resources -
 * i)   LINK_UP when the link becomes available
 * ii)  PORT_CHANGE when the PKEY has been created
 * iii) MCG_CREATED when the IPoIB broadcast group for the given pkey has been
 * created
 * via ibd_async_handler() for events i) and ii), and via
 * ibd_snet_notices_handler() for iii.
 * The driver handles these events (as and when they arrive) and completes the
 * initialization of the partition object and transitions it to a usable state.
 *
 * 3. Brussels support and its implications to the current architecture.
 * ---------------------------------------------------------------------
 * The brussels support introduces two new interfaces to the ibd driver -
 * ibd_m_getprop() and ibd_m_setprop().
 * These interfaces allow setting and retrieval of certain properties.
 * Some of them are public properties while most other are private properties
 * meant to be used by developers. Tuning the latter kind can cause
 * performance issues and should not be used without understanding the
 * implications. All properties are specific to an instance of either the
 * partition object or the port driver.
 *
 * The public properties are : mtu and linkmode.
 * mtu is a read-only property.
 * linkmode can take two values - UD and CM.
 *
 * Changing the linkmode requires some bookkeeping in the driver. The
 * capabilities need to be re-reported to the mac layer. This is done by
 * calling mac_capab_update().  The maxsdu is updated by calling
 * mac_maxsdu_update2().
 * The private properties retain their values across the change of linkmode.
 * NOTE:
 * - The port driver does not support any property apart from mtu.
 * - All other properties are only meant for the partition object.
 * - The properties cannot be set when an instance is plumbed. The
 * instance has to be unplumbed to effect any setting.
 */

/*
 * Driver wide tunables
 *
 * ibd_tx_softintr
 * ibd_rx_softintr
 *     The softintr mechanism allows ibd to avoid event queue overflows if
 *     the receive/completion handlers are to be expensive. These are enabled
 *     by default.
 *
 * ibd_log_sz
 *     This specifies the size of the ibd log buffer in bytes. The buffer is
 *     allocated and logging is enabled only when IBD_LOGGING is defined.
 *
 */
uint_t ibd_rx_softintr = 1;
uint_t ibd_tx_softintr = 1;

#ifdef IBD_LOGGING
uint_t ibd_log_sz = 0x20000;
#endif

#ifdef IBD_LOGGING
#define	IBD_LOG_SZ			ibd_log_sz
#endif

/* Post IBD_RX_POST_CNT receive work requests at a time. */
#define	IBD_RX_POST_CNT			8

/* Hash into 1 << IBD_LOG_RX_POST number of rx post queues */
#define	IBD_LOG_RX_POST			4

/* Minimum number of receive work requests driver needs to always have */
#define	IBD_RWQE_MIN	((IBD_RX_POST_CNT << IBD_LOG_RX_POST) * 4)

/*
 * LSO parameters
 */
#define	IBD_LSO_MAXLEN			65536
#define	IBD_LSO_BUFSZ			8192

/*
 * Async operation states
 */
#define	IBD_OP_NOTSTARTED		0
#define	IBD_OP_ONGOING			1
#define	IBD_OP_COMPLETED		2
#define	IBD_OP_ERRORED			3
#define	IBD_OP_ROUTERED			4

/*
 * Start/stop in-progress flags; note that restart must always remain
 * the OR of start and stop flag values.
 */
#define	IBD_DRV_START_IN_PROGRESS	0x10000000
#define	IBD_DRV_STOP_IN_PROGRESS	0x20000000
#define	IBD_DRV_RESTART_IN_PROGRESS	0x30000000
#define	IBD_DRV_DELETE_IN_PROGRESS	IBD_DRV_RESTART_IN_PROGRESS

/*
 * Miscellaneous constants
 */
#define	IB_MGID_IPV4_LOWGRP_MASK	0xFFFFFFFF
#define	IBD_DEF_MAX_SDU			2044
#define	IBD_DEF_MAX_MTU			(IBD_DEF_MAX_SDU + IPOIB_HDRSIZE)
#define	IBD_DEF_RC_MAX_SDU		65520
#define	IBD_DEF_RC_MAX_MTU		(IBD_DEF_RC_MAX_SDU + IPOIB_HDRSIZE)
#define	IBD_DEFAULT_QKEY		0xB1B
#ifdef IBD_LOGGING
#define	IBD_DMAX_LINE			100
#endif

/*
 * Enumerations for link states
 */
typedef enum {
	IBD_LINK_DOWN,
	IBD_LINK_UP,
	IBD_LINK_UP_ABSENT
} ibd_link_op_t;

/*
 * Driver State Pointer
 */
void *ibd_list;

/*
 * Driver Global Data
 */
ibd_global_state_t ibd_gstate;

/*
 * Partition object list
 */
ibd_state_t	*ibd_objlist_head = NULL;
kmutex_t	ibd_objlist_lock;

int ibd_rc_conn_timeout = 60 * 10;	/* 10 minutes */

/*
 * Logging
 */
#ifdef IBD_LOGGING
kmutex_t ibd_lbuf_lock;
uint8_t *ibd_lbuf;
uint32_t ibd_lbuf_ndx;
#endif

/*
 * Required system entry points
 */
static int ibd_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int ibd_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);

/*
 * Required driver entry points for GLDv3
 */
static int ibd_m_stat(void *, uint_t, uint64_t *);
static int ibd_m_start(void *);
static void ibd_m_stop(void *);
static int ibd_m_promisc(void *, boolean_t);
static int ibd_m_multicst(void *, boolean_t, const uint8_t *);
static int ibd_m_unicst(void *, const uint8_t *);
static mblk_t *ibd_m_tx(void *, mblk_t *);
static boolean_t ibd_m_getcapab(void *, mac_capab_t, void *);

static int ibd_m_setprop(void *, const char *, mac_prop_id_t, uint_t,
    const void *);
static int ibd_m_getprop(void *, const char *, mac_prop_id_t, uint_t, void *);
static void ibd_m_propinfo(void *, const char *, mac_prop_id_t,
    mac_prop_info_handle_t);
static int ibd_set_priv_prop(ibd_state_t *, const char *, uint_t,
    const void *);
static int ibd_get_priv_prop(ibd_state_t *, const char *, uint_t, void *);

/*
 * Private driver entry points for GLDv3
 */

/*
 * Initialization
 */
static int ibd_state_init(ibd_state_t *, dev_info_t *);
static int ibd_init_txlist(ibd_state_t *);
static int ibd_init_rxlist(ibd_state_t *);
static int ibd_acache_init(ibd_state_t *);
#ifdef IBD_LOGGING
static void ibd_log_init(void);
#endif

/*
 * Termination/cleanup
 */
static void ibd_state_fini(ibd_state_t *);
static void ibd_fini_txlist(ibd_state_t *);
static void ibd_fini_rxlist(ibd_state_t *);
static void ibd_tx_cleanup(ibd_state_t *, ibd_swqe_t *);
static void ibd_tx_cleanup_list(ibd_state_t *, ibd_swqe_t *, ibd_swqe_t *);
static void ibd_acache_fini(ibd_state_t *);
#ifdef IBD_LOGGING
static void ibd_log_fini(void);
#endif

/*
 * Allocation/acquire/map routines
 */
static int ibd_alloc_tx_copybufs(ibd_state_t *);
static int ibd_alloc_rx_copybufs(ibd_state_t *);
static int ibd_alloc_tx_lsobufs(ibd_state_t *);
static ibd_swqe_t *ibd_acquire_swqe(ibd_state_t *);
static int ibd_acquire_lsobufs(ibd_state_t *, uint_t, ibt_wr_ds_t *,
    uint32_t *);

/*
 * Free/release/unmap routines
 */
static void ibd_free_rwqe(ibd_state_t *, ibd_rwqe_t *);
static void ibd_free_tx_copybufs(ibd_state_t *);
static void ibd_free_rx_copybufs(ibd_state_t *);
static void ibd_free_rx_rsrcs(ibd_state_t *);
static void ibd_free_tx_lsobufs(ibd_state_t *);
static void ibd_release_swqe(ibd_state_t *, ibd_swqe_t *, ibd_swqe_t *, int);
static void ibd_release_lsobufs(ibd_state_t *, ibt_wr_ds_t *, uint32_t);
static void ibd_free_lsohdr(ibd_swqe_t *, mblk_t *);

/*
 * Handlers/callback routines
 */
static uint_t ibd_intr(caddr_t);
static uint_t ibd_tx_recycle(caddr_t);
static void ibd_rcq_handler(ibt_cq_hdl_t, void *);
static void ibd_scq_handler(ibt_cq_hdl_t, void *);
static void ibd_poll_rcq(ibd_state_t *, ibt_cq_hdl_t);
static void ibd_poll_scq(ibd_state_t *, ibt_cq_hdl_t);
static void ibd_drain_rcq(ibd_state_t *, ibt_cq_hdl_t);
static void ibd_drain_scq(ibd_state_t *, ibt_cq_hdl_t);
static void ibd_freemsg_cb(char *);
static void ibd_async_handler(void *, ibt_hca_hdl_t, ibt_async_code_t,
    ibt_async_event_t *);
static void ibdpd_async_handler(void *, ibt_hca_hdl_t, ibt_async_code_t,
    ibt_async_event_t *);
static void ibd_snet_notices_handler(void *, ib_gid_t,
    ibt_subnet_event_code_t, ibt_subnet_event_t *);

/*
 * Send/receive routines
 */
static boolean_t ibd_send(ibd_state_t *, mblk_t *);
static void ibd_post_send(ibd_state_t *, ibd_swqe_t *);
static void ibd_post_recv(ibd_state_t *, ibd_rwqe_t *);
static mblk_t *ibd_process_rx(ibd_state_t *, ibd_rwqe_t *, ibt_wc_t *);

/*
 * Threads
 */
static void ibd_async_work(ibd_state_t *);

/*
 * Async tasks
 */
static void ibd_async_acache(ibd_state_t *, ipoib_mac_t *);
static void ibd_async_multicast(ibd_state_t *, ib_gid_t, int);
static void ibd_async_setprom(ibd_state_t *);
static void ibd_async_unsetprom(ibd_state_t *);
static void ibd_async_reap_group(ibd_state_t *, ibd_mce_t *, ib_gid_t, uint8_t);
static void ibd_async_trap(ibd_state_t *, ibd_req_t *);
static void ibd_async_txsched(ibd_state_t *);
static void ibd_async_link(ibd_state_t *, ibd_req_t *);

/*
 * Async task helpers
 */
static ibd_mce_t *ibd_async_mcache(ibd_state_t *, ipoib_mac_t *, boolean_t *);
static ibd_mce_t *ibd_join_group(ibd_state_t *, ib_gid_t, uint8_t);
static ibd_mce_t *ibd_mcache_find(ib_gid_t, struct list *);
static boolean_t ibd_get_allroutergroup(ibd_state_t *,
    ipoib_mac_t *, ipoib_mac_t *);
static void ibd_leave_group(ibd_state_t *, ib_gid_t, uint8_t);
static void ibd_reacquire_group(ibd_state_t *, ibd_mce_t *);
static ibt_status_t ibd_iba_join(ibd_state_t *, ib_gid_t, ibd_mce_t *);
static ibt_status_t ibd_find_bgroup(ibd_state_t *);
static void ibd_n2h_gid(ipoib_mac_t *, ib_gid_t *);
static void ibd_h2n_mac(ipoib_mac_t *, ib_qpn_t, ib_sn_prefix_t, ib_guid_t);
static uint64_t ibd_get_portspeed(ibd_state_t *);
static boolean_t ibd_async_safe(ibd_state_t *);
static void ibd_async_done(ibd_state_t *);
static ibd_ace_t *ibd_acache_lookup(ibd_state_t *, ipoib_mac_t *, int *, int);
static ibd_ace_t *ibd_acache_get_unref(ibd_state_t *);
static void ibd_link_mod(ibd_state_t *, ibt_async_code_t);
static int ibd_locate_pkey(ib_pkey_t *, uint16_t, ib_pkey_t, uint16_t *);

/*
 * Helpers for attach/start routines
 */
static int ibd_register_mac(ibd_state_t *, dev_info_t *);
static int ibd_record_capab(ibd_state_t *);
static int ibd_get_port_details(ibd_state_t *);
static int ibd_alloc_cqs(ibd_state_t *);
static int ibd_setup_ud_channel(ibd_state_t *);
static int ibd_start(ibd_state_t *);
static int ibd_undo_start(ibd_state_t *, link_state_t);
static void ibd_set_mac_progress(ibd_state_t *, uint_t);
static void ibd_clr_mac_progress(ibd_state_t *, uint_t);
static int ibd_part_attach(ibd_state_t *state, dev_info_t *dip);
static void ibd_part_unattach(ibd_state_t *state);
static int ibd_port_attach(dev_info_t *);
static int ibd_port_unattach(ibd_state_t *state, dev_info_t *dip);
static int ibd_get_port_state(ibd_state_t *, link_state_t *);
static int ibd_part_busy(ibd_state_t *);

/*
 * Miscellaneous helpers
 */
static int ibd_sched_poll(ibd_state_t *, int, int);
static void ibd_resume_transmission(ibd_state_t *);
static int ibd_setup_lso(ibd_swqe_t *, mblk_t *, uint32_t, ibt_ud_dest_hdl_t);
static int ibd_prepare_sgl(ibd_state_t *, mblk_t *, ibd_swqe_t *, uint_t);
static void *list_get_head(list_t *);
static int ibd_hash_key_cmp(mod_hash_key_t, mod_hash_key_t);
static uint_t ibd_hash_by_id(void *, mod_hash_key_t);

ibt_status_t ibd_get_part_attr(datalink_id_t, ibt_part_attr_t *);
ibt_status_t ibd_get_all_part_attr(ibt_part_attr_t **, int *);

#ifdef IBD_LOGGING
static void ibd_log(const char *, ...);
#endif

DDI_DEFINE_STREAM_OPS(ibd_dev_ops, nulldev, nulldev, ibd_attach, ibd_detach,
    nodev, NULL, D_MP, NULL, ddi_quiesce_not_needed);

/* Module Driver Info */
static struct modldrv ibd_modldrv = {
	&mod_driverops,			/* This one is a driver */
	"InfiniBand GLDv3 Driver",	/* short description */
	&ibd_dev_ops			/* driver specific ops */
};

/* Module Linkage */
static struct modlinkage ibd_modlinkage = {
	MODREV_1, (void *)&ibd_modldrv, NULL
};

/*
 * Module (static) info passed to IBTL during ibt_attach
 */
static struct ibt_clnt_modinfo_s ibd_clnt_modinfo = {
	IBTI_V_CURR,
	IBT_NETWORK,
	ibd_async_handler,
	NULL,
	"IBPART"
};

static struct ibt_clnt_modinfo_s ibdpd_clnt_modinfo = {
	IBTI_V_CURR,
	IBT_NETWORK,
	ibdpd_async_handler,
	NULL,
	"IPIB"
};

/*
 * GLDv3 entry points
 */
#define	IBD_M_CALLBACK_FLAGS	\
	(MC_GETCAPAB | MC_SETPROP | MC_GETPROP | MC_PROPINFO)

static mac_callbacks_t ibd_m_callbacks = {
	IBD_M_CALLBACK_FLAGS,
	ibd_m_stat,
	ibd_m_start,
	ibd_m_stop,
	ibd_m_promisc,
	ibd_m_multicst,
	ibd_m_unicst,
	ibd_m_tx,
	NULL,
	NULL,
	ibd_m_getcapab,
	NULL,
	NULL,
	ibd_m_setprop,
	ibd_m_getprop,
	ibd_m_propinfo
};

/* Private properties */
char *ibd_priv_props[] = {
	"_ibd_broadcast_group",
	"_ibd_coalesce_completions",
	"_ibd_create_broadcast_group",
	"_ibd_hash_size",
	"_ibd_lso_enable",
	"_ibd_num_ah",
	"_ibd_num_lso_bufs",
	"_ibd_rc_enable_srq",
	"_ibd_rc_num_rwqe",
	"_ibd_rc_num_srq",
	"_ibd_rc_num_swqe",
	"_ibd_rc_rx_comp_count",
	"_ibd_rc_rx_comp_usec",
	"_ibd_rc_rx_copy_thresh",
	"_ibd_rc_rx_rwqe_thresh",
	"_ibd_rc_tx_comp_count",
	"_ibd_rc_tx_comp_usec",
	"_ibd_rc_tx_copy_thresh",
	"_ibd_ud_num_rwqe",
	"_ibd_ud_num_swqe",
	"_ibd_ud_rx_comp_count",
	"_ibd_ud_rx_comp_usec",
	"_ibd_ud_tx_comp_count",
	"_ibd_ud_tx_comp_usec",
	"_ibd_ud_tx_copy_thresh",
	NULL
};

static int ibd_create_partition(void *, intptr_t, int, cred_t *, int *);
static int ibd_delete_partition(void *, intptr_t, int, cred_t *, int *);
static int ibd_get_partition_info(void *, intptr_t, int, cred_t *, int *);

static dld_ioc_info_t ibd_dld_ioctl_list[] = {
	{IBD_CREATE_IBPART, DLDCOPYINOUT, sizeof (ibpart_ioctl_t),
	    ibd_create_partition, secpolicy_dl_config},
	{IBD_DELETE_IBPART, DLDCOPYIN, sizeof (ibpart_ioctl_t),
	    ibd_delete_partition, secpolicy_dl_config},
	{IBD_INFO_IBPART, DLDCOPYIN, sizeof (ibd_ioctl_t),
	    ibd_get_partition_info, NULL}
};

/*
 * Fill/clear <scope> and <p_key> in multicast/broadcast address
 */
#define	IBD_FILL_SCOPE_PKEY(maddr, scope, pkey)		\
{							\
	*(uint32_t *)((char *)(maddr) + 4) |=		\
	    htonl((uint32_t)(scope) << 16);		\
	*(uint32_t *)((char *)(maddr) + 8) |=		\
	    htonl((uint32_t)(pkey) << 16);		\
}

#define	IBD_CLEAR_SCOPE_PKEY(maddr)			\
{							\
	*(uint32_t *)((char *)(maddr) + 4) &=		\
	    htonl(~((uint32_t)0xF << 16));		\
	*(uint32_t *)((char *)(maddr) + 8) &=		\
	    htonl(~((uint32_t)0xFFFF << 16));		\
}

/*
 * Rudimentary debugging support
 */
#ifdef DEBUG
int ibd_debuglevel = 100;
void
debug_print(int l, char *fmt, ...)
{
	va_list ap;

	if (l < ibd_debuglevel)
		return;
	va_start(ap, fmt);
	vcmn_err(CE_CONT, fmt, ap);
	va_end(ap);
}
#endif

/*
 * Common routine to print warning messages; adds in hca guid, port number
 * and pkey to be able to identify the IBA interface.
 */
void
ibd_print_warn(ibd_state_t *state, char *fmt, ...)
{
	ib_guid_t hca_guid;
	char ibd_print_buf[MAXNAMELEN + 256];
	int len;
	va_list ap;
	char part_name[MAXNAMELEN];
	datalink_id_t linkid = state->id_plinkid;

	hca_guid = ddi_prop_get_int64(DDI_DEV_T_ANY, state->id_dip,
	    0, "hca-guid", 0);
	(void) dls_mgmt_get_linkinfo(linkid, part_name, NULL, NULL, NULL);
	len = snprintf(ibd_print_buf, sizeof (ibd_print_buf),
	    "%s%d: HCA GUID %016llx port %d PKEY %02x link %s ",
	    ddi_driver_name(state->id_dip), ddi_get_instance(state->id_dip),
	    (u_longlong_t)hca_guid, state->id_port, state->id_pkey,
	    part_name);
	va_start(ap, fmt);
	(void) vsnprintf(ibd_print_buf + len, sizeof (ibd_print_buf) - len,
	    fmt, ap);
	cmn_err(CE_NOTE, "!%s", ibd_print_buf);
	va_end(ap);
}

/*
 * Warlock directives
 */

/*
 * id_lso_lock
 *
 * state->id_lso->bkt_nfree may be accessed without a lock to
 * determine the threshold at which we have to ask the nw layer
 * to resume transmission (see ibd_resume_transmission()).
 */
_NOTE(MUTEX_PROTECTS_DATA(ibd_state_t::id_lso_lock,
    ibd_state_t::id_lso))
_NOTE(DATA_READABLE_WITHOUT_LOCK(ibd_state_t::id_lso))
_NOTE(SCHEME_PROTECTS_DATA("init", ibd_state_t::id_lso_policy))
_NOTE(DATA_READABLE_WITHOUT_LOCK(ibd_lsobkt_t::bkt_nfree))

/*
 * id_scq_poll_lock
 */
_NOTE(MUTEX_PROTECTS_DATA(ibd_state_t::id_scq_poll_lock,
    ibd_state_t::id_scq_poll_busy))

/*
 * id_txpost_lock
 */
_NOTE(MUTEX_PROTECTS_DATA(ibd_state_t::id_txpost_lock,
    ibd_state_t::id_tx_head))
_NOTE(MUTEX_PROTECTS_DATA(ibd_state_t::id_txpost_lock,
    ibd_state_t::id_tx_busy))

/*
 * id_acache_req_lock
 */
_NOTE(MUTEX_PROTECTS_DATA(ibd_state_t::id_acache_req_lock, 
    ibd_state_t::id_acache_req_cv))
_NOTE(MUTEX_PROTECTS_DATA(ibd_state_t::id_acache_req_lock, 
    ibd_state_t::id_req_list))
_NOTE(SCHEME_PROTECTS_DATA("atomic",
    ibd_acache_s::ac_ref))

/*
 * id_ac_mutex
 *
 * This mutex is actually supposed to protect id_ah_op as well,
 * but this path of the code isn't clean (see update of id_ah_op
 * in ibd_async_acache(), immediately after the call to
 * ibd_async_mcache()). For now, we'll skip this check by
 * declaring that id_ah_op is protected by some internal scheme
 * that warlock isn't aware of.
 */
_NOTE(MUTEX_PROTECTS_DATA(ibd_state_t::id_ac_mutex,
    ibd_state_t::id_ah_active))
_NOTE(MUTEX_PROTECTS_DATA(ibd_state_t::id_ac_mutex,
    ibd_state_t::id_ah_free))
_NOTE(MUTEX_PROTECTS_DATA(ibd_state_t::id_ac_mutex,
    ibd_state_t::id_ah_addr))
_NOTE(SCHEME_PROTECTS_DATA("ac mutex should protect this",
    ibd_state_t::id_ah_op))
_NOTE(MUTEX_PROTECTS_DATA(ibd_state_t::id_ac_mutex,
    ibd_state_t::id_ah_error))
_NOTE(MUTEX_PROTECTS_DATA(ibd_state_t::id_ac_mutex,
    ibd_state_t::id_ac_hot_ace))
_NOTE(DATA_READABLE_WITHOUT_LOCK(ibd_state_t::id_ah_error))

/*
 * id_mc_mutex
 */
_NOTE(MUTEX_PROTECTS_DATA(ibd_state_t::id_mc_mutex,
    ibd_state_t::id_mc_full))
_NOTE(MUTEX_PROTECTS_DATA(ibd_state_t::id_mc_mutex,
    ibd_state_t::id_mc_non))

/*
 * id_trap_lock
 */
_NOTE(MUTEX_PROTECTS_DATA(ibd_state_t::id_trap_lock,
    ibd_state_t::id_trap_cv))
_NOTE(MUTEX_PROTECTS_DATA(ibd_state_t::id_trap_lock,
    ibd_state_t::id_trap_stop))
_NOTE(MUTEX_PROTECTS_DATA(ibd_state_t::id_trap_lock,
    ibd_state_t::id_trap_inprog))

/*
 * id_prom_op
 */
_NOTE(SCHEME_PROTECTS_DATA("only by async thread",
    ibd_state_t::id_prom_op))

/*
 * id_sched_lock
 */
_NOTE(MUTEX_PROTECTS_DATA(ibd_state_t::id_sched_lock,
    ibd_state_t::id_sched_needed))

/*
 * id_link_mutex
 */
_NOTE(MUTEX_PROTECTS_DATA(ibd_state_t::id_link_mutex, 
    ibd_state_t::id_link_state))
_NOTE(DATA_READABLE_WITHOUT_LOCK(ibd_state_t::id_link_state))
_NOTE(SCHEME_PROTECTS_DATA("only async thr and ibd_m_start",
    ibd_state_t::id_link_speed))
_NOTE(DATA_READABLE_WITHOUT_LOCK(ibd_state_t::id_sgid))

/*
 * id_tx_list.dl_mutex
 */
_NOTE(MUTEX_PROTECTS_DATA(ibd_state_t::id_tx_list.dl_mutex,
    ibd_state_t::id_tx_list.dl_head))
_NOTE(MUTEX_PROTECTS_DATA(ibd_state_t::id_tx_list.dl_mutex,
    ibd_state_t::id_tx_list.dl_pending_sends))
_NOTE(MUTEX_PROTECTS_DATA(ibd_state_t::id_tx_list.dl_mutex,
    ibd_state_t::id_tx_list.dl_cnt))

/*
 * id_rx_list.dl_mutex
 */
_NOTE(SCHEME_PROTECTS_DATA("atomic or dl mutex or single thr",
    ibd_state_t::id_rx_list.dl_bufs_outstanding))
_NOTE(SCHEME_PROTECTS_DATA("atomic or dl mutex or single thr",
    ibd_state_t::id_rx_list.dl_cnt))

/*
 * rc_timeout_lock
 */
_NOTE(MUTEX_PROTECTS_DATA(ibd_state_t::rc_timeout_lock,
    ibd_state_t::rc_timeout_start))
_NOTE(MUTEX_PROTECTS_DATA(ibd_state_t::rc_timeout_lock,
    ibd_state_t::rc_timeout))


/*
 * Items protected by atomic updates
 */
_NOTE(SCHEME_PROTECTS_DATA("atomic update only",
    ibd_state_s::id_brd_rcv
    ibd_state_s::id_brd_xmt
    ibd_state_s::id_multi_rcv
    ibd_state_s::id_multi_xmt
    ibd_state_s::id_num_intrs
    ibd_state_s::id_rcv_bytes
    ibd_state_s::id_rcv_pkt
    ibd_state_s::id_rx_post_queue_index
    ibd_state_s::id_tx_short
    ibd_state_s::id_xmt_bytes
    ibd_state_s::id_xmt_pkt
    ibd_state_s::rc_rcv_trans_byte
    ibd_state_s::rc_rcv_trans_pkt
    ibd_state_s::rc_rcv_copy_byte
    ibd_state_s::rc_rcv_copy_pkt
    ibd_state_s::rc_xmt_bytes
    ibd_state_s::rc_xmt_small_pkt
    ibd_state_s::rc_xmt_fragmented_pkt
    ibd_state_s::rc_xmt_map_fail_pkt
    ibd_state_s::rc_xmt_map_succ_pkt
    ibd_rc_chan_s::rcq_invoking))

/*
 * Non-mutex protection schemes for data elements. Almost all of
 * these are non-shared items.
 */
_NOTE(SCHEME_PROTECTS_DATA("unshared or single-threaded",
    callb_cpr
    ib_gid_s
    ib_header_info
    ibd_acache_rq
    ibd_acache_s::ac_mce
    ibd_acache_s::ac_chan
    ibd_mcache::mc_fullreap
    ibd_mcache::mc_jstate
    ibd_mcache::mc_req
    ibd_rwqe_s
    ibd_swqe_s
    ibd_wqe_s
    ibt_wr_ds_s::ds_va
    ibt_wr_lso_s
    ipoib_mac::ipoib_qpn
    mac_capab_lso_s
    msgb::b_next
    msgb::b_cont
    msgb::b_rptr
    msgb::b_wptr
    ibd_state_s::id_bgroup_created
    ibd_state_s::id_mac_state
    ibd_state_s::id_mtu
    ibd_state_s::id_ud_num_rwqe
    ibd_state_s::id_ud_num_swqe
    ibd_state_s::id_qpnum
    ibd_state_s::id_rcq_hdl
    ibd_state_s::id_rx_buf_sz
    ibd_state_s::id_rx_bufs
    ibd_state_s::id_rx_mr_hdl
    ibd_state_s::id_rx_wqes
    ibd_state_s::id_rxwcs
    ibd_state_s::id_rxwcs_size
    ibd_state_s::id_rx_nqueues
    ibd_state_s::id_rx_queues
    ibd_state_s::id_scope
    ibd_state_s::id_scq_hdl
    ibd_state_s::id_tx_buf_sz
    ibd_state_s::id_tx_bufs
    ibd_state_s::id_tx_mr_hdl
    ibd_state_s::id_tx_rel_list.dl_cnt
    ibd_state_s::id_tx_wqes
    ibd_state_s::id_txwcs
    ibd_state_s::id_txwcs_size
    ibd_state_s::rc_listen_hdl
    ibd_state_s::rc_listen_hdl_OFED_interop
    ibd_state_s::rc_srq_size
    ibd_state_s::rc_srq_rwqes
    ibd_state_s::rc_srq_rx_bufs
    ibd_state_s::rc_srq_rx_mr_hdl
    ibd_state_s::rc_tx_largebuf_desc_base
    ibd_state_s::rc_tx_mr_bufs
    ibd_state_s::rc_tx_mr_hdl
    ipha_s
    icmph_s
    ibt_path_info_s::pi_sid
    ibd_rc_chan_s::ace
    ibd_rc_chan_s::chan_hdl
    ibd_rc_chan_s::state
    ibd_rc_chan_s::chan_state
    ibd_rc_chan_s::is_tx_chan
    ibd_rc_chan_s::rcq_hdl
    ibd_rc_chan_s::rcq_size
    ibd_rc_chan_s::scq_hdl
    ibd_rc_chan_s::scq_size
    ibd_rc_chan_s::rx_bufs
    ibd_rc_chan_s::rx_mr_hdl
    ibd_rc_chan_s::rx_rwqes
    ibd_rc_chan_s::tx_wqes
    ibd_rc_chan_s::tx_mr_bufs
    ibd_rc_chan_s::tx_mr_hdl
    ibd_rc_chan_s::tx_rel_list.dl_cnt
    ibd_rc_chan_s::is_used
    ibd_rc_tx_largebuf_s::lb_buf
    ibd_rc_msg_hello_s
    ibt_cm_return_args_s))

/*
 * ibd_rc_chan_s::next is protected by two mutexes:
 * 1) ibd_state_s::rc_pass_chan_list.chan_list_mutex
 * 2) ibd_state_s::rc_obs_act_chan_list.chan_list_mutex.
 */
_NOTE(SCHEME_PROTECTS_DATA("protected by two mutexes",
    ibd_rc_chan_s::next))

/*
 * ibd_state_s.rc_tx_large_bufs_lock
 */
_NOTE(MUTEX_PROTECTS_DATA(ibd_state_s::rc_tx_large_bufs_lock,
    ibd_state_s::rc_tx_largebuf_free_head))
_NOTE(MUTEX_PROTECTS_DATA(ibd_state_s::rc_tx_large_bufs_lock,
    ibd_state_s::rc_tx_largebuf_nfree))
_NOTE(MUTEX_PROTECTS_DATA(ibd_state_s::rc_tx_large_bufs_lock,
    ibd_rc_tx_largebuf_s::lb_next))

/*
 * ibd_acache_s.tx_too_big_mutex
 */
_NOTE(MUTEX_PROTECTS_DATA(ibd_acache_s::tx_too_big_mutex,
    ibd_acache_s::tx_too_big_ongoing))

/*
 * tx_wqe_list.dl_mutex
 */
_NOTE(MUTEX_PROTECTS_DATA(ibd_rc_chan_s::tx_wqe_list.dl_mutex,
    ibd_rc_chan_s::tx_wqe_list.dl_head))
_NOTE(MUTEX_PROTECTS_DATA(ibd_rc_chan_s::tx_wqe_list.dl_mutex,
    ibd_rc_chan_s::tx_wqe_list.dl_pending_sends))
_NOTE(MUTEX_PROTECTS_DATA(ibd_rc_chan_s::tx_wqe_list.dl_mutex,
    ibd_rc_chan_s::tx_wqe_list.dl_cnt))

/*
 * ibd_state_s.rc_ace_recycle_lock
 */
_NOTE(MUTEX_PROTECTS_DATA(ibd_state_s::rc_ace_recycle_lock,
    ibd_state_s::rc_ace_recycle))

/*
 * rc_srq_rwqe_list.dl_mutex
 */
_NOTE(SCHEME_PROTECTS_DATA("atomic or dl mutex or single thr",
    ibd_state_t::rc_srq_rwqe_list.dl_bufs_outstanding))
_NOTE(SCHEME_PROTECTS_DATA("atomic or dl mutex or single thr",
    ibd_state_t::rc_srq_rwqe_list.dl_cnt))

/*
 * Non-mutex protection schemes for data elements. They are counters
 * for problem diagnosis. Don't need be protected.
 */
_NOTE(SCHEME_PROTECTS_DATA("counters for problem diagnosis",
    ibd_state_s::rc_rcv_alloc_fail
    ibd_state_s::rc_rcq_err
    ibd_state_s::rc_ace_not_found
    ibd_state_s::rc_xmt_drop_too_long_pkt
    ibd_state_s::rc_xmt_icmp_too_long_pkt
    ibd_state_s::rc_xmt_reenter_too_long_pkt
    ibd_state_s::rc_swqe_short
    ibd_state_s::rc_swqe_mac_update
    ibd_state_s::rc_xmt_buf_short
    ibd_state_s::rc_xmt_buf_mac_update
    ibd_state_s::rc_scq_no_swqe
    ibd_state_s::rc_scq_no_largebuf
    ibd_state_s::rc_conn_succ
    ibd_state_s::rc_conn_fail
    ibd_state_s::rc_null_conn
    ibd_state_s::rc_no_estab_conn
    ibd_state_s::rc_act_close
    ibd_state_s::rc_pas_close
    ibd_state_s::rc_delay_ace_recycle
    ibd_state_s::rc_act_close_simultaneous
    ibd_state_s::rc_act_close_not_clean
    ibd_state_s::rc_pas_close_rcq_invoking
    ibd_state_s::rc_reset_cnt
    ibd_state_s::rc_timeout_act
    ibd_state_s::rc_timeout_pas
    ibd_state_s::rc_stop_connect))

#ifdef DEBUG
/*
 * Non-mutex protection schemes for data elements. They are counters
 * for problem diagnosis. Don't need be protected.
 */
_NOTE(SCHEME_PROTECTS_DATA("counters for problem diagnosis",
    ibd_state_s::rc_rwqe_short
    ibd_rc_stat_s::rc_rcv_trans_byte
    ibd_rc_stat_s::rc_rcv_trans_pkt
    ibd_rc_stat_s::rc_rcv_copy_byte
    ibd_rc_stat_s::rc_rcv_copy_pkt
    ibd_rc_stat_s::rc_rcv_alloc_fail
    ibd_rc_stat_s::rc_rcq_err 
    ibd_rc_stat_s::rc_rwqe_short
    ibd_rc_stat_s::rc_xmt_bytes
    ibd_rc_stat_s::rc_xmt_small_pkt
    ibd_rc_stat_s::rc_xmt_fragmented_pkt
    ibd_rc_stat_s::rc_xmt_map_fail_pkt
    ibd_rc_stat_s::rc_xmt_map_succ_pkt
    ibd_rc_stat_s::rc_ace_not_found
    ibd_rc_stat_s::rc_scq_no_swqe
    ibd_rc_stat_s::rc_scq_no_largebuf
    ibd_rc_stat_s::rc_swqe_short
    ibd_rc_stat_s::rc_swqe_mac_update
    ibd_rc_stat_s::rc_xmt_buf_short
    ibd_rc_stat_s::rc_xmt_buf_mac_update
    ibd_rc_stat_s::rc_conn_succ
    ibd_rc_stat_s::rc_conn_fail
    ibd_rc_stat_s::rc_null_conn
    ibd_rc_stat_s::rc_no_estab_conn
    ibd_rc_stat_s::rc_act_close
    ibd_rc_stat_s::rc_pas_close
    ibd_rc_stat_s::rc_delay_ace_recycle
    ibd_rc_stat_s::rc_act_close_simultaneous
    ibd_rc_stat_s::rc_reset_cnt
    ibd_rc_stat_s::rc_timeout_act
    ibd_rc_stat_s::rc_timeout_pas))
#endif

int
_init()
{
	int status;

	status = ddi_soft_state_init(&ibd_list, max(sizeof (ibd_state_t),
	    PAGESIZE), 0);
	if (status != 0) {
		DPRINT(10, "_init:failed in ddi_soft_state_init()");
		return (status);
	}

	mutex_init(&ibd_objlist_lock, NULL, MUTEX_DRIVER, NULL);

	mac_init_ops(&ibd_dev_ops, "ibp");
	status = mod_install(&ibd_modlinkage);
	if (status != 0) {
		DPRINT(10, "_init:failed in mod_install()");
		ddi_soft_state_fini(&ibd_list);
		mac_fini_ops(&ibd_dev_ops);
		return (status);
	}

	mutex_init(&ibd_gstate.ig_mutex, NULL, MUTEX_DRIVER, NULL);
	mutex_enter(&ibd_gstate.ig_mutex);
	ibd_gstate.ig_ibt_hdl = NULL;
	ibd_gstate.ig_ibt_hdl_ref_cnt = 0;
	ibd_gstate.ig_service_list = NULL;
	mutex_exit(&ibd_gstate.ig_mutex);

	if (dld_ioc_register(IBPART_IOC, ibd_dld_ioctl_list,
	    DLDIOCCNT(ibd_dld_ioctl_list)) != 0) {
		return (EIO);
	}

	ibt_register_part_attr_cb(ibd_get_part_attr, ibd_get_all_part_attr);

#ifdef IBD_LOGGING
	ibd_log_init();
#endif
	return (0);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&ibd_modlinkage, modinfop));
}

int
_fini()
{
	int status;

	status = mod_remove(&ibd_modlinkage);
	if (status != 0)
		return (status);

	ibt_unregister_part_attr_cb();

	mac_fini_ops(&ibd_dev_ops);
	mutex_destroy(&ibd_objlist_lock);
	ddi_soft_state_fini(&ibd_list);
	mutex_destroy(&ibd_gstate.ig_mutex);
#ifdef IBD_LOGGING
	ibd_log_fini();
#endif
	return (0);
}

/*
 * Convert the GID part of the mac address from network byte order
 * to host order.
 */
static void
ibd_n2h_gid(ipoib_mac_t *mac, ib_gid_t *dgid)
{
	ib_sn_prefix_t nbopref;
	ib_guid_t nboguid;

	bcopy(mac->ipoib_gidpref, &nbopref, sizeof (ib_sn_prefix_t));
	bcopy(mac->ipoib_gidsuff, &nboguid, sizeof (ib_guid_t));
	dgid->gid_prefix = b2h64(nbopref);
	dgid->gid_guid = b2h64(nboguid);
}

/*
 * Create the IPoIB address in network byte order from host order inputs.
 */
static void
ibd_h2n_mac(ipoib_mac_t *mac, ib_qpn_t qpn, ib_sn_prefix_t prefix,
    ib_guid_t guid)
{
	ib_sn_prefix_t nbopref;
	ib_guid_t nboguid;

	mac->ipoib_qpn = htonl(qpn);
	nbopref = h2b64(prefix);
	nboguid = h2b64(guid);
	bcopy(&nbopref, mac->ipoib_gidpref, sizeof (ib_sn_prefix_t));
	bcopy(&nboguid, mac->ipoib_gidsuff, sizeof (ib_guid_t));
}

/*
 * Send to the appropriate all-routers group when the IBA multicast group
 * does not exist, based on whether the target group is v4 or v6.
 */
static boolean_t
ibd_get_allroutergroup(ibd_state_t *state, ipoib_mac_t *mcmac,
    ipoib_mac_t *rmac)
{
	boolean_t retval = B_TRUE;
	uint32_t adjscope = state->id_scope << 16;
	uint32_t topword;

	/*
	 * Copy the first 4 bytes in without assuming any alignment of
	 * input mac address; this will have IPoIB signature, flags and
	 * scope bits.
	 */
	bcopy(mcmac->ipoib_gidpref, &topword, sizeof (uint32_t));
	topword = ntohl(topword);

	/*
	 * Generate proper address for IPv4/v6, adding in the Pkey properly.
	 */
	if ((topword == (IB_MCGID_IPV4_PREFIX | adjscope)) ||
	    (topword == (IB_MCGID_IPV6_PREFIX | adjscope)))
		ibd_h2n_mac(rmac, IB_MC_QPN, (((uint64_t)topword << 32) |
		    ((uint32_t)(state->id_pkey << 16))),
		    (INADDR_ALLRTRS_GROUP - INADDR_UNSPEC_GROUP));
	else
		/*
		 * Does not have proper bits in the mgid address.
		 */
		retval = B_FALSE;

	return (retval);
}

/*
 * Membership states for different mcg's are tracked by two lists:
 * the "non" list is used for promiscuous mode, when all mcg traffic
 * needs to be inspected. This type of membership is never used for
 * transmission, so there can not be an AH in the active list
 * corresponding to a member in this list. This list does not need
 * any protection, since all operations are performed by the async
 * thread.
 *
 * "Full" and "SendOnly" membership is tracked using a single list,
 * the "full" list. This is because this single list can then be
 * searched during transmit to a multicast group (if an AH for the
 * mcg is not found in the active list), since at least one type
 * of membership must be present before initiating the transmit.
 * This list is also emptied during driver detach, since sendonly
 * membership acquired during transmit is dropped at detach time
 * along with ipv4 broadcast full membership. Insert/deletes to
 * this list are done only by the async thread, but it is also
 * searched in program context (see multicast disable case), thus
 * the id_mc_mutex protects the list. The driver detach path also
 * deconstructs the "full" list, but it ensures that the async
 * thread will not be accessing the list (by blocking out mcg
 * trap handling and making sure no more Tx reaping will happen).
 *
 * Currently, an IBA attach is done in the SendOnly case too,
 * although this is not required.
 */
#define	IBD_MCACHE_INSERT_FULL(state, mce) \
	list_insert_head(&state->id_mc_full, mce)
#define	IBD_MCACHE_INSERT_NON(state, mce) \
	list_insert_head(&state->id_mc_non, mce)
#define	IBD_MCACHE_FIND_FULL(state, mgid) \
	ibd_mcache_find(mgid, &state->id_mc_full)
#define	IBD_MCACHE_FIND_NON(state, mgid) \
	ibd_mcache_find(mgid, &state->id_mc_non)
#define	IBD_MCACHE_PULLOUT_FULL(state, mce) \
	list_remove(&state->id_mc_full, mce)
#define	IBD_MCACHE_PULLOUT_NON(state, mce) \
	list_remove(&state->id_mc_non, mce)

static void *
list_get_head(list_t *list)
{
	list_node_t *lhead = list_head(list);

	if (lhead != NULL)
		list_remove(list, lhead);
	return (lhead);
}

/*
 * This is always guaranteed to be able to queue the work.
 */
void
ibd_queue_work_slot(ibd_state_t *state, ibd_req_t *ptr, int op)
{
	/* Initialize request */
	DPRINT(1, "ibd_queue_work_slot : op: %d \n", op);
	ptr->rq_op = op;

	/*
	 * Queue provided slot onto request pool.
	 */
	mutex_enter(&state->id_acache_req_lock);
	list_insert_tail(&state->id_req_list, ptr);

	/* Go, fetch, async thread */
	cv_signal(&state->id_acache_req_cv);
	mutex_exit(&state->id_acache_req_lock);
}

/*
 * Main body of the per interface async thread.
 */
static void
ibd_async_work(ibd_state_t *state)
{
	ibd_req_t *ptr;
	callb_cpr_t cprinfo;

	mutex_enter(&state->id_acache_req_lock);
	CALLB_CPR_INIT(&cprinfo, &state->id_acache_req_lock,
	    callb_generic_cpr, "ibd_async_work");

	for (;;) {
		ptr = list_get_head(&state->id_req_list);
		if (ptr != NULL) {
			mutex_exit(&state->id_acache_req_lock);

			/*
			 * If we are in late hca initialization mode, do not
			 * process any other async request other than TRAP. TRAP
			 * is used for indicating creation of a broadcast group;
			 * in which case, we need to join/create the group.
			 */
			if ((state->id_mac_state & IBD_DRV_IN_LATE_HCA_INIT) &&
			    (ptr->rq_op != IBD_ASYNC_TRAP)) {
				goto free_req_and_continue;
			}

			/*
			 * Once we have done the operation, there is no
			 * guarantee the request slot is going to be valid,
			 * it might be freed up (as in IBD_ASYNC_LEAVE, REAP,
			 * TRAP).
			 *
			 * Perform the request.
			 */
			switch (ptr->rq_op) {
				case IBD_ASYNC_GETAH:
					ibd_async_acache(state, &ptr->rq_mac);
					break;
				case IBD_ASYNC_JOIN:
				case IBD_ASYNC_LEAVE:
					ibd_async_multicast(state,
					    ptr->rq_gid, ptr->rq_op);
					break;
				case IBD_ASYNC_PROMON:
					ibd_async_setprom(state);
					break;
				case IBD_ASYNC_PROMOFF:
					ibd_async_unsetprom(state);
					break;
				case IBD_ASYNC_REAP:
					ibd_async_reap_group(state,
					    ptr->rq_ptr, ptr->rq_gid,
					    IB_MC_JSTATE_FULL);
					/*
					 * the req buf contains in mce
					 * structure, so we do not need
					 * to free it here.
					 */
					ptr = NULL;
					break;
				case IBD_ASYNC_TRAP:
					ibd_async_trap(state, ptr);
					break;
				case IBD_ASYNC_SCHED:
					ibd_async_txsched(state);
					break;
				case IBD_ASYNC_LINK:
					ibd_async_link(state, ptr);
					break;
				case IBD_ASYNC_EXIT:
					mutex_enter(&state->id_acache_req_lock);
#ifndef __lock_lint
					CALLB_CPR_EXIT(&cprinfo);
#else
					mutex_exit(&state->id_acache_req_lock);
#endif
					return;
				case IBD_ASYNC_RC_TOO_BIG:
					ibd_async_rc_process_too_big(state,
					    ptr);
					break;
				case IBD_ASYNC_RC_CLOSE_ACT_CHAN:
					ibd_async_rc_close_act_chan(state, ptr);
					break;
				case IBD_ASYNC_RC_RECYCLE_ACE:
					ibd_async_rc_recycle_ace(state, ptr);
					break;
				case IBD_ASYNC_RC_CLOSE_PAS_CHAN:
					(void) ibd_rc_pas_close(ptr->rq_ptr,
					    B_TRUE, B_TRUE);
					break;
			}
free_req_and_continue:
			if (ptr != NULL)
				kmem_cache_free(state->id_req_kmc, ptr);

			mutex_enter(&state->id_acache_req_lock);
		} else {
#ifndef __lock_lint
			/*
			 * Nothing to do: wait till new request arrives.
			 */
			CALLB_CPR_SAFE_BEGIN(&cprinfo);
			cv_wait(&state->id_acache_req_cv,
			    &state->id_acache_req_lock);
			CALLB_CPR_SAFE_END(&cprinfo,
			    &state->id_acache_req_lock);
#endif
		}
	}

	/*NOTREACHED*/
	_NOTE(NOT_REACHED)
}

/*
 * Return when it is safe to queue requests to the async daemon; primarily
 * for subnet trap and async event handling. Disallow requests before the
 * daemon is created, and when interface deinitilization starts.
 */
static boolean_t
ibd_async_safe(ibd_state_t *state)
{
	mutex_enter(&state->id_trap_lock);
	if (state->id_trap_stop) {
		mutex_exit(&state->id_trap_lock);
		return (B_FALSE);
	}
	state->id_trap_inprog++;
	mutex_exit(&state->id_trap_lock);
	return (B_TRUE);
}

/*
 * Wake up ibd_m_stop() if the unplumb code is waiting for pending subnet
 * trap or event handling to complete to kill the async thread and deconstruct
 * the mcg/ace list.
 */
static void
ibd_async_done(ibd_state_t *state)
{
	mutex_enter(&state->id_trap_lock);
	if (--state->id_trap_inprog == 0)
		cv_signal(&state->id_trap_cv);
	mutex_exit(&state->id_trap_lock);
}

/*
 * Hash functions:
 * ibd_hash_by_id: Returns the qpn as the hash entry into bucket.
 * ibd_hash_key_cmp: Compares two keys, return 0 on success or else 1.
 * These operate on mac addresses input into ibd_send, but there is no
 * guarantee on the alignment of the ipoib_mac_t structure.
 */
/*ARGSUSED*/
static uint_t
ibd_hash_by_id(void *hash_data, mod_hash_key_t key)
{
	ulong_t ptraddr = (ulong_t)key;
	uint_t hval;

	/*
	 * If the input address is 4 byte aligned, we can just dereference
	 * it. This is most common, since IP will send in a 4 byte aligned
	 * IP header, which implies the 24 byte IPoIB psuedo header will be
	 * 4 byte aligned too.
	 */
	if ((ptraddr & 3) == 0)
		return ((uint_t)((ipoib_mac_t *)key)->ipoib_qpn);

	bcopy(&(((ipoib_mac_t *)key)->ipoib_qpn), &hval, sizeof (uint_t));
	return (hval);
}

static int
ibd_hash_key_cmp(mod_hash_key_t key1, mod_hash_key_t key2)
{
	if (bcmp((char *)key1, (char *)key2, IPOIB_ADDRL) == 0)
		return (0);
	else
		return (1);
}

/*
 * Initialize all the per interface caches and lists; AH cache,
 * MCG list etc.
 */
static int
ibd_acache_init(ibd_state_t *state)
{
	ibd_ace_t *ce;
	int i;

	mutex_init(&state->id_ac_mutex, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&state->id_mc_mutex, NULL, MUTEX_DRIVER, NULL);
	mutex_enter(&state->id_ac_mutex);
	list_create(&state->id_ah_free, sizeof (ibd_ace_t),
	    offsetof(ibd_ace_t, ac_list));
	list_create(&state->id_ah_active, sizeof (ibd_ace_t),
	    offsetof(ibd_ace_t, ac_list));
	state->id_ah_active_hash = mod_hash_create_extended("IBD AH hash",
	    state->id_hash_size, mod_hash_null_keydtor, mod_hash_null_valdtor,
	    ibd_hash_by_id, NULL, ibd_hash_key_cmp, KM_SLEEP);
	list_create(&state->id_mc_full, sizeof (ibd_mce_t),
	    offsetof(ibd_mce_t, mc_list));
	list_create(&state->id_mc_non, sizeof (ibd_mce_t),
	    offsetof(ibd_mce_t, mc_list));
	state->id_ac_hot_ace = NULL;

	state->id_ac_list = ce = (ibd_ace_t *)kmem_zalloc(sizeof (ibd_ace_t) *
	    state->id_num_ah, KM_SLEEP);
	for (i = 0; i < state->id_num_ah; i++, ce++) {
		if (ibt_alloc_ud_dest(state->id_hca_hdl, IBT_UD_DEST_NO_FLAGS,
		    state->id_pd_hdl, &ce->ac_dest) != IBT_SUCCESS) {
			mutex_exit(&state->id_ac_mutex);
			ibd_acache_fini(state);
			return (DDI_FAILURE);
		} else {
			CLEAR_REFCYCLE(ce);
			ce->ac_mce = NULL;
			mutex_init(&ce->tx_too_big_mutex, NULL,
			    MUTEX_DRIVER, NULL);
			IBD_ACACHE_INSERT_FREE(state, ce);
		}
	}
	mutex_exit(&state->id_ac_mutex);
	return (DDI_SUCCESS);
}

static void
ibd_acache_fini(ibd_state_t *state)
{
	ibd_ace_t *ptr;

	mutex_enter(&state->id_ac_mutex);

	while ((ptr = IBD_ACACHE_GET_ACTIVE(state)) != NULL) {
		ASSERT(GET_REF(ptr) == 0);
		mutex_destroy(&ptr->tx_too_big_mutex);
		(void) ibt_free_ud_dest(ptr->ac_dest);
	}

	while ((ptr = IBD_ACACHE_GET_FREE(state)) != NULL) {
		ASSERT(GET_REF(ptr) == 0);
		mutex_destroy(&ptr->tx_too_big_mutex);
		(void) ibt_free_ud_dest(ptr->ac_dest);
	}

	list_destroy(&state->id_ah_free);
	list_destroy(&state->id_ah_active);
	list_destroy(&state->id_mc_full);
	list_destroy(&state->id_mc_non);
	kmem_free(state->id_ac_list, sizeof (ibd_ace_t) * state->id_num_ah);
	mutex_exit(&state->id_ac_mutex);
	mutex_destroy(&state->id_ac_mutex);
	mutex_destroy(&state->id_mc_mutex);
}

/*
 * Search AH active hash list for a cached path to input destination.
 * If we are "just looking", hold == F. When we are in the Tx path,
 * we set hold == T to grab a reference on the AH so that it can not
 * be recycled to a new destination while the Tx request is posted.
 */
ibd_ace_t *
ibd_acache_find(ibd_state_t *state, ipoib_mac_t *mac, boolean_t hold, int num)
{
	ibd_ace_t *ptr;

	ASSERT(mutex_owned(&state->id_ac_mutex));

	/*
	 * Do hash search.
	 */
	if (mod_hash_find(state->id_ah_active_hash,
	    (mod_hash_key_t)mac, (mod_hash_val_t)&ptr) == 0) {
		if (hold)
			INC_REF(ptr, num);
		return (ptr);
	}
	return (NULL);
}

/*
 * This is called by the tx side; if an initialized AH is found in
 * the active list, it is locked down and can be used; if no entry
 * is found, an async request is queued to do path resolution.
 */
static ibd_ace_t *
ibd_acache_lookup(ibd_state_t *state, ipoib_mac_t *mac, int *err, int numwqe)
{
	ibd_ace_t *ptr;
	ibd_req_t *req;

	/*
	 * Only attempt to print when we can; in the mdt pattr case, the
	 * address is not aligned properly.
	 */
	if (((ulong_t)mac & 3) == 0) {
		DPRINT(4,
		    "ibd_acache_lookup : lookup for %08X:%08X:%08X:%08X:%08X",
		    htonl(mac->ipoib_qpn), htonl(mac->ipoib_gidpref[0]),
		    htonl(mac->ipoib_gidpref[1]), htonl(mac->ipoib_gidsuff[0]),
		    htonl(mac->ipoib_gidsuff[1]));
	}

	mutex_enter(&state->id_ac_mutex);

	if (((ptr = state->id_ac_hot_ace) != NULL) &&
	    (memcmp(&ptr->ac_mac, mac, sizeof (*mac)) == 0)) {
		INC_REF(ptr, numwqe);
		mutex_exit(&state->id_ac_mutex);
		return (ptr);
	}
	if (((ptr = ibd_acache_find(state, mac, B_TRUE, numwqe)) != NULL)) {
		state->id_ac_hot_ace = ptr;
		mutex_exit(&state->id_ac_mutex);
		return (ptr);
	}

	/*
	 * Implementation of a single outstanding async request; if
	 * the operation is not started yet, queue a request and move
	 * to ongoing state. Remember in id_ah_addr for which address
	 * we are queueing the request, in case we need to flag an error;
	 * Any further requests, for the same or different address, until
	 * the operation completes, is sent back to GLDv3 to be retried.
	 * The async thread will update id_ah_op with an error indication
	 * or will set it to indicate the next look up can start; either
	 * way, it will mac_tx_update() so that all blocked requests come
	 * back here.
	 */
	*err = EAGAIN;
	if (state->id_ah_op == IBD_OP_NOTSTARTED) {
		req = kmem_cache_alloc(state->id_req_kmc, KM_NOSLEEP);
		if (req != NULL) {
			/*
			 * We did not even find the entry; queue a request
			 * for it.
			 */
			bcopy(mac, &(req->rq_mac), IPOIB_ADDRL);
			state->id_ah_op = IBD_OP_ONGOING;
			ibd_queue_work_slot(state, req, IBD_ASYNC_GETAH);
			bcopy(mac, &state->id_ah_addr, IPOIB_ADDRL);
		}
	} else if ((state->id_ah_op != IBD_OP_ONGOING) &&
	    (bcmp(&state->id_ah_addr, mac, IPOIB_ADDRL) == 0)) {
		/*
		 * Check the status of the pathrecord lookup request
		 * we had queued before.
		 */
		if (state->id_ah_op == IBD_OP_ERRORED) {
			*err = EFAULT;
			state->id_ah_error++;
		} else {
			/*
			 * IBD_OP_ROUTERED case: We need to send to the
			 * all-router MCG. If we can find the AH for
			 * the mcg, the Tx will be attempted. If we
			 * do not find the AH, we return NORESOURCES
			 * to retry.
			 */
			ipoib_mac_t routermac;

			(void) ibd_get_allroutergroup(state, mac, &routermac);
			ptr = ibd_acache_find(state, &routermac, B_TRUE,
			    numwqe);
		}
		state->id_ah_op = IBD_OP_NOTSTARTED;
	} else if ((state->id_ah_op != IBD_OP_ONGOING) &&
	    (bcmp(&state->id_ah_addr, mac, IPOIB_ADDRL) != 0)) {
		/*
		 * This case can happen when we get a higher band
		 * packet. The easiest way is to reset the state machine
		 * to accommodate the higher priority packet.
		 */
		state->id_ah_op = IBD_OP_NOTSTARTED;
	}
	mutex_exit(&state->id_ac_mutex);

	return (ptr);
}

/*
 * Grab a not-currently-in-use AH/PathRecord from the active
 * list to recycle to a new destination. Only the async thread
 * executes this code.
 */
static ibd_ace_t *
ibd_acache_get_unref(ibd_state_t *state)
{
	ibd_ace_t *ptr = list_tail(&state->id_ah_active);
	boolean_t try_rc_chan_recycle = B_FALSE;

	ASSERT(mutex_owned(&state->id_ac_mutex));

	/*
	 * Do plain linear search.
	 */
	while (ptr != NULL) {
		/*
		 * Note that it is possible that the "cycle" bit
		 * is set on the AH w/o any reference count. The
		 * mcg must have been deleted, and the tx cleanup
		 * just decremented the reference count to 0, but
		 * hasn't gotten around to grabbing the id_ac_mutex
		 * to move the AH into the free list.
		 */
		if (GET_REF(ptr) == 0) {
			if (ptr->ac_chan != NULL) {
				ASSERT(state->id_enable_rc == B_TRUE);
				if (!try_rc_chan_recycle) {
					try_rc_chan_recycle = B_TRUE;
					ibd_rc_signal_ace_recycle(state, ptr);
				}
			} else {
				IBD_ACACHE_PULLOUT_ACTIVE(state, ptr);
				break;
			}
		}
		ptr = list_prev(&state->id_ah_active, ptr);
	}
	return (ptr);
}

/*
 * Invoked to clean up AH from active list in case of multicast
 * disable and to handle sendonly memberships during mcg traps.
 * And for port up processing for multicast and unicast AHs.
 * Normally, the AH is taken off the active list, and put into
 * the free list to be recycled for a new destination. In case
 * Tx requests on the AH have not completed yet, the AH is marked
 * for reaping (which will put the AH on the free list) once the Tx's
 * complete; in this case, depending on the "force" input, we take
 * out the AH from the active list right now, or leave it also for
 * the reap operation. Returns TRUE if the AH is taken off the active
 * list (and either put into the free list right now, or arranged for
 * later), FALSE otherwise.
 */
boolean_t
ibd_acache_recycle(ibd_state_t *state, ipoib_mac_t *acmac, boolean_t force)
{
	ibd_ace_t *acactive;
	boolean_t ret = B_TRUE;

	ASSERT(mutex_owned(&state->id_ac_mutex));

	if ((acactive = ibd_acache_find(state, acmac, B_FALSE, 0)) != NULL) {

		/*
		 * Note that the AH might already have the cycle bit set
		 * on it; this might happen if sequences of multicast
		 * enables and disables are coming so fast, that posted
		 * Tx's to the mcg have not completed yet, and the cycle
		 * bit is set successively by each multicast disable.
		 */
		if (SET_CYCLE_IF_REF(acactive)) {
			if (!force) {
				/*
				 * The ace is kept on the active list, further
				 * Tx's can still grab a reference on it; the
				 * ace is reaped when all pending Tx's
				 * referencing the AH complete.
				 */
				ret = B_FALSE;
			} else {
				/*
				 * In the mcg trap case, we always pull the
				 * AH from the active list. And also the port
				 * up multi/unicast case.
				 */
				ASSERT(acactive->ac_chan == NULL);
				IBD_ACACHE_PULLOUT_ACTIVE(state, acactive);
				acactive->ac_mce = NULL;
			}
		} else {
			/*
			 * Determined the ref count is 0, thus reclaim
			 * immediately after pulling out the ace from
			 * the active list.
			 */
			ASSERT(acactive->ac_chan == NULL);
			IBD_ACACHE_PULLOUT_ACTIVE(state, acactive);
			acactive->ac_mce = NULL;
			IBD_ACACHE_INSERT_FREE(state, acactive);
		}

	}
	return (ret);
}

/*
 * Helper function for async path record lookup. If we are trying to
 * Tx to a MCG, check our membership, possibly trying to join the
 * group if required. If that fails, try to send the packet to the
 * all router group (indicated by the redirect output), pointing
 * the input mac address to the router mcg address.
 */
static ibd_mce_t *
ibd_async_mcache(ibd_state_t *state, ipoib_mac_t *mac, boolean_t *redirect)
{
	ib_gid_t mgid;
	ibd_mce_t *mce;
	ipoib_mac_t routermac;

	*redirect = B_FALSE;
	ibd_n2h_gid(mac, &mgid);

	/*
	 * Check the FullMember+SendOnlyNonMember list.
	 * Since we are the only one who manipulates the
	 * id_mc_full list, no locks are needed.
	 */
	mce = IBD_MCACHE_FIND_FULL(state, mgid);
	if (mce != NULL) {
		DPRINT(4, "ibd_async_mcache : already joined to group");
		return (mce);
	}

	/*
	 * Not found; try to join(SendOnlyNonMember) and attach.
	 */
	DPRINT(4, "ibd_async_mcache : not joined to group");
	if ((mce = ibd_join_group(state, mgid, IB_MC_JSTATE_SEND_ONLY_NON)) !=
	    NULL) {
		DPRINT(4, "ibd_async_mcache : nonmem joined to group");
		return (mce);
	}

	/*
	 * MCGroup not present; try to join the all-router group. If
	 * any of the following steps succeed, we will be redirecting
	 * to the all router group.
	 */
	DPRINT(4, "ibd_async_mcache : nonmem join failed");
	if (!ibd_get_allroutergroup(state, mac, &routermac))
		return (NULL);
	*redirect = B_TRUE;
	ibd_n2h_gid(&routermac, &mgid);
	bcopy(&routermac, mac, IPOIB_ADDRL);
	DPRINT(4, "ibd_async_mcache : router mgid : %016llx:%016llx\n",
	    mgid.gid_prefix, mgid.gid_guid);

	/*
	 * Are we already joined to the router group?
	 */
	if ((mce = IBD_MCACHE_FIND_FULL(state, mgid)) != NULL) {
		DPRINT(4, "ibd_async_mcache : using already joined router"
		    "group\n");
		return (mce);
	}

	/*
	 * Can we join(SendOnlyNonMember) the router group?
	 */
	DPRINT(4, "ibd_async_mcache : attempting join to router grp");
	if ((mce = ibd_join_group(state, mgid, IB_MC_JSTATE_SEND_ONLY_NON)) !=
	    NULL) {
		DPRINT(4, "ibd_async_mcache : joined to router grp");
		return (mce);
	}

	return (NULL);
}

/*
 * Async path record lookup code.
 */
static void
ibd_async_acache(ibd_state_t *state, ipoib_mac_t *mac)
{
	ibd_ace_t *ce;
	ibd_mce_t *mce = NULL;
	ibt_path_attr_t path_attr;
	ibt_path_info_t path_info;
	ib_gid_t destgid;
	char ret = IBD_OP_NOTSTARTED;

	DPRINT(4, "ibd_async_acache :  %08X:%08X:%08X:%08X:%08X",
	    htonl(mac->ipoib_qpn), htonl(mac->ipoib_gidpref[0]),
	    htonl(mac->ipoib_gidpref[1]), htonl(mac->ipoib_gidsuff[0]),
	    htonl(mac->ipoib_gidsuff[1]));

	/*
	 * Check whether we are trying to transmit to a MCG.
	 * In that case, we need to make sure we are a member of
	 * the MCG.
	 */
	if (mac->ipoib_qpn == htonl(IB_MC_QPN)) {
		boolean_t redirected;

		/*
		 * If we can not find or join the group or even
		 * redirect, error out.
		 */
		if ((mce = ibd_async_mcache(state, mac, &redirected)) ==
		    NULL) {
			state->id_ah_op = IBD_OP_ERRORED;
			return;
		}

		/*
		 * If we got redirected, we need to determine whether
		 * the AH for the new mcg is in the cache already, and
		 * not pull it in then; otherwise proceed to get the
		 * path for the new mcg. There is no guarantee that
		 * if the AH is currently in the cache, it will still be
		 * there when we look in ibd_acache_lookup(), but that's
		 * okay, we will come back here.
		 */
		if (redirected) {
			ret = IBD_OP_ROUTERED;
			DPRINT(4, "ibd_async_acache :  redirected to "
			    "%08X:%08X:%08X:%08X:%08X",
			    htonl(mac->ipoib_qpn), htonl(mac->ipoib_gidpref[0]),
			    htonl(mac->ipoib_gidpref[1]),
			    htonl(mac->ipoib_gidsuff[0]),
			    htonl(mac->ipoib_gidsuff[1]));

			mutex_enter(&state->id_ac_mutex);
			if (ibd_acache_find(state, mac, B_FALSE, 0) != NULL) {
				state->id_ah_op = IBD_OP_ROUTERED;
				mutex_exit(&state->id_ac_mutex);
				DPRINT(4, "ibd_async_acache : router AH found");
				return;
			}
			mutex_exit(&state->id_ac_mutex);
		}
	}

	/*
	 * Get an AH from the free list.
	 */
	mutex_enter(&state->id_ac_mutex);
	if ((ce = IBD_ACACHE_GET_FREE(state)) == NULL) {
		/*
		 * No free ones; try to grab an unreferenced active
		 * one. Maybe we need to make the active list LRU,
		 * but that will create more work for Tx callbacks.
		 * Is there a way of not having to pull out the
		 * entry from the active list, but just indicate it
		 * is being recycled? Yes, but that creates one more
		 * check in the fast lookup path.
		 */
		if ((ce = ibd_acache_get_unref(state)) == NULL) {
			/*
			 * Pretty serious shortage now.
			 */
			state->id_ah_op = IBD_OP_NOTSTARTED;
			mutex_exit(&state->id_ac_mutex);
			DPRINT(10, "ibd_async_acache : failed to find AH "
			    "slot\n");
			return;
		}
		/*
		 * We could check whether ac_mce points to a SendOnly
		 * member and drop that membership now. Or do it lazily
		 * at detach time.
		 */
		ce->ac_mce = NULL;
	}
	mutex_exit(&state->id_ac_mutex);
	ASSERT(ce->ac_mce == NULL);

	/*
	 * Update the entry.
	 */
	bcopy((char *)mac, &ce->ac_mac, IPOIB_ADDRL);

	bzero(&path_info, sizeof (path_info));
	bzero(&path_attr, sizeof (ibt_path_attr_t));
	path_attr.pa_sgid = state->id_sgid;
	path_attr.pa_num_dgids = 1;
	ibd_n2h_gid(&ce->ac_mac, &destgid);
	path_attr.pa_dgids = &destgid;
	path_attr.pa_sl = state->id_mcinfo->mc_adds_vect.av_srvl;
	path_attr.pa_pkey = state->id_pkey;
	if (ibt_get_paths(state->id_ibt_hdl, IBT_PATH_PKEY, &path_attr, 1,
	    &path_info, NULL) != IBT_SUCCESS) {
		DPRINT(10, "ibd_async_acache : failed in ibt_get_paths");
		goto error;
	}
	if (ibt_modify_ud_dest(ce->ac_dest, state->id_mcinfo->mc_qkey,
	    ntohl(ce->ac_mac.ipoib_qpn),
	    &path_info.pi_prim_cep_path.cep_adds_vect) != IBT_SUCCESS) {
		DPRINT(10, "ibd_async_acache : failed in ibt_modify_ud_dest");
		goto error;
	}

	/*
	 * mce is set whenever an AH is being associated with a
	 * MCG; this will come in handy when we leave the MCG. The
	 * lock protects Tx fastpath from scanning the active list.
	 */
	if (mce != NULL)
		ce->ac_mce = mce;

	/*
	 * initiate a RC mode connection for unicast address
	 */
	if (state->id_enable_rc && (mac->ipoib_qpn != htonl(IB_MC_QPN)) &&
	    (htonl(mac->ipoib_qpn) & IBD_MAC_ADDR_RC)) {
		ASSERT(ce->ac_chan == NULL);
		DPRINT(10, "ibd_async_acache: call "
		    "ibd_rc_try_connect(ace=%p)", ce);
		ibd_rc_try_connect(state, ce, &path_info);
		if (ce->ac_chan == NULL) {
			DPRINT(10, "ibd_async_acache: fail to setup RC"
			    " channel");
			state->rc_conn_fail++;
			goto error;
		}
	}

	mutex_enter(&state->id_ac_mutex);
	IBD_ACACHE_INSERT_ACTIVE(state, ce);
	state->id_ah_op = ret;
	mutex_exit(&state->id_ac_mutex);
	return;
error:
	/*
	 * We might want to drop SendOnly membership here if we
	 * joined above. The lock protects Tx callbacks inserting
	 * into the free list.
	 */
	mutex_enter(&state->id_ac_mutex);
	state->id_ah_op = IBD_OP_ERRORED;
	IBD_ACACHE_INSERT_FREE(state, ce);
	mutex_exit(&state->id_ac_mutex);
}

/*
 * While restoring port's presence on the subnet on a port up, it is possible
 * that the port goes down again.
 */
static void
ibd_async_link(ibd_state_t *state, ibd_req_t *req)
{
	ibd_link_op_t opcode = (ibd_link_op_t)req->rq_ptr;
	link_state_t lstate = (opcode == IBD_LINK_DOWN) ? LINK_STATE_DOWN :
	    LINK_STATE_UP;
	ibd_mce_t *mce, *pmce;
	ibd_ace_t *ace, *pace;

	DPRINT(10, "ibd_async_link(): %d", opcode);

	/*
	 * On a link up, revalidate the link speed/width. No point doing
	 * this on a link down, since we will be unable to do SA operations,
	 * defaulting to the lowest speed. Also notice that we update our
	 * notion of speed before calling mac_link_update(), which will do
	 * necessary higher level notifications for speed changes.
	 */
	if ((opcode == IBD_LINK_UP_ABSENT) || (opcode == IBD_LINK_UP)) {
		_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*state))
		state->id_link_speed = ibd_get_portspeed(state);
		_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*state))
	}

	/*
	 * Do all the work required to establish our presence on
	 * the subnet.
	 */
	if (opcode == IBD_LINK_UP_ABSENT) {
		/*
		 * If in promiscuous mode ...
		 */
		if (state->id_prom_op == IBD_OP_COMPLETED) {
			/*
			 * Drop all nonmembership.
			 */
			ibd_async_unsetprom(state);

			/*
			 * Then, try to regain nonmembership to all mcg's.
			 */
			ibd_async_setprom(state);

		}

		/*
		 * Drop all sendonly membership (which also gets rid of the
		 * AHs); try to reacquire all full membership.
		 */
		mce = list_head(&state->id_mc_full);
		while ((pmce = mce) != NULL) {
			mce = list_next(&state->id_mc_full, mce);
			if (pmce->mc_jstate == IB_MC_JSTATE_SEND_ONLY_NON)
				ibd_leave_group(state,
				    pmce->mc_info.mc_adds_vect.av_dgid,
				    IB_MC_JSTATE_SEND_ONLY_NON);
			else
				ibd_reacquire_group(state, pmce);
		}

		/*
		 * Recycle all active AHs to free list (and if there are
		 * pending posts, make sure they will go into the free list
		 * once the Tx's complete). Grab the lock to prevent
		 * concurrent Tx's as well as Tx cleanups.
		 */
		mutex_enter(&state->id_ac_mutex);
		ace = list_head(&state->id_ah_active);
		while ((pace = ace) != NULL) {
			boolean_t cycled;

			ace = list_next(&state->id_ah_active, ace);
			mce = pace->ac_mce;
			if (pace->ac_chan != NULL) {
				ASSERT(mce == NULL);
				ASSERT(state->id_enable_rc == B_TRUE);
				if (pace->ac_chan->chan_state ==
				    IBD_RC_STATE_ACT_ESTAB) {
					INC_REF(pace, 1);
					IBD_ACACHE_PULLOUT_ACTIVE(state, pace);
					pace->ac_chan->chan_state =
					    IBD_RC_STATE_ACT_CLOSING;
					ibd_rc_signal_act_close(state, pace);
				} else {
					state->rc_act_close_simultaneous++;
					DPRINT(40, "ibd_async_link: other "
					    "thread is closing it, ace=%p, "
					    "ac_chan=%p, chan_state=%d",
					    pace, pace->ac_chan,
					    pace->ac_chan->chan_state);
				}
			} else {
				cycled = ibd_acache_recycle(state,
				    &pace->ac_mac, B_TRUE);
			}
			/*
			 * If this is for an mcg, it must be for a fullmember,
			 * since we got rid of send-only members above when
			 * processing the mce list.
			 */
			ASSERT(cycled && ((mce == NULL) || (mce->mc_jstate ==
			    IB_MC_JSTATE_FULL)));

			/*
			 * Check if the fullmember mce needs to be torn down,
			 * ie whether the DLPI disable has already been done.
			 * If so, do some of the work of tx_cleanup, namely
			 * causing leave (which will fail), detach and
			 * mce-freeing. tx_cleanup will put the AH into free
			 * list. The reason to duplicate some of this
			 * tx_cleanup work is because we want to delete the
			 * AH right now instead of waiting for tx_cleanup, to
			 * force subsequent Tx's to reacquire an AH.
			 */
			if ((mce != NULL) && (mce->mc_fullreap))
				ibd_async_reap_group(state, mce,
				    mce->mc_info.mc_adds_vect.av_dgid,
				    mce->mc_jstate);
		}
		mutex_exit(&state->id_ac_mutex);
	}

	/*
	 * mac handle is guaranteed to exist since driver does ibt_close_hca()
	 * (which stops further events from being delivered) before
	 * mac_unregister(). At this point, it is guaranteed that mac_register
	 * has already been done.
	 */
	mutex_enter(&state->id_link_mutex);
	state->id_link_state = lstate;
	mac_link_update(state->id_mh, lstate);
	mutex_exit(&state->id_link_mutex);

	ibd_async_done(state);
}

/*
 * Check the pkey table to see if we can find the pkey we're looking for.
 * Set the pkey index in 'pkix' if found. Return 0 on success and -1 on
 * failure.
 */
static int
ibd_locate_pkey(ib_pkey_t *pkey_tbl, uint16_t pkey_tbl_sz, ib_pkey_t pkey,
    uint16_t *pkix)
{
	uint16_t ndx;

	ASSERT(pkix != NULL);

	for (ndx = 0; ndx < pkey_tbl_sz; ndx++) {
		if (pkey_tbl[ndx] == pkey) {
			*pkix = ndx;
			return (0);
		}
	}
	return (-1);
}

/*
 * Late HCA Initialization:
 * If plumb had succeeded without the availability of an active port or the
 * pkey, and either of their availability is now being indicated via PORT_UP
 * or PORT_CHANGE respectively, try a start of the interface.
 *
 * Normal Operation:
 * When the link is notified up, we need to do a few things, based
 * on the port's current p_init_type_reply claiming a reinit has been
 * done or not. The reinit steps are:
 * 1. If in InitTypeReply, NoLoadReply == PreserveContentReply == 0, verify
 *    the old Pkey and GID0 are correct.
 * 2. Register for mcg traps (already done by ibmf).
 * 3. If PreservePresenceReply indicates the SM has restored port's presence
 *    in subnet, nothing more to do. Else go to next steps (on async daemon).
 * 4. Give up all sendonly memberships.
 * 5. Acquire all full memberships.
 * 6. In promiscuous mode, acquire all non memberships.
 * 7. Recycle all AHs to free list.
 */
static void
ibd_link_mod(ibd_state_t *state, ibt_async_code_t code)
{
	ibt_hca_portinfo_t *port_infop = NULL;
	ibt_status_t ibt_status;
	uint_t psize, port_infosz;
	ibd_link_op_t opcode;
	ibd_req_t *req;
	link_state_t new_link_state = LINK_STATE_UP;
	uint8_t itreply;
	uint16_t pkix;
	int ret;

	/*
	 * Let's not race with a plumb or an unplumb; if we detect a
	 * pkey relocation event later on here, we may have to restart.
	 */
	ibd_set_mac_progress(state, IBD_DRV_RESTART_IN_PROGRESS);

	mutex_enter(&state->id_link_mutex);

	/*
	 * If the link state is unknown, a plumb has not yet been attempted
	 * on the interface. Nothing to do.
	 */
	if (state->id_link_state == LINK_STATE_UNKNOWN) {
		mutex_exit(&state->id_link_mutex);
		goto link_mod_return;
	}

	/*
	 * If link state is down because of plumb failure, and we are not in
	 * late HCA init, and we were not successfully plumbed, nothing to do.
	 */
	if ((state->id_link_state == LINK_STATE_DOWN) &&
	    ((state->id_mac_state & IBD_DRV_IN_LATE_HCA_INIT) == 0) &&
	    ((state->id_mac_state & IBD_DRV_STARTED) == 0)) {
		mutex_exit(&state->id_link_mutex);
		goto link_mod_return;
	}

	/*
	 * If this routine was called in response to a port down event,
	 * we just need to see if this should be informed.
	 */
	if (code == IBT_ERROR_PORT_DOWN) {
		new_link_state = LINK_STATE_DOWN;
		goto update_link_state;
	}

	/*
	 * If it's not a port down event we've received, try to get the port
	 * attributes first. If we fail here, the port is as good as down.
	 * Otherwise, if the link went down by the time the handler gets
	 * here, give up - we cannot even validate the pkey/gid since those
	 * are not valid and this is as bad as a port down anyway.
	 */
	ibt_status = ibt_query_hca_ports(state->id_hca_hdl, state->id_port,
	    &port_infop, &psize, &port_infosz);
	if ((ibt_status != IBT_SUCCESS) || (psize != 1) ||
	    (port_infop->p_linkstate != IBT_PORT_ACTIVE)) {
		new_link_state = LINK_STATE_DOWN;
		goto update_link_state;
	}

	/*
	 * If in the previous attempt, the pkey was not found either due to the
	 * port state being down, or due to it's absence in the pkey table,
	 * look for it now and try to start the interface.
	 */
	if (state->id_mac_state & IBD_DRV_IN_LATE_HCA_INIT) {
		mutex_exit(&state->id_link_mutex);
		if ((ret = ibd_start(state)) != 0) {
			DPRINT(10, "ibd_linkmod: cannot start from late HCA "
			    "init, ret=%d", ret);
		}
		ibt_free_portinfo(port_infop, port_infosz);
		goto link_mod_return;
	}

	/*
	 * Check the SM InitTypeReply flags. If both NoLoadReply and
	 * PreserveContentReply are 0, we don't know anything about the
	 * data loaded into the port attributes, so we need to verify
	 * if gid0 and pkey are still valid.
	 */
	itreply = port_infop->p_init_type_reply;
	if (((itreply & SM_INIT_TYPE_REPLY_NO_LOAD_REPLY) == 0) &&
	    ((itreply & SM_INIT_TYPE_PRESERVE_CONTENT_REPLY) == 0)) {
		/*
		 * Check to see if the subnet part of GID0 has changed. If
		 * not, check the simple case first to see if the pkey
		 * index is the same as before; finally check to see if the
		 * pkey has been relocated to a different index in the table.
		 */
		_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(state->id_sgid))
		if (bcmp(port_infop->p_sgid_tbl,
		    &state->id_sgid, sizeof (ib_gid_t)) != 0) {

			new_link_state = LINK_STATE_DOWN;

		} else if (port_infop->p_pkey_tbl[state->id_pkix] ==
		    state->id_pkey) {

			new_link_state = LINK_STATE_UP;

		} else if (ibd_locate_pkey(port_infop->p_pkey_tbl,
		    port_infop->p_pkey_tbl_sz, state->id_pkey, &pkix) == 0) {

			ibt_free_portinfo(port_infop, port_infosz);
			mutex_exit(&state->id_link_mutex);

			/*
			 * Currently a restart is required if our pkey has moved
			 * in the pkey table. If we get the ibt_recycle_ud() to
			 * work as documented (expected), we may be able to
			 * avoid a complete restart.  Note that we've already
			 * marked both the start and stop 'in-progress' flags,
			 * so it is ok to go ahead and do this restart.
			 */
			(void) ibd_undo_start(state, LINK_STATE_DOWN);
			if ((ret = ibd_start(state)) != 0) {
				DPRINT(10, "ibd_restart: cannot restart, "
				    "ret=%d", ret);
			}

			goto link_mod_return;
		} else {
			new_link_state = LINK_STATE_DOWN;
		}
		_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(state->id_sgid))
	}

update_link_state:
	if (port_infop) {
		ibt_free_portinfo(port_infop, port_infosz);
	}

	/*
	 * If we're reporting a link up, check InitTypeReply to see if
	 * the SM has ensured that the port's presence in mcg, traps,
	 * etc. is intact.
	 */
	if (new_link_state == LINK_STATE_DOWN) {
		opcode = IBD_LINK_DOWN;
	} else {
		if ((itreply & SM_INIT_TYPE_PRESERVE_PRESENCE_REPLY) ==
		    SM_INIT_TYPE_PRESERVE_PRESENCE_REPLY) {
			opcode = IBD_LINK_UP;
		} else {
			opcode = IBD_LINK_UP_ABSENT;
		}
	}

	/*
	 * If the old state is the same as the new state, and the SM indicated
	 * no change in the port parameters, nothing to do.
	 */
	if ((state->id_link_state == new_link_state) && (opcode !=
	    IBD_LINK_UP_ABSENT)) {
		mutex_exit(&state->id_link_mutex);
		goto link_mod_return;
	}

	/*
	 * Ok, so there was a link state change; see if it's safe to ask
	 * the async thread to do the work
	 */
	if (!ibd_async_safe(state)) {
		state->id_link_state = new_link_state;
		mutex_exit(&state->id_link_mutex);
		goto link_mod_return;
	}

	mutex_exit(&state->id_link_mutex);

	/*
	 * Queue up a request for ibd_async_link() to handle this link
	 * state change event
	 */
	req = kmem_cache_alloc(state->id_req_kmc, KM_SLEEP);
	req->rq_ptr = (void *)opcode;
	ibd_queue_work_slot(state, req, IBD_ASYNC_LINK);

link_mod_return:
	ibd_clr_mac_progress(state, IBD_DRV_RESTART_IN_PROGRESS);
}

/*
 * For the port up/down events, IBTL guarantees there will not be concurrent
 * invocations of the handler. IBTL might coalesce link transition events,
 * and not invoke the handler for _each_ up/down transition, but it will
 * invoke the handler with last known state
 */
static void
ibd_async_handler(void *clnt_private, ibt_hca_hdl_t hca_hdl,
    ibt_async_code_t code, ibt_async_event_t *event)
{
	ibd_state_t *state = (ibd_state_t *)clnt_private;

	switch (code) {
	case IBT_ERROR_CATASTROPHIC_CHAN:
		ibd_print_warn(state, "catastrophic channel error");
		break;
	case IBT_ERROR_CQ:
		ibd_print_warn(state, "completion queue error");
		break;
	case IBT_PORT_CHANGE_EVENT:
		/*
		 * Events will be delivered to all instances that have
		 * done ibt_open_hca() but not yet done ibt_close_hca().
		 * Only need to do work for our port; IBTF will deliver
		 * events for other ports on the hca we have ibt_open_hca'ed
		 * too. Note that id_port is initialized in ibd_attach()
		 * before we do an ibt_open_hca() in ibd_attach().
		 */
		ASSERT(state->id_hca_hdl == hca_hdl);
		if (state->id_port != event->ev_port)
			break;

		if ((event->ev_port_flags & IBT_PORT_CHANGE_PKEY) ==
		    IBT_PORT_CHANGE_PKEY) {
			ibd_link_mod(state, code);
		}
		break;
	case IBT_ERROR_PORT_DOWN:
	case IBT_CLNT_REREG_EVENT:
	case IBT_EVENT_PORT_UP:
		/*
		 * Events will be delivered to all instances that have
		 * done ibt_open_hca() but not yet done ibt_close_hca().
		 * Only need to do work for our port; IBTF will deliver
		 * events for other ports on the hca we have ibt_open_hca'ed
		 * too. Note that id_port is initialized in ibd_attach()
		 * before we do an ibt_open_hca() in ibd_attach().
		 */
		ASSERT(state->id_hca_hdl == hca_hdl);
		if (state->id_port != event->ev_port)
			break;

		ibd_link_mod(state, code);
		break;

	case IBT_HCA_ATTACH_EVENT:
	case IBT_HCA_DETACH_EVENT:
		/*
		 * When a new card is plugged to the system, attach_event is
		 * invoked. Additionally, a cfgadm needs to be run to make the
		 * card known to the system, and an ifconfig needs to be run to
		 * plumb up any ibd interfaces on the card. In the case of card
		 * unplug, a cfgadm is run that will trigger any RCM scripts to
		 * unplumb the ibd interfaces on the card; when the card is
		 * actually unplugged, the detach_event is invoked;
		 * additionally, if any ibd instances are still active on the
		 * card (eg there were no associated RCM scripts), driver's
		 * detach routine is invoked.
		 */
		break;
	default:
		break;
	}
}

static int
ibd_register_mac(ibd_state_t *state, dev_info_t *dip)
{
	mac_register_t *macp;
	int ret;

	if ((macp = mac_alloc(MAC_VERSION)) == NULL) {
		DPRINT(10, "ibd_register_mac: mac_alloc() failed");
		return (DDI_FAILURE);
	}

	/*
	 * Note that when we register with mac during attach, we don't
	 * have the id_macaddr yet, so we'll simply be registering a
	 * zero macaddr that we'll overwrite later during plumb (in
	 * ibd_m_start()). Similar is the case with id_mtu - we'll
	 * update the mac layer with the correct mtu during plumb.
	 */
	macp->m_type_ident = MAC_PLUGIN_IDENT_IB;
	macp->m_driver = state;
	macp->m_dip = dip;
	macp->m_src_addr = (uint8_t *)&state->id_macaddr;
	macp->m_callbacks = &ibd_m_callbacks;
	macp->m_min_sdu = 0;
	macp->m_multicast_sdu = IBD_DEF_MAX_SDU;
	if (state->id_type == IBD_PORT_DRIVER) {
		macp->m_max_sdu = IBD_DEF_RC_MAX_SDU;
	} else if (state->id_enable_rc) {
		macp->m_max_sdu = state->rc_mtu - IPOIB_HDRSIZE;
	} else {
		macp->m_max_sdu = IBD_DEF_MAX_SDU;
	}
	macp->m_priv_props = ibd_priv_props;

	/*
	 *  Register ourselves with the GLDv3 interface
	 */
	if ((ret = mac_register(macp, &state->id_mh)) != 0) {
		mac_free(macp);
		DPRINT(10,
		    "ibd_register_mac: mac_register() failed, ret=%d", ret);
		return (DDI_FAILURE);
	}

	mac_free(macp);
	return (DDI_SUCCESS);
}

static int
ibd_record_capab(ibd_state_t *state)
{
	ibt_hca_attr_t hca_attrs;
	ibt_status_t ibt_status;

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*state))

	/*
	 * Query the HCA and fetch its attributes
	 */
	ibt_status = ibt_query_hca(state->id_hca_hdl, &hca_attrs);
	ASSERT(ibt_status == IBT_SUCCESS);

	/*
	 * 1. Set the Hardware Checksum capability. Currently we only consider
	 *    full checksum offload.
	 */
	if (state->id_enable_rc) {
			state->id_hwcksum_capab = 0;
	} else {
		if ((hca_attrs.hca_flags & IBT_HCA_CKSUM_FULL)
		    == IBT_HCA_CKSUM_FULL) {
			state->id_hwcksum_capab = IBT_HCA_CKSUM_FULL;
		}
	}

	/*
	 * 2. Set LSO policy, capability and maximum length
	 */
	if (state->id_enable_rc) {
		state->id_lso_capable = B_FALSE;
		state->id_lso_maxlen = 0;
	} else {
		if (hca_attrs.hca_max_lso_size > 0) {
			state->id_lso_capable = B_TRUE;
			if (hca_attrs.hca_max_lso_size > IBD_LSO_MAXLEN)
				state->id_lso_maxlen = IBD_LSO_MAXLEN;
			else
				state->id_lso_maxlen =
				    hca_attrs.hca_max_lso_size;
		} else {
			state->id_lso_capable = B_FALSE;
			state->id_lso_maxlen = 0;
		}
	}

	/*
	 * 3. Set Reserved L_Key capability
	 */
	if ((hca_attrs.hca_flags2 & IBT_HCA2_RES_LKEY) == IBT_HCA2_RES_LKEY) {
		state->id_hca_res_lkey_capab = 1;
		state->id_res_lkey = hca_attrs.hca_reserved_lkey;
		state->rc_enable_iov_map = B_TRUE;
	} else {
		/* If no reserved lkey, we will not use ibt_map_mem_iov */
		state->rc_enable_iov_map = B_FALSE;
	}

	/*
	 * 4. Set maximum sqseg value after checking to see if extended sgl
	 *    size information is provided by the hca
	 */
	if (hca_attrs.hca_flags & IBT_HCA_WQE_SIZE_INFO) {
		state->id_max_sqseg = hca_attrs.hca_ud_send_sgl_sz;
		state->rc_tx_max_sqseg = hca_attrs.hca_conn_send_sgl_sz;
	} else {
		state->id_max_sqseg = hca_attrs.hca_max_sgl;
		state->rc_tx_max_sqseg = hca_attrs.hca_max_sgl;
	}
	if (state->id_max_sqseg > IBD_MAX_SQSEG) {
		state->id_max_sqseg = IBD_MAX_SQSEG;
	} else if (state->id_max_sqseg < IBD_MAX_SQSEG) {
		ibd_print_warn(state, "Set #sgl = %d instead of default %d",
		    state->id_max_sqseg, IBD_MAX_SQSEG);
	}
	if (state->rc_tx_max_sqseg > IBD_MAX_SQSEG) {
		state->rc_tx_max_sqseg = IBD_MAX_SQSEG;
	} else if (state->rc_tx_max_sqseg < IBD_MAX_SQSEG) {
		ibd_print_warn(state, "RC mode: Set #sgl = %d instead of "
		    "default %d", state->rc_tx_max_sqseg, IBD_MAX_SQSEG);
	}

	/*
	 * Translating the virtual address regions into physical regions
	 * for using the Reserved LKey feature results in a wr sgl that
	 * is a little longer. Since failing ibt_map_mem_iov() is costly,
	 * we'll fix a high-water mark (65%) for when we should stop.
	 */
	state->id_max_sqseg_hiwm = (state->id_max_sqseg * 65) / 100;
	state->rc_max_sqseg_hiwm = (state->rc_tx_max_sqseg * 65) / 100;

	/*
	 * 5. Set number of recv and send wqes after checking hca maximum
	 *    channel size. Store the max channel size in the state so that it
	 *    can be referred to when the swqe/rwqe change is requested via
	 *    dladm.
	 */

	state->id_hca_max_chan_sz = hca_attrs.hca_max_chan_sz;

	if (hca_attrs.hca_max_chan_sz < state->id_ud_num_rwqe)
		state->id_ud_num_rwqe = hca_attrs.hca_max_chan_sz;

	state->id_rx_bufs_outstanding_limit = state->id_ud_num_rwqe -
	    IBD_RWQE_MIN;

	if (hca_attrs.hca_max_chan_sz < state->id_ud_num_swqe)
		state->id_ud_num_swqe = hca_attrs.hca_max_chan_sz;

	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(*state))

	return (DDI_SUCCESS);
}

static int
ibd_part_busy(ibd_state_t *state)
{
	if (atomic_add_32_nv(&state->id_rx_list.dl_bufs_outstanding, 0) != 0) {
		DPRINT(10, "ibd_part_busy: failed: rx bufs outstanding\n");
		return (DDI_FAILURE);
	}

	if (state->rc_srq_rwqe_list.dl_bufs_outstanding != 0) {
		DPRINT(10, "ibd_part_busy: failed: srq bufs outstanding\n");
		return (DDI_FAILURE);
	}

	/*
	 * "state->id_ah_op == IBD_OP_ONGOING" means this IPoIB port is
	 * connecting to a remote IPoIB port. We can't remove this port.
	 */
	if (state->id_ah_op == IBD_OP_ONGOING) {
		DPRINT(10, "ibd_part_busy: failed: connecting\n");
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}


static void
ibd_part_unattach(ibd_state_t *state)
{
	uint32_t progress = state->id_mac_state;
	ibt_status_t ret;

	/* make sure rx resources are freed */
	ibd_free_rx_rsrcs(state);

	if (progress & IBD_DRV_RC_SRQ_ALLOCD) {
		ASSERT(state->id_enable_rc);
		ibd_rc_fini_srq_list(state);
		state->id_mac_state &= (~IBD_DRV_RC_SRQ_ALLOCD);
	}

	if (progress & IBD_DRV_MAC_REGISTERED) {
		(void) mac_unregister(state->id_mh);
		state->id_mac_state &= (~IBD_DRV_MAC_REGISTERED);
	}

	if (progress & IBD_DRV_ASYNC_THR_CREATED) {
		/*
		 * No new async requests will be posted since the device
		 * link state has been marked as unknown; completion handlers
		 * have been turned off, so Tx handler will not cause any
		 * more IBD_ASYNC_REAP requests.
		 *
		 * Queue a request for the async thread to exit, which will
		 * be serviced after any pending ones. This can take a while,
		 * specially if the SM is unreachable, since IBMF will slowly
		 * timeout each SM request issued by the async thread.  Reap
		 * the thread before continuing on, we do not want it to be
		 * lingering in modunloaded code.
		 */
		ibd_queue_work_slot(state, &state->id_ah_req, IBD_ASYNC_EXIT);
		thread_join(state->id_async_thrid);

		state->id_mac_state &= (~IBD_DRV_ASYNC_THR_CREATED);
	}

	if (progress & IBD_DRV_REQ_LIST_INITED) {
		list_destroy(&state->id_req_list);
		mutex_destroy(&state->id_acache_req_lock);
		cv_destroy(&state->id_acache_req_cv);
		state->id_mac_state &= ~IBD_DRV_REQ_LIST_INITED;
	}

	if (progress & IBD_DRV_PD_ALLOCD) {
		if ((ret = ibt_free_pd(state->id_hca_hdl,
		    state->id_pd_hdl)) != IBT_SUCCESS) {
			ibd_print_warn(state, "failed to free "
			    "protection domain, ret=%d", ret);
		}
		state->id_pd_hdl = NULL;
		state->id_mac_state &= (~IBD_DRV_PD_ALLOCD);
	}

	if (progress & IBD_DRV_HCA_OPENED) {
		if ((ret = ibt_close_hca(state->id_hca_hdl)) !=
		    IBT_SUCCESS) {
			ibd_print_warn(state, "failed to close "
			    "HCA device, ret=%d", ret);
		}
		state->id_hca_hdl = NULL;
		state->id_mac_state &= (~IBD_DRV_HCA_OPENED);
	}

	mutex_enter(&ibd_gstate.ig_mutex);
	if (progress & IBD_DRV_IBTL_ATTACH_DONE) {
		if ((ret = ibt_detach(state->id_ibt_hdl)) !=
		    IBT_SUCCESS) {
			ibd_print_warn(state,
			    "ibt_detach() failed, ret=%d", ret);
		}
		state->id_ibt_hdl = NULL;
		state->id_mac_state &= (~IBD_DRV_IBTL_ATTACH_DONE);
		ibd_gstate.ig_ibt_hdl_ref_cnt--;
	}
	if ((ibd_gstate.ig_ibt_hdl_ref_cnt == 0) &&
	    (ibd_gstate.ig_ibt_hdl != NULL)) {
		if ((ret = ibt_detach(ibd_gstate.ig_ibt_hdl)) !=
		    IBT_SUCCESS) {
			ibd_print_warn(state, "ibt_detach(): global "
			    "failed, ret=%d", ret);
		}
		ibd_gstate.ig_ibt_hdl = NULL;
	}
	mutex_exit(&ibd_gstate.ig_mutex);

	if (progress & IBD_DRV_TXINTR_ADDED) {
		ddi_remove_softintr(state->id_tx);
		state->id_tx = NULL;
		state->id_mac_state &= (~IBD_DRV_TXINTR_ADDED);
	}

	if (progress & IBD_DRV_RXINTR_ADDED) {
		ddi_remove_softintr(state->id_rx);
		state->id_rx = NULL;
		state->id_mac_state &= (~IBD_DRV_RXINTR_ADDED);
	}

#ifdef DEBUG
	if (progress & IBD_DRV_RC_PRIVATE_STATE) {
		kstat_delete(state->rc_ksp);
		state->id_mac_state &= (~IBD_DRV_RC_PRIVATE_STATE);
	}
#endif

	if (progress & IBD_DRV_STATE_INITIALIZED) {
		ibd_state_fini(state);
		state->id_mac_state &= (~IBD_DRV_STATE_INITIALIZED);
	}
}

int
ibd_part_attach(ibd_state_t *state, dev_info_t *dip)
{
	ibt_status_t ret;
	int rv;
	kthread_t *kht;

	/*
	 * Initialize mutexes and condition variables
	 */
	if (ibd_state_init(state, dip) != DDI_SUCCESS) {
		DPRINT(10, "ibd_part_attach: failed in ibd_state_init()");
		return (DDI_FAILURE);
	}
	state->id_mac_state |= IBD_DRV_STATE_INITIALIZED;

	/*
	 * Allocate rx,tx softintr
	 */
	if (ibd_rx_softintr == 1) {
		if ((rv = ddi_add_softintr(dip, DDI_SOFTINT_LOW, &state->id_rx,
		    NULL, NULL, ibd_intr, (caddr_t)state)) != DDI_SUCCESS) {
			DPRINT(10, "ibd_part_attach: failed in "
			    "ddi_add_softintr(id_rx),  ret=%d", rv);
			return (DDI_FAILURE);
		}
		state->id_mac_state |= IBD_DRV_RXINTR_ADDED;
	}
	if (ibd_tx_softintr == 1) {
		if ((rv = ddi_add_softintr(dip, DDI_SOFTINT_LOW, &state->id_tx,
		    NULL, NULL, ibd_tx_recycle,
		    (caddr_t)state)) != DDI_SUCCESS) {
			DPRINT(10, "ibd_part_attach: failed in "
			    "ddi_add_softintr(id_tx), ret=%d", rv);
			return (DDI_FAILURE);
		}
		state->id_mac_state |= IBD_DRV_TXINTR_ADDED;
	}

	/*
	 * Attach to IBTL
	 */
	mutex_enter(&ibd_gstate.ig_mutex);
	if (ibd_gstate.ig_ibt_hdl == NULL) {
		if ((ret = ibt_attach(&ibd_clnt_modinfo, dip, state,
		    &ibd_gstate.ig_ibt_hdl)) != IBT_SUCCESS) {
			DPRINT(10, "ibd_part_attach: global: failed in "
			    "ibt_attach(), ret=%d", ret);
			mutex_exit(&ibd_gstate.ig_mutex);
			return (DDI_FAILURE);
		}
	}
	if ((ret = ibt_attach(&ibd_clnt_modinfo, dip, state,
	    &state->id_ibt_hdl)) != IBT_SUCCESS) {
		DPRINT(10, "ibd_part_attach: failed in ibt_attach(), ret=%d",
		    ret);
		mutex_exit(&ibd_gstate.ig_mutex);
		return (DDI_FAILURE);
	}
	ibd_gstate.ig_ibt_hdl_ref_cnt++;
	mutex_exit(&ibd_gstate.ig_mutex);
	state->id_mac_state |= IBD_DRV_IBTL_ATTACH_DONE;

	/*
	 * Open the HCA
	 */
	if ((ret = ibt_open_hca(state->id_ibt_hdl, state->id_hca_guid,
	    &state->id_hca_hdl)) != IBT_SUCCESS) {
		DPRINT(10, "ibd_part_attach: ibt_open_hca() failed, ret=%d",
		    ret);
		return (DDI_FAILURE);
	}
	state->id_mac_state |= IBD_DRV_HCA_OPENED;

#ifdef DEBUG
	/* Initialize Driver Counters for Reliable Connected Mode */
	if (state->id_enable_rc) {
		if (ibd_rc_init_stats(state) != DDI_SUCCESS) {
			DPRINT(10, "ibd_part_attach: failed in "
			    "ibd_rc_init_stats");
			return (DDI_FAILURE);
		}
		state->id_mac_state |= IBD_DRV_RC_PRIVATE_STATE;
	}
#endif

	/*
	 * Record capabilities
	 */
	(void) ibd_record_capab(state);

	/*
	 * Allocate a protection domain on the HCA
	 */
	if ((ret = ibt_alloc_pd(state->id_hca_hdl, IBT_PD_NO_FLAGS,
	    &state->id_pd_hdl)) != IBT_SUCCESS) {
		DPRINT(10, "ibd_part_attach: ibt_alloc_pd() failed, ret=%d",
		    ret);
		return (DDI_FAILURE);
	}
	state->id_mac_state |= IBD_DRV_PD_ALLOCD;


	/*
	 * We need to initialise the req_list that is required for the
	 * operation of the async_thread.
	 */
	mutex_init(&state->id_acache_req_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&state->id_acache_req_cv, NULL, CV_DEFAULT, NULL);
	list_create(&state->id_req_list, sizeof (ibd_req_t),
	    offsetof(ibd_req_t, rq_list));
	state->id_mac_state |= IBD_DRV_REQ_LIST_INITED;

	/*
	 * Create the async thread; thread_create never fails.
	 */
	kht = thread_create(NULL, 0, ibd_async_work, state, 0, &p0,
	    TS_RUN, minclsyspri);
	state->id_async_thrid = kht->t_did;
	state->id_mac_state |= IBD_DRV_ASYNC_THR_CREATED;

	return (DDI_SUCCESS);
}

/*
 * Attach device to the IO framework.
 */
static int
ibd_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int ret;

	switch (cmd) {
		case DDI_ATTACH:
			ret = ibd_port_attach(dip);
			break;
		default:
			ret = DDI_FAILURE;
			break;
	}
	return (ret);
}

/*
 * Detach device from the IO framework.
 */
static int
ibd_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	ibd_state_t *state;
	int instance;

	/*
	 * IBD doesn't support suspend/resume
	 */
	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);

	/*
	 * Get the instance softstate
	 */
	instance = ddi_get_instance(dip);
	state = ddi_get_soft_state(ibd_list, instance);

	/*
	 * Release all resources we're holding still.  Note that if we'd
	 * done ibd_attach(), ibd_m_start() and ibd_m_stop() correctly
	 * so far, we should find all the flags we need in id_mac_state.
	 */
	return (ibd_port_unattach(state, dip));
}

/*
 * Pre ibt_attach() driver initialization
 */
static int
ibd_state_init(ibd_state_t *state, dev_info_t *dip)
{
	char buf[64];

	mutex_init(&state->id_link_mutex, NULL, MUTEX_DRIVER, NULL);
	state->id_link_state = LINK_STATE_UNKNOWN;

	mutex_init(&state->id_trap_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&state->id_trap_cv, NULL, CV_DEFAULT, NULL);
	state->id_trap_stop = B_TRUE;
	state->id_trap_inprog = 0;

	mutex_init(&state->id_scq_poll_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&state->id_rcq_poll_lock, NULL, MUTEX_DRIVER, NULL);
	state->id_dip = dip;

	mutex_init(&state->id_sched_lock, NULL, MUTEX_DRIVER, NULL);

	mutex_init(&state->id_tx_list.dl_mutex, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&state->id_tx_rel_list.dl_mutex, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&state->id_txpost_lock, NULL, MUTEX_DRIVER, NULL);
	state->id_tx_busy = 0;
	mutex_init(&state->id_lso_lock, NULL, MUTEX_DRIVER, NULL);

	state->id_rx_list.dl_bufs_outstanding = 0;
	state->id_rx_list.dl_cnt = 0;
	mutex_init(&state->id_rx_list.dl_mutex, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&state->id_rx_free_list.dl_mutex, NULL, MUTEX_DRIVER, NULL);
	(void) sprintf(buf, "ibd_req%d_%x_%u", ddi_get_instance(dip),
	    state->id_pkey, state->id_plinkid);
	state->id_req_kmc = kmem_cache_create(buf, sizeof (ibd_req_t),
	    0, NULL, NULL, NULL, NULL, NULL, 0);

	/* For Reliable Connected Mode */
	mutex_init(&state->rc_rx_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&state->rc_tx_large_bufs_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&state->rc_srq_rwqe_list.dl_mutex, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&state->rc_srq_free_list.dl_mutex, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&state->rc_pass_chan_list.chan_list_mutex, NULL,
	    MUTEX_DRIVER, NULL);
	mutex_init(&state->rc_timeout_lock, NULL, MUTEX_DRIVER, NULL);

	/*
	 * Make the default link mode as RC. If this fails during connection
	 * setup, the link mode is automatically transitioned to UD.
	 * Also set the RC MTU.
	 */
	state->id_enable_rc = IBD_DEF_LINK_MODE;
	state->rc_mtu = IBD_DEF_RC_MAX_MTU;
	state->id_mtu = IBD_DEF_MAX_MTU;

	/* Iniatialize all tunables to default */
	state->id_lso_policy = IBD_DEF_LSO_POLICY;
	state->id_num_lso_bufs = IBD_DEF_NUM_LSO_BUFS;
	state->id_num_ah = IBD_DEF_NUM_AH;
	state->id_hash_size = IBD_DEF_HASH_SIZE;
	state->id_create_broadcast_group = IBD_DEF_CREATE_BCAST_GROUP;
	state->id_allow_coalesce_comp_tuning = IBD_DEF_COALESCE_COMPLETIONS;
	state->id_ud_rx_comp_count = IBD_DEF_UD_RX_COMP_COUNT;
	state->id_ud_rx_comp_usec = IBD_DEF_UD_RX_COMP_USEC;
	state->id_ud_tx_comp_count = IBD_DEF_UD_TX_COMP_COUNT;
	state->id_ud_tx_comp_usec = IBD_DEF_UD_TX_COMP_USEC;
	state->id_rc_rx_comp_count = IBD_DEF_RC_RX_COMP_COUNT;
	state->id_rc_rx_comp_usec = IBD_DEF_RC_RX_COMP_USEC;
	state->id_rc_tx_comp_count = IBD_DEF_RC_TX_COMP_COUNT;
	state->id_rc_tx_comp_usec = IBD_DEF_RC_TX_COMP_USEC;
	state->id_ud_tx_copy_thresh = IBD_DEF_UD_TX_COPY_THRESH;
	state->id_rc_rx_copy_thresh = IBD_DEF_RC_RX_COPY_THRESH;
	state->id_rc_tx_copy_thresh = IBD_DEF_RC_TX_COPY_THRESH;
	state->id_ud_num_rwqe = IBD_DEF_UD_NUM_RWQE;
	state->id_ud_num_swqe = IBD_DEF_UD_NUM_SWQE;
	state->id_rc_num_rwqe = IBD_DEF_RC_NUM_RWQE;
	state->id_rc_num_swqe = IBD_DEF_RC_NUM_SWQE;
	state->rc_enable_srq = IBD_DEF_RC_ENABLE_SRQ;
	state->id_rc_num_srq = IBD_DEF_RC_NUM_SRQ;
	state->id_rc_rx_rwqe_thresh = IBD_DEF_RC_RX_RWQE_THRESH;

	return (DDI_SUCCESS);
}

/*
 * Post ibt_detach() driver deconstruction
 */
static void
ibd_state_fini(ibd_state_t *state)
{
	kmem_cache_destroy(state->id_req_kmc);

	mutex_destroy(&state->id_rx_list.dl_mutex);
	mutex_destroy(&state->id_rx_free_list.dl_mutex);

	mutex_destroy(&state->id_txpost_lock);
	mutex_destroy(&state->id_tx_list.dl_mutex);
	mutex_destroy(&state->id_tx_rel_list.dl_mutex);
	mutex_destroy(&state->id_lso_lock);

	mutex_destroy(&state->id_sched_lock);
	mutex_destroy(&state->id_scq_poll_lock);
	mutex_destroy(&state->id_rcq_poll_lock);

	cv_destroy(&state->id_trap_cv);
	mutex_destroy(&state->id_trap_lock);
	mutex_destroy(&state->id_link_mutex);

	/* For Reliable Connected Mode */
	mutex_destroy(&state->rc_timeout_lock);
	mutex_destroy(&state->rc_srq_free_list.dl_mutex);
	mutex_destroy(&state->rc_srq_rwqe_list.dl_mutex);
	mutex_destroy(&state->rc_pass_chan_list.chan_list_mutex);
	mutex_destroy(&state->rc_tx_large_bufs_lock);
	mutex_destroy(&state->rc_rx_lock);
}

/*
 * Fetch link speed from SA for snmp ifspeed reporting.
 */
static uint64_t
ibd_get_portspeed(ibd_state_t *state)
{
	int			ret;
	ibt_path_info_t		path;
	ibt_path_attr_t		path_attr;
	uint8_t			num_paths;
	uint64_t		ifspeed;

	/*
	 * Due to serdes 8b10b encoding on the wire, 2.5 Gbps on wire
	 * translates to 2 Gbps data rate. Thus, 1X single data rate is
	 * 2000000000. Start with that as default.
	 */
	ifspeed = 2000000000;

	bzero(&path_attr, sizeof (path_attr));

	/*
	 * Get the port speed from Loopback path information.
	 */
	path_attr.pa_dgids = &state->id_sgid;
	path_attr.pa_num_dgids = 1;
	path_attr.pa_sgid = state->id_sgid;

	if (ibt_get_paths(state->id_ibt_hdl, IBT_PATH_NO_FLAGS,
	    &path_attr, 1, &path, &num_paths) != IBT_SUCCESS)
		goto earlydone;

	if (num_paths < 1)
		goto earlydone;

	/*
	 * In case SA does not return an expected value, report the default
	 * speed as 1X.
	 */
	ret = 1;
	switch (path.pi_prim_cep_path.cep_adds_vect.av_srate) {
		case IBT_SRATE_2:	/*  1X SDR i.e 2.5 Gbps */
			ret = 1;
			break;
		case IBT_SRATE_10:	/*  4X SDR or 1X QDR i.e 10 Gbps */
			ret = 4;
			break;
		case IBT_SRATE_30:	/* 12X SDR i.e 30 Gbps */
			ret = 12;
			break;
		case IBT_SRATE_5:	/*  1X DDR i.e  5 Gbps */
			ret = 2;
			break;
		case IBT_SRATE_20:	/*  4X DDR or 8X SDR i.e 20 Gbps */
			ret = 8;
			break;
		case IBT_SRATE_40:	/*  8X DDR or 4X QDR i.e 40 Gbps */
			ret = 16;
			break;
		case IBT_SRATE_60:	/* 12X DDR i.e 60 Gbps */
			ret = 24;
			break;
		case IBT_SRATE_80:	/*  8X QDR i.e 80 Gbps */
			ret = 32;
			break;
		case IBT_SRATE_120:	/* 12X QDR i.e 120 Gbps */
			ret = 48;
			break;
	}

	ifspeed *= ret;

earlydone:
	return (ifspeed);
}

/*
 * Search input mcg list (id_mc_full or id_mc_non) for an entry
 * representing the input mcg mgid.
 */
static ibd_mce_t *
ibd_mcache_find(ib_gid_t mgid, struct list *mlist)
{
	ibd_mce_t *ptr = list_head(mlist);

	/*
	 * Do plain linear search.
	 */
	while (ptr != NULL) {
		if (bcmp(&mgid, &ptr->mc_info.mc_adds_vect.av_dgid,
		    sizeof (ib_gid_t)) == 0)
			return (ptr);
		ptr = list_next(mlist, ptr);
	}
	return (NULL);
}

/*
 * Execute IBA JOIN.
 */
static ibt_status_t
ibd_iba_join(ibd_state_t *state, ib_gid_t mgid, ibd_mce_t *mce)
{
	ibt_mcg_attr_t mcg_attr;

	bzero(&mcg_attr, sizeof (ibt_mcg_attr_t));
	mcg_attr.mc_qkey = state->id_mcinfo->mc_qkey;
	mcg_attr.mc_mgid = mgid;
	mcg_attr.mc_join_state = mce->mc_jstate;
	mcg_attr.mc_scope = state->id_scope;
	mcg_attr.mc_pkey = state->id_pkey;
	mcg_attr.mc_flow = state->id_mcinfo->mc_adds_vect.av_flow;
	mcg_attr.mc_sl = state->id_mcinfo->mc_adds_vect.av_srvl;
	mcg_attr.mc_tclass = state->id_mcinfo->mc_adds_vect.av_tclass;
	return (ibt_join_mcg(state->id_sgid, &mcg_attr, &mce->mc_info,
	    NULL, NULL));
}

/*
 * This code JOINs the port in the proper way (depending on the join
 * state) so that IBA fabric will forward mcg packets to/from the port.
 * It also attaches the QPN to the mcg so it can receive those mcg
 * packets. This code makes sure not to attach the mcg to the QP if
 * that has been previously done due to the mcg being joined with a
 * different join state, even though this is not required by SWG_0216,
 * refid 3610.
 */
static ibd_mce_t *
ibd_join_group(ibd_state_t *state, ib_gid_t mgid, uint8_t jstate)
{
	ibt_status_t ibt_status;
	ibd_mce_t *mce, *tmce, *omce = NULL;
	boolean_t do_attach = B_TRUE;

	DPRINT(2, "ibd_join_group : join_group state %d : %016llx:%016llx\n",
	    jstate, mgid.gid_prefix, mgid.gid_guid);

	/*
	 * For enable_multicast Full member joins, we need to do some
	 * extra work. If there is already an mce on the list that
	 * indicates full membership, that means the membership has
	 * not yet been dropped (since the disable_multicast was issued)
	 * because there are pending Tx's to the mcg; in that case, just
	 * mark the mce not to be reaped when the Tx completion queues
	 * an async reap operation.
	 *
	 * If there is already an mce on the list indicating sendonly
	 * membership, try to promote to full membership. Be careful
	 * not to deallocate the old mce, since there might be an AH
	 * pointing to it; instead, update the old mce with new data
	 * that tracks the full membership.
	 */
	if ((jstate == IB_MC_JSTATE_FULL) && ((omce =
	    IBD_MCACHE_FIND_FULL(state, mgid)) != NULL)) {
		if (omce->mc_jstate == IB_MC_JSTATE_FULL) {
			ASSERT(omce->mc_fullreap);
			omce->mc_fullreap = B_FALSE;
			return (omce);
		} else {
			ASSERT(omce->mc_jstate == IB_MC_JSTATE_SEND_ONLY_NON);
		}
	}

	/*
	 * Allocate the ibd_mce_t to track this JOIN.
	 */
	mce = kmem_zalloc(sizeof (ibd_mce_t), KM_SLEEP);
	mce->mc_fullreap = B_FALSE;
	mce->mc_jstate = jstate;

	if ((ibt_status = ibd_iba_join(state, mgid, mce)) != IBT_SUCCESS) {
		DPRINT(10, "ibd_join_group : failed ibt_join_mcg() %d",
		    ibt_status);
		kmem_free(mce, sizeof (ibd_mce_t));
		return (NULL);
	}

	/*
	 * Is an IBA attach required? Not if the interface is already joined
	 * to the mcg in a different appropriate join state.
	 */
	if (jstate == IB_MC_JSTATE_NON) {
		tmce = IBD_MCACHE_FIND_FULL(state, mgid);
		if ((tmce != NULL) && (tmce->mc_jstate == IB_MC_JSTATE_FULL))
			do_attach = B_FALSE;
	} else if (jstate == IB_MC_JSTATE_FULL) {
		if (IBD_MCACHE_FIND_NON(state, mgid) != NULL)
			do_attach = B_FALSE;
	} else {	/* jstate == IB_MC_JSTATE_SEND_ONLY_NON */
		do_attach = B_FALSE;
	}

	if (do_attach) {
		/*
		 * Do the IBA attach.
		 */
		DPRINT(10, "ibd_join_group: ibt_attach_mcg \n");
		if ((ibt_status = ibt_attach_mcg(state->id_chnl_hdl,
		    &mce->mc_info)) != IBT_SUCCESS) {
			DPRINT(10, "ibd_join_group : failed qp attachment "
			    "%d\n", ibt_status);
			/*
			 * NOTE that we should probably preserve the join info
			 * in the list and later try to leave again at detach
			 * time.
			 */
			(void) ibt_leave_mcg(state->id_sgid, mgid,
			    state->id_sgid, jstate);
			kmem_free(mce, sizeof (ibd_mce_t));
			return (NULL);
		}
	}

	/*
	 * Insert the ibd_mce_t in the proper list.
	 */
	if (jstate == IB_MC_JSTATE_NON) {
		IBD_MCACHE_INSERT_NON(state, mce);
	} else {
		/*
		 * Set up the mc_req fields used for reaping the
		 * mcg in case of delayed tx completion (see
		 * ibd_tx_cleanup()). Also done for sendonly join in
		 * case we are promoted to fullmembership later and
		 * keep using the same mce.
		 */
		mce->mc_req.rq_gid = mgid;
		mce->mc_req.rq_ptr = mce;
		/*
		 * Check whether this is the case of trying to join
		 * full member, and we were already joined send only.
		 * We try to drop our SendOnly membership, but it is
		 * possible that the mcg does not exist anymore (and
		 * the subnet trap never reached us), so the leave
		 * operation might fail.
		 */
		if (omce != NULL) {
			(void) ibt_leave_mcg(state->id_sgid, mgid,
			    state->id_sgid, IB_MC_JSTATE_SEND_ONLY_NON);
			omce->mc_jstate = IB_MC_JSTATE_FULL;
			bcopy(&mce->mc_info, &omce->mc_info,
			    sizeof (ibt_mcg_info_t));
			kmem_free(mce, sizeof (ibd_mce_t));
			return (omce);
		}
		mutex_enter(&state->id_mc_mutex);
		IBD_MCACHE_INSERT_FULL(state, mce);
		mutex_exit(&state->id_mc_mutex);
	}

	return (mce);
}

/*
 * Called during port up event handling to attempt to reacquire full
 * membership to an mcg. Stripped down version of ibd_join_group().
 * Note that it is possible that the mcg might have gone away, and
 * gets recreated at this point.
 */
static void
ibd_reacquire_group(ibd_state_t *state, ibd_mce_t *mce)
{
	ib_gid_t mgid;

	/*
	 * If the mc_fullreap flag is set, or this join fails, a subsequent
	 * reap/leave is going to try to leave the group. We could prevent
	 * that by adding a boolean flag into ibd_mce_t, if required.
	 */
	if (mce->mc_fullreap)
		return;

	mgid = mce->mc_info.mc_adds_vect.av_dgid;

	DPRINT(2, "ibd_reacquire_group : %016llx:%016llx\n", mgid.gid_prefix,
	    mgid.gid_guid);

	/* While reacquiring, leave and then join the MCG */
	(void) ibt_leave_mcg(state->id_sgid, mgid, state->id_sgid,
	    mce->mc_jstate);
	if (ibd_iba_join(state, mgid, mce) != IBT_SUCCESS)
		ibd_print_warn(state, "Failure on port up to rejoin "
		    "multicast gid %016llx:%016llx",
		    (u_longlong_t)mgid.gid_prefix,
		    (u_longlong_t)mgid.gid_guid);
}

/*
 * This code handles delayed Tx completion cleanups for mcg's to which
 * disable_multicast has been issued, regular mcg related cleanups during
 * disable_multicast, disable_promiscuous and mcg traps, as well as
 * cleanups during driver detach time. Depending on the join state,
 * it deletes the mce from the appropriate list and issues the IBA
 * leave/detach; except in the disable_multicast case when the mce
 * is left on the active list for a subsequent Tx completion cleanup.
 */
static void
ibd_async_reap_group(ibd_state_t *state, ibd_mce_t *mce, ib_gid_t mgid,
    uint8_t jstate)
{
	ibd_mce_t *tmce;
	boolean_t do_detach = B_TRUE;

	/*
	 * Before detaching, we must check whether the other list
	 * contains the mcg; if we detach blindly, the consumer
	 * who set up the other list will also stop receiving
	 * traffic.
	 */
	if (jstate == IB_MC_JSTATE_FULL) {
		/*
		 * The following check is only relevant while coming
		 * from the Tx completion path in the reap case.
		 */
		if (!mce->mc_fullreap)
			return;
		mutex_enter(&state->id_mc_mutex);
		IBD_MCACHE_PULLOUT_FULL(state, mce);
		mutex_exit(&state->id_mc_mutex);
		if (IBD_MCACHE_FIND_NON(state, mgid) != NULL)
			do_detach = B_FALSE;
	} else if (jstate == IB_MC_JSTATE_NON) {
		IBD_MCACHE_PULLOUT_NON(state, mce);
		tmce = IBD_MCACHE_FIND_FULL(state, mgid);
		if ((tmce != NULL) && (tmce->mc_jstate == IB_MC_JSTATE_FULL))
			do_detach = B_FALSE;
	} else {	/* jstate == IB_MC_JSTATE_SEND_ONLY_NON */
		mutex_enter(&state->id_mc_mutex);
		IBD_MCACHE_PULLOUT_FULL(state, mce);
		mutex_exit(&state->id_mc_mutex);
		do_detach = B_FALSE;
	}

	/*
	 * If we are reacting to a mcg trap and leaving our sendonly or
	 * non membership, the mcg is possibly already gone, so attempting
	 * to leave might fail. On the other hand, we must try to leave
	 * anyway, since this might be a trap from long ago, and we could
	 * have potentially sendonly joined to a recent incarnation of
	 * the mcg and are about to loose track of this information.
	 */
	if (do_detach) {
		DPRINT(2, "ibd_async_reap_group : ibt_detach_mcg : "
		    "%016llx:%016llx\n", mgid.gid_prefix, mgid.gid_guid);
		(void) ibt_detach_mcg(state->id_chnl_hdl, &mce->mc_info);
	}

	(void) ibt_leave_mcg(state->id_sgid, mgid, state->id_sgid, jstate);
	kmem_free(mce, sizeof (ibd_mce_t));
}

/*
 * Async code executed due to multicast and promiscuous disable requests
 * and mcg trap handling; also executed during driver detach. Mostly, a
 * leave and detach is done; except for the fullmember case when Tx
 * requests are pending, whence arrangements are made for subsequent
 * cleanup on Tx completion.
 */
static void
ibd_leave_group(ibd_state_t *state, ib_gid_t mgid, uint8_t jstate)
{
	ipoib_mac_t mcmac;
	boolean_t recycled;
	ibd_mce_t *mce;

	DPRINT(2, "ibd_leave_group : leave_group state %d : %016llx:%016llx\n",
	    jstate, mgid.gid_prefix, mgid.gid_guid);

	if (jstate == IB_MC_JSTATE_NON) {
		recycled = B_TRUE;
		mce = IBD_MCACHE_FIND_NON(state, mgid);
		/*
		 * In case we are handling a mcg trap, we might not find
		 * the mcg in the non list.
		 */
		if (mce == NULL) {
			return;
		}
	} else {
		mce = IBD_MCACHE_FIND_FULL(state, mgid);

		/*
		 * In case we are handling a mcg trap, make sure the trap
		 * is not arriving late; if we have an mce that indicates
		 * that we are already a fullmember, that would be a clear
		 * indication that the trap arrived late (ie, is for a
		 * previous incarnation of the mcg).
		 */
		if (jstate == IB_MC_JSTATE_SEND_ONLY_NON) {
			if ((mce == NULL) || (mce->mc_jstate ==
			    IB_MC_JSTATE_FULL)) {
				return;
			}
		} else {
			ASSERT(jstate == IB_MC_JSTATE_FULL);

			/*
			 * If join group failed, mce will be NULL here.
			 * This is because in GLDv3 driver, set multicast
			 *  will always return success.
			 */
			if (mce == NULL) {
				return;
			}

			mce->mc_fullreap = B_TRUE;
		}

		/*
		 * If no pending Tx's remain that reference the AH
		 * for the mcg, recycle it from active to free list.
		 * Else in the IB_MC_JSTATE_FULL case, just mark the AH,
		 * so the last completing Tx will cause an async reap
		 * operation to be invoked, at which time we will drop our
		 * membership to the mcg so that the pending Tx's complete
		 * successfully. Refer to comments on "AH and MCE active
		 * list manipulation" at top of this file. The lock protects
		 * against Tx fast path and Tx cleanup code.
		 */
		mutex_enter(&state->id_ac_mutex);
		ibd_h2n_mac(&mcmac, IB_MC_QPN, mgid.gid_prefix, mgid.gid_guid);
		recycled = ibd_acache_recycle(state, &mcmac, (jstate ==
		    IB_MC_JSTATE_SEND_ONLY_NON));
		mutex_exit(&state->id_ac_mutex);
	}

	if (recycled) {
		DPRINT(2, "ibd_leave_group : leave_group reaping : "
		    "%016llx:%016llx\n", mgid.gid_prefix, mgid.gid_guid);
		ibd_async_reap_group(state, mce, mgid, jstate);
	}
}

/*
 * Find the broadcast address as defined by IPoIB; implicitly
 * determines the IBA scope, mtu, tclass etc of the link the
 * interface is going to be a member of.
 */
static ibt_status_t
ibd_find_bgroup(ibd_state_t *state)
{
	ibt_mcg_attr_t mcg_attr;
	uint_t numg;
	uchar_t scopes[] = { IB_MC_SCOPE_SUBNET_LOCAL,
	    IB_MC_SCOPE_SITE_LOCAL, IB_MC_SCOPE_ORG_LOCAL,
	    IB_MC_SCOPE_GLOBAL };
	int i, mcgmtu;
	boolean_t found = B_FALSE;
	int ret;
	ibt_mcg_info_t mcg_info;

	state->id_bgroup_created = B_FALSE;
	state->id_bgroup_present = B_FALSE;

query_bcast_grp:
	bzero(&mcg_attr, sizeof (ibt_mcg_attr_t));
	mcg_attr.mc_pkey = state->id_pkey;
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(state->id_mgid))
	state->id_mgid.gid_guid = IB_MGID_IPV4_LOWGRP_MASK;
	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(state->id_mgid))

	for (i = 0; i < sizeof (scopes)/sizeof (scopes[0]); i++) {
		state->id_scope = mcg_attr.mc_scope = scopes[i];

		/*
		 * Look for the IPoIB broadcast group.
		 */
		_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(state->id_mgid))
		state->id_mgid.gid_prefix =
		    (((uint64_t)IB_MCGID_IPV4_PREFIX << 32) |
		    ((uint64_t)state->id_scope << 48) |
		    ((uint32_t)(state->id_pkey << 16)));
		mcg_attr.mc_mgid = state->id_mgid;
		_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(state->id_mgid))
		if (ibt_query_mcg(state->id_sgid, &mcg_attr, 1,
		    &state->id_mcinfo, &numg) == IBT_SUCCESS) {
			found = B_TRUE;
			break;
		}
	}

	if (!found) {
		if (state->id_create_broadcast_group) {
			/*
			 * If we created the broadcast group, but failed to
			 * find it, we can't do anything except leave the
			 * one we created and return failure.
			 */
			if (state->id_bgroup_created) {
				ibd_print_warn(state, "IPoIB broadcast group "
				    "absent. Unable to query after create.");
				goto find_bgroup_fail;
			}

			/*
			 * Create the ipoib broadcast group if it didn't exist
			 */
			bzero(&mcg_attr, sizeof (ibt_mcg_attr_t));
			mcg_attr.mc_qkey = IBD_DEFAULT_QKEY;
			mcg_attr.mc_join_state = IB_MC_JSTATE_FULL;
			mcg_attr.mc_scope = IB_MC_SCOPE_SUBNET_LOCAL;
			mcg_attr.mc_pkey = state->id_pkey;
			mcg_attr.mc_flow = 0;
			mcg_attr.mc_sl = 0;
			mcg_attr.mc_tclass = 0;
			_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(state->id_mgid))
			state->id_mgid.gid_prefix =
			    (((uint64_t)IB_MCGID_IPV4_PREFIX << 32) |
			    ((uint64_t)IB_MC_SCOPE_SUBNET_LOCAL << 48) |
			    ((uint32_t)(state->id_pkey << 16)));
			mcg_attr.mc_mgid = state->id_mgid;
			_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(state->id_mgid))

			if ((ret = ibt_join_mcg(state->id_sgid, &mcg_attr,
			    &mcg_info, NULL, NULL)) != IBT_SUCCESS) {
				ibd_print_warn(state, "IPoIB broadcast group "
				    "absent, create failed: ret = %d\n", ret);
				state->id_bgroup_created = B_FALSE;
				return (IBT_FAILURE);
			}
			state->id_bgroup_created = B_TRUE;
			goto query_bcast_grp;
		} else {
			ibd_print_warn(state, "IPoIB broadcast group absent");
			return (IBT_FAILURE);
		}
	}

	/*
	 * Assert that the mcg mtu <= id_mtu. Fill in updated id_mtu.
	 */
	mcgmtu = (128 << state->id_mcinfo->mc_mtu);
	if (state->id_mtu < mcgmtu) {
		ibd_print_warn(state, "IPoIB broadcast group MTU %d "
		    "greater than port's maximum MTU %d", mcgmtu,
		    state->id_mtu);
		ibt_free_mcg_info(state->id_mcinfo, 1);
		goto find_bgroup_fail;
	}
	state->id_mtu = mcgmtu;
	state->id_bgroup_present = B_TRUE;

	return (IBT_SUCCESS);

find_bgroup_fail:
	if (state->id_bgroup_created) {
		(void) ibt_leave_mcg(state->id_sgid,
		    mcg_info.mc_adds_vect.av_dgid, state->id_sgid,
		    IB_MC_JSTATE_FULL);
	}

	return (IBT_FAILURE);
}

static int
ibd_alloc_tx_copybufs(ibd_state_t *state)
{
	ibt_mr_attr_t mem_attr;

	/*
	 * Allocate one big chunk for all regular tx copy bufs
	 */
	state->id_tx_buf_sz = state->id_mtu;
	if (state->id_lso_policy && state->id_lso_capable &&
	    (state->id_ud_tx_copy_thresh > state->id_mtu)) {
		state->id_tx_buf_sz = state->id_ud_tx_copy_thresh;
	}

	state->id_tx_bufs = kmem_zalloc(state->id_ud_num_swqe *
	    state->id_tx_buf_sz, KM_SLEEP);

	state->id_tx_wqes = kmem_zalloc(state->id_ud_num_swqe *
	    sizeof (ibd_swqe_t), KM_SLEEP);

	/*
	 * Do one memory registration on the entire txbuf area
	 */
	mem_attr.mr_vaddr = (uint64_t)(uintptr_t)state->id_tx_bufs;
	mem_attr.mr_len = state->id_ud_num_swqe * state->id_tx_buf_sz;
	mem_attr.mr_as = NULL;
	mem_attr.mr_flags = IBT_MR_SLEEP;
	if (ibt_register_mr(state->id_hca_hdl, state->id_pd_hdl, &mem_attr,
	    &state->id_tx_mr_hdl, &state->id_tx_mr_desc) != IBT_SUCCESS) {
		DPRINT(10, "ibd_alloc_tx_copybufs: ibt_register_mr failed");
		kmem_free(state->id_tx_wqes,
		    state->id_ud_num_swqe * sizeof (ibd_swqe_t));
		kmem_free(state->id_tx_bufs,
		    state->id_ud_num_swqe * state->id_tx_buf_sz);
		state->id_tx_bufs = NULL;
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

static int
ibd_alloc_tx_lsobufs(ibd_state_t *state)
{
	ibt_mr_attr_t mem_attr;
	ibd_lsobuf_t *buflist;
	ibd_lsobuf_t *lbufp;
	ibd_lsobuf_t *tail;
	ibd_lsobkt_t *bktp;
	uint8_t *membase;
	uint8_t *memp;
	uint_t memsz;
	int i;

	/*
	 * Allocate the lso bucket
	 */
	bktp = kmem_zalloc(sizeof (ibd_lsobkt_t), KM_SLEEP);

	/*
	 * Allocate the entire lso memory and register it
	 */
	memsz = state->id_num_lso_bufs * IBD_LSO_BUFSZ;
	membase = kmem_zalloc(memsz, KM_SLEEP);

	mem_attr.mr_vaddr = (uint64_t)(uintptr_t)membase;
	mem_attr.mr_len = memsz;
	mem_attr.mr_as = NULL;
	mem_attr.mr_flags = IBT_MR_SLEEP;
	if (ibt_register_mr(state->id_hca_hdl, state->id_pd_hdl,
	    &mem_attr, &bktp->bkt_mr_hdl, &bktp->bkt_mr_desc) != IBT_SUCCESS) {
		DPRINT(10, "ibd_alloc_tx_lsobufs: ibt_register_mr failed");
		kmem_free(membase, memsz);
		kmem_free(bktp, sizeof (ibd_lsobkt_t));
		return (DDI_FAILURE);
	}

	mutex_enter(&state->id_lso_lock);

	/*
	 * Now allocate the buflist.  Note that the elements in the buflist and
	 * the buffers in the lso memory have a permanent 1-1 relation, so we
	 * can always derive the address of a buflist entry from the address of
	 * an lso buffer.
	 */
	buflist = kmem_zalloc(state->id_num_lso_bufs * sizeof (ibd_lsobuf_t),
	    KM_SLEEP);

	/*
	 * Set up the lso buf chain
	 */
	memp = membase;
	lbufp = buflist;
	for (i = 0; i < state->id_num_lso_bufs; i++) {
		lbufp->lb_isfree = 1;
		lbufp->lb_buf = memp;
		lbufp->lb_next = lbufp + 1;

		tail = lbufp;

		memp += IBD_LSO_BUFSZ;
		lbufp++;
	}
	tail->lb_next = NULL;

	/*
	 * Set up the LSO buffer information in ibd state
	 */
	bktp->bkt_bufl = buflist;
	bktp->bkt_free_head = buflist;
	bktp->bkt_mem = membase;
	bktp->bkt_nelem = state->id_num_lso_bufs;
	bktp->bkt_nfree = bktp->bkt_nelem;

	state->id_lso = bktp;
	mutex_exit(&state->id_lso_lock);

	return (DDI_SUCCESS);
}

/*
 * Statically allocate Tx buffer list(s).
 */
static int
ibd_init_txlist(ibd_state_t *state)
{
	ibd_swqe_t *swqe;
	ibt_lkey_t lkey;
	int i;
	uint_t len;
	uint8_t *bufaddr;

	if (ibd_alloc_tx_copybufs(state) != DDI_SUCCESS)
		return (DDI_FAILURE);

	if (state->id_lso_policy && state->id_lso_capable) {
		if (ibd_alloc_tx_lsobufs(state) != DDI_SUCCESS)
			state->id_lso_capable = B_FALSE;
	}

	mutex_enter(&state->id_tx_list.dl_mutex);
	state->id_tx_list.dl_head = NULL;
	state->id_tx_list.dl_pending_sends = B_FALSE;
	state->id_tx_list.dl_cnt = 0;
	mutex_exit(&state->id_tx_list.dl_mutex);
	mutex_enter(&state->id_tx_rel_list.dl_mutex);
	state->id_tx_rel_list.dl_head = NULL;
	state->id_tx_rel_list.dl_pending_sends = B_FALSE;
	state->id_tx_rel_list.dl_cnt = 0;
	mutex_exit(&state->id_tx_rel_list.dl_mutex);

	/*
	 * Allocate and setup the swqe list
	 */
	lkey = state->id_tx_mr_desc.md_lkey;
	bufaddr = state->id_tx_bufs;
	len = state->id_tx_buf_sz;
	swqe = state->id_tx_wqes;
	mutex_enter(&state->id_tx_list.dl_mutex);
	for (i = 0; i < state->id_ud_num_swqe; i++, swqe++, bufaddr += len) {
		swqe->swqe_next = NULL;
		swqe->swqe_im_mblk = NULL;

		swqe->swqe_copybuf.ic_sgl.ds_va = (ib_vaddr_t)(uintptr_t)
		    bufaddr;
		swqe->swqe_copybuf.ic_sgl.ds_key = lkey;
		swqe->swqe_copybuf.ic_sgl.ds_len = 0; /* set in send */

		swqe->w_swr.wr_id = (ibt_wrid_t)(uintptr_t)swqe;
		swqe->w_swr.wr_flags = IBT_WR_NO_FLAGS;
		swqe->w_swr.wr_trans = IBT_UD_SRV;

		/* These are set in send */
		swqe->w_swr.wr_nds = 0;
		swqe->w_swr.wr_sgl = NULL;
		swqe->w_swr.wr_opcode = IBT_WRC_SEND;

		/* add to list */
		state->id_tx_list.dl_cnt++;
		swqe->swqe_next = state->id_tx_list.dl_head;
		state->id_tx_list.dl_head = SWQE_TO_WQE(swqe);
	}
	mutex_exit(&state->id_tx_list.dl_mutex);

	return (DDI_SUCCESS);
}

static int
ibd_acquire_lsobufs(ibd_state_t *state, uint_t req_sz, ibt_wr_ds_t *sgl_p,
    uint32_t *nds_p)
{
	ibd_lsobkt_t *bktp;
	ibd_lsobuf_t *lbufp;
	ibd_lsobuf_t *nextp;
	ibt_lkey_t lso_lkey;
	uint_t frag_sz;
	uint_t num_needed;
	int i;

	ASSERT(sgl_p != NULL);
	ASSERT(nds_p != NULL);
	ASSERT(req_sz != 0);

	/*
	 * Determine how many bufs we'd need for the size requested
	 */
	num_needed = req_sz / IBD_LSO_BUFSZ;
	if ((frag_sz = req_sz % IBD_LSO_BUFSZ) != 0)
		num_needed++;

	mutex_enter(&state->id_lso_lock);

	/*
	 * If we don't have enough lso bufs, return failure
	 */
	ASSERT(state->id_lso != NULL);
	bktp = state->id_lso;
	if (bktp->bkt_nfree < num_needed) {
		mutex_exit(&state->id_lso_lock);
		return (-1);
	}

	/*
	 * Pick the first 'num_needed' bufs from the free list
	 */
	lso_lkey = bktp->bkt_mr_desc.md_lkey;
	lbufp = bktp->bkt_free_head;
	for (i = 0; i < num_needed; i++) {
		ASSERT(lbufp->lb_isfree != 0);
		ASSERT(lbufp->lb_buf != NULL);

		nextp = lbufp->lb_next;

		sgl_p[i].ds_va = (ib_vaddr_t)(uintptr_t)lbufp->lb_buf;
		sgl_p[i].ds_key = lso_lkey;
		sgl_p[i].ds_len = IBD_LSO_BUFSZ;

		lbufp->lb_isfree = 0;
		lbufp->lb_next = NULL;

		lbufp = nextp;
	}
	bktp->bkt_free_head = lbufp;

	/*
	 * If the requested size is not a multiple of IBD_LSO_BUFSZ, we need
	 * to adjust the last sgl entry's length. Since we know we need atleast
	 * one, the i-1 use below is ok.
	 */
	if (frag_sz) {
		sgl_p[i-1].ds_len = frag_sz;
	}

	/*
	 * Update nfree count and return
	 */
	bktp->bkt_nfree -= num_needed;

	mutex_exit(&state->id_lso_lock);

	*nds_p = num_needed;

	return (0);
}

static void
ibd_release_lsobufs(ibd_state_t *state, ibt_wr_ds_t *sgl_p, uint32_t nds)
{
	ibd_lsobkt_t *bktp;
	ibd_lsobuf_t *lbufp;
	uint8_t *lso_mem_end;
	uint_t ndx;
	int i;

	mutex_enter(&state->id_lso_lock);

	bktp = state->id_lso;
	ASSERT(bktp != NULL);

	lso_mem_end = bktp->bkt_mem + bktp->bkt_nelem * IBD_LSO_BUFSZ;
	for (i = 0; i < nds; i++) {
		uint8_t *va;

		va = (uint8_t *)(uintptr_t)sgl_p[i].ds_va;
		ASSERT(va >= bktp->bkt_mem && va < lso_mem_end);

		/*
		 * Figure out the buflist element this sgl buffer corresponds
		 * to and put it back at the head
		 */
		ndx = (va - bktp->bkt_mem) / IBD_LSO_BUFSZ;
		lbufp = bktp->bkt_bufl + ndx;

		ASSERT(lbufp->lb_isfree == 0);
		ASSERT(lbufp->lb_buf == va);

		lbufp->lb_isfree = 1;
		lbufp->lb_next = bktp->bkt_free_head;
		bktp->bkt_free_head = lbufp;
	}
	bktp->bkt_nfree += nds;

	mutex_exit(&state->id_lso_lock);
}

static void
ibd_free_tx_copybufs(ibd_state_t *state)
{
	/*
	 * Unregister txbuf mr
	 */
	if (ibt_deregister_mr(state->id_hca_hdl,
	    state->id_tx_mr_hdl) != IBT_SUCCESS) {
		DPRINT(10, "ibd_free_tx_copybufs: ibt_deregister_mr failed");
	}
	state->id_tx_mr_hdl = NULL;

	/*
	 * Free txbuf memory
	 */
	kmem_free(state->id_tx_wqes, state->id_ud_num_swqe *
	    sizeof (ibd_swqe_t));
	kmem_free(state->id_tx_bufs, state->id_ud_num_swqe *
	    state->id_tx_buf_sz);
	state->id_tx_wqes = NULL;
	state->id_tx_bufs = NULL;
}

static void
ibd_free_tx_lsobufs(ibd_state_t *state)
{
	ibd_lsobkt_t *bktp;

	mutex_enter(&state->id_lso_lock);

	if ((bktp = state->id_lso) == NULL) {
		mutex_exit(&state->id_lso_lock);
		return;
	}

	/*
	 * First, free the buflist
	 */
	ASSERT(bktp->bkt_bufl != NULL);
	kmem_free(bktp->bkt_bufl, bktp->bkt_nelem * sizeof (ibd_lsobuf_t));

	/*
	 * Unregister the LSO memory and free it
	 */
	ASSERT(bktp->bkt_mr_hdl != NULL);
	if (ibt_deregister_mr(state->id_hca_hdl,
	    bktp->bkt_mr_hdl) != IBT_SUCCESS) {
		DPRINT(10,
		    "ibd_free_lsobufs: ibt_deregister_mr failed");
	}
	ASSERT(bktp->bkt_mem);
	kmem_free(bktp->bkt_mem, bktp->bkt_nelem * IBD_LSO_BUFSZ);

	/*
	 * Finally free the bucket
	 */
	kmem_free(bktp, sizeof (ibd_lsobkt_t));
	state->id_lso = NULL;

	mutex_exit(&state->id_lso_lock);
}

/*
 * Free the statically allocated Tx buffer list.
 */
static void
ibd_fini_txlist(ibd_state_t *state)
{
	/*
	 * Free the allocated swqes
	 */
	mutex_enter(&state->id_tx_list.dl_mutex);
	mutex_enter(&state->id_tx_rel_list.dl_mutex);
	state->id_tx_list.dl_head = NULL;
	state->id_tx_list.dl_pending_sends = B_FALSE;
	state->id_tx_list.dl_cnt = 0;
	state->id_tx_rel_list.dl_head = NULL;
	state->id_tx_rel_list.dl_pending_sends = B_FALSE;
	state->id_tx_rel_list.dl_cnt = 0;
	mutex_exit(&state->id_tx_rel_list.dl_mutex);
	mutex_exit(&state->id_tx_list.dl_mutex);

	ibd_free_tx_lsobufs(state);
	ibd_free_tx_copybufs(state);
}

/*
 * post a list of rwqes, NULL terminated.
 */
static void
ibd_post_recv_list(ibd_state_t *state, ibd_rwqe_t *rwqe)
{
	uint_t		i;
	uint_t		num_posted;
	ibt_status_t	ibt_status;
	ibt_recv_wr_t	wrs[IBD_RX_POST_CNT];

	while (rwqe) {
		/* Post up to IBD_RX_POST_CNT receive work requests */
		for (i = 0; i < IBD_RX_POST_CNT; i++) {
			wrs[i] = rwqe->w_rwr;
			rwqe = WQE_TO_RWQE(rwqe->rwqe_next);
			if (rwqe == NULL) {
				i++;
				break;
			}
		}

		/*
		 * If posting fails for some reason, we'll never receive
		 * completion intimation, so we'll need to cleanup. But
		 * we need to make sure we don't clean up nodes whose
		 * wrs have been successfully posted. We assume that the
		 * hca driver returns on the first failure to post and
		 * therefore the first 'num_posted' entries don't need
		 * cleanup here.
		 */
		atomic_add_32(&state->id_rx_list.dl_cnt, i);

		num_posted = 0;
		ibt_status = ibt_post_recv(state->id_chnl_hdl, wrs, i,
		    &num_posted);
		if (ibt_status != IBT_SUCCESS) {
			/* This cannot happen unless the device has an error. */
			ibd_print_warn(state, "ibd_post_recv: FATAL: "
			    "posting multiple wrs failed: "
			    "requested=%d, done=%d, ret=%d",
			    IBD_RX_POST_CNT, num_posted, ibt_status);
			atomic_add_32(&state->id_rx_list.dl_cnt,
			    num_posted - i);
		}
	}
}

/*
 * Grab a list of rwqes from the array of lists, and post the list.
 */
static void
ibd_post_recv_intr(ibd_state_t *state)
{
	ibd_rx_queue_t	*rxp;
	ibd_rwqe_t *list;

	/* rotate through the rx_queue array, expecting an adequate number */
	state->id_rx_post_queue_index =
	    (state->id_rx_post_queue_index + 1) &
	    (state->id_rx_nqueues - 1);

	rxp = state->id_rx_queues + state->id_rx_post_queue_index;
	mutex_enter(&rxp->rx_post_lock);
	list = WQE_TO_RWQE(rxp->rx_head);
	rxp->rx_head = NULL;
	rxp->rx_cnt = 0;
	mutex_exit(&rxp->rx_post_lock);
	ibd_post_recv_list(state, list);
}

/* macro explained below */
#define	RX_QUEUE_HASH(rwqe) \
	(((uintptr_t)(rwqe) >> 8) & (state->id_rx_nqueues - 1))

/*
 * Add a rwqe to one of the the Rx lists.  If the list is large enough
 * (exactly IBD_RX_POST_CNT), post the list to the hardware.
 *
 * Note: one of 2^N lists is chosen via a hash.  This is done
 * because using one list is contentious.  If the first list is busy
 * (mutex_tryenter fails), use a second list (just call mutex_enter).
 *
 * The number 8 in RX_QUEUE_HASH is a random choice that provides
 * even distribution of mapping rwqes to the 2^N queues.
 */
static void
ibd_post_recv(ibd_state_t *state, ibd_rwqe_t *rwqe)
{
	ibd_rx_queue_t	*rxp;

	rxp = state->id_rx_queues + RX_QUEUE_HASH(rwqe);

	if (!mutex_tryenter(&rxp->rx_post_lock)) {
		/* Failed.  Try a different queue ("ptr + 16" ensures that). */
		rxp = state->id_rx_queues + RX_QUEUE_HASH(rwqe + 16);
		mutex_enter(&rxp->rx_post_lock);
	}
	rwqe->rwqe_next = rxp->rx_head;
	if (++rxp->rx_cnt >= IBD_RX_POST_CNT - 2) {
		uint_t active = atomic_inc_32_nv(&state->id_rx_post_active);

		/* only call ibt_post_recv() every Nth time through here */
		if ((active & (state->id_rx_nqueues - 1)) == 0) {
			rxp->rx_head = NULL;
			rxp->rx_cnt = 0;
			mutex_exit(&rxp->rx_post_lock);
			ibd_post_recv_list(state, rwqe);
			return;
		}
	}
	rxp->rx_head = RWQE_TO_WQE(rwqe);
	mutex_exit(&rxp->rx_post_lock);
}

static int
ibd_alloc_rx_copybufs(ibd_state_t *state)
{
	ibt_mr_attr_t mem_attr;
	int i;

	/*
	 * Allocate one big chunk for all regular rx copy bufs
	 */
	state->id_rx_buf_sz = state->id_mtu + IPOIB_GRH_SIZE;

	state->id_rx_bufs = kmem_zalloc(state->id_ud_num_rwqe *
	    state->id_rx_buf_sz, KM_SLEEP);

	state->id_rx_wqes = kmem_zalloc(state->id_ud_num_rwqe *
	    sizeof (ibd_rwqe_t), KM_SLEEP);

	state->id_rx_nqueues = 1 << IBD_LOG_RX_POST;
	state->id_rx_queues = kmem_zalloc(state->id_rx_nqueues *
	    sizeof (ibd_rx_queue_t), KM_SLEEP);
	for (i = 0; i < state->id_rx_nqueues; i++) {
		ibd_rx_queue_t *rxp = state->id_rx_queues + i;
		mutex_init(&rxp->rx_post_lock, NULL, MUTEX_DRIVER, NULL);
	}

	/*
	 * Do one memory registration on the entire rxbuf area
	 */
	mem_attr.mr_vaddr = (uint64_t)(uintptr_t)state->id_rx_bufs;
	mem_attr.mr_len = state->id_ud_num_rwqe * state->id_rx_buf_sz;
	mem_attr.mr_as = NULL;
	mem_attr.mr_flags = IBT_MR_SLEEP | IBT_MR_ENABLE_LOCAL_WRITE;
	if (ibt_register_mr(state->id_hca_hdl, state->id_pd_hdl, &mem_attr,
	    &state->id_rx_mr_hdl, &state->id_rx_mr_desc) != IBT_SUCCESS) {
		DPRINT(10, "ibd_alloc_rx_copybufs: ibt_register_mr failed");
		kmem_free(state->id_rx_wqes,
		    state->id_ud_num_rwqe * sizeof (ibd_rwqe_t));
		kmem_free(state->id_rx_bufs,
		    state->id_ud_num_rwqe * state->id_rx_buf_sz);
		state->id_rx_bufs = NULL;
		state->id_rx_wqes = NULL;
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/*
 * Allocate the statically allocated Rx buffer list.
 */
static int
ibd_init_rxlist(ibd_state_t *state)
{
	ibd_rwqe_t *rwqe, *next;
	ibd_wqe_t *list;
	ibt_lkey_t lkey;
	int i;
	uint_t len;
	uint8_t *bufaddr;

	mutex_enter(&state->id_rx_free_list.dl_mutex);
	if (state->id_rx_free_list.dl_head != NULL) {
		/* rx rsrcs were never freed.  Just repost them */
		len = state->id_rx_buf_sz;
		list = state->id_rx_free_list.dl_head;
		state->id_rx_free_list.dl_head = NULL;
		state->id_rx_free_list.dl_cnt = 0;
		mutex_exit(&state->id_rx_free_list.dl_mutex);
		for (rwqe = WQE_TO_RWQE(list); rwqe != NULL;
		    rwqe = WQE_TO_RWQE(rwqe->rwqe_next)) {
			if ((rwqe->rwqe_im_mblk = desballoc(
			    rwqe->rwqe_copybuf.ic_bufaddr, len, 0,
			    &rwqe->w_freemsg_cb)) == NULL) {
				/* allow freemsg_cb to free the rwqes */
				if (atomic_dec_32_nv(&state->id_running) != 0) {
					cmn_err(CE_WARN, "ibd_init_rxlist: "
					    "id_running was not 1\n");
				}
				DPRINT(10, "ibd_init_rxlist : "
				    "failed in desballoc()");
				for (rwqe = WQE_TO_RWQE(list); rwqe != NULL;
				    rwqe = next) {
					next = WQE_TO_RWQE(rwqe->rwqe_next);
					if (rwqe->rwqe_im_mblk) {
						atomic_inc_32(&state->
						    id_rx_list.
						    dl_bufs_outstanding);
						freemsg(rwqe->rwqe_im_mblk);
					} else
						ibd_free_rwqe(state, rwqe);
				}
				atomic_inc_32(&state->id_running);
				return (DDI_FAILURE);
			}
		}
		ibd_post_recv_list(state, WQE_TO_RWQE(list));
		return (DDI_SUCCESS);
	}
	mutex_exit(&state->id_rx_free_list.dl_mutex);

	if (ibd_alloc_rx_copybufs(state) != DDI_SUCCESS)
		return (DDI_FAILURE);

	/*
	 * Allocate and setup the rwqe list
	 */
	len = state->id_rx_buf_sz;
	lkey = state->id_rx_mr_desc.md_lkey;
	rwqe = state->id_rx_wqes;
	bufaddr = state->id_rx_bufs;
	list = NULL;
	for (i = 0; i < state->id_ud_num_rwqe; i++, rwqe++, bufaddr += len) {
		rwqe->w_state = state;
		rwqe->w_freemsg_cb.free_func = ibd_freemsg_cb;
		rwqe->w_freemsg_cb.free_arg = (char *)rwqe;

		rwqe->rwqe_copybuf.ic_bufaddr = bufaddr;

		if ((rwqe->rwqe_im_mblk = desballoc(bufaddr, len, 0,
		    &rwqe->w_freemsg_cb)) == NULL) {
			DPRINT(10, "ibd_init_rxlist : failed in desballoc()");
			/* allow freemsg_cb to free the rwqes */
			if (atomic_dec_32_nv(&state->id_running) != 0) {
				cmn_err(CE_WARN, "ibd_init_rxlist: "
				    "id_running was not 1\n");
			}
			DPRINT(10, "ibd_init_rxlist : "
			    "failed in desballoc()");
			for (rwqe = WQE_TO_RWQE(list); rwqe != NULL;
			    rwqe = next) {
				next = WQE_TO_RWQE(rwqe->rwqe_next);
				freemsg(rwqe->rwqe_im_mblk);
			}
			atomic_inc_32(&state->id_running);

			/* remove reference to free'd rwqes */
			mutex_enter(&state->id_rx_free_list.dl_mutex);
			state->id_rx_free_list.dl_head = NULL;
			state->id_rx_free_list.dl_cnt = 0;
			mutex_exit(&state->id_rx_free_list.dl_mutex);

			ibd_fini_rxlist(state);
			return (DDI_FAILURE);
		}

		rwqe->rwqe_copybuf.ic_sgl.ds_key = lkey;
		rwqe->rwqe_copybuf.ic_sgl.ds_va =
		    (ib_vaddr_t)(uintptr_t)bufaddr;
		rwqe->rwqe_copybuf.ic_sgl.ds_len = len;
		rwqe->w_rwr.wr_id = (ibt_wrid_t)(uintptr_t)rwqe;
		rwqe->w_rwr.wr_nds = 1;
		rwqe->w_rwr.wr_sgl = &rwqe->rwqe_copybuf.ic_sgl;

		rwqe->rwqe_next = list;
		list = RWQE_TO_WQE(rwqe);
	}
	ibd_post_recv_list(state, WQE_TO_RWQE(list));

	return (DDI_SUCCESS);
}

static void
ibd_free_rx_copybufs(ibd_state_t *state)
{
	int i;

	/*
	 * Unregister rxbuf mr
	 */
	if (ibt_deregister_mr(state->id_hca_hdl,
	    state->id_rx_mr_hdl) != IBT_SUCCESS) {
		DPRINT(10, "ibd_free_rx_copybufs: ibt_deregister_mr failed");
	}
	state->id_rx_mr_hdl = NULL;

	/*
	 * Free rxbuf memory
	 */
	for (i = 0; i < state->id_rx_nqueues; i++) {
		ibd_rx_queue_t *rxp = state->id_rx_queues + i;
		mutex_destroy(&rxp->rx_post_lock);
	}
	kmem_free(state->id_rx_queues, state->id_rx_nqueues *
	    sizeof (ibd_rx_queue_t));
	kmem_free(state->id_rx_wqes, state->id_ud_num_rwqe *
	    sizeof (ibd_rwqe_t));
	kmem_free(state->id_rx_bufs, state->id_ud_num_rwqe *
	    state->id_rx_buf_sz);
	state->id_rx_queues = NULL;
	state->id_rx_wqes = NULL;
	state->id_rx_bufs = NULL;
}

static void
ibd_free_rx_rsrcs(ibd_state_t *state)
{
	mutex_enter(&state->id_rx_free_list.dl_mutex);
	if (state->id_rx_free_list.dl_head == NULL) {
		/* already freed */
		mutex_exit(&state->id_rx_free_list.dl_mutex);
		return;
	}
	ASSERT(state->id_rx_free_list.dl_cnt == state->id_ud_num_rwqe);
	ibd_free_rx_copybufs(state);
	state->id_rx_free_list.dl_cnt = 0;
	state->id_rx_free_list.dl_head = NULL;
	mutex_exit(&state->id_rx_free_list.dl_mutex);
}

/*
 * Free the statically allocated Rx buffer list.
 */
static void
ibd_fini_rxlist(ibd_state_t *state)
{
	ibd_rwqe_t *rwqe;
	int i;

	/* run through the rx_queue's, calling freemsg() */
	for (i = 0; i < state->id_rx_nqueues; i++) {
		ibd_rx_queue_t *rxp = state->id_rx_queues + i;
		mutex_enter(&rxp->rx_post_lock);
		for (rwqe = WQE_TO_RWQE(rxp->rx_head); rwqe;
		    rwqe = WQE_TO_RWQE(rwqe->rwqe_next)) {
			freemsg(rwqe->rwqe_im_mblk);
			rxp->rx_cnt--;
		}
		rxp->rx_head = NULL;
		mutex_exit(&rxp->rx_post_lock);
	}

	/* cannot free rx resources unless gld returned everything */
	if (atomic_add_32_nv(&state->id_rx_list.dl_bufs_outstanding, 0) == 0)
		ibd_free_rx_rsrcs(state);
}

/*
 * Free an allocated recv wqe.
 */
/* ARGSUSED */
static void
ibd_free_rwqe(ibd_state_t *state, ibd_rwqe_t *rwqe)
{
	/*
	 * desballoc() failed (no memory).
	 *
	 * This rwqe is placed on a free list so that it
	 * can be reinstated when memory is available.
	 *
	 * NOTE: no code currently exists to reinstate
	 * these "lost" rwqes.
	 */
	mutex_enter(&state->id_rx_free_list.dl_mutex);
	state->id_rx_free_list.dl_cnt++;
	rwqe->rwqe_next = state->id_rx_free_list.dl_head;
	state->id_rx_free_list.dl_head = RWQE_TO_WQE(rwqe);
	mutex_exit(&state->id_rx_free_list.dl_mutex);
}

/*
 * IBA Rx completion queue handler. Guaranteed to be single
 * threaded and nonreentrant for this CQ.
 */
/* ARGSUSED */
static void
ibd_rcq_handler(ibt_cq_hdl_t cq_hdl, void *arg)
{
	ibd_state_t *state = (ibd_state_t *)arg;

	atomic_inc_64(&state->id_num_intrs);

	if (ibd_rx_softintr == 1) {
		mutex_enter(&state->id_rcq_poll_lock);
		if (state->id_rcq_poll_busy & IBD_CQ_POLLING) {
			state->id_rcq_poll_busy |= IBD_REDO_CQ_POLLING;
			mutex_exit(&state->id_rcq_poll_lock);
			return;
		} else {
			mutex_exit(&state->id_rcq_poll_lock);
			ddi_trigger_softintr(state->id_rx);
		}
	} else
		(void) ibd_intr((caddr_t)state);
}

/*
 * CQ handler for Tx completions, when the Tx CQ is in
 * interrupt driven mode.
 */
/* ARGSUSED */
static void
ibd_scq_handler(ibt_cq_hdl_t cq_hdl, void *arg)
{
	ibd_state_t *state = (ibd_state_t *)arg;

	atomic_inc_64(&state->id_num_intrs);

	if (ibd_tx_softintr == 1) {
		mutex_enter(&state->id_scq_poll_lock);
		if (state->id_scq_poll_busy & IBD_CQ_POLLING) {
			state->id_scq_poll_busy |= IBD_REDO_CQ_POLLING;
			mutex_exit(&state->id_scq_poll_lock);
			return;
		} else {
			mutex_exit(&state->id_scq_poll_lock);
			ddi_trigger_softintr(state->id_tx);
		}
	} else
		(void) ibd_tx_recycle((caddr_t)state);
}

/*
 * Multicast group create/delete trap handler. These will be delivered
 * on a kernel thread (handling can thus block) and can be invoked
 * concurrently. The handler can be invoked anytime after it is
 * registered and before ibt_detach().
 */
/* ARGSUSED */
static void
ibd_snet_notices_handler(void *arg, ib_gid_t gid, ibt_subnet_event_code_t code,
    ibt_subnet_event_t *event)
{
	ibd_state_t *state = (ibd_state_t *)arg;
	ibd_req_t *req;

	/*
	 * The trap handler will get invoked once for every event for
	 * every port. The input "gid" is the GID0 of the port the
	 * trap came in on; we just need to act on traps that came
	 * to our port, meaning the port on which the ipoib interface
	 * resides. Since ipoib uses GID0 of the port, we just match
	 * the gids to check whether we need to handle the trap.
	 */
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(state->id_sgid))
	if (bcmp(&gid, &state->id_sgid, sizeof (ib_gid_t)) != 0)
		return;
	_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(state->id_sgid))

	DPRINT(10, "ibd_notices_handler : %d\n", code);

	switch (code) {
		case IBT_SM_EVENT_UNAVAILABLE:
			/*
			 * If we are in promiscuous mode or have
			 * sendnonmembers, we need to print a warning
			 * message right now. Else, just store the
			 * information, print when we enter promiscuous
			 * mode or attempt nonmember send. We might
			 * also want to stop caching sendnonmember.
			 */
			ibd_print_warn(state, "IBA multicast support "
			    "degraded due to unavailability of multicast "
			    "traps");
			break;
		case IBT_SM_EVENT_AVAILABLE:
			/*
			 * If we printed a warning message above or
			 * while trying to nonmember send or get into
			 * promiscuous mode, print an okay message.
			 */
			ibd_print_warn(state, "IBA multicast support "
			    "restored due to availability of multicast "
			    "traps");
			break;
		case IBT_SM_EVENT_MCG_CREATED:
		case IBT_SM_EVENT_MCG_DELETED:
			/*
			 * If it is a "deleted" event and we are in late hca
			 * init, nothing to do.
			 */
			if (((state->id_mac_state & IBD_DRV_IN_LATE_HCA_INIT) ==
			    IBD_DRV_IN_LATE_HCA_INIT) && (code ==
			    IBT_SM_EVENT_MCG_DELETED)) {
				break;
			}
			/*
			 * Common processing of creation/deletion traps.
			 * First check if the instance is being
			 * [de]initialized; back off then, without doing
			 * anything more, since we are not sure if the
			 * async thread is around, or whether we might
			 * be racing with the detach code in ibd_m_stop()
			 * that scans the mcg list.
			 */
			if (!ibd_async_safe(state))
				return;

			req = kmem_cache_alloc(state->id_req_kmc, KM_SLEEP);
			req->rq_gid = event->sm_notice_gid;
			req->rq_ptr = (void *)code;
			ibd_queue_work_slot(state, req, IBD_ASYNC_TRAP);
			break;
	}
}

static void
ibd_async_trap(ibd_state_t *state, ibd_req_t *req)
{
	ib_gid_t mgid = req->rq_gid;
	ibt_subnet_event_code_t code = (ibt_subnet_event_code_t)req->rq_ptr;
	int ret;
	ib_pkey_t pkey = (mgid.gid_prefix >> 16) & 0xffff;

	DPRINT(10, "ibd_async_trap : %d\n", code);

	/*
	 * Check if we have already joined the IPoIB broadcast group for our
	 * PKEY. If joined, perform the rest of the operation.
	 * Else, the interface is not initialised. Do the initialisation here
	 * by calling ibd_start() and return.
	 */

	if (((state->id_mac_state & IBD_DRV_IN_LATE_HCA_INIT) ==
	    IBD_DRV_IN_LATE_HCA_INIT) && (state->id_bgroup_present == 0) &&
	    (code == IBT_SM_EVENT_MCG_CREATED)) {
		/*
		 * If we are in late HCA init and a notification for the
		 * creation of a MCG came in, check if it is the IPoIB MCG for
		 * this pkey. If not, return.
		 */
		if ((mgid.gid_guid != IB_MGID_IPV4_LOWGRP_MASK) || (pkey !=
		    state->id_pkey)) {
			ibd_async_done(state);
			return;
		}
		ibd_set_mac_progress(state, IBD_DRV_RESTART_IN_PROGRESS);
		/*
		 * Check if there is still a necessity to start the interface.
		 * It is possible that the user attempted unplumb at just about
		 * the same time, and if unplumb succeeded, we have nothing to
		 * do.
		 */
		if (((state->id_mac_state & IBD_DRV_IN_LATE_HCA_INIT) ==
		    IBD_DRV_IN_LATE_HCA_INIT) &&
		    ((ret = ibd_start(state)) != 0)) {
			DPRINT(10, "ibd_async_trap: cannot start from late HCA "
			    "init, ret=%d", ret);
		}
		ibd_clr_mac_progress(state, IBD_DRV_RESTART_IN_PROGRESS);
		ibd_async_done(state);
		return;
	}

	/*
	 * Atomically search the nonmember and sendonlymember lists and
	 * delete.
	 */
	ibd_leave_group(state, mgid, IB_MC_JSTATE_SEND_ONLY_NON);

	if (state->id_prom_op == IBD_OP_COMPLETED) {
		ibd_leave_group(state, mgid, IB_MC_JSTATE_NON);

		/*
		 * If in promiscuous mode, try to join/attach to the new
		 * mcg. Given the unreliable out-of-order mode of trap
		 * delivery, we can never be sure whether it is a problem
		 * if the join fails. Thus, we warn the admin of a failure
		 * if this was a creation trap. Note that the trap might
		 * actually be reporting a long past event, and the mcg
		 * might already have been deleted, thus we might be warning
		 * in vain.
		 */
		if ((ibd_join_group(state, mgid, IB_MC_JSTATE_NON) ==
		    NULL) && (code == IBT_SM_EVENT_MCG_CREATED))
			ibd_print_warn(state, "IBA promiscuous mode missed "
			    "new multicast gid %016llx:%016llx",
			    (u_longlong_t)mgid.gid_prefix,
			    (u_longlong_t)mgid.gid_guid);
	}

	/*
	 * Free the request slot allocated by the subnet event thread.
	 */
	ibd_async_done(state);
}

/*
 * GLDv3 entry point to get capabilities.
 */
static boolean_t
ibd_m_getcapab(void *arg, mac_capab_t cap, void *cap_data)
{
	ibd_state_t *state = arg;

	if (state->id_type == IBD_PORT_DRIVER)
		return (B_FALSE);

	switch (cap) {
	case MAC_CAPAB_HCKSUM: {
		uint32_t *txflags = cap_data;

		/*
		 * We either do full checksum or not do it at all
		 */
		if (state->id_hwcksum_capab & IBT_HCA_CKSUM_FULL)
			*txflags = HCK_FULLCKSUM | HCKSUM_INET_FULL_V4;
		else
			return (B_FALSE);
		break;
	}

	case MAC_CAPAB_LSO: {
		mac_capab_lso_t *cap_lso = cap_data;

		/*
		 * In addition to the capability and policy, since LSO
		 * relies on hw checksum, we'll not enable LSO if we
		 * don't have hw checksum.  Of course, if the HCA doesn't
		 * provide the reserved lkey capability, enabling LSO will
		 * actually affect performance adversely, so we'll disable
		 * LSO even for that case.
		 */
		if (!state->id_lso_policy || !state->id_lso_capable)
			return (B_FALSE);

		if ((state->id_hwcksum_capab & IBT_HCA_CKSUM_FULL) == 0)
			return (B_FALSE);

		if (state->id_hca_res_lkey_capab == 0) {
			ibd_print_warn(state, "no reserved-lkey capability, "
			    "disabling LSO");
			return (B_FALSE);
		}

		cap_lso->lso_flags = LSO_TX_BASIC_TCP_IPV4;
		cap_lso->lso_basic_tcp_ipv4.lso_max = state->id_lso_maxlen - 1;
		break;
	}

	default:
		return (B_FALSE);
	}

	return (B_TRUE);
}

/*
 * callback function for set/get of properties
 */
static int
ibd_m_setprop(void *arg, const char *pr_name, mac_prop_id_t pr_num,
    uint_t pr_valsize, const void *pr_val)
{
	ibd_state_t *state = arg;
	int err = 0;
	uint32_t link_mode;

	/* Cannot set properties on a port driver */
	if (state->id_type == IBD_PORT_DRIVER) {
		return (ENOTSUP);
	}

	switch (pr_num) {
		case MAC_PROP_IB_LINKMODE:
			if (state->id_mac_state & IBD_DRV_STARTED) {
				err = EBUSY;
				break;
			}
			if (pr_val == NULL) {
				err = EINVAL;
				break;
			}
			bcopy(pr_val, &link_mode, sizeof (link_mode));
			if (link_mode != IBD_LINK_MODE_UD &&
			    link_mode != IBD_LINK_MODE_RC) {
				err = EINVAL;
			} else {
				if (link_mode == IBD_LINK_MODE_RC) {
					if (state->id_enable_rc) {
						return (0);
					}
					state->id_enable_rc = 1;
					/* inform MAC framework of new MTU */
					err = mac_maxsdu_update2(state->id_mh,
					    state->rc_mtu - IPOIB_HDRSIZE,
					    state->id_mtu - IPOIB_HDRSIZE);
				} else {
					if (!state->id_enable_rc) {
						return (0);
					}
					state->id_enable_rc = 0;
					err = mac_maxsdu_update2(state->id_mh,
					    state->id_mtu - IPOIB_HDRSIZE,
					    state->id_mtu - IPOIB_HDRSIZE);
				}
				(void) ibd_record_capab(state);
				mac_capab_update(state->id_mh);
			}
			break;
		case MAC_PROP_PRIVATE:
			err = ibd_set_priv_prop(state, pr_name,
			    pr_valsize, pr_val);
			break;
		default:
			err = ENOTSUP;
			break;
	}
	return (err);
}

static int
ibd_m_getprop(void *arg, const char *pr_name, mac_prop_id_t pr_num,
    uint_t pr_valsize, void *pr_val)
{
	ibd_state_t *state = arg;
	int err = 0;

	switch (pr_num) {
		case MAC_PROP_MTU:
			break;
		default:
			if (state->id_type == IBD_PORT_DRIVER) {
				return (ENOTSUP);
			}
			break;
	}

	switch (pr_num) {
		case MAC_PROP_IB_LINKMODE:
			*(uint_t *)pr_val = state->id_enable_rc;
			break;
		case MAC_PROP_PRIVATE:
			err = ibd_get_priv_prop(state, pr_name, pr_valsize,
			    pr_val);
			break;
		default:
			err = ENOTSUP;
			break;
	}
	return (err);
}

static void
ibd_m_propinfo(void *arg, const char *pr_name, mac_prop_id_t pr_num,
    mac_prop_info_handle_t prh)
{
	ibd_state_t *state = arg;

	switch (pr_num) {
	case MAC_PROP_IB_LINKMODE: {
		mac_prop_info_set_default_uint32(prh, IBD_DEF_LINK_MODE);
		break;
	}
	case MAC_PROP_MTU: {
		uint32_t min, max;
		if (state->id_type == IBD_PORT_DRIVER) {
			min = 1500;
			max = IBD_DEF_RC_MAX_SDU;
		} else if (state->id_enable_rc) {
			min = max = IBD_DEF_RC_MAX_SDU;
		} else {
			min = max = state->id_mtu - IPOIB_HDRSIZE;
		}
		mac_prop_info_set_perm(prh, MAC_PROP_PERM_READ);
		mac_prop_info_set_range_uint32(prh, min, max);
		break;
	}
	case MAC_PROP_PRIVATE: {
		char valstr[64];
		int value;

		if (strcmp(pr_name, "_ibd_broadcast_group") == 0) {
			mac_prop_info_set_perm(prh, MAC_PROP_PERM_READ);
			return;
		} else if (strcmp(pr_name, "_ibd_coalesce_completions") == 0) {
			value = IBD_DEF_COALESCE_COMPLETIONS;
		} else if (strcmp(pr_name,
		    "_ibd_create_broadcast_group") == 0) {
			value = IBD_DEF_CREATE_BCAST_GROUP;
		} else if (strcmp(pr_name, "_ibd_hash_size") == 0) {
			value = IBD_DEF_HASH_SIZE;
		} else if (strcmp(pr_name, "_ibd_lso_enable") == 0) {
			value = IBD_DEF_LSO_POLICY;
		} else if (strcmp(pr_name, "_ibd_num_ah") == 0) {
			value = IBD_DEF_NUM_AH;
		} else if (strcmp(pr_name, "_ibd_num_lso_bufs") == 0) {
			value = IBD_DEF_NUM_LSO_BUFS;
		} else if (strcmp(pr_name, "_ibd_rc_enable_srq") == 0) {
			value = IBD_DEF_RC_ENABLE_SRQ;
		} else if (strcmp(pr_name, "_ibd_rc_num_rwqe") == 0) {
			value = IBD_DEF_RC_NUM_RWQE;
		} else if (strcmp(pr_name, "_ibd_rc_num_srq") == 0) {
			value = IBD_DEF_RC_NUM_SRQ;
		} else if (strcmp(pr_name, "_ibd_rc_num_swqe") == 0) {
			value = IBD_DEF_RC_NUM_SWQE;
		} else if (strcmp(pr_name, "_ibd_rc_rx_comp_count") == 0) {
			value = IBD_DEF_RC_RX_COMP_COUNT;
		} else if (strcmp(pr_name, "_ibd_rc_rx_comp_usec") == 0) {
			value = IBD_DEF_RC_RX_COMP_USEC;
		} else if (strcmp(pr_name, "_ibd_rc_rx_copy_thresh") == 0) {
			value = IBD_DEF_RC_RX_COPY_THRESH;
		} else if (strcmp(pr_name, "_ibd_rc_rx_rwqe_thresh") == 0) {
			value = IBD_DEF_RC_RX_RWQE_THRESH;
		} else if (strcmp(pr_name, "_ibd_rc_tx_comp_count") == 0) {
			value = IBD_DEF_RC_TX_COMP_COUNT;
		} else if (strcmp(pr_name, "_ibd_rc_tx_comp_usec") == 0) {
			value = IBD_DEF_RC_TX_COMP_USEC;
		} else if (strcmp(pr_name, "_ibd_rc_tx_copy_thresh") == 0) {
			value = IBD_DEF_RC_TX_COPY_THRESH;
		} else if (strcmp(pr_name, "_ibd_ud_num_rwqe") == 0) {
			value = IBD_DEF_UD_NUM_RWQE;
		} else if (strcmp(pr_name, "_ibd_ud_num_swqe") == 0) {
			value = IBD_DEF_UD_NUM_SWQE;
		} else if (strcmp(pr_name, "_ibd_ud_rx_comp_count") == 0) {
			value = IBD_DEF_UD_RX_COMP_COUNT;
		} else if (strcmp(pr_name, "_ibd_ud_rx_comp_usec") == 0) {
			value = IBD_DEF_UD_RX_COMP_USEC;
		} else if (strcmp(pr_name, "_ibd_ud_tx_comp_count") == 0) {
			value = IBD_DEF_UD_TX_COMP_COUNT;
		} else if (strcmp(pr_name, "_ibd_ud_tx_comp_usec") == 0) {
			value = IBD_DEF_UD_TX_COMP_USEC;
		} else if (strcmp(pr_name, "_ibd_ud_tx_copy_thresh") == 0) {
			value = IBD_DEF_UD_TX_COPY_THRESH;
		} else {
			return;
		}

		(void) snprintf(valstr, sizeof (valstr), "%d", value);
		mac_prop_info_set_default_str(prh, valstr);
		break;
	}
	} /* switch (pr_num) */
}

/* ARGSUSED2 */
static int
ibd_set_priv_prop(ibd_state_t *state, const char *pr_name,
    uint_t pr_valsize, const void *pr_val)
{
	int err = 0;
	long result;

	if (strcmp(pr_name, "_ibd_coalesce_completions") == 0) {
		if (pr_val == NULL) {
			return (EINVAL);
		}
		(void) ddi_strtol(pr_val, (char **)NULL, 0, &result);
		if (result < 0 || result > 1) {
			err = EINVAL;
		} else {
			state->id_allow_coalesce_comp_tuning = (result == 1) ?
			    B_TRUE: B_FALSE;
		}
		return (err);
	}
	if (strcmp(pr_name, "_ibd_create_broadcast_group") == 0) {
		if (state->id_mac_state & IBD_DRV_STARTED) {
			return (EBUSY);
		}
		if (pr_val == NULL) {
			return (EINVAL);
		}
		(void) ddi_strtol(pr_val, (char **)NULL, 0, &result);
		if (result < 0 || result > 1) {
			err = EINVAL;
		} else {
			state->id_create_broadcast_group = (result == 1) ?
			    B_TRUE: B_FALSE;
		}
		return (err);
	}
	if (strcmp(pr_name, "_ibd_hash_size") == 0) {
		if (state->id_mac_state & IBD_DRV_STARTED) {
			return (EBUSY);
		}
		if (pr_val == NULL) {
			return (EINVAL);
		}
		(void) ddi_strtol(pr_val, (char **)NULL, 0, &result);
		if (result < IBD_MIN_HASH_SIZE || result > IBD_MAX_HASH_SIZE) {
			err = EINVAL;
		} else {
			state->id_hash_size = (uint32_t)result;
		}
		return (err);
	}
	if (strcmp(pr_name, "_ibd_lso_enable") == 0) {
		if (state->id_mac_state & IBD_DRV_STARTED) {
			return (EBUSY);
		}
		if (pr_val == NULL) {
			return (EINVAL);
		}
		(void) ddi_strtol(pr_val, (char **)NULL, 0, &result);
		if (result < 0 || result > 1) {
			err = EINVAL;
		} else {
			state->id_lso_policy = (result == 1) ?
			    B_TRUE: B_FALSE;
		}
		mac_capab_update(state->id_mh);
		return (err);
	}
	if (strcmp(pr_name, "_ibd_num_ah") == 0) {
		if (state->id_mac_state & IBD_DRV_STARTED) {
			return (EBUSY);
		}
		if (pr_val == NULL) {
			return (EINVAL);
		}
		(void) ddi_strtol(pr_val, (char **)NULL, 0, &result);
		if (result < IBD_MIN_NUM_AH || result > IBD_MAX_NUM_AH) {
			err = EINVAL;
		} else {
			state->id_num_ah = (uint32_t)result;
		}
		return (err);
	}
	if (strcmp(pr_name, "_ibd_num_lso_bufs") == 0) {
		if (state->id_mac_state & IBD_DRV_STARTED) {
			return (EBUSY);
		}
		if (!state->id_lso_policy || !state->id_lso_capable) {
			return (EINVAL);
		}
		if (pr_val == NULL) {
			return (EINVAL);
		}
		(void) ddi_strtol(pr_val, (char **)NULL, 0, &result);
		if (result < IBD_MIN_NUM_LSO_BUFS ||
		    result > IBD_MAX_NUM_LSO_BUFS) {
			err = EINVAL;
		} else {
			state->id_num_lso_bufs = (uint32_t)result;
		}
		return (err);
	}
	if (strcmp(pr_name, "_ibd_rc_enable_srq") == 0) {
		if (state->id_mac_state & IBD_DRV_STARTED) {
			return (EBUSY);
		}
		if (pr_val == NULL) {
			return (EINVAL);
		}
		(void) ddi_strtol(pr_val, (char **)NULL, 0, &result);
		if (result < 0 || result > 1) {
			err = EINVAL;
		} else {
			state->rc_enable_srq = (result == 1) ?
			    B_TRUE: B_FALSE;
		}
		if (!state->rc_enable_srq) {
			state->id_rc_num_srq = 0;
		}
		return (err);
	}
	if (strcmp(pr_name, "_ibd_rc_num_rwqe") == 0) {
		if (state->id_mac_state & IBD_DRV_STARTED) {
			return (EBUSY);
		}
		if (pr_val == NULL) {
			return (EINVAL);
		}
		(void) ddi_strtol(pr_val, (char **)NULL, 0, &result);
		if (result < IBD_MIN_RC_NUM_RWQE ||
		    result > IBD_MAX_RC_NUM_RWQE) {
			err = EINVAL;
		} else {
			state->id_rc_num_rwqe = (uint32_t)result;
			if (state->id_allow_coalesce_comp_tuning &&
			    state->id_rc_rx_comp_count > state->id_rc_num_rwqe)
				state->id_rc_rx_comp_count =
				    state->id_rc_num_rwqe;
			if (state->id_rc_num_srq > state->id_rc_num_rwqe)
				state->id_rc_num_srq =
				    state->id_rc_num_rwqe - 1;
			/*
			 * If rx_rwqe_threshold is greater than the number of
			 * rwqes, pull it back to 25% of number of rwqes.
			 */
			if (state->id_rc_rx_rwqe_thresh > state->id_rc_num_rwqe)
				state->id_rc_rx_rwqe_thresh =
				    (state->id_rc_num_rwqe >> 2);

		}
		return (err);
	}
	if (strcmp(pr_name, "_ibd_rc_num_srq") == 0) {
		if (state->id_mac_state & IBD_DRV_STARTED) {
			return (EBUSY);
		}
		if (pr_val == NULL) {
			return (EINVAL);
		}
		if (!state->rc_enable_srq)
			return (EINVAL);

		(void) ddi_strtol(pr_val, (char **)NULL, 0, &result);
		if (result < IBD_MIN_RC_NUM_SRQ ||
		    result >= state->id_rc_num_rwqe) {
			err = EINVAL;
		} else
			state->id_rc_num_srq = (uint32_t)result;
		return (err);
	}
	if (strcmp(pr_name, "_ibd_rc_num_swqe") == 0) {
		if (state->id_mac_state & IBD_DRV_STARTED) {
			return (EBUSY);
		}
		if (pr_val == NULL) {
			return (EINVAL);
		}
		(void) ddi_strtol(pr_val, (char **)NULL, 0, &result);
		if (result < IBD_MIN_RC_NUM_SWQE ||
		    result > IBD_MAX_RC_NUM_SWQE) {
			err = EINVAL;
		} else {
			state->id_rc_num_swqe = (uint32_t)result;
			if (state->id_allow_coalesce_comp_tuning &&
			    state->id_rc_tx_comp_count > state->id_rc_num_swqe)
				state->id_rc_tx_comp_count =
				    state->id_rc_num_swqe;
		}
		return (err);
	}
	if (strcmp(pr_name, "_ibd_rc_rx_comp_count") == 0) {
		if (!state->id_allow_coalesce_comp_tuning) {
			return (ENOTSUP);
		}
		if (pr_val == NULL) {
			return (EINVAL);
		}
		(void) ddi_strtol(pr_val, (char **)NULL, 0, &result);
		if (result < 1 || result > state->id_rc_num_rwqe) {
			err = EINVAL;
		} else {
			state->id_rc_rx_comp_count = (uint32_t)result;
		}
		return (err);
	}
	if (strcmp(pr_name, "_ibd_rc_rx_comp_usec") == 0) {
		if (!state->id_allow_coalesce_comp_tuning) {
			return (ENOTSUP);
		}
		if (pr_val == NULL) {
			return (EINVAL);
		}
		(void) ddi_strtol(pr_val, (char **)NULL, 0, &result);
		if (result < 1) {
			err = EINVAL;
		} else {
			state->id_rc_rx_comp_usec = (uint32_t)result;
		}
		return (err);
	}
	if (strcmp(pr_name, "_ibd_rc_rx_copy_thresh") == 0) {
		if (state->id_mac_state & IBD_DRV_STARTED) {
			return (EBUSY);
		}
		if (pr_val == NULL) {
			return (EINVAL);
		}
		(void) ddi_strtol(pr_val, (char **)NULL, 0, &result);
		if (result < IBD_MIN_RC_RX_COPY_THRESH ||
		    result > state->rc_mtu) {
			err = EINVAL;
		} else {
			state->id_rc_rx_copy_thresh = (uint32_t)result;
		}
		return (err);
	}
	if (strcmp(pr_name, "_ibd_rc_rx_rwqe_thresh") == 0) {
		if (state->id_mac_state & IBD_DRV_STARTED) {
			return (EBUSY);
		}
		if (pr_val == NULL) {
			return (EINVAL);
		}
		(void) ddi_strtol(pr_val, (char **)NULL, 0, &result);
		if (result < IBD_MIN_RC_RX_RWQE_THRESH ||
		    result >= state->id_rc_num_rwqe) {
			err = EINVAL;
		} else {
			state->id_rc_rx_rwqe_thresh = (uint32_t)result;
		}
		return (err);
	}
	if (strcmp(pr_name, "_ibd_rc_tx_comp_count") == 0) {
		if (!state->id_allow_coalesce_comp_tuning) {
			return (ENOTSUP);
		}
		if (pr_val == NULL) {
			return (EINVAL);
		}
		(void) ddi_strtol(pr_val, (char **)NULL, 0, &result);
		if (result < 1 || result > state->id_rc_num_swqe) {
			err = EINVAL;
		} else {
			state->id_rc_tx_comp_count = (uint32_t)result;
		}
		return (err);
	}
	if (strcmp(pr_name, "_ibd_rc_tx_comp_usec") == 0) {
		if (!state->id_allow_coalesce_comp_tuning) {
			return (ENOTSUP);
		}
		if (pr_val == NULL) {
			return (EINVAL);
		}
		(void) ddi_strtol(pr_val, (char **)NULL, 0, &result);
		if (result < 1)
			err = EINVAL;
		else {
			state->id_rc_tx_comp_usec = (uint32_t)result;
		}
		return (err);
	}
	if (strcmp(pr_name, "_ibd_rc_tx_copy_thresh") == 0) {
		if (state->id_mac_state & IBD_DRV_STARTED) {
			return (EBUSY);
		}
		if (pr_val == NULL) {
			return (EINVAL);
		}
		(void) ddi_strtol(pr_val, (char **)NULL, 0, &result);
		if (result < IBD_MIN_RC_TX_COPY_THRESH ||
		    result > state->rc_mtu) {
			err = EINVAL;
		} else {
			state->id_rc_tx_copy_thresh = (uint32_t)result;
		}
		return (err);
	}
	if (strcmp(pr_name, "_ibd_ud_num_rwqe") == 0) {
		if (state->id_mac_state & IBD_DRV_STARTED) {
			return (EBUSY);
		}
		if (pr_val == NULL) {
			return (EINVAL);
		}
		(void) ddi_strtol(pr_val, (char **)NULL, 0, &result);
		if (result < IBD_MIN_UD_NUM_RWQE ||
		    result > IBD_MAX_UD_NUM_RWQE) {
			err = EINVAL;
		} else {
			if (result > state->id_hca_max_chan_sz) {
				state->id_ud_num_rwqe =
				    state->id_hca_max_chan_sz;
			} else {
				state->id_ud_num_rwqe = (uint32_t)result;
			}
			if (state->id_allow_coalesce_comp_tuning &&
			    state->id_ud_rx_comp_count > state->id_ud_num_rwqe)
				state->id_ud_rx_comp_count =
				    state->id_ud_num_rwqe;
		}
		return (err);
	}
	if (strcmp(pr_name, "_ibd_ud_num_swqe") == 0) {
		if (state->id_mac_state & IBD_DRV_STARTED) {
			return (EBUSY);
		}
		if (pr_val == NULL) {
			return (EINVAL);
		}
		(void) ddi_strtol(pr_val, (char **)NULL, 0, &result);
		if (result < IBD_MIN_UD_NUM_SWQE ||
		    result > IBD_MAX_UD_NUM_SWQE) {
			err = EINVAL;
		} else {
			if (result > state->id_hca_max_chan_sz) {
				state->id_ud_num_swqe =
				    state->id_hca_max_chan_sz;
			} else {
				state->id_ud_num_swqe = (uint32_t)result;
			}
			if (state->id_allow_coalesce_comp_tuning &&
			    state->id_ud_tx_comp_count > state->id_ud_num_swqe)
				state->id_ud_tx_comp_count =
				    state->id_ud_num_swqe;
		}
		return (err);
	}
	if (strcmp(pr_name, "_ibd_ud_rx_comp_count") == 0) {
		if (!state->id_allow_coalesce_comp_tuning) {
			return (ENOTSUP);
		}
		if (pr_val == NULL) {
			return (EINVAL);
		}
		(void) ddi_strtol(pr_val, (char **)NULL, 0, &result);
		if (result < 1 || result > state->id_ud_num_rwqe) {
			err = EINVAL;
		} else {
			state->id_ud_rx_comp_count = (uint32_t)result;
		}
		return (err);
	}
	if (strcmp(pr_name, "_ibd_ud_rx_comp_usec") == 0) {
		if (!state->id_allow_coalesce_comp_tuning) {
			return (ENOTSUP);
		}
		if (pr_val == NULL) {
			return (EINVAL);
		}
		(void) ddi_strtol(pr_val, (char **)NULL, 0, &result);
		if (result < 1) {
			err = EINVAL;
		} else {
			state->id_ud_rx_comp_usec = (uint32_t)result;
		}
		return (err);
	}
	if (strcmp(pr_name, "_ibd_ud_tx_comp_count") == 0) {
		if (!state->id_allow_coalesce_comp_tuning) {
			return (ENOTSUP);
		}
		if (pr_val == NULL) {
			return (EINVAL);
		}
		(void) ddi_strtol(pr_val, (char **)NULL, 0, &result);
		if (result < 1 || result > state->id_ud_num_swqe) {
			err = EINVAL;
		} else {
			state->id_ud_tx_comp_count = (uint32_t)result;
		}
		return (err);
	}
	if (strcmp(pr_name, "_ibd_ud_tx_comp_usec") == 0) {
		if (!state->id_allow_coalesce_comp_tuning) {
			return (ENOTSUP);
		}
		if (pr_val == NULL) {
			return (EINVAL);
		}
		(void) ddi_strtol(pr_val, (char **)NULL, 0, &result);
		if (result < 1) {
			err = EINVAL;
		} else {
			state->id_ud_tx_comp_usec = (uint32_t)result;
		}
		return (err);
	}
	if (strcmp(pr_name, "_ibd_ud_tx_copy_thresh") == 0) {
		if (state->id_mac_state & IBD_DRV_STARTED) {
			return (EBUSY);
		}
		if (pr_val == NULL) {
			return (EINVAL);
		}
		(void) ddi_strtol(pr_val, (char **)NULL, 0, &result);
		if (result < IBD_MIN_UD_TX_COPY_THRESH ||
		    result > IBD_MAX_UD_TX_COPY_THRESH) {
			err = EINVAL;
		} else {
			state->id_ud_tx_copy_thresh = (uint32_t)result;
		}
		return (err);
	}
	return (ENOTSUP);
}

static int
ibd_get_priv_prop(ibd_state_t *state, const char *pr_name, uint_t pr_valsize,
    void *pr_val)
{
	int err = ENOTSUP;
	int value;

	if (strcmp(pr_name, "_ibd_broadcast_group") == 0) {
		value = state->id_bgroup_present;
		err = 0;
		goto done;
	}
	if (strcmp(pr_name, "_ibd_coalesce_completions") == 0) {
		value = state->id_allow_coalesce_comp_tuning;
		err = 0;
		goto done;
	}
	if (strcmp(pr_name, "_ibd_create_broadcast_group") == 0) {
		value = state->id_create_broadcast_group;
		err = 0;
		goto done;
	}
	if (strcmp(pr_name, "_ibd_hash_size") == 0) {
		value = state->id_hash_size;
		err = 0;
		goto done;
	}
	if (strcmp(pr_name, "_ibd_lso_enable") == 0) {
		value = state->id_lso_policy;
		err = 0;
		goto done;
	}
	if (strcmp(pr_name, "_ibd_num_ah") == 0) {
		value = state->id_num_ah;
		err = 0;
		goto done;
	}
	if (strcmp(pr_name, "_ibd_num_lso_bufs") == 0) {
		value = state->id_num_lso_bufs;
		err = 0;
		goto done;
	}
	if (strcmp(pr_name, "_ibd_rc_enable_srq") == 0) {
		value = state->rc_enable_srq;
		err = 0;
		goto done;
	}
	if (strcmp(pr_name, "_ibd_rc_num_rwqe") == 0) {
		value = state->id_rc_num_rwqe;
		err = 0;
		goto done;
	}
	if (strcmp(pr_name, "_ibd_rc_num_srq") == 0) {
		value = state->id_rc_num_srq;
		err = 0;
		goto done;
	}
	if (strcmp(pr_name, "_ibd_rc_num_swqe") == 0) {
		value = state->id_rc_num_swqe;
		err = 0;
		goto done;
	}
	if (strcmp(pr_name, "_ibd_rc_rx_comp_count") == 0) {
		value = state->id_rc_rx_comp_count;
		err = 0;
		goto done;
	}
	if (strcmp(pr_name, "_ibd_rc_rx_comp_usec") == 0) {
		value = state->id_rc_rx_comp_usec;
		err = 0;
		goto done;
	}
	if (strcmp(pr_name, "_ibd_rc_rx_copy_thresh") == 0) {
		value = state->id_rc_rx_copy_thresh;
		err = 0;
		goto done;
	}
	if (strcmp(pr_name, "_ibd_rc_rx_rwqe_thresh") == 0) {
		value = state->id_rc_rx_rwqe_thresh;
		err = 0;
		goto done;
	}
	if (strcmp(pr_name, "_ibd_rc_tx_comp_count") == 0) {
		value = state->id_rc_tx_comp_count;
		err = 0;
		goto done;
	}
	if (strcmp(pr_name, "_ibd_rc_tx_comp_usec") == 0) {
		value = state->id_rc_tx_comp_usec;
		err = 0;
		goto done;
	}
	if (strcmp(pr_name, "_ibd_rc_tx_copy_thresh") == 0) {
		value = state->id_rc_tx_copy_thresh;
		err = 0;
		goto done;
	}
	if (strcmp(pr_name, "_ibd_ud_num_rwqe") == 0) {
		value = state->id_ud_num_rwqe;
		err = 0;
		goto done;
	}
	if (strcmp(pr_name, "_ibd_ud_num_swqe") == 0) {
		value = state->id_ud_num_swqe;
		err = 0;
		goto done;
	}
	if (strcmp(pr_name, "_ibd_ud_rx_comp_count") == 0) {
		value = state->id_ud_rx_comp_count;
		err = 0;
		goto done;
	}
	if (strcmp(pr_name, "_ibd_ud_rx_comp_usec") == 0) {
		value = state->id_ud_rx_comp_usec;
		err = 0;
		goto done;
	}
	if (strcmp(pr_name, "_ibd_ud_tx_comp_count") == 0) {
		value = state->id_ud_tx_comp_count;
		err = 0;
		goto done;
	}
	if (strcmp(pr_name, "_ibd_ud_tx_comp_usec") == 0) {
		value = state->id_ud_tx_comp_usec;
		err = 0;
		goto done;
	}
	if (strcmp(pr_name, "_ibd_ud_tx_copy_thresh") == 0) {
		value = state->id_ud_tx_copy_thresh;
		err = 0;
		goto done;
	}
done:
	if (err == 0) {
		(void) snprintf(pr_val, pr_valsize, "%d", value);
	}
	return (err);
}

static int
ibd_get_port_details(ibd_state_t *state)
{
	ibt_hca_portinfo_t *port_infop;
	ibt_status_t ret;
	uint_t psize, port_infosz;

	mutex_enter(&state->id_link_mutex);

	/*
	 * Query for port information
	 */
	ret = ibt_query_hca_ports(state->id_hca_hdl, state->id_port,
	    &port_infop, &psize, &port_infosz);
	if ((ret != IBT_SUCCESS) || (psize != 1)) {
		mutex_exit(&state->id_link_mutex);
		DPRINT(10, "ibd_get_port_details: ibt_query_hca_ports() "
		    "failed, ret=%d", ret);
		return (ENETDOWN);
	}

	/*
	 * If the link is active, verify the pkey
	 */
	if (port_infop->p_linkstate == IBT_PORT_ACTIVE) {
		if ((ret = ibt_pkey2index(state->id_hca_hdl, state->id_port,
		    state->id_pkey, &state->id_pkix)) != IBT_SUCCESS) {
			state->id_link_state = LINK_STATE_DOWN;
		} else {
			state->id_link_state = LINK_STATE_UP;
		}
		state->id_mtu = (128 << port_infop->p_mtu);
		_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(state->id_sgid))
		state->id_sgid = *port_infop->p_sgid_tbl;
		_NOTE(NOW_VISIBLE_TO_OTHER_THREADS(state->id_sgid))
		/*
		 * Now that the port is active, record the port speed
		 */
		state->id_link_speed = ibd_get_portspeed(state);
	} else {
		/* Make sure that these are handled in PORT_UP/CHANGE */
		state->id_mtu = 0;
		state->id_link_state = LINK_STATE_DOWN;
		state->id_link_speed = 0;
	}
	mutex_exit(&state->id_link_mutex);
	ibt_free_portinfo(port_infop, port_infosz);

	return (0);
}

static int
ibd_alloc_cqs(ibd_state_t *state)
{
	ibt_hca_attr_t hca_attrs;
	ibt_cq_attr_t cq_attr;
	ibt_status_t ret;
	uint32_t real_size;
	uint_t num_rwqe_change = 0;
	uint_t num_swqe_change = 0;

	ret = ibt_query_hca(state->id_hca_hdl, &hca_attrs);
	ASSERT(ret == IBT_SUCCESS);

	/*
	 * Allocate Rx/combined CQ:
	 * Theoretically, there is no point in having more than #rwqe
	 * plus #swqe cqe's, except that the CQ will be signaled for
	 * overflow when the last wqe completes, if none of the previous
	 * cqe's have been polled. Thus, we allocate just a few less wqe's
	 * to make sure such overflow does not occur.
	 */
	cq_attr.cq_sched = NULL;
	cq_attr.cq_flags = IBT_CQ_NO_FLAGS;

	/*
	 * Allocate Receive CQ.
	 */
	if (hca_attrs.hca_max_cq_sz >= (state->id_ud_num_rwqe + 1)) {
		cq_attr.cq_size = state->id_ud_num_rwqe + 1;
	} else {
		cq_attr.cq_size = hca_attrs.hca_max_cq_sz;
		num_rwqe_change = state->id_ud_num_rwqe;
		state->id_ud_num_rwqe = cq_attr.cq_size - 1;
	}

	if ((ret = ibt_alloc_cq(state->id_hca_hdl, &cq_attr,
	    &state->id_rcq_hdl, &real_size)) != IBT_SUCCESS) {
		DPRINT(10, "ibd_alloc_cqs: ibt_alloc_cq(rcq) "
		    "failed, ret=%d\n", ret);
		return (DDI_FAILURE);
	}

	if ((ret = ibt_modify_cq(state->id_rcq_hdl, state->id_ud_rx_comp_count,
	    state->id_ud_rx_comp_usec, 0)) != IBT_SUCCESS) {
		DPRINT(10, "ibd_alloc_cqs: Receive CQ interrupt "
		    "moderation failed, ret=%d\n", ret);
	}

	/* make the #rx wc's the same as max rx chain size */
	state->id_rxwcs_size = IBD_MAX_RX_MP_LEN;
	state->id_rxwcs = kmem_alloc(sizeof (ibt_wc_t) *
	    state->id_rxwcs_size, KM_SLEEP);

	/*
	 * Allocate Send CQ.
	 */
	if (hca_attrs.hca_max_cq_sz >= (state->id_ud_num_swqe + 1)) {
		cq_attr.cq_size = state->id_ud_num_swqe + 1;
	} else {
		cq_attr.cq_size = hca_attrs.hca_max_cq_sz;
		num_swqe_change = state->id_ud_num_swqe;
		state->id_ud_num_swqe = cq_attr.cq_size - 1;
	}

	if ((ret = ibt_alloc_cq(state->id_hca_hdl, &cq_attr,
	    &state->id_scq_hdl, &real_size)) != IBT_SUCCESS) {
		DPRINT(10, "ibd_alloc_cqs: ibt_alloc_cq(scq) "
		    "failed, ret=%d\n", ret);
		kmem_free(state->id_rxwcs, sizeof (ibt_wc_t) *
		    state->id_rxwcs_size);
		(void) ibt_free_cq(state->id_rcq_hdl);
		return (DDI_FAILURE);
	}
	if ((ret = ibt_modify_cq(state->id_scq_hdl, state->id_ud_tx_comp_count,
	    state->id_ud_tx_comp_usec, 0)) != IBT_SUCCESS) {
		DPRINT(10, "ibd_alloc_cqs: Send CQ interrupt "
		    "moderation failed, ret=%d\n", ret);
	}

	state->id_txwcs_size = IBD_TX_POLL_THRESH;
	state->id_txwcs = kmem_alloc(sizeof (ibt_wc_t) *
	    state->id_txwcs_size, KM_SLEEP);

	/*
	 * Print message in case we could not allocate as many wqe's
	 * as was requested.
	 */
	if (num_rwqe_change) {
		ibd_print_warn(state, "Setting #rwqe = %d instead of default "
		    "%d", state->id_ud_num_rwqe, num_rwqe_change);
	}
	if (num_swqe_change) {
		ibd_print_warn(state, "Setting #swqe = %d instead of default "
		    "%d", state->id_ud_num_swqe, num_swqe_change);
	}

	return (DDI_SUCCESS);
}

static int
ibd_setup_ud_channel(ibd_state_t *state)
{
	ibt_ud_chan_alloc_args_t ud_alloc_attr;
	ibt_ud_chan_query_attr_t ud_chan_attr;
	ibt_status_t ret;

	ud_alloc_attr.ud_flags  = IBT_ALL_SIGNALED;
	if (state->id_hca_res_lkey_capab)
		ud_alloc_attr.ud_flags |= IBT_FAST_REG_RES_LKEY;
	if (state->id_lso_policy && state->id_lso_capable)
		ud_alloc_attr.ud_flags |= IBT_USES_LSO;

	ud_alloc_attr.ud_hca_port_num	= state->id_port;
	ud_alloc_attr.ud_sizes.cs_sq_sgl = state->id_max_sqseg;
	ud_alloc_attr.ud_sizes.cs_rq_sgl = IBD_MAX_RQSEG;
	ud_alloc_attr.ud_sizes.cs_sq    = state->id_ud_num_swqe;
	ud_alloc_attr.ud_sizes.cs_rq    = state->id_ud_num_rwqe;
	ud_alloc_attr.ud_qkey		= state->id_mcinfo->mc_qkey;
	ud_alloc_attr.ud_scq		= state->id_scq_hdl;
	ud_alloc_attr.ud_rcq		= state->id_rcq_hdl;
	ud_alloc_attr.ud_pd		= state->id_pd_hdl;
	ud_alloc_attr.ud_pkey_ix	= state->id_pkix;
	ud_alloc_attr.ud_clone_chan	= NULL;

	if ((ret = ibt_alloc_ud_channel(state->id_hca_hdl, IBT_ACHAN_NO_FLAGS,
	    &ud_alloc_attr, &state->id_chnl_hdl, NULL)) != IBT_SUCCESS) {
		DPRINT(10, "ibd_setup_ud_channel: ibt_alloc_ud_channel() "
		    "failed, ret=%d\n", ret);
		return (DDI_FAILURE);
	}

	if ((ret = ibt_query_ud_channel(state->id_chnl_hdl,
	    &ud_chan_attr)) != IBT_SUCCESS) {
		DPRINT(10, "ibd_setup_ud_channel: ibt_query_ud_channel() "
		    "failed, ret=%d\n", ret);
		(void) ibt_free_channel(state->id_chnl_hdl);
		return (DDI_FAILURE);
	}

	state->id_qpnum = ud_chan_attr.ud_qpn;

	return (DDI_SUCCESS);
}

static int
ibd_undo_start(ibd_state_t *state, link_state_t cur_link_state)
{
	uint32_t progress = state->id_mac_state;
	uint_t attempts;
	ibt_status_t ret;
	ib_gid_t mgid;
	ibd_mce_t *mce;
	uint8_t jstate;
	timeout_id_t tid;

	if (atomic_dec_32_nv(&state->id_running) != 0)
		cmn_err(CE_WARN, "ibd_undo_start: id_running was not 1\n");

	/*
	 * Before we try to stop/undo whatever we did in ibd_start(),
	 * we need to mark the link state appropriately to prevent the
	 * ip layer from using this instance for any new transfers. Note
	 * that if the original state of the link was "up" when we're
	 * here, we'll set the final link state to "unknown", to behave
	 * in the same fashion as other ethernet drivers.
	 */
	mutex_enter(&state->id_link_mutex);
	if (cur_link_state == LINK_STATE_DOWN) {
		state->id_link_state = cur_link_state;
	} else {
		state->id_link_state = LINK_STATE_UNKNOWN;
	}
	mutex_exit(&state->id_link_mutex);
	bzero(&state->id_macaddr, sizeof (ipoib_mac_t));
	mac_link_update(state->id_mh, state->id_link_state);

	state->id_mac_state &= (~IBD_DRV_PORT_DETAILS_OBTAINED);
	if (progress & IBD_DRV_STARTED) {
		state->id_mac_state &= (~IBD_DRV_STARTED);
	}

	if (progress & IBD_DRV_IN_LATE_HCA_INIT) {
		state->id_mac_state &= (~IBD_DRV_IN_LATE_HCA_INIT);
	}

	/* Stop listen under Reliable Connected Mode */
	if (progress & IBD_DRV_RC_LISTEN) {
		ASSERT(state->id_enable_rc);
		if (state->rc_listen_hdl != NULL) {
			ibd_rc_stop_listen(state);
		}
		state->id_mac_state &= (~IBD_DRV_RC_LISTEN);
	}

	/* Stop timeout routine */
	if (progress & IBD_DRV_RC_TIMEOUT) {
		ASSERT(state->id_enable_rc);
		mutex_enter(&state->rc_timeout_lock);
		state->rc_timeout_start = B_FALSE;
		tid = state->rc_timeout;
		state->rc_timeout = 0;
		mutex_exit(&state->rc_timeout_lock);
		if (tid != 0)
			(void) untimeout(tid);
		state->id_mac_state &= (~IBD_DRV_RC_TIMEOUT);
	}

	if ((state->id_enable_rc) && (progress & IBD_DRV_ACACHE_INITIALIZED)) {
		attempts = 100;
		while (state->id_ah_op == IBD_OP_ONGOING) {
			/*
			 * "state->id_ah_op == IBD_OP_ONGOING" means this IPoIB
			 * port is connecting to a remote IPoIB port. Wait for
			 * the end of this connecting operation.
			 */
			delay(drv_usectohz(100000));
			if (--attempts == 0) {
				state->rc_stop_connect++;
				DPRINT(40, "ibd_undo_start: connecting");
				break;
			}
		}
		mutex_enter(&state->id_sched_lock);
		state->id_sched_needed = 0;
		mutex_exit(&state->id_sched_lock);
		(void) ibd_rc_close_all_chan(state);
	}

	/*
	 * First, stop receive interrupts; this stops the driver from
	 * handing up buffers to higher layers.  Wait for receive buffers
	 * to be returned and give up after 1 second.
	 */
	if (progress & IBD_DRV_RCQ_NOTIFY_ENABLED) {
		attempts = 10;
		while (atomic_add_32_nv(&state->id_rx_list.dl_bufs_outstanding,
		    0) > 0) {
			delay(drv_usectohz(100000));
			if (--attempts == 0) {
				/*
				 * There are pending bufs with the network
				 * layer and we have no choice but to wait
				 * for them to be done with. Reap all the
				 * Tx/Rx completions that were posted since
				 * we turned off the notification and
				 * return failure.
				 */
				cmn_err(CE_CONT, "!ibd: bufs outstanding\n");
				DPRINT(2, "ibd_undo_start: "
				    "reclaiming failed");
				break;
			}
		}
		state->id_mac_state &= (~IBD_DRV_RCQ_NOTIFY_ENABLED);
	}

	if (progress & IBD_DRV_RC_LARGEBUF_ALLOCD) {
		ibd_rc_fini_tx_largebuf_list(state);
		state->id_mac_state &= (~IBD_DRV_RC_LARGEBUF_ALLOCD);
	}

	if (progress & IBD_DRV_RC_SRQ_ALLOCD) {
		ASSERT(state->id_enable_rc);
		if (state->rc_srq_rwqe_list.dl_bufs_outstanding == 0) {
			if (state->id_ah_op == IBD_OP_ONGOING) {
				delay(drv_usectohz(10000));
				if (state->id_ah_op == IBD_OP_ONGOING) {
					/*
					 * "state->id_ah_op == IBD_OP_ONGOING"
					 * means this IPoIB port is connecting
					 * to a remote IPoIB port. We can't
					 * delete SRQ here.
					 */
					state->rc_stop_connect++;
					DPRINT(40, "ibd_undo_start: "
					    "connecting");
				} else {
					ibd_rc_fini_srq_list(state);
					state->id_mac_state &=
					    (~IBD_DRV_RC_SRQ_ALLOCD);
				}
			} else {
				ibd_rc_fini_srq_list(state);
				state->id_mac_state &= (~IBD_DRV_RC_SRQ_ALLOCD);
			}
		} else {
			DPRINT(40, "ibd_undo_start: srq bufs outstanding\n");
		}
	}

	if (progress & IBD_DRV_SM_NOTICES_REGISTERED) {
		ibt_register_subnet_notices(state->id_ibt_hdl, NULL, NULL);

		mutex_enter(&state->id_trap_lock);
		state->id_trap_stop = B_TRUE;
		while (state->id_trap_inprog > 0)
			cv_wait(&state->id_trap_cv, &state->id_trap_lock);
		mutex_exit(&state->id_trap_lock);

		state->id_mac_state &= (~IBD_DRV_SM_NOTICES_REGISTERED);
	}

	if (progress & IBD_DRV_SCQ_NOTIFY_ENABLED) {
		/*
		 * Flushing the channel ensures that all pending WQE's
		 * are marked with flush_error and handed to the CQ. It
		 * does not guarantee the invocation of the CQ handler.
		 * This call is guaranteed to return successfully for
		 * UD QPNs.
		 */
		if ((ret = ibt_flush_channel(state->id_chnl_hdl)) !=
		    IBT_SUCCESS) {
			DPRINT(10, "ibd_undo_start: flush_channel "
			    "failed, ret=%d", ret);
		}

		/*
		 * Give some time for the TX CQ handler to process the
		 * completions.
		 */
		attempts = 10;
		mutex_enter(&state->id_tx_list.dl_mutex);
		mutex_enter(&state->id_tx_rel_list.dl_mutex);
		while (state->id_tx_list.dl_cnt + state->id_tx_rel_list.dl_cnt
		    != state->id_ud_num_swqe) {
			if (--attempts == 0)
				break;
			mutex_exit(&state->id_tx_rel_list.dl_mutex);
			mutex_exit(&state->id_tx_list.dl_mutex);
			delay(drv_usectohz(100000));
			mutex_enter(&state->id_tx_list.dl_mutex);
			mutex_enter(&state->id_tx_rel_list.dl_mutex);
		}
		ibt_set_cq_handler(state->id_scq_hdl, 0, 0);
		if (state->id_tx_list.dl_cnt + state->id_tx_rel_list.dl_cnt !=
		    state->id_ud_num_swqe) {
			cmn_err(CE_WARN, "tx resources not freed\n");
		}
		mutex_exit(&state->id_tx_rel_list.dl_mutex);
		mutex_exit(&state->id_tx_list.dl_mutex);

		attempts = 10;
		while (atomic_add_32_nv(&state->id_rx_list.dl_cnt, 0) != 0) {
			if (--attempts == 0)
				break;
			delay(drv_usectohz(100000));
		}
		ibt_set_cq_handler(state->id_rcq_hdl, 0, 0);
		if (atomic_add_32_nv(&state->id_rx_list.dl_cnt, 0) != 0) {
			cmn_err(CE_WARN, "rx resources not freed\n");
		}

		state->id_mac_state &= (~IBD_DRV_SCQ_NOTIFY_ENABLED);
	}

	if (progress & IBD_DRV_BCAST_GROUP_JOINED) {
		/*
		 * Drop all residual full/non membership. This includes full
		 * membership to the broadcast group, and any nonmembership
		 * acquired during transmits. We do this after the Tx completion
		 * handlers are done, since those might result in some late
		 * leaves; this also eliminates a potential race with that
		 * path wrt the mc full list insert/delete. Trap handling
		 * has also been suppressed at this point. Thus, no locks
		 * are required while traversing the mc full list.
		 */
		DPRINT(2, "ibd_undo_start: clear full cache entries");
		mce = list_head(&state->id_mc_full);
		while (mce != NULL) {
			mgid = mce->mc_info.mc_adds_vect.av_dgid;
			jstate = mce->mc_jstate;
			mce = list_next(&state->id_mc_full, mce);
			ibd_leave_group(state, mgid, jstate);
		}
		state->id_mac_state &= (~IBD_DRV_BCAST_GROUP_JOINED);
	}

	if (progress & IBD_DRV_RXLIST_ALLOCD) {
		ibd_fini_rxlist(state);
		state->id_mac_state &= (~IBD_DRV_RXLIST_ALLOCD);
	}

	if (progress & IBD_DRV_TXLIST_ALLOCD) {
		ibd_fini_txlist(state);
		state->id_mac_state &= (~IBD_DRV_TXLIST_ALLOCD);
	}

	if (progress & IBD_DRV_UD_CHANNEL_SETUP) {
		if ((ret = ibt_free_channel(state->id_chnl_hdl)) !=
		    IBT_SUCCESS) {
			DPRINT(10, "ibd_undo_start: free_channel "
			    "failed, ret=%d", ret);
		}

		state->id_mac_state &= (~IBD_DRV_UD_CHANNEL_SETUP);
	}

	if (progress & IBD_DRV_CQS_ALLOCD) {
		kmem_free(state->id_txwcs,
		    sizeof (ibt_wc_t) * state->id_txwcs_size);
		if ((ret = ibt_free_cq(state->id_scq_hdl)) !=
		    IBT_SUCCESS) {
			DPRINT(10, "ibd_undo_start: free_cq(scq) "
			    "failed, ret=%d", ret);
		}

		kmem_free(state->id_rxwcs,
		    sizeof (ibt_wc_t) * state->id_rxwcs_size);
		if ((ret = ibt_free_cq(state->id_rcq_hdl)) != IBT_SUCCESS) {
			DPRINT(10, "ibd_undo_start: free_cq(rcq) failed, "
			    "ret=%d", ret);
		}

		state->id_txwcs = NULL;
		state->id_rxwcs = NULL;
		state->id_scq_hdl = NULL;
		state->id_rcq_hdl = NULL;

		state->id_mac_state &= (~IBD_DRV_CQS_ALLOCD);
	}

	if (progress & IBD_DRV_ACACHE_INITIALIZED) {
		mutex_enter(&state->id_ac_mutex);
		mod_hash_destroy_hash(state->id_ah_active_hash);
		mutex_exit(&state->id_ac_mutex);
		ibd_acache_fini(state);

		state->id_mac_state &= (~IBD_DRV_ACACHE_INITIALIZED);
	}

	if (progress & IBD_DRV_BCAST_GROUP_FOUND) {
		/*
		 * If we'd created the ipoib broadcast group and had
		 * successfully joined it, leave it now
		 */
		if (state->id_bgroup_created) {
			mgid = state->id_mcinfo->mc_adds_vect.av_dgid;
			jstate = IB_MC_JSTATE_FULL;
			(void) ibt_leave_mcg(state->id_sgid, mgid,
			    state->id_sgid, jstate);
		}
		ibt_free_mcg_info(state->id_mcinfo, 1);

		state->id_mac_state &= (~IBD_DRV_BCAST_GROUP_FOUND);
	}

	return (DDI_SUCCESS);
}

/*
 * These pair of routines are used to set/clear the condition that
 * the caller is likely to do something to change the id_mac_state.
 * If there's already someone doing either a start or a stop (possibly
 * due to the async handler detecting a pkey relocation event, a plumb
 * or dlpi_open, or an unplumb or dlpi_close coming in), we wait until
 * that's done.
 */
static void
ibd_set_mac_progress(ibd_state_t *state, uint_t flag)
{
	mutex_enter(&state->id_macst_lock);
	while (state->id_mac_state & IBD_DRV_RESTART_IN_PROGRESS)
		cv_wait(&state->id_macst_cv, &state->id_macst_lock);

	state->id_mac_state |= flag;
	mutex_exit(&state->id_macst_lock);
}

static void
ibd_clr_mac_progress(ibd_state_t *state, uint_t flag)
{
	mutex_enter(&state->id_macst_lock);
	state->id_mac_state &= (~flag);
	cv_signal(&state->id_macst_cv);
	mutex_exit(&state->id_macst_lock);
}

/*
 * GLDv3 entry point to start hardware.
 */
/*ARGSUSED*/
static int
ibd_m_start(void *arg)
{
	ibd_state_t *state = arg;
	int	ret;

	if (state->id_type == IBD_PORT_DRIVER)
		return (EINVAL);

	ibd_set_mac_progress(state, IBD_DRV_START_IN_PROGRESS);
	if (state->id_mac_state & IBD_DRV_IN_DELETION) {
		ibd_clr_mac_progress(state, IBD_DRV_START_IN_PROGRESS);
		return (EIO);
	}

	ret = ibd_start(state);
	ibd_clr_mac_progress(state, IBD_DRV_START_IN_PROGRESS);
	return (ret);
}

static int
ibd_start(ibd_state_t *state)
{
	int err;
	ibt_status_t ret;
	int late_hca_init = 0;

	if (state->id_mac_state & IBD_DRV_STARTED)
		return (DDI_SUCCESS);

	/*
	 * We do not increment the running flag when calling ibd_start() as
	 * a result of some event which moves the state away from late HCA
	 * initialization viz. MCG_CREATED, PORT_CHANGE or link availability.
	 */
	if (!(state->id_mac_state & IBD_DRV_IN_LATE_HCA_INIT) &&
	    (atomic_inc_32_nv(&state->id_running) != 1)) {
		DPRINT(10, "ibd_start: id_running is non-zero");
		cmn_err(CE_WARN, "ibd_start: id_running was not 0\n");
		atomic_dec_32(&state->id_running);
		return (EINVAL);
	}

	/*
	 * Get port details; if we fail here, something bad happened.
	 * Fail plumb.
	 */
	if ((err = ibd_get_port_details(state)) != 0) {
		DPRINT(10, "ibd_start: ibd_get_port_details() failed");
		goto start_fail;
	}
	/*
	 * If state->id_link_state is DOWN, it indicates that either the port
	 * is down, or the pkey is not available. In both cases, resort to late
	 * initialization. Register for subnet notices, and return success.
	 */
	state->id_mac_state |= IBD_DRV_PORT_DETAILS_OBTAINED;
	if (state->id_link_state == LINK_STATE_DOWN) {
		late_hca_init = 1;
		goto late_hca_init_return;
	}

	/*
	 * Find the IPoIB broadcast group
	 */
	if (ibd_find_bgroup(state) != IBT_SUCCESS) {
		/* Resort to late initialization */
		late_hca_init = 1;
		goto reg_snet_notices;
	}
	state->id_mac_state |= IBD_DRV_BCAST_GROUP_FOUND;

	/*
	 * Initialize per-interface caches and lists; if we fail here,
	 * it is most likely due to a lack of resources
	 */
	if (ibd_acache_init(state) != DDI_SUCCESS) {
		DPRINT(10, "ibd_start: ibd_acache_init() failed");
		err = ENOMEM;
		goto start_fail;
	}
	state->id_mac_state |= IBD_DRV_ACACHE_INITIALIZED;

	/*
	 * Allocate send and receive completion queues
	 */
	if (ibd_alloc_cqs(state) != DDI_SUCCESS) {
		DPRINT(10, "ibd_start: ibd_alloc_cqs() failed");
		err = ENOMEM;
		goto start_fail;
	}
	state->id_mac_state |= IBD_DRV_CQS_ALLOCD;

	/*
	 * Setup a UD channel
	 */
	if (ibd_setup_ud_channel(state) != DDI_SUCCESS) {
		err = ENOMEM;
		DPRINT(10, "ibd_start: ibd_setup_ud_channel() failed");
		goto start_fail;
	}
	state->id_mac_state |= IBD_DRV_UD_CHANNEL_SETUP;

	/*
	 * Allocate and initialize the tx buffer list
	 */
	if (ibd_init_txlist(state) != DDI_SUCCESS) {
		DPRINT(10, "ibd_start: ibd_init_txlist() failed");
		err = ENOMEM;
		goto start_fail;
	}
	state->id_mac_state |= IBD_DRV_TXLIST_ALLOCD;

	/*
	 * Create the send cq handler here
	 */
	ibt_set_cq_handler(state->id_scq_hdl, ibd_scq_handler, state);
	if ((ret = ibt_enable_cq_notify(state->id_scq_hdl,
	    IBT_NEXT_COMPLETION)) != IBT_SUCCESS) {
		DPRINT(10, "ibd_start: ibt_enable_cq_notify(scq) "
		    "failed, ret=%d", ret);
		err = EINVAL;
		goto start_fail;
	}
	state->id_mac_state |= IBD_DRV_SCQ_NOTIFY_ENABLED;

	/*
	 * Allocate and initialize the rx buffer list
	 */
	if (ibd_init_rxlist(state) != DDI_SUCCESS) {
		DPRINT(10, "ibd_start: ibd_init_rxlist() failed");
		err = ENOMEM;
		goto start_fail;
	}
	state->id_mac_state |= IBD_DRV_RXLIST_ALLOCD;

	/*
	 * Join IPoIB broadcast group
	 */
	if (ibd_join_group(state, state->id_mgid, IB_MC_JSTATE_FULL) == NULL) {
		DPRINT(10, "ibd_start: ibd_join_group() failed");
		err = ENOTACTIVE;
		goto start_fail;
	}
	state->id_mac_state |= IBD_DRV_BCAST_GROUP_JOINED;

	/*
	 * When we did mac_register() in ibd_attach(), we didn't register
	 * the real macaddr and we didn't have the true port mtu. Now that
	 * we're almost ready, set the local mac address and broadcast
	 * addresses and update gldv3 about the real values of these
	 * parameters.
	 */
	if (state->id_enable_rc) {
		ibd_h2n_mac(&state->id_macaddr,
		    IBD_MAC_ADDR_RC + state->id_qpnum,
		    state->id_sgid.gid_prefix, state->id_sgid.gid_guid);
		ibd_h2n_mac(&state->rc_macaddr_loopback, state->id_qpnum,
		    state->id_sgid.gid_prefix, state->id_sgid.gid_guid);
	} else {
		ibd_h2n_mac(&state->id_macaddr, state->id_qpnum,
		    state->id_sgid.gid_prefix, state->id_sgid.gid_guid);
	}
	ibd_h2n_mac(&state->id_bcaddr, IB_QPN_MASK,
	    state->id_mgid.gid_prefix, state->id_mgid.gid_guid);

	if (!state->id_enable_rc) {
		(void) mac_maxsdu_update2(state->id_mh,
		    state->id_mtu - IPOIB_HDRSIZE,
		    state->id_mtu - IPOIB_HDRSIZE);
	}
	mac_unicst_update(state->id_mh, (uint8_t *)&state->id_macaddr);

	/*
	 * Setup the receive cq handler
	 */
	ibt_set_cq_handler(state->id_rcq_hdl, ibd_rcq_handler, state);
	if ((ret = ibt_enable_cq_notify(state->id_rcq_hdl,
	    IBT_NEXT_COMPLETION)) != IBT_SUCCESS) {
		DPRINT(10, "ibd_start: ibt_enable_cq_notify(rcq) "
		    "failed, ret=%d", ret);
		err = EINVAL;
		goto start_fail;
	}
	state->id_mac_state |= IBD_DRV_RCQ_NOTIFY_ENABLED;

reg_snet_notices:
	/*
	 * In case of normal initialization sequence,
	 * Setup the subnet notices handler after we've initialized the acache/
	 * mcache and started the async thread, both of which are required for
	 * the trap handler to function properly.
	 *
	 * Now that the async thread has been started (and we've already done
	 * a mac_register() during attach so mac_tx_update() can be called
	 * if necessary without any problem), we can enable the trap handler
	 * to queue requests to the async thread.
	 *
	 * In case of late hca initialization, the subnet notices handler will
	 * only handle MCG created/deleted event. The action performed as part
	 * of handling these events is to start the interface. So, the
	 * acache/mcache initialization is not a necessity in such cases for
	 * registering the subnet notices handler. Also, if we are in
	 * ibd_start() as a result of, say, some event handling after entering
	 * late hca initialization phase no need to register again.
	 */
	if ((state->id_mac_state & IBD_DRV_SM_NOTICES_REGISTERED) == 0) {
		ibt_register_subnet_notices(state->id_ibt_hdl,
		    ibd_snet_notices_handler, state);
		mutex_enter(&state->id_trap_lock);
		state->id_trap_stop = B_FALSE;
		mutex_exit(&state->id_trap_lock);
		state->id_mac_state |= IBD_DRV_SM_NOTICES_REGISTERED;
	}

late_hca_init_return:
	if (late_hca_init == 1) {
		state->id_mac_state |= IBD_DRV_IN_LATE_HCA_INIT;
		/*
		 * In case of late initialization, mark the link state as down,
		 * immaterial of the actual link state as reported in the
		 * port_info.
		 */
		state->id_link_state = LINK_STATE_DOWN;
		mac_unicst_update(state->id_mh, (uint8_t *)&state->id_macaddr);
		mac_link_update(state->id_mh, state->id_link_state);
		return (DDI_SUCCESS);
	}

	if (state->id_enable_rc) {
		if (state->rc_enable_srq) {
			if (state->id_mac_state & IBD_DRV_RC_SRQ_ALLOCD) {
				if (ibd_rc_repost_srq_free_list(state) !=
				    IBT_SUCCESS) {
					err = ENOMEM;
					goto start_fail;
				}
			} else {
				/* Allocate SRQ resource */
				if (ibd_rc_init_srq_list(state) !=
				    IBT_SUCCESS) {
					err = ENOMEM;
					goto start_fail;
				}
				state->id_mac_state |= IBD_DRV_RC_SRQ_ALLOCD;
			}
		}

		if (ibd_rc_init_tx_largebuf_list(state) != IBT_SUCCESS) {
			DPRINT(10, "ibd_start: ibd_rc_init_tx_largebuf_list() "
			    "failed");
			err = ENOMEM;
			goto start_fail;
		}
		state->id_mac_state |= IBD_DRV_RC_LARGEBUF_ALLOCD;

		/* RC: begin to listen only after everything is available */
		if (ibd_rc_listen(state) != IBT_SUCCESS) {
			DPRINT(10, "ibd_start: ibd_rc_listen() failed");
			err = EINVAL;
			goto start_fail;
		}
		state->id_mac_state |= IBD_DRV_RC_LISTEN;
	}

	/*
	 * Indicate link status to GLDv3 and higher layers. By default,
	 * we assume we are in up state (which must have been true at
	 * least at the time the broadcast mcg's were probed); if there
	 * were any up/down transitions till the time we come here, the
	 * async handler will have updated last known state, which we
	 * use to tell GLDv3. The async handler will not send any
	 * notifications to GLDv3 till we reach here in the initialization
	 * sequence.
	 */
	mac_link_update(state->id_mh, state->id_link_state);
	state->id_mac_state &= ~IBD_DRV_IN_LATE_HCA_INIT;
	state->id_mac_state |= IBD_DRV_STARTED;

	/* Start timer after everything is ready */
	if (state->id_enable_rc) {
		mutex_enter(&state->rc_timeout_lock);
		state->rc_timeout_start = B_TRUE;
		state->rc_timeout = timeout(ibd_rc_conn_timeout_call, state,
		    SEC_TO_TICK(ibd_rc_conn_timeout));
		mutex_exit(&state->rc_timeout_lock);
		state->id_mac_state |= IBD_DRV_RC_TIMEOUT;
	}

	return (DDI_SUCCESS);

start_fail:
	/*
	 * If we ran into a problem during ibd_start() and ran into
	 * some other problem during undoing our partial work, we can't
	 * do anything about it.  Ignore any errors we might get from
	 * ibd_undo_start() and just return the original error we got.
	 */
	(void) ibd_undo_start(state, LINK_STATE_DOWN);
	return (err);
}

/*
 * GLDv3 entry point to stop hardware from receiving packets.
 */
/*ARGSUSED*/
static void
ibd_m_stop(void *arg)
{
	ibd_state_t *state = (ibd_state_t *)arg;

	if (state->id_type == IBD_PORT_DRIVER)
		return;

	ibd_set_mac_progress(state, IBD_DRV_STOP_IN_PROGRESS);

	(void) ibd_undo_start(state, state->id_link_state);

	ibd_clr_mac_progress(state, IBD_DRV_STOP_IN_PROGRESS);
}

/*
 * GLDv3 entry point to modify device's mac address. We do not
 * allow address modifications.
 */
static int
ibd_m_unicst(void *arg, const uint8_t *macaddr)
{
	ibd_state_t *state = arg;

	if (state->id_type == IBD_PORT_DRIVER)
		return (EINVAL);

	/*
	 * Don't bother even comparing the macaddr if we haven't
	 * completed ibd_m_start().
	 */
	if ((state->id_mac_state & IBD_DRV_STARTED) == 0)
		return (0);

	if (bcmp(macaddr, &state->id_macaddr, IPOIB_ADDRL) == 0)
		return (0);
	else
		return (EINVAL);
}

/*
 * The blocking part of the IBA join/leave operations are done out
 * of here on the async thread.
 */
static void
ibd_async_multicast(ibd_state_t *state, ib_gid_t mgid, int op)
{
	DPRINT(3, "ibd_async_multicast : async_setmc op %d :"
	    "%016llx:%016llx\n", op, mgid.gid_prefix, mgid.gid_guid);

	if (op == IBD_ASYNC_JOIN) {
		if (ibd_join_group(state, mgid, IB_MC_JSTATE_FULL) == NULL) {
			ibd_print_warn(state, "Join multicast group failed :"
			"%016llx:%016llx", mgid.gid_prefix, mgid.gid_guid);
		}
	} else {
		/*
		 * Here, we must search for the proper mcg_info and
		 * use that to leave the group.
		 */
		ibd_leave_group(state, mgid, IB_MC_JSTATE_FULL);
	}
}

/*
 * GLDv3 entry point for multicast enable/disable requests.
 * This function queues the operation to the async thread and
 * return success for a valid multicast address.
 */
static int
ibd_m_multicst(void *arg, boolean_t add, const uint8_t *mcmac)
{
	ibd_state_t *state = (ibd_state_t *)arg;
	ipoib_mac_t maddr, *mcast;
	ib_gid_t mgid;
	ibd_req_t *req;

	if (state->id_type == IBD_PORT_DRIVER)
		return (EINVAL);

	/*
	 * If we haven't completed ibd_m_start(), async thread wouldn't
	 * have been started and id_bcaddr wouldn't be set, so there's
	 * no point in continuing.
	 */
	if ((state->id_mac_state & IBD_DRV_STARTED) == 0)
		return (0);

	/*
	 * The incoming multicast address might not be aligned properly
	 * on a 4 byte boundary to be considered an ipoib_mac_t. We force
	 * it to look like one though, to get the offsets of the mc gid,
	 * since we know we are not going to dereference any values with
	 * the ipoib_mac_t pointer.
	 */
	bcopy(mcmac, &maddr, sizeof (ipoib_mac_t));
	mcast = &maddr;

	/*
	 * Check validity of MCG address. We could additionally check
	 * that a enable/disable is not being issued on the "broadcast"
	 * mcg, but since this operation is only invokable by privileged
	 * programs anyway, we allow the flexibility to those dlpi apps.
	 * Note that we do not validate the "scope" of the IBA mcg.
	 */
	if ((ntohl(mcast->ipoib_qpn) & IB_QPN_MASK) != IB_MC_QPN)
		return (EINVAL);

	/*
	 * fill in multicast pkey and scope
	 */
	IBD_FILL_SCOPE_PKEY(mcast, state->id_scope, state->id_pkey);

	/*
	 * If someone is trying to JOIN/LEAVE the broadcast group, we do
	 * nothing (i.e. we stay JOINed to the broadcast group done in
	 * ibd_m_start()), to mimic ethernet behavior. IPv4 specifically
	 * requires to be joined to broadcast groups at all times.
	 * ibd_join_group() has an ASSERT(omce->mc_fullreap) that also
	 * depends on this.
	 */
	if (bcmp(mcast, &state->id_bcaddr, IPOIB_ADDRL) == 0)
		return (0);

	ibd_n2h_gid(mcast, &mgid);
	req = kmem_cache_alloc(state->id_req_kmc, KM_NOSLEEP);
	if (req == NULL)
		return (ENOMEM);

	req->rq_gid = mgid;

	if (add) {
		DPRINT(1, "ibd_m_multicst : %016llx:%016llx\n",
		    mgid.gid_prefix, mgid.gid_guid);
		ibd_queue_work_slot(state, req, IBD_ASYNC_JOIN);
	} else {
		DPRINT(1, "ibd_m_multicst : unset_multicast : "
		    "%016llx:%016llx", mgid.gid_prefix, mgid.gid_guid);
		ibd_queue_work_slot(state, req, IBD_ASYNC_LEAVE);
	}
	return (0);
}

/*
 * The blocking part of the IBA promiscuous operations are done
 * out of here on the async thread. The dlpireq parameter indicates
 * whether this invocation is due to a dlpi request or due to
 * a port up/down event.
 */
static void
ibd_async_unsetprom(ibd_state_t *state)
{
	ibd_mce_t *mce = list_head(&state->id_mc_non);
	ib_gid_t mgid;

	DPRINT(2, "ibd_async_unsetprom : async_unset_promisc");

	while (mce != NULL) {
		mgid = mce->mc_info.mc_adds_vect.av_dgid;
		mce = list_next(&state->id_mc_non, mce);
		ibd_leave_group(state, mgid, IB_MC_JSTATE_NON);
	}
	state->id_prom_op = IBD_OP_NOTSTARTED;
}

/*
 * The blocking part of the IBA promiscuous operations are done
 * out of here on the async thread. The dlpireq parameter indicates
 * whether this invocation is due to a dlpi request or due to
 * a port up/down event.
 */
static void
ibd_async_setprom(ibd_state_t *state)
{
	ibt_mcg_attr_t mcg_attr;
	ibt_mcg_info_t *mcg_info;
	ib_gid_t mgid;
	uint_t numg;
	int i;
	char ret = IBD_OP_COMPLETED;

	DPRINT(2, "ibd_async_setprom : async_set_promisc");

	/*
	 * Obtain all active MC groups on the IB fabric with
	 * specified criteria (scope + Pkey + Qkey + mtu).
	 */
	bzero(&mcg_attr, sizeof (mcg_attr));
	mcg_attr.mc_pkey = state->id_pkey;
	mcg_attr.mc_scope = state->id_scope;
	mcg_attr.mc_qkey = state->id_mcinfo->mc_qkey;
	mcg_attr.mc_mtu_req.r_mtu = state->id_mcinfo->mc_mtu;
	mcg_attr.mc_mtu_req.r_selector = IBT_EQU;
	if (ibt_query_mcg(state->id_sgid, &mcg_attr, 0, &mcg_info, &numg) !=
	    IBT_SUCCESS) {
		ibd_print_warn(state, "Could not get list of IBA multicast "
		    "groups");
		ret = IBD_OP_ERRORED;
		goto done;
	}

	/*
	 * Iterate over the returned mcg's and join as NonMember
	 * to the IP mcg's.
	 */
	for (i = 0; i < numg; i++) {
		/*
		 * Do a NonMember JOIN on the MC group.
		 */
		mgid = mcg_info[i].mc_adds_vect.av_dgid;
		if (ibd_join_group(state, mgid, IB_MC_JSTATE_NON) == NULL)
			ibd_print_warn(state, "IBA promiscuous mode missed "
			    "multicast gid %016llx:%016llx",
			    (u_longlong_t)mgid.gid_prefix,
			    (u_longlong_t)mgid.gid_guid);
	}

	ibt_free_mcg_info(mcg_info, numg);
	DPRINT(4, "ibd_async_setprom : async_set_promisc completes");
done:
	state->id_prom_op = ret;
}

/*
 * GLDv3 entry point for multicast promiscuous enable/disable requests.
 * GLDv3 assumes phys state receives more packets than multi state,
 * which is not true for IPoIB. Thus, treat the multi and phys
 * promiscuous states the same way to work with GLDv3's assumption.
 */
static int
ibd_m_promisc(void *arg, boolean_t on)
{
	ibd_state_t *state = (ibd_state_t *)arg;
	ibd_req_t *req;

	if (state->id_type == IBD_PORT_DRIVER)
		return (EINVAL);

	/*
	 * Async thread wouldn't have been started if we haven't
	 * passed ibd_m_start()
	 */
	if ((state->id_mac_state & IBD_DRV_STARTED) == 0)
		return (0);

	req = kmem_cache_alloc(state->id_req_kmc, KM_NOSLEEP);
	if (req == NULL)
		return (ENOMEM);
	if (on) {
		DPRINT(1, "ibd_m_promisc : set_promisc : %d", on);
		ibd_queue_work_slot(state, req, IBD_ASYNC_PROMON);
	} else {
		DPRINT(1, "ibd_m_promisc : unset_promisc");
		ibd_queue_work_slot(state, req, IBD_ASYNC_PROMOFF);
	}

	return (0);
}

/*
 * GLDv3 entry point for gathering statistics.
 */
static int
ibd_m_stat(void *arg, uint_t stat, uint64_t *val)
{
	ibd_state_t *state = (ibd_state_t *)arg;

	switch (stat) {
	case MAC_STAT_IFSPEED:
		*val = state->id_link_speed;
		break;
	case MAC_STAT_MULTIRCV:
		*val = state->id_multi_rcv;
		break;
	case MAC_STAT_BRDCSTRCV:
		*val = state->id_brd_rcv;
		break;
	case MAC_STAT_MULTIXMT:
		*val = state->id_multi_xmt;
		break;
	case MAC_STAT_BRDCSTXMT:
		*val = state->id_brd_xmt;
		break;
	case MAC_STAT_RBYTES:
		*val = state->id_rcv_bytes + state->rc_rcv_trans_byte
		    + state->rc_rcv_copy_byte;
		break;
	case MAC_STAT_IPACKETS:
		*val = state->id_rcv_pkt + state->rc_rcv_trans_pkt
		    + state->rc_rcv_copy_pkt;
		break;
	case MAC_STAT_OBYTES:
		*val = state->id_xmt_bytes + state->rc_xmt_bytes;
		break;
	case MAC_STAT_OPACKETS:
		*val = state->id_xmt_pkt + state->rc_xmt_small_pkt +
		    state->rc_xmt_fragmented_pkt +
		    state->rc_xmt_map_fail_pkt + state->rc_xmt_map_succ_pkt;
		break;
	case MAC_STAT_OERRORS:
		*val = state->id_ah_error;	/* failed AH translation */
		break;
	case MAC_STAT_IERRORS:
		*val = 0;
		break;
	case MAC_STAT_NOXMTBUF:
		*val = state->id_tx_short + state->rc_swqe_short +
		    state->rc_xmt_buf_short;
		break;
	case MAC_STAT_NORCVBUF:
	default:
		return (ENOTSUP);
	}

	return (0);
}

static void
ibd_async_txsched(ibd_state_t *state)
{
	ibd_resume_transmission(state);
}

static void
ibd_resume_transmission(ibd_state_t *state)
{
	int flag;
	int met_thresh = 0;
	int thresh = 0;
	int ret = -1;

	mutex_enter(&state->id_sched_lock);
	if (state->id_sched_needed & IBD_RSRC_SWQE) {
		mutex_enter(&state->id_tx_list.dl_mutex);
		mutex_enter(&state->id_tx_rel_list.dl_mutex);
		met_thresh = state->id_tx_list.dl_cnt +
		    state->id_tx_rel_list.dl_cnt;
		mutex_exit(&state->id_tx_rel_list.dl_mutex);
		mutex_exit(&state->id_tx_list.dl_mutex);
		thresh = IBD_FREE_SWQES_THRESH;
		flag = IBD_RSRC_SWQE;
	} else if (state->id_sched_needed & IBD_RSRC_LSOBUF) {
		ASSERT(state->id_lso != NULL);
		mutex_enter(&state->id_lso_lock);
		met_thresh = state->id_lso->bkt_nfree;
		thresh = IBD_FREE_LSOS_THRESH;
		mutex_exit(&state->id_lso_lock);
		flag = IBD_RSRC_LSOBUF;
		if (met_thresh > thresh)
			state->id_sched_lso_cnt++;
	}
	if (met_thresh > thresh) {
		state->id_sched_needed &= ~flag;
		state->id_sched_cnt++;
		ret = 0;
	}
	mutex_exit(&state->id_sched_lock);

	if (ret == 0)
		mac_tx_update(state->id_mh);
}

/*
 * Release the send wqe back into free list.
 */
static void
ibd_release_swqe(ibd_state_t *state, ibd_swqe_t *head, ibd_swqe_t *tail, int n)
{
	/*
	 * Add back on Tx list for reuse.
	 */
	ASSERT(tail->swqe_next == NULL);
	mutex_enter(&state->id_tx_rel_list.dl_mutex);
	state->id_tx_rel_list.dl_pending_sends = B_FALSE;
	tail->swqe_next = state->id_tx_rel_list.dl_head;
	state->id_tx_rel_list.dl_head = SWQE_TO_WQE(head);
	state->id_tx_rel_list.dl_cnt += n;
	mutex_exit(&state->id_tx_rel_list.dl_mutex);
}

/*
 * Acquire a send wqe from free list.
 * Returns error number and send wqe pointer.
 */
static ibd_swqe_t *
ibd_acquire_swqe(ibd_state_t *state)
{
	ibd_swqe_t *wqe;

	mutex_enter(&state->id_tx_rel_list.dl_mutex);
	if (state->id_tx_rel_list.dl_head != NULL) {
		/* transfer id_tx_rel_list to id_tx_list */
		state->id_tx_list.dl_head =
		    state->id_tx_rel_list.dl_head;
		state->id_tx_list.dl_cnt =
		    state->id_tx_rel_list.dl_cnt;
		state->id_tx_list.dl_pending_sends = B_FALSE;

		/* clear id_tx_rel_list */
		state->id_tx_rel_list.dl_head = NULL;
		state->id_tx_rel_list.dl_cnt = 0;
		mutex_exit(&state->id_tx_rel_list.dl_mutex);

		wqe = WQE_TO_SWQE(state->id_tx_list.dl_head);
		state->id_tx_list.dl_cnt -= 1;
		state->id_tx_list.dl_head = wqe->swqe_next;
	} else {	/* no free swqe */
		mutex_exit(&state->id_tx_rel_list.dl_mutex);
		state->id_tx_list.dl_pending_sends = B_TRUE;
		DPRINT(5, "ibd_acquire_swqe: out of Tx wqe");
		state->id_tx_short++;
		wqe = NULL;
	}
	return (wqe);
}

static int
ibd_setup_lso(ibd_swqe_t *node, mblk_t *mp, uint32_t mss,
    ibt_ud_dest_hdl_t ud_dest)
{
	mblk_t	*nmp;
	int iph_len, tcph_len;
	ibt_wr_lso_t *lso;
	uintptr_t ip_start, tcp_start;
	uint8_t *dst;
	uint_t pending, mblen;

	/*
	 * The code in ibd_send would've set 'wr.ud.udwr_dest' by default;
	 * we need to adjust it here for lso.
	 */
	lso = &(node->w_swr.wr.ud_lso);
	lso->lso_ud_dest = ud_dest;
	lso->lso_mss = mss;

	/*
	 * Calculate the LSO header size and set it in the UD LSO structure.
	 * Note that the only assumption we make is that each of the IPoIB,
	 * IP and TCP headers will be contained in a single mblk fragment;
	 * together, the headers may span multiple mblk fragments.
	 */
	nmp = mp;
	ip_start = (uintptr_t)(nmp->b_rptr) + IPOIB_HDRSIZE;
	if (ip_start >= (uintptr_t)(nmp->b_wptr)) {
		ip_start = (uintptr_t)nmp->b_cont->b_rptr
		    + (ip_start - (uintptr_t)(nmp->b_wptr));
		nmp = nmp->b_cont;

	}
	iph_len = IPH_HDR_LENGTH((ipha_t *)ip_start);

	tcp_start = ip_start + iph_len;
	if (tcp_start >= (uintptr_t)(nmp->b_wptr)) {
		tcp_start = (uintptr_t)nmp->b_cont->b_rptr
		    + (tcp_start - (uintptr_t)(nmp->b_wptr));
		nmp = nmp->b_cont;
	}
	tcph_len = TCP_HDR_LENGTH((tcph_t *)tcp_start);
	lso->lso_hdr_sz = IPOIB_HDRSIZE + iph_len + tcph_len;

	/*
	 * If the lso header fits entirely within a single mblk fragment,
	 * we'll avoid an additional copy of the lso header here and just
	 * pass the b_rptr of the mblk directly.
	 *
	 * If this isn't true, we'd have to allocate for it explicitly.
	 */
	if (lso->lso_hdr_sz <= MBLKL(mp)) {
		lso->lso_hdr = mp->b_rptr;
	} else {
		/* On work completion, remember to free this allocated hdr */
		lso->lso_hdr = kmem_zalloc(lso->lso_hdr_sz, KM_NOSLEEP);
		if (lso->lso_hdr == NULL) {
			DPRINT(10, "ibd_setup_lso: couldn't allocate lso hdr, "
			    "sz = %d", lso->lso_hdr_sz);
			lso->lso_hdr_sz = 0;
			lso->lso_mss = 0;
			return (-1);
		}
	}

	/*
	 * Copy in the lso header only if we need to
	 */
	if (lso->lso_hdr != mp->b_rptr) {
		dst = lso->lso_hdr;
		pending = lso->lso_hdr_sz;

		for (nmp = mp; nmp && pending; nmp = nmp->b_cont) {
			mblen = MBLKL(nmp);
			if (pending > mblen) {
				bcopy(nmp->b_rptr, dst, mblen);
				dst += mblen;
				pending -= mblen;
			} else {
				bcopy(nmp->b_rptr, dst, pending);
				break;
			}
		}
	}

	return (0);
}

static void
ibd_free_lsohdr(ibd_swqe_t *node, mblk_t *mp)
{
	ibt_wr_lso_t *lso;

	if ((!node) || (!mp))
		return;

	/*
	 * Free any header space that we might've allocated if we
	 * did an LSO
	 */
	if (node->w_swr.wr_opcode == IBT_WRC_SEND_LSO) {
		lso = &(node->w_swr.wr.ud_lso);
		if ((lso->lso_hdr) && (lso->lso_hdr != mp->b_rptr)) {
			kmem_free(lso->lso_hdr, lso->lso_hdr_sz);
			lso->lso_hdr = NULL;
			lso->lso_hdr_sz = 0;
		}
	}
}

static void
ibd_post_send(ibd_state_t *state, ibd_swqe_t *node)
{
	uint_t		i;
	uint_t		num_posted;
	uint_t		n_wrs;
	ibt_status_t	ibt_status;
	ibt_send_wr_t	wrs[IBD_MAX_TX_POST_MULTIPLE];
	ibd_swqe_t	*tx_head, *elem;
	ibd_swqe_t	*nodes[IBD_MAX_TX_POST_MULTIPLE];

	/* post the one request, then check for more */
	ibt_status = ibt_post_send(state->id_chnl_hdl,
	    &node->w_swr, 1, NULL);
	if (ibt_status != IBT_SUCCESS) {
		ibd_print_warn(state, "ibd_post_send: "
		    "posting one wr failed: ret=%d", ibt_status);
		ibd_tx_cleanup(state, node);
	}

	tx_head = NULL;
	for (;;) {
		if (tx_head == NULL) {
			mutex_enter(&state->id_txpost_lock);
			tx_head = state->id_tx_head;
			if (tx_head == NULL) {
				state->id_tx_busy = 0;
				mutex_exit(&state->id_txpost_lock);
				return;
			}
			state->id_tx_head = NULL;
			mutex_exit(&state->id_txpost_lock);
		}

		/*
		 * Collect pending requests, IBD_MAX_TX_POST_MULTIPLE wrs
		 * at a time if possible, and keep posting them.
		 */
		for (n_wrs = 0, elem = tx_head;
		    (elem) && (n_wrs < IBD_MAX_TX_POST_MULTIPLE);
		    elem = WQE_TO_SWQE(elem->swqe_next), n_wrs++) {
			nodes[n_wrs] = elem;
			wrs[n_wrs] = elem->w_swr;
		}
		tx_head = elem;

		ASSERT(n_wrs != 0);

		/*
		 * If posting fails for some reason, we'll never receive
		 * completion intimation, so we'll need to cleanup. But
		 * we need to make sure we don't clean up nodes whose
		 * wrs have been successfully posted. We assume that the
		 * hca driver returns on the first failure to post and
		 * therefore the first 'num_posted' entries don't need
		 * cleanup here.
		 */
		num_posted = 0;
		ibt_status = ibt_post_send(state->id_chnl_hdl,
		    wrs, n_wrs, &num_posted);
		if (ibt_status != IBT_SUCCESS) {
			ibd_print_warn(state, "ibd_post_send: "
			    "posting multiple wrs failed: "
			    "requested=%d, done=%d, ret=%d",
			    n_wrs, num_posted, ibt_status);

			for (i = num_posted; i < n_wrs; i++)
				ibd_tx_cleanup(state, nodes[i]);
		}
	}
}

static int
ibd_prepare_sgl(ibd_state_t *state, mblk_t *mp, ibd_swqe_t *node,
    uint_t lsohdr_sz)
{
	ibt_wr_ds_t *sgl;
	ibt_status_t ibt_status;
	mblk_t *nmp;
	mblk_t *data_mp;
	uchar_t *bufp;
	size_t blksize;
	size_t skip;
	size_t avail;
	uint_t pktsize;
	uint_t frag_len;
	uint_t pending_hdr;
	int nmblks;
	int i;

	/*
	 * Let's skip ahead to the data if this is LSO
	 */
	data_mp = mp;
	pending_hdr = 0;
	if (lsohdr_sz) {
		pending_hdr = lsohdr_sz;
		for (nmp = mp; nmp; nmp = nmp->b_cont) {
			frag_len = nmp->b_wptr - nmp->b_rptr;
			if (frag_len > pending_hdr)
				break;
			pending_hdr -= frag_len;
		}
		data_mp = nmp;	/* start of data past lso header */
		ASSERT(data_mp != NULL);
	}

	/*
	 * Calculate the size of message data and number of msg blocks
	 */
	pktsize = 0;
	for (nmblks = 0, nmp = data_mp; nmp != NULL;
	    nmp = nmp->b_cont, nmblks++) {
		pktsize += MBLKL(nmp);
	}
	pktsize -= pending_hdr;

	/*
	 * We only do ibt_map_mem_iov() if the pktsize is above the
	 * "copy-threshold", and if the number of mp fragments is less than
	 * the maximum acceptable.
	 */
	if ((state->id_hca_res_lkey_capab) &&
	    (pktsize > state->id_ud_tx_copy_thresh) &&
	    (nmblks < state->id_max_sqseg_hiwm)) {
		ibt_iov_t iov_arr[IBD_MAX_SQSEG];
		ibt_iov_attr_t iov_attr;

		iov_attr.iov_as = NULL;
		iov_attr.iov = iov_arr;
		iov_attr.iov_buf = NULL;
		iov_attr.iov_list_len = nmblks;
		iov_attr.iov_wr_nds = state->id_max_sqseg;
		iov_attr.iov_lso_hdr_sz = lsohdr_sz;
		iov_attr.iov_flags = IBT_IOV_SLEEP;

		for (nmp = data_mp, i = 0; i < nmblks; i++, nmp = nmp->b_cont) {
			iov_arr[i].iov_addr = (caddr_t)(void *)nmp->b_rptr;
			iov_arr[i].iov_len = MBLKL(nmp);
			if (i == 0) {
				iov_arr[i].iov_addr += pending_hdr;
				iov_arr[i].iov_len -= pending_hdr;
			}
		}

		node->w_buftype = IBD_WQE_MAPPED;
		node->w_swr.wr_sgl = node->w_sgl;

		ibt_status = ibt_map_mem_iov(state->id_hca_hdl, &iov_attr,
		    (ibt_all_wr_t *)&node->w_swr, &node->w_mi_hdl);
		if (ibt_status != IBT_SUCCESS) {
			ibd_print_warn(state, "ibd_send: ibt_map_mem_iov "
			    "failed, nmblks=%d, ret=%d\n", nmblks, ibt_status);
			goto ibd_copy_path;
		}

		return (0);
	}

ibd_copy_path:
	if (pktsize <= state->id_tx_buf_sz) {
		node->swqe_copybuf.ic_sgl.ds_len = pktsize;
		node->w_swr.wr_nds = 1;
		node->w_swr.wr_sgl = &node->swqe_copybuf.ic_sgl;
		node->w_buftype = IBD_WQE_TXBUF;

		/*
		 * Even though this is the copy path for transfers less than
		 * id_tx_buf_sz, it could still be an LSO packet.  If so, it
		 * is possible the first data mblk fragment (data_mp) still
		 * contains part of the LSO header that we need to skip.
		 */
		bufp = (uchar_t *)(uintptr_t)node->w_swr.wr_sgl->ds_va;
		for (nmp = data_mp; nmp != NULL; nmp = nmp->b_cont) {
			blksize = MBLKL(nmp) - pending_hdr;
			bcopy(nmp->b_rptr + pending_hdr, bufp, blksize);
			bufp += blksize;
			pending_hdr = 0;
		}

		return (0);
	}

	/*
	 * Copy path for transfers greater than id_tx_buf_sz
	 */
	node->w_swr.wr_sgl = node->w_sgl;
	if (ibd_acquire_lsobufs(state, pktsize,
	    node->w_swr.wr_sgl, &(node->w_swr.wr_nds)) != 0) {
		DPRINT(10, "ibd_prepare_sgl: lso bufs acquire failed");
		return (-1);
	}
	node->w_buftype = IBD_WQE_LSOBUF;

	/*
	 * Copy the larger-than-id_tx_buf_sz packet into a set of
	 * fixed-sized, pre-mapped LSO buffers. Note that we might
	 * need to skip part of the LSO header in the first fragment
	 * as before.
	 */
	nmp = data_mp;
	skip = pending_hdr;
	for (i = 0; i < node->w_swr.wr_nds; i++) {
		sgl = node->w_swr.wr_sgl + i;
		bufp = (uchar_t *)(uintptr_t)sgl->ds_va;
		avail = IBD_LSO_BUFSZ;
		while (nmp && avail) {
			blksize = MBLKL(nmp) - skip;
			if (blksize > avail) {
				bcopy(nmp->b_rptr + skip, bufp, avail);
				skip += avail;
				avail = 0;
			} else {
				bcopy(nmp->b_rptr + skip, bufp, blksize);
				skip = 0;
				avail -= blksize;
				bufp += blksize;
				nmp = nmp->b_cont;
			}
		}
	}

	return (0);
}

/*
 * Schedule a completion queue polling to reap the resource we're
 * short on.  If we implement the change to reap tx completions
 * in a separate thread, we'll need to wake up that thread here.
 */
static int
ibd_sched_poll(ibd_state_t *state, int resource_type, int q_flag)
{
	ibd_req_t *req;

	mutex_enter(&state->id_sched_lock);
	state->id_sched_needed |= resource_type;
	mutex_exit(&state->id_sched_lock);

	/*
	 * If we are asked to queue a work entry, we need to do it
	 */
	if (q_flag) {
		req = kmem_cache_alloc(state->id_req_kmc, KM_NOSLEEP);
		if (req == NULL)
			return (-1);

		ibd_queue_work_slot(state, req, IBD_ASYNC_SCHED);
	}

	return (0);
}

/*
 * The passed in packet has this format:
 * IPOIB_ADDRL b dest addr :: 2b sap :: 2b 0's :: data
 */
static boolean_t
ibd_send(ibd_state_t *state, mblk_t *mp)
{
	ibd_ace_t *ace;
	ibd_swqe_t *node;
	ipoib_mac_t *dest;
	ib_header_info_t *ipibp;
	ip6_t *ip6h;
	uint_t pktsize;
	uint32_t mss;
	uint32_t hckflags;
	uint32_t lsoflags = 0;
	uint_t lsohdr_sz = 0;
	int ret, len;
	boolean_t dofree = B_FALSE;
	boolean_t rc;
	/* if (rc_chan == NULL) send by UD; else send by RC; */
	ibd_rc_chan_t *rc_chan;
	int nmblks;
	mblk_t *nmp;

	/*
	 * If we aren't done with the device initialization and start,
	 * we shouldn't be here.
	 */
	if ((state->id_mac_state & IBD_DRV_STARTED) == 0)
		return (B_FALSE);

	/*
	 * Obtain an address handle for the destination.
	 */
	ipibp = (ib_header_info_t *)mp->b_rptr;
	dest = (ipoib_mac_t *)&ipibp->ib_dst;
	if ((ntohl(dest->ipoib_qpn) & IB_QPN_MASK) == IB_MC_QPN)
		IBD_FILL_SCOPE_PKEY(dest, state->id_scope, state->id_pkey);

	rc_chan = NULL;
	ace = ibd_acache_lookup(state, dest, &ret, 1);
	if (state->id_enable_rc && (ace != NULL) &&
	    (ace->ac_mac.ipoib_qpn != htonl(IB_MC_QPN))) {
		if (ace->ac_chan == NULL) {
			state->rc_null_conn++;
		} else {
			if (ace->ac_chan->chan_state ==
			    IBD_RC_STATE_ACT_ESTAB) {
				rc_chan = ace->ac_chan;
				rc_chan->is_used = B_TRUE;
				mutex_enter(&rc_chan->tx_wqe_list.dl_mutex);
				node = WQE_TO_SWQE(
				    rc_chan->tx_wqe_list.dl_head);
				if (node != NULL) {
					rc_chan->tx_wqe_list.dl_cnt -= 1;
					rc_chan->tx_wqe_list.dl_head =
					    node->swqe_next;
				} else {
					node = ibd_rc_acquire_swqes(rc_chan);
				}
				mutex_exit(&rc_chan->tx_wqe_list.dl_mutex);

				if (node == NULL) {
					state->rc_swqe_short++;
					mutex_enter(&state->id_sched_lock);
					state->id_sched_needed |=
					    IBD_RSRC_RC_SWQE;
					mutex_exit(&state->id_sched_lock);
					ibd_dec_ref_ace(state, ace);
					return (B_FALSE);
				}
			} else {
				state->rc_no_estab_conn++;
			}
		}
	}

	if (rc_chan == NULL) {
		mutex_enter(&state->id_tx_list.dl_mutex);
		node = WQE_TO_SWQE(state->id_tx_list.dl_head);
		if (node != NULL) {
			state->id_tx_list.dl_cnt -= 1;
			state->id_tx_list.dl_head = node->swqe_next;
		} else {
			node = ibd_acquire_swqe(state);
		}
		mutex_exit(&state->id_tx_list.dl_mutex);
		if (node == NULL) {
			/*
			 * If we don't have an swqe available, schedule a
			 * transmit completion queue cleanup and hold off on
			 * sending more packets until we have some free swqes
			 */
			if (ibd_sched_poll(state, IBD_RSRC_SWQE, 0) == 0) {
				if (ace != NULL) {
					ibd_dec_ref_ace(state, ace);
				}
				return (B_FALSE);
			}

			/*
			 * If a poll cannot be scheduled, we have no choice but
			 * to drop this packet
			 */
			ibd_print_warn(state, "ibd_send: no swqe, pkt drop");
			if (ace != NULL) {
				ibd_dec_ref_ace(state, ace);
			}
			return (B_TRUE);
		}
	}

	/*
	 * Initialize the commonly used fields in swqe to NULL to protect
	 * against ibd_tx_cleanup accidentally misinterpreting these on a
	 * failure.
	 */
	node->swqe_im_mblk = NULL;
	node->w_swr.wr_nds = 0;
	node->w_swr.wr_sgl = NULL;
	node->w_swr.wr_opcode = IBT_WRC_SEND;

	/*
	 * Calculate the size of message data and number of msg blocks
	 */
	pktsize = 0;
	for (nmblks = 0, nmp = mp; nmp != NULL;
	    nmp = nmp->b_cont, nmblks++) {
		pktsize += MBLKL(nmp);
	}

	if (bcmp(&ipibp->ib_dst, &state->id_bcaddr, IPOIB_ADDRL) == 0)
		atomic_inc_64(&state->id_brd_xmt);
	else if ((ntohl(ipibp->ib_dst.ipoib_qpn) & IB_QPN_MASK) == IB_MC_QPN)
		atomic_inc_64(&state->id_multi_xmt);

	if (ace != NULL) {
		node->w_ahandle = ace;
		node->w_swr.wr.ud.udwr_dest = ace->ac_dest;
	} else {
		DPRINT(5,
		    "ibd_send: acache lookup %s for %08X:%08X:%08X:%08X:%08X",
		    ((ret == EFAULT) ? "failed" : "queued"),
		    htonl(dest->ipoib_qpn), htonl(dest->ipoib_gidpref[0]),
		    htonl(dest->ipoib_gidpref[1]),
		    htonl(dest->ipoib_gidsuff[0]),
		    htonl(dest->ipoib_gidsuff[1]));
		state->rc_ace_not_found++;
		node->w_ahandle = NULL;

		/*
		 * Here if ibd_acache_lookup() returns EFAULT, it means ibd
		 * can not find a path for the specific dest address. We
		 * should get rid of this kind of packet.  We also should get
		 * rid of the packet if we cannot schedule a poll via the
		 * async thread.  For the normal case, ibd will return the
		 * packet to upper layer and wait for AH creating.
		 *
		 * Note that we always queue a work slot entry for the async
		 * thread when we fail AH lookup (even in intr mode); this is
		 * due to the convoluted way the code currently looks for AH.
		 */
		if (ret == EFAULT) {
			dofree = B_TRUE;
			rc = B_TRUE;
		} else if (ibd_sched_poll(state, IBD_RSRC_SWQE, 1) != 0) {
			dofree = B_TRUE;
			rc = B_TRUE;
		} else {
			dofree = B_FALSE;
			rc = B_FALSE;
		}
		goto ibd_send_fail;
	}

	/*
	 * For ND6 packets, padding is at the front of the source lladdr.
	 * Insert the padding at front.
	 */
	if (ntohs(ipibp->ipib_rhdr.ipoib_type) == ETHERTYPE_IPV6) {
		if (MBLKL(mp) < sizeof (ib_header_info_t) + IPV6_HDR_LEN) {
			if (!pullupmsg(mp, IPV6_HDR_LEN +
			    sizeof (ib_header_info_t))) {
				DPRINT(10, "ibd_send: pullupmsg failure ");
				dofree = B_TRUE;
				rc = B_TRUE;
				goto ibd_send_fail;
			}
			ipibp = (ib_header_info_t *)mp->b_rptr;
		}
		ip6h = (ip6_t *)((uchar_t *)ipibp +
		    sizeof (ib_header_info_t));
		len = ntohs(ip6h->ip6_plen);
		if (ip6h->ip6_nxt == IPPROTO_ICMPV6) {
			mblk_t	*pad;

			pad = allocb(4, 0);
			pad->b_wptr = (uchar_t *)pad->b_rptr + 4;
			linkb(mp, pad);
			if (MBLKL(mp) < sizeof (ib_header_info_t) +
			    IPV6_HDR_LEN + len + 4) {
				if (!pullupmsg(mp, sizeof (ib_header_info_t) +
				    IPV6_HDR_LEN + len + 4)) {
					DPRINT(10, "ibd_send: pullupmsg "
					    "failure ");
					dofree = B_TRUE;
					rc = B_TRUE;
					goto ibd_send_fail;
				}
				ip6h = (ip6_t *)((uchar_t *)mp->b_rptr +
				    sizeof (ib_header_info_t));
			}

			/* LINTED: E_CONSTANT_CONDITION */
			IBD_PAD_NSNA(ip6h, len, IBD_SEND);
		}
	}

	ASSERT(mp->b_wptr - mp->b_rptr >= sizeof (ib_addrs_t));
	mp->b_rptr += sizeof (ib_addrs_t);
	pktsize -= sizeof (ib_addrs_t);

	if (rc_chan) {	/* send in RC mode */
		ibt_iov_t iov_arr[IBD_MAX_SQSEG];
		ibt_iov_attr_t iov_attr;
		uint_t		i;
		size_t	blksize;
		uchar_t *bufp;
		ibd_rc_tx_largebuf_t *lbufp;

		atomic_add_64(&state->rc_xmt_bytes, pktsize);

		/*
		 * Upper layer does Tx checksum, we don't need do any
		 * checksum here.
		 */
		ASSERT(node->w_swr.wr_trans == IBT_RC_SRV);

		/*
		 * We only do ibt_map_mem_iov() if the pktsize is above
		 * the "copy-threshold", and if the number of mp
		 * fragments is less than the maximum acceptable.
		 */
		if (pktsize <= state->id_rc_tx_copy_thresh) {
			atomic_inc_64(&state->rc_xmt_small_pkt);
			/*
			 * Only process unicast packet in Reliable Connected
			 * mode.
			 */
			node->swqe_copybuf.ic_sgl.ds_len = pktsize;
			node->w_swr.wr_nds = 1;
			node->w_swr.wr_sgl = &node->swqe_copybuf.ic_sgl;
			node->w_buftype = IBD_WQE_TXBUF;

			bufp = (uchar_t *)(uintptr_t)node->w_swr.wr_sgl->ds_va;
			for (nmp = mp; nmp != NULL; nmp = nmp->b_cont) {
				blksize = MBLKL(nmp);
				bcopy(nmp->b_rptr, bufp, blksize);
				bufp += blksize;
			}
			freemsg(mp);
			ASSERT(node->swqe_im_mblk == NULL);
		} else {
			if ((state->rc_enable_iov_map) &&
			    (nmblks < state->rc_max_sqseg_hiwm)) {

				/* do ibt_map_mem_iov() */
				iov_attr.iov_as = NULL;
				iov_attr.iov = iov_arr;
				iov_attr.iov_buf = NULL;
				iov_attr.iov_wr_nds = state->rc_tx_max_sqseg;
				iov_attr.iov_lso_hdr_sz = 0;
				iov_attr.iov_flags = IBT_IOV_SLEEP;

				i = 0;
				for (nmp = mp; nmp != NULL; nmp = nmp->b_cont) {
					iov_arr[i].iov_len = MBLKL(nmp);
					if (iov_arr[i].iov_len != 0) {
						iov_arr[i].iov_addr = (caddr_t)
						    (void *)nmp->b_rptr;
						i++;
					}
				}
				iov_attr.iov_list_len = i;
				node->w_swr.wr_sgl = node->w_sgl;

				ret = ibt_map_mem_iov(state->id_hca_hdl,
				    &iov_attr, (ibt_all_wr_t *)&node->w_swr,
				    &node->w_mi_hdl);
				if (ret != IBT_SUCCESS) {
					atomic_inc_64(
					    &state->rc_xmt_map_fail_pkt);
					DPRINT(30, "ibd_send: ibt_map_mem_iov("
					    ") failed, nmblks=%d, real_nmblks"
					    "=%d, ret=0x%x", nmblks, i, ret);
					goto ibd_rc_large_copy;
				}

				atomic_inc_64(&state->rc_xmt_map_succ_pkt);
				node->w_buftype = IBD_WQE_MAPPED;
				node->swqe_im_mblk = mp;
			} else {
				atomic_inc_64(&state->rc_xmt_fragmented_pkt);
ibd_rc_large_copy:
				mutex_enter(&state->rc_tx_large_bufs_lock);
				if (state->rc_tx_largebuf_nfree == 0) {
					state->rc_xmt_buf_short++;
					mutex_exit
					    (&state->rc_tx_large_bufs_lock);
					mutex_enter(&state->id_sched_lock);
					state->id_sched_needed |=
					    IBD_RSRC_RC_TX_LARGEBUF;
					mutex_exit(&state->id_sched_lock);
					dofree = B_FALSE;
					rc = B_FALSE;
					/*
					 * If we don't have Tx large bufs,
					 * return failure. node->w_buftype
					 * should not be IBD_WQE_RC_COPYBUF,
					 * otherwise it will cause problem
					 * in ibd_rc_tx_cleanup()
					 */
					node->w_buftype = IBD_WQE_TXBUF;
					goto ibd_send_fail;
				}

				lbufp = state->rc_tx_largebuf_free_head;
				ASSERT(lbufp->lb_buf != NULL);
				state->rc_tx_largebuf_free_head =
				    lbufp->lb_next;
				lbufp->lb_next = NULL;
				/* Update nfree count */
				state->rc_tx_largebuf_nfree --;
				mutex_exit(&state->rc_tx_large_bufs_lock);
				bufp = lbufp->lb_buf;
				node->w_sgl[0].ds_va =
				    (ib_vaddr_t)(uintptr_t)bufp;
				node->w_sgl[0].ds_key =
				    state->rc_tx_mr_desc.md_lkey;
				node->w_sgl[0].ds_len = pktsize;
				node->w_swr.wr_sgl = node->w_sgl;
				node->w_swr.wr_nds = 1;
				node->w_buftype = IBD_WQE_RC_COPYBUF;
				node->w_rc_tx_largebuf = lbufp;

				for (nmp = mp; nmp != NULL; nmp = nmp->b_cont) {
					blksize = MBLKL(nmp);
					if (blksize != 0) {
						bcopy(nmp->b_rptr, bufp,
						    blksize);
						bufp += blksize;
					}
				}
				freemsg(mp);
				ASSERT(node->swqe_im_mblk == NULL);
			}
		}

		node->swqe_next = NULL;
		mutex_enter(&rc_chan->tx_post_lock);
		if (rc_chan->tx_busy) {
			if (rc_chan->tx_head) {
				rc_chan->tx_tail->swqe_next =
				    SWQE_TO_WQE(node);
			} else {
				rc_chan->tx_head = node;
			}
			rc_chan->tx_tail = node;
			mutex_exit(&rc_chan->tx_post_lock);
		} else {
			rc_chan->tx_busy = 1;
			mutex_exit(&rc_chan->tx_post_lock);
			ibd_rc_post_send(rc_chan, node);
		}

		return (B_TRUE);
	} /* send by RC */

	if ((state->id_enable_rc) && (pktsize > state->id_mtu)) {
		/*
		 * Too long pktsize. The packet size from GLD should <=
		 * state->id_mtu + sizeof (ib_addrs_t)
		 */
		if (ace->ac_mac.ipoib_qpn != htonl(IB_MC_QPN)) {
			ibd_req_t *req;

			mutex_enter(&ace->tx_too_big_mutex);
			if (ace->tx_too_big_ongoing) {
				mutex_exit(&ace->tx_too_big_mutex);
				state->rc_xmt_reenter_too_long_pkt++;
				dofree = B_TRUE;
			} else {
				ace->tx_too_big_ongoing = B_TRUE;
				mutex_exit(&ace->tx_too_big_mutex);
				state->rc_xmt_icmp_too_long_pkt++;

				req = kmem_cache_alloc(state->id_req_kmc,
				    KM_NOSLEEP);
				if (req == NULL) {
					ibd_print_warn(state, "ibd_send: alloc "
					    "ibd_req_t fail");
					/* Drop it. */
					dofree = B_TRUE;
				} else {
					req->rq_ptr = mp;
					req->rq_ptr2 = ace;
					ibd_queue_work_slot(state, req,
					    IBD_ASYNC_RC_TOO_BIG);
					dofree = B_FALSE;
				}
			}
		} else {
			ibd_print_warn(state, "Reliable Connected mode is on. "
			    "Multicast packet length %d > %d is too long to "
			    "send packet (%d > %d), drop it",
			    pktsize, state->id_mtu);
			state->rc_xmt_drop_too_long_pkt++;
			/* Drop it. */
			dofree = B_TRUE;
		}
		rc = B_TRUE;
		goto ibd_send_fail;
	}

	atomic_add_64(&state->id_xmt_bytes, pktsize);
	atomic_inc_64(&state->id_xmt_pkt);

	/*
	 * Do LSO and checksum related work here.  For LSO send, adjust the
	 * ud destination, the opcode and the LSO header information to the
	 * work request.
	 */
	mac_lso_get(mp, &mss, &lsoflags);
	if ((lsoflags & HW_LSO) != HW_LSO) {
		node->w_swr.wr_opcode = IBT_WRC_SEND;
		lsohdr_sz = 0;
	} else {
		if (ibd_setup_lso(node, mp, mss, ace->ac_dest) != 0) {
			/*
			 * The routine can only fail if there's no memory; we
			 * can only drop the packet if this happens
			 */
			ibd_print_warn(state,
			    "ibd_send: no memory, lso posting failed");
			dofree = B_TRUE;
			rc = B_TRUE;
			goto ibd_send_fail;
		}

		node->w_swr.wr_opcode = IBT_WRC_SEND_LSO;
		lsohdr_sz = (node->w_swr.wr.ud_lso).lso_hdr_sz;
	}

	mac_hcksum_get(mp, NULL, NULL, NULL, NULL, &hckflags);
	if ((hckflags & HCK_FULLCKSUM) == HCK_FULLCKSUM)
		node->w_swr.wr_flags |= IBT_WR_SEND_CKSUM;
	else
		node->w_swr.wr_flags &= ~IBT_WR_SEND_CKSUM;

	/*
	 * Prepare the sgl for posting; the routine can only fail if there's
	 * no lso buf available for posting. If this is the case, we should
	 * probably resched for lso bufs to become available and then try again.
	 */
	if (ibd_prepare_sgl(state, mp, node, lsohdr_sz) != 0) {
		if (ibd_sched_poll(state, IBD_RSRC_LSOBUF, 1) != 0) {
			dofree = B_TRUE;
			rc = B_TRUE;
		} else {
			dofree = B_FALSE;
			rc = B_FALSE;
		}
		goto ibd_send_fail;
	}
	node->swqe_im_mblk = mp;

	/*
	 * Queue the wqe to hardware; since we can now simply queue a
	 * post instead of doing it serially, we cannot assume anything
	 * about the 'node' after ibd_post_send() returns.
	 */
	node->swqe_next = NULL;

	mutex_enter(&state->id_txpost_lock);
	if (state->id_tx_busy) {
		if (state->id_tx_head) {
			state->id_tx_tail->swqe_next =
			    SWQE_TO_WQE(node);
		} else {
			state->id_tx_head = node;
		}
		state->id_tx_tail = node;
		mutex_exit(&state->id_txpost_lock);
	} else {
		state->id_tx_busy = 1;
		mutex_exit(&state->id_txpost_lock);
		ibd_post_send(state, node);
	}

	return (B_TRUE);

ibd_send_fail:
	if (node && mp)
		ibd_free_lsohdr(node, mp);

	if (dofree)
		freemsg(mp);

	if (node != NULL) {
		if (rc_chan) {
			ibd_rc_tx_cleanup(node);
		} else {
			ibd_tx_cleanup(state, node);
		}
	}

	return (rc);
}

/*
 * GLDv3 entry point for transmitting datagram.
 */
static mblk_t *
ibd_m_tx(void *arg, mblk_t *mp)
{
	ibd_state_t *state = (ibd_state_t *)arg;
	mblk_t *next;

	if (state->id_type == IBD_PORT_DRIVER) {
		freemsgchain(mp);
		return (NULL);
	}

	if ((state->id_link_state != LINK_STATE_UP) ||
	    !(state->id_mac_state & IBD_DRV_STARTED)) {
		freemsgchain(mp);
		mp = NULL;
	}

	while (mp != NULL) {
		next = mp->b_next;
		mp->b_next = NULL;
		if (ibd_send(state, mp) == B_FALSE) {
			/* Send fail */
			mp->b_next = next;
			break;
		}
		mp = next;
	}

	return (mp);
}

/*
 * this handles Tx and Rx completions. With separate CQs, this handles
 * only Rx completions.
 */
static uint_t
ibd_intr(caddr_t arg)
{
	ibd_state_t *state = (ibd_state_t *)arg;

	ibd_poll_rcq(state, state->id_rcq_hdl);

	return (DDI_INTR_CLAIMED);
}

/*
 * Poll and fully drain the send cq
 */
static void
ibd_drain_scq(ibd_state_t *state, ibt_cq_hdl_t cq_hdl)
{
	ibt_wc_t *wcs = state->id_txwcs;
	uint_t numwcs = state->id_txwcs_size;
	ibd_wqe_t *wqe;
	ibd_swqe_t *head, *tail;
	ibt_wc_t *wc;
	uint_t num_polled;
	int i;

	while (ibt_poll_cq(cq_hdl, wcs, numwcs, &num_polled) == IBT_SUCCESS) {
		head = tail = NULL;
		for (i = 0, wc = wcs; i < num_polled; i++, wc++) {
			wqe = (ibd_wqe_t *)(uintptr_t)wc->wc_id;
			if (wc->wc_status != IBT_WC_SUCCESS) {
				/*
				 * Channel being torn down.
				 */
				if (wc->wc_status == IBT_WC_WR_FLUSHED_ERR) {
					DPRINT(5, "ibd_drain_scq: flush error");
					DPRINT(10, "ibd_drain_scq: Bad "
					    "status %d", wc->wc_status);
				} else {
					DPRINT(10, "ibd_drain_scq: "
					    "unexpected wc_status %d",
					    wc->wc_status);
				}
				/*
				 * Fallthrough to invoke the Tx handler to
				 * release held resources, e.g., AH refcount.
				 */
			}
			/*
			 * Add this swqe to the list to be cleaned up.
			 */
			if (head)
				tail->swqe_next = wqe;
			else
				head = WQE_TO_SWQE(wqe);
			tail = WQE_TO_SWQE(wqe);
		}
		tail->swqe_next = NULL;
		ibd_tx_cleanup_list(state, head, tail);

		/*
		 * Resume any blocked transmissions if possible
		 */
		ibd_resume_transmission(state);
	}
}

/*
 * Poll and fully drain the receive cq
 */
static void
ibd_drain_rcq(ibd_state_t *state, ibt_cq_hdl_t cq_hdl)
{
	ibt_wc_t *wcs = state->id_rxwcs;
	uint_t numwcs = state->id_rxwcs_size;
	ibd_rwqe_t *rwqe;
	ibt_wc_t *wc;
	uint_t num_polled;
	int i;
	mblk_t *head, *tail, *mp;

	while (ibt_poll_cq(cq_hdl, wcs, numwcs, &num_polled) == IBT_SUCCESS) {
		head = tail = NULL;
		for (i = 0, wc = wcs; i < num_polled; i++, wc++) {
			rwqe = (ibd_rwqe_t *)(uintptr_t)wc->wc_id;
			if (wc->wc_status != IBT_WC_SUCCESS) {
				/*
				 * Channel being torn down.
				 */
				if (wc->wc_status == IBT_WC_WR_FLUSHED_ERR) {
					DPRINT(5, "ibd_drain_rcq: "
					    "expected flushed rwqe");
				} else {
					DPRINT(5, "ibd_drain_rcq: "
					    "unexpected wc_status %d",
					    wc->wc_status);
				}
				atomic_inc_32(
				    &state->id_rx_list.dl_bufs_outstanding);
				freemsg(rwqe->rwqe_im_mblk);
				continue;
			}
			mp = ibd_process_rx(state, rwqe, wc);
			if (mp == NULL)
				continue;

			/*
			 * Add this mp to the list to send to the nw layer.
			 */
			if (head)
				tail->b_next = mp;
			else
				head = mp;
			tail = mp;
		}
		if (head)
			mac_rx(state->id_mh, state->id_rh, head);

		/*
		 * Account for #rwqes polled.
		 * Post more here, if less than one fourth full.
		 */
		if (atomic_add_32_nv(&state->id_rx_list.dl_cnt, -num_polled) <
		    (state->id_ud_num_rwqe / 4))
			ibd_post_recv_intr(state);
	}
}

/*
 * Common code for interrupt handling as well as for polling
 * for all completed wqe's while detaching.
 */
static void
ibd_poll_scq(ibd_state_t *state, ibt_cq_hdl_t cq_hdl)
{
	int flag, redo_flag;
	int redo = 1;

	flag = IBD_CQ_POLLING;
	redo_flag = IBD_REDO_CQ_POLLING;

	mutex_enter(&state->id_scq_poll_lock);
	if (state->id_scq_poll_busy & flag) {
		ibd_print_warn(state, "ibd_poll_scq: multiple polling threads");
		state->id_scq_poll_busy |= redo_flag;
		mutex_exit(&state->id_scq_poll_lock);
		return;
	}
	state->id_scq_poll_busy |= flag;
	mutex_exit(&state->id_scq_poll_lock);

	/*
	 * In some cases (eg detaching), this code can be invoked on
	 * any cpu after disabling cq notification (thus no concurrency
	 * exists). Apart from that, the following applies normally:
	 * Transmit completion handling could be from any cpu if
	 * Tx CQ is poll driven, but always on Tx interrupt cpu if Tx CQ
	 * is interrupt driven.
	 */

	/*
	 * Poll and drain the CQ
	 */
	ibd_drain_scq(state, cq_hdl);

	/*
	 * Enable CQ notifications and redrain the cq to catch any
	 * completions we might have missed after the ibd_drain_scq()
	 * above and before the ibt_enable_cq_notify() that follows.
	 * Finally, service any new requests to poll the cq that
	 * could've come in after the ibt_enable_cq_notify().
	 */
	do {
		if (ibt_enable_cq_notify(cq_hdl, IBT_NEXT_COMPLETION) !=
		    IBT_SUCCESS) {
			DPRINT(10, "ibd_intr: ibt_enable_cq_notify() failed");
		}

		ibd_drain_scq(state, cq_hdl);

		mutex_enter(&state->id_scq_poll_lock);
		if (state->id_scq_poll_busy & redo_flag)
			state->id_scq_poll_busy &= ~redo_flag;
		else {
			state->id_scq_poll_busy &= ~flag;
			redo = 0;
		}
		mutex_exit(&state->id_scq_poll_lock);

	} while (redo);
}

/*
 * Common code for interrupt handling as well as for polling
 * for all completed wqe's while detaching.
 */
static void
ibd_poll_rcq(ibd_state_t *state, ibt_cq_hdl_t rcq)
{
	int flag, redo_flag;
	int redo = 1;

	flag = IBD_CQ_POLLING;
	redo_flag = IBD_REDO_CQ_POLLING;

	mutex_enter(&state->id_rcq_poll_lock);
	if (state->id_rcq_poll_busy & flag) {
		ibd_print_warn(state, "ibd_poll_rcq: multiple polling threads");
		state->id_rcq_poll_busy |= redo_flag;
		mutex_exit(&state->id_rcq_poll_lock);
		return;
	}
	state->id_rcq_poll_busy |= flag;
	mutex_exit(&state->id_rcq_poll_lock);

	/*
	 * Poll and drain the CQ
	 */
	ibd_drain_rcq(state, rcq);

	/*
	 * Enable CQ notifications and redrain the cq to catch any
	 * completions we might have missed after the ibd_drain_cq()
	 * above and before the ibt_enable_cq_notify() that follows.
	 * Finally, service any new requests to poll the cq that
	 * could've come in after the ibt_enable_cq_notify().
	 */
	do {
		if (ibt_enable_cq_notify(rcq, IBT_NEXT_COMPLETION) !=
		    IBT_SUCCESS) {
			DPRINT(10, "ibd_intr: ibt_enable_cq_notify() failed");
		}

		ibd_drain_rcq(state, rcq);

		mutex_enter(&state->id_rcq_poll_lock);
		if (state->id_rcq_poll_busy & redo_flag)
			state->id_rcq_poll_busy &= ~redo_flag;
		else {
			state->id_rcq_poll_busy &= ~flag;
			redo = 0;
		}
		mutex_exit(&state->id_rcq_poll_lock);

	} while (redo);
}

/*
 * Unmap the memory area associated with a given swqe.
 */
void
ibd_unmap_mem(ibd_state_t *state, ibd_swqe_t *swqe)
{
	ibt_status_t stat;

	DPRINT(20, "ibd_unmap_mem: wqe=%p, seg=%d\n", swqe, swqe->w_swr.wr_nds);

	if (swqe->w_mi_hdl) {
		if ((stat = ibt_unmap_mem_iov(state->id_hca_hdl,
		    swqe->w_mi_hdl)) != IBT_SUCCESS) {
			DPRINT(10,
			    "failed in ibt_unmap_mem_iov, ret=%d\n", stat);
		}
		swqe->w_mi_hdl = NULL;
	}
	swqe->w_swr.wr_nds = 0;
}

void
ibd_dec_ref_ace(ibd_state_t *state, ibd_ace_t *ace)
{
	/*
	 * The recycling logic can be eliminated from here
	 * and put into the async thread if we create another
	 * list to hold ACE's for unjoined mcg's.
	 */
	if (DEC_REF_DO_CYCLE(ace)) {
		ibd_mce_t *mce;

		/*
		 * Check with the lock taken: we decremented
		 * reference count without the lock, and some
		 * transmitter might already have bumped the
		 * reference count (possible in case of multicast
		 * disable when we leave the AH on the active
		 * list). If not still 0, get out, leaving the
		 * recycle bit intact.
		 *
		 * Atomically transition the AH from active
		 * to free list, and queue a work request to
		 * leave the group and destroy the mce. No
		 * transmitter can be looking at the AH or
		 * the MCE in between, since we have the
		 * ac_mutex lock. In the SendOnly reap case,
		 * it is not necessary to hold the ac_mutex
		 * and recheck the ref count (since the AH was
		 * taken off the active list), we just do it
		 * to have uniform processing with the Full
		 * reap case.
		 */
		mutex_enter(&state->id_ac_mutex);
		mce = ace->ac_mce;
		if (GET_REF_CYCLE(ace) == 0) {
			CLEAR_REFCYCLE(ace);
			/*
			 * Identify the case of fullmember reap as
			 * opposed to mcg trap reap. Also, port up
			 * might set ac_mce to NULL to indicate Tx
			 * cleanup should do no more than put the
			 * AH in the free list (see ibd_async_link).
			 */
			if (mce != NULL) {
				ace->ac_mce = NULL;
				IBD_ACACHE_PULLOUT_ACTIVE(state, ace);
				/*
				 * mc_req was initialized at mce
				 * creation time.
				 */
				ibd_queue_work_slot(state,
				    &mce->mc_req, IBD_ASYNC_REAP);
			}
			IBD_ACACHE_INSERT_FREE(state, ace);
		}
		mutex_exit(&state->id_ac_mutex);
	}
}

/*
 * Common code that deals with clean ups after a successful or
 * erroneous transmission attempt.
 */
static void
ibd_tx_cleanup(ibd_state_t *state, ibd_swqe_t *swqe)
{
	ibd_ace_t *ace = swqe->w_ahandle;

	DPRINT(20, "ibd_tx_cleanup %p\n", swqe);

	/*
	 * If this was a dynamic mapping in ibd_send(), we need to
	 * unmap here. If this was an lso buffer we'd used for sending,
	 * we need to release the lso buf to the pool, since the resource
	 * is scarce. However, if this was simply a normal send using
	 * the copybuf (present in each swqe), we don't need to release it.
	 */
	if (swqe->swqe_im_mblk != NULL) {
		if (swqe->w_buftype == IBD_WQE_MAPPED) {
			ibd_unmap_mem(state, swqe);
		} else if (swqe->w_buftype == IBD_WQE_LSOBUF) {
			ibd_release_lsobufs(state,
			    swqe->w_swr.wr_sgl, swqe->w_swr.wr_nds);
		}
		ibd_free_lsohdr(swqe, swqe->swqe_im_mblk);
		freemsg(swqe->swqe_im_mblk);
		swqe->swqe_im_mblk = NULL;
	}

	/*
	 * Drop the reference count on the AH; it can be reused
	 * now for a different destination if there are no more
	 * posted sends that will use it. This can be eliminated
	 * if we can always associate each Tx buffer with an AH.
	 * The ace can be null if we are cleaning up from the
	 * ibd_send() error path.
	 */
	if (ace != NULL) {
		ibd_dec_ref_ace(state, ace);
	}

	/*
	 * Release the send wqe for reuse.
	 */
	swqe->swqe_next = NULL;
	ibd_release_swqe(state, swqe, swqe, 1);
}

static void
ibd_tx_cleanup_list(ibd_state_t *state, ibd_swqe_t *head, ibd_swqe_t *tail)
{
	ibd_ace_t *ace;
	ibd_swqe_t *swqe;
	int n = 0;

	DPRINT(20, "ibd_tx_cleanup_list %p %p\n", head, tail);

	for (swqe = head; swqe != NULL; swqe = WQE_TO_SWQE(swqe->swqe_next)) {

		/*
		 * If this was a dynamic mapping in ibd_send(), we need to
		 * unmap here. If this was an lso buffer we'd used for sending,
		 * we need to release the lso buf to the pool, since the
		 * resource is scarce. However, if this was simply a normal
		 * send using the copybuf (present in each swqe), we don't need
		 * to release it.
		 */
		if (swqe->swqe_im_mblk != NULL) {
			if (swqe->w_buftype == IBD_WQE_MAPPED) {
				ibd_unmap_mem(state, swqe);
			} else if (swqe->w_buftype == IBD_WQE_LSOBUF) {
				ibd_release_lsobufs(state,
				    swqe->w_swr.wr_sgl, swqe->w_swr.wr_nds);
			}
			ibd_free_lsohdr(swqe, swqe->swqe_im_mblk);
			freemsg(swqe->swqe_im_mblk);
			swqe->swqe_im_mblk = NULL;
		}

		/*
		 * Drop the reference count on the AH; it can be reused
		 * now for a different destination if there are no more
		 * posted sends that will use it. This can be eliminated
		 * if we can always associate each Tx buffer with an AH.
		 * The ace can be null if we are cleaning up from the
		 * ibd_send() error path.
		 */
		ace = swqe->w_ahandle;
		if (ace != NULL) {
			ibd_dec_ref_ace(state, ace);
		}
		n++;
	}

	/*
	 * Release the send wqes for reuse.
	 */
	ibd_release_swqe(state, head, tail, n);
}

/*
 * Processing to be done after receipt of a packet; hand off to GLD
 * in the format expected by GLD.  The received packet has this
 * format: 2b sap :: 00 :: data.
 */
static mblk_t *
ibd_process_rx(ibd_state_t *state, ibd_rwqe_t *rwqe, ibt_wc_t *wc)
{
	ib_header_info_t *phdr;
	mblk_t *mp;
	ipoib_hdr_t *ipibp;
	ipha_t *iphap;
	ip6_t *ip6h;
	int len;
	ib_msglen_t pkt_len = wc->wc_bytes_xfer;
	uint32_t bufs;

	/*
	 * Track number handed to upper layer that need to be returned.
	 */
	bufs = atomic_inc_32_nv(&state->id_rx_list.dl_bufs_outstanding);

	/* Never run out of rwqes, use allocb when running low */
	if (bufs >= state->id_rx_bufs_outstanding_limit) {
		atomic_dec_32(&state->id_rx_list.dl_bufs_outstanding);
		atomic_inc_32(&state->id_rx_allocb);
		mp = allocb(pkt_len, BPRI_HI);
		if (mp) {
			bcopy(rwqe->rwqe_im_mblk->b_rptr, mp->b_rptr, pkt_len);
			ibd_post_recv(state, rwqe);
		} else {	/* no memory */
			atomic_inc_32(&state->id_rx_allocb_failed);
			ibd_post_recv(state, rwqe);
			return (NULL);
		}
	} else {
		mp = rwqe->rwqe_im_mblk;
	}


	/*
	 * Adjust write pointer depending on how much data came in.
	 */
	mp->b_wptr = mp->b_rptr + pkt_len;

	/*
	 * Make sure this is NULL or we're in trouble.
	 */
	if (mp->b_next != NULL) {
		ibd_print_warn(state,
		    "ibd_process_rx: got duplicate mp from rcq?");
		mp->b_next = NULL;
	}

	/*
	 * the IB link will deliver one of the IB link layer
	 * headers called, the Global Routing Header (GRH).
	 * ibd driver uses the information in GRH to build the
	 * Header_info structure and pass it with the datagram up
	 * to GLDv3.
	 * If the GRH is not valid, indicate to GLDv3 by setting
	 * the VerTcFlow field to 0.
	 */
	phdr = (ib_header_info_t *)mp->b_rptr;
	if (wc->wc_flags & IBT_WC_GRH_PRESENT) {
		phdr->ib_grh.ipoib_sqpn = htonl(wc->wc_qpn);

		/* if it is loop back packet, just drop it. */
		if (state->id_enable_rc) {
			if (bcmp(&phdr->ib_grh.ipoib_sqpn,
			    &state->rc_macaddr_loopback,
			    IPOIB_ADDRL) == 0) {
				freemsg(mp);
				return (NULL);
			}
		} else {
			if (bcmp(&phdr->ib_grh.ipoib_sqpn, &state->id_macaddr,
			    IPOIB_ADDRL) == 0) {
				freemsg(mp);
				return (NULL);
			}
		}

		ovbcopy(&phdr->ib_grh.ipoib_sqpn, &phdr->ib_src,
		    sizeof (ipoib_mac_t));
		if (*(uint8_t *)(phdr->ib_grh.ipoib_dgid_pref) == 0xFF) {
			phdr->ib_dst.ipoib_qpn = htonl(IB_MC_QPN);
			IBD_CLEAR_SCOPE_PKEY(&phdr->ib_dst);
		} else {
			phdr->ib_dst.ipoib_qpn = state->id_macaddr.ipoib_qpn;
		}
	} else {
		/*
		 * It can not be a IBA multicast packet. Must have been
		 * unicast for us. Just copy the interface address to dst.
		 */
		phdr->ib_grh.ipoib_vertcflow = 0;
		ovbcopy(&state->id_macaddr, &phdr->ib_dst,
		    sizeof (ipoib_mac_t));
	}

	/*
	 * For ND6 packets, padding is at the front of the source/target
	 * lladdr. However the inet6 layer is not aware of it, hence remove
	 * the padding from such packets.
	 */
	ipibp = (ipoib_hdr_t *)((uchar_t *)mp->b_rptr + sizeof (ipoib_pgrh_t));
	if (ntohs(ipibp->ipoib_type) == ETHERTYPE_IPV6) {
		ip6h = (ip6_t *)((uchar_t *)ipibp + sizeof (ipoib_hdr_t));
		len = ntohs(ip6h->ip6_plen);
		if (ip6h->ip6_nxt == IPPROTO_ICMPV6) {
			/* LINTED: E_CONSTANT_CONDITION */
			IBD_PAD_NSNA(ip6h, len, IBD_RECV);
		}
	}

	/*
	 * Update statistics
	 */
	atomic_add_64(&state->id_rcv_bytes, pkt_len);
	atomic_inc_64(&state->id_rcv_pkt);
	if (bcmp(&phdr->ib_dst, &state->id_bcaddr, IPOIB_ADDRL) == 0)
		atomic_inc_64(&state->id_brd_rcv);
	else if ((ntohl(phdr->ib_dst.ipoib_qpn) & IB_QPN_MASK) == IB_MC_QPN)
		atomic_inc_64(&state->id_multi_rcv);

	iphap = (ipha_t *)((uchar_t *)ipibp + sizeof (ipoib_hdr_t));
	/*
	 * Set receive checksum status in mp
	 * Hardware checksumming can be considered valid only if:
	 * 1. CQE.IP_OK bit is set
	 * 2. CQE.CKSUM = 0xffff
	 * 3. IPv6 routing header is not present in the packet
	 * 4. If there are no IP_OPTIONS in the IP HEADER
	 */

	if (((wc->wc_flags & IBT_WC_CKSUM_OK) == IBT_WC_CKSUM_OK) &&
	    (wc->wc_cksum == 0xFFFF) &&
	    (iphap->ipha_version_and_hdr_length == IP_SIMPLE_HDR_VERSION)) {
		mac_hcksum_set(mp, 0, 0, 0, 0, HCK_FULLCKSUM_OK);
	}

	return (mp);
}

/*
 * Callback code invoked from STREAMs when the receive data buffer is
 * free for recycling.
 */
static void
ibd_freemsg_cb(char *arg)
{
	ibd_rwqe_t *rwqe = (ibd_rwqe_t *)arg;
	ibd_state_t *state = rwqe->w_state;

	atomic_dec_32(&state->id_rx_list.dl_bufs_outstanding);

	/*
	 * If the driver is stopped, just free the rwqe.
	 */
	if (atomic_add_32_nv(&state->id_running, 0) == 0) {
		DPRINT(6, "ibd_freemsg: wqe being freed");
		rwqe->rwqe_im_mblk = NULL;
		ibd_free_rwqe(state, rwqe);
		return;
	}

	rwqe->rwqe_im_mblk = desballoc(rwqe->rwqe_copybuf.ic_bufaddr,
	    state->id_mtu + IPOIB_GRH_SIZE, 0, &rwqe->w_freemsg_cb);
	if (rwqe->rwqe_im_mblk == NULL) {
		ibd_free_rwqe(state, rwqe);
		DPRINT(6, "ibd_freemsg: desballoc failed");
		return;
	}

	ibd_post_recv(state, rwqe);
}

static uint_t
ibd_tx_recycle(caddr_t arg)
{
	ibd_state_t *state = (ibd_state_t *)arg;

	/*
	 * Poll for completed entries
	 */
	ibd_poll_scq(state, state->id_scq_hdl);

	return (DDI_INTR_CLAIMED);
}

#ifdef IBD_LOGGING
static void
ibd_log_init(void)
{
	ibd_lbuf = kmem_zalloc(IBD_LOG_SZ, KM_SLEEP);
	ibd_lbuf_ndx = 0;

	mutex_init(&ibd_lbuf_lock, NULL, MUTEX_DRIVER, NULL);
}

static void
ibd_log_fini(void)
{
	if (ibd_lbuf)
		kmem_free(ibd_lbuf, IBD_LOG_SZ);
	ibd_lbuf_ndx = 0;
	ibd_lbuf = NULL;

	mutex_destroy(&ibd_lbuf_lock);
}

static void
ibd_log(const char *fmt, ...)
{
	va_list	ap;
	uint32_t off;
	uint32_t msglen;
	char tmpbuf[IBD_DMAX_LINE];

	if (ibd_lbuf == NULL)
		return;

	va_start(ap, fmt);
	msglen = vsnprintf(tmpbuf, IBD_DMAX_LINE, fmt, ap);
	va_end(ap);

	if (msglen >= IBD_DMAX_LINE)
		msglen = IBD_DMAX_LINE - 1;

	mutex_enter(&ibd_lbuf_lock);

	off = ibd_lbuf_ndx;		/* current msg should go here */
	if ((ibd_lbuf_ndx) && (ibd_lbuf[ibd_lbuf_ndx-1] != '\n'))
		ibd_lbuf[ibd_lbuf_ndx-1] = '\n';

	ibd_lbuf_ndx += msglen;		/* place where next msg should start */
	ibd_lbuf[ibd_lbuf_ndx] = 0;	/* current msg should terminate */

	if (ibd_lbuf_ndx >= (IBD_LOG_SZ - 2 * IBD_DMAX_LINE))
		ibd_lbuf_ndx = 0;

	mutex_exit(&ibd_lbuf_lock);

	bcopy(tmpbuf, ibd_lbuf+off, msglen);	/* no lock needed for this */
}
#endif

/* ARGSUSED */
static int
ibd_create_partition(void *karg, intptr_t arg, int mode, cred_t *credp,
    int *rvalp)
{
	ibd_create_ioctl_t	*cmd = karg;
	ibd_state_t		*state, *port_state, *p;
	int			i, err, rval = 0;
	mac_register_t		*macp;
	ibt_hca_portinfo_t 	*pinfop = NULL;
	ibt_status_t 		ibt_status;
	uint_t 			psize, pinfosz;
	boolean_t		force_create = B_FALSE;

	cmd->ibdioc.ioc_status = 0;

	if (cmd->ibdioc.ioc_port_inst < 0) {
		cmd->ibdioc.ioc_status = IBD_INVALID_PORT_INST;
		return (EINVAL);
	}
	port_state = ddi_get_soft_state(ibd_list, cmd->ibdioc.ioc_port_inst);
	if (port_state == NULL) {
		DPRINT(10, "ibd_create_partition: failed to get state %d",
		    cmd->ibdioc.ioc_port_inst);
		cmd->ibdioc.ioc_status = IBD_INVALID_PORT_INST;
		return (EINVAL);
	}

	/* Limited PKeys not supported */
	if (cmd->ioc_pkey <= IB_PKEY_INVALID_FULL) {
		rval = EINVAL;
		goto part_create_return;
	}

	if (cmd->ioc_force_create == 0) {
		/*
		 * Check if the port pkey table contains the pkey for which
		 * this partition is being created.
		 */
		ibt_status = ibt_query_hca_ports(port_state->id_hca_hdl,
		    port_state->id_port, &pinfop, &psize, &pinfosz);

		if ((ibt_status != IBT_SUCCESS) || (psize != 1)) {
			rval = EINVAL;
			goto part_create_return;
		}

		if (pinfop->p_linkstate != IBT_PORT_ACTIVE) {
			rval = ENETDOWN;
			cmd->ibdioc.ioc_status = IBD_PORT_IS_DOWN;
			goto part_create_return;
		}

		for (i = 0; i < pinfop->p_pkey_tbl_sz; i++) {
			if (pinfop->p_pkey_tbl[i] == cmd->ioc_pkey) {
				break;
			}
		}
		if (i == pinfop->p_pkey_tbl_sz) {
			rval = EINVAL;
			cmd->ibdioc.ioc_status = IBD_PKEY_NOT_PRESENT;
			goto part_create_return;
		}
	} else {
		force_create = B_TRUE;
	}

	mutex_enter(&ibd_objlist_lock);
	for (p = ibd_objlist_head; p; p = p->id_next) {
		if ((p->id_port_inst == cmd->ibdioc.ioc_port_inst) &&
		    (p->id_pkey == cmd->ioc_pkey) &&
		    (p->id_plinkid == cmd->ioc_partid)) {
			mutex_exit(&ibd_objlist_lock);
			rval = EEXIST;
			cmd->ibdioc.ioc_status = IBD_PARTITION_EXISTS;
			goto part_create_return;
		}
	}
	mutex_exit(&ibd_objlist_lock);

	state = kmem_zalloc(sizeof (ibd_state_t), KM_SLEEP);

	state->id_type		= IBD_PARTITION_OBJ;

	state->id_plinkid	= cmd->ioc_partid;
	state->id_dlinkid	= cmd->ibdioc.ioc_linkid;
	state->id_port_inst	= cmd->ibdioc.ioc_port_inst;

	state->id_dip		= port_state->id_dip;
	state->id_port		= port_state->id_port;
	state->id_pkey		= cmd->ioc_pkey;
	state->id_hca_guid	= port_state->id_hca_guid;
	state->id_port_guid	= port_state->id_port_guid;
	state->id_force_create	= force_create;

	mutex_init(&state->id_macst_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&state->id_macst_cv, NULL, CV_DEFAULT, NULL);

	if (ibd_part_attach(state, state->id_dip) != DDI_SUCCESS) {
		rval = EIO;
		cmd->ibdioc.ioc_status = IBD_NO_HW_RESOURCE;
		goto fail;
	}

	if ((macp = mac_alloc(MAC_VERSION)) == NULL) {
		rval = EAGAIN;
		goto fail;
	}

	macp->m_type_ident	= MAC_PLUGIN_IDENT_IB;
	macp->m_dip		= port_state->id_dip;
	macp->m_instance	= (uint_t)-1;
	macp->m_driver		= state;
	macp->m_src_addr	= (uint8_t *)&state->id_macaddr;
	macp->m_callbacks	= &ibd_m_callbacks;
	macp->m_min_sdu		= 0;
	macp->m_multicast_sdu	= IBD_DEF_MAX_SDU;
	if (state->id_enable_rc) {
		macp->m_max_sdu		= IBD_DEF_RC_MAX_SDU;
	} else {
		macp->m_max_sdu		= IBD_DEF_MAX_SDU;
	}
	macp->m_priv_props = ibd_priv_props;

	err = mac_register(macp, &state->id_mh);
	mac_free(macp);

	if (err != 0) {
		DPRINT(10, "ibd_create_partition: mac_register() failed %d",
		    err);
		rval = err;
		goto fail;
	}

	err = dls_devnet_create(state->id_mh,
	    cmd->ioc_partid, crgetzoneid(credp));
	if (err != 0) {
		DPRINT(10, "ibd_create_partition: dls_devnet_create() failed "
		    "%d", err);
		rval = err;
		(void) mac_unregister(state->id_mh);
		goto fail;
	}

	/*
	 * Add the new partition state structure to the list
	 */
	mutex_enter(&ibd_objlist_lock);
	if (ibd_objlist_head)
		state->id_next = ibd_objlist_head;

	ibd_objlist_head = state;
	mutex_exit(&ibd_objlist_lock);

part_create_return:
	if (pinfop) {
		ibt_free_portinfo(pinfop, pinfosz);
	}
	return (rval);

fail:
	if (pinfop) {
		ibt_free_portinfo(pinfop, pinfosz);
	}
	ibd_part_unattach(state);
	kmem_free(state, sizeof (ibd_state_t));
	return (rval);
}

/* ARGSUSED */
static int
ibd_delete_partition(void *karg, intptr_t arg, int mode, cred_t *credp,
    int *rvalp)
{
	int err;
	datalink_id_t tmpid;
	ibd_state_t *node, *prev;
	ibd_delete_ioctl_t *cmd = karg;

	prev = NULL;

	mutex_enter(&ibd_objlist_lock);
	node = ibd_objlist_head;

	/* Find the ibd state structure corresponding to the partition */
	while (node != NULL) {
		if (node->id_plinkid == cmd->ioc_partid)
			break;
		prev = node;
		node = node->id_next;
	}

	if (node == NULL) {
		mutex_exit(&ibd_objlist_lock);
		return (ENOENT);
	}

	if ((err = dls_devnet_destroy(node->id_mh, &tmpid, B_TRUE)) != 0) {
		DPRINT(10, "ibd_delete_partition: dls_devnet_destroy() failed "
		    "%d", err);
		mutex_exit(&ibd_objlist_lock);
		return (err);
	}

	/*
	 * Call ibd_part_unattach() only after making sure that the instance has
	 * not been started yet and is also not in late hca init mode.
	 */
	ibd_set_mac_progress(node, IBD_DRV_DELETE_IN_PROGRESS);

	err = 0;
	if ((node->id_mac_state & IBD_DRV_STARTED) ||
	    (node->id_mac_state & IBD_DRV_IN_LATE_HCA_INIT) ||
	    (ibd_part_busy(node) != DDI_SUCCESS) ||
	    ((err = mac_disable(node->id_mh)) != 0)) {
		(void) dls_devnet_create(node->id_mh, cmd->ioc_partid,
		    crgetzoneid(credp));
		ibd_clr_mac_progress(node, IBD_DRV_DELETE_IN_PROGRESS);
		mutex_exit(&ibd_objlist_lock);
		return (err != 0 ? err : EBUSY);
	}

	node->id_mac_state |= IBD_DRV_IN_DELETION;

	ibd_part_unattach(node);

	ibd_clr_mac_progress(node, IBD_DRV_DELETE_IN_PROGRESS);

	/* Remove the partition state structure from the linked list */
	if (prev == NULL)
		ibd_objlist_head = node->id_next;
	else
		prev->id_next = node->id_next;
	mutex_exit(&ibd_objlist_lock);

	if ((err = mac_unregister(node->id_mh)) != 0) {
		DPRINT(10, "ibd_delete_partition: mac_unregister() failed %d",
		    err);
	}

	cv_destroy(&node->id_macst_cv);
	mutex_destroy(&node->id_macst_lock);

	kmem_free(node, sizeof (ibd_state_t));

	return (0);
}

/* ARGSUSED */
static int
ibd_get_partition_info(void *karg, intptr_t arg, int mode, cred_t *cred,
    int *rvalp)
{
	ibd_ioctl_t		cmd;
	ibpart_ioctl_t		partioc;
	ibport_ioctl_t		portioc;
#ifdef _MULTI_DATAMODEL
	ibport_ioctl32_t	portioc32;
#endif
	ibd_state_t		*state, *port_state;
	int			size;
	ibt_hca_portinfo_t 	*pinfop = NULL;
	ibt_status_t 		ibt_status;
	uint_t 			psize, pinfosz;
	int			rval = 0;

	size = sizeof (ibd_ioctl_t);
	if (ddi_copyin((void *)arg, &cmd, size, mode)) {
		return (EFAULT);
	}
	cmd.ioc_status = 0;
	switch (cmd.ioc_info_cmd) {
	case IBD_INFO_CMD_IBPART:
		size = sizeof (ibpart_ioctl_t);
		if (ddi_copyin((void *)arg, &partioc, size, mode)) {
			return (EFAULT);
		}

		mutex_enter(&ibd_objlist_lock);
		/* Find the ibd state structure corresponding the partition */
		for (state = ibd_objlist_head; state; state = state->id_next) {
			if (state->id_plinkid == cmd.ioc_linkid) {
				break;
			}
		}

		if (state == NULL) {
			mutex_exit(&ibd_objlist_lock);
			return (ENOENT);
		}

		partioc.ibdioc.ioc_linkid = state->id_dlinkid;
		partioc.ibdioc.ioc_port_inst = state->id_port_inst;
		partioc.ibdioc.ioc_portnum = state->id_port;
		partioc.ibdioc.ioc_hcaguid = state->id_hca_guid;
		partioc.ibdioc.ioc_portguid = state->id_port_guid;
		partioc.ibdioc.ioc_status = 0;
		partioc.ioc_partid = state->id_plinkid;
		partioc.ioc_pkey = state->id_pkey;
		partioc.ioc_force_create = state->id_force_create;
		if (ddi_copyout((void *)&partioc, (void *)arg, size, mode)) {
			mutex_exit(&ibd_objlist_lock);
			return (EFAULT);
		}
		mutex_exit(&ibd_objlist_lock);

		break;

	case IBD_INFO_CMD_IBPORT:
		if ((cmd.ioc_port_inst < 0) || ((port_state =
		    ddi_get_soft_state(ibd_list, cmd.ioc_port_inst)) == NULL)) {
			DPRINT(10, "ibd_create_partition: failed to get"
			    " state %d", cmd.ioc_port_inst);
			size = sizeof (ibd_ioctl_t);
			cmd.ioc_status = IBD_INVALID_PORT_INST;
			if (ddi_copyout((void *)&cmd, (void *)arg, size,
			    mode)) {
				return (EFAULT);
			}
			return (EINVAL);
		}
		ibt_status = ibt_query_hca_ports(port_state->id_hca_hdl,
		    port_state->id_port, &pinfop, &psize, &pinfosz);
		if ((ibt_status != IBT_SUCCESS) || (psize != 1)) {
			return (EINVAL);
		}
#ifdef _MULTI_DATAMODEL
		switch (ddi_model_convert_from(mode & FMODELS)) {
		case DDI_MODEL_ILP32: {
			size = sizeof (ibport_ioctl32_t);
			if (ddi_copyin((void *)arg, &portioc32, size, mode)) {
				rval = EFAULT;
				goto fail;
			}
			portioc32.ibdioc.ioc_status = 0;
			portioc32.ibdioc.ioc_portnum = port_state->id_port;
			portioc32.ibdioc.ioc_hcaguid =
			    port_state->id_hca_guid;
			portioc32.ibdioc.ioc_portguid =
			    port_state->id_port_guid;
			if (portioc32.ioc_pkey_tbl_sz !=
			    pinfop->p_pkey_tbl_sz) {
				rval = EINVAL;
				size = sizeof (ibd_ioctl_t);
				portioc32.ibdioc.ioc_status =
				    IBD_INVALID_PKEY_TBL_SIZE;
				if (ddi_copyout((void *)&portioc32.ibdioc,
				    (void *)arg, size, mode)) {
					rval = EFAULT;
					goto fail;
				}
				goto fail;
			}
			size = pinfop->p_pkey_tbl_sz * sizeof (ib_pkey_t);
			if (ddi_copyout((void *)pinfop->p_pkey_tbl,
			    (void *)(uintptr_t)portioc32.ioc_pkeys, size,
			    mode)) {
				rval = EFAULT;
				goto fail;
			}
			size = sizeof (ibport_ioctl32_t);
			if (ddi_copyout((void *)&portioc32, (void *)arg, size,
			    mode)) {
				rval = EFAULT;
				goto fail;
			}
			break;
		}
		case DDI_MODEL_NONE:
			size = sizeof (ibport_ioctl_t);
			if (ddi_copyin((void *)arg, &portioc, size, mode)) {
				rval = EFAULT;
				goto fail;
			}
			portioc.ibdioc.ioc_status = 0;
			portioc.ibdioc.ioc_portnum = port_state->id_port;
			portioc.ibdioc.ioc_hcaguid = port_state->id_hca_guid;
			portioc.ibdioc.ioc_portguid = port_state->id_port_guid;
			if (portioc.ioc_pkey_tbl_sz != pinfop->p_pkey_tbl_sz) {
				rval = EINVAL;
				size = sizeof (ibd_ioctl_t);
				portioc.ibdioc.ioc_status =
				    IBD_INVALID_PKEY_TBL_SIZE;
				if (ddi_copyout((void *)&portioc.ibdioc,
				    (void *)arg, size, mode)) {
					rval = EFAULT;
					goto fail;
				}
				goto fail;
			}
			size = pinfop->p_pkey_tbl_sz * sizeof (ib_pkey_t);
			if (ddi_copyout((void *)pinfop->p_pkey_tbl,
			    (void *)(portioc.ioc_pkeys), size, mode)) {
				rval = EFAULT;
				goto fail;
			}
			size = sizeof (ibport_ioctl_t);
			if (ddi_copyout((void *)&portioc, (void *)arg, size,
			    mode)) {
				rval = EFAULT;
				goto fail;
			}
			break;
		}
#else /* ! _MULTI_DATAMODEL */
		size = sizeof (ibport_ioctl_t);
		if (ddi_copyin((void *)arg, &portioc, size, mode)) {
			rval = EFAULT;
			goto fail;
		}
		portioc.ibdioc.ioc_status = 0;
		portioc.ibdioc.ioc_portnum = port_state->id_port;
		portioc.ibdioc.ioc_hcaguid = port_state->id_hca_guid;
		portioc.ibdioc.ioc_portguid = port_state->id_port_guid;
		if (portioc.ioc_pkey_tbl_sz != pinfop->p_pkey_tbl_sz) {
			rval = EINVAL;
			size = sizeof (ibd_ioctl_t);
			portioc.ibdioc.ioc_status = IBD_INVALID_PKEY_TBL_SIZE;
			if (ddi_copyout((void *)&portioc.ibdioc, (void *)arg,
			    size, mode)) {
				rval = EFAULT;
				goto fail;
			}
			goto fail;
		}
		size = pinfop->p_pkey_tbl_sz * sizeof (ib_pkey_t);
		if (ddi_copyout((void *)pinfop->p_pkey_tbl,
		    (void *)(portioc.ioc_pkeys), size, mode)) {
			rval = EFAULT;
			goto fail;
		}
		size = sizeof (ibport_ioctl_t);
		if (ddi_copyout((void *)&portioc, (void *)arg, size,
		    mode)) {
			rval = EFAULT;
			goto fail;
		}
#endif /* _MULTI_DATAMODEL */

		break;

	case IBD_INFO_CMD_PKEYTBLSZ:
		if ((cmd.ioc_port_inst < 0) || ((port_state =
		    ddi_get_soft_state(ibd_list, cmd.ioc_port_inst)) == NULL)) {
			DPRINT(10, "ibd_create_partition: failed to get"
			    " state %d", cmd.ioc_port_inst);
			size = sizeof (ibd_ioctl_t);
			cmd.ioc_status = IBD_INVALID_PORT_INST;
			if (ddi_copyout((void *)&cmd, (void *)arg, size,
			    mode)) {
				return (EFAULT);
			}
			return (EINVAL);
		}
		ibt_status = ibt_query_hca_ports(port_state->id_hca_hdl,
		    port_state->id_port, &pinfop, &psize, &pinfosz);
		if ((ibt_status != IBT_SUCCESS) || (psize != 1)) {
			return (EINVAL);
		}
#ifdef _MULTI_DATAMODEL
		switch (ddi_model_convert_from(mode & FMODELS)) {
		case DDI_MODEL_ILP32: {
			size = sizeof (ibport_ioctl32_t);
			if (ddi_copyin((void *)arg, &portioc32, size, mode)) {
				rval = EFAULT;
				goto fail;
			}
			portioc32.ibdioc.ioc_status = 0;
			portioc32.ibdioc.ioc_portnum = port_state->id_port;
			portioc32.ibdioc.ioc_hcaguid =
			    port_state->id_hca_guid;
			portioc32.ibdioc.ioc_portguid =
			    port_state->id_port_guid;
			portioc32.ioc_pkey_tbl_sz = pinfop->p_pkey_tbl_sz;
			if (ddi_copyout((void *)&portioc32, (void *)arg, size,
			    mode)) {
				rval = EFAULT;
				goto fail;
			}
			break;
		}
		case DDI_MODEL_NONE:
			size = sizeof (ibport_ioctl_t);
			if (ddi_copyin((void *)arg, &portioc, size, mode)) {
				rval = EFAULT;
				goto fail;
			}
			portioc.ibdioc.ioc_status = 0;
			portioc.ibdioc.ioc_portnum = port_state->id_port;
			portioc.ibdioc.ioc_hcaguid = port_state->id_hca_guid;
			portioc.ibdioc.ioc_portguid = port_state->id_port_guid;
			portioc.ioc_pkey_tbl_sz = pinfop->p_pkey_tbl_sz;
			if (ddi_copyout((void *)&portioc, (void *)arg, size,
			    mode)) {
				rval = EFAULT;
				goto fail;
			}
			break;
		}
#else /* ! _MULTI_DATAMODEL */
		size = sizeof (ibport_ioctl_t);
		if (ddi_copyin((void *)arg, &portioc, size, mode)) {
			rval = EFAULT;
			goto fail;
		}
		portioc.ibdioc.ioc_status = 0;
		portioc.ibdioc.ioc_portnum = port_state->id_port;
		portioc.ibdioc.ioc_hcaguid = port_state->id_hca_guid;
		portioc.ibdioc.ioc_portguid = port_state->id_port_guid;
		portioc.ioc_pkey_tbl_sz = pinfop->p_pkey_tbl_sz;
		if (ddi_copyout((void *)&portioc, (void *)arg, size,
		    mode)) {
			rval = EFAULT;
			goto fail;
		}
#endif /* _MULTI_DATAMODEL */
		break;

	default:
		return (EINVAL);

	} /* switch (cmd.ioc_info_cmd) */
fail:
	if (pinfop) {
		ibt_free_portinfo(pinfop, pinfosz);
	}
	return (rval);
}

/* ARGSUSED */
static void
ibdpd_async_handler(void *arg, ibt_hca_hdl_t hca_hdl,
    ibt_async_code_t code, ibt_async_event_t *event)
{
	ibd_state_t *state = (ibd_state_t *)arg;
	link_state_t	lstate;

	switch (code) {
	case IBT_EVENT_PORT_UP:
	case IBT_ERROR_PORT_DOWN:
		if (ibd_get_port_state(state, &lstate) != 0)
			break;

		if (state->id_link_state != lstate) {
			state->id_link_state = lstate;
			mac_link_update(state->id_mh, lstate);
		}
		break;
	default:
		break;
	}
}

static int
ibd_get_port_state(ibd_state_t *state, link_state_t *lstate)
{
	ibt_hca_portinfo_t *port_infop;
	uint_t psize, port_infosz;
	ibt_status_t	ret;

	ret = ibt_query_hca_ports(state->id_hca_hdl, state->id_port,
	    &port_infop, &psize, &port_infosz);
	if ((ret != IBT_SUCCESS) || (psize != 1))
		return (-1);

	state->id_sgid = *port_infop->p_sgid_tbl;
	state->id_link_speed = ibd_get_portspeed(state);

	if (port_infop->p_linkstate == IBT_PORT_ACTIVE)
		*lstate = LINK_STATE_UP;
	else
		*lstate = LINK_STATE_DOWN;

	ibt_free_portinfo(port_infop, port_infosz);
	return (0);
}

static int
ibd_port_attach(dev_info_t *dip)
{
	ibd_state_t		*state;
	link_state_t		lstate;
	int			instance;
	ibt_status_t		ret;

	/*
	 * Allocate softstate structure
	 */
	instance = ddi_get_instance(dip);
	if (ddi_soft_state_zalloc(ibd_list, instance) == DDI_FAILURE) {
		DPRINT(10, "ibd_port_attach: ddi_soft_state_zalloc() failed");
		return (DDI_FAILURE);
	}

	state = ddi_get_soft_state(ibd_list, instance);

	state->id_dip = dip;
	state->id_type = IBD_PORT_DRIVER;

	if ((state->id_port = ddi_prop_get_int(DDI_DEV_T_ANY, dip, 0,
	    "port-number", 0)) == 0) {
		DPRINT(10, "ibd_port_attach: invalid port number (%d)",
		    state->id_port);
		return (DDI_FAILURE);
	}
	if ((state->id_hca_guid = ddi_prop_get_int64(DDI_DEV_T_ANY, dip, 0,
	    "hca-guid", 0)) == 0) {
		DPRINT(10, "ibd_port_attach: hca has invalid guid (0x%llx)",
		    state->id_hca_guid);
		return (DDI_FAILURE);
	}
	if ((state->id_port_guid = ddi_prop_get_int64(DDI_DEV_T_ANY, dip, 0,
	    "port-guid", 0)) == 0) {
		DPRINT(10, "ibd_port_attach: port has invalid guid (0x%llx)",
		    state->id_port_guid);
		return (DDI_FAILURE);
	}

	/*
	 * Attach to IBTL
	 */
	if ((ret = ibt_attach(&ibdpd_clnt_modinfo, dip, state,
	    &state->id_ibt_hdl)) != IBT_SUCCESS) {
		DPRINT(10, "ibd_port_attach: failed in ibt_attach(), ret=%d",
		    ret);
		goto done;
	}

	state->id_mac_state |= IBD_DRV_IBTL_ATTACH_DONE;

	if ((ret = ibt_open_hca(state->id_ibt_hdl, state->id_hca_guid,
	    &state->id_hca_hdl)) != IBT_SUCCESS) {
		DPRINT(10, "ibd_port_attach: ibt_open_hca() failed, ret=%d",
		    ret);
		goto done;
	}
	state->id_mac_state |= IBD_DRV_HCA_OPENED;

	/* Update link status */

	if (ibd_get_port_state(state, &lstate) != 0) {
		DPRINT(10, "ibd_port_attach: ibt_open_hca() failed, ret=%d",
		    ret);
		goto done;
	}
	state->id_link_state = lstate;
	/*
	 * Register ibd interfaces with the Nemo framework
	 */
	if (ibd_register_mac(state, dip) != IBT_SUCCESS) {
		DPRINT(10, "ibd_port_attach: failed in ibd_register_mac()");
		goto done;
	}
	state->id_mac_state |= IBD_DRV_MAC_REGISTERED;

	mac_link_update(state->id_mh, lstate);

	return (DDI_SUCCESS);
done:
	(void) ibd_port_unattach(state, dip);
	return (DDI_FAILURE);
}

static int
ibd_port_unattach(ibd_state_t *state, dev_info_t *dip)
{
	int instance;
	uint32_t progress = state->id_mac_state;
	ibt_status_t ret;

	if (progress & IBD_DRV_MAC_REGISTERED) {
		(void) mac_unregister(state->id_mh);
		state->id_mac_state &= (~IBD_DRV_MAC_REGISTERED);
	}

	if (progress & IBD_DRV_HCA_OPENED) {
		if ((ret = ibt_close_hca(state->id_hca_hdl)) !=
		    IBT_SUCCESS) {
			ibd_print_warn(state, "failed to close "
			    "HCA device, ret=%d", ret);
		}
		state->id_hca_hdl = NULL;
		state->id_mac_state &= (~IBD_DRV_HCA_OPENED);
	}

	if (progress & IBD_DRV_IBTL_ATTACH_DONE) {
		if ((ret = ibt_detach(state->id_ibt_hdl)) != IBT_SUCCESS) {
			ibd_print_warn(state,
			    "ibt_detach() failed, ret=%d", ret);
		}
		state->id_ibt_hdl = NULL;
		state->id_mac_state &= (~IBD_DRV_IBTL_ATTACH_DONE);
	}
	instance = ddi_get_instance(dip);
	ddi_soft_state_free(ibd_list, instance);

	return (DDI_SUCCESS);
}

ibt_status_t
ibd_get_part_attr(datalink_id_t linkid, ibt_part_attr_t *attr)
{
	ibd_state_t	*state;

	mutex_enter(&ibd_objlist_lock);

	/* Find the ibd state structure corresponding the partition */
	for (state = ibd_objlist_head; state; state = state->id_next) {
		if (state->id_plinkid == linkid) {
			break;
		}
	}

	if (state == NULL) {
		mutex_exit(&ibd_objlist_lock);
		return (IBT_NO_SUCH_OBJECT);
	}

	attr->pa_dlinkid = state->id_dlinkid;
	attr->pa_plinkid = state->id_plinkid;
	attr->pa_port = state->id_port;
	attr->pa_hca_guid = state->id_hca_guid;
	attr->pa_port_guid = state->id_port_guid;
	attr->pa_pkey = state->id_pkey;

	mutex_exit(&ibd_objlist_lock);

	return (IBT_SUCCESS);
}

ibt_status_t
ibd_get_all_part_attr(ibt_part_attr_t **attr_list, int *nparts)
{
	ibd_state_t	*state;
	int		n = 0;
	ibt_part_attr_t	*attr;

	mutex_enter(&ibd_objlist_lock);

	for (state = ibd_objlist_head; state; state = state->id_next)
		n++;

	*nparts = n;
	if (n == 0) {
		*attr_list = NULL;
		mutex_exit(&ibd_objlist_lock);
		return (IBT_SUCCESS);
	}

	*attr_list = kmem_alloc(sizeof (ibt_part_attr_t) * n, KM_SLEEP);
	attr = *attr_list;
	for (state = ibd_objlist_head; state; state = state->id_next) {
#ifdef DEBUG
		ASSERT(n > 0);
		n--;
#endif
		attr->pa_dlinkid = state->id_dlinkid;
		attr->pa_plinkid = state->id_plinkid;
		attr->pa_port = state->id_port;
		attr->pa_hca_guid = state->id_hca_guid;
		attr->pa_port_guid = state->id_port_guid;
		attr->pa_pkey = state->id_pkey;
		attr++;
	}

	mutex_exit(&ibd_objlist_lock);
	return (IBT_SUCCESS);
}
