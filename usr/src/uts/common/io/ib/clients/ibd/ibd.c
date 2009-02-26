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
#include <sys/ethernet.h>	/* for ETHERTYPE_IP */
#include <netinet/in.h>		/* for netinet/ip.h below */
#include <netinet/ip.h>		/* for struct ip */
#include <netinet/udp.h>	/* for struct udphdr */
#include <inet/common.h>	/* for inet/ip.h below */
#include <inet/ip.h>		/* for ipha_t */
#include <inet/ip_if.h>		/* for IP6_DL_SAP */
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

/*
 * Per-interface tunables
 *
 * ibd_tx_copy_thresh
 *     This sets the threshold at which ibd will attempt to do a bcopy of the
 *     outgoing data into a pre-mapped buffer. The IPoIB driver's send behavior
 *     is restricted by various parameters, so setting of this value must be
 *     made after careful considerations only.  For instance, IB HCAs currently
 *     impose a relatively small limit (when compared to ethernet NICs) on the
 *     length of the SGL for transmit. On the other hand, the ip stack could
 *     send down mp chains that are quite long when LSO is enabled.
 *
 * ibd_num_swqe
 *     Number of "send WQE" elements that will be allocated and used by ibd.
 *     When tuning this parameter, the size of pre-allocated, pre-mapped copy
 *     buffer in each of these send wqes must be taken into account. This
 *     copy buffer size is determined by the value of IBD_TX_BUF_SZ (this is
 *     currently set to the same value of ibd_tx_copy_thresh, but may be
 *     changed independently if needed).
 *
 * ibd_num_rwqe
 *     Number of "receive WQE" elements that will be allocated and used by
 *     ibd. This parameter is limited by the maximum channel size of the HCA.
 *     Each buffer in the receive wqe will be of MTU size.
 *
 * ibd_num_lso_bufs
 *     Number of "larger-than-MTU" copy buffers to use for cases when the
 *     outgoing mblk chain is too fragmented to be used with ibt_map_mem_iov()
 *     and too large to be used with regular MTU-sized copy buffers. It is
 *     not recommended to tune this variable without understanding the
 *     application environment and/or memory resources. The size of each of
 *     these lso buffers is determined by the value of IBD_LSO_BUFSZ.
 *
 * ibd_num_ah
 *     Number of AH cache entries to allocate
 *
 * ibd_hash_size
 *     Hash table size for the active AH list
 *
 * ibd_separate_cqs
 * ibd_txcomp_poll
 *     These boolean variables (1 or 0) may be used to tune the behavior of
 *     ibd in managing the send and receive completion queues and in deciding
 *     whether or not transmit completions should be polled or interrupt
 *     driven (when the completion queues are separate). If both the completion
 *     queues are interrupt driven, it may not be possible for the handlers to
 *     be invoked concurrently, depending on how the interrupts are tied on
 *     the PCI intr line.  Note that some combination of these two parameters
 *     may not be meaningful (and therefore not allowed).
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
uint_t ibd_tx_copy_thresh = 0x1000;
uint_t ibd_num_swqe = 4000;
uint_t ibd_num_rwqe = 4000;
uint_t ibd_num_lso_bufs = 0x400;
uint_t ibd_num_ah = 64;
uint_t ibd_hash_size = 32;
uint_t ibd_separate_cqs = 1;
uint_t ibd_txcomp_poll = 0;
uint_t ibd_rx_softintr = 1;
uint_t ibd_tx_softintr = 1;
#ifdef IBD_LOGGING
uint_t ibd_log_sz = 0x20000;
#endif

#define	IBD_TX_COPY_THRESH		ibd_tx_copy_thresh
#define	IBD_TX_BUF_SZ			ibd_tx_copy_thresh
#define	IBD_NUM_SWQE			ibd_num_swqe
#define	IBD_NUM_RWQE			ibd_num_rwqe
#define	IBD_NUM_LSO_BUFS		ibd_num_lso_bufs
#define	IBD_NUM_AH			ibd_num_ah
#define	IBD_HASH_SIZE			ibd_hash_size
#ifdef IBD_LOGGING
#define	IBD_LOG_SZ			ibd_log_sz
#endif

/*
 * Receive CQ moderation parameters: NOT tunables
 */
static uint_t ibd_rxcomp_count = 4;
static uint_t ibd_rxcomp_usec = 10;

/*
 * Thresholds
 *
 * When waiting for resources (swqes or lso buffers) to become available,
 * the first two thresholds below determine how long to wait before informing
 * the network layer to start sending packets again. The IBD_TX_POLL_THRESH
 * determines how low the available swqes should go before we start polling
 * the completion queue.
 */
#define	IBD_FREE_LSOS_THRESH		8
#define	IBD_FREE_SWQES_THRESH		20
#define	IBD_TX_POLL_THRESH		80

/*
 * When doing multiple-send-wr or multiple-recv-wr posts, this value
 * determines how many to do at a time (in a single ibt_post_send/recv).
 */
#define	IBD_MAX_POST_MULTIPLE		4

/*
 * Maximum length for returning chained mps back to crossbow
 */
#define	IBD_MAX_RX_MP_LEN		16

/*
 * LSO parameters
 */
#define	IBD_LSO_MAXLEN			65536
#define	IBD_LSO_BUFSZ			8192
#define	IBD_PROP_LSO_POLICY		"lso-policy"

/*
 * Completion queue polling control
 */
#define	IBD_RX_CQ_POLLING		0x1
#define	IBD_TX_CQ_POLLING		0x2
#define	IBD_REDO_RX_CQ_POLLING		0x4
#define	IBD_REDO_TX_CQ_POLLING		0x8

/*
 * Flag bits for resources to reap
 */
#define	IBD_RSRC_SWQE			0x1
#define	IBD_RSRC_LSOBUF			0x2

/*
 * Async operation types
 */
#define	IBD_ASYNC_GETAH			1
#define	IBD_ASYNC_JOIN			2
#define	IBD_ASYNC_LEAVE			3
#define	IBD_ASYNC_PROMON		4
#define	IBD_ASYNC_PROMOFF		5
#define	IBD_ASYNC_REAP			6
#define	IBD_ASYNC_TRAP			7
#define	IBD_ASYNC_SCHED			8
#define	IBD_ASYNC_LINK			9
#define	IBD_ASYNC_EXIT			10

/*
 * Async operation states
 */
#define	IBD_OP_NOTSTARTED		0
#define	IBD_OP_ONGOING			1
#define	IBD_OP_COMPLETED		2
#define	IBD_OP_ERRORED			3
#define	IBD_OP_ROUTERED			4

/*
 * Miscellaneous constants
 */
#define	IBD_SEND			0
#define	IBD_RECV			1
#define	IB_MGID_IPV4_LOWGRP_MASK	0xFFFFFFFF
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

/*
 * Private driver entry points for GLDv3
 */

/*
 * Initialization
 */
static int ibd_state_init(ibd_state_t *, dev_info_t *);
static int ibd_drv_init(ibd_state_t *);
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
static void ibd_drv_fini(ibd_state_t *);
static void ibd_fini_txlist(ibd_state_t *);
static void ibd_fini_rxlist(ibd_state_t *);
static void ibd_tx_cleanup(ibd_state_t *, ibd_swqe_t *);
static void ibd_acache_fini(ibd_state_t *);
#ifdef IBD_LOGGING
static void ibd_log_fini(void);
#endif

/*
 * Allocation/acquire/map routines
 */
static int ibd_alloc_swqe(ibd_state_t *, ibd_swqe_t **, int, ibt_lkey_t);
static int ibd_alloc_rwqe(ibd_state_t *, ibd_rwqe_t **);
static int ibd_alloc_tx_copybufs(ibd_state_t *);
static int ibd_alloc_tx_lsobufs(ibd_state_t *);
static int ibd_acquire_swqe(ibd_state_t *, ibd_swqe_t **);
static int ibd_acquire_lsobufs(ibd_state_t *, uint_t, ibt_wr_ds_t *,
    uint32_t *);

/*
 * Free/release/unmap routines
 */
static void ibd_free_swqe(ibd_state_t *, ibd_swqe_t *);
static void ibd_free_rwqe(ibd_state_t *, ibd_rwqe_t *);
static void ibd_delete_rwqe(ibd_state_t *, ibd_rwqe_t *);
static void ibd_free_tx_copybufs(ibd_state_t *);
static void ibd_free_tx_lsobufs(ibd_state_t *);
static void ibd_release_swqe(ibd_state_t *, ibd_swqe_t *);
static void ibd_release_lsobufs(ibd_state_t *, ibt_wr_ds_t *, uint32_t);
static void ibd_free_lsohdr(ibd_swqe_t *, mblk_t *);
static void ibd_unmap_mem(ibd_state_t *, ibd_swqe_t *);

/*
 * Handlers/callback routines
 */
static uint_t ibd_intr(char *);
static uint_t ibd_tx_recycle(char *);
static void ibd_rcq_handler(ibt_cq_hdl_t, void *);
static void ibd_scq_handler(ibt_cq_hdl_t, void *);
static void ibd_poll_compq(ibd_state_t *, ibt_cq_hdl_t);
static uint_t ibd_drain_cq(ibd_state_t *, ibt_cq_hdl_t, ibt_wc_t *, uint_t);
static void ibd_freemsg_cb(char *);
static void ibd_async_handler(void *, ibt_hca_hdl_t, ibt_async_code_t,
    ibt_async_event_t *);
static void ibd_snet_notices_handler(void *, ib_gid_t,
    ibt_subnet_event_code_t, ibt_subnet_event_t *);

/*
 * Send/receive routines
 */
static boolean_t ibd_send(ibd_state_t *, mblk_t *);
static void ibd_post_send(ibd_state_t *, ibd_swqe_t *);
static int ibd_post_rwqe(ibd_state_t *, ibd_rwqe_t *, boolean_t);
static void ibd_process_rx(ibd_state_t *, ibd_rwqe_t *, ibt_wc_t *);
static void ibd_flush_rx(ibd_state_t *, mblk_t *);

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
static int ibd_get_portpkey(ibd_state_t *, ib_guid_t *);
static boolean_t ibd_async_safe(ibd_state_t *);
static void ibd_async_done(ibd_state_t *);
static ibd_ace_t *ibd_acache_find(ibd_state_t *, ipoib_mac_t *, boolean_t, int);
static ibd_ace_t *ibd_acache_lookup(ibd_state_t *, ipoib_mac_t *, int *, int);
static ibd_ace_t *ibd_acache_get_unref(ibd_state_t *);
static boolean_t ibd_acache_recycle(ibd_state_t *, ipoib_mac_t *, boolean_t);
static void ibd_link_mod(ibd_state_t *, ibt_async_code_t);

/*
 * Miscellaneous helpers
 */
static int ibd_sched_poll(ibd_state_t *, int, int);
static void ibd_queue_work_slot(ibd_state_t *, ibd_req_t *, int);
static int ibd_resume_transmission(ibd_state_t *);
static int ibd_setup_lso(ibd_swqe_t *, mblk_t *, uint32_t, ibt_ud_dest_hdl_t);
static int ibd_prepare_sgl(ibd_state_t *, mblk_t *, ibd_swqe_t *, uint_t);
static void *list_get_head(list_t *);
static int ibd_hash_key_cmp(mod_hash_key_t, mod_hash_key_t);
static uint_t ibd_hash_by_id(void *, mod_hash_key_t);
static void ibd_print_warn(ibd_state_t *, char *, ...);
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
	"IPIB"
};

/*
 * GLDv3 entry points
 */
#define	IBD_M_CALLBACK_FLAGS	(MC_GETCAPAB)
static mac_callbacks_t ib_m_callbacks = {
	IBD_M_CALLBACK_FLAGS,
	ibd_m_stat,
	ibd_m_start,
	ibd_m_stop,
	ibd_m_promisc,
	ibd_m_multicst,
	ibd_m_unicst,
	ibd_m_tx,
	NULL,
	ibd_m_getcapab
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
static void
debug_print(int l, char *fmt, ...)
{
	va_list ap;

	if (l < ibd_debuglevel)
		return;
	va_start(ap, fmt);
	vcmn_err(CE_CONT, fmt, ap);
	va_end(ap);
}
#define	DPRINT		debug_print
#else
#define	DPRINT
#endif

/*
 * Common routine to print warning messages; adds in hca guid, port number
 * and pkey to be able to identify the IBA interface.
 */
static void
ibd_print_warn(ibd_state_t *state, char *fmt, ...)
{
	ib_guid_t hca_guid;
	char ibd_print_buf[256];
	int len;
	va_list ap;

	hca_guid = ddi_prop_get_int64(DDI_DEV_T_ANY, state->id_dip,
	    0, "hca-guid", 0);
	len = snprintf(ibd_print_buf, sizeof (ibd_print_buf),
	    "%s%d: HCA GUID %016llx port %d PKEY %02x ",
	    ddi_driver_name(state->id_dip), ddi_get_instance(state->id_dip),
	    (u_longlong_t)hca_guid, state->id_port, state->id_pkey);
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
_NOTE(DATA_READABLE_WITHOUT_LOCK(ibd_lsobkt_t::bkt_nfree))

/*
 * id_cq_poll_lock
 */
_NOTE(MUTEX_PROTECTS_DATA(ibd_state_t::id_cq_poll_lock,
    ibd_state_t::id_cq_poll_busy))

/*
 * id_txpost_lock
 */
_NOTE(MUTEX_PROTECTS_DATA(ibd_state_t::id_txpost_lock,
    ibd_state_t::id_tx_head))
_NOTE(MUTEX_PROTECTS_DATA(ibd_state_t::id_txpost_lock,
    ibd_state_t::id_tx_busy))
_NOTE(MUTEX_PROTECTS_DATA(ibd_state_t::id_txpost_lock,
    ibd_state_t::id_tx_tailp))

/*
 * id_rxpost_lock
 */
_NOTE(MUTEX_PROTECTS_DATA(ibd_state_t::id_rxpost_lock,
    ibd_state_t::id_rx_head))
_NOTE(MUTEX_PROTECTS_DATA(ibd_state_t::id_rxpost_lock,
    ibd_state_t::id_rx_busy))
_NOTE(MUTEX_PROTECTS_DATA(ibd_state_t::id_rxpost_lock,
    ibd_state_t::id_rx_tailp))

/*
 * id_acache_req_lock
 */
_NOTE(MUTEX_PROTECTS_DATA(ibd_state_t::id_acache_req_lock, 
    ibd_state_t::id_acache_req_cv))
_NOTE(MUTEX_PROTECTS_DATA(ibd_state_t::id_acache_req_lock, 
    ibd_state_t::id_req_list))

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
_NOTE(SCHEME_PROTECTS_DATA("only async thr and drv init",
    ibd_state_t::id_link_speed))

/*
 * id_tx_list.dl_mutex
 */
_NOTE(MUTEX_PROTECTS_DATA(ibd_state_t::id_tx_list.dl_mutex, 
    ibd_state_t::id_tx_list.dl_head))
_NOTE(MUTEX_PROTECTS_DATA(ibd_state_t::id_tx_list.dl_mutex, 
    ibd_state_t::id_tx_list.dl_tail))
_NOTE(SCHEME_PROTECTS_DATA("atomic or dl mutex or single thr",
    ibd_state_t::id_tx_list.dl_pending_sends))
_NOTE(SCHEME_PROTECTS_DATA("atomic or dl mutex or single thr",
    ibd_state_t::id_tx_list.dl_cnt))

/*
 * id_rx_list.dl_mutex
 */
_NOTE(MUTEX_PROTECTS_DATA(ibd_state_t::id_rx_list.dl_mutex, 
    ibd_state_t::id_rx_list.dl_head))
_NOTE(MUTEX_PROTECTS_DATA(ibd_state_t::id_rx_list.dl_mutex, 
    ibd_state_t::id_rx_list.dl_tail))
_NOTE(SCHEME_PROTECTS_DATA("atomic or dl mutex or single thr",
    ibd_state_t::id_rx_list.dl_bufs_outstanding))
_NOTE(SCHEME_PROTECTS_DATA("atomic or dl mutex or single thr",
    ibd_state_t::id_rx_list.dl_cnt))


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
    ibd_state_s::id_tx_short
    ibd_state_s::id_xmt_bytes
    ibd_state_s::id_xmt_pkt))

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
    msgb::b_rptr
    msgb::b_wptr))

int
_init()
{
	int status;

	/*
	 * Sanity check some parameter settings. Tx completion polling
	 * only makes sense with separate CQs for Tx and Rx.
	 */
	if ((ibd_txcomp_poll == 1) && (ibd_separate_cqs == 0)) {
		cmn_err(CE_NOTE, "!ibd: %s",
		    "Setting ibd_txcomp_poll = 0 for combined CQ");
		ibd_txcomp_poll = 0;
	}

	status = ddi_soft_state_init(&ibd_list, sizeof (ibd_state_t), 0);
	if (status != 0) {
		DPRINT(10, "_init:failed in ddi_soft_state_init()");
		return (status);
	}

	mac_init_ops(&ibd_dev_ops, "ibd");
	status = mod_install(&ibd_modlinkage);
	if (status != 0) {
		DPRINT(10, "_init:failed in mod_install()");
		ddi_soft_state_fini(&ibd_list);
		mac_fini_ops(&ibd_dev_ops);
		return (status);
	}

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

	mac_fini_ops(&ibd_dev_ops);
	ddi_soft_state_fini(&ibd_list);
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
 * Padding for nd6 Neighbor Solicitation and Advertisement needs to be at
 * front of optional src/tgt link layer address. Right now Solaris inserts
 * padding by default at the end. The routine which is doing is nce_xmit()
 * in ip_ndp.c. It copies the nd_lla_addr after the nd_opt_hdr_t. So when
 * the packet comes down from IP layer to the IBD driver, it is in the
 * following format: [IPoIB_PTXHDR_T][INET6 packet][ICMP6][OPT_ND_HDR_T]
 * This size is 2 bytes followed by [22 bytes of ipoib_machdr]. As a result
 * machdr is not 4 byte aligned and had 2 bytes of padding at the end.
 *
 * The send routine at IBD driver changes this packet as follows:
 * [IPoIB_HDR_T][INET6 packet][ICMP6][OPT_ND_HDR_T + 2 bytes of padding]
 * followed by [22 bytes of ipoib_machdr] resulting in machdr 4 byte
 * aligned.
 *
 * At the receiving side again ibd_process_rx takes the above packet and
 * removes the two bytes of front padding and inserts it at the end. This
 * is since the IP layer does not understand padding at the front.
 */
#define	IBD_PAD_NSNA(ip6h, len, type) {					\
	uchar_t 	*nd_lla_ptr;					\
	icmp6_t 	*icmp6;						\
	nd_opt_hdr_t	*opt;						\
	int 		i;						\
									\
	icmp6 = (icmp6_t *)&ip6h[1];					\
	len -= sizeof (nd_neighbor_advert_t);				\
	if (((icmp6->icmp6_type == ND_NEIGHBOR_SOLICIT) ||		\
	    (icmp6->icmp6_type == ND_NEIGHBOR_ADVERT)) &&		\
	    (len != 0)) {						\
		opt = (nd_opt_hdr_t *)((uint8_t *)ip6h			\
		    + IPV6_HDR_LEN + sizeof (nd_neighbor_advert_t));	\
		ASSERT(opt != NULL);					\
		nd_lla_ptr = (uchar_t *)&opt[1];			\
		if (type == IBD_SEND) {					\
			for (i = IPOIB_ADDRL; i > 0; i--)		\
				*(nd_lla_ptr + i + 1) =			\
				    *(nd_lla_ptr + i - 1);		\
		} else {						\
			for (i = 0; i < IPOIB_ADDRL; i++)		\
				*(nd_lla_ptr + i) =			\
				    *(nd_lla_ptr + i + 2);		\
		}							\
		*(nd_lla_ptr + i) = 0;					\
		*(nd_lla_ptr + i + 1) = 0;				\
	}								\
}

/*
 * Address handle entries maintained by the driver are kept in the
 * free and active lists. Each entry starts out in the free list;
 * it migrates to the active list when primed using ibt_get_paths()
 * and ibt_modify_ud_dest() for transmission to a specific destination.
 * In the active list, the entry has a reference count indicating the
 * number of ongoing/uncompleted transmits that reference it. The
 * entry is left in the active list even after the reference count
 * goes to 0, since successive transmits can find it there and do
 * not need to set up another entry (ie the path information is
 * cached using the active list). Entries on the active list are
 * also hashed using the destination link address as a key for faster
 * lookups during transmits.
 *
 * For any destination address (unicast or multicast, whatever the
 * join states), there will be at most one entry in the active list.
 * Entries with a 0 reference count on the active list can be reused
 * for a transmit to a new destination, if the free list is empty.
 *
 * The AH free list insertion/deletion is protected with the id_ac_mutex,
 * since the async thread and Tx callback handlers insert/delete. The
 * active list does not need a lock (all operations are done by the
 * async thread) but updates to the reference count are atomically
 * done (increments done by Tx path, decrements by the Tx callback handler).
 */
#define	IBD_ACACHE_INSERT_FREE(state, ce) \
	list_insert_head(&state->id_ah_free, ce)
#define	IBD_ACACHE_GET_FREE(state) \
	list_get_head(&state->id_ah_free)
#define	IBD_ACACHE_INSERT_ACTIVE(state, ce) {			\
	int _ret_;						\
	list_insert_head(&state->id_ah_active, ce);		\
	_ret_ = mod_hash_insert(state->id_ah_active_hash,	\
	    (mod_hash_key_t)&ce->ac_mac, (mod_hash_val_t)ce);	\
	ASSERT(_ret_ == 0);					\
}
#define	IBD_ACACHE_PULLOUT_ACTIVE(state, ce) {			\
	list_remove(&state->id_ah_active, ce);			\
	(void) mod_hash_remove(state->id_ah_active_hash,	\
	    (mod_hash_key_t)&ce->ac_mac, (mod_hash_val_t)ce);	\
}
#define	IBD_ACACHE_GET_ACTIVE(state) \
	list_get_head(&state->id_ah_active)

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
 * alongwith ipv4 broadcast full membership. Insert/deletes to
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

/*
 * AH and MCE active list manipulation:
 *
 * Multicast disable requests and MCG delete traps are two cases
 * where the active AH entry for the mcg (if any unreferenced one exists)
 * will be moved to the free list (to force the next Tx to the mcg to
 * join the MCG in SendOnly mode). Port up handling will also move AHs
 * from active to free list.
 *
 * In the case when some transmits are still pending on an entry
 * for an mcg, but a multicast disable has already been issued on the
 * mcg, there are some options to consider to preserve the join state
 * to ensure the emitted packet is properly routed on the IBA fabric.
 * For the AH, we can
 * 1. take out of active list at multicast disable time.
 * 2. take out of active list only when last pending Tx completes.
 * For the MCE, we can
 * 3. take out of active list at multicast disable time.
 * 4. take out of active list only when last pending Tx completes.
 * 5. move from active list to stale list at multicast disable time.
 * We choose to use 2,4. We use option 4 so that if a multicast enable
 * is tried before the pending Tx completes, the enable code finds the
 * mce in the active list and just has to make sure it will not be reaped
 * (ie the mcg leave done) when the pending Tx does complete. Alternatively,
 * a stale list (#5) that would be checked in the enable code would need
 * to be implemented. Option 2 is used, because otherwise, a Tx attempt
 * after the multicast disable would try to put an AH in the active list,
 * and associate the mce it finds in the active list to this new AH,
 * whereas the mce is already associated with the previous AH (taken off
 * the active list), and will be removed once the pending Tx's complete
 * (unless a reference count on mce's is implemented). One implication of
 * using 2,4 is that new Tx's posted before the pending Tx's complete will
 * grab new references on the AH, further delaying the leave.
 *
 * In the case of mcg delete (or create) trap when the port is sendonly
 * joined, the AH and MCE handling is different: the AH and MCE has to be
 * immediately taken off the active lists (forcing a join and path lookup
 * at the next Tx is the only guaranteed means of ensuring a proper Tx
 * to an mcg as it is repeatedly created and deleted and goes thru
 * reincarnations).
 *
 * When a port is already sendonly joined, and a multicast enable is
 * attempted, the same mce structure is promoted; this ensures only a
 * single mce on the active list tracks the most powerful join state.
 *
 * In the case of port up event handling, the MCE for sendonly membership
 * is freed up, and the ACE is put into the free list as soon as possible
 * (depending on whether posted Tx's have completed). For fullmembership
 * MCE's though, the ACE is similarly handled; but the MCE is kept around
 * (a re-JOIN is attempted) only if the DLPI leave has not already been
 * done; else the mce is deconstructed (mc_fullreap case).
 *
 * MCG creation and deletion trap handling:
 *
 * These traps are unreliable (meaning sometimes the trap might never
 * be delivered to the subscribed nodes) and may arrive out-of-order
 * since they use UD transport. An alternative to relying on these
 * unreliable traps is to poll for mcg presence every so often, but
 * instead of doing that, we try to be as conservative as possible
 * while handling the traps, and hope that the traps do arrive at
 * the subscribed nodes soon. Note that if a node is fullmember
 * joined to an mcg, it can not possibly receive a mcg create/delete
 * trap for that mcg (by fullmember definition); if it does, it is
 * an old trap from a previous incarnation of the mcg.
 *
 * Whenever a trap is received, the driver cleans up its sendonly
 * membership to the group; we choose to do a sendonly leave even
 * on a creation trap to handle the case of a prior deletion of the mcg
 * having gone unnoticed. Consider an example scenario:
 * T1: MCG M is deleted, and fires off deletion trap D1.
 * T2: MCG M is recreated, fires off creation trap C1, which is lost.
 * T3: Node N tries to transmit to M, joining in sendonly mode.
 * T4: MCG M is deleted, and fires off deletion trap D2.
 * T5: N receives a deletion trap, but can not distinguish D1 from D2.
 *     If the trap is D2, then a LEAVE is not required, since the mcg
 *     is already deleted; but if it is D1, a LEAVE is required. A safe
 *     approach is to always LEAVE, but the SM may be confused if it
 *     receives a LEAVE without a prior JOIN.
 *
 * Management of the non-membership to an mcg is similar to the above,
 * except that if the interface is in promiscuous mode, it is required
 * to attempt to re-join the mcg after receiving a trap. Unfortunately,
 * if the re-join attempt fails (in which case a warning message needs
 * to be printed), it is not clear whether it failed due to the mcg not
 * existing, or some fabric/hca issues, due to the delayed nature of
 * trap delivery. Querying the SA to establish presence/absence of the
 * mcg is also racy at best. Thus, the driver just prints a warning
 * message when it can not rejoin after receiving a create trap, although
 * this might be (on rare occassions) a mis-warning if the create trap is
 * received after the mcg was deleted.
 */

/*
 * Implementation of atomic "recycle" bits and reference count
 * on address handles. This utilizes the fact that max reference
 * count on any handle is limited by number of send wqes, thus
 * high bits in the ac_ref field can be used as the recycle bits,
 * and only the low bits hold the number of pending Tx requests.
 * This atomic AH reference counting allows the Tx completion
 * handler not to acquire the id_ac_mutex to process every completion,
 * thus reducing lock contention problems between completion and
 * the Tx path.
 */
#define	CYCLEVAL		0x80000
#define	CLEAR_REFCYCLE(ace)	(ace)->ac_ref = 0
#define	CYCLE_SET(ace)		(((ace)->ac_ref & CYCLEVAL) == CYCLEVAL)
#define	GET_REF(ace)		((ace)->ac_ref)
#define	GET_REF_CYCLE(ace) (				\
	/*						\
	 * Make sure "cycle" bit is set.		\
	 */						\
	ASSERT(CYCLE_SET(ace)),				\
	((ace)->ac_ref & ~(CYCLEVAL))			\
)
#define	INC_REF(ace, num) {				\
	atomic_add_32(&(ace)->ac_ref, num);		\
}
#define	SET_CYCLE_IF_REF(ace) (				\
	CYCLE_SET(ace) ? B_TRUE :			\
	    atomic_add_32_nv(&ace->ac_ref, CYCLEVAL) ==	\
		CYCLEVAL ?				\
		/*					\
		 * Clear the "cycle" bit we just set;	\
		 * ref count known to be 0 from above.	\
		 */					\
		CLEAR_REFCYCLE(ace), B_FALSE :		\
		/*					\
		 * We set "cycle" bit; let caller know.	\
		 */					\
		B_TRUE					\
)
#define	DEC_REF_DO_CYCLE(ace) (				\
	atomic_add_32_nv(&ace->ac_ref, -1) ==		\
	    CYCLEVAL ?					\
		/*					\
		 * Ref count known to be 0 from above.	\
		 */					\
		B_TRUE :				\
		B_FALSE					\
)

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
static void
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
			}
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
 * Wake up ibd_drv_fini() if the detach code is waiting for pending subnet
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

	mutex_init(&state->id_acache_req_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&state->id_acache_req_cv, NULL, CV_DEFAULT, NULL);

	mutex_init(&state->id_ac_mutex, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&state->id_mc_mutex, NULL, MUTEX_DRIVER, NULL);
	list_create(&state->id_ah_free, sizeof (ibd_ace_t),
	    offsetof(ibd_ace_t, ac_list));
	list_create(&state->id_ah_active, sizeof (ibd_ace_t),
	    offsetof(ibd_ace_t, ac_list));
	state->id_ah_active_hash = mod_hash_create_extended("IBD AH hash",
	    IBD_HASH_SIZE, mod_hash_null_keydtor, mod_hash_null_valdtor,
	    ibd_hash_by_id, NULL, ibd_hash_key_cmp, KM_SLEEP);
	list_create(&state->id_mc_full, sizeof (ibd_mce_t),
	    offsetof(ibd_mce_t, mc_list));
	list_create(&state->id_mc_non, sizeof (ibd_mce_t),
	    offsetof(ibd_mce_t, mc_list));
	list_create(&state->id_req_list, sizeof (ibd_req_t),
	    offsetof(ibd_req_t, rq_list));

	state->id_ac_list = ce = (ibd_ace_t *)kmem_zalloc(sizeof (ibd_ace_t) *
	    IBD_NUM_AH, KM_SLEEP);
	for (i = 0; i < IBD_NUM_AH; i++, ce++) {
		if (ibt_alloc_ud_dest(state->id_hca_hdl, IBT_UD_DEST_NO_FLAGS,
		    state->id_pd_hdl, &ce->ac_dest) != IBT_SUCCESS) {
			ibd_acache_fini(state);
			return (DDI_FAILURE);
		} else {
			CLEAR_REFCYCLE(ce);
			ce->ac_mce = NULL;
			IBD_ACACHE_INSERT_FREE(state, ce);
		}
	}
	return (DDI_SUCCESS);
}

static void
ibd_acache_fini(ibd_state_t *state)
{
	ibd_ace_t *ptr;

	mutex_enter(&state->id_ac_mutex);

	while ((ptr = IBD_ACACHE_GET_ACTIVE(state)) != NULL) {
		ASSERT(GET_REF(ptr) == 0);
		(void) ibt_free_ud_dest(ptr->ac_dest);
	}

	while ((ptr = IBD_ACACHE_GET_FREE(state)) != NULL) {
		ASSERT(GET_REF(ptr) == 0);
		(void) ibt_free_ud_dest(ptr->ac_dest);
	}

	list_destroy(&state->id_ah_free);
	list_destroy(&state->id_ah_active);
	list_destroy(&state->id_mc_full);
	list_destroy(&state->id_mc_non);
	list_destroy(&state->id_req_list);
	kmem_free(state->id_ac_list, sizeof (ibd_ace_t) * IBD_NUM_AH);
	mutex_exit(&state->id_ac_mutex);
	mutex_destroy(&state->id_ac_mutex);
	mutex_destroy(&state->id_mc_mutex);
	mutex_destroy(&state->id_acache_req_lock);
	cv_destroy(&state->id_acache_req_cv);
}

/*
 * Search AH active hash list for a cached path to input destination.
 * If we are "just looking", hold == F. When we are in the Tx path,
 * we set hold == T to grab a reference on the AH so that it can not
 * be recycled to a new destination while the Tx request is posted.
 */
static ibd_ace_t *
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

	if ((ptr = ibd_acache_find(state, mac, B_TRUE, numwqe)) != NULL) {
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
			ibd_queue_work_slot(state, req, IBD_ASYNC_GETAH);
			state->id_ah_op = IBD_OP_ONGOING;
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
	ibd_ace_t *ptr = list_head(&state->id_ah_active);

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
			IBD_ACACHE_PULLOUT_ACTIVE(state, ptr);
			break;
		}
		ptr = list_next(&state->id_ah_active, ptr);
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
static boolean_t
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
				IBD_ACACHE_PULLOUT_ACTIVE(state, acactive);
				acactive->ac_mce = NULL;
			}
		} else {
			/*
			 * Determined the ref count is 0, thus reclaim
			 * immediately after pulling out the ace from
			 * the active list.
			 */
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
	int ret = IBD_OP_NOTSTARTED;

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
	if (ibt_get_paths(state->id_ibt_hdl, IBT_PATH_NO_FLAGS,
	    &path_attr, 1, &path_info, NULL) != IBT_SUCCESS) {
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
	 * neccesary higher level notifications for speed changes.
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
			cycled = ibd_acache_recycle(state, &pace->ac_mac,
			    B_TRUE);
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
	ibt_hca_portinfo_t *port_infop;
	ibt_status_t ibt_status;
	uint_t psize, port_infosz;
	ibd_link_op_t opcode;
	ibd_req_t *req;

	/*
	 * Do not send a request to the async daemon if it has not
	 * yet been created or is being destroyed. If the async
	 * daemon has not yet been created, we still need to track
	 * last known state of the link. If this code races with the
	 * detach path, then we are assured that the detach path has
	 * not yet done the ibt_close_hca (which waits for all async
	 * events to complete). If the code races with the attach path,
	 * we need to validate the pkey/gid (in the link_up case) if
	 * the initialization path has already set these up and created
	 * IBTF resources based on the values.
	 */
	mutex_enter(&state->id_link_mutex);

	/*
	 * If the init code in ibd_drv_init hasn't yet set up the
	 * pkey/gid, nothing to do; that code will set the link state.
	 */
	if (state->id_link_state == LINK_STATE_UNKNOWN) {
		mutex_exit(&state->id_link_mutex);
		return;
	}

	if (code == IBT_EVENT_PORT_UP) {
		uint8_t itreply;
		boolean_t badup = B_FALSE;

		ibt_status = ibt_query_hca_ports(state->id_hca_hdl,
		    state->id_port, &port_infop, &psize, &port_infosz);
		if ((ibt_status != IBT_SUCCESS) || (psize != 1)) {
			mutex_exit(&state->id_link_mutex);
			DPRINT(10, "ibd_link_up : failed in"
			    " ibt_query_port()\n");
			return;
		}

		/*
		 * If the link already went down by the time the handler gets
		 * here, give up; we can not even validate pkey/gid since those
		 * are not valid.
		 */
		if (port_infop->p_linkstate != IBT_PORT_ACTIVE)
			badup = B_TRUE;

		itreply = port_infop->p_init_type_reply;

		/*
		 * In InitTypeReply, check if NoLoadReply ==
		 * PreserveContentReply == 0, in which case, verify Pkey/GID0.
		 */
		if (((itreply & SM_INIT_TYPE_REPLY_NO_LOAD_REPLY) == 0) &&
		    ((itreply & SM_INIT_TYPE_PRESERVE_CONTENT_REPLY) == 0) &&
		    (!badup)) {
			/*
			 * Check that the subnet part of GID0 has not changed.
			 */
			if (bcmp(port_infop->p_sgid_tbl, &state->id_sgid,
			    sizeof (ib_gid_t)) != 0)
				badup = B_TRUE;

			/*
			 * Check that Pkey/index mapping is still valid.
			 */
			if ((port_infop->p_pkey_tbl_sz <= state->id_pkix) ||
			    (port_infop->p_pkey_tbl[state->id_pkix] !=
			    state->id_pkey))
				badup = B_TRUE;
		}

		/*
		 * In InitTypeReply, if PreservePresenceReply indicates the SM
		 * has ensured that the port's presence in mcg, traps etc is
		 * intact, nothing more to do.
		 */
		opcode = IBD_LINK_UP_ABSENT;
		if ((itreply & SM_INIT_TYPE_PRESERVE_PRESENCE_REPLY) ==
		    SM_INIT_TYPE_PRESERVE_PRESENCE_REPLY)
			opcode = IBD_LINK_UP;

		if (badup)
			code = IBT_ERROR_PORT_DOWN;
		ibt_free_portinfo(port_infop, port_infosz);
	}

	if (!ibd_async_safe(state)) {
		state->id_link_state = ((code == IBT_EVENT_PORT_UP) ?
		    LINK_STATE_UP : LINK_STATE_DOWN);
		mutex_exit(&state->id_link_mutex);
		return;
	}
	mutex_exit(&state->id_link_mutex);

	if (code == IBT_ERROR_PORT_DOWN)
		opcode = IBD_LINK_DOWN;

	req = kmem_cache_alloc(state->id_req_kmc, KM_SLEEP);
	req->rq_ptr = (void *)opcode;
	ibd_queue_work_slot(state, req, IBD_ASYNC_LINK);
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
	case IBT_ERROR_PORT_DOWN:
	case IBT_EVENT_PORT_UP:
		/*
		 * Events will be delivered to all instances that have
		 * done ibt_open_hca() but not yet done ibt_close_hca().
		 * Only need to do work for our port; IBTF will deliver
		 * events for other ports on the hca we have ibt_open_hca'ed
		 * too. Note that ibd_drv_init() initializes id_port before
		 * doing ibt_open_hca().
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

/*
 * Attach device to the IO framework.
 */
static int
ibd_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	mac_register_t *macp;
	ibd_state_t *state;
	int instance;
	int err;

	switch (cmd) {
		case DDI_ATTACH:
			break;
		case DDI_RESUME:
			/* This driver does not support resume */
		default:
			return (DDI_FAILURE);
	}

	/*
	 * Allocate soft device data structure
	 */
	instance = ddi_get_instance(dip);
	if (ddi_soft_state_zalloc(ibd_list, instance) == DDI_FAILURE)
		return (DDI_FAILURE);
	state = ddi_get_soft_state(ibd_list, instance);

	/* pre ibt_attach() soft state initialization */
	if (ibd_state_init(state, dip) != DDI_SUCCESS) {
		DPRINT(10, "ibd_attach : failed in ibd_state_init()");
		goto attach_fail_state_init;
	}

	/* alloc rx soft intr */
	if ((ibd_rx_softintr == 1) &&
	    ddi_add_softintr(dip, DDI_SOFTINT_LOW, &state->id_rx,
	    NULL, NULL, ibd_intr, (caddr_t)state) != DDI_SUCCESS) {
		DPRINT(10, "ibd_attach : failed in ddi_add_softintr()");
		goto attach_fail_ddi_add_rx_softintr;
	}

	/* alloc tx soft intr */
	if ((ibd_tx_softintr == 1) &&
	    ddi_add_softintr(dip, DDI_SOFTINT_LOW, &state->id_tx,
	    NULL, NULL, ibd_tx_recycle, (caddr_t)state) != DDI_SUCCESS) {
		DPRINT(10, "ibd_attach : failed in ddi_add_softintr()");
		goto attach_fail_ddi_add_tx_softintr;
	}

	/* "attach" to IBTL */
	if (ibt_attach(&ibd_clnt_modinfo, dip, state,
	    &state->id_ibt_hdl) != IBT_SUCCESS) {
		DPRINT(10, "ibd_attach : failed in ibt_attach()");
		goto attach_fail_ibt_attach;
	}

	/* Finish initializing this driver */
	if (ibd_drv_init(state) != DDI_SUCCESS) {
		DPRINT(10, "ibd_attach : failed in ibd_drv_init()\n");
		goto attach_fail_drv_init;
	}

	/*
	 * Initialize pointers to device specific functions which will be
	 * used by the generic layer.
	 */
	if ((macp = mac_alloc(MAC_VERSION)) == NULL) {
		DPRINT(10, "ibd_attach : failed in mac_alloc()");
		goto attach_fail_drv_init;
	}

	macp->m_type_ident = MAC_PLUGIN_IDENT_IB;
	macp->m_driver = state;
	macp->m_dip = state->id_dip;
	macp->m_src_addr = (uint8_t *)&state->id_macaddr;
	macp->m_callbacks = &ib_m_callbacks;
	macp->m_min_sdu = 0;
	macp->m_max_sdu = state->id_mtu - IPOIB_HDRSIZE;

	/*
	 *  Register ourselves with the GLDv3 interface
	 */
	err = mac_register(macp, &state->id_mh);
	mac_free(macp);
	if (err != 0) {
		DPRINT(10, "ibd_attach : failed in mac_register()");
		goto attach_fail_mac_register;
	}

	/*
	 * Setup the handler we will use for regular DLPI stuff. Its important
	 * to setup the recv handler after registering with gldv3.
	 */
	ibt_set_cq_handler(state->id_rcq_hdl, ibd_rcq_handler, state);
	if (ibt_enable_cq_notify(state->id_rcq_hdl, IBT_NEXT_COMPLETION) !=
	    IBT_SUCCESS) {
		DPRINT(10, "ibd_attach : failed in ibt_enable_cq_notify()\n");
		goto attach_fail_setup_handler;
	}

	/*
	 * Setup the subnet notices handler after we initialize the a/mcaches
	 * and start the async thread, both of which are required for the
	 * trap handler to function properly. Enable the trap handler to
	 * queue requests to the async thread after the mac_register, because
	 * the async daemon invokes mac_tx_update(), which must be done after
	 * mac_register().
	 */
	ibt_register_subnet_notices(state->id_ibt_hdl,
	    ibd_snet_notices_handler, state);
	mutex_enter(&state->id_trap_lock);
	state->id_trap_stop = B_FALSE;
	mutex_exit(&state->id_trap_lock);

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

	return (DDI_SUCCESS);

	/* Attach failure points, cleanup */
attach_fail_setup_handler:
	(void) mac_unregister(state->id_mh);

attach_fail_mac_register:
	ibd_drv_fini(state);

attach_fail_drv_init:
	if (ibt_detach(state->id_ibt_hdl) != IBT_SUCCESS)
		ibd_print_warn(state, "failed to free IB resources");

attach_fail_ibt_attach:
	if (ibd_tx_softintr == 1)
		ddi_remove_softintr(state->id_tx);

attach_fail_ddi_add_tx_softintr:
	if (ibd_rx_softintr == 1)
		ddi_remove_softintr(state->id_rx);

attach_fail_ddi_add_rx_softintr:
	ibd_state_fini(state);

attach_fail_state_init:
	ddi_soft_state_free(ibd_list, instance);

	return (DDI_FAILURE);
}

/*
 * Detach device from the IO framework.
 */
static int
ibd_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	ibd_state_t *state;
	int status;
	int instance;

	switch (cmd) {
		case DDI_DETACH:
			break;
		case DDI_SUSPEND:
		default:
			return (DDI_FAILURE);
	}

	instance = ddi_get_instance(dip);
	state = ddi_get_soft_state(ibd_list, instance);

	/*
	 * First, stop receive interrupts; this stops the
	 * driver from handing up buffers to higher layers.
	 * Wait for receive buffers to be returned; give up
	 * after 5 seconds.
	 */
	ibt_set_cq_handler(state->id_rcq_hdl, 0, 0);
	status = 50;
	while (state->id_rx_list.dl_bufs_outstanding > 0) {
		delay(drv_usectohz(100000));
		if (--status == 0) {
			DPRINT(2, "ibd_detach : reclaiming failed");
			goto failed;
		}
	}

	if (mac_unregister(state->id_mh) != DDI_SUCCESS) {
		DPRINT(10, "ibd_detach : failed in mac_unregister()");
		goto failed;
	}

	if (ibd_rx_softintr == 1)
		ddi_remove_softintr(state->id_rx);

	if (ibd_tx_softintr == 1)
		ddi_remove_softintr(state->id_tx);

	ibd_drv_fini(state);

	if (ibt_detach(state->id_ibt_hdl) != IBT_SUCCESS)
		ibd_print_warn(state, "failed to free all IB resources at "
		    "driver detach time");

	ibd_state_fini(state);
	ddi_soft_state_free(ibd_list, instance);
	return (DDI_SUCCESS);

failed:
	/*
	 * Reap all the Tx/Rx completions that were posted since we
	 * turned off the notification. Turn on notifications. There
	 * is a race in that we do not reap completions that come in
	 * after the poll and before notifications get turned on. That
	 * is okay, the next rx/tx packet will trigger a completion
	 * that will reap any missed completions.
	 */
	ibd_poll_compq(state, state->id_rcq_hdl);
	ibt_set_cq_handler(state->id_rcq_hdl, ibd_rcq_handler, state);
	return (DDI_FAILURE);
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

	mutex_init(&state->id_cq_poll_lock, NULL, MUTEX_DRIVER, NULL);
	state->id_dip = dip;

	mutex_init(&state->id_sched_lock, NULL, MUTEX_DRIVER, NULL);

	state->id_tx_list.dl_head = NULL;
	state->id_tx_list.dl_tail = NULL;
	state->id_tx_list.dl_pending_sends = B_FALSE;
	state->id_tx_list.dl_cnt = 0;
	mutex_init(&state->id_tx_list.dl_mutex, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&state->id_txpost_lock, NULL, MUTEX_DRIVER, NULL);
	state->id_tx_busy = 0;

	state->id_rx_list.dl_head = NULL;
	state->id_rx_list.dl_tail = NULL;
	state->id_rx_list.dl_bufs_outstanding = 0;
	state->id_rx_list.dl_cnt = 0;
	mutex_init(&state->id_rx_list.dl_mutex, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&state->id_rxpost_lock, NULL, MUTEX_DRIVER, NULL);

	(void) sprintf(buf, "ibd_req%d", ddi_get_instance(dip));
	state->id_req_kmc = kmem_cache_create(buf, sizeof (ibd_req_t),
	    0, NULL, NULL, NULL, NULL, NULL, 0);

#ifdef IBD_LOGGING
	mutex_init(&ibd_lbuf_lock, NULL, MUTEX_DRIVER, NULL);
#endif

	return (DDI_SUCCESS);
}

/*
 * Post ibt_detach() driver deconstruction
 */
static void
ibd_state_fini(ibd_state_t *state)
{
	kmem_cache_destroy(state->id_req_kmc);

	mutex_destroy(&state->id_rxpost_lock);
	mutex_destroy(&state->id_rx_list.dl_mutex);

	mutex_destroy(&state->id_txpost_lock);
	mutex_destroy(&state->id_tx_list.dl_mutex);

	mutex_destroy(&state->id_sched_lock);
	mutex_destroy(&state->id_cq_poll_lock);

	cv_destroy(&state->id_trap_cv);
	mutex_destroy(&state->id_trap_lock);
	mutex_destroy(&state->id_link_mutex);

#ifdef IBD_LOGGING
	mutex_destroy(&ibd_lbuf_lock);
#endif
}

/*
 * Fetch IBA parameters for the network device from IB nexus.
 */
static int
ibd_get_portpkey(ibd_state_t *state, ib_guid_t *hca_guid)
{
	/*
	 * Get the IBA Pkey ... allow only fullmembers, per IPoIB spec.
	 * Note that the default partition is also allowed.
	 */
	state->id_pkey = ddi_prop_get_int(DDI_DEV_T_ANY, state->id_dip,
	    0, "port-pkey", IB_PKEY_INVALID_LIMITED);
	if (state->id_pkey <= IB_PKEY_INVALID_FULL) {
		DPRINT(10, "ibd_get_portpkey : ERROR: IBport device has wrong"
		    "partition\n");
		return (DDI_FAILURE);
	}

	/*
	 * ... the IBA port ...
	 */
	state->id_port = ddi_prop_get_int(DDI_DEV_T_ANY, state->id_dip,
	    0, "port-number", 0);
	if (state->id_port == 0) {
		DPRINT(10, "ibd_get_portpkey : ERROR: invalid port number\n");
		return (DDI_FAILURE);
	}

	/*
	 * ... and HCA GUID.
	 */
	*hca_guid = ddi_prop_get_int64(DDI_DEV_T_ANY, state->id_dip,
	    0, "hca-guid", 0);
	if (*hca_guid == 0) {
		DPRINT(10, "ibd_get_portpkey : ERROR: IBport hca has wrong "
		    "guid\n");
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
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

	if (ibd_iba_join(state, mgid, mce) != IBT_SUCCESS)
		ibd_print_warn(state, "Failure on port up to rejoin "
		    "multicast gid %016llx:%016llx",
		    (u_longlong_t)mgid.gid_prefix,
		    (u_longlong_t)mgid.gid_guid);
}

/*
 * This code handles delayed Tx completion cleanups for mcg's to which
 * disable_multicast has been issued, regular mcg related cleanups during
 * disable_multicast, disable_promiscous and mcg traps, as well as
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
		if (mce == NULL)
			return;
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
			    IB_MC_JSTATE_FULL))
				return;
			ASSERT(mce->mc_jstate == IB_MC_JSTATE_SEND_ONLY_NON);
		} else {
			ASSERT(jstate == IB_MC_JSTATE_FULL);

			/*
			 * If join group failed, mce will be NULL here.
			 * This is because in GLDv3 driver, set multicast
			 *  will always return success.
			 */
			if (mce == NULL)
				return;

			ASSERT(mce->mc_jstate == IB_MC_JSTATE_FULL);

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

	bzero(&mcg_attr, sizeof (ibt_mcg_attr_t));
	mcg_attr.mc_pkey = state->id_pkey;
	state->id_mgid.gid_guid = IB_MGID_IPV4_LOWGRP_MASK;

	for (i = 0; i < sizeof (scopes)/sizeof (scopes[0]); i++) {
		state->id_scope = mcg_attr.mc_scope = scopes[i];

		/*
		 * Look for the IPoIB broadcast group.
		 */
		state->id_mgid.gid_prefix =
		    (((uint64_t)IB_MCGID_IPV4_PREFIX << 32) |
		    ((uint64_t)state->id_scope << 48) |
		    ((uint32_t)(state->id_pkey << 16)));
		mcg_attr.mc_mgid = state->id_mgid;
		if (ibt_query_mcg(state->id_sgid, &mcg_attr, 1,
		    &state->id_mcinfo, &numg) == IBT_SUCCESS) {
			found = B_TRUE;
			break;
		}

	}

	if (!found) {
		ibd_print_warn(state, "IPoIB broadcast group absent");
		return (IBT_FAILURE);
	}

	/*
	 * Assert that the mcg mtu <= id_mtu. Fill in updated id_mtu.
	 */
	mcgmtu = (128 << state->id_mcinfo->mc_mtu);
	if (state->id_mtu < mcgmtu) {
		ibd_print_warn(state, "IPoIB broadcast group MTU %d "
		    "greater than port's maximum MTU %d", mcgmtu,
		    state->id_mtu);
		return (IBT_FAILURE);
	}
	state->id_mtu = mcgmtu;

	return (IBT_SUCCESS);
}

/*
 * Post ibt_attach() initialization.
 */
static int
ibd_drv_init(ibd_state_t *state)
{
	kthread_t *kht;
	ibt_ud_chan_alloc_args_t ud_alloc_attr;
	ibt_ud_chan_query_attr_t ud_chan_attr;
	ibt_hca_portinfo_t *port_infop;
	ibt_hca_attr_t hca_attrs;
	ibt_status_t ibt_status;
	ibt_cq_attr_t cq_attr;
	ib_guid_t hca_guid;
	uint32_t real_size;
	uint32_t *ptr;
	char pathname[OBP_MAXPATHLEN];
	uint_t psize, port_infosz;

	/*
	 * Initialize id_port before ibt_open_hca because of
	 * ordering requirements in port up/down handling.
	 */
	if (ibd_get_portpkey(state, &hca_guid) != DDI_SUCCESS)
		return (DDI_FAILURE);

	if (ibt_open_hca(state->id_ibt_hdl, hca_guid,
	    &state->id_hca_hdl) != IBT_SUCCESS) {
		DPRINT(10, "ibd_drv_init : failed in ibt_open_hca()\n");
		return (DDI_FAILURE);
	}

	mutex_enter(&state->id_link_mutex);
	ibt_status = ibt_query_hca_ports(state->id_hca_hdl,
	    state->id_port, &port_infop, &psize,
	    &port_infosz);
	if ((ibt_status != IBT_SUCCESS) || (psize != 1)) {
		mutex_exit(&state->id_link_mutex);
		DPRINT(10, "ibd_drv_init : failed in ibt_query_port()\n");
		(void) ibt_close_hca(state->id_hca_hdl);
		return (DDI_FAILURE);
	}

	/*
	 * If the link already went down by the time we get here, give up;
	 * we can not even get the gid since that is not valid. We would
	 * fail in ibd_find_bgroup() anyway.
	 */
	if (port_infop->p_linkstate != IBT_PORT_ACTIVE) {
		mutex_exit(&state->id_link_mutex);
		ibt_free_portinfo(port_infop, port_infosz);
		(void) ibt_close_hca(state->id_hca_hdl);
		ibd_print_warn(state, "Port is not active");
		return (DDI_FAILURE);
	}

	/*
	 * This verifies the Pkey ibnexus handed us is still valid.
	 * This is also the point from which the pkey table for the
	 * port must hold the exact pkey value at the exact index
	 * across port up/downs.
	 */
	if (ibt_pkey2index(state->id_hca_hdl, state->id_port,
	    state->id_pkey, &state->id_pkix) != IBT_SUCCESS) {
		mutex_exit(&state->id_link_mutex);
		ibt_free_portinfo(port_infop, port_infosz);
		DPRINT(10, "ibd_drv_init : failed in ibt_pkey2index()\n");
		(void) ibt_close_hca(state->id_hca_hdl);
		return (DDI_FAILURE);
	}

	state->id_mtu = (128 << port_infop->p_mtu);
	state->id_sgid = *port_infop->p_sgid_tbl;
	state->id_link_state = LINK_STATE_UP;
	mutex_exit(&state->id_link_mutex);

	ibt_free_portinfo(port_infop, port_infosz);

	state->id_link_speed = ibd_get_portspeed(state);

	/*
	 * Read drv conf and record what the policy is on enabling LSO
	 */
	if (ddi_prop_get_int(DDI_DEV_T_ANY, state->id_dip,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, IBD_PROP_LSO_POLICY, 1)) {
		state->id_lso_policy = B_TRUE;
	} else {
		state->id_lso_policy = B_FALSE;
	}

	ibt_status = ibt_query_hca(state->id_hca_hdl, &hca_attrs);
	ASSERT(ibt_status == IBT_SUCCESS);

	if (ibd_find_bgroup(state) != IBT_SUCCESS) {
		DPRINT(10, "ibd_drv_init : failed in ibd_find_bgroup\n");
		goto drv_init_fail_find_bgroup;
	}

	if (ibt_alloc_pd(state->id_hca_hdl, IBT_PD_NO_FLAGS,
	    &state->id_pd_hdl) != IBT_SUCCESS) {
		DPRINT(10, "ibd_drv_init : failed in ibt_alloc_pd()\n");
		goto drv_init_fail_alloc_pd;
	}

	/* Initialize the parallel ARP cache and AHs */
	if (ibd_acache_init(state) != DDI_SUCCESS) {
		DPRINT(10, "ibd_drv_init : failed in ibd_acache_init()\n");
		goto drv_init_fail_acache;
	}

	if ((hca_attrs.hca_flags2 & IBT_HCA2_RES_LKEY) == IBT_HCA2_RES_LKEY) {
		state->id_hca_res_lkey_capab = 1;
		state->id_res_lkey = hca_attrs.hca_reserved_lkey;
	}

	/*
	 * Check various tunable limits.
	 */

	/*
	 * See if extended sgl size information is provided by the hca; if yes,
	 * use the correct one and set the maximum sqseg value.
	 */
	if (hca_attrs.hca_flags & IBT_HCA_WQE_SIZE_INFO)
		state->id_max_sqseg = hca_attrs.hca_ud_send_sgl_sz;
	else
		state->id_max_sqseg = hca_attrs.hca_max_sgl;

	/*
	 * Set LSO capability and maximum length
	 */
	if (hca_attrs.hca_max_lso_size > 0) {
		state->id_lso_capable = B_TRUE;
		if (hca_attrs.hca_max_lso_size > IBD_LSO_MAXLEN)
			state->id_lso_maxlen = IBD_LSO_MAXLEN;
		else
			state->id_lso_maxlen = hca_attrs.hca_max_lso_size;
	} else {
		state->id_lso_capable = B_FALSE;
		state->id_lso_maxlen = 0;
	}


	/*
	 * Check #r/s wqes against max channel size.
	 */
	if (hca_attrs.hca_max_chan_sz < IBD_NUM_RWQE)
		state->id_num_rwqe = hca_attrs.hca_max_chan_sz;
	else
		state->id_num_rwqe = IBD_NUM_RWQE;

	if (hca_attrs.hca_max_chan_sz < IBD_NUM_SWQE)
		state->id_num_swqe = hca_attrs.hca_max_chan_sz;
	else
		state->id_num_swqe = IBD_NUM_SWQE;

	/*
	 * Check the hardware checksum capability. Currently we only consider
	 * full checksum offload.
	 */
	if ((hca_attrs.hca_flags & IBT_HCA_CKSUM_FULL) == IBT_HCA_CKSUM_FULL) {
		state->id_hwcksum_capab = IBT_HCA_CKSUM_FULL;
	}

	/*
	 * Allocate Rx/combined CQ:
	 * Theoretically, there is no point in having more than #rwqe
	 * plus #swqe cqe's, except that the CQ will be signalled for
	 * overflow when the last wqe completes, if none of the previous
	 * cqe's have been polled. Thus, we allocate just a few less wqe's
	 * to make sure such overflow does not occur.
	 */
	cq_attr.cq_sched = NULL;
	cq_attr.cq_flags = IBT_CQ_NO_FLAGS;

	if (ibd_separate_cqs == 1) {
		/*
		 * Allocate Receive CQ.
		 */
		if (hca_attrs.hca_max_cq_sz >= (state->id_num_rwqe + 1)) {
			cq_attr.cq_size = state->id_num_rwqe + 1;
		} else {
			cq_attr.cq_size = hca_attrs.hca_max_cq_sz;
			state->id_num_rwqe = cq_attr.cq_size - 1;
		}

		if (ibt_alloc_cq(state->id_hca_hdl, &cq_attr,
		    &state->id_rcq_hdl, &real_size) != IBT_SUCCESS) {
			DPRINT(10, "ibd_drv_init : failed in ibt_alloc_cq()\n");
			goto drv_init_fail_alloc_rcq;
		}

		if (ibt_modify_cq(state->id_rcq_hdl,
		    ibd_rxcomp_count, ibd_rxcomp_usec, 0) != IBT_SUCCESS) {
			DPRINT(10, "ibd_drv_init: Receive CQ interrupt "
			    "moderation failed\n");
		}

		state->id_rxwcs_size = state->id_num_rwqe + 1;
		state->id_rxwcs = kmem_alloc(sizeof (ibt_wc_t) *
		    state->id_rxwcs_size, KM_SLEEP);

		/*
		 * Allocate Send CQ.
		 */
		if (hca_attrs.hca_max_cq_sz >= (state->id_num_swqe + 1)) {
			cq_attr.cq_size = state->id_num_swqe + 1;
		} else {
			cq_attr.cq_size = hca_attrs.hca_max_cq_sz;
			state->id_num_swqe = cq_attr.cq_size - 1;
		}

		if (ibt_alloc_cq(state->id_hca_hdl, &cq_attr,
		    &state->id_scq_hdl, &real_size) != IBT_SUCCESS) {
			DPRINT(10, "ibd_drv_init : failed in ibt_alloc_cq()\n");
			goto drv_init_fail_alloc_scq;
		}
		if (ibt_modify_cq(state->id_scq_hdl,
		    10, 300, 0) != IBT_SUCCESS) {
			DPRINT(10, "ibd_drv_init: Send CQ interrupt "
			    "moderation failed\n");
		}

		state->id_txwcs_size = state->id_num_swqe + 1;
		state->id_txwcs = kmem_alloc(sizeof (ibt_wc_t) *
		    state->id_txwcs_size, KM_SLEEP);
	} else {
		/*
		 * Allocate combined Send/Receive CQ.
		 */
		if (hca_attrs.hca_max_cq_sz >= (state->id_num_rwqe +
		    state->id_num_swqe + 1)) {
			cq_attr.cq_size = state->id_num_rwqe +
			    state->id_num_swqe + 1;
		} else {
			cq_attr.cq_size = hca_attrs.hca_max_cq_sz;
			state->id_num_rwqe = ((cq_attr.cq_size - 1) *
			    state->id_num_rwqe) / (state->id_num_rwqe +
			    state->id_num_swqe);
			state->id_num_swqe = cq_attr.cq_size - 1 -
			    state->id_num_rwqe;
		}

		state->id_rxwcs_size = cq_attr.cq_size;
		state->id_txwcs_size = state->id_rxwcs_size;

		if (ibt_alloc_cq(state->id_hca_hdl, &cq_attr,
		    &state->id_rcq_hdl, &real_size) != IBT_SUCCESS) {
			DPRINT(10, "ibd_drv_init : failed in ibt_alloc_cq()\n");
			goto drv_init_fail_alloc_rcq;
		}
		state->id_scq_hdl = state->id_rcq_hdl;
		state->id_rxwcs = kmem_alloc(sizeof (ibt_wc_t) *
		    state->id_rxwcs_size, KM_SLEEP);
		state->id_txwcs = state->id_rxwcs;
	}

	/*
	 * Print message in case we could not allocate as many wqe's
	 * as was requested. Note that in the combined CQ case, we will
	 * get the following message.
	 */
	if (state->id_num_rwqe != IBD_NUM_RWQE)
		ibd_print_warn(state, "Setting #rwqe = %d instead of default "
		    "%d", state->id_num_rwqe, IBD_NUM_RWQE);
	if (state->id_num_swqe != IBD_NUM_SWQE)
		ibd_print_warn(state, "Setting #swqe = %d instead of default "
		    "%d", state->id_num_swqe, IBD_NUM_SWQE);

	ud_alloc_attr.ud_flags  = IBT_WR_SIGNALED;
	if (state->id_hca_res_lkey_capab)
		ud_alloc_attr.ud_flags |= IBT_FAST_REG_RES_LKEY;
	if (state->id_lso_policy && state->id_lso_capable)
		ud_alloc_attr.ud_flags |= IBT_USES_LSO;

	ud_alloc_attr.ud_hca_port_num	= state->id_port;
	ud_alloc_attr.ud_sizes.cs_sq_sgl = state->id_max_sqseg;
	ud_alloc_attr.ud_sizes.cs_rq_sgl = IBD_MAX_RQSEG;
	ud_alloc_attr.ud_sizes.cs_sq	= state->id_num_swqe;
	ud_alloc_attr.ud_sizes.cs_rq	= state->id_num_rwqe;
	ud_alloc_attr.ud_qkey		= state->id_mcinfo->mc_qkey;
	ud_alloc_attr.ud_scq		= state->id_scq_hdl;
	ud_alloc_attr.ud_rcq		= state->id_rcq_hdl;
	ud_alloc_attr.ud_pd		= state->id_pd_hdl;
	ud_alloc_attr.ud_pkey_ix	= state->id_pkix;
	ud_alloc_attr.ud_clone_chan	= NULL;

	if (ibt_alloc_ud_channel(state->id_hca_hdl, IBT_ACHAN_NO_FLAGS,
	    &ud_alloc_attr, &state->id_chnl_hdl, NULL) != IBT_SUCCESS) {
		DPRINT(10, "ibd_drv_init : failed in ibt_alloc_ud_channel()"
		    "\n");
		goto drv_init_fail_alloc_chan;
	}

	if (ibt_query_ud_channel(state->id_chnl_hdl, &ud_chan_attr) !=
	    DDI_SUCCESS) {
		DPRINT(10, "ibd_drv_init : failed in ibt_query_ud_channel()");
		goto drv_init_fail_query_chan;
	}

	state->id_qpnum = ud_chan_attr.ud_qpn;
	/* state->id_max_sqseg = ud_chan_attr.ud_chan_sizes.cs_sq_sgl; */

	if (state->id_max_sqseg > IBD_MAX_SQSEG) {
		state->id_max_sqseg = IBD_MAX_SQSEG;
	} else if (state->id_max_sqseg < IBD_MAX_SQSEG) {
		ibd_print_warn(state, "Set #sgl = %d instead of default %d",
		    state->id_max_sqseg, IBD_MAX_SQSEG);
	}

	/* Initialize the Transmit buffer list */
	if (ibd_init_txlist(state) != DDI_SUCCESS) {
		DPRINT(10, "ibd_drv_init : failed in ibd_init_txlist()\n");
		goto drv_init_fail_txlist_init;
	}

	if ((ibd_separate_cqs == 1) && (ibd_txcomp_poll == 0)) {
		/*
		 * Setup the handler we will use for regular DLPI stuff
		 */
		ibt_set_cq_handler(state->id_scq_hdl, ibd_scq_handler, state);
		if (ibt_enable_cq_notify(state->id_scq_hdl,
		    IBT_NEXT_COMPLETION) != IBT_SUCCESS) {
			DPRINT(10, "ibd_drv_init : failed in"
			    " ibt_enable_cq_notify()\n");
			goto drv_init_fail_cq_notify;
		}
	}

	/* Initialize the Receive buffer list */
	if (ibd_init_rxlist(state) != DDI_SUCCESS) {
		DPRINT(10, "ibd_drv_init : failed in ibd_init_rxlist()\n");
		goto drv_init_fail_rxlist_init;
	}

	/* Join to IPoIB broadcast group as required by IPoIB */
	if (ibd_join_group(state, state->id_mgid, IB_MC_JSTATE_FULL) == NULL) {
		DPRINT(10, "ibd_drv_init : failed in ibd_join_group\n");
		goto drv_init_fail_join_group;
	}

	/*
	 * Create the async thread; thread_create never fails.
	 */
	kht = thread_create(NULL, 0, ibd_async_work, state, 0, &p0,
	    TS_RUN, minclsyspri);

	state->id_async_thrid = kht->t_did;

	/*
	 * The local mac address is now known. Create the IPoIB
	 * address.
	 */
	ibd_h2n_mac(&state->id_macaddr, state->id_qpnum,
	    state->id_sgid.gid_prefix, state->id_sgid.gid_guid);
	/*
	 * Similarly, program in the broadcast mac address.
	 */
	ibd_h2n_mac(&state->id_bcaddr, IB_QPN_MASK, state->id_mgid.gid_prefix,
	    state->id_mgid.gid_guid);

	ptr = (uint32_t *)&state->id_macaddr;
	DPRINT(10, "ibd_drv_init : INFO: MAC %08X:%08X:%08X:%08X:%08X\n",
	    *ptr, *(ptr+1), *(ptr+2), *(ptr+3), *(ptr+4));
	ptr = (uint32_t *)&state->id_bcaddr;
	DPRINT(10, "ibd_drv_init : INFO: BCMAC %08X:%08X:%08X:%08X:%08X\n",
	    *ptr, *(ptr+1), *(ptr+2), *(ptr+3), *(ptr+4));
	DPRINT(10, "ibd_drv_init : INFO: Pkey 0x%x, Mgid %016llx%016llx\n",
	    state->id_pkey, state->id_mgid.gid_prefix,
	    state->id_mgid.gid_guid);
	DPRINT(10, "ibd_drv_init : INFO: GID %016llx%016llx\n",
	    state->id_sgid.gid_prefix, state->id_sgid.gid_guid);
	DPRINT(10, "ibd_drv_init : INFO: PKEY %04x\n", state->id_pkey);
	DPRINT(10, "ibd_drv_init : INFO: MTU %d\n", state->id_mtu);
	(void) ddi_pathname(state->id_dip, pathname);
	DPRINT(10, "ibd_drv_init : INFO: Pathname %s\n", pathname);

	return (DDI_SUCCESS);

drv_init_fail_join_group:
	ibd_fini_rxlist(state);

drv_init_fail_rxlist_init:
drv_init_fail_cq_notify:
	ibd_fini_txlist(state);

drv_init_fail_txlist_init:
drv_init_fail_query_chan:
	if (ibt_free_channel(state->id_chnl_hdl) != IBT_SUCCESS)
		DPRINT(10, "ibd_drv_init : failed in ibt_free_channel()");

drv_init_fail_alloc_chan:
	if ((ibd_separate_cqs == 1) && (ibt_free_cq(state->id_scq_hdl) !=
	    IBT_SUCCESS))
		DPRINT(10, "ibd_drv_init : Tx ibt_free_cq()");

	if (ibd_separate_cqs == 1)
		kmem_free(state->id_txwcs, sizeof (ibt_wc_t) *
		    state->id_txwcs_size);

drv_init_fail_alloc_scq:
	if (ibt_free_cq(state->id_rcq_hdl) != IBT_SUCCESS)
		DPRINT(10, "ibd_drv_init : Rx ibt_free_cq()");
	kmem_free(state->id_rxwcs, sizeof (ibt_wc_t) * state->id_rxwcs_size);

drv_init_fail_alloc_rcq:
	ibd_acache_fini(state);
drv_init_fail_acache:
	if (ibt_free_pd(state->id_hca_hdl, state->id_pd_hdl) != IBT_SUCCESS)
		DPRINT(10, "ibd_drv_init : failed in ibt_free_pd()");

drv_init_fail_alloc_pd:
	ibt_free_mcg_info(state->id_mcinfo, 1);
drv_init_fail_find_bgroup:
	if (ibt_close_hca(state->id_hca_hdl) != IBT_SUCCESS)
		DPRINT(10, "ibd_drv_init : failed in ibt_close_hca()");

	return (DDI_FAILURE);
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
	    (IBD_TX_BUF_SZ > state->id_mtu)) {
		state->id_tx_buf_sz = IBD_TX_BUF_SZ;
	}

	state->id_tx_bufs = kmem_zalloc(state->id_num_swqe *
	    state->id_tx_buf_sz, KM_SLEEP);

	/*
	 * Do one memory registration on the entire txbuf area
	 */
	mem_attr.mr_vaddr = (uint64_t)(uintptr_t)state->id_tx_bufs;
	mem_attr.mr_len = state->id_num_swqe * state->id_tx_buf_sz;
	mem_attr.mr_as = NULL;
	mem_attr.mr_flags = IBT_MR_SLEEP;
	if (ibt_register_mr(state->id_hca_hdl, state->id_pd_hdl, &mem_attr,
	    &state->id_tx_mr_hdl, &state->id_tx_mr_desc) != IBT_SUCCESS) {
		DPRINT(10, "ibd_alloc_tx_copybufs: ibt_register_mr failed");
		kmem_free(state->id_tx_bufs,
		    state->id_num_swqe * state->id_tx_buf_sz);
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
	memsz = IBD_NUM_LSO_BUFS * IBD_LSO_BUFSZ;
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

	/*
	 * Now allocate the buflist.  Note that the elements in the buflist and
	 * the buffers in the lso memory have a permanent 1-1 relation, so we
	 * can always derive the address of a buflist entry from the address of
	 * an lso buffer.
	 */
	buflist = kmem_zalloc(IBD_NUM_LSO_BUFS * sizeof (ibd_lsobuf_t),
	    KM_SLEEP);

	/*
	 * Set up the lso buf chain
	 */
	memp = membase;
	lbufp = buflist;
	for (i = 0; i < IBD_NUM_LSO_BUFS; i++) {
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
	bktp->bkt_nelem = IBD_NUM_LSO_BUFS;
	bktp->bkt_nfree = bktp->bkt_nelem;

	state->id_lso = bktp;

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

	if (ibd_alloc_tx_copybufs(state) != DDI_SUCCESS)
		return (DDI_FAILURE);

	if (state->id_lso_policy && state->id_lso_capable) {
		if (ibd_alloc_tx_lsobufs(state) != DDI_SUCCESS)
			state->id_lso_policy = B_FALSE;
	}

	/*
	 * Allocate and setup the swqe list
	 */
	lkey = state->id_tx_mr_desc.md_lkey;
	for (i = 0; i < state->id_num_swqe; i++) {
		if (ibd_alloc_swqe(state, &swqe, i, lkey) != DDI_SUCCESS) {
			DPRINT(10, "ibd_init_txlist: ibd_alloc_swqe failed");
			ibd_fini_txlist(state);
			return (DDI_FAILURE);
		}

		/* add to list */
		state->id_tx_list.dl_cnt++;
		if (state->id_tx_list.dl_head == NULL) {
			swqe->swqe_prev = NULL;
			swqe->swqe_next = NULL;
			state->id_tx_list.dl_head = SWQE_TO_WQE(swqe);
			state->id_tx_list.dl_tail = SWQE_TO_WQE(swqe);
		} else {
			swqe->swqe_prev = state->id_tx_list.dl_tail;
			swqe->swqe_next = NULL;
			state->id_tx_list.dl_tail->w_next = SWQE_TO_WQE(swqe);
			state->id_tx_list.dl_tail = SWQE_TO_WQE(swqe);
		}
	}

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
	kmem_free(state->id_tx_bufs, state->id_num_swqe * state->id_tx_buf_sz);
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
	ibd_swqe_t *node;

	/*
	 * Free the allocated swqes
	 */
	mutex_enter(&state->id_tx_list.dl_mutex);
	while (state->id_tx_list.dl_head != NULL) {
		node = WQE_TO_SWQE(state->id_tx_list.dl_head);
		state->id_tx_list.dl_head = node->swqe_next;
		state->id_tx_list.dl_cnt--;
		ASSERT(state->id_tx_list.dl_cnt >= 0);
		ibd_free_swqe(state, node);
	}
	mutex_exit(&state->id_tx_list.dl_mutex);

	ibd_free_tx_lsobufs(state);
	ibd_free_tx_copybufs(state);
}

/*
 * Allocate a single send wqe and register it so it is almost
 * ready to be posted to the hardware.
 */
static int
ibd_alloc_swqe(ibd_state_t *state, ibd_swqe_t **wqe, int ndx, ibt_lkey_t lkey)
{
	ibd_swqe_t *swqe;

	swqe = kmem_zalloc(sizeof (ibd_swqe_t), KM_SLEEP);
	*wqe = swqe;

	swqe->swqe_type = IBD_WQE_SEND;
	swqe->swqe_next = NULL;
	swqe->swqe_prev = NULL;
	swqe->swqe_im_mblk = NULL;

	swqe->swqe_copybuf.ic_sgl.ds_va = (ib_vaddr_t)(uintptr_t)
	    (state->id_tx_bufs + ndx * state->id_tx_buf_sz);
	swqe->swqe_copybuf.ic_sgl.ds_key = lkey;
	swqe->swqe_copybuf.ic_sgl.ds_len = 0; /* set in send */

	swqe->w_swr.wr_id = (ibt_wrid_t)(uintptr_t)swqe;
	swqe->w_swr.wr_flags = IBT_WR_SEND_SIGNAL;
	swqe->w_swr.wr_trans = IBT_UD_SRV;

	/* These are set in send */
	swqe->w_swr.wr_nds = 0;
	swqe->w_swr.wr_sgl = NULL;
	swqe->w_swr.wr_opcode = IBT_WRC_SEND;

	return (DDI_SUCCESS);
}

/*
 * Free an allocated send wqe.
 */
/*ARGSUSED*/
static void
ibd_free_swqe(ibd_state_t *state, ibd_swqe_t *swqe)
{
	kmem_free(swqe, sizeof (ibd_swqe_t));
}

/*
 * Post a rwqe to the hardware and add it to the Rx list. The
 * "recycle" parameter indicates whether an old rwqe is being
 * recycled, or this is a new one.
 */
static int
ibd_post_rwqe(ibd_state_t *state, ibd_rwqe_t *rwqe, boolean_t recycle)
{
	ibt_status_t ibt_status;

	if (recycle == B_FALSE) {
		mutex_enter(&state->id_rx_list.dl_mutex);
		if (state->id_rx_list.dl_head == NULL) {
			rwqe->rwqe_prev = NULL;
			rwqe->rwqe_next = NULL;
			state->id_rx_list.dl_head = RWQE_TO_WQE(rwqe);
			state->id_rx_list.dl_tail = RWQE_TO_WQE(rwqe);
		} else {
			rwqe->rwqe_prev = state->id_rx_list.dl_tail;
			rwqe->rwqe_next = NULL;
			state->id_rx_list.dl_tail->w_next = RWQE_TO_WQE(rwqe);
			state->id_rx_list.dl_tail = RWQE_TO_WQE(rwqe);
		}
		mutex_exit(&state->id_rx_list.dl_mutex);
	}

	mutex_enter(&state->id_rxpost_lock);
	if (state->id_rx_busy) {
		rwqe->w_post_link = NULL;
		if (state->id_rx_head)
			*(state->id_rx_tailp) = (ibd_wqe_t *)rwqe;
		else
			state->id_rx_head = rwqe;
		state->id_rx_tailp = &(rwqe->w_post_link);
	} else {
		state->id_rx_busy = 1;
		do {
			mutex_exit(&state->id_rxpost_lock);

			/*
			 * Here we should add dl_cnt before post recv, because
			 * we would have to make sure dl_cnt is updated before
			 * the corresponding ibd_process_rx() is called.
			 */
			atomic_add_32(&state->id_rx_list.dl_cnt, 1);

			ibt_status = ibt_post_recv(state->id_chnl_hdl,
			    &rwqe->w_rwr, 1, NULL);
			if (ibt_status != IBT_SUCCESS) {
				(void) atomic_add_32_nv(
				    &state->id_rx_list.dl_cnt, -1);
				ibd_print_warn(state, "ibd_post_rwqe: "
				    "posting failed, ret=%d", ibt_status);
				return (DDI_FAILURE);
			}

			mutex_enter(&state->id_rxpost_lock);
			rwqe = state->id_rx_head;
			if (rwqe) {
				state->id_rx_head =
				    (ibd_rwqe_t *)(rwqe->w_post_link);
			}
		} while (rwqe);
		state->id_rx_busy = 0;
	}
	mutex_exit(&state->id_rxpost_lock);

	return (DDI_SUCCESS);
}

/*
 * Allocate the statically allocated Rx buffer list.
 */
static int
ibd_init_rxlist(ibd_state_t *state)
{
	ibd_rwqe_t *rwqe;
	int i;

	for (i = 0; i < state->id_num_rwqe; i++) {
		if (ibd_alloc_rwqe(state, &rwqe) != DDI_SUCCESS) {
			ibd_fini_rxlist(state);
			return (DDI_FAILURE);
		}

		if (ibd_post_rwqe(state, rwqe, B_FALSE) == DDI_FAILURE) {
			ibd_free_rwqe(state, rwqe);
			ibd_fini_rxlist(state);
			return (DDI_FAILURE);
		}
	}

	return (DDI_SUCCESS);
}

/*
 * Free the statically allocated Rx buffer list.
 *
 */
static void
ibd_fini_rxlist(ibd_state_t *state)
{
	ibd_rwqe_t *node;

	mutex_enter(&state->id_rx_list.dl_mutex);
	while (state->id_rx_list.dl_head != NULL) {
		node = WQE_TO_RWQE(state->id_rx_list.dl_head);
		state->id_rx_list.dl_head = state->id_rx_list.dl_head->w_next;
		state->id_rx_list.dl_cnt--;
		ASSERT(state->id_rx_list.dl_cnt >= 0);

		ibd_free_rwqe(state, node);
	}
	mutex_exit(&state->id_rx_list.dl_mutex);
}

/*
 * Allocate a single recv wqe and register it so it is almost
 * ready to be posted to the hardware.
 */
static int
ibd_alloc_rwqe(ibd_state_t *state, ibd_rwqe_t **wqe)
{
	ibt_mr_attr_t mem_attr;
	ibd_rwqe_t *rwqe;

	if ((rwqe = kmem_zalloc(sizeof (ibd_rwqe_t), KM_NOSLEEP)) == NULL) {
		DPRINT(10, "ibd_alloc_rwqe: failed in kmem_alloc");
		return (DDI_FAILURE);
	}
	*wqe = rwqe;
	rwqe->rwqe_type = IBD_WQE_RECV;
	rwqe->w_state = state;
	rwqe->rwqe_next = NULL;
	rwqe->rwqe_prev = NULL;
	rwqe->w_freeing_wqe = B_FALSE;
	rwqe->w_freemsg_cb.free_func = ibd_freemsg_cb;
	rwqe->w_freemsg_cb.free_arg = (char *)rwqe;

	rwqe->rwqe_copybuf.ic_bufaddr = kmem_alloc(state->id_mtu +
	    IPOIB_GRH_SIZE, KM_NOSLEEP);
	if (rwqe->rwqe_copybuf.ic_bufaddr == NULL) {
		DPRINT(10, "ibd_alloc_rwqe: failed in kmem_alloc");
		kmem_free(rwqe, sizeof (ibd_rwqe_t));
		return (DDI_FAILURE);
	}

	if ((rwqe->rwqe_im_mblk = desballoc(rwqe->rwqe_copybuf.ic_bufaddr,
	    state->id_mtu + IPOIB_GRH_SIZE, 0, &rwqe->w_freemsg_cb)) ==
	    NULL) {
		DPRINT(10, "ibd_alloc_rwqe : failed in desballoc()");
		kmem_free(rwqe->rwqe_copybuf.ic_bufaddr,
		    state->id_mtu + IPOIB_GRH_SIZE);
		rwqe->rwqe_copybuf.ic_bufaddr = NULL;
		kmem_free(rwqe, sizeof (ibd_rwqe_t));
		return (DDI_FAILURE);
	}

	mem_attr.mr_vaddr = (uint64_t)(uintptr_t)rwqe->rwqe_copybuf.ic_bufaddr;
	mem_attr.mr_len = state->id_mtu + IPOIB_GRH_SIZE;
	mem_attr.mr_as = NULL;
	mem_attr.mr_flags = IBT_MR_NOSLEEP | IBT_MR_ENABLE_LOCAL_WRITE;
	if (ibt_register_mr(state->id_hca_hdl, state->id_pd_hdl, &mem_attr,
	    &rwqe->rwqe_copybuf.ic_mr_hdl, &rwqe->rwqe_copybuf.ic_mr_desc) !=
	    IBT_SUCCESS) {
		DPRINT(10, "ibd_alloc_rwqe : failed in ibt_register_mem()");
		rwqe->w_freeing_wqe = B_TRUE;
		freemsg(rwqe->rwqe_im_mblk);
		kmem_free(rwqe->rwqe_copybuf.ic_bufaddr,
		    state->id_mtu + IPOIB_GRH_SIZE);
		rwqe->rwqe_copybuf.ic_bufaddr = NULL;
		kmem_free(rwqe, sizeof (ibd_rwqe_t));
		return (DDI_FAILURE);
	}

	rwqe->rwqe_copybuf.ic_sgl.ds_va =
	    (ib_vaddr_t)(uintptr_t)rwqe->rwqe_copybuf.ic_bufaddr;
	rwqe->rwqe_copybuf.ic_sgl.ds_key =
	    rwqe->rwqe_copybuf.ic_mr_desc.md_lkey;
	rwqe->rwqe_copybuf.ic_sgl.ds_len = state->id_mtu + IPOIB_GRH_SIZE;
	rwqe->w_rwr.wr_id = (ibt_wrid_t)(uintptr_t)rwqe;
	rwqe->w_rwr.wr_nds = 1;
	rwqe->w_rwr.wr_sgl = &rwqe->rwqe_copybuf.ic_sgl;

	return (DDI_SUCCESS);
}

/*
 * Free an allocated recv wqe.
 */
static void
ibd_free_rwqe(ibd_state_t *state, ibd_rwqe_t *rwqe)
{
	if (ibt_deregister_mr(state->id_hca_hdl,
	    rwqe->rwqe_copybuf.ic_mr_hdl) != IBT_SUCCESS) {
		DPRINT(10, "ibd_free_rwqe: failed in ibt_deregister_mr()");
		return;
	}

	/*
	 * Indicate to the callback function that this rwqe/mblk
	 * should not be recycled. The freemsg() will invoke
	 * ibd_freemsg_cb().
	 */
	if (rwqe->rwqe_im_mblk != NULL) {
		rwqe->w_freeing_wqe = B_TRUE;
		freemsg(rwqe->rwqe_im_mblk);
	}
	kmem_free(rwqe->rwqe_copybuf.ic_bufaddr,
	    state->id_mtu + IPOIB_GRH_SIZE);
	rwqe->rwqe_copybuf.ic_bufaddr = NULL;
	kmem_free(rwqe, sizeof (ibd_rwqe_t));
}

/*
 * Delete the rwqe being freed from the rx list.
 */
static void
ibd_delete_rwqe(ibd_state_t *state, ibd_rwqe_t *rwqe)
{
	mutex_enter(&state->id_rx_list.dl_mutex);
	if (state->id_rx_list.dl_head == RWQE_TO_WQE(rwqe))
		state->id_rx_list.dl_head = rwqe->rwqe_next;
	else
		rwqe->rwqe_prev->w_next = rwqe->rwqe_next;
	if (state->id_rx_list.dl_tail == RWQE_TO_WQE(rwqe))
		state->id_rx_list.dl_tail = rwqe->rwqe_prev;
	else
		rwqe->rwqe_next->w_prev = rwqe->rwqe_prev;
	mutex_exit(&state->id_rx_list.dl_mutex);
}

/*
 * Pre ibt_detach() deconstruction.
 */
static void
ibd_drv_fini(ibd_state_t *state)
{
	ib_gid_t mgid;
	ibd_mce_t *mce;
	ibt_status_t status;
	uint8_t jstate;

	/*
	 * Desubscribe from trap notices; we will be tearing down
	 * the mcg lists soon. Make sure the trap handler does nothing
	 * even if it is invoked (ie till we invoke ibt_detach()).
	 */
	ibt_register_subnet_notices(state->id_ibt_hdl, NULL, NULL);
	mutex_enter(&state->id_trap_lock);
	state->id_trap_stop = B_TRUE;
	while (state->id_trap_inprog > 0)
		cv_wait(&state->id_trap_cv, &state->id_trap_lock);
	mutex_exit(&state->id_trap_lock);

	/*
	 * Flushing the channel ensures that all pending WQE's
	 * are marked with flush_error and handed to the CQ. It
	 * does not guarantee the invocation of the CQ handler.
	 * This call is guaranteed to return successfully for UD QPNs.
	 */
	status = ibt_flush_channel(state->id_chnl_hdl);
	ASSERT(status == IBT_SUCCESS);

	/*
	 * We possibly need a loop here to wait for all the Tx
	 * callbacks to happen. The Tx handlers will retrieve
	 * held resources like AH ac_ref count, registered memory
	 * and possibly IBD_ASYNC_REAP requests. Rx interrupts were already
	 * turned off (in ibd_detach()); turn off Tx interrupts and
	 * poll. By the time the polling returns an empty indicator,
	 * we are sure we have seen all pending Tx callbacks. Note
	 * that after the ibt_set_cq_handler() returns, the old handler
	 * is guaranteed not to be invoked anymore.
	 */
	if (ibd_separate_cqs == 1)
		ibt_set_cq_handler(state->id_scq_hdl, 0, 0);
	ibd_poll_compq(state, state->id_scq_hdl);

	/*
	 * No more async requests will be posted since the device has been
	 * unregistered; completion handlers have been turned off, so Tx
	 * handler will not cause any more IBD_ASYNC_REAP requests. Queue a
	 * request for the async thread to exit, which will be serviced
	 * after any pending ones. This can take a while, specially if the
	 * SM is unreachable, since IBMF will slowly timeout each SM request
	 * issued by the async thread. Reap the thread before continuing on,
	 * we do not want it to be lingering in modunloaded code.
	 */
	ibd_queue_work_slot(state, &state->id_ah_req, IBD_ASYNC_EXIT);
	thread_join(state->id_async_thrid);

	/*
	 * We can not be in promiscuous mode anymore, upper layers
	 * would have made a request to disable it (if ever set previously)
	 * before the detach is allowed to progress to this point; and the
	 * aysnc thread would have processed that request by now. Thus the
	 * nonmember list is guaranteed empty at this point.
	 */
	ASSERT(state->id_prom_op != IBD_OP_COMPLETED);

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
	DPRINT(2, "ibd_drv_fini : clear full cache entries");
	mce = list_head(&state->id_mc_full);
	while (mce != NULL) {
		mgid = mce->mc_info.mc_adds_vect.av_dgid;
		jstate = mce->mc_jstate;
		mce = list_next(&state->id_mc_full, mce);
		ibd_leave_group(state, mgid, jstate);
	}

	ibt_free_mcg_info(state->id_mcinfo, 1);

	/*
	 * Kill the channel now; guaranteed to return successfully
	 * for UD QPNs.
	 */
	status = ibt_free_channel(state->id_chnl_hdl);
	ASSERT(status == IBT_SUCCESS);

	/*
	 * Kill the CQ; all completion handlers are guaranteed to
	 * have terminated by the time this returns. Since we killed
	 * the QPN above, we can not receive the IBT_CQ_BUSY error.
	 */
	status = ibt_free_cq(state->id_rcq_hdl);
	ASSERT(status == IBT_SUCCESS);
	kmem_free(state->id_rxwcs, sizeof (ibt_wc_t) * state->id_rxwcs_size);

	if (ibd_separate_cqs == 1) {
		status = ibt_free_cq(state->id_scq_hdl);
		ASSERT(status == IBT_SUCCESS);
		kmem_free(state->id_txwcs, sizeof (ibt_wc_t) *
		    state->id_txwcs_size);
	}

	/*
	 * Since these following will act on the Rx/Tx list, which
	 * is also looked at by the Rx/Tx handlers, keep them around
	 * till all handlers are guaranteed to have completed.
	 */
	ibd_fini_rxlist(state);
	ibd_fini_txlist(state);

	/*
	 * Clean up the active AH hash list.
	 */
	mod_hash_destroy_hash(state->id_ah_active_hash);

	/*
	 * Free parallel ARP cache and AHs; we are sure all of these
	 * resources have been released by the Tx completion handler.
	 */
	ibd_acache_fini(state);

	/*
	 * We freed the QPN, all the MRs and AHs. This step should not
	 * fail; print a warning message if it does fail, due to a bug
	 * in the driver.
	 */
	if (ibt_free_pd(state->id_hca_hdl, state->id_pd_hdl) != IBT_SUCCESS)
		ibd_print_warn(state, "failed to free protection domain");

	if (ibt_close_hca(state->id_hca_hdl) != IBT_SUCCESS)
		ibd_print_warn(state, "failed to close HCA device");
}

/*
 * IBA Rx/Tx completion queue handler. Guaranteed to be single
 * threaded and nonreentrant for this CQ. When using combined CQ,
 * this handles Tx and Rx completions. With separate CQs, this handles
 * only Rx completions.
 */
/* ARGSUSED */
static void
ibd_rcq_handler(ibt_cq_hdl_t cq_hdl, void *arg)
{
	ibd_state_t *state = (ibd_state_t *)arg;

	atomic_add_64(&state->id_num_intrs, 1);

	if (ibd_rx_softintr == 1)
		ddi_trigger_softintr(state->id_rx);
	else
		(void) ibd_intr((char *)state);
}

/*
 * Separate CQ handler for Tx completions, when the Tx CQ is in
 * interrupt driven mode.
 */
/* ARGSUSED */
static void
ibd_scq_handler(ibt_cq_hdl_t cq_hdl, void *arg)
{
	ibd_state_t *state = (ibd_state_t *)arg;

	atomic_add_64(&state->id_num_intrs, 1);

	if (ibd_tx_softintr == 1)
		ddi_trigger_softintr(state->id_tx);
	else
		(void) ibd_tx_recycle((char *)state);
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
	 * evert port. The input "gid" is the GID0 of the port the
	 * trap came in on; we just need to act on traps that came
	 * to our port, meaning the port on which the ipoib interface
	 * resides. Since ipoib uses GID0 of the port, we just match
	 * the gids to check whether we need to handle the trap.
	 */
	if (bcmp(&gid, &state->id_sgid, sizeof (ib_gid_t)) != 0)
		return;

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
			 * Common processing of creation/deletion traps.
			 * First check if the instance is being
			 * [de]initialized; back off then, without doing
			 * anything more, since we are not sure if the
			 * async thread is around, or whether we might
			 * be racing with the detach code in ibd_drv_fini()
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

	DPRINT(10, "ibd_async_trap : %d\n", code);

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
 * GLDv3 entry point to start hardware.
 */
/*ARGSUSED*/
static int
ibd_m_start(void *arg)
{
	return (0);
}

/*
 * GLDv3 entry point to stop hardware from receiving packets.
 */
/*ARGSUSED*/
static void
ibd_m_stop(void *arg)
{
}

/*
 * GLDv3 entry point to modify device's mac address. We do not
 * allow address modifications.
 */
static int
ibd_m_unicst(void *arg, const uint8_t *macaddr)
{
	ibd_state_t *state;

	state = (ibd_state_t *)arg;
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
			ibd_print_warn(state, "Joint multicast group failed :"
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
	 * mcg, but since this operation is only invokable by priviledged
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
	 * nothing (ie we stay JOINed to the broadcast group done in
	 * ibd_drv_init()), to mimic ethernet behavior. IPv4 specifically
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
	int i, ret = IBD_OP_COMPLETED;

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
		*val = state->id_rcv_bytes;
		break;
	case MAC_STAT_IPACKETS:
		*val = state->id_rcv_pkt;
		break;
	case MAC_STAT_OBYTES:
		*val = state->id_xmt_bytes;
		break;
	case MAC_STAT_OPACKETS:
		*val = state->id_xmt_pkt;
		break;
	case MAC_STAT_OERRORS:
		*val = state->id_ah_error;	/* failed AH translation */
		break;
	case MAC_STAT_IERRORS:
		*val = 0;
		break;
	case MAC_STAT_NOXMTBUF:
		*val = state->id_tx_short;
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
	ibd_req_t *req;
	int ret;

	if (ibd_txcomp_poll)
		ibd_poll_compq(state, state->id_scq_hdl);

	ret = ibd_resume_transmission(state);
	if (ret && ibd_txcomp_poll) {
		if (req = kmem_cache_alloc(state->id_req_kmc, KM_NOSLEEP))
			ibd_queue_work_slot(state, req, IBD_ASYNC_SCHED);
		else {
			ibd_print_warn(state, "ibd_async_txsched: "
			    "no memory, can't schedule work slot");
		}
	}
}

static int
ibd_resume_transmission(ibd_state_t *state)
{
	int flag;
	int met_thresh = 0;
	int ret = -1;

	mutex_enter(&state->id_sched_lock);
	if (state->id_sched_needed & IBD_RSRC_SWQE) {
		met_thresh = (state->id_tx_list.dl_cnt >
		    IBD_FREE_SWQES_THRESH);
		flag = IBD_RSRC_SWQE;
	} else if (state->id_sched_needed & IBD_RSRC_LSOBUF) {
		ASSERT(state->id_lso != NULL);
		met_thresh = (state->id_lso->bkt_nfree >
		    IBD_FREE_LSOS_THRESH);
		flag = IBD_RSRC_LSOBUF;
	}
	if (met_thresh) {
		state->id_sched_needed &= ~flag;
		ret = 0;
	}
	mutex_exit(&state->id_sched_lock);

	if (ret == 0)
		mac_tx_update(state->id_mh);

	return (ret);
}

/*
 * Release the send wqe back into free list.
 */
static void
ibd_release_swqe(ibd_state_t *state, ibd_swqe_t *swqe)
{
	/*
	 * Add back on Tx list for reuse.
	 */
	swqe->swqe_next = NULL;
	mutex_enter(&state->id_tx_list.dl_mutex);
	if (state->id_tx_list.dl_pending_sends) {
		state->id_tx_list.dl_pending_sends = B_FALSE;
	}
	if (state->id_tx_list.dl_head == NULL) {
		state->id_tx_list.dl_head = SWQE_TO_WQE(swqe);
	} else {
		state->id_tx_list.dl_tail->w_next = SWQE_TO_WQE(swqe);
	}
	state->id_tx_list.dl_tail = SWQE_TO_WQE(swqe);
	state->id_tx_list.dl_cnt++;
	mutex_exit(&state->id_tx_list.dl_mutex);
}

/*
 * Acquire a send wqe from free list.
 * Returns error number and send wqe pointer.
 */
static int
ibd_acquire_swqe(ibd_state_t *state, ibd_swqe_t **swqe)
{
	int rc = 0;
	ibd_swqe_t *wqe;

	/*
	 * Check and reclaim some of the completed Tx requests.
	 * If someone else is already in this code and pulling Tx
	 * completions, no need to poll, since the current lock holder
	 * will do the work anyway. Normally, we poll for completions
	 * every few Tx attempts, but if we are short on Tx descriptors,
	 * we always try to poll.
	 */
	if ((ibd_txcomp_poll == 1) &&
	    (state->id_tx_list.dl_cnt < IBD_TX_POLL_THRESH)) {
		ibd_poll_compq(state, state->id_scq_hdl);
	}

	/*
	 * Grab required transmit wqes.
	 */
	mutex_enter(&state->id_tx_list.dl_mutex);
	wqe = WQE_TO_SWQE(state->id_tx_list.dl_head);
	if (wqe != NULL) {
		state->id_tx_list.dl_cnt -= 1;
		state->id_tx_list.dl_head = wqe->swqe_next;
		if (state->id_tx_list.dl_tail == SWQE_TO_WQE(wqe))
			state->id_tx_list.dl_tail = NULL;
	} else {
		/*
		 * If we did not find the number we were looking for, flag
		 * no resource. Adjust list appropriately in either case.
		 */
		rc = ENOENT;
		state->id_tx_list.dl_pending_sends = B_TRUE;
		DPRINT(5, "ibd_acquire_swqe: out of Tx wqe");
		atomic_add_64(&state->id_tx_short, 1);
	}
	mutex_exit(&state->id_tx_list.dl_mutex);
	*swqe = wqe;

	return (rc);
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
	ibt_send_wr_t	wrs[IBD_MAX_POST_MULTIPLE];
	ibd_swqe_t	*elem;
	ibd_swqe_t	*nodes[IBD_MAX_POST_MULTIPLE];

	node->swqe_next = NULL;

	mutex_enter(&state->id_txpost_lock);

	/*
	 * Enqueue the new node in chain of wqes to send
	 */
	if (state->id_tx_head) {
		*(state->id_tx_tailp) = (ibd_wqe_t *)node;
	} else {
		state->id_tx_head = node;
	}
	state->id_tx_tailp = &(node->swqe_next);

	/*
	 * If someone else is helping out with the sends,
	 * just go back
	 */
	if (state->id_tx_busy) {
		mutex_exit(&state->id_txpost_lock);
		return;
	}

	/*
	 * Otherwise, mark the flag to indicate that we'll be
	 * doing the dispatch of what's there in the wqe chain
	 */
	state->id_tx_busy = 1;

	while (state->id_tx_head) {
		/*
		 * Collect pending requests, IBD_MAX_POST_MULTIPLE wrs
		 * at a time if possible, and keep posting them.
		 */
		for (n_wrs = 0, elem = state->id_tx_head;
		    (elem) && (n_wrs < IBD_MAX_POST_MULTIPLE);
		    elem = WQE_TO_SWQE(elem->swqe_next), n_wrs++) {

			nodes[n_wrs] = elem;
			wrs[n_wrs] = elem->w_swr;
		}
		state->id_tx_head = elem;

		/*
		 * Release the txpost lock before posting the
		 * send request to the hca; if the posting fails
		 * for some reason, we'll never receive completion
		 * intimation, so we'll need to cleanup.
		 */
		mutex_exit(&state->id_txpost_lock);

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

		/*
		 * Grab the mutex before we go and check the tx Q again
		 */
		mutex_enter(&state->id_txpost_lock);
	}

	state->id_tx_busy = 0;
	mutex_exit(&state->id_txpost_lock);
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
	uint_t hiwm;
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
	 * Translating the virtual address regions into physical regions
	 * for using the Reserved LKey feature results in a wr sgl that
	 * is a little longer. Since failing ibt_map_mem_iov() is costly,
	 * we'll fix a high-water mark (65%) for when we should stop.
	 */
	hiwm = (state->id_max_sqseg * 65) / 100;

	/*
	 * We only do ibt_map_mem_iov() if the pktsize is above the
	 * "copy-threshold", and if the number of mp fragments is less than
	 * the maximum acceptable.
	 */
	if ((state->id_hca_res_lkey_capab) &&
	    (pktsize > IBD_TX_COPY_THRESH) &&
	    (nmblks < hiwm)) {
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

	node = NULL;
	if (ibd_acquire_swqe(state, &node) != 0) {
		/*
		 * If we don't have an swqe available, schedule a transmit
		 * completion queue cleanup and hold off on sending more
		 * more packets until we have some free swqes
		 */
		if (ibd_sched_poll(state, IBD_RSRC_SWQE, ibd_txcomp_poll) == 0)
			return (B_FALSE);

		/*
		 * If a poll cannot be scheduled, we have no choice but
		 * to drop this packet
		 */
		ibd_print_warn(state, "ibd_send: no swqe, pkt drop");
		return (B_TRUE);
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
	 * Obtain an address handle for the destination.
	 */
	ipibp = (ib_header_info_t *)mp->b_rptr;
	dest = (ipoib_mac_t *)&ipibp->ib_dst;
	if ((ntohl(dest->ipoib_qpn) & IB_QPN_MASK) == IB_MC_QPN)
		IBD_FILL_SCOPE_PKEY(dest, state->id_scope, state->id_pkey);

	pktsize = msgsize(mp);

	atomic_add_64(&state->id_xmt_bytes, pktsize);
	atomic_inc_64(&state->id_xmt_pkt);
	if (bcmp(&ipibp->ib_dst, &state->id_bcaddr, IPOIB_ADDRL) == 0)
		atomic_inc_64(&state->id_brd_xmt);
	else if ((ntohl(ipibp->ib_dst.ipoib_qpn) & IB_QPN_MASK) == IB_MC_QPN)
		atomic_inc_64(&state->id_multi_xmt);

	if ((ace = ibd_acache_lookup(state, dest, &ret, 1)) != NULL) {
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
		node->w_ahandle = NULL;

		/*
		 * for the poll mode, it is probably some cqe pending in the
		 * cq. So ibd has to poll cq here, otherwise acache probably
		 * may not be recycled.
		 */
		if (ibd_txcomp_poll == 1)
			ibd_poll_compq(state, state->id_scq_hdl);

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
	if (ntohs(ipibp->ipib_rhdr.ipoib_type) == IP6_DL_SAP) {
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

	mp->b_rptr += sizeof (ib_addrs_t);

	/*
	 * Do LSO and checksum related work here.  For LSO send, adjust the
	 * ud destination, the opcode and the LSO header information to the
	 * work request.
	 */
	lso_info_get(mp, &mss, &lsoflags);
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

	hcksum_retrieve(mp, NULL, NULL, NULL, NULL, NULL, NULL, &hckflags);
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
	ibd_post_send(state, node);

	return (B_TRUE);

ibd_send_fail:
	if (node && mp)
		ibd_free_lsohdr(node, mp);

	if (dofree)
		freemsg(mp);

	if (node != NULL)
		ibd_tx_cleanup(state, node);

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
ibd_intr(char *arg)
{
	ibd_state_t *state = (ibd_state_t *)arg;

	ibd_poll_compq(state, state->id_rcq_hdl);

	return (DDI_INTR_CLAIMED);
}

/*
 * Poll and drain the cq
 */
static uint_t
ibd_drain_cq(ibd_state_t *state, ibt_cq_hdl_t cq_hdl, ibt_wc_t *wcs,
    uint_t numwcs)
{
	ibd_wqe_t *wqe;
	ibt_wc_t *wc;
	uint_t total_polled = 0;
	uint_t num_polled;
	int i;

	while (ibt_poll_cq(cq_hdl, wcs, numwcs, &num_polled) == IBT_SUCCESS) {
		total_polled += num_polled;
		for (i = 0, wc = wcs; i < num_polled; i++, wc++) {
			wqe = (ibd_wqe_t *)(uintptr_t)wc->wc_id;
			ASSERT((wqe->w_type == IBD_WQE_SEND) ||
			    (wqe->w_type == IBD_WQE_RECV));
			if (wc->wc_status != IBT_WC_SUCCESS) {
				/*
				 * Channel being torn down.
				 */
				if (wc->wc_status == IBT_WC_WR_FLUSHED_ERR) {
					DPRINT(5, "ibd_drain_cq: flush error");
					/*
					 * Only invoke the Tx handler to
					 * release possibly held resources
					 * like AH refcount etc. Can not
					 * invoke Rx handler because it might
					 * try adding buffers to the Rx pool
					 * when we are trying to deinitialize.
					 */
					if (wqe->w_type == IBD_WQE_RECV) {
						continue;
					} else {
						DPRINT(10, "ibd_drain_cq: Bad "
						    "status %d", wc->wc_status);
					}
				}
			}
			if (wqe->w_type == IBD_WQE_SEND) {
				ibd_tx_cleanup(state, WQE_TO_SWQE(wqe));
			} else {
				ibd_process_rx(state, WQE_TO_RWQE(wqe), wc);
			}
		}
	}

	return (total_polled);
}

/*
 * Common code for interrupt handling as well as for polling
 * for all completed wqe's while detaching.
 */
static void
ibd_poll_compq(ibd_state_t *state, ibt_cq_hdl_t cq_hdl)
{
	ibt_wc_t *wcs;
	uint_t numwcs;
	int flag, redo_flag;
	int redo = 1;
	uint_t num_polled = 0;

	if (ibd_separate_cqs == 1) {
		if (cq_hdl == state->id_rcq_hdl) {
			flag = IBD_RX_CQ_POLLING;
			redo_flag = IBD_REDO_RX_CQ_POLLING;
		} else {
			flag = IBD_TX_CQ_POLLING;
			redo_flag = IBD_REDO_TX_CQ_POLLING;
		}
	} else {
		flag = IBD_RX_CQ_POLLING | IBD_TX_CQ_POLLING;
		redo_flag = IBD_REDO_RX_CQ_POLLING | IBD_REDO_TX_CQ_POLLING;
	}

	mutex_enter(&state->id_cq_poll_lock);
	if (state->id_cq_poll_busy & flag) {
		state->id_cq_poll_busy |= redo_flag;
		mutex_exit(&state->id_cq_poll_lock);
		return;
	}
	state->id_cq_poll_busy |= flag;
	mutex_exit(&state->id_cq_poll_lock);

	/*
	 * In some cases (eg detaching), this code can be invoked on
	 * any cpu after disabling cq notification (thus no concurrency
	 * exists). Apart from that, the following applies normally:
	 * The receive completion handling is always on the Rx interrupt
	 * cpu. Transmit completion handling could be from any cpu if
	 * Tx CQ is poll driven, but always on Tx interrupt cpu if Tx CQ
	 * is interrupt driven. Combined completion handling is always
	 * on the interrupt cpu. Thus, lock accordingly and use the
	 * proper completion array.
	 */
	if (ibd_separate_cqs == 1) {
		if (cq_hdl == state->id_rcq_hdl) {
			wcs = state->id_rxwcs;
			numwcs = state->id_rxwcs_size;
		} else {
			wcs = state->id_txwcs;
			numwcs = state->id_txwcs_size;
		}
	} else {
		wcs = state->id_rxwcs;
		numwcs = state->id_rxwcs_size;
	}

	/*
	 * Poll and drain the CQ
	 */
	num_polled = ibd_drain_cq(state, cq_hdl, wcs, numwcs);

	/*
	 * Enable CQ notifications and redrain the cq to catch any
	 * completions we might have missed after the ibd_drain_cq()
	 * above and before the ibt_enable_cq_notify() that follows.
	 * Finally, service any new requests to poll the cq that
	 * could've come in after the ibt_enable_cq_notify().
	 */
	do {
		if (ibt_enable_cq_notify(cq_hdl, IBT_NEXT_COMPLETION) !=
		    IBT_SUCCESS) {
			DPRINT(10, "ibd_intr: ibt_enable_cq_notify() failed");
		}

		num_polled += ibd_drain_cq(state, cq_hdl, wcs, numwcs);

		mutex_enter(&state->id_cq_poll_lock);
		if (state->id_cq_poll_busy & redo_flag)
			state->id_cq_poll_busy &= ~redo_flag;
		else {
			state->id_cq_poll_busy &= ~flag;
			redo = 0;
		}
		mutex_exit(&state->id_cq_poll_lock);

	} while (redo);

	/*
	 * If we polled the receive cq and found anything, we need to flush
	 * it out to the nw layer here.
	 */
	if ((flag & IBD_RX_CQ_POLLING) && (num_polled > 0)) {
		ibd_flush_rx(state, NULL);
	}
}

/*
 * Unmap the memory area associated with a given swqe.
 */
static void
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
			 * transmitter might alreay have bumped the
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
			 * it is not neccesary to hold the ac_mutex
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
	 * Release the send wqe for reuse.
	 */
	ibd_release_swqe(state, swqe);
}

/*
 * Hand off the processed rx mp chain to mac_rx()
 */
static void
ibd_flush_rx(ibd_state_t *state, mblk_t *mpc)
{
	if (mpc == NULL) {
		mutex_enter(&state->id_rx_lock);

		mpc = state->id_rx_mp;

		state->id_rx_mp = NULL;
		state->id_rx_mp_tail = NULL;
		state->id_rx_mp_len = 0;

		mutex_exit(&state->id_rx_lock);
	}

	if (mpc) {
		mac_rx(state->id_mh, state->id_rh, mpc);
	}
}

/*
 * Processing to be done after receipt of a packet; hand off to GLD
 * in the format expected by GLD.  The received packet has this
 * format: 2b sap :: 00 :: data.
 */
static void
ibd_process_rx(ibd_state_t *state, ibd_rwqe_t *rwqe, ibt_wc_t *wc)
{
	ib_header_info_t *phdr;
	mblk_t *mp;
	mblk_t *mpc = NULL;
	ipoib_hdr_t *ipibp;
	ip6_t *ip6h;
	int rxcnt, len;

	/*
	 * Track number handed to upper layer, and number still
	 * available to receive packets.
	 */
	rxcnt = atomic_add_32_nv(&state->id_rx_list.dl_cnt, -1);
	ASSERT(rxcnt >= 0);
	atomic_add_32(&state->id_rx_list.dl_bufs_outstanding, 1);

	/*
	 * Adjust write pointer depending on how much data came in.
	 */
	mp = rwqe->rwqe_im_mblk;
	mp->b_wptr = mp->b_rptr + wc->wc_bytes_xfer;

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
		if (bcmp(&phdr->ib_grh.ipoib_sqpn, &state->id_macaddr,
		    IPOIB_ADDRL) == 0) {
			freemsg(mp);
			return;
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
	if (ntohs(ipibp->ipoib_type) == IP6_DL_SAP) {
		if (MBLKL(mp) < sizeof (ipoib_hdr_t) + IPV6_HDR_LEN) {
			if (!pullupmsg(mp, IPV6_HDR_LEN +
			    sizeof (ipoib_hdr_t))) {
				DPRINT(10, "ibd_process_rx: pullupmsg failed");
				freemsg(mp);
				return;
			}
			ipibp = (ipoib_hdr_t *)((uchar_t *)mp->b_rptr +
			    sizeof (ipoib_pgrh_t));
		}
		ip6h = (ip6_t *)((uchar_t *)ipibp + sizeof (ipoib_hdr_t));
		len = ntohs(ip6h->ip6_plen);
		if (ip6h->ip6_nxt == IPPROTO_ICMPV6) {
			if (MBLKL(mp) < sizeof (ipoib_hdr_t) +
			    IPV6_HDR_LEN + len) {
				if (!pullupmsg(mp, sizeof (ipoib_hdr_t) +
				    IPV6_HDR_LEN + len)) {
					DPRINT(10, "ibd_process_rx: pullupmsg"
					    " failed");
					freemsg(mp);
					return;
				}
				ip6h = (ip6_t *)((uchar_t *)mp->b_rptr +
				    sizeof (ipoib_pgrh_t) +
				    sizeof (ipoib_hdr_t));
			}
			/* LINTED: E_CONSTANT_CONDITION */
			IBD_PAD_NSNA(ip6h, len, IBD_RECV);
		}
	}

	/*
	 * Update statistics
	 */
	atomic_add_64(&state->id_rcv_bytes, wc->wc_bytes_xfer);
	atomic_inc_64(&state->id_rcv_pkt);
	if (bcmp(&phdr->ib_dst, &state->id_bcaddr, IPOIB_ADDRL) == 0)
		atomic_inc_64(&state->id_brd_rcv);
	else if ((ntohl(phdr->ib_dst.ipoib_qpn) & IB_QPN_MASK) == IB_MC_QPN)
		atomic_inc_64(&state->id_multi_rcv);

	/*
	 * Set receive checksum status in mp
	 */
	if ((wc->wc_flags & IBT_WC_CKSUM_OK) == IBT_WC_CKSUM_OK) {
		(void) hcksum_assoc(mp, NULL, NULL, 0, 0, 0, 0,
		    HCK_FULLCKSUM | HCK_FULLCKSUM_OK, 0);
	}

	/*
	 * Add this mp to the list of processed mp's to send to
	 * the nw layer
	 */
	mutex_enter(&state->id_rx_lock);
	if (state->id_rx_mp) {
		ASSERT(state->id_rx_mp_tail != NULL);
		state->id_rx_mp_tail->b_next = mp;
	} else {
		ASSERT(state->id_rx_mp_tail == NULL);
		state->id_rx_mp = mp;
	}

	state->id_rx_mp_tail = mp;
	state->id_rx_mp_len++;

	if (state->id_rx_mp_len  >= IBD_MAX_RX_MP_LEN) {
		mpc = state->id_rx_mp;

		state->id_rx_mp = NULL;
		state->id_rx_mp_tail = NULL;
		state->id_rx_mp_len = 0;
	}

	mutex_exit(&state->id_rx_lock);

	if (mpc) {
		ibd_flush_rx(state, mpc);
	}
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

	/*
	 * If the wqe is being destructed, do not attempt recycling.
	 */
	if (rwqe->w_freeing_wqe == B_TRUE) {
		DPRINT(6, "ibd_freemsg: wqe being freed");
		return;
	} else {
		/*
		 * Upper layer has released held mblk, so we have
		 * no more use for keeping the old pointer in
		 * our rwqe.
		 */
		rwqe->rwqe_im_mblk = NULL;
	}

	rwqe->rwqe_im_mblk = desballoc(rwqe->rwqe_copybuf.ic_bufaddr,
	    state->id_mtu + IPOIB_GRH_SIZE, 0, &rwqe->w_freemsg_cb);
	if (rwqe->rwqe_im_mblk == NULL) {
		ibd_delete_rwqe(state, rwqe);
		ibd_free_rwqe(state, rwqe);
		DPRINT(6, "ibd_freemsg: desballoc failed");
		return;
	}

	if (ibd_post_rwqe(state, rwqe, B_TRUE) == DDI_FAILURE) {
		ibd_delete_rwqe(state, rwqe);
		ibd_free_rwqe(state, rwqe);
		return;
	}

	atomic_add_32(&state->id_rx_list.dl_bufs_outstanding, -1);
}

static uint_t
ibd_tx_recycle(char *arg)
{
	ibd_state_t *state = (ibd_state_t *)arg;

	/*
	 * Poll for completed entries
	 */
	ibd_poll_compq(state, state->id_scq_hdl);

	/*
	 * Resume any blocked transmissions if possible
	 */
	(void) ibd_resume_transmission(state);

	return (DDI_INTR_CLAIMED);
}

#ifdef IBD_LOGGING
static void
ibd_log_init(void)
{
	ibd_lbuf = kmem_zalloc(IBD_LOG_SZ, KM_SLEEP);
	ibd_lbuf_ndx = 0;
}

static void
ibd_log_fini(void)
{
	if (ibd_lbuf)
		kmem_free(ibd_lbuf, IBD_LOG_SZ);
	ibd_lbuf_ndx = 0;
	ibd_lbuf = NULL;
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
