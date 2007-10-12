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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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

#include <sys/pattr.h>		/* for HCK_PARTIALCKSUM */
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
#include <netinet/icmp6.h>	/* for icmp6_t */
#include <sys/callb.h>
#include <sys/modhash.h>

#include <sys/ib/clients/ibd/ibd.h>
#include <sys/ib/mgt/sm_attr.h>	/* for SM_INIT_TYPE_* */
#include <sys/note.h>
#include <sys/pattr.h>
#include <sys/multidata.h>

#include <sys/ib/mgt/ibmf/ibmf.h>	/* for ibd_get_portspeed */

/*
 * Modes of hardware/driver/software checksum, useful for debugging
 * and performance studies.
 *
 * none: h/w (Tavor) and driver does not do checksum, IP software must.
 * partial: driver does data checksum, IP must provide psuedo header.
 * perf_partial: driver uses IP provided psuedo cksum as data checksum
 *		 (thus, real checksumming is not done).
 */
typedef enum {
	IBD_CSUM_NONE,
	IBD_CSUM_PARTIAL,
	IBD_CSUM_PERF_PARTIAL
} ibd_csum_type_t;

typedef enum {IBD_LINK_DOWN, IBD_LINK_UP, IBD_LINK_UP_ABSENT} ibd_link_op_t;

/*
 * Per interface tunable parameters.
 */
static uint_t ibd_rx_threshold = 16;
static uint_t ibd_tx_current_copy_threshold = 0x10000000;
static uint_t ibd_num_rwqe = 4095;	/* 1 less than max Tavor CQsize */
static uint_t ibd_num_swqe = 4095;	/* 1 less than max Tavor CQsize */
static uint_t ibd_num_ah = 16;
static uint_t ibd_hash_size = 16;
static uint_t ibd_srv_fifos = 0xffff;
static uint_t ibd_fifo_depth = 0;
static ibd_csum_type_t ibd_csum_send = IBD_CSUM_NONE;
static ibd_csum_type_t ibd_csum_recv = IBD_CSUM_NONE;

/*
 * The driver can use separate CQs for send and receive queueus.
 * While using separate CQs, it is possible to put the send CQ
 * in polling mode, ie not to enable notifications on that CQ.
 * If both CQs are interrupt driven, currently it is not possible
 * for their handlers to be invoked concurrently (since Tavor ties
 * both interrupts to the same PCI intr line); but the handlers
 * are not coded with a single interrupt cpu assumption (eg
 * id_num_intrs is incremented atomically).
 *
 * The driver private struct uses id_scq_hdl to track the separate
 * CQ being used for send; the id_rcq_hdl tracks the receive CQ
 * if using separate CQs, or it tracks the single CQ when using
 * combined CQ. The id_wcs completion array is used in the combined
 * CQ case, and for fetching Rx completions in the separate CQs case;
 * the id_txwcs is used to fetch Tx completions in the separate CQs
 * case.
 */
static uint_t ibd_separate_cqs = 1;
static uint_t ibd_txcomp_poll = 0;

/*
 * Initial number of IBA resources allocated.
 */
#define	IBD_NUM_RWQE	ibd_num_rwqe
#define	IBD_NUM_SWQE	ibd_num_swqe
#define	IBD_NUM_AH	ibd_num_ah

/* when <= threshold, it's faster to copy to a premapped buffer */
#define	IBD_TX_COPY_THRESHOLD	ibd_tx_current_copy_threshold

/*
 * When the number of WQEs on the rxlist < IBD_RX_THRESHOLD, ibd will
 * allocate a new WQE to put on the the rxlist. This value must be <=
 * IBD_NUM_RWQE/id_num_rwqe.
 */
#define	IBD_RX_THRESHOLD	ibd_rx_threshold

/*
 * Hash table size for the active AH list.
 */
#define	IBD_HASH_SIZE	ibd_hash_size

/*
 * Size of completion array to be filled by a single poll call.
 */
#define	IBD_WC_SIZE	16

/*
 * We poll every (IBD_TXPOLL_MASK + 1) sends for completions. This
 * is based on our above completion array size.
 */
#define	IBD_TXPOLL_MASK	0xf

/*
 * Number of payload areas the MDT code can support. Choose the same value
 * that we know is supported by TCP/MDT.
 */
#define	IBD_MDTMAX_SEGS	16

/*
 * PAD routine called during send/recv context
 */
#define	IBD_SEND	0
#define	IBD_RECV	1

/* Driver State Pointer */
void *ibd_list;

/* Required system entry points */
static int ibd_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int ibd_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);

/* Required driver entry points for GLD */
static int ibd_reset(gld_mac_info_t *);
static int ibd_start(gld_mac_info_t *);
static int ibd_stop(gld_mac_info_t *);
static int ibd_set_mac_addr(gld_mac_info_t *, unsigned char *);
static int ibd_set_multicast(gld_mac_info_t *, unsigned char *, int);
static int ibd_set_promiscuous(gld_mac_info_t *, int);
static int ibd_get_stats(gld_mac_info_t *, struct gld_stats *);
static int ibd_send(gld_mac_info_t *, mblk_t *);
static int ibd_mdt_pre(gld_mac_info_t *, mblk_t *, void **);
static void ibd_mdt_txone(gld_mac_info_t *, void *, pdescinfo_t *);
static void ibd_mdt_post(gld_mac_info_t *, mblk_t *, void *);
static uint_t ibd_intr(gld_mac_info_t *);

/* Private driver entry points for GLD */
static int ibd_state_init(ibd_state_t *, dev_info_t *);
static void ibd_state_fini(ibd_state_t *);
static int ibd_drv_init(ibd_state_t *);
static void ibd_drv_fini(ibd_state_t *);
static void ibd_rcq_handler(ibt_cq_hdl_t, void *);
static void ibd_scq_handler(ibt_cq_hdl_t, void *);
static void ibd_snet_notices_handler(void *, ib_gid_t,
    ibt_subnet_event_code_t, ibt_subnet_event_t *);
static int ibd_init_txlist(ibd_state_t *);
static void ibd_fini_txlist(ibd_state_t *);
static int ibd_init_rxlist(ibd_state_t *);
static void ibd_fini_rxlist(ibd_state_t *);
static void ibd_freemsg_cb(char *);
static void ibd_tx_cleanup(ibd_state_t *, ibd_swqe_t *, boolean_t);
static void ibd_process_rx(ibd_state_t *, ibd_rwqe_t *, ibt_wc_t *);
static int ibd_alloc_swqe(ibd_state_t *, ibd_swqe_t **);
static void ibd_free_swqe(ibd_state_t *, ibd_swqe_t *);
static int ibd_alloc_rwqe(ibd_state_t *, ibd_rwqe_t **);
static void ibd_free_rwqe(ibd_state_t *, ibd_rwqe_t *);
static void ibd_async_handler(void *, ibt_hca_hdl_t, ibt_async_code_t,
    ibt_async_event_t *);
static int ibd_acache_init(ibd_state_t *);
static void ibd_acache_fini(ibd_state_t *);
static ibd_mce_t *ibd_join_group(ibd_state_t *, ib_gid_t, uint8_t);
static void ibd_async_reap_group(ibd_state_t *, ibd_mce_t *, ib_gid_t, uint8_t);
static void ibd_async_unsetprom(ibd_state_t *, boolean_t);
static void ibd_async_setprom(ibd_state_t *, boolean_t);
static void ibd_async_multicast(ibd_state_t *, ib_gid_t, int);
static void ibd_async_acache(ibd_state_t *, ipoib_mac_t *);
static void ibd_async_txsched(ibd_state_t *);
static void ibd_async_trap(ibd_state_t *, ibd_req_t *);
static void ibd_async_work(ibd_state_t *);
static void ibd_async_link(ibd_state_t *, ibd_req_t *);
static ibd_mce_t *ibd_mcache_find(ib_gid_t, struct list *);
static int ibd_post_rwqe(ibd_state_t *, ibd_rwqe_t *, boolean_t);
static boolean_t ibd_get_allroutergroup(ibd_state_t *, ipoib_mac_t *,
    ipoib_mac_t *);
static void ibd_poll_compq(ibd_state_t *, ibt_cq_hdl_t);
static void ibd_deregister_mr(ibd_state_t *, ibd_swqe_t *);
static void ibd_reacquire_group(ibd_state_t *, ibd_mce_t *);
static void ibd_leave_group(ibd_state_t *, ib_gid_t, uint8_t);
static uint64_t ibd_get_portspeed(ibd_state_t *);

#ifdef RUN_PERFORMANCE
static void ibd_perf(ibd_state_t *);
#endif

/* Streams Module Info */
static struct module_info ibd_minfo = {
	IBD_IDNUM,		/* module ID Number */
	"ibd",			/* module name */
	0,			/* min packet size */
	INFPSZ,			/* maximum packet size */
	IBD_HIWAT,		/* high water mark */
	IBD_LOWAT		/* low water mark */
};

/* Streams Read Queue */
static struct qinit ibd_rdinit = {
	NULL,			/* put */
	gld_rsrv,		/* service */
	gld_open,		/* open */
	gld_close,		/* close */
	NULL,			/* unused */
	&ibd_minfo,		/* parameters */
	NULL			/* statistics */
};

/* Streams Write Queue */
static struct qinit ibd_wrinit = {
	gld_wput,		/* put */
	gld_wsrv,		/* service */
	NULL,			/* open */
	NULL,			/* close */
	NULL,			/* unused */
	&ibd_minfo,		/* parameters */
	NULL			/* statistics */
};

/* Stream Operations */
static struct streamtab ibd_streamtab = {
	&ibd_rdinit,		/* read queue */
	&ibd_wrinit,		/* write queue */
	NULL,			/* lower read queue (MUX) */
	NULL			/* lower write queue (MUX) */
};

/* Character/Block Operations */
static struct cb_ops ibd_cb_ops = {
	nulldev,		/* open */
	nulldev,		/* close */
	nodev,			/* strategy (block) */
	nodev,			/* print (block) */
	nodev,			/* dump (block) */
	nodev,			/* read */
	nodev,			/* write */
	nodev,			/* ioctl */
	nodev,			/* devmap */
	nodev,			/* mmap */
	nodev,			/* segmap */
	nochpoll,		/* chpoll */
	ddi_prop_op,		/* prop_op */
	&ibd_streamtab,		/* streams */
	D_MP | D_64BIT,		/* flags */
	CB_REV			/* rev */
};

/* Driver Operations */
static struct dev_ops ibd_dev_ops = {
	DEVO_REV,		/* struct rev */
	0,			/* refcnt */
	gld_getinfo,		/* getinfo */
	nulldev,		/* identify */
	nulldev,		/* probe */
	ibd_attach,		/* attach */
	ibd_detach,		/* detach */
	nodev,			/* reset */
	&ibd_cb_ops,		/* cb_ops */
	NULL,			/* bus_ops */
	nodev			/* power */
};

/* Module Driver Info */
static struct modldrv ibd_modldrv = {
	&mod_driverops,
	"InfiniBand DLPI Driver %I%",
	&ibd_dev_ops
};

/* Module Linkage */
static struct modlinkage ibd_modlinkage = {
	MODREV_1,
	&ibd_modldrv,
	NULL
};

/*
 * Module Info passed to IBTL during IBT_ATTACH.
 *   NOTE:  This data must be static (i.e. IBTL just keeps a pointer to this
 *	    data).
 */
static struct ibt_clnt_modinfo_s ibd_clnt_modinfo = {
	IBTI_V2,
	IBT_NETWORK,
	ibd_async_handler,
	NULL,
	"IPIB"
};

/*
 * Async operation types.
 */
#define	ASYNC_GETAH	1
#define	ASYNC_JOIN	2
#define	ASYNC_LEAVE	3
#define	ASYNC_PROMON	4
#define	ASYNC_PROMOFF	5
#define	ASYNC_REAP	6
#define	ASYNC_POKE	7
#define	ASYNC_TRAP	8
#define	ASYNC_SCHED	9
#define	ASYNC_LINK	10
#define	ASYNC_EXIT	11

/*
 * Async operation states
 */
#define	NOTSTARTED	0
#define	ONGOING		1
#define	COMPLETED	2
#define	ERRORED		3
#define	ROUTERED	4

#define	IB_MCGID_IPV4_LOW_GROUP_MASK 0xFFFFFFFF

#ifdef DEBUG

static int rxpack = 1, txpack = 1;
int debuglevel = 100;
static void
debug_print(int l, char *fmt, ...)
{
	va_list ap;

	if (l < debuglevel)
		return;
	va_start(ap, fmt);
	vcmn_err(CE_CONT, fmt, ap);
	va_end(ap);
}
#define	INCRXPACK	(rxpack++)
#define	INCTXPACK	(txpack++)
#define	DPRINT		debug_print

#else /* DEBUG */

#define	INCRXPACK	0
#define	INCTXPACK	0
#define	DPRINT

#endif /* DEBUG */

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
	    "%s%d: HCA GUID %016llx port %d PKEY %02x ", ibd_minfo.mi_idname,
	    state->id_macinfo->gldm_ppa, (u_longlong_t)hca_guid,
	    state->id_port, state->id_pkey);
	va_start(ap, fmt);
	(void) vsnprintf(ibd_print_buf + len, sizeof (ibd_print_buf) - len,
	    fmt, ap);
	cmn_err(CE_NOTE, "!%s", ibd_print_buf);
	va_end(ap);
}

/* warlock directives */
_NOTE(MUTEX_PROTECTS_DATA(ibd_state_t::id_ac_mutex, 
    ibd_state_t::id_ah_active))
_NOTE(MUTEX_PROTECTS_DATA(ibd_state_t::id_ac_mutex, ibd_state_t::id_ah_free))
_NOTE(MUTEX_PROTECTS_DATA(ibd_state_t::id_acache_req_lock, 
    ibd_state_t::id_req_list))
_NOTE(MUTEX_PROTECTS_DATA(ibd_state_t::id_acache_req_lock, 
    ibd_state_t::id_acache_req_cv))
_NOTE(MUTEX_PROTECTS_DATA(ibd_state_t::id_mc_mutex, 
    ibd_state_t::id_multi_req))
_NOTE(MUTEX_PROTECTS_DATA(ibd_state_t::id_mc_mutex, 
    ibd_state_t::id_multi_addr))
_NOTE(MUTEX_PROTECTS_DATA(ibd_state_t::id_mc_mutex, 
    ibd_state_t::id_multi_op))
_NOTE(MUTEX_PROTECTS_DATA(ibd_state_t::id_mc_mutex, 
    ibd_state_t::id_multi_queued))
_NOTE(MUTEX_PROTECTS_DATA(ibd_state_t::id_mc_mutex, 
    ibd_state_t::id_mc_full))
_NOTE(MUTEX_PROTECTS_DATA(ibd_state_t::id_mc_mutex, 
    ibd_state_t::id_mc_non))
_NOTE(MUTEX_PROTECTS_DATA(ibd_state_t::id_link_mutex, 
    ibd_state_t::id_link_state))
_NOTE(MUTEX_PROTECTS_DATA(ibd_state_t::id_tx_list.dl_mutex, 
    ibd_state_s::id_tx_list))
_NOTE(MUTEX_PROTECTS_DATA(ibd_state_t::id_rx_list.dl_mutex, 
    ibd_state_s::id_rx_list))

_NOTE(SCHEME_PROTECTS_DATA("Protected by Scheme", ibd_state_s::id_multi_op))
_NOTE(SCHEME_PROTECTS_DATA("Protected by Scheme", ibd_state_s::id_ah_error))
_NOTE(SCHEME_PROTECTS_DATA("Protected by Scheme", ibd_state_s::id_ah_op))
_NOTE(SCHEME_PROTECTS_DATA("Protected by Scheme", ibd_state_s::id_num_intrs))
_NOTE(SCHEME_PROTECTS_DATA("Protected by Scheme", ibd_state_s::id_prom_op))
_NOTE(SCHEME_PROTECTS_DATA("Protected by Scheme", ibd_state_s::id_rx_short))
_NOTE(SCHEME_PROTECTS_DATA("Protected by Scheme", ibd_state_s::id_rx_list))
_NOTE(SCHEME_PROTECTS_DATA("Protected by Scheme", ibd_state_s::id_tx_list))
_NOTE(SCHEME_PROTECTS_DATA("Protected by Scheme", ibd_acache_rq::rq_op))
_NOTE(SCHEME_PROTECTS_DATA("Protected by Scheme", ibd_acache_rq::rq_gid))
_NOTE(SCHEME_PROTECTS_DATA("Protected by Scheme", ibd_acache_rq::rq_ptr))
_NOTE(SCHEME_PROTECTS_DATA("Protected by Scheme", ibd_acache_s::ac_mce))
_NOTE(SCHEME_PROTECTS_DATA("Protected by Scheme", ibd_acache_s::ac_ref))

_NOTE(SCHEME_PROTECTS_DATA("Protected by Scheme", ibd_wqe_s))
_NOTE(SCHEME_PROTECTS_DATA("Protected by Scheme", ibd_rwqe_s))
_NOTE(SCHEME_PROTECTS_DATA("Protected by Scheme", ibd_swqe_s))
_NOTE(SCHEME_PROTECTS_DATA("Protected by Scheme", ipoib_mac))
_NOTE(SCHEME_PROTECTS_DATA("Protected by Scheme", ipoib_pgrh))

_NOTE(SCHEME_PROTECTS_DATA("Protected by Scheme", ib_gid_s))
_NOTE(SCHEME_PROTECTS_DATA("Protected by Scheme", ibd_mce_t::mc_req))
_NOTE(SCHEME_PROTECTS_DATA("Protected by Scheme", ibd_mce_t::mc_fullreap))
_NOTE(SCHEME_PROTECTS_DATA("Protected by Scheme", ibd_mce_t::mc_jstate))

_NOTE(SCHEME_PROTECTS_DATA("Protected by Scheme", msgb::b_rptr))
_NOTE(SCHEME_PROTECTS_DATA("Protected by Scheme", msgb::b_wptr))
_NOTE(SCHEME_PROTECTS_DATA("Protected by Scheme", gld_stats))
_NOTE(SCHEME_PROTECTS_DATA("Protected by Scheme", callb_cpr::cc_id))

#ifdef DEBUG
_NOTE(SCHEME_PROTECTS_DATA("Protected_by_Scheme", rxpack))
_NOTE(SCHEME_PROTECTS_DATA("Protected_by_Scheme", txpack))
#endif

int
_init()
{
	int status;

	/*
	 * Sanity check some parameter settings. Tx completion polling
	 * only makes sense with separate CQs for Tx and Rx.
	 */
	if ((ibd_txcomp_poll == 1) && (ibd_separate_cqs == 0)) {
		cmn_err(CE_NOTE, "!%s: %s", ibd_minfo.mi_idname,
		    "Setting ibd_txcomp_poll = 0 for combined CQ");
		ibd_txcomp_poll = 0;
	}

	status = ddi_soft_state_init(&ibd_list, sizeof (ibd_state_t), 0);
	if (status != 0) {
		DPRINT(10, "_init:failed in ddi_soft_state_init()");
		return (status);
	}

	status = mod_install(&ibd_modlinkage);
	if (status != 0) {
		DPRINT(10, "_init:failed in mod_install()");
		ddi_soft_state_fini(&ibd_list);
		return (status);
	}

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

	ddi_soft_state_fini(&ibd_list);
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
 * Implementation of various (software) flavors of send and receive side
 * checksumming.
 */
#define	IBD_CKSUM_SEND(mp) {						\
	uint32_t start, stuff, end, value, flags;			\
	uint32_t cksum, sum;						\
	uchar_t *dp, *buf;						\
	uint16_t *up;							\
									\
	if (ibd_csum_send == IBD_CSUM_NONE)				\
		goto punt_send;						\
									\
	/*								\
	 * Query IP whether Tx cksum needs to be done.			\
	 */								\
	hcksum_retrieve(mp, NULL, NULL, &start, &stuff, &end,		\
	    &value, &flags);						\
									\
	if (flags == HCK_PARTIALCKSUM)	{				\
		dp = ((uchar_t *)mp->b_rptr + IPOIB_HDRSIZE);		\
		up =  (uint16_t *)(dp + stuff);				\
		if (ibd_csum_send == IBD_CSUM_PARTIAL) {		\
			end = ((uchar_t *)mp->b_wptr - dp - start);	\
			cksum = *up;					\
			*up = 0;					\
			/*						\
			 * Does NOT handle chained mblks/more than one	\
			 * SGL. Applicable only for a single SGL	\
			 * entry/mblk, where the stuff offset is	\
			 * within the range of buf.			\
			 */						\
			buf = (dp + start);				\
			sum = IP_BCSUM_PARTIAL(buf, end, cksum);	\
		} else {						\
			sum = *up;					\
		}							\
		DPRINT(10, "strt %d stff %d end %d sum: %x csm %x \n",	\
		    start, stuff, end, sum, cksum);			\
		sum = ~(sum);						\
		*(up) = (uint16_t)((sum) ? (sum) : ~(sum));		\
	}								\
punt_send:								\
	;								\
}

#define	IBD_CKSUM_RECV(mp) {						\
	uchar_t *dp, *buf;						\
	uint32_t start, end, value, stuff, flags;			\
	uint16_t *up, frag;						\
	ipha_t *iphp;							\
	ipoib_hdr_t *ipibh;						\
									\
	if (ibd_csum_recv == IBD_CSUM_NONE)				\
		goto punt_recv;					 	\
									\
	ipibh = (ipoib_hdr_t *)((uchar_t *)mp->b_rptr + IPOIB_GRH_SIZE);\
	if (ntohs(ipibh->ipoib_type) != ETHERTYPE_IP)		 	\
		goto punt_recv;						\
									\
	dp = ((uchar_t *)ipibh + IPOIB_HDRSIZE);			\
	iphp = (ipha_t *)dp;						\
	frag = ntohs(iphp->ipha_fragment_offset_and_flags);		\
	if ((frag) & (~IPH_DF))						\
		goto punt_recv;						\
	start = IPH_HDR_LENGTH(iphp);					\
	if (iphp->ipha_protocol == IPPROTO_TCP)				\
		stuff = start + 16;					\
	else if (iphp->ipha_protocol == IPPROTO_UDP)			\
		stuff = start + 6;					\
	else								\
		goto punt_recv;						\
									\
	flags = HCK_PARTIALCKSUM;					\
	end = ntohs(iphp->ipha_length);					\
	up = (uint16_t *)(dp + stuff);					\
									\
	if (ibd_csum_recv == IBD_CSUM_PARTIAL) {			\
		buf = (dp + start);					\
		value = IP_BCSUM_PARTIAL(buf, end - start, 0);		\
	} else {							\
		value = (*up);						\
	}								\
	if (hcksum_assoc(mp, NULL, NULL, start, stuff, end,		\
	    value, flags, 0) != 0)					\
		DPRINT(10, "cksum_recv: value: %x\n", value);		\
punt_recv:								\
	;								\
}

#define	IBD_CKSUM_MDT(mp, dlmdp, np, stp, stfp, ep, vp, fp) {		\
	/*								\
	 * Query IP whether Tx cksum needs to be done.			\
	 */								\
	if (ibd_csum_send != IBD_CSUM_NONE)				\
		hcksum_retrieve(mp, dlmdp, np, stp, stfp, ep, vp, fp);	\
}

#define	IBD_CKSUM_MDT_PACKET(pinfo, st, stf, fl) {			\
	if ((ibd_csum_send != IBD_CSUM_NONE) &&				\
	    (fl == HCK_PARTIALCKSUM)) {					\
		extern uint_t bcksum(uchar_t *, int, uint32_t);		\
		uint16_t *up;						\
		uint32_t sum;						\
		uchar_t *hp = (pinfo)->hdr_rptr + IPOIB_HDRSIZE;	\
		int k;							\
									\
		up = (uint16_t *)(hp + stf);				\
		if (ibd_csum_send == IBD_CSUM_PARTIAL) {		\
			sum = *up;					\
			*up = 0;					\
			sum = IP_BCSUM_PARTIAL(hp + st,			\
			    PDESC_HDRL(pinfo) - st - IPOIB_HDRSIZE,	\
			    sum);					\
			for (k = 0; k < pinfo->pld_cnt; k++)		\
				sum = IP_BCSUM_PARTIAL(pinfo->pld_ary[k].\
				    pld_rptr, PDESC_PLDL(pinfo, k),	\
				    sum);				\
		} else {						\
			sum = *up;					\
		}							\
		sum = ~(sum);						\
		*(up) = (uint16_t)((sum) ? (sum) : ~(sum));		\
	}								\
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
		if (type == 0) {					\
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
 * The service fifo code is copied verbatim from Cassini. This can be
 * enhanced by doing a cpu_bind_thread() to bind each fifo to a cpu.
 */

typedef caddr_t fifo_obj_t, *p_fifo_obj_t;

typedef struct _srv_fifo_t {
	kmutex_t fifo_lock;
	kcondvar_t fifo_cv;
	size_t size;
	uint_t max_index;
	uint_t rd_index;
	uint_t wr_index;
	uint_t objs_pending;
	p_fifo_obj_t fifo_objs;
	kthread_t *fifo_thread;
	void (*drain_func)(caddr_t drain_func_arg);
	caddr_t drain_func_arg;
	boolean_t running;
	callb_cpr_t cprinfo;
} srv_fifo_t, *p_srv_fifo_t;
_NOTE(MUTEX_PROTECTS_DATA(_srv_fifo_t::fifo_lock, _srv_fifo_t::fifo_cv))
_NOTE(MUTEX_PROTECTS_DATA(_srv_fifo_t::fifo_lock, _srv_fifo_t::cprinfo))

static int
_ddi_srv_fifo_create(p_srv_fifo_t *handle, size_t size,
			void (*drain_func)(), caddr_t drain_func_arg)
{
	int status;
	p_srv_fifo_t srv_fifo;

	status = DDI_SUCCESS;
	srv_fifo = (p_srv_fifo_t)kmem_zalloc(sizeof (srv_fifo_t), KM_SLEEP);
	srv_fifo->size = size;
	srv_fifo->max_index = size - 1;
	srv_fifo->fifo_objs = (p_fifo_obj_t)kmem_zalloc(
	    size * sizeof (fifo_obj_t), KM_SLEEP);
	mutex_init(&srv_fifo->fifo_lock, "srv_fifo", MUTEX_DRIVER, NULL);
	cv_init(&srv_fifo->fifo_cv, "srv_fifo", CV_DRIVER, NULL);
	srv_fifo->drain_func = drain_func;
	srv_fifo->drain_func_arg = drain_func_arg;
	srv_fifo->running = DDI_SUCCESS;
	srv_fifo->fifo_thread = thread_create(NULL, 0, drain_func,
	    (caddr_t)srv_fifo, 0, &p0, TS_RUN, 60);
	if (srv_fifo->fifo_thread == NULL) {
		cv_destroy(&srv_fifo->fifo_cv);
		mutex_destroy(&srv_fifo->fifo_lock);
		kmem_free(srv_fifo->fifo_objs, size * sizeof (fifo_obj_t));
		kmem_free(srv_fifo, sizeof (srv_fifo_t));
		srv_fifo = NULL;
		status = DDI_FAILURE;
	} else
		*handle = srv_fifo;
	return (status);
}

static void
_ddi_srv_fifo_destroy(p_srv_fifo_t handle)
{
	kt_did_t tid = handle->fifo_thread->t_did;

	mutex_enter(&handle->fifo_lock);
	handle->running = DDI_FAILURE;
	cv_signal(&handle->fifo_cv);
	while (handle->running == DDI_FAILURE)
		cv_wait(&handle->fifo_cv, &handle->fifo_lock);
	mutex_exit(&handle->fifo_lock);
	if (handle->objs_pending != 0)
		cmn_err(CE_NOTE, "!Thread Exit with work undone.");
	cv_destroy(&handle->fifo_cv);
	mutex_destroy(&handle->fifo_lock);
	kmem_free(handle->fifo_objs, handle->size * sizeof (fifo_obj_t));
	kmem_free(handle, sizeof (srv_fifo_t));
	thread_join(tid);
}

static caddr_t
_ddi_srv_fifo_begin(p_srv_fifo_t handle)
{
#ifndef __lock_lint
	CALLB_CPR_INIT(&handle->cprinfo, &handle->fifo_lock,
	    callb_generic_cpr, "srv_fifo");
#endif /* ! _lock_lint */
	return (handle->drain_func_arg);
}

static void
_ddi_srv_fifo_end(p_srv_fifo_t handle)
{
	callb_cpr_t cprinfo;

	mutex_enter(&handle->fifo_lock);
	cprinfo = handle->cprinfo;
	handle->running = DDI_SUCCESS;
	cv_signal(&handle->fifo_cv);
#ifndef __lock_lint
	CALLB_CPR_EXIT(&cprinfo);
#endif /* ! _lock_lint */
	thread_exit();
	_NOTE(NOT_REACHED)
}

static int
_ddi_put_fifo(p_srv_fifo_t handle, fifo_obj_t ptr, boolean_t signal)
{
	int status;

	mutex_enter(&handle->fifo_lock);
	status = handle->running;
	if (status == DDI_SUCCESS) {
		if (ptr) {
			if (handle->objs_pending < handle->size) {
				if (handle->wr_index == handle->max_index)
					handle->wr_index = 0;
				else
					handle->wr_index++;
				handle->fifo_objs[handle->wr_index] = ptr;
				handle->objs_pending++;
			} else
				status = DDI_FAILURE;
			if (signal)
				cv_signal(&handle->fifo_cv);
		} else {
			if (signal && (handle->objs_pending > 0))
				cv_signal(&handle->fifo_cv);
		}
	}
	mutex_exit(&handle->fifo_lock);
	return (status);
}

static int
_ddi_get_fifo(p_srv_fifo_t handle, p_fifo_obj_t ptr)
{
	int status;

	mutex_enter(&handle->fifo_lock);
	status = handle->running;
	if (status == DDI_SUCCESS) {
		if (handle->objs_pending == 0) {
#ifndef __lock_lint
			CALLB_CPR_SAFE_BEGIN(&handle->cprinfo);
			cv_wait(&handle->fifo_cv, &handle->fifo_lock);
			CALLB_CPR_SAFE_END(&handle->cprinfo,
			    &handle->fifo_lock);
#endif /* !_lock_lint */
			*ptr = NULL;
		}
		if (handle->objs_pending > 0) {
			if (handle->rd_index == handle->max_index)
				handle->rd_index = 0;
			else
				handle->rd_index++;
			*ptr = handle->fifo_objs[handle->rd_index];
			handle->objs_pending--;
		}
		status = handle->running;
	} else {
		if (handle->objs_pending) {
			if (handle->rd_index == handle->max_index)
				handle->rd_index = 0;
			else
				handle->rd_index++;
			*ptr = handle->fifo_objs[handle->rd_index];
			handle->objs_pending--;
			status = DDI_SUCCESS;
		} else
			status = DDI_FAILURE;
	}
	mutex_exit(&handle->fifo_lock);
	return (status);
}

/*
 * [un]map_rx_srv_fifos has been modified from its CE version.
 */
static void
drain_fifo(p_srv_fifo_t handle)
{
	ibd_state_t *state;
	mblk_t *mp;

	state = (ibd_state_t *)_ddi_srv_fifo_begin(handle);
	while (_ddi_get_fifo(handle, (p_fifo_obj_t)&mp) == DDI_SUCCESS) {
		/*
		 * Hand off to GLD.
		 */
		IBD_CKSUM_RECV(mp);
		gld_recv(state->id_macinfo, mp);
	}
	_ddi_srv_fifo_end(handle);
}

static p_srv_fifo_t *
map_rx_srv_fifos(int *nfifos, void *private)
{
	p_srv_fifo_t *srv_fifos;
	int i, inst_taskqs, depth;

	/*
	 * Default behavior on both sparc and amd cpus in terms of
	 * of worker thread is as follows: (N) indicates worker thread
	 * not enabled , (Y) indicates worker thread enabled. Default of
	 * ibd_srv_fifo is set to 0xffff. The default behavior can be
	 * overridden by setting ibd_srv_fifos to 0 or 1 as shown below.
	 * Worker thread model assigns lower priority to network
	 * processing making system more usable at higher network
	 * loads.
	 *  ________________________________________________________
	 * |Value of ibd_srv_fifo | 0 | 1 | 0xffff| 0 | 1 | 0xfffff |
	 * |----------------------|---|---|-------|---|---|---------|
	 * |			  |   Sparc	  |   	x86	    |
	 * |----------------------|---|---|-------|---|---|---------|
	 * | Single CPU		  |N  | Y | N	  | N | Y | N	    |
	 * |----------------------|---|---|-------|---|---|---------|
	 * | Multi CPU		  |N  | Y | Y	  | N | Y | Y	    |
	 * |______________________|___|___|_______|___|___|_________|
	 */
	if ((((inst_taskqs = ncpus) == 1) && (ibd_srv_fifos != 1)) ||
	    (ibd_srv_fifos == 0)) {
		*nfifos = 0;
		return ((p_srv_fifo_t *)1);
	}

	*nfifos = inst_taskqs;
	srv_fifos = kmem_zalloc(inst_taskqs * sizeof (p_srv_fifo_t),
	    KM_SLEEP);

	/*
	 * If the administrator has specified a fifo depth, use
	 * that, else just decide what should be the depth.
	 */
	if (ibd_fifo_depth == 0)
		depth = (IBD_NUM_RWQE / inst_taskqs) + 16;
	else
		depth = ibd_fifo_depth;

	for (i = 0; i < inst_taskqs; i++)
		if (_ddi_srv_fifo_create(&srv_fifos[i],
		    depth, drain_fifo,
		    (caddr_t)private) != DDI_SUCCESS)
			break;

	if (i < inst_taskqs)
		goto map_rx_srv_fifos_fail1;

	goto map_rx_srv_fifos_exit;

map_rx_srv_fifos_fail1:
	i--;
	for (; i >= 0; i--) {
		_ddi_srv_fifo_destroy(srv_fifos[i]);
	}
	kmem_free(srv_fifos, inst_taskqs * sizeof (p_srv_fifo_t));
	srv_fifos = NULL;

map_rx_srv_fifos_exit:
	return (srv_fifos);
}

static void
unmap_rx_srv_fifos(int inst_taskqs, p_srv_fifo_t *srv_fifos)
{
	int i;

	/*
	 * If this interface was not using service fifos, quickly return.
	 */
	if (inst_taskqs == 0)
		return;

	for (i = 0; i < inst_taskqs; i++) {
		_ddi_srv_fifo_destroy(srv_fifos[i]);
	}
	kmem_free(srv_fifos, inst_taskqs * sizeof (p_srv_fifo_t));
}

/*
 * Choose between sending up the packet directly and handing off
 * to a service thread.
 */
static void
ibd_send_up(ibd_state_t *state, mblk_t *mp)
{
	p_srv_fifo_t *srvfifo;
	ipoib_hdr_t *lhdr;
	struct ip *ip_hdr;
	struct udphdr *tran_hdr;
	uchar_t prot;
	int tnum = -1, nfifos = state->id_nfifos;

	/*
	 * Quick path if the interface is not using service fifos.
	 */
	if (nfifos == 0) {
hand_off:
		IBD_CKSUM_RECV(mp);
		gld_recv(state->id_macinfo, mp);
		return;
	}

	/*
	 * Is the packet big enough to look at the IPoIB header
	 * and basic IP header to determine whether it is an
	 * IPv4 packet?
	 */
	if (MBLKL(mp) >= (IPOIB_GRH_SIZE + IPOIB_HDRSIZE +
	    sizeof (struct ip))) {

		lhdr = (ipoib_hdr_t *)(mp->b_rptr + IPOIB_GRH_SIZE);

		/*
		 * Is the packet an IP(v4) packet?
		 */
		if (ntohs(lhdr->ipoib_type) == ETHERTYPE_IP) {

			ip_hdr = (struct ip *)(mp->b_rptr + IPOIB_GRH_SIZE +
			    IPOIB_HDRSIZE);
			prot = ip_hdr->ip_p;

			/*
			 * TCP or UDP packet? We use the UDP header, since
			 * the first few words of both headers are laid out
			 * similarly (src/dest ports).
			 */
			if ((prot == IPPROTO_TCP) || (prot == IPPROTO_UDP)) {

				tran_hdr = (struct udphdr *)(
				    (uint8_t *)ip_hdr + (ip_hdr->ip_hl << 2));

				/*
				 * Are we within limits of this packet? If
				 * so, use the destination port to hash to
				 * a service thread.
				 */
				if (mp->b_wptr >= ((uchar_t *)tran_hdr +
				    sizeof (*tran_hdr)))
					tnum = (ntohs(tran_hdr->uh_dport) +
					    ntohs(tran_hdr->uh_sport)) %
					    nfifos;
			}
		}
	}

	/*
	 * For non TCP/UDP traffic (eg SunCluster heartbeat), we hand the
	 * packet up in interrupt context, reducing latency.
	 */
	if (tnum == -1) {
		goto hand_off;
	}

	srvfifo = (p_srv_fifo_t *)state->id_fifos;
	if (_ddi_put_fifo(srvfifo[tnum], (fifo_obj_t)mp,
	    B_TRUE) != DDI_SUCCESS)
		freemsg(mp);
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
			 * it might be freed up (as in ASYNC_LEAVE,REAP,TRAP).
			 */

			/* Perform the request */
			switch (ptr->rq_op) {
				case ASYNC_GETAH:
					ibd_async_acache(state, &ptr->rq_mac);
					break;
				case ASYNC_POKE:
					/*
					 * We need the gld_sched; that
					 * happens below. No locks are
					 * needed for the multi_op update.
					 */
					state->id_multi_op = NOTSTARTED;
					break;
				case ASYNC_REAP:
					ibd_async_reap_group(state,
					    ptr->rq_ptr, ptr->rq_gid,
					    IB_MC_JSTATE_FULL);
					break;
				case ASYNC_LEAVE:
				case ASYNC_JOIN:
					ibd_async_multicast(state,
					    ptr->rq_gid, ptr->rq_op);
					break;
				case ASYNC_PROMON:
					ibd_async_setprom(state, B_TRUE);
					break;
				case ASYNC_PROMOFF:
					ibd_async_unsetprom(state, B_TRUE);
					break;
				case ASYNC_TRAP:
					ibd_async_trap(state, ptr);
					break;
				case ASYNC_SCHED:
					ibd_async_txsched(state);
					break;
				case ASYNC_LINK:
					ibd_async_link(state, ptr);
					break;
				case ASYNC_EXIT:
					mutex_enter(&state->id_acache_req_lock);
#ifndef	__lock_lint
					CALLB_CPR_EXIT(&cprinfo);
#endif /* !__lock_lint */
					_NOTE(NOT_REACHED)
					return;
			}

			/*
			 * Indicate blocked operation can now be retried.
			 * Note gld_sched() gets the gld_maclock,
			 * and the multicast/promiscuous paths
			 * (ibd_set_multicast(), ibd_set_promiscuous())
			 * grab id_acache_req_lock in ibd_queue_work_slot()
			 * with gld_maclock held, so we must not hold the
			 * id_acache_req_lock while calling gld_sched to
			 * prevent deadlock.
			 */
			gld_sched(state->id_macinfo);

			mutex_enter(&state->id_acache_req_lock);
		} else {
			/*
			 * Nothing to do: wait till new request arrives.
			 */
#ifndef __lock_lint
			CALLB_CPR_SAFE_BEGIN(&cprinfo);
			cv_wait(&state->id_acache_req_cv,
			    &state->id_acache_req_lock);
			CALLB_CPR_SAFE_END(&cprinfo,
			    &state->id_acache_req_lock);
#endif /* !_lock_lint */
		}
	}
	/*NOTREACHED*/
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

	/*
	 * Only attempt to print when we can; in the mdt pattr case, the
	 * address is not aligned properly.
	 */
	if (((ulong_t)mac & 3) == 0)
		DPRINT(4,
		    "ibd_acache_lookup : lookup for %08X:%08X:%08X:%08X:%08X",
		    htonl(mac->ipoib_qpn), htonl(mac->ipoib_gidpref[0]),
		    htonl(mac->ipoib_gidpref[1]), htonl(mac->ipoib_gidsuff[0]),
		    htonl(mac->ipoib_gidsuff[1]));

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
	 * the operation completes, is sent back to GLD to be retried.
	 * The async thread will update id_ah_op with an error indication
	 * or will set it to indicate the next look up can start; either
	 * way, it will gld_sched() so that all blocked requests come
	 * back here.
	 */
	*err = GLD_NORESOURCES;
	if (state->id_ah_op == NOTSTARTED) {
		/*
		 * We did not even find the entry; queue a request for it.
		 */
		bcopy(mac, &(state->id_ah_req.rq_mac), IPOIB_ADDRL);
		ibd_queue_work_slot(state, &state->id_ah_req, ASYNC_GETAH);
		state->id_ah_op = ONGOING;
		bcopy(mac, &state->id_ah_addr, IPOIB_ADDRL);
	} else if ((state->id_ah_op != ONGOING) &&
	    (bcmp(&state->id_ah_addr, mac, IPOIB_ADDRL) == 0)) {
		/*
		 * Check the status of the pathrecord lookup request
		 * we had queued before.
		 */
		if (state->id_ah_op == ERRORED) {
			*err = GLD_FAILURE;
			state->id_ah_error++;
		} else {
			/*
			 * ROUTERED case: We need to send to the
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
		state->id_ah_op = NOTSTARTED;
	} else if ((state->id_ah_op != ONGOING) &&
	    (bcmp(&state->id_ah_addr, mac, IPOIB_ADDRL) != 0)) {
		/*
		 * This case can happen when we get a higher band
		 * packet. The easiest way is to reset the state machine
		 * to accommodate the higher priority packet.
		 */
		state->id_ah_op = NOTSTARTED;
	}
	mutex_exit(&state->id_ac_mutex);

	/*
	 * The PathRecord lookup failed; retry any other blocked
	 * Tx requests that might have come in between when we
	 * initiated the path lookup and now that were sent back
	 * to GLD to implement single outstanding lookup scheme.
	 */
	if (*err == GLD_FAILURE)
		gld_sched(state->id_macinfo);
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
	int ret = NOTSTARTED;

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
			state->id_ah_op = ERRORED;
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
			ret = ROUTERED;
			DPRINT(4, "ibd_async_acache :  redirected to "
			    "%08X:%08X:%08X:%08X:%08X",
			    htonl(mac->ipoib_qpn), htonl(mac->ipoib_gidpref[0]),
			    htonl(mac->ipoib_gidpref[1]),
			    htonl(mac->ipoib_gidsuff[0]),
			    htonl(mac->ipoib_gidsuff[1]));

			mutex_enter(&state->id_ac_mutex);
			if (ibd_acache_find(state, mac, B_FALSE, 0) != NULL) {
				mutex_exit(&state->id_ac_mutex);
				DPRINT(4, "ibd_async_acache : router AH found");
				state->id_ah_op = ROUTERED;
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
			state->id_ah_op = NOTSTARTED;
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
	state->id_ah_op = ERRORED;
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
	int32_t lstate = (opcode == IBD_LINK_DOWN) ? GLD_LINKSTATE_DOWN :
	    GLD_LINKSTATE_UP;
	ibd_mce_t *mce, *pmce;
	ibd_ace_t *ace, *pace;

	DPRINT(10, "ibd_async_link(): %d", opcode);

	/*
	 * On a link up, revalidate the link speed/width. No point doing
	 * this on a link down, since we will be unable to do SA operations,
	 * defaulting to the lowest speed. Also notice that we update our
	 * notion of speed before calling gld_linkstate(), which will do
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
		if (state->id_prom_op == COMPLETED) {
			/*
			 * Drop all nonmembership.
			 */
			ibd_async_unsetprom(state, B_FALSE);

			/*
			 * Then, try to regain nonmembership to all mcg's.
			 */
			ibd_async_setprom(state, B_FALSE);

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
	 * Macinfo is guaranteed to exist since driver does ibt_close_hca()
	 * (which stops further events from being delivered) before
	 * gld_mac_free(). At this point, it is guaranteed that gld_register
	 * has already been done.
	 */
	mutex_enter(&state->id_link_mutex);
	state->id_link_state = lstate;
	gld_linkstate(state->id_macinfo, lstate);
	mutex_exit(&state->id_link_mutex);

	/*
	 * Free the request slot allocated by the event thread.
	 */
	kmem_free(req, sizeof (ibd_req_t));

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
	if (state->id_link_state == GLD_LINKSTATE_UNKNOWN) {
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
		    GLD_LINKSTATE_UP : GLD_LINKSTATE_DOWN);
		mutex_exit(&state->id_link_mutex);
		return;
	}
	mutex_exit(&state->id_link_mutex);

	if (code == IBT_ERROR_PORT_DOWN)
		opcode = IBD_LINK_DOWN;

	req = kmem_alloc(sizeof (ibd_req_t), KM_SLEEP);
	req->rq_ptr = (void *)opcode;
	ibd_queue_work_slot(state, req, ASYNC_LINK);
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
	ibd_state_t *state;
	int instance;

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
	 *  Register ourselves with the GLD interface
	 *
	 *  gld_register will:
	 *	link us with the GLD module;
	 *	set our ddi_set_driver_private(9F) data to the macinfo ptr;
	 *	save the devinfo pointer in macinfo->gldm_devinfo;
	 *	create the minor device node.
	 */
	if (gld_register(dip, "ibd", state->id_macinfo) != DDI_SUCCESS) {
		DPRINT(10, "ibd_attach : failed in gld_register()");
		goto attach_fail_gld_register;
	}

	/*
	 * Setup the handler we will use for regular DLPI stuff. Its important
	 * to setup the recv handler after registering with gld. Setting it
	 * before causes at times an incoming packet to be forwarded to gld
	 * before the gld_register. This will result in gld dropping the packet
	 * which is ignored by ibd_rcq_handler, thus failing to re-arm the
	 * tavor events. This will cause tavor_isr on recv path to be not
	 * invoked any further.
	 */
	ibt_set_cq_handler(state->id_rcq_hdl, ibd_rcq_handler, state);
	if (ibt_enable_cq_notify(state->id_rcq_hdl, IBT_NEXT_COMPLETION) !=
	    IBT_SUCCESS) {
		DPRINT(10, "ibd_attach : failed in ibt_enable_cq_notify()\n");
		goto attach_fail_gld_register;
	}

	/*
	 * Setup the subnet notices handler after we initialize the a/mcaches
	 * and start the async thread, both of which are required for the
	 * trap handler to function properly. Enable the trap handler to
	 * queue requests to the async thread after the gld_register, because
	 * the async daemon invokes gld_sched(), which must be done after
	 * gld_register().
	 */
	ibt_register_subnet_notices(state->id_ibt_hdl,
	    ibd_snet_notices_handler, state);
	mutex_enter(&state->id_trap_lock);
	state->id_trap_stop = B_FALSE;
	mutex_exit(&state->id_trap_lock);

	/*
	 * Indicate link status to GLD and higher layers. By default,
	 * we assume we are in up state (which must have been true at
	 * least at the time the broadcast mcg's were probed); if there
	 * were any up/down transitions till the time we come here, the
	 * async handler will have updated last known state, which we
	 * use to tell GLD. The async handler will not send any
	 * notifications to GLD till we reach here in the initialization
	 * sequence.
	 */
	mutex_enter(&state->id_link_mutex);
	gld_linkstate(state->id_macinfo, state->id_link_state);
	mutex_exit(&state->id_link_mutex);

	return (DDI_SUCCESS);

	/* Attach failure points, cleanup */
attach_fail_gld_register:
	ibd_drv_fini(state);

attach_fail_drv_init:
	if (ibt_detach(state->id_ibt_hdl) != IBT_SUCCESS)
		ibd_print_warn(state, "failed to free IB resources");

attach_fail_ibt_attach:
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

	if (gld_unregister(state->id_macinfo) != DDI_SUCCESS) {
		DPRINT(10, "ibd_detach : failed in gld_unregister()");
		goto failed;
	}

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
	gld_mac_info_t *macinfo;

	if ((macinfo = gld_mac_alloc(dip)) == NULL) {
		DPRINT(10, "ibd_state_init : failed in gld_mac_alloc()");
		return (DDI_FAILURE);
	}

	mutex_init(&state->id_link_mutex, NULL, MUTEX_DRIVER, NULL);
	state->id_link_state = GLD_LINKSTATE_UNKNOWN;

	mutex_init(&state->id_trap_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&state->id_trap_cv, NULL, CV_DEFAULT, NULL);
	state->id_trap_stop = B_TRUE;
	state->id_trap_inprog = 0;

	mutex_init(&state->id_txcomp_lock, NULL, MUTEX_DRIVER, NULL);
	state->id_dip = dip;
	state->id_wcs = kmem_alloc(sizeof (ibt_wc_t) * IBD_WC_SIZE, KM_SLEEP);
	state->id_txwcs = kmem_alloc(sizeof (ibt_wc_t) * IBD_WC_SIZE, KM_SLEEP);

	state->id_sched_queued = B_FALSE;
	mutex_init(&state->id_sched_lock, NULL, MUTEX_DRIVER, NULL);

	state->id_tx_list.dl_head = NULL;
	state->id_tx_list.dl_tail = NULL;
	state->id_tx_list.dl_pending_sends = B_FALSE;
	state->id_tx_list.dl_cnt = 0;
	mutex_init(&state->id_tx_list.dl_mutex, NULL, MUTEX_DRIVER, NULL);

	state->id_rx_list.dl_head = NULL;
	state->id_rx_list.dl_tail = NULL;
	state->id_rx_list.dl_bufs_outstanding = 0;
	state->id_rx_list.dl_cnt = 0;
	mutex_init(&state->id_rx_list.dl_mutex, NULL, MUTEX_DRIVER, NULL);

	/* Link up various structs for later access */
	macinfo->gldm_private = (caddr_t)state;
	state->id_macinfo = macinfo;

	/*
	 * Initialize pointers to device specific functions which will be
	 * used by the generic layer.
	 */
	macinfo->gldm_reset = ibd_reset;
	macinfo->gldm_start = ibd_start;
	macinfo->gldm_stop = ibd_stop;
	macinfo->gldm_set_mac_addr = ibd_set_mac_addr;
	macinfo->gldm_set_multicast = ibd_set_multicast;
	macinfo->gldm_set_promiscuous = ibd_set_promiscuous;
	macinfo->gldm_get_stats = ibd_get_stats;
	macinfo->gldm_send = ibd_send;
	macinfo->gldm_intr = ibd_intr;
	macinfo->gldm_mdt_pre = ibd_mdt_pre;
	macinfo->gldm_mdt_send = ibd_mdt_txone;
	macinfo->gldm_mdt_post = ibd_mdt_post;
	macinfo->gldm_mdt_sgl = state->id_max_sqseg;
	macinfo->gldm_mdt_segs = IBD_MDTMAX_SEGS;

	/* Initialize board characteristics needed by the generic layer. */
	macinfo->gldm_ident = "InfiniBand DLPI Driver";
	macinfo->gldm_type = DL_IB;
	macinfo->gldm_minpkt = 0; /* assumes we pad ourselves */
	macinfo->gldm_addrlen = IPOIB_ADDRL;
	macinfo->gldm_saplen = -2;
	macinfo->gldm_capabilities = GLD_CAP_LINKSTATE;

	/* Other required initialization */
	macinfo->gldm_ppa = ddi_get_instance(dip);
	macinfo->gldm_devinfo = dip;

	return (DDI_SUCCESS);
}

/*
 * Post ibt_detach() driver deconstruction
 */
static void
ibd_state_fini(ibd_state_t *state)
{
	mutex_destroy(&state->id_tx_list.dl_mutex);
	mutex_destroy(&state->id_rx_list.dl_mutex);
	mutex_destroy(&state->id_sched_lock);
	mutex_destroy(&state->id_txcomp_lock);
	kmem_free(state->id_txwcs, sizeof (ibt_wc_t) * IBD_WC_SIZE);
	kmem_free(state->id_wcs, sizeof (ibt_wc_t) * IBD_WC_SIZE);
	cv_destroy(&state->id_trap_cv);
	mutex_destroy(&state->id_trap_lock);
	mutex_destroy(&state->id_link_mutex);
	gld_mac_free(state->id_macinfo);
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
	uint64_t		ifspeed;
	size_t			length;
	ib_lid_t		lid;
	sa_portinfo_record_t	req, *resp = NULL;
	ibmf_saa_access_args_t	args;
	ibmf_saa_handle_t	saa_handle;

	/*
	 * Due to serdes 8b10b encoding on the wire, 2.5 Gbps on wire
	 * translates to 2 Gbps data rate. Thus, 1X single data rate is
	 * 2000000000. Start with that as default.
	 */
	ifspeed = 2000000000;

	/* Get port lid */
	if (ibt_get_port_state(state->id_hca_hdl, state->id_port, NULL,
	    &lid) != IBT_SUCCESS)
		goto earlydone;

	if (ibmf_sa_session_open(state->id_sgid.gid_guid, 0, NULL,
	    IBMF_VERSION, 0, &saa_handle) != IBMF_SUCCESS)
		goto earlydone;

	/* Contact SA Access */
	bzero(&req, sizeof (sa_portinfo_record_t));
	req.EndportLID = lid;

	args.sq_attr_id		= SA_PORTINFORECORD_ATTRID;
	args.sq_access_type	= IBMF_SAA_RETRIEVE;
	args.sq_component_mask	= SA_PORTINFO_COMPMASK_PORTLID;
	args.sq_template	= &req;
	args.sq_callback	= NULL;
	args.sq_callback_arg	= NULL;

	ret = ibmf_sa_access(saa_handle, &args, 0, &length, (void **) &resp);
	if ((ret != IBMF_SUCCESS) || (length == 0) || (resp == NULL))
		goto done;

	/*
	 * 4X/12X needs appropriate multipliers. With IBA 1.2 additions,
	 * double and quad multipliers are also needed per LinkSpeedEnabled.
	 * In case SA does not return an expected value, report the default
	 * speed as 1X.
	 */
	ret = 1;
	switch (resp->PortInfo.LinkWidthActive) {
		case SM_LINK_WIDTH_ACTIVE_1X:
			ret = 1;
			break;
		case SM_LINK_WIDTH_ACTIVE_4X:
			ret = 4;
			break;
		case SM_LINK_WIDTH_ACTIVE_12X:
			ret = 12;
			break;
	}
	ifspeed *= ret;
	kmem_free(resp, length);

done:
	(void) ibmf_sa_session_close(&saa_handle, 0);

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
		DPRINT(10, "ibd_join_group : ibt_attach_mcg \n");
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
			ASSERT((mce != NULL) && (mce->mc_jstate ==
			    IB_MC_JSTATE_FULL));
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
	state->id_mgid.gid_guid = IB_MCGID_IPV4_LOW_GROUP_MASK;

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
	state->id_link_state = GLD_LINKSTATE_UP;
	mutex_exit(&state->id_link_mutex);

	ibt_free_portinfo(port_infop, port_infosz);

	state->id_link_speed = ibd_get_portspeed(state);

	ibt_status = ibt_query_hca(state->id_hca_hdl, &hca_attrs);
	ASSERT(ibt_status == IBT_SUCCESS);

	/*
	 * We need to determine whether the HCA can support checksum
	 * and indicate that to higher layers.
	 */
	if (ibd_csum_send > IBD_CSUM_NONE)
		state->id_macinfo->gldm_capabilities |= GLD_CAP_CKSUM_PARTIAL;

	if (ibd_find_bgroup(state) != IBT_SUCCESS) {
		DPRINT(10, "ibd_drv_init : failed in ibd_find_bgroup\n");
		goto drv_init_fail_find_bgroup;
	}
	state->id_macinfo->gldm_maxpkt = state->id_mtu - IPOIB_HDRSIZE;

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

	/*
	 * Check various tunable limits.
	 */
	if (hca_attrs.hca_max_sgl < IBD_MAX_SQSEG) {
		ibd_print_warn(state, "Setting #sgl = %d instead of default %d",
		    hca_attrs.hca_max_sgl, IBD_MAX_SQSEG);
		state->id_max_sqseg = hca_attrs.hca_max_sgl;
	} else {
		state->id_max_sqseg = IBD_MAX_SQSEG;
	}

	/*
	 * First, check #r/s wqes against max channel size.
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

		if (state->id_num_rwqe < IBD_RX_THRESHOLD) {
			ibd_print_warn(state, "Computed #rwqe %d based on "
			    "requested size and supportable CQ size is less "
			    "than the required threshold %d",
			    state->id_num_rwqe, IBD_RX_THRESHOLD);
			goto drv_init_fail_min_rwqes;
		}

		if (ibt_alloc_cq(state->id_hca_hdl, &cq_attr,
		    &state->id_rcq_hdl, &real_size) != IBT_SUCCESS) {
			DPRINT(10, "ibd_drv_init : failed in ibt_alloc_cq()\n");
			goto drv_init_fail_alloc_rcq;
		}

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

		if (state->id_num_rwqe < IBD_RX_THRESHOLD) {
			ibd_print_warn(state, "Computed #rwqe %d based on "
			    "requested size and supportable CQ size is less "
			    "than the required threshold %d",
			    state->id_num_rwqe, IBD_RX_THRESHOLD);
			goto drv_init_fail_min_rwqes;
		}

		if (ibt_alloc_cq(state->id_hca_hdl, &cq_attr,
		    &state->id_rcq_hdl, &real_size) != IBT_SUCCESS) {
			DPRINT(10, "ibd_drv_init : failed in ibt_alloc_cq()\n");
			goto drv_init_fail_alloc_rcq;
		}
		state->id_scq_hdl = state->id_rcq_hdl;
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

	ud_alloc_attr.ud_flags	= IBT_WR_SIGNALED;
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

	/* Initialize the Transmit buffer list */
	if (ibd_init_txlist(state) != DDI_SUCCESS) {
		DPRINT(10, "ibd_drv_init : failed in ibd_init_txlist()\n");
		goto drv_init_fail_txlist_init;
	}

	if ((ibd_separate_cqs == 1) && (ibd_txcomp_poll == 0)) {
		/* Setup the handler we will use for regular DLPI stuff */
		ibt_set_cq_handler(state->id_scq_hdl, ibd_scq_handler, state);
		if (ibt_enable_cq_notify(state->id_scq_hdl,
		    IBT_NEXT_COMPLETION) != IBT_SUCCESS) {
			DPRINT(10, "ibd_drv_init : failed in"
			    " ibt_enable_cq_notify()\n");
			goto drv_init_fail_cq_notify;
		}
	}

	/* Create the service fifos before we start receiving */
	if ((state->id_fifos = map_rx_srv_fifos(&state->id_nfifos,
	    state)) == NULL) {
		DPRINT(10, "ibd_drv_init : failed in map_rx_srv_fifos()\n");
		goto drv_init_fail_srv_fifo;
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

	/* Create the async thread */
	if ((kht = thread_create(NULL, 0, ibd_async_work, state, 0, &p0,
	    TS_RUN, minclsyspri)) == NULL) {
		/* Do we have to specially leave the group? */
		DPRINT(10, "ibd_drv_init : failed in thread_create\n");
		goto drv_init_fail_thread_create;
	}
	state->id_async_thrid = kht->t_did;

	/*
	 * The local mac address is now known. Create the IPoIB
	 * address.
	 */
	ibd_h2n_mac(&state->id_macaddr, state->id_qpnum,
	    state->id_sgid.gid_prefix, state->id_sgid.gid_guid);
	state->id_macinfo->gldm_vendor_addr = (uchar_t *)&state->id_macaddr;

	/*
	 * Similarly, program in the broadcast mac address.
	 */
	ibd_h2n_mac(&state->id_bcaddr, IB_QPN_MASK, state->id_mgid.gid_prefix,
	    state->id_mgid.gid_guid);
	state->id_macinfo->gldm_broadcast_addr = (uchar_t *)&state->id_bcaddr;

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

drv_init_fail_thread_create:
	ibd_leave_group(state, state->id_mgid, IB_MC_JSTATE_FULL);

drv_init_fail_join_group:
	ibd_fini_rxlist(state);

drv_init_fail_rxlist_init:
	unmap_rx_srv_fifos(state->id_nfifos, state->id_fifos);

drv_init_fail_srv_fifo:
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

drv_init_fail_alloc_scq:
	if (ibt_free_cq(state->id_rcq_hdl) != IBT_SUCCESS)
		DPRINT(10, "ibd_drv_init : Rx ibt_free_cq()");

drv_init_fail_min_rwqes:
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

/*
 * Allocate the statically allocated Tx buffer list.
 */
static int
ibd_init_txlist(ibd_state_t *state)
{
	ibd_swqe_t *swqe;
	int i;

	for (i = 0; i < state->id_num_swqe; i++) {
		if (ibd_alloc_swqe(state, &swqe) != DDI_SUCCESS) {
			DPRINT(10, "ibd_init_txlist : failed in "
			    "ibd_alloc_swqe()\n");
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

/*
 * Free the statically allocated Tx buffer list.
 */
static void
ibd_fini_txlist(ibd_state_t *state)
{
	ibd_swqe_t *node;

	mutex_enter(&state->id_tx_list.dl_mutex);
	while (state->id_tx_list.dl_head != NULL) {
		node = WQE_TO_SWQE(state->id_tx_list.dl_head);
		state->id_tx_list.dl_head = node->swqe_next;
		state->id_tx_list.dl_cnt--;
		ASSERT(state->id_tx_list.dl_cnt >= 0);
		ibd_free_swqe(state, node);
	}
	mutex_exit(&state->id_tx_list.dl_mutex);
}

/*
 * Allocate a single send wqe and register it so it is almost
 * ready to be posted to the hardware.
 */
static int
ibd_alloc_swqe(ibd_state_t *state, ibd_swqe_t **wqe)
{
	ibt_mr_attr_t mem_attr;
	ibd_swqe_t *swqe;

	swqe = kmem_alloc(sizeof (ibd_swqe_t), KM_SLEEP);
	*wqe = swqe;
	swqe->swqe_type = IBD_WQE_SEND;
	swqe->swqe_next = NULL;
	swqe->swqe_prev = NULL;
	swqe->swqe_im_mblk = NULL;
	swqe->w_mdtinfo = NULL;

	/* alloc copy buffer, must be max size to handle multiple mblk case */
	swqe->swqe_copybuf.ic_bufaddr = kmem_alloc(state->id_mtu, KM_SLEEP);

	mem_attr.mr_vaddr = (uint64_t)(uintptr_t)swqe->swqe_copybuf.ic_bufaddr;
	mem_attr.mr_len = state->id_mtu;
	mem_attr.mr_as = NULL;
	mem_attr.mr_flags = IBT_MR_SLEEP;
	if (ibt_register_mr(state->id_hca_hdl, state->id_pd_hdl, &mem_attr,
	    &swqe->swqe_copybuf.ic_mr_hdl, &swqe->swqe_copybuf.ic_mr_desc) !=
	    IBT_SUCCESS) {
		DPRINT(10, "ibd_alloc_swqe : failed in ibt_register_mem()");
		kmem_free(swqe->swqe_copybuf.ic_bufaddr,
		    state->id_mtu);
		kmem_free(swqe, sizeof (ibd_swqe_t));
		return (DDI_FAILURE);
	}

	swqe->swqe_copybuf.ic_sgl.ds_va =
	    (ib_vaddr_t)(uintptr_t)swqe->swqe_copybuf.ic_bufaddr;
	swqe->swqe_copybuf.ic_sgl.ds_key =
	    swqe->swqe_copybuf.ic_mr_desc.md_lkey;
	swqe->swqe_copybuf.ic_sgl.ds_len = 0; /* set in send */

	swqe->w_swr.wr_id = (ibt_wrid_t)(uintptr_t)swqe;
	swqe->w_swr.wr_flags = IBT_WR_SEND_SIGNAL;
	swqe->w_swr.wr_trans = IBT_UD_SRV;
	swqe->w_swr.wr_opcode = IBT_WRC_SEND;

	/* These are set in send */
	swqe->w_swr.wr_nds = 0;
	swqe->w_swr.wr_sgl = NULL;

	return (DDI_SUCCESS);
}

/*
 * Free an allocated send wqe.
 */
static void
ibd_free_swqe(ibd_state_t *state, ibd_swqe_t *swqe)
{

	if (ibt_deregister_mr(state->id_hca_hdl,
	    swqe->swqe_copybuf.ic_mr_hdl) != IBT_SUCCESS) {
		DPRINT(10, "ibd_free_swqe : failed in ibt_deregister_mem()");
		return;
	}
	kmem_free(swqe->swqe_copybuf.ic_bufaddr, state->id_mtu);
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
	if (ibt_post_recv(state->id_chnl_hdl, &rwqe->w_rwr, 1, NULL) !=
	    IBT_SUCCESS) {
		DPRINT(10, "ibd_post_rwqe : failed in ibt_post_recv()");
		return (DDI_FAILURE);
	}
	atomic_add_32(&state->id_rx_list.dl_cnt, 1);

	/*
	 * Buffers being recycled are already in the list.
	 */
	if (recycle)
		return (DDI_SUCCESS);

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

	if ((rwqe = kmem_alloc(sizeof (ibd_rwqe_t), KM_NOSLEEP)) == NULL) {
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

	if ((rwqe->rwqe_copybuf.ic_bufaddr = kmem_alloc(state->id_mtu +
	    IPOIB_GRH_SIZE, KM_NOSLEEP)) == NULL) {
		DPRINT(10, "ibd_alloc_rwqe: failed in kmem_alloc2");
		kmem_free(rwqe, sizeof (ibd_rwqe_t));
		return (DDI_FAILURE);
	}

	if ((rwqe->rwqe_im_mblk = desballoc(rwqe->rwqe_copybuf.ic_bufaddr,
	    state->id_mtu + IPOIB_GRH_SIZE, 0, &rwqe->w_freemsg_cb)) ==
	    NULL) {
		DPRINT(10, "ibd_alloc_rwqe : failed in desballoc()");
		kmem_free(rwqe->rwqe_copybuf.ic_bufaddr,
		    state->id_mtu + IPOIB_GRH_SIZE);
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
		DPRINT(10, "ibd_free_rwqe : failed in ibt_deregister_mr()");
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
	 * and possibly ASYNC_REAP requests. Rx interrupts were already
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
	 * handler will not cause any more ASYNC_REAP requests. Queue a
	 * request for the async thread to exit, which will be serviced
	 * after any pending ones. This can take a while, specially if the
	 * SM is unreachable, since IBMF will slowly timeout each SM request
	 * issued by the async thread. Reap the thread before continuing on,
	 * we do not want it to be lingering in modunloaded code.
	 */
	ibd_queue_work_slot(state, &state->id_ah_req, ASYNC_EXIT);
	thread_join(state->id_async_thrid);

	/*
	 * We can not be in promiscuous mode anymore, upper layers
	 * would have made a request to disable it (if ever set previously)
	 * before the detach is allowed to progress to this point; and the
	 * aysnc thread would have processed that request by now. Thus the
	 * nonmember list is guaranteed empty at this point.
	 */
	ASSERT(state->id_prom_op != COMPLETED);

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

	if (ibd_separate_cqs == 1) {
		status = ibt_free_cq(state->id_scq_hdl);
		ASSERT(status == IBT_SUCCESS);
	}

	/*
	 * We killed the receive interrupts, thus, we will not be
	 * required to handle received packets anymore. Thus, kill
	 * service threads since they are not going to be used anymore.
	 */
	unmap_rx_srv_fifos(state->id_nfifos, state->id_fifos);

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
	(void) gld_intr(state->id_macinfo);
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

	/*
	 * Poll for completed entries; the CQ will not interrupt any
	 * more for completed packets.
	 */
	ibd_poll_compq(state, state->id_scq_hdl);

	/*
	 * Now enable CQ notifications; all completions originating now
	 * will cause new interrupts.
	 */
	if (ibt_enable_cq_notify(state->id_scq_hdl, IBT_NEXT_COMPLETION) !=
	    IBT_SUCCESS) {
		/*
		 * We do not expect a failure here.
		 */
		DPRINT(10, "ibd_intr: ibt_enable_cq_notify() failed");
	}

	/*
	 * Repoll to catch all packets that might have completed after
	 * we finished the first poll loop and before interrupts got
	 * armed.
	 */
	ibd_poll_compq(state, state->id_scq_hdl);
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

			req = kmem_alloc(sizeof (ibd_req_t), KM_SLEEP);
			req->rq_gid = event->sm_notice_gid;
			req->rq_ptr = (void *)code;
			ibd_queue_work_slot(state, req, ASYNC_TRAP);
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

	if (state->id_prom_op == COMPLETED) {
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
	kmem_free(req, sizeof (ibd_req_t));

	ibd_async_done(state);
}

/*
 * GLD entry point to reset hardware.
 */
/* ARGSUSED */
static int
ibd_reset(gld_mac_info_t *macinfo)
{
	/*
	 * This will be invoked from Style 1 open() and Style 2
	 * attach() routines, ie just before the interface starts
	 * getting used.
	 */
	return (GLD_SUCCESS);
}

/*
 * GLD entry point to start hardware.
 */
/* ARGSUSED */
static int
ibd_start(gld_mac_info_t *macinfo)
{
	return (GLD_SUCCESS);
}

/*
 * GLD entry point to stop hardware from receiving packets.
 */
/* ARGSUSED */
static int
ibd_stop(gld_mac_info_t *macinfo)
{
#ifdef RUN_PERFORMANCE
	ibd_perf((ibd_state_t *)macinfo->gldm_private);
#endif
	return (GLD_SUCCESS);
}

/*
 * GLD entry point to modify device's mac address. We do not
 * allow address modifications.
 */
static int
ibd_set_mac_addr(gld_mac_info_t *macinfo, unsigned char *macaddr)
{
	ibd_state_t *state;

	state = (ibd_state_t *)macinfo->gldm_private;
	if (bcmp(macaddr, &state->id_macaddr, IPOIB_ADDRL) == 0)
		return (GLD_SUCCESS);
	else
		return (GLD_FAILURE);
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

	if (op == ASYNC_JOIN) {
		int ret = ERRORED;

		if (ibd_join_group(state, mgid, IB_MC_JSTATE_FULL) != NULL)
			ret = COMPLETED;

		state->id_multi_op = ret;
	} else {
		/*
		 * Here, we must search for the proper mcg_info and
		 * use that to leave the group.
		 */
		ibd_leave_group(state, mgid, IB_MC_JSTATE_FULL);
	}
}

/*
 * GLD entry point for multicast enable/disable requests.
 * Invoked by GLD only on the first multicast enable for a specific
 * address (GLD is free to retry ocassionally if we return RETRY),
 * and on last disable of the same address. Just queue the operation
 * to the async thread.
 */
static int
ibd_set_multicast(gld_mac_info_t *macinfo, unsigned char *mcmac, int op)
{
	ibd_state_t *state = (ibd_state_t *)macinfo->gldm_private;
	ipoib_mac_t *mcast;
	ib_gid_t mgid;
	ib_qpn_t mcqpn;
	int ret;

	/*
	 * The incoming multicast address might not be aligned properly
	 * on a 4 byte boundary to be considered an ipoib_mac_t. We force
	 * it to look like one though, to get the offsets of the mc gid,
	 * since we know we are not going to dereference any values with
	 * the ipoib_mac_t pointer.
	 */
	mcast = (ipoib_mac_t *)mcmac;

	/*
	 * Check validity of MCG address. We could additionally check
	 * that a enable/disable is not being issued on the "broadcast"
	 * mcg, but since this operation is only invokable by priviledged
	 * programs anyway, we allow the flexibility to those dlpi apps.
	 * Note that we do not validate the "scope" of the IBA mcg.
	 */
	bcopy(&mcast->ipoib_qpn, &mcqpn, sizeof (ib_qpn_t));
	if (mcqpn != htonl(IB_MC_QPN))
		return (GLD_FAILURE);

	/*
	 * If someone is trying to JOIN/LEAVE the broadcast group, we do
	 * nothing (ie we stay JOINed to the broadcast group done in
	 * ibd_drv_init()), to mimic ethernet behavior. IPv4 specifically
	 * requires to be joined to broadcast groups at all times.
	 * ibd_join_group() has an ASSERT(omce->mc_fullreap) that also
	 * depends on this.
	 */
	if (bcmp(mcast, state->id_macinfo->gldm_broadcast_addr,
	    IPOIB_ADDRL) == 0)
		return (GLD_SUCCESS);

	ibd_n2h_gid(mcast, &mgid);

	if (op == GLD_MULTI_ENABLE) {
		DPRINT(1, "ibd_set_multicast : %016llx:%016llx\n",
		    mgid.gid_prefix, mgid.gid_guid);
		ret = GLD_RETRY;
		mutex_enter(&state->id_mc_mutex);
		if (state->id_multi_op == NOTSTARTED) {
			state->id_multi_req.rq_gid = mgid;
			ibd_queue_work_slot(state, &state->id_multi_req,
			    ASYNC_JOIN);
			state->id_multi_op = ONGOING;
			bcopy(mcast, &state->id_multi_addr, IPOIB_ADDRL);
		} else if (bcmp(&state->id_multi_addr, mcast,
		    IPOIB_ADDRL) == 0) {
			if (state->id_multi_op != ONGOING) {
				if (state->id_multi_op == COMPLETED)
					ret = GLD_SUCCESS;
				else if (state->id_multi_op == ERRORED)
					ret = GLD_FAILURE;
				if (state->id_multi_queued) {
					state->id_multi_queued = B_FALSE;
					ibd_queue_work_slot(state,
					    &state->id_multi_req, ASYNC_POKE);
				} else {
					state->id_multi_op = NOTSTARTED;
				}
			}
		} else {
			/*
			 * Hmmm, a set was tried on another mcg. We
			 * need to make sure to gld_sched for this
			 * stream to retry once the ongoing one terminates.
			 * The gld_sched out of the async thread on completion
			 * of the mcg join is not enough; because the queued
			 * stream might come in and get a RETRY again because
			 * the mcg join result has still not been reaped by
			 * the originator. If gld_sched ensured that streams
			 * get tried in the order they received RETRYs, things
			 * would be simpler.
			 */
			state->id_multi_queued = B_TRUE;
		}
		mutex_exit(&state->id_mc_mutex);
	} else {
		ibd_mce_t *mce;
		DPRINT(1, "ibd_set_multicast : unset_multicast : "
		    "%016llx:%016llx", mgid.gid_prefix, mgid.gid_guid);
		ret = GLD_SUCCESS;
		mutex_enter(&state->id_mc_mutex);
		mce = IBD_MCACHE_FIND_FULL(state, mgid);
		mutex_exit(&state->id_mc_mutex);
		/*
		 * GLD should not have invoked us unless the mcg was
		 * added in the past.
		 */
		ASSERT(mce != NULL);
		ASSERT(bcmp(&mce->mc_req.rq_gid, &mgid, sizeof (mgid)) == 0);
		ibd_queue_work_slot(state, &mce->mc_req, ASYNC_LEAVE);
	}
	return (ret);
}

/*
 * The blocking part of the IBA promiscuous operations are done
 * out of here on the async thread. The dlpireq parameter indicates
 * whether this invocation is due to a dlpi request or due to
 * a port up/down event.
 */
static void
ibd_async_unsetprom(ibd_state_t *state, boolean_t dlpireq)
{
	ibd_mce_t *mce = list_head(&state->id_mc_non);
	ib_gid_t mgid;

	DPRINT(2, "ibd_async_unsetprom : async_unset_promisc");

	/*
	 * Mark the request slot as empty and reusable for the
	 * next promiscuous set request.
	 */
	if (dlpireq)
		state->id_prom_op = NOTSTARTED;

	while (mce != NULL) {
		mgid = mce->mc_info.mc_adds_vect.av_dgid;
		mce = list_next(&state->id_mc_non, mce);
		ibd_leave_group(state, mgid, IB_MC_JSTATE_NON);
	}
}

/*
 * The blocking part of the IBA promiscuous operations are done
 * out of here on the async thread. The dlpireq parameter indicates
 * whether this invocation is due to a dlpi request or due to
 * a port up/down event.
 */
static void
ibd_async_setprom(ibd_state_t *state, boolean_t dlpireq)
{
	ibt_mcg_attr_t mcg_attr;
	ibt_mcg_info_t *mcg_info;
	ib_gid_t mgid;
	uint_t numg;
	int i;

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
		if (dlpireq)
			state->id_prom_op = ERRORED;
		return;
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
	if (dlpireq)
		state->id_prom_op = COMPLETED;
	DPRINT(4, "ibd_async_setprom : async_set_promisc completes");
}

/*
 * GLD entry point for multicast promiscuous enable/disable requests.
 * GLD assumes phys state receives more packets than multi state,
 * which is not true for IPoIB. Thus, treat the multi and phys
 * promiscuous states the same way to work with GLD's assumption.
 */
static int
ibd_set_promiscuous(gld_mac_info_t *macinfo, int mode)
{
	ibd_state_t *state;
	int ret;

	state = (ibd_state_t *)macinfo->gldm_private;
	switch (mode) {
		case GLD_MAC_PROMISC_PHYS:
		case GLD_MAC_PROMISC_MULTI:
			DPRINT(1, "ibd_set_promiscuous : set_promisc : %d",
			    mode);
			/*
			 * Look at gld: this might be getting
			 * called because someone is turning off
			 * prom_phys. Nothing needs to be done in
			 * that case.
			 */
			ret = GLD_RETRY;
			mutex_enter(&state->id_mc_mutex);
			switch (state->id_prom_op) {
				case NOTSTARTED:
					ibd_queue_work_slot(state,
					    &state->id_prom_req, ASYNC_PROMON);
					state->id_prom_op = ONGOING;
					break;
				case COMPLETED:
					ret = GLD_SUCCESS;
					break;
				case ERRORED:
					state->id_prom_op = NOTSTARTED;
					ret = GLD_FAILURE;
			}
			/*
			 * Else in the ONGOING case, nothing special
			 * needs to be done; the async thread will poke
			 * all streams. A prior set, or the last unset
			 * request is still in the async queue.
			 */
			mutex_exit(&state->id_mc_mutex);
			return (ret);
		case GLD_MAC_PROMISC_NONE:
			DPRINT(1, "ibd_set_promiscuous : unset_promisc");
			/*
			 * Look at gld: this might be getting
			 * called because someone is turning off
			 * prom_phys or prom_multi. Mark operation
			 * as ongoing, to prevent a subsequent set
			 * operation from using the request slot
			 * unless the async thread is ready to give
			 * it up. The async thread will mark the
			 * request slot as usable as soon as it
			 * starts doing the unset operation.
			 */
			ASSERT(state->id_prom_op == COMPLETED);
			state->id_prom_op = ONGOING;
			ibd_queue_work_slot(state, &state->id_prom_req,
			    ASYNC_PROMOFF);
			return (GLD_SUCCESS);
		default:
			return (GLD_NOTSUPPORTED);
	}
}

/*
 * GLD entry point for gathering statistics.
 */
static int
ibd_get_stats(gld_mac_info_t *macinfo, struct gld_stats *sp)
{
	ibd_state_t *state = (ibd_state_t *)macinfo->gldm_private;

	sp->glds_errrcv = 0;
	sp->glds_underflow = 0;
	sp->glds_missed = 0;

	sp->glds_overflow = state->id_tx_short;	/* Tx overflow */
	sp->glds_speed = state->id_link_speed;
	sp->glds_media = GLDM_IB;
	sp->glds_errxmt = state->id_ah_error;	/* failed AH translation */
	sp->glds_norcvbuf = state->id_rx_short;	/* # times below water mark */
	sp->glds_intr = state->id_num_intrs;	/* number of intrs */

	return (GLD_SUCCESS);
}

/*
 * Arrange for a Tx request that is failing, or has already failed due to
 * Tx descriptor shortage to be retried soon. Used mostly with poll based
 * Tx completion, since gld_sched() can not be invoked in ibd_send() context
 * due to potential single processor deadlock (when the ibd_send() is
 * caused by gld_recv()).
 */
static void
ibd_tx_sched(ibd_state_t *state)
{
	mutex_enter(&state->id_sched_lock);
	/*
	 * If a sched request is already enqueued, do not try to do
	 * that again, since the async work request list would get
	 * corrupted.
	 */
	if (!state->id_sched_queued) {
		state->id_sched_queued = B_TRUE;
		ibd_queue_work_slot(state, &state->id_sched_req, ASYNC_SCHED);
	}
	mutex_exit(&state->id_sched_lock);
}

/*
 * The gld_sched() in ibd_async_work() does the work for us.
 */
static void
ibd_async_txsched(ibd_state_t *state)
{
	mutex_enter(&state->id_sched_lock);
	state->id_sched_queued = B_FALSE;
	mutex_exit(&state->id_sched_lock);
}

/*
 * Release one or more chained send wqes back into free list.
 */
static void
ibd_release_swqes(ibd_state_t *state, ibd_swqe_t *fswqe, ibd_swqe_t *lswqe,
    boolean_t send_context)
{
	boolean_t call_gld_sched = B_FALSE;

	/*
	 * Add back on Tx list for reuse.
	 */
	lswqe->swqe_next = NULL;
	mutex_enter(&state->id_tx_list.dl_mutex);
	if (state->id_tx_list.dl_pending_sends) {
		state->id_tx_list.dl_pending_sends = B_FALSE;
		call_gld_sched = B_TRUE;
	}
	if (state->id_tx_list.dl_head == NULL) {
		state->id_tx_list.dl_head = SWQE_TO_WQE(fswqe);
	} else {
		state->id_tx_list.dl_tail->w_next = SWQE_TO_WQE(fswqe);
	}
	state->id_tx_list.dl_tail = SWQE_TO_WQE(lswqe);
	mutex_exit(&state->id_tx_list.dl_mutex);

	/*
	 * See comments in ibd_tx_sched(); make sure not to call
	 * gld_sched() if we are in ibd_send() context.
	 */
	if (call_gld_sched)
		if ((ibd_txcomp_poll == 0) && (!send_context))
			gld_sched(state->id_macinfo);
		else
			ibd_tx_sched(state);
}

/*
 * Acquire a number of chained send wqe's from the free list. Returns the
 * number of wqe's actually allocated, and pointers to the first and last
 * in the chain.
 */
static int
ibd_acquire_swqes(ibd_state_t *state, ibd_swqe_t **fswqe, ibd_swqe_t **lswqe,
    int number)
{
	int numwqe = number;
	ibd_swqe_t *node, *wqes;

	/*
	 * Check and reclaim some of the completed Tx requests.
	 * If someone else is already in this code and pulling Tx
	 * completions, no need to poll, since the current lock holder
	 * will do the work anyway. Normally, we poll for completions
	 * every few Tx attempts, but if we are short on Tx descriptors,
	 * we always try to poll.
	 */
	if ((ibd_txcomp_poll == 1) &&
	    (((atomic_add_32_nv(&state->id_tx_sends, 1) & IBD_TXPOLL_MASK) ==
	    0) || state->id_tx_list.dl_pending_sends) &&
	    (mutex_tryenter(&state->id_txcomp_lock) != 0)) {
		DPRINT(10, "ibd_send : polling");
		ibd_poll_compq(state, state->id_scq_hdl);
		mutex_exit(&state->id_txcomp_lock);
	}

	/*
	 * Grab required transmit wqes.
	 */
	mutex_enter(&state->id_tx_list.dl_mutex);
	node = wqes = WQE_TO_SWQE(state->id_tx_list.dl_head);
	while ((node != NULL) && (numwqe-- > 1))
		node = WQE_TO_SWQE(node->swqe_next);

	/*
	 * If we did not find the number we were looking for, flag no resource.
	 * Adjust list appropriately in either case.
	 */
	if (numwqe != 0) {
		state->id_tx_list.dl_head = state->id_tx_list.dl_tail = NULL;
		state->id_tx_list.dl_pending_sends = B_TRUE;
		mutex_exit(&state->id_tx_list.dl_mutex);
		DPRINT(5, "ibd_acquire_swqes: out of Tx wqe");
		atomic_add_64(&state->id_tx_short, 1);
		if (ibd_txcomp_poll == 1) {
			/*
			 * Arrange for a future gld_sched(). Note that when
			 * the Tx is retried after a little bit, it will
			 * surely poll the completion queue above.
			 */
			ibd_tx_sched(state);
		}
	} else {
		state->id_tx_list.dl_head = node->swqe_next;
		if (state->id_tx_list.dl_tail == SWQE_TO_WQE(node))
			state->id_tx_list.dl_tail = NULL;
		mutex_exit(&state->id_tx_list.dl_mutex);
	}

	/*
	 * Set return parameters.
	 */
	*fswqe = wqes;
	*lswqe = node;
	return (number - numwqe);
}

typedef struct ibd_mpack_s {
	ibd_swqe_t	*ip_swqe;
	uint32_t	ip_start, ip_stuff, ip_flags;
	ibd_ace_t	*ip_ace;
	boolean_t	ip_copy;
	boolean_t	ip_noresources;
	int		ip_segs;
	ibt_mr_hdl_t	ip_mhdl[IBD_MDTMAX_SEGS + 1];
	ibt_mr_desc_t	ip_mdsc[IBD_MDTMAX_SEGS + 1];
} ibd_mpack_t;
_NOTE(SCHEME_PROTECTS_DATA("Protected by Scheme", ibd_mpack_s))

static void
ibd_mdt_txone(gld_mac_info_t *macinfo, void *cookie, pdescinfo_t *dl_pkt_info)
{
	ibd_state_t *state = (ibd_state_t *)macinfo->gldm_private;
	ibd_mpack_t *ptx = (ibd_mpack_t *)cookie;
	ibd_ace_t *ace = ptx->ip_ace;
	ibd_swqe_t *wqes, *node = ptx->ip_swqe;
	boolean_t docopy = ptx->ip_copy;
	uchar_t *pptr;
	int i, pktsize, seglen, seg = 0;

	/*
	 * Snag the next wqe before we post this one, since it could complete
	 * very fast and the wqe could get put at the end of the list,
	 * corrupting our chain. Set up for the next packet.
	 */
	wqes = WQE_TO_SWQE(node->swqe_next);
	ptx->ip_swqe = wqes;

	IBD_CKSUM_MDT_PACKET(dl_pkt_info, ptx->ip_start, ptx->ip_stuff,
	    ptx->ip_flags);
	node->w_ahandle = ace;
	node->w_swr.wr.ud.udwr_dest = ace->ac_dest;

	if (docopy) {
		node->w_swr.wr_sgl = &node->swqe_copybuf.ic_sgl;
		pptr = (uchar_t *)(uintptr_t)node->w_swr.wr_sgl->ds_va;
		pktsize = seglen = PDESC_HDRL(dl_pkt_info);
		if (seglen > 0) {
			bcopy(dl_pkt_info->hdr_rptr, pptr, seglen);
			pptr += seglen;
		}
		for (; seg < dl_pkt_info->pld_cnt; seg++)
			if ((seglen = PDESC_PLDL(dl_pkt_info, seg)) > 0) {
				bcopy(dl_pkt_info->pld_ary[seg].pld_rptr,
				    pptr, seglen);
				pptr += seglen;
				pktsize += seglen;
			}
		node->w_swr.wr_nds = 1;
		node->swqe_copybuf.ic_sgl.ds_len = pktsize;
	} else {
		seglen = PDESC_HDRL(dl_pkt_info);
		if (seglen > 0) {
			node->w_smblk_sgl[seg].ds_va =
			    (ib_vaddr_t)(uintptr_t)dl_pkt_info->hdr_rptr;
			node->w_smblk_sgl[seg].ds_key = ptx->ip_mdsc[0].md_lkey;
			node->w_smblk_sgl[seg].ds_len = seglen;
			seg++;
		}
		for (i = 0; i < dl_pkt_info->pld_cnt; i++) {
			if ((seglen = PDESC_PLDL(dl_pkt_info, i)) > 0) {
				node->w_smblk_sgl[seg].ds_va = (ib_vaddr_t)
				    (uintptr_t)dl_pkt_info->pld_ary[i].pld_rptr;
				node->w_smblk_sgl[seg].ds_key =
				    ptx->ip_mdsc[dl_pkt_info->
				    pld_ary[i].pld_pbuf_idx + 1].md_lkey;
				node->w_smblk_sgl[seg].ds_len = seglen;
				seg++;
			}
		}
		node->w_swr.wr_sgl = node->w_smblk_sgl;
		node->w_swr.wr_nds = seg;
	}

	if (ibt_post_send(state->id_chnl_hdl, &node->w_swr, 1, NULL) !=
	    IBT_SUCCESS) {
		/*
		 * We never expect a failure here. But handle it, just in case.
		 * If this is not the last packet, there are no problems; if
		 * it is the last packet and the previous ones have not been
		 * transmitted yet by the hardware, in the registration case,
		 * the hardware might transmit garbage since we will be
		 * freemsg'ing. The AH is still safe.
		 */
		DPRINT(5, "ibd_mdt_txone: posting failed");
		ibd_tx_cleanup(state, node, B_TRUE);
	}
}

static int
ibd_mdt_pre(gld_mac_info_t *macinfo, mblk_t *mp, void **cookie)
{
	ibd_state_t *state = (ibd_state_t *)macinfo->gldm_private;
	multidata_t *dlmdp = mmd_getmultidata(mp);
	ibd_mpack_t *mdinfo;
	mbufinfo_t bufinfo, *binfo = &bufinfo;
	pattrinfo_t attr_info;
	uchar_t *dlap;
	ibt_mr_attr_t mem_attr;
	ibd_swqe_t *wqes, *node;
	ipoib_mac_t *dest;
	size_t hsize, psize = 0;
	int numwqes, numpackets = (int)mmd_getcnt(dlmdp, NULL, NULL);
	int i, ret;
	uint32_t end, value;
	boolean_t noresources = B_FALSE;

	ASSERT(DB_TYPE(mp) == M_MULTIDATA);
	ASSERT(mp->b_cont == NULL);

	if ((numwqes = ibd_acquire_swqes(state, &wqes, &node, numpackets)) == 0)
		return (0);
	else if (numwqes != numpackets)
		noresources = B_TRUE;

	DPRINT(20, "ibd_mdt_pre: %d packets %p/%p\n", numwqes, wqes, node);

	/*
	 * Allocate the cookie that will be passed to subsequent packet
	 * transmit and post_mdt calls by GLD. We can not sleep, so if
	 * there is no memory, just tell GLD to drop the entire MDT message.
	 */
	if ((mdinfo = kmem_zalloc(sizeof (ibd_mpack_t), KM_NOSLEEP)) == NULL) {
		ibd_release_swqes(state, wqes, node, B_TRUE);
		return (-1);
	}
	*cookie = (void *)mdinfo;
	mdinfo->ip_noresources = noresources;

	/*
	 * Walk Global Attributes. If TCP failed to provide destination
	 * information, or some interposing module removed the information,
	 * fail the entire message.
	 */
	attr_info.type = PATTR_DSTADDRSAP;
	if (mmd_getpattr(dlmdp, NULL, &attr_info) == NULL) {
		ibd_release_swqes(state, wqes, node, B_TRUE);
		kmem_free(mdinfo, sizeof (ibd_mpack_t));
		return (-1);
	}
	dlap = ((pattr_addr_t *)attr_info.buf)->addr;
	dest = (ipoib_mac_t *)dlap;

	/*
	 * Get the AH for this destination, incrementing the posted
	 * reference count properly.
	 */
	if ((mdinfo->ip_ace = ibd_acache_lookup(state, dest, &ret,
	    numwqes)) == NULL) {
		ibd_release_swqes(state, wqes, node, B_TRUE);
		kmem_free(mdinfo, sizeof (ibd_mpack_t));
		return ((ret == GLD_FAILURE) ? -1 : 0);
	}

	/*
	 * Depending on how costly it is to copy vs register, we try to
	 * register, falling back on copying if we fail.
	 */
	mmd_getregions(dlmdp, &bufinfo);
	hsize = binfo->hbuf_wptr - binfo->hbuf_rptr;
	for (i = 0; i < binfo->pbuf_cnt; i++)
		psize += (binfo->pbuf_ary[i].pbuf_wptr -
		    binfo->pbuf_ary[i].pbuf_rptr);
	if ((hsize + psize) > IBD_TX_COPY_THRESHOLD) {
		mdinfo->ip_segs = i + 1;
		if (hsize != 0) {
			mem_attr.mr_as = NULL;
			mem_attr.mr_flags = IBT_MR_NOSLEEP;
			mem_attr.mr_vaddr =
			    (uint64_t)(uintptr_t)binfo->hbuf_rptr;
			mem_attr.mr_len = hsize;
			if (ibt_register_mr(state->id_hca_hdl, state->id_pd_hdl,
			    &mem_attr, &mdinfo->ip_mhdl[0],
			    &mdinfo->ip_mdsc[0]) != IBT_SUCCESS)
				goto ibd_mdt_copy;
			DPRINT(10, "ibd_mdt_pre: hsize = %d\n", hsize);
		}
		for (i = 0; i < binfo->pbuf_cnt; i++) {
			if ((psize = (binfo->pbuf_ary[i].pbuf_wptr -
			    binfo->pbuf_ary[i].pbuf_rptr)) != 0) {
				mem_attr.mr_as = NULL;
				mem_attr.mr_flags = IBT_MR_NOSLEEP;
				mem_attr.mr_vaddr = (uint64_t)(uintptr_t)
				    binfo->pbuf_ary[i].pbuf_rptr;
				mem_attr.mr_len = psize;
				if (ibt_register_mr(state->id_hca_hdl,
				    state->id_pd_hdl, &mem_attr,
				    &mdinfo->ip_mhdl[i + 1],
				    &mdinfo->ip_mdsc[i + 1]) != IBT_SUCCESS) {
					for (; i >= 0; i--) {
						(void) ibt_deregister_mr(
						    state->id_hca_hdl,
						    mdinfo->ip_mhdl[i]);
					}
					goto ibd_mdt_copy;
				}
				DPRINT(10, "ibd_mdt_pre: psize = %lu\n", psize);
			}
		}

		mdinfo->ip_copy = B_FALSE;

		/*
		 * All the deregistration must happen once the last swqe
		 * completes.
		 */
		node->swqe_im_mblk = mp;
		node->w_mdtinfo = mdinfo;
		DPRINT(10, "ibd_mdt_pre: last wqe = %p\n", node);
	} else {
ibd_mdt_copy:
		mdinfo->ip_copy = B_TRUE;
	}

	/*
	 * Do checksum related work.
	 */
	IBD_CKSUM_MDT(mp, dlmdp, NULL, &mdinfo->ip_start, &mdinfo->ip_stuff,
	    &end, &value, &mdinfo->ip_flags);

	mdinfo->ip_swqe = wqes;
	return (numwqes);
}

/* ARGSUSED */
static void
ibd_mdt_post(gld_mac_info_t *macinfo, mblk_t *mp, void *cookie)
{
	ibd_mpack_t *mdinfo = (ibd_mpack_t *)cookie;

	if (mdinfo->ip_copy) {
		if (!mdinfo->ip_noresources)
			freemsg(mp);
		kmem_free(mdinfo, sizeof (ibd_mpack_t));
	}
}

/*
 * GLD entry point for transmitting a datagram.
 * The passed in packet has this format:
 * IPOIB_ADDRL b dest addr :: 2b sap :: 2b 0's :: data
 */
static int
ibd_send(gld_mac_info_t *macinfo, mblk_t *mp)
{
	ibt_status_t ibt_status;
	ibt_mr_attr_t mem_attr;
	ibd_state_t *state = (ibd_state_t *)macinfo->gldm_private;
	ibd_ace_t *ace;
	ibd_swqe_t *node;
	ipoib_mac_t *dest;
	ipoib_ptxhdr_t *ipibp;
	ip6_t *ip6h;
	mblk_t *nmp = mp;
	uint_t pktsize;
	size_t	blksize;
	uchar_t *bufp;
	int i, ret, len, nmblks = 1;
	boolean_t dofree = B_TRUE;

	if (ibd_acquire_swqes(state, &node, &node, 1) == 0)
		return (GLD_NORESOURCES);

	/*
	 * Obtain an address handle for the destination.
	 */
	dest = (ipoib_mac_t *)mp->b_rptr;
	if ((ace = ibd_acache_lookup(state, dest, &ret, 1)) != NULL) {
		node->w_ahandle = ace;
		node->w_swr.wr.ud.udwr_dest = ace->ac_dest;
	} else {
		DPRINT(5,
		    "ibd_send: acache lookup %s for %08X:%08X:%08X:%08X:%08X",
		    ((ret == GLD_FAILURE) ? "failed" : "queued"),
		    htonl(dest->ipoib_qpn), htonl(dest->ipoib_gidpref[0]),
		    htonl(dest->ipoib_gidpref[1]),
		    htonl(dest->ipoib_gidsuff[0]),
		    htonl(dest->ipoib_gidsuff[1]));
		node->w_ahandle = NULL;
		goto ibd_send_fail;
	}

	/*
	 * For ND6 packets, padding is at the front of the source lladdr.
	 * Insert the padding at front.
	 */
	ipibp = (ipoib_ptxhdr_t *)mp->b_rptr;
	if (ntohs(ipibp->ipoib_rhdr.ipoib_type) == IP6_DL_SAP) {
		if (MBLKL(mp) < sizeof (ipoib_ptxhdr_t) + IPV6_HDR_LEN) {
			if (!pullupmsg(mp, IPV6_HDR_LEN +
			    sizeof (ipoib_ptxhdr_t))) {
				DPRINT(10, "ibd_send: pullupmsg failure ");
				ret = GLD_FAILURE;
				goto ibd_send_fail;
			}
		}
		ip6h = (ip6_t *)((uchar_t *)ipibp + sizeof (ipoib_ptxhdr_t));
		len = ntohs(ip6h->ip6_plen);
		if (ip6h->ip6_nxt == IPPROTO_ICMPV6) {
			if (MBLKL(mp) < sizeof (ipoib_ptxhdr_t) +
			    IPV6_HDR_LEN + len) {
				if (!pullupmsg(mp, sizeof (ipoib_ptxhdr_t) +
				    IPV6_HDR_LEN + len)) {
					DPRINT(10, "ibd_send: pullupmsg "
					    "failure ");
					ret = GLD_FAILURE;
					goto ibd_send_fail;
				}
			}
			/* LINTED: E_CONSTANT_CONDITION */
			IBD_PAD_NSNA(ip6h, len, IBD_SEND);
		}
	}

	mp->b_rptr += IPOIB_ADDRL;
	while (((nmp = nmp->b_cont) != NULL) &&
	    (++nmblks < (state->id_max_sqseg + 1)))
		;
	pktsize = msgsize(mp);
	if (pktsize > state->id_mtu) {
		ret = GLD_BADARG;
		goto ibd_send_fail;
	}

	/*
	 * Do checksum related work.
	 */
	IBD_CKSUM_SEND(mp);

	/*
	 * Copy the data to preregistered buffers, or register the buffer.
	 */
	if ((nmblks <= state->id_max_sqseg) &&
	    (pktsize > IBD_TX_COPY_THRESHOLD)) {
		for (i = 0, nmp = mp; i < nmblks; i++, nmp = nmp->b_cont) {
			mem_attr.mr_vaddr = (uint64_t)(uintptr_t)nmp->b_rptr;
			mem_attr.mr_len = nmp->b_wptr - nmp->b_rptr;
			mem_attr.mr_as = NULL;
			mem_attr.mr_flags = IBT_MR_NOSLEEP;
			ibt_status = ibt_register_mr(state->id_hca_hdl,
			    state->id_pd_hdl, &mem_attr,
			    &node->w_smblkbuf[i].im_mr_hdl,
			    &node->w_smblkbuf[i].im_mr_desc);
			if (ibt_status != IBT_SUCCESS) {
				/*
				 * We do not expect any error other than
				 * IBT_INSUFF_RESOURCE.
				 */
				if (ibt_status != IBT_INSUFF_RESOURCE)
					DPRINT(10, "ibd_send:%d\n",
					    "failed in ibt_register_mem()",
					    ibt_status);
				DPRINT(5, "ibd_send: registration failed");
				node->w_swr.wr_nds = i;
				/*
				 * Deregister already registered memory;
				 * fallback to copying the mblk.
				 */
				ibd_deregister_mr(state, node);
				goto ibd_copy_path;
			}
			node->w_smblk_sgl[i].ds_va =
			    (ib_vaddr_t)(uintptr_t)nmp->b_rptr;
			node->w_smblk_sgl[i].ds_key =
			    node->w_smblkbuf[i].im_mr_desc.md_lkey;
			node->w_smblk_sgl[i].ds_len =
			    nmp->b_wptr - nmp->b_rptr;
		}
		node->swqe_im_mblk = mp;
		node->w_swr.wr_sgl = node->w_smblk_sgl;
		node->w_swr.wr_nds = nmblks;
		dofree = B_FALSE;
	} else {
ibd_copy_path:
		node->swqe_copybuf.ic_sgl.ds_len = pktsize;
		node->w_swr.wr_nds = 1;
		node->w_swr.wr_sgl = &node->swqe_copybuf.ic_sgl;

		bufp = (uchar_t *)(uintptr_t)node->w_swr.wr_sgl->ds_va;
		for (nmp = mp; nmp != NULL; nmp = nmp->b_cont) {
			blksize = MBLKL(nmp);
			bcopy(nmp->b_rptr, bufp, blksize);
			bufp += blksize;
		}
	}

	/*
	 * Queue the wqe to hardware.
	 */
	ibt_status = ibt_post_send(state->id_chnl_hdl, &node->w_swr, 1, NULL);
	if (ibt_status != IBT_SUCCESS) {
		/*
		 * We should not fail here; but just in case we do, we
		 * tell GLD about this error.
		 */
		ret = GLD_FAILURE;
		DPRINT(5, "ibd_send: posting failed");
		goto ibd_send_fail;
	}

	DPRINT(10, "ibd_send : posted packet %d to %08X:%08X:%08X:%08X:%08X",
	    INCTXPACK, htonl(ace->ac_mac.ipoib_qpn),
	    htonl(ace->ac_mac.ipoib_gidpref[0]),
	    htonl(ace->ac_mac.ipoib_gidpref[1]),
	    htonl(ace->ac_mac.ipoib_gidsuff[0]),
	    htonl(ace->ac_mac.ipoib_gidsuff[1]));

	if (dofree)
		freemsg(mp);

	return (GLD_SUCCESS);

ibd_send_fail:
	ibd_tx_cleanup(state, node, B_TRUE);
	return (ret);
}

/*
 * GLD entry point for handling interrupts. When using combined CQ,
 * this handles Tx and Rx completions. With separate CQs, this handles
 * only Rx completions.
 */
static uint_t
ibd_intr(gld_mac_info_t *macinfo)
{
	ibd_state_t *state = (ibd_state_t *)macinfo->gldm_private;

	/*
	 * Poll for completed entries; the CQ will not interrupt any
	 * more for incoming (or transmitted) packets.
	 */
	ibd_poll_compq(state, state->id_rcq_hdl);

	/*
	 * Now enable CQ notifications; all packets that arrive now
	 * (or complete transmission) will cause new interrupts.
	 */
	if (ibt_enable_cq_notify(state->id_rcq_hdl, IBT_NEXT_COMPLETION) !=
	    IBT_SUCCESS) {
		/*
		 * We do not expect a failure here.
		 */
		DPRINT(10, "ibd_intr: ibt_enable_cq_notify() failed");
	}

	/*
	 * Repoll to catch all packets that might have arrived after
	 * we finished the first poll loop and before interrupts got
	 * armed.
	 */
	ibd_poll_compq(state, state->id_rcq_hdl);

	return (DDI_INTR_CLAIMED);
}

/*
 * Common code for interrupt handling as well as for polling
 * for all completed wqe's while detaching.
 */
static void
ibd_poll_compq(ibd_state_t *state, ibt_cq_hdl_t cq_hdl)
{
	ibd_wqe_t *wqe;
	ibt_wc_t *wc, *wcs;
	uint_t numwcs;
	int i;

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
	if (cq_hdl == state->id_rcq_hdl)
		wcs = state->id_wcs;
	else
		wcs = state->id_txwcs;

	while (ibt_poll_cq(cq_hdl, wcs, IBD_WC_SIZE, &numwcs) == IBT_SUCCESS) {

		for (i = 0, wc = wcs; i < numwcs; i++, wc++) {
			wqe = (ibd_wqe_t *)(uintptr_t)wc->wc_id;
			ASSERT((wqe->w_type == IBD_WQE_SEND) ||
			    (wqe->w_type == IBD_WQE_RECV));
			if (wc->wc_status != IBT_WC_SUCCESS) {
				/*
				 * Channel being torn down.
				 */
				if (wc->wc_status == IBT_WC_WR_FLUSHED_ERR) {
					DPRINT(5, "ibd_intr: flush error");
					/*
					 * Only invoke the Tx handler to
					 * release possibly held resources
					 * like AH refcount etc. Can not
					 * invoke Rx handler because it might
					 * try adding buffers to the Rx pool
					 * when we are trying to deinitialize.
					 */
					if (wqe->w_type == IBD_WQE_RECV)
						continue;
				} else {
					DPRINT(10, "%s %d",
					    "ibd_intr: Bad CQ status",
					    wc->wc_status);
				}
			}
			if (wqe->w_type == IBD_WQE_SEND)
				ibd_tx_cleanup(state, WQE_TO_SWQE(wqe),
				    B_FALSE);
			else
				ibd_process_rx(state, WQE_TO_RWQE(wqe), wc);
		}
	}
}

/*
 * Deregister the mr associated with a given mblk.
 */
static void
ibd_deregister_mr(ibd_state_t *state, ibd_swqe_t *swqe)
{
	int i;

	DPRINT(20, "ibd_deregister_mr: wqe = %p, seg = %d\n", swqe,
	    swqe->w_swr.wr_nds);
	/*
	 * If this is an MDT case, process accordingly.
	 */
	if (swqe->w_mdtinfo != NULL) {
		ibd_mpack_t *mdinfo = (ibd_mpack_t *)swqe->w_mdtinfo;

		for (i = 0; i < mdinfo->ip_segs; i++)
			if ((mdinfo->ip_mhdl[i] != 0) &&
			    (ibt_deregister_mr(state->id_hca_hdl,
			    mdinfo->ip_mhdl[i]) != IBT_SUCCESS))
				DPRINT(10, "MDT deregistration failed\n");
		ASSERT(!mdinfo->ip_copy);
		kmem_free(mdinfo, sizeof (ibd_mpack_t));
		swqe->w_mdtinfo = NULL;
		return;
	}

	for (i = 0; i < swqe->w_swr.wr_nds; i++) {
		if (ibt_deregister_mr(state->id_hca_hdl,
		    swqe->w_smblkbuf[i].im_mr_hdl) != IBT_SUCCESS) {
			/*
			 * We do not expect any errors here.
			 */
			DPRINT(10, "failed in ibt_deregister_mem()\n");
		}
	}
}

/*
 * Common code that deals with clean ups after a successful or
 * erroneous transmission attempt.
 */
static void
ibd_tx_cleanup(ibd_state_t *state, ibd_swqe_t *swqe, boolean_t send_context)
{
	ibd_ace_t *ace = swqe->w_ahandle;

	DPRINT(20, "ibd_tx_cleanup %p\n", swqe);

	/*
	 * If this was a dynamic registration in ibd_send() or in MDT,
	 * deregister now.
	 */
	if (swqe->swqe_im_mblk != NULL) {
		ibd_deregister_mr(state, swqe);
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
					    &mce->mc_req, ASYNC_REAP);
				}
				IBD_ACACHE_INSERT_FREE(state, ace);
			}
			mutex_exit(&state->id_ac_mutex);
		}
	}

	/*
	 * Release the send wqe for reuse.
	 */
	ibd_release_swqes(state, swqe, swqe, send_context);
}

/*
 * Processing to be done after receipt of a packet; hand off to GLD
 * in the format expected by GLD.
 * The recvd packet has this format: 2b sap :: 00 :: data.
 */
static void
ibd_process_rx(ibd_state_t *state, ibd_rwqe_t *rwqe, ibt_wc_t *wc)
{
	ipoib_pgrh_t *pgrh;
	mblk_t *mp;
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
	 * If the GRH is not valid, indicate to GLD by setting
	 * the VerTcFlow field to 0. Else, update the pseudoGRH
	 * so that GLD can determine the source mac of the packet.
	 */
	pgrh = (ipoib_pgrh_t *)mp->b_rptr;
	if (wc->wc_flags & IBT_WC_GRH_PRESENT)
		pgrh->ipoib_sqpn = htonl(wc->wc_qpn);
	else
		pgrh->ipoib_vertcflow = 0;

	DPRINT(10, "ibd_process_rx : got packet %d", INCRXPACK);

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
			}
			/* LINTED: E_CONSTANT_CONDITION */
			IBD_PAD_NSNA(ip6h, len, IBD_RECV);
		}
	}

	/*
	 * Hand off to service thread/GLD. When we have hardware that
	 * does hardware checksum, we will pull the checksum from the
	 * work completion structure here.
	 * on interrupt cpu.
	 */
	ibd_send_up(state, mp);

	/*
	 * Possibly replenish the Rx pool if needed.
	 */
	if (rxcnt < IBD_RX_THRESHOLD) {
		state->id_rx_short++;
		if (ibd_alloc_rwqe(state, &rwqe) == DDI_SUCCESS) {
			if (ibd_post_rwqe(state, rwqe, B_FALSE) ==
			    DDI_FAILURE) {
				ibd_free_rwqe(state, rwqe);
				return;
			}
		}
	}
}

/*
 * Callback code invoked from STREAMs when the recv data buffer is free
 * for recycling.
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
		DPRINT(6, "ibd_freemsg_cb: wqe being freed");
		return;
	}

	/*
	 * Upper layer has released held mblk.
	 */
	atomic_add_32(&state->id_rx_list.dl_bufs_outstanding, -1);

	if (state->id_rx_list.dl_cnt >= state->id_num_rwqe) {
		/*
		 * There are already enough buffers on the Rx ring.
		 * Free this one up.
		 */
		rwqe->rwqe_im_mblk = NULL;
		ibd_delete_rwqe(state, rwqe);
		ibd_free_rwqe(state, rwqe);
		DPRINT(6, "ibd_freemsg_cb: free up wqe");
	} else {
		rwqe->rwqe_im_mblk = desballoc(rwqe->rwqe_copybuf.ic_bufaddr,
		    state->id_mtu + IPOIB_GRH_SIZE, 0, &rwqe->w_freemsg_cb);
		if (rwqe->rwqe_im_mblk == NULL) {
			ibd_delete_rwqe(state, rwqe);
			ibd_free_rwqe(state, rwqe);
			DPRINT(6, "ibd_freemsg_cb: desballoc failed");
			return;
		}

		/*
		 * Post back to h/w. We could actually have more than
		 * id_num_rwqe WQEs on the list if there were multiple
		 * ibd_freemsg_cb() calls outstanding (since the lock is
		 * not held the entire time). This will start getting
		 * corrected over subsequent ibd_freemsg_cb() calls.
		 */
		if (ibd_post_rwqe(state, rwqe, B_TRUE) == DDI_FAILURE) {
			ibd_delete_rwqe(state, rwqe);
			ibd_free_rwqe(state, rwqe);
			return;
		}
	}
}

#ifdef RUN_PERFORMANCE

/*
 * To run the performance test, first do the "ifconfig ibdN plumb" on
 * the Rx and Tx side. Then use mdb -kw to tweak the following variables:
 * ibd_performance=1.
 * ibd_receiver=1 on Rx side.
 * ibd_sender=1 on Tx side.
 * Do "ifconfig ibdN" on Rx side to get the Rx mac address, and update
 * ibd_dest on the Tx side. Next, do ifconfig/unplumb on Rx, this will
 * make it drop into a 1 minute loop waiting for packets. An
 * ifconfig/unplumb on the Tx will cause it to send packets to Rx.
 */

#define	IBD_NUM_UNSIGNAL	ibd_num_unsignal
#define	IBD_TX_PKTSIZE		ibd_tx_pktsize
#define	IBD_TX_DATASIZE		ibd_tx_datasize

static ibd_swqe_t **swqes;
static ibt_wc_t *wcs;

/*
 * Set these on Rx and Tx side to do performance run.
 */
static int ibd_performance = 0;
static int ibd_receiver = 0;
static int ibd_sender = 0;
static ipoib_mac_t ibd_dest;

/*
 * Interrupt coalescing is achieved by asking for a completion intr
 * only every ibd_num_unsignal'th packet.
 */
static int ibd_num_unsignal = 8;

/*
 * How big is each packet?
 */
static int ibd_tx_pktsize = 2048;

/*
 * Total data size to be transmitted.
 */
static int ibd_tx_datasize = 512*1024*1024;

static volatile boolean_t cq_handler_ran = B_FALSE;
static volatile int num_completions;

/* ARGSUSED */
static void
ibd_perf_handler(ibt_cq_hdl_t cq_hdl, void *arg)
{
	ibd_state_t *state = (ibd_state_t *)arg;
	ibt_cq_hdl_t cqhdl;
	ibd_wqe_t *wqe;
	uint_t polled, i;
	boolean_t cq_enabled = B_FALSE;

	if (ibd_receiver == 1)
		cqhdl = state->id_rcq_hdl;
	else
		cqhdl = state->id_scq_hdl;

	/*
	 * Mark the handler as having run and possibly freed up some
	 * slots. Blocked sends can be retried.
	 */
	cq_handler_ran = B_TRUE;

repoll:
	while (ibt_poll_cq(cqhdl, wcs, IBD_NUM_UNSIGNAL, &polled) ==
	    IBT_SUCCESS) {
		num_completions += polled;
		if (ibd_receiver == 1) {
			/*
			 * We can immediately recycle the buffer. No
			 * need to pass up to any IP layer ...
			 */
			for (i = 0; i < polled; i++) {
				wqe = (ibd_wqe_t *)wcs[i].wc_id;
				(void) ibt_post_recv(state->id_chnl_hdl,
				    &(WQE_TO_RWQE(wqe))->w_rwr, 1, NULL);
			}
		}
	}

	/*
	 * If we just repolled, we are done; exit.
	 */
	if (cq_enabled)
		return;

	/*
	 * Enable CQ.
	 */
	if (ibt_enable_cq_notify(cqhdl, IBT_NEXT_COMPLETION) != IBT_SUCCESS) {
		/*
		 * We do not expect a failure here.
		 */
		cmn_err(CE_CONT, "ibd_perf_handler: notify failed");
	}
	cq_enabled = B_TRUE;

	/*
	 * Repoll for packets that came in after we finished previous
	 * poll loop but before we turned on notifications.
	 */
	goto repoll;
}

static void
ibd_perf_tx(ibd_state_t *state)
{
	ibt_mr_hdl_t mrhdl;
	ibt_mr_desc_t mrdesc;
	ibt_mr_attr_t mem_attr;
	ibt_status_t stat;
	ibd_ace_t *ace = NULL;
	ibd_swqe_t *node;
	uchar_t *sendbuf;
	longlong_t stime, etime;
	longlong_t sspin, espin, tspin = 0;
	int i, reps, packets;

	cmn_err(CE_CONT, "ibd_perf_tx: Tx to %08X:%08X:%08X:%08X:%08X",
	    htonl(ibd_dest.ipoib_qpn), htonl(ibd_dest.ipoib_gidpref[0]),
	    htonl(ibd_dest.ipoib_gidpref[1]), htonl(ibd_dest.ipoib_gidsuff[0]),
	    htonl(ibd_dest.ipoib_gidsuff[1]));
	if ((ibd_dest.ipoib_qpn == 0) || (ibd_dest.ipoib_gidsuff[1] == 0) ||
	    (ibd_dest.ipoib_gidpref[1] == 0)) {
		cmn_err(CE_CONT, "ibd_perf_tx: Invalid Rx address");
		return;
	}

	packets = (IBD_TX_DATASIZE / IBD_TX_PKTSIZE);
	reps = (packets / IBD_NUM_SWQE);

	cmn_err(CE_CONT, "ibd_perf_tx: Data Size = %d", IBD_TX_DATASIZE);
	cmn_err(CE_CONT, "ibd_perf_tx: Packet Size = %d", IBD_TX_PKTSIZE);
	cmn_err(CE_CONT, "ibd_perf_tx: # Packets = %d", packets);
	cmn_err(CE_CONT, "ibd_perf_tx: SendQ depth = %d", IBD_NUM_SWQE);
	cmn_err(CE_CONT, "ibd_perf_tx: Signal Grp size = %d", IBD_NUM_UNSIGNAL);
	if ((packets % IBD_NUM_UNSIGNAL) != 0) {
		/*
		 * This is required to ensure the last packet will trigger
		 * a CQ handler callback, thus we can spin waiting fot all
		 * packets to be received.
		 */
		cmn_err(CE_CONT,
		    "ibd_perf_tx: #Packets not multiple of Signal Grp size");
		return;
	}
	num_completions = 0;

	swqes = kmem_zalloc(sizeof (ibd_swqe_t *) * IBD_NUM_SWQE,
	    KM_NOSLEEP);
	if (swqes == NULL) {
		cmn_err(CE_CONT, "ibd_perf_tx: no storage");
		return;
	}

	wcs = kmem_zalloc(sizeof (ibt_wc_t) * IBD_NUM_UNSIGNAL, KM_NOSLEEP);
	if (wcs == NULL) {
		kmem_free(swqes, sizeof (ibd_swqe_t *) * IBD_NUM_SWQE);
		cmn_err(CE_CONT, "ibd_perf_tx: no storage");
		return;
	}

	/*
	 * Get the ud_dest for the destination.
	 */
	ibd_async_acache(state, &ibd_dest);
	mutex_enter(&state->id_ac_mutex);
	ace = ibd_acache_find(state, &ibd_dest, B_FALSE, 0);
	mutex_exit(&state->id_ac_mutex);
	if (ace == NULL) {
		kmem_free(swqes, sizeof (ibd_swqe_t *) * IBD_NUM_SWQE);
		kmem_free(wcs, sizeof (ibt_wc_t) * IBD_NUM_UNSIGNAL);
		cmn_err(CE_CONT, "ibd_perf_tx: no AH");
		return;
	}

	/*
	 * Set up the send buffer.
	 */
	sendbuf = kmem_zalloc(IBD_TX_PKTSIZE, KM_NOSLEEP);
	if (sendbuf == NULL) {
		kmem_free(swqes, sizeof (ibd_swqe_t *) * IBD_NUM_SWQE);
		kmem_free(wcs, sizeof (ibt_wc_t) * IBD_NUM_UNSIGNAL);
		cmn_err(CE_CONT, "ibd_perf_tx: no send buffer");
		return;
	}

	/*
	 * This buffer can be used in the case when we want to
	 * send data from the same memory area over and over;
	 * it might help in reducing memory traffic.
	 */
	mem_attr.mr_vaddr = (uint64_t)sendbuf;
	mem_attr.mr_len = IBD_TX_PKTSIZE;
	mem_attr.mr_as = NULL;
	mem_attr.mr_flags = IBT_MR_NOSLEEP;
	if (ibt_register_mr(state->id_hca_hdl, state->id_pd_hdl, &mem_attr,
	    &mrhdl, &mrdesc) != IBT_SUCCESS) {
		kmem_free(swqes, sizeof (ibd_swqe_t *) * IBD_NUM_SWQE);
		kmem_free(sendbuf, IBD_TX_PKTSIZE);
		kmem_free(wcs, sizeof (ibt_wc_t) * IBD_NUM_UNSIGNAL);
		cmn_err(CE_CONT, "ibd_perf_tx: registration failed");
		return;
	}

	/*
	 * Allocate private send wqe's.
	 */
	for (i = 0; i < IBD_NUM_SWQE; i++) {
		if (ibd_alloc_swqe(state, &node) != DDI_SUCCESS) {
			kmem_free(swqes, sizeof (ibd_swqe_t *) * IBD_NUM_SWQE);
			kmem_free(sendbuf, IBD_TX_PKTSIZE);
			kmem_free(wcs, sizeof (ibt_wc_t) * IBD_NUM_UNSIGNAL);
			cmn_err(CE_CONT, "ibd_alloc_swqe failure");
			return;
		}
		node->w_ahandle = ace;
#if 0
		node->w_smblkbuf[0].im_mr_hdl = mrhdl;
		node->w_smblkbuf[0].im_mr_desc = mrdesc;
		node->w_smblk_sgl[0].ds_va = (ib_vaddr_t)sendbuf;
		node->w_smblk_sgl[0].ds_key =
		    node->w_smblkbuf[0].im_mr_desc.md_lkey;
		node->w_smblk_sgl[0].ds_len = IBD_TX_PKTSIZE;
		node->w_swr.wr_sgl = node->w_smblk_sgl;
#else
		node->swqe_copybuf.ic_sgl.ds_len = IBD_TX_PKTSIZE;
		node->w_swr.wr_sgl = &node->swqe_copybuf.ic_sgl;
#endif

		/*
		 * The last of IBD_NUM_UNSIGNAL consecutive posted WRs
		 * is marked to invoke the CQ handler. That is the only
		 * way we come to know when the send queue can accept more
		 * WRs.
		 */
		if (((i + 1) % IBD_NUM_UNSIGNAL) != 0)
			node->w_swr.wr_flags = IBT_WR_NO_FLAGS;
		node->w_swr.wr.ud.udwr_dest = ace->ac_dest;
		node->w_swr.wr_nds = 1;

		swqes[i] = node;
	}

	ibt_set_cq_handler(state->id_scq_hdl, ibd_perf_handler, state);

	/*
	 * Post all the requests. We expect this stream of post's will
	 * not overwhelm the hardware due to periodic completions and
	 * pollings that happen out of ibd_perf_handler.
	 * Post a set of requests, till the channel can accept; after
	 * that, wait for the CQ handler to notify us that there is more
	 * space.
	 */
	stime = gethrtime();
	for (; reps > 0; reps--)
		for (i = 0; i < IBD_NUM_SWQE; i++) {
			node = swqes[i];
retry:
			if ((stat = ibt_post_send(state->id_chnl_hdl,
			    &node->w_swr, 1, NULL)) != IBT_SUCCESS) {
				if (stat == IBT_CHAN_FULL) {
					/*
					 * Spin till the CQ handler runs
					 * and then try again.
					 */
					sspin = gethrtime();
					while (!cq_handler_ran)
						;
					espin = gethrtime();
					tspin += (espin - sspin);
					cq_handler_ran = B_FALSE;
					goto retry;
				}
				cmn_err(CE_CONT, "post failure %d/%d", stat, i);
				goto done;
			}
		}

done:
	/*
	 * We should really be snapshotting when we get the last
	 * completion.
	 */
	while (num_completions != (packets / IBD_NUM_UNSIGNAL))
		;
	etime = gethrtime();

	cmn_err(CE_CONT, "ibd_perf_tx: # signaled completions = %d",
	    num_completions);
	cmn_err(CE_CONT, "ibd_perf_tx: Time = %lld nanosec", (etime - stime));
	cmn_err(CE_CONT, "ibd_perf_tx: Spin Time = %lld nanosec", tspin);

	/*
	 * Wait a sec for everything to get over.
	 */
	delay(drv_usectohz(2000000));

	/*
	 * Reset CQ handler to real one; free resources.
	 */
	if (ibd_separate_cqs == 0) {
		ibt_set_cq_handler(state->id_scq_hdl, ibd_rcq_handler, state);
	} else {
		if (ibd_txcomp_poll == 0)
			ibt_set_cq_handler(state->id_scq_hdl, ibd_scq_handler,
			    state);
		else
			ibt_set_cq_handler(state->id_scq_hdl, 0, 0);
	}

	for (i = 0; i < IBD_NUM_SWQE; i++)
		ibd_free_swqe(state, swqes[i]);
	(void) ibt_deregister_mr(state->id_hca_hdl, mrhdl);
	kmem_free(sendbuf, IBD_TX_PKTSIZE);
	kmem_free(swqes, sizeof (ibd_swqe_t *) * IBD_NUM_SWQE);
	kmem_free(wcs, sizeof (ibt_wc_t) * IBD_NUM_UNSIGNAL);
}

static void
ibd_perf_rx(ibd_state_t *state)
{
	wcs = kmem_zalloc(sizeof (ibt_wc_t) * IBD_NUM_UNSIGNAL, KM_NOSLEEP);
	if (wcs == NULL) {
		kmem_free(swqes, sizeof (ibd_swqe_t *) * IBD_NUM_SWQE);
		cmn_err(CE_CONT, "ibd_perf_tx: no storage");
		return;
	}

	/*
	 * We do not need to allocate private recv wqe's. We will
	 * just use the regular ones.
	 */

	num_completions = 0;
	ibt_set_cq_handler(state->id_rcq_hdl, ibd_perf_handler, state);

	/*
	 * Delay for a minute for all the packets to come in from
	 * transmitter.
	 */
	cmn_err(CE_CONT, "ibd_perf_rx: RecvQ depth = %d", IBD_NUM_SWQE);
	delay(drv_usectohz(60000000));
	cmn_err(CE_CONT, "ibd_perf_rx: Received %d packets", num_completions);

	/*
	 * Reset CQ handler to real one; free resources.
	 */
	ibt_set_cq_handler(state->id_rcq_hdl, ibd_rcq_handler, state);
	kmem_free(wcs, sizeof (ibt_wc_t) * IBD_NUM_UNSIGNAL);
}

static void
ibd_perf(ibd_state_t *state)
{
	if (ibd_performance == 0)
		return;

	if (ibd_receiver == 1) {
		ibd_perf_rx(state);
		return;
	}

	if (ibd_sender == 1) {
		ibd_perf_tx(state);
		return;
	}
}

#endif /* RUN_PERFORMANCE */
