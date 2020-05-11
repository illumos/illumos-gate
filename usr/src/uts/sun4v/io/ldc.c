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
 * Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * sun4v LDC Link Layer
 */
#include <sys/types.h>
#include <sys/file.h>
#include <sys/errno.h>
#include <sys/open.h>
#include <sys/cred.h>
#include <sys/kmem.h>
#include <sys/conf.h>
#include <sys/cmn_err.h>
#include <sys/ksynch.h>
#include <sys/modctl.h>
#include <sys/stat.h> /* needed for S_IFBLK and S_IFCHR */
#include <sys/debug.h>
#include <sys/cred.h>
#include <sys/promif.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/cyclic.h>
#include <sys/machsystm.h>
#include <sys/vm.h>
#include <sys/cpu.h>
#include <sys/intreg.h>
#include <sys/machcpuvar.h>
#include <sys/mmu.h>
#include <sys/pte.h>
#include <vm/hat.h>
#include <vm/as.h>
#include <vm/hat_sfmmu.h>
#include <sys/vm_machparam.h>
#include <vm/seg_kmem.h>
#include <vm/seg_kpm.h>
#include <sys/note.h>
#include <sys/ivintr.h>
#include <sys/hypervisor_api.h>
#include <sys/ldc.h>
#include <sys/ldc_impl.h>
#include <sys/cnex.h>
#include <sys/hsvc.h>
#include <sys/sdt.h>
#include <sys/kldc.h>

/* Core internal functions */
int i_ldc_h2v_error(int h_error);
void i_ldc_reset(ldc_chan_t *ldcp, boolean_t force_reset);

static int i_ldc_txq_reconf(ldc_chan_t *ldcp);
static int i_ldc_rxq_reconf(ldc_chan_t *ldcp, boolean_t force_reset);
static void i_ldc_rxq_drain(ldc_chan_t *ldcp);
static void i_ldc_reset_state(ldc_chan_t *ldcp);
static void i_ldc_debug_enter(void);

static int i_ldc_get_tx_tail(ldc_chan_t *ldcp, uint64_t *tail);
static void i_ldc_get_tx_head(ldc_chan_t *ldcp, uint64_t *head);
static int i_ldc_set_tx_tail(ldc_chan_t *ldcp, uint64_t tail);
static int i_ldc_set_rx_head(ldc_chan_t *ldcp, uint64_t head);
static int i_ldc_send_pkt(ldc_chan_t *ldcp, uint8_t pkttype, uint8_t subtype,
    uint8_t ctrlmsg);

static int  i_ldc_set_rxdq_head(ldc_chan_t *ldcp, uint64_t head);
static void i_ldc_rxdq_copy(ldc_chan_t *ldcp, uint64_t *head);
static uint64_t i_ldc_dq_rx_get_state(ldc_chan_t *ldcp, uint64_t *head,
    uint64_t *tail, uint64_t *link_state);
static uint64_t i_ldc_hvq_rx_get_state(ldc_chan_t *ldcp, uint64_t *head,
    uint64_t *tail, uint64_t *link_state);
static int i_ldc_rx_ackpeek(ldc_chan_t *ldcp, uint64_t rx_head,
    uint64_t rx_tail);
static uint_t i_ldc_chkq(ldc_chan_t *ldcp);

/* Interrupt handling functions */
static uint_t i_ldc_tx_hdlr(caddr_t arg1, caddr_t arg2);
static uint_t i_ldc_rx_hdlr(caddr_t arg1, caddr_t arg2);
static uint_t i_ldc_rx_process_hvq(ldc_chan_t *ldcp, boolean_t *notify_client,
    uint64_t *notify_event);
static void i_ldc_clear_intr(ldc_chan_t *ldcp, cnex_intrtype_t itype);

/* Read method functions */
static int i_ldc_read_raw(ldc_chan_t *ldcp, caddr_t target_bufp, size_t *sizep);
static int i_ldc_read_packet(ldc_chan_t *ldcp, caddr_t target_bufp,
	size_t *sizep);
static int i_ldc_read_stream(ldc_chan_t *ldcp, caddr_t target_bufp,
	size_t *sizep);

/* Write method functions */
static int i_ldc_write_raw(ldc_chan_t *ldcp, caddr_t target_bufp,
	size_t *sizep);
static int i_ldc_write_packet(ldc_chan_t *ldcp, caddr_t target_bufp,
	size_t *sizep);
static int i_ldc_write_stream(ldc_chan_t *ldcp, caddr_t target_bufp,
	size_t *sizep);

/* Pkt processing internal functions */
static int i_ldc_check_seqid(ldc_chan_t *ldcp, ldc_msg_t *ldcmsg);
static int i_ldc_ctrlmsg(ldc_chan_t *ldcp, ldc_msg_t *ldcmsg);
static int i_ldc_process_VER(ldc_chan_t *ldcp, ldc_msg_t *msg);
static int i_ldc_process_RTS(ldc_chan_t *ldcp, ldc_msg_t *msg);
static int i_ldc_process_RTR(ldc_chan_t *ldcp, ldc_msg_t *msg);
static int i_ldc_process_RDX(ldc_chan_t *ldcp, ldc_msg_t *msg);
static int i_ldc_process_data_ACK(ldc_chan_t *ldcp, ldc_msg_t *msg);

/* Imported functions */
extern void i_ldc_mem_set_hsvc_vers(uint64_t major, uint64_t minor);
extern void i_ldc_init_mapin(ldc_soft_state_t *ldcssp, uint64_t major,
	uint64_t minor);

/* LDC Version */
static ldc_ver_t ldc_versions[] = { {1, 0} };

/* number of supported versions */
#define	LDC_NUM_VERS	(sizeof (ldc_versions) / sizeof (ldc_versions[0]))

/* Invalid value for the ldc_chan_t rx_ack_head field */
#define	ACKPEEK_HEAD_INVALID	((uint64_t)-1)


/* Module State Pointer */
ldc_soft_state_t *ldcssp;

static struct modldrv md = {
	&mod_miscops,			/* This is a misc module */
	"sun4v LDC module",		/* Name of the module */
};

static struct modlinkage ml = {
	MODREV_1,
	&md,
	NULL
};

static uint64_t ldc_sup_minor;		/* Supported minor number */
static hsvc_info_t ldc_hsvc = {
	HSVC_REV_1, NULL, HSVC_GROUP_LDC, 1, 2, "ldc"
};

/*
 * The no. of MTU size messages that can be stored in
 * the LDC Tx queue. The number of Tx queue entries is
 * then computed as (mtu * mtu_msgs)/sizeof(queue_entry)
 */
uint64_t ldc_mtu_msgs = LDC_MTU_MSGS;

/*
 * The minimum queue length. This is the size of the smallest
 * LDC queue. If the computed value is less than this default,
 * the queue length is rounded up to 'ldc_queue_entries'.
 */
uint64_t ldc_queue_entries = LDC_QUEUE_ENTRIES;

/*
 * The length of the reliable-mode data queue in terms of the LDC
 * receive queue length. i.e., the number of times larger than the
 * LDC receive queue that the data queue should be. The HV receive
 * queue is required to be a power of 2 and this implementation
 * assumes the data queue will also be a power of 2. By making the
 * multiplier a power of 2, we ensure the data queue will be a
 * power of 2. We use a multiplier because the receive queue is
 * sized to be sane relative to the MTU and the same is needed for
 * the data queue.
 */
uint64_t ldc_rxdq_multiplier = LDC_RXDQ_MULTIPLIER;

/*
 * LDC retry count and delay - when the HV returns EWOULDBLOCK
 * the operation is retried 'ldc_max_retries' times with a
 * wait of 'ldc_delay' usecs between each retry.
 */
int ldc_max_retries = LDC_MAX_RETRIES;
clock_t ldc_delay = LDC_DELAY;

/*
 * Channels which have a devclass satisfying the following
 * will be reset when entering the prom or kmdb.
 *
 *   LDC_DEVCLASS_PROM_RESET(devclass) != 0
 *
 * By default, only block device service channels are reset.
 */
#define	LDC_DEVCLASS_BIT(dc)		(0x1 << (dc))
#define	LDC_DEVCLASS_PROM_RESET(dc)	\
	(LDC_DEVCLASS_BIT(dc) & ldc_debug_reset_mask)
static uint64_t ldc_debug_reset_mask = LDC_DEVCLASS_BIT(LDC_DEV_BLK_SVC) |
    LDC_DEVCLASS_BIT(LDC_DEV_GENERIC);

/*
 * delay between each retry of channel unregistration in
 * ldc_close(), to wait for pending interrupts to complete.
 */
clock_t ldc_close_delay = LDC_CLOSE_DELAY;


/*
 * Reserved mapin space for descriptor rings.
 */
uint64_t ldc_dring_direct_map_rsvd = LDC_DIRECT_MAP_SIZE_DEFAULT;

/*
 * Maximum direct map space allowed per channel.
 */
uint64_t	ldc_direct_map_size_max = (16 * 1024 * 1024);	/* 16 MB */

#ifdef DEBUG

/*
 * Print debug messages
 *
 * set ldcdbg to 0x7 for enabling all msgs
 * 0x4 - Warnings
 * 0x2 - All debug messages
 * 0x1 - Minimal debug messages
 *
 * set ldcdbgchan to the channel number you want to debug
 * setting it to -1 prints debug messages for all channels
 * NOTE: ldcdbgchan has no effect on error messages
 */

int ldcdbg = 0x0;
int64_t ldcdbgchan = DBG_ALL_LDCS;
uint64_t ldc_inject_err_flag = 0;

void
ldcdebug(int64_t id, const char *fmt, ...)
{
	char buf[512];
	va_list ap;

	/*
	 * Do not return if,
	 * caller wants to print it anyway - (id == DBG_ALL_LDCS)
	 * debug channel is set to all LDCs - (ldcdbgchan == DBG_ALL_LDCS)
	 * debug channel = caller specified channel
	 */
	if ((id != DBG_ALL_LDCS) &&
	    (ldcdbgchan != DBG_ALL_LDCS) &&
	    (ldcdbgchan != id)) {
		return;
	}

	va_start(ap, fmt);
	(void) vsprintf(buf, fmt, ap);
	va_end(ap);

	cmn_err(CE_CONT, "?%s", buf);
}

#define	LDC_ERR_RESET		0x1
#define	LDC_ERR_PKTLOSS		0x2
#define	LDC_ERR_DQFULL		0x4
#define	LDC_ERR_DRNGCLEAR	0x8

static boolean_t
ldc_inject_error(ldc_chan_t *ldcp, uint64_t error)
{
	if ((ldcdbgchan != DBG_ALL_LDCS) && (ldcdbgchan != ldcp->id))
		return (B_FALSE);

	if ((ldc_inject_err_flag & error) == 0)
		return (B_FALSE);

	/* clear the injection state */
	ldc_inject_err_flag &= ~error;

	return (B_TRUE);
}

#define	DUMP_PAYLOAD(id, addr)						\
{									\
	char buf[65*3];							\
	int i;								\
	uint8_t *src = (uint8_t *)addr;					\
	for (i = 0; i < 64; i++, src++)					\
		(void) sprintf(&buf[i * 3], "|%02x", *src);		\
	(void) sprintf(&buf[i * 3], "|\n");				\
	D2((id), "payload: %s", buf);					\
}

#define	DUMP_LDC_PKT(c, s, addr)					\
{									\
	ldc_msg_t *msg = (ldc_msg_t *)(addr);				\
	uint32_t mid = ((c)->mode != LDC_MODE_RAW) ? msg->seqid : 0;	\
	if (msg->type == LDC_DATA) {                                    \
	    D2((c)->id, "%s: msg%d (/%x/%x/%x/,env[%c%c,sz=%d])",	\
	    (s), mid, msg->type, msg->stype, msg->ctrl,			\
	    (msg->env & LDC_FRAG_START) ? 'B' : ' ',                    \
	    (msg->env & LDC_FRAG_STOP) ? 'E' : ' ',                     \
	    (msg->env & LDC_LEN_MASK));					\
	} else {							\
	    D2((c)->id, "%s: msg%d (/%x/%x/%x/,env=%x)", (s),		\
	    mid, msg->type, msg->stype, msg->ctrl, msg->env);		\
	}								\
}

#define	LDC_INJECT_RESET(_ldcp)	ldc_inject_error(_ldcp, LDC_ERR_RESET)
#define	LDC_INJECT_PKTLOSS(_ldcp) ldc_inject_error(_ldcp, LDC_ERR_PKTLOSS)
#define	LDC_INJECT_DQFULL(_ldcp) ldc_inject_error(_ldcp, LDC_ERR_DQFULL)
#define	LDC_INJECT_DRNGCLEAR(_ldcp) ldc_inject_error(_ldcp, LDC_ERR_DRNGCLEAR)
extern void i_ldc_mem_inject_dring_clear(ldc_chan_t *ldcp);

#else

#define	DBG_ALL_LDCS -1

#define	DUMP_PAYLOAD(id, addr)
#define	DUMP_LDC_PKT(c, s, addr)

#define	LDC_INJECT_RESET(_ldcp)	(B_FALSE)
#define	LDC_INJECT_PKTLOSS(_ldcp) (B_FALSE)
#define	LDC_INJECT_DQFULL(_ldcp) (B_FALSE)
#define	LDC_INJECT_DRNGCLEAR(_ldcp) (B_FALSE)

#endif

/*
 * dtrace SDT probes to ease tracing of the rx data queue and HV queue
 * lengths. Just pass the head, tail, and entries values so that the
 * length can be calculated in a dtrace script when the probe is enabled.
 */
#define	TRACE_RXDQ_LENGTH(ldcp)						\
	DTRACE_PROBE4(rxdq__size,					\
	uint64_t, ldcp->id,						\
	uint64_t, ldcp->rx_dq_head,					\
	uint64_t, ldcp->rx_dq_tail,					\
	uint64_t, ldcp->rx_dq_entries)

#define	TRACE_RXHVQ_LENGTH(ldcp, head, tail)				\
	DTRACE_PROBE4(rxhvq__size,					\
	uint64_t, ldcp->id,						\
	uint64_t, head,							\
	uint64_t, tail,							\
	uint64_t, ldcp->rx_q_entries)

/* A dtrace SDT probe to ease tracing of data queue copy operations */
#define	TRACE_RXDQ_COPY(ldcp, bytes)					\
	DTRACE_PROBE2(rxdq__copy, uint64_t, ldcp->id, uint64_t, bytes)	\

/* The amount of contiguous space at the tail of the queue */
#define	Q_CONTIG_SPACE(head, tail, size)				\
	((head) <= (tail) ? ((size) - (tail)) :				\
	((head) - (tail) - LDC_PACKET_SIZE))

#define	ZERO_PKT(p)			\
	bzero((p), sizeof (ldc_msg_t));

#define	IDX2COOKIE(idx, pg_szc, pg_shift)				\
	(((pg_szc) << LDC_COOKIE_PGSZC_SHIFT) | ((idx) << (pg_shift)))

int
_init(void)
{
	int status;

	status = hsvc_register(&ldc_hsvc, &ldc_sup_minor);
	if (status != 0) {
		cmn_err(CE_NOTE, "!%s: cannot negotiate hypervisor LDC services"
		    " group: 0x%lx major: %ld minor: %ld errno: %d",
		    ldc_hsvc.hsvc_modname, ldc_hsvc.hsvc_group,
		    ldc_hsvc.hsvc_major, ldc_hsvc.hsvc_minor, status);
		return (-1);
	}

	/* Initialize shared memory HV API version checking */
	i_ldc_mem_set_hsvc_vers(ldc_hsvc.hsvc_major, ldc_sup_minor);

	/* allocate soft state structure */
	ldcssp = kmem_zalloc(sizeof (ldc_soft_state_t), KM_SLEEP);

	i_ldc_init_mapin(ldcssp, ldc_hsvc.hsvc_major, ldc_sup_minor);

	/* Link the module into the system */
	status = mod_install(&ml);
	if (status != 0) {
		kmem_free(ldcssp, sizeof (ldc_soft_state_t));
		return (status);
	}

	/* Initialize the LDC state structure */
	mutex_init(&ldcssp->lock, NULL, MUTEX_DRIVER, NULL);

	mutex_enter(&ldcssp->lock);

	/* Create a cache for memory handles */
	ldcssp->memhdl_cache = kmem_cache_create("ldc_memhdl_cache",
	    sizeof (ldc_mhdl_t), 0, NULL, NULL, NULL, NULL, NULL, 0);
	if (ldcssp->memhdl_cache == NULL) {
		DWARN(DBG_ALL_LDCS, "_init: ldc_memhdl cache create failed\n");
		mutex_exit(&ldcssp->lock);
		return (-1);
	}

	/* Create cache for memory segment structures */
	ldcssp->memseg_cache = kmem_cache_create("ldc_memseg_cache",
	    sizeof (ldc_memseg_t), 0, NULL, NULL, NULL, NULL, NULL, 0);
	if (ldcssp->memseg_cache == NULL) {
		DWARN(DBG_ALL_LDCS, "_init: ldc_memseg cache create failed\n");
		mutex_exit(&ldcssp->lock);
		return (-1);
	}


	ldcssp->channel_count = 0;
	ldcssp->channels_open = 0;
	ldcssp->chan_list = NULL;
	ldcssp->dring_list = NULL;

	/* Register debug_enter callback */
	kldc_set_debug_cb(&i_ldc_debug_enter);

	mutex_exit(&ldcssp->lock);

	return (0);
}

int
_info(struct modinfo *modinfop)
{
	/* Report status of the dynamically loadable driver module */
	return (mod_info(&ml, modinfop));
}

int
_fini(void)
{
	int		rv, status;
	ldc_chan_t	*tmp_ldcp, *ldcp;
	ldc_dring_t	*tmp_dringp, *dringp;
	ldc_mem_info_t	minfo;

	/* Unlink the driver module from the system */
	status = mod_remove(&ml);
	if (status) {
		DWARN(DBG_ALL_LDCS, "_fini: mod_remove failed\n");
		return (EIO);
	}

	/* Unregister debug_enter callback */
	kldc_set_debug_cb(NULL);

	/* Free descriptor rings */
	dringp = ldcssp->dring_list;
	while (dringp != NULL) {
		tmp_dringp = dringp->next;

		rv = ldc_mem_dring_info((ldc_dring_handle_t)dringp, &minfo);
		if (rv == 0 && minfo.status != LDC_UNBOUND) {
			if (minfo.status == LDC_BOUND) {
				(void) ldc_mem_dring_unbind(
				    (ldc_dring_handle_t)dringp);
			}
			if (minfo.status == LDC_MAPPED) {
				(void) ldc_mem_dring_unmap(
				    (ldc_dring_handle_t)dringp);
			}
		}

		(void) ldc_mem_dring_destroy((ldc_dring_handle_t)dringp);
		dringp = tmp_dringp;
	}
	ldcssp->dring_list = NULL;

	/* close and finalize channels */
	ldcp = ldcssp->chan_list;
	while (ldcp != NULL) {
		tmp_ldcp = ldcp->next;

		(void) ldc_close((ldc_handle_t)ldcp);
		(void) ldc_fini((ldc_handle_t)ldcp);

		ldcp = tmp_ldcp;
	}
	ldcssp->chan_list = NULL;

	/* Destroy kmem caches */
	kmem_cache_destroy(ldcssp->memhdl_cache);
	kmem_cache_destroy(ldcssp->memseg_cache);

	/*
	 * We have successfully "removed" the driver.
	 * Destroying soft states
	 */
	mutex_destroy(&ldcssp->lock);
	kmem_free(ldcssp, sizeof (ldc_soft_state_t));

	(void) hsvc_unregister(&ldc_hsvc);

	return (status);
}

/* -------------------------------------------------------------------------- */

/*
 * LDC Link Layer Internal Functions
 */

/*
 * Translate HV Errors to sun4v error codes
 */
int
i_ldc_h2v_error(int h_error)
{
	switch (h_error) {

	case	H_EOK:
		return (0);

	case	H_ENORADDR:
		return (EFAULT);

	case	H_EBADPGSZ:
	case	H_EINVAL:
		return (EINVAL);

	case	H_EWOULDBLOCK:
		return (EWOULDBLOCK);

	case	H_ENOACCESS:
	case	H_ENOMAP:
		return (EACCES);

	case	H_EIO:
	case	H_ECPUERROR:
		return (EIO);

	case	H_ENOTSUPPORTED:
		return (ENOTSUP);

	case	H_ETOOMANY:
		return (ENOSPC);

	case	H_ECHANNEL:
		return (ECHRNG);
	default:
		break;
	}

	return (EIO);
}

/*
 * Reconfigure the transmit queue
 */
static int
i_ldc_txq_reconf(ldc_chan_t *ldcp)
{
	int rv;

	ASSERT(MUTEX_HELD(&ldcp->lock));
	ASSERT(MUTEX_HELD(&ldcp->tx_lock));

	rv = hv_ldc_tx_qconf(ldcp->id, ldcp->tx_q_ra, ldcp->tx_q_entries);
	if (rv) {
		cmn_err(CE_WARN,
		    "i_ldc_txq_reconf: (0x%lx) cannot set qconf", ldcp->id);
		return (EIO);
	}
	rv = hv_ldc_tx_get_state(ldcp->id, &(ldcp->tx_head),
	    &(ldcp->tx_tail), &(ldcp->link_state));
	if (rv) {
		cmn_err(CE_WARN,
		    "i_ldc_txq_reconf: (0x%lx) cannot get qptrs", ldcp->id);
		return (EIO);
	}
	D1(ldcp->id, "i_ldc_txq_reconf: (0x%llx) h=0x%llx,t=0x%llx,"
	    "s=0x%llx\n", ldcp->id, ldcp->tx_head, ldcp->tx_tail,
	    ldcp->link_state);

	return (0);
}

/*
 * Reconfigure the receive queue
 */
static int
i_ldc_rxq_reconf(ldc_chan_t *ldcp, boolean_t force_reset)
{
	int rv;
	uint64_t rx_head, rx_tail;

	ASSERT(MUTEX_HELD(&ldcp->lock));
	rv = hv_ldc_rx_get_state(ldcp->id, &rx_head, &rx_tail,
	    &(ldcp->link_state));
	if (rv) {
		cmn_err(CE_WARN,
		    "i_ldc_rxq_reconf: (0x%lx) cannot get state",
		    ldcp->id);
		return (EIO);
	}

	if (force_reset || (ldcp->tstate & ~TS_IN_RESET) == TS_UP) {
		rv = hv_ldc_rx_qconf(ldcp->id, ldcp->rx_q_ra,
		    ldcp->rx_q_entries);
		if (rv) {
			cmn_err(CE_WARN,
			    "i_ldc_rxq_reconf: (0x%lx) cannot set qconf",
			    ldcp->id);
			return (EIO);
		}
		D1(ldcp->id, "i_ldc_rxq_reconf: (0x%llx) completed q reconf",
		    ldcp->id);
	}

	return (0);
}


/*
 * Drain the contents of the receive queue
 */
static void
i_ldc_rxq_drain(ldc_chan_t *ldcp)
{
	int rv;
	uint64_t rx_head, rx_tail;
	int retries = 0;

	ASSERT(MUTEX_HELD(&ldcp->lock));
	rv = hv_ldc_rx_get_state(ldcp->id, &rx_head, &rx_tail,
	    &(ldcp->link_state));
	if (rv) {
		cmn_err(CE_WARN, "i_ldc_rxq_drain: (0x%lx) cannot get state, "
		    "rv = 0x%x", ldcp->id, rv);
		return;
	}

	/* If the queue is already empty just return success. */
	if (rx_head == rx_tail)
		return;

	/*
	 * We are draining the queue in order to close the channel.
	 * Call hv_ldc_rx_set_qhead directly instead of i_ldc_set_rx_head
	 * because we do not need to reset the channel if the set
	 * qhead fails.
	 */
	if ((rv = hv_ldc_rx_set_qhead(ldcp->id, rx_tail)) == 0)
		return;

	while ((rv == H_EWOULDBLOCK) && (retries++ < ldc_max_retries)) {
		drv_usecwait(ldc_delay);
		if ((rv = hv_ldc_rx_set_qhead(ldcp->id, rx_tail)) == 0)
			return;
	}

	cmn_err(CE_WARN, "i_ldc_rxq_drain: (0x%lx) cannot set qhead 0x%lx, "
	    "rv = 0x%x", ldcp->id, rx_tail, rv);
}


/*
 * Reset LDC state structure and its contents
 */
static void
i_ldc_reset_state(ldc_chan_t *ldcp)
{
	ASSERT(MUTEX_HELD(&ldcp->lock));
	ldcp->last_msg_snt = LDC_INIT_SEQID;
	ldcp->last_ack_rcd = 0;
	ldcp->last_msg_rcd = 0;
	ldcp->tx_ackd_head = ldcp->tx_head;
	ldcp->stream_remains = 0;
	ldcp->next_vidx = 0;
	ldcp->hstate = 0;
	ldcp->tstate = TS_OPEN;
	ldcp->status = LDC_OPEN;
	ldcp->rx_ack_head = ACKPEEK_HEAD_INVALID;
	ldcp->rx_dq_head = 0;
	ldcp->rx_dq_tail = 0;

	if (ldcp->link_state == LDC_CHANNEL_UP ||
	    ldcp->link_state == LDC_CHANNEL_RESET) {

		if (ldcp->mode == LDC_MODE_RAW) {
			ldcp->status = LDC_UP;
			ldcp->tstate = TS_UP;
		} else {
			ldcp->status = LDC_READY;
			ldcp->tstate |= TS_LINK_READY;
		}
	}
}

/*
 * Reset a LDC channel
 */
void
i_ldc_reset(ldc_chan_t *ldcp, boolean_t force_reset)
{
	DWARN(ldcp->id, "i_ldc_reset: (0x%llx) channel reset\n", ldcp->id);

	ASSERT(MUTEX_HELD(&ldcp->lock));
	ASSERT(MUTEX_HELD(&ldcp->tx_lock));

	/* reconfig Tx and Rx queues */
	(void) i_ldc_txq_reconf(ldcp);
	(void) i_ldc_rxq_reconf(ldcp, force_reset);

	/* Clear Tx and Rx interrupts */
	(void) i_ldc_clear_intr(ldcp, CNEX_TX_INTR);
	(void) i_ldc_clear_intr(ldcp, CNEX_RX_INTR);

	/* Reset channel state */
	i_ldc_reset_state(ldcp);

	/* Mark channel in reset */
	ldcp->tstate |= TS_IN_RESET;
}

/*
 * Walk the channel list and reset channels if they are of the right
 * devclass and their Rx queues have been configured. No locks are
 * taken because the function is only invoked by the kernel just before
 * entering the prom or debugger when the system is single-threaded.
 */
static void
i_ldc_debug_enter(void)
{
	ldc_chan_t *ldcp;

	ldcp = ldcssp->chan_list;
	while (ldcp != NULL) {
		if (((ldcp->tstate & TS_QCONF_RDY) == TS_QCONF_RDY) &&
		    (LDC_DEVCLASS_PROM_RESET(ldcp->devclass) != 0)) {
			(void) hv_ldc_rx_qconf(ldcp->id, ldcp->rx_q_ra,
			    ldcp->rx_q_entries);
		}
		ldcp = ldcp->next;
	}
}

/*
 * Clear pending interrupts
 */
static void
i_ldc_clear_intr(ldc_chan_t *ldcp, cnex_intrtype_t itype)
{
	ldc_cnex_t *cinfo = &ldcssp->cinfo;

	ASSERT(MUTEX_HELD(&ldcp->lock));
	ASSERT(cinfo->dip != NULL);

	switch (itype) {
	case CNEX_TX_INTR:
		/* check Tx interrupt */
		if (ldcp->tx_intr_state)
			ldcp->tx_intr_state = LDC_INTR_NONE;
		else
			return;
		break;

	case CNEX_RX_INTR:
		/* check Rx interrupt */
		if (ldcp->rx_intr_state)
			ldcp->rx_intr_state = LDC_INTR_NONE;
		else
			return;
		break;
	}

	(void) cinfo->clr_intr(cinfo->dip, ldcp->id, itype);
	D2(ldcp->id,
	    "i_ldc_clear_intr: (0x%llx) cleared 0x%x intr\n",
	    ldcp->id, itype);
}

/*
 * Set the receive queue head
 * Resets connection and returns an error if it fails.
 */
static int
i_ldc_set_rx_head(ldc_chan_t *ldcp, uint64_t head)
{
	int	rv;
	int	retries;

	ASSERT(MUTEX_HELD(&ldcp->lock));
	for (retries = 0; retries < ldc_max_retries; retries++) {

		if ((rv = hv_ldc_rx_set_qhead(ldcp->id, head)) == 0)
			return (0);

		if (rv != H_EWOULDBLOCK)
			break;

		/* wait for ldc_delay usecs */
		drv_usecwait(ldc_delay);
	}

	cmn_err(CE_WARN, "ldc_set_rx_qhead: (0x%lx) cannot set qhead 0x%lx, "
	    "rv = 0x%x", ldcp->id, head, rv);
	mutex_enter(&ldcp->tx_lock);
	i_ldc_reset(ldcp, B_TRUE);
	mutex_exit(&ldcp->tx_lock);

	return (ECONNRESET);
}

/*
 * Returns the tx_head to be used for transfer
 */
static void
i_ldc_get_tx_head(ldc_chan_t *ldcp, uint64_t *head)
{
	ldc_msg_t	*pkt;

	ASSERT(MUTEX_HELD(&ldcp->tx_lock));

	/* get current Tx head */
	*head = ldcp->tx_head;

	/*
	 * Reliable mode will use the ACKd head instead of the regular tx_head.
	 * Also in Reliable mode, advance ackd_head for all non DATA/INFO pkts,
	 * up to the current location of tx_head. This needs to be done
	 * as the peer will only ACK DATA/INFO pkts.
	 */
	if (ldcp->mode == LDC_MODE_RELIABLE) {
		while (ldcp->tx_ackd_head != ldcp->tx_head) {
			pkt = (ldc_msg_t *)(ldcp->tx_q_va + ldcp->tx_ackd_head);
			if ((pkt->type & LDC_DATA) && (pkt->stype & LDC_INFO)) {
				break;
			}
			/* advance ACKd head */
			ldcp->tx_ackd_head =
			    (ldcp->tx_ackd_head + LDC_PACKET_SIZE) %
			    (ldcp->tx_q_entries << LDC_PACKET_SHIFT);
		}
		*head = ldcp->tx_ackd_head;
	}
}

/*
 * Returns the tx_tail to be used for transfer
 * Re-reads the TX queue ptrs if and only if the
 * the cached head and tail are equal (queue is full)
 */
static int
i_ldc_get_tx_tail(ldc_chan_t *ldcp, uint64_t *tail)
{
	int		rv;
	uint64_t	current_head, new_tail;

	ASSERT(MUTEX_HELD(&ldcp->tx_lock));
	/* Read the head and tail ptrs from HV */
	rv = hv_ldc_tx_get_state(ldcp->id,
	    &ldcp->tx_head, &ldcp->tx_tail, &ldcp->link_state);
	if (rv) {
		cmn_err(CE_WARN,
		    "i_ldc_get_tx_tail: (0x%lx) cannot read qptrs\n",
		    ldcp->id);
		return (EIO);
	}
	if (ldcp->link_state == LDC_CHANNEL_DOWN) {
		D1(ldcp->id, "i_ldc_get_tx_tail: (0x%llx) channel not ready\n",
		    ldcp->id);
		return (ECONNRESET);
	}

	i_ldc_get_tx_head(ldcp, &current_head);

	/* increment the tail */
	new_tail = (ldcp->tx_tail + LDC_PACKET_SIZE) %
	    (ldcp->tx_q_entries << LDC_PACKET_SHIFT);

	if (new_tail == current_head) {
		DWARN(ldcp->id,
		    "i_ldc_get_tx_tail: (0x%llx) TX queue is full\n",
		    ldcp->id);
		return (EWOULDBLOCK);
	}

	D2(ldcp->id, "i_ldc_get_tx_tail: (0x%llx) head=0x%llx, tail=0x%llx\n",
	    ldcp->id, ldcp->tx_head, ldcp->tx_tail);

	*tail = ldcp->tx_tail;
	return (0);
}

/*
 * Set the tail pointer. If HV returns EWOULDBLOCK, it will back off
 * and retry ldc_max_retries times before returning an error.
 * Returns 0, EWOULDBLOCK or EIO
 */
static int
i_ldc_set_tx_tail(ldc_chan_t *ldcp, uint64_t tail)
{
	int		rv, retval = EWOULDBLOCK;
	int		retries;

	ASSERT(MUTEX_HELD(&ldcp->tx_lock));
	for (retries = 0; retries < ldc_max_retries; retries++) {

		if ((rv = hv_ldc_tx_set_qtail(ldcp->id, tail)) == 0) {
			retval = 0;
			break;
		}
		if (rv != H_EWOULDBLOCK) {
			DWARN(ldcp->id, "i_ldc_set_tx_tail: (0x%llx) set "
			    "qtail=0x%llx failed, rv=%d\n", ldcp->id, tail, rv);
			retval = EIO;
			break;
		}

		/* wait for ldc_delay usecs */
		drv_usecwait(ldc_delay);
	}
	return (retval);
}

/*
 * Copy a data packet from the HV receive queue to the data queue.
 * Caller must ensure that the data queue is not already full.
 *
 * The *head argument represents the current head pointer for the HV
 * receive queue. After copying a packet from the HV receive queue,
 * the *head pointer will be updated. This allows the caller to update
 * the head pointer in HV using the returned *head value.
 */
void
i_ldc_rxdq_copy(ldc_chan_t *ldcp, uint64_t *head)
{
	uint64_t	q_size, dq_size;

	ASSERT(MUTEX_HELD(&ldcp->lock));

	q_size  = ldcp->rx_q_entries << LDC_PACKET_SHIFT;
	dq_size = ldcp->rx_dq_entries << LDC_PACKET_SHIFT;

	ASSERT(Q_CONTIG_SPACE(ldcp->rx_dq_head, ldcp->rx_dq_tail,
	    dq_size) >= LDC_PACKET_SIZE);

	bcopy((void *)(ldcp->rx_q_va + *head),
	    (void *)(ldcp->rx_dq_va + ldcp->rx_dq_tail), LDC_PACKET_SIZE);
	TRACE_RXDQ_COPY(ldcp, LDC_PACKET_SIZE);

	/* Update rx head */
	*head = (*head + LDC_PACKET_SIZE) % q_size;

	/* Update dq tail */
	ldcp->rx_dq_tail = (ldcp->rx_dq_tail + LDC_PACKET_SIZE) % dq_size;
}

/*
 * Update the Rx data queue head pointer
 */
static int
i_ldc_set_rxdq_head(ldc_chan_t *ldcp, uint64_t head)
{
	ldcp->rx_dq_head = head;
	return (0);
}

/*
 * Get the Rx data queue head and tail pointers
 */
static uint64_t
i_ldc_dq_rx_get_state(ldc_chan_t *ldcp, uint64_t *head, uint64_t *tail,
    uint64_t *link_state)
{
	_NOTE(ARGUNUSED(link_state))
	*head = ldcp->rx_dq_head;
	*tail = ldcp->rx_dq_tail;
	return (0);
}

/*
 * Wrapper for the Rx HV queue set head function. Giving the
 * data queue and HV queue set head functions the same type.
 */
static uint64_t
i_ldc_hvq_rx_get_state(ldc_chan_t *ldcp, uint64_t *head, uint64_t *tail,
    uint64_t *link_state)
{
	return (i_ldc_h2v_error(hv_ldc_rx_get_state(ldcp->id, head, tail,
	    link_state)));
}

/*
 * LDC receive interrupt handler
 *    triggered for channel with data pending to read
 *    i.e. Rx queue content changes
 */
static uint_t
i_ldc_rx_hdlr(caddr_t arg1, caddr_t arg2)
{
	_NOTE(ARGUNUSED(arg2))

	ldc_chan_t	*ldcp;
	boolean_t	notify;
	uint64_t	event;
	int		rv, status;

	/* Get the channel for which interrupt was received */
	if (arg1 == NULL) {
		cmn_err(CE_WARN, "i_ldc_rx_hdlr: invalid arg\n");
		return (DDI_INTR_UNCLAIMED);
	}

	ldcp = (ldc_chan_t *)arg1;

	D1(ldcp->id, "i_ldc_rx_hdlr: (0x%llx) Received intr, ldcp=0x%p\n",
	    ldcp->id, ldcp);
	D1(ldcp->id, "i_ldc_rx_hdlr: (%llx) USR%lx/TS%lx/HS%lx, LSTATE=%lx\n",
	    ldcp->id, ldcp->status, ldcp->tstate, ldcp->hstate,
	    ldcp->link_state);

	/* Lock channel */
	mutex_enter(&ldcp->lock);

	/* Mark the interrupt as being actively handled */
	ldcp->rx_intr_state = LDC_INTR_ACTIVE;

	status = i_ldc_rx_process_hvq(ldcp, &notify, &event);

	if (ldcp->mode != LDC_MODE_RELIABLE) {
		/*
		 * If there are no data packets on the queue, clear
		 * the interrupt. Otherwise, the ldc_read will clear
		 * interrupts after draining the queue. To indicate the
		 * interrupt has not yet been cleared, it is marked
		 * as pending.
		 */
		if ((event & LDC_EVT_READ) == 0) {
			i_ldc_clear_intr(ldcp, CNEX_RX_INTR);
		} else {
			ldcp->rx_intr_state = LDC_INTR_PEND;
		}
	}

	/* if callbacks are disabled, do not notify */
	if (notify && ldcp->cb_enabled) {
		ldcp->cb_inprogress = B_TRUE;
		mutex_exit(&ldcp->lock);
		rv = ldcp->cb(event, ldcp->cb_arg);
		if (rv) {
			DWARN(ldcp->id,
			    "i_ldc_rx_hdlr: (0x%llx) callback failure",
			    ldcp->id);
		}
		mutex_enter(&ldcp->lock);
		ldcp->cb_inprogress = B_FALSE;
	}

	if (ldcp->mode == LDC_MODE_RELIABLE) {
		if (status == ENOSPC) {
			/*
			 * Here, ENOSPC indicates the secondary data
			 * queue is full and the Rx queue is non-empty.
			 * Much like how reliable and raw modes are
			 * handled above, since the Rx queue is non-
			 * empty, we mark the interrupt as pending to
			 * indicate it has not yet been cleared.
			 */
			ldcp->rx_intr_state = LDC_INTR_PEND;
		} else {
			/*
			 * We have processed all CTRL packets and
			 * copied all DATA packets to the secondary
			 * queue. Clear the interrupt.
			 */
			i_ldc_clear_intr(ldcp, CNEX_RX_INTR);
		}
	}

	mutex_exit(&ldcp->lock);

	D1(ldcp->id, "i_ldc_rx_hdlr: (0x%llx) exiting handler", ldcp->id);

	return (DDI_INTR_CLAIMED);
}

/*
 * Wrapper for the Rx HV queue processing function to be used when
 * checking the Rx HV queue for data packets. Unlike the interrupt
 * handler code flow, the Rx interrupt is not cleared here and
 * callbacks are not made.
 */
static uint_t
i_ldc_chkq(ldc_chan_t *ldcp)
{
	boolean_t	notify;
	uint64_t	event;

	return (i_ldc_rx_process_hvq(ldcp, &notify, &event));
}

/*
 * Send a LDC message
 */
static int
i_ldc_send_pkt(ldc_chan_t *ldcp, uint8_t pkttype, uint8_t subtype,
    uint8_t ctrlmsg)
{
	int		rv;
	ldc_msg_t	*pkt;
	uint64_t	tx_tail;
	uint32_t	curr_seqid;

	/* Obtain Tx lock */
	mutex_enter(&ldcp->tx_lock);

	curr_seqid = ldcp->last_msg_snt;

	/* get the current tail for the message */
	rv = i_ldc_get_tx_tail(ldcp, &tx_tail);
	if (rv) {
		DWARN(ldcp->id,
		    "i_ldc_send_pkt: (0x%llx) error sending pkt, "
		    "type=0x%x,subtype=0x%x,ctrl=0x%x\n",
		    ldcp->id, pkttype, subtype, ctrlmsg);
		mutex_exit(&ldcp->tx_lock);
		return (rv);
	}

	pkt = (ldc_msg_t *)(ldcp->tx_q_va + tx_tail);
	ZERO_PKT(pkt);

	/* Initialize the packet */
	pkt->type = pkttype;
	pkt->stype = subtype;
	pkt->ctrl = ctrlmsg;

	/* Store ackid/seqid iff it is RELIABLE mode & not a RTS/RTR message */
	if (((ctrlmsg & LDC_CTRL_MASK) != LDC_RTS) &&
	    ((ctrlmsg & LDC_CTRL_MASK) != LDC_RTR)) {
		curr_seqid++;
		if (ldcp->mode != LDC_MODE_RAW) {
			pkt->seqid = curr_seqid;
			pkt->ackid = ldcp->last_msg_rcd;
		}
	}
	DUMP_LDC_PKT(ldcp, "i_ldc_send_pkt", (uint64_t)pkt);

	/* initiate the send by calling into HV and set the new tail */
	tx_tail = (tx_tail + LDC_PACKET_SIZE) %
	    (ldcp->tx_q_entries << LDC_PACKET_SHIFT);

	rv = i_ldc_set_tx_tail(ldcp, tx_tail);
	if (rv) {
		DWARN(ldcp->id,
		    "i_ldc_send_pkt:(0x%llx) error sending pkt, "
		    "type=0x%x,stype=0x%x,ctrl=0x%x\n",
		    ldcp->id, pkttype, subtype, ctrlmsg);
		mutex_exit(&ldcp->tx_lock);
		return (EIO);
	}

	ldcp->last_msg_snt = curr_seqid;
	ldcp->tx_tail = tx_tail;

	mutex_exit(&ldcp->tx_lock);
	return (0);
}

/*
 * Checks if packet was received in right order
 * in the case of a reliable link.
 * Returns 0 if in order, else EIO
 */
static int
i_ldc_check_seqid(ldc_chan_t *ldcp, ldc_msg_t *msg)
{
	/* No seqid checking for RAW mode */
	if (ldcp->mode == LDC_MODE_RAW)
		return (0);

	/* No seqid checking for version, RTS, RTR message */
	if (msg->ctrl == LDC_VER ||
	    msg->ctrl == LDC_RTS ||
	    msg->ctrl == LDC_RTR)
		return (0);

	/* Initial seqid to use is sent in RTS/RTR and saved in last_msg_rcd */
	if (msg->seqid != (ldcp->last_msg_rcd + 1)) {
		DWARN(ldcp->id,
		    "i_ldc_check_seqid: (0x%llx) out-of-order pkt, got 0x%x, "
		    "expecting 0x%x\n", ldcp->id, msg->seqid,
		    (ldcp->last_msg_rcd + 1));
		return (EIO);
	}

#ifdef DEBUG
	if (LDC_INJECT_PKTLOSS(ldcp)) {
		DWARN(ldcp->id,
		    "i_ldc_check_seqid: (0x%llx) inject pkt loss\n", ldcp->id);
		return (EIO);
	}
#endif

	return (0);
}


/*
 * Process an incoming version ctrl message
 */
static int
i_ldc_process_VER(ldc_chan_t *ldcp, ldc_msg_t *msg)
{
	int		rv = 0, idx = ldcp->next_vidx;
	ldc_msg_t	*pkt;
	uint64_t	tx_tail;
	ldc_ver_t	*rcvd_ver;

	/* get the received version */
	rcvd_ver = (ldc_ver_t *)((uint64_t)msg + LDC_PAYLOAD_VER_OFF);

	D2(ldcp->id, "i_ldc_process_VER: (0x%llx) received VER v%u.%u\n",
	    ldcp->id, rcvd_ver->major, rcvd_ver->minor);

	/* Obtain Tx lock */
	mutex_enter(&ldcp->tx_lock);

	switch (msg->stype) {
	case LDC_INFO:

		if ((ldcp->tstate & ~TS_IN_RESET) == TS_VREADY) {
			(void) i_ldc_txq_reconf(ldcp);
			i_ldc_reset_state(ldcp);
			mutex_exit(&ldcp->tx_lock);
			return (EAGAIN);
		}

		/* get the current tail and pkt for the response */
		rv = i_ldc_get_tx_tail(ldcp, &tx_tail);
		if (rv != 0) {
			DWARN(ldcp->id,
			    "i_ldc_process_VER: (0x%llx) err sending "
			    "version ACK/NACK\n", ldcp->id);
			i_ldc_reset(ldcp, B_TRUE);
			mutex_exit(&ldcp->tx_lock);
			return (ECONNRESET);
		}

		pkt = (ldc_msg_t *)(ldcp->tx_q_va + tx_tail);
		ZERO_PKT(pkt);

		/* initialize the packet */
		pkt->type = LDC_CTRL;
		pkt->ctrl = LDC_VER;

		for (;;) {

			D1(ldcp->id, "i_ldc_process_VER: got %u.%u chk %u.%u\n",
			    rcvd_ver->major, rcvd_ver->minor,
			    ldc_versions[idx].major, ldc_versions[idx].minor);

			if (rcvd_ver->major == ldc_versions[idx].major) {
				/* major version match - ACK version */
				pkt->stype = LDC_ACK;

				/*
				 * lower minor version to the one this endpt
				 * supports, if necessary
				 */
				if (rcvd_ver->minor > ldc_versions[idx].minor)
					rcvd_ver->minor =
					    ldc_versions[idx].minor;
				bcopy(rcvd_ver, pkt->udata, sizeof (*rcvd_ver));

				break;
			}

			if (rcvd_ver->major > ldc_versions[idx].major) {

				D1(ldcp->id, "i_ldc_process_VER: using next"
				    " lower idx=%d, v%u.%u\n", idx,
				    ldc_versions[idx].major,
				    ldc_versions[idx].minor);

				/* nack with next lower version */
				pkt->stype = LDC_NACK;
				bcopy(&ldc_versions[idx], pkt->udata,
				    sizeof (ldc_versions[idx]));
				ldcp->next_vidx = idx;
				break;
			}

			/* next major version */
			idx++;

			D1(ldcp->id, "i_ldc_process_VER: inc idx %x\n", idx);

			if (idx == LDC_NUM_VERS) {
				/* no version match - send NACK */
				pkt->stype = LDC_NACK;
				bzero(pkt->udata, sizeof (ldc_ver_t));
				ldcp->next_vidx = 0;
				break;
			}
		}

		/* initiate the send by calling into HV and set the new tail */
		tx_tail = (tx_tail + LDC_PACKET_SIZE) %
		    (ldcp->tx_q_entries << LDC_PACKET_SHIFT);

		rv = i_ldc_set_tx_tail(ldcp, tx_tail);
		if (rv == 0) {
			ldcp->tx_tail = tx_tail;
			if (pkt->stype == LDC_ACK) {
				D2(ldcp->id, "i_ldc_process_VER: (0x%llx) sent"
				    " version ACK\n", ldcp->id);
				/* Save the ACK'd version */
				ldcp->version.major = rcvd_ver->major;
				ldcp->version.minor = rcvd_ver->minor;
				ldcp->hstate |= TS_RCVD_VER;
				ldcp->tstate |= TS_VER_DONE;
				D1(DBG_ALL_LDCS,
				    "(0x%llx) Sent ACK, "
				    "Agreed on version v%u.%u\n",
				    ldcp->id, rcvd_ver->major, rcvd_ver->minor);
			}
		} else {
			DWARN(ldcp->id,
			    "i_ldc_process_VER: (0x%llx) error sending "
			    "ACK/NACK\n", ldcp->id);
			i_ldc_reset(ldcp, B_TRUE);
			mutex_exit(&ldcp->tx_lock);
			return (ECONNRESET);
		}

		break;

	case LDC_ACK:
		if ((ldcp->tstate & ~TS_IN_RESET) == TS_VREADY) {
			if (ldcp->version.major != rcvd_ver->major ||
			    ldcp->version.minor != rcvd_ver->minor) {

				/* mismatched version - reset connection */
				DWARN(ldcp->id,
				    "i_ldc_process_VER: (0x%llx) recvd"
				    " ACK ver != sent ACK ver\n", ldcp->id);
				i_ldc_reset(ldcp, B_TRUE);
				mutex_exit(&ldcp->tx_lock);
				return (ECONNRESET);
			}
		} else {
			/* SUCCESS - we have agreed on a version */
			ldcp->version.major = rcvd_ver->major;
			ldcp->version.minor = rcvd_ver->minor;
			ldcp->tstate |= TS_VER_DONE;
		}

		D1(ldcp->id, "(0x%llx) Got ACK, Agreed on version v%u.%u\n",
		    ldcp->id, rcvd_ver->major, rcvd_ver->minor);

		/* initiate RTS-RTR-RDX handshake */
		rv = i_ldc_get_tx_tail(ldcp, &tx_tail);
		if (rv) {
			DWARN(ldcp->id,
		    "i_ldc_process_VER: (0x%llx) cannot send RTS\n",
			    ldcp->id);
			i_ldc_reset(ldcp, B_TRUE);
			mutex_exit(&ldcp->tx_lock);
			return (ECONNRESET);
		}

		pkt = (ldc_msg_t *)(ldcp->tx_q_va + tx_tail);
		ZERO_PKT(pkt);

		pkt->type = LDC_CTRL;
		pkt->stype = LDC_INFO;
		pkt->ctrl = LDC_RTS;
		pkt->env = ldcp->mode;
		if (ldcp->mode != LDC_MODE_RAW)
			pkt->seqid = LDC_INIT_SEQID;

		ldcp->last_msg_rcd = LDC_INIT_SEQID;

		DUMP_LDC_PKT(ldcp, "i_ldc_process_VER snd rts", (uint64_t)pkt);

		/* initiate the send by calling into HV and set the new tail */
		tx_tail = (tx_tail + LDC_PACKET_SIZE) %
		    (ldcp->tx_q_entries << LDC_PACKET_SHIFT);

		rv = i_ldc_set_tx_tail(ldcp, tx_tail);
		if (rv) {
			D2(ldcp->id,
			    "i_ldc_process_VER: (0x%llx) no listener\n",
			    ldcp->id);
			i_ldc_reset(ldcp, B_TRUE);
			mutex_exit(&ldcp->tx_lock);
			return (ECONNRESET);
		}

		ldcp->tx_tail = tx_tail;
		ldcp->hstate |= TS_SENT_RTS;

		break;

	case LDC_NACK:
		/* check if version in NACK is zero */
		if (rcvd_ver->major == 0 && rcvd_ver->minor == 0) {
			/* version handshake failure */
			DWARN(DBG_ALL_LDCS,
			    "i_ldc_process_VER: (0x%llx) no version match\n",
			    ldcp->id);
			i_ldc_reset(ldcp, B_TRUE);
			mutex_exit(&ldcp->tx_lock);
			return (ECONNRESET);
		}

		/* get the current tail and pkt for the response */
		rv = i_ldc_get_tx_tail(ldcp, &tx_tail);
		if (rv != 0) {
			cmn_err(CE_NOTE,
			    "i_ldc_process_VER: (0x%lx) err sending "
			    "version ACK/NACK\n", ldcp->id);
			i_ldc_reset(ldcp, B_TRUE);
			mutex_exit(&ldcp->tx_lock);
			return (ECONNRESET);
		}

		pkt = (ldc_msg_t *)(ldcp->tx_q_va + tx_tail);
		ZERO_PKT(pkt);

		/* initialize the packet */
		pkt->type = LDC_CTRL;
		pkt->ctrl = LDC_VER;
		pkt->stype = LDC_INFO;

		/* check ver in NACK msg has a match */
		for (;;) {
			if (rcvd_ver->major == ldc_versions[idx].major) {
				/*
				 * major version match - resubmit request
				 * if lower minor version to the one this endpt
				 * supports, if necessary
				 */
				if (rcvd_ver->minor > ldc_versions[idx].minor)
					rcvd_ver->minor =
					    ldc_versions[idx].minor;
				bcopy(rcvd_ver, pkt->udata, sizeof (*rcvd_ver));
				break;
			}

			if (rcvd_ver->major > ldc_versions[idx].major) {

				D1(ldcp->id, "i_ldc_process_VER: using next"
				    " lower idx=%d, v%u.%u\n", idx,
				    ldc_versions[idx].major,
				    ldc_versions[idx].minor);

				/* send next lower version */
				bcopy(&ldc_versions[idx], pkt->udata,
				    sizeof (ldc_versions[idx]));
				ldcp->next_vidx = idx;
				break;
			}

			/* next version */
			idx++;

			D1(ldcp->id, "i_ldc_process_VER: inc idx %x\n", idx);

			if (idx == LDC_NUM_VERS) {
				/* no version match - terminate */
				ldcp->next_vidx = 0;
				mutex_exit(&ldcp->tx_lock);
				return (ECONNRESET);
			}
		}

		/* initiate the send by calling into HV and set the new tail */
		tx_tail = (tx_tail + LDC_PACKET_SIZE) %
		    (ldcp->tx_q_entries << LDC_PACKET_SHIFT);

		rv = i_ldc_set_tx_tail(ldcp, tx_tail);
		if (rv == 0) {
			D2(ldcp->id, "i_ldc_process_VER: (0x%llx) sent version"
			    "INFO v%u.%u\n", ldcp->id, ldc_versions[idx].major,
			    ldc_versions[idx].minor);
			ldcp->tx_tail = tx_tail;
		} else {
			cmn_err(CE_NOTE,
			    "i_ldc_process_VER: (0x%lx) error sending version"
			    "INFO\n", ldcp->id);
			i_ldc_reset(ldcp, B_TRUE);
			mutex_exit(&ldcp->tx_lock);
			return (ECONNRESET);
		}

		break;
	}

	mutex_exit(&ldcp->tx_lock);
	return (rv);
}


/*
 * Process an incoming RTS ctrl message
 */
static int
i_ldc_process_RTS(ldc_chan_t *ldcp, ldc_msg_t *msg)
{
	int		rv = 0;
	ldc_msg_t	*pkt;
	uint64_t	tx_tail;
	boolean_t	sent_NACK = B_FALSE;

	D2(ldcp->id, "i_ldc_process_RTS: (0x%llx) received RTS\n", ldcp->id);

	switch (msg->stype) {
	case LDC_NACK:
		DWARN(ldcp->id,
		    "i_ldc_process_RTS: (0x%llx) RTS NACK received\n",
		    ldcp->id);

		/* Reset the channel -- as we cannot continue */
		mutex_enter(&ldcp->tx_lock);
		i_ldc_reset(ldcp, B_TRUE);
		mutex_exit(&ldcp->tx_lock);
		rv = ECONNRESET;
		break;

	case LDC_INFO:

		/* check mode */
		if (ldcp->mode != (ldc_mode_t)msg->env) {
			cmn_err(CE_NOTE,
			    "i_ldc_process_RTS: (0x%lx) mode mismatch\n",
			    ldcp->id);
			/*
			 * send NACK in response to MODE message
			 * get the current tail for the response
			 */
			rv = i_ldc_send_pkt(ldcp, LDC_CTRL, LDC_NACK, LDC_RTS);
			if (rv) {
				/* if cannot send NACK - reset channel */
				mutex_enter(&ldcp->tx_lock);
				i_ldc_reset(ldcp, B_TRUE);
				mutex_exit(&ldcp->tx_lock);
				rv = ECONNRESET;
				break;
			}
			sent_NACK = B_TRUE;
		}
		break;
	default:
		DWARN(ldcp->id, "i_ldc_process_RTS: (0x%llx) unexp ACK\n",
		    ldcp->id);
		mutex_enter(&ldcp->tx_lock);
		i_ldc_reset(ldcp, B_TRUE);
		mutex_exit(&ldcp->tx_lock);
		rv = ECONNRESET;
		break;
	}

	/*
	 * If either the connection was reset (when rv != 0) or
	 * a NACK was sent, we return. In the case of a NACK
	 * we dont want to consume the packet that came in but
	 * not record that we received the RTS
	 */
	if (rv || sent_NACK)
		return (rv);

	/* record RTS received */
	ldcp->hstate |= TS_RCVD_RTS;

	/* store initial SEQID info */
	ldcp->last_msg_snt = msg->seqid;

	/* Obtain Tx lock */
	mutex_enter(&ldcp->tx_lock);

	/* get the current tail for the response */
	rv = i_ldc_get_tx_tail(ldcp, &tx_tail);
	if (rv != 0) {
		cmn_err(CE_NOTE,
		    "i_ldc_process_RTS: (0x%lx) err sending RTR\n",
		    ldcp->id);
		i_ldc_reset(ldcp, B_TRUE);
		mutex_exit(&ldcp->tx_lock);
		return (ECONNRESET);
	}

	pkt = (ldc_msg_t *)(ldcp->tx_q_va + tx_tail);
	ZERO_PKT(pkt);

	/* initialize the packet */
	pkt->type = LDC_CTRL;
	pkt->stype = LDC_INFO;
	pkt->ctrl = LDC_RTR;
	pkt->env = ldcp->mode;
	if (ldcp->mode != LDC_MODE_RAW)
		pkt->seqid = LDC_INIT_SEQID;

	ldcp->last_msg_rcd = msg->seqid;

	/* initiate the send by calling into HV and set the new tail */
	tx_tail = (tx_tail + LDC_PACKET_SIZE) %
	    (ldcp->tx_q_entries << LDC_PACKET_SHIFT);

	rv = i_ldc_set_tx_tail(ldcp, tx_tail);
	if (rv == 0) {
		D2(ldcp->id,
		    "i_ldc_process_RTS: (0x%llx) sent RTR\n", ldcp->id);
		DUMP_LDC_PKT(ldcp, "i_ldc_process_RTS sent rtr", (uint64_t)pkt);

		ldcp->tx_tail = tx_tail;
		ldcp->hstate |= TS_SENT_RTR;

	} else {
		cmn_err(CE_NOTE,
		    "i_ldc_process_RTS: (0x%lx) error sending RTR\n",
		    ldcp->id);
		i_ldc_reset(ldcp, B_TRUE);
		mutex_exit(&ldcp->tx_lock);
		return (ECONNRESET);
	}

	mutex_exit(&ldcp->tx_lock);
	return (0);
}

/*
 * Process an incoming RTR ctrl message
 */
static int
i_ldc_process_RTR(ldc_chan_t *ldcp, ldc_msg_t *msg)
{
	int		rv = 0;
	boolean_t	sent_NACK = B_FALSE;

	D2(ldcp->id, "i_ldc_process_RTR: (0x%llx) received RTR\n", ldcp->id);

	switch (msg->stype) {
	case LDC_NACK:
		/* RTR NACK received */
		DWARN(ldcp->id,
		    "i_ldc_process_RTR: (0x%llx) RTR NACK received\n",
		    ldcp->id);

		/* Reset the channel -- as we cannot continue */
		mutex_enter(&ldcp->tx_lock);
		i_ldc_reset(ldcp, B_TRUE);
		mutex_exit(&ldcp->tx_lock);
		rv = ECONNRESET;

		break;

	case LDC_INFO:

		/* check mode */
		if (ldcp->mode != (ldc_mode_t)msg->env) {
			DWARN(ldcp->id,
			    "i_ldc_process_RTR: (0x%llx) mode mismatch, "
			    "expecting 0x%x, got 0x%x\n",
			    ldcp->id, ldcp->mode, (ldc_mode_t)msg->env);
			/*
			 * send NACK in response to MODE message
			 * get the current tail for the response
			 */
			rv = i_ldc_send_pkt(ldcp, LDC_CTRL, LDC_NACK, LDC_RTR);
			if (rv) {
				/* if cannot send NACK - reset channel */
				mutex_enter(&ldcp->tx_lock);
				i_ldc_reset(ldcp, B_TRUE);
				mutex_exit(&ldcp->tx_lock);
				rv = ECONNRESET;
				break;
			}
			sent_NACK = B_TRUE;
		}
		break;

	default:
		DWARN(ldcp->id, "i_ldc_process_RTR: (0x%llx) unexp ACK\n",
		    ldcp->id);

		/* Reset the channel -- as we cannot continue */
		mutex_enter(&ldcp->tx_lock);
		i_ldc_reset(ldcp, B_TRUE);
		mutex_exit(&ldcp->tx_lock);
		rv = ECONNRESET;
		break;
	}

	/*
	 * If either the connection was reset (when rv != 0) or
	 * a NACK was sent, we return. In the case of a NACK
	 * we dont want to consume the packet that came in but
	 * not record that we received the RTR
	 */
	if (rv || sent_NACK)
		return (rv);

	ldcp->last_msg_snt = msg->seqid;
	ldcp->hstate |= TS_RCVD_RTR;

	rv = i_ldc_send_pkt(ldcp, LDC_CTRL, LDC_INFO, LDC_RDX);
	if (rv) {
		cmn_err(CE_NOTE,
		    "i_ldc_process_RTR: (0x%lx) cannot send RDX\n",
		    ldcp->id);
		mutex_enter(&ldcp->tx_lock);
		i_ldc_reset(ldcp, B_TRUE);
		mutex_exit(&ldcp->tx_lock);
		return (ECONNRESET);
	}
	D2(ldcp->id,
	    "i_ldc_process_RTR: (0x%llx) sent RDX\n", ldcp->id);

	ldcp->hstate |= TS_SENT_RDX;
	ldcp->tstate |= TS_HSHAKE_DONE;
	if ((ldcp->tstate & TS_IN_RESET) == 0)
		ldcp->status = LDC_UP;

	D1(ldcp->id, "(0x%llx) Handshake Complete\n", ldcp->id);

	return (0);
}


/*
 * Process an incoming RDX ctrl message
 */
static int
i_ldc_process_RDX(ldc_chan_t *ldcp, ldc_msg_t *msg)
{
	int	rv = 0;

	D2(ldcp->id, "i_ldc_process_RDX: (0x%llx) received RDX\n", ldcp->id);

	switch (msg->stype) {
	case LDC_NACK:
		/* RDX NACK received */
		DWARN(ldcp->id,
		    "i_ldc_process_RDX: (0x%llx) RDX NACK received\n",
		    ldcp->id);

		/* Reset the channel -- as we cannot continue */
		mutex_enter(&ldcp->tx_lock);
		i_ldc_reset(ldcp, B_TRUE);
		mutex_exit(&ldcp->tx_lock);
		rv = ECONNRESET;

		break;

	case LDC_INFO:

		/*
		 * if channel is UP and a RDX received after data transmission
		 * has commenced it is an error
		 */
		if ((ldcp->tstate == TS_UP) && (ldcp->hstate & TS_RCVD_RDX)) {
			DWARN(DBG_ALL_LDCS,
			    "i_ldc_process_RDX: (0x%llx) unexpected RDX"
			    " - LDC reset\n", ldcp->id);
			mutex_enter(&ldcp->tx_lock);
			i_ldc_reset(ldcp, B_TRUE);
			mutex_exit(&ldcp->tx_lock);
			return (ECONNRESET);
		}

		ldcp->hstate |= TS_RCVD_RDX;
		ldcp->tstate |= TS_HSHAKE_DONE;
		if ((ldcp->tstate & TS_IN_RESET) == 0)
			ldcp->status = LDC_UP;

		D1(DBG_ALL_LDCS, "(0x%llx) Handshake Complete\n", ldcp->id);
		break;

	default:
		DWARN(ldcp->id, "i_ldc_process_RDX: (0x%llx) unexp ACK\n",
		    ldcp->id);

		/* Reset the channel -- as we cannot continue */
		mutex_enter(&ldcp->tx_lock);
		i_ldc_reset(ldcp, B_TRUE);
		mutex_exit(&ldcp->tx_lock);
		rv = ECONNRESET;
		break;
	}

	return (rv);
}

/*
 * Process an incoming ACK for a data packet
 */
static int
i_ldc_process_data_ACK(ldc_chan_t *ldcp, ldc_msg_t *msg)
{
	int		rv;
	uint64_t	tx_head;
	ldc_msg_t	*pkt;

	/* Obtain Tx lock */
	mutex_enter(&ldcp->tx_lock);

	/*
	 * Read the current Tx head and tail
	 */
	rv = hv_ldc_tx_get_state(ldcp->id,
	    &ldcp->tx_head, &ldcp->tx_tail, &ldcp->link_state);
	if (rv != 0) {
		cmn_err(CE_WARN,
		    "i_ldc_process_data_ACK: (0x%lx) cannot read qptrs\n",
		    ldcp->id);

		/* Reset the channel -- as we cannot continue */
		i_ldc_reset(ldcp, B_TRUE);
		mutex_exit(&ldcp->tx_lock);
		return (ECONNRESET);
	}

	/*
	 * loop from where the previous ACK location was to the
	 * current head location. This is how far the HV has
	 * actually send pkts. Pkts between head and tail are
	 * yet to be sent by HV.
	 */
	tx_head = ldcp->tx_ackd_head;
	for (;;) {
		pkt = (ldc_msg_t *)(ldcp->tx_q_va + tx_head);
		tx_head = (tx_head + LDC_PACKET_SIZE) %
		    (ldcp->tx_q_entries << LDC_PACKET_SHIFT);

		if (pkt->seqid == msg->ackid) {
			D2(ldcp->id,
			    "i_ldc_process_data_ACK: (0x%llx) found packet\n",
			    ldcp->id);
			ldcp->last_ack_rcd = msg->ackid;
			ldcp->tx_ackd_head = tx_head;
			break;
		}
		if (tx_head == ldcp->tx_head) {
			/* could not find packet */
			DWARN(ldcp->id,
			    "i_ldc_process_data_ACK: (0x%llx) invalid ACKid\n",
			    ldcp->id);

			/* Reset the channel -- as we cannot continue */
			i_ldc_reset(ldcp, B_TRUE);
			mutex_exit(&ldcp->tx_lock);
			return (ECONNRESET);
		}
	}

	mutex_exit(&ldcp->tx_lock);
	return (0);
}

/*
 * Process incoming control message
 * Return 0 - session can continue
 *        EAGAIN - reprocess packet - state was changed
 *	  ECONNRESET - channel was reset
 */
static int
i_ldc_ctrlmsg(ldc_chan_t *ldcp, ldc_msg_t *msg)
{
	int		rv = 0;

	D1(ldcp->id, "i_ldc_ctrlmsg: (%llx) tstate = %lx, hstate = %lx\n",
	    ldcp->id, ldcp->tstate, ldcp->hstate);

	switch (ldcp->tstate & ~TS_IN_RESET) {

	case TS_OPEN:
	case TS_READY:

		switch (msg->ctrl & LDC_CTRL_MASK) {
		case LDC_VER:
			/* process version message */
			rv = i_ldc_process_VER(ldcp, msg);
			break;
		default:
			DWARN(ldcp->id,
			    "i_ldc_ctrlmsg: (0x%llx) unexp ctrl 0x%x "
			    "tstate=0x%x\n", ldcp->id,
			    (msg->ctrl & LDC_CTRL_MASK), ldcp->tstate);
			break;
		}

		break;

	case TS_VREADY:

		switch (msg->ctrl & LDC_CTRL_MASK) {
		case LDC_VER:
			/* process version message */
			rv = i_ldc_process_VER(ldcp, msg);
			break;
		case LDC_RTS:
			/* process RTS message */
			rv = i_ldc_process_RTS(ldcp, msg);
			break;
		case LDC_RTR:
			/* process RTR message */
			rv = i_ldc_process_RTR(ldcp, msg);
			break;
		case LDC_RDX:
			/* process RDX message */
			rv = i_ldc_process_RDX(ldcp, msg);
			break;
		default:
			DWARN(ldcp->id,
			    "i_ldc_ctrlmsg: (0x%llx) unexp ctrl 0x%x "
			    "tstate=0x%x\n", ldcp->id,
			    (msg->ctrl & LDC_CTRL_MASK), ldcp->tstate);
			break;
		}

		break;

	case TS_UP:

		switch (msg->ctrl & LDC_CTRL_MASK) {
		case LDC_VER:
			DWARN(ldcp->id,
			    "i_ldc_ctrlmsg: (0x%llx) unexpected VER "
			    "- LDC reset\n", ldcp->id);
			/* peer is redoing version negotiation */
			mutex_enter(&ldcp->tx_lock);
			(void) i_ldc_txq_reconf(ldcp);
			i_ldc_reset_state(ldcp);
			mutex_exit(&ldcp->tx_lock);
			rv = EAGAIN;
			break;

		case LDC_RDX:
			/* process RDX message */
			rv = i_ldc_process_RDX(ldcp, msg);
			break;

		default:
			DWARN(ldcp->id,
			    "i_ldc_ctrlmsg: (0x%llx) unexp ctrl 0x%x "
			    "tstate=0x%x\n", ldcp->id,
			    (msg->ctrl & LDC_CTRL_MASK), ldcp->tstate);
			break;
		}
	}

	return (rv);
}

/*
 * Register channel with the channel nexus
 */
static int
i_ldc_register_channel(ldc_chan_t *ldcp)
{
	int		rv = 0;
	ldc_cnex_t	*cinfo = &ldcssp->cinfo;

	if (cinfo->dip == NULL) {
		DWARN(ldcp->id,
		    "i_ldc_register_channel: cnex has not registered\n");
		return (EAGAIN);
	}

	rv = cinfo->reg_chan(cinfo->dip, ldcp->id, ldcp->devclass);
	if (rv) {
		DWARN(ldcp->id,
		    "i_ldc_register_channel: cannot register channel\n");
		return (rv);
	}

	rv = cinfo->add_intr(cinfo->dip, ldcp->id, CNEX_TX_INTR,
	    i_ldc_tx_hdlr, ldcp, NULL);
	if (rv) {
		DWARN(ldcp->id,
		    "i_ldc_register_channel: cannot add Tx interrupt\n");
		(void) cinfo->unreg_chan(cinfo->dip, ldcp->id);
		return (rv);
	}

	rv = cinfo->add_intr(cinfo->dip, ldcp->id, CNEX_RX_INTR,
	    i_ldc_rx_hdlr, ldcp, NULL);
	if (rv) {
		DWARN(ldcp->id,
		    "i_ldc_register_channel: cannot add Rx interrupt\n");
		(void) cinfo->rem_intr(cinfo->dip, ldcp->id, CNEX_TX_INTR);
		(void) cinfo->unreg_chan(cinfo->dip, ldcp->id);
		return (rv);
	}

	ldcp->tstate |= TS_CNEX_RDY;

	return (0);
}

/*
 * Unregister a channel with the channel nexus
 */
static int
i_ldc_unregister_channel(ldc_chan_t *ldcp)
{
	int		rv = 0;
	ldc_cnex_t	*cinfo = &ldcssp->cinfo;

	if (cinfo->dip == NULL) {
		DWARN(ldcp->id,
		    "i_ldc_unregister_channel: cnex has not registered\n");
		return (EAGAIN);
	}

	if (ldcp->tstate & TS_CNEX_RDY) {

		/* Remove the Rx interrupt */
		rv = cinfo->rem_intr(cinfo->dip, ldcp->id, CNEX_RX_INTR);
		if (rv) {
			if (rv != EAGAIN) {
				DWARN(ldcp->id,
				    "i_ldc_unregister_channel: err removing "
				    "Rx intr\n");
				return (rv);
			}

			/*
			 * If interrupts are pending and handler has
			 * finished running, clear interrupt and try
			 * again
			 */
			if (ldcp->rx_intr_state != LDC_INTR_PEND)
				return (rv);

			(void) i_ldc_clear_intr(ldcp, CNEX_RX_INTR);
			rv = cinfo->rem_intr(cinfo->dip, ldcp->id,
			    CNEX_RX_INTR);
			if (rv) {
				DWARN(ldcp->id, "i_ldc_unregister_channel: "
				    "err removing Rx interrupt\n");
				return (rv);
			}
		}

		/* Remove the Tx interrupt */
		rv = cinfo->rem_intr(cinfo->dip, ldcp->id, CNEX_TX_INTR);
		if (rv) {
			DWARN(ldcp->id,
			    "i_ldc_unregister_channel: err removing Tx intr\n");
			return (rv);
		}

		/* Unregister the channel */
		rv = cinfo->unreg_chan(ldcssp->cinfo.dip, ldcp->id);
		if (rv) {
			DWARN(ldcp->id,
			    "i_ldc_unregister_channel: cannot unreg channel\n");
			return (rv);
		}

		ldcp->tstate &= ~TS_CNEX_RDY;
	}

	return (0);
}


/*
 * LDC transmit interrupt handler
 *    triggered for chanel up/down/reset events
 *    and Tx queue content changes
 */
static uint_t
i_ldc_tx_hdlr(caddr_t arg1, caddr_t arg2)
{
	_NOTE(ARGUNUSED(arg2))

	int		rv;
	ldc_chan_t	*ldcp;
	boolean_t	notify_client = B_FALSE;
	uint64_t	notify_event = 0, link_state;

	/* Get the channel for which interrupt was received */
	ASSERT(arg1 != NULL);
	ldcp = (ldc_chan_t *)arg1;

	D1(ldcp->id, "i_ldc_tx_hdlr: (0x%llx) Received intr, ldcp=0x%p\n",
	    ldcp->id, ldcp);

	/* Lock channel */
	mutex_enter(&ldcp->lock);

	/* Obtain Tx lock */
	mutex_enter(&ldcp->tx_lock);

	/* mark interrupt as pending */
	ldcp->tx_intr_state = LDC_INTR_ACTIVE;

	/* save current link state */
	link_state = ldcp->link_state;

	rv = hv_ldc_tx_get_state(ldcp->id, &ldcp->tx_head, &ldcp->tx_tail,
	    &ldcp->link_state);
	if (rv) {
		cmn_err(CE_WARN,
		    "i_ldc_tx_hdlr: (0x%lx) cannot read queue ptrs rv=0x%d\n",
		    ldcp->id, rv);
		i_ldc_clear_intr(ldcp, CNEX_TX_INTR);
		mutex_exit(&ldcp->tx_lock);
		mutex_exit(&ldcp->lock);
		return (DDI_INTR_CLAIMED);
	}

	/*
	 * reset the channel state if the channel went down
	 * (other side unconfigured queue) or channel was reset
	 * (other side reconfigured its queue)
	 */
	if (link_state != ldcp->link_state &&
	    ldcp->link_state == LDC_CHANNEL_DOWN) {
		D1(ldcp->id, "i_ldc_tx_hdlr: channel link down\n", ldcp->id);
		i_ldc_reset(ldcp, B_FALSE);
		notify_client = B_TRUE;
		notify_event = LDC_EVT_DOWN;
	}

	if (link_state != ldcp->link_state &&
	    ldcp->link_state == LDC_CHANNEL_RESET) {
		D1(ldcp->id, "i_ldc_tx_hdlr: channel link reset\n", ldcp->id);
		i_ldc_reset(ldcp, B_FALSE);
		notify_client = B_TRUE;
		notify_event = LDC_EVT_RESET;
	}

	if (link_state != ldcp->link_state &&
	    (ldcp->tstate & ~TS_IN_RESET) == TS_OPEN &&
	    ldcp->link_state == LDC_CHANNEL_UP) {
		D1(ldcp->id, "i_ldc_tx_hdlr: channel link up\n", ldcp->id);
		notify_client = B_TRUE;
		notify_event = LDC_EVT_RESET;
		ldcp->tstate |= TS_LINK_READY;
		ldcp->status = LDC_READY;
	}

	/* if callbacks are disabled, do not notify */
	if (!ldcp->cb_enabled)
		notify_client = B_FALSE;

	i_ldc_clear_intr(ldcp, CNEX_TX_INTR);
	mutex_exit(&ldcp->tx_lock);

	if (notify_client) {
		ldcp->cb_inprogress = B_TRUE;
		mutex_exit(&ldcp->lock);
		rv = ldcp->cb(notify_event, ldcp->cb_arg);
		if (rv) {
			DWARN(ldcp->id, "i_ldc_tx_hdlr: (0x%llx) callback "
			    "failure", ldcp->id);
		}
		mutex_enter(&ldcp->lock);
		ldcp->cb_inprogress = B_FALSE;
	}

	mutex_exit(&ldcp->lock);

	D1(ldcp->id, "i_ldc_tx_hdlr: (0x%llx) exiting handler", ldcp->id);

	return (DDI_INTR_CLAIMED);
}

/*
 * Process the Rx HV queue.
 *
 * Returns 0 if data packets were found and no errors were encountered,
 * otherwise returns an error. In either case, the *notify argument is
 * set to indicate whether or not the client callback function should
 * be invoked. The *event argument is set to contain the callback event.
 *
 * Depending on the channel mode, packets are handled differently:
 *
 * RAW MODE
 * For raw mode channels, when a data packet is encountered,
 * processing stops and all packets are left on the queue to be removed
 * and processed by the ldc_read code path.
 *
 * UNRELIABLE MODE
 * For unreliable mode, when a data packet is encountered, processing
 * stops, and all packets are left on the queue to be removed and
 * processed by the ldc_read code path. Control packets are processed
 * inline if they are encountered before any data packets.
 *
 * RELIABLE MODE
 * For reliable mode channels, all packets on the receive queue
 * are processed: data packets are copied to the data queue and
 * control packets are processed inline. Packets are only left on
 * the receive queue when the data queue is full.
 */
static uint_t
i_ldc_rx_process_hvq(ldc_chan_t *ldcp, boolean_t *notify_client,
    uint64_t *notify_event)
{
	int		rv;
	uint64_t	rx_head, rx_tail;
	ldc_msg_t	*msg;
	uint64_t	link_state, first_fragment = 0;
	boolean_t	trace_length = B_TRUE;

	ASSERT(MUTEX_HELD(&ldcp->lock));
	*notify_client = B_FALSE;
	*notify_event = 0;

	/*
	 * Read packet(s) from the queue
	 */
	for (;;) {

		link_state = ldcp->link_state;
		rv = hv_ldc_rx_get_state(ldcp->id, &rx_head, &rx_tail,
		    &ldcp->link_state);
		if (rv) {
			cmn_err(CE_WARN,
			    "i_ldc_rx_process_hvq: (0x%lx) cannot read "
			    "queue ptrs, rv=0x%d\n", ldcp->id, rv);
			i_ldc_clear_intr(ldcp, CNEX_RX_INTR);
			return (EIO);
		}

		/*
		 * reset the channel state if the channel went down
		 * (other side unconfigured queue) or channel was reset
		 * (other side reconfigured its queue)
		 */

		if (link_state != ldcp->link_state) {

			switch (ldcp->link_state) {
			case LDC_CHANNEL_DOWN:
				D1(ldcp->id, "i_ldc_rx_process_hvq: channel "
				    "link down\n", ldcp->id);
				mutex_enter(&ldcp->tx_lock);
				i_ldc_reset(ldcp, B_FALSE);
				mutex_exit(&ldcp->tx_lock);
				*notify_client = B_TRUE;
				*notify_event = LDC_EVT_DOWN;
				goto loop_exit;

			case LDC_CHANNEL_UP:
				D1(ldcp->id, "i_ldc_rx_process_hvq: "
				    "channel link up\n", ldcp->id);

				if ((ldcp->tstate & ~TS_IN_RESET) == TS_OPEN) {
					*notify_client = B_TRUE;
					*notify_event = LDC_EVT_RESET;
					ldcp->tstate |= TS_LINK_READY;
					ldcp->status = LDC_READY;
				}
				break;

			case LDC_CHANNEL_RESET:
			default:
#ifdef DEBUG
force_reset:
#endif
				D1(ldcp->id, "i_ldc_rx_process_hvq: channel "
				    "link reset\n", ldcp->id);
				mutex_enter(&ldcp->tx_lock);
				i_ldc_reset(ldcp, B_FALSE);
				mutex_exit(&ldcp->tx_lock);
				*notify_client = B_TRUE;
				*notify_event = LDC_EVT_RESET;
				break;
			}
		}

#ifdef DEBUG
		if (LDC_INJECT_RESET(ldcp))
			goto force_reset;
		if (LDC_INJECT_DRNGCLEAR(ldcp))
			i_ldc_mem_inject_dring_clear(ldcp);
#endif
		if (trace_length) {
			TRACE_RXHVQ_LENGTH(ldcp, rx_head, rx_tail);
			trace_length = B_FALSE;
		}

		if (rx_head == rx_tail) {
			D2(ldcp->id, "i_ldc_rx_process_hvq: (0x%llx) "
			    "No packets\n", ldcp->id);
			break;
		}

		D2(ldcp->id, "i_ldc_rx_process_hvq: head=0x%llx, "
		    "tail=0x%llx\n", rx_head, rx_tail);
		DUMP_LDC_PKT(ldcp, "i_ldc_rx_process_hvq rcd",
		    ldcp->rx_q_va + rx_head);

		/* get the message */
		msg = (ldc_msg_t *)(ldcp->rx_q_va + rx_head);

		/* if channel is in RAW mode or data pkt, notify and return */
		if (ldcp->mode == LDC_MODE_RAW) {
			*notify_client = B_TRUE;
			*notify_event |= LDC_EVT_READ;
			break;
		}

		if ((msg->type & LDC_DATA) && (msg->stype & LDC_INFO)) {

			/* discard packet if channel is not up */
			if ((ldcp->tstate & ~TS_IN_RESET) != TS_UP) {

				/* move the head one position */
				rx_head = (rx_head + LDC_PACKET_SIZE) %
				    (ldcp->rx_q_entries << LDC_PACKET_SHIFT);

				if (rv = i_ldc_set_rx_head(ldcp, rx_head))
					break;

				continue;
			} else {
				uint64_t dq_head, dq_tail;

				/* process only RELIABLE mode data packets */
				if (ldcp->mode != LDC_MODE_RELIABLE) {
					if ((ldcp->tstate & TS_IN_RESET) == 0)
						*notify_client = B_TRUE;
					*notify_event |= LDC_EVT_READ;
					break;
				}

				/* don't process packet if queue full */
				(void) i_ldc_dq_rx_get_state(ldcp, &dq_head,
				    &dq_tail, NULL);
				dq_tail = (dq_tail + LDC_PACKET_SIZE) %
				    (ldcp->rx_dq_entries << LDC_PACKET_SHIFT);
				if (dq_tail == dq_head ||
				    LDC_INJECT_DQFULL(ldcp)) {
					rv = ENOSPC;
					break;
				}
			}
		}

		/* Check the sequence ID for the message received */
		rv = i_ldc_check_seqid(ldcp, msg);
		if (rv != 0) {

			DWARN(ldcp->id, "i_ldc_rx_process_hvq: (0x%llx) "
			    "seqid error, q_ptrs=0x%lx,0x%lx", ldcp->id,
			    rx_head, rx_tail);

			/* Reset last_msg_rcd to start of message */
			if (first_fragment != 0) {
				ldcp->last_msg_rcd = first_fragment - 1;
				first_fragment = 0;
			}

			/*
			 * Send a NACK due to seqid mismatch
			 */
			rv = i_ldc_send_pkt(ldcp, msg->type, LDC_NACK,
			    (msg->ctrl & LDC_CTRL_MASK));

			if (rv) {
				cmn_err(CE_NOTE, "i_ldc_rx_process_hvq: "
				    "(0x%lx) err sending CTRL/DATA NACK msg\n",
				    ldcp->id);

				/* if cannot send NACK - reset channel */
				mutex_enter(&ldcp->tx_lock);
				i_ldc_reset(ldcp, B_TRUE);
				mutex_exit(&ldcp->tx_lock);

				*notify_client = B_TRUE;
				*notify_event = LDC_EVT_RESET;
				break;
			}

			/* purge receive queue */
			(void) i_ldc_set_rx_head(ldcp, rx_tail);
			break;
		}

		/* record the message ID */
		ldcp->last_msg_rcd = msg->seqid;

		/* process control messages */
		if (msg->type & LDC_CTRL) {
			/* save current internal state */
			uint64_t tstate = ldcp->tstate;

			rv = i_ldc_ctrlmsg(ldcp, msg);
			if (rv == EAGAIN) {
				/* re-process pkt - state was adjusted */
				continue;
			}
			if (rv == ECONNRESET) {
				*notify_client = B_TRUE;
				*notify_event = LDC_EVT_RESET;
				break;
			}

			/*
			 * control message processing was successful
			 * channel transitioned to ready for communication
			 */
			if (rv == 0 && ldcp->tstate == TS_UP &&
			    (tstate & ~TS_IN_RESET) !=
			    (ldcp->tstate & ~TS_IN_RESET)) {
				*notify_client = B_TRUE;
				*notify_event = LDC_EVT_UP;
			}
		}

		/* process data NACKs */
		if ((msg->type & LDC_DATA) && (msg->stype & LDC_NACK)) {
			DWARN(ldcp->id,
			    "i_ldc_rx_process_hvq: (0x%llx) received DATA/NACK",
			    ldcp->id);
			mutex_enter(&ldcp->tx_lock);
			i_ldc_reset(ldcp, B_TRUE);
			mutex_exit(&ldcp->tx_lock);
			*notify_client = B_TRUE;
			*notify_event = LDC_EVT_RESET;
			break;
		}

		/* process data ACKs */
		if ((msg->type & LDC_DATA) && (msg->stype & LDC_ACK)) {
			if (rv = i_ldc_process_data_ACK(ldcp, msg)) {
				*notify_client = B_TRUE;
				*notify_event = LDC_EVT_RESET;
				break;
			}
		}

		if ((msg->type & LDC_DATA) && (msg->stype & LDC_INFO)) {
			ASSERT(ldcp->mode == LDC_MODE_RELIABLE);

			/*
			 * Copy the data packet to the data queue. Note
			 * that the copy routine updates the rx_head pointer.
			 */
			i_ldc_rxdq_copy(ldcp, &rx_head);

			if ((ldcp->tstate & TS_IN_RESET) == 0)
				*notify_client = B_TRUE;
			*notify_event |= LDC_EVT_READ;
		} else {
			rx_head = (rx_head + LDC_PACKET_SIZE) %
			    (ldcp->rx_q_entries << LDC_PACKET_SHIFT);
		}

		/* move the head one position */
		if (rv = i_ldc_set_rx_head(ldcp, rx_head)) {
			*notify_client = B_TRUE;
			*notify_event = LDC_EVT_RESET;
			break;
		}

	} /* for */

loop_exit:

	if (ldcp->mode == LDC_MODE_RELIABLE) {
		/* ACK data packets */
		if ((*notify_event &
		    (LDC_EVT_READ | LDC_EVT_RESET)) == LDC_EVT_READ) {
			int ack_rv;
			ack_rv = i_ldc_send_pkt(ldcp, LDC_DATA, LDC_ACK, 0);
			if (ack_rv && ack_rv != EWOULDBLOCK) {
				cmn_err(CE_NOTE,
				    "i_ldc_rx_process_hvq: (0x%lx) cannot "
				    "send ACK\n", ldcp->id);

				mutex_enter(&ldcp->tx_lock);
				i_ldc_reset(ldcp, B_FALSE);
				mutex_exit(&ldcp->tx_lock);

				*notify_client = B_TRUE;
				*notify_event = LDC_EVT_RESET;
				goto skip_ackpeek;
			}
		}

		/*
		 * If we have no more space on the data queue, make sure
		 * there are no ACKs on the rx queue waiting to be processed.
		 */
		if (rv == ENOSPC) {
			if (i_ldc_rx_ackpeek(ldcp, rx_head, rx_tail) != 0) {
				ldcp->rx_ack_head = ACKPEEK_HEAD_INVALID;
				*notify_client = B_TRUE;
				*notify_event = LDC_EVT_RESET;
			}
			return (rv);
		} else {
			ldcp->rx_ack_head = ACKPEEK_HEAD_INVALID;
		}
	}

skip_ackpeek:

	/* Return, indicating whether or not data packets were found */
	if ((*notify_event & (LDC_EVT_READ | LDC_EVT_RESET)) == LDC_EVT_READ)
		return (0);

	return (ENOMSG);
}

/*
 * Process any ACK packets on the HV receive queue.
 *
 * This function is only used by RELIABLE mode channels when the
 * secondary data queue fills up and there are packets remaining on
 * the HV receive queue.
 */
int
i_ldc_rx_ackpeek(ldc_chan_t *ldcp, uint64_t rx_head, uint64_t rx_tail)
{
	int		rv = 0;
	ldc_msg_t	*msg;

	if (ldcp->rx_ack_head == ACKPEEK_HEAD_INVALID)
		ldcp->rx_ack_head = rx_head;

	while (ldcp->rx_ack_head != rx_tail) {
		msg = (ldc_msg_t *)(ldcp->rx_q_va + ldcp->rx_ack_head);

		if ((msg->type & LDC_DATA) && (msg->stype & LDC_ACK)) {
			if (rv = i_ldc_process_data_ACK(ldcp, msg))
				break;
			msg->stype &= ~LDC_ACK;
		}

		ldcp->rx_ack_head =
		    (ldcp->rx_ack_head + LDC_PACKET_SIZE) %
		    (ldcp->rx_q_entries << LDC_PACKET_SHIFT);
	}
	return (rv);
}

/* -------------------------------------------------------------------------- */

/*
 * LDC API functions
 */

/*
 * Initialize the channel. Allocate internal structure and memory for
 * TX/RX queues, and initialize locks.
 */
int
ldc_init(uint64_t id, ldc_attr_t *attr, ldc_handle_t *handle)
{
	ldc_chan_t	*ldcp;
	int		rv, exit_val;
	uint64_t	ra_base, nentries;
	uint64_t	qlen;

	exit_val = EINVAL;	/* guarantee an error if exit on failure */

	if (attr == NULL) {
		DWARN(id, "ldc_init: (0x%llx) invalid attr\n", id);
		return (EINVAL);
	}
	if (handle == NULL) {
		DWARN(id, "ldc_init: (0x%llx) invalid handle\n", id);
		return (EINVAL);
	}

	/* check if channel is valid */
	rv = hv_ldc_tx_qinfo(id, &ra_base, &nentries);
	if (rv == H_ECHANNEL) {
		DWARN(id, "ldc_init: (0x%llx) invalid channel id\n", id);
		return (EINVAL);
	}

	/* check if the channel has already been initialized */
	mutex_enter(&ldcssp->lock);
	ldcp = ldcssp->chan_list;
	while (ldcp != NULL) {
		if (ldcp->id == id) {
			DWARN(id, "ldc_init: (0x%llx) already initialized\n",
			    id);
			mutex_exit(&ldcssp->lock);
			return (EADDRINUSE);
		}
		ldcp = ldcp->next;
	}
	mutex_exit(&ldcssp->lock);

	ASSERT(ldcp == NULL);

	*handle = 0;

	/* Allocate an ldcp structure */
	ldcp = kmem_zalloc(sizeof (ldc_chan_t), KM_SLEEP);

	/*
	 * Initialize the channel and Tx lock
	 *
	 * The channel 'lock' protects the entire channel and
	 * should be acquired before initializing, resetting,
	 * destroying or reading from a channel.
	 *
	 * The 'tx_lock' should be acquired prior to transmitting
	 * data over the channel. The lock should also be acquired
	 * prior to channel reconfiguration (in order to prevent
	 * concurrent writes).
	 *
	 * ORDERING: When both locks are being acquired, to prevent
	 * deadlocks, the channel lock should be always acquired prior
	 * to the tx_lock.
	 */
	mutex_init(&ldcp->lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&ldcp->tx_lock, NULL, MUTEX_DRIVER, NULL);

	/* Initialize the channel */
	ldcp->id = id;
	ldcp->cb = NULL;
	ldcp->cb_arg = NULL;
	ldcp->cb_inprogress = B_FALSE;
	ldcp->cb_enabled = B_FALSE;
	ldcp->next = NULL;

	/* Read attributes */
	ldcp->mode = attr->mode;
	ldcp->devclass = attr->devclass;
	ldcp->devinst = attr->instance;
	ldcp->mtu = (attr->mtu > 0) ? attr->mtu : LDC_DEFAULT_MTU;

	D1(ldcp->id,
	    "ldc_init: (0x%llx) channel attributes, class=0x%x, "
	    "instance=0x%llx, mode=%d, mtu=%d\n",
	    ldcp->id, ldcp->devclass, ldcp->devinst, ldcp->mode, ldcp->mtu);

	ldcp->next_vidx = 0;
	ldcp->tstate = TS_IN_RESET;
	ldcp->hstate = 0;
	ldcp->last_msg_snt = LDC_INIT_SEQID;
	ldcp->last_ack_rcd = 0;
	ldcp->last_msg_rcd = 0;
	ldcp->rx_ack_head = ACKPEEK_HEAD_INVALID;

	ldcp->stream_bufferp = NULL;
	ldcp->exp_dring_list = NULL;
	ldcp->imp_dring_list = NULL;
	ldcp->mhdl_list = NULL;

	ldcp->tx_intr_state = LDC_INTR_NONE;
	ldcp->rx_intr_state = LDC_INTR_NONE;

	/* Initialize payload size depending on whether channel is reliable */
	switch (ldcp->mode) {
	case LDC_MODE_RAW:
		ldcp->pkt_payload = LDC_PAYLOAD_SIZE_RAW;
		ldcp->read_p = i_ldc_read_raw;
		ldcp->write_p = i_ldc_write_raw;
		break;
	case LDC_MODE_UNRELIABLE:
		ldcp->pkt_payload = LDC_PAYLOAD_SIZE_UNRELIABLE;
		ldcp->read_p = i_ldc_read_packet;
		ldcp->write_p = i_ldc_write_packet;
		break;
	case LDC_MODE_RELIABLE:
		ldcp->pkt_payload = LDC_PAYLOAD_SIZE_RELIABLE;

		ldcp->stream_remains = 0;
		ldcp->stream_offset = 0;
		ldcp->stream_bufferp = kmem_alloc(ldcp->mtu, KM_SLEEP);
		ldcp->read_p = i_ldc_read_stream;
		ldcp->write_p = i_ldc_write_stream;
		break;
	default:
		exit_val = EINVAL;
		goto cleanup_on_exit;
	}

	/*
	 * qlen is (mtu * ldc_mtu_msgs) / pkt_payload. If this
	 * value is smaller than default length of ldc_queue_entries,
	 * qlen is set to ldc_queue_entries. Ensure that computed
	 * length is a power-of-two value.
	 */
	qlen = (ldcp->mtu * ldc_mtu_msgs) / ldcp->pkt_payload;
	if (!ISP2(qlen)) {
		uint64_t	tmp = 1;
		while (qlen) {
			qlen >>= 1; tmp <<= 1;
		}
		qlen = tmp;
	}

	ldcp->rx_q_entries =
	    (qlen < ldc_queue_entries) ? ldc_queue_entries : qlen;
	ldcp->tx_q_entries = ldcp->rx_q_entries;

	D1(ldcp->id, "ldc_init: queue length = 0x%llx\n", ldcp->rx_q_entries);

	/* Create a transmit queue */
	ldcp->tx_q_va = (uint64_t)
	    contig_mem_alloc(ldcp->tx_q_entries << LDC_PACKET_SHIFT);
	if (ldcp->tx_q_va == 0) {
		cmn_err(CE_WARN,
		    "ldc_init: (0x%lx) TX queue allocation failed\n",
		    ldcp->id);
		exit_val = ENOMEM;
		goto cleanup_on_exit;
	}
	ldcp->tx_q_ra = va_to_pa((caddr_t)ldcp->tx_q_va);

	D2(ldcp->id, "ldc_init: txq_va=0x%llx, txq_ra=0x%llx, entries=0x%llx\n",
	    ldcp->tx_q_va, ldcp->tx_q_ra, ldcp->tx_q_entries);

	ldcp->tstate |= TS_TXQ_RDY;

	/* Create a receive queue */
	ldcp->rx_q_va = (uint64_t)
	    contig_mem_alloc(ldcp->rx_q_entries << LDC_PACKET_SHIFT);
	if (ldcp->rx_q_va == 0) {
		cmn_err(CE_WARN,
		    "ldc_init: (0x%lx) RX queue allocation failed\n",
		    ldcp->id);
		exit_val = ENOMEM;
		goto cleanup_on_exit;
	}
	ldcp->rx_q_ra = va_to_pa((caddr_t)ldcp->rx_q_va);

	D2(ldcp->id, "ldc_init: rxq_va=0x%llx, rxq_ra=0x%llx, entries=0x%llx\n",
	    ldcp->rx_q_va, ldcp->rx_q_ra, ldcp->rx_q_entries);

	ldcp->tstate |= TS_RXQ_RDY;

	/* Setup a separate read data queue */
	if (ldcp->mode == LDC_MODE_RELIABLE) {
		ldcp->readq_get_state = i_ldc_dq_rx_get_state;
		ldcp->readq_set_head  = i_ldc_set_rxdq_head;

		/* Make sure the data queue multiplier is a power of 2 */
		if (!ISP2(ldc_rxdq_multiplier)) {
			D1(ldcp->id, "ldc_init: (0x%llx) ldc_rxdq_multiplier "
			    "not a power of 2, resetting", ldcp->id);
			ldc_rxdq_multiplier = LDC_RXDQ_MULTIPLIER;
		}

		ldcp->rx_dq_entries = ldc_rxdq_multiplier * ldcp->rx_q_entries;
		ldcp->rx_dq_va = (uint64_t)
		    kmem_alloc(ldcp->rx_dq_entries << LDC_PACKET_SHIFT,
		    KM_SLEEP);
		if (ldcp->rx_dq_va == 0) {
			cmn_err(CE_WARN,
			    "ldc_init: (0x%lx) RX data queue "
			    "allocation failed\n", ldcp->id);
			exit_val = ENOMEM;
			goto cleanup_on_exit;
		}

		ldcp->rx_dq_head = ldcp->rx_dq_tail = 0;

		D2(ldcp->id, "ldc_init: rx_dq_va=0x%llx, "
		    "rx_dq_entries=0x%llx\n", ldcp->rx_dq_va,
		    ldcp->rx_dq_entries);
	} else {
		ldcp->readq_get_state = i_ldc_hvq_rx_get_state;
		ldcp->readq_set_head  = i_ldc_set_rx_head;
	}

	/* Init descriptor ring and memory handle list lock */
	mutex_init(&ldcp->exp_dlist_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&ldcp->imp_dlist_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&ldcp->mlist_lock, NULL, MUTEX_DRIVER, NULL);

	/* mark status as INITialized */
	ldcp->status = LDC_INIT;

	/* Add to channel list */
	mutex_enter(&ldcssp->lock);
	ldcp->next = ldcssp->chan_list;
	ldcssp->chan_list = ldcp;
	ldcssp->channel_count++;
	mutex_exit(&ldcssp->lock);

	/* set the handle */
	*handle = (ldc_handle_t)ldcp;

	D1(ldcp->id, "ldc_init: (0x%llx) channel initialized\n", ldcp->id);

	return (0);

cleanup_on_exit:

	if (ldcp->mode == LDC_MODE_RELIABLE && ldcp->stream_bufferp)
		kmem_free(ldcp->stream_bufferp, ldcp->mtu);

	if (ldcp->tstate & TS_TXQ_RDY)
		contig_mem_free((caddr_t)ldcp->tx_q_va,
		    (ldcp->tx_q_entries << LDC_PACKET_SHIFT));

	if (ldcp->tstate & TS_RXQ_RDY)
		contig_mem_free((caddr_t)ldcp->rx_q_va,
		    (ldcp->rx_q_entries << LDC_PACKET_SHIFT));

	mutex_destroy(&ldcp->tx_lock);
	mutex_destroy(&ldcp->lock);

	kmem_free(ldcp, sizeof (ldc_chan_t));

	return (exit_val);
}

/*
 * Finalizes the LDC connection. It will return EBUSY if the
 * channel is open. A ldc_close() has to be done prior to
 * a ldc_fini operation. It frees TX/RX queues, associated
 * with the channel
 */
int
ldc_fini(ldc_handle_t handle)
{
	ldc_chan_t	*ldcp;
	ldc_chan_t	*tmp_ldcp;
	uint64_t	id;

	if (handle == 0) {
		DWARN(DBG_ALL_LDCS, "ldc_fini: invalid channel handle\n");
		return (EINVAL);
	}
	ldcp = (ldc_chan_t *)handle;
	id = ldcp->id;

	mutex_enter(&ldcp->lock);

	if ((ldcp->tstate & ~TS_IN_RESET) > TS_INIT) {
		DWARN(ldcp->id, "ldc_fini: (0x%llx) channel is open\n",
		    ldcp->id);
		mutex_exit(&ldcp->lock);
		return (EBUSY);
	}

	/* Remove from the channel list */
	mutex_enter(&ldcssp->lock);
	tmp_ldcp = ldcssp->chan_list;
	if (tmp_ldcp == ldcp) {
		ldcssp->chan_list = ldcp->next;
		ldcp->next = NULL;
	} else {
		while (tmp_ldcp != NULL) {
			if (tmp_ldcp->next == ldcp) {
				tmp_ldcp->next = ldcp->next;
				ldcp->next = NULL;
				break;
			}
			tmp_ldcp = tmp_ldcp->next;
		}
		if (tmp_ldcp == NULL) {
			DWARN(DBG_ALL_LDCS, "ldc_fini: invalid channel hdl\n");
			mutex_exit(&ldcssp->lock);
			mutex_exit(&ldcp->lock);
			return (EINVAL);
		}
	}

	ldcssp->channel_count--;

	mutex_exit(&ldcssp->lock);

	/* Free the map table for this channel */
	if (ldcp->mtbl) {
		(void) hv_ldc_set_map_table(ldcp->id, 0, 0);
		if (ldcp->mtbl->contigmem)
			contig_mem_free(ldcp->mtbl->table, ldcp->mtbl->size);
		else
			kmem_free(ldcp->mtbl->table, ldcp->mtbl->size);
		mutex_destroy(&ldcp->mtbl->lock);
		kmem_free(ldcp->mtbl, sizeof (ldc_mtbl_t));
	}

	/* Destroy descriptor ring and memory handle list lock */
	mutex_destroy(&ldcp->exp_dlist_lock);
	mutex_destroy(&ldcp->imp_dlist_lock);
	mutex_destroy(&ldcp->mlist_lock);

	/* Free the stream buffer for RELIABLE_MODE */
	if (ldcp->mode == LDC_MODE_RELIABLE && ldcp->stream_bufferp)
		kmem_free(ldcp->stream_bufferp, ldcp->mtu);

	/* Free the RX queue */
	contig_mem_free((caddr_t)ldcp->rx_q_va,
	    (ldcp->rx_q_entries << LDC_PACKET_SHIFT));
	ldcp->tstate &= ~TS_RXQ_RDY;

	/* Free the RX data queue */
	if (ldcp->mode == LDC_MODE_RELIABLE) {
		kmem_free((caddr_t)ldcp->rx_dq_va,
		    (ldcp->rx_dq_entries << LDC_PACKET_SHIFT));
	}

	/* Free the TX queue */
	contig_mem_free((caddr_t)ldcp->tx_q_va,
	    (ldcp->tx_q_entries << LDC_PACKET_SHIFT));
	ldcp->tstate &= ~TS_TXQ_RDY;

	mutex_exit(&ldcp->lock);

	/* Destroy mutex */
	mutex_destroy(&ldcp->tx_lock);
	mutex_destroy(&ldcp->lock);

	/* free channel structure */
	kmem_free(ldcp, sizeof (ldc_chan_t));

	D1(id, "ldc_fini: (0x%llx) channel finalized\n", id);

	return (0);
}

/*
 * Open the LDC channel for use. It registers the TX/RX queues
 * with the Hypervisor. It also specifies the interrupt number
 * and target CPU for this channel
 */
int
ldc_open(ldc_handle_t handle)
{
	ldc_chan_t	*ldcp;
	int		rv;

	if (handle == 0) {
		DWARN(DBG_ALL_LDCS, "ldc_open: invalid channel handle\n");
		return (EINVAL);
	}

	ldcp = (ldc_chan_t *)handle;

	mutex_enter(&ldcp->lock);

	if (ldcp->tstate < TS_INIT) {
		DWARN(ldcp->id,
		    "ldc_open: (0x%llx) channel not initialized\n", ldcp->id);
		mutex_exit(&ldcp->lock);
		return (EFAULT);
	}
	if ((ldcp->tstate & ~TS_IN_RESET) >= TS_OPEN) {
		DWARN(ldcp->id,
		    "ldc_open: (0x%llx) channel is already open\n", ldcp->id);
		mutex_exit(&ldcp->lock);
		return (EFAULT);
	}

	/*
	 * Unregister/Register the tx queue with the hypervisor
	 */
	rv = hv_ldc_tx_qconf(ldcp->id, 0, 0);
	if (rv) {
		cmn_err(CE_WARN,
		    "ldc_open: (0x%lx) channel tx queue unconf failed\n",
		    ldcp->id);
		mutex_exit(&ldcp->lock);
		return (EIO);
	}

	rv = hv_ldc_tx_qconf(ldcp->id, ldcp->tx_q_ra, ldcp->tx_q_entries);
	if (rv) {
		cmn_err(CE_WARN,
		    "ldc_open: (0x%lx) channel tx queue conf failed\n",
		    ldcp->id);
		mutex_exit(&ldcp->lock);
		return (EIO);
	}

	D2(ldcp->id, "ldc_open: (0x%llx) registered tx queue with LDC\n",
	    ldcp->id);

	/*
	 * Unregister/Register the rx queue with the hypervisor
	 */
	rv = hv_ldc_rx_qconf(ldcp->id, 0, 0);
	if (rv) {
		cmn_err(CE_WARN,
		    "ldc_open: (0x%lx) channel rx queue unconf failed\n",
		    ldcp->id);
		mutex_exit(&ldcp->lock);
		return (EIO);
	}

	rv = hv_ldc_rx_qconf(ldcp->id, ldcp->rx_q_ra, ldcp->rx_q_entries);
	if (rv) {
		cmn_err(CE_WARN,
		    "ldc_open: (0x%lx) channel rx queue conf failed\n",
		    ldcp->id);
		mutex_exit(&ldcp->lock);
		return (EIO);
	}

	D2(ldcp->id, "ldc_open: (0x%llx) registered rx queue with LDC\n",
	    ldcp->id);

	ldcp->tstate |= TS_QCONF_RDY;

	/* Register the channel with the channel nexus */
	rv = i_ldc_register_channel(ldcp);
	if (rv && rv != EAGAIN) {
		cmn_err(CE_WARN,
		    "ldc_open: (0x%lx) channel register failed\n", ldcp->id);
		ldcp->tstate &= ~TS_QCONF_RDY;
		(void) hv_ldc_tx_qconf(ldcp->id, 0, 0);
		(void) hv_ldc_rx_qconf(ldcp->id, 0, 0);
		mutex_exit(&ldcp->lock);
		return (EIO);
	}

	/* mark channel in OPEN state */
	ldcp->status = LDC_OPEN;

	/* Read channel state */
	rv = hv_ldc_tx_get_state(ldcp->id,
	    &ldcp->tx_head, &ldcp->tx_tail, &ldcp->link_state);
	if (rv) {
		cmn_err(CE_WARN,
		    "ldc_open: (0x%lx) cannot read channel state\n",
		    ldcp->id);
		(void) i_ldc_unregister_channel(ldcp);
		ldcp->tstate &= ~TS_QCONF_RDY;
		(void) hv_ldc_tx_qconf(ldcp->id, 0, 0);
		(void) hv_ldc_rx_qconf(ldcp->id, 0, 0);
		mutex_exit(&ldcp->lock);
		return (EIO);
	}

	/*
	 * set the ACKd head to current head location for reliable
	 */
	ldcp->tx_ackd_head = ldcp->tx_head;

	/* mark channel ready if HV report link is UP (peer alloc'd Rx queue) */
	if (ldcp->link_state == LDC_CHANNEL_UP ||
	    ldcp->link_state == LDC_CHANNEL_RESET) {
		ldcp->tstate |= TS_LINK_READY;
		ldcp->status = LDC_READY;
	}

	/*
	 * if channel is being opened in RAW mode - no handshake is needed
	 * switch the channel READY and UP state
	 */
	if (ldcp->mode == LDC_MODE_RAW) {
		ldcp->tstate = TS_UP;	/* set bits associated with LDC UP */
		ldcp->status = LDC_UP;
	}

	mutex_exit(&ldcp->lock);

	/*
	 * Increment number of open channels
	 */
	mutex_enter(&ldcssp->lock);
	ldcssp->channels_open++;
	mutex_exit(&ldcssp->lock);

	D1(ldcp->id,
	    "ldc_open: (0x%llx) channel (0x%p) open for use "
	    "(tstate=0x%x, status=0x%x)\n",
	    ldcp->id, ldcp, ldcp->tstate, ldcp->status);

	return (0);
}

/*
 * Close the LDC connection. It will return EBUSY if there
 * are memory segments or descriptor rings either bound to or
 * mapped over the channel
 */
int
ldc_close(ldc_handle_t handle)
{
	ldc_chan_t	*ldcp;
	int		rv = 0, retries = 0;
	boolean_t	chk_done = B_FALSE;

	if (handle == 0) {
		DWARN(DBG_ALL_LDCS, "ldc_close: invalid channel handle\n");
		return (EINVAL);
	}
	ldcp = (ldc_chan_t *)handle;

	mutex_enter(&ldcp->lock);

	/* return error if channel is not open */
	if ((ldcp->tstate & ~TS_IN_RESET) < TS_OPEN) {
		DWARN(ldcp->id,
		    "ldc_close: (0x%llx) channel is not open\n", ldcp->id);
		mutex_exit(&ldcp->lock);
		return (EFAULT);
	}

	/* if any memory handles, drings, are bound or mapped cannot close */
	if (ldcp->mhdl_list != NULL) {
		DWARN(ldcp->id,
		    "ldc_close: (0x%llx) channel has bound memory handles\n",
		    ldcp->id);
		mutex_exit(&ldcp->lock);
		return (EBUSY);
	}
	if (ldcp->exp_dring_list != NULL) {
		DWARN(ldcp->id,
		    "ldc_close: (0x%llx) channel has bound descriptor rings\n",
		    ldcp->id);
		mutex_exit(&ldcp->lock);
		return (EBUSY);
	}
	if (ldcp->imp_dring_list != NULL) {
		DWARN(ldcp->id,
		    "ldc_close: (0x%llx) channel has mapped descriptor rings\n",
		    ldcp->id);
		mutex_exit(&ldcp->lock);
		return (EBUSY);
	}

	if (ldcp->cb_inprogress) {
		DWARN(ldcp->id, "ldc_close: (0x%llx) callback active\n",
		    ldcp->id);
		mutex_exit(&ldcp->lock);
		return (EWOULDBLOCK);
	}

	/* Obtain Tx lock */
	mutex_enter(&ldcp->tx_lock);

	/*
	 * Wait for pending transmits to complete i.e Tx queue to drain
	 * if there are pending pkts - wait 1 ms and retry again
	 */
	for (;;) {

		rv = hv_ldc_tx_get_state(ldcp->id,
		    &ldcp->tx_head, &ldcp->tx_tail, &ldcp->link_state);
		if (rv) {
			cmn_err(CE_WARN,
			    "ldc_close: (0x%lx) cannot read qptrs\n", ldcp->id);
			mutex_exit(&ldcp->tx_lock);
			mutex_exit(&ldcp->lock);
			return (EIO);
		}

		if (ldcp->tx_head == ldcp->tx_tail ||
		    ldcp->link_state != LDC_CHANNEL_UP) {
			break;
		}

		if (chk_done) {
			DWARN(ldcp->id,
			    "ldc_close: (0x%llx) Tx queue drain timeout\n",
			    ldcp->id);
			break;
		}

		/* wait for one ms and try again */
		delay(drv_usectohz(1000));
		chk_done = B_TRUE;
	}

	/*
	 * Drain the Tx and Rx queues as we are closing the
	 * channel. We dont care about any pending packets.
	 * We have to also drain the queue prior to clearing
	 * pending interrupts, otherwise the HV will trigger
	 * an interrupt the moment the interrupt state is
	 * cleared.
	 */
	(void) i_ldc_txq_reconf(ldcp);
	i_ldc_rxq_drain(ldcp);

	/*
	 * Unregister the channel with the nexus
	 */
	while ((rv = i_ldc_unregister_channel(ldcp)) != 0) {

		mutex_exit(&ldcp->tx_lock);
		mutex_exit(&ldcp->lock);

		/* if any error other than EAGAIN return back */
		if (rv != EAGAIN || retries >= ldc_max_retries) {
			cmn_err(CE_WARN,
			    "ldc_close: (0x%lx) unregister failed, %d\n",
			    ldcp->id, rv);
			return (rv);
		}

		/*
		 * As there could be pending interrupts we need
		 * to wait and try again
		 */
		drv_usecwait(ldc_close_delay);
		mutex_enter(&ldcp->lock);
		mutex_enter(&ldcp->tx_lock);
		retries++;
	}

	ldcp->tstate &= ~TS_QCONF_RDY;

	/*
	 * Unregister queues
	 */
	rv = hv_ldc_tx_qconf(ldcp->id, 0, 0);
	if (rv) {
		cmn_err(CE_WARN,
		    "ldc_close: (0x%lx) channel TX queue unconf failed\n",
		    ldcp->id);
		mutex_exit(&ldcp->tx_lock);
		mutex_exit(&ldcp->lock);
		return (EIO);
	}
	rv = hv_ldc_rx_qconf(ldcp->id, 0, 0);
	if (rv) {
		cmn_err(CE_WARN,
		    "ldc_close: (0x%lx) channel RX queue unconf failed\n",
		    ldcp->id);
		mutex_exit(&ldcp->tx_lock);
		mutex_exit(&ldcp->lock);
		return (EIO);
	}

	/* Reset channel state information */
	i_ldc_reset_state(ldcp);

	/* Mark channel as down and in initialized state */
	ldcp->tx_ackd_head = 0;
	ldcp->tx_head = 0;
	ldcp->tstate = TS_IN_RESET|TS_INIT;
	ldcp->status = LDC_INIT;

	mutex_exit(&ldcp->tx_lock);
	mutex_exit(&ldcp->lock);

	/* Decrement number of open channels */
	mutex_enter(&ldcssp->lock);
	ldcssp->channels_open--;
	mutex_exit(&ldcssp->lock);

	D1(ldcp->id, "ldc_close: (0x%llx) channel closed\n", ldcp->id);

	return (0);
}

/*
 * Register channel callback
 */
int
ldc_reg_callback(ldc_handle_t handle,
    uint_t(*cb)(uint64_t event, caddr_t arg), caddr_t arg)
{
	ldc_chan_t *ldcp;

	if (handle == 0) {
		DWARN(DBG_ALL_LDCS,
		    "ldc_reg_callback: invalid channel handle\n");
		return (EINVAL);
	}
	if (((uint64_t)cb) < KERNELBASE) {
		DWARN(DBG_ALL_LDCS, "ldc_reg_callback: invalid callback\n");
		return (EINVAL);
	}
	ldcp = (ldc_chan_t *)handle;

	mutex_enter(&ldcp->lock);

	if (ldcp->cb) {
		DWARN(ldcp->id, "ldc_reg_callback: (0x%llx) callback exists\n",
		    ldcp->id);
		mutex_exit(&ldcp->lock);
		return (EIO);
	}
	if (ldcp->cb_inprogress) {
		DWARN(ldcp->id, "ldc_reg_callback: (0x%llx) callback active\n",
		    ldcp->id);
		mutex_exit(&ldcp->lock);
		return (EWOULDBLOCK);
	}

	ldcp->cb = cb;
	ldcp->cb_arg = arg;
	ldcp->cb_enabled = B_TRUE;

	D1(ldcp->id,
	    "ldc_reg_callback: (0x%llx) registered callback for channel\n",
	    ldcp->id);

	mutex_exit(&ldcp->lock);

	return (0);
}

/*
 * Unregister channel callback
 */
int
ldc_unreg_callback(ldc_handle_t handle)
{
	ldc_chan_t *ldcp;

	if (handle == 0) {
		DWARN(DBG_ALL_LDCS,
		    "ldc_unreg_callback: invalid channel handle\n");
		return (EINVAL);
	}
	ldcp = (ldc_chan_t *)handle;

	mutex_enter(&ldcp->lock);

	if (ldcp->cb == NULL) {
		DWARN(ldcp->id,
		    "ldc_unreg_callback: (0x%llx) no callback exists\n",
		    ldcp->id);
		mutex_exit(&ldcp->lock);
		return (EIO);
	}
	if (ldcp->cb_inprogress) {
		DWARN(ldcp->id,
		    "ldc_unreg_callback: (0x%llx) callback active\n",
		    ldcp->id);
		mutex_exit(&ldcp->lock);
		return (EWOULDBLOCK);
	}

	ldcp->cb = NULL;
	ldcp->cb_arg = NULL;
	ldcp->cb_enabled = B_FALSE;

	D1(ldcp->id,
	    "ldc_unreg_callback: (0x%llx) unregistered callback for channel\n",
	    ldcp->id);

	mutex_exit(&ldcp->lock);

	return (0);
}


/*
 * Bring a channel up by initiating a handshake with the peer
 * This call is asynchronous. It will complete at a later point
 * in time when the peer responds back with an RTR.
 */
int
ldc_up(ldc_handle_t handle)
{
	int		rv;
	ldc_chan_t	*ldcp;
	ldc_msg_t	*ldcmsg;
	uint64_t	tx_tail, tstate, link_state;

	if (handle == 0) {
		DWARN(DBG_ALL_LDCS, "ldc_up: invalid channel handle\n");
		return (EINVAL);
	}
	ldcp = (ldc_chan_t *)handle;

	mutex_enter(&ldcp->lock);

	D1(ldcp->id, "ldc_up: (0x%llx) doing channel UP\n", ldcp->id);

	/* clear the reset state */
	tstate = ldcp->tstate;
	ldcp->tstate &= ~TS_IN_RESET;

	if (ldcp->tstate == TS_UP) {
		DWARN(ldcp->id,
		    "ldc_up: (0x%llx) channel is already in UP state\n",
		    ldcp->id);

		/* mark channel as up */
		ldcp->status = LDC_UP;

		/*
		 * if channel was in reset state and there was
		 * pending data clear interrupt state. this will
		 * trigger an interrupt, causing the RX handler to
		 * to invoke the client's callback
		 */
		if ((tstate & TS_IN_RESET) &&
		    ldcp->rx_intr_state == LDC_INTR_PEND) {
			D1(ldcp->id,
			    "ldc_up: (0x%llx) channel has pending data, "
			    "clearing interrupt\n", ldcp->id);
			i_ldc_clear_intr(ldcp, CNEX_RX_INTR);
		}

		mutex_exit(&ldcp->lock);
		return (0);
	}

	/* if the channel is in RAW mode - mark it as UP, if READY */
	if (ldcp->mode == LDC_MODE_RAW && ldcp->tstate >= TS_READY) {
		ldcp->tstate = TS_UP;
		mutex_exit(&ldcp->lock);
		return (0);
	}

	/* Don't start another handshake if there is one in progress */
	if (ldcp->hstate) {
		D1(ldcp->id,
		    "ldc_up: (0x%llx) channel handshake in progress\n",
		    ldcp->id);
		mutex_exit(&ldcp->lock);
		return (0);
	}

	mutex_enter(&ldcp->tx_lock);

	/* save current link state */
	link_state = ldcp->link_state;

	/* get the current tail for the LDC msg */
	rv = i_ldc_get_tx_tail(ldcp, &tx_tail);
	if (rv) {
		D1(ldcp->id, "ldc_up: (0x%llx) cannot initiate handshake\n",
		    ldcp->id);
		mutex_exit(&ldcp->tx_lock);
		mutex_exit(&ldcp->lock);
		return (ECONNREFUSED);
	}

	/*
	 * If i_ldc_get_tx_tail() changed link_state to either RESET or UP,
	 * from a previous state of DOWN, then mark the channel as
	 * being ready for handshake.
	 */
	if ((link_state == LDC_CHANNEL_DOWN) &&
	    (link_state != ldcp->link_state)) {

		ASSERT((ldcp->link_state == LDC_CHANNEL_RESET) ||
		    (ldcp->link_state == LDC_CHANNEL_UP));

		if (ldcp->mode == LDC_MODE_RAW) {
			ldcp->status = LDC_UP;
			ldcp->tstate = TS_UP;
			mutex_exit(&ldcp->tx_lock);
			mutex_exit(&ldcp->lock);
			return (0);
		} else {
			ldcp->status = LDC_READY;
			ldcp->tstate |= TS_LINK_READY;
		}

	}

	ldcmsg = (ldc_msg_t *)(ldcp->tx_q_va + tx_tail);
	ZERO_PKT(ldcmsg);

	ldcmsg->type = LDC_CTRL;
	ldcmsg->stype = LDC_INFO;
	ldcmsg->ctrl = LDC_VER;
	ldcp->next_vidx = 0;
	bcopy(&ldc_versions[0], ldcmsg->udata, sizeof (ldc_versions[0]));

	DUMP_LDC_PKT(ldcp, "ldc_up snd ver", (uint64_t)ldcmsg);

	/* initiate the send by calling into HV and set the new tail */
	tx_tail = (tx_tail + LDC_PACKET_SIZE) %
	    (ldcp->tx_q_entries << LDC_PACKET_SHIFT);

	rv = i_ldc_set_tx_tail(ldcp, tx_tail);
	if (rv) {
		DWARN(ldcp->id,
		    "ldc_up: (0x%llx) cannot initiate handshake rv=%d\n",
		    ldcp->id, rv);
		mutex_exit(&ldcp->tx_lock);
		mutex_exit(&ldcp->lock);
		return (rv);
	}

	ldcp->hstate |= TS_SENT_VER;
	ldcp->tx_tail = tx_tail;
	D1(ldcp->id, "ldc_up: (0x%llx) channel up initiated\n", ldcp->id);

	mutex_exit(&ldcp->tx_lock);
	mutex_exit(&ldcp->lock);

	return (rv);
}


/*
 * Bring a channel down by resetting its state and queues
 */
int
ldc_down(ldc_handle_t handle)
{
	ldc_chan_t	*ldcp;

	if (handle == 0) {
		DWARN(DBG_ALL_LDCS, "ldc_down: invalid channel handle\n");
		return (EINVAL);
	}
	ldcp = (ldc_chan_t *)handle;
	mutex_enter(&ldcp->lock);
	mutex_enter(&ldcp->tx_lock);
	i_ldc_reset(ldcp, B_TRUE);
	mutex_exit(&ldcp->tx_lock);
	mutex_exit(&ldcp->lock);

	return (0);
}

/*
 * Get the current channel status
 */
int
ldc_status(ldc_handle_t handle, ldc_status_t *status)
{
	ldc_chan_t *ldcp;

	if (handle == 0 || status == NULL) {
		DWARN(DBG_ALL_LDCS, "ldc_status: invalid argument\n");
		return (EINVAL);
	}
	ldcp = (ldc_chan_t *)handle;

	*status = ((ldc_chan_t *)handle)->status;

	D1(ldcp->id,
	    "ldc_status: (0x%llx) returned status %d\n", ldcp->id, *status);
	return (0);
}


/*
 * Set the channel's callback mode - enable/disable callbacks
 */
int
ldc_set_cb_mode(ldc_handle_t handle, ldc_cb_mode_t cmode)
{
	ldc_chan_t	*ldcp;

	if (handle == 0) {
		DWARN(DBG_ALL_LDCS,
		    "ldc_set_intr_mode: invalid channel handle\n");
		return (EINVAL);
	}
	ldcp = (ldc_chan_t *)handle;

	/*
	 * Record no callbacks should be invoked
	 */
	mutex_enter(&ldcp->lock);

	switch (cmode) {
	case LDC_CB_DISABLE:
		if (!ldcp->cb_enabled) {
			DWARN(ldcp->id,
			    "ldc_set_cb_mode: (0x%llx) callbacks disabled\n",
			    ldcp->id);
			break;
		}
		ldcp->cb_enabled = B_FALSE;

		D1(ldcp->id, "ldc_set_cb_mode: (0x%llx) disabled callbacks\n",
		    ldcp->id);
		break;

	case LDC_CB_ENABLE:
		if (ldcp->cb_enabled) {
			DWARN(ldcp->id,
			    "ldc_set_cb_mode: (0x%llx) callbacks enabled\n",
			    ldcp->id);
			break;
		}
		ldcp->cb_enabled = B_TRUE;

		D1(ldcp->id, "ldc_set_cb_mode: (0x%llx) enabled callbacks\n",
		    ldcp->id);
		break;
	}

	mutex_exit(&ldcp->lock);

	return (0);
}

/*
 * Check to see if there are packets on the incoming queue
 * Will return hasdata = B_FALSE if there are no packets
 */
int
ldc_chkq(ldc_handle_t handle, boolean_t *hasdata)
{
	int		rv;
	uint64_t	rx_head, rx_tail;
	ldc_chan_t	*ldcp;

	if (handle == 0) {
		DWARN(DBG_ALL_LDCS, "ldc_chkq: invalid channel handle\n");
		return (EINVAL);
	}
	ldcp = (ldc_chan_t *)handle;

	*hasdata = B_FALSE;

	mutex_enter(&ldcp->lock);

	if (ldcp->tstate != TS_UP) {
		D1(ldcp->id,
		    "ldc_chkq: (0x%llx) channel is not up\n", ldcp->id);
		mutex_exit(&ldcp->lock);
		return (ECONNRESET);
	}

	/* Read packet(s) from the queue */
	rv = hv_ldc_rx_get_state(ldcp->id, &rx_head, &rx_tail,
	    &ldcp->link_state);
	if (rv != 0) {
		cmn_err(CE_WARN,
		    "ldc_chkq: (0x%lx) unable to read queue ptrs", ldcp->id);
		mutex_exit(&ldcp->lock);
		return (EIO);
	}

	/* reset the channel state if the channel went down */
	if (ldcp->link_state == LDC_CHANNEL_DOWN ||
	    ldcp->link_state == LDC_CHANNEL_RESET) {
		mutex_enter(&ldcp->tx_lock);
		i_ldc_reset(ldcp, B_FALSE);
		mutex_exit(&ldcp->tx_lock);
		mutex_exit(&ldcp->lock);
		return (ECONNRESET);
	}

	switch (ldcp->mode) {
	case LDC_MODE_RAW:
		/*
		 * In raw mode, there are no ctrl packets, so checking
		 * if the queue is non-empty is sufficient.
		 */
		*hasdata = (rx_head != rx_tail);
		break;

	case LDC_MODE_UNRELIABLE:
		/*
		 * In unreliable mode, if the queue is non-empty, we need
		 * to check if it actually contains unread data packets.
		 * The queue may just contain ctrl packets.
		 */
		if (rx_head != rx_tail) {
			*hasdata = (i_ldc_chkq(ldcp) == 0);
			/*
			 * If no data packets were found on the queue,
			 * all packets must have been control packets
			 * which will now have been processed, leaving
			 * the queue empty. If the interrupt state
			 * is pending, we need to clear the interrupt
			 * here.
			 */
			if (*hasdata == B_FALSE &&
			    ldcp->rx_intr_state == LDC_INTR_PEND) {
				i_ldc_clear_intr(ldcp, CNEX_RX_INTR);
			}
		}
		break;

	case LDC_MODE_RELIABLE:
		/*
		 * In reliable mode, first check for 'stream_remains' > 0.
		 * Otherwise, if the data queue head and tail pointers
		 * differ, there must be data to read.
		 */
		if (ldcp->stream_remains > 0)
			*hasdata = B_TRUE;
		else
			*hasdata = (ldcp->rx_dq_head != ldcp->rx_dq_tail);
		break;

	default:
		cmn_err(CE_WARN, "ldc_chkq: (0x%lx) unexpected channel mode "
		    "(0x%x)", ldcp->id, ldcp->mode);
		mutex_exit(&ldcp->lock);
		return (EIO);
	}

	mutex_exit(&ldcp->lock);

	return (0);
}


/*
 * Read 'size' amount of bytes or less. If incoming buffer
 * is more than 'size', ENOBUFS is returned.
 *
 * On return, size contains the number of bytes read.
 */
int
ldc_read(ldc_handle_t handle, caddr_t bufp, size_t *sizep)
{
	ldc_chan_t	*ldcp;
	uint64_t	rx_head = 0, rx_tail = 0;
	int		rv = 0, exit_val;

	if (handle == 0) {
		DWARN(DBG_ALL_LDCS, "ldc_read: invalid channel handle\n");
		return (EINVAL);
	}

	ldcp = (ldc_chan_t *)handle;

	/* channel lock */
	mutex_enter(&ldcp->lock);

	if (ldcp->tstate != TS_UP) {
		DWARN(ldcp->id,
		    "ldc_read: (0x%llx) channel is not in UP state\n",
		    ldcp->id);
		exit_val = ECONNRESET;
	} else if (ldcp->mode == LDC_MODE_RELIABLE) {
		TRACE_RXDQ_LENGTH(ldcp);
		exit_val = ldcp->read_p(ldcp, bufp, sizep);

		/*
		 * For reliable mode channels, the interrupt
		 * state is only set to pending during
		 * interrupt handling when the secondary data
		 * queue became full, leaving unprocessed
		 * packets on the Rx queue. If the interrupt
		 * state is pending and space is now available
		 * on the data queue, clear the interrupt.
		 */
		if (ldcp->rx_intr_state == LDC_INTR_PEND &&
		    Q_CONTIG_SPACE(ldcp->rx_dq_head, ldcp->rx_dq_tail,
		    ldcp->rx_dq_entries << LDC_PACKET_SHIFT) >=
		    LDC_PACKET_SIZE) {
			/* data queue is not full */
			i_ldc_clear_intr(ldcp, CNEX_RX_INTR);
		}

		mutex_exit(&ldcp->lock);
		return (exit_val);
	} else {
		exit_val = ldcp->read_p(ldcp, bufp, sizep);
	}

	/*
	 * if queue has been drained - clear interrupt
	 */
	rv = hv_ldc_rx_get_state(ldcp->id, &rx_head, &rx_tail,
	    &ldcp->link_state);
	if (rv != 0) {
		cmn_err(CE_WARN, "ldc_read: (0x%lx) unable to read queue ptrs",
		    ldcp->id);
		mutex_enter(&ldcp->tx_lock);
		i_ldc_reset(ldcp, B_TRUE);
		mutex_exit(&ldcp->tx_lock);
		mutex_exit(&ldcp->lock);
		return (ECONNRESET);
	}

	if (exit_val == 0) {
		if (ldcp->link_state == LDC_CHANNEL_DOWN ||
		    ldcp->link_state == LDC_CHANNEL_RESET) {
			mutex_enter(&ldcp->tx_lock);
			i_ldc_reset(ldcp, B_FALSE);
			exit_val = ECONNRESET;
			mutex_exit(&ldcp->tx_lock);
		}
		if ((rv == 0) &&
		    (ldcp->rx_intr_state == LDC_INTR_PEND) &&
		    (rx_head == rx_tail)) {
			i_ldc_clear_intr(ldcp, CNEX_RX_INTR);
		}
	}

	mutex_exit(&ldcp->lock);
	return (exit_val);
}

/*
 * Basic raw mondo read -
 * no interpretation of mondo contents at all.
 *
 * Enter and exit with ldcp->lock held by caller
 */
static int
i_ldc_read_raw(ldc_chan_t *ldcp, caddr_t target_bufp, size_t *sizep)
{
	uint64_t	q_size_mask;
	ldc_msg_t	*msgp;
	uint8_t		*msgbufp;
	int		rv = 0, space;
	uint64_t	rx_head, rx_tail;

	space = *sizep;

	if (space < LDC_PAYLOAD_SIZE_RAW)
		return (ENOBUFS);

	ASSERT(mutex_owned(&ldcp->lock));

	/* compute mask for increment */
	q_size_mask = (ldcp->rx_q_entries-1)<<LDC_PACKET_SHIFT;

	/*
	 * Read packet(s) from the queue
	 */
	rv = hv_ldc_rx_get_state(ldcp->id, &rx_head, &rx_tail,
	    &ldcp->link_state);
	if (rv != 0) {
		cmn_err(CE_WARN,
		    "ldc_read_raw: (0x%lx) unable to read queue ptrs",
		    ldcp->id);
		return (EIO);
	}
	D1(ldcp->id, "ldc_read_raw: (0x%llx) rxh=0x%llx,"
	    " rxt=0x%llx, st=0x%llx\n",
	    ldcp->id, rx_head, rx_tail, ldcp->link_state);

	/* reset the channel state if the channel went down */
	if (ldcp->link_state == LDC_CHANNEL_DOWN ||
	    ldcp->link_state == LDC_CHANNEL_RESET) {
		mutex_enter(&ldcp->tx_lock);
		i_ldc_reset(ldcp, B_FALSE);
		mutex_exit(&ldcp->tx_lock);
		return (ECONNRESET);
	}

	/*
	 * Check for empty queue
	 */
	if (rx_head == rx_tail) {
		*sizep = 0;
		return (0);
	}

	/* get the message */
	msgp = (ldc_msg_t *)(ldcp->rx_q_va + rx_head);

	/* if channel is in RAW mode, copy data and return */
	msgbufp = (uint8_t *)&(msgp->raw[0]);

	bcopy(msgbufp, target_bufp, LDC_PAYLOAD_SIZE_RAW);

	DUMP_PAYLOAD(ldcp->id, msgbufp);

	*sizep = LDC_PAYLOAD_SIZE_RAW;

	rx_head = (rx_head + LDC_PACKET_SIZE) & q_size_mask;
	rv = i_ldc_set_rx_head(ldcp, rx_head);

	return (rv);
}

/*
 * Process LDC mondos to build larger packets
 * with either un-reliable or reliable delivery.
 *
 * Enter and exit with ldcp->lock held by caller
 */
static int
i_ldc_read_packet(ldc_chan_t *ldcp, caddr_t target_bufp, size_t *sizep)
{
	int		rv = 0;
	uint64_t	rx_head = 0, rx_tail = 0;
	uint64_t	curr_head = 0;
	ldc_msg_t	*msg;
	caddr_t		target;
	size_t		len = 0, bytes_read = 0;
	int		retries = 0;
	uint64_t	q_va, q_size_mask;
	uint64_t	first_fragment = 0;

	target = target_bufp;

	ASSERT(mutex_owned(&ldcp->lock));

	/* check if the buffer and size are valid */
	if (target_bufp == NULL || *sizep == 0) {
		DWARN(ldcp->id, "ldc_read: (0x%llx) invalid buffer/size\n",
		    ldcp->id);
		return (EINVAL);
	}

	/* Set q_va and compute increment mask for the appropriate queue */
	if (ldcp->mode == LDC_MODE_RELIABLE) {
		q_va	    = ldcp->rx_dq_va;
		q_size_mask = (ldcp->rx_dq_entries-1)<<LDC_PACKET_SHIFT;
	} else {
		q_va	    = ldcp->rx_q_va;
		q_size_mask = (ldcp->rx_q_entries-1)<<LDC_PACKET_SHIFT;
	}

	/*
	 * Read packet(s) from the queue
	 */
	rv = ldcp->readq_get_state(ldcp, &curr_head, &rx_tail,
	    &ldcp->link_state);
	if (rv != 0) {
		cmn_err(CE_WARN, "ldc_read: (0x%lx) unable to read queue ptrs",
		    ldcp->id);
		mutex_enter(&ldcp->tx_lock);
		i_ldc_reset(ldcp, B_TRUE);
		mutex_exit(&ldcp->tx_lock);
		return (ECONNRESET);
	}
	D1(ldcp->id, "ldc_read: (0x%llx) chd=0x%llx, tl=0x%llx, st=0x%llx\n",
	    ldcp->id, curr_head, rx_tail, ldcp->link_state);

	/* reset the channel state if the channel went down */
	if (ldcp->link_state != LDC_CHANNEL_UP)
		goto channel_is_reset;

	for (;;) {

		if (curr_head == rx_tail) {
			/*
			 * If a data queue is being used, check the Rx HV
			 * queue. This will copy over any new data packets
			 * that have arrived.
			 */
			if (ldcp->mode == LDC_MODE_RELIABLE)
				(void) i_ldc_chkq(ldcp);

			rv = ldcp->readq_get_state(ldcp,
			    &rx_head, &rx_tail, &ldcp->link_state);
			if (rv != 0) {
				cmn_err(CE_WARN,
				    "ldc_read: (0x%lx) cannot read queue ptrs",
				    ldcp->id);
				mutex_enter(&ldcp->tx_lock);
				i_ldc_reset(ldcp, B_TRUE);
				mutex_exit(&ldcp->tx_lock);
				return (ECONNRESET);
			}

			if (ldcp->link_state != LDC_CHANNEL_UP)
				goto channel_is_reset;

			if (curr_head == rx_tail) {

				/* If in the middle of a fragmented xfer */
				if (first_fragment != 0) {

					/* wait for ldc_delay usecs */
					drv_usecwait(ldc_delay);

					if (++retries < ldc_max_retries)
						continue;

					*sizep = 0;
					if (ldcp->mode != LDC_MODE_RELIABLE)
						ldcp->last_msg_rcd =
						    first_fragment - 1;
					DWARN(DBG_ALL_LDCS, "ldc_read: "
					    "(0x%llx) read timeout", ldcp->id);
					return (EAGAIN);
				}
				*sizep = 0;
				break;
			}
		}
		retries = 0;

		D2(ldcp->id,
		    "ldc_read: (0x%llx) chd=0x%llx, rxhd=0x%llx, rxtl=0x%llx\n",
		    ldcp->id, curr_head, rx_head, rx_tail);

		/* get the message */
		msg = (ldc_msg_t *)(q_va + curr_head);

		DUMP_LDC_PKT(ldcp, "ldc_read received pkt",
		    ldcp->rx_q_va + curr_head);

		/* Check the message ID for the message received */
		if (ldcp->mode != LDC_MODE_RELIABLE) {
			if ((rv = i_ldc_check_seqid(ldcp, msg)) != 0) {

				DWARN(ldcp->id, "ldc_read: (0x%llx) seqid "
				    "error, q_ptrs=0x%lx,0x%lx",
				    ldcp->id, rx_head, rx_tail);

				/* throw away data */
				bytes_read = 0;

				/* Reset last_msg_rcd to start of message */
				if (first_fragment != 0) {
					ldcp->last_msg_rcd = first_fragment - 1;
					first_fragment = 0;
				}
				/*
				 * Send a NACK -- invalid seqid
				 * get the current tail for the response
				 */
				rv = i_ldc_send_pkt(ldcp, msg->type, LDC_NACK,
				    (msg->ctrl & LDC_CTRL_MASK));
				if (rv) {
					cmn_err(CE_NOTE,
					    "ldc_read: (0x%lx) err sending "
					    "NACK msg\n", ldcp->id);

					/* if cannot send NACK - reset chan */
					mutex_enter(&ldcp->tx_lock);
					i_ldc_reset(ldcp, B_FALSE);
					mutex_exit(&ldcp->tx_lock);
					rv = ECONNRESET;
					break;
				}

				/* purge receive queue */
				rv = i_ldc_set_rx_head(ldcp, rx_tail);

				break;
			}

			/*
			 * Process any messages of type CTRL messages
			 * Future implementations should try to pass these
			 * to LDC link by resetting the intr state.
			 *
			 * NOTE: not done as a switch() as type can be
			 * both ctrl+data
			 */
			if (msg->type & LDC_CTRL) {
				if (rv = i_ldc_ctrlmsg(ldcp, msg)) {
					if (rv == EAGAIN)
						continue;
					rv = i_ldc_set_rx_head(ldcp, rx_tail);
					*sizep = 0;
					bytes_read = 0;
					break;
				}
			}

			/* process data ACKs */
			if ((msg->type & LDC_DATA) && (msg->stype & LDC_ACK)) {
				if (rv = i_ldc_process_data_ACK(ldcp, msg)) {
					*sizep = 0;
					bytes_read = 0;
					break;
				}
			}

			/* process data NACKs */
			if ((msg->type & LDC_DATA) && (msg->stype & LDC_NACK)) {
				DWARN(ldcp->id,
				    "ldc_read: (0x%llx) received DATA/NACK",
				    ldcp->id);
				mutex_enter(&ldcp->tx_lock);
				i_ldc_reset(ldcp, B_TRUE);
				mutex_exit(&ldcp->tx_lock);
				return (ECONNRESET);
			}
		}

		/* process data messages */
		if ((msg->type & LDC_DATA) && (msg->stype & LDC_INFO)) {

			uint8_t *msgbuf = (uint8_t *)(
			    (ldcp->mode == LDC_MODE_RELIABLE) ?
			    msg->rdata : msg->udata);

			D2(ldcp->id,
			    "ldc_read: (0x%llx) received data msg\n", ldcp->id);

			/* get the packet length */
			len = (msg->env & LDC_LEN_MASK);

				/*
				 * FUTURE OPTIMIZATION:
				 * dont need to set q head for every
				 * packet we read just need to do this when
				 * we are done or need to wait for more
				 * mondos to make a full packet - this is
				 * currently expensive.
				 */

			if (first_fragment == 0) {

				/*
				 * first packets should always have the start
				 * bit set (even for a single packet). If not
				 * throw away the packet
				 */
				if (!(msg->env & LDC_FRAG_START)) {

					DWARN(DBG_ALL_LDCS,
					    "ldc_read: (0x%llx) not start - "
					    "frag=%x\n", ldcp->id,
					    (msg->env) & LDC_FRAG_MASK);

					/* toss pkt, inc head, cont reading */
					bytes_read = 0;
					target = target_bufp;
					curr_head =
					    (curr_head + LDC_PACKET_SIZE)
					    & q_size_mask;
					if (rv = ldcp->readq_set_head(ldcp,
					    curr_head))
						break;

					continue;
				}

				first_fragment = msg->seqid;
			} else {
				/* check to see if this is a pkt w/ START bit */
				if (msg->env & LDC_FRAG_START) {
					DWARN(DBG_ALL_LDCS,
					    "ldc_read:(0x%llx) unexpected pkt"
					    " env=0x%x discarding %d bytes,"
					    " lastmsg=%d, currentmsg=%d\n",
					    ldcp->id, msg->env&LDC_FRAG_MASK,
					    bytes_read, ldcp->last_msg_rcd,
					    msg->seqid);

					/* throw data we have read so far */
					bytes_read = 0;
					target = target_bufp;
					first_fragment = msg->seqid;

					if (rv = ldcp->readq_set_head(ldcp,
					    curr_head))
						break;
				}
			}

			/* copy (next) pkt into buffer */
			if (len <= (*sizep - bytes_read)) {
				bcopy(msgbuf, target, len);
				target += len;
				bytes_read += len;
			} else {
				/*
				 * there is not enough space in the buffer to
				 * read this pkt. throw message away & continue
				 * reading data from queue
				 */
				DWARN(DBG_ALL_LDCS,
				    "ldc_read: (0x%llx) buffer too small, "
				    "head=0x%lx, expect=%d, got=%d\n", ldcp->id,
				    curr_head, *sizep, bytes_read+len);

				first_fragment = 0;
				target = target_bufp;
				bytes_read = 0;

				/* throw away everything received so far */
				if (rv = ldcp->readq_set_head(ldcp, curr_head))
					break;

				/* continue reading remaining pkts */
				continue;
			}
		}

		/* set the message id */
		if (ldcp->mode != LDC_MODE_RELIABLE)
			ldcp->last_msg_rcd = msg->seqid;

		/* move the head one position */
		curr_head = (curr_head + LDC_PACKET_SIZE) & q_size_mask;

		if (msg->env & LDC_FRAG_STOP) {

			/*
			 * All pkts that are part of this fragmented transfer
			 * have been read or this was a single pkt read
			 * or there was an error
			 */

			/* set the queue head */
			if (rv = ldcp->readq_set_head(ldcp, curr_head))
				bytes_read = 0;

			*sizep = bytes_read;

			break;
		}

		/* advance head if it is a CTRL packet or a DATA ACK packet */
		if ((msg->type & LDC_CTRL) ||
		    ((msg->type & LDC_DATA) && (msg->stype & LDC_ACK))) {

			/* set the queue head */
			if (rv = ldcp->readq_set_head(ldcp, curr_head)) {
				bytes_read = 0;
				break;
			}

			D2(ldcp->id, "ldc_read: (0x%llx) set ACK qhead 0x%llx",
			    ldcp->id, curr_head);
		}

	} /* for (;;) */

	D2(ldcp->id, "ldc_read: (0x%llx) end size=%d", ldcp->id, *sizep);

	return (rv);

channel_is_reset:
	mutex_enter(&ldcp->tx_lock);
	i_ldc_reset(ldcp, B_FALSE);
	mutex_exit(&ldcp->tx_lock);
	return (ECONNRESET);
}

/*
 * Fetch and buffer incoming packets so we can hand them back as
 * a basic byte stream.
 *
 * Enter and exit with ldcp->lock held by caller
 */
static int
i_ldc_read_stream(ldc_chan_t *ldcp, caddr_t target_bufp, size_t *sizep)
{
	int	rv;
	size_t	size;

	ASSERT(mutex_owned(&ldcp->lock));

	D2(ldcp->id, "i_ldc_read_stream: (0x%llx) buffer size=%d",
	    ldcp->id, *sizep);

	if (ldcp->stream_remains == 0) {
		size = ldcp->mtu;
		rv = i_ldc_read_packet(ldcp,
		    (caddr_t)ldcp->stream_bufferp, &size);
		D2(ldcp->id, "i_ldc_read_stream: read packet (0x%llx) size=%d",
		    ldcp->id, size);

		if (rv != 0)
			return (rv);

		ldcp->stream_remains = size;
		ldcp->stream_offset = 0;
	}

	size = MIN(ldcp->stream_remains, *sizep);

	bcopy(ldcp->stream_bufferp + ldcp->stream_offset, target_bufp, size);
	ldcp->stream_offset += size;
	ldcp->stream_remains -= size;

	D2(ldcp->id, "i_ldc_read_stream: (0x%llx) fill from buffer size=%d",
	    ldcp->id, size);

	*sizep = size;
	return (0);
}

/*
 * Write specified amount of bytes to the channel
 * in multiple pkts of pkt_payload size. Each
 * packet is tagged with an unique packet ID in
 * the case of a reliable link.
 *
 * On return, size contains the number of bytes written.
 */
int
ldc_write(ldc_handle_t handle, caddr_t buf, size_t *sizep)
{
	ldc_chan_t	*ldcp;
	int		rv = 0;

	if (handle == 0) {
		DWARN(DBG_ALL_LDCS, "ldc_write: invalid channel handle\n");
		return (EINVAL);
	}
	ldcp = (ldc_chan_t *)handle;

	mutex_enter(&ldcp->tx_lock);

	/* check if non-zero data to write */
	if (buf == NULL || sizep == NULL) {
		DWARN(ldcp->id, "ldc_write: (0x%llx) invalid data write\n",
		    ldcp->id);
		mutex_exit(&ldcp->tx_lock);
		return (EINVAL);
	}

	if (*sizep == 0) {
		DWARN(ldcp->id, "ldc_write: (0x%llx) write size of zero\n",
		    ldcp->id);
		mutex_exit(&ldcp->tx_lock);
		return (0);
	}

	/* Check if channel is UP for data exchange */
	if (ldcp->tstate != TS_UP) {
		DWARN(ldcp->id,
		    "ldc_write: (0x%llx) channel is not in UP state\n",
		    ldcp->id);
		*sizep = 0;
		rv = ECONNRESET;
	} else {
		rv = ldcp->write_p(ldcp, buf, sizep);
	}

	mutex_exit(&ldcp->tx_lock);

	return (rv);
}

/*
 * Write a raw packet to the channel
 * On return, size contains the number of bytes written.
 */
static int
i_ldc_write_raw(ldc_chan_t *ldcp, caddr_t buf, size_t *sizep)
{
	ldc_msg_t	*ldcmsg;
	uint64_t	tx_head, tx_tail, new_tail;
	int		rv = 0;
	size_t		size;

	ASSERT(MUTEX_HELD(&ldcp->tx_lock));
	ASSERT(ldcp->mode == LDC_MODE_RAW);

	size = *sizep;

	/*
	 * Check to see if the packet size is less than or
	 * equal to packet size support in raw mode
	 */
	if (size > ldcp->pkt_payload) {
		DWARN(ldcp->id,
		    "ldc_write: (0x%llx) invalid size (0x%llx) for RAW mode\n",
		    ldcp->id, *sizep);
		*sizep = 0;
		return (EMSGSIZE);
	}

	/* get the qptrs for the tx queue */
	rv = hv_ldc_tx_get_state(ldcp->id,
	    &ldcp->tx_head, &ldcp->tx_tail, &ldcp->link_state);
	if (rv != 0) {
		cmn_err(CE_WARN,
		    "ldc_write: (0x%lx) cannot read queue ptrs\n", ldcp->id);
		*sizep = 0;
		return (EIO);
	}

	if (ldcp->link_state == LDC_CHANNEL_DOWN ||
	    ldcp->link_state == LDC_CHANNEL_RESET) {
		DWARN(ldcp->id,
		    "ldc_write: (0x%llx) channel down/reset\n", ldcp->id);

		*sizep = 0;
		if (mutex_tryenter(&ldcp->lock)) {
			i_ldc_reset(ldcp, B_FALSE);
			mutex_exit(&ldcp->lock);
		} else {
			/*
			 * Release Tx lock, and then reacquire channel
			 * and Tx lock in correct order
			 */
			mutex_exit(&ldcp->tx_lock);
			mutex_enter(&ldcp->lock);
			mutex_enter(&ldcp->tx_lock);
			i_ldc_reset(ldcp, B_FALSE);
			mutex_exit(&ldcp->lock);
		}
		return (ECONNRESET);
	}

	tx_tail = ldcp->tx_tail;
	tx_head = ldcp->tx_head;
	new_tail = (tx_tail + LDC_PACKET_SIZE) &
	    ((ldcp->tx_q_entries-1) << LDC_PACKET_SHIFT);

	if (new_tail == tx_head) {
		DWARN(DBG_ALL_LDCS,
		    "ldc_write: (0x%llx) TX queue is full\n", ldcp->id);
		*sizep = 0;
		return (EWOULDBLOCK);
	}

	D2(ldcp->id, "ldc_write: (0x%llx) start xfer size=%d",
	    ldcp->id, size);

	/* Send the data now */
	ldcmsg = (ldc_msg_t *)(ldcp->tx_q_va + tx_tail);

	/* copy the data into pkt */
	bcopy((uint8_t *)buf, ldcmsg, size);

	/* increment tail */
	tx_tail = new_tail;

	/*
	 * All packets have been copied into the TX queue
	 * update the tail ptr in the HV
	 */
	rv = i_ldc_set_tx_tail(ldcp, tx_tail);
	if (rv) {
		if (rv == EWOULDBLOCK) {
			DWARN(ldcp->id, "ldc_write: (0x%llx) write timed out\n",
			    ldcp->id);
			*sizep = 0;
			return (EWOULDBLOCK);
		}

		*sizep = 0;
		if (mutex_tryenter(&ldcp->lock)) {
			i_ldc_reset(ldcp, B_FALSE);
			mutex_exit(&ldcp->lock);
		} else {
			/*
			 * Release Tx lock, and then reacquire channel
			 * and Tx lock in correct order
			 */
			mutex_exit(&ldcp->tx_lock);
			mutex_enter(&ldcp->lock);
			mutex_enter(&ldcp->tx_lock);
			i_ldc_reset(ldcp, B_FALSE);
			mutex_exit(&ldcp->lock);
		}
		return (ECONNRESET);
	}

	ldcp->tx_tail = tx_tail;
	*sizep = size;

	D2(ldcp->id, "ldc_write: (0x%llx) end xfer size=%d", ldcp->id, size);

	return (rv);
}


/*
 * Write specified amount of bytes to the channel
 * in multiple pkts of pkt_payload size. Each
 * packet is tagged with an unique packet ID in
 * the case of a reliable link.
 *
 * On return, size contains the number of bytes written.
 * This function needs to ensure that the write size is < MTU size
 */
static int
i_ldc_write_packet(ldc_chan_t *ldcp, caddr_t buf, size_t *size)
{
	ldc_msg_t	*ldcmsg;
	uint64_t	tx_head, tx_tail, new_tail, start;
	uint64_t	txq_size_mask, numavail;
	uint8_t		*msgbuf, *source = (uint8_t *)buf;
	size_t		len, bytes_written = 0, remaining;
	int		rv;
	uint32_t	curr_seqid;

	ASSERT(MUTEX_HELD(&ldcp->tx_lock));

	ASSERT(ldcp->mode == LDC_MODE_RELIABLE ||
	    ldcp->mode == LDC_MODE_UNRELIABLE);

	/* compute mask for increment */
	txq_size_mask = (ldcp->tx_q_entries - 1) << LDC_PACKET_SHIFT;

	/* get the qptrs for the tx queue */
	rv = hv_ldc_tx_get_state(ldcp->id,
	    &ldcp->tx_head, &ldcp->tx_tail, &ldcp->link_state);
	if (rv != 0) {
		cmn_err(CE_WARN,
		    "ldc_write: (0x%lx) cannot read queue ptrs\n", ldcp->id);
		*size = 0;
		return (EIO);
	}

	if (ldcp->link_state == LDC_CHANNEL_DOWN ||
	    ldcp->link_state == LDC_CHANNEL_RESET) {
		DWARN(ldcp->id,
		    "ldc_write: (0x%llx) channel down/reset\n", ldcp->id);
		*size = 0;
		if (mutex_tryenter(&ldcp->lock)) {
			i_ldc_reset(ldcp, B_FALSE);
			mutex_exit(&ldcp->lock);
		} else {
			/*
			 * Release Tx lock, and then reacquire channel
			 * and Tx lock in correct order
			 */
			mutex_exit(&ldcp->tx_lock);
			mutex_enter(&ldcp->lock);
			mutex_enter(&ldcp->tx_lock);
			i_ldc_reset(ldcp, B_FALSE);
			mutex_exit(&ldcp->lock);
		}
		return (ECONNRESET);
	}

	tx_tail = ldcp->tx_tail;
	new_tail = (tx_tail + LDC_PACKET_SIZE) %
	    (ldcp->tx_q_entries << LDC_PACKET_SHIFT);

	/*
	 * Check to see if the queue is full. The check is done using
	 * the appropriate head based on the link mode.
	 */
	i_ldc_get_tx_head(ldcp, &tx_head);

	if (new_tail == tx_head) {
		DWARN(DBG_ALL_LDCS,
		    "ldc_write: (0x%llx) TX queue is full\n", ldcp->id);
		*size = 0;
		return (EWOULDBLOCK);
	}

	/*
	 * Make sure that the LDC Tx queue has enough space
	 */
	numavail = (tx_head >> LDC_PACKET_SHIFT) - (tx_tail >> LDC_PACKET_SHIFT)
	    + ldcp->tx_q_entries - 1;
	numavail %= ldcp->tx_q_entries;

	if (*size > (numavail * ldcp->pkt_payload)) {
		DWARN(DBG_ALL_LDCS,
		    "ldc_write: (0x%llx) TX queue has no space\n", ldcp->id);
		return (EWOULDBLOCK);
	}

	D2(ldcp->id, "ldc_write: (0x%llx) start xfer size=%d",
	    ldcp->id, *size);

	/* Send the data now */
	bytes_written = 0;
	curr_seqid = ldcp->last_msg_snt;
	start = tx_tail;

	while (*size > bytes_written) {

		ldcmsg = (ldc_msg_t *)(ldcp->tx_q_va + tx_tail);

		msgbuf = (uint8_t *)((ldcp->mode == LDC_MODE_RELIABLE) ?
		    ldcmsg->rdata : ldcmsg->udata);

		ldcmsg->type = LDC_DATA;
		ldcmsg->stype = LDC_INFO;
		ldcmsg->ctrl = 0;

		remaining = *size - bytes_written;
		len = min(ldcp->pkt_payload, remaining);
		ldcmsg->env = (uint8_t)len;

		curr_seqid++;
		ldcmsg->seqid = curr_seqid;

		/* copy the data into pkt */
		bcopy(source, msgbuf, len);

		source += len;
		bytes_written += len;

		/* increment tail */
		tx_tail = (tx_tail + LDC_PACKET_SIZE) & txq_size_mask;

		ASSERT(tx_tail != tx_head);
	}

	/* Set the start and stop bits */
	ldcmsg->env |= LDC_FRAG_STOP;
	ldcmsg = (ldc_msg_t *)(ldcp->tx_q_va + start);
	ldcmsg->env |= LDC_FRAG_START;

	/*
	 * All packets have been copied into the TX queue
	 * update the tail ptr in the HV
	 */
	rv = i_ldc_set_tx_tail(ldcp, tx_tail);
	if (rv == 0) {
		ldcp->tx_tail = tx_tail;
		ldcp->last_msg_snt = curr_seqid;
		*size = bytes_written;
	} else {
		int rv2;

		if (rv != EWOULDBLOCK) {
			*size = 0;
			if (mutex_tryenter(&ldcp->lock)) {
				i_ldc_reset(ldcp, B_FALSE);
				mutex_exit(&ldcp->lock);
			} else {
				/*
				 * Release Tx lock, and then reacquire channel
				 * and Tx lock in correct order
				 */
				mutex_exit(&ldcp->tx_lock);
				mutex_enter(&ldcp->lock);
				mutex_enter(&ldcp->tx_lock);
				i_ldc_reset(ldcp, B_FALSE);
				mutex_exit(&ldcp->lock);
			}
			return (ECONNRESET);
		}

		D1(ldcp->id, "hv_tx_set_tail returns 0x%x (head 0x%x, "
		    "old tail 0x%x, new tail 0x%x, qsize=0x%x)\n",
		    rv, ldcp->tx_head, ldcp->tx_tail, tx_tail,
		    (ldcp->tx_q_entries << LDC_PACKET_SHIFT));

		rv2 = hv_ldc_tx_get_state(ldcp->id,
		    &tx_head, &tx_tail, &ldcp->link_state);

		D1(ldcp->id, "hv_ldc_tx_get_state returns 0x%x "
		    "(head 0x%x, tail 0x%x state 0x%x)\n",
		    rv2, tx_head, tx_tail, ldcp->link_state);

		*size = 0;
	}

	D2(ldcp->id, "ldc_write: (0x%llx) end xfer size=%d", ldcp->id, *size);

	return (rv);
}

/*
 * Write specified amount of bytes to the channel
 * in multiple pkts of pkt_payload size. Each
 * packet is tagged with an unique packet ID in
 * the case of a reliable link.
 *
 * On return, size contains the number of bytes written.
 * This function needs to ensure that the write size is < MTU size
 */
static int
i_ldc_write_stream(ldc_chan_t *ldcp, caddr_t buf, size_t *sizep)
{
	ASSERT(MUTEX_HELD(&ldcp->tx_lock));
	ASSERT(ldcp->mode == LDC_MODE_RELIABLE);

	/* Truncate packet to max of MTU size */
	if (*sizep > ldcp->mtu) *sizep = ldcp->mtu;
	return (i_ldc_write_packet(ldcp, buf, sizep));
}


/*
 * Interfaces for channel nexus to register/unregister with LDC module
 * The nexus will register functions to be used to register individual
 * channels with the nexus and enable interrupts for the channels
 */
int
ldc_register(ldc_cnex_t *cinfo)
{
	ldc_chan_t	*ldcp;

	if (cinfo == NULL || cinfo->dip == NULL ||
	    cinfo->reg_chan == NULL || cinfo->unreg_chan == NULL ||
	    cinfo->add_intr == NULL || cinfo->rem_intr == NULL ||
	    cinfo->clr_intr == NULL) {

		DWARN(DBG_ALL_LDCS, "ldc_register: invalid nexus info\n");
		return (EINVAL);
	}

	mutex_enter(&ldcssp->lock);

	/* nexus registration */
	ldcssp->cinfo.dip = cinfo->dip;
	ldcssp->cinfo.reg_chan = cinfo->reg_chan;
	ldcssp->cinfo.unreg_chan = cinfo->unreg_chan;
	ldcssp->cinfo.add_intr = cinfo->add_intr;
	ldcssp->cinfo.rem_intr = cinfo->rem_intr;
	ldcssp->cinfo.clr_intr = cinfo->clr_intr;

	/* register any channels that might have been previously initialized */
	ldcp = ldcssp->chan_list;
	while (ldcp) {
		if ((ldcp->tstate & TS_QCONF_RDY) &&
		    (ldcp->tstate & TS_CNEX_RDY) == 0)
			(void) i_ldc_register_channel(ldcp);

		ldcp = ldcp->next;
	}

	mutex_exit(&ldcssp->lock);

	return (0);
}

int
ldc_unregister(ldc_cnex_t *cinfo)
{
	if (cinfo == NULL || cinfo->dip == NULL) {
		DWARN(DBG_ALL_LDCS, "ldc_unregister: invalid nexus info\n");
		return (EINVAL);
	}

	mutex_enter(&ldcssp->lock);

	if (cinfo->dip != ldcssp->cinfo.dip) {
		DWARN(DBG_ALL_LDCS, "ldc_unregister: invalid dip\n");
		mutex_exit(&ldcssp->lock);
		return (EINVAL);
	}

	/* nexus unregister */
	ldcssp->cinfo.dip = NULL;
	ldcssp->cinfo.reg_chan = NULL;
	ldcssp->cinfo.unreg_chan = NULL;
	ldcssp->cinfo.add_intr = NULL;
	ldcssp->cinfo.rem_intr = NULL;
	ldcssp->cinfo.clr_intr = NULL;

	mutex_exit(&ldcssp->lock);

	return (0);
}

int
ldc_info(ldc_handle_t handle, ldc_info_t *info)
{
	ldc_chan_t	*ldcp;
	uint64_t	avail;

	if (handle == 0 || info == NULL) {
		DWARN(DBG_ALL_LDCS, "ldc_get_info: invalid args\n");
		return (EINVAL);
	}

	ldcp = (ldc_chan_t *)handle;

	mutex_enter(&ldcp->lock);

	/* check to see if channel is initalized */
	if ((ldcp->tstate & ~TS_IN_RESET) < TS_INIT) {
		DWARN(ldcp->id,
		    "ldc_get_info: (0x%llx) channel not initialized\n",
		    ldcp->id);
		mutex_exit(&ldcp->lock);
		return (EINVAL);
	}

	mutex_exit(&ldcp->lock);

	/*
	 * ldcssp->mapin_size is the max amount of shared memory supported by
	 * the Hypervisor per guest. e.g, legacy HV supports 64MB; latest HV
	 * support 1GB. This size is read during ldc module initialization.
	 *
	 * ldc_dring_direct_map_rsvd is the amount of memory reserved for
	 * mapping in descriptor rings. In the initial implementation, we use a
	 * simple approach to determine the amount of mapin space available per
	 * channel. In future, we may implement strict accounting of the actual
	 * memory consumed to determine the exact amount available per channel.
	 */
	if (ldcssp->mapin_size <= ldc_dring_direct_map_rsvd) {
		info->direct_map_size_max = 0;
		return (0);
	}

	avail = ldcssp->mapin_size - ldc_dring_direct_map_rsvd;
	if (avail >= ldc_direct_map_size_max) {
		info->direct_map_size_max = ldc_direct_map_size_max;
	} else {
		info->direct_map_size_max = 0;
	}

	return (0);
}
