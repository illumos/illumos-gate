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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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
#include <sys/types.h>
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

/* Core internal functions */
static int i_ldc_h2v_error(int h_error);
static int i_ldc_txq_reconf(ldc_chan_t *ldcp);
static int i_ldc_rxq_reconf(ldc_chan_t *ldcp, boolean_t force_reset);
static int i_ldc_rxq_drain(ldc_chan_t *ldcp);
static void i_ldc_reset_state(ldc_chan_t *ldcp);
static void i_ldc_reset(ldc_chan_t *ldcp, boolean_t force_reset);

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

/* Memory synchronization internal functions */
static int i_ldc_mem_acquire_release(ldc_mem_handle_t mhandle,
    uint8_t direction, uint64_t offset, size_t size);
static int i_ldc_dring_acquire_release(ldc_dring_handle_t dhandle,
    uint8_t direction, uint64_t start, uint64_t end);

/* LDC Version */
static ldc_ver_t ldc_versions[] = { {1, 0} };

/* number of supported versions */
#define	LDC_NUM_VERS	(sizeof (ldc_versions) / sizeof (ldc_versions[0]))

/* Invalid value for the ldc_chan_t rx_ack_head field */
#define	ACKPEEK_HEAD_INVALID	((uint64_t)-1)


/* Module State Pointer */
static ldc_soft_state_t *ldcssp;

static struct modldrv md = {
	&mod_miscops,			/* This is a misc module */
	"sun4v LDC module v%I%",	/* Name of the module */
};

static struct modlinkage ml = {
	MODREV_1,
	&md,
	NULL
};

static uint64_t ldc_sup_minor;		/* Supported minor number */
static hsvc_info_t ldc_hsvc = {
	HSVC_REV_1, NULL, HSVC_GROUP_LDC, 1, 0, "ldc"
};

/*
 * LDC framework supports mapping remote domain's memory
 * either directly or via shadow memory pages. Default
 * support is currently implemented via shadow copy.
 * Direct map can be enabled by setting 'ldc_shmem_enabled'
 */
int ldc_shmem_enabled = 0;

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
 * Pages exported for remote access over each channel is
 * maintained in a table registered with the Hypervisor.
 * The default number of entries in the table is set to
 * 'ldc_mtbl_entries'.
 */
uint64_t ldc_maptable_entries = LDC_MTBL_ENTRIES;

/*
 * LDC retry count and delay - when the HV returns EWOULDBLOCK
 * the operation is retried 'ldc_max_retries' times with a
 * wait of 'ldc_delay' usecs between each retry.
 */
int ldc_max_retries = LDC_MAX_RETRIES;
clock_t ldc_delay = LDC_DELAY;

/*
 * delay between each retry of channel unregistration in
 * ldc_close(), to wait for pending interrupts to complete.
 */
clock_t ldc_close_delay = LDC_CLOSE_DELAY;

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

#define	DBG_ALL_LDCS -1

int ldcdbg = 0x0;
int64_t ldcdbgchan = DBG_ALL_LDCS;
uint64_t ldc_inject_err_flag = 0;

static void
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

#define	LDC_ERR_RESET	0x1
#define	LDC_ERR_PKTLOSS	0x2
#define	LDC_ERR_DQFULL	0x4

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

#define	D1		\
if (ldcdbg & 0x01)	\
	ldcdebug

#define	D2		\
if (ldcdbg & 0x02)	\
	ldcdebug

#define	DWARN		\
if (ldcdbg & 0x04)	\
	ldcdebug

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
	} else { 							\
	    D2((c)->id, "%s: msg%d (/%x/%x/%x/,env=%x)", (s),		\
	    mid, msg->type, msg->stype, msg->ctrl, msg->env);		\
	} 								\
}

#define	LDC_INJECT_RESET(_ldcp)	ldc_inject_error(_ldcp, LDC_ERR_RESET)
#define	LDC_INJECT_PKTLOSS(_ldcp) ldc_inject_error(_ldcp, LDC_ERR_PKTLOSS)
#define	LDC_INJECT_DQFULL(_ldcp) ldc_inject_error(_ldcp, LDC_ERR_DQFULL)

#else

#define	DBG_ALL_LDCS -1

#define	D1
#define	D2
#define	DWARN

#define	DUMP_PAYLOAD(id, addr)
#define	DUMP_LDC_PKT(c, s, addr)

#define	LDC_INJECT_RESET(_ldcp)	(B_FALSE)
#define	LDC_INJECT_PKTLOSS(_ldcp) (B_FALSE)
#define	LDC_INJECT_DQFULL(_ldcp) (B_FALSE)

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

	/* allocate soft state structure */
	ldcssp = kmem_zalloc(sizeof (ldc_soft_state_t), KM_SLEEP);

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
	int 		rv, status;
	ldc_chan_t 	*tmp_ldcp, *ldcp;
	ldc_dring_t 	*tmp_dringp, *dringp;
	ldc_mem_info_t 	minfo;

	/* Unlink the driver module from the system */
	status = mod_remove(&ml);
	if (status) {
		DWARN(DBG_ALL_LDCS, "_fini: mod_remove failed\n");
		return (EIO);
	}

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
static int
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

	case 	H_ETOOMANY:
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
static int
i_ldc_rxq_drain(ldc_chan_t *ldcp)
{
	int rv;
	uint64_t rx_head, rx_tail;

	ASSERT(MUTEX_HELD(&ldcp->lock));
	rv = hv_ldc_rx_get_state(ldcp->id, &rx_head, &rx_tail,
	    &(ldcp->link_state));
	if (rv) {
		cmn_err(CE_WARN, "i_ldc_rxq_drain: (0x%lx) cannot get state",
		    ldcp->id);
		return (EIO);
	}

	/* flush contents by setting the head = tail */
	return (i_ldc_set_rx_head(ldcp, rx_tail));
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
static void
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
	int 	rv;
	int 	retries;

	ASSERT(MUTEX_HELD(&ldcp->lock));
	for (retries = 0; retries < ldc_max_retries; retries++) {

		if ((rv = hv_ldc_rx_set_qhead(ldcp->id, head)) == 0)
			return (0);

		if (rv != H_EWOULDBLOCK)
			break;

		/* wait for ldc_delay usecs */
		drv_usecwait(ldc_delay);
	}

	cmn_err(CE_WARN, "ldc_rx_set_qhead: (0x%lx) cannot set qhead 0x%lx",
	    ldcp->id, head);
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
	ldc_msg_t 	*pkt;

	ASSERT(MUTEX_HELD(&ldcp->tx_lock));

	/* get current Tx head */
	*head = ldcp->tx_head;

	/*
	 * Reliable mode will use the ACKd head instead of the regular tx_head.
	 * Also in Reliable mode, advance ackd_head for all non DATA/INFO pkts,
	 * up to the current location of tx_head. This needs to be done
	 * as the peer will only ACK DATA/INFO pkts.
	 */
	if (ldcp->mode == LDC_MODE_RELIABLE || ldcp->mode == LDC_MODE_STREAM) {
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
	int 		rv;
	uint64_t 	current_head, new_tail;

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
	int 		retries;

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
	int		rv;

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

	(void) i_ldc_rx_process_hvq(ldcp, &notify, &event);

	if (ldcp->mode != LDC_MODE_STREAM) {
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

	if (ldcp->mode == LDC_MODE_STREAM) {
		/*
		 * If we are using a secondary data queue, clear the
		 * interrupt. We should have processed all CTRL packets
		 * and copied all DATA packets to the secondary queue.
		 * Even if secondary queue filled up, clear the interrupts,
		 * this will trigger another interrupt and force the
		 * handler to copy more data.
		 */
		i_ldc_clear_intr(ldcp, CNEX_RX_INTR);
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
	ldc_msg_t 	*pkt;
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
	int 		rv = 0, idx = ldcp->next_vidx;
	ldc_msg_t 	*pkt;
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
	int 		rv = 0;
	ldc_msg_t 	*pkt;
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
	int 		rv = 0;
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
	uint64_t 	tx_head;
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
	int 		rv = 0;

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

	int 		rv;
	ldc_chan_t 	*ldcp;
	boolean_t 	notify_client = B_FALSE;
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
 * STEAMING MODE
 * For streaming mode channels, all packets on the receive queue
 * are processed: data packets are copied to the data queue and
 * control packets are processed inline. Packets are only left on
 * the receive queue when the data queue is full.
 */
static uint_t
i_ldc_rx_process_hvq(ldc_chan_t *ldcp, boolean_t *notify_client,
    uint64_t *notify_event)
{
	int		rv;
	uint64_t 	rx_head, rx_tail;
	ldc_msg_t 	*msg;
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

				/* process only STREAM mode data packets */
				if (ldcp->mode != LDC_MODE_STREAM) {
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
			ASSERT(ldcp->mode == LDC_MODE_STREAM);

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

	if (ldcp->mode == LDC_MODE_STREAM) {
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
 * This function is only used by STREAMING mode channels when the
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
	ldc_chan_t 	*ldcp;
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
		ldcp->read_p = i_ldc_read_packet;
		ldcp->write_p = i_ldc_write_packet;
		break;
	case LDC_MODE_STREAM:
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
	if (ldcp->tx_q_va == NULL) {
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
	if (ldcp->rx_q_va == NULL) {
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
	if (ldcp->mode == LDC_MODE_STREAM) {
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
		if (ldcp->rx_dq_va == NULL) {
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

	if (ldcp->mode == LDC_MODE_STREAM && ldcp->stream_bufferp)
		kmem_free(ldcp->stream_bufferp, ldcp->mtu);

	if (ldcp->tstate & TS_TXQ_RDY)
		contig_mem_free((caddr_t)ldcp->tx_q_va,
		    (ldcp->tx_q_entries << LDC_PACKET_SHIFT));

	if (ldcp->tstate & TS_RXQ_RDY)
		contig_mem_free((caddr_t)ldcp->rx_q_va,
		    (ldcp->rx_q_entries << LDC_PACKET_SHIFT));

	mutex_destroy(&ldcp->tx_lock);
	mutex_destroy(&ldcp->lock);

	if (ldcp)
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
	ldc_chan_t 	*ldcp;
	ldc_chan_t 	*tmp_ldcp;
	uint64_t 	id;

	if (handle == NULL) {
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
		(void) hv_ldc_set_map_table(ldcp->id, NULL, NULL);
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

	/* Free the stream buffer for STREAM_MODE */
	if (ldcp->mode == LDC_MODE_STREAM && ldcp->stream_bufferp)
		kmem_free(ldcp->stream_bufferp, ldcp->mtu);

	/* Free the RX queue */
	contig_mem_free((caddr_t)ldcp->rx_q_va,
	    (ldcp->rx_q_entries << LDC_PACKET_SHIFT));
	ldcp->tstate &= ~TS_RXQ_RDY;

	/* Free the RX data queue */
	if (ldcp->mode == LDC_MODE_STREAM) {
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
	ldc_chan_t 	*ldcp;
	int 		rv;

	if (handle == NULL) {
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
	rv = hv_ldc_tx_qconf(ldcp->id, NULL, NULL);
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
	rv = hv_ldc_rx_qconf(ldcp->id, NULL, NULL);
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
		(void) hv_ldc_tx_qconf(ldcp->id, NULL, NULL);
		(void) hv_ldc_rx_qconf(ldcp->id, NULL, NULL);
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
		(void) hv_ldc_tx_qconf(ldcp->id, NULL, NULL);
		(void) hv_ldc_rx_qconf(ldcp->id, NULL, NULL);
		mutex_exit(&ldcp->lock);
		return (EIO);
	}

	/*
	 * set the ACKd head to current head location for reliable &
	 * streaming mode
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
	ldc_chan_t 	*ldcp;
	int		rv = 0, retries = 0;
	boolean_t	chk_done = B_FALSE;

	if (handle == NULL) {
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
	(void) i_ldc_rxq_drain(ldcp);

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

	/*
	 * Unregister queues
	 */
	rv = hv_ldc_tx_qconf(ldcp->id, NULL, NULL);
	if (rv) {
		cmn_err(CE_WARN,
		    "ldc_close: (0x%lx) channel TX queue unconf failed\n",
		    ldcp->id);
		mutex_exit(&ldcp->tx_lock);
		mutex_exit(&ldcp->lock);
		return (EIO);
	}
	rv = hv_ldc_rx_qconf(ldcp->id, NULL, NULL);
	if (rv) {
		cmn_err(CE_WARN,
		    "ldc_close: (0x%lx) channel RX queue unconf failed\n",
		    ldcp->id);
		mutex_exit(&ldcp->tx_lock);
		mutex_exit(&ldcp->lock);
		return (EIO);
	}

	ldcp->tstate &= ~TS_QCONF_RDY;

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

	if (handle == NULL) {
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

	if (handle == NULL) {
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
	int 		rv;
	ldc_chan_t 	*ldcp;
	ldc_msg_t 	*ldcmsg;
	uint64_t 	tx_tail, tstate, link_state;

	if (handle == NULL) {
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
	ldc_chan_t 	*ldcp;

	if (handle == NULL) {
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

	if (handle == NULL || status == NULL) {
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
	ldc_chan_t 	*ldcp;

	if (handle == NULL) {
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
	int 		rv;
	uint64_t 	rx_head, rx_tail;
	ldc_chan_t 	*ldcp;

	if (handle == NULL) {
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
		if (rx_head != rx_tail)
			*hasdata = (i_ldc_chkq(ldcp) == 0);
		break;

	case LDC_MODE_STREAM:
		/*
		 * In stream mode, first check for 'stream_remains' > 0.
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
	ldc_chan_t 	*ldcp;
	uint64_t 	rx_head = 0, rx_tail = 0;
	int		rv = 0, exit_val;

	if (handle == NULL) {
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
	} else if (ldcp->mode == LDC_MODE_STREAM) {
		TRACE_RXDQ_LENGTH(ldcp);
		exit_val = ldcp->read_p(ldcp, bufp, sizep);
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
	uint64_t 	q_size_mask;
	ldc_msg_t 	*msgp;
	uint8_t		*msgbufp;
	int		rv = 0, space;
	uint64_t 	rx_head, rx_tail;

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
	uint64_t 	rx_head = 0, rx_tail = 0;
	uint64_t 	curr_head = 0;
	ldc_msg_t 	*msg;
	caddr_t 	target;
	size_t 		len = 0, bytes_read = 0;
	int 		retries = 0;
	uint64_t 	q_va, q_size_mask;
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
	if (ldcp->mode == LDC_MODE_STREAM) {
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
			if (ldcp->mode == LDC_MODE_STREAM)
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
					if (ldcp->mode != LDC_MODE_STREAM)
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
		if (ldcp->mode != LDC_MODE_STREAM) {
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
			    (ldcp->mode == LDC_MODE_RELIABLE ||
			    ldcp->mode == LDC_MODE_STREAM) ?
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
		if (ldcp->mode != LDC_MODE_STREAM)
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
 * Use underlying reliable packet mechanism to fetch
 * and buffer incoming packets so we can hand them back as
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

	if (handle == NULL) {
		DWARN(DBG_ALL_LDCS, "ldc_write: invalid channel handle\n");
		return (EINVAL);
	}
	ldcp = (ldc_chan_t *)handle;

	/* check if writes can occur */
	if (!mutex_tryenter(&ldcp->tx_lock)) {
		/*
		 * Could not get the lock - channel could
		 * be in the process of being unconfigured
		 * or reader has encountered an error
		 */
		return (EAGAIN);
	}

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
	ldc_msg_t 	*ldcmsg;
	uint64_t 	tx_head, tx_tail, new_tail;
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
	ldc_msg_t 	*ldcmsg;
	uint64_t 	tx_head, tx_tail, new_tail, start;
	uint64_t	txq_size_mask, numavail;
	uint8_t 	*msgbuf, *source = (uint8_t *)buf;
	size_t 		len, bytes_written = 0, remaining;
	int		rv;
	uint32_t	curr_seqid;

	ASSERT(MUTEX_HELD(&ldcp->tx_lock));

	ASSERT(ldcp->mode == LDC_MODE_RELIABLE ||
	    ldcp->mode == LDC_MODE_UNRELIABLE ||
	    ldcp->mode == LDC_MODE_STREAM);

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

		msgbuf = (uint8_t *)((ldcp->mode == LDC_MODE_RELIABLE ||
		    ldcp->mode == LDC_MODE_STREAM) ?
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
	ASSERT(ldcp->mode == LDC_MODE_STREAM);

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


/* ------------------------------------------------------------------------- */

/*
 * Allocate a memory handle for the channel and link it into the list
 * Also choose which memory table to use if this is the first handle
 * being assigned to this channel
 */
int
ldc_mem_alloc_handle(ldc_handle_t handle, ldc_mem_handle_t *mhandle)
{
	ldc_chan_t 	*ldcp;
	ldc_mhdl_t	*mhdl;

	if (handle == NULL) {
		DWARN(DBG_ALL_LDCS,
		    "ldc_mem_alloc_handle: invalid channel handle\n");
		return (EINVAL);
	}
	ldcp = (ldc_chan_t *)handle;

	mutex_enter(&ldcp->lock);

	/* check to see if channel is initalized */
	if ((ldcp->tstate & ~TS_IN_RESET) < TS_INIT) {
		DWARN(ldcp->id,
		    "ldc_mem_alloc_handle: (0x%llx) channel not initialized\n",
		    ldcp->id);
		mutex_exit(&ldcp->lock);
		return (EINVAL);
	}

	/* allocate handle for channel */
	mhdl = kmem_cache_alloc(ldcssp->memhdl_cache, KM_SLEEP);

	/* initialize the lock */
	mutex_init(&mhdl->lock, NULL, MUTEX_DRIVER, NULL);

	mhdl->myshadow = B_FALSE;
	mhdl->memseg = NULL;
	mhdl->ldcp = ldcp;
	mhdl->status = LDC_UNBOUND;

	/* insert memory handle (@ head) into list */
	if (ldcp->mhdl_list == NULL) {
		ldcp->mhdl_list = mhdl;
		mhdl->next = NULL;
	} else {
		/* insert @ head */
		mhdl->next = ldcp->mhdl_list;
		ldcp->mhdl_list = mhdl;
	}

	/* return the handle */
	*mhandle = (ldc_mem_handle_t)mhdl;

	mutex_exit(&ldcp->lock);

	D1(ldcp->id, "ldc_mem_alloc_handle: (0x%llx) allocated handle 0x%llx\n",
	    ldcp->id, mhdl);

	return (0);
}

/*
 * Free memory handle for the channel and unlink it from the list
 */
int
ldc_mem_free_handle(ldc_mem_handle_t mhandle)
{
	ldc_mhdl_t 	*mhdl, *phdl;
	ldc_chan_t 	*ldcp;

	if (mhandle == NULL) {
		DWARN(DBG_ALL_LDCS,
		    "ldc_mem_free_handle: invalid memory handle\n");
		return (EINVAL);
	}
	mhdl = (ldc_mhdl_t *)mhandle;

	mutex_enter(&mhdl->lock);

	ldcp = mhdl->ldcp;

	if (mhdl->status == LDC_BOUND || mhdl->status == LDC_MAPPED) {
		DWARN(ldcp->id,
		    "ldc_mem_free_handle: cannot free, 0x%llx hdl bound\n",
		    mhdl);
		mutex_exit(&mhdl->lock);
		return (EINVAL);
	}
	mutex_exit(&mhdl->lock);

	mutex_enter(&ldcp->mlist_lock);

	phdl = ldcp->mhdl_list;

	/* first handle */
	if (phdl == mhdl) {
		ldcp->mhdl_list = mhdl->next;
		mutex_destroy(&mhdl->lock);
		kmem_cache_free(ldcssp->memhdl_cache, mhdl);

		D1(ldcp->id,
		    "ldc_mem_free_handle: (0x%llx) freed handle 0x%llx\n",
		    ldcp->id, mhdl);
	} else {
		/* walk the list - unlink and free */
		while (phdl != NULL) {
			if (phdl->next == mhdl) {
				phdl->next = mhdl->next;
				mutex_destroy(&mhdl->lock);
				kmem_cache_free(ldcssp->memhdl_cache, mhdl);
				D1(ldcp->id,
				    "ldc_mem_free_handle: (0x%llx) freed "
				    "handle 0x%llx\n", ldcp->id, mhdl);
				break;
			}
			phdl = phdl->next;
		}
	}

	if (phdl == NULL) {
		DWARN(ldcp->id,
		    "ldc_mem_free_handle: invalid handle 0x%llx\n", mhdl);
		mutex_exit(&ldcp->mlist_lock);
		return (EINVAL);
	}

	mutex_exit(&ldcp->mlist_lock);

	return (0);
}

/*
 * Bind a memory handle to a virtual address.
 * The virtual address is converted to the corresponding real addresses.
 * Returns pointer to the first ldc_mem_cookie and the total number
 * of cookies for this virtual address. Other cookies can be obtained
 * using the ldc_mem_nextcookie() call. If the pages are stored in
 * consecutive locations in the table, a single cookie corresponding to
 * the first location is returned. The cookie size spans all the entries.
 *
 * If the VA corresponds to a page that is already being exported, reuse
 * the page and do not export it again. Bump the page's use count.
 */
int
ldc_mem_bind_handle(ldc_mem_handle_t mhandle, caddr_t vaddr, size_t len,
    uint8_t mtype, uint8_t perm, ldc_mem_cookie_t *cookie, uint32_t *ccount)
{
	ldc_mhdl_t	*mhdl;
	ldc_chan_t 	*ldcp;
	ldc_mtbl_t	*mtbl;
	ldc_memseg_t	*memseg;
	ldc_mte_t	tmp_mte;
	uint64_t	index, prev_index = 0;
	int64_t		cookie_idx;
	uintptr_t	raddr, ra_aligned;
	uint64_t	psize, poffset, v_offset;
	uint64_t	pg_shift, pg_size, pg_size_code, pg_mask;
	pgcnt_t		npages;
	caddr_t		v_align, addr;
	int 		i, rv;

	if (mhandle == NULL) {
		DWARN(DBG_ALL_LDCS,
		    "ldc_mem_bind_handle: invalid memory handle\n");
		return (EINVAL);
	}
	mhdl = (ldc_mhdl_t *)mhandle;
	ldcp = mhdl->ldcp;

	/* clear count */
	*ccount = 0;

	mutex_enter(&mhdl->lock);

	if (mhdl->status == LDC_BOUND || mhdl->memseg != NULL) {
		DWARN(ldcp->id,
		    "ldc_mem_bind_handle: (0x%x) handle already bound\n",
		    mhandle);
		mutex_exit(&mhdl->lock);
		return (EINVAL);
	}

	/* Force address and size to be 8-byte aligned */
	if ((((uintptr_t)vaddr | len) & 0x7) != 0) {
		DWARN(ldcp->id,
		    "ldc_mem_bind_handle: addr/size is not 8-byte aligned\n");
		mutex_exit(&mhdl->lock);
		return (EINVAL);
	}

	/*
	 * If this channel is binding a memory handle for the
	 * first time allocate it a memory map table and initialize it
	 */
	if ((mtbl = ldcp->mtbl) == NULL) {

		mutex_enter(&ldcp->lock);

		/* Allocate and initialize the map table structure */
		mtbl = kmem_zalloc(sizeof (ldc_mtbl_t), KM_SLEEP);
		mtbl->num_entries = mtbl->num_avail = ldc_maptable_entries;
		mtbl->size = ldc_maptable_entries * sizeof (ldc_mte_slot_t);
		mtbl->next_entry = NULL;
		mtbl->contigmem = B_TRUE;

		/* Allocate the table itself */
		mtbl->table = (ldc_mte_slot_t *)
		    contig_mem_alloc_align(mtbl->size, MMU_PAGESIZE);
		if (mtbl->table == NULL) {

			/* allocate a page of memory using kmem_alloc */
			mtbl->table = kmem_alloc(MMU_PAGESIZE, KM_SLEEP);
			mtbl->size = MMU_PAGESIZE;
			mtbl->contigmem = B_FALSE;
			mtbl->num_entries = mtbl->num_avail =
			    mtbl->size / sizeof (ldc_mte_slot_t);
			DWARN(ldcp->id,
			    "ldc_mem_bind_handle: (0x%llx) reduced tbl size "
			    "to %lx entries\n", ldcp->id, mtbl->num_entries);
		}

		/* zero out the memory */
		bzero(mtbl->table, mtbl->size);

		/* initialize the lock */
		mutex_init(&mtbl->lock, NULL, MUTEX_DRIVER, NULL);

		/* register table for this channel */
		rv = hv_ldc_set_map_table(ldcp->id,
		    va_to_pa(mtbl->table), mtbl->num_entries);
		if (rv != 0) {
			cmn_err(CE_WARN,
			    "ldc_mem_bind_handle: (0x%lx) err %d mapping tbl",
			    ldcp->id, rv);
			if (mtbl->contigmem)
				contig_mem_free(mtbl->table, mtbl->size);
			else
				kmem_free(mtbl->table, mtbl->size);
			mutex_destroy(&mtbl->lock);
			kmem_free(mtbl, sizeof (ldc_mtbl_t));
			mutex_exit(&ldcp->lock);
			mutex_exit(&mhdl->lock);
			return (EIO);
		}

		ldcp->mtbl = mtbl;
		mutex_exit(&ldcp->lock);

		D1(ldcp->id,
		    "ldc_mem_bind_handle: (0x%llx) alloc'd map table 0x%llx\n",
		    ldcp->id, ldcp->mtbl->table);
	}

	/* FUTURE: get the page size, pgsz code, and shift */
	pg_size = MMU_PAGESIZE;
	pg_size_code = page_szc(pg_size);
	pg_shift = page_get_shift(pg_size_code);
	pg_mask = ~(pg_size - 1);

	D1(ldcp->id, "ldc_mem_bind_handle: (0x%llx) binding "
	    "va 0x%llx pgsz=0x%llx, pgszc=0x%llx, pg_shift=0x%llx\n",
	    ldcp->id, vaddr, pg_size, pg_size_code, pg_shift);

	/* aligned VA and its offset */
	v_align = (caddr_t)(((uintptr_t)vaddr) & ~(pg_size - 1));
	v_offset = ((uintptr_t)vaddr) & (pg_size - 1);

	npages = (len+v_offset)/pg_size;
	npages = ((len+v_offset)%pg_size == 0) ? npages : npages+1;

	D1(ldcp->id, "ldc_mem_bind_handle: binding "
	    "(0x%llx) v=0x%llx,val=0x%llx,off=0x%x,pgs=0x%x\n",
	    ldcp->id, vaddr, v_align, v_offset, npages);

	/* lock the memory table - exclusive access to channel */
	mutex_enter(&mtbl->lock);

	if (npages > mtbl->num_avail) {
		D1(ldcp->id, "ldc_mem_bind_handle: (0x%llx) no table entries\n",
		    ldcp->id);
		mutex_exit(&mtbl->lock);
		mutex_exit(&mhdl->lock);
		return (ENOMEM);
	}

	/* Allocate a memseg structure */
	memseg = mhdl->memseg =
	    kmem_cache_alloc(ldcssp->memseg_cache, KM_SLEEP);

	/* Allocate memory to store all pages and cookies */
	memseg->pages = kmem_zalloc((sizeof (ldc_page_t) * npages), KM_SLEEP);
	memseg->cookies =
	    kmem_zalloc((sizeof (ldc_mem_cookie_t) * npages), KM_SLEEP);

	D2(ldcp->id, "ldc_mem_bind_handle: (0x%llx) processing 0x%llx pages\n",
	    ldcp->id, npages);

	addr = v_align;

	/*
	 * Check if direct shared memory map is enabled, if not change
	 * the mapping type to include SHADOW_MAP.
	 */
	if (ldc_shmem_enabled == 0)
		mtype = LDC_SHADOW_MAP;

	/*
	 * Table slots are used in a round-robin manner. The algorithm permits
	 * inserting duplicate entries. Slots allocated earlier will typically
	 * get freed before we get back to reusing the slot.Inserting duplicate
	 * entries should be OK as we only lookup entries using the cookie addr
	 * i.e. tbl index, during export, unexport and copy operation.
	 *
	 * One implementation what was tried was to search for a duplicate
	 * page entry first and reuse it. The search overhead is very high and
	 * in the vnet case dropped the perf by almost half, 50 to 24 mbps.
	 * So it does make sense to avoid searching for duplicates.
	 *
	 * But during the process of searching for a free slot, if we find a
	 * duplicate entry we will go ahead and use it, and bump its use count.
	 */

	/* index to start searching from */
	index = mtbl->next_entry;
	cookie_idx = -1;

	tmp_mte.ll = 0;	/* initialise fields to 0 */

	if (mtype & LDC_DIRECT_MAP) {
		tmp_mte.mte_r = (perm & LDC_MEM_R) ? 1 : 0;
		tmp_mte.mte_w = (perm & LDC_MEM_W) ? 1 : 0;
		tmp_mte.mte_x = (perm & LDC_MEM_X) ? 1 : 0;
	}

	if (mtype & LDC_SHADOW_MAP) {
		tmp_mte.mte_cr = (perm & LDC_MEM_R) ? 1 : 0;
		tmp_mte.mte_cw = (perm & LDC_MEM_W) ? 1 : 0;
	}

	if (mtype & LDC_IO_MAP) {
		tmp_mte.mte_ir = (perm & LDC_MEM_R) ? 1 : 0;
		tmp_mte.mte_iw = (perm & LDC_MEM_W) ? 1 : 0;
	}

	D1(ldcp->id, "ldc_mem_bind_handle mte=0x%llx\n", tmp_mte.ll);

	tmp_mte.mte_pgszc = pg_size_code;

	/* initialize each mem table entry */
	for (i = 0; i < npages; i++) {

		/* check if slot is available in the table */
		while (mtbl->table[index].entry.ll != 0) {

			index = (index + 1) % mtbl->num_entries;

			if (index == mtbl->next_entry) {
				/* we have looped around */
				DWARN(DBG_ALL_LDCS,
				    "ldc_mem_bind_handle: (0x%llx) cannot find "
				    "entry\n", ldcp->id);
				*ccount = 0;

				/* NOTE: free memory, remove previous entries */
				/* this shouldnt happen as num_avail was ok */

				mutex_exit(&mtbl->lock);
				mutex_exit(&mhdl->lock);
				return (ENOMEM);
			}
		}

		/* get the real address */
		raddr = va_to_pa((void *)addr);
		ra_aligned = ((uintptr_t)raddr & pg_mask);

		/* build the mte */
		tmp_mte.mte_rpfn = ra_aligned >> pg_shift;

		D1(ldcp->id, "ldc_mem_bind_handle mte=0x%llx\n", tmp_mte.ll);

		/* update entry in table */
		mtbl->table[index].entry = tmp_mte;

		D2(ldcp->id, "ldc_mem_bind_handle: (0x%llx) stored MTE 0x%llx"
		    " into loc 0x%llx\n", ldcp->id, tmp_mte.ll, index);

		/* calculate the size and offset for this export range */
		if (i == 0) {
			/* first page */
			psize = min((pg_size - v_offset), len);
			poffset = v_offset;

		} else if (i == (npages - 1)) {
			/* last page */
			psize =	(((uintptr_t)(vaddr + len)) &
			    ((uint64_t)(pg_size-1)));
			if (psize == 0)
				psize = pg_size;
			poffset = 0;

		} else {
			/* middle pages */
			psize = pg_size;
			poffset = 0;
		}

		/* store entry for this page */
		memseg->pages[i].index = index;
		memseg->pages[i].raddr = raddr;
		memseg->pages[i].offset = poffset;
		memseg->pages[i].size = psize;
		memseg->pages[i].mte = &(mtbl->table[index]);

		/* create the cookie */
		if (i == 0 || (index != prev_index + 1)) {
			cookie_idx++;
			memseg->cookies[cookie_idx].addr =
			    IDX2COOKIE(index, pg_size_code, pg_shift);
			memseg->cookies[cookie_idx].addr |= poffset;
			memseg->cookies[cookie_idx].size = psize;

		} else {
			memseg->cookies[cookie_idx].size += psize;
		}

		D1(ldcp->id, "ldc_mem_bind_handle: bound "
		    "(0x%llx) va=0x%llx, idx=0x%llx, "
		    "ra=0x%llx(sz=0x%x,off=0x%x)\n",
		    ldcp->id, addr, index, raddr, psize, poffset);

		/* decrement number of available entries */
		mtbl->num_avail--;

		/* increment va by page size */
		addr += pg_size;

		/* increment index */
		prev_index = index;
		index = (index + 1) % mtbl->num_entries;

		/* save the next slot */
		mtbl->next_entry = index;
	}

	mutex_exit(&mtbl->lock);

	/* memory handle = bound */
	mhdl->mtype = mtype;
	mhdl->perm = perm;
	mhdl->status = LDC_BOUND;

	/* update memseg_t */
	memseg->vaddr = vaddr;
	memseg->raddr = memseg->pages[0].raddr;
	memseg->size = len;
	memseg->npages = npages;
	memseg->ncookies = cookie_idx + 1;
	memseg->next_cookie = (memseg->ncookies > 1) ? 1 : 0;

	/* return count and first cookie */
	*ccount = memseg->ncookies;
	cookie->addr = memseg->cookies[0].addr;
	cookie->size = memseg->cookies[0].size;

	D1(ldcp->id,
	    "ldc_mem_bind_handle: (0x%llx) bound 0x%llx, va=0x%llx, "
	    "pgs=0x%llx cookies=0x%llx\n",
	    ldcp->id, mhdl, vaddr, npages, memseg->ncookies);

	mutex_exit(&mhdl->lock);
	return (0);
}

/*
 * Return the next cookie associated with the specified memory handle
 */
int
ldc_mem_nextcookie(ldc_mem_handle_t mhandle, ldc_mem_cookie_t *cookie)
{
	ldc_mhdl_t	*mhdl;
	ldc_chan_t 	*ldcp;
	ldc_memseg_t	*memseg;

	if (mhandle == NULL) {
		DWARN(DBG_ALL_LDCS,
		    "ldc_mem_nextcookie: invalid memory handle\n");
		return (EINVAL);
	}
	mhdl = (ldc_mhdl_t *)mhandle;

	mutex_enter(&mhdl->lock);

	ldcp = mhdl->ldcp;
	memseg = mhdl->memseg;

	if (cookie == 0) {
		DWARN(ldcp->id,
		    "ldc_mem_nextcookie:(0x%llx) invalid cookie arg\n",
		    ldcp->id);
		mutex_exit(&mhdl->lock);
		return (EINVAL);
	}

	if (memseg->next_cookie != 0) {
		cookie->addr = memseg->cookies[memseg->next_cookie].addr;
		cookie->size = memseg->cookies[memseg->next_cookie].size;
		memseg->next_cookie++;
		if (memseg->next_cookie == memseg->ncookies)
			memseg->next_cookie = 0;

	} else {
		DWARN(ldcp->id,
		    "ldc_mem_nextcookie:(0x%llx) no more cookies\n", ldcp->id);
		cookie->addr = 0;
		cookie->size = 0;
		mutex_exit(&mhdl->lock);
		return (EINVAL);
	}

	D1(ldcp->id,
	    "ldc_mem_nextcookie: (0x%llx) cookie addr=0x%llx,sz=0x%llx\n",
	    ldcp->id, cookie->addr, cookie->size);

	mutex_exit(&mhdl->lock);
	return (0);
}

/*
 * Unbind the virtual memory region associated with the specified
 * memory handle. Allassociated cookies are freed and the corresponding
 * RA space is no longer exported.
 */
int
ldc_mem_unbind_handle(ldc_mem_handle_t mhandle)
{
	ldc_mhdl_t	*mhdl;
	ldc_chan_t 	*ldcp;
	ldc_mtbl_t	*mtbl;
	ldc_memseg_t	*memseg;
	uint64_t	cookie_addr;
	uint64_t	pg_shift, pg_size_code;
	int		i, rv;

	if (mhandle == NULL) {
		DWARN(DBG_ALL_LDCS,
		    "ldc_mem_unbind_handle: invalid memory handle\n");
		return (EINVAL);
	}
	mhdl = (ldc_mhdl_t *)mhandle;

	mutex_enter(&mhdl->lock);

	if (mhdl->status == LDC_UNBOUND) {
		DWARN(DBG_ALL_LDCS,
		    "ldc_mem_unbind_handle: (0x%x) handle is not bound\n",
		    mhandle);
		mutex_exit(&mhdl->lock);
		return (EINVAL);
	}

	ldcp = mhdl->ldcp;
	mtbl = ldcp->mtbl;

	memseg = mhdl->memseg;

	/* lock the memory table - exclusive access to channel */
	mutex_enter(&mtbl->lock);

	/* undo the pages exported */
	for (i = 0; i < memseg->npages; i++) {

		/* check for mapped pages, revocation cookie != 0 */
		if (memseg->pages[i].mte->cookie) {

			pg_size_code = page_szc(memseg->pages[i].size);
			pg_shift = page_get_shift(memseg->pages[i].size);
			cookie_addr = IDX2COOKIE(memseg->pages[i].index,
			    pg_size_code, pg_shift);

			D1(ldcp->id, "ldc_mem_unbind_handle: (0x%llx) revoke "
			    "cookie 0x%llx, rcookie 0x%llx\n", ldcp->id,
			    cookie_addr, memseg->pages[i].mte->cookie);
			rv = hv_ldc_revoke(ldcp->id, cookie_addr,
			    memseg->pages[i].mte->cookie);
			if (rv) {
				DWARN(ldcp->id,
				    "ldc_mem_unbind_handle: (0x%llx) cannot "
				    "revoke mapping, cookie %llx\n", ldcp->id,
				    cookie_addr);
			}
		}

		/* clear the entry from the table */
		memseg->pages[i].mte->entry.ll = 0;
		mtbl->num_avail++;
	}
	mutex_exit(&mtbl->lock);

	/* free the allocated memseg and page structures */
	kmem_free(memseg->pages, (sizeof (ldc_page_t) * memseg->npages));
	kmem_free(memseg->cookies,
	    (sizeof (ldc_mem_cookie_t) * memseg->npages));
	kmem_cache_free(ldcssp->memseg_cache, memseg);

	/* uninitialize the memory handle */
	mhdl->memseg = NULL;
	mhdl->status = LDC_UNBOUND;

	D1(ldcp->id, "ldc_mem_unbind_handle: (0x%llx) unbound handle 0x%llx\n",
	    ldcp->id, mhdl);

	mutex_exit(&mhdl->lock);
	return (0);
}

/*
 * Get information about the dring. The base address of the descriptor
 * ring along with the type and permission are returned back.
 */
int
ldc_mem_info(ldc_mem_handle_t mhandle, ldc_mem_info_t *minfo)
{
	ldc_mhdl_t	*mhdl;

	if (mhandle == NULL) {
		DWARN(DBG_ALL_LDCS, "ldc_mem_info: invalid memory handle\n");
		return (EINVAL);
	}
	mhdl = (ldc_mhdl_t *)mhandle;

	if (minfo == NULL) {
		DWARN(DBG_ALL_LDCS, "ldc_mem_info: invalid args\n");
		return (EINVAL);
	}

	mutex_enter(&mhdl->lock);

	minfo->status = mhdl->status;
	if (mhdl->status == LDC_BOUND || mhdl->status == LDC_MAPPED) {
		minfo->vaddr = mhdl->memseg->vaddr;
		minfo->raddr = mhdl->memseg->raddr;
		minfo->mtype = mhdl->mtype;
		minfo->perm = mhdl->perm;
	}
	mutex_exit(&mhdl->lock);

	return (0);
}

/*
 * Copy data either from or to the client specified virtual address
 * space to or from the exported memory associated with the cookies.
 * The direction argument determines whether the data is read from or
 * written to exported memory.
 */
int
ldc_mem_copy(ldc_handle_t handle, caddr_t vaddr, uint64_t off, size_t *size,
    ldc_mem_cookie_t *cookies, uint32_t ccount, uint8_t direction)
{
	ldc_chan_t 	*ldcp;
	uint64_t	local_voff, local_valign;
	uint64_t	cookie_addr, cookie_size;
	uint64_t	pg_shift, pg_size, pg_size_code;
	uint64_t 	export_caddr, export_poff, export_psize, export_size;
	uint64_t	local_ra, local_poff, local_psize;
	uint64_t	copy_size, copied_len = 0, total_bal = 0, idx = 0;
	pgcnt_t		npages;
	size_t		len = *size;
	int 		i, rv = 0;

	uint64_t	chid;

	if (handle == NULL) {
		DWARN(DBG_ALL_LDCS, "ldc_mem_copy: invalid channel handle\n");
		return (EINVAL);
	}
	ldcp = (ldc_chan_t *)handle;
	chid = ldcp->id;

	/* check to see if channel is UP */
	if (ldcp->tstate != TS_UP) {
		DWARN(chid, "ldc_mem_copy: (0x%llx) channel is not UP\n",
		    chid);
		return (ECONNRESET);
	}

	/* Force address and size to be 8-byte aligned */
	if ((((uintptr_t)vaddr | len) & 0x7) != 0) {
		DWARN(chid,
		    "ldc_mem_copy: addr/sz is not 8-byte aligned\n");
		return (EINVAL);
	}

	/* Find the size of the exported memory */
	export_size = 0;
	for (i = 0; i < ccount; i++)
		export_size += cookies[i].size;

	/* check to see if offset is valid */
	if (off > export_size) {
		DWARN(chid,
		    "ldc_mem_copy: (0x%llx) start offset > export mem size\n",
		    chid);
		return (EINVAL);
	}

	/*
	 * Check to see if the export size is smaller than the size we
	 * are requesting to copy - if so flag an error
	 */
	if ((export_size - off) < *size) {
		DWARN(chid,
		    "ldc_mem_copy: (0x%llx) copy size > export mem size\n",
		    chid);
		return (EINVAL);
	}

	total_bal = min(export_size, *size);

	/* FUTURE: get the page size, pgsz code, and shift */
	pg_size = MMU_PAGESIZE;
	pg_size_code = page_szc(pg_size);
	pg_shift = page_get_shift(pg_size_code);

	D1(chid, "ldc_mem_copy: copying data "
	    "(0x%llx) va 0x%llx pgsz=0x%llx, pgszc=0x%llx, pg_shift=0x%llx\n",
	    chid, vaddr, pg_size, pg_size_code, pg_shift);

	/* aligned VA and its offset */
	local_valign = (((uintptr_t)vaddr) & ~(pg_size - 1));
	local_voff = ((uintptr_t)vaddr) & (pg_size - 1);

	npages = (len+local_voff)/pg_size;
	npages = ((len+local_voff)%pg_size == 0) ? npages : npages+1;

	D1(chid,
	    "ldc_mem_copy: (0x%llx) v=0x%llx,val=0x%llx,off=0x%x,pgs=0x%x\n",
	    chid, vaddr, local_valign, local_voff, npages);

	local_ra = va_to_pa((void *)local_valign);
	local_poff = local_voff;
	local_psize = min(len, (pg_size - local_voff));

	len -= local_psize;

	/*
	 * find the first cookie in the list of cookies
	 * if the offset passed in is not zero
	 */
	for (idx = 0; idx < ccount; idx++) {
		cookie_size = cookies[idx].size;
		if (off < cookie_size)
			break;
		off -= cookie_size;
	}

	cookie_addr = cookies[idx].addr + off;
	cookie_size = cookies[idx].size - off;

	export_caddr = cookie_addr & ~(pg_size - 1);
	export_poff = cookie_addr & (pg_size - 1);
	export_psize = min(cookie_size, (pg_size - export_poff));

	for (;;) {

		copy_size = min(export_psize, local_psize);

		D1(chid,
		    "ldc_mem_copy:(0x%llx) dir=0x%x, caddr=0x%llx,"
		    " loc_ra=0x%llx, exp_poff=0x%llx, loc_poff=0x%llx,"
		    " exp_psz=0x%llx, loc_psz=0x%llx, copy_sz=0x%llx,"
		    " total_bal=0x%llx\n",
		    chid, direction, export_caddr, local_ra, export_poff,
		    local_poff, export_psize, local_psize, copy_size,
		    total_bal);

		rv = hv_ldc_copy(chid, direction,
		    (export_caddr + export_poff), (local_ra + local_poff),
		    copy_size, &copied_len);

		if (rv != 0) {
			int 		error = EIO;
			uint64_t	rx_hd, rx_tl;

			DWARN(chid,
			    "ldc_mem_copy: (0x%llx) err %d during copy\n",
			    (unsigned long long)chid, rv);
			DWARN(chid,
			    "ldc_mem_copy: (0x%llx) dir=0x%x, caddr=0x%lx, "
			    "loc_ra=0x%lx, exp_poff=0x%lx, loc_poff=0x%lx,"
			    " exp_psz=0x%lx, loc_psz=0x%lx, copy_sz=0x%lx,"
			    " copied_len=0x%lx, total_bal=0x%lx\n",
			    chid, direction, export_caddr, local_ra,
			    export_poff, local_poff, export_psize, local_psize,
			    copy_size, copied_len, total_bal);

			*size = *size - total_bal;

			/*
			 * check if reason for copy error was due to
			 * a channel reset. we need to grab the lock
			 * just in case we have to do a reset.
			 */
			mutex_enter(&ldcp->lock);
			mutex_enter(&ldcp->tx_lock);

			rv = hv_ldc_rx_get_state(ldcp->id,
			    &rx_hd, &rx_tl, &(ldcp->link_state));
			if (ldcp->link_state == LDC_CHANNEL_DOWN ||
			    ldcp->link_state == LDC_CHANNEL_RESET) {
				i_ldc_reset(ldcp, B_FALSE);
				error = ECONNRESET;
			}

			mutex_exit(&ldcp->tx_lock);
			mutex_exit(&ldcp->lock);

			return (error);
		}

		ASSERT(copied_len <= copy_size);

		D2(chid, "ldc_mem_copy: copied=0x%llx\n", copied_len);
		export_poff += copied_len;
		local_poff += copied_len;
		export_psize -= copied_len;
		local_psize -= copied_len;
		cookie_size -= copied_len;

		total_bal -= copied_len;

		if (copy_size != copied_len)
			continue;

		if (export_psize == 0 && total_bal != 0) {

			if (cookie_size == 0) {
				idx++;
				cookie_addr = cookies[idx].addr;
				cookie_size = cookies[idx].size;

				export_caddr = cookie_addr & ~(pg_size - 1);
				export_poff = cookie_addr & (pg_size - 1);
				export_psize =
				    min(cookie_size, (pg_size-export_poff));
			} else {
				export_caddr += pg_size;
				export_poff = 0;
				export_psize = min(cookie_size, pg_size);
			}
		}

		if (local_psize == 0 && total_bal != 0) {
			local_valign += pg_size;
			local_ra = va_to_pa((void *)local_valign);
			local_poff = 0;
			local_psize = min(pg_size, len);
			len -= local_psize;
		}

		/* check if we are all done */
		if (total_bal == 0)
			break;
	}


	D1(chid,
	    "ldc_mem_copy: (0x%llx) done copying sz=0x%llx\n",
	    chid, *size);

	return (0);
}

/*
 * Copy data either from or to the client specified virtual address
 * space to or from HV physical memory.
 *
 * The direction argument determines whether the data is read from or
 * written to HV memory. direction values are LDC_COPY_IN/OUT similar
 * to the ldc_mem_copy interface
 */
int
ldc_mem_rdwr_cookie(ldc_handle_t handle, caddr_t vaddr, size_t *size,
    caddr_t paddr, uint8_t direction)
{
	ldc_chan_t 	*ldcp;
	uint64_t	local_voff, local_valign;
	uint64_t	pg_shift, pg_size, pg_size_code;
	uint64_t 	target_pa, target_poff, target_psize, target_size;
	uint64_t	local_ra, local_poff, local_psize;
	uint64_t	copy_size, copied_len = 0;
	pgcnt_t		npages;
	size_t		len = *size;
	int 		rv = 0;

	if (handle == NULL) {
		DWARN(DBG_ALL_LDCS,
		    "ldc_mem_rdwr_cookie: invalid channel handle\n");
		return (EINVAL);
	}
	ldcp = (ldc_chan_t *)handle;

	mutex_enter(&ldcp->lock);

	/* check to see if channel is UP */
	if (ldcp->tstate != TS_UP) {
		DWARN(ldcp->id,
		    "ldc_mem_rdwr_cookie: (0x%llx) channel is not UP\n",
		    ldcp->id);
		mutex_exit(&ldcp->lock);
		return (ECONNRESET);
	}

	/* Force address and size to be 8-byte aligned */
	if ((((uintptr_t)vaddr | len) & 0x7) != 0) {
		DWARN(ldcp->id,
		    "ldc_mem_rdwr_cookie: addr/size is not 8-byte aligned\n");
		mutex_exit(&ldcp->lock);
		return (EINVAL);
	}

	target_size = *size;

	/* FUTURE: get the page size, pgsz code, and shift */
	pg_size = MMU_PAGESIZE;
	pg_size_code = page_szc(pg_size);
	pg_shift = page_get_shift(pg_size_code);

	D1(ldcp->id, "ldc_mem_rdwr_cookie: copying data "
	    "(0x%llx) va 0x%llx pgsz=0x%llx, pgszc=0x%llx, pg_shift=0x%llx\n",
	    ldcp->id, vaddr, pg_size, pg_size_code, pg_shift);

	/* aligned VA and its offset */
	local_valign = ((uintptr_t)vaddr) & ~(pg_size - 1);
	local_voff = ((uintptr_t)vaddr) & (pg_size - 1);

	npages = (len + local_voff) / pg_size;
	npages = ((len + local_voff) % pg_size == 0) ? npages : npages+1;

	D1(ldcp->id, "ldc_mem_rdwr_cookie: (0x%llx) v=0x%llx, "
	    "val=0x%llx,off=0x%x,pgs=0x%x\n",
	    ldcp->id, vaddr, local_valign, local_voff, npages);

	local_ra = va_to_pa((void *)local_valign);
	local_poff = local_voff;
	local_psize = min(len, (pg_size - local_voff));

	len -= local_psize;

	target_pa = ((uintptr_t)paddr) & ~(pg_size - 1);
	target_poff = ((uintptr_t)paddr) & (pg_size - 1);
	target_psize = pg_size - target_poff;

	for (;;) {

		copy_size = min(target_psize, local_psize);

		D1(ldcp->id,
		    "ldc_mem_rdwr_cookie: (0x%llx) dir=0x%x, tar_pa=0x%llx,"
		    " loc_ra=0x%llx, tar_poff=0x%llx, loc_poff=0x%llx,"
		    " tar_psz=0x%llx, loc_psz=0x%llx, copy_sz=0x%llx,"
		    " total_bal=0x%llx\n",
		    ldcp->id, direction, target_pa, local_ra, target_poff,
		    local_poff, target_psize, local_psize, copy_size,
		    target_size);

		rv = hv_ldc_copy(ldcp->id, direction,
		    (target_pa + target_poff), (local_ra + local_poff),
		    copy_size, &copied_len);

		if (rv != 0) {
			DWARN(DBG_ALL_LDCS,
			    "ldc_mem_rdwr_cookie: (0x%lx) err %d during copy\n",
			    ldcp->id, rv);
			DWARN(DBG_ALL_LDCS,
			    "ldc_mem_rdwr_cookie: (0x%llx) dir=%lld, "
			    "tar_pa=0x%llx, loc_ra=0x%llx, tar_poff=0x%llx, "
			    "loc_poff=0x%llx, tar_psz=0x%llx, loc_psz=0x%llx, "
			    "copy_sz=0x%llx, total_bal=0x%llx\n",
			    ldcp->id, direction, target_pa, local_ra,
			    target_poff, local_poff, target_psize, local_psize,
			    copy_size, target_size);

			*size = *size - target_size;
			mutex_exit(&ldcp->lock);
			return (i_ldc_h2v_error(rv));
		}

		D2(ldcp->id, "ldc_mem_rdwr_cookie: copied=0x%llx\n",
		    copied_len);
		target_poff += copied_len;
		local_poff += copied_len;
		target_psize -= copied_len;
		local_psize -= copied_len;

		target_size -= copied_len;

		if (copy_size != copied_len)
			continue;

		if (target_psize == 0 && target_size != 0) {
			target_pa += pg_size;
			target_poff = 0;
			target_psize = min(pg_size, target_size);
		}

		if (local_psize == 0 && target_size != 0) {
			local_valign += pg_size;
			local_ra = va_to_pa((void *)local_valign);
			local_poff = 0;
			local_psize = min(pg_size, len);
			len -= local_psize;
		}

		/* check if we are all done */
		if (target_size == 0)
			break;
	}

	mutex_exit(&ldcp->lock);

	D1(ldcp->id, "ldc_mem_rdwr_cookie: (0x%llx) done copying sz=0x%llx\n",
	    ldcp->id, *size);

	return (0);
}

/*
 * Map an exported memory segment into the local address space. If the
 * memory range was exported for direct map access, a HV call is made
 * to allocate a RA range. If the map is done via a shadow copy, local
 * shadow memory is allocated and the base VA is returned in 'vaddr'. If
 * the mapping is a direct map then the RA is returned in 'raddr'.
 */
int
ldc_mem_map(ldc_mem_handle_t mhandle, ldc_mem_cookie_t *cookie, uint32_t ccount,
    uint8_t mtype, uint8_t perm, caddr_t *vaddr, caddr_t *raddr)
{
	int		i, j, idx, rv, retries;
	ldc_chan_t 	*ldcp;
	ldc_mhdl_t	*mhdl;
	ldc_memseg_t	*memseg;
	caddr_t		tmpaddr;
	uint64_t	map_perm = perm;
	uint64_t	pg_size, pg_shift, pg_size_code, pg_mask;
	uint64_t	exp_size = 0, base_off, map_size, npages;
	uint64_t	cookie_addr, cookie_off, cookie_size;
	tte_t		ldc_tte;

	if (mhandle == NULL) {
		DWARN(DBG_ALL_LDCS, "ldc_mem_map: invalid memory handle\n");
		return (EINVAL);
	}
	mhdl = (ldc_mhdl_t *)mhandle;

	mutex_enter(&mhdl->lock);

	if (mhdl->status == LDC_BOUND || mhdl->status == LDC_MAPPED ||
	    mhdl->memseg != NULL) {
		DWARN(DBG_ALL_LDCS,
		    "ldc_mem_map: (0x%llx) handle bound/mapped\n", mhandle);
		mutex_exit(&mhdl->lock);
		return (EINVAL);
	}

	ldcp = mhdl->ldcp;

	mutex_enter(&ldcp->lock);

	if (ldcp->tstate != TS_UP) {
		DWARN(ldcp->id,
		    "ldc_mem_dring_map: (0x%llx) channel is not UP\n",
		    ldcp->id);
		mutex_exit(&ldcp->lock);
		mutex_exit(&mhdl->lock);
		return (ECONNRESET);
	}

	if ((mtype & (LDC_SHADOW_MAP|LDC_DIRECT_MAP|LDC_IO_MAP)) == 0) {
		DWARN(ldcp->id, "ldc_mem_map: invalid map type\n");
		mutex_exit(&ldcp->lock);
		mutex_exit(&mhdl->lock);
		return (EINVAL);
	}

	D1(ldcp->id, "ldc_mem_map: (0x%llx) cookie = 0x%llx,0x%llx\n",
	    ldcp->id, cookie->addr, cookie->size);

	/* FUTURE: get the page size, pgsz code, and shift */
	pg_size = MMU_PAGESIZE;
	pg_size_code = page_szc(pg_size);
	pg_shift = page_get_shift(pg_size_code);
	pg_mask = ~(pg_size - 1);

	/* calculate the number of pages in the exported cookie */
	base_off = cookie[0].addr & (pg_size - 1);
	for (idx = 0; idx < ccount; idx++)
		exp_size += cookie[idx].size;
	map_size = P2ROUNDUP((exp_size + base_off), pg_size);
	npages = (map_size >> pg_shift);

	/* Allocate memseg structure */
	memseg = mhdl->memseg =
	    kmem_cache_alloc(ldcssp->memseg_cache, KM_SLEEP);

	/* Allocate memory to store all pages and cookies */
	memseg->pages =	kmem_zalloc((sizeof (ldc_page_t) * npages), KM_SLEEP);
	memseg->cookies =
	    kmem_zalloc((sizeof (ldc_mem_cookie_t) * ccount), KM_SLEEP);

	D2(ldcp->id, "ldc_mem_map: (0x%llx) exp_size=0x%llx, map_size=0x%llx,"
	    "pages=0x%llx\n", ldcp->id, exp_size, map_size, npages);

	/*
	 * Check if direct map over shared memory is enabled, if not change
	 * the mapping type to SHADOW_MAP.
	 */
	if (ldc_shmem_enabled == 0)
		mtype = LDC_SHADOW_MAP;

	/*
	 * Check to see if the client is requesting direct or shadow map
	 * If direct map is requested, try to map remote memory first,
	 * and if that fails, revert to shadow map
	 */
	if (mtype == LDC_DIRECT_MAP) {

		/* Allocate kernel virtual space for mapping */
		memseg->vaddr = vmem_xalloc(heap_arena, map_size,
		    pg_size, 0, 0, NULL, NULL, VM_NOSLEEP);
		if (memseg->vaddr == NULL) {
			cmn_err(CE_WARN,
			    "ldc_mem_map: (0x%lx) memory map failed\n",
			    ldcp->id);
			kmem_free(memseg->cookies,
			    (sizeof (ldc_mem_cookie_t) * ccount));
			kmem_free(memseg->pages,
			    (sizeof (ldc_page_t) * npages));
			kmem_cache_free(ldcssp->memseg_cache, memseg);

			mutex_exit(&ldcp->lock);
			mutex_exit(&mhdl->lock);
			return (ENOMEM);
		}

		/* Unload previous mapping */
		hat_unload(kas.a_hat, memseg->vaddr, map_size,
		    HAT_UNLOAD_NOSYNC | HAT_UNLOAD_UNLOCK);

		/* for each cookie passed in - map into address space */
		idx = 0;
		cookie_size = 0;
		tmpaddr = memseg->vaddr;

		for (i = 0; i < npages; i++) {

			if (cookie_size == 0) {
				ASSERT(idx < ccount);
				cookie_addr = cookie[idx].addr & pg_mask;
				cookie_off = cookie[idx].addr & (pg_size - 1);
				cookie_size =
				    P2ROUNDUP((cookie_off + cookie[idx].size),
				    pg_size);
				idx++;
			}

			D1(ldcp->id, "ldc_mem_map: (0x%llx) mapping "
			    "cookie 0x%llx, bal=0x%llx\n", ldcp->id,
			    cookie_addr, cookie_size);

			/* map the cookie into address space */
			for (retries = 0; retries < ldc_max_retries;
			    retries++) {

				rv = hv_ldc_mapin(ldcp->id, cookie_addr,
				    &memseg->pages[i].raddr, &map_perm);
				if (rv != H_EWOULDBLOCK && rv != H_ETOOMANY)
					break;

				drv_usecwait(ldc_delay);
			}

			if (rv || memseg->pages[i].raddr == 0) {
				DWARN(ldcp->id,
				    "ldc_mem_map: (0x%llx) hv mapin err %d\n",
				    ldcp->id, rv);

				/* remove previous mapins */
				hat_unload(kas.a_hat, memseg->vaddr, map_size,
				    HAT_UNLOAD_NOSYNC | HAT_UNLOAD_UNLOCK);
				for (j = 0; j < i; j++) {
					rv = hv_ldc_unmap(
					    memseg->pages[j].raddr);
					if (rv) {
						DWARN(ldcp->id,
						    "ldc_mem_map: (0x%llx) "
						    "cannot unmap ra=0x%llx\n",
						    ldcp->id,
						    memseg->pages[j].raddr);
					}
				}

				/* free kernel virtual space */
				vmem_free(heap_arena, (void *)memseg->vaddr,
				    map_size);

				/* direct map failed - revert to shadow map */
				mtype = LDC_SHADOW_MAP;
				break;

			} else {

				D1(ldcp->id,
				    "ldc_mem_map: (0x%llx) vtop map 0x%llx -> "
				    "0x%llx, cookie=0x%llx, perm=0x%llx\n",
				    ldcp->id, tmpaddr, memseg->pages[i].raddr,
				    cookie_addr, perm);

				/*
				 * NOTE: Calling hat_devload directly, causes it
				 * to look for page_t using the pfn. Since this
				 * addr is greater than the memlist, it treates
				 * it as non-memory
				 */
				sfmmu_memtte(&ldc_tte,
				    (pfn_t)(memseg->pages[i].raddr >> pg_shift),
				    PROT_READ | PROT_WRITE | HAT_NOSYNC, TTE8K);

				D1(ldcp->id,
				    "ldc_mem_map: (0x%llx) ra 0x%llx -> "
				    "tte 0x%llx\n", ldcp->id,
				    memseg->pages[i].raddr, ldc_tte);

				sfmmu_tteload(kas.a_hat, &ldc_tte, tmpaddr,
				    NULL, HAT_LOAD_LOCK);

				cookie_size -= pg_size;
				cookie_addr += pg_size;
				tmpaddr += pg_size;
			}
		}
	}

	if (mtype == LDC_SHADOW_MAP) {
		if (*vaddr == NULL) {
			memseg->vaddr = kmem_zalloc(exp_size, KM_SLEEP);
			mhdl->myshadow = B_TRUE;

			D1(ldcp->id, "ldc_mem_map: (0x%llx) allocated "
			    "shadow page va=0x%llx\n", ldcp->id, memseg->vaddr);
		} else {
			/*
			 * Use client supplied memory for memseg->vaddr
			 * WARNING: assuming that client mem is >= exp_size
			 */
			memseg->vaddr = *vaddr;
		}

		/* Save all page and cookie information */
		for (i = 0, tmpaddr = memseg->vaddr; i < npages; i++) {
			memseg->pages[i].raddr = va_to_pa(tmpaddr);
			memseg->pages[i].size = pg_size;
			tmpaddr += pg_size;
		}

	}

	/* save all cookies */
	bcopy(cookie, memseg->cookies, ccount * sizeof (ldc_mem_cookie_t));

	/* update memseg_t */
	memseg->raddr = memseg->pages[0].raddr;
	memseg->size = (mtype == LDC_SHADOW_MAP) ? exp_size : map_size;
	memseg->npages = npages;
	memseg->ncookies = ccount;
	memseg->next_cookie = 0;

	/* memory handle = mapped */
	mhdl->mtype = mtype;
	mhdl->perm = perm;
	mhdl->status = LDC_MAPPED;

	D1(ldcp->id, "ldc_mem_map: (0x%llx) mapped 0x%llx, ra=0x%llx, "
	    "va=0x%llx, pgs=0x%llx cookies=0x%llx\n",
	    ldcp->id, mhdl, memseg->raddr, memseg->vaddr,
	    memseg->npages, memseg->ncookies);

	if (mtype == LDC_SHADOW_MAP)
		base_off = 0;
	if (raddr)
		*raddr = (caddr_t)(memseg->raddr | base_off);
	if (vaddr)
		*vaddr = (caddr_t)((uintptr_t)memseg->vaddr | base_off);

	mutex_exit(&ldcp->lock);
	mutex_exit(&mhdl->lock);
	return (0);
}

/*
 * Unmap a memory segment. Free shadow memory (if any).
 */
int
ldc_mem_unmap(ldc_mem_handle_t mhandle)
{
	int		i, rv;
	ldc_mhdl_t	*mhdl = (ldc_mhdl_t *)mhandle;
	ldc_chan_t 	*ldcp;
	ldc_memseg_t	*memseg;

	if (mhdl == 0 || mhdl->status != LDC_MAPPED) {
		DWARN(DBG_ALL_LDCS,
		    "ldc_mem_unmap: (0x%llx) handle is not mapped\n",
		    mhandle);
		return (EINVAL);
	}

	mutex_enter(&mhdl->lock);

	ldcp = mhdl->ldcp;
	memseg = mhdl->memseg;

	D1(ldcp->id, "ldc_mem_unmap: (0x%llx) unmapping handle 0x%llx\n",
	    ldcp->id, mhdl);

	/* if we allocated shadow memory - free it */
	if (mhdl->mtype == LDC_SHADOW_MAP && mhdl->myshadow) {
		kmem_free(memseg->vaddr, memseg->size);
	} else if (mhdl->mtype == LDC_DIRECT_MAP) {

		/* unmap in the case of DIRECT_MAP */
		hat_unload(kas.a_hat, memseg->vaddr, memseg->size,
		    HAT_UNLOAD_UNLOCK);

		for (i = 0; i < memseg->npages; i++) {
			rv = hv_ldc_unmap(memseg->pages[i].raddr);
			if (rv) {
				cmn_err(CE_WARN,
				    "ldc_mem_map: (0x%lx) hv unmap err %d\n",
				    ldcp->id, rv);
			}
		}

		vmem_free(heap_arena, (void *)memseg->vaddr, memseg->size);
	}

	/* free the allocated memseg and page structures */
	kmem_free(memseg->pages, (sizeof (ldc_page_t) * memseg->npages));
	kmem_free(memseg->cookies,
	    (sizeof (ldc_mem_cookie_t) * memseg->ncookies));
	kmem_cache_free(ldcssp->memseg_cache, memseg);

	/* uninitialize the memory handle */
	mhdl->memseg = NULL;
	mhdl->status = LDC_UNBOUND;

	D1(ldcp->id, "ldc_mem_unmap: (0x%llx) unmapped handle 0x%llx\n",
	    ldcp->id, mhdl);

	mutex_exit(&mhdl->lock);
	return (0);
}

/*
 * Internal entry point for LDC mapped memory entry consistency
 * semantics. Acquire copies the contents of the remote memory
 * into the local shadow copy. The release operation copies the local
 * contents into the remote memory. The offset and size specify the
 * bounds for the memory range being synchronized.
 */
static int
i_ldc_mem_acquire_release(ldc_mem_handle_t mhandle, uint8_t direction,
    uint64_t offset, size_t size)
{
	int 		err;
	ldc_mhdl_t	*mhdl;
	ldc_chan_t	*ldcp;
	ldc_memseg_t	*memseg;
	caddr_t		local_vaddr;
	size_t		copy_size;

	if (mhandle == NULL) {
		DWARN(DBG_ALL_LDCS,
		    "i_ldc_mem_acquire_release: invalid memory handle\n");
		return (EINVAL);
	}
	mhdl = (ldc_mhdl_t *)mhandle;

	mutex_enter(&mhdl->lock);

	if (mhdl->status != LDC_MAPPED || mhdl->ldcp == NULL) {
		DWARN(DBG_ALL_LDCS,
		    "i_ldc_mem_acquire_release: not mapped memory\n");
		mutex_exit(&mhdl->lock);
		return (EINVAL);
	}

	/* do nothing for direct map */
	if (mhdl->mtype == LDC_DIRECT_MAP) {
		mutex_exit(&mhdl->lock);
		return (0);
	}

	/* do nothing if COPY_IN+MEM_W and COPY_OUT+MEM_R */
	if ((direction == LDC_COPY_IN && (mhdl->perm & LDC_MEM_R) == 0) ||
	    (direction == LDC_COPY_OUT && (mhdl->perm & LDC_MEM_W) == 0)) {
		mutex_exit(&mhdl->lock);
		return (0);
	}

	if (offset >= mhdl->memseg->size ||
	    (offset + size) > mhdl->memseg->size) {
		DWARN(DBG_ALL_LDCS,
		    "i_ldc_mem_acquire_release: memory out of range\n");
		mutex_exit(&mhdl->lock);
		return (EINVAL);
	}

	/* get the channel handle and memory segment */
	ldcp = mhdl->ldcp;
	memseg = mhdl->memseg;

	if (mhdl->mtype == LDC_SHADOW_MAP) {

		local_vaddr = memseg->vaddr + offset;
		copy_size = size;

		/* copy to/from remote from/to local memory */
		err = ldc_mem_copy((ldc_handle_t)ldcp, local_vaddr, offset,
		    &copy_size, memseg->cookies, memseg->ncookies,
		    direction);
		if (err || copy_size != size) {
			DWARN(ldcp->id,
			    "i_ldc_mem_acquire_release: copy failed\n");
			mutex_exit(&mhdl->lock);
			return (err);
		}
	}

	mutex_exit(&mhdl->lock);

	return (0);
}

/*
 * Ensure that the contents in the remote memory seg are consistent
 * with the contents if of local segment
 */
int
ldc_mem_acquire(ldc_mem_handle_t mhandle, uint64_t offset, uint64_t size)
{
	return (i_ldc_mem_acquire_release(mhandle, LDC_COPY_IN, offset, size));
}


/*
 * Ensure that the contents in the local memory seg are consistent
 * with the contents if of remote segment
 */
int
ldc_mem_release(ldc_mem_handle_t mhandle, uint64_t offset, uint64_t size)
{
	return (i_ldc_mem_acquire_release(mhandle, LDC_COPY_OUT, offset, size));
}

/*
 * Allocate a descriptor ring. The size of each each descriptor
 * must be 8-byte aligned and the entire ring should be a multiple
 * of MMU_PAGESIZE.
 */
int
ldc_mem_dring_create(uint32_t len, uint32_t dsize, ldc_dring_handle_t *dhandle)
{
	ldc_dring_t *dringp;
	size_t size = (dsize * len);

	D1(DBG_ALL_LDCS, "ldc_mem_dring_create: len=0x%x, size=0x%x\n",
	    len, dsize);

	if (dhandle == NULL) {
		DWARN(DBG_ALL_LDCS, "ldc_mem_dring_create: invalid dhandle\n");
		return (EINVAL);
	}

	if (len == 0) {
		DWARN(DBG_ALL_LDCS, "ldc_mem_dring_create: invalid length\n");
		return (EINVAL);
	}

	/* descriptor size should be 8-byte aligned */
	if (dsize == 0 || (dsize & 0x7)) {
		DWARN(DBG_ALL_LDCS, "ldc_mem_dring_create: invalid size\n");
		return (EINVAL);
	}

	*dhandle = 0;

	/* Allocate a desc ring structure */
	dringp = kmem_zalloc(sizeof (ldc_dring_t), KM_SLEEP);

	/* Initialize dring */
	dringp->length = len;
	dringp->dsize = dsize;

	/* round off to multiple of pagesize */
	dringp->size = (size & MMU_PAGEMASK);
	if (size & MMU_PAGEOFFSET)
		dringp->size += MMU_PAGESIZE;

	dringp->status = LDC_UNBOUND;

	/* allocate descriptor ring memory */
	dringp->base = kmem_zalloc(dringp->size, KM_SLEEP);

	/* initialize the desc ring lock */
	mutex_init(&dringp->lock, NULL, MUTEX_DRIVER, NULL);

	/* Add descriptor ring to the head of global list */
	mutex_enter(&ldcssp->lock);
	dringp->next = ldcssp->dring_list;
	ldcssp->dring_list = dringp;
	mutex_exit(&ldcssp->lock);

	*dhandle = (ldc_dring_handle_t)dringp;

	D1(DBG_ALL_LDCS, "ldc_mem_dring_create: dring allocated\n");

	return (0);
}


/*
 * Destroy a descriptor ring.
 */
int
ldc_mem_dring_destroy(ldc_dring_handle_t dhandle)
{
	ldc_dring_t *dringp;
	ldc_dring_t *tmp_dringp;

	D1(DBG_ALL_LDCS, "ldc_mem_dring_destroy: entered\n");

	if (dhandle == NULL) {
		DWARN(DBG_ALL_LDCS,
		    "ldc_mem_dring_destroy: invalid desc ring handle\n");
		return (EINVAL);
	}
	dringp = (ldc_dring_t *)dhandle;

	if (dringp->status == LDC_BOUND) {
		DWARN(DBG_ALL_LDCS,
		    "ldc_mem_dring_destroy: desc ring is bound\n");
		return (EACCES);
	}

	mutex_enter(&dringp->lock);
	mutex_enter(&ldcssp->lock);

	/* remove from linked list - if not bound */
	tmp_dringp = ldcssp->dring_list;
	if (tmp_dringp == dringp) {
		ldcssp->dring_list = dringp->next;
		dringp->next = NULL;

	} else {
		while (tmp_dringp != NULL) {
			if (tmp_dringp->next == dringp) {
				tmp_dringp->next = dringp->next;
				dringp->next = NULL;
				break;
			}
			tmp_dringp = tmp_dringp->next;
		}
		if (tmp_dringp == NULL) {
			DWARN(DBG_ALL_LDCS,
			    "ldc_mem_dring_destroy: invalid descriptor\n");
			mutex_exit(&ldcssp->lock);
			mutex_exit(&dringp->lock);
			return (EINVAL);
		}
	}

	mutex_exit(&ldcssp->lock);

	/* free the descriptor ring */
	kmem_free(dringp->base, dringp->size);

	mutex_exit(&dringp->lock);

	/* destroy dring lock */
	mutex_destroy(&dringp->lock);

	/* free desc ring object */
	kmem_free(dringp, sizeof (ldc_dring_t));

	return (0);
}

/*
 * Bind a previously allocated dring to a channel. The channel should
 * be OPEN in order to bind the ring to the channel. Returns back a
 * descriptor ring cookie. The descriptor ring is exported for remote
 * access by the client at the other end of the channel. An entry for
 * dring pages is stored in map table (via call to ldc_mem_bind_handle).
 */
int
ldc_mem_dring_bind(ldc_handle_t handle, ldc_dring_handle_t dhandle,
    uint8_t mtype, uint8_t perm, ldc_mem_cookie_t *cookie, uint32_t *ccount)
{
	int		err;
	ldc_chan_t 	*ldcp;
	ldc_dring_t	*dringp;
	ldc_mem_handle_t mhandle;

	/* check to see if channel is initalized */
	if (handle == NULL) {
		DWARN(DBG_ALL_LDCS,
		    "ldc_mem_dring_bind: invalid channel handle\n");
		return (EINVAL);
	}
	ldcp = (ldc_chan_t *)handle;

	if (dhandle == NULL) {
		DWARN(DBG_ALL_LDCS,
		    "ldc_mem_dring_bind: invalid desc ring handle\n");
		return (EINVAL);
	}
	dringp = (ldc_dring_t *)dhandle;

	if (cookie == NULL) {
		DWARN(ldcp->id,
		    "ldc_mem_dring_bind: invalid cookie arg\n");
		return (EINVAL);
	}

	mutex_enter(&dringp->lock);

	if (dringp->status == LDC_BOUND) {
		DWARN(DBG_ALL_LDCS,
		    "ldc_mem_dring_bind: (0x%llx) descriptor ring is bound\n",
		    ldcp->id);
		mutex_exit(&dringp->lock);
		return (EINVAL);
	}

	if ((perm & LDC_MEM_RW) == 0) {
		DWARN(DBG_ALL_LDCS,
		    "ldc_mem_dring_bind: invalid permissions\n");
		mutex_exit(&dringp->lock);
		return (EINVAL);
	}

	if ((mtype & (LDC_SHADOW_MAP|LDC_DIRECT_MAP|LDC_IO_MAP)) == 0) {
		DWARN(DBG_ALL_LDCS, "ldc_mem_dring_bind: invalid type\n");
		mutex_exit(&dringp->lock);
		return (EINVAL);
	}

	dringp->ldcp = ldcp;

	/* create an memory handle */
	err = ldc_mem_alloc_handle(handle, &mhandle);
	if (err || mhandle == NULL) {
		DWARN(DBG_ALL_LDCS,
		    "ldc_mem_dring_bind: (0x%llx) error allocating mhandle\n",
		    ldcp->id);
		mutex_exit(&dringp->lock);
		return (err);
	}
	dringp->mhdl = mhandle;

	/* bind the descriptor ring to channel */
	err = ldc_mem_bind_handle(mhandle, dringp->base, dringp->size,
	    mtype, perm, cookie, ccount);
	if (err) {
		DWARN(ldcp->id,
		    "ldc_mem_dring_bind: (0x%llx) error binding mhandle\n",
		    ldcp->id);
		mutex_exit(&dringp->lock);
		return (err);
	}

	/*
	 * For now return error if we get more than one cookie
	 * FUTURE: Return multiple cookies ..
	 */
	if (*ccount > 1) {
		(void) ldc_mem_unbind_handle(mhandle);
		(void) ldc_mem_free_handle(mhandle);

		dringp->ldcp = NULL;
		dringp->mhdl = NULL;
		*ccount = 0;

		mutex_exit(&dringp->lock);
		return (EAGAIN);
	}

	/* Add descriptor ring to channel's exported dring list */
	mutex_enter(&ldcp->exp_dlist_lock);
	dringp->ch_next = ldcp->exp_dring_list;
	ldcp->exp_dring_list = dringp;
	mutex_exit(&ldcp->exp_dlist_lock);

	dringp->status = LDC_BOUND;

	mutex_exit(&dringp->lock);

	return (0);
}

/*
 * Return the next cookie associated with the specified dring handle
 */
int
ldc_mem_dring_nextcookie(ldc_dring_handle_t dhandle, ldc_mem_cookie_t *cookie)
{
	int		rv = 0;
	ldc_dring_t 	*dringp;
	ldc_chan_t	*ldcp;

	if (dhandle == NULL) {
		DWARN(DBG_ALL_LDCS,
		    "ldc_mem_dring_nextcookie: invalid desc ring handle\n");
		return (EINVAL);
	}
	dringp = (ldc_dring_t *)dhandle;
	mutex_enter(&dringp->lock);

	if (dringp->status != LDC_BOUND) {
		DWARN(DBG_ALL_LDCS,
		    "ldc_mem_dring_nextcookie: descriptor ring 0x%llx "
		    "is not bound\n", dringp);
		mutex_exit(&dringp->lock);
		return (EINVAL);
	}

	ldcp = dringp->ldcp;

	if (cookie == NULL) {
		DWARN(ldcp->id,
		    "ldc_mem_dring_nextcookie:(0x%llx) invalid cookie arg\n",
		    ldcp->id);
		mutex_exit(&dringp->lock);
		return (EINVAL);
	}

	rv = ldc_mem_nextcookie((ldc_mem_handle_t)dringp->mhdl, cookie);
	mutex_exit(&dringp->lock);

	return (rv);
}
/*
 * Unbind a previously bound dring from a channel.
 */
int
ldc_mem_dring_unbind(ldc_dring_handle_t dhandle)
{
	ldc_dring_t 	*dringp;
	ldc_dring_t	*tmp_dringp;
	ldc_chan_t	*ldcp;

	if (dhandle == NULL) {
		DWARN(DBG_ALL_LDCS,
		    "ldc_mem_dring_unbind: invalid desc ring handle\n");
		return (EINVAL);
	}
	dringp = (ldc_dring_t *)dhandle;

	mutex_enter(&dringp->lock);

	if (dringp->status == LDC_UNBOUND) {
		DWARN(DBG_ALL_LDCS,
		    "ldc_mem_dring_bind: descriptor ring 0x%llx is unbound\n",
		    dringp);
		mutex_exit(&dringp->lock);
		return (EINVAL);
	}
	ldcp = dringp->ldcp;

	mutex_enter(&ldcp->exp_dlist_lock);

	tmp_dringp = ldcp->exp_dring_list;
	if (tmp_dringp == dringp) {
		ldcp->exp_dring_list = dringp->ch_next;
		dringp->ch_next = NULL;

	} else {
		while (tmp_dringp != NULL) {
			if (tmp_dringp->ch_next == dringp) {
				tmp_dringp->ch_next = dringp->ch_next;
				dringp->ch_next = NULL;
				break;
			}
			tmp_dringp = tmp_dringp->ch_next;
		}
		if (tmp_dringp == NULL) {
			DWARN(DBG_ALL_LDCS,
			    "ldc_mem_dring_unbind: invalid descriptor\n");
			mutex_exit(&ldcp->exp_dlist_lock);
			mutex_exit(&dringp->lock);
			return (EINVAL);
		}
	}

	mutex_exit(&ldcp->exp_dlist_lock);

	(void) ldc_mem_unbind_handle((ldc_mem_handle_t)dringp->mhdl);
	(void) ldc_mem_free_handle((ldc_mem_handle_t)dringp->mhdl);

	dringp->ldcp = NULL;
	dringp->mhdl = NULL;
	dringp->status = LDC_UNBOUND;

	mutex_exit(&dringp->lock);

	return (0);
}

/*
 * Get information about the dring. The base address of the descriptor
 * ring along with the type and permission are returned back.
 */
int
ldc_mem_dring_info(ldc_dring_handle_t dhandle, ldc_mem_info_t *minfo)
{
	ldc_dring_t	*dringp;
	int		rv;

	if (dhandle == NULL) {
		DWARN(DBG_ALL_LDCS,
		    "ldc_mem_dring_info: invalid desc ring handle\n");
		return (EINVAL);
	}
	dringp = (ldc_dring_t *)dhandle;

	mutex_enter(&dringp->lock);

	if (dringp->mhdl) {
		rv = ldc_mem_info(dringp->mhdl, minfo);
		if (rv) {
			DWARN(DBG_ALL_LDCS,
			    "ldc_mem_dring_info: error reading mem info\n");
			mutex_exit(&dringp->lock);
			return (rv);
		}
	} else {
		minfo->vaddr = dringp->base;
		minfo->raddr = NULL;
		minfo->status = dringp->status;
	}

	mutex_exit(&dringp->lock);

	return (0);
}

/*
 * Map an exported descriptor ring into the local address space. If the
 * descriptor ring was exported for direct map access, a HV call is made
 * to allocate a RA range. If the map is done via a shadow copy, local
 * shadow memory is allocated.
 */
int
ldc_mem_dring_map(ldc_handle_t handle, ldc_mem_cookie_t *cookie,
    uint32_t ccount, uint32_t len, uint32_t dsize, uint8_t mtype,
    ldc_dring_handle_t *dhandle)
{
	int		err;
	ldc_chan_t 	*ldcp = (ldc_chan_t *)handle;
	ldc_mem_handle_t mhandle;
	ldc_dring_t	*dringp;
	size_t		dring_size;

	if (dhandle == NULL) {
		DWARN(DBG_ALL_LDCS,
		    "ldc_mem_dring_map: invalid dhandle\n");
		return (EINVAL);
	}

	/* check to see if channel is initalized */
	if (handle == NULL) {
		DWARN(DBG_ALL_LDCS,
		    "ldc_mem_dring_map: invalid channel handle\n");
		return (EINVAL);
	}
	ldcp = (ldc_chan_t *)handle;

	if (cookie == NULL) {
		DWARN(ldcp->id,
		    "ldc_mem_dring_map: (0x%llx) invalid cookie\n",
		    ldcp->id);
		return (EINVAL);
	}

	/* FUTURE: For now we support only one cookie per dring */
	ASSERT(ccount == 1);

	if (cookie->size < (dsize * len)) {
		DWARN(ldcp->id,
		    "ldc_mem_dring_map: (0x%llx) invalid dsize/len\n",
		    ldcp->id);
		return (EINVAL);
	}

	*dhandle = 0;

	/* Allocate an dring structure */
	dringp = kmem_zalloc(sizeof (ldc_dring_t), KM_SLEEP);

	D1(ldcp->id,
	    "ldc_mem_dring_map: 0x%x,0x%x,0x%x,0x%llx,0x%llx\n",
	    mtype, len, dsize, cookie->addr, cookie->size);

	/* Initialize dring */
	dringp->length = len;
	dringp->dsize = dsize;

	/* round of to multiple of page size */
	dring_size = len * dsize;
	dringp->size = (dring_size & MMU_PAGEMASK);
	if (dring_size & MMU_PAGEOFFSET)
		dringp->size += MMU_PAGESIZE;

	dringp->ldcp = ldcp;

	/* create an memory handle */
	err = ldc_mem_alloc_handle(handle, &mhandle);
	if (err || mhandle == NULL) {
		DWARN(DBG_ALL_LDCS,
		    "ldc_mem_dring_map: cannot alloc hdl err=%d\n",
		    err);
		kmem_free(dringp, sizeof (ldc_dring_t));
		return (ENOMEM);
	}

	dringp->mhdl = mhandle;
	dringp->base = NULL;

	/* map the dring into local memory */
	err = ldc_mem_map(mhandle, cookie, ccount, mtype, LDC_MEM_RW,
	    &(dringp->base), NULL);
	if (err || dringp->base == NULL) {
		cmn_err(CE_WARN,
		    "ldc_mem_dring_map: cannot map desc ring err=%d\n", err);
		(void) ldc_mem_free_handle(mhandle);
		kmem_free(dringp, sizeof (ldc_dring_t));
		return (ENOMEM);
	}

	/* initialize the desc ring lock */
	mutex_init(&dringp->lock, NULL, MUTEX_DRIVER, NULL);

	/* Add descriptor ring to channel's imported dring list */
	mutex_enter(&ldcp->imp_dlist_lock);
	dringp->ch_next = ldcp->imp_dring_list;
	ldcp->imp_dring_list = dringp;
	mutex_exit(&ldcp->imp_dlist_lock);

	dringp->status = LDC_MAPPED;

	*dhandle = (ldc_dring_handle_t)dringp;

	return (0);
}

/*
 * Unmap a descriptor ring. Free shadow memory (if any).
 */
int
ldc_mem_dring_unmap(ldc_dring_handle_t dhandle)
{
	ldc_dring_t 	*dringp;
	ldc_dring_t	*tmp_dringp;
	ldc_chan_t	*ldcp;

	if (dhandle == NULL) {
		DWARN(DBG_ALL_LDCS,
		    "ldc_mem_dring_unmap: invalid desc ring handle\n");
		return (EINVAL);
	}
	dringp = (ldc_dring_t *)dhandle;

	if (dringp->status != LDC_MAPPED) {
		DWARN(DBG_ALL_LDCS,
		    "ldc_mem_dring_unmap: not a mapped desc ring\n");
		return (EINVAL);
	}

	mutex_enter(&dringp->lock);

	ldcp = dringp->ldcp;

	mutex_enter(&ldcp->imp_dlist_lock);

	/* find and unlink the desc ring from channel import list */
	tmp_dringp = ldcp->imp_dring_list;
	if (tmp_dringp == dringp) {
		ldcp->imp_dring_list = dringp->ch_next;
		dringp->ch_next = NULL;

	} else {
		while (tmp_dringp != NULL) {
			if (tmp_dringp->ch_next == dringp) {
				tmp_dringp->ch_next = dringp->ch_next;
				dringp->ch_next = NULL;
				break;
			}
			tmp_dringp = tmp_dringp->ch_next;
		}
		if (tmp_dringp == NULL) {
			DWARN(DBG_ALL_LDCS,
			    "ldc_mem_dring_unmap: invalid descriptor\n");
			mutex_exit(&ldcp->imp_dlist_lock);
			mutex_exit(&dringp->lock);
			return (EINVAL);
		}
	}

	mutex_exit(&ldcp->imp_dlist_lock);

	/* do a LDC memory handle unmap and free */
	(void) ldc_mem_unmap(dringp->mhdl);
	(void) ldc_mem_free_handle((ldc_mem_handle_t)dringp->mhdl);

	dringp->status = 0;
	dringp->ldcp = NULL;

	mutex_exit(&dringp->lock);

	/* destroy dring lock */
	mutex_destroy(&dringp->lock);

	/* free desc ring object */
	kmem_free(dringp, sizeof (ldc_dring_t));

	return (0);
}

/*
 * Internal entry point for descriptor ring access entry consistency
 * semantics. Acquire copies the contents of the remote descriptor ring
 * into the local shadow copy. The release operation copies the local
 * contents into the remote dring. The start and end locations specify
 * bounds for the entries being synchronized.
 */
static int
i_ldc_dring_acquire_release(ldc_dring_handle_t dhandle,
    uint8_t direction, uint64_t start, uint64_t end)
{
	int 			err;
	ldc_dring_t		*dringp;
	ldc_chan_t		*ldcp;
	uint64_t		soff;
	size_t			copy_size;

	if (dhandle == NULL) {
		DWARN(DBG_ALL_LDCS,
		    "i_ldc_dring_acquire_release: invalid desc ring handle\n");
		return (EINVAL);
	}
	dringp = (ldc_dring_t *)dhandle;
	mutex_enter(&dringp->lock);

	if (dringp->status != LDC_MAPPED || dringp->ldcp == NULL) {
		DWARN(DBG_ALL_LDCS,
		    "i_ldc_dring_acquire_release: not a mapped desc ring\n");
		mutex_exit(&dringp->lock);
		return (EINVAL);
	}

	if (start >= dringp->length || end >= dringp->length) {
		DWARN(DBG_ALL_LDCS,
		    "i_ldc_dring_acquire_release: index out of range\n");
		mutex_exit(&dringp->lock);
		return (EINVAL);
	}

	/* get the channel handle */
	ldcp = dringp->ldcp;

	copy_size = (start <= end) ? (((end - start) + 1) * dringp->dsize) :
	    ((dringp->length - start) * dringp->dsize);

	/* Calculate the relative offset for the first desc */
	soff = (start * dringp->dsize);

	/* copy to/from remote from/to local memory */
	D1(ldcp->id, "i_ldc_dring_acquire_release: c1 off=0x%llx sz=0x%llx\n",
	    soff, copy_size);
	err = i_ldc_mem_acquire_release((ldc_mem_handle_t)dringp->mhdl,
	    direction, soff, copy_size);
	if (err) {
		DWARN(ldcp->id,
		    "i_ldc_dring_acquire_release: copy failed\n");
		mutex_exit(&dringp->lock);
		return (err);
	}

	/* do the balance */
	if (start > end) {
		copy_size = ((end + 1) * dringp->dsize);
		soff = 0;

		/* copy to/from remote from/to local memory */
		D1(ldcp->id, "i_ldc_dring_acquire_release: c2 "
		    "off=0x%llx sz=0x%llx\n", soff, copy_size);
		err = i_ldc_mem_acquire_release((ldc_mem_handle_t)dringp->mhdl,
		    direction, soff, copy_size);
		if (err) {
			DWARN(ldcp->id,
			    "i_ldc_dring_acquire_release: copy failed\n");
			mutex_exit(&dringp->lock);
			return (err);
		}
	}

	mutex_exit(&dringp->lock);

	return (0);
}

/*
 * Ensure that the contents in the local dring are consistent
 * with the contents if of remote dring
 */
int
ldc_mem_dring_acquire(ldc_dring_handle_t dhandle, uint64_t start, uint64_t end)
{
	return (i_ldc_dring_acquire_release(dhandle, LDC_COPY_IN, start, end));
}

/*
 * Ensure that the contents in the remote dring are consistent
 * with the contents if of local dring
 */
int
ldc_mem_dring_release(ldc_dring_handle_t dhandle, uint64_t start, uint64_t end)
{
	return (i_ldc_dring_acquire_release(dhandle, LDC_COPY_OUT, start, end));
}


/* ------------------------------------------------------------------------- */
