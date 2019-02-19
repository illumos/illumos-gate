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
 * Copyright 2008 NetXen, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#include <sys/types.h>
#include <sys/conf.h>
#include <sys/debug.h>
#include <sys/stropts.h>
#include <sys/stream.h>
#include <sys/strlog.h>
#include <sys/kmem.h>
#include <sys/stat.h>
#include <sys/kstat.h>
#include <sys/vtrace.h>
#include <sys/dlpi.h>
#include <sys/strsun.h>
#include <sys/ethernet.h>
#include <sys/modctl.h>
#include <sys/errno.h>
#include <sys/dditypes.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sysmacros.h>
#include <sys/pci.h>

#include <sys/gld.h>
#include <netinet/in.h>
#include <inet/ip.h>
#include <inet/tcp.h>

#include <sys/rwlock.h>
#include <sys/mutex.h>
#include <sys/pattr.h>
#include <sys/strsubr.h>
#include <sys/ddi_impldefs.h>
#include<sys/task.h>

#include "unm_nic_hw.h"
#include "unm_nic.h"

#include "nic_phan_reg.h"
#include "unm_nic_ioctl.h"
#include "nic_cmn.h"
#include "unm_version.h"
#include "unm_brdcfg.h"

#if defined(lint)
#undef MBLKL
#define	MBLKL(_mp_)	((uintptr_t)(_mp_)->b_wptr - (uintptr_t)(_mp_)->b_rptr)
#endif /* lint */

#undef UNM_LOOPBACK
#undef SINGLE_DMA_BUF

#define	UNM_ADAPTER_UP_MAGIC	777
#define	VLAN_TAGSZ		0x4

#define	index2rxbuf(_rdp_, _idx_)	((_rdp_)->rx_buf_pool + (_idx_))
#define	rxbuf2index(_rdp_, _bufp_)	((_bufp_) - (_rdp_)->rx_buf_pool)

/*
 * Receive ISR processes NX_RX_MAXBUFS incoming packets at most, then posts
 * as many buffers as packets processed. This loop repeats as required to
 * process all incoming packets delivered in a single interrupt. Higher
 * value of NX_RX_MAXBUFS improves performance by posting rx buffers less
 * frequently, but at the cost of not posting quickly enough when card is
 * running out of rx buffers.
 */
#define	NX_RX_THRESHOLD		32
#define	NX_RX_MAXBUFS		128
#define	NX_MAX_TXCOMPS		256

extern int create_rxtx_rings(unm_adapter *adapter);
extern void destroy_rxtx_rings(unm_adapter *adapter);

static void unm_post_rx_buffers_nodb(struct unm_adapter_s *adapter,
    uint32_t ringid);
static mblk_t *unm_process_rcv(unm_adapter *adapter, statusDesc_t *desc);
static int unm_process_rcv_ring(unm_adapter *, int);
static int unm_process_cmd_ring(struct unm_adapter_s *adapter);

static int unm_nic_do_ioctl(unm_adapter *adapter, queue_t *q, mblk_t *mp);
static void unm_nic_ioctl(struct unm_adapter_s *adapter, int cmd, queue_t *q,
    mblk_t *mp);

/* GLDv3 interface functions */
static int ntxn_m_start(void *);
static void ntxn_m_stop(void *);
static int ntxn_m_multicst(void *, boolean_t, const uint8_t *);
static int ntxn_m_promisc(void *, boolean_t);
static int ntxn_m_stat(void *arg, uint_t stat, uint64_t *val);
static mblk_t *ntxn_m_tx(void *, mblk_t *);
static void ntxn_m_ioctl(void *arg, queue_t *wq, mblk_t *mp);
static boolean_t ntxn_m_getcapab(void *arg, mac_capab_t cap, void *cap_data);

/*
 * Allocates DMA handle, virtual memory and binds them
 * returns size of actual memory binded and the physical address.
 */
int
unm_pci_alloc_consistent(unm_adapter *adapter,
		int size, caddr_t *address, ddi_dma_cookie_t *cookie,
		ddi_dma_handle_t *dma_handle, ddi_acc_handle_t *handlep)
{
	int			err;
	uint32_t		ncookies;
	size_t			ring_len;
	uint_t			dma_flags = DDI_DMA_RDWR | DDI_DMA_CONSISTENT;

	*dma_handle = NULL;

	if (size <= 0)
		return (DDI_ENOMEM);

	err = ddi_dma_alloc_handle(adapter->dip,
	    &adapter->gc_dma_attr_desc,
	    DDI_DMA_DONTWAIT, NULL, dma_handle);
	if (err != DDI_SUCCESS) {
		cmn_err(CE_WARN, "!%s: %s: ddi_dma_alloc_handle FAILED:"
		    " %d", unm_nic_driver_name, __func__, err);
		return (DDI_ENOMEM);
	}

	err = ddi_dma_mem_alloc(*dma_handle,
	    size, &adapter->gc_attr_desc,
	    dma_flags & (DDI_DMA_STREAMING | DDI_DMA_CONSISTENT),
	    DDI_DMA_DONTWAIT, NULL, address, &ring_len,
	    handlep);
	if (err != DDI_SUCCESS) {
		cmn_err(CE_WARN, "!%s: %s: ddi_dma_mem_alloc failed:"
		    "ret %d, request size: %d",
		    unm_nic_driver_name, __func__, err, size);
		ddi_dma_free_handle(dma_handle);
		return (DDI_ENOMEM);
	}

	if (ring_len < size) {
		cmn_err(CE_WARN, "%s: %s: could not allocate required "
		    "memory :%d\n", unm_nic_driver_name,
		    __func__, err);
		ddi_dma_mem_free(handlep);
		ddi_dma_free_handle(dma_handle);
		return (DDI_FAILURE);
	}

	(void) memset(*address, 0, size);

	if (((err = ddi_dma_addr_bind_handle(*dma_handle,
	    NULL, *address, ring_len,
	    dma_flags,
	    DDI_DMA_DONTWAIT, NULL,
	    cookie, &ncookies)) != DDI_DMA_MAPPED) ||
	    (ncookies != 1)) {
		cmn_err(CE_WARN,
		    "!%s: %s: ddi_dma_addr_bind_handle FAILED: %d",
		    unm_nic_driver_name, __func__, err);
		ddi_dma_mem_free(handlep);
		ddi_dma_free_handle(dma_handle);
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/*
 * Unbinds the memory, frees the DMA handle and at the end, frees the memory
 */
void
unm_pci_free_consistent(ddi_dma_handle_t *dma_handle,
    ddi_acc_handle_t *acc_handle)
{
	int err;

	err = ddi_dma_unbind_handle(*dma_handle);
	if (err != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s: Error unbinding memory\n", __func__);
		return;
	}

	ddi_dma_mem_free(acc_handle);
	ddi_dma_free_handle(dma_handle);
}

static uint32_t msi_tgt_status[] = {
    ISR_INT_TARGET_STATUS, ISR_INT_TARGET_STATUS_F1,
    ISR_INT_TARGET_STATUS_F2, ISR_INT_TARGET_STATUS_F3,
    ISR_INT_TARGET_STATUS_F4, ISR_INT_TARGET_STATUS_F5,
    ISR_INT_TARGET_STATUS_F6, ISR_INT_TARGET_STATUS_F7
};

static void
unm_nic_disable_int(unm_adapter *adapter)
{
	__uint32_t	temp = 0;

	adapter->unm_nic_hw_write_wx(adapter, adapter->interrupt_crb,
	    &temp, 4);
}

static inline int
unm_nic_clear_int(unm_adapter *adapter)
{
	uint32_t	mask, temp, our_int, status;

	UNM_READ_LOCK(&adapter->adapter_lock);

	/* check whether it's our interrupt */
	if (!UNM_IS_MSI_FAMILY(adapter)) {

		/* Legacy Interrupt case */
		adapter->unm_nic_pci_read_immediate(adapter, ISR_INT_VECTOR,
		    &status);

		if (!(status & adapter->legacy_intr.int_vec_bit)) {
			UNM_READ_UNLOCK(&adapter->adapter_lock);
			return (-1);
		}

		if (adapter->ahw.revision_id >= NX_P3_B1) {
			adapter->unm_nic_pci_read_immediate(adapter,
			    ISR_INT_STATE_REG, &temp);
			if (!ISR_IS_LEGACY_INTR_TRIGGERED(temp)) {
				UNM_READ_UNLOCK(&adapter->adapter_lock);
				return (-1);
			}
		} else if (NX_IS_REVISION_P2(adapter->ahw.revision_id)) {
			our_int = adapter->unm_nic_pci_read_normalize(adapter,
			    CRB_INT_VECTOR);

			/* FIXME: Assumes pci_func is same as ctx */
			if ((our_int & (0x80 << adapter->portnum)) == 0) {
				if (our_int != 0) {
					/* not our interrupt */
					UNM_READ_UNLOCK(&adapter->adapter_lock);
					return (-1);
				}
			}
			temp = our_int & ~((u32)(0x80 << adapter->portnum));
			adapter->unm_nic_pci_write_normalize(adapter,
			    CRB_INT_VECTOR, temp);
		}

		if (adapter->fw_major < 4)
			unm_nic_disable_int(adapter);

		/* claim interrupt */
		temp = 0xffffffff;
		adapter->unm_nic_pci_write_immediate(adapter,
		    adapter->legacy_intr.tgt_status_reg, &temp);

		adapter->unm_nic_pci_read_immediate(adapter, ISR_INT_VECTOR,
		    &mask);

		/*
		 * Read again to make sure the legacy interrupt message got
		 * flushed out
		 */
		adapter->unm_nic_pci_read_immediate(adapter, ISR_INT_VECTOR,
		    &mask);
	} else if (adapter->flags & UNM_NIC_MSI_ENABLED) {
		/* clear interrupt */
		temp = 0xffffffff;
		adapter->unm_nic_pci_write_immediate(adapter,
		    msi_tgt_status[adapter->ahw.pci_func], &temp);
	}

	UNM_READ_UNLOCK(&adapter->adapter_lock);

	return (0);
}

static void
unm_nic_enable_int(unm_adapter *adapter)
{
	u32	temp = 1;

	adapter->unm_nic_hw_write_wx(adapter, adapter->interrupt_crb,
	    &temp, 4);

	if (!UNM_IS_MSI_FAMILY(adapter)) {
		u32	mask = 0xfbff;

		adapter->unm_nic_pci_write_immediate(adapter,
		    adapter->legacy_intr.tgt_mask_reg, &mask);
	}
}

static void
unm_free_hw_resources(unm_adapter *adapter)
{
	unm_recv_context_t *recv_ctx;
	unm_rcv_desc_ctx_t *rcv_desc;
	int ctx, ring;

	if (adapter->context_alloced == 1) {
		netxen_destroy_rxtx(adapter);
		adapter->context_alloced = 0;
	}

	if (adapter->ctxDesc != NULL) {
		unm_pci_free_consistent(&adapter->ctxDesc_dma_handle,
		    &adapter->ctxDesc_acc_handle);
		adapter->ctxDesc = NULL;
	}

	if (adapter->ahw.cmdDescHead != NULL) {
		unm_pci_free_consistent(&adapter->ahw.cmd_desc_dma_handle,
		    &adapter->ahw.cmd_desc_acc_handle);
		adapter->ahw.cmdDesc_physAddr = 0;
		adapter->ahw.cmdDescHead = NULL;
	}

	for (ctx = 0; ctx < MAX_RCV_CTX; ++ctx) {
		recv_ctx = &adapter->recv_ctx[ctx];
		for (ring = 0; ring < adapter->max_rds_rings; ring++) {
			rcv_desc = &recv_ctx->rcv_desc[ring];

			if (rcv_desc->desc_head != NULL) {
				unm_pci_free_consistent(
				    &rcv_desc->rx_desc_dma_handle,
				    &rcv_desc->rx_desc_acc_handle);
				rcv_desc->desc_head = NULL;
				rcv_desc->phys_addr = 0;
			}
		}

		if (recv_ctx->rcvStatusDescHead != NULL) {
			unm_pci_free_consistent(
			    &recv_ctx->status_desc_dma_handle,
			    &recv_ctx->status_desc_acc_handle);
			recv_ctx->rcvStatusDesc_physAddr = 0;
			recv_ctx->rcvStatusDescHead = NULL;
		}
	}
}

static void
cleanup_adapter(struct unm_adapter_s *adapter)
{
	ddi_regs_map_free(&(adapter->regs_handle));
	ddi_regs_map_free(&(adapter->db_handle));
	kmem_free(adapter, sizeof (unm_adapter));
}

void
unm_nic_remove(unm_adapter *adapter)
{
	mac_link_update(adapter->mach, LINK_STATE_DOWN);
	unm_nic_stop_port(adapter);

	if (adapter->interrupt_crb) {
		UNM_READ_LOCK(&adapter->adapter_lock);
		unm_nic_disable_int(adapter);
		UNM_READ_UNLOCK(&adapter->adapter_lock);
	}
	(void) untimeout(adapter->watchdog_timer);

	unm_free_hw_resources(adapter);

	if (adapter->is_up == UNM_ADAPTER_UP_MAGIC)
		destroy_rxtx_rings(adapter);

	if (adapter->portnum == 0)
		unm_free_dummy_dma(adapter);

	unm_destroy_intr(adapter);

	ddi_set_driver_private(adapter->dip, NULL);
	cleanup_adapter(adapter);
}

static int
init_firmware(unm_adapter *adapter)
{
	uint32_t state = 0, loops = 0, tempout;

	/* Window 1 call */
	UNM_READ_LOCK(&adapter->adapter_lock);
	state = adapter->unm_nic_pci_read_normalize(adapter, CRB_CMDPEG_STATE);
	UNM_READ_UNLOCK(&adapter->adapter_lock);

	if (state == PHAN_INITIALIZE_ACK)
		return (0);

	while (state != PHAN_INITIALIZE_COMPLETE && loops < 200000) {
		drv_usecwait(100);
		/* Window 1 call */
		UNM_READ_LOCK(&adapter->adapter_lock);
		state = adapter->unm_nic_pci_read_normalize(adapter,
		    CRB_CMDPEG_STATE);
		UNM_READ_UNLOCK(&adapter->adapter_lock);
		loops++;
	}

	if (loops >= 200000) {
		cmn_err(CE_WARN, "%s%d: CmdPeg init incomplete:%x\n",
		    adapter->name, adapter->instance, state);
		return (-EIO);
	}

	/* Window 1 call */
	UNM_READ_LOCK(&adapter->adapter_lock);
	tempout = INTR_SCHEME_PERPORT;
	adapter->unm_nic_hw_write_wx(adapter, CRB_NIC_CAPABILITIES_HOST,
	    &tempout, 4);
	tempout = MSI_MODE_MULTIFUNC;
	adapter->unm_nic_hw_write_wx(adapter, CRB_NIC_MSI_MODE_HOST,
	    &tempout, 4);
	tempout = MPORT_MULTI_FUNCTION_MODE;
	adapter->unm_nic_hw_write_wx(adapter, CRB_MPORT_MODE, &tempout, 4);
	tempout = PHAN_INITIALIZE_ACK;
	adapter->unm_nic_hw_write_wx(adapter, CRB_CMDPEG_STATE, &tempout, 4);
	UNM_READ_UNLOCK(&adapter->adapter_lock);

	return (0);
}

/*
 * Utility to synchronize with receive peg.
 *  Returns   0 on sucess
 *         -EIO on error
 */
int
receive_peg_ready(struct unm_adapter_s *adapter)
{
	uint32_t state = 0;
	int loops = 0, err = 0;

	/* Window 1 call */
	UNM_READ_LOCK(&adapter->adapter_lock);
	state = adapter->unm_nic_pci_read_normalize(adapter, CRB_RCVPEG_STATE);
	UNM_READ_UNLOCK(&adapter->adapter_lock);

	while ((state != PHAN_PEG_RCV_INITIALIZED) && (loops < 20000)) {
		drv_usecwait(100);
		/* Window 1 call */

		UNM_READ_LOCK(&adapter->adapter_lock);
		state = adapter->unm_nic_pci_read_normalize(adapter,
		    CRB_RCVPEG_STATE);
		UNM_READ_UNLOCK(&adapter->adapter_lock);

		loops++;
	}

	if (loops >= 20000) {
		cmn_err(CE_WARN, "Receive Peg initialization incomplete 0x%x\n",
		    state);
		err = -EIO;
	}

	return (err);
}

/*
 * check if the firmware has been downloaded and ready to run  and
 * setup the address for the descriptors in the adapter
 */
static int
unm_nic_hw_resources(unm_adapter *adapter)
{
	hardware_context	*hw = &adapter->ahw;
	void			*addr;
	int			err;
	int			ctx, ring;
	unm_recv_context_t	*recv_ctx;
	unm_rcv_desc_ctx_t	*rcv_desc;
	ddi_dma_cookie_t	cookie;
	int			size;

	if (err = receive_peg_ready(adapter))
		return (err);

	size = (sizeof (RingContext) + sizeof (uint32_t));

	err = unm_pci_alloc_consistent(adapter,
	    size, (caddr_t *)&addr, &cookie,
	    &adapter->ctxDesc_dma_handle,
	    &adapter->ctxDesc_acc_handle);
	if (err != DDI_SUCCESS) {
		cmn_err(CE_WARN, "Failed to allocate HW context\n");
		return (err);
	}

	adapter->ctxDesc_physAddr = cookie.dmac_laddress;

	(void) memset(addr, 0, sizeof (RingContext));

	adapter->ctxDesc = (RingContext *) addr;
	adapter->ctxDesc->CtxId = adapter->portnum;
	adapter->ctxDesc->CMD_CONSUMER_OFFSET =
	    adapter->ctxDesc_physAddr + sizeof (RingContext);
	adapter->cmdConsumer =
	    (uint32_t *)(uintptr_t)(((char *)addr) + sizeof (RingContext));

	ASSERT(!((unsigned long)adapter->ctxDesc_physAddr & 0x3f));

	/*
	 * Allocate command descriptor ring.
	 */
	size = (sizeof (cmdDescType0_t) * adapter->MaxTxDescCount);
	err = unm_pci_alloc_consistent(adapter,
	    size, (caddr_t *)&addr, &cookie,
	    &hw->cmd_desc_dma_handle,
	    &hw->cmd_desc_acc_handle);
	if (err != DDI_SUCCESS) {
		cmn_err(CE_WARN, "Failed to allocate cmd desc ring\n");
		return (err);
	}

	hw->cmdDesc_physAddr = cookie.dmac_laddress;
	hw->cmdDescHead = (cmdDescType0_t *)addr;

	for (ctx = 0; ctx < MAX_RCV_CTX; ++ctx) {
		recv_ctx = &adapter->recv_ctx[ctx];

		size = (sizeof (statusDesc_t)* adapter->MaxRxDescCount);
		err = unm_pci_alloc_consistent(adapter,
		    size, (caddr_t *)&addr,
		    &recv_ctx->status_desc_dma_cookie,
		    &recv_ctx->status_desc_dma_handle,
		    &recv_ctx->status_desc_acc_handle);
		if (err != DDI_SUCCESS) {
			cmn_err(CE_WARN, "Failed to allocate sts desc ring\n");
			goto free_cmd_desc;
		}

		(void) memset(addr, 0, size);
		recv_ctx->rcvStatusDesc_physAddr =
		    recv_ctx->status_desc_dma_cookie.dmac_laddress;
		recv_ctx->rcvStatusDescHead = (statusDesc_t *)addr;

		/* rds rings */
		for (ring = 0; ring < adapter->max_rds_rings; ring++) {
			rcv_desc = &recv_ctx->rcv_desc[ring];

			size = (sizeof (rcvDesc_t) * adapter->MaxRxDescCount);
			err = unm_pci_alloc_consistent(adapter,
			    size, (caddr_t *)&addr,
			    &rcv_desc->rx_desc_dma_cookie,
			    &rcv_desc->rx_desc_dma_handle,
			    &rcv_desc->rx_desc_acc_handle);
			if (err != DDI_SUCCESS) {
				cmn_err(CE_WARN, "Failed to allocate "
				    "rx desc ring %d\n", ring);
				goto free_status_desc;
			}

			rcv_desc->phys_addr =
			    rcv_desc->rx_desc_dma_cookie.dmac_laddress;
			rcv_desc->desc_head = (rcvDesc_t *)addr;
		}
	}

	if (err = netxen_create_rxtx(adapter))
		goto free_statusrx_desc;
	adapter->context_alloced = 1;

	return (DDI_SUCCESS);

free_statusrx_desc:
free_status_desc:
free_cmd_desc:
	unm_free_hw_resources(adapter);

	return (err);
}

void unm_desc_dma_sync(ddi_dma_handle_t handle, uint_t start, uint_t count,
    uint_t range, uint_t unit_size, uint_t direction)
{
	if ((start + count) < range) {
		(void) ddi_dma_sync(handle, start * unit_size,
		    count * unit_size, direction);
	} else {
		(void) ddi_dma_sync(handle, start * unit_size, 0, direction);
		(void) ddi_dma_sync(handle, 0,
		    (start + count - range) * unit_size, DDI_DMA_SYNC_FORCPU);
	}
}

static uint32_t crb_cmd_producer[4] = { CRB_CMD_PRODUCER_OFFSET,
    CRB_CMD_PRODUCER_OFFSET_1, CRB_CMD_PRODUCER_OFFSET_2,
    CRB_CMD_PRODUCER_OFFSET_3 };

static uint32_t crb_cmd_consumer[4] = { CRB_CMD_CONSUMER_OFFSET,
    CRB_CMD_CONSUMER_OFFSET_1, CRB_CMD_CONSUMER_OFFSET_2,
    CRB_CMD_CONSUMER_OFFSET_3 };

void
unm_nic_update_cmd_producer(struct unm_adapter_s *adapter,
    uint32_t crb_producer)
{
	int data = crb_producer;

	if (adapter->crb_addr_cmd_producer) {
		UNM_READ_LOCK(&adapter->adapter_lock);
		adapter->unm_nic_hw_write_wx(adapter,
		    adapter->crb_addr_cmd_producer, &data, 4);
		UNM_READ_UNLOCK(&adapter->adapter_lock);
	}
}

static void
unm_nic_update_cmd_consumer(struct unm_adapter_s *adapter,
    uint32_t crb_producer)
{
	int data = crb_producer;

	if (adapter->crb_addr_cmd_consumer)
		adapter->unm_nic_hw_write_wx(adapter,
		    adapter->crb_addr_cmd_consumer, &data, 4);
}

/*
 * Looks for type of packet and sets opcode accordingly
 * so that checksum offload can be used.
 */
static void
unm_tx_csum(cmdDescType0_t *desc, mblk_t *mp, pktinfo_t *pktinfo)
{
	if (pktinfo->mac_hlen == sizeof (struct ether_vlan_header))
		desc->u1.s1.flags = FLAGS_VLAN_TAGGED;

	if (pktinfo->etype == htons(ETHERTYPE_IP)) {
		uint32_t	start, flags;

		mac_hcksum_get(mp, &start, NULL, NULL, NULL, &flags);
		if ((flags & (HCK_FULLCKSUM | HCK_IPV4_HDRCKSUM)) == 0)
			return;

		/*
		 * For TCP/UDP, ask hardware to do both IP header and
		 * full checksum, even if stack has already done one or
		 * the other. Hardware will always get it correct even
		 * if stack has already done it.
		 */
		switch (pktinfo->l4_proto) {
			case IPPROTO_TCP:
				desc->u1.s1.opcode = TX_TCP_PKT;
				break;
			case IPPROTO_UDP:
				desc->u1.s1.opcode = TX_UDP_PKT;
				break;
			default:
				/* Must be here with HCK_IPV4_HDRCKSUM */
				desc->u1.s1.opcode = TX_IP_PKT;
				return;
		}

		desc->u1.s1.ipHdrOffset = pktinfo->mac_hlen;
		desc->u1.s1.tcpHdrOffset = pktinfo->mac_hlen + pktinfo->ip_hlen;
	}
}

/*
 * For IP/UDP/TCP checksum offload, this checks for MAC+IP header in one
 * contiguous block ending at 8 byte aligned address as required by hardware.
 * Caller assumes pktinfo->total_len will be updated by this function and
 * if pktinfo->etype is set to 0, it will need to linearize the mblk and
 * invoke unm_update_pkt_info() to determine ethertype, IP header len and
 * protocol.
 */
static boolean_t
unm_get_pkt_info(mblk_t *mp, pktinfo_t *pktinfo)
{
	mblk_t		*bp;
	ushort_t	type;

	(void) memset(pktinfo, 0, sizeof (pktinfo_t));

	for (bp = mp; bp != NULL; bp = bp->b_cont) {
		if (MBLKL(bp) == 0)
			continue;
		pktinfo->mblk_no++;
		pktinfo->total_len += MBLKL(bp);
	}

	if (MBLKL(mp) < (sizeof (struct ether_header) + sizeof (ipha_t)))
		return (B_FALSE);

	/*
	 * We just need non 1 byte aligned address, since ether_type is
	 * ushort.
	 */
	if ((uintptr_t)mp->b_rptr & 1)
		return (B_FALSE);

	type = ((struct ether_header *)(uintptr_t)mp->b_rptr)->ether_type;
	if (type == htons(ETHERTYPE_VLAN)) {
		if (MBLKL(mp) < (sizeof (struct ether_vlan_header) +
		    sizeof (ipha_t)))
			return (B_FALSE);
		type = ((struct ether_vlan_header *) \
		    (uintptr_t)mp->b_rptr)->ether_type;
		pktinfo->mac_hlen = sizeof (struct ether_vlan_header);
	} else {
		pktinfo->mac_hlen = sizeof (struct ether_header);
	}
	pktinfo->etype = type;

	if (pktinfo->etype == htons(ETHERTYPE_IP)) {
		uchar_t *ip_off = mp->b_rptr + pktinfo->mac_hlen;

		pktinfo->ip_hlen = IPH_HDR_LENGTH((uintptr_t)ip_off);
		pktinfo->l4_proto =
		    ((ipha_t *)(uintptr_t)ip_off)->ipha_protocol;

		/* IP header not aligned to quadward boundary? */
		if ((unsigned long)(ip_off + pktinfo->ip_hlen) % 8 != 0)
			return (B_FALSE);
	}

	return (B_TRUE);
}

static void
unm_update_pkt_info(char *ptr, pktinfo_t *pktinfo)
{
	ushort_t	type;

	type = ((struct ether_header *)(uintptr_t)ptr)->ether_type;
	if (type == htons(ETHERTYPE_VLAN)) {
		type = ((struct ether_vlan_header *)(uintptr_t)ptr)->ether_type;
		pktinfo->mac_hlen = sizeof (struct ether_vlan_header);
	} else {
		pktinfo->mac_hlen = sizeof (struct ether_header);
	}
	pktinfo->etype = type;

	if (pktinfo->etype == htons(ETHERTYPE_IP)) {
		char *ipp = ptr + pktinfo->mac_hlen;

		pktinfo->ip_hlen = IPH_HDR_LENGTH((uintptr_t)ipp);
		pktinfo->l4_proto = ((ipha_t *)(uintptr_t)ipp)->ipha_protocol;
	}
}

static boolean_t
unm_send_copy(struct unm_adapter_s *adapter, mblk_t *mp, pktinfo_t *pktinfo)
{
	hardware_context *hw;
	u32				producer = 0;
	cmdDescType0_t			*hwdesc;
	struct unm_cmd_buffer		*pbuf = NULL;
	u32				mblen;
	int				no_of_desc = 1;
	int				MaxTxDescCount;
	mblk_t				*bp;
	char				*txb;

	hw = &adapter->ahw;
	MaxTxDescCount = adapter->MaxTxDescCount;

	UNM_SPIN_LOCK(&adapter->tx_lock);
	membar_enter();

	if (find_diff_among(adapter->cmdProducer, adapter->lastCmdConsumer,
	    MaxTxDescCount) <= 2) {
		adapter->stats.outofcmddesc++;
		adapter->resched_needed = 1;
		membar_exit();
		UNM_SPIN_UNLOCK(&adapter->tx_lock);
		return (B_FALSE);
	}
	adapter->freecmds -= no_of_desc;

	producer = adapter->cmdProducer;

	adapter->cmdProducer = get_index_range(adapter->cmdProducer,
	    MaxTxDescCount, no_of_desc);

	hwdesc = &hw->cmdDescHead[producer];
	(void) memset(hwdesc, 0, sizeof (cmdDescType0_t));
	pbuf = &adapter->cmd_buf_arr[producer];

	pbuf->msg = NULL;
	pbuf->head = NULL;
	pbuf->tail = NULL;

	txb = pbuf->dma_area.vaddr;

	for (bp = mp; bp != NULL; bp = bp->b_cont) {
		if ((mblen = MBLKL(bp)) == 0)
			continue;
		bcopy(bp->b_rptr, txb, mblen);
		txb += mblen;
	}

	/*
	 * Determine metadata if not previously done due to fragmented mblk.
	 */
	if (pktinfo->etype == 0)
		unm_update_pkt_info(pbuf->dma_area.vaddr, pktinfo);

	(void) ddi_dma_sync(pbuf->dma_area.dma_hdl,
	    0, pktinfo->total_len, DDI_DMA_SYNC_FORDEV);

	/* hwdesc->u1.s1.tcpHdrOffset = 0; */
	/* hwdesc->mss = 0; */
	hwdesc->u1.s1.opcode = TX_ETHER_PKT;
	hwdesc->u3.s1.port = adapter->portnum;
	hwdesc->u3.s1.ctx_id = adapter->portnum;

	hwdesc->u6.s1.buffer1Length = pktinfo->total_len;
	hwdesc->u5.AddrBuffer1 = pbuf->dma_area.dma_addr;
	hwdesc->u1.s1.numOfBuffers = 1;
	hwdesc->u1.s1.totalLength = pktinfo->total_len;

	unm_tx_csum(hwdesc, mp, pktinfo);

	unm_desc_dma_sync(hw->cmd_desc_dma_handle,
	    producer,
	    no_of_desc,
	    MaxTxDescCount,
	    sizeof (cmdDescType0_t),
	    DDI_DMA_SYNC_FORDEV);

	hw->cmdProducer = adapter->cmdProducer;
	unm_nic_update_cmd_producer(adapter, adapter->cmdProducer);

	adapter->stats.txbytes += pktinfo->total_len;
	adapter->stats.xmitfinished++;
	adapter->stats.txcopyed++;
	UNM_SPIN_UNLOCK(&adapter->tx_lock);

	freemsg(mp);
	return (B_TRUE);
}

/* Should be called with adapter->tx_lock held. */
static void
unm_return_dma_handle(unm_adapter *adapter, unm_dmah_node_t *head,
    unm_dmah_node_t *tail, uint32_t num)
{
	ASSERT(tail != NULL);
	tail->next = adapter->dmahdl_pool;
	adapter->dmahdl_pool = head;
	adapter->freehdls += num;
}

static unm_dmah_node_t *
unm_reserve_dma_handle(unm_adapter* adapter)
{
	unm_dmah_node_t *dmah = NULL;

	dmah = adapter->dmahdl_pool;
	if (dmah != NULL) {
		adapter->dmahdl_pool = dmah->next;
		dmah->next = NULL;
		adapter->freehdls--;
		membar_exit();
	}

	return (dmah);
}

static boolean_t
unm_send_mapped(struct unm_adapter_s *adapter, mblk_t *mp, pktinfo_t *pktinfo)
{
	hardware_context		*hw;
	u32				producer = 0;
	u32				saved_producer = 0;
	cmdDescType0_t			*hwdesc;
	struct unm_cmd_buffer		*pbuf = NULL;
	int				no_of_desc;
	int				k;
	int				MaxTxDescCount;
	mblk_t				*bp;

	unm_dmah_node_t *dmah, *head = NULL, *tail = NULL, *hdlp;
	ddi_dma_cookie_t cookie[MAX_COOKIES_PER_CMD + 1];
	int ret, i;
	uint32_t hdl_reserved = 0;
	uint32_t mblen;
	uint32_t ncookies, index = 0, total_cookies = 0;

	MaxTxDescCount = adapter->MaxTxDescCount;

	UNM_SPIN_LOCK(&adapter->tx_lock);

	/* bind all the mblks of the packet first */
	for (bp = mp; bp != NULL; bp = bp->b_cont) {
		mblen = MBLKL(bp);
		if (mblen == 0)
			continue;

		dmah = unm_reserve_dma_handle(adapter);
		if (dmah == NULL) {
			adapter->stats.outoftxdmahdl++;
			goto err_map;
		}

		ret = ddi_dma_addr_bind_handle(dmah->dmahdl,
		    NULL, (caddr_t)bp->b_rptr, mblen,
		    DDI_DMA_STREAMING | DDI_DMA_WRITE,
		    DDI_DMA_DONTWAIT, NULL, &cookie[index], &ncookies);

		if (ret != DDI_DMA_MAPPED)
			goto err_map;

		if (tail == NULL) {
			head = tail = dmah;
		} else {
			tail->next = dmah;
			tail = dmah;
		}
		hdl_reserved++;

		total_cookies += ncookies;
		if (total_cookies > MAX_COOKIES_PER_CMD) {
			dmah = NULL;
			goto err_map;
		}

		if (index == 0) {
			size_t	hsize = cookie[0].dmac_size;

			/*
			 * For TCP/UDP packets with checksum offload,
			 * MAC/IP headers need to be contiguous. Otherwise,
			 * there must be at least 16 bytes in the first
			 * descriptor.
			 */
			if ((pktinfo->l4_proto == IPPROTO_TCP) ||
			    (pktinfo->l4_proto == IPPROTO_UDP)) {
				if (hsize < (pktinfo->mac_hlen +
				    pktinfo->ip_hlen)) {
					dmah = NULL;
					goto err_map;
				}
			} else {
				if (hsize < 16) {
					dmah = NULL;
					goto err_map;
				}
			}
		}

		index++;
		ncookies--;
		for (i = 0; i < ncookies; i++, index++)
			ddi_dma_nextcookie(dmah->dmahdl, &cookie[index]);
	}

	dmah = NULL;
	hw = &adapter->ahw;
	no_of_desc = (total_cookies + 3) >> 2;

	membar_enter();
	if (find_diff_among(adapter->cmdProducer, adapter->lastCmdConsumer,
	    MaxTxDescCount) < no_of_desc+2) {
		/*
		 * If we are going to be trying the copy path, no point
		 * scheduling an upcall when Tx resources are freed.
		 */
		if (pktinfo->total_len > adapter->maxmtu) {
			adapter->stats.outofcmddesc++;
			adapter->resched_needed = 1;
		}
		membar_exit();
		goto err_alloc_desc;
	}
	adapter->freecmds -= no_of_desc;

	/* Copy the descriptors into the hardware    */
	producer = adapter->cmdProducer;
	saved_producer = producer;
	hwdesc = &hw->cmdDescHead[producer];
	(void) memset(hwdesc, 0, sizeof (cmdDescType0_t));
	pbuf = &adapter->cmd_buf_arr[producer];

	pbuf->msg = mp;
	pbuf->head = head;
	pbuf->tail = tail;

	hwdesc->u1.s1.numOfBuffers = total_cookies;
	hwdesc->u1.s1.opcode = TX_ETHER_PKT;
	hwdesc->u3.s1.port = adapter->portnum;
	/* hwdesc->u1.s1.tcpHdrOffset = 0; */
	/* hwdesc->mss = 0; */
	hwdesc->u3.s1.ctx_id = adapter->portnum;
	hwdesc->u1.s1.totalLength = pktinfo->total_len;
	unm_tx_csum(hwdesc, mp, pktinfo);

	for (i = k = 0; i < total_cookies; i++) {
		if (k == 4) {
			/* Move to the next descriptor */
			k = 0;
			producer = get_next_index(producer, MaxTxDescCount);
			hwdesc = &hw->cmdDescHead[producer];
			(void) memset(hwdesc, 0, sizeof (cmdDescType0_t));
		}

		switch (k) {
		case 0:
			hwdesc->u6.s1.buffer1Length = cookie[i].dmac_size;
			hwdesc->u5.AddrBuffer1 = cookie[i].dmac_laddress;
			break;
		case 1:
			hwdesc->u6.s1.buffer2Length = cookie[i].dmac_size;
			hwdesc->u2.AddrBuffer2 = cookie[i].dmac_laddress;
			break;
		case 2:
			hwdesc->u6.s1.buffer3Length = cookie[i].dmac_size;
			hwdesc->u4.AddrBuffer3 = cookie[i].dmac_laddress;
			break;
		case 3:
			hwdesc->u6.s1.buffer4Length = cookie[i].dmac_size;
			hwdesc->u7.AddrBuffer4 = cookie[i].dmac_laddress;
			break;
		}
		k++;
	}

	unm_desc_dma_sync(hw->cmd_desc_dma_handle, saved_producer, no_of_desc,
	    MaxTxDescCount, sizeof (cmdDescType0_t), DDI_DMA_SYNC_FORDEV);

	adapter->cmdProducer = get_next_index(producer, MaxTxDescCount);
	hw->cmdProducer = adapter->cmdProducer;
	unm_nic_update_cmd_producer(adapter, adapter->cmdProducer);

	adapter->stats.txbytes += pktinfo->total_len;
	adapter->stats.xmitfinished++;
	adapter->stats.txmapped++;
	UNM_SPIN_UNLOCK(&adapter->tx_lock);
	return (B_TRUE);

err_alloc_desc:
err_map:

	hdlp = head;
	while (hdlp != NULL) {
		(void) ddi_dma_unbind_handle(hdlp->dmahdl);
		hdlp = hdlp->next;
	}

	/*
	 * add the reserved but bind failed one to the list to be returned
	 */
	if (dmah != NULL) {
		if (tail == NULL)
			head = tail = dmah;
		else {
			tail->next = dmah;
			tail = dmah;
		}
		hdl_reserved++;
	}

	if (head != NULL)
		unm_return_dma_handle(adapter, head, tail, hdl_reserved);

	UNM_SPIN_UNLOCK(&adapter->tx_lock);
	return (B_FALSE);
}

static boolean_t
unm_nic_xmit_frame(unm_adapter *adapter, mblk_t *mp)
{
	pktinfo_t	pktinfo;
	boolean_t	status = B_FALSE, send_mapped;

	adapter->stats.xmitcalled++;

	send_mapped = unm_get_pkt_info(mp, &pktinfo);

	if (pktinfo.total_len <= adapter->tx_bcopy_threshold ||
	    pktinfo.mblk_no >= MAX_COOKIES_PER_CMD)
		send_mapped = B_FALSE;

	if (send_mapped == B_TRUE)
		status = unm_send_mapped(adapter, mp, &pktinfo);

	if (status != B_TRUE) {
		if (pktinfo.total_len <= adapter->maxmtu)
			return (unm_send_copy(adapter, mp, &pktinfo));

		/* message too large */
		freemsg(mp);
		adapter->stats.txdropped++;
		status = B_TRUE;
	}

	return (status);
}

static int
unm_nic_check_temp(struct unm_adapter_s *adapter)
{
	uint32_t temp, temp_state, temp_val;
	int rv = 0;

	if ((adapter->ahw.revision_id == NX_P3_A2) ||
	    (adapter->ahw.revision_id == NX_P3_A0))
		return (0);

	temp = adapter->unm_nic_pci_read_normalize(adapter, CRB_TEMP_STATE);

	temp_state = nx_get_temp_state(temp);
	temp_val = nx_get_temp_val(temp);

	if (temp_state == NX_TEMP_PANIC) {
		cmn_err(CE_WARN, "%s: Device temperature %d C exceeds "
		    "maximum allowed, device has been shut down\n",
		    unm_nic_driver_name, temp_val);
		rv = 1;
	} else if (temp_state == NX_TEMP_WARN) {
		if (adapter->temp == NX_TEMP_NORMAL) {
		cmn_err(CE_WARN, "%s: Device temperature %d C exceeds"
		    "operating range. Immediate action needed.\n",
		    unm_nic_driver_name, temp_val);
		}
	} else {
		if (adapter->temp == NX_TEMP_WARN) {
			cmn_err(CE_WARN, "%s: Device temperature is now %d "
			    "degrees C in normal range.\n",
			    unm_nic_driver_name, temp_val);
		}
	}

	adapter->temp = temp_state;
	return (rv);
}

static void
unm_watchdog(unsigned long v)
{
	unm_adapter *adapter = (unm_adapter *)v;

	if ((adapter->portnum == 0) && unm_nic_check_temp(adapter)) {
		/*
		 * We return without turning on the netdev queue as there
		 * was an overheated device
		 */
		return;
	}

	unm_nic_handle_phy_intr(adapter);

	/*
	 * This function schedules a call for itself.
	 */
	adapter->watchdog_timer = timeout((void (*)(void *))&unm_watchdog,
	    (void *)adapter, 2 * drv_usectohz(1000000));

}

static void unm_nic_clear_stats(unm_adapter *adapter)
{
	(void) memset(&adapter->stats, 0, sizeof (adapter->stats));
}

static void
unm_nic_poll(unm_adapter *adapter)
{
	int	work_done, tx_complete;

	adapter->stats.polled++;

loop:
	tx_complete = unm_process_cmd_ring(adapter);
	work_done = unm_process_rcv_ring(adapter, NX_RX_MAXBUFS);
	if ((!tx_complete) || (!(work_done < NX_RX_MAXBUFS)))
		goto loop;

	UNM_READ_LOCK(&adapter->adapter_lock);
	unm_nic_enable_int(adapter);
	UNM_READ_UNLOCK(&adapter->adapter_lock);
}

/* ARGSUSED */
uint_t
unm_intr(caddr_t data, caddr_t arg)
{
	unm_adapter	*adapter = (unm_adapter *)(uintptr_t)data;

	if (unm_nic_clear_int(adapter))
		return (DDI_INTR_UNCLAIMED);

	unm_nic_poll(adapter);
	return (DDI_INTR_CLAIMED);
}

/*
 * This is invoked from receive isr. Due to the single threaded nature
 * of the invocation, pool_lock acquisition is not neccesary to protect
 * pool_list.
 */
static void
unm_free_rx_buffer(unm_rcv_desc_ctx_t *rcv_desc, unm_rx_buffer_t *rx_buffer)
{
	/* mutex_enter(rcv_desc->pool_lock); */
	rx_buffer->next = rcv_desc->pool_list;
	rcv_desc->pool_list = rx_buffer;
	rcv_desc->rx_buf_free++;
	/* mutex_exit(rcv_desc->pool_lock); */
}

/*
 * unm_process_rcv() send the received packet to the protocol stack.
 */
static mblk_t *
unm_process_rcv(unm_adapter *adapter, statusDesc_t *desc)
{
	unm_recv_context_t	*recv_ctx = &(adapter->recv_ctx[0]);
	unm_rx_buffer_t		*rx_buffer;
	mblk_t *mp;
	u32			desc_ctx = desc->u1.s1.type;
	unm_rcv_desc_ctx_t	*rcv_desc = &recv_ctx->rcv_desc[desc_ctx];
	u32			pkt_length = desc->u1.s1.totalLength;
	int			poff = desc->u1.s1.pkt_offset;
	int			index, cksum_flags, docopy;
	int			index_lo = desc->u1.s1.referenceHandle_lo;
	char			*vaddr;

	index = ((desc->u1.s1.referenceHandle_hi << 4) | index_lo);

	rx_buffer = index2rxbuf(rcv_desc, index);

	if (rx_buffer == NULL) {
		cmn_err(CE_WARN, "\r\nNULL rx_buffer idx=%d", index);
		return (NULL);
	}
	vaddr = (char *)rx_buffer->dma_info.vaddr;
	if (vaddr == NULL) {
		cmn_err(CE_WARN, "\r\nNULL vaddr");
		return (NULL);
	}
	rcv_desc->rx_desc_handled++;
	rcv_desc->rx_buf_card--;

	(void) ddi_dma_sync(rx_buffer->dma_info.dma_hdl, 0,
	    pkt_length + poff + (adapter->ahw.cut_through ? 0 :
	    IP_ALIGNMENT_BYTES), DDI_DMA_SYNC_FORCPU);

	/*
	 * Copy packet into new allocated message buffer, if pkt_length
	 * is below copy threshold.
	 */
	docopy = (pkt_length <= adapter->rx_bcopy_threshold) ? 1 : 0;

	/*
	 * If card is running out of rx buffers, then attempt to allocate
	 * new mblk so we can feed this rx buffer back to card (we
	 * _could_ look at what's pending on free and recycle lists).
	 */
	if (rcv_desc->rx_buf_card < NX_RX_THRESHOLD) {
		docopy = 1;
		adapter->stats.rxbufshort++;
	}

	if (docopy == 1) {
		if ((mp = allocb(pkt_length + IP_ALIGNMENT_BYTES, 0)) == NULL) {
			adapter->stats.allocbfailed++;
			goto freebuf;
		}

		mp->b_rptr += IP_ALIGNMENT_BYTES;
		vaddr += poff;
		bcopy(vaddr, mp->b_rptr, pkt_length);
		adapter->stats.rxcopyed++;
		unm_free_rx_buffer(rcv_desc, rx_buffer);
	} else {
		mp = (mblk_t *)rx_buffer->mp;
		if (mp == NULL) {
			mp = desballoc(rx_buffer->dma_info.vaddr,
			    rcv_desc->dma_size, 0, &rx_buffer->rx_recycle);
			if (mp == NULL) {
				adapter->stats.desballocfailed++;
				goto freebuf;
			}
			rx_buffer->mp = mp;
		}
		mp->b_rptr += poff;
		adapter->stats.rxmapped++;
	}

	mp->b_wptr = (uchar_t *)((unsigned long)mp->b_rptr + pkt_length);

	if (desc->u1.s1.status == STATUS_CKSUM_OK) {
		adapter->stats.csummed++;
		cksum_flags =
		    HCK_FULLCKSUM_OK | HCK_IPV4_HDRCKSUM_OK;
	} else {
		cksum_flags = 0;
	}
	mac_hcksum_set(mp, 0, 0, 0, 0, cksum_flags);

	adapter->stats.no_rcv++;
	adapter->stats.rxbytes += pkt_length;
	adapter->stats.uphappy++;

	return (mp);

freebuf:
	unm_free_rx_buffer(rcv_desc, rx_buffer);
	return (NULL);
}

/* Process Receive status ring */
static int
unm_process_rcv_ring(unm_adapter *adapter, int max)
{
	unm_recv_context_t	*recv_ctx = &(adapter->recv_ctx[0]);
	statusDesc_t		*desc_head = recv_ctx->rcvStatusDescHead;
	statusDesc_t		*desc = NULL;
	uint32_t		consumer, start;
	int			count = 0, ring;
	mblk_t *mp;

	start = consumer = recv_ctx->statusRxConsumer;

	unm_desc_dma_sync(recv_ctx->status_desc_dma_handle, start, max,
	    adapter->MaxRxDescCount, sizeof (statusDesc_t),
	    DDI_DMA_SYNC_FORCPU);

	while (count < max) {
		desc = &desc_head[consumer];
		if (!(desc->u1.s1.owner & STATUS_OWNER_HOST))
			break;

		mp = unm_process_rcv(adapter, desc);
		desc->u1.s1.owner = STATUS_OWNER_PHANTOM;

		consumer = (consumer + 1) % adapter->MaxRxDescCount;
		count++;
		if (mp != NULL)
			mac_rx(adapter->mach, NULL, mp);
	}

	for (ring = 0; ring < adapter->max_rds_rings; ring++) {
		if (recv_ctx->rcv_desc[ring].rx_desc_handled > 0)
			unm_post_rx_buffers_nodb(adapter, ring);
	}

	if (count) {
		unm_desc_dma_sync(recv_ctx->status_desc_dma_handle, start,
		    count, adapter->MaxRxDescCount, sizeof (statusDesc_t),
		    DDI_DMA_SYNC_FORDEV);

		/* update the consumer index in phantom */
		recv_ctx->statusRxConsumer = consumer;

		UNM_READ_LOCK(&adapter->adapter_lock);
		adapter->unm_nic_hw_write_wx(adapter,
		    recv_ctx->host_sds_consumer, &consumer, 4);
		UNM_READ_UNLOCK(&adapter->adapter_lock);
	}

	return (count);
}

/* Process Command status ring */
static int
unm_process_cmd_ring(struct unm_adapter_s *adapter)
{
	u32			last_consumer;
	u32			consumer;
	int			count = 0;
	struct unm_cmd_buffer	*buffer;
	int			done;
	unm_dmah_node_t *dmah, *head = NULL, *tail = NULL;
	uint32_t	free_hdls = 0;

	(void) ddi_dma_sync(adapter->ctxDesc_dma_handle, sizeof (RingContext),
	    sizeof (uint32_t), DDI_DMA_SYNC_FORCPU);

	last_consumer = adapter->lastCmdConsumer;
	consumer = *(adapter->cmdConsumer);

	while (last_consumer != consumer) {
		buffer = &adapter->cmd_buf_arr[last_consumer];
		if (buffer->head != NULL) {
			dmah = buffer->head;
			while (dmah != NULL) {
				(void) ddi_dma_unbind_handle(dmah->dmahdl);
				dmah = dmah->next;
				free_hdls++;
			}

			if (head == NULL) {
				head = buffer->head;
				tail = buffer->tail;
			} else {
				tail->next = buffer->head;
				tail = buffer->tail;
			}

			buffer->head = NULL;
			buffer->tail = NULL;

			if (buffer->msg != NULL) {
				freemsg(buffer->msg);
				buffer->msg = NULL;
			}
		}

		last_consumer = get_next_index(last_consumer,
		    adapter->MaxTxDescCount);
		if (++count > NX_MAX_TXCOMPS)
			break;
	}

	if (count) {
		int	doresched;

		UNM_SPIN_LOCK(&adapter->tx_lock);
		adapter->lastCmdConsumer = last_consumer;
		adapter->freecmds += count;
		membar_exit();

		doresched = adapter->resched_needed;
		if (doresched)
			adapter->resched_needed = 0;

		if (head != NULL)
			unm_return_dma_handle(adapter, head, tail, free_hdls);

		UNM_SPIN_UNLOCK(&adapter->tx_lock);

		if (doresched)
			mac_tx_update(adapter->mach);
	}

	(void) ddi_dma_sync(adapter->ctxDesc_dma_handle, sizeof (RingContext),
	    sizeof (uint32_t), DDI_DMA_SYNC_FORCPU);

	consumer = *(adapter->cmdConsumer);
	done = (adapter->lastCmdConsumer == consumer);

	return (done);
}

/*
 * This is invoked from receive isr, and at initialization time when no
 * rx buffers have been posted to card. Due to the single threaded nature
 * of the invocation, pool_lock acquisition is not neccesary to protect
 * pool_list.
 */
static unm_rx_buffer_t *
unm_reserve_rx_buffer(unm_rcv_desc_ctx_t *rcv_desc)
{
	unm_rx_buffer_t *rx_buffer = NULL;

	/* mutex_enter(rcv_desc->pool_lock); */
	if (rcv_desc->rx_buf_free) {
		rx_buffer = rcv_desc->pool_list;
		rcv_desc->pool_list = rx_buffer->next;
		rx_buffer->next = NULL;
		rcv_desc->rx_buf_free--;
	} else {
		mutex_enter(rcv_desc->recycle_lock);

		if (rcv_desc->rx_buf_recycle) {
			rcv_desc->pool_list = rcv_desc->recycle_list;
			rcv_desc->recycle_list = NULL;
			rcv_desc->rx_buf_free += rcv_desc->rx_buf_recycle;
			rcv_desc->rx_buf_recycle = 0;

			rx_buffer = rcv_desc->pool_list;
			rcv_desc->pool_list = rx_buffer->next;
			rx_buffer->next = NULL;
			rcv_desc->rx_buf_free--;
		}

		mutex_exit(rcv_desc->recycle_lock);
	}

	/* mutex_exit(rcv_desc->pool_lock); */
	return (rx_buffer);
}

static void
post_rx_doorbell(struct unm_adapter_s *adapter, uint32_t ringid, int count)
{
#define	UNM_RCV_PEG_DB_ID	2
#define	UNM_RCV_PRODUCER_OFFSET	0
	ctx_msg msg = {0};

	/*
	 * Write a doorbell msg to tell phanmon of change in
	 * receive ring producer
	 */
	msg.PegId = UNM_RCV_PEG_DB_ID;
	msg.privId = 1;
	msg.Count = count;
	msg.CtxId = adapter->portnum;
	msg.Opcode = UNM_RCV_PRODUCER(ringid);
	dbwritel(*((__uint32_t *)&msg),
	    (void *)(DB_NORMALIZE(adapter, UNM_RCV_PRODUCER_OFFSET)));
}

static int
unm_post_rx_buffers(struct unm_adapter_s *adapter, uint32_t ringid)
{
	unm_recv_context_t	*recv_ctx = &(adapter->recv_ctx[0]);
	unm_rcv_desc_ctx_t	*rcv_desc = &recv_ctx->rcv_desc[ringid];
	unm_rx_buffer_t		*rx_buffer;
	rcvDesc_t		*pdesc;
	int			count;

	for (count = 0; count < rcv_desc->MaxRxDescCount; count++) {
		rx_buffer = unm_reserve_rx_buffer(rcv_desc);
		if (rx_buffer != NULL) {
			pdesc = &rcv_desc->desc_head[count];
			pdesc->referenceHandle = rxbuf2index(rcv_desc,
			    rx_buffer);
			pdesc->flags = ringid;
			pdesc->bufferLength = rcv_desc->dma_size;
			pdesc->AddrBuffer = rx_buffer->dma_info.dma_addr;
		}
		else
			return (DDI_FAILURE);
	}

	rcv_desc->producer = count % rcv_desc->MaxRxDescCount;
	count--;
	unm_desc_dma_sync(rcv_desc->rx_desc_dma_handle,
	    0,		/* start */
	    count,	/* count */
	    count,	/* range */
	    sizeof (rcvDesc_t),	/* unit_size */
	    DDI_DMA_SYNC_FORDEV);	/* direction */

	rcv_desc->rx_buf_card = rcv_desc->MaxRxDescCount;
	UNM_READ_LOCK(&adapter->adapter_lock);
	adapter->unm_nic_hw_write_wx(adapter, rcv_desc->host_rx_producer,
	    &count, 4);
	if (adapter->fw_major < 4)
		post_rx_doorbell(adapter, ringid, count);
	UNM_READ_UNLOCK(&adapter->adapter_lock);

	return (DDI_SUCCESS);
}

static void
unm_post_rx_buffers_nodb(struct unm_adapter_s *adapter,
    uint32_t ringid)
{
	unm_recv_context_t	*recv_ctx = &(adapter->recv_ctx[0]);
	unm_rcv_desc_ctx_t	*rcv_desc = &recv_ctx->rcv_desc[ringid];
	struct unm_rx_buffer	*rx_buffer;
	rcvDesc_t		*pdesc;
	int 			count, producer = rcv_desc->producer;
	int 			last_producer = producer;

	for (count = 0; count < rcv_desc->rx_desc_handled; count++) {
		rx_buffer = unm_reserve_rx_buffer(rcv_desc);
		if (rx_buffer != NULL) {
			pdesc = &rcv_desc->desc_head[producer];
			pdesc->referenceHandle = rxbuf2index(rcv_desc,
			    rx_buffer);
			pdesc->flags = ringid;
			pdesc->bufferLength = rcv_desc->dma_size;
			pdesc->AddrBuffer = rx_buffer->dma_info.dma_addr;
		} else {
			adapter->stats.outofrxbuf++;
			break;
		}
		producer = get_next_index(producer, rcv_desc->MaxRxDescCount);
	}

	/* if we did allocate buffers, then write the count to Phantom */
	if (count) {
		/* Sync rx ring, considering case for wrap around */
		unm_desc_dma_sync(rcv_desc->rx_desc_dma_handle, last_producer,
		    count, rcv_desc->MaxRxDescCount, sizeof (rcvDesc_t),
		    DDI_DMA_SYNC_FORDEV);

		rcv_desc->producer = producer;
		rcv_desc->rx_desc_handled -= count;
		rcv_desc->rx_buf_card += count;

		producer = (producer - 1) % rcv_desc->MaxRxDescCount;
		UNM_READ_LOCK(&adapter->adapter_lock);
		adapter->unm_nic_hw_write_wx(adapter,
		    rcv_desc->host_rx_producer, &producer, 4);
		UNM_READ_UNLOCK(&adapter->adapter_lock);
	}
}

int
unm_nic_fill_statistics_128M(struct unm_adapter_s *adapter,
			    struct unm_statistics *unm_stats)
{
	void *addr;
	if (adapter->ahw.board_type == UNM_NIC_XGBE) {
		UNM_WRITE_LOCK(&adapter->adapter_lock);
		unm_nic_pci_change_crbwindow_128M(adapter, 0);

		/* LINTED: E_FALSE_LOGICAL_EXPR */
		UNM_NIC_LOCKED_READ_REG(UNM_NIU_XGE_TX_BYTE_CNT,
		    &(unm_stats->tx_bytes));
		/* LINTED: E_FALSE_LOGICAL_EXPR */
		UNM_NIC_LOCKED_READ_REG(UNM_NIU_XGE_TX_FRAME_CNT,
		    &(unm_stats->tx_packets));
		/* LINTED: E_FALSE_LOGICAL_EXPR */
		UNM_NIC_LOCKED_READ_REG(UNM_NIU_XGE_RX_BYTE_CNT,
		    &(unm_stats->rx_bytes));
		/* LINTED: E_FALSE_LOGICAL_EXPR */
		UNM_NIC_LOCKED_READ_REG(UNM_NIU_XGE_RX_FRAME_CNT,
		    &(unm_stats->rx_packets));
		/* LINTED: E_FALSE_LOGICAL_EXPR */
		UNM_NIC_LOCKED_READ_REG(UNM_NIU_XGE_AGGR_ERROR_CNT,
		    &(unm_stats->rx_errors));
		/* LINTED: E_FALSE_LOGICAL_EXPR */
		UNM_NIC_LOCKED_READ_REG(UNM_NIU_XGE_CRC_ERROR_CNT,
		    &(unm_stats->rx_CRC_errors));
		/* LINTED: E_FALSE_LOGICAL_EXPR */
		UNM_NIC_LOCKED_READ_REG(UNM_NIU_XGE_OVERSIZE_FRAME_ERR,
		    &(unm_stats->rx_long_length_error));
		/* LINTED: E_FALSE_LOGICAL_EXPR */
		UNM_NIC_LOCKED_READ_REG(UNM_NIU_XGE_UNDERSIZE_FRAME_ERR,
		    &(unm_stats->rx_short_length_error));

		/*
		 * For reading rx_MAC_error bit different procedure
		 * UNM_NIC_LOCKED_WRITE_REG(UNM_NIU_TEST_MUX_CTL, 0x15);
		 * UNM_NIC_LOCKED_READ_REG((UNM_CRB_NIU + 0xC0), &temp);
		 * unm_stats->rx_MAC_errors = temp & 0xff;
		 */

		unm_nic_pci_change_crbwindow_128M(adapter, 1);
		UNM_WRITE_UNLOCK(&adapter->adapter_lock);
	} else {
		UNM_SPIN_LOCK_ISR(&adapter->tx_lock);
		unm_stats->tx_bytes = adapter->stats.txbytes;
		unm_stats->tx_packets = adapter->stats.xmitedframes +
		    adapter->stats.xmitfinished;
		unm_stats->rx_bytes = adapter->stats.rxbytes;
		unm_stats->rx_packets = adapter->stats.no_rcv;
		unm_stats->rx_errors = adapter->stats.rcvdbadmsg;
		unm_stats->tx_errors = adapter->stats.nocmddescriptor;
		unm_stats->rx_short_length_error = adapter->stats.uplcong;
		unm_stats->rx_long_length_error = adapter->stats.uphcong;
		unm_stats->rx_CRC_errors = 0;
		unm_stats->rx_MAC_errors = 0;
		UNM_SPIN_UNLOCK_ISR(&adapter->tx_lock);
	}
	return (0);
}

int
unm_nic_fill_statistics_2M(struct unm_adapter_s *adapter,
    struct unm_statistics *unm_stats)
{
	if (adapter->ahw.board_type == UNM_NIC_XGBE) {
		(void) unm_nic_hw_read_wx_2M(adapter, UNM_NIU_XGE_TX_BYTE_CNT,
		    &(unm_stats->tx_bytes), 4);
		(void) unm_nic_hw_read_wx_2M(adapter, UNM_NIU_XGE_TX_FRAME_CNT,
		    &(unm_stats->tx_packets), 4);
		(void) unm_nic_hw_read_wx_2M(adapter, UNM_NIU_XGE_RX_BYTE_CNT,
		    &(unm_stats->rx_bytes), 4);
		(void) unm_nic_hw_read_wx_2M(adapter, UNM_NIU_XGE_RX_FRAME_CNT,
		    &(unm_stats->rx_packets), 4);
		(void) unm_nic_hw_read_wx_2M(adapter,
		    UNM_NIU_XGE_AGGR_ERROR_CNT, &(unm_stats->rx_errors), 4);
		(void) unm_nic_hw_read_wx_2M(adapter, UNM_NIU_XGE_CRC_ERROR_CNT,
		    &(unm_stats->rx_CRC_errors), 4);
		(void) unm_nic_hw_read_wx_2M(adapter,
		    UNM_NIU_XGE_OVERSIZE_FRAME_ERR,
		    &(unm_stats->rx_long_length_error), 4);
		(void) unm_nic_hw_read_wx_2M(adapter,
		    UNM_NIU_XGE_UNDERSIZE_FRAME_ERR,
		    &(unm_stats->rx_short_length_error), 4);
	} else {
		UNM_SPIN_LOCK_ISR(&adapter->tx_lock);
		unm_stats->tx_bytes = adapter->stats.txbytes;
		unm_stats->tx_packets = adapter->stats.xmitedframes +
		    adapter->stats.xmitfinished;
		unm_stats->rx_bytes = adapter->stats.rxbytes;
		unm_stats->rx_packets = adapter->stats.no_rcv;
		unm_stats->rx_errors = adapter->stats.rcvdbadmsg;
		unm_stats->tx_errors = adapter->stats.nocmddescriptor;
		unm_stats->rx_short_length_error = adapter->stats.uplcong;
		unm_stats->rx_long_length_error = adapter->stats.uphcong;
		unm_stats->rx_CRC_errors = 0;
		unm_stats->rx_MAC_errors = 0;
		UNM_SPIN_UNLOCK_ISR(&adapter->tx_lock);
	}
	return (0);
}

int
unm_nic_clear_statistics_128M(struct unm_adapter_s *adapter)
{
	void *addr;
	int data = 0;

	UNM_WRITE_LOCK(&adapter->adapter_lock);
	unm_nic_pci_change_crbwindow_128M(adapter, 0);

	/* LINTED: E_FALSE_LOGICAL_EXPR */
	UNM_NIC_LOCKED_WRITE_REG(UNM_NIU_XGE_TX_BYTE_CNT, &data);
	/* LINTED: E_FALSE_LOGICAL_EXPR */
	UNM_NIC_LOCKED_WRITE_REG(UNM_NIU_XGE_TX_FRAME_CNT, &data);
	/* LINTED: E_FALSE_LOGICAL_EXPR */
	UNM_NIC_LOCKED_WRITE_REG(UNM_NIU_XGE_RX_BYTE_CNT, &data);
	/* LINTED: E_FALSE_LOGICAL_EXPR */
	UNM_NIC_LOCKED_WRITE_REG(UNM_NIU_XGE_RX_FRAME_CNT, &data);
	/* LINTED: E_FALSE_LOGICAL_EXPR */
	UNM_NIC_LOCKED_WRITE_REG(UNM_NIU_XGE_AGGR_ERROR_CNT, &data);
	/* LINTED: E_FALSE_LOGICAL_EXPR */
	UNM_NIC_LOCKED_WRITE_REG(UNM_NIU_XGE_CRC_ERROR_CNT, &data);
	/* LINTED: E_FALSE_LOGICAL_EXPR */
	UNM_NIC_LOCKED_WRITE_REG(UNM_NIU_XGE_OVERSIZE_FRAME_ERR, &data);
	/* LINTED: E_FALSE_LOGICAL_EXPR */
	UNM_NIC_LOCKED_WRITE_REG(UNM_NIU_XGE_UNDERSIZE_FRAME_ERR, &data);

	unm_nic_pci_change_crbwindow_128M(adapter, 1);
	UNM_WRITE_UNLOCK(&adapter->adapter_lock);
	unm_nic_clear_stats(adapter);
	return (0);
}

int
unm_nic_clear_statistics_2M(struct unm_adapter_s *adapter)
{
	int data = 0;

	(void) unm_nic_hw_write_wx_2M(adapter, UNM_NIU_XGE_TX_BYTE_CNT,
	    &data, 4);
	(void) unm_nic_hw_write_wx_2M(adapter, UNM_NIU_XGE_TX_FRAME_CNT,
	    &data, 4);
	(void) unm_nic_hw_write_wx_2M(adapter, UNM_NIU_XGE_RX_BYTE_CNT,
	    &data, 4);
	(void) unm_nic_hw_write_wx_2M(adapter, UNM_NIU_XGE_RX_FRAME_CNT,
	    &data, 4);
	(void) unm_nic_hw_write_wx_2M(adapter, UNM_NIU_XGE_AGGR_ERROR_CNT,
	    &data, 4);
	(void) unm_nic_hw_write_wx_2M(adapter, UNM_NIU_XGE_CRC_ERROR_CNT,
	    &data, 4);
	(void) unm_nic_hw_write_wx_2M(adapter, UNM_NIU_XGE_OVERSIZE_FRAME_ERR,
	    &data, 4);
	(void) unm_nic_hw_write_wx_2M(adapter, UNM_NIU_XGE_UNDERSIZE_FRAME_ERR,
	    &data, 4);
	unm_nic_clear_stats(adapter);
	return (0);
}

/*
 * unm_nic_ioctl ()    We provide the tcl/phanmon support
 * through these ioctls.
 */
static void
unm_nic_ioctl(struct unm_adapter_s *adapter, int cmd, queue_t *q, mblk_t *mp)
{
	void *ptr;

	switch (cmd) {
	case UNM_NIC_CMD:
		(void) unm_nic_do_ioctl(adapter, q, mp);
		break;

	case UNM_NIC_NAME:
		ptr = (void *) mp->b_cont->b_rptr;

		/*
		 * Phanmon checks for "UNM-UNM" string
		 * Replace the hardcoded value with appropriate macro
		 */
		DPRINTF(-1, (CE_CONT, "UNM_NIC_NAME ioctl executed %d %d\n",
		    cmd, __LINE__));
		(void) memcpy(ptr, "UNM-UNM", 10);
		miocack(q, mp, 10, 0);
		break;

	default:
		cmn_err(CE_WARN, "Netxen ioctl cmd %x not supported\n", cmd);

		miocnak(q, mp, 0, EINVAL);
		break;
	}
}

int
unm_nic_resume(unm_adapter *adapter)
{

	adapter->watchdog_timer = timeout((void (*)(void *))&unm_watchdog,
	    (void *) adapter, 50000);

	if (adapter->intr_type == DDI_INTR_TYPE_MSI)
		(void) ddi_intr_block_enable(&adapter->intr_handle, 1);
	else
		(void) ddi_intr_enable(adapter->intr_handle);
	UNM_READ_LOCK(&adapter->adapter_lock);
	unm_nic_enable_int(adapter);
	UNM_READ_UNLOCK(&adapter->adapter_lock);

	mac_link_update(adapter->mach, LINK_STATE_UP);

	return (DDI_SUCCESS);
}

int
unm_nic_suspend(unm_adapter *adapter)
{
	mac_link_update(adapter->mach, LINK_STATE_DOWN);

	(void) untimeout(adapter->watchdog_timer);

	UNM_READ_LOCK(&adapter->adapter_lock);
	unm_nic_disable_int(adapter);
	UNM_READ_UNLOCK(&adapter->adapter_lock);
	if (adapter->intr_type == DDI_INTR_TYPE_MSI)
		(void) ddi_intr_block_disable(&adapter->intr_handle, 1);
	else
		(void) ddi_intr_disable(adapter->intr_handle);

	return (DDI_SUCCESS);
}

static int
unm_nic_do_ioctl(unm_adapter *adapter, queue_t *wq, mblk_t *mp)
{
	unm_nic_ioctl_data_t		data;
	struct unm_nic_ioctl_data	*up_data;
	ddi_acc_handle_t		conf_handle;
	int				retval = 0;
	uint64_t			efuse_chip_id = 0;
	char				*ptr1;
	short				*ptr2;
	int				*ptr4;

	up_data = (struct unm_nic_ioctl_data *)(mp->b_cont->b_rptr);
	(void) memcpy(&data, (void **)(uintptr_t)(mp->b_cont->b_rptr),
	    sizeof (data));

	/* Shouldn't access beyond legal limits of  "char u[64];" member */
	if (data.size > sizeof (data.uabc)) {
		/* evil user tried to crash the kernel */
		cmn_err(CE_WARN, "bad size: %d\n", data.size);
		retval = GLD_BADARG;
		goto error_out;
	}

	switch (data.cmd) {
	case unm_nic_cmd_pci_read:

		if ((retval = adapter->unm_nic_hw_read_ioctl(adapter,
		    data.off, up_data, data.size))) {
			DPRINTF(-1, (CE_WARN, "%s(%d) unm_nic_hw_read_wx "
		    "returned %d\n", __FUNCTION__, __LINE__, retval));

			retval = data.rv;
			goto error_out;
		}

		data.rv = 0;
		break;

	case unm_nic_cmd_pci_write:
		if ((data.rv = adapter->unm_nic_hw_write_ioctl(adapter,
		    data.off, &(data.uabc), data.size))) {
			DPRINTF(-1, (CE_WARN, "%s(%d) unm_nic_hw_write_wx "
			    "returned %d\n", __FUNCTION__,
			    __LINE__, data.rv));
			retval = data.rv;
			goto error_out;
		}
		data.size = 0;
		break;

	case unm_nic_cmd_pci_mem_read:
		if ((data.rv = adapter->unm_nic_pci_mem_read(adapter,
		    data.off, up_data, data.size))) {
			DPRINTF(-1, (CE_WARN, "%s(%d) unm_nic_pci_mem_read "
			    "returned %d\n", __FUNCTION__,
			    __LINE__, data.rv));
			retval = data.rv;
			goto error_out;
		}
		data.rv = 0;
		break;

	case unm_nic_cmd_pci_mem_write:
		if ((data.rv = adapter->unm_nic_pci_mem_write(adapter,
		    data.off, &(data.uabc), data.size))) {
			DPRINTF(-1, (CE_WARN,
			    "%s(%d) unm_nic_cmd_pci_mem_write "
			    "returned %d\n",
			    __FUNCTION__, __LINE__, data.rv));
			retval = data.rv;
			goto error_out;
		}

		data.size = 0;
		data.rv = 0;
		break;

	case unm_nic_cmd_pci_config_read:

		if (adapter->pci_cfg_handle != NULL) {
			conf_handle = adapter->pci_cfg_handle;

		} else if ((retval = pci_config_setup(adapter->dip,
		    &conf_handle)) != DDI_SUCCESS) {
			DPRINTF(-1, (CE_WARN, "!%s: pci_config_setup failed"
			    " error:%d\n", unm_nic_driver_name, retval));
			goto error_out;

		} else
			adapter->pci_cfg_handle = conf_handle;

		switch (data.size) {
		case 1:
			ptr1 = (char *)up_data;
			*ptr1 = (char)pci_config_get8(conf_handle, data.off);
			break;
		case 2:
			ptr2 = (short *)up_data;
			*ptr2 = (short)pci_config_get16(conf_handle, data.off);
			break;
		case 4:
			ptr4 = (int *)up_data;
			*ptr4 = (int)pci_config_get32(conf_handle, data.off);
			break;
		}

		break;

	case unm_nic_cmd_pci_config_write:

		if (adapter->pci_cfg_handle != NULL) {
			conf_handle = adapter->pci_cfg_handle;
		} else if ((retval = pci_config_setup(adapter->dip,
		    &conf_handle)) != DDI_SUCCESS) {
			DPRINTF(-1, (CE_WARN, "!%s: pci_config_setup failed"
			    " error:%d\n", unm_nic_driver_name, retval));
			goto error_out;
		} else {
			adapter->pci_cfg_handle = conf_handle;
		}

		switch (data.size) {
		case 1:
			pci_config_put8(conf_handle,
			    data.off, *(char *)&(data.uabc));
			break;
		case 2:
			pci_config_put16(conf_handle,
			    data.off, *(short *)(uintptr_t)&(data.uabc));
			break;
		case 4:
			pci_config_put32(conf_handle,
			    data.off, *(u32 *)(uintptr_t)&(data.uabc));
			break;
		}
		data.size = 0;
		break;

	case unm_nic_cmd_get_stats:
		data.rv = adapter->unm_nic_fill_statistics(adapter,
		    (struct unm_statistics *)up_data);
		data.size = sizeof (struct unm_statistics);

		break;

	case unm_nic_cmd_clear_stats:
		data.rv = adapter->unm_nic_clear_statistics(adapter);
		break;

	case unm_nic_cmd_get_version:
		(void) memcpy(up_data, UNM_NIC_VERSIONID,
		    sizeof (UNM_NIC_VERSIONID));
		data.size = sizeof (UNM_NIC_VERSIONID);

		break;

	case unm_nic_cmd_get_phy_type:
		cmn_err(CE_WARN, "unm_nic_cmd_get_phy_type unimplemented\n");
		break;

	case unm_nic_cmd_efuse_chip_id:
		efuse_chip_id = adapter->unm_nic_pci_read_normalize(adapter,
		    UNM_EFUSE_CHIP_ID_HIGH);
		efuse_chip_id <<= 32;
		efuse_chip_id |= adapter->unm_nic_pci_read_normalize(adapter,
		    UNM_EFUSE_CHIP_ID_LOW);
		(void) memcpy(up_data, &efuse_chip_id, sizeof (uint64_t));
		data.rv = 0;
		break;

	default:
		cmn_err(CE_WARN, "%s%d: bad command %d\n", adapter->name,
		    adapter->instance, data.cmd);
		data.rv = GLD_NOTSUPPORTED;
		data.size = 0;
		goto error_out;
	}

work_done:
	miocack(wq, mp, data.size, data.rv);
	return (DDI_SUCCESS);

error_out:
	cmn_err(CE_WARN, "%s(%d) ioctl error\n", __FUNCTION__, data.cmd);
	miocnak(wq, mp, 0, EINVAL);
	return (retval);
}

/*
 * Local datatype for defining tables of (Offset, Name) pairs
 */
typedef struct {
	offset_t	index;
	char		*name;
} unm_ksindex_t;

static const unm_ksindex_t unm_kstat[] = {
	{ 0,		"freehdls"		},
	{ 1,		"freecmds"		},
	{ 2,		"tx_bcopy_threshold"	},
	{ 3,		"rx_bcopy_threshold"	},
	{ 4,		"xmitcalled"		},
	{ 5,		"xmitedframes"		},
	{ 6,		"xmitfinished"		},
	{ 7,		"txbytes"		},
	{ 8,		"txcopyed"		},
	{ 9,		"txmapped"		},
	{ 10,		"outoftxdmahdl"		},
	{ 11,		"outofcmddesc"		},
	{ 12,		"txdropped"		},
	{ 13,		"polled"		},
	{ 14,		"uphappy"		},
	{ 15,		"updropped"		},
	{ 16,		"csummed"		},
	{ 17,		"no_rcv"		},
	{ 18,		"rxbytes"		},
	{ 19,		"rxcopyed"		},
	{ 20,		"rxmapped"		},
	{ 21,		"desballocfailed"	},
	{ 22,		"outofrxbuf"		},
	{ 23,		"promiscmode"		},
	{ 24,		"rxbufshort"		},
	{ 25,		"allocbfailed"		},
	{ -1,		NULL			}
};

static int
unm_kstat_update(kstat_t *ksp, int flag)
{
	unm_adapter *adapter;
	kstat_named_t *knp;

	if (flag != KSTAT_READ)
		return (EACCES);

	adapter = ksp->ks_private;
	knp = ksp->ks_data;

	(knp++)->value.ui32 = adapter->freehdls;
	(knp++)->value.ui64 = adapter->freecmds;
	(knp++)->value.ui64 = adapter->tx_bcopy_threshold;
	(knp++)->value.ui64 = adapter->rx_bcopy_threshold;

	(knp++)->value.ui64 = adapter->stats.xmitcalled;
	(knp++)->value.ui64 = adapter->stats.xmitedframes;
	(knp++)->value.ui64 = adapter->stats.xmitfinished;
	(knp++)->value.ui64 = adapter->stats.txbytes;
	(knp++)->value.ui64 = adapter->stats.txcopyed;
	(knp++)->value.ui64 = adapter->stats.txmapped;
	(knp++)->value.ui64 = adapter->stats.outoftxdmahdl;
	(knp++)->value.ui64 = adapter->stats.outofcmddesc;
	(knp++)->value.ui64 = adapter->stats.txdropped;
	(knp++)->value.ui64 = adapter->stats.polled;
	(knp++)->value.ui64 = adapter->stats.uphappy;
	(knp++)->value.ui64 = adapter->stats.updropped;
	(knp++)->value.ui64 = adapter->stats.csummed;
	(knp++)->value.ui64 = adapter->stats.no_rcv;
	(knp++)->value.ui64 = adapter->stats.rxbytes;
	(knp++)->value.ui64 = adapter->stats.rxcopyed;
	(knp++)->value.ui64 = adapter->stats.rxmapped;
	(knp++)->value.ui64 = adapter->stats.desballocfailed;
	(knp++)->value.ui64 = adapter->stats.outofrxbuf;
	(knp++)->value.ui64 = adapter->stats.promiscmode;
	(knp++)->value.ui64 = adapter->stats.rxbufshort;
	(knp++)->value.ui64 = adapter->stats.allocbfailed;

	return (0);
}

static kstat_t *
unm_setup_named_kstat(unm_adapter *adapter, int instance, char *name,
	const unm_ksindex_t *ksip, size_t size, int (*update)(kstat_t *, int))
{
	kstat_t *ksp;
	kstat_named_t *knp;
	char *np;
	int type;
	int count = 0;

	size /= sizeof (unm_ksindex_t);
	ksp = kstat_create(unm_nic_driver_name, instance, name, "net",
	    KSTAT_TYPE_NAMED, size-1, KSTAT_FLAG_PERSISTENT);
	if (ksp == NULL)
		return (NULL);

	ksp->ks_private = adapter;
	ksp->ks_update = update;
	for (knp = ksp->ks_data; (np = ksip->name) != NULL; ++knp, ++ksip) {
		count++;
		switch (*np) {
		default:
			type = KSTAT_DATA_UINT64;
			break;
		case '%':
			np += 1;
			type = KSTAT_DATA_UINT32;
			break;
		case '$':
			np += 1;
			type = KSTAT_DATA_STRING;
			break;
		case '&':
			np += 1;
			type = KSTAT_DATA_CHAR;
			break;
		}
		kstat_named_init(knp, np, type);
	}
	kstat_install(ksp);

	return (ksp);
}

void
unm_init_kstats(unm_adapter* adapter, int instance)
{
	adapter->kstats[0] = unm_setup_named_kstat(adapter,
	    instance, "kstatinfo", unm_kstat,
	    sizeof (unm_kstat), unm_kstat_update);
}

void
unm_fini_kstats(unm_adapter* adapter)
{

	if (adapter->kstats[0] != NULL) {
			kstat_delete(adapter->kstats[0]);
			adapter->kstats[0] = NULL;
		}
}

static int
unm_nic_set_pauseparam(unm_adapter *adapter, unm_pauseparam_t *pause)
{
	int ret = 0;

	if (adapter->ahw.board_type == UNM_NIC_GBE) {
		if (unm_niu_gbe_set_rx_flow_ctl(adapter, pause->rx_pause))
			ret = -EIO;

		if (unm_niu_gbe_set_tx_flow_ctl(adapter, pause->tx_pause))
			ret = -EIO;

	} else if (adapter->ahw.board_type == UNM_NIC_XGBE) {
		if (unm_niu_xg_set_tx_flow_ctl(adapter, pause->tx_pause))
			ret =  -EIO;
	} else
		ret = -EIO;

	return (ret);
}

/*
 * GLD/MAC interfaces
 */
static int
ntxn_m_start(void *arg)
{
	unm_adapter	*adapter = arg;
	int		ring;

	UNM_SPIN_LOCK(&adapter->lock);
	if (adapter->is_up == UNM_ADAPTER_UP_MAGIC) {
		UNM_SPIN_UNLOCK(&adapter->lock);
		return (DDI_SUCCESS);
	}

	if (create_rxtx_rings(adapter) != DDI_SUCCESS) {
		UNM_SPIN_UNLOCK(&adapter->lock);
		return (DDI_FAILURE);
	}

	if (init_firmware(adapter) != DDI_SUCCESS) {
		UNM_SPIN_UNLOCK(&adapter->lock);
		cmn_err(CE_WARN, "%s%d: Failed to init firmware\n",
		    adapter->name, adapter->instance);
		goto dest_rings;
	}

	unm_nic_clear_stats(adapter);

	if (unm_nic_hw_resources(adapter) != 0) {
		UNM_SPIN_UNLOCK(&adapter->lock);
		cmn_err(CE_WARN, "%s%d: Error setting hw resources\n",
		    adapter->name, adapter->instance);
		goto dest_rings;
	}

	if (adapter->fw_major < 4) {
		adapter->crb_addr_cmd_producer =
		    crb_cmd_producer[adapter->portnum];
		adapter->crb_addr_cmd_consumer =
		    crb_cmd_consumer[adapter->portnum];
		unm_nic_update_cmd_producer(adapter, 0);
		unm_nic_update_cmd_consumer(adapter, 0);
	}

	for (ring = 0; ring < adapter->max_rds_rings; ring++) {
		if (unm_post_rx_buffers(adapter, ring) != DDI_SUCCESS) {
			UNM_SPIN_UNLOCK(&adapter->lock);
			goto free_hw_res;
		}
	}

	if (unm_nic_macaddr_set(adapter, adapter->mac_addr) != 0) {
		UNM_SPIN_UNLOCK(&adapter->lock);
		cmn_err(CE_WARN, "%s%d: Could not set mac address\n",
		    adapter->name, adapter->instance);
		goto free_hw_res;
	}

	if (unm_nic_init_port(adapter) != 0) {
		UNM_SPIN_UNLOCK(&adapter->lock);
		cmn_err(CE_WARN, "%s%d: Could not initialize port\n",
		    adapter->name, adapter->instance);
		goto free_hw_res;
	}

	unm_nic_set_link_parameters(adapter);

	/*
	 * P2 and P3 should be handled similarly.
	 */
	if (NX_IS_REVISION_P2(adapter->ahw.revision_id)) {
		if (unm_nic_set_promisc_mode(adapter) != 0) {
			UNM_SPIN_UNLOCK(&adapter->lock);
			cmn_err(CE_WARN, "%s%d: Could not set promisc mode\n",
			    adapter->name, adapter->instance);
			goto stop_and_free;
		}
	} else {
		nx_p3_nic_set_multi(adapter);
	}
	adapter->stats.promiscmode = 1;

	if (unm_nic_set_mtu(adapter, adapter->mtu) != 0) {
		UNM_SPIN_UNLOCK(&adapter->lock);
		cmn_err(CE_WARN, "%s%d: Could not set mtu\n",
		    adapter->name, adapter->instance);
		goto stop_and_free;
	}

	adapter->watchdog_timer = timeout((void (*)(void *))&unm_watchdog,
	    (void *)adapter, 0);

	adapter->is_up = UNM_ADAPTER_UP_MAGIC;

	if (adapter->intr_type == DDI_INTR_TYPE_MSI)
		(void) ddi_intr_block_enable(&adapter->intr_handle, 1);
	else
		(void) ddi_intr_enable(adapter->intr_handle);
	unm_nic_enable_int(adapter);

	UNM_SPIN_UNLOCK(&adapter->lock);
	return (GLD_SUCCESS);

stop_and_free:
	unm_nic_stop_port(adapter);
free_hw_res:
	unm_free_hw_resources(adapter);
dest_rings:
	destroy_rxtx_rings(adapter);
	return (DDI_FAILURE);
}


/*
 * This code is kept here for reference so as to
 * see if something different is required to be done
 * in GLDV3. This will be deleted later.
 */
/* ARGSUSED */
static void
ntxn_m_stop(void *arg)
{
}

/*ARGSUSED*/
static int
ntxn_m_multicst(void *arg, boolean_t add, const uint8_t *ep)
{
	/*
	 * When we correctly implement this, invoke nx_p3_nic_set_multi()
	 * or nx_p2_nic_set_multi() here.
	 */
	return (GLD_SUCCESS);
}

/*ARGSUSED*/
static int
ntxn_m_promisc(void *arg, boolean_t on)
{
#if 0
	int err = 0;
	struct unm_adapter_s *adapter = arg;

	err = on ? unm_nic_set_promisc_mode(adapter) :
	    unm_nic_unset_promisc_mode(adapter);

	if (err)
		return (GLD_FAILURE);
#endif

	return (GLD_SUCCESS);
}

static int
ntxn_m_stat(void *arg, uint_t stat, uint64_t *val)
{
	struct unm_adapter_s		*adapter = arg;
	struct unm_adapter_stats	*portstat = &adapter->stats;

	switch (stat) {
	case MAC_STAT_IFSPEED:
		if (adapter->ahw.board_type == UNM_NIC_XGBE) {
			/* 10 Gigs */
			*val = 10000000000ULL;
		} else {
			/* 1 Gig */
			*val = 1000000000;
		}
		break;

	case MAC_STAT_MULTIRCV:
		*val = 0;
		break;

	case MAC_STAT_BRDCSTRCV:
	case MAC_STAT_BRDCSTXMT:
		*val = 0;
		break;

	case MAC_STAT_NORCVBUF:
		*val = portstat->updropped;
		break;

	case MAC_STAT_NOXMTBUF:
		*val = portstat->txdropped;
		break;

	case MAC_STAT_RBYTES:
		*val = portstat->rxbytes;
		break;

	case MAC_STAT_OBYTES:
		*val = portstat->txbytes;
		break;

	case MAC_STAT_OPACKETS:
		*val = portstat->xmitedframes;
		break;

	case MAC_STAT_IPACKETS:
		*val = portstat->uphappy;
		break;

	case MAC_STAT_OERRORS:
		*val = portstat->xmitcalled - portstat->xmitedframes;
		break;

	case ETHER_STAT_LINK_DUPLEX:
		*val = LINK_DUPLEX_FULL;
		break;

	default:
		/*
		 * Shouldn't reach here...
		 */
		*val = 0;
		DPRINTF(0, (CE_WARN, ": unrecognized parameter = %d, value "
		    "returned 1\n", stat));

	}

	return (0);
}

static int
ntxn_m_unicst(void *arg, const uint8_t *mac)
{
	struct unm_adapter_s *adapter = arg;

	DPRINTF(-1, (CE_CONT, "%s: called\n", __func__));

	if (unm_nic_macaddr_set(adapter, (uint8_t *)mac))
		return (EAGAIN);
	bcopy(mac, adapter->mac_addr, ETHERADDRL);

	return (0);
}

static mblk_t *
ntxn_m_tx(void *arg, mblk_t *mp)
{
	unm_adapter *adapter = arg;
	mblk_t *next;

	while (mp != NULL) {
		next = mp->b_next;
		mp->b_next = NULL;

		if (unm_nic_xmit_frame(adapter, mp) != B_TRUE) {
			mp->b_next = next;
			break;
		}
		mp = next;
		adapter->stats.xmitedframes++;
	}

	return (mp);
}

static void
ntxn_m_ioctl(void *arg, queue_t *wq, mblk_t *mp)
{
	int		cmd;
	struct iocblk   *iocp = (struct iocblk *)(uintptr_t)mp->b_rptr;
	struct unm_adapter_s *adapter = (struct unm_adapter_s *)arg;
	enum ioc_reply status = IOC_DONE;

	iocp->ioc_error = 0;
	cmd = iocp->ioc_cmd;

	if (cmd == ND_GET || cmd == ND_SET) {
		status = unm_nd_ioctl(adapter, wq, mp, iocp);
		switch (status) {
		default:
		case IOC_INVAL:
			miocnak(wq, mp, 0, iocp->ioc_error == 0 ?
			    EINVAL : iocp->ioc_error);
			break;

		case IOC_DONE:
			break;

		case IOC_RESTART_ACK:
		case IOC_ACK:
			miocack(wq, mp, 0, 0);
			break;

		case IOC_RESTART_REPLY:
		case IOC_REPLY:
			mp->b_datap->db_type = iocp->ioc_error == 0 ?
			    M_IOCACK : M_IOCNAK;
			qreply(wq, mp);
			break;
		}
	} else if (cmd <= UNM_NIC_NAME && cmd >= UNM_CMD_START) {
		unm_nic_ioctl(adapter, cmd, wq, mp);
		return;
	} else {
		miocnak(wq, mp, 0, EINVAL);
		return;
	}
}

/* ARGSUSED */
static boolean_t
ntxn_m_getcapab(void *arg, mac_capab_t cap, void *cap_data)
{
	switch (cap) {
	case MAC_CAPAB_HCKSUM:
		{
			uint32_t *txflags = cap_data;

			*txflags = (HCKSUM_ENABLE |
			    HCKSUM_INET_FULL_V4 | HCKSUM_IPHDRCKSUM);
		}
		break;

#ifdef SOLARIS11
	case MAC_CAPAB_ANCHOR_VNIC:
	case MAC_CAPAB_MULTIFACTADDR:
#else
	case MAC_CAPAB_POLL:
	case MAC_CAPAB_MULTIADDRESS:
#endif
	default:
		return (B_FALSE);
	}

	return (B_TRUE);
}

#define	NETXEN_M_CALLBACK_FLAGS	(MC_IOCTL | MC_GETCAPAB)

static mac_callbacks_t ntxn_m_callbacks = {
	NETXEN_M_CALLBACK_FLAGS,
	ntxn_m_stat,
	ntxn_m_start,
	ntxn_m_stop,
	ntxn_m_promisc,
	ntxn_m_multicst,
	ntxn_m_unicst,
	ntxn_m_tx,
	NULL,			/* mc_reserved */
	ntxn_m_ioctl,
	ntxn_m_getcapab,
	NULL,			/* mc_open */
	NULL,			/* mc_close */
	NULL,			/* mc_setprop */
	NULL			/* mc_getprop */
};

int
unm_register_mac(unm_adapter *adapter)
{
	int ret;
	mac_register_t *macp;
	unm_pauseparam_t pause;

	dev_info_t *dip = adapter->dip;

	if ((macp = mac_alloc(MAC_VERSION)) == NULL) {
		cmn_err(CE_WARN, "Memory not available\n");
		return (DDI_FAILURE);
	}

	macp->m_type_ident = MAC_PLUGIN_IDENT_ETHER;
	macp->m_driver = adapter;
	macp->m_dip = dip;
	macp->m_instance = adapter->instance;
	macp->m_src_addr = adapter->mac_addr;
	macp->m_callbacks = &ntxn_m_callbacks;
	macp->m_min_sdu = 0;
	macp->m_max_sdu = adapter->mtu;
#ifdef SOLARIS11
	macp->m_margin = VLAN_TAGSZ;
#endif /* SOLARIS11 */

	ret = mac_register(macp, &adapter->mach);
	mac_free(macp);
	if (ret != 0) {
		cmn_err(CE_WARN, "mac_register failed for port %d\n",
		    adapter->portnum);
		return (DDI_FAILURE);
	}

	unm_init_kstats(adapter, adapter->instance);

	/* Register NDD-tweakable parameters */
	if (unm_nd_init(adapter)) {
		cmn_err(CE_WARN, "unm_nd_init() failed");
		return (DDI_FAILURE);
	}

	pause.rx_pause = adapter->nd_params[PARAM_ADV_PAUSE_CAP].ndp_val;
	pause.tx_pause = adapter->nd_params[PARAM_ADV_ASYM_PAUSE_CAP].ndp_val;

	if (unm_nic_set_pauseparam(adapter, &pause)) {
		cmn_err(CE_WARN, "\nBad Pause settings RX %d, Tx %d",
		    pause.rx_pause, pause.tx_pause);
	}
	adapter->nd_params[PARAM_PAUSE_CAP].ndp_val = pause.rx_pause;
	adapter->nd_params[PARAM_ASYM_PAUSE_CAP].ndp_val = pause.tx_pause;

	return (DDI_SUCCESS);
}
