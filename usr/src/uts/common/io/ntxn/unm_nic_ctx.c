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

#include "unm_nic_hw.h"
#include "unm_nic.h"
#include "nic_phan_reg.h"
#include "nic_cmn.h"

typedef unsigned int nx_rcode_t;

#include "nx_errorcode.h"
#include "nxhal_nic_interface.h"

#define	NXHAL_VERSION	1

#define	NX_OS_CRB_RETRY_COUNT	4000

#define	NX_CDRP_CLEAR		0x00000000
#define	NX_CDRP_CMD_BIT		0x80000000

/*
 * All responses must have the NX_CDRP_CMD_BIT cleared
 * in the crb NX_CDRP_CRB_OFFSET.
 */
#define	NX_CDRP_FORM_RSP(rsp)	(rsp)
#define	NX_CDRP_IS_RSP(rsp)	(((rsp) & NX_CDRP_CMD_BIT) == 0)

#define	NX_CDRP_RSP_OK		0x00000001
#define	NX_CDRP_RSP_FAIL	0x00000002
#define	NX_CDRP_RSP_TIMEOUT	0x00000003

/*
 * All commands must have the NX_CDRP_CMD_BIT set in
 * the crb NX_CDRP_CRB_OFFSET.
 */
#define	NX_CDRP_FORM_CMD(cmd)	(NX_CDRP_CMD_BIT | (cmd))
#define	NX_CDRP_IS_CMD(cmd)	(((cmd) & NX_CDRP_CMD_BIT) != 0)

#define	NX_CDRP_CMD_SUBMIT_CAPABILITIES		0x00000001
#define	NX_CDRP_CMD_READ_MAX_RDS_PER_CTX    0x00000002
#define	NX_CDRP_CMD_READ_MAX_SDS_PER_CTX    0x00000003
#define	NX_CDRP_CMD_READ_MAX_RULES_PER_CTX  0x00000004
#define	NX_CDRP_CMD_READ_MAX_RX_CTX			0x00000005
#define	NX_CDRP_CMD_READ_MAX_TX_CTX			0x00000006
#define	NX_CDRP_CMD_CREATE_RX_CTX			0x00000007
#define	NX_CDRP_CMD_DESTROY_RX_CTX			0x00000008
#define	NX_CDRP_CMD_CREATE_TX_CTX			0x00000009
#define	NX_CDRP_CMD_DESTROY_TX_CTX			0x0000000a
#define	NX_CDRP_CMD_SETUP_STATISTICS		0x0000000e
#define	NX_CDRP_CMD_GET_STATISTICS			0x0000000f
#define	NX_CDRP_CMD_DELETE_STATISTICS		0x00000010
#define	NX_CDRP_CMD_SET_MTU					0x00000012
#define	NX_CDRP_CMD_MAX						0x00000013

#define	NX_DESTROY_CTX_RESET		0
#define	NX_DESTROY_CTX_D3_RESET		1
#define	NX_DESTROY_CTX_MAX		2

/*
 * Context state
 */
#define	NX_HOST_CTX_STATE_FREED		0
#define	NX_HOST_CTX_STATE_ALLOCATED	1
#define	NX_HOST_CTX_STATE_ACTIVE	2
#define	NX_HOST_CTX_STATE_DISABLED	3
#define	NX_HOST_CTX_STATE_QUIESCED	4
#define	NX_HOST_CTX_STATE_MAX		5

static int
netxen_api_lock(struct unm_adapter_s *adapter)
{
	u32 done = 0, timeout = 0;

	for (;;) {
		/* Acquire PCIE HW semaphore5 */
		unm_nic_read_w0(adapter,
		    UNM_PCIE_REG(PCIE_SEM5_LOCK), &done);

		if (done == 1)
			break;

		if (++timeout >= NX_OS_CRB_RETRY_COUNT) {
			cmn_err(CE_WARN, "%s: lock timeout.\n", __func__);
			return (-1);
		}

		drv_usecwait(1000);
	}

#if 0
	unm_nic_reg_write(adapter, NETXEN_API_LOCK_ID, NX_OS_API_LOCK_DRIVER);
#endif
	return (0);
}

static void
netxen_api_unlock(struct unm_adapter_s *adapter)
{
	u32 val;

	/* Release PCIE HW semaphore5 */
	unm_nic_read_w0(adapter,
	    UNM_PCIE_REG(PCIE_SEM5_UNLOCK), &val);
}

static u32
netxen_poll_rsp(struct unm_adapter_s *adapter)
{
	u32 raw_rsp, rsp = NX_CDRP_RSP_OK;
	int	timeout = 0;

	do {
		/* give atleast 1ms for firmware to respond */
		drv_usecwait(1000);

		if (++timeout > NX_OS_CRB_RETRY_COUNT)
			return (NX_CDRP_RSP_TIMEOUT);

		adapter->unm_nic_hw_read_wx(adapter, NX_CDRP_CRB_OFFSET,
		    &raw_rsp, 4);

		rsp = LE_TO_HOST_32(raw_rsp);
	} while (!NX_CDRP_IS_RSP(rsp));

	return (rsp);
}

static u32
netxen_issue_cmd(struct unm_adapter_s *adapter,
	u32 pci_fn, u32 version, u32 arg1, u32 arg2, u32 arg3, u32 cmd)
{
	u32 rsp;
	u32 signature = 0;
	u32 rcode = NX_RCODE_SUCCESS;

	signature = NX_CDRP_SIGNATURE_MAKE(pci_fn, version);

	/* Acquire semaphore before accessing CRB */
	if (netxen_api_lock(adapter))
		return (NX_RCODE_TIMEOUT);

	unm_nic_reg_write(adapter, NX_SIGN_CRB_OFFSET,
	    HOST_TO_LE_32(signature));

	unm_nic_reg_write(adapter, NX_ARG1_CRB_OFFSET,
	    HOST_TO_LE_32(arg1));

	unm_nic_reg_write(adapter, NX_ARG2_CRB_OFFSET,
	    HOST_TO_LE_32(arg2));

	unm_nic_reg_write(adapter, NX_ARG3_CRB_OFFSET,
	    HOST_TO_LE_32(arg3));

	unm_nic_reg_write(adapter, NX_CDRP_CRB_OFFSET,
	    HOST_TO_LE_32(NX_CDRP_FORM_CMD(cmd)));

	rsp = netxen_poll_rsp(adapter);

	if (rsp == NX_CDRP_RSP_TIMEOUT) {
		cmn_err(CE_WARN, "%s: card response timeout.\n",
		    unm_nic_driver_name);

		rcode = NX_RCODE_TIMEOUT;
	} else if (rsp == NX_CDRP_RSP_FAIL) {
		adapter->unm_nic_hw_read_wx(adapter, NX_ARG1_CRB_OFFSET,
		    &rcode, 4);
		rcode = LE_TO_HOST_32(rcode);

		cmn_err(CE_WARN, "%s: failed card response code:0x%x\n",
		    unm_nic_driver_name, rcode);
	}

	/* Release semaphore */
	netxen_api_unlock(adapter);

	return (rcode);
}

int
nx_fw_cmd_set_mtu(struct unm_adapter_s *adapter, int mtu)
{
	u32 rcode = NX_RCODE_SUCCESS;
	struct unm_recv_context_s *recv_ctx = &adapter->recv_ctx[0];

	if (recv_ctx->state == NX_HOST_CTX_STATE_ACTIVE)
		rcode = netxen_issue_cmd(adapter,
		    adapter->ahw.pci_func,
		    NXHAL_VERSION,
		    recv_ctx->context_id,
		    mtu,
		    0,
		    NX_CDRP_CMD_SET_MTU);

	if (rcode != NX_RCODE_SUCCESS)
		return (-EIO);

	return (0);
}

static int
nx_fw_cmd_create_rx_ctx(struct unm_adapter_s *adapter)
{
	unm_recv_context_t	*recv_ctx = &adapter->recv_ctx[0];
	nx_hostrq_rx_ctx_t	*prq;
	nx_cardrsp_rx_ctx_t	*prsp;
	nx_hostrq_rds_ring_t	*prq_rds;
	nx_hostrq_sds_ring_t	*prq_sds;
	nx_cardrsp_rds_ring_t	*prsp_rds;
	nx_cardrsp_sds_ring_t	*prsp_sds;
	unm_rcv_desc_ctx_t	*rcv_desc;
	ddi_dma_cookie_t	cookie;
	ddi_dma_handle_t	rqdhdl, rsdhdl;
	ddi_acc_handle_t	rqahdl, rsahdl;
	uint64_t		hostrq_phys_addr, cardrsp_phys_addr;
	u64			phys_addr;
	u32			cap, reg;
	size_t			rq_size, rsp_size;
	void			*addr;
	int			i, nrds_rings, nsds_rings, err;

	/* only one sds ring for now */
	nrds_rings = adapter->max_rds_rings;
	nsds_rings = 1;

	rq_size =
	    SIZEOF_HOSTRQ_RX(nx_hostrq_rx_ctx_t, nrds_rings, nsds_rings);
	rsp_size =
	    SIZEOF_CARDRSP_RX(nx_cardrsp_rx_ctx_t, nrds_rings, nsds_rings);

	if (unm_pci_alloc_consistent(adapter, rq_size, (caddr_t *)&addr,
	    &cookie, &rqdhdl, &rqahdl) != DDI_SUCCESS)
		return (-ENOMEM);
	hostrq_phys_addr = cookie.dmac_laddress;
	prq = (nx_hostrq_rx_ctx_t *)addr;

	if (unm_pci_alloc_consistent(adapter, rsp_size, (caddr_t *)&addr,
	    &cookie, &rsdhdl, &rsahdl) != DDI_SUCCESS) {
		err = -ENOMEM;
		goto out_free_rq;
	}
	cardrsp_phys_addr = cookie.dmac_laddress;
	prsp = (nx_cardrsp_rx_ctx_t *)addr;

	prq->host_rsp_dma_addr = HOST_TO_LE_64(cardrsp_phys_addr);

	cap = (NX_CAP0_LEGACY_CONTEXT | NX_CAP0_LEGACY_MN);
	cap |= (NX_CAP0_JUMBO_CONTIGUOUS);

	prq->capabilities[0] = HOST_TO_LE_32(cap);
	prq->host_int_crb_mode =
	    HOST_TO_LE_32(NX_HOST_INT_CRB_MODE_SHARED);
	prq->host_rds_crb_mode =
	    HOST_TO_LE_32(NX_HOST_RDS_CRB_MODE_UNIQUE);

	prq->num_rds_rings = HOST_TO_LE_16(nrds_rings);
	prq->num_sds_rings = HOST_TO_LE_16(nsds_rings);
	prq->rds_ring_offset = 0;
	prq->sds_ring_offset = prq->rds_ring_offset +
	    (sizeof (nx_hostrq_rds_ring_t) * nrds_rings);

	prq_rds = (nx_hostrq_rds_ring_t *)(uintptr_t)((char *)prq +
	    sizeof (*prq) + prq->rds_ring_offset);

	for (i = 0; i < nrds_rings; i++) {
		rcv_desc = &recv_ctx->rcv_desc[i];

		prq_rds[i].host_phys_addr = HOST_TO_LE_64(rcv_desc->phys_addr);
		prq_rds[i].ring_size = HOST_TO_LE_32(rcv_desc->MaxRxDescCount);
		prq_rds[i].ring_kind = HOST_TO_LE_32(i);
		prq_rds[i].buff_size = HOST_TO_LE_64(rcv_desc->dma_size);
	}

	prq_sds = (nx_hostrq_sds_ring_t *)(uintptr_t)((char *)prq +
	    sizeof (*prq) + prq->sds_ring_offset);

	prq_sds[0].host_phys_addr =
	    HOST_TO_LE_64(recv_ctx->rcvStatusDesc_physAddr);
	prq_sds[0].ring_size = HOST_TO_LE_32(adapter->MaxRxDescCount);
	/* only one msix vector for now */
	prq_sds[0].msi_index = HOST_TO_LE_32(0);

	/* now byteswap offsets */
	prq->rds_ring_offset = HOST_TO_LE_32(prq->rds_ring_offset);
	prq->sds_ring_offset = HOST_TO_LE_32(prq->sds_ring_offset);

	phys_addr = hostrq_phys_addr;
	err = netxen_issue_cmd(adapter,
	    adapter->ahw.pci_func,
	    NXHAL_VERSION,
	    (u32)(phys_addr >> 32),
	    (u32)(phys_addr & 0xffffffff),
	    rq_size,
	    NX_CDRP_CMD_CREATE_RX_CTX);
	if (err) {
		cmn_err(CE_WARN, "Failed to create rx ctx in firmware%d\n",
		    err);
		goto out_free_rsp;
	}


	prsp_rds = (nx_cardrsp_rds_ring_t *)(uintptr_t)((char *)prsp +
	    sizeof (*prsp) + prsp->rds_ring_offset);

	for (i = 0; i < LE_TO_HOST_32(prsp->num_rds_rings); i++) {
		rcv_desc = &recv_ctx->rcv_desc[i];

		reg = LE_TO_HOST_32(prsp_rds[i].host_producer_crb);
		rcv_desc->host_rx_producer = UNM_NIC_REG(reg - 0x200);
	}

	prsp_sds = (nx_cardrsp_sds_ring_t *)(uintptr_t)((char *)prsp +
	    sizeof (*prsp) + prsp->sds_ring_offset);
	reg = LE_TO_HOST_32(prsp_sds[0].host_consumer_crb);
	recv_ctx->host_sds_consumer = UNM_NIC_REG(reg - 0x200);

	reg = LE_TO_HOST_32(prsp_sds[0].interrupt_crb);
	adapter->interrupt_crb = UNM_NIC_REG(reg - 0x200);

	recv_ctx->state = LE_TO_HOST_32(prsp->host_ctx_state);
	recv_ctx->context_id = LE_TO_HOST_16(prsp->context_id);
	recv_ctx->virt_port = LE_TO_HOST_16(prsp->virt_port);

out_free_rsp:
	unm_pci_free_consistent(&rsdhdl, &rsahdl);
out_free_rq:
	unm_pci_free_consistent(&rqdhdl, &rqahdl);
	return (err);
}

static void
nx_fw_cmd_destroy_rx_ctx(struct unm_adapter_s *adapter)
{
	struct unm_recv_context_s *recv_ctx = &adapter->recv_ctx[0];

	if (netxen_issue_cmd(adapter,
	    adapter->ahw.pci_func,
	    NXHAL_VERSION,
	    recv_ctx->context_id,
	    NX_DESTROY_CTX_RESET,
	    0,
	    NX_CDRP_CMD_DESTROY_RX_CTX)) {

		cmn_err(CE_WARN, "%s: Failed to destroy rx ctx in firmware\n",
		    unm_nic_driver_name);
	}
}

static int
nx_fw_cmd_create_tx_ctx(struct unm_adapter_s *adapter)
{
	nx_hostrq_tx_ctx_t	*prq;
	nx_hostrq_cds_ring_t	*prq_cds;
	nx_cardrsp_tx_ctx_t	*prsp;
	ddi_dma_cookie_t	cookie;
	ddi_dma_handle_t	rqdhdl, rsdhdl;
	ddi_acc_handle_t	rqahdl, rsahdl;
	void			*rq_addr, *rsp_addr;
	size_t			rq_size, rsp_size;
	u32			temp;
	int			err = 0;
	u64			offset, phys_addr;
	uint64_t		rq_phys_addr, rsp_phys_addr;

	rq_size = SIZEOF_HOSTRQ_TX(nx_hostrq_tx_ctx_t);
	if (unm_pci_alloc_consistent(adapter, rq_size, (caddr_t *)&rq_addr,
	    &cookie, &rqdhdl, &rqahdl) != DDI_SUCCESS)
		return (-ENOMEM);
	rq_phys_addr = cookie.dmac_laddress;

	rsp_size = SIZEOF_CARDRSP_TX(nx_cardrsp_tx_ctx_t);
	if (unm_pci_alloc_consistent(adapter, rsp_size, (caddr_t *)&rsp_addr,
	    &cookie, &rsdhdl, &rsahdl) != DDI_SUCCESS) {
		err = -ENOMEM;
		goto out_free_rq;
	}
	rsp_phys_addr = cookie.dmac_laddress;

	(void) memset(rq_addr, 0, rq_size);
	prq = (nx_hostrq_tx_ctx_t *)rq_addr;

	(void) memset(rsp_addr, 0, rsp_size);
	prsp = (nx_cardrsp_tx_ctx_t *)rsp_addr;

	prq->host_rsp_dma_addr = HOST_TO_LE_64(rsp_phys_addr);

	temp = (NX_CAP0_LEGACY_CONTEXT | NX_CAP0_LEGACY_MN);
	prq->capabilities[0] = HOST_TO_LE_32(temp);

	prq->host_int_crb_mode =
	    HOST_TO_LE_32(NX_HOST_INT_CRB_MODE_SHARED);

	prq->interrupt_ctl = 0;
	prq->msi_index = 0;

	prq->dummy_dma_addr = HOST_TO_LE_64(adapter->dummy_dma.phys_addr);

	offset = adapter->ctxDesc_physAddr + sizeof (RingContext);
	prq->cmd_cons_dma_addr = HOST_TO_LE_64(offset);

	prq_cds = &prq->cds_ring;

	prq_cds->host_phys_addr =
	    HOST_TO_LE_64(adapter->ahw.cmdDesc_physAddr);

	prq_cds->ring_size = HOST_TO_LE_32(adapter->MaxTxDescCount);

	phys_addr = rq_phys_addr;
	err = netxen_issue_cmd(adapter,
	    adapter->ahw.pci_func,
	    NXHAL_VERSION,
	    (u32)(phys_addr >> 32),
	    ((u32)phys_addr & 0xffffffff),
	    rq_size,
	    NX_CDRP_CMD_CREATE_TX_CTX);

	if (err == NX_RCODE_SUCCESS) {
		temp = LE_TO_HOST_32(prsp->cds_ring.host_producer_crb);
		adapter->crb_addr_cmd_producer =
		    UNM_NIC_REG(temp - 0x200);
#if 0
		adapter->tx_state =
		    LE_TO_HOST_32(prsp->host_ctx_state);
#endif
		adapter->tx_context_id =
		    LE_TO_HOST_16(prsp->context_id);
	} else {
		cmn_err(CE_WARN, "Failed to create tx ctx in firmware%d\n",
		    err);
		err = -EIO;
	}

	unm_pci_free_consistent(&rsdhdl, &rsahdl);

out_free_rq:
	unm_pci_free_consistent(&rqdhdl, &rqahdl);

	return (err);
}

static void
nx_fw_cmd_destroy_tx_ctx(struct unm_adapter_s *adapter)
{
	if (netxen_issue_cmd(adapter,
	    adapter->ahw.pci_func,
	    NXHAL_VERSION,
	    adapter->tx_context_id,
	    NX_DESTROY_CTX_RESET,
	    0,
	    NX_CDRP_CMD_DESTROY_TX_CTX)) {

		cmn_err(CE_WARN, "%s: Failed to destroy tx ctx in firmware\n",
		    unm_nic_driver_name);
	}
}

static u64 ctx_addr_sig_regs[][3] = {
	{UNM_NIC_REG(0x188), UNM_NIC_REG(0x18c), UNM_NIC_REG(0x1c0)},
	{UNM_NIC_REG(0x190), UNM_NIC_REG(0x194), UNM_NIC_REG(0x1c4)},
	{UNM_NIC_REG(0x198), UNM_NIC_REG(0x19c), UNM_NIC_REG(0x1c8)},
	{UNM_NIC_REG(0x1a0), UNM_NIC_REG(0x1a4), UNM_NIC_REG(0x1cc)}
};

#define	CRB_CTX_ADDR_REG_LO(FUNC_ID)	(ctx_addr_sig_regs[FUNC_ID][0])
#define	CRB_CTX_ADDR_REG_HI(FUNC_ID)	(ctx_addr_sig_regs[FUNC_ID][2])
#define	CRB_CTX_SIGNATURE_REG(FUNC_ID)	(ctx_addr_sig_regs[FUNC_ID][1])

struct netxen_recv_crb {
	u32	crb_rcv_producer[NUM_RCV_DESC_RINGS];
	u32	crb_sts_consumer;
};

static struct netxen_recv_crb recv_crb_registers[] = {
	/* Instance 0 */
	{
		/* crb_rcv_producer: */
		{
			UNM_NIC_REG(0x100),
			/* Jumbo frames */
			UNM_NIC_REG(0x110),
			/* LRO */
			UNM_NIC_REG(0x120)
		},
		/* crb_sts_consumer: */
		UNM_NIC_REG(0x138),
	},
	/* Instance 1 */
	{
		/* crb_rcv_producer: */
		{
			UNM_NIC_REG(0x144),
			/* Jumbo frames */
			UNM_NIC_REG(0x154),
			/* LRO */
			UNM_NIC_REG(0x164)
		},
		/* crb_sts_consumer: */
		UNM_NIC_REG(0x17c),
	},
	/* Instance 2 */
	{
		/* crb_rcv_producer: */
		{
			UNM_NIC_REG(0x1d8),
			/* Jumbo frames */
			UNM_NIC_REG(0x1f8),
			/* LRO */
			UNM_NIC_REG(0x208)
		},
		/* crb_sts_consumer: */
		UNM_NIC_REG(0x220),
	},
	/* Instance 3 */
	{
		/* crb_rcv_producer: */
		{
			UNM_NIC_REG(0x22c),
			/* Jumbo frames */
			UNM_NIC_REG(0x23c),
			/* LRO */
			UNM_NIC_REG(0x24c)
		},
		/* crb_sts_consumer: */
		UNM_NIC_REG(0x264),
	},
};

static uint32_t sw_int_mask[4] = {
	CRB_SW_INT_MASK_0, CRB_SW_INT_MASK_1,
	CRB_SW_INT_MASK_2, CRB_SW_INT_MASK_3
};

static int
netxen_init_old_ctx(struct unm_adapter_s *adapter)
{
	hardware_context		*hw = &adapter->ahw;
	struct unm_recv_context_s	*recv_ctx;
	unm_rcv_desc_ctx_t		*rcv_desc;
	int				ctx, ring, func_id = adapter->portnum;
	unsigned int			temp;

	adapter->ctxDesc->CmdRingAddrLo = hw->cmdDesc_physAddr & 0xffffffffUL;
	adapter->ctxDesc->CmdRingAddrHi = ((U64)hw->cmdDesc_physAddr >> 32);
	adapter->ctxDesc->CmdRingSize = adapter->MaxTxDescCount;

	for (ctx = 0; ctx < MAX_RCV_CTX; ++ctx) {
		recv_ctx = &adapter->recv_ctx[ctx];

		for (ring = 0; ring < adapter->max_rds_rings; ring++) {
			rcv_desc = &recv_ctx->rcv_desc[ring];

			adapter->ctxDesc->RcvContext[ring].RcvRingAddrLo =
			    rcv_desc->phys_addr & 0xffffffffUL;
			adapter->ctxDesc->RcvContext[ring].RcvRingAddrHi =
			    ((U64)rcv_desc->phys_addr>>32);
			adapter->ctxDesc->RcvContext[ring].RcvRingSize =
			    rcv_desc->MaxRxDescCount;

			rcv_desc->host_rx_producer =
			    recv_crb_registers[adapter->portnum].
			    crb_rcv_producer[ring];
		}

		adapter->ctxDesc->StsRingAddrLo =
		    recv_ctx->rcvStatusDesc_physAddr & 0xffffffff;
		adapter->ctxDesc->StsRingAddrHi =
		    recv_ctx->rcvStatusDesc_physAddr >> 32;
		adapter->ctxDesc->StsRingSize = adapter->MaxRxDescCount;

		recv_ctx->host_sds_consumer =
		    recv_crb_registers[adapter->portnum].crb_sts_consumer;
	}

	adapter->interrupt_crb = sw_int_mask[adapter->portnum];

	temp = lower32(adapter->ctxDesc_physAddr);
	adapter->unm_nic_hw_write_wx(adapter, CRB_CTX_ADDR_REG_LO(func_id),
	    &temp, 4);
	temp = upper32(adapter->ctxDesc_physAddr);
	adapter->unm_nic_hw_write_wx(adapter, CRB_CTX_ADDR_REG_HI(func_id),
	    &temp, 4);
	temp = UNM_CTX_SIGNATURE | func_id;
	adapter->unm_nic_hw_write_wx(adapter, CRB_CTX_SIGNATURE_REG(func_id),
	    &temp, 4);

	return (0);
}

void
netxen_destroy_rxtx(struct unm_adapter_s *adapter)
{
	if (adapter->fw_major >= 4) {
		nx_fw_cmd_destroy_tx_ctx(adapter);
		nx_fw_cmd_destroy_rx_ctx(adapter);
	}
}

int
netxen_create_rxtx(struct unm_adapter_s *adapter)
{
	int	err;

	if (adapter->fw_major >= 4) {
		err = nx_fw_cmd_create_rx_ctx(adapter);
		if (err)
			return (err);
		err = nx_fw_cmd_create_tx_ctx(adapter);
		if (err)
			nx_fw_cmd_destroy_rx_ctx(adapter);
		return (err);
	} else {
		return (netxen_init_old_ctx(adapter));
	}
}
