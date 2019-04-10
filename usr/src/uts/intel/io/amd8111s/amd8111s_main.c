/*
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2001-2006 Advanced Micro Devices, Inc.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * + Redistributions of source code must retain the above copyright notice,
 * + this list of conditions and the following disclaimer.
 *
 * + Redistributions in binary form must reproduce the above copyright
 * + notice, this list of conditions and the following disclaimer in the
 * + documentation and/or other materials provided with the distribution.
 *
 * + Neither the name of Advanced Micro Devices, Inc. nor the names of its
 * + contributors may be used to endorse or promote products derived from
 * + this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
 * CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL ADVANCED MICRO DEVICES, INC. OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Import/Export/Re-Export/Use/Release/Transfer Restrictions and
 * Compliance with Applicable Laws.  Notice is hereby given that
 * the software may be subject to restrictions on use, release,
 * transfer, importation, exportation and/or re-exportation under
 * the laws and regulations of the United States or other
 * countries ("Applicable Laws"), which include but are not
 * limited to U.S. export control laws such as the Export
 * Administration Regulations and national security controls as
 * defined thereunder, as well as State Department controls under
 * the U.S. Munitions List.  Permission to use and/or
 * redistribute the software is conditioned upon compliance with
 * all Applicable Laws, including U.S. export control laws
 * regarding specifically designated persons, countries and
 * nationals of countries subject to national security controls.
 */

/* include files */
#include <sys/disp.h>
#include <sys/atomic.h>
#include <sys/vlan.h>
#include "amd8111s_main.h"

/* Global macro Definations */
#define	ROUNDUP(x, a)	(((x) + (a) - 1) & ~((a) - 1))
#define	INTERFACE_NAME "amd8111s"
#define	AMD8111S_SPLIT	128
#define	AMD8111S_SEND_MAX	64

static char ident[] = "AMD8111 10/100M Ethernet";

/*
 * Driver Entry Points
 */
static int amd8111s_attach(dev_info_t *, ddi_attach_cmd_t);
static int amd8111s_detach(dev_info_t *, ddi_detach_cmd_t);

/*
 * GLD Entry points prototype
 */
static int amd8111s_m_unicst(void *, const uint8_t *);
static int amd8111s_m_promisc(void *, boolean_t);
static int amd8111s_m_stat(void *, uint_t, uint64_t *);
static void amd8111s_m_ioctl(void *, queue_t *, mblk_t *);
static int amd8111s_m_multicst(void *, boolean_t, const uint8_t *addr);
static int amd8111s_m_start(void *);
static void amd8111s_m_stop(void *);
static mblk_t *amd8111s_m_tx(void *, mblk_t *mp);
static uint_t amd8111s_intr(caddr_t);

static int amd8111s_unattach(dev_info_t *, struct LayerPointers *);

static boolean_t amd8111s_allocate_buffers(struct LayerPointers *);
static int amd8111s_odlInit(struct LayerPointers *);
static boolean_t amd8111s_allocate_descriptors(struct LayerPointers *);
static void amd8111s_free_descriptors(struct LayerPointers *);
static boolean_t amd8111s_alloc_dma_ringbuf(struct LayerPointers *,
		struct amd8111s_dma_ringbuf *, uint32_t, uint32_t);
static void amd8111s_free_dma_ringbuf(struct amd8111s_dma_ringbuf *);


static void amd8111s_log(struct LayerPointers *adapter, int level,
    char *fmt, ...);

static struct cb_ops amd8111s_cb_ops = {
	nulldev,
	nulldev,
	nodev,
	nodev,
	nodev,
	nodev,
	nodev,
	nodev,
	nodev,
	nodev,
	nodev,
	nochpoll,
	ddi_prop_op,
	NULL,
	D_NEW | D_MP,
	CB_REV,		/* cb_rev */
	nodev,		/* cb_aread */
	nodev		/* cb_awrite */
};

static struct dev_ops amd8111s_dev_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* devo_refcnt */
	NULL,			/* devo_getinfo */
	nulldev,		/* devo_identify */
	nulldev,		/* devo_probe */
	amd8111s_attach,	/* devo_attach */
	amd8111s_detach,	/* devo_detach */
	nodev,			/* devo_reset */
	&amd8111s_cb_ops,	/* devo_cb_ops */
	NULL,			/* devo_bus_ops */
	nodev,			/* devo_power */
	ddi_quiesce_not_supported,	/* devo_quiesce */
};

struct modldrv amd8111s_modldrv = {
	&mod_driverops,		/* Type of module. This one is a driver */
	ident,			/* short description */
	&amd8111s_dev_ops	/* driver specific ops */
};

struct modlinkage amd8111s_modlinkage = {
	MODREV_1, (void *)&amd8111s_modldrv, NULL
};

/*
 * Global Variables
 */
struct LayerPointers *amd8111sadapter;

static ddi_dma_attr_t pcn_buff_dma_attr_t = {
	DMA_ATTR_V0,	/* dma_attr_version */
	(uint64_t)0,		/* dma_attr_addr_lo */
	(uint64_t)0xFFFFFFFF,	/* dma_attr_addr_hi */
	(uint64_t)0xFFFFFFFF,	/* dma_attr_count_max */
	(uint64_t)1,		/* dma_attr_align */
	(uint_t)0x7F,		/* dma_attr_burstsizes */
	(uint32_t)1,		/* dma_attr_minxfer */
	(uint64_t)0xFFFFFFFF,	/* dma_attr_maxxfer */
	(uint64_t)0xFFFFFFFF,	/* dma_attr_seg */
	(int)1,			/* dma_attr_sgllen */
	(uint32_t)1,		/* granularity */
	(uint_t)0		/* dma_attr_flags */
};

static ddi_dma_attr_t pcn_desc_dma_attr_t = {
	DMA_ATTR_V0,		/* dma_attr_version */
	(uint64_t)0,		/* dma_attr_addr_lo */
	(uint64_t)0xFFFFFFFF,	/* dma_attr_addr_hi */
	(uint64_t)0x7FFFFFFF,	/* dma_attr_count_max */
	(uint64_t)0x10,		/* dma_attr_align */
	(uint_t)0xFFFFFFFFU,	/* dma_attr_burstsizes */
	(uint32_t)1,		/* dma_attr_minxfer */
	(uint64_t)0xFFFFFFFF,	/* dma_attr_maxxfer */
	(uint64_t)0xFFFFFFFF,	/* dma_attr_seg */
	(int)1,			/* dma_attr_sgllen */
	(uint32_t)1,		/* granularity */
	(uint_t)0		/* dma_attr_flags */
};

/* PIO access attributes for registers */
static ddi_device_acc_attr_t pcn_acc_attr = {
	DDI_DEVICE_ATTR_V0,
	DDI_STRUCTURE_LE_ACC,
	DDI_STRICTORDER_ACC
};


static mac_callbacks_t amd8111s_m_callbacks = {
	MC_IOCTL,
	amd8111s_m_stat,
	amd8111s_m_start,
	amd8111s_m_stop,
	amd8111s_m_promisc,
	amd8111s_m_multicst,
	amd8111s_m_unicst,
	amd8111s_m_tx,
	NULL,
	amd8111s_m_ioctl
};


/*
 * Standard Driver Load Entry Point
 * It will be called at load time of driver.
 */
int
_init()
{
	int status;
	mac_init_ops(&amd8111s_dev_ops, "amd8111s");

	status = mod_install(&amd8111s_modlinkage);
	if (status != DDI_SUCCESS) {
		mac_fini_ops(&amd8111s_dev_ops);
	}

	return (status);
}

/*
 * Standard Driver Entry Point for Query.
 * It will be called at any time to get Driver info.
 */
int
_info(struct modinfo *modinfop)
{
	return (mod_info(&amd8111s_modlinkage, modinfop));
}

/*
 *	Standard Driver Entry Point for Unload.
 *	It will be called at unload time of driver.
 */
int
_fini()
{
	int status;

	status = mod_remove(&amd8111s_modlinkage);
	if (status == DDI_SUCCESS) {
		mac_fini_ops(&amd8111s_dev_ops);
	}

	return (status);
}

/*
 * Loopback Support
 */
static lb_property_t loopmodes[] = {
	{ normal,	"normal",	AMD8111S_LB_NONE		},
	{ external,	"100Mbps",	AMD8111S_LB_EXTERNAL_100	},
	{ external,	"10Mbps",	AMD8111S_LB_EXTERNAL_10		},
	{ internal,	"MAC",		AMD8111S_LB_INTERNAL_MAC	}
};

static void
amd8111s_set_loop_mode(struct LayerPointers *adapter, uint32_t mode)
{

	/*
	 * If the mode isn't being changed, there's nothing to do ...
	 */
	if (mode == adapter->pOdl->loopback_mode)
		return;

	/*
	 * Validate the requested mode and prepare a suitable message
	 * to explain the link down/up cycle that the change will
	 * probably induce ...
	 */
	switch (mode) {
	default:
		return;

	case AMD8111S_LB_NONE:
		mdlStopChip(adapter);
		if (adapter->pOdl->loopback_mode == AMD8111S_LB_INTERNAL_MAC) {
			cmn_err(CE_NOTE, "LB_NONE restored from Interanl LB");
			WRITE_REG32(adapter, adapter->pMdl->Mem_Address + CMD2,
			    INLOOP);
			WRITE_REG32(adapter, adapter->pMdl->Mem_Address + CMD3,
			    FORCE_FULL_DUPLEX | FORCE_LINK_STATUS);
		} else {
			cmn_err(CE_NOTE, "LB_NONE restored from Exteranl LB");
			WRITE_REG32(adapter, adapter->pMdl->Mem_Address + CMD2,
			    EXLOOP);
		}

		amd8111s_reset(adapter);
		adapter->pOdl->LinkStatus = LINK_STATE_DOWN;
		adapter->pOdl->rx_fcs_stripped = B_FALSE;
		mdlStartChip(adapter);
		break;

	case AMD8111S_LB_EXTERNAL_100:
		cmn_err(CE_NOTE, "amd8111s_set_loop_mode LB_EXTERNAL_100");
		mdlStopChip(adapter);
		amd8111s_reset(adapter);
		SetIntrCoalesc(adapter, B_FALSE);
		mdlPHYAutoNegotiation(adapter, PHY_FORCE_FD_100);
		WRITE_REG32(adapter, adapter->pMdl->Mem_Address + CMD2,
		    VAL0 | EXLOOP);
		adapter->pOdl->LinkStatus = LINK_STATE_UP;
		adapter->pMdl->Speed = 100;
		adapter->pMdl->FullDuplex = B_TRUE;
		/* Tell GLD the state of the physical link. */
		mac_link_update(adapter->pOdl->mh, LINK_STATE_UP);

		adapter->pOdl->rx_fcs_stripped = B_TRUE;

		mdlStartChip(adapter);
		break;

	case AMD8111S_LB_EXTERNAL_10:
		cmn_err(CE_NOTE, "amd8111s_set_loop_mode LB_EXTERNAL_10");
		mdlStopChip(adapter);
		amd8111s_reset(adapter);
		SetIntrCoalesc(adapter, B_FALSE);
		mdlPHYAutoNegotiation(adapter, PHY_FORCE_FD_10);
		WRITE_REG32(adapter, adapter->pMdl->Mem_Address + CMD2,
		    VAL0 | EXLOOP);
		adapter->pOdl->LinkStatus = LINK_STATE_UP;
		adapter->pMdl->Speed = 10;
		adapter->pMdl->FullDuplex = B_TRUE;
		/* Tell GLD the state of the physical link. */
		mac_link_update(adapter->pOdl->mh, LINK_STATE_UP);

		adapter->pOdl->rx_fcs_stripped = B_TRUE;

		mdlStartChip(adapter);
		break;

	case AMD8111S_LB_INTERNAL_MAC:
		cmn_err(CE_NOTE, "amd8111s_set_loop_mode LB_INTERNAL_MAC");
		mdlStopChip(adapter);
		amd8111s_reset(adapter);
		SetIntrCoalesc(adapter, B_FALSE);
		/* Disable Port Manager */
		WRITE_REG32(adapter, adapter->pMdl->Mem_Address + CMD3,
		    EN_PMGR);
		WRITE_REG32(adapter, adapter->pMdl->Mem_Address + CMD2,
		    VAL0 | INLOOP);

		WRITE_REG32(adapter, adapter->pMdl->Mem_Address + CMD3,
		    VAL1 | FORCE_FULL_DUPLEX | FORCE_LINK_STATUS);

		adapter->pOdl->LinkStatus = LINK_STATE_UP;
		adapter->pMdl->FullDuplex = B_TRUE;
		/* Tell GLD the state of the physical link. */
		mac_link_update(adapter->pOdl->mh, LINK_STATE_UP);

		adapter->pOdl->rx_fcs_stripped = B_TRUE;

		mdlStartChip(adapter);
		break;
	}

	/*
	 * All OK; tell the caller to reprogram
	 * the PHY and/or MAC for the new mode ...
	 */
	adapter->pOdl->loopback_mode = mode;
}

static enum ioc_reply
amd8111s_loopback_ioctl(struct LayerPointers *adapter, struct iocblk *iocp,
    mblk_t *mp)
{
	lb_info_sz_t *lbsp;
	lb_property_t *lbpp;
	uint32_t *lbmp;
	int cmd;

	/*
	 * Validate format of ioctl
	 */
	if (mp->b_cont == NULL)
		return (IOC_INVAL);

	cmd = iocp->ioc_cmd;
	switch (cmd) {
	default:
		/* NOTREACHED */
		amd8111s_log(adapter, CE_NOTE,
		    "amd8111s_loop_ioctl: invalid cmd 0x%x", cmd);
		return (IOC_INVAL);

	case LB_GET_INFO_SIZE:
		if (iocp->ioc_count != sizeof (lb_info_sz_t)) {
			amd8111s_log(adapter, CE_NOTE,
			    "wrong LB_GET_INFO_SIZE size");
			return (IOC_INVAL);
		}
		lbsp = (void *)mp->b_cont->b_rptr;
		*lbsp = sizeof (loopmodes);
		break;

	case LB_GET_INFO:
		if (iocp->ioc_count != sizeof (loopmodes)) {
			amd8111s_log(adapter, CE_NOTE,
			    "Wrong LB_GET_INFO size");
			return (IOC_INVAL);
		}
		lbpp = (void *)mp->b_cont->b_rptr;
		bcopy(loopmodes, lbpp, sizeof (loopmodes));
		break;

	case LB_GET_MODE:
		if (iocp->ioc_count != sizeof (uint32_t)) {
			amd8111s_log(adapter, CE_NOTE,
			    "Wrong LB_GET_MODE size");
			return (IOC_INVAL);
		}
		lbmp = (void *)mp->b_cont->b_rptr;
		*lbmp = adapter->pOdl->loopback_mode;
		break;

	case LB_SET_MODE:
		if (iocp->ioc_count != sizeof (uint32_t)) {
			amd8111s_log(adapter, CE_NOTE,
			    "Wrong LB_SET_MODE size");
			return (IOC_INVAL);
		}
		lbmp = (void *)mp->b_cont->b_rptr;
		amd8111s_set_loop_mode(adapter, *lbmp);
		break;
	}
	return (IOC_REPLY);
}

static void
amd8111s_m_ioctl(void *arg, queue_t *q, mblk_t *mp)
{
	struct iocblk *iocp;
	struct LayerPointers *adapter;
	enum ioc_reply status;

	iocp = (void *)mp->b_rptr;
	iocp->ioc_error = 0;
	adapter = arg;

	ASSERT(adapter);
	if (adapter == NULL) {
		miocnak(q, mp, 0, EINVAL);
		return;
	}

	switch (iocp->ioc_cmd) {

	case LB_GET_INFO_SIZE:
	case LB_GET_INFO:
	case LB_GET_MODE:
	case LB_SET_MODE:
		status = amd8111s_loopback_ioctl(adapter, iocp, mp);
		break;

	default:
		status = IOC_INVAL;
		break;
	}

	/*
	 * Decide how to reply
	 */
	switch (status) {
	default:
	case IOC_INVAL:
		/*
		 * Error, reply with a NAK and EINVAL or the specified error
		 */
		miocnak(q, mp, 0, iocp->ioc_error == 0 ?
		    EINVAL : iocp->ioc_error);
		break;

	case IOC_DONE:
		/*
		 * OK, reply already sent
		 */
		break;

	case IOC_ACK:
		/*
		 * OK, reply with an ACK
		 */
		miocack(q, mp, 0, 0);
		break;

	case IOC_REPLY:
		/*
		 * OK, send prepared reply as ACK or NAK
		 */
		mp->b_datap->db_type = iocp->ioc_error == 0 ?
		    M_IOCACK : M_IOCNAK;
		qreply(q, mp);
		break;
	}
}

/*
 * Copy one packet from dma memory to mblk. Inc dma descriptor pointer.
 */
static boolean_t
amd8111s_recv_copy(struct LayerPointers *pLayerPointers, mblk_t **last_mp)
{
	int length = 0;
	mblk_t *mp;
	struct rx_desc *descriptor;
	struct odl *pOdl = pLayerPointers->pOdl;
	struct amd8111s_statistics *statistics = &pOdl->statistics;
	struct nonphysical *pNonphysical = pLayerPointers->pMil
	    ->pNonphysical;

	mutex_enter(&pOdl->mdlRcvLock);
	descriptor = pNonphysical->RxBufDescQRead->descriptor;
	(void) ddi_dma_sync(pOdl->rx_desc_dma_handle,
	    pNonphysical->RxBufDescQRead->descriptor -
	    pNonphysical->RxBufDescQStart->descriptor,
	    sizeof (struct rx_desc), DDI_DMA_SYNC_FORCPU);
	if ((descriptor->Rx_OWN) == 0) {
	/*
	 * If the frame is received with errors, then set MCNT
	 * of that pkt in ReceiveArray to 0. This packet would
	 * be discarded later and not indicated to OS.
	 */
		if (descriptor->Rx_ERR) {
			statistics->rx_desc_err ++;
			descriptor->Rx_ERR = 0;
			if (descriptor->Rx_FRAM == 1) {
				statistics->rx_desc_err_FRAM ++;
				descriptor->Rx_FRAM = 0;
			}
			if (descriptor->Rx_OFLO == 1) {
				statistics->rx_desc_err_OFLO ++;
				descriptor->Rx_OFLO = 0;
				pOdl->rx_overflow_counter ++;
				if ((pOdl->rx_overflow_counter > 5) &&
				    (pOdl->pause_interval == 0)) {
					statistics->rx_double_overflow ++;
					mdlSendPause(pLayerPointers);
					pOdl->rx_overflow_counter = 0;
					pOdl->pause_interval = 25;
				}
			}
			if (descriptor->Rx_CRC == 1) {
				statistics->rx_desc_err_CRC ++;
				descriptor->Rx_CRC = 0;
			}
			if (descriptor->Rx_BUFF == 1) {
				statistics->rx_desc_err_BUFF ++;
				descriptor->Rx_BUFF = 0;
			}
			goto Next_Descriptor;
		}

		/* Length of incoming packet */
		if (pOdl->rx_fcs_stripped) {
			length = descriptor->Rx_MCNT -4;
		} else {
			length = descriptor->Rx_MCNT;
		}
		if (length < 62) {
			statistics->rx_error_zerosize ++;
		}

		if ((mp = allocb(length, BPRI_MED)) == NULL) {
			statistics->rx_allocfail ++;
			goto failed;
		}
		/* Copy from virtual address of incoming packet */
		bcopy((long *)*(pNonphysical->RxBufDescQRead->USpaceMap),
		    mp->b_rptr, length);
		mp->b_wptr = mp->b_rptr + length;
		statistics->rx_ok_packets ++;
		if (*last_mp == NULL) {
			*last_mp = mp;
		} else {
			(*last_mp)->b_next = mp;
			*last_mp = mp;
		}

Next_Descriptor:
		descriptor->Rx_MCNT = 0;
		descriptor->Rx_SOP = 0;
		descriptor->Rx_EOP = 0;
		descriptor->Rx_PAM = 0;
		descriptor->Rx_BAM = 0;
		descriptor->TT = 0;
		descriptor->Rx_OWN = 1;
		pNonphysical->RxBufDescQRead->descriptor++;
		pNonphysical->RxBufDescQRead->USpaceMap++;
		if (pNonphysical->RxBufDescQRead->descriptor >
		    pNonphysical->RxBufDescQEnd->descriptor) {
			pNonphysical->RxBufDescQRead->descriptor =
			    pNonphysical->RxBufDescQStart->descriptor;
			pNonphysical->RxBufDescQRead->USpaceMap =
			    pNonphysical->RxBufDescQStart->USpaceMap;
		}
		mutex_exit(&pOdl->mdlRcvLock);

		return (B_TRUE);
	}

failed:
	mutex_exit(&pOdl->mdlRcvLock);
	return (B_FALSE);
}

/*
 * Get the received packets from NIC card and send them to GLD.
 */
static void
amd8111s_receive(struct LayerPointers *pLayerPointers)
{
	int numOfPkts = 0;
	struct odl *pOdl;
	mblk_t *ret_mp = NULL, *last_mp = NULL;

	pOdl = pLayerPointers->pOdl;

	rw_enter(&pOdl->chip_lock, RW_READER);
	if (!pLayerPointers->run) {
		rw_exit(&pOdl->chip_lock);
		return;
	}

	if (pOdl->pause_interval > 0)
		pOdl->pause_interval --;

	while (numOfPkts < RX_RING_SIZE) {

		if (!amd8111s_recv_copy(pLayerPointers, &last_mp)) {
			break;
		}
		if (ret_mp == NULL)
			ret_mp = last_mp;
		numOfPkts++;
	}

	if (ret_mp) {
		mac_rx(pOdl->mh, NULL, ret_mp);
	}

	(void) ddi_dma_sync(pOdl->rx_desc_dma_handle, 0, 0,
	    DDI_DMA_SYNC_FORDEV);

	mdlReceive(pLayerPointers);

	rw_exit(&pOdl->chip_lock);

}

/*
 * Print message in release-version driver.
 */
static void
amd8111s_log(struct LayerPointers *adapter, int level, char *fmt, ...)
{
	auto char name[32];
	auto char buf[256];
	va_list ap;

	if (adapter != NULL) {
		(void) sprintf(name, "amd8111s%d",
		    ddi_get_instance(adapter->pOdl->devinfo));
	} else {
		(void) sprintf(name, "amd8111s");
	}
	va_start(ap, fmt);
	(void) vsprintf(buf, fmt, ap);
	va_end(ap);
	cmn_err(level, "%s: %s", name, buf);
}

/*
 * To allocate & initilize all resources.
 * Called by amd8111s_attach().
 */
static int
amd8111s_odlInit(struct LayerPointers *pLayerPointers)
{
	unsigned long mem_req_array[MEM_REQ_MAX];
	unsigned long mem_set_array[MEM_REQ_MAX];
	unsigned long *pmem_req_array;
	unsigned long *pmem_set_array;
	int i, size;

	for (i = 0; i < MEM_REQ_MAX; i++) {
		mem_req_array[i] = 0;
		mem_set_array[i] = 0;
	}

	milRequestResources(mem_req_array);

	pmem_req_array = mem_req_array;
	pmem_set_array = mem_set_array;
	while (*pmem_req_array) {
		switch (*pmem_req_array) {
		case VIRTUAL:
			*pmem_set_array = VIRTUAL;
			pmem_req_array++;
			pmem_set_array++;
			*(pmem_set_array) = *(pmem_req_array);
			pmem_set_array++;
			*(pmem_set_array) = (unsigned long) kmem_zalloc(
			    *(pmem_req_array), KM_NOSLEEP);
			if (*pmem_set_array == 0)
				goto odl_init_failure;
			break;
		}
		pmem_req_array++;
		pmem_set_array++;
	}

	/*
	 * Initilize memory on lower layers
	 */
	milSetResources(pLayerPointers, mem_set_array);

	/* Allocate Rx/Tx descriptors */
	if (amd8111s_allocate_descriptors(pLayerPointers) != B_TRUE) {
		*pmem_set_array = 0;
		goto odl_init_failure;
	}

	/*
	 * Allocate Rx buffer for each Rx descriptor. Then call mil layer
	 * routine to fill physical address of Rx buffer into Rx descriptor.
	 */
	if (amd8111s_allocate_buffers(pLayerPointers) == B_FALSE) {
		amd8111s_free_descriptors(pLayerPointers);
		*pmem_set_array = 0;
		goto odl_init_failure;
	}
	milInitGlbds(pLayerPointers);

	return (0);

odl_init_failure:
	/*
	 * Free All memory allocated so far
	 */
	pmem_req_array = mem_set_array;
	while ((*pmem_req_array) && (pmem_req_array != pmem_set_array)) {
		switch (*pmem_req_array) {
		case VIRTUAL:
			pmem_req_array++;	/* Size */
			size = *(pmem_req_array);
			pmem_req_array++;	/* Virtual Address */
			if (pmem_req_array == NULL)
				return (1);
			kmem_free((int *)*pmem_req_array, size);
			break;
		}
		pmem_req_array++;
	}
	return (1);
}

/*
 * Allocate and initialize Tx/Rx descriptors
 */
static boolean_t
amd8111s_allocate_descriptors(struct LayerPointers *pLayerPointers)
{
	struct odl *pOdl = pLayerPointers->pOdl;
	struct mil *pMil = pLayerPointers->pMil;
	dev_info_t *devinfo = pOdl->devinfo;
	uint_t length, count, i;
	size_t real_length;

	/*
	 * Allocate Rx descriptors
	 */
	if (ddi_dma_alloc_handle(devinfo, &pcn_desc_dma_attr_t, DDI_DMA_SLEEP,
	    NULL, &pOdl->rx_desc_dma_handle) != DDI_SUCCESS) {
		amd8111s_log(pLayerPointers, CE_WARN,
		    "ddi_dma_alloc_handle for Rx desc failed");
		pOdl->rx_desc_dma_handle = NULL;
		return (B_FALSE);
	}

	length = sizeof (struct rx_desc) * RX_RING_SIZE + ALIGNMENT;
	if (ddi_dma_mem_alloc(pOdl->rx_desc_dma_handle, length,
	    &pcn_acc_attr, DDI_DMA_CONSISTENT, DDI_DMA_SLEEP,
	    NULL, (caddr_t *)&pMil->Rx_desc_original, &real_length,
	    &pOdl->rx_desc_acc_handle) != DDI_SUCCESS) {

		amd8111s_log(pLayerPointers, CE_WARN,
		    "ddi_dma_mem_handle for Rx desc failed");
		ddi_dma_free_handle(&pOdl->rx_desc_dma_handle);
		pOdl->rx_desc_dma_handle = NULL;
		return (B_FALSE);
	}

	if (ddi_dma_addr_bind_handle(pOdl->rx_desc_dma_handle,
	    NULL, (caddr_t)pMil->Rx_desc_original, real_length,
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT, DDI_DMA_SLEEP,
	    NULL, &pOdl->rx_desc_dma_cookie,
	    &count) != DDI_SUCCESS) {

		amd8111s_log(pLayerPointers, CE_WARN,
		    "ddi_dma_addr_bind_handle for Rx desc failed");
		ddi_dma_mem_free(&pOdl->rx_desc_acc_handle);
		ddi_dma_free_handle(&pOdl->rx_desc_dma_handle);
		pOdl->rx_desc_dma_handle = NULL;
		return (B_FALSE);
	}
	ASSERT(count == 1);

	/* Initialize Rx descriptors related variables */
	pMil->Rx_desc = (struct rx_desc *)
	    ((pMil->Rx_desc_original + ALIGNMENT) & ~ALIGNMENT);
	pMil->Rx_desc_pa = (unsigned int)
	    ((pOdl->rx_desc_dma_cookie.dmac_laddress + ALIGNMENT) & ~ALIGNMENT);

	pLayerPointers->pMdl->init_blk->RDRA = pMil->Rx_desc_pa;


	/*
	 * Allocate Tx descriptors
	 */
	if (ddi_dma_alloc_handle(devinfo, &pcn_desc_dma_attr_t, DDI_DMA_SLEEP,
	    NULL, &pOdl->tx_desc_dma_handle) != DDI_SUCCESS) {
		amd8111s_log(pLayerPointers, CE_WARN,
		    "ddi_dma_alloc_handle for Tx desc failed");
		goto allocate_desc_fail;
	}

	length = sizeof (struct tx_desc) * TX_RING_SIZE + ALIGNMENT;
	if (ddi_dma_mem_alloc(pOdl->tx_desc_dma_handle, length,
	    &pcn_acc_attr, DDI_DMA_CONSISTENT, DDI_DMA_SLEEP,
	    NULL, (caddr_t *)&pMil->Tx_desc_original, &real_length,
	    &pOdl->tx_desc_acc_handle) != DDI_SUCCESS) {

		amd8111s_log(pLayerPointers, CE_WARN,
		    "ddi_dma_mem_handle for Tx desc failed");
		ddi_dma_free_handle(&pOdl->tx_desc_dma_handle);
		goto allocate_desc_fail;
	}

	if (ddi_dma_addr_bind_handle(pOdl->tx_desc_dma_handle,
	    NULL, (caddr_t)pMil->Tx_desc_original, real_length,
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT, DDI_DMA_SLEEP,
	    NULL, &pOdl->tx_desc_dma_cookie,
	    &count) != DDI_SUCCESS) {

		amd8111s_log(pLayerPointers, CE_WARN,
		    "ddi_dma_addr_bind_handle for Tx desc failed");
		ddi_dma_mem_free(&pOdl->tx_desc_acc_handle);
		ddi_dma_free_handle(&pOdl->tx_desc_dma_handle);
		goto allocate_desc_fail;
	}
	ASSERT(count == 1);
	/* Set the DMA area to all zeros */
	bzero((caddr_t)pMil->Tx_desc_original, length);

	/* Initialize Tx descriptors related variables */
	pMil->Tx_desc = (struct tx_desc *)
	    ((pMil->Tx_desc_original + ALIGNMENT) & ~ALIGNMENT);
	pMil->pNonphysical->TxDescQRead = pMil->Tx_desc;
	pMil->pNonphysical->TxDescQWrite = pMil->Tx_desc;
	pMil->pNonphysical->TxDescQStart = pMil->Tx_desc;
	pMil->pNonphysical->TxDescQEnd = &(pMil->Tx_desc[TX_RING_SIZE -1]);

	/* Physical Addr of Tx_desc_original & Tx_desc */
	pLayerPointers->pMil->Tx_desc_pa =
	    ((pOdl->tx_desc_dma_cookie.dmac_laddress + ALIGNMENT) &
	    ~ALIGNMENT);

	/* Setting the reserved bits in the tx descriptors */
	for (i = 0; i < TX_RING_SIZE; i++) {
		pMil->pNonphysical->TxDescQWrite->Tx_RES0 = 0x0f;
		pMil->pNonphysical->TxDescQWrite->Tx_OWN = 0;
		pMil->pNonphysical->TxDescQWrite++;
	}
	pMil->pNonphysical->TxDescQWrite = pMil->pNonphysical->TxDescQStart;

	pLayerPointers->pMdl->init_blk->TDRA = pMil->Tx_desc_pa;

	return (B_TRUE);

allocate_desc_fail:
	pOdl->tx_desc_dma_handle = NULL;
	(void) ddi_dma_unbind_handle(pOdl->rx_desc_dma_handle);
	ddi_dma_mem_free(&pOdl->rx_desc_acc_handle);
	ddi_dma_free_handle(&pOdl->rx_desc_dma_handle);
	pOdl->rx_desc_dma_handle = NULL;
	return (B_FALSE);
}

/*
 * Free Tx/Rx descriptors
 */
static void
amd8111s_free_descriptors(struct LayerPointers *pLayerPointers)
{
	struct odl *pOdl = pLayerPointers->pOdl;

	/* Free Rx descriptors */
	if (pOdl->rx_desc_dma_handle) {
		(void) ddi_dma_unbind_handle(pOdl->rx_desc_dma_handle);
		ddi_dma_mem_free(&pOdl->rx_desc_acc_handle);
		ddi_dma_free_handle(&pOdl->rx_desc_dma_handle);
		pOdl->rx_desc_dma_handle = NULL;
	}

	/* Free Rx descriptors */
	if (pOdl->tx_desc_dma_handle) {
		(void) ddi_dma_unbind_handle(pOdl->tx_desc_dma_handle);
		ddi_dma_mem_free(&pOdl->tx_desc_acc_handle);
		ddi_dma_free_handle(&pOdl->tx_desc_dma_handle);
		pOdl->tx_desc_dma_handle = NULL;
	}
}

/*
 * Allocate Tx/Rx Ring buffer
 */
static boolean_t
amd8111s_alloc_dma_ringbuf(struct LayerPointers *pLayerPointers,
    struct amd8111s_dma_ringbuf *pRing, uint32_t ring_size, uint32_t msg_size)
{
	uint32_t idx, msg_idx = 0, msg_acc;
	dev_info_t *devinfo = pLayerPointers->pOdl->devinfo;
	size_t real_length;
	uint_t count = 0;

	ASSERT(pcn_buff_dma_attr_t.dma_attr_align == 1);
	pRing->dma_buf_sz = msg_size;
	pRing->ring_size = ring_size;
	pRing->trunk_num = AMD8111S_SPLIT;
	pRing->buf_sz = msg_size * ring_size;
	if (ring_size < pRing->trunk_num)
		pRing->trunk_num = ring_size;
	ASSERT((pRing->buf_sz % pRing->trunk_num) == 0);

	pRing->trunk_sz = pRing->buf_sz / pRing->trunk_num;
	ASSERT((pRing->trunk_sz % pRing->dma_buf_sz) == 0);

	pRing->msg_buf = kmem_zalloc(sizeof (struct amd8111s_msgbuf) *
	    ring_size, KM_NOSLEEP);
	pRing->dma_hdl = kmem_zalloc(sizeof (ddi_dma_handle_t) *
	    pRing->trunk_num, KM_NOSLEEP);
	pRing->acc_hdl = kmem_zalloc(sizeof (ddi_acc_handle_t) *
	    pRing->trunk_num, KM_NOSLEEP);
	pRing->dma_cookie = kmem_zalloc(sizeof (ddi_dma_cookie_t) *
	    pRing->trunk_num, KM_NOSLEEP);
	pRing->trunk_addr = kmem_zalloc(sizeof (caddr_t) *
	    pRing->trunk_num, KM_NOSLEEP);
	if (pRing->msg_buf == NULL || pRing->dma_hdl == NULL ||
	    pRing->acc_hdl == NULL || pRing->trunk_addr == NULL ||
	    pRing->dma_cookie == NULL) {
		amd8111s_log(pLayerPointers, CE_NOTE,
		    "kmem_zalloc failed");
		goto failed;
	}

	for (idx = 0; idx < pRing->trunk_num; ++idx) {
		if (ddi_dma_alloc_handle(devinfo, &pcn_buff_dma_attr_t,
		    DDI_DMA_SLEEP, NULL, &(pRing->dma_hdl[idx]))
		    != DDI_SUCCESS) {

			amd8111s_log(pLayerPointers, CE_WARN,
			    "ddi_dma_alloc_handle failed");
			goto failed;
		} else if (ddi_dma_mem_alloc(pRing->dma_hdl[idx],
		    pRing->trunk_sz, &pcn_acc_attr, DDI_DMA_STREAMING,
		    DDI_DMA_SLEEP, NULL,
		    (caddr_t *)&(pRing->trunk_addr[idx]),
		    (size_t *)(&real_length), &pRing->acc_hdl[idx])
		    != DDI_SUCCESS) {

			amd8111s_log(pLayerPointers, CE_WARN,
			    "ddi_dma_mem_alloc failed");
			goto failed;
		} else if (real_length != pRing->trunk_sz) {
			amd8111s_log(pLayerPointers, CE_WARN,
			    "ddi_dma_mem_alloc failed");
			goto failed;
		} else if (ddi_dma_addr_bind_handle(pRing->dma_hdl[idx],
		    NULL, (caddr_t)pRing->trunk_addr[idx], real_length,
		    DDI_DMA_WRITE | DDI_DMA_STREAMING, DDI_DMA_SLEEP, NULL,
		    &pRing->dma_cookie[idx], &count) != DDI_DMA_MAPPED) {

			amd8111s_log(pLayerPointers, CE_WARN,
			    "ddi_dma_addr_bind_handle failed");
			goto failed;
		} else {
			for (msg_acc = 0;
			    msg_acc < pRing->trunk_sz / pRing->dma_buf_sz;
			    ++ msg_acc) {
				pRing->msg_buf[msg_idx].offset =
				    msg_acc * pRing->dma_buf_sz;
				pRing->msg_buf[msg_idx].vir_addr =
				    pRing->trunk_addr[idx] +
				    pRing->msg_buf[msg_idx].offset;
				pRing->msg_buf[msg_idx].phy_addr =
				    pRing->dma_cookie[idx].dmac_laddress +
				    pRing->msg_buf[msg_idx].offset;
				pRing->msg_buf[msg_idx].p_hdl =
				    pRing->dma_hdl[idx];
				msg_idx ++;
			}
		}
	}

	pRing->free = pRing->msg_buf;
	pRing->next = pRing->msg_buf;
	pRing->curr = pRing->msg_buf;

	return (B_TRUE);
failed:
	amd8111s_free_dma_ringbuf(pRing);
	return (B_FALSE);
}

/*
 * Free Tx/Rx ring buffer
 */
static void
amd8111s_free_dma_ringbuf(struct amd8111s_dma_ringbuf *pRing)
{
	int idx;

	if (pRing->dma_cookie != NULL) {
		for (idx = 0; idx < pRing->trunk_num; idx ++) {
			if (pRing->dma_cookie[idx].dmac_laddress == 0) {
				break;
			}
			(void) ddi_dma_unbind_handle(pRing->dma_hdl[idx]);
		}
		kmem_free(pRing->dma_cookie,
		    sizeof (ddi_dma_cookie_t) * pRing->trunk_num);
	}

	if (pRing->acc_hdl != NULL) {
		for (idx = 0; idx < pRing->trunk_num; idx ++) {
			if (pRing->acc_hdl[idx] == NULL)
				break;
			ddi_dma_mem_free(&pRing->acc_hdl[idx]);
		}
		kmem_free(pRing->acc_hdl,
		    sizeof (ddi_acc_handle_t) * pRing->trunk_num);
	}

	if (pRing->dma_hdl != NULL) {
		for (idx = 0; idx < pRing->trunk_num; idx ++) {
			if (pRing->dma_hdl[idx] == 0) {
				break;
			}
			ddi_dma_free_handle(&pRing->dma_hdl[idx]);
		}
		kmem_free(pRing->dma_hdl,
		    sizeof (ddi_dma_handle_t) * pRing->trunk_num);
	}

	if (pRing->msg_buf != NULL) {
		kmem_free(pRing->msg_buf,
		    sizeof (struct amd8111s_msgbuf) * pRing->ring_size);
	}

	if (pRing->trunk_addr != NULL) {
		kmem_free(pRing->trunk_addr,
		    sizeof (caddr_t) * pRing->trunk_num);
	}

	bzero(pRing, sizeof (*pRing));
}


/*
 * Allocate all Tx buffer.
 * Allocate a Rx buffer for each Rx descriptor. Then
 * call mil routine to fill physical address of Rx
 * buffer into Rx descriptors
 */
static boolean_t
amd8111s_allocate_buffers(struct LayerPointers *pLayerPointers)
{
	struct odl *pOdl = pLayerPointers->pOdl;

	/*
	 * Allocate rx Buffers
	 */
	if (amd8111s_alloc_dma_ringbuf(pLayerPointers, &pOdl->rx_buf,
	    RX_RING_SIZE, RX_BUF_SIZE) == B_FALSE) {
		amd8111s_log(pLayerPointers, CE_WARN,
		    "amd8111s_alloc_dma_ringbuf for tx failed");
		goto allocate_buf_fail;
	}

	/*
	 * Allocate Tx buffers
	 */
	if (amd8111s_alloc_dma_ringbuf(pLayerPointers, &pOdl->tx_buf,
	    TX_COALESC_SIZE, TX_BUF_SIZE) == B_FALSE) {
		amd8111s_log(pLayerPointers, CE_WARN,
		    "amd8111s_alloc_dma_ringbuf for tx failed");
		goto allocate_buf_fail;
	}

	/*
	 * Initilize the mil Queues
	 */
	milInitGlbds(pLayerPointers);

	milInitRxQ(pLayerPointers);

	return (B_TRUE);

allocate_buf_fail:

	amd8111s_log(pLayerPointers, CE_WARN,
	    "amd8111s_allocate_buffers failed");
	return (B_FALSE);
}

/*
 * Free all Rx/Tx buffer
 */

static void
amd8111s_free_buffers(struct LayerPointers *pLayerPointers)
{
	/* Free Tx buffers */
	amd8111s_free_dma_ringbuf(&pLayerPointers->pOdl->tx_buf);

	/* Free Rx Buffers */
	amd8111s_free_dma_ringbuf(&pLayerPointers->pOdl->rx_buf);
}

/*
 * Try to recycle all the descriptors and Tx buffers
 * which are already freed by hardware.
 */
static int
amd8111s_recycle_tx(struct LayerPointers *pLayerPointers)
{
	struct nonphysical *pNonphysical;
	uint32_t count = 0;

	pNonphysical = pLayerPointers->pMil->pNonphysical;
	while (pNonphysical->TxDescQRead->Tx_OWN == 0 &&
	    pNonphysical->TxDescQRead != pNonphysical->TxDescQWrite) {
		pLayerPointers->pOdl->tx_buf.free =
		    NEXT(pLayerPointers->pOdl->tx_buf, free);
		pNonphysical->TxDescQRead++;
		if (pNonphysical->TxDescQRead > pNonphysical->TxDescQEnd) {
			pNonphysical->TxDescQRead = pNonphysical->TxDescQStart;
		}
		count ++;
	}

	if (pLayerPointers->pMil->tx_reschedule)
		ddi_trigger_softintr(pLayerPointers->pOdl->drain_id);

	return (count);
}

/*
 * Get packets in the Tx buffer, then copy them to the send buffer.
 * Trigger hardware to send out packets.
 */
static void
amd8111s_send_serial(struct LayerPointers *pLayerPointers)
{
	struct nonphysical *pNonphysical;
	uint32_t count;

	pNonphysical = pLayerPointers->pMil->pNonphysical;

	mutex_enter(&pLayerPointers->pOdl->mdlSendLock);

	for (count = 0; count < AMD8111S_SEND_MAX; count ++) {
		if (pLayerPointers->pOdl->tx_buf.curr ==
		    pLayerPointers->pOdl->tx_buf.next) {
			break;
		}
		/* to verify if it needs to recycle the tx Buf */
		if (((pNonphysical->TxDescQWrite + 1 >
		    pNonphysical->TxDescQEnd) ? pNonphysical->TxDescQStart :
		    (pNonphysical->TxDescQWrite + 1)) ==
		    pNonphysical->TxDescQRead)
			if (amd8111s_recycle_tx(pLayerPointers) == 0) {
				pLayerPointers->pOdl
				    ->statistics.tx_no_descriptor ++;
				break;
			}

		/* Fill packet length */
		pNonphysical->TxDescQWrite->Tx_BCNT = (uint16_t)pLayerPointers
		    ->pOdl->tx_buf.curr->msg_size;

		/* Fill physical buffer address */
		pNonphysical->TxDescQWrite->Tx_Base_Addr = (unsigned int)
		    pLayerPointers->pOdl->tx_buf.curr->phy_addr;

		pNonphysical->TxDescQWrite->Tx_SOP = 1;
		pNonphysical->TxDescQWrite->Tx_EOP = 1;
		pNonphysical->TxDescQWrite->Tx_ADD_FCS = 1;
		pNonphysical->TxDescQWrite->Tx_LTINT = 1;
		pNonphysical->TxDescQWrite->Tx_USPACE = 0;
		pNonphysical->TxDescQWrite->Tx_OWN = 1;

		pNonphysical->TxDescQWrite++;
		if (pNonphysical->TxDescQWrite > pNonphysical->TxDescQEnd) {
			pNonphysical->TxDescQWrite = pNonphysical->TxDescQStart;
		}

		pLayerPointers->pOdl->tx_buf.curr =
		    NEXT(pLayerPointers->pOdl->tx_buf, curr);

	}

	pLayerPointers->pOdl->statistics.tx_ok_packets += count;

	mutex_exit(&pLayerPointers->pOdl->mdlSendLock);

	/* Call mdlTransmit to send the pkt out on the network */
	mdlTransmit(pLayerPointers);

}

/*
 * Softintr entrance. try to send out packets in the Tx buffer.
 * If reschedule is True, call mac_tx_update to re-enable the
 * transmit
 */
static uint_t
amd8111s_send_drain(caddr_t arg)
{
	struct LayerPointers *pLayerPointers = (void *)arg;

	amd8111s_send_serial(pLayerPointers);

	if (pLayerPointers->pMil->tx_reschedule &&
	    NEXT(pLayerPointers->pOdl->tx_buf, next) !=
	    pLayerPointers->pOdl->tx_buf.free) {
		mac_tx_update(pLayerPointers->pOdl->mh);
		pLayerPointers->pMil->tx_reschedule = B_FALSE;
	}

	return (DDI_INTR_CLAIMED);
}

/*
 * Get a Tx buffer
 */
static struct amd8111s_msgbuf *
amd8111s_getTxbuf(struct LayerPointers *pLayerPointers)
{
	struct amd8111s_msgbuf *tmp, *next;

	mutex_enter(&pLayerPointers->pOdl->mdlSendLock);
	next = NEXT(pLayerPointers->pOdl->tx_buf, next);
	if (next == pLayerPointers->pOdl->tx_buf.free) {
		tmp = NULL;
	} else {
		tmp = pLayerPointers->pOdl->tx_buf.next;
		pLayerPointers->pOdl->tx_buf.next = next;
	}
	mutex_exit(&pLayerPointers->pOdl->mdlSendLock);

	return (tmp);
}

static boolean_t
amd8111s_send(struct LayerPointers *pLayerPointers, mblk_t *mp)
{
	struct odl *pOdl;
	size_t frag_len;
	mblk_t *tmp;
	struct amd8111s_msgbuf *txBuf;
	uint8_t *pMsg;

	pOdl = pLayerPointers->pOdl;

	/* alloc send buffer */
	txBuf = amd8111s_getTxbuf(pLayerPointers);
	if (txBuf == NULL) {
		pOdl->statistics.tx_no_buffer ++;
		pLayerPointers->pMil->tx_reschedule = B_TRUE;
		amd8111s_send_serial(pLayerPointers);
		return (B_FALSE);
	}

	/* copy packet to send buffer */
	txBuf->msg_size = 0;
	pMsg = (uint8_t *)txBuf->vir_addr;
	for (tmp = mp; tmp; tmp = tmp->b_cont) {
		frag_len = MBLKL(tmp);
		bcopy(tmp->b_rptr, pMsg, frag_len);
		txBuf->msg_size += frag_len;
		pMsg += frag_len;
	}
	freemsg(mp);

	amd8111s_send_serial(pLayerPointers);

	return (B_TRUE);
}

/*
 * (GLD Entry Point) Send the message block to lower layer
 */
static mblk_t *
amd8111s_m_tx(void *arg, mblk_t *mp)
{
	struct LayerPointers *pLayerPointers = arg;
	mblk_t *next;

	rw_enter(&pLayerPointers->pOdl->chip_lock, RW_READER);
	if (!pLayerPointers->run) {
		pLayerPointers->pOdl->statistics.tx_afterunplumb ++;
		freemsgchain(mp);
		mp = NULL;
	}

	while (mp != NULL) {
		next = mp->b_next;
		mp->b_next = NULL;
		if (!amd8111s_send(pLayerPointers, mp)) {
			/* Send fail */
			mp->b_next = next;
			break;
		}
		mp = next;
	}

	rw_exit(&pLayerPointers->pOdl->chip_lock);
	return (mp);
}

/*
 * (GLD Entry Point) Interrupt Service Routine
 */
static uint_t
amd8111s_intr(caddr_t arg)
{
	unsigned int intrCauses;
	struct LayerPointers *pLayerPointers = (void *)arg;

	/* Read the interrupt status from mdl */
	intrCauses = mdlReadInterrupt(pLayerPointers);

	if (intrCauses == 0) {
		pLayerPointers->pOdl->statistics.intr_OTHER ++;
		return (DDI_INTR_UNCLAIMED);
	}

	if (intrCauses & LCINT) {
		if (mdlReadLink(pLayerPointers) == LINK_UP) {
			mdlGetActiveMediaInfo(pLayerPointers);
			/* Link status changed */
			if (pLayerPointers->pOdl->LinkStatus !=
			    LINK_STATE_UP) {
				pLayerPointers->pOdl->LinkStatus =
				    LINK_STATE_UP;
				mac_link_update(pLayerPointers->pOdl->mh,
				    LINK_STATE_UP);
			}
		} else {
			if (pLayerPointers->pOdl->LinkStatus !=
			    LINK_STATE_DOWN) {
				pLayerPointers->pOdl->LinkStatus =
				    LINK_STATE_DOWN;
				mac_link_update(pLayerPointers->pOdl->mh,
				    LINK_STATE_DOWN);
			}
		}
	}
	/*
	 * RINT0: Receive Interrupt is set by the controller after the last
	 * descriptor of a receive frame for this ring has been updated by
	 * writing a 0 to the OWNership bit.
	 */
	if (intrCauses & RINT0) {
		pLayerPointers->pOdl->statistics.intr_RINT0 ++;
		amd8111s_receive(pLayerPointers);
	}

	/*
	 * TINT0: Transmit Interrupt is set by the controller after the OWN bit
	 * in the last descriptor of a transmit frame in this particular ring
	 * has been cleared to indicate the frame has been copied to the
	 * transmit FIFO.
	 */
	if (intrCauses & TINT0) {
		pLayerPointers->pOdl->statistics.intr_TINT0 ++;
		/*
		 * if desc ring is NULL and tx buf is not NULL, it should
		 * drain tx buffer
		 */
		amd8111s_send_serial(pLayerPointers);
	}

	if (intrCauses & STINT) {
		pLayerPointers->pOdl->statistics.intr_STINT ++;
	}


	return (DDI_INTR_CLAIMED);
}

/*
 * To re-initilize data structures.
 */
static void
amd8111s_sw_reset(struct LayerPointers *pLayerPointers)
{
	/* Reset all Tx/Rx queues and descriptors */
	milResetTxQ(pLayerPointers);
	milInitRxQ(pLayerPointers);
}

/*
 * Send all pending tx packets
 */
static void
amd8111s_tx_drain(struct LayerPointers *adapter)
{
	struct tx_desc *pTx_desc = adapter->pMil->pNonphysical->TxDescQStart;
	int i, desc_count = 0;
	for (i = 0; i < 30; i++) {
		while ((pTx_desc->Tx_OWN == 0) && (desc_count < TX_RING_SIZE)) {
			/* This packet has been transmitted */
			pTx_desc ++;
			desc_count ++;
		}
		if (desc_count == TX_RING_SIZE) {
			break;
		}
		/* Wait 1 ms */
		drv_usecwait(1000);
	}
	adapter->pOdl->statistics.tx_draintime = i;
}

/*
 * (GLD Entry Point) To start card will be called at
 * ifconfig plumb
 */
static int
amd8111s_m_start(void *arg)
{
	struct LayerPointers *pLayerPointers = arg;
	struct odl *pOdl = pLayerPointers->pOdl;

	amd8111s_sw_reset(pLayerPointers);
	mdlHWReset(pLayerPointers);
	rw_enter(&pOdl->chip_lock, RW_WRITER);
	pLayerPointers->run = B_TRUE;
	rw_exit(&pOdl->chip_lock);
	return (0);
}

/*
 * (GLD Entry Point) To stop card will be called at
 * ifconfig unplumb
 */
static void
amd8111s_m_stop(void *arg)
{
	struct LayerPointers *pLayerPointers = (struct LayerPointers *)arg;
	struct odl *pOdl = pLayerPointers->pOdl;

	/* Ensure send all pending tx packets */
	amd8111s_tx_drain(pLayerPointers);
	/*
	 * Stop the controller and disable the controller interrupt
	 */
	rw_enter(&pOdl->chip_lock, RW_WRITER);
	mdlStopChip(pLayerPointers);
	pLayerPointers->run = B_FALSE;
	rw_exit(&pOdl->chip_lock);
}

/*
 *	To clean up all
 */
static void
amd8111s_free_resource(struct LayerPointers *pLayerPointers)
{
	unsigned long mem_free_array[100];
	unsigned long *pmem_free_array, size;

	/* Free Rx/Tx descriptors */
	amd8111s_free_descriptors(pLayerPointers);

	/* Free memory on lower layers */
	milFreeResources(pLayerPointers, mem_free_array);
	pmem_free_array = mem_free_array;
	while (*pmem_free_array) {
		switch (*pmem_free_array) {
		case VIRTUAL:
			size = *(++pmem_free_array);
			pmem_free_array++;
			kmem_free((void *)*(pmem_free_array), size);
			break;
		}
		pmem_free_array++;
	}

	amd8111s_free_buffers(pLayerPointers);
}

/*
 * (GLD Enty pointer) To add/delete multi cast addresses
 *
 */
static int
amd8111s_m_multicst(void *arg, boolean_t add, const uint8_t *addr)
{
	struct LayerPointers *pLayerPointers = arg;

	if (add) {
		/* Add a multicast entry */
		mdlAddMulticastAddress(pLayerPointers, (UCHAR *)addr);
	} else {
		/* Delete a multicast entry */
		mdlDeleteMulticastAddress(pLayerPointers, (UCHAR *)addr);
	}

	return (0);
}

#ifdef AMD8111S_DEBUG
/*
 * The size of MIB registers is only 32 bits. Dump them before one
 * of them overflows.
 */
static void
amd8111s_dump_mib(struct LayerPointers *pLayerPointers)
{
	struct amd8111s_statistics *adapterStat;

	adapterStat = &pLayerPointers->pOdl->statistics;

	adapterStat->mib_dump_counter ++;

	/*
	 * Rx Counters
	 */
	adapterStat->rx_mib_unicst_packets +=
	    mdlReadMib(pLayerPointers, RcvUniCastPkts);
	adapterStat->rx_mib_multicst_packets +=
	    mdlReadMib(pLayerPointers, RcvMultiCastPkts);
	adapterStat->rx_mib_broadcst_packets +=
	    mdlReadMib(pLayerPointers, RcvBroadCastPkts);
	adapterStat->rx_mib_macctrl_packets +=
	    mdlReadMib(pLayerPointers, RcvMACCtrl);
	adapterStat->rx_mib_flowctrl_packets +=
	    mdlReadMib(pLayerPointers, RcvFlowCtrl);

	adapterStat->rx_mib_bytes +=
	    mdlReadMib(pLayerPointers, RcvOctets);
	adapterStat->rx_mib_good_bytes +=
	    mdlReadMib(pLayerPointers, RcvGoodOctets);

	adapterStat->rx_mib_undersize_packets +=
	    mdlReadMib(pLayerPointers, RcvUndersizePkts);
	adapterStat->rx_mib_oversize_packets +=
	    mdlReadMib(pLayerPointers, RcvOversizePkts);

	adapterStat->rx_mib_drop_packets +=
	    mdlReadMib(pLayerPointers, RcvDropPktsRing0);
	adapterStat->rx_mib_align_err_packets +=
	    mdlReadMib(pLayerPointers, RcvAlignmentErrors);
	adapterStat->rx_mib_fcs_err_packets +=
	    mdlReadMib(pLayerPointers, RcvFCSErrors);
	adapterStat->rx_mib_symbol_err_packets +=
	    mdlReadMib(pLayerPointers, RcvSymbolErrors);
	adapterStat->rx_mib_miss_packets +=
	    mdlReadMib(pLayerPointers, RcvMissPkts);

	/*
	 * Tx Counters
	 */
	adapterStat->tx_mib_packets +=
	    mdlReadMib(pLayerPointers, XmtPackets);
	adapterStat->tx_mib_multicst_packets +=
	    mdlReadMib(pLayerPointers, XmtMultiCastPkts);
	adapterStat->tx_mib_broadcst_packets +=
	    mdlReadMib(pLayerPointers, XmtBroadCastPkts);
	adapterStat->tx_mib_flowctrl_packets +=
	    mdlReadMib(pLayerPointers, XmtFlowCtrl);

	adapterStat->tx_mib_bytes +=
	    mdlReadMib(pLayerPointers, XmtOctets);

	adapterStat->tx_mib_defer_trans_packets +=
	    mdlReadMib(pLayerPointers, XmtDeferredTransmit);
	adapterStat->tx_mib_collision_packets +=
	    mdlReadMib(pLayerPointers, XmtCollisions);
	adapterStat->tx_mib_one_coll_packets +=
	    mdlReadMib(pLayerPointers, XmtOneCollision);
	adapterStat->tx_mib_multi_coll_packets +=
	    mdlReadMib(pLayerPointers, XmtMultipleCollision);
	adapterStat->tx_mib_late_coll_packets +=
	    mdlReadMib(pLayerPointers, XmtLateCollision);
	adapterStat->tx_mib_ex_coll_packets +=
	    mdlReadMib(pLayerPointers, XmtExcessiveCollision);


	/* Clear all MIB registers */
	WRITE_REG16(pLayerPointers, pLayerPointers->pMdl->Mem_Address
	    + MIB_ADDR, MIB_CLEAR);
}
#endif

/*
 * (GLD Entry Point) set/unset promiscus mode
 */
static int
amd8111s_m_promisc(void *arg, boolean_t on)
{
	struct LayerPointers *pLayerPointers = arg;

	if (on) {
		mdlSetPromiscuous(pLayerPointers);
	} else {
		mdlDisablePromiscuous(pLayerPointers);
	}

	return (0);
}

/*
 * (Gld Entry point) Changes the Mac address of card
 */
static int
amd8111s_m_unicst(void *arg, const uint8_t *macaddr)
{
	struct LayerPointers *pLayerPointers = arg;

	mdlDisableInterrupt(pLayerPointers);
	mdlSetMacAddress(pLayerPointers, (unsigned char *)macaddr);
	mdlEnableInterrupt(pLayerPointers);

	return (0);
}

/*
 * Reset the card
 */
void
amd8111s_reset(struct LayerPointers *pLayerPointers)
{
	amd8111s_sw_reset(pLayerPointers);
	mdlHWReset(pLayerPointers);
}

/*
 * attach(9E) -- Attach a device to the system
 *
 * Called once for each board after successfully probed.
 * will do
 *	a. creating minor device node for the instance.
 *	b. allocate & Initilize four layers (call odlInit)
 *	c. get MAC address
 *	d. initilize pLayerPointers to gld private pointer
 *	e. register with GLD
 * if any action fails does clean up & returns DDI_FAILURE
 * else retursn DDI_SUCCESS
 */
static int
amd8111s_attach(dev_info_t *devinfo, ddi_attach_cmd_t cmd)
{
	mac_register_t *macp;
	struct LayerPointers *pLayerPointers;
	struct odl *pOdl;
	ddi_acc_handle_t *pci_handle;
	ddi_device_acc_attr_t dev_attr;
	caddr_t addrp = NULL;

	switch (cmd) {
	case DDI_ATTACH:
		break;
	default:
		return (DDI_FAILURE);
	}

	pLayerPointers = (struct LayerPointers *)
	    kmem_zalloc(sizeof (struct LayerPointers), KM_SLEEP);
	amd8111sadapter = pLayerPointers;

	/* Get device instance number */
	pLayerPointers->instance = ddi_get_instance(devinfo);
	ddi_set_driver_private(devinfo, (caddr_t)pLayerPointers);

	pOdl = (struct odl *)kmem_zalloc(sizeof (struct odl), KM_SLEEP);
	pLayerPointers->pOdl = pOdl;

	pOdl->devinfo = devinfo;

	/*
	 * Here, we only allocate memory for struct odl and initilize it.
	 * All other memory allocation & initilization will be done in odlInit
	 * later on this routine.
	 */
	if (ddi_get_iblock_cookie(devinfo, 0, &pLayerPointers->pOdl->iblock)
	    != DDI_SUCCESS) {
		amd8111s_log(pLayerPointers, CE_NOTE,
		    "attach: get iblock cookies failed");
		goto attach_failure;
	}

	rw_init(&pOdl->chip_lock, NULL, RW_DRIVER, (void *)pOdl->iblock);
	mutex_init(&pOdl->mdlSendLock, "amd8111s Send Protection Lock",
	    MUTEX_DRIVER, (void *)pOdl->iblock);
	mutex_init(&pOdl->mdlRcvLock, "amd8111s Rcv Protection Lock",
	    MUTEX_DRIVER, (void *)pOdl->iblock);

	/* Setup PCI space */
	if (pci_config_setup(devinfo, &pOdl->pci_handle) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}
	pLayerPointers->attach_progress = AMD8111S_ATTACH_PCI;
	pci_handle = &pOdl->pci_handle;

	pOdl->vendor_id = pci_config_get16(*pci_handle, PCI_CONF_VENID);
	pOdl->device_id = pci_config_get16(*pci_handle, PCI_CONF_DEVID);

	/*
	 * Allocate and initialize all resource and map device registers.
	 * If failed, it returns a non-zero value.
	 */
	if (amd8111s_odlInit(pLayerPointers) != 0) {
		goto attach_failure;
	}
	pLayerPointers->attach_progress |= AMD8111S_ATTACH_RESOURCE;

	dev_attr.devacc_attr_version = DDI_DEVICE_ATTR_V0;
	dev_attr.devacc_attr_endian_flags = DDI_STRUCTURE_LE_ACC;
	dev_attr.devacc_attr_dataorder = DDI_STRICTORDER_ACC;

	if (ddi_regs_map_setup(devinfo, 1, &addrp, 0,  4096, &dev_attr,
	    &(pLayerPointers->pOdl->MemBasehandle)) != 0) {
		amd8111s_log(pLayerPointers, CE_NOTE,
		    "attach: ddi_regs_map_setup failed");
		goto attach_failure;
	}
	pLayerPointers->pMdl->Mem_Address = (unsigned long)addrp;

	/* Initialize HW */
	mdlOpen(pLayerPointers);
	mdlGetActiveMediaInfo(pLayerPointers);
	pLayerPointers->attach_progress |= AMD8111S_ATTACH_REGS;

	/*
	 * Setup the interrupt
	 */
	if (ddi_add_intr(devinfo, 0, &pOdl->iblock, 0, amd8111s_intr,
	    (caddr_t)pLayerPointers) != DDI_SUCCESS) {
		goto attach_failure;
	}
	pLayerPointers->attach_progress |= AMD8111S_ATTACH_INTRADDED;

	/*
	 * Setup soft intr
	 */
	if (ddi_add_softintr(devinfo, DDI_SOFTINT_LOW, &pOdl->drain_id,
	    NULL, NULL, amd8111s_send_drain,
	    (caddr_t)pLayerPointers) != DDI_SUCCESS) {
		goto attach_failure;
	}
	pLayerPointers->attach_progress |= AMD8111S_ATTACH_RESCHED;

	/*
	 * Initilize the mac structure
	 */
	if ((macp = mac_alloc(MAC_VERSION)) == NULL)
		goto attach_failure;

	macp->m_type_ident = MAC_PLUGIN_IDENT_ETHER;
	macp->m_driver = pLayerPointers;
	macp->m_dip = devinfo;
	/* Get MAC address */
	mdlGetMacAddress(pLayerPointers, (unsigned char *)pOdl->MacAddress);
	macp->m_src_addr = pOdl->MacAddress;
	macp->m_callbacks = &amd8111s_m_callbacks;
	macp->m_min_sdu = 0;
	/* 1518 - 14 (ether header) - 4 (CRC) */
	macp->m_max_sdu = ETHERMTU;
	macp->m_margin = VLAN_TAGSZ;

	/*
	 * Finally, we're ready to register ourselves with the MAC layer
	 * interface; if this succeeds, we're ready to start.
	 */
	if (mac_register(macp, &pOdl->mh) != DDI_SUCCESS) {
		mac_free(macp);
		goto attach_failure;
	}
	mac_free(macp);

	pLayerPointers->attach_progress |= AMD8111S_ATTACH_MACREGED;

	return (DDI_SUCCESS);

attach_failure:
	(void) amd8111s_unattach(devinfo, pLayerPointers);
	return (DDI_FAILURE);

}

/*
 * detach(9E) -- Detach a device from the system
 *
 * It is called for each device instance when the system is preparing to
 * unload a dynamically unloadable driver.
 * will Do
 *	a. check if any driver buffers are held by OS.
 *	b. do clean up of all allocated memory if it is not in use by OS.
 *	c. un register with GLD
 *	d. return DDI_SUCCESS on succes full free & unregister
 *	else GLD_FAILURE
 */
static int
amd8111s_detach(dev_info_t *devinfo, ddi_detach_cmd_t cmd)
{
	struct LayerPointers *pLayerPointers;

	switch (cmd) {
	case DDI_DETACH:
		break;
	default:
		return (DDI_FAILURE);
	}

	/*
	 * Get the driver private (struct LayerPointers *) structure
	 */
	if ((pLayerPointers = (struct LayerPointers *)ddi_get_driver_private
	    (devinfo)) == NULL) {
		return (DDI_FAILURE);
	}

	return (amd8111s_unattach(devinfo, pLayerPointers));
}

static int
amd8111s_unattach(dev_info_t *devinfo, struct LayerPointers *pLayerPointers)
{
	struct odl *pOdl = pLayerPointers->pOdl;

	if (pLayerPointers->attach_progress & AMD8111S_ATTACH_MACREGED) {
		/* Unregister driver from the GLD interface */
		if (mac_unregister(pOdl->mh) != DDI_SUCCESS) {
			return (DDI_FAILURE);
		}
	}

	if (pLayerPointers->attach_progress & AMD8111S_ATTACH_INTRADDED) {
		ddi_remove_intr(devinfo, 0, pOdl->iblock);
	}

	if (pLayerPointers->attach_progress & AMD8111S_ATTACH_RESCHED) {
		ddi_remove_softintr(pOdl->drain_id);
	}

	if (pLayerPointers->attach_progress & AMD8111S_ATTACH_REGS) {
		/* Stop HW */
		mdlStopChip(pLayerPointers);
		ddi_regs_map_free(&(pOdl->MemBasehandle));
	}

	if (pLayerPointers->attach_progress & AMD8111S_ATTACH_RESOURCE) {
		/* Free All memory allocated */
		amd8111s_free_resource(pLayerPointers);
	}

	if (pLayerPointers->attach_progress & AMD8111S_ATTACH_PCI) {
		pci_config_teardown(&pOdl->pci_handle);
		mutex_destroy(&pOdl->mdlSendLock);
		mutex_destroy(&pOdl->mdlRcvLock);
		rw_destroy(&pOdl->chip_lock);
	}

	kmem_free(pOdl, sizeof (struct odl));
	kmem_free(pLayerPointers, sizeof (struct LayerPointers));

	return (DDI_SUCCESS);
}

/*
 * (GLD Entry Point)GLD will call this entry point perodicaly to
 * get driver statistices.
 */
static int
amd8111s_m_stat(void *arg, uint_t stat, uint64_t *val)
{
	struct LayerPointers *pLayerPointers = arg;
	struct amd8111s_statistics *adapterStat;

	adapterStat = &pLayerPointers->pOdl->statistics;

	switch (stat) {

	/*
	 * Current Status
	 */
	case MAC_STAT_IFSPEED:
		*val = pLayerPointers->pMdl->Speed * 1000000;
		break;

	case ETHER_STAT_LINK_DUPLEX:
		if (pLayerPointers->pMdl->FullDuplex) {
			*val = LINK_DUPLEX_FULL;
		} else {
			*val = LINK_DUPLEX_HALF;
		}
		break;

	/*
	 * Capabilities
	 */
	case ETHER_STAT_CAP_1000FDX:
		*val = 0;
		break;

	case ETHER_STAT_CAP_1000HDX:
		*val = 0;
		break;

	case ETHER_STAT_CAP_100FDX:
		*val = 1;
		break;

	case ETHER_STAT_CAP_100HDX:
		*val = 1;
		break;

	case ETHER_STAT_CAP_10FDX:
		*val = 1;
		break;

	case ETHER_STAT_CAP_10HDX:
		*val = 1;
		break;

	case ETHER_STAT_CAP_ASMPAUSE:
		*val = 1;
		break;

	case ETHER_STAT_CAP_PAUSE:
		*val = 1;
		break;

	case ETHER_STAT_CAP_AUTONEG:
		*val = 1;
		break;

	case ETHER_STAT_ADV_CAP_1000FDX:
		*val = 0;
		break;

	case ETHER_STAT_ADV_CAP_1000HDX:
		*val = 0;
		break;

	case ETHER_STAT_ADV_CAP_100FDX:
		*val = 1;
		break;

	case ETHER_STAT_ADV_CAP_100HDX:
		*val = 1;
		break;

	case ETHER_STAT_ADV_CAP_10FDX:
		*val = 1;
		break;

	case ETHER_STAT_ADV_CAP_10HDX:
		*val = 1;
		break;

	case ETHER_STAT_ADV_CAP_ASMPAUSE:
		*val = 1;
		break;

	case ETHER_STAT_ADV_CAP_PAUSE:
		*val = 1;
		break;

	case ETHER_STAT_ADV_CAP_AUTONEG:
		*val = 1;
		break;

	/*
	 * Rx Counters
	 */
	case MAC_STAT_IPACKETS:
		*val = adapterStat->rx_mib_unicst_packets +
		    adapterStat->rx_mib_multicst_packets +
		    adapterStat->rx_mib_broadcst_packets +
		    mdlReadMib(pLayerPointers, RcvUniCastPkts) +
		    mdlReadMib(pLayerPointers, RcvMultiCastPkts) +
		    mdlReadMib(pLayerPointers, RcvBroadCastPkts);
		break;

	case MAC_STAT_RBYTES:
		*val = adapterStat->rx_mib_bytes +
		    mdlReadMib(pLayerPointers, RcvOctets);
		break;

	case MAC_STAT_MULTIRCV:
		*val = adapterStat->rx_mib_multicst_packets +
		    mdlReadMib(pLayerPointers, RcvMultiCastPkts);
		break;

	case MAC_STAT_BRDCSTRCV:
		*val = adapterStat->rx_mib_broadcst_packets +
		    mdlReadMib(pLayerPointers, RcvBroadCastPkts);
		break;

	case MAC_STAT_NORCVBUF:
		*val = adapterStat->rx_allocfail +
		    adapterStat->rx_mib_drop_packets +
		    mdlReadMib(pLayerPointers, RcvDropPktsRing0);
		break;

	case MAC_STAT_IERRORS:
		*val = adapterStat->rx_mib_align_err_packets +
		    adapterStat->rx_mib_fcs_err_packets +
		    adapterStat->rx_mib_symbol_err_packets +
		    mdlReadMib(pLayerPointers, RcvAlignmentErrors) +
		    mdlReadMib(pLayerPointers, RcvFCSErrors) +
		    mdlReadMib(pLayerPointers, RcvSymbolErrors);
		break;

	case ETHER_STAT_ALIGN_ERRORS:
		*val = adapterStat->rx_mib_align_err_packets +
		    mdlReadMib(pLayerPointers, RcvAlignmentErrors);
		break;

	case ETHER_STAT_FCS_ERRORS:
		*val = adapterStat->rx_mib_fcs_err_packets +
		    mdlReadMib(pLayerPointers, RcvFCSErrors);
		break;

	/*
	 * Tx Counters
	 */
	case MAC_STAT_OPACKETS:
		*val = adapterStat->tx_mib_packets +
		    mdlReadMib(pLayerPointers, XmtPackets);
		break;

	case MAC_STAT_OBYTES:
		*val = adapterStat->tx_mib_bytes +
		    mdlReadMib(pLayerPointers, XmtOctets);
		break;

	case MAC_STAT_MULTIXMT:
		*val = adapterStat->tx_mib_multicst_packets +
		    mdlReadMib(pLayerPointers, XmtMultiCastPkts);
		break;

	case MAC_STAT_BRDCSTXMT:
		*val = adapterStat->tx_mib_broadcst_packets +
		    mdlReadMib(pLayerPointers, XmtBroadCastPkts);
		break;

	case MAC_STAT_NOXMTBUF:
		*val = adapterStat->tx_no_descriptor;
		break;

	case MAC_STAT_OERRORS:
		*val = adapterStat->tx_mib_ex_coll_packets +
		    mdlReadMib(pLayerPointers, XmtExcessiveCollision);
		break;

	case MAC_STAT_COLLISIONS:
		*val = adapterStat->tx_mib_ex_coll_packets +
		    mdlReadMib(pLayerPointers, XmtCollisions);
		break;

	case ETHER_STAT_FIRST_COLLISIONS:
		*val = adapterStat->tx_mib_one_coll_packets +
		    mdlReadMib(pLayerPointers, XmtOneCollision);
		break;

	case ETHER_STAT_MULTI_COLLISIONS:
		*val = adapterStat->tx_mib_multi_coll_packets +
		    mdlReadMib(pLayerPointers, XmtMultipleCollision);
		break;

	case ETHER_STAT_EX_COLLISIONS:
		*val = adapterStat->tx_mib_ex_coll_packets +
		    mdlReadMib(pLayerPointers, XmtExcessiveCollision);
		break;

	case ETHER_STAT_TX_LATE_COLLISIONS:
		*val = adapterStat->tx_mib_late_coll_packets +
		    mdlReadMib(pLayerPointers, XmtLateCollision);
		break;

	case ETHER_STAT_DEFER_XMTS:
		*val = adapterStat->tx_mib_defer_trans_packets +
		    mdlReadMib(pLayerPointers, XmtDeferredTransmit);
		break;

	default:
		return (ENOTSUP);
	}
	return (0);
}

/*
 *	Memory Read Function Used by MDL to set card registers.
 */
unsigned char
READ_REG8(struct LayerPointers *pLayerPointers, long x)
{
	return (ddi_get8(pLayerPointers->pOdl->MemBasehandle, (uint8_t *)x));
}

int
READ_REG16(struct LayerPointers *pLayerPointers, long x)
{
	return (ddi_get16(pLayerPointers->pOdl->MemBasehandle,
	    (uint16_t *)(x)));
}

long
READ_REG32(struct LayerPointers *pLayerPointers, long x)
{
	return (ddi_get32(pLayerPointers->pOdl->MemBasehandle,
	    (uint32_t *)(x)));
}

void
WRITE_REG8(struct LayerPointers *pLayerPointers, long x, int y)
{
	ddi_put8(pLayerPointers->pOdl->MemBasehandle, (uint8_t *)(x), y);
}

void
WRITE_REG16(struct LayerPointers *pLayerPointers, long x, int y)
{
	ddi_put16(pLayerPointers->pOdl->MemBasehandle, (uint16_t *)(x), y);
}

void
WRITE_REG32(struct LayerPointers *pLayerPointers, long x, int y)
{
	ddi_put32(pLayerPointers->pOdl->MemBasehandle, (uint32_t *)(x), y);
}

void
WRITE_REG64(struct LayerPointers *pLayerPointers, long x, char *y)
{
	int i;
	for (i = 0; i < 8; i++) {
		WRITE_REG8(pLayerPointers, (x + i), y[i]);
	}
}
