/*
 * Copyright 2014-2017 Cavium, Inc.
 * The contents of this file are subject to the terms of the Common Development
 * and Distribution License, v.1,  (the "License").
 *
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the License at available
 * at http://opensource.org/licenses/CDDL-1.0
 *
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2019, Joyent, Inc.
 */

#include "bnx.h"
#include "bnx_mm.h"
#include "bnxgld.h"
#include "bnxsnd.h"
#include "bnxtmr.h"
#include "bnxcfg.h"
#include "serdes.h"

#include "shmem.h"

#define	MII_REG(_type, _field)	(OFFSETOF(_type, _field)/2)

ddi_dma_attr_t bnx_std_dma_attrib = {
	DMA_ATTR_V0,		/* dma_attr_version */
	0,			/* dma_attr_addr_lo */
	0xffffffffffffffff,	/* dma_attr_addr_hi */
	0x0ffffff,		/* dma_attr_count_max */
	BNX_DMA_ALIGNMENT,	/* dma_attr_align */
	0xffffffff,		/* dma_attr_burstsizes */
	1,			/* dma_attr_minxfer */
	0x00ffffff,		/* dma_attr_maxxfer */
	0xffffffff,		/* dma_attr_seg */
	1,			/* dma_attr_sgllen */
	1,			/* dma_attr_granular */
	0,			/* dma_attr_flags */
};


static ddi_dma_attr_t bnx_page_dma_attrib = {
	DMA_ATTR_V0,		/* dma_attr_version */
	0,			/* dma_attr_addr_lo */
	0xffffffffffffffff,	/* dma_attr_addr_hi */
	0x0ffffff,		/* dma_attr_count_max */
	LM_PAGE_SIZE,		/* dma_attr_align */
	0xffffffff,		/* dma_attr_burstsizes */
	1,			/* dma_attr_minxfer */
	0x00ffffff,		/* dma_attr_maxxfer */
	0xffffffff,		/* dma_attr_seg */
	1,			/* dma_attr_sgllen */
	1,			/* dma_attr_granular */
	0,			/* dma_attr_flags */
};



/*
 * Name:        mm_wait
 *
 * Input:       ptr to LM's device structure,
 *              delay value in micro-secs
 *
 * Return:      None.
 *
 * Description: This funtion will be in a busy loop for specified number of
 *              micro-seconds and will return only after the time is elasped.
 */
void
mm_wait(lm_device_t *pdev, u32_t delay_us)
{
	FLUSHPOSTEDWRITES(pdev);
	drv_usecwait(delay_us * 10);
} /* mm_wait */



/*
 * Name:        mm_read_pci
 *
 * Input:       ptr to LM's device structure,
 *              register offset into config space,
 *              ptr to u32 where the register value is returned
 *
 * Return:      LM_STATUS_SUCCESS, if successful
 *              LM_STATUS_FAILURE, if BAR register veiw is not mapped
 *
 * Description: This routine reads the PCI config space for the given device
 *              by calling pci_config_get32().
 */
lm_status_t
mm_read_pci(lm_device_t *pdev, u32_t pci_reg, u32_t *reg_value)
{
	um_device_t *udevp = (um_device_t *)pdev;

	*reg_value = pci_config_get32(udevp->os_param.pci_cfg_handle,
	    (off_t)pci_reg);

	return (LM_STATUS_SUCCESS);
} /* mm_read_pci */



/*
 * Name:        mm_write_pci
 *
 * Input:       ptr to LM's device structure,
 *              register offset into config space,
 *              u32 value to be written to PCI config register
 *
 * Return:      LM_STATUS_SUCCESS, if successful
 *              LM_STATUS_FAILURE, if BAR register veiw is not mapped
 *
 * Description: This routine writes to PCI config register using DDI call,
 *              pci_config_put32().
 */
lm_status_t
mm_write_pci(lm_device_t *pdev, u32_t pci_reg, u32_t reg_value)
{
	um_device_t *udevp = (um_device_t *)pdev;

	pci_config_put32(udevp->os_param.pci_cfg_handle,
	    (off_t)pci_reg, (uint32_t)reg_value);

	return (LM_STATUS_SUCCESS);
} /* mm_write_pci */



/*
 * Name:        mm_map_io_base
 *
 * Input:       ptr to LM's device structure,
 *              physical address of the BAR reg
 *                      (not used in this implementation),
 *              size of the register window
 *
 * Return:      ptr to mapped virtual memory
 *
 * Description: This routine maps the BAR register window and returns the
 *              virtual address in the CPU address scape
 */
void *
mm_map_io_base(lm_device_t *pdev, lm_address_t base_addr, u32_t size)
{
	um_device_t *udevp = (um_device_t *)pdev;

	pdev->vars.dmaRegAccHandle = udevp->os_param.reg_acc_handle;

	return ((void *)(udevp->os_param.regs_addr));
} /* mm_map_io_base */



/*
 * Name:        mm_desc_size
 *
 * Input:       ptr to LM's device structure,
 *              descriptor type
 *
 * Return:      size of the descriptor structure
 *
 * Description: This routine currently returns the size of packet descriptor
 *              as defined by the UM module (lm_pkt_t is embedded in this
 *              struct). This is used by LM's init routines trying to allocate
 *              memory for TX/RX descriptor queues.
 */
u32_t
mm_desc_size(lm_device_t *pdev, u32_t desc_type)
{
	u32_t desc_size;

	switch (desc_type) {
	case DESC_TYPE_L2RX_PACKET:
		desc_size = sizeof (um_rxpacket_t);
		break;

	default:
		desc_size = 0;
		break;
	}

	desc_size = ALIGN_VALUE_TO_WORD_BOUNDARY(desc_size);

	return (desc_size);
} /* mm_desc_size */



/*
 * Name:        mm_get_user_config
 *
 * Input:       ptr to LM's device structure
 *
 * Return:      SUCCESS
 *
 * Description: This rotuine maps user option to corresponding parameters in
 *              LM and UM device structures.
 */
lm_status_t
mm_get_user_config(lm_device_t *pdev)
{
	u32_t keep_vlan_tag = 0;
	u32_t offset;
	u32_t val;
	um_device_t *umdevice = (um_device_t *)pdev;

	bnx_cfg_init(umdevice);

	bnx_cfg_map_phy(umdevice);

	/*
	 * If Management Firmware is running ensure that we don't
	 * keep the VLAN tag, this is for older firmware
	 */
	offset = pdev->hw_info.shmem_base;
	offset += OFFSETOF(shmem_region_t,
	    dev_info.port_feature_config.config);
	REG_RD_IND(pdev, offset, &val);

	if (!(val & PORT_FEATURE_MFW_ENABLED))
		keep_vlan_tag = 1;

	/*
	 * Newer versions of the firmware can handle VLAN tags
	 * check to see if this version of the firmware can handle them
	 */
	offset = pdev->hw_info.shmem_base;
	offset += OFFSETOF(shmem_region_t, drv_fw_cap_mb.fw_cap_mb);
	REG_RD_IND(pdev, offset, &val);

	if ((val & FW_CAP_SIGNATURE) == FW_CAP_SIGNATURE) {
		if ((val & (FW_CAP_MFW_CAN_KEEP_VLAN |
		    FW_CAP_BC_CAN_UPDATE_VLAN)) ==
		    (FW_CAP_MFW_CAN_KEEP_VLAN | FW_CAP_BC_CAN_UPDATE_VLAN)) {
			offset = pdev->hw_info.shmem_base;
			offset += OFFSETOF(shmem_region_t,
			    drv_fw_cap_mb.drv_ack_cap_mb);
			REG_WR_IND(pdev, offset, DRV_ACK_CAP_SIGNATURE |
			    FW_CAP_MFW_CAN_KEEP_VLAN |
			    FW_CAP_BC_CAN_UPDATE_VLAN);

			keep_vlan_tag = 1;
		}
	}

	pdev->params.keep_vlan_tag = keep_vlan_tag;

	return (LM_STATUS_SUCCESS);
} /* mm_get_user_config */



/*
 * Name:        mm_alloc_mem
 *
 * Input:       ptr to LM's device structure,
 *              size of the memory block to be allocated
 *
 * Return:      ptr to newly allocated memory region
 *
 * Description: This routine allocates memory region, updates the
 *              resource list to reflect this newly allocated memory.
 */
void *
mm_alloc_mem(lm_device_t *pdev, u32_t mem_size, void *resc_list)
{
	void *memptr;
	bnx_memreq_t *memreq;
	um_device_t *umdevice;

	(void) resc_list;

	umdevice = (um_device_t *)pdev;

	if (mem_size == 0) {
		return (NULL);
	}

	if (umdevice->memcnt == BNX_MAX_MEMREQS) {
		cmn_err(CE_WARN, "%s: Lower module memreq overflow.\n",
		    umdevice->dev_name);
		return (NULL);
	}

	memptr = kmem_zalloc(mem_size, KM_NOSLEEP);
	if (memptr == NULL) {
		cmn_err(CE_WARN, "%s: Failed to allocate local memory.\n",
		    umdevice->dev_name);
		return (NULL);
	}

	memreq = &umdevice->memreq[umdevice->memcnt];

	memreq->addr = memptr;
	memreq->size = mem_size;

	umdevice->memcnt++;

	return (memptr);
} /* mm_alloc_mem */



/*
 * Name:        mm_alloc_phys_mem
 *
 * Input:       ptr to LM's device structure,
 *              size of the memory block to be allocated,
 *              pointer to store phys address,
 *              memory type
 *
 * Return:      virtual memory ptr to newly allocated memory region
 *
 * Description: This routine allocates memory region, updates the
 *              resource list to reflect this newly allocated memory.
 *              This function returns physical address in addition the
 *              virtual address pointer.
 */
void *
mm_alloc_phys_mem(lm_device_t *pdev, u32_t mem_size, lm_address_t *phys_mem,
    u8_t mem_type, void *resc_list)
{
	int rc;
	caddr_t pbuf;
	um_device_t *udevp;
	size_t real_len;
	unsigned int count;
	ddi_dma_attr_t *dma_attrib;
	ddi_dma_handle_t *dma_handle;
	ddi_acc_handle_t *acc_handle;
	ddi_dma_cookie_t cookie;

	(void) mem_type;
	(void) resc_list;

	udevp = (um_device_t *)pdev;

	if (mem_size == 0) {
		return (NULL);
	}

	if (udevp->os_param.dma_handles_used == BNX_MAX_PHYS_MEMREQS) {
		cmn_err(CE_WARN, "%s: %s: Lower module phys memreq overflow.\n",
		    udevp->dev_name, __func__);
		return (NULL);
	}

	if (!(mem_size & LM_PAGE_MASK)) {
		/* Size is multiple of page size. */
		dma_attrib = &bnx_page_dma_attrib;
	} else {
		dma_attrib = &bnx_std_dma_attrib;
	}

	rc = udevp->os_param.dma_handles_used;
	dma_handle = &udevp->os_param.dma_handle[rc];
	acc_handle = &udevp->os_param.dma_acc_handle[rc];

	rc = ddi_dma_alloc_handle(udevp->os_param.dip, dma_attrib,
	    DDI_DMA_DONTWAIT, (void *)0, dma_handle);
	if (rc != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s: %s: Failed to alloc phys dma handle.\n",
		    udevp->dev_name, __func__);
		return (NULL);
	}

	rc = ddi_dma_mem_alloc(*dma_handle, (size_t)mem_size +
	    BNX_DMA_ALIGNMENT, &bnxAccessAttribBUF, DDI_DMA_CONSISTENT,
	    DDI_DMA_DONTWAIT, (void *)0, &pbuf, &real_len, acc_handle);
	if (rc != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s: %s: Failed to alloc phys memory.\n",
		    udevp->dev_name, __func__);
		goto error1;
	}

	rc = ddi_dma_addr_bind_handle(*dma_handle, (struct as *)0, pbuf,
	    real_len, DDI_DMA_RDWR | DDI_DMA_CONSISTENT, DDI_DMA_DONTWAIT,
	    (void *)0, &cookie, &count);
	if (rc != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s: %s: Failed to bind DMA address.\n",
		    udevp->dev_name, __func__);
		goto error2;
	}

	phys_mem->as_u64 = (u64_t)cookie.dmac_laddress;

	/*
	 * Save the virtual memory address so
	 * we can get the dma_handle later.
	 */
	udevp->os_param.dma_virt[udevp->os_param.dma_handles_used] = pbuf;

	udevp->os_param.dma_handles_used++;

	/* Zero the memory... */
	bzero(pbuf, real_len);

	/* ...and make sure the new contents are flushed back to main memory. */
	(void) ddi_dma_sync(*dma_handle, 0, real_len, DDI_DMA_SYNC_FORDEV);

	return (pbuf);

error2:
	ddi_dma_mem_free(acc_handle);

error1:
	ddi_dma_free_handle(dma_handle);

	return (NULL);
} /* mm_alloc_phys_mem */



/*
 * Name:        mm_indicate_tx
 *
 * Input:       ptr to LM's device structure,
 *              TX chain index,
 *              array of pointers to packet descriptors,
 *              number of packet descriptors in array
 *
 * Return:      None
 *
 * Description:
 *              Lower module calls this API function to return transmit packet
 *              buffers to the system, and to allow the driver to reclaim
 *              transmit resources.  This function is only called upon transmit
 *              abort and so is not in the fast path.
 */
void
mm_indicate_tx(lm_device_t *pdev, u32_t chain_idx,
    struct _lm_packet_t *packet_arr[], u32_t num_packets)
{
	um_txpacket_t **pkt_ptr;
	um_txpacket_t *pkt;
	s_list_t comp_list;

	pkt_ptr = (um_txpacket_t **)packet_arr;

	s_list_init(&comp_list, NULL, NULL, 0);

	while (num_packets) {
		pkt = *pkt_ptr;

		s_list_push_tail(&comp_list, &(pkt->lm_pkt.link));

		pkt_ptr++;
		num_packets--;
	}

	bnx_xmit_ring_reclaim((um_device_t *)pdev, chain_idx, &comp_list);
} /* mm_indicate_tx */



/*
 * Description:
 *
 * Return:
 */
static void
bnx_display_link_msg(um_device_t * const umdevice)
{
	char *media;
	char linkstr[128];

	if (umdevice->dev_var.isfiber) {
		media = "Fiber";
	} else {
		media = "Copper";
	}

	if (umdevice->nddcfg.link_speed != 0) {
		(void) strlcpy(linkstr, "up (", sizeof (linkstr));

		switch (umdevice->nddcfg.link_speed) {
		case 2500:
			(void) strlcat(linkstr, "2500Mbps, ", sizeof (linkstr));
			break;
		case 1000:
			(void) strlcat(linkstr, "1000Mbps, ", sizeof (linkstr));
			break;
		case 100:
			(void) strlcat(linkstr, "100Mbps, ", sizeof (linkstr));
			break;
		case 10:
			(void) strlcat(linkstr, "10Mbps, ", sizeof (linkstr));
			break;
		default:
			(void) strlcat(linkstr, "0Mbps, ", sizeof (linkstr));
		}

		if (umdevice->nddcfg.link_duplex) {
			(void) strlcat(linkstr, "Full Duplex",
			    sizeof (linkstr));
		} else {
			(void) strlcat(linkstr, "Half Duplex",
			    sizeof (linkstr));
		}

		if (umdevice->nddcfg.link_tx_pause ||
		    umdevice->nddcfg.link_rx_pause) {
			(void) strlcat(linkstr, ", ", sizeof (linkstr));
			if (umdevice->nddcfg.link_tx_pause) {
				(void) strlcat(linkstr, "Tx", sizeof (linkstr));
				if (umdevice->nddcfg.link_rx_pause) {
					(void) strlcat(linkstr, " & Rx",
					    sizeof (linkstr));
				}
			} else {
				(void) strlcat(linkstr, "Rx", sizeof (linkstr));
			}
			(void) strlcat(linkstr, " Flow Control ON",
			    sizeof (linkstr));
		}
		(void) strlcat(linkstr, ")", sizeof (linkstr));
	} else {
		(void) snprintf(linkstr, sizeof (linkstr), "down");
	}

	cmn_err(CE_NOTE, "!%s: %s link is %s", umdevice->dev_name, media,
	    linkstr);
} /* bnx_display_link_msg */



/*
 * Name:        bnx_update_lp_cap
 *
 * Input:       ptr to device structure
 *
 * Return:      None
 *
 * Description: This function is updates link partners advertised
 *              capabilities.
 */
static void
bnx_update_lp_cap(um_device_t *const umdevice)
{
	u32_t		miireg;
	lm_status_t	lmstatus;
	lm_device_t	*lmdevice;

	lmdevice = &(umdevice->lm_dev);

	if (umdevice->dev_var.isfiber) {
		lmstatus = lm_mread(lmdevice, lmdevice->params.phy_addr,
		    MII_REG(serdes_reg_t, mii_aneg_nxt_pg_rcv1), &miireg);
		if (lmstatus == LM_STATUS_SUCCESS) {
			if (miireg & MII_ANEG_NXT_PG_RCV1_2G5) {
				umdevice->remote.param_2500fdx = B_TRUE;
			}
		}

		lmstatus = lm_mread(lmdevice, lmdevice->params.phy_addr,
		    PHY_LINK_PARTNER_ABILITY_REG, &miireg);
		if (lmstatus == LM_STATUS_SUCCESS) {
			miireg &= MII_ABILITY_PAUSE;
			if (miireg == MII_ADVERT_SYM_PAUSE) {
				umdevice->remote.param_tx_pause = B_TRUE;
				umdevice->remote.param_rx_pause = B_TRUE;
			} else if (miireg == MII_ADVERT_ASYM_PAUSE) {
				umdevice->remote.param_tx_pause = B_TRUE;
			}

			if (miireg & MII_ABILITY_FULL) {
				umdevice->remote.param_1000fdx = B_TRUE;
			}

			if (miireg & MII_ABILITY_HALF) {
				umdevice->remote.param_1000hdx = B_TRUE;
			}
		}
	} else {
		/* Copper */
		lmstatus = lm_mread(lmdevice, lmdevice->params.phy_addr,
		    PHY_1000BASET_STATUS_REG, &miireg);
		if (lmstatus == LM_STATUS_SUCCESS) {
			if (miireg & PHY_LINK_PARTNER_1000BASET_FULL) {
				umdevice->remote.param_1000fdx = B_TRUE;
			}

			if (miireg & PHY_LINK_PARTNER_1000BASET_HALF) {
				umdevice->remote.param_1000hdx = B_TRUE;
			}
		}

		lmstatus = lm_mread(lmdevice, lmdevice->params.phy_addr,
		    PHY_LINK_PARTNER_ABILITY_REG, &miireg);
		if (lmstatus == LM_STATUS_SUCCESS) {
			if (miireg & PHY_LINK_PARTNER_PAUSE_CAPABLE) {
				umdevice->remote.param_tx_pause = B_TRUE;
				umdevice->remote.param_rx_pause = B_TRUE;
			} else if (miireg & PHY_LINK_PARTNER_ASYM_PAUSE) {
				umdevice->remote.param_tx_pause = B_TRUE;
			}

			if (miireg & PHY_LINK_PARTNER_100BASETX_FULL) {
				umdevice->remote.param_100fdx = B_TRUE;
			}

			if (miireg & PHY_LINK_PARTNER_100BASETX_HALF) {
				umdevice->remote.param_100hdx = B_TRUE;
			}

			if (miireg & PHY_LINK_PARTNER_10BASET_FULL) {
				umdevice->remote.param_10fdx = B_TRUE;
			}

			if (miireg & PHY_LINK_PARTNER_10BASET_HALF) {
				umdevice->remote.param_10hdx = B_TRUE;
			}
		}
	}

#if 0
	/*
	 * If we can gather _any_ information about our link partner, then
	 * because this information is exchanged through autonegotiation, we
	 * know that our link partner supports autonegotiation.
	 *
	 * FIXME -- Find a more authoritative way to update link_autoneg.  I'm
	 * not sure it is legal, but it sounds possible to have autonegotiation
	 * enabled on the remote end with no capabilities advertised.
	 */
	if (umdevice->remote.param_2500fdx ||
	    umdevice->remote.param_1000fdx ||
	    umdevice->remote.param_1000hdx ||
	    umdevice->remote.param_100fdx ||
	    umdevice->remote.param_100hdx ||
	    umdevice->remote.param_10fdx ||
	    umdevice->remote.param_10hdx ||
	    umdevice->remote.param_tx_pause ||
	    umdevice->remote.param_rx_pause) {
		umdevice->remote.param_autoneg = B_TRUE;
	}
#else
	lmstatus = lm_mread(lmdevice, lmdevice->params.phy_addr,
	    BCM540X_AUX_STATUS_REG, &miireg);
	if (lmstatus == LM_STATUS_SUCCESS) {
		if (miireg & BIT_12) {
			umdevice->remote.link_autoneg = B_TRUE;
		}
	}
#endif
} /* bnx_update_lp_cap */



/*
 * Name:        mm_indicate_link
 *
 * Input:       ptr to LM's device structure,
 *              link status,
 *              lm_medium_t struct
 *
 * Return:      None
 *
 * Description: Lower module calls this function when ever there is a network
 *              link status change. This routine updates the driver data
 *              structure as well calls gld_linkstate() to notify event to GLD.
 */
void
mm_indicate_link(lm_device_t *lmdevice, lm_status_t link, lm_medium_t medium)
{
	int link_speed;
	um_device_t *umdevice;

	umdevice = (um_device_t *)lmdevice;

	if (umdevice->link_updates_ok == B_FALSE) {
		return;
	}

	/* ignore link status if it has not changed since the last indicate */
	if ((umdevice->dev_var.indLink == link) &&
	    (umdevice->dev_var.indMedium == medium)) {
		return;
	}

	umdevice->dev_var.indLink = link;
	umdevice->dev_var.indMedium = medium;

	switch (GET_MEDIUM_SPEED(medium)) {
	case LM_MEDIUM_SPEED_10MBPS:
		link_speed = 10;
		break;

	case LM_MEDIUM_SPEED_100MBPS:
		link_speed = 100;
		break;

	case LM_MEDIUM_SPEED_1000MBPS:
		link_speed = 1000;
		break;

	case LM_MEDIUM_SPEED_2500MBPS:
		link_speed = 2500;
		break;

	default:
		link_speed = 0;
		break;
	}

	/*
	 * Validate the linespeed against known hardware capabilities.
	 * This is a common occurance.
	 */
	if (umdevice->dev_var.isfiber) {
		if (link_speed != 2500 && link_speed != 1000) {
			link_speed = 0;
		}
	}

	if (link_speed == 0) {
		link = LM_STATUS_LINK_DOWN;
	}

	/*
	 * If neither link-up or link-down flag is present, then there must
	 * have been multiple link events.  Do the right thing.
	 */
	if (link != LM_STATUS_LINK_ACTIVE && link != LM_STATUS_LINK_DOWN) {
		/* Fill in the missing information. */
		if (link_speed != 0) {
			link = LM_STATUS_LINK_ACTIVE;
		} else {
			link = LM_STATUS_LINK_DOWN;
		}
	}

#if 0
	if (((umdevice->nddcfg.link_speed == 0) &&
	    (link != LM_STATUS_LINK_ACTIVE)) ||
	    ((umdevice->nddcfg.link_speed != 0) &&
	    (link != LM_STATUS_LINK_DOWN))) {
		/* This is a false notification. */
		return;
	}
#endif

	if (umdevice->timer_link_check_interval) {
		if (link == LM_STATUS_LINK_ACTIVE) {
			if (lmdevice->vars.serdes_fallback_status) {
				/*
				 * Start the timer to poll the serdes for
				 * reception of configs from the link partner.
				 * When this happens the remote has autoneg
				 * enabled and we'll restart our autoneg.
				 */
				bnx_link_timer_restart(umdevice);
			}
		} else {
			if (umdevice->timer_link_check_counter) {
				bnx_link_timer_restart(umdevice);
			}
		}
	}

	if (link == LM_STATUS_LINK_DOWN) {
		umdevice->nddcfg.link_speed = 0;
		umdevice->nddcfg.link_duplex  = B_FALSE;
		umdevice->nddcfg.link_tx_pause = B_FALSE;
		umdevice->nddcfg.link_rx_pause = B_FALSE;

		umdevice->remote.link_autoneg  = B_FALSE;
		umdevice->remote.param_2500fdx = B_FALSE;
		umdevice->remote.param_1000fdx = B_FALSE;
		umdevice->remote.param_1000hdx = B_FALSE;
		umdevice->remote.param_100fdx  = B_FALSE;
		umdevice->remote.param_100hdx  = B_FALSE;
		umdevice->remote.param_10fdx = B_FALSE;
		umdevice->remote.param_10hdx = B_FALSE;
		umdevice->remote.param_tx_pause = B_FALSE;
		umdevice->remote.param_rx_pause = B_FALSE;

		bnx_display_link_msg(umdevice);

		bnx_gld_link(umdevice, LINK_STATE_DOWN);
	} else if (link == LM_STATUS_LINK_ACTIVE) {
		umdevice->nddcfg.link_speed  = link_speed;

		if (GET_MEDIUM_DUPLEX(medium)) {
			/* half duplex */
			umdevice->nddcfg.link_duplex = B_FALSE;
		} else {
			/* full duplex */
			umdevice->nddcfg.link_duplex = B_TRUE;
		}

		if (lmdevice->vars.flow_control &
		    LM_FLOW_CONTROL_TRANSMIT_PAUSE) {
			umdevice->nddcfg.link_tx_pause = B_TRUE;
		} else {
			umdevice->nddcfg.link_tx_pause = B_FALSE;
		}

		if (lmdevice->vars.flow_control &
		    LM_FLOW_CONTROL_RECEIVE_PAUSE) {
			umdevice->nddcfg.link_rx_pause = B_TRUE;
		} else {
			umdevice->nddcfg.link_rx_pause = B_FALSE;
		}

		if (umdevice->curcfg.lnkcfg.link_autoneg == B_TRUE) {
			bnx_update_lp_cap(umdevice);
		}

		bnx_display_link_msg(umdevice);

		bnx_gld_link(umdevice, LINK_STATE_UP);
	}
} /* mm_indicate_link */



/*
 * Description:
 *
 * Return:
 */
void
mm_acquire_ind_reg_lock(struct _lm_device_t *pdev)
{
	um_device_t *umdevice;

	umdevice = (um_device_t *)pdev;

	mutex_enter(&umdevice->os_param.ind_mutex);
} /* mm_acquire_ind_reg_lock */



/*
 * Description:
 *
 * Return:
 */
void
mm_release_ind_reg_lock(struct _lm_device_t *pdev)
{
	um_device_t *umdevice;

	umdevice = (um_device_t *)pdev;

	mutex_exit(&umdevice->os_param.ind_mutex);
} /* mm_release_ind_reg_lock */
