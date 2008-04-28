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
 * nxge_hio_guest.c
 *
 * This file manages the virtualization resources for a guest domain.
 *
 */

#include <sys/nxge/nxge_impl.h>
#include <sys/nxge/nxge_fzc.h>
#include <sys/nxge/nxge_rxdma.h>
#include <sys/nxge/nxge_txdma.h>

#include <sys/nxge/nxge_hio.h>

/*
 * nxge_hio_unregister
 *
 *	Unregister with the VNET module.
 *
 * Arguments:
 * 	nxge
 *
 * Notes:
 *	We must uninitialize all DMA channels associated with the VR, too.
 *
 *	We're assuming that the channels will be disabled & unassigned
 *	in the service domain, after we're done here.
 *
 * Context:
 *	Guest domain
 */
void
nxge_hio_unregister(
	nxge_t *nxge)
{
	nxge_hio_data_t *nhd = (nxge_hio_data_t *)nxge->nxge_hw_p->hio;

	if (nhd == 0) {
		return;
	}

#if defined(sun4v)
	/* Unregister with vNet. */
	if (nhd->hio.vio.unregister) {
		if (nxge->hio_vr)
			(*nhd->hio.vio.unregister)(nxge->hio_vr->vhp);
	}
#endif
}

/*
 * nxge_guest_regs_map
 *
 *	Map in a guest domain's register set(s).
 *
 * Arguments:
 * 	nxge
 *
 * Notes:
 *	Note that we set <is_vraddr> to TRUE.
 *
 * Context:
 *	Guest domain
 */
static ddi_device_acc_attr_t nxge_guest_register_access_attributes = {
	DDI_DEVICE_ATTR_V0,
	DDI_STRUCTURE_LE_ACC,
	DDI_STRICTORDER_ACC,
};

int
nxge_guest_regs_map(
	nxge_t *nxge)
{
	dev_regs_t 	*regs;
	off_t		regsize;
	int rv;

	NXGE_DEBUG_MSG((nxge, HIO_CTL, "==> nxge_guest_regs_map"));

	/* So we can allocate properly-aligned memory. */
	nxge->niu_type = N2_NIU; /* Version 1.0 only */
	nxge->function_num = nxge->instance; /* HIOXXX Looking for ideas. */

	nxge->dev_regs = KMEM_ZALLOC(sizeof (dev_regs_t), KM_SLEEP);
	regs = nxge->dev_regs;

	if ((rv = ddi_dev_regsize(nxge->dip, 0, &regsize)) != DDI_SUCCESS) {
		NXGE_ERROR_MSG((nxge, HIO_CTL, "ddi_dev_regsize() failed"));
		return (NXGE_ERROR);
	}

	rv = ddi_regs_map_setup(nxge->dip, 0, (caddr_t *)&regs->nxge_regp, 0, 0,
	    &nxge_guest_register_access_attributes, &regs->nxge_regh);

	if (rv != DDI_SUCCESS) {
		NXGE_ERROR_MSG((nxge, HIO_CTL, "ddi_regs_map_setup() failed"));
		return (NXGE_ERROR);
	}

	nxge->npi_handle.regh = regs->nxge_regh;
	nxge->npi_handle.regp = (npi_reg_ptr_t)regs->nxge_regp;
	nxge->npi_handle.is_vraddr = B_TRUE;
	nxge->npi_handle.function.instance = nxge->instance;
	nxge->npi_handle.function.function = nxge->function_num;
	nxge->npi_handle.nxgep = (void *)nxge;

	/* NPI_REG_ADD_HANDLE_SET() */
	nxge->npi_reg_handle.regh = regs->nxge_regh;
	nxge->npi_reg_handle.regp = (npi_reg_ptr_t)regs->nxge_regp;
	nxge->npi_reg_handle.is_vraddr = B_TRUE;
	nxge->npi_reg_handle.function.instance = nxge->instance;
	nxge->npi_reg_handle.function.function = nxge->function_num;
	nxge->npi_reg_handle.nxgep = (void *)nxge;

	/* NPI_VREG_ADD_HANDLE_SET() */
	nxge->npi_vreg_handle.regh = regs->nxge_regh;
	nxge->npi_vreg_handle.regp = (npi_reg_ptr_t)regs->nxge_regp;
	nxge->npi_vreg_handle.is_vraddr = B_TRUE;
	nxge->npi_vreg_handle.function.instance = nxge->instance;
	nxge->npi_vreg_handle.function.function = nxge->function_num;
	nxge->npi_vreg_handle.nxgep = (void *)nxge;

	regs->nxge_vir_regp = regs->nxge_regp;
	regs->nxge_vir_regh = regs->nxge_regh;

	/*
	 * We do NOT set the PCI, MSI-X, 2nd Virtualization,
	 * or FCODE reg variables.
	 */

	NXGE_DEBUG_MSG((nxge, HIO_CTL, "<== nxge_guest_regs_map"));

	return (NXGE_OK);
}

void
nxge_guest_regs_map_free(
	nxge_t *nxge)
{
	NXGE_DEBUG_MSG((nxge, HIO_CTL, "==> nxge_guest_regs_map_free"));

	if (nxge->dev_regs) {
		if (nxge->dev_regs->nxge_regh) {
			NXGE_DEBUG_MSG((nxge, DDI_CTL,
			    "==> nxge_unmap_regs: device registers"));
			ddi_regs_map_free(&nxge->dev_regs->nxge_regh);
			nxge->dev_regs->nxge_regh = NULL;
		}
		kmem_free(nxge->dev_regs, sizeof (dev_regs_t));
		nxge->dev_regs = 0;
	}

	NXGE_DEBUG_MSG((nxge, HIO_CTL, "<== nxge_guest_regs_map_free"));
}

#if defined(sun4v)

/*
 * -------------------------------------------------------------
 * Local prototypes
 * -------------------------------------------------------------
 */
static nxge_hio_dc_t *nxge_guest_dc_alloc(
	nxge_t *, nxge_hio_vr_t *, nxge_grp_type_t);

static void res_map_parse(nxge_t *, nxge_grp_type_t, uint64_t);
static void nxge_check_guest_state(nxge_hio_vr_t *);

/*
 * nxge_hio_vr_add
 *
 *	If we have been given a virtualization region (VR),
 *	then initialize it.
 *
 * Arguments:
 * 	nxge
 *
 * Notes:
 *
 * Context:
 *	Guest domain
 */
/* ARGSUSED */
int
nxge_hio_vr_add(
	nxge_t *nxge)
{
	extern mac_callbacks_t nxge_m_callbacks;

	nxge_hio_data_t *nhd = (nxge_hio_data_t *)nxge->nxge_hw_p->hio;
	nxge_hio_vr_t *vr;
	nxge_hio_dc_t *dc;

	int *reg_val;
	uint_t reg_len;
	uint8_t vr_index;

	nxhv_vr_fp_t *fp;
	uint64_t cookie, vr_address, vr_size;

	nxhv_dc_fp_t *tx, *rx;
	uint64_t tx_map, rx_map;

	uint64_t hv_rv;

	/* Variables needed to register with vnet. */
	mac_register_t *mac_info;
	ether_addr_t mac_addr;
	nx_vio_fp_t *vio;

	int i;

	NXGE_DEBUG_MSG((nxge, HIO_CTL, "==> nxge_hio_vr_add"));

	/*
	 * Get our HV cookie.
	 */
	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, nxge->dip,
	    0, "reg", &reg_val, &reg_len) != DDI_PROP_SUCCESS) {
		NXGE_DEBUG_MSG((nxge, VPD_CTL, "`reg' property not found"));
		return (NXGE_ERROR);
	}

	cookie = (uint64_t)(reg_val[0]);
	ddi_prop_free(reg_val);

	fp = &nhd->hio.vr;
	hv_rv = (*fp->getinfo)(cookie, &vr_address, &vr_size);
	if (hv_rv != 0) {
		NXGE_ERROR_MSG((nxge, NXGE_ERR_CTL,
		    "vr->getinfo() failed"));
		return (NXGE_ERROR);
	}

	/*
	 * In the guest domain, we can use any VR data structure
	 * we want, because we're not supposed to know which VR
	 * the service domain has allocated to us.
	 *
	 * In the current version, the least significant nybble of
	 * the cookie is the VR region, but that could change
	 * very easily.
	 *
	 * In the future, a guest may have more than one VR allocated
	 * to it, which is why we go through this exercise.
	 */
	MUTEX_ENTER(&nhd->lock);
	for (vr_index = 0; vr_index < FUNC_VIR_MAX; vr_index++) {
		if (nhd->vr[vr_index].nxge == 0) {
			nhd->vr[vr_index].nxge = (uintptr_t)nxge;
			break;
		}
	}
	MUTEX_EXIT(&nhd->lock);

	if (vr_index == FUNC_VIR_MAX) {
		NXGE_ERROR_MSG((nxge, NXGE_ERR_CTL, "nxge_hio_vr_add "
		    "no VRs available"));
		return (NXGE_ERROR);
	}

	vr = &nhd->vr[vr_index];

	vr->nxge = (uintptr_t)nxge;
	vr->cookie = (uint32_t)cookie;
	vr->address = vr_address;
	vr->size = vr_size;
	vr->region = vr_index;

	/*
	 * This is redundant data, but useful nonetheless.  It helps
	 * us to keep track of which RDCs & TDCs belong to us.
	 */
	if (nxge->tx_set.lg.count == 0)
		(void) nxge_grp_add(nxge, NXGE_TRANSMIT_GROUP);
	if (nxge->rx_set.lg.count == 0)
		(void) nxge_grp_add(nxge, NXGE_RECEIVE_GROUP);

	/*
	 * See nxge_intr.c.
	 */
	if (nxge_hio_intr_init(nxge) != NXGE_OK) {
		NXGE_ERROR_MSG((nxge, NXGE_ERR_CTL,
		    "nxge_hio_intr_init() failed"));
		return (NXGE_ERROR);
	}

	/*
	 * Now we find out which RDCs & TDCs have been allocated to us.
	 */
	tx = &nhd->hio.tx;
	if (tx->get_map) {
		/*
		 * The map we get back is a bitmap of the
		 * virtual Tx DMA channels we own -
		 * they are NOT real channel numbers.
		 */
		hv_rv = (*tx->get_map)(vr->cookie, &tx_map);
		if (hv_rv != 0) {
			NXGE_ERROR_MSG((nxge, NXGE_ERR_CTL,
			    "tx->get_map() failed"));
			return (NXGE_ERROR);
		}
		res_map_parse(nxge, NXGE_TRANSMIT_GROUP, tx_map);

		/*
		 * For each channel, mark these two fields
		 * while we have the VR data structure.
		 */
		for (i = 0; i < VP_CHANNEL_MAX; i++) {
			if ((1 << i) & tx_map) {
				dc = nxge_guest_dc_alloc(nxge, vr,
				    NXGE_TRANSMIT_GROUP);
				if (dc == 0) {
					NXGE_ERROR_MSG((nxge, NXGE_ERR_CTL,
					    "DC add failed"));
					return (NXGE_ERROR);
				}
				dc->channel = (nxge_channel_t)i;
			}
		}
	}

	rx = &nhd->hio.rx;
	if (rx->get_map) {
		/*
		 * I repeat, the map we get back is a bitmap of
		 * the virtual Rx DMA channels we own -
		 * they are NOT real channel numbers.
		 */
		hv_rv = (*rx->get_map)(vr->cookie, &rx_map);
		if (hv_rv != 0) {
			NXGE_ERROR_MSG((nxge, NXGE_ERR_CTL,
			    "rx->get_map() failed"));
			return (NXGE_ERROR);
		}
		res_map_parse(nxge, NXGE_RECEIVE_GROUP, rx_map);

		/*
		 * For each channel, mark these two fields
		 * while we have the VR data structure.
		 */
		for (i = 0; i < VP_CHANNEL_MAX; i++) {
			if ((1 << i) & rx_map) {
				dc = nxge_guest_dc_alloc(nxge, vr,
				    NXGE_RECEIVE_GROUP);
				if (dc == 0) {
					NXGE_ERROR_MSG((nxge, NXGE_ERR_CTL,
					    "DC add failed"));
					return (NXGE_ERROR);
				}
				dc->channel = (nxge_channel_t)i;
			}
		}
	}

	/*
	 * Register with vnet.
	 */
	if ((mac_info = mac_alloc(MAC_VERSION)) == NULL)
		return (NXGE_ERROR);

	mac_info->m_type_ident = MAC_PLUGIN_IDENT_ETHER;
	mac_info->m_driver = nxge;
	mac_info->m_dip = nxge->dip;
	mac_info->m_src_addr = KMEM_ZALLOC(MAXMACADDRLEN, KM_SLEEP);
	mac_info->m_dst_addr = KMEM_ZALLOC(MAXMACADDRLEN, KM_SLEEP);
	(void) memset(mac_info->m_src_addr, 0xff, sizeof (MAXMACADDRLEN));
	mac_info->m_callbacks = &nxge_m_callbacks;
	mac_info->m_min_sdu = 0;
	mac_info->m_max_sdu = NXGE_MTU_DEFAULT_MAX -
	    sizeof (struct ether_header) - ETHERFCSL - 4;

	(void) memset(&mac_addr, 0xff, sizeof (mac_addr));

	/* Register with vio_net. */
	vio = &nhd->hio.vio;
	if ((*vio->__register)(mac_info, VIO_NET_RES_HYBRID,
	    nxge->hio_mac_addr, mac_addr, &vr->vhp, &vio->cb)) {
		NXGE_DEBUG_MSG((nxge, HIO_CTL, "HIO registration() failed"));
		return (NXGE_ERROR);
	}

	nxge->hio_vr = vr;	/* For faster lookups. */

	NXGE_DEBUG_MSG((nxge, HIO_CTL, "<== nxge_hio_vr_add"));

	return (NXGE_OK);
}

/*
 * nxge_guest_dc_alloc
 *
 *	Find a free nxge_hio_dc_t data structure.
 *
 * Arguments:
 * 	nxge
 * 	type	TRANSMIT or RECEIVE.
 *
 * Notes:
 *
 * Context:
 *	Guest domain
 */
nxge_hio_dc_t *
nxge_guest_dc_alloc(
	nxge_t *nxge,
	nxge_hio_vr_t *vr,
	nxge_grp_type_t type)
{
	nxge_hio_data_t *nhd = (nxge_hio_data_t *)nxge->nxge_hw_p->hio;
	nxge_hio_dc_t *dc;
	int limit, i;

	/*
	 * In the guest domain, there may be more than one VR.
	 * each one of which will be using the same slots, or
	 * virtual channel numbers.  So the <nhd>'s rdc & tdc
	 * tables must be shared.
	 */
	if (type == NXGE_TRANSMIT_GROUP) {
		dc = &nhd->tdc[0];
		limit = NXGE_MAX_TDCS;
	} else {
		dc = &nhd->rdc[0];
		limit = NXGE_MAX_RDCS;
	}

	MUTEX_ENTER(&nhd->lock);
	for (i = 0; i < limit; i++, dc++) {
		if (dc->vr == 0) {
			dc->vr = vr;
			dc->cookie = vr->cookie;
			MUTEX_EXIT(&nhd->lock);
			return (dc);
		}
	}
	MUTEX_EXIT(&nhd->lock);

	return (0);
}

/*
 * res_map_parse
 *
 *	Parse a resource map.  The resources are DMA channels, receive
 *	or transmit, depending on <type>.
 *
 * Arguments:
 * 	nxge
 * 	type	Transmit or receive.
 *	res_map	The resource map to parse.
 *
 * Notes:
 *
 * Context:
 *	Guest domain
 */
void
res_map_parse(
	nxge_t *nxge,
	nxge_grp_type_t type,
	uint64_t res_map)
{
	uint8_t slots, mask, slot;
	int first, count;

	nxge_hw_pt_cfg_t *hardware;
	nxge_grp_t *group;

	/* Slots are numbered 0 - 7. */
	slots = (uint8_t)(res_map & 0xff);

	/* Count the number of bits in the bitmap. */
	for (slot = 0, count = 0, mask = 1; slot < 8; slot++) {
		if (slots & mask)
			count++;
		if (count == 1)
			first = slot;
		mask <<= 1;
	}

	hardware = &nxge->pt_config.hw_config;
	group = (type == NXGE_TRANSMIT_GROUP) ?
	    nxge->tx_set.group[0] : nxge->rx_set.group[0];

	/*
	 * A guest domain has one Tx & one Rx group, so far.
	 * In the future, there may be more than one.
	 */
	if (type == NXGE_TRANSMIT_GROUP) {
		nxge_dma_pt_cfg_t *port = &nxge->pt_config;

		hardware->tdc.start = first;
		hardware->tdc.count = count;
		hardware->tdc.owned = count;

		group->map = slots;

		/*
		 * Pointless in a guest domain.  This bitmap is used
		 * in only one place: nxge_txc_init(),
		 * a service-domain-only function.
		 */
		port->tx_dma_map = slots;

		nxge->tx_set.owned.map |= slots;
	} else {
		nxge_rdc_grp_t *rdc_grp = &nxge->pt_config.rdc_grps[0];

		hardware->start_rdc = first;
		hardware->max_rdcs = count;

		rdc_grp->start_rdc = (uint8_t)first;
		rdc_grp->max_rdcs = (uint8_t)count;
		rdc_grp->def_rdc = (uint8_t)first;

		rdc_grp->map = slots;
		group->map = slots;

		nxge->rx_set.owned.map |= slots;
	}
}

/*
 * nxge_hio_vr_release
 *
 *	Release a virtualization region (VR).
 *
 * Arguments:
 * 	nxge
 *
 * Notes:
 *	We must uninitialize all DMA channels associated with the VR, too.
 *
 *	The service domain will re-initialize these DMA channels later.
 *	See nxge_hio.c:nxge_hio_share_free() for details.
 *
 * Context:
 *	Guest domain
 */
int
nxge_hio_vr_release(
	nxge_t *nxge)
{
	NXGE_DEBUG_MSG((nxge, MEM2_CTL, "==> nxge_hio_vr_release"));

	/*
	 * Uninitialize interrupts.
	 */
	nxge_hio_intr_uninit(nxge);

	/*
	 * Uninitialize the receive DMA channels.
	 */
	nxge_uninit_rxdma_channels(nxge);

	/*
	 * Uninitialize the transmit DMA channels.
	 */
	nxge_uninit_txdma_channels(nxge);

	// Remove both groups. Assumption: only two groups!
	nxge_grp_remove(nxge, (vr_handle_t)nxge->rx_set.group[0]);
	nxge_grp_remove(nxge, (vr_handle_t)nxge->tx_set.group[0]);

	NXGE_DEBUG_MSG((nxge, MEM2_CTL, "<== nxge_hio_vr_release"));

	return (NXGE_OK);
}

#if defined(NIU_LP_WORKAROUND)
/*
 * nxge_tdc_lp_conf
 *
 *	Configure the logical pages for a TDC.
 *
 * Arguments:
 * 	nxge
 * 	channel	The TDC to configure.
 *
 * Notes:
 *
 * Context:
 *	Guest domain
 */
nxge_status_t
nxge_tdc_lp_conf(
	p_nxge_t nxge,
	int channel)
{
	nxge_hio_dc_t		*dc;
	nxge_dma_common_t	*data;
	nxge_dma_common_t	*control;
	tx_ring_t 		*ring;

	uint64_t		hv_rv;
	uint64_t		ra, size;

	NXGE_DEBUG_MSG((nxge, HIO_CTL, "==> nxge_tdc_lp_conf"));

	ring = nxge->tx_rings->rings[channel];

	if (ring->hv_set) {
		/* This shouldn't happen. */
		return (NXGE_OK);
	}

	if (!(dc = nxge_grp_dc_find(nxge, VP_BOUND_TX, channel)))
		return (NXGE_ERROR);

	/*
	 * Initialize logical page 0 for data buffers.
	 *
	 * <orig_ioaddr_pp> & <orig_alength> are initialized in
	 * nxge_main.c:nxge_dma_mem_alloc().
	 */
	data = nxge->tx_buf_pool_p->dma_buf_pool_p[channel];
	ring->hv_tx_buf_base_ioaddr_pp = (uint64_t)data->orig_ioaddr_pp;
	ring->hv_tx_buf_ioaddr_size = (uint64_t)data->orig_alength;

	hv_rv = hv_niu_vrtx_logical_page_conf(dc->cookie,
	    (uint64_t)channel, 0,
	    ring->hv_tx_buf_base_ioaddr_pp,
	    ring->hv_tx_buf_ioaddr_size);

	if (hv_rv != 0) {
		NXGE_ERROR_MSG((nxge, NXGE_ERR_CTL,
		    "<== nxge_tdc_lp_conf: channel %d "
		    "(page 0 data buf) hv: %d "
		    "ioaddr_pp $%p size 0x%llx ",
		    channel, hv_rv,
		    ring->hv_tx_buf_base_ioaddr_pp,
		    ring->hv_tx_buf_ioaddr_size));
		return (NXGE_ERROR | hv_rv);
	}

	ra = size = 0;
	hv_rv = hv_niu_vrtx_logical_page_info(dc->cookie,
	    (uint64_t)channel, 0, &ra, &size);

	NXGE_DEBUG_MSG((nxge, HIO_CTL,
	    "==> nxge_tdc_lp_conf: channel %d "
	    "(page 0 data buf) hv_rv 0x%llx "
	    "set ioaddr_pp $%p set size 0x%llx "
	    "get ra ioaddr_pp $%p get size 0x%llx ",
	    channel, hv_rv, ring->hv_tx_buf_base_ioaddr_pp,
	    ring->hv_tx_buf_ioaddr_size, ra, size));

	/*
	 * Initialize logical page 1 for control buffers.
	 */
	control = nxge->tx_cntl_pool_p->dma_buf_pool_p[channel];
	ring->hv_tx_cntl_base_ioaddr_pp = (uint64_t)control->orig_ioaddr_pp;
	ring->hv_tx_cntl_ioaddr_size = (uint64_t)control->orig_alength;

	hv_rv = hv_niu_vrtx_logical_page_conf(dc->cookie,
	    (uint64_t)channel, (uint64_t)1,
	    ring->hv_tx_cntl_base_ioaddr_pp,
	    ring->hv_tx_cntl_ioaddr_size);

	if (hv_rv != 0) {
		NXGE_ERROR_MSG((nxge, NXGE_ERR_CTL,
		    "<== nxge_tdc_lp_conf: channel %d "
		    "(page 1 cntl buf) hv_rv 0x%llx "
		    "ioaddr_pp $%p size 0x%llx ",
		    channel, hv_rv,
		    ring->hv_tx_cntl_base_ioaddr_pp,
		    ring->hv_tx_cntl_ioaddr_size));
		return (NXGE_ERROR | hv_rv);
	}

	ra = size = 0;
	hv_rv = hv_niu_vrtx_logical_page_info(dc->cookie,
	    (uint64_t)channel, (uint64_t)1, &ra, &size);

	NXGE_DEBUG_MSG((nxge, HIO_CTL,
	    "==> nxge_tdc_lp_conf: channel %d "
	    "(page 1 cntl buf) hv_rv 0x%llx "
	    "set ioaddr_pp $%p set size 0x%llx "
	    "get ra ioaddr_pp $%p get size 0x%llx ",
	    channel, hv_rv, ring->hv_tx_cntl_base_ioaddr_pp,
	    ring->hv_tx_cntl_ioaddr_size, ra, size));

	ring->hv_set = B_TRUE;

	NXGE_DEBUG_MSG((nxge, HIO_CTL, "<== nxge_tdc_lp_conf"));

	return (NXGE_OK);
}

/*
 * nxge_rdc_lp_conf
 *
 *	Configure an RDC's logical pages.
 *
 * Arguments:
 * 	nxge
 * 	channel	The RDC to configure.
 *
 * Notes:
 *
 * Context:
 *	Guest domain
 */
nxge_status_t
nxge_rdc_lp_conf(
	p_nxge_t nxge,
	int channel)
{
	nxge_hio_dc_t		*dc;
	nxge_dma_common_t	*data;
	nxge_dma_common_t	*control;
	rx_rbr_ring_t		*ring;

	uint64_t		hv_rv;
	uint64_t		ra, size;

	NXGE_DEBUG_MSG((nxge, HIO_CTL, "==> nxge_rdc_lp_conf"));

	ring = nxge->rx_rbr_rings->rbr_rings[channel];

	if (ring->hv_set) {
		return (NXGE_OK);
	}

	if (!(dc = nxge_grp_dc_find(nxge, VP_BOUND_RX, channel)))
		return (NXGE_ERROR);

	/*
	 * Initialize logical page 0 for data buffers.
	 *
	 * <orig_ioaddr_pp> & <orig_alength> are initialized in
	 * nxge_main.c:nxge_dma_mem_alloc().
	 */
	data = nxge->rx_buf_pool_p->dma_buf_pool_p[channel];
	ring->hv_rx_buf_base_ioaddr_pp = (uint64_t)data->orig_ioaddr_pp;
	ring->hv_rx_buf_ioaddr_size = (uint64_t)data->orig_alength;

	hv_rv = hv_niu_vrrx_logical_page_conf(dc->cookie,
	    (uint64_t)channel, 0,
	    ring->hv_rx_buf_base_ioaddr_pp,
	    ring->hv_rx_buf_ioaddr_size);

	if (hv_rv != 0) {
		NXGE_ERROR_MSG((nxge, NXGE_ERR_CTL,
		    "<== nxge_rdc_lp_conf: channel %d "
		    "(page 0 data buf) hv_rv 0x%llx "
		    "ioaddr_pp $%p size 0x%llx ",
		    channel, hv_rv,
		    ring->hv_rx_buf_base_ioaddr_pp,
		    ring->hv_rx_buf_ioaddr_size));
		return (NXGE_ERROR | hv_rv);
	}

	ra = size = 0;
	hv_rv = hv_niu_vrrx_logical_page_info(dc->cookie,
	    (uint64_t)channel, 0, &ra, &size);

	NXGE_DEBUG_MSG((nxge, HIO_CTL,
	    "==> nxge_rdc_lp_conf: channel %d "
	    "(page 0 data buf) hv_rv 0x%llx "
	    "set ioaddr_pp $%p set size 0x%llx "
	    "get ra ioaddr_pp $%p get size 0x%llx ",
	    channel, hv_rv, ring->hv_rx_buf_base_ioaddr_pp,
	    ring->hv_rx_buf_ioaddr_size, ra, size));

	/*
	 * Initialize logical page 1 for control buffers.
	 */
	control = nxge->rx_cntl_pool_p->dma_buf_pool_p[channel];
	ring->hv_rx_cntl_base_ioaddr_pp = (uint64_t)control->orig_ioaddr_pp;
	ring->hv_rx_cntl_ioaddr_size = (uint64_t)control->orig_alength;

	hv_rv = hv_niu_vrrx_logical_page_conf(dc->cookie,
	    (uint64_t)channel, (uint64_t)1,
	    ring->hv_rx_cntl_base_ioaddr_pp,
	    ring->hv_rx_cntl_ioaddr_size);

	if (hv_rv != 0) {
		NXGE_ERROR_MSG((nxge, NXGE_ERR_CTL,
		    "<== nxge_rdc_lp_conf: channel %d "
		    "(page 1 cntl buf) hv_rv 0x%llx "
		    "ioaddr_pp $%p size 0x%llx ",
		    channel, hv_rv,
		    ring->hv_rx_cntl_base_ioaddr_pp,
		    ring->hv_rx_cntl_ioaddr_size));
		return (NXGE_ERROR | hv_rv);
	}

	ra = size = 0;
	hv_rv = hv_niu_vrrx_logical_page_info(dc->cookie,
	    (uint64_t)channel, (uint64_t)1, &ra, &size);

	NXGE_DEBUG_MSG((nxge, HIO_CTL,
	    "==> nxge_rdc_lp_conf: channel %d "
	    "(page 1 cntl buf) hv_rv 0x%llx "
	    "set ioaddr_pp $%p set size 0x%llx "
	    "get ra ioaddr_pp $%p get size 0x%llx ",
	    channel, hv_rv, ring->hv_rx_cntl_base_ioaddr_pp,
	    ring->hv_rx_cntl_ioaddr_size, ra, size));

	ring->hv_set = B_TRUE;

	NXGE_DEBUG_MSG((nxge, HIO_CTL, "<== nxge_rdc_lp_conf"));

	return (NXGE_OK);
}
#endif	/* defined(NIU_LP_WORKAROUND) */

/*
 * This value is in milliseconds.
 */
#define	NXGE_GUEST_TIMER	500 /* 1/2 second, for now */

/*
 * nxge_hio_start_timer
 *
 *	Start the timer which checks for Tx hangs.
 *
 * Arguments:
 * 	nxge
 *
 * Notes:
 *	This function is called from nxge_attach().
 *
 *	This function kicks off the guest domain equivalent of
 *	nxge_check_hw_state().  It is called only once, from attach.
 *
 * Context:
 *	Guest domain
 */
void
nxge_hio_start_timer(
	nxge_t *nxge)
{
	nxge_hio_data_t *nhd = (nxge_hio_data_t *)nxge->nxge_hw_p->hio;
	nxge_hio_vr_t *vr;
	int region;

	NXGE_DEBUG_MSG((nxge, HIO_CTL, "==> nxge_hio_timer_start"));

	MUTEX_ENTER(&nhd->lock);

	/*
	 * Find our VR data structure.  (We are currently assuming
	 * one VR per guest domain.  That may change in the future.)
	 */
	for (region = FUNC0_VIR0; region < NXGE_VR_SR_MAX; region++) {
		if (nhd->vr[region].nxge == (uintptr_t)nxge)
			break;
	}

	MUTEX_EXIT(&nhd->lock);

	if (region == NXGE_VR_SR_MAX) {
		return;
	}

	vr = (nxge_hio_vr_t *)&nhd->vr[region];

	nxge->nxge_timerid = timeout((void(*)(void *))nxge_check_guest_state,
	    (void *)vr, drv_usectohz(1000 * NXGE_GUEST_TIMER));

	NXGE_DEBUG_MSG((nxge, HIO_CTL, "<== nxge_hio_timer_start"));
}

/*
 * nxge_check_guest_state
 *
 *	Essentially, check for Tx hangs.  In the future, if we are
 *	polling the hardware, we may do so here.
 *
 * Arguments:
 * 	vr	The virtualization region (VR) data structure.
 *
 * Notes:
 *	This function is the guest domain equivalent of
 *	nxge_check_hw_state().  Since we have no hardware to
 * 	check, we simply call nxge_check_tx_hang().
 *
 * Context:
 *	Guest domain
 */
void
nxge_check_guest_state(
	nxge_hio_vr_t *vr)
{
	nxge_t *nxge = (nxge_t *)vr->nxge;

	NXGE_DEBUG_MSG((nxge, SYSERR_CTL, "==> nxge_check_guest_state"));

	MUTEX_ENTER(nxge->genlock);

	nxge->nxge_timerid = 0;

	nxge_check_tx_hang(nxge);

	nxge->nxge_timerid = timeout((void(*)(void *))nxge_check_guest_state,
	    (caddr_t)vr, drv_usectohz(1000 * NXGE_GUEST_TIMER));

nxge_check_guest_state_exit:
	MUTEX_EXIT(nxge->genlock);
	NXGE_DEBUG_MSG((nxge, SYSERR_CTL, "<== nxge_check_guest_state"));
}

#endif	/* defined(sun4v) */
