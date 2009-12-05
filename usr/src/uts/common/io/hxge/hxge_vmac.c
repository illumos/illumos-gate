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

#include <hxge_impl.h>
#include <hxge_vmac.h>

hxge_status_t hxge_vmac_init(p_hxge_t hxgep);
hxge_status_t hxge_tx_vmac_init(p_hxge_t hxgep);
hxge_status_t hxge_rx_vmac_init(p_hxge_t hxgep);
hxge_status_t hxge_tx_vmac_enable(p_hxge_t hxgep);
hxge_status_t hxge_tx_vmac_disable(p_hxge_t hxgep);
hxge_status_t hxge_rx_vmac_enable(p_hxge_t hxgep);
hxge_status_t hxge_rx_vmac_disable(p_hxge_t hxgep);
hxge_status_t hxge_tx_vmac_reset(p_hxge_t hxgep);
hxge_status_t hxge_rx_vmac_reset(p_hxge_t hxgep);
uint_t hxge_vmac_intr(caddr_t arg1, caddr_t arg2);
hxge_status_t hxge_set_promisc(p_hxge_t hxgep, boolean_t on);

hxge_status_t
hxge_link_init(p_hxge_t hxgep)
{
	p_hxge_stats_t		statsp;

	HXGE_DEBUG_MSG((hxgep, MAC_CTL, "==> hxge_link_init>"));

	statsp = hxgep->statsp;

	statsp->mac_stats.cap_10gfdx = 1;
	statsp->mac_stats.lp_cap_10gfdx = 1;

	/*
	 * The driver doesn't control the link.
	 * It is always 10Gb full duplex.
	 */
	statsp->mac_stats.link_duplex = 2;
	statsp->mac_stats.link_speed = 10000;

	HXGE_DEBUG_MSG((hxgep, MAC_CTL, "<== hxge_link_init"));
	return (HXGE_OK);
}

hxge_status_t
hxge_vmac_init(p_hxge_t hxgep)
{
	hxge_status_t status = HXGE_OK;

	HXGE_DEBUG_MSG((hxgep, MAC_CTL, "==> hxge_vmac_init:"));

	if ((status = hxge_tx_vmac_reset(hxgep)) != HXGE_OK)
		goto fail;

	if ((status = hxge_rx_vmac_reset(hxgep)) != HXGE_OK)
		goto fail;

	if ((status = hxge_tx_vmac_enable(hxgep)) != HXGE_OK)
		goto fail;

	if ((status = hxge_rx_vmac_enable(hxgep)) != HXGE_OK)
		goto fail;

	/* Clear the interrupt status registers */
	(void) hpi_vmac_clear_rx_int_stat(hxgep->hpi_handle);
	(void) hpi_vmac_clear_tx_int_stat(hxgep->hpi_handle);

	/*
	 * Take the masks off the overflow counters. Interrupt the system when
	 * any counts overflow. Don't interrupt the system for each frame.
	 * The current counts are retrieved when the "kstat" command is used.
	 */
	(void) hpi_pfc_set_rx_int_stat_mask(hxgep->hpi_handle, 0, 1);
	(void) hpi_pfc_set_tx_int_stat_mask(hxgep->hpi_handle, 0, 1);

	HXGE_DEBUG_MSG((hxgep, MAC_CTL, "<== hxge_vmac_init:"));

	return (HXGE_OK);
fail:
	HXGE_DEBUG_MSG((hxgep, MAC_CTL,
	    "hxge_vmac_init: failed to initialize VMAC>"));

	return (status);
}


/* Initialize the TxVMAC sub-block */

hxge_status_t
hxge_tx_vmac_init(p_hxge_t hxgep)
{
	uint64_t	config;
	hpi_handle_t	handle = hxgep->hpi_handle;

	/* CFG_VMAC_TX_EN is done separately */
	config = CFG_VMAC_TX_CRC_INSERT | CFG_VMAC_TX_PAD;

	if (hpi_vmac_tx_config(handle, INIT, config,
	    hxgep->vmac.maxframesize) != HPI_SUCCESS)
		return (HXGE_ERROR);

	hxgep->vmac.tx_config = config;

	return (HXGE_OK);
}

/* Initialize the RxVMAC sub-block */

hxge_status_t
hxge_rx_vmac_init(p_hxge_t hxgep)
{
	uint64_t	xconfig;
	hpi_handle_t	handle = hxgep->hpi_handle;
	uint16_t	max_frame_length = hxgep->vmac.maxframesize;

	/*
	 * NOTE: CFG_VMAC_RX_ENABLE is done separately. Do not enable
	 * strip CRC.  Bug ID 11451 -- enable strip CRC will cause
	 * rejection on minimum sized packets.
	 */
	xconfig = CFG_VMAC_RX_PASS_FLOW_CTRL_FR;

	if (hxgep->filter.all_phys_cnt != 0)
		xconfig |= CFG_VMAC_RX_PROMISCUOUS_MODE;

	if (hxgep->filter.all_multicast_cnt != 0)
		xconfig |= CFG_VMAC_RX_PROMIXCUOUS_GROUP;

	if (hxgep->statsp->port_stats.lb_mode != hxge_lb_normal)
		xconfig |= CFG_VMAC_RX_LOOP_BACK;

	if (hpi_vmac_rx_config(handle, INIT, xconfig,
	    max_frame_length) != HPI_SUCCESS)
		return (HXGE_ERROR);

	hxgep->vmac.rx_config = xconfig;

	return (HXGE_OK);
}

/* Enable TxVMAC */

hxge_status_t
hxge_tx_vmac_enable(p_hxge_t hxgep)
{
	hpi_status_t	rv;
	hxge_status_t	status = HXGE_OK;
	hpi_handle_t	handle = hxgep->hpi_handle;

	HXGE_DEBUG_MSG((hxgep, MAC_CTL, "==> hxge_tx_vmac_enable"));

	rv = hxge_tx_vmac_init(hxgep);
	if (rv != HXGE_OK)
		return (rv);

	/* Based on speed */
	hxgep->msg_min = ETHERMIN;

	rv = hpi_vmac_tx_config(handle, ENABLE, CFG_VMAC_TX_EN, 0);

	status = (rv == HPI_SUCCESS) ? HXGE_OK : HXGE_ERROR;

	HXGE_DEBUG_MSG((hxgep, MAC_CTL, "<== hxge_tx_vmac_enable"));

	return (status);
}

/* Disable TxVMAC */

hxge_status_t
hxge_tx_vmac_disable(p_hxge_t hxgep)
{
	hpi_status_t	rv;
	hxge_status_t	status = HXGE_OK;
	hpi_handle_t	handle = hxgep->hpi_handle;

	HXGE_DEBUG_MSG((hxgep, MAC_CTL, "==> hxge_tx_vmac_disable"));

	rv = hpi_vmac_tx_config(handle, DISABLE, CFG_VMAC_TX_EN, 0);

	status = (rv == HPI_SUCCESS) ? HXGE_OK : HXGE_ERROR;

	HXGE_DEBUG_MSG((hxgep, MAC_CTL, "<== hxge_tx_vmac_disable"));

	return (status);
}

/* Enable RxVMAC */

hxge_status_t
hxge_rx_vmac_enable(p_hxge_t hxgep)
{
	hpi_status_t	rv;
	hxge_status_t	status = HXGE_OK;
	hpi_handle_t	handle = hxgep->hpi_handle;

	HXGE_DEBUG_MSG((hxgep, MAC_CTL, "==> hxge_rx_vmac_enable"));

	/*
	 * Because of hardware bug document with CR6770577, need
	 * reprogram max framesize when enabling/disabling RX
	 * vmac.  Max framesize is programed here in
	 * hxge_rx_vmac_init().
	 */
	rv = hpi_vmac_rx_set_framesize(HXGE_DEV_HPI_HANDLE(hxgep),
	    (uint16_t)hxgep->vmac.maxframesize);
	if (rv != HPI_SUCCESS) {
		HXGE_DEBUG_MSG((hxgep, MAC_CTL, "<== hxge_rx_vmac_enable"));
		return (HXGE_ERROR);
	}

	/*
	 * Wait for a period of time.
	 */
	HXGE_DELAY(10);

	/*
	 * Enable the vmac.
	 */
	rv = hpi_vmac_rx_config(handle, ENABLE, CFG_VMAC_RX_EN, 0);

	status = (rv == HPI_SUCCESS) ? HXGE_OK : HXGE_ERROR;

	HXGE_DEBUG_MSG((hxgep, MAC_CTL, "<== hxge_rx_vmac_enable"));
	return (status);
}

/* Disable RxVMAC */

hxge_status_t
hxge_rx_vmac_disable(p_hxge_t hxgep)
{
	hpi_status_t	rv;
	hxge_status_t	status = HXGE_OK;
	hpi_handle_t	handle = hxgep->hpi_handle;

	HXGE_DEBUG_MSG((hxgep, MAC_CTL, "==> hxge_rx_vmac_disable"));

	/*
	 * Because of hardware bug document with CR6770577, need
	 * reprogram max framesize when enabling/disabling RX
	 * vmac.  Max framesize is programed here in
	 * hxge_rx_vmac_init().
	 */
	(void) hpi_vmac_rx_set_framesize(HXGE_DEV_HPI_HANDLE(hxgep),
	    (uint16_t)0);

	/*
	 * Wait for 10us before doing disable.
	 */
	HXGE_DELAY(10);

	rv = hpi_vmac_rx_config(handle, DISABLE, CFG_VMAC_RX_EN, 0);

	status = (rv == HPI_SUCCESS) ? HXGE_OK : HXGE_ERROR;

	HXGE_DEBUG_MSG((hxgep, MAC_CTL, "<== hxge_rx_vmac_disable"));
	return (status);
}

/* Reset TxVMAC */

hxge_status_t
hxge_tx_vmac_reset(p_hxge_t hxgep)
{
	hpi_handle_t	handle = hxgep->hpi_handle;

	(void) hpi_tx_vmac_reset(handle);

	return (HXGE_OK);
}

/* Reset RxVMAC */

hxge_status_t
hxge_rx_vmac_reset(p_hxge_t hxgep)
{
	hpi_handle_t	handle = hxgep->hpi_handle;

	(void) hpi_vmac_rx_set_framesize(HXGE_DEV_HPI_HANDLE(hxgep),
	    (uint16_t)0);

	/*
	 * Wait for 10us  before doing reset.
	 */
	HXGE_DELAY(10);

	(void) hpi_rx_vmac_reset(handle);

	return (HXGE_OK);
}

/*ARGSUSED*/
uint_t
hxge_vmac_intr(caddr_t arg1, caddr_t arg2)
{
	p_hxge_t	hxgep = (p_hxge_t)arg2;
	hpi_handle_t	handle;

	HXGE_DEBUG_MSG((hxgep, INT_CTL, "==> hxge_vmac_intr"));

	handle = HXGE_DEV_HPI_HANDLE(hxgep);

	hxge_save_cntrs(hxgep);

	/* Clear the interrupt status registers */
	(void) hpi_vmac_clear_rx_int_stat(handle);
	(void) hpi_vmac_clear_tx_int_stat(handle);

	HXGE_DEBUG_MSG((hxgep, INT_CTL, "<== hxge_vmac_intr"));
	return (DDI_INTR_CLAIMED);
}

/*
 * Set promiscous mode
 */
hxge_status_t
hxge_set_promisc(p_hxge_t hxgep, boolean_t on)
{
	hxge_status_t status = HXGE_OK;

	HXGE_DEBUG_MSG((hxgep, MAC_CTL, "==> hxge_set_promisc: on %d", on));

	hxgep->filter.all_phys_cnt = ((on) ? 1 : 0);

	RW_ENTER_WRITER(&hxgep->filter_lock);
	if ((status = hxge_rx_vmac_disable(hxgep)) != HXGE_OK)
		goto fail;
	if ((status = hxge_rx_vmac_enable(hxgep)) != HXGE_OK)
		goto fail;
	RW_EXIT(&hxgep->filter_lock);

	if (on)
		hxgep->statsp->mac_stats.promisc = B_TRUE;
	else
		hxgep->statsp->mac_stats.promisc = B_FALSE;

	HXGE_DEBUG_MSG((hxgep, MAC_CTL, "<== hxge_set_promisc"));
	return (HXGE_OK);

fail:
	RW_EXIT(&hxgep->filter_lock);

	HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL, "hxge_set_promisc: "
	    "Unable to set promisc (%d)", on));
	return (status);
}

void
hxge_save_cntrs(p_hxge_t hxgep)
{
	p_hxge_stats_t	statsp;
	hpi_handle_t	handle;

	vmac_tx_frame_cnt_t tx_frame_cnt;
	vmac_tx_byte_cnt_t tx_byte_cnt;
	vmac_rx_frame_cnt_t rx_frame_cnt;
	vmac_rx_byte_cnt_t rx_byte_cnt;
	vmac_rx_drop_fr_cnt_t rx_drop_fr_cnt;
	vmac_rx_drop_byte_cnt_t rx_drop_byte_cnt;
	vmac_rx_crc_cnt_t rx_crc_cnt;
	vmac_rx_pause_cnt_t rx_pause_cnt;
	vmac_rx_bcast_fr_cnt_t rx_bcast_fr_cnt;
	vmac_rx_mcast_fr_cnt_t rx_mcast_fr_cnt;

	HXGE_DEBUG_MSG((hxgep, INT_CTL, "==> hxge_save_cntrs"));

	statsp = (p_hxge_stats_t)hxgep->statsp;
	handle = hxgep->hpi_handle;

	HXGE_REG_RD64(handle, VMAC_TX_FRAME_CNT, &tx_frame_cnt.value);
	HXGE_REG_RD64(handle, VMAC_TX_BYTE_CNT, &tx_byte_cnt.value);
	HXGE_REG_RD64(handle, VMAC_RX_FRAME_CNT, &rx_frame_cnt.value);
	HXGE_REG_RD64(handle, VMAC_RX_BYTE_CNT, &rx_byte_cnt.value);
	HXGE_REG_RD64(handle, VMAC_RX_DROP_FR_CNT, &rx_drop_fr_cnt.value);
	HXGE_REG_RD64(handle, VMAC_RX_DROP_BYTE_CNT, &rx_drop_byte_cnt.value);
	HXGE_REG_RD64(handle, VMAC_RX_CRC_CNT, &rx_crc_cnt.value);
	HXGE_REG_RD64(handle, VMAC_RX_PAUSE_CNT, &rx_pause_cnt.value);
	HXGE_REG_RD64(handle, VMAC_RX_BCAST_FR_CNT, &rx_bcast_fr_cnt.value);
	HXGE_REG_RD64(handle, VMAC_RX_MCAST_FR_CNT, &rx_mcast_fr_cnt.value);

	statsp->vmac_stats.tx_frame_cnt += tx_frame_cnt.bits.tx_frame_cnt;
	statsp->vmac_stats.tx_byte_cnt += tx_byte_cnt.bits.tx_byte_cnt;
	statsp->vmac_stats.rx_frame_cnt += rx_frame_cnt.bits.rx_frame_cnt;
	statsp->vmac_stats.rx_byte_cnt += rx_byte_cnt.bits.rx_byte_cnt;
	statsp->vmac_stats.rx_drop_frame_cnt +=
	    rx_drop_fr_cnt.bits.rx_drop_frame_cnt;
	statsp->vmac_stats.rx_drop_byte_cnt +=
	    rx_drop_byte_cnt.bits.rx_drop_byte_cnt;
	statsp->vmac_stats.rx_crc_cnt += rx_crc_cnt.bits.rx_crc_cnt;
	statsp->vmac_stats.rx_pause_cnt += rx_pause_cnt.bits.rx_pause_cnt;
	statsp->vmac_stats.rx_bcast_fr_cnt +=
	    rx_bcast_fr_cnt.bits.rx_bcast_fr_cnt;
	statsp->vmac_stats.rx_mcast_fr_cnt +=
	    rx_mcast_fr_cnt.bits.rx_mcast_fr_cnt;

hxge_save_cntrs_exit:
	HXGE_DEBUG_MSG((hxgep, INT_CTL, "<== hxge_save_cntrs"));
}

int
hxge_vmac_set_framesize(p_hxge_t hxgep)
{
	int	status = 0;

	HXGE_DEBUG_MSG((hxgep, NDD_CTL, "==> hxge_vmac_set_framesize"));

	RW_ENTER_WRITER(&hxgep->filter_lock);
	(void) hxge_rx_vmac_disable(hxgep);
	(void) hxge_tx_vmac_disable(hxgep);

	/*
	 * Apply the new jumbo parameter here which is contained in hxgep
	 * data structure (hxgep->vmac.maxframesize);
	 * The order of the following two calls is important.
	 */
	(void) hxge_tx_vmac_enable(hxgep);
	(void) hxge_rx_vmac_enable(hxgep);
	RW_EXIT(&hxgep->filter_lock);

	HXGE_DEBUG_MSG((hxgep, NDD_CTL, "<== hxge_vmac_set_framesize"));
	return (status);
}
