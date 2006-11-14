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
 *
 * Copyright (c) 2002-2006 Neterion, Inc.
 */

#include "xgehal-stats.h"
#include "xgehal-device.h"

/*
 * __hal_stats_initialize
 * @stats: xge_hal_stats_t structure that contains, in particular,
 *         Xframe hw stat counters.
 * @devh: HAL device handle.
 *
 * Initialize per-device statistics object.
 * See also: xge_hal_stats_getinfo(), xge_hal_status_e{}.
 */
xge_hal_status_e
__hal_stats_initialize (xge_hal_stats_t *stats, xge_hal_device_h devh)
{
	int dma_flags;
	xge_hal_device_t *hldev = (xge_hal_device_t*)devh;

	xge_assert(!stats->is_initialized);

	dma_flags = XGE_OS_DMA_CACHELINE_ALIGNED;
#ifdef XGE_HAL_DMA_STATS_CONSISTENT
	dma_flags |= XGE_OS_DMA_CONSISTENT;
#else
	dma_flags |= XGE_OS_DMA_STREAMING;
#endif

	stats->hw_info = (xge_hal_stats_hw_info_t *) xge_os_dma_malloc(hldev->pdev,
                     sizeof(xge_hal_stats_hw_info_t),
					 dma_flags,
					 &stats->hw_info_dmah,
                     &stats->hw_info_dma_acch);

	if (stats->hw_info == NULL) {
		xge_debug_stats(XGE_ERR, "%s", "can not DMA alloc");
		return XGE_HAL_ERR_OUT_OF_MEMORY;
	}
	xge_os_memzero(stats->hw_info, sizeof(xge_hal_stats_hw_info_t));
	xge_os_memzero(&stats->hw_info_saved, sizeof(xge_hal_stats_hw_info_t));
	xge_os_memzero(&stats->hw_info_latest, sizeof(xge_hal_stats_hw_info_t));

	stats->devh = devh;

	stats->dma_addr = xge_os_dma_map(hldev->pdev,
	                               stats->hw_info_dmah,
				       stats->hw_info,
				       sizeof(xge_hal_stats_hw_info_t),
				       XGE_OS_DMA_DIR_FROMDEVICE,
				       XGE_OS_DMA_CACHELINE_ALIGNED |
#ifdef XGE_HAL_DMA_STATS_CONSISTENT
				       XGE_OS_DMA_CONSISTENT
#else
			               XGE_OS_DMA_STREAMING
#endif
                                       );
	if (stats->dma_addr == XGE_OS_INVALID_DMA_ADDR) {
		xge_debug_stats(XGE_ERR, "can not map vaddr 0x"XGE_OS_LLXFMT" to DMA",
				 (unsigned long long)(ulong_t)stats->hw_info);
		xge_os_dma_free(hldev->pdev,
			      stats->hw_info,
			      sizeof(xge_hal_stats_hw_info_t),
			      &stats->hw_info_dma_acch,
			      &stats->hw_info_dmah);
		return XGE_HAL_ERR_OUT_OF_MAPPING;
	}

	xge_os_memzero(&stats->sw_dev_info_stats,
		     sizeof(xge_hal_stats_device_info_t));

	stats->is_initialized = 1;

	return XGE_HAL_OK;
}

static void
__hal_stats_save (xge_hal_stats_t *stats)
{
	xge_hal_stats_hw_info_t	*latest;

	(void) xge_hal_stats_hw(stats->devh, &latest);

	xge_os_memcpy(&stats->hw_info_saved, stats->hw_info,
		      sizeof(xge_hal_stats_hw_info_t));
}

/*
 * __hal_stats_disable
 * @stats: xge_hal_stats_t structure that contains, in particular,
 *         Xframe hw stat counters.
 *
 * Ask device to stop collecting stats.
 * See also: xge_hal_stats_getinfo().
 */
void
__hal_stats_disable (xge_hal_stats_t *stats)
{
	xge_hal_device_t *hldev;
	xge_hal_pci_bar0_t *bar0;
	u64 val64;

	xge_assert(stats->hw_info);

	hldev = (xge_hal_device_t*)stats->devh;
	xge_assert(hldev);

	bar0 = (xge_hal_pci_bar0_t *)(void *)hldev->bar0;

	val64 = xge_os_pio_mem_read64(hldev->pdev, hldev->regh0,
			&bar0->stat_cfg);
	val64 &= ~XGE_HAL_STAT_CFG_STAT_EN;
	xge_os_pio_mem_write64(hldev->pdev, hldev->regh0, val64,
			&bar0->stat_cfg);

	/* flush the write */
	(void)xge_os_pio_mem_read64(hldev->pdev, hldev->regh0,
			&bar0->stat_cfg);

	xge_debug_stats(XGE_TRACE, "stats disabled at 0x"XGE_OS_LLXFMT,
			 (unsigned long long)stats->dma_addr);

	stats->is_enabled = 0;
}

/*
 * __hal_stats_terminate
 * @stats: xge_hal_stats_t structure that contains, in particular,
 *         Xframe hw stat counters.
 * Terminate per-device statistics object.
 */
void
__hal_stats_terminate (xge_hal_stats_t *stats)
{
	xge_hal_device_t *hldev;

	xge_assert(stats->hw_info);

	hldev = (xge_hal_device_t*)stats->devh;
	xge_assert(hldev);

	xge_os_dma_unmap(hldev->pdev,
	               stats->hw_info_dmah,
		       stats->dma_addr,
		       sizeof(xge_hal_stats_hw_info_t),
		       XGE_OS_DMA_DIR_FROMDEVICE);

	xge_os_dma_free(hldev->pdev,
		      stats->hw_info,
		      sizeof(xge_hal_stats_hw_info_t),
		      &stats->hw_info_dma_acch,
		      &stats->hw_info_dmah);

	stats->is_initialized = 0;
	stats->is_enabled = 0;
}



/*
 * __hal_stats_enable
 * @stats: xge_hal_stats_t structure that contains, in particular,
 *         Xframe hw stat counters.
 *
 * Ask device to start collecting stats.
 * See also: xge_hal_stats_getinfo().
 */
void
__hal_stats_enable (xge_hal_stats_t *stats)
{
	xge_hal_device_t *hldev;
	xge_hal_pci_bar0_t *bar0;
	u64 val64;
	unsigned int refresh_time_pci_clocks;

	xge_assert(stats->hw_info);

	hldev = (xge_hal_device_t*)stats->devh;
	xge_assert(hldev);

	bar0 = (xge_hal_pci_bar0_t *)(void *)hldev->bar0;

	/* enable statistics */
	xge_os_pio_mem_write64(hldev->pdev, hldev->regh0, stats->dma_addr,
			       &bar0->stat_addr);

        refresh_time_pci_clocks = XGE_HAL_XENA_PER_SEC *
	                          hldev->config.stats_refresh_time_sec;
	refresh_time_pci_clocks =
	        __hal_fix_time_ival_herc(hldev, refresh_time_pci_clocks);

#ifdef XGE_HAL_HERC_EMULATION
	/*
	 * The clocks in the emulator are running ~1000 times slower than real world,
		* so the stats transfer will occur ~1000 times less frequent.
	 * STAT_CFG.STAT_TRSF_PERIOD should be set to 0x20C for Hercules emulation
		* (stats transferred every 0.5 sec).
	 */

	val64 = (0x20C | XGE_HAL_STAT_CFG_STAT_RO | XGE_HAL_STAT_CFG_STAT_EN);
#else
	val64 = XGE_HAL_SET_UPDT_PERIOD(refresh_time_pci_clocks) |
			                XGE_HAL_STAT_CFG_STAT_RO |
					XGE_HAL_STAT_CFG_STAT_EN;
#endif

	xge_os_pio_mem_write64(hldev->pdev, hldev->regh0, val64,
	                       &bar0->stat_cfg);

	xge_debug_stats(XGE_TRACE, "stats enabled at 0x"XGE_OS_LLXFMT,
			 (unsigned long long)stats->dma_addr);

	stats->is_enabled = 1;
}

/*
 * __hal_stats_update_latest - Update hw stats counters, based on the real
 * hardware maintained counters and the stored "reset" values.
 */
static void
__hal_stats_update_latest(xge_hal_device_h devh)
{
	xge_hal_device_t *hldev = (xge_hal_device_t *)devh;

#define set_latest_stat_cnt(_dev, _p)                                   \
        hldev->stats.hw_info_latest._p =                                \
	((hldev->stats.hw_info->_p >= hldev->stats.hw_info_saved._p) ?  \
          hldev->stats.hw_info->_p - hldev->stats.hw_info_saved._p :    \
	  ((-1) - hldev->stats.hw_info_saved._p) + hldev->stats.hw_info->_p)

	/* Tx MAC statistics counters. */
	set_latest_stat_cnt(hldev, tmac_frms);
	set_latest_stat_cnt(hldev, tmac_data_octets);
	set_latest_stat_cnt(hldev, tmac_drop_frms);
	set_latest_stat_cnt(hldev, tmac_mcst_frms);
	set_latest_stat_cnt(hldev, tmac_bcst_frms);
	set_latest_stat_cnt(hldev, tmac_pause_ctrl_frms);
	set_latest_stat_cnt(hldev, tmac_ttl_octets);
	set_latest_stat_cnt(hldev, tmac_ucst_frms);
	set_latest_stat_cnt(hldev, tmac_nucst_frms);
	set_latest_stat_cnt(hldev, tmac_any_err_frms);
	set_latest_stat_cnt(hldev, tmac_ttl_less_fb_octets);
	set_latest_stat_cnt(hldev, tmac_vld_ip_octets);
	set_latest_stat_cnt(hldev, tmac_vld_ip);
	set_latest_stat_cnt(hldev, tmac_drop_ip);
	set_latest_stat_cnt(hldev, tmac_icmp);
	set_latest_stat_cnt(hldev, tmac_rst_tcp);
	set_latest_stat_cnt(hldev, tmac_tcp);
	set_latest_stat_cnt(hldev, tmac_udp);
	set_latest_stat_cnt(hldev, reserved_0);

	/* Rx MAC Statistics counters. */
	set_latest_stat_cnt(hldev, rmac_vld_frms);
	set_latest_stat_cnt(hldev, rmac_data_octets);
	set_latest_stat_cnt(hldev, rmac_fcs_err_frms);
	set_latest_stat_cnt(hldev, rmac_drop_frms);
	set_latest_stat_cnt(hldev, rmac_vld_mcst_frms);
	set_latest_stat_cnt(hldev, rmac_vld_bcst_frms);
	set_latest_stat_cnt(hldev, rmac_in_rng_len_err_frms);
	set_latest_stat_cnt(hldev, rmac_out_rng_len_err_frms);
	set_latest_stat_cnt(hldev, rmac_long_frms);
	set_latest_stat_cnt(hldev, rmac_pause_ctrl_frms);
	set_latest_stat_cnt(hldev, rmac_unsup_ctrl_frms);
	set_latest_stat_cnt(hldev, rmac_ttl_octets);
	set_latest_stat_cnt(hldev, rmac_accepted_ucst_frms);
	set_latest_stat_cnt(hldev, rmac_accepted_nucst_frms);
	set_latest_stat_cnt(hldev, rmac_discarded_frms);
	set_latest_stat_cnt(hldev, rmac_drop_events);
	set_latest_stat_cnt(hldev, reserved_1);
	set_latest_stat_cnt(hldev, rmac_ttl_less_fb_octets);
	set_latest_stat_cnt(hldev, rmac_ttl_frms);
	set_latest_stat_cnt(hldev, reserved_2);
	set_latest_stat_cnt(hldev, reserved_3);
	set_latest_stat_cnt(hldev, rmac_usized_frms);
	set_latest_stat_cnt(hldev, rmac_osized_frms);
	set_latest_stat_cnt(hldev, rmac_frag_frms);
	set_latest_stat_cnt(hldev, rmac_jabber_frms);
	set_latest_stat_cnt(hldev, reserved_4);
	set_latest_stat_cnt(hldev, rmac_ttl_64_frms);
	set_latest_stat_cnt(hldev, rmac_ttl_65_127_frms);
	set_latest_stat_cnt(hldev, reserved_5);
	set_latest_stat_cnt(hldev, rmac_ttl_128_255_frms);
	set_latest_stat_cnt(hldev, rmac_ttl_256_511_frms);
	set_latest_stat_cnt(hldev, reserved_6);
	set_latest_stat_cnt(hldev, rmac_ttl_512_1023_frms);
	set_latest_stat_cnt(hldev, rmac_ttl_1024_1518_frms);
	set_latest_stat_cnt(hldev, reserved_7);
	set_latest_stat_cnt(hldev, rmac_ip);
	set_latest_stat_cnt(hldev, rmac_ip_octets);
	set_latest_stat_cnt(hldev, rmac_hdr_err_ip);
	set_latest_stat_cnt(hldev, rmac_drop_ip);
	set_latest_stat_cnt(hldev, rmac_icmp);
	set_latest_stat_cnt(hldev, reserved_8);
	set_latest_stat_cnt(hldev, rmac_tcp);
	set_latest_stat_cnt(hldev, rmac_udp);
	set_latest_stat_cnt(hldev, rmac_err_drp_udp);
	set_latest_stat_cnt(hldev, rmac_xgmii_err_sym);
	set_latest_stat_cnt(hldev, rmac_frms_q0);
	set_latest_stat_cnt(hldev, rmac_frms_q1);
	set_latest_stat_cnt(hldev, rmac_frms_q2);
	set_latest_stat_cnt(hldev, rmac_frms_q3);
	set_latest_stat_cnt(hldev, rmac_frms_q4);
	set_latest_stat_cnt(hldev, rmac_frms_q5);
	set_latest_stat_cnt(hldev, rmac_frms_q6);
	set_latest_stat_cnt(hldev, rmac_frms_q7);
	set_latest_stat_cnt(hldev, rmac_full_q0);
	set_latest_stat_cnt(hldev, rmac_full_q1);
	set_latest_stat_cnt(hldev, rmac_full_q2);
	set_latest_stat_cnt(hldev, rmac_full_q3);
	set_latest_stat_cnt(hldev, rmac_full_q4);
	set_latest_stat_cnt(hldev, rmac_full_q5);
	set_latest_stat_cnt(hldev, rmac_full_q6);
	set_latest_stat_cnt(hldev, rmac_full_q7);
	set_latest_stat_cnt(hldev, rmac_pause_cnt);
	set_latest_stat_cnt(hldev, reserved_9);
	set_latest_stat_cnt(hldev, rmac_xgmii_data_err_cnt);
	set_latest_stat_cnt(hldev, rmac_xgmii_ctrl_err_cnt);
	set_latest_stat_cnt(hldev, rmac_accepted_ip);
	set_latest_stat_cnt(hldev, rmac_err_tcp);

	/* PCI/PCI-X Read transaction statistics. */
	set_latest_stat_cnt(hldev, rd_req_cnt);
	set_latest_stat_cnt(hldev, new_rd_req_cnt);
	set_latest_stat_cnt(hldev, new_rd_req_rtry_cnt);
	set_latest_stat_cnt(hldev, rd_rtry_cnt);
	set_latest_stat_cnt(hldev, wr_rtry_rd_ack_cnt);

	/* PCI/PCI-X write transaction statistics. */
	set_latest_stat_cnt(hldev, wr_req_cnt);
	set_latest_stat_cnt(hldev, new_wr_req_cnt);
	set_latest_stat_cnt(hldev, new_wr_req_rtry_cnt);
	set_latest_stat_cnt(hldev, wr_rtry_cnt);
	set_latest_stat_cnt(hldev, wr_disc_cnt);
	set_latest_stat_cnt(hldev, rd_rtry_wr_ack_cnt);

	/* DMA Transaction statistics. */
	set_latest_stat_cnt(hldev, txp_wr_cnt);
	set_latest_stat_cnt(hldev, txd_rd_cnt);
	set_latest_stat_cnt(hldev, txd_wr_cnt);
	set_latest_stat_cnt(hldev, rxd_rd_cnt);
	set_latest_stat_cnt(hldev, rxd_wr_cnt);
	set_latest_stat_cnt(hldev, txf_rd_cnt);
	set_latest_stat_cnt(hldev, rxf_wr_cnt);

	/* Enhanced Herc statistics */
	set_latest_stat_cnt(hldev, tmac_frms_oflow);
	set_latest_stat_cnt(hldev, tmac_data_octets_oflow);
	set_latest_stat_cnt(hldev, tmac_mcst_frms_oflow);
	set_latest_stat_cnt(hldev, tmac_bcst_frms_oflow);
	set_latest_stat_cnt(hldev, tmac_ttl_octets_oflow);
	set_latest_stat_cnt(hldev, tmac_ucst_frms_oflow);
	set_latest_stat_cnt(hldev, tmac_nucst_frms_oflow);
	set_latest_stat_cnt(hldev, tmac_any_err_frms_oflow);
	set_latest_stat_cnt(hldev, tmac_vlan_frms);
	set_latest_stat_cnt(hldev, tmac_vld_ip_oflow);
	set_latest_stat_cnt(hldev, tmac_drop_ip_oflow);
	set_latest_stat_cnt(hldev, tmac_icmp_oflow);
	set_latest_stat_cnt(hldev, tmac_rst_tcp_oflow);
	set_latest_stat_cnt(hldev, tmac_udp_oflow);
	set_latest_stat_cnt(hldev, tpa_unknown_protocol);
	set_latest_stat_cnt(hldev, tpa_parse_failure);
	set_latest_stat_cnt(hldev, rmac_vld_frms_oflow);
	set_latest_stat_cnt(hldev, rmac_data_octets_oflow);
	set_latest_stat_cnt(hldev, rmac_vld_mcst_frms_oflow);
	set_latest_stat_cnt(hldev, rmac_vld_bcst_frms_oflow);
	set_latest_stat_cnt(hldev, rmac_ttl_octets_oflow);
	set_latest_stat_cnt(hldev, rmac_accepted_ucst_frms_oflow);
	set_latest_stat_cnt(hldev, rmac_accepted_nucst_frms_oflow);
	set_latest_stat_cnt(hldev, rmac_discarded_frms_oflow);
	set_latest_stat_cnt(hldev, rmac_drop_events_oflow);
	set_latest_stat_cnt(hldev, rmac_usized_frms_oflow);
	set_latest_stat_cnt(hldev, rmac_osized_frms_oflow);
	set_latest_stat_cnt(hldev, rmac_frag_frms_oflow);
	set_latest_stat_cnt(hldev, rmac_jabber_frms_oflow);
	set_latest_stat_cnt(hldev, rmac_ip_oflow);
	set_latest_stat_cnt(hldev, rmac_drop_ip_oflow);
	set_latest_stat_cnt(hldev, rmac_icmp_oflow);
	set_latest_stat_cnt(hldev, rmac_udp_oflow);
	set_latest_stat_cnt(hldev, rmac_err_drp_udp_oflow);
	set_latest_stat_cnt(hldev, rmac_pause_cnt_oflow);
	set_latest_stat_cnt(hldev, rmac_ttl_1519_4095_frms);
	set_latest_stat_cnt(hldev, rmac_ttl_4096_8191_frms);
	set_latest_stat_cnt(hldev, rmac_ttl_8192_max_frms);
	set_latest_stat_cnt(hldev, rmac_ttl_gt_max_frms);
	set_latest_stat_cnt(hldev, rmac_osized_alt_frms);
	set_latest_stat_cnt(hldev, rmac_jabber_alt_frms);
	set_latest_stat_cnt(hldev, rmac_gt_max_alt_frms);
	set_latest_stat_cnt(hldev, rmac_vlan_frms);
	set_latest_stat_cnt(hldev, rmac_fcs_discard);
	set_latest_stat_cnt(hldev, rmac_len_discard);
	set_latest_stat_cnt(hldev, rmac_da_discard);
	set_latest_stat_cnt(hldev, rmac_pf_discard);
	set_latest_stat_cnt(hldev, rmac_rts_discard);
	set_latest_stat_cnt(hldev, rmac_red_discard);
	set_latest_stat_cnt(hldev, rmac_ingm_full_discard);
	set_latest_stat_cnt(hldev, rmac_accepted_ip_oflow);
	set_latest_stat_cnt(hldev, link_fault_cnt);
}

/**
 * xge_hal_stats_hw - Get HW device statistics.
 * @devh: HAL device handle.
 * @hw_info: Xframe statistic counters. See xge_hal_stats_hw_info_t.
 *           Returned by HAL.
 *
 * Get device and HAL statistics. The latter is part of the in-host statistics
 * that HAL maintains for _that_ device.
 *
 * Returns: XGE_HAL_OK - success.
 * XGE_HAL_INF_STATS_IS_NOT_READY - Statistics information is not
 * currently available.
 *
 * See also: xge_hal_status_e{}.
 */
xge_hal_status_e
xge_hal_stats_hw(xge_hal_device_h devh, xge_hal_stats_hw_info_t **hw_info)
{
	xge_hal_device_t *hldev = (xge_hal_device_t *)devh;

	if (!hldev->stats.is_initialized ||
	    !hldev->stats.is_enabled) {
		*hw_info = NULL;
		return XGE_HAL_INF_STATS_IS_NOT_READY;
	}

#if defined(XGE_OS_DMA_REQUIRES_SYNC) && defined(XGE_HAL_DMA_STATS_STREAMING)
	xge_os_dma_sync(hldev->pdev,
	              hldev->stats.hw_info_dmah,
		      hldev->stats.dma_addr,
		      0,
		      sizeof(xge_hal_stats_hw_info_t),
		      XGE_OS_DMA_DIR_FROMDEVICE);
#endif

        /*
	 * update hw counters, taking into account
	 * the "reset" or "saved"
	 * values
	 */
	__hal_stats_update_latest(devh);

	*hw_info = &hldev->stats.hw_info_latest;

	return XGE_HAL_OK;
}

/**
 * xge_hal_stats_device - Get HAL statistics.
 * @devh: HAL device handle.
 * @hw_info: Xframe statistic counters. See xge_hal_stats_hw_info_t.
 *           Returned by HAL.
 * @device_info: HAL statistics. See xge_hal_stats_device_info_t.
 *               Returned by HAL.
 *
 * Get device and HAL statistics. The latter is part of the in-host statistics
 * that HAL maintains for _that_ device.
 *
 * Returns: XGE_HAL_OK - success.
 * XGE_HAL_INF_STATS_IS_NOT_READY - Statistics information is not
 * currently available.
 *
 * See also: xge_hal_status_e{}.
 */
xge_hal_status_e
xge_hal_stats_device(xge_hal_device_h devh,
		xge_hal_stats_device_info_t **device_info)
{
	xge_hal_device_t *hldev = (xge_hal_device_t *)devh;

	if (!hldev->stats.is_initialized ||
	    !hldev->stats.is_enabled) {
		*device_info = NULL;
		return XGE_HAL_INF_STATS_IS_NOT_READY;
	}

	hldev->stats.sw_dev_info_stats.traffic_intr_cnt =
		hldev->stats.sw_dev_info_stats.total_intr_cnt -
			hldev->stats.sw_dev_info_stats.not_traffic_intr_cnt;

	*device_info = &hldev->stats.sw_dev_info_stats;

	return XGE_HAL_OK;
}

/**
 * xge_hal_stats_channel - Get channel statistics.
 * @channelh: Channel handle.
 * @channel_info: HAL channel statistic counters.
 *                See xge_hal_stats_channel_info_t{}. Returned by HAL.
 *
 * Retrieve statistics of a particular HAL channel. This includes, for instance,
 * number of completions per interrupt, number of traffic interrupts, etc.
 *
 * Returns: XGE_HAL_OK - success.
 * XGE_HAL_INF_STATS_IS_NOT_READY - Statistics information is not
 * currently available.
 *
 * See also: xge_hal_status_e{}.
 */
xge_hal_status_e
xge_hal_stats_channel(xge_hal_channel_h channelh,
		xge_hal_stats_channel_info_t **channel_info)
{
	xge_hal_stats_hw_info_t	*latest;
	xge_hal_channel_t *channel;
	xge_hal_device_t *hldev;

	channel = (xge_hal_channel_t *)channelh;
	hldev = (xge_hal_device_t *)channel->devh;
	if ((hldev == NULL) || (hldev->magic != XGE_HAL_MAGIC)) {
		return XGE_HAL_ERR_INVALID_DEVICE;
	}
	if ((channel == NULL) || (channel->magic != XGE_HAL_MAGIC)) {
		return XGE_HAL_ERR_INVALID_DEVICE;
	}

	if (!hldev->stats.is_initialized ||
	    !hldev->stats.is_enabled ||
	    !channel->is_open) {
		*channel_info = NULL;
		return XGE_HAL_INF_STATS_IS_NOT_READY;
	}

	hldev->stats.sw_dev_info_stats.traffic_intr_cnt =
		hldev->stats.sw_dev_info_stats.total_intr_cnt -
			hldev->stats.sw_dev_info_stats.not_traffic_intr_cnt;

	if (hldev->stats.sw_dev_info_stats.traffic_intr_cnt) {
		int rxcnt = hldev->stats.sw_dev_info_stats.rx_traffic_intr_cnt;
		int txcnt = hldev->stats.sw_dev_info_stats.tx_traffic_intr_cnt;
		if (channel->type == XGE_HAL_CHANNEL_TYPE_FIFO) {
			if (!txcnt)
				txcnt = 1;
			channel->stats.avg_compl_per_intr_cnt =
				channel->stats.total_compl_cnt / txcnt;
		} else if (channel->type == XGE_HAL_CHANNEL_TYPE_RING &&
			   !hldev->config.bimodal_interrupts) {
			if (!rxcnt)
				rxcnt = 1;
			channel->stats.avg_compl_per_intr_cnt =
				channel->stats.total_compl_cnt / rxcnt;
		}
		if (channel->stats.avg_compl_per_intr_cnt == 0) {
			/* to not confuse user */
			channel->stats.avg_compl_per_intr_cnt = 1;
		}
	}

	(void) xge_hal_stats_hw(hldev, &latest);

	if (channel->stats.total_posts) {
		channel->stats.avg_buffers_per_post =
			channel->stats.total_buffers /
				channel->stats.total_posts;
#ifdef XGE_OS_PLATFORM_64BIT
	        if (channel->type == XGE_HAL_CHANNEL_TYPE_FIFO) {
		        channel->stats.avg_post_size =
			(u32)(latest->tmac_ttl_less_fb_octets /
				channel->stats.total_posts);
	        }
#endif
	}

#ifdef XGE_OS_PLATFORM_64BIT
	if (channel->stats.total_buffers &&
	    channel->type == XGE_HAL_CHANNEL_TYPE_FIFO) {
		channel->stats.avg_buffer_size =
			(u32)(latest->tmac_ttl_less_fb_octets /
				channel->stats.total_buffers);
	}
#endif

	*channel_info = &channel->stats;
	return XGE_HAL_OK;
}

/**
 * xge_hal_stats_reset - Reset (zero-out) device statistics
 * @devh: HAL device handle.
 *
 * Reset all device statistics.
 * Returns: XGE_HAL_OK - success.
 * XGE_HAL_INF_STATS_IS_NOT_READY - Statistics information is not
 * currently available.
 *
 * See also: xge_hal_status_e{}, xge_hal_stats_channel_info_t{},
 * xge_hal_stats_sw_err_t{}, xge_hal_stats_device_info_t{}.
 */
xge_hal_status_e
xge_hal_stats_reset(xge_hal_device_h devh)
{
	xge_hal_device_t *hldev = (xge_hal_device_t *)devh;

	if (!hldev->stats.is_initialized ||
	    !hldev->stats.is_enabled) {
		return XGE_HAL_INF_STATS_IS_NOT_READY;
	}

	/* save hw stats to calculate the after-reset values */
	__hal_stats_save(&hldev->stats);

	/* zero-out driver-maintained stats, don't reset the saved */
        __hal_stats_soft_reset(hldev, 0);

	return XGE_HAL_OK;
}

/*
 * __hal_stats_soft_reset - Reset software-maintained statistics.
 */
void
__hal_stats_soft_reset (xge_hal_device_h devh, int reset_all)
{
	xge_list_t *item;
	xge_hal_channel_t *channel;
	xge_hal_device_t *hldev = (xge_hal_device_t *)devh;

        if (reset_all)  {
	        xge_os_memzero(&hldev->stats.hw_info_saved,
		               sizeof(xge_hal_stats_hw_info_t));
	        xge_os_memzero(&hldev->stats.hw_info_latest,
		               sizeof(xge_hal_stats_hw_info_t));
        }

	/* Reset the "soft" error and informational statistics */
	xge_os_memzero(&hldev->stats.sw_dev_err_stats,
	             sizeof(xge_hal_stats_sw_err_t));
	xge_os_memzero(&hldev->stats.sw_dev_info_stats,
	             sizeof(xge_hal_stats_device_info_t));

	/* for each Rx channel */
	xge_list_for_each(item, &hldev->ring_channels) {
		channel = xge_container_of(item, xge_hal_channel_t, item);
		xge_os_memzero(&channel->stats,
		             sizeof(xge_hal_stats_channel_info_t));
	}

	/* for each Tx channel */
	xge_list_for_each(item, &hldev->fifo_channels) {
		channel = xge_container_of(item, xge_hal_channel_t, item);
		xge_os_memzero(&channel->stats,
		             sizeof(xge_hal_stats_channel_info_t));
	}
}

