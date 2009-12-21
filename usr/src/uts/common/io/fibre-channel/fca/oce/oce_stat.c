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
 * Copyright 2009 Emulex.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Source file containing the implementation of the driver statistics
 * and related helper functions
 */

#include <oce_impl.h>
#include <oce_stat.h>
#include <oce_buf.h>

/*
 * function called by kstat to update the stats counters
 *
 * ksp - pointer to the kstats structure
 * rw - flags defining read/write
 *
 * return DDI_SUCCESS => success, failure otherwise
 */
static int
oce_update_stats(kstat_t *ksp, int rw)
{
	struct oce_dev *dev;
	struct oce_stat *stats;
	struct rx_port_stats *port_stats;
	clock_t new;
	boolean_t is_update_stats = B_FALSE;
	int ret;

	if (rw == KSTAT_WRITE) {
		return (EACCES);
	}

	dev = ksp->ks_private;
	stats = (struct oce_stat *)ksp->ks_data;
	port_stats = &dev->hw_stats->params.rsp.rx.port[dev->port_id];

	mutex_enter(&dev->dev_lock);
	if (dev->suspended) {
		mutex_exit(&dev->dev_lock);
		return (EIO);
	}

	/*
	 * allow stats update only if enough
	 * time has elapsed since last update
	 */
	new = ddi_get_lbolt();
	if ((new - dev->stat_ticks) >= drv_usectohz(STAT_TIMEOUT)) {
		dev->stat_ticks = new;
		is_update_stats = B_TRUE;
	}

	mutex_exit(&dev->dev_lock);

	/* fetch the latest stats from the adapter */
	if (is_update_stats) {
		if (dev->in_stats) {
			return (EIO);
		} else {
			atomic_add_32(&dev->in_stats, 1);
			ret = oce_get_hw_stats(dev);
			atomic_add_32(&dev->in_stats, -1);
			if (ret != DDI_SUCCESS) {
				oce_log(dev, CE_WARN, MOD_CONFIG,
				    "Failed to get stats:%d", ret);
				return (EIO);
			}
		}
	}

	/* update the stats */
	stats->rx_bytes_lo.value.ul = port_stats->rx_bytes_lsd;
	stats->rx_bytes_hi.value.ul = port_stats->rx_bytes_msd;

	stats->rx_frames.value.ul = port_stats->rx_total_frames;
	stats->rx_errors.value.ul = port_stats->rx_crc_errors +
	    port_stats->rx_alignment_symbol_errors +
	    port_stats->rx_in_range_errors +
	    port_stats->rx_out_range_errors +
	    port_stats->rx_frame_too_long +
	    port_stats->rx_ip_checksum_errs +
	    port_stats->rx_tcp_checksum_errs +
	    port_stats->rx_udp_checksum_errs;

	stats->rx_drops.value.ul = port_stats->rx_dropped_too_small +
	    port_stats->rx_dropped_too_short +
	    port_stats->rx_dropped_header_too_small +
	    port_stats->rx_dropped_tcp_length +
	    port_stats->rx_dropped_runt;

	stats->tx_bytes_lo.value.ul = port_stats->tx_bytes_lsd;
	stats->tx_bytes_hi.value.ul = port_stats->tx_bytes_msd;

	stats->tx_frames.value.ul = port_stats->tx_unicast_frames +
	    port_stats->tx_multicast_frames +
	    port_stats->tx_broadcast_frames +
	    port_stats->tx_pause_frames +
	    port_stats->tx_control_frames;
	stats->tx_errors.value.ul = dev->tx_errors;

	stats->rx_unicast_frames.value.ul =
	    port_stats->rx_unicast_frames;
	stats->rx_multicast_frames.value.ul =
	    port_stats->rx_multicast_frames;
	stats->rx_broadcast_frames.value.ul =
	    port_stats->rx_broadcast_frames;
	stats->rx_crc_errors.value.ul =
	    port_stats->rx_crc_errors;

	stats->rx_alignment_symbol_errors.value.ul =
	    port_stats->rx_alignment_symbol_errors;
	stats->rx_in_range_errors.value.ul =
	    port_stats->rx_in_range_errors;
	stats->rx_out_range_errors.value.ul =
	    port_stats->rx_out_range_errors;
	stats->rx_frame_too_long.value.ul =
	    port_stats->rx_frame_too_long;
	stats->rx_address_match_errors.value.ul =
	    port_stats->rx_address_match_errors;

	stats->rx_pause_frames.value.ul =
	    port_stats->rx_pause_frames;
	stats->rx_control_frames.value.ul =
	    port_stats->rx_control_frames;
	stats->rx_ip_checksum_errs.value.ul =
	    port_stats->rx_ip_checksum_errs;
	stats->rx_tcp_checksum_errs.value.ul =
	    port_stats->rx_tcp_checksum_errs;
	stats->rx_udp_checksum_errs.value.ul =
	    port_stats->rx_udp_checksum_errs;
	stats->rx_fifo_overflow.value.ul = port_stats->rx_fifo_overflow;
	stats->rx_input_fifo_overflow.value.ul =
	    port_stats->rx_input_fifo_overflow;

	stats->tx_unicast_frames.value.ul =
	    port_stats->tx_unicast_frames;
	stats->tx_multicast_frames.value.ul =
	    port_stats->tx_multicast_frames;
	stats->tx_broadcast_frames.value.ul =
	    port_stats->tx_broadcast_frames;
	stats->tx_pause_frames.value.ul =
	    port_stats->tx_pause_frames;
	stats->tx_control_frames.value.ul =
	    port_stats->tx_control_frames;
	return (DDI_SUCCESS);
} /* oce_update_stats */

/*
 * function to setup the kstat_t structure for the device and install it
 *
 * dev - software handle to the device
 *
 * return DDI_SUCCESS => success, failure otherwise
 */
int
oce_stat_init(struct oce_dev *dev)
{
	struct oce_stat *stats;
	uint32_t num_stats = sizeof (struct oce_stat) /
	    sizeof (kstat_named_t);

	/* allocate the kstat */
	dev->oce_kstats = kstat_create(OCE_MOD_NAME, dev->dev_id, "stats",
	    "net", KSTAT_TYPE_NAMED,
	    num_stats, 0);
	if (dev->oce_kstats == NULL) {
		oce_log(dev, CE_NOTE, MOD_CONFIG,
		    "kstat creation failed: 0x%p",
		    (void *)dev->oce_kstats);
		return (DDI_FAILURE);
	}

	/* allocate the device copy of the stats */
	dev->stats_dbuf = oce_alloc_dma_buffer(dev,
	    sizeof (struct mbx_get_nic_stats),
	    DDI_DMA_CONSISTENT);
	if (dev->stats_dbuf == NULL) {
		oce_log(dev, CE_NOTE, MOD_CONFIG,
		    "Could not allocate stats_dbuf: %p",
		    (void *)dev->stats_dbuf);
		kstat_delete(dev->oce_kstats);
		return (DDI_FAILURE);
	}
	dev->hw_stats = (struct mbx_get_nic_stats *)DBUF_VA(dev->stats_dbuf);

	/* initialize the counters */
	stats = (struct oce_stat *)dev->oce_kstats->ks_data;
	kstat_named_init(&stats->rx_bytes_hi, "rx bytes msd", KSTAT_DATA_ULONG);
	kstat_named_init(&stats->rx_bytes_lo, "rx bytes lsd", KSTAT_DATA_ULONG);

	kstat_named_init(&stats->rx_frames, "rx frames", KSTAT_DATA_ULONG);
	kstat_named_init(&stats->rx_errors, "rx errors", KSTAT_DATA_ULONG);
	kstat_named_init(&stats->rx_drops, "rx drops", KSTAT_DATA_ULONG);

	kstat_named_init(&stats->tx_bytes_hi, "tx bytes msd", KSTAT_DATA_ULONG);
	kstat_named_init(&stats->tx_bytes_lo, "tx bytes lsd", KSTAT_DATA_ULONG);

	kstat_named_init(&stats->tx_frames, "tx frames", KSTAT_DATA_ULONG);
	kstat_named_init(&stats->tx_errors, "tx errors", KSTAT_DATA_ULONG);

	kstat_named_init(&stats->rx_unicast_frames,
	    "rx unicast frames", KSTAT_DATA_ULONG);
	kstat_named_init(&stats->rx_multicast_frames,
	    "rx multicast frames", KSTAT_DATA_ULONG);
	kstat_named_init(&stats->rx_broadcast_frames,
	    "rx broadcast frames", KSTAT_DATA_ULONG);
	kstat_named_init(&stats->rx_crc_errors,
	    "rx crc errors", KSTAT_DATA_ULONG);

	kstat_named_init(&stats->rx_alignment_symbol_errors,
	    "rx alignment symbol errors", KSTAT_DATA_ULONG);
	kstat_named_init(&stats->rx_in_range_errors,
	    "rx in range errors", KSTAT_DATA_ULONG);
	kstat_named_init(&stats->rx_out_range_errors,
	    "rx out range errors", KSTAT_DATA_ULONG);
	kstat_named_init(&stats->rx_frame_too_long,
	    "rx frame too long", KSTAT_DATA_ULONG);
	kstat_named_init(&stats->rx_address_match_errors,
	    "rx address match errors", KSTAT_DATA_ULONG);

	kstat_named_init(&stats->rx_pause_frames,
	    "rx pause frames", KSTAT_DATA_ULONG);
	kstat_named_init(&stats->rx_control_frames,
	    "rx control frames", KSTAT_DATA_ULONG);
	kstat_named_init(&stats->rx_ip_checksum_errs,
	    "rx ip checksum errors", KSTAT_DATA_ULONG);
	kstat_named_init(&stats->rx_tcp_checksum_errs,
	    "rx tcp checksum errors", KSTAT_DATA_ULONG);
	kstat_named_init(&stats->rx_udp_checksum_errs,
	    "rx udp checksum errors", KSTAT_DATA_ULONG);
	kstat_named_init(&stats->rx_fifo_overflow,
	    "rx fifo overflow", KSTAT_DATA_ULONG);
	kstat_named_init(&stats->rx_input_fifo_overflow,
	    "rx input fifo overflow", KSTAT_DATA_ULONG);

	kstat_named_init(&stats->tx_unicast_frames,
	    "tx unicast frames", KSTAT_DATA_ULONG);
	kstat_named_init(&stats->tx_multicast_frames,
	    "tx multicast frames", KSTAT_DATA_ULONG);
	kstat_named_init(&stats->tx_broadcast_frames,
	    "tx broadcast frames", KSTAT_DATA_ULONG);
	kstat_named_init(&stats->tx_pause_frames,
	    "tx pause frames", KSTAT_DATA_ULONG);
	kstat_named_init(&stats->tx_control_frames,
	    "tx control frames", KSTAT_DATA_ULONG);

	dev->oce_kstats->ks_update = oce_update_stats;
	dev->oce_kstats->ks_private = (void *)dev;
	kstat_install(dev->oce_kstats);

	return (DDI_SUCCESS);
} /* oce_stat_init */

/*
 * function to undo initialization done in oce_stat_init
 *
 * dev - software handle to the device
 *
 * return none
 */
void
oce_stat_fini(struct oce_dev *dev)
{
	oce_free_dma_buffer(dev, dev->stats_dbuf);
	dev->hw_stats = NULL;
	dev->stats_dbuf = NULL;
	kstat_delete(dev->oce_kstats);
	dev->oce_kstats = NULL;
} /* oce_stat_fini */

/*
 * GLDv3 entry for statistic query
 */
int
oce_m_stat(void *arg, uint_t stat, uint64_t *val)
{
	struct oce_dev *dev = arg;
	struct oce_stat *stats;
	struct rx_port_stats *port_stats;
	boolean_t is_update_stats = B_FALSE;
	clock_t new;

	stats = (struct oce_stat *)dev->oce_kstats->ks_data;
	port_stats = &dev->hw_stats->params.rsp.rx.port[dev->port_id];

	mutex_enter(&dev->dev_lock);

	if (dev->suspended ||
	    (dev->state & STATE_MAC_STOPPING) ||
	    !(dev->state & STATE_MAC_STARTED)) {
		mutex_exit(&dev->dev_lock);
		return (EIO);
	}

	/*
	 * allow stats update only if enough
	 * time has elapsed since last update
	 */
	new = ddi_get_lbolt();
	if ((new - dev->stat_ticks) >= drv_usectohz(STAT_TIMEOUT)) {
		dev->stat_ticks = new;
		is_update_stats = B_TRUE;
	}
	mutex_exit(&dev->dev_lock);

	/* update hw stats. Required for netstat */
	if (is_update_stats) {
		if (dev->in_stats == 0) {
			atomic_add_32(&dev->in_stats, 1);
			(void) oce_get_hw_stats(dev);
			atomic_add_32(&dev->in_stats, -1);
		}
	}

	switch (stat) {
	case MAC_STAT_IFSPEED:
		if (dev->state & STATE_MAC_STARTED)
			*val = 10000000000ull;
		else
			*val = 0;
	break;

	case MAC_STAT_RBYTES:
		stats->rx_bytes_lo.value.ul = port_stats->rx_bytes_lsd;
		stats->rx_bytes_hi.value.ul = port_stats->rx_bytes_msd;
		*val = (uint64_t)stats->rx_bytes_hi.value.ul << 32 |
		    (uint64_t)stats->rx_bytes_lo.value.ul;
	break;

	case MAC_STAT_IPACKETS:
		stats->rx_frames.value.ul = port_stats->rx_total_frames;
		*val = stats->rx_frames.value.ul;
	break;

	case MAC_STAT_OBYTES:
		stats->tx_bytes_lo.value.ul = port_stats->tx_bytes_lsd;
		stats->tx_bytes_hi.value.ul = port_stats->tx_bytes_msd;
		*val = (uint64_t)stats->tx_bytes_hi.value.ul << 32 |
		    (uint64_t)stats->tx_bytes_lo.value.ul;
	break;

	case MAC_STAT_OPACKETS:
		stats->tx_frames.value.ul = port_stats->tx_unicast_frames +
		    port_stats->tx_multicast_frames +
		    port_stats->tx_broadcast_frames +
		    port_stats->tx_pause_frames +
		    port_stats->tx_control_frames;
		*val = stats->tx_frames.value.ul;
	break;

	case MAC_STAT_BRDCSTRCV:
		stats->rx_broadcast_frames.value.ul =
		    port_stats->rx_broadcast_frames;
		*val = stats->rx_broadcast_frames.value.ul;
	break;

	case MAC_STAT_MULTIRCV:
		stats->rx_multicast_frames.value.ul =
		    port_stats->rx_multicast_frames;
		*val = stats->rx_multicast_frames.value.ul;
	break;

	case MAC_STAT_MULTIXMT:
		stats->tx_multicast_frames.value.ul =
		    port_stats->tx_multicast_frames;
		*val = stats->tx_multicast_frames.value.ul;
	break;

	case MAC_STAT_BRDCSTXMT:
		stats->tx_broadcast_frames.value.ul =
		    port_stats->tx_broadcast_frames;
		*val = stats->tx_broadcast_frames.value.ul;
	break;

	case MAC_STAT_NORCVBUF:
		stats->rx_fifo_overflow.value.ul =
		    port_stats->rx_fifo_overflow;
		*val = stats->rx_fifo_overflow.value.ul;
	break;

	case MAC_STAT_IERRORS:
		stats->rx_errors.value.ul = port_stats->rx_crc_errors +
		    port_stats->rx_alignment_symbol_errors +
		    port_stats->rx_in_range_errors +
		    port_stats->rx_out_range_errors +
		    port_stats->rx_frame_too_long +
		    port_stats->rx_ip_checksum_errs +
		    port_stats->rx_tcp_checksum_errs +
		    port_stats->rx_udp_checksum_errs;
		*val = stats->rx_errors.value.ul;
	break;

	case MAC_STAT_NOXMTBUF:
		*val = dev->tx_noxmtbuf;
	break;

	case MAC_STAT_OERRORS:
		*val = stats->tx_errors.value.ul;
	break;

	case ETHER_STAT_LINK_DUPLEX:
		if (dev->state & STATE_MAC_STARTED)
			*val = LINK_DUPLEX_FULL;
		else
			*val = LINK_DUPLEX_UNKNOWN;
	break;

	case ETHER_STAT_ALIGN_ERRORS:
		stats->rx_alignment_symbol_errors.value.ul =
		    port_stats->rx_alignment_symbol_errors;
		*val = port_stats->rx_alignment_symbol_errors;
	break;

	case ETHER_STAT_FCS_ERRORS:
		stats->rx_crc_errors.value.ul =
		    port_stats->rx_crc_errors;
		*val = port_stats->rx_crc_errors;
	break;

	case ETHER_STAT_MACRCV_ERRORS:
		stats->rx_errors.value.ul = port_stats->rx_crc_errors +
		    port_stats->rx_alignment_symbol_errors +
		    port_stats->rx_in_range_errors +
		    port_stats->rx_out_range_errors +
		    port_stats->rx_frame_too_long +
		    port_stats->rx_ip_checksum_errs +
		    port_stats->rx_tcp_checksum_errs +
		    port_stats->rx_udp_checksum_errs;

		*val = stats->rx_errors.value.ul;
	break;

	case ETHER_STAT_MACXMT_ERRORS:
		*val = stats->tx_errors.value.ul;
	break;

	case ETHER_STAT_TOOLONG_ERRORS:
		stats->rx_frame_too_long.value.ul =
		    port_stats->rx_frame_too_long;
		*val = port_stats->rx_frame_too_long;
	break;

	case ETHER_STAT_CAP_PAUSE:
	case ETHER_STAT_LINK_PAUSE:
		if (dev->flow_control & OCE_FC_TX &&
		    dev->flow_control & OCE_FC_RX)
			*val = LINK_FLOWCTRL_BI;
		else if (dev->flow_control == OCE_FC_TX)
			*val = LINK_FLOWCTRL_TX;
		else if (dev->flow_control == OCE_FC_RX)
			*val = LINK_FLOWCTRL_RX;
		else if (dev->flow_control == 0)
			*val = LINK_FLOWCTRL_NONE;
	break;

	default:
		return (ENOTSUP);
	}
	return (0);
} /* oce_m_stat */
