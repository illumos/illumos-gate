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

/* Copyright © 2003-2011 Emulex. All rights reserved.  */

/*
 * Statistic specific data structures and function prototypes
 */

#ifndef	_OCE_STAT_H_
#define	_OCE_STAT_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <oce_hw_eth.h>
#include <oce_impl.h>

struct oce_stat {
	kstat_named_t rx_bytes_hi;
	kstat_named_t rx_bytes_lo;
	kstat_named_t rx_frames;
	kstat_named_t rx_errors;
	kstat_named_t rx_drops;

	kstat_named_t tx_bytes_hi;
	kstat_named_t tx_bytes_lo;
	kstat_named_t tx_frames;
	kstat_named_t tx_errors;

	kstat_named_t rx_unicast_frames;
	kstat_named_t rx_multicast_frames;
	kstat_named_t rx_broadcast_frames;
	kstat_named_t rx_crc_errors;

	kstat_named_t rx_alignment_symbol_errors;
	kstat_named_t rx_in_range_errors;
	kstat_named_t rx_out_range_errors;
	kstat_named_t rx_frame_too_long;
	kstat_named_t rx_address_match_errors;

	kstat_named_t rx_pause_frames;
	kstat_named_t rx_control_frames;
	kstat_named_t rx_ip_checksum_errs;
	kstat_named_t rx_tcp_checksum_errs;
	kstat_named_t rx_udp_checksum_errs;
	kstat_named_t rx_fifo_overflow;
	kstat_named_t rx_input_fifo_overflow;

	kstat_named_t tx_unicast_frames;
	kstat_named_t tx_multicast_frames;
	kstat_named_t tx_broadcast_frames;
	kstat_named_t tx_pause_frames;
	kstat_named_t tx_control_frames;


	kstat_named_t rx_drops_no_pbuf;
	kstat_named_t rx_drops_no_txpb;
	kstat_named_t rx_drops_no_erx_descr;
	kstat_named_t rx_drops_no_tpre_descr;
	kstat_named_t rx_drops_too_many_frags;
	kstat_named_t rx_drops_invalid_ring;
	kstat_named_t rx_drops_mtu;

	kstat_named_t rx_dropped_too_small;
	kstat_named_t rx_dropped_too_short;
	kstat_named_t rx_dropped_header_too_small;
	kstat_named_t rx_dropped_tcp_length;
	kstat_named_t rx_dropped_runt;

	kstat_named_t rx_drops_no_fragments;
};

int oce_stat_init(struct oce_dev *dev);
void oce_stat_fini(struct oce_dev *dev);

#ifdef __cplusplus
}
#endif

#endif /* _OCE_STAT_H_ */
