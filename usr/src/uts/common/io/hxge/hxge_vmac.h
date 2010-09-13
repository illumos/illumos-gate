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

#ifndef	_SYS_HXGE_HXGE_VMAC_H
#define	_SYS_HXGE_HXGE_VMAC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <hxge_vmac_hw.h>
#include <hpi_vmac.h>

/* Common MAC statistics */
typedef	struct _hxge_mac_stats {
	/* Transciever state informations. */
	uint32_t	cap_10gfdx;

	/* Advertised capabilities. */
	uint32_t	adv_cap_10gfdx;

	/* Link partner capabilities. */
	uint32_t	lp_cap_10gfdx;

	/* Physical link statistics. */
	uint32_t	link_speed;
	uint32_t	link_duplex;
	uint32_t	link_up;

	/* Promiscous mode */
	boolean_t	promisc;
} hxge_mac_stats_t;

/* VMAC statistics */

typedef	struct _hxge_vmac_stats {
	uint64_t	tx_frame_cnt;		/* vmac_tx_frame_cnt_t */
	uint64_t	tx_byte_cnt;		/* vmac_tx_byte_cnt_t */

	uint64_t	rx_frame_cnt;		/* vmac_rx_frame_cnt_t */
	uint64_t	rx_byte_cnt;		/* vmac_rx_byte_cnt_t */
	uint64_t	rx_drop_frame_cnt;	/* vmac_rx_drop_fr_cnt_t */
	uint64_t	rx_drop_byte_cnt;	/* vmac_rx_drop_byte_cnt_t */
	uint64_t	rx_crc_cnt;		/* vmac_rx_crc_cnt_t */
	uint64_t	rx_pause_cnt;		/* vmac_rx_pause_cnt_t */
	uint64_t	rx_bcast_fr_cnt;	/* vmac_rx_bcast_fr_cnt_t */
	uint64_t	rx_mcast_fr_cnt;	/* vmac_rx_mcast_fr_cnt_t */
} hxge_vmac_stats_t, *p_hxge_vmac_stats_t;


typedef	struct _hxge_vmac {
	boolean_t		is_jumbo;
	uint64_t		tx_config;
	uint64_t		rx_config;
	uint16_t		minframesize;
	uint16_t		maxframesize;
	uint16_t		maxburstsize;
} hxge_vmac_t;


#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_HXGE_HXGE_VMAC_H */
