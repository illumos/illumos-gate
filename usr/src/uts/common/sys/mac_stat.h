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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_MAC_STAT_H
#define	_MAC_STAT_H

#include <sys/mac_flow_impl.h>

#ifdef	__cplusplus
extern "C" {
#endif
#ifdef	__cplusplus
}
#endif

struct mac_soft_ring_set_s;
struct mac_soft_ring_s;

typedef struct mac_rx_stats_s {
	uint64_t	mrs_lclbytes;
	uint64_t	mrs_lclcnt;
	uint64_t	mrs_pollcnt;
	uint64_t	mrs_pollbytes;
	uint64_t	mrs_intrcnt;
	uint64_t	mrs_intrbytes;
	uint64_t	mrs_sdrops;
	uint64_t	mrs_chaincntundr10;
	uint64_t	mrs_chaincnt10to50;
	uint64_t	mrs_chaincntover50;
	uint64_t	mrs_ierrors;
} mac_rx_stats_t;

typedef struct mac_tx_stats_s {
	uint64_t	mts_obytes;
	uint64_t	mts_opackets;
	uint64_t	mts_oerrors;
	/*
	 * Number of times the srs gets blocked due to lack of Tx
	 * desc is noted down. Corresponding wakeup from driver
	 * to unblock is also noted down. They should match in a
	 * correctly working setup. If there is less unblocks
	 * than blocks, then Tx side waits forever for a wakeup
	 * from below. The following protected by srs_lock.
	 */
	uint64_t	mts_blockcnt;	/* times blocked for Tx descs */
	uint64_t	mts_unblockcnt;	/* unblock calls from driver */
	uint64_t	mts_sdrops;
} mac_tx_stats_t;

typedef struct mac_misc_stats_s {
	uint64_t	mms_multircv;
	uint64_t	mms_brdcstrcv;
	uint64_t	mms_multixmt;
	uint64_t	mms_brdcstxmt;
	uint64_t	mms_multircvbytes;
	uint64_t	mms_brdcstrcvbytes;
	uint64_t	mms_multixmtbytes;
	uint64_t	mms_brdcstxmtbytes;
	uint64_t	mms_txerrors; 	/* vid_check, tag needed errors */

	/*
	 * When a ring is taken away from a mac client, before destroying
	 * corresponding SRS (for rx ring) or soft ring (for tx ring), add stats
	 * recorded by that SRS or soft ring to defunct lane stats.
	 */
	mac_rx_stats_t	mms_defunctrxlanestats;
	mac_tx_stats_t	mms_defuncttxlanestats;

	/* link protection stats */
	uint64_t	mms_macspoofed;
	uint64_t	mms_ipspoofed;
	uint64_t	mms_dhcpspoofed;
	uint64_t	mms_restricted;
	uint64_t	mms_dhcpdropped;
} mac_misc_stats_t;

extern void	mac_misc_stat_create(flow_entry_t *);
extern void 	mac_misc_stat_delete(flow_entry_t *);

extern void	mac_ring_stat_create(mac_ring_t *);
extern void	mac_ring_stat_delete(mac_ring_t *);

extern void	mac_srs_stat_create(struct mac_soft_ring_set_s *);
extern void 	mac_srs_stat_delete(struct mac_soft_ring_set_s *);
extern void	mac_tx_srs_stat_recreate(struct mac_soft_ring_set_s *,
		    boolean_t);

extern void	mac_soft_ring_stat_create(struct mac_soft_ring_s *);
extern void	mac_soft_ring_stat_delete(struct mac_soft_ring_s *);

extern void	mac_stat_rename(mac_client_impl_t *);
extern void	mac_pseudo_ring_stat_rename(mac_impl_t *);

extern void	mac_driver_stat_create(mac_impl_t *);
extern void	mac_driver_stat_delete(mac_impl_t *);
extern uint64_t	mac_driver_stat_default(mac_impl_t *, uint_t);

extern uint64_t mac_rx_ring_stat_get(void *, uint_t);
extern uint64_t mac_tx_ring_stat_get(void *, uint_t);

#endif	/* _MAC_STAT_H */
