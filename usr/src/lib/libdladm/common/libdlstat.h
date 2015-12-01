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

#ifndef _LIBDLSTAT_H
#define	_LIBDLSTAT_H

/*
 * This file includes structures, macros and common routines shared by all
 * data-link administration, and routines which are used to retrieve and
 * display statistics.
 */

#include <kstat.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	LINK_REPORT	1
#define	FLOW_REPORT	2

#define	DLSTAT_INVALID_ENTRY	-1
#define	MAXSTATNAMELEN	256
/*
 * Definitions common to all stats
 */
typedef struct dladm_stat_chain_s {
	char				dc_statheader[MAXSTATNAMELEN];
	void				*dc_statentry;
	struct dladm_stat_chain_s	*dc_next;
} dladm_stat_chain_t;

typedef enum {
	DLADM_STAT_RX_LANE = 0,		/* Per lane rx stats */
	DLADM_STAT_TX_LANE,		/* Per lane tx stats */
	DLADM_STAT_RX_LANE_TOTAL,	/* Stats summed across all rx lanes */
	DLADM_STAT_TX_LANE_TOTAL,	/* Stats summed across all tx lanes */
	DLADM_STAT_RX_LANE_FOUT,	/* Per fanout (rx lane) stats */
	DLADM_STAT_RX_RING,		/* Per ring rx stats */
	DLADM_STAT_TX_RING,		/* Per ring tx stats  */
	DLADM_STAT_RX_RING_TOTAL,	/* Stats summed across all rx rings */
	DLADM_STAT_TX_RING_TOTAL,	/* Stats summed across all tx rings */
	DLADM_STAT_TOTAL,		/* Summary view */
	DLADM_STAT_AGGR_PORT,		/* Aggr port stats */
	DLADM_STAT_MISC,		/* Misc stats */
	DLADM_STAT_NUM_STATS		/* This must always be the last entry */
} dladm_stat_type_t;

/*
 * Definitions for rx lane stats
 */
typedef struct rx_lane_stat_s {
	uint64_t	rl_ipackets;
	uint64_t	rl_rbytes;
	uint64_t	rl_lclpackets;
	uint64_t	rl_lclbytes;
	uint64_t	rl_intrs;
	uint64_t	rl_intrbytes;
	uint64_t	rl_pollbytes;
	uint64_t	rl_polls;
	uint64_t	rl_sdrops;
	uint64_t	rl_chl10;
	uint64_t	rl_ch10_50;
	uint64_t	rl_chg50;
} rx_lane_stat_t;

typedef enum {
	L_HWLANE,
	L_SWLANE,
	L_LOCAL,
	L_LCLSWLANE,
	L_BCAST,
	L_DFNCT
} lane_type_t;

typedef struct rx_lane_stat_entry_s {
	int64_t		rle_index;
	lane_type_t	rle_id;
	rx_lane_stat_t	rle_stats;
} rx_lane_stat_entry_t;

/*
 * Definitions for tx lane stats
 */
typedef struct tx_lane_stat_s {
	uint64_t	tl_opackets;
	uint64_t	tl_obytes;
	uint64_t	tl_blockcnt;
	uint64_t	tl_unblockcnt;
	uint64_t	tl_sdrops;
} tx_lane_stat_t;

typedef struct tx_lane_stat_entry_s {
	int64_t		tle_index;
	lane_type_t	tle_id;
	tx_lane_stat_t	tle_stats;
} tx_lane_stat_entry_t;

/*
 * Definitions for tx/rx misc stats
 */
typedef struct misc_stat_s {
	uint64_t	ms_multircv;
	uint64_t	ms_brdcstrcv;
	uint64_t	ms_multixmt;
	uint64_t	ms_brdcstxmt;
	uint64_t	ms_multircvbytes;
	uint64_t	ms_brdcstrcvbytes;
	uint64_t	ms_multixmtbytes;
	uint64_t	ms_brdcstxmtbytes;
	uint64_t	ms_txerrors;
	uint64_t	ms_macspoofed;
	uint64_t	ms_ipspoofed;
	uint64_t	ms_dhcpspoofed;
	uint64_t	ms_restricted;
	uint64_t	ms_dhcpdropped;
	uint64_t	ms_ipackets;
	uint64_t	ms_rbytes;
	uint64_t	ms_local;
	uint64_t	ms_localbytes;
	uint64_t	ms_intrs;
	uint64_t	ms_intrbytes;
	uint64_t	ms_polls;
	uint64_t	ms_pollbytes;
	uint64_t	ms_rxsdrops;
	uint64_t	ms_chainunder10;
	uint64_t	ms_chain10to50;
	uint64_t	ms_chainover50;
	uint64_t	ms_obytes;
	uint64_t	ms_opackets;
	uint64_t	ms_blockcnt;
	uint64_t	ms_unblockcnt;
	uint64_t	ms_txsdrops;
} misc_stat_t;

/*
 * To be consistent with other stat entries, misc stat
 * is wrapped in stat entry
 */
typedef struct misc_stat_entry_s {
	misc_stat_t	mse_stats;
} misc_stat_entry_t;

/*
 * Definitions for ring stats: used by rx as well as tx
 */
typedef struct ring_stat_s {
	uint64_t	r_packets;
	uint64_t	r_bytes;
} ring_stat_t;

typedef struct ring_stat_entry_s {
	int64_t		re_index;
	ring_stat_t	re_stats;
} ring_stat_entry_t;

/*
 * Definitions for fanout stats
 */
typedef struct fanout_stat_s {
	uint64_t	f_ipackets;
	uint64_t	f_rbytes;
} fanout_stat_t;

typedef struct fanout_stat_entry_s {
	int64_t		fe_index;
	lane_type_t	fe_id;		/* hw, sw, local */
	int64_t		fe_foutindex;	/* fanout index */
	fanout_stat_t	fe_stats;
} fanout_stat_entry_t;

/*
 * Definitions for total stats
 */
typedef struct total_stat_s {
	uint64_t	ts_ipackets;
	uint64_t	ts_rbytes;
	uint64_t	ts_opackets;
	uint64_t	ts_obytes;
} total_stat_t;

/*
 * To be consistent with other stat entries, total stat
 * is wrapped in stat entry
 */
typedef struct total_stat_entry_s {
	total_stat_t	tse_stats;
} total_stat_entry_t;

/*
 * Definitions for aggr stats
 */
typedef struct aggr_port_stat_s {
	uint64_t	ap_ipackets;
	uint64_t	ap_rbytes;
	uint64_t	ap_opackets;
	uint64_t	ap_obytes;
} aggr_port_stat_t;

typedef struct aggr_port_stat_entry_s {
	datalink_id_t		ape_portlinkid;
	aggr_port_stat_t	ape_stats;
} aggr_port_stat_entry_t;

/*
 * Definitions for query all stats
 */
typedef struct name_value_stat_s {
	char				nv_statname[MAXSTATNAMELEN];
	uint64_t			nv_statval;
	struct name_value_stat_s	*nv_nextstat;
} name_value_stat_t;

typedef struct name_value_stat_entry_s {
	char			nve_header[MAXSTATNAMELEN];
	name_value_stat_t	*nve_stats;
} name_value_stat_entry_t;

/*
 * Definitions for flow stats
 */
typedef struct flow_stat_s {
	uint64_t	fl_ipackets;
	uint64_t	fl_rbytes;
	uint64_t	fl_ierrors;
	uint64_t	fl_opackets;
	uint64_t	fl_obytes;
	uint64_t	fl_oerrors;
	uint64_t	fl_sdrops;
} flow_stat_t;

typedef struct pktsum_s {
	hrtime_t	snaptime;
	uint64_t	ipackets;
	uint64_t	opackets;
	uint64_t	rbytes;
	uint64_t	obytes;
	uint64_t	ierrors;
	uint64_t	oerrors;
} pktsum_t;

extern kstat_t		*dladm_kstat_lookup(kstat_ctl_t *, const char *, int,
			    const char *, const char *);
extern void		dladm_get_stats(kstat_ctl_t *, kstat_t *, pktsum_t *);
extern int		dladm_kstat_value(kstat_t *, const char *, uint8_t,
			    void *);
extern dladm_status_t	dladm_get_single_mac_stat(dladm_handle_t, datalink_id_t,
			    const char *, uint8_t, void *);

extern void		dladm_stats_total(pktsum_t *, pktsum_t *, pktsum_t *);
extern void		dladm_stats_diff(pktsum_t *, pktsum_t *, pktsum_t *);

extern dladm_stat_chain_t	*dladm_link_stat_query(dladm_handle_t,
				    datalink_id_t, dladm_stat_type_t);
extern dladm_stat_chain_t	*dladm_link_stat_diffchain(dladm_stat_chain_t *,
				    dladm_stat_chain_t *, dladm_stat_type_t);
extern dladm_stat_chain_t	*dladm_link_stat_query_all(dladm_handle_t,
				    datalink_id_t, dladm_stat_type_t);

extern flow_stat_t		*dladm_flow_stat_query(const char *);
extern flow_stat_t		*dladm_flow_stat_diff(flow_stat_t *,
				    flow_stat_t *);
extern name_value_stat_entry_t	*dladm_flow_stat_query_all(const char *);

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBDLSTAT_H */
