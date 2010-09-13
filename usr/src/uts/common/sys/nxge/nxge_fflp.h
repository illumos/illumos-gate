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

#ifndef	_SYS_NXGE_NXGE_FFLP_H
#define	_SYS_NXGE_NXGE_FFLP_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <npi_fflp.h>

#define	MAX_PARTITION 8

typedef	struct _fflp_errlog {
	uint32_t		vlan;
	uint32_t		tcam;
	uint32_t		hash_pio[MAX_PARTITION];
	uint32_t		hash_lookup1;
	uint32_t		hash_lookup2;
} fflp_errlog_t, *p_fflp_errlog_t;

typedef struct _fflp_stats {
	uint32_t 		tcam_entries;
	uint32_t 		fcram_entries;
	uint32_t 		tcam_parity_err;
	uint32_t 		tcam_ecc_err;
	uint32_t 		vlan_parity_err;
	uint32_t 		hash_lookup_err;
	uint32_t 		hash_pio_err[MAX_PARTITION];
	fflp_errlog_t		errlog;
} nxge_fflp_stats_t, *p_nxge_fflp_stats_t;

/*
 * The FCRAM (hash table) cosnists of 1 meg cells
 * each 64 byte wide. Each cell can hold either of:
 * 2 IPV4 Exact match entry (each 32 bytes)
 * 1 IPV6 Exact match entry (each 56 bytes) and
 *    1 Optimistic match entry (each 8 bytes)
 * 8 Optimistic match entries (each 8 bytes)
 * In the case IPV4 Exact match, half of the cell
 * (the first or the second 32 bytes) could be used
 * to hold 4 Optimistic matches
 */

#define	FCRAM_CELL_EMPTY	0x00
#define	FCRAM_CELL_IPV4_IPV4	0x01
#define	FCRAM_CELL_IPV4_OPT	0x02
#define	FCRAM_CELL_OPT_IPV4	0x04
#define	FCRAM_CELL_IPV6_OPT	0x08
#define	FCRAM_CELL_OPT_OPT	0x10


#define	FCRAM_SUBAREA0_OCCUPIED	0x01
#define	FCRAM_SUBAREA1_OCCUPIED	0x02
#define	FCRAM_SUBAREA2_OCCUPIED	0x04
#define	FCRAM_SUBAREA3_OCCUPIED	0x08

#define	FCRAM_SUBAREA4_OCCUPIED	0x10
#define	FCRAM_SUBAREA5_OCCUPIED	0x20
#define	FCRAM_SUBAREA6_OCCUPIED	0x40
#define	FCRAM_SUBAREA7_OCCUPIED	0x20

#define	FCRAM_IPV4_SUBAREA0_OCCUPIED \
	(FCRAM_SUBAREA0_OCCUPIED | FCRAM_SUBAREA1_OCCUPIED | \
	FCRAM_SUBAREA2_OCCUPIED | FCRAM_SUBAREA3_OCCUPIED)

#define	FCRAM_IPV4_SUBAREA4_OCCUPIED \
	(FCRAM_SUBAREA4_OCCUPIED | FCRAM_SUBAREA5_OCCUPIED | \
	FCRAM_SUBAREA6_OCCUPIED | FCRAM_SUBAREA7_OCCUPIED)


#define	FCRAM_IPV6_SUBAREA0_OCCUPIED \
	(FCRAM_SUBAREA0_OCCUPIED | FCRAM_SUBAREA1_OCCUPIED | \
	FCRAM_SUBAREA2_OCCUPIED | FCRAM_SUBAREA3_OCCUPIED | \
	FCRAM_SUBAREA4_OCCUPIED | FCRAM_SUBAREA5_OCCUPIED | \
	FCRAM_SUBAREA6_OCCUPIED)

	/*
	 * The current occupancy state of each FCRAM cell isy
	 * described by the fcram_cell_t data structure.
	 * The "type" field denotes the type of entry (or combination)
	 * the cell holds (FCRAM_CELL_EMPTY ...... FCRAM_CELL_OPT_OPT)
	 * The "occupied" field indicates if individual 8 bytes (subareas)
	 * with in the cell are occupied
	 */

typedef struct _fcram_cell {
	uint32_t 		type:8;
	uint32_t 		occupied:8;
	uint32_t 		shadow_loc:16;
} fcram_cell_t, *p_fcram_cell_t;

typedef struct _fcram_parition {
	uint8_t 		id;
	uint8_t 		base;
	uint8_t 		mask;
	uint8_t 		reloc;
	uint32_t 		flags;
#define	HASH_PARTITION_ENABLED 1
	uint32_t 		offset;
	uint32_t 		size;
} fcram_parition_t, *p_fcram_partition_t;


typedef struct _tcam_flow_spec {
	tcam_entry_t tce;
	uint64_t flags;
	uint64_t user_info;
	uint8_t valid;
} tcam_flow_spec_t, *p_tcam_flow_spec_t;


/*
 * Used for configuration.
 * ndd as well nxge.conf use the following definitions
 */

#define	NXGE_CLASS_CONFIG_PARAMS	20
/* Used for ip class flow key and tcam key config */

#define	NXGE_CLASS_TCAM_LOOKUP		0x0001
#define	NXGE_CLASS_TCAM_USE_SRC_ADDR	0x0002
#define	NXGE_CLASS_FLOW_USE_PORTNUM	0x0010
#define	NXGE_CLASS_FLOW_USE_L2DA	0x0020
#define	NXGE_CLASS_FLOW_USE_VLAN	0x0040
#define	NXGE_CLASS_FLOW_USE_PROTO	0x0080
#define	NXGE_CLASS_FLOW_USE_IPSRC	0x0100
#define	NXGE_CLASS_FLOW_USE_IPDST	0x0200
#define	NXGE_CLASS_FLOW_USE_SRC_PORT	0x0400
#define	NXGE_CLASS_FLOW_USE_DST_PORT	0x0800
#define	NXGE_CLASS_DISCARD		0x80000000

/* these are used for quick configs */
#define	NXGE_CLASS_FLOW_WEB_SERVER	NXGE_CLASS_FLOW_USE_IPSRC | \
					NXGE_CLASS_FLOW_USE_SRC_PORT

#define	NXGE_CLASS_FLOW_GEN_SERVER	NXGE_CLASS_FLOW_USE_IPSRC | \
					NXGE_CLASS_FLOW_USE_IPDST | \
					NXGE_CLASS_FLOW_USE_SRC_PORT |	\
					NXGE_CLASS_FLOW_USE_DST_PORT | \
					NXGE_CLASS_FLOW_USE_PROTO | \
					NXGE_CLASS_FLOW_USE_L2DA | \
					NXGE_CLASS_FLOW_USE_VLAN

/*
 * used for use classes
 */


/* Ethernet Classes */
#define	NXGE_CLASS_CFG_ETHER_TYPE_MASK		0x0000FFFF
#define	NXGE_CLASS_CFG_ETHER_ENABLE_MASK	0x40000000

/* IP Classes */
#define	NXGE_CLASS_CFG_IP_TOS_MASK		0x000000FF
#define	NXGE_CLASS_CFG_IP_TOS_SHIFT		0
#define	NXGE_CLASS_CFG_IP_TOS_MASK_MASK		0x0000FF00
#define	NXGE_CLASS_CFG_IP_TOS_MASK_SHIFT	8
#define	NXGE_CLASS_CFG_IP_PROTO_MASK		0x00FFFF00
#define	NXGE_CLASS_CFG_IP_PROTO_SHIFT		16

#define	NXGE_CLASS_CFG_IP_IPV6_MASK		0x01000000
#define	NXGE_CLASS_CFG_IP_PARAM_MASK	NXGE_CLASS_CFG_IP_TOS_MASK | \
					NXGE_CLASS_CFG_IP_TOS_MASK_MASK | \
					NXGE_CLASS_CFG_IP_PROTO_MASK | \
					NXGE_CLASS_CFG_IP_IPV6_MASK

#define	NXGE_CLASS_CFG_IP_ENABLE_MASK		0x40000000

typedef struct _vlan_rdcgrp_map {
	uint32_t		rsrvd:8;
	uint32_t		vid:16;
	uint32_t		rdc_grp:8;
}	vlan_rdcgrp_map_t, *p_vlan_rdcgrp_map_t;

#define	NXGE_INIT_VLAN_RDCG_TBL	32

typedef struct _nxge_classify {
	nxge_os_mutex_t 	tcam_lock;
	nxge_os_mutex_t		fcram_lock;
	nxge_os_mutex_t		hash_lock[MAX_PARTITION];
	uint32_t 		tcam_size;
	uint32_t		tcam_entry_cnt;
	uint32_t 		state;
#define	NXGE_FFLP_HW_RESET	0x1
#define	NXGE_FFLP_HW_INIT	0x2
#define	NXGE_FFLP_SW_INIT	0x4
#define	NXGE_FFLP_FCRAM_PART	0x80000000
	p_nxge_fflp_stats_t	fflp_stats;

	tcam_flow_spec_t    	*tcam_entries;
	uint8_t			tcam_top;
	uint8_t			tcam_location;
	uint64_t		tcam_l2_prog_cls[NXGE_L2_PROG_CLS];
	uint64_t		tcam_l3_prog_cls[NXGE_L3_PROG_CLS];
	uint64_t		tcam_key[12];
	uint64_t		flow_key[12];
	uint16_t		tcam_l3_prog_cls_refcnt[NXGE_L3_PROG_CLS];
	uint8_t			tcam_l3_prog_cls_pid[NXGE_L3_PROG_CLS];
#define	NXGE_FLOW_NO_SUPPORT  0x0
#define	NXGE_FLOW_USE_TCAM    0x1
#define	NXGE_FLOW_USE_FCRAM   0x2
#define	NXGE_FLOW_USE_TCAM_FCRAM   0x3

#define	NXGE_FLOW_COMPUTE_H1   0x10
#define	NXGE_FLOW_COMPUTE_H2   0x20
	uint8_t	fragment_bug;
	uint8_t	fragment_bug_location;
	fcram_cell_t		*hash_table; /* allocated for Neptune only */
	fcram_parition_t    partition[MAX_PARTITION];
} nxge_classify_t, *p_nxge_classify_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_NXGE_NXGE_FFLP_H */
