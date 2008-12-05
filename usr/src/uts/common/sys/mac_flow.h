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

#ifndef	_MAC_FLOW_H
#define	_MAC_FLOW_H

/*
 * Main structure describing a flow of packets, for classification use
 */

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <netinet/in.h>		/* for IPPROTO_* constants */
#include <sys/ethernet.h>

#define	MAXFLOWNAME		32

/* need to use MAXMACADDRLEN from dld.h instead of this one */
#define	MAXMACADDR		20

/* Bit-mask for the selectors carried in the flow descriptor */
typedef	uint64_t		flow_mask_t;

#define	FLOW_LINK_DST		0x00000001	/* Destination MAC addr */
#define	FLOW_LINK_SRC		0x00000002	/* Source MAC address */
#define	FLOW_LINK_VID		0x00000004	/* VLAN ID */
#define	FLOW_LINK_SAP		0x00000008	/* SAP value */

#define	FLOW_IP_VERSION		0x00000010	/* V4 or V6 */
#define	FLOW_IP_PROTOCOL	0x00000020	/* Protocol type */
#define	FLOW_IP_LOCAL		0x00000040	/* Local address */
#define	FLOW_IP_REMOTE		0x00000080	/* Remote address */
#define	FLOW_IP_DSFIELD		0x00000100	/* DSfield value */

#define	FLOW_ULP_PORT_LOCAL	0x00001000	/* ULP local port */
#define	FLOW_ULP_PORT_REMOTE	0x00002000	/* ULP remote port */

#if _LONG_LONG_ALIGNMENT == 8 && _LONG_LONG_ALIGNMENT_32 == 4
#pragma pack(4)
#endif

typedef struct flow_desc_s {
	flow_mask_t			fd_mask;
	uint32_t			fd_mac_len;
	uint8_t				fd_dst_mac[MAXMACADDR];
	uint8_t				fd_src_mac[MAXMACADDR];
	uint16_t			fd_vid;
	uint32_t			fd_sap;
	uint8_t				fd_ipversion;
	uint8_t				fd_protocol;
	in6_addr_t			fd_local_addr;
	in6_addr_t			fd_local_netmask;
	in6_addr_t			fd_remote_addr;
	in6_addr_t			fd_remote_netmask;
	in_port_t			fd_local_port;
	in_port_t			fd_remote_port;
	uint8_t				fd_dsfield;
	uint8_t				fd_dsfield_mask;
} flow_desc_t;

#define	MRP_NCPUS	128

/*
 * In MCM_CPUS mode, cpu bindings is user specified. In MCM_FANOUT mode,
 * user only specifies a fanout count.
 * mc_fanout_cnt gives the number of CPUs used for fanout soft rings.
 * mc_fanout_cpus[] array stores the CPUs used for fanout soft rings.
 */
typedef enum {
	MCM_FANOUT = 1,
	MCM_CPUS
} mac_cpu_mode_t;

typedef struct mac_cpus_props_s {
	uint32_t		mc_ncpus;		/* num of cpus */
	uint32_t		mc_cpus[MRP_NCPUS]; 	/* cpu list */
	uint32_t		mc_fanout_cnt;		/* soft ring cpu cnt */
	uint32_t		mc_fanout_cpus[MRP_NCPUS]; /* SR cpu list */
	uint32_t		mc_pollid;		/* poll thr binding */
	uint32_t		mc_workerid;		/* worker thr binding */
	/*
	 * interrupt cpu: mrp_intr_cpu less than 0 implies platform limitation
	 * in retargetting the interrupt assignment.
	 */
	int32_t			mc_intr_cpu;
	mac_cpu_mode_t		mc_fanout_mode;		/*  fanout mode */
} mac_cpus_t;

/* Priority values */
typedef enum {
	MPL_LOW,
	MPL_MEDIUM,
	MPL_HIGH,
	MPL_RESET
} mac_priority_level_t;

/* The default priority for links */
#define	MPL_LINK_DEFAULT		MPL_HIGH

/* The default priority for flows */
#define	MPL_SUBFLOW_DEFAULT		MPL_MEDIUM

#define	MRP_MAXBW		0x00000001 	/* Limit set */
#define	MRP_CPUS		0x00000002 	/* CPU/fanout set */
#define	MRP_CPUS_USERSPEC	0x00000004 	/* CPU/fanout from user */
#define	MRP_PRIORITY		0x00000008 	/* Priority set */

#define	MRP_THROTTLE		MRP_MAXBW

/* 3 levels - low, medium, high */
#define	MRP_PRIORITY_LEVELS		3

/* Special value denoting no bandwidth control */
#define	MRP_MAXBW_RESETVAL		-1ULL

/*
 * Until sub-megabit limit is implemented,
 * reject values lower than 1 MTU per tick or 1.2Mbps
 */
#define	MRP_MAXBW_MINVAL		1200000

typedef	struct mac_resource_props_s {
	/*
	 * Bit-mask for the network resource control types types
	 */
	uint32_t		mrp_mask;
	uint64_t		mrp_maxbw;	/* bandwidth limit in bps */
	mac_priority_level_t	mrp_priority;	/* relative flow priority */
	mac_cpus_t		mrp_cpus;
} mac_resource_props_t;

#define	mrp_ncpus	mrp_cpus.mc_ncpus
#define	mrp_cpu		mrp_cpus.mc_cpus
#define	mrp_fanout_cnt	mrp_cpus.mc_fanout_cnt
#define	mrp_fanout_cpu	mrp_cpus.mc_fanout_cpus
#define	mrp_pollid	mrp_cpus.mc_pollid
#define	mrp_workerid	mrp_cpus.mc_workerid
#define	mrp_intr_cpu	mrp_cpus.mc_intr_cpu
#define	mrp_fanout_mode	mrp_cpus.mc_fanout_mode

#define	MAC_COPY_CPUS(mrp, fmrp) {					\
	int	ncpus;							\
	(fmrp)->mrp_ncpus = (mrp)->mrp_ncpus;				\
	(fmrp)->mrp_intr_cpu = (mrp)->mrp_intr_cpu;			\
	(fmrp)->mrp_fanout_mode = (mrp)->mrp_fanout_mode;		\
	if ((mrp)->mrp_ncpus == 0) {					\
		(fmrp)->mrp_mask &= ~MRP_CPUS;				\
		(fmrp)->mrp_mask &= ~MRP_CPUS_USERSPEC;			\
	} else {							\
		for (ncpus = 0; ncpus < (fmrp)->mrp_ncpus; ncpus++)	\
			(fmrp)->mrp_cpu[ncpus] = (mrp)->mrp_cpu[ncpus];\
		(fmrp)->mrp_mask |= MRP_CPUS;				\
		if ((mrp)->mrp_mask & MRP_CPUS_USERSPEC)		\
			(fmrp)->mrp_mask |= MRP_CPUS_USERSPEC;		\
	}								\
}

typedef struct flow_stats_s {
	uint64_t	fs_rbytes;
	uint64_t	fs_ipackets;
	uint64_t	fs_ierrors;
	uint64_t	fs_obytes;
	uint64_t	fs_opackets;
	uint64_t	fs_oerrors;
} flow_stats_t;

typedef enum {
	FLOW_STAT_RBYTES,
	FLOW_STAT_IPACKETS,
	FLOW_STAT_IERRORS,
	FLOW_STAT_OBYTES,
	FLOW_STAT_OPACKETS,
	FLOW_STAT_OERRORS
} flow_stat_t;

#if _LONG_LONG_ALIGNMENT == 8 && _LONG_LONG_ALIGNMENT_32 == 4
#pragma pack()
#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _MAC_FLOW_H */
