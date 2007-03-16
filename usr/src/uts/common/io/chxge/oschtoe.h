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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * This file is part of the Chelsio T1 Ethernet driver.
 *
 * Copyright (C) 2003-2005 Chelsio Communications.  All rights reserved.
 */

#ifndef _CHELSIO_OSCHTOE_H
#define	_CHELSIO_OSCHTOE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _pesge  pesge;

/* looks like this should really be with mc5.h */
#define	DEFAULT_SERVER_REGION_LEN 256
#define	DEFAULT_RT_REGION_LEN 1024

/*
 * Bits used to configure driver behavior.
 */
#define	CFGDMP_RSPQ	0x00000001 /* dump respq info */
#define	CFGDMP_CMDQ0	0x00000010 /* dump cmdq0 info */
#define	CFGDMP_CMDQ0MB	0x00000020 /* dump cmdq0 mbufs */
#define	CFGDMP_CMDQ1	0x00000040 /* dump cmdq1 info */
#define	CFGDMP_CMDQ1MB	0x00000080 /* dump cmdq1 mbufs */
#define	CFGDMP_FLQ0	0x00000100 /* dump flq0 info */
#define	CFGDMP_FLQ0MB	0x00000200 /* dump flq0 mbufs */
#define	CFGDMP_FLQ1	0x00000400 /* dump flq1 info */
#define	CFGDMP_FLQ1MB	0x00000800 /* dump flq1 mbufs */
#define	CFGDMP_ISRC	0x00001000 /* dump ISR 32 bit cause */
#define	CFGDMP_ISR	0x00002000 /* dump ISR info */
#define	CFGDMP_OUT	0x00004000 /* dump OUT info */
#define	CFGDMP_GMACC	0x00010000 /* dump GMAC cause bits */
#define	CFGDMP_PCIXC	0x00020000 /* dump PCIX cause bits */
#define	CFGDMP_TPC	0x00040000 /* dump TP cause bits */
#define	CFGDMP_MC5C	0x00080000 /* dump MC5 cause bits */

#define	CFGMD_RINGB	0x00100000 /* Store all packets in ring buffer */
#define	CFGMD_PROFILE	0x00200000 /* Enable driver profiling */

#define	CFGDMP_ERR	0x01000000 /* dump errors */
#define	CFGDMP_WRN	0x02000000 /* dump warnings */
#define	CFGDMP_STA	0x04000000 /* dump status info */
#define	CFGDMP_PTH	0x08000000 /* dump function paths */

#define	CFGMD_TUNNEL	0x10000000 /* Global tunnel mode ( 0-offload mode ) */
#define	CFGMD_144BIT	0x20000000 /* Puts MC5 in 144 bit mode */
#define	CFGMD_CPLBPF	0x40000000 /* Include CPL header when bpf_map called */

/*
 * Structure used to store drivers configuration information.
 * Some of this information will be move out later or
 * stored elsewhere.  For now, it helps with development.
 */
typedef struct pe_config_data {
	uint32_t gtm;			/* run in Global Tunnel Mode */
	uint32_t global_config;		/* override global debug value */

	uint32_t is_asic;

	/*
	 * 5-auto-neg
	 * 2-1000Gbps(force);
	 * 1-100Gbps(force);
	 * 0-10Gbps(force)
	 */
	uint32_t link_speed;

	uint32_t num_of_ports;		/* Set the number of ports [1-4] */

	uint32_t tp_reset_cm;		/* reset CM memory map */

	uint32_t phy_tx_fifo;		/* phy's tx fifo depth */
	uint32_t phy_rx_fifo;		/* phy's rx fifo depth */
	uint32_t phy_force_master;	/* force link always in master mode */

	uint32_t mc5_rtbl_size;		/* TCAM routing table size */
	uint32_t mc5_dbsvr_size;	/* TCAM server size */
	uint32_t mc5_mode;		/* 72 bit or 144 bit mode */
	uint32_t mc5_parity;		/* Enable parity error checking */
	uint32_t mc5_issue_syn;		/* Allow for transaction overlap */

	uint32_t packet_tracing;

	uint32_t server_region_len;
	uint32_t rt_region_len;

	uint32_t offload_ip_cksum;	/* on/off checksum offloading */
	uint32_t offload_udp_cksum;
	uint32_t offload_tcp_cksum;

	uint32_t sge_cmdq_sp;		/* set sw schedule policy */
	uint32_t sge_cmdq_threshold;	/* used w/ sw schedule policy */
	uint32_t sge_flq_threshold;	/* set SGE's flq threshold register */

	uint32_t sge_cmdq0_cnt;		/* set # entries of cmdq0 */
	uint32_t sge_cmdq1_cnt;		/* set # entries of cmdq1 */
	uint32_t sge_flq0_cnt;		/* set # entries of flq0 */
	uint32_t sge_flq1_cnt;		/* set # entries of flq1 */
	uint32_t sge_respq_cnt;		/* set # entries of respq */


	/*
	 * Update MAC stats automatically.
	 * Sometimes we don't want this to
	 * happen when debugging
	 */
	uint32_t stats;

	/*
	 * Add microsecond delay to packets
	 * sent in Tx direction. This is useful
	 * in testing hardware.
	 */
	uint32_t tx_delay_us;

	/*
	 * Can change chip revision support
	 * settting -1 default. Uses hardware
	 * lookup table.
	 * 0 force T1A
	 * 1 force T1B
	 */
	uint32_t chip;

	/*
	 * Used to only initialize PCI so
	 * read/write registers work. The
	 * driver does not initialize anything
	 * of the HW blocks.
	 */
	uint32_t exit_early;

	/* local ring buffer */
	uint32_t rb_num_of_entries;	/* number of entries */
	uint32_t rb_size_of_entries;	/* bytes size of an entry */
	uint32_t rb_flag;		/* varies flags */

	/* Opt values used to store CATP options.  */
	uint32_t type;
	uint64_t cat_opt0;
	uint64_t cat_opt1;

} pe_config_data_t;

struct pe_port_t {
	uint8_t enaddr[6];
	struct cmac *mac;
	struct cphy *phy;
	struct link_config link_config;
	u32 line_up;
};

#define	DBGASSERT(c) ASSERT(c)

#define	t1_is_T1A(adap) adapter_matches_type(adap, CHBT_TERM_T1, TERM_T1A)
#define	t1_is_T1B(adap) adapter_matches_type(adap, CHBT_TERM_T1, TERM_T1B)
#define	t1_is_T1C(adap) adapter_matches_type(adap, CHBT_TERM_T1, TERM_T1C)

#ifdef __cplusplus
}
#endif

#endif /* _CHELSIO_OSCHTOE_H */
