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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	_SYS_IB_ADAPTERS_HERMON_HW_H
#define	_SYS_IB_ADAPTERS_HERMON_HW_H

/*
 * hermon_hw.h
 *    Contains all the structure definitions and #defines for all Hermon
 *    hardware resources and registers (as defined by the Hermon register
 *    specification).  Wherever possible, the names in the Hermon spec
 *    have been preserved in the structure and field names below.
 */

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#ifdef __cplusplus
extern "C" {
#endif


/*
 * PCI IDs for supported chipsets
 */
#define	PCI_VENID_MLX		0x15b3
#define	PCI_DEVID_HERMON_SDR	0x6340	/* Mellanox MT25208-SDR PCIe Gen1 */
#define	PCI_DEVID_HERMON_DDR	0x634A	/* Mellanox MT25208-DDR PCIe Gen1 */
#define	PCI_DEVID_HERMON_DDRG2	0x6732	/* Mellanox MT25208-DDR PCIe Gen2 */
#define	PCI_DEVID_HERMON_QDRG2	0x673C	/* Mellanox MT25208-QDR PCIe Gen2 */
#define	PCI_DEVID_HERMON_QDRG2V	0x6746	/* Mellanox MT25208-QDR PCIe Gen2 */
#define	PCI_DEVID_HERMON_MAINT	0x0191  /* Maintenance/Mem Controller Mode */

/*
 * Native page size of the adapter
 */
#define	HERMON_PAGESIZE		0x1000	/* 4Kb */
#define	HERMON_PAGEOFFSET	(HERMON_PAGESIZE - 1)
#define	HERMON_PAGEMASK		(~HERMON_PAGEOFFSET)
#define	HERMON_PAGESHIFT	0xC		/* 12  */

/*
 * Offsets into the CMD BAR (BAR 0) for many of the more interesting hardware
 * registers.  These registers include the HCR (more below), and the software
 * reset register (SW_RESET).
 */
#define	HERMON_CMD_HCR_OFFSET		0x80680 /* PRM */
#define	HERMON_CMD_SW_RESET_OFFSET	0xF0010 /* PRM */
#define	HERMON_CMD_SW_SEMAPHORE_OFFSET	0xF03FC /* PRM */
#define	HERMON_CMD_OFFSET_MASK		0xFFFFF /* per MLX instruction */


/*
 * Ownership flags used to define hardware or software ownership for
 * various Hermon resources
 */
#define	HERMON_HW_OWNER			0x1
#define	HERMON_SW_OWNER			0x0

/*
 * Determines whether or not virtual-to-physical address translation is
 * required.  Several of the Hermon hardware structures can be optionally
 * accessed by Hermon without going through the TPT address translation
 * tables.
 */
#define	HERMON_VA2PA_XLAT_ENABLED	0x1
#define	HERMON_VA2PA_XLAT_DISABLED	0x0

/*
 * HCA Command Register (HCR)
 *    The HCR command interface provides privileged access to the HCA in
 *    order to query, configure and modify HCA execution.  It is the
 *    primary mechanism through which mailboxes may be posted to Hermon
 *    firmware.  To use this interface software fills the HCR with pointers
 *    to input and output mailboxes.  Some commands support immediate
 *    parameters, however, and for these commands the HCR will contain the
 *    input or output parameters. Command execution completion can be
 *    detected either by the software polling the HCR or by waiting for a
 *    command completion event.
 */
struct hermon_hw_hcr_s {
	uint32_t	in_param0;
	uint32_t	in_param1;
	uint32_t	input_modifier;
	uint32_t	out_param0;
	uint32_t	out_param1;
	uint32_t	token;
	uint32_t	cmd;
};
#define	HERMON_HCR_TOKEN_MASK		0xFFFF0000
#define	HERMON_HCR_TOKEN_SHIFT		16

#define	HERMON_HCR_CMD_STATUS_MASK	0xFF000000
#define	HERMON_HCR_CMD_GO_MASK		0x00800000
#define	HERMON_HCR_CMD_E_MASK		0x00400000
#define	HERMON_HCR_CMD_T_MASK		0x00200000
#define	HERMON_HCR_CMD_OPMOD_MASK	0x0000F000
#define	HERMON_HCR_CMD_OPCODE_MASK	0x00000FFF
#define	HERMON_HCR_CMD_STATUS_SHFT	24
#define	HERMON_HCR_CMD_GO_SHFT		23
#define	HERMON_HCR_CMD_E_SHFT		22
#define	HERMON_HCR_CMD_T_SHFT		21
#define	HERMON_HCR_CMD_OPMOD_SHFT	12

/*
 * Arbel/tavor "QUERY_DEV_LIM" == Hermon "QUERY_DEV_CAP" - Same hex code
 *    same function as tavor/arbel QUERY_DEV_LIM, just renamed (whatever).
 *    The QUERY_DEV_LIM command returns the device limits and capabilities
 *    supported by the Hermon device.  This command must be run before
 *    running the INIT_HCA command (below) in order to determine the maximum
 *    capabilities of the device and which optional features are supported.
 */
#ifdef  _LITTLE_ENDIAN
struct hermon_hw_querydevlim_s {
	uint32_t	rsrv0[4];

	uint32_t	log_max_scqs 	:4;
	uint32_t			:4;
	uint32_t	num_rsvd_scqs 	:6;
	uint32_t			:2;
	uint32_t	log_max_srq	:5;
	uint32_t			:7;
	uint32_t	log_rsvd_srq	:4;

	uint32_t	log_max_qp	:5;
	uint32_t			:3;
	uint32_t	log_rsvd_qp	:4;
	uint32_t			:4;
	uint32_t	log_max_qp_sz	:8;
	uint32_t	log_max_srq_sz	:8;

	uint32_t	log_max_eq	:4;
	uint32_t			:4;
	uint32_t	num_rsvd_eq	:4;
	uint32_t			:4;
	uint32_t	log_max_dmpt	:6;
	uint32_t			:2;
	uint32_t	log_max_eq_sz	:8;

	uint32_t	log_max_cq	:5;
	uint32_t			:3;
	uint32_t	log_rsvd_cq	:4;
	uint32_t			:4;
	uint32_t	log_max_cq_sz	:8;
	uint32_t			:8;


	uint32_t			:32;

	uint32_t	log_max_mtt	:6;
	uint32_t			:2;
	uint32_t	log_rsvd_dmpt	:4;
	uint32_t			:4;
	uint32_t	log_max_mrw_sz	:7;
	uint32_t			:5;
	uint32_t	log_rsvd_mtt	:4;

	uint32_t	log_max_ra_glob	:6;
	uint32_t			:2;
	uint32_t	log_max_rss_tbl_sz :4;
	uint32_t	rss_toep	:1;	/* rss toeplitz hashing */
	uint32_t	rss_xor		:1;	/* rss xor hashing */
	uint32_t			:2;
	uint32_t	log_max_gso_sz	:5;	/* Lge Send Offload */
	uint32_t			:11;	/* new w/ 0.35, RSS info */

	uint32_t	log_max_ra_res_qp	:6;
	uint32_t			:10;
	uint32_t	log_max_ra_req_qp	:6;
	uint32_t			:10;

	uint32_t	num_ports	:4;
	uint32_t			:12;
	uint32_t	ca_ack_delay	:5;
	uint32_t	cqmep		:3;	/* cq moderation policies */
	uint32_t			:4;
	uint32_t			:1;
	uint32_t			:3;

	uint32_t	mod_wr_srq	:1;	/* resize SRQ supported */
	uint32_t			:31;

	uint32_t			:16;
	uint32_t	stat_rate_sup	:16;

	uint32_t			:8;
	uint32_t			:4;
	uint32_t			:4;
	uint32_t			:8;
	uint32_t	log_max_msg	:5;
	uint32_t			:3;

	uint32_t	rc		:1;	/* 0x44 */
	uint32_t	uc		:1;
	uint32_t	ud		:1;
	uint32_t	xrc		:1;
	uint32_t	rcm		:1;
	uint32_t	fcoib		:1;
	uint32_t	srq		:1;
	uint32_t	ipoib_cksm	:1;
	uint32_t	pkey_v		:1;
	uint32_t	qkey_v		:1;
	uint32_t	vmm		:1;
	uint32_t	fcoe		:1;
	uint32_t	dpdp		:1;	/* dual port diff protocol */
	uint32_t	raw_etype	:1;
	uint32_t	raw_ipv4	:1;
	uint32_t	blh		:1;	/* big LSO header, bit in WQE */
	uint32_t	mem_win		:1;
	uint32_t	apm		:1;
	uint32_t	atomic		:1;
	uint32_t	raw_multi	:1;
	uint32_t	avp		:1;
	uint32_t	ud_multi	:1;
	uint32_t	udm_ipv4	:1;
	uint32_t	dif		:1;	/* DIF supported */
	uint32_t	pg_on_demand	:1;
	uint32_t	router		:1;
	uint32_t	l2mc		:1;	/* lev 2 enet multicast */
	uint32_t			:1;
	uint32_t	ud_swp		:1;	/* sw parse for UD xport */
	uint32_t	ipv6_ex		:1;	/* offload w/ IPV6 ext hdrs */
	uint32_t	lle		:1;	/* low latency enet */
	uint32_t	fcoe_t11	:1;	/* fcoenet T11 frame support */

						/* 0x40 */
	uint32_t	eth_uc_lb	:1;	/* enet unicast loopback */
	uint32_t			:3;
	uint32_t	hdr_split	:1;
	uint32_t	hdr_lookahead	:1;
	uint32_t			:2;
	uint32_t	rss_udp		:1;
	uint32_t			:7;
	uint32_t			:16;

	uint32_t	log_max_bf_page	:6;	/* 0x4c */
	uint32_t			:2;
	uint32_t	log_max_bf_req_ppg :6;
	uint32_t			:2;
	uint32_t	log_bf_reg_sz	:5;
	uint32_t			:10;
	uint32_t	blu_flm		:1;

	uint32_t	log_pg_sz	:8;	/* 0x48 */
	uint32_t			:8;
	uint32_t	log_max_uar_sz	:6;
	uint32_t			:6;
	uint32_t	num_rsvd_uar	:4;

	uint32_t	max_desc_sz_rq	:16;	/* 0x54 */
	uint32_t	max_sg_rq	:8;
	uint32_t			:8;

	uint32_t	max_desc_sz_sq	:16;	/* 0x50 */
	uint32_t	max_sg_sq	:8;
	uint32_t			:8;


	uint32_t	rsvd_fcoib;		/* 0x5C */

	uint32_t			:1;	/* 0x58 */
	uint32_t	fexch_base_mpt	:7;	/* FC exch base mpt num */
	uint32_t	fcp_ud_base_qp	:16;	/* RC UD base qp num */
	uint32_t	fexch_base_qp	:8;	/* FC exch base qp num */


	uint32_t	log_max_xrcd	:5;	/* 0x64 */
	uint32_t			:7;
	uint32_t	num_rsvd_xrcds	:4;
	uint32_t	log_max_pd	:5;
	uint32_t			:7;
	uint32_t	num_rsvd_pd	:4;

	uint32_t	log_max_mcg	:8;	/* 0x60 */
	uint32_t	num_rsvd_mcg	:4;
	uint32_t			:4;
	uint32_t	log_max_qp_mcg	:8;
	uint32_t			:8;

	uint32_t	rsrv2[6];

	uint32_t	altc_entry_sz	:16;	/* 0x84 */
	uint32_t	aux_entry_sz	:16;

	uint32_t	qpc_entry_sz	:16;	/* 0x80 */
	uint32_t	rdmardc_entry_sz :16;

	uint32_t	cmpt_entry_sz	:16;	/* 0x8C */
	uint32_t	srq_entry_sz	:16;

	uint32_t	cqc_entry_sz	:16;	/* 0x88 */
	uint32_t	eqc_entry_sz	:16;

	uint32_t	bmme		:1;	/* 0x94 */
	uint32_t	win_type	:1;
	uint32_t	mps		:1;
	uint32_t	bl		:1;
	uint32_t	zb		:1;
	uint32_t	lif		:1;
	uint32_t	local_inv	:1;
	uint32_t	remote_inv	:1;
	uint32_t			:1;
	uint32_t	win_type2	:1;
	uint32_t	reserved_lkey	:1;
	uint32_t	fast_reg_wr	:1;
	uint32_t			:20;

	uint32_t	dmpt_entry_sz	:16;	/* 0x90 */
	uint32_t	mtt_entry_sz	:16;

	uint32_t			:32;

	uint32_t	rsv_lkey;
						/* 0xA0 */
	uint64_t	max_icm_size;

	uint32_t	rsrv3[22];
};

#else		/* BIG ENDIAN */

struct hermon_hw_querydevlim_s {
	uint32_t	rsrv0[4];

	uint32_t	log_max_srq_sz	:8;
	uint32_t	log_max_qp_sz	:8;
	uint32_t			:4;
	uint32_t	log_rsvd_qp	:4;
	uint32_t			:3;
	uint32_t	log_max_qp	:5;

	uint32_t	log_rsvd_srq	:4;
	uint32_t			:7;
	uint32_t	log_max_srq	:5;
	uint32_t			:2;
	uint32_t	num_rsvd_scqs 	:6;
	uint32_t			:4;
	uint32_t	log_max_scqs 	:4;

	uint32_t			:8;
	uint32_t	log_max_cq_sz	:8;
	uint32_t			:4;
	uint32_t	log_rsvd_cq	:4;
	uint32_t			:3;
	uint32_t	log_max_cq	:5;

	uint32_t	log_max_eq_sz	:8;
	uint32_t			:2;
	uint32_t	log_max_dmpt	:6;
	uint32_t			:4;
	uint32_t	num_rsvd_eq	:4;
	uint32_t			:4;
	uint32_t	log_max_eq	:4;

	uint32_t	log_rsvd_mtt	:4;
	uint32_t			:5;
	uint32_t	log_max_mrw_sz	:7;
	uint32_t			:4;
	uint32_t	log_rsvd_dmpt	:4;
	uint32_t			:2;
	uint32_t	log_max_mtt	:6;

	uint32_t			:32;

	uint32_t			:10;
	uint32_t	log_max_ra_req_qp	:6;
	uint32_t			:10;
	uint32_t	log_max_ra_res_qp	:6;

	uint32_t			:11;	/* new w/ 0.35, RSS info */
	uint32_t	log_max_gso_sz	:5;	/* Lge Send Offload */
	uint32_t			:2;
	uint32_t	rss_xor		:1;	/* rss xor hashing */
	uint32_t	rss_toep	:1;	/* rss toeplitz hashing */
	uint32_t	log_max_rss_tbl_sz :4;
	uint32_t			:2;
	uint32_t	log_max_ra_glob	:6;

	uint32_t			:31;
	uint32_t	mod_wr_srq	:1;	/* resize SRQ supported */

	uint32_t			:3;
	uint32_t			:1;
	uint32_t			:4;
	uint32_t	cqmep		:3;	/* cq moderation policies */
	uint32_t	ca_ack_delay	:5;
	uint32_t			:12;
	uint32_t	num_ports	:4;

	uint32_t			:3;
	uint32_t	log_max_msg	:5;
	uint32_t			:8;
	uint32_t			:4;
	uint32_t			:4;
	uint32_t			:8;

	uint32_t	stat_rate_sup	:16;
	uint32_t			:16;

	uint32_t			:16;	/* 0x40 */
	uint32_t			:7;
	uint32_t	rss_udp		:1;
	uint32_t			:2;
	uint32_t	hdr_lookahead	:1;
	uint32_t	hdr_split	:1;
	uint32_t			:3;
	uint32_t	eth_uc_lb	:1;	/* enet unicast loopback */
						/* 0x44 */
	uint32_t	fcoe_t11	:1;	/* fcoenet T11 frame support */
	uint32_t	lle		:1;	/* low latency enet */
	uint32_t	ipv6_ex		:1;	/* offload w/ IPV6 ext hdrs */
	uint32_t	ud_swp		:1;	/* sw parse for UD xport */
	uint32_t			:1;
	uint32_t	l2mc		:1;	/* lev 2 enet multicast */
	uint32_t	router		:1;
	uint32_t	pg_on_demand	:1;
	uint32_t	dif		:1;	/* DIF supported */
	uint32_t	udm_ipv4	:1;
	uint32_t	ud_multi	:1;
	uint32_t	avp		:1;
	uint32_t	raw_multi	:1;
	uint32_t	atomic		:1;
	uint32_t	apm		:1;
	uint32_t	mem_win		:1;
	uint32_t	blh		:1;	/* big LSO header, bit in WQE */
	uint32_t	raw_ipv4	:1;
	uint32_t	raw_etype	:1;
	uint32_t	dpdp		:1;	/* dual port diff protocol */
	uint32_t	fcoe		:1;
	uint32_t	vmm		:1;
	uint32_t	qkey_v		:1;
	uint32_t	pkey_v		:1;
	uint32_t	ipoib_cksm	:1;
	uint32_t	srq		:1;
	uint32_t	fcoib		:1;
	uint32_t	rcm		:1;
	uint32_t	xrc		:1;
	uint32_t	ud		:1;
	uint32_t	uc		:1;
	uint32_t	rc		:1;

	uint32_t	num_rsvd_uar	:4;	/* 0x48 */
	uint32_t			:6;
	uint32_t	log_max_uar_sz	:6;
	uint32_t			:8;
	uint32_t	log_pg_sz	:8;

	uint32_t	blu_flm		:1;	/* 0x4c */
	uint32_t			:10;
	uint32_t	log_bf_reg_sz	:5;
	uint32_t			:2;
	uint32_t	log_max_bf_req_ppg :6;
	uint32_t			:2;
	uint32_t	log_max_bf_page	:6;

	uint32_t			:8;	/* 0x50 */
	uint32_t	max_sg_sq	:8;
	uint32_t	max_desc_sz_sq	:16;

	uint32_t			:8;	/* 0x54 */
	uint32_t	max_sg_rq	:8;
	uint32_t	max_desc_sz_rq	:16;

						/* 0x58 */
	uint32_t	fexch_base_qp	:8;	/* FC exch base qp num */
	uint32_t	fcp_ud_base_qp	:16;	/* RC UD base qp num */
	uint32_t	fexch_base_mpt	:7;	/* FC exch base mpt num */
	uint32_t			:1;

	uint32_t	rsvd_fcoib;		/* 0x5C */

	uint32_t			:8;	/* 0x60 */
	uint32_t	log_max_qp_mcg	:8;
	uint32_t			:4;
	uint32_t	num_rsvd_mcg	:4;
	uint32_t	log_max_mcg	:8;

	uint32_t	num_rsvd_pd	:4;	/* 0x64 */
	uint32_t			:7;
	uint32_t	log_max_pd	:5;
	uint32_t	num_rsvd_xrcds	:4;
	uint32_t			:7;
	uint32_t	log_max_xrcd	:5;

	uint32_t	rsrv2[6];

	uint32_t	rdmardc_entry_sz :16;	/* 0x80 */
	uint32_t	qpc_entry_sz	:16;

	uint32_t	aux_entry_sz	:16;	/* 0x84 */
	uint32_t	altc_entry_sz	:16;

	uint32_t	eqc_entry_sz	:16;	/* 0x88 */
	uint32_t	cqc_entry_sz	:16;

	uint32_t	srq_entry_sz	:16;	/* 0x8C */
	uint32_t	cmpt_entry_sz	:16;

	uint32_t	mtt_entry_sz	:16;	/* 0x90 */
	uint32_t	dmpt_entry_sz	:16;

	uint32_t			:20;	/* 0x94 */
	uint32_t	fast_reg_wr	:1;
	uint32_t	reserved_lkey	:1;
	uint32_t	win_type2	:1;
	uint32_t			:1;
	uint32_t	remote_inv	:1;
	uint32_t	local_inv	:1;
	uint32_t	lif		:1;
	uint32_t	zb		:1;
	uint32_t	bl		:1;
	uint32_t	mps		:1;
	uint32_t	win_type	:1;
	uint32_t	bmme		:1;

	uint32_t	rsv_lkey;

	uint32_t			:32;

	uint64_t	max_icm_size;
						/* 0xA0 */
	uint32_t	rsrv3[22];
};
#endif



/*
 * Hermon "QUERY_FW" command
 *    The QUERY_FW command retrieves the firmware revision and the Command
 *    Interface revision.  The command also returns the HCA attached local
 *    memory area (DDR) which is used by the firmware.  Below we also
 *    include some defines which are used to enforce a minimum firmware
 *    version check (see hermon_fw_version_check() for more details).
 */

#ifdef	_LITTLE_ENDIAN
struct hermon_hw_queryfw_s {
	uint32_t	fw_rev_minor	:16;
	uint32_t	fw_rev_subminor	:16;

	uint32_t	fw_rev_major	:16;
	uint32_t	fw_pages	:16;

	uint32_t	log_max_cmd	:8;
	uint32_t			:23;
	uint32_t	dbg_trace	:1;

	uint32_t	cmd_intf_rev	:16;
	uint32_t			:16;

	uint32_t	fw_day		:8;
	uint32_t	fw_month	:8;
	uint32_t	fw_year		:16;

	uint32_t			:1;
	uint32_t	ccq		:1;	/* currently not def'd */
	uint32_t			:6;
	uint32_t	fw_sec		:8;
	uint32_t	fw_min		:8;
	uint32_t	fw_hour		:8;

	uint32_t	rsrv0[2];

	uint64_t	clr_intr_offs;

	uint32_t			:32;

	uint32_t			:30;
	uint32_t	clr_int_bar	:2;

	uint64_t	error_buf_addr;

	uint32_t			:30;
	uint32_t	err_buf_bar	:2;

	uint32_t	error_buf_sz;

	uint64_t	vf_com_ch_addr;

	uint32_t			:32;

	uint32_t			:30;
	uint32_t	vf_com_ch_bar	:2;

	uint32_t	rsrv2[44];
};
#else	/* BIG ENDIAN */
struct hermon_hw_queryfw_s {
	uint32_t	fw_pages	:16;
	uint32_t	fw_rev_major	:16;

	uint32_t	fw_rev_subminor	:16;
	uint32_t	fw_rev_minor	:16;

	uint32_t			:16;
	uint32_t	cmd_intf_rev	:16;

	uint32_t	dbg_trace	:1;
	uint32_t			:23;
	uint32_t	log_max_cmd	:8;

	uint32_t	fw_hour		:8;
	uint32_t	fw_min		:8;
	uint32_t	fw_sec		:8;
	uint32_t			:6;
	uint32_t	ccq		:1;	/* currently not def'd */
	uint32_t			:1;

	uint32_t	fw_year		:16;
	uint32_t	fw_month	:8;
	uint32_t	fw_day		:8;

	uint32_t	rsrv1[2];

	uint64_t	clr_intr_offs;

	uint32_t	clr_int_bar	:2;
	uint32_t			:30;

	uint32_t			:32;

	uint64_t	error_buf_addr;

	uint32_t	error_buf_sz;

	uint32_t	err_buf_bar	:2;
	uint32_t			:30;

	uint64_t	vf_com_ch_addr;

	uint32_t	vf_com_ch_bar	:2;
	uint32_t			:30;

	uint32_t			:32;

	uint32_t	rsrv2[44];
};
#endif

/*
 * 2.6.000 is critical for some performance features, e.g., Reserved_Lkey,
 * and 2.7.000 is needed for FRWR and FCoIB.  Requiring 2.6.000 now so that
 * existing customers get the performance, but are not required to upgrade
 * to the latest.  Less than 2.6.000 will cause the driver to attach in
 * maintenance mode, and throw an FMA event about upgrading the firmware.
 */

#define	HERMON_FW_VER_MAJOR		0x0002
#define	HERMON_FW_VER_MINOR		0x0006
#define	HERMON_FW_VER_SUBMINOR		0x0000

/*
 * Hermon "QUERY_ADAPTER" command
 *    The QUERY_ADAPTER command retrieves adapter specific parameters. The
 *    command also retrieves the PCI(X) interrupt pin routing for each of
 *    the INTx# pins supported by the device.  This information is used by
 *    the driver during interrupt processing in order to clear the appropriate
 *    interrupt bit.
 */
#ifdef	_LITTLE_ENDIAN
struct hermon_hw_queryadapter_s {
	uint32_t	rsrv0[4];

	uint32_t			:32;

	uint32_t			:24;
	uint32_t	inta_pin	:8;

	uint32_t	vsd_vend_id	:16;		/* added v35 hermon */
	uint32_t			:16;

	uint32_t			:32;

	uint32_t	vsd[52];
	uint32_t	psid[4];
};
#else
struct hermon_hw_queryadapter_s {
	uint32_t	rsrv0[4];

	uint32_t	inta_pin	:8;
	uint32_t			:24;

	uint32_t			:32;

	uint32_t			:32;

	uint32_t			:16;
	uint32_t	vsd_vend_id	:16;		/* added v35 hermon */

	uint32_t	vsd[52];
	uint32_t	psid[4];
};
#endif
#define	HERMON_REV_A0	0xA0
#define	HERMON_REV_A1	0xA1

/*
 * Virtual physical mapping structure for: MAP_FA, MAP_ICM_AUX, and
 * MAP_ICM commands.
 */

#ifdef	_LITTLE_ENDIAN
struct hermon_hw_vpm_s {
	uint32_t			:12;
	uint32_t	vaddr_l		:20;

	uint32_t	vaddr_h;

	uint32_t	log2sz		:5;	/* in 4KB pages */
	uint32_t			:7;
	uint32_t	paddr_l		:20;

	uint32_t	paddr_h;
};
#else
struct hermon_hw_vpm_s {
	uint32_t	vaddr_h;

	uint32_t	vaddr_l		:20;
	uint32_t			:12;

	uint32_t	paddr_h;

	uint32_t	paddr_l		:20;
	uint32_t			:7;
	uint32_t	log2sz		:5;	/* in 4KB pages */
};
#endif




/*
 * Hermon "INIT_HCA" and "QUERY_HCA" commands
 *    The INIT_HCA command configures all HCA resources in HCA attached local
 *    memory and some system relevant information.  The same mailbox output
 *    format is used by the QUERY_HCA command.  All parameters, which are
 *    specifically the output of the QUERY_HCA command are marked as
 *    "QUERY_HCA only".  These parameters are not configurable through the
 *    INIT_HCA command, but can be retrieved as read-only through the
 *    QUERY_HCA command.
 *
 *    Below we first define several structures which help make up the whole
 *    of the INIT_HCA/QUERY_HCA command.  These are:
 *    hermon_hw_qp_ee_cq_eq_rdb_t for "QPC/EEC/CQC/EQC/RDB Parameters",
 *    hermon_udav_mem_param_t for "Memory Access Parameters for UDAV Table",
 *    hermon_multicast_param_t for "Multicast Support Parameters",
 *    hermon_tpt_param_t for "Translation and Protection Table Parameters",
 *    and hermon_uar_param_t for Hermon "UAR Parameters".
 */

/*
 *  need to consider removing any ref to "ee", hermon doesn't support
 *       ee/rd stuff, and they've taken away the pretense
 */


#ifdef	_LITTLE_ENDIAN
typedef struct hermon_hw_qp_ee_cq_eq_rdb_s {
	uint32_t	rsrv0[4];

	uint32_t	log_num_qp	:5;
	uint32_t	qpc_baseaddr_l	:27;
	uint32_t	qpc_baseaddr_h;

	uint32_t	rsrv1[4];

	uint32_t	log_num_srq	:5;
	uint32_t	srqc_baseaddr_l	:27;
	uint32_t	srqc_baseaddr_h;

	uint32_t	log_num_cq	:5;
	uint32_t	cqc_baseaddr_l	:27;
	uint32_t	cqc_baseaddr_h;

	uint32_t	rsrv2[2];

	uint64_t	altc_baseaddr;

	uint32_t	rsrv3[2];

	uint64_t	auxc_baseaddr;

	uint32_t	rsrv4[2];

	uint32_t	log_num_eq	:5;
	uint32_t	eqc_baseaddr_l	:27;
	uint32_t	eqc_baseaddr_h;

	uint32_t	rsv5[2];

	uint32_t	log_num_rdmardc	:3;
	uint32_t			:2;
	uint32_t	rdmardc_baseaddr_l :27;
	uint32_t	rdmardc_baseaddr_h;

	uint32_t	rsrv6[2];
} hermon_hw_qp_ee_cq_eq_rdb_t;
#else	/* BIG ENDIAN */
typedef struct hermon_hw_qp_ee_cq_eq_rdb_s {
	uint32_t	rsrv0[4];

	uint32_t	qpc_baseaddr_h;
	uint32_t	qpc_baseaddr_l	:27;
	uint32_t	log_num_qp	:5;

	uint32_t	rsrv1[4];

	uint32_t	srqc_baseaddr_h;
	uint32_t	srqc_baseaddr_l	:27;
	uint32_t	log_num_srq	:5;

	uint32_t	cqc_baseaddr_h;
	uint32_t	cqc_baseaddr_l	:27;
	uint32_t	log_num_cq	:5;

	uint32_t	rsrv2[2];

	uint64_t	altc_baseaddr;

	uint32_t	rsrv3[2];

	uint64_t	auxc_baseaddr;

	uint32_t	rsrv4[2];

	uint32_t	eqc_baseaddr_h;
	uint32_t	eqc_baseaddr_l	:27;
	uint32_t	log_num_eq	:5;

	uint32_t	rsv5[2];

	uint32_t	rdmardc_baseaddr_h;
	uint32_t	rdmardc_baseaddr_l :27;
	uint32_t			:2;
	uint32_t	log_num_rdmardc	:3;

	uint32_t	rsrv6[2];
} hermon_hw_qp_ee_cq_eq_rdb_t;
#endif




#ifdef	_LITTLE_ENDIAN
typedef struct hermon_multicast_param_s {
	uint64_t	mc_baseaddr;

	uint32_t	rsrv0[2];

	uint32_t	log_mc_tbl_hash_sz :5;
	uint32_t			:27;

	uint32_t	log_mc_tbl_ent	:5;
	uint32_t			:27;

	uint32_t			:32;

	uint32_t	log_mc_tbl_sz	:5;
	uint32_t			:19;
	uint32_t	mc_hash_fn	:3;
	uint32_t			:5;
} hermon_multicast_param_t;
#else	/* BIG ENDIAN */
typedef struct hermon_multicast_param_s {
	uint64_t	mc_baseaddr;

	uint32_t	rsrv0[2];

	uint32_t			:27;
	uint32_t	log_mc_tbl_ent	:5;

	uint32_t			:27;
	uint32_t	log_mc_tbl_hash_sz :5;

	uint32_t			:5;
	uint32_t	mc_hash_fn	:3;
	uint32_t			:19;
	uint32_t	log_mc_tbl_sz	:5;

	uint32_t			:32;
} hermon_multicast_param_t;
#endif

#define	HERMON_MCG_DEFAULT_HASH_FN	0x0

#ifdef	_LITTLE_ENDIAN
typedef struct hermon_tpt_param_s {
	uint64_t	dmpt_baseaddr;

	uint32_t			:32;

	uint32_t	log_dmpt_sz	:6;
	uint32_t			:2;
	uint32_t	pgfault_rnr_to	:5;
	uint32_t			:19;

	uint64_t	mtt_baseaddr;

	uint64_t	cmpt_baseaddr;
} hermon_tpt_param_t;
#else	/* BIG ENDIAN */
typedef struct hermon_tpt_param_s {
	uint64_t	dmpt_baseaddr;

	uint32_t			:19;
	uint32_t	pgfault_rnr_to	:5;
	uint32_t			:2;
	uint32_t	log_dmpt_sz	:6;

	uint32_t			:32;

	uint64_t	mtt_baseaddr;

	uint64_t	cmpt_baseaddr;
} hermon_tpt_param_t;
#endif


#ifdef	_LITTLE_ENDIAN
typedef struct hermon_uar_param_s {
	uint32_t	rsvd0[2];

	uint32_t			:32;

	uint32_t	uar_pg_sz	:8;
	uint32_t	log_max_uars	:4;
	uint32_t			:20;

	uint32_t	resvd1[4];
} hermon_uar_param_t;
#else
typedef struct hermon_uar_param_s {
	uint32_t	rsvd0[2];

	uint32_t			:20;
	uint32_t	log_max_uars	:4;
	uint32_t	uar_pg_sz	:8;

	uint32_t			:32;

	uint32_t	resvd1[4];
} hermon_uar_param_t;
#endif

/*
 * NEW for Hermon
 *   QP Allocation Params
 *	NOTE:  	as of PRM v0.50 no longer needed (ccq not supported
 *		leave structure here, just in case ccq comes back )
 *		but adjust the overall structure
 *		not to use it
 *
 */

#ifdef _LITTLE_ENDIAN
typedef struct hermon_qp_alloc_param_s {
	uint32_t			:32;

	uint32_t	ccq_base	:24;
	uint32_t	log2ccqs	:5;
	uint32_t			:2;
	uint32_t	ccq_en	:1;

	uint32_t	rsvd[6];	/* but 0x14 def'd for fibre channel */
} hermon_qp_alloc_param_t;
#else /* BIG ENDIAN */
typedef struct hermon_qp_alloc_param_s {
	uint32_t	ccq_en		:1;
	uint32_t			:2;
	uint32_t	log2ccqs	:5;
	uint32_t	ccq_base	:24;

	uint32_t			:32;

	uint32_t	rsvd[6];	/* but 0x14 def'd for fibre channel */
} hermon_qp_alloc_param_t;
#endif


#ifdef	_LITTLE_ENDIAN
struct hermon_hw_initqueryhca_s {
	uint32_t			:32;

	uint32_t			:24;
	uint32_t	version		:8;

	uint32_t			:13;
	uint32_t	log2_cacheline  :3;
	uint32_t	hca_core_clock	:16;	/* QUERY_HCA only */

	uint32_t			:32;

	uint32_t	udav_port_chk	:1;
	uint32_t	big_endian	:1;
	uint32_t	qos		:1;
	uint32_t	chsum_en	:1;
	uint32_t			:12;
	uint32_t	cqpm_short_pkt_lim :14; /* short pkt limit for qpm */
	uint32_t	cqmp		:2;	/* cq moderation policy */

	uint32_t	router_qp	:24;
	uint32_t			:5;
	uint32_t	ipr2		:1;
	uint32_t	ipr1		:1;
	uint32_t	router_en	:1;

	uint32_t	rsrv1[2];

	hermon_hw_qp_ee_cq_eq_rdb_t	context;

	uint32_t	rsrv2[8];

	hermon_multicast_param_t	multi;

	uint32_t	rsrv3[4];

	hermon_tpt_param_t		tpt;

	uint32_t	rsrv4[4];

	hermon_uar_param_t		uar;

	uint32_t	rsrv5[36];

	hermon_multicast_param_t	enet_multi;

	uint32_t	rsrv6[24];		/* to 0x24C */

	uint32_t			:32;

	uint32_t	fcoe_t11	:1;	/* fcoe t11 frame enable */
	uint32_t			:31;

	uint32_t	rsrv7[42];		/* 0x254 - 0x2FC */
};
#else	/* BIG ENDIAN */
struct hermon_hw_initqueryhca_s {
	uint32_t	version		:8;
	uint32_t			:24;

	uint32_t			:32;

	uint32_t			:32;

	uint32_t	hca_core_clock	:16;	/* QUERY_HCA only */
	uint32_t	log2_cacheline	:3;
	uint32_t			:13;

	uint32_t	router_en	:1;
	uint32_t	ipr1		:1;
	uint32_t	ipr2		:1;
	uint32_t			:5;
	uint32_t	router_qp	:24;

	uint32_t	cqmp		:2;	/* cq moderation policy */
	uint32_t	cqpm_short_pkt_lim :14; /* short pkt limit for qpm */
	uint32_t			:12;
	uint32_t	chsum_en	:1;
	uint32_t	qos		:1;
	uint32_t	big_endian	:1;
	uint32_t	udav_port_chk	:1;

	uint32_t	rsrv1[2];

	hermon_hw_qp_ee_cq_eq_rdb_t	context;

	uint32_t	rsrv2[8];

	hermon_multicast_param_t	multi;

	uint32_t	rsrv3[4];

	hermon_tpt_param_t		tpt;

	uint32_t	rsrv4[4];

	hermon_uar_param_t		uar;

	uint32_t	rsrv5[36];

	hermon_multicast_param_t	enet_multi;

	uint32_t	rsrv6[24];		/* to 0x24C */

	uint32_t			:31;
	uint32_t	fcoe_t11	:1;	/* fcoe t11 frame enable */

	uint32_t			:32;

	uint32_t	rsrv7[42];		/* 0x254 - 0x2FC */
};
#endif
#define	HERMON_UDAV_PROTECT_DISABLED	0x0
#define	HERMON_UDAV_PROTECT_ENABLED	0x1
#define	HERMON_UDAV_PORTCHK_DISABLED	0x0
#define	HERMON_UDAV_PORTCHK_ENABLED	0x1


/*
 * Hermon "INIT_IB"/"INIT_PORT" command
 *    The INIT_IB/INIT_PORT command enables the physical layer of an IB port.
 *    It provides control over the IB port attributes.  The capabilities
 *    requested here should not exceed the device limits, as retrieved by
 *    the QUERY_DEV_LIM/CAP command (above).  To query information about the IB
 *    port or node, the driver may submit GetPortInfo or GetNodeInfo MADs
 *    through the Hermon MAD_IFC command.
 *
 *	Changed name to initport, but operates similar to initib - but as of
 *	PRM v0.35c the initport just does that, and the params set previously
 *	by initib are now set in SET_PORT
 */




/*
 * HERMON query_port and set_port commands.  QUERY_PORT is new for hermon,
 *	doing some of what used to be done in the QUERY_DEV_CAP command.  It is
 *	introduced in PRM v0.35 and will need to be added to the list of
 *	supported HCA commands
 *
 *	SET_PORT is similar to the SET_IB command from tavor and arbel.  Here,
 *	tho, it's more extensive and will be easier to deal with I suspect by
 * 	making it a structure and filling it in and then doing the copy to the
 *	mailbox (instead of just writing the minimal information to the mailbox
 *	directly as was done for the previous HCAs).
 */

/*
 * 	PRM 0.4X and 0.50 changed the query_port to integrate the ethernet
 *	stuff as well, so this is a signficant change to the structure
 */

#ifdef _LITTLE_ENDIAN
struct hermon_hw_query_port_s {
						/* 0x04 */
	uint32_t	log_max_pkey 	:4;	/* pkey table size */
	uint32_t	log_max_gid	:4;	/* max gids / port */
	uint32_t	ib_port_wid	:8;
	/*
	 * Enet link speed - 0x0 10Gb XAUI, 0x01 10Gb XFI,
	 *	0x02 1Gb, 0xF other
	 */
	uint32_t	eth_link_spd	:4;
	uint32_t			:4;
	/*
	 * IB Link speed - bit 0 SDR, bit1 DDR, Bit 2 QDR
	 */
	uint32_t	ib_link_spd	:8;

						/* 0x00 */
	uint32_t	eth_mtu		:16;	/* in bytes */
	/*
	 * IB MTU - 0x0 rsvd, 0x1=256, 0x2=512, 0x3=1024, 0x4=2048, 0x5=4096
	 */
	uint32_t	ib_mtu		:4;
	uint32_t			:4;
	/*
	 * for next two if link down
	 * -> what port supports, if up
	 * -> what port is running
	 */

	uint32_t	ib_link		:1;
	uint32_t	eth_link	:1;
	uint32_t			:1;
	uint32_t	vpi		:1;
	uint32_t			:3;
	uint32_t	link_up		:1;


	uint32_t			:32;	/* 0x0C */

	/* max vl's supported (not incl vl_15) */
	uint32_t	max_vl		:4;	/* 0x08 */
	uint32_t			:4;
	uint32_t	log_max_mac	:4;
	uint32_t	log_max_vlan	:4;
	uint32_t			:16;

	uint32_t	mac_lo;

	uint32_t	mac_hi		:16;
	uint32_t			:16;

	uint32_t	rsvd1[2];
};

#else /* BIG ENDIAN */
struct hermon_hw_query_port_s {
						/* 0x00 */
	uint32_t	link_up		:1;
	uint32_t			:3;
	uint32_t	vpi		:1;
	uint32_t			:1;
	/*
	 * for next two if link down
	 * -> what port supports, if up
	 * -> what port is running
	 */
	uint32_t	eth_link	:1;
	uint32_t	ib_link		:1;
	uint32_t			:4;
	/*
	 * IB MTU - 0x0 rsvd, 0x1=256, 0x2=512, 0x3=1024, 0x4=2048, 0x5=4096
	 */
	uint32_t	ib_mtu		:4;
	uint32_t	eth_mtu		:16;	/* in bytes */

						/* 0x04 */
	/*
	 * IB Link speed - bit 0 SDR, bit1 DDR, Bit 2 QDR
	 */
	uint32_t	ib_link_spd	:8;
	uint32_t			:4;
	/*
	 * Enet link speed - 0x0 10Gb XAUI, 0x01 10Gb XFI,
	 *	0x02 1Gb, 0xF other
	 */
	uint32_t	eth_link_spd	:4;
	uint32_t	ib_port_wid	:8;
	uint32_t	log_max_gid	:4;	/* max gids / port */
	uint32_t	log_max_pkey 	:4;	/* pkey table size */

	uint32_t			:16;	/* 0x08 */
	uint32_t	log_max_vlan	:4;
	uint32_t	log_max_mac	:4;
	uint32_t			:4;
	/* max vl's supported (not incl vl_15) */
	uint32_t	max_vl		:4;

	uint32_t			:32;	/* 0x0C */

	uint32_t			:16;
	uint32_t	mac_hi		:16;

	uint32_t	mac_lo;

	uint32_t	rsvd1[2];

};
#endif

/*
 * the following structure is used for IB set port
 *	others following are for ethernet set port
 */

#define	HERMON_HW_OPMOD_SETPORT_IB	0x0
#define	HERMON_HW_OPMOD_SETPORT_EN	0x1
#define	HERMON_HW_OPMOD_SETPORT_EXT	0x2


#ifdef _LITTLE_ENDIAN
struct hermon_hw_set_port_s {
	uint32_t	cap_mask;

	uint32_t	rqk		:1;	/* reset qkey violation cntr */
	uint32_t	rcm		:1;	/* reset capability mask */
	uint32_t			:2;
	uint32_t	vl_cap		:4;
	uint32_t			:4;
	uint32_t	mtu_cap		:4;
	uint32_t	g0		:1;	/* set port GUID0 */
	uint32_t	ng		:1;	/* set node GUID (all ports) */
	uint32_t	sig		:1;	/* set sys image */
	uint32_t	mg		:1;	/* change GID table */
	uint32_t	mp		:1;	/* change pkey table size */
	uint32_t	mvc		:1;	/* change vl_cap */
	uint32_t	mmc		:1;	/* change mtu_cap */
	uint32_t			:9;

	uint64_t	sys_img_guid;

	uint64_t	guid0;

	uint64_t	node_guid;

	uint32_t	ingress_sniff_qpn  :24;
	uint32_t	ingress_sniff_mode :1;
	uint32_t			   :7;

	uint32_t	egress_sniff_qpn  :24;
	uint32_t	egress_sniff_mode :1;
	uint32_t			  :7;

	uint32_t			:32;

	uint32_t	max_gid		:16;	/* valid if noted above */
	uint32_t	max_pkey	:16;	/* valid if noted above */

	uint32_t	rsrd0[500];
};
#else	/* BIG ENDIAN */
struct hermon_hw_set_port_s {
	uint32_t			:9;
	uint32_t	mmc		:1;	/* change mtu_cap */
	uint32_t	mvc		:1;	/* change vl_cap */
	uint32_t	mp		:1;	/* change pkey table size */
	uint32_t	mg		:1;	/* change GID table size */
	uint32_t	sig		:1;	/* set sys image GUID */
	uint32_t	ng		:1;	/* set node GUID (all ports) */
	uint32_t	g0		:1;	/* set port GUID0 */
	uint32_t	mtu_cap		:4;
	uint32_t			:4;
	uint32_t	vl_cap		:4;
	uint32_t			:2;
	uint32_t	rcm		:1;	/* reset capability mask */
	uint32_t	rqk		:1;	/* reset qkey violation cntr */

	uint32_t	cap_mask;

	uint64_t	sys_img_guid;

	uint64_t	guid0;

	uint64_t	node_guid;

	uint32_t			  :7;
	uint32_t	egress_sniff_mode :1;
	uint32_t	egress_sniff_qpn   :24;

	uint32_t			   :7;
	uint32_t	ingress_sniff_mode :1;
	uint32_t	ingress_sniff_qpn  :24;


	uint32_t	max_pkey	:16;	/* valid if noted above */
	uint32_t	max_gid		:16;	/* valid if noted above */

	uint32_t			:32;

	uint32_t	rsrd0[500];
};
#endif

/*
 * structures  for ethernet setport
 * Which structure is used depends on low-16 of opmod
 * Low 8 == port number, 15:8 == selector
 * Or the following with port number
 */

#define	HERMON_HW_ENET_OPMOD_SELECT_GEN	0x0000		/* general params */
#define	HERMON_HW_ENET_OPMOD_SELECT_RQN 0x0100		/* rcv qpn calc */
#define	HERMON_HW_ENET_OPMOD_SELECT_MAC 0x0200		/* MAC table conf */
#define	HERMON_HW_ENET_OPMOD_SELECT_VLAN 0x0300		/* VLAN table conf */
#define	HERMON_HW_ENET_OPMOD_SELECT_PRIO 0x0400		/* Priority table */
#define	HERMON_HW_ENET_OPMOD_SELECT_GID	 0x0500		/* GID Table */

/*
 * set port for enthernet, general parameters
 * Which structure
 */

#ifdef _LITTLE_ENDIAN
struct hermon_hw_set_port_en_s {
	uint32_t	mtu		:16;
	uint32_t			:16;

	uint32_t	v_mtu		:1;
	uint32_t	v_pprx		:1;
	uint32_t	v_pptx		:1;
	uint32_t			:29;

	uint32_t			:16;
	uint32_t	pfcrx		:8;
	uint32_t			:7;
	uint32_t	pprx		:1;

	uint32_t			:16;
	uint32_t	pfctx		:8;
	uint32_t			:7;
	uint32_t	pptx		:1;

	uint32_t	rsvd0[4];
};

#else /* BIG ENDIAN */
struct hermon_hw_set_port_en_s {
	uint32_t			:29;
	uint32_t	v_pptx		:1;
	uint32_t	v_pprx		:1;
	uint32_t	v_mtu		:1;

	uint32_t			:16;
	uint32_t	mtu		:16;

	uint32_t	pptx		:1;
	uint32_t			:7;
	uint32_t	pfctx		:8;
	uint32_t			:16;

	uint32_t	pprx		:1;
	uint32_t			:7;
	uint32_t	pfcrx		:8;
	uint32_t			:16;

	uint32_t	rsvd0[4];

};
#endif

/* set_port for enet, RX QPM calculations Parameters */

#ifdef _LITTLE_ENDIAN
struct hermon_hw_set_port_en_rqpn_s {
	uint32_t	n_p		:2;
	uint32_t			:6;
	uint32_t	n_v		:3;
	uint32_t			:5;
	uint32_t	n_m		:4;
	uint32_t			:12;

	uint32_t	base_qpn	:24;
	uint32_t			:8;

	uint32_t	vlan_miss_idx	:7;
	uint32_t			:8;
	uint32_t	intra_vlan_miss	:1;
	uint32_t	no_vlan_idx	:7;
	uint32_t			:8;
	uint32_t	intra_no_vlan	:1;

	uint32_t	mac_miss_idx	:8;
	uint32_t			:24;

	uint32_t	promisc_qpn	:24;
	uint32_t			:7;
	uint32_t	en_uc_promisc	:1;

	uint32_t	no_vlan_prio	:3;
	uint32_t			:29;

	uint32_t			:32;

	uint32_t	def_mcast_qpn	:24;
	uint32_t			:5;
	uint32_t	mc_by_vlan	:1;
	uint32_t	mc_promisc_mode :2;

	uint32_t	rsvd0[4];
};

#else /* BIG ENDIAN */
struct hermon_hw_set_port_en_rqpn_s {
	uint32_t			:8;
	uint32_t	base_qpn	:24;

	uint32_t			:12;
	uint32_t	n_m		:4;
	uint32_t			:5;
	uint32_t	n_v		:3;
	uint32_t			:6;
	uint32_t	n_p		:2;

	uint32_t			:24;
	uint32_t	mac_miss_idx	:8;

	uint32_t	intra_no_vlan	:1;
	uint32_t			:8;
	uint32_t	no_vlan_idx	:7;
	uint32_t	intra_vlan_miss	:1;
	uint32_t			:8;
	uint32_t	vlan_miss_idx	:7;

	uint32_t			:29;
	uint32_t	no_vlan_prio	:3;

	uint32_t	en_uc_promisc	:1;
	uint32_t			:7;
	uint32_t	promisc_qpn	:24;

	uint32_t	mc_promisc_mode :2;
	uint32_t	mc_by_vlan	:1;
	uint32_t			:5;
	uint32_t	def_mcast_qpn	:24;

	uint32_t			:32;

	uint32_t	rsvd0[4];
};
#endif


#ifdef _LITTLE_ENDIAN
struct hermon_hw_set_port_mact_entry_s {
	uint32_t	mac_lo		:32;

	uint32_t	mac_hi		:16;
	uint32_t			:7;
	uint32_t	mac_valid	:1;
};
#else /* BIG ENDIAN */
struct hermon_hw_set_port_mact_entry_s {
	uint32_t	mac_valid	:1;
	uint32_t			:7;
	uint32_t	mac_hi		:16;

	uint32_t	mac_lo		:32;

};
#endif


/* set_port for enet, MAC Table Configuration */

#ifdef _LITTLE_ENDIAN
struct hermon_hw_set_port_en_mact_s {
	struct hermon_hw_set_port_mact_entry_s mtable[128];
};
#else /* BIG ENDIAN */
struct hermon_hw_set_port_en_mact_s {
	struct hermon_hw_set_port_mact_entry_s mtable[128];
};
#endif


/* set_port for enet, VLAN Table Configuration */

#ifdef _LITTLE_ENDIAN
struct hermon_hw_set_port_vlant_entry_s {
	uint32_t	vlan_id		:12;
	uint32_t			:18;
	uint32_t	intra		:1;
	uint32_t	valid		:1;
};
#else /* BIG ENDIAN */
struct hermon_hw_set_port_vlant_entry_s {
	uint32_t	valid		:1;
	uint32_t	intra		:1;
	uint32_t			:18;
	uint32_t	vlan_id		:12;
};
#endif

#ifdef _LITTLE_ENDIAN
struct hermon_hw_set_port_en_vlant_s {
	uint32_t	rsvd[2];
	struct hermon_hw_set_port_vlant_entry_s table[126];
};
#else /* BIG ENDIAN */
struct hermon_hw_set_port_en_vlant_s {
	uint32_t	rsvd[2];
	struct hermon_hw_set_port_vlant_entry_s table[126];
};
#endif

/* set_port for enet, Priority table Parameters */

#ifdef _LITTLE_ENDIAN
struct hermon_hw_set_port_en_priot_s {
	uint32_t			:32;

	uint32_t	prio0		:3;
	uint32_t			:1;
	uint32_t	prio1		:3;
	uint32_t			:1;
	uint32_t	prio2		:3;
	uint32_t			:1;
	uint32_t	prio3		:3;
	uint32_t			:1;
	uint32_t	prio4		:3;
	uint32_t			:1;
	uint32_t	prio5		:3;
	uint32_t			:1;
	uint32_t	prio6		:3;
	uint32_t			:1;
	uint32_t	prio7		:3;
	uint32_t			:1;

	uint32_t	rsvd[2];
};
#else /* BIG ENDIAN */
struct hermon_hw_set_port_en_priot_s {
	uint32_t			:1;
	uint32_t	prio7		:3;
	uint32_t			:1;
	uint32_t	prio6		:3;
	uint32_t			:1;
	uint32_t	prio5		:3;
	uint32_t			:1;
	uint32_t	prio4		:3;
	uint32_t			:1;
	uint32_t	prio3		:3;
	uint32_t			:1;
	uint32_t	prio2		:3;
	uint32_t			:1;
	uint32_t	prio1		:3;
	uint32_t			:1;
	uint32_t	prio0		:3;

	uint32_t			:32;

	uint32_t	rsvd[2];

};
#endif


/* note:  GID table is same BIG or LITTLE ENDIAN */

struct hermon_hw_set_port_gidtable_s {
	uint64_t	gid[128];
};

#ifdef _LITTLE_ENDIAN
struct hermon_hw_conf_int_mod_s {
	uint32_t			:32;

	uint32_t	int_vect	:16;
	uint32_t	min_delay	:16;
};
#else /* BIG ENDIAN */
struct hermon_hw_conf_int_mod_s {
	uint32_t	min_delay	:16;
	uint32_t	int_vect	:16;

	uint32_t			:32;
};
#endif




/*
 * Hermon Memory Protection Table (MPT) entries
 *
 *    The Memory Protection Table (MPT) contains the information associated
 *    with all the regions and windows. The MPT table resides in a virtually-
 *    contiguous area in ICM, and the memory key (R_Key or L_Key) is used to
 *    calculate the physical address for accessing the entries in the table.
 *
 *
 *    The SW2HW_MPT command transfers ownership of an MPT entry from software
 *    to hardware. The command takes the MPT entry from the input mailbox and
 *    stores it in the MPT in the hardware. The command will fail if the
 *    requested MPT entry is already owned by the hardware or if the MPT index
 *    given in the command is inconsistent with the MPT entry memory key.
 *    The QUERY_MPT command retrieves a snapshot of an MPT entry. The command
 *    takes the current state of an MPT entry from the hardware and stores it
 *    in the output mailbox.  The command will fail if the requested MPT entry
 *    is already owned by software.
 *    Finally, the HW2SW_MPT command transfers ownership of an MPT entry from
 *    the hardware to the software. The command takes the MPT entry from the
 *    hardware, invalidates it, and stores it in the output mailbox. The
 *    command will fail if the requested entry is already owned by software.
 *    The command will also fail if the MPT entry in question is a Memory
 *    Region which has Memory Windows currently bound to it.
 *
 *    The following structure is used in the SW2HW_MPT, QUERY_MPT, and
 *    HW2SW_MPT commands, and ONLY for the dMPT - for data.
 */

#ifdef _LITTLE_ENDIAN
struct hermon_hw_dmpt_s {
	uint32_t			:7;
	uint32_t	bnd_qp		:1;
	uint32_t	qpn		:24;	/* dw 1, byte 4-7 */

	uint32_t			:8;
	uint32_t	reg_win		:1;
	uint32_t	phys_addr	:1;
	uint32_t	lr		:1;
	uint32_t	lw		:1;
	uint32_t	rr		:1;
	uint32_t	rw		:1;
	uint32_t	atomic		:1;
	uint32_t	en_bind		:1;
	uint32_t	atc_req		:1;
	uint32_t	atc_xlat	:1;
	uint32_t			:1;
	uint32_t	no_snoop	:1;
	uint32_t			:8;
	uint32_t	status		:4;	/* dw 0, byte 0-3 */

	uint32_t	pd		:24;
	uint32_t	ren_inval	:1;
	uint32_t	en_inval	:1;
	uint32_t	net_cache	:1;
	uint32_t	fast_reg_en	:1;
	uint32_t	rem_acc_en	:1;
	uint32_t	w_dif		:1;
	uint32_t	m_dif		:1;
	uint32_t			:1; 	/* dw 2, byte 0xc-f */

	uint32_t	mem_key;

	uint64_t	start_addr;		/* dw 4-5, byte 0x10-17 */

	uint64_t	reg_win_len;		/* dw 6-7, byte 0x18-1f */

	uint32_t	win_cnt		:24;
	uint32_t			:8; 	/* dw 9, byte 0x24-27 */

	uint32_t	lkey;			/* dw 8, byte 0x20-23 */

	uint32_t	mtt_addr_h	:8;
	uint32_t			:24;	/* dw 11, byte 0x2c-2f */

	uint32_t	mtt_rep		:4;
	uint32_t			:17;
	uint32_t	blk_mode	:1;
	uint32_t	len_b64		:1;	/* bit 64 of length */
	uint32_t	fbo_en		:1;
	uint32_t			:8; 	/* dw 10, byte 0x28-2b */

	uint32_t	mtt_size;		/* dw 13, byte 0x34-37 */

	uint32_t			:3;
	uint32_t	mtt_addr_l	:29; 	/* dw 12, byte 0x30-33 */

	uint32_t	mtt_fbo		:21;
	uint32_t			:11; 	/* dw 15, byte 0x3c-3f */

	uint32_t	entity_sz	:21;
	uint32_t			:11;	/* dw 14, byte 0x38-3b */

	uint32_t	dif_m_atag	:16;
	uint32_t			:16;	/* dw 17, 0x44-47 */

	uint32_t	dif_a_msk	:16;
	uint32_t	dif_v_msk	:2;
	uint32_t	dif_rep		:2;
	uint32_t			:4;
	uint32_t	dif_err		:3;
	uint32_t			:5;	/* dw 16, 0x40-43 */

	uint32_t	dif_w_atag	:16;
	uint32_t			:16;	/* dw 19, 0x4c-4f */

	uint32_t	dif_m_rtagb;		/* dw 18, 0x48-4b */

	uint32_t			:32;

	uint32_t	dif_w_rtagb;		/* dw 20, 0x50-53 */

	uint32_t	rsvd[10];

};

#else /* BIG ENDIAN */
struct hermon_hw_dmpt_s {
	uint32_t	status		:4;
	uint32_t			:8;
	uint32_t	no_snoop	:1;
	uint32_t			:1;
	uint32_t	atc_xlat	:1;
	uint32_t	atc_req		:1;
	uint32_t	en_bind		:1;
	uint32_t	atomic		:1;
	uint32_t	rw		:1;
	uint32_t	rr		:1;
	uint32_t	lw		:1;
	uint32_t	lr		:1;
	uint32_t	phys_addr	:1;
	uint32_t	reg_win		:1;
	uint32_t			:8;	/* dw 0, byte 0x0-3 */

	uint32_t	qpn		:24;
	uint32_t	bnd_qp		:1;
	uint32_t			:7;	/* dw 1, byte 0x4-7 */

	uint32_t	mem_key;		/* dw 2, byte 0x8-b */

	uint32_t			:1;
	uint32_t	m_dif		:1;
	uint32_t	w_dif		:1;
	uint32_t	rem_acc_en	:1;
	uint32_t	fast_reg_en	:1;
	uint32_t	net_cache	:1;
	uint32_t	en_inval	:1;
	uint32_t	ren_inval	:1;
	uint32_t	pd		:24;	/* dw 3, byte 0xc-f */

	uint64_t	start_addr;		/* dw 4-5, byte 0x10-17 */

	uint64_t	reg_win_len;		/* dw 6-7, byte 0x18-1f */

	uint32_t	lkey;			/* dw 8, bytd 0x20-23 */

	uint32_t			:8;
	uint32_t	win_cnt		:24;	/* dw 9, byte 0x24-27 */

	uint32_t			:8;
	uint32_t	fbo_en		:1;
	uint32_t	len_b64		:1;	/* bit 64 of length */
	uint32_t	blk_mode	:1;
	uint32_t			:17;
	uint32_t	mtt_rep		:4;	/* dw 10, byte 0x28-2b */

	uint32_t			:24;
	uint32_t	mtt_addr_h	:8;	/* dw 11, byte 0x2c-2f */

	uint32_t	mtt_addr_l	:29;
	uint32_t			:3;	/* dw 12, byte 0x30-33 */

	uint32_t	mtt_size;		/* dw 13, byte 0x34-37 */

	uint32_t			:11;
	uint32_t	entity_sz	:21;	/* dw 14, byte 0x38-3b */

	uint32_t			:11;
	uint32_t	mtt_fbo		:21;	/* dw 15, byte 0x3c-3f */

	uint32_t			:5;
	uint32_t	dif_err		:3;
	uint32_t			:4;
	uint32_t	dif_rep		:2;
	uint32_t	dif_v_msk	:2;
	uint32_t	dif_a_msk	:16;	/* dw 16, 0x40-43 */

	uint32_t			:16;
	uint32_t	dif_m_atag	:16;	/* dw 17, 0x44-47 */

	uint32_t	dif_m_rtagb;		/* dw 18, 0x48-4b */

	uint32_t			:16;
	uint32_t	dif_w_atag	:16;	/* dw 19, 0x4c-4f */

	uint32_t	dif_w_rtagb;		/* dw 20, 0x50-53 */

	uint32_t			:32;

	uint32_t	rsvd[10];

};
#endif

/*
 * The following structure is for the CMPTs.  This is NEVER actually built and
 * passed to the hardware - we use it to track information needed for the
 * context entries, and to facilitate the alloc tracking.  It differs from
 * the dMPT sturcture above in that it does not have/need the "dif" stuff.
 *
 */



#ifdef _LITTLE_ENDIAN
struct hermon_hw_cmpt_s {
	uint32_t			:7;
	uint32_t	bnd_qp		:1;
	uint32_t	qpn		:24;	/* dw 1, byte 4-7 */

	uint32_t			:8;
	uint32_t	reg_win	:1;
	uint32_t	phys_addr	:1;
	uint32_t	lr		:1;
	uint32_t	lw		:1;
	uint32_t	rr		:1;
	uint32_t	rw		:1;
	uint32_t	atomic		:1;
	uint32_t	en_bind		:1;
	uint32_t	atc_req		:1;
	uint32_t	atc_xlat	:1;
	uint32_t			:1;
	uint32_t	no_snoop	:1;
	uint32_t			:8;
	uint32_t	status		:4;	/* dw 0, byte 0-3 */

	uint32_t	pd		:24;
	uint32_t	ren_inval	:1;
	uint32_t	en_inval	:1;
	uint32_t	net_cache	:1;
	uint32_t	fast_reg_en	:1;
	uint32_t	rem_acc_en	:1;
	uint32_t	w_dif		:1;
	uint32_t	m_dif		:1;
	uint32_t			:1; 	/* dw 2, byte 0xc-f */

	uint32_t	mem_key;
	uint64_t	start_addr;		/* dw 4-5, byte 0x10-17 */

	uint64_t	reg_win_len;		/* dw 6-7, byte 0x18-1f */

	uint32_t	win_cnt		:24;
	uint32_t			:8; 	/* dw 9, byte 0x24-27 */

	uint32_t	lkey;			/* dw 8, byte 0x20-23 */

	uint32_t	mtt_addr_h	:8;
	uint32_t			:24;	/* dw 11, byte 0x2c-2f */

	uint32_t	mtt_rep		:4;
	uint32_t			:17;
	uint32_t	blk_mode	:1;
	uint32_t	len_b64		:1;	/* bit 64 of length */
	uint32_t	fbo_en		:1;
	uint32_t			:8; 	/* dw 10, byte 0x28-2b */

	uint32_t	mtt_size;		/* dw 13, byte 0x34-37 */

	uint32_t			:3;
	uint32_t	mtt_addr_l	:29; 	/* dw 12, byte 0x30-33 */

	uint32_t	mtt_fbo		:21;
	uint32_t			:11; 	/* dw 15, byte 0x3c-3f */

	uint32_t	entity_sz	:21;
	uint32_t			:11;	/* dw 14, byte 0x38-3b */

};


#else /* BIG ENDIAN */
struct hermon_hw_cmpt_s {
	uint32_t	status		:4;
	uint32_t			:8;
	uint32_t	no_snoop	:1;
	uint32_t			:1;
	uint32_t	atc_xlat	:1;
	uint32_t	atc_req		:1;
	uint32_t	en_bind		:1;
	uint32_t	atomic		:1;
	uint32_t	rw		:1;
	uint32_t	rr		:1;
	uint32_t	lw		:1;
	uint32_t	lr		:1;
	uint32_t	phys_addr	:1;
	uint32_t	reg_win		:1;
	uint32_t			:8;	/* dw 0, byte 0x0-3 */

	uint32_t	qpn		:24;
	uint32_t	bnd_qp		:1;
	uint32_t			:7;	/* dw 1, byte 0x4-7 */

	uint32_t	mem_key;		/* dw 2, byte 0x8-b */

	uint32_t			:1;
	uint32_t	m_dif		:1;
	uint32_t	w_dif		:1;
	uint32_t	rem_acc_en	:1;
	uint32_t	fast_reg_en	:1;
	uint32_t	net_cache	:1;
	uint32_t	en_inval	:1;
	uint32_t	ren_inval	:1;
	uint32_t	pd		:24;	/* dw 3, byte 0xc-f */

	uint64_t	start_addr;		/* dw 4-5, byte 0x10-17 */

	uint64_t	reg_win_len;	/* dw 6-7, byte 0x18-1f */

	uint32_t	lkey;			/* dw 8, bytd 0x20-23 */

	uint32_t			:8;
	uint32_t	win_cnt		:24;	/* dw 9, byte 0x24-27 */

	uint32_t			:8;
	uint32_t	fbo_en		:1;
	uint32_t	len_b64		:1;	/* bit 64 of length */
	uint32_t	blk_mode	:1;
	uint32_t			:17;
	uint32_t	mtt_rep		:4;	/* dw 10, byte 0x28-2b */

	uint32_t			:24;
	uint32_t	mtt_addr_h	:8;	/* dw 11, byte 0x2c-2f */

	uint32_t	mtt_addr_l	:29;
	uint32_t			:3;	/* dw 12, byte 0x30-33 */

	uint32_t	mtt_size;		/* dw 13, byte 0x34-37 */

	uint32_t			:11;
	uint32_t	entity_sz	:21;	/* dw 14, byte 0x38-3b */

	uint32_t			:11; 	/* dw 15, byte 0x3c-3f */
	uint32_t	mtt_fbo		:21;
};
#endif


#define	HERMON_MEM_CYCLE_GENERATE	0x1
#define	HERMON_IO_CYCLE_GENERATE	0x0

#define	HERMON_MPT_IS_WINDOW		0x0
#define	HERMON_MPT_IS_REGION		0x1

#define	HERMON_MPT_DEFAULT_VERSION	0x0

#define	HERMON_UNLIMITED_WIN_BIND	0x0

#define	HERMON_PHYSADDR_ENABLED		0x1
#define	HERMON_PHYSADDR_DISABLED	0x0


/*
 * Hermon Memory Translation Table (MTT) entries
 *    After accessing the MPT table (above) and validating the access rights
 *    to the region/window, Hermon address translation moves to the next step
 *    where it translates the virtual address to a physical address.  This
 *    translation is performed using the Memory Translation Table entries
 *    (MTT).  Note: The MTT in hardware is organized into segments and each
 *    segment contains multiple address translation pages (MTT entries).
 *    Each memory region (MPT above) points to the first segment in the MTT
 *    that corresponds to that region.
 */

#ifdef _LITTLE_ENDIAN
struct hermon_hw_mtt_s {
	uint32_t	present	:1;
	uint32_t		:2;
	uint32_t	ptag_l	:29;

	uint32_t	ptag_h;
};
#else /* BIG_ENDIAN */
struct hermon_hw_mtt_s {
	uint32_t	ptag_h;

	uint32_t	ptag_l	:29;
	uint32_t		:2;
	uint32_t	present	:1;
};

#endif
#define	HERMON_MTT_ENTRY_NOTPRESENT	0x0
#define	HERMON_MTT_ENTRY_PRESENT	0x1


/*
 * Hermon Event Queue Context Table (EQC) entries
 *    Hermon supports 512 Event Queues, and the status of Event Queues is stored
 *    in the Event Queue Context (EQC) table.  The EQC table is a virtually-
 *    contiguous memory structure in the ICM.  Each EQC
 *    table entry contains Event Queue status and information required by
 *    the hardware in order to access the event queue.
 * 	NOTE that in Hermon (as opposed to earlier HCAs),
 *	you have to allocate ICM for 2**32 (or about 16 M), even though
 *	it doesn't support that many.  See PRM v35.  Also, some set of them
 * 	will be available for each domain in a virtual environment, needing to
 *	rething the allocation and usage model for EQs - in the future.
 *
 *    The following structure is used in the SW2HW_EQ, QUERY_EQ, and HW2SW_EQ
 *    commands.
 *    The SW2HW_EQ command transfers ownership of an EQ context from software
 *    to hardware. The command takes the EQC entry from the input mailbox and
 *    stores it in the EQC in the hardware. The command will fail if the
 *    requested EQC entry is already owned by the hardware.  NOTE:  the
 *    initialization of the cMPT for the EQC occurs implicitly as a result
 *    of executing this command, and MR has/had to be adjusted for it.
 *    The QUERY_EQ command retrieves a snapshot of an EQC entry. The command
 *    stores the snapshot in the output mailbox.  The EQC state and its values
 *    are not affected by the QUERY_EQ command.
 *    Finally, the HW2SW_EQ command transfers ownership of an EQC entry from
 *    the hardware to the software. The command takes the EQC entry from the
 *    hardware and stores it in the output mailbox. The EQC entry will be
 *    invalidated as a result of the command.  It is the responsibility of the
 *    software to unmap all the events, which might have been previously
 *    mapped to the EQ, prior to issuing the HW2SW_EQ command.
 */


#ifdef	_LITTLE_ENDIAN
struct hermon_hw_eqc_s {
	uint32_t			:32;

	uint32_t			:8;
	uint32_t	state		:4;
	uint32_t			:5;
	uint32_t	overrun_ignore	:1;
	uint32_t	ev_coalesc	:1;
	uint32_t			:9;
	uint32_t	status		:4;

	uint32_t			:24;
	uint32_t	log_eq_sz	:5;
	uint32_t			:3;

	uint32_t			:5;
	uint32_t	pg_offs		:7;
	uint32_t			:20;

	uint32_t	intr		:10;
	uint32_t			:22;

	uint32_t	eq_max_cnt	:16;
	uint32_t	eq_period	:16;

	uint32_t			:3;
	uint32_t	mtt_base_addrl	:29;

	uint32_t	mtt_base_addrh 	:8;
	uint32_t			:16;
	uint32_t	log2_pgsz	:6;	/* in 4K pages */
	uint32_t			:2;

	uint32_t	rsrv0[2];

	uint32_t	prod_indx	:24;
	uint32_t			:8;

	uint32_t	cons_indx	:24;
	uint32_t			:8;

	uint64_t	rsrv1[2];	/* force it to 8b alignment */
};
#else /* BIG ENDIAN */
struct hermon_hw_eqc_s {
	uint32_t	status		:4;
	uint32_t			:9;
	uint32_t	ev_coalesc	:1;
	uint32_t	overrun_ignore	:1;
	uint32_t			:5;
	uint32_t	state		:4;
	uint32_t			:8;

	uint32_t			:32;

	uint32_t			:20;
	uint32_t	pg_offs		:7;
	uint32_t			:5;

	uint32_t			:3;
	uint32_t	log_eq_sz	:5;
	uint32_t			:24;

	uint32_t	eq_period	:16;
	uint32_t	eq_max_cnt	:16;

	uint32_t			:22;
	uint32_t	intr		:10;

	uint32_t			:2;
	uint32_t	log2_pgsz	:6;	/* in 4K pages */
	uint32_t			:16;
	uint32_t	mtt_base_addrh 	:8;

	uint32_t	mtt_base_addrl	:29;
	uint32_t			:3;

	uint32_t	rsrv0[2];

	uint32_t			:8;
	uint32_t	cons_indx	:24;

	uint32_t			:8;
	uint32_t	prod_indx	:24;

	uint64_t	rsrv1[2];	/* force it to 8b alignment */
};
#endif
#define	HERMON_EQ_STATUS_OK		0x0
#define	HERMON_EQ_STATUS_OVERFLOW	0x9
#define	HERMON_EQ_STATUS_WRITE_FAILURE	0xA

#define	HERMON_EQ_ARMED			0x9
#define	HERMON_EQ_FIRED			0xA
#define	HERMON_EQ_ALWAYS_ARMED		0xB


/*
 * Hermon Event Queue Entries (EQE)
 *    Each EQE contains enough information for the software to identify the
 *    source of the event.  The following structures are used to define each
 *    of the various kinds of events that the Hermon hardware will generate.
 *    Note: The hermon_hw_eqe_t below is the generic "Event Queue Entry".  All
 *    other EQEs differ only in the contents of their "event_data" field.
 *
 *    Below we first define several structures which define the contents of
 *    the "event_data" fields:
 *    hermon_hw_eqe_cq_t for "Completion Queue Events"
 *    hermon_hw_eqe_qp_evt_t for "Queue Pair Events" such as Path Migration
 *        Succeeded, Path Migration Failed, Communication Established, Send
 *        Queue Drained, Local WQ Catastrophic Error, Invalid Request Local
 *        WQ Error, and Local Access Violation WQ Error.
 *    hermon_hw_eqe_cqerr_t for "Completion Queue Error Events"
 *    hermon_hw_eqe_portstate_t for "Port State Change Events"
 *    hermon_hw_eqe_gpio_t for "GPIO State Change Events"
 *    hermon_hw_eqe_cmdcmpl_t for "Command Interface Completion Events"
 *    hermon_hw_eqe_operr_t for "Operational and Catastrophic Error Events"
 *        such as EQ Overflow, Misbehaved UAR page, Internal Parity Error,
 *        Uplink bus error, and DDR data error.
 *    hermon_hw_eqe_pgflt_t for "Not-present Page Fault on WQE or Data
 *        Buffer Access".  (Note: Currently, this event is unsupported).
 *
 *    Note also: The following structures are not #define'd with both
 *    little-endian and big-endian definitions.  This is because their
 *    individual fields are not directly accessed except through the macros
 *    defined below.
 */


typedef struct hermon_hw_eqe_cq_s {
	uint32_t			:8;
	uint32_t	cqn		:24;
	uint32_t	rsrv0[5];
} hermon_hw_eqe_cq_t;



typedef struct hermon_hw_eqe_qp_evt_s {
	uint32_t			:8;
	uint32_t	qpn		:24;

	uint32_t	rsrv0[5];
} hermon_hw_eqe_qpevt_t;


typedef struct hermon_hw_eqe_cqerr_s {
	uint32_t			:8;
	uint32_t	cqn		:24;

	uint32_t			:32;

	uint32_t			:24;
	uint32_t	syndrome	:8;

	uint32_t	rsrv0[3];
} hermon_hw_eqe_cqerr_t;
#define	HERMON_CQERR_OVERFLOW		0x1
#define	HERMON_CQERR_ACCESS_VIOLATION	0x2


typedef struct hermon_hw_eqe_portstate_s {
	uint32_t	rsrv0[2];

	uint32_t			:2;
	uint32_t	port		:2;
	uint32_t			:28;

	uint32_t	rsrv1[3];
} hermon_hw_eqe_portstate_t;
#define	HERMON_PORT_LINK_ACTIVE		0x4
#define	HERMON_PORT_LINK_DOWN		0x1


typedef struct hermon_hw_eqe_gpio_s {
	uint32_t	rsrv0[3];

	uint32_t	gpio_ev0;

	uint32_t	gpio_ev1;

	uint32_t		:32;
} hermon_hw_eqe_gpio_t;


typedef struct hermon_hw_eqe_cmdcmpl_s {
	uint32_t			:16;
	uint32_t	token		:16;

	uint32_t			:32;

	uint32_t			:24;
	uint32_t	status	:8;

	uint32_t	out_param0;

	uint32_t	out_param1;

	uint32_t			:32;
} hermon_hw_eqe_cmdcmpl_t;


typedef struct hermon_hw_eqe_operr_s {
	uint32_t	rsrv0[2];

	uint32_t			:24;
	uint32_t	error_type	:8;

	uint32_t	data;

	uint32_t	rsrv1[2];
} hermon_hw_eqe_operr_t;
#define	HERMON_ERREVT_EQ_OVERFLOW	0x1
#define	HERMON_ERREVT_BAD_UARPG		0x2
#define	HERMON_ERREVT_UPLINK_BUSERR	0x3
#define	HERMON_ERREVT_DDR_DATAERR	0x4
#define	HERMON_ERREVT_INTERNAL_PARITY	0x5


typedef struct hermon_hw_eqe_fcerr_s {
	uint32_t			:14;
	uint32_t	port		:2;
	uint32_t	fexch		:16;	/* fexch number */

	uint32_t			:32;

	uint32_t			:24;
	uint32_t	fcsyndrome	:8;

	uint32_t	rsvd[3];
} hermon_hw_eqe_fcerr_t;

#define	HERMON_ERR_FC_BADIU		0x0
#define	HERMON_ERR_FC_SEQUENCE		0x01

typedef struct hermon_hw_eqe_pgflt_s {
	uint32_t	rsrv0[2];
	uint32_t			:24;
	uint32_t	fault_type	:4;
	uint32_t	wqv		:1;
	uint32_t	wqe_data	:1;
	uint32_t	rem_loc		:1;
	uint32_t	snd_rcv		:1;
	uint32_t	vaddr_h;
	uint32_t	vaddr_l;
	uint32_t	mem_key;
} hermon_hw_eqe_pgflt_t;
#define	HERMON_PGFLT_PG_NOTPRESENT	0x8
#define	HERMON_PGFLT_PG_WRACC_VIOL	0xA
#define	HERMON_PGFLT_UNSUP_NOTPRESENT	0xE
#define	HERMON_PGFLT_UNSUP_WRACC_VIOL	0xF
#define	HERMON_PGFLT_WQE_CAUSED		0x1
#define	HERMON_PGFLT_DATA_CAUSED		0x0
#define	HERMON_PGFLT_REMOTE_CAUSED	0x1
#define	HERMON_PGFLT_LOCAL_CAUSED	0x0
#define	HERMON_PGFLT_SEND_CAUSED		0x1
#define	HERMON_PGFLT_RECV_CAUSED		0x0
#define	HERMON_PGFLT_DESC_CONSUMED	0x1
#define	HERMON_PGFLT_DESC_NOTCONSUMED	0x0

struct hermon_hw_eqe_s {
	uint32_t			:8;
	uint32_t	event_type	:8;
	uint32_t			:8;
	uint32_t	event_subtype	:8;
	union {
		hermon_hw_eqe_cq_t		eqe_cq;
		hermon_hw_eqe_qpevt_t		eqe_qpevt;
		hermon_hw_eqe_cqerr_t		eqe_cqerr;
		hermon_hw_eqe_portstate_t	eqe_portstate;
		hermon_hw_eqe_gpio_t		eqe_gpio;
		hermon_hw_eqe_cmdcmpl_t		eqe_cmdcmpl;
		hermon_hw_eqe_operr_t		eqe_operr;
		hermon_hw_eqe_pgflt_t		eqe_pgflt;
		hermon_hw_eqe_fcerr_t		eqe_fcerr;
	} event_data;
	uint32_t			:24;
	uint32_t	owner		:1;
	uint32_t			:7;
};
#define	eqe_cq				event_data.eqe_cq
#define	eqe_qpevt			event_data.eqe_qpevt
#define	eqe_cqerr			event_data.eqe_cqerr
#define	eqe_portstate			event_data.eqe_portstate
#define	eqe_gpio			event_data.eqe_gpio
#define	eqe_cmdcmpl			event_data.eqe_cmdcmpl
#define	eqe_operr			event_data.eqe_operr
#define	eqe_pgflt			event_data.eqe_pgflt
#define	eqe_fcerr			event_data.eqe_fcerr

/*
 * The following macros are used for extracting (and in some cases filling in)
 * information from EQEs
 */
#define	HERMON_EQE_CQNUM_MASK		0x00FFFFFF
#define	HERMON_EQE_CQNUM_SHIFT		0
#define	HERMON_EQE_QPNUM_MASK		0x00FFFFFF
#define	HERMON_EQE_QPNUM_SHIFT		0
#define	HERMON_EQE_PORTNUM_MASK		0x30
#define	HERMON_EQE_PORTNUM_SHIFT	4
#define	HERMON_EQE_OWNER_MASK		0x00000080
#define	HERMON_EQE_OWNER_SHIFT		7

#define	HERMON_EQE_EVTTYPE_GET(eq, eqe)					\
	(((uint8_t *)(eqe))[1])
#define	HERMON_EQE_EVTSUBTYPE_GET(eq, eqe)				\
	(((uint8_t *)(eqe))[3])
#define	HERMON_EQE_CQNUM_GET(eq, eqe)					\
	((htonl(((uint32_t *)(eqe))[1]) & HERMON_EQE_CQNUM_MASK) >>	\
	    HERMON_EQE_CQNUM_SHIFT)
#define	HERMON_EQE_QPNUM_GET(eq, eqe)					\
	((htonl(((uint32_t *)(eqe))[1]) & HERMON_EQE_QPNUM_MASK) >>	\
	HERMON_EQE_QPNUM_SHIFT)
#define	HERMON_EQE_PORTNUM_GET(eq, eqe)					\
	(((((uint8_t *)(eqe))[12]) & HERMON_EQE_PORTNUM_MASK) >>	\
	    HERMON_EQE_PORTNUM_SHIFT)
#define	HERMON_EQE_CMDTOKEN_GET(eq, eqe)				\
	htons(((uint16_t *)(eqe))[3])
#define	HERMON_EQE_CMDSTATUS_GET(eq, eqe)				\
	(((uint8_t *)(eqe))[0xf])
#define	HERMON_EQE_CMDOUTP0_GET(eq, eqe)				\
	htonl(((uint32_t *)(eqe))[4])
#define	HERMON_EQE_CMDOUTP1_GET(eq, eqe)				\
	htonl(((uint32_t *)(eqe))[5])
#define	HERMON_EQE_OPERRTYPE_GET(eq, eqe)				\
	(((uint8_t *)(eqe))[0xf])
#define	HERMON_EQE_OPERRDATA_GET(eq, eqe)				\
	htonl(((uint32_t *)(eqe))[4])
#define	HERMON_EQE_FEXCH_PORTNUM_GET(eq, eqe)				\
	(((uint8_t *)(eqe))[5] & 0x3)
#define	HERMON_EQE_FEXCH_FEXCH_GET(eq, eqe)				\
	htons(((uint16_t *)(eqe))[3])
#define	HERMON_EQE_FEXCH_SYNDROME_GET(eq, eqe)				\
	(((uint8_t *)(eqe))[15])

/*
 * Hermon does ownership of CQ and EQ differently from Arbel & Tavor.
 * Now, you keep track of the TOTAL number of CQE's or EQE's that have been
 * processed, and the sense of the ownership bit changes each time through.
 * That is, if the size of the queue is 16, so 4 bits [3:0] are the index
 * number, then bit [4] is the ownership bit in the count.  So you mask that
 * bit and compare it to the owner bit in the entry - if the same, then the
 * entry is in SW onwership.  Otherwise, it's in hardware and the driver
 * does not consume it.
 */

#define	HERMON_EQE_OWNER_IS_SW(eq, eqe, consindx, shift)		\
	((((uint8_t *)(eqe))[0x1f] & HERMON_EQE_OWNER_MASK) ==		\
	    (((consindx) & eq->eq_bufsz) >> (shift)))

/*
 * Hermon Completion Queue Context Table (CQC) entries
 *    The CQC table is a virtually-contiguous memory area residing in HCA's
 *    ICM.  Each CQC table entry contains information
 *    required by the hardware to access the completion queue to post
 *    completions (CQE).
 *
 *    The following structure is used in the SW2HW_CQ, QUERY_CQ, RESIZE_CQ,
 *    and HW2SW_CQ commands.
 *    The SW2HW_CQ command transfers ownership of an CQ context from software
 *    to hardware. The command takes the CQC entry from the input mailbox and
 *    stores it in the CQC in the hardware. The command will fail if the
 *    requested CQC entry is already owned by the hardware.
 *    The QUERY_CQ command retrieves a snapshot of a CQC entry. The command
 *    stores the snapshot in the output mailbox.  The CQC state and its values
 *    are not affected by the QUERY_CQ command.
 *    Finally, the HW2SW_CQ command transfers ownership of a CQC entry from
 *    the hardware to the software. The command takes the CQC entry from the
 *    hardware and stores it in the output mailbox. The CQC entry will be
 *    invalidated as a result of the command.
 */


#ifdef	_LITTLE_ENDIAN
struct hermon_hw_cqc_s {
	uint32_t			:32;

	uint32_t			:8;
	uint32_t	state		:4;
	uint32_t			:5;
	uint32_t	overrun_ignore	:1;
	uint32_t	cqe_coalesc	:1;
	uint32_t			:9;
	uint32_t	status		:4;

	uint32_t	usr_page	:24;
	uint32_t	log_cq_sz	:5;
	uint32_t			:3;

	uint32_t			:5;
	uint32_t	pg_offs		:7;
	uint32_t			:20;

	uint32_t	c_eqn		:9;
	uint32_t			:23;

	uint32_t	cq_max_cnt	:16;
	uint32_t	cq_period	:16;

	uint32_t			:3;
	uint32_t	mtt_base_addl 	:29;

	uint32_t	mtt_base_addh 	:8;
	uint32_t			:16;
	uint32_t	log2_pgsz	:6;
	uint32_t			:2;

	uint32_t	solicit_prod_indx :24;
	uint32_t				:8;

	uint32_t	last_notified_indx	:24;
	uint32_t				:8;

	uint32_t	prod_cntr		:24;	/* producer counter */
	uint32_t				:8;

	uint32_t	cons_cntr		:24;	/* consumer counter */
	uint32_t				:8;

	uint32_t	rsrv0[2];

	uint32_t				:3;
	uint32_t	dbr_addrl		:29;

	uint32_t	dbr_addrh;

	uint64_t	rsrv1[8];		/* hermon, match DEV_CAP size */
};
#else
struct hermon_hw_cqc_s {
	uint32_t	status		:4;
	uint32_t			:9;
	uint32_t	cqe_coalesc	:1;
	uint32_t	overrun_ignore	:1;
	uint32_t			:5;
	uint32_t	state		:4;
	uint32_t			:8;

	uint32_t			:32;

	uint32_t			:20;
	uint32_t	pg_offs		:7;
	uint32_t			:5;

	uint32_t			:3;
	uint32_t	log_cq_sz	:5;
	uint32_t	usr_page	:24;

	uint32_t	cq_period	:16;
	uint32_t	cq_max_cnt	:16;

	uint32_t			:23;
	uint32_t	c_eqn		:9;

	uint32_t			:2;
	uint32_t	log2_pgsz	:6;
	uint32_t			:16;
	uint32_t	mtt_base_addh 	:8;

	uint32_t	mtt_base_addl 	:29;
	uint32_t				:3;

	uint32_t				:8;
	uint32_t	last_notified_indx	:24;

	uint32_t				:8;
	uint32_t	solicit_prod_indx	:24;

	uint32_t				:8;
	uint32_t	cons_cntr		:24;	/* consumer counter */

	uint32_t				:8;
	uint32_t	prod_cntr		:24;	/* priducer counter */

	uint32_t	rsrv0[2];

	uint32_t	dbr_addrh;

	uint32_t	dbr_addrl		:29;
	uint32_t				:3;

	uint64_t	rsrv1[8];		/* hermon, match DEV_CAP size */
};
#endif
#define	HERMON_CQ_STATUS_OK		0x0
#define	HERMON_CQ_STATUS_OVERFLOW	0x9
#define	HERMON_CQ_STATUS_WRITE_FAILURE	0xA

#define	HERMON_CQ_DISARMED		0x0
#define	HERMON_CQ_ARMED			0x1
#define	HERMON_CQ_ARMED_SOLICITED	0x4
#define	HERMON_CQ_FIRED			0xA

/*
 * Hermon Completion Queue Entries (CQE)
 *    Each CQE contains enough information for the software to associate the
 *    completion with the Work Queue Element (WQE) to which it corresponds.
 *
 *    Note: The following structure is not #define'd with both little-endian
 *    and big-endian definitions.  This is because each CQE's individual
 *    fields are not directly accessed except through the macros defined below.
 */


struct hermon_hw_cqe_s {
	uint32_t	dife		:1;
	uint32_t	vlan		:2;
	uint32_t	fl		:1;
	uint32_t	fcrc_sd		:1;
	uint32_t	d2s		:1;
	uint32_t			:2;
	uint32_t	my_qpn		:24;

	uint32_t	immed_rss_val_key;

	uint32_t	grh		:1;
	uint32_t	ml_path		:7;
	uint32_t	srq_rqpn	:24;

	uint32_t	sl		:4;
	uint32_t	vid		:12;
	uint32_t	slid		:16;	/* SMAC 47:32 or SLID */

	uint32_t	ipoib_status; /* SMAC 31:0 or enet/ipoib/EoIB status */

	uint32_t	byte_cnt;

	uint32_t	wqe_cntr	:16;
	uint32_t	checksum	:16;

	uint32_t			:8;
	uint32_t			:16;
	uint32_t	owner		:1;
	uint32_t	send_or_recv	:1;
	uint32_t	inline_scatter	:1;
	uint32_t	opcode		:5;
};
#define	HERMON_COMPLETION_RECV		0x0
#define	HERMON_COMPLETION_SEND		0x1

#define	HERMON_CQE_DEFAULT_VERSION	0x0

/*
 * The following macros are used for extracting (and in some cases filling in)
 * information from CQEs
 */
#define	HERMON_CQE_QPNUM_MASK		0x00FFFFFF
#define	HERMON_CQE_QPNUM_SHIFT		0


#define	HERMON_CQE_DQPN_MASK		0x00FFFFFF
#define	HERMON_CQE_DQPN_SHIFT		0


#define	HERMON_CQE_SL_SHIFT		4
#define	HERMON_CQE_GRH_MASK		0x80
#define	HERMON_CQE_PATHBITS_MASK	0x7F
#define	HERMON_CQE_SLID_15_8		0xe
#define	HERMON_CQE_SLID_7_0		0xf
#define	HERMON_CQE_OPCODE_MASK		0x1F
#define	HERMON_CQE_SENDRECV_MASK	0x40
#define	HERMON_CQE_SENDRECV_SHIFT	6
#define	HERMON_CQE_OWNER_MASK		0x80
#define	HERMON_CQE_OWNER_SHIFT		7
#define	HERMON_CQE_WQECNTR_15_8		0x18
#define	HERMON_CQE_WQECNTR_7_0		0x19
/* Byte offsets for IPoIB Checksum Offload fields */
#define	HERMON_CQE_CKSUM_15_8		0x1a
#define	HERMON_CQE_CKSUM_7_0		0x1b
#define	HERMON_CQE_IPOK			0x10	/* byte 0x10 in cqe */
#define	HERMON_CQE_IPOK_BIT		0x10	/* bitmask for OK bit */

#define	HERMON_CQE_IS_IPOK(cq, cqe)					\
	(((uint8_t *)(cqe))[HERMON_CQE_IPOK] & HERMON_CQE_IPOK_BIT)

#define	HERMON_CQE_CKSUM(cq, cqe)					\
	((((uint8_t *)(cqe))[HERMON_CQE_CKSUM_15_8] << 8) |		\
	    (((uint8_t *)(cqe))[HERMON_CQE_CKSUM_7_0]))

#define	HERMON_CQE_IPOIB_STATUS(cq, cqe)				\
	htonl((((uint32_t *)(cqe)))[4])

#define	HERMON_CQE_QPNUM_GET(cq, cqe)					\
	((htonl((((uint32_t *)(cqe)))[0]) & HERMON_CQE_QPNUM_MASK) >>	\
	    HERMON_CQE_QPNUM_SHIFT)

#define	HERMON_CQE_IMM_ETH_PKEY_CRED_GET(cq, cqe)			\
	htonl(((uint32_t *)(cqe))[1])

#define	HERMON_CQE_DQPN_GET(cq, cqe)					\
	((htonl(((uint32_t *)(cqe))[2]) & HERMON_CQE_DQPN_MASK) >>	\
	    HERMON_CQE_DQPN_SHIFT)

#define	HERMON_CQE_GRH_GET(cq, cqe)					\
	(((uint8_t *)(cqe))[8] & HERMON_CQE_GRH_MASK)

#define	HERMON_CQE_PATHBITS_GET(cq, cqe)				\
	(((uint8_t *)(cqe))[8] & HERMON_CQE_PATHBITS_MASK)

#define	HERMON_CQE_DLID_GET(cq, cqe)					\
	((((uint8_t *)(cqe))[HERMON_CQE_SLID_15_8] << 8) |		\
	    (((uint8_t *)(cqe))[HERMON_CQE_SLID_7_0]))

#define	HERMON_CQE_SL_GET(cq, cqe)					\
	((((uint8_t *)(cqe))[12]) >> HERMON_CQE_SL_SHIFT)

#define	HERMON_CQE_BYTECNT_GET(cq, cqe)					\
	htonl(((uint32_t *)(cqe))[5])

#define	HERMON_CQE_WQECNTR_GET(cq, cqe)					\
	((((uint8_t *)(cqe))[HERMON_CQE_WQECNTR_15_8] << 8) |		\
	    (((uint8_t *)(cqe))[HERMON_CQE_WQECNTR_7_0]))

#define	HERMON_CQE_ERROR_SYNDROME_GET(cq, cqe)				\
	(((uint8_t *)(cqe))[27])

#define	HERMON_CQE_ERROR_VENDOR_SYNDROME_GET(cq, cqe)			\
	(((uint8_t *)(cqe))[26])

#define	HERMON_CQE_OPCODE_GET(cq, cqe)					\
	((((uint8_t *)(cqe))[31]) & HERMON_CQE_OPCODE_MASK)

#define	HERMON_CQE_SENDRECV_GET(cq, cqe)				\
	(((((uint8_t *)(cqe))[31]) & HERMON_CQE_SENDRECV_MASK) >>	\
	    HERMON_CQE_SENDRECV_SHIFT)

#define	HERMON_CQE_FEXCH_SEQ_CNT(cq, cqe)				\
	HERMON_CQE_CKSUM(cq, cqe)

#define	HERMON_CQE_FEXCH_TX_BYTES(cq, cqe)				\
	htonl(((uint32_t *)(cqe))[3])

#define	HERMON_CQE_FEXCH_RX_BYTES(cq, cqe)				\
	htonl(((uint32_t *)(cqe))[4])

#define	HERMON_CQE_FEXCH_SEQ_ID(cq, cqe)				\
	(((uint8_t *)(cqe))[8])

#define	HERMON_CQE_FEXCH_DETAIL(cq, cqe)				\
	htonl(((uint32_t *)(cqe))[0])

#define	HERMON_CQE_FEXCH_DIFE(cq, cqe)					\
	((((uint8_t *)(cqe))[0]) & 0x80)

/* See Comment above for EQE - ownership of CQE is handled the same */

#define	HERMON_CQE_OWNER_IS_SW(cq, cqe, considx, shift, mask)		\
	(((((uint8_t *)(cqe))[31] & HERMON_CQE_OWNER_MASK) >>		\
	    HERMON_CQE_OWNER_SHIFT) == 					\
	    (((considx) & (mask)) >> (shift)))

/*
 * Hermon Shared Receive Queue (SRQ) Context Entry Format
 */

#ifdef _LITTLE_ENDIAN
struct hermon_hw_srqc_s {
	uint32_t	xrc_domain		:16;
	uint32_t				:8;
	uint32_t	log_rq_stride		:3;
	uint32_t				:5;

	uint32_t	srqn			:24;
	uint32_t	log_srq_size		:4;
	uint32_t	state			:4;

	uint32_t				:32;

	uint32_t	cqn_xrc			:24;
	uint32_t				:2;
	uint32_t	page_offs		:6;

	uint32_t				:3;
	uint32_t	mtt_base_addrl		:29;

	uint32_t	mtt_base_addrh		:8;
	uint32_t				:16;
	uint32_t	log2_pgsz		:6;
	uint32_t				:2;

	uint32_t	wqe_cnt			:16;
	uint32_t	lwm			:16;

	uint32_t	pd			:24;
	uint32_t				:8;

	uint32_t				:32;

	uint32_t	srq_wqe_cntr		:16;
	uint32_t				:16;

	uint32_t				:2;
	uint32_t	dbr_addrl		:30;

	uint32_t	dbr_addrh;

	uint32_t	rsrc0[80];	/* to match DEV_CAP size of 0x80 */

};
#else  /* BIG ENDIAN */
struct hermon_hw_srqc_s {
	uint32_t	state			:4;
	uint32_t	log_srq_size		:4;
	uint32_t	srqn			:24;

	uint32_t				:5;
	uint32_t	log_rq_stride		:3;
	uint32_t				:8;
	uint32_t	xrc_domain		:16;

	uint32_t	page_offs		:6;
	uint32_t				:2;
	uint32_t	cqn_xrc			:24;

	uint32_t				:32;

	uint32_t				:2;
	uint32_t	log2_pgsz		:6;
	uint32_t				:16;
	uint32_t	mtt_base_addrh		:8;

	uint32_t	mtt_base_addrl		:29;
	uint32_t				:3;

	uint32_t				:8;
	uint32_t	pd			:24;

	uint32_t	lwm			:16;
	uint32_t	wqe_cnt			:16;

	uint32_t				:16;
	uint32_t	srq_wqe_cntr		:16;

	uint32_t				:32;

	uint32_t	dbr_addrh;

	uint32_t	dbr_addrl		:30;
	uint32_t				:2;

	uint32_t	rsrc0[80];	/* to match DEV_CAP size of 0x80 */
};
#endif

/*
 * Hermon MOD_STAT_CFG input mailbox structure
 */


#ifdef _LITTLE_ENDIAN
struct hermon_hw_mod_stat_cfg_s {
	uint32_t				:16;
	uint32_t	qdr_rx_op		:4;
	uint32_t				:3;
	uint32_t	qdr_rx_opt_m		:1;
	uint32_t	qdr_tx_op		:4;
	uint32_t				:3;
	uint32_t	qdr_tx_opt_m		:1;

	uint32_t	log_pg_sz		:8;
	uint32_t	log_pg_sz_m		:1;
	uint32_t				:5;
	uint32_t	dife			:1;
	uint32_t	dife_m			:1;
	uint32_t	rx_options		:4;
	uint32_t				:3;
	uint32_t	rx_options_m		:1;
	uint32_t	tx_options		:4;
	uint32_t				:3;
	uint32_t	tx_options_m		:1;

	uint32_t	lid			:16;
	uint32_t	lid_m			:1;
	uint32_t				:3;
	uint32_t	port_en			:1;
	uint32_t	port_en_m		:1;
	uint32_t				:10;

	uint32_t				:32;

	uint32_t	guid_hi;

	uint32_t				:31;
	uint32_t	guid_hi_m		:1;

	uint32_t	guid_lo;

	uint32_t				:31;
	uint32_t	guid_lo_m		:1;

	uint32_t	rsvd[4];

	uint32_t	inbuf_ind_en		:3;
	uint32_t				:1;
	uint32_t	sd_main			:4;
	uint32_t				:4;
	uint32_t	sd_equal		:4;
	uint32_t				:4;
	uint32_t	sd_mux_main		:2;
	uint32_t				:2;
	uint32_t	mux_eq			:2;
	uint32_t				:2;
	uint32_t	sigdet_th		:3;
	uint32_t				:1;

	uint32_t	ob_preemp_pre		:5;
	uint32_t				:3;
	uint32_t	op_preemp_post		:5;
	uint32_t				:3;
	uint32_t	ob_preemp_main		:5;
	uint32_t				:3;
	uint32_t	ob_preemp		:5;
	uint32_t				:2;
	uint32_t	serdes_m		:1;

	uint32_t	reserved[22];

	uint32_t	mac_lo			:32;

	uint32_t	mac_hi			:16;
	uint32_t				:15;
	uint32_t	mac_m			:1;
};
#else /* BIG ENDIAN */
struct hermon_hw_mod_stat_cfg_s {
	uint32_t	tx_options_m		:1;
	uint32_t				:3;
	uint32_t	tx_options		:4;
	uint32_t	rx_options_m		:1;
	uint32_t				:3;
	uint32_t	rx_options		:4;
	uint32_t	dife_m			:1;
	uint32_t	dife			:1;
	uint32_t				:5;
	uint32_t	log_pg_sz_m		:1;
	uint32_t	log_pg_sz		:8;

	uint32_t	qdr_tx_opt_m		:1;
	uint32_t				:3;
	uint32_t	qdr_tx_op		:4;
	uint32_t	qdr_rx_opt_m		:1;
	uint32_t				:3;
	uint32_t	qdr_rx_op		:4;
	uint32_t				:16;

	uint32_t				:32;

	uint32_t				:10;
	uint32_t	port_en_m		:1;
	uint32_t	port_en			:1;
	uint32_t				:3;
	uint32_t	lid_m			:1;
	uint32_t	lid			:16;

	uint32_t	guid_hi_m		:1;
	uint32_t				:31;

	uint32_t	guid_hi;

	uint32_t	guid_lo_m		:1;
	uint32_t				:31;

	uint32_t	guid_lo;

	uint32_t	rsvd[4];

	uint32_t	serdes_m		:1;
	uint32_t				:2;
	uint32_t	ob_preemp		:5;
	uint32_t				:3;
	uint32_t	ob_preemp_main		:5;
	uint32_t				:3;
	uint32_t	op_preemp_post		:5;
	uint32_t				:3;
	uint32_t	ob_preemp_pre		:5;

	uint32_t				:1;
	uint32_t	sigdet_th		:3;
	uint32_t				:2;
	uint32_t	mux_eq			:2;
	uint32_t				:2;
	uint32_t	sd_mux_main		:2;
	uint32_t				:4;
	uint32_t	sd_equal		:4;
	uint32_t				:4;
	uint32_t	sd_main			:4;
	uint32_t				:1;
	uint32_t	inbuf_ind_en		:3;

	uint32_t	reserved[22];		/* get to new enet stuff */

	uint32_t	mac_m			:1;
	uint32_t				:15;
	uint32_t	mac_hi			:16;

	uint32_t	mac_lo			:32;
};
#endif

/*
 * Hermon MOD_STAT_CFG input modifier structure
 * NOTE:  this might end up defined ONLY one way,
 * if usage is access via macros
 */
struct hermon_hw_msg_in_mod_s {
#ifdef _LITTLE_ENDIAN
	uint32_t	offset			:8;
	uint32_t	port_num		:8;
	uint32_t	lane_num		:4;
	uint32_t	link_speed		:3;
	uint32_t	auto_neg		:1;
	uint32_t				:8;
#else
	uint32_t				:8;
	uint32_t	auto_neg		:1;
	uint32_t	link_speed		:3;
	uint32_t	lane_num		:4;
	uint32_t	port_num		:8;
	uint32_t	offset			:8;
#endif
};


/*
 * Hermon UD Address Vector (UDAV)
 *    Hermon UDAV are used in conjunction with Unreliable Datagram (UD) send
 *    WQEs. Each UD send message contains an address vector in in the datagram
 *    segment. The verbs consumer must use special verbs to create and modify
 *    address handles, each of which contains a UDAV structure.  When posting
 *    send WQEs to UD QP, the verbs consumer must supply a valid address
 *    handle/UDAV.
 */


#ifdef	_LITTLE_ENDIAN
struct hermon_hw_udav_s {
	uint32_t	rlid		:16;
	uint32_t	ml_path		:7;	/* mlid or SMAC idx */
	uint32_t	grh		:1;
	uint32_t			:8;

	uint32_t	pd		:24;
	uint32_t	portnum		:2;
	uint32_t			:5;
	uint32_t	force_lb	:1;

	uint32_t	flow_label	:20;
	uint32_t	tclass		:8;
	uint32_t	sl		:4;

	uint32_t	hop_limit	:8;
	uint32_t	max_stat_rate	:4;
	uint32_t			:4;
	uint32_t	mgid_index	:7;
	uint32_t			:9;

	uint64_t	rgid_h;
	uint64_t	rgid_l;
};
#else
struct hermon_hw_udav_s {
	uint32_t	force_lb	:1;
	uint32_t			:5;
	uint32_t	portnum		:2;
	uint32_t	pd		:24;

	uint32_t			:8;
	uint32_t	grh		:1;
	uint32_t	ml_path		:7;	/* mlid or SMAC idx */
	uint32_t	rlid		:16;

	uint32_t			:9;
	uint32_t	mgid_index	:7;
	uint32_t			:4;
	uint32_t	max_stat_rate	:4;
	uint32_t	hop_limit	:8;

	uint32_t	sl		:4;
	uint32_t	tclass		:8;
	uint32_t	flow_label	:20;

	uint64_t	rgid_h;
	uint64_t	rgid_l;
};
#endif
#define	HERMON_UDAV_MODIFY_MASK0		0xFCFFFFFFFF000000ULL
#define	HERMON_UDAV_MODIFY_MASK1		0xFF80F00000000000ULL

/* UDAV for enthernet */

#ifdef	_LITTLE_ENDIAN
struct hermon_hw_udav_enet_s {
	uint32_t			:16;
	uint32_t	smac_idx	:7;
	uint32_t			:9;

	uint32_t	pd		:24;
	uint32_t	portnum		:2;
	uint32_t			:3;
	uint32_t	cv		:1;
	uint32_t			:1;
	uint32_t	force_lb	:1;

	uint32_t	flow_label	:20;
	uint32_t	tclass		:8;
	uint32_t	sl		:4;

	uint32_t	hop_limit	:8;
	uint32_t	max_stat_rate	:4;
	uint32_t			:4;
	uint32_t	mgid_index	:7;
	uint32_t			:9;

	uint64_t	rgid_h;
	uint64_t	rgid_l;

	uint32_t	rsrv[2];

	uint32_t	dmac_lo;

	uint32_t	dmac_hi		:16;
	uint32_t	vlan		:16;
};
#else
struct hermon_hw_udav_enet_s {
	uint32_t	force_lb	:1;
	uint32_t			:1;
	uint32_t	cv		:1;
	uint32_t			:3;
	uint32_t	portnum		:2;
	uint32_t	pd		:24;

	uint32_t			:9;
	uint32_t	smac_idx	:7;
	uint32_t			:16;

	uint32_t			:9;
	uint32_t	mgid_index	:7;
	uint32_t			:4;
	uint32_t	max_stat_rate	:4;
	uint32_t	hop_limit	:8;

	uint32_t	sl		:4;
	uint32_t	tclass		:8;
	uint32_t	flow_label	:20;

	uint64_t	rgid_h;
	uint64_t	rgid_l;

	uint32_t	rsrv[2];

	uint32_t	vlan		:16;
	uint32_t	dmac_hi		:16;

	uint32_t	dmac_low;
};
#endif

/*
 * Hermon Queue Pair Context Table (QPC) entries
 *    The QPC table is a virtually-contiguous memory area residing in HCA
 *    ICM.  Each QPC entry is accessed for reads and writes
 *    by the HCA while executing work requests on the associated QP.
 *
 *    The following structure is used in the RST2INIT_QP, INIT2INIT_QP,
 *    INIT2RTR_QP, RTR2RTS_QP, RTS2RTS_QP, SQERR2RTS_QP, TOERR_QP, RTS2SQD_QP,
 *    SQD2RTS_QP, TORST_QP, and QUERY_QP commands.
 *    With the exception of the QUERY_QP command, each of these commands reads
 *    from some portion of the QPC in the input mailbox and modified the QPC
 *    stored in the hardware.  The QUERY_QP command retrieves a snapshot of a
 *    QPC entry. The command stores the snapshot in the output mailbox.  The
 *    QPC state and its values are not affected by the QUERY_QP command.
 *
 *    Below we first define the hermon_hw_addr_path_t or "Hermon Address Path"
 *    structure.  This structure is used to provide address path information
 *    (both primary and secondary) for each QP context.  Note:  Since this
 *    structure is _very_ similar to the hermon_hw_udav_t structure above,
 *    we are able to leverage the similarity with filling in and reading from
 *    the two types of structures.  See hermon_get_addr_path() and
 *    hermon_set_addr_path() in hermon_misc.c for more details.
 */
#if (DATAMODEL_NATIVE == DATAMODEL_LP64)
#pragma pack(4)
#endif

#ifdef	_LITTLE_ENDIAN
struct hermon_hw_addr_path_s {
	uint32_t	rlid		:16;
	uint32_t	mlid		:7;	/* mlid or SMAC idx */
	uint32_t	grh		:1;
	uint32_t	cntr_idx	:8;

	uint32_t	pkey_indx	:7;
	uint32_t			:22;
	uint32_t			:1;	/* but may be used for enet */
	uint32_t	cv		:1;
	uint32_t	force_lb	:1;

	uint32_t	flow_label	:20;
	uint32_t	tclass		:8;
	uint32_t	sniff_s_in	:1;
	uint32_t	sniff_s_out	:1;
	uint32_t	sniff_r_in	:1;
	uint32_t	sniff_r_out 	:1; 	/* sniff-rcv-egress */

	uint32_t	hop_limit	:8;
	uint32_t	max_stat_rate	:4;
	uint32_t			:4;
	uint32_t	mgid_index	:7;
	uint32_t			:1;
	uint32_t	link_type	:3;
	uint32_t	ack_timeout	:5;

	uint64_t	rgid_h;
	uint64_t	rgid_l;

	uint32_t	dmac_hi		:16;
	uint32_t			:16;

	uint32_t			:8;	/* but may be used for enet */
	uint32_t	sp		:1;
	uint32_t			:2;
	uint32_t	fvl		:1;
	uint32_t	fsip		:1;
	uint32_t	fsm		:1;
	uint32_t			:2;
	uint32_t	vlan_idx	:7;
	uint32_t			:1;
	uint32_t	sched_q		:8;

	uint32_t	dmac_lo		:32;
};
#else
struct hermon_hw_addr_path_s {
	uint32_t	force_lb	:1;
	uint32_t	cv		:1;
	uint32_t			:1;	/* but may be used for enet */
	uint32_t			:22;
	uint32_t	pkey_indx	:7;

	uint32_t	cntr_idx	:8;
	uint32_t	grh		:1;
	uint32_t	mlid		:7;	/* mlid or SMAC idx */
	uint32_t	rlid		:16;

	uint32_t	ack_timeout	:5;
	uint32_t	link_type	:3;
	uint32_t			:1;
	uint32_t	mgid_index	:7;
	uint32_t			:4;
	uint32_t	max_stat_rate	:4;
	uint32_t	hop_limit	:8;

	uint32_t	sniff_r_out	:1;	/* sniff-rcv-egress */
	uint32_t	sniff_r_in	:1;
	uint32_t	sniff_s_out	:1;
	uint32_t	sniff_s_in	:1;
	uint32_t	tclass		:8;
	uint32_t	flow_label	:20;

	uint64_t	rgid_h;
	uint64_t	rgid_l;

	uint32_t	sched_q		:8;
	uint32_t			:1;
	uint32_t	vlan_idx	:7;
	uint32_t			:2;
	uint32_t	fsm		:1;
	uint32_t	fsip		:1;
	uint32_t	fvl		:1;
	uint32_t			:2;
	uint32_t	sp		:1;
	uint32_t			:8;	/* but may be used for enet */

	uint32_t			:16;
	uint32_t	dmac_hi		:16;

	uint32_t	dmac_lo		:32;
};
#endif	/* LITTLE ENDIAN */

/* The addr path includes RSS fields for RSS QPs */
#ifdef	_LITTLE_ENDIAN
struct hermon_hw_rss_s {
	uint32_t	rlid		:16;
	uint32_t	mlid		:7;
	uint32_t	grh		:1;
	uint32_t	cntr_idx	:8;

	uint32_t	pkey_indx	:7;
	uint32_t			:22;
	uint32_t			:1;	/* but may be used for enet */
	uint32_t	cv		:1;
	uint32_t	force_lb	:1;

	uint32_t	flow_label	:20;
	uint32_t	tclass		:8;
	uint32_t	sniff_s_in	:1;
	uint32_t	sniff_s_out	:1;
	uint32_t	sniff_r_in	:1;
	uint32_t	sniff_r_out 	:1; 	/* sniff-rcv-egress */

	uint32_t	hop_limit	:8;
	uint32_t	max_stat_rate	:4;
	uint32_t			:4;
	uint32_t	mgid_index	:7;
	uint32_t			:1;
	uint32_t	link_type	:3;
	uint32_t	ack_timeout	:5;

	uint64_t	rgid_h;
	uint64_t	rgid_l;

	uint32_t	base_qpn	:24;
	uint32_t	log2_tbl_sz	:4;
	uint32_t			:4;

	uint32_t			:8;	/* but may be used for enet */
	uint32_t	sp		:1;
	uint32_t			:2;
	uint32_t	fvl		:1;
	uint32_t	fsip		:1;
	uint32_t	fsm		:1;
	uint32_t			:2;
	uint32_t	vlan_idx	:7;
	uint32_t			:1;
	uint32_t	sched_q		:8;

	uint32_t			:2;
	uint32_t	tcp_ipv6	:1;
	uint32_t	ipv6		:1;
	uint32_t	tcp_ipv4	:1;
	uint32_t	ipv4		:1;
	uint32_t			:2;
	uint32_t	hash_fn		:2;
	uint32_t			:22;

	uint32_t	default_qpn	:24;
	uint32_t			:8;

	uint8_t		rss_key[40];
};
#else  /* BIG ENDIAN */
struct hermon_hw_rss_s {
	uint32_t	force_lb	:1;
	uint32_t	cv		:1;
	uint32_t			:1;	/* but may be used for enet */
	uint32_t			:22;
	uint32_t	pkey_indx	:7;

	uint32_t	cntr_idx	:8;
	uint32_t	grh		:1;
	uint32_t	mlid		:7;
	uint32_t	rlid		:16;

	uint32_t	ack_timeout	:5;
	uint32_t	link_type	:3;
	uint32_t			:1;
	uint32_t	mgid_index	:7;
	uint32_t			:4;
	uint32_t	max_stat_rate	:4;
	uint32_t	hop_limit	:8;

	uint32_t	sniff_r_out	:1;	/* sniff-rcv-egress */
	uint32_t	sniff_r_in	:1;
	uint32_t	sniff_s_out	:1;
	uint32_t	sniff_s_in	:1;
	uint32_t	tclass		:8;
	uint32_t	flow_label	:20;

	uint64_t	rgid_h;
	uint64_t	rgid_l;

	uint32_t	sched_q		:8;
	uint32_t			:1;
	uint32_t	vlan_idx	:7;
	uint32_t			:2;
	uint32_t	fsm		:1;
	uint32_t	fsip		:1;
	uint32_t	fvl		:1;
	uint32_t			:2;
	uint32_t	sp		:1;
	uint32_t			:8;	/* but may be used for enet */

	uint32_t			:4;
	uint32_t	log2_tbl_sz	:4;
	uint32_t	base_qpn	:24;

	uint32_t			:8;
	uint32_t	default_qpn	:24;

	uint32_t			:22;
	uint32_t	hash_fn		:2;
	uint32_t			:2;
	uint32_t	ipv4		:1;
	uint32_t	tcp_ipv4	:1;
	uint32_t	ipv6		:1;
	uint32_t	tcp_ipv6	:1;
	uint32_t			:2;

	uint8_t		rss_key[40];
};
#endif	/* LITTLE ENDIAN */

#if (DATAMODEL_NATIVE == DATAMODEL_LP64)
#pragma pack()
#endif

#if (DATAMODEL_NATIVE == DATAMODEL_LP64)
#pragma pack(4)
#endif
#ifdef	_LITTLE_ENDIAN
struct hermon_hw_qpc_s {
	uint32_t	pd		:24;
	uint32_t			:8;

	uint32_t			:11;
	uint32_t	pm_state	:2;
	uint32_t	rss		:1;
	uint32_t			:2;
	uint32_t	serv_type	:8;
	uint32_t			:4;
	uint32_t	state		:4;

	uint32_t	usr_page	:24;
	uint32_t			:8;

	uint32_t			:4;
	uint32_t	rlky		:1;
	uint32_t			:3;
	uint32_t	log_sq_stride	:3;
	uint32_t	log_sq_size	:4;
	uint32_t	sq_no_prefetch	:1;
	uint32_t	log_rq_stride	:3;
	uint32_t	log_rq_size	:4;
	uint32_t			:1;
	uint32_t	msg_max		:5;
	uint32_t	mtu		:3;

	uint32_t	rem_qpn		:24;
	uint32_t			:8;

	uint32_t	loc_qpn		:24;
	uint32_t			:8;

	hermon_hw_addr_path_t	pri_addr_path;

	hermon_hw_addr_path_t	alt_addr_path;

	uint32_t			:32;

	uint32_t			:5;
	uint32_t	cur_retry_cnt	:3;
	uint32_t	cur_rnr_retry	:3;
	uint32_t	fre		:1;
	uint32_t			:1;
	uint32_t	rnr_retry	:3;
	uint32_t	retry_cnt	:3;
	uint32_t			:2;
	uint32_t	sra_max		:3;
	uint32_t			:4;
	uint32_t	ack_req_freq	:4;

	uint32_t	cqn_snd		:24;
	uint32_t			:8;

	uint32_t	next_snd_psn	:24;
	uint32_t			:8;

	uint32_t			:32;

	uint32_t			:32;

	uint32_t	ssn		:24;
	uint32_t			:8;

	uint32_t	last_acked_psn	:24;
	uint32_t			:8;

	uint32_t	next_rcv_psn	:24;
	uint32_t	min_rnr_nak	:5;
	uint32_t			:3;

	uint32_t			:4;
	uint32_t	ric		:1;
	uint32_t			:1;
	uint32_t	page_offs	:6;
	uint32_t			:1;
	uint32_t	rae		:1;
	uint32_t	rwe		:1;
	uint32_t	rre		:1;
	uint32_t			:5;
	uint32_t	rra_max		:3;
	uint32_t			:8;

	uint32_t	cqn_rcv		:24;
	uint32_t			:8;

	uint32_t	xrcd		:16;
	uint32_t			:16;

	uint32_t			:2;
	uint32_t	dbr_addrl	:30;

	uint32_t	dbr_addrh	:32;

	uint32_t	srq_number	:24;
	uint32_t	srq_en		:1;
	uint32_t			:7;

	uint32_t	qkey;

	uint32_t	sq_wqe_counter	:16;
	uint32_t	rq_wqe_counter	:16;

	uint32_t	rmsn		:24;
	uint32_t			:8;

	uint32_t	rsrv0[2];

	/* new w/ hermon */

	uint32_t	base_mkey	:24;	/* bits 32-8, low 7 m/b 0 */
	uint32_t	num_rmc_peers	:8;

	uint32_t	rmc_parent_qpn	:24;
	uint32_t	header_sep	:1;
	uint32_t	inline_scatter  :1; 	/* m/b 0 for srq */
	uint32_t			:1;
	uint32_t	rmc_enable	:2;
	uint32_t			:2;	/* may use one bit for enet */
	uint32_t	mkey_remap	:1;

	uint32_t			:3;
	uint32_t	mtt_base_addrl	:29;

	uint32_t	mtt_base_addrh	:8;
	uint32_t			:16;
	uint32_t	log2_pgsz	:6;
	uint32_t			:2;

	uint32_t	exch_base	:16;
	uint32_t	exch_size	:4;
	uint32_t			:12;

	uint32_t	vft_vf_id	:12;
	uint32_t	vft_prior	:3;
	uint32_t			:16;
	uint32_t	ve		:1;

	uint32_t			:32;

	uint32_t			:16;
	uint32_t	my_fc_id_idx	:8;
	uint32_t	vft_hop_cnt	:8;

	uint32_t	rsvd[8];
};
#else /* BIG ENDIAN */
struct hermon_hw_qpc_s {
	uint32_t	state		:4;
	uint32_t			:4;
	uint32_t	serv_type	:8;
	uint32_t			:2;
	uint32_t	rss		:1;
	uint32_t	pm_state	:2;
	uint32_t			:11;

	uint32_t			:8;
	uint32_t	pd		:24;

	uint32_t	mtu		:3;
	uint32_t	msg_max		:5;
	uint32_t			:1;
	uint32_t	log_rq_size	:4;
	uint32_t	log_rq_stride	:3;
	uint32_t	sq_no_prefetch	:1;
	uint32_t	log_sq_size	:4;
	uint32_t	log_sq_stride	:3;
	uint32_t			:3;
	uint32_t	rlky		:1;
	uint32_t			:4;

	uint32_t			:8;
	uint32_t	usr_page	:24;

	uint32_t			:8;
	uint32_t	loc_qpn		:24;

	uint32_t			:8;
	uint32_t	rem_qpn		:24;

	hermon_hw_addr_path_t	pri_addr_path;

	hermon_hw_addr_path_t	alt_addr_path;

	uint32_t	ack_req_freq	:4;
	uint32_t			:4;
	uint32_t	sra_max		:3;
	uint32_t			:2;
	uint32_t	retry_cnt	:3;
	uint32_t	rnr_retry	:3;
	uint32_t			:1;
	uint32_t	fre		:1;
	uint32_t	cur_rnr_retry	:3;
	uint32_t	cur_retry_cnt	:3;
	uint32_t			:5;

	uint32_t			:32;

	uint32_t			:8;
	uint32_t	next_snd_psn	:24;

	uint32_t			:8;
	uint32_t	cqn_snd		:24;

	uint32_t			:32;

	uint32_t			:32;

	uint32_t			:8;
	uint32_t	last_acked_psn	:24;

	uint32_t			:8;
	uint32_t	ssn		:24;

	uint32_t			:8;
	uint32_t	rra_max		:3;
	uint32_t			:5;
	uint32_t	rre		:1;
	uint32_t	rwe		:1;
	uint32_t	rae		:1;
	uint32_t			:1;
	uint32_t	page_offs	:6;
	uint32_t			:1;
	uint32_t	ric		:1;
	uint32_t			:4;

	uint32_t			:3;
	uint32_t	min_rnr_nak	:5;
	uint32_t	next_rcv_psn	:24;

	uint32_t			:16;
	uint32_t	xrcd		:16;

	uint32_t			:8;
	uint32_t	cqn_rcv		:24;

	uint32_t	dbr_addrh	:32;

	uint32_t	dbr_addrl	:30;
	uint32_t			:2;

	uint32_t	qkey;

	uint32_t			:7;
	uint32_t	srq_en		:1;
	uint32_t	srq_number	:24;

	uint32_t			:8;
	uint32_t	rmsn		:24;

	uint32_t	rq_wqe_counter	:16;
	uint32_t	sq_wqe_counter	:16;

	uint32_t	rsrv0[2];

	/* new w/ hermon */

	uint32_t	mkey_remap	:1;
	uint32_t			:2;	/* may use one bit for enet */
	uint32_t	rmc_enable	:2;
	uint32_t			:1;
	uint32_t	inline_scatter  :1; 	/* m/b 0 for srq */
	uint32_t	header_sep	:1;
	uint32_t	rmc_parent_qpn	:24;

	uint32_t	num_rmc_peers	:8;
	uint32_t	base_mkey	:24;	/* bits 32-8, low 7 m/b 0 */

	uint32_t			:2;
	uint32_t	log2_pgsz	:6;
	uint32_t			:16;
	uint32_t	mtt_base_addrh	:8;

	uint32_t	mtt_base_addrl	:29;
	uint32_t			:3;

	uint32_t	ve		:1;
	uint32_t			:16;
	uint32_t	vft_prior	:3;
	uint32_t	vft_vf_id	:12;

	uint32_t			:12;
	uint32_t	exch_size	:4;
	uint32_t	exch_base	:16;

	uint32_t	vft_hop_cnt	:8;
	uint32_t	my_fc_id_idx	:8;
	uint32_t			:16;

	uint32_t			:32;

	uint32_t	rsvd[8];
};
#endif	/* LITTLE ENDIAN */

#if (DATAMODEL_NATIVE == DATAMODEL_LP64)
#pragma pack()
#endif

#define	HERMON_QP_RESET			0x0
#define	HERMON_QP_INIT			0x1
#define	HERMON_QP_RTR			0x2
#define	HERMON_QP_RTS			0x3
#define	HERMON_QP_SQERR			0x4
#define	HERMON_QP_SQD			0x5
#define	HERMON_QP_ERR			0x6
#define	HERMON_QP_SQDRAINING		0x7

#define	HERMON_QP_RC			0x0
#define	HERMON_QP_UC			0x1
#define	HERMON_QP_UD			0x3
#define	HERMON_QP_FCMND			0x4
#define	HERMON_QP_FEXCH			0x5
#define	HERMON_QP_XRC			0x6
#define	HERMON_QP_MLX			0x7
#define	HERMON_QP_RFCI			0x9

#define	HERMON_QP_PMSTATE_MIGRATED	0x3
#define	HERMON_QP_PMSTATE_ARMED		0x0
#define	HERMON_QP_PMSTATE_REARM		0x1

#define	HERMON_QP_DESC_EVT_DISABLED	0x0
#define	HERMON_QP_DESC_EVT_ENABLED	0x1

#define	HERMON_QP_FLIGHT_LIM_UNLIMITED	0xF

#define	HERMON_QP_SQ_ALL_SIGNALED	0x1
#define	HERMON_QP_SQ_WR_SIGNALED		0x0
#define	HERMON_QP_RQ_ALL_SIGNALED	0x1
#define	HERMON_QP_RQ_WR_SIGNALED		0x0

#define	HERMON_QP_SRQ_ENABLED	0x1
#define	HERMON_QP_SRQ_DISABLED	0x0

#define	HERMON_QP_WQE_BASE_SHIFT		0x6

/*
 * Hermon Multicast Group Member (MCG)
 *    Hermon MCG are organized in a virtually-contiguous memory table (the
 *    Multicast Group Table) in the ICM.  This table is
 *    actually comprised of two consecutive tables: the Multicast Group Hash
 *    Table (MGHT) and the Additional Multicast Group Members Table (AMGM).
 *    Each such entry contains an MGID and a list of QPs that are attached to
 *    the multicast group.  Each such entry may also include an index to an
 *    Additional Multicast Group Member Table (AMGM) entry.  The AMGMs are
 *    used to form a linked list of MCG entries that all map to the same hash
 *    value.  The MCG entry size is configured through the INIT_HCA command.
 *    Note:  An MCG actually consists of a single hermon_hw_mcg_t and some
 *    number of hermon_hw_mcg_qp_list_t (such that the combined structure is a
 *    power-of-2).
 *
 *    The following structures are used in the READ_MGM and WRITE_MGM commands.
 *    The READ_MGM command reads an MCG entry from the multicast table and
 *    returns it in the output mailbox.  Note: This operation does not affect
 *    the MCG entry state or values.
 *    The WRITE_MGM command retrieves an MCG entry from the input mailbox and
 *    stores it in the multicast group table at the index specified in the
 *    command.  Once the command has finished execution, the multicast group
 *    table is updated.  The old entry contents are lost.
 */
#ifdef	_LITTLE_ENDIAN
struct hermon_hw_mcg_s {
	uint32_t	member_cnt	:24;
	uint32_t			:6;
	uint32_t	protocol	:2;

	uint32_t			:6;
	uint32_t	next_gid_indx	:26;

	uint32_t			:32;
	uint32_t			:32;

	uint64_t	mgid_h;
	uint64_t	mgid_l;
};
#else
struct hermon_hw_mcg_s {
	uint32_t	next_gid_indx	:26;
	uint32_t			:6;

	uint32_t	protocol	:2;
	uint32_t			:6;
	uint32_t	member_cnt	:24;

	uint32_t			:32;
	uint32_t			:32;

	uint64_t	mgid_h;
	uint64_t	mgid_l;
};
#endif

#ifdef	_LITTLE_ENDIAN
struct hermon_hw_mcg_en_s {
	uint32_t	member_cnt	:24;
	uint32_t			:6;
	uint32_t	protocol	:2;

	uint32_t			:6;
	uint32_t	next_gid_indx	:26;

	uint32_t			:32;
	uint32_t			:32;

	uint32_t	vlan_present	:1;
	uint32_t			:31;

	uint32_t			:32;

	uint32_t	mac_lo		:32;

	uint32_t	mac_hi		:16;
	uint32_t	vlan_id		:12;
	uint32_t	vlan_cfi	:1;
	uint32_t	vlan_prior	:3;

};
#else
struct hermon_hw_mcg_en_s {
	uint32_t	next_gid_indx	:26;
	uint32_t			:6;

	uint32_t	protocol	:2;
	uint32_t			:6;
	uint32_t	member_cnt	:24;

	uint32_t			:32;
	uint32_t			:32;

	uint32_t			:32;

	uint32_t			:31;
	uint32_t	vlan_present	:1;

	uint32_t	vlan_prior	:3;
	uint32_t	vlan_cfi	:1;
	uint32_t	vlan_id		:12;
	uint32_t	mac_hi		:16;

	uint32_t	mac_lo		:32;

};
#endif


/* Multicast Group Member - QP List entries */
#ifdef	_LITTLE_ENDIAN
struct hermon_hw_mcg_qp_list_s {
	uint32_t	qpn		:24;
	uint32_t			:6;
	uint32_t	blk_lb		:1;
	uint32_t			:1;
};
#else
struct hermon_hw_mcg_qp_list_s {
	uint32_t			:1;
	uint32_t	blk_lb		:1;
	uint32_t			:6;
	uint32_t	qpn		:24;
};
#endif

#define	HERMON_MCG_QPN_BLOCK_LB		0x40000000

/*
 * ETHERNET ONLY Commands
 * The follow are new commands, used only for an Ethernet Port
 */

#ifdef _LITTLE_ENDIAN
struct hermon_hw_set_mcast_fltr_s {
	uint32_t	mac_lo;

	uint32_t	mac_hi		:16;
	uint32_t			:15;
	uint32_t	sfs		:1;
};
#else	/* BIG ENDIAN */
struct hermon_hw_set_mcast_fltr_s {
	uint32_t	sfs		:1;
	uint32_t			:15;
	uint32_t	mac_hi		:16;

	uint32_t	mac_lo;
};
#endif

/* opmod for set_mcast_fltr */
#define	HERMON_SET_MCAST_FLTR_CONF	0x0
#define	HERMON_SET_MCAST_FLTR_DIS	0x1
#define	HERMON_SET_MCAST_FLTR_EN	0x2


/*
 * FC Command structures
 */



#ifdef _LITTLE_ENDIAN
struct hermon_hw_config_fc_basic_s {
	uint32_t	n_p		:2;
	uint32_t			:6;
	uint32_t	n_v		:3;
	uint32_t			:5;
	uint32_t	n_m		:4;
	uint32_t			:12;

	uint32_t			:16;
	uint32_t	fexch_base_hi	:8;
	uint32_t			:8;

	uint32_t	rfci_base	:24;
	uint32_t	log2_num_rfci	:3;
	uint32_t			:5;

	uint32_t	fx_base_mpt_lo	:8;
	uint32_t			:17;
	uint32_t	fx_base_mpt_hi	:7;

	uint32_t	fcoe_prom_qpn	:24;
	uint32_t	uint32_t	:8;

	uint32_t			:32;

	uint32_t	rsrv[58];
};
#else
struct hermon_hw_config_fc_basic_s {
	uint32_t			:8;
	uint32_t	fexch_base_hi	:8;
	uint32_t			:16;

	uint32_t			:12;
	uint32_t	n_m		:4;
	uint32_t			:5;
	uint32_t	n_v		:3;
	uint32_t			:6;
	uint32_t	n_p		:2;

	uint32_t	fx_base_mpt_hi	:7;
	uint32_t			:17;
	uint32_t	fx_base_mpt_lo	:8;

	uint32_t			:5;
	uint32_t	log2_num_rfci	:3;
	uint32_t	rfci_base	:24;

	uint32_t			:32;

	uint32_t	uint32_t	:8;
	uint32_t	fcoe_prom_qpn	:24;

	uint32_t	rsrv[58];
};
#endif

#define	HERMON_HW_FC_PORT_ENABLE	0x0
#define	HERMON_HW_FC_PORT_DISABLE	0x1
#define	HERMON_HW_FC_CONF_BASIC		0x0000
#define	HERMON_HW_FC_CONF_NPORT		0x0100

#ifdef _LITTLE_ENDIAN
struct hermon_hw_query_fc_s {
	uint32_t			:32;

	uint32_t	log2_max_rfci	:3;
	uint32_t			:5;
	uint32_t	log2_max_fexch	:5;
	uint32_t			:3;
	uint32_t	log2_max_nports	:3;
	uint32_t			:13;

	uint32_t	rsrv[62];
};
#else
struct hermon_hw_query_fc_s {
	uint32_t			:13;
	uint32_t	log2_max_nports	:3;
	uint32_t			:3;
	uint32_t	log2_max_fexch	:5;
	uint32_t			:5;
	uint32_t	log2_max_rfci	:3;

	uint32_t			:32;

	uint32_t	rsrv[62];
};
#endif




/* ARM_RQ - limit water mark for srq & rq */
#ifdef _LITTLE_ENDIAN
struct hermon_hw_arm_req_s {
	uint32_t	lwm		:16;
	uint32_t			:16;

	uint32_t			:32;
};
#else
struct hermon_hw_arm_req_s {
	uint32_t			:32;

	uint32_t			:16;
	uint32_t	lwm		:16;
};
#endif

/*
 * Structure for getting the peformance counters from the HCA
 */

#ifdef _LITTLE_ENDIAN
struct hermon_hw_sm_perfcntr_s {
	uint32_t	linkdown	:8;
	uint32_t	linkerrrec	:8;
	uint32_t	symerr		:16;

	uint32_t	cntrsel		:16;
	uint32_t	portsel		:8;
	uint32_t			:8;

	uint32_t	portxmdiscard	:16;
	uint32_t	portrcvswrelay	:16;

	uint32_t	portrcvrem	:16;
	uint32_t	portrcv		:16;

	uint32_t	vl15drop	:16;
	uint32_t			:16;

	uint32_t	xsbuffovrun	:4;
	uint32_t	locallinkint	:4;
	uint32_t			:8;
	uint32_t	portrcconstr	:8;
	uint32_t	portxmconstr	:8;

	uint32_t	portrcdata;

	uint32_t	portxmdata;

	uint32_t	portrcpkts;

	uint32_t	portxmpkts;

	uint32_t	reserved;

	uint32_t	portxmwait;
};
#else	/* BIG ENDIAN */
struct hermon_hw_sm_perfcntr_s {
	uint32_t			:8;
	uint32_t	portsel		:8;
	uint32_t	cntrsel		:16;

	uint32_t	symerr		:16;
	uint32_t	linkerrrec	:8;
	uint32_t	linkdown	:8;

	uint32_t	portrcv		:16;
	uint32_t	portrcvrem	:16;

	uint32_t	portrcvswrelay	:16;
	uint32_t	portxmdiscard	:16;

	uint32_t	portxmconstr	:8;
	uint32_t	portrcconstr	:8;
	uint32_t			:8;
	uint32_t	locallinkint	:4;
	uint32_t	xsbuffovrun	:4;

	uint32_t			:16;
	uint32_t	vl15drop	:16;

	uint32_t	portxmdata;

	uint32_t	portrcdata;

	uint32_t	portxmpkts;

	uint32_t	portrcpkts;

	uint32_t	portxmwait;

	uint32_t	reserved;
};
#endif

/*
 * Structure for getting the extended peformance counters from the HCA
 */

#ifdef _LITTLE_ENDIAN
struct hermon_hw_sm_extperfcntr_s {
	uint32_t	rsvd;
	uint32_t	cntrsel		:16;
	uint32_t	portsel		:8;
	uint32_t			:8;

	uint64_t	portxmdata;

	uint64_t	portrcdata;

	uint64_t	portxmpkts;

	uint64_t	portrcpkts;

	uint64_t	portunicastxmpkts;

	uint64_t	portunicastrcpkts;

	uint64_t	portmulticastxmpkts;

	uint64_t	portmulticastrcpkts;
};
#else	/* BIG ENDIAN */
struct hermon_hw_sm_extperfcntr_s {
	uint32_t			:8;
	uint32_t	portsel		:8;
	uint32_t	cntrsel		:16;
	uint32_t	rsvd;

	uint64_t	portxmdata;

	uint64_t	portrcdata;

	uint64_t	portxmpkts;

	uint64_t	portrcpkts;

	uint64_t	portunicastxmpkts;

	uint64_t	portunicastrcpkts;

	uint64_t	portmulticastxmpkts;

	uint64_t	portmulticastrcpkts;
};
#endif


/*
 * Hermon User Access Region (UAR)
 *
 *	JBDB :  writeup on the UAR for memfree
 *
 *	JBDB :  writeup on the structures
 *		UAR page
 *		DB register
 *		DB record
 *		UCE
 *
 * [es] and change it even further for hermon
 * the whole UAR and doorbell record (dbr) approach is changed again
 * from arbel, and needs commenting
 *
 * --  Tavor comment
 *
 *
 *    Tavor doorbells are each rung by writing to the doorbell registers that
 *    form a User Access Region (UAR).  A doorbell is a write-only hardware
 *    register which enables passing information from software to hardware
 *    with minimum software latency. A write operation from the host software
 *    to these doorbell registers passes information about the HCA resources
 *    and initiates processing of the doorbell data.  There are 6 types of
 *    doorbells in Tavor.
 *
 *    "Send Doorbell" for synchronizing the attachment of a WQE (or a chain
 *	of WQEs) to the send queue.
 *    "RD Send Doorbell" (Same as above, except for RD QPs) is not supported.
 *    "Receive Doorbell" for synchronizing the attachment of a WQE (or a chain
 *	of WQEs) to the receive queue.
 *    "CQ Doorbell" for updating the CQ consumer index and requesting
 * 	completion notifications.
 *    "EQ Doorbell" for updating the EQ consumer index, arming interrupt
 *	triggering, and disarming CQ notification requests.
 *    "InfiniBlast" (which would have enabled access to the "InfiniBlast
 *	buffer") is not supported.
 *
 *    Note: The tavor_hw_uar_t below is the container for all of the various
 *    doorbell types.  Below we first define several structures which make up
 *    the contents of those doorbell types.
 *
 *    Note also: The following structures are not #define'd with both little-
 *    endian and big-endian definitions.  This is because each doorbell type
 *    is not directly accessed except through a single ddi_put64() operation
 *    (see tavor_qp_send_doorbell, tavor_qp_recv_doorbell, tavor_cq_doorbell,
 *    or tavor_eq_doorbell)
 */

/*
 * Send doorbell register structure
 */
typedef struct hermon_hw_send_db_reg_s {
	uint32_t			:32;

	uint32_t	snd_q_num	:24;
	uint32_t			:8;
} hermon_hw_send_db_reg_t;

#define	HERMON_QPSNDDB_QPN_SHIFT		0x8

/* Max descriptors per Hermon doorbell */
#define	HERMON_QP_MAXDESC_PER_DB		256

/*
 * CQ doorbell register structure
 */
typedef struct hermon_hw_cq_db_reg_s {
	uint32_t			:2;
	uint32_t	cmd_sn		:2;
	uint32_t			:2;
	uint32_t	cmd		:2;
	uint32_t	cqn		:24;

	uint32_t			:8;
	/* consumer cntr of last polled completion */
	uint32_t	cq_ci		:24;
} hermon_hw_cq_db_reg_t;

#define	HERMON_CQDB_CMD_SHIFT		0x18	/* dec 24 */
#define	HERMON_CQDB_CMDSN_SHIFT		0x1C	/* dec 28 */


#define	HERMON_CQDB_NOTIFY_CQ		0x02
#define	HERMON_CQDB_NOTIFY_CQ_SOLICIT	0x01

/* Default value for use in NOTIFY_CQ doorbell */
#define	HERMON_CQDB_DEFAULT_PARAM	0xFFFFFFFF

typedef struct hermon_hw_guest_eq_ci_s {	/* guest op eq consumer index */
	uint32_t	armed		:1;
	uint32_t			:7;
	uint32_t	guestos_ci	:24;

	uint32_t			:32;
} hermon_hw_guest_eq_ci_t;



/*
 * UAR page structure, containing all doorbell registers
 */
struct hermon_hw_uar_s {
	uint32_t		rsrv0[4];

	hermon_hw_send_db_reg_t	send;

	uint32_t		rsrv1[2];

	hermon_hw_cq_db_reg_t	cq;

	uint32_t		rsrv2[502];	/* next is at offset 0x800 */

	hermon_hw_guest_eq_ci_t	g_eq0;
	hermon_hw_guest_eq_ci_t	g_eq1;
	hermon_hw_guest_eq_ci_t	g_eq2;
	hermon_hw_guest_eq_ci_t	g_eq3;

	uint32_t		rsrv3[504];	/* end of page */
};

/*
 * QP (RQ, SRQ) doorbell record-specific data
 *	Note that this structure is NOT in ICM, but just kept in host memory
 *	and managed independently of PRM or other constraints.  Also, though
 *	the qp/srq doorbell need to be only 4 bytes, it is 8 bytes in memory for
 *	ease of management.  Hermon defines its usage in the QP chapter.
 */
typedef struct hermon_hw_qp_db_s {
	uint32_t			:16;
	uint32_t	rcv_wqe_cntr	:16;	/* wqe_counter */

	uint32_t			:32;
} hermon_hw_qp_db_t;

/*
 * CQ (ARM and SET_CI) doorbell record-specific data
 *	See comment above re: QP doorbell.  This dbr is 8 bytes long, and its
 *	usage is defined in PRM chapter on Completion Queues
 */
typedef struct hermon_hw_cq_arm_db_s {
	uint32_t			:8;
	uint32_t	update_ci	:24;

	uint32_t			:2;
	/* sequence number of the doorbell ring % 4 */
	uint32_t	cmd_sn		:2;
	uint32_t			:1;
	uint32_t	cmd		:3;	/* command */
	uint32_t	cq_ci		:24;
} hermon_hw_cq_db_t;

#define	HERMON_CQ_DB_CMD_SOLICTED	0x01
#define	HERMON_CQ_DB_CMD_NEXT		0x02


/*
 * Hermon Blue Flame (BF)
 *	Hermon has the ability to do a low-latency write of successive WQEs
 * 	for the HCA.  This utilizes part of the memory area behind the
 *	same BAR as the UAR page (see above) - half the area is devoted to
 *	UAR pages, the other half to BlueFlame (though in fairness, the return
 * 	information from QUERY_DEV_CAP should be consulted _in case_ they ever
 *	decide to change it.
 *
 *	We define the structures to access them below.
 */


/*
 * Hermon Send Work Queue Element (WQE)
 *    A Hermon Send WQE is built of the following segments, each of which is a
 *    multiple of 16 bytes.  Note: Each individual WQE may contain only a
 *    subset of these segments described below (according to the operation type
 *    and transport type of the QP).
 *
 *    The first 16 bytes of ever WQE are formed from the "Ctrl" segment.
 *    This segment contains the address of the next WQE to be executed and the
 *    information required in order to allocate the resources to execute the
 *    next WQE.  The "Ctrl" part of this segment contains the control
 *    information required to execute the WQE, including the opcode and other
 *    control information.
 *    The "Datagram" segment contains address information required in order to
 *    form a UD message.
 *    The "Bind" segment contains the parameters required for a Bind Memory
 *    Window operation.
 *    The "Remote Address" segment is present only in RDMA or Atomic WQEs and
 *    specifies remote virtual addresses and RKey, respectively.  Length of
 *    the remote access is calculated from the scatter/gather list (for
 *    RDMA-write/RDMA-read) or set to eight (for Atomic).
 *    The "Atomic" segment is present only in Atomic WQEs and specifies
 *    Swap/Add and Compare data.
 *
 *    Note: The following structures are not #define'd with both little-endian
 *    and big-endian definitions.  This is because their individual fields are
 *    not directly accessed except through macros defined below.
 */


struct hermon_hw_snd_wqe_ctrl_s {
	uint32_t	owner		:1;
	uint32_t			:1;
	uint32_t	nec		:1;
	uint32_t			:5;
	uint32_t	fceof		:8;
	uint32_t			:9;
	uint32_t	rr		:1;
	uint32_t			:1;
	uint32_t	opcode		:5;

	uint32_t	vlan		:16;
	uint32_t			:1;
	uint32_t	cv		:1;
	uint32_t			:7;
	uint32_t	fence		:1;
	uint32_t	ds		:6;	/* WQE size in octowords */

	/*
	 * XRC remote buffer if impl
	 * XRC 23:0, or DMAC 47:32& 8 bits of pad
	 */
	uint32_t	xrc_rem_buf	:24;
	uint32_t	so		:1;
	uint32_t	fcrc		:1;	/* fc crc calc */
	uint32_t	tcp_udp		:1;	/* Checksumming */
	uint32_t	ip		:1;	/* Checksumming */
	uint32_t	cq_gen		:2;	/* 00=no cqe, 11= gen cqe */
	/* s-bit set means solicit bit in last packet */
	uint32_t	s		:1;
	uint32_t	force_lb	:1;

	/*
	 * immediate OR invalidation key OR DMAC 31:0 depending
	 */
	uint32_t	immediate	:32;
};

struct hermon_hw_srq_wqe_next_s {
	uint32_t			:16;
	uint32_t	next_wqe_idx	:16;

	uint32_t	rsvd[3];
};


struct hermonw_hw_fcp3_ctrl_s {
	uint32_t	owner		:1;
	uint32_t			:1;
	uint32_t	nec		:1;
	uint32_t			:24;
	uint32_t	opcode		:5;

	uint32_t			:24;
	uint32_t	sit		:1;
	uint32_t			:1;
	uint32_t	ds		:6;

	uint32_t	seq_id		:8;
	uint32_t	info		:4;
	uint32_t			:3;
	uint32_t	ls		:1;
	uint32_t			:8;
	uint32_t	so		:1;
	uint32_t			:3;
	uint32_t	cq_gen		:2;
	uint32_t			:2;

	uint32_t	param		:32;
};

struct hermon_hw_fcp3_init_s {
	uint32_t			:8;
	uint32_t	pe		:1;
	uint32_t			:23;

	uint32_t	csctl_prior	:8;
	uint32_t	seqid_tx	:8;
	uint32_t			:6;
	uint32_t	mtu		:10;

	uint32_t	rem_id		:24;
	uint32_t	abort		:2;
	uint32_t			:1;
	uint32_t	op		:2;
	uint32_t			:1;
	uint32_t	org		:1;
	uint32_t			:1;

	uint32_t	rem_exch	:16;
	uint32_t	loc_exch_idx	:16;
};

struct hermon_hw_fcmd_o_enet_s {
	uint32_t			:4;
	uint32_t	stat_rate	:4;
	uint32_t			:24;

	uint32_t			:32;

	uint32_t			:16;
	uint32_t	dmac_hi		:16;

	uint32_t	dmac_lo		:32;
};

struct hermon_hw_fcmd_o_ib_s {
	uint32_t			:32;

	uint32_t			:8;
	uint32_t	grh		:1;
	uint32_t			:7;
	uint32_t	rlid		:16;

	uint32_t			:20;
	uint32_t	stat_rate	:4;
	uint32_t	hop_limit	:8;

	uint32_t	sl		:4;
	uint32_t	tclass		:8;
	uint32_t	flow_label	:20;

	uint64_t	rgid_hi;

	uint64_t	rgid_lo;

	uint32_t			:8;
	uint32_t	rqp		:24;

	uint32_t	rsrv[3];
};





#define	HERMON_WQE_SEND_FENCE_MASK	0x40

#define	HERMON_WQE_SEND_NOPCODE_NOP	0x00
#define	HERMON_WQE_SEND_NOPCODE_SND_INV 0x01
#define	HERMON_WQE_SEND_NOPCODE_RDMAW	0x8
#define	HERMON_WQE_SEND_NOPCODE_RDMAWI	0x9
#define	HERMON_WQE_SEND_NOPCODE_SEND	0xA
#define	HERMON_WQE_SEND_NOPCODE_SENDI	0xB
#define	HERMON_WQE_SEND_NOPCODE_INIT_AND_SEND 0xD
#define	HERMON_WQE_SEND_NOPCODE_LSO	0xE
#define	HERMON_WQE_SEND_NOPCODE_RDMAR	0x10
#define	HERMON_WQE_SEND_NOPCODE_ATMCS	0x11
#define	HERMON_WQE_SEND_NOPCODE_ATMFA	0x12
#define	HERMON_WQE_SEND_NOPCODE_ATMCSE 0x14
#define	HERMON_WQE_SEND_NOPCODE_ATMFAE 0x15
#define	HERMON_WQE_SEND_NOPCODE_BIND	0x18
#define	HERMON_WQE_SEND_NOPCODE_FRWR	0x19
#define	HERMON_WQE_SEND_NOPCODE_LCL_INV 0x1B
#define	HERMON_WQE_SEND_NOPCODE_CONFIG 0x1F		/* for ccq only */

#define	HERMON_WQE_FCP_OPCODE_INIT_AND_SEND 0xD
#define	HERMON_WQE_FCP_OPCODE_INIT_FEXCH  0xC

#define	HERMON_WQE_SEND_SIGNALED_MASK	0x0000000C00000000ull
#define	HERMON_WQE_SEND_SOLICIT_MASK	0x0000000200000000ull
#define	HERMON_WQE_SEND_IMMEDIATE_MASK	0x0000000100000000ull

struct hermon_hw_snd_wqe_ud_s {
	struct hermon_hw_udav_s		ud_addr_v;

	uint32_t			:8;
	uint32_t	dest_qp		:24;

	uint32_t	qkey		:32;

	uint32_t	vlan		:16;
	uint32_t	dmac_hi		:16;

	uint32_t	dmac_lo		:32;
};
#define	HERMON_WQE_SENDHDR_UD_AV_MASK	0xFFFFFFFFFFFFFFE0ull
#define	HERMON_WQE_SENDHDR_UD_DQPN_MASK	0xFFFFFF

struct hermon_hw_snd_wqe_bind_s {
	uint32_t	ae		:1;
	uint32_t	rw		:1;
	uint32_t	rr		:1;
	uint32_t			:3;
	uint32_t	l_64		:1;
	uint32_t			:25;

	uint32_t	win_t		:1;
	uint32_t	z_base		:1;
	uint32_t			:30;

	uint32_t	new_rkey;
	uint32_t	reg_lkey;
	uint64_t	addr;
	uint64_t	len;
};
#define	HERMON_WQE_SENDHDR_BIND_ATOM	0x8000000000000000ull
#define	HERMON_WQE_SENDHDR_BIND_WR	0x4000000000000000ull
#define	HERMON_WQE_SENDHDR_BIND_RD	0x2000000000000000ull

struct hermon_hw_snd_wqe_lso_s {
	uint32_t	mss		:16;
	uint32_t			:6;
	uint32_t	hdr_size	:10;
};

struct hermon_hw_snd_wqe_remaddr_s {
	uint64_t	vaddr;
	uint32_t	rkey;
	uint32_t			:32;
};

struct hermon_hw_snd_wqe_atomic_s {
	uint64_t	swap_add;
	uint64_t	compare;
};

struct hermon_hw_snd_wqe_atomic_ext_s {
	uint64_t	swap_add;
	uint64_t	compare;
	uint64_t	swapmask;
	uint64_t	cmpmask;
};

struct hermon_hw_snd_wqe_local_inv_s {
	uint32_t			:6;
	uint32_t	atc_shoot	:1;
	uint32_t			:25;

	uint32_t			:32;

	uint32_t	mkey;

	uint32_t	rsrv0;

	uint32_t	rsrv1;
	uint32_t			:25;
	uint32_t	guest_id	:7;	/* for atc shootdown */

	uint32_t	p_addrh;
	uint32_t	p_addrl		:23;
	uint32_t			:9;
};

struct hermon_hw_snd_rem_addr_s {
	uint64_t	rem_vaddr;

	uint32_t	rkey;
	uint32_t	rsrv;
};


struct hermon_hw_snd_wqe_frwr_s {
	uint32_t	rem_atomic	:1;
	uint32_t	rem_write	:1;
	uint32_t	rem_read	:1;
	uint32_t	loc_write	:1;
	uint32_t	loc_read	:1;
	uint32_t	fbo_en		:1;
	uint32_t	len_64		:1;
	uint32_t			:2;
	uint32_t	dif		:1;	/* FCoIB */
	uint32_t	bind_en		:1;
	uint32_t	blk_pg_mode	:1;
	uint32_t	mtt_rep		:4;
	uint32_t			:16;

	uint32_t	mkey;		/* swapped w/ addrh relative to arbel */

	uint64_t	pbl_addr;

	uint64_t	start_addr;

	uint64_t	reg_len;	/* w/ len_64 allows 65 bits of length */

	uint32_t			:11;
	uint32_t	fbo		:21;

	uint32_t			:11;
	uint32_t	pge_blk_sz	:21;

	uint32_t	rsrv0[2];
};

struct hermon_hw_snd_wqe_frwr_ext_s {
	uint32_t	dif_in_mem	:1;
	uint32_t	dif_on_wire	:1;
	uint32_t	valid_ref	:1;
	uint32_t	valid_crc	:1;
	uint32_t	repl_ref_tag	:1;
	uint32_t	repl_app_tag	:1;
	uint32_t			:10;
	uint32_t	app_mask	:16;

	uint32_t	wire_app_tag	:16;
	uint32_t	mem_app_tag	:16;

	uint32_t	wire_ref_tag_base;

	uint32_t	mem_ref_tag_base;
};



/*
 * Hermon "MLX transport" Work Queue Element (WQE)
 *    The format of the MLX WQE is similar to that of the Send WQE (above)
 *    with the following exceptions.  MLX WQEs are used for sending MADs on
 *    special QPs 0 and 1.  Everything following the "Next/Ctrl" header
 *    (defined below) consists of scatter-gather list entries.  The contents
 *    of these SGLs (also defined below) will be put on the wire exactly as
 *    they appear in the buffers.  In addition, the VCRC and the ICRC of each
 *    sent packet can be modified by changing values in the following header
 *    or in the payload of the packet itself.
 */


struct hermon_hw_mlx_wqe_nextctrl_s {
	uint32_t	owner		:1;
	uint32_t			:23;
	uint32_t			:3;
	uint32_t	opcode		:5;	/* is 0x0A (send) for MLX */

	uint32_t			:26;
	uint32_t	ds		:6;	/* WQE size in octowords */

	uint32_t			:14;
	uint32_t	vl15		:1;
	uint32_t	slr		:1;
	uint32_t	max_srate	:4;
	uint32_t	sl		:4;
	uint32_t			:3;	/* FCoIB usage */
	uint32_t	icrc		:1;	/* 1==don't replace icrc fld */
	uint32_t	cq_gen		:2;	/* 00= no cqe, 11==cqe */
	uint32_t			:1;
	uint32_t	force_lb	:1;

	uint32_t	rlid		:16;
	uint32_t			:16;
};


#define	HERMON_WQE_MLXHDR_VL15_MASK	0x0002000000000000ull
#define	HERMON_WQE_MLXHDR_SLR_MASK	0x0001000000000000ull
#define	HERMON_WQE_MLXHDR_SRATE_SHIFT	44
#define	HERMON_WQE_MLXHDR_SL_SHIFT	40
#define	HERMON_WQE_MLXHDR_SIGNALED_MASK	0x0000000800000000ull
#define	HERMON_WQE_MLXHDR_RLID_SHIFT	16


/*
 * Hermon Receive Work Queue Element (WQE)
 *    Unlike the Send WQE, the Receive WQE is built ONLY of 16-byte segments. A
 *    "Next/Ctrl" segment is no longer needed, because of the fixed
 *	receive queue stride (RQ.STRIDE).  It contains just
 *    some number of scatter list entries for the incoming message.
 *
 *    The format of the scatter-gather list entries is shown below.  For
 *    Receive WQEs the "inline_data" field must be cleared (i.e. data segments
 *    cannot contain inline data).
 */


struct hermon_hw_wqe_sgl_s {
	uint32_t	inline_data	:1;
	uint32_t	byte_cnt	:31;

	uint32_t	lkey;

	uint64_t	addr;
};
#define	HERMON_WQE_SGL_BYTE_CNT_MASK	0x7FFFFFFF
#define	HERMON_WQE_SGL_INLINE_MASK	0x80000000

/*
 * The following defines are used when building descriptors for special QP
 * work requests (i.e. MLX transport WQEs).  Note: Because Hermon MLX transport
 * requires the driver to build actual IB packet headers, we use these defines
 * for the most common fields in those headers.
 */


#define	HERMON_MLX_VL15_LVER		0xF0000000
#define	HERMON_MLX_VL0_LVER		0x00000000
#define	HERMON_MLX_IPVER_TC_FLOW	0x60000000
#define	HERMON_MLX_TC_SHIFT		20
#define	HERMON_MLX_DEF_PKEY		0xFFFF
#define	HERMON_MLX_GSI_QKEY		0x80010000
#define	HERMON_MLX_UDSEND_OPCODE	0x64000000
#define	HERMON_MLX_DQPN_MASK		0xFFFFFF

/*
 * The following macros are used for building each of the individual
 * segments that can make up a Hermon WQE.  Note: We try not to use the
 * structures (with their associated bitfields) here, instead opting to
 * build and put 64-bit or 32-bit chunks to the WQEs as appropriate,
 * primarily because using the bitfields appears to force more read-modify-
 * write operations.
 *
 *    HERMON_WQE_BUILD_UD		- Builds Unreliable Datagram Segment
 *
 *    HERMON_WQE_BUILD_REMADDR		- Builds Remote Address Segment using
 *					    RDMA info from the work request
 *    HERMON_WQE_BUILD_RC_ATOMIC_REMADDR	- Builds Remote Address Segment
 *					    for RC Atomic work requests
 *    HERMON_WQE_BUILD_ATOMIC		- Builds Atomic Segment using atomic
 *					    info from the work request
 *    HERMON_WQE_BUILD_BIND		- Builds the Bind Memory Window
 *					    Segment using bind info from the
 *					    work request
 *    HERMON_WQE_BUILD_DATA_SEG		- Builds the individual Data Segments
 *					    for Send, Receive, and MLX WQEs
 *    HERMON_WQE_BUILD_INLINE		- Builds an "inline" Data Segment
 *					    (primarily for MLX transport)
 *    HERMON_WQE_BUILD_INLINE_ICRC	- Also builds an "inline" Data Segment
 *					    (but used primarily in the ICRC
 *					    portion of MLX transport WQEs)
 *    HERMON_WQE_LINKNEXT		- Links the current WQE to the
 *					    previous one
 *    HERMON_WQE_LINKFIRST		- Links the first WQE on the current
 *					    chain to the previous WQE
 *    HERMON_WQE_BUILD_MLX_LRH		- Builds the inline LRH header for
 *					    MLX transport MADs
 *    HERMON_WQE_BUILD_MLX_GRH		- Builds the inline GRH header for
 *					    MLX transport MADs
 *    HERMON_WQE_BUILD_MLX_BTH		- Builds the inline BTH header for
 *					    MLX transport MADs
 *    HERMON_WQE_BUILD_MLX_DETH		- Builds the inline DETH header for
 *					    MLX transport MADs
 */
#define	HERMON_WQE_BUILD_UD(qp, ud, ah, dest)				\
{									\
	uint64_t		*tmp;					\
	uint64_t		*udav;					\
									\
	tmp	= (uint64_t *)(ud);					\
	udav	= (uint64_t *)(ah)->ah_udav;				\
	tmp[0]	= ntohll(udav[0]);					\
	tmp[1]	= ntohll(udav[1]);					\
	tmp[2]	= ntohll(udav[2]);					\
	tmp[3]	= ntohll(udav[3]);					\
	tmp[4]	= ntohll((((uint64_t)((dest)->ud_dst_qpn &		\
	    HERMON_WQE_SENDHDR_UD_DQPN_MASK) << 32) |			\
	    (dest)->ud_qkey));						\
	tmp[5] = 0;							\
}

#define	HERMON_WQE_BUILD_LSO(qp, ds, mss, hdr_sz)			\
	*(uint32_t *)(ds) = htonl(((mss) << 16) | hdr_sz);

#define	HERMON_WQE_BUILD_REMADDR(qp, ra, wr_rdma)			\
{									\
	uint64_t		*tmp;					\
									\
	tmp	= (uint64_t *)(ra);					\
	tmp[0] = htonll((wr_rdma)->rdma_raddr);				\
	tmp[1] = htonll((uint64_t)(wr_rdma)->rdma_rkey << 32);		\
}

#define	HERMON_WQE_BUILD_RC_ATOMIC_REMADDR(qp, rc, wr)			\
{									\
	uint64_t		*tmp;					\
									\
	tmp	= (uint64_t *)(rc);					\
	tmp[0] = htonll((wr)->wr.rc.rcwr.atomic->atom_raddr);		\
	tmp[1] = htonll((uint64_t)(wr)->wr.rc.rcwr.atomic->atom_rkey << 32); \
}

#define	HERMON_WQE_BUILD_ATOMIC(qp, at, wr_atom)			\
{									\
	uint64_t		*tmp;					\
									\
	tmp	= (uint64_t *)(at);					\
	tmp[0] = htonll((wr_atom)->atom_arg2);				\
	tmp[1] = htonll((wr_atom)->atom_arg1);				\
}

#define	HERMON_WQE_BUILD_BIND(qp, bn, wr_bind)				\
{									\
	uint64_t		*tmp;					\
	uint64_t		bn0_tmp;				\
	ibt_bind_flags_t	bind_flags;				\
									\
	tmp	   = (uint64_t *)(bn);					\
	bind_flags = (wr_bind)->bind_flags;				\
	bn0_tmp	   = (bind_flags & IBT_WR_BIND_ATOMIC) ?		\
	    HERMON_WQE_SENDHDR_BIND_ATOM : 0;				\
	bn0_tmp	  |= (bind_flags & IBT_WR_BIND_WRITE) ?			\
	    HERMON_WQE_SENDHDR_BIND_WR : 0;				\
	bn0_tmp	  |= (bind_flags & IBT_WR_BIND_READ) ?			\
	    HERMON_WQE_SENDHDR_BIND_RD : 0;				\
	tmp[0] = htonll(bn0_tmp);					\
	tmp[1] = htonll(((uint64_t)(wr_bind)->bind_rkey_out << 32) |	\
	    (wr_bind)->bind_lkey);					\
	tmp[2] = htonll((wr_bind)->bind_va);				\
	tmp[3] = htonll((wr_bind)->bind_len);				\
}

#define	HERMON_WQE_BUILD_FRWR(qp, frwr_arg, pmr_arg)			\
{									\
	ibt_mr_flags_t		flags;					\
	ibt_lkey_t		lkey;					\
	ibt_wr_reg_pmr_t	*pmr = (pmr_arg);			\
	uint64_t		*frwr64 = (uint64_t *)(frwr_arg);	\
									\
	flags = pmr->pmr_flags;						\
	((uint32_t *)frwr64)[0] = htonl(0x08000000 |			\
	    ((flags & IBT_MR_ENABLE_REMOTE_ATOMIC) ? 0x80000000 : 0) |	\
	    ((flags & IBT_MR_ENABLE_REMOTE_WRITE) ? 0x40000000 : 0) |	\
	    ((flags & IBT_MR_ENABLE_REMOTE_READ) ? 0x20000000 : 0) |	\
	    ((flags & IBT_MR_ENABLE_LOCAL_WRITE) ? 0x10000000 : 0) |	\
	    ((flags & IBT_MR_ENABLE_WINDOW_BIND) ? 0x00200000 : 0));	\
	lkey = (pmr->pmr_lkey & ~0xff) | pmr->pmr_key;			\
	pmr->pmr_rkey = pmr->pmr_lkey = lkey;				\
	((uint32_t *)frwr64)[1] = htonl(lkey);				\
	frwr64[1] = htonll(pmr->pmr_addr_list->p_laddr);		\
	frwr64[2] = htonll(pmr->pmr_iova);				\
	frwr64[3] = htonll(pmr->pmr_len);				\
	((uint32_t *)frwr64)[8] = htonl(pmr->pmr_offset);		\
	((uint32_t *)frwr64)[9] = htonl(pmr->pmr_buf_sz);		\
	frwr64[5] = 0;							\
}

#define	HERMON_WQE_BUILD_LI(qp, li_arg, wr_li)				\
{									\
	uint64_t		*li64 = (uint64_t *)(void *)(li_arg);	\
									\
	li64[0] = 0;							\
	((uint32_t *)li64)[2] = htonl((wr_li)->li_rkey);		\
	((uint32_t *)li64)[3] = 0;					\
	li64[2] = 0;							\
	li64[3] = 0;							\
}

#define	HERMON_WQE_BUILD_FCP3_INIT(ds, fctl, cs_pri, seq_id, mtu,	\
		dest_id, op, rem_exch, local_exch_idx)			\
{									\
	uint32_t		*fc_init;				\
									\
	fc_init = (uint32_t *)ds;					\
	fc_init[1] = htonl((cs_pri) << 24 | (seq_id) << 16 | (mtu));	\
	fc_init[2] = htonl((dest_id) << 8 |				\
	    IBT_FCTL_GET_ABORT_FIELD(fctl) << 6 | (op) << 3 | 0x2);	\
	fc_init[3] = htonl((rem_exch) << 16 | (local_exch_idx));	\
	membar_producer(); /* fc_init[0] is where the stamping is */	\
	fc_init[0] = htonl(((fctl) & IBT_FCTL_PRIO) << 6);		\
}

#define	HERMON_WQE_BUILD_DATA_SEG_RECV(ds, sgl)				\
{									\
	uint64_t		*tmp;					\
									\
	tmp	= (uint64_t *)(ds);					\
	tmp[0] = htonll((((uint64_t)((sgl)->ds_len &			\
	    HERMON_WQE_SGL_BYTE_CNT_MASK) << 32) | (sgl)->ds_key));	\
	tmp[1] = htonll((sgl)->ds_va);					\
}

#define	HERMON_WQE_BUILD_DATA_SEG_SEND(ds, sgl)				\
{									\
	((uint64_t *)(ds))[1] = htonll((sgl)->ds_va);			\
	((uint32_t *)(ds))[1] = htonl((sgl)->ds_key);			\
	membar_producer();						\
	((uint32_t *)(ds))[0] =						\
	    htonl((sgl)->ds_len & HERMON_WQE_SGL_BYTE_CNT_MASK);	\
}

#define	HERMON_WQE_BUILD_INLINE(qp, ds, sz)				\
	*(uint32_t *)(ds) = htonl(HERMON_WQE_SGL_INLINE_MASK | (sz))

#define	HERMON_WQE_BUILD_INLINE_ICRC(qp, ds, sz, icrc)			\
{									\
	uint32_t		*tmp;					\
									\
	tmp = (uint32_t *)(ds);						\
	tmp[1] = htonl(icrc);						\
	membar_producer();						\
	tmp[0] = htonl(HERMON_WQE_SGL_INLINE_MASK | (sz));		\
}

#define	HERMON_WQE_SET_CTRL_SEGMENT(desc, desc_sz, fence,	 	\
		imm, sol, sig, cksum, qp, strong, fccrc)		\
{									\
	uint32_t		*tmp;					\
	uint32_t		cntr_tmp;				\
									\
	/* do not set the first dword (owner/opcode) here */		\
	tmp = (uint32_t *)desc;						\
	cntr_tmp = (fence << 6) | desc_sz;				\
	tmp[1] = ntohl(cntr_tmp); 					\
	cntr_tmp = strong | fccrc | sol | sig | cksum;			\
	tmp[2] = ntohl(cntr_tmp); 					\
	tmp[3] = ntohl(imm);						\
}

#define	HERMON_WQE_SET_MLX_CTRL_SEGMENT(desc, desc_sz, sig, maxstat, 	\
		lid, qp, sl)						\
{									\
	uint32_t		*tmp;					\
	uint32_t		cntr_tmp;				\
									\
	tmp = (uint32_t *)desc;						\
	cntr_tmp = htonl(tmp[0]);					\
	cntr_tmp &= 0x80000000;						\
	cntr_tmp |= HERMON_WQE_SEND_NOPCODE_SEND;			\
	tmp[0] = ntohl(cntr_tmp);					\
	tmp[1] = ntohl(desc_sz);					\
	cntr_tmp = (((maxstat << 4) | (sl & 0xff)) << 8) | sig;		\
	if (qp->qp_is_special == HERMON_QP_SMI)				\
		cntr_tmp |= (0x02 << 16);				\
	if (lid == IB_LID_PERMISSIVE)					\
		cntr_tmp |= (0x01 << 16);				\
	tmp[2] = ntohl(cntr_tmp);					\
	tmp[3] = ntohl((lid) << 16);					\
}

#define	HERMON_WQE_BUILD_MLX_LRH(lrh, qp, udav, pktlen)	\
{									\
	uint32_t		*tmp;					\
	uint32_t		lrh_tmp;				\
									\
	tmp	 = (uint32_t *)(void *)(lrh);				\
									\
	if ((qp)->qp_is_special == HERMON_QP_SMI) {			\
		lrh_tmp = HERMON_MLX_VL15_LVER;				\
	} else {							\
		lrh_tmp = HERMON_MLX_VL0_LVER | ((udav)->sl << 20);	\
	}								\
	if ((udav)->grh) {						\
		lrh_tmp |= (IB_LRH_NEXT_HDR_GRH << 16);			\
	} else {							\
		lrh_tmp |= (IB_LRH_NEXT_HDR_BTH << 16);			\
	}								\
	lrh_tmp |= (udav)->rlid;					\
	tmp[0] = htonl(lrh_tmp);					\
									\
	lrh_tmp	 = (pktlen) << 16;					\
	if ((udav)->rlid == IB_LID_PERMISSIVE) {			\
		lrh_tmp |= IB_LID_PERMISSIVE;				\
	} else {							\
		lrh_tmp |= (udav)->ml_path;				\
	}								\
	tmp[1] = htonl(lrh_tmp);					\
}

/*
 * Note: The GRH payload length, calculated below, is the overall packet
 * length (in bytes) minus LRH header and GRH headers.
 *
 * Also note: Filling in the GIDs in the way we do below is helpful because
 * it avoids potential alignment restrictions and/or conflicts.
 */
#define	HERMON_WQE_BUILD_MLX_GRH(state, grh, qp, udav, pktlen)		\
{									\
	uint32_t		*tmp;					\
	uint32_t		grh_tmp;				\
	ib_gid_t		sgid;					\
									\
	tmp	 = (uint32_t *)(grh);					\
									\
	grh_tmp	 = HERMON_MLX_IPVER_TC_FLOW;				\
	grh_tmp |= (udav)->tclass << HERMON_MLX_TC_SHIFT;		\
	grh_tmp |= (udav)->flow_label;					\
	tmp[0] = htonl(grh_tmp);					\
									\
	grh_tmp	 = (((pktlen) << 2) - (sizeof (ib_lrh_hdr_t) +		\
	    sizeof (ib_grh_t))) << 16;					\
	grh_tmp |= (IB_GRH_NEXT_HDR_BTH << 8);				\
	grh_tmp |= (udav)->hop_limit;					\
	tmp[1] = htonl(grh_tmp);					\
									\
	sgid.gid_prefix = (state)->hs_sn_prefix[(qp)->qp_portnum];	\
	sgid.gid_guid = (state)->hs_guid[(qp)->qp_portnum]		\
	    [(udav)->mgid_index];					\
	bcopy(&sgid, &tmp[2], sizeof (ib_gid_t));			\
	bcopy(&(udav)->rgid_h, &tmp[6], sizeof (ib_gid_t));		\
}

#define	HERMON_WQE_BUILD_MLX_BTH(state, bth, qp, wr)			\
{									\
	uint32_t		*tmp;					\
	uint32_t		bth_tmp;				\
									\
	tmp	 = (uint32_t *)(bth);					\
									\
	bth_tmp	 = HERMON_MLX_UDSEND_OPCODE;				\
	if ((wr)->wr_flags & IBT_WR_SEND_SOLICIT) {			\
		bth_tmp |= (IB_BTH_SOLICITED_EVENT_MASK << 16);		\
	}								\
	if (qp->qp_is_special == HERMON_QP_SMI) {			\
		bth_tmp |= HERMON_MLX_DEF_PKEY;				\
	} else {							\
		bth_tmp |= (state)->hs_pkey[(qp)->qp_portnum]		\
		    [(qp)->qp_pkeyindx];				\
	}								\
	tmp[0] = htonl(bth_tmp);					\
	tmp[1] = htonl((wr)->wr.ud.udwr_dest->ud_dst_qpn &		\
	    HERMON_MLX_DQPN_MASK);					\
	tmp[2] = 0x0;							\
}

#define	HERMON_WQE_BUILD_MLX_DETH(deth, qp)				\
{									\
	uint32_t		*tmp;					\
									\
	tmp	 = (uint32_t *)(deth);					\
									\
	if ((qp)->qp_is_special == HERMON_QP_SMI) {			\
		tmp[0] = 0x0;						\
		tmp[1] = 0x0;						\
	} else {							\
		tmp[0] = htonl(HERMON_MLX_GSI_QKEY);			\
		tmp[1] = htonl(0x1);					\
	}								\
}


/*
 * Flash interface:
 *    Below we have PCI config space space offsets for flash interface
 *    access, offsets within Hermon CR space for accessing flash-specific
 *    information or settings, masks used for flash settings, and
 *    timeout values for flash operations.
 */
#define	HERMON_HW_FLASH_CFG_HWREV			8
#define	HERMON_HW_FLASH_CFG_ADDR			88
#define	HERMON_HW_FLASH_CFG_DATA			92

#define	HERMON_HW_FLASH_RESET_AMD			0xF0
#define	HERMON_HW_FLASH_RESET_INTEL		0xFF
#define	HERMON_HW_FLASH_CPUMODE			0xF0150
#define	HERMON_HW_FLASH_ADDR			0xF01A4
#define	HERMON_HW_FLASH_DATA			0xF01A8
#define	HERMON_HW_FLASH_GPIO_SEMA		0xF03FC
#define	HERMON_HW_FLASH_WRCONF_SEMA		0xF0380
#define	HERMON_HW_FLASH_GPIO_DATA			0xF0040
#define	HERMON_HW_FLASH_GPIO_MOD1			0xF004C
#define	HERMON_HW_FLASH_GPIO_MOD0			0xF0050
#define	HERMON_HW_FLASH_GPIO_DATACLEAR		0xF00D4
#define	HERMON_HW_FLASH_GPIO_DATASET		0xF00DC
#define	HERMON_HW_FLASH_GPIO_LOCK		0xF0048
#define	HERMON_HW_FLASH_GPIO_UNLOCK_VAL		0xD42F
#define	HERMON_HW_FLASH_GPIO_PIN_ENABLE		0x1E000000

#define	HERMON_HW_FLASH_CPU_MASK			0xC0000000
#define	HERMON_HW_FLASH_CPU_SHIFT		30
#define	HERMON_HW_FLASH_ADDR_MASK		0x0007FFFC
#define	HERMON_HW_FLASH_CMD_MASK			0xE0000000
#define	HERMON_HW_FLASH_BANK_MASK		0xFFF80000

#define	HERMON_HW_FLASH_SPI_BUSY			0x40000000
#define	HERMON_HW_FLASH_SPI_WIP			0x01000000
#define	HERMON_HW_FLASH_SPI_READ_OP		0x00000001
#define	HERMON_HW_FLASH_SPI_USE_INSTR		0x00000040
#define	HERMON_HW_FLASH_SPI_NO_ADDR		0x00000020
#define	HERMON_HW_FLASH_SPI_NO_DATA		0x00000010
#define	HERMON_HW_FLASH_SPI_TRANS_SZ_4B		0x00000200

#define	HERMON_HW_FLASH_SPI_SECTOR_ERASE		0xD8
#define	HERMON_HW_FLASH_SPI_READ		0x03
#define	HERMON_HW_FLASH_SPI_PAGE_PROGRAM		0x02
#define	HERMON_HW_FLASH_SPI_READ_STATUS_REG	0x05
#define	HERMON_HW_FLASH_SPI_WRITE_ENABLE		0x06
#define	HERMON_HW_FLASH_SPI_READ_ESIGNATURE	0xAB

#define	HERMON_HW_FLASH_SPI_GW			0xF0400
#define	HERMON_HW_FLASH_SPI_ADDR			0xF0404
#define	HERMON_HW_FLASH_SPI_DATA			0xF0410
#define	HERMON_HW_FLASH_SPI_DATA4		0xF0414
#define	HERMON_HW_FLASH_SPI_DATA8		0xF0418
#define	HERMON_HW_FLASH_SPI_DATA12		0xF041C
#define	HERMON_HW_FLASH_SPI_ADDR_MASK		0x00FFFFFF
#define	HERMON_HW_FLASH_SPI_INSTR_PHASE_OFF	0x04
#define	HERMON_HW_FLASH_SPI_ADDR_PHASE_OFF	0x08
#define	HERMON_HW_FLASH_SPI_DATA_PHASE_OFF	0x10
#define	HERMON_HW_FLASH_SPI_ENABLE_OFF		0x2000
#define	HERMON_HW_FLASH_SPI_CS_OFF		0x800
#define	HERMON_HW_FLASH_SPI_INSTR_OFF		0x10000
#define	HERMON_HW_FLASH_SPI_INSTR_SHIFT		0x10
#define	HERMON_HW_FLASH_SPI_BOOT_ADDR_REG	0xF0000

#define	HERMON_HW_FLASH_TIMEOUT_WRITE		300
#define	HERMON_HW_FLASH_TIMEOUT_ERASE		1000000
#define	HERMON_HW_FLASH_TIMEOUT_GPIO_SEMA	1000
#define	HERMON_HW_FLASH_TIMEOUT_CONFIG		50

#define	HERMON_HW_FLASH_ICS_ERASE		0x20
#define	HERMON_HW_FLASH_ICS_ERROR		0x3E
#define	HERMON_HW_FLASH_ICS_WRITE		0x40
#define	HERMON_HW_FLASH_ICS_STATUS		0x70
#define	HERMON_HW_FLASH_ICS_READY		0x80
#define	HERMON_HW_FLASH_ICS_CONFIRM		0xD0
#define	HERMON_HW_FLASH_ICS_READ			0xFF

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_IB_ADAPTERS_HERMON_HW_H */
