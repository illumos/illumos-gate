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

#ifndef	_SYS_IB_ADAPTERS_TAVOR_HW_H
#define	_SYS_IB_ADAPTERS_TAVOR_HW_H

/*
 * tavor_hw.h
 *    Contains all the structure definitions and #defines for all Tavor
 *    hardware resources and registers (as defined by the Tavor register
 *    specification).  Wherever possible, the names in the Tavor spec
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
 * Offsets into the CMD BAR (BAR 0) for many of the more interesting hardware
 * registers.  These registers include the HCR (more below), the Event Cause
 * Register (ECR) and its related clear register, the Interrupt Clear register
 * (CLR_INT), and the software reset register (SW_RESET).
 */
#define	TAVOR_CMD_HCR_OFFSET		0x80680
#define	TAVOR_CMD_ECR_OFFSET		0x80700
#define	TAVOR_CMD_CLR_ECR_OFFSET	0x80708
#define	TAVOR_CMD_CLR_INT_OFFSET	0xF00D8
#define	TAVOR_CMD_SW_RESET_OFFSET	0xF0010

/*
 * Ownership flags used to define hardware or software ownership for
 * various Tavor resources
 */
#define	TAVOR_HW_OWNER			0x1
#define	TAVOR_SW_OWNER			0x0

/*
 * Determines whether or not virtual-to-physical address translation is
 * required.  Several of the Tavor hardware structures can be optionally
 * accessed by Tavor without going through the TPT address translation
 * tables.
 */
#define	TAVOR_VA2PA_XLAT_ENABLED	0x1
#define	TAVOR_VA2PA_XLAT_DISABLED	0x0

/*
 * HCA Command Register (HCR)
 *    The HCR command interface provides privileged access to the HCA in
 *    order to query, configure and modify HCA execution.  It is the
 *    primary mechanism through which mailboxes may be posted to Tavor
 *    firmware.  To use this interface software fills the HCR with pointers
 *    to input and output mailboxes.  Some commands support immediate
 *    parameters, however, and for these commands the HCR will contain the
 *    input or output parameters. Command execution completion can be
 *    detected either by the software polling the HCR or by waiting for a
 *    command completion event.
 */
struct tavor_hw_hcr_s {
	uint32_t	in_param0;
	uint32_t	in_param1;
	uint32_t	input_modifier;
	uint32_t	out_param0;
	uint32_t	out_param1;
	uint32_t	token;
	uint32_t	cmd;
};
#define	TAVOR_HCR_TOKEN_MASK		0xFFFF0000
#define	TAVOR_HCR_TOKEN_SHIFT		16

#define	TAVOR_HCR_CMD_STATUS_MASK	0xFF000000
#define	TAVOR_HCR_CMD_GO_MASK		0x00800000
#define	TAVOR_HCR_CMD_E_MASK		0x00400000
#define	TAVOR_HCR_CMD_OPMOD_MASK	0x0000F000
#define	TAVOR_HCR_CMD_OPCODE_MASK	0x00000FFF
#define	TAVOR_HCR_CMD_STATUS_SHFT	24
#define	TAVOR_HCR_CMD_GO_SHFT		23
#define	TAVOR_HCR_CMD_E_SHFT		22
#define	TAVOR_HCR_CMD_OPMOD_SHFT	12


/*
 * Tavor "QUERY_DEV_LIM" command
 *    The QUERY_DEV_LIM command returns the device limits and capabilities
 *    supported by the Tavor device.  This command should be run before
 *    running the INIT_HCA command (below) in order to determine the maximum
 *    capabilities of the device and which optional features are supported.
 */
#ifdef	_LITTLE_ENDIAN
struct tavor_hw_querydevlim_s {
	uint32_t	rsrv0[4];
	uint32_t	log_max_ee	:5;
	uint32_t			:3;
	uint32_t	log_rsvd_ee	:4;
	uint32_t			:4;
	uint32_t	log_max_srq	:5;
	uint32_t			:7;
	uint32_t	log_rsvd_srq	:4;
	uint32_t	log_max_qp	:5;
	uint32_t			:3;
	uint32_t	log_rsvd_qp	:4;
	uint32_t			:4;
	uint32_t	log_max_qp_sz	:8;
	uint32_t	log_max_srq_sz	:8;
	uint32_t	log_max_eq	:3;
	uint32_t			:5;
	uint32_t	num_rsvd_eq	:4;
	uint32_t			:4;
	uint32_t	log_max_mpt	:6;
	uint32_t			:10;
	uint32_t	log_max_cq	:5;
	uint32_t			:3;
	uint32_t	log_rsvd_cq	:4;
	uint32_t			:4;
	uint32_t	log_max_cq_sz	:8;
	uint32_t			:8;
	uint32_t	log_max_av	:6;
	uint32_t			:26;
	uint32_t	log_max_mttseg	:6;
	uint32_t			:2;
	uint32_t	log_rsvd_mpt	:4;
	uint32_t			:4;
	uint32_t	log_max_mrw_sz	:8;
	uint32_t			:4;
	uint32_t	log_rsvd_mttseg	:4;
	uint32_t	log_max_ra_glob	:6;
	uint32_t			:26;
	uint32_t	log_max_ras_qp	:6;
	uint32_t			:10;
	uint32_t	log_max_raq_qp	:6;
	uint32_t			:10;
	uint32_t	num_ports	:4;
	uint32_t	max_vl		:4;
	uint32_t	max_port_width	:4;
	uint32_t	max_mtu		:4;
	uint32_t	ca_ack_delay	:5;
	uint32_t			:11;
	uint32_t			:32;
	uint32_t	log_max_pkey	:4;
	uint32_t			:12;
	uint32_t	stat_rate_sup	:16;
	uint32_t	log_max_gid	:4;
	uint32_t			:28;
	uint32_t	rc		:1;
	uint32_t	uc		:1;
	uint32_t	ud		:1;
	uint32_t	rd		:1;
	uint32_t	raw_ipv6	:1;
	uint32_t	raw_ether	:1;
	uint32_t	srq		:1;
	uint32_t			:1;
	uint32_t	pkey_v		:1;
	uint32_t	qkey_v		:1;
	uint32_t			:6;
	uint32_t	mem_win		:1;
	uint32_t	apm		:1;
	uint32_t	atomic		:1;
	uint32_t	raw_multi	:1;
	uint32_t	avp		:1;
	uint32_t	ud_multi	:1;
	uint32_t			:2;
	uint32_t	pg_on_demand	:1;
	uint32_t	router		:1;
	uint32_t			:6;
	uint32_t			:32;
	uint32_t			:32;
	uint32_t	log_pg_sz	:8;
	uint32_t			:8;
	uint32_t	log_max_uar_sz	:6;
	uint32_t			:6;
	uint32_t	num_rsvd_uar	:4;
	uint32_t			:32;
	uint32_t	max_desc_sz	:16;
	uint32_t	max_sg		:8;
	uint32_t			:8;
	uint32_t	rsrv1[2];
	uint32_t	log_max_rdd	:6;
	uint32_t			:6;
	uint32_t	num_rsvd_rdd	:4;
	uint32_t	log_max_pd	:6;
	uint32_t			:6;
	uint32_t	num_rsvd_pd	:4;
	uint32_t	log_max_mcg	:8;
	uint32_t	num_rsvd_mcg	:4;
	uint32_t			:4;
	uint32_t	log_max_qp_mcg	:8;
	uint32_t			:8;
	uint32_t	rsrv2[6];
	uint32_t	eqpc_entry_sz	:16;
	uint32_t	eeec_entry_sz	:16;
	uint32_t	qpc_entry_sz	:16;
	uint32_t	eec_entry_sz	:16;
	uint32_t	uarscr_entry_sz	:16;
	uint32_t	srq_entry_sz	:16;
	uint32_t	cqc_entry_sz	:16;
	uint32_t	eqc_entry_sz	:16;
	uint32_t	rsrv3[28];
};
#else
struct tavor_hw_querydevlim_s {
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
	uint32_t			:4;
	uint32_t	log_rsvd_ee	:4;
	uint32_t			:3;
	uint32_t	log_max_ee	:5;
	uint32_t			:8;
	uint32_t	log_max_cq_sz	:8;
	uint32_t			:4;
	uint32_t	log_rsvd_cq	:4;
	uint32_t			:3;
	uint32_t	log_max_cq	:5;
	uint32_t			:10;
	uint32_t	log_max_mpt	:6;
	uint32_t			:4;
	uint32_t	num_rsvd_eq	:4;
	uint32_t			:5;
	uint32_t	log_max_eq	:3;
	uint32_t	log_rsvd_mttseg	:4;
	uint32_t			:4;
	uint32_t	log_max_mrw_sz	:8;
	uint32_t			:4;
	uint32_t	log_rsvd_mpt	:4;
	uint32_t			:2;
	uint32_t	log_max_mttseg	:6;
	uint32_t			:26;
	uint32_t	log_max_av	:6;
	uint32_t			:10;
	uint32_t	log_max_raq_qp	:6;
	uint32_t			:10;
	uint32_t	log_max_ras_qp	:6;
	uint32_t			:26;
	uint32_t	log_max_ra_glob	:6;
	uint32_t			:32;
	uint32_t			:11;
	uint32_t	ca_ack_delay	:5;
	uint32_t	max_mtu		:4;
	uint32_t	max_port_width	:4;
	uint32_t	max_vl		:4;
	uint32_t	num_ports	:4;
	uint32_t			:28;
	uint32_t	log_max_gid	:4;
	uint32_t	stat_rate_sup	:16;
	uint32_t			:12;
	uint32_t	log_max_pkey	:4;
	uint32_t			:32;
	uint32_t			:6;
	uint32_t	router		:1;
	uint32_t	pg_on_demand	:1;
	uint32_t			:2;
	uint32_t	ud_multi	:1;
	uint32_t	avp		:1;
	uint32_t	raw_multi	:1;
	uint32_t	atomic		:1;
	uint32_t	apm		:1;
	uint32_t	mem_win		:1;
	uint32_t			:6;
	uint32_t	qkey_v		:1;
	uint32_t	pkey_v		:1;
	uint32_t			:1;
	uint32_t	srq		:1;
	uint32_t	raw_ether	:1;
	uint32_t	raw_ipv6	:1;
	uint32_t	rd		:1;
	uint32_t	ud		:1;
	uint32_t	uc		:1;
	uint32_t	rc		:1;
	uint32_t	num_rsvd_uar	:4;
	uint32_t			:6;
	uint32_t	log_max_uar_sz	:6;
	uint32_t			:8;
	uint32_t	log_pg_sz	:8;
	uint32_t			:32;
	uint32_t			:8;
	uint32_t	max_sg		:8;
	uint32_t	max_desc_sz	:16;
	uint32_t			:32;
	uint32_t	rsrv1[2];
	uint32_t			:8;
	uint32_t	log_max_qp_mcg	:8;
	uint32_t			:4;
	uint32_t	num_rsvd_mcg	:4;
	uint32_t	log_max_mcg	:8;
	uint32_t	num_rsvd_pd	:4;
	uint32_t			:6;
	uint32_t	log_max_pd	:6;
	uint32_t	num_rsvd_rdd	:4;
	uint32_t			:6;
	uint32_t	log_max_rdd	:6;
	uint32_t	rsrv2[6];
	uint32_t	eec_entry_sz	:16;
	uint32_t	qpc_entry_sz	:16;
	uint32_t	eeec_entry_sz	:16;
	uint32_t	eqpc_entry_sz	:16;
	uint32_t	eqc_entry_sz	:16;
	uint32_t	cqc_entry_sz	:16;
	uint32_t	srq_entry_sz	:16;
	uint32_t	uarscr_entry_sz	:16;
	uint32_t	rsrv3[28];
};
#endif


/*
 * Tavor "QUERY_FW" command
 *    The QUERY_FW command retrieves the firmware revision and the Command
 *    Interface revision.  The command also returns the HCA attached local
 *    memory area (DDR) which is used by the firmware.  Below we also
 *    include some defines which are used to enforce a minimum firmware
 *    version check (see tavor_fw_version_check() for more details).
 */
#ifdef	_LITTLE_ENDIAN
struct tavor_hw_queryfw_s {
	uint32_t	fw_rev_minor	:16;
	uint32_t	fw_rev_subminor	:16;
	uint32_t	fw_rev_major	:16;
	uint32_t			:16;
	uint32_t	log_max_cmd	:8;
	uint32_t			:23;
	uint32_t	dbg_trace	:1;
	uint32_t	cmd_intf_rev	:16;
	uint32_t			:16;
	uint32_t	rsrv0[4];
	uint64_t	fw_baseaddr;
	uint64_t	fw_endaddr;
	uint64_t	error_buf_addr;
	uint32_t			:32;
	uint32_t	error_buf_sz;
	uint32_t	rsrv1[48];
};
#else
struct tavor_hw_queryfw_s {
	uint32_t			:16;
	uint32_t	fw_rev_major	:16;
	uint32_t	fw_rev_subminor	:16;
	uint32_t	fw_rev_minor	:16;
	uint32_t			:16;
	uint32_t	cmd_intf_rev	:16;
	uint32_t	dbg_trace	:1;
	uint32_t			:23;
	uint32_t	log_max_cmd	:8;
	uint32_t	rsrv0[4];
	uint64_t	fw_baseaddr;
	uint64_t	fw_endaddr;
	uint64_t	error_buf_addr;
	uint32_t	error_buf_sz;
	uint32_t	rsrv1[49];
};
#endif
#define	TAVOR_FW_VER_MAJOR		0x0003
#define	TAVOR_FW_VER_MINOR		0x0001
#define	TAVOR_FW_VER_SUBMINOR		0x0000
#define	TAVOR_COMPAT_FW_VER_MAJOR	0x0004
#define	TAVOR_COMPAT_FW_VER_MINOR	0x0005
#define	TAVOR_COMPAT_FW_VER_SUBMINOR	0x0003


/*
 * Tavor "QUERY_DDR" command
 *    The QUERY_DDR command retrieves information regarding the HCA attached
 *    local memory area (DDR). This information includes:  the DIMM PCI BAR,
 *    the total address space provided by the HCA attached local memory, and
 *    some DIMM-specific information.  Note:  Some of the HCA attached local
 *    memory is reserved for use by firmware.  This extent of this reserved
 *    area can be obtained through the QUERY_FW command (above).
 *
 *    Below we first define the tavor_hw_queryddr_dimm_t or "Logical DIMM
 *    Information" structure.  Four of these are present in the QUERY_DDR
 *    command.
 */
#ifdef	_LITTLE_ENDIAN
typedef struct tavor_hw_queryddr_dimm_s {
	uint32_t	spd		:1;
	uint32_t	sladr		:3;
	uint32_t	sock_num	:2;
	uint32_t	syn		:4;
	uint32_t			:22;
	uint32_t	dimmsz		:16;
	uint32_t			:8;
	uint32_t	dimmstatus	:1;
	uint32_t	dimm_hidden	:1;
	uint32_t	write_only	:1;
	uint32_t			:5;
	uint32_t	vendor_id_l;
	uint32_t	vendor_id_h;
	uint32_t	dimm_baseaddr_l;
	uint32_t	dimm_baseaddr_h;
	uint32_t	rsrv0[2];
} tavor_hw_queryddr_dimm_t;
#else
typedef struct tavor_hw_queryddr_dimm_s {
	uint32_t			:5;
	uint32_t	write_only	:1;
	uint32_t	dimm_hidden	:1;
	uint32_t	dimmstatus	:1;
	uint32_t			:8;
	uint32_t	dimmsz		:16;
	uint32_t			:22;
	uint32_t	syn		:4;
	uint32_t	sock_num	:2;
	uint32_t	sladr		:3;
	uint32_t	spd		:1;
	uint32_t	vendor_id_h;
	uint32_t	vendor_id_l;
	uint32_t	dimm_baseaddr_h;
	uint32_t	dimm_baseaddr_l;
	uint32_t	rsrv0[2];
} tavor_hw_queryddr_dimm_t;
#endif
#define	TAVOR_DIMMSTATUS_ENABLED	0x0
#define	TAVOR_DIMMSTATUS_DISABLED	0x1

#define	TAVOR_DIMM_ERR_NONE		0x0
#define	TAVOR_DIMM_ERR_SPD		0x1
#define	TAVOR_DIMM_ERR_BOUNDS		0x2
#define	TAVOR_DIMM_ERR_CONFLICT		0x3
#define	TAVOR_DIMM_ERR_SIZETRIM		0x5

#define	TAVOR_DIMM_SPD_FROM_DIMM	0x0
#define	TAVOR_DIMM_SPD_FROM_NVMEM	0x1

#ifdef	_LITTLE_ENDIAN
struct tavor_hw_queryddr_s {
	uint64_t	ddr_baseaddr;
	uint64_t	ddr_endaddr;
	uint32_t			:32;
	uint32_t	data_integrity	:2;
	uint32_t	auto_precharge	:2;
	uint32_t	ddr_hidden	:1;
	uint32_t			:27;
	uint32_t	rsrv0[10];
	tavor_hw_queryddr_dimm_t	dimm[4];
	uint32_t	rsrv1[16];
};
#else
struct tavor_hw_queryddr_s {
	uint64_t	ddr_baseaddr;
	uint64_t	ddr_endaddr;
	uint32_t			:27;
	uint32_t	ddr_hidden	:1;
	uint32_t	auto_precharge	:2;
	uint32_t	data_integrity	:2;
	uint32_t			:32;
	uint32_t	rsrv0[10];
	tavor_hw_queryddr_dimm_t	dimm[4];
	uint32_t	rsrv1[16];
};
#endif
#define	TAVOR_AUTO_PRECHRG_NONE		0x0
#define	TAVOR_AUTO_PRECHRG_PER_TRANS	0x1
#define	TAVOR_AUTO_PRECHRG_PER_64B	0x2

#define	TAVOR_DATA_INT_NONE		0x0
#define	TAVOR_DATA_INT_PARITY		0x1
#define	TAVOR_DATA_INT_ECC_DETECT_ONLY	0x2
#define	TAVOR_DATA_INT_ECC_CORRECT	0x3


/*
 * Tavor "QUERY_ADAPTER" command
 *    The QUERY_ADAPTER command retrieves adapter specific parameters. The
 *    command also retrieves the PCI(X) interrupt pin routing for each of
 *    the INTx# pins supported by the device.  This information is used by
 *    the driver during interrupt processing in order to clear the appropriate
 *    interrupt bit.
 */
#ifdef	_LITTLE_ENDIAN
struct tavor_hw_queryadapter_s {
	uint32_t	device_id;
	uint32_t	vendor_id;
	uint32_t			:32;
	uint32_t	rev_id;
	uint32_t			:32;
	uint32_t			:24;
	uint32_t	inta_pin	:8;
	uint32_t	rsrv0[58];
};
#else
struct tavor_hw_queryadapter_s {
	uint32_t	vendor_id;
	uint32_t	device_id;
	uint32_t	rev_id;
	uint32_t			:32;
	uint32_t	inta_pin	:8;
	uint32_t			:24;
	uint32_t			:32;
	uint32_t	rsrv0[58];
};
#endif
#define	TAVOR_REV_A0	0xA0
#define	TAVOR_REV_A1	0xA1


/*
 * Tavor "INIT_HCA" and "QUERY_HCA" commands
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
 *    tavor_hw_qp_ee_cq_eq_rdb_t for "QPC/EEC/CQC/EQC/RDB Parameters",
 *    tavor_udav_mem_param_t for "Memory Access Parameters for UDAV Table",
 *    tavor_multicast_param_t for "Multicast Support Parameters",
 *    tavor_tpt_param_t for "Translation and Protection Table Parameters",
 *    and tavor_uar_param_t for Tavor "UAR Parameters".
 */
#ifdef	_LITTLE_ENDIAN
typedef struct tavor_hw_qp_ee_cq_eq_rdb_s {
	uint32_t	rsrv0[4];
	uint32_t	log_num_qp	:5;
	uint32_t			:2;
	uint32_t	qpc_baseaddr_l	:25;
	uint32_t	qpc_baseaddr_h;
	uint32_t	rsrv1[2];
	uint32_t	log_num_ee	:5;
	uint32_t			:2;
	uint32_t	eec_baseaddr_l	:25;
	uint32_t	eec_baseaddr_h;
	uint32_t	log_num_srq	:5;
	uint32_t	srqc_baseaddr_l	:27;
	uint32_t	srqc_baseaddr_h;
	uint32_t	log_num_cq	:5;
	uint32_t			:1;
	uint32_t	cqc_baseaddr_l	:26;
	uint32_t	cqc_baseaddr_h;
	uint32_t	rsrv2[2];
	uint64_t	eqpc_baseaddr;
	uint32_t	rsrv3[2];
	uint64_t	eeec_baseaddr;
	uint32_t	rsrv4[2];
	uint32_t	log_num_eq	:4;
	uint32_t			:2;
	uint32_t	eqc_baseaddr_l	:26;
	uint32_t	eqc_baseaddr_h;
	uint32_t	rsrv5[2];
	uint32_t	rdb_baseaddr_l;
	uint32_t	rdb_baseaddr_h;
	uint32_t	rsrv6[2];
} tavor_hw_qp_ee_cq_eq_rdb_t;
#else
typedef struct tavor_hw_qp_ee_cq_eq_rdb_s {
	uint32_t	rsrv0[4];
	uint32_t	qpc_baseaddr_h;
	uint32_t	qpc_baseaddr_l	:25;
	uint32_t			:2;
	uint32_t	log_num_qp	:5;
	uint32_t	rsrv1[2];
	uint32_t	eec_baseaddr_h;
	uint32_t	eec_baseaddr_l	:25;
	uint32_t			:2;
	uint32_t	log_num_ee	:5;
	uint32_t	srqc_baseaddr_h;
	uint32_t	srqc_baseaddr_l	:27;
	uint32_t	log_num_srq	:5;
	uint32_t	cqc_baseaddr_h;
	uint32_t	cqc_baseaddr_l	:26;
	uint32_t			:1;
	uint32_t	log_num_cq	:5;
	uint32_t	rsrv2[2];
	uint64_t	eqpc_baseaddr;
	uint32_t	rsrv3[2];
	uint64_t	eeec_baseaddr;
	uint32_t	rsrv4[2];
	uint32_t	eqc_baseaddr_h;
	uint32_t	eqc_baseaddr_l	:26;
	uint32_t			:2;
	uint32_t	log_num_eq	:4;
	uint32_t	rsrv5[2];
	uint32_t	rdb_baseaddr_h;
	uint32_t	rdb_baseaddr_l;
	uint32_t	rsrv6[2];
} tavor_hw_qp_ee_cq_eq_rdb_t;
#endif

#ifdef	_LITTLE_ENDIAN
typedef struct tavor_udav_mem_param_s {
	uint32_t	udav_pd		:24;
	uint32_t			:5;
	uint32_t	udav_xlat_en	:1;
	uint32_t			:2;
	uint32_t	udav_lkey;
} tavor_udav_mem_param_t;
#else
typedef struct tavor_udav_mem_param_s {
	uint32_t	udav_lkey;
	uint32_t			:2;
	uint32_t	udav_xlat_en	:1;
	uint32_t			:5;
	uint32_t	udav_pd		:24;
} tavor_udav_mem_param_t;
#endif

#ifdef	_LITTLE_ENDIAN
typedef struct tavor_multicast_param_s {
	uint64_t	mc_baseaddr;
	uint32_t	rsrv0[2];
	uint32_t	mc_tbl_hash_sz	:17;
	uint32_t			:15;
	uint32_t	log_mc_tbl_ent	:16;
	uint32_t			:16;
	uint32_t			:32;
	uint32_t	log_mc_tbl_sz	:5;
	uint32_t			:19;
	uint32_t	mc_hash_fn	:3;
	uint32_t			:5;
} tavor_multicast_param_t;
#else
typedef struct tavor_multicast_param_s {
	uint64_t	mc_baseaddr;
	uint32_t	rsrv0[2];
	uint32_t			:16;
	uint32_t	log_mc_tbl_ent	:16;
	uint32_t			:15;
	uint32_t	mc_tbl_hash_sz	:17;
	uint32_t			:5;
	uint32_t	mc_hash_fn	:3;
	uint32_t			:19;
	uint32_t	log_mc_tbl_sz	:5;
	uint32_t			:32;
} tavor_multicast_param_t;
#endif
#define	TAVOR_MCG_DEFAULT_HASH_FN	0x0

#ifdef	_LITTLE_ENDIAN
typedef struct tavor_tpt_param_s {
	uint64_t	mpt_baseaddr;
	uint32_t	mtt_version	:8;
	uint32_t			:24;
	uint32_t	log_mpt_sz	:6;
	uint32_t			:2;
	uint32_t	pgfault_rnr_to	:5;
	uint32_t			:3;
	uint32_t	mttseg_sz	:3;
	uint32_t			:13;
	uint64_t	mtt_baseaddr;
	uint32_t	rsrv0[2];
} tavor_tpt_param_t;
#else
typedef struct tavor_tpt_param_s {
	uint64_t	mpt_baseaddr;
	uint32_t			:13;
	uint32_t	mttseg_sz	:3;
	uint32_t			:3;
	uint32_t	pgfault_rnr_to	:5;
	uint32_t			:2;
	uint32_t	log_mpt_sz	:6;
	uint32_t			:24;
	uint32_t	mtt_version	:8;
	uint64_t	mtt_baseaddr;
	uint32_t	rsrv0[2];
} tavor_tpt_param_t;
#endif

#ifdef	_LITTLE_ENDIAN
typedef struct tavor_uar_param_s {
	uint32_t			:20;
	uint32_t	uar_baseaddr_l	:12;	/* QUERY_HCA only */
	uint32_t	uar_baseaddr_h;		/* QUERY_HCA only */
	uint32_t			:32;
	uint32_t	uar_pg_sz	:8;
	uint32_t			:24;
	uint64_t	uarscr_baseaddr;
	uint32_t	rsrv0[2];
} tavor_uar_param_t;
#else
typedef struct tavor_uar_param_s {
	uint32_t	uar_baseaddr_h;		/* QUERY_HCA only */
	uint32_t	uar_baseaddr_l	:12;	/* QUERY_HCA only */
	uint32_t			:20;
	uint32_t			:24;
	uint32_t	uar_pg_sz	:8;
	uint32_t			:32;
	uint64_t	uarscr_baseaddr;
	uint32_t	rsrv0[2];
} tavor_uar_param_t;
#endif

#ifdef	_LITTLE_ENDIAN
struct tavor_hw_initqueryhca_s {
	uint32_t	rsrv0[2];
	uint32_t			:24;
	uint32_t	hca_core_clock	:8;	/* QUERY_HCA only */
	uint32_t			:32;
	uint32_t	udav_port_chk	:1;
	uint32_t	big_endian	:1;
	uint32_t	udav_chk	:1;
	uint32_t			:5;
	uint32_t	responder_exu	:4;
	uint32_t			:4;
	uint32_t	wqe_quota	:15;
	uint32_t	wqe_quota_en	:1;
	uint32_t			:8;
	uint32_t	router_qp	:16;
	uint32_t			:7;
	uint32_t	router_en	:1;
	uint32_t	rsrv1[2];
	tavor_hw_qp_ee_cq_eq_rdb_t	context;
	uint32_t	rsrv2[4];
	tavor_udav_mem_param_t		udav;
	uint32_t	rsrv3[2];
	tavor_multicast_param_t		multi;
	uint32_t	rsrv4[4];
	tavor_tpt_param_t		tpt;
	uint32_t	rsrv5[4];
	tavor_uar_param_t		uar;
	uint32_t	rsrv6[48];
};
#else
struct tavor_hw_initqueryhca_s {
	uint32_t	rsrv0[2];
	uint32_t			:32;
	uint32_t	hca_core_clock	:8;	/* QUERY_HCA only */
	uint32_t			:24;
	uint32_t	router_en	:1;
	uint32_t			:7;
	uint32_t	router_qp	:16;
	uint32_t			:8;
	uint32_t	wqe_quota_en	:1;
	uint32_t	wqe_quota	:15;
	uint32_t			:4;
	uint32_t	responder_exu	:4;
	uint32_t			:5;
	uint32_t	udav_chk	:1;
	uint32_t	big_endian	:1;
	uint32_t	udav_port_chk	:1;
	uint32_t	rsrv1[2];
	tavor_hw_qp_ee_cq_eq_rdb_t	context;
	uint32_t	rsrv2[4];
	tavor_udav_mem_param_t		udav;
	uint32_t	rsrv3[2];
	tavor_multicast_param_t		multi;
	uint32_t	rsrv4[4];
	tavor_tpt_param_t		tpt;
	uint32_t	rsrv5[4];
	tavor_uar_param_t		uar;
	uint32_t	rsrv6[48];
};
#endif
#define	TAVOR_UDAV_PROTECT_DISABLED	0x0
#define	TAVOR_UDAV_PROTECT_ENABLED	0x1
#define	TAVOR_UDAV_PORTCHK_DISABLED	0x0
#define	TAVOR_UDAV_PORTCHK_ENABLED	0x1


/*
 * Tavor "INIT_IB" command
 *    The INIT_IB command enables the physical layer of a given IB port.
 *    It provides control over the IB port attributes.  The capabilities
 *    requested here should not exceed the device limits, as retrieved by
 *    the QUERY_DEV_LIM command (above).  To query information about the IB
 *    port or node, the driver may submit GetPortInfo or GetNodeInfo MADs
 *    through the Tavor MAD_IFC command.
 */
#ifdef	_LITTLE_ENDIAN
struct tavor_hw_initib_s {
	uint32_t	max_gid		:16;
	uint32_t			:16;
	uint32_t			:4;
	uint32_t	vl_cap		:4;
	uint32_t	port_width_cap	:4;
	uint32_t	mtu_cap		:4;
	uint32_t	set_port_guid0	:1;
	uint32_t	set_node_guid	:1;
	uint32_t	set_sysimg_guid	:1;
	uint32_t			:13;
	uint32_t			:32;
	uint32_t	max_pkey	:16;
	uint32_t			:16;
	uint64_t	guid0;
	uint64_t	node_guid;
	uint64_t	sysimg_guid;
	uint32_t	rsrv0[54];
};
#else
struct tavor_hw_initib_s {
	uint32_t			:13;
	uint32_t	set_sysimg_guid	:1;
	uint32_t	set_node_guid	:1;
	uint32_t	set_port_guid0	:1;
	uint32_t	mtu_cap		:4;
	uint32_t	port_width_cap	:4;
	uint32_t	vl_cap		:4;
	uint32_t			:4;
	uint32_t			:16;
	uint32_t	max_gid		:16;
	uint32_t			:16;
	uint32_t	max_pkey	:16;
	uint32_t			:32;
	uint64_t	guid0;
	uint64_t	node_guid;
	uint64_t	sysimg_guid;
	uint32_t	rsrv0[54];
};
#endif

/*
 * Tavor Memory Protection Table (MPT) entries
 *    The Memory Protection Table (MPT) contains the information associated
 *    with all the regions and windows. The MPT table resides in a physically-
 *    contiguous area in HCA attached local memory, and the memory key (R_Key
 *    or L_Key) is used to calculate the physical address for accessing the
 *    entries in the table.
 *
 *    The following structure is used in the SW2HW_MPT, QUERY_MPT, and
 *    HW2SW_MPT commands.
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
 */
#ifdef	_LITTLE_ENDIAN
struct tavor_hw_mpt_s {
	uint32_t	page_sz		:5;
	uint32_t			:27;
	uint32_t	ver		:4;
	uint32_t			:4;
	uint32_t	reg_win		:1;
	uint32_t	phys_addr	:1;
	uint32_t	lr		:1;
	uint32_t	lw		:1;
	uint32_t	rr		:1;
	uint32_t	rw		:1;
	uint32_t	atomic		:1;
	uint32_t	en_bind		:1;
	uint32_t			:1;
	uint32_t	m_io		:1;
	uint32_t			:10;
	uint32_t	status		:4;
	uint32_t	pd		:24;
	uint32_t			:8;
	uint32_t	mem_key;
	uint64_t	start_addr;
	uint64_t	reg_win_len;
	uint32_t	win_cnt;
	uint32_t	lkey;
	uint32_t	mttseg_addr_h;
	uint32_t	win_cnt_limit;
	uint32_t			:32;
	uint32_t			:6;
	uint32_t	mttseg_addr_l	:26;
	uint32_t	rsrv0[2];
};
#else
struct tavor_hw_mpt_s {
	uint32_t	status		:4;
	uint32_t			:10;
	uint32_t	m_io		:1;
	uint32_t			:1;
	uint32_t	en_bind		:1;
	uint32_t	atomic		:1;
	uint32_t	rw		:1;
	uint32_t	rr		:1;
	uint32_t	lw		:1;
	uint32_t	lr		:1;
	uint32_t	phys_addr	:1;
	uint32_t	reg_win		:1;
	uint32_t			:4;
	uint32_t	ver		:4;
	uint32_t			:27;
	uint32_t	page_sz		:5;
	uint32_t	mem_key;
	uint32_t			:8;
	uint32_t	pd		:24;
	uint64_t	start_addr;
	uint64_t	reg_win_len;
	uint32_t	lkey;
	uint32_t	win_cnt;
	uint32_t	win_cnt_limit;
	uint32_t	mttseg_addr_h;
	uint32_t	mttseg_addr_l	:26;
	uint32_t			:6;
	uint32_t			:32;
	uint32_t	rsrv0[2];
};
#endif
#define	TAVOR_MEM_CYCLE_GENERATE	0x1
#define	TAVOR_IO_CYCLE_GENERATE		0x0

#define	TAVOR_MPT_IS_WINDOW		0x0
#define	TAVOR_MPT_IS_REGION		0x1

#define	TAVOR_MPT_DEFAULT_VERSION	0x0

#define	TAVOR_UNLIMITED_WIN_BIND	0x0

#define	TAVOR_PHYSADDR_ENABLED		0x1
#define	TAVOR_PHYSADDR_DISABLED		0x0


/*
 * Tavor Memory Translation Table (MTT) entries
 *    After accessing the MPT table (above) and validating the access rights
 *    to the region/window, Tavor address translation moves to the next step
 *    where it translates the virtual address to a physical address.  This
 *    translation is performed using the Memory Translation Table entries
 *    (MTT).  Note: The MTT in hardware is organized into segments and each
 *    segment contains multiple address translation pages (MTT entries).
 *    Each memory region (MPT above) points to the first segment in the MTT
 *    that corresponds to that region.
 */
#ifdef	_LITTLE_ENDIAN
struct tavor_hw_mtt_s {
	uint32_t	present		:1;
	uint32_t			:11;
	uint32_t	ptag_l		:20;
	uint32_t	ptag_h;
};
#else
struct tavor_hw_mtt_s {
	uint32_t	ptag_h;
	uint32_t	ptag_l		:20;
	uint32_t			:11;
	uint32_t	present		:1;
};
#endif
#define	TAVOR_MTT_ENTRY_NOTPRESET	0x0
#define	TAVOR_MTT_ENTRY_PRESET		0x1


/*
 * Tavor Event Queue Context Table (EQC) entries
 *    Tavor supports 64 Event Queues, and the status of Event Queues is stored
 *    in the Event Queue Context (EQC) table.  The EQC table is a physically-
 *    contiguous memory structure in the HCA attached local memory.  Each EQC
 *    table entry contains Event Queue status and information required by
 *    the hardware in order to access the event queue.
 *
 *    The following structure is used in the SW2HW_EQ, QUERY_EQ, and HW2SW_EQ
 *    commands.
 *    The SW2HW_EQ command transfers ownership of an EQ context from software
 *    to hardware. The command takes the EQC entry from the input mailbox and
 *    stores it in the EQC in the hardware. The command will fail if the
 *    requested EQC entry is already owned by the hardware.
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
struct tavor_hw_eqc_s {
	uint32_t	start_addr_h;
	uint32_t			:8;
	uint32_t	state		:2;
	uint32_t			:7;
	uint32_t	overrun_ignore	:1;
	uint32_t	xlat		:1;
	uint32_t			:5;
	uint32_t	owner		:4;
	uint32_t	status		:4;
	uint32_t	usr_page	:24;
	uint32_t	log_eq_sz	:5;
	uint32_t			:3;
	uint32_t	start_addr_l;
	uint32_t	intr		:8;
	uint32_t			:24;
	uint32_t	pd		:24;
	uint32_t			:8;
	uint32_t	lkey;
	uint32_t	lost_cnt;
	uint32_t	rsrv0[2];
	uint32_t	prod_indx;
	uint32_t	cons_indx;
	uint32_t	rsrv1[4];
};
#else
struct tavor_hw_eqc_s {
	uint32_t	status		:4;
	uint32_t	owner		:4;
	uint32_t			:5;
	uint32_t	xlat		:1;
	uint32_t	overrun_ignore	:1;
	uint32_t			:7;
	uint32_t	state		:2;
	uint32_t			:8;
	uint32_t	start_addr_h;
	uint32_t	start_addr_l;
	uint32_t			:3;
	uint32_t	log_eq_sz	:5;
	uint32_t	usr_page	:24;
	uint32_t			:8;
	uint32_t	pd		:24;
	uint32_t			:24;
	uint32_t	intr		:8;
	uint32_t	lost_cnt;
	uint32_t	lkey;
	uint32_t	rsrv0[2];
	uint32_t	cons_indx;
	uint32_t	prod_indx;
	uint32_t	rsrv1[4];
};
#endif
#define	TAVOR_EQ_STATUS_OK		0x0
#define	TAVOR_EQ_STATUS_OVERFLOW	0x9
#define	TAVOR_EQ_STATUS_WRITE_FAILURE	0xA

#define	TAVOR_EQ_ARMED			0x1
#define	TAVOR_EQ_FIRED			0x2
#define	TAVOR_EQ_ALWAYS_ARMED		0x3


/*
 * Tavor Event Queue Entries (EQE)
 *    Each EQE contains enough information for the software to identify the
 *    source of the event.  The following structures are used to define each
 *    of the various kinds of events that the Tavor hardware will generate.
 *    Note: The tavor_hw_eqe_t below is the generic "Event Queue Entry".  All
 *    other EQEs differ only in the contents of their "event_data" field.
 *
 *    Below we first define several structures which define the contents of
 *    the "event_data" fields:
 *    tavor_hw_eqe_cq_t for "Completion Queue Events"
 *    tavor_hw_eqe_cqerr_t for "Completion Queue Error Events"
 *    tavor_hw_eqe_portstate_t for "Port State Change Events"
 *    tavor_hw_eqe_cmdcmpl_t for "Command Interface Completion Events"
 *    tavor_hw_eqe_qp_evt_t for "Queue Pair Events" such as Path Migration
 *        Succeeded, Path Migration Failed, Communication Established, Send
 *        Queue Drained, Local WQ Catastrophic Error, Invalid Request Local
 *        WQ Error, and Local Access Violation WQ Error.
 *    tavor_hw_eqe_operr_t for "Operational and Catastrophic Error Events"
 *        such as EQ Overflow, Misbehaved UAR page, Internal Parity Error,
 *        Uplink bus error, and DDR data error.
 *    tavor_hw_eqe_pgflt_t for "Not-present Page Fault on WQE or Data
 *        Buffer Access".  (Note: Currently, this event is unsupported).
 *
 *    Note also: The following structures are not #define'd with both
 *    little-endian and big-endian definitions.  This is because their
 *    individual fields are not directly accessed except through the macros
 *    defined below.
 */
typedef struct tavor_hw_eqe_cq_s {
	uint32_t			:8;
	uint32_t	cqn		:24;
	uint32_t	rsrv0[5];
} tavor_hw_eqe_cq_t;

typedef struct tavor_hw_eqe_cqerr_s {
	uint32_t			:8;
	uint32_t	cqn		:24;
	uint32_t			:32;
	uint32_t			:24;
	uint32_t	syndrome	:8;
	uint32_t	rsrv0[3];
} tavor_hw_eqe_cqerr_t;
#define	TAVOR_CQERR_OVERFLOW		0x1
#define	TAVOR_CQERR_ACCESS_VIOLATION	0x2

typedef struct tavor_hw_eqe_portstate_s {
	uint32_t	rsrv0[2];
	uint32_t			:2;
	uint32_t	port		:2;
	uint32_t			:28;
	uint32_t	rsrv1[3];
} tavor_hw_eqe_portstate_t;
#define	TAVOR_PORT_LINK_ACTIVE		0x4
#define	TAVOR_PORT_LINK_DOWN		0x1

typedef struct tavor_hw_eqe_cmdcmpl_s {
	uint32_t			:16;
	uint32_t	token		:16;
	uint32_t			:32;
	uint32_t			:24;
	uint32_t	status		:8;
	uint32_t	out_param0;
	uint32_t	out_param1;
	uint32_t			:32;
} tavor_hw_eqe_cmdcmpl_t;

typedef struct tavor_hw_eqe_qp_evt_s {
	uint32_t			:8;
	uint32_t	qpn		:24;
	uint32_t			:32;
	uint32_t			:3;
	uint32_t	qp_ee		:1;
	uint32_t			:28;
	uint32_t	rsrv0[3];
} tavor_hw_eqe_qpevt_t;

typedef struct tavor_hw_eqe_operr_s {
	uint32_t	rsrv0[2];
	uint32_t			:24;
	uint32_t	error_type	:8;
	uint32_t	data;
	uint32_t	rsrv1[2];
} tavor_hw_eqe_operr_t;
#define	TAVOR_ERREVT_EQ_OVERFLOW	0x1
#define	TAVOR_ERREVT_BAD_UARPG		0x2
#define	TAVOR_ERREVT_UPLINK_BUSERR	0x3
#define	TAVOR_ERREVT_DDR_DATAERR	0x4
#define	TAVOR_ERREVT_INTERNAL_PARITY	0x5

typedef struct tavor_hw_eqe_pgflt_s {
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
} tavor_hw_eqe_pgflt_t;
#define	TAVOR_PGFLT_PG_NOTPRESENT	0x8
#define	TAVOR_PGFLT_PG_WRACC_VIOL	0xA
#define	TAVOR_PGFLT_UNSUP_NOTPRESENT	0xE
#define	TAVOR_PGFLT_UNSUP_WRACC_VIOL	0xF
#define	TAVOR_PGFLT_WQE_CAUSED		0x1
#define	TAVOR_PGFLT_DATA_CAUSED		0x0
#define	TAVOR_PGFLT_REMOTE_CAUSED	0x1
#define	TAVOR_PGFLT_LOCAL_CAUSED	0x0
#define	TAVOR_PGFLT_SEND_CAUSED		0x1
#define	TAVOR_PGFLT_RECV_CAUSED		0x0
#define	TAVOR_PGFLT_DESC_CONSUMED	0x1
#define	TAVOR_PGFLT_DESC_NOTCONSUMED	0x0

typedef struct tavor_hw_eqe_ecc_s {
	uint32_t	rsrcv0[4];
	uint32_t	overflow	:1;
	uint32_t			:15;
	uint32_t			:2;
	uint32_t	err_ba		:2;
	uint32_t	err_da		:2;
	uint32_t	err_src_id	:3;
	uint32_t	err_rmw		:1;
	uint32_t			:2;
	uint32_t	cause_msb	:1;
	uint32_t			:2;
	uint32_t	cause_lsb	:1;

	uint32_t	err_ca		:16;
	uint32_t	err_ra		:16;
} tavor_hw_eqe_ecc_t;

struct tavor_hw_eqe_s {
	uint32_t			:8;
	uint32_t	event_type	:8;
	uint32_t			:8;
	uint32_t	event_subtype	:8;
	union {
		tavor_hw_eqe_cq_t		eqe_cq;
		tavor_hw_eqe_cqerr_t		eqe_cqerr;
		tavor_hw_eqe_portstate_t	eqe_portstate;
		tavor_hw_eqe_cmdcmpl_t		eqe_cmdcmpl;
		tavor_hw_eqe_qpevt_t		eqe_qpevt;
		tavor_hw_eqe_operr_t		eqe_operr;
		tavor_hw_eqe_pgflt_t		eqe_pgflt;
		tavor_hw_eqe_ecc_t		eqe_ecc;
	} event_data;
	uint32_t			:24;
	uint32_t	owner		:1;
	uint32_t			:7;
};
#define	eqe_cq				event_data.eqe_cq
#define	eqe_cqerr			event_data.eqe_cqerr
#define	eqe_portstate			event_data.eqe_portstate
#define	eqe_cmdcmpl			event_data.eqe_cmdcmpl
#define	eqe_qpevt			event_data.eqe_qpevt
#define	eqe_operr			event_data.eqe_operr
#define	eqe_pgflt			event_data.eqe_pgflt

/*
 * The following macros are used for extracting (and in some cases filling in)
 * information from EQEs
 */
#define	TAVOR_EQE_EVTTYPE_MASK		0x00FF0000
#define	TAVOR_EQE_EVTTYPE_SHIFT		16
#define	TAVOR_EQE_EVTSUBTYPE_MASK	0x000000FF
#define	TAVOR_EQE_EVTSUBTYPE_SHIFT	0
#define	TAVOR_EQE_CQNUM_MASK		0x00FFFFFF
#define	TAVOR_EQE_CQNUM_SHIFT		0
#define	TAVOR_EQE_QPNUM_MASK		0x00FFFFFF
#define	TAVOR_EQE_QPNUM_SHIFT		0
#define	TAVOR_EQE_PORTNUM_MASK		0x30000000
#define	TAVOR_EQE_PORTNUM_SHIFT		28
#define	TAVOR_EQE_CMDTOKEN_MASK		0x0000FFFF
#define	TAVOR_EQE_CMDTOKEN_SHIFT	0
#define	TAVOR_EQE_CMDSTATUS_MASK	0x000000FF
#define	TAVOR_EQE_CMDSTATUS_SHIFT	0
#define	TAVOR_EQE_OPERRTYPE_MASK 	0x000000FF
#define	TAVOR_EQE_OPERRTYPE_SHIFT	0
#define	TAVOR_EQE_OWNER_MASK		0x00000080
#define	TAVOR_EQE_OWNER_SHIFT		7

#define	TAVOR_EQE_EVTTYPE_GET(eq, eqe)					\
	((ddi_get32((eq)->eq_eqinfo.qa_acchdl,				\
	    &((uint32_t *)(eqe))[0]) & TAVOR_EQE_EVTTYPE_MASK) >>	\
	    TAVOR_EQE_EVTTYPE_SHIFT)
#define	TAVOR_EQE_EVTSUBTYPE_GET(eq, eqe)				\
	((ddi_get32((eq)->eq_eqinfo.qa_acchdl,				\
	    &((uint32_t *)(eqe))[0]) & TAVOR_EQE_EVTSUBTYPE_MASK) >>	\
	    TAVOR_EQE_EVTSUBTYPE_SHIFT)
#define	TAVOR_EQE_CQNUM_GET(eq, eqe)					\
	((ddi_get32((eq)->eq_eqinfo.qa_acchdl,				\
	    &((uint32_t *)(eqe))[1]) & TAVOR_EQE_CQNUM_MASK) >>		\
	    TAVOR_EQE_CQNUM_SHIFT)
#define	TAVOR_EQE_QPNUM_GET(eq, eqe)					\
	((ddi_get32((eq)->eq_eqinfo.qa_acchdl,				\
	&((uint32_t *)(eqe))[1]) & TAVOR_EQE_QPNUM_MASK) >>		\
	TAVOR_EQE_QPNUM_SHIFT)
#define	TAVOR_EQE_PORTNUM_GET(eq, eqe)					\
	((ddi_get32((eq)->eq_eqinfo.qa_acchdl,				\
	    &((uint32_t *)(eqe))[3]) & TAVOR_EQE_PORTNUM_MASK) >>	\
	    TAVOR_EQE_PORTNUM_SHIFT)
#define	TAVOR_EQE_CMDTOKEN_GET(eq, eqe)					\
	((ddi_get32((eq)->eq_eqinfo.qa_acchdl,				\
	    &((uint32_t *)(eqe))[1]) & TAVOR_EQE_CMDTOKEN_MASK) >>	\
	    TAVOR_EQE_CMDTOKEN_SHIFT)
#define	TAVOR_EQE_CMDSTATUS_GET(eq, eqe)				\
	((ddi_get32((eq)->eq_eqinfo.qa_acchdl,				\
	    &((uint32_t *)(eqe))[3]) & TAVOR_EQE_CMDSTATUS_MASK) >>	\
	    TAVOR_EQE_CMDSTATUS_SHIFT)
#define	TAVOR_EQE_CMDOUTP0_GET(eq, eqe)					\
	(ddi_get32((eq)->eq_eqinfo.qa_acchdl, &((uint32_t *)(eqe))[4]))
#define	TAVOR_EQE_CMDOUTP1_GET(eq, eqe)					\
	(ddi_get32((eq)->eq_eqinfo.qa_acchdl, &((uint32_t *)(eqe))[5]))
#define	TAVOR_EQE_OPERRTYPE_GET(eq, eqe)				\
	((ddi_get32((eq)->eq_eqinfo.qa_acchdl,				\
	    &((uint32_t *)(eqe))[3]) & TAVOR_EQE_OPERRTYPE_MASK) >>	\
	    TAVOR_EQE_OPERRTYPE_SHIFT)
#define	TAVOR_EQE_OPERRDATA_GET(eq, eqe)				\
	(ddi_get32((eq)->eq_eqinfo.qa_acchdl, &((uint32_t *)(eqe))[4]))
#define	TAVOR_EQE_OWNER_IS_SW(eq, eqe)					\
	(((ddi_get32((eq)->eq_eqinfo.qa_acchdl,				\
	    &((uint32_t *)(eqe))[7]) & TAVOR_EQE_OWNER_MASK) >>		\
	    TAVOR_EQE_OWNER_SHIFT) == TAVOR_SW_OWNER)
#define	TAVOR_EQE_OWNER_SET_HW(eq, eqe)					\
	(ddi_put32((eq)->eq_eqinfo.qa_acchdl, &((uint32_t *)(eqe))[7],	\
	    ((TAVOR_HW_OWNER <<	TAVOR_EQE_OWNER_SHIFT) &		\
	    TAVOR_EQE_OWNER_MASK)))


/*
 * Tavor Completion Queue Context Table (CQC) entries
 *    The CQC table is a physically-contiguous memory area residing in HCA
 *    attached local memory.  Each CQC table entry contains information
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
struct tavor_hw_cqc_s {
	uint32_t	start_addr_h;
	uint32_t			:8;
	uint32_t	state		:4;
	uint32_t			:5;
	uint32_t	overrun_ignore	:1;
	uint32_t	xlat		:1;
	uint32_t			:9;
	uint32_t	status		:4;
	uint32_t	usr_page	:24;
	uint32_t	log_cq_sz	:5;
	uint32_t			:3;
	uint32_t	start_addr_l;
	uint32_t	c_eqn		:8;
	uint32_t			:24;
	uint32_t	e_eqn		:8;
	uint32_t			:24;
	uint32_t	lkey;
	uint32_t	pd		:24;
	uint32_t			:8;
	uint32_t	solicit_prod_indx;
	uint32_t	last_notified_indx;
	uint32_t	prod_indx;
	uint32_t	cons_indx;
	uint32_t			:32;
	uint32_t	cqn		:24;
	uint32_t			:8;
	uint32_t	rsrv0[2];
};
#else
struct tavor_hw_cqc_s {
	uint32_t	status		:4;
	uint32_t			:9;
	uint32_t	xlat		:1;
	uint32_t	overrun_ignore	:1;
	uint32_t			:5;
	uint32_t	state		:4;
	uint32_t			:8;
	uint32_t	start_addr_h;
	uint32_t	start_addr_l;
	uint32_t			:3;
	uint32_t	log_cq_sz	:5;
	uint32_t	usr_page	:24;
	uint32_t			:24;
	uint32_t	e_eqn		:8;
	uint32_t			:24;
	uint32_t	c_eqn		:8;
	uint32_t			:8;
	uint32_t	pd		:24;
	uint32_t	lkey;
	uint32_t	last_notified_indx;
	uint32_t	solicit_prod_indx;
	uint32_t	cons_indx;
	uint32_t	prod_indx;
	uint32_t			:8;
	uint32_t	cqn		:24;
	uint32_t			:32;
	uint32_t	rsrv0[2];
};
#endif
#define	TAVOR_CQ_STATUS_OK		0x0
#define	TAVOR_CQ_STATUS_OVERFLOW	0x9
#define	TAVOR_CQ_STATUS_WRITE_FAILURE	0xA

#define	TAVOR_CQ_DISARMED		0x0
#define	TAVOR_CQ_ARMED			0x1
#define	TAVOR_CQ_ARMED_SOLICITED	0x4
#define	TAVOR_CQ_FIRED			0xA

/*
 * Tavor Completion Queue Entries (CQE)
 *    Each CQE contains enough information for the software to associate the
 *    completion with the Work Queue Element (WQE) to which it corresponds.
 *
 *    Note: The following structure is not #define'd with both little-endian
 *    and big-endian definitions.  This is because each CQE's individual
 *    fields are not directly accessed except through the macros defined below.
 */
struct tavor_hw_cqe_s {
	uint32_t	ver		:4;
	uint32_t			:4;
	uint32_t	my_qpn		:24;
	uint32_t			:8;
	uint32_t	my_ee		:24;
	uint32_t			:8;
	uint32_t	rqpn		:24;
	uint32_t	sl		:4;
	uint32_t			:4;
	uint32_t	grh		:1;
	uint32_t	ml_path		:7;
	uint32_t	rlid		:16;
	uint32_t	imm_eth_pkey_cred;
	uint32_t	byte_cnt;
	uint32_t	wqe_addr	:26;
	uint32_t	wqe_sz		:6;
	uint32_t	opcode		:8;
	uint32_t	send_or_recv	:1;
	uint32_t			:15;
	uint32_t	owner		:1;
	uint32_t			:7;
};
#define	TAVOR_COMPLETION_RECV		0x0
#define	TAVOR_COMPLETION_SEND		0x1

#define	TAVOR_CQE_DEFAULT_VERSION	0x0

/*
 * The following macros are used for extracting (and in some cases filling in)
 * information from CQEs
 */
#define	TAVOR_CQE_QPNUM_MASK		0x00FFFFFF
#define	TAVOR_CQE_QPNUM_SHIFT		0
#define	TAVOR_CQE_DQPN_MASK		0x00FFFFFF
#define	TAVOR_CQE_DQPN_SHIFT		0
#define	TAVOR_CQE_SL_MASK		0xF0000000
#define	TAVOR_CQE_SL_SHIFT		28
#define	TAVOR_CQE_GRH_MASK		0x00800000
#define	TAVOR_CQE_GRH_SHIFT		23
#define	TAVOR_CQE_PATHBITS_MASK		0x007F0000
#define	TAVOR_CQE_PATHBITS_SHIFT	16
#define	TAVOR_CQE_DLID_MASK		0x0000FFFF
#define	TAVOR_CQE_DLID_SHIFT		0
#define	TAVOR_CQE_OPCODE_MASK		0xFF000000
#define	TAVOR_CQE_OPCODE_SHIFT		24
#define	TAVOR_CQE_SENDRECV_MASK		0x00800000
#define	TAVOR_CQE_SENDRECV_SHIFT	23
#define	TAVOR_CQE_OWNER_MASK		0x00000080
#define	TAVOR_CQE_OWNER_SHIFT		7

#define	TAVOR_CQE_QPNUM_GET(cq, cqe)					\
	((ddi_get32((cq)->cq_cqinfo.qa_acchdl,				\
	    &((uint32_t *)(cqe))[0]) & TAVOR_CQE_QPNUM_MASK) >>		\
	    TAVOR_CQE_QPNUM_SHIFT)
#define	TAVOR_CQE_DQPN_GET(cq, cqe)					\
	((ddi_get32((cq)->cq_cqinfo.qa_acchdl,				\
	    &((uint32_t *)(cqe))[2]) & TAVOR_CQE_DQPN_MASK) >>		\
	    TAVOR_CQE_DQPN_SHIFT)
#define	TAVOR_CQE_SL_GET(cq, cqe)					\
	((ddi_get32((cq)->cq_cqinfo.qa_acchdl,				\
	    &((uint32_t *)(cqe))[3]) & TAVOR_CQE_SL_MASK) >>		\
	    TAVOR_CQE_SL_SHIFT)
#define	TAVOR_CQE_GRH_GET(cq, cqe)					\
	((ddi_get32((cq)->cq_cqinfo.qa_acchdl,				\
	    &((uint32_t *)(cqe))[3]) & TAVOR_CQE_GRH_MASK) >>		\
	    TAVOR_CQE_GRH_SHIFT)
#define	TAVOR_CQE_PATHBITS_GET(cq, cqe)					\
	((ddi_get32((cq)->cq_cqinfo.qa_acchdl,				\
	    &((uint32_t *)(cqe))[3]) & TAVOR_CQE_PATHBITS_MASK) >>	\
	    TAVOR_CQE_PATHBITS_SHIFT)
#define	TAVOR_CQE_DLID_GET(cq, cqe)					\
	((ddi_get32((cq)->cq_cqinfo.qa_acchdl,				\
	    &((uint32_t *)(cqe))[3]) & TAVOR_CQE_DLID_MASK) >>		\
	    TAVOR_CQE_DLID_SHIFT)
#define	TAVOR_CQE_IMM_ETH_PKEY_CRED_GET(cq, cqe)			\
	(ddi_get32((cq)->cq_cqinfo.qa_acchdl, &((uint32_t *)(cqe))[4]))
#define	TAVOR_CQE_IMM_ETH_PKEY_CRED_SET(cq, cqe, arg)			\
	(ddi_put32((cq)->cq_cqinfo.qa_acchdl, &((uint32_t *)(cqe))[4],	\
	    (arg)))
#define	TAVOR_CQE_BYTECNT_GET(cq, cqe)					\
	(ddi_get32((cq)->cq_cqinfo.qa_acchdl, &((uint32_t *)(cqe))[5]))
#define	TAVOR_CQE_WQEADDRSZ_GET(cq, cqe)				\
	(ddi_get32((cq)->cq_cqinfo.qa_acchdl, &((uint32_t *)(cqe))[6]))
#define	TAVOR_CQE_WQEADDRSZ_SET(cq, cqe, arg)				\
	(ddi_put32((cq)->cq_cqinfo.qa_acchdl, &((uint32_t *)(cqe))[6],	\
	    (arg)))
#define	TAVOR_CQE_OPCODE_GET(cq, cqe)					\
	((ddi_get32((cq)->cq_cqinfo.qa_acchdl,				\
	    &((uint32_t *)(cqe))[7]) & TAVOR_CQE_OPCODE_MASK) >>	\
	    TAVOR_CQE_OPCODE_SHIFT)
#define	TAVOR_CQE_SENDRECV_GET(cq, cqe)					\
	((ddi_get32((cq)->cq_cqinfo.qa_acchdl,				\
	    &((uint32_t *)(cqe))[7]) & TAVOR_CQE_SENDRECV_MASK) >>	\
	    TAVOR_CQE_SENDRECV_SHIFT)
#define	TAVOR_CQE_OWNER_IS_SW(cq, cqe)					\
	(((ddi_get32((cq)->cq_cqinfo.qa_acchdl,				\
	    &((uint32_t *)(cqe))[7]) & TAVOR_CQE_OWNER_MASK) >>		\
	    TAVOR_CQE_OWNER_SHIFT) == TAVOR_SW_OWNER)
#ifdef	_LITTLE_ENDIAN
#define	TAVOR_CQE_OWNER_SET_HW(cq, cqe)					\
	{								\
	    if ((cq)->cq_is_umap) {					\
		((uint32_t *)(cqe))[7] = 0x80000000;			\
	    } else {							\
		ddi_put32((cq)->cq_cqinfo.qa_acchdl,			\
		    &((uint32_t *)(cqe))[7], 0x00000080);		\
	    }								\
	}
#else
#define	TAVOR_CQE_OWNER_SET_HW(cq, cqe)					\
	{								\
	    if ((cq)->cq_is_umap) {					\
		((uint32_t *)(cqe))[7] = 0x00000080;			\
	    } else {							\
		ddi_put32((cq)->cq_cqinfo.qa_acchdl,			\
		    &((uint32_t *)(cqe))[7], 0x00000080);		\
	    }								\
	}
#endif

/*
 * Tavor Shared Receive Queue (SRQ) Context Entry Format
 */
#ifdef _LITTLE_ENDIAN
struct tavor_hw_srqc_s {
	uint32_t	ds			:5;
	uint32_t	next_wqe_addr_l		:27;
	uint32_t	wqe_addr_h;

	uint32_t	lkey;
	uint32_t	pd			:24;
	uint32_t				:4;
	uint32_t	state			:4;

	uint32_t	wqe_cnt			:16;
	uint32_t				:16;
	uint32_t	uar			:24;
	uint32_t				:8;
};
#else
struct tavor_hw_srqc_s {
	uint32_t	wqe_addr_h;
	uint32_t	next_wqe_addr_l		:27;
	uint32_t	ds			:5;

	uint32_t	state			:4;
	uint32_t				:4;
	uint32_t	pd			:24;
	uint32_t	lkey;

	uint32_t				:8;
	uint32_t	uar			:24;
	uint32_t				:16;
	uint32_t	wqe_cnt			:16;
};
#endif

/*
 * Tavor MOD_STAT_CFG input mailbox structure
 */
#ifdef _LITTLE_ENDIAN
struct tavor_hw_mod_stat_cfg_s {
	uint32_t				:32;
	uint32_t	log_max_srq		:5;
	uint32_t				:1;
	uint32_t	srq			:1;
	uint32_t	srq_m			:1;
	uint32_t				:24;
	uint32_t	reserved[62];
};
#else
struct tavor_hw_mod_stat_cfg_s {
	uint32_t				:24;
	uint32_t	srq_m			:1;
	uint32_t	srq			:1;
	uint32_t				:1;
	uint32_t	log_max_srq		:5;
	uint32_t				:32;
	uint32_t	reserved[62];
};
#endif

/*
 * Tavor UD Address Vector (UDAV)
 *    Tavor UDAV are used in conjunction with Unreliable Datagram (UD) send
 *    WQEs. Each UD send message specifies an address vector that denotes its
 *    link and (optional) network layer destination address.  The IBA verbs
 *    interface enables the separation of the address administration from the
 *    send WQE posting. The verbs consumer must use special verbs to create
 *    and modify address handles (which represent hardware address vectors).
 *    When posting send WQEs to UD QP, the verbs consumer must supply a
 *    valid address handle/UDAV.
 */
#ifdef	_LITTLE_ENDIAN
struct tavor_hw_udav_s {
	uint32_t	rlid		:16;
	uint32_t	ml_path		:7;
	uint32_t	grh		:1;
	uint32_t			:8;
	uint32_t	pd		:24;
	uint32_t	portnum		:2;
	uint32_t			:6;
	uint32_t	flow_label	:20;
	uint32_t	tclass		:8;
	uint32_t	sl		:4;
	uint32_t	hop_limit	:8;
	uint32_t	max_stat_rate	:3;
	uint32_t			:1;
	uint32_t	msg_sz		:2;
	uint32_t			:2;
	uint32_t	mgid_index	:6;
	uint32_t			:10;
	uint64_t	rgid_h;
	uint64_t	rgid_l;
};
#else
struct tavor_hw_udav_s {
	uint32_t			:6;
	uint32_t	portnum		:2;
	uint32_t	pd		:24;
	uint32_t			:8;
	uint32_t	grh		:1;
	uint32_t	ml_path		:7;
	uint32_t	rlid		:16;
	uint32_t			:10;
	uint32_t	mgid_index	:6;
	uint32_t			:2;
	uint32_t	msg_sz		:2;
	uint32_t			:1;
	uint32_t	max_stat_rate	:3;
	uint32_t	hop_limit	:8;
	uint32_t	sl		:4;
	uint32_t	tclass		:8;
	uint32_t	flow_label	:20;
	uint64_t	rgid_h;
	uint64_t	rgid_l;
};
#endif
#define	TAVOR_UDAV_MODIFY_MASK0		0xFCFFFFFFFF000000ULL
#define	TAVOR_UDAV_MODIFY_MASK1		0xFFC0F80000000000ULL


/*
 * Tavor Queue Pair Context Table (QPC) entries
 *    The QPC table is a physically-contiguous memory area residing in HCA
 *    attached local memory.  Each QPC entry is accessed for reads and writes
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
 *    Below we first define the tavor_hw_addr_path_t or "Tavor Address Path"
 *    structure.  This structure is used to provide address path information
 *    (both primary and secondary) for each QP context.  Note:  Since this
 *    structure is _very_ similar to the tavor_hw_udav_t structure above,
 *    we are able to leverage the similarity with filling in and reading from
 *    the two types of structures.  See tavor_get_addr_path() and
 *    tavor_set_addr_path() in tavor_misc.c for more details.
 */
#ifdef	_LITTLE_ENDIAN
struct tavor_hw_addr_path_s {
	uint32_t	rlid		:16;
	uint32_t	ml_path		:7;
	uint32_t	grh		:1;
	uint32_t			:5;
	uint32_t	rnr_retry	:3;
	uint32_t	pkey_indx	:7;
	uint32_t			:17;
	uint32_t	portnum		:2;
	uint32_t			:6;
	uint32_t	flow_label	:20;
	uint32_t	tclass		:8;
	uint32_t	sl		:4;
	uint32_t	hop_limit	:8;
	uint32_t	max_stat_rate	:3;
	uint32_t			:5;
	uint32_t	mgid_index	:6;
	uint32_t			:5;
	uint32_t	ack_timeout	:5;
	uint64_t	rgid_h;
	uint64_t	rgid_l;
};
#else
struct tavor_hw_addr_path_s {
	uint32_t			:6;
	uint32_t	portnum		:2;
	uint32_t			:17;
	uint32_t	pkey_indx	:7;
	uint32_t	rnr_retry	:3;
	uint32_t			:5;
	uint32_t	grh		:1;
	uint32_t	ml_path		:7;
	uint32_t	rlid		:16;
	uint32_t	ack_timeout	:5;
	uint32_t			:5;
	uint32_t	mgid_index	:6;
	uint32_t			:5;
	uint32_t	max_stat_rate	:3;
	uint32_t	hop_limit	:8;
	uint32_t	sl		:4;
	uint32_t	tclass		:8;
	uint32_t	flow_label	:20;
	uint64_t	rgid_h;
	uint64_t	rgid_l;
};
#endif

#ifdef	_LITTLE_ENDIAN
struct tavor_hw_qpc_s {
	uint32_t	sched_q		:4;
	uint32_t			:28;
	uint32_t			:8;
	uint32_t	de		:1;
	uint32_t			:2;
	uint32_t	pm_state	:2;
	uint32_t			:3;
	uint32_t	serv_type	:3;
	uint32_t			:9;
	uint32_t	state		:4;
	uint32_t	usr_page	:24;
	uint32_t			:8;
	uint32_t			:24;
	uint32_t	msg_max		:5;
	uint32_t	mtu		:3;
	uint32_t	rem_qpn		:24;
	uint32_t			:8;
	uint32_t	loc_qpn		:24;
	uint32_t			:8;
	uint32_t			:32;
	uint32_t			:32;
	tavor_hw_addr_path_t	pri_addr_path;
	tavor_hw_addr_path_t	alt_addr_path;
	uint32_t	pd		:24;
	uint32_t			:8;
	uint32_t	rdd		:24;
	uint32_t			:8;
	uint32_t	wqe_lkey;
	uint32_t	wqe_baseaddr;
	uint32_t			:32;
	uint32_t			:3;
	uint32_t	ssc		:1;
	uint32_t	sic		:1;
	uint32_t	cur_retry_cnt	:3;
	uint32_t	cur_rnr_retry	:3;
	uint32_t			:2;
	uint32_t	sae		:1;
	uint32_t	swe		:1;
	uint32_t	sre		:1;
	uint32_t	retry_cnt	:3;
	uint32_t			:2;
	uint32_t	sra_max		:3;
	uint32_t	flight_lim	:4;
	uint32_t	ack_req_freq	:4;
	uint32_t	cqn_snd		:24;
	uint32_t			:8;
	uint32_t	next_snd_psn	:24;
	uint32_t			:8;
	uint64_t	next_snd_wqe;
	uint32_t	ssn		:24;
	uint32_t			:8;
	uint32_t	last_acked_psn	:24;
	uint32_t			:8;
	uint32_t	next_rcv_psn	:24;
	uint32_t	min_rnr_nak	:5;
	uint32_t			:3;
	uint32_t			:3;
	uint32_t	rsc		:1;
	uint32_t	ric		:1;
	uint32_t			:8;
	uint32_t	rae		:1;
	uint32_t	rwe		:1;
	uint32_t	rre		:1;
	uint32_t			:5;
	uint32_t	rra_max		:3;
	uint32_t			:8;
	uint32_t	cqn_rcv		:24;
	uint32_t			:8;
	uint32_t			:5;
	uint32_t	ra_buff_indx	:27;
	uint64_t	next_rcv_wqe;
	uint32_t	srq_number	:24;
	uint32_t	srq_en		:1;
	uint32_t			:7;
	uint32_t	qkey;
	uint32_t			:32;
	uint32_t	rmsn		:24;
	uint32_t			:8;
	uint32_t	rsrv0[18];
};
#else
struct tavor_hw_qpc_s {
	uint32_t	state		:4;
	uint32_t			:9;
	uint32_t	serv_type	:3;
	uint32_t			:3;
	uint32_t	pm_state	:2;
	uint32_t			:2;
	uint32_t	de		:1;
	uint32_t			:8;
	uint32_t			:28;
	uint32_t	sched_q		:4;
	uint32_t	mtu		:3;
	uint32_t	msg_max		:5;
	uint32_t			:24;
	uint32_t			:8;
	uint32_t	usr_page	:24;
	uint32_t			:8;
	uint32_t	loc_qpn		:24;
	uint32_t			:8;
	uint32_t	rem_qpn		:24;
	uint32_t			:32;
	uint32_t			:32;
	tavor_hw_addr_path_t	pri_addr_path;
	tavor_hw_addr_path_t	alt_addr_path;
	uint32_t			:8;
	uint32_t	rdd		:24;
	uint32_t			:8;
	uint32_t	pd		:24;
	uint32_t	wqe_baseaddr;
	uint32_t	wqe_lkey;
	uint32_t	ack_req_freq	:4;
	uint32_t	flight_lim	:4;
	uint32_t	sra_max		:3;
	uint32_t			:2;
	uint32_t	retry_cnt	:3;
	uint32_t	sre		:1;
	uint32_t	swe		:1;
	uint32_t	sae		:1;
	uint32_t			:2;
	uint32_t	cur_rnr_retry	:3;
	uint32_t	cur_retry_cnt	:3;
	uint32_t	sic		:1;
	uint32_t	ssc		:1;
	uint32_t			:3;
	uint32_t			:32;
	uint32_t			:8;
	uint32_t	next_snd_psn	:24;
	uint32_t			:8;
	uint32_t	cqn_snd		:24;
	uint64_t	next_snd_wqe;
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
	uint32_t			:8;
	uint32_t	ric		:1;
	uint32_t	rsc		:1;
	uint32_t			:3;
	uint32_t			:3;
	uint32_t	min_rnr_nak	:5;
	uint32_t	next_rcv_psn	:24;
	uint32_t	ra_buff_indx	:27;
	uint32_t			:5;
	uint32_t			:8;
	uint32_t	cqn_rcv		:24;
	uint64_t	next_rcv_wqe;
	uint32_t	qkey;
	uint32_t			:7;
	uint32_t	srq_en		:1;
	uint32_t	srq_number	:24;
	uint32_t			:8;
	uint32_t	rmsn		:24;
	uint32_t			:32;
	uint32_t	rsrv0[18];
};
#endif
#define	TAVOR_QP_RESET			0x0
#define	TAVOR_QP_INIT			0x1
#define	TAVOR_QP_RTR			0x2
#define	TAVOR_QP_RTS			0x3
#define	TAVOR_QP_SQERR			0x4
#define	TAVOR_QP_SQD			0x5
#define	TAVOR_QP_ERR			0x6
#define	TAVOR_QP_SQDRAINING		0x7

#define	TAVOR_QP_RC			0x0
#define	TAVOR_QP_UC			0x1
#define	TAVOR_QP_UD			0x3
#define	TAVOR_QP_MLX			0x7

#define	TAVOR_QP_PMSTATE_MIGRATED	0x3
#define	TAVOR_QP_PMSTATE_ARMED		0x0
#define	TAVOR_QP_PMSTATE_REARM		0x1

#define	TAVOR_QP_DESC_EVT_DISABLED	0x0
#define	TAVOR_QP_DESC_EVT_ENABLED	0x1

#define	TAVOR_QP_FLIGHT_LIM_UNLIMITED	0xF

#define	TAVOR_QP_SQ_ALL_SIGNALED	0x1
#define	TAVOR_QP_SQ_WR_SIGNALED		0x0
#define	TAVOR_QP_RQ_ALL_SIGNALED	0x1
#define	TAVOR_QP_RQ_WR_SIGNALED		0x0

#define	TAVOR_QP_SRQ_ENABLED	0x1
#define	TAVOR_QP_SRQ_DISABLED	0x0


/*
 * Tavor Multicast Group Member (MCG)
 *    Tavor MCG are organized in a physically-contiguous memory table (the
 *    Multicast Group Table) in the HCA attached local memory.  This table is
 *    actually comprised of two consecutive tables: the Multicast Group Hash
 *    Table (MGHT) and the Additional Multicast Group Members Table (AMGM).
 *    Each such entry contains an MGID and a list of QPs that are attached to
 *    the multicast group.  Each such entry may also include an index to an
 *    Additional Multicast Group Member Table (AMGM) entry.  The AMGMs are
 *    used to form a linked list of MCG entries that all map to the same hash
 *    value.  The MCG entry size is configured through the INIT_HCA command.
 *    Note:  An MCG actually consists of a single tavor_hw_mcg_t and some
 *    number of tavor_hw_mcg_qp_list_t (such that the combined structure is a
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
struct tavor_hw_mcg_s {
	uint32_t			:32;
	uint32_t			:6;
	uint32_t	next_gid_indx	:26;
	uint32_t			:32;
	uint32_t			:32;
	uint64_t	mgid_h;
	uint64_t	mgid_l;
};
#else
struct tavor_hw_mcg_s {
	uint32_t	next_gid_indx	:26;
	uint32_t			:6;
	uint32_t			:32;
	uint32_t			:32;
	uint32_t			:32;
	uint64_t	mgid_h;
	uint64_t	mgid_l;
};
#endif

/* Multicast Group Member - QP List entries */
#ifdef	_LITTLE_ENDIAN
struct tavor_hw_mcg_qp_list_s {
	uint32_t	qpn		:24;
	uint32_t			:7;
	uint32_t	q		:1;
};
#else
struct tavor_hw_mcg_qp_list_s {
	uint32_t	q		:1;
	uint32_t			:7;
	uint32_t	qpn		:24;
};
#endif
#define	TAVOR_MCG_QPN_INVALID		0x0
#define	TAVOR_MCG_QPN_VALID		0x1

/*
 * Structure for getting the peformance counters from the HCA
 */

#ifdef _LITTLE_ENDIAN
struct tavor_hw_sm_perfcntr_s {
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
struct tavor_hw_sm_perfcntr_s {
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
 * Tavor User Access Region (UAR)
 *    Tavor doorbells are each rung by writing to the doorbell registers that
 *    form a User Access Region (UAR).  A doorbell is a write-only hardware
 *    register which enables passing information from software to hardware
 *    with minimum software latency. A write operation from the host software
 *    to these doorbell registers passes information about the HCA resources
 *    and initiates processing of the doorbell data.  There are 6 types of
 *    doorbells in Tavor.
 *
 *    "Send Doorbell" for synchronizing the attachment of a WQE (or a chain
 *        of WQEs) to the send queue.
 *    "RD Send Doorbell" (Same as above, except for RD QPs) is not supported.
 *    "Receive Doorbell" for synchronizing the attachment of a WQE (or a chain
 *        of WQEs) to the receive queue.
 *    "CQ Doorbell" for updating the CQ consumer index and requesting
 *        completion notifications.
 *    "EQ Doorbell" for updating the EQ consumer index, arming interrupt
 *        triggering, and disarming CQ notification requests.
 *    "InfiniBlast" (which would have enabled access to the "InfiniBlast
 *        buffer") is not supported.
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
typedef struct tavor_hw_uar_send_s {
	uint32_t	nda		:26;
	uint32_t	fence		:1;
	uint32_t	nopcode		:5;
	uint32_t	qpn		:24;
	uint32_t			:2;
	uint32_t	nds		:6;
} tavor_hw_uar_send_t;
#define	TAVOR_QPSNDDB_NDA_MASK		0xFFFFFFC0
#define	TAVOR_QPSNDDB_NDA_SHIFT		0x20
#define	TAVOR_QPSNDDB_F_SHIFT		0x25
#define	TAVOR_QPSNDDB_NOPCODE_SHIFT	0x20
#define	TAVOR_QPSNDDB_QPN_SHIFT		0x8

typedef struct tavor_hw_uar_recv_s {
	uint32_t	nda		:26;
	uint32_t	nds		:6;
	uint32_t	qpn		:24;
	uint32_t	credits		:8;
} tavor_hw_uar_recv_t;
#define	TAVOR_QPRCVDB_NDA_MASK		0xFFFFFFC0
#define	TAVOR_QPRCVDB_NDA_SHIFT		0x20
#define	TAVOR_QPRCVDB_NDS_SHIFT		0x20
#define	TAVOR_QPRCVDB_QPN_SHIFT		0x8
/* Max descriptors per Tavor doorbell */
#define	TAVOR_QP_MAXDESC_PER_DB		256

typedef struct tavor_hw_uar_cq_s {
	uint32_t	cmd		:8;
	uint32_t	cqn		:24;
	uint32_t	param;
} tavor_hw_uar_cq_t;
#define	TAVOR_CQDB_CMD_SHIFT		0x38
#define	TAVOR_CQDB_CQN_SHIFT		0x20

#define	TAVOR_CQDB_INCR_CONSINDX	0x01
#define	TAVOR_CQDB_NOTIFY_CQ		0x02
#define	TAVOR_CQDB_NOTIFY_CQ_SOLICIT	0x03
#define	TAVOR_CQDB_SET_CONSINDX		0x04
/* Default value for use in NOTIFY_CQ doorbell */
#define	TAVOR_CQDB_DEFAULT_PARAM	0xFFFFFFFF

typedef struct tavor_hw_uar_eq_s {
	uint32_t	cmd		:8;
	uint32_t			:18;
	uint32_t	eqn		:6;
	uint32_t	param;
} tavor_hw_uar_eq_t;
#define	TAVOR_EQDB_CMD_SHIFT		0x38
#define	TAVOR_EQDB_EQN_SHIFT		0x20

#define	TAVOR_EQDB_INCR_CONSINDX	0x01
#define	TAVOR_EQDB_REARM_EQ		0x02
#define	TAVOR_EQDB_DISARM_CQ		0x03
#define	TAVOR_EQDB_SET_CONSINDX		0x04
#define	TAVOR_EQDB_SET_ALWAYSARMED	0x05

struct tavor_hw_uar_s {
	uint32_t		rsrv0[4];	/* "RD Send" unsupported */
	tavor_hw_uar_send_t	send;
	tavor_hw_uar_recv_t	recv;
	tavor_hw_uar_cq_t	cq;
	tavor_hw_uar_eq_t	eq;
	uint32_t		rsrv1[244];
	uint32_t		iblast[256];	/* "InfiniBlast" unsupported */
};


/*
 * Tavor Send Work Queue Element (WQE)
 *    A Tavor Send WQE is built of the following segments, each of which is a
 *    multiple of 16 bytes.  Note: Each individual WQE may contain only a
 *    subset of these segments described below (according to the operation type
 *    and transport type of the QP).
 *
 *    The first 16 bytes of ever WQE are formed from the "Next/Ctrl" segment.
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
struct tavor_hw_snd_wqe_nextctrl_s {
	uint32_t	next_wqe_addr	:26;
	uint32_t			:1;
	uint32_t	nopcode		:5;
	uint32_t	next_eec	:24;
	uint32_t	dbd		:1;
	uint32_t	fence		:1;
	uint32_t	nds		:6;

	uint32_t			:28;
	uint32_t	c		:1;
	uint32_t	e		:1;
	uint32_t	s		:1;
	uint32_t	i		:1;
	uint32_t	immediate	:32;
};
#define	TAVOR_WQE_NDA_MASK		0x00000000FFFFFFC0ull
#define	TAVOR_WQE_NDS_MASK		0x3F
#define	TAVOR_WQE_DBD_MASK		0x80

#define	TAVOR_WQE_SEND_FENCE_MASK	0x40
#define	TAVOR_WQE_SEND_NOPCODE_RDMAW	0x8
#define	TAVOR_WQE_SEND_NOPCODE_RDMAWI	0x9
#define	TAVOR_WQE_SEND_NOPCODE_SEND	0xA
#define	TAVOR_WQE_SEND_NOPCODE_SENDI	0xB
#define	TAVOR_WQE_SEND_NOPCODE_RDMAR	0x10
#define	TAVOR_WQE_SEND_NOPCODE_ATMCS	0x11
#define	TAVOR_WQE_SEND_NOPCODE_ATMFA	0x12
#define	TAVOR_WQE_SEND_NOPCODE_BIND	0x18

#define	TAVOR_WQE_SEND_SIGNALED_MASK	0x0000000800000000ull
#define	TAVOR_WQE_SEND_SOLICIT_MASK	0x0000000200000000ull
#define	TAVOR_WQE_SEND_IMMEDIATE_MASK	0x0000000100000000ull

struct tavor_hw_snd_wqe_ud_s {
	uint32_t			:32;
	uint32_t	lkey		:32;
	uint32_t	av_addr_h	:32;
	uint32_t	av_addr_l	:27;
	uint32_t			:5;
	uint32_t	rsrv0[4];
	uint32_t			:8;
	uint32_t	dest_qp		:24;
	uint32_t	qkey		:32;
	uint32_t			:32;
	uint32_t			:32;
};
#define	TAVOR_WQE_SENDHDR_UD_AV_MASK	0xFFFFFFFFFFFFFFE0ull
#define	TAVOR_WQE_SENDHDR_UD_DQPN_MASK	0xFFFFFF

struct tavor_hw_snd_wqe_bind_s {
	uint32_t	ae		:1;
	uint32_t	rw		:1;
	uint32_t	rr		:1;
	uint32_t			:29;
	uint32_t			:32;
	uint32_t	new_rkey;
	uint32_t	reg_lkey;
	uint64_t	addr;
	uint64_t	len;
};
#define	TAVOR_WQE_SENDHDR_BIND_ATOM	0x8000000000000000ull
#define	TAVOR_WQE_SENDHDR_BIND_WR	0x4000000000000000ull
#define	TAVOR_WQE_SENDHDR_BIND_RD	0x2000000000000000ull

struct tavor_hw_snd_wqe_remaddr_s {
	uint64_t	vaddr;
	uint32_t	rkey;
	uint32_t			:32;
};

struct tavor_hw_snd_wqe_atomic_s {
	uint64_t	swap_add;
	uint64_t	compare;
};


/*
 * Tavor "MLX transport" Work Queue Element (WQE)
 *    The format of the MLX WQE is similar to that of the Send WQE (above)
 *    with the following exceptions.  MLX WQEs are used for sending MADs on
 *    special QPs 0 and 1.  Everything following the "Next/Ctrl" header
 *    (defined below) consists of scatter-gather list entries.  The contents
 *    of these SGLs (also defined below) will be put on the wire exactly as
 *    they appear in the buffers.  In addition, the VCRC and the ICRC of each
 *    sent packet can be modified by changing values in the following header
 *    or in the payload of the packet itself.
 */
struct tavor_hw_mlx_wqe_nextctrl_s {
	uint32_t	next_wqe_addr	:26;
	uint32_t			:1;
	uint32_t	nopcode		:5;
	uint32_t			:24;
	uint32_t	dbd		:1;
	uint32_t			:1;
	uint32_t	nds		:6;

	uint32_t			:14;
	uint32_t	vl15		:1;
	uint32_t	slr		:1;
	uint32_t			:1;
	uint32_t	max_srate	:3;
	uint32_t	sl		:4;
	uint32_t			:4;
	uint32_t	c		:1;
	uint32_t	e		:1;
	uint32_t			:2;
	uint32_t	rlid		:16;
	uint32_t	vcrc		:16;
};
#define	TAVOR_WQE_MLXHDR_VL15_MASK	0x0002000000000000ull
#define	TAVOR_WQE_MLXHDR_SLR_MASK	0x0001000000000000ull
#define	TAVOR_WQE_MLXHDR_SRATE_SHIFT	44
#define	TAVOR_WQE_MLXHDR_SL_SHIFT	40
#define	TAVOR_WQE_MLXHDR_SIGNALED_MASK	0x0000000800000000ull
#define	TAVOR_WQE_MLXHDR_RLID_SHIFT	16

/*
 * Tavor Receive Work Queue Element (WQE)
 *    Like the Send WQE, the Receive WQE is built of 16-byte segments. The
 *    segment is the "Next/Ctrl" segment (defined below).  It is followed by
 *    some number of scatter list entries for the incoming message.
 *
 *    The format of the scatter-gather list entries is also shown below.  For
 *    Receive WQEs the "inline_data" field must be cleared (i.e. data segments
 *    cannot contain inline data).
 */
struct tavor_hw_rcv_wqe_nextctrl_s {
	uint32_t	next_wqe_addr	:26;
	uint32_t			:5;
	uint32_t	one		:1;
	uint32_t			:24;
	uint32_t	dbd		:1;
	uint32_t			:1;
	uint32_t	nds		:6;

	uint32_t			:28;
	uint32_t	c		:1;
	uint32_t	e		:1;
	uint32_t			:2;
	uint32_t			:32;
};

/*
 * This bit must be set in the next/ctrl field of all Receive WQEs
 * as a workaround to a Tavor hardware erratum related to having
 * the first 32-bits in the WQE set to zero.
 */
#define	TAVOR_RCV_WQE_NDA0_WA_MASK	0x0000000100000000ull

struct tavor_hw_wqe_sgl_s {
	uint32_t	inline_data	:1;
	uint32_t	byte_cnt	:31;
	uint32_t	lkey;
	uint64_t	addr;
};
#define	TAVOR_WQE_SGL_BYTE_CNT_MASK	0x7FFFFFFF
#define	TAVOR_WQE_SGL_INLINE_MASK	0x80000000

/*
 * The following defines are used when building descriptors for special QP
 * work requests (i.e. MLX transport WQEs).  Note: Because Tavor MLX transport
 * requires the driver to build actual IB packet headers, we use these defines
 * for the most common fields in those headers.
 */
#define	TAVOR_MLX_VL15_LVER		0xF0000000
#define	TAVOR_MLX_VL0_LVER		0x00000000
#define	TAVOR_MLX_IPVER_TC_FLOW		0x60000000
#define	TAVOR_MLX_TC_SHIFT		20
#define	TAVOR_MLX_DEF_PKEY		0xFFFF
#define	TAVOR_MLX_GSI_QKEY		0x80010000
#define	TAVOR_MLX_UDSEND_OPCODE		0x64000000
#define	TAVOR_MLX_DQPN_MASK		0xFFFFFF

/*
 * The following macros are used for building each of the individual
 * segments that can make up a Tavor WQE.  Note: We try not to use the
 * structures (with their associated bitfields) here, instead opting to
 * build and put 64-bit or 32-bit chunks to the WQEs as appropriate,
 * primarily because using the bitfields appears to force more read-modify-
 * write operations.
 *
 *    TAVOR_WQE_BUILD_UD		- Builds Unreliable Datagram Segment
 *
 *    TAVOR_WQE_BUILD_REMADDR		- Builds Remote Address Segment using
 *					    RDMA info from the work request
 *    TAVOR_WQE_BUILD_RC_ATOMIC_REMADDR	- Builds Remote Address Segment
 *					    for RC Atomic work requests
 *    TAVOR_WQE_BUILD_ATOMIC		- Builds Atomic Segment using atomic
 *					    info from the work request
 *    TAVOR_WQE_BUILD_BIND		- Builds the Bind Memory Window
 *					    Segment using bind info from the
 *					    work request
 *    TAVOR_WQE_BUILD_DATA_SEG		- Builds the individual Data Segments
 *					    for Send, Receive, and MLX WQEs
 *    TAVOR_WQE_BUILD_INLINE		- Builds an "inline" Data Segment
 *					    (primarily for MLX transport)
 *    TAVOR_WQE_BUILD_INLINE_ICRC	- Also builds an "inline" Data Segment
 *					    (but used primarily in the ICRC
 *					    portion of MLX transport WQEs)
 *    TAVOR_WQE_LINKNEXT		- Links the current WQE to the
 *					    previous one
 *    TAVOR_WQE_LINKFIRST		- Links the first WQE on the current
 *					    chain to the previous WQE
 *    TAVOR_WQE_BUILD_MLX_LRH		- Builds the inline LRH header for
 *					    MLX transport MADs
 *    TAVOR_WQE_BUILD_MLX_GRH		- Builds the inline GRH header for
 *					    MLX transport MADs
 *    TAVOR_WQE_BUILD_MLX_BTH		- Builds the inline BTH header for
 *					    MLX transport MADs
 *    TAVOR_WQE_BUILD_MLX_DETH		- Builds the inline DETH header for
 *					    MLX transport MADs
 */
#define	TAVOR_WQE_BUILD_UD(qp, ud, ah, wr)				\
{									\
	uint64_t		*tmp;					\
									\
	tmp	= (uint64_t *)(ud);					\
	ddi_put64((qp)->qp_wqinfo.qa_acchdl, &tmp[0],			\
	    (uint64_t)(ah)->ah_mrhdl->mr_lkey);				\
	ddi_put64((qp)->qp_wqinfo.qa_acchdl, &tmp[1],			\
	    (ah)->ah_mrhdl->mr_bindinfo.bi_addr &			\
	    TAVOR_WQE_SENDHDR_UD_AV_MASK);				\
	ddi_put64((qp)->qp_wqinfo.qa_acchdl, &tmp[2], 0x0);		\
	ddi_put64((qp)->qp_wqinfo.qa_acchdl, &tmp[3], 0x0);		\
	ddi_put64((qp)->qp_wqinfo.qa_acchdl, &tmp[4],			\
	    (((uint64_t)((wr)->wr.ud.udwr_dest->ud_dst_qpn &		\
	    TAVOR_WQE_SENDHDR_UD_DQPN_MASK) << 32) |			\
	    (wr)->wr.ud.udwr_dest->ud_qkey));				\
}

#define	TAVOR_WQE_BUILD_REMADDR(qp, ra, wr_rdma)			\
{									\
	uint64_t		*tmp;					\
									\
	tmp	= (uint64_t *)(ra);					\
	ddi_put64((qp)->qp_wqinfo.qa_acchdl, &tmp[0],			\
	    (wr_rdma)->rdma_raddr);					\
	ddi_put64((qp)->qp_wqinfo.qa_acchdl, &tmp[1],			\
	    (uint64_t)(wr_rdma)->rdma_rkey << 32);			\
}

#define	TAVOR_WQE_BUILD_RC_ATOMIC_REMADDR(qp, rc, wr)			\
{									\
	uint64_t		*tmp;					\
									\
	tmp	= (uint64_t *)(rc);					\
	ddi_put64((qp)->qp_wqinfo.qa_acchdl, &tmp[0],			\
	    (wr)->wr.rc.rcwr.atomic->atom_raddr);			\
	ddi_put64((qp)->qp_wqinfo.qa_acchdl, &tmp[1],			\
	    (uint64_t)(wr)->wr.rc.rcwr.atomic->atom_rkey << 32);	\
}

#define	TAVOR_WQE_BUILD_ATOMIC(qp, at, wr_atom)				\
{									\
	uint64_t		*tmp;					\
									\
	tmp	= (uint64_t *)(at);					\
	ddi_put64((qp)->qp_wqinfo.qa_acchdl, &tmp[0],			\
	    (wr_atom)->atom_arg2);					\
	ddi_put64((qp)->qp_wqinfo.qa_acchdl, &tmp[1],			\
	    (wr_atom)->atom_arg1);					\
}

#define	TAVOR_WQE_BUILD_BIND(qp, bn, wr_bind)				\
{									\
	uint64_t		*tmp;					\
	uint64_t		bn0_tmp;				\
	ibt_bind_flags_t	bind_flags;				\
									\
	tmp	   = (uint64_t *)(bn);					\
	bind_flags = (wr_bind)->bind_flags;				\
	bn0_tmp	   = (bind_flags & IBT_WR_BIND_ATOMIC) ?		\
	    TAVOR_WQE_SENDHDR_BIND_ATOM : 0;				\
	bn0_tmp	  |= (bind_flags & IBT_WR_BIND_WRITE) ?			\
	    TAVOR_WQE_SENDHDR_BIND_WR : 0;				\
	bn0_tmp	  |= (bind_flags & IBT_WR_BIND_READ) ?			\
	    TAVOR_WQE_SENDHDR_BIND_RD : 0;				\
	ddi_put64((qp)->qp_wqinfo.qa_acchdl, &tmp[0], bn0_tmp);		\
	ddi_put64((qp)->qp_wqinfo.qa_acchdl, &tmp[1],			\
	    (((uint64_t)(wr_bind)->bind_rkey_out << 32) |		\
	    (wr_bind)->bind_lkey));					\
	ddi_put64((qp)->qp_wqinfo.qa_acchdl, &tmp[2],			\
	    (wr_bind)->bind_va);					\
	ddi_put64((qp)->qp_wqinfo.qa_acchdl, &tmp[3],			\
	    (wr_bind)->bind_len);					\
}

#define	TAVOR_WQE_BUILD_DATA_SEG(qp, ds, sgl)				\
{									\
	uint64_t		*tmp;					\
									\
	tmp	= (uint64_t *)(ds);					\
	ddi_put64((qp)->qp_wqinfo.qa_acchdl, &tmp[0],			\
	    (((uint64_t)((sgl)->ds_len &				\
	    TAVOR_WQE_SGL_BYTE_CNT_MASK) << 32) | (sgl)->ds_key));	\
	ddi_put64((qp)->qp_wqinfo.qa_acchdl, &tmp[1], (sgl)->ds_va);	\
}

#define	TAVOR_WQE_BUILD_DATA_SEG_SRQ(srq, ds, sgl)			\
{									\
	uint64_t		*tmp;					\
									\
	tmp	= (uint64_t *)(ds);					\
	ddi_put64((srq)->srq_wqinfo.qa_acchdl, &tmp[0],			\
	    (((uint64_t)((sgl)->ds_len &				\
	    TAVOR_WQE_SGL_BYTE_CNT_MASK) << 32) | (sgl)->ds_key));	\
	ddi_put64((srq)->srq_wqinfo.qa_acchdl, &tmp[1], (sgl)->ds_va);	\
}

#define	TAVOR_WQE_BUILD_INLINE(qp, ds, sz)				\
{									\
	uint32_t		*tmp;					\
	uint32_t		inline_tmp;				\
									\
	tmp	   = (uint32_t *)(ds);					\
	inline_tmp = TAVOR_WQE_SGL_INLINE_MASK | sz;			\
	ddi_put32((qp)->qp_wqinfo.qa_acchdl, &tmp[0], inline_tmp);	\
}

#define	TAVOR_WQE_BUILD_INLINE_ICRC(qp, ds, sz, icrc)			\
{									\
	uint32_t		*tmp;					\
	uint32_t		inline_tmp;				\
									\
	tmp = (uint32_t *)(ds);						\
	inline_tmp = TAVOR_WQE_SGL_INLINE_MASK | sz;			\
	ddi_put32((qp)->qp_wqinfo.qa_acchdl, &tmp[0], inline_tmp);	\
	ddi_put32((qp)->qp_wqinfo.qa_acchdl, &tmp[1], icrc);		\
}

#define	TAVOR_WQE_LINKNEXT(qp, prev, ctrl, next)			\
{									\
	ddi_put64((qp)->qp_wqinfo.qa_acchdl, &((uint64_t *)(prev))[1],	\
	    (ctrl));							\
	ddi_put64((qp)->qp_wqinfo.qa_acchdl, &((uint64_t *)(prev))[0],	\
	    (next));							\
}

#define	TAVOR_WQE_LINKNEXT_SRQ(srq, prev, ctrl, next)			\
{									\
	ddi_put64((srq)->srq_wqinfo.qa_acchdl, &((uint64_t *)(prev))[1],\
	    (ctrl));							\
	ddi_put64((srq)->srq_wqinfo.qa_acchdl, &((uint64_t *)(prev))[0],\
	    (next));							\
}

#define	TAVOR_WQE_LINKFIRST(qp, prev, next)				\
{									\
	ddi_put64((qp)->qp_wqinfo.qa_acchdl, &((uint64_t *)(prev))[0],	\
	    (next));							\
}

#define	TAVOR_WQE_BUILD_MLX_LRH(lrh, qp, udav, pktlen)			\
{									\
	uint32_t		*tmp;					\
	uint32_t		lrh_tmp;				\
									\
	tmp	 = (uint32_t *)(lrh);					\
									\
	if ((qp)->qp_is_special == TAVOR_QP_SMI) {			\
		lrh_tmp = TAVOR_MLX_VL15_LVER;				\
	} else {							\
		lrh_tmp = TAVOR_MLX_VL0_LVER | ((udav).sl << 20);	\
	}								\
	if ((udav).grh) {						\
		lrh_tmp |= (IB_LRH_NEXT_HDR_GRH << 16);			\
	} else {							\
		lrh_tmp |= (IB_LRH_NEXT_HDR_BTH << 16);			\
	}								\
	lrh_tmp |= (udav).rlid;						\
	ddi_put32((qp)->qp_wqinfo.qa_acchdl, &tmp[0], lrh_tmp);		\
									\
	lrh_tmp	 = (pktlen) << 16;					\
	if ((udav).rlid == IB_LID_PERMISSIVE) {				\
		lrh_tmp |= IB_LID_PERMISSIVE;				\
	} else {							\
		lrh_tmp |= (udav).ml_path;				\
	}								\
	ddi_put32((qp)->qp_wqinfo.qa_acchdl, &tmp[1], lrh_tmp);		\
}

/*
 * Note: The GRH payload length, calculated below, is the overall packet
 * length (in bytes) minus LRH header and GRH headers.
 *
 * Also note: Filling in the GIDs in the way we do below is helpful because
 * it avoids potential alignment restrictions and/or conflicts.
 */
#define	TAVOR_WQE_BUILD_MLX_GRH(state, grh, qp, udav, pktlen)		\
{									\
	uint32_t		*tmp;					\
	uint32_t		grh_tmp;				\
	ib_gid_t		sgid;					\
									\
	tmp	 = (uint32_t *)(grh);					\
									\
	grh_tmp	 = TAVOR_MLX_IPVER_TC_FLOW;				\
	grh_tmp |= (udav).tclass << TAVOR_MLX_TC_SHIFT;			\
	grh_tmp |= (udav).flow_label;					\
	ddi_put32((qp)->qp_wqinfo.qa_acchdl, &tmp[0], grh_tmp);		\
									\
	grh_tmp	 = (((pktlen) << 2) - (sizeof (ib_lrh_hdr_t) +		\
	    sizeof (ib_grh_t))) << 16;					\
	grh_tmp |= (IB_GRH_NEXT_HDR_BTH << 8);				\
	grh_tmp |= (udav).hop_limit;					\
	ddi_put32((qp)->qp_wqinfo.qa_acchdl, &tmp[1], grh_tmp);		\
									\
	TAVOR_SGID_FROM_INDX_GET((state), (qp)->qp_portnum,		\
	    (udav).mgid_index, &sgid);					\
	bcopy(&sgid, &tmp[2], sizeof (ib_gid_t));			\
	bcopy(&(udav).rgid_h, &tmp[6], sizeof (ib_gid_t));		\
}

#define	TAVOR_WQE_BUILD_MLX_BTH(state, bth, qp, wr)			\
{									\
	uint32_t		*tmp;					\
	uint32_t		bth_tmp;				\
									\
	tmp	 = (uint32_t *)(bth);					\
									\
	bth_tmp	 = TAVOR_MLX_UDSEND_OPCODE;				\
	if ((wr)->wr_flags & IBT_WR_SEND_SOLICIT) {			\
		bth_tmp |= (IB_BTH_SOLICITED_EVENT_MASK << 16);		\
	}								\
	if (qp->qp_is_special == TAVOR_QP_SMI) {			\
		bth_tmp |= TAVOR_MLX_DEF_PKEY;				\
	} else {							\
		bth_tmp |= TAVOR_PKEY_FROM_INDX_GET((state),		\
		    (qp)->qp_portnum, (qp)->qp_pkeyindx);		\
	}								\
	ddi_put32((qp)->qp_wqinfo.qa_acchdl, &tmp[0], bth_tmp);		\
	ddi_put32((qp)->qp_wqinfo.qa_acchdl, &tmp[1],			\
	    (wr)->wr.ud.udwr_dest->ud_dst_qpn &				\
	    TAVOR_MLX_DQPN_MASK);					\
	ddi_put32((qp)->qp_wqinfo.qa_acchdl, &tmp[2], 0x0);		\
}

#define	TAVOR_WQE_BUILD_MLX_DETH(deth, qp)				\
{									\
	uint32_t		*tmp;					\
									\
	tmp	 = (uint32_t *)(deth);					\
									\
	if ((qp)->qp_is_special == TAVOR_QP_SMI) {			\
		ddi_put32((qp)->qp_wqinfo.qa_acchdl, &tmp[0], 0x0);	\
		ddi_put32((qp)->qp_wqinfo.qa_acchdl, &tmp[1], 0x0);	\
	} else {							\
		ddi_put32((qp)->qp_wqinfo.qa_acchdl, &tmp[0],		\
		    TAVOR_MLX_GSI_QKEY);				\
		ddi_put32((qp)->qp_wqinfo.qa_acchdl, &tmp[1], 0x1);	\
	}								\
}


/*
 * Undocumented:
 *    The following registers (and the macros to access them) are not defined
 *    in the Tavor PRM.  But we have high confidence that these offsets are
 *    unlikely to change in the lifetime of the Tavor hardware.
 */
#define	TAVOR_HW_PORTINFO_LMC_OFFSET		0x10020
#define	TAVOR_HW_PORTINFO_BASELID_OFFSET	0x10010
#define	TAVOR_HW_PORTINFO_MASTERSMLID_OFFSET	0x10010
#define	TAVOR_HW_PORTINFO_LINKWIDTH_OFFSET	0x1001C
#define	TAVOR_HW_PORT_SIZE			0x800

#define	TAVOR_HW_PMEG_PORTXMITDATA_OFFSET	0x10120
#define	TAVOR_HW_PMEG_PORTRECVDATA_OFFSET	0x10124
#define	TAVOR_HW_PMEG_PORTXMITPKTS_OFFSET	0x10128
#define	TAVOR_HW_PMEG_PORTRECVPKTS_OFFSET	0x1012C
#define	TAVOR_HW_PMEG_PORTRECVERR_OFFSET	0x10130
#define	TAVOR_HW_PMEG_PORTXMITDISCARD_OFFSET	0x10134
#define	TAVOR_HW_PMEG_VL15DROPPED_OFFSET	0x10138
#define	TAVOR_HW_PMEG_PORTXMITWAIT_OFFSET	0x1013C
#define	TAVOR_HW_PMEG_PORTRECVREMPHYSERR_OFFSET	0x10144
#define	TAVOR_HW_PMEG_PORTXMITCONSTERR_OFFSET	0x10148
#define	TAVOR_HW_PMEG_PORTRECVCONSTERR_OFFSET	0x1014C
#define	TAVOR_HW_PMEG_SYMBOLERRCNT_OFFSET	0x10150
#define	TAVOR_HW_PMEG_LINKERRRECOVERCNT_OFFSET	0x10154
#define	TAVOR_HW_PMEG_LINKDOWNEDCNT_OFFSET	0x10154
#define	TAVOR_HW_PMEG_EXCESSBUFOVERRUN_OFFSET	0x10164
#define	TAVOR_HW_PMEG_LOCALLINKINTERR_OFFSET	0x10164

#define	TAVOR_HW_GUIDTABLE_OFFSET		0x4C800
#define	TAVOR_HW_GUIDTABLE_PORT_SIZE		0x200
#define	TAVOR_HW_GUIDTABLE_GID_SIZE		0x10
#define	TAVOR_HW_GUIDTABLE_GIDPREFIX_SIZE	0x8

#define	TAVOR_HW_PKEYTABLE_OFFSET		0x4D800
#define	TAVOR_HW_PKEYTABLE_PORT_SIZE		0x100
#define	TAVOR_HW_PKEYTABLE_PKEY_SIZE		0x4

#define	TAVOR_PORT_LMC_GET(state, port)				\
	((ddi_get32((state)->ts_reg_cmdhdl,			\
	(uint32_t *)((uintptr_t)(state)->ts_reg_cmd_baseaddr +	\
	TAVOR_HW_PORTINFO_LMC_OFFSET +				\
	(TAVOR_HW_PORT_SIZE * (port)))) >> 8) & 0x7);

#define	TAVOR_PORT_BASELID_GET(state, port)			\
	(ddi_get32((state)->ts_reg_cmdhdl,			\
	(uint32_t *)((uintptr_t)(state)->ts_reg_cmd_baseaddr +	\
	TAVOR_HW_PORTINFO_BASELID_OFFSET +			\
	(TAVOR_HW_PORT_SIZE * (port)))) >> 16);

#define	TAVOR_PORT_MASTERSMLID_GET(state, port)			\
	(ddi_get32((state)->ts_reg_cmdhdl,			\
	(uint32_t *)((uintptr_t)(state)->ts_reg_cmd_baseaddr +	\
	TAVOR_HW_PORTINFO_MASTERSMLID_OFFSET +			\
	(TAVOR_HW_PORT_SIZE * (port)))) & 0xFFFF);

#define	TAVOR_PORT_LINKWIDTH_ACTIVE_GET(state, port)		\
	(ddi_get32((state)->ts_reg_cmdhdl,			\
	(uint32_t *)((uintptr_t)(state)->ts_reg_cmd_baseaddr +	\
	TAVOR_HW_PORTINFO_LINKWIDTH_OFFSET +			\
	(TAVOR_HW_PORT_SIZE * (port)))) & 0xF);

#define	TAVOR_SGID_FROM_INDX_GET(state, port, sgid_ix, sgid)	\
	(sgid)->gid_prefix = ddi_get64((state)->ts_reg_cmdhdl,	\
	(uint64_t *)((uintptr_t)(state)->ts_reg_cmd_baseaddr +	\
	TAVOR_HW_GUIDTABLE_OFFSET +				\
	((port) * TAVOR_HW_GUIDTABLE_PORT_SIZE) +		\
	((sgid_ix) * TAVOR_HW_GUIDTABLE_GID_SIZE)));		\
	(sgid)->gid_guid = ddi_get64((state)->ts_reg_cmdhdl,	\
	(uint64_t *)((uintptr_t)(state)->ts_reg_cmd_baseaddr +	\
	TAVOR_HW_GUIDTABLE_OFFSET +				\
	((port) * TAVOR_HW_GUIDTABLE_PORT_SIZE) +		\
	((sgid_ix) * TAVOR_HW_GUIDTABLE_GID_SIZE) +		\
	TAVOR_HW_GUIDTABLE_GIDPREFIX_SIZE));

#define	TAVOR_PKEY_FROM_INDX_GET(state, port, pkey_ix)		\
	(ddi_get32((state)->ts_reg_cmdhdl,			\
	(uint32_t *)((uintptr_t)(state)->ts_reg_cmd_baseaddr +	\
	TAVOR_HW_PKEYTABLE_OFFSET +				\
	((port) * TAVOR_HW_PKEYTABLE_PORT_SIZE) +		\
	((pkey_ix) * TAVOR_HW_PKEYTABLE_PKEY_SIZE))) & 0xFFFF)


/*
 * Flash interface:
 *    Below we have PCI config space space offsets for flash interface
 *    access, offsets within Tavor CR space for accessing flash-specific
 *    information or settings, masks used for flash settings, and
 *    timeout values for flash operations.
 */
#define	TAVOR_HW_FLASH_CFG_HWREV		8
#define	TAVOR_HW_FLASH_CFG_ADDR			88
#define	TAVOR_HW_FLASH_CFG_DATA			92

#define	TAVOR_HW_FLASH_RESET_AMD		0xF0
#define	TAVOR_HW_FLASH_RESET_INTEL		0xFF
#define	TAVOR_HW_FLASH_CPUMODE			0xF0150
#define	TAVOR_HW_FLASH_ADDR			0xF01A4
#define	TAVOR_HW_FLASH_DATA			0xF01A8
#define	TAVOR_HW_FLASH_GPIO_SEMA		0xF03FC
#define	TAVOR_HW_FLASH_GPIO_DIR			0xF008C
#define	TAVOR_HW_FLASH_GPIO_POL			0xF0094
#define	TAVOR_HW_FLASH_GPIO_MOD			0xF009C
#define	TAVOR_HW_FLASH_GPIO_DAT			0xF0084
#define	TAVOR_HW_FLASH_GPIO_DATACLEAR		0xF00D4
#define	TAVOR_HW_FLASH_GPIO_DATASET		0xF00DC

#define	TAVOR_HW_FLASH_CPU_MASK			0xC0000000
#define	TAVOR_HW_FLASH_CPU_SHIFT		30
#define	TAVOR_HW_FLASH_ADDR_MASK		0x0007FFFC
#define	TAVOR_HW_FLASH_CMD_MASK			0xE0000000
#define	TAVOR_HW_FLASH_BANK_MASK		0xFFF80000

#define	TAVOR_HW_FLASH_TIMEOUT_WRITE		300
#define	TAVOR_HW_FLASH_TIMEOUT_ERASE		1000000
#define	TAVOR_HW_FLASH_TIMEOUT_GPIO_SEMA	1000
#define	TAVOR_HW_FLASH_TIMEOUT_CONFIG		50

/* Intel Command Set */
#define	TAVOR_HW_FLASH_ICS_ERASE		0x20
#define	TAVOR_HW_FLASH_ICS_ERROR		0x3E
#define	TAVOR_HW_FLASH_ICS_WRITE		0x40
#define	TAVOR_HW_FLASH_ICS_STATUS		0x70
#define	TAVOR_HW_FLASH_ICS_READY		0x80
#define	TAVOR_HW_FLASH_ICS_CONFIRM		0xD0
#define	TAVOR_HW_FLASH_ICS_READ			0xFF

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_IB_ADAPTERS_TAVOR_HW_H */
