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

#ifndef	_RFIOSPC_TABLES_H
#define	_RFIOSPC_TABLES_H

/*
 * Table definitions for the RF IOS performance counters.
 *
 * Each table consists of one or more groups of counters.
 *
 * A counter group will have a name (used by busstat as the kstat "module"
 * name), have its own set of kstats, and a common event select register.
 * A group is represented as an iospc_grp_t.
 *
 * Each counter is represented by an iospc_cntr_t.  Each has its own register
 * offset (or address), bits for the data it represents, plus an associated
 * register for zeroing it.
 *
 * All registers for iospc are 64 bit, but a size field can be entered into this
 * structure if registers sizes vary for other implementations (as if this code
 * is leveraged for a future driver).
 *
 * A select register is represented by an iospc_regsel_t.  This defines the
 * offset or address, and an array of fields which define the events for each
 * counter it services.  All counters need to have an entry in the fields array
 * even if they don't have any representation in a select register.  Please see
 * the explanation of the events array (below) for more information.  Counters
 * without representation in a select register can specify their (non-existant)
 * select register field with mask NONPROG_DUMMY_MASK and offset
 * NONPROG_DUMMY_OFF.
 *
 * This implementation supports only one select register per group.  If more
 * are needed (e.g. if this implementation is used as a template for another
 * device which has multiple select registers per group) the data structures can
 * easily be changed to support an array of them.   Add an array index in the
 * counter structure to associate that counter with a particular select
 * register, and add a field for the number of select registers in the group
 * structure.
 *
 * Each counter has an array of programmable events associated with it, even if
 * it is not programmable.  This array is a series of name/value pairs defined
 * by iospc_event_t.  The value is the event value loaded into the select
 * register to select that event for that counter.  The last entry in the array
 * is always an entry with a bitmask of LSB-aligned bits of that counter's
 * select register's field's width;  it is usually called the CLEAR_PIC entry.
 * CLEAR_PIC entries are not shown to the user.
 *
 * Note that counters without programmable events still need to define a
 * (small) events array with at least CLEAR_PIC and a single event, so that
 * event's name can display in busstat output.  The CLEAR_PIC entry of
 * nonprogrammable counters can have a value of NONPROG_DUMMY_MASK.
 */

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/kstat.h>

/* RF IOS specific definitions. */

/*
 * Event bitmask definitions for all groups.
 */
#define	RFIOS_IMU_CTR_EVT_MASK	0xffull
#define	RFIOS_IMU_CTR_0_EVT_OFF	0
#define	RFIOS_IMU_CTR_1_EVT_OFF	8

#define	RFIOS_ATU_CTR_EVT_MASK	0xffull
#define	RFIOS_ATU_CTR_0_EVT_OFF	0
#define	RFIOS_ATU_CTR_1_EVT_OFF	8

#define	RFIOS_NPU_CTR_EVT_MASK	0xffull
#define	RFIOS_NPU_CTR_0_EVT_OFF	0
#define	RFIOS_NPU_CTR_1_EVT_OFF	8

#define	RFIOS_PEX_CTR_EVT_MASK	0xffull
#define	RFIOS_PEX_CTR_0_EVT_OFF	0
#define	RFIOS_PEX_CTR_1_EVT_OFF	8

#define	RFIOS_PEU_CTR_EVT_MASK	0x7full
#define	RFIOS_PEU_CTR_0_EVT_OFF	0
#define	RFIOS_PEU_CTR_1_EVT_OFF	32

/*
 * Definitions of the different types of events.
 *
 * The first part says which registers these events are for.
 * For example, IMU01 means the IMU performance counters 0 and 1
 */

/* String sought by busstat to locate the event field width "event" entry. */
#define	COMMON_S_CLEAR_PIC			"clear_pic"

#define	RFIOS_IMU01_S_EVT_NONE			"event_none"
#define	RFIOS_IMU01_S_EVT_CLK			"clock_cyc"
#define	RFIOS_IMU01_S_EVT_TOTAL_MSIX		"total_msix"
#define	RFIOS_IMU01_S_EVT_IOS_MSI		"ios_msi"
#define	RFIOS_IMU01_S_EVT_PCIE_MSIX		"pcie_msix"
#define	RFIOS_IMU01_S_EVT_PCIE_MSGS		"pcie_msgs"
#define	RFIOS_IMU01_S_EVT_FILTERED_MSIX		"filtered_msix"
#define	RFIOS_IMU01_S_EVT_EQ_WR			"eq_write"
#define	RFIOS_IMU01_S_EVT_MONDOS		"mondos"

#define	RFIOS_IMU01_EVT_NONE			0x0
#define	RFIOS_IMU01_EVT_CLK			0x1
#define	RFIOS_IMU01_EVT_TOTAL_MSIX		0x2
#define	RFIOS_IMU01_EVT_IOS_MSI			0x3
#define	RFIOS_IMU01_EVT_PCIE_MSIX		0x4
#define	RFIOS_IMU01_EVT_PCIE_MSGS		0x5
#define	RFIOS_IMU01_EVT_FILTERED_MSIX		0x6
#define	RFIOS_IMU01_EVT_EQ_WR			0x7
#define	RFIOS_IMU01_EVT_MONDOS			0x8

#define	RFIOS_ATU01_S_EVT_NONE			"event_none"
#define	RFIOS_ATU01_S_EVT_CLK			"clock_cyc"
#define	RFIOS_ATU01_S_EVT_FLOW_CTRL_STALL	"flow_ctrl_cyc"
#define	RFIOS_ATU01_S_EVT_CLUMP_ACC		"clump_accesses"
#define	RFIOS_ATU01_S_EVT_CLUMP_MISS		"clump_misses"
#define	RFIOS_ATU01_S_EVT_CLUMP_RESETS		"clump_resets"
#define	RFIOS_ATU01_S_EVT_CLUMP_TBL_WALK	"clump_table_walk"
#define	RFIOS_ATU01_S_EVT_VIRT_ACC		"virt_accesses"
#define	RFIOS_ATU01_S_EVT_VIRT_MISS		"virt_misses"
#define	RFIOS_ATU01_S_EVT_VIRT_RESETS		"virt_resets"
#define	RFIOS_ATU01_S_EVT_VIRT_TBL_WALK		"virt_table_walk"
#define	RFIOS_ATU01_S_EVT_REAL_ACC		"real_accesses"
#define	RFIOS_ATU01_S_EVT_REAL_MISS		"real_misses"
#define	RFIOS_ATU01_S_EVT_REAL_RESETS		"real_resets"
#define	RFIOS_ATU01_S_EVT_REAL_TBL_WALK		"real_table_walk"
#define	RFIOS_ATU01_S_EVT_CMD_ERRORS		"cmd_errors"
#define	RFIOS_ATU01_S_EVT_VIRT_TRANS		"virt_trans"
#define	RFIOS_ATU01_S_EVT_REAL_TRANS		"real_trans"
#define	RFIOS_ATU01_S_EVT_PHYS_TRANS		"phys_trans"
#define	RFIOS_ATU01_S_EVT_STRICT_ORDER_FORCED	"str_order_forced"
#define	RFIOS_ATU01_S_EVT_RELAX_ORDER_FORCED	"relax_order_forced"
#define	RFIOS_ATU01_S_EVT_RELAX_ORDER_TLP	"relax_order_tlp"
#define	RFIOS_ATU01_S_EVT_RELAX_ORDER_TOTAL	"relax_order_total"

#define	RFIOS_ATU01_EVT_NONE			0x0
#define	RFIOS_ATU01_EVT_CLK			0x1
#define	RFIOS_ATU01_EVT_FLOW_CTRL_STALL		0x3
#define	RFIOS_ATU01_EVT_CLUMP_ACC		0x4
#define	RFIOS_ATU01_EVT_CLUMP_MISS		0x5
#define	RFIOS_ATU01_EVT_CLUMP_RESETS		0x6
#define	RFIOS_ATU01_EVT_CLUMP_TBL_WALK		0x7
#define	RFIOS_ATU01_EVT_VIRT_ACC		0x8
#define	RFIOS_ATU01_EVT_VIRT_MISS		0x9
#define	RFIOS_ATU01_EVT_VIRT_RESETS		0xa
#define	RFIOS_ATU01_EVT_VIRT_TBL_WALK		0xb
#define	RFIOS_ATU01_EVT_REAL_ACC		0xc
#define	RFIOS_ATU01_EVT_REAL_MISS		0xd
#define	RFIOS_ATU01_EVT_REAL_RESETS		0xe
#define	RFIOS_ATU01_EVT_REAL_TBL_WALK		0xf
#define	RFIOS_ATU01_EVT_CMD_ERRORS		0x10
#define	RFIOS_ATU01_EVT_VIRT_TRANS		0x11
#define	RFIOS_ATU01_EVT_REAL_TRANS		0x12
#define	RFIOS_ATU01_EVT_PHYS_TRANS		0x13
#define	RFIOS_ATU01_EVT_STRICT_ORDER_FORCED	0x14
#define	RFIOS_ATU01_EVT_RELAX_ORDER_FORCED	0x15
#define	RFIOS_ATU01_EVT_RELAX_ORDER_TLP		0x16
#define	RFIOS_ATU01_EVT_RELAX_ORDER_TOTAL	0x17

#define	RFIOS_NPU01_S_EVT_NONE			"event_none"
#define	RFIOS_NPU01_S_EVT_CLK			"clock_cyc"
#define	RFIOS_NPU01_S_EVT_ZERO_BYTE_READ	"zero_byte_reads"
#define	RFIOS_NPU01_S_EVT_DMA_WRITE_LATENCY	"write_latency"
#define	RFIOS_NPU01_S_EVT_DMA_WRITE_LATENCY_NUM	"write_latency_num"
#define	RFIOS_NPU01_S_EVT_OSB_FULL_CYCLES	"osb_full_cyc"
#define	RFIOS_NPU01_S_EVT_DMA_READ_LATENCY	"read_latency"
#define	RFIOS_NPU01_S_EVT_DMA_READ_LATENCY_NUM	"read_latency_num"
#define	RFIOS_NPU01_S_EVT_PSB_FULL_CYCLES	"psb_full_cyc"
#define	RFIOS_NPU01_S_EVT_ICB_FULL_CYCLES	"icb_full_cyc"
#define	RFIOS_NPU01_S_EVT_ECB_FULL_CYCLES	"ecb_full_cyc"
#define	RFIOS_NPU01_S_EVT_ATU_CSR_CFG_WRITES	"atu_csr_cfg_wrs"
#define	RFIOS_NPU01_S_EVT_ATU_CSR_CFG_READS	"atu_csr_cfg_rds"
#define	RFIOS_NPU01_S_EVT_ATU_CSR_MEM_WRITES	"atu_csr_mem_wrs"
#define	RFIOS_NPU01_S_EVT_ATU_CSR_MEM_READS	"atu_csr_mem_rds"
#define	RFIOS_NPU01_S_EVT_IMU_CSR_CFG_WRITES	"imu_csr_cfg_wrs"
#define	RFIOS_NPU01_S_EVT_IMU_CSR_CFG_READS	"imu_csr_cfg_rds"
#define	RFIOS_NPU01_S_EVT_IMU_CSR_MEM_WRITES	"imu_csr_mem_wrs"
#define	RFIOS_NPU01_S_EVT_IMU_CSR_MEM_READS	"imu_csr_mem_rds"
#define	RFIOS_NPU01_S_EVT_NPU_CSR_CFG_WRITES	"npu_csr_cfg_wrs"
#define	RFIOS_NPU01_S_EVT_NPU_CSR_CFG_READS	"npu_csr_cfg_rds"
#define	RFIOS_NPU01_S_EVT_NPU_CSR_MEM_WRITES	"npu_csr_mem_wrs"
#define	RFIOS_NPU01_S_EVT_NPU_CSR_MEM_READS	"npu_csr_mem_rds"
#define	RFIOS_NPU01_S_EVT_OTHER_CSR_CFG_WRITES	"other_csr_cfg_wrs"
#define	RFIOS_NPU01_S_EVT_OTHER_CSR_CFG_READS	"other_csr_cfg_rds"
#define	RFIOS_NPU01_S_EVT_OTHER_CSR_MEM64_WRITES \
						"other_csr_mem64_wrs"
#define	RFIOS_NPU01_S_EVT_OTHER_CSR_MEM64_READS	"other_csr_mem64_rds"
#define	RFIOS_NPU01_S_EVT_OTHER_CSR_MEM32_WRITES \
						"other_csr_mem32_wrs"
#define	RFIOS_NPU01_S_EVT_OTHER_CSR_MEM32_READS	"other_csr_mem32_rds"
#define	RFIOS_NPU01_S_EVT_IO_SPACE_WRITES	"io_space_wrs"
#define	RFIOS_NPU01_S_EVT_IO_SPACE_READS	"io_space_rds"
#define	RFIOS_NPU01_S_EVT_TOTAL_MSI		"total_msi"
#define	RFIOS_NPU01_S_EVT_ATU_MSI		"atu_msi"
#define	RFIOS_NPU01_S_EVT_IMU_MSI		"imu_msi"
#define	RFIOS_NPU01_S_EVT_NPU_MSI		"npu_msi"
#define	RFIOS_NPU01_S_EVT_RETIRED_TAGS_CTO	"retired_tags"
#define	RFIOS_NPU01_S_EVT_NO_POSTED_TAGS_CYCYLES \
						"no_posted_tags_cyc"

#define	RFIOS_NPU01_EVT_NONE			0
#define	RFIOS_NPU01_EVT_CLK			1
#define	RFIOS_NPU01_EVT_ZERO_BYTE_READ		2
#define	RFIOS_NPU01_EVT_DMA_WRITE_LATENCY	3
#define	RFIOS_NPU01_EVT_DMA_WRITE_LATENCY_NUM	4
#define	RFIOS_NPU01_EVT_OSB_FULL_CYCLES		5
#define	RFIOS_NPU01_EVT_DMA_READ_LATENCY	8
#define	RFIOS_NPU01_EVT_DMA_READ_LATENCY_NUM	9
#define	RFIOS_NPU01_EVT_PSB_FULL_CYCLES		10
#define	RFIOS_NPU01_EVT_ICB_FULL_CYCLES		16
#define	RFIOS_NPU01_EVT_ECB_FULL_CYCLES		24
#define	RFIOS_NPU01_EVT_ATU_CSR_CFG_WRITES	32
#define	RFIOS_NPU01_EVT_ATU_CSR_CFG_READS	33
#define	RFIOS_NPU01_EVT_ATU_CSR_MEM_WRITES	34
#define	RFIOS_NPU01_EVT_ATU_CSR_MEM_READS	35
#define	RFIOS_NPU01_EVT_IMU_CSR_CFG_WRITES	36
#define	RFIOS_NPU01_EVT_IMU_CSR_CFG_READS	37
#define	RFIOS_NPU01_EVT_IMU_CSR_MEM_WRITES	38
#define	RFIOS_NPU01_EVT_IMU_CSR_MEM_READS	39
#define	RFIOS_NPU01_EVT_NPU_CSR_CFG_WRITES	40
#define	RFIOS_NPU01_EVT_NPU_CSR_CFG_READS	41
#define	RFIOS_NPU01_EVT_NPU_CSR_MEM_WRITES	42
#define	RFIOS_NPU01_EVT_NPU_CSR_MEM_READS	43
#define	RFIOS_NPU01_EVT_OTHER_CSR_CFG_WRITES	44
#define	RFIOS_NPU01_EVT_OTHER_CSR_CFG_READS	45
#define	RFIOS_NPU01_EVT_OTHER_CSR_MEM64_WRITES	46
#define	RFIOS_NPU01_EVT_OTHER_CSR_MEM64_READS	47
#define	RFIOS_NPU01_EVT_OTHER_CSR_MEM32_WRITES	48
#define	RFIOS_NPU01_EVT_OTHER_CSR_MEM32_READS	49
#define	RFIOS_NPU01_EVT_IO_SPACE_WRITES		50
#define	RFIOS_NPU01_EVT_IO_SPACE_READS		51
#define	RFIOS_NPU01_EVT_TOTAL_MSI		52
#define	RFIOS_NPU01_EVT_ATU_MSI			53
#define	RFIOS_NPU01_EVT_IMU_MSI			54
#define	RFIOS_NPU01_EVT_NPU_MSI			55
#define	RFIOS_NPU01_EVT_RETIRED_TAGS_CTO	56
#define	RFIOS_NPU01_EVT_NO_POSTED_TAGS_CYCYLES	57

#define	RFIOS_PEX01_S_EVT_NONE			"event_none"
#define	RFIOS_PEX01_S_EVT_CLK			"clock_cyc"
#define	RFIOS_PEX01_S_EVT_PEU0_DMA_WR_REC	"peu0_dma_wr_received"
#define	RFIOS_PEX01_S_EVT_PEU0_PIO_RD_REC	"peu0_pio_rd_received"
#define	RFIOS_PEX01_S_EVT_PEU0_DMA_RD_SENT	"peu0_dma_rd_sent"
#define	RFIOS_PEX01_S_EVT_PEU0_TLP_REC		"peu0_tlp_recieved"
#define	RFIOS_PEX01_S_EVT_PEU0_TRP_FULL_CYCLES	"peu0_trp_full_cyc"
#define	RFIOS_PEX01_S_EVT_PEU0_TCH_FULL_CYCLES	"peu0_tch_full_cyc"
#define	RFIOS_PEX01_S_EVT_PEU0_TCD_FULL_CYCLES	"peu0_tcd_full_cyc"
#define	RFIOS_PEX01_S_EVT_NON_POSTED_PIOS_LATENCY \
						"non_posted_pios_latency"
#define	RFIOS_PEX01_S_EVT_NON_POSTED_PIOS_NUM	"non_posted_pios_num"
#define	RFIOS_PEX01_S_EVT_PEX_CFG_WRITE		"pex_config_wr"
#define	RFIOS_PEX01_S_EVT_PEX_CFG_READ		"pex_config_rd"
#define	RFIOS_PEX01_S_EVT_PEX_MEM_WRITE		"pex_mem_wr"
#define	RFIOS_PEX01_S_EVT_PEX_MEM_READ		"pex_mem_rd"
#define	RFIOS_PEX01_S_EVT_PEU1_DMA_WR_REC	"peu1_dma_wr_received"
#define	RFIOS_PEX01_S_EVT_PEU1_PIO_RD_REC	"peu1_pio_rd_received"
#define	RFIOS_PEX01_S_EVT_PEU1_DMA_RD_SENT	"peu1_dma_rd_sent"
#define	RFIOS_PEX01_S_EVT_PEU1_TLP_REC		"peu1_tlp_recieved"
#define	RFIOS_PEX01_S_EVT_PEU1_TRP_FULL_CYCLES	"peu1_trp_full_cyc"
#define	RFIOS_PEX01_S_EVT_PEU1_TCH_FULL_CYCLES	"peu1_tch_full_cyc"
#define	RFIOS_PEX01_S_EVT_PEU1_TCD_FULL_CYCLES	"peu1_tcd_full_cyc"

#define	RFIOS_PEX01_EVT_NONE			0x0
#define	RFIOS_PEX01_EVT_CLK			0x1
#define	RFIOS_PEX01_EVT_PEU0_DMA_WR_REC		0x2
#define	RFIOS_PEX01_EVT_PEU0_PIO_RD_REC		0x3
#define	RFIOS_PEX01_EVT_PEU0_DMA_RD_SENT	0x4
#define	RFIOS_PEX01_EVT_PEU0_TLP_REC		0x5
#define	RFIOS_PEX01_EVT_PEU0_TRP_FULL_CYCLES	0x6
#define	RFIOS_PEX01_EVT_PEU0_TCH_FULL_CYCLES	0x7
#define	RFIOS_PEX01_EVT_PEU0_TCD_FULL_CYCLES	0x8
#define	RFIOS_PEX01_EVT_NON_POSTED_PIOS_LATENCY	0x9
#define	RFIOS_PEX01_EVT_NON_POSTED_PIOS_NUM	0xa
#define	RFIOS_PEX01_EVT_PEX_CFG_WRITE		0xb
#define	RFIOS_PEX01_EVT_PEX_CFG_READ		0xc
#define	RFIOS_PEX01_EVT_PEX_MEM_WRITE		0xd
#define	RFIOS_PEX01_EVT_PEX_MEM_READ		0xe
#define	RFIOS_PEX01_EVT_PEU1_DMA_WR_REC		0x20
#define	RFIOS_PEX01_EVT_PEU1_PIO_RD_REC		0x30
#define	RFIOS_PEX01_EVT_PEU1_DMA_RD_SENT	0x40
#define	RFIOS_PEX01_EVT_PEU1_TLP_REC		0x50
#define	RFIOS_PEX01_EVT_PEU1_TRP_FULL_CYCLES	0x60
#define	RFIOS_PEX01_EVT_PEU1_TCH_FULL_CYCLES	0x70
#define	RFIOS_PEX01_EVT_PEU1_TCD_FULL_CYCLES	0x80

#define	RFIOS_PEU01_S_EVT_NONE			"event_none"
#define	RFIOS_PEU01_S_EVT_CLK			"clock_cyc"
#define	RFIOS_PEU01_S_EVT_INT_CFG_WR_RECD	"int_config_wr_recd"
#define	RFIOS_PEU01_S_EVT_INT_CFG_RD_RECD	"int_config_rd_recd"
#define	RFIOS_PEU01_S_EVT_INT_MEM_WR_RECD	"int_mem_wr_recd"
#define	RFIOS_PEU01_S_EVT_INT_MEM_RD_RECD	"int_mem_rd_recd"
#define	RFIOS_PEU01_S_EVT_EXT_CFG_WR_RECD	"ext_config_wr_recd"
#define	RFIOS_PEU01_S_EVT_EXT_CFG_RD_RECD	"ext_config_rd_recd"
#define	RFIOS_PEU01_S_EVT_EXT_MEM_WR_RECD	"ext_mem_wr_recd"
#define	RFIOS_PEU01_S_EVT_EXT_MEM_RD_RECD	"ext_mem_rd_recd"
#define	RFIOS_PEU01_S_EVT_MEM_RD_REQ_RECD_ALL	"mem_rd_recd_all"
#define	RFIOS_PEU01_S_EVT_MEM_RD_REQ_RECD_1_15DW \
						"mem_rd_recd_1_15dw"
#define	RFIOS_PEU01_S_EVT_MEM_RD_REQ_RECD_16_31DW \
						"mem_rd_recd_16_31dw"
#define	RFIOS_PEU01_S_EVT_MEM_RD_REQ_RECD_32_63DW \
						"mem_rd_recd_32_63dw"
#define	RFIOS_PEU01_S_EVT_MEM_RD_REQ_RECD_64_127DW \
						"mem_rd_recd_64_127dw"
#define	RFIOS_PEU01_S_EVT_MEM_RD_REQ_RECD_128_255DW \
						"mem_rd_recd_128_255dw"
#define	RFIOS_PEU01_S_EVT_MEM_RD_REQ_RECD_256_511DW \
						"mem_rd_recd_256_511dw"
#define	RFIOS_PEU01_S_EVT_MEM_RD_REQ_RECD_512_1024DW \
						"mem_rd_recd_512_1024dw"
#define	RFIOS_PEU01_S_EVT_MEM_WR_REQ_RECD_ALL	"mem_wr_recd_all"
#define	RFIOS_PEU01_S_EVT_MEM_WR_REQ_RECD_1_15DW \
						"mem_wr_recd_1_15dw"
#define	RFIOS_PEU01_S_EVT_MEM_WR_REQ_RECD_16_31DW \
						"mem_wr_recd_16_31dw"
#define	RFIOS_PEU01_S_EVT_MEM_WR_REQ_RECD_32_63DW \
						"mem_wr_recd_32_63dw"
#define	RFIOS_PEU01_S_EVT_MEM_WR_REQ_RECD_64_127DW \
						"mem_wr_recd_64_127dw"
#define	RFIOS_PEU01_S_EVT_MEM_WR_REQ_RECD_128_255DW \
						"mem_wr_recd_128_255dw"
#define	RFIOS_PEU01_S_EVT_MEM_WR_REQ_RECD_256_511DW \
						"mem_wr_recd_256_511dw"
#define	RFIOS_PEU01_S_EVT_MEM_WR_REQ_RECD_512_1024DW \
						"mem_wr_recd_512_1024dw"
#define	RFIOS_PEU01_S_EVT_XMIT_POSTED_HDR_NA_CYC \
						"xmit_posted_hdr_na_cyc"
#define	RFIOS_PEU01_S_EVT_XMIT_POSTED_DATA_NA_CYC \
						"xmit_posted_data_na_cyc"
#define	RFIOS_PEU01_S_EVT_XMIT_NON_POSTED_HDR_NA_CYC \
						"xmit_non_posted_hdr_na_cyc"
#define	RFIOS_PEU01_S_EVT_XMIT_NON_POSTED_DATA_NA_CYC \
						"xmit_non_posted_data_na_cyc"
#define	RFIOS_PEU01_S_EVT_XMIT_COMPL_HDR_NA_CYC	"xmit_compl_hdr_na_cyc"
#define	RFIOS_PEU01_S_EVT_XMIT_COMPL_DATA_NA_CYC \
						"xmit_compl_data_na_cyc"
#define	RFIOS_PEU01_S_EVT_NO_XMIT_CRED_CYC	"no_xmit_cred_cyc"
#define	RFIOS_PEU01_S_EVT_RETRY_BUFF_NA_CYC	"retry_buffer_na_cyc"
#define	RFIOS_PEU01_S_EVT_REC_FLCTRL_COMP_EXST_CYC \
						"rec_flw_compl_hdr_exhast_cyc"
#define	RFIOS_PEU01_S_EVT_REC_FLCTRL_NPOST_EXST_CYC \
						"rec_flw_npost_hdr_exhast_cyc"
#define	RFIOS_PEU01_S_EVT_REC_FLCTRL_PST_DAT_EXST \
						"rec_flw_post_data_exhast_cyc"
#define	RFIOS_PEU01_S_EVT_REC_FLCTRL_PST_DT_CDT_EXST \
						"rec_flw_post_data_cred_exh_cyc"
#define	RFIOS_PEU01_S_EVT_REC_FLCTRL_PST_CDT_EXST \
						"rec_flw_post_data_exh_cyc"
#define	RFIOS_PEU01_S_EVT_REC_FLCTRL_CDT_EXST	"rec_flw_cred_exh_cyc"
#define	RFIOS_PEU01_S_EVT_DLLP_CRC_ERRORS	"dllp_crc_errs"
#define	RFIOS_PEU01_S_EVT_TLP_CRC_ERRORS	"tlp_crc_errs"
#define	RFIOS_PEU01_S_EVT_TLP_RECD_WITH_EDB	"tlp_recd_with_edb"
#define	RFIOS_PEU01_S_EVT_RECD_FC_TIMEOUT_ERROR	"recd_fc_to_errs"
#define	RFIOS_PEU01_S_EVT_REPLAY_NUM_ROLLOVERS	"replay_num_ro"
#define	RFIOS_PEU01_S_EVT_REPLAY_TIMER_TIMEOUTS	"replay_timer_to"
#define	RFIOS_PEU01_S_EVT_REPLAYS_INITIATED	"replays_init"
#define	RFIOS_PEU01_S_EVT_LTSSM_RECOVERY_CYC	"ltssm_rec_cyc"
#define	RFIOS_PEU01_S_EVT_ENTRIES_LTSSM_RECOVERY \
						"entries_ltssm_rec"
#define	RFIOS_PEU01_S_EVT_REC_L0S_STATE_CYC	"rec_l0s_state_cyc"
#define	RFIOS_PEU01_S_EVT_REC_L0S_STATE_TRANS	"rec_l0s_state_trans"
#define	RFIOS_PEU01_S_EVT_XMIT_L0S_STATE_CYC	"xmit_l0s_state_cyc"
#define	RFIOS_PEU01_S_EVT_XMIT_L0S_STATE_TRANS	"xmit_l0s_state_trans"


#define	RFIOS_PEU01_EVT_NONE				0x0
#define	RFIOS_PEU01_EVT_CLK				0x1
#define	RFIOS_PEU01_EVT_INT_CFG_WR_RECD			0x2
#define	RFIOS_PEU01_EVT_INT_CFG_RD_RECD			0x3
#define	RFIOS_PEU01_EVT_INT_MEM_WR_RECD			0x4
#define	RFIOS_PEU01_EVT_INT_MEM_RD_RECD			0x5
#define	RFIOS_PEU01_EVT_EXT_CFG_WR_RECD			0x6
#define	RFIOS_PEU01_EVT_EXT_CFG_RD_RECD			0x7
#define	RFIOS_PEU01_EVT_EXT_MEM_WR_RECD			0x8
#define	RFIOS_PEU01_EVT_EXT_MEM_RD_RECD			0x9
#define	RFIOS_PEU01_EVT_MEM_RD_REQ_RECD_ALL		0x10
#define	RFIOS_PEU01_EVT_MEM_RD_REQ_RECD_1_15DW		0x11
#define	RFIOS_PEU01_EVT_MEM_RD_REQ_RECD_16_31DW		0x12
#define	RFIOS_PEU01_EVT_MEM_RD_REQ_RECD_32_63DW		0x13
#define	RFIOS_PEU01_EVT_MEM_RD_REQ_RECD_64_127DW	0x14
#define	RFIOS_PEU01_EVT_MEM_RD_REQ_RECD_128_255DW	0x15
#define	RFIOS_PEU01_EVT_MEM_RD_REQ_RECD_256_511DW	0x16
#define	RFIOS_PEU01_EVT_MEM_RD_REQ_RECD_512_1024DW	0x17
#define	RFIOS_PEU01_EVT_MEM_WR_REQ_RECD_ALL		0x18
#define	RFIOS_PEU01_EVT_MEM_WR_REQ_RECD_1_15DW		0x19
#define	RFIOS_PEU01_EVT_MEM_WR_REQ_RECD_16_31DW		0x1a
#define	RFIOS_PEU01_EVT_MEM_WR_REQ_RECD_32_63DW		0x1b
#define	RFIOS_PEU01_EVT_MEM_WR_REQ_RECD_64_127DW	0x1c
#define	RFIOS_PEU01_EVT_MEM_WR_REQ_RECD_128_255DW	0x1d
#define	RFIOS_PEU01_EVT_MEM_WR_REQ_RECD_256_511DW	0x1e
#define	RFIOS_PEU01_EVT_MEM_WR_REQ_RECD_512_1024DW	0x1f
#define	RFIOS_PEU01_EVT_XMIT_POSTED_HDR_NA_CYC		0x20
#define	RFIOS_PEU01_EVT_XMIT_POSTED_DATA_NA_CYC		0x21
#define	RFIOS_PEU01_EVT_XMIT_NON_POSTED_HDR_NA_CYC	0x22
#define	RFIOS_PEU01_EVT_XMIT_NON_POSTED_DATA_NA_CYC	0x23
#define	RFIOS_PEU01_EVT_XMIT_COMPL_HDR_NA_CYC		0x24
#define	RFIOS_PEU01_EVT_XMIT_COMPL_DATA_NA_CYC		0x25
#define	RFIOS_PEU01_EVT_NO_XMIT_CRED_CYC		0x26
#define	RFIOS_PEU01_EVT_RETRY_BUFF_NA_CYC		0x27
#define	RFIOS_PEU01_EVT_REC_FLCTRL_COMP_EXST_CYC	0x28
#define	RFIOS_PEU01_EVT_REC_FLCTRL_NPOST_EXST_CYC	0x29
#define	RFIOS_PEU01_EVT_REC_FLCTRL_PST_DAT_EXST		0x2a
#define	RFIOS_PEU01_EVT_REC_FLCTRL_PST_DT_CDT_EXST	0x2b
#define	RFIOS_PEU01_EVT_REC_FLCTRL_PST_CDT_EXST		0x2c
#define	RFIOS_PEU01_EVT_REC_FLCTRL_CDT_EXST		0x2d
#define	RFIOS_PEU01_EVT_DLLP_CRC_ERRORS			0x30
#define	RFIOS_PEU01_EVT_TLP_CRC_ERRORS			0x31
#define	RFIOS_PEU01_EVT_TLP_RECD_WITH_EDB		0x32
#define	RFIOS_PEU01_EVT_RECD_FC_TIMEOUT_ERROR		0x33
#define	RFIOS_PEU01_EVT_REPLAY_NUM_ROLLOVERS		0x34
#define	RFIOS_PEU01_EVT_REPLAY_TIMER_TIMEOUTS		0x35
#define	RFIOS_PEU01_EVT_REPLAYS_INITIATED		0x36
#define	RFIOS_PEU01_EVT_LTSSM_RECOVERY_CYC		0x37
#define	RFIOS_PEU01_EVT_ENTRIES_LTSSM_RECOVERY		0x38
#define	RFIOS_PEU01_EVT_REC_L0S_STATE_CYC		0x40
#define	RFIOS_PEU01_EVT_REC_L0S_STATE_TRANS		0x41
#define	RFIOS_PEU01_EVT_XMIT_L0S_STATE_CYC		0x42
#define	RFIOS_PEU01_EVT_XMIT_L0S_STATE_TRANS		0x43

extern int rfiospc_get_perfreg(cntr_handle_t handle, int regid, uint64_t *data);
extern int rfiospc_set_perfreg(cntr_handle_t handle, int regid, uint64_t data);

extern int rfios_access_hv(iospc_t *iospc_p, void *arg, int op, int regid,
    uint64_t *data);
extern int rfios_access_init(iospc_t *iospc_p, iospc_ksinfo_t *ksinfo_p);
extern int rfios_access_fini(iospc_t *iospc_p, iospc_ksinfo_t *ksinfo_p);

#ifdef	__cplusplus
}
#endif

#endif	/* _RFIOSPC_TABLES_H */
