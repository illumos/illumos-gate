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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_NXGE_NXGE_ZCP_HW_H
#define	_SYS_NXGE_NXGE_ZCP_HW_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <nxge_defs.h>

/*
 * Neptune Zerocopy Hardware definitions
 * Updated to reflect PRM-0.8.
 */

#define	ZCP_CONFIG_REG		(FZC_ZCP + 0x00000)
#define	ZCP_INT_STAT_REG	(FZC_ZCP + 0x00008)
#define	ZCP_INT_STAT_TEST_REG	(FZC_ZCP + 0x00108)
#define	ZCP_INT_MASK_REG	(FZC_ZCP + 0x00010)

#define	ZCP_BAM4_RE_CTL_REG 	(FZC_ZCP + 0x00018)
#define	ZCP_BAM8_RE_CTL_REG 	(FZC_ZCP + 0x00020)
#define	ZCP_BAM16_RE_CTL_REG 	(FZC_ZCP + 0x00028)
#define	ZCP_BAM32_RE_CTL_REG 	(FZC_ZCP + 0x00030)

#define	ZCP_DST4_RE_CTL_REG 	(FZC_ZCP + 0x00038)
#define	ZCP_DST8_RE_CTL_REG 	(FZC_ZCP + 0x00040)
#define	ZCP_DST16_RE_CTL_REG 	(FZC_ZCP + 0x00048)
#define	ZCP_DST32_RE_CTL_REG 	(FZC_ZCP + 0x00050)

#define	ZCP_RAM_DATA_REG	(FZC_ZCP + 0x00058)
#define	ZCP_RAM_DATA0_REG	(FZC_ZCP + 0x00058)
#define	ZCP_RAM_DATA1_REG	(FZC_ZCP + 0x00060)
#define	ZCP_RAM_DATA2_REG	(FZC_ZCP + 0x00068)
#define	ZCP_RAM_DATA3_REG	(FZC_ZCP + 0x00070)
#define	ZCP_RAM_DATA4_REG	(FZC_ZCP + 0x00078)
#define	ZCP_RAM_BE_REG		(FZC_ZCP + 0x00080)
#define	ZCP_RAM_ACC_REG		(FZC_ZCP + 0x00088)

#define	ZCP_TRAINING_VECTOR_REG	(FZC_ZCP + 0x000C0)
#define	ZCP_STATE_MACHINE_REG	(FZC_ZCP + 0x000C8)
#define	ZCP_CHK_BIT_DATA_REG	(FZC_ZCP + 0x00090)
#define	ZCP_RESET_CFIFO_REG	(FZC_ZCP + 0x00098)
#define	ZCP_RESET_CFIFO_MASK	0x0F

#define	ZCP_CFIFIO_RESET_WAIT		10
#define	ZCP_P0_P1_CFIFO_DEPTH		2048
#define	ZCP_P2_P3_CFIFO_DEPTH		1024
#define	ZCP_NIU_CFIFO_DEPTH		1024

typedef union _zcp_reset_cfifo {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t rsrvd:28;
			uint32_t reset_cfifo3:1;
			uint32_t reset_cfifo2:1;
			uint32_t reset_cfifo1:1;
			uint32_t reset_cfifo0:1;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t reset_cfifo0:1;
			uint32_t reset_cfifo1:1;
			uint32_t reset_cfifo2:1;
			uint32_t reset_cfifo3:1;
			uint32_t rsrvd:28;
#endif
		} ldw;
#if !defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
	} bits;
} zcp_reset_cfifo_t, *p_zcp_reset_cfifo_t;

#define	ZCP_CFIFO_ECC_PORT0_REG	(FZC_ZCP + 0x000A0)
#define	ZCP_CFIFO_ECC_PORT1_REG	(FZC_ZCP + 0x000A8)
#define	ZCP_CFIFO_ECC_PORT2_REG	(FZC_ZCP + 0x000B0)
#define	ZCP_CFIFO_ECC_PORT3_REG	(FZC_ZCP + 0x000B8)

/* NOTE: Same as RX_LOG_PAGE_HDL */
#define	ZCP_PAGE_HDL_REG	(FZC_DMC + 0x20038)

/* Data Structures */

typedef union zcp_config_reg_u {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t rsvd:7;
			uint32_t mode_32_bit:1;
			uint32_t debug_sel:8;
			uint32_t rdma_th:11;
			uint32_t ecc_chk_dis:1;
			uint32_t par_chk_dis:1;
			uint32_t dis_buf_rn:1;
			uint32_t dis_buf_rq_if:1;
			uint32_t zc_enable:1;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t zc_enable:1;
			uint32_t dis_buf_rq_if:1;
			uint32_t dis_buf_rn:1;
			uint32_t par_chk_dis:1;
			uint32_t ecc_chk_dis:1;
			uint32_t rdma_th:11;
			uint32_t debug_sel:8;
			uint32_t mode_32_bit:1;
			uint32_t rsvd:7;
#endif
		} ldw;
#if !defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
	} bits;
} zcp_config_reg_t, *zcp_config_reg_pt;

#define	ZCP_DEBUG_SEL_BITS	0xFF
#define	ZCP_DEBUG_SEL_SHIFT	16
#define	ZCP_DEBUG_SEL_MASK	(ZCP_DEBUG_SEL_BITS << ZCP_DEBUG_SEL_SHIFT)
#define	RDMA_TH_BITS		0x7FF
#define	RDMA_TH_SHIFT		5
#define	RDMA_TH_MASK		(RDMA_TH_BITS << RDMA_TH_SHIFT)
#define	ECC_CHK_DIS		(1 << 4)
#define	PAR_CHK_DIS		(1 << 3)
#define	DIS_BUFF_RN		(1 << 2)
#define	DIS_BUFF_RQ_IF		(1 << 1)
#define	ZC_ENABLE		(1 << 0)

typedef union zcp_int_stat_reg_u {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t rsvd:16;
			uint32_t rrfifo_urun:1;
			uint32_t rrfifo_orun:1;
			uint32_t rsvd1:1;
			uint32_t rspfifo_uc_err:1;
			uint32_t buf_overflow:1;
			uint32_t stat_tbl_perr:1;
			uint32_t dyn_tbl_perr:1;
			uint32_t buf_tbl_perr:1;
			uint32_t tt_tbl_perr:1;
			uint32_t rsp_tt_index_err:1;
			uint32_t slv_tt_index_err:1;
			uint32_t zcp_tt_index_err:1;
			uint32_t cfifo_ecc3:1;
			uint32_t cfifo_ecc2:1;
			uint32_t cfifo_ecc1:1;
			uint32_t cfifo_ecc0:1;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t cfifo_ecc0:1;
			uint32_t cfifo_ecc1:1;
			uint32_t cfifo_ecc2:1;
			uint32_t cfifo_ecc3:1;
			uint32_t zcp_tt_index_err:1;
			uint32_t slv_tt_index_err:1;
			uint32_t rsp_tt_index_err:1;
			uint32_t tt_tbl_perr:1;
			uint32_t buf_tbl_perr:1;
			uint32_t dyn_tbl_perr:1;
			uint32_t stat_tbl_perr:1;
			uint32_t buf_overflow:1;
			uint32_t rspfifo_uc_err:1;
			uint32_t rsvd1:1;
			uint32_t rrfifo_orun:1;
			uint32_t rrfifo_urun:1;
			uint32_t rsvd:16;
#endif
		} ldw;
#if !defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
	} bits;
} zcp_int_stat_reg_t, *zcp_int_stat_reg_pt, zcp_int_mask_reg_t,
	*zcp_int_mask_reg_pt;

#define	RRFIFO_UNDERRUN		(1 << 15)
#define	RRFIFO_OVERRUN		(1 << 14)
#define	RSPFIFO_UNCORR_ERR	(1 << 12)
#define	BUFFER_OVERFLOW		(1 << 11)
#define	STAT_TBL_PERR		(1 << 10)
#define	BUF_DYN_TBL_PERR	(1 << 9)
#define	BUF_TBL_PERR		(1 << 8)
#define	TT_PROGRAM_ERR		(1 << 7)
#define	RSP_TT_INDEX_ERR	(1 << 6)
#define	SLV_TT_INDEX_ERR	(1 << 5)
#define	ZCP_TT_INDEX_ERR	(1 << 4)
#define	CFIFO_ECC3		(1 << 3)
#define	CFIFO_ECC0		(1 << 0)
#define	CFIFO_ECC2		(1 << 2)
#define	CFIFO_ECC1		(1 << 1)

typedef union zcp_bam_region_reg_u {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t loj:1;
			uint32_t range_chk_en:1;
			uint32_t last_zcfid:10;
			uint32_t first_zcfid:10;
			uint32_t offset:10;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t offset:10;
			uint32_t first_zcfid:10;
			uint32_t last_zcfid:10;
			uint32_t range_chk_en:1;
			uint32_t loj:1;
#endif
		} ldw;
#if !defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
	} bits;
} zcp_bam_region_reg_t, *zcp_bam_region_reg_pt;

typedef union zcp_dst_region_reg_u {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t rsvd:22;
			uint32_t ds_offset:10;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t rsvd:22;
			uint32_t ds_offset:10;
#endif
		} ldw;
#if !defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
	} bits;
} zcp_dst_region_reg_t, *zcp_dst_region_reg_pt;

typedef	enum tbuf_size_e {
	TBUF_4K		= 0,
	TBUF_8K,
	TBUF_16K,
	TBUF_32K,
	TBUF_64K,
	TBUF_128K,
	TBUF_256K,
	TBUF_512K,
	TBUF_1M,
	TBUF_2M,
	TBUF_4M,
	TBUF_8M
} tbuf_size_t;

typedef	enum tbuf_num_e {
	TBUF_NUM_4	= 0,
	TBUF_NUM_8,
	TBUF_NUM_16,
	TBUF_NUM_32
} tbuf_num_t;

typedef	enum tmode_e {
	TMODE_BASIC		= 0,
	TMODE_AUTO_UNMAP	= 1,
	TMODE_AUTO_ADV		= 3
} tmode_t;

typedef	struct tte_sflow_attr_s {
	union {
		uint64_t value;
		struct {
#if defined(_BIG_ENDIAN)
			uint32_t hdw;
#endif
			struct {
#if defined(_BIT_FIELDS_HTOL)
				uint32_t ulp_end:18;
				uint32_t num_buf:2;
				uint32_t buf_size:4;
				uint32_t rdc_tbl_offset:8;
#elif defined(_BIT_FIELDS_LTOH)
				uint32_t rdc_tbl_offset:8;
				uint32_t buf_size:4;
				uint32_t num_buf:2;
				uint32_t ulp_end:18;
#endif
			} ldw;
#if !defined(_BIG_ENDIAN)
			uint32_t hdw;
#endif
		} bits;
	} qw0;

	union {
		uint64_t value;
		struct {
#if defined(_BIG_ENDIAN)
			uint32_t hdw;
#endif
			struct {
#if defined(_BIT_FIELDS_HTOL)
				uint32_t ring_base:12;
				uint32_t skip:1;
				uint32_t rsvd:1;
				uint32_t tmode:2;
				uint32_t unmap_all_en:1;
				uint32_t ulp_end_en:1;
				uint32_t ulp_end:14;
#elif defined(_BIT_FIELDS_LTOH)
				uint32_t ulp_end:14;
				uint32_t ulp_end_en:1;
				uint32_t unmap_all_en:1;
				uint32_t tmode:2;
				uint32_t rsvd:1;
				uint32_t skip:1;
				uint32_t ring_base:12;
#endif
			} ldw;
#if !defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
		} bits;
	} qw1;

	union {
		uint64_t value;
		struct {
#if defined(_BIG_ENDIAN)
			uint32_t hdw;
#endif
			struct {
#if defined(_BIT_FIELDS_HTOL)
				uint32_t busy:1;
				uint32_t ring_size:4;
				uint32_t ring_base:27;
#elif defined(_BIT_FIELDS_LTOH)
				uint32_t ring_base:27;
				uint32_t ring_size:4;
				uint32_t busy:1;
#endif
			} ldw;
#if !defined(_BIG_ENDIAN)
			uint32_t hdw;
#endif
		} bits;
	} qw2;

	union {
		uint64_t value;
		struct {
#if defined(_BIG_ENDIAN)
			uint32_t hdw;
#endif
			struct {
#if defined(_BIT_FIELDS_HTOL)
				uint32_t rsvd:16;
				uint32_t toq:16;
#elif defined(_BIT_FIELDS_LTOH)
				uint32_t toq:16;
				uint32_t rsvd:16;
#endif
			} ldw;
#if !defined(_BIG_ENDIAN)
			uint32_t hdw;
#endif
		} bits;
	} qw3;

	union {
		uint64_t value;
		struct {
#if defined(_BIG_ENDIAN)
			uint32_t hdw;
#endif
			struct {
#if defined(_BIT_FIELDS_HTOL)
				uint32_t rsvd:28;
				uint32_t dat4:4;
#elif defined(_BIT_FIELDS_LTOH)
				uint32_t dat4:4;
				uint32_t rsvd:28;
#endif
			} ldw;
#if !defined(_BIG_ENDIAN)
			uint32_t hdw;
#endif
		} bits;
	} qw4;

} tte_sflow_attr_t, *tte_sflow_attr_pt;

#define	TTE_RDC_TBL_SFLOW_BITS_EN	0x0001
#define	TTE_BUF_SIZE_BITS_EN		0x0002
#define	TTE_NUM_BUF_BITS_EN		0x0002
#define	TTE_ULP_END_BITS_EN		0x003E
#define	TTE_ULP_END_EN_BITS_EN		0x0020
#define	TTE_UNMAP_ALL_BITS_EN		0x0020
#define	TTE_TMODE_BITS_EN		0x0040
#define	TTE_SKIP_BITS_EN		0x0040
#define	TTE_RING_BASE_ADDR_BITS_EN	0x0FC0
#define	TTE_RING_SIZE_BITS_EN		0x0800
#define	TTE_BUSY_BITS_EN		0x0800
#define	TTE_TOQ_BITS_EN			0x3000

#define	TTE_MAPPED_IN_BITS_EN		0x0000F
#define	TTE_ANCHOR_SEQ_BITS_EN		0x000F0
#define	TTE_ANCHOR_OFFSET_BITS_EN	0x00700
#define	TTE_ANCHOR_BUFFER_BITS_EN	0x00800
#define	TTE_ANCHOR_BUF_FLAG_BITS_EN	0x00800
#define	TTE_UNMAP_ON_LEFT_BITS_EN	0x00800
#define	TTE_ULP_END_REACHED_BITS_EN	0x00800
#define	TTE_ERR_STAT_BITS_EN		0x01000
#define	TTE_WR_PTR_BITS_EN		0x01000
#define	TTE_HOQ_BITS_EN			0x0E000
#define	TTE_PREFETCH_ON_BITS_EN		0x08000

typedef	enum tring_size_e {
	TRING_SIZE_8		= 0,
	TRING_SIZE_16,
	TRING_SIZE_32,
	TRING_SIZE_64,
	TRING_SIZE_128,
	TRING_SIZE_256,
	TRING_SIZE_512,
	TRING_SIZE_1K,
	TRING_SIZE_2K,
	TRING_SIZE_4K,
	TRING_SIZE_8K,
	TRING_SIZE_16K,
	TRING_SIZE_32K
} tring_size_t;

typedef struct tte_dflow_attr_s {
	union {
		uint64_t value;
		struct {
#if defined(_BIG_ENDIAN)
			uint32_t hdw;
#endif
			struct {
#if defined(_BIT_FIELDS_HTOL)
				uint32_t mapped_in;
#elif defined(_BIT_FIELDS_LTOH)
				uint32_t mapped_in;
#endif
			} ldw;
#if !defined(_BIG_ENDIAN)
			uint32_t hdw;
#endif
		} bits;
	} qw0;

	union {
		uint64_t value;
		struct {
#if defined(_BIG_ENDIAN)
			uint32_t hdw;
#endif
			struct {
#if defined(_BIT_FIELDS_HTOL)
				uint32_t anchor_seq;
#elif defined(_BIT_FIELDS_LTOH)
				uint32_t anchor_seq;
#endif
			} ldw;
#if !defined(_BIG_ENDIAN)
			uint32_t hdw;
#endif
		} bits;
	} qw1;

	union {
		uint64_t value;
		struct {
#if defined(_BIG_ENDIAN)
			uint32_t hdw;
#endif
			struct {
#if defined(_BIT_FIELDS_HTOL)
				uint32_t ulp_end_reached;
				uint32_t unmap_on_left;
				uint32_t anchor_buf_flag;
				uint32_t anchor_buf:5;
				uint32_t anchor_offset:24;
#elif defined(_BIT_FIELDS_LTOH)
				uint32_t anchor_offset:24;
				uint32_t anchor_buf:5;
				uint32_t anchor_buf_flag;
				uint32_t unmap_on_left;
				uint32_t ulp_end_reached;
#endif
			} ldw;
#if !defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
		} bits;
	} qw2;

	union {
		uint64_t value;
		struct {
#if defined(_BIG_ENDIAN)
			uint32_t hdw;
#endif
			struct {
#if defined(_BIT_FIELDS_HTOL)
				uint32_t rsvd1:1;
				uint32_t prefetch_on:1;
				uint32_t hoq:16;
				uint32_t rsvd:6;
				uint32_t wr_ptr:6;
				uint32_t err_stat:2;
#elif defined(_BIT_FIELDS_LTOH)
				uint32_t err_stat:2;
				uint32_t wr_ptr:6;
				uint32_t rsvd:6;
				uint32_t hoq:16;
				uint32_t prefetch_on:1;
				uint32_t rsvd1:1;
#endif
			} ldw;
#if !defined(_BIG_ENDIAN)
			uint32_t hdw;
#endif
		} bits;
	} qw3;

	union {
		uint64_t value;
		struct {
#if defined(_BIG_ENDIAN)
			uint32_t hdw;
#endif
			struct {
#if defined(_BIT_FIELDS_HTOL)
				uint32_t rsvd:28;
				uint32_t dat4:4;
#elif defined(_BIT_FIELDS_LTOH)
				uint32_t dat4:4;
				uint32_t rsvd:28;
#endif
			} ldw;
#if !defined(_BIG_ENDIAN)
			uint32_t hdw;
#endif
		} bits;
	} qw4;

} tte_dflow_attr_t, *tte_dflow_attr_pt;

#define	MAX_BAM_BANKS	8

typedef	struct zcp_ram_unit_s {
	uint32_t	w0;
	uint32_t	w1;
	uint32_t	w2;
	uint32_t	w3;
	uint32_t	w4;
} zcp_ram_unit_t;

typedef	enum dmaw_type_e {
	DMAW_NO_CROSS_BUF	= 0,
	DMAW_IP_CROSS_BUF_2,
	DMAW_IP_CROSS_BUF_3,
	DMAW_IP_CROSS_BUF_4
} dmaw_type_t;

typedef union zcp_ram_data_u {
	tte_sflow_attr_t sentry;
	tte_dflow_attr_t dentry;
} zcp_ram_data_t, *zcp_ram_data_pt;

typedef union zcp_ram_access_u {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t busy:1;
			uint32_t rdwr:1;
			uint32_t rsvd:1;
			uint32_t zcfid:12;
			uint32_t ram_sel:5;
			uint32_t cfifo:12;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t cfifo:12;
			uint32_t ram_sel:5;
			uint32_t zcfid:12;
			uint32_t rsvd:1;
			uint32_t rdwr:1;
			uint32_t busy:1;
#endif
		} ldw;
#if !defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
	} bits;
} zcp_ram_access_t, *zcp_ram_access_pt;

#define	ZCP_RAM_WR		0
#define	ZCP_RAM_RD		1
#define	ZCP_RAM_SEL_BAM0	0
#define	ZCP_RAM_SEL_BAM1	0x1
#define	ZCP_RAM_SEL_BAM2	0x2
#define	ZCP_RAM_SEL_BAM3	0x3
#define	ZCP_RAM_SEL_BAM4	0x4
#define	ZCP_RAM_SEL_BAM5	0x5
#define	ZCP_RAM_SEL_BAM6	0x6
#define	ZCP_RAM_SEL_BAM7	0x7
#define	ZCP_RAM_SEL_TT_STATIC	0x8
#define	ZCP_RAM_SEL_TT_DYNAMIC	0x9
#define	ZCP_RAM_SEL_CFIFO0	0x10
#define	ZCP_RAM_SEL_CFIFO1	0x11
#define	ZCP_RAM_SEL_CFIFO2	0x12
#define	ZCP_RAM_SEL_CFIFO3	0x13

typedef union zcp_ram_benable_u {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t rsvd:15;
			uint32_t be:17;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t be:17;
			uint32_t rsvd:15;
#endif
		} ldw;
#if !defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
	} bits;
} zcp_ram_benable_t, *zcp_ram_benable_pt;

typedef union zcp_training_vector_u {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t train_vec;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t train_vec;
#endif
		} ldw;
#if !defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
	} bits;
} zcp_training_vector_t, *zcp_training_vector_pt;

typedef union zcp_state_machine_u {
	uint64_t value;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
			uint32_t state;
#elif defined(_BIT_FIELDS_LTOH)
			uint32_t state;
#endif
		} ldw;
#if !defined(_BIG_ENDIAN)
		uint32_t hdw;
#endif
	} bits;
} zcp_state_machine_t, *zcp_state_machine_pt;

typedef	struct zcp_hdr_s {
	uint16_t	zflowid;
	uint16_t	tcp_hdr_len;
	uint16_t	tcp_payld_len;
	uint16_t	head_of_que;
	uint32_t	first_b_offset;
	boolean_t	reach_buf_end;
	dmaw_type_t	dmaw_type;
	uint8_t		win_buf_offset;
} zcp_hdr_t;

typedef	union _zcp_ecc_ctrl {
	uint64_t value;

	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	w1;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
		uint32_t dis_dbl	: 1;
		uint32_t res3		: 13;
		uint32_t cor_dbl	: 1;
		uint32_t cor_sng	: 1;
		uint32_t res2		: 5;
		uint32_t cor_all	: 1;
		uint32_t res1		: 7;
		uint32_t cor_lst	: 1;
		uint32_t cor_snd	: 1;
		uint32_t cor_fst	: 1;
#elif defined(_BIT_FIELDS_LTOH)
		uint32_t cor_fst	: 1;
		uint32_t cor_snd	: 1;
		uint32_t cor_lst	: 1;
		uint32_t res1		: 7;
		uint32_t cor_all	: 1;
		uint32_t res2		: 5;
		uint32_t cor_sng	: 1;
		uint32_t cor_dbl	: 1;
		uint32_t res3		: 13;
		uint32_t dis_dbl	: 1;
#else
#error	one of _BIT_FIELDS_HTOL or _BIT_FIELDS_LTOH must be defined
#endif
	} w0;

#if !defined(_BIG_ENDIAN)
		uint32_t	w1;
#endif
	} bits;
} zcp_ecc_ctrl_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_NXGE_NXGE_ZCP_HW_H */
