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

#ifndef _NV_SGPIO_H
#define	_NV_SGPIO_H


#ifdef	__cplusplus
extern "C" {
#endif

/*
 * SGPIO Command Timeout (2000ms, in nsecs)
 */
#define	NV_SGP_CMD_TIMEOUT	2000000000

/*
 * SGPIO Configuration Space Offsets
 */
#define	SGPIO_CSRP	0x58
#define	SGPIO_CBP	0x5c


/*
 * SGPIO Command/Status Register
 */

/* Command field - write-only */
#define	SGPIO_CSR_CMD_MASK	0x000000e0
#define	SGPIO_CSR_CMD_SHFT	5
#define	SGPIO_CSR_CMD_SET(y)	(((y) << SGPIO_CSR_CMD_SHFT) & \
				    SGPIO_CSR_CMD_MASK)

/* Command field values */
#define	SGPIO_CMD_RESET		0x0
#define	SGPIO_CMD_READ_PARAMS	0x1
#define	SGPIO_CMD_READ_DATA	0x2
#define	SGPIO_CMD_WRITE_DATA	0x3

/* Command Status field - read-only */
#define	SGPIO_CSR_CSTAT_MASK	0x00000018
#define	SGPIO_CSR_CSTAT_SHFT	3
#define	SGPIO_CSR_CSTAT(x)	(((x) & SGPIO_CSR_CSTAT_MASK) >> \
				    SGPIO_CSR_CSTAT_SHFT)

/* Command Status field values */
#define	SGPIO_CMD_OK		0x0
#define	SGPIO_CMD_ACTIVE	0x1
#define	SGPIO_CMD_ERROR		0x2

/* Sequence field - read-only */
#define	SGPIO_CSR_SEQ_MASK	0x00000004
#define	SGPIO_CSR_SEQ_SHFT	2
#define	SGPIO_CSR_SEQ(x)	(((x) & SGPIO_CSR_SEQ_MASK) >> \
				    SGPIO_CSR_SEQ_SHFT)

/* SGPIO Status field - read-only */
#define	SGPIO_CSR_SSTAT_MASK	0x00000003
#define	SGPIO_CSR_SSTAT_SHFT	0
#define	SGPIO_CSR_SSTAT(x)	(((x) & SGPIO_CSR_SSTAT_MASK) >> \
				    SGPIO_CSR_SSTAT_SHFT)

/* SGPIO Status field values */
#define	SGPIO_STATE_RESET	0x0
#define	SGPIO_STATE_OPERATIONAL	0x1
#define	SGPIO_STATE_ERROR	0x2


/*
 * SGPIO Control Block
 * This is not the entire control block.  It stops at the last register
 * that could possibly be used.
 */
typedef struct nv_sgp_cb {
#if defined(__amd64)
	uint64_t	sgpio_sr;	/* Scratch Register 0-1 */
#else
	uint32_t	sgpio_sr;	/* Scratch Register 0-1 */
	uint32_t	sgpio_sr1;	/* Scratch Register 0-1 */
#endif
	uint32_t	sgpio_nvcr;	/* NVIDIA Configuration Register */
	uint32_t	sgpio_cr0;	/* Configuration Register 0 */
	uint32_t	sgpio_cr1;	/* Configuration Register 1 */
	uint32_t	rsrd;
	uint32_t	sgpio_gptxcr;	/* General Purpose Transmit */
					/* Configuration Register */
	uint32_t	sgpio_gprxcr;	/* General Purpose Receive */
					/* Configuration Register */
	uint32_t	sgpio0_tr;	/* SGPIO 0 Transmit Register */
	uint32_t	sgpio1_tr;	/* SGPIO 1 Transmit Register */
} nv_sgp_cb_t;


/*
 * NVIDIA Configuration Register (SGPIO_NVCR)
 * Contains read-only configuration fields that are unique to NVIDIA's
 * implementation of SGPIO and therefore not defined in SFF8485.
 */

/* Initiator Count */
#define	SGP_NVCR_INIT_CNT_MASK	0x0000000f
#define	SGP_NVCR_INIT_CNT_SHFT	0
#define	SGP_NVCR_INIT_CNT(x)	(((x) & SGP_NVCR_INIT_CNT_MASK) >> \
				    SGP_NVCR_INIT_CNT_SHFT)

/* fixed value */
#define	SGPIO_NVCR_INIT_CNT_VAL	0x2

/* Command Block Size */
#define	SGP_NVCR_CB_SIZE_MASK	0x0000ff00
#define	SGP_NVCR_CB_SIZE_SHFT	8
#define	SGP_NVCR_CB_SIZE(x)	(((x) & SGP_NVCR_CB_SIZE_MASK) >> \
				    SGP_NVCR_CB_SIZE_SHFT)

/* Command Block Version */
#define	SGP_NVCR_CB_VERS_MASK	0x00ff0000
#define	SGP_NVCR_CB_VERS_SHFT	16
#define	SGP_NVCR_CB_VERS(x)	(((x) & SGP_NVCR_CB_VERS_MASK) >> \
				    SGP_NVCR_CB_VERS_SHFT)

/* current version value */
#define	SGP_NVCR_CB_VERSION	0


/*
 * SGPIO Configuration Register 0 (SGPIO_CR0)
 */

/* Version */
#define	SGP_CR0_VERS_MASK	0x00000f00
#define	SGP_CR0_VERS_SHFT	8
#define	SGP_CR0_VERS(x)		(((x) & SGP_CR0_VERS_MASK) >> \
				    SGP_CR0_VERS_SHFT)

/* fixed value */
#define	SGP_CR0_VERSION		0

/* Enable - write-only */
#define	SGP_CR0_ENABLE_MASK	0x00800000

/* CFG Register Count */
#define	SGP_CR0_CFG_RC_MASK	0x00700000
#define	SGP_CR0_CFG_RC_SHFT	20
#define	SGP_CR0_CFG_RC(x)	(((x) & SGP_CR0_CFG_RC_MASK) >> \
				    SGP_CR0_CFG_RC_SHFT)

/* fixed value */
#define	SGPIO_CR_GP_REG_COUNT	0x1

/* GP Register Count */
#define	SGP_CR0_GP_RC_MASK	0x000f0000
#define	SGP_CR0_GP_RC_SHFT	16
#define	SGP_CR0_GP_RC(x)	(((x) & SGP_CR0_GP_RC_MASK) >> \
				    SGP_CR0_GP_RC_SHFT)

/* fixed value */
#define	SGPIO_CR_CFG_REG_COUNT	0x2

/* Supported Drive Count */
#define	SGP_CR0_DRV_CNT_MASK	0xff000000
#define	SGP_CR0_DRV_CNT_SHFT	24
#define	SGP_CR0_DRV_CNT(x)	(((x) & SGP_CR0_DRV_CNT_MASK) >> \
				    SGP_CR0_DRV_CNT_SHFT)

/* fixed value */
#define	SGPIO_DRV_CNT_VALUE	4

/*
 * SGPIO Configuration Register 1 (SGPIO_CR1)
 */

#ifdef SGPIO_BLINK
/*
 * NVIDIA documents these Blink Generator Rate values.  However,
 * setting up the LEDs to use these Blink Generators does not result
 * in blinking LEDs.
 */

/* Blink Generator Rate B */
#define	SGPIO_CR1_BGR_B_MASK	0x0000f000
#define	SGPIO_CR1_BGR_B_SHFT	12
#define	SGPIO_CR1_BGR_B_SET(y)	((y) << SGPIO_CR1_BGR_B_SHFT) & \
				    SGPIO_CR1_BGR_B_MASK)

/* Blink Generator Rate A */
#define	SGPIO_CR1_BGR_A_MASK	0x00000f00
#define	SGPIO_CR1_BGR_A_SHFT	8
#define	SGPIO_CR1_BGR_A_SET(y)	((y) << SGPIO_CR1_BGR_A_SHFT) & \
				    SGPIO_CR1_BGR_A_MASK)

/* Blink Generator Rate values */
#define	SGPIO_BLK_1_8		0x0	/* 1/8 seconds */
#define	SGPIO_BLK_2_8		0x1	/* 2/8 seconds */
#define	SGPIO_BLK_3_8		0x2	/* 3/8 seconds */
#define	SGPIO_BLK_4_8		0x3	/* 4/8 seconds */
#define	SGPIO_BLK_5_8		0x4	/* 5/8 seconds */
#define	SGPIO_BLK_6_8		0x5	/* 6/8 seconds */
#define	SGPIO_BLK_7_8		0x6	/* 7/8 seconds */
#define	SGPIO_BLK_8_8		0x7	/* 8/8 seconds */
#define	SGPIO_BLK_9_8		0x8	/* 9/8 seconds */
#define	SGPIO_BLK_10_8		0x9	/* 10/8 seconds */
#define	SGPIO_BLK_11_8		0xa	/* 11/8 seconds */
#define	SGPIO_BLK_12_8		0xb	/* 12/8 seconds */
#define	SGPIO_BLK_13_8		0xc	/* 13/8 seconds */
#define	SGPIO_BLK_14_8		0xd	/* 14/8 seconds */
#define	SGPIO_BLK_15_8		0xe	/* 15/8 seconds */
#define	SGPIO_BLK_16_8		0xf	/* 16/8 seconds */
#endif	/* SGPIO_BLINK */

/*
 * SGPIO 0 Transmit Register (SGPIO_0_TR)
 */

/* Drive x Activity/Locate/Error */
#define	SGPIO0_TR_DRV_SET(y, a)	(((y) & 0xff) << ((3 - (a)) * 8))
#define	SGPIO0_TR_DRV_CLR(a)	~(0xff << ((3 - (a)) * 8))
#define	SGPIO0_TR_DRV(x, a)	(((x) >> ((3 - (a)) * 8)) & 0xff)
#define	TR_ACTIVE_MASK_ALL	0xe0e0e0e0
#define	TR_LOCATE_MASK_ALL	0x18181818
#define	TR_ERROR_MASK_ALL	0x07070707

/* Drive x Activity */
#define	TR_ACTIVE_MASK		0xe0
#define	TR_ACTIVE_SHFT		5
#define	TR_ACTIVE_SET(y)	(((y) << TR_ACTIVE_SHFT) & TR_ACTIVE_MASK)
#define	TR_ACTIVE(x)		(((x) & TR_ACTIVE_MASK) >> TR_ACTIVE_SHFT)

/* Drive x Activity values */
#define	TR_ACTIVE_DISABLE	0x0	/* Disable activity indicator */
#define	TR_ACTIVE_ENABLE	0x1	/* Enable activity indicator */
#ifdef SGPIO_BLINK
#define	TR_ACTIVE_BLINK_A_ON	0x2	/* Select blink generator A, 50% */
					/* duty cycle, on for the first */
					/* half-cycle, off for the second */
					/* half. */
#define	TR_ACTIVE_BLINK_A_OFF	0x3	/* Select blink generator A, 50% */
					/* duty cycle, off for the first */
					/* half-cycle, on for the second */
					/* half. */
#define	TR_ACTIVE_BLINK_B_ON	0x6	/* Select blink generator B, 50% */
					/* duty cycle, on for the first */
					/* half-cycle, off for the second */
					/* half. */
#define	TR_ACTIVE_BLINK_B_OFF	0x7	/* Select blink generator B, 50% */
					/* duty cycle, off for the first */
					/* half-cycle, on for the second */
					/* half. */
#endif	/* SGPIO_BLINK */

/* Drive x Locate */
#define	TR_LOCATE_MASK		0x18
#define	TR_LOCATE_SHFT		3
#define	TR_LOCATE_SET(y)	(((y) << TR_LOCATE_SHFT) & TR_LOCATE_MASK)
#define	TR_LOCATE(x)		(((x) & TR_LOCATE_MASK) >> TR_LOCATE_SHFT)

/* Drive x Locate values */
#define	TR_LOCATE_DISABLE	0x0	/* Disable locate indicator */
#define	TR_LOCATE_ENABLE	0x1	/* Enable locate indicator */
#ifdef SGPIO_BLINK
#define	TR_LOCATE_BLINK_ON	0x2	/* Select blink generator A, 50% */
					/* duty cycle, on for the first */
					/* half-cycle, off for the second */
					/* half. */
#define	TR_LOCATE_BLINK_OFF	0x3	/* Select blink generator A, 50% */
					/* duty cycle, off for the first */
					/* half-cycle, on for the second */
					/* half. */
#endif	/* SGPIO_BLINK */

/* Drive x Error */
#define	TR_ERROR_MASK		0x07
#define	TR_ERROR_SHFT		0
#define	TR_ERROR_SET(y)		(((y) << TR_ERROR_SHFT) & TR_ERROR_MASK)
#define	TR_ERROR(x)		(((x) & TR_ERROR_MASK) >> TR_ERROR_SHFT)

/* Drive x Error values */
#define	TR_ERROR_DISABLE	0x0	/* Disable error indicator */
#define	TR_ERROR_ENABLE		0x1	/* Enable error indicator */
#ifdef SGPIO_BLINK
#define	TR_ERROR_BLINK_A_ON	0x2	/* Select blink generator A, 50% */
					/* duty cycle, on for the first */
					/* half-cycle, off for the second */
					/* half for error indicator. */
#define	TR_ERROR_BLINK_A_OFF	0x3	/* Select blink generator A, 50% */
					/* duty cycle, off for the first */
					/* half-cycle, on for the second */
					/* half for error indicator. */
#define	TR_ERROR_BLINK_B_ON	0x6	/* Select blink generator B, 50% */
					/* duty cycle, on for the first */
					/* half-cycle, off for the second */
					/* half for error indicator. */
#define	TR_ERROR_BLINK_B_OFF	0x7	/* Select blink generator B, 50% */
					/* duty cycle, off for the first */
					/* half-cycle, on for the second */
					/* half for error indicator. */
#endif	/* SGPIO_BLINK */

/*
 * SGPIO 1 Transmit Register (SGPIO_1_TR)
 */

/* Drive x Activity/Locate/Error */
#define	SGPIO1_TR_DRV_SET(y, a)	(((y) & 0xff) << ((7 - (a)) * 8))
#define	SGPIO1_TR_DRV_CLR(a)	~(0xff << ((7 - (a)) * 8))
#define	SGPIO1_TR_DRV(x, a)	(((x) >> ((7 - (a)) * 8)) & 0xff)

#ifdef	__cplusplus
}
#endif

#endif /* _NV_SGPIO_H */
