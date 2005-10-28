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
 * Copyright 1998 Sun Microsystems, Inc. All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_SOCALREG_H
#define	_SYS_SOCALREG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * socalreg.h:
 *
 * 	SOC+ Register Definitions, Interface Adaptor to Fiber Channel
 */

#define	N_SOCAL_NPORTS	2

/*
 * Define the SOC+ configuration register bits.
 */
typedef union socal_cr_register {
	struct cr {
		uint_t	aaa:5;
		uint_t	ramsel:3;	/* Ram bank select. */
		uint_t	bbb:6;
		uint_t	eepromsel:2;	/* Eeprom bank select. */
		uint_t	ccc:5;
		uint_t	burst64:3;	/* Sbus Burst size, 64 bit mode. */
		uint_t	ddd:2;
		uint_t	parenable:1;	/* Partity test enable. */
		uint_t	parsbus:1;	/* Sbus Parity checking. */
		uint_t	sbusmode:1;	/* Enhanced Sbus mode. */
		uint_t	sbusburst:3;	/* Sbus burst size. */
	} reg;
	uint32_t	w;
} socal_cr_reg_t;

/*
 * Define Configuration register bits.
 */

#define	SOCAL_CR_SBUS_BURST_SIZE_MASK		0x007
#define	SOCAL_CR_SBUS_BURST_SIZE_64BIT_MASK	0x700
#define	SOCAL_CR_SBUS_BURST_SIZE_64BIT(a)	\
	(((a) & SOCAL_CR_SBUS_BURST_SIZE_64BIT_MASK) >> 8)

#define	SOCAL_CR_BURST_4		0x0
#define	SOCAL_CR_BURST_8		0x3
#define	SOCAL_CR_BURST_16		0x4
#define	SOCAL_CR_BURST_32		0x5
#define	SOCAL_CR_BURST_64		0x6
#define	SOCAL_CR_BURST_128		0x7

#define	SOCAL_CR_SBUS_ENHANCED		0x08
#define	SOCAL_CR_SBUS_PARITY_CHK	0x10
#define	SOCAL_CR_SBUS_PARITY_TEST	0x20

#define	SOCAL_CR_EEPROM_BANK_MASK	0x30000
#define	SOCAL_CR_EEPROM_BANK(a)	(((a) & SOCAL_CR_EEPROM_BANK_MASK) >> 16)

#define	SOCAL_CR_EXTERNAL_RAM_BANK_MASK	0x7000000
#define	SOCAL_CR_EXTERNAL_RAM_BANK(a) \
	(((a) & SOCAL_CR_EXTERNAL_RAM_BANK_MASK) >> 24)

/*
 * Define SOC+ Slave Access Register.
 */
typedef union socal_sae_register {
	struct sae {
		uint_t	aaa:29;			/* Reserved. */
		uint_t	alignment_err:1;	/* Soc Alignment Error. */
		uint_t	bad_size_err:1;		/* Bad Size error. */
		uint_t	parity_err:1;		/* Parity Error. */
	} reg;
	uint32_t	w;
} socal_sae_reg_t;

/*
 * Define the Slave Access Regsiter Bits.
 */

#define	SOCAL_SAE_PARITY_ERROR		0x01
#define	SOCAL_SAE_UNSUPPORTED_TRANSFER	0x02
#define	SOCAL_SAE_ALIGNMENT_ERROR	0x04

/*
 * Define SOC+ Command and Status Register.
 */
typedef union socal_csr_register {
	struct csr {
		uint_t	comm_param:8;	/* Communication Parameters. */
		uint_t	aaa:4;
		uint_t	socal_to_host:4;	/* Soc to host attention. */
		uint_t	bbb:4;
		uint_t	host_to_socal:4;	/* Host to soc+ attention. */
		uint_t	sae:1;		/* Slave access error indicator. */
		uint_t	ccc:3;
		uint_t	int_pending:1;	/* Interrupt Pending. */
		uint_t	nqcmd:1;	/* Non queued command */
		uint_t	idle:1;		/* SOC+ idle indicator. */
		uint_t	reset:1;	/* Software Reset. */
	} reg;
	uint32_t	w;
} socal_csr_reg_t;


/*
 * Define SOC+ CSR Register Macros.
 */
#define	SOCAL_CSR_ZEROS		0x00000070
#define	SOCAL_CSR_SOCAL_TO_HOST	0x000f0000
#define	SOCAL_CSR_HOST_TO_SOCAL	0x00000f00
#define	SOCAL_CSR_SLV_ACC_ERR	0x00000080
#define	SOCAL_CSR_INT_PENDING	0x00000008
#define	SOCAL_CSR_NON_Q_CMD	0x00000004
#define	SOCAL_CSR_IDLE		0x00000002
#define	SOCAL_CSR_SOFT_RESET	0x00000001

#define	SOCAL_CSR_1ST_S_TO_H	0x00010000
#define	SOCAL_CSR_1ST_H_TO_S	0x00000100

#define	SOCAL_CSR_RSP_QUE_0	SOCAL_CSR_1ST_S_TO_H
#define	SOCAL_CSR_RSP_QUE_1	0x00020000
#define	SOCAL_CSR_RSP_QUE_2	0x00040000
#define	SOCAL_CSR_RSP_QUE_3	0x00080000

#define	SOCAL_CSR_REQ_QUE_0	SOCAL_CSR_1ST_H_TO_S
#define	SOCAL_CSR_REQ_QUE_1	0x00000200
#define	SOCAL_CSR_REQ_QUE_2	0x00000400
#define	SOCAL_CSR_REQ_QUE_3	0x00000800

/*
 * Define SOC Interrupt Mask Register Bits.
 */

#define	SOCAL_IMR_NON_QUEUED_STATE	0x04
#define	SOCAL_IMR_SLAVE_ACCESS_ERROR	0x80

#define	SOCAL_IMR_REQUEST_QUEUE_0	0x100
#define	SOCAL_IMR_REQUEST_QUEUE_1	0x200
#define	SOCAL_IMR_REQUEST_QUEUE_2	0x400
#define	SOCAL_IMR_REQUEST_QUEUE_3	0x800

#define	SOCAL_IMR_RESPONSE_QUEUE_0	0x10000
#define	SOCAL_IMR_RESPONSE_QUEUE_1	0x20000
#define	SOCAL_IMR_RESPONSE_QUEUE_2	0x40000
#define	SOCAL_IMR_RESPONSE_QUEUE_3	0x80000

/*
 * Define SOC+ Request Queue Index Register
 */
typedef union socal_reqp_register {
	struct reqp {
		uint_t	reqq0_index:8;
		uint_t	reqq1_index:8;
		uint_t	reqq2_index:8;
		uint_t	reqq3_index:8;
	} reg;
	uint32_t	w;
} socal_reqp_reg_t;

#define	SOCAL_REQUESTQ0_MASK	0xff000000
#define	SOCAL_REQUESTQ1_MASK	0x00ff0000
#define	SOCAL_REQUESTQ2_MASK	0x0000ff00
#define	SOCAL_REQUESTQ3_MASK	0x000000ff

#define	SOCAL_REQUESTQ0_INDEX(a) (((a) & SOCAL_REQUESTQ0_MASK) >> 24)
#define	SOCAL_REQUESTQ1_INDEX(a) (((a) & SOCAL_REQUESTQ1_MASK) >> 16)
#define	SOCAL_REQUESTQ2_INDEX(a) (((a) & SOCAL_REQUESTQ2_MASK) >> 8)
#define	SOCAL_REQUESTQ3_INDEX(a) ((a) & SOCAL_REQUESTQ3_MASK)

#define	SOCAL_REQUESTQ_INDEX(a, b) ((b)>>((3-(a))<<3) & 0xff)

/*
 * Define SOC+ Response Queue Index Register
 */
typedef union socal_rspp_register {
	struct rspp {
		uint_t	rspq0_index:8;
		uint_t	rspq1_index:8;
		uint_t	rspq2_index:8;
		uint_t	rspq3_index:8;
	} reg;
	uint32_t	w;
} socal_rspp_reg_t;

#define	SOCAL_RESPONSEQ0_MASK	0xff000000
#define	SOCAL_RESPONSEQ1_MASK	0x00ff0000
#define	SOCAL_RESPONSEQ2_MASK	0x0000ff00
#define	SOCAL_RESPONSEQ3_MASK	0x000000ff

#define	SOCAL_RESPONSEQ0_INDEX(a) (((a) & SOCAL_RESPONSEQ0_MASK) >> 24)
#define	SOCAL_RESPONSEQ1_INDEX(a) (((a) & SOCAL_RESPONSEQ1_MASK) >> 16)
#define	SOCAL_RESPONSEQ2_INDEX(a) (((a) & SOCAL_RESPONSEQ2_MASK) >> 8)
#define	SOCAL_RESPONSEQ3_INDEX(a) ((a) & SOCAL_RESPONSEQ3_MASK)

#define	SOCAL_RESPONSEQ_INDEX(a, b) ((b)>>((3-(a))<<3) & 0xff)

typedef struct _socalreg_ {
	socal_cr_reg_t		socal_cr;	/* Configuration reg */
	socal_sae_reg_t		socal_sae;	/* Slave access error reg */
	socal_csr_reg_t		socal_csr;	/* Command Status reg */
	uint32_t		socal_imr;	/* Interrupt Mask reg */
	socal_reqp_reg_t	socal_reqp;	/* request queue index reg */
	socal_rspp_reg_t	socal_rspp;	/* response queue index reg */
} socal_reg_t;

/*
 * Device Address Space Offsets.
 */

#define	SOCAL_XRAM_OFFSET	0x10000
#define	SOCAL_XRAM_SIZE		0x10000

#define	SOCAL_MAX_XCHG		1024

#define	SOCAL_REG_OFFSET	(SOCAL_XRAM_OFFSET + SOCAL_XRAM_SIZE)

#define	SOCAL_CQ_REQUEST_OFFSET (SOCAL_XRAM_OFFSET + 0x200)
#define	SOCAL_CQ_RESPONSE_OFFSET (SOCAL_XRAM_OFFSET + 0x220)


#define	SOCAL_INTR_CAUSE(socalp, csr) \
	(((csr) & SOCAL_CSR_SOCAL_TO_HOST) | \
	((~csr) & (SOCAL_CSR_HOST_TO_SOCAL))) & socalp->socal_k_imr

/*
 * Bus dma burst sizes
 */
#ifndef BURSTSIZE
#define	BURSTSIZE
#define	BURST1			0x01
#define	BURST2			0x02
#define	BURST4			0x04
#define	BURST8			0x08
#define	BURST16			0x10
#define	BURST32			0x20
#define	BURST64			0x40
#define	BURST128		0x80
#define	BURSTSIZE_MASK		0xff
#define	DEFAULT_BURSTSIZE	BURST16|BURST8|BURST4|BURST2|BURST1
#endif  /* BURSTSIZE */

#ifdef __cplusplus
}
#endif

#endif /* !_SYS_SOCALREG_H */
