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

#ifndef _SYS_PX_ERR_H
#define	_SYS_PX_ERR_H

#ifdef	__cplusplus
extern "C" {
#endif

/* error packet definitions */

/* Block Definitions */
#define	BLOCK_RSVD		0x0
#define	BLOCK_HOSTBUS		0x1
#define	BLOCK_MMU		0x2
#define	BLOCK_INTR		0x3
#define	BLOCK_PCIE		0x4
#define	BLOCK_PORT		0x5
#define	BLOCK_UNKNOWN		0xe

/* Op definitions for HOSTBUS */
#define	OP_RESERVED		0x0
#define	OP_PIO			0x1
#define	OP_DMA			0x2
#define	OP_UNKNOWN		0xe

/* Op definitions for MMU */
#define	OP_RESERVED		0x0
#define	OP_XLAT			0x1
#define	OP_BYPASS		0x2
#define	OP_TBW			0x3
#define	OP_UNKNOWN		0xe

/* Op definitions for INTR */
#define	OP_RESERVED		0x0
#define	OP_MSI32		0x1
#define	OP_MSI64		0x2
#define	OP_MSIQ			0x3
#define	OP_PCIEMSG		0x4
#define	OP_FIXED		0x5
#define	OP_UNKNOWN		0xe

/* Op definitions for PORT */
#define	OP_RESERVED		0x0
#define	OP_PIO			0x1
#define	OP_DMA			0x2
#define	OP_LINK			0x3
#define	OP_UNKNOWN		0xe

/* Phase definitons */
#define	PH_RESERVED		0x0
#define	PH_ADDR			0x1
#define	PH_DATA			0x2
#define	PH_UNKNOWN		0xe
#define	PH_IRR			0xf

/* Phase definitions for PORT/Link */
#define	PH_FC			0x1


/* Condition definitions for any major Block/Op/Phase */
#define	CND_RESERVED		0x0
#define	CND_ILL			0x1
#define	CND_UNMAP		0x2
#define	CND_INT			0x3
#define	CND_UE			0x4
#define	CND_INV			0x6
#define	CND_UNKNOWN		0xe
#define	CND_IRR			0xf

/* Additional condition definitions for INTR Block MSIQ phase */
#define	CND_OV			0x5

/* Additional condition definitions for MMU|INTR Block ADDR phase */
#define	CND_PROT		0x5

/* Additional condition definitions for DATA phase */
#define	CND_TO			0x5

/* Additional condition definitions for Port Link phase */
#define	CND_RCA			0x7
#define	CND_RUR			0x8
#define	CND_UC			0x9

/* Dir definitions for HOSTBUS & MMU */
#define	DIR_RESERVED		0x0
#define	DIR_READ		0x1
#define	DIR_WRITE		0x2
#define	DIR_RDWR		0x3
#define	DIR_INGRESS		0x4
#define	DIR_EGRESS		0x5
#define	DIR_LINK		0x6
#define	DIR_UNKNOWN		0xe
#define	DIR_IRR			0xf

#define	PX_FM_RC_UNRECOG	"fire.epkt"
#define	EPKT_SYSINO		"sysino"
#define	EPKT_EHDL		"ehdl"
#define	EPKT_STICK		"stick"
#define	EPKT_DW0		"dw0"
#define	EPKT_DW1		"dw1"
#define	EPKT_DW2		"dw2"
#define	EPKT_DW3		"dw3"
#define	EPKT_DW4		"dw4"
#define	EPKT_RC_DESCR		"rc_descr"
#define	EPKT_PEC_DESCR		"pec_descr"

#ifndef _ESC
typedef struct root_complex {
	uint64_t  sysino;
	uint64_t  ehdl;
	uint64_t  stick;
	struct  {
#if defined(_BIT_FIELDS_LTOH)
		uint32_t S	: 1,	/* Also the "Q" flag */
			M	: 1,
			D	: 1,
			R	: 1,
			H	: 1,
			C	: 1,
			I	: 1,
			B	: 1,
				: 3,
			STOP	: 1,
			dir	: 4,
			cond	: 4,
			phase	: 4,
			op	: 4,
			block	: 4;
#elif defined(_BIT_FIELDS_HTOL)
		uint32_t block	: 4,
			op	: 4,
			phase	: 4,
			cond	: 4,
			dir	: 4,
			STOP	: 1,
				: 3,
			B	: 1,
			I	: 1,
			C	: 1,
			H	: 1,
			R	: 1,
			D	: 1,
			M	: 1,
			S	: 1;	/* Also the "Q" flag */
#else
#error "bit field not defined"
#endif
	} rc_descr;
	uint32_t  size;			/* Also the EQ Num */
	uint64_t  addr;
	uint64_t  hdr[2];
	uint64_t  reserved;		/* Contains Port */
} px_rc_err_t;

typedef struct pec_block_err {
	uint64_t  sysino;
	uint64_t  ehdl;
	uint64_t  stick;
	struct  {
		uint32_t block	: 4,
			rsvd1	: 12,
			dir	: 4,
				: 3,
			Z	: 1,
			S	: 1,
			R	: 1,
			I	: 1,
			H	: 1,
			C	: 1,
			U	: 1,
			E	: 1,
			P	: 1;
	} pec_descr;
	uint16_t  pci_err_status;
	uint16_t  pcie_err_status;
	uint32_t  ce_reg_status;
	uint32_t  ue_reg_status;
	uint64_t  hdr[2];
	uint32_t  err_src_reg;
	uint32_t  root_err_status;
} px_pec_err_t;
#endif	/* _ESC */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PX_ERR_H */
