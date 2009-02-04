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
 * Copyright 2008 NetXen, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _UNM_INC_H_
#define	_UNM_INC_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "nx_errorcode.h"

#define	PREALIGN(x)
#define	POSTALIGN(x)

typedef char					__int8_t;
typedef short					__int16_t;
typedef int						__int32_t;
typedef long long				__int64_t;
typedef unsigned char			__uint8_t;
typedef unsigned short			__uint16_t;
typedef unsigned int			__uint32_t;
typedef unsigned long long		__uint64_t;
typedef __uint64_t				jiffies_t;

typedef uint8_t			u8;
typedef uint8_t			U8;
typedef uint16_t		U16;
typedef uint32_t		u32;
typedef uint32_t		U32;
typedef unsigned long long	u64;
typedef unsigned long long	U64;

#define	UNUSED __attribute__((unused))
#define	NOINLINE __attribute__((noinline))

#include "nx_hw_pci_regs.h"

#define	UNM_CONF_X86		3

#define	bzero(A, B)			memset((A), 0, (B))

/*
 * MAX_RCV_CTX : The number of receive contexts that are available on
 * the phantom.
 */
#define	MAX_RCV_CTX			1

/* ------------------------------------------------------------------------ */
/*  CRB Hub and Agent addressing */
/* ------------------------------------------------------------------------ */
/*
 *  WARNING:  pex_tgt_adr.v assumes if MSB of hub adr is set then it is an
 *  ILLEGAL hub!!!!!
 */
#define	UNM_HW_H0_CH_HUB_ADR    0x05
#define	UNM_HW_H1_CH_HUB_ADR    0x0E
#define	UNM_HW_H2_CH_HUB_ADR    0x03
#define	UNM_HW_H3_CH_HUB_ADR    0x01
#define	UNM_HW_H4_CH_HUB_ADR    0x06
#define	UNM_HW_H5_CH_HUB_ADR    0x07
#define	UNM_HW_H6_CH_HUB_ADR    0x08
/*
 * WARNING:  pex_tgt_adr.v assumes if MSB of hub adr is set then it is an
 * ILLEGAL hub!!!!!
 */

/*  Hub 0 */
#define	UNM_HW_MN_CRB_AGT_ADR   0x15
#define	UNM_HW_MS_CRB_AGT_ADR   0x25

/*  Hub 1 */
#define	UNM_HW_PS_CRB_AGT_ADR		0x73
#define	UNM_HW_SS_CRB_AGT_ADR		0x20
#define	UNM_HW_RPMX3_CRB_AGT_ADR	0x0b
#define	UNM_HW_QMS_CRB_AGT_ADR		0x00
#define	UNM_HW_SQGS0_CRB_AGT_ADR	0x01
#define	UNM_HW_SQGS1_CRB_AGT_ADR	0x02
#define	UNM_HW_SQGS2_CRB_AGT_ADR	0x03
#define	UNM_HW_SQGS3_CRB_AGT_ADR	0x04
#define	UNM_HW_C2C0_CRB_AGT_ADR		0x58
#define	UNM_HW_C2C1_CRB_AGT_ADR		0x59
#define	UNM_HW_C2C2_CRB_AGT_ADR		0x5a
#define	UNM_HW_RPMX2_CRB_AGT_ADR	0x0a
#define	UNM_HW_RPMX4_CRB_AGT_ADR	0x0c
#define	UNM_HW_RPMX7_CRB_AGT_ADR	0x0f
#define	UNM_HW_RPMX9_CRB_AGT_ADR	0x12
#define	UNM_HW_SMB_CRB_AGT_ADR		0x18

/*  Hub 2 */
#define	UNM_HW_NIU_CRB_AGT_ADR		0x31
#define	UNM_HW_I2C0_CRB_AGT_ADR		0x19
#define	UNM_HW_I2C1_CRB_AGT_ADR		0x29

#define	UNM_HW_SN_CRB_AGT_ADR		0x10
#define	UNM_HW_I2Q_CRB_AGT_ADR		0x20
#define	UNM_HW_LPC_CRB_AGT_ADR		0x22
#define	UNM_HW_ROMUSB_CRB_AGT_ADR	0x21
#define	UNM_HW_QM_CRB_AGT_ADR		0x66
#define	UNM_HW_SQG0_CRB_AGT_ADR		0x60
#define	UNM_HW_SQG1_CRB_AGT_ADR		0x61
#define	UNM_HW_SQG2_CRB_AGT_ADR		0x62
#define	UNM_HW_SQG3_CRB_AGT_ADR		0x63
#define	UNM_HW_RPMX1_CRB_AGT_ADR	0x09
#define	UNM_HW_RPMX5_CRB_AGT_ADR	0x0d
#define	UNM_HW_RPMX6_CRB_AGT_ADR	0x0e
#define	UNM_HW_RPMX8_CRB_AGT_ADR	0x11

/*  Hub 3 */
#define	UNM_HW_PH_CRB_AGT_ADR		0x1A
#define	UNM_HW_SRE_CRB_AGT_ADR		0x50
#define	UNM_HW_EG_CRB_AGT_ADR		0x51
#define	UNM_HW_RPMX0_CRB_AGT_ADR	0x08

/*  Hub 4 */
#define	UNM_HW_PEGN0_CRB_AGT_ADR		0x40
#define	UNM_HW_PEGN1_CRB_AGT_ADR		0x41
#define	UNM_HW_PEGN2_CRB_AGT_ADR		0x42
#define	UNM_HW_PEGN3_CRB_AGT_ADR		0x43
#define	UNM_HW_PEGNI_CRB_AGT_ADR		0x44
#define	UNM_HW_PEGND_CRB_AGT_ADR		0x45
#define	UNM_HW_PEGNC_CRB_AGT_ADR		0x46
#define	UNM_HW_PEGR0_CRB_AGT_ADR		0x47
#define	UNM_HW_PEGR1_CRB_AGT_ADR		0x48
#define	UNM_HW_PEGR2_CRB_AGT_ADR		0x49
#define	UNM_HW_PEGR3_CRB_AGT_ADR		0x4a
#define	UNM_HW_PEGN4_CRB_AGT_ADR		0x4b

/*  Hub 5 */
#define	UNM_HW_PEGS0_CRB_AGT_ADR		0x40
#define	UNM_HW_PEGS1_CRB_AGT_ADR		0x41
#define	UNM_HW_PEGS2_CRB_AGT_ADR		0x42
#define	UNM_HW_PEGS3_CRB_AGT_ADR		0x43
#define	UNM_HW_PEGSI_CRB_AGT_ADR		0x44
#define	UNM_HW_PEGSD_CRB_AGT_ADR		0x45
#define	UNM_HW_PEGSC_CRB_AGT_ADR		0x46

/*  Hub 6 */
#define	UNM_HW_CAS0_CRB_AGT_ADR 0x46
#define	UNM_HW_CAS1_CRB_AGT_ADR 0x47
#define	UNM_HW_CAS2_CRB_AGT_ADR 0x48
#define	UNM_HW_CAS3_CRB_AGT_ADR 0x49
#define	UNM_HW_NCM_CRB_AGT_ADR  0x16
#define	UNM_HW_TMR_CRB_AGT_ADR  0x17
#define	UNM_HW_XDMA_CRB_AGT_ADR 0x05
#define	UNM_HW_OCM0_CRB_AGT_ADR 0x06
#define	UNM_HW_OCM1_CRB_AGT_ADR 0x07

/*  This field defines PCI/X adr [25:20] of agents on the CRB */
/*  */
#define	UNM_HW_PX_MAP_CRB_PH    0
#define	UNM_HW_PX_MAP_CRB_PS    1
#define	UNM_HW_PX_MAP_CRB_MN    2
#define	UNM_HW_PX_MAP_CRB_MS    3
#define	UNM_HW_PX_MAP_CRB_SRE   5
#define	UNM_HW_PX_MAP_CRB_NIU   6
#define	UNM_HW_PX_MAP_CRB_QMN   7
#define	UNM_HW_PX_MAP_CRB_SQN0  8
#define	UNM_HW_PX_MAP_CRB_SQN1  9
#define	UNM_HW_PX_MAP_CRB_SQN2  10
#define	UNM_HW_PX_MAP_CRB_SQN3  11
#define	UNM_HW_PX_MAP_CRB_QMS   12
#define	UNM_HW_PX_MAP_CRB_SQS0  13
#define	UNM_HW_PX_MAP_CRB_SQS1  14
#define	UNM_HW_PX_MAP_CRB_SQS2  15
#define	UNM_HW_PX_MAP_CRB_SQS3  16
#define	UNM_HW_PX_MAP_CRB_PGN0  17
#define	UNM_HW_PX_MAP_CRB_PGN1  18
#define	UNM_HW_PX_MAP_CRB_PGN2  19
#define	UNM_HW_PX_MAP_CRB_PGN3  20
#define	UNM_HW_PX_MAP_CRB_PGND  21
#define	UNM_HW_PX_MAP_CRB_PGNI  22
#define	UNM_HW_PX_MAP_CRB_PGS0  23
#define	UNM_HW_PX_MAP_CRB_PGS1  24
#define	UNM_HW_PX_MAP_CRB_PGS2  25
#define	UNM_HW_PX_MAP_CRB_PGS3  26
#define	UNM_HW_PX_MAP_CRB_PGSD  27
#define	UNM_HW_PX_MAP_CRB_PGSI  28
#define	UNM_HW_PX_MAP_CRB_SN    29
#define	UNM_HW_PX_MAP_CRB_EG	31
#define	UNM_HW_PX_MAP_CRB_PH2   32
#define	UNM_HW_PX_MAP_CRB_PS2   33
#define	UNM_HW_PX_MAP_CRB_CAM   34
#define	UNM_HW_PX_MAP_CRB_CAS0  35
#define	UNM_HW_PX_MAP_CRB_CAS1  36
#define	UNM_HW_PX_MAP_CRB_CAS2  37
#define	UNM_HW_PX_MAP_CRB_C2C0  38
#define	UNM_HW_PX_MAP_CRB_C2C1  39
#define	UNM_HW_PX_MAP_CRB_TIMR  40
/* N/A: Not use in either Phantom1 or Phantom2 => use for TIMR */
/* #define	PX_MAP_CRB_C2C2		40 */
/* #define	PX_MAP_CRB_SS		41 */
#define	UNM_HW_PX_MAP_CRB_RPMX1 42
#define	UNM_HW_PX_MAP_CRB_RPMX2 43
#define	UNM_HW_PX_MAP_CRB_RPMX3 44
#define	UNM_HW_PX_MAP_CRB_RPMX4 45
#define	UNM_HW_PX_MAP_CRB_RPMX5 46
#define	UNM_HW_PX_MAP_CRB_RPMX6 47
#define	UNM_HW_PX_MAP_CRB_RPMX7 48
#define	UNM_HW_PX_MAP_CRB_XDMA  49
#define	UNM_HW_PX_MAP_CRB_I2Q   50
#define	UNM_HW_PX_MAP_CRB_ROMUSB	51
#define	UNM_HW_PX_MAP_CRB_CAS3  52
#define	UNM_HW_PX_MAP_CRB_RPMX0 53
#define	UNM_HW_PX_MAP_CRB_RPMX8 54
#define	UNM_HW_PX_MAP_CRB_RPMX9 55
#define	UNM_HW_PX_MAP_CRB_OCM0  56
#define	UNM_HW_PX_MAP_CRB_OCM1  57
#define	UNM_HW_PX_MAP_CRB_SMB   58
#define	UNM_HW_PX_MAP_CRB_I2C0  59
#define	UNM_HW_PX_MAP_CRB_I2C1  60
#define	UNM_HW_PX_MAP_CRB_LPC   61
#define	UNM_HW_PX_MAP_CRB_PGNC  62
#define	UNM_HW_PX_MAP_CRB_PGR0  63
#define	UNM_HW_PX_MAP_CRB_PGR1  4
#define	UNM_HW_PX_MAP_CRB_PGR2  30
#define	UNM_HW_PX_MAP_CRB_PGR3  41

/*  This field defines CRB adr [31:20] of the agents */
/*  */

#define	UNM_HW_CRB_HUB_AGT_ADR_MN	((UNM_HW_H0_CH_HUB_ADR << 7)	\
		| UNM_HW_MN_CRB_AGT_ADR)
#define	UNM_HW_CRB_HUB_AGT_ADR_PH	((UNM_HW_H0_CH_HUB_ADR << 7)	\
		| UNM_HW_PH_CRB_AGT_ADR)
#define	UNM_HW_CRB_HUB_AGT_ADR_MS	((UNM_HW_H0_CH_HUB_ADR << 7)	\
		| UNM_HW_MS_CRB_AGT_ADR)

#define	UNM_HW_CRB_HUB_AGT_ADR_PS	((UNM_HW_H1_CH_HUB_ADR << 7)	\
		| UNM_HW_PS_CRB_AGT_ADR)
#define	UNM_HW_CRB_HUB_AGT_ADR_SS	((UNM_HW_H1_CH_HUB_ADR << 7)	\
		| UNM_HW_SS_CRB_AGT_ADR)
#define	UNM_HW_CRB_HUB_AGT_ADR_RPMX3	((UNM_HW_H1_CH_HUB_ADR << 7)	\
		| UNM_HW_RPMX3_CRB_AGT_ADR)
#define	UNM_HW_CRB_HUB_AGT_ADR_QMS	((UNM_HW_H1_CH_HUB_ADR << 7)	\
		| UNM_HW_QMS_CRB_AGT_ADR)
#define	UNM_HW_CRB_HUB_AGT_ADR_SQS0	((UNM_HW_H1_CH_HUB_ADR << 7)	\
		| UNM_HW_SQGS0_CRB_AGT_ADR)
#define	UNM_HW_CRB_HUB_AGT_ADR_SQS1	((UNM_HW_H1_CH_HUB_ADR << 7)	\
		| UNM_HW_SQGS1_CRB_AGT_ADR)
#define	UNM_HW_CRB_HUB_AGT_ADR_SQS2	((UNM_HW_H1_CH_HUB_ADR << 7)	\
		| UNM_HW_SQGS2_CRB_AGT_ADR)
#define	UNM_HW_CRB_HUB_AGT_ADR_SQS3	((UNM_HW_H1_CH_HUB_ADR << 7)	\
		| UNM_HW_SQGS3_CRB_AGT_ADR)
#define	UNM_HW_CRB_HUB_AGT_ADR_C2C0	((UNM_HW_H1_CH_HUB_ADR << 7)	\
		| UNM_HW_C2C0_CRB_AGT_ADR)
#define	UNM_HW_CRB_HUB_AGT_ADR_C2C1	((UNM_HW_H1_CH_HUB_ADR << 7)	\
		| UNM_HW_C2C1_CRB_AGT_ADR)
#define	UNM_HW_CRB_HUB_AGT_ADR_RPMX2	((UNM_HW_H1_CH_HUB_ADR << 7)	\
		| UNM_HW_RPMX2_CRB_AGT_ADR)
#define	UNM_HW_CRB_HUB_AGT_ADR_RPMX4	((UNM_HW_H1_CH_HUB_ADR << 7)	\
		| UNM_HW_RPMX4_CRB_AGT_ADR)
#define	UNM_HW_CRB_HUB_AGT_ADR_RPMX7	((UNM_HW_H1_CH_HUB_ADR << 7)	\
		| UNM_HW_RPMX7_CRB_AGT_ADR)
#define	UNM_HW_CRB_HUB_AGT_ADR_RPMX9	((UNM_HW_H1_CH_HUB_ADR << 7)	\
		| UNM_HW_RPMX9_CRB_AGT_ADR)
#define	UNM_HW_CRB_HUB_AGT_ADR_SMB	((UNM_HW_H1_CH_HUB_ADR << 7)	\
		| UNM_HW_SMB_CRB_AGT_ADR)

#define	UNM_HW_CRB_HUB_AGT_ADR_NIU	((UNM_HW_H2_CH_HUB_ADR << 7)	\
		| UNM_HW_NIU_CRB_AGT_ADR)
#define	UNM_HW_CRB_HUB_AGT_ADR_I2C0	((UNM_HW_H2_CH_HUB_ADR << 7)	\
		| UNM_HW_I2C0_CRB_AGT_ADR)
#define	UNM_HW_CRB_HUB_AGT_ADR_I2C1	((UNM_HW_H2_CH_HUB_ADR << 7)	\
		| UNM_HW_I2C1_CRB_AGT_ADR)

#define	UNM_HW_CRB_HUB_AGT_ADR_SRE	((UNM_HW_H3_CH_HUB_ADR << 7)	\
		| UNM_HW_SRE_CRB_AGT_ADR)
#define	UNM_HW_CRB_HUB_AGT_ADR_EG	((UNM_HW_H3_CH_HUB_ADR << 7)	\
		| UNM_HW_EG_CRB_AGT_ADR)
#define	UNM_HW_CRB_HUB_AGT_ADR_RPMX0	((UNM_HW_H3_CH_HUB_ADR << 7)	\
		| UNM_HW_RPMX0_CRB_AGT_ADR)
#define	UNM_HW_CRB_HUB_AGT_ADR_QMN	((UNM_HW_H3_CH_HUB_ADR << 7)	\
		| UNM_HW_QM_CRB_AGT_ADR)
#define	UNM_HW_CRB_HUB_AGT_ADR_SQN0	((UNM_HW_H3_CH_HUB_ADR << 7)	\
		| UNM_HW_SQG0_CRB_AGT_ADR)
#define	UNM_HW_CRB_HUB_AGT_ADR_SQN1	((UNM_HW_H3_CH_HUB_ADR << 7)	\
		| UNM_HW_SQG1_CRB_AGT_ADR)
#define	UNM_HW_CRB_HUB_AGT_ADR_SQN2	((UNM_HW_H3_CH_HUB_ADR << 7)	\
		| UNM_HW_SQG2_CRB_AGT_ADR)
#define	UNM_HW_CRB_HUB_AGT_ADR_SQN3	((UNM_HW_H3_CH_HUB_ADR << 7)	\
		| UNM_HW_SQG3_CRB_AGT_ADR)
#define	UNM_HW_CRB_HUB_AGT_ADR_RPMX1	((UNM_HW_H3_CH_HUB_ADR << 7)	\
		| UNM_HW_RPMX1_CRB_AGT_ADR)
#define	UNM_HW_CRB_HUB_AGT_ADR_RPMX5	((UNM_HW_H3_CH_HUB_ADR << 7)	\
		| UNM_HW_RPMX5_CRB_AGT_ADR)
#define	UNM_HW_CRB_HUB_AGT_ADR_RPMX6	((UNM_HW_H3_CH_HUB_ADR << 7)	\
		| UNM_HW_RPMX6_CRB_AGT_ADR)
#define	UNM_HW_CRB_HUB_AGT_ADR_RPMX8	((UNM_HW_H3_CH_HUB_ADR << 7)	\
		| UNM_HW_RPMX8_CRB_AGT_ADR)
#define	UNM_HW_CRB_HUB_AGT_ADR_CAS0	((UNM_HW_H3_CH_HUB_ADR << 7)	\
		| UNM_HW_CAS0_CRB_AGT_ADR)
#define	UNM_HW_CRB_HUB_AGT_ADR_CAS1	((UNM_HW_H3_CH_HUB_ADR << 7)	\
		| UNM_HW_CAS1_CRB_AGT_ADR)
#define	UNM_HW_CRB_HUB_AGT_ADR_CAS2	((UNM_HW_H3_CH_HUB_ADR << 7)	\
		| UNM_HW_CAS2_CRB_AGT_ADR)
#define	UNM_HW_CRB_HUB_AGT_ADR_CAS3	((UNM_HW_H3_CH_HUB_ADR << 7)	\
		| UNM_HW_CAS3_CRB_AGT_ADR)

#define	UNM_HW_CRB_HUB_AGT_ADR_PGNI	((UNM_HW_H4_CH_HUB_ADR << 7)	\
		| UNM_HW_PEGNI_CRB_AGT_ADR)
#define	UNM_HW_CRB_HUB_AGT_ADR_PGND	((UNM_HW_H4_CH_HUB_ADR << 7)	\
		| UNM_HW_PEGND_CRB_AGT_ADR)
#define	UNM_HW_CRB_HUB_AGT_ADR_PGN0	((UNM_HW_H4_CH_HUB_ADR << 7)	\
		| UNM_HW_PEGN0_CRB_AGT_ADR)
#define	UNM_HW_CRB_HUB_AGT_ADR_PGN1	((UNM_HW_H4_CH_HUB_ADR << 7)	\
		| UNM_HW_PEGN1_CRB_AGT_ADR)
#define	UNM_HW_CRB_HUB_AGT_ADR_PGN2	((UNM_HW_H4_CH_HUB_ADR << 7)	\
		| UNM_HW_PEGN2_CRB_AGT_ADR)
#define	UNM_HW_CRB_HUB_AGT_ADR_PGN3	((UNM_HW_H4_CH_HUB_ADR << 7)	\
		| UNM_HW_PEGN3_CRB_AGT_ADR)
#define	UNM_HW_CRB_HUB_AGT_ADR_PGN4	((UNM_HW_H4_CH_HUB_ADR << 7)	\
		| UNM_HW_PEGN4_CRB_AGT_ADR)

#define	UNM_HW_CRB_HUB_AGT_ADR_PGNC	((UNM_HW_H4_CH_HUB_ADR << 7)	\
		| UNM_HW_PEGNC_CRB_AGT_ADR)
#define	UNM_HW_CRB_HUB_AGT_ADR_PGR0	((UNM_HW_H4_CH_HUB_ADR << 7)	\
		| UNM_HW_PEGR0_CRB_AGT_ADR)
#define	UNM_HW_CRB_HUB_AGT_ADR_PGR1	((UNM_HW_H4_CH_HUB_ADR << 7)	\
		| UNM_HW_PEGR1_CRB_AGT_ADR)
#define	UNM_HW_CRB_HUB_AGT_ADR_PGR2	((UNM_HW_H4_CH_HUB_ADR << 7)	\
	| UNM_HW_PEGR2_CRB_AGT_ADR)
#define	UNM_HW_CRB_HUB_AGT_ADR_PGR3	((UNM_HW_H4_CH_HUB_ADR << 7)	\
		| UNM_HW_PEGR3_CRB_AGT_ADR)

#define	UNM_HW_CRB_HUB_AGT_ADR_PGSI	((UNM_HW_H5_CH_HUB_ADR << 7)	\
		| UNM_HW_PEGSI_CRB_AGT_ADR)
#define	UNM_HW_CRB_HUB_AGT_ADR_PGSD	((UNM_HW_H5_CH_HUB_ADR << 7)	\
		| UNM_HW_PEGSD_CRB_AGT_ADR)
#define	UNM_HW_CRB_HUB_AGT_ADR_PGS0	((UNM_HW_H5_CH_HUB_ADR << 7)	\
		| UNM_HW_PEGS0_CRB_AGT_ADR)
#define	UNM_HW_CRB_HUB_AGT_ADR_PGS1	((UNM_HW_H5_CH_HUB_ADR << 7)	\
		| UNM_HW_PEGS1_CRB_AGT_ADR)
#define	UNM_HW_CRB_HUB_AGT_ADR_PGS2	((UNM_HW_H5_CH_HUB_ADR << 7)	\
		| UNM_HW_PEGS2_CRB_AGT_ADR)
#define	UNM_HW_CRB_HUB_AGT_ADR_PGS3	((UNM_HW_H5_CH_HUB_ADR << 7)	\
		| UNM_HW_PEGS3_CRB_AGT_ADR)
#define	UNM_HW_CRB_HUB_AGT_ADR_PGSC	((UNM_HW_H5_CH_HUB_ADR << 7)	\
		| UNM_HW_PEGSC_CRB_AGT_ADR)

#define	UNM_HW_CRB_HUB_AGT_ADR_CAM	((UNM_HW_H6_CH_HUB_ADR << 7)	\
		| UNM_HW_NCM_CRB_AGT_ADR)
#define	UNM_HW_CRB_HUB_AGT_ADR_TIMR	((UNM_HW_H6_CH_HUB_ADR << 7)	\
		| UNM_HW_TMR_CRB_AGT_ADR)
#define	UNM_HW_CRB_HUB_AGT_ADR_XDMA	((UNM_HW_H6_CH_HUB_ADR << 7)	\
		| UNM_HW_XDMA_CRB_AGT_ADR)
#define	UNM_HW_CRB_HUB_AGT_ADR_SN	((UNM_HW_H6_CH_HUB_ADR << 7)	\
	| UNM_HW_SN_CRB_AGT_ADR)
#define	UNM_HW_CRB_HUB_AGT_ADR_I2Q	((UNM_HW_H6_CH_HUB_ADR << 7)	\
		| UNM_HW_I2Q_CRB_AGT_ADR)
#define	UNM_HW_CRB_HUB_AGT_ADR_ROMUSB	((UNM_HW_H6_CH_HUB_ADR << 7)	\
		| UNM_HW_ROMUSB_CRB_AGT_ADR)
#define	UNM_HW_CRB_HUB_AGT_ADR_OCM0	((UNM_HW_H6_CH_HUB_ADR << 7)	\
		| UNM_HW_OCM0_CRB_AGT_ADR)
#define	UNM_HW_CRB_HUB_AGT_ADR_OCM1	((UNM_HW_H6_CH_HUB_ADR << 7)	\
		| UNM_HW_OCM1_CRB_AGT_ADR)
#define	UNM_HW_CRB_HUB_AGT_ADR_LPC	((UNM_HW_H6_CH_HUB_ADR << 7)	\
		| UNM_HW_LPC_CRB_AGT_ADR)

/*
 * ROM USB CRB space is divided into 4 regions depending on decode of
 * address bits [19:16]
 */
#define	ROMUSB_GLB			(UNM_CRB_ROMUSB + 0x00000)
#define	ROMUSB_ROM			(UNM_CRB_ROMUSB + 0x10000)
#define	ROMUSB_USB			(UNM_CRB_ROMUSB + 0x20000)
#define	ROMUSB_DIRECT_ROM	(UNM_CRB_ROMUSB + 0x30000)
#define	ROMUSB_TAP			(UNM_CRB_ROMUSB + 0x40000)

/*  ROMUSB  GLB register definitions */
#define	UNM_ROMUSB_GLB_CONTROL		(ROMUSB_GLB + 0x0000)
#define	UNM_ROMUSB_GLB_STATUS		(ROMUSB_GLB + 0x0004)
#define	UNM_ROMUSB_GLB_SW_RESET		(ROMUSB_GLB + 0x0008)
#define	UNM_ROMUSB_GLB_PAD_GPIO_I	(ROMUSB_GLB + 0x000c)
#define	UNM_ROMUSB_GLB_RNG_PLL_CTL	(ROMUSB_GLB + 0x0010)
#define	UNM_ROMUSB_GLB_TEST_MUX_O	(ROMUSB_GLB + 0x0014)
#define	UNM_ROMUSB_GLB_PLL0_CTRL	(ROMUSB_GLB + 0x0018)
#define	UNM_ROMUSB_GLB_PLL1_CTRL	(ROMUSB_GLB + 0x001c)
#define	UNM_ROMUSB_GLB_PLL2_CTRL	(ROMUSB_GLB + 0x0020)
#define	UNM_ROMUSB_GLB_PLL3_CTRL	(ROMUSB_GLB + 0x0024)
#define	UNM_ROMUSB_GLB_PLL_LOCK		(ROMUSB_GLB + 0x0028)
#define	UNM_ROMUSB_GLB_EXTERN_INT	(ROMUSB_GLB + 0x002c)
#define	UNM_ROMUSB_GLB_PH_RST		(ROMUSB_GLB + 0x0030)
#define	UNM_ROMUSB_GLB_PS_RST		(ROMUSB_GLB + 0x0034)
#define	UNM_ROMUSB_GLB_CAS_RST		(ROMUSB_GLB + 0x0038)
#define	UNM_ROMUSB_GLB_MIU_RST		(ROMUSB_GLB + 0x003c)
#define	UNM_ROMUSB_GLB_CRB_RST		(ROMUSB_GLB + 0x0040)
#define	UNM_ROMUSB_GLB_TEST_MUX_SEL	(ROMUSB_GLB + 0x0044)
#define	UNM_ROMUSB_GLB_MN_COM_A2T	(ROMUSB_GLB + 0x0050)
#define	UNM_ROMUSB_GLB_REV_ID		(ROMUSB_GLB + 0x0054)
#define	UNM_ROMUSB_GLB_PEGTUNE_DONE	(ROMUSB_GLB + 0x005c)
#define	UNM_ROMUSB_GLB_VENDOR_DEV_ID	(ROMUSB_GLB + 0x0058)
#define	UNM_ROMUSB_GLB_CHIP_CLK_CTRL	(ROMUSB_GLB + 0x00a8)

#define	UNM_ROMUSB_GPIO(n) ((n) <= 15 ? (ROMUSB_GLB + 0x60 + (4 * (n))): \
				((n) <= 18)?(ROMUSB_GLB + 0x70 + (4 * (n))): \
				(ROMUSB_GLB + 0x70 + (4 * (19))))

#define	UNM_ROMUSB_ROM_CONTROL			(ROMUSB_ROM + 0x0000)
#define	UNM_ROMUSB_ROM_INSTR_OPCODE		(ROMUSB_ROM + 0x0004)
#define	UNM_ROMUSB_ROM_ADDRESS			(ROMUSB_ROM + 0x0008)
#define	UNM_ROMUSB_ROM_WDATA			(ROMUSB_ROM + 0x000c)
#define	UNM_ROMUSB_ROM_ABYTE_CNT		(ROMUSB_ROM + 0x0010)
#define	UNM_ROMUSB_ROM_DUMMY_BYTE_CNT	(ROMUSB_ROM + 0x0014)
#define	UNM_ROMUSB_ROM_RDATA			(ROMUSB_ROM + 0x0018)
#define	UNM_ROMUSB_ROM_AGT_TAG			(ROMUSB_ROM + 0x001c)
#define	UNM_ROMUSB_ROM_TIME_PARM		(ROMUSB_ROM + 0x0020)
#define	UNM_ROMUSB_ROM_CLK_DIV			(ROMUSB_ROM + 0x0024)
#define	UNM_ROMUSB_ROM_MISS_INSTR		(ROMUSB_ROM + 0x0028)

/* Lock IDs for ROM lock */
#define	ROM_LOCK_DRIVER					0x0d417340

/* Lock IDs for PHY lock */
#define	PHY_LOCK_DRIVER					0x44524956

#define	UNM_PCI_CRB_WINDOWSIZE    0x00100000    /* all are 1MB windows */
#define	UNM_PCI_CRB_WINDOW(A)    (UNM_PCI_CRBSPACE + (A)*UNM_PCI_CRB_WINDOWSIZE)
#define	UNM_CRB_C2C_0		UNM_PCI_CRB_WINDOW(UNM_HW_PX_MAP_CRB_C2C0)
#define	UNM_CRB_C2C_1		UNM_PCI_CRB_WINDOW(UNM_HW_PX_MAP_CRB_C2C1)
#define	UNM_CRB_C2C_2		UNM_PCI_CRB_WINDOW(UNM_HW_PX_MAP_CRB_C2C2)
#define	UNM_CRB_CAM		UNM_PCI_CRB_WINDOW(UNM_HW_PX_MAP_CRB_CAM)
#define	UNM_CRB_CASPER		UNM_PCI_CRB_WINDOW(UNM_HW_PX_MAP_CRB_CAS)
#define	UNM_CRB_CASPER_0	UNM_PCI_CRB_WINDOW(UNM_HW_PX_MAP_CRB_CAS0)
#define	UNM_CRB_CASPER_1	UNM_PCI_CRB_WINDOW(UNM_HW_PX_MAP_CRB_CAS1)
#define	UNM_CRB_CASPER_2	UNM_PCI_CRB_WINDOW(UNM_HW_PX_MAP_CRB_CAS2)
#define	UNM_CRB_DDR_MD		UNM_PCI_CRB_WINDOW(UNM_HW_PX_MAP_CRB_MS)
#define	UNM_CRB_DDR_NET		UNM_PCI_CRB_WINDOW(UNM_HW_PX_MAP_CRB_MN)
#define	UNM_CRB_EPG			UNM_PCI_CRB_WINDOW(UNM_HW_PX_MAP_CRB_EG)
#define	UNM_CRB_I2Q		UNM_PCI_CRB_WINDOW(UNM_HW_PX_MAP_CRB_I2Q)
#define	UNM_CRB_NIU		UNM_PCI_CRB_WINDOW(UNM_HW_PX_MAP_CRB_NIU)
/* HACK upon HACK upon HACK (for PCIE builds) */
#define	UNM_CRB_PCIX_HOST	UNM_PCI_CRB_WINDOW(UNM_HW_PX_MAP_CRB_PH)
#define	UNM_CRB_PCIX_HOST2	UNM_PCI_CRB_WINDOW(UNM_HW_PX_MAP_CRB_PH2)
#define	UNM_CRB_PCIX_MD		UNM_PCI_CRB_WINDOW(UNM_HW_PX_MAP_CRB_PS)
#define	UNM_CRB_PCIE		UNM_CRB_PCIX_MD
// window 1 pcie slot
#define	UNM_CRB_PCIE2		UNM_PCI_CRB_WINDOW(UNM_HW_PX_MAP_CRB_PS2)

#define	UNM_CRB_PEG_MD_0   UNM_PCI_CRB_WINDOW(UNM_HW_PX_MAP_CRB_PGS0)
#define	UNM_CRB_PEG_MD_1   UNM_PCI_CRB_WINDOW(UNM_HW_PX_MAP_CRB_PGS1)
#define	UNM_CRB_PEG_MD_2   UNM_PCI_CRB_WINDOW(UNM_HW_PX_MAP_CRB_PGS2)
#define	UNM_CRB_PEG_MD_3   UNM_PCI_CRB_WINDOW(UNM_HW_PX_MAP_CRB_PGS3)
#define	UNM_CRB_PEG_MD_D   UNM_PCI_CRB_WINDOW(UNM_HW_PX_MAP_CRB_PGSD)
#define	UNM_CRB_PEG_MD_I   UNM_PCI_CRB_WINDOW(UNM_HW_PX_MAP_CRB_PGSI)
#define	UNM_CRB_PEG_NET_0  UNM_PCI_CRB_WINDOW(UNM_HW_PX_MAP_CRB_PGN0)
#define	UNM_CRB_PEG_NET_1  UNM_PCI_CRB_WINDOW(UNM_HW_PX_MAP_CRB_PGN1)
#define	UNM_CRB_PEG_NET_2  UNM_PCI_CRB_WINDOW(UNM_HW_PX_MAP_CRB_PGN2)
#define	UNM_CRB_PEG_NET_3  UNM_PCI_CRB_WINDOW(UNM_HW_PX_MAP_CRB_PGN3)
#define	UNM_CRB_PEG_NET_D  UNM_PCI_CRB_WINDOW(UNM_HW_PX_MAP_CRB_PGND)
#define	UNM_CRB_PEG_NET_I  UNM_PCI_CRB_WINDOW(UNM_HW_PX_MAP_CRB_PGNI)
#define	UNM_CRB_PQM_MD		UNM_PCI_CRB_WINDOW(UNM_HW_PX_MAP_CRB_QMS)
#define	UNM_CRB_PQM_NET		UNM_PCI_CRB_WINDOW(UNM_HW_PX_MAP_CRB_QMN)
#define	UNM_CRB_QDR_MD		UNM_PCI_CRB_WINDOW(UNM_HW_PX_MAP_CRB_SS)
#define	UNM_CRB_QDR_NET		UNM_PCI_CRB_WINDOW(UNM_HW_PX_MAP_CRB_SN)
#define	UNM_CRB_ROMUSB		UNM_PCI_CRB_WINDOW(UNM_HW_PX_MAP_CRB_ROMUSB)
#define	UNM_CRB_RPMX_0		UNM_PCI_CRB_WINDOW(UNM_HW_PX_MAP_CRB_RPMX0)
#define	UNM_CRB_RPMX_1		UNM_PCI_CRB_WINDOW(UNM_HW_PX_MAP_CRB_RPMX1)
#define	UNM_CRB_RPMX_2		UNM_PCI_CRB_WINDOW(UNM_HW_PX_MAP_CRB_RPMX2)
#define	UNM_CRB_RPMX_3		UNM_PCI_CRB_WINDOW(UNM_HW_PX_MAP_CRB_RPMX3)
#define	UNM_CRB_RPMX_4		UNM_PCI_CRB_WINDOW(UNM_HW_PX_MAP_CRB_RPMX4)
#define	UNM_CRB_RPMX_5		UNM_PCI_CRB_WINDOW(UNM_HW_PX_MAP_CRB_RPMX5)
#define	UNM_CRB_RPMX_6		UNM_PCI_CRB_WINDOW(UNM_HW_PX_MAP_CRB_RPMX6)
#define	UNM_CRB_RPMX_7		UNM_PCI_CRB_WINDOW(UNM_HW_PX_MAP_CRB_RPMX7)
#define	UNM_CRB_SQM_MD_0	UNM_PCI_CRB_WINDOW(UNM_HW_PX_MAP_CRB_SQS0)
#define	UNM_CRB_SQM_MD_1	UNM_PCI_CRB_WINDOW(UNM_HW_PX_MAP_CRB_SQS1)
#define	UNM_CRB_SQM_MD_2	UNM_PCI_CRB_WINDOW(UNM_HW_PX_MAP_CRB_SQS2)
#define	UNM_CRB_SQM_MD_3	UNM_PCI_CRB_WINDOW(UNM_HW_PX_MAP_CRB_SQS3)
#define	UNM_CRB_SQM_NET_0  UNM_PCI_CRB_WINDOW(UNM_HW_PX_MAP_CRB_SQN0)
#define	UNM_CRB_SQM_NET_1  UNM_PCI_CRB_WINDOW(UNM_HW_PX_MAP_CRB_SQN1)
#define	UNM_CRB_SQM_NET_2  UNM_PCI_CRB_WINDOW(UNM_HW_PX_MAP_CRB_SQN2)
#define	UNM_CRB_SQM_NET_3	UNM_PCI_CRB_WINDOW(UNM_HW_PX_MAP_CRB_SQN3)
#define	UNM_CRB_SRE		UNM_PCI_CRB_WINDOW(UNM_HW_PX_MAP_CRB_SRE)
#define	UNM_CRB_TIMER		UNM_PCI_CRB_WINDOW(UNM_HW_PX_MAP_CRB_TIMR)
#define	UNM_CRB_XDMA		UNM_PCI_CRB_WINDOW(UNM_HW_PX_MAP_CRB_XDMA)
#define	UNM_CRB_I2C0	UNM_PCI_CRB_WINDOW(UNM_HW_PX_MAP_CRB_I2C0)
#define	UNM_CRB_I2C1	UNM_PCI_CRB_WINDOW(UNM_HW_PX_MAP_CRB_I2C1)
#define	UNM_CRB_OCM0	UNM_PCI_CRB_WINDOW(UNM_HW_PX_MAP_CRB_OCM0)
#define	UNM_CRB_SMB		UNM_PCI_CRB_WINDOW(UNM_HW_PX_MAP_CRB_SMB)

#define	UNM_CRB_MAX		UNM_PCI_CRB_WINDOW(64)

/*
 * ====================== BASE ADDRESSES ON-CHIP ======================
 * Base addresses of major components on-chip.
 * ====================== BASE ADDRESSES ON-CHIP ======================
 */
#define	UNM_ADDR_DDR_NET		(0x0000000000000000ULL)
#define	UNM_ADDR_DDR_NET_MAX	(0x000000000fffffffULL)

/*
 * Imbus address bit used to indicate a host address. This bit is
 * eliminated by the pcie bar and bar select before presentation
 * over pcie.
 */
/* host memory via IMBUS */
#define	NX_P2_ADDR_PCIE		(0x0000000800000000ULL)
#define	NX_P3_ADDR_PCIE		(0x0000008000000000ULL)

#define	UNM_ADDR_PCIE_MAX	(0x0000000FFFFFFFFFULL)
#define	UNM_ADDR_OCM0		(0x0000000200000000ULL)
#define	UNM_ADDR_OCM0_MAX	(0x00000002000fffffULL)
#define	UNM_ADDR_OCM1		(0x0000000200400000ULL)
#define	UNM_ADDR_OCM1_MAX    (0x00000002004fffffULL)
#define	UNM_ADDR_QDR_NET	(0x0000000300000000ULL)

#define	NX_P2_ADDR_QDR_NET_MAX	(0x00000003001fffffULL)
#define	NX_P3_ADDR_QDR_NET_MAX	(0x0000000303ffffffULL)
/*
 * The ifdef at the bottom should go. All drivers should start using the
 * above 2 defines.
 */
#ifdef P3
#define	UNM_ADDR_QDR_NET_MAX	NX_P3_ADDR_QDR_NET_MAX
#else
#define	UNM_ADDR_QDR_NET_MAX	NX_P2_ADDR_QDR_NET_MAX
#endif

#define	D3_CRB_REG_FUN0			(UNM_PCIX_PS_REG(0x0084))
#define	D3_CRB_REG_FUN1			(UNM_PCIX_PS_REG(0x1084))
#define	D3_CRB_REG_FUN2			(UNM_PCIX_PS_REG(0x2084))
#define	D3_CRB_REG_FUN3			(UNM_PCIX_PS_REG(0x3084))


#define	ISR_I2Q_CLR_PCI_LO		(UNM_PCIX_PS_REG(UNM_I2Q_CLR_PCI_LO))
#define	ISR_I2Q_CLR_PCI_HI		(UNM_PCIX_PS_REG(UNM_I2Q_CLR_PCI_HI))
#define	UNM_PCI_ARCH_CRB_BASE   (UNM_PCI_DIRECT_CRB)

/* we're mapping 128MB of mem on the PCI bus */
#define	UNM_PCI_MAPSIZE			128
#define	UNM_PCI_DDR_NET			(unsigned long)0x00000000
#define	UNM_PCI_DDR_NET_MAX		(unsigned long)0x01ffffff
#define	UNM_PCI_DDR_MD			(unsigned long)0x02000000
#define	UNM_PCI_DDR_MD_MAX		(unsigned long)0x03ffffff
#define	UNM_PCI_QDR_NET			(unsigned long)0x04000000
#define	UNM_PCI_QDR_NET_MAX		(unsigned long)0x043fffff
#define	UNM_PCI_DIRECT_CRB		(unsigned long)0x04400000
#define	UNM_PCI_DIRECT_CRB_MAX	(unsigned long)0x047fffff
#define	UNM_PCI_CAMQM			(unsigned long)0x04800000
#define	UNM_PCI_CAMQM_MAX		(unsigned long)0x04ffffff
#define	UNM_PCI_OCM0			(unsigned long)0x05000000
#define	UNM_PCI_OCM0_MAX		(unsigned long)0x050fffff
#define	UNM_PCI_OCM1			(unsigned long)0x05100000
#define	UNM_PCI_OCM1_MAX		(unsigned long)0x051fffff
#define	UNM_PCI_CRBSPACE		(unsigned long)0x06000000
#define	UNM_PCI_CRBSPACE_MAX	(unsigned long)0x07ffffff
#define	UNM_PCI_128MB_SIZE		(unsigned long)0x08000000
#define	UNM_PCI_32MB_SIZE		(unsigned long)0x02000000
#define	UNM_PCI_2MB_SIZE		(unsigned long)0x00200000

/*
 * The basic unit of access when reading/writing control registers.
 */
typedef	long		native_t; /* most efficient integer on h/w */
typedef	__uint64_t	unm_dataword_t; /* single word in data space */
typedef	__uint64_t	unm64ptr_t; /* a pointer that occupies 64 bits */
#define	UNM64PTR(P)	((unm64ptr_t)((native_t)(P)))  /* convert for us */

typedef	__uint32_t	unm_crbword_t; /* single word in CRB space */

/*
 * Definitions relating to access/control of the Network Interface Unit
 * h/w block.
 */
/*
 * Configuration registers.
 */
#define	UNM_NIU_MODE				(UNM_CRB_NIU + 0x00000)

#define	UNM_NIU_XG_SINGLE_TERM		(UNM_CRB_NIU + 0x00004)
#define	UNM_NIU_XG_DRIVE_HI			(UNM_CRB_NIU + 0x00008)
#define	UNM_NIU_XG_DRIVE_LO			(UNM_CRB_NIU + 0x0000c)
#define	UNM_NIU_XG_DTX				(UNM_CRB_NIU + 0x00010)
#define	UNM_NIU_XG_DEQ				(UNM_CRB_NIU + 0x00014)
#define	UNM_NIU_XG_WORD_ALIGN		(UNM_CRB_NIU + 0x00018)
#define	UNM_NIU_XG_RESET			(UNM_CRB_NIU + 0x0001c)
#define	UNM_NIU_XG_POWER_DOWN		(UNM_CRB_NIU + 0x00020)
#define	UNM_NIU_XG_RESET_PLL		(UNM_CRB_NIU + 0x00024)
#define	UNM_NIU_XG_SERDES_LOOPBACK	(UNM_CRB_NIU + 0x00028)
#define	UNM_NIU_XG_DO_BYTE_ALIGN	(UNM_CRB_NIU + 0x0002c)
#define	UNM_NIU_XG_TX_ENABLE		(UNM_CRB_NIU + 0x00030)
#define	UNM_NIU_XG_RX_ENABLE		(UNM_CRB_NIU + 0x00034)
#define	UNM_NIU_XG_STATUS			(UNM_CRB_NIU + 0x00038)
#define	UNM_NIU_XG_PAUSE_THRESHOLD	(UNM_CRB_NIU + 0x0003c)
#define	UNM_NIU_INT_MASK			(UNM_CRB_NIU + 0x00040)
#define	UNM_NIU_ACTIVE_INT			(UNM_CRB_NIU + 0x00044)
#define	UNM_NIU_MASKABLE_INT		(UNM_CRB_NIU + 0x00048)
#define	UNM_NIU_TEST_MUX_CTL		(UNM_CRB_NIU + 0x00094)
#define	UNM_NIU_XG_PAUSE_CTL		(UNM_CRB_NIU + 0x00098)
#define	UNM_NIU_XG_PAUSE_LEVEL		(UNM_CRB_NIU + 0x000dc)
#define	UNM_NIU_XG_SEL				(UNM_CRB_NIU + 0x00128)
#define	UNM_NIU_GB_PAUSE_CTL		(UNM_CRB_NIU + 0x0030c)
#define	UNM_NIU_FULL_LEVEL_XG		(UNM_CRB_NIU + 0x00450)


#define	UNM_NIU_XG1_RESET			(UNM_CRB_NIU + 0x0011c)
#define	UNM_NIU_XG1_POWER_DOWN		(UNM_CRB_NIU + 0x00120)
#define	UNM_NIU_XG1_RESET_PLL		(UNM_CRB_NIU + 0x00124)

#define	UNM_NIU_STRAP_VALUE_SAVE_HIGHER (UNM_CRB_NIU + 0x0004c)

#define	UNM_NIU_GB_SERDES_RESET (UNM_CRB_NIU + 0x00050)
#define	UNM_NIU_GB0_GMII_MODE   (UNM_CRB_NIU + 0x00054)
#define	UNM_NIU_GB0_MII_MODE    (UNM_CRB_NIU + 0x00058)
#define	UNM_NIU_GB1_GMII_MODE   (UNM_CRB_NIU + 0x0005c)
#define	UNM_NIU_GB1_MII_MODE    (UNM_CRB_NIU + 0x00060)
#define	UNM_NIU_GB2_GMII_MODE   (UNM_CRB_NIU + 0x00064)
#define	UNM_NIU_GB2_MII_MODE    (UNM_CRB_NIU + 0x00068)
#define	UNM_NIU_GB3_GMII_MODE   (UNM_CRB_NIU + 0x0006c)
#define	UNM_NIU_GB3_MII_MODE    (UNM_CRB_NIU + 0x00070)
#define	UNM_NIU_REMOTE_LOOPBACK (UNM_CRB_NIU + 0x00074)
#define	UNM_NIU_GB0_HALF_DUPLEX (UNM_CRB_NIU + 0x00078)
#define	UNM_NIU_GB1_HALF_DUPLEX (UNM_CRB_NIU + 0x0007c)
#define	UNM_NIU_GB2_HALF_DUPLEX (UNM_CRB_NIU + 0x00080)
#define	UNM_NIU_GB3_HALF_DUPLEX (UNM_CRB_NIU + 0x00084)
#define	UNM_NIU_RESET_SYS_FIFOS (UNM_CRB_NIU + 0x00088)
#define	UNM_NIU_GB_CRC_DROP		(UNM_CRB_NIU + 0x0008c)
#define	UNM_NIU_GB_DROP_WRONGADDR  (UNM_CRB_NIU + 0x00090)
#define	UNM_NIU_TEST_MUX_CTL    (UNM_CRB_NIU + 0x00094)
#define	UNM_NIU_XG_PAUSE_CTL    (UNM_CRB_NIU + 0x00098)
#define	UNM_NIU_GB0_PAUSE_LEVEL (UNM_CRB_NIU + 0x000cc)
#define	UNM_NIU_GB1_PAUSE_LEVEL (UNM_CRB_NIU + 0x000d0)
#define	UNM_NIU_GB2_PAUSE_LEVEL (UNM_CRB_NIU + 0x000d4)
#define	UNM_NIU_GB3_PAUSE_LEVEL (UNM_CRB_NIU + 0x000d8)
#define	UNM_NIU_XG_PAUSE_LEVEL  (UNM_CRB_NIU + 0x000dc)
#define	UNM_NIU_FRAME_COUNT_SELECT  (UNM_CRB_NIU + 0x000ac)
#define	UNM_NIU_FRAME_COUNT  (UNM_CRB_NIU + 0x000b0)
#define	UNM_NIU_XG_SE			(UNM_CRB_NIU + 0x00128)
#define	UNM_NIU_FULL_LEVEL_XG   (UNM_CRB_NIU + 0x00450)

#define	UNM_NIU_FC_RX_STATUS(I)	(UNM_CRB_NIU + 0x10000 + (I)*0x10000)
#define	UNM_NIU_FC_RX_COMMA_DETECT(I)   (UNM_CRB_NIU + 0x10004 + (I)*0x10000)
#define	UNM_NIU_FC_LASER_UNSAFE(I)	(UNM_CRB_NIU + 0x10008 + (I)*0x10000)
#define	UNM_NIU_FC_TX_CONTROL(I)	(UNM_CRB_NIU + 0x1000c + (I)*0x10000)
#define	UNM_NIU_FC_ON_OFFLINE_CTL(I)    (UNM_CRB_NIU + 0x10010 + (I)*0x10000)
#define	UNM_NIU_FC_PORT_ACTIVE_STAT(I)  (UNM_CRB_NIU + 0x10014 + (I)*0x10000)
#define	UNM_NIU_FC_PORT_INACTIVE_STAT(I)(UNM_CRB_NIU + 0x10018 + (I)*0x10000)
#define	UNM_NIU_FC_LINK_FAILURE_CNT(I)  (UNM_CRB_NIU + 0x1001c + (I)*0x10000)
#define	UNM_NIU_FC_LOSS_SYNC_CNT(I)	(UNM_CRB_NIU + 0x10020 + (I)*0x10000)
#define	UNM_NIU_FC_LOSS_SIGNAL_CNT(I)   (UNM_CRB_NIU + 0x10024 + (I)*0x10000)
#define	UNM_NIU_FC_PRIM_SEQ_ERR_CNT(I)  (UNM_CRB_NIU + 0x10028 + (I)*0x10000)
#define	UNM_NIU_FC_INVLD_TX_WORD_CNT(I) (UNM_CRB_NIU + 0x1002c + (I)*0x10000)
#define	UNM_NIU_FC_INVLD_CRC_CNT(I)	(UNM_CRB_NIU + 0x10030 + (I)*0x10000)
#define	UNM_NIU_FC_RX_CELL_CNT(I)	(UNM_CRB_NIU + 0x10034 + (I)*0x10000)
#define	UNM_NIU_FC_TX_CELL_CNT(I)	(UNM_CRB_NIU + 0x10038 + (I)*0x10000)
#define	UNM_NIU_FC_B2B_CREDIT(I)	(UNM_CRB_NIU + 0x1003c + (I)*0x10000)
#define	UNM_NIU_FC_LOGIN_DONE(I)	(UNM_CRB_NIU + 0x10040 + (I)*0x10000)
#define	UNM_NIU_FC_OPERATING_SPEED(I)	(UNM_CRB_NIU + 0x10044 + (I)*0x10000)

#define	UNM_NIU_GB_MAC_CONFIG_0(I)	(UNM_CRB_NIU + 0x30000 + (I)*0x10000)
#define	UNM_NIU_GB_MAC_CONFIG_1(I)	(UNM_CRB_NIU + 0x30004 + (I)*0x10000)
#define	UNM_NIU_GB_MAC_IPG_IFG(I)	(UNM_CRB_NIU + 0x30008 + (I)*0x10000)
#define	UNM_NIU_GB_HALF_DUPLEX_CTRL(I)	(UNM_CRB_NIU + 0x3000c + (I)*0x10000)
#define	UNM_NIU_GB_MAX_FRAME_SIZE(I)    (UNM_CRB_NIU + 0x30010 + (I)*0x10000)
#define	UNM_NIU_GB_TEST_REG(I)		(UNM_CRB_NIU + 0x3001c + (I)*0x10000)
#define	UNM_NIU_GB_MII_MGMT_CONFIG(I)   (UNM_CRB_NIU + 0x30020 + (I)*0x10000)
#define	UNM_NIU_GB_MII_MGMT_COMMAND(I)  (UNM_CRB_NIU + 0x30024 + (I)*0x10000)
#define	UNM_NIU_GB_MII_MGMT_ADDR(I)	(UNM_CRB_NIU + 0x30028 + (I)*0x10000)
#define	UNM_NIU_GB_MII_MGMT_CTRL(I)	(UNM_CRB_NIU + 0x3002c + (I)*0x10000)
#define	UNM_NIU_GB_MII_MGMT_STATUS(I)   (UNM_CRB_NIU + 0x30030 + (I)*0x10000)
#define	UNM_NIU_GB_MII_MGMT_INDICATE(I) (UNM_CRB_NIU + 0x30034 + (I)*0x10000)
#define	UNM_NIU_GB_INTERFACE_CTRL(I)    (UNM_CRB_NIU + 0x30038 + (I)*0x10000)
#define	UNM_NIU_GB_INTERFACE_STATUS(I)  (UNM_CRB_NIU + 0x3003c + (I)*0x10000)
#define	UNM_NIU_GB_STATION_ADDR_0(I)    (UNM_CRB_NIU + 0x30040 + (I)*0x10000)
#define	UNM_NIU_GB_STATION_ADDR_1(I)    (UNM_CRB_NIU + 0x30044 + (I)*0x10000)

#define	UNM_NIU_XGE_CONFIG_0	(UNM_CRB_NIU + 0x70000)
#define	UNM_NIU_XGE_CONFIG_1	(UNM_CRB_NIU + 0x70004)
#define	UNM_NIU_XGE_IPG			(UNM_CRB_NIU + 0x70008)
#define	UNM_NIU_XGE_STATION_ADDR_0_HI   (UNM_CRB_NIU + 0x7000c)
#define	UNM_NIU_XGE_STATION_ADDR_0_1    (UNM_CRB_NIU + 0x70010)
#define	UNM_NIU_XGE_STATION_ADDR_1_LO   (UNM_CRB_NIU + 0x70014)
#define	UNM_NIU_XGE_STATUS		(UNM_CRB_NIU + 0x70018)
#define	UNM_NIU_XGE_MAX_FRAME_SIZE	(UNM_CRB_NIU + 0x7001c)
#define	UNM_NIU_XGE_PAUSE_FRAME_VALUE   (UNM_CRB_NIU + 0x70020)
#define	UNM_NIU_XGE_TX_BYTE_CNT		(UNM_CRB_NIU + 0x70024)
#define	UNM_NIU_XGE_TX_FRAME_CNT	(UNM_CRB_NIU + 0x70028)
#define	UNM_NIU_XGE_RX_BYTE_CNT		(UNM_CRB_NIU + 0x7002c)
#define	UNM_NIU_XGE_RX_FRAME_CNT	(UNM_CRB_NIU + 0x70030)
#define	UNM_NIU_XGE_AGGR_ERROR_CNT	(UNM_CRB_NIU + 0x70034)
#define	UNM_NIU_XGE_MULTICAST_FRAME_CNT (UNM_CRB_NIU + 0x70038)
#define	UNM_NIU_XGE_UNICAST_FRAME_CNT   (UNM_CRB_NIU + 0x7003c)
#define	UNM_NIU_XGE_CRC_ERROR_CNT	(UNM_CRB_NIU + 0x70040)
#define	UNM_NIU_XGE_OVERSIZE_FRAME_ERR  (UNM_CRB_NIU + 0x70044)
#define	UNM_NIU_XGE_UNDERSIZE_FRAME_ERR (UNM_CRB_NIU + 0x70048)
#define	UNM_NIU_XGE_LOCAL_ERROR_CNT		(UNM_CRB_NIU + 0x7004c)
#define	UNM_NIU_XGE_REMOTE_ERROR_CNT	(UNM_CRB_NIU + 0x70050)
#define	UNM_NIU_XGE_CONTROL_CHAR_CNT    (UNM_CRB_NIU + 0x70054)
#define	UNM_NIU_XGE_PAUSE_FRAME_CNT		(UNM_CRB_NIU + 0x70058)
#define	UNM_NIU_XG1_CONFIG_0			(UNM_CRB_NIU + 0x80000)
#define	UNM_NIU_XG1_CONFIG_1			(UNM_CRB_NIU + 0x80004)
#define	UNM_NIU_XG1_IPG					(UNM_CRB_NIU + 0x80008)
#define	UNM_NIU_XG1_STATION_ADDR_0_HI   (UNM_CRB_NIU + 0x8000c)
#define	UNM_NIU_XG1_STATION_ADDR_0_1    (UNM_CRB_NIU + 0x80010)
#define	UNM_NIU_XG1_STATION_ADDR_1_LO   (UNM_CRB_NIU + 0x80014)
#define	UNM_NIU_XG1_STATUS				(UNM_CRB_NIU + 0x80018)
#define	UNM_NIU_XG1_MAX_FRAME_SIZE		(UNM_CRB_NIU + 0x8001c)
#define	UNM_NIU_XG1_PAUSE_FRAME_VALUE   (UNM_CRB_NIU + 0x80020)
#define	UNM_NIU_XG1_TX_BYTE_CNT			(UNM_CRB_NIU + 0x80024)
#define	UNM_NIU_XG1_TX_FRAME_CNT		(UNM_CRB_NIU + 0x80028)
#define	UNM_NIU_XG1_RX_BYTE_CNT			(UNM_CRB_NIU + 0x8002c)
#define	UNM_NIU_XG1_RX_FRAME_CNT		(UNM_CRB_NIU + 0x80030)
#define	UNM_NIU_XG1_AGGR_ERROR_CNT		(UNM_CRB_NIU + 0x80034)
#define	UNM_NIU_XG1_MULTICAST_FRAME_CNT	(UNM_CRB_NIU + 0x80038)
#define	UNM_NIU_XG1_UNICAST_FRAME_CNT	(UNM_CRB_NIU + 0x8003c)
#define	UNM_NIU_XG1_CRC_ERROR_CNT		(UNM_CRB_NIU + 0x80040)
#define	UNM_NIU_XG1_OVERSIZE_FRAME_ERR  (UNM_CRB_NIU + 0x80044)
#define	UNM_NIU_XG1_UNDERSIZE_FRAME_ERR (UNM_CRB_NIU + 0x80048)
#define	UNM_NIU_XG1_LOCAL_ERROR_CNT		(UNM_CRB_NIU + 0x8004c)
#define	UNM_NIU_XG1_REMOTE_ERROR_CNT	(UNM_CRB_NIU + 0x80050)
#define	UNM_NIU_XG1_CONTROL_CHAR_CNT    (UNM_CRB_NIU + 0x80054)
#define	UNM_NIU_XG1_PAUSE_FRAME_CNT		(UNM_CRB_NIU + 0x80058)

#define	UNM_TIMER_GT_TICKCTL			(UNM_CRB_TIMER + 0x00200)
#define	UNM_TIMER_GLOBAL_TIMESTAMP_LO   (UNM_CRB_TIMER + 0x00220)
#define	UNM_TIMER_TIMESTAMP		(UNM_CRB_TIMER + 0x00208)

#define	UNM_PEXQ_REQ_HDR_LO				(UNM_CRB_XDMA + 0x00110)
#define	UNM_PEXQ_REQ_HDR_HI				(UNM_CRB_XDMA + 0x00114)

/* P3 802.3ap */
#define	UNM_NIU_AP_MAC_CONFIG_0(I)	(UNM_CRB_NIU + 0xa0000 + (I)*0x10000)
#define	UNM_NIU_AP_MAC_CONFIG_1(I)	(UNM_CRB_NIU + 0xa0004 + (I)*0x10000)
#define	UNM_NIU_AP_MAC_IPG_IFG(I)	(UNM_CRB_NIU + 0xa0008 + (I)*0x10000)
#define	UNM_NIU_AP_HALF_DUPLEX_CTRL(I)  (UNM_CRB_NIU + 0xa000c + (I)*0x10000)
#define	UNM_NIU_AP_MAX_FRAME_SIZE(I)    (UNM_CRB_NIU + 0xa0010 + (I)*0x10000)
#define	UNM_NIU_AP_TEST_REG(I)		(UNM_CRB_NIU + 0xa001c + (I)*0x10000)
#define	UNM_NIU_AP_MII_MGMT_CONFIG(I)   (UNM_CRB_NIU + 0xa0020 + (I)*0x10000)
#define	UNM_NIU_AP_MII_MGMT_COMMAND(I)  (UNM_CRB_NIU + 0xa0024 + (I)*0x10000)
#define	UNM_NIU_AP_MII_MGMT_ADDR(I)	(UNM_CRB_NIU + 0xa0028 + (I)*0x10000)
#define	UNM_NIU_AP_MII_MGMT_CTRL(I)	(UNM_CRB_NIU + 0xa002c + (I)*0x10000)
#define	UNM_NIU_AP_MII_MGMT_STATUS(I)   (UNM_CRB_NIU + 0xa0030 + (I)*0x10000)
#define	UNM_NIU_AP_MII_MGMT_INDICATE(I) (UNM_CRB_NIU + 0xa0034 + (I)*0x10000)
#define	UNM_NIU_AP_INTERFACE_CTRL(I)    (UNM_CRB_NIU + 0xa0038 + (I)*0x10000)
#define	UNM_NIU_AP_INTERFACE_STATUS(I)  (UNM_CRB_NIU + 0xa003c + (I)*0x10000)
#define	UNM_NIU_AP_STATION_ADDR_0(I)    (UNM_CRB_NIU + 0xa0040 + (I)*0x10000)
#define	UNM_NIU_AP_STATION_ADDR_1(I)    (UNM_CRB_NIU + 0xa0044 + (I)*0x10000)

/*
 *   Register offsets for MN
 */
#define	MIU_CONTROL		(0x000)
#define	MIU_TAG			(0x004)
#define	MIU_TEST_AGT_CTRL		(0x090)
#define	MIU_TEST_AGT_ADDR_LO	(0x094)
#define	MIU_TEST_AGT_ADDR_HI	(0x098)
#define	MIU_TEST_AGT_WRDATA_LO	(0x0a0)
#define	MIU_TEST_AGT_WRDATA_HI	(0x0a4)
#define	MIU_TEST_AGT_WRDATA(i)	(0x0a0+(4*(i)))
#define	MIU_TEST_AGT_RDDATA_LO	(0x0a8)
#define	MIU_TEST_AGT_RDDATA_HI	(0x0ac)
#define	MIU_TEST_AGT_RDDATA(i)	(0x0a8+(4*(i)))
#define	MIU_TEST_AGT_ADDR_MASK	0xfffffff8
#define	MIU_TEST_AGT_UPPER_ADDR(off)	(0)

/* MIU_TEST_AGT_CTRL flags. work for SIU as well */
#define	MIU_TA_CTL_START		1
#define	MIU_TA_CTL_ENABLE		2
#define	MIU_TA_CTL_WRITE		4
#define	MIU_TA_CTL_BUSY			8

#define	SIU_TEST_AGT_CTRL		(0x060)
#define	SIU_TEST_AGT_ADDR_LO	(0x064)
#define	SIU_TEST_AGT_ADDR_HI	(0x078)
#define	SIU_TEST_AGT_WRDATA_LO	(0x068)
#define	SIU_TEST_AGT_WRDATA_HI	(0x06c)
#define	SIU_TEST_AGT_WRDATA(i)	(0x068+(4*(i)))
#define	SIU_TEST_AGT_RDDATA_LO	(0x070)
#define	SIU_TEST_AGT_RDDATA_HI	(0x074)
#define	SIU_TEST_AGT_RDDATA(i)	(0x070+(4*(i)))

#define	SIU_TEST_AGT_ADDR_MASK	0x3ffff8
#define	SIU_TEST_AGT_UPPER_ADDR(off)	((off)>>22)

/* XG Link status */
#define	XG_LINK_UP    0x10


/* ======================  Configuration Constants ======================== */
#define	UNM_NIU_PHY_WAITLEN    200000    /* 200ms delay in each loop */
#define	UNM_NIU_PHY_WAITMAX    50    /* 10 seconds before we give up */
#define	UNM_NIU_MAX_GBE_PORTS 4
#define	UNM_NIU_MAX_XG_PORTS 2

typedef __uint8_t unm_ethernet_macaddr_t[6];

#define	MIN_CORE_CLK_SPEED 200
#define	MAX_CORE_CLK_SPEED 400
#define	ACCEPTABLE_CORE_CLK_RANGE(speed)	\
	((speed >= MIN_CORE_CLK_SPEED) && (speed <= MAX_CORE_CLK_SPEED))

#define	P2_TICKS_PER_SEC    2048
#define	P2_MIN_TICKS_PER_SEC    (P2_TICKS_PER_SEC-10)
#define	P2_MAX_TICKS_PER_SEC    (P2_TICKS_PER_SEC+10)
#define	CHECK_TICKS_PER_SEC(ticks)	\
	((ticks >= P2_MIN_TICKS_PER_SEC) && (ticks <= P2_MAX_TICKS_PER_SEC))

/* =============================    1GbE    =============================== */
/* Nibble or Byte mode for phy interface (GbE mode only) */
typedef enum {
    UNM_NIU_10_100_MB = 0,
    UNM_NIU_1000_MB
} unm_niu_gbe_ifmode_t;

/* Promiscous mode options (GbE mode only) */
typedef enum {
    UNM_NIU_PROMISCOUS_MODE = 0,
    UNM_NIU_NON_PROMISCOUS_MODE
} unm_niu_prom_mode_t;

/*
 * NIU GB Drop CRC Register
 */
typedef struct {
    unm_crbword_t
		drop_gb0:1, /* 1:drop pkts with bad CRCs, 0:pass them on */
		drop_gb1:1, /* 1:drop pkts with bad CRCs, 0:pass them on */
		drop_gb2:1, /* 1:drop pkts with bad CRCs, 0:pass them on */
		drop_gb3:1, /* 1:drop pkts with bad CRCs, 0:pass them on */
		rsvd:28;
} unm_niu_gb_drop_crc_t;

/*
 * NIU GB GMII Mode Register (applies to GB0, GB1, GB2, GB3)
 * To change the mode, turn off the existing mode, then turn on the new mode.
 */
typedef struct {
    unm_crbword_t
		gmiimode:1, /* 1:GMII mode, 0:xmit clk taken from SERDES */
		rsvd:29;
} unm_niu_gb_gmii_mode_t;

/*
 * NIU GB MII Mode Register (applies to GB0, GB1, GB2, GB3)
 * To change the mode, turn off the existing mode, then turn on the new mode.
 */
typedef struct {
    unm_crbword_t
		miimode:1, /* 1:MII mode, 0:xmit clk provided to SERDES */
		rsvd:29;
} unm_niu_gb_mii_mode_t;

/*
 * NIU GB MAC Config Register 0 (applies to GB0, GB1, GB2, GB3)
 */
typedef struct {
    unm_crbword_t
		tx_enable:1, /* 1:enable frame xmit, 0:disable */
		tx_synched:1, /* R/O: xmit enable synched to xmit stream */
		rx_enable:1, /* 1:enable frame recv, 0:disable */
		rx_synched:1, /* R/O: recv enable synched to recv stream */
		tx_flowctl:1, /* 1:enable pause frame generation, 0:disable */
		rx_flowctl:1, /* 1:act on recv'd pause frames, 0:ignore */
		rsvd1:2,
		loopback:1, /* 1:loop MAC xmits to MAC recvs, 0:normal */
		rsvd2:7,
		tx_reset_pb:1, /* 1:reset frame xmit protocol blk, 0:no-op */
		rx_reset_pb:1, /* 1:reset frame recv protocol blk, 0:no-op */
		tx_reset_mac:1, /* 1:reset data/ctl multiplexer blk, 0:no-op */
		rx_reset_mac:1, /* 1:reset ctl frames & timers blk, 0:no-op */
		rsvd3:11,
		soft_reset:1; /* 1:reset the MAC and the SERDES, 0:no-op */
} unm_niu_gb_mac_config_0_t;

/*
 * NIU GB MAC Config Register 1 (applies to GB0, GB1, GB2, GB3)
 */
typedef struct {
    unm_crbword_t
		duplex:1, /* 1:full duplex mode, 0:half duplex */
		crc_enable:1, /* 1:append CRC to xmit frames, 0:dont append */
		padshort:1, /* 1:pad short frames and add CRC, 0:dont pad */
		rsvd1:1,
		checklength:1, /* 1:check framelen with actual, 0:dont check */
		hugeframes:1, /* 1:allow oversize xmit frames, 0:dont allow */
		rsvd2:2,
		intfmode:2, /* 01:nibble (10/100), 10:byte (1000) */
		rsvd3:2,
		preamblelen:4, /* preamble field length in bytes, default 7 */
		rsvd4:16;
} unm_niu_gb_mac_config_1_t;

/*
 * NIU XG Pause Ctl Register
 */
typedef struct {
    unm_crbword_t
		xg0_mask:1, /* 1:disable tx pause frames */
		xg0_request:1, /* request single pause frame */
		xg0_on_off:1, /* 1:req is pause on, 0:off */
		xg1_mask:1, /* 1:disable tx pause frames */
		xg1_request:1, /* request single pause frame */
		xg1_on_off:1, /* 1:req is pause on, 0:off */
		rsvd:26;
} unm_niu_xg_pause_ctl_t;

/*
 * NIU GBe Pause Ctl Register
 */
typedef struct {
    unm_crbword_t
		gb0_mask:1, /* 1:disable tx pause frames */
		gb0_pause_req:1, /* 1: send pause on, 0: send pause off */
		gb1_mask:1, /* 1:disable tx pause frames */
		gb1_pause_req:1, /* 1: send pause on, 0: send pause off */
		gb2_mask:1, /* 1:disable tx pause frames */
		gb2_pause_req:1, /* 1: send pause on, 0: send pause off */
		gb3_mask:1, /* 1:disable tx pause frames */
		gb3_pause_req:1, /* 1: send pause on, 0: send pause off */
		rsvd:24;
} unm_niu_gb_pause_ctl_t;


/*
 * NIU XG MAC Config Register
 */
typedef struct {
    unm_crbword_t
		tx_enable:1, /* 1:enable frame xmit, 0:disable */
		rsvd1:1,
		rx_enable:1, /* 1:enable frame recv, 0:disable */
		rsvd2:1,
		soft_reset:1, /* 1:reset the MAC , 0:no-op */
		rsvd3:22,
		xaui_framer_reset:1,
		xaui_rx_reset:1,
		xaui_tx_reset:1,
		xg_ingress_afifo_reset:1,
		xg_egress_afifo_reset:1;
} unm_niu_xg_mac_config_0_t;

/*
 * NIU GB MII Mgmt Config Register (applies to GB0, GB1, GB2, GB3)
 */
typedef struct {
    unm_crbword_t
		clockselect:3, /* 0:clk/4,  1:clk/4,  2:clk/6,  3:clk/8 */
		/* 4:clk/10, 5:clk/14, 6:clk/20, 7:clk/28 */
		rsvd1:1,
		nopreamble:1, /* 1:suppress preamble generation, 0:normal */
		scanauto:1, /* ???? */
		rsvd2:25,
		reset:1; /* 1:reset MII mgmt, 0:no-op */
} unm_niu_gb_mii_mgmt_config_t;

/*
 * NIU GB MII Mgmt Command Register (applies to GB0, GB1, GB2, GB3)
 */
typedef struct {
    unm_crbword_t
		read_cycle:1, /* 1:perform single read cycle, 0:no-op */
		scan_cycle:1, /* 1:perform continuous read cycles, 0:no-op */
		rsvd:30;
} unm_niu_gb_mii_mgmt_command_t;

/*
 * NIU GB MII Mgmt Address Register (applies to GB0, GB1, GB2, GB3)
 */
typedef struct {
    unm_crbword_t
		reg_addr:5, /* which mgmt register we want to talk to */
		rsvd1:3,
		phy_addr:5, /* which PHY to talk to (0 is reserved) */
		rsvd:19;
} unm_niu_gb_mii_mgmt_address_t;

/*
 * NIU GB MII Mgmt Indicators Register (applies to GB0, GB1, GB2, GB3)
 * Read-only register.
 */
typedef struct {
    unm_crbword_t
		busy:1, /* 1:performing an MII mgmt cycle, 0:idle */
		scanning:1, /* 1:scan operation in progress, 0:idle */
		notvalid:1, /* 1:mgmt result data not yet valid, 0:idle */
		rsvd:29;
} unm_niu_gb_mii_mgmt_indicators_t;

/*
 * NIU GB Station Address High Register
 * NOTE: this value is in network byte order.
 */
typedef struct {
    unm_crbword_t
		address:32; /* station address [47:16] */
} unm_niu_gb_station_address_high_t;

/*
 * NIU GB Station Address Low Register
 * NOTE: this value is in network byte order.
 */
typedef struct {
    unm_crbword_t
		rsvd:16,
		address:16; /* station address [15:0] */
} unm_niu_gb_station_address_low_t;

/* ============================  PHY Definitions  ========================== */
/*
 * PHY-Specific MII control/status registers.
 */
typedef enum {
    UNM_NIU_GB_MII_MGMT_ADDR_CONTROL = 0,
    UNM_NIU_GB_MII_MGMT_ADDR_STATUS = 1,
    UNM_NIU_GB_MII_MGMT_ADDR_PHY_ID_0 = 2,
    UNM_NIU_GB_MII_MGMT_ADDR_PHY_ID_1 = 3,
    UNM_NIU_GB_MII_MGMT_ADDR_AUTONEG = 4,
    UNM_NIU_GB_MII_MGMT_ADDR_LNKPART = 5,
    UNM_NIU_GB_MII_MGMT_ADDR_AUTONEG_MORE = 6,
    UNM_NIU_GB_MII_MGMT_ADDR_NEXTPAGE_XMIT = 7,
    UNM_NIU_GB_MII_MGMT_ADDR_LNKPART_NEXTPAGE = 8,
    UNM_NIU_GB_MII_MGMT_ADDR_1000BT_CONTROL = 9,
    UNM_NIU_GB_MII_MGMT_ADDR_1000BT_STATUS = 10,
    UNM_NIU_GB_MII_MGMT_ADDR_EXTENDED_STATUS = 15,
    UNM_NIU_GB_MII_MGMT_ADDR_PHY_CONTROL = 16,
    UNM_NIU_GB_MII_MGMT_ADDR_PHY_STATUS = 17,
    UNM_NIU_GB_MII_MGMT_ADDR_INT_ENABLE = 18,
    UNM_NIU_GB_MII_MGMT_ADDR_INT_STATUS = 19,
    UNM_NIU_GB_MII_MGMT_ADDR_PHY_CONTROL_MORE = 20,
    UNM_NIU_GB_MII_MGMT_ADDR_RECV_ERROR_COUNT = 21,
    UNM_NIU_GB_MII_MGMT_ADDR_LED_CONTROL = 24,
    UNM_NIU_GB_MII_MGMT_ADDR_LED_OVERRIDE = 25,
    UNM_NIU_GB_MII_MGMT_ADDR_PHY_CONTROL_MORE_YET = 26,
    UNM_NIU_GB_MII_MGMT_ADDR_PHY_STATUS_MORE = 27
} unm_niu_phy_register_t;

/*
 * PHY-Specific Status Register (reg 17).
 */
typedef struct {
    unm_crbword_t
		jabber:1, /* 1:jabber detected, 0:not */
		polarity:1, /* 1:polarity reversed, 0:normal */
		recvpause:1, /* 1:receive pause enabled, 0:disabled */
		xmitpause:1, /* 1:transmit pause enabled, 0:disabled */
		energydetect:1, /* 1:sleep, 0:active */
		downshift:1, /* 1:downshift, 0:no downshift */
		crossover:1, /* 1:MDIX (crossover), 0:MDI (no crossover) */
		cablelen:3, /* not valid in 10Mb/s mode */
		/* 0:<50m, 1:50-80m, 2:80-110m, 3:110-140m, 4:>140m */
		link:1, /* 1:link up, 0:link down */
		resolved:1, /* 1:speed and duplex resolved, 0:not yet */
		pagercvd:1, /* 1:page received, 0:page not received */
		duplex:1, /* 1:full duplex, 0:half duplex */
		speed:2, /* 0:10Mb/s, 1:100Mb/s, 2:1000Mb/s, 3:rsvd */
		rsvd:16;
} unm_niu_phy_status_t;

/*
 * Interrupt Register definition
 * This definition applies to registers 18 and 19 (int enable and int status).
 */
typedef struct {
    unm_crbword_t
		jabber:1,
		polarity_changed:1,
		reserved:2,
		energy_detect:1,
		downshift:1,
		mdi_xover_changed:1,
		fifo_over_underflow:1,
		false_carrier:1,
		symbol_error:1,
		link_status_changed:1,
		autoneg_completed:1,
		page_received:1,
		duplex_changed:1,
		speed_changed:1,
		autoneg_error:1,
		rsvd:16;
} unm_niu_phy_interrupt_t;

/* =============================   10GbE    =============================== */
/*
 * NIU Mode Register.
 */
typedef struct {
    unm_crbword_t
		enable_fc:1, /* enable FibreChannel */
		enable_ge:1, /* enable 10/100/1000 Ethernet */
		enable_xgb:1, /* enable 10Gb Ethernet */
		rsvd:29;
} unm_niu_control_t;

/* ==========================  Interface Functions  ======================= */

/* Generic enable for GbE ports. Will detect the speed of the link. */
long unm_niu_gbe_init_port(long port);

/* XG Link status */
#define	XG_LINK_UP    0x10
#define	XG_LINK_DOWN  0x20

#define	XG_LINK_UP_P3    0x1
#define	XG_LINK_DOWN_P3  0x2
#define	XG_LINK_UNKNOWN_P3  0

#define	XG_LINK_STATE_P3_MASK 0xf
#define	XG_LINK_STATE_P3(pcifn, val) \
	(((val) >> ((pcifn) * 4)) & XG_LINK_STATE_P3_MASK)

#define	MTU_MARGIN			100

#define	PF_LINK_SPEED_MHZ 100
#define	PF_LINK_SPEED_REG(pcifn)  (CRB_PF_LINK_SPEED_1 + (((pcifn)/4)* 4))
#define	PF_LINK_SPEED_MASK 0xff
#define	PF_LINK_SPEED_VAL(pcifn, reg) \
		(((reg) >> (8 * ((pcifn) & 0x3))) & PF_LINK_SPEED_MASK)



/*
 * Definitions relating to access/control of the CAM RAM
 */

typedef union {
    struct {
					/*
					 * =1 if watchdog is active.
					 * =0 if watchdog is inactive
					 *  This is read-only for anyone
					 *  but the watchdog itself.
					 */
		unsigned int    enabled: 1,
					/*
					 * Set this to 1 to send disable
					 * request to watchdog . Watchdog
					 * will complete the shutdown
					 * process and acknowledge it
					 * by clearing this bit and the
					 * "enable" bit.
					 */
						disable_request: 1,
					/*
					 * Set this to 1 to send enable
					 * request to watchdog . Watchdog
					 * will complete the enable
					 * process and acknowledge it
					 * by clearing this bit and
					 * setting the "enable" bit.
					 */
						enable_request: 1,
						unused: 29;
	} s1;
	unm_crbword_t word;
} dma_watchdog_ctrl_t;

#define	UNM_CAM_RAM_BASE		(UNM_CRB_CAM + 0x02000)
#define	UNM_CAM_RAM(reg)		(UNM_CAM_RAM_BASE + (reg))

#define	UNM_PORT_MODE_NONE			0
#define	UNM_PORT_MODE_XG			1
#define	UNM_PORT_MODE_GB			2
#define	UNM_PORT_MODE_802_3_AP		3
#define	UNM_PORT_MODE_AUTO_NEG		4
#define	UNM_PORT_MODE_AUTO_NEG_1G	5
#define	UNM_PORT_MODE_AUTO_NEG_XG	6
#define	UNM_PORT_MODE_ADDR			(UNM_CAM_RAM(0x24))
#define	UNM_WOL_PORT_MODE			(UNM_CAM_RAM(0x198))

#define	UNM_ROM_LOCK_ID		(UNM_CAM_RAM(0x100))
#define	UNM_I2C_ROM_LOCK_ID (UNM_CAM_RAM(0x104))
#define	UNM_PHY_LOCK_ID		(UNM_CAM_RAM(0x120))
#define	UNM_CRB_WIN_LOCK_ID (UNM_CAM_RAM(0x124))
#define	CAM_RAM_DMA_WATCHDOG_CTRL	0x14 /* See dma_watchdog_ctrl_t */
#define	UNM_EFUSE_CHIP_ID	(UNM_CAM_RAM(0x18))

#define	UNM_FW_VERSION_MAJOR (UNM_CAM_RAM(0x150))
#define	UNM_FW_VERSION_MINOR (UNM_CAM_RAM(0x154))
#define	UNM_FW_VERSION_BUILD (UNM_CAM_RAM(0x168))
#define	UNM_FW_VERSION_SUB   (UNM_CAM_RAM(0x158))
#define	UNM_TCP_FW_VERSION_MAJOR_ADDR (UNM_CAM_RAM(0x15c))
#define	UNM_TCP_FW_VERSION_MINOR_ADDR (UNM_CAM_RAM(0x160))
#define	UNM_TCP_FW_VERSION_SUB_ADDR (UNM_CAM_RAM(0x164))
#define	UNM_PCIE_REG(reg) (UNM_CRB_PCIE + (reg))

#define	PCIE_DCR				(0x00d8)
#define	PCIE_DB_DATA2			(0x10070)
#define	PCIE_DB_CTRL			(0x100a0)
#define	PCIE_DB_ADDR			(0x100a4)
#define	PCIE_DB_DATA			(0x100a8)
#define	PCIE_IMBUS_CONTROL		(0x101b8)
#define	PCIE_SETUP_FUNCTION		(0x12040)
#define	PCIE_SETUP_FUNCTION2	(0x12048)
#define	PCIE_TGT_SPLIT_CHICKEN	(0x12080)
#define	PCIE_CHICKEN3			(0x120c8)
#define	PCIE_MAX_MASTER_SPLIT	(0x14048)
#define	PCIE_MAX_DMA_XFER_SIZE	(0x1404c)

#define	UNM_WOL_WAKE (UNM_CAM_RAM(0x180))
#define	UNM_WOL_CONFIG_NV (UNM_CAM_RAM(0x184))
#define	UNM_WOL_CONFIG (UNM_CAM_RAM(0x188))
#define	UNM_PRE_WOL_RX_ENABLE (UNM_CAM_RAM(0x18c))

/*
 *  Following define address space withing PCIX CRB space to talk with
 *  devices on the storage side PCI bus.
 */
#define	PCIX_PS_MEM_SPACE		(0x90000)

#define	UNM_PCIX_PH_REG(reg)	(UNM_CRB_PCIE + (reg))

/*
 * Configuration registers. These are the same offsets on both host and
 * storage side PCI blocks.
 */
/* Used for PS PCI Memory access */
#define	PCIX_PS_OP_ADDR_LO		(0x10000)
#define	PCIX_PS_OP_ADDR_HI		(0x10004)  /* via CRB  (PS side only) */

#define	PCIX_MS_WINDOW			(0x10204)   /* UNUSED */

#define	PCIX_CRB_WINDOW			(0x10210)
#define	PCIX_CRB_WINDOW_F0		(0x10210)
#define	PCIX_CRB_WINDOW_F1		(0x10230)
#define	PCIX_CRB_WINDOW_F2		(0x10250)
#define	PCIX_CRB_WINDOW_F3		(0x10270)
#define	PCIX_CRB_WINDOW_F4		(0x102ac)
#define	PCIX_CRB_WINDOW_F5		(0x102bc)
#define	PCIX_CRB_WINDOW_F6		(0x102cc)
#define	PCIX_CRB_WINDOW_F7		(0x102dc)
#define	PCIE_CRB_WINDOW_REG(func) (((func) < 4) ? \
		(PCIX_CRB_WINDOW_F0 + (0x20 * (func))) :\
		(PCIX_CRB_WINDOW_F4 + (0x10 * ((func)-4))))

#define	PCIX_MN_WINDOW			(0x10200)
#define	PCIX_MN_WINDOW_F0		(0x10200)
#define	PCIX_MN_WINDOW_F1		(0x10220)
#define	PCIX_MN_WINDOW_F2		(0x10240)
#define	PCIX_MN_WINDOW_F3		(0x10260)
#define	PCIX_MN_WINDOW_F4		(0x102a0)
#define	PCIX_MN_WINDOW_F5		(0x102b0)
#define	PCIX_MN_WINDOW_F6		(0x102c0)
#define	PCIX_MN_WINDOW_F7		(0x102d0)
#define	PCIE_MN_WINDOW_REG(func) (((func) < 4) ? \
		(PCIX_MN_WINDOW_F0 + (0x20 * (func))) :\
		(PCIX_MN_WINDOW_F4 + (0x10 * ((func)-4))))

#define	PCIX_SN_WINDOW			(0x10208)
#define	PCIX_SN_WINDOW_F0		(0x10208)
#define	PCIX_SN_WINDOW_F1		(0x10228)
#define	PCIX_SN_WINDOW_F2		(0x10248)
#define	PCIX_SN_WINDOW_F3		(0x10268)
#define	PCIX_SN_WINDOW_F4		(0x102a8)
#define	PCIX_SN_WINDOW_F5		(0x102b8)
#define	PCIX_SN_WINDOW_F6		(0x102c8)
#define	PCIX_SN_WINDOW_F7		(0x102d8)
#define	PCIE_SN_WINDOW_REG(func) (((func) < 4) ? \
		(PCIX_SN_WINDOW_F0 + (0x20 * (func))) :\
		(PCIX_SN_WINDOW_F4 + (0x10 * ((func)-4))))

#define	UNM_PCIX_PS_REG(reg) (UNM_CRB_PCIX_MD + (reg))
#define	UNM_PCIX_PS2_REG(reg) (UNM_CRB_PCIE2 + (reg))
#define	MANAGEMENT_COMMAND_REG	(UNM_CRB_PCIE + (4))

#define	UNM_PH_INT_MASK		(UNM_CRB_PCIE + PCIX_INT_MASK)

/*
 * CRB window register.
 */
typedef struct {
    unm_crbword_t	rsvd1:25,
					addrbit:1, /* bit 25 of CRB address */
					rsvd2:6;
} unm_pcix_crb_window_t;

/*
 * Tell which interrupt source we want to operate on.
 */
typedef enum {
    UNM_PCIX_INT_SRC_UNDEFINED = 0,
	UNM_PCIX_INT_SRC_DMA0, /* DMA engine 0 */
	UNM_PCIX_INT_SRC_DMA1, /* DMA engine 1 */
	UNM_PCIX_INT_SRC_I2Q  /* I2Q block */
} unm_pcix_int_source_t;

typedef enum {
    UNM_PCIX_INT_SRC_UNDEFINEDSTATE = 0,
	UNM_PCIX_INT_SRC_ALLOW, /* Allow this src to int. the host */
	UNM_PCIX_INT_SRC_MASK /* Mask this src */
} unm_pcix_int_state_t;

/*
 * PCIX Interrupt Mask Register.
 */
typedef struct {
					/* 0=DMA0 not masked, 1=masked */
	unm_crbword_t	dma0:1,
					/* 0=DMA1 not masked, 1=masked */
					dma1:1,
					/* 0=I2Q  not masked, 1=masked */
					i2q:1,
					dma0_err:1,
					dma1_err:1,
					target_status:1,
					mega_err:1,
					ps_serr_int:1,
					split_discard:1,
					io_write_func0:1,
					io_write_func1:1,
					io_write_func2:1,
					io_write_func3:1,
					msi_write_func0:1,
					msi_write_func1:1,
					msi_write_func2:1,
					msi_write_func3:1,
					rsvd:15;
} unm_pcix_int_mask_t;

int unm_pcix_int_control(unm_pcix_int_source_t src,
    unm_pcix_int_state_t state);

#define	UNM_SRE_INT_STATUS			(UNM_CRB_SRE + 0x00034)
#define	UNM_SRE_BUF_CTL				(UNM_CRB_SRE + 0x01000)
#define	UNM_SRE_PBI_ACTIVE_STATUS	(UNM_CRB_SRE + 0x01014)
#define	UNM_SRE_SCRATCHPAD			(UNM_CRB_SRE + 0x01018)
#define	UNM_SRE_L1RE_CTL			(UNM_CRB_SRE + 0x03000)
#define	UNM_SRE_L2RE_CTL			(UNM_CRB_SRE + 0x05000)

// These are offset to a particular Peg's CRB base address
#define	CRB_REG_EX_PC		0x3c

#define	PEG_NETWORK_BASE(N)	(UNM_CRB_PEG_NET_0 + (((N)&3) << 20))

/*
 * Definitions relating to enqueue/dequeue/control of the Queue Operations
 * to either the Primary Queue Manager or the Secondary Queue Manager.
 */

/*
 * General configuration constants.
 */
#define	UNM_QM_MAX_SIDE		1

/*
 * Data movement registers (differs based on processor).
 */
#define	UNM_QM_COMMAND (UNM_PCI_CAMQM + 0x00000)
#define	UNM_QM_STATUS  (UNM_PCI_CAMQM + 0x00008)
#define	UNM_QM_DATA(W, P) (UNM_PCI_CAMQM + 0x00010 +	\
		(W)*sizeof (unm_dataword_t))
#define	UNM_QM_REPLY(W, P)(UNM_PCI_CAMQM + 0x00050 +	\
		(W)*sizeof (unm_dataword_t))

/*
 * Control commands to the QM block.
 */
#define	UNM_QM_CMD_READ		0x0  /* interpret "readop" field */

/*
 * Platform-specific fields in the queue command word
 */
#define	UNM_QM_CMD_SIDE  0
/* Casper and Peg need this bit.  PCI interface does not */
#define	UNM_QM_CMD_START 1


/*
 * Pegasus has two QM ports. This is the default one to use (unless
 * QM async interface is called explicitly with other port).
 */
#define	UNM_QM_DEFAULT_PORT 0

/*
 * Status result returned to caller of unm_qm_request_status()
 */
typedef enum {
	/* error in HW - most likely PCI bug. retry  */
	unm_qm_status_unknown = 0,
	unm_qm_status_done, /* done with last command */
	unm_qm_status_busy, /* busy */
	unm_qm_status_notfound, /* queue is empty to read or full to write */
	unm_qm_status_error /* error (e.g. timeout) encountered */
} unm_qm_result_t;

/*
 * Definitions relating to access/control of the I2Q h/w block.
 */
/*
 * Configuration registers.
 */
#define	UNM_I2Q_CONFIG			(UNM_CRB_I2Q + 0x00000)
#define	UNM_I2Q_ENA_PCI_LO		(UNM_CRB_I2Q + 0x00010)
#define	UNM_I2Q_ENA_PCI_HI		(UNM_CRB_I2Q + 0x00014)
#define	UNM_I2Q_ENA_CASPER_LO	(UNM_CRB_I2Q + 0x00018)
#define	UNM_I2Q_ENA_CASPER_HI	(UNM_CRB_I2Q + 0x0001c)
#define	UNM_I2Q_ENA_QM_LO		(UNM_CRB_I2Q + 0x00020)
#define	UNM_I2Q_ENA_QM_HI		(UNM_CRB_I2Q + 0x00024)
#define	UNM_I2Q_CLR_PCI_LO		(UNM_CRB_I2Q + 0x00030)
#define	UNM_I2Q_CLR_PCI_HI		(UNM_CRB_I2Q + 0x00034)
#define	UNM_I2Q_CLR_CASPER_LO	(UNM_CRB_I2Q + 0x00038)
#define	UNM_I2Q_CLR_CASPER_HI	(UNM_CRB_I2Q + 0x0003c)
#define	UNM_I2Q_MSG_HDR_LO(I)	(UNM_CRB_I2Q + 0x00100 + (I)*0x8)
#define	UNM_I2Q_MSG_HDR_HI(I)	(UNM_CRB_I2Q + 0x00104 + (I)*0x8)

/*
 * List the bit positions in the registers of the interrupt sources.
 */
typedef	enum {
	UNM_I2Q_SRC_PCI32		= 0, /* PCI32 block */
	UNM_I2Q_SRC_PCIE		= 1, /* PCI-Express block */
	UNM_I2Q_SRC_CASPER		= 2, /* Casper */
	UNM_I2Q_SRC_CASPER_ERR	= 3, /* Casper error */
	UNM_I2Q_SRC_PEG_0		= 4, /* Peg 0  */
	UNM_I2Q_SRC_PEG_1		= 5, /* Peg 1 */
	UNM_I2Q_SRC_PEG_2		= 6, /* Peg 2 */
	UNM_I2Q_SRC_PEG_3		= 7, /* Peg 3 */
	UNM_I2Q_SRC_PEG_DCACHE	= 8, /* Peg Data cache */
	UNM_I2Q_SRC_PEG_ICACHE	= 9, /* Peg Instruction cache */
	UNM_I2Q_SRC_DMA0		= 10, /* DMA engine 0 */
	UNM_I2Q_SRC_DMA1		= 11, /* DMA engine 1 */
	UNM_I2Q_SRC_DMA2		= 12, /* DMA engine 2 */
	NM_I2Q_SRC_DMA3			= 13, /* DMA engine 3 */
	UNM_I2Q_SRC_LPC			= 14, /*  */
	UNM_I2Q_SRC_SMB			= 15, /*  */
	UNM_I2Q_SRC_TIMER		= 16, /* One of the global timers */
	UNM_I2Q_SRC_SQG0		= 17, /* SQM SQG0 empty->non-empty */
	UNM_I2Q_SRC_SQG1		= 18, /* SQM SQG1 empty->non-empty */
	UNM_I2Q_SRC_SQG2		= 19, /* SQM SQG2 empty->non-empty */
	UNM_I2Q_SRC_SQG3		= 20, /* SQM SQG3 empty->non-empty */
	UNM_I2Q_SRC_SQG0_LW		= 21, /* SQM SQG0 low on free buffers */
	UNM_I2Q_SRC_SQG1_LW		= 22, /* SQM SQG1 low on free buffers */
	UNM_I2Q_SRC_SQG2_LW		= 23, /* SQM SQG2 low on free buffers */
	UNM_I2Q_SRC_SQG3_LW		= 24, /* SQM SQG3 low on free buffers */
	UNM_I2Q_SRC_PQM_0		= 25, /* PQM group 0 */
	UNM_I2Q_SRC_PQM_1		= 26, /* PQM group 1 */
	UNM_I2Q_SRC_PQM_2		= 27, /* PQM group 2 */
	UNM_I2Q_SRC_PQM_3		= 28, /* PQM group 3 */
	/* [29:31] reserved */
	UNM_I2Q_SRC_SW_0		= 32, /* SW INT 0 */
	UNM_I2Q_SRC_SW_1		= 33, /* SW INT 1 */
	UNM_I2Q_SRC_SW_2		= 34, /* SW INT 2 */
	UNM_I2Q_SRC_SW_3		= 35, /* SW INT 3 */
	UNM_I2Q_SRC_SW_4		= 36, /* SW INT 4 */
	UNM_I2Q_SRC_SW_5		= 37, /* SW INT 5 */
	UNM_I2Q_SRC_SW_6		= 38, /* SW INT 6 */
	UNM_I2Q_SRC_SW_7		= 39, /* SW INT 7 */
	UNM_I2Q_SRC_SRE_EPG		= 40, /* SRE/EPG aggregate interrupt */
	UNM_I2Q_SRC_XDMA		= 41, /* XDMA engine */
	UNM_I2Q_SRC_MN			= 42, /* DDR interface unit */
	UNM_I2Q_SRC_NIU			= 43, /* Network interface unit */
	UNM_I2Q_SRC_SN			= 44, /* QDR interface unit */
	UNM_I2Q_SRC_CAM			= 45, /* CAM */
	UNM_I2Q_SRC_EXT1		= 46, /* External 1 */
	UNM_I2Q_SRC_EXT2		= 47, /* External 2 */
	/* [48:63] reserved */
	UNM_I2Q_SRC_MAX			= 47, /* max used interrupt line */
	UNM_I2Q_SRC_MAX_LO		= 32 /* max bits in "lo" register */
} unm_i2q_source_t;

/*
 * Interrupt Source Enable/Clear registers for the I2Q.
 */
typedef struct {
    unm_crbword_t  source:32;    /* int enable/status bits */
} unm_i2q_source_lo_t;

typedef struct {
	unm_crbword_t	source:16, /* int enable/status bits */
					rsvd:16;
} unm_i2q_source_hi_t;

/*
 * List the possible interrupt sources and the
 * control operations to be performed for each.
 */
typedef	enum {
	UNM_I2Q_CTL_SRCUNKNOWN = 0, /* undefined */
	UNM_I2Q_CTL_PCI, /* PCI block */
	UNM_I2Q_CTL_CASPER, /* Casper */
	UNM_I2Q_CTL_QM /* Queue Manager */
} unm_i2q_ctl_src_t;

typedef	enum {
	UNM_I2Q_CTL_OPUNKNOWN = 0, /* undefined */
	UNM_I2Q_CTL_ADD, /* add int'ing for that source */
	UNM_I2Q_CTL_DEL  /* stop int'ing for that source */
} unm_i2q_ctl_op_t;

/*
 * Definitions relating to access/control of the Secondary Queue Manager
 * h/w block.
 */
/*
 * Configuration registers.
 */
#define	UNM_SQM_BASE(G)                                        	\
	((G) == 0 ? UNM_CRB_SQM_NET_0 :                             \
	((G) == 1 ? UNM_CRB_SQM_NET_1 :                         \
	((G) == 2 ? UNM_CRB_SQM_NET_2 : UNM_CRB_SQM_NET_3)))

#define	UNM_SQM_INT_ENABLE(G)		(UNM_SQM_BASE(G) + 0x00018)
#define	UNM_SQM_INT_STATUS(G)		(UNM_SQM_BASE(G) + 0x0001c)
#define	UNN_SQM_SCRATCHPAD(G)		(UNM_SQM_BASE(G) + 0x01000)

#define	UNM_SQM_MAX_GRP			4  /* num groups per side */
#define	UNM_SQM_MAX_SUBQ		16 /* num Q's per type-0 group */
#define	UNM_SQM_MAX_SUBGRP		4  /* subgrps per type-1 group */

#define	UNM_SQM_MAX_TYPE_1_NUM		(256*1024)

/*
 * Interrupt enables and interrupt status for all 16 queues in a group.
 */
typedef	struct {
	unm_crbword_t	queues:16, /* enable/status: 0x1=Q0, 0x8000=Q15 */
					rsvd:16;
} unm_sqm_int_enstat_t;

/*
 * Control operation for an SQM Group interrupt.
 */
typedef	enum {
	UNM_SQM_INTOP_OPUNKNOWN = 0, /* undefined */
	UNM_SQM_INTOP_GET, /* return all bits for that group */
	UNM_SQM_INTOP_SET, /* assign all bits for that group */
	UNM_SQM_INTOP_ADD, /* set one bit for that group */
	UNM_SQM_INTOP_DEL  /* clear one bit for that group */
} unm_sqm_int_op_t;
typedef enum {
	UNM_SQM_INTARG_ARGUNKNOWN = 0, /* undefined */
	UNM_SQM_INTARG_ENABLE, /* affect the 'enable' register */
	UNM_SQM_INTARG_STATUS  /* affect the 'status' register */
} unm_sqm_int_arg_t;

int unm_sqm_int_control(unm_sqm_int_op_t op, unm_sqm_int_arg_t arg,
    int side, int group, int queue, int *image);


int unm_crb_read(unsigned long off, void *data);
native_t unm_crb_read_val(unsigned long off);
int unm_crb_write(unsigned long off, void *data);
int unm_crb_writelit(unsigned long off, int data);
int unm_imb_read(unsigned long off, void *data);
int unm_imb_write(unsigned long off, void *data);
int unm_imb_writelit64(unsigned long off, __uint64_t data);

unsigned long unm_xport_lock(void);
void unm_xport_unlock(unsigned long);

#define	UNM_CRB_READ_VAL(ADDR) unm_crb_read_val((ADDR))
#define	UNM_CRB_READ(ADDR, VALUE) unm_crb_read((ADDR), (unm_crbword_t *)(VALUE))
#define	UNM_CRB_READ_CHECK(ADDR, VALUE)		\
	do {								\
		if (unm_crb_read(ADDR, VALUE))	\
			return (-1);					\
	} while (0)
#define	UNM_CRB_WRITE_CHECK(ADDR, VALUE)		\
	do {								\
		if (unm_crb_write(ADDR, VALUE))			\
			return (-1);			\
	} while (0)
#define	UNM_CRB_WRITELIT(ADDR, VALUE)			\
	do {						\
		unm_crb_writelit(ADDR, VALUE);			\
	} while (0)
#define	UNM_CRB_WRITE(ADDR, VALUE)				\
	do {					\
		unm_crb_write(ADDR, VALUE);				\
	} while (0)
#define	UNM_CRB_WRITELIT_CHECK(ADDR, VALUE)			\
	do {								\
		if (unm_crb_writelit(ADDR, VALUE))	\
			return (-1);		\
	} while (0)

#define	UNM_IMB_READ_CHECK(ADDR, VALUE)				\
	do {					\
		if (unm_imb_read(ADDR, VALUE))		\
			return (-1);		\
	} while (0)
#define	UNM_IMB_WRITE_CHECK(ADDR, VALUE)			\
	do {						\
		if (unm_imb_write(ADDR, VALUE))		\
			return (-1);		\
	} while (0)
#define	UNM_IMB_WRITELIT_CHECK(ADDR, VALUE)			\
	do {						\
		if (unm_imb_writelit64(ADDR, VALUE))	\
			return (-1);	\
	} while (0)

/*
 * Configuration registers.
 */
#ifdef PCIX
#define	UNM_DMA_BASE(U)    (UNM_CRB_PCIX_HOST + 0x20000 + ((U)<<16))
#else
#define	UNM_DMA_BASE(U)    (UNM_CRB_PCIX_MD + 0x20000 + ((U)<<16))
#endif
#define	UNM_DMA_COMMAND(U)    (UNM_DMA_BASE(U) + 0x00008)


#define	PCIE_SEM2_LOCK		(0x1c010)  /* Flash lock  */
#define	PCIE_SEM2_UNLOCK	(0x1c014)  /* Flash unlock */
#define	PCIE_SEM3_LOCK		(0x1c018)  /* Phy lock */
#define	PCIE_SEM3_UNLOCK	(0x1c01c)  /* Phy unlock */
#define	PCIE_SEM4_LOCK		(0x1c020)  /* I2C lock */
#define	PCIE_SEM4_UNLOCK	(0x1c024)  /* I2C unlock */
#define	PCIE_SEM5_LOCK		(0x1c028)  /* API lock */
#define	PCIE_SEM5_UNLOCK	(0x1c02c)  /* API unlock */
#define	PCIE_SEM6_LOCK		(0x1c030)  /* sw lock */
#define	PCIE_SEM6_UNLOCK	(0x1c034)  /* sw unlock */
#define	PCIE_SEM7_LOCK		(0x1c038)  /* crb win lock */
#define	PCIE_SEM7_UNLOCK	(0x1c03c)  /* crbwin unlock */


#define	PCIE_PS_STRAP_RESET	(0x18000)

#define	M25P_INSTR_WREN		0x06
#define	M25P_INSTR_RDSR		0x05
#define	M25P_INSTR_PP		0x02
#define	M25P_INSTR_SE		0xd8
#define	CAM_RAM_P2I_ENABLE	0xc
#define	CAM_RAM_P2D_ENABLE	0x8
#define	PCIX_IMBTAG			(0x18004)
#define	UNM_MAC_ADDR_CNTL_REG	(UNM_CRB_NIU + 0x1000)

#define	UNM_MULTICAST_ADDR_HI_0		(UNM_CRB_NIU + 0x1010)
#define	UNM_MULTICAST_ADDR_HI_1		(UNM_CRB_NIU + 0x1014)
#define	UNM_MULTICAST_ADDR_HI_2		(UNM_CRB_NIU + 0x1018)
#define	UNM_MULTICAST_ADDR_HI_3		(UNM_CRB_NIU + 0x101c)

#define	M_UNICAST_ADDR_BASE			(UNM_CRB_NIU + 0x1080)

#define	UNM_UNICAST_ADDR_LO_0_0		(UNM_CRB_NIU + 0x1080) // port 0
#define	UNM_UNICAST_ADDR_HI_0_0		(UNM_CRB_NIU + 0x1084)
#define	UNM_UNICAST_ADDR_LO_0_1		(UNM_CRB_NIU + 0x1088)
#define	UNM_UNICAST_ADDR_HI_0_1		(UNM_CRB_NIU + 0x108c)
#define	UNM_UNICAST_ADDR_LO_0_2		(UNM_CRB_NIU + 0x1090)
#define	UNM_UNICAST_ADDR_HI_0_2		(UNM_CRB_NIU + 0x1084)
#define	UNM_UNICAST_ADDR_LO_0_3		(UNM_CRB_NIU + 0x1098)
#define	UNM_UNICAST_ADDR_HI_0_3		(UNM_CRB_NIU + 0x109c)

#define	UNM_UNICAST_ADDR_LO_1_0		(UNM_CRB_NIU + 0x10a0)
#define	UNM_UNICAST_ADDR_HI_1_0		(UNM_CRB_NIU + 0x10a4)
#define	UNM_UNICAST_ADDR_LO_1_1		(UNM_CRB_NIU + 0x10a8)
#define	UNM_UNICAST_ADDR_HI_1_1		(UNM_CRB_NIU + 0x10ac)
#define	UNM_UNICAST_ADDR_LO_1_2		(UNM_CRB_NIU + 0x10b0)
#define	UNM_UNICAST_ADDR_HI_1_2		(UNM_CRB_NIU + 0x10b4)
#define	UNM_UNICAST_ADDR_LO_1_3		(UNM_CRB_NIU + 0x10b8)
#define	UNM_UNICAST_ADDR_HI_1_3		(UNM_CRB_NIU + 0x10bc)

#define	UNM_UNICAST_ADDR_LO_2_0		(UNM_CRB_NIU + 0x10c0)
#define	UNM_UNICAST_ADDR_HI_2_0		(UNM_CRB_NIU + 0x10c4)
#define	UNM_UNICAST_ADDR_LO_2_1		(UNM_CRB_NIU + 0x10c8)
#define	UNM_UNICAST_ADDR_HI_2_1		(UNM_CRB_NIU + 0x10cc)
#define	UNM_UNICAST_ADDR_LO_2_2		(UNM_CRB_NIU + 0x10d0)
#define	UNM_UNICAST_ADDR_HI_2_2		(UNM_CRB_NIU + 0x10d4)
#define	UNM_UNICAST_ADDR_LO_2_3		(UNM_CRB_NIU + 0x10d8)
#define	UNM_UNICAST_ADDR_HI_2_3		(UNM_CRB_NIU + 0x10dc)

#define	UNM_UNICAST_ADDR_LO_3_0		(UNM_CRB_NIU + 0x10e0)
#define	UNM_UNICAST_ADDR_HI_3_0		(UNM_CRB_NIU + 0x10e4)
#define	UNM_UNICAST_ADDR_LO_3_1		(UNM_CRB_NIU + 0x10e8)
#define	UNM_UNICAST_ADDR_HI_3_1		(UNM_CRB_NIU + 0x10ec)
#define	UNM_UNICAST_ADDR_LO_3_2		(UNM_CRB_NIU + 0x10f0)
#define	UNM_UNICAST_ADDR_HI_3_2		(UNM_CRB_NIU + 0x10f4)
#define	UNM_UNICAST_ADDR_LO_3_3		(UNM_CRB_NIU + 0x10f8)
#define	UNM_UNICAST_ADDR_HI_3_3		(UNM_CRB_NIU + 0x10fc)

#define	UNM_MULTICAST_ADDR_BASE		(UNM_CRB_NIU + 0x1100)

// BASE ADDRESS FOR POOL/PORT 0
#define	UNM_MULTICAST_ADDR_LO_0		(UNM_CRB_NIU + 0x1100)
// FOR PORT 1
#define	UNM_MULTICAST_ADDR_LO_1		(UNM_CRB_NIU + 0x1180)
// FOR PORT 2
#define	UNM_MULTICAST_ADDR_LO_2		(UNM_CRB_NIU + 0x1200)
// PORT 3
#define	UNM_MULTICAST_ADDR_LO_3		(UNM_CRB_NIU + 0x1280)

#define	PHAN_VENDOR_ID			0x4040

#define	CAM_RAM_PEG_ENABLES  0x4

/*
 * The PCI VendorID and DeviceID for our board.
 */
#define	PCI_VENDOR_ID_NX			0x4040
#define	PCI_DEVICE_ID_NX_XG			0x0001
#define	PCI_DEVICE_ID_NX_CX4		0x0002
#define	PCI_DEVICE_ID_NX_QG			0x0003
#define	PCI_DEVICE_ID_NX_IMEZ		0x0004
#define	PCI_DEVICE_ID_NX_HMEZ		0x0005
#define	PCI_DEVICE_ID_NX_IMEZ_DUP	0x0024
#define	PCI_DEVICE_ID_NX_HMEZ_DUP	0x0025
#define	PCI_DEVICE_ID_NX_P3_XG		0x0100

/*
 * Time base tick control registers (global and per-flow).
 */

typedef struct {
	/* half period of time cycle */
	/* global: in units of core clock */
	/* per-flow: in units of global ticks */
    unm_crbword_t   count:16,
					rsvd:15,
					enable:1;   /* 0=disable, 1=enable */
} unm_timer_tickctl_t;


typedef struct
{
	unm_crbword_t
	id_pool_0:2,
	enable_xtnd_0:1,
	rsvd1:1,
	id_pool_1:2,
	enable_xtnd_1:1,
	rsvd2:1,
	id_pool_2:2,
	enable_xtnd_2:1,
	rsvd3:1,
	id_pool_3:2,
	enable_xtnd_3:1,
    rsvd4:9,
	mode_select:2,
	rsvd5:2,
	enable_pool:4;
} unm_mac_addr_cntl_t;

typedef struct {
    unm_crbword_t	start:1,
					enable:1,
					command:1,
					busy:1,
					rsvd:28;
} unm_miu_test_agt_ctrl_t;

#define	UNM_MIU_TEST_AGENT_CMD_READ 0
#define	UNM_MIU_TEST_AGENT_CMD_WRITE 1
#define	UNM_MIU_TEST_AGENT_BUSY 1
#define	UNM_MIU_TEST_AGENT_ENABLE 1
#define	UNM_MIU_TEST_AGENT_START 1

#define	UNM_MIU_MN_CONTROL		(UNM_CRB_DDR_NET + MIU_CONTROL)
#define	UNM_MIU_MN_TAG			(UNM_CRB_DDR_NET + MIU_TAG)
#define	UNM_MIU_MN_TEST_AGT_ADDR_LO   (UNM_CRB_DDR_NET + MIU_TEST_AGT_ADDR_LO)
#define	UNM_MIU_MN_TEST_AGT_ADDR_HI   (UNM_CRB_DDR_NET + MIU_TEST_AGT_ADDR_HI)
#define	UNM_MIU_MN_TEST_AGT_WRDATA_LO (UNM_CRB_DDR_NET + MIU_TEST_AGT_WRDATA_LO)
#define	UNM_MIU_MN_TEST_AGT_WRDATA_HI (UNM_CRB_DDR_NET + MIU_TEST_AGT_WRDATA_HI)
#define	UNM_MIU_MN_TEST_AGT_CTRL	(UNM_CRB_DDR_NET + MIU_TEST_AGT_CTRL)
#define	UNM_MIU_MN_TEST_AGT_RDDATA_LO (UNM_CRB_DDR_NET + MIU_TEST_AGT_RDDATA_LO)
#define	UNM_MIU_MN_TEST_AGT_RDDATA_HI (UNM_CRB_DDR_NET + MIU_TEST_AGT_RDDATA_HI)

#define	UNM_SIU_SN_TEST_AGT_ADDR_LO   (UNM_CRB_QDR_NET + SIU_TEST_AGT_ADDR_LO)
#define	UNM_SIU_SN_TEST_AGT_ADDR_HI   (UNM_CRB_QDR_NET + SIU_TEST_AGT_ADDR_HI)
#define	UNM_SIU_SN_TEST_AGT_WRDATA_LO (UNM_CRB_QDR_NET + SIU_TEST_AGT_WRDATA_LO)
#define	UNM_SIU_SN_TEST_AGT_WRDATA_HI (UNM_CRB_QDR_NET + SIU_TEST_AGT_WRDATA_HI)
#define	UNM_SIU_SN_TEST_AGT_CTRL	(UNM_CRB_QDR_NET + SIU_TEST_AGT_CTRL)
#define	UNM_SIU_SN_TEST_AGT_RDDATA_LO (UNM_CRB_QDR_NET + SIU_TEST_AGT_RDDATA_LO)
#define	UNM_SIU_SN_TEST_AGT_RDDATA_HI (UNM_CRB_QDR_NET + SIU_TEST_AGT_RDDATA_HI)

#define	NX_IS_SYSTEM_CUT_THROUGH(MIU_CTRL)	(((MIU_CTRL) & 0x4) ? 1 : 0)
#define	NX_SET_SYSTEM_LEGACY(MIU_CTRL)		{(MIU_CTRL) &= ~0x4; }
#define	NX_SET_SYSTEM_CUT_THROUGH(MIU_CTRL)	{(MIU_CTRL) |= 0x4; }

#ifdef __cplusplus
}
#endif

#endif /* _UNM_INC_H_ */
