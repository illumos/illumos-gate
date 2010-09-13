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

#ifndef	_SYS_NXGE_NXGE_ESPC_H
#define	_SYS_NXGE_NXGE_ESPC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <nxge_espc_hw.h>

#define	ESPC_MAC_ADDR_0		ESPC_NCR_REGN(0)
#define	ESPC_MAC_ADDR_1		ESPC_NCR_REGN(1)
#define	ESPC_NUM_PORTS_MACS	ESPC_NCR_REGN(2)
#define	ESPC_MOD_STR_LEN	ESPC_NCR_REGN(4)
#define	ESPC_MOD_STR_1		ESPC_NCR_REGN(5)
#define	ESPC_MOD_STR_2		ESPC_NCR_REGN(6)
#define	ESPC_MOD_STR_3		ESPC_NCR_REGN(7)
#define	ESPC_MOD_STR_4		ESPC_NCR_REGN(8)
#define	ESPC_MOD_STR_5		ESPC_NCR_REGN(9)
#define	ESPC_MOD_STR_6		ESPC_NCR_REGN(10)
#define	ESPC_MOD_STR_7		ESPC_NCR_REGN(11)
#define	ESPC_MOD_STR_8		ESPC_NCR_REGN(12)
#define	ESPC_BD_MOD_STR_LEN	ESPC_NCR_REGN(13)
#define	ESPC_BD_MOD_STR_1	ESPC_NCR_REGN(14)
#define	ESPC_BD_MOD_STR_2	ESPC_NCR_REGN(15)
#define	ESPC_BD_MOD_STR_3	ESPC_NCR_REGN(16)
#define	ESPC_BD_MOD_STR_4	ESPC_NCR_REGN(17)
#define	ESPC_PHY_TYPE		ESPC_NCR_REGN(18)
#define	ESPC_MAX_FM_SZ		ESPC_NCR_REGN(19)
#define	ESPC_INTR_NUM		ESPC_NCR_REGN(20)
#define	ESPC_VER_IMGSZ		ESPC_NCR_REGN(21)
#define	ESPC_CHKSUM		ESPC_NCR_REGN(22)

#define	NUM_PORTS_MASK		0xff
#define	NUM_MAC_ADDRS_MASK	0xff0000
#define	NUM_MAC_ADDRS_SHIFT	16
#define	MOD_STR_LEN_MASK	0xffff
#define	BD_MOD_STR_LEN_MASK	0xffff
#define	MAX_FM_SZ_MASK		0xffff
#define	VER_NUM_MASK		0xffff
#define	IMG_SZ_MASK		0xffff0000
#define	IMG_SZ_SHIFT		16
#define	CHKSUM_MASK		0xff

/* 0 <= n < 8 */
#define	ESPC_MOD_STR(n)		(ESPC_MOD_STR_1 + n*8)
#define	MAX_MOD_STR_LEN		32

/* 0 <= n < 4 */
#define	ESPC_BD_MOD_STR(n)	(ESPC_BD_MOD_STR_1 + n*8)
#define	MAX_BD_MOD_STR_LEN	16

#define	ESC_PHY_10G_FIBER	0x0
#define	ESC_PHY_10G_COPPER	0x1
#define	ESC_PHY_1G_FIBER	0x2
#define	ESC_PHY_1G_COPPER	0x3
#define	ESC_PHY_NONE		0xf

#define	ESC_IMG_CHKSUM_VAL	0xab

typedef union _mac_addr_0_t {
	uint64_t value;

	struct {
#if defined(_BIG_ENDIAN)
		uint32_t msw;	/* Most significant word */
		uint32_t lsw;	/* Least significant word */
#elif defined(_LITTLE_ENDIAN)
		uint32_t lsw;	/* Least significant word */
		uint32_t msw;	/* Most significant word */
#endif
	} val;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	w1;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
		uint32_t byte3		: 8;
		uint32_t byte2		: 8;
		uint32_t byte1		: 8;
		uint32_t byte0		: 8;
#elif defined(_BIT_FIELDS_LTOH)
		uint32_t byte0		: 8;
		uint32_t byte1		: 8;
		uint32_t byte2		: 8;
		uint32_t byte3		: 8;
#endif
		} w0;

#if defined(_LITTLE_ENDIAN)
		uint32_t	w1;
#endif
	} bits;
} mac_addr_0_t;

typedef union _mac_addr_1_t {
	uint64_t value;

	struct {
#if defined(_BIG_ENDIAN)
		uint32_t msw;	/* Most significant word */
		uint32_t lsw;	/* Least significant word */
#elif defined(_LITTLE_ENDIAN)
		uint32_t lsw;	/* Least significant word */
		uint32_t msw;	/* Most significant word */
#endif
	} val;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	w1;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
		uint32_t res		: 16;
		uint32_t byte5		: 8;
		uint32_t byte4		: 8;
#elif defined(_BIT_FIELDS_LTOH)
		uint32_t byte4		: 8;
		uint32_t byte5		: 8;
		uint32_t res		: 16;
#endif
		} w0;

#if defined(_LITTLE_ENDIAN)
		uint32_t	w1;
#endif
	} bits;
} mac_addr_1_t;


typedef union _phy_type_t {
	uint64_t value;

	struct {
#if defined(_BIG_ENDIAN)
		uint32_t msw;	/* Most significant word */
		uint32_t lsw;	/* Least significant word */
#elif defined(_LITTLE_ENDIAN)
		uint32_t lsw;	/* Least significant word */
		uint32_t msw;	/* Most significant word */
#endif
	} val;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	w1;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
		uint32_t pt0_phy_type	: 8;
		uint32_t pt1_phy_type	: 8;
		uint32_t pt2_phy_type	: 8;
		uint32_t pt3_phy_type	: 8;
#elif defined(_BIT_FIELDS_LTOH)
		uint32_t pt3_phy_type	: 8;
		uint32_t pt2_phy_type	: 8;
		uint32_t pt1_phy_type	: 8;
		uint32_t pt0_phy_type	: 8;
#endif
		} w0;

#if defined(_LITTLE_ENDIAN)
		uint32_t	w1;
#endif
	} bits;
} phy_type_t;


typedef union _intr_num_t {
	uint64_t value;

	struct {
#if defined(_BIG_ENDIAN)
		uint32_t msw;	/* Most significant word */
		uint32_t lsw;	/* Least significant word */
#elif defined(_LITTLE_ENDIAN)
		uint32_t lsw;	/* Least significant word */
		uint32_t msw;	/* Most significant word */
#endif
	} val;
	struct {
#if defined(_BIG_ENDIAN)
		uint32_t	w1;
#endif
		struct {
#if defined(_BIT_FIELDS_HTOL)
		uint32_t pt0_intr_num	: 8;
		uint32_t pt1_intr_num	: 8;
		uint32_t pt2_intr_num	: 8;
		uint32_t pt3_intr_num	: 8;
#elif defined(_BIT_FIELDS_LTOH)
		uint32_t pt3_intr_num	: 8;
		uint32_t pt2_intr_num	: 8;
		uint32_t pt1_intr_num	: 8;
		uint32_t pt0_intr_num	: 8;
#endif
		} w0;

#if defined(_LITTLE_ENDIAN)
		uint32_t	w1;
#endif
	} bits;
} intr_num_t;


#ifdef __cplusplus
}
#endif

#endif	/* _SYS_NXGE_NXGE_ESPC_H */
