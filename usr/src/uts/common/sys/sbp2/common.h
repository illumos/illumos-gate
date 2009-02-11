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

#ifndef	_SYS_SBP2_COMMON_H
#define	_SYS_SBP2_COMMON_H

/*
 * Serial Bus Protocol 2 (SBP-2) common definitions
 */

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef _LITTLE_ENDIAN
#define	SBP2_SWAP16(data)	\
	((((data) & 0xff) << 8) | ((data) >> 8))

#define	SBP2_SWAP32(data)	\
	(((uint32_t)SBP2_SWAP16((uint16_t)((data) & 0xffff)) << 16) | \
	(uint32_t)SBP2_SWAP16((uint16_t)((data) >> 16)))

#define	SBP2_SWAP16_1(data)	(data) = SBP2_SWAP16(data)
#define	SBP2_SWAP32_1(data)	(data) = SBP2_SWAP32(data)

#define	SBP2_SWAP16_2(data)	\
	((uint16_t *)(data))[0] = SBP2_SWAP16(((uint16_t *)(data))[0]);	\
	((uint16_t *)(data))[1] = SBP2_SWAP16(((uint16_t *)(data))[1]);

#define	SBP2_SWAP32_2(data)	\
	((uint32_t *)(data))[0] = SBP2_SWAP32(((uint32_t *)(data))[0]);	\
	((uint32_t *)(data))[1] = SBP2_SWAP32(((uint32_t *)(data))[1]);

#define	SBP2_SWAP32_BUF(data, len)	sbp2_swap32_buf((uint32_t *)data, len)

#else
#define	SBP2_SWAP16(data)	(data)
#define	SBP2_SWAP32(data)	(data)
#define	SBP2_SWAP16_1(data)
#define	SBP2_SWAP32_1(data)
#define	SBP2_SWAP16_2(data)
#define	SBP2_SWAP32_2(data)
#define	SBP2_SWAP32_BUF(data, len)
#endif

/*
 * serial bus address: it is a 64-bit value, but ORB structures require quadlet
 * (32-bit) alignment, so it is defined as two quadlets rather than one octlet
 */
typedef uint32_t sbp2_addr_t[2];

#define	SBP2_ADDR_NODE_ID		0xFFFF000000000000ULL
#define	SBP2_ADDR_NODE_ID_SHIFT		48
#define	SBP2_ADDR_OFFSET		0x0000FFFFFFFFFFFCULL

#define	SBP2_OFFSET_HI(offset)		(((offset) & SBP2_ADDR_OFFSET) >> 32)
#define	SBP2_OFFSET_LO(offset)		(((offset) & SBP2_ADDR_OFFSET))

#define	SBP2_ADDR_SET(var, addr, node_ID) { \
		((uint32_t *)(var))[0] = SBP2_SWAP32(((addr) | \
		((uint64_t)(node_ID) << SBP2_ADDR_NODE_ID_SHIFT)) >> 32); \
		((uint32_t *)(var))[1] = SBP2_SWAP32(SBP2_OFFSET_LO(addr)); \
	}

#define	SBP2_ADDR2UINT64(addr)	((((uint64_t)(addr)[0])) << 32) | ((addr)[1])

/* ORB pointer: serial bus address without node ID */
typedef uint32_t sbp2_orbp_t[2];

#define	SBP2_ORBP_NULL			0x8000000000000000ULL
#define	SBP2_ORBP_OFFSET		0x0000FFFFFFFFFFFCULL
#define	SBP2_ORBP_MASK			(SBP2_ORBP_NULL | SBP2_ORBP_OFFSET)

#define	SBP2_ORBP_HI(orbp)		\
		((uint32_t)(((orbp) & SBP2_ORBP_MASK) >> 32))
#define	SBP2_ORBP_LO(orbp)		((uint32_t)((orbp) & SBP2_ORBP_MASK))

#define	SBP2_ORBP_SET(var, orbp) { \
		((uint32_t *)(var))[0] = SBP2_SWAP32(SBP2_ORBP_HI(orbp)); \
		((uint32_t *)(var))[1] = SBP2_SWAP32(SBP2_ORBP_LO(orbp)); \
	}

#define	SBP2_ORBP2UINT64(orbp) \
	((((uint64_t)(orbp)[0] << 32) | (orbp)[1]) & SBP2_ORBP_OFFSET)


/*
 * return codes
 * NOTE: SBP2_SUCCESS/FAILURE values should be the same as DDI_SUCCESS/FAILURE
 */
enum {
	SBP2_SUCCESS		= 0,
	SBP2_FAILURE		= -1,	/* generic/undefined failure */
	SBP2_EINVAL		= 1,	/* invalid arguments */
	SBP2_ENOMEM		= 2,	/* memory not available */
	SBP2_EIO		= 3,	/* I/O operation failed */
	SBP2_EBUSY		= 4,	/* device busy */
	SBP2_EADDR		= 5,	/* wrong address */
	SBP2_EDEAD		= 6,	/* agent dead */
	SBP2_ETIMEOUT		= 7,	/* operation timed out */
	SBP2_ECFGROM		= 8,	/* bad/corrupted Config ROM */
	SBP2_EALREADY		= 9,	/* already exists/completed/etc */
	SBP2_ESTALE		= 10,	/* stale login session */
	SBP2_EDATA		= 11,	/* bad/corrupted data */
	SBP2_ENODEV		= 12,	/* device not there */
	SBP2_ECONTEXT		= 13	/* bad context for I/O operation */
};

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SBP2_COMMON_H */
