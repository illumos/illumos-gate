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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_BGE_H
#define	_SYS_BGE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>

/*
 * Name of the driver
 */
#define	BGE_DRIVER_NAME		"bge"

/*
 * The driver supports the NDD ioctls ND_GET/ND_SET, and the loopback
 * ioctls LB_GET_INFO_SIZE/LB_GET_INFO/LB_GET_MODE/LB_SET_MODE
 *
 * These are the values to use with LD_SET_MODE.
 * Note: they may not all be supported on any given chip/driver.
 */
#define	BGE_LOOP_NONE		0
#define	BGE_LOOP_EXTERNAL_1000	1	/* with Gbit loopback cable	*/
#define	BGE_LOOP_EXTERNAL_100	2	/* with loopback cable		*/
#define	BGE_LOOP_EXTERNAL_10	3	/* with loopback cable		*/
#define	BGE_LOOP_INTERNAL_PHY	4
#define	BGE_LOOP_INTERNAL_MAC	5

/*
 * BGE-specific ioctls ...
 */
#define	BGE_IOC			((((('B' << 8) + 'G') << 8) + 'E') << 8)

/*
 * PHY register read/write ioctls, used by cable test software
 */
#define	BGE_MII_READ		(BGE_IOC|1)
#define	BGE_MII_WRITE		(BGE_IOC|2)

struct bge_mii_rw {
	uint32_t	mii_reg;	/* PHY register number [0..31]	*/
	uint32_t	mii_data;	/* data to write/data read	*/
};

/*
 * SEEPROM read/write ioctls, for use by SEEPROM upgrade utility
 *
 * Note: SEEPROMs can only be accessed as 32-bit words, so <see_addr>
 * must be a multiple of 4.  Not all systems have a SEEPROM fitted!
 */
#define	BGE_SEE_READ		(BGE_IOC|3)
#define	BGE_SEE_WRITE		(BGE_IOC|4)

struct bge_see_rw {
	uint32_t	see_addr;	/* Byte offset within SEEPROM	*/
	uint32_t	see_data;	/* Data read/data to write	*/
};

/*
 * Flash read/write ioctls, for flash upgrade utility
 *
 * Note: flash can only be accessed as 32-bit words, so <flash_addr>
 * must be a multiple of 4. Not all systems have flash fitted!
 */
#define	BGE_FLASH_READ		(BGE_IOC|5)
#define	BGE_FLASH_WRITE		(BGE_IOC|6)

struct bge_flash_rw {
	uint32_t	flash_addr;	/* Byte offset within flash	*/
	uint32_t	flash_data;	/* Data read/data to write	*/
};

/*
 * These diagnostic IOCTLS are enabled only in DEBUG drivers
 */
#define	BGE_DIAG		(BGE_IOC|10)	/* currently a no-op	*/
#define	BGE_PEEK		(BGE_IOC|11)
#define	BGE_POKE		(BGE_IOC|12)
#define	BGE_PHY_RESET		(BGE_IOC|13)
#define	BGE_SOFT_RESET		(BGE_IOC|14)
#define	BGE_HARD_RESET		(BGE_IOC|15)

typedef struct {
	uint64_t		pp_acc_size;	/* in bytes: 1,2,4,8	*/
	uint64_t		pp_acc_space;	/* See #defines below	*/
	uint64_t		pp_acc_offset;
	uint64_t		pp_acc_data;	/* output for peek	*/
						/* input for poke	*/
} bge_peekpoke_t;

#define	BGE_PP_SPACE_CFG	0		/* PCI config space	*/
#define	BGE_PP_SPACE_REG	1		/* PCI memory space	*/
#define	BGE_PP_SPACE_NIC	2		/* on-chip memory	*/
#define	BGE_PP_SPACE_MII	3		/* PHY's MII registers	*/
#define	BGE_PP_SPACE_BGE	4		/* driver's soft state	*/
#define	BGE_PP_SPACE_TXDESC	5		/* TX descriptors	*/
#define	BGE_PP_SPACE_TXBUFF	6		/* TX buffers		*/
#define	BGE_PP_SPACE_RXDESC	7		/* RX descriptors	*/
#define	BGE_PP_SPACE_RXBUFF	8		/* RX buffers		*/
#define	BGE_PP_SPACE_STATUS	9		/* status block		*/
#define	BGE_PP_SPACE_STATISTICS	10		/* statistics block	*/
#define	BGE_PP_SPACE_SEEPROM	11		/* SEEPROM (if fitted)	*/
#define	BGE_PP_SPACE_FLASH	12		/* FLASH (if fitted)    */

#define	BGE_IPMI_ASF

/*
 * Enable BGE_NETCONSOLE only with SPARC
 */
#ifdef __sparc
#define	BGE_NETCONSOLE
#endif

/*
 * BGE_MAXPKT_RCVED is defined to make sure bge does not stick
 * in a receiving loop too long. This value is the tuning result
 * of performance testing on sparc/x86 platforms, with regarding
 * to throughput/latency/CPU utilization, TCP/UDP
 */
#define	BGE_MAXPKT_RCVED	32

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_BGE_H */
