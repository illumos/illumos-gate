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
 *
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright 2019 Joyent, Inc.
 * Copyright 2022 Oxide Computer Company
 */

#ifndef _SYS_MC_H
#define	_SYS_MC_H

/*
 * Public interfaces exposed by the memory controller driver
 */

#include <sys/cpuvar.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	MC_UNUM_NAMLEN		192
#define	MC_UNUM_NDIMM		2

typedef struct mc_unum {
	int unum_board;			/* system board */
	int unum_chip;			/* chip/socket */
	int unum_mc;			/* memory-controller or branch */
	int unum_chan;			/* DRAM channel */
	int unum_cs;			/* chip-select */
	int unum_rank;			/* rank */
	uint64_t unum_offset;		/* row, column, bank-select etc */
	int unum_dimms[MC_UNUM_NDIMM];
} mc_unum_t;

/*
 * Invalid marker used in some numeric properties
 */
#define	MC_INVALNUM		((uint32_t)-1)

/*
 * /dev/mc/mc* ioctl cmds
 */
#define	MC_IOC			(0x4d43 << 16)
#define	MC_IOC_SNAPSHOT_INFO	(MC_IOC | 1)
#define	MC_IOC_SNAPSHOT		(MC_IOC | 2)
#define	MC_IOC_ONLINESPARE_EN	(MC_IOC | 4)
#define	MC_IOC_DECODE_PA	(MC_IOC | 5)
#define	MC_IOC_DECODE_SNAPSHOT_INFO	(MC_IOC | 6)
#define	MC_IOC_DECODE_SNAPSHOT	(MC_IOC | 7)

/*
 * Prior to requesting a copy of the snapshot, consumers are advised to request
 * information regarding the snapshot.  An mc_snapshot_info_t will be returned,
 * containing the snapshot size as well as the snapshot generation number.  Note
 * that, due to the potentially dynamic nature of the system, the snapshot may
 * change at any time.  As such, the information in the mc_snapshot_info_t may
 * be out of date by the time it is used.  The generation number is used to
 * track snapshot changes.  That is, the generation number will be updated each
 * time the source data for the snapshot is updated.  The consumer should not
 * attach any meaning to the magnitude of a generation number change, and pay
 * attention only to the fact that the number has changed.
 */
typedef struct mc_snapshot_info {
	uint32_t mcs_size;	/* snapshot size */
	uint_t mcs_gen;		/* snapshot generation number */
} mc_snapshot_info_t;

/*
 * Data used to simulate encoding or decoding of a physical / DIMM address.
 * These are used in different ways between AMD and Intel, so this is a bit of a
 * smorgasbord. Details about each field are listed below.
 */
typedef struct mc_encode_ioc {
	/*
	 * The first three values here are different addresses. We have a
	 * physical / system address. A DRAM-channel relative address, and
	 * finally a rank-relative address. Where a platform does not support
	 * one of these, UINT64_MAX is used.
	 */
	uint64_t	mcei_pa;
	uint64_t	mcei_chan_addr;
	uint64_t	mcei_rank_addr;
	/*
	 * These next two provide a way for the memory controller software
	 * driver to provide additional information. The mcei_err generally
	 * corresponds to an enum that the driver has and the errdata is
	 * error-specific data that can be useful.
	 */
	uint64_t	mcei_errdata;
	uint32_t	mcei_err;
	/*
	 * This next set is used to identify information about where to find a
	 * DIMM in question. The board and chip are used to uniquely identify a
	 * socket. Generally on x86, there is only one board, so it would be
	 * zero. The chip should correspond to the socket ID. The die refers to
	 * a particular internal die if on a chiplet or MCP. The memory
	 * controller and channel refer to a unique instance of both within a
	 * given die. On platforms where the memory controller and channel are
	 * 1:1 (that is each memory controller has only a single channel or
	 * doesn't have a specific distinction between the two), set chan to 0
	 * and set the mc to the logical channel value. The DIMM is a relative
	 * DIMM in the channel, meaning it's usually going to be 0, 1, or 2.
	 */
	uint32_t	mcei_board;
	uint32_t	mcei_chip;
	uint32_t	mcei_die;
	uint32_t	mcei_mc;
	uint32_t	mcei_chan;
	uint32_t	mcei_dimm;
	/*
	 * These values all refer to information on the DIMM itself and identify
	 * how to find the address. mcei_rank is meant to be a logical rank;
	 * however, some systems phrase things that way while others phrase
	 * things in terms of a chip select and rank multiplication. For unknown
	 * entries use UINT8_MAX.
	 */
	uint32_t	mcei_row;
	uint32_t	mcei_column;
	uint8_t		mcei_rank;
	uint8_t		mcei_cs;
	uint8_t		mcei_rm;
	uint8_t		mcei_bank;
	uint8_t		mcei_bank_group;
	uint8_t		mcei_subchan;
	uint8_t		mcei_pad[6];
} mc_encode_ioc_t;

#ifdef __cplusplus
}
#endif

#endif /* _SYS_MC_H */
