/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 * Copyright (c) 2011 Gary Mills
 * Copyright 2024 MNX Cloud, Inc.
 */

#ifndef _PCFS_COMMON_H
#define	_PCFS_COMMON_H

/*
 * Common routines for the pcfs user-level utilities
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <sys/isa_defs.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include "pcfs_bpb.h"

#define	IN_RANGE(n, x, y) (((n) >= (x)) && ((n) <= (y)))

/*
 *  A macro implementing a ceiling function for integer divides.
 */
#define	idivceil(dvend, dvsor) \
	((dvend)/(dvsor) + (((dvend)%(dvsor) == 0) ? 0 : 1))

/*
 * These defines should move into a kernel header file eventually
 * and pcfs_mount may want to refuse to mount FAT32's that aren't "clean"
 *
 *	If Windows shuts down properly it sets the fourth bit of the 8th
 *	and final reserved byte at the start of the FAT.
 */
#define	WIN_SHUTDOWN_STATUS_BYTE	7
#define	WIN_SHUTDOWN_BIT_MASK		0x8

/*
 *  Define some special logical drives we use.
 */
#define	BOOT_PARTITION_DRIVE	99
#define	PRIMARY_DOS_DRIVE	1

/*
 * Function prototypes
 */
extern off64_t findPartitionOffset(int fd, size_t bpsec, char *ldrive);
extern char *stat_actual_disk(const char *diskname, struct stat *info,
	char **suffix);
extern void header_for_dump(void);
extern void store_16_bits(uchar_t **bp, uint32_t v);
extern void store_32_bits(uchar_t **bp, uint32_t v);
extern void read_16_bits(uchar_t *bp, uint32_t *value);
extern void read_32_bits(uchar_t *bp, uint32_t *value);
extern void missing_arg(char *option);
extern void dump_bytes(uchar_t *b, int n);
extern void bad_arg(char *option);
extern void usage(void);
extern bool is_sector_size_valid(size_t size);
extern int  get_media_sector_size(int fd, size_t *sizep);

/*
 *	The assumption here is that _BIG_ENDIAN implies sparc, and
 *	so in addition to swapping bytes we also have to construct
 *	packed structures by hand to avoid bus errors due to improperly
 *	aligned pointers.
 */
#ifdef _BIG_ENDIAN
extern void swap_pack_grab32bpb(bpb_t *wbpb, struct _boot_sector *bsp);
extern void swap_pack_grabbpb(bpb_t *wbpb, struct _boot_sector *bsp);
#endif	/* _BIG_ENDIAN */

#ifdef __cplusplus
}
#endif

#endif /* _PCFS_COMMON_H */
