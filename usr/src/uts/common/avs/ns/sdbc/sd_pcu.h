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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SD_PCU_H
#define	_SD_PCU_H

/*
 * All structures here are on-disk, unless specified otherwise.
 * In-core stuff is hidden inside implementation modules.
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Header.
 */
#define	SDBC_PWF_MAGIC	0xbcbcbc01

typedef struct sdbc_pwf_hdr_s {
	int32_t magic;		/* magic number to distinguish file revs */
	int32_t alignment;	/* all sections are multiples of this */
				/* a cache block is this identical size */
	int32_t bmap_size;	/* number of entries in each bitmap entry */
	int32_t cd_count;	/* number of devices we have data for */
	nsc_off_t string_pool;	/* offset in file to pool of filenames */
	nsc_off_t descriptor_pool; /* offset in file to dbc_pwf_desc_t vector */
	int64_t dump_time;	/* Timestamp == longest time_t */
} sdbc_pwf_hdr_t;

/*
 * File description
 */
typedef struct sdbc_pwf_desc_s {
	int32_t pad0;
	uint32_t name;		/* name + stringpool == offset of filename */
				/* the name given to nsc_open */
	nsc_off_t blocks;	/* offset into swap for this device's data */
	nsc_off_t bitmaps;	/* offset into swap for data bitmaps */
				/* (i.e. nothing to do with rdc bitmaps */
	uint64_t nblocks;	/* number of data blocks == bitmap dimension */
	/* long	rdc_data; */	/* offset to rdc data (NYI) */
} sdbc_pwf_desc_t;

/*
 * record status section - describes the state of each cache block in the file
 *
 * zaitcev - XXX errs is per block, not per fba?
 */
typedef struct sdbc_pwf_rec_s {
	uint32_t dirty;		/* Bitmap of dirty fba'a (_sd_bitmap_t) */
	int32_t errs;	/* error status per fba, needed to recover */
			/* from errors to a raidset where we must recover */
			/* from a stripe write error */
			/* (i.e. parity is bad or suspect ) */
	nsc_off_t fba_num;	/* the block on the disk */
} sdbc_pwf_rec_t;

typedef struct sdbc_pwf_bitmap_s {
	sdbc_pwf_rec_t bitmaps[1]; /* dynamic array based on cache block size */
} sdbc_pwf_bitmap_t;

/*
 * Prototypes
 */
#ifdef _KERNEL	/* XXX Split into sd_pcu_ondisk.h, sd_pcu_iface.h */
extern char _sdbc_shutdown_in_progress;

extern int _sdbc_pcu_config(int c, char **v);
extern void _sdbc_pcu_unload(void);
extern void _sdbc_power_lost(int rideout);
extern void _sdbc_power_ok(void);
extern void _sdbc_power_down(void);
#endif

#ifdef __cplusplus
}
#endif

#endif	/* _SD_PCU_H */
