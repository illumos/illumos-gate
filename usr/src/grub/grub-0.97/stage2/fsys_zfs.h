/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 1999,2000,2001,2002,2003,2004  Free Software Foundation, Inc.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

/*
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2012 by Delphix. All rights reserved.
 * Copyright (c) 2013 by Saso Kiselkov. All rights reserved.
 */

#ifndef _FSYS_ZFS_H
#define	_FSYS_ZFS_H

#ifdef	FSYS_ZFS

#ifndef	FSIMAGE
typedef unsigned long long uint64_t;
typedef unsigned int uint32_t;
typedef unsigned short uint16_t;
typedef unsigned char uint8_t;
typedef unsigned char uchar_t;

#if defined(_LP64) || defined(_I32LPx)
typedef	unsigned long size_t;
#else
typedef	unsigned int size_t;
#endif
#else
#include "fsi_zfs.h"
#endif	/* !FSIMAGE */

#include <zfs-include/zfs.h>
#include <zfs-include/dmu.h>
#include <zfs-include/spa.h>
#include <zfs-include/zio.h>
#include <zfs-include/zio_checksum.h>
#include <zfs-include/vdev_impl.h>
#include <zfs-include/zap_impl.h>
#include <zfs-include/zap_leaf.h>
#include <zfs-include/uberblock_impl.h>
#include <zfs-include/dnode.h>
#include <zfs-include/dsl_dir.h>
#include <zfs-include/zfs_acl.h>
#include <zfs-include/zfs_znode.h>
#include <zfs-include/dsl_dataset.h>
#include <zfs-include/zil.h>
#include <zfs-include/dmu_objset.h>
#include <zfs-include/sa_impl.h>

/*
 * Global Memory addresses to store MOS and DNODE data
 */
#define	MOS		((dnode_phys_t *)\
	(RAW_ADDR((mbi.mem_upper << 10) + 0x100000) - ZFS_SCRATCH_SIZE))
#define	DNODE		(MOS+1) /* move sizeof(dnode_phys_t) bytes */
#define	ZFS_SCRATCH	((char *)(DNODE+1))

/*
 * Verify dnode type.
 * Can only be used in functions returning non-0 for failure.
 */
#define	VERIFY_DN_TYPE(dnp, type) \
	if (type && (dnp)->dn_type != type) { \
		return (ERR_FSYS_CORRUPT); \
	}

/*
 * Verify object set type.
 * Can only be used in functions returning 0 for failure.
 */
#define	VERIFY_OS_TYPE(osp, type) \
	if (type && (osp)->os_type != type) { \
		errnum = ERR_FSYS_CORRUPT; \
		return (0); \
	}

#define	ZPOOL_PROP_BOOTFS		"bootfs"

/* General macros */
#define	BSWAP_8(x)	((x) & 0xff)
#define	BSWAP_16(x)	((BSWAP_8(x) << 8) | BSWAP_8((x) >> 8))
#define	BSWAP_32(x)	((BSWAP_16(x) << 16) | BSWAP_16((x) >> 16))
#define	BSWAP_64(x)	((BSWAP_32(x) << 32) | BSWAP_32((x) >> 32))
#define	P2ROUNDUP(x, align)	(-(-(x) & -(align)))

typedef struct uberblock uberblock_t;

/*
 * Macros to get fields in a bp or DVA.
 */
#define	P2PHASE(x, align)		((x) & ((align) - 1))
#define	DVA_OFFSET_TO_PHYS_SECTOR(offset) \
	((offset + VDEV_LABEL_START_SIZE) >> SPA_MINBLOCKSHIFT)

/*
 * return x rounded down to an align boundary
 * eg, P2ALIGN(1200, 1024) == 1024 (1*align)
 * eg, P2ALIGN(1024, 1024) == 1024 (1*align)
 * eg, P2ALIGN(0x1234, 0x100) == 0x1200 (0x12*align)
 * eg, P2ALIGN(0x5600, 0x100) == 0x5600 (0x56*align)
 */
#define	P2ALIGN(x, align)		((x) & -(align))

/*
 * For nvlist manipulation. (from nvpair.h)
 */
#define	NV_ENCODE_NATIVE	0
#define	NV_ENCODE_XDR		1
#define	HOST_ENDIAN		1	/* for x86 machine */
typedef enum {
	DATA_TYPE_UNKNOWN = 0,
	DATA_TYPE_BOOLEAN,
	DATA_TYPE_BYTE,
	DATA_TYPE_INT16,
	DATA_TYPE_UINT16,
	DATA_TYPE_INT32,
	DATA_TYPE_UINT32,
	DATA_TYPE_INT64,
	DATA_TYPE_UINT64,
	DATA_TYPE_STRING,
	DATA_TYPE_BYTE_ARRAY,
	DATA_TYPE_INT16_ARRAY,
	DATA_TYPE_UINT16_ARRAY,
	DATA_TYPE_INT32_ARRAY,
	DATA_TYPE_UINT32_ARRAY,
	DATA_TYPE_INT64_ARRAY,
	DATA_TYPE_UINT64_ARRAY,
	DATA_TYPE_STRING_ARRAY,
	DATA_TYPE_HRTIME,
	DATA_TYPE_NVLIST,
	DATA_TYPE_NVLIST_ARRAY,
	DATA_TYPE_BOOLEAN_VALUE,
	DATA_TYPE_INT8,
	DATA_TYPE_UINT8,
	DATA_TYPE_BOOLEAN_ARRAY,
	DATA_TYPE_INT8_ARRAY,
	DATA_TYPE_UINT8_ARRAY,
	DATA_TYPE_DOUBLE
} data_type_t;

/*
 * Decompression Entry - lzjb
 */
#ifndef	NBBY
#define	NBBY	8
#endif

typedef int zfs_decomp_func_t(void *s_start, void *d_start, size_t s_len,
			size_t d_len);
typedef struct decomp_entry {
	char *name;
	zfs_decomp_func_t *decomp_func;
} decomp_entry_t;

/*
 * FAT ZAP data structures
 */
#define	ZFS_CRC64_POLY 0xC96C5795D7870F42ULL /* ECMA-182, reflected form */
#define	ZAP_HASH_IDX(hash, n)	(((n) == 0) ? 0 : ((hash) >> (64 - (n))))
#define	CHAIN_END	0xffff	/* end of the chunk chain */

/*
 * The amount of space within the chunk available for the array is:
 * chunk size - space for type (1) - space for next pointer (2)
 */
#define	ZAP_LEAF_ARRAY_BYTES (ZAP_LEAF_CHUNKSIZE - 3)

#define	ZAP_LEAF_HASH_SHIFT(bs)	(bs - 5)
#define	ZAP_LEAF_HASH_NUMENTRIES(bs) (1 << ZAP_LEAF_HASH_SHIFT(bs))
#define	LEAF_HASH(bs, h) \
	((ZAP_LEAF_HASH_NUMENTRIES(bs)-1) & \
	((h) >> (64 - ZAP_LEAF_HASH_SHIFT(bs)-l->l_hdr.lh_prefix_len)))

/*
 * The amount of space available for chunks is:
 * block size shift - hash entry size (2) * number of hash
 * entries - header space (2*chunksize)
 */
#define	ZAP_LEAF_NUMCHUNKS(bs) \
	(((1<<bs) - 2*ZAP_LEAF_HASH_NUMENTRIES(bs)) / \
	ZAP_LEAF_CHUNKSIZE - 2)

/*
 * The chunks start immediately after the hash table.  The end of the
 * hash table is at l_hash + HASH_NUMENTRIES, which we simply cast to a
 * chunk_t.
 */
#define	ZAP_LEAF_CHUNK(l, bs, idx) \
	((zap_leaf_chunk_t *)(l->l_hash + ZAP_LEAF_HASH_NUMENTRIES(bs)))[idx]
#define	ZAP_LEAF_ENTRY(l, bs, idx) (&ZAP_LEAF_CHUNK(l, bs, idx).l_entry)

extern void fletcher_2_native(const void *, uint64_t, zio_cksum_t *);
extern void fletcher_2_byteswap(const void *, uint64_t, zio_cksum_t *);
extern void fletcher_4_native(const void *, uint64_t, zio_cksum_t *);
extern void fletcher_4_byteswap(const void *, uint64_t, zio_cksum_t *);
extern void zio_checksum_SHA256(const void *, uint64_t, zio_cksum_t *);
extern void zio_checksum_SHA512(const void *, uint64_t, zio_cksum_t *);
extern int lzjb_decompress(void *, void *, size_t, size_t);
extern int lz4_decompress(void *, void *, size_t, size_t);

#endif	/* FSYS_ZFS */

#endif /* !_FSYS_ZFS_H */
