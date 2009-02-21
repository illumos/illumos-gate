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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * The zfs plug-in routines for GRUB are:
 *
 * zfs_mount() - locates a valid uberblock of the root pool and reads
 *		in its MOS at the memory address MOS.
 *
 * zfs_open() - locates a plain file object by following the MOS
 *		and places its dnode at the memory address DNODE.
 *
 * zfs_read() - read in the data blocks pointed by the DNODE.
 *
 * ZFS_SCRATCH is used as a working area.
 *
 * (memory addr)   MOS      DNODE	ZFS_SCRATCH
 *		    |         |          |
 *	    +-------V---------V----------V---------------+
 *   memory |       | dnode   | dnode    |  scratch      |
 *	    |       | 512B    | 512B     |  area         |
 *	    +--------------------------------------------+
 */

#ifdef	FSYS_ZFS

#include "shared.h"
#include "filesys.h"
#include "fsys_zfs.h"

/* cache for a file block of the currently zfs_open()-ed file */
static void *file_buf = NULL;
static uint64_t file_start = 0;
static uint64_t file_end = 0;

/* cache for a dnode block */
static dnode_phys_t *dnode_buf = NULL;
static dnode_phys_t *dnode_mdn = NULL;
static uint64_t dnode_start = 0;
static uint64_t dnode_end = 0;

static uberblock_t current_uberblock;
static char *stackbase;

decomp_entry_t decomp_table[ZIO_COMPRESS_FUNCTIONS] =
{
	{"inherit", 0},			/* ZIO_COMPRESS_INHERIT */
	{"on", lzjb_decompress}, 	/* ZIO_COMPRESS_ON */
	{"off", 0},			/* ZIO_COMPRESS_OFF */
	{"lzjb", lzjb_decompress},	/* ZIO_COMPRESS_LZJB */
	{"empty", 0}			/* ZIO_COMPRESS_EMPTY */
};

static int zio_read_data(blkptr_t *bp, void *buf, char *stack);

/*
 * Our own version of bcmp().
 */
static int
zfs_bcmp(const void *s1, const void *s2, size_t n)
{
	const uchar_t *ps1 = s1;
	const uchar_t *ps2 = s2;

	if (s1 != s2 && n != 0) {
		do {
			if (*ps1++ != *ps2++)
				return (1);
		} while (--n != 0);
	}

	return (0);
}

/*
 * Our own version of log2().  Same thing as highbit()-1.
 */
static int
zfs_log2(uint64_t num)
{
	int i = 0;

	while (num > 1) {
		i++;
		num = num >> 1;
	}

	return (i);
}

/* Checksum Functions */
static void
zio_checksum_off(const void *buf, uint64_t size, zio_cksum_t *zcp)
{
	ZIO_SET_CHECKSUM(zcp, 0, 0, 0, 0);
}

/* Checksum Table and Values */
zio_checksum_info_t zio_checksum_table[ZIO_CHECKSUM_FUNCTIONS] = {
	NULL,			NULL,			0, 0,	"inherit",
	NULL,			NULL,			0, 0,	"on",
	zio_checksum_off,	zio_checksum_off,	0, 0,	"off",
	zio_checksum_SHA256,	zio_checksum_SHA256,	1, 1,	"label",
	zio_checksum_SHA256,	zio_checksum_SHA256,	1, 1,	"gang_header",
	fletcher_2_native,	fletcher_2_byteswap,	0, 1,	"zilog",
	fletcher_2_native,	fletcher_2_byteswap,	0, 0,	"fletcher2",
	fletcher_4_native,	fletcher_4_byteswap,	1, 0,	"fletcher4",
	zio_checksum_SHA256,	zio_checksum_SHA256,	1, 0,	"SHA256",
};

/*
 * zio_checksum_verify: Provides support for checksum verification.
 *
 * Fletcher2, Fletcher4, and SHA256 are supported.
 *
 * Return:
 * 	-1 = Failure
 *	 0 = Success
 */
static int
zio_checksum_verify(blkptr_t *bp, char *data, int size)
{
	zio_cksum_t zc = bp->blk_cksum;
	uint32_t checksum = BP_GET_CHECKSUM(bp);
	int byteswap = BP_SHOULD_BYTESWAP(bp);
	zio_block_tail_t *zbt = (zio_block_tail_t *)(data + size) - 1;
	zio_checksum_info_t *ci = &zio_checksum_table[checksum];
	zio_cksum_t actual_cksum, expected_cksum;

	/* byteswap is not supported */
	if (byteswap)
		return (-1);

	if (checksum >= ZIO_CHECKSUM_FUNCTIONS || ci->ci_func[0] == NULL)
		return (-1);

	if (ci->ci_zbt) {
		expected_cksum = zbt->zbt_cksum;
		zbt->zbt_cksum = zc;
		ci->ci_func[0](data, size, &actual_cksum);
		zbt->zbt_cksum = expected_cksum;
		zc = expected_cksum;

	} else {
		ci->ci_func[byteswap](data, size, &actual_cksum);
	}

	if ((actual_cksum.zc_word[0] - zc.zc_word[0]) |
	    (actual_cksum.zc_word[1] - zc.zc_word[1]) |
	    (actual_cksum.zc_word[2] - zc.zc_word[2]) |
	    (actual_cksum.zc_word[3] - zc.zc_word[3]))
		return (-1);

	return (0);
}

/*
 * vdev_label_offset takes "offset" (the offset within a vdev_label) and
 * returns its physical disk offset (starting from the beginning of the vdev).
 *
 * Input:
 *	psize	: Physical size of this vdev
 *      l	: Label Number (0-3)
 *	offset	: The offset with a vdev_label in which we want the physical
 *		  address
 * Return:
 * 	Success : physical disk offset
 * 	Failure : errnum = ERR_BAD_ARGUMENT, return value is meaningless
 */
static uint64_t
vdev_label_offset(uint64_t psize, int l, uint64_t offset)
{
	/* XXX Need to add back label support! */
	if (l >= VDEV_LABELS/2 || offset > sizeof (vdev_label_t)) {
		errnum = ERR_BAD_ARGUMENT;
		return (0);
	}

	return (offset + l * sizeof (vdev_label_t) + (l < VDEV_LABELS / 2 ?
	    0 : psize - VDEV_LABELS * sizeof (vdev_label_t)));

}

/*
 * vdev_uberblock_compare takes two uberblock structures and returns an integer
 * indicating the more recent of the two.
 * 	Return Value = 1 if ub2 is more recent
 * 	Return Value = -1 if ub1 is more recent
 * The most recent uberblock is determined using its transaction number and
 * timestamp.  The uberblock with the highest transaction number is
 * considered "newer".  If the transaction numbers of the two blocks match, the
 * timestamps are compared to determine the "newer" of the two.
 */
static int
vdev_uberblock_compare(uberblock_t *ub1, uberblock_t *ub2)
{
	if (ub1->ub_txg < ub2->ub_txg)
		return (-1);
	if (ub1->ub_txg > ub2->ub_txg)
		return (1);

	if (ub1->ub_timestamp < ub2->ub_timestamp)
		return (-1);
	if (ub1->ub_timestamp > ub2->ub_timestamp)
		return (1);

	return (0);
}

/*
 * Three pieces of information are needed to verify an uberblock: the magic
 * number, the version number, and the checksum.
 *
 * Currently Implemented: version number, magic number
 * Need to Implement: checksum
 *
 * Return:
 *     0 - Success
 *    -1 - Failure
 */
static int
uberblock_verify(uberblock_phys_t *ub, int offset)
{

	uberblock_t *uber = &ub->ubp_uberblock;
	blkptr_t bp;

	BP_ZERO(&bp);
	BP_SET_CHECKSUM(&bp, ZIO_CHECKSUM_LABEL);
	BP_SET_BYTEORDER(&bp, ZFS_HOST_BYTEORDER);
	ZIO_SET_CHECKSUM(&bp.blk_cksum, offset, 0, 0, 0);

	if (zio_checksum_verify(&bp, (char *)ub, UBERBLOCK_SIZE) != 0)
		return (-1);

	if (uber->ub_magic == UBERBLOCK_MAGIC &&
	    uber->ub_version > 0 && uber->ub_version <= SPA_VERSION)
		return (0);

	return (-1);
}

/*
 * Find the best uberblock.
 * Return:
 *    Success - Pointer to the best uberblock.
 *    Failure - NULL
 */
static uberblock_phys_t *
find_bestub(uberblock_phys_t *ub_array, int label)
{
	uberblock_phys_t *ubbest = NULL;
	int i, offset;

	for (i = 0; i < (VDEV_UBERBLOCK_RING >> VDEV_UBERBLOCK_SHIFT); i++) {
		offset = vdev_label_offset(0, label, VDEV_UBERBLOCK_OFFSET(i));
		if (errnum == ERR_BAD_ARGUMENT)
			return (NULL);
		if (uberblock_verify(&ub_array[i], offset) == 0) {
			if (ubbest == NULL) {
				ubbest = &ub_array[i];
			} else if (vdev_uberblock_compare(
			    &(ub_array[i].ubp_uberblock),
			    &(ubbest->ubp_uberblock)) > 0) {
				ubbest = &ub_array[i];
			}
		}
	}

	return (ubbest);
}

/*
 * Read a block of data based on the gang block address dva,
 * and put its data in buf.
 *
 * Return:
 *	0 - success
 *	1 - failure
 */
static int
zio_read_gang(blkptr_t *bp, dva_t *dva, void *buf, char *stack)
{
	zio_gbh_phys_t *zio_gb;
	uint64_t offset, sector;
	blkptr_t tmpbp;
	int i;

	zio_gb = (zio_gbh_phys_t *)stack;
	stack += SPA_GANGBLOCKSIZE;
	offset = DVA_GET_OFFSET(dva);
	sector =  DVA_OFFSET_TO_PHYS_SECTOR(offset);

	/* read in the gang block header */
	if (devread(sector, 0, SPA_GANGBLOCKSIZE, (char *)zio_gb) == 0) {
		grub_printf("failed to read in a gang block header\n");
		return (1);
	}

	/* self checksuming the gang block header */
	BP_ZERO(&tmpbp);
	BP_SET_CHECKSUM(&tmpbp, ZIO_CHECKSUM_GANG_HEADER);
	BP_SET_BYTEORDER(&tmpbp, ZFS_HOST_BYTEORDER);
	ZIO_SET_CHECKSUM(&tmpbp.blk_cksum, DVA_GET_VDEV(dva),
	    DVA_GET_OFFSET(dva), bp->blk_birth, 0);
	if (zio_checksum_verify(&tmpbp, (char *)zio_gb, SPA_GANGBLOCKSIZE)) {
		grub_printf("failed to checksum a gang block header\n");
		return (1);
	}

	for (i = 0; i < SPA_GBH_NBLKPTRS; i++) {
		if (zio_gb->zg_blkptr[i].blk_birth == 0)
			continue;

		if (zio_read_data(&zio_gb->zg_blkptr[i], buf, stack))
			return (1);
		buf += BP_GET_PSIZE(&zio_gb->zg_blkptr[i]);
	}

	return (0);
}

/*
 * Read in a block of raw data to buf.
 *
 * Return:
 *	0 - success
 *	1 - failure
 */
static int
zio_read_data(blkptr_t *bp, void *buf, char *stack)
{
	int i, psize;

	psize = BP_GET_PSIZE(bp);

	/* pick a good dva from the block pointer */
	for (i = 0; i < SPA_DVAS_PER_BP; i++) {
		uint64_t offset, sector;

		if (bp->blk_dva[i].dva_word[0] == 0 &&
		    bp->blk_dva[i].dva_word[1] == 0)
			continue;

		if (DVA_GET_GANG(&bp->blk_dva[i])) {
			if (zio_read_gang(bp, &bp->blk_dva[i], buf, stack) == 0)
				return (0);
		} else {
			/* read in a data block */
			offset = DVA_GET_OFFSET(&bp->blk_dva[i]);
			sector =  DVA_OFFSET_TO_PHYS_SECTOR(offset);
			if (devread(sector, 0, psize, buf))
				return (0);
		}
	}

	return (1);
}

/*
 * Read in a block of data, verify its checksum, decompress if needed,
 * and put the uncompressed data in buf.
 *
 * Return:
 *	0 - success
 *	errnum - failure
 */
static int
zio_read(blkptr_t *bp, void *buf, char *stack)
{
	int lsize, psize, comp;
	char *retbuf;

	comp = BP_GET_COMPRESS(bp);
	lsize = BP_GET_LSIZE(bp);
	psize = BP_GET_PSIZE(bp);

	if ((unsigned int)comp >= ZIO_COMPRESS_FUNCTIONS ||
	    (comp != ZIO_COMPRESS_OFF &&
	    decomp_table[comp].decomp_func == NULL)) {
		grub_printf("compression algorithm not supported\n");
		return (ERR_FSYS_CORRUPT);
	}

	if ((char *)buf < stack && ((char *)buf) + lsize > stack) {
		grub_printf("not enough memory allocated\n");
		return (ERR_WONT_FIT);
	}

	retbuf = buf;
	if (comp != ZIO_COMPRESS_OFF) {
		buf = stack;
		stack += psize;
	}

	if (zio_read_data(bp, buf, stack)) {
		grub_printf("zio_read_data failed\n");
		return (ERR_FSYS_CORRUPT);
	}

	if (zio_checksum_verify(bp, buf, psize) != 0) {
		grub_printf("checksum verification failed\n");
		return (ERR_FSYS_CORRUPT);
	}

	if (comp != ZIO_COMPRESS_OFF)
		decomp_table[comp].decomp_func(buf, retbuf, psize, lsize);

	return (0);
}

/*
 * Get the block from a block id.
 * push the block onto the stack.
 *
 * Return:
 * 	0 - success
 * 	errnum - failure
 */
static int
dmu_read(dnode_phys_t *dn, uint64_t blkid, void *buf, char *stack)
{
	int idx, level;
	blkptr_t *bp_array = dn->dn_blkptr;
	int epbs = dn->dn_indblkshift - SPA_BLKPTRSHIFT;
	blkptr_t *bp, *tmpbuf;

	bp = (blkptr_t *)stack;
	stack += sizeof (blkptr_t);

	tmpbuf = (blkptr_t *)stack;
	stack += 1<<dn->dn_indblkshift;

	for (level = dn->dn_nlevels - 1; level >= 0; level--) {
		idx = (blkid >> (epbs * level)) & ((1<<epbs)-1);
		*bp = bp_array[idx];
		if (level == 0)
			tmpbuf = buf;
		if (BP_IS_HOLE(bp)) {
			grub_memset(buf, 0,
			    dn->dn_datablkszsec << SPA_MINBLOCKSHIFT);
			break;
		} else if (errnum = zio_read(bp, tmpbuf, stack)) {
			return (errnum);
		}

		bp_array = tmpbuf;
	}

	return (0);
}

/*
 * mzap_lookup: Looks up property described by "name" and returns the value
 * in "value".
 *
 * Return:
 *	0 - success
 *	errnum - failure
 */
static int
mzap_lookup(mzap_phys_t *zapobj, int objsize, char *name,
	uint64_t *value)
{
	int i, chunks;
	mzap_ent_phys_t *mzap_ent = zapobj->mz_chunk;

	chunks = objsize/MZAP_ENT_LEN - 1;
	for (i = 0; i < chunks; i++) {
		if (grub_strcmp(mzap_ent[i].mze_name, name) == 0) {
			*value = mzap_ent[i].mze_value;
			return (0);
		}
	}

	return (ERR_FSYS_CORRUPT);
}

static uint64_t
zap_hash(uint64_t salt, const char *name)
{
	static uint64_t table[256];
	const uint8_t *cp;
	uint8_t c;
	uint64_t crc = salt;

	if (table[128] == 0) {
		uint64_t *ct;
		int i, j;
		for (i = 0; i < 256; i++) {
			for (ct = table + i, *ct = i, j = 8; j > 0; j--)
				*ct = (*ct >> 1) ^ (-(*ct & 1) &
				    ZFS_CRC64_POLY);
		}
	}

	if (crc == 0 || table[128] != ZFS_CRC64_POLY) {
		errnum = ERR_FSYS_CORRUPT;
		return (0);
	}

	for (cp = (const uint8_t *)name; (c = *cp) != '\0'; cp++)
		crc = (crc >> 8) ^ table[(crc ^ c) & 0xFF];

	/*
	 * Only use 28 bits, since we need 4 bits in the cookie for the
	 * collision differentiator.  We MUST use the high bits, since
	 * those are the onces that we first pay attention to when
	 * chosing the bucket.
	 */
	crc &= ~((1ULL << (64 - ZAP_HASHBITS)) - 1);

	return (crc);
}

/*
 * Only to be used on 8-bit arrays.
 * array_len is actual len in bytes (not encoded le_value_length).
 * buf is null-terminated.
 */
static int
zap_leaf_array_equal(zap_leaf_phys_t *l, int blksft, int chunk,
    int array_len, const char *buf)
{
	int bseen = 0;

	while (bseen < array_len) {
		struct zap_leaf_array *la =
		    &ZAP_LEAF_CHUNK(l, blksft, chunk).l_array;
		int toread = MIN(array_len - bseen, ZAP_LEAF_ARRAY_BYTES);

		if (chunk >= ZAP_LEAF_NUMCHUNKS(blksft))
			return (0);

		if (zfs_bcmp(la->la_array, buf + bseen, toread) != 0)
			break;
		chunk = la->la_next;
		bseen += toread;
	}
	return (bseen == array_len);
}

/*
 * Given a zap_leaf_phys_t, walk thru the zap leaf chunks to get the
 * value for the property "name".
 *
 * Return:
 *	0 - success
 *	errnum - failure
 */
static int
zap_leaf_lookup(zap_leaf_phys_t *l, int blksft, uint64_t h,
    const char *name, uint64_t *value)
{
	uint16_t chunk;
	struct zap_leaf_entry *le;

	/* Verify if this is a valid leaf block */
	if (l->l_hdr.lh_block_type != ZBT_LEAF)
		return (ERR_FSYS_CORRUPT);
	if (l->l_hdr.lh_magic != ZAP_LEAF_MAGIC)
		return (ERR_FSYS_CORRUPT);

	for (chunk = l->l_hash[LEAF_HASH(blksft, h)];
	    chunk != CHAIN_END; chunk = le->le_next) {

		if (chunk >= ZAP_LEAF_NUMCHUNKS(blksft))
			return (ERR_FSYS_CORRUPT);

		le = ZAP_LEAF_ENTRY(l, blksft, chunk);

		/* Verify the chunk entry */
		if (le->le_type != ZAP_CHUNK_ENTRY)
			return (ERR_FSYS_CORRUPT);

		if (le->le_hash != h)
			continue;

		if (zap_leaf_array_equal(l, blksft, le->le_name_chunk,
		    le->le_name_length, name)) {

			struct zap_leaf_array *la;
			uint8_t *ip;

			if (le->le_int_size != 8 || le->le_value_length != 1)
				return (ERR_FSYS_CORRUPT);

			/* get the uint64_t property value */
			la = &ZAP_LEAF_CHUNK(l, blksft,
			    le->le_value_chunk).l_array;
			ip = la->la_array;

			*value = (uint64_t)ip[0] << 56 | (uint64_t)ip[1] << 48 |
			    (uint64_t)ip[2] << 40 | (uint64_t)ip[3] << 32 |
			    (uint64_t)ip[4] << 24 | (uint64_t)ip[5] << 16 |
			    (uint64_t)ip[6] << 8 | (uint64_t)ip[7];

			return (0);
		}
	}

	return (ERR_FSYS_CORRUPT);
}

/*
 * Fat ZAP lookup
 *
 * Return:
 *	0 - success
 *	errnum - failure
 */
static int
fzap_lookup(dnode_phys_t *zap_dnode, zap_phys_t *zap,
    char *name, uint64_t *value, char *stack)
{
	zap_leaf_phys_t *l;
	uint64_t hash, idx, blkid;
	int blksft = zfs_log2(zap_dnode->dn_datablkszsec << DNODE_SHIFT);

	/* Verify if this is a fat zap header block */
	if (zap->zap_magic != (uint64_t)ZAP_MAGIC)
		return (ERR_FSYS_CORRUPT);

	hash = zap_hash(zap->zap_salt, name);
	if (errnum)
		return (errnum);

	/* get block id from index */
	if (zap->zap_ptrtbl.zt_numblks != 0) {
		/* external pointer tables not supported */
		return (ERR_FSYS_CORRUPT);
	}
	idx = ZAP_HASH_IDX(hash, zap->zap_ptrtbl.zt_shift);
	blkid = ((uint64_t *)zap)[idx + (1<<(blksft-3-1))];

	/* Get the leaf block */
	l = (zap_leaf_phys_t *)stack;
	stack += 1<<blksft;
	if ((1<<blksft) < sizeof (zap_leaf_phys_t))
		return (ERR_FSYS_CORRUPT);
	if (errnum = dmu_read(zap_dnode, blkid, l, stack))
		return (errnum);

	return (zap_leaf_lookup(l, blksft, hash, name, value));
}

/*
 * Read in the data of a zap object and find the value for a matching
 * property name.
 *
 * Return:
 *	0 - success
 *	errnum - failure
 */
static int
zap_lookup(dnode_phys_t *zap_dnode, char *name, uint64_t *val, char *stack)
{
	uint64_t block_type;
	int size;
	void *zapbuf;

	/* Read in the first block of the zap object data. */
	zapbuf = stack;
	size = zap_dnode->dn_datablkszsec << SPA_MINBLOCKSHIFT;
	stack += size;
	if (errnum = dmu_read(zap_dnode, 0, zapbuf, stack))
		return (errnum);

	block_type = *((uint64_t *)zapbuf);

	if (block_type == ZBT_MICRO) {
		return (mzap_lookup(zapbuf, size, name, val));
	} else if (block_type == ZBT_HEADER) {
		/* this is a fat zap */
		return (fzap_lookup(zap_dnode, zapbuf, name,
		    val, stack));
	}

	return (ERR_FSYS_CORRUPT);
}

/*
 * Get the dnode of an object number from the metadnode of an object set.
 *
 * Input
 *	mdn - metadnode to get the object dnode
 *	objnum - object number for the object dnode
 *	buf - data buffer that holds the returning dnode
 *	stack - scratch area
 *
 * Return:
 *	0 - success
 *	errnum - failure
 */
static int
dnode_get(dnode_phys_t *mdn, uint64_t objnum, uint8_t type, dnode_phys_t *buf,
	char *stack)
{
	uint64_t blkid, blksz; /* the block id this object dnode is in */
	int epbs; /* shift of number of dnodes in a block */
	int idx; /* index within a block */
	dnode_phys_t *dnbuf;

	blksz = mdn->dn_datablkszsec << SPA_MINBLOCKSHIFT;
	epbs = zfs_log2(blksz) - DNODE_SHIFT;
	blkid = objnum >> epbs;
	idx = objnum & ((1<<epbs)-1);

	if (dnode_buf != NULL && dnode_mdn == mdn &&
	    objnum >= dnode_start && objnum < dnode_end) {
		grub_memmove(buf, &dnode_buf[idx], DNODE_SIZE);
		VERIFY_DN_TYPE(buf, type);
		return (0);
	}

	if (dnode_buf && blksz == 1<<DNODE_BLOCK_SHIFT) {
		dnbuf = dnode_buf;
		dnode_mdn = mdn;
		dnode_start = blkid << epbs;
		dnode_end = (blkid + 1) << epbs;
	} else {
		dnbuf = (dnode_phys_t *)stack;
		stack += blksz;
	}

	if (errnum = dmu_read(mdn, blkid, (char *)dnbuf, stack))
		return (errnum);

	grub_memmove(buf, &dnbuf[idx], DNODE_SIZE);
	VERIFY_DN_TYPE(buf, type);

	return (0);
}

/*
 * Check if this is a special file that resides at the top
 * dataset of the pool. Currently this is the GRUB menu,
 * boot signature and boot signature backup.
 * str starts with '/'.
 */
static int
is_top_dataset_file(char *str)
{
	char *tptr;

	if ((tptr = grub_strstr(str, "menu.lst")) &&
	    (tptr[8] == '\0' || tptr[8] == ' ') &&
	    *(tptr-1) == '/')
		return (1);

	if (grub_strncmp(str, BOOTSIGN_DIR"/",
	    grub_strlen(BOOTSIGN_DIR) + 1) == 0)
		return (1);

	if (grub_strcmp(str, BOOTSIGN_BACKUP) == 0)
		return (1);

	return (0);
}

/*
 * Get the file dnode for a given file name where mdn is the meta dnode
 * for this ZFS object set. When found, place the file dnode in dn.
 * The 'path' argument will be mangled.
 *
 * Return:
 *	0 - success
 *	errnum - failure
 */
static int
dnode_get_path(dnode_phys_t *mdn, char *path, dnode_phys_t *dn,
    char *stack)
{
	uint64_t objnum, version;
	char *cname, ch;

	if (errnum = dnode_get(mdn, MASTER_NODE_OBJ, DMU_OT_MASTER_NODE,
	    dn, stack))
		return (errnum);

	if (errnum = zap_lookup(dn, ZPL_VERSION_STR, &version, stack))
		return (errnum);
	if (version > ZPL_VERSION)
		return (-1);

	if (errnum = zap_lookup(dn, ZFS_ROOT_OBJ, &objnum, stack))
		return (errnum);

	if (errnum = dnode_get(mdn, objnum, DMU_OT_DIRECTORY_CONTENTS,
	    dn, stack))
		return (errnum);

	/* skip leading slashes */
	while (*path == '/')
		path++;

	while (*path && !isspace(*path)) {

		/* get the next component name */
		cname = path;
		while (*path && !isspace(*path) && *path != '/')
			path++;
		ch = *path;
		*path = 0;   /* ensure null termination */

		if (errnum = zap_lookup(dn, cname, &objnum, stack))
			return (errnum);

		objnum = ZFS_DIRENT_OBJ(objnum);
		if (errnum = dnode_get(mdn, objnum, 0, dn, stack))
			return (errnum);

		*path = ch;
		while (*path == '/')
			path++;
	}

	/* We found the dnode for this file. Verify if it is a plain file. */
	VERIFY_DN_TYPE(dn, DMU_OT_PLAIN_FILE_CONTENTS);

	return (0);
}

/*
 * Get the default 'bootfs' property value from the rootpool.
 *
 * Return:
 *	0 - success
 *	errnum -failure
 */
static int
get_default_bootfsobj(dnode_phys_t *mosmdn, uint64_t *obj, char *stack)
{
	uint64_t objnum = 0;
	dnode_phys_t *dn = (dnode_phys_t *)stack;
	stack += DNODE_SIZE;

	if (errnum = dnode_get(mosmdn, DMU_POOL_DIRECTORY_OBJECT,
	    DMU_OT_OBJECT_DIRECTORY, dn, stack))
		return (errnum);

	/*
	 * find the object number for 'pool_props', and get the dnode
	 * of the 'pool_props'.
	 */
	if (zap_lookup(dn, DMU_POOL_PROPS, &objnum, stack))
		return (ERR_FILESYSTEM_NOT_FOUND);

	if (errnum = dnode_get(mosmdn, objnum, DMU_OT_POOL_PROPS, dn, stack))
		return (errnum);

	if (zap_lookup(dn, ZPOOL_PROP_BOOTFS, &objnum, stack))
		return (ERR_FILESYSTEM_NOT_FOUND);

	if (!objnum)
		return (ERR_FILESYSTEM_NOT_FOUND);

	*obj = objnum;
	return (0);
}

/*
 * Given a MOS metadnode, get the metadnode of a given filesystem name (fsname),
 * e.g. pool/rootfs, or a given object number (obj), e.g. the object number
 * of pool/rootfs.
 *
 * If no fsname and no obj are given, return the DSL_DIR metadnode.
 * If fsname is given, return its metadnode and its matching object number.
 * If only obj is given, return the metadnode for this object number.
 *
 * Return:
 *	0 - success
 *	errnum - failure
 */
static int
get_objset_mdn(dnode_phys_t *mosmdn, char *fsname, uint64_t *obj,
    dnode_phys_t *mdn, char *stack)
{
	uint64_t objnum, headobj;
	char *cname, ch;
	blkptr_t *bp;
	objset_phys_t *osp;
	int issnapshot = 0;
	char *snapname;

	if (fsname == NULL && obj) {
		headobj = *obj;
		goto skip;
	}

	if (errnum = dnode_get(mosmdn, DMU_POOL_DIRECTORY_OBJECT,
	    DMU_OT_OBJECT_DIRECTORY, mdn, stack))
		return (errnum);

	if (errnum = zap_lookup(mdn, DMU_POOL_ROOT_DATASET, &objnum,
	    stack))
		return (errnum);

	if (errnum = dnode_get(mosmdn, objnum, DMU_OT_DSL_DIR, mdn, stack))
		return (errnum);

	if (fsname == NULL) {
		headobj =
		    ((dsl_dir_phys_t *)DN_BONUS(mdn))->dd_head_dataset_obj;
		goto skip;
	}

	/* take out the pool name */
	while (*fsname && !isspace(*fsname) && *fsname != '/')
		fsname++;

	while (*fsname && !isspace(*fsname)) {
		uint64_t childobj;

		while (*fsname == '/')
			fsname++;

		cname = fsname;
		while (*fsname && !isspace(*fsname) && *fsname != '/')
			fsname++;
		ch = *fsname;
		*fsname = 0;

		snapname = cname;
		while (*snapname && !isspace(*snapname) && *snapname != '@')
			snapname++;
		if (*snapname == '@') {
			issnapshot = 1;
			*snapname = 0;
		}
		childobj =
		    ((dsl_dir_phys_t *)DN_BONUS(mdn))->dd_child_dir_zapobj;
		if (errnum = dnode_get(mosmdn, childobj,
		    DMU_OT_DSL_DIR_CHILD_MAP, mdn, stack))
			return (errnum);

		if (zap_lookup(mdn, cname, &objnum, stack))
			return (ERR_FILESYSTEM_NOT_FOUND);

		if (errnum = dnode_get(mosmdn, objnum, DMU_OT_DSL_DIR,
		    mdn, stack))
			return (errnum);

		*fsname = ch;
		if (issnapshot)
			*snapname = '@';
	}
	headobj = ((dsl_dir_phys_t *)DN_BONUS(mdn))->dd_head_dataset_obj;
	if (obj)
		*obj = headobj;

skip:
	if (errnum = dnode_get(mosmdn, headobj, DMU_OT_DSL_DATASET, mdn, stack))
		return (errnum);
	if (issnapshot) {
		uint64_t snapobj;

		snapobj = ((dsl_dataset_phys_t *)DN_BONUS(mdn))->
		    ds_snapnames_zapobj;

		if (errnum = dnode_get(mosmdn, snapobj,
		    DMU_OT_DSL_DS_SNAP_MAP, mdn, stack))
			return (errnum);
		if (zap_lookup(mdn, snapname + 1, &headobj, stack))
			return (ERR_FILESYSTEM_NOT_FOUND);
		if (errnum = dnode_get(mosmdn, headobj,
		    DMU_OT_DSL_DATASET, mdn, stack))
			return (errnum);
		if (obj)
			*obj = headobj;
	}

	bp = &((dsl_dataset_phys_t *)DN_BONUS(mdn))->ds_bp;
	osp = (objset_phys_t *)stack;
	stack += sizeof (objset_phys_t);
	if (errnum = zio_read(bp, osp, stack))
		return (errnum);

	grub_memmove((char *)mdn, (char *)&osp->os_meta_dnode, DNODE_SIZE);

	return (0);
}

/*
 * For a given XDR packed nvlist, verify the first 4 bytes and move on.
 *
 * An XDR packed nvlist is encoded as (comments from nvs_xdr_create) :
 *
 *      encoding method/host endian     (4 bytes)
 *      nvl_version                     (4 bytes)
 *      nvl_nvflag                      (4 bytes)
 *	encoded nvpairs:
 *		encoded size of the nvpair      (4 bytes)
 *		decoded size of the nvpair      (4 bytes)
 *		name string size                (4 bytes)
 *		name string data                (sizeof(NV_ALIGN4(string))
 *		data type                       (4 bytes)
 *		# of elements in the nvpair     (4 bytes)
 *		data
 *      2 zero's for the last nvpair
 *		(end of the entire list)	(8 bytes)
 *
 * Return:
 *	0 - success
 *	1 - failure
 */
static int
nvlist_unpack(char *nvlist, char **out)
{
	/* Verify if the 1st and 2nd byte in the nvlist are valid. */
	if (nvlist[0] != NV_ENCODE_XDR || nvlist[1] != HOST_ENDIAN)
		return (1);

	nvlist += 4;
	*out = nvlist;
	return (0);
}

static char *
nvlist_array(char *nvlist, int index)
{
	int i, encode_size;

	for (i = 0; i < index; i++) {
		/* skip the header, nvl_version, and nvl_nvflag */
		nvlist = nvlist + 4 * 2;

		while (encode_size = BSWAP_32(*(uint32_t *)nvlist))
			nvlist += encode_size; /* goto the next nvpair */

		nvlist = nvlist + 4 * 2; /* skip the ending 2 zeros - 8 bytes */
	}

	return (nvlist);
}

static int
nvlist_lookup_value(char *nvlist, char *name, void *val, int valtype,
    int *nelmp)
{
	int name_len, type, slen, encode_size;
	char *nvpair, *nvp_name, *strval = val;
	uint64_t *intval = val;

	/* skip the header, nvl_version, and nvl_nvflag */
	nvlist = nvlist + 4 * 2;

	/*
	 * Loop thru the nvpair list
	 * The XDR representation of an integer is in big-endian byte order.
	 */
	while (encode_size = BSWAP_32(*(uint32_t *)nvlist))  {

		nvpair = nvlist + 4 * 2; /* skip the encode/decode size */

		name_len = BSWAP_32(*(uint32_t *)nvpair);
		nvpair += 4;

		nvp_name = nvpair;
		nvpair = nvpair + ((name_len + 3) & ~3); /* align */

		type = BSWAP_32(*(uint32_t *)nvpair);
		nvpair += 4;

		if ((grub_strncmp(nvp_name, name, name_len) == 0) &&
		    type == valtype) {
			int nelm;

			if ((nelm = BSWAP_32(*(uint32_t *)nvpair)) < 1)
				return (1);
			nvpair += 4;

			switch (valtype) {
			case DATA_TYPE_STRING:
				slen = BSWAP_32(*(uint32_t *)nvpair);
				nvpair += 4;
				grub_memmove(strval, nvpair, slen);
				strval[slen] = '\0';
				return (0);

			case DATA_TYPE_UINT64:
				*intval = BSWAP_64(*(uint64_t *)nvpair);
				return (0);

			case DATA_TYPE_NVLIST:
				*(void **)val = (void *)nvpair;
				return (0);

			case DATA_TYPE_NVLIST_ARRAY:
				*(void **)val = (void *)nvpair;
				if (nelmp)
					*nelmp = nelm;
				return (0);
			}
		}

		nvlist += encode_size; /* goto the next nvpair */
	}

	return (1);
}

/*
 * Check if this vdev is online and is in a good state.
 */
static int
vdev_validate(char *nv)
{
	uint64_t ival;

	if (nvlist_lookup_value(nv, ZPOOL_CONFIG_OFFLINE, &ival,
	    DATA_TYPE_UINT64, NULL) == 0 ||
	    nvlist_lookup_value(nv, ZPOOL_CONFIG_FAULTED, &ival,
	    DATA_TYPE_UINT64, NULL) == 0 ||
	    nvlist_lookup_value(nv, ZPOOL_CONFIG_REMOVED, &ival,
	    DATA_TYPE_UINT64, NULL) == 0)
		return (ERR_DEV_VALUES);

	return (0);
}

/*
 * Get a list of valid vdev pathname from the boot device.
 * The caller should already allocate MAXPATHLEN memory for bootpath and devid.
 */
int
vdev_get_bootpath(char *nv, uint64_t inguid, char *devid, char *bootpath)
{
	char type[16];

	if (nvlist_lookup_value(nv, ZPOOL_CONFIG_TYPE, &type, DATA_TYPE_STRING,
	    NULL))
		return (ERR_FSYS_CORRUPT);

	if (strcmp(type, VDEV_TYPE_DISK) == 0) {
		uint64_t guid;

		if (vdev_validate(nv) != 0)
			return (ERR_NO_BOOTPATH);

		if (nvlist_lookup_value(nv, ZPOOL_CONFIG_GUID,
		    &guid, DATA_TYPE_UINT64, NULL) != 0)
			return (ERR_NO_BOOTPATH);

		if (guid != inguid)
			return (ERR_NO_BOOTPATH);

		if (nvlist_lookup_value(nv, ZPOOL_CONFIG_PHYS_PATH,
		    bootpath, DATA_TYPE_STRING, NULL) != 0)
			bootpath[0] = '\0';

		if (nvlist_lookup_value(nv, ZPOOL_CONFIG_DEVID,
		    devid, DATA_TYPE_STRING, NULL) != 0)
			devid[0] = '\0';

		if (strlen(bootpath) >= MAXPATHLEN ||
		    strlen(devid) >= MAXPATHLEN)
			return (ERR_WONT_FIT);

		return (0);

	} else if (strcmp(type, VDEV_TYPE_MIRROR) == 0) {
		int nelm, i;
		char *child;

		if (nvlist_lookup_value(nv, ZPOOL_CONFIG_CHILDREN, &child,
		    DATA_TYPE_NVLIST_ARRAY, &nelm))
			return (ERR_FSYS_CORRUPT);

		for (i = 0; i < nelm; i++) {
			char *child_i;

			child_i = nvlist_array(child, i);
			if (vdev_get_bootpath(child_i, inguid, devid,
			    bootpath) == 0)
				return (0);
		}
	}

	return (ERR_NO_BOOTPATH);
}

/*
 * Check the disk label information and retrieve needed vdev name-value pairs.
 *
 * Return:
 *	0 - success
 *	ERR_* - failure
 */
int
check_pool_label(int label, char *stack, char *outdevid, char *outpath)
{
	vdev_phys_t *vdev;
	uint64_t sector, pool_state, txg = 0;
	char *nvlist, *nv;
	uint64_t diskguid;
	uint64_t version;

	sector = (label * sizeof (vdev_label_t) + VDEV_SKIP_SIZE)
	    >> SPA_MINBLOCKSHIFT;

	/* Read in the vdev name-value pair list (112K). */
	if (devread(sector, 0, VDEV_PHYS_SIZE, stack) == 0)
		return (ERR_READ);

	vdev = (vdev_phys_t *)stack;
	stack += sizeof (vdev_phys_t);

	if (nvlist_unpack(vdev->vp_nvlist, &nvlist))
		return (ERR_FSYS_CORRUPT);

	if (nvlist_lookup_value(nvlist, ZPOOL_CONFIG_POOL_STATE, &pool_state,
	    DATA_TYPE_UINT64, NULL))
		return (ERR_FSYS_CORRUPT);

	if (pool_state == POOL_STATE_DESTROYED)
		return (ERR_FILESYSTEM_NOT_FOUND);

	if (nvlist_lookup_value(nvlist, ZPOOL_CONFIG_POOL_NAME,
	    current_rootpool, DATA_TYPE_STRING, NULL))
		return (ERR_FSYS_CORRUPT);

	if (nvlist_lookup_value(nvlist, ZPOOL_CONFIG_POOL_TXG, &txg,
	    DATA_TYPE_UINT64, NULL))
		return (ERR_FSYS_CORRUPT);

	/* not an active device */
	if (txg == 0)
		return (ERR_NO_BOOTPATH);

	if (nvlist_lookup_value(nvlist, ZPOOL_CONFIG_VERSION, &version,
	    DATA_TYPE_UINT64, NULL))
		return (ERR_FSYS_CORRUPT);
	if (version > SPA_VERSION)
		return (ERR_NEWER_VERSION);
	if (nvlist_lookup_value(nvlist, ZPOOL_CONFIG_VDEV_TREE, &nv,
	    DATA_TYPE_NVLIST, NULL))
		return (ERR_FSYS_CORRUPT);
	if (nvlist_lookup_value(nvlist, ZPOOL_CONFIG_GUID, &diskguid,
	    DATA_TYPE_UINT64, NULL))
		return (ERR_FSYS_CORRUPT);
	if (vdev_get_bootpath(nv, diskguid, outdevid, outpath))
		return (ERR_NO_BOOTPATH);
	return (0);
}

/*
 * zfs_mount() locates a valid uberblock of the root pool and read in its MOS
 * to the memory address MOS.
 *
 * Return:
 *	1 - success
 *	0 - failure
 */
int
zfs_mount(void)
{
	char *stack;
	int label = 0;
	uberblock_phys_t *ub_array, *ubbest = NULL;
	objset_phys_t *osp;
	char tmp_bootpath[MAXNAMELEN];
	char tmp_devid[MAXNAMELEN];

	/* if it's our first time here, zero the best uberblock out */
	if (best_drive == 0 && best_part == 0 && find_best_root)
		grub_memset(&current_uberblock, 0, sizeof (uberblock_t));

	stackbase = ZFS_SCRATCH;
	stack = stackbase;
	ub_array = (uberblock_phys_t *)stack;
	stack += VDEV_UBERBLOCK_RING;

	osp = (objset_phys_t *)stack;
	stack += sizeof (objset_phys_t);

	/* XXX add back labels support? */
	for (label = 0; ubbest == NULL && label < (VDEV_LABELS/2); label++) {
		uint64_t sector = (label * sizeof (vdev_label_t) +
		    VDEV_SKIP_SIZE + VDEV_PHYS_SIZE) >> SPA_MINBLOCKSHIFT;

		/* Read in the uberblock ring (128K). */
		if (devread(sector, 0, VDEV_UBERBLOCK_RING,
		    (char *)ub_array) == 0)
			continue;

		if ((ubbest = find_bestub(ub_array, label)) != NULL &&
		    zio_read(&ubbest->ubp_uberblock.ub_rootbp, osp, stack)
		    == 0) {

			VERIFY_OS_TYPE(osp, DMU_OST_META);

			if (check_pool_label(label, stack, tmp_devid,
			    tmp_bootpath))
				return (0);

			if (find_best_root &&
			    vdev_uberblock_compare(&ubbest->ubp_uberblock,
			    &(current_uberblock)) <= 0)
				continue;

			/* Got the MOS. Save it at the memory addr MOS. */
			grub_memmove(MOS, &osp->os_meta_dnode, DNODE_SIZE);
			grub_memmove(&current_uberblock,
			    &ubbest->ubp_uberblock, sizeof (uberblock_t));
			grub_memmove(current_bootpath, tmp_bootpath,
			    MAXNAMELEN);
			grub_memmove(current_devid, tmp_devid,
			    grub_strlen(tmp_devid));
			is_zfs_mount = 1;
			return (1);
		}
	}

	return (0);
}

/*
 * zfs_open() locates a file in the rootpool by following the
 * MOS and places the dnode of the file in the memory address DNODE.
 *
 * Return:
 *	1 - success
 *	0 - failure
 */
int
zfs_open(char *filename)
{
	char *stack;
	dnode_phys_t *mdn;

	file_buf = NULL;
	stackbase = ZFS_SCRATCH;
	stack = stackbase;

	mdn = (dnode_phys_t *)stack;
	stack += sizeof (dnode_phys_t);

	dnode_mdn = NULL;
	dnode_buf = (dnode_phys_t *)stack;
	stack += 1<<DNODE_BLOCK_SHIFT;

	/*
	 * menu.lst is placed at the root pool filesystem level,
	 * do not goto 'current_bootfs'.
	 */
	if (is_top_dataset_file(filename)) {
		if (errnum = get_objset_mdn(MOS, NULL, NULL, mdn, stack))
			return (0);

		current_bootfs_obj = 0;
	} else {
		if (current_bootfs[0] == '\0') {
			/* Get the default root filesystem object number */
			if (errnum = get_default_bootfsobj(MOS,
			    &current_bootfs_obj, stack))
				return (0);

			if (errnum = get_objset_mdn(MOS, NULL,
			    &current_bootfs_obj, mdn, stack))
				return (0);
		} else {
			if (errnum = get_objset_mdn(MOS, current_bootfs,
			    &current_bootfs_obj, mdn, stack)) {
				grub_memset(current_bootfs, 0, MAXNAMELEN);
				return (0);
			}
		}
	}

	if (dnode_get_path(mdn, filename, DNODE, stack)) {
		errnum = ERR_FILE_NOT_FOUND;
		return (0);
	}

	/* get the file size and set the file position to 0 */
	filemax = ((znode_phys_t *)DN_BONUS(DNODE))->zp_size;
	filepos = 0;

	dnode_buf = NULL;
	return (1);
}

/*
 * zfs_read reads in the data blocks pointed by the DNODE.
 *
 * Return:
 *	len - the length successfully read in to the buffer
 *	0   - failure
 */
int
zfs_read(char *buf, int len)
{
	char *stack;
	char *tmpbuf;
	int blksz, length, movesize;

	if (file_buf == NULL) {
		file_buf = stackbase;
		stackbase += SPA_MAXBLOCKSIZE;
		file_start = file_end = 0;
	}
	stack = stackbase;

	/*
	 * If offset is in memory, move it into the buffer provided and return.
	 */
	if (filepos >= file_start && filepos+len <= file_end) {
		grub_memmove(buf, file_buf + filepos - file_start, len);
		filepos += len;
		return (len);
	}

	blksz = DNODE->dn_datablkszsec << SPA_MINBLOCKSHIFT;

	/*
	 * Entire Dnode is too big to fit into the space available.  We
	 * will need to read it in chunks.  This could be optimized to
	 * read in as large a chunk as there is space available, but for
	 * now, this only reads in one data block at a time.
	 */
	length = len;
	while (length) {
		/*
		 * Find requested blkid and the offset within that block.
		 */
		uint64_t blkid = filepos / blksz;

		if (errnum = dmu_read(DNODE, blkid, file_buf, stack))
			return (0);

		file_start = blkid * blksz;
		file_end = file_start + blksz;

		movesize = MIN(length, file_end - filepos);

		grub_memmove(buf, file_buf + filepos - file_start,
		    movesize);
		buf += movesize;
		length -= movesize;
		filepos += movesize;
	}

	return (len);
}

/*
 * No-Op
 */
int
zfs_embed(int *start_sector, int needed_sectors)
{
	return (1);
}

#endif /* FSYS_ZFS */
