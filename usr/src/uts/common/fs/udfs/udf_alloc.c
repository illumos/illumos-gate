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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/t_lock.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/systm.h>
#include <sys/sysmacros.h>
#include <sys/resource.h>
#include <sys/signal.h>
#include <sys/cred.h>
#include <sys/user.h>
#include <sys/buf.h>
#include <sys/vfs.h>
#include <sys/stat.h>
#include <sys/vnode.h>
#include <sys/mode.h>
#include <sys/proc.h>
#include <sys/disp.h>
#include <sys/file.h>
#include <sys/fcntl.h>
#include <sys/flock.h>
#include <sys/kmem.h>
#include <sys/uio.h>
#include <sys/dnlc.h>
#include <sys/conf.h>
#include <sys/errno.h>
#include <sys/mman.h>
#include <sys/fbuf.h>
#include <sys/pathname.h>
#include <sys/debug.h>
#include <sys/vmsystm.h>
#include <sys/cmn_err.h>
#include <sys/dirent.h>
#include <sys/errno.h>
#include <sys/modctl.h>
#include <sys/statvfs.h>
#include <sys/mount.h>
#include <sys/sunddi.h>
#include <sys/bootconf.h>
#include <sys/policy.h>

#include <vm/hat.h>
#include <vm/page.h>
#include <vm/pvn.h>
#include <vm/as.h>
#include <vm/seg.h>
#include <vm/seg_map.h>
#include <vm/seg_kmem.h>
#include <vm/seg_vn.h>
#include <vm/rm.h>
#include <vm/page.h>
#include <sys/swap.h>

#include <fs/fs_subr.h>

#include <sys/fs/udf_volume.h>
#include <sys/fs/udf_inode.h>

#ifdef	DEBUG
extern struct ud_inode *ud_search_icache(struct vfs *, uint16_t, uint32_t);
#endif

int32_t ud_alloc_space_bmap(struct vfs *, struct ud_part *,
	uint32_t, uint32_t, uint32_t *, uint32_t *, int32_t);
int32_t ud_check_free_and_mark_used(struct vfs *,
	struct ud_part *, uint32_t, uint32_t *);
int32_t ud_check_free(uint8_t *, uint8_t *, uint32_t, uint32_t);
void ud_mark_used(uint8_t *, uint32_t, uint32_t);
void ud_mark_free(uint8_t *, uint32_t, uint32_t);
int32_t ud_alloc_space_stbl(struct vfs *, struct ud_part *,
	uint32_t, uint32_t, uint32_t *, uint32_t *, int32_t);
int32_t ud_free_space_bmap(struct vfs *,
	struct ud_part *, uint32_t, uint32_t);
int32_t ud_free_space_stbl(struct vfs *,
	struct ud_part *, uint32_t, uint32_t);


/*
 * WORKSAROUND to the buffer cache crap
 * If the requested block exists in the buffer cache
 * buffer cache does not care about the count
 * it just returns the old buffer(does not even
 * set resid value). Same problem exists if the
 * block that is requested is not the first block
 * in the cached buffer then this will return
 * a different buffer. We work around the above by
 * using a fixed size request to the buffer cache
 * all the time. This is currently udf_lbsize.
 * (Actually it is restricted to udf_lbsize
 * because iget always does udf_lbsize requests)
 */


/*
 * allocate blkcount blocks continuously
 * near "proximity" block in partion defined by prn.
 * if proximity != 0 means less_is_ok = 0
 * return the starting block no and count
 * of blocks allocated in start_blkno & size
 * if less_is_ok == 0 then allocate only if
 * entire requirement can be met.
 */
int32_t
ud_alloc_space(struct vfs *vfsp, uint16_t prn,
	uint32_t proximity, uint32_t blkcount,
	uint32_t *start_blkno, uint32_t *size,
	int32_t less_is_ok, int32_t metadata)
{
	int32_t i, error = 0;
	struct udf_vfs *udf_vfsp;
	struct ud_part *ud_part;

	ud_printf("ud_alloc_space\n");


/*
 * prom_printf("ud_alloc_space %x %x %x %x\n",
 * proximity, blkcount, less_is_ok, metadata);
 */

	if (blkcount == 0) {
		*start_blkno = 0;
		*size = 0;
		return (0);
	}

	udf_vfsp = (struct udf_vfs *)vfsp->vfs_data;
	ud_part = udf_vfsp->udf_parts;
	for (i = 0; i < udf_vfsp->udf_npart; i++) {
		if (prn == ud_part->udp_number) {
			break;
		}
		ud_part ++;
	}

	if (i == udf_vfsp->udf_npart) {
		return (1);
	}
	*start_blkno = 0;
	*size = 0;
	if (metadata) {
		error = ud_alloc_from_cache(udf_vfsp, ud_part, start_blkno);
		if (error == 0) {
			*size = 1;
			return (0);
		}
	}
	if (ud_part->udp_nfree != 0) {
		if (ud_part->udp_flags == UDP_BITMAPS) {
			error = ud_alloc_space_bmap(vfsp, ud_part, proximity,
			    blkcount, start_blkno, size, less_is_ok);
		} else {
			error = ud_alloc_space_stbl(vfsp, ud_part, proximity,
			    blkcount, start_blkno, size, less_is_ok);
		}
		if (error == 0) {
			mutex_enter(&udf_vfsp->udf_lock);
			ASSERT(ud_part->udp_nfree >= *size);
			ASSERT(udf_vfsp->udf_freeblks >= *size);
			ud_part->udp_nfree -= *size;
			udf_vfsp->udf_freeblks -= *size;
			mutex_exit(&udf_vfsp->udf_lock);
		}
	} else {
		error = ENOSPC;
	}
/*
 * prom_printf("end %x %x %x\n", error, *start_blkno, *size);
 */

	return (error);
}

#ifdef	SKIP_USED_BLOCKS
/*
 * This table is manually constructed
 */
int8_t skip[256] = {
8, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
5, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
6, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
5, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
7, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
5, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
6, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
5, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0,
4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0
};
#endif

#define	HDR_BLKS	(24 * 8)

int32_t
ud_alloc_space_bmap(struct vfs *vfsp,
	struct ud_part *ud_part, uint32_t proximity,
	uint32_t blkcount, uint32_t *start_blkno,
	uint32_t *size, int32_t less_is_ok)
{
	struct buf *bp = NULL;
	struct udf_vfs *udf_vfsp;
	uint32_t old_loc, old_size, new_size;
	uint8_t *addr, *eaddr;
	uint32_t loop_count, loop_begin, loop_end;
	uint32_t bno, begin, dummy, temp, lbsz, bb_count;
	uint32_t bblk = 0, eblk = 0;
	int32_t fragmented;

	ud_printf("ud_alloc_space_bmap\n");

	ASSERT(ud_part);
	ASSERT(ud_part->udp_flags == UDP_BITMAPS);

	if (ud_part->udp_unall_len == 0) {
		return (ENOSPC);
	}
	udf_vfsp = (struct udf_vfs *)vfsp->vfs_data;
	lbsz = udf_vfsp->udf_lbsize;
	bb_count = udf_vfsp->udf_lbsize << 3;

	if (proximity != 0) {
		/*
		 * directly try allocating
		 * at proximity
		 */
		temp = blkcount;
		if (ud_check_free_and_mark_used(vfsp,
		    ud_part, proximity, &temp) == 0) {
			if (temp != 0) {
				*start_blkno = proximity;
				*size = temp;
				return (0);
			}
		}
		*start_blkno = 0;
		*size = 0;
	}

	mutex_enter(&udf_vfsp->udf_lock);
	fragmented = udf_vfsp->udf_fragmented;
	mutex_exit(&udf_vfsp->udf_lock);
retry:
	old_loc = old_size = 0;

	mutex_enter(&udf_vfsp->udf_lock);
	loop_begin = (ud_part->udp_last_alloc + CLSTR_MASK) & ~CLSTR_MASK;
	mutex_exit(&udf_vfsp->udf_lock);

	loop_end = ud_part->udp_nblocks + HDR_BLKS;
	loop_count = (loop_begin) ? 2 : 1;
	while (loop_count--) {
		for (bno = loop_begin + HDR_BLKS; bno + blkcount < loop_end; ) {


			/*
			 * Each bread is restricted to lbsize
			 * due to the way bread is implemented
			 */
			if ((bp == NULL) ||
			    ((eblk - bno) < blkcount)) {
				if (bp != NULL) {
					brelse(bp);
				}
				begin = ud_part->udp_unall_loc +
				    bno / bb_count;
				bp = ud_bread(vfsp->vfs_dev,
				    ud_xlate_to_daddr(udf_vfsp,
				    ud_part->udp_number,
				    begin, 1, &dummy) <<
				    udf_vfsp->udf_l2d_shift, lbsz);
				if (bp->b_flags & B_ERROR) {
					brelse(bp);
					return (EIO);
				}
				bblk = begin * bb_count;
				eblk = bblk + bb_count;
				addr = (uint8_t *)bp->b_un.b_addr;
				eaddr = addr + bp->b_bcount;
			}

			if (blkcount > (eblk - bno)) {
				temp = eblk - bno;
			} else {
				temp = blkcount;
			}
			if ((new_size = ud_check_free(addr, eaddr,
			    bno - bblk, temp)) == temp) {
				ud_mark_used(addr, bno - bblk, temp);
				bdwrite(bp);
				*start_blkno = bno - HDR_BLKS;
				*size = temp;
				mutex_enter(&udf_vfsp->udf_lock);
				ud_part->udp_last_alloc =
				    bno + temp - HDR_BLKS;
				mutex_exit(&udf_vfsp->udf_lock);
				return (0);
			}
			if (less_is_ok) {
				if (old_size < new_size) {
					old_loc = bno - HDR_BLKS;
					old_size = new_size;
				}
			}
			if (new_size != 0) {
				bno += new_size;
			} else {
#ifdef	SKIP_USED_BLOCKS
				/*
				 * Skipping 0's
				 * implement a allocated block skip
				 * using a while loop with an
				 * preinitialised array of 256 elements
				 * for number of blocks skipped
				 */
				bno &= ~3;
				while (skip[addr[(bno - bblk) >> 3]] == 8)
					bno += 8;
				bno += skip[addr[(bno - bblk) >> 3]];
#else
				bno++;
#endif
			}
			if (!fragmented) {
				bno = (bno + CLSTR_MASK) & ~CLSTR_MASK;
			}
		}
		if (bp != NULL) {
			brelse(bp);
			bp = NULL;
		}
		if (loop_count) {
			loop_end = loop_begin + HDR_BLKS;
			loop_begin = 0;
		}
	}
	if ((old_size == 0) && (!fragmented)) {
		mutex_enter(&udf_vfsp->udf_lock);
		fragmented = udf_vfsp->udf_fragmented = 1;
		mutex_exit(&udf_vfsp->udf_lock);
		goto retry;
	}
	if (less_is_ok && (old_size != 0)) {

		/*
		 * Check once again
		 * somebody else might have
		 * already allocated behind us
		 */
		if (ud_check_free_and_mark_used(vfsp,
		    ud_part, old_loc, &old_size) == 0) {
			if (old_size != 0) {
				*start_blkno = old_loc;
				*size = old_size;
				mutex_enter(&udf_vfsp->udf_lock);
				ud_part->udp_last_alloc = old_loc + old_size;
				mutex_exit(&udf_vfsp->udf_lock);
				return (0);
			}
		}

		/*
		 * Failed what ever the reason
		 */
		goto retry;
	}
	return (ENOSPC);
}

/*
 * start is the block from the begining
 * of the partition ud_part
 */
int32_t
ud_check_free_and_mark_used(struct vfs *vfsp,
	struct ud_part *ud_part, uint32_t start, uint32_t *count)
{
	struct buf *bp;
	struct udf_vfs *udf_vfsp;
	uint32_t begin, dummy, bb_count;

	/*
	 * Adjust start for the header
	 */
	start += HDR_BLKS;
	udf_vfsp = (struct udf_vfs *)vfsp->vfs_data;
	bb_count = udf_vfsp->udf_lbsize << 3;

	/*
	 * Read just on block worth of bitmap
	 */
	begin = ud_part->udp_unall_loc + (start / bb_count);
	bp = ud_bread(vfsp->vfs_dev,
	    ud_xlate_to_daddr(udf_vfsp, ud_part->udp_number,
	    begin, 1, &dummy) << udf_vfsp->udf_l2d_shift,
	    udf_vfsp->udf_lbsize);
	if (bp->b_flags & B_ERROR) {
		brelse(bp);
		return (EIO);
	}

	/*
	 * Adjust the count if necessary
	 */
	start -= begin * bb_count;
	if ((start + *count) > bb_count) {
		*count = bb_count - start;
		ASSERT(*count > 0);
	}
	if (ud_check_free((uint8_t *)bp->b_un.b_addr,
	    (uint8_t *)bp->b_un.b_addr + bp->b_bcount, start,
	    *count) != *count) {
		brelse(bp);
		return (1);
	}
	ud_mark_used((uint8_t *)bp->b_un.b_addr, start, *count);
	bdwrite(bp);

	return (0);
}

int32_t
ud_check_free(uint8_t *addr, uint8_t *eaddr, uint32_t start, uint32_t count)
{
	int32_t i = 0;

	for (i = 0; i < count; i++) {
		if (&addr[start >> 3] >= eaddr) {
			break;
		}
		if ((addr[start >> 3] & (1 << (start & 0x7))) == 0) {
			break;
		}
		start ++;
	}
	return (i);
}

void
ud_mark_used(uint8_t *addr, uint32_t start, uint32_t count)
{
	int32_t i = 0;

	for (i = 0; i < count; i++) {
		addr[start >> 3] &= ~(1 << (start & 0x7));
		start++;
	}
}

void
ud_mark_free(uint8_t *addr, uint32_t start, uint32_t count)
{
	int32_t i = 0;

	for (i = 0; i < count; i++) {
		addr[start >> 3] |= (1 << (start & 0x7));
		start++;
	}
}

/* ARGSUSED */
int32_t
ud_alloc_space_stbl(struct vfs *vfsp,
	struct ud_part *ud_part, uint32_t proximity,
	uint32_t blkcount, uint32_t *start_blkno,
	uint32_t *size, int32_t less_is_ok)
{
	uint16_t adesc;
	uint32_t temp, sz;
	int32_t error, index, count, larg_index, larg_sz;
	struct buf *bp;
	struct udf_vfs *udf_vfsp;
	struct unall_space_ent *use;

	ASSERT(ud_part);
	ASSERT(ud_part->udp_flags == UDP_SPACETBLS);

	ud_printf("ud_alloc_space_stbl\n");

	if (ud_part->udp_unall_len == 0) {
		return (ENOSPC);
	}

	udf_vfsp = (struct udf_vfs *)vfsp->vfs_data;
	ASSERT((ud_part->udp_unall_len + 40) <= udf_vfsp->udf_lbsize);

	bp = ud_bread(vfsp->vfs_dev,
	    ud_xlate_to_daddr(udf_vfsp, ud_part->udp_number,
	    ud_part->udp_unall_loc, 1, &temp), udf_vfsp->udf_lbsize);

	use = (struct unall_space_ent *)bp->b_un.b_addr;
	sz = SWAP_32(use->use_len_ad);
	adesc = SWAP_16(use->use_icb_tag.itag_flags) & 0x7;
	if (adesc == ICB_FLAG_SHORT_AD) {
		struct short_ad *sad;

		sad = (struct short_ad *)use->use_ad;
		count = sz / sizeof (struct short_ad);

		/*
		 * Search the entire list for
		 * a extent which can give the entire data
		 * Do only first fit
		 */
		larg_index = larg_sz = 0;
		for (index = 0; index < count; index++, sad++) {
			temp = SWAP_32(sad->sad_ext_len) >>
			    udf_vfsp->udf_l2b_shift;
			if (temp == blkcount) {
				/*
				 * We found the right fit
				 * return the values and
				 * compress the table
				 */
				less_is_ok = 1;
				larg_index = index;
				larg_sz = temp;
				goto compress_sad;
			} else if (temp > blkcount) {
				/*
				 * We found an entry larger than the
				 * requirement. Change the start block
				 * number and the count to reflect the
				 * allocation
				 */
				*start_blkno = SWAP_32(sad->sad_ext_loc);
				*size = blkcount;
				temp = (temp - blkcount) <<
				    udf_vfsp->udf_l2b_shift;
				sad->sad_ext_len = SWAP_32(temp);
				temp = SWAP_32(sad->sad_ext_loc) + blkcount;
				sad->sad_ext_loc = SWAP_32(temp);
				goto end;
			}
			/*
			 * Let us keep track of the largest
			 * extent available if less_is_ok.
			 */
			if (less_is_ok) {
				if (temp > larg_sz) {
					larg_sz = temp;
					larg_index = index;
				}
			}
		}
compress_sad:
		if ((less_is_ok) && (larg_sz != 0)) {
			/*
			 * If we came here we could
			 * not find a extent to cover the entire size
			 * return whatever could be allocated
			 * and compress the table
			 */
			sad = (struct short_ad *)use->use_ad;
			sad += larg_index;
			*start_blkno = SWAP_32(sad->sad_ext_loc);
			*size = larg_sz;
			for (index = larg_index; index < count;
			    index++, sad++) {
				*sad = *(sad+1);
			}
			sz -= sizeof (struct short_ad);
			use->use_len_ad = SWAP_32(sz);
		} else {
			error = ENOSPC;
		}
		goto end;
	} else if (adesc == ICB_FLAG_LONG_AD) {
		struct long_ad *lad;

		lad = (struct long_ad *)use->use_ad;
		count = sz / sizeof (struct long_ad);

		/*
		 * Search the entire list for
		 * a extent which can give the entire data
		 * Do only first fit
		 */
		larg_index = larg_sz = 0;
		for (index = 0; index < count; index++, lad++) {
			temp = SWAP_32(lad->lad_ext_len) >>
			    udf_vfsp->udf_l2b_shift;
			if (temp == blkcount) {
				/*
				 * We found the right fit
				 * return the values and
				 * compress the table
				 */
				less_is_ok = 1;
				larg_index = index;
				larg_sz = temp;
				goto compress_lad;
			} else if (temp > blkcount) {
				/*
				 * We found an entry larger than the
				 * requirement. Change the start block
				 * number and the count to reflect the
				 * allocation
				 */
				*start_blkno = SWAP_32(lad->lad_ext_loc);
				*size = blkcount;
				temp = (temp - blkcount) <<
				    udf_vfsp->udf_l2b_shift;
				lad->lad_ext_len = SWAP_32(temp);
				temp = SWAP_32(lad->lad_ext_loc) + blkcount;
				lad->lad_ext_loc = SWAP_32(temp);
				goto end;
			}
			/*
			 * Let us keep track of the largest
			 * extent available if less_is_ok.
			 */
			if (less_is_ok) {
				if (temp > larg_sz) {
					larg_sz = temp;
					larg_index = index;
				}
			}
		}
compress_lad:
		if ((less_is_ok) && (larg_sz != 0)) {
			/*
			 * If we came here we could
			 * not find a extent to cover the entire size
			 * return whatever could be allocated
			 * and compress the table
			 */
			lad = (struct long_ad *)use->use_ad;
			lad += larg_index;
			*start_blkno = SWAP_32(lad->lad_ext_loc);
			*size = larg_sz;
			for (index = larg_index; index < count;
			    index++, lad++) {
				*lad = *(lad+1);
			}
			sz -= sizeof (struct long_ad);
			use->use_len_ad = SWAP_32(sz);
		} else {
			error = ENOSPC;
		}
		goto end;
	} else {
		error = ENOSPC;
	}
end:
	if (!error) {
		bdwrite(bp);
	} else {
		brelse(bp);
	}
	return (error);
}


/*
 * release blkcount blocks starting from beginblk
 * Call appropriate bmap/space table fucntions
 */
void
ud_free_space(struct vfs *vfsp, uint16_t prn,
	uint32_t beginblk, uint32_t blkcount)
{
	int32_t i, error;
	struct ud_part *ud_part;
	struct udf_vfs *udf_vfsp;

	ud_printf("ud_free_space\n");

	if (blkcount == 0) {
		return;
	}

	udf_vfsp = (struct udf_vfs *)vfsp->vfs_data;
	ud_part = udf_vfsp->udf_parts;
	for (i = 0; i < udf_vfsp->udf_npart; i++) {
		if (prn == ud_part->udp_number) {
			break;
		}
		ud_part ++;
	}

	if (i == udf_vfsp->udf_npart) {
		return;
	}

	if (ud_part->udp_flags == UDP_BITMAPS) {
		error = ud_free_space_bmap(vfsp, ud_part, beginblk, blkcount);
	} else {
		error = ud_free_space_stbl(vfsp, ud_part, beginblk, blkcount);
	}

	if (error) {
		udf_vfsp->udf_mark_bad = 1;
	}
}

/*
 * If there is a freed table then
 * release blocks to the freed table
 * other wise release to the un allocated table.
 * Findout the offset into the bitmap and
 * mark the blocks as free blocks
 */
int32_t
ud_free_space_bmap(struct vfs *vfsp,
	struct ud_part *ud_part,
	uint32_t beginblk, uint32_t blkcount)
{
	struct buf *bp;
	struct udf_vfs *udf_vfsp;
	uint32_t block, begin, end, blkno, count, map_end_blk, dummy;

	ud_printf("ud_free_space_bmap\n");

	ASSERT(ud_part);
	ASSERT(ud_part->udp_flags == UDP_BITMAPS);
/*
 * prom_printf("%x %x\n", udblock, udcount);
 */

	udf_vfsp = (struct udf_vfs *)vfsp->vfs_data;
	if ((ud_part->udp_freed_len == 0) &&
	    (ud_part->udp_unall_len == 0)) {
		return (ENOSPC);
	}
	/*
	 * decide unallocated/freed table to use
	 */
	if (ud_part->udp_freed_len == 0) {
		begin = ud_part->udp_unall_loc;
		map_end_blk = ud_part->udp_unall_len << 3;
	} else {
		begin = ud_part->udp_freed_loc;
		map_end_blk = ud_part->udp_freed_len << 3;
	}

	if (beginblk + blkcount > map_end_blk) {
		return (ENOSPC);
	}

	/* adjust for the bitmap header */
	beginblk += HDR_BLKS;

	end = begin + ((beginblk + blkcount) / (udf_vfsp->udf_lbsize << 3));
	begin += (beginblk / (udf_vfsp->udf_lbsize << 3));

	for (block = begin; block <= end; block++) {

		bp = ud_bread(vfsp->vfs_dev,
		    ud_xlate_to_daddr(udf_vfsp, ud_part->udp_number, block, 1,
		    &dummy) << udf_vfsp->udf_l2d_shift, udf_vfsp->udf_lbsize);
		if (bp->b_flags & B_ERROR) {
			brelse(bp);
			return (EIO);
		}
		ASSERT(dummy == 1);

		mutex_enter(&udf_vfsp->udf_lock);

		/*
		 * add freed blocks to the bitmap
		 */

		blkno = beginblk - (block * (udf_vfsp->udf_lbsize << 3));
		if (blkno + blkcount > (udf_vfsp->udf_lbsize << 3)) {
			count = (udf_vfsp->udf_lbsize << 3) - blkno;
		} else {
			count = blkcount;
		}

/*
 * if (begin != end) {
 *	printf("%x %x %x %x %x %x\n",
 *		begin, end, block, blkno, count);
 *	printf("%x %x %x\n", bp->b_un.b_addr, blkno, count);
 * }
 */

		ud_mark_free((uint8_t *)bp->b_un.b_addr, blkno, count);

		beginblk += count;
		blkcount -= count;

		if (ud_part->udp_freed_len == 0) {
			ud_part->udp_nfree += count;
			udf_vfsp->udf_freeblks += count;
		}
		mutex_exit(&udf_vfsp->udf_lock);

		bdwrite(bp);
	}

	return (0);
}


/* ARGSUSED */
/*
 * search the entire table if there is
 * a entry with which we can merge the
 * current entry. Other wise create
 * a new entry at the end of the table
 */
int32_t
ud_free_space_stbl(struct vfs *vfsp,
	struct ud_part *ud_part,
	uint32_t beginblk, uint32_t blkcount)
{
	uint16_t adesc;
	int32_t error = 0, index, count;
	uint32_t block, dummy, sz;
	struct buf *bp;
	struct udf_vfs *udf_vfsp;
	struct unall_space_ent *use;

	ud_printf("ud_free_space_stbl\n");

	ASSERT(ud_part);
	ASSERT(ud_part->udp_flags == UDP_SPACETBLS);

	if ((ud_part->udp_freed_len == 0) && (ud_part->udp_unall_len == 0)) {
		return (ENOSPC);
	}

	if (ud_part->udp_freed_len != 0) {
		block = ud_part->udp_freed_loc;
	} else {
		block = ud_part->udp_unall_loc;
	}

	udf_vfsp = (struct udf_vfs *)vfsp->vfs_data;
	ASSERT((ud_part->udp_unall_len + 40) <= udf_vfsp->udf_lbsize);

	bp = ud_bread(vfsp->vfs_dev,
	    ud_xlate_to_daddr(udf_vfsp, ud_part->udp_number, block, 1, &dummy),
	    udf_vfsp->udf_lbsize);

	use = (struct unall_space_ent *)bp->b_un.b_addr;
	sz = SWAP_32(use->use_len_ad);
	adesc = SWAP_16(use->use_icb_tag.itag_flags) & 0x7;
	if (adesc == ICB_FLAG_SHORT_AD) {
		struct short_ad *sad;

		sad = (struct short_ad *)use->use_ad;
		count = sz / sizeof (struct short_ad);
		/*
		 * Check if the blocks being freed
		 * are continuous with any of the
		 * existing extents
		 */
		for (index = 0; index < count; index++, sad++) {
			if (beginblk == (SWAP_32(sad->sad_ext_loc) +
			    (SWAP_32(sad->sad_ext_len) /
			    udf_vfsp->udf_lbsize))) {
				dummy = SWAP_32(sad->sad_ext_len) +
				    blkcount * udf_vfsp->udf_lbsize;
				sad->sad_ext_len = SWAP_32(dummy);
				goto end;
			} else if ((beginblk + blkcount) ==
			    SWAP_32(sad->sad_ext_loc)) {
				sad->sad_ext_loc = SWAP_32(beginblk);
				goto end;
			}
		}

		/*
		 * We need to add a new entry
		 * Check if we space.
		 */
		if ((40 + sz + sizeof (struct short_ad)) >
		    udf_vfsp->udf_lbsize) {
			error = ENOSPC;
			goto end;
		}

		/*
		 * We have enough space
		 * just add the entry at the end
		 */
		dummy = SWAP_32(use->use_len_ad);
		sad = (struct short_ad *)&use->use_ad[dummy];
		sz = blkcount * udf_vfsp->udf_lbsize;
		sad->sad_ext_len = SWAP_32(sz);
		sad->sad_ext_loc = SWAP_32(beginblk);
		dummy += sizeof (struct short_ad);
		use->use_len_ad = SWAP_32(dummy);
	} else if (adesc == ICB_FLAG_LONG_AD) {
		struct long_ad *lad;

		lad = (struct long_ad *)use->use_ad;
		count = sz / sizeof (struct long_ad);
		/*
		 * Check if the blocks being freed
		 * are continuous with any of the
		 * existing extents
		 */
		for (index = 0; index < count; index++, lad++) {
			if (beginblk == (SWAP_32(lad->lad_ext_loc) +
			    (SWAP_32(lad->lad_ext_len) /
			    udf_vfsp->udf_lbsize))) {
				dummy = SWAP_32(lad->lad_ext_len) +
				    blkcount * udf_vfsp->udf_lbsize;
				lad->lad_ext_len = SWAP_32(dummy);
				goto end;
			} else if ((beginblk + blkcount) ==
			    SWAP_32(lad->lad_ext_loc)) {
				lad->lad_ext_loc = SWAP_32(beginblk);
				goto end;
			}
		}

		/*
		 * We need to add a new entry
		 * Check if we space.
		 */
		if ((40 + sz + sizeof (struct long_ad)) >
		    udf_vfsp->udf_lbsize) {
			error = ENOSPC;
			goto end;
		}

		/*
		 * We have enough space
		 * just add the entry at the end
		 */
		dummy = SWAP_32(use->use_len_ad);
		lad = (struct long_ad *)&use->use_ad[dummy];
		sz = blkcount * udf_vfsp->udf_lbsize;
		lad->lad_ext_len = SWAP_32(sz);
		lad->lad_ext_loc = SWAP_32(beginblk);
		lad->lad_ext_prn = SWAP_16(ud_part->udp_number);
		dummy += sizeof (struct long_ad);
		use->use_len_ad = SWAP_32(dummy);
	} else {
		error = ENOSPC;
		goto end;
	}

end:
	if (!error) {
		bdwrite(bp);
	} else {
		brelse(bp);
	}
	return (error);
}

/* ARGSUSED */
int32_t
ud_ialloc(struct ud_inode *pip,
	struct ud_inode **ipp, struct vattr *vap, struct cred *cr)
{
	int32_t err;
	uint32_t blkno, size, loc;
	uint32_t imode, ichar, lbsize, ea_len, dummy;
	uint16_t prn, flags;
	struct buf *bp;
	struct file_entry *fe;
	struct timespec32 time;
	struct timespec32 settime;
	struct icb_tag *icb;
	struct ext_attr_hdr *eah;
	struct dev_spec_ear *ds;
	struct udf_vfs *udf_vfsp;
	timestruc_t now;
	uid_t uid;
	gid_t gid;


	ASSERT(pip);
	ASSERT(vap != NULL);

	ud_printf("ud_ialloc\n");

	if (((vap->va_mask & AT_ATIME) && TIMESPEC_OVERFLOW(&vap->va_atime)) ||
	    ((vap->va_mask & AT_MTIME) && TIMESPEC_OVERFLOW(&vap->va_mtime)))
		return (EOVERFLOW);

	udf_vfsp = pip->i_udf;
	lbsize = udf_vfsp->udf_lbsize;
	prn = pip->i_icb_prn;

	if ((err = ud_alloc_space(pip->i_vfs, prn,
	    0, 1, &blkno, &size, 0, 1)) != 0) {
		return (err);
	}
	loc = ud_xlate_to_daddr(udf_vfsp, prn, blkno, 1, &dummy);
	ASSERT(dummy == 1);

	bp = ud_bread(pip->i_dev, loc << udf_vfsp->udf_l2d_shift, lbsize);
	if (bp->b_flags & B_ERROR) {
		ud_free_space(pip->i_vfs, prn, blkno, size);
		return (EIO);
	}
	bzero(bp->b_un.b_addr, bp->b_bcount);
	fe = (struct file_entry *)bp->b_un.b_addr;

	uid = crgetuid(cr);
	fe->fe_uid = SWAP_32(uid);

	/*
	 * To determine the group-id of the created file:
	 * 1) If the gid is set in the attribute list (non-Sun & pre-4.0
	 *	clients are not likely to set the gid), then use it if
	 *	the process is privileged, belongs to the target group,
	 *	or the group is the same as the parent directory.
	 * 2) If the filesystem was not mounted with the Old-BSD-compatible
	 *	GRPID option, and the directory's set-gid bit is clear,
	 *	then use the process's gid.
	 * 3) Otherwise, set the group-id to the gid of the parent directory.
	 */
	if ((vap->va_mask & AT_GID) &&
	    ((vap->va_gid == pip->i_gid) || groupmember(vap->va_gid, cr) ||
	    secpolicy_vnode_create_gid(cr) == 0)) {
		/*
		 * XXX - is this only the case when a 4.0 NFS client, or a
		 * client derived from that code, makes a call over the wire?
		 */
		fe->fe_gid = SWAP_32(vap->va_gid);
	} else {
		gid = crgetgid(cr);
		fe->fe_gid = (pip->i_char & ISGID) ?
		    SWAP_32(pip->i_gid) : SWAP_32(gid);
	}

	imode = MAKEIMODE(vap->va_type, vap->va_mode);
	ichar = imode & (VSUID | VSGID | VSVTX);
	imode = UD_UPERM2DPERM(imode);

	/*
	 * Under solaris only the owner can
	 * change the attributes of files so set
	 * the change attribute bit only for user
	 */
	imode |= IATTR;

	/*
	 * File delete permissions on Solaris are
	 * the permissions on the directory but not the file
	 * when we create a file just inherit the directorys
	 * write permission to be the file delete permissions
	 * Atleast we will be consistent in the files we create
	 */
	imode |= (pip->i_perm & (IWRITE | IWRITE >> 5 | IWRITE >> 10)) << 3;

	fe->fe_perms = SWAP_32(imode);

	/*
	 * udf does not have a "." entry in dir's
	 * so even directories have only one link
	 */
	fe->fe_lcount = SWAP_16(1);

	fe->fe_info_len = 0;
	fe->fe_lbr = 0;

	gethrestime(&now);
	time.tv_sec = now.tv_sec;
	time.tv_nsec = now.tv_nsec;
	if (vap->va_mask & AT_ATIME) {
		TIMESPEC_TO_TIMESPEC32(&settime, &vap->va_atime)
		ud_utime2dtime(&settime, &fe->fe_acc_time);
	} else
		ud_utime2dtime(&time, &fe->fe_acc_time);
	if (vap->va_mask & AT_MTIME) {
		TIMESPEC_TO_TIMESPEC32(&settime, &vap->va_mtime)
		ud_utime2dtime(&settime, &fe->fe_mod_time);
	} else
		ud_utime2dtime(&time, &fe->fe_mod_time);
	ud_utime2dtime(&time, &fe->fe_attr_time);

	ud_update_regid(&fe->fe_impl_id);

	mutex_enter(&udf_vfsp->udf_lock);
	fe->fe_uniq_id = SWAP_64(udf_vfsp->udf_maxuniq);
	udf_vfsp->udf_maxuniq++;
	mutex_exit(&udf_vfsp->udf_lock);

	ea_len = 0;
	if ((vap->va_type == VBLK) || (vap->va_type == VCHR)) {
		eah = (struct ext_attr_hdr *)fe->fe_spec;
		ea_len = (sizeof (struct ext_attr_hdr) + 3) & ~3;
		eah->eah_ial = SWAP_32(ea_len);

		ds = (struct dev_spec_ear *)&fe->fe_spec[ea_len];
		ea_len += ud_make_dev_spec_ear(ds,
		    getmajor(vap->va_rdev), getminor(vap->va_rdev));
		ea_len = (ea_len + 3) & ~3;
		eah->eah_aal = SWAP_32(ea_len);
		ud_make_tag(udf_vfsp, &eah->eah_tag,
		    UD_EXT_ATTR_HDR, blkno, ea_len);
	}

	fe->fe_len_ear = SWAP_32(ea_len);
	fe->fe_len_adesc = 0;

	icb = &fe->fe_icb_tag;
	icb->itag_prnde = 0;
	icb->itag_strategy = SWAP_16(STRAT_TYPE4);
	icb->itag_param = 0;
	icb->itag_max_ent = SWAP_16(1);
	switch (vap->va_type) {
		case VREG :
			icb->itag_ftype = FTYPE_FILE;
			break;
		case VDIR :
			icb->itag_ftype = FTYPE_DIRECTORY;
			break;
		case VBLK :
			icb->itag_ftype = FTYPE_BLOCK_DEV;
			break;
		case VCHR :
			icb->itag_ftype = FTYPE_CHAR_DEV;
			break;
		case VLNK :
			icb->itag_ftype = FTYPE_SYMLINK;
			break;
		case VFIFO :
			icb->itag_ftype = FTYPE_FIFO;
			break;
		case VSOCK :
			icb->itag_ftype = FTYPE_C_ISSOCK;
			break;
		default :
			brelse(bp);
			goto error;
	}
	icb->itag_lb_loc = 0;
	icb->itag_lb_prn = 0;
	flags = ICB_FLAG_ONE_AD;
	if ((pip->i_char & ISGID) && (vap->va_type == VDIR)) {
		ichar |= ISGID;
	} else {
		if ((ichar & ISGID) &&
		    secpolicy_vnode_setids_setgids(cr,
		    (gid_t)SWAP_32(fe->fe_gid)) != 0) {
			ichar &= ~ISGID;
		}
	}
	if (ichar & ISUID) {
		flags |= ICB_FLAG_SETUID;
	}
	if (ichar & ISGID) {
		flags |= ICB_FLAG_SETGID;
	}
	if (ichar & ISVTX) {
		flags |= ICB_FLAG_STICKY;
	}
	icb->itag_flags = SWAP_16(flags);
	ud_make_tag(udf_vfsp, &fe->fe_tag, UD_FILE_ENTRY, blkno,
	    offsetof(struct file_entry, fe_spec) +
	    SWAP_32(fe->fe_len_ear) + SWAP_32(fe->fe_len_adesc));

	BWRITE2(bp);

	mutex_enter(&udf_vfsp->udf_lock);
	if (vap->va_type == VDIR) {
		udf_vfsp->udf_ndirs++;
	} else {
		udf_vfsp->udf_nfiles++;
	}
	mutex_exit(&udf_vfsp->udf_lock);

#ifdef	DEBUG
	{
		struct ud_inode *ip;

		if ((ip = ud_search_icache(pip->i_vfs, prn, blkno)) != NULL) {
			cmn_err(CE_NOTE, "duplicate %p %x\n",
			    (void *)ip, (uint32_t)ip->i_icb_lbano);
		}
	}
#endif

	if ((err = ud_iget(pip->i_vfs, prn, blkno, ipp, bp, cr)) != 0) {
error:
		ud_free_space(pip->i_vfs, prn, blkno, size);
		return (err);
	}

	return (0);

noinodes:
	cmn_err(CE_NOTE, "%s: out of inodes\n", pip->i_udf->udf_volid);
	return (ENOSPC);
}


void
ud_ifree(struct ud_inode *ip, vtype_t type)
{
	struct udf_vfs *udf_vfsp;
	struct buf *bp;

	ud_printf("ud_ifree\n");

	if (ip->i_vfs == NULL) {
		return;
	}

	udf_vfsp = (struct udf_vfs *)ip->i_vfs->vfs_data;
	bp = ud_bread(ip->i_dev, ip->i_icb_lbano <<
	    udf_vfsp->udf_l2d_shift, udf_vfsp->udf_lbsize);
	if (bp->b_flags & B_ERROR) {
		/*
		 * Error get rid of bp
		 */
		brelse(bp);
	} else {
		/*
		 * Just trash the inode
		 */
		bzero(bp->b_un.b_addr, 0x10);
		BWRITE(bp);
	}
	ud_free_space(ip->i_vfs, ip->i_icb_prn, ip->i_icb_block, 1);
	mutex_enter(&udf_vfsp->udf_lock);
	if (type == VDIR) {
		if (udf_vfsp->udf_ndirs > 1) {
			udf_vfsp->udf_ndirs--;
		}
	} else {
		if (udf_vfsp->udf_nfiles > 0) {
			udf_vfsp->udf_nfiles --;
		}
	}
	mutex_exit(&udf_vfsp->udf_lock);
}


/*
 * Free storage space associated with the specified inode.  The portion
 * to be freed is specified by lp->l_start and lp->l_len (already
 * normalized to a "whence" of 0).
 *
 * This is an experimental facility whose continued existence is not
 * guaranteed.  Currently, we only support the special case
 * of l_len == 0, meaning free to end of file.
 *
 * Blocks are freed in reverse order.  This FILO algorithm will tend to
 * maintain a contiguous free list much longer than FIFO.
 * See also ufs_itrunc() in ufs_inode.c.
 *
 * Bug: unused bytes in the last retained block are not cleared.
 * This may result in a "hole" in the file that does not read as zeroes.
 */
int32_t
ud_freesp(struct vnode *vp,
	struct flock64 *lp,
	int32_t flag, struct cred *cr)
{
	int32_t i;
	struct ud_inode *ip = VTOI(vp);
	int32_t error;

	ASSERT(vp->v_type == VREG);
	ASSERT(lp->l_start >= (offset_t)0);	/* checked by convoff */

	ud_printf("udf_freesp\n");

	if (lp->l_len != 0) {
		return (EINVAL);
	}

	rw_enter(&ip->i_contents, RW_READER);
	if (ip->i_size == (u_offset_t)lp->l_start) {
		rw_exit(&ip->i_contents);
		return (0);
	}

	/*
	 * Check if there is any active mandatory lock on the
	 * range that will be truncated/expanded.
	 */
	if (MANDLOCK(vp, ip->i_char)) {
		offset_t save_start;

		save_start = lp->l_start;

		if (ip->i_size < lp->l_start) {
			/*
			 * "Truncate up" case: need to make sure there
			 * is no lock beyond current end-of-file. To
			 * do so, we need to set l_start to the size
			 * of the file temporarily.
			 */
			lp->l_start = ip->i_size;
		}
		lp->l_type = F_WRLCK;
		lp->l_sysid = 0;
		lp->l_pid = ttoproc(curthread)->p_pid;
		i = (flag & (FNDELAY|FNONBLOCK)) ? 0 : SLPFLCK;
		rw_exit(&ip->i_contents);
		if ((i = reclock(vp, lp, i, 0, lp->l_start, NULL)) != 0 ||
		    lp->l_type != F_UNLCK) {
			return (i ? i : EAGAIN);
		}
		rw_enter(&ip->i_contents, RW_READER);

		lp->l_start = save_start;
	}
	/*
	 * Make sure a write isn't in progress (allocating blocks)
	 * by acquiring i_rwlock (we promised ufs_bmap we wouldn't
	 * truncate while it was allocating blocks).
	 * Grab the locks in the right order.
	 */
	rw_exit(&ip->i_contents);
	rw_enter(&ip->i_rwlock, RW_WRITER);
	rw_enter(&ip->i_contents, RW_WRITER);
	error = ud_itrunc(ip, lp->l_start, 0, cr);
	rw_exit(&ip->i_contents);
	rw_exit(&ip->i_rwlock);
	return (error);
}



/*
 * Cache is implemented by
 * allocating a cluster of blocks
 */
int32_t
ud_alloc_from_cache(struct udf_vfs *udf_vfsp,
	struct ud_part *part, uint32_t *blkno)
{
	uint32_t bno, sz;
	int32_t error, index, free = 0;

	ud_printf("ud_alloc_from_cache\n");

	ASSERT(udf_vfsp);

	mutex_enter(&udf_vfsp->udf_lock);
	if (part->udp_cache_count == 0) {
		mutex_exit(&udf_vfsp->udf_lock);
		/* allocate new cluster */
		if ((error = ud_alloc_space(udf_vfsp->udf_vfs,
		    part->udp_number, 0, CLSTR_SIZE, &bno, &sz, 1, 0)) != 0) {
			return (error);
		}
		if (sz == 0) {
			return (ENOSPC);
		}
		mutex_enter(&udf_vfsp->udf_lock);
		if (part->udp_cache_count == 0) {
			for (index = 0; index < sz; index++, bno++) {
				part->udp_cache[index] = bno;
			}
			part->udp_cache_count = sz;
		} else {
			free = 1;
		}
	}
	part->udp_cache_count--;
	*blkno = part->udp_cache[part->udp_cache_count];
	mutex_exit(&udf_vfsp->udf_lock);
	if (free) {
		ud_free_space(udf_vfsp->udf_vfs, part->udp_number, bno, sz);
	}
	return (0);
}

/*
 * Will be called from unmount
 */
int32_t
ud_release_cache(struct udf_vfs *udf_vfsp)
{
	int32_t i, error = 0;
	struct ud_part *part;
	uint32_t start, nblks;

	ud_printf("ud_release_cache\n");

	mutex_enter(&udf_vfsp->udf_lock);
	part = udf_vfsp->udf_parts;
	for (i = 0; i < udf_vfsp->udf_npart; i++, part++) {
		if (part->udp_cache_count) {
			nblks = part->udp_cache_count;
			start = part->udp_cache[0];
			part->udp_cache_count = 0;
			mutex_exit(&udf_vfsp->udf_lock);
			ud_free_space(udf_vfsp->udf_vfs,
			    part->udp_number, start, nblks);
			mutex_enter(&udf_vfsp->udf_lock);
		}
	}
	mutex_exit(&udf_vfsp->udf_lock);
	return (error);
}
