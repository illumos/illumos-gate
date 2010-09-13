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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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


int32_t ud_break_create_new_icb(struct ud_inode *, int32_t, uint32_t);
int32_t ud_bump_ext_count(struct ud_inode *, int32_t);
void ud_remove_ext_at_index(struct ud_inode *, int32_t);
int32_t ud_last_alloc_ext(struct ud_inode *, uint64_t, uint32_t, int32_t);
int32_t ud_create_ext(struct ud_inode *, int32_t, uint32_t,
	int32_t, uint64_t, uint64_t *);
int32_t	ud_zero_it(struct ud_inode *, uint32_t, uint32_t);

#define	ALLOC_SPACE	0x01
#define	NEW_EXT		0x02

#define	MEXT_BITS	30

int32_t
ud_bmap_has_holes(struct ud_inode *ip)
{
	int32_t i, error = 0;
	struct icb_ext *iext;

	ud_printf("ud_bmap_has_holes\n");

	ASSERT(RW_LOCK_HELD(&ip->i_contents));

	/* ICB_FLAG_ONE_AD is always continuos */
	if (ip->i_desc_type != ICB_FLAG_ONE_AD) {
		if ((error = ud_read_icb_till_off(ip, ip->i_size)) == 0) {
			for (i = 0; i < ip->i_ext_used; i++) {
				iext = &ip->i_ext[i];
				if (iext->ib_flags == IB_UN_RE_AL) {
					error = 1;
					break;
				}
			}
		}
	}

	return (error);
}

int32_t
ud_bmap_read(struct ud_inode *ip, u_offset_t off, daddr_t *bnp, int32_t *lenp)
{
	struct icb_ext *iext;
	daddr_t bno;
	int32_t lbmask, i, l2b, l2d, error = 0, count;
	uint32_t length, block, dummy;

	ud_printf("ud_bmap_read\n");

	ASSERT(RW_LOCK_HELD(&ip->i_contents));

	lbmask = ip->i_udf->udf_lbmask;
	l2b = ip->i_udf->udf_l2b_shift;
	l2d = ip->i_udf->udf_l2d_shift;

	if ((error = ud_read_icb_till_off(ip, ip->i_size)) == 0) {
		for (i = 0; i < ip->i_ext_used; i++) {
			iext = &ip->i_ext[i];
			if ((iext->ib_offset <= off) &&
				(off < (iext->ib_offset + iext->ib_count))) {
				length = ((iext->ib_offset +
						iext->ib_count - off) +
						lbmask) & ~lbmask;
				if (iext->ib_flags == IB_UN_RE_AL) {
					*bnp = UDF_HOLE;
					*lenp = length;
					break;
				}

				block = iext->ib_block +
					((off - iext->ib_offset) >> l2b);
				count = length >> l2b;

				bno = ud_xlate_to_daddr(ip->i_udf,
					iext->ib_prn, block, count, &dummy);
				ASSERT(dummy != 0);
				ASSERT(dummy <= count);
				*bnp = bno << l2d;
				*lenp = dummy << l2b;

				break;
			}
		}
		if (i == ip->i_ext_used) {
			error = EINVAL;
		}
	}

	return (error);
}


/*
 * Extent allocation in the inode
 * Initially when the inode is allocated we
 * will allocate EXT_PER_MALLOC extents and once these
 * are used we allocate another 10 and copy
 * the old extents and start using the others
 */
#define	BASE(count)	((count) & ~lbmask)
#define	CEIL(count)	(((count) + lbmask) & ~lbmask)

#define	PBASE(count)	((count) & PAGEMASK)
#define	PCEIL(count)	(((count) + PAGEOFFSET) & PAGEMASK)


/* ARGSUSED3 */
int32_t
ud_bmap_write(struct ud_inode *ip,
	u_offset_t off, int32_t size, int32_t alloc_only, struct cred *cr)
{
	int32_t error = 0, i, isdir, issync;
	struct udf_vfs *udf_vfsp;
	struct icb_ext *iext, *pext;
	uint32_t blkno, sz;
	u_offset_t isize;
	uint32_t acount, prox;
	int32_t blkcount, next;
	int32_t lbmask, l2b;
	uint64_t end_req, end_ext, mext_sz, icb_offset, count;
	int32_t dtype_changed = 0, memory_allocated = 0;
	struct	fbuf *fbp = NULL;


	ud_printf("ud_bmap_write\n");

	ASSERT(RW_WRITE_HELD(&ip->i_contents));

	udf_vfsp = ip->i_udf;
	lbmask = udf_vfsp->udf_lbmask;
	l2b = udf_vfsp->udf_l2b_shift;
	mext_sz = (1 << MEXT_BITS) - PAGESIZE;

	if (lblkno(udf_vfsp, off) < 0) {
		return (EFBIG);
	}

	issync = ((ip->i_flag & ISYNC) != 0);

	isdir = (ip->i_type == VDIR);
	if (isdir || issync) {
		alloc_only = 0;		/* make sure */
	}

	end_req = BASE(off) + size;
	if (ip->i_desc_type == ICB_FLAG_ONE_AD) {
		if (end_req < ip->i_max_emb) {
			goto out;
		}

		if (ip->i_size != 0) {
			error = fbread(ITOV(ip), 0, ip->i_size, S_OTHER, &fbp);
			if (error != 0) {
				goto out;
			}
		} else {
			fbp = NULL;
		}
		/*
		 * Change the desc_type
		 */
		ip->i_desc_type = ICB_FLAG_SHORT_AD;
		dtype_changed = 1;

one_ad_no_i_ext:
		ASSERT(ip->i_ext == NULL);
		ASSERT(ip->i_astrat == STRAT_TYPE4);

		ip->i_ext_used = 0;
		ip->i_cur_max_ext = ip->i_max_emb / sizeof (struct short_ad);
		ip->i_cur_max_ext --;
		if (end_req > mext_sz) {
			next = end_req / mext_sz;
		} else {
			next = 1;
		}
		ip->i_ext_count =
			((next / EXT_PER_MALLOC) + 1) * EXT_PER_MALLOC;
		iext = ip->i_ext = (struct icb_ext  *)kmem_zalloc(
			ip->i_ext_count * sizeof (struct icb_ext), KM_SLEEP);
		memory_allocated = 1;

		/* There will be atleast EXT_PER_MALLOC icb_ext's allocated */

one_ad_i_ext:
		icb_offset = 0;
		count = end_req;

		/* Can we create a HOLE */

		if ((PCEIL(ip->i_size) < PBASE(off)) &&
			((PBASE(off) - PCEIL(ip->i_size)) >= PAGESIZE)) {

			if (ip->i_size != 0) {

				/*
				 * Allocate one block for
				 * old data.(cannot be more than one page)
				 */

				count = PAGESIZE;
				if (error = ud_create_ext(ip, ip->i_ext_used,
					ALLOC_SPACE | NEW_EXT, alloc_only,
					icb_offset, &count)) {
					goto embedded_error;
				}
				icb_offset = PAGESIZE;
			}

			/*
			 * Allocate a hole from PCEIL(ip->i_size) to PBASE(off)
			 */

			count = PBASE(off) - PCEIL(ip->i_size);
			(void) ud_create_ext(ip, ip->i_ext_used, NEW_EXT,
					alloc_only, icb_offset, &count);
			icb_offset = PBASE(off);

			/*
			 * Allocate the rest of the space PBASE(off) to end_req
			 */
			count = end_req - PBASE(off);
		} else {
			/*
			 * If no hole can be created then allocate
			 * space till the end of the request
			 */
			count = end_req;
		}



		if (error = ud_create_ext(ip, ip->i_ext_used,
				ALLOC_SPACE | NEW_EXT,
				alloc_only, icb_offset, &count)) {
embedded_error:
			/*
			 * Something error
			 * most probable file system is full
			 * we know that the file came in as a embedded file.
			 * undo what ever we did in this block of code
			 */
			if (dtype_changed) {
				ip->i_desc_type = ICB_FLAG_ONE_AD;
			}
			for (i = 0; i < ip->i_ext_used; i++) {
				iext = &ip->i_ext[i];
				if (iext->ib_flags != IB_UN_RE_AL) {
					ud_free_space(ip->i_udf->udf_vfs,
						iext->ib_prn, iext->ib_block,
						(iext->ib_count + lbmask) >>
							l2b);
				}
			}
			if (memory_allocated) {
				kmem_free(ip->i_ext,
					ip->i_ext_count *
					sizeof (struct icb_ext));
				ip->i_ext = NULL;
				ip->i_ext_count = ip->i_ext_used = 0;
			}
		}

		if (fbp != NULL) {
			fbrelse(fbp, S_WRITE);
		}

		return (error);
	} else {

		/*
		 * Type 4 directories being created
		 */
		if (ip->i_ext == NULL) {
			goto one_ad_no_i_ext;
		}

		/*
		 * Read the entire icb's to memory
		 */
		if (ud_read_icb_till_off(ip, ip->i_size) != 0) {
			error = EINVAL;
			goto out;
		}

		isize = CEIL(ip->i_size);

		if (end_req > isize) {

			/*
			 * The new file size is greater
			 * than the old size
			 */

			if (ip->i_ext == NULL) {
				goto one_ad_no_i_ext;
			} else if (ip->i_ext_used == 0) {
				goto one_ad_i_ext;
			}

			error = ud_last_alloc_ext(ip, off, size, alloc_only);

			return (error);
		} else {

			/*
			 * File growing the new size will be less than
			 * iext->ib_offset + CEIL(iext->ib_count)
			 */

			iext = &ip->i_ext[ip->i_ext_used - 1];

			if (end_req > (iext->ib_offset + iext->ib_count)) {

				iext->ib_count = end_req - iext->ib_offset;

				if (iext->ib_flags != IB_UN_RE_AL) {
					error = 0;
					goto out;
				}
			}
		}
	}

	/* By this point the end of last extent is >= BASE(off) + size */

	ASSERT(ip->i_ext);

	/*
	 * Figure out the icb_ext that has offset "off"
	 */
	for (i = 0; i < ip->i_ext_used; i++) {
		iext = &ip->i_ext[i];
		if ((iext->ib_offset <= off) &&
			((iext->ib_offset + iext->ib_count) > off)) {
			break;
		}
	}

	/*
	 * iext will have offset "off"
	 */


	do {
		iext = &ip->i_ext[i];

		if ((iext->ib_flags & IB_UN_RE_AL) == 0) {

			/*
			 * Already allocated do nothing
			 */

			i++;
		} else {

			/*
			 * We are in a hole.
			 * allocate the required space
			 * while trying to create smaller holes
			 */

			if ((PBASE(off) > PBASE(iext->ib_offset)) &&
				((PBASE(off) - PBASE(iext->ib_offset)) >=
						PAGESIZE)) {

				/*
				 * Allocate space from begining of
				 * old hole to the begining of new hole
				 * We want all holes created by us
				 * to be MMUPAGE Aligned
				 */

				if (PBASE(iext->ib_offset) !=
						BASE(iext->ib_offset)) {
					if ((error = ud_break_create_new_icb(
						ip, i, BASE(iext->ib_offset) -
						PBASE(iext->ib_offset))) != 0) {
						return (error);
					}
					goto alloc_cur_ext;
				}

				/*
				 * Create the new hole
				 */

				if ((error = ud_break_create_new_icb(ip, i,
					PBASE(off) - iext->ib_offset)) != 0) {
					return (error);
				}
				iext = &ip->i_ext[i];
				i++;
				continue;
			}

			end_ext = iext->ib_offset + iext->ib_count;

			if ((PBASE(end_ext) > PCEIL(end_req)) &&
				((PBASE(end_ext) - PCEIL(end_req)) >=
							PAGESIZE)) {
				/*
				 * We can create a hole
				 * from PCEIL(end_req) - BASE(end_ext)
				 */
				if ((error = ud_break_create_new_icb(ip, i,
				PCEIL(end_req) - iext->ib_offset)) != 0) {
					return (error);
				}
			}


alloc_cur_ext:
			/*
			 * Allocate the current extent
			 */


			/*
			 * If the previous extent
			 * is allocated then try to allocate
			 * adjascent to the previous extent
			 */
			prox = 0;
			if (i != 0) {
				pext = &ip->i_ext[i - 1];
				if (pext->ib_flags != IB_UN_RE_AL) {
					prox = pext->ib_block +
						(CEIL(pext->ib_count) >> l2b);
				}
			}

			iext = &ip->i_ext[i];
			blkcount = CEIL(iext->ib_count) >> l2b;

			if ((error = ud_alloc_space(ip->i_vfs,
					ip->i_icb_prn, prox, blkcount,
					&blkno, &sz, 1, 0)) != 0) {
				return (error);
			}
			ip->i_lbr += sz;
			if (sz == 0) {
				return (ENOSPC);
			}

			if (alloc_only == 0) {
				error = ud_zero_it(ip, blkno, sz);
			}

			acount = sz << l2b;
			if ((prox == blkno) &&
				((pext->ib_count + acount) < mext_sz)) {

				/*
				 * We are able to allocate adjascent to
				 * the previous extent. Increment the
				 * previous extent count if the size
				 * of the extent is not greater than
				 * max extent size
				 */

				pext = &ip->i_ext[i - 1];
				pext->ib_count += acount;

				if (sz == blkcount) {
					/*
					 * and get rid of the current
					 * extent since we have
					 * allocated all of its size
					 * and incremented the
					 * previous extents count
					 */
					ud_remove_ext_at_index(ip, i);
				} else {
					/*
					 * reduce the count of the
					 * current extent by the amount
					 * allocated in the last extent
					 */
					ASSERT(acount < iext->ib_count);
					iext->ib_count -= acount;
					iext->ib_offset += acount;
				}
			} else {
				if (sz < blkcount) {
					if ((error = ud_break_create_new_icb(
						ip, i, sz << l2b)) != 0) {
						return (error);
					}
				}
				iext = &ip->i_ext[i];
				count -= CEIL(iext->ib_count);
				iext->ib_prn = ip->i_icb_prn;
				iext->ib_block = blkno;
				iext->ib_flags &= ~IB_UN_RE_AL;
/*
 *				iext->ib_flags |= IB_UN_REC;
 */
				i++;
				continue;
			}
		}
	} while ((iext->ib_offset + iext->ib_count) < end_req);

out:
	return (error);
}


/*
 * increase i_con/i_ext arrays and set new elements
 * using long or short allocation descriptors
 */
static void
ud_common_ad(struct ud_inode *ip, struct buf *bp)
{
	int32_t ndesc, count, lbmask;
	uint32_t length;
	struct alloc_ext_desc *aed;
	struct icb_ext *iext, *con;
	u_offset_t offset;
	long_ad_t *lad;
	short_ad_t *sad;
	int islong;
	void *addr;

	addr = bp->b_un.b_addr + sizeof (struct alloc_ext_desc);
	aed = (struct alloc_ext_desc *)bp->b_un.b_addr;
	length = SWAP_32(aed->aed_len_aed);
	if (ip->i_desc_type == ICB_FLAG_LONG_AD) {
		islong = 1;
		lad = addr;
		ndesc = length / sizeof (*lad);
	} else if (ip->i_desc_type == ICB_FLAG_SHORT_AD) {
		islong = 0;
		sad = addr;
		ndesc = length / sizeof (*sad);
	} else
		return;

	/*
	 * realloc i_ext array
	 */
	count = (((ip->i_ext_used + ndesc) / EXT_PER_MALLOC) + 1) *
	    EXT_PER_MALLOC;
	addr = kmem_zalloc(count * sizeof (struct icb_ext), KM_SLEEP);
	bcopy(ip->i_ext, addr, ip->i_ext_used * sizeof (struct icb_ext));
	kmem_free(ip->i_ext, ip->i_ext_count * sizeof (struct icb_ext));
	ip->i_ext = addr;
	ip->i_ext_count = count;

	/*
	 * scan descriptors
	 */
	lbmask = ip->i_udf->udf_lbmask;
	iext = &ip->i_ext[ip->i_ext_used - 1];
	offset = iext->ib_offset + iext->ib_count;
	iext++;
	while (ndesc--) {
		if (islong)
			length = SWAP_32(lad->lad_ext_len);
		else
			length = SWAP_32(sad->sad_ext_len);

		if ((length & 0x3FFFFFFF) == 0)
			break;
		else if (((length >> 30) & IB_MASK) == IB_CON) {
			if (ip->i_con_used == ip->i_con_count) {
				struct icb_ext *old;
				int32_t old_count;

				old = ip->i_con;
				old_count = ip->i_con_count *
				    sizeof (struct icb_ext);
				ip->i_con_count += EXT_PER_MALLOC;
				ip->i_con = kmem_zalloc(ip->i_con_count *
				    sizeof (struct icb_ext), KM_SLEEP);

				if (old) {
					bcopy(old, ip->i_con, old_count);
					kmem_free(old, old_count);
				}
			}
			con = &ip->i_con[ip->i_con_used];
			if (islong) {
				con->ib_prn = SWAP_16(lad->lad_ext_prn);
				con->ib_block = SWAP_32(lad->lad_ext_loc);
			} else {
				con->ib_prn = ip->i_icb_prn;
				con->ib_block = SWAP_32(sad->sad_ext_loc);
			}
			con->ib_count = length & 0x3FFFFFFF;
			con->ib_flags = (length >> 30) & IB_MASK;
			ip->i_con_used++;
			break;
		}

		if (islong) {
			iext->ib_prn = SWAP_16(lad->lad_ext_prn);
			iext->ib_block = SWAP_32(lad->lad_ext_loc);
			lad++;
		} else {
			iext->ib_prn = 0;
			iext->ib_block = SWAP_32(sad->sad_ext_loc);
			sad++;
		}
		iext->ib_count = length & 0x3FFFFFFF;
		iext->ib_offset = offset;
		iext->ib_marker1 = (uint32_t)0xAAAAAAAA;
		iext->ib_marker2 = (uint32_t)0xBBBBBBBB;
		offset += (iext->ib_count + lbmask) & (~lbmask);
		iext->ib_flags = (length >> 30) & IB_MASK;
		ip->i_ext_used++;
		iext++;
	}
}


static int32_t
ud_read_next_cont(struct ud_inode *ip)
{
	uint32_t dummy, error = 0;
	struct alloc_ext_desc *aed;
	struct icb_ext *cont;
	struct buf *bp;
	daddr_t bno;

	cont = &ip->i_con[ip->i_con_read];
	ASSERT(cont->ib_count > 0);

	bno = ud_xlate_to_daddr(ip->i_udf, cont->ib_prn, cont->ib_block,
	    1, &dummy);
	bp = ud_bread(ip->i_dev, bno << ip->i_udf->udf_l2d_shift,
	    cont->ib_count);
	if (bp->b_flags & B_ERROR)
		error = bp->b_error;
	else {
		aed = (struct alloc_ext_desc *)bp->b_un.b_addr;
		if (ud_verify_tag_and_desc(&aed->aed_tag, UD_ALLOC_EXT_DESC,
		    cont->ib_block, 1, cont->ib_count))
			error = EINVAL;
	}

	if (error == 0)
		ud_common_ad(ip, bp);

	brelse(bp);
	return (error);
}


int32_t
ud_read_icb_till_off(struct ud_inode *ip, u_offset_t offset)
{
	int32_t error = 0;
	struct icb_ext *iext;

	ud_printf("ud_read_icb_till_off\n");

	if (ip->i_desc_type == ICB_FLAG_ONE_AD)
		return (0);
	else if ((ip->i_astrat != STRAT_TYPE4) &&
	    (ip->i_astrat != STRAT_TYPE4096))
		return (EINVAL);
	else if (ip->i_ext_used == 0)
		return ((ip->i_size == 0) ? 0 : EINVAL);

	/*
	 * supported allocation strategies are
	 * STRAT_TYPE4 and STRAT_TYPE4096
	 */

	mutex_enter(&ip->i_con_lock);
	iext = &ip->i_ext[ip->i_ext_used - 1];
	while ((iext->ib_offset + iext->ib_count) < offset) {
		if (ip->i_con_used == ip->i_con_read) {
			error = EINVAL;
			break;
		}
		if (error = ud_read_next_cont(ip))
			break;
		ip->i_con_read++;
		iext = &ip->i_ext[ip->i_ext_used - 1];
	}
	mutex_exit(&ip->i_con_lock);

	return (error);
}


/*
 * Assumption is the off is beyond ip->i_size
 * And we will have atleast one ext used
 */
int32_t
ud_last_alloc_ext(struct ud_inode *ip, uint64_t off,
		uint32_t size, int32_t alloc_only)
{
	struct icb_ext *iext;
	struct udf_vfs *udf_vfsp;
	int32_t lbsize, lbmask;
	uint64_t end_req, end_count, icb_offset;
	uint64_t count;
	int32_t error = 0;


	udf_vfsp = ip->i_udf;
	lbsize = udf_vfsp->udf_lbsize;
	lbmask = udf_vfsp->udf_lbmask;

	end_req = BASE(off) + size;


	/*
	 * If we are here it means the file
	 * is growing beyond the end of the
	 * current block. So round up the
	 * last extent
	 */

	iext = &ip->i_ext[ip->i_ext_used - 1];
	iext->ib_count = CEIL(iext->ib_count);

	/*
	 * Figure out if we can create
	 * a hole here
	 */


	end_count = iext->ib_offset + iext->ib_count;

	if ((PCEIL(end_count) < PBASE(off)) &&
		((PBASE(off) - PCEIL(end_count)) >= PAGESIZE)) {

		count = PCEIL(end_count) - CEIL(end_count);
		if (count >= lbsize) {

			/*
			 * There is space between the begining
			 * of the hole to be created and
			 * end of the last offset
			 * Allocate blocks for it
			 */

			iext = &ip->i_ext[ip->i_ext_used - 1];
			icb_offset = iext->ib_offset + CEIL(iext->ib_count);

			if (iext->ib_flags == IB_UN_RE_AL) {

				/*
				 * Previous extent is a unallocated
				 * extent. Create a new allocated
				 * extent
				 */

				error = ud_create_ext(ip, ip->i_ext_used,
					ALLOC_SPACE | NEW_EXT,
					alloc_only, icb_offset, &count);

			} else {

				/*
				 * Last extent is allocated
				 * try to allocate adjascent to the
				 * last extent
				 */

				error = ud_create_ext(ip, ip->i_ext_used - 1,
						ALLOC_SPACE, alloc_only,
						icb_offset, &count);
			}

			if (error != 0) {
				return (error);
			}
		}

		iext = &ip->i_ext[ip->i_ext_used - 1];
		end_count = iext->ib_offset + iext->ib_count;
		count = PBASE(off) - PCEIL(end_count);
		icb_offset = PCEIL(end_count);

		if (iext->ib_flags == IB_UN_RE_AL) {

			/*
			 * The last extent is unallocated
			 * Just bump the extent count
			 */
			(void) ud_create_ext(ip, ip->i_ext_used - 1,
					0, alloc_only, icb_offset, &count);
		} else {

			/*
			 * Last extent is allocated
			 * round up the size of the extent to
			 * lbsize and allocate a new unallocated extent
			 */
			iext->ib_count = CEIL(iext->ib_count);
			(void) ud_create_ext(ip, ip->i_ext_used,
				NEW_EXT, alloc_only, icb_offset, &count);
		}

		icb_offset = PBASE(off);
	} else {

		/*
		 * We cannot create any hole inbetween
		 * the last extent and the off so
		 * round up the count in the last extent
		 */

		iext = &ip->i_ext[ip->i_ext_used - 1];
		iext->ib_count = CEIL(iext->ib_count);

	}


	iext = &ip->i_ext[ip->i_ext_used - 1];
	count = end_req - (iext->ib_offset + iext->ib_count);
	icb_offset = iext->ib_offset + CEIL(iext->ib_count);

	if (iext->ib_flags == IB_UN_RE_AL) {

		/*
		 * Last extent was a unallocated extent
		 * create a new extent
		 */

		error = ud_create_ext(ip, ip->i_ext_used,
			ALLOC_SPACE | NEW_EXT, alloc_only, icb_offset, &count);
	} else {

		/*
		 * Last extent was an allocated extent
		 * try to allocate adjascent to the old blocks
		 */

		error = ud_create_ext(ip, ip->i_ext_used - 1,
			ALLOC_SPACE, alloc_only, icb_offset, &count);
	}

	return (error);
}

/*
 * Break up the icb_ext at index
 * into two icb_ext,
 * one at index ib_count "count" and
 * the other at index+1 with ib_count = old_ib_count - count
 */
int32_t
ud_break_create_new_icb(struct ud_inode *ip,
	int32_t index, uint32_t count)
{
	int32_t i, error;
	struct icb_ext *iext, *next;


	ud_printf("ud_break_create_new_icb\n");
	iext = &ip->i_ext[index];

	ASSERT(count < iext->ib_count);

	if ((error = ud_bump_ext_count(ip, KM_SLEEP)) != 0) {
		return (error);
	}

	for (i = ip->i_ext_used; i > index; i--) {
		ip->i_ext[i] = ip->i_ext[i - 1];
	}

	next = &ip->i_ext[index + 1];
	iext = &ip->i_ext[index];

	iext->ib_count = count;
	next->ib_count -= count;
	next->ib_offset = iext->ib_offset + iext->ib_count;
	if (iext->ib_flags != IB_UN_RE_AL) {
		next->ib_block = iext->ib_block +
			iext->ib_count >> ip->i_udf->udf_l2b_shift;
	}
	ip->i_ext_used++;
	return (0);
}

void
ud_remove_ext_at_index(struct ud_inode *ip, int32_t index)
{
	int32_t i;

	ASSERT(index <= ip->i_ext_used);

	for (i = index; i < ip->i_ext_used; i++) {
		if ((i + 1) < ip->i_ext_count) {
			ip->i_ext[i] = ip->i_ext[i + 1];
		} else {
			bzero(&ip->i_ext[i], sizeof (struct icb_ext));
		}
	}
	ip->i_ext_used --;
}

int32_t
ud_bump_ext_count(struct ud_inode *ip, int32_t sleep_flag)
{
	int32_t error = 0;
	struct icb_ext *iext;
	uint32_t old_count, elen;

	ASSERT(ip);
	ASSERT(sleep_flag == KM_SLEEP);

	ud_printf("ud_bump_ext_count\n");

	if (ip->i_ext_used >= ip->i_ext_count) {

		old_count = sizeof (struct icb_ext) * ip->i_ext_count;
		ip->i_ext_count += EXT_PER_MALLOC;
		iext = kmem_zalloc(sizeof (struct icb_ext) *
				ip->i_ext_count, sleep_flag);
		bcopy(ip->i_ext, iext, old_count);
		kmem_free(ip->i_ext, old_count);
		ip->i_ext = iext;
	}

	if (ip->i_ext_used >= ip->i_cur_max_ext) {
		int32_t prox;
		struct icb_ext *icon;
		uint32_t blkno, sz;
		int32_t lbmask, l2b;

		lbmask = ip->i_udf->udf_lbmask;
		l2b = ip->i_udf->udf_l2b_shift;

		if ((error = ud_read_icb_till_off(ip, ip->i_size)) != 0) {
			return (error);
		}

		/*
		 * If there are any old cont extents
		 * allocate the new one ajscant to the old one
		 */
		if (ip->i_con_used != 0) {
			icon = &ip->i_con[ip->i_con_used - 1];
			prox = icon->ib_block + (CEIL(icon->ib_count) >> l2b);
		} else {
			prox = 0;
		}

		/*
		 * Allocate space
		 */
		if ((error = ud_alloc_space(ip->i_vfs, ip->i_icb_prn,
				prox, 1, &blkno, &sz, 0, 0)) != 0) {
			return (error);
		}
		if (sz == 0) {
			return (ENOSPC);
		}

		sz <<= l2b;

		if (ip->i_con_used == ip->i_con_count) {
			struct icb_ext *old;
			int32_t old_count;

			old = ip->i_con;
			old_count = ip->i_con_count *
				sizeof (struct icb_ext);
			ip->i_con_count += EXT_PER_MALLOC;
			ip->i_con = kmem_zalloc(ip->i_con_count *
				sizeof (struct icb_ext), KM_SLEEP);
			if (old != 0) {
				bcopy(old, ip->i_con, old_count);
				kmem_free(old, old_count);
			}
		}
		icon = &ip->i_con[ip->i_con_used++];
		icon->ib_flags = IB_CON;
		icon->ib_prn = ip->i_icb_prn;
		icon->ib_block = blkno;
		icon->ib_count = sz;
		icon->ib_offset = 0;
		icon->ib_marker1 = (uint32_t)0xAAAAAAAA;
		icon->ib_marker2 = (uint32_t)0xBBBBBBBB;

		/*
		 * Bump the i_cur_max_ext according to
		 * the space allocated
		 */
		if (ip->i_desc_type == ICB_FLAG_SHORT_AD) {
			elen = sizeof (struct short_ad);
		} else if (ip->i_desc_type == ICB_FLAG_LONG_AD) {
			elen = sizeof (struct long_ad);
		} else {
			return (ENOSPC);
		}
		sz = sz - (sizeof (struct alloc_ext_desc) + elen);
		ip->i_cur_max_ext += sz / elen;
	}
	return (error);
}

int32_t
ud_create_ext(struct ud_inode *ip, int32_t index, uint32_t flags,
	int32_t alloc_only, uint64_t offset, uint64_t *count)
{
	struct icb_ext *iext, *pext;
	struct udf_vfs *udf_vfsp;
	int32_t error = 0, blkcount, acount;
	uint32_t blkno, sz, prox, mext_sz;
	int32_t lbmask, l2b;

	if (*count == 0) {
		return (0);
	}

begin:
	udf_vfsp = ip->i_udf;
	lbmask = udf_vfsp->udf_lbmask;
	l2b = udf_vfsp->udf_l2b_shift;
	mext_sz = (1 << MEXT_BITS) - PAGESIZE;

	if ((error = ud_bump_ext_count(ip, KM_SLEEP)) != 0) {
		return (error);
	}

	iext = &ip->i_ext[index];
	if (flags & ALLOC_SPACE) {
		if ((flags & NEW_EXT) ||
			(ip->i_ext_count == 0)) {

			iext->ib_flags = 0;
			iext->ib_prn = ip->i_icb_prn;
			if (*count > mext_sz) {
				blkcount = mext_sz >> l2b;
			} else {
				blkcount = CEIL(*count) >> l2b;
			}
			if ((error = ud_alloc_space(ip->i_vfs,
					ip->i_icb_prn, 0, blkcount,
					&blkno, &sz, 1, 0)) != 0) {
				return (error);
			}
			if (sz == 0) {
				return (ENOSPC);
			}
			ip->i_lbr += sz;
			iext->ib_block = blkno;
			acount = sz << l2b;
			if ((sz << l2b) > *count) {
				iext->ib_count = *count;
				*count = 0;
			} else {
				iext->ib_count = sz << l2b;
				*count -= iext->ib_count;
			}
			iext->ib_offset = offset;
			if (ip->i_ext_used <= index)
				ip->i_ext_used ++;
		} else {
			if ((iext->ib_count + *count) > mext_sz) {
				blkcount = (mext_sz - iext->ib_count) >> l2b;
			} else {
				blkcount = CEIL(*count) >> l2b;
			}
			if (blkcount == 0) {
				flags |= NEW_EXT;
				index++;
				goto begin;
			}
			prox = iext->ib_block + (CEIL(iext->ib_count) >> l2b);
			if ((error = ud_alloc_space(ip->i_vfs,
					ip->i_icb_prn, prox, blkcount,
					&blkno, &sz, 1, 0)) != 0) {
				return (error);
			}
			if (sz == 0) {
				return (ENOSPC);
			}
			acount = sz << l2b;
			if (acount > *count) {
				acount = *count;
				*count = 0;
			} else {
				*count -= acount;
			}
			ip->i_lbr += sz;
			if (prox == blkno) {
				iext->ib_count += acount;
			} else {
				if ((error = ud_bump_ext_count(ip, KM_SLEEP))
						!= 0) {
					return (error);
				}
				pext = &ip->i_ext[index];
				iext = &ip->i_ext[index + 1];
				iext->ib_flags = 0;
				iext->ib_prn = ip->i_icb_prn;
				iext->ib_block = blkno;
				iext->ib_offset =
					pext->ib_offset + pext->ib_count;
				iext->ib_count = acount;
				/*
				 * Increment the index, since we have used
				 * the extent at [index+1] above.
				 */
				index++;
				if (ip->i_ext_used <= index)
					ip->i_ext_used ++;
			}
		}
		if (alloc_only == 0) {
			error = ud_zero_it(ip, blkno, sz);
		}
		if (*count) {
			offset = iext->ib_offset + CEIL(iext->ib_count);
			flags |= NEW_EXT;
			index++;
			goto begin;
		}
	} else {
		if (flags & NEW_EXT) {
			iext->ib_flags = IB_UN_RE_AL;
			iext->ib_prn = 0;
			iext->ib_block = 0;
			if (*count > mext_sz) {
				iext->ib_count = mext_sz;
				*count -= iext->ib_count;
			} else {
				iext->ib_count = *count;
				*count = 0;
			}
			iext->ib_offset = offset;
			if (ip->i_ext_used <= index)
				ip->i_ext_used ++;
		} else {
			ASSERT(iext->ib_flags == IB_UN_RE_AL);
			if ((iext->ib_count + *count) > mext_sz) {
				acount = mext_sz - iext->ib_count;
				iext->ib_count += acount;
				*count -= acount;
			} else {
				iext->ib_count += *count;
				*count = 0;
			}
		}
		if (*count != 0) {
			offset = iext->ib_offset + CEIL(iext->ib_count);
			flags |= NEW_EXT;
			index++;
			goto begin;
		}
	}
	iext->ib_marker1 = (uint32_t)0xAAAAAAAA;
	iext->ib_marker2 = (uint32_t)0xBBBBBBBB;
	return (error);
}

#undef	CEIL
#undef	BASE

int32_t
ud_zero_it(struct ud_inode *ip, uint32_t start_block, uint32_t block_count)
{
	struct udf_vfs *udf_vfsp;
	uint32_t bno, dummy;
	int32_t error;
	struct buf *bp;

	/*
	 * Donot use bio routines
	 * since the buffer can sit
	 * long enough in cache for the space
	 * to be allocated/freed and
	 * then allocated
	 */
	udf_vfsp = ip->i_udf;
	bno = ud_xlate_to_daddr(udf_vfsp,
		ip->i_icb_prn, start_block, block_count, &dummy);

	dummy = block_count << udf_vfsp->udf_l2b_shift;
	bp = (struct buf *)kmem_zalloc(biosize(), KM_SLEEP);
	sema_init(&bp->b_sem, 0, NULL, SEMA_DEFAULT, NULL);
	sema_init(&bp->b_io, 0, NULL, SEMA_DEFAULT, NULL);

	bp->b_flags = B_WRITE | B_BUSY;
	bp->b_edev = ip->i_dev;
	bp->b_dev = cmpdev(ip->i_dev);
	bp->b_blkno = bno << udf_vfsp->udf_l2d_shift;
	bp->b_bcount = dummy;
	bp->b_un.b_addr = kmem_zalloc(bp->b_bcount, KM_SLEEP);
	bp->b_file = ip->i_vnode;
	bp->b_offset = -1;

	(void) bdev_strategy(bp);
	if (error = biowait(bp)) {
		cmn_err(CE_WARN, "error in write\n");
	}

	kmem_free(bp->b_un.b_addr, dummy);
	sema_destroy(&bp->b_io);
	sema_destroy(&bp->b_sem);
	kmem_free((caddr_t)bp, biosize());

	return (error);
}
