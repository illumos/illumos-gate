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
 * Copyright (c) 1998, 2010, Oracle and/or its affiliates. All rights reserved.
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

extern struct vnodeops *udf_vnodeops;

kmutex_t ud_sync_busy;
/*
 * udf_vfs list manipulation routines
 */
kmutex_t udf_vfs_mutex;
struct udf_vfs *udf_vfs_instances;
#ifndef	__lint
_NOTE(MUTEX_PROTECTS_DATA(udf_vfs_mutex, udf_vfs_instances))
#endif

union ihead ud_ihead[UD_HASH_SZ];
kmutex_t ud_icache_lock;

#define	UD_BEGIN	0x0
#define	UD_END		0x1
#define	UD_UNKN		0x2
struct ud_inode *udf_ifreeh, *udf_ifreet;
kmutex_t udf_ifree_lock;
#ifndef	__lint
_NOTE(MUTEX_PROTECTS_DATA(udf_ifree_lock, udf_ifreeh))
_NOTE(MUTEX_PROTECTS_DATA(udf_ifree_lock, udf_ifreet))
#endif

kmutex_t ud_nino_lock;
int32_t ud_max_inodes = 512;
int32_t ud_cur_inodes = 0;
#ifndef	__lint
_NOTE(MUTEX_PROTECTS_DATA(ud_nino_lock, ud_cur_inodes))
#endif

uid_t ud_default_uid = 0;
gid_t ud_default_gid = 3;

int32_t ud_updat_ext4(struct ud_inode *, struct file_entry *);
int32_t ud_updat_ext4096(struct ud_inode *, struct file_entry *);
void ud_make_sad(struct icb_ext *, struct short_ad *, int32_t);
void ud_make_lad(struct icb_ext *, struct long_ad *, int32_t);
void ud_trunc_ext4(struct ud_inode *, u_offset_t);
void ud_trunc_ext4096(struct ud_inode *, u_offset_t);
void ud_add_to_free_list(struct ud_inode *, uint32_t);
void ud_remove_from_free_list(struct ud_inode *, uint32_t);


#ifdef	DEBUG
struct ud_inode *
ud_search_icache(struct vfs *vfsp, uint16_t prn, uint32_t ploc)
{
	int32_t hno;
	union ihead *ih;
	struct ud_inode *ip;
	struct udf_vfs *udf_vfsp;
	uint32_t loc, dummy;

	udf_vfsp = (struct udf_vfs *)vfsp->vfs_data;
	loc = ud_xlate_to_daddr(udf_vfsp, prn, ploc, 1, &dummy);

	mutex_enter(&ud_icache_lock);
	hno = UD_INOHASH(vfsp->vfs_dev, loc);
	ih = &ud_ihead[hno];
	for (ip = ih->ih_chain[0];
	    ip != (struct ud_inode *)ih;
	    ip = ip->i_forw) {
		if ((prn == ip->i_icb_prn) && (ploc == ip->i_icb_block) &&
		    (vfsp->vfs_dev == ip->i_dev)) {
			mutex_exit(&ud_icache_lock);
			return (ip);
		}
	}
	mutex_exit(&ud_icache_lock);
	return (0);
}
#endif

/* ARGSUSED */
int
ud_iget(struct vfs *vfsp, uint16_t prn, uint32_t ploc,
	struct ud_inode **ipp, struct buf *pbp, struct cred *cred)
{
	int32_t hno, nomem = 0, icb_tag_flags;
	union ihead *ih;
	struct ud_inode *ip;
	struct vnode *vp;
	struct buf *bp = NULL;
	struct file_entry *fe;
	struct udf_vfs *udf_vfsp;
	struct ext_attr_hdr *eah;
	struct attr_hdr *ah;
	int32_t ea_len, ea_off;
	daddr_t loc;
	uint64_t offset = 0;
	struct icb_ext *iext, *con;
	uint32_t length, dummy;
	int32_t ndesc, ftype;
	uint16_t old_prn;
	uint32_t old_block, old_lbano;

	ud_printf("ud_iget\n");
	udf_vfsp = (struct udf_vfs *)vfsp->vfs_data;
	old_prn = 0;
	old_block = old_lbano = 0;
	ftype = 0;
	loc = ud_xlate_to_daddr(udf_vfsp, prn, ploc, 1, &dummy);
loop:
	mutex_enter(&ud_icache_lock);
	hno = UD_INOHASH(vfsp->vfs_dev, loc);

	ih = &ud_ihead[hno];
	for (ip = ih->ih_chain[0];
	    ip != (struct ud_inode *)ih;
	    ip = ip->i_forw) {

		if ((prn == ip->i_icb_prn) &&
		    (ploc == ip->i_icb_block) &&
		    (vfsp->vfs_dev == ip->i_dev)) {

			vp = ITOV(ip);
			VN_HOLD(vp);
			mutex_exit(&ud_icache_lock);

			rw_enter(&ip->i_contents, RW_READER);
			mutex_enter(&ip->i_tlock);
			if ((ip->i_flag & IREF) == 0) {
				mutex_enter(&udf_ifree_lock);
				ud_remove_from_free_list(ip, UD_UNKN);
				mutex_exit(&udf_ifree_lock);
			}
			ip->i_flag |= IREF;
			mutex_exit(&ip->i_tlock);
			rw_exit(&ip->i_contents);

			*ipp = ip;

			if (pbp != NULL) {
				brelse(pbp);
			}

			return (0);
		}
	}

	/*
	 * We don't have it in the cache
	 * Allocate a new entry
	 */
tryagain:
	mutex_enter(&udf_ifree_lock);
	mutex_enter(&ud_nino_lock);
	if (ud_cur_inodes > ud_max_inodes) {
		int32_t purged;

		mutex_exit(&ud_nino_lock);
		while (udf_ifreeh == NULL ||
		    vn_has_cached_data(ITOV(udf_ifreeh))) {
			/*
			 * Try to put an inode on the freelist that's
			 * sitting in the dnlc.
			 */
			mutex_exit(&udf_ifree_lock);
			purged = dnlc_fs_purge1(udf_vnodeops);
			mutex_enter(&udf_ifree_lock);
			if (!purged) {
				break;
			}
		}
		mutex_enter(&ud_nino_lock);
	}

	/*
	 * If there's a free one available and it has no pages attached
	 * take it. If we're over the high water mark, take it even if
	 * it has attached pages. Otherwise, make a new one.
	 */
	if (udf_ifreeh &&
	    (nomem || !vn_has_cached_data(ITOV(udf_ifreeh)) ||
	    ud_cur_inodes >= ud_max_inodes)) {

		mutex_exit(&ud_nino_lock);
		ip = udf_ifreeh;
		vp = ITOV(ip);

		ud_remove_from_free_list(ip, UD_BEGIN);

		mutex_exit(&udf_ifree_lock);
		if (ip->i_flag & IREF) {
			cmn_err(CE_WARN, "ud_iget: bad i_flag\n");
			mutex_exit(&ud_icache_lock);
			if (pbp != NULL) {
				brelse(pbp);
			}
			return (EINVAL);
		}
		rw_enter(&ip->i_contents, RW_WRITER);

		/*
		 * We call udf_syncip() to synchronously destroy all pages
		 * associated with the vnode before re-using it. The pageout
		 * thread may have beat us to this page so our v_count can
		 * be > 0 at this point even though we are on the freelist.
		 */
		mutex_enter(&ip->i_tlock);
		ip->i_flag = (ip->i_flag & IMODTIME) | IREF;
		mutex_exit(&ip->i_tlock);

		VN_HOLD(vp);
		if (ud_syncip(ip, B_INVAL, I_SYNC) != 0) {
			ud_idrop(ip);
			rw_exit(&ip->i_contents);
			mutex_exit(&ud_icache_lock);
			goto loop;
		}

		mutex_enter(&ip->i_tlock);
		ip->i_flag &= ~IMODTIME;
		mutex_exit(&ip->i_tlock);

		if (ip->i_ext) {
			kmem_free(ip->i_ext,
			    sizeof (struct icb_ext) * ip->i_ext_count);
			ip->i_ext = 0;
			ip->i_ext_count = ip->i_ext_used = 0;
		}

		if (ip->i_con) {
			kmem_free(ip->i_con,
			    sizeof (struct icb_ext) * ip->i_con_count);
			ip->i_con = 0;
			ip->i_con_count = ip->i_con_used = ip->i_con_read = 0;
		}

		/*
		 * The pageout thread may not have had a chance to release
		 * its hold on the vnode (if it was active with this vp),
		 * but the pages should all be invalidated.
		 */
	} else {
		mutex_exit(&ud_nino_lock);
		mutex_exit(&udf_ifree_lock);
		/*
		 * Try to get memory for this inode without blocking.
		 * If we can't and there is something on the freelist,
		 * go ahead and use it, otherwise block waiting for
		 * memory holding the hash_lock. We expose a potential
		 * deadlock if all users of memory have to do a ud_iget()
		 * before releasing memory.
		 */
		ip = (struct ud_inode *)kmem_zalloc(sizeof (struct ud_inode),
		    KM_NOSLEEP);
		vp = vn_alloc(KM_NOSLEEP);
		if ((ip == NULL) || (vp == NULL)) {
			mutex_enter(&udf_ifree_lock);
			if (udf_ifreeh) {
				mutex_exit(&udf_ifree_lock);
				if (ip != NULL)
					kmem_free(ip, sizeof (struct ud_inode));
				if (vp != NULL)
					vn_free(vp);
				nomem = 1;
				goto tryagain;
			} else {
				mutex_exit(&udf_ifree_lock);
				if (ip == NULL)
					ip = (struct ud_inode *)
					    kmem_zalloc(
					    sizeof (struct ud_inode),
					    KM_SLEEP);
				if (vp == NULL)
					vp = vn_alloc(KM_SLEEP);
			}
		}
		ip->i_vnode = vp;

		ip->i_marker1 = (uint32_t)0xAAAAAAAA;
		ip->i_marker2 = (uint32_t)0xBBBBBBBB;
		ip->i_marker3 = (uint32_t)0xCCCCCCCC;

		rw_init(&ip->i_rwlock, NULL, RW_DEFAULT, NULL);
		rw_init(&ip->i_contents, NULL, RW_DEFAULT, NULL);
		mutex_init(&ip->i_tlock, NULL, MUTEX_DEFAULT, NULL);

		ip->i_forw = ip;
		ip->i_back = ip;
		vp->v_data = (caddr_t)ip;
		vn_setops(vp, udf_vnodeops);
		ip->i_flag = IREF;
		cv_init(&ip->i_wrcv, NULL, CV_DRIVER, NULL);
		mutex_enter(&ud_nino_lock);
		ud_cur_inodes++;
		mutex_exit(&ud_nino_lock);

		rw_enter(&ip->i_contents, RW_WRITER);
	}

	if (vp->v_count < 1) {
		cmn_err(CE_WARN, "ud_iget: v_count < 1\n");
		mutex_exit(&ud_icache_lock);
		rw_exit(&ip->i_contents);
		if (pbp != NULL) {
			brelse(pbp);
		}
		return (EINVAL);
	}
	if (vn_has_cached_data(vp)) {
		cmn_err(CE_WARN, "ud_iget: v_pages not NULL\n");
		mutex_exit(&ud_icache_lock);
		rw_exit(&ip->i_contents);
		if (pbp != NULL) {
			brelse(pbp);
		}
		return (EINVAL);
	}

	/*
	 * Move the inode on the chain for its new (ino, dev) pair
	 */
	remque(ip);
	ip->i_forw = ip;
	ip->i_back = ip;
	insque(ip, ih);

	ip->i_dev = vfsp->vfs_dev;
	ip->i_udf = udf_vfsp;
	ip->i_diroff = 0;
	ip->i_devvp = ip->i_udf->udf_devvp;
	ip->i_icb_prn = prn;
	ip->i_icb_block = ploc;
	ip->i_icb_lbano = loc;
	ip->i_nextr = 0;
	ip->i_seq = 0;
	mutex_exit(&ud_icache_lock);

read_de:
	if (pbp != NULL) {
		/*
		 * assumption is that we will not
		 * create a 4096 file
		 */
		bp = pbp;
	} else {
		bp = ud_bread(ip->i_dev,
		    ip->i_icb_lbano << udf_vfsp->udf_l2d_shift,
		    udf_vfsp->udf_lbsize);
	}

	/*
	 * Check I/O errors
	 */
	fe = (struct file_entry *)bp->b_un.b_addr;
	if ((bp->b_flags & B_ERROR) ||
	    (ud_verify_tag_and_desc(&fe->fe_tag, UD_FILE_ENTRY,
	    ip->i_icb_block, 1, udf_vfsp->udf_lbsize) != 0)) {

		if (((bp->b_flags & B_ERROR) == 0) &&
		    (ftype == STRAT_TYPE4096)) {
			if (ud_check_te_unrec(udf_vfsp,
			    bp->b_un.b_addr, ip->i_icb_block) == 0) {

				brelse(bp);

				/*
				 * restore old file entry location
				 */
				ip->i_icb_prn = old_prn;
				ip->i_icb_block = old_block;
				ip->i_icb_lbano = old_lbano;

				/*
				 * reread old file entry
				 */
				bp = ud_bread(ip->i_dev,
				    old_lbano << udf_vfsp->udf_l2d_shift,
				    udf_vfsp->udf_lbsize);
				if ((bp->b_flags & B_ERROR) == 0) {
					fe = (struct file_entry *)
					    bp->b_un.b_addr;
					if (ud_verify_tag_and_desc(&fe->fe_tag,
					    UD_FILE_ENTRY, ip->i_icb_block, 1,
					    udf_vfsp->udf_lbsize) == 0) {
						goto end_4096;
					}
				}
			}
		}
error_ret:
		brelse(bp);
		/*
		 * The inode may not contain anything useful. Mark it as
		 * having an error and let anyone else who was waiting for
		 * this know there was an error. Callers waiting for
		 * access to this inode in ud_iget will find
		 * the i_icb_lbano == 0, so there won't be a match.
		 * It remains in the cache. Put it back on the freelist.
		 */
		mutex_enter(&vp->v_lock);
		vp->v_count--;
		mutex_exit(&vp->v_lock);
		ip->i_icb_lbano = 0;

		/*
		 * The folowing two lines make
		 * it impossible for any one do
		 * a VN_HOLD and then a VN_RELE
		 * so avoiding a ud_iinactive
		 */
		ip->i_icb_prn = 0xffff;
		ip->i_icb_block = 0;

		/*
		 * remove the bad inode from hash chains
		 * so that during unmount we will not
		 * go through this inode
		 */
		mutex_enter(&ud_icache_lock);
		remque(ip);
		ip->i_forw = ip;
		ip->i_back = ip;
		mutex_exit(&ud_icache_lock);

		/* Put the inode at the front of the freelist */
		mutex_enter(&ip->i_tlock);
		mutex_enter(&udf_ifree_lock);
		ud_add_to_free_list(ip, UD_BEGIN);
		mutex_exit(&udf_ifree_lock);
		ip->i_flag = 0;
		mutex_exit(&ip->i_tlock);
		rw_exit(&ip->i_contents);
		return (EIO);
	}

	if (fe->fe_icb_tag.itag_strategy == SWAP_16(STRAT_TYPE4096)) {
		struct buf *ibp = NULL;
		struct indirect_entry *ie;

		/*
		 * save old file_entry location
		 */
		old_prn = ip->i_icb_prn;
		old_block = ip->i_icb_block;
		old_lbano = ip->i_icb_lbano;

		ftype = STRAT_TYPE4096;

		/*
		 * If astrat is 4096 different versions
		 * of the file exist on the media.
		 * we are supposed to get to the latest
		 * version of the file
		 */

		/*
		 * IE is supposed to be in the next block
		 * of DE
		 */
		ibp = ud_bread(ip->i_dev,
		    (ip->i_icb_lbano + 1) << udf_vfsp->udf_l2d_shift,
		    udf_vfsp->udf_lbsize);
		if (ibp->b_flags & B_ERROR) {
			/*
			 * Get rid of current ibp and
			 * then goto error on DE's bp
			 */
ie_error:
			brelse(ibp);
			goto error_ret;
		}

		ie = (struct indirect_entry *)ibp->b_un.b_addr;
		if (ud_verify_tag_and_desc(&ie->ie_tag,
		    UD_INDIRECT_ENT, ip->i_icb_block + 1,
		    1, udf_vfsp->udf_lbsize) == 0) {
			struct long_ad *lad;

			lad = &ie->ie_indirecticb;
			ip->i_icb_prn = SWAP_16(lad->lad_ext_prn);
			ip->i_icb_block = SWAP_32(lad->lad_ext_loc);
			ip->i_icb_lbano = ud_xlate_to_daddr(udf_vfsp,
			    ip->i_icb_prn, ip->i_icb_block,
			    1, &dummy);
			brelse(ibp);
			brelse(bp);
			goto read_de;
		}

		/*
		 * If this block is TE or unrecorded we
		 * are at the last entry
		 */
		if (ud_check_te_unrec(udf_vfsp, ibp->b_un.b_addr,
		    ip->i_icb_block + 1) != 0) {
			/*
			 * This is not an unrecorded block
			 * Check if it a valid IE and
			 * get the address of DE that
			 * this IE points to
			 */
			goto ie_error;
		}
		/*
		 * If ud_check_unrec returns "0"
		 * this is the last in the chain
		 * Latest file_entry
		 */
		brelse(ibp);
	}

end_4096:

	ip->i_uid = SWAP_32(fe->fe_uid);
	if (ip->i_uid == -1) {
		ip->i_uid = ud_default_uid;
	}
	ip->i_gid = SWAP_32(fe->fe_gid);
	if (ip->i_gid == -1) {
		ip->i_gid = ud_default_gid;
	}
	ip->i_perm = SWAP_32(fe->fe_perms) & 0xFFFF;
	if (fe->fe_icb_tag.itag_strategy == SWAP_16(STRAT_TYPE4096)) {
		ip->i_perm &= ~(IWRITE | (IWRITE >> 5) | (IWRITE >> 10));
	}

	ip->i_nlink = SWAP_16(fe->fe_lcount);
	ip->i_size = SWAP_64(fe->fe_info_len);
	ip->i_lbr = SWAP_64(fe->fe_lbr);

	ud_dtime2utime(&ip->i_atime, &fe->fe_acc_time);
	ud_dtime2utime(&ip->i_mtime, &fe->fe_mod_time);
	ud_dtime2utime(&ip->i_ctime, &fe->fe_attr_time);


	ip->i_uniqid = SWAP_64(fe->fe_uniq_id);
	icb_tag_flags = SWAP_16(fe->fe_icb_tag.itag_flags);

	if ((fe->fe_icb_tag.itag_ftype == FTYPE_CHAR_DEV) ||
	    (fe->fe_icb_tag.itag_ftype == FTYPE_BLOCK_DEV)) {

		eah = (struct ext_attr_hdr *)fe->fe_spec;
		ea_off = GET_32(&eah->eah_ial);
		ea_len = GET_32(&fe->fe_len_ear);
		if (ea_len && (ud_verify_tag_and_desc(&eah->eah_tag,
		    UD_EXT_ATTR_HDR, ip->i_icb_block, 1,
		    sizeof (struct file_entry) -
		    offsetof(struct file_entry, fe_spec)) == 0)) {

			while (ea_off < ea_len) {
				/*
				 * We now check the validity of ea_off.
				 * (ea_len - ea_off) should be large enough to
				 * hold the attribute header atleast.
				 */
				if ((ea_len - ea_off) <
				    sizeof (struct attr_hdr)) {
					cmn_err(CE_NOTE,
					    "ea_len(0x%x) - ea_off(0x%x) is "
					    "too small to hold attr. info. "
					    "blockno 0x%x\n",
					    ea_len, ea_off, ip->i_icb_block);
					goto error_ret;
				}
				ah = (struct attr_hdr *)&fe->fe_spec[ea_off];

				/*
				 * Device Specification EA
				 */
				if ((GET_32(&ah->ahdr_atype) == 12) &&
					(ah->ahdr_astype == 1)) {
					struct dev_spec_ear *ds;

					if ((ea_len - ea_off) <
					    sizeof (struct dev_spec_ear)) {
						cmn_err(CE_NOTE,
						    "ea_len(0x%x) - "
						    "ea_off(0x%x) is too small "
						    "to hold dev_spec_ear."
						    " blockno 0x%x\n",
						    ea_len, ea_off,
						    ip->i_icb_block);
						goto error_ret;
					}
					ds = (struct dev_spec_ear *)ah;
					ip->i_major = GET_32(&ds->ds_major_id);
					ip->i_minor = GET_32(&ds->ds_minor_id);
				}

				/*
				 * Impl Use EA
				 */
				if ((GET_32(&ah->ahdr_atype) == 2048) &&
					(ah->ahdr_astype == 1)) {
					struct iu_ea *iuea;
					struct copy_mgt_info *cmi;

					if ((ea_len - ea_off) <
					    sizeof (struct iu_ea)) {
						cmn_err(CE_NOTE,
"ea_len(0x%x) - ea_off(0x%x) is too small to hold iu_ea. blockno 0x%x\n",
						    ea_len, ea_off,
						    ip->i_icb_block);
						goto error_ret;
					}
					iuea = (struct iu_ea *)ah;
					if (strncmp(iuea->iuea_ii.reg_id,
					    UDF_FREEEASPACE,
					    sizeof (iuea->iuea_ii.reg_id))
					    == 0) {
						/* skip it */
						iuea = iuea;
					} else if (strncmp(iuea->iuea_ii.reg_id,
					    UDF_CGMS_INFO,
					    sizeof (iuea->iuea_ii.reg_id))
					    == 0) {
						cmi = (struct copy_mgt_info *)
							iuea->iuea_iu;
						cmi = cmi;
					}
				}
				/* ??? PARANOIA */
				if (GET_32(&ah->ahdr_length) == 0) {
					break;
				}
				ea_off += GET_32(&ah->ahdr_length);
			}
		}
	}

	ip->i_nextr = 0;

	ip->i_maxent = SWAP_16(fe->fe_icb_tag.itag_max_ent);
	ip->i_astrat = SWAP_16(fe->fe_icb_tag.itag_strategy);

	ip->i_desc_type = icb_tag_flags & 0x7;

	/* Strictly Paranoia */
	ip->i_ext = NULL;
	ip->i_ext_count = ip->i_ext_used = 0;
	ip->i_con = 0;
	ip->i_con_count = ip->i_con_used = ip->i_con_read = 0;

	ip->i_data_off = 0xB0 + SWAP_32(fe->fe_len_ear);
	ip->i_max_emb =  udf_vfsp->udf_lbsize - ip->i_data_off;
	if (ip->i_desc_type == ICB_FLAG_SHORT_AD) {
		/* Short allocation desc */
		struct short_ad *sad;

		ip->i_ext_used = 0;
		ip->i_ext_count = ndesc =
		    SWAP_32(fe->fe_len_adesc) / sizeof (struct short_ad);
		ip->i_ext_count =
		    ((ip->i_ext_count / EXT_PER_MALLOC) + 1) * EXT_PER_MALLOC;
		ip->i_ext = (struct icb_ext  *)kmem_zalloc(ip->i_ext_count *
		    sizeof (struct icb_ext), KM_SLEEP);
		ip->i_cur_max_ext = ip->i_max_emb / sizeof (struct short_ad);
		ip->i_cur_max_ext --;

		if ((ip->i_astrat != STRAT_TYPE4) &&
		    (ip->i_astrat != STRAT_TYPE4096)) {
			goto error_ret;
		}

		sad = (struct short_ad *)
		    (fe->fe_spec + SWAP_32(fe->fe_len_ear));
		iext = ip->i_ext;
		while (ndesc --) {
			length = SWAP_32(sad->sad_ext_len);
			if ((length & 0x3FFFFFFF) == 0) {
				break;
			}
			if (((length >> 30) & IB_MASK) == IB_CON) {
				if (ip->i_con == NULL) {
					ip->i_con_count = EXT_PER_MALLOC;
					ip->i_con_used = 0;
					ip->i_con_read = 0;
					ip->i_con = kmem_zalloc(
					    ip->i_con_count *
					    sizeof (struct icb_ext),
					    KM_SLEEP);
				}
				con = &ip->i_con[ip->i_con_used];
				con->ib_prn = 0;
				con->ib_block = SWAP_32(sad->sad_ext_loc);
				con->ib_count = length & 0x3FFFFFFF;
				con->ib_flags = (length >> 30) & IB_MASK;
				ip->i_con_used++;
				sad ++;
				break;
			}
			iext->ib_prn = 0;
			iext->ib_block = SWAP_32(sad->sad_ext_loc);
			length = SWAP_32(sad->sad_ext_len);
			iext->ib_count = length & 0x3FFFFFFF;
			iext->ib_offset = offset;
			iext->ib_marker1 = (uint32_t)0xAAAAAAAA;
			iext->ib_marker2 = (uint32_t)0xBBBBBBBB;
			offset += (iext->ib_count + udf_vfsp->udf_lbmask) &
			    (~udf_vfsp->udf_lbmask);

			iext->ib_flags = (length >> 30) & IB_MASK;

			ip->i_ext_used++;
			iext++;
			sad ++;
		}
	} else if (ip->i_desc_type == ICB_FLAG_LONG_AD) {
		/* Long allocation desc */
		struct long_ad *lad;

		ip->i_ext_used = 0;
		ip->i_ext_count = ndesc =
		    SWAP_32(fe->fe_len_adesc) / sizeof (struct long_ad);
		ip->i_ext_count =
		    ((ip->i_ext_count / EXT_PER_MALLOC) + 1) * EXT_PER_MALLOC;
		ip->i_ext = (struct icb_ext  *)kmem_zalloc(ip->i_ext_count *
		    sizeof (struct icb_ext), KM_SLEEP);

		ip->i_cur_max_ext = ip->i_max_emb / sizeof (struct long_ad);
		ip->i_cur_max_ext --;

		if ((ip->i_astrat != STRAT_TYPE4) &&
		    (ip->i_astrat != STRAT_TYPE4096)) {
			goto error_ret;
		}

		lad = (struct long_ad *)
		    (fe->fe_spec + SWAP_32(fe->fe_len_ear));
		iext = ip->i_ext;
		while (ndesc --) {
			length = SWAP_32(lad->lad_ext_len);
			if ((length & 0x3FFFFFFF) == 0) {
				break;
			}
			if (((length >> 30) & IB_MASK) == IB_CON) {
				if (ip->i_con == NULL) {
					ip->i_con_count = EXT_PER_MALLOC;
					ip->i_con_used = 0;
					ip->i_con_read = 0;
					ip->i_con = kmem_zalloc(
					    ip->i_con_count *
					    sizeof (struct icb_ext),
					    KM_SLEEP);
				}
				con = &ip->i_con[ip->i_con_used];
				con->ib_prn = SWAP_16(lad->lad_ext_prn);
				con->ib_block = SWAP_32(lad->lad_ext_loc);
				con->ib_count = length & 0x3FFFFFFF;
				con->ib_flags = (length >> 30) & IB_MASK;
				ip->i_con_used++;
				lad ++;
				break;
			}
			iext->ib_prn = SWAP_16(lad->lad_ext_prn);
			iext->ib_block = SWAP_32(lad->lad_ext_loc);
			iext->ib_count = length & 0x3FFFFFFF;
			iext->ib_offset = offset;
			iext->ib_marker1 = (uint32_t)0xAAAAAAAA;
			iext->ib_marker2 = (uint32_t)0xBBBBBBBB;
			offset += (iext->ib_count + udf_vfsp->udf_lbmask) &
			    (~udf_vfsp->udf_lbmask);

			iext->ib_flags = (length >> 30) & IB_MASK;

			ip->i_ext_used++;
			iext++;
			lad ++;
		}
	} else if (ip->i_desc_type == ICB_FLAG_ONE_AD) {
		ASSERT(SWAP_32(fe->fe_len_ear) < udf_vfsp->udf_lbsize);

		if (SWAP_32(fe->fe_len_ear) > udf_vfsp->udf_lbsize) {
			goto error_ret;
		}
	} else {
		/* Not to be used in UDF 1.50 */
		cmn_err(CE_NOTE, "Invalid Allocation Descriptor type %x\n",
		    ip->i_desc_type);
		goto error_ret;
	}


	if (icb_tag_flags & ICB_FLAG_SETUID) {
		ip->i_char = ISUID;
	} else {
		ip->i_char = 0;
	}
	if (icb_tag_flags & ICB_FLAG_SETGID) {
		ip->i_char |= ISGID;
	}
	if (icb_tag_flags & ICB_FLAG_STICKY) {
		ip->i_char |= ISVTX;
	}
	switch (fe->fe_icb_tag.itag_ftype) {
		case FTYPE_DIRECTORY :
			ip->i_type = VDIR;
			break;
		case FTYPE_FILE :
			ip->i_type = VREG;
			break;
		case FTYPE_BLOCK_DEV :
			ip->i_type = VBLK;
			break;
		case FTYPE_CHAR_DEV :
			ip->i_type = VCHR;
			break;
		case FTYPE_FIFO :
			ip->i_type = VFIFO;
			break;
		case FTYPE_C_ISSOCK :
			ip->i_type = VSOCK;
			break;
		case FTYPE_SYMLINK :
			ip->i_type = VLNK;
			break;
		default :
			ip->i_type = VNON;
			break;
	}

	if (ip->i_type == VBLK || ip->i_type == VCHR) {
		ip->i_rdev = makedevice(ip->i_major, ip->i_minor);
	}

	/*
	 * Fill in the rest.  Don't bother with the vnode lock because nobody
	 * should be looking at this vnode.  We have already invalidated the
	 * pages if it had any so pageout shouldn't be referencing this vnode
	 * and we are holding the write contents lock so a look up can't use
	 * the vnode.
	 */
	vp->v_vfsp = vfsp;
	vp->v_type = ip->i_type;
	vp->v_rdev = ip->i_rdev;
	if (ip->i_udf->udf_root_blkno == loc) {
		vp->v_flag = VROOT;
	} else {
		vp->v_flag = 0;
	}

	brelse(bp);
	*ipp = ip;
	rw_exit(&ip->i_contents);
	vn_exists(vp);
	return (0);
}

void
ud_iinactive(struct ud_inode *ip, struct cred *cr)
{
	int32_t busy = 0;
	struct vnode *vp;
	vtype_t type;
	caddr_t addr, addr1;
	size_t size, size1;


	ud_printf("ud_iinactive\n");

	/*
	 * Get exclusive access to inode data.
	 */
	rw_enter(&ip->i_contents, RW_WRITER);

	/*
	 * Make sure no one reclaimed the inode before we put
	 * it on the freelist or destroy it. We keep our 'hold'
	 * on the vnode from vn_rele until we are ready to
	 * do something with the inode (freelist/destroy).
	 *
	 * Pageout may put a VN_HOLD/VN_RELE at anytime during this
	 * operation via an async putpage, so we must make sure
	 * we don't free/destroy the inode more than once. ud_iget
	 * may also put a VN_HOLD on the inode before it grabs
	 * the i_contents lock. This is done so we don't kmem_free
	 * an inode that a thread is waiting on.
	 */
	vp = ITOV(ip);

	mutex_enter(&vp->v_lock);
	if (vp->v_count < 1) {
		cmn_err(CE_WARN, "ud_iinactive: v_count < 1\n");
		return;
	}
	if ((vp->v_count > 1) || ((ip->i_flag & IREF) == 0)) {
		vp->v_count--;		/* release our hold from vn_rele */
		mutex_exit(&vp->v_lock);
		rw_exit(&ip->i_contents);
		return;
	}
	mutex_exit(&vp->v_lock);

	/*
	 * For forced umount case: if i_udf is NULL, the contents of
	 * the inode and all the pages have already been pushed back
	 * to disk. It can be safely destroyed.
	 */
	if (ip->i_udf == NULL) {
		addr = (caddr_t)ip->i_ext;
		size = sizeof (struct icb_ext) * ip->i_ext_count;
		ip->i_ext = 0;
		ip->i_ext_count = ip->i_ext_used = 0;
		addr1 = (caddr_t)ip->i_con;
		size1 = sizeof (struct icb_ext) * ip->i_con_count;
		ip->i_con = 0;
		ip->i_con_count = ip->i_con_used = ip->i_con_read = 0;
		rw_exit(&ip->i_contents);
		vn_invalid(vp);

		mutex_enter(&ud_nino_lock);
		ud_cur_inodes--;
		mutex_exit(&ud_nino_lock);

		cv_destroy(&ip->i_wrcv);  /* throttling */
		rw_destroy(&ip->i_rwlock);
		rw_exit(&ip->i_contents);
		rw_destroy(&ip->i_contents);
		kmem_free(addr, size);
		kmem_free(addr1, size1);
		vn_free(vp);
		kmem_free(ip, sizeof (struct ud_inode));
		return;
	}

	if ((ip->i_udf->udf_flags & UDF_FL_RDONLY) == 0) {
		if (ip->i_nlink <= 0) {
			ip->i_marker3 = (uint32_t)0xDDDD0000;
			ip->i_nlink = 1;	/* prevent free-ing twice */
			(void) ud_itrunc(ip, 0, 0, cr);
			type = ip->i_type;
			ip->i_perm = 0;
			ip->i_uid = 0;
			ip->i_gid = 0;
			ip->i_rdev = 0;	/* Zero in core version of rdev */
			mutex_enter(&ip->i_tlock);
			ip->i_flag |= IUPD|ICHG;
			mutex_exit(&ip->i_tlock);
			ud_ifree(ip, type);
			ip->i_icb_prn = 0xFFFF;
		} else if (!IS_SWAPVP(vp)) {
			/*
			 * Write the inode out if dirty. Pages are
			 * written back and put on the freelist.
			 */
			(void) ud_syncip(ip, B_FREE | B_ASYNC, 0);
			/*
			 * Do nothing if inode is now busy -- inode may
			 * have gone busy because ud_syncip
			 * releases/reacquires the i_contents lock
			 */
			mutex_enter(&vp->v_lock);
			if (vp->v_count > 1) {
				vp->v_count--;
				mutex_exit(&vp->v_lock);
				rw_exit(&ip->i_contents);
				return;
			}
			mutex_exit(&vp->v_lock);
		} else {
			ud_iupdat(ip, 0);
		}
	}


	/*
	 * Put the inode on the end of the free list.
	 * Possibly in some cases it would be better to
	 * put the inode at the head of the free list,
	 * (e.g.: where i_perm == 0 || i_number == 0)
	 * but I will think about that later.
	 * (i_number is rarely 0 - only after an i/o error in ud_iget,
	 * where i_perm == 0, the inode will probably be wanted
	 * again soon for an ialloc, so possibly we should keep it)
	 */
	/*
	 * If inode is invalid or there is no page associated with
	 * this inode, put the inode in the front of the free list.
	 * Since we have a VN_HOLD on the vnode, and checked that it
	 * wasn't already on the freelist when we entered, we can safely
	 * put it on the freelist even if another thread puts a VN_HOLD
	 * on it (pageout/ud_iget).
	 */
tryagain:
	mutex_enter(&ud_nino_lock);
	if (vn_has_cached_data(vp)) {
		mutex_exit(&ud_nino_lock);
		mutex_enter(&vp->v_lock);
		vp->v_count--;
		mutex_exit(&vp->v_lock);
		mutex_enter(&ip->i_tlock);
		mutex_enter(&udf_ifree_lock);
		ud_add_to_free_list(ip, UD_END);
		mutex_exit(&udf_ifree_lock);
		ip->i_flag &= IMODTIME;
		mutex_exit(&ip->i_tlock);
		rw_exit(&ip->i_contents);
	} else if (busy || ud_cur_inodes < ud_max_inodes) {
		mutex_exit(&ud_nino_lock);
		/*
		 * We're not over our high water mark, or it's
		 * not safe to kmem_free the inode, so put it
		 * on the freelist.
		 */
		mutex_enter(&vp->v_lock);
		if (vn_has_cached_data(vp)) {
			cmn_err(CE_WARN, "ud_iinactive: v_pages not NULL\n");
		}
		vp->v_count--;
		mutex_exit(&vp->v_lock);

	mutex_enter(&ip->i_tlock);
		mutex_enter(&udf_ifree_lock);
		ud_add_to_free_list(ip, UD_BEGIN);
		mutex_exit(&udf_ifree_lock);
	ip->i_flag &= IMODTIME;
	mutex_exit(&ip->i_tlock);
		rw_exit(&ip->i_contents);
	} else {
		mutex_exit(&ud_nino_lock);
		if (vn_has_cached_data(vp)) {
			cmn_err(CE_WARN, "ud_iinactive: v_pages not NULL\n");
		}
		/*
		 * Try to free the inode. We must make sure
		 * it's o.k. to destroy this inode. We can't destroy
		 * if a thread is waiting for this inode. If we can't get the
		 * cache now, put it back on the freelist.
		 */
		if (!mutex_tryenter(&ud_icache_lock)) {
			busy = 1;
			goto tryagain;
		}
		mutex_enter(&vp->v_lock);
		if (vp->v_count > 1) {
			/* inode is wanted in ud_iget */
			busy = 1;
			mutex_exit(&vp->v_lock);
			mutex_exit(&ud_icache_lock);
			goto tryagain;
		}
		mutex_exit(&vp->v_lock);
		remque(ip);
		ip->i_forw = ip;
		ip->i_back = ip;
		mutex_enter(&ud_nino_lock);
		ud_cur_inodes--;
		mutex_exit(&ud_nino_lock);
		mutex_exit(&ud_icache_lock);
		if (ip->i_icb_prn != 0xFFFF) {
			ud_iupdat(ip, 0);
		}
		addr = (caddr_t)ip->i_ext;
		size = sizeof (struct icb_ext) * ip->i_ext_count;
		ip->i_ext = 0;
		ip->i_ext_count = ip->i_ext_used = 0;
		addr1 = (caddr_t)ip->i_con;
		size1 = sizeof (struct icb_ext) * ip->i_con_count;
		ip->i_con = 0;
		ip->i_con_count = ip->i_con_used = ip->i_con_read = 0;
		cv_destroy(&ip->i_wrcv);  /* throttling */
		rw_destroy(&ip->i_rwlock);
		rw_exit(&ip->i_contents);
		rw_destroy(&ip->i_contents);
		kmem_free(addr, size);
		kmem_free(addr1, size1);
		ip->i_marker3 = (uint32_t)0xDDDDDDDD;
		vn_free(vp);
		kmem_free(ip, sizeof (struct ud_inode));
	}
}


void
ud_iupdat(struct ud_inode *ip, int32_t waitfor)
{
	uint16_t flag, tag_flags;
	int32_t error;
	struct buf *bp;
	struct udf_vfs *udf_vfsp;
	struct file_entry *fe;
	uint16_t crc_len = 0;

	ASSERT(RW_WRITE_HELD(&ip->i_contents));

	ud_printf("ud_iupdat\n");
	/*
	 * Return if file system has been forcibly umounted.
	 */
	if (ip->i_udf == NULL) {
		return;
	}

	udf_vfsp = ip->i_udf;
	flag = ip->i_flag;	/* Atomic read */
	if ((flag & (IUPD|IACC|ICHG|IMOD|IMODACC)) != 0) {
		if (udf_vfsp->udf_flags & UDF_FL_RDONLY) {
			ip->i_flag &= ~(IUPD|IACC|ICHG|IMOD|IMODACC|IATTCHG);
			return;
		}

		bp = ud_bread(ip->i_dev,
		    ip->i_icb_lbano << udf_vfsp->udf_l2d_shift,
		    ip->i_udf->udf_lbsize);
		if (bp->b_flags & B_ERROR) {
			brelse(bp);
			return;
		}
		fe = (struct file_entry *)bp->b_un.b_addr;
		if (ud_verify_tag_and_desc(&fe->fe_tag, UD_FILE_ENTRY,
		    ip->i_icb_block,
		    1, ip->i_udf->udf_lbsize) != 0) {
			brelse(bp);
			return;
		}

		mutex_enter(&ip->i_tlock);
		if (ip->i_flag & (IUPD|IACC|ICHG)) {
			IMARK(ip);
		}
		ip->i_flag &= ~(IUPD|IACC|ICHG|IMOD|IMODACC);
		mutex_exit(&ip->i_tlock);

		fe->fe_uid = SWAP_32(ip->i_uid);
		fe->fe_gid = SWAP_32(ip->i_gid);

		fe->fe_perms = SWAP_32(ip->i_perm);

		fe->fe_lcount = SWAP_16(ip->i_nlink);
		fe->fe_info_len = SWAP_64(ip->i_size);
		fe->fe_lbr = SWAP_64(ip->i_lbr);

		ud_utime2dtime(&ip->i_atime, &fe->fe_acc_time);
		ud_utime2dtime(&ip->i_mtime, &fe->fe_mod_time);
		ud_utime2dtime(&ip->i_ctime, &fe->fe_attr_time);

		if (ip->i_char & ISUID) {
			tag_flags = ICB_FLAG_SETUID;
		} else {
			tag_flags = 0;
		}
		if (ip->i_char & ISGID) {
			tag_flags |= ICB_FLAG_SETGID;
		}
		if (ip->i_char & ISVTX) {
			tag_flags |= ICB_FLAG_STICKY;
		}
		tag_flags |= ip->i_desc_type;

		/*
		 * Remove the following it is no longer contig
		 * if (ip->i_astrat  == STRAT_TYPE4) {
		 *	tag_flags |= ICB_FLAG_CONTIG;
		 * }
		 */

		fe->fe_icb_tag.itag_flags &= ~SWAP_16((uint16_t)0x3C3);
		fe->fe_icb_tag.itag_strategy = SWAP_16(ip->i_astrat);
		fe->fe_icb_tag.itag_flags |= SWAP_16(tag_flags);

		ud_update_regid(&fe->fe_impl_id);

		crc_len = offsetof(struct file_entry, fe_spec) +
		    SWAP_32(fe->fe_len_ear);
		if (ip->i_desc_type == ICB_FLAG_ONE_AD) {
			crc_len += ip->i_size;
			fe->fe_len_adesc = SWAP_32(((uint32_t)ip->i_size));
		} else if ((ip->i_size != 0) && (ip->i_ext != NULL) &&
		    (ip->i_ext_used != 0)) {

			if ((error = ud_read_icb_till_off(ip,
			    ip->i_size)) == 0) {
				if (ip->i_astrat == STRAT_TYPE4) {
					error = ud_updat_ext4(ip, fe);
				} else if (ip->i_astrat == STRAT_TYPE4096) {
					error = ud_updat_ext4096(ip, fe);
				}
				if (error) {
					udf_vfsp->udf_mark_bad = 1;
				}
			}
			crc_len += SWAP_32(fe->fe_len_adesc);
		} else {
			fe->fe_len_adesc = 0;
		}

		/*
		 * Zero out the rest of the block
		 */
		bzero(bp->b_un.b_addr + crc_len,
		    ip->i_udf->udf_lbsize - crc_len);

		ud_make_tag(ip->i_udf, &fe->fe_tag,
		    UD_FILE_ENTRY, ip->i_icb_block, crc_len);


		if (waitfor) {
			BWRITE(bp);

			/*
			 * Synchronous write has guaranteed that inode
			 * has been written on disk so clear the flag
			 */
			ip->i_flag &= ~(IBDWRITE);
		} else {
			bdwrite(bp);

			/*
			 * This write hasn't guaranteed that inode has been
			 * written on the disk.
			 * Since, all updat flags on indoe are cleared, we must
			 * remember the condition in case inode is to be updated
			 * synchronously later (e.g.- fsync()/fdatasync())
			 * and inode has not been modified yet.
			 */
			ip->i_flag |= (IBDWRITE);
		}
	} else {
		/*
		 * In case previous inode update was done asynchronously
		 * (IBDWRITE) and this inode update request wants guaranteed
		 * (synchronous) disk update, flush the inode.
		 */
		if (waitfor && (flag & IBDWRITE)) {
			blkflush(ip->i_dev,
			    (daddr_t)fsbtodb(udf_vfsp, ip->i_icb_lbano));
			ip->i_flag &= ~(IBDWRITE);
		}
	}
}

int32_t
ud_updat_ext4(struct ud_inode *ip, struct file_entry *fe)
{
	uint32_t dummy;
	int32_t elen, ndent, index, count, con_index;
	daddr_t bno;
	struct buf *bp;
	struct short_ad *sad;
	struct long_ad *lad;
	struct icb_ext *iext, *icon;


	ASSERT(ip);
	ASSERT(fe);
	ASSERT((ip->i_desc_type == ICB_FLAG_SHORT_AD) ||
	    (ip->i_desc_type == ICB_FLAG_LONG_AD));

	if (ip->i_desc_type == ICB_FLAG_SHORT_AD) {
		elen = sizeof (struct short_ad);
		sad = (struct short_ad *)
		    (fe->fe_spec + SWAP_32(fe->fe_len_ear));
	} else if (ip->i_desc_type == ICB_FLAG_LONG_AD) {
		elen = sizeof (struct long_ad);
		lad = (struct long_ad *)
		    (fe->fe_spec + SWAP_32(fe->fe_len_ear));
	} else {
		/* This cannot happen return */
		return (EINVAL);
	}

	ndent = ip->i_max_emb / elen;

	if (ip->i_ext_used < ndent) {

		if (ip->i_desc_type == ICB_FLAG_SHORT_AD) {
			ud_make_sad(ip->i_ext, sad, ip->i_ext_used);
		} else {
			ud_make_lad(ip->i_ext, lad, ip->i_ext_used);
		}
		fe->fe_len_adesc = SWAP_32(ip->i_ext_used * elen);
		con_index = 0;
	} else {

		con_index = index = 0;

		while (index < ip->i_ext_used) {
			if (index == 0) {
				/*
				 * bp is already read
				 * First few extents will go
				 * into the file_entry
				 */
				count = ndent - 1;
				fe->fe_len_adesc = SWAP_32(ndent * elen);
				bp = NULL;

				/*
				 * Last entry to be cont ext
				 */
				icon = &ip->i_con[con_index];
			} else {
				/*
				 * Read the buffer
				 */
				icon = &ip->i_con[con_index];

				bno = ud_xlate_to_daddr(ip->i_udf,
				    icon->ib_prn, icon->ib_block,
				    icon->ib_count >> ip->i_udf->udf_l2d_shift,
				    &dummy);
				bp = ud_bread(ip->i_dev,
				    bno << ip->i_udf->udf_l2d_shift,
				    ip->i_udf->udf_lbsize);
				if (bp->b_flags & B_ERROR) {
					brelse(bp);
					return (EIO);
				}

				/*
				 * Figure out how many extents in
				 * this time
				 */
				count = (bp->b_bcount -
				    sizeof (struct alloc_ext_desc)) / elen;
				if (count > (ip->i_ext_used - index)) {
					count = ip->i_ext_used - index;
				} else {
					count --;
				}
				con_index++;
				if (con_index >= ip->i_con_used) {
					icon = NULL;
				} else {
					icon = &ip->i_con[con_index];
				}
			}



			/*
			 * convert to on disk form and
			 * update
			 */
			iext = &ip->i_ext[index];
			if (ip->i_desc_type == ICB_FLAG_SHORT_AD) {
				if (index != 0) {
					sad = (struct short_ad *)
					    (bp->b_un.b_addr +
					    sizeof (struct alloc_ext_desc));
				}
				ud_make_sad(iext, sad, count);
				sad += count;
				if (icon != NULL) {
					ud_make_sad(icon, sad, 1);
				}
			} else {
				if (index != 0) {
					lad = (struct long_ad *)
					    (bp->b_un.b_addr +
					    sizeof (struct alloc_ext_desc));
				}
				ud_make_lad(iext, lad, count);
				lad += count;
				if (icon != NULL) {
					ud_make_lad(icon, lad, 1);
				}
			}

			if (con_index != 0) {
				struct alloc_ext_desc *aed;
				int32_t sz;
				struct icb_ext *oicon;

				oicon = &ip->i_con[con_index - 1];
				sz = count * elen;
				if (icon != NULL) {
					sz += elen;
				}
				aed = (struct alloc_ext_desc *)bp->b_un.b_addr;
				aed->aed_len_aed = SWAP_32(sz);
				if (con_index == 1) {
					aed->aed_rev_ael =
					    SWAP_32(ip->i_icb_block);
				} else {
					aed->aed_rev_ael =
					    SWAP_32(oicon->ib_block);
				}
				sz += sizeof (struct alloc_ext_desc);
				ud_make_tag(ip->i_udf, &aed->aed_tag,
				    UD_ALLOC_EXT_DESC, oicon->ib_block, sz);
			}

			/*
			 * Write back to disk
			 */
			if (bp != NULL) {
				BWRITE(bp);
			}
			index += count;
		}

	}

	if (con_index != ip->i_con_used) {
		int32_t lbmask, l2b, temp;

		temp = con_index;
		lbmask = ip->i_udf->udf_lbmask;
		l2b = ip->i_udf->udf_l2b_shift;
		/*
		 * Free unused continuation extents
		 */
		for (; con_index < ip->i_con_used; con_index++) {
			icon = &ip->i_con[con_index];
			count = (icon->ib_count + lbmask) >> l2b;
			ud_free_space(ip->i_udf->udf_vfs, icon->ib_prn,
			    icon->ib_block, count);
			count = (count << l2b) - sizeof (struct alloc_ext_desc);
			ip->i_cur_max_ext -= (count / elen) - 1;
		}
		ip->i_con_used = temp;
	}
	return (0);
}

/* ARGSUSED */
int32_t
ud_updat_ext4096(struct ud_inode *ip, struct file_entry *fe)
{
	return (ENXIO);
}

void
ud_make_sad(struct icb_ext *iext, struct short_ad *sad, int32_t count)
{
	int32_t index = 0, scount;

	ASSERT(iext);
	ASSERT(sad);

	if (count != 0) {
		ASSERT(count > 0);
		while (index < count) {
			scount = (iext->ib_count & 0x3FFFFFFF) |
			    (iext->ib_flags << 30);
			sad->sad_ext_len = SWAP_32(scount);
			sad->sad_ext_loc = SWAP_32(iext->ib_block);
			sad++;
			iext++;
			index++;
		}
	}
}

void
ud_make_lad(struct icb_ext *iext, struct long_ad *lad, int32_t count)
{
	int32_t index = 0, scount;

	ASSERT(iext);
	ASSERT(lad);

	if (count != 0) {
		ASSERT(count > 0);

		while (index < count) {
			lad->lad_ext_prn = SWAP_16(iext->ib_prn);
			scount = (iext->ib_count & 0x3FFFFFFF) |
			    (iext->ib_flags << 30);
			lad->lad_ext_len = SWAP_32(scount);
			lad->lad_ext_loc = SWAP_32(iext->ib_block);
			lad++;
			iext++;
			index++;
		}
	}
}

/*
 * Truncate the inode ip to at most length size.
 * Free affected disk blocks -- the blocks of the
 * file are removed in reverse order.
 */
/* ARGSUSED */
int
ud_itrunc(struct ud_inode *oip, u_offset_t length,
    int32_t flags, struct cred *cr)
{
	int32_t error, boff;
	off_t bsize;
	mode_t mode;
	struct udf_vfs *udf_vfsp;

	ud_printf("ud_itrunc\n");

	ASSERT(RW_WRITE_HELD(&oip->i_contents));
	udf_vfsp = oip->i_udf;
	bsize = udf_vfsp->udf_lbsize;

	/*
	 * We only allow truncation of regular files and directories
	 * to arbritary lengths here.  In addition, we allow symbolic
	 * links to be truncated only to zero length.  Other inode
	 * types cannot have their length set here.
	 */
	mode = oip->i_type;
	if (mode == VFIFO) {
		return (0);
	}
	if ((mode != VREG) && (mode != VDIR) &&
	    (!(mode == VLNK && length == 0))) {
		return (EINVAL);
	}
	if (length == oip->i_size) {
		/* update ctime and mtime to please POSIX tests */
		mutex_enter(&oip->i_tlock);
		oip->i_flag |= ICHG |IUPD;
		mutex_exit(&oip->i_tlock);
		return (0);
	}

	boff = blkoff(udf_vfsp, length);

	if (length > oip->i_size) {
		/*
		 * Trunc up case.ud_bmap_write will insure that the right blocks
		 * are allocated.  This includes doing any work needed for
		 * allocating the last block.
		 */
		if (boff == 0) {
			error = ud_bmap_write(oip, length - 1,
			    (int)bsize, 0, cr);
		} else {
			error = ud_bmap_write(oip, length - 1, boff, 0, cr);
		}
		if (error == 0) {
			u_offset_t osize = oip->i_size;
			oip->i_size  = length;

			/*
			 * Make sure we zero out the remaining bytes of
			 * the page in case a mmap scribbled on it. We
			 * can't prevent a mmap from writing beyond EOF
			 * on the last page of a file.
			 */
			if ((boff = blkoff(udf_vfsp, osize)) != 0) {
				pvn_vpzero(ITOV(oip), osize,
				    (uint32_t)(bsize - boff));
			}
			mutex_enter(&oip->i_tlock);
			oip->i_flag |= ICHG;
			ITIMES_NOLOCK(oip);
			mutex_exit(&oip->i_tlock);
		}
		return (error);
	}

	/*
	 * Update the pages of the file.  If the file is not being
	 * truncated to a block boundary, the contents of the
	 * pages following the end of the file must be zero'ed
	 * in case it ever become accessable again because
	 * of subsequent file growth.
	 */
	if (boff == 0) {
		(void) pvn_vplist_dirty(ITOV(oip), length,
		    ud_putapage, B_INVAL | B_TRUNC, CRED());
	} else {
		/*
		 * Make sure that the last block is properly allocated.
		 * We only really have to do this if the last block is
		 * actually allocated.  Just to be sure, we do it now
		 * independent of current allocation.
		 */
		error = ud_bmap_write(oip, length - 1, boff, 0, cr);
		if (error) {
			return (error);
		}

		pvn_vpzero(ITOV(oip), length, (uint32_t)(bsize - boff));

		(void) pvn_vplist_dirty(ITOV(oip), length,
		    ud_putapage, B_INVAL | B_TRUNC, CRED());
	}


	/* Free the blocks */
	if (oip->i_desc_type == ICB_FLAG_ONE_AD) {
		if (length > oip->i_max_emb) {
			return (EFBIG);
		}
		oip->i_size = length;
		mutex_enter(&oip->i_tlock);
		oip->i_flag |= ICHG|IUPD;
		mutex_exit(&oip->i_tlock);
		ud_iupdat(oip, 1);
	} else {
		if ((error = ud_read_icb_till_off(oip, oip->i_size)) != 0) {
			return (error);
		}

		if (oip->i_astrat == STRAT_TYPE4) {
			ud_trunc_ext4(oip, length);
		} else if (oip->i_astrat == STRAT_TYPE4096) {
			ud_trunc_ext4096(oip, length);
		}
	}

done:
	return (0);
}

void
ud_trunc_ext4(struct ud_inode *ip, u_offset_t length)
{
	int32_t index, l2b, count, ecount;
	int32_t elen, ndent, nient;
	u_offset_t ext_beg, ext_end;
	struct icb_ext *iext, *icon;
	int32_t lbmask, ext_used;
	uint32_t loc;
	struct icb_ext text;
	uint32_t con_freed;

	ASSERT((ip->i_desc_type == ICB_FLAG_SHORT_AD) ||
	    (ip->i_desc_type == ICB_FLAG_LONG_AD));

	if (ip->i_ext_used == 0) {
		return;
	}

	ext_used = ip->i_ext_used;

	lbmask = ip->i_udf->udf_lbmask;
	l2b = ip->i_udf->udf_l2b_shift;

	ASSERT(ip->i_ext);

	ip->i_lbr = 0;
	for (index = 0; index < ext_used; index++) {
		iext = &ip->i_ext[index];

		/*
		 * Find the begining and end
		 * of current extent
		 */
		ext_beg = iext->ib_offset;
		ext_end = iext->ib_offset +
		    ((iext->ib_count + lbmask) & ~lbmask);

		/*
		 * This is the extent that has offset "length"
		 * make a copy of this extent and
		 * remember the index. We can use
		 * it to free blocks
		 */
		if ((length <= ext_end) && (length >= ext_beg)) {
			text = *iext;

			iext->ib_count = length - ext_beg;
			ip->i_ext_used = index + 1;
			break;
		}
		if (iext->ib_flags != IB_UN_RE_AL) {
			ip->i_lbr += iext->ib_count >> l2b;
		}
	}
	if (ip->i_ext_used != index) {
		if (iext->ib_flags != IB_UN_RE_AL) {
			ip->i_lbr +=
			    ((iext->ib_count + lbmask) & ~lbmask) >> l2b;
		}
	}

	ip->i_size = length;
	mutex_enter(&ip->i_tlock);
	ip->i_flag |= ICHG|IUPD;
	mutex_exit(&ip->i_tlock);
	ud_iupdat(ip, 1);

	/*
	 * Free the unused space
	 */
	if (text.ib_flags != IB_UN_RE_AL) {
		count = (ext_end - length) >> l2b;
		if (count) {
			loc = text.ib_block +
			    (((length - text.ib_offset) + lbmask) >> l2b);
			ud_free_space(ip->i_udf->udf_vfs, text.ib_prn,
			    loc, count);
		}
	}
	for (index = ip->i_ext_used; index < ext_used; index++) {
		iext = &ip->i_ext[index];
		if (iext->ib_flags != IB_UN_RE_AL) {
			count = (iext->ib_count + lbmask) >> l2b;
			ud_free_space(ip->i_udf->udf_vfs, iext->ib_prn,
			    iext->ib_block, count);
		}
		bzero(iext, sizeof (struct icb_ext));
		continue;
	}

	/*
	 * release any continuation blocks
	 */
	if (ip->i_con) {

		ASSERT(ip->i_con_count >= ip->i_con_used);

		/*
		 * Find out how many indirect blocks
		 * are required and release the rest
		 */
		if (ip->i_desc_type == ICB_FLAG_SHORT_AD) {
			elen = sizeof (struct short_ad);
		} else if (ip->i_desc_type == ICB_FLAG_LONG_AD) {
			elen = sizeof (struct long_ad);
		}
		ndent = ip->i_max_emb / elen;
		if (ip->i_ext_used > ndent) {
			ecount = ip->i_ext_used - ndent;
		} else {
			ecount = 0;
		}
		con_freed = 0;
		for (index = 0; index < ip->i_con_used; index++) {
			icon = &ip->i_con[index];
			nient = icon->ib_count -
			    (sizeof (struct alloc_ext_desc) + elen);
			/* Header + 1 indirect extent */
			nient /= elen;
			if (ecount) {
				if (ecount > nient) {
					ecount -= nient;
				} else {
					ecount = 0;
				}
			} else {
				count = ((icon->ib_count + lbmask) &
				    ~lbmask) >> l2b;
				ud_free_space(ip->i_udf->udf_vfs,
				    icon->ib_prn, icon->ib_block, count);
				con_freed++;
				ip->i_cur_max_ext -= nient;
			}
		}
		/*
		 * set the continuation extents used(i_con_used)i to correct
		 * value. It is possible for i_con_used to be zero,
		 * if we free up all continuation extents. This happens
		 * when ecount is 0 before entering the for loop above.
		 */
		ip->i_con_used -= con_freed;
		if (ip->i_con_read > ip->i_con_used) {
			ip->i_con_read = ip->i_con_used;
		}
	}
}

void
ud_trunc_ext4096(struct ud_inode *ip, u_offset_t length)
{
	/*
	 * Truncate code is the same for
	 * both file of type 4 and 4096
	 */
	ud_trunc_ext4(ip, length);
}

/*
 * Remove any inodes in the inode cache belonging to dev
 *
 * There should not be any active ones, return error if any are found but
 * still invalidate others (N.B.: this is a user error, not a system error).
 *
 * Also, count the references to dev by block devices - this really
 * has nothing to do with the object of the procedure, but as we have
 * to scan the inode table here anyway, we might as well get the
 * extra benefit.
 */
int32_t
ud_iflush(struct vfs *vfsp)
{
	int32_t index, busy = 0;
	union ihead *ih;
	struct udf_vfs *udf_vfsp;
	dev_t dev;
	struct vnode *rvp, *vp;
	struct ud_inode *ip, *next;

	ud_printf("ud_iflush\n");
	udf_vfsp = (struct udf_vfs *)vfsp->vfs_data;
	rvp = udf_vfsp->udf_root;
	dev = vfsp->vfs_dev;

	mutex_enter(&ud_icache_lock);
	for (index = 0; index < UD_HASH_SZ; index++) {
		ih = &ud_ihead[index];

		next = ih->ih_chain[0];
		while (next != (struct ud_inode *)ih) {
			ip = next;
			next = ip->i_forw;
			if (ip->i_dev != dev) {
				continue;
			}
			vp = ITOV(ip);
			/*
			 * root inode is processed by the caller
			 */
			if (vp == rvp) {
				if (vp->v_count > 1) {
					busy = -1;
				}
				continue;
			}
			if (ip->i_flag & IREF) {
				/*
				 * Set error indicator for return value,
				 * but continue invalidating other
				 * inodes.
				 */
				busy = -1;
				continue;
			}

			rw_enter(&ip->i_contents, RW_WRITER);
			remque(ip);
			ip->i_forw = ip;
			ip->i_back = ip;
			/*
			 * Hold the vnode since its not done
			 * in VOP_PUTPAGE anymore.
			 */
			VN_HOLD(vp);
			/*
			 * XXX Synchronous write holding
			 * cache lock
			 */
			(void) ud_syncip(ip, B_INVAL, I_SYNC);
			rw_exit(&ip->i_contents);
			VN_RELE(vp);
		}
	}
	mutex_exit(&ud_icache_lock);

	return (busy);
}


/*
 * Check mode permission on inode.  Mode is READ, WRITE or EXEC.
 * In the case of WRITE, the read-only status of the file system
 * is checked.  The applicable mode bits are compared with the
 * requested form of access.  If bits are missing, the secpolicy
 * function will check for privileges.
 */
int
ud_iaccess(struct ud_inode *ip, int32_t mode, struct cred *cr, int dolock)
{
	int shift = 0;
	int ret = 0;

	if (dolock)
		rw_enter(&ip->i_contents, RW_READER);
	ASSERT(RW_LOCK_HELD(&ip->i_contents));

	ud_printf("ud_iaccess\n");
	if (mode & IWRITE) {
		/*
		 * Disallow write attempts on read-only
		 * file systems, unless the file is a block
		 * or character device or a FIFO.
		 */
		if (ip->i_udf->udf_flags & UDF_FL_RDONLY) {
			if ((ip->i_type != VCHR) &&
			    (ip->i_type != VBLK) &&
			    (ip->i_type != VFIFO)) {
				ret = EROFS;
				goto out;
			}
		}
	}

	/*
	 * Access check is based on only
	 * one of owner, group, public.
	 * If not owner, then check group.
	 * If not a member of the group, then
	 * check public access.
	 */
	if (crgetuid(cr) != ip->i_uid) {
		shift += 5;
		if (!groupmember((uid_t)ip->i_gid, cr))
			shift += 5;
	}

	ret = secpolicy_vnode_access2(cr, ITOV(ip), ip->i_uid,
	    UD2VA_PERM(ip->i_perm << shift), UD2VA_PERM(mode));

out:
	if (dolock)
		rw_exit(&ip->i_contents);
	return (ret);
}

void
ud_imark(struct ud_inode *ip)
{
	timestruc_t	now;

	gethrestime(&now);
	ud_printf("ud_imark\n");
	if (ip->i_flag & IACC) {
		ip->i_atime.tv_sec = now.tv_sec;
		ip->i_atime.tv_nsec = now.tv_nsec;
	}
	if (ip->i_flag & IUPD) {
		ip->i_mtime.tv_sec = now.tv_sec;
		ip->i_mtime.tv_nsec = now.tv_nsec;
		ip->i_flag |= IMODTIME;
	}
	if (ip->i_flag & ICHG) {
		ip->i_diroff = 0;
		ip->i_ctime.tv_sec = now.tv_sec;
		ip->i_ctime.tv_nsec = now.tv_nsec;
	}
}


void
ud_itimes_nolock(struct ud_inode *ip)
{
	ud_printf("ud_itimes_nolock\n");

	if (ip->i_flag & (IUPD|IACC|ICHG)) {
		if (ip->i_flag & ICHG) {
			ip->i_flag |= IMOD;
		} else {
			ip->i_flag |= IMODACC;
		}
		ud_imark(ip);
		ip->i_flag &= ~(IACC|IUPD|ICHG);
	}
}

void
ud_delcache(struct ud_inode *ip)
{
	ud_printf("ud_delcache\n");

	mutex_enter(&ud_icache_lock);
	remque(ip);
	ip->i_forw = ip;
	ip->i_back = ip;
	mutex_exit(&ud_icache_lock);
}

void
ud_idrop(struct ud_inode *ip)
{
	struct vnode *vp = ITOV(ip);

	ASSERT(RW_WRITE_HELD(&ip->i_contents));

	ud_printf("ud_idrop\n");

	mutex_enter(&vp->v_lock);
	if (vp->v_count > 1) {
		vp->v_count--;
		mutex_exit(&vp->v_lock);
		return;
	}
	vp->v_count = 0;
	mutex_exit(&vp->v_lock);


	/*
	 *  if inode is invalid or there is no page associated with
	 *  this inode, put the inode in the front of the free list
	 */
	mutex_enter(&ip->i_tlock);
	mutex_enter(&udf_ifree_lock);
	if (!vn_has_cached_data(vp) || ip->i_perm == 0) {
		ud_add_to_free_list(ip, UD_BEGIN);
	} else {
		/*
		 * Otherwise, put the inode back on the end of the free list.
		 */
		ud_add_to_free_list(ip, UD_END);
	}
	mutex_exit(&udf_ifree_lock);
	ip->i_flag &= IMODTIME;
	mutex_exit(&ip->i_tlock);
}

void
ud_add_to_free_list(struct ud_inode *ip, uint32_t at)
{
	ASSERT(ip);
	ASSERT(mutex_owned(&udf_ifree_lock));

#ifdef	DEBUG
	/* Search if the element is already in the list */
	if (udf_ifreeh != NULL) {
		struct ud_inode *iq;

		iq = udf_ifreeh;
		while (iq) {
			if (iq == ip) {
				cmn_err(CE_WARN, "Duplicate %p\n", (void *)ip);
			}
			iq = iq->i_freef;
		}
	}
#endif

	ip->i_freef = NULL;
	ip->i_freeb = NULL;
	if (udf_ifreeh == NULL) {
		/*
		 * Nothing on the list just add it
		 */
		udf_ifreeh = ip;
		udf_ifreet = ip;
	} else {
		if (at == UD_BEGIN) {
			/*
			 * Add at the begining of the list
			 */
			ip->i_freef = udf_ifreeh;
			udf_ifreeh->i_freeb = ip;
			udf_ifreeh = ip;
		} else {
			/*
			 * Add at the end of the list
			 */
			ip->i_freeb = udf_ifreet;
			udf_ifreet->i_freef = ip;
			udf_ifreet = ip;
		}
	}
}

void
ud_remove_from_free_list(struct ud_inode *ip, uint32_t at)
{
	ASSERT(ip);
	ASSERT(mutex_owned(&udf_ifree_lock));

#ifdef	DEBUG
	{
		struct ud_inode *iq;
		uint32_t found = 0;

		iq = udf_ifreeh;
		while (iq) {
			if (iq == ip) {
				found++;
			}
			iq = iq->i_freef;
		}
		if (found != 1) {
			cmn_err(CE_WARN, "ip %p is found %x times\n",
			    (void *)ip,  found);
		}
	}
#endif

	if ((ip->i_freef == NULL) && (ip->i_freeb == NULL)) {
		if (ip != udf_ifreeh) {
			return;
		}
	}

	if ((at == UD_BEGIN) || (ip == udf_ifreeh)) {
		udf_ifreeh = ip->i_freef;
		if (ip->i_freef == NULL) {
			udf_ifreet = NULL;
		} else {
			udf_ifreeh->i_freeb = NULL;
		}
	} else {
		ip->i_freeb->i_freef = ip->i_freef;
		if (ip->i_freef) {
			ip->i_freef->i_freeb = ip->i_freeb;
		} else {
			udf_ifreet = ip->i_freeb;
		}
	}
	ip->i_freef = NULL;
	ip->i_freeb = NULL;
}

void
ud_init_inodes(void)
{
	union ihead *ih = ud_ihead;
	int index;

#ifndef	__lint
	_NOTE(NO_COMPETING_THREADS_NOW);
#endif
	for (index = 0; index < UD_HASH_SZ; index++, ih++) {
		ih->ih_head[0] = ih;
		ih->ih_head[1] = ih;
	}
	mutex_init(&ud_icache_lock, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&ud_nino_lock, NULL, MUTEX_DEFAULT, NULL);

	udf_ifreeh = NULL;
	udf_ifreet = NULL;
	mutex_init(&udf_ifree_lock, NULL, MUTEX_DEFAULT, NULL);

	mutex_init(&ud_sync_busy, NULL, MUTEX_DEFAULT, NULL);
	udf_vfs_instances = NULL;
	mutex_init(&udf_vfs_mutex, NULL, MUTEX_DEFAULT, NULL);

#ifndef	__lint
	_NOTE(COMPETING_THREADS_NOW);
#endif
}
