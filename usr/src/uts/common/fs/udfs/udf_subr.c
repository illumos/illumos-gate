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

int32_t ud_trace;

/*
 * HASH chains and mutex
 */
extern union ihead ud_ihead[UD_HASH_SZ];
extern kmutex_t ud_icache_lock;


extern kmutex_t ud_sync_busy;
/*
 * udf_vfs list manipulation routines
 */
extern kmutex_t udf_vfs_mutex;
extern struct udf_vfs *udf_vfs_instances;

/*
 * Used to verify that a given entry on the udf_instances list (see below)
 * still refers to a mounted file system.
 *
 * XXX: This is a crock that substitutes for proper locking to coordinate
 *      updates to and uses of the entries in udf_instances.
 */
struct check_node {
	struct vfs	*vfsp;
	struct udf_vfs	*udf_vfs;
	dev_t		vfs_dev;
};

vfs_t *ud_still_mounted(struct check_node *);
void ud_checkclean(struct vfs *,
		struct udf_vfs *, dev_t, time_t);
int32_t ud_icheck(struct udf_vfs *);
void ud_flushi(int32_t);

/*
 * Link udf_vfsp in at the head of the list of udf_vfs_instances.
 */
void
ud_vfs_add(struct udf_vfs *udf_vfsp)
{
	mutex_enter(&udf_vfs_mutex);
	udf_vfsp->udf_next = udf_vfs_instances;
	udf_vfs_instances = udf_vfsp;
	mutex_exit(&udf_vfs_mutex);
}

/*
 * Remove udf_vfsp from the list of udf_vfs_instances.
 *
 * Does no error checking; udf_vfsp is assumed to actually be on the list.
 */
void
ud_vfs_remove(struct udf_vfs *udf_vfsp)
{
	struct udf_vfs **delpt = &udf_vfs_instances;

	mutex_enter(&udf_vfs_mutex);
	for (; *delpt != NULL; delpt = &((*delpt)->udf_next)) {
		if (*delpt == udf_vfsp) {
			*delpt = udf_vfsp->udf_next;
			udf_vfsp->udf_next = NULL;
			break;
		}
	}
	mutex_exit(&udf_vfs_mutex);
}

/*
 * Search for the prn in the array
 * of partitions and translate
 * to the disk block number
 */
daddr_t
ud_xlate_to_daddr(struct udf_vfs *udf_vfsp,
	uint16_t prn, uint32_t blkno, int32_t nblks, uint32_t *count)
{
	int32_t i;
	struct ud_map *map;
	struct ud_part *ud_parts;
	uint32_t lblkno, retblkno = 0, *addr;
	uint32_t begin_req, end_req;
	uint32_t begin_bad, end_bad;

	ud_printf("ud_xlate_to_daddr\n");

	/* Is prn valid */
	if (prn < udf_vfsp->udf_nmaps) {
		map = &(udf_vfsp->udf_maps[prn]);

		if (map->udm_flags == UDM_MAP_VPM) {
			/*
			 * Map is Virtual Parition Map
			 * first check for the appropriate
			 * table and then return the converted
			 * block number
			 */
			for (i = 0; i < map->udm_nent; i++) {
				if (blkno < map->udm_count[i]) {
					addr = map->udm_addr[i];
					lblkno = SWAP_32(addr[blkno]);
					*count = 1;
					break;
				} else {
					blkno -= map->udm_count[i];
				}
			}
		} else if (map->udm_flags == UDM_MAP_SPM) {
			struct stbl *stbl;
			struct stbl_entry *te;
			int32_t entry_count;

			/*
			 * Map type is Sparable Parition Map
			 * if the block is in the map
			 * return the translated block
			 * other wise use the regular
			 * partition stuff
			 */
			begin_req = blkno;
			end_req = begin_req + nblks;

			stbl = (struct stbl *)map->udm_spaddr[0];
			te = (struct stbl_entry *)&stbl->stbl_entry;
			entry_count = SWAP_16(stbl->stbl_len);

			for (i = 0; i < entry_count; i++, te++) {
				begin_bad = SWAP_32(te->sent_ol);
				end_bad = begin_bad + map->udm_plen;

				/*
				 * Either unmapped or reserved
				 * or defective. need not consider
				 */
				if (begin_bad >= (uint32_t)0xFFFFFFF0) {
					continue;
				}
				if ((end_req < begin_bad) ||
				    (begin_req >= end_bad)) {
					continue;
				}

				if (begin_req < begin_bad) {
					ASSERT(end_req >= begin_bad);
					end_req = begin_bad;
				} else {
					retblkno = SWAP_32(te->sent_ml) +
					    begin_req - begin_bad;
					if (end_req < end_bad) {
						*count = end_req - begin_req;
					} else {
						*count = end_bad - begin_req;
					}
					goto end;
				}
			}

			lblkno = blkno;
			*count = end_req - begin_req;
		} else {
			/*
			 * regular partition
			 */
			lblkno = blkno;
			*count = nblks;
		}
		ud_parts = udf_vfsp->udf_parts;
		for (i = 0; i < udf_vfsp->udf_npart; i++) {
			if (map->udm_pn == ud_parts->udp_number) {
				/*
				 * Check if the block is inside
				 * the partition or not
				 */
				if (lblkno >= ud_parts->udp_length) {
					retblkno = 0;
				} else {
					retblkno = ud_parts->udp_start + lblkno;
				}
				goto end;
			}
			ud_parts ++;
		}
	}

end:
	return (retblkno);
}

#ifdef	UNDEF
uint32_t
ud_xlate_to_addr(struct udf_vfs *udf_vfsp,
	uint16_t prn, daddr_t blkno, int32_t lad)
{
	int32_t i;
	struct ud_part *ud_parts;

	ud_printf("ud_xlate_to_addr\n");

	if (lad == 0) {
		return (blkno);
	}
	ud_parts = udf_vfsp->udf_parts;
	for (i = 0; i < udf_vfsp->udf_npart; i++) {
		if (prn == ud_parts->udp_number) {
			return (blkno - ud_parts->udp_start);
		}
	}
	return (0);
}
#endif

/*
 * Directories do not have holes
 */
int32_t
ud_ip_off2bno(struct ud_inode *ip, uint32_t offset, uint32_t *bno)
{
	int32_t i, error;
	struct icb_ext *iext;

	ASSERT(ip->i_type == VDIR);

	if (ip->i_desc_type == ICB_FLAG_ONE_AD) {
		*bno = ip->i_icb_block;
		return (0);
	}

	if ((error = ud_read_icb_till_off(ip, (u_offset_t)offset)) != 0) {
		return (error);
	}

	for (i = 0; i < ip->i_ext_used; i++) {
		iext = &ip->i_ext[i];
		if ((iext->ib_offset <= offset) &&
		    (offset < (iext->ib_offset + iext->ib_count))) {
			*bno = iext->ib_block +
			    ((offset - iext->ib_offset) >>
			    ip->i_udf->udf_l2b_shift);
			break;
		}
	}
	return (0);
}

static uint32_t cum_sec[] = {
	0x0, 0x28de80, 0x4dc880, 0x76a700, 0x9e3400, 0xc71280,
	0xee9f80, 0x1177e00, 0x1405c80, 0x167e980, 0x190c800, 0x1b85500
};
static uint32_t cum_sec_leap[] = {
	0x0, 0x28de80, 0x4f1a00, 0x77f880, 0x9f8580, 0xc86400,
	0xeff100, 0x118cf80, 0x141ae00, 0x1693b00, 0x1921980, 0x1b9a680
};

#define	DAYS_PER_YEAR	365

#define	SEC_PER_DAY	0x15180
#define	SEC_PER_YEAR	0x1e13380


/* This holds good till yr 2100 */
void
ud_dtime2utime(struct timespec32 *utime,
	struct tstamp const *dtime)
{
	int16_t year, tzone;
	int32_t	sec;
	uint32_t *cp;

	ud_printf("ud_dtime2utime\n");

	year = SWAP_16(dtime->ts_year);
	cp = (year % 4) ? cum_sec : cum_sec_leap;

	utime->tv_sec = cp[dtime->ts_month - 1];
	utime->tv_sec += (dtime->ts_day - 1) * SEC_PER_DAY;
	utime->tv_sec += ((dtime->ts_hour * 60) +
	    dtime->ts_min) * 60 +
	    dtime->ts_sec;

	tzone = SWAP_16(dtime->ts_tzone);
	if ((tzone & TMODE) == 0x1000) {
		/* Local time */
		if ((tzone & TINVALID) != TINVALID) {
			if (tzone & TSIGN) {
				/*
				 * Sign extend the tzone
				 */
				sec = tzone | 0xFFFFF000;
			} else {
				sec = tzone & TOFFSET;
			}
			sec *= 60;
			utime->tv_sec -= sec;
		}
	}

	utime->tv_nsec = ((((dtime->ts_csec * 100) +
	    dtime->ts_husec) * 100) +
	    dtime->ts_usec) * 1000;
	if (year >= 1970) {
		utime->tv_sec += (year - 1970) * SEC_PER_YEAR;
		utime->tv_sec += ((year - 1969) / 4) * SEC_PER_DAY;
	} else {
		utime->tv_sec = ((1970 - year) * SEC_PER_YEAR +
		    ((1972 - year) / 4) * SEC_PER_DAY -
		    utime->tv_sec) * -1;
		if (utime->tv_nsec) {
			utime->tv_sec++;
			utime->tv_nsec = 1000 * 1000 * 1000 - utime->tv_nsec;
		}
	}
}

void
ud_utime2dtime(struct timespec32 const *utime,
	struct tstamp *dtime)
{
	time32_t sec = utime->tv_sec;
	int32_t usec = utime->tv_nsec / 1000;
	uint32_t lyrs, nyrs, dummy;
	uint32_t *cp;
	int32_t before = 0;

	ud_printf("ud_utime2dtime\n");

	if (sec < 0) {
		before = 1;
		sec = sec * -1;
		if (usec) {
			sec = sec + 1;
			usec = 1000 * 1000 - usec;
		}
	}

	dtime->ts_csec = usec / 10000;
	usec %= 10000;
	dtime->ts_husec = usec / 100;
	dtime->ts_usec = usec % 100;

	nyrs = sec / SEC_PER_YEAR;
	if (before == 0) {
		lyrs = (nyrs + 1) / 4;
	} else {
		lyrs = (nyrs + 2) / 4;
	}
	if (nyrs != ((sec - (lyrs * SEC_PER_DAY)) / SEC_PER_YEAR)) {
		nyrs--;
		if (before == 0) {
			lyrs = (nyrs + 1) / 4;
		} else {
			lyrs = (nyrs + 2) / 4;
		}
	}
	sec -= nyrs * SEC_PER_YEAR + lyrs * SEC_PER_DAY;

	if (before == 1) {
		nyrs = 1970 - nyrs;
		if (sec != 0) {
			nyrs --;
			if ((nyrs % 4) == 0) {
				sec = SEC_PER_YEAR + SEC_PER_DAY - sec;
			} else {
				sec = SEC_PER_YEAR - sec;
			}
		}
	} else {
		nyrs += 1970;
	}
	cp = (nyrs % 4) ? cum_sec : cum_sec_leap;
	dummy = sec / (SEC_PER_DAY * 29);
	if (dummy > 11) {
		dummy = 11;
	}
	if (sec < cp[dummy]) {
		dummy--;
	}
	dtime->ts_year = SWAP_16(nyrs);
	dtime->ts_month = dummy;
	sec -= cp[dtime->ts_month];
	dtime->ts_month++;
	dtime->ts_day = sec / SEC_PER_DAY;
	sec -= dtime->ts_day * SEC_PER_DAY;
	dtime->ts_day++;
	dtime->ts_hour = sec / SECS_PER_HOUR;
	sec -= dtime->ts_hour * SECS_PER_HOUR;
	dtime->ts_min = sec / SECS_PER_MIN;
	sec -= dtime->ts_min * SECS_PER_MIN;
	dtime->ts_sec = (uint8_t)sec;

	/* GMT offset is 0 */
	dtime->ts_tzone = SWAP_16(0x1000);
}


int32_t
ud_syncip(struct ud_inode *ip, int32_t flags, int32_t waitfor)
{
	int32_t error;
	struct vnode *vp = ITOV(ip);

	ud_printf("ud_syncip\n");

	if (ip->i_udf == NULL) {
		return (0);
	}

	if (!vn_has_cached_data(vp) || (vp->v_type == VCHR)) {
		error = 0;
	} else {
		rw_exit(&ip->i_contents);
		error = VOP_PUTPAGE(vp, (offset_t)0,
		    (uint32_t)0, flags, CRED(), NULL);
		rw_enter(&ip->i_contents, RW_WRITER);
	}

	if (ip->i_flag & (IUPD |IACC | ICHG | IMOD)) {
		ud_iupdat(ip, waitfor);
	}

	return (error);
}


/* ARGSUSED */
int32_t
ud_fbwrite(struct fbuf *fbp, struct ud_inode *ip)
{
	ud_printf("ud_fbwrite\n");

	ASSERT(fbp != NULL);

	return (fbwrite(fbp));
}


void
ud_sbwrite(struct udf_vfs *udf_vfsp)
{
	struct log_vol_int_desc *lvid;
	struct ud_part *ud_part;
	struct lvid_iu *iu;
	uint32_t *temp;
	int32_t i, c;

	ud_printf("ud_sbwrite\n");
	ASSERT(udf_vfsp);
	ASSERT(MUTEX_HELD(&udf_vfsp->udf_lock));

	/*
	 * updatable information in the superblock
	 * integrity type, udf_maxuniq, udf_nfiles, udf_ndirs
	 * udp_nfree in lvid
	 */
	lvid = (struct log_vol_int_desc *)udf_vfsp->udf_lvid;
	if (udf_vfsp->udf_clean == UDF_DIRTY) {
		lvid->lvid_int_type = SWAP_32(LOG_VOL_OPEN_INT);
	} else {
		lvid->lvid_int_type = SWAP_32(LOG_VOL_CLOSE_INT);
	}
	lvid->lvid_uniqid = SWAP_64(udf_vfsp->udf_maxuniq);
	temp = lvid->lvid_fst;
	c = SWAP_32(lvid->lvid_npart);
	ud_part = udf_vfsp->udf_parts;
	for (i = 0; i < c; i++) {
		temp[i] = SWAP_32(ud_part->udp_nfree);
		ud_part++;
	}
	iu = (struct lvid_iu *)(temp + c * 2);
	iu->lvidiu_nfiles = SWAP_32(udf_vfsp->udf_nfiles);
	iu->lvidiu_ndirs = SWAP_32(udf_vfsp->udf_ndirs);

	ud_update_regid(&iu->lvidiu_regid);

	ud_make_tag(udf_vfsp, &lvid->lvid_tag,
	    UD_LOG_VOL_INT, udf_vfsp->udf_iseq_loc,
	    sizeof (struct log_vol_int_desc) - 8 +
	    8 * udf_vfsp->udf_npart +
	    SWAP_32(lvid->lvid_liu));

	/*
	 * Don't release the buffer after writing to the disk
	 */
	bwrite2(udf_vfsp->udf_iseq);
}


int32_t
ud_sync_indir(struct ud_inode *ip)
{
	int32_t elen;

	ud_printf("ud_sync_indir\n");

	if (ip->i_desc_type == ICB_FLAG_ONE_AD) {
		return (0);
	} else if (ip->i_desc_type == ICB_FLAG_SHORT_AD) {
		elen = sizeof (struct short_ad);
	} else if (ip->i_desc_type == ICB_FLAG_LONG_AD) {
		elen = sizeof (struct long_ad);
	} else {
		return (EINVAL);
	}

	if (ip->i_astrat == STRAT_TYPE4) {
		int32_t ndentry;

		ndentry = ip->i_max_emb / elen;
		if (ip->i_ext_used < ndentry) {
			return (0);
		}
		ASSERT(ip->i_con);
	} else {
		cmn_err(CE_WARN, "unsupported strategy type\n");
		return (EINVAL);
	}

	return (0);
}

void
ud_update(int32_t flag)
{
	struct vfs *vfsp;
	struct udf_vfs *udfsp, *udfsnext, *update_list = NULL;
	int32_t check_cnt = 0;
	size_t check_size;
	struct check_node *check_list, *ptr;
	time_t start_time;

	ud_printf("ud_update\n");

	mutex_enter(&ud_sync_busy);
	/*
	 * Examine all udf_vfs structures and add those that we can lock to the
	 * update list.  This is so that we don't hold the list lock for a
	 * long time.  If vfs_lock fails for a file system instance, then skip
	 * it because somebody is doing a unmount on it.
	 */
	mutex_enter(&udf_vfs_mutex);
	for (udfsp = udf_vfs_instances;
	    udfsp != NULL; udfsp = udfsp->udf_next) {
		vfsp = udfsp->udf_vfs;
		if (vfs_lock(vfsp) != 0) {
			continue;
		}
		udfsp->udf_wnext = update_list;
		update_list = udfsp;
		check_cnt++;
	}
	mutex_exit(&udf_vfs_mutex);

	if (update_list == NULL) {
		mutex_exit(&ud_sync_busy);
		return;
	}

	check_size = sizeof (struct check_node) * check_cnt;
	check_list = ptr = kmem_alloc(check_size, KM_NOSLEEP);

	/*
	 * Write back modified superblocks.
	 * Consistency check that the superblock of
	 * each file system is still in the buffer cache.
	 *
	 * Note that the update_list traversal is done without the protection
	 * of an overall list lock, so it's necessary to rely on the fact that
	 * each entry of the list is vfs_locked when moving from one entry to
	 * the next.  This works because a concurrent attempt to add an entry
	 * to another thread's update_list won't find it, since it'll already
	 * be locked.
	 */
	check_cnt = 0;
	for (udfsp = update_list; udfsp != NULL; udfsp = udfsnext) {
		/*
		 * Need to grab the next ptr before we unlock this one so
		 * another thread doesn't grab it and change it before we move
		 * on to the next vfs.  (Once we unlock it, it's ok if another
		 * thread finds it to add it to its own update_list; we don't
		 * attempt to refer to it through our list any more.)
		 */
		udfsnext = udfsp->udf_wnext;
		vfsp = udfsp->udf_vfs;

		if (!vfsp->vfs_data) {
			vfs_unlock(vfsp);
			continue;
		}
		mutex_enter(&udfsp->udf_lock);

		/*
		 * Build up the STABLE check list, so we can unlock the vfs
		 * until we do the actual checking.
		 */
		if (check_list != NULL) {
			if ((udfsp->udf_flags & UDF_FL_RDONLY) == 0) {
				ptr->vfsp = vfsp;
				ptr->udf_vfs = udfsp;
				ptr->vfs_dev = vfsp->vfs_dev;
				ptr++;
				check_cnt++;
			}
		}

		/*
		 * superblock is not modified
		 */
		if (udfsp->udf_mod == 0) {
			mutex_exit(&udfsp->udf_lock);
			vfs_unlock(vfsp);
			continue;
		}
		if ((udfsp->udf_flags & UDF_FL_RDONLY) == 0) {
			mutex_exit(&udfsp->udf_lock);
			mutex_exit(&ud_sync_busy);
			cmn_err(CE_WARN, "update ro udfs mod\n");
			return;
		}
		udfsp->udf_mod = 0;
		mutex_exit(&udfsp->udf_lock);

		ud_update_superblock(vfsp);
		vfs_unlock(vfsp);
	}

	ud_flushi(flag);
	/*
	 * Force stale buffer cache information to be flushed,
	 * for all devices.  This should cause any remaining control
	 * information (e.g., inode info) to be flushed back.
	 */
	bflush((dev_t)NODEV);

	if (check_list == NULL) {
		mutex_exit(&ud_sync_busy);
		return;
	}

	/*
	 * For each udf filesystem in the STABLE check_list, update
	 * the clean flag if warranted.
	 */
	start_time = gethrestime_sec();
	for (ptr = check_list; check_cnt > 0; check_cnt--, ptr++) {
		/*
		 * ud_still_mounted() returns with vfsp and the vfs_reflock
		 * held if ptr refers to a vfs that is still mounted.
		 */
		if ((vfsp = ud_still_mounted(ptr)) == NULL) {
			continue;
		}
		ud_checkclean(vfsp, ptr->udf_vfs, ptr->vfs_dev, start_time);
		vfs_unlock(vfsp);
	}
	mutex_exit(&ud_sync_busy);
	kmem_free(check_list, check_size);
}


/*
 * Returns vfsp and hold the lock if the vfs is still being mounted.
 * Otherwise, returns 0.
 *
 * For our purposes, "still mounted" means that the file system still appears
 * on the list of UFS file system instances.
 */
vfs_t *
ud_still_mounted(struct check_node *checkp)
{
	struct vfs *vfsp;
	struct udf_vfs *udf_vfsp;

	ud_printf("ud_still_mounted\n");

	mutex_enter(&udf_vfs_mutex);
	for (udf_vfsp = udf_vfs_instances;
	    udf_vfsp != NULL; udf_vfsp = udf_vfsp->udf_next) {
		if (udf_vfsp != checkp->udf_vfs) {
			continue;
		}
		/*
		 * Tentative match:  verify it and try to lock.  (It's not at
		 * all clear how the verification could fail, given that we've
		 * gotten this far.  We would have had to reallocate the
		 * ufsvfs struct at hand for a new incarnation; is that really
		 * possible in the interval from constructing the check_node
		 * to here?)
		 */
		vfsp = udf_vfsp->udf_vfs;
		if (vfsp != checkp->vfsp) {
			continue;
		}
		if (vfsp->vfs_dev != checkp->vfs_dev) {
			continue;
		}
		if (vfs_lock(vfsp) != 0) {
			continue;
		}
		mutex_exit(&udf_vfs_mutex);
		return (vfsp);
	}
	mutex_exit(&udf_vfs_mutex);
	return (NULL);
}

/* ARGSUSED */
void
ud_checkclean(struct vfs *vfsp,
	struct udf_vfs *udf_vfsp, dev_t dev, time_t timev)
{
	ud_printf("ud_checkclean\n");
	udf_vfsp = (struct udf_vfs *)vfsp->vfs_data;
	/*
	 * ignore if buffers or inodes are busy
	 */
	if ((bcheck(dev, udf_vfsp->udf_iseq)) ||
	    (ud_icheck(udf_vfsp))) {
		return;
	}
	mutex_enter(&udf_vfsp->udf_lock);
	ud_sbwrite(udf_vfsp);
	mutex_exit(&udf_vfsp->udf_lock);
}

int32_t
ud_icheck(struct udf_vfs *udf_vfsp)
{
	int32_t index, error = 0;
	union ihead *ih;
	struct ud_inode *ip;

	mutex_enter(&ud_icache_lock);
	for (index = 0; index < UD_HASH_SZ; index++) {
		ih = &ud_ihead[index];
		for (ip = ih->ih_chain[0];
			ip != (struct ud_inode *)ih; ip = ip->i_forw) {
			if ((ip->i_udf == udf_vfsp) &&
				((ip->i_flag & (IMOD|IUPD|ICHG)) ||
				(RW_ISWRITER(&ip->i_rwlock)) ||
				((ip->i_nlink <= 0) && (ip->i_flag & IREF)))) {
					error = 1;
					goto end;
			}
		}
	}
end:
	mutex_exit(&ud_icache_lock);
	return (error);
}

void
ud_flushi(int32_t flag)
{
	struct ud_inode *ip, *lip;
	struct vnode *vp;
	int cheap = flag & SYNC_ATTR;
	int32_t index;
	union  ihead *ih;

	/*
	 * Write back each (modified) inode,
	 * but don't sync back pages if vnode is
	 * part of the virtual swap device.
	 */
	mutex_enter(&ud_icache_lock);
	for (index = 0; index < UD_HASH_SZ; index++) {
		ih = &ud_ihead[index];
		lip = NULL;

		for (ip = ih->ih_chain[0], lip = NULL;
		    ip && ip != (struct ud_inode *)ih;
		    ip = ip->i_forw) {
			int flag = ip->i_flag;

			vp = ITOV(ip);
			/*
			 * Skip locked & inactive inodes.
			 * Skip vnodes w/ no cached data and no inode changes.
			 * Skip read-only vnodes
			 */
			if ((flag & IREF) == 0 ||
			    (!vn_has_cached_data(vp) &&
			    ((flag & (IMOD|IACC|IUPD|ICHG)) == 0)) ||
			    (vp->v_vfsp == NULL) || vn_is_readonly(vp)) {
				continue;
			}

			if (!rw_tryenter(&ip->i_contents, RW_WRITER)) {
				continue;
			}

			VN_HOLD(vp);

			if (lip != NULL) {
				ITIMES(lip);
				VN_RELE(ITOV(lip));
			}
			lip = ip;

			/*
			 * If this is an inode sync for file system hardening
			 * or this is a full sync but file is a swap file,
			 * don't sync pages but make sure the inode is up
			 * to date.  In other cases, push everything out.
			 */
			if (cheap || IS_SWAPVP(vp)) {
				ud_iupdat(ip, 0);
			} else {
				(void) ud_syncip(ip, B_ASYNC, I_SYNC);
			}
			rw_exit(&ip->i_contents);
		}
		if (lip != NULL) {
			ITIMES(lip);
			VN_RELE(ITOV(lip));
		}
	}
	mutex_exit(&ud_icache_lock);
}


void
ud_update_regid(struct regid *reg)
{
	ud_printf("ud_update_regid\n");

	bzero(reg->reg_id, 23);
	(void) strncpy(reg->reg_id, SUN_IMPL_ID, SUN_IMPL_ID_LEN);
	reg->reg_ids[0] = SUN_OS_CLASS;
	reg->reg_ids[1] = SUN_OS_ID;
}

/* ARGSUSED4 */
void
ud_make_tag(struct udf_vfs *udf_vfsp,
	struct tag *tag, uint16_t tag_id, uint32_t blkno, uint16_t crc_len)
{
	int32_t i;
	uint16_t crc;
	uint8_t *addr, cksum = 0;

	ud_printf("ud_make_tag\n");

	ASSERT(crc_len > 0x10);
	addr = (uint8_t *)tag;
	crc_len -= sizeof (struct tag);
	crc = ud_crc(addr + 0x10, crc_len);

	tag->tag_id = SWAP_16(tag_id);
	tag->tag_desc_ver = SWAP_16(2);
	tag->tag_cksum = 0;
	tag->tag_res = 0;
	tag->tag_sno = SWAP_16(udf_vfsp->udf_tsno);
	tag->tag_crc = SWAP_16(crc);

	tag->tag_crc_len = SWAP_16(crc_len);
	tag->tag_loc = SWAP_32(blkno);

	addr = (uint8_t *)tag;
	for (i = 0; i <= 15; i++) {
		cksum += addr[i];
	}
	tag->tag_cksum = cksum;
}

int32_t
ud_make_dev_spec_ear(struct dev_spec_ear *ds,
	major_t major, minor_t minor)
{
	int32_t attr_len;

	ud_printf("ud_make_dev_spec_ear\n");

	bzero(ds, sizeof (struct dev_spec_ear));

	attr_len = sizeof (struct dev_spec_ear);
	ds->ds_atype = SWAP_32(12);
	ds->ds_astype = 1;
	ds->ds_attr_len = SWAP_32(attr_len);
	ds->ds_iu_len = 0;
	ds->ds_major_id = SWAP_32(major);
	ds->ds_minor_id = SWAP_32(minor);

	return (attr_len);
}


int32_t
ud_get_next_fid(struct ud_inode *ip, struct fbuf **fbp, uint32_t offset,
	struct file_id **fid, uint8_t **name, uint8_t *buf)
{
	struct vnode *vp = ITOV(ip);
	caddr_t beg, end;
	int32_t error, lbsize, lbmask, sz, iulen, idlen, copied = 0;
	struct udf_vfs *udf_vfsp;
	uint8_t *obuf;
	int32_t count;
	uint32_t tbno;
	uint16_t crc_len;
	uint32_t len;

	ud_printf("ud_get_next_fid\n");

	obuf = buf;
	udf_vfsp = ip->i_udf;
	lbsize = udf_vfsp->udf_lbsize;
	lbmask = udf_vfsp->udf_lbmask;

	if ((error = ud_ip_off2bno(ip, offset, &tbno)) != 0) {
		return (error);
	}
	/* First time read */
	if (*fbp == NULL) {
		if ((error = fbread(vp, (offset_t)(offset & ~lbmask),
		    lbsize, S_READ, fbp)) != 0) {
			return (error);
		}
	}

	end = (*fbp)->fb_addr + (*fbp)->fb_count;
	beg = (*fbp)->fb_addr + (offset & lbmask);


	if ((offset % lbsize) ||
	    (offset == 0)) {
		sz = end - beg;
	} else {
		sz = 0;
	}


	if (F_LEN <= sz) {
		*fid = (struct file_id *)beg;
		beg += F_LEN;
	} else {
		copied = 1;
		bcopy(beg, buf, sz);
		fbrelse(*fbp, S_OTHER);
		*fbp = NULL;

		/* Skip to next block */
		if (offset & lbmask) {
			offset = (offset & ~lbmask) + lbsize;
		}
		if ((error = fbread(vp, (offset_t)offset,
		    lbsize, S_READ, fbp)) != 0) {
			return (error);
		}
		end = (*fbp)->fb_addr + (*fbp)->fb_count;
		beg = (*fbp)->fb_addr;

		bcopy(beg, buf + sz, F_LEN - sz);
		beg = beg + F_LEN - sz;
		*fid = (struct file_id *)buf;

		buf += F_LEN;
	}


	/*
	 * Check if this a valid file_identifier
	 */
	if (ud_verify_tag_and_desc(&(*fid)->fid_tag, UD_FILE_ID_DESC,
	    tbno, 0, lbsize) != 0) {
		/*
		 * Either end of directory or corrupted
		 */
		return (EINVAL);
	}

	crc_len = SWAP_16((*fid)->fid_tag.tag_crc_len);
	if (crc_len > udf_vfsp->udf_lbsize) {
		/*
		 * Entries cannot be larger than
		 * blocksize
		 */
		return (EINVAL);
	}

	if (crc_len < (F_LEN - sizeof (struct tag))) {
		iulen = SWAP_16((*fid)->fid_iulen);
		idlen = FID_LEN(*fid) - F_LEN;
		goto use_id_iu_len;
	}

	/*
	 * By now beg points to the start fo the file name
	 */

	sz = end - beg;
	len = crc_len + sizeof (struct tag) - (F_LEN);
	if (len <= sz) {
		if (copied == 1) {
			bcopy(beg, buf, len);
			buf += len;
		}
		beg += len;
	} else {
		copied = 1;
		/*
		 * We are releasing the
		 * old buffer so copy fid to buf
		 */
		if (obuf == buf) {
			count = F_LEN + sz;
			bcopy(*fid, buf, count);
			*fid = (struct file_id *)buf;
			buf += count;
		} else {
			bcopy(beg, buf, sz);
			*fid = (struct file_id *)buf;
			buf += sz;
		}
		fbrelse(*fbp, S_OTHER);
		*fbp = NULL;

		/* Skip to next block */
		if (offset & lbmask) {
			offset = (offset & ~lbmask) + lbsize;
		}
		if ((error = fbread(vp, (offset_t)offset,
		    lbsize, S_READ, fbp)) != 0) {
			return (error);
		}
		end = (*fbp)->fb_addr + (*fbp)->fb_count;
		beg = (*fbp)->fb_addr;
		count = len - sz;
		bcopy(beg, buf, count);
		beg += count;
	}

	/*
	 * First we verify that the tag id and the FID_LEN are valid.
	 * Next we verify the crc of the descriptor.
	 */
	if (ud_verify_tag_and_desc(&(*fid)->fid_tag, UD_FILE_ID_DESC,
	    tbno, 0, lbsize) != 0) {
		/* directory is corrupted */
		return (EINVAL);
	}
	if (ud_verify_tag_and_desc(&(*fid)->fid_tag, UD_FILE_ID_DESC,
	    tbno, 1, FID_LEN(*fid)) != 0) {
		/* directory is corrupted */
		return (EINVAL);
	}

	idlen = FID_LEN(*fid);

	idlen -= F_LEN;
	iulen = SWAP_16((*fid)->fid_iulen);
	if (crc_len < (F_LEN - sizeof (struct tag) + idlen)) {
use_id_iu_len:
		len = (F_LEN - sizeof (struct tag) + idlen) - crc_len;
		sz = end - beg;
		if (len <= sz) {
			if (copied == 1) {
				bcopy(beg, buf, len);
			}
		} else {
			if (obuf == buf) {
				count = crc_len + sizeof (struct tag);
				bcopy(*fid, buf, count);
				*fid = (struct file_id *)buf;
				buf += count;
			} else {
				bcopy(beg, buf, sz);
				*fid = (struct file_id *)buf;
				buf += sz;
			}
			fbrelse(*fbp, S_OTHER);
			*fbp = NULL;

			/* Skip to next block */
			if (offset & lbmask) {
				offset = (offset & ~lbmask) + lbsize;
			}
			if ((error = fbread(vp, (offset_t)offset,
			    lbsize, S_READ, fbp)) != 0) {
				return (error);
			}
			end = (*fbp)->fb_addr + (*fbp)->fb_count;
			beg = (*fbp)->fb_addr;
			count = len - sz;
			bcopy(beg, buf, count);
			beg += count;
		}
	}

	*name = ((uint8_t *)*fid) + F_LEN + iulen;

	return (0);
}


int32_t
ud_verify_tag_and_desc(struct tag *tag, uint16_t id, uint32_t blockno,
			int32_t verify_desc, int32_t desc_len)
{
	int32_t i;
	uint8_t *addr, cksum = 0;
	uint16_t crc;
	file_entry_t	*fe;
	struct ext_attr_hdr *eah;
	struct file_id	*fid;
	int32_t fidlen, ea_off;

	if (tag->tag_id != SWAP_16(id)) {
		return (1);
	}
	addr = (uint8_t *)tag;
	eah = (struct ext_attr_hdr *)tag;
	for (i = 0; i < 4; i++) {
		cksum += addr[i];
	}
	for (i = 5; i <= 15; i++) {
		cksum += addr[i];
	}
	if (cksum != tag->tag_cksum) {
		cmn_err(CE_NOTE,
		"Checksum Does not Verify TAG %x CALC %x blockno 0x%x\n",
		    tag->tag_cksum, cksum, blockno);
		return (1);
	}
	/*
	 * Validate the meta data for UD_FILE_ID_DESC.
	 * The FID_LEN should not exceed the desc_len.
	 * This validation is done before the entire descriptor is read.
	 * A call to this routine is made initially with verify_desc set as 0
	 * but a non zero value in desc_len.
	 */
	if (id == UD_FILE_ID_DESC) {
		fid = (struct file_id *)tag;
		fidlen = FID_LEN(fid);
		if (fidlen > desc_len) {
			cmn_err(CE_NOTE,
	"Invalid FID_LEN(0x%x). Greater than expected(0x%x) blockno 0x%x\n",
			    fidlen, desc_len, blockno);
				return (1);
		}
	}
	if (verify_desc == 0)
		return (0);
	/*
	 * We are done verifying the tag. We proceed with verifying the
	 * the descriptor. desc_len indicates the size of the structure
	 * pointed to by argument tag. It includes the size of struct tag.
	 * We first check the tag_crc_len since we use this to compute the
	 * crc of the descriptor.
	 * Verifying the crc is normally sufficient to ensure the integrity
	 * of the meta data in the descriptor. However given the paranoia
	 * about the panic caused by illegal meta data values we do an
	 * additional check of the meta data for decriptor UD_FILE_ENTRY.
	 * (The original panic was caused because this routine was not called
	 * to verify the integrity of the tag and descriptor.)
	 */
	if (SWAP_16(tag->tag_crc_len) > (desc_len - sizeof (struct tag))) {
		cmn_err(CE_NOTE,
	"tag_crc_len(0x%x) is greater than expected len(0x%x) blockno 0x%x\n",
		    SWAP_16(tag->tag_crc_len),
		    desc_len, blockno);
		return (1);
	}
	if (tag->tag_crc_len) {
		crc = ud_crc(addr + 0x10, SWAP_16(tag->tag_crc_len));
		if (crc != SWAP_16(tag->tag_crc)) {
			cmn_err(CE_NOTE, "CRC mismatch TAG_ID 0x%x TAG_CRC 0x%x"
			" Computed crc 0x%x tag_loc %x blockno 0x%x\n",
			    id, SWAP_16(tag->tag_crc), crc,
			    SWAP_32(tag->tag_loc), blockno);
			return (1);
		}
	}
	switch (id) {
		case UD_FILE_ENTRY:
			fe = (file_entry_t *)tag;
			if ((offsetof(struct file_entry, fe_spec) +
			    SWAP_32(fe->fe_len_ear) +
			    SWAP_32(fe->fe_len_adesc)) > desc_len) {
				cmn_err(CE_NOTE,
	"fe_len_ear(0x%x) fe_len_adesc(0x%x) fields are not OK. blockno 0x%x\n",
				    SWAP_32(fe->fe_len_ear),
				    SWAP_32(fe->fe_len_adesc),
				    blockno);
				return (1);
			}
			break;
		case UD_EXT_ATTR_HDR:
			eah = (struct ext_attr_hdr *)tag;
			if (SWAP_32(eah->eah_aal) > desc_len) {
				cmn_err(CE_NOTE,
		    "eah_all(0x%x) exceeds desc. len(0x%x) blockno 0x%x\n",
				    SWAP_32(eah->eah_aal), desc_len, blockno);
				return (1);
			}
			ea_off = GET_32(&eah->eah_ial);
			if (ea_off >= desc_len) {
				cmn_err(CE_NOTE,
		    "ea_off(0x%x) is not less than ea_len(0x%x) blockno 0x%x\n",
				    ea_off, desc_len, blockno);
				return (1);
			}
			break;
		default:
			break;
	}
	if (SWAP_32(blockno) != tag->tag_loc) {
		cmn_err(CE_NOTE,
		    "Tag Location mismatch blockno %x tag_blockno %x\n",
		    blockno, SWAP_32(tag->tag_loc));
		return (1);
	}
	return (0);
}

/* **************** udf specific subroutines *********************** */

uint16_t ud_crc_table[256] = {
	0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50A5, 0x60C6, 0x70E7,
	0x8108, 0x9129, 0xA14A, 0xB16B, 0xC18C, 0xD1AD, 0xE1CE, 0xF1EF,
	0x1231, 0x0210, 0x3273, 0x2252, 0x52B5, 0x4294, 0x72F7, 0x62D6,
	0x9339, 0x8318, 0xB37B, 0xA35A, 0xD3BD, 0xC39C, 0xF3FF, 0xE3DE,
	0x2462, 0x3443, 0x0420, 0x1401, 0x64E6, 0x74C7, 0x44A4, 0x5485,
	0xA56A, 0xB54B, 0x8528, 0x9509, 0xE5EE, 0xF5CF, 0xC5AC, 0xD58D,
	0x3653, 0x2672, 0x1611, 0x0630, 0x76D7, 0x66F6, 0x5695, 0x46B4,
	0xB75B, 0xA77A, 0x9719, 0x8738, 0xF7DF, 0xE7FE, 0xD79D, 0xC7BC,
	0x48C4, 0x58E5, 0x6886, 0x78A7, 0x0840, 0x1861, 0x2802, 0x3823,
	0xC9CC, 0xD9ED, 0xE98E, 0xF9AF, 0x8948, 0x9969, 0xA90A, 0xB92B,
	0x5AF5, 0x4AD4, 0x7AB7, 0x6A96, 0x1A71, 0x0A50, 0x3A33, 0x2A12,
	0xDBFD, 0xCBDC, 0xFBBF, 0xEB9E, 0x9B79, 0x8B58, 0xBB3B, 0xAB1A,
	0x6CA6, 0x7C87, 0x4CE4, 0x5CC5, 0x2C22, 0x3C03, 0x0C60, 0x1C41,
	0xEDAE, 0xFD8F, 0xCDEC, 0xDDCD, 0xAD2A, 0xBD0B, 0x8D68, 0x9D49,
	0x7E97, 0x6EB6, 0x5ED5, 0x4EF4, 0x3E13, 0x2E32, 0x1E51, 0x0E70,
	0xFF9F, 0xEFBE, 0xDFDD, 0xCFFC, 0xBF1B, 0xAF3A, 0x9F59, 0x8F78,
	0x9188, 0x81A9, 0xB1CA, 0xA1EB, 0xD10C, 0xC12D, 0xF14E, 0xE16F,
	0x1080, 0x00A1, 0x30C2, 0x20E3, 0x5004, 0x4025, 0x7046, 0x6067,
	0x83B9, 0x9398, 0xA3FB, 0xB3DA, 0xC33D, 0xD31C, 0xE37F, 0xF35E,
	0x02B1, 0x1290, 0x22F3, 0x32D2, 0x4235, 0x5214, 0x6277, 0x7256,
	0xB5EA, 0xA5CB, 0x95A8, 0x8589, 0xF56E, 0xE54F, 0xD52C, 0xC50D,
	0x34E2, 0x24C3, 0x14A0, 0x0481, 0x7466, 0x6447, 0x5424, 0x4405,
	0xA7DB, 0xB7FA, 0x8799, 0x97B8, 0xE75F, 0xF77E, 0xC71D, 0xD73C,
	0x26D3, 0x36F2, 0x0691, 0x16B0, 0x6657, 0x7676, 0x4615, 0x5634,
	0xD94C, 0xC96D, 0xF90E, 0xE92F, 0x99C8, 0x89E9, 0xB98A, 0xA9AB,
	0x5844, 0x4865, 0x7806, 0x6827, 0x18C0, 0x08E1, 0x3882, 0x28A3,
	0xCB7D, 0xDB5C, 0xEB3F, 0xFB1E, 0x8BF9, 0x9BD8, 0xABBB, 0xBB9A,
	0x4A75, 0x5A54, 0x6A37, 0x7A16, 0x0AF1, 0x1AD0, 0x2AB3, 0x3A92,
	0xFD2E, 0xED0F, 0xDD6C, 0xCD4D, 0xBDAA, 0xAD8B, 0x9DE8, 0x8DC9,
	0x7C26, 0x6C07, 0x5C64, 0x4C45, 0x3CA2, 0x2C83, 0x1CE0, 0x0CC1,
	0xEF1F, 0xFF3E, 0xCF5D, 0xDF7C, 0xAF9B, 0xBFBA, 0x8FD9, 0x9FF8,
	0x6E17, 0x7E36, 0x4E55, 0x5E74, 0x2E93, 0x3EB2, 0x0ED1, 0x1EF0
};

uint16_t
ud_crc(uint8_t *addr, int32_t len)
{
	uint16_t crc = 0;

	while (len-- > 0) {
		crc = ud_crc_table[(crc >> 8 ^ *addr++) & 0xff] ^ (crc<<8);
	}

	return (crc);
}

typedef unsigned short unicode_t;

#define	POUND		0x0023
#define	DOT		0x002E
#define	SLASH		0x002F
#define	UNDERBAR	0x005F


static uint16_t htoc[16] = {'0', '1', '2', '3',
	'4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};


/*
 * An unrecorded block will return all
 * 0's on a WORM media. to simulate
 * a unrecorded block on a rw media
 * we fill it with all zero's
 *	return 0 : If unrecorded
 *	return 1 : If recorded.
 */
uint32_t
ud_check_te_unrec(struct udf_vfs *udf_vfsp, caddr_t addr, uint32_t blkno)
{
	int32_t i, lbsize;
	struct term_entry *te;

	ASSERT(udf_vfsp);
	ASSERT(addr);

	te = (struct term_entry *)addr;
	if (ud_verify_tag_and_desc(&te->te_tag, UD_TERMINAL_ENT,
	    blkno, 1, udf_vfsp->udf_lbsize) != 0) {
		lbsize = udf_vfsp->udf_lbsize;
		for (i = 0; i < lbsize; i++) {
			if (addr[i] != 0) {
				return (1);
			}
		}
	}
	return (0);
}


/*
 * The algorithms ud_utf82utf16 and ud_utf162utf8
 * donot handle surrogates. This is unicode 1.1 as I
 * understand. When writing udf2.0 this code has
 * to be changed to process surrogates also
 * (Dont ask me what is a surrogate character)
 */

/*
 * This will take a utf8 string convert the first character
 * to utf16 and return the number of bytes consumed in this
 * process. A 0 will be returned if the character is invalid
 */
uint8_t bytes_from_utf8[] = {
0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,
0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,
0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,
0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,
0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,
0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,
0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,
0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,
0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,
0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,
0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,
0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,
1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,
1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,
2, 2, 2, 2,  2, 2, 2, 2,  2, 2, 2, 2,  2, 2, 2, 2,
3, 3, 3, 3,  3, 3, 3, 3,  4, 4, 4, 4,  5, 5, 5, 5
};
int32_t
ud_utf82utf16(uint8_t *s_8, uint16_t *c_16, int32_t count)
{
	int32_t extra_bytes;
	uint32_t c_32;
	ASSERT(s_8);
	ASSERT(c_16);

	/*
	 * First convert to a 32-bit
	 * character
	 */
	c_32 = 0;
	extra_bytes = bytes_from_utf8[*s_8];
	if (extra_bytes > count) {
		return (0);
	}

	/*
	 * verify if the string is a valid
	 * utf8 string
	 */
	if (extra_bytes == 0) {
		/*
		 * Apply one byte rule
		 */
		if (*s_8 & 0x80) {
			return (0);
		}
		c_32 = *s_8 & 0x7F;
	} else if (extra_bytes == 1) {
		if (((*s_8 & 0xE0) != 0xC0) ||
		    ((*(s_8 + 1) & 0xC0) != 0x80)) {
			return (0);
		}
		c_32 = *s_8 & 0x1F;
	} else if (extra_bytes == 2) {
		if (((*s_8 & 0xF0) != 0xE0) ||
		    ((*(s_8 + 1) & 0xC0) != 0x80) ||
		    ((*(s_8 + 2) & 0xC0) != 0x80)) {
			return (0);
		}
		c_32 = *s_8 & 0x0F;
	} else if (extra_bytes == 3) {
		if (((*s_8 & 0xF8) != 0xF0) ||
		    ((*(s_8 + 1) & 0xC0) != 0x80) ||
		    ((*(s_8 + 2) & 0xC0) != 0x80) ||
		    ((*(s_8 + 3) & 0xC0) != 0x80)) {
			return (0);
		}
		c_32 = *s_8 & 0x07;
	} else if (extra_bytes == 4) {
		if (((*s_8 & 0xFC) != 0xF8) ||
		    ((*(s_8 + 1) & 0xC0) != 0x80) ||
		    ((*(s_8 + 2) & 0xC0) != 0x80) ||
		    ((*(s_8 + 3) & 0xC0) != 0x80) ||
		    ((*(s_8 + 4) & 0xC0) != 0x80)) {
			return (0);
		}
		c_32 = *s_8 & 0x03;
	} else if (extra_bytes == 5) {
		if (((*s_8 & 0xFE) != 0xFC) ||
		    ((*(s_8 + 1) & 0xC0) != 0x80) ||
		    ((*(s_8 + 2) & 0xC0) != 0x80) ||
		    ((*(s_8 + 3) & 0xC0) != 0x80) ||
		    ((*(s_8 + 4) & 0xC0) != 0x80) ||
		    ((*(s_8 + 5) & 0xC0) != 0x80)) {
			return (0);
		}
		c_32 = *s_8 & 0x01;
	} else {
		return (0);
	}
	s_8++;

	/*
	 * Convert to 32-bit character
	 */
	switch (extra_bytes) {
		case 5 :
			c_32 <<= 6;
			c_32 += (*s_8++ & 0x3F);
			/* FALLTHROUGH */
		case 4 :
			c_32 <<= 6;
			c_32 += (*s_8++ & 0x3F);
			/* FALLTHROUGH */
		case 3 :
			c_32 <<= 6;
			c_32 += (*s_8++ & 0x3F);
			/* FALLTHROUGH */
		case 2 :
			c_32 <<= 6;
			c_32 += (*s_8++ & 0x3F);
			/* FALLTHROUGH */
		case 1 :
			c_32 <<= 6;
			c_32 += (*s_8++ & 0x3F);
			/* FALLTHROUGH */
		case 0 :
			break;
	}

	/*
	 * now convert the 32-bit
	 * character into a 16-bit character
	 */
	*c_16 = c_32;
	return (extra_bytes + 1);
}

/*
 * Convert to a form that can be put on the media
 * out_len has the size of out_str when we are called.
 * This routine will set out_len to actual bytes written to out_str.
 * We make sure that we will not attempt to write beyond the out_str_len.
 */
int32_t
ud_compress(int32_t in_len, int32_t *out_len,
		uint8_t *in_str, uint8_t *out_str)
{
	int32_t error, in_index, out_index, index, c_tx_sz, out_str_len;
	uint16_t w2_char, *w2_str;
	uint8_t comp_id;

	out_str_len = *out_len;
	if (in_len > (out_str_len - 2)) {
		return (ENAMETOOLONG);
	}

	*out_len = 0;
	w2_str = (uint16_t *)kmem_zalloc(512, KM_SLEEP);

	error = in_index = out_index = c_tx_sz = 0;
	comp_id = 8;
	for (in_index = 0; in_index < in_len; in_index += c_tx_sz) {
		if ((c_tx_sz = ud_utf82utf16(&in_str[in_index],
		    &w2_char, in_len - in_index)) == 0) {
			error = EINVAL;
			goto end;
		}
		/*
		 * utf-8 characters can be
		 * of 1 - 6 bytes in length
		 */
		ASSERT(c_tx_sz > 0);
		ASSERT(c_tx_sz < 7);
		if ((comp_id == 8) && (w2_char & 0xff00)) {
			comp_id = 0x10;
		}
		w2_str[out_index++] = w2_char;
	}
	if (((comp_id == 0x10) && (out_index > ((out_str_len - 2)/2))) ||
	    ((comp_id == 0x8) && (out_index > (out_str_len - 2)))) {
		error = ENAMETOOLONG;
		goto end;
	}

	in_index = out_index;
	out_index = 0;
	out_str[out_index++] = comp_id;
	for (index = 0; index < in_index; index++) {
		if (comp_id == 0x10) {
			out_str[out_index++] = (w2_str[index] & 0xFF00) >> 8;
		}
		out_str[out_index++] = w2_str[index] & 0xFF;
	}
	ASSERT(out_index <= (out_str_len - 1));
	*out_len = out_index;
end:
	if (w2_str != NULL) {
		kmem_free((caddr_t)w2_str, 512);
	}
	return (error);
}

/*
 * Take a utf16 character and convert
 * it into a utf8 character.
 * A 0 will be returned if the conversion fails
 */
uint8_t first_byte_mark[7] = { 0x00, 0x00, 0xC0, 0xE0, 0xF0, 0xF8, 0xFC};
int32_t
ud_utf162utf8(uint16_t c_16, uint8_t *s_8)
{
	int32_t nc;
	uint32_t c_32;
	uint32_t byte_mask = 0xBF;
	uint32_t byte_mark = 0x80;

	ASSERT(s_8);

	/*
	 * Convert the 16-bit character to
	 * a 32-bit character
	 */
	c_32 = c_16;

	/*
	 * By here the 16-bit character is converted
	 * to a 32-bit wide character
	 */
	if (c_32 < 0x80) {
		nc = 1;
	} else if (c_32 < 0x800) {
		nc = 2;
	} else if (c_32 < 0x10000) {
		nc = 3;
	} else if (c_32 < 0x200000) {
		nc = 4;
	} else if (c_32 < 0x4000000) {
		nc = 5;
	} else if (c_32 < (uint32_t)0x80000000) {
		nc = 6;
	} else {
		nc = 0;
	}
	s_8 += nc;
	switch (nc) {
		case 6 :
			*(--s_8) = (c_32 | byte_mark)  & byte_mask;
			c_32 >>= 6;
			/* FALLTHROUGH */
		case 5 :
			*(--s_8) = (c_32 | byte_mark)  & byte_mask;
			c_32 >>= 6;
			/* FALLTHROUGH */
		case 4 :
			*(--s_8) = (c_32 | byte_mark)  & byte_mask;
			c_32 >>= 6;
			/* FALLTHROUGH */
		case 3 :
			*(--s_8) = (c_32 | byte_mark)  & byte_mask;
			c_32 >>= 6;
			/* FALLTHROUGH */
		case 2 :
			*(--s_8) = (c_32 | byte_mark)  & byte_mask;
			c_32 >>= 6;
			/* FALLTHROUGH */
		case 1 :
			*(--s_8) = c_32 | first_byte_mark[nc];
	}
	return (nc);
}

/*
 * Convert to a form that can be transferred to the user
 * Assumption's
 * in_length < 256, out_str is at least 255 bytes long
 * The converted byte stream length is returned in out_len
 */
#define	MAX_ALLOWABLE_STRING 250

int32_t
ud_uncompress(int32_t in_len, int32_t *out_len,
		uint8_t *in_str, uint8_t *out_str)
{
	uint8_t comp_id, utf8[6];
	uint16_t w2_char, crc;
	int32_t error, index, c_tx_sz, len_till_now;
	int32_t make_crc, lic, dot_loc, crc_start_loc = 0, k = 0;

	if (in_len == 0) {
		*out_len = 0;
		out_str[0] = '\0';
		return (0);
	}

	error = len_till_now = make_crc = 0;
	dot_loc = lic = -2;
	*out_len = 0;
	crc = 0;
	comp_id = in_str[0];

	/*
	 * File names "." and ".." are invalid under unix.
	 * Transform them into something
	 */
	if (comp_id == 8) {
		if ((in_str[1] == DOT) &&
		    ((in_len == 2) || ((in_len == 3) &&
		    (in_str[2] == DOT)))) {
			out_str[k++] = UNDERBAR;
			len_till_now = 1;
			goto make_append_crc;
		}
	} else if (comp_id == 0x10) {
		if (((in_str[1] << 8 | in_str[2]) == DOT) &&
		    ((in_len == 3) || ((in_len == 5) &&
		    ((in_str[3] << 8 | in_str[4]) == DOT)))) {
			out_str[k++] = UNDERBAR;
			len_till_now = 1;
			goto make_append_crc;
		}
	} else {
		*out_len = 0;
		return (EINVAL);
	}

	for (index = 1; index < in_len; ) {

		/*
		 * Uncompress each character
		 */
		if (comp_id == 0x10) {
			w2_char = in_str[index++] << 8;
			w2_char |= in_str[index++];
		} else {
			w2_char = in_str[index++];
		}

		if (make_crc != 0) {
			crc += w2_char;
		}

		if (w2_char == DOT) {
			dot_loc = len_till_now;
		}

		/*
		 * Get rid of invalid characters
		 */
		if ((w2_char == SLASH) ||
		    (w2_char == NULL)) {
			make_crc = 1;
			if (((comp_id == 8) &&
			    (lic != (index - 1))) ||
			    (comp_id == 0x10) &&
			    (lic != (index - 2))) {
				w2_char = UNDERBAR;
				lic = index;
			} else {
				lic = index;
				continue;
			}
		}

		/*
		 * Conver a 16bit character to a
		 * utf8 byte stream
		 */
		if ((c_tx_sz = ud_utf162utf8(w2_char, utf8)) == 0) {
			error = EINVAL;
			goto end;
		}
		ASSERT(c_tx_sz > 0);
		ASSERT(c_tx_sz < 7);

		/*
		 * The output string is larger than
		 * the maximum allowed string length
		 */
		if ((crc_start_loc == 0) &&
		    ((len_till_now + c_tx_sz) > MAX_ALLOWABLE_STRING)) {
			crc_start_loc = len_till_now;
		}

		if ((len_till_now + c_tx_sz) < MAXNAMELEN) {
			(void) strncpy((caddr_t)&out_str[len_till_now],
			    (caddr_t)utf8, c_tx_sz);
			len_till_now += c_tx_sz;
		} else {
			break;
		}
	}

	/*
	 * If we need to append CRC do it now
	 */

	if (make_crc) {

		if (len_till_now > MAX_ALLOWABLE_STRING) {
			len_till_now = crc_start_loc;
		}

		if (dot_loc > 0) {
			/*
			 * Make space for crc before the DOT
			 * move the rest of the file name to the end
			 */
			for (k = len_till_now - 1; k >= dot_loc; k--) {
				out_str[k + 5] = out_str[k];
			}
			k = dot_loc;
		} else {
			k = len_till_now;
		}
make_append_crc:
		crc = ud_crc(in_str, in_len);
		out_str[k++] = POUND;
		out_str[k++] = htoc[(uint16_t)(crc & 0xf000) >> 12];
		out_str[k++] = htoc[(uint16_t)(crc & 0xf00) >> 8];
		out_str[k++] = htoc[(uint16_t)(crc & 0xf0) >> 4];
		out_str[k++] = htoc[crc & 0xf];
		len_till_now += 5;
	}
	*out_len = len_till_now;
end:
	return (error);
}


struct buf *
ud_bread(dev_t dev, daddr_t blkno, long bsize)
{
	struct buf *bp;

begin:
	bp = bread(dev, blkno, bsize);

	if (((bp->b_flags & B_ERROR) == 0) &&
	    (bp->b_bcount != bsize)) {
		/*
		 * Buffer cache returned a
		 * wrong number of bytes
		 * flush the old buffer and
		 * reread it again
		 */
		if (bp->b_flags & B_DELWRI) {
			bwrite(bp);
		} else {
			bp->b_flags |= (B_AGE | B_STALE);
			brelse(bp);
		}
		goto begin;
	}

	return (bp);
}

/*
 * Decide whether it is okay to remove within a sticky directory.
 * Two conditions need to be met:  write access to the directory
 * is needed.  In sticky directories, write access is not sufficient;
 * you can remove entries from a directory only if you own the directory,
 * if you are privileged, if you own the entry or if they entry is
 * a plain file and you have write access to that file.
 * Function returns 0 if remove access is granted.
 */
int
ud_sticky_remove_access(struct ud_inode *dir, struct ud_inode *entry,
	struct cred *cr)
{
	uid_t uid;

	ASSERT(RW_LOCK_HELD(&entry->i_contents));

	if ((dir->i_char & ISVTX) &&
	    (uid = crgetuid(cr)) != dir->i_uid &&
	    uid != entry->i_uid &&
	    (entry->i_type != VREG ||
	    ud_iaccess(entry, IWRITE, cr, 0) != 0))
		return (secpolicy_vnode_remove(cr));

	return (0);
}
