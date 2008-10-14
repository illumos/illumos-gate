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

#include <sys/types.h>
#include <sys/ksynch.h>
#include <sys/cmn_err.h>
#include <sys/errno.h>
#include <sys/kmem.h>
#include <sys/cred.h>
#include <sys/buf.h>
#include <sys/ddi.h>
#include <sys/nsc_thread.h>


#include "sd_bcache.h"
#include "sd_trace.h"
#include "sd_io.h"
#include "sd_bio.h"
#include "sd_ft.h"
#include "sd_misc.h"
#include "sd_pcu.h"

/*
 * PCU (aka UPS) handling -
 */
#define	bitmap_next cc_dirty_link
#define	bitmap_tail cc_dirty_next

#define	anon_next cc_dirty_link
#define	anon_tail cc_dirty_next
#define	anon_data cc_data

struct bitmap {
	_sd_cctl_t *bmps;
	int bmaps_per_block;
	int inuse;			/* In use in the _last_ block */
};

#define	SDBC_PCU_MAXSWAPIL  3		/* Watch for 5 fields in ioctl arg. */

struct swapfiles {
	int nswpf;			/* Number of filenames */
	int colsize;			/* In cache blocks */
	char *names[SDBC_PCU_MAXSWAPIL];
};

static void _sdbc_pcu_cleanup(struct swapfiles *);

/*
 * Forward declare functions containing 64-bit argument types to enforce
 * type-checking.
 */
static int add_bitmap_entry(struct bitmap *bmp, _sd_bitmap_t bits, int any_fail,
    nsc_off_t fba_num);
static int flush_bitmap_list(struct bitmap *bmp, dev_t dev, nsc_off_t *blkno);
static int flush_centry_list(_sd_cd_info_t *cdi, _sd_cctl_t *dirty, dev_t dev,
    nsc_off_t *blkno, int failed, struct bitmap *bmaps);
static int flush_hdr(_sd_cctl_t *hdr, dev_t dev, nsc_off_t blkno);
static int flush_anon_list(_sd_cctl_t *anon_list, dev_t dev, nsc_off_t *blkno);
static void sdbc_anon_copy(caddr_t src, nsc_size_t len, _sd_cctl_t *dest,
    nsc_off_t dest_off);
static void sdbc_anon_get(_sd_cctl_t *src, nsc_off_t src_off, caddr_t dest,
    nsc_size_t len);
static _sd_cctl_t *sdbc_get_anon_list(nsc_size_t bytes);

static int got_hint;			/* did we capture hint at power_lost */
static unsigned int wrthru_hint;	/* saved hint at power_lost */
static int saw_power_lost;

char _sdbc_shutdown_in_progress;
static struct swapfiles swfs;

/*
 * sdbc_get_anon_list - allocate a set of anonymous cache block
 * entries that can pretend to be a single blocks of data holding
 * a virtual character array holding "bytes" entries.
 *
 * returns - the cache block heading the chain.
 */
static _sd_cctl_t *
sdbc_get_anon_list(nsc_size_t bytes)
{
	_sd_cctl_t *list, *prev;
	nsc_size_t i, blks;

	prev = NULL;
	blks = (bytes + CACHE_BLOCK_SIZE - 1) / CACHE_BLOCK_SIZE;
	for (i = 0; i < blks; i++) {

		list = sdbc_centry_alloc_blks(_CD_NOHASH, 0, 1, 0);
		bzero(list->cc_data, CACHE_BLOCK_SIZE);
		list->anon_next = prev;
		prev = list;
	};

	return (list);
}

/*
 * sdbc_anon_get - gets "len" bytes of data virtual character array represented
 * by "src" begining at index "dest_off" and copy to buffer "dest".
 *
 * dest - pointer to our virtual array (chain of cache blocks).
 * dest_off - first location to copy data to.
 * src - pointer to data to copy
 * len - the number of bytes of data to copy
 *
 */
static void
sdbc_anon_get(_sd_cctl_t *src, nsc_off_t src_off, caddr_t dest, nsc_size_t len)
{
	nsc_size_t i;
	nsc_size_t nlen;
	nsc_off_t blk_start, blk_end;

	if (len == 0)
		return;

	blk_start = src_off / CACHE_BLOCK_SIZE;
	blk_end = (src_off + len) / CACHE_BLOCK_SIZE;

	for (i = 0; i < blk_start; i++) {
		src = src->anon_next;
		src_off -= CACHE_BLOCK_SIZE;
	}

	nlen = min(len, CACHE_BLOCK_SIZE - src_off);
	bcopy(&src->anon_data[src_off], dest, (size_t)nlen);

	for (i = 1; i < blk_end - blk_start; i++) {
		bcopy(src->anon_data, &dest[nlen], (size_t)CACHE_BLOCK_SIZE);
		nlen += CACHE_BLOCK_SIZE;
		src = src->anon_next;
	}
	if (nlen != len) {
		bcopy(src->anon_data, &dest[nlen], (size_t)(len - nlen));
	}
}

/*
 * sdbc_anon_copy - copies "len" bytes of data from "src" to the
 * virtual character array represented by "dest" begining at index
 * "dest_off".
 *
 * src - pointer to data to copy
 * len - the number of bytes of data to copy
 * dest - pointer to our virtual array (chain of cache blocks).
 * dest_off - first location to copy data to.
 *
 */
static void
sdbc_anon_copy(caddr_t src, nsc_size_t len, _sd_cctl_t *dest,
    nsc_off_t dest_off)
{
	nsc_size_t i;
	nsc_size_t nlen;
	nsc_off_t blk_start, blk_end;

	if (len == 0)
		return;

	blk_start = dest_off / CACHE_BLOCK_SIZE;
	blk_end = (dest_off + len) / CACHE_BLOCK_SIZE;

	for (i = 0; i < blk_start; i++) {
		dest = dest->anon_next;
		dest_off -= CACHE_BLOCK_SIZE;
	}

	nlen = min(len, CACHE_BLOCK_SIZE - dest_off);
	bcopy(src, &dest->anon_data[dest_off], (size_t)nlen);

	for (i = 1; i < blk_end - blk_start; i++) {
		bcopy(&src[nlen], dest->anon_data, (size_t)CACHE_BLOCK_SIZE);
		nlen += CACHE_BLOCK_SIZE;
		dest = dest->anon_next;
	}
	if (nlen != len) {
		bcopy(&src[nlen], dest->anon_data, (size_t)(len - nlen));
	}
}

/*
 * flush_anon_list - flush a chain of anonymous cache blocks
 * to the state file. Anonymous chains of cache blocks represent
 * virtual arrays for the state flushing code and can contain
 * various types of data.
 *
 * anon_list - chain of cache blocks to flush.
 *
 * dev - the state file device
 *
 * blkno - on input the cache block number to begin writing at.
 * On exit the next cache block number following the data
 * just written.
 *
 * returns - 0 on success, error number on failure.
 */
static int
flush_anon_list(_sd_cctl_t *anon_list,
		dev_t dev,
		nsc_off_t *blkno)
{
	struct buf *bp;
	int rc;
	_sd_cctl_t *prev;
	nsc_size_t bcnt;

	if (anon_list == NULL)
		return (0);

	bcnt = 0;
	do {
		bp = sd_alloc_iob(dev, BLK_TO_FBA_NUM(*blkno),
		    BLK_TO_FBA_NUM(1), 0);
		sd_add_fba(bp, &anon_list->cc_addr, 0, BLK_FBAS);
		rc = sd_start_io(bp, NULL, NULL, 0);
		(*blkno)++;

		/*
		 * A failure here is death. This is harsh but not sure
		 * what else to do
		 */

		if (rc != NSC_DONE)
			return (rc);
		bcnt++;

		prev = anon_list;
		anon_list = anon_list->anon_next;
		_sd_centry_release(prev);

	} while (anon_list);

	cmn_err(CE_CONT, "sdbc(flush_anon_list) %" NSC_SZFMT "\n", bcnt);
	return (0);

}

/*
 * start_bitmap_list - allocate an anonymous cache block entry
 * to anchor a chain of cache blocks representing a virtual
 * array of bitmap entries.
 *
 * returns - the cache block heading the chain.
 */
static void
start_bitmap_list(struct bitmap *bmp, int bpb)
{
	_sd_cctl_t *list;

	list = sdbc_centry_alloc_blks(_CD_NOHASH, 0, 1, 0);
	bzero(list->cc_data, CACHE_BLOCK_SIZE);
	list->bitmap_next = NULL;
	list->bitmap_tail = list;

	bmp->bmps = list;
	bmp->inuse = 0;
	bmp->bmaps_per_block = bpb;
}

/*
 * add_bitmap_entry - Add a bitmap entry to the chain of bitmap
 * entries we are creating for cd's entry in the state file.
 *
 * Bitmaps are stored in a chain of anonymous cache blocks. Each
 * cache block can hold bmaps_per_block in it. As each block is
 * filled a new block is added to the tail of the chain.
 *
 * list - the chain of cache blocks containing the bitmaps.
 * bits - the bitmap entry to add.
 * any_fail - flag saying whether the data corresponding to this
 * bitmap entry had previously failed going to disk.
 * fba_num - FBA number corresponding to the entry.
 *
 * returns - 0 on success, error number on failure.
 */
static int
add_bitmap_entry(struct bitmap *bmp,
    _sd_bitmap_t bits, int any_fail, nsc_off_t fba_num)
{
	sdbc_pwf_bitmap_t *bmap;
	_sd_cctl_t *list = bmp->bmps;
	int i;

	bmap = (sdbc_pwf_bitmap_t *)list->bitmap_tail->cc_data;
	if (bmp->inuse == bmp->bmaps_per_block) {
		_sd_cctl_t *nlist;

		nlist = sdbc_centry_alloc_blks(_CD_NOHASH, 0, 1, 0);
		bzero(nlist->cc_data, CACHE_BLOCK_SIZE);
		nlist->bitmap_next = NULL;
		nlist->bitmap_tail = NULL;
		list->bitmap_tail->bitmap_next = nlist;
		list->bitmap_tail = nlist;
		bmp->inuse = 0;
	}
	i = bmp->inuse++;
	bmap->bitmaps[i].fba_num = fba_num;
	bmap->bitmaps[i].dirty = bits;
	bmap->bitmaps[i].errs = (char)any_fail;

	return (0);
}

/*
 * flush_bitmap_list - flush a chain of anonymous cache blocks
 * containing the dirty/valid bitmaps for a set of cache blocks.
 *
 * b_list - the chain of bitmap data.
 * dev - the state file device.
 * blkno - on input the cache block number to begin writing at.
 * On exit the next cache block number following the data
 * just written.
 *
 * returns - 0 on success, error number on failure.
 */
static int
flush_bitmap_list(struct bitmap *bmp, dev_t dev, nsc_off_t *blkno)
{
	_sd_cctl_t *b_list;
	struct buf *bp;
	int rc;
	_sd_cctl_t *prev;
	int bcnt = 0;	/* P3 temp */

	if ((b_list = bmp->bmps) == NULL)
		return (0);

	do {
		bp = sd_alloc_iob(dev, BLK_TO_FBA_NUM(*blkno),
		    BLK_TO_FBA_NUM(1), 0);
		sd_add_fba(bp, &b_list->cc_addr, 0, BLK_FBAS);
		rc = sd_start_io(bp, NULL, NULL, 0);
		(*blkno)++;

		/*
		 * A failure here is death. This is harsh but not sure
		 * what else to do
		 */

		if (rc != NSC_DONE)
			return (rc);
		bcnt++;

		prev = b_list;
		b_list = b_list->bitmap_next;
		_sd_centry_release(prev);

	} while (b_list);
	cmn_err(CE_CONT, "sdbc(flush_bitmap_list) %d\n", bcnt);  /* P3 */

	return (0);

}

/*
 * flush_centry_list - flush a chain of cache blocks for the
 * cache descriptor described by "cdi" to the state file.
 * In addition the bitmaps describing the validity and dirty
 * state of each entry are captured to the bitmap chain.
 *
 * cdi - pointer to description of the cd we are writing.
 * dirty - chain of dirty cache blocks to flush (linked
 * by dirty_next (sequential) and dirty_link (disjoint).
 *
 * dev - the state file device.
 *
 * blkno - on input the cache block number to begin writing at.
 * On exit the next cache block number following the data
 * just written.
 *
 * failed - a flag noting whether these blocks had already
 * been attempted to write to their true destination and
 * failed. (i.e. is the chain from fail_head).
 *
 * bmaps - a chain of anonymous cache blocks containing all
 * the dirty/valid bitmaps for the cache blocks we write.
 *
 * returns - 0 on success, error number on failure.
 */
static int
flush_centry_list(_sd_cd_info_t *cdi,
		_sd_cctl_t *dirty,
		dev_t dev,
		nsc_off_t *blkno,
		int failed,
		struct bitmap *bmaps)
{
	_sd_cctl_t *cc_ent;
	nsc_size_t count; /* count of cache blocks in a sequential chain */
	struct buf *bp;
	int rc;
	int bcnt = 0;

	if (dirty == NULL)
		return (0);

	mutex_enter(&cdi->cd_lock);

	do {
		/*
		 * each cache block is written to the disk regardless of its
		 * valid/dirty masks.
		 */
		count = 0;
		cc_ent = dirty;
		do {
			count++;
			cc_ent = cc_ent->cc_dirty_next;
		} while (cc_ent);

		bp = sd_alloc_iob(dev, BLK_TO_FBA_NUM(*blkno),
		    BLK_TO_FBA_NUM(count), 0);

		cc_ent = dirty;
		do {
			sd_add_fba(bp, &cc_ent->cc_addr, 0, BLK_FBAS);
			rc = add_bitmap_entry(bmaps,
			    cc_ent->cc_dirty | cc_ent->cc_toflush, failed,
			    BLK_TO_FBA_NUM(CENTRY_BLK(cc_ent)));
			if (rc)
				return (rc);
			cc_ent = cc_ent->cc_dirty_next;
		} while (cc_ent);

		*blkno += count;
		rc = sd_start_io(bp, NULL, NULL, 0);

		/*
		 * A failure here is death. This is harsh but not sure
		 * what else to do
		 */

		if (rc != NSC_DONE)
			return (rc);
		bcnt += count;

		dirty = dirty->cc_dirty_link;
	} while (dirty);
	cmn_err(CE_CONT, "sdbc(flush_centry_list) %d\n", bcnt);  /* P3 */

	mutex_exit(&cdi->cd_lock);
	return (0);
}

/*
 * flush_hdr - Flush the state file header to the disk partition
 * "dev" at FBA "blkno". Return the result of the i/o operation.
 * hdr - a cache block containing the header.
 * dev - the state file device.
 * blkno -  cache block position to write the header.
 *
 * returns - 0 on success, error number on failure.
 */
static int
flush_hdr(_sd_cctl_t *hdr, dev_t dev, nsc_off_t blkno)
{
	struct buf *bp;
	int rc;

	bp = sd_alloc_iob(dev, BLK_TO_FBA_NUM(blkno), BLK_TO_FBA_NUM(1), 0);
	sd_add_fba(bp, &hdr->cc_addr, 0, BLK_FBAS);
	rc = sd_start_io(bp, NULL, NULL, 0);
	_sd_centry_release(hdr);
	return (rc);

}

/*
 * _sdbc_power_flush - flushd the state of sdbc to the state "file"
 * on the system disk. All dirty blocks (in progress, unscheduled,
 * failed) are written along with the bitmap for each block. The
 * data is written using normal sdbc i/o via anonymous cache blocks.
 * This is done to simplify the job here (and to limit memory
 * requests) at the expense of making the recovery programs more
 * complex. Since recovery is done at user level this seems to be
 * a good trade off.
 *
 * Returns: 0 on success, error number on failure.
 */
static int
_sdbc_power_flush(void)
{
	_sd_cctl_t *name_pool;
	int string_size;

	sdbc_pwf_hdr_t *hdr;
	_sd_cctl_t *hdrblk;

	struct bitmap bmap;

	_sd_cd_info_t *cdi;
	int open_files;
	_sd_cctl_t *file_pool;
	sdbc_pwf_desc_t current;

	nsc_fd_t *state_fd;
	dev_t state_rdev;
	int devmaj, devmin;
	nsc_off_t blkno;
	long len;
	long total_len;
	int pending;
	int rc = 0;

	/*
	 * Force wrthru just in case SLM software didn't really send us a
	 * warning. (Also makes for easier testing)
	 */
	(void) _sd_set_node_hint(NSC_FORCED_WRTHRU);
	/* disable all (dangerous) cache entry points */

	cmn_err(CE_CONT, "sdbc(sdbc_power_flush) hint set..\n"); /* P3 */

	_sdbc_shutdown_in_progress = 1;

#if 0
	if (sdbc_io && (rc = nsc_unregister_io(sdbc_io, NSC_PCATCH)) != 0) {
		/*
		 * this is bad, in theory we could just busy-out all our
		 * interfaces and continue.
		 */
		cmn_err(CE_WARN,
		    "sdbc(_sdbc_power_flush) couldn't unregister i/o %d", rc);
		return (rc);
	}

	sdbc_io = NULL;
#endif

	/* wait for all i/o to finish/timeout ? */

	if ((pending = _sdbc_wait_pending()) != 0)
		cmn_err(CE_NOTE, "sdbc(_sdbc_power_flush) %d I/Os were"
		    " pending at power shutdown", pending);

	cmn_err(CE_CONT, "sdbc(sdbc_power_flush) over pending\n"); /* P3 */

	/* prevent any further async flushing */

	_sdbc_flush_deconfigure();

	/*
	 * At this point no higher level clients should be able to get thru.
	 * Failover i/o from the other node is our only other concern as
	 * far as disturbing the state of sdbc.
	 */

	/* figure out the names for the string pool */

	string_size = 0;
	open_files = 0;
	cdi = _sd_cache_files;
	do {

		if (cdi->cd_info == NULL)
			continue;
		if (cdi->cd_info->sh_alloc == 0)
			continue;
		open_files++;
		string_size += strlen(cdi->cd_info->sh_filename) + 1;
	} while (++cdi != &_sd_cache_files[sdbc_max_devs]);

	if (open_files == 0) {
		return (0);
	}

	hdrblk = sdbc_centry_alloc_blks(_CD_NOHASH, 0, 1, 0);
	bzero(hdrblk->cc_data, CACHE_BLOCK_SIZE);
	hdr = (sdbc_pwf_hdr_t *)hdrblk->cc_data;
	hdr->magic = SDBC_PWF_MAGIC;
	hdr->alignment = CACHE_BLOCK_SIZE;
	hdr->cd_count = open_files;
	/* XXX bmap_size is redundant */
	hdr->bmap_size = CACHE_BLOCK_SIZE / sizeof (sdbc_pwf_bitmap_t);

	name_pool = sdbc_get_anon_list(string_size);
	file_pool = sdbc_get_anon_list(sizeof (sdbc_pwf_desc_t) * open_files);

	open_files = 0;
	cdi = _sd_cache_files;
	total_len = 0;
	do {

		if (cdi->cd_info == NULL)
			continue;
		if (cdi->cd_info->sh_alloc == 0)
			continue;

		len = strlen(cdi->cd_info->sh_filename) + 1;

		/* copy the name to string pool */
		sdbc_anon_copy(cdi->cd_info->sh_filename,
		    len, name_pool, total_len);

		bzero(&current, sizeof (current));
		current.name = total_len;
		sdbc_anon_copy((caddr_t)&current, sizeof (current), file_pool,
		    open_files * sizeof (sdbc_pwf_desc_t));

		open_files++;
		total_len += len;

	} while (++cdi != &_sd_cache_files[sdbc_max_devs]);

	/* flush dirty data */

	if (swfs.nswpf == 0 || swfs.names[0] == NULL) {
		cmn_err(CE_WARN, "sdbc(_sdbc_power_flush): State file"
		    " is not configured");
		rc = ENODEV;
		goto cleanup;
	}

	if (!(state_fd =
	    nsc_open(swfs.names[0], NSC_DEVICE, NULL, NULL, &rc)) ||
	    !nsc_getval(state_fd, "DevMaj", (int *)&devmaj) ||
	    !nsc_getval(state_fd, "DevMin", (int *)&devmin)) {
		if (state_fd) {
			(void) nsc_close(state_fd);
		}
		/*
		 * We are hosed big time. We can't get device to write the
		 * state file opened.
		 */
		cmn_err(CE_WARN, "sdbc(_sdbc_power_flush): Couldn't "
		    "open %s for saved state file", swfs.names[0]);
		rc = EIO;
		goto cleanup;
	}

	state_rdev = makedevice(devmaj, devmin);

	blkno = 1;

	hdr->string_pool = blkno;
	rc = flush_anon_list(name_pool, state_rdev, &blkno);

	hdr->descriptor_pool = blkno;
	rc = flush_anon_list(file_pool, state_rdev, &blkno);

	/*
	 * iterate across all devices, flushing the data and collecting bitmaps
	 */

	open_files = 0;
	for (cdi = _sd_cache_files;
	    cdi != &_sd_cache_files[sdbc_max_devs]; cdi++) {
		nsc_off_t blk2;
		nsc_off_t fp_off;

		if (cdi->cd_info == NULL)
			continue;
		if (cdi->cd_info->sh_alloc == 0)
			continue;

		/* retrieve the file description so we can update it */
		fp_off = (open_files++) * sizeof (sdbc_pwf_desc_t);
		sdbc_anon_get(file_pool, fp_off,
		    (caddr_t)&current, sizeof (current));

		current.blocks = blkno;

		if (cdi->cd_io_head) {
			/*
			 * Need to wait for this to timeout?
			 * Seems like worst case we just write the data twice
			 * so we should be ok.
			 */
			/*EMPTY*/
			;
		}

		start_bitmap_list(&bmap, hdr->bmap_size);

		/* Flush the enqueued dirty data blocks */

		(void) flush_centry_list(cdi, cdi->cd_dirty_head, state_rdev,
		    &blkno, 0, &bmap);
		cdi->cd_dirty_head = NULL;
		cdi->cd_dirty_tail = NULL;

		/* Flush the failed dirty data blocks */

		(void) flush_centry_list(cdi, cdi->cd_fail_head, state_rdev,
		    &blkno, 1, &bmap);
		cdi->cd_fail_head = NULL;

		/*
		 * Flush the in progress dirty data blocks. These really should
		 * really be null by now. Worst case we write the data again
		 * on recovery as we know the dirty masks won't change since
		 * flusher is stopped.
		 */

		(void) flush_centry_list(cdi, cdi->cd_io_head, state_rdev,
		    &blkno, 0, &bmap);
		cdi->cd_io_head = NULL;
		cdi->cd_io_tail = NULL;

		current.bitmaps = blkno;
		current.nblocks = blkno - current.blocks;

		(void) flush_bitmap_list(&bmap, state_rdev, &blkno);

		/* update the current cd's file description */
		sdbc_anon_copy((caddr_t)&current, sizeof (current), file_pool,
		    fp_off);

		blk2 = hdr->descriptor_pool;
		rc = flush_anon_list(file_pool, state_rdev, &blk2);
	}

#if !defined(_SunOS_5_6)
	hdr->dump_time = ddi_get_time();
#else
	hdr->dump_time = hrestime.tv_sec;
#endif
	/* write the header at front and back */
	(void) flush_hdr(hdrblk, state_rdev, blkno);
	(void) flush_hdr(hdrblk, state_rdev, 0L);

	/* P3 */
	cmn_err(CE_CONT, "sdbc(sdbc_power_flush) %" NSC_SZFMT " total\n",
	    blkno);

cleanup:
	;
	return (rc);

}

/*
 * _sdbc_power_lost - System is running on UPS power we have "rideout"
 * minutes of power left prior to shutdown. Get into a state where we
 * will be ready should we need to shutdown.
 *
 * ARGUMENTS:
 *	rideout - minutes of power left prior to shutdown.
 */
void
_sdbc_power_lost(int rideout)
{
	cmn_err(CE_WARN, "sdbc(_sdbc_power_lost) battery time "
	    "remaining %d minute(s)", rideout);

	got_hint = 1;
	if (_sd_get_node_hint(&wrthru_hint))
		got_hint = 0;

	cmn_err(CE_WARN, "sdbc(_sdbc_power_lost) got hint %d "
		"hint 0x%x", got_hint, wrthru_hint);

	(void) _sd_set_node_hint(NSC_FORCED_WRTHRU);
	saw_power_lost = 1;
}

/*
 * _sdbc_power_ok - System is back running on mains power after
 * seeing a power fail. Return to normal power up operation.
 *
 */
void
_sdbc_power_ok(void)
{
	cmn_err(CE_WARN, "sdbc(_sdbc_power_ok) power ok");
	if (saw_power_lost && got_hint) {
		/*
		 * In theory we have a race here between _sdbc_power_lost
		 * and here. However it is expected that power ioctls that
		 * cause these to be generated are sequential in nature
		 * so there is no race.
		 */
		saw_power_lost = 0;
		if (wrthru_hint & _SD_WRTHRU_MASK)
			(void) _sd_set_node_hint(wrthru_hint & _SD_WRTHRU_MASK);
		else
			(void) _sd_clear_node_hint(_SD_WRTHRU_MASK);
	}
}

/*
 * _sdbc_power_down - System is running on UPS power and we must stop
 * operation as the machine is now going down. Schedule a shutdown
 * thread.
 *
 * When we return all cache activity will be blocked.
 */
void
_sdbc_power_down(void)
{
	cmn_err(CE_WARN, "sdbc(_sdbc_power_down) powering down...");
	(void) _sdbc_power_flush();
}

/*
 * Configure safe store from the general cache configuration ioctl.
 */
int
_sdbc_pcu_config(int namec, char **namev)
{
	int i;

	if (swfs.nswpf != 0) {
		/*
		 * This should not happen because cache protects itself
		 * from double configuration in sd_conf.c.
		 */
		cmn_err(CE_CONT, "sdbc(_sdbc_pcu_config) double "
		    "configuration of Safe Store\n");
		return (EINVAL);
	}
	swfs.colsize = 32;	/* No way to configure in the general ioctl */

	for (i = 0; i < namec; i++) {
		if ((swfs.names[i] = kmem_alloc(strlen(namev[i])+1,
		    KM_NOSLEEP)) == NULL) {
			_sdbc_pcu_cleanup(&swfs);
			return (ENOMEM);
		}
		swfs.nswpf++;
		(void) strcpy(swfs.names[i], namev[i]);
	}

	return (0);
}

/*
 */
void
_sdbc_pcu_unload()
{
	_sdbc_pcu_cleanup(&swfs);
}

/*
 * Destructor for struct swapfiles.
 */
static void
_sdbc_pcu_cleanup(struct swapfiles *swp)
{
	int i;
	char *s;

	for (i = 0; i < swp->nswpf; i++) {
		if ((s = swp->names[i]) != NULL)
			kmem_free(s, strlen(s)+1);
		swp->names[i] = NULL;
	}
	swp->nswpf = 0;
}
