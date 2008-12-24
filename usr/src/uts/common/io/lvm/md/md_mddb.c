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
#include <sys/conf.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/systeminfo.h>
#include <sys/sysmacros.h>
#include <sys/buf.h>
#include <sys/kmem.h>
#include <sys/file.h>
#include <sys/open.h>
#include <sys/debug.h>
#include <sys/stat.h>
#include <sys/lvm/mdvar.h>
#include <sys/lvm/md_crc.h>
#include <sys/lvm/md_convert.h>
#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/lvm/mdmn_commd.h>
#include <sys/cladm.h>

mhd_mhiargs_t	defmhiargs = {
	1000,
	{ 6000, 6000, 30000 }
};

#define	MDDB

#include <sys/lvm/mdvar.h>
#include <sys/lvm/mdmed.h>
#include <sys/lvm/md_names.h>
#include <sys/cred.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/esunddi.h>

#include <sys/sysevent/eventdefs.h>
#include <sys/sysevent/svm.h>

extern char svm_bootpath[];

int			md_maxbootlist = MAXBOOTLIST;
static ulong_t		mddb_maxblocks = 0;	/* tune for small records */
static int		mddb_maxbufheaders = 50;
static uint_t		mddb_maxcopies = MDDB_NLB;

/*
 * If this is set, more detailed messages about DB init will be given, instead
 * of just the MDE_DB_NODB.
 */
static int		mddb_db_err_detail = 0;

/*
 * This lock is used to single-thread load/unload of all sets
 */
static kmutex_t		mddb_lock;

/*
 * You really do NOT want to change this boolean.
 * It can be VERY dangerous to do so.  Loss of
 * data may occur. USE AT YOUR OWN RISK!!!!
 */
static int		mddb_allow_half = 0;
/*
 * For mirrored root allow reboot with only half the replicas available
 * Flag inserted for Santa Fe project.
 */
int mirrored_root_flag;

#define	ISWHITE(c)	(((c) == ' ') || ((c) == '\t') || \
			    ((c) == '\r') || ((c) == '\n'))
#define	ISNUM(c)	(((c) >= '0') && ((c) <= '9'))

#define	SETMUTEX(setno)	(&md_set[setno].s_dbmx)

extern md_krwlock_t	md_unit_array_rw;	/* md.c */
extern set_t		md_nsets;		/* md.c */
extern int		md_nmedh;		/* md.c */
extern md_set_t		md_set[];		/* md.c */
extern int		(*mdv_strategy_tstpnt)(buf_t *, int, void*);
extern dev_info_t	*md_devinfo;
extern int		md_init_debug;
extern int		md_status;
extern md_ops_t		*md_opslist;
extern md_krwlock_t	nm_lock;

static int 		update_locatorblock(mddb_set_t *s, md_dev64_t dev,
				ddi_devid_t didptr, ddi_devid_t old_didptr);

/*
 * Defines for crc calculation for records
 * rec_crcgen generates a crc checksum for a record block
 * rec_crcchk checks the crc checksum for a record block
 */
#define	REC_CRCGEN	0
#define	REC_CRCCHK	1
#define	rec_crcgen(s, dep, rbp) \
	(void) rec_crcfunc(s, dep, rbp, REC_CRCGEN)
#define	rec_crcchk(s, dep, rbp) \
	rec_crcfunc(s, dep, rbp, REC_CRCCHK)

/*
 * During upgrade, SVM basically runs with the devt from the target
 * being upgraded.  Translations are made from the target devt to the
 * miniroot devt when writing data out to the disk.  This is done by
 * the following routines:
 *	wrtblklst
 *	writeblks
 *	readblklst
 *	readblks
 *	dt_read
 *
 * The following routines are used by the routines listed above and
 * expect a translated (aka miniroot) devt:
 *	getblks
 * 	getmasters
 *
 * Also, when calling any system routines, such as ddi_lyr_get_devid,
 * the translated (aka miniroot) devt must be used.
 *
 * By the same token, the major number and major name conversion operations
 * need to use the name_to_major file from the target system instead
 * of the name_to_major file on the miniroot.  So, calls to
 * ddi_name_to_major must be replaced with calls to md_targ_name_to_major
 * when running on an upgrade.  Same is true with calls to
 * ddi_major_to_name.
 */


#ifndef MDDB_FAKE

static int
mddb_rwdata(
	mddb_set_t	*s,	/* incore db set structure */
	int		flag,	/* B_ASYNC, B_FAILFAST or 0 passed in here */
	buf_t		*bp
)
{
	int		err = 0;

	bp->b_flags = (flag | B_BUSY) & (~B_ASYNC);

	mutex_exit(SETMUTEX(s->s_setno));
	if (mdv_strategy_tstpnt == NULL ||
	    (*mdv_strategy_tstpnt)(bp, 0, NULL) == 0)
		(void) bdev_strategy(bp);

	if (flag & B_ASYNC) {
		mutex_enter(SETMUTEX(s->s_setno));
		return (0);
	}

	err = biowait(bp);
	mutex_enter(SETMUTEX(s->s_setno));
	return (err);
}

static void
setidentifier(
	mddb_set_t	*s,
	identifier_t	*ident
)
{
	if (s->s_setno == MD_LOCAL_SET)
		(void) strcpy(&ident->serial[0], s->s_ident.serial);
	else
		ident->createtime = s->s_ident.createtime;
}

static int
cmpidentifier(
	mddb_set_t	*s,
	identifier_t	*ident
)
{
	if (s->s_setno == MD_LOCAL_SET)
		return (strcmp(ident->serial, s->s_ident.serial));
	else
		return (timercmp(&ident->createtime,
		    /*CSTYLED*/
		    &s->s_ident.createtime, !=));
}

static int
mddb_devopen(
	md_dev64_t	dev
)
{
	dev_t		ddi_dev = md_dev64_to_dev(dev);

	if (dev_lopen(&ddi_dev, FREAD|FWRITE, OTYP_LYR, kcred) == 0)
		return (0);
	return (1);
}

static void
mddb_devclose(
	md_dev64_t	dev
)
{
	(void) dev_lclose(md_dev64_to_dev(dev), FREAD|FWRITE, OTYP_LYR, kcred);
}

/*
 * stripe_skip_ts
 *
 * Returns a list of fields to be skipped in the stripe record structure.
 * These fields are ms_timestamp in the component structure.
 * Used to skip these fields when calculating the checksum.
 */
static crc_skip_t *
stripe_skip_ts(void *un, uint_t revision)
{
	struct ms_row32_od	*small_mdr;
	struct ms_row		*big_mdr;
	uint_t			row, comp, ncomps, compoff;
	crc_skip_t		*skip;
	crc_skip_t		*skip_prev;
	crc_skip_t		skip_start = {0, 0, 0};
	ms_unit_t		*big_un;
	ms_unit32_od_t		*small_un;
	uint_t			rb_off = offsetof(mddb_rb32_t, rb_data[0]);

	switch (revision) {
	case MDDB_REV_RB:
	case MDDB_REV_RBFN:
		small_un = (ms_unit32_od_t *)un;
		skip_prev = &skip_start;

		if (small_un->un_nrows == 0)
			return (NULL);
		/*
		 * walk through all rows to find the total number
		 * of components
		 */
		small_mdr   = &small_un->un_row[0];
		ncomps = 0;
		for (row = 0; (row < small_un->un_nrows); row++) {
			ncomps += small_mdr[row].un_ncomp;
		}

		/* Now walk through the components */
		compoff = small_un->un_ocomp + rb_off;
		for (comp = 0; (comp < ncomps); ++comp) {
			uint_t	mdcp = compoff +
			    (comp * sizeof (ms_comp32_od_t));
			skip = (crc_skip_t *)kmem_zalloc(sizeof (crc_skip_t),
			    KM_SLEEP);
			skip->skip_offset = mdcp +
			    offsetof(ms_comp32_od_t, un_mirror.ms_timestamp);
			skip->skip_size = sizeof (md_timeval32_t);
			skip_prev->skip_next = skip;
			skip_prev = skip;
		}
		break;
	case MDDB_REV_RB64:
	case MDDB_REV_RB64FN:
		big_un = (ms_unit_t *)un;
		skip_prev = &skip_start;

		if (big_un->un_nrows == 0)
			return (NULL);
		/*
		 * walk through all rows to find the total number
		 * of components
		 */
		big_mdr   = &big_un->un_row[0];
		ncomps = 0;
		for (row = 0; (row < big_un->un_nrows); row++) {
			ncomps += big_mdr[row].un_ncomp;
		}

		/* Now walk through the components */
		compoff = big_un->un_ocomp + rb_off;
		for (comp = 0; (comp < ncomps); ++comp) {
			uint_t	mdcp = compoff +
			    (comp * sizeof (ms_comp_t));
			skip = (crc_skip_t *)kmem_zalloc(sizeof (crc_skip_t),
			    KM_SLEEP);
			skip->skip_offset = mdcp +
			    offsetof(ms_comp_t, un_mirror.ms_timestamp);
			skip->skip_size = sizeof (md_timeval32_t);
			skip_prev->skip_next = skip;
			skip_prev = skip;
		}
		break;
	}
	/* Return the start of the list of fields to skip */
	return (skip_start.skip_next);
}

/*
 * mirror_skip_ts
 *
 * Returns a list of fields to be skipped in the mirror record structure.
 * This includes un_last_read and sm_timestamp for each submirror
 * Used to skip these fields when calculating the checksum.
 */
static crc_skip_t *
mirror_skip_ts(uint_t revision)
{
	int		i;
	crc_skip_t	*skip;
	crc_skip_t	*skip_prev;
	crc_skip_t	skip_start = {0, 0, 0};
	uint_t		rb_off = offsetof(mddb_rb32_t, rb_data[0]);

	skip_prev = &skip_start;

	skip = (crc_skip_t *)kmem_zalloc(sizeof (crc_skip_t), KM_SLEEP);
	switch (revision) {
	case MDDB_REV_RB:
	case MDDB_REV_RBFN:
		skip->skip_offset = offsetof(mm_unit32_od_t,
		    un_last_read) + rb_off;
		break;
	case MDDB_REV_RB64:
	case MDDB_REV_RB64FN:
		skip->skip_offset = offsetof(mm_unit_t,
		    un_last_read) + rb_off;
		break;
	}
	skip->skip_size = sizeof (int);
	skip_prev->skip_next = skip;
	skip_prev = skip;

	for (i = 0; i < NMIRROR; i++) {
		skip = (crc_skip_t *)kmem_zalloc(sizeof (crc_skip_t), KM_SLEEP);
		switch (revision) {
		case MDDB_REV_RB:
		case MDDB_REV_RBFN:
			skip->skip_offset = offsetof(mm_unit32_od_t,
			    un_sm[i].sm_timestamp) + rb_off;
			break;
		case MDDB_REV_RB64:
		case MDDB_REV_RB64FN:
			skip->skip_offset = offsetof(mm_unit_t,
			    un_sm[i].sm_timestamp) + rb_off;
			break;
		}
		skip->skip_size = sizeof (md_timeval32_t);
		skip_prev->skip_next = skip;
		skip_prev = skip;
	}
	/* Return the start of the list of fields to skip */
	return (skip_start.skip_next);
}

/*
 * hotspare_skip_ts
 *
 * Returns a list of the timestamp fields in the hotspare record structure.
 * Used to skip these fields when calculating the checksum.
 */
static crc_skip_t *
hotspare_skip_ts(uint_t revision)
{
	crc_skip_t	*skip;
	uint_t		rb_off = offsetof(mddb_rb32_t, rb_data[0]);

	skip = (crc_skip_t *)kmem_zalloc(sizeof (crc_skip_t), KM_SLEEP);
	switch (revision) {
	case MDDB_REV_RB:
	case MDDB_REV_RBFN:
		skip->skip_offset = offsetof(hot_spare32_od_t, hs_timestamp) +
		    rb_off;
		break;
	case MDDB_REV_RB64:
	case MDDB_REV_RB64FN:
		skip->skip_offset = offsetof(hot_spare_t, hs_timestamp) +
		    rb_off;
		break;
	}
	skip->skip_size = sizeof (md_timeval32_t);
	return (skip);
}

/*
 * rec_crcfunc
 *
 * Calculate or check the checksum for a record
 * Calculate the crc if check == 0, Check the crc if check == 1
 *
 * Record block may be written by different nodes in a multi-owner diskset
 * (in case of master change), the function rec_crcchk excludes timestamp
 * fields in crc computation of record data.
 * Otherwise, timestamp fields will cause each node to have a different
 * checksum for same record block causing the exclusive-or of all record block
 * checksums and data block record sums to be non-zero after new master writes
 * at least one record block.
 */
static uint_t
rec_crcfunc(
	mddb_set_t	*s,
	mddb_de_ic_t	*dep,
	mddb_rb32_t	*rbp,
	int		check
)
{
	crc_skip_t	*skip;
	crc_skip_t	*skip_tail;
	mddb_type_t	type = dep->de_type1;
	uint_t		ret;

	/*
	 * Generate a list of the areas to be skipped when calculating
	 * the checksum.
	 * First skip rb_checksum, rb_private and rb_userdata.
	 */
	skip = (crc_skip_t *)kmem_zalloc(sizeof (crc_skip_t), KM_SLEEP);
	skip->skip_offset = offsetof(mddb_rb32_t, rb_checksum_fiddle);
	skip->skip_size = 3 * sizeof (uint_t);
	skip_tail = skip;
	if (MD_MNSET_SETNO(s->s_setno)) {
		/* For a MN set, skip rb_timestamp */
		skip_tail = (crc_skip_t *)kmem_zalloc(sizeof (crc_skip_t),
		    KM_SLEEP);
		skip_tail->skip_offset = offsetof(mddb_rb32_t, rb_timestamp);
		skip_tail->skip_size = sizeof (md_timeval32_t);
		skip->skip_next = skip_tail;

		/* Now add a list of timestamps to be skipped */
		if (type >= MDDB_FIRST_MODID) {
			switch (dep->de_flags) {
				case MDDB_F_STRIPE:
					skip_tail->skip_next =
					    stripe_skip_ts((void *)rbp->rb_data,
					    rbp->rb_revision);
					break;
				case MDDB_F_MIRROR:
					skip_tail->skip_next =
					    mirror_skip_ts(rbp->rb_revision);
					break;
				case MDDB_F_HOTSPARE:
					skip_tail->skip_next =
					    hotspare_skip_ts(rbp->rb_revision);
					break;
				default:
					break;
			}
		}
	}

	if (check) {
		ret = crcchk(rbp, &rbp->rb_checksum, dep->de_recsize, skip);
	} else {
		crcgen(rbp, &rbp->rb_checksum, dep->de_recsize, skip);
		ret = rbp->rb_checksum;
	}
	while (skip) {
		crc_skip_t	*skip_save = skip;

		skip = skip->skip_next;
		kmem_free(skip_save, sizeof (crc_skip_t));
	}
	return (ret);
}

static mddb_bf_t *
allocbuffer(
	mddb_set_t	*s,
	int		sleepflag
)
{
	mddb_bf_t	*bfp;

	while ((bfp = s->s_freebufhead) == NULL) {
		if (sleepflag == MDDB_NOSLEEP)
			return ((mddb_bf_t *)NULL);
		++s->s_bufmisses;
#ifdef	DEBUG
		if (s->s_bufmisses == 1)
			cmn_err(CE_NOTE,
			    "md: mddb: set %u sleeping for buffer", s->s_setno);
#endif
		s->s_bufwakeup = 1;
		cv_wait(&s->s_buf_cv, SETMUTEX(s->s_setno));
	}
	s->s_freebufhead = bfp->bf_next;
	bzero((caddr_t)bfp, sizeof (*bfp));
	bfp->bf_buf.b_back = bfp->bf_buf.b_forw = &bfp->bf_buf;
	bfp->bf_buf.b_flags = B_BUSY;	/* initialize flags */
	return (bfp);
}

static void
freebuffer(
	mddb_set_t		*s,
	mddb_bf_t	*bfp
)
{
	bfp->bf_next = s->s_freebufhead;
	s->s_freebufhead = bfp;
	if (s->s_bufwakeup) {
		cv_broadcast(&s->s_buf_cv);
		s->s_bufwakeup = 0;
	}
}


static void
blkbusy(
	mddb_set_t	*s,
	mddb_block_t	blk
)
{
	int		bit, byte;

	s->s_freeblkcnt--;
	byte = blk / 8;
	bit = 1 << (blk & 7);
	ASSERT(! (s->s_freebitmap[byte] & bit));
	s->s_freebitmap[byte] |= bit;
}

static void
blkfree(
	mddb_set_t	*s,
	mddb_block_t	blk
)
{
	int		bit, byte;

	s->s_freeblkcnt++;
	byte = blk / 8;
	bit = 1 << (blk & 7);
	ASSERT(s->s_freebitmap[byte] & bit);
	s->s_freebitmap[byte] &= ~bit;
}

static int
blkcheck(
	mddb_set_t	*s,
	mddb_block_t	blk
)
{
	int		bit, byte;

	byte = blk / 8;
	bit = 1 << (blk & 7);
	return (s->s_freebitmap[byte] & bit);
}

/*
 * not fast but simple
 */
static mddb_block_t
getfreeblks(
	mddb_set_t	*s,
	size_t		count
)
{
	int		i;
	size_t		contig;

	contig = 0;
	for (i = 0; i < s->s_totalblkcnt; i++) {
		if (blkcheck(s, i)) {
			contig = 0;
		} else {
			contig++;
			if (contig == count) {
				contig = i - count + 1;
				for (i = (int)contig; i < contig + count; i++)
					blkbusy(s, i);
				return ((mddb_block_t)contig);
			}
		}
	}
	return (0);
}

static void
computefreeblks(
	mddb_set_t	*s
)
{
	mddb_db_t	*dbp;
	mddb_de_ic_t	*dep;
	int		i;
	int		minblks;
	int		freeblks;
	mddb_mb_ic_t	*mbip;
	mddb_lb_t	*lbp;
	mddb_block_t	maxblk;
	mddb_did_db_t	*did_dbp;
	int		nblks;

	minblks = 0;
	lbp = s->s_lbp;
	maxblk = 0;

	/*
	 * Determine the max number of blocks.
	 */
	nblks = (lbp->lb_flags & MDDB_MNSET) ? MDDB_MN_MAXBLKS : MDDB_MAXBLKS;
	/*
	 * go through and find highest logical block
	 */
	for (dbp = s->s_dbp; dbp != 0;	dbp = dbp->db_next) {
		if (dbp->db_blknum > maxblk)
			maxblk = dbp->db_blknum;
		for (dep = dbp->db_firstentry; dep != 0; dep = dep->de_next)
			for (i = 0; i < dep->de_blkcount; i++)
				if (dep->de_blks[i] > maxblk)
					maxblk = dep->de_blks[i];
	}

	for (i = 0; i < lbp->lb_loccnt; i++) {
		mddb_locator_t	*lp = &lbp->lb_locators[i];

		if ((lp->l_flags & MDDB_F_DELETED) ||
		    (lp->l_flags & MDDB_F_EMASTER))
			continue;

		freeblks = 0;
		for (mbip = s->s_mbiarray[i]; mbip != NULL;
		    mbip = mbip->mbi_next) {
			freeblks += mbip->mbi_mddb_mb.mb_blkcnt;
		}
		if (freeblks == 0)	/* this happen when there is no */
			continue;	/*	master blk		*/

		if (freeblks <= maxblk) {
			lp->l_flags |= MDDB_F_TOOSMALL;
			lp->l_flags &= ~MDDB_F_ACTIVE;
		}

		if (freeblks < minblks || minblks == 0)
			minblks = freeblks;
	}
	/*
	 * set up reasonable freespace if no
	 * data bases exist
	 */
	if (minblks == 0)
		minblks = 100;
	if (minblks > nblks)
		minblks = nblks;
	s->s_freeblkcnt = minblks;
	s->s_totalblkcnt = minblks;
	if (! s->s_freebitmapsize) {
		s->s_freebitmapsize = nblks / 8;
		s->s_freebitmap = (uchar_t *)kmem_zalloc(s->s_freebitmapsize,
		    KM_SLEEP);
	}
	bzero((caddr_t)s->s_freebitmap, s->s_freebitmapsize);

	/* locator block sectors */
	for (i = 0; i < s->s_lbp->lb_blkcnt; i++)
		blkbusy(s, i);

	/* locator name sectors */
	for (i = 0; i < s->s_lbp->lb_lnblkcnt; i++)
		blkbusy(s, (s->s_lbp->lb_lnfirstblk + i));

	if (lbp->lb_flags & MDDB_DEVID_STYLE) {
		/* locator block device id information */
		for (i = 0; i < s->s_lbp->lb_didblkcnt; i++)
			blkbusy(s, (s->s_lbp->lb_didfirstblk + i));

		/* disk blocks containing actual device ids */
		did_dbp = s->s_did_icp->did_ic_dbp;
		while (did_dbp) {
			for (i = 0; i < did_dbp->db_blkcnt; i++) {
				blkbusy(s, did_dbp->db_firstblk + i);
			}
			did_dbp = did_dbp->db_next;
		}
	}

	/* Only use data tags if not a MN set */
	if (!(lbp->lb_flags & MDDB_MNSET)) {
		/* Found a bad tag, do NOT mark the data tag blks busy here */
		if (! (md_get_setstatus(s->s_setno) & MD_SET_BADTAG)) {
			for (i = 0; i < s->s_lbp->lb_dtblkcnt; i++)
				blkbusy(s, (s->s_lbp->lb_dtfirstblk + i));
		}
	}

	/* directory block/entry sectors */
	for (dbp = s->s_dbp; dbp != 0;	dbp = dbp->db_next) {
		blkbusy(s, dbp->db_blknum);
		for (dep = dbp->db_firstentry; dep != 0; dep = dep->de_next)
			for (i = 0; i < dep->de_blkcount; i++)
				blkbusy(s, dep->de_blks[i]);
	}
}

/*
 * Add free space to the device id incore free list.
 * Called:
 *    - During startup when all devid blocks are temporarily placed on the
 *       free list
 *    - After a devid has been deleted via the metadb command.
 *    - When mddb_devid_free_get adds unused space from a disk block
 *       to free list
 */
static int
mddb_devid_free_add(
	mddb_set_t *s,
	uint_t firstblk,
	uint_t offset,
	uint_t length
)
{
	mddb_did_free_t	*did_freep;

	if (!(s->s_lbp->lb_flags & MDDB_DEVID_STYLE)) {
		return (0);
	}

	did_freep = (mddb_did_free_t *)kmem_zalloc(sizeof (mddb_did_free_t),
	    KM_SLEEP);
	did_freep->free_blk = firstblk;
	did_freep->free_offset = offset;
	did_freep->free_length = length;
	did_freep->free_next = s->s_did_icp->did_ic_freep;
	s->s_did_icp->did_ic_freep = did_freep;

	return (0);
}

/*
 * Remove specific free space from the device id incore free list.
 * Called at startup (after all devid blocks have been placed on
 * free list) in order to remove the free space from the list that
 * contains actual devids.
 * Returns 0 if area successfully removed.
 * Returns 1 if no matching area is found - so nothing removed.
 */
static int
mddb_devid_free_delete(
	mddb_set_t *s,
	uint_t firstblk,
	uint_t offset,
	uint_t length
)
{
	int		block_found = 0;
	mddb_did_free_t	*did_freep1;		/* next free block */
	mddb_did_free_t	*did_freep2 = 0;	/* previous free block */
	mddb_did_free_t *did_freep_before;	/* area before offset, len */
	mddb_did_free_t	*did_freep_after;	/* area after offset, len */
	uint_t		old_length;

	if (!(s->s_lbp->lb_flags & MDDB_DEVID_STYLE)) {
		return (1);
	}

	/* find free block for this devid */
	did_freep1 = s->s_did_icp->did_ic_freep;
	while (did_freep1) {
		/*
		 * Look through free list of <block, offset, length> to
		 * find our entry in the free list.  Our entry should
		 * exist since the entire devid block was placed into
		 * this free list at startup.  This code is just removing
		 * the non-free (in-use) portions of the devid block so
		 * that the remaining linked list does indeed just
		 * contain a free list.
		 *
		 * Our entry has been found if
		 *   - the blocks match,
		 *   - the offset (starting address) in the free list is
		 *	less than the offset of our entry and
		 *   - the length+offset (ending address) in the free list is
		 *	greater than the length+offset of our entry.
		 */
		if ((did_freep1->free_blk == firstblk) &&
		    (did_freep1->free_offset <= offset) &&
		    ((did_freep1->free_length + did_freep1->free_offset) >=
		    (length + offset))) {
			/* Have found our entry - remove from list */
			block_found = 1;
			did_freep_before = did_freep1;
			old_length = did_freep1->free_length;
			/* did_freep1 - pts to next free block */
			did_freep1 = did_freep1->free_next;
			if (did_freep2) {
				did_freep2->free_next = did_freep1;
			} else {
				s->s_did_icp->did_ic_freep = did_freep1;
			}

			/*
			 * did_freep_before points to area in block before
			 * offset, length.
			 */
			did_freep_before->free_length = offset -
			    did_freep_before->free_offset;
			/*
			 * did_freep_after points to area in block after
			 * offset, length.
			 */
			did_freep_after = (mddb_did_free_t *)kmem_zalloc
			    (sizeof (mddb_did_free_t), KM_SLEEP);
			did_freep_after->free_blk = did_freep_before->free_blk;
			did_freep_after->free_offset = offset + length;
			did_freep_after->free_length = old_length - length -
			    did_freep_before->free_length;
			/*
			 * Add before and after areas to free list
			 * If area before or after offset, length has length
			 * of 0, that entry is not added.
			 */
			if (did_freep_after->free_length) {
				did_freep_after->free_next = did_freep1;
				if (did_freep2) {
					did_freep2->free_next =
					    did_freep_after;
				} else {
					s->s_did_icp->did_ic_freep =
					    did_freep_after;
				}
				did_freep1 = did_freep_after;
			} else {
				kmem_free(did_freep_after,
				    sizeof (mddb_did_free_t));
			}

			if (did_freep_before->free_length) {
				did_freep_before->free_next = did_freep1;
				if (did_freep2) {
					did_freep2->free_next =
					    did_freep_before;
				} else {
					s->s_did_icp->did_ic_freep =
					    did_freep_before;
				}
			} else {
				kmem_free(did_freep_before,
				    sizeof (mddb_did_free_t));
			}
			break;
		} else {
			did_freep2 = did_freep1;
			did_freep1 = did_freep1->free_next;
		}
	}
	if (block_found == 0) {
		return (1);
	} else {
		return (0);
	}
}

/*
 * Find free space of devid length and remove free space from list.
 * Return a pointer to the previously free area.
 *
 * If there's not enough free space on the free list, get an empty
 * disk block, put the empty disk block on the did_ic_dbp linked list,
 * and add the disk block space not used for devid to the free list.
 *
 * Return pointer to address (inside disk block) of free area for devid.
 * Return 0 if error.
 */
static caddr_t
mddb_devid_free_get(
	mddb_set_t *s,
	uint_t len,
	uint_t *blk,
	uint_t *cnt,
	uint_t *offset
)
{
	mddb_did_free_t	*freep, *freep2;
	mddb_did_db_t	*dbp;
	uint_t		blk_cnt, blk_num;
	ddi_devid_t	devid_ptr = NULL;

	if (!(s->s_lbp->lb_flags & MDDB_DEVID_STYLE)) {
		return (0);
	}

	freep = s->s_did_icp->did_ic_freep;
	freep2 = (mddb_did_free_t *)NULL;
	while (freep) {
		/* found a free area - remove from free list */
		if (len <= freep->free_length) {
			*blk = freep->free_blk;
			*offset = freep->free_offset;
			/* find disk block pointer that contains free area */
			dbp = s->s_did_icp->did_ic_dbp;
			while (dbp) {
				if (dbp->db_firstblk == *blk)
					break;
				else
					dbp = dbp->db_next;
			}
			/*
			 * If a disk block pointer can't be found - something
			 * is wrong, so don't use this free space.
			 */
			if (dbp == NULL) {
				freep2 = freep;
				freep = freep->free_next;
				continue;
			}

			devid_ptr = (ddi_devid_t)(dbp->db_ptr + *offset);
			*cnt = dbp->db_blkcnt;

			/* Update free list information */
			freep->free_offset += len;
			freep->free_length -= len;
			if (freep->free_length == 0) {
				if (freep2) {
					freep2->free_next =
					    freep->free_next;
				} else {
					s->s_did_icp->did_ic_freep =
					    freep->free_next;
				}
				kmem_free(freep, sizeof (mddb_did_free_t));
			}
			break;
		}
		freep2 = freep;
		freep = freep->free_next;
	}

	/* Didn't find a free spot */
	if (freep == NULL) {
		/* get free logical disk blk in replica */
		blk_cnt = btodb(len + (MDDB_BSIZE - 1));
		blk_num = getfreeblks(s, blk_cnt);
		if (blk_num == 0)
			return (0);

		/* Add disk block to disk block linked list */
		dbp = kmem_zalloc(sizeof (mddb_did_db_t), KM_SLEEP);
		dbp->db_firstblk = blk_num;
		dbp->db_blkcnt = blk_cnt;
		dbp->db_ptr = (caddr_t)kmem_zalloc(dbtob(blk_cnt), KM_SLEEP);
		dbp->db_next = s->s_did_icp->did_ic_dbp;
		s->s_did_icp->did_ic_dbp = dbp;
		devid_ptr = (ddi_devid_t)dbp->db_ptr;

		/* Update return values */
		*blk = blk_num;
		*offset = 0;
		*cnt = blk_cnt;

		/* Add unused part of block to free list */
		(void) mddb_devid_free_add(s, blk_num,
		    len, (dbtob(blk_cnt) - len));
	}

	return ((caddr_t)devid_ptr);
}

/*
 * Add device id information for locator index to device id area in set.
 * Get free area to store device id from free list.   Update checksum
 * for mddb_did_blk.
 *
 * This routine does not write any data out to disk.
 * After this routine has been called, the routine, writelocall, should
 * be called to write both the locator block and device id area out
 * to disk.
 */
static int
mddb_devid_add(
	mddb_set_t	*s,
	uint_t		index,
	ddi_devid_t	devid,
	char		*minor_name
)
{
	uint_t		devid_len;
	uint_t		blk, offset;
	ddi_devid_t	devid_ptr;
	mddb_did_info_t	*did_info;
	uint_t		blkcnt, i;
	mddb_did_blk_t	*did_blk;

	if (!(s->s_lbp->lb_flags & MDDB_DEVID_STYLE)) {
		return (1);
	}
	if (strlen(minor_name) > (MDDB_MINOR_NAME_MAX - 1))
		return (1);

	/* Check if device id has already been added */
	did_blk = s->s_did_icp->did_ic_blkp;
	did_info = &(did_blk->blk_info[index]);
	if (did_info->info_flags & MDDB_DID_EXISTS)
		return (0);

	devid_len = ddi_devid_sizeof(devid);
	devid_ptr = (ddi_devid_t)mddb_devid_free_get(s,
	    devid_len, &blk, &blkcnt, &offset);

	if (devid_ptr == NULL) {
		return (1);
	}

	/* Copy devid into devid free area */
	for (i = 0; i < devid_len; i++)
		((char *)devid_ptr)[i] = ((char *)devid)[i];

	/* Update mddb_did_info area for new device id */
	did_info->info_flags = MDDB_DID_EXISTS | MDDB_DID_VALID;

	/*
	 * Only set UPDATED flag for non-replicated import cases.
	 * This allows the side locator driver name index to get
	 * updated in load_old_replicas.
	 */
	if (!(md_get_setstatus(s->s_setno) & MD_SET_REPLICATED_IMPORT))
		did_info->info_flags |= MDDB_DID_UPDATED;

	did_info->info_firstblk = blk;
	did_info->info_blkcnt = blkcnt;
	did_info->info_offset = offset;
	did_info->info_length = devid_len;
	(void) strcpy(did_info->info_minor_name, minor_name);
	crcgen(devid_ptr, &did_info->info_checksum, devid_len, NULL);

	/* Add device id pointer to did_ic_devid array */
	s->s_did_icp->did_ic_devid[index] = devid_ptr;

	return (0);
}


/*
 * Delete device id information for locator index from device id area in set.
 * Add device id space to free area.
 *
 * This routine does not write any data out to disk.
 * After this routine has been called, the routine, writelocall, should
 * be called to write both the locator block and device id area out
 * to disk.
 */
static int
mddb_devid_delete(mddb_set_t *s, uint_t index)
{
	mddb_did_info_t	*did_info;
	mddb_did_blk_t	*did_blk;

	if (!(s->s_lbp->lb_flags & MDDB_DEVID_STYLE)) {
		return (1);
	}

	/* Get device id information from mddb_did_blk */
	did_blk = s->s_did_icp->did_ic_blkp;
	did_info = &(did_blk->blk_info[index]);

	/*
	 * Ensure that the underlying device supports device ids
	 * before arbitrarily removing them.
	 */
	if (!(did_info->info_flags & MDDB_DID_EXISTS)) {
		return (1);
	}

	/* Remove device id information from mddb_did_blk */
	did_info->info_flags = 0;

	/* Remove device id from incore area */
	s->s_did_icp->did_ic_devid[index] = (ddi_devid_t)NULL;

	/* Add new free space in disk block to free list */
	(void) mddb_devid_free_add(s, did_info->info_firstblk,
	    did_info->info_offset, did_info->info_length);

	return (0);
}

/*
 * Check if there is a device id for a locator index.
 *
 * Caller of this routine should not free devid or minor_name since
 * these will point to internal data structures that should not
 * be freed.
 */
static int
mddb_devid_get(
	mddb_set_t *s,
	uint_t index,
	ddi_devid_t *devid,
	char **minor_name
)
{
	mddb_did_info_t	*did_info;

	if (!(s->s_lbp->lb_flags & MDDB_DEVID_STYLE)) {
		return (0);
	}
	did_info = &(s->s_did_icp->did_ic_blkp->blk_info[index]);

	if (did_info->info_flags & MDDB_DID_EXISTS) {
		*devid = s->s_did_icp->did_ic_devid[index];
		*minor_name =
		    s->s_did_icp->did_ic_blkp->blk_info[index].info_minor_name;
		return (1);
	} else
		return (0);


}

/*
 * Check if device id is valid on current system.
 * Needs devid, previously known dev_t and current minor_name.
 *
 * Success:
 * 	Returns 0 if valid device id is found and updates
 * 	dev_t if the dev_t associated with the device id is
 *	different than dev_t.
 * Failure:
 * 	Returns 1 if device id not valid on current system.
 */
static int
mddb_devid_validate(ddi_devid_t devid, md_dev64_t *dev, char *minor_name)
{
	int		retndevs;
	dev_t		*ddi_devs;
	int		devid_flag = 0;
	int 		cnt;

	if (dev == 0)
		return (1);
	/*
	 * See if devid is valid in the current system.
	 * If so, set dev to match the devid.
	 */
	if (ddi_lyr_devid_to_devlist(devid, minor_name,
	    &retndevs, &ddi_devs) == DDI_SUCCESS) {
		if (retndevs > 0) {
			/* devid is valid to use */
			devid_flag = 1;
			/* does dev_t in list match dev */
			cnt = 0;
			while (cnt < retndevs) {
				if (*dev == md_expldev(ddi_devs[cnt]))
					break;
				cnt++;
			}
			/*
			 * If a different dev_t, then setup
			 * new dev and new major name
			 */
			if (cnt == retndevs) {
				*dev = md_expldev(ddi_devs[0]);
			}
			ddi_lyr_free_devlist(ddi_devs, retndevs);
		}
	}
	if (devid_flag)
		return (0);
	else
		return (1);
}


/*
 * Free the devid incore data areas
 */
static void
mddb_devid_icp_free(mddb_did_ic_t **did_icp, mddb_lb_t *lbp)
{
	mddb_did_free_t	*did_freep1, *did_freep2;
	mddb_did_db_t	*did_dbp1, *did_dbp2;
	mddb_did_ic_t	*icp = *did_icp;

	if (icp) {
		if (icp->did_ic_blkp) {
			kmem_free((caddr_t)icp->did_ic_blkp,
			    dbtob(lbp->lb_didblkcnt));
			icp->did_ic_blkp = (mddb_did_blk_t *)NULL;
		}

		if (icp->did_ic_dbp) {
			did_dbp1 = icp->did_ic_dbp;
			while (did_dbp1) {
				did_dbp2 = did_dbp1->db_next;
				kmem_free((caddr_t)did_dbp1->db_ptr,
				    dbtob(did_dbp1->db_blkcnt));
				kmem_free((caddr_t)did_dbp1,
				    sizeof (mddb_did_db_t));
				did_dbp1 = did_dbp2;
			}
		}

		if (icp->did_ic_freep) {
			did_freep1 = icp->did_ic_freep;
			while (did_freep1) {
				did_freep2 = did_freep1->free_next;
				kmem_free((caddr_t)did_freep1,
				    sizeof (mddb_did_free_t));
				did_freep1 = did_freep2;
			}
		}

		kmem_free((caddr_t)icp, sizeof (mddb_did_ic_t));
		*did_icp = (mddb_did_ic_t *)NULL;
	}

}

static daddr_t
getphysblk(
	mddb_block_t		blk,
	mddb_mb_ic_t		*mbip
)
{
	mddb_mb_t	*mbp = &(mbip->mbi_mddb_mb);

	while (blk >= mbp->mb_blkcnt) {
		if (! mbip->mbi_next)
			return ((daddr_t)-1);	/* no such block */
		blk -= mbp->mb_blkcnt;
		mbip = mbip->mbi_next;
		mbp = &(mbip->mbi_mddb_mb);
	}

	if (blk >= mbp->mb_blkmap.m_consecutive)
		return ((daddr_t)-1);	/* no such block */

	return ((daddr_t)(mbp->mb_blkmap.m_firstblk + blk));
}

/*
 * when a buf header is passed in the new buffer must be
 * put on the front of the chain. writerec counts on it
 */
static int
putblks(
	mddb_set_t	*s,		/* incore db set structure */
	caddr_t		buffer,		/* adr of buffer to be written */
	daddr_t		blk,		/* block number for first block */
	int		cnt,		/* number of blocks to be written */
	md_dev64_t	device,		/* device to be written to */
	mddb_bf_t	**bufhead	/* if non-zero then ASYNC I/O */
					/*    and put buf address here */
)
{
	buf_t		*bp;
	mddb_bf_t	*bfp;
	int		err = 0;

	bfp = allocbuffer(s, MDDB_SLEEPOK);
	bp = &bfp->bf_buf;
	bp->b_bcount = MDDB_BSIZE * cnt;
	bp->b_un.b_addr = buffer;
	bp->b_blkno = blk;
	bp->b_edev = md_dev64_to_dev(device);
	/*
	 * if a header for a buf chain is passed in this is async io.
	 * currently only done for optimize  records
	 */
	if (bufhead) {
		bfp->bf_next = *bufhead;
		*bufhead = bfp;
		(void) mddb_rwdata(s, B_WRITE|B_ASYNC, bp);
		return (0);
	}
	err = mddb_rwdata(s, B_WRITE, bp);
	freebuffer(s, bfp);
	if (err) {
		SE_NOTIFY(EC_SVM_STATE, ESC_SVM_ERRED, SVM_TAG_REPLICA,
		    s->s_setno, device);
		return (MDDB_F_EWRITE);
	}
	return (0);
}

/*
 * wrtblklst - takes an array of logical block numbers
 *		and writes the buffer to those blocks (scatter).
 * If called during upgrade, this routine expects a
 * non-translated (aka target) dev.
 */
static int
wrtblklst(
	mddb_set_t	*s,		/* incore set structure */
	caddr_t		buffer,		/* buffer to be written (record blk) */
	mddb_block_t	blka[],		/* list of logical blks for record */
	daddr_t		cnt,		/* number of logical blks */
	const int	li,		/* locator index */
	mddb_bf_t	**bufhead,	/* if non-zero then ASYNC I/O */
					/*    and put buf address here */
	int		master_only	/* allow only master node to write */
)
{
	daddr_t		blk;
	daddr_t		blk1;
	int		err = 0;
	int		cons;
	mddb_lb_t	*lbp = s->s_lbp;
	mddb_locator_t	*lp = &lbp->lb_locators[li];
	md_dev64_t	dev;
	mddb_mb_ic_t	*mbip = s->s_mbiarray[li];

	/*
	 * If a MN diskset and only the master can write,
	 * then a non-master node will just return success.
	 */
	if (lbp->lb_flags & MDDB_MNSET) {
		if (master_only == MDDB_WR_ONLY_MASTER) {
			/* return successfully if we aren't the master */
			if (!(md_set[s->s_setno].s_am_i_master)) {
				return (0);
			}
		}
		if (mbip == NULL)
			return (MDDB_F_EWRITE);
	}

	dev = md_xlate_targ_2_mini(md_expldev(lp->l_dev));
	if (dev == NODEV64) {
		return (1);
	}

	blk = getphysblk(blka[0], mbip);
	ASSERT(blk >= 0);

	cons = 1;
	while (cnt) {
		if (cons != cnt) {
			blk1 = getphysblk(blka[cons], mbip);
			ASSERT(blk1 >= 0);
			if ((blk + cons) == blk1) {
				cons++;
				continue;
			}
		}
		if (err = putblks(s, buffer, blk, cons, dev, bufhead)) {
			/*
			 * If an MN diskset and any_node_can_write
			 * then this request is coming from writeoptrecord
			 * and l_flags field should not be updated.
			 * l_flags will be updated as a result of sending
			 * a class1 message to the master.  Setting l_flags
			 * here will cause slave to be out of sync with
			 * master.
			 *
			 * Otherwise, set the error in l_flags
			 * (this occurs if this is not a MN diskset or
			 * only_master_can_write is set).
			 */
			if ((!(lbp->lb_flags & MDDB_MNSET)) ||
			    (master_only == MDDB_WR_ONLY_MASTER)) {
				lp->l_flags |= MDDB_F_EWRITE;
			}
			return (err);
		}
		if (bufhead)
			(*bufhead)->bf_locator = lp;

		buffer += MDDB_BSIZE * cons;
		cnt -= cons;
		blka += cons;
		if (cnt) {
			blk = getphysblk(blka[0], mbip);
			ASSERT(blk >= 0);
		}
		cons = 1;
	}

	return (0);
}

/*
 * writeblks - takes a logical block number/block count pair
 * 		and writes the buffer to those contiguous logical blocks.
 * If called during upgrade, this routine expects a non-translated
 * (aka target) dev.
 */
static int
writeblks(
	mddb_set_t	*s,		/* incore set structure */
	caddr_t		buffer,		/* buffer to be written */
	mddb_block_t	blk,		/* starting logical block number */
	int		cnt,		/* number of log blocks to be written */
	const int	li,		/* locator index */
	int		master_only	/* allow only master node to write */
)
{
	daddr_t		physblk;
	int		err = 0;
	int		i;
	mddb_lb_t	*lbp = s->s_lbp;
	mddb_locator_t	*lp = &lbp->lb_locators[li];
	md_dev64_t	dev;
	mddb_block_t	*blkarray;
	int		size;
	int		ret;

	/*
	 * If a MN diskset and only the master can write,
	 * then a non-master node will just return success.
	 */
	if ((lbp->lb_flags & MDDB_MNSET) &&
	    (master_only == MDDB_WR_ONLY_MASTER)) {
		/* return successfully if we aren't the master */
		if (!(md_set[s->s_setno].s_am_i_master)) {
			return (0);
		}
	}

	dev = md_xlate_targ_2_mini(md_expldev(lp->l_dev));
	if (dev == NODEV64) {
		return (1);
	}

	if (cnt > 1) {
		size = sizeof (mddb_block_t) * cnt;
		blkarray = (mddb_block_t *)kmem_alloc(size, KM_SLEEP);
		for (i = 0; i < cnt; i++)
			blkarray[i] = blk + i;
		ret = wrtblklst(s, buffer, blkarray, cnt,
		    li, 0, MDDB_WR_ONLY_MASTER);
		kmem_free(blkarray, size);
		return (ret);
	}
	physblk = getphysblk(blk, s->s_mbiarray[li]);
	ASSERT(physblk > 0);
	if (err = putblks(s, buffer, physblk, 1, dev, (mddb_bf_t **)0)) {
		lp->l_flags |= MDDB_F_EWRITE;
		return (err);
	}
	return (0);
}

/*
 * writeall - will write the buffer to all ACTIVE/NON-ERRORED replicas.
 */
static int
writeall(
	mddb_set_t	*s,		/* incore set structure */
	caddr_t		buffer,		/* buffer to be written */
	mddb_block_t	block,		/* starting logical block number */
	int		cnt,		/* number of log blocks to be written */
	int		master_only	/* allow only master node to write */
)
{
	int		li;
	int		err = 0;
	mddb_lb_t	*lbp = s->s_lbp;

	for (li = 0; li < lbp->lb_loccnt; li++) {
		mddb_locator_t	*lp = &lbp->lb_locators[li];

		if ((! (lp->l_flags & MDDB_F_ACTIVE)) ||
		    (lp->l_flags & MDDB_F_EWRITE))
			continue;

		err |= writeblks(s, buffer, block, cnt, li, master_only);
	}

	return (err);
}

/*
 * writelocall - write the locator block and device id information (if
 * replica is in device id format) to all ACTIVE/NON-ERRORER replicas.
 *
 * Increments the locator block's commitcnt.  Updates the device id area's
 * commitcnt if the replica is in device id format.  Regenerates the
 * checksums after updating the commitcnt(s).
 */
static int
writelocall(
	mddb_set_t	*s	/* incore set structure */
)
{
	int		li;
	int		err = 0;
	mddb_lb_t	*lbp = s->s_lbp;
	mddb_did_blk_t	*did_blk;
	mddb_did_db_t	*did_dbp;

	s->s_lbp->lb_commitcnt++;
	if (lbp->lb_flags & MDDB_DEVID_STYLE) {
		did_blk = s->s_did_icp->did_ic_blkp;
		did_blk->blk_commitcnt = s->s_lbp->lb_commitcnt;
		crcgen(did_blk, &did_blk->blk_checksum,
		    dbtob(lbp->lb_didblkcnt), NULL);
	}
	crcgen(lbp, &lbp->lb_checksum, dbtob(lbp->lb_blkcnt), NULL);

	for (li = 0; li < lbp->lb_loccnt; li++) {
		mddb_locator_t	*lp = &lbp->lb_locators[li];

		if ((! (lp->l_flags & MDDB_F_ACTIVE)) ||
		    (lp->l_flags & MDDB_F_EWRITE))
			continue;

		if (lbp->lb_flags & MDDB_DEVID_STYLE) {
			/* write out blocks containing actual device ids */
			did_dbp = s->s_did_icp->did_ic_dbp;
			while (did_dbp) {
				err |= writeblks(s, (caddr_t)did_dbp->db_ptr,
				    did_dbp->db_firstblk,
				    did_dbp->db_blkcnt, li,
				    MDDB_WR_ONLY_MASTER);
				did_dbp = did_dbp->db_next;
			}

			/* write out device id area block */
			err |= writeblks(s, (caddr_t)did_blk,
			    lbp->lb_didfirstblk, lbp->lb_didblkcnt, li,
			    MDDB_WR_ONLY_MASTER);
		}
		/* write out locator block */
		err |= writeblks(s, (caddr_t)lbp, 0, lbp->lb_blkcnt, li,
		    MDDB_WR_ONLY_MASTER);
	}

	/*
	 * If a MN diskset and this is the master, set the PARSE_LOCBLK flag
	 * in the mddb_set structure to show that the locator block has
	 * been changed.
	 */

	if ((lbp->lb_flags & MDDB_MNSET) &&
	    (md_set[s->s_setno].s_am_i_master)) {
		s->s_mn_parseflags |= MDDB_PARSE_LOCBLK;
	}
	return (err);
}

/*
 * If called during upgrade, this routine expects a translated
 * (aka miniroot) dev.
 */
static int
getblks(
	mddb_set_t	*s,	/* incore db set structure */
	caddr_t		buffer,	/* buffer to read data into */
	md_dev64_t	device,	/* device to read from */
	daddr_t		blk,	/* physical block number to read */
	int		cnt,	/* number of blocks to read */
	int		flag	/* flags for I/O */
)
{
	buf_t		*bp;
	mddb_bf_t	*bfp;
	int		err = 0;

	bfp = allocbuffer(s, MDDB_SLEEPOK);	/* this will never sleep */
	bp = &bfp->bf_buf;
	bp->b_bcount = MDDB_BSIZE * cnt;
	bp->b_un.b_addr = buffer;
	bp->b_blkno = blk;
	bp->b_edev = md_dev64_to_dev(device);
	err = mddb_rwdata(s, (B_READ | flag), bp);
	freebuffer(s, bfp);
	if (err) {
		SE_NOTIFY(EC_SVM_STATE, ESC_SVM_ERRED, SVM_TAG_REPLICA,
		    s->s_setno, device);
		return (MDDB_F_EREAD);
	}
	return (0);
}

/*
 * readblklst - takes an array of logical block numbers
 * 		and reads those blocks (gather) into the buffer.
 * If called during upgrade, this routine expects a non-translated
 * (aka target) dev.
 */
static int
readblklst(
	mddb_set_t	*s,	/* incore set structure */
	caddr_t		buffer,	/* buffer to be read (record block) */
	mddb_block_t	blka[],	/* list of logical blocks to be read */
	daddr_t		cnt,	/* number of logical blocks */
	int		li,	/* locator index */
	int		flag	/* flags for I/O */
)
{
	daddr_t		blk;
	daddr_t		blk1;
	int		err = 0;
	int		cons;
	md_dev64_t	dev;
	mddb_mb_ic_t	*mbip;

	mbip = s->s_mbiarray[li];
	dev = md_expldev(s->s_lbp->lb_locators[li].l_dev);
	dev = md_xlate_targ_2_mini(dev);
	if (dev == NODEV64) {
		return (1);
	}

	blk = getphysblk(blka[0], mbip);
	ASSERT(blk >= 0);

	cons = 1;
	while (cnt) {
		if (cons != cnt) {
			blk1 = getphysblk(blka[cons], mbip);
			ASSERT(blk1 >= 0);
			if ((blk + cons) == blk1) {
				cons++;
				continue;
			}
		}
		if (err = getblks(s, buffer, dev, blk, cons, flag))
			return (err);
		buffer += MDDB_BSIZE * cons;
		cnt -= cons;
		blka += cons;
		if (cnt) {
			blk = getphysblk(blka[0], mbip);
			ASSERT(blk >= 0);
		}
		cons = 1;
	}
	return (0);
}

/*
 * readblks - takes a logical block number/block count pair
 * 		and reads those contiguous logical blocks into the buffer.
 * If called during upgrade, this routine expects a non-translated
 * (aka target) dev.
 */
static int
readblks(
	mddb_set_t	*s,	/* incore set structure */
	caddr_t		buffer,	/* buffer to be read into */
	mddb_block_t	blk,	/* logical block number to be read */
	int		cnt,	/* number of logical blocks to be read */
	int		li	/* locator index */
)
{
	daddr_t		physblk;
	md_dev64_t	device;
	int		i;
	mddb_block_t	*blkarray;
	int		size;
	int		ret;

	if (cnt > 1) {
		size = sizeof (mddb_block_t) * cnt;
		blkarray = (mddb_block_t *)kmem_alloc(size, KM_SLEEP);
		for (i = 0; i < cnt; i++)
			blkarray[i] = blk + i;
		ret = readblklst(s, buffer, blkarray, cnt, li, 0);
		kmem_free(blkarray, size);
		return (ret);
	}
	physblk = getphysblk(blk, s->s_mbiarray[li]);
	ASSERT(physblk > 0);
	device = md_expldev(s->s_lbp->lb_locators[li].l_dev);
	device = md_xlate_targ_2_mini(device);
	if (device == NODEV64) {
		return (1);
	}
	return (getblks(s, buffer, device, physblk, 1, 0));
}

static void
single_thread_start(
	mddb_set_t	*s
)
{
	while (s->s_singlelockgotten) {
		s->s_singlelockwanted++;
		cv_wait(&s->s_single_thread_cv, SETMUTEX(s->s_setno));
	}
	s->s_singlelockgotten++;
}

static void
single_thread_end(
	mddb_set_t	*s
)
{
	ASSERT(s->s_singlelockgotten);
	s->s_singlelockgotten = 0;
	if (s->s_singlelockwanted) {
		s->s_singlelockwanted = 0;
		cv_broadcast(&s->s_single_thread_cv);
	}
}

static size_t
sizeofde(
	mddb_de_ic_t	*dep
)
{
	size_t		size;

	size = sizeof (mddb_de_ic_t) - sizeof (mddb_block_t) +
	    sizeof (mddb_block_t) * dep->de_blkcount;
	return (size);
}

static size_t
sizeofde32(
	mddb_de32_t	*dep
)
{
	size_t		size;

	size = sizeof (*dep) - sizeof (dep->de32_blks) +
	    sizeof (mddb_block_t) * dep->de32_blkcount;
	return (size);
}

static mddb_de32_t *
nextentry(
	mddb_de32_t	*dep
)
{
	mddb_de32_t	*ret;

	ret = (mddb_de32_t *)((void *)((caddr_t)dep + sizeofde32(dep)));
	return (ret);
}

static void
create_db32rec(
	mddb_db32_t *db32p,
	mddb_db_t *dbp
)
{
	mddb_de_ic_t *dep;
	mddb_de32_t *de32p;

#if defined(_ILP32) && !defined(lint)
	ASSERT(sizeof (mddb_de_t) == sizeof (mddb_de32_t));
	ASSERT(sizeof (mddb_db_t) == sizeof (mddb_db32_t));
#endif

	dbtodb32(dbp, db32p);
	if ((dbp->db_firstentry != NULL) && (db32p->db32_firstentry == 0))
		db32p->db32_firstentry = 0x4;
	de32p = (mddb_de32_t *)((void *) ((caddr_t)(&db32p->db32_firstentry)
	    + sizeof (db32p->db32_firstentry)));
	for (dep = dbp->db_firstentry; dep; dep = dep->de_next) {
		detode32(dep, de32p);
		if ((dep->de_next != NULL) && (de32p->de32_next == 0))
			de32p->de32_next = 0x4;
		de32p = nextentry(de32p);
	}
	ASSERT((uintptr_t)de32p <= (uintptr_t)de32p + MDDB_BSIZE);
}

/*
 * If called during upgrade, this routine expects a translated
 * (aka miniroot) dev.
 * If master blocks are found, set the mn_set parameter to 1 if the
 * the master block revision number is MDDB_REV_MNMB; otherwise,
 * set it to 0.
 * If master blocks are not found, do not change the mnset parameter.
 */
static mddb_mb_ic_t *
getmasters(
	mddb_set_t	*s,
	md_dev64_t	dev,
	daddr_t		blkno,
	uint_t		*flag,
	int		*mn_set
)
{
	mddb_mb_ic_t	*mbi = NULL;
	mddb_mb_t	*mb;
	int		error = 0;
	ddi_devid_t	devid;


	if (mddb_devopen(dev)) {
		if (flag)
			*flag |= MDDB_F_EMASTER;
		return ((mddb_mb_ic_t *)NULL);
	}


	mbi = (mddb_mb_ic_t *)kmem_zalloc(MDDB_IC_BSIZE, KM_SLEEP);
	mb = &(mbi->mbi_mddb_mb);
	if (error = getblks(s, (caddr_t)mb, dev, blkno,
	    btodb(MDDB_BSIZE), 0)) {
		error |= MDDB_F_EMASTER;
	}
	if (mb->mb_magic != MDDB_MAGIC_MB) {
		error = MDDB_F_EFMT | MDDB_F_EMASTER;
	}
	/* Check for MDDB_REV_MNMB and lower */
	if (revchk(MDDB_REV_MNMB, mb->mb_revision)) {
		error = MDDB_F_EFMT | MDDB_F_EMASTER;
	}
	if (crcchk(mb, &mb->mb_checksum, MDDB_BSIZE, NULL)) {
		error = MDDB_F_EFMT | MDDB_F_EMASTER;
	}

	if (!(md_get_setstatus(s->s_setno) &
	    (MD_SET_IMPORT | MD_SET_REPLICATED_IMPORT)) &&
	    (mb->mb_setno != s->s_setno)) {
		error = MDDB_F_EFMT | MDDB_F_EMASTER;
	}
	if (mb->mb_blkno != blkno) {
		error = MDDB_F_EFMT | MDDB_F_EMASTER;
	}
	mb->mb_next = NULL;
	mbi->mbi_next = NULL;

	if (error)
		goto out;

	/*
	 * Check the md_devid_destroy and md_keep_repl_state flags
	 * to see if we need to regen the devid or not.
	 *
	 * Don't care about devid in local set since it is not used
	 * and this should not be part of set importing
	 */
	if ((s->s_setno != MD_LOCAL_SET) &&
	    !(md_get_setstatus(s->s_setno) &
	    (MD_SET_IMPORT | MD_SET_REPLICATED_IMPORT))) {
		/*
		 * Now check the destroy flag. We also need to handle
		 * the case where the destroy flag is reset after the
		 * destroy
		 */
		if (md_devid_destroy || (mb->mb_devid_len == 0)) {

			if (md_devid_destroy) {
				bzero(mb->mb_devid, mb->mb_devid_len);
				mb->mb_devid_len = 0;
			}

			/*
			 * Try to regenerate it if the 'keep' flag is not set
			 */
			if (!md_keep_repl_state) {
				if (ddi_lyr_get_devid(md_dev64_to_dev(dev),
				    &devid) == DDI_SUCCESS) {
					mb->mb_devid_len =
					    ddi_devid_sizeof(devid);
					bcopy(devid, mb->mb_devid,
					    mb->mb_devid_len);
					ddi_devid_free(devid);
				} else {
					error = MDDB_F_EFMT | MDDB_F_EMASTER;
				}
			}

			crcgen(mb, &mb->mb_checksum, MDDB_BSIZE, NULL);

			/*
			 * Push
			 */
			if (putblks(s, (caddr_t)mb, blkno, 1, dev, 0) != 0) {
				error = MDDB_F_EFMT | MDDB_F_EMASTER;
			}
		}
	}

	if (! error) {
		/* Set mn_set parameter to 1 if a MN set */
		if (mb->mb_revision == MDDB_REV_MNMB)
			*mn_set = 1;
		else
			*mn_set = 0;
		return (mbi);
	}

out:
	/* Error Out */
	if (flag)
		*flag |= error;

	kmem_free((caddr_t)mbi, MDDB_IC_BSIZE);
	mddb_devclose(dev);
	return ((mddb_mb_ic_t *)NULL);
}

static int
getrecord(
	mddb_set_t	*s,
	mddb_de_ic_t	*dep,
	int		li
)
{
	int		err = 0;
	mddb_rb32_t	*rbp;

#if defined(_ILP32) && !defined(lint)
	ASSERT(sizeof (mddb_rb_t) == sizeof (mddb_rb32_t));
#endif


	dep->de_rb = (mddb_rb32_t *)kmem_zalloc(dep->de_recsize, KM_SLEEP);
	rbp = dep->de_rb;

	err = readblklst(s, (caddr_t)rbp, dep->de_blks,
	    dep->de_blkcount, li, 0);
	if (err) {
		return (MDDB_F_EDATA | err);
	}
	if (rbp->rb_magic != MDDB_MAGIC_RB) {
		return (MDDB_F_EFMT | MDDB_F_EDATA);
	}
	if ((revchk(MDDB_REV_RB, rbp->rb_revision) != 0) &&
	    (revchk(MDDB_REV_RB64, rbp->rb_revision) != 0) &&
	    (revchk(MDDB_REV_RBFN, rbp->rb_revision) != 0) &&
	    (revchk(MDDB_REV_RB64FN, rbp->rb_revision) != 0)) {
		return (MDDB_F_EFMT | MDDB_F_EDATA);
	}
	/* Check crc for this record */
	if (rec_crcchk(s, dep, rbp)) {
		return (MDDB_F_EFMT | MDDB_F_EDATA);
	}
	return (0);
}

/*
 * Code to read in the locator name information
 */
static int
readlocnames(
	mddb_set_t	*s,
	int		li
)
{
	mddb_ln_t	*lnp;
	int		err = 0;
	mddb_block_t	ln_blkcnt, ln_blkno;

	/*
	 * read in the locator name blocks
	 */
	s->s_lnp = NULL;

	ln_blkno = s->s_lbp->lb_lnfirstblk;
	ln_blkcnt = s->s_lbp->lb_lnblkcnt;
	lnp = (mddb_ln_t *)kmem_zalloc(dbtob(ln_blkcnt), KM_SLEEP);

	err = readblks(s, (caddr_t)lnp, ln_blkno, ln_blkcnt, li);
	if (err) {
		err |= MDDB_F_EDATA;
		goto out;
	}
	if (lnp->ln_magic != MDDB_MAGIC_LN) {
		err = MDDB_F_EDATA | MDDB_F_EFMT;
		goto out;
	}
	if (s->s_lbp->lb_flags & MDDB_MNSET) {
		if (revchk(MDDB_REV_MNLN, lnp->ln_revision)) {
			err = MDDB_F_EDATA | MDDB_F_EFMT;
			goto out;
		}
	} else {
		if (revchk(MDDB_REV_LN, lnp->ln_revision)) {
			err = MDDB_F_EDATA | MDDB_F_EFMT;
			goto out;
		}
	}
	if (crcchk(lnp, &lnp->ln_checksum, dbtob(ln_blkcnt), NULL)) {
		err = MDDB_F_EDATA | MDDB_F_EFMT;
		goto out;
	}
out:
	/*
	 *	if error occurred in locator name blocks free them
	 *	and return
	 */
	if (err) {
		kmem_free((caddr_t)lnp, dbtob(ln_blkcnt));
		return (err);
	}
	s->s_lnp = lnp;
	return (0);
}

/*
 * code to read in a copy of the database.
 */

static int
readcopy(
	mddb_set_t	*s,
	int		li
)
{
	uint_t		blk;
	mddb_db_t	*dbp, *dbp1, *dbhp;
	mddb_db32_t	*db32p;
	mddb_de_ic_t	*dep, *dep2;
	mddb_de32_t	*de32p, *de32p2;
	int		err = 0;
	uint_t		checksum;


#if defined(_ILP32) && !defined(lint)
	ASSERT(sizeof (mddb_de_t) == sizeof (mddb_de32_t));
	ASSERT(sizeof (mddb_db_t) == sizeof (mddb_db32_t));
#endif

	dbp = NULL;
	dbhp = NULL;
	/*
	 *	read in all the directory blocks
	 */
	blk = s->s_lbp->lb_dbfirstblk;
	db32p = (mddb_db32_t *)kmem_zalloc(MDDB_BSIZE, KM_SLEEP);

	for (; blk != 0; blk = dbp->db_nextblk) {
		dbp1 = (mddb_db_t *)kmem_zalloc(sizeof (mddb_db_t), KM_SLEEP);
		if (! dbhp) {
			dbhp = dbp1;
		} else {
			dbp->db_next = dbp1;
		}
		dbp = dbp1;

		err = readblks(s, (caddr_t)db32p, blk, 1, li);
		if (err) {
			err |= MDDB_F_EDATA;
			break;
		}
		db32todb(db32p, dbp);
		if (db32p->db32_magic != MDDB_MAGIC_DB) {
			err = MDDB_F_EDATA | MDDB_F_EFMT;
			break;
		}
		if (revchk(MDDB_REV_DB, db32p->db32_revision)) {
			err = MDDB_F_EDATA | MDDB_F_EFMT;
			break;
		}
		if (crcchk(db32p, &db32p->db32_checksum, MDDB_BSIZE, NULL)) {
			err = MDDB_F_EDATA | MDDB_F_EFMT;
			break;
		}
		/*
		 * first go through and fix up all de_next pointers
		 */
		if (dbp->db_firstentry) {

			de32p = (mddb_de32_t *)
			    ((void *) ((caddr_t)(&db32p->db32_firstentry)
			    + sizeof (db32p->db32_firstentry)));

			dep = (mddb_de_ic_t *)
			    kmem_zalloc(sizeof (mddb_de_ic_t) -
			    sizeof (mddb_block_t) +
			    sizeof (mddb_block_t) * de32p->de32_blkcount,
			    KM_SLEEP);
			de32tode(de32p, dep);

			dbp->db_firstentry = dep;
			while (de32p && de32p->de32_next) {

				de32p2 = nextentry(de32p);

				dep2 = (mddb_de_ic_t *)kmem_zalloc(
				    sizeof (mddb_de_ic_t) -
				    sizeof (mddb_block_t) +
				    sizeof (mddb_block_t) *
				    de32p2->de32_blkcount, KM_SLEEP);

				de32tode(de32p2, dep2);

				dep->de_next = dep2;
				dep = dep2;
				de32p = de32p2;
			}
		}
		/*
		 * go through and make all of the pointer to record blocks
		 * are null;
		 */
		for (dep = dbp->db_firstentry; dep != NULL; dep = dep->de_next)
			dep->de_rb = NULL;
	}
	kmem_free((caddr_t)db32p, MDDB_BSIZE);
	dbp->db_next = NULL;
	/*
	 *	if error occurred in directory blocks free them
	 *	and return
	 */
	if (err) {
		dbp = dbhp;
		while (dbp) {
			dep = dbp->db_firstentry;
			while (dep) {
				/* No mddb_rb32_t structures yet */
				dep2 = dep->de_next;
				kmem_free((caddr_t)dep, sizeofde(dep));
				dep = dep2;
			}
			dbp1 = dbp->db_next;
			kmem_free((caddr_t)dbp, sizeof (mddb_db_t));
			dbp = dbp1;
		}
		s->s_dbp = NULL;
		return (err);

	}
	/*
	 */
	err = 0;
	checksum = MDDB_GLOBAL_XOR;
	for (dbp = dbhp; dbp != NULL; dbp = dbp->db_next) {
		checksum ^= dbp->db_recsum;
		for (dep = dbp->db_firstentry; dep; dep = dep->de_next) {
			if (dep->de_flags & MDDB_F_OPT)
				continue;
			err = getrecord(s, dep, li);
			if (err)
				break;
			/* Don't include CHANGELOG in big XOR */
			if (dep->de_flags & MDDB_F_CHANGELOG)
				continue;
			checksum ^= dep->de_rb->rb_checksum;
			checksum ^= dep->de_rb->rb_checksum_fiddle;
		}
		if (err)
			break;
	}
	if (checksum) {
		if (! err)
			err = MDDB_F_EDATA | MDDB_F_EFMT;
	}
	if (err) {
		dbp = dbhp;
		dbhp = NULL;
		while (dbp) {
			dep = dbp->db_firstentry;
			while (dep) {
				if (dep->de_rb)
					kmem_free((caddr_t)dep->de_rb,
					    dep->de_recsize);
				dep2 = dep->de_next;
				kmem_free((caddr_t)dep, sizeofde(dep));
				dep = dep2;
			}
			dbp1 = dbp->db_next;
			kmem_free((caddr_t)dbp, sizeof (mddb_db_t));
			dbp = dbp1;
		}
	}
	s->s_dbp = dbhp;
	return (err);
}

static int
getoptcnt(
	mddb_set_t	*s,
	int		li)
{
	int		result;
	mddb_de_ic_t	*dep;
	mddb_db_t	*dbp;

#if defined(_ILP32) && !defined(lint)
	ASSERT(sizeof (mddb_de_t) == sizeof (mddb_de32_t));
	ASSERT(sizeof (mddb_db_t) == sizeof (mddb_db32_t));
#endif

	result = 0;
	for (dbp = s->s_dbp; dbp != NULL; dbp = dbp->db_next) {
		dep = dbp->db_firstentry;
		for (; dep != NULL; dep = dep->de_next) {
			if (! (dep->de_flags & MDDB_F_OPT))
				continue;
			if (((dep->de_optinfo[0].o_flags & MDDB_F_ACTIVE) &&
			    (li == dep->de_optinfo[0].o_li)) ||
			    ((dep->de_optinfo[1].o_flags & MDDB_F_ACTIVE) &&
			    (li == dep->de_optinfo[1].o_li)))
			result++;
		}
	}
	return (result);
}

static void
getoptdev(
	mddb_set_t	*s,
	mddb_de_ic_t	*rdep,
	int		opti
)
{
	mddb_lb_t	*lbp;
	mddb_locator_t	*lp;
	mddb_optinfo_t	*otherop;
	mddb_optinfo_t	*resultop;
	int		li;
	dev_t		otherdev;
	int		blkonly = 0;
	int		mincnt;
	int		thiscnt;

	lbp = s->s_lbp;

	resultop = &rdep->de_optinfo[opti];
	otherop = &rdep->de_optinfo[1-opti];

	resultop->o_flags = 0;

	/*
	 * scan through and see if data bases have to vary by only device
	 */

	if (otherop->o_flags & MDDB_F_ACTIVE) {
		blkonly = 1;
		otherdev = expldev(lbp->lb_locators[otherop->o_li].l_dev);
		for (li = 0; li < lbp->lb_loccnt; li++) {
			lp = &lbp->lb_locators[li];
			if (! (lp->l_flags & MDDB_F_ACTIVE))
				continue;
			if (expldev(lp->l_dev) != otherdev) {
				blkonly = 0;
				break;
			}
		}
	}

	mincnt = 999999;
	for (li = 0; li < lbp->lb_loccnt; li++) {
		dev_info_t	*devi;
		int		removable = 0;

		lp = &lbp->lb_locators[li];
		if (! (lp->l_flags & MDDB_F_ACTIVE))
			continue;
		if (otherop->o_flags & MDDB_F_ACTIVE) {
			if (blkonly) {
				if (otherop->o_li == li)
					continue;
			} else {
				if (otherdev == expldev(lp->l_dev))
					continue;
			}
		}

		/*
		 * Check if this is a removable device.  If it is we
		 * assume it is something like a USB flash disk, a zip disk
		 * or even a floppy that is being used to help maintain
		 * mddb quorum.  We don't want to put any optimized resync
		 * records on these kinds of disks since they are usually
		 * slower or don't have the same read/write lifetimes as
		 * a regular fixed disk.
		 */
		if ((devi = e_ddi_hold_devi_by_dev(lp->l_dev, 0)) != NULL) {
			int		error;
			struct cb_ops	*cb;
			ddi_prop_op_t	prop_op = PROP_LEN_AND_VAL_BUF;
			int		propvalue = 0;
			int		proplength = sizeof (int);

			if ((cb = devopsp[getmajor(lp->l_dev)]->devo_cb_ops)
			    != NULL) {
				error = (*cb->cb_prop_op)(DDI_DEV_T_ANY, devi,
				    prop_op, DDI_PROP_NOTPROM |
				    DDI_PROP_DONTPASS, "removable-media",
				    (caddr_t)&propvalue, &proplength);

				if (error == DDI_PROP_SUCCESS)
					removable = 1;
			}

			ddi_release_devi(devi);
		}

		if (removable)
			continue;

		thiscnt = getoptcnt(s, li);
		if (thiscnt < mincnt) {
			resultop->o_li  = li;
			mincnt = thiscnt;
			resultop->o_flags = MDDB_F_ACTIVE;
		}
	}
}

static void
allocuserdata(
	mddb_de_ic_t	*dep
)
{
	mddb_rb32_t	*rbp;

#if defined(_ILP32) && !defined(lint)
	ASSERT(sizeof (mddb_rb_t) == sizeof (mddb_rb32_t));
#endif

	rbp = dep->de_rb;
	rbp->rb_private = 0;
	dep->de_rb_userdata = kmem_zalloc(dep->de_reqsize, KM_SLEEP);
	rbp->rb_userdata = 0x4;	/* Make sure this is non-zero */
	bcopy((caddr_t)rbp->rb_data, dep->de_rb_userdata, dep->de_reqsize);
}


static void
getuserdata(
	set_t		setno,
	mddb_de_ic_t	*dep
)
{
	mddb_rb32_t	 *rbp;


	mddb_type_t	type = dep->de_type1;
	caddr_t		data, udata;

#if defined(_ILP32) && !defined(lint)
	ASSERT(sizeof (mddb_rb_t) == sizeof (mddb_rb32_t));
#endif
	rbp = dep->de_rb;
	data = (caddr_t)rbp->rb_data;
	udata = (caddr_t)dep->de_rb_userdata;

	/*
	 * If it's a driver record, and an old style record, and not a DRL
	 * record, we must convert it because it was incore as a 64 bit
	 * structure but its on disk layout has only 32 bit for block sizes
	 */
	if (!(md_get_setstatus(setno) &
	    (MD_SET_IMPORT | MD_SET_REPLICATED_IMPORT)) &&
	    (type >= MDDB_FIRST_MODID) &&
	    ((rbp->rb_revision == MDDB_REV_RB) ||
	    (rbp->rb_revision == MDDB_REV_RBFN))) {

		switch (dep->de_flags) {

			case MDDB_F_STRIPE:
				stripe_convert(data, udata, BIG_2_SMALL);
				break;

			case MDDB_F_MIRROR:
				mirror_convert(data, udata, BIG_2_SMALL);
				break;

			case MDDB_F_RAID:
				raid_convert(data, udata, BIG_2_SMALL);
				break;

			case MDDB_F_SOFTPART:
				softpart_convert(data, udata, BIG_2_SMALL);
				break;

			case MDDB_F_TRANS_MASTER:
				trans_master_convert(data, udata, BIG_2_SMALL);
				break;

			case MDDB_F_TRANS_LOG:
				trans_log_convert(data, udata, BIG_2_SMALL);
				break;

			case MDDB_F_HOTSPARE:
				hs_convert(data, udata, BIG_2_SMALL);
				break;

			case MDDB_F_OPT:
			default:
				bcopy(udata, data, dep->de_reqsize);
		}
	} else {
		bcopy(udata, data, dep->de_reqsize);
	}
}

static void
getoptrecord(
	mddb_set_t	*s,
	mddb_de_ic_t	*dep
)
{
	mddb_lb_t	*lbp;
	mddb_locator_t	*lp;
	mddb_rb32_t	*rbp, *crbp;
	int		li;
	int		i;
	int		err = 0;
	size_t		recsize;

#if defined(_ILP32) && !defined(lint)
	ASSERT(sizeof (mddb_rb_t) == sizeof (mddb_rb32_t));
#endif

	lbp = s->s_lbp;

	recsize = dep->de_recsize;
	dep->de_rb = (mddb_rb32_t *)kmem_zalloc(recsize, KM_SLEEP);
	rbp = dep->de_rb;
	crbp = (mddb_rb32_t *)kmem_zalloc(recsize, KM_SLEEP);

	dep->de_optinfo[0].o_flags |= MDDB_F_EDATA;
	dep->de_optinfo[1].o_flags |= MDDB_F_EDATA;

	for (i = 0; i < 2; i++) {
		if (! (dep->de_optinfo[i].o_flags & MDDB_F_ACTIVE))
			continue;
		li = dep->de_optinfo[i].o_li;
		lp = &lbp->lb_locators[li];

		if (! (lp->l_flags & MDDB_F_ACTIVE) ||
		    (lp->l_flags & MDDB_F_EMASTER))
			continue;

		err = readblklst(s, (caddr_t)rbp, dep->de_blks,
		    dep->de_blkcount, li, 0);

		if (err)
			continue;

		if (rbp->rb_magic != MDDB_MAGIC_RB)
			continue;

		if (revchk(MDDB_REV_RB, rbp->rb_revision))
			continue;

		/* Check the crc for this record */
		if (rec_crcchk(s, dep, rbp)) {
			continue;
		}

		dep->de_optinfo[i].o_flags = MDDB_F_ACTIVE;

		if (rbp == crbp) {
			if (rbp->rb_checksum != crbp->rb_checksum)
				dep->de_optinfo[1].o_flags |= MDDB_F_EDATA;
			break;
		}
		rbp = crbp;
	}

	if (rbp == crbp) {
		rbp->rb_private = 0;
		kmem_free((caddr_t)crbp, recsize);
		return;
	}
	bzero((caddr_t)rbp, recsize);
	rbp->rb_magic = MDDB_MAGIC_RB;
	rbp->rb_revision = MDDB_REV_RB;
	uniqtime32(&rbp->rb_timestamp);
	/* Generate the crc for this record */
	rec_crcgen(s, dep, rbp);
	kmem_free((caddr_t)crbp, recsize);
}

/*
 * writeoptrecord writes out an optimized record.
 */
static int
writeoptrecord(
	mddb_set_t	*s,
	mddb_de_ic_t	*dep
)
{
	mddb_rb32_t	*rbp;
	int		li;
	int		err = 0, wrt_err = 0;
	mddb_bf_t	*bufhead, *bfp;
	mddb_lb_t	*lbp = s->s_lbp;
	mddb_locator_t	*lp;
	int		i;

#if defined(_ILP32) && !defined(lint)
	ASSERT(sizeof (mddb_rb_t) == sizeof (mddb_rb32_t));
#endif

	bufhead = NULL;
	err = 0;

	while (s->s_opthavequeuinglck) {
		s->s_optwantqueuinglck++;
		cv_wait(&s->s_optqueuing_cv, SETMUTEX(s->s_setno));
	}
	s->s_opthavequeuinglck++;
	rbp = dep->de_rb;
	for (i = 0; i < 2; i++) {
		/*
		 * only possible error is xlate. This can
		 * occur if a replica was off line and came
		 * back. During the mean time the database grew
		 * large than the now on line replica can store
		 */
		if (! (dep->de_optinfo[i].o_flags & MDDB_F_ACTIVE))
			continue;
		li = dep->de_optinfo[i].o_li;
		/*
		 * In a MN diskset, any node can write optimized record(s).
		 */
		wrt_err = wrtblklst(s, (caddr_t)rbp, dep->de_blks,
		    dep->de_blkcount, li, &bufhead, MDDB_WR_ANY_NODE);
		/*
		 * For MN diskset, set error in optinfo structure so
		 * that mddb_commitrec knows which replica failed.
		 */
		if ((MD_MNSET_SETNO(s->s_setno)) &&
		    (wrt_err & MDDB_F_EWRITE)) {
			dep->de_optinfo[i].o_flags |= MDDB_F_EWRITE;
		}
		err |= wrt_err;
	}
	s->s_opthavequeuinglck = 0;
	if (s->s_optwantqueuinglck) {
		s->s_optwantqueuinglck = 0;
		cv_broadcast(&s->s_optqueuing_cv);
	}
	for (bfp = bufhead; bfp; bfp = bufhead) {
		mutex_exit(SETMUTEX(s->s_setno));
		(void) biowait(&bfp->bf_buf);
		mutex_enter(SETMUTEX(s->s_setno));
		if (bfp->bf_buf.b_flags & B_ERROR) {
			/*
			 * If an MN diskset, don't set replica
			 * in error since this hasn't been set in master.
			 * Setting replica in error before master could
			 * leave the nodes with different views of the
			 * world since a class 1 configuration change
			 * could occur in mddb_commitrec as soon as
			 * all locks are dropped.  Must keep this
			 * node the same as master and can't afford a
			 * failure from the class 1 config change
			 * if master succeeded.
			 */
			if (!(MD_MNSET_SETNO(s->s_setno))) {
				bfp->bf_locator->l_flags |= MDDB_F_EWRITE;
			} else {
				/*
				 * Find which de_optinfo (which replica)
				 * had a failure and set the failure in
				 * the o_flags field.
				 */
				lp = &lbp->lb_locators[dep->de_optinfo[0].o_li];
				if (lp == bfp->bf_locator) {
					dep->de_optinfo[0].o_flags |=
					    MDDB_F_EWRITE;
				} else {
					dep->de_optinfo[1].o_flags |=
					    MDDB_F_EWRITE;
				}
			}
			err |= MDDB_F_EWRITE;
		}
		bufhead = bfp->bf_next;
		freebuffer(s, bfp);
	}
	return (err);
}

/*
 * Fix up the optimized resync record.  Used in the traditional and local
 * disksets to move an optimized record from a failed or deleted mddb
 * to an active one.
 *
 * In a MN diskset, the fixing of the optimized record is split between
 * the master and slave nodes.  If the master node moves the optimized
 * resync record, then the master node will send a MDDB_PARSE_OPTRECS
 * message to the slave nodes causing the slave nodes to reget the
 * directory entry containing the location of the optimized resync record.
 * After the record is reread from disk, then writeoptrecord is called
 * if the location of the optimized resync record or flags have changed.
 * When writeoptrecord is called, the node that is the owner of this record
 * will write the optimized record to the location specified in the directory
 * entry.  Since the master node uses the highest class message (PARSE)
 * the record owner node is guaranteed to already have an updated
 * directory entry incore.
 *
 * The other difference between the traditional/local set and MN diskset
 * is that the directory entry can be written to disk before the optimized
 * record in a MN diskset if the record is owned by a slave node.  So,
 * the users of an optimized record must handle the failure case when no
 * data is available from an optimized record since the master node could
 * have failed during the relocation of the optimized record to another mddb.
 */
static int
fixoptrecord(
	mddb_set_t	*s,
	mddb_de_ic_t	*dep,
	mddb_db_t	*dbp
)
{
	int		changed;
	int		writedata;
	int		err = 0;
	int		i;
	mddb_lb_t	*lbp;
	mddb_optinfo_t	*op;
	mddb_db32_t	*db32p;
	int		rec_owner;	/* Is node owner of record? */

#if defined(_ILP32) && !defined(lint)
	ASSERT(sizeof (mddb_db_t) == sizeof (mddb_db32_t));
#endif

	lbp = s->s_lbp;
	changed = 0;
	writedata = 0;
	for (i = 0; i < 2; i++) {
		op = &dep->de_optinfo[i];

		if (! (lbp->lb_locators[op->o_li].l_flags & MDDB_F_ACTIVE))
			op->o_flags = 0;

		/*
		 * If optimized record has seen a replica failure,
		 * assign new replica to record and re-write data
		 * to new record.
		 */
		if (! (op->o_flags & MDDB_F_ACTIVE)) {
			getoptdev(s, dep, i);
			writedata++;
			changed++;
			/* Set flag for slaves to reread dep and write rec */
			if (lbp->lb_flags & MDDB_MNSET) {
				s->s_mn_parseflags |= MDDB_PARSE_OPTRECS;
			}
		}

		/*
		 * If just an error in the data was seen, set
		 * the optimized record's replica flag to active (ok)
		 * and try again.
		 */
		if (op->o_flags & MDDB_F_EDATA) {
			dep->de_optinfo[0].o_flags = MDDB_F_ACTIVE;
			writedata++;
		}
	}

	rec_owner = 0;
	if (lbp->lb_flags & MDDB_MNSET) {
		/*
		 * If a MN diskset then check the owner of optimized record.
		 * If the master node owns the record or if there is
		 * no owner of the record, then the master can write the
		 * optimized record to disk.
		 * Master node can write the optimized record now, but
		 * slave nodes write their records during handling of
		 * the MDDB_PARSE_OPTRECS message.
		 */
		if ((dep->de_owner_nodeid == MD_MN_INVALID_NID) ||
		    (dep->de_owner_nodeid == md_set[s->s_setno].s_nodeid)) {
			rec_owner = 1;
		}
	} else {
		/*
		 * In traditional diskset and local set, this node
		 * is always the record owner and always the master.
		 */
		rec_owner = 1;
	}

	/*
	 * If this node is the record owner, write out record.
	 */
	if ((writedata) && (rec_owner)) {
		if (err = writeoptrecord(s, dep)) {
			return (err);
		}
	}
	if (! changed)
		return (0);
	uniqtime32(&dbp->db_timestamp);
	dbp->db_revision = MDDB_REV_DB;
	db32p = (mddb_db32_t *)kmem_zalloc(MDDB_BSIZE, KM_SLEEP);
	create_db32rec(db32p, dbp);
	crcgen(db32p, &db32p->db32_checksum, MDDB_BSIZE, NULL);
	err = writeall(s, (caddr_t)db32p, db32p->db32_blknum,
	    1, MDDB_WR_ONLY_MASTER);
	kmem_free((caddr_t)db32p, MDDB_BSIZE);
	return (err);
}

static int
fixoptrecords(
	mddb_set_t		*s
)
{
	mddb_de_ic_t	*dep;
	mddb_db_t	*dbp;
	int		err = 0;
	set_t		setno;

	/*
	 * In a MN diskset, the master node is the only node that runs
	 * fixoptrecords.  If the master node changes anything, then the
	 * master node sends PARSE message to the slave nodes.  The slave
	 * nodes will then re-read in the locator block or re-read in the
	 * directory blocks and re-write the optimized resync records.
	 */
	setno = s->s_setno;
	if ((setno != MD_LOCAL_SET) && (s->s_lbp->lb_flags & MDDB_MNSET) &&
	    (md_set[setno].s_am_i_master == 0)) {
		return (0);
	}

	for (dbp = s->s_dbp; dbp != NULL; dbp = dbp->db_next) {
		for (dep = dbp->db_firstentry; dep; dep = dep->de_next) {
			if (! (dep->de_flags & MDDB_F_OPT))
				continue;
			err = fixoptrecord(s, dep, dbp);
			if (err != 0)
				return (err);
		}
	}
	return (0);
}

/*
 * Checks incore version of mddb data to mddb data ondisk.
 *
 * Returns:
 *	- 0 if the data was successfully read and is good.
 *	- MDDB_F_EREAD if a read error occurred.
 *	- 1 if the data read is bad (checksum failed, etc)
 */
static int
checkcopy
(
	mddb_set_t	*s,
	int		li
)
{
	mddb_db_t	*dbp;
	mddb_db32_t	*cdb32p;
	mddb_de_ic_t	*dep;
	mddb_de32_t	*cde32p;
	mddb_rb32_t	*rbp, *crbp;
	size_t		size;
	int		i;
	int		retval = 1;

#if defined(_ILP32) && !defined(lint)
	ASSERT(sizeof (mddb_de_t) == sizeof (mddb_de32_t));
	ASSERT(sizeof (mddb_db_t) == sizeof (mddb_db32_t));
	ASSERT(sizeof (mddb_rb_t) == sizeof (mddb_rb32_t));
#endif

	if (s->s_databuffer_size == 0) {
		size_t maxrecsize = MDDB_BSIZE;

		for (dbp = s->s_dbp; dbp != NULL; dbp = dbp->db_next)
			for (dep = dbp->db_firstentry; dep; dep = dep->de_next)
				if (! (dep->de_flags & MDDB_F_OPT) &&
				    dep->de_recsize > maxrecsize)
					maxrecsize = dep->de_recsize;

		s->s_databuffer = (caddr_t)kmem_zalloc(maxrecsize, KM_SLEEP);
		s->s_databuffer_size = maxrecsize;
	}

	cdb32p = (mddb_db32_t *)s->s_databuffer;

	/*
	 * first go through and make sure all directory stuff
	 * is the same
	 */
	for (dbp = s->s_dbp; dbp != NULL; dbp = dbp->db_next) {
		if (readblks(s, (caddr_t)cdb32p, dbp->db_blknum, 1, li)) {
			retval = MDDB_F_EREAD;
			goto err;
		}
		if (cdb32p->db32_magic != MDDB_MAGIC_DB)
			goto err;
		if (revchk(MDDB_REV_DB, cdb32p->db32_revision))
			goto err;
		if (crcchk(cdb32p, &cdb32p->db32_checksum, MDDB_BSIZE, NULL))
			goto err;
		if (cdb32p->db32_nextblk != dbp->db_nextblk)
			goto err;
		if (cdb32p->db32_recsum != dbp->db_recsum)
			goto err;
		if (cdb32p->db32_firstentry) {
			cde32p = (mddb_de32_t *)
			    ((void *)((caddr_t)(&cdb32p->db32_firstentry)
			    + sizeof (cdb32p->db32_firstentry)));
		} else
			cde32p = NULL;

		dep = dbp->db_firstentry;
		/*
		 * check if all directory entries are identical
		 */
		while (dep && cde32p) {
			if (dep->de_recid != cde32p->de32_recid)
				goto err;
			if (dep->de_type1 != cde32p->de32_type1)
				goto err;
			if (dep->de_type2 != cde32p->de32_type2)
				goto err;
			if (dep->de_reqsize != cde32p->de32_reqsize)
				goto err;
			if (dep->de_flags != cde32p->de32_flags)
				goto err;

			for (i = 0; i < 2; i++) {
				if (dep->de_optinfo[i].o_li !=
				    cde32p->de32_optinfo[i].o_li)
					break;
			}
			if (i != 2)
				goto err;
			size = sizeof (mddb_block_t) * dep->de_blkcount;
			if (bcmp((caddr_t)dep->de_blks,
			    (caddr_t)cde32p->de32_blks, size))
				goto err;
			dep = dep->de_next;
			if (cde32p->de32_next)
				cde32p = nextentry(cde32p);
			else
				cde32p = NULL;
		}
		if (dep || cde32p)
			goto err;
	}
	/*
	 * If here, all directories are functionally identical
	 * check to make sure all records are identical
	 * the reason the records are not just bcmped is that the
	 * lock flag does not want to be compared.
	 */
	crbp = (mddb_rb32_t *)cdb32p;
	for (dbp = s->s_dbp; dbp != NULL; dbp = dbp->db_next) {
		for (dep = dbp->db_firstentry; dep; dep = dep->de_next) {
			if ((dep->de_flags & MDDB_F_OPT) ||
			    (dep->de_flags & MDDB_F_CHANGELOG))
				continue;
			rbp = (mddb_rb32_t *)dep->de_rb;
			if (readblklst(s, (caddr_t)crbp, dep->de_blks,
			    dep->de_blkcount, li, 0)) {
				retval = MDDB_F_EREAD;
				goto err;
			}
			/* Check the crc for this record */
			if (rec_crcchk(s, dep, crbp))
				goto err;

			if (rbp->rb_checksum != crbp->rb_checksum ||
			    rbp->rb_checksum_fiddle != crbp->rb_checksum_fiddle)
				goto err;
		}
	}
	return (0);
err:
	return (retval);
}

/*
 * Determine if the location information for two mddbs is the same.
 * The device slice and block offset should match.  If both have devids then
 * use that for the comparison, otherwise we compare the dev_ts.
 * Comparing with the devid allows us to handle the case where a mddb was
 * relocated to a dead mddbs dev_t.  The live mddb will have the dev_t of
 * the dead mddb but the devid comparison will catch this and not match.
 *
 * Return 1 if the location of the two mddbs match, 0 if not.
 */
static int
match_mddb(mddb_ri_t *rip, ddi_devid_t devid, char *minor, md_dev64_t dev,
	daddr32_t blkno)
{
	if (rip->ri_flags & MDDB_F_EMASTER) {
		/*
		 * If this element is errored then we don't try to match on it.
		 * If we try to match we could erroneously match on the dev_t
		 * of a relocated disk.
		 */
		return (0);
	}

	if (rip->ri_devid && devid && minor) {
		/*
		 * If old devid exists, then this is a replicated diskset
		 * and both old and new devids must be checked.
		 */
		if (rip->ri_old_devid) {
			if (((ddi_devid_compare(rip->ri_devid, devid) != 0) &&
			    (ddi_devid_compare(rip->ri_old_devid,
			    devid) != 0)) ||
			    (strcmp(rip->ri_minor_name, minor) != 0))
				return (0);
		} else {
			if (ddi_devid_compare(rip->ri_devid, devid) != 0 ||
			    strcmp(rip->ri_minor_name, minor) != 0)
				return (0);
		}
	} else {
		if (rip->ri_dev != dev)
			return (0);
	}

	if (rip->ri_blkno != blkno)
		return (0);

	return (1);
}

static int
ridev(
	mddb_ri_t	**rip,
	mddb_cfg_loc_t	*clp,
	dev32_t		*dev_2b_fixed,
	int		flag)
{
	mddb_ri_t	*r, *r1;
	md_dev64_t	ldev, ndev;
	major_t		majordev;
	int		sz;

	if (MD_UPGRADE) {
		ldev = md_makedevice(md_targ_name_to_major(clp->l_driver),
		    clp->l_mnum);
	} else {
		if (ddi_name_to_major(clp->l_driver) == (major_t)-1)
			return (EINVAL);

		ldev = md_makedevice(ddi_name_to_major(clp->l_driver),
		    clp->l_mnum);
	}

	if (clp->l_devid != 0) {
		/*
		 * Get dev associated with device id and minor name.
		 * Setup correct driver name if dev is now different.
		 * Don't change driver name if during upgrade.
		 */
		ndev = ldev;
		if (!mddb_devid_validate((ddi_devid_t)(uintptr_t)clp->l_devid,
		    &ndev, clp->l_minor_name)) {
			if ((ndev != ldev) && (!(MD_UPGRADE))) {
				majordev = md_getmajor(ndev);
				(void) strcpy(clp->l_driver,
				    ddi_major_to_name(majordev));
				clp->l_mnum = md_getminor(ndev);
				clp->l_devid_flags |= MDDB_DEVID_VALID;
				ldev = ndev;
			}
		} else {
			/* Mark as invalid */
			clp->l_devid_flags &= ~MDDB_DEVID_VALID;
		}
	}

	clp->l_dev = md_cmpldev(ldev);
	if (dev_2b_fixed)
		*dev_2b_fixed = clp->l_dev;
	r = *rip;

	while (r) {
		if (match_mddb(r, (ddi_devid_t)(uintptr_t)clp->l_devid,
		    clp->l_minor_name, ldev, clp->l_blkno)) {
			if ((clp->l_devid != 0) &&
			    !(clp->l_devid_flags & MDDB_DEVID_VALID)) {
				r->ri_flags |= MDDB_F_EMASTER;
			} else {
				r->ri_flags |= flag;
			}
			return (0);	/* already entered return success */
		}
		r = r->ri_next;
	}

	/*
	 * This replica not represented in the current rip list,
	 * so add it to the list.
	 */
	r = (mddb_ri_t *)kmem_zalloc(sizeof (**rip), KM_SLEEP);
	r->ri_dev = ldev;
	r->ri_blkno = clp->l_blkno;
	(void) strncpy(r->ri_driver, clp->l_driver, MD_MAXDRVNM);
	if (strlen(clp->l_driver) >= MD_MAXDRVNM) {
		r->ri_driver[(MD_MAXDRVNM -1)] = '\0';
	}
	if (clp->l_devname != NULL) {
		(void) strcpy(r->ri_devname, clp->l_devname);
	}
	r->ri_flags |= flag;
	if (clp->l_devid != 0) {
		sz = clp->l_devid_sz;
		r->ri_devid = (ddi_devid_t)kmem_zalloc(sz, KM_SLEEP);
		bcopy((void *)(uintptr_t)clp->l_devid, (char *)r->ri_devid, sz);

		if (clp->l_old_devid != NULL) {
			sz = clp->l_old_devid_sz;
			r->ri_old_devid = (ddi_devid_t)kmem_zalloc(sz,
			    KM_SLEEP);
			bcopy((char *)(uintptr_t)clp->l_old_devid,
			    (char *)r->ri_old_devid, sz);
		} else {
			r->ri_old_devid = 0;
		}
		if (strlen(clp->l_minor_name) < MDDB_MINOR_NAME_MAX)
			(void) strcpy(r->ri_minor_name, clp->l_minor_name);

		if (!(clp->l_devid_flags & MDDB_DEVID_VALID)) {
			/*
			 * Devid is present, but not valid.  This could
			 * happen if device has been powered off or if
			 * the device has been removed.  Mark the device in
			 * error.  Don't allow any writes to this device
			 * based on the dev_t since another device could
			 * have been placed in its spot and be responding to
			 * the dev_t accesses.
			 */
			r->ri_flags |= MDDB_F_EMASTER;
		}
	} else {
		r->ri_devid = 0;
		r->ri_old_devid = 0;
	}

	/*
	 * If the rip list is empty then this entry
	 * is the list.
	 */
	if (*rip == NULL) {
		*rip = r;
		return (0);
	}

	/*
	 * Add this entry to the end of the rip list
	 */
	r1 = *rip;
	while (r1->ri_next)
		r1 = r1->ri_next;
	r1->ri_next = r;
	return (0);
}

/*
 * writecopy writes the incore data blocks out to all of the replicas.
 * This is called from writestart
 *	- when a diskset is started or
 *	- when an error has been enountered during the write to a mddb.
 * and from newdev when a new mddb is being added.
 *
 * flag can be 2 values:
 *	MDDB_WRITECOPY_ALL - write all records to all mddbs.  This is
 *		always used for traditional and local disksets.
 *		For MN diskset:
 *			All nodes can call writecopy, but only the
 *			master node actually writes data to the disk
 *			except for optimized resync records.
 *			An optimized resync record can only be written to
 *			by the record owner.
 *	MDDB_WRITECOPY_SYNC - special case for MN diskset.  When a new
 *		master has been chosen, the new master may need to
 * 		write its incore mddb to disk (this is the case where the
 *		old master had executed a message but hadn't relayed it
 *		to this slave yet).  New master should not write the
 *		change log records since new master would be overwriting
 *		valuable data.  Only used during a reconfig cycle.
 */
static int
writecopy(
	mddb_set_t	*s,
	int		li,
	int		flag
)
{
	mddb_db_t	*dbp;
	mddb_db32_t	*db32p;
	mddb_de_ic_t	*dep;
	mddb_rb32_t	*rbp;
	uint_t		checksum;
	int		err = 0;

#if defined(_ILP32) && !defined(lint)
	ASSERT(sizeof (mddb_rb_t) == sizeof (mddb_rb32_t));
	ASSERT(sizeof (mddb_db_t) == sizeof (mddb_db32_t));
#endif

	for (dbp = s->s_dbp; dbp != NULL; dbp = dbp->db_next) {
		db32p = (mddb_db32_t *)kmem_zalloc(MDDB_BSIZE, KM_SLEEP);
		create_db32rec(db32p, dbp);
		crcgen(db32p, &db32p->db32_checksum, MDDB_BSIZE, NULL);
		err = writeblks(s, (caddr_t)db32p, dbp->db_blknum, 1, li,
		    MDDB_WR_ONLY_MASTER);
		kmem_free((caddr_t)db32p, MDDB_BSIZE);
		if (err)
			return (err);
		for (dep = dbp->db_firstentry; dep; dep = dep->de_next) {
			/*
			 * In a multinode diskset, when a new master is
			 * chosen the new master may need to write its
			 * incore copy of the mddb to disk.  In this case,
			 * don't want to overwrite the change log records
			 * so new master sets flag to MDDB_WRITECOPY_SYNC.
			 */
			if (flag == MDDB_WRITECOPY_SYNC) {
				if (dep->de_flags & MDDB_F_CHANGELOG)
					continue;
			}
			/*
			 * In a multinode diskset, don't write out optimized
			 * resync resyncs since only the mirror owner node
			 * will have the correct data.  If writecopy is
			 * being called from writestart as a result of
			 * an mddb failure, then writestart will handle
			 * the optimized records when it calls fixoptrecords.
			 */
			if ((MD_MNSET_SETNO(s->s_setno)) &&
			    (dep->de_flags & MDDB_F_OPT)) {
				continue;
			}

			rbp = dep->de_rb;
			checksum = rbp->rb_checksum_fiddle;
			checksum ^= rbp->rb_checksum;
			/* Generate the crc for this record */
			rec_crcgen(s, dep, rbp);
			checksum ^= rbp->rb_checksum;
			rbp->rb_checksum_fiddle = checksum;
			if (err = wrtblklst(s, (caddr_t)rbp, dep->de_blks,
			    dep->de_blkcount, li, (mddb_bf_t **)0,
			    MDDB_WR_ONLY_MASTER))
				return (err);
		}
	}
	return (0);
}

static int
upd_med(
	mddb_set_t	*s,
	char		*tag
)
{
	med_data_t	meddb;
	int		medok;
	mddb_lb_t	*lbp = s->s_lbp;
	set_t		setno = s->s_setno;
	int		li;
	int		alc;
	int		lc;


	/* If no mediator hosts, nothing to do */
	if (s->s_med.n_cnt == 0)
		return (0);

	/*
	 * If this is a MN set and we are not the master, then don't
	 * update mediator hosts or mark mediator as golden since
	 * only master node should do that.
	 */
	if ((setno != MD_LOCAL_SET) && (s->s_lbp->lb_flags & MDDB_MNSET) &&
	    (md_set[setno].s_am_i_master == 0)) {
		return (0);
	}

	bzero((char *)&meddb, sizeof (med_data_t));
	meddb.med_dat_mag = MED_DATA_MAGIC;
	meddb.med_dat_rev = MED_DATA_REV;
	meddb.med_dat_fl = 0;
	meddb.med_dat_sn = setno;
	meddb.med_dat_cc = lbp->lb_commitcnt;
	TIMEVAL32_TO_TIMEVAL(&meddb.med_dat_id, &lbp->lb_ident.createtime);
	crcgen(&meddb, &meddb.med_dat_cks, sizeof (med_data_t), NULL);

	/* count accessible mediators */
	medok = upd_med_hosts(&s->s_med, s->s_setname, &meddb, tag);

	/* count accessible and existing replicas */
	for (li = 0, alc = 0, lc = 0; li < lbp->lb_loccnt; li++) {
		mddb_locator_t	*lp = &lbp->lb_locators[li];

		if (lp->l_flags & MDDB_F_DELETED)
			continue;

		lc++;

		if (! (lp->l_flags & MDDB_F_ACTIVE) ||
		    (lp->l_flags & MDDB_F_EMASTER) ||
		    (lp->l_flags & MDDB_F_EWRITE))
			continue;

		alc++;
	}

	/*
	 * Mediator update quorum is >= 50%: check for less than
	 * "mediator update" quorum.
	 */
	if ((medok * 2) < s->s_med.n_cnt) {
		/* panic if <= 50% of all replicas are accessible */
		if ((lc > 0) && ((alc * 2) <= lc)) {
			cmn_err(CE_PANIC,
			    "md: Update of 50%% of the mediator hosts failed");
			/* NOTREACHED */
		}

		cmn_err(CE_WARN,
		    "md: Update of 50%% of the mediator hosts failed");
	}

	/*
	 * If we have mediator update quorum and exactly 50% of the replicas
	 * are accessible then mark the mediator as golden.
	 */
	if (((medok * 2) >= (s->s_med.n_cnt + 1)) && (lc > 0) &&
	    ((alc * 2) == lc)) {
		meddb.med_dat_fl = MED_DFL_GOLDEN;
		crcgen(&meddb, &meddb.med_dat_cks, sizeof (med_data_t), NULL);
		(void) upd_med_hosts(&s->s_med, s->s_setname, &meddb, tag);
	}

	return (0);
}

static int
push_lb(mddb_set_t *s)
{
	mddb_lb_t	*lbp = s->s_lbp;

	/* push the change to all the replicas */
	uniqtime32(&lbp->lb_timestamp);
	if (MD_MNSET_SETNO(s->s_setno)) {
		lbp->lb_revision = MDDB_REV_MNLB;
	} else {
		lbp->lb_revision = MDDB_REV_LB;
	}
	/*
	 * The updates to the mediator hosts are done
	 * by the callers of this function.
	 */
	return (writelocall(s));
}

/* Should not call for MN diskset since data tags are not supported */
static int
dtl_cmp(const mddb_dtag_t *odtp, const mddb_dtag_t *ndtp)
{
	int 		diff = 0;

	diff = (int)(odtp->dt_setno - ndtp->dt_setno);
	if (diff)
		return (diff);

	diff = strncmp(odtp->dt_sn, ndtp->dt_sn, MDDB_SN_LEN);
	if (diff)
		return (diff);

	diff = strncmp(odtp->dt_hn, ndtp->dt_hn, MD_MAX_NODENAME_PLUS_1);
	if (diff)
		return (diff);

	/*CSTYLED*/
	return (timercmp(&odtp->dt_tv, &ndtp->dt_tv, !=));
}

/* Should not call for MN diskset since data tags are not supported */
static int
dtl_addl(mddb_set_t *s, const mddb_dtag_t *ndtp)
{
	int		nextid = 0;
	mddb_dtag_lst_t **dtlpp = &s->s_dtlp;

	/* Run to the end of the list */
	for (/* void */; (*dtlpp != NULL); dtlpp = &(*dtlpp)->dtl_nx) {
		if (dtl_cmp(&(*dtlpp)->dtl_dt, ndtp) == 0)
			return (0);
		nextid++;
	}

	/* Add the new member */
	*dtlpp = kmem_zalloc(sizeof (**dtlpp), KM_SLEEP);

	/* Update the dtag portion of the list */
	bcopy((caddr_t)ndtp, (caddr_t)&((*dtlpp)->dtl_dt),
	    sizeof (mddb_dtag_t));

	/* Fix up the id value */
	(*dtlpp)->dtl_dt.dt_id = ++nextid;

	return (0);
}

/*
 * Even though data tags are not supported in MN disksets, dt_cntl may
 * be called for a MN diskset since this routine is called even before
 * it is known the kind of diskset being read in from disk.
 * For a MNdiskset, s_dtlp is 0 so a count of 0 is returned.
 */
static int
dtl_cntl(mddb_set_t *s)
{
	mddb_dtag_lst_t	*dtlp = s->s_dtlp;
	int		ndt = 0;

	while (dtlp != NULL) {
		ndt++;
		dtlp = dtlp->dtl_nx;
	}

	return (ndt);
}

/*
 * Even though data tags are not supported in MN disksets, dt_cntl may
 * be called for a MN diskset since this routine is called even before
 * it is known the kind of diskset being read in from disk.
 * For a MNdiskset, s_dtlp is 0 so a 0 is returned.
 */
static mddb_dtag_t *
dtl_findl(mddb_set_t *s, int id)
{
	mddb_dtag_lst_t	*dtlp = s->s_dtlp;

	while (dtlp != NULL) {
		if (dtlp->dtl_dt.dt_id == id)
			return (&dtlp->dtl_dt);
		dtlp = dtlp->dtl_nx;
	}
	return ((mddb_dtag_t *)NULL);
}

/* Should not call for MN diskset since data tags are not supported */
static void
dtl_freel(mddb_dtag_lst_t **dtlpp)
{
	mddb_dtag_lst_t	*dtlp;
	mddb_dtag_lst_t	*tdtlp;


	for (tdtlp = *dtlpp; tdtlp != NULL; tdtlp = dtlp) {
		dtlp = tdtlp->dtl_nx;
		kmem_free(tdtlp, sizeof (mddb_dtag_lst_t));
	}
	*dtlpp = (mddb_dtag_lst_t *)NULL;
}

/*
 * Even though data tags are not supported in MN disksets, dt_setup will
 * be called for a MN diskset since this routine is called even before
 * it is known the kind of diskset being read in from disk.
 * Once this set is known as a MN diskset, the dtp area will be freed.
 */
static void
dt_setup(mddb_set_t *s, const mddb_dtag_t *dtagp)
{
	mddb_dt_t	*dtp;
	set_t		setno = s->s_setno;


	if (md_set[setno].s_dtp == (mddb_dt_t *)NULL)
		md_set[setno].s_dtp = kmem_zalloc(MDDB_DT_BYTES, KM_SLEEP);
	else if (dtagp == (mddb_dtag_t *)NULL)
		bzero((caddr_t)md_set[setno].s_dtp, MDDB_DT_BYTES);

	/* shorthand */
	dtp = (mddb_dt_t *)md_set[setno].s_dtp;

	dtp->dt_mag = MDDB_MAGIC_DT;
	dtp->dt_rev = MDDB_REV_DT;

	if (dtagp != NULL)
		dtp->dt_dtag = *dtagp;		/* structure assignment */

	/* Initialize the setno */
	dtp->dt_dtag.dt_setno = setno;

	/* Clear the id and flags, this is only used in user land */
	dtp->dt_dtag.dt_id = 0;

	/* Checksum it */
	crcgen(dtp, &dtp->dt_cks, MDDB_DT_BYTES, NULL);
}

/* Should not call for MN diskset since data tags are not supported */
static int
set_dtag(mddb_set_t *s, md_error_t *ep)
{
	mddb_lb_t	*lbp = s->s_lbp;
	mddb_dtag_t	tag;

	if (lbp->lb_dtblkcnt == 0) {
		/* Data tags not used in a MN set - so no failure returned */
		if (lbp->lb_flags & MDDB_MNSET)
			return (0);

		cmn_err(CE_WARN,
		    "No tag record allocated, unable to tag data");
		(void) mdmddberror(ep, MDE_DB_NOTAGREC, NODEV32, s->s_setno);
		return (1);
	}

	/* Clear the stack variable */
	bzero((caddr_t)&tag, sizeof (mddb_dtag_t));

	/* Get the HW serial number for this host */
	(void) strncpy(tag.dt_sn, hw_serial, MDDB_SN_LEN);
	tag.dt_sn[MDDB_SN_LEN - 1] = '\0';

	/* Get the nodename that this host goes by */
	(void) strncpy(tag.dt_hn, utsname.nodename, MD_MAX_NODENAME);
	tag.dt_hn[MD_MAX_NODENAME] = '\0';

	/* Get a time stamp for NOW */
	uniqtime32(&tag.dt_tv);

	/* Setup the data tag record */
	dt_setup(s, &tag);

	/* Free any list of tags if they exist */
	dtl_freel(&s->s_dtlp);

	/* Put the new tag onto the tag list */
	(void) dtl_addl(s, &tag);

	return (0);
}

/*
 * If called during upgrade, this routine expects a non-translated
 * (aka target) dev.
 * Should not call for MN diskset since data tags are not supported.
 */
static int
dt_read(mddb_set_t *s, mddb_lb_t *lbp, mddb_ri_t *rip)
{
	int		err = 0;
	md_dev64_t	dev;
	caddr_t		tbuf;
	daddr_t		physblk;
	mddb_block_t	blk;
	mddb_dt_t	*dtp;
	mddb_dtag_t	*dtagp;
	set_t		setno = s->s_setno;

	/* If have not allocated a data tag record, there is nothing to do */
	if (lbp->lb_dtblkcnt == 0)
		return (1);

	dtp = rip->ri_dtp = (mddb_dt_t *)kmem_zalloc(MDDB_DT_BYTES, KM_SLEEP);

	if (dtp == (mddb_dt_t *)NULL)
		return (1);

	/* shorthand */
	dev = md_xlate_targ_2_mini(rip->ri_dev);
	if (dev == NODEV64) {
		return (1);
	}

	tbuf = (caddr_t)rip->ri_dtp;

	for (blk = 0; blk < lbp->lb_dtblkcnt; blk++) {
		physblk = getphysblk((blk + lbp->lb_dtfirstblk), rip->ri_mbip);
		err = getblks(s, tbuf, dev, physblk, btodb(MDDB_BSIZE), 0);
		/* error reading the tag */
		if (err) {
			err = 1;
			goto out;
		}
		tbuf += MDDB_BSIZE;
	}

	/* magic is valid? */
	if (dtp->dt_mag != MDDB_MAGIC_DT) {
		err = 1;
		goto out;
	}

	/* revision is valid? */
	if (revchk(MDDB_REV_DT, dtp->dt_rev)) {
		err = 1;
		goto out;
	}

	/* crc is valid? */
	if (crcchk(dtp, &dtp->dt_cks, MDDB_DT_BYTES, NULL)) {
		err = 1;
		goto out;
	}

	/* shorthand */
	dtagp = &dtp->dt_dtag;

	/* set number match? */
	if (dtagp->dt_setno != setno) {
		err = 1;
		goto out;
	}

	/* tag is not empty? */
	if (dtagp->dt_sn[0] == '\0' && dtagp->dt_hn[0] == '\0' &&
	    (dtagp->dt_tv.tv_sec == 0 && dtagp->dt_tv.tv_usec == 0) &&
	    dtagp->dt_id == 0) {
		err = 2;
		goto out;
	}

	/* Mark the locator as having tagged data */
	rip->ri_flags |= MDDB_F_TAGDATA;

out:
	if (err) {
		if (err == 1) {
			md_set_setstatus(setno, MD_SET_BADTAG);
			rip->ri_flags |= MDDB_F_BADTAG;
		}
		if (dtp != NULL) {
			kmem_free(dtp, MDDB_DT_BYTES);
			rip->ri_dtp = (mddb_dt_t *)NULL;
		}
	}

	return (err);
}

/* Should not call for MN diskset since data tags are not supported */
static int
dt_write(mddb_set_t *s)
{
	int		li;
	int		err = 0;
	int		werr;
	int		empty_tag = 0;
	mddb_dtag_t	*dtagp;
	mddb_dt_t	*dtp;
	mddb_lb_t	*lbp = s->s_lbp;
	set_t		setno = s->s_setno;
	uint_t		set_status = md_get_setstatus(setno);


	ASSERT(md_set[setno].s_dtp != NULL);

	/* Nowhere to write to */
	if (lbp->lb_dtblkcnt == 0)
		return (err);

	if (set_status & MD_SET_BADTAG)
		return (err);

	/* shorthand */
	dtp = (mddb_dt_t *)md_set[setno].s_dtp;
	dtagp = &dtp->dt_dtag;

	/* See if the tag is empty. */
	if (dtagp->dt_sn[0] == '\0' && dtagp->dt_hn[0] == '\0' &&
	    (dtagp->dt_tv.tv_sec == 0 && dtagp->dt_tv.tv_usec == 0) &&
	    dtagp->dt_id == 0)
		empty_tag = 1;

	/* Write the tag to the locators and reset appropriate flags. */
	for (li = 0; li < lbp->lb_loccnt; li++) {
		mddb_locator_t	*lp = &lbp->lb_locators[li];

		if ((! (lp->l_flags & MDDB_F_ACTIVE)) ||
		    (lp->l_flags & MDDB_F_DELETED) ||
		    (lp->l_flags & MDDB_F_EWRITE))
			continue;

		werr = writeblks(s, (caddr_t)dtp, lbp->lb_dtfirstblk,
		    MDDB_DT_BLOCKS, li, MDDB_WR_ONLY_MASTER);

		if (werr) {
			err |= werr;
			continue;
		}

		if (empty_tag)
			lp->l_flags &= ~(MDDB_F_BADTAG | MDDB_F_TAGDATA);
		else {
			lp->l_flags |= MDDB_F_TAGDATA;
			lp->l_flags &= ~MDDB_F_BADTAG;
		}
	}

	if (err)
		return (err);


	/* If the tags were written, check to see if any tags remain. */
	for (li = 0; li < lbp->lb_loccnt; li++) {
		mddb_locator_t	*lp = &lbp->lb_locators[li];

		if ((! (lp->l_flags & MDDB_F_ACTIVE)) ||
		    (lp->l_flags & MDDB_F_DELETED) ||
		    (lp->l_flags & MDDB_F_EWRITE))
			continue;

		if (lp->l_flags & MDDB_F_TAGDATA)
			break;
	}

	/* If there are no tags, then clear CLRTAG and TAGDATA */
	if (li == lbp->lb_loccnt) {
		md_clr_setstatus(setno, MD_SET_CLRTAG);
		md_clr_setstatus(setno, MD_SET_TAGDATA);
	}

	return (err);
}

/* Should not call for MN diskset since data tags are not supported */
static int
dt_alloc_if_needed(mddb_set_t *s)
{
	int		i;
	int		li;
	int		moveit = 0;
	mddb_lb_t	*lbp = s->s_lbp;
	mddb_block_t	blkcnt = lbp->lb_dtblkcnt;
	set_t		setno = s->s_setno;
	uint_t		set_status = md_get_setstatus(setno);

	/*
	 * If the data tag record is allocated (blkcnt != 0) and a bad tag was
	 * not detected, there is nothing to do.
	 */
	if (blkcnt != 0 && ! (set_status & MD_SET_BADTAG))
		return (0);

	/* Bitmap not setup, checks can't be done */
	if (s->s_totalblkcnt == 0)
		return (0);

	/* While reading the tag(s) an invalid tag data record was seen */
	if (set_status & MD_SET_BADTAG)
		/* See if the invalid tag needs to be moved */
		for (i = 0; i < MDDB_DT_BLOCKS; i++)
			if (blkcheck(s, (i + lbp->lb_dtfirstblk))) {
				moveit = 1;
				break;
			}

	/* Need to move or allocate the tag data record */
	if (moveit || blkcnt == 0) {
		lbp->lb_dtfirstblk = getfreeblks(s, MDDB_DT_BLOCKS);
		if (lbp->lb_dtfirstblk == 0) {
			cmn_err(CE_WARN,
			    "Unable to allocate data tag record");
			return (0);
		}
		lbp->lb_dtblkcnt = MDDB_DT_BLOCKS;

		/* Mark the locators so that they get written to disk. */
		for (li = 0; li < lbp->lb_loccnt; li++) {
			mddb_locator_t	*lp = &lbp->lb_locators[li];

			if ((! (lp->l_flags & MDDB_F_ACTIVE)) ||
			    (lp->l_flags & MDDB_F_DELETED) ||
			    (lp->l_flags & MDDB_F_EWRITE))
				continue;

			lp->l_flags |= MDDB_F_BADTAG;
		}
		return (1);
	}

	/*
	 * Make sure the blocks are owned, since the calculation in
	 * computefreeblks() is bypassed when MD_SET_BADTAG is set.
	 */
	for (i = 0; i < MDDB_DT_BLOCKS; i++)
		blkbusy(s, (i + lbp->lb_dtfirstblk));

	return (1);
}

/*
 * Writestart writes the incore mddb out to all of the replicas.
 * This is called when a diskset is started and when an error has
 * been enountered during the write to a mddb.
 *
 * flag can be 2 values:
 *	MDDB_WRITECOPY_ALL - write all records to all mddbs.  This is
 *		always used for traditional and local disksets.
 *		This is the normal path for MN disksets since the slave
 *		nodes aren't actually allowed to write to disk.
 *	MDDB_WRITECOPY_SYNC - special case for MN diskset.  When a new
 *		master has been chosen, the new master may need to
 * 		write its incore mddb to disk (this is the case where the
 *		old master had executed a message but hadn't relayed it
 *		to this slave yet).  New master should not write the
 *		change log records since new master would be overwriting
 *		valuable data.  Only used during a reconfig cycle.
 */
static int
writestart(
	mddb_set_t	*s,
	int		flag
)
{
	int		li;
	mddb_locator_t	*lp;
	mddb_lb_t	*lbp;
	mddb_ln_t	*lnp;
	int		err = 0;
	uint_t		set_status;

	lbp = s->s_lbp;

	for (li = 0; li < lbp->lb_loccnt; li++) {
		lp = &lbp->lb_locators[li];
		if (! (lp->l_flags & MDDB_F_ACTIVE))
			continue;
		if (! (lp->l_flags & MDDB_F_SUSPECT))
			continue;
		if (writecopy(s, li, flag))
			return (1);
		lp->l_flags |= MDDB_F_UP2DATE;
	}

	for (li = 0; li < lbp->lb_loccnt; li++) {
		lp = &lbp->lb_locators[li];
		if (! (lp->l_flags & MDDB_F_ACTIVE))
			continue;
		if ((lp->l_flags & MDDB_F_UP2DATE))
			continue;
		if (checkcopy(s, li))
			if (err = writecopy(s, li, flag))
				return (1);
		lp->l_flags |= MDDB_F_UP2DATE;
	}

	/*
	 * Call fixoptrecord even during a reconfig cycle since a replica
	 * failure may force the master to re-assign the optimized
	 * resync record to another replica.
	 */
	if (fixoptrecords(s))
		return (1);

	set_status = md_get_setstatus(s->s_setno);

	/* See if any (ACTIVE and not OLDACT) or (not ACTIVE and OLDACT) */
	for (li = 0; li < lbp->lb_loccnt; li++) {
		lp = &lbp->lb_locators[li];

		if (lp->l_flags & MDDB_F_DELETED)
			continue;

		if (((lp->l_flags & MDDB_F_ACTIVE) != 0 &&
		    (lp->l_flags & MDDB_F_OLDACT) == 0) ||
		    ((lp->l_flags & MDDB_F_ACTIVE) == 0 &&
		    (lp->l_flags & MDDB_F_OLDACT) != 0))
			break;

		if ((set_status & MD_SET_TAGDATA) ||
		    (set_status & MD_SET_CLRTAG))
			if ((lp->l_flags & MDDB_F_TAGDATA) ||
			    (lp->l_flags & MDDB_F_BADTAG))
				break;
	}

	/*
	 * If we found (ACTIVE and not OLDACT) or (not ACTIVE and OLDACT)
	 * the lbp identifier and the set identifier doesn't match.
	 */
	if (li != lbp->lb_loccnt || cmpidentifier(s, &lbp->lb_ident)) {

		/* Only call for traditional and local sets */
		if (!(lbp->lb_flags & MDDB_MNSET))
			(void) dt_write(s);

		setidentifier(s, &lbp->lb_ident);

		if (err = push_lb(s)) {
			(void) upd_med(s, "writestart(0)");
			return (err);
		}

		(void) upd_med(s, "writestart(0)");

		if (err = push_lb(s)) {
			(void) upd_med(s, "writestart(1)");
			return (err);
		}

		(void) upd_med(s, "writestart(1)");

		lnp = s->s_lnp;
		uniqtime32(&lnp->ln_timestamp);
		if (lbp->lb_flags & MDDB_MNSET)
			lnp->ln_revision = MDDB_REV_MNLN;
		else
			lnp->ln_revision = MDDB_REV_LN;
		crcgen(lnp, &lnp->ln_checksum, dbtob(lbp->lb_lnblkcnt), NULL);
		err = writeall(s, (caddr_t)lnp, lbp->lb_lnfirstblk,
		    lbp->lb_lnblkcnt, 0);
		/*
		 * If a MN diskset and this is the master, set the PARSE_LOCNM
		 * flag in the mddb_set structure to show that the locator
		 * names have changed.
		 * Don't set parseflags as a result of a new master sync
		 * during reconfig cycle since slaves nodes are already
		 * in-sync with the new master.
		 */

		if ((lbp->lb_flags & MDDB_MNSET) &&
		    (md_set[s->s_setno].s_am_i_master) &&
		    (flag != MDDB_WRITECOPY_SYNC)) {
			s->s_mn_parseflags |= MDDB_PARSE_LOCNM;
		}

		if (err)
			return (err);
	}

	for (li = 0; li < lbp->lb_loccnt; li++) {
		lp = &lbp->lb_locators[li];
		if (lp->l_flags & MDDB_F_DELETED)
			continue;
		if (lp->l_flags & MDDB_F_ACTIVE) {
			lp->l_flags |= MDDB_F_OLDACT;
		} else {
			lp->l_flags &= ~MDDB_F_OLDACT;
		}
	}

	md_clr_setstatus(s->s_setno, MD_SET_STALE);

	return (0);
}

/*
 * selectreplicas selects the working replicas and may write the incore
 * version of the mddb out to the replicas ondisk.
 *
 * flag can be 3 values:
 *	MDDB_RETRYSCAN - quick scan to see if there is an error.
 *			If no new error, returns without writing mddb
 *			to disks.  If a new error is seen, writes out
 *			mddb to disks.
 *	MDDB_SCANALL  - lengthy scan to check out mddbs and always writes
 *			out mddb to the replica ondisk.  Calls writecopy
 *			with MDDB_WRITECOPY_ALL flag which writes out
 *			all records to the replicas ondisk.
 *	MDDB_SCANALLSYNC - called during reconfig cycle to sync up incore
 *			and ondisk mddbs by writing incore values to disk.
 *			Calls writecopy with MDDB_WRITECOPY_SYNC flag so
 *			that change log records are not written out.
 *			Only used by MN disksets.
 *
 * Returns:
 *	0 - Successful
 *	1 - Unable to write incore mddb data to disk since < 50% replicas.
 */
int
selectreplicas(
	mddb_set_t	*s,
	int		flag
)
{
	int		li;
	int		alc;
	int		lc;
	mddb_locator_t	*lp;
	mddb_lb_t	*lbp = s->s_lbp;
	set_t		setno = s->s_setno;
	int		wc_flag;

	/*
	 * can never transition from stale to not stale
	 */
	if (md_get_setstatus(setno) & MD_SET_STALE) {
		for (li = 0; li < lbp->lb_loccnt; li++) {
			lp = &lbp->lb_locators[li];
			if (lp->l_flags & MDDB_F_DELETED)
				continue;
			if (! (lp->l_flags & MDDB_F_EMASTER)) {
				lp->l_flags |= MDDB_F_ACTIVE;
			} else {
				lp->l_flags &= ~MDDB_F_ACTIVE;
			}
		}
		return (1);
	}

	if ((flag == MDDB_SCANALL) || (flag == MDDB_SCANALLSYNC)) {
		for (li = 0; li < lbp->lb_loccnt; li++) {
			lp = &lbp->lb_locators[li];
			if (lp->l_flags & MDDB_F_DELETED)
				continue;
			if (lp->l_flags & MDDB_F_ACTIVE) {
				lp->l_flags |= MDDB_F_OLDACT;
				lp->l_flags &= ~MDDB_F_SUSPECT;
			} else {
				lp->l_flags |= MDDB_F_SUSPECT;
				lp->l_flags &= ~MDDB_F_OLDACT;
			}

			if (! (lp->l_flags & MDDB_F_EMASTER)) {
				lp->l_flags |= MDDB_F_ACTIVE;
				lp->l_flags &= ~MDDB_F_EWRITE;
				lp->l_flags &= ~MDDB_F_TOOSMALL;
			} else {
				lp->l_flags &= ~MDDB_F_ACTIVE;
			}
		}
		computefreeblks(s); /* set up free block bits */
	} else {
		for (li = 0; li < lbp->lb_loccnt; li++) {
			lp = &lbp->lb_locators[li];
			if (! (lp->l_flags & MDDB_F_ACTIVE))
				continue;
			if (lp->l_flags & MDDB_F_EWRITE)
				break;
		}

		/*
		 * if there are no errors this is error has already
		 * been processed return current state
		 */
		if (li == lbp->lb_loccnt)
			return (md_get_setstatus(setno) & MD_SET_TOOFEW);

		lp->l_flags &= ~MDDB_F_ACTIVE;
		do {
			lp = &lbp->lb_locators[li];
			lp->l_flags &= ~MDDB_F_UP2DATE;
		} while (++li < lbp->lb_loccnt);
	}

	alc = 0;
	lc = 0;
	for (li = 0; li < lbp->lb_loccnt; li++) {
		lp = &lbp->lb_locators[li];
		if (lp->l_flags & MDDB_F_DELETED)
			continue;
		lc++;
		if (! (lp->l_flags & MDDB_F_ACTIVE))
			continue;
		alc++;
	}

	if (alc < ((lc + 1) / 2)) {
		md_set_setstatus(setno, MD_SET_TOOFEW);
		return (1);
	}

	/* Set wc_flag based on flag passed in. */
	if (flag == MDDB_SCANALLSYNC)
		wc_flag = MDDB_WRITECOPY_SYNC;
	else
		wc_flag = MDDB_WRITECOPY_ALL;

	do {
		if (! writestart(s, wc_flag)) {
			md_clr_setstatus(setno, MD_SET_TOOFEW);
			return (0);
		}
		alc  = 0;
		for (li = 0; li < lbp->lb_loccnt; li++) {
			lp = &lbp->lb_locators[li];
			if ((lp->l_flags & MDDB_F_DELETED) ||
			    (lp->l_flags & MDDB_F_EMASTER))
				continue;

			if (lp->l_flags & MDDB_F_EWRITE) {
				lp->l_flags &= ~MDDB_F_ACTIVE;
				lp->l_flags &= ~MDDB_F_UP2DATE;
				continue;
			}
			alc++;
		}
	} while (alc >= ((lc + 1) / 2));
	md_set_setstatus(setno, MD_SET_TOOFEW);
	return (1);
}

static int
checkstate(
	mddb_set_t	*s,
	int		probe
)
{
	int		error;
	uint_t		set_status = md_get_setstatus(s->s_setno);

	ASSERT(s != NULL);

	if (! (set_status & MD_SET_STALE) && ! (set_status & MD_SET_TOOFEW))
		return (0);

	if (probe == MDDB_NOPROBE)
		return (1);

	single_thread_start(s);
	error = selectreplicas(s, MDDB_SCANALL);
	single_thread_end(s);

	if (error == 0 && s->s_zombie != 0) {
		mutex_exit(SETMUTEX(s->s_setno));
		error = mddb_deleterec(s->s_zombie);
		mutex_enter(SETMUTEX(s->s_setno));
		if (error == 0)
			s->s_zombie = 0;
	}
	return (error);
}

static int
writeretry(
	mddb_set_t	*s
)
{
	if (selectreplicas(s, MDDB_RETRYSCAN))
		if (selectreplicas(s, MDDB_SCANALL))
			return (1);
	return (0);
}

static void
free_mbipp(mddb_mb_ic_t **mbipp)
{
	mddb_mb_ic_t	*mbip1, *mbip2;

	for (mbip1 = *mbipp; mbip1 != NULL; mbip1 = mbip2) {
		mbip2 = mbip1->mbi_next;
		kmem_free((caddr_t)mbip1, MDDB_IC_BSIZE);
	}
	*mbipp = (mddb_mb_ic_t *)NULL;
}

static mddb_ri_t *
save_rip(mddb_set_t *s)
{
	mddb_ri_t	*trip = s->s_rip;
	mddb_ri_t	*nrip = NULL;
	mddb_ri_t	**nripp = &nrip;
	mddb_ri_t	*rip;

	while (trip) {
		/* Run to the end of the list */
		for (/* void */; (*nripp != NULL); nripp = &(*nripp)->ri_next)
			/* void */;

		/* Add the new member */
		*nripp = kmem_zalloc(sizeof (**nripp), KM_SLEEP);

		ASSERT(*nripp != NULL);

		/* shorthand */
		rip = *nripp;

		*rip = *trip;			/* structure assignment */

		/* Clear the stuff that is not needed for hints */
		rip->ri_flags = 0;
		rip->ri_commitcnt = 0;
		rip->ri_transplant = 0;
		rip->ri_mbip = (mddb_mb_ic_t *)NULL;
		rip->ri_dtp = (mddb_dt_t *)NULL;
		rip->ri_lbp = (mddb_lb_t *)NULL;
		rip->ri_did_icp = (mddb_did_ic_t *)NULL;
		rip->ri_devid = (ddi_devid_t)NULL;
		rip->ri_old_devid = (ddi_devid_t)NULL;
		rip->ri_next = (mddb_ri_t *)NULL;

		trip = trip->ri_next;
	}
	return (nrip);
}

static void
free_rip(mddb_ri_t **ripp)
{
	mddb_ri_t	*rip;
	mddb_ri_t	*arip;

	for (rip = *ripp; rip != (mddb_ri_t *)NULL; rip = arip) {
		arip = rip->ri_next;
		if (rip->ri_devid != (ddi_devid_t)NULL) {
			ddi_devid_free(rip->ri_devid);
			rip->ri_devid = (ddi_devid_t)NULL;
		}
		if (rip->ri_old_devid != (ddi_devid_t)NULL) {
			ddi_devid_free(rip->ri_old_devid);
			rip->ri_old_devid = (ddi_devid_t)NULL;
		}
		kmem_free((caddr_t)rip, sizeof (*rip));
	}
	*ripp = (mddb_ri_t *)NULL;
}

/*
 * this routine selects the correct replica to use
 * the rules are as follows
 *	1.	if all replica has same init time select highest commit count
 *	2.	if some but not all replicas are from another hostid discard
 *		them.
 *	3.	find which init time is present is most replicas
 *	4.	discard all replicas which do not match most init times
 *	5.	select replica with highest commit count
 */

static mddb_lb_t *
selectlocator(
	mddb_set_t	*s
)
{
	mddb_ri_t	*rip = s->s_rip;
	mddb_ri_t	*r, *r1;
	mddb_lb_t	*lbp;
	struct timeval32 *tp = (struct timeval32 *)NULL;
	int		different;
	int		same;
	int		count;
	int		maxcount;
	set_t		setno = s->s_setno;
	size_t		sz;
	int		mn_set = 0;

	/* Clear the ri_transplant flag on all the rip entries. */
	/* Set ri_commitcnt to locator's commitcnt - if available */
	for (r = rip; r != (mddb_ri_t *)NULL; r = r->ri_next) {
		r->ri_transplant = 0;
		if (r->ri_lbp != (mddb_lb_t *)NULL) {
			r->ri_commitcnt = r->ri_lbp->lb_commitcnt;
			/* If any locators have MN bit set, set flag */
			if (r->ri_lbp->lb_flags & MDDB_MNSET)
				mn_set = 1;
		}
	}

	/*
	 * A data tag is being used, so use it to limit the selection first.
	 * Data tags not used in MN diskset.
	 */
	if ((mn_set == 0) && (md_get_setstatus(setno) & MD_SET_USETAG)) {
		mddb_dt_t	*dtp = (mddb_dt_t *)md_set[setno].s_dtp;

		/*
		 * now toss any locators that have a different data tag
		 */
		for (r = rip; r != (mddb_ri_t *)NULL; r = r->ri_next) {
			if (r->ri_lbp == (mddb_lb_t *)NULL)
				continue;

			if (r->ri_dtp != (mddb_dt_t *)NULL) {
				/* If same tag, keep it */
				if (dtl_cmp(&dtp->dt_dtag,
				    &r->ri_dtp->dt_dtag) == 0)
					continue;
			}

			if (r->ri_dtp != (mddb_dt_t *)NULL) {
				kmem_free((caddr_t)r->ri_dtp, MDDB_DT_BYTES);
				r->ri_dtp = (mddb_dt_t *)NULL;
			}

			mddb_devid_icp_free(&r->ri_did_icp, r->ri_lbp);
			if (!(md_get_setstatus(setno) &
			    MD_SET_REPLICATED_IMPORT)) {
				if (r->ri_old_devid != (ddi_devid_t)NULL) {
					sz = ddi_devid_sizeof(r->ri_old_devid);
					kmem_free((caddr_t)r->ri_old_devid, sz);
					r->ri_old_devid = (ddi_devid_t)NULL;
				}
			}

			kmem_free((caddr_t)r->ri_lbp,
			    dbtob(r->ri_lbp->lb_blkcnt));
			r->ri_lbp = (mddb_lb_t *)NULL;

			r->ri_transplant = 1;
		}

		/* Tag used, clear the bit */
		md_clr_setstatus(s->s_setno, MD_SET_USETAG);

		if (md_get_setstatus(s->s_setno) & MD_SET_TAGDATA) {
			/*
			 * Get rid of the list of tags.
			 */
			dtl_freel(&s->s_dtlp);

			/*
			 * Re-create the list with the tag used.
			 */
			(void) dtl_addl(s, &dtp->dt_dtag);
		}
	}

	/*
	 * scan to see if all replicas have same time
	 */
	for (r = rip; r != (mddb_ri_t *)NULL; r = r->ri_next) {
		if (r->ri_lbp == (mddb_lb_t *)NULL)
			continue;
		if (tp == NULL) {
			tp = &r->ri_lbp->lb_inittime;
			continue;
		}
		/* CSTYLED */
		if (timercmp(tp, &r->ri_lbp->lb_inittime, !=))
			break;
	}

	/*
	 * if r == NULL then they were all them same. Choose highest
	 * commit count
	 */
	if (r == (mddb_ri_t *)NULL)
		goto out;

	/*
	 * If here, a bogus replica is present and at least 1 lb_inittime
	 * did not match.
	 */

	/*
	 * look and see if any but not all are from different id
	 */

	different = 0;
	same = 0;
	for (r = rip; r != (mddb_ri_t *)NULL; r = r->ri_next) {
		if (r->ri_lbp == (mddb_lb_t *)NULL)
			continue;
		if (cmpidentifier(s, &r->ri_lbp->lb_ident))
			different = 1;
		else
			same = 1;
	}

	/*
	 * now go through and throw out different if there are some
	 * that are the same
	 */
	if (different != 0 && same != 0) {
		for (r = rip; r != (mddb_ri_t *)NULL; r = r->ri_next) {
			if (r->ri_lbp == (mddb_lb_t *)NULL)
				continue;

			if (!cmpidentifier(s, &r->ri_lbp->lb_ident))
				continue;

			if (r->ri_dtp != (mddb_dt_t *)NULL) {
				kmem_free((caddr_t)r->ri_dtp, MDDB_DT_BYTES);
				r->ri_dtp = (mddb_dt_t *)NULL;
			}

			mddb_devid_icp_free(&r->ri_did_icp, r->ri_lbp);
			if (!(md_get_setstatus(setno) &
			    MD_SET_REPLICATED_IMPORT)) {
				if (r->ri_old_devid != (ddi_devid_t)NULL) {
					sz = ddi_devid_sizeof(r->ri_old_devid);
					kmem_free((caddr_t)r->ri_old_devid, sz);
					r->ri_old_devid = (ddi_devid_t)NULL;
				}
			}

			kmem_free((caddr_t)r->ri_lbp,
			    dbtob(r->ri_lbp->lb_blkcnt));
			r->ri_lbp = (mddb_lb_t *)NULL;

			r->ri_transplant = 1;
		}
	}

	/*
	 * go through and pick highest. Use n square because it is
	 * simple and 40 some is max possible
	 */
	maxcount = 0;
	lbp = (mddb_lb_t *)NULL;
	for (r1 = rip; r1 != (mddb_ri_t *)NULL; r1 = r1->ri_next) {
		if (r1->ri_lbp == (mddb_lb_t *)NULL)
			continue;
		count = 0;
		for (r = r1; r != (mddb_ri_t *)NULL; r = r->ri_next) {
			if (r->ri_lbp == (mddb_lb_t *)NULL)
				continue;
			if (timercmp(&r1->ri_lbp->lb_inittime, /* CSTYLED */
			    &r->ri_lbp->lb_inittime, ==))
				count++;
		}
		if (count > maxcount) {
			maxcount = count;
			lbp = r1->ri_lbp;
		}
	}

	/*
	 * now go though and toss any that are of a different time stamp
	 */
	for (r = rip; r != (mddb_ri_t *)NULL; r = r->ri_next) {
		if (r->ri_lbp == (mddb_lb_t *)NULL)
			continue;
		if (timercmp(&lbp->lb_inittime, /* CSTYLED */
		    &r->ri_lbp->lb_inittime, ==))
			continue;

		if (r->ri_dtp != (mddb_dt_t *)NULL) {
			kmem_free((caddr_t)r->ri_dtp, MDDB_DT_BYTES);
			r->ri_dtp = (mddb_dt_t *)NULL;
		}

		mddb_devid_icp_free(&r->ri_did_icp, r->ri_lbp);
		if (!(md_get_setstatus(setno) & MD_SET_REPLICATED_IMPORT)) {
			if (r->ri_old_devid != (ddi_devid_t)NULL) {
				sz = ddi_devid_sizeof(r->ri_old_devid);
				kmem_free((caddr_t)r->ri_old_devid, sz);
				r->ri_old_devid = (ddi_devid_t)NULL;
			}
		}

		kmem_free((caddr_t)r->ri_lbp, dbtob(r->ri_lbp->lb_blkcnt));
		r->ri_lbp = (mddb_lb_t *)NULL;

		r->ri_transplant = 1;
	}

out:
	/*
	 * Find the locator with the highest commit count, and make it the
	 * "chosen" one.
	 */
	lbp = (mddb_lb_t *)NULL;
	for (r = rip; r != (mddb_ri_t *)NULL; r = r->ri_next) {
		if (r->ri_lbp == (mddb_lb_t *)NULL)
			continue;

		if (lbp == NULL) {
			lbp = r->ri_lbp;
			continue;
		}

		if (r->ri_lbp->lb_commitcnt > lbp->lb_commitcnt)
			lbp = r->ri_lbp;
	}

	/* Toss all locator blocks, except the "chosen" one. */
	for (r = rip; r != (mddb_ri_t *)NULL; r = r->ri_next) {
		if (r->ri_lbp == (mddb_lb_t *)NULL)
			continue;

		/* Get rid of all dtp's */
		if (r->ri_dtp != (mddb_dt_t *)NULL) {
			kmem_free((caddr_t)r->ri_dtp, MDDB_DT_BYTES);
			r->ri_dtp = (mddb_dt_t *)NULL;
		}

		if (r->ri_lbp == lbp)
			continue;

		/* Get rid of extra locator devid block info */
		mddb_devid_icp_free(&r->ri_did_icp, r->ri_lbp);
		if (!(md_get_setstatus(setno) & MD_SET_REPLICATED_IMPORT)) {
			if (r->ri_old_devid != (ddi_devid_t)NULL) {
				sz = ddi_devid_sizeof(r->ri_old_devid);
				kmem_free((caddr_t)r->ri_old_devid, sz);
				r->ri_old_devid = (ddi_devid_t)NULL;
			}
		}

		/* Get rid of extra locators */
		kmem_free((caddr_t)r->ri_lbp, dbtob(r->ri_lbp->lb_blkcnt));
		r->ri_lbp = (mddb_lb_t *)NULL;
	}
	return (lbp);
}

static void
locator2cfgloc(
	mddb_lb_t		*lbp,
	mddb_cfg_loc_t		*clp,
	int			li,
	side_t			sideno,
	mddb_did_ic_t		*did_icp
)
{
	mddb_drvnm_t		*dn;
	mddb_locator_t		*lp = &lbp->lb_locators[li];
	mddb_sidelocator_t	*slp;
	mddb_mnsidelocator_t	*mnslp;
	mddb_did_info_t		*did_info;
	int 			i, sz, szalloc;
	int			mn_set = 0;
	mddb_mnlb_t		*mnlbp;

	if (lbp->lb_flags & MDDB_MNSET) {
		mn_set = 1;
		mnlbp = (mddb_mnlb_t *)lbp;
		for (i = 0; i < MD_MNMAXSIDES; i++) {
			mnslp = &mnlbp->lb_mnsidelocators[i][li];
			if (mnslp->mnl_sideno == sideno)
				break;
		}
		if (i == MD_MNMAXSIDES)
			return;
	} else {
		slp = &lbp->lb_sidelocators[sideno][li];
	}

	if (lbp->lb_flags & MDDB_DEVID_STYLE) {
		did_info = &(did_icp->did_ic_blkp->blk_info[li]);
		if (did_info->info_flags & MDDB_DID_EXISTS) {
			sz = (int)ddi_devid_sizeof(did_icp->did_ic_devid[li]);
			if (clp->l_devid_flags & MDDB_DEVID_SPACE) {
				/*
				 * copy device id from mddb to
				 * cfg_loc structure
				 */
				szalloc = clp->l_devid_sz;
				if (sz <= szalloc) {
					for (i = 0; i < sz; i++) {
						((char *)(uintptr_t)
						    clp->l_devid)[i] =
						    ((char *)did_icp->
						    did_ic_devid[li])[i];
					}
					clp->l_devid_flags |= MDDB_DEVID_VALID;
					(void) strcpy(clp->l_minor_name,
					    did_info->info_minor_name);
				} else {
					clp->l_devid_flags |=
					    MDDB_DEVID_NOSPACE;
				}
			} else if (clp->l_devid_flags & MDDB_DEVID_GETSZ) {
				clp->l_devid_flags = MDDB_DEVID_SZ;
				clp->l_devid_sz = sz;
			}
		}
	}

	/*
	 * Even if a devid exists, use the dev, drvnm and mnum in the locators
	 * and sidelocators.  During startup, the dev, drvnm and mnum in
	 * these structures may not match the devid (the locators and
	 * sidelocators will be updated to match the devid by the routine
	 * load_old_replicas).  Using out-of-sync values won't cause any
	 * problems since ridev will re-derive these from the devid and mnum.
	 * After startup, the dev, drvnm and mnum in these structures have
	 * been updated and can be used.
	 */

	clp->l_blkno = lp->l_blkno;
	clp->l_flags = lp->l_flags;
	clp->l_dev = lp->l_dev;

	if (mn_set) {
		dn = &lbp->lb_drvnm[mnslp->mnl_drvnm_index];
		clp->l_mnum = mnslp->mnl_mnum;
	} else {
		dn = &lbp->lb_drvnm[slp->l_drvnm_index];
		clp->l_mnum = slp->l_mnum;
	}
	(void) strncpy(clp->l_driver, dn->dn_data, MD_MAXDRVNM);
}

/*
 * Find the index into the mnsidelocator where entry will go.
 * Then index can be fed into both splitname2locatorblocks and
 * cfgloc2locator so that those entries can be kept in sync.
 *
 * Returns:
 *	-1 if failed to find unused slot or if a traditional diskset
 *	index, if successful  (0 <= index <= MD_MNMAXSIDES)
 */
static int
checklocator(
	mddb_lb_t		*lbp,
	int			li,
	side_t			sideno
)
{
	uchar_t			i;
	mddb_mnsidelocator_t	*mnslp;
	mddb_mnlb_t		*mnlbp;
	int			index = -1;

	if (lbp->lb_flags & MDDB_MNSET) {
		/*
		 * Checking side locator structure.  First, check if
		 * there is already an entry for this side.  If so,
		 * then use that entry.  Otherwise, find an entry
		 * that has a sideno of 0.
		 */
		mnlbp = (mddb_mnlb_t *)lbp;
		for (i = 0; i < MD_MNMAXSIDES; i++) {
			mnslp = &mnlbp->lb_mnsidelocators[i][li];
			if (mnslp->mnl_sideno == sideno) {
				/* Found a match - stop looking */
				index = i;
				break;
			} else if ((mnslp->mnl_sideno == 0) && (index == -1)) {
				/* Set first empty slot, but keep looking */
				index = i;
			}
		}
		/* Didn't find empty slot or previously used slot */
		if ((i == MD_MNMAXSIDES) && (index == -1)) {
			return (-1);
		}
		return (index);
	} else
		return (0);
}

/*
 * Takes locator information (driver name, minor number, sideno) and
 * stores it in the locator block.
 * For traditional diskset, the sideno is the index into the sidelocator
 * array in the locator block.
 * For the MN diskset, the sideno is the nodeid which can be any number,
 * so the index passed in is the index into the mnsidelocator array
 * in the locator block.
 */
static int
cfgloc2locator(
	mddb_lb_t		*lbp,
	mddb_cfg_loc_t		*clp,
	int			li,
	side_t			sideno,
	int			index	/* Only useful in MNsets when > 1 */
)
{
	uchar_t			i;
	mddb_sidelocator_t	*slp;
	mddb_mnsidelocator_t	*mnslp;
	mddb_set_t		*s;
	int			mn_set = 0;
	mddb_mnlb_t		*mnlbp;

	if (lbp->lb_flags & MDDB_MNSET) {
		mnlbp = (mddb_mnlb_t *)lbp;
		mn_set = 1;
		/*
		 * Index will be the slot that has the given sideno or
		 * the first empty slot if no match is found.
		 * This was pre-checked out in check locator.
		 */
		mnslp = &mnlbp->lb_mnsidelocators[index][li];
	} else {
		slp = &lbp->lb_sidelocators[sideno][li];
	}

	/*
	 * Look for the driver name
	 */
	for (i = 0; i < MDDB_DRVNMCNT; i++) {
		if (lbp->lb_drvnm[i].dn_len == 0)
			continue;
		if (strncmp(lbp->lb_drvnm[i].dn_data, clp->l_driver,
		    MD_MAXDRVNM) == 0)
			break;
	}

	/*
	 * Didn't find one, add a new one
	 */
	if (i == MDDB_DRVNMCNT) {
		for (i = 0; i < MDDB_DRVNMCNT; i++) {
			if (lbp->lb_drvnm[i].dn_len == 0)
				break;
		}
		if (i == MDDB_DRVNMCNT)
			return (1);
		(void) strncpy(lbp->lb_drvnm[i].dn_data, clp->l_driver,
		    MD_MAXDRVNM);
		lbp->lb_drvnm[i].dn_len = (uchar_t)strlen(clp->l_driver);
	}

	/* Fill in the drvnm index */
	if (mn_set) {
		mnslp->mnl_drvnm_index = i;
		mnslp->mnl_mnum = clp->l_mnum;
		mnslp->mnl_sideno = sideno;
	} else {
		slp->l_drvnm_index = i;
		slp->l_mnum = clp->l_mnum;
	}

	if (lbp->lb_flags & MDDB_DEVID_STYLE) {
		/*
		 * This device id could already be associated with this index
		 * if this is not the first side added to the set.
		 * If device id is 0, there is no device id for this device.
		 */
		if ((ddi_devid_t)(uintptr_t)clp->l_devid == 0)
			return (0);
		s = (mddb_set_t *)md_set[lbp->lb_setno].s_db;
		if (mddb_devid_add(s, li, (ddi_devid_t)(uintptr_t)clp->l_devid,
		    clp->l_minor_name)) {
			return (1);
		}
	}

	return (0);
}

/*
 * See if there are mediator hosts and try to use the data.
 */
static int
mediate(
	mddb_set_t	*s
)
{
	mddb_lb_t	*lbp = s->s_lbp;
	med_data_lst_t	*meddlp = NULL;
	med_data_lst_t	*tmeddlp = NULL;
	med_data_t	*meddp;
	int		medok = 0;
	int		medacc = 0;
	uint_t		maxcc;
	int		golden = 0;
	int		err = 1;
	set_t		setno = s->s_setno;

	/* Do not have a mediator, then the state is stale */
	if (s->s_med.n_cnt == 0)
		return (err);

	/* Contact the mediator hosts for the data */
	meddlp = get_med_host_data(&s->s_med, s->s_setname, setno);

	/* No mediator data, stale */
	if (meddlp == NULL)
		return (err);

	/* Mark all the mediator data that is not for this set as errored */
	for (tmeddlp = meddlp; tmeddlp != NULL; tmeddlp = tmeddlp->mdl_nx) {
		struct timeval32 tmptime;
		meddp = tmeddlp->mdl_med;

		/* Count the number of mediators contacted */
		medacc++;

		/* Paranoid check */
		if (meddp->med_dat_sn != setno)
			meddp->med_dat_fl |= MED_DFL_ERROR;

		TIMEVAL_TO_TIMEVAL32(&tmptime, &meddp->med_dat_id);

		/*CSTYLED*/
		if (timercmp(&tmptime, &lbp->lb_ident.createtime, !=))
			meddp->med_dat_fl |= MED_DFL_ERROR;
	}

	/* Get the max commitcount */
	maxcc = 0;
	for (tmeddlp = meddlp; tmeddlp != NULL; tmeddlp = tmeddlp->mdl_nx) {
		meddp = tmeddlp->mdl_med;
		if (meddp->med_dat_fl & MED_DFL_ERROR)
			continue;
		if (meddp->med_dat_cc > maxcc)
			maxcc = meddp->med_dat_cc;
	}

	/* Now mark the records that don't have the highest cc as errored */
	for (tmeddlp = meddlp; tmeddlp != NULL; tmeddlp = tmeddlp->mdl_nx) {
		meddp = tmeddlp->mdl_med;
		if (meddp->med_dat_fl & MED_DFL_ERROR)
			continue;
		if (meddp->med_dat_cc != maxcc)
			meddp->med_dat_fl |= MED_DFL_ERROR;
	}

	/* Now mark the records that don't match the lb commitcnt as errored */
	for (tmeddlp = meddlp; tmeddlp != NULL; tmeddlp = tmeddlp->mdl_nx) {
		meddp = tmeddlp->mdl_med;
		if (meddp->med_dat_fl & MED_DFL_ERROR)
			continue;
		if (meddp->med_dat_cc != lbp->lb_commitcnt)
			meddp->med_dat_fl |= MED_DFL_ERROR;
	}

	/* Is there a "golden" copy and how many valid mediators */
	for (tmeddlp = meddlp; tmeddlp != NULL; tmeddlp = tmeddlp->mdl_nx) {
		meddp = tmeddlp->mdl_med;
		if (meddp->med_dat_fl & MED_DFL_ERROR)
			continue;

		if (meddp->med_dat_fl & MED_DFL_GOLDEN)
			golden++;

		medok++;
	}

	/* No survivors, stale */
	if (medok == 0)
		goto out;

	/* No mediator quorum and no golden copies, stale */
	if (medacc < ((s->s_med.n_cnt / 2) + 1) && ! golden) {
		/* Skip odd numbers, no exact 50% */
		if (s->s_med.n_cnt & 1)
			goto out;
		/* Have 50%, allow an accept */
		if (medacc == (s->s_med.n_cnt / 2))
			md_set_setstatus(setno, MD_SET_ACCOK);
		goto out;
	}

	/* We either have a quorum or a golden copy, or both */
	err = 0;

out:
	if (meddlp) {
		for (/* void */; meddlp != NULL; meddlp = tmeddlp) {
			tmeddlp = meddlp->mdl_nx;
			kmem_free(meddlp->mdl_med, sizeof (med_data_t));
			kmem_free(meddlp, sizeof (med_data_lst_t));
		}
	}

	return (err);
}

/*
 *	1. read masterblks and locator blocks for all know database locations
 *		a. keep track of which have good master blks
 *		b. keep track of which have good locators
 *
 */
static int
get_mbs_n_lbs(
	mddb_set_t	*s,
	int		*write_lb
)
{
	mddb_lb_t	*lbp = NULL;		/* pointer to locator block */
						/* May be cast to mddb_mnlb_t */
						/* if accessing sidenames in */
						/* MN set */
	mddb_did_ic_t	*did_icp = NULL;	/* ptr to Device ID incore */
	mddb_did_blk_t	*did_blkp = 0;
	int		did_blkp_sz = 0;
	mddb_did_db_t	*did_dbp;
	mddb_did_info_t	*did_info;
	caddr_t		did_block;
	mddb_ri_t	*rip;
	mddb_dtag_lst_t	*dtlp;
	mddb_locator_t	*lp;
	daddr_t		physblk;
	int		li;
	uint_t		blk;
	md_dev64_t	dev;
	caddr_t		buffer;
	uint_t		lb_blkcnt;
	int		retval = 0;
	int		err = 0;
	int		lb_ok = 0;
	int		lb_total = 0;
	int		lb_tagged = 0;
	int		lb_tags;
	set_t		setno = s->s_setno;
	int		cont_flag, i;
	mddb_did_db_t	*did_dbp1, *did_dbp2;
	int		mn_set = 0;
	mddb_cfg_loc_t	*cl;

	/*
	 * read in master blocks and locator block for all known locators.
	 * lb_blkcnt will be set correctly for MN set later once getmasters
	 * has determined that the set is a MN set.
	 */
	lb_blkcnt = ((setno == MD_LOCAL_SET) ? MDDB_LOCAL_LBCNT : MDDB_LBCNT);

	for (rip = s->s_rip; rip != NULL; rip = rip->ri_next) {
		rip->ri_flags &= (MDDB_F_PTCHED | MDDB_F_IOCTL |
		    MDDB_F_EMASTER);
		rip->ri_lbp = (mddb_lb_t *)NULL;
		rip->ri_did_icp = (mddb_did_ic_t *)NULL;

		/*
		 * Translated dev is only used in calls to getmasters and
		 * getblks which expect a translated (aka miniroot) dev.
		 */
		dev = md_xlate_targ_2_mini(rip->ri_dev);
		if (dev == NODEV64) {
			/* Set error flag that getmasters would have set */
			/* if getmasters had been allowed to fail */
			rip->ri_flags |= MDDB_F_EMASTER;
		}

		/*
		 * Invalid device id on system (due to failed or
		 * removed device) or invalid devt during upgrade
		 * (due to powered off device) will cause this
		 * replica to be marked in error and not used.
		 */
		if (rip->ri_flags & MDDB_F_EMASTER)
			continue;

		/* get all master blocks, does mddb_devopen() */
		rip->ri_mbip = getmasters(s, dev, rip->ri_blkno,
		    &rip->ri_flags, &mn_set);

		/* if invalid master block - try next replica */
		if (! rip->ri_mbip)
			continue;

		/*
		 * If lbp alloc'd to wrong size - reset it.
		 * If MN set, lb_blkcnt must be MDDB_MNLBCNT.
		 * If a traditional set, lb_blkcnt must NOT be MDDB_MNLBCNT.
		 */
		if (lbp) {
			if (((mn_set) && (lb_blkcnt != MDDB_MNLBCNT)) ||
			    ((!mn_set) && (lb_blkcnt == MDDB_MNLBCNT))) {
				kmem_free((caddr_t)lbp, dbtob(lb_blkcnt));
				lbp = (mddb_lb_t *)NULL;
			}
		}

		if (lbp == (mddb_lb_t *)NULL) {
			/* If a MN set, set lb_blkcnt for MN loc blk size */
			if (mn_set)
				lb_blkcnt = MDDB_MNLBCNT;
			lbp = (mddb_lb_t *)kmem_zalloc(dbtob(lb_blkcnt),
			    KM_SLEEP);
		}

		/*
		 * Read in all the sectors for the locator block
		 * NOTE: Need to use getblks, rather than readblklst.
		 *	because it is too early and things are
		 *	NOT set up yet for read*()'s
		 */
		buffer = (caddr_t)lbp;
		for (blk = 0; blk < lb_blkcnt; blk++) {
			physblk = getphysblk(blk, rip->ri_mbip);
			err = getblks(s, buffer, dev, physblk,
			    btodb(MDDB_BSIZE), 0);
			if (err) {
				rip->ri_flags |= err;
				break;
			}
			buffer += MDDB_BSIZE;
		}

		if (err)
			continue;

		/* Verify the locator block */
		if (blk != lb_blkcnt)
			continue;
		if (lbp->lb_magic != MDDB_MAGIC_LB)
			continue;
		if (lbp->lb_blkcnt != lb_blkcnt)
			continue;
		if (mn_set) {
			/* If a MN set, check for MNLB revision in lb. */
			if (revchk(MDDB_REV_MNLB, lbp->lb_revision))
				continue;
		} else {
			/* If not a MN set, check for LB revision in lb. */
			if (revchk(MDDB_REV_LB, lbp->lb_revision))
				continue;
		}
		if (crcchk(lbp, &lbp->lb_checksum, dbtob(lb_blkcnt), NULL))
			continue;

		/*
		 * With the addition of MultiNode Disksets, we must make sure
		 * to verify that this is the correct set.  A node could
		 * have been out of the config for awhile and this disk could
		 * have been moved to a different diskset and we don't want
		 * to accidentally start the wrong set.
		 *
		 * We don't do this check if we're in the middle of
		 * importing a set.
		 */
		if (!(md_get_setstatus(s->s_setno) &
		    (MD_SET_IMPORT | MD_SET_REPLICATED_IMPORT)) &&
		    (lbp->lb_setno != s->s_setno))
			continue;

		rip->ri_flags |= MDDB_F_LOCACC;

		/*
		 * a commit count of zero means this locator has been deleted
		 */
		if (lbp->lb_commitcnt == 0)
			continue;

		/*
		 * If replica is in the device ID style and md_devid_destroy
		 * flag is set, turn off device id style.  This is only to be
		 * used in a catastrophic failure case.  Examples would be
		 * where the device id of all drives in the system
		 * (especially the mirror'd root drives) had been changed
		 * by firmware upgrade or by a patch to an existing disk
		 * driver.  Another example would be in the case of non-unique
		 * device ids due to a bug.  The device id would be valid on
		 * the system, but would return the wrong dev_t.
		 */
		if ((lbp->lb_flags & MDDB_DEVID_STYLE) && md_devid_destroy) {
			lbp->lb_flags &= ~MDDB_DEVID_STYLE;
			lbp->lb_didfirstblk = 0;
			lbp->lb_didblkcnt = 0;
			*write_lb = 1;
		}


		/*
		 * If replica is in device ID style, read in device ID
		 * block and verify device ID block information.
		 */
		if (lbp->lb_flags & MDDB_DEVID_STYLE) {

			/* Read in device ID block */
			if (did_icp == NULL) {
				did_icp = (mddb_did_ic_t *)
				    kmem_zalloc(sizeof (mddb_did_ic_t),
				    KM_SLEEP);
			} else {
				/* Reuse did_icp, but clear out data */
				if (did_icp->did_ic_blkp !=
				    (mddb_did_blk_t *)NULL) {
					kmem_free((caddr_t)did_icp->did_ic_blkp,
					    did_blkp_sz);
					did_blkp = (mddb_did_blk_t *)NULL;
					did_icp->did_ic_blkp =
					    (mddb_did_blk_t *)NULL;
				}
				if (did_icp->did_ic_dbp !=
				    (mddb_did_db_t *)NULL) {
					did_dbp1 = did_icp->did_ic_dbp;
					while (did_dbp1) {
						did_dbp2 = did_dbp1->db_next;
						kmem_free((caddr_t)
						    did_dbp1->db_ptr,
						    dbtob(did_dbp1->db_blkcnt));
						kmem_free((caddr_t)did_dbp1,
						    sizeof (mddb_did_db_t));
						did_dbp1 = did_dbp2;
					}
					did_icp->did_ic_dbp =
					    (mddb_did_db_t *)NULL;
				}
				for (i = 0; i < MDDB_NLB; i++) {
					did_icp->did_ic_devid[i] =
					    (ddi_devid_t)NULL;
				}
			}

			/* Can't reuse blkp since size could be different */
			if (did_blkp != (mddb_did_blk_t *)NULL) {
				kmem_free(did_blkp, did_blkp_sz);
			}
			did_blkp_sz = (int)dbtob(lbp->lb_didblkcnt);
			did_blkp = (mddb_did_blk_t *)kmem_zalloc(did_blkp_sz,
			    KM_SLEEP);
			did_icp->did_ic_blkp = did_blkp;
			buffer = (caddr_t)did_blkp;
			for (blk = lbp->lb_didfirstblk;
			    blk < (lbp->lb_didblkcnt + lbp->lb_didfirstblk);
			    blk++) {
				physblk = getphysblk(blk, rip->ri_mbip);
				err = getblks(s, buffer, dev, physblk,
				    btodb(MDDB_BSIZE), 0);
				if (err) {
					rip->ri_flags |= err;
					break;
				}
				buffer += MDDB_BSIZE;
			}
			if (err)
				continue;

			/* Verify the Device ID block */
			if (blk != (lbp->lb_didblkcnt + lbp->lb_didfirstblk))
				continue;
			if (did_blkp->blk_magic != MDDB_MAGIC_DI)
				continue;
			if (lbp->lb_didblkcnt != MDDB_DID_BLOCKS)
				continue;
			if (revchk(MDDB_REV_DI, did_blkp->blk_revision))
				continue;
			if (crcchk(did_blkp, &did_blkp->blk_checksum,
			    dbtob(lbp->lb_didblkcnt), NULL))
				continue;

			/*
			 * Check if device ID block is out of sync with the
			 * Locator Block by checking if the locator block
			 * commitcnt does not match the device id block
			 * commitcnt.  If an 'out of sync' condition
			 * exists, discard this replica since it has
			 * inconsistent data and can't be used in
			 * determining the best replica.
			 *
			 * An 'out of sync' condition could happen if old
			 * SDS code was running with new devid style replicas
			 * or if a failure occurred between the writing of
			 * the locator block's commitcnt and the device
			 * id block's commitcnt.
			 *
			 * If old SDS code had been running, the upgrade
			 * process should detect this situation and
			 * have removed all of the device id information
			 * via the md_devid_destroy flag in md.conf.
			 */
			if (did_blkp->blk_commitcnt !=
			    lbp->lb_commitcnt) {
				continue;
			}
		}


		/*
		 * If replica is still in device ID style, read in all
		 * of the device IDs, verify the checksum of the device IDs.
		 */
		if (lbp->lb_flags & MDDB_DEVID_STYLE) {
			/*
			 * Reset valid bit in device id info block flags. This
			 * flag is stored on disk, but the valid bit is reset
			 * when reading in the replica.  If the corresponding
			 * device id is valid (aka meaning that the system
			 * knows about this device id), the valid bit will
			 * be set at a later time.  The valid bit for this
			 * replica's device ID will be set in this routine.
			 * The valid bits for the rest of the device id's
			 * will be set after the 'best' replica has
			 * been selected in routine load_old_replicas.
			 * Reset updated bit in device id info block flags.
			 * This flag is also stored on disk, reset when read
			 * in and set when the locators and side locators
			 * have been updated to match this valid device
			 * id information.
			 */
			for (li = 0; li < lbp->lb_loccnt; li++) {
				did_info = &did_blkp->blk_info[li];
				if (did_info->info_flags & MDDB_DID_EXISTS)
					did_info->info_flags &=
					    ~(MDDB_DID_VALID |
					    MDDB_DID_UPDATED);
			}

			cont_flag = 0;
			for (li = 0; li < lbp->lb_loccnt; li++) {
				did_info = &did_blkp->blk_info[li];
				did_block = (caddr_t)NULL;
				if (did_info->info_flags & MDDB_DID_EXISTS) {
					/*
					 * Check if block has
					 * already been read in
					 */
					did_dbp = did_icp->did_ic_dbp;
					while (did_dbp != 0) {
						if (did_dbp->db_firstblk ==
						    did_info->info_firstblk)
							break;
						else
							did_dbp =
							    did_dbp->db_next;
					}
					/* if block not found, read it in */
					if (did_dbp == NULL) {
						did_block = (caddr_t)
						    (kmem_zalloc(dbtob(
						    did_info->info_blkcnt),
						    KM_SLEEP));
						buffer = (caddr_t)did_block;
						for (blk =
						    did_info->info_firstblk;
						    blk < (did_info->
						    info_firstblk +
						    did_info->info_blkcnt);
						    blk++) {
							physblk =
							    getphysblk(blk,
							    rip->ri_mbip);
							err = getblks(s,
							    buffer, dev,
							    physblk, btodb(
							    MDDB_BSIZE), 0);
							if (err) {
								rip->ri_flags |=
								    err;
								break;
							}
							buffer += MDDB_BSIZE;
						}
						if (err) {
							kmem_free(did_block,
							    dbtob(did_info->
							    info_blkcnt));
							did_block =
							    (caddr_t)NULL;
							cont_flag = 1;
							break;
						}

						/*
						 * Block read in -
						 * alloc Disk Block area
						 */
						did_dbp = (mddb_did_db_t *)
						    kmem_zalloc(
						    sizeof (mddb_did_db_t),
						    KM_SLEEP);
						did_dbp->db_ptr = did_block;
						did_dbp->db_firstblk =
						    did_info->info_firstblk;
						did_dbp->db_blkcnt =
						    did_info->info_blkcnt;

						/* Add to front of dbp list */
						did_dbp->db_next =
						    did_icp->did_ic_dbp;
						did_icp->did_ic_dbp = did_dbp;
					}
					/* Check validity of devid in block */
					if (crcchk(((char *)did_dbp->db_ptr +
					    did_info->info_offset),
					    &did_info->info_checksum,
					    did_info->info_length, NULL)) {
						cont_flag = 1;
						break;
					}

					/* Block now pointed to by did_dbp */
					did_icp->did_ic_devid[li] =
					    (ddi_devid_t)((char *)
					    did_dbp->db_ptr +
					    did_info->info_offset);
				}
			}
			if (cont_flag)
				continue;
		}

		/*
		 * All blocks containing devids are now in core.
		 */

		/*
		 * If we're doing a replicated import (also known as
		 * remote copy import), the device id in the locator
		 * block is incorrect and we need to fix it up here
		 * alongwith the l_dev otherwise we run into lots of
		 * trouble later on.
		 */
		if ((md_get_setstatus(setno) & MD_SET_REPLICATED_IMPORT)) {
			mddb_ri_t	*trip;
			for (li = 0; li < lbp->lb_loccnt; li++) {
				did_info = &did_blkp->blk_info[li];
				lp = &lbp->lb_locators[li];

				if (lp->l_flags & MDDB_F_DELETED)
					continue;

				if (!(did_info->info_flags & MDDB_DID_EXISTS))
					continue;

				if (did_icp->did_ic_devid[li] == NULL)
					continue;

				for (trip = s->s_rip; trip != NULL;
				    trip = trip->ri_next) {
					if (trip->ri_old_devid == NULL)
						continue;
					if (ddi_devid_compare(
					    trip->ri_old_devid,
					    did_icp->did_ic_devid[li]) != 0) {
						continue;
					}

					/* update l_dev and side mnum */
					lp->l_dev = md_cmpldev(trip->ri_dev);
					lbp->lb_sidelocators[0][li].l_mnum =
					    md_getminor(trip->ri_dev);
				}
			}
		}

		/*
		 * If there is a valid devid, verify that this locator
		 * block has information about itself by checking the
		 * device ID, minor_name and block
		 * number from this replica's incore data structure
		 * against the locator block information that has just
		 * been read in from disk.
		 *
		 * If not a valid devid, verify that this locator block
		 * has information about itself by checking the minor
		 * number, block number and driver name from this
		 * replica's incore data structure against the locator
		 * block information that has just been read in from disk.
		 */
		if ((rip->ri_devid != NULL) &&
		    (lbp->lb_flags & MDDB_DEVID_STYLE)) {
			/*
			 * This locator block MUST have locator (replica)
			 * information about itself.  Check against devid,
			 * slice part of minor number, and block number.
			 */
			for (li = 0; li < lbp->lb_loccnt; li++) {
				did_info = &did_blkp->blk_info[li];
				lp = &lbp->lb_locators[li];
				if (lp->l_flags & MDDB_F_DELETED)
					continue;

				if (!(did_info->info_flags & MDDB_DID_EXISTS))
					continue;

				if (((md_get_setstatus(setno) &
				    MD_SET_REPLICATED_IMPORT)) &&
				    (rip->ri_old_devid != (ddi_devid_t)NULL)) {
					if (ddi_devid_compare(rip->ri_old_devid,
					    did_icp->did_ic_devid[li]) != 0)
						continue;
				} else {
					if (ddi_devid_compare(rip->ri_devid,
					    did_icp->did_ic_devid[li]) != 0)
						continue;
				}

				if (strcmp(rip->ri_minor_name,
				    did_info->info_minor_name) != 0)
					continue;

				if (lp->l_blkno == rip->ri_blkno)
					break;
			}
		} else {
			/*
			 * This locator block MUST have locator (replica)
			 * information about itself.
			 */
			if (!mn_set) {
				for (li = 0; li < lbp->lb_loccnt; li++) {
					mddb_drvnm_t		*dn;
					mddb_sidelocator_t	*slp;

					lp = &lbp->lb_locators[li];
					slp = &lbp->
					    lb_sidelocators[s->s_sideno][li];
					if (lp->l_flags & MDDB_F_DELETED)
						continue;
					if (slp->l_mnum != md_getminor(
					    rip->ri_dev))
						continue;
					if (lp->l_blkno != rip->ri_blkno)
						continue;
					dn = &lbp->lb_drvnm[slp->l_drvnm_index];
					if (strncmp(dn->dn_data,
					    rip->ri_driver, MD_MAXDRVNM) == 0)
						break;
				}
			} else {
				for (li = 0; li < lbp->lb_loccnt; li++) {
					mddb_drvnm_t		*dn;
					mddb_mnsidelocator_t	*mnslp;
					mddb_mnlb_t		*mnlbp;
					int			i;

					/*
					 * Check all possible locators locking
					 * for match to the currently read-in
					 * locator, must match on:
					 *	- blkno
					 *	- side locator for this
					 *	  node's side
					 *	- side locator minor number
					 *	- side locator driver name
					 */

					/*
					 * Looking at sidelocs:
					 * cast lbp -> mnlbp
					 */
					mnlbp = (mddb_mnlb_t *)lbp;
					lp = &mnlbp->lb_locators[li];
					if (lp->l_flags & MDDB_F_DELETED)
						continue;
					if (lp->l_blkno != rip->ri_blkno)
						continue;

					for (i = 0; i < MD_MNMAXSIDES; i++) {
						mnslp = &mnlbp->
						    lb_mnsidelocators[i][li];
						if (mnslp->mnl_sideno ==
						    s->s_sideno) {
							break;
						}
					}
					/* No matching side found */
					if (i == MD_MNMAXSIDES)
						continue;
					if (mnslp->mnl_mnum !=
					    md_getminor(rip->ri_dev))
						continue;
					dn = &lbp->
					    lb_drvnm[mnslp->mnl_drvnm_index];
					if (strncmp(dn->dn_data,
					    rip->ri_driver, MD_MAXDRVNM) == 0)
						break;
				}
			}
		}

		/*
		 * Didn't find ourself in this locator block it means
		 * the locator block is a stale transplant. Probably from
		 * a user doing a dd.
		 */
		if (li == lbp->lb_loccnt)
			continue;

		/*
		 * Keep track of the number of accessed and valid
		 * locator blocks.
		 */
		lb_ok++;

		/*
		 * Read the tag in, skips invalid or blank tags.
		 * Only valid tags allocate storage
		 * Data tags are not used in MN disksets.
		 */
		if ((!mn_set) && (! dt_read(s, lbp, rip))) {
			/*
			 * Keep track of the number of tagged
			 * locator blocks.
			 */
			lb_tagged++;

			/* Keep a list of unique tags. */
			(void) dtl_addl(s, &rip->ri_dtp->dt_dtag);
		}

		if (!(md_get_setstatus(setno) & MD_SET_REPLICATED_IMPORT)) {
			/*
			 * go through locator block and add any other
			 * locations of the data base.
			 * For the replicated import case, this was done earlier
			 * and we really don't need or want to do so again
			 */
			cl = kmem_zalloc(sizeof (mddb_cfg_loc_t), KM_SLEEP);
			for (li = 0; li < lbp->lb_loccnt; li++) {
				lp = &lbp->lb_locators[li];
				if (lp->l_flags & MDDB_F_DELETED)
					continue;

				cl->l_devid_flags = MDDB_DEVID_GETSZ;
				cl->l_devid = (uint64_t)0;
				cl->l_devid_sz = 0;
				cl->l_old_devid = (uint64_t)0;
				cl->l_old_devid_sz = 0;
				cl->l_minor_name[0] = '\0';
				locator2cfgloc(lbp, cl, li, s->s_sideno,
				    did_icp);

				if (cl->l_devid_flags & MDDB_DEVID_SZ) {
					if ((cl->l_devid = (uintptr_t)kmem_alloc
					    (cl->l_devid_sz, KM_SLEEP))
					    == NULL) {
						continue;
					} else {
						cl->l_devid_flags =
						    MDDB_DEVID_SPACE;
					}
				}
				locator2cfgloc(lbp, cl, li, s->s_sideno,
				    did_icp);

				(void) ridev(&s->s_rip, cl, &lp->l_dev, 0);

				if (cl->l_devid_flags & MDDB_DEVID_SPACE)
					kmem_free((caddr_t)(uintptr_t)
					    cl->l_devid, cl->l_devid_sz);
			}
			kmem_free(cl, sizeof (mddb_cfg_loc_t));
		}

		/* Save LB for later */
		rip->ri_lbp = lbp;
		if (lbp->lb_flags & MDDB_DEVID_STYLE) {
			rip->ri_did_icp = did_icp;
			did_icp = (mddb_did_ic_t *)NULL;
			did_blkp = (mddb_did_blk_t *)NULL;
		} else
			rip->ri_did_icp = NULL;
		lbp = (mddb_lb_t *)NULL;
	}

	if (lbp != (mddb_lb_t *)NULL)
		kmem_free((caddr_t)lbp, dbtob(lb_blkcnt));

	if (did_icp != (mddb_did_ic_t *)NULL) {
		if (did_icp->did_ic_blkp != (mddb_did_blk_t *)NULL) {
			kmem_free((caddr_t)did_icp->did_ic_blkp, did_blkp_sz);
			did_blkp = (mddb_did_blk_t *)NULL;
		}
		if (did_icp->did_ic_dbp != (mddb_did_db_t *)NULL) {
			mddb_did_db_t	*did_dbp1, *did_dbp2;

			did_dbp1 = did_icp->did_ic_dbp;
			while (did_dbp1) {
				did_dbp2 = did_dbp1->db_next;
				kmem_free((caddr_t)did_dbp1->db_ptr,
				    dbtob(did_dbp1->db_blkcnt));
				kmem_free((caddr_t)did_dbp1,
				    sizeof (mddb_did_db_t));
				did_dbp1 = did_dbp2;
			}
		}
		kmem_free((caddr_t)did_icp, sizeof (mddb_did_ic_t));
	}

	if (did_blkp != (mddb_did_blk_t *)NULL) {
		kmem_free((caddr_t)did_blkp, did_blkp_sz);
	}

	/* No locator blocks were ok */
	if (lb_ok == 0)
		goto out;

	/* No tagged data was found - will be 0 for MN diskset */
	if (lb_tagged == 0)
		goto out;

	/* Find the highest non-deleted replica count */
	for (rip = s->s_rip; rip != NULL; rip = rip->ri_next) {
		int		lb_tot = 0;

		if (rip->ri_mbip == (mddb_mb_ic_t *)NULL)
			continue;

		if (rip->ri_lbp == (mddb_lb_t *)NULL)
			continue;

		for (li = 0; li < rip->ri_lbp->lb_loccnt; li++) {
			lp = &rip->ri_lbp->lb_locators[li];
			if (lp->l_flags & MDDB_F_DELETED)
				continue;
			lb_tot++;
		}

		if (lb_tot > lb_total)
			lb_total = lb_tot;
	}

	/* Count the number of unique tags */
	for (lb_tags = 0, dtlp = s->s_dtlp; dtlp != NULL; dtlp = dtlp->dtl_nx)
		lb_tags++;

	/* Should have at least one tag at this point */
	ASSERT(lb_tags > 0);


	/*
	 * If the number of tagged locators is not the same as the number of
	 * OK locators OR more than one tag exists, then make sure the
	 * selected tag will be written out later.
	 */
	if ((lb_tagged - lb_ok) != 0 || lb_tags > 1)
		md_set_setstatus(setno, MD_SET_TAGDATA);

	/* Only a single tag, take the tagged data */
	if (lb_tags == 1) {
		dt_setup(s, &s->s_dtlp->dtl_dt);
		md_set_setstatus(setno, MD_SET_USETAG);
		goto out;
	}

	/* Multiple tags, not selecting a tag, tag mode is on */
	if (! (md_get_setstatus(setno) & MD_SET_USETAG))
		retval = MDDB_E_TAGDATA;

out:

	return (retval);
}

/*
 *	1. Select a locator.
 *	2. check if enough locators now have current copies
 *	3. read in database from one of latest
 *	4. if known to have latest make all database the same
 *	5. if configuration has changed rewrite locators
 *
 * Parameters:
 * 	s - pointer to mddb_set structure
 *	flag - used in MN disksets to tell if this node is being joined to
 *		a diskset that is in the STALE state.  If the flag is
 *		MDDB_MN_STALE, then this node should be marked in the STALE
 *		state even if > 50% mddbs are available.  (The diskset can
 *		only change from STALE->OK if all nodes withdraw from the
 *		MN diskset and then rejoin).
 */
static int
load_old_replicas(
	mddb_set_t	*s,
	int		flag
)
{
	mddb_lb_t	*lbp = NULL;
	mddb_mnlb_t	*mnlbp = NULL;
	mddb_ri_t	*rip;
	mddb_locator_t	*lp;
	mddb_db_t	*dbp;
	mddb_de_ic_t	*dep;
	int		li;
	int		alc;
	int		lc;
	int		tlc;
	int		retval = 0;
	caddr_t		p;
	size_t		maxrecsize;
	set_t		setno = s->s_setno;
	mddb_did_db_t	*did_dbp1;
	mddb_did_info_t	*did_info;
	mddb_did_ic_t	*did_icp = NULL;
	md_dev64_t	*newdev;
	mddb_sidelocator_t	*slp = 0;
	mddb_mnsidelocator_t	*mnslp = 0;
	uchar_t		i;
	char		*name;
	ddi_devid_t	ret_devid;
	md_dev64_t	dev;
	uint_t		len, sz;
	char		*minor_name;
	int		write_lb = 0;
	int		rval;
	int		stale_rtn = 0;

	/* The only error path out of get_mbs_n_lbs() is MDDB_E_TAGDATA */
	if (retval = get_mbs_n_lbs(s, &write_lb))
		goto errout;

	if ((lbp = s->s_lbp = selectlocator(s)) == NULL) {
		retval = MDDB_E_NOLOCBLK;
		goto errout;
	}

	/* If a multi-node set, then set md_set.s_status flag */
	if (lbp->lb_flags & MDDB_MNSET) {
		md_set_setstatus(setno, MD_SET_MNSET);
		/*
		 * If data tag area had been allocated before set type was
		 * known - free it now.
		 */
		if (md_set[setno].s_dtp) {
			kmem_free((caddr_t)md_set[setno].s_dtp, MDDB_DT_BYTES);
			md_set[setno].s_dtp = NULL;
		}
	}

	/*
	 * If the replica is in devid format, setup the devid incore ptr.
	 */
	if (lbp->lb_flags & MDDB_DEVID_STYLE) {
		for (rip = s->s_rip; rip != NULL; rip = rip->ri_next) {
			if (rip->ri_lbp == s->s_lbp) {
				did_icp = s->s_did_icp = rip->ri_did_icp;
				break;
			}
		}
		/*
		 * If no devid incore info found - something has gone
		 * wrong so errout.
		 */
		if (rip == NULL) {
			retval = MDDB_E_NODEVID;
			goto errout;
		}

		/*
		 * Add all blocks containing devids to free list.
		 * Then remove addresses that actually contain devids.
		 */
		did_dbp1 = did_icp->did_ic_dbp;
		while (did_dbp1) {
			if (mddb_devid_free_add(s, did_dbp1->db_firstblk,
			    0, dbtob(did_dbp1->db_blkcnt))) {
				retval = MDDB_E_NOSPACE;
				goto errout;
			}

			did_dbp1 = did_dbp1->db_next;
		}
		for (li = 0; li < lbp->lb_loccnt; li++) {
			did_info = &(did_icp->did_ic_blkp->blk_info[li]);
			if (!(did_info->info_flags & MDDB_DID_EXISTS))
				continue;

			if (mddb_devid_free_delete(s, did_info->info_firstblk,
			    did_info->info_offset, did_info->info_length)) {
				/* unable to find disk block */
				retval = MDDB_E_NODEVID;
				goto errout;
			}
		}
	}

	/*
	 * create mddb_mbaray, count all locators and active locators.
	 */
	alc = 0;
	lc = 0;
	for (li = 0; li < lbp->lb_loccnt; li++) {
		ddi_devid_t	li_devid;

		lp = &lbp->lb_locators[li];

		if (lp->l_flags & MDDB_F_DELETED)
			continue;

		/* Count non-deleted replicas */
		lc++;

		/*
		 * Use the devid of this locator to compare with the rip
		 * list.  The scenario to watch out for here is that this
		 * locator could be on a disk that is dead and there could
		 * be a valid entry in the rip list for a different disk
		 * that has been moved to the dead disks dev_t.  We don't
		 * want to match with the moved disk.
		 */
		li_devid = NULL;
		(void) mddb_devid_get(s, li, &li_devid, &minor_name);

		for (rip = s->s_rip; rip != NULL; rip = rip->ri_next) {
			if (match_mddb(rip, li_devid, minor_name,
			    md_expldev(lp->l_dev), lp->l_blkno)) {
				break;
			}
		}
		if (rip == NULL) {
			/*
			 * If rip not found, then mark error in master block
			 * so that no writes are later attempted to this
			 * replica.  rip may not be setup if ridev
			 * failed due to un-found driver name.
			 */
			lp->l_flags |= MDDB_F_EMASTER;
			continue;
		}

		s->s_mbiarray[li] = rip->ri_mbip;

		lp->l_flags &= MDDB_F_ACTIVE;
		lp->l_flags |= (int)rip->ri_flags;

		if (rip->ri_transplant)
			lp->l_flags &= ~MDDB_F_ACTIVE;

		if (lp->l_flags & MDDB_F_LOCACC)
			alc++;
	}

	/* Save on a divide - calculate 50% + 1 up front */
	tlc = ((lc + 1) / 2);

	if (alc > tlc) {		/* alc > tlc		- OK */
		md_clr_setstatus(setno, MD_SET_STALE);
	} else if (alc < tlc) {		/* alc < tlc		- stale */
		md_set_setstatus(setno, MD_SET_STALE);
	} else if (lc & 1) {		/* alc == tlc && odd	- OK */
		md_clr_setstatus(setno, MD_SET_STALE);
	} else {			/* alc == tlc && even	- ? */
		/* Can do an accept, and are */
		if (md_get_setstatus(setno) & (MD_SET_ACCOK | MD_SET_ACCEPT)) {
			md_clr_setstatus(setno, MD_SET_STALE);
		} else {		/* possibly has a mediator */
			if (mediate(s)) {
				md_set_setstatus(setno, MD_SET_STALE);
			} else {
				md_clr_setstatus(setno, MD_SET_STALE);
			}
		}

		/*
		 * The mirrored_root_flag allows the sysadmin to decide to
		 * start the local set in a read/write (non-stale) mode
		 * when there are only 50% available mddbs on the system and
		 * when the root file system is on a mirror.  This is useful
		 * in a 2 disk system where 1 disk failure would cause an mddb
		 * quorum failure and subsequent boot failures since the root
		 * filesystem would be in a read-only state.
		 */
		if (mirrored_root_flag == 1 && setno == 0 &&
		    svm_bootpath[0] != 0) {
			md_clr_setstatus(setno, MD_SET_STALE);
		} else {
			if (md_get_setstatus(setno) & MD_SET_STALE) {
				/* Allow half mode - CAREFUL! */
				if (mddb_allow_half)
					md_clr_setstatus(setno, MD_SET_STALE);
			}
		}

		/*
		 * In a MN diskset,
		 *	- if 50% mddbs are unavailable and this
		 *		has been marked STALE above
		 * 	- master node isn't in the STALE state
		 *	- this node isn't the master node (this node
		 *		isn't the first node to join the set)
		 * then clear the STALE state and set TOOFEW.
		 *
		 * If this node is the master node and set was marked STALE,
		 * then the set stays STALE.
		 *
		 * If this node is not the master and this node's state is
		 * STALE and the master node is not marked STALE,
		 * then master node must be in the TOOFEW state or the
		 * master is panic'ing.  A MN diskset can only be placed into
		 * the STALE state by having the first node join the set
		 * with <= 50% mddbs.  There's no way for a MN diskset to
		 * transition between STALE and not-STALE states unless all
		 * nodes are withdrawn from the diskset or all nodes in the
		 * diskset are rebooted at the same time.
		 *
		 * So, mark this node's state as TOOFEW instead of STALE.
		 */
		if (((md_get_setstatus(setno) & (MD_SET_MNSET | MD_SET_STALE))
		    == (MD_SET_MNSET | MD_SET_STALE)) &&
		    ((flag & MDDB_MN_STALE) == 0) &&
		    (!(md_set[setno].s_am_i_master))) {
			md_clr_setstatus(setno, MD_SET_STALE);
			md_set_setstatus(setno, MD_SET_TOOFEW);
		}
	}

	/*
	 * If a MN set is marked STALE on the other nodes,
	 * mark it stale here.  Override all other considerations
	 * such as a mediator or > 50% mddbs available.
	 */
	if (md_get_setstatus(setno) & MD_SET_MNSET) {
		if (flag & MDDB_MN_STALE)
			md_set_setstatus(setno, MD_SET_STALE);
	}

	/*
	 * read a good copy of the locator names
	 * if an error occurs reading what is suppose
	 * to be a good copy continue looking for another
	 * good copy
	 */
	s->s_lnp = NULL;
	for (li = 0; li < lbp->lb_loccnt; li++) {
		lp = &lbp->lb_locators[li];
		if ((! (lp->l_flags & MDDB_F_ACTIVE)) ||
		    (lp->l_flags & MDDB_F_EMASTER))
			continue;

		/* Find rip entry for this locator if one exists */
		for (rip = s->s_rip; rip != NULL; rip = rip->ri_next) {
			if (match_mddb(rip, NULL, NULL, md_expldev(lp->l_dev),
			    lp->l_blkno))
				break;
		}

		if (rip == NULL) {
			continue;
		}

		/*
		 * Use the rip commitcnt since the commitcnt in lbp could
		 * been cleared by selectlocator.  Looking for a replica with
		 * the same commitcnt as the 'golden' copy in order to
		 * get the same data.
		 */
		if (rip->ri_commitcnt != lbp->lb_commitcnt) {
			continue;
		}

		/*
		 * Now have a copy of the database that is equivalent
		 * to the chosen locator block with respect to
		 * inittime, identifier and commitcnt.   Trying the
		 * equivalent databases in the order that they were
		 * written will provide the most up to date data.
		 */
		lp->l_flags |= readlocnames(s, li);
		if (s->s_lnp)
			break;
	}

	if (s->s_lnp == NULL) {
		retval = MDDB_E_NOLOCNMS;
		goto errout;
	}

	/*
	 * read a good copy of the data base
	 * if an error occurs reading what is suppose
	 * to be a good copy continue looking for another
	 * good copy
	 */

	s->s_dbp = NULL;
	for (li = 0; li < lbp->lb_loccnt; li++) {
		lp = &lbp->lb_locators[li];
		if ((! (lp->l_flags & MDDB_F_ACTIVE)) ||
		    (lp->l_flags & MDDB_F_EMASTER))
			continue;

		/* Find rip entry for this locator if one exists */
		for (rip = s->s_rip; rip != NULL; rip = rip->ri_next) {
			if (match_mddb(rip, NULL, NULL, md_expldev(lp->l_dev),
			    lp->l_blkno))
				break;
		}

		if (rip == NULL) {
			continue;
		}

		/*
		 * Use the rip commitcnt since the commitcnt in lbp could
		 * been cleared by selectlocator.  Looking for a replica with
		 * the same commitcnt as the 'golden' copy in order to
		 * get the same data.
		 */
		if (rip->ri_commitcnt != lbp->lb_commitcnt) {
			continue;
		}

		/*
		 * Now have a copy of the database that is equivalent
		 * to the chosen locator block with respect to
		 * inittime, identifier and commitcnt.   Trying the
		 * equivalent databases in the order that they were
		 * written will provide the most up to date data.
		 */
		lp->l_flags |= readcopy(s, li);

		if (s->s_dbp)
			break;
	}

	if (s->s_dbp == NULL) {
		retval = MDDB_E_NODIRBLK;
		goto errout;
	}

	lp->l_flags |= MDDB_F_MASTER;
	lp->l_flags |= MDDB_F_UP2DATE;

	/*
	 * go through and find largest record;
	 * Also fixup the user data area's
	 */
	maxrecsize = MAX(MDDB_BSIZE, s->s_databuffer_size);

	for (dbp = s->s_dbp; dbp != NULL; dbp = dbp->db_next)
		for (dep = dbp->db_firstentry; dep != NULL; dep = dep->de_next)
			if (dep->de_flags & MDDB_F_OPT)
				getoptrecord(s, dep);
			else {
				allocuserdata(dep);
				maxrecsize = MAX(dep->de_recsize, maxrecsize);
			}

	if (maxrecsize > s->s_databuffer_size) {
		p = (caddr_t)kmem_zalloc(maxrecsize, KM_SLEEP);
		if (s->s_databuffer_size)
			kmem_free(s->s_databuffer, s->s_databuffer_size);
		s->s_databuffer = p;
		s->s_databuffer_size = maxrecsize;
	}

	/* If we can clear the tag data record, do it now. */
	/* Data tags not supported on MN sets */
	if ((md_get_setstatus(setno) & MD_SET_CLRTAG) &&
	    (!(md_get_setstatus(setno) & MD_SET_MNSET)))
		dt_setup(s, NULL);

	/* This will return non-zero if STALE or TOOFEW */
	/* This will write out chosen replica image to all replicas */
	stale_rtn = selectreplicas(s, MDDB_SCANALL);

	if ((md_get_setstatus(setno) & MD_SET_REPLICATED_IMPORT)) {
		ddi_devid_t	devidptr;

		/*
		 * ignore the return value from selectreplicas because we
		 * may have a STALE or TOOFEW set in the case of a partial
		 * replicated diskset. We will fix that up later.
		 */

		lbp = s->s_lbp;
		for (li = 0; li < lbp->lb_loccnt; li++) {
			did_info = &(did_icp->did_ic_blkp->blk_info[li]);

			if (did_info->info_flags & MDDB_DID_EXISTS) {
				devidptr = s->s_did_icp->did_ic_devid[li];
				lp = &lbp->lb_locators[li];
				for (rip = s->s_rip; rip != NULL;
				    rip = rip->ri_next) {
					if (rip->ri_old_devid == 0)
						continue;
					if (ddi_devid_compare(rip->ri_old_devid,
					    devidptr) != 0) {
						continue;
					}
					if (update_locatorblock(s,
					    md_expldev(lp->l_dev),
					    rip->ri_devid, rip->ri_old_devid)) {
						goto errout;
					}
				}
			}
		}
	} else {
		if (stale_rtn)
			goto errout;
	}

	/*
	 * If the replica is in device id style - validate the device id's,
	 * if present, in the locator block devid area.
	 */
	newdev = kmem_zalloc(sizeof (md_dev64_t) * MDDB_NLB, KM_SLEEP);
	if (lbp->lb_flags & MDDB_DEVID_STYLE) {
		for (li = 0; li < lbp->lb_loccnt; li++) {
			newdev[li] = 0;
			lp = &lbp->lb_locators[li];
			if (lp->l_flags & MDDB_F_DELETED)
				continue;
			did_info = &(did_icp->did_ic_blkp->blk_info[li]);
			dev = md_expldev(lp->l_dev);
			if (did_info->info_flags & MDDB_DID_EXISTS) {
				/* Validate device id on current system */
				newdev[li] = dev;
				if (mddb_devid_validate(
				    did_icp->did_ic_devid[li],
				    &(newdev[li]),
				    did_info->info_minor_name) == 0) {
					/* Set valid flag */
					did_info->info_flags |= MDDB_DID_VALID;
				} else {
					lp->l_flags |= MDDB_F_EMASTER;
				}
			} else if (!(MD_UPGRADE)) {
				/*
				 * If a device doesn't have a device id,
				 * check if there is now a device ID
				 * associated with device.  If one exists,
				 * add it to the locator block devid area.
				 * If there's not enough space to add it,
				 * print a warning.
				 * Don't do this during upgrade.
				 */
				dev_t ddi_dev = md_dev64_to_dev(dev);
				if (ddi_lyr_get_devid(ddi_dev, &ret_devid) ==
				    DDI_SUCCESS) {
					if (ddi_lyr_get_minor_name(ddi_dev,
					    S_IFBLK, &minor_name)
					    == DDI_SUCCESS) {
						if (mddb_devid_add(s, li,
						    ret_devid, minor_name)) {
							cmn_err(CE_WARN,
							    "Not enough space"
							    " in metadevice"
							    " state"
							    " database\n");
							cmn_err(CE_WARN,
							    "to add relocation"
							    " information for"
							    " device:\n");
							cmn_err(CE_WARN,
							    " major = %d, "
							    " minor = %d\n",
							    getmajor(ddi_dev),
							    getminor(ddi_dev));
						} else {
							write_lb = 1;
						}
						kmem_free(minor_name,
						    strlen(minor_name) + 1);
					}
					ddi_devid_free(ret_devid);
				}
			}
		}

		/*
		 * If a device has a valid device id and if the dev_t
		 * associated with the device id has changed, update the
		 * driver name, minor num and dev_t in the local and side
		 * locators to match the dev_t that the system currently
		 * associates with the device id.
		 *
		 * Don't do this during upgrade.
		 */
		if (!(MD_UPGRADE)) {
		    for (li = 0; li < lbp->lb_loccnt; li++) {
			lp = &lbp->lb_locators[li];
			if (lp->l_flags & MDDB_F_DELETED)
				continue;
			did_info = &(did_icp->did_ic_blkp->blk_info[li]);
			if ((did_info->info_flags & MDDB_DID_VALID) &&
			    !(did_info->info_flags & MDDB_DID_UPDATED)) {
				if (lbp->lb_flags & MDDB_MNSET) {
					int 	j;
					int	index = -1;
					mnlbp = (mddb_mnlb_t *)lbp;
					for (j = 0; j < MD_MNMAXSIDES; j++) {
					    mnslp = &mnlbp->
						lb_mnsidelocators[j][li];
					    if (mnslp->mnl_sideno ==
						s->s_sideno)
						break;
					    if (mnslp->mnl_sideno == 0)
						index = j;
					}
					if (j == MD_MNMAXSIDES) {
					    /* No match found; take empty */
					    mnslp = &mnlbp->
						lb_mnsidelocators[index][li];
					    write_lb = 1;
					    mnslp->mnl_mnum =
						md_getminor(newdev[li]);
					} else if (mnslp->mnl_mnum !=
					    md_getminor(newdev[li])) {
						write_lb = 1;
						mnslp->mnl_mnum =
						    md_getminor(newdev[li]);
					}
				} else {
					slp = &lbp->
					    lb_sidelocators[s->s_sideno][li];
					if (slp->l_mnum !=
					    md_getminor(newdev[li])) {
						write_lb = 1;
						slp->l_mnum =
						    md_getminor(newdev[li]);
					}
				}
				name = ddi_major_to_name(
						md_getmajor(newdev[li]));
				if (lbp->lb_flags & MDDB_MNSET) {
					i = mnslp->mnl_drvnm_index;
				} else {
					i = slp->l_drvnm_index;
				}
				if (strncmp(lbp->lb_drvnm[i].dn_data, name,
					lbp->lb_drvnm[i].dn_len) != 0) {
					/* Driver name has changed */
					len = strlen(name);
					/* Look for the driver name */
					for (i = 0; i < MDDB_DRVNMCNT; i++) {
						if (lbp->lb_drvnm[i].dn_len
						    != len)
							continue;
						if (strncmp(
						    lbp->lb_drvnm[i].dn_data,
						    name, len) == 0)
							break;
					}
					/* Didn't find one, add it */
					if (i == MDDB_DRVNMCNT) {
					    for (i = 0; i < MDDB_DRVNMCNT;
						i++) {
						if (lbp->lb_drvnm[i].dn_len
						    == 0)
							break;
					    }
					    if (i == MDDB_DRVNMCNT) {
						cmn_err(CE_WARN,
						    "Unable to update driver"
						    " name for dev:  "
						    "major = %d, "
						    "minor = %d\n",
						    md_getmajor(newdev[li]),
						    md_getminor(newdev[li]));
						continue;
					    }
					    (void) strncpy(
						lbp->lb_drvnm[i].dn_data,
						name, MD_MAXDRVNM);
					    lbp->lb_drvnm[i].dn_len =
						(uchar_t)strlen(name);
					}
					/* Fill in the drvnm index */
					if (lbp->lb_flags & MDDB_MNSET) {
						mnslp->mnl_drvnm_index = i;
					} else {
						slp->l_drvnm_index = i;
					}
					write_lb = 1;
				}
				did_info->info_flags |= MDDB_DID_UPDATED;
			}
		}
	    }
	}
	kmem_free(newdev, sizeof (md_dev64_t) * MDDB_NLB);

	/*
	 * If locator block has been changed by get_mbs_n_lbs,
	 * by addition of new device id, by updated minor name or
	 * by updated driver name - write out locator block.
	 */
	if (write_lb) {
		rval = push_lb(s);
		(void) upd_med(s, "load_old_replicas(0)");
		if (rval)
			goto errout;
	}

	/*
	 * If the tag was moved, allocated, or a BADTAG was seen for some other
	 * reason, then make sure tags are written to all the replicas.
	 * Data tags not supported on MN sets.
	 */
	if (!(md_get_setstatus(setno) & MD_SET_MNSET)) {
		if (! (lc = dt_alloc_if_needed(s))) {
			for (li = 0; li < lbp->lb_loccnt; li++) {
				lp = &lbp->lb_locators[li];

				if ((! (lp->l_flags & MDDB_F_ACTIVE)) ||
				    (lp->l_flags & MDDB_F_EMASTER))
					continue;

				if (lp->l_flags & MDDB_F_BADTAG) {
					lc = 1;
					break;
				}
			}
		}

		if (lc) {
			md_set_setstatus(setno, MD_SET_TAGDATA);
			md_clr_setstatus(setno, MD_SET_BADTAG);
			(void) selectreplicas(s, MDDB_SCANALL);
		}
	}

errout:

	/* Free extraneous rip components. */
	for (rip = s->s_rip; rip != NULL; rip = rip->ri_next) {
		/* Get rid of lbp's and dtp's */

		if (rip->ri_lbp != lbp) {
			if (rip->ri_dtp != (mddb_dt_t *)NULL) {
				kmem_free((caddr_t)rip->ri_dtp, MDDB_DT_BYTES);
				rip->ri_dtp = (mddb_dt_t *)NULL;
			}

			if (rip->ri_devid != (ddi_devid_t)NULL) {
				sz = (int)ddi_devid_sizeof(rip->ri_devid);
				kmem_free((caddr_t)rip->ri_devid, sz);
				rip->ri_devid = (ddi_devid_t)NULL;
			}
			if (rip->ri_old_devid != (ddi_devid_t)NULL) {
				sz = (int)ddi_devid_sizeof(rip->ri_old_devid);
				kmem_free((caddr_t)rip->ri_old_devid, sz);
				rip->ri_old_devid = (ddi_devid_t)NULL;
			}

			if (rip->ri_lbp != (mddb_lb_t *)NULL) {
				mddb_devid_icp_free(&rip->ri_did_icp,
				    rip->ri_lbp);

				kmem_free((caddr_t)rip->ri_lbp,
				    dbtob(rip->ri_lbp->lb_blkcnt));
				rip->ri_lbp = (mddb_lb_t *)NULL;
			}
		}

		if (lbp != NULL) {
			for (li = 0; li < lbp->lb_loccnt; li++) {
				lp = &lbp->lb_locators[li];
				if (lp->l_flags & MDDB_F_DELETED)
					continue;
				if (rip->ri_dev == md_expldev(lp->l_dev) &&
				    rip->ri_blkno == lp->l_blkno)
					break;
			}
			if (li < lbp->lb_loccnt)
				continue;
		}

		/*
		 * Get rid of mbp's:
		 *	if lbp, those out of lb_loccnt bounds
		 *	if !lbp,  all of them.
		 */
		if (rip->ri_mbip) {
			md_dev64_t dev64 = md_xlate_targ_2_mini(rip->ri_dev);
			if (dev64 != NODEV64)
				mddb_devclose(dev64);

			free_mbipp(&rip->ri_mbip);
		}
		/*
		 * Turn off MDDB_F_EMASTER flag in a diskset since diskset
		 * code always ends up calling ridev for all replicas
		 * before calling load_old_replicas.  ridev will reset
		 * MDDB_F_EMASTER flag if flag was due to unresolved devid.
		 */
		if (setno != MD_LOCAL_SET)
			rip->ri_flags &= ~MDDB_F_EMASTER;
	}
	return (retval);
}

/*
 * Given the devt from the md.conf info, get the devid for the device.
 */
static void
lookup_db_devid(mddb_cfg_loc_t *cl)
{
	dev_t		ldev;
	ddi_devid_t	devid;
	char		*minor;

	if (ddi_name_to_major(cl->l_driver) == (major_t)-1) {
		cmn_err(CE_NOTE, "mddb: unknown major name '%s'", cl->l_driver);
		return;
	}

	ldev = makedevice(ddi_name_to_major(cl->l_driver), cl->l_mnum);
	if (ddi_lyr_get_devid(ldev, &devid) != DDI_SUCCESS) {
		cmn_err(CE_NOTE, "mddb: unable to get devid for '%s', 0x%x",
		    cl->l_driver, cl->l_mnum);
		return;
	}

	if (ddi_lyr_get_minor_name(ldev, S_IFBLK, &minor) != DDI_SUCCESS) {
		cmn_err(CE_NOTE, "mddb: unable to get minor name 0x%x",
		    cl->l_mnum);
		return;
	}

	cl->l_devid_flags = MDDB_DEVID_SPACE | MDDB_DEVID_VALID | MDDB_DEVID_SZ;
	cl->l_devid_sz = (int)ddi_devid_sizeof(devid);
	cl->l_devid = (uint64_t)(uintptr_t)devid;
	(void) strlcpy(cl->l_minor_name, minor, MDDB_MINOR_NAME_MAX);

	kmem_free(minor, strlen(minor) + 1);
}

/*
 * grab driver name, minor, block and devid out of
 * strings like "driver:minor:block:devid"
 */
static int
parse_db_loc(
	char		*str,
	mddb_cfg_loc_t	*clp
)
{
	char		*p, *e;
	char		*minor_name;
	ddi_devid_t	ret_devid;

	clp->l_dev = 0;
	p = clp->l_driver;
	e = p + sizeof (clp->l_driver) - 1;
	while ((*str != ':') && (*str != '\0') && (p < e))
		*p++ = *str++;
	*p = '\0';
	if (*str++ != ':')
		return (-1);
	clp->l_mnum = 0;
	while (ISNUM(*str)) {
		clp->l_mnum *= 10;
		clp->l_mnum += *str++ - '0';
	}
	if (*str++ != ':')
		return (-1);
	clp->l_blkno = 0;
	while (ISNUM(*str)) {
		clp->l_blkno *= 10;
		clp->l_blkno += *str++ - '0';
	}
	if (*str++ != ':')
		return (-1);

	/*
	 * If the md_devid_destroy flag is set, ignore the device ids.
	 * This is only to used in a catastrophic failure case.  Examples
	 * would be where the device id of all drives in the system
	 * (especially the mirror'd root drives) had been changed
	 * by firmware upgrade or by a patch to an existing disk
	 * driver.  Another example would be in the case of non-unique
	 * device ids due to a bug.  The device id would be valid on
	 * the system, but would return the wrong dev_t.
	 */
	if (md_devid_destroy) {
		clp->l_devid_flags = 0;
		clp->l_devid = (uint64_t)NULL;
		clp->l_devid_sz = 0;
		clp->l_old_devid = (uint64_t)NULL;
		clp->l_old_devid_sz = 0;
		clp->l_minor_name[0] = '\0';
		return (0);
	}

	if (ddi_devid_str_decode(str,
	    (ddi_devid_t *)&ret_devid, &minor_name) == DDI_FAILURE)
		return (-1);

	clp->l_devid = (uint64_t)(uintptr_t)ret_devid;
	clp->l_devid_flags = 0;
	clp->l_old_devid = (uint64_t)NULL;
	clp->l_old_devid_sz = 0;

	/* If no device id associated with device, just return */
	if ((ddi_devid_t)(uintptr_t)clp->l_devid == (ddi_devid_t)NULL) {
		clp->l_devid_sz = 0;
		clp->l_minor_name[0] = '\0';
		if (strcmp(str, "id0") == 0 && md_devid_destroy == 0 &&
		    md_keep_repl_state == 0) {
			/*
			 * No devid in md.conf; we're in recovery mode so
			 * lookup the devid for the device as specified by
			 * the devt in md.conf.
			 */
			lookup_db_devid(clp);
		}
		return (0);
	}

	clp->l_devid_flags = MDDB_DEVID_SPACE | MDDB_DEVID_VALID |
	    MDDB_DEVID_SZ;
	clp->l_devid_sz = (int)ddi_devid_sizeof(
	    (ddi_devid_t)(uintptr_t)clp->l_devid);
	(void) strcpy(clp->l_minor_name, minor_name);
	kmem_free(minor_name, strlen(minor_name) + 1);

	return (0);
}

/*
 * grab driver name, minor, and block out of
 * strings like "driver:minor:block:devid driver:minor:block:devid ..."
 */
static void
parse_db_string(
	char		*str
)
{
	char		*p, *e;
	mddb_cfg_loc_t	*cl;
	char		restore_space;

	/* CSTYLED */
	cl = kmem_zalloc(sizeof (mddb_cfg_loc_t), KM_SLEEP);
	for (p = str; (*p != '\0'); ) {
		for (; ((*p != '\0') && (ISWHITE(*p))); ++p)
			;
		if (*p == '\0')
			break;
		for (e = p; ((*e != '\0') && (! ISWHITE(*e))); ++e)
			;
		/*
		 * Only give parse_db_loc 1 entry, so stuff a null into
		 * the string if we're not at the end.  We need to save this
		 * char and restore it after call.
		 */
		restore_space = '\0';
		if (*e != '\0') {
			restore_space = *e;
			*e = '\0';
		}
		if (parse_db_loc(p, cl) != 0) {
			cmn_err(CE_NOTE, "mddb: parsing error on '%s'", p);
		} else {
			(void) ridev(
			    &((mddb_set_t *)md_set[MD_LOCAL_SET].s_db)->s_rip,
			    cl, NULL, MDDB_F_PTCHED);
			if (cl->l_devid_flags & MDDB_DEVID_SPACE) {
				kmem_free((caddr_t)(uintptr_t)cl->l_devid,
				    cl->l_devid_sz);
			}
		}
		if (restore_space != '\0') {
			*e = restore_space;
		}
		p = e;
	}
	kmem_free(cl, sizeof (mddb_cfg_loc_t));
}

/*
 * grab database locations supplied by md.conf as properties
 */
static void
parse_db_strings(void)
{
	int		bootlist_id;
	int		proplen;
	/*
	 * size of _bootlist_name should match uses of line and entry in
	 * libmeta meta_systemfile_append_mddb routine (meta_systemfile.c)
	 */
	char 		_bootlist_name[MDDB_BOOTLIST_MAX_LEN];
	char		*bootlist_name;
	caddr_t		prop;

/*
 * Step through the bootlist properties one at a time by forming the
 * correct name, fetching the property, parsing the property and
 * then freeing the memory.  If a property does not exist or returns
 * some form of error just ignore it.  There is no guarantee that
 * the properties will always exist in sequence, for example
 * mddb_bootlist1 may exist and mddb_bootlist2 may not exist with
 * mddb_bootlist3 existing.
 */
	bootlist_name = &_bootlist_name[0];
	for (bootlist_id = 0; bootlist_id < md_maxbootlist; bootlist_id++) {

		proplen = 0;
		(void) sprintf(bootlist_name, "mddb_bootlist%d", bootlist_id);

		if (ddi_getlongprop(DDI_DEV_T_ANY, md_devinfo,
		    DDI_PROP_CANSLEEP, bootlist_name, (caddr_t)&prop,
		    &proplen) != DDI_PROP_SUCCESS)
			continue;

		if (proplen <= 0)
			continue;

		if (md_init_debug)
			cmn_err(CE_NOTE, "%s is %s", bootlist_name, prop);

		parse_db_string(prop);
		kmem_free(prop, proplen);
	}
}

static int
initit(
	set_t		setno,
	int		flag
)
{
	int		i;
	mddb_set_t	*s;
	mddb_lb_t	*lbp;		/* pointer to locator block */
	mddb_ln_t	*lnp;		/* pointer to locator names */
	mddb_db_t	*dbp;		/* pointer to directory block */
	mddb_did_blk_t	*did_blkp;	/* pointer to Device ID block */
	mddb_did_ic_t	*did_icp;	/* pointer to Device ID incore area */
	mddb_bf_t	*bfp;
	side_t		sideno;
	side_t		maxsides;
	mddb_block_t	lb_blkcnt;
	int		retval = 0;
	md_dev64_t	dev;
	mddb_mnlb_t	*mnlbp;
	int		devid_flag;

	/* single thread's all loads/unloads of set's */
	mutex_enter(&mddb_lock);
	mutex_enter(SETMUTEX(setno));

	if (((mddb_set_t *)md_set[setno].s_db) == NULL) {
		mutex_exit(SETMUTEX(setno));
		mutex_exit(&mddb_lock);
		return (MDDB_E_NOTNOW);
	}

	s = (mddb_set_t *)md_set[setno].s_db;

	single_thread_start(s);

	/*
	 * init is already underway, block. Return success.
	 */
	if (s->s_lbp) {
		single_thread_end(s);
		mutex_exit(SETMUTEX(setno));
		mutex_exit(&mddb_lock);
		return (0);
	}

	uniqtime32(&s->s_inittime);

	/* grab database locations patched by /etc/system */
	if (setno == MD_LOCAL_SET)
		parse_db_strings();

	s->s_mbiarray = (mddb_mb_ic_t **)kmem_zalloc(
	    sizeof (mddb_mb_ic_t *) * mddb_maxcopies, KM_SLEEP);

	s->s_zombie = 0;
	s->s_staledeletes = 0;
	s->s_optcmtcnt = 0;
	s->s_opthavelck = 0;
	s->s_optwantlck = 0;
	s->s_optwaiterr = 0;
	s->s_opthungerr = 0;

	/*
	 * KEEPTAG can never be set for a MN diskset since no tags are
	 * allowed to be stored in a MN diskset.  No way to check
	 * if this is a MN diskset or not at this point since the mddb
	 * hasn't been read in from disk yet.  (flag will only have
	 * MUTLINODE bit set if a new set is being created.)
	 */
	if (! (md_get_setstatus(s->s_setno) & MD_SET_KEEPTAG))
		dt_setup(s, NULL);

	md_clr_setstatus(s->s_setno, MD_SET_TOOFEW);

	for (i = 0; i <	mddb_maxbufheaders; i++) {
		bfp = (mddb_bf_t *)kmem_zalloc(sizeof (*bfp), KM_SLEEP);
		sema_init(&bfp->bf_buf.b_io, 0, NULL,
		    SEMA_DEFAULT, NULL);
		sema_init(&bfp->bf_buf.b_sem, 0, NULL,
		    SEMA_DEFAULT, NULL);
		bfp->bf_buf.b_offset = -1;
		freebuffer(s, bfp);
	}

	retval = load_old_replicas(s, flag);
	/* If 0 return value - success */
	if (! retval) {
		single_thread_end(s);
		mutex_exit(SETMUTEX(setno));
		mutex_exit(&mddb_lock);
		return (0);
	}

	/*
	 * If here, then the load_old_replicas() failed
	 */


	/* If the database was supposed to exist. */
	if (flag & MDDB_MUSTEXIST) {
		if (s->s_mbiarray != (mddb_mb_ic_t **)NULL) {
			for (i = 0; i < mddb_maxcopies;	 i++) {
				if (! s->s_mbiarray[i])
					continue;
				dev = md_expldev(
				    s->s_lbp->lb_locators[i].l_dev);
				dev = md_xlate_targ_2_mini(dev);
				if (dev != NODEV64)
					mddb_devclose(dev);

				free_mbipp(&s->s_mbiarray[i]);
			}

			kmem_free((caddr_t)s->s_mbiarray,
			    sizeof (mddb_mb_ic_t *) * mddb_maxcopies);
			s->s_mbiarray = NULL;
		}

		if (s->s_lnp != (mddb_ln_t *)NULL) {
			kmem_free((caddr_t)s->s_lnp,
			    dbtob(s->s_lbp->lb_lnblkcnt));
			s->s_lnp = (mddb_ln_t *)NULL;
		}

		mddb_devid_icp_free(&s->s_did_icp, s->s_lbp);

		if (s->s_lbp != (mddb_lb_t *)NULL) {
			kmem_free((caddr_t)s->s_lbp,
			    dbtob(s->s_lbp->lb_blkcnt));
			s->s_lbp = (mddb_lb_t *)NULL;
		}

		while ((bfp = allocbuffer(s, MDDB_NOSLEEP)) != NULL)
			kmem_free((caddr_t)bfp, sizeof (*bfp));

		single_thread_end(s);
		mutex_exit(SETMUTEX(setno));
		mutex_exit(&mddb_lock);

		if (retval == MDDB_E_TAGDATA)
			return (retval);

		/* Want a bit more detailed error messages */
		if (mddb_db_err_detail)
			return (retval);

		return (MDDB_E_NODB);
	}


	/*
	 * MDDB_NOOLDOK set - Creating a new database, so do
	 * more initialization.
	 */

	lb_blkcnt = (mddb_block_t)((setno == MD_LOCAL_SET) ?
	    MDDB_LOCAL_LBCNT : MDDB_LBCNT);
	if (flag & MDDB_MULTINODE) {
		lb_blkcnt = MDDB_MNLBCNT;
	}

	if (s->s_lbp == NULL)
		s->s_lbp = (mddb_lb_t *)kmem_alloc(dbtob(lb_blkcnt), KM_SLEEP);
	lbp = s->s_lbp;

	bzero((caddr_t)lbp, dbtob(lb_blkcnt));
	lbp->lb_setno = setno;
	lbp->lb_magic = MDDB_MAGIC_LB;
	if (flag & MDDB_MULTINODE) {
		lbp->lb_revision = MDDB_REV_MNLB;
	} else {
		lbp->lb_revision = MDDB_REV_LB;
	}
	lbp->lb_inittime = s->s_inittime;
	if (flag & MDDB_MULTINODE) {
		mnlbp = (mddb_mnlb_t *)lbp;
		for (i = 0; i < MDDB_NLB; i++) {
			for (sideno = 0; sideno < MD_MNMAXSIDES; sideno++) {
				mddb_mnsidelocator_t	*mnslp;
				mnslp = &mnlbp->lb_mnsidelocators[sideno][i];
				mnslp->mnl_mnum = NODEV32;
				mnslp->mnl_sideno = 0;
				mnslp->mnl_drvnm_index = 0;
			}
		}
	} else {
		maxsides = ((setno == MD_LOCAL_SET) ? 1 : MD_MAXSIDES);
		for (i = 0; i < MDDB_NLB; i++) {
			for (sideno = 0; sideno < maxsides; sideno++) {
				mddb_sidelocator_t	*slp;
				slp = &lbp->lb_sidelocators[sideno][i];
				slp->l_mnum = NODEV32;
			}
		}
	}
	lbp->lb_blkcnt = lb_blkcnt;

	/* lb starts on block 0 */
	/* locator names starts after locator block */
	lbp->lb_lnfirstblk = lb_blkcnt;
	if (flag & MDDB_MULTINODE) {
		lbp->lb_lnblkcnt = (mddb_block_t)MDDB_MNLNCNT;
	} else {
		lbp->lb_lnblkcnt = (mddb_block_t)((setno == MD_LOCAL_SET) ?
		    MDDB_LOCAL_LNCNT : MDDB_LNCNT);
	}

	if (flag & MDDB_MULTINODE) {
		/* Creating a multinode diskset */
		md_set_setstatus(setno, MD_SET_MNSET);
		lbp->lb_flags |= MDDB_MNSET;
	}

	/* Data portion of mddb located after locator names */
	lbp->lb_dbfirstblk = lbp->lb_lnfirstblk + lbp->lb_lnblkcnt;

	/* the btodb that follows is converting the directory block size */
	/* Data tag part of mddb located after first block of mddb data */
	lbp->lb_dtfirstblk = (mddb_block_t)(lbp->lb_dbfirstblk +
	    btodb(MDDB_BSIZE));
	/* Data tags are not used in MN diskset - so set count to 0 */
	if (flag & MDDB_MULTINODE)
		lbp->lb_dtblkcnt = (mddb_block_t)0;
	else
		lbp->lb_dtblkcnt = (mddb_block_t)MDDB_DT_BLOCKS;


	lnp = (mddb_ln_t *)kmem_zalloc(dbtob(lbp->lb_lnblkcnt), KM_SLEEP);
	lnp->ln_magic = MDDB_MAGIC_LN;
	if (flag & MDDB_MULTINODE) {
		lnp->ln_revision = MDDB_REV_MNLN;
	} else {
		lnp->ln_revision = MDDB_REV_LN;
	}
	s->s_lnp = lnp;

	/*
	 * Set up Device ID portion of Locator Block.
	 * Do not set locator to device id style if
	 * md_devid_destroy is 1 and md_keep_repl_state is 1
	 * (destroy all device id data and keep replica in
	 * non device id mode).
	 *
	 * This is logically equivalent to set locator to
	 * device id style if md_devid_destroy is 0 or
	 * md_keep_repl_state is 0.
	 *
	 * In SunCluster environment, device id mode is disabled
	 * which means diskset will be run in non-devid mode.  For
	 * localset, the behavior will remain intact and run in
	 * device id mode.
	 *
	 * In multinode diskset devids are turned off.
	 */
	devid_flag = 1;
	if (cluster_bootflags & CLUSTER_CONFIGURED)
		if (setno != MD_LOCAL_SET)
			devid_flag = 0;
	if (flag & MDDB_MULTINODE)
		devid_flag = 0;
	if ((md_devid_destroy == 1) && (md_keep_repl_state == 1))
		devid_flag = 0;
	/*
	 * if we weren't devid style before and md_keep_repl_state=1
	 * we need to stay non-devid
	 */
	if (((lbp->lb_flags & MDDB_DEVID_STYLE) == 0) &&
	    (md_keep_repl_state == 1))
		devid_flag = 0;
	if (devid_flag) {
		lbp->lb_didfirstblk = lbp->lb_dtfirstblk +
		    lbp->lb_dtblkcnt;
		lbp->lb_didblkcnt = (mddb_block_t)MDDB_DID_BLOCKS;
		lbp->lb_flags |= MDDB_DEVID_STYLE;

		did_icp = (mddb_did_ic_t *)kmem_zalloc
		    (sizeof (mddb_did_ic_t), KM_SLEEP);
		did_blkp = (mddb_did_blk_t *)
		    kmem_zalloc(dbtob(lbp->lb_didblkcnt), KM_SLEEP);
		did_blkp->blk_magic = MDDB_MAGIC_DI;
		did_blkp->blk_revision = MDDB_REV_DI;
		did_icp->did_ic_blkp = did_blkp;
		s->s_did_icp = did_icp;
	}

	setidentifier(s, &lbp->lb_ident);
	uniqtime32(&lbp->lb_timestamp);
	dbp = (mddb_db_t *)kmem_zalloc(sizeof (mddb_db_t), KM_SLEEP);
	dbp->db_magic = MDDB_MAGIC_DB;
	dbp->db_revision = MDDB_REV_DB;
	uniqtime32(&dbp->db_timestamp);
	dbp->db_nextblk = 0;
	dbp->db_firstentry = NULL;
	dbp->db_blknum = lbp->lb_dbfirstblk;
	dbp->db_recsum = MDDB_GLOBAL_XOR;
	s->s_dbp = dbp;
	single_thread_end(s);
	mutex_exit(SETMUTEX(setno));
	mutex_exit(&mddb_lock);
	return (0);
}

mddb_set_t *
mddb_setenter(
	set_t		setno,
	int		flag,
	int		*errorcodep
)
{
	mddb_set_t	*s;
	int		err = 0;
	size_t		sz = sizeof (void *) * MD_MAXUNITS;

	mutex_enter(SETMUTEX(setno));
	if (! md_set[setno].s_db) {
		mutex_exit(SETMUTEX(setno));
		if (errorcodep != NULL)
			*errorcodep = MDDB_E_NOTOWNER;
		return (NULL);
	}

	/* Allocate s_un and s_ui arrays if not already present. */
	if (md_set[setno].s_un == NULL) {
		md_set[setno].s_un = kmem_zalloc(sz, KM_NOSLEEP);
		if (md_set[setno].s_un == NULL) {
			mutex_exit(SETMUTEX(setno));
			if (errorcodep != NULL)
				*errorcodep = MDDB_E_NOTOWNER;
			return (NULL);
		}
	}
	if (md_set[setno].s_ui == NULL) {
		md_set[setno].s_ui = kmem_zalloc(sz, KM_NOSLEEP);
		if (md_set[setno].s_ui == NULL) {
			mutex_exit(&md_set[setno].s_dbmx);
			kmem_free(md_set[setno].s_un, sz);
			md_set[setno].s_un = NULL;
			if (errorcodep != NULL)
				*errorcodep = MDDB_E_NOTOWNER;
			return (NULL);
		}
	}
	s = (mddb_set_t *)md_set[setno].s_db;
	if (s->s_lbp)
		return (s);

	if (flag & MDDB_NOINIT)
		return (s);

	/*
	 * Release the set mutex - it will be acquired and released in
	 * initit after acquiring the mddb_lock.  This is done to assure
	 * that mutexes are always acquired in the same order to prevent
	 * possible deadlock
	 */
	mutex_exit(SETMUTEX(setno));

	if ((err = initit(setno, flag)) != 0) {
		if (errorcodep != NULL)
			*errorcodep = err;
		return (NULL);
	}

	mutex_enter(SETMUTEX(setno));
	return ((mddb_set_t *)md_set[setno].s_db);
}

/*
 * Release the set lock for a given set.
 *
 * In a MN diskset, this routine may send messages to the rpc.mdcommd
 * in order to have the slave nodes re-parse parts of the mddb.
 * Messages are only sent if the global ioctl lock is not held.
 *
 * With the introduction of multi-threaded ioctls, there is no way
 * to determine which thread(s) are holding the ioctl lock.  So, if
 * the ioctl lock is held (by process X) process X will send the
 * messages to the slave nodes when process X releases the ioctl lock.
 */
void
mddb_setexit(
	mddb_set_t	*s
)
{
	md_mn_msg_mddb_parse_t		*mddb_parse_msg;
	md_mn_kresult_t			*kresult;
	mddb_lb_t			*lbp = s->s_lbp;
	int				i;
	int				rval = 1;

	/*
	 * If not a MN diskset OR
	 * a MN diskset but this node isn't master,
	 * then release the mutex.
	 */
	if (!(MD_MNSET_SETNO(s->s_setno)) ||
	    ((MD_MNSET_SETNO(s->s_setno)) &&
	    (!md_set[s->s_setno].s_am_i_master))) {
		mutex_exit(SETMUTEX(s->s_setno));
		return;
	}

	/*
	 * If global ioctl lock is held, then send no messages,
	 * just release mutex and return.
	 *
	 */
	if (md_status & MD_GBL_IOCTL_LOCK) {
		mutex_exit(SETMUTEX(s->s_setno));
		return;
	}

	/*
	 * This thread is not holding the ioctl lock, so drop the set
	 * lock, send messages to slave nodes to reparse portions
	 * of the mddb and return.
	 *
	 * If the block parse flag is set, do not send parse messages.
	 * This flag is set when master is adding a new mddb that would
	 * cause parse messages to be sent to the slaves, but the slaves
	 * don't have knowledge of the new mddb yet since the mddb add
	 * operation hasn't been run on the slave nodes yet.  When the
	 * master unblocks the parse flag, the parse messages will be
	 * generated.
	 *
	 * If s_mn_parseflags_sending is non-zero, then another thread
	 * is already currently sending a parse message, so just release
	 * the mutex and return.  If an mddb change occurred that results
	 * in a parse message to be generated, the thread that is currently
	 * sending a parse message would generate the additional parse message.
	 *
	 * If s_mn_parseflags_sending is zero and parsing is not blocked,
	 * then loop until s_mn_parseflags is 0 (until there are no more
	 * messages to send).
	 * While s_mn_parseflags is non-zero,
	 * 	put snapshot of parse_flags in s_mn_parseflags_sending
	 * 	set s_mn_parseflags to zero
	 *	release mutex
	 *	send message
	 *	re-grab mutex
	 *	set s_mn_parseflags_sending to zero
	 */
	mddb_parse_msg = kmem_zalloc(sizeof (md_mn_msg_mddb_parse_t), KM_SLEEP);
	while (((s->s_mn_parseflags_sending & MDDB_PARSE_MASK) == 0) &&
	    (s->s_mn_parseflags & MDDB_PARSE_MASK) &&
	    (!(md_get_setstatus(s->s_setno) & MD_SET_MNPARSE_BLK))) {
		/* Grab snapshot of parse flags */
		s->s_mn_parseflags_sending = s->s_mn_parseflags;
		s->s_mn_parseflags = 0;

		mutex_exit(SETMUTEX(s->s_setno));

		/*
		 * Send the message to the slaves to re-parse
		 * the indicated portions of the mddb. Send the status
		 * of the 50 mddbs in this set so that slaves know which
		 * mddbs that the master node thinks are 'good'.
		 * Otherwise, slave may reparse, but from wrong replica.
		 */
		mddb_parse_msg->msg_parse_flags = s->s_mn_parseflags_sending;
		for (i = 0; i < MDDB_NLB; i++) {
			mddb_parse_msg->msg_lb_flags[i] =
			    lbp->lb_locators[i].l_flags;
		}
		kresult = kmem_zalloc(sizeof (md_mn_kresult_t), KM_SLEEP);
		while (rval != 0) {
			rval = mdmn_ksend_message(s->s_setno,
			    MD_MN_MSG_MDDB_PARSE, 0, 0,
			    (char *)mddb_parse_msg,
			    sizeof (md_mn_msg_mddb_parse_t), kresult);
			if (rval != 0)
				cmn_err(CE_WARN, "mddb_setexit: Unable to send "
				    "mddb update message to other nodes in "
				    "diskset %s\n", s->s_setname);
		}
		kmem_free(kresult, sizeof (md_mn_kresult_t));

		/*
		 * Re-grab mutex to clear sending field and to
		 * see if another parse message needs to be generated.
		 */
		mutex_enter(SETMUTEX(s->s_setno));
		s->s_mn_parseflags_sending = 0;
	}
	kmem_free(mddb_parse_msg, sizeof (md_mn_msg_mddb_parse_t));
	mutex_exit(SETMUTEX(s->s_setno));
}

static void
mddb_setexit_no_parse(
	mddb_set_t	*s
)
{
	mutex_exit(SETMUTEX(s->s_setno));
}

uint_t
mddb_lb_did_convert(mddb_set_t *s, uint_t doit, uint_t *blk_cnt)
{
	uint_t			li;
	mddb_lb_t		*lbp = s->s_lbp;
	mddb_locator_t		*lp;
	ddi_devid_t		ret_devid;
	uint_t			devid_len;
	dev_t			ddi_dev;
	mddb_did_ic_t		*did_icp;
	mddb_did_blk_t		*did_blkp;
	char			*minor_name;
	size_t			sz;
	int			retval;
	int			err;
	md_dev64_t		dev64; /* tmp var to make code look better */


	/* Need disk block(s) to hold mddb_did_blk_t */
	*blk_cnt = MDDB_DID_BLOCKS;

	if (doit) {
		/*
		 * Alloc mddb_did_blk_t disk block and fill in header area.
		 * Don't fill in did magic number until end of routine so
		 * if machine panics in the middle of conversion, the
		 * device id information will be thrown away at the
		 * next snarfing of this set.
		 * Need to set DEVID_STYLE so that mddb_devid_add will
		 * function properly.
		 */
		/* grab the mutex */
		if ((mddb_setenter(s->s_setno, MDDB_NOINIT, &err)) == NULL) {
			return (1);
		}
		single_thread_start(s);
		lbp->lb_didfirstblk = getfreeblks(s, MDDB_DID_BLOCKS);
		if (lbp->lb_didfirstblk == 0) {
			single_thread_end(s);
			mddb_setexit(s);
			return (1);
		}
		lbp->lb_didblkcnt = (mddb_block_t)MDDB_DID_BLOCKS;
		did_icp = (mddb_did_ic_t *)kmem_zalloc(sizeof (mddb_did_ic_t),
		    KM_SLEEP);
		did_blkp = (mddb_did_blk_t *)kmem_zalloc(MDDB_DID_BYTES,
		    KM_SLEEP);

		did_blkp->blk_revision = MDDB_REV_DI;
		did_icp->did_ic_blkp = did_blkp;
		s->s_did_icp = did_icp;
		lbp->lb_flags |= MDDB_DEVID_STYLE;
	}

	/* Fill in information in mddb_did_info_t array */
	for (li = 0; li < lbp->lb_loccnt; li++) {
		lp = &lbp->lb_locators[li];
		if (lp->l_flags & MDDB_F_DELETED)
			continue;

		dev64 = md_xlate_targ_2_mini(md_expldev(lp->l_dev));
		ddi_dev = md_dev64_to_dev(dev64);
		if (ddi_dev == NODEV) {
			/*
			 * No translation available for replica.
			 * Could fail conversion to device id replica,
			 * but instead will just continue with next
			 * replica in list.
			 */
			continue;
		}
		if (ddi_lyr_get_devid(ddi_dev, &ret_devid) == DDI_SUCCESS) {
			/*
			 * Just count each devid as at least 1 block.  This
			 * is conservative since several device id's may fit
			 * into 1 disk block, but it's better to overestimate
			 * the number of blocks needed than to underestimate.
			 */
			devid_len = (int)ddi_devid_sizeof(ret_devid);
			*blk_cnt += btodb(devid_len + (MDDB_BSIZE - 1));
			if (doit) {
				if (ddi_lyr_get_minor_name(ddi_dev, S_IFBLK,
				    &minor_name) == DDI_SUCCESS) {
					if (mddb_devid_add(s, li, ret_devid,
					    minor_name)) {
						cmn_err(CE_WARN,
						    "Not enough space in metadb"
						    " to add device id for"
						    "  dev: major = %d, "
						    "minor = %d\n",
						    getmajor(ddi_dev),
						    getminor(ddi_dev));
					}
					sz = strlen(minor_name) + 1;
					kmem_free(minor_name, sz);
				}
			}
			ddi_devid_free(ret_devid);
		}
	}

	if (doit) {
		did_blkp->blk_magic = MDDB_MAGIC_DI;
		retval = push_lb(s);
		(void) upd_med(s, "mddb_lb_did_convert(0)");
		single_thread_end(s);
		mddb_setexit(s);
		if (retval != 0)
			return (1);
	}

	return (0);
}

static mddb_set_t *
init_set(
	mddb_config_t	*cp,
	int		flag,
	int		*errp
)
{
	mddb_set_t	*s;
	char		*setname = NULL;
	set_t		setno = MD_LOCAL_SET;
	side_t		sideno = 0;
	struct timeval32 *created = NULL;

	if (cp != NULL) {
		setname = cp->c_setname;
		setno = cp->c_setno;
		sideno = cp->c_sideno;
		created = &cp->c_timestamp;
	}

	if (setno >= MD_MAXSETS)
		return ((mddb_set_t *)NULL);

	if (md_set[setno].s_db)
		return (mddb_setenter(setno, flag, errp));

	s = (mddb_set_t *)kmem_zalloc(sizeof (*s), KM_SLEEP);

	cv_init(&s->s_buf_cv, NULL, CV_DEFAULT, NULL);
	cv_init(&s->s_single_thread_cv, NULL, CV_DEFAULT, NULL);
	cv_init(&s->s_optqueuing_cv, NULL, CV_DEFAULT, NULL);
	cv_init(&s->s_opthungerr_cv, NULL, CV_DEFAULT, NULL);
	cv_init(&s->s_optwantlck_cv, NULL, CV_DEFAULT, NULL);

	s->s_setno = setno;
	s->s_sideno = sideno;
	if (setno == MD_LOCAL_SET) {
		(void) strcpy(s->s_ident.serial, hw_serial);
	} else {
		s->s_ident.createtime = *created;
		s->s_setname = (char *)kmem_alloc(strlen(setname) + 1,
		    KM_SLEEP);
		(void) strcpy(s->s_setname, setname);
	}

	/* have a config struct,  copy mediator information */
	if (cp != NULL)
		s->s_med = cp->c_med;		/* structure assignment */

	md_set[setno].s_db = (void *) s;

	SE_NOTIFY(EC_SVM_STATE, ESC_SVM_TAKEOVER, SVM_TAG_SET, setno, NODEV64);

	return (mddb_setenter(setno, flag, errp));
}

void
mddb_unload_set(
	set_t		setno
)
{

	mddb_set_t	*s;
	mddb_db_t	*dbp, *adbp = NULL;
	mddb_de_ic_t	*dep, *dep2;
	mddb_bf_t	*bfp;
	int		i;
	md_dev64_t	dev;

	if ((s = mddb_setenter(setno, MDDB_NOINIT, NULL)) == NULL)
		return;

	single_thread_start(s);

	s->s_opthavequeuinglck = 0;
	s->s_optwantqueuinglck = 0;

	for (dbp = s->s_dbp; dbp != 0; dbp = adbp) {
		for (dep = dbp->db_firstentry; dep != NULL; dep = dep2) {
			if (dep->de_rb_userdata != NULL) {
				if (dep->de_icreqsize)
					kmem_free(dep->de_rb_userdata_ic,
					    dep->de_icreqsize);
				else
					kmem_free(dep->de_rb_userdata,
					    dep->de_reqsize);
			}
			kmem_free((caddr_t)dep->de_rb, dep->de_recsize);
			dep2 = dep->de_next;
			kmem_free((caddr_t)dep, sizeofde(dep));
		}
		adbp = dbp->db_next;
		kmem_free((caddr_t)dbp, sizeof (mddb_db_t));
	}
	s->s_dbp = (mddb_db_t *)NULL;

	free_rip(&s->s_rip);

	for (i = 0; i < mddb_maxcopies;	 i++) {
		if (! s->s_mbiarray)
			break;

		if (! s->s_mbiarray[i])
			continue;

		dev = md_expldev(s->s_lbp->lb_locators[i].l_dev);
		dev = md_xlate_targ_2_mini(dev);
		if (dev != NODEV64)
			mddb_devclose(dev);

		free_mbipp(&s->s_mbiarray[i]);
	}

	if (s->s_mbiarray) {
		kmem_free((caddr_t)s->s_mbiarray,
		    sizeof (mddb_mb_ic_t *) * mddb_maxcopies);
		s->s_mbiarray = (mddb_mb_ic_t **)NULL;
	}

	if (s->s_lnp) {
		kmem_free((caddr_t)s->s_lnp, dbtob(s->s_lbp->lb_lnblkcnt));
		s->s_lnp = (mddb_ln_t *)NULL;
	}

	if (s->s_lbp) {
		mddb_devid_icp_free(&s->s_did_icp, s->s_lbp);
		kmem_free((caddr_t)s->s_lbp, dbtob(s->s_lbp->lb_blkcnt));
		s->s_lbp = (mddb_lb_t *)NULL;
	}

	if (s->s_freebitmap) {
		kmem_free((caddr_t)s->s_freebitmap, s->s_freebitmapsize);
		s->s_freebitmap = NULL;
		s->s_freebitmapsize = 0;
	}

	while ((bfp = allocbuffer(s, MDDB_NOSLEEP)) != NULL)
		kmem_free((caddr_t)bfp, sizeof (*bfp));

	if (s->s_databuffer_size) {
		kmem_free(s->s_databuffer, s->s_databuffer_size);
		s->s_databuffer_size = 0;
	}

	if (s->s_setname != NULL)
		kmem_free((caddr_t)s->s_setname, strlen(s->s_setname)+1);

	/* Data tags not supported on MN sets. */
	if (!(md_get_setstatus(setno) & MD_SET_MNSET))
		dtl_freel(&s->s_dtlp);

	md_set[setno].s_db = NULL;
	ASSERT(s->s_singlelockwanted == 0);
	kmem_free(s, sizeof (mddb_set_t));

	/* Take care of things setup in the md_set array */
	if (! (md_get_setstatus(setno) & MD_SET_KEEPTAG)) {
		if (md_set[setno].s_dtp) {
			kmem_free((caddr_t)md_set[setno].s_dtp, MDDB_DT_BYTES);
			md_set[setno].s_dtp = NULL;
		}
	}

	md_clr_setstatus(setno, MD_SET_ACCOK | MD_SET_ACCEPT |
	    MD_SET_TAGDATA | MD_SET_USETAG | MD_SET_TOOFEW | MD_SET_STALE |
	    MD_SET_OWNERSHIP | MD_SET_BADTAG | MD_SET_CLRTAG | MD_SET_MNSET |
	    MD_SET_DIDCLUP | MD_SET_MNPARSE_BLK | MD_SET_MN_MIR_STATE_RC |
	    MD_SET_IMPORT | MD_SET_REPLICATED_IMPORT);

	mutex_exit(SETMUTEX(setno));
}

/*
 * returns 0 if name can be put into locator block
 * returns 1 if locator block prefixes are all used
 *
 * Takes splitname (suffix, prefix, sideno) and
 * stores it in the locator name structure.
 * For traditional diskset, the sideno is the index into the suffixes
 * array in the locator name structure.
 * For the MN diskset, the sideno is the nodeid which can be any number,
 * so the index passed in is the index into the mnsuffixes array
 * in the locator structure.  This index was computed by the
 * routine checklocator which basically checked the locator block
 * mnside locator structure.
 */
static int
splitname2locatorblock(
	md_splitname	*spn,
	mddb_ln_t	*lnp,
	int		li,
	side_t		sideno,
	int		index
)
{
	uchar_t			i;
	md_name_suffix		*sn;
	md_mnname_suffix_t	*mnsn;
	mddb_mnln_t		*mnlnp;

	for (i = 0; i < MDDB_PREFIXCNT; i++) {
		if (lnp->ln_prefixes[i].pre_len != SPN_PREFIX(spn).pre_len)
			continue;
		if (bcmp(lnp->ln_prefixes[i].pre_data, SPN_PREFIX(spn).pre_data,
		    SPN_PREFIX(spn).pre_len) == 0)
			break;
	}
	if (i == MDDB_PREFIXCNT) {
		for (i = 0; i < MDDB_PREFIXCNT; i++) {
			if (lnp->ln_prefixes[i].pre_len == 0)
				break;
		}
		if (i == MDDB_PREFIXCNT)
			return (1);
		bcopy(SPN_PREFIX(spn).pre_data, lnp->ln_prefixes[i].pre_data,
		    SPN_PREFIX(spn).pre_len);
		lnp->ln_prefixes[i].pre_len = SPN_PREFIX(spn).pre_len;
	}

	if (lnp->ln_revision == MDDB_REV_MNLN) {
		/* If a MN diskset, use index */
		mnlnp = (mddb_mnln_t *)lnp;
		mnsn = &mnlnp->ln_mnsuffixes[index][li];
		mnsn->mn_ln_sideno = sideno;
		mnsn->mn_ln_suffix.suf_len = SPN_SUFFIX(spn).suf_len;
		mnsn->mn_ln_suffix.suf_prefix = i;
		bcopy(SPN_SUFFIX(spn).suf_data,
		    mnsn->mn_ln_suffix.suf_data, SPN_SUFFIX(spn).suf_len);
	} else {
		sn = &lnp->ln_suffixes[sideno][li];
		sn->suf_len = SPN_SUFFIX(spn).suf_len;
		sn->suf_prefix = i;
		bcopy(SPN_SUFFIX(spn).suf_data, sn->suf_data,
		    SPN_SUFFIX(spn).suf_len);
	}
	return (0);
}

/*
 * Find the locator name for the given sideno and convert the locator name
 * information into a splitname structure.
 */
void
mddb_locatorblock2splitname(
	mddb_ln_t	*lnp,
	int		li,
	side_t		sideno,
	md_splitname	*spn
)
{
	int			iprefix;
	md_name_suffix		*sn;
	md_mnname_suffix_t	*mnsn;
	int			i;
	mddb_mnln_t		*mnlnp;

	if (lnp->ln_revision == MDDB_REV_MNLN) {
		mnlnp = (mddb_mnln_t *)lnp;
		for (i = 0; i < MD_MNMAXSIDES; i++) {
			mnsn = &mnlnp->ln_mnsuffixes[i][li];
			if (mnsn->mn_ln_sideno == sideno)
				break;
		}
		if (i == MD_MNMAXSIDES)
			return;

		SPN_SUFFIX(spn).suf_len = mnsn->mn_ln_suffix.suf_len;
		bcopy(mnsn->mn_ln_suffix.suf_data, SPN_SUFFIX(spn).suf_data,
		    SPN_SUFFIX(spn).suf_len);
		iprefix = mnsn->mn_ln_suffix.suf_prefix;
	} else {
		sn = &lnp->ln_suffixes[sideno][li];
		SPN_SUFFIX(spn).suf_len = sn->suf_len;
		bcopy(sn->suf_data, SPN_SUFFIX(spn).suf_data,
		    SPN_SUFFIX(spn).suf_len);
		iprefix = sn->suf_prefix;
	}
	SPN_PREFIX(spn).pre_len = lnp->ln_prefixes[iprefix].pre_len;
	bcopy(lnp->ln_prefixes[iprefix].pre_data, SPN_PREFIX(spn).pre_data,
	    SPN_PREFIX(spn).pre_len);
}

static int
getdeldev(
	mddb_config_t	*cp,
	int		command,
	md_error_t	*ep
)
{
	mddb_set_t	*s;
	mddb_lb_t	*lbp;
	mddb_locator_t	*locators;
	uint_t		loccnt;
	mddb_mb_ic_t	*mbip;
	mddb_block_t	blk;
	int		err = 0;
	int		i, j;
	int		li;
	uint_t		commitcnt;
	set_t		setno = cp->c_setno;
	uint_t		set_status;
	md_dev64_t	dev;
	int		flags = MDDB_MUSTEXIST;

	cp->c_dbmax = MDDB_NLB;

	/*
	 * Data checking
	 */
	if (setno >= md_nsets || cp->c_id < 0 ||
	    cp->c_id > cp->c_dbmax) {
		return (mdmderror(ep, MDE_INVAL_UNIT, MD_ADM_MINOR));
	}

	if (cp->c_flags & MDDB_C_STALE)
		flags |= MDDB_MN_STALE;

	if ((s = mddb_setenter(setno, flags, &err)) == NULL)
		return (mddbstatus2error(ep, err, NODEV32, setno));

	cp->c_flags = 0;

	lbp = s->s_lbp;
	loccnt = lbp->lb_loccnt;
	locators = lbp->lb_locators;

	/* shorthand */
	set_status = md_get_setstatus(setno);

	if (set_status & MD_SET_STALE)
		cp->c_flags |= MDDB_C_STALE;

	if (set_status & MD_SET_TOOFEW)
		cp->c_flags |= MDDB_C_TOOFEW;

	cp->c_sideno = s->s_sideno;

	cp->c_dbcnt = 0;
	/*
	 * go through and count active entries
	 */
	for (i = 0; i < loccnt;	 i++) {
		if (locators[i].l_flags & MDDB_F_DELETED)
			continue;
		cp->c_dbcnt++;
	}

	/*
	 * add the ability to accept a locator block index
	 * which is not relative to previously deleted replicas.  This
	 * is for support of MD_DEBUG=STAT in metastat since it asks for
	 * replica information specifically for each of the mirror resync
	 * records.  MDDB_CONFIG_SUBCMD uses one of the pad spares in
	 * the mddb_config_t type.
	 */
	if (cp->c_subcmd == MDDB_CONFIG_ABS) {
		if (cp->c_id < 0 || cp->c_id > cp->c_dbmax) {
			mddb_setexit(s);
			return (mdmddberror(ep, MDE_DB_INVALID, NODEV32,
			    setno));
		}
		li = cp->c_id;
	} else {
		if (cp->c_id >= cp->c_dbcnt) {
			mddb_setexit(s);
			return (mdmddberror(ep, MDE_DB_INVALID, NODEV32,
			    setno));
		}

		/* CSTYLED */
		for (li = 0, j = 0; /* void */; li++) {
			if (locators[li].l_flags & MDDB_F_DELETED)
				continue;
			j++;
			if (j > cp->c_id)
				break;
		}
	}

	if (command == MDDB_ENDDEV) {
		daddr_t ib = 0, jb;

		blk = 0;
		if ((s != NULL) && s->s_mbiarray[li]) {
			mbip = s->s_mbiarray[li];
			while ((jb = getphysblk(blk++, mbip)) > 0) {
				if (jb > ib)
					ib = jb;
			}
			cp->c_dbend = (int)ib;
		} else {
			cp->c_dbend = 0;
		}
	}

	locator2cfgloc(lbp, &cp->c_locator, li, s->s_sideno, s->s_did_icp);
	mddb_locatorblock2splitname(s->s_lnp, li, s->s_sideno, &cp->c_devname);

	if (command != MDDB_DELDEV) {
		mddb_setexit(s);
		return (0);
	}

	/* Currently don't allow addition/deletion of sides during upgrade */
	if (MD_UPGRADE) {
		cmn_err(CE_WARN,
		    "Deletion of replica not allowed during upgrade.\n");
		mddb_setexit(s);
		return (mdmddberror(ep, MDE_DB_NOTNOW, NODEV32, setno));
	}

	/*
	 * If here, replica delete in progress.
	 */
	single_thread_start(s);

	if ((! (locators[li].l_flags & MDDB_F_EMASTER)) &&
	    (locators[li].l_flags & MDDB_F_ACTIVE)) {
		commitcnt = lbp->lb_commitcnt;
		lbp->lb_commitcnt = 0;
		setidentifier(s, &lbp->lb_ident);
		crcgen(lbp, &lbp->lb_checksum, dbtob(lbp->lb_blkcnt), NULL);
		/*
		 * Don't need to write out device id area, since locator
		 * block on this replica is being deleted by setting the
		 * commitcnt to 0.
		 */
		(void) writeblks(s, (caddr_t)lbp, 0, lbp->lb_blkcnt, li,
		    MDDB_WR_ONLY_MASTER);
		lbp->lb_commitcnt = commitcnt;
	}

	if (s->s_mbiarray[li])
		free_mbipp(&s->s_mbiarray[li]);

	if (! (locators[li].l_flags & MDDB_F_EMASTER)) {
		dev = md_expldev(locators[li].l_dev);
		dev = md_xlate_targ_2_mini(dev);
		if (dev != NODEV64)
			mddb_devclose(dev);
	}

	s->s_mbiarray[li] = 0;
	lbp->lb_locators[li].l_flags = MDDB_F_DELETED;

	/* Only support data tags for traditional and local sets */
	if ((md_get_setstatus(setno) & MD_SET_STALE) &&
	    (!(lbp->lb_flags & MDDB_MNSET)) &&
	    setno != MD_LOCAL_SET)
		if (set_dtag(s, ep))
			mdclrerror(ep);

	/* Write data tags to all accessible devices */
	/* Only support data tags for traditional and local sets */
	if (!(lbp->lb_flags & MDDB_MNSET)) {
		(void) dt_write(s);
	}

	/* Delete device id of deleted replica */
	if (lbp->lb_flags & MDDB_DEVID_STYLE) {
		(void) mddb_devid_delete(s, li);
	}
	/* write new locator to all devices */
	err = writelocall(s);

	(void) upd_med(s, "getdeldev(0)");

	SE_NOTIFY(EC_SVM_CONFIG, ESC_SVM_DELETE, SVM_TAG_REPLICA, setno,
	    md_expldev(locators[li].l_dev));

	computefreeblks(s); /* recompute always it may be larger */
	cp->c_dbcnt--;
	err |= fixoptrecords(s);
	if (err) {
		if (writeretry(s)) {
			single_thread_end(s);
			mddb_setexit(s);
			return (mdmddberror(ep, MDDB_E_NOTNOW, NODEV32, setno));
		}
	}

	single_thread_end(s);
	mddb_setexit(s);
	return (0);
}

static int
getdriver(
	mddb_cfg_loc_t	*clp
)
{
	major_t		majordev;

	/*
	 * Data checking
	 */
	if (clp->l_dev <= 0)
		return (EINVAL);

	majordev = getmajor(expldev(clp->l_dev));

	if (ddi_major_to_name(majordev) == (char *)NULL)
		return (EINVAL);

	if (MD_UPGRADE)
		(void) strcpy(clp->l_driver, md_targ_major_to_name(majordev));
	else
		(void) strcpy(clp->l_driver, ddi_major_to_name(majordev));
	return (0);
}

/*
 * update_valid_replica - updates the locator block namespace (prefix
 * 	and/or suffix) with new pathname and devname.
 *	RETURN
 *		1	Error
 *		0	Success
 */
static int
update_valid_replica(
	side_t		side,
	mddb_locator_t	*lp,
	mddb_set_t	*s,
	int		li,
	char		*devname,
	char		*pathname,
	md_dev64_t	devt
)
{
	uchar_t		pre_len, suf_len;
	md_name_suffix	*sn;
	mddb_ln_t	*lnp;
	uchar_t		pre_index;
	uchar_t		i;

	if (md_expldev(lp->l_dev) != devt) {
		return (0);
	}

	if (pathname[strlen(pathname) - 1] == '/')
		pathname[strlen(pathname) - 1] = '\0';

	pre_len = (uchar_t)strlen(pathname);
	suf_len = (uchar_t)strlen(devname);

	if ((pre_len > MD_MAXPREFIX) || (suf_len > MD_MAXSUFFIX))
		return (1);

	lnp = s->s_lnp;

	/*
	 * Future note:  Need to do something here for the MN diskset case
	 * when device ids are supported in disksets.
	 * Can't add until merging devids_in_diskset code into code base
	 * Currently only called with side of 0.
	 */

	sn = &lnp->ln_suffixes[side][li];

	/*
	 * Check if prefix (Ex: /dev/dsk) needs to be changed.
	 * If new prefix is the same as the previous prefix - no change.
	 *
	 * If new prefix is not the same, check if new prefix
	 * matches an existing one.  If so, use that one.
	 *
	 * If new prefix doesn't exist, add a new prefix.  If not enough
	 * space, return failure.
	 */
	pre_index = sn->suf_prefix;
	/* Check if new prefix is the same as the old prefix. */
	if ((lnp->ln_prefixes[pre_index].pre_len != pre_len) ||
	    (bcmp(lnp->ln_prefixes[pre_index].pre_data, pathname,
	    pre_len) != 0)) {
		/* Check if new prefix is an already known prefix. */
		for (i = 0; i < MDDB_PREFIXCNT; i++) {
			if (lnp->ln_prefixes[i].pre_len != pre_len) {
				continue;
			}
			if (bcmp(lnp->ln_prefixes[i].pre_data, pathname,
			    pre_len) == 0) {
				break;
			}
		}
		/* If no match found for new prefix - add the new prefix */
		if (i == MDDB_PREFIXCNT) {
			for (i = 0; i < MDDB_PREFIXCNT; i++) {
				if (lnp->ln_prefixes[i].pre_len == 0)
					break;
			}
			/* No space to add new prefix - return failure */
			if (i == MDDB_PREFIXCNT) {
				return (1);
			}
			bcopy(pathname, lnp->ln_prefixes[i].pre_data, pre_len);
			lnp->ln_prefixes[i].pre_len = pre_len;
		}
		sn->suf_prefix = i;
	}

	/* Now, update the suffix (Ex: c0t0d0s0) if needed */
	if ((sn->suf_len != suf_len) ||
	    (bcmp(sn->suf_data, devname, suf_len) != 0)) {
		bcopy(devname, sn->suf_data, suf_len);
		sn->suf_len = suf_len;
	}
	return (0);
}


/*
 * md_update_locator_namespace - If in devid style and active and the devid's
 *		exist and are valid update the locator namespace pathname
 *		and devname.
 *	RETURN
 *		1	Error
 *		0	Success
 */
int
md_update_locator_namespace(
	set_t		setno,		/* which set to get name from */
	side_t		side,
	char		*dname,
	char		*pname,
	md_dev64_t	devt
)
{
	mddb_set_t	*s;
	mddb_lb_t	*lbp;
	int		li;
	uint_t		flg;
	int		err = 0;
	mddb_ln_t	*lnp;

	if ((s = mddb_setenter(setno, MDDB_MUSTEXIST, &err)) == NULL)
		return (1);
	single_thread_start(s);
	lbp = s->s_lbp;
	/* must be DEVID_STYLE */
	if (lbp->lb_flags & MDDB_DEVID_STYLE) {
		for (li = 0; li < lbp->lb_loccnt; li++) {
			mddb_locator_t *lp = &lbp->lb_locators[li];

			if (lp->l_flags & MDDB_F_DELETED) {
				continue;
			}

			/* replica also must be active */
			if (lp->l_flags & MDDB_F_ACTIVE) {
				flg = s->s_did_icp->did_ic_blkp->
				    blk_info[li].info_flags;
				/* only update if did exists and is valid */
				if ((flg & MDDB_DID_EXISTS) &&
				    (flg & MDDB_DID_VALID)) {
					if (update_valid_replica(side, lp, s,
					    li, dname, pname, devt)) {
						err = 1;
						goto out;
					}
				}
			}
		}
	}
	lnp = s->s_lnp;
	uniqtime32(&lnp->ln_timestamp);
	if (lbp->lb_flags & MDDB_MNSET)
		lnp->ln_revision = MDDB_REV_MNLN;
	else
		lnp->ln_revision = MDDB_REV_LN;
	crcgen(lnp, &lnp->ln_checksum, dbtob(lbp->lb_lnblkcnt), NULL);
	err = writeall(s, (caddr_t)lnp, lbp->lb_lnfirstblk,
	    lbp->lb_lnblkcnt, 0);
	/*
	 * If a MN diskset and this is the master, set the PARSE_LOCNM
	 * flag in the mddb_set structure to show that the locator
	 * names have changed.
	 */

	if ((lbp->lb_flags & MDDB_MNSET) &&
	    (md_set[s->s_setno].s_am_i_master)) {
		s->s_mn_parseflags |= MDDB_PARSE_LOCNM;
	}
out:
	single_thread_end(s);
	mddb_setexit(s);
	if (err)
		return (1);
	return (0);
}

/*
 * update_locatorblock - for active entries in the locator block, check
 *		the devt to see if it matches the given devt. If so, and
 *		there is an associated device id which is not the same
 *		as the passed in devid, delete old devid and add a new one.
 *
 *		During import of replicated disksets, old_didptr contains
 *		the original disk's device id.  Use this device id in
 *		addition to the devt to determine if an entry is a match
 *		and should be updated with the new device id of the
 *		replicated disk.  Specifically, this is the case being handled:
 *
 *		Original_disk	Replicated_disk	Disk_Available_During_Import
 *		c1t1d0		c1t3d0		no - so old name c1t1d0 shown
 *		c1t2d0		c1t1d0		yes - name is c1t1d0
 *		c1t3d0		c1t2d0		yes - name is c1t2d0
 *
 *		Can't just match on devt since devt for the first and third
 *		disks will be the same, but the original disk's device id
 *		is known and can be used to distinguish which disk's
 *		replicated device id should be updated.
 *	RETURN
 *		MDDB_E_NODEVID
 *		MDDB_E_NOLOCBLK
 *		1	Error
 *		0	Success
 */
static int
update_locatorblock(
	mddb_set_t	*s,
	md_dev64_t	dev,
	ddi_devid_t	didptr,
	ddi_devid_t	old_didptr
)
{
	mddb_lb_t	*lbp = NULL;
	mddb_locator_t	*lp;
	int		li;
	uint_t		flg;
	ddi_devid_t	devid_ptr;
	int		retval = 0;
	char		*minor_name;
	int		repl_import_flag;

	/* Set replicated flag if this is a replicated import */
	repl_import_flag = md_get_setstatus(s->s_setno) &
	    MD_SET_REPLICATED_IMPORT;

	lbp = s->s_lbp;
	/* find replicas that haven't been deleted */
	for (li = 0; li < lbp->lb_loccnt; li++) {
		lp = &lbp->lb_locators[li];

		if ((lp->l_flags & MDDB_F_DELETED)) {
			continue;
		}
		/*
		 * check to see if locator devt matches given dev
		 * and if there is a device ID associated with it
		 */
		flg = s->s_did_icp->did_ic_blkp-> blk_info[li].info_flags;
		if ((md_expldev(lp->l_dev) == dev) &&
		    (flg & MDDB_DID_EXISTS)) {
			if (flg & MDDB_DID_VALID) {
				continue; /* cont to nxt active entry */
			}
			devid_ptr = s->s_did_icp->did_ic_devid[li];
			if (devid_ptr == NULL) {
				return (MDDB_E_NODEVID);
			}

			/*
			 * During a replicated import the old_didptr
			 * must match the current devid before the
			 * devid can be updated.
			 */
			if (repl_import_flag) {
				if (ddi_devid_compare(devid_ptr,
				    old_didptr) != 0)
					continue;
			}

			if (ddi_devid_compare(devid_ptr, didptr) != 0) {
				/*
				 * devid's not equal so
				 * delete and add
				 */
				if (ddi_lyr_get_minor_name(
				    md_dev64_to_dev(dev),
				    S_IFBLK, &minor_name) == DDI_SUCCESS) {
					(void) mddb_devid_delete(s, li);
					(void) mddb_devid_add(s, li, didptr,
					    minor_name);
					kmem_free(minor_name,
					    strlen(minor_name)+1);
					break;
				} else {
					retval = 1;
					goto err_out;
				}
			}
		}
	} /* end for */
	retval = push_lb(s);
	(void) upd_med(s, "update_locatorblock(0)");
err_out:
	return (retval);
}

static int
update_mb_devid(
	mddb_set_t	*s,
	mddb_ri_t	*rip,
	ddi_devid_t	devidptr
)
{
	mddb_mb_ic_t	*mbip;
	mddb_mb_t	*mb = NULL;
	daddr_t		blkno;
	md_dev64_t	device;
	uint_t		sz;
	int		mb2free = 0;
	int		err = 0;


	/*
	 * There is case where a disk may not have mddb,
	 * and only has dummy mddb which contains
	 * a valid devid we like to update and in this
	 * case, the rip_lbp will be NULL but we still
	 * like to update the devid embedded in the
	 * dummy mb block.
	 *
	 */
	if (rip->ri_mbip != (mddb_mb_ic_t *)NULL) {
		mbip = rip->ri_mbip;
		mb = &mbip->mbi_mddb_mb;
	} else {
		/*
		 * Done if it is non-replicated set
		 */
		if (devidptr != (ddi_devid_t)NULL) {
			mb = (mddb_mb_t *)kmem_zalloc(MDDB_BSIZE,
			    KM_SLEEP);
			mb->mb_magic = MDDB_MAGIC_DU;
			mb->mb_revision = MDDB_REV_MB;
			mb2free = 1;
		} else {
			goto out;
		}
	}

	blkno = rip->ri_blkno;
	device = rip->ri_dev;
	/*
	 * Replace the mb_devid with the new/valid one
	 */
	if (devidptr != (ddi_devid_t)NULL) {
		/*
		 * Zero out what we have previously
		 */
		if (mb->mb_devid_len)
			bzero(mb->mb_devid, mb->mb_devid_len);
		sz = ddi_devid_sizeof(devidptr);
		bcopy((char *)devidptr, (char *)mb->mb_devid, sz);
		mb->mb_devid_len = sz;
	}

	mb->mb_setno = s->s_setno;
	uniqtime32(&mb->mb_timestamp);
	crcgen(mb, &mb->mb_checksum, MDDB_BSIZE, NULL);
	/*
	 * putblks will
	 *
	 *	- drop the s_dbmx lock
	 *	- biowait
	 *	- regain the s_dbmx lock
	 *
	 * Need to update this if we wants to handle
	 * mb_next != NULL which it is unlikely will happen
	 */
	err = putblks(s, (caddr_t)mb, blkno, 1, device, 0);

	if (mb2free) {
		kmem_free(mb, MDDB_BSIZE);
	}
out:
	return (err);
}

static int
setdid(
	mddb_config_t		*cp
)
{
	ddi_devid_t		devidp;
	dev_t			ddi_dev;
	mddb_set_t		*s;
	int			err = 0;
	mddb_ri_t		*rip;

	/*
	 * Data integrity check
	 */
	if (cp->c_setno >= md_nsets || cp->c_devt <= 0)
		return (EINVAL);

	if ((md_get_setstatus(cp->c_setno) & MD_SET_STALE))
		return (0);

	ddi_dev = md_dev64_to_dev(cp->c_devt);
	if (ddi_lyr_get_devid(ddi_dev, &devidp) != DDI_SUCCESS) {
		return (-1);
	}
	if (devidp == NULL) {
		return (-1);
	}

	if ((s = mddb_setenter(cp->c_setno, MDDB_MUSTEXIST, &err)) == NULL)
		return (-1);
	single_thread_start(s);

	for (rip = s->s_rip; rip != NULL; rip = rip->ri_next) {
		if (rip->ri_lbp == (mddb_lb_t *)NULL)
			continue;
		/*
		 * We only update what is asked
		 */
		if (rip->ri_dev == cp->c_devt) {
			if (update_mb_devid(s, rip, devidp) != 0) {
				err = -1;
				goto out;
			}
		}
	}

	if (update_locatorblock(s, cp->c_devt, devidp, NULL)) {
		err = -1;
		goto out;
	}

out:
	single_thread_end(s);
	mddb_setexit(s);
	ddi_devid_free(devidp);
	return (err);
}

static int
delnewside(
	mddb_config_t		*cp,
	int			command,
	md_error_t		*ep
)
{
	mddb_set_t		*s;
	int			li;
	mddb_lb_t		*lbp;		/* pointer to locator block */
	mddb_ln_t		*lnp;		/* pointer to locator names */
	mddb_mnln_t		*mnlnp;		/* pointer to locator names */
	mddb_locator_t		*lp;
	mddb_sidelocator_t	*slp;
	mddb_cfg_loc_t		*clp;
	int			err = 0;
	set_t			setno = cp->c_setno;
	ddi_devid_t		devid;
	ddi_devid_t		ret_devid = NULL;
	char			*minor_name;
	uint_t			use_devid = 0;
	dev_t			ddi_dev;
	md_mnname_suffix_t	*mnsn;
	mddb_mnlb_t		*mnlbp;
	mddb_mnsidelocator_t	*mnslp;

	/* Currently don't allow addition/deletion of sides during upgrade */
	if (MD_UPGRADE) {
		cmn_err(CE_WARN,
		    "Addition and deletion of sides not allowed"
		    " during upgrade. \n");
		return (mdmddberror(ep, MDE_DB_NOTNOW, NODEV32, setno));
	}

	/*
	 * Data integrity check
	 */
	if (setno >= md_nsets || cp->c_locator.l_dev <= 0)
		return (mdmderror(ep, MDE_INVAL_UNIT, MD_ADM_MINOR));

	if ((s = mddb_setenter(setno, MDDB_MUSTEXIST, &err)) == NULL)
		return (mddbstatus2error(ep, err, NODEV32, setno));

	single_thread_start(s);
	clp = &cp->c_locator;

	lbp = s->s_lbp;

	if (lbp->lb_setno != setno) {
		single_thread_end(s);
		mddb_setexit(s);
		return (mdmddberror(ep, MDE_DB_INVALID, NODEV32, setno));
	}

	/*
	 * Find this device/blkno pair
	 */
	if (lbp->lb_flags & MDDB_DEVID_STYLE) {
		ddi_dev = md_dev64_to_dev(clp->l_dev);
		if ((ddi_lyr_get_devid(ddi_dev, &ret_devid) == DDI_SUCCESS) &&
		    (ddi_lyr_get_minor_name(ddi_dev, S_IFBLK, &minor_name)
		    == DDI_SUCCESS)) {
			if (strlen(minor_name) < MDDB_MINOR_NAME_MAX) {
				clp->l_devid = (uint64_t)(uintptr_t)ret_devid;
				use_devid = 1;
				(void) strcpy(clp->l_minor_name, minor_name);
			}
			kmem_free(minor_name, strlen(minor_name)+1);
		}
		if (use_devid != 1 && ret_devid != NULL)
			ddi_devid_free(ret_devid);
	}
	for (li = 0; li < lbp->lb_loccnt; li++) {
		lp = &lbp->lb_locators[li];
		if (lp->l_flags & MDDB_F_DELETED)
			continue;
		if (use_devid) {
			if ((mddb_devid_get(s, li, &devid, &minor_name)) == 0)
				continue;
			if ((ddi_devid_compare(devid,
			    (ddi_devid_t)(uintptr_t)clp->l_devid) == 0) &&
			    (strcmp(clp->l_minor_name, minor_name) == 0) &&
			    ((daddr_t)lp->l_blkno == clp->l_blkno)) {
				break;
			}
		} else {
			if (lp->l_dev == clp->l_dev &&
			    (daddr_t)lp->l_blkno == clp->l_blkno) {
				break;
			}
		}
	}

	if (li == lbp->lb_loccnt) {
		if (use_devid)
			ddi_devid_free((ddi_devid_t)(uintptr_t)clp->l_devid);
		single_thread_end(s);
		mddb_setexit(s);
		return (mdmddberror(ep, MDE_DB_INVALID, NODEV32, setno));
	}

	lnp = s->s_lnp;
	if (command == MDDB_NEWSIDE) {
		int 	index = 0;
		/*
		 * If a MN diskset, need to find the index where the new
		 * locator information is to be stored in the mnsidelocator
		 * field of the locator block so that the locator name can
		 * be stored at the same array index in the mnsuffixes
		 * field of the locator names structure.
		 */
		if (lbp->lb_flags & MDDB_MNSET) {
			if ((index = checklocator(lbp, li,
			    cp->c_sideno)) == -1) {
				if (use_devid) {
					ddi_devid_free((ddi_devid_t)
					    (uintptr_t)clp->l_devid);
				}
				single_thread_end(s);
				mddb_setexit(s);
				return (mdmddberror(ep, MDE_DB_TOOSMALL,
				    NODEV32, setno));
			}
		}

		/*
		 * Store the locator name before the sidelocator information
		 * in case a panic occurs between these 2 steps.  Must have
		 * the locator name information in order to print reasonable
		 * error information.
		 */
		if (splitname2locatorblock(&cp->c_devname, lnp, li,
		    cp->c_sideno, index)) {
			if (use_devid)
				ddi_devid_free(
				    (ddi_devid_t)(uintptr_t)clp->l_devid);
			single_thread_end(s);
			mddb_setexit(s);
			return (mdmddberror(ep, MDE_DB_TOOSMALL, NODEV32,
			    setno));
		}

		if (cfgloc2locator(lbp, clp, li, cp->c_sideno, index)) {
			if (use_devid)
				ddi_devid_free(
				    (ddi_devid_t)(uintptr_t)clp->l_devid);
			single_thread_end(s);
			mddb_setexit(s);
			return (mdmddberror(ep, MDE_DB_TOOSMALL, NODEV32,
			    setno));
		}
	}

	if (use_devid)
		ddi_devid_free((ddi_devid_t)(uintptr_t)clp->l_devid);

	if (command == MDDB_DELSIDE) {
		int i;
		for (i = 0; i < lbp->lb_loccnt; i++) {
			if (lbp->lb_flags & MDDB_MNSET) {
				int	j;
				mnlbp = (mddb_mnlb_t *)lbp;
				for (j = 0; j < MD_MNMAXSIDES; j++) {
					mnslp = &mnlbp->lb_mnsidelocators[j][i];
					if (mnslp->mnl_sideno == cp->c_sideno)
						break;
				}
				if (j < MD_MNMAXSIDES) {
					mnslp->mnl_mnum = NODEV32;
					mnslp->mnl_sideno = 0;
					mnlnp = (mddb_mnln_t *)lnp;
					mnsn = &(mnlnp->ln_mnsuffixes[j][i]);
					bzero((caddr_t)mnsn,
					    sizeof (md_mnname_suffix_t));
				}
			} else {
				slp = &lbp->lb_sidelocators[cp->c_sideno][i];
				bzero((caddr_t)&lnp->ln_suffixes
				    [cp->c_sideno][i], sizeof (md_name_suffix));
				slp->l_mnum = NODEV32;
			}
		}
	}

	/* write new locator names to all devices */
	uniqtime32(&lnp->ln_timestamp);
	if (lbp->lb_flags & MDDB_MNSET)
		lnp->ln_revision = MDDB_REV_MNLN;
	else
		lnp->ln_revision = MDDB_REV_LN;
	crcgen(lnp, &lnp->ln_checksum, dbtob(lbp->lb_lnblkcnt), NULL);
	err |= writeall(s, (caddr_t)lnp, lbp->lb_lnfirstblk,
	    lbp->lb_lnblkcnt, 0);
	/*
	 * If a MN diskset and this is the master, set the PARSE_LOCNM
	 * flag in the mddb_set structure to show that the locator
	 * names have changed.
	 */

	if ((lbp->lb_flags & MDDB_MNSET) &&
	    (md_set[s->s_setno].s_am_i_master)) {
		s->s_mn_parseflags |= MDDB_PARSE_LOCNM;
	}
	if (err) {
		if (writeretry(s)) {
			single_thread_end(s);
			mddb_setexit(s);
			return (mdmddberror(ep, MDE_DB_NOTNOW, NODEV32, setno));
		}
	}

	uniqtime32(&lbp->lb_timestamp);
	/* write new locator to all devices */
	err = writelocall(s);

	(void) upd_med(s, "delnewside(0)");

	computefreeblks(s); /* recompute always it may be larger */
	if (err) {
		if (writeretry(s)) {
			single_thread_end(s);
			mddb_setexit(s);
			return (mdmddberror(ep, MDE_DB_NOTNOW, NODEV32, setno));
		}
	}

	single_thread_end(s);
	mddb_setexit(s);

	return (0);
}

static int
newdev(
	mddb_config_t	*cp,
	int		command,
	md_error_t	*ep
)
{
	mddb_set_t	*s;
	mddb_mb_ic_t	*mbip, *mbip1;
	int		i, j;
	int		li;
	mddb_lb_t	*lbp;		/* pointer to locator block */
	mddb_ln_t	*lnp;		/* pointer to locator names */
	mddb_locator_t	*lp;
	mddb_cfg_loc_t	*clp;
	int		err = 0;
	set_t		setno = cp->c_setno;
	ddi_devid_t	devid2;
	ddi_devid_t	ret_devid = NULL;
	char		*minor_name;
	uint_t		use_devid = 0;
	dev_t		ddi_dev;
	int		old_flags;
	int		flags;
	int		mn_set = 0;
	int		index;


	/* Currently don't allow addition of new replica during upgrade */
	if (MD_UPGRADE) {
		cmn_err(CE_WARN,
		    "Addition of new replica not allowed during upgrade.\n");
		return (mdmddberror(ep, MDE_DB_NOTNOW, NODEV32, setno));
	}

	/*
	 * Data integrity check
	 */
	if (setno >= md_nsets || cp->c_locator.l_dev <= 0)
		return (mdmderror(ep, MDE_INVAL_UNIT, MD_ADM_MINOR));

	/* Determine the flag settings for multinode sets */
	flags = MDDB_NOOLDOK;
	if (cp->c_multi_node)
		flags |= MDDB_MULTINODE;

	if ((s = mddb_setenter(setno, flags, &err)) == NULL) {
		if (err != MDDB_E_NOTOWNER)
			return (mddbstatus2error(ep, err, NODEV32, setno));
		s = init_set(cp, flags, &err);
		if (s == NULL)
			return (mddbstatus2error(ep, err, NODEV32, setno));
	}

	single_thread_start(s);

	/* shorthand */
	clp = &cp->c_locator;

	/* shorthand */
	lbp = s->s_lbp;

	if (lbp->lb_setno != setno) {
		single_thread_end(s);
		mddb_setexit(s);
		return (mdmddberror(ep, MDE_DB_INVALID, NODEV32, setno));
	}

	/*
	 * See if this device/blkno pair is already a replica
	 */
	if (lbp->lb_flags & MDDB_DEVID_STYLE) {
		ddi_dev = expldev(clp->l_dev);
		if ((ddi_lyr_get_devid(ddi_dev, &ret_devid) == DDI_SUCCESS) &&
		    (ddi_lyr_get_minor_name(ddi_dev,
		    S_IFBLK, &minor_name) == DDI_SUCCESS)) {
			if (strlen(minor_name) < MDDB_MINOR_NAME_MAX) {
				clp->l_devid = (uint64_t)(uintptr_t)ret_devid;
				use_devid = 1;
				(void) strcpy(clp->l_minor_name, minor_name);
			}
			kmem_free(minor_name, strlen(minor_name)+1);
		}
		if (use_devid != 1 && ret_devid != NULL)
			ddi_devid_free(ret_devid);
	}

	for (i = 0; i < lbp->lb_loccnt;	 i++) {
		lp = &lbp->lb_locators[i];
		if (lp->l_flags & MDDB_F_DELETED)
			continue;
		if (use_devid) {
			if ((mddb_devid_get(s, i, &devid2, &minor_name)) == 0)
				continue;
			if ((ddi_devid_compare(devid2,
			    (ddi_devid_t)(uintptr_t)clp->l_devid) == 0) &&
			    (strcmp(clp->l_minor_name, minor_name) == 0) &&
			    ((daddr_t)lp->l_blkno == clp->l_blkno)) {
				if (command == MDDB_NEWDEV) {
					ddi_devid_free((ddi_devid_t)(uintptr_t)
					    clp->l_devid);
					single_thread_end(s);
					mddb_setexit(s);
					return (mdmddberror(ep,
					    MDE_DB_EXISTS, NODEV32, setno));
				}
			}
		} else {
			if (lp->l_dev == clp->l_dev &&
			    (daddr_t)lp->l_blkno == clp->l_blkno) {
				if (command == MDDB_NEWDEV) {
					single_thread_end(s);
					mddb_setexit(s);
					return (mdmddberror(ep,
					    MDE_DB_EXISTS, NODEV32, setno));
				}
			}
		}
	}

	/*
	 * Really is a new replica, go get the master blocks
	 */
	mbip = getmasters(s, md_expldev(clp->l_dev), clp->l_blkno,
	    (uint_t *)0, &mn_set);
	if (! mbip) {
		if (use_devid)
			ddi_devid_free((ddi_devid_t)(uintptr_t)clp->l_devid);
		single_thread_end(s);
		mddb_setexit(s);
		return (mdmddberror(ep, MDE_DB_MASTER, NODEV32, setno));
	}

	/*
	 * Compute free blocks in replica.
	 */
	computefreeblks(s);

	/*
	 * Check if this is large enough
	 */
	for (mbip1 = mbip, i = 0; mbip1 != NULL; mbip1 = mbip1->mbi_next)
		i += mbip1->mbi_mddb_mb.mb_blkcnt;
	for (j = i; j < s->s_totalblkcnt; j++) {
		if (blkcheck(s, j)) {
			while (mbip) {
				mbip1 = mbip->mbi_next;
				kmem_free((caddr_t)mbip, MDDB_IC_BSIZE);
				mbip = mbip1;
			}
			if (use_devid)
				ddi_devid_free(
				    (ddi_devid_t)(uintptr_t)clp->l_devid);
			mddb_devclose(md_expldev(clp->l_dev));
			single_thread_end(s);
			mddb_setexit(s);
			return (mdmddberror(ep, MDE_DB_TOOSMALL, NODEV32,
			    setno));
		}
	}

	/* Look for a deleted slot */
	for (li = 0; li < lbp->lb_loccnt; li++) {
		lp = &lbp->lb_locators[li];
		if (lp->l_flags & MDDB_F_DELETED)
			break;
	}

	/* If no deleted slots, add a new one */
	if (li == lbp->lb_loccnt) {
		/* Already have the max replicas, bail */
		if (lbp->lb_loccnt == MDDB_NLB) {
			if (use_devid)
				ddi_devid_free((ddi_devid_t)(uintptr_t)
				    clp->l_devid);
			mddb_devclose(md_expldev(clp->l_dev));
			single_thread_end(s);
			mddb_setexit(s);
			return (mdmddberror(ep, MDE_TOOMANY_REPLICAS, NODEV32,
			    setno));
		}
		lbp->lb_loccnt++;
		lp = &lbp->lb_locators[li];
	}

	/* Initialize the new or deleted slot */
	old_flags = lp->l_flags;
	lp->l_dev = clp->l_dev;
	lp->l_blkno = (daddr32_t)clp->l_blkno;
	lp->l_flags = clp->l_flags;

	/* shorthand */
	lnp = s->s_lnp;

	index = 0;
	if ((lbp->lb_flags & MDDB_MNSET) || (flags & MDDB_MULTINODE)) {
		/*
		 * If a MN diskset, need to find the index where the new
		 * locator information is to be stored in the mnsidelocator
		 * field of the locator block so that the locator name can
		 * be stored at the same array index in the mnsuffixes
		 * field of the locator names structure.
		 */
		lbp->lb_flags |= MDDB_MNSET;
		if ((index = checklocator(lbp, li, s->s_sideno)) == -1) {
			if (use_devid)
				ddi_devid_free((ddi_devid_t)(uintptr_t)clp->
				    l_devid);
			lp->l_flags = old_flags;
			lbp->lb_loccnt--;
			mddb_devclose(md_expldev(clp->l_dev));
			single_thread_end(s);
			mddb_setexit(s);
			return (mdmddberror(ep, MDE_DB_TOOSMALL,
			    NODEV32, setno));
		}
	}
	/*
	 * Store the locator name before the sidelocator information
	 * in case a panic occurs between these 2 steps.  Must have
	 * the locator name information in order to print reasonable
	 * error information.
	 */
	if (splitname2locatorblock(&cp->c_devname, lnp, li,
	    s->s_sideno, index)) {
		if (use_devid)
			ddi_devid_free((ddi_devid_t)(uintptr_t)clp->l_devid);
		lp->l_flags = old_flags;
		lbp->lb_loccnt--;
		mddb_devclose(md_expldev(clp->l_dev));
		single_thread_end(s);
		mddb_setexit(s);
		return (mdmddberror(ep, MDE_DB_TOOSMALL, NODEV32, setno));
	}

	/*
	 * Compute free blocks in replica before calling cfgloc2locator
	 * since cfgloc2locator may attempt to alloc an unused block
	 * to store the device id.
	 * mbiarray needs to be setup before calling computefreeblks.
	 */
	s->s_mbiarray[li] = mbip;
	computefreeblks(s);

	if (cfgloc2locator(lbp, clp, li, s->s_sideno, index)) {
		if (use_devid)
			ddi_devid_free((ddi_devid_t)(uintptr_t)clp->l_devid);
		lp->l_flags = old_flags;
		lbp->lb_loccnt--;
		s->s_mbiarray[li] = 0;
		mddb_devclose(md_expldev(clp->l_dev));
		single_thread_end(s);
		mddb_setexit(s);
		return (mdmddberror(ep, MDE_DB_TOOSMALL, NODEV32, setno));
	}

	if (use_devid)
		ddi_devid_free((ddi_devid_t)(uintptr_t)clp->l_devid);

	uniqtime32(&lbp->lb_timestamp);
	lp->l_flags = MDDB_F_ACTIVE;

	/* write db copy to new device */
	err = writecopy(s, li, MDDB_WRITECOPY_ALL);
	lp->l_flags |= MDDB_F_UP2DATE;

	/* write new locator names to all devices */
	uniqtime32(&lnp->ln_timestamp);
	if (lbp->lb_flags & MDDB_MNSET)
		lnp->ln_revision = MDDB_REV_MNLN;
	else
		lnp->ln_revision = MDDB_REV_LN;
	crcgen(lnp, &lnp->ln_checksum, dbtob(lbp->lb_lnblkcnt), NULL);
	err |= writeall(s, (caddr_t)lnp, lbp->lb_lnfirstblk,
	    lbp->lb_lnblkcnt, 0);
	/*
	 * If a MN diskset and this is the master, set the PARSE_LOCNM
	 * flag in the mddb_set structure to show that the locator
	 * names have changed.
	 */

	if ((lbp->lb_flags & MDDB_MNSET) &&
	    (md_set[s->s_setno].s_am_i_master)) {
		s->s_mn_parseflags |= MDDB_PARSE_LOCNM;
	}
	if (err) {
		if (writeretry(s)) {
			single_thread_end(s);
			mddb_setexit(s);
			return (mdmddberror(ep, MDE_DB_NOTNOW, NODEV32, setno));
		}
	}

	/* Data tags not supported on MN sets */
	if ((md_get_setstatus(setno) & MD_SET_STALE) &&
	    (!(lbp->lb_flags & MDDB_MNSET)) &&
	    setno != MD_LOCAL_SET)
		if (set_dtag(s, ep))
			mdclrerror(ep);

	/* Write data tags to all accessible devices */
	/* Data tags not supported on MN sets */
	if (!(lbp->lb_flags & MDDB_MNSET)) {
		(void) dt_write(s);
	}

	/* write new locator to all devices */
	err = writelocall(s);

	(void) upd_med(s, "newdev(0)");

	SE_NOTIFY(EC_SVM_CONFIG, ESC_SVM_CREATE, SVM_TAG_REPLICA, setno,
	    md_expldev(clp->l_dev));

	computefreeblks(s); /* recompute always it may be smaller */
	if (err) {
		if (writeretry(s)) {
			single_thread_end(s);
			mddb_setexit(s);
			return (mdmddberror(ep, MDE_DB_NOTNOW, NODEV32, setno));
		}
	}

	single_thread_end(s);
	mddb_setexit(s);

	return (0);
}

#ifdef DEBUG
static void
mddb_check_set(
	set_t	setno
)
{
	mddb_set_t	*s;
	mddb_db_t	*dbp;
	mddb_de_ic_t	*dep;
	mddb_rb32_t	*rbp;

	if (! md_set[setno].s_db)
		return;

	s = (mddb_set_t *)md_set[setno].s_db;

	for (dbp = s->s_dbp; dbp != NULL; dbp = dbp->db_next) {
		for (dep = dbp->db_firstentry;
		    dep != NULL; dep = dep->de_next) {
			rbp = dep->de_rb;
			ASSERT(rbp->rb_magic == MDDB_MAGIC_RB);
			if (dep->de_rb_userdata)
				ASSERT((uintptr_t)dep->de_rb_userdata > 2000);
		}
	}
}
#endif /* DEBUG */

/*
 * Exported Entry Points
 */
#ifdef DEBUG
void
mddb_check(void)
{
	int	i;

	for (i = 0; i < md_nsets; i++) {
		if (! md_set[i].s_db)
			return;

		mddb_check_set(i);
	}

}
#endif /* DEBUG */

int
mddb_configure(
	mddb_cfgcmd_t	command,
	mddb_config_t	*cp
)
{
	mddb_set_t	*s;
	md_error_t	*ep = &cp->c_mde;
	int		flag = 0;
	int		err = 0;
	set_t		setno = cp->c_setno;

	mdclrerror(ep);

	switch (command) {
		case MDDB_NEWDEV:
			err = newdev(cp, command, ep);
			break;

		case MDDB_NEWSIDE:
		case MDDB_DELSIDE:
			err = delnewside(cp, command, ep);
			break;

		case MDDB_GETDEV:
		case MDDB_DELDEV:
		case MDDB_ENDDEV:
			err = getdeldev(cp, command, ep);
			break;

		case MDDB_GETDRVRNAME:
			err = getdriver(&cp->c_locator);
			break;

		case MDDB_USEDEV:
			/*
			 * Note: must allow USEDEV ioctl during upgrade to
			 * support auto-take disksets.
			 *
			 * Also during the set import if the md_devid_destroy
			 * flag is set then error out
			 */

			if ((cp->c_flags & MDDB_C_IMPORT) && md_devid_destroy)
				return (mdmderror(ep, MDE_INVAL_UNIT,
				    MD_ADM_MINOR));

			if (setno >= md_nsets)
				return (mdmderror(ep, MDE_INVAL_UNIT,
				    MD_ADM_MINOR));

			if ((s = mddb_setenter(setno, MDDB_NOINIT, &err)) ==
			    NULL) {
				if ((s = init_set(cp, MDDB_NOINIT, &err)) ==
				    NULL) {
					err = mddbstatus2error(ep, err,
					    NODEV32, setno);
					break;
				}
			}
			if (setno == MD_LOCAL_SET)
				flag = MDDB_F_IOCTL;
			if (cp->c_locator.l_old_devid) {
				md_set_setstatus(setno,
				    MD_SET_REPLICATED_IMPORT);
			}
			err = ridev(&s->s_rip, &cp->c_locator, NULL, flag);
			mddb_setexit(s);
			break;

		case MDDB_RELEASESET:
			mutex_enter(&mddb_lock);
			mddb_unload_set(cp->c_setno);
			mutex_exit(&mddb_lock);
			break;

		case MDDB_SETDID:
			err = setdid(cp);
			break;

		default:
			err = mdmddberror(ep, MDE_DB_INVALID, NODEV32,
			    cp->c_setno);
	}

	return (err);
}

int
mddb_getoptloc(
	mddb_optloc_t		*ol
)
{
	mddb_set_t		*s;
	mddb_db_t		*dbp;
	mddb_de_ic_t		*dep;
	mddb_recid_t		id;
	set_t			setno;

	ol->li[0] = -1;
	ol->li[1] = -1;

	id = ol->recid;
	setno = DBSET(id);
	if (setno >= md_nsets)
		return (EINVAL);

	if ((s = mddb_setenter(setno, MDDB_MUSTEXIST, NULL)) == NULL)
		return (0);

	id = DBID(id);
	for (dbp = s->s_dbp; dbp != NULL; dbp = dbp->db_next) {
		for (dep = dbp->db_firstentry;
		    dep != NULL; dep = dep->de_next) {
			if (dep->de_recid != id)
				continue;
			ol->li[0] = dep->de_optinfo[0].o_li;
			ol->li[1] = dep->de_optinfo[1].o_li;
			mddb_setexit(s);
			return (0);
		}
	}
	mddb_setexit(s);
	return (0);
}

void
mddb_init(void)
{
	mddb_set_t	*s;

	mutex_init(&mddb_lock, NULL, MUTEX_DEFAULT, NULL);
	if ((s = init_set(NULL, MDDB_NOINIT, NULL)) != NULL)
		mddb_setexit(s);
}


void
mddb_unload(void)
{
	int	i;

	mutex_enter(&mddb_lock);

	for (i = 0; i < md_nsets; i++) {
		md_clr_setstatus(i, MD_SET_KEEPTAG);
		mddb_unload_set(i);
	}

	crcfreetab();

	mutex_exit(&mddb_lock);
}

mddb_recid_t
mddb_createrec(
	size_t		usersize,	 /* size of db record */
	mddb_type_t	type,		 /* type1 of db record */
	uint_t		type2,		 /* type2 of db record */
	md_create_rec_option_t	options, /* options for this creation  */
	set_t		setno		 /* set number to create record in */
)
{
	mddb_set_t	*s;
	mddb_db_t	*dbp, *prevdbp, *newdbp;
	mddb_db32_t	*db32p;
	mddb_de_ic_t	*dep;
	/* LINTED variable unused - used for sizeof calculations */
	mddb_de32_t	*de32p;
	mddb_rb32_t	*rbp;
	size_t		recsize;
	ulong_t		blkcnt;
	ulong_t		maxblocks;
	size_t		desize, desize_ic;
	size_t		used;
	mddb_recid_t	newid;
	caddr_t		tmppnt;
	int		i, err = 0;
	void		*userdata;
	uint_t		flag_type;

#if defined(_ILP32) && !defined(lint)
	ASSERT(sizeof (mddb_de_t) == sizeof (mddb_de32_t));
	ASSERT(sizeof (mddb_db_t) == sizeof (mddb_db32_t));
	ASSERT(sizeof (mddb_rb_t) == sizeof (mddb_rb32_t));
#endif

	/*
	 * everyone is supposed to sepcify if it's a
	 * 32 bit or a 64 bit record
	 */
	if ((options &(MD_CRO_32BIT|MD_CRO_64BIT)) == 0) {
		return (MDDB_E_INVALID);
	}

	if ((s = mddb_setenter(setno, MDDB_MUSTEXIST, &err)) == NULL)
		return (err);

	if (checkstate(s, MDDB_PROBE)) {
		mddb_setexit(s);
		return (MDDB_E_NOTNOW);
	}

	recsize = roundup((sizeof (*rbp) - sizeof (rbp->rb_data)) +
	    usersize, MDDB_BSIZE);
	blkcnt = btodb(recsize);

	if (mddb_maxblocks)
		maxblocks = mddb_maxblocks;
	else
		maxblocks = (MDDB_BSIZE - (sizeof (*db32p) + sizeof (*de32p) -
		    sizeof (de32p->de32_blks))) / sizeof (mddb_block_t);

	if (blkcnt > maxblocks) {
		mddb_setexit(s);
		return (MDDB_E_INVALID);
	}
	/*
	 * allocate record block
	 * and new directory block so to avoid sleeping
	 * after starting single_thread
	 */
	rbp = (mddb_rb32_t *)kmem_zalloc(recsize, KM_SLEEP);
	if ((options & MD_CRO_OPTIMIZE) == 0)
		userdata = kmem_zalloc(usersize, KM_SLEEP);
	newdbp = (mddb_db_t *)kmem_zalloc(sizeof (*newdbp), KM_SLEEP);

	/*
	 * if this is the largest record allocate new buffer for
	 * checkcopy();
	 */
	if (recsize > s->s_databuffer_size) {
		tmppnt = (caddr_t)kmem_zalloc(recsize, KM_SLEEP);
		/*
		 * this test is incase when to sleep during kmem_alloc
		 * and some other task bumped max record size
		 */
		if (recsize > s->s_databuffer_size) {
			if (s->s_databuffer_size)
				kmem_free(s->s_databuffer,
				    s->s_databuffer_size);
			s->s_databuffer = tmppnt;
			s->s_databuffer_size = recsize;
		} else {
			kmem_free(tmppnt, recsize);
		}
	}

	single_thread_start(s);

	newid = 0;
	do {
		newid++;
		if (DBID(newid) == 0) {
			kmem_free((caddr_t)newdbp, sizeof (*newdbp));
			kmem_free((caddr_t)rbp, ((size_t)recsize));
			if ((options & MD_CRO_OPTIMIZE) == 0)
				kmem_free(userdata, usersize);
			single_thread_end(s);
			mddb_setexit(s);
			return (MDDB_E_NOTNOW);
		}

		for (dbp = s->s_dbp; dbp != NULL; dbp = dbp->db_next) {
			for (dep = dbp->db_firstentry; dep;
			    dep = dep->de_next) {
				if (dep->de_recid == newid)
					break;
			}
			if (dep != NULL)
				break;
		}
	} while (dbp);

	desize = (sizeof (*de32p) - sizeof (de32p->de32_blks)) +
	    (sizeof (mddb_block_t) * blkcnt);

	/*
	 * see if a directory block exists which will hold this entry
	 */
	for (dbp = s->s_dbp; dbp != NULL; dbp = dbp->db_next) {
		used = sizeof (*db32p);
		for (dep = dbp->db_firstentry;
		    dep != NULL; dep = dep->de_next) {
			used += sizeof (*de32p) - sizeof (de32p->de32_blks);
			used += sizeof (mddb_block_t) * dep->de_blkcount;
		}
		if ((used + desize) < MDDB_BSIZE)
			break;
	}
	if (dbp) {
		kmem_free((caddr_t)newdbp, sizeof (*newdbp));
		if (blkcnt > s->s_freeblkcnt) {
			kmem_free((caddr_t)rbp, ((size_t)recsize));
			if ((options & MD_CRO_OPTIMIZE) == 0)
				kmem_free(userdata, usersize);
			single_thread_end(s);
			mddb_setexit(s);
			return (MDDB_E_NOSPACE);
		}
		prevdbp = NULL;
	} else {
		/*
		 * need to add directory block
		 */
		if ((blkcnt + 1) > s->s_freeblkcnt) {
			kmem_free((caddr_t)newdbp, sizeof (*newdbp));
			kmem_free((caddr_t)rbp, ((size_t)recsize));
			if ((options & MD_CRO_OPTIMIZE) == 0)
				kmem_free(userdata, usersize);
			single_thread_end(s);
			mddb_setexit(s);
			return (MDDB_E_NOSPACE);
		}
		for (dbp = s->s_dbp; dbp->db_next; dbp = dbp->db_next)
			;
		dbp->db_next = newdbp;
		bzero((caddr_t)dbp->db_next, sizeof (*newdbp));
		dbp->db_nextblk = getfreeblks(s, 1);
		dbp->db_next->db_blknum = dbp->db_nextblk;
		prevdbp = dbp;
		dbp = dbp->db_next;
		dbp->db_nextblk = 0;
		dbp->db_firstentry = NULL;
		dbp->db_recsum = 0;
		dbp->db_magic = MDDB_MAGIC_DB;
	}
	/*
	 * ready to add record
	 */
	desize_ic = (sizeof (*dep) - sizeof (dep->de_blks)) +
	    (sizeof (mddb_block_t) * blkcnt);
	if (dbp->db_firstentry) {
		for (dep = dbp->db_firstentry; dep->de_next; dep = dep->de_next)
			;
		dep->de_next = (mddb_de_ic_t *)kmem_zalloc(desize_ic, KM_SLEEP);
		dep = dep->de_next;
	} else {
		dep = (mddb_de_ic_t *)kmem_zalloc(desize_ic, KM_SLEEP);
		dbp->db_firstentry = dep;
	}
	bzero((caddr_t)dep, desize_ic);
	dep->de_recid = newid;
	/*
	 * Optimized records have an owner node associated with them in
	 * a MN diskset.  The owner is only set on a node that is actively
	 * writing to that record.  The other nodes will show that record
	 * as having an invalid owner.  The owner for an optimized record
	 * is used during fixoptrecord to determine which node should
	 * write out the record when the replicas associated with that
	 * optimized record have been changed.
	 */
	if (MD_MNSET_SETNO(s->s_setno)) {
		dep->de_owner_nodeid = MD_MN_INVALID_NID;
	}
	dep->de_type1 =	type;
	dep->de_type2 = type2;
	dep->de_reqsize = usersize;
	dep->de_recsize = recsize;
	dep->de_blkcount = blkcnt;
	flag_type = options &
	    (MD_CRO_OPTIMIZE | MD_CRO_STRIPE | MD_CRO_MIRROR | MD_CRO_RAID |
	    MD_CRO_SOFTPART | MD_CRO_TRANS_MASTER | MD_CRO_TRANS_LOG |
	    MD_CRO_HOTSPARE | MD_CRO_HOTSPARE_POOL | MD_CRO_CHANGELOG);
	switch (flag_type) {
	case MD_CRO_OPTIMIZE:
		dep->de_flags = MDDB_F_OPT;
		getoptdev(s, dep, 0);
		getoptdev(s, dep, 1);
		break;
	case MD_CRO_STRIPE:
		dep->de_flags = MDDB_F_STRIPE;
		break;
	case MD_CRO_MIRROR:
		dep->de_flags = MDDB_F_MIRROR;
		break;
	case MD_CRO_RAID:
		dep->de_flags = MDDB_F_RAID;
		break;
	case MD_CRO_SOFTPART:
		dep->de_flags = MDDB_F_SOFTPART;
		break;
	case MD_CRO_TRANS_MASTER:
		dep->de_flags = MDDB_F_TRANS_MASTER;
		break;
	case MD_CRO_TRANS_LOG:
		dep->de_flags = MDDB_F_TRANS_LOG;
		break;
	case MD_CRO_HOTSPARE:
		dep->de_flags = MDDB_F_HOTSPARE;
		break;
	case MD_CRO_HOTSPARE_POOL:
		dep->de_flags = MDDB_F_HOTSPARE_POOL;
		break;
	case MD_CRO_CHANGELOG:
		dep->de_flags = MDDB_F_CHANGELOG;
		break;
	}
	/*
	 * try to get all blocks consecutive. If not possible
	 * just get them one at a time
	 */
	dep->de_blks[0] = getfreeblks(s, blkcnt);
	if (dep->de_blks[0]) {
		for (i = 1; i < blkcnt; i++)
			dep->de_blks[i] = dep->de_blks[0] + i;
	} else {
		for (i = 0; i < blkcnt;	 i++)
			dep->de_blks[i] = getfreeblks(s, 1);
	}
	dep->de_rb = rbp;
	bzero((caddr_t)rbp, recsize);
	rbp->rb_magic = MDDB_MAGIC_RB;

	/* Do we have to create an old style (32 bit) record?  */
	if (options & MD_CRO_32BIT) {
		if (options & MD_CRO_FN)
			rbp->rb_revision = MDDB_REV_RBFN;
		else
			rbp->rb_revision = MDDB_REV_RB;
	} else {
		if (options & MD_CRO_FN)
			rbp->rb_revision = MDDB_REV_RB64FN;
		else
			rbp->rb_revision = MDDB_REV_RB64;
	}

	/* set de_rb_userdata for non optimization records */
	if ((options & MD_CRO_OPTIMIZE) == 0) {
		dep->de_rb_userdata = userdata;
	}

	uniqtime32(&rbp->rb_timestamp);
	/* Generate the crc for this record */
	rec_crcgen(s, dep, rbp);
	tmppnt = (caddr_t)rbp;
	/*
	 * the following code writes new records to all instances of
	 * the data base. Writing one block at a time to each instance
	 * is safe because they are not yet in a directory entry which
	 * has been written to the data base
	 */
	err = 0;
	if ((options & MD_CRO_OPTIMIZE) == 0) {
		for (i = 0; i < blkcnt;	 i++) {
			err |= writeall(s, (caddr_t)tmppnt,
			    dep->de_blks[i], 1, 0);
			tmppnt += MDDB_BSIZE;
		}
	} else {
		if ((MD_MNSET_SETNO(s->s_setno)) &&
		    md_set[s->s_setno].s_am_i_master) {
		/*
		 * If a MN diskset then only master writes out newly
		 * created optimized record.
		 */
			err |= writeoptrecord(s, dep);
		}
	}
	uniqtime32(&dbp->db_timestamp);
	dbp->db_revision = MDDB_REV_DB;
	/* Don't include opt resync and change log records in global XOR */
	if (!(dep->de_flags & MDDB_F_OPT) &&
	    !(dep->de_flags & MDDB_F_CHANGELOG))
		dbp->db_recsum ^= rbp->rb_checksum;
	db32p = (mddb_db32_t *)kmem_zalloc(MDDB_BSIZE, KM_SLEEP);
	create_db32rec(db32p, dbp);
	crcgen(db32p, &db32p->db32_checksum, MDDB_BSIZE, NULL);
	err |= writeall(s, (caddr_t)db32p, dbp->db_blknum, 1, 0);
	if (prevdbp) {
		dbp = prevdbp;
		uniqtime32(&dbp->db_timestamp);
		dbp->db_revision = MDDB_REV_DB;
		create_db32rec(db32p, dbp);
		crcgen(db32p, &db32p->db32_checksum, MDDB_BSIZE, NULL);
		err |= writeall(s, (caddr_t)db32p, dbp->db_blknum, 1, 0);
	}
	kmem_free((caddr_t)db32p, MDDB_BSIZE);
	if (err) {
		if (writeretry(s)) {
			s->s_zombie = newid;
			single_thread_end(s);
			mddb_setexit(s);
			return (MDDB_E_NOTNOW);
		}
	}
	single_thread_end(s);
	mddb_setexit(s);

	ASSERT((newid & MDDB_SETMASK) == 0);
	return (MAKERECID(setno, newid));
}

int
mddb_deleterec(
	mddb_recid_t	id
)
{
	mddb_set_t	*s;
	mddb_db_t	*dbp;
	mddb_db32_t	*db32p;
	mddb_de_ic_t	*dep, *dep1;
	int		i;

#if defined(_ILP32) && !defined(lint)
	ASSERT(sizeof (mddb_db_t) == sizeof (mddb_db32_t));
	ASSERT(sizeof (mddb_rb_t) == sizeof (mddb_rb32_t));
#endif

	s = mddb_setenter(DBSET(id), MDDB_NOINIT, NULL);
	ASSERT(s != NULL);

	id = DBID(id);
	if (checkstate(s, MDDB_PROBE)) {
		mddb_setexit(s);
		return (MDDB_E_NOTNOW);
	}

	ASSERT(s->s_lbp != NULL);
	single_thread_start(s);

	for (dbp = s->s_dbp; dbp != NULL; dbp = dbp->db_next) {
		dep1 = NULL;
		for (dep = dbp->db_firstentry; dep; dep = dep->de_next) {
			if (dep->de_recid == id)
				break;
			dep1 = dep;
		}
		if (dep != NULL)
			break;
	}
	/*
	 * no such record
	 */
	if (dep == NULL) {
		single_thread_end(s);
		ASSERT(s->s_staledeletes != 0);
		s->s_staledeletes--;
		mddb_setexit(s);
		return (0);
	}

	if (!(dep->de_flags & MDDB_F_OPT) &&
	    !(dep->de_flags & MDDB_F_CHANGELOG)) {
		dbp->db_recsum ^= dep->de_rb->rb_checksum;
		dbp->db_recsum ^= dep->de_rb->rb_checksum_fiddle;
	}

	if (dep->de_rb_userdata != NULL) {
		if (dep->de_icreqsize)
			kmem_free(dep->de_rb_userdata_ic, dep->de_icreqsize);
		else
			kmem_free(dep->de_rb_userdata, dep->de_reqsize);
	}

	kmem_free((caddr_t)dep->de_rb, dep->de_recsize);

	for (i = 0; i < dep->de_blkcount; i++)
		blkfree(s, dep->de_blks[i]);
	if (dep1)
		dep1->de_next = dep->de_next;
	else
		dbp->db_firstentry = dep->de_next;

	kmem_free(dep, sizeofde(dep));

	uniqtime32(&dbp->db_timestamp);
	dbp->db_revision = MDDB_REV_DB;
	db32p = (mddb_db32_t *)kmem_zalloc(MDDB_BSIZE, KM_SLEEP);
	create_db32rec(db32p, dbp);
	crcgen(db32p, &db32p->db32_checksum, MDDB_BSIZE, NULL);
	if (writeall(s, (caddr_t)db32p, dbp->db_blknum, 1, 0)) {
		if (writeretry(s)) {
			/*
			 * staledelete is used to mark deletes which failed.
			 * its only use is to not panic when the user retries
			 * the delete once the database is active again
			 */
			single_thread_end(s);
			s->s_staledeletes++;
			kmem_free((caddr_t)db32p, MDDB_BSIZE);
			mddb_setexit(s);
			return (MDDB_E_NOTNOW);
		}
	}
	single_thread_end(s);
	kmem_free((caddr_t)db32p, MDDB_BSIZE);
	mddb_setexit(s);
	return (0);
}

mddb_recid_t
mddb_getnextrec(
	mddb_recid_t		id,
	mddb_type_t		typ,
	uint_t			type2
)
{
	mddb_set_t		*s;
	mddb_db_t		*dbp;
	mddb_de_ic_t		*dep;
	int			searching, err;
	set_t			setno;

	setno = DBSET(id);
	id = DBID(id);
	searching = id;

	if ((s = mddb_setenter(setno, MDDB_MUSTEXIST, &err)) == NULL)
		return (err);

	for (dbp = s->s_dbp; dbp != NULL; dbp = dbp->db_next) {
		for (dep = dbp->db_firstentry;
		    dep != NULL; dep = dep->de_next) {
			if (searching) {
				if (dep->de_recid == id)
					searching = 0;
			} else {
				if ((typ == MDDB_ALL || dep->de_type1 == typ) &&
				    (type2 == 0 || dep->de_type2 == type2)) {
					id = dep->de_recid;
					mddb_setexit(s);
					ASSERT((id & MDDB_SETMASK) == 0);
					return (MAKERECID(setno, id));
				}
			}
		}
	}

	mddb_setexit(s);

	if (searching)
		return (MDDB_E_NORECORD);
	return (0);
}

void *
mddb_getrecaddr(
	mddb_recid_t		id
)
{
	mddb_set_t		*s;
	mddb_db_t		*dbp;
	mddb_de_ic_t		*dep;
	void			*rval;

	if ((s = mddb_setenter(DBSET(id), MDDB_MUSTEXIST, NULL)) == NULL)
		return (NULL);

	id = DBID(id);
	for (dbp = s->s_dbp; dbp != NULL; dbp = dbp->db_next) {
		for (dep = dbp->db_firstentry;
		    dep != NULL; dep = dep->de_next) {
			if (dep->de_recid != id)
				continue;
			if (dep->de_rb_userdata)
				rval = (void *)dep->de_rb_userdata;
			else
				rval = (void *)dep->de_rb->rb_data;
			mddb_setexit(s);
			return (rval);
		}
	}

	mddb_setexit(s);
	return (NULL);
}


mddb_de_ic_t *
mddb_getrecdep(
	mddb_recid_t		id
)
{
	mddb_set_t		*s;
	mddb_db_t		*dbp;
	mddb_de_ic_t		*dep;

	if ((s = mddb_setenter(DBSET(id), MDDB_MUSTEXIST, NULL)) == NULL)
		return (NULL);

	id = DBID(id);
	for (dbp = s->s_dbp; dbp != NULL; dbp = dbp->db_next) {
		for (dep = dbp->db_firstentry;
		    dep != NULL; dep = dep->de_next) {
			if (dep->de_recid != id)
				continue;
			mddb_setexit(s);
			return (dep);
		}
	}

	mddb_setexit(s);
	return (NULL);
}

void *
mddb_getrecaddr_resize(
	mddb_recid_t		id,
	size_t			icsize,
	off_t			off
)
{
	mddb_set_t		*s;
	mddb_db_t		*dbp;
	mddb_de_ic_t		*dep;
	void			*rval = NULL;

	if ((s = mddb_setenter(DBSET(id), MDDB_MUSTEXIST, NULL)) == NULL)
		return (NULL);

	id = DBID(id);
	for (dbp = s->s_dbp; dbp != NULL; dbp = dbp->db_next) {
		for (dep = dbp->db_firstentry;
		    dep != NULL; dep = dep->de_next) {
			if (dep->de_recid != id)
				continue;
			if (dep->de_rb_userdata)
				rval = (void *)dep->de_rb_userdata;
			else
				rval = (void *)dep->de_rb->rb_data;
			break;
		}
		if (rval != NULL)
			break;
	}

	if (rval == NULL) {
		mddb_setexit(s);
		return (NULL);
	}

	if (dep->de_rb_userdata) {
		caddr_t nud;

		if (dep->de_icreqsize || (dep->de_reqsize >= icsize)) {
			mddb_setexit(s);
			return (rval);
		}
		ASSERT((dep->de_reqsize + off) <= icsize);
		nud = kmem_zalloc(icsize, KM_SLEEP);
		bcopy(dep->de_rb_userdata, nud + off, dep->de_reqsize);
		kmem_free(dep->de_rb_userdata, dep->de_reqsize);
		dep->de_rb_userdata = nud + off;
		dep->de_rb_userdata_ic = nud;
		dep->de_icreqsize = icsize;
		rval = nud;
	} else {
		size_t recsize;
		/* LINTED variable unused - used for sizeof calculations */
		mddb_rb32_t *nrbp;

		recsize = roundup((sizeof (*nrbp) - sizeof (nrbp->rb_data)) +
		    icsize, MDDB_BSIZE);
		if (dep->de_recsize < recsize)
			cmn_err(CE_PANIC, "mddb_getrecaddr_resize: only "
			    "nonoptimized records can be resized\n");
	}

	mddb_setexit(s);
	return (rval);
}

int
mddb_getrecprivate(
	mddb_recid_t		id
)
{
	mddb_set_t		*s;
	mddb_db_t		*dbp;
	mddb_de_ic_t		*dep;
	int			err = 0;
	int			private;

	if ((s = mddb_setenter(DBSET(id), MDDB_MUSTEXIST, &err)) == NULL)
		return (err);

	id = DBID(id);
	for (dbp = s->s_dbp; dbp != NULL; dbp = dbp->db_next) {
		for (dep = dbp->db_firstentry;
		    dep != NULL; dep = dep->de_next) {
			if (dep->de_recid != id)
				continue;
			private = (int)dep->de_rb->rb_private;
			mddb_setexit(s);
			return (private);
		}
	}

	mddb_setexit(s);
	return (MDDB_E_NORECORD);
}

void
mddb_setrecprivate(
	mddb_recid_t		id,
	uint_t			private
)
{
	mddb_set_t		*s;
	mddb_db_t		*dbp;
	mddb_de_ic_t		*dep;

	if ((s = mddb_setenter(DBSET(id), MDDB_MUSTEXIST, NULL)) == NULL) {
		ASSERT(0);
		return;
	}

	id = DBID(id);
	for (dbp = s->s_dbp; dbp != NULL; dbp = dbp->db_next) {
		for (dep = dbp->db_firstentry;
		    dep != NULL; dep = dep->de_next) {
			if (dep->de_recid != id)
				continue;
			dep->de_rb->rb_private = private;
			mddb_setexit(s);
			return;
		}
	}

	mddb_setexit(s);
	ASSERT(0);
}

mddb_type_t
mddb_getrectype1(
	mddb_recid_t		id
)
{
	mddb_set_t		*s;
	mddb_db_t		*dbp;
	mddb_de_ic_t		*dep;
	int			err = 0;
	mddb_type_t		rval;

	if ((s = mddb_setenter(DBSET(id), MDDB_MUSTEXIST, &err)) == NULL)
		return (err);

	id = DBID(id);
	for (dbp = s->s_dbp; dbp != NULL; dbp = dbp->db_next) {
		for (dep = dbp->db_firstentry;
		    dep != NULL; dep = dep->de_next) {
			if (dep->de_recid != id)
				continue;
			rval = dep->de_type1;
			mddb_setexit(s);
			return (rval);
		}
	}

	mddb_setexit(s);
	return (MDDB_E_NORECORD);
}

int
mddb_getrectype2(
	mddb_recid_t		id
)
{
	mddb_set_t		*s;
	mddb_db_t		*dbp;
	mddb_de_ic_t		*dep;
	int			err = 0;
	int			rval;

	if ((s = mddb_setenter(DBSET(id), MDDB_MUSTEXIST, &err)) == NULL)
		return (err);

	id = DBID(id);
	for (dbp = s->s_dbp; dbp != NULL; dbp = dbp->db_next) {
		for (dep = dbp->db_firstentry;
		    dep != NULL; dep = dep->de_next) {
			if (dep->de_recid != id)
				continue;
			rval = (int)dep->de_type2;
			mddb_setexit(s);
			return (rval);
		}
	}

	mddb_setexit(s);
	return (MDDB_E_NORECORD);
}

int
mddb_getrecsize(
	mddb_recid_t		id
)
{
	mddb_set_t		*s;
	mddb_db_t		*dbp;
	mddb_de_ic_t		*dep;
	int			err = 0;
	int			rval;

	if ((s = mddb_setenter(DBSET(id), MDDB_MUSTEXIST, &err)) == NULL)
		return (err);

	id = DBID(id);
	for (dbp = s->s_dbp; dbp != NULL; dbp = dbp->db_next) {
		for (dep = dbp->db_firstentry;
		    dep != NULL; dep = dep->de_next) {
			if (dep->de_recid != id)
				continue;
			rval = (int)dep->de_reqsize;
			mddb_setexit(s);
			return (rval);
		}
	}

	mddb_setexit(s);
	return (MDDB_E_NORECORD);
}


mddb_recstatus_t
mddb_getrecstatus(
	mddb_recid_t		id
)
{
	mddb_set_t		*s;
	mddb_db_t		*dbp;
	mddb_de_ic_t		*dep;
	int			err = 0;
	mddb_recstatus_t	e_err;

	if ((s = mddb_setenter(DBSET(id), MDDB_MUSTEXIST, &err)) == NULL)
		return ((mddb_recstatus_t)err);

	id = DBID(id);
	for (dbp = s->s_dbp; dbp != NULL; dbp = dbp->db_next) {
		for (dep = dbp->db_firstentry;
		    dep != NULL; dep = dep->de_next) {
			if (dep->de_recid == id)
				break;
		}
		if (dep)
			break;
	}

	e_err = MDDB_OK;

	if (! dep)
		e_err = MDDB_NORECORD;
	else if (! dep->de_rb->rb_commitcnt)
		e_err = MDDB_NODATA;
	else if (md_get_setstatus(s->s_setno) & MD_SET_STALE)
		e_err = MDDB_STALE;

	mddb_setexit(s);
	return (e_err);
}

/*
 * Commit given record to disk.
 * If committing an optimized record, do not call
 * with md ioctl lock held.
 */
int
mddb_commitrec(
	mddb_recid_t	id
)
{
	mddb_set_t			*s;
	mddb_db_t			*dbp;
	mddb_de_ic_t			*dep;
	mddb_recid_t			ids[2];
	mddb_rb32_t			*rbp;
	static int			err = 0;
	md_mn_msg_mddb_optrecerr_t	*msg_recerr;
	md_mn_kresult_t			*kres;
	mddb_lb_t			*lbp;
	mddb_mnlb_t			*mnlbp;
	mddb_locator_t			*lp;
	mddb_mnsidelocator_t		*mnslp;
	mddb_drvnm_t			*dn;
	int				li;
	md_replica_recerr_t		*recerr;
	int				i, j;
	int				rval;
	int				hit_err = 0;

	s = mddb_setenter(DBSET(id), MDDB_NOINIT, NULL);
	ASSERT(s != NULL);

	if (checkstate(s, MDDB_PROBE)) {
		mddb_setexit(s);
		return (MDDB_E_NOTNOW);
	}

	if (DBID(id) == 0) {
		mddb_setexit(s);
		return (0);
	}

	for (dbp = s->s_dbp; dbp != NULL; dbp = dbp->db_next) {
		for (dep = dbp->db_firstentry; dep; dep = dep->de_next) {
			if (dep->de_recid == DBID(id))
				break;
		}
		if (dep)
			break;
	}

	if (dep == NULL) {
		mddb_setexit(s);
		return (MDDB_E_NORECORD);
	}

	if (! (dep->de_flags & MDDB_F_OPT)) {
		ids[0] = id;
		ids[1] = 0;
		mddb_setexit(s);
		return (mddb_commitrecs(ids));
	}

	/*
	 * following code allows multiple processes to be doing
	 * optimization commits in parallel.
	 * NOTE: if lots of optimization commits then the lock
	 * will not get released until it winds down
	 */
	if (s->s_optwaiterr) {
		while (s->s_optwaiterr) {
			s->s_opthungerr = 1;
			cv_wait(&s->s_opthungerr_cv, SETMUTEX(s->s_setno));
		}
		if (checkstate(s, MDDB_PROBE)) {
			mddb_setexit(s);
			return (MDDB_E_NOTNOW);
		}
	}
	if (s->s_optcmtcnt++ == 0) {
		single_thread_start(s);
		s->s_opthavelck = 1;
		if (s->s_optwantlck) {
			cv_broadcast(&s->s_optwantlck_cv);
			s->s_optwantlck = 0;
		}
	} else {
		while (! s->s_opthavelck) {
			s->s_optwantlck = 1;
			cv_wait(&s->s_optwantlck_cv, SETMUTEX(s->s_setno));
		}
	}

	for (dbp = s->s_dbp; dbp != NULL; dbp = dbp->db_next) {
		for (dep = dbp->db_firstentry; dep; dep = dep->de_next) {
			if (dep->de_recid == DBID(id))
				break;
		}
		if (dep)
			break;
	}

	if (dep == NULL) {
		if (! (--s->s_optcmtcnt)) {
			single_thread_end(s);
			s->s_opthavelck = 0;
		}
		mddb_setexit(s);
		return (MDDB_E_NORECORD);
	}

	rbp = dep->de_rb;
	rbp->rb_commitcnt++;
	uniqtime32(&rbp->rb_timestamp);
	/* Generate the crc for this record */
	rec_crcgen(s, dep, rbp);

	if (writeoptrecord(s, dep)) {
		if (MD_MNSET_SETNO(s->s_setno)) {
			hit_err = 1;
		}
		s->s_optwaiterr++;
	}
	if (MD_MNSET_SETNO(s->s_setno)) {
		/* If last thread out, release single_thread_start */
		if (! (--s->s_optcmtcnt)) {
			single_thread_end(s);
			s->s_opthavelck = 0;
		}
		/*
		 * If this thread had a writeoptrecords failure, then
		 * need to send message to master.
		 * But, multiple threads could all be running on the
		 * same single_thread_start, so serialize the threads
		 * by making each thread grab single_thread_start.
		 *
		 * After return from sending message to master message,
		 * replicas associated with optimized record will havei
		 * been changed (via a callback from the master to all
		 * nodes), so retry call to writeoptrecord.
		 * This code is replacing the call to writeretry that
		 * occurs for the local and traditional disksets.
		 */
		if (hit_err) {
			single_thread_start(s);
			/*
			 * If > 50% of replicas are alive then continue
			 * to send message to master until writeoptrecord
			 * succeeds.  For now, assume that minor name,
			 * major number on this node is the same as on
			 * the master node.  Once devids are turned on
			 * for MN disksets, can send devid.
			 */
			kres = kmem_zalloc(sizeof (md_mn_kresult_t), KM_SLEEP);
			msg_recerr = kmem_zalloc(
			    sizeof (md_mn_msg_mddb_optrecerr_t), KM_SLEEP);
			while (!(md_get_setstatus(s->s_setno) &
			    MD_SET_TOOFEW)) {
				bzero((caddr_t)msg_recerr,
				    sizeof (md_mn_msg_mddb_optrecerr_t));
				lbp = s->s_lbp;
				mnlbp = (mddb_mnlb_t *)lbp;
				for (i = 0; i < 2; i++) {
					li = dep->de_optinfo[i].o_li;
					lp = &lbp->lb_locators[li];
					for (j = 0; j < MD_MNMAXSIDES; j++) {
						mnslp =
						    &mnlbp->
						    lb_mnsidelocators[j][li];
						if (mnslp->mnl_sideno ==
						    s->s_sideno)
							break;
					}
					if (j == MD_MNMAXSIDES)
						continue;

					dn = &lbp->
					    lb_drvnm[mnslp->mnl_drvnm_index];
					recerr = &msg_recerr->msg_recerr[i];
					recerr->r_li = li;
					recerr->r_flags =
					    dep->de_optinfo[i].o_flags;
					recerr->r_blkno = lp->l_blkno;
					recerr->r_mnum = md_getminor(lp->l_dev);
					(void) strncpy(recerr->r_driver_name,
					    dn->dn_data, MD_MAXDRVNM);
				}

				/* Release locks */
				single_thread_end(s);
				mutex_exit(SETMUTEX(s->s_setno));

				/*
				 * Send message to master about optimized
				 * record failure.  After return, master
				 * should have marked failed replicas
				 * and sent parse message to slaves causing
				 * slaves to have fixed up the optimized
				 * record.
				 * On return from ksend_message, retry
				 * the write since this node should have fixed
				 * the optimized resync records it owns.
				 */
				rval = mdmn_ksend_message(s->s_setno,
				    MD_MN_MSG_MDDB_OPTRECERR,
				    MD_MSGF_NO_BCAST, 0,
				    (char *)msg_recerr,
				    sizeof (md_mn_msg_mddb_optrecerr_t),
				    kres);
				if (!MDMN_KSEND_MSG_OK(rval, kres)) {
					cmn_err(CE_WARN, "mddb_commitrec: "
					    "Unable to send optimized "
					    "resync record failure "
					    "message to other nodes in "
					    "diskset %s\n", s->s_setname);
					mdmn_ksend_show_error(rval, kres,
					    "MD_MN_MSG_MDDB_OPTRECERR");
				}

				/* Regrab locks */
				mutex_enter(SETMUTEX(s->s_setno));
				single_thread_start(s);

				/* Start over in case mddb changed */
				for (dbp = s->s_dbp; dbp != NULL;
				    dbp = dbp->db_next) {
					for (dep = dbp->db_firstentry; dep;
					    dep = dep->de_next) {
						if (dep->de_recid == DBID(id))
							break;
					}
					if (dep)
						break;
				}
				if (dep) {
					rbp = dep->de_rb;
					rbp->rb_commitcnt++;
					uniqtime32(&rbp->rb_timestamp);
					/* Generate the crc for this record */
					rec_crcgen(s, dep, rbp);

					/*
					 * If writeoptrecord succeeds, then
					 * break out.
					 */
					if (!(writeoptrecord(s, dep)))
						break;
				}
			}
			kmem_free(kres, sizeof (md_mn_kresult_t));
			kmem_free(msg_recerr,
			    sizeof (md_mn_msg_mddb_optrecerr_t));

			/* Resync record should be fixed - if possible */
			s->s_optwaiterr--;
			if (s->s_optwaiterr == 0) {
				/* All errors have been handled */
				if (s->s_opthungerr) {
					s->s_opthungerr = 0;
					cv_broadcast(&s->s_opthungerr_cv);
				}
			}
			single_thread_end(s);
			mddb_setexit(s);
			if (md_get_setstatus(s->s_setno) & MD_SET_TOOFEW) {
				return (MDDB_E_NOTNOW);
			} else {
				return (0);
			}
		}
	} else {
		/* If set is a traditional or local set */
		if (! (--s->s_optcmtcnt)) {
			err = 0;
			if (s->s_optwaiterr) {
				err = writeretry(s);
				s->s_optwaiterr = 0;
				if (s->s_opthungerr) {
					s->s_opthungerr = 0;
					cv_broadcast(&s->s_opthungerr_cv);
				}
			}
			single_thread_end(s);
			s->s_opthavelck = 0;
			mddb_setexit(s);
			if (err)
				return (MDDB_E_NOTNOW);
			return (0);
		}
		if (s->s_optwaiterr) {
			while (s->s_optwaiterr) {
				s->s_opthungerr = 1;
				cv_wait(&s->s_opthungerr_cv,
				    SETMUTEX(s->s_setno));
			}
			if (checkstate(s, MDDB_NOPROBE)) {
				mddb_setexit(s);
				return (MDDB_E_NOTNOW);
			}
		}
	}

	mddb_setexit(s);
	return (0);
}

int
mddb_commitrecs(
	mddb_recid_t	ids[]
)
{
	mddb_set_t	*s;
	mddb_db_t	*dbp;
	mddb_de_ic_t	*dep;
	mddb_rb32_t	*rbp;
	mddb_rb32_t	*saverbp;
	mddb_lb_t	*lbp;
	int		li;
	uint_t		checksum;
	mddb_recid_t	*idp;
	int		err = 0;
	set_t		setno;

	if (panicstr)
		cmn_err(CE_PANIC, "md: mddb: commit not allowed");

	/*
	 * scan through and make sure ids are from the same set
	 */
	setno = DBSET(ids[0]);
	for (idp = ids; *idp != NULL; idp++)
		ASSERT(DBSET(*idp) == setno);

	s = mddb_setenter(setno, MDDB_MUSTEXIST, NULL);

	if (checkstate(s, MDDB_PROBE)) {
		mddb_setexit(s);
		return (MDDB_E_NOTNOW);
	}

	ASSERT(s->s_lbp != NULL);
	err = 0;

	if (! ids[0]) {
		mddb_setexit(s);
		return (0);
	}

	single_thread_start(s);
	/*
	 * scan through and make sure ids all exist
	 */
	for (idp = ids; *idp != NULL; idp++) {
		for (dbp = s->s_dbp; dbp != NULL; dbp = dbp->db_next) {
			for (dep = dbp->db_firstentry; dep;
			    dep = dep->de_next) {
				if (dep->de_recid == DBID(*idp))
					break;
			}
			if (dep != NULL)
				break;
		}
		if (dep == NULL) {
			single_thread_end(s);
			mddb_setexit(s);
			return (MDDB_E_NORECORD);
		}
	}

	/*
	 * scan through records fix commit counts and
	 * zero fiddles and update time stamp and rechecksum record
	 */
	checksum = 0;
	idp = ids;
	saverbp = NULL;
	while (*idp) {
		for (dbp = s->s_dbp; dbp != NULL; dbp = dbp->db_next) {
			for (dep = dbp->db_firstentry; dep;
			    dep = dep->de_next) {
				if (dep->de_recid == DBID(*idp))
					break;
			}
			if (dep != NULL)
				break;
		}
		rbp = dep->de_rb;
		ASSERT(! (dep->de_flags & MDDB_F_OPT));

		getuserdata(setno, dep);
		/* Don't do fiddles for CHANGE LOG records */
		if (!(dep->de_flags & MDDB_F_CHANGELOG)) {
			checksum ^= rbp->rb_checksum_fiddle;
			rbp->rb_checksum_fiddle = 0;
			checksum ^= rbp->rb_checksum;
			saverbp = rbp;
		}
		rbp->rb_commitcnt++;
		uniqtime32(&rbp->rb_timestamp);
		/* Generate the crc for this record */
		rec_crcgen(s, dep, rbp);

		/* Don't do fiddles for CHANGE LOG records */
		if (!(dep->de_flags & MDDB_F_CHANGELOG)) {
			checksum ^= rbp->rb_checksum;
		}
		idp++;
	}

	if (saverbp)
		saverbp->rb_checksum_fiddle = checksum;

	/*
	 * If this is a MN set but we are not the master, then we are not
	 * supposed to update the mddb on disk. So we finish at this point.
	 */
	if ((setno != MD_LOCAL_SET) && (s->s_lbp->lb_flags & MDDB_MNSET) &&
	    (md_set[setno].s_am_i_master == 0)) {
		single_thread_end(s);
		mddb_setexit(s);
		return (0);
	}

	lbp = s->s_lbp;
	for (li = 0; li < lbp->lb_loccnt; li++) {
		if (! (lbp->lb_locators[li].l_flags & MDDB_F_ACTIVE))
			continue;

		idp = ids;
		while (*idp) {
			for (dbp = s->s_dbp; dbp != NULL; dbp = dbp->db_next) {
				dep = dbp->db_firstentry;
				while (dep && (dep->de_recid != DBID(*idp)))
					dep = dep->de_next;
				if (dep != NULL)
					break;
			}
			rbp = dep->de_rb;
			err = wrtblklst(s, (caddr_t)rbp, dep->de_blks,
			    dep->de_blkcount, li, (mddb_bf_t **)0,
			    MDDB_WR_ONLY_MASTER);
			if (err)
				break;
			idp++;
		}
		if (err)
			break;
	}
	if (err) {
		if (writeretry(s)) {
			single_thread_end(s);
			mddb_setexit(s);
			return (MDDB_E_NOTNOW);
		}
	}
	single_thread_end(s);
	mddb_setexit(s);
	return (0);
}

mddb_recid_t
mddb_makerecid(
	set_t		setno,
	mddb_recid_t	id
)
{
	return (MAKERECID(setno, id));
}

set_t
mddb_getsetnum(
	mddb_recid_t	id
)
{
	return (DBSET(id));
}

char *
mddb_getsetname(
	set_t	setno
)
{
	return (((mddb_set_t *)md_set[setno].s_db)->s_setname);
}

side_t
mddb_getsidenum(
	set_t	setno
)
{
	if (md_set[setno].s_db)
		return (((mddb_set_t *)md_set[setno].s_db)->s_sideno);
	return (0);
}

int
mddb_ownset(
	set_t	setno
)
{
	if ((md_get_setstatus(setno) & MD_SET_TAGDATA) && md_set[setno].s_db)
		return (1);

	if (md_set[setno].s_db && ((mddb_set_t *)md_set[setno].s_db)->s_lbp)
		return (1);

	return (0);
}

/*ARGSUSED*/
int
getmed_ioctl(mddb_med_parm_t *medpp, int mode)
{
	mddb_set_t	*s;
	int		err = 0;
	set_t		setno = medpp->med_setno;
	md_error_t	*ep = &medpp->med_mde;

	mdclrerror(ep);

	if (setno >= md_nsets)
		return (mdmderror(ep, MDE_INVAL_UNIT, MD_ADM_MINOR));

	if (md_snarf_db_set(MD_LOCAL_SET, ep) != 0)
		return (0);

	if ((md_get_setstatus(setno) & MD_SET_SNARFED) == 0)
		return (mdmddberror(ep, MDE_DB_NOTOWNER, NODEV32, setno));

	if ((s = mddb_setenter(setno, MDDB_MUSTEXIST, &err)) == NULL)
		return (mddbstatus2error(ep, err, NODEV32, setno));

	medpp->med = s->s_med;			/* structure assignment */

	mddb_setexit(s);

	return (0);
}

int
setmed_ioctl(mddb_med_parm_t *medpp, int mode)
{

	mddb_set_t	*s;
	int		err = 0;
	set_t		setno = medpp->med_setno;
	md_error_t	*ep = &medpp->med_mde;

	mdclrerror(ep);

	if ((mode & FWRITE) == 0)
		return (mdsyserror(ep, EACCES));

	/*
	 * This should be the only thing that prevents LOCAL sets from having
	 * mediators, at least in the kernel, userland needs to have some code
	 * written.
	 */
	if (setno == MD_LOCAL_SET)
		return (mdmderror(ep, MDE_INVAL_UNIT, MD_ADM_MINOR));

	if (setno >= md_nsets)
		return (mdmderror(ep, MDE_INVAL_UNIT, MD_ADM_MINOR));

	if (md_snarf_db_set(MD_LOCAL_SET, ep) != 0)
		return (0);

	if ((md_get_setstatus(setno) & MD_SET_SNARFED) == 0)
		return (mdmddberror(ep, MDE_DB_NOTOWNER, NODEV32, setno));

	if ((s = mddb_setenter(setno, MDDB_MUSTEXIST, &err)) == NULL)
		return (mddbstatus2error(ep, err, NODEV32, setno));

	s->s_med = medpp->med;			/* structure assignment */

	mddb_setexit(s);

	return (0);
}

int
updmed_ioctl(mddb_med_upd_parm_t *medpp, int mode)
{

	mddb_set_t	*s;
	int		err = 0;
	set_t		setno = medpp->med_setno;
	md_error_t	*ep = &medpp->med_mde;

	mdclrerror(ep);

	if ((mode & FWRITE) == 0)
		return (mdsyserror(ep, EACCES));

	if (setno >= md_nsets)
		return (mdmderror(ep, MDE_INVAL_UNIT, MD_ADM_MINOR));

	if (md_snarf_db_set(MD_LOCAL_SET, ep) != 0)
		return (0);

	if ((md_get_setstatus(setno) & MD_SET_SNARFED) == 0)
		return (mdmddberror(ep, MDE_DB_NOTOWNER, NODEV32, setno));

	if ((s = mddb_setenter(setno, MDDB_MUSTEXIST, &err)) == NULL)
		return (mddbstatus2error(ep, err, NODEV32, setno));

	single_thread_start(s);
	(void) upd_med(s, "updmed_ioctl()");
	single_thread_end(s);

	mddb_setexit(s);

	return (0);
}

int
take_set(mddb_config_t *cp, int mode)
{
	int			err = 0;
	mddb_med_upd_parm_t	medup;
	set_t			setno = cp->c_setno;
	md_error_t		*ep = &cp->c_mde;
	int			snarf_ok = 0;

	if (md_get_setstatus(setno) & MD_SET_SNARFED)
		return (0);

	err = mddb_configure(MDDB_GETDEV, cp);
	if (! err && mdisok(ep)) {
		if (md_snarf_db_set(setno, ep) != 0)
			goto out;
		snarf_ok = 1;
	}

	/*
	 * Clear replicated import flag since this is
	 * used during the take of a diskset with
	 * previously unresolved replicated disks.
	 */
	if (md_get_setstatus(setno) &
	    MD_SET_REPLICATED_IMPORT) {
		md_clr_setstatus(setno, MD_SET_REPLICATED_IMPORT);
	}

	if (! err && mdisok(ep)) {
		if (! cp->c_flags) {
			medup.med_setno = setno;
			mdclrerror(&medup.med_mde);

			err = updmed_ioctl(&medup, mode);
			if (! mdisok(&medup.med_mde))
				(void) mdstealerror(ep, &medup.med_mde);
		}
	}

out:
	/*
	 * In the case that the snarf failed, the diskset is
	 * left with s_db set, but s_lbp not set.  The node is not
	 * an owner of the set and won't be allowed to release the
	 * diskset in order to cleanup.  With s_db set, any call to the
	 * GETDEV or ENDDEV ioctl (done by libmeta routine metareplicalist)
	 * will cause the diskset to be loaded.  So, cleanup the diskset so
	 * that an inadvertent start of the diskset doesn't happen later.
	 */
	if ((snarf_ok == 0) && md_set[setno].s_db &&
	    (((mddb_set_t *)md_set[setno].s_db)->s_lbp == 0)) {
		mutex_enter(&mddb_lock);
		mddb_unload_set(setno);
		mutex_exit(&mddb_lock);
	}
	return (err);
}

/*ARGSUSED*/
int
release_set(mddb_config_t *cp, int mode)
{
	int			err = 0;
	set_t			setno = cp->c_setno;
	md_error_t		*ep = &cp->c_mde;

	/*
	 * Data integrity check
	 */
	if (setno >= md_nsets)
		return (mdmderror(ep, MDE_INVAL_UNIT, MD_ADM_MINOR));

	rw_enter(&md_unit_array_rw.lock, RW_WRITER);
	md_haltsnarf_enter(setno);
	/*
	 * Attempt to mark set as HOLD. If it is marked as HOLD, this means
	 * that the mirror code is currently searching all mirrors for a
	 * errored component that needs a hotspare. While this search is in
	 * progress, we cannot release the set and thgerefore we return EBUSY.
	 * Once we have set HOLD, the mirror function (check_4_hotspares) will
	 * block before the search until the set is released.
	 */
	if (md_holdset_testandenter(setno) != 0) {
		md_haltsnarf_exit(setno);
		rw_exit(&md_unit_array_rw.lock);
		return (EBUSY);
	}

	if ((err = md_halt_set(setno, MD_HALT_ALL)) == 0)
		err = mddb_configure(MDDB_RELEASESET, cp);

	md_holdset_exit(setno);
	md_haltsnarf_exit(setno);
	rw_exit(&md_unit_array_rw.lock);

	if (! err && mdisok(ep)) {
		SE_NOTIFY(EC_SVM_STATE, ESC_SVM_RELEASE, SVM_TAG_SET, setno,
		    NODEV64);
	}

	return (err);
}

int
gettag_ioctl(mddb_dtag_get_parm_t *dtgpp, int mode)
{
	mddb_set_t	*s;
	int		err = 0;
	mddb_dtag_lst_t	*dtlp;
	set_t		setno = dtgpp->dtgp_setno;
	md_error_t	*ep = &dtgpp->dtgp_mde;

	mdclrerror(ep);

	if ((mode & FREAD) == 0)
		return (mdsyserror(ep, EACCES));

	if (setno >= md_nsets)
		return (mdmderror(ep, MDE_INVAL_UNIT, MD_ADM_MINOR));

	if (md_snarf_db_set(MD_LOCAL_SET, ep) != 0)
		return (0);

	if ((s = mddb_setenter(setno, MDDB_NOINIT, &err)) == NULL)
		return (mddbstatus2error(ep, err, NODEV32, setno));

	/*
	 * Data tags not supported on MN sets so return invalid operation.
	 * This ioctl could be called before the mddb has been read in so
	 * the set status may not yet be set to MNSET, so code following
	 * this check must handle a MN diskset properly.
	 */
	if (md_get_setstatus(setno) & MD_SET_MNSET) {
		mddb_setexit(s);
		return (mderror(ep, MDE_INVAL_MNOP));
	}

	/* s_dtlp is NULL for MN diskset */
	dtlp = s->s_dtlp;
	while (dtlp != NULL) {
		if (dtgpp->dtgp_dt.dt_id == 0 ||
		    dtgpp->dtgp_dt.dt_id == dtlp->dtl_dt.dt_id) {
			bcopy((caddr_t)&dtlp->dtl_dt, (caddr_t)&dtgpp->dtgp_dt,
			    sizeof (mddb_dtag_t));
			break;
		}
		dtlp = dtlp->dtl_nx;
	}

	/* Walked the whole list and id not found, return error */
	if (dtlp == (mddb_dtag_lst_t *)NULL) {
		mddb_setexit(s);
		return (mdmddberror(ep, MDE_DB_NOTAG, NODEV32, setno));
	}

	mddb_setexit(s);

	return (0);
}

int
usetag_ioctl(mddb_dtag_use_parm_t *dtupp, int mode)
{
	mddb_set_t	*s;
	int		err = 0;
	mddb_config_t	*cp;
	mddb_ri_t	*trip = NULL;
	mddb_dtag_t	*dtagp = NULL;
	set_t		setno = dtupp->dtup_setno;
	md_error_t	*ep = &dtupp->dtup_mde;

	mdclrerror(ep);

	if ((mode & FWRITE) == 0)
		return (mdsyserror(ep, EACCES));

	if (setno >= md_nsets)
		return (mdmderror(ep, MDE_INVAL_UNIT, MD_ADM_MINOR));

	if (dtupp->dtup_id < 0)
		return (mdsyserror(ep, EINVAL));
	else if (dtupp->dtup_id == 0)
		return (mdmddberror(ep, MDE_DB_NOTAG, NODEV32, setno));

	if (md_snarf_db_set(MD_LOCAL_SET, ep) != 0)
		return (0);

	if ((md_get_setstatus(setno) & MD_SET_TAGDATA) == 0)
		return (mdmddberror(ep, MDE_DB_NTAGDATA, NODEV32, setno));

	if ((s = mddb_setenter(setno, MDDB_NOINIT, &err)) == NULL)
		return (mddbstatus2error(ep, err, NODEV32, setno));

	/*
	 * Data tags not supported on MN sets so return invalid operation.
	 * This ioctl could be called before the mddb has been read in so
	 * the set status may not yet be set to MNSET, so code following
	 * this check must handle a MN diskset properly.
	 */
	if (md_get_setstatus(setno) & MD_SET_MNSET) {
		mddb_setexit(s);
		return (mderror(ep, MDE_INVAL_MNOP));
	}

	/* Validate and find the id requested - nothing found if MN diskset */
	if ((dtagp = dtl_findl(s, dtupp->dtup_id)) == NULL) {
		mddb_setexit(s);
		return (mdmddberror(ep, MDE_DB_NOTAG, NODEV32, setno));
	}

	/* Usetag is only valid when more than one tag exists */
	if (dtl_cntl(s) < 2) {
		mddb_setexit(s);
		return (mdmddberror(ep, MDE_DB_NTAGDATA, NODEV32, setno));
	}

	/* Put the selected tag in place */
	dt_setup(s, dtagp);

	cp = kmem_zalloc(sizeof (mddb_config_t), KM_SLEEP);

	/* Save the hint information */
	trip = save_rip(s);

	cp->c_timestamp = s->s_ident.createtime;	/* struct assignment */
	cp->c_setno = setno;
	cp->c_sideno = s->s_sideno;
	(void) strncpy(cp->c_setname, s->s_setname, MD_MAX_SETNAME);
	cp->c_setname[MD_MAX_SETNAME] = '\0';
	cp->c_med = s->s_med;				/* struct assignment */

	mddb_setexit(s);

	s = NULL;

	/* shorthand */
	setno = cp->c_setno;

	/* Let unload know not to free the tag */
	md_set_setstatus(setno, MD_SET_KEEPTAG);

	/* Release the set */
	if (err = release_set(cp, mode))
		goto out;

	if (! mdisok(&cp->c_mde)) {
		(void) mdstealerror(ep, &cp->c_mde);
		err = 1;
		goto out;
	}

	/* Re-init set using the saved mddb_config_t structure */
	if ((s = mddb_setenter(setno, MDDB_NOINIT, &err)) == NULL) {
		if ((s = init_set(cp, MDDB_NOINIT, &err)) == NULL) {
			err = mddbstatus2error(ep, err, NODEV32, setno);
			goto out;
		}
	}

	ASSERT(s->s_rip == (mddb_ri_t *)NULL);

	/* use the saved rip structure */
	s->s_rip = trip;
	trip = (mddb_ri_t *)NULL;

	/* Let the take code know a tag is being used */
	md_set_setstatus(setno, MD_SET_USETAG);

	mddb_setexit(s);

	s = NULL;

	/* Take the set */
	if (err = take_set(cp, mode))
		goto out;

	if (! mdisok(&cp->c_mde))
		(void) mdstealerror(ep, &cp->c_mde);

out:
	md_clr_setstatus(setno, (MD_SET_USETAG | MD_SET_KEEPTAG));

	kmem_free(cp, sizeof (mddb_config_t));

	if (trip)
		free_rip(&trip);

	if (s)
		mddb_setexit(s);

	return (err);
}

int
accept_ioctl(mddb_accept_parm_t *accpp, int mode)
{
	mddb_set_t	*s;
	int		err = 0;
	mddb_config_t	*cp;
	mddb_ri_t	*trip = NULL;
	set_t		setno = accpp->accp_setno;
	md_error_t	*ep = &accpp->accp_mde;

	mdclrerror(ep);

	if ((mode & FWRITE) == 0)
		return (mdsyserror(ep, EACCES));

	if (setno >= md_nsets)
		return (mdmderror(ep, MDE_INVAL_UNIT, MD_ADM_MINOR));

	if (md_snarf_db_set(MD_LOCAL_SET, ep) != 0)
		return (0);

	if ((md_get_setstatus(setno) & MD_SET_ACCOK) == 0)
		return (mdmddberror(ep, MDE_DB_ACCNOTOK, NODEV32, setno));

	if ((s = mddb_setenter(setno, MDDB_MUSTEXIST, &err)) == NULL)
		return (mddbstatus2error(ep, err, NODEV32, setno));

	/*
	 * Data tags not supported on MN sets so return invalid operation.
	 * mddb is guaranteed to be incore at this point, so this
	 * check will catch all MN disksets.
	 */
	if (md_get_setstatus(setno) & MD_SET_MNSET) {
		mddb_setexit(s);
		return (mderror(ep, MDE_INVAL_MNOP));
	}

	cp = kmem_zalloc(sizeof (mddb_config_t), KM_SLEEP);

	trip = save_rip(s);

	cp->c_timestamp = s->s_ident.createtime;	/* struct assignment */
	cp->c_setno = setno;
	cp->c_sideno = s->s_sideno;
	(void) strncpy(cp->c_setname, s->s_setname, MD_MAX_SETNAME);
	cp->c_setname[MD_MAX_SETNAME] = '\0';
	cp->c_med = s->s_med;				/* struct assignment */

	/* Tag the data */
	if (err = set_dtag(s, ep)) {
		err = mdsyserror(ep, err);
		goto out;
	}

	/* If we had a BADTAG, it will be re-written, so clear the bit. */
	if (md_get_setstatus(setno) & MD_SET_BADTAG)
		md_clr_setstatus(setno, MD_SET_BADTAG);

	if (err = dt_write(s)) {
		err = mdsyserror(ep, err);
		goto out;
	}

	mddb_setexit(s);

	s = NULL;

	/* shorthand */
	setno = cp->c_setno;

	/* Clear the keeptag */
	md_clr_setstatus(setno, MD_SET_KEEPTAG);

	/* Release the set */
	if (err = release_set(cp, mode))
		goto out;

	if (! mdisok(&cp->c_mde)) {
		(void) mdstealerror(ep, &cp->c_mde);
		goto out;
	}

	/* Re-init set using the saved mddb_config_t structure */
	if ((s = mddb_setenter(setno, MDDB_NOINIT, &err)) == NULL) {
		if ((s = init_set(cp, MDDB_NOINIT, &err)) == NULL) {
			err = mddbstatus2error(ep, err, NODEV32, setno);
			goto out;
		}
	}

	ASSERT(s->s_rip == (mddb_ri_t *)NULL);

	/* Free the allocated rip structure */
	if (s->s_rip != (mddb_ri_t *)NULL)
		free_rip(&s->s_rip);

	/* use the saved rip structure */
	s->s_rip = trip;
	trip = (mddb_ri_t *)NULL;

	/* Let the set init code know an accept is in progress */
	md_set_setstatus(setno, MD_SET_ACCEPT);

	mddb_setexit(s);

	s = NULL;

	/* Take the set */
	if (err = take_set(cp, mode))
		goto out;

	if (! mdisok(&cp->c_mde))
		(void) mdstealerror(ep, &cp->c_mde);

out:
	md_clr_setstatus(setno, (MD_SET_ACCOK | MD_SET_ACCEPT));

	kmem_free(cp, sizeof (mddb_config_t));

	if (trip)
		free_rip(&trip);

	if (s)
		mddb_setexit(s);

	return (err);
}

/*
 * mddb_getinvlb_devid - cycles through the locator block and determines
 *		if the device id's for any of the replica disks are invalid.
 *		If so, it returns the diskname in the ctdptr.
 *	RETURN
 *		-1	Error
 *		cnt	number of invalid device id's
 */
int
mddb_getinvlb_devid(
	set_t	setno,
	int	count,
	int	size,
	char	**ctdptr
)
{
	mddb_set_t	*s;
	int		err = 0;
	mddb_lb_t	*lbp;
	int		li;
	mddb_did_blk_t	*did_blk;
	mddb_did_info_t	*did_info;
	int		len;
	int		cnt = 0;
	char		*cptr;
	md_name_suffix	*sn;
	int		i, dont_add_it;
	char		*tmpctd, *diskname;
	char		*tmpname;

	cptr = *ctdptr;
	if ((s = mddb_setenter(setno, MDDB_MUSTEXIST, &err)) == NULL) {
		return (-1);
	}

	single_thread_start(s);
	lbp = s->s_lbp;

	if (lbp->lb_setno != setno) {
		single_thread_end(s);
		mddb_setexit(s);
		return (-1);
	}

	/* check for lb being devid style */
	if (lbp->lb_flags & MDDB_DEVID_STYLE) {
		did_blk = s->s_did_icp->did_ic_blkp;
		for (li = 0; li < lbp->lb_loccnt; li++) {
			did_info = &(did_blk->blk_info[li]);
			/* Only if devid exists and isn't valid */
			if ((did_info->info_flags & MDDB_DID_EXISTS) &&
			    !(did_info->info_flags & MDDB_DID_VALID)) {
				/*
				 * if we count more invalid did's than
				 * was passed in there's an error somewhere
				 */
				if (cnt++ > count) {
					single_thread_end(s);
					mddb_setexit(s);
					return (-1);
				}

				/*
				 * Future note: Need to do something here
				 * for the MN diskset case when device ids
				 * are supported in disksets.
				 * Can't add until merging devids_in_diskset
				 * code into code base.
				 */

				sn = &s->s_lnp->ln_suffixes[0][li];
				/*
				 * check to make sure length of device name is
				 * not greater than computed first time through
				 */
				len = sn->suf_len;
				if (len > size) {
					single_thread_end(s);
					mddb_setexit(s);
					return (-1);
				}
				tmpctd = *ctdptr;
				/* strip off slice part */
				diskname = md_strdup(sn->suf_data);
				tmpname = strrchr(diskname, 's');
				*tmpname = '\0';
				dont_add_it = 0;
				/* look to see if diskname is already in list */
				for (i = 0; i < (cnt-1); i++) {
					if (strcmp(diskname, tmpctd) == 0) {
						/* already there, don't add */
						dont_add_it = 1;
						break;
					}
					/* point to next diskname in list */
					tmpctd += size;
				}
				if (dont_add_it == 0) {
					/* add diskname to list */
					(void) strcpy(cptr, diskname);
					cptr += size;
				}
				kmem_free(diskname, strlen(sn->suf_data) + 1);
			}
		}
	}
	/* null terminate the list */
	*cptr = '\0';
	/*
	 * need to save the new pointer so that calling routine can continue
	 * to add information onto the end.
	 */
	*ctdptr = cptr;
	single_thread_end(s);
	mddb_setexit(s);
	return (cnt);
}

/*
 * mddb_validate_lb - count the number of lb's with invalid device id's. Keep
 *		track of length of longest devicename.
 *	RETURN
 *		-1	error
 *		 cnt	number of lb's with invalid devid's
 */
int
mddb_validate_lb(
	set_t	setno,
	int	*rmaxsz
)
{
	mddb_set_t	*s;
	int		err = 0;
	mddb_lb_t	*lbp;
	int		li;
	mddb_did_blk_t	*did_blk;
	mddb_did_info_t	*did_info;
	int		len;
	int		cnt = 0;

	if ((s = mddb_setenter(setno, MDDB_MUSTEXIST, &err)) == NULL)
		return (-1);

	single_thread_start(s);
	lbp = s->s_lbp;

	if (lbp->lb_setno != setno) {
		single_thread_end(s);
		mddb_setexit(s);
		return (-1);
	}

	/* lb must be in devid style */
	if ((lbp->lb_flags & MDDB_DEVID_STYLE) == 0)
		goto mvl_out;

	did_blk = s->s_did_icp->did_ic_blkp;
	for (li = 0; li < lbp->lb_loccnt; li++) {
		char		*minor_name;
		mddb_locator_t	*lp;
		dev_t		ddi_dev;
		ddi_devid_t	devid;
		ddi_devid_t	rtn_devid = NULL;
		int		get_rval;

		did_info = &(did_blk->blk_info[li]);
		if (((did_info->info_flags & MDDB_DID_EXISTS) == 0) ||
		    (did_info->info_flags & MDDB_DID_VALID))
			continue;

		/* Here we know, did exists but isn't valid */

		lp = &lbp->lb_locators[li];
		ddi_dev = expldev(lp->l_dev);
		get_rval = mddb_devid_get(s, li, &devid, &minor_name);
		ASSERT(get_rval == 1);
		if ((ddi_lyr_get_devid(ddi_dev, &rtn_devid) == DDI_SUCCESS) &&
		    (ddi_devid_compare(rtn_devid, devid) == 0)) {
			did_info->info_flags = MDDB_DID_VALID |
			    MDDB_DID_EXISTS | MDDB_DID_UPDATED;
		} else {
			cnt++;
			/*
			 * Future note: Need to do something here
			 * for the MN diskset case when device ids
			 * are supported in disksets.
			 * Can't add until merging devids_in_diskset
			 * code into code base.
			 */
			len = (&s->s_lnp->ln_suffixes[0][li])-> suf_len;
			if (*rmaxsz < len)
				*rmaxsz = len;
		}
		if (rtn_devid != NULL)
			ddi_devid_free(rtn_devid);
	}

mvl_out:

	if (push_lb(s) != 0)
		cnt = -1;
	(void) upd_med(s, "mddb_validate_lb(0)");
	single_thread_end(s);
	mddb_setexit(s);
	return (cnt);
}

int
check_active_locators()
{
	mddb_set_t	*s;
	mddb_lb_t	*lbp;
	int		li;
	int		active = 0;

	mutex_enter(&mddb_lock);
	/* there is nothing here..so we can unload */
	if ((mddb_set_t *)md_set[MD_LOCAL_SET].s_db == NULL) {
		mutex_exit(&mddb_lock);
		return (0);
	}
	s = (mddb_set_t *)md_set[MD_LOCAL_SET].s_db;
	lbp = s->s_lbp;
	if (lbp == NULL) {
		mutex_exit(&mddb_lock);
		return (0);
	}

	for (li = 0; li < lbp->lb_loccnt; li++) {
		mddb_locator_t *lp = &lbp->lb_locators[li];
		if (lp->l_flags & MDDB_F_ACTIVE) {
			active = 1;
			break;
		}
	}
	mutex_exit(&mddb_lock);
	return (active);
}

/*
 * regetoptrecord:
 * --------------
 *	Update the in-core optimized resync record contents by re-reading the
 *	record from the on-disk metadb.
 *	The contents of the resync record will be overwritten by calling this
 *	routine. This means that callers that require the previous contents to
 *	be preserved must save the data before calling this routine.
 *	Return values:
 *	0 - successfully read in resync record from a mddb
 *	1 - failure.  Unable to read resync record from either mddb.
 */
static int
regetoptrecord(
	mddb_set_t	*s,
	mddb_de_ic_t	*dep
)
{
	mddb_lb_t	*lbp;
	mddb_locator_t	*lp;
	mddb_rb32_t	*rbp, *crbp;
	int		li;
	int		i;
	int		err = 0;
	size_t		recsize;

#if defined(_ILP32) && !defined(lint)
	ASSERT(sizeof (mddb_rb_t) == sizeof (mddb_rb32_t));
#endif

	recsize = dep->de_recsize;
	crbp = (mddb_rb32_t *)kmem_zalloc(recsize, KM_SLEEP);

	single_thread_start(s);
	rbp = dep->de_rb;

	dep->de_optinfo[0].o_flags |= MDDB_F_EDATA;
	dep->de_optinfo[1].o_flags |= MDDB_F_EDATA;

	lbp = s->s_lbp;

	for (i = 0; i < 2; i++) {
		if (! (dep->de_optinfo[i].o_flags & MDDB_F_ACTIVE))
			continue;
		li = dep->de_optinfo[i].o_li;
		lp = &lbp->lb_locators[li];

		if (! (lp->l_flags & MDDB_F_ACTIVE) ||
		    (lp->l_flags & MDDB_F_EMASTER))
			continue;

		/*
		 * re-read the optimized resync record with failfast set
		 * since a failed disk could lead to a very long wait.
		 */
		err = readblklst(s, (caddr_t)rbp, dep->de_blks,
		    dep->de_blkcount, li, B_FAILFAST);

		if (err)
			continue;

		if (rbp->rb_magic != MDDB_MAGIC_RB)
			continue;

		if (revchk(MDDB_REV_RB, rbp->rb_revision))
			continue;

		/* Check the crc for this record */
		if (rec_crcchk(s, dep, rbp)) {
			continue;
		}
		dep->de_optinfo[i].o_flags = MDDB_F_ACTIVE;

		if (rbp == crbp) {
			if (rbp->rb_checksum != crbp->rb_checksum)
				dep->de_optinfo[1].o_flags |= MDDB_F_EDATA;
			break;
		}
		rbp = crbp;
	}

	single_thread_end(s);

	if (rbp == crbp) {
		rbp->rb_private = 0;
		kmem_free((caddr_t)crbp, recsize);
		return (0);
	}
	uniqtime32(&rbp->rb_timestamp);
	/* Generate the crc for this record */
	rec_crcgen(s, dep, rbp);
	kmem_free((caddr_t)crbp, recsize);
	return (1);
}

/*
 * mddb_reread_rr:
 *	Re-read the resync record from the on-disk copy. This is required for
 *	multi-node support so that a new mirror-owner can determine if a resync
 *	operation is required to guarantee data integrity.
 *
 * Arguments:
 *	setno	Associated set
 *	id	Resync record ID
 *
 * Return Value:
 *	0	successful reread
 *	-1	invalid set (not multi-node or non-existant)
 *	>0	metadb state invalid, failed to reread
 */
int
mddb_reread_rr(
	set_t		setno,
	mddb_recid_t	id
)
{
	mddb_set_t	*s;
	int		err = 0;
	mddb_db_t	*dbp;
	mddb_de_ic_t	*dep;

	if (setno >= md_nsets)
		return (-1);

	if ((s = mddb_setenter(setno, MDDB_MUSTEXIST, &err)) == NULL)
		return (-1);

	if ((setno == MD_LOCAL_SET) || !(s->s_lbp->lb_flags & MDDB_MNSET)) {
		mddb_setexit(s);
		return (-1);
	}

	for (dbp = s->s_dbp; dbp != NULL; dbp = dbp->db_next) {
		dep = dbp->db_firstentry;
		while (dep && (dep->de_recid != DBID(id)))
			dep = dep->de_next;
		if (dep != NULL)
			break;
	}

	if (dep != NULL) {
		err = regetoptrecord(s, dep);
	} else {
		err = -1;
	}
	mddb_setexit(s);
	return (err);
}

/*
 * Set owner associated with MN optimized resync record.
 *
 * Optimized records have an owner node associated with them in
 * a MN diskset.  The owner is only set on a node that is actively
 * writing to that record.  The other nodes will show that record
 * as having an invalid owner.  The owner for an optimized record
 * is used during fixoptrecord to determine which node should
 * write out the record when the replicas associated with that
 * optimized record have been changed.
 *
 * Called directly from mirror driver and not from an ioctl.
 *
 * Returns
 *	NULL if successful.
 *	MDDB_E_NORECORD if record not found.
 */
int
mddb_setowner(
	mddb_recid_t		id,
	md_mn_nodeid_t		owner
)
{
	mddb_set_t		*s;
	mddb_db_t		*dbp;
	mddb_de_ic_t		*dep;
	int			found = 0;


	if (DBSET(id) >= md_nsets)
		return (MDDB_E_NORECORD);

	if ((s = mddb_setenter(DBSET(id), MDDB_MUSTEXIST, NULL)) == NULL)
		return (MDDB_E_NORECORD);

	id = DBID(id);
	for (dbp = s->s_dbp; dbp != NULL; dbp = dbp->db_next) {
		for (dep = dbp->db_firstentry;
		    dep != NULL; dep = dep->de_next) {
			if (dep->de_recid != id)
				continue;
			dep->de_owner_nodeid = owner;
			found = 1;
			break;
		}
		if (found)
			break;
	}

	mddb_setexit(s);

	if (!found) {
		return (MDDB_E_NORECORD);
	}

	return (NULL);
}

/*
 * mddb_parse re-reads portions of the mddb from disk given a list
 * of good replicas to read from and flags describing
 * which portion of the mddb to read in.
 *
 * Used in a MN diskset when the master has made a change to some part
 * of the mddb and wants to relay this information to the slaves.
 */
int
mddb_parse(mddb_parse_parm_t *mpp)
{
	mddb_set_t	*s;
	int		err = 0;
	mddb_locator_t	*lp, *old_lp;
	mddb_lb_t	*lbp, *old_lbp;
	int		rval = 0;
	int		i, li;
	int		found_good_one = 0;
	mddb_ln_t	*lnp;
	mddb_block_t	ln_blkcnt;
	md_error_t	*ep = &mpp->c_mde;

	if (mpp->c_setno >= md_nsets)
		return (EINVAL);

	if (md_snarf_db_set(MD_LOCAL_SET, ep) != 0)
		return (0);

	if ((s = mddb_setenter(mpp->c_setno, MDDB_MUSTEXIST, &err)) == NULL) {
		return (mddbstatus2error(ep, err, NODEV32, mpp->c_setno));
	}

	if (!(MD_MNSET_SETNO(mpp->c_setno))) {
		mddb_setexit_no_parse(s);
		return (EINVAL);
	}

	/*
	 * Master node initiated this request, so there's no work for
	 * the master node to do.
	 */
	if (md_set[mpp->c_setno].s_am_i_master) {
		mddb_setexit_no_parse(s);
		return (rval);
	}

	single_thread_start(s);

	if (mpp->c_parse_flags & MDDB_PARSE_LOCBLK) {
		lbp = 0;
		for (i = 0; i < MDDB_NLB; i++) {
			/* Walk through master's active list */
			if (!(mpp->c_lb_flags[i] & MDDB_F_ACTIVE))
				continue;
			if (s->s_mbiarray[i] == NULL)
				continue;

			/* Assumes master blocks are already setup */
			if (lbp == (mddb_lb_t *)NULL) {
				lbp = (mddb_lb_t *)kmem_zalloc(
				    dbtob(MDDB_MNLBCNT), KM_SLEEP);
			}
			err |= readblks(s, (caddr_t)lbp, 0, lbp->lb_blkcnt, i);

			if (err)
				continue;

			if (lbp->lb_magic != MDDB_MAGIC_LB)
				continue;
			if (lbp->lb_blkcnt != MDDB_MNLBCNT)
				continue;
			if (revchk(MDDB_REV_MNLB, lbp->lb_revision))
				continue;
			if (crcchk(lbp, &lbp->lb_checksum, dbtob(MDDB_MNLBCNT),
			    NULL))
				continue;
			if (lbp->lb_setno != s->s_setno)
				continue;
			/*
			 * a commit count of zero means this locator has
			 * been deleted
			 */
			if (lbp->lb_commitcnt == 0) {
				continue;
			}
			/* Found a good locator - keep it */
			found_good_one = 1;
			break;
		}

		/*
		 * If found a good copy of the mddb, then read it into
		 * this node's locator block.  Fix up the set's s_mbiarray
		 * pointer (master block incore array pointer) to be
		 * in sync with the newly read in locator block.  If a
		 * new mddb was added, read in the master blocks associated
		 * with the new mddb.  If an mddb was deleted, free the
		 * master blocks associated with deleted mddb.
		 */
		if (found_good_one)  {
			/* Compare old and new view of mddb locator blocks */
			old_lbp = s->s_lbp;
			for (li = 0; li < lbp->lb_loccnt; li++) {
				int	mn_set;

				lp = &lbp->lb_locators[li];
				old_lp = &old_lbp->lb_locators[li];

				/* If old and new views match, continue */
				if ((lp->l_flags & MDDB_F_ACTIVE) ==
				    (old_lp->l_flags & MDDB_F_ACTIVE))
					continue;

				if (lp->l_flags & MDDB_F_ACTIVE) {
					/*
					 * If new mddb has been added - delete
					 * old mbiarray and get new one.
					 *
					 * When devids are supported, will
					 * need to get dev from devid.
					 */
					if (s->s_mbiarray[li]) {
						free_mbipp(&s->s_mbiarray[li]);
					}
					/*
					 * If getmasters fails, getmasters
					 * will set appropriate error flags.
					 */
					s->s_mbiarray[li] = getmasters(s,
					    md_expldev(lp->l_dev), lp->l_blkno,
					    (uint_t *)&(lp->l_flags), &mn_set);
				} else if (lp->l_flags & MDDB_F_DELETED) {
					/*
					 * If old one has been deleted -
					 * delete old mbiarray.
					 */
					if (s->s_mbiarray[li]) {
						free_mbipp(&s->s_mbiarray[li]);
					}
				}
			}

			/* Free this node's old view of mddb locator blocks */
			kmem_free((caddr_t)s->s_lbp,
			    dbtob(s->s_lbp->lb_blkcnt));
			s->s_lbp = lbp;
		} else {
			if (lbp)
				kmem_free(lbp, dbtob(MDDB_MNLBCNT));
		}
	}

	if (mpp->c_parse_flags & MDDB_PARSE_LOCNM) {
		lnp = s->s_lnp;
		lbp = s->s_lbp;
		ln_blkcnt = lbp->lb_lnblkcnt;
		s->s_lnp = NULL; /* readlocnames does this anyway */
		for (li = 0; li < lbp->lb_loccnt; li++) {
			lp = &lbp->lb_locators[li];

			if ((! (lp->l_flags & MDDB_F_ACTIVE)) ||
			    (lp->l_flags & MDDB_F_EMASTER))
				continue;

			/* Successfully read the locator names */
			if (readlocnames(s, li) == 0)
				break;
		}

		if (li == lbp->lb_loccnt) {
			/* Did not successfully read locnames; restore lnp */
			s->s_lnp = lnp;
		} else {
			/* readlocnames successful, free old struct */
			kmem_free((caddr_t)lnp, dbtob(ln_blkcnt));
		}
	}

	if (mpp->c_parse_flags & MDDB_PARSE_OPTRECS) {
		mddb_de_ic_t	*dep, *tdep, *first_dep, *dep2;
		mddb_db_t	*dbp;
		mddb_db32_t	*db32p;
		mddb_de32_t	*de32p, *de32p2;
		int		writeout;

		lbp = s->s_lbp;
		/*
		 * Walk through directory block and directory entry incore
		 * linked list looking for optimized resync records.
		 * For each opt record found, re-read in directory block.
		 * The directoy block consists of a number of directory
		 * entries.  The directory entry for this opt record will
		 * describe which 2 mddbs actually contain the resync record
		 * since it could have been relocated by the master node
		 * due to mddb failure or mddb deletion.  If this node
		 * is the record owner for this opt record, then write out
		 * the record to the 2 mddbs listed in the directory entry
		 * if the mddbs locations are different than previously known.
		 */
		for (dbp = s->s_dbp; dbp != NULL; dbp = dbp->db_next) {
			for (dep = dbp->db_firstentry; dep;
			    dep = dep->de_next) {
				/* Found an opt record */
				if (dep->de_flags & MDDB_F_OPT)
					break;
			}
			/* If no opt records found, go to next dbp */
			if (dep == NULL)
				continue;

			/*
			 * Reread directory block from disk since
			 * master could have rewritten in during fixoptrecord.
			 */
			db32p = (mddb_db32_t *)kmem_zalloc(MDDB_BSIZE,
			    KM_SLEEP);
			create_db32rec(db32p, dbp);
			for (li = 0; li < lbp->lb_loccnt; li++) {
				lp = &lbp->lb_locators[li];

				if ((! (lp->l_flags & MDDB_F_ACTIVE)) ||
				    (lp->l_flags & MDDB_F_EMASTER))
					continue;

				err = readblks(s, (caddr_t)db32p,
				    db32p->db32_blknum, 1, li);
				if (err)
					continue;

				/* Reverify db; go to next mddb if bad */
				if ((db32p->db32_magic != MDDB_MAGIC_DB) ||
				    (revchk(MDDB_REV_DB,
				    db32p->db32_revision)) ||
				    (crcchk(db32p, &db32p->db32_checksum,
				    MDDB_BSIZE, NULL))) {
					continue;
				} else {
					break;
				}
			}
			/*
			 * If all mddbs are unavailable then panic since
			 * this slave cannot be allowed to continue out-of-sync
			 * with the master node.  Since the optimized resync
			 * records are written by all nodes, all nodes must
			 * stay in sync with the master.
			 *
			 * This also handles the case when all storage
			 * connectivity to a slave node has failed.  The
			 * slave node will send an MDDB_OPTRECERR message to
			 * the master node when the slave node has been unable
			 * to write an optimized resync record to both
			 * designated mddbs.  After the master has fixed the
			 * optimized records to be on available mddbs, the
			 * MDDB_PARSE message (with the flag MDDB_PARSE_OPTRECS)
			 * is sent to all slave nodes.  If a slave node is
			 * unable to access any mddb in order to read in the
			 * relocated optimized resync record, then the slave
			 * node must panic.
			 */
			if (li == lbp->lb_loccnt) {
				kmem_free((caddr_t)db32p, MDDB_BSIZE);
				cmn_err(CE_PANIC, "md: mddb: Node unable to "
				    "access any SVM state database "
				    "replicas for diskset %s\n", s->s_setname);
			}
			/*
			 * Setup temp copy of linked list of de's.
			 * Already have an incore copy, but need to walk
			 * the directory entry list contained in the
			 * new directory block that was just read in above.
			 * After finding the directory entry of an opt record
			 * by walking the incore list, find the corresponding
			 * entry in the temporary list and then update
			 * the incore directory entry record with
			 * the (possibly changed) mddb location stored
			 * for the optimized resync records.
			 */
			de32p = (mddb_de32_t *)
			    ((void *) ((caddr_t)
			    (&db32p->db32_firstentry)
			    + sizeof (db32p->db32_firstentry)));
			tdep = (mddb_de_ic_t *)
			    kmem_zalloc(sizeof (mddb_de_ic_t) -
			    sizeof (mddb_block_t) +
			    sizeof (mddb_block_t) *
			    de32p->de32_blkcount, KM_SLEEP);
			de32tode(de32p, tdep);
			first_dep = tdep;
			while (de32p && de32p->de32_next) {
				de32p2 = nextentry(de32p);
				dep2 = (mddb_de_ic_t *)kmem_zalloc(
				    sizeof (mddb_de_ic_t) -
				    sizeof (mddb_block_t) +
				    sizeof (mddb_block_t) *
				    de32p2->de32_blkcount, KM_SLEEP);
				de32tode(de32p2, dep2);
				tdep->de_next = dep2;
				tdep = dep2;
				de32p = de32p2;
			}

			/* Now, walk the incore directory entry list */
			for (dep = dbp->db_firstentry; dep;
			    dep = dep->de_next) {
				if (! (dep->de_flags & MDDB_F_OPT))
					continue;
				/*
				 * Found an opt record in the incore copy.
				 * Find the corresponding entry in the temp
				 * list.  If anything has changed in the
				 * opt record info between the incore copy
				 * and the temp copy, update the incore copy
				 * and set a flag to writeout the opt record
				 * to the new mddb locations.
				 */
				for (tdep = first_dep; tdep;
				    tdep = tdep->de_next) {
					if (dep->de_recid == tdep->de_recid) {
					    writeout = 0;
					    /* Check first mddb location */
					    if ((dep->de_optinfo[0].o_li !=
						tdep->de_optinfo[0].o_li) ||
						(dep->de_optinfo[0].o_flags !=
						tdep->de_optinfo[0].o_flags)) {
						    dep->de_optinfo[0] =
						    tdep->de_optinfo[0];
						    writeout = 1;
					    }
					    /* Check second mddb location */
					    if ((dep->de_optinfo[1].o_li !=
						tdep->de_optinfo[1].o_li) ||
						(dep->de_optinfo[1].o_flags !=
						tdep->de_optinfo[1].o_flags)) {
						    dep->de_optinfo[1] =
						    tdep->de_optinfo[1];
						    writeout = 1;
					    }
					    /* Record owner should rewrite it */
					    if ((writeout) &&
						(dep->de_owner_nodeid ==
						md_set[mpp->c_setno].
						s_nodeid)) {
						    (void) writeoptrecord(s,
							dep);
					    }
					    break;
					}
				}
			}
			/*
			 * Update the incore checksum information for this
			 * directory block to match the newly read in checksum.
			 * This should have only changed if the incore and
			 * temp directory entries differed, but it takes
			 * more code to do the check than to just update
			 * the information everytime.
			 */
			dbp->db_checksum = db32p->db32_checksum;

			/* Now free everything */
			tdep = first_dep;
			while (tdep) {
				dep2 = tdep->de_next;
				kmem_free((caddr_t)tdep,
				    sizeofde(tdep));
				tdep = dep2;
			}
			kmem_free((caddr_t)db32p, MDDB_BSIZE);
		}
		rval = 0;
	}
out:
	single_thread_end(s);
	mddb_setexit_no_parse(s);
	return (rval);
}

int
mddb_block(mddb_block_parm_t *mbp)
{
	mddb_set_t	*s;
	int		err = 0;
	md_error_t	*ep = &mbp->c_mde;

	if (mbp->c_setno >= md_nsets)
		return (EINVAL);

	/*
	 * If the new_master flag is set for this setno we are in the middle
	 * of a reconfig cycle, and blocking or unblocking is not needed.
	 * Hence we can return success immediately
	 */
	if (md_get_setstatus(mbp->c_setno) & MD_SET_MN_NEWMAS_RC) {
		return (0);
	}

	if (md_snarf_db_set(MD_LOCAL_SET, ep) != 0)
		return (0);

	if ((s = mddb_setenter(mbp->c_setno, MDDB_MUSTEXIST, &err)) == NULL) {
		return (mddbstatus2error(ep, err, NODEV32, mbp->c_setno));
	}

	if (!(MD_MNSET_SETNO(mbp->c_setno))) {
		mddb_setexit_no_parse(s);
		return (EINVAL);
	}

	single_thread_start(s);

	if (mbp->c_blk_flags & MDDB_BLOCK_PARSE)
		md_set_setstatus(mbp->c_setno, MD_SET_MNPARSE_BLK);

	if (mbp->c_blk_flags & MDDB_UNBLOCK_PARSE)
		md_clr_setstatus(mbp->c_setno, MD_SET_MNPARSE_BLK);

	single_thread_end(s);
	mddb_setexit_no_parse(s);
	return (err);
}

/*
 * mddb_optrecfix marks up to 2 mddbs as failed and calls fixoptrecords
 * to relocate any optimized resync records to available mddbs.
 * This routine is only called on the master node.
 *
 * Used in a MN diskset when a slave node has failed to write an optimized
 * resync record.  The failed mddb information is sent to the master node
 * so the master can relocate the optimized records, if possible.  If the
 * failed mddb information has a mddb marked as failed that was previously
 * marked active on the master, the master sets its incore mddb state to
 * EWRITE and sets the PARSE_LOCBLK flag.  The master node then attempts
 * to relocate any optimized records on the newly failed mddbs by calling
 * fixoptrecords.  (fixoptrecords will set the PARSE_OPTRECS flag if any
 * optimized records are relocated.)
 *
 * When mddb_optrecfix is finished, the ioctl exit code will notice the PARSE
 * flags and will send a PARSE message to the slave nodes.  The PARSE_LOCBLK
 * flag causes the slave node to re-read in the locator block from disk.
 * The PARSE_OPTRECS flag causes the slave node to re-read in the directory
 * blocks and write out any optimized resync records that have been
 * relocated to a different mddb.
 */
int
mddb_optrecfix(mddb_optrec_parm_t *mop)
{
	mddb_set_t		*s;
	int			err = 0;
	mddb_lb_t		*lbp;
	mddb_mnlb_t		*mnlbp;
	mddb_locator_t		*lp;
	int			li;
	mddb_mnsidelocator_t	*mnslp;
	mddb_drvnm_t		*dn;
	int			i, j;
	md_replica_recerr_t	*recerr;
	md_error_t		*ep = &mop->c_mde;
	int			something_changed = 0;
	int			alc, lc;
	int			setno;

	setno = mop->c_setno;
	if (mop->c_setno >= md_nsets)
		return (EINVAL);

	if (md_snarf_db_set(MD_LOCAL_SET, ep) != 0)
		return (0);

	if ((s = mddb_setenter(mop->c_setno, MDDB_MUSTEXIST, &err)) == NULL) {
		return (mddbstatus2error(ep, err, NODEV32, mop->c_setno));
	}

	if (!(MD_MNSET_SETNO(mop->c_setno))) {
		mddb_setexit(s);
		return (EINVAL);
	}

	single_thread_start(s);
	lbp = s->s_lbp;
	mnlbp = (mddb_mnlb_t *)lbp;

	/*
	 * If slave node has seen an mddb failure, but the master node
	 * hasn't encountered this failure, mark the mddb as failed on
	 * the master node and set the something_changed flag to 1.
	 */
	for (i = 0; i < 2; i++) {
		recerr = &mop->c_recerr[i];
		if (recerr->r_flags & MDDB_F_EWRITE) {
			li = recerr->r_li;
			lp = &lbp->lb_locators[li];
			for (j = 0; j < MD_MNMAXSIDES; j++) {
				mnslp = &mnlbp->lb_mnsidelocators[j][li];
				if (mnslp->mnl_sideno == s->s_sideno)
					break;
			}
			/* Do quick check using li */
			if (j != MD_MNMAXSIDES)
				dn = &lbp->lb_drvnm[mnslp->mnl_drvnm_index];

			if ((j != MD_MNMAXSIDES) &&
			    (strncmp(dn->dn_data, recerr->r_driver_name,
			    MD_MAXDRVNM) == 0) &&
			    (recerr->r_blkno == lp->l_blkno) &&
			    (recerr->r_mnum == mnslp->mnl_mnum)) {
				if ((lp->l_flags & MDDB_F_ACTIVE) ||
				    ((lp->l_flags & MDDB_F_EWRITE) == 0)) {
					something_changed = 1;
					lp->l_flags |= MDDB_F_EWRITE;
					lp->l_flags &= ~MDDB_F_ACTIVE;
				}
			} else {
				/*
				 * Passed in li from slave does not match
				 * the replica in the master's structures.
				 * This could have occurred if a delete
				 * mddb command was running when the
				 * optimized resync record had a failure.
				 * Search all replicas for this entry.
				 * If no match, just ignore.
				 * If a match, set replica in error.
				 */
				for (li = 0; li < lbp->lb_loccnt; li++) {
					lp = &lbp->lb_locators[li];
					if (lp->l_flags & MDDB_F_DELETED)
						continue;

					for (j = 0; j < MD_MNMAXSIDES; j++) {
						mnslp =
						    &mnlbp->
						    lb_mnsidelocators[j][li];
						if (mnslp->mnl_sideno ==
						    s->s_sideno)
							break;
					}
					if (j == MD_MNMAXSIDES)
						continue;

					dn = &lbp->
					    lb_drvnm[mnslp->mnl_drvnm_index];
					if ((strncmp(dn->dn_data,
					    recerr->r_driver_name,
					    MD_MAXDRVNM) == 0) &&
					    (recerr->r_blkno == lp->l_blkno) &&
					    (recerr->r_mnum ==
					    mnslp->mnl_mnum)) {
						if ((lp->l_flags &
						    MDDB_F_ACTIVE) ||
						    ((lp->l_flags &
						    MDDB_F_EWRITE) == 0)) {
							something_changed = 1;
							lp->l_flags |=
							    MDDB_F_EWRITE;
							lp->l_flags &=
							    ~MDDB_F_ACTIVE;
						}
						break;
					}
				}
			}
		}
	}

	/*
	 * If this message changed nothing, then we're done since this
	 * failure has already been handled.
	 * If some mddb state has been changed, send a parse message to
	 * the slave nodes so that the slaves will re-read the locator
	 * block from disk.
	 */
	if (something_changed == 0) {
		single_thread_end(s);
		mddb_setexit(s);
		return (0);
	} else {
		s->s_mn_parseflags |= MDDB_PARSE_LOCBLK;
	}

	/*
	 * Scan replicas setting MD_SET_TOOFEW if
	 * 50% or more of the mddbs have seen errors.
	 * Note: Don't call selectreplicas or writeretry
	 * since these routines may end up setting the ACTIVE flag
	 * on a failed mddb if the master is able to access the mddb
	 * but the slave node couldn't.  Need to have the ACTIVE flag
	 * turned off in order to relocate the optimized records to
	 * mddbs that are (hopefully) available on all nodes.
	 */
	alc = 0;
	lc = 0;
	for (li = 0; li < lbp->lb_loccnt; li++) {
		lp = &lbp->lb_locators[li];
		if (lp->l_flags & MDDB_F_DELETED)
			continue;
		lc++;
		if (! (lp->l_flags & MDDB_F_ACTIVE))
			continue;
		alc++;
	}

	/*
	 * If more than 50% mddbs have failed, then don't relocate opt recs.
	 * The node sending the mddb failure information will detect TOOFEW
	 * and will panic when it attempts to re-write the optimized record.
	 */
	if (alc < ((lc + 1) / 2)) {
		md_set_setstatus(setno, MD_SET_TOOFEW);
		(void) push_lb(s);
		(void) upd_med(s, "mddb_optrecfix(0)");
		single_thread_end(s);
		mddb_setexit(s);
		return (0);
	}

	/* Attempt to relocate optimized records that are on failed mddbs */
	(void) fixoptrecords(s);

	/* Push changed locator block out to disk */
	(void) push_lb(s);
	(void) upd_med(s, "mddb_optrecfix(1)");

	/* Recheck for TOOFEW after writing out locator blocks */
	alc = 0;
	lc = 0;
	for (li = 0; li < lbp->lb_loccnt; li++) {
		lp = &lbp->lb_locators[li];
		if (lp->l_flags & MDDB_F_DELETED)
			continue;
		lc++;
		if (! (lp->l_flags & MDDB_F_ACTIVE))
			continue;
		alc++;
	}

	/* If more than 50% mddbs have failed, then don't relocate opt recs */
	if (alc < ((lc + 1) / 2)) {
		md_set_setstatus(setno, MD_SET_TOOFEW);
		single_thread_end(s);
		mddb_setexit(s);
		return (0);
	}

	single_thread_end(s);
	mddb_setexit(s);
	return (0);
}

/*
 * Check if incore mddb on master node matches ondisk mddb.
 * If not, master writes out incore view to all mddbs.
 * Have previously verified that master is an owner of the
 * diskset (master has snarfed diskset) and that diskset is
 * not stale.
 *
 * Meant to be called during reconfig cycle during change of master.
 * Previous master in diskset may have changed the mddb and
 * panic'd before relaying information to slave nodes.  New
 * master node just writes out its incore view of the mddb and
 * the replay of the change log will resync all the nodes.
 *
 * Only supported for MN disksets.
 *
 * Return values:
 *	0 - success
 *	non-zero - failure
 */
int
mddb_check_write_ioctl(mddb_config_t *info)
{
	int			err = 0;
	set_t			setno = info->c_setno;
	mddb_set_t		*s;
	int			li;
	mddb_locator_t		*lp;
	mddb_lb_t		*lbp;
	mddb_mnlb_t		*mnlbp_od;
	mddb_ln_t		*lnp;
	mddb_mnln_t		*mnlnp_od;
	mddb_db_t		*dbp;
	mddb_de_ic_t		*dep;
	int			write_out_mddb;
	md_error_t		*ep = &info->c_mde;
	int			mddb_err = 0;
	int			prev_li = 0;
	int			rval = 0;
	int			alc, lc;
	int			mddbs_present = 0;

	/* Verify that setno is in valid range */
	if (setno >= md_nsets)
		return (EINVAL);

	if (md_snarf_db_set(MD_LOCAL_SET, ep) != 0)
		return (0);

	if ((s = mddb_setenter(setno, MDDB_MUSTEXIST, &err)) == NULL) {
		return (mddbstatus2error(ep, err, NODEV32, setno));
	}

	/* Calling diskset must be a MN diskset */
	if (!(MD_MNSET_SETNO(setno))) {
		mddb_setexit(s);
		return (EINVAL);
	}

	/* Re-verify that set is not stale */
	if (md_get_setstatus(setno) & MD_SET_STALE) {
		mddb_setexit(s);
		return (mdmddberror(ep, MDE_DB_STALE, NODEV32, setno));
	}

	lbp = s->s_lbp;
	lnp = s->s_lnp;

	/*
	 * Previous master could have died during the write of data to
	 * the mddbs so that the ondisk mddbs may not be consistent.
	 * So, need to check the contents of the first and last active mddb
	 * to see if the mddbs need to be rewritten.
	 */
	for (li = 0; li < lbp->lb_loccnt; li++) {
		int	checkcopy_err;

		lp = &lbp->lb_locators[li];
		/* Find replica that is active */
		if (lp->l_flags & MDDB_F_DELETED)
			continue;
		mddbs_present = 1;
		if (! (lp->l_flags & MDDB_F_ACTIVE))
			continue;
		if (s->s_mbiarray[li] == NULL)
			continue;
		/* Check locator block */
		mnlbp_od = (mddb_mnlb_t *)kmem_zalloc(dbtob(MDDB_MNLBCNT),
		    KM_SLEEP);
		/* read in on-disk locator block */
		err = readblks(s, (caddr_t)mnlbp_od, 0, lbp->lb_blkcnt, li);

		/* If err, try next mddb */
		if (err) {
			kmem_free(mnlbp_od, dbtob(MDDB_MNLBCNT));
			continue;
		}

		/*
		 * We resnarf all changelog entries for this set.
		 * They may have been altered by the previous master
		 */
		for (dbp = s->s_dbp; dbp != NULL; dbp = dbp->db_next) {
			for (dep = dbp->db_firstentry; dep; dep =
			    dep->de_next) {
				if ((dep->de_flags & MDDB_F_CHANGELOG) == 0) {
					continue;
				}
				/*
				 * This has been alloc'ed while
				 * joining the set
				 */
				if (dep->de_rb) {
					kmem_free(dep->de_rb, dep->de_recsize);
					dep->de_rb = (mddb_rb32_t *)NULL;
				}
				if (dep->de_rb_userdata) {
					kmem_free(dep->de_rb_userdata,
					    dep->de_reqsize);
					dep->de_rb_userdata = (caddr_t)NULL;
				}

				err = getrecord(s, dep, li);
				if (err) {
					/*
					 * When we see on error while reading
					 * the changelog entries, we move on
					 * to the next mddb
					 */
					err = 1;
					break; /* out of inner for-loop */
				}
				allocuserdata(dep);
			}
			if (err)
				break; /* out of outer for-loop */
		}

		/* If err, try next mddb */
		if (err) {
			kmem_free(mnlbp_od, dbtob(MDDB_MNLBCNT));
			continue;
		}

		/* Is incore locator block same as ondisk? */
		if (bcmp((mddb_mnlb_t *)lbp, mnlbp_od, dbtob(MDDB_MNLBCNT))
		    == 1) {
			write_out_mddb = 1;
			kmem_free((caddr_t)mnlbp_od, dbtob(MDDB_MNLBCNT));
			break;
		}

		kmem_free((caddr_t)mnlbp_od, dbtob(MDDB_MNLBCNT));

		/* If lb ok, check locator names */
		mnlnp_od = (mddb_mnln_t *)kmem_zalloc(dbtob(MDDB_MNLNCNT),
		    KM_SLEEP);
		/* read in on-disk locator names */
		err = readblks(s, (caddr_t)mnlnp_od, lbp->lb_lnfirstblk,
		    lbp->lb_lnblkcnt, li);

		/* If err, try next mddb */
		if (err) {
			kmem_free(mnlnp_od, dbtob(MDDB_MNLNCNT));
			continue;
		}

		/* Are incore locator names same as ondisk? */
		if (bcmp((mddb_mnln_t *)lnp, mnlnp_od, dbtob(MDDB_MNLNCNT))
		    == 1) {
			kmem_free((caddr_t)mnlnp_od, dbtob(MDDB_MNLNCNT));
			write_out_mddb = 1;
			break;
		}

		kmem_free((caddr_t)mnlnp_od, dbtob(MDDB_MNLNCNT));

		/*
		 * Check records in mddb.
		 * If a read error is encountered, set the error flag and
		 * continue to the next mddb.  Otherwise, if incore data is
		 * different from ondisk, then set the flag to write out
		 * the mddb and break out.
		 */
		checkcopy_err = checkcopy(s, li);
		if (checkcopy_err == MDDB_F_EREAD) {
			lp->l_flags |= MDDB_F_EREAD;
			mddb_err = 1;
			continue;
		} else if (checkcopy_err == 1) {
			write_out_mddb = 1;
			break;
		}
		/*
		 * Have found first active mddb and the data is the same as
		 * incore - break out of loop
		 */
		write_out_mddb = 0;
		break;
	}

	/*
	 * Skip checking for last active mddb if:
	 *	- already found a mismatch in the first active mddb
	 *		(write_out_mddb is 1)  OR
	 * 	- didn't find a readable mddb when looking for first
	 *	  active mddb (there are mddbs present but all failed
	 *	  when read was attempted).
	 *
	 * In either case, go to write_out_mddb label in order to attempt
	 * to write out the data. If < 50% mddbs are available, panic.
	 */
	if ((write_out_mddb == 1) ||
	    ((li == lbp->lb_loccnt) && mddbs_present)) {
		write_out_mddb = 1;
		goto write_out_mddb;
	}

	/*
	 * Save which index was checked for the first active mddb.  If only 1
	 * active mddb, don't want to recheck the same mddb when looking for
	 * last active mddb.
	 */
	prev_li = li;

	/*
	 * Now, checking for last active mddb.  If found same index as before
	 * (only 1 active mddb), then skip.
	 */
	for (li = (lbp->lb_loccnt - 1); li >= 0; li--) {
		int	checkcopy_err;

		lp = &lbp->lb_locators[li];
		/* Find replica that is active */
		if (! (lp->l_flags & MDDB_F_ACTIVE))
			continue;
		if (lp->l_flags & MDDB_F_DELETED)
			continue;
		if (s->s_mbiarray[li] == NULL)
			continue;
		/* If already checked mddb, bail out */
		if (li == prev_li)
			break;
		/* Check locator block */
		mnlbp_od = (mddb_mnlb_t *)kmem_zalloc(dbtob(MDDB_MNLBCNT),
		    KM_SLEEP);
		/* read in on-disk locator block */
		err = readblks(s, (caddr_t)mnlbp_od, 0, lbp->lb_blkcnt, li);

		/* If err, try next mddb */
		if (err) {
			kmem_free(mnlbp_od, dbtob(MDDB_MNLBCNT));
			continue;
		}


		/* Is incore locator block same as ondisk? */
		if (bcmp((mddb_mnlb_t *)lbp, mnlbp_od, dbtob(MDDB_MNLBCNT))
		    == 1) {
			kmem_free((caddr_t)mnlbp_od, dbtob(MDDB_MNLBCNT));
			write_out_mddb = 1;
			break;
		}

		kmem_free((caddr_t)mnlbp_od, dbtob(MDDB_MNLBCNT));

		/* If lb ok, check locator names */
		mnlnp_od = (mddb_mnln_t *)
		    kmem_zalloc(dbtob(MDDB_MNLNCNT), KM_SLEEP);

		/* read in on-disk locator names */
		err = readblks(s, (caddr_t)mnlnp_od, lbp->lb_lnfirstblk,
		    lbp->lb_lnblkcnt, li);

		/* If err, try next mddb */
		if (err) {
			kmem_free(mnlnp_od, dbtob(MDDB_MNLNCNT));
			continue;
		}

		/* Are incore locator names same as ondisk? */
		if (bcmp((mddb_mnln_t *)lnp, mnlnp_od, dbtob(MDDB_MNLNCNT))
		    == 1) {
			kmem_free((caddr_t)mnlnp_od, dbtob(MDDB_MNLNCNT));
			write_out_mddb = 1;
			break;
		}

		kmem_free((caddr_t)mnlnp_od, dbtob(MDDB_MNLNCNT));

		/*
		 * Check records in mddb.
		 * If a read error is encountered, set the error flag and
		 * continue to the next mddb.  Otherwise, if incore data is
		 * different from ondisk, then set the flag to write out
		 * the mddb and break out.
		 */
		checkcopy_err = checkcopy(s, li);
		if (checkcopy_err == MDDB_F_EREAD) {
			lp->l_flags |= MDDB_F_EREAD;
			mddb_err = 1;
			continue;
		} else if (checkcopy_err == 1) {
			write_out_mddb = 1;
			break;
		}
		/*
		 * Have found last active mddb and the data is the same as
		 * incore - break out of loop
		 */
		write_out_mddb = 0;
		break;
	}

	/*
	 * If ondisk and incore versions of the mddb don't match, then
	 * write out this node's incore version to disk.
	 * Or, if unable to read a copy of the mddb, attempt to write
	 * out a new one.
	 */
write_out_mddb:
	if (write_out_mddb) {
		/* Recompute free blocks based on incore information */
		computefreeblks(s); /* set up free block bits */

		/*
		 * Write directory entries and record blocks.
		 * Use flag MDDB_WRITECOPY_SYNC so that writecopy
		 * routine won't write out change log records.
		 */
		for (li = 0; li < lbp->lb_loccnt; li++) {
			lp = &lbp->lb_locators[li];
			/* Don't write to inactive or deleted mddbs */
			if (! (lp->l_flags & MDDB_F_ACTIVE))
				continue;
			if (lp->l_flags & MDDB_F_DELETED)
				continue;
			if (s->s_mbiarray[li] == NULL)
				continue;
			/* If encounter a write error, save it for later */
			if (writecopy(s, li, MDDB_WRITECOPY_SYNC)) {
				lp->l_flags |= MDDB_F_EWRITE;
				mddb_err = 1;
			}
		}

		/*
		 * Write out locator blocks to all replicas.
		 * push_lb will set MDDB_F_EWRITE on replicas that fail.
		 */
		if (push_lb(s))
			mddb_err = 1;
		(void) upd_med(s, "mddb_check_write_ioctl(0)");

		/* Write out locator names to all replicas */
		lnp = s->s_lnp;
		uniqtime32(&lnp->ln_timestamp);
		lnp->ln_revision = MDDB_REV_MNLN;
		crcgen(lnp, &lnp->ln_checksum, dbtob(lbp->lb_lnblkcnt), NULL);

		/* writeall sets MDDB_F_EWRITE if writes fails to replica */
		if (writeall(s, (caddr_t)lnp, lbp->lb_lnfirstblk,
		    lbp->lb_lnblkcnt, 0))
			mddb_err = 1;

		/*
		 * The writes to the replicas above would have set
		 * the MDDB_F_EWRITE flags if any write error was
		 * encountered.
		 * If < 50% of the mddbs are available, panic.
		 */
		lc = alc = 0;
		for (li = 0; li < lbp->lb_loccnt; li++) {
			lp = &lbp->lb_locators[li];
			if (lp->l_flags & MDDB_F_DELETED)
				continue;
			lc++;
			/*
			 * If mddb:
			 *	- is not active (previously had an error)
			 *	- had an error reading the master blocks  or
			 *	- had an error in writing to the mddb
			 * then don't count this mddb in the active count.
			 */
			if (! (lp->l_flags & MDDB_F_ACTIVE) ||
			    (lp->l_flags & MDDB_F_EMASTER) ||
			    (lp->l_flags & MDDB_F_EWRITE))
				continue;
			alc++;
		}
		if (alc < ((lc + 1) / 2)) {
			cmn_err(CE_PANIC,
			    "md: Panic due to lack of DiskSuite state\n"
			    " database replicas. Fewer than 50%% of "
			    "the total were available,\n so panic to "
			    "ensure data integrity.");
		}
	}

	/*
	 * If encountered an error during checking or writing of
	 * mddbs, call selectreplicas so that replica error can
	 * be properly handled. This will involve another attempt
	 * to write the mddb out to any mddb marked MDDB_F_EWRITE.
	 * If mddb still fails, it will have the MDDB_F_ACTIVE bit
	 * turned off. Set the MDDB_SCANALLSYNC flag so that
	 * selectreplicas doesn't overwrite the change log entries.
	 *
	 * Set the PARSE_LOCBLK flag in the mddb_set structure to show
	 * that the locator block has been changed.
	 */
	if (mddb_err) {
		(void) selectreplicas(s, MDDB_SCANALLSYNC);
		s->s_mn_parseflags |= MDDB_PARSE_LOCBLK;
	}

write_out_end:
	mddb_setexit(s);
	return (rval);
}

/*
 * Set/reset/get set flags in set structure.
 * Used during reconfig cycle
 * Only supported for MN disksets.
 *
 * Return values:
 *	0 - success
 *	non-zero - failure
 */
int
mddb_setflags_ioctl(mddb_setflags_config_t *info)
{
	set_t			setno = info->sf_setno;

	/* Verify that setno is in valid range */
	if (setno >= md_nsets)
		return (EINVAL);

	/*
	 * When setting the flags, the set may not
	 * be snarfed yet. So, don't check for SNARFED or MNset
	 * and don't call mddb_setenter.
	 * In order to discourage bad ioctl calls,
	 * verify that magic field in structure is set correctly.
	 */
	if (info->sf_magic != MDDB_SETFLAGS_MAGIC)
		return (EINVAL);

	switch (info->sf_flags) {
	case MDDB_NM_SET:
		if (info->sf_setflags & MD_SET_MN_NEWMAS_RC)
			md_set_setstatus(setno, MD_SET_MN_NEWMAS_RC);
		if (info->sf_setflags & MD_SET_MN_START_RC)
			md_set_setstatus(setno, MD_SET_MN_START_RC);
		if (info->sf_setflags & MD_SET_MN_MIR_STATE_RC)
			md_set_setstatus(setno, MD_SET_MN_MIR_STATE_RC);
		break;

	case MDDB_NM_RESET:
		if (info->sf_setflags & MD_SET_MN_NEWMAS_RC)
			md_clr_setstatus(setno, MD_SET_MN_NEWMAS_RC);
		if (info->sf_setflags & MD_SET_MN_START_RC)
			md_clr_setstatus(setno, MD_SET_MN_START_RC);
		if (info->sf_setflags & MD_SET_MN_MIR_STATE_RC)
			md_clr_setstatus(setno, MD_SET_MN_MIR_STATE_RC);
		break;

	case MDDB_NM_GET:
		info->sf_setflags = md_get_setstatus(setno) &
		    (MD_SET_MN_NEWMAS_RC|MD_SET_MN_START_RC|
		    MD_SET_MN_MIR_STATE_RC);
		break;
	}

	return (0);
}

/*
 * md_update_minor
 *
 * This function updates the minor in the namespace entry for an
 * underlying metadevice.  The function is called in mod_imp_set
 * where mod is sp, stripe, mirror and raid.
 *
 */
int
md_update_minor(
	set_t	setno,
	side_t	side,
	mdkey_t	key
)
{
	struct nm_next_hdr	*nh;
	struct nm_name		*n;
	char			*shn;
	int			retval = 1;

	/*
	 * Load the devid name space if it exists
	 */
	(void) md_load_namespace(setno, NULL, NM_DEVID);
	if (! md_load_namespace(setno, NULL, 0L)) {
		/*
		 * Unload the devid namespace
		 */
		(void) md_unload_namespace(setno, NM_DEVID);
		return (0);
	}

	rw_enter(&nm_lock.lock, RW_READER);

	if ((nh = get_first_record(setno, 0, NM_NOTSHARED)) == NULL) {
		retval = 0;
		goto out;
	}

	/*
	 * Look up the key
	 */
	if ((n = lookup_entry(nh, setno, side, key, NODEV64, 0L)) != NULL) {
		/*
		 * Find the entry, update its n_minor if metadevice
		 */
		if ((shn = (char *)getshared_name(setno, n->n_drv_key, 0L))
		    == NULL) {
			retval = 0;
			goto out;
		}

		if (strcmp(shn, "md") == 0) {
			n->n_minor = MD_MKMIN(setno, MD_MIN2UNIT(n->n_minor));
		}
	}

out:
	rw_exit(&nm_lock.lock);
	return (retval);
}

/*
 * md_update_top_device_minor
 *
 * This function updates the minor in the namespace entry for a top
 * level metadevice.  The function is called in mod_imp_set where
 * mod is sp, stripe, mirror and raid.
 *
 */
int
md_update_top_device_minor(
	set_t	setno,
	side_t	side,
	md_dev64_t dev
)
{
	struct nm_next_hdr	*nh;
	struct nm_name		*n;
	char			*shn;
	int			retval = 1;

	/*
	 * Load the devid name space if it exists
	 */
	(void) md_load_namespace(setno, NULL, NM_DEVID);
	if (! md_load_namespace(setno, NULL, 0L)) {
		/*
		 * Unload the devid namespace
		 */
		(void) md_unload_namespace(setno, NM_DEVID);
		return (0);
	}

	rw_enter(&nm_lock.lock, RW_READER);

	if ((nh = get_first_record(setno, 0, NM_NOTSHARED)) == NULL) {
		retval = 0;
		goto out;
	}

	/*
	 * Look up the key
	 */
	if ((n = lookup_entry(nh, setno, side, MD_KEYWILD, dev, 0L)) != NULL) {
		/*
		 * Find the entry, update its n_minor if metadevice
		 */
		if ((shn = (char *)getshared_name(setno, n->n_drv_key, 0L))
		    == NULL) {
			retval = 0;
			goto out;
		}

		if (strcmp(shn, "md") == 0) {
			n->n_minor = MD_MKMIN(setno, MD_MIN2UNIT(n->n_minor));
		}
	}

out:
	rw_exit(&nm_lock.lock);
	return (retval);
}

static void
md_imp_nm(
	mddb_set_t	*s
)
{
	mddb_db_t		*dbp;
	mddb_de_ic_t		*dep;
	struct nm_rec_hdr	*hdr;
	struct nm_header	*hhdr;
	set_t			setno = s->s_setno;

	for (dbp = s->s_dbp; dbp != NULL; dbp = dbp->db_next) {
		for (dep = dbp->db_firstentry; dep != NULL;
		    dep = dep->de_next) {
			switch (dep->de_type1) {

			case MDDB_NM_HDR:
			case MDDB_DID_NM_HDR:

				hhdr = (struct nm_header *)
				    dep->de_rb_userdata;

				hdr = &hhdr->h_names;
				if (hdr->r_next_recid > 0) {
					hdr->r_next_recid = MAKERECID(setno,
					    DBID(hdr->r_next_recid));
				}

				hdr = &hhdr->h_shared;
				if (hdr->r_next_recid > 0) {
					hdr->r_next_recid = MAKERECID(setno,
					    DBID(hdr->r_next_recid));
				}
				break;

			case MDDB_NM:
			case MDDB_DID_NM:
			case MDDB_SHR_NM:
			case MDDB_DID_SHR_NM:

				hdr = (struct nm_rec_hdr *)
				    dep->de_rb_userdata;

				if (hdr->r_next_recid > 0) {
					hdr->r_next_recid = MAKERECID
					    (setno, DBID(hdr->r_next_recid));
				}
				break;

			default:
				break;
			}
		}
	}
}

static int
update_db_rec(
	mddb_set_t	*s
)
{
	mddb_db_t	*dbp;
	mddb_de_ic_t	*dep;
	mddb_recid_t	ids[2];

	for (dbp = s->s_dbp; dbp != NULL; dbp = dbp->db_next) {
		for (dep = dbp->db_firstentry; dep != NULL;
		    dep = dep->de_next) {
			if (! (dep->de_flags & MDDB_F_OPT)) {
				ids[0] = MAKERECID(s->s_setno, dep->de_recid);
				ids[1] = 0;
				if (mddb_commitrecs(ids)) {
					return (MDDB_E_NORECORD);
				}
			}
		}
	}
	return (0);
}

static int
update_mb(
	mddb_set_t	*s
)
{
	mddb_ri_t	*rip;
	int	err = 0;

	for (rip = s->s_rip; rip != NULL; rip = rip->ri_next) {
		if (rip->ri_flags & MDDB_F_EMASTER)
			/* disk is powered off or not there */
			continue;

		if (md_get_setstatus(s->s_setno) & MD_SET_REPLICATED_IMPORT) {
			/*
			 * It is a replicated set
			 */
			if (rip->ri_devid == (ddi_devid_t)NULL) {
				return (-1);
			}
			err = update_mb_devid(s, rip, rip->ri_devid);
		} else {
			/*
			 * It is a non-replicated set
			 * and there is no need to update
			 * devid
			 */
			err = update_mb_devid(s, rip, NULL);
		}

		if (err)
			return (err);
	}

	return (0);
}

static int
update_setname(
	set_t	setno
)
{
	struct nm_next_hdr	*nh;
	struct nm_shared_name	*shn, *new_shn;
	char			*prefix = "/dev/md/";
	char			*shrname;
	int			len;
	mdkey_t			o_key;
	uint32_t		o_count, o_data;
	mddb_recid_t		recid, ids[3];
	int			err = 0;
	mddb_set_t		*dbp;

	/* Import setname */
	dbp = (mddb_set_t *)md_set[setno].s_db;
	len = strlen(prefix) + strlen(dbp->s_setname) + strlen("/dsk/") + 1;
	shrname = kmem_zalloc(len, KM_SLEEP);
	(void) sprintf(shrname, "%s%s%s", prefix, dbp->s_setname, "/dsk/");

	rw_enter(&nm_lock.lock, RW_WRITER);
	if ((nh = get_first_record(setno, 0, NM_SHARED)) == NULL) {
		/*
		 * No namespace is okay
		 */
		err = 0;
		goto out;
	}

	if ((shn = (struct nm_shared_name *)lookup_shared_entry(nh,
	    0, prefix, NULL, NM_SHARED | NM_IMP_SHARED)) == NULL) {
		/*
		 * No metadevice is okay
		 */
		err = 0;
		goto out;
	}

	/*
	 * We have it, go ahead and update the namespace.
	 */
	o_key = shn->sn_key;
	o_count = shn->sn_count;
	o_data = shn->sn_data;

	if (remove_shared_entry(nh, o_key, NULL, 0L | NM_IMP_SHARED |
	    NM_NOCOMMIT)) {
		err = MDDB_E_NORECORD;
		goto out;
	}
	if ((new_shn = (struct nm_shared_name *)alloc_entry(
	    nh, md_set[setno].s_nmid, len, NM_SHARED |
	    NM_NOCOMMIT, &recid)) == NULL) {
		err = MDDB_E_NORECORD;
		goto out;
	}

	new_shn->sn_key = o_key;
	new_shn->sn_count = o_count;
	new_shn->sn_data = o_data;
	new_shn->sn_namlen = (ushort_t)len;
	(void) strcpy(new_shn->sn_name, shrname);

	ids[0] = recid;
	ids[1] = md_set[setno].s_nmid;
	ids[2] = 0;
	err = mddb_commitrecs(ids);

out:
	if (shrname)
		kmem_free(shrname, len);
	rw_exit(&nm_lock.lock);
	return (err);
}

/*
 * Returns 0 on success.
 * Returns -1 on failure with ep filled in.
 */
static int
md_imp_db(
	set_t		setno,
	int		stale_flag,
	md_error_t	*ep
)
{
	mddb_set_t	*s;
	int		err = 0;
	mddb_dt_t	*dtp;
	mddb_lb_t	*lbp;
	int		i;
	int		loccnt;

	if ((s = mddb_setenter(setno, MDDB_MUSTEXIST, &err)) == NULL) {
		return (mddbstatus2error(ep, err, NODEV32, setno));
	}

	/* Update dt */
	if ((dtp = (mddb_dt_t *)md_set[setno].s_dtp) != NULL) {
		crcgen(dtp, &dtp->dt_cks, MDDB_DT_BYTES, NULL);
	}

	if ((err = dt_write(s)) != 0) {
		err = mdsyserror(ep, err);
		mddb_setexit(s);
		return (err);
	}

	/*
	 * Update lb, no need to update the mediator because
	 * the diskset will only exist on the importing node
	 * and as such a mediator adds no value.
	 */

	/* Update lb */
	if (stale_flag & MD_IMP_STALE_SET) {
		lbp = s->s_lbp;
		loccnt = lbp->lb_loccnt;
		for (i = 0; i < loccnt; i++) {
			mddb_locator_t	*lp = &lbp->lb_locators[i];
			md_dev64_t	ndev = md_expldev(lp->l_dev);
			ddi_devid_t	devid_ptr;

			devid_ptr = s->s_did_icp->did_ic_devid[i];
			if (devid_ptr == NULL) {
				/*
				 * Already deleted, go to next one.
				 */
				continue;
			}
			if (mddb_devid_validate((ddi_devid_t)devid_ptr, &ndev,
			    NULL)) {
				/* disk unavailable, mark deleted */
				lp->l_flags = MDDB_F_DELETED;
				/* then remove the device id from the list */
				free_mbipp(&s->s_mbiarray[i]);
				(void) mddb_devid_delete(s, i);
			}
		}
		md_clr_setstatus(setno, MD_SET_STALE);
	}

	if ((err = writelocall(s)) != 0) {
		err = mdmddberror(ep, MDDB_E_NOTNOW, NODEV32, setno);
		mddb_setexit(s);
		return (err);
	}

	mddb_setexit(s);

	/* Update db records */
	if ((err = update_db_rec(s)) != 0) {
		return (mddbstatus2error(ep, err, NODEV32, setno));
	}

	/* Update setname embedded in the namespace */
	if ((err = update_setname(setno)) != 0)
		return (mddbstatus2error(ep, err, NODEV32, setno));

	return (err);
}

static void
md_dr_add(
	md_set_record	*sr,
	md_drive_record	*dr
)
{
	md_drive_record	*drv;

	if (sr->sr_driverec == 0) {
		sr->sr_driverec = dr->dr_selfid;
		return;
	}

	for (drv = (md_drive_record *)mddb_getrecaddr(sr->sr_driverec);
	    drv->dr_nextrec != 0;
	    drv = (md_drive_record *)mddb_getrecaddr(drv->dr_nextrec))
		;
	drv->dr_nextrec = dr->dr_selfid;
}

static void
md_setup_recids(
	md_set_record	*sr,
	mddb_recid_t	**ids,
	size_t		size
)
{
	md_drive_record	*drv;
	int		cnt;
	mddb_recid_t	*recids;

	recids = (mddb_recid_t *)kmem_zalloc(sizeof (mddb_recid_t)
	    * size, KM_SLEEP);
	recids[0] = sr->sr_selfid;
	cnt = 1;

	for (drv = (md_drive_record *)mddb_getrecaddr(sr->sr_driverec);
	    /* CSTYLED */
	    drv != NULL;) {
		recids[cnt++] = drv->dr_selfid;
		if (drv->dr_nextrec != 0)
			drv = (md_drive_record *)mddb_getrecaddr
			    (drv->dr_nextrec);
		else
			drv = NULL;
	}
	recids[cnt] = 0;
	*ids = &recids[0];
}

/*
 * The purpose of this function is to replace the old_devid with the
 * new_devid in the given namespace.   This is used for importing
 * remotely replicated drives.
 */
int
md_update_namespace_rr_did(
	mddb_config_t	*cp
)
{
	set_t			setno = cp->c_setno;
	struct nm_next_hdr	*nh;
	mdkey_t			key = MD_KEYWILD;
	side_t			side = MD_SIDEWILD;
	mddb_recid_t		recids[3];
	struct did_min_name	*n;
	struct nm_next_hdr	*did_shr_nh;
	struct did_shr_name	*shr_n;
	mdkey_t			ent_did_key;
	uint32_t		ent_did_count;
	uint32_t		ent_did_data;
	size_t			ent_size, size;
	ddi_devid_t		devid = NULL;
	struct did_shr_name	*shn;
	size_t			offset;
	struct nm_next_hdr	*this_did_shr_nh;
	void			*old_devid, *new_devid;

	if (!(md_get_setstatus(setno) & MD_SET_NM_LOADED))
		return (EIO);

	old_devid = (void *)(uintptr_t)cp->c_locator.l_old_devid;
	new_devid = (void *)(uintptr_t)cp->c_locator.l_devid;

	/*
	 * It is okay if we dont have any configuration
	 */
	offset = (sizeof (struct devid_shr_rec) - sizeof (struct did_shr_name));
	if ((nh = get_first_record(setno, 0, NM_DEVID | NM_NOTSHARED))
	    == NULL) {
		return (0);
	}
	while ((key = md_getnextkey(setno, side, key, NULL)) != MD_KEYWILD) {
		/* check out every entry in the namespace */
		if ((n = (struct did_min_name *)lookup_entry(nh, setno,
		    side, key, NODEV64, NM_DEVID)) == NULL) {
			continue;
		} else {
			did_shr_nh = get_first_record(setno, 0, NM_DEVID |
			    NM_SHARED);
			if (did_shr_nh == NULL) {
				return (ENOENT);
			}
			this_did_shr_nh = did_shr_nh->nmn_nextp;
			shr_n = (struct did_shr_name *)lookup_shared_entry(
			    did_shr_nh, n->min_devid_key, (char *)0,
			    &recids[0], NM_DEVID);
			if (shr_n == NULL) {
				return (ENOENT);
			}
			rw_enter(&nm_lock.lock, RW_WRITER);
			devid = (ddi_devid_t)shr_n->did_devid;
			/* find this devid in the incore replica  */
			if (ddi_devid_compare(devid, old_devid) == 0) {
				/*
				 * found the corresponding entry
				 * update with new devid
				 */
				/* first remove old devid info */
				ent_did_key = shr_n ->did_key;
				ent_did_count = shr_n->did_count;
				ent_did_data = shr_n->did_data;
				ent_size = DID_SHR_NAMSIZ(shr_n);
				size = ((struct nm_rec_hdr *)
				    this_did_shr_nh->nmn_record)->
				    r_used_size - offset - ent_size;
				if (size == 0) {
					(void) bzero(shr_n, ent_size);
				} else {
					(void) ovbcopy((caddr_t)shr_n +
					    ent_size, shr_n, size);
					(void) bzero((caddr_t)shr_n +
					    size, ent_size);
				}
				((struct nm_rec_hdr *)this_did_shr_nh->
				    nmn_record)->r_used_size -=
				    ent_size;
				/* add in new devid info */
				if ((shn = (struct did_shr_name *)
				    alloc_entry(did_shr_nh,
				    md_set[setno].s_did_nmid,
				    cp->c_locator.l_devid_sz,
				    NM_DEVID | NM_SHARED | NM_NOCOMMIT,
				    &recids[0])) == NULL) {
						rw_exit(&nm_lock.lock);
						return (ENOMEM);
					}
					shn->did_key = ent_did_key;
					shn->did_count = ent_did_count;
					ent_did_data |= NM_DEVID_VALID;
					shn->did_data = ent_did_data;
					shn->did_size = ddi_devid_sizeof(
					    new_devid);
					bcopy((void *)new_devid, (void *)
					    shn->did_devid, shn->did_size);
					recids[1] = md_set[setno].s_nmid;
					recids[2] = 0;
					mddb_commitrecs_wrapper(recids);
			}
			rw_exit(&nm_lock.lock);
		}
	}

	return (0);
}

/*
 * namespace is loaded before this is called.
 * This function is a wrapper for md_update_namespace_rr_did.
 *
 * md_update_namespace_rr_did may be called twice if attempting to
 * resolve a replicated device id during the take of a diskset - once
 * for the diskset namespace and a second time for the local namespace.
 * The local namespace would need to be updated when a drive has been
 * found during a take of the diskset that hadn't been resolved during
 * the import (aka partial replicated import).
 *
 * If being called during the import of the diskset (IMPORT flag set)
 * md_update_namespace_rr_did will only be called once with the disket
 * namespace.
 */
int
md_update_nm_rr_did_ioctl(
	mddb_config_t	*cp
)
{
	int	rval = 0;

	/* If update of diskset namespace fails, stop and return failure */
	if ((rval = md_update_namespace_rr_did(cp)) != 0)
		return (rval);

	if (cp->c_flags & MDDB_C_IMPORT)
		return (0);

	/* If update of local namespace fails, return failure */
	cp->c_setno = MD_LOCAL_SET;
	rval = md_update_namespace_rr_did(cp);
	return (rval);
}

/*ARGSUSED*/
int
md_imp_snarf_set(
	mddb_config_t	*cp
)
{
	set_t		setno;
	int		stale_flag;
	mddb_set_t	*s;
	int		i, err = 0;
	md_ops_t	*ops;
	md_error_t	*ep = &cp->c_mde;

	setno = cp->c_setno;
	stale_flag = cp->c_flags;

	mdclrerror(ep);
	if (setno >= md_nsets) {
		return (mdsyserror(ep, EINVAL));
	}

	md_haltsnarf_enter(setno);
	if (md_get_setstatus(setno) & MD_SET_IMPORT) {
		goto out;
	}

	/* Set the bit first otherwise load_old_replicas can fail */
	md_set_setstatus(setno, MD_SET_IMPORT);

	if ((s = mddb_setenter(setno, MDDB_MUSTEXIST, &err)) == NULL) {
		err = mddbstatus2error(ep, err, NODEV32, setno);
		goto out;
	}

	/*
	 * Upon completion of load_old_replicas, the old setno is
	 * restored from the disk so we need to reset
	 */
	s->s_lbp->lb_setno = setno;

	/*
	 * Fixup the NM records before loading namespace
	 */
	(void) md_imp_nm(s);
	mddb_setexit(s);

	/*
	 * Load the devid name space if it exists
	 * and ask each module to fixup unit records
	 */
	if (!md_load_namespace(setno, NULL, NM_DEVID)) {
		err = mdsyserror(ep, ENOENT);
		goto cleanup;
	}
	if (!md_load_namespace(setno, NULL, 0L)) {
		(void) md_unload_namespace(setno, NM_DEVID);
		err = mdsyserror(ep, ENOENT);
		goto cleanup;
	}

	do {
		i = 0;
		for (ops = md_opslist; ops != NULL; ops = ops->md_next)
			if (ops->md_imp_set != NULL)
				i += ops->md_imp_set(setno);
	} while (i);

	/*
	 * Fixup
	 *	(1) locator block
	 *	(2) locator name block if necessary
	 *	(3) master block
	 *	(4) directory block
	 * calls appropriate writes to push changes out
	 */
	if ((err = md_imp_db(setno, stale_flag, ep)) != 0) {
		goto cleanup;
	}

	/*
	 * Don't unload namespace if importing a replicated diskset.
	 * Namespace will be unloaded with an explicit RELEASE_SET ioctl.
	 */
	if (md_get_setstatus(s->s_setno) & MD_SET_REPLICATED_IMPORT) {
		md_haltsnarf_exit(setno);
		return (err);
	}

cleanup:
	/*
	 * Halt the set
	 */
	rw_enter(&md_unit_array_rw.lock, RW_WRITER);
	(void) md_halt_set(setno, MD_HALT_ALL);
	rw_exit(&md_unit_array_rw.lock);

	/*
	 * Unload the namespace for the imported set
	 */
	mutex_enter(&mddb_lock);
	mddb_unload_set(setno);
	mutex_exit(&mddb_lock);

out:
	md_haltsnarf_exit(setno);
	md_clr_setstatus(setno, MD_SET_IMPORT | MD_SET_REPLICATED_IMPORT);
	return (err);
}
#endif	/* MDDB_FAKE */
