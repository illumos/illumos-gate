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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * NAME:	raid_replay.c
 *
 * DESCRIPTION: RAID driver source file containing routines related to replay
 *		operation.
 *
 * ROUTINES PROVIDED FOR EXTERNAL USE:
 *		raid_replay() - replay all the pre write entries in the unit.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/file.h>
#include <sys/user.h>
#include <sys/uio.h>
#include <sys/t_lock.h>
#include <sys/buf.h>
#include <sys/dkio.h>
#include <sys/vtoc.h>
#include <sys/kmem.h>
#include <vm/page.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/mkdev.h>
#include <sys/stat.h>
#include <sys/open.h>
#include <sys/modctl.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#include <sys/lvm/md_raid.h>

#include <sys/sysevent/eventdefs.h>
#include <sys/sysevent/svm.h>

/* functions forward declarations */
static int	raid_replay_error(mr_unit_t *un, int column);

int		raid_total_rply_entries = 0;

/*
 * NAMES:	raid_rply_dealloc, raid_rply_alloc
 * DESCRIPTION: RAID metadevice replay buffer allocation/deallocation routines
 * PARAMETERS:	mr_unit_t *un - pointer to the unit structure
 *		mr_unit_t *un - pointer to the unit structure
 * RETURNS:
 */
static void
raid_rply_dealloc(mr_unit_t *un,
		raid_rplybuf_t **bufs,
		raid_rplybuf_t *rwbuf1,
		raid_rplybuf_t *rwbuf2)
{
	int	i;
	raid_rplybuf_t *tmp;

	for (i = 0, tmp = *bufs; i < un->un_totalcolumncnt; i++, tmp++) {
		if (tmp->rpl_data) {
			kmem_free(tmp->rpl_data, DEV_BSIZE);
			tmp->rpl_data = NULL;
		}
		if (tmp->rpl_buf) {
			kmem_free(tmp->rpl_buf, sizeof (buf_t));
			tmp->rpl_buf = NULL;
		}
	}
	kmem_free(*bufs, sizeof (raid_rplybuf_t) * un->un_totalcolumncnt);
	*bufs = NULL;
	if (rwbuf1->rpl_data) {
		kmem_free(rwbuf1->rpl_data, dbtob(un->un_iosize));
		rwbuf1->rpl_data = NULL;
	}
	if (rwbuf1->rpl_buf) {
		kmem_free((caddr_t)rwbuf1->rpl_buf, sizeof (buf_t));
		rwbuf1->rpl_buf = NULL;
	}
	if (rwbuf2->rpl_data) {
		kmem_free(rwbuf2->rpl_data, dbtob(un->un_iosize));
		rwbuf2->rpl_data = NULL;
	}
	if (rwbuf2->rpl_buf) {
		kmem_free((caddr_t)rwbuf2->rpl_buf, sizeof (buf_t));
		rwbuf2->rpl_buf = NULL;
	}
}

static void
raid_rply_alloc(mr_unit_t *un,
		raid_rplybuf_t **bufs,
		raid_rplybuf_t *rwbuf1,
		raid_rplybuf_t *rwbuf2)
{
	int		i;
	raid_rplybuf_t *tmp;
	buf_t		*bp;

	/* intialization */
	*bufs = kmem_zalloc(sizeof (raid_rplybuf_t) * un->un_totalcolumncnt,
	    KM_SLEEP);
	ASSERT(*bufs != NULL);
	bzero((caddr_t)rwbuf1, sizeof (raid_rplybuf_t));
	bzero((caddr_t)rwbuf2, sizeof (raid_rplybuf_t));

	/* allocate all the buffers required for the replay processing */
	for (i = 0, tmp = *bufs; i < un->un_totalcolumncnt; i++, tmp++) {
		tmp->rpl_data = kmem_zalloc(DEV_BSIZE, KM_SLEEP);
		ASSERT(tmp->rpl_data != NULL);
		tmp->rpl_buf = kmem_zalloc(sizeof (buf_t), KM_SLEEP);
		ASSERT(tmp->rpl_buf != NULL);
		bp = (buf_t *)tmp->rpl_buf;
		bp->b_back = bp;
		bp->b_forw = bp;
		bp->b_flags = B_BUSY;
		bp->b_offset = -1;
		/* Initialize semaphores */
		sema_init(&bp->b_io, 0, NULL,
			SEMA_DEFAULT, NULL);
		sema_init(&bp->b_sem, 0, NULL,
			SEMA_DEFAULT, NULL);
	}

	rwbuf1->rpl_data = kmem_zalloc(dbtob(un->un_iosize), KM_SLEEP);
	ASSERT(rwbuf1->rpl_data != NULL);
	rwbuf1->rpl_buf = kmem_zalloc(sizeof (buf_t), KM_SLEEP);
	ASSERT(rwbuf1->rpl_buf != NULL);
	rwbuf2->rpl_data = kmem_zalloc(dbtob(un->un_iosize), KM_SLEEP);
	ASSERT(rwbuf2->rpl_data != NULL);
	rwbuf2->rpl_buf = kmem_zalloc(sizeof (buf_t), KM_SLEEP);
	ASSERT(rwbuf2->rpl_buf != NULL);

	bp = (buf_t *)rwbuf1->rpl_buf;
	bp->b_back = bp;
	bp->b_forw = bp;
	bp->b_flags = B_BUSY;
	bp->b_offset = -1;
	/* Initialize semaphores */
	sema_init(&bp->b_io, 0, NULL,
		SEMA_DEFAULT, NULL);
	sema_init(&bp->b_sem, 0, NULL,
		SEMA_DEFAULT, NULL);
	bp = (buf_t *)rwbuf2->rpl_buf;
	bp->b_back = bp;
	bp->b_forw = bp;
	bp->b_flags = B_BUSY;
	bp->b_offset = -1;
	/* Initialize semaphores */
	sema_init(&bp->b_io, 0, NULL,
		SEMA_DEFAULT, NULL);
	sema_init(&bp->b_sem, 0, NULL,
		SEMA_DEFAULT, NULL);
}

/*
 * NAMES:	rpl_insert, rpl_delete, rpl_find
 * DESCRIPTION: RAID metadevice replay list processing APIs
 * PARAMETERS:	raid_rplylst_t *list - pointer to the replay list.
 *		raid_pwhdr_t   *pwptr - pointer to a pre-write header.
 * RETURNS:
 */
static void
rpl_insert(raid_rplylst_t **listp, raid_rplylst_t *newp)
{
	raid_rplylst_t *tmp, **prevp;

	for (prevp = listp; ((tmp = *prevp) != NULL); prevp = &tmp->rpl_next) {
		if (tmp->rpl_id > newp->rpl_id) {
			break;
		}
	}
	newp->rpl_next = tmp;
	*prevp = newp;
}

static void
rpl_delete(raid_rplylst_t **prevp, raid_rplylst_t *oldp)
{

	ASSERT((caddr_t)oldp);
	raid_total_rply_entries --;
	*prevp = oldp->rpl_next;
	kmem_free((caddr_t)oldp, sizeof (raid_rplylst_t));
}

static raid_rplylst_t *
rpl_find(raid_rplylst_t *list, long long pw_id)
{
	raid_rplylst_t *tmp;

	for (tmp = list; tmp; tmp = tmp->rpl_next) {
		if (pw_id == tmp->rpl_id) {
			return (tmp);
		}
	}
	return ((raid_rplylst_t *)NULL);
}

/*
 * NAMES:	enq_rplylst
 * DESCRIPTION: Enqueue a pre-write header into the replay list.
 * PARAMETERS:	raid_rplylst_t *list - pointer to the replay list.
 *		raid_pwhdr_t   *pwptr - pointer to a pre-write header.
 * RETURNS:
 */
static void
enq_rplylst(raid_rplylst_t **listp, raid_pwhdr_t *pwhp,
		uint_t slot, int column)
{
	raid_rplylst_t *newp, *oldp;

	/* check if the pre-write existed in the list */
	if ((pwhp->rpw_colcount <= 2) &&
	    (oldp = rpl_find(*listp, pwhp->rpw_id))) {
		bcopy((caddr_t)pwhp, (caddr_t)&oldp->rpl_pwhdr2,
			sizeof (raid_pwhdr_t));
		oldp->rpl_slot2   = slot;
		oldp->rpl_column2 = column;
	} else {
		raid_total_rply_entries ++;
		newp = (raid_rplylst_t *)kmem_zalloc(sizeof (raid_rplylst_t),
		    KM_SLEEP);
		ASSERT(newp != NULL);
		bcopy((caddr_t)pwhp, (caddr_t)&newp->rpl_pwhdr1,
			sizeof (raid_pwhdr_t));
		bzero((caddr_t)&newp->rpl_pwhdr2, sizeof (raid_pwhdr_t));

		newp->rpl_id = pwhp->rpw_id;
		newp->rpl_column1 = column;
		newp->rpl_slot1 = slot;
		newp->rpl_next = (raid_rplylst_t *)NULL;
		newp->rpl_colcnt = pwhp->rpw_colcount;
		rpl_insert(listp, newp);
	}
}

/*
 * NAMES:	pw_read_done and pw_write_done
 * DESCRIPTION: don't know the usage yet ??? (TBD)
 * PARAMETERS:
 * RETURNS:
 */
static int
pw_read_done(buf_t *bp)
{
	ASSERT(SEMA_HELD(&bp->b_sem));
	ASSERT((bp->b_flags & B_DONE) == 0);

	bp->b_flags |= B_DONE;

	if (bp->b_flags & B_ASYNC)
		sema_v(&bp->b_sem);
	else
		/* wakeup the thread waiting on this buf */
		sema_v(&bp->b_io);
	return (0);
}

static int
pw_write_done(buf_t *bp)
{
	ASSERT(SEMA_HELD(&bp->b_sem));
	ASSERT((bp->b_flags & B_DONE) == 0);

	bp->b_flags |= B_DONE;

	if (bp->b_flags & B_ASYNC)
		sema_v(&bp->b_sem);
	else
		/* wakeup the thread waiting on this buf */
		sema_v(&bp->b_io);

	return (0);
}

/*
 * NAMES:	raid_pwhdr_read
 * DESCRIPTION: issue a syncronous read to read a pre-write header
 * PARAMETERS:	mr_unit_t *un - pointer to the unit structure
 *		int	pw_slot - pre-write entry slot number
 *		int	column	- column number for the pre-write entry
 *		raid_rplybuf_t *bufp - pointer to the replay buffer structure
 * RETURNS:
 */
static void
raid_pwhdr_read(mr_unit_t *un, int pw_slot, int column, raid_rplybuf_t *bufp)
{
	buf_t		*bp;

	/* set up pointers from raid_rplybuf_t *bufp */
	bp = (buf_t *)bufp->rpl_buf;

	/* calculate the data address or block number */
	bp->b_un.b_addr = bufp->rpl_data;
	bp->b_lblkno = un->un_column[column].un_pwstart +
		pw_slot * un->un_iosize;
	bp->b_edev = md_dev64_to_dev(un->un_column[column].un_dev);
	bp->b_bufsize = DEV_BSIZE;
	bp->b_bcount = DEV_BSIZE;
	bp->b_flags  = (B_READ | B_BUSY);
	bp->b_iodone = pw_read_done;
	(void) md_call_strategy(bp, 0, NULL);
}

/*
 * NAMES:	raid_pw_read
 * DESCRIPTION: issue a syncronous read to read a pre-write entry
 * PARAMETERS:	mr_unit_t	*un    - pointer to the unit structure
 *		int		column - column number for the pre-write entry
 *		u_int		slot   - pre-write entry slot number
 *		raid_rplybuf_t	*bufp  - pointer to the replay buffer structure
 * RETURNS:
 */
static int
raid_pw_read(mr_unit_t *un, int column, uint_t slot, raid_rplybuf_t *bufp)
{
	buf_t	*bp;
	int	error;
	uint_t	blkcnt  = un->un_iosize;
	uint_t	bytecnt = blkcnt * DEV_BSIZE;

	/* if this column is no longer accessible, return */
	if (!COLUMN_ISUP(un, column))
		return (RAID_RPLY_COMPREPLAY);

	/* set up pointers from raid_rplybuf_t *bufp */
	bp = (buf_t *)bufp->rpl_buf;

	/* calculate the data address or block number */
	bp->b_un.b_addr = bufp->rpl_data;
	bp->b_bufsize = bytecnt;
	bp->b_bcount = bytecnt;
	bp->b_flags = (B_READ | B_BUSY);
	bp->b_edev = md_dev64_to_dev(un->un_column[column].un_dev);
	bp->b_lblkno = un->un_column[column].un_pwstart + (slot * blkcnt);
	bp->b_iodone = pw_read_done;
	(void) md_call_strategy(bp, 0, NULL);
	if (biowait(bp)) {
		error = raid_replay_error(un, column);
		return (error);
	}
	return (0);
}

/*
 * NAMES:	raid_pw_write
 * DESCRIPTION: issue a syncronous write to write a pre-write entry
 * PARAMETERS:	mr_unit_t *un - pointer to the unit structure
 *		int	column	- column number for the pre-write entry
 *		raid_pwhdr_t   *pwhp - needed for some infos about the pw header
 *		raid_rplybuf_t *bufp - pointer to the replay buffer structure
 * RETURNS:
 */
static int
raid_pw_write(mr_unit_t *un, int column, raid_pwhdr_t *pwhp,
    raid_rplybuf_t *bufp)
{
	buf_t	 *bp;
	int	 error;

	/* if this column is no longer accessible, return */
	if (!COLUMN_ISUP(un, column))
		return (RAID_RPLY_COMPREPLAY);

	/* set up pointers from raid_rplybuf_t *bufp */
	bp = (buf_t *)bufp->rpl_buf;

	/* calculate the data address or block number */
	bp->b_un.b_addr = bufp->rpl_data + DEV_BSIZE;
	bp->b_bufsize = dbtob(pwhp->rpw_blkcnt);
	bp->b_bcount = dbtob(pwhp->rpw_blkcnt);
	bp->b_flags = (B_WRITE | B_BUSY);
	bp->b_edev  = md_dev64_to_dev(un->un_column[column].un_dev);
	bp->b_lblkno = un->un_column[column].un_devstart + pwhp->rpw_blkno;
	bp->b_iodone = pw_write_done;
	(void) md_call_strategy(bp, 0, NULL);
	if (biowait(bp)) {
		error = raid_replay_error(un, column);
		return (error);
	}
	return (0);
}

/*
 * NAMES:	genchecksum
 * DESCRIPTION: generate check sum for a pre-write entry
 * PARAMETERS:	caddr_t addr - where the data bytes are
 *		int bcount - number of bytes in the pre-write entry
 * RETURNS:
 */
static uint_t
genchecksum(caddr_t addr, size_t bcount)
{
	uint_t *dbuf;
	size_t wordcnt;
	uint_t dsum = 0;

	wordcnt = bcount / sizeof (uint_t);
	dbuf = (uint_t *)(void *)(addr);

	while (wordcnt--) {
		dsum ^= *dbuf;
		dbuf++;
	}
	return (dsum);
}

/*
 * NAMES:	raid_rply_verify
 * DESCRIPTION: verify the pre-write entry for replay
 * PARAMETERS:	mr_unit_t *un	- pointer to unit structure
 *		int col1	- column number 1
 *		int goodsum1	- flag to indicate good checksum
 *		int *do_1	- flag to indicate whether we should replay
 *				  the first pre-write
 *		int col2	- column number 2
 *		int goodsum2	- flag to indicate good checksum
 *		int *do_2	- flag to indicate whether we should replay
 *				  the first pre-write
 * RETURNS:
 */
static void
raid_rply_verify(mr_unit_t *un, int col1, int goodsum1, int *do_1,
    int col2, int goodsum2, int *do_2)
{
	int	good_state1 = 0;
	int	good_state2 = 0;

	*do_1 = 0; *do_2 = 0;		/* prepare for the worst */
	if (COLUMN_ISUP(un, col1)) {
		good_state1 = 1;
	}
	if (COLUMN_ISUP(un, col2)) {
		good_state2 = 1;
	}
	if ((good_state1 & good_state2) && (goodsum1 & goodsum2)) {
		/* if both columns check out, do it */
		*do_1 = 1; *do_2 = 1;
	} else if ((good_state1 & goodsum1) && !good_state2) {
		/* if one column is okay and the other is errored, do it */
		*do_1 = 1; *do_2 = 0;
	} else if ((good_state2 & goodsum2) && !good_state1) {
		/* if one column is okay and the other is errored, do it */
		*do_2 = 1; *do_1 = 0;
	}
}

/*
 * NAMES:	raid_rplyeach
 * DESCRIPTION: issue a syncronous read to read a pre-write header
 * PARAMETERS:	mr_unit_t *un - pointer to the unit structure
 *		raid_rplylst_t *eachp - pointer to the replay list entry
 *		raid_rplybuf_t *rwbuf1 - pointer to the replay buffer structure
 *		raid_rplybuf_t *rwbuf2 - pointer to the replay buffer structure
 * RETURNS:
 */
static int
raid_rplyeach(
	mr_unit_t	*un,
	raid_rplylst_t	*eachp,
	raid_rplybuf_t	*rwbuf1,
	raid_rplybuf_t	*rwbuf2
)
{
	raid_pwhdr_t	*pwhp1;
	raid_pwhdr_t	*pwhp2;
	uint_t		dsum1 = 0;
	uint_t		dsum2 = 0;
	int		good_pw1 = 0;
	int		good_pw2 = 0;
	int		do_1 = 0;
	int		do_2 = 0;
	int		error = 0;

	/* First verify the normal case - two pre-write entries are all good */
	if ((eachp->rpl_pwhdr1.rpw_magic == RAID_PWMAGIC &&
	    eachp->rpl_pwhdr2.rpw_magic == RAID_PWMAGIC) &&
	    (eachp->rpl_pwhdr1.rpw_blkcnt == eachp->rpl_pwhdr2.rpw_blkcnt)) {

		ASSERT(eachp->rpl_pwhdr1.rpw_id == eachp->rpl_pwhdr2.rpw_id);

		/* read the pre-write entries */
		error = raid_pw_read(un, eachp->rpl_column1,
		    eachp->rpl_slot1, rwbuf1);
		pwhp1 = &eachp->rpl_pwhdr1;
		if (error) {
			if (error != RAID_RPLY_COMPREPLAY)
				return (error);
			good_pw1 = FALSE;
		} else {
			/* generate checksum for each pre-write entry */
			dsum1 = genchecksum(rwbuf1->rpl_data + DEV_BSIZE,
						dbtob(pwhp1->rpw_blkcnt));
			good_pw1 = (dsum1 == pwhp1->rpw_sum);
		}

		error = raid_pw_read(un, eachp->rpl_column2, eachp->rpl_slot2,
		    rwbuf2);
		pwhp2 = &eachp->rpl_pwhdr2;
		if (error) {
			if (error != RAID_RPLY_COMPREPLAY)
				return (error);
			good_pw2 = FALSE;
		} else {
			/* generate checksum for pre-write entry */
			dsum2 = genchecksum(rwbuf2->rpl_data + DEV_BSIZE,
						dbtob(pwhp2->rpw_blkcnt));
			good_pw2 = (dsum2 == pwhp2->rpw_sum);
		}

		/* verify the checksums and states */
		raid_rply_verify(un, eachp->rpl_column1, good_pw1, &do_1,
			eachp->rpl_column2, good_pw2, &do_2);

		/* write (replay) the pre-write entries */
		if (do_1) {
			error = raid_pw_write(un, eachp->rpl_column1,
			    &eachp->rpl_pwhdr1, rwbuf1);
			if (error && (error != RAID_RPLY_COMPREPLAY)) {
				return (error);
			}
		}
		if (do_2) {
			error = raid_pw_write(un, eachp->rpl_column2,
			    &eachp->rpl_pwhdr2, rwbuf2);
			if (error && (error != RAID_RPLY_COMPREPLAY)) {
				return (error);
			}
		}
		return (0);
	}
	if (eachp->rpl_pwhdr1.rpw_magic == RAID_PWMAGIC) {
		/*
		 * if partner was errored at time of write
		 * or due to open or replay, replay this entry
		 */
		if ((eachp->rpl_pwhdr1.rpw_columnnum == -1) ||
		    (! COLUMN_ISUP(un, eachp->rpl_pwhdr1.rpw_columnnum))) {
			/* read the pre-write entry */
			error = raid_pw_read(un, eachp->rpl_column1,
			    eachp->rpl_slot1, rwbuf1);
			if (error)
				return (error);
			/* generate checksum for the pre-write entry */
			pwhp1 = &eachp->rpl_pwhdr1;
			dsum1 = genchecksum(rwbuf1->rpl_data + DEV_BSIZE,
						dbtob(pwhp1->rpw_blkcnt));
			if (dsum1 == pwhp1->rpw_sum) {
				error = raid_pw_write(un, eachp->rpl_column1,
						&eachp->rpl_pwhdr1, rwbuf1);
				if (error && (error != RAID_RPLY_COMPREPLAY)) {
					return (error);
				}
			}
		}
		return (0);
	}

	return (0);
}

static int
replay_line(mr_unit_t *un, raid_rplylst_t *eachp, raid_rplybuf_t *rplybuf)
{
	raid_pwhdr_t	*pwhdr1, *pwhdr2;
	raid_rplylst_t	*eachpn;
	int		i;
	int		cnt;
	diskaddr_t	blkno;
	uint_t		blkcnt;
	long long	id;
	int		dsum;
	int		error;
	int		colcnt, col, col2;
	int		down;

	if (eachp->rpl_id == 0)
		return (0);
	/*
	 * check: 1 - enough equal ids
	 *	  2 - all have same columncnt
	 *	  3 - all have same blkno
	 *	  4 - all have same blkcnt
	 *
	 * read each and check the checksum
	 * write each
	 */

	cnt = eachp->rpl_colcnt;
	id = eachp->rpl_id;
	pwhdr1 = &eachp->rpl_pwhdr1;
	blkno = pwhdr1->rpw_blkno;
	blkcnt = pwhdr1->rpw_blkcnt;

	error = raid_pw_read(un, eachp->rpl_column1, eachp->rpl_slot1, rplybuf);
	dsum = genchecksum(rplybuf->rpl_data + DEV_BSIZE,
	    dbtob(pwhdr1->rpw_blkcnt));

	if (dsum != pwhdr1->rpw_sum)
		return (0);

	if (error) {
		if (error == RAID_RPLY_COMPREPLAY)
			return (0);
		else
			return (1);
	}

	eachpn = eachp->rpl_next;
	for (i = 1; i < cnt; i++) {
		if (eachpn == NULL)
			break;
		col2 = eachpn->rpl_column1;
		ASSERT(col2 < un->un_totalcolumncnt);
		pwhdr2 = &eachpn->rpl_pwhdr1;
		if ((pwhdr2->rpw_blkno != blkno) ||
		    (pwhdr2->rpw_blkcnt != blkcnt) ||
		    (eachpn->rpl_id != id) ||
		    (pwhdr2->rpw_colcount != cnt)) {
			return (0);
		}

		error = raid_pw_read(un, col2, eachpn->rpl_slot1, rplybuf);
		dsum = genchecksum(rplybuf->rpl_data + DEV_BSIZE,
		    dbtob(pwhdr2->rpw_blkcnt));
		if (dsum != pwhdr2->rpw_sum)
			return (0);
		eachpn = eachpn->rpl_next;
	}
	colcnt = i;

	if (error)
		return (0);

	down = raid_state_cnt(un, RCS_ERRED);
	if ((i != un->un_totalcolumncnt) &&
	    (i != (un->un_totalcolumncnt - down)))
		return (0);

	/* there ara enough columns to write correctly */
	eachpn = eachp;
	for (i = 0; i < colcnt; i++) {
		col = eachpn->rpl_column1;
		error = raid_pw_read(un, col, eachpn->rpl_slot1, rplybuf);
		error = raid_pw_write(un, col, &eachpn->rpl_pwhdr1, rplybuf);
		eachpn->rpl_id = 0;
		if (error && (error != RAID_RPLY_COMPREPLAY))
			return (1);
		eachpn = eachpn->rpl_next;
	}
	return (0);
}

/*
 * NAMES:	raid_replay_error
 * DESCRIPTION: RAID metadevice replay error handling routine (TBD)
 * PARAMETERS:
 * RETURNS:
 */
static int
raid_replay_error(mr_unit_t *un, int column)
{
	int	error = RAID_RPLY_COMPREPLAY;

	raid_set_state(un, column, RCS_ERRED, 0);
	raid_commit(un, NULL);

	if (UNIT_STATE(un) == RUS_LAST_ERRED) {
		error = RAID_RPLY_READONLY;
		SE_NOTIFY(EC_SVM_STATE, ESC_SVM_LASTERRED, SVM_TAG_METADEVICE,
		    MD_UN2SET(un), MD_SID(un));
	} else if (UNIT_STATE(un) == RUS_ERRED) {
		SE_NOTIFY(EC_SVM_STATE, ESC_SVM_ERRED, SVM_TAG_METADEVICE,
		    MD_UN2SET(un), MD_SID(un));
	}

	return (error);
}

/*
 * NAMES:	raid_replay
 * DESCRIPTION: RAID metadevice main replay processing routine
 * PARAMETERS:	mr_unit_t *un - pointer to an unit structure
 * RETURNS:
 */

int
raid_replay(mr_unit_t *un)
{
	raid_rplylst_t	*rplylst = NULL;
	raid_rplylst_t	**prevp, *eachp;
	raid_rplybuf_t	*rplybuf;
	raid_rplybuf_t	rwbuf1;
	raid_rplybuf_t	rwbuf2;
	mr_column_t	*colptr;
	raid_pwhdr_t	pwhdr;
	raid_pwhdr_t	*pwhdrp = &pwhdr;
	int		error = 0;
	int		i, j;
	diskaddr_t	max_blkno = un->un_segsize * un->un_segsincolumn;
	int		totalcolumns = un->un_totalcolumncnt;

	raid_rply_alloc(un, &rplybuf, &rwbuf1, &rwbuf2);

	/* build a replay list based on the order of pre-write id */
	for (i = 0; i < un->un_pwcnt; i++) {
		/* issue a synchronous read for each column */
		for (j = 0; j < un->un_totalcolumncnt; j++) {
			if (COLUMN_ISUP(un, j)) {
				raid_pwhdr_read(un, i, j, &rplybuf[j]);
				/* wait for I/O completion for each column */
				if (biowait((buf_t *)rplybuf[j].rpl_buf)) {
					/* potential state transition */
					error = raid_replay_error(un, j);
					if (error == RAID_RPLY_COMPREPLAY)
						continue;
					else
						goto replay_failed;
				}
				if (un->c.un_revision & MD_64BIT_META_DEV) {
					pwhdrp = (raid_pwhdr_t *)
							rplybuf[j].rpl_data;
				} else {
					RAID_CONVERT_RPW((raid_pwhdr32_od_t *)
							rplybuf[j].rpl_data,
							pwhdrp);
				}

				/* first check pre-write magic number */
				if (pwhdrp->rpw_magic != RAID_PWMAGIC) {
					continue;
				}
				if (pwhdrp->rpw_column != j) {
					continue;
				}
				if (pwhdrp->rpw_id == (long long) 0) {
					continue;
				}
				if (pwhdrp->rpw_blkcnt > (un->un_iosize - 1)) {
					continue;
				}
				if (pwhdrp->rpw_blkcnt == 0) {
					continue;
				}
				if (pwhdrp->rpw_blkno > max_blkno) {
					continue;
				}
				if ((pwhdrp->rpw_columnnum < 0) ||
				    (pwhdrp->rpw_columnnum > totalcolumns)) {
					continue;
				}
				if (((pwhdrp->rpw_colcount != 1) &&
				    (pwhdrp->rpw_colcount != 2) &&
				    (pwhdrp->rpw_colcount != totalcolumns))) {
					continue;
				}

				enq_rplylst(&rplylst, pwhdrp, i, j);
			}
		}
	}

	/* replay each entry in the replay list */
	prevp = &rplylst;
	while ((eachp = *prevp) != NULL) {
		/* zero out the pre-write headers in the buffer */
		bzero((caddr_t)rwbuf1.rpl_data, sizeof (raid_pwhdr_t));
		bzero((caddr_t)rwbuf2.rpl_data, sizeof (raid_pwhdr_t));

		if (eachp->rpl_colcnt <= 2)
			error = raid_rplyeach(un, eachp, &rwbuf1, &rwbuf2);
		else
			error = replay_line(un, eachp, &rwbuf1);

		if (error && (error != RAID_RPLY_COMPREPLAY)) {
			goto replay_failed;
		}

		/* free the processed replay list entry */
		rpl_delete(prevp, eachp);
		prevp = &rplylst;
	}

	/* zero out all pre-write entries in this unit */
	for (j = 0; j < un->un_totalcolumncnt; j++) {
		if (COLUMN_ISUP(un, j)) {
			colptr = &un->un_column[j];
			if (init_pw_area(un, colptr->un_dev,
						colptr->un_pwstart, j))
				break;
		}
	}

	/* deallocate all the buffer resource allocated in this routine */
	raid_rply_dealloc(un, &rplybuf, &rwbuf1, &rwbuf2);

	return (RAID_RPLY_SUCCESS);

replay_failed:

	/* first release the list */
	prevp = &rplylst;
	while ((eachp = *prevp) != NULL) {
		rpl_delete(prevp, eachp);
		prevp = &rplylst;
	}

	/* then release buffers */
	raid_rply_dealloc(un, &rplybuf, &rwbuf1, &rwbuf2);

	/* also reset the pre-write id variable to one */
	un->un_pwid = 1;
	raid_total_rply_entries = 0;

	return (error);
}
