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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * NAME:	raid_resync.c
 * DESCRIPTION: RAID driver source file containing routines related to resync
 *		operation.
 * ROUTINES PROVIDED FOR EXTERNAL USE:
 *	   resync_request() - get resync lock if available
 *	   release_resync_request() - relinquish resync lock
 *	   erred_check_line() - provide write instruction for erred column
 *	     init_pw_area() - initialize pre-write area
 *	     copy_pw_area() - copy pre-write area from one device to another
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
#include <sys/disp.h>
#include <sys/modctl.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/lvm/md_raid.h>

#include <sys/sysevent/eventdefs.h>
#include <sys/sysevent/svm.h>

#define	NOCOLUMN	(-1)

extern md_set_t		md_set[];
extern kmem_cache_t	*raid_child_cache;
extern kmem_cache_t	*raid_parent_cache;
extern md_resync_t	md_cpr_resync;
extern major_t		md_major;
extern void		raid_parent_init(md_raidps_t *ps);
extern void		raid_child_init(md_raidcs_t *ps);

/*
 * NAMES:	xor
 * DESCRIPTION: Xor two chunks of data together.  The data referenced by
 *		addr1 and addr2 are xor'd together for size and written into
 *		addr1.
 * PARAMETERS:	caddr_t addr1 - address of first chunk of data and destination
 *		caddr_t addr2 - address of second chunk of data
 *		u_int	 size - number to xor
 */
static void
xor(caddr_t addr1, caddr_t addr2, size_t size)
{
	while (size--) {
		*addr1++ ^= *addr2++;
	}
}

/*
 * NAME:	release_resync_request
 *
 * DESCRIPTION: Release resync active flag and reset unit values accordingly.
 *
 * PARAMETERS:	minor_t	    mnum - minor number identity of metadevice
 *
 * LOCKS:	Expects Unit Writer Lock to be held across call.
 */
void
release_resync_request(
	minor_t		mnum
)
{
	mr_unit_t	*un;

	un = MD_UNIT(mnum);
	ASSERT(un != NULL);

	un->c.un_status &= ~MD_UN_RESYNC_ACTIVE;

	un->un_column[un->un_resync_index].un_devflags &= ~MD_RAID_RESYNC;
	un->un_column[un->un_resync_index].un_devflags &= ~MD_RAID_RESYNC_ERRED;
	un->un_column[un->un_resync_index].un_devflags &=
	    ~(MD_RAID_COPY_RESYNC | MD_RAID_REGEN_RESYNC);

	un->un_resync_line_index = 0;
	un->un_resync_index = NOCOLUMN;
}

/*
 * NAME:	resync_request
 *
 * DESCRIPTION: Request resync.	 If resync is available (no current active
 *		resync), mark unit as resync active and initialize.
 *
 * PARAMETERS:	minor_t	    mnum - minor number identity of metadevice
 *		int column_index - index of column to resync
 *		int	copysize - copysize of ioctl request
 *		md_error_t   *ep - error output parameter
 *
 * RETURN:	0 if resync is available, 1 otherwise.
 *
 * LOCKS:	Expects Unit Writer Lock to be held across call.
 *
 * NOTE:	Sets un_resync_copysize to the input value in copysize, the
 *		existing value from an incomplete previous resync with an
 *		input value in copysize, or the lesser of the unit segment
 *		size or maxio.
 */
/* ARGSUSED */
int
resync_request(
	minor_t		mnum,
	int		column_index,
	size_t		copysize,
	md_error_t	*mde
)
{
	mr_unit_t	*un;

	un = MD_UNIT(mnum);
	ASSERT(un != NULL);

	/* if resync or grow not already active, set resync active for unit */
	if (! (un->un_column[column_index].un_devflags & MD_RAID_RESYNC) &&
	    ((un->c.un_status & MD_UN_RESYNC_ACTIVE) ||
	    (un->c.un_status & MD_UN_GROW_PENDING) ||
	    (un->un_column[column_index].un_devstate & RCS_RESYNC))) {
		if (mde)
			return (mdmderror(mde, MDE_GROW_DELAYED, mnum));
		return (1);
	}

	if (un->un_column[column_index].un_devstate &
	    (RCS_ERRED | RCS_LAST_ERRED))
		un->un_column[column_index].un_devflags |= MD_RAID_DEV_ERRED;
	else
		un->un_column[column_index].un_devflags &= ~MD_RAID_DEV_ERRED;
	un->c.un_status |= MD_UN_RESYNC_ACTIVE;
	un->un_resync_index = column_index;
	un->un_resync_line_index = 0;
	raid_set_state(un, column_index, RCS_RESYNC, 0);

	return (0);
}

/*
 * Name:	alloc_bufs
 *
 * DESCRIPTION: Initialize resync_comp buffers.
 *
 * PARAMETERS:	size_t	   bsize - size of buffer
 *		buf_t *read_buf1 - first read buf
 *		buf_t *read_buf2 - second read buf
 *		buf_t *write_buf - write buf
 */
static void
alloc_bufs(md_raidcs_t *cs, size_t bsize)
{
	/* allocate buffers, write uses the read_buf1 buffer */
	cs->cs_dbuffer = kmem_zalloc(bsize, KM_SLEEP);
	cs->cs_pbuffer = kmem_zalloc(bsize, KM_SLEEP);
}

void
init_buf(buf_t *bp, int flags, size_t size)
{
	/* zero buf */
	bzero((caddr_t)bp, sizeof (buf_t));

	/* set b_back and b_forw to point back to buf */
	bp->b_back = bp;
	bp->b_forw = bp;

	/* set flags size */
	bp->b_flags = flags;
	bp->b_bufsize = size;
	bp->b_offset = -1;

	/* setup semaphores */
	sema_init(&bp->b_io, 0, NULL, SEMA_DEFAULT, NULL);
	sema_init(&bp->b_sem, 0, NULL, SEMA_DEFAULT, NULL);
}

void
destroy_buf(buf_t *bp)
{
	sema_destroy(&bp->b_io);
	sema_destroy(&bp->b_sem);
}

void
reset_buf(buf_t *bp, int flags, size_t size)
{
	destroy_buf(bp);
	init_buf(bp, flags, size);
}

/*
 * NAME:	free_bufs
 *
 * DESCRIPTION: Free up buffers.
 *
 * PARAMETERS:	size_t	   bsize - size of buffer
 *		buf_t *read_buf1 - first read buf
 *		buf_t *read_buf2 - second read buf
 *		buf_t *write_buf - write buf
 */
static void
free_bufs(size_t bsize, md_raidcs_t *cs)
{
	kmem_free(cs->cs_dbuffer, bsize);
	kmem_free(cs->cs_pbuffer, bsize);
}

/*
 * NAME:	init_pw_area
 *
 * DESCRIPTION: Initialize pre-write area to all zeros.
 *
 * PARAMETERS:	minor_t	      mnum      - minor number identity of metadevice
 *		md_dev64_t dev_to_write - index of column to resync
 *		int   column_index      - index of column to resync
 *
 * RETURN:	1 if write error on resync device, otherwise 0
 *
 * LOCKS:	Expects Unit Reader Lock to be held across call.
 */
int
init_pw_area(
	mr_unit_t *un,
	md_dev64_t dev_to_write,
	diskaddr_t pwstart,
	uint_t	col
)
{
	buf_t	buf;
	caddr_t	databuffer;
	size_t	copysize;
	size_t	bsize;
	int	error = 0;
	int	i;

	ASSERT(un != NULL);
	ASSERT(un->un_column[col].un_devflags & MD_RAID_DEV_ISOPEN);

	bsize = un->un_iosize;
	copysize = dbtob(bsize);
	databuffer = kmem_zalloc(copysize, KM_SLEEP);
	init_buf(&buf, (B_BUSY | B_WRITE), copysize);

	for (i = 0; i < un->un_pwcnt; i++) {
		/* magic field is 0 for 4.0 compatability */
		RAID_FILLIN_RPW(databuffer, un, 0, 0,
				0, 0, 0,
				0, col, 0);
		buf.b_un.b_addr = (caddr_t)databuffer;
		buf.b_edev = md_dev64_to_dev(dev_to_write);
		buf.b_bcount = dbtob(bsize);
		buf.b_lblkno = pwstart + (i * un->un_iosize);

		/* write buf */
		(void) md_call_strategy(&buf, MD_STR_NOTTOP, NULL);

		if (biowait(&buf)) {
			error = 1;
			break;
		}
		reset_buf(&buf, (B_BUSY | B_WRITE), copysize);
	} /* for */

	destroy_buf(&buf);
	kmem_free(databuffer, copysize);

	return (error);
}

/*
 * NAME:	raid_open_alt
 *
 * DESCRIPTION: opens the alt device used during resync.
 *
 * PARAMETERS:	un
 *
 * RETURN:	0 - successfull
 *		1 - failed
 *
 * LOCKS:	requires unit writer lock
 */

static int
raid_open_alt(mr_unit_t *un, int index)
{
	mr_column_t	*column = &un->un_column[index];
	set_t		setno = MD_MIN2SET(MD_SID(un));
	side_t		side = mddb_getsidenum(setno);
	md_dev64_t	tmpdev = column->un_alt_dev;

	/* correct locks */
	ASSERT(UNIT_WRITER_HELD(un));
	/* not already writing to */
	ASSERT(! (column->un_devflags & MD_RAID_WRITE_ALT));
	/* not already open */
	ASSERT(! (column->un_devflags & MD_RAID_ALT_ISOPEN));

	if (tmpdev != NODEV64) {
		/*
		 * Open by device id. We use orig_key since alt_dev
		 * has been set by the caller to be the same as orig_dev.
		 */
		if ((md_getmajor(tmpdev) != md_major) &&
			md_devid_found(setno, side, column->un_orig_key) == 1) {
			tmpdev = md_resolve_bydevid(MD_SID(un), tmpdev,
				column->un_orig_key);
		}
		if (md_layered_open(MD_SID(un), &tmpdev, MD_OFLG_NULL)) {
			/* failed open */
			column->un_alt_dev = tmpdev;
			return (1);
		} else {
			/* open suceeded */
			column->un_alt_dev = tmpdev;
			column->un_devflags |= MD_RAID_ALT_ISOPEN;
			return (0);
		}
	} else
		/* no alt device to open */
		return (1);
}


/*
 * NAME:	raid_close_alt
 *
 * DESCRIPTION: closes the alt device used during resync.
 *
 * PARAMETERS:	un - raid unit structure
 *		indes - raid column
 *
 * RETURN:	none
 *
 * LOCKS:	requires unit writer lock
 */

static void
raid_close_alt(mr_unit_t *un, int index)
{
	mr_column_t	*column = &un->un_column[index];
	md_dev64_t	tmpdev = column->un_alt_dev;

	ASSERT(UNIT_WRITER_HELD(un));	/* correct locks */
	ASSERT(! (column->un_devflags & MD_RAID_WRITE_ALT)); /* not writing */
	ASSERT(column->un_devflags & MD_RAID_ALT_ISOPEN); /* already open */
	ASSERT(tmpdev != NODEV64); /* is a device */

	md_layered_close(column->un_alt_dev, MD_OFLG_NULL);
	column->un_devflags &= ~MD_RAID_ALT_ISOPEN;
	column->un_alt_dev = NODEV64;
}

static diskaddr_t
raid_resync_fillin_cs(diskaddr_t line, uint_t line_count, md_raidcs_t *cs)
{
	mr_unit_t	*un = cs->cs_un;

	ASSERT(line < un->un_segsincolumn);

	cs->cs_line = line;
	cs->cs_blkno = line * un->un_segsize;
	cs->cs_blkcnt = un->un_segsize * line_count;
	cs->cs_lastblk = cs->cs_blkno + cs->cs_blkcnt - 1;
	raid_line_reader_lock(cs, 1);

	return (line + line_count);
}

/* states returned by raid_resync_line */

#define	RAID_RESYNC_OKAY	0
#define	RAID_RESYNC_RDERROR	2
#define	RAID_RESYNC_WRERROR	3
#define	RAID_RESYNC_STATE	4

int
raid_resync_region(
	md_raidcs_t	*cs,
	diskaddr_t	line,
	uint_t		line_count,
	int		*single_read,
	hs_cmds_t	*hs_state,
	int		*err_col,
	md_dev64_t	dev_to_write,
	diskaddr_t	write_dev_start)
{
	mr_unit_t 	*un = cs->cs_un;
	buf_t		*readb1 = &cs->cs_pbuf;
	buf_t		*readb2 = &cs->cs_dbuf;
	buf_t		*writeb = &cs->cs_hbuf;
	diskaddr_t	off;
	size_t		tcopysize;
	size_t		copysize;
	int 		resync;
	int		quit = 0;
	size_t		leftinseg;
	int		i;

	resync = un->un_resync_index;
	off = line * un->un_segsize;
	copysize = un->un_resync_copysize;

	/* find first column to read, skip resync column */

	leftinseg = un->un_segsize * line_count;
	while (leftinseg) {

		/* truncate last chunk to end if needed */
		if (copysize > leftinseg)
			tcopysize = leftinseg;
		else
			tcopysize = copysize;
		leftinseg -= tcopysize;

		/*
		 * One of two scenarios:
		 * 1) resync device with hotspare ok.  This implies that
		 *    we are copying from a good hotspare to a new good original
		 *    device.  In this case readb1 is used as the buf for
		 *    the read from the hotspare device.
		 * 2) For all other cases, including when in case 1) and an
		 *    error is detected on the (formerly good) hotspare device,
		 *    readb1 is used for the initial read.  readb2 is used for
		 *    all other reads.	Each readb2 buffer is xor'd into the
		 *    readb1 buffer.
		 *
		 * In both cases, writeb is used for the write, using readb1's
		 * buffer.
		 *
		 * For case 2, we could alternatively perform the read for all
		 * devices concurrently to improve performance.	 However,
		 * this could diminish performance for concurrent reads and
		 * writes if low on memory.
		 */

		/* read first buffer */

		/* switch to read from good columns if single_read */
		if (*single_read) {
			if (un->un_column[resync].un_dev == NODEV64)
				return (RAID_RESYNC_RDERROR);

			reset_buf(readb1, B_READ | B_BUSY,
			    dbtob(copysize));
			readb1->b_bcount = dbtob(tcopysize);
			readb1->b_un.b_addr = cs->cs_pbuffer;
			readb1->b_edev = md_dev64_to_dev(
						un->un_column[resync].un_dev);
			readb1->b_lblkno =
			    un->un_column[resync].un_devstart + off;
			(void) md_call_strategy(readb1, MD_STR_NOTTOP, NULL);
			if (biowait(readb1)) {
				/*
				 * at this point just start rebuilding the
				 * data and go on since the other column
				 * are ok.
				 */
				*single_read = 0;
				*hs_state = HS_BAD;
				un->un_column[resync].un_devflags &=
				    ~MD_RAID_COPY_RESYNC;
				un->un_column[resync].un_devflags |=
				    MD_RAID_REGEN_RESYNC;
			}
		}

		/* if reading from all non-resync columns */
		if (!*single_read) {
			/* for each column, read line and xor into write buf */
			bzero(cs->cs_pbuffer, dbtob(tcopysize));
			for (i = 0; i < un->un_totalcolumncnt; i++) {

				if (un->un_column[i].un_dev == NODEV64)
					return (RAID_RESYNC_RDERROR);

				/* skip column getting resync'ed */
				if (i == resync) {
					continue;
				}
				reset_buf(readb1, B_READ | B_BUSY,
				    dbtob(copysize));
				readb1->b_bcount = dbtob(tcopysize);
				readb1->b_un.b_addr = cs->cs_dbuffer;
				readb1->b_edev = md_dev64_to_dev(
						un->un_column[i].un_dev);
				readb1->b_lblkno =
				    un->un_column[i].un_devstart + off;

				(void) md_call_strategy(readb1, MD_STR_NOTTOP,
					NULL);
				if (biowait(readb1)) {
					*err_col = i;
					quit = RAID_RESYNC_RDERROR;
				}

				if (quit)
					return (quit);

				/* xor readb2 data into readb1 */
				xor(cs->cs_pbuffer, readb1->b_un.b_addr,
				    dbtob(tcopysize));
			} /* for */
		}

		reset_buf(writeb, B_WRITE | B_BUSY,
		    dbtob(copysize));
		writeb->b_bcount = dbtob(tcopysize);
		writeb->b_un.b_addr = cs->cs_pbuffer;
		writeb->b_lblkno = off + write_dev_start;
		writeb->b_edev = md_dev64_to_dev(dev_to_write);

		/* set write block number and perform the write */
		(void) md_call_strategy(writeb, MD_STR_NOTTOP, NULL);
		if (biowait(writeb)) {
			if (*single_read == 0) {
				*hs_state = HS_BAD;
			}
			return (RAID_RESYNC_WRERROR);
		}
		writeb->b_blkno += tcopysize;
		off += tcopysize;
	} /* while */
	sema_destroy(&readb1->b_io);
	sema_destroy(&readb1->b_sem);
	sema_destroy(&readb2->b_io);
	sema_destroy(&readb2->b_sem);
	sema_destroy(&writeb->b_io);
	sema_destroy(&writeb->b_sem);
	return (RAID_RESYNC_OKAY);
}

/*
 * NAME:	resync_comp
 *
 * DESCRIPTION: Resync the component.  Iterate through the raid unit a line at
 *		a time, read from the good device(s) and write the resync
 *		device.
 *
 * PARAMETERS:	minor_t	   mnum - minor number identity of metadevice
 *		md_raidcs_t *cs - child save struct
 *
 * RETURN:	 0 - successfull
 *		 1 - failed
 *		-1 - aborted
 *
 * LOCKS:	Expects Unit Reader Lock to be held across call.  Acquires and
 *		releases Line Reader Lock for per-line I/O.
 */
static void
resync_comp(
	minor_t		mnum,
	md_raidcs_t	*cs
)
{
	mdi_unit_t	*ui;
	mr_unit_t	*un;
	mddb_recid_t	recids[2];
	rcs_state_t	state;
	md_dev64_t	dev_to_write;
	diskaddr_t	write_pwstart;
	diskaddr_t	write_devstart;
	md_dev64_t	dev;
	int		resync;
	int		i;
	int		single_read = 0;
	int		err;
	int		err_cnt;
	int		last_err;
	diskaddr_t	line;
	diskaddr_t	segsincolumn;
	size_t		bsize;
	uint_t		line_count;

	/*
	 * hs_state is the state of the hotspare on the column being resynced
	 * dev_state is the state of the resync target
	 */
	hs_cmds_t	hs_state;
	int		err_col = -1;
	diskaddr_t	resync_end_pos;

	ui = MDI_UNIT(mnum);
	ASSERT(ui != NULL);

	un = cs->cs_un;

	md_unit_readerexit(ui);
	un = (mr_unit_t *)md_io_writerlock(ui);
	un = (mr_unit_t *)md_unit_writerlock(ui);
	resync = un->un_resync_index;
	state = un->un_column[resync].un_devstate;
	line_count = un->un_maxio / un->un_segsize;
	if (line_count == 0) { /* handle the case of segsize > maxio */
		line_count = 1;
		bsize = un->un_maxio;
	} else
		bsize = line_count * un->un_segsize;

	un->un_resync_copysize = (uint_t)bsize;

	ASSERT(un->c.un_status & MD_UN_RESYNC_ACTIVE);
	ASSERT(un->un_column[resync].un_devflags &
	    (MD_RAID_COPY_RESYNC | MD_RAID_REGEN_RESYNC));

	/*
	 * if the column is not in resync then just bail out.
	 */
	if (! (un->un_column[resync].un_devstate & RCS_RESYNC)) {
		md_unit_writerexit(ui);
		md_io_writerexit(ui);
		un = (mr_unit_t *)md_unit_readerlock(ui);
		return;
	}
	SE_NOTIFY(EC_SVM_STATE, ESC_SVM_RESYNC_START, SVM_TAG_METADEVICE,
	    MD_UN2SET(un), MD_SID(un));

	/* identify device to write and its start block */

	if (un->un_column[resync].un_alt_dev != NODEV64) {
		if (raid_open_alt(un, resync)) {
			raid_set_state(un, resync, state, 0);
			md_unit_writerexit(ui);
			md_io_writerexit(ui);
			un = (mr_unit_t *)md_unit_readerlock(ui);
			cmn_err(CE_WARN, "md: %s: %s open failed replace "
				"terminated", md_shortname(MD_SID(un)),
				md_devname(MD_UN2SET(un),
					un->un_column[resync].un_alt_dev,
					NULL, 0));
			SE_NOTIFY(EC_SVM_STATE, ESC_SVM_RESYNC_FAILED,
			    SVM_TAG_METADEVICE, MD_UN2SET(un), MD_SID(un));
			return;
		}
		ASSERT(un->un_column[resync].un_devflags & MD_RAID_COPY_RESYNC);
		dev_to_write = un->un_column[resync].un_alt_dev;
		write_devstart = un->un_column[resync].un_alt_devstart;
		write_pwstart = un->un_column[resync].un_alt_pwstart;
		if (un->un_column[resync].un_devflags & MD_RAID_DEV_ERRED) {
			single_read = 0;
			hs_state = HS_BAD;
		} else {
			hs_state = HS_FREE;
			single_read = 1;
		}
		un->un_column[resync].un_devflags |= MD_RAID_WRITE_ALT;
	} else {
		dev_to_write = un->un_column[resync].un_dev;
		write_devstart = un->un_column[resync].un_devstart;
		write_pwstart = un->un_column[resync].un_pwstart;
		single_read = 0;
		hs_state = HS_FREE;
		ASSERT(un->un_column[resync].un_devflags &
		    MD_RAID_REGEN_RESYNC);
	}

	alloc_bufs(cs, dbtob(bsize));
	/* initialize pre-write area */
	if (init_pw_area(un, dev_to_write, write_pwstart, resync)) {
		un->un_column[resync].un_devflags &= ~MD_RAID_WRITE_ALT;
		if (un->un_column[resync].un_alt_dev != NODEV64) {
			raid_close_alt(un, resync);
		}
		md_unit_writerexit(ui);
		md_io_writerexit(ui);
		if (dev_to_write == un->un_column[resync].un_dev)
			hs_state = HS_BAD;
		err = RAID_RESYNC_WRERROR;
		goto resync_comp_error;
	}

	un->c.un_status &= ~MD_UN_RESYNC_CANCEL;
	segsincolumn = un->un_segsincolumn;
	err_cnt = raid_state_cnt(un, RCS_ERRED | RCS_LAST_ERRED);

	/* commit the record */

	md_unit_writerexit(ui);
	md_io_writerexit(ui);


	/* resync each line of the unit */
	for (line = 0; line <  segsincolumn; line += line_count) {
		/*
		 * Update address range in child struct and lock the line.
		 *
		 * The reader version of the line lock is used since only
		 * resync will use data beyond un_resync_line_index on the
		 * resync device.
		 */
		un = (mr_unit_t *)md_io_readerlock(ui);
		if (line + line_count > segsincolumn)
			line_count = segsincolumn - line;
		resync_end_pos = raid_resync_fillin_cs(line, line_count, cs);
		(void) md_unit_readerlock(ui);
		ASSERT(un->un_resync_line_index == resync_end_pos);
		err = raid_resync_region(cs, line, (int)line_count,
		    &single_read, &hs_state, &err_col, dev_to_write,
		    write_devstart);

		/*
		 * if the column failed to resync then stop writing directly
		 * to the column.
		 */
		if (err)
			un->un_resync_line_index = 0;

		md_unit_readerexit(ui);
		raid_line_exit(cs);
		md_io_readerexit(ui);

		if (err)
			break;

		un = (mr_unit_t *)md_unit_writerlock(ui);

		if (raid_state_cnt(un, RCS_ERRED | RCS_LAST_ERRED) != err_cnt) {
			err = RAID_RESYNC_STATE;
			md_unit_writerexit(ui);
			break;
		}
		md_unit_writerexit(ui);
	} /* for */

resync_comp_error:
	un = (mr_unit_t *)md_io_writerlock(ui);
	(void) md_unit_writerlock(ui);
	un->un_column[resync].un_devflags &= ~MD_RAID_WRITE_ALT;

	recids[0] = 0;
	recids[1] = 0;
	switch (err) {
		/*
		 * successful resync
		 */
	    case RAID_RESYNC_OKAY:
		/* initialize pre-write area */
		if ((un->un_column[resync].un_orig_dev != NODEV64) &&
		    (un->un_column[resync].un_orig_dev ==
		    un->un_column[resync].un_alt_dev)) {
			/*
			 * replacing a hot spare
			 * release the hot spare, which will close the hotspare
			 * and mark it closed.
			 */
			raid_hs_release(hs_state, un, &recids[0], resync);
			/*
			 * make the resync target the main device and
			 * mark open
			 */
			un->un_column[resync].un_hs_id = 0;
			un->un_column[resync].un_dev =
			    un->un_column[resync].un_orig_dev;
			un->un_column[resync].un_devstart =
			    un->un_column[resync].un_orig_devstart;
			un->un_column[resync].un_pwstart =
			    un->un_column[resync].un_orig_pwstart;
			un->un_column[resync].un_devflags |= MD_RAID_DEV_ISOPEN;
			/* alt becomes the device so don't close it */
			un->un_column[resync].un_devflags &= ~MD_RAID_WRITE_ALT;
			un->un_column[resync].un_devflags &=
			    ~MD_RAID_ALT_ISOPEN;
			un->un_column[resync].un_alt_dev = NODEV64;
		}
		raid_set_state(un, resync, RCS_OKAY, 0);
		break;

	    case RAID_RESYNC_WRERROR:
		if (HOTSPARED(un, resync) && single_read &&
		    (un->un_column[resync].un_devflags & MD_RAID_COPY_RESYNC)) {
			/*
			 * this is the case where the resync target is
			 * bad but there is a good hotspare.  In this
			 * case keep the hotspare, and go back to okay.
			 */
			raid_set_state(un, resync, RCS_OKAY, 0);
			cmn_err(CE_WARN, "md: %s: %s write error, replace "
				"terminated", md_shortname(MD_SID(un)),
				md_devname(MD_UN2SET(un),
					un->un_column[resync].un_orig_dev,
					NULL, 0));
			break;
		}
		if (HOTSPARED(un, resync)) {
			raid_hs_release(hs_state, un, &recids[0], resync);
			un->un_column[resync].un_dev =
			    un->un_column[resync].un_orig_dev;
			un->un_column[resync].un_devstart =
			    un->un_column[resync].un_orig_devstart;
			un->un_column[resync].un_pwstart =
			    un->un_column[resync].un_orig_pwstart;
		}
		raid_set_state(un, resync, RCS_ERRED, 0);
		if (un->un_column[resync].un_devflags & MD_RAID_REGEN_RESYNC)
			dev = un->un_column[resync].un_dev;
		else
			dev = un->un_column[resync].un_alt_dev;
		cmn_err(CE_WARN, "md: %s: %s write error replace terminated",
		    md_shortname(MD_SID(un)), md_devname(MD_UN2SET(un), dev,
		    NULL, 0));
		break;

	    case RAID_RESYNC_STATE:
		if (HOTSPARED(un, resync) && single_read &&
		    (un->un_column[resync].un_devflags & MD_RAID_COPY_RESYNC)) {
			/*
			 * this is the case where the resync target is
			 * bad but there is a good hotspare.  In this
			 * case keep the hotspare, and go back to okay.
			 */
			raid_set_state(un, resync, RCS_OKAY, 0);
			cmn_err(CE_WARN, "md: %s: needs maintenance, replace "
			    "terminated", md_shortname(MD_SID(un)));
			break;
		}
		if (HOTSPARED(un, resync)) {
			raid_hs_release(hs_state, un, &recids[0], resync);
			un->un_column[resync].un_dev =
			    un->un_column[resync].un_orig_dev;
			un->un_column[resync].un_devstart =
			    un->un_column[resync].un_orig_devstart;
			un->un_column[resync].un_pwstart =
			    un->un_column[resync].un_orig_pwstart;
		}
		break;
	    case RAID_RESYNC_RDERROR:
		if (HOTSPARED(un, resync)) {
			raid_hs_release(hs_state, un, &recids[0], resync);
			un->un_column[resync].un_dev =
			    un->un_column[resync].un_orig_dev;
			un->un_column[resync].un_devstart =
			    un->un_column[resync].un_orig_devstart;
			un->un_column[resync].un_pwstart =
			    un->un_column[resync].un_orig_pwstart;
		}

		if ((resync != err_col) && (err_col != NOCOLUMN))
			raid_set_state(un, err_col, RCS_ERRED, 0);
		break;

	    default:
		ASSERT(0);
	}
	if (un->un_column[resync].un_alt_dev != NODEV64) {
		raid_close_alt(un, resync);
	}

	/*
	 * an io operation may have gotten an error and placed a
	 * column in erred state.  This will abort the resync, which
	 * will end up in last erred.  This is ugly so go through
	 * the columns and do cleanup
	 */
	err_cnt = 0;
	last_err = 0;
	for (i = 0; i < un->un_totalcolumncnt; i++) {
		if (un->un_column[i].un_devstate & RCS_OKAY)
			continue;
		if (i == resync) {
			raid_set_state(un, i, RCS_ERRED, 1);
			err_cnt++;
		} else if (err == RAID_RESYNC_OKAY) {
			err_cnt++;
		} else {
			raid_set_state(un, i, RCS_LAST_ERRED, 1);
			last_err++;
		}
	}
	if ((err_cnt == 0) && (last_err == 0))
		un->un_state = RUS_OKAY;
	else if (last_err == 0) {
		un->un_state = RUS_ERRED;
		ASSERT(err_cnt == 1);
	} else if (last_err > 0) {
		un->un_state = RUS_LAST_ERRED;
	}

	uniqtime32(&un->un_column[resync].un_devtimestamp);
	un->un_resync_copysize = 0;
	un->un_column[resync].un_devflags &=
	    ~(MD_RAID_REGEN_RESYNC | MD_RAID_COPY_RESYNC);
	raid_commit(un, recids);
	/* release unit writer lock and acquire unit reader lock */
	md_unit_writerexit(ui);
	md_io_writerexit(ui);
	(void) md_unit_readerlock(ui);
	if (err == RAID_RESYNC_OKAY) {
		SE_NOTIFY(EC_SVM_STATE, ESC_SVM_RESYNC_DONE,
		    SVM_TAG_METADEVICE, MD_UN2SET(un), MD_SID(un));
	} else {
		SE_NOTIFY(EC_SVM_STATE, ESC_SVM_RESYNC_FAILED,
		    SVM_TAG_METADEVICE, MD_UN2SET(un), MD_SID(un));
		if (raid_state_cnt(un, RCS_ERRED |
			RCS_LAST_ERRED) > 1) {
			SE_NOTIFY(EC_SVM_STATE, ESC_SVM_LASTERRED,
			    SVM_TAG_METADEVICE, MD_UN2SET(un), MD_SID(un));
		} else {
			SE_NOTIFY(EC_SVM_STATE, ESC_SVM_ERRED,
			    SVM_TAG_METADEVICE, MD_UN2SET(un), MD_SID(un));
		}
	}

	free_bufs(dbtob(bsize), cs);
}

/*
 * NAME:	resync_unit
 *
 * DESCRIPTION: Start of RAID resync thread.  Perform up front allocations,
 *		initializations and consistency checking, then call
 *		resync_comp to resync the component.
 *
 * PARAMETERS:	minor_t mnum - minor number identity of metadevice
 *
 * LOCKS:	Acquires and releases Unit Reader Lock to maintain unit
 *		existence during resync.
 *		Acquires and releases the resync count lock for cpr.
 */
static void
resync_unit(
	minor_t mnum
)
{
	mdi_unit_t	*ui;
	mr_unit_t	*un;
	md_raidps_t	*ps = NULL;
	md_raidcs_t	*cs = NULL;
	int		resync;

	/*
	 * Increment the raid resync count for cpr
	 */
	mutex_enter(&md_cpr_resync.md_resync_mutex);
	md_cpr_resync.md_raid_resync++;
	mutex_exit(&md_cpr_resync.md_resync_mutex);

	ui = MDI_UNIT(mnum);
	ASSERT(ui != NULL);

	un = (mr_unit_t *)md_unit_readerlock(ui);

	/*
	 * Allocate parent and child memory pool structures.  These are
	 * only needed to lock raid lines, so only the minimal
	 * required fields for this purpose are initialized.
	 *
	 * Do not use the reserve pool for resync.
	 */
	ps = kmem_cache_alloc(raid_parent_cache, MD_ALLOCFLAGS);
	raid_parent_init(ps);
	cs = kmem_cache_alloc(raid_child_cache, MD_ALLOCFLAGS);
	raid_child_init(cs);
	resync = un->un_resync_index;
	ps->ps_un = un;
	ps->ps_ui = ui;
	ps->ps_flags = MD_RPS_INUSE;
	cs->cs_ps = ps;
	cs->cs_un = un;

	ASSERT(!(un->un_column[resync].un_devflags & MD_RAID_WRITE_ALT));

	resync_comp(mnum, cs);
	release_resync_request(mnum);

	kmem_cache_free(raid_child_cache, cs);
	kmem_cache_free(raid_parent_cache, ps);

	md_unit_readerexit(ui);

	/* close raid unit */
	(void) raid_internal_close(mnum, OTYP_LYR, 0, 0);

	/* poke hot spare daemon */
	(void) raid_hotspares();

	/*
	 * Decrement the raid resync count for cpr
	 */
	mutex_enter(&md_cpr_resync.md_resync_mutex);
	md_cpr_resync.md_raid_resync--;
	mutex_exit(&md_cpr_resync.md_resync_mutex);

	thread_exit();
}

/*
 * NAME:	raid_resync_unit
 *
 * DESCRIPTION: RAID metadevice specific resync routine.
 *		Open the unit and start resync_unit as a separate thread.
 *
 * PARAMETERS:	minor_t	  mnum - minor number identity of metadevice
 *		md_error_t *ep - output error parameter
 *
 * RETURN:	On error return 1 or set ep to nonzero, otherwise return 0.
 *
 * LOCKS:	Acquires and releases Unit Writer Lock.
 */
int
raid_resync_unit(
	minor_t			mnum,
	md_error_t		*ep
)
{
	mdi_unit_t	*ui;
	set_t		setno = MD_MIN2SET(mnum);
	mr_unit_t	*un;

	ui = MDI_UNIT(mnum);
	un = MD_UNIT(mnum);

	if (md_get_setstatus(setno) & MD_SET_STALE)
		return (mdmddberror(ep, MDE_DB_STALE, mnum, setno));

	ASSERT(un->un_column[un->un_resync_index].un_devflags &
	    (MD_RAID_COPY_RESYNC | MD_RAID_REGEN_RESYNC));

	/* Don't start a resync if the device is not available */
	if ((ui == NULL) || (ui->ui_tstate & MD_DEV_ERRORED)) {
		return (mdmderror(ep, MDE_RAID_OPEN_FAILURE, mnum));
	}

	if (raid_internal_open(mnum, FREAD | FWRITE, OTYP_LYR, 0)) {
		(void) md_unit_writerlock(ui);
		release_resync_request(mnum);
		md_unit_writerexit(ui);
		SE_NOTIFY(EC_SVM_STATE, ESC_SVM_OPEN_FAIL, SVM_TAG_METADEVICE,
		    setno, MD_SID(un));
		return (mdmderror(ep, MDE_RAID_OPEN_FAILURE, mnum));
	}

	/* start resync_unit thread */
	(void) thread_create(NULL, 0, resync_unit, (void *)(uintptr_t)mnum,
	    0, &p0, TS_RUN, minclsyspri);

	return (0);
}
