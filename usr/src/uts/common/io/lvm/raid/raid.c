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

/*
 * NAME:	raid.c
 *
 * DESCRIPTION: Main RAID driver source file containing open, close and I/O
 *		operations.
 *
 * ROUTINES PROVIDED FOR EXTERNAL USE:
 *  raid_open()			- open the RAID metadevice for access.
 *  raid_internal_open()	- internal open routine of RAID metdevice.
 *  md_raid_strategy()		- perform normal I/O operations,
 *				    such as read and write.
 *  raid_close()		- close the RAID metadevice.
 *  raid_internal_close()	- internal close routine of RAID metadevice.
 *  raid_snarf()		- initialize and clean up MDD records.
 *  raid_halt()			- reset the RAID metadevice
 *  raid_line()			- return the line # of this segment
 *  raid_dcolumn()		- return the data column # of this segment
 *  raid_pcolumn()		- return the parity column # of this segment
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
#include <sys/cmn_err.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/mkdev.h>
#include <sys/stat.h>
#include <sys/open.h>
#include <sys/modctl.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/debug.h>
#include <sys/lvm/md_raid.h>
#include <sys/lvm/mdvar.h>
#include <sys/lvm/md_convert.h>

#include <sys/sysevent/eventdefs.h>
#include <sys/sysevent/svm.h>

md_ops_t		raid_md_ops;
#ifndef lint
char			_depends_on[] = "drv/md";
md_ops_t		*md_interface_ops = &raid_md_ops;
#endif	/* lint */

extern unit_t		md_nunits;
extern unit_t		md_nsets;
extern md_set_t		md_set[];
extern int		md_status;
extern major_t		md_major;
extern mdq_anchor_t	md_done_daemon;
extern mdq_anchor_t	md_mstr_daemon;
extern int		md_sleep_for_test;
extern clock_t		md_hz;

extern md_event_queue_t	*md_event_queue;


int pchunks		= 16;
int phigh		= 1024;
int plow		= 128;
int cchunks		= 64;
int chigh		= 1024;
int clow		= 512;
int bchunks		= 32;
int bhigh		= 256;
int blow		= 128;

int raid_total_io		= 0;
int raid_reads			= 0;
int raid_writes			= 0;
int raid_no_bpmaps		= 0;
int raid_512			= 0;
int raid_1024			= 0;
int raid_1024_8192		= 0;
int raid_8192			= 0;
int raid_8192_bigger		= 0;
int raid_line_lock_wait	= 0;

int data_buffer_waits		= 0;
int parity_buffer_waits	= 0;

/* writer line locks */
int raid_writer_locks		= 0; /* total writer locks */
int raid_write_waits		= 0; /* total writer locks that waited */
int raid_full_line_writes	= 0; /* total full line writes */
int raid_write_queue_length	= 0; /* wait queue length */
int raid_max_write_q_length	= 0; /* maximum queue length */
int raid_write_locks_active	= 0; /* writer locks at any time */
int raid_max_write_locks	= 0; /* maximum writer locks active */

/* read line locks */
int raid_reader_locks		= 0; /* total reader locks held */
int raid_reader_locks_active	= 0; /* reader locks held */
int raid_max_reader_locks	= 0; /* maximum reader locks held in run */
int raid_read_overlaps		= 0; /* number of times 2 reads hit same line */
int raid_read_waits		= 0; /* times a reader waited on writer */

/* prewrite stats */
int raid_prewrite_waits		= 0; /* number of waits for a pw slot */
int raid_pw			= 0; /* number of pw slots in use */
int raid_prewrite_max		= 0; /* maximum number of pw slots in use */
int raid_pw_invalidates		= 0;

static clock_t md_wr_wait	= 0;

int nv_available	= 0; /* presence of nv-ram support in device */
int nv_prewrite		= 1; /* mark prewrites with nv_available */
int nv_parity		= 1; /* mark parity with nv_available */

kmem_cache_t	*raid_parent_cache = NULL;
kmem_cache_t	*raid_child_cache = NULL;
kmem_cache_t	*raid_cbuf_cache = NULL;

int			raid_internal_open(minor_t mnum, int flag, int otyp,
			    int md_oflags);

static void		freebuffers(md_raidcs_t *cs);
static int		raid_read(mr_unit_t *un, md_raidcs_t *cs);
static void		raid_read_io(mr_unit_t *un, md_raidcs_t *cs);
static int		raid_write(mr_unit_t *un, md_raidcs_t *cs);
static void		raid_write_io(mr_unit_t *un, md_raidcs_t *cs);
static void		raid_stage(md_raidcs_t *cs);
static void		raid_enqueue(md_raidcs_t *cs);
static diskaddr_t	raid_line(diskaddr_t segment, mr_unit_t *un);
uint_t			raid_dcolumn(diskaddr_t segment, mr_unit_t *un);
static void		getpbuffer(md_raidcs_t *cs);
static void		getdbuffer(md_raidcs_t *cs);
static void		raid_done(buf_t *bp);
static void		raid_io_startup(mr_unit_t *un);

static rus_state_t
raid_col2unit(rcs_state_t state, rus_state_t unitstate)
{
	switch (state) {
	case RCS_INIT:
		return (RUS_INIT);
	case RCS_OKAY:
		return (RUS_OKAY);
	case RCS_RESYNC:
		if (unitstate & RUS_LAST_ERRED)
			return (RUS_LAST_ERRED);
		else
			return (RUS_ERRED);
	case RCS_ERRED:
		return (RUS_ERRED);
	case RCS_LAST_ERRED:
		return (RUS_ERRED);
	default:
		break;
	}
	panic("raid_col2unit");
	/*NOTREACHED*/
}

void
raid_set_state(mr_unit_t *un, int col, rcs_state_t newstate, int force)
{

	rus_state_t	unitstate, origstate;
	rcs_state_t	colstate;
	rcs_state_t	orig_colstate;
	int		errcnt = 0, okaycnt = 0, resynccnt = 0;
	int		i;
	char		*devname;

	ASSERT(un);
	ASSERT(col < un->un_totalcolumncnt);
	ASSERT(newstate &
	    (RCS_INIT | RCS_INIT_ERRED | RCS_OKAY | RCS_RESYNC | RCS_ERRED |
	    RCS_LAST_ERRED | RCS_REGEN));
	ASSERT((newstate &
	    ~(RCS_INIT | RCS_INIT_ERRED | RCS_OKAY | RCS_RESYNC | RCS_ERRED |
	    RCS_LAST_ERRED | RCS_REGEN))
	    == 0);

	ASSERT(MDI_UNIT(MD_SID(un)) ? UNIT_WRITER_HELD(un) : 1);

	unitstate = un->un_state;
	origstate = unitstate;

	if (force) {
		un->un_column[col].un_devstate = newstate;
		un->un_state = raid_col2unit(newstate, unitstate);
		uniqtime32(&un->un_column[col].un_devtimestamp);
		uniqtime32(&un->un_timestamp);
		return;
	}

	ASSERT(un->un_state &
	    (RUS_INIT | RUS_OKAY | RUS_ERRED | RUS_DOI | RUS_LAST_ERRED |
	    RUS_REGEN));
	ASSERT((un->un_state & ~(RUS_INIT |
	    RUS_OKAY | RUS_ERRED | RUS_DOI | RUS_LAST_ERRED | RUS_REGEN)) == 0);

	if (un->un_column[col].un_devstate == newstate)
		return;

	if (newstate == RCS_REGEN) {
		if (raid_state_cnt(un, RCS_OKAY) != un->un_totalcolumncnt)
			return;
		un->un_state = RUS_REGEN;
		return;
	}

	orig_colstate = un->un_column[col].un_devstate;

	/*
	 * if there is another column in the error state then this
	 * column should go to the last errored state
	 */
	for (i = 0; i < un->un_totalcolumncnt; i++) {
		if (i == col)
			colstate = newstate;
		else
			colstate = un->un_column[i].un_devstate;
		if (colstate & (RCS_ERRED | RCS_LAST_ERRED | RCS_INIT_ERRED))
			errcnt++;
		if (colstate & RCS_OKAY)
			okaycnt++;
		if (colstate & RCS_RESYNC)
			resynccnt++;
	}
	ASSERT(resynccnt < 2);

	if (okaycnt == un->un_totalcolumncnt)
		unitstate = RUS_OKAY;
	else if (errcnt > 1) {
		unitstate = RUS_LAST_ERRED;
		if (newstate & RCS_ERRED)
			newstate = RCS_LAST_ERRED;
	} else if (errcnt == 1)
		if (!(unitstate & RUS_LAST_ERRED))
			unitstate = RUS_ERRED;

	if (un->un_state == RUS_DOI)
		unitstate = RUS_DOI;

	un->un_column[col].un_devstate = newstate;
	uniqtime32(&un->un_column[col].un_devtimestamp);
	/*
	 * if there are last errored column being brought back online
	 * by open or snarf, then be sure to clear the RUS_LAST_ERRED
	 * bit to allow writes.  If there is a real error then the
	 * column will go back into last erred.
	 */
	if ((raid_state_cnt(un, RCS_LAST_ERRED) == 0) &&
	    (raid_state_cnt(un, RCS_ERRED) == 1))
		unitstate = RUS_ERRED;

	un->un_state = unitstate;
	uniqtime32(&un->un_timestamp);

	if ((! (origstate & (RUS_ERRED|RUS_LAST_ERRED|RUS_DOI))) &&
	    (unitstate & (RUS_ERRED|RUS_LAST_ERRED|RUS_DOI))) {
		devname = md_devname(MD_UN2SET(un),
		    un->un_column[col].un_dev, NULL, 0);

		cmn_err(CE_WARN, "md: %s: %s needs maintenance",
		    md_shortname(MD_SID(un)), devname);

		if (unitstate & RUS_LAST_ERRED) {
			cmn_err(CE_WARN, "md: %s: %s last erred",
			    md_shortname(MD_SID(un)), devname);

		} else if (un->un_column[col].un_devflags &
		    MD_RAID_DEV_ISOPEN) {
			/*
			 * Close the broken device and clear the open flag on
			 * it.  We have to check that the device is open,
			 * otherwise the first open on it has resulted in the
			 * error that is being processed and the actual un_dev
			 * will be NODEV64.
			 */
			md_layered_close(un->un_column[col].un_dev,
			    MD_OFLG_NULL);
			un->un_column[col].un_devflags &= ~MD_RAID_DEV_ISOPEN;
		}
	} else if (orig_colstate == RCS_LAST_ERRED && newstate == RCS_ERRED &&
	    un->un_column[col].un_devflags & MD_RAID_DEV_ISOPEN) {
		/*
		 * Similar to logic above except no log messages since we
		 * are just transitioning from Last Erred to Erred.
		 */
		md_layered_close(un->un_column[col].un_dev, MD_OFLG_NULL);
		un->un_column[col].un_devflags &= ~MD_RAID_DEV_ISOPEN;
	}

	/*
	 * If a resync has completed, see if there is a Last Erred
	 * component that we can change to the Erred state.
	 */
	if ((orig_colstate == RCS_RESYNC) && (newstate == RCS_OKAY)) {
		for (i = 0; i < un->un_totalcolumncnt; i++) {
			if (i != col &&
			    (un->un_column[i].un_devstate & RCS_LAST_ERRED)) {
				raid_set_state(un, i, RCS_ERRED, 0);
				break;
			}
		}
	}
}

/*
 * NAME:	erred_check_line
 *
 * DESCRIPTION: Return the type of write to perform on an erred column based
 *		upon any resync activity.
 *
 *		if a column is being resynced and the write is above the
 *		resync point may have to write to the target being resynced.
 *
 *		Column state may make it impossible to do the write
 *		in which case RCL_EIO or RCL_ENXIO is returned.
 *
 *		If a column cannot be written directly, RCL_ERRED is
 *		returned and processing should proceed accordingly.
 *
 * PARAMETERS:	minor_t		 mnum - minor number identity of metadevice
 *		md_raidcs_t	 *cs - child save structure
 *		mr_column_t	 *dcolumn - pointer to data column structure
 *		mr_column_t	 *pcolumn - pointer to parity column structure
 *
 * RETURNS:	RCL_OKAY, RCL_ERRED
 *
 * LOCKS:	Expects Line Writer Lock and Unit Resource Lock to be held
 *		across call.
 */

static int
erred_check_line(mr_unit_t *un, md_raidcs_t *cs, mr_column_t *column)
{

	ASSERT(un != NULL);
	ASSERT(cs->cs_flags & MD_RCS_LLOCKD);

	if (column->un_devstate & RCS_OKAY)
		return (RCL_OKAY);

	if (column->un_devstate & RCS_ERRED)
		return (RCL_ERRED);  /* do not read from errored disk */

	/*
	 * for the last errored case their are two considerations.
	 * When the last errored column is the only errored column then
	 * do treat it like a maintenance column, not doing I/O from
	 * it.   When it there are other failures then just attempt
	 * to use it.
	 */
	if (column->un_devstate & RCS_LAST_ERRED)
		return (RCL_ERRED);

	ASSERT(column->un_devstate & RCS_RESYNC);

	/*
	 * When a resync from a hotspare is being done (copy resync)
	 * then always treat it as an OKAY column, since no regen
	 * is required.
	 */
	if (column->un_devflags & MD_RAID_COPY_RESYNC) {
		return (RCL_OKAY);
	}

	mutex_enter(&un->un_mx);
	if (cs->cs_line < un->un_resync_line_index) {
		mutex_exit(&un->un_mx);
		return (RCL_OKAY);
	}
	mutex_exit(&un->un_mx);
	return (RCL_ERRED);

}

/*
 * NAMES:	raid_state_cnt
 *
 * DESCRIPTION: counts number of column in a specific state
 *
 * PARAMETERS:	md_raid_t *un
 *		rcs_state state
 */
int
raid_state_cnt(mr_unit_t *un, rcs_state_t state)
{
	int	i, retval = 0;

	for (i = 0; i < un->un_totalcolumncnt; i++)
		if (un->un_column[i].un_devstate & state)
			retval++;
	return (retval);
}

/*
 * NAMES:	raid_io_overlaps
 *
 * DESCRIPTION: checkst for overlap of 2 child save structures
 *
 * PARAMETERS:	md_raidcs_t cs1
 *		md_raidcs_t cs2
 *
 * RETURNS:	0 - no overlap
 *		1 - overlap
 */
int
raid_io_overlaps(md_raidcs_t *cs1, md_raidcs_t *cs2)
{
	if (cs1->cs_blkno > cs2->cs_lastblk)
		return (0);
	if (cs1->cs_lastblk < cs2->cs_blkno)
		return (0);
	return (1);
}

/*
 * NAMES:	raid_parent_constructor
 * DESCRIPTION: parent structure constructor routine
 * PARAMETERS:
 */
/*ARGSUSED1*/
static int
raid_parent_constructor(void *p, void *d1, int d2)
{
	mutex_init(&((md_raidps_t *)p)->ps_mx,
	    NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&((md_raidps_t *)p)->ps_mapin_mx,
	    NULL, MUTEX_DEFAULT, NULL);
	return (0);
}

void
raid_parent_init(md_raidps_t *ps)
{
	bzero(ps, offsetof(md_raidps_t, ps_mx));
	((md_raidps_t *)ps)->ps_flags = MD_RPS_INUSE;
	((md_raidps_t *)ps)->ps_magic = RAID_PSMAGIC;
}

/*ARGSUSED1*/
static void
raid_parent_destructor(void *p, void *d)
{
	mutex_destroy(&((md_raidps_t *)p)->ps_mx);
	mutex_destroy(&((md_raidps_t *)p)->ps_mapin_mx);
}

/*
 * NAMES:	raid_child_constructor
 * DESCRIPTION: child structure constructor routine
 * PARAMETERS:
 */
/*ARGSUSED1*/
static int
raid_child_constructor(void *p, void *d1, int d2)
{
	md_raidcs_t	*cs = (md_raidcs_t *)p;
	mutex_init(&cs->cs_mx, NULL, MUTEX_DEFAULT, NULL);
	bioinit(&cs->cs_dbuf);
	bioinit(&cs->cs_pbuf);
	bioinit(&cs->cs_hbuf);
	return (0);
}

void
raid_child_init(md_raidcs_t *cs)
{
	bzero(cs, offsetof(md_raidcs_t, cs_mx));

	md_bioreset(&cs->cs_dbuf);
	md_bioreset(&cs->cs_pbuf);
	md_bioreset(&cs->cs_hbuf);

	((md_raidcs_t *)cs)->cs_dbuf.b_chain =
	    ((md_raidcs_t *)cs)->cs_pbuf.b_chain =
	    ((md_raidcs_t *)cs)->cs_hbuf.b_chain =
	    (struct buf *)(cs);

	cs->cs_magic = RAID_CSMAGIC;
	cs->cs_line = MD_DISKADDR_ERROR;
	cs->cs_dpwslot = -1;
	cs->cs_ppwslot = -1;
}

/*ARGSUSED1*/
static void
raid_child_destructor(void *p, void *d)
{
	biofini(&((md_raidcs_t *)p)->cs_dbuf);
	biofini(&((md_raidcs_t *)p)->cs_hbuf);
	biofini(&((md_raidcs_t *)p)->cs_pbuf);
	mutex_destroy(&((md_raidcs_t *)p)->cs_mx);
}

/*ARGSUSED1*/
static int
raid_cbuf_constructor(void *p, void *d1, int d2)
{
	bioinit(&((md_raidcbuf_t *)p)->cbuf_bp);
	return (0);
}

static void
raid_cbuf_init(md_raidcbuf_t *cb)
{
	bzero(cb, offsetof(md_raidcbuf_t, cbuf_bp));
	md_bioreset(&cb->cbuf_bp);
	cb->cbuf_magic = RAID_BUFMAGIC;
	cb->cbuf_pwslot = -1;
	cb->cbuf_flags = CBUF_WRITE;
}

/*ARGSUSED1*/
static void
raid_cbuf_destructor(void *p, void *d)
{
	biofini(&((md_raidcbuf_t *)p)->cbuf_bp);
}

/*
 * NAMES:	raid_run_queue
 * DESCRIPTION: spawn a backend processing daemon for RAID metadevice.
 * PARAMETERS:
 */
/*ARGSUSED*/
static void
raid_run_queue(void *d)
{
	if (!(md_status & MD_GBL_DAEMONS_LIVE))
		md_daemon(1, &md_done_daemon);
}

/*
 * NAME:	raid_build_pwslot
 * DESCRIPTION: builds mr_pw_reserve for the column
 * PARAMETERS:	un is the pointer to the unit structure
 *		colindex is the column to create the structure for
 */
int
raid_build_pw_reservation(mr_unit_t *un, int colindex)
{
	mr_pw_reserve_t	*pw;
	mr_scoreboard_t	*sb;
	int		i;

	pw = (mr_pw_reserve_t *) kmem_zalloc(sizeof (mr_pw_reserve_t) +
	    (sizeof (mr_scoreboard_t) * un->un_pwcnt), KM_SLEEP);
	pw->pw_magic = RAID_PWMAGIC;
	pw->pw_column = colindex;
	pw->pw_free = un->un_pwcnt;
	sb = &pw->pw_sb[0];
	for (i = 0; i < un->un_pwcnt; i++) {
		sb[i].sb_column = colindex;
		sb[i].sb_flags = SB_UNUSED;
		sb[i].sb_start_blk = 0;
		sb[i].sb_last_blk = 0;
		sb[i].sb_cs = NULL;
	}
	un->un_column_ic[colindex].un_pw_reserve = pw;
	return (0);
}
/*
 * NAME:	raid_free_pw_reservation
 * DESCRIPTION: RAID metadevice pre-write slot structure destroy routine
 * PARAMETERS:	mr_unit_t *un - pointer to a unit structure
 *		int colindex  - index of the column whose pre-write slot struct
 *			is to be destroyed.
 */
void
raid_free_pw_reservation(mr_unit_t *un, int colindex)
{
	mr_pw_reserve_t	*pw = un->un_column_ic[colindex].un_pw_reserve;

	kmem_free(pw, sizeof (mr_pw_reserve_t) +
	    (sizeof (mr_scoreboard_t) * un->un_pwcnt));
}

/*
 * NAME:	raid_cancel_pwslot
 * DESCRIPTION: RAID metadevice write routine
 * PARAMETERS:	md_raidcs_t *cs - pointer to a child structure
 */
static void
raid_cancel_pwslot(md_raidcs_t *cs)
{
	mr_unit_t		*un = cs->cs_un;
	mr_pw_reserve_t		*pw;
	mr_scoreboard_t		*sb;
	mr_column_ic_t		*col;
	md_raidcbuf_t		*cbuf;
	int			broadcast = 0;

	if (cs->cs_ps->ps_flags & MD_RPS_READ)
		return;
	if (cs->cs_dpwslot != -1) {
		col = &un->un_column_ic[cs->cs_dcolumn];
		pw = col->un_pw_reserve;
		sb = &pw->pw_sb[cs->cs_dpwslot];
		sb->sb_flags = SB_AVAIL;
		if ((pw->pw_free++ == 0) || (un->un_rflags & MD_RFLAG_NEEDPW))
			broadcast++;
		sb->sb_cs = NULL;
	}

	if (cs->cs_ppwslot != -1) {
		col = &un->un_column_ic[cs->cs_pcolumn];
		pw = col->un_pw_reserve;
		sb = &pw->pw_sb[cs->cs_ppwslot];
		sb->sb_flags = SB_AVAIL;
		if ((pw->pw_free++ == 0) || (un->un_rflags & MD_RFLAG_NEEDPW))
			broadcast++;
		sb->sb_cs = NULL;
	}

	for (cbuf = cs->cs_buflist; cbuf; cbuf = cbuf->cbuf_next) {
		if (cbuf->cbuf_pwslot == -1)
			continue;
		col = &un->un_column_ic[cbuf->cbuf_column];
		pw = col->un_pw_reserve;
		sb = &pw->pw_sb[cbuf->cbuf_pwslot];
		sb->sb_flags = SB_AVAIL;
		if ((pw->pw_free++ == 0) || (un->un_rflags & MD_RFLAG_NEEDPW))
			broadcast++;
		sb->sb_cs = NULL;
	}
	if (broadcast) {
		cv_broadcast(&un->un_cv);
		return;
	}
	mutex_enter(&un->un_mx);
	if (un->un_rflags & MD_RFLAG_NEEDPW)
		cv_broadcast(&un->un_cv);
	mutex_exit(&un->un_mx);
}

static void
raid_free_pwinvalidate(md_raidcs_t *cs)
{
	md_raidcbuf_t		*cbuf;
	md_raidcbuf_t		*cbuf_to_free;
	mr_unit_t		*un = cs->cs_un;
	mdi_unit_t		*ui = MDI_UNIT(MD_SID(un));
	mr_pw_reserve_t		*pw;
	mr_scoreboard_t		*sb;
	int			broadcast = 0;

	cbuf = cs->cs_pw_inval_list;
	ASSERT(cbuf);
	mutex_enter(&un->un_linlck_mx);
	while (cbuf) {
		pw = un->un_column_ic[cbuf->cbuf_column].un_pw_reserve;
		sb = &pw->pw_sb[0];
		ASSERT(sb[cbuf->cbuf_pwslot].sb_flags & SB_INVAL_PEND);
		sb[cbuf->cbuf_pwslot].sb_flags = SB_UNUSED;
		sb[cbuf->cbuf_pwslot].sb_cs = NULL;
		if ((pw->pw_free++ == 0) || (un->un_rflags & MD_RFLAG_NEEDPW))
			broadcast++;
		cbuf_to_free = cbuf;
		cbuf = cbuf->cbuf_next;
		kmem_free(cbuf_to_free->cbuf_buffer, dbtob(un->un_iosize));
		kmem_cache_free(raid_cbuf_cache, cbuf_to_free);
	}
	cs->cs_pw_inval_list = (md_raidcbuf_t *)NULL;
	/*
	 * now that there is a free prewrite slot, check to see if there
	 * are any io operations waiting first wake up the raid_io_startup
	 * then signal the the processes waiting in raid_write.
	 */
	if (ui->ui_io_lock->io_list_front)
		raid_io_startup(un);
	mutex_exit(&un->un_linlck_mx);
	if (broadcast) {
		cv_broadcast(&un->un_cv);
		return;
	}
	mutex_enter(&un->un_mx);
	if (un->un_rflags & MD_RFLAG_NEEDPW)
		cv_broadcast(&un->un_cv);
	mutex_exit(&un->un_mx);
}


static int
raid_get_pwslot(md_raidcs_t *cs, int column)
{
	mr_scoreboard_t	*sb;
	mr_pw_reserve_t	*pw;
	mr_unit_t	*un = cs->cs_un;
	diskaddr_t	start_blk = cs->cs_blkno;
	diskaddr_t	last_blk = cs->cs_lastblk;
	int		i;
	int		pwcnt = un->un_pwcnt;
	int		avail = -1;
	int		use = -1;
	int		flags;


	/* start with the data column */
	pw = cs->cs_un->un_column_ic[column].un_pw_reserve;
	sb = &pw->pw_sb[0];
	ASSERT(pw->pw_free > 0);
	for (i = 0; i < pwcnt; i++) {
		flags = sb[i].sb_flags;
		if (flags & SB_INVAL_PEND)
			continue;

		if ((avail == -1) && (flags & (SB_AVAIL | SB_UNUSED)))
			avail = i;

		if ((start_blk > sb[i].sb_last_blk) ||
		    (last_blk < sb[i].sb_start_blk))
			continue;

		/* OVERLAP */
		ASSERT(! (sb[i].sb_flags & SB_INUSE));

		/*
		 * raid_invalidate_pwslot attempts to zero out prewrite entry
		 * in parallel with other disk reads/writes related to current
		 * transaction. however cs_frags accounting for this case is
		 * broken because raid_write_io resets cs_frags i.e. ignoring
		 * that it could have been been set to > 0 value by
		 * raid_invalidate_pwslot. While this can be fixed an
		 * additional problem is that we don't seem to handle
		 * correctly the case of getting a disk error for prewrite
		 * entry invalidation.
		 * It does not look like we really need
		 * to invalidate prewrite slots because raid_replay sorts
		 * prewrite id's in ascending order and during recovery the
		 * latest prewrite entry for the same block will be replay
		 * last. That's why i ifdef'd out the call to
		 * raid_invalidate_pwslot. --aguzovsk@east
		 */

		if (use == -1) {
			use = i;
		}
	}

	ASSERT(avail != -1);
	pw->pw_free--;
	if (use == -1)
		use = avail;

	ASSERT(! (sb[use].sb_flags & SB_INUSE));
	sb[use].sb_flags = SB_INUSE;
	sb[use].sb_cs = cs;
	sb[use].sb_start_blk = start_blk;
	sb[use].sb_last_blk = last_blk;
	ASSERT((use >= 0) && (use < un->un_pwcnt));
	return (use);
}

static int
raid_check_pw(md_raidcs_t *cs)
{

	mr_unit_t	*un = cs->cs_un;
	int		i;

	ASSERT(! (cs->cs_flags & MD_RCS_HAVE_PW_SLOTS));
	/*
	 * check to be sure there is a prewrite slot available
	 * if not just return.
	 */
	if (cs->cs_flags & MD_RCS_LINE) {
		for (i = 0; i < un->un_totalcolumncnt; i++)
			if (un->un_column_ic[i].un_pw_reserve->pw_free <= 0)
				return (1);
		return (0);
	}

	if (un->un_column_ic[cs->cs_dcolumn].un_pw_reserve->pw_free <= 0)
		return (1);
	if (un->un_column_ic[cs->cs_pcolumn].un_pw_reserve->pw_free <= 0)
		return (1);
	return (0);
}
static int
raid_alloc_pwslot(md_raidcs_t *cs)
{
	mr_unit_t	*un = cs->cs_un;
	md_raidcbuf_t	*cbuf;

	ASSERT(! (cs->cs_flags & MD_RCS_HAVE_PW_SLOTS));
	if (raid_check_pw(cs))
		return (1);

	mutex_enter(&un->un_mx);
	un->un_pwid++;
	cs->cs_pwid = un->un_pwid;
	mutex_exit(&un->un_mx);

	cs->cs_dpwslot = raid_get_pwslot(cs, cs->cs_dcolumn);
	for (cbuf = cs->cs_buflist; cbuf; cbuf = cbuf->cbuf_next) {
		cbuf->cbuf_pwslot = raid_get_pwslot(cs, cbuf->cbuf_column);
	}
	cs->cs_ppwslot = raid_get_pwslot(cs, cs->cs_pcolumn);

	cs->cs_flags |= MD_RCS_HAVE_PW_SLOTS;

	return (0);
}

/*
 * NAMES:	raid_build_incore
 * DESCRIPTION: RAID metadevice incore structure building routine
 * PARAMETERS:	void *p - pointer to a unit structure
 *		int snarfing - a flag to indicate snarfing is required
 */
int
raid_build_incore(void *p, int snarfing)
{
	mr_unit_t	*un = (mr_unit_t *)p;
	minor_t		mnum = MD_SID(un);
	mddb_recid_t	hs_recid = 0;
	int		i;
	int		preserve_flags;
	mr_column_t	*column;
	int		iosize;
	md_dev64_t	hs, dev;
	int		resync_cnt = 0, error_cnt = 0;

	hs = NODEV64;
	dev = NODEV64;

	/* clear out bogus pointer incase we return(1) prior to alloc */
	un->mr_ic = NULL;

	if (MD_STATUS(un) & MD_UN_BEING_RESET) {
		mddb_setrecprivate(un->c.un_record_id, MD_PRV_PENDCLEAN);
		return (1);
	}

	if (MD_UNIT(mnum) != NULL)
		return (0);

	if (snarfing)
		MD_STATUS(un) = 0;

	un->mr_ic = (mr_unit_ic_t *)kmem_zalloc(sizeof (*un->mr_ic),
	    KM_SLEEP);

	un->un_column_ic = (mr_column_ic_t *)
	    kmem_zalloc(sizeof (mr_column_ic_t) *
	    un->un_totalcolumncnt, KM_SLEEP);

	for (i = 0; i < un->un_totalcolumncnt; i++) {

		column	= &un->un_column[i];
		preserve_flags = column->un_devflags &
		    (MD_RAID_COPY_RESYNC | MD_RAID_REGEN_RESYNC);
		column->un_devflags &=
		    ~(MD_RAID_ALT_ISOPEN | MD_RAID_DEV_ISOPEN |
		    MD_RAID_WRITE_ALT);
		if (raid_build_pw_reservation(un, i) != 0) {
			/* could not build pwslot */
			return (1);
		}

		if (snarfing) {
			set_t		setno = MD_MIN2SET(mnum);
			dev =  md_getdevnum(setno, mddb_getsidenum(setno),
			    column->un_orig_key, MD_NOTRUST_DEVT);
			/*
			 * Comment out instead of remove so we have history
			 * In the pre-SVM releases stored devt is used so
			 * as long as there is one snarf is always happy
			 * even the component is powered off.  This is not
			 * the case in current SVM implementation.  NODEV64
			 * can be returned and in this case since we resolve
			 * the devt at 'open' time (first use of metadevice)
			 * we will allow snarf continue.
			 *
			 * if (dev == NODEV64)
			 *	return (1);
			 */

			/*
			 * Setup un_orig_dev from device id info if the device
			 * is valid (not NODEV64).
			 */
			if (dev != NODEV64)
				column->un_orig_dev = dev;

			if (column->un_devstate & RCS_RESYNC)
				resync_cnt++;
			if (column->un_devstate & (RCS_ERRED | RCS_LAST_ERRED))
				error_cnt++;

			if (HOTSPARED(un, i)) {
				(void) md_hot_spare_ifc(HS_MKDEV,
				    0, 0, 0, &column->un_hs_id, NULL,
				    &hs, NULL);
				/*
				 * Same here
				 *
				 * if (hs == NODEV64)
				 *	return (1);
				 */
			}

			if (HOTSPARED(un, i)) {
				if (column->un_devstate &
				    (RCS_OKAY | RCS_LAST_ERRED)) {
					column->un_dev = hs;
					column->un_pwstart =
					    column->un_hs_pwstart;
					column->un_devstart =
					    column->un_hs_devstart;
					preserve_flags &=
					    ~(MD_RAID_COPY_RESYNC |
					    MD_RAID_REGEN_RESYNC);
				} else  if (column->un_devstate & RCS_RESYNC) {
					/*
					 * if previous system was 4.0 set
					 * the direction flags
					 */
					if ((preserve_flags &
					    (MD_RAID_COPY_RESYNC |
					    MD_RAID_REGEN_RESYNC)) == 0) {
						if (column->un_alt_dev !=
						    NODEV64)
							preserve_flags |=
							    MD_RAID_COPY_RESYNC;
						else
							preserve_flags |=
							   MD_RAID_REGEN_RESYNC;
					}
				}
			} else { /* no hot spares */
				column->un_dev = dev;
				column->un_pwstart = column->un_orig_pwstart;
				column->un_devstart = column->un_orig_devstart;
				if (column->un_devstate & RCS_RESYNC) {
					preserve_flags |= MD_RAID_REGEN_RESYNC;
					preserve_flags &= ~MD_RAID_COPY_RESYNC;
				}
			}
			if (! (column->un_devstate & RCS_RESYNC)) {
				preserve_flags &=
				    ~(MD_RAID_REGEN_RESYNC |
				    MD_RAID_COPY_RESYNC);
			}

			column->un_devflags = preserve_flags;
			column->un_alt_dev = NODEV64;
			column->un_alt_pwstart = 0;
			column->un_alt_devstart = 0;
			un->un_resync_line_index = 0;
			un->un_resync_index = 0;
			un->un_percent_done = 0;
		}
	}

	if (resync_cnt && error_cnt) {
		for (i = 0; i < un->un_totalcolumncnt; i++) {
			column  = &un->un_column[i];
			if (HOTSPARED(un, i) &&
			    (column->un_devstate & RCS_RESYNC) &&
			    (column->un_devflags & MD_RAID_COPY_RESYNC))
				/* hotspare has data */
				continue;

			if (HOTSPARED(un, i) &&
			    (column->un_devstate & RCS_RESYNC)) {
				/* hotspare does not have data */
				raid_hs_release(HS_FREE, un, &hs_recid, i);
				column->un_dev = column->un_orig_dev;
				column->un_pwstart = column->un_orig_pwstart;
				column->un_devstart = column->un_orig_devstart;
				mddb_setrecprivate(hs_recid, MD_PRV_PENDCOM);
			}

			if (column->un_devstate & RCS_ERRED)
				column->un_devstate = RCS_LAST_ERRED;

			if (column->un_devstate & RCS_RESYNC)
				column->un_devstate = RCS_ERRED;
		}
	}
	mddb_setrecprivate(un->c.un_record_id, MD_PRV_PENDCOM);

	un->un_pwid = 1; /* or some other possible value */
	un->un_magic = RAID_UNMAGIC;
	iosize = un->un_iosize;
	un->un_pbuffer = kmem_alloc(dbtob(iosize), KM_SLEEP);
	un->un_dbuffer = kmem_alloc(dbtob(iosize), KM_SLEEP);
	mutex_init(&un->un_linlck_mx, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&un->un_linlck_cv, NULL, CV_DEFAULT, NULL);
	un->un_linlck_chn = NULL;

	/* place various information in the in-core data structures */
	md_nblocks_set(mnum, un->c.un_total_blocks);
	MD_UNIT(mnum) = un;

	return (0);
}

/*
 * NAMES:	reset_raid
 * DESCRIPTION: RAID metadevice reset routine
 * PARAMETERS:	mr_unit_t *un - pointer to a unit structure
 *		minor_t mnum - RAID metadevice minor number
 *		int removing - a flag to imply removing device name from
 *			MDDB database.
 */
void
reset_raid(mr_unit_t *un, minor_t mnum, int removing)
{
	int		i, n = 0;
	sv_dev_t	*sv;
	mr_column_t	*column;
	int		column_cnt = un->un_totalcolumncnt;
	mddb_recid_t	*recids, vtoc_id;
	int		hserr;

	ASSERT((MDI_UNIT(mnum)->ui_io_lock->io_list_front == NULL) &&
	    (MDI_UNIT(mnum)->ui_io_lock->io_list_back == NULL));

	md_destroy_unit_incore(mnum, &raid_md_ops);

	md_nblocks_set(mnum, -1ULL);
	MD_UNIT(mnum) = NULL;

	if (un->un_pbuffer) {
		kmem_free(un->un_pbuffer, dbtob(un->un_iosize));
		un->un_pbuffer = NULL;
	}
	if (un->un_dbuffer) {
		kmem_free(un->un_dbuffer, dbtob(un->un_iosize));
		un->un_dbuffer = NULL;
	}

	/* free all pre-write slots created during build incore */
	for (i = 0; i < un->un_totalcolumncnt; i++)
		raid_free_pw_reservation(un, i);

	kmem_free(un->un_column_ic, sizeof (mr_column_ic_t) *
	    un->un_totalcolumncnt);

	kmem_free(un->mr_ic, sizeof (*un->mr_ic));

	/*
	 * Attempt release of its minor node
	 */
	md_remove_minor_node(mnum);

	if (!removing)
		return;

	sv = (sv_dev_t *)kmem_zalloc((column_cnt + 1) * sizeof (sv_dev_t),
	    KM_SLEEP);

	recids = (mddb_recid_t *)
	    kmem_zalloc((column_cnt + 2) * sizeof (mddb_recid_t), KM_SLEEP);

	for (i = 0; i < column_cnt; i++) {
		md_unit_t	*comp_un;
		md_dev64_t	comp_dev;

		column = &un->un_column[i];
		sv[i].setno = MD_MIN2SET(mnum);
		sv[i].key = column->un_orig_key;
		if (HOTSPARED(un, i)) {
			if (column->un_devstate & (RCS_ERRED | RCS_LAST_ERRED))
				hserr = HS_BAD;
			else
				hserr = HS_FREE;
			raid_hs_release(hserr, un, &recids[n++], i);
		}
		/*
		 * deparent any metadevices.
		 * NOTE: currently soft partitions are the only metadevices
		 * allowed in RAID metadevices.
		 */
		comp_dev = column->un_dev;
		if (md_getmajor(comp_dev) == md_major) {
			comp_un = MD_UNIT(md_getminor(comp_dev));
			recids[n++] = MD_RECID(comp_un);
			md_reset_parent(comp_dev);
		}
	}
	/* decrement the reference count of the old hsp */
	if (un->un_hsp_id != -1)
		(void) md_hot_spare_ifc(HSP_DECREF, un->un_hsp_id, 0, 0,
		    &recids[n++], NULL, NULL, NULL);
	recids[n] = 0;
	MD_STATUS(un) |= MD_UN_BEING_RESET;
	vtoc_id = un->c.un_vtoc_id;

	raid_commit(un, recids);

	/*
	 * Remove self from the namespace
	 */
	if (un->c.un_revision & MD_FN_META_DEV) {
		(void) md_rem_selfname(un->c.un_self_id);
	}

	/* Remove the unit structure */
	mddb_deleterec_wrapper(un->c.un_record_id);

	/* Remove the vtoc, if present */
	if (vtoc_id)
		mddb_deleterec_wrapper(vtoc_id);
	md_rem_names(sv, column_cnt);
	kmem_free(sv, (column_cnt + 1) * sizeof (sv_dev_t));
	kmem_free(recids, (column_cnt + 2) * sizeof (mddb_recid_t));

	SE_NOTIFY(EC_SVM_CONFIG, ESC_SVM_DELETE, SVM_TAG_METADEVICE,
	    MD_MIN2SET(mnum), mnum);
}

/*
 * NAMES:	raid_error_parent
 * DESCRIPTION: mark a parent structure in error
 * PARAMETERS:	md_raidcs_t *cs - pointer to child structure
 *		int	error - error value to set
 * NOTE:	(TBR) - this routine currently is not in use.
 */
static void
raid_error_parent(md_raidps_t *ps, int error)
{
	mutex_enter(&ps->ps_mx);
	ps->ps_flags |= MD_RPS_ERROR;
	ps->ps_error = error;
	mutex_exit(&ps->ps_mx);
}

/*
 * The following defines tell raid_free_parent
 *	RFP_RLS_LOCK		release the unit reader lock when done.
 *	RFP_DECR_PWFRAGS	decrement ps_pwfrags
 *	RFP_DECR_FRAGS		decrement ps_frags
 *	RFP_DECR_READFRAGS	read keeps FRAGS and PWFRAGS in lockstep
 */
#define	RFP_RLS_LOCK		0x00001
#define	RFP_DECR_PWFRAGS	0x00002
#define	RFP_DECR_FRAGS		0x00004
#define	RFP_DECR_READFRAGS	(RFP_DECR_PWFRAGS | RFP_DECR_FRAGS)

/*
 * NAMES:	raid_free_parent
 * DESCRIPTION: free a parent structure
 * PARAMETERS:	md_raidcs_t *cs - pointer to child structure
 *		int	todo - indicates what needs to be done
 */
static void
raid_free_parent(md_raidps_t *ps, int todo)
{
	mdi_unit_t	*ui = ps->ps_ui;

	ASSERT(ps->ps_magic == RAID_PSMAGIC);
	ASSERT(ps->ps_flags & MD_RPS_INUSE);
	mutex_enter(&ps->ps_mx);
	if (todo & RFP_DECR_PWFRAGS) {
		ASSERT(ps->ps_pwfrags);
		ps->ps_pwfrags--;
		if (ps->ps_pwfrags == 0 && (! (ps->ps_flags & MD_RPS_IODONE))) {
			if (ps->ps_flags & MD_RPS_ERROR) {
				ps->ps_bp->b_flags |= B_ERROR;
				ps->ps_bp->b_error = ps->ps_error;
			}
			md_kstat_done(ui, ps->ps_bp, 0);
			biodone(ps->ps_bp);
			ps->ps_flags |= MD_RPS_IODONE;
		}
	}

	if (todo & RFP_DECR_FRAGS) {
		ASSERT(ps->ps_frags);
		ps->ps_frags--;
	}

	if (ps->ps_frags != 0) {
		mutex_exit(&ps->ps_mx);
		return;
	}

	ASSERT((ps->ps_frags == 0) && (ps->ps_pwfrags == 0));
	mutex_exit(&ps->ps_mx);

	if (todo & RFP_RLS_LOCK)
		md_io_readerexit(ui);

	if (panicstr) {
		ps->ps_flags |= MD_RPS_DONE;
		return;
	}

	if (ps->ps_flags & MD_RPS_HSREQ)
		(void) raid_hotspares();

	ASSERT(todo & RFP_RLS_LOCK);
	ps->ps_flags &= ~MD_RPS_INUSE;

	md_dec_iocount(MD_MIN2SET(ps->ps_un->c.un_self_id));

	kmem_cache_free(raid_parent_cache, ps);
}

/*
 * NAMES:	raid_free_child
 * DESCRIPTION: free a parent structure
 * PARAMETERS:	md_raidcs_t *cs - pointer to child structure
 *		int drop_locks	- 0 for no locks held
 * NOTE:	(TBR) - this routine currently is not in use.
 */
static void
raid_free_child(md_raidcs_t *cs, int drop_locks)
{
	mr_unit_t	*un = cs->cs_un;
	md_raidcbuf_t	*cbuf, *cbuf1;

	if (cs->cs_pw_inval_list)
		raid_free_pwinvalidate(cs);

	if (drop_locks) {
		ASSERT(cs->cs_flags & MD_RCS_LLOCKD &&
		    (cs->cs_flags & (MD_RCS_READER | MD_RCS_WRITER)));
		md_unit_readerexit(MDI_UNIT(MD_SID(un)));
		raid_line_exit(cs);
	} else {
		ASSERT(!(cs->cs_flags & MD_RCS_LLOCKD));
	}

	freebuffers(cs);
	cbuf = cs->cs_buflist;
	while (cbuf) {
		cbuf1 = cbuf->cbuf_next;
		kmem_cache_free(raid_cbuf_cache, cbuf);
		cbuf = cbuf1;
	}
	if (cs->cs_dbuf.b_flags & B_REMAPPED)
		bp_mapout(&cs->cs_dbuf);
	kmem_cache_free(raid_child_cache, cs);
}

/*
 * NAME:	raid_regen_parity
 *
 * DESCRIPTION:	This routine is used to regenerate the parity blocks
 *		for the entire raid device.  It is called from
 *		both the regen thread and the IO path.
 *
 *		On error the entire device is marked as in error by
 *		placing the erroring device in error and all other
 *		devices in last_errored.
 *
 * PARAMETERS:	md_raidcs_t	*cs
 */
void
raid_regen_parity(md_raidcs_t *cs)
{
	mr_unit_t	*un = cs->cs_un;
	mdi_unit_t	*ui = MDI_UNIT(un->c.un_self_id);
	caddr_t		buffer;
	caddr_t		parity_buffer;
	buf_t		*bp;
	uint_t		*dbuf, *pbuf;
	uint_t		colcnt = un->un_totalcolumncnt;
	int		column;
	int		parity_column = cs->cs_pcolumn;
	size_t		bcount;
	int		j;

	/*
	 * This routine uses the data and parity buffers allocated to a
	 * write.  In the case of a read the buffers are allocated and
	 * freed at the end.
	 */

	ASSERT(IO_READER_HELD(un));
	ASSERT(cs->cs_flags & MD_RCS_LLOCKD);
	ASSERT(UNIT_READER_HELD(un));

	if (raid_state_cnt(un, RCS_OKAY) != colcnt)
		return;

	if (cs->cs_flags & MD_RCS_READER) {
		getpbuffer(cs);
		getdbuffer(cs);
	}
	ASSERT(cs->cs_dbuffer && cs->cs_pbuffer);
	bcount = cs->cs_bcount;
	buffer = cs->cs_dbuffer;
	parity_buffer = cs->cs_pbuffer;
	bzero(parity_buffer, bcount);
	bp = &cs->cs_dbuf;
	for (column = 0; column < colcnt; column++) {
		if (column == parity_column)
			continue;
		reset_buf(bp, B_READ | B_BUSY, bcount);
		bp->b_un.b_addr = buffer;
		bp->b_edev = md_dev64_to_dev(un->un_column[column].un_dev);
		bp->b_lblkno = cs->cs_blkno + un->un_column[column].un_devstart;
		bp->b_bcount = bcount;
		bp->b_bufsize = bcount;
		(void) md_call_strategy(bp, MD_STR_NOTTOP, NULL);
		if (biowait(bp))
			goto bail;
		pbuf = (uint_t *)(void *)parity_buffer;
		dbuf = (uint_t *)(void *)buffer;
		for (j = 0; j < (bcount / (sizeof (uint_t))); j++) {
			*pbuf = *pbuf ^ *dbuf;
			pbuf++;
			dbuf++;
		}
	}

	reset_buf(bp, B_WRITE | B_BUSY, cs->cs_bcount);
	bp->b_un.b_addr = parity_buffer;
	bp->b_edev = md_dev64_to_dev(un->un_column[parity_column].un_dev);
	bp->b_lblkno = cs->cs_blkno + un->un_column[parity_column].un_devstart;
	bp->b_bcount = bcount;
	bp->b_bufsize = bcount;
	(void) md_call_strategy(bp, MD_STR_NOTTOP, NULL);
	if (biowait(bp))
		goto bail;

	if (cs->cs_flags & MD_RCS_READER) {
		freebuffers(cs);
		cs->cs_pbuffer = NULL;
		cs->cs_dbuffer = NULL;
	}
	bp->b_chain = (struct buf *)cs;
	return;
bail:
	if (cs->cs_flags & MD_RCS_READER) {
		freebuffers(cs);
		cs->cs_pbuffer = NULL;
		cs->cs_dbuffer = NULL;
	}
	md_unit_readerexit(ui);
	un = md_unit_writerlock(ui);
	raid_set_state(un, column, RCS_ERRED, 0);
	for (column = 0; column < colcnt; column++)
		raid_set_state(un, column, RCS_ERRED, 0);
	raid_commit(un, NULL);
	md_unit_writerexit(ui);
	un = md_unit_readerlock(ui);
	bp->b_chain = (struct buf *)cs;
}

/*
 * NAMES:	raid_error_state
 * DESCRIPTION: check unit and column states' impact on I/O error
 *		NOTE:	the state now may not be the state when the
 *			I/O completed due to race conditions.
 * PARAMETERS:	mr_unit_t *un - pointer to raid unit structure
 *		md_raidcs_t *cs - pointer to child structure
 *		buf_t	  *bp - pointer to buffer structure
 */
static int
raid_error_state(mr_unit_t *un, buf_t *bp)
{
	int		column;
	int		i;

	ASSERT(IO_READER_HELD(un));
	ASSERT(UNIT_WRITER_HELD(un));

	column = -1;
	for (i = 0; i < un->un_totalcolumncnt; i++) {
		if (un->un_column[i].un_dev == md_expldev(bp->b_edev)) {
			column = i;
			break;
		}
		if (un->un_column[i].un_alt_dev == md_expldev(bp->b_edev)) {
			column = i;
			break;
		}
	}

	/* in case a replace snuck in while waiting on unit writer lock */

	if (column == -1) {
		return (0);
	}

	(void) raid_set_state(un, column, RCS_ERRED, 0);
	ASSERT(un->un_state & (RUS_ERRED | RUS_LAST_ERRED));

	raid_commit(un, NULL);
	if (un->un_state & RUS_ERRED) {
		SE_NOTIFY(EC_SVM_STATE, ESC_SVM_ERRED, SVM_TAG_METADEVICE,
		    MD_UN2SET(un), MD_SID(un));
	} else if (un->un_state & RUS_LAST_ERRED) {
		SE_NOTIFY(EC_SVM_STATE, ESC_SVM_LASTERRED, SVM_TAG_METADEVICE,
		    MD_UN2SET(un), MD_SID(un));
	}

	return (EIO);
}

/*
 * NAME:	raid_mapin_buf
 * DESCRIPTION:	wait for the input buffer header to be maped in
 * PARAMETERS:	md_raidps_t *ps
 */
static void
raid_mapin_buf(md_raidcs_t *cs)
{
	md_raidps_t	*ps = cs->cs_ps;

	/*
	 * check to see if the buffer is maped.  If all is ok return the
	 * offset of the data and return.  Since it is expensive to grab
	 * a mutex this is only done if the mapin is not complete.
	 * Once the mutex is aquired it is possible that the mapin was
	 * not done so recheck and if necessary do the mapin.
	 */
	if (ps->ps_mapin > 0) {
		cs->cs_addr = ps->ps_addr + cs->cs_offset;
		return;
	}
	mutex_enter(&ps->ps_mapin_mx);
	if (ps->ps_mapin > 0) {
		cs->cs_addr = ps->ps_addr + cs->cs_offset;
		mutex_exit(&ps->ps_mapin_mx);
		return;
	}
	bp_mapin(ps->ps_bp);
	/*
	 * get the new b_addr out of the parent since bp_mapin just changed it
	 */
	ps->ps_addr = ps->ps_bp->b_un.b_addr;
	cs->cs_addr = ps->ps_addr + cs->cs_offset;
	ps->ps_mapin++;
	mutex_exit(&ps->ps_mapin_mx);
}

/*
 * NAMES:	raid_read_no_retry
 * DESCRIPTION: I/O retry routine for a RAID metadevice read
 *		read failed attempting to regenerate the data,
 *		no retry possible, error occured in raid_raidregenloop().
 * PARAMETERS:	mr_unit_t   *un - pointer to raid unit structure
 *		md_raidcs_t *cs - pointer to child structure
 */
/*ARGSUSED*/
static void
raid_read_no_retry(mr_unit_t *un, md_raidcs_t *cs)
{
	md_raidps_t	*ps = cs->cs_ps;

	raid_error_parent(ps, EIO);
	raid_free_child(cs, 1);

	/* decrement readfrags */
	raid_free_parent(ps, RFP_DECR_READFRAGS | RFP_RLS_LOCK);
}

/*
 * NAMES:	raid_read_retry
 * DESCRIPTION: I/O retry routine for a RAID metadevice read
 * PARAMETERS:	md_raidcs_t *cs - pointer to child structure
 */
static void
raid_read_retry(mr_unit_t *un, md_raidcs_t *cs)
{
	/* re-initialize the buf_t structure for raid_read() */
	cs->cs_dbuf.b_chain = (struct buf *)cs;
	cs->cs_dbuf.b_back = &cs->cs_dbuf;
	cs->cs_dbuf.b_forw = &cs->cs_dbuf;
	cs->cs_dbuf.b_flags = B_BUSY;	/* initialize flags */
	cs->cs_dbuf.b_error = 0;	/* initialize error */
	cs->cs_dbuf.b_offset = -1;
	/* Initialize semaphores */
	sema_init(&cs->cs_dbuf.b_io, 0, NULL,
	    SEMA_DEFAULT, NULL);
	sema_init(&cs->cs_dbuf.b_sem, 0, NULL,
	    SEMA_DEFAULT, NULL);

	cs->cs_pbuf.b_chain = (struct buf *)cs;
	cs->cs_pbuf.b_back = &cs->cs_pbuf;
	cs->cs_pbuf.b_forw = &cs->cs_pbuf;
	cs->cs_pbuf.b_flags = B_BUSY;	/* initialize flags */
	cs->cs_pbuf.b_error = 0;	/* initialize error */
	cs->cs_pbuf.b_offset = -1;
	sema_init(&cs->cs_pbuf.b_io, 0, NULL,
	    SEMA_DEFAULT, NULL);
	sema_init(&cs->cs_pbuf.b_sem, 0, NULL,
	    SEMA_DEFAULT, NULL);

	cs->cs_flags &= ~MD_RCS_ERROR;	/* reset child error flag */
	cs->cs_flags |= MD_RCS_RECOVERY;  /* set RECOVERY flag */

	/*
	 * re-scheduling I/O with raid_read_io() is simpler. basically,
	 * raid_read_io() is invoked again with same child structure.
	 * (NOTE: we aren`t supposed to do any error recovery when an I/O
	 * error occured in raid_raidregenloop().
	 */
	raid_mapin_buf(cs);
	raid_read_io(un, cs);
}

/*
 * NAMES:	raid_rderr
 * DESCRIPTION: I/O error handling routine for a RAID metadevice read
 * PARAMETERS:	md_raidcs_t *cs - pointer to child structure
 * LOCKS:	must obtain unit writer lock while calling raid_error_state
 *		since a unit or column state transition may take place.
 *		must obtain unit reader lock to retry I/O.
 */
/*ARGSUSED*/
static void
raid_rderr(md_raidcs_t *cs)
{
	md_raidps_t	*ps;
	mdi_unit_t	*ui;
	mr_unit_t	*un;
	int		error = 0;

	ps = cs->cs_ps;
	ui = ps->ps_ui;
	un = (mr_unit_t *)md_unit_writerlock(ui);
	ASSERT(un != 0);

	if (cs->cs_dbuf.b_flags & B_ERROR)
		error = raid_error_state(un, &cs->cs_dbuf);
	if (cs->cs_pbuf.b_flags & B_ERROR)
		error |= raid_error_state(un, &cs->cs_pbuf);

	md_unit_writerexit(ui);

	ps->ps_flags |= MD_RPS_HSREQ;

	un = (mr_unit_t *)md_unit_readerlock(ui);
	ASSERT(un != 0);
	/* now attempt the appropriate retry routine */
	(*(cs->cs_retry_call))(un, cs);
}


/*
 * NAMES:	raid_read_error
 * DESCRIPTION: I/O error handling routine for a RAID metadevice read
 * PARAMETERS:	md_raidcs_t *cs - pointer to child structure
 */
/*ARGSUSED*/
static void
raid_read_error(md_raidcs_t *cs)
{
	md_raidps_t	*ps;
	mdi_unit_t	*ui;
	mr_unit_t	*un;
	set_t		setno;

	ps = cs->cs_ps;
	ui = ps->ps_ui;
	un = cs->cs_un;

	setno = MD_UN2SET(un);

	if ((cs->cs_dbuf.b_flags & B_ERROR) &&
	    (COLUMN_STATE(un, cs->cs_dcolumn) != RCS_ERRED) &&
	    (COLUMN_STATE(un, cs->cs_dcolumn) != RCS_LAST_ERRED))
		cmn_err(CE_WARN, "md %s: read error on %s",
		    md_shortname(MD_SID(un)),
		    md_devname(setno, md_expldev(cs->cs_dbuf.b_edev), NULL, 0));

	if ((cs->cs_pbuf.b_flags & B_ERROR) &&
	    (COLUMN_STATE(un, cs->cs_pcolumn) != RCS_ERRED) &&
	    (COLUMN_STATE(un, cs->cs_pcolumn) != RCS_LAST_ERRED))
		cmn_err(CE_WARN, "md %s: read error on %s",
		    md_shortname(MD_SID(un)),
		    md_devname(setno, md_expldev(cs->cs_pbuf.b_edev), NULL, 0));

	md_unit_readerexit(ui);

	ASSERT(cs->cs_frags == 0);

	/* now schedule processing for possible state change */
	daemon_request(&md_mstr_daemon, raid_rderr,
	    (daemon_queue_t *)cs, REQ_OLD);

}

/*
 * NAMES:	getdbuffer
 * DESCRIPTION: data buffer allocation for a child structure
 * PARAMETERS:	md_raidcs_t *cs - pointer to child structure
 *
 * NOTE: always get dbuffer before pbuffer
 *	 and get both buffers before pwslot
 *	 otherwise a deadlock could be introduced.
 */
static void
getdbuffer(md_raidcs_t *cs)
{
	mr_unit_t	*un;

	cs->cs_dbuffer = kmem_alloc(cs->cs_bcount + DEV_BSIZE, KM_NOSLEEP);
	if (cs->cs_dbuffer != NULL)
		return;
	un = cs->cs_ps->ps_un;
	mutex_enter(&un->un_mx);
	while (un->un_dbuffer == NULL) {
		STAT_INC(data_buffer_waits);
		un->un_rflags |= MD_RFLAG_NEEDBUF;
		cv_wait(&un->un_cv, &un->un_mx);
	}
	cs->cs_dbuffer = un->un_dbuffer;
	cs->cs_flags |= MD_RCS_UNDBUF;
	un->un_dbuffer = NULL;
	mutex_exit(&un->un_mx);
}

/*
 * NAMES:	getpbuffer
 * DESCRIPTION: parity buffer allocation for a child structure
 * PARAMETERS:	md_raidcs_t *cs - pointer to child structure
 *
 * NOTE: always get dbuffer before pbuffer
 *	 and get both buffers before pwslot
 *	 otherwise a deadlock could be introduced.
 */
static void
getpbuffer(md_raidcs_t *cs)
{
	mr_unit_t *un;

	cs->cs_pbuffer = kmem_alloc(cs->cs_bcount + DEV_BSIZE, KM_NOSLEEP);
	if (cs->cs_pbuffer != NULL)
		return;
	un = cs->cs_ps->ps_un;
	mutex_enter(&un->un_mx);
	while (un->un_pbuffer == NULL) {
		STAT_INC(parity_buffer_waits);
		un->un_rflags |= MD_RFLAG_NEEDBUF;
		cv_wait(&un->un_cv, &un->un_mx);
	}
	cs->cs_pbuffer = un->un_pbuffer;
	cs->cs_flags |= MD_RCS_UNPBUF;
	un->un_pbuffer = NULL;
	mutex_exit(&un->un_mx);
}
static void
getresources(md_raidcs_t *cs)
{
	md_raidcbuf_t	*cbuf;
	/*
	 * NOTE: always get dbuffer before pbuffer
	 *	 and get both buffers before pwslot
	 *	 otherwise a deadlock could be introduced.
	 */
	getdbuffer(cs);
	getpbuffer(cs);
	for (cbuf = cs->cs_buflist; cbuf; cbuf = cbuf->cbuf_next)
		cbuf->cbuf_buffer =
		    kmem_alloc(cs->cs_bcount + DEV_BSIZE, KM_SLEEP);
}
/*
 * NAMES:	freebuffers
 * DESCRIPTION: child structure buffer freeing routine
 * PARAMETERS:	md_raidcs_t *cs - pointer to child structure
 */
static void
freebuffers(md_raidcs_t *cs)
{
	mr_unit_t	*un;
	md_raidcbuf_t	*cbuf;

	/* free buffers used for full line write */
	for (cbuf = cs->cs_buflist; cbuf; cbuf = cbuf->cbuf_next) {
		if (cbuf->cbuf_buffer == NULL)
			continue;
		kmem_free(cbuf->cbuf_buffer, cbuf->cbuf_bcount + DEV_BSIZE);
		cbuf->cbuf_buffer = NULL;
		cbuf->cbuf_bcount = 0;
	}

	if (cs->cs_flags & (MD_RCS_UNDBUF | MD_RCS_UNPBUF)) {
		un = cs->cs_un;
		mutex_enter(&un->un_mx);
	}
	if (cs->cs_dbuffer) {
		if (cs->cs_flags & MD_RCS_UNDBUF)
			un->un_dbuffer = cs->cs_dbuffer;
		else
			kmem_free(cs->cs_dbuffer, cs->cs_bcount + DEV_BSIZE);
	}
	if (cs->cs_pbuffer) {
		if (cs->cs_flags & MD_RCS_UNPBUF)
			un->un_pbuffer = cs->cs_pbuffer;
		else
			kmem_free(cs->cs_pbuffer, cs->cs_bcount + DEV_BSIZE);
	}
	if (cs->cs_flags & (MD_RCS_UNDBUF | MD_RCS_UNPBUF)) {
		un->un_rflags &= ~MD_RFLAG_NEEDBUF;
		cv_broadcast(&un->un_cv);
		mutex_exit(&un->un_mx);
	}
}

/*
 * NAMES:	raid_line_reader_lock, raid_line_writer_lock
 * DESCRIPTION: RAID metadevice line reader and writer lock routines
 *		data column # and parity column #.
 * PARAMETERS:	md_raidcs_t *cs - pointer to child structure
 */

void
raid_line_reader_lock(md_raidcs_t *cs, int resync_thread)
{
	mr_unit_t	*un;
	md_raidcs_t	*cs1;

	ASSERT(cs->cs_line != MD_DISKADDR_ERROR);
	un = cs->cs_un;
	cs->cs_flags |= MD_RCS_READER;
	STAT_CHECK(raid_line_lock_wait, MUTEX_HELD(&un->un_linlck_mx));
	if (!panicstr)
		mutex_enter(&un->un_linlck_mx);
	cs1 = un->un_linlck_chn;
	while (cs1 != NULL) {
		for (cs1 = un->un_linlck_chn; cs1; cs1 = cs1->cs_linlck_next)
			if (raid_io_overlaps(cs, cs1) == 1)
				if (cs1->cs_flags & MD_RCS_WRITER)
					break;

		if (cs1 != NULL) {
			if (panicstr)
				panic("md; raid line write lock held");
			un->un_linlck_flg = 1;
			cv_wait(&un->un_linlck_cv, &un->un_linlck_mx);
			STAT_INC(raid_read_waits);
		}
	}
	STAT_MAX(raid_max_reader_locks, raid_reader_locks_active);
	STAT_INC(raid_reader_locks);
	cs1 = un->un_linlck_chn;
	if (cs1 != NULL)
		cs1->cs_linlck_prev = cs;
	cs->cs_linlck_next = cs1;
	cs->cs_linlck_prev = NULL;
	un->un_linlck_chn = cs;
	cs->cs_flags |= MD_RCS_LLOCKD;
	if (resync_thread) {
		diskaddr_t lastblk = cs->cs_blkno + cs->cs_blkcnt - 1;
		diskaddr_t line = (lastblk + 1) / un->un_segsize;
		ASSERT(raid_state_cnt(un, RCS_RESYNC));
		mutex_enter(&un->un_mx);
		un->un_resync_line_index = line;
		mutex_exit(&un->un_mx);
	}
	if (!panicstr)
		mutex_exit(&un->un_linlck_mx);
}

int
raid_line_writer_lock(md_raidcs_t *cs, int lock)
{
	mr_unit_t	*un;
	md_raidcs_t	*cs1;

	ASSERT(cs->cs_line != MD_DISKADDR_ERROR);
	cs->cs_flags |= MD_RCS_WRITER;
	un = cs->cs_ps->ps_un;

	STAT_CHECK(raid_line_lock_wait, MUTEX_HELD(&un->un_linlck_mx));
	if (lock && !panicstr)
		mutex_enter(&un->un_linlck_mx);
	ASSERT(MUTEX_HELD(&un->un_linlck_mx));

	cs1 = un->un_linlck_chn;
	for (cs1 = un->un_linlck_chn; cs1; cs1 = cs1->cs_linlck_next)
		if (raid_io_overlaps(cs, cs1))
			break;

	if (cs1 != NULL) {
		if (panicstr)
			panic("md: line writer lock inaccessible");
		goto no_lock_exit;
	}

	if (raid_alloc_pwslot(cs)) {
		if (panicstr)
			panic("md: no prewrite slots");
		STAT_INC(raid_prewrite_waits);
		goto no_lock_exit;
	}

	cs1 = un->un_linlck_chn;
	if (cs1 != NULL)
		cs1->cs_linlck_prev = cs;
	cs->cs_linlck_next = cs1;
	cs->cs_linlck_prev = NULL;
	un->un_linlck_chn = cs;
	cs->cs_flags |= MD_RCS_LLOCKD;
	cs->cs_flags &= ~MD_RCS_WAITING;
	STAT_INC(raid_writer_locks);
	STAT_MAX(raid_max_write_locks, raid_write_locks_active);
	if (lock && !panicstr)
		mutex_exit(&un->un_linlck_mx);
	return (0);

no_lock_exit:
	/* if this is already queued then do not requeue it */
	ASSERT(! (cs->cs_flags & MD_RCS_LLOCKD));
	if (!lock || (cs->cs_flags & MD_RCS_WAITING))
		return (1);
	cs->cs_flags |= MD_RCS_WAITING;
	cs->cs_un = un;
	raid_enqueue(cs);
	if (lock && !panicstr)
		mutex_exit(&un->un_linlck_mx);
	return (1);
}

static void
raid_startio(md_raidcs_t *cs)
{
	mdi_unit_t	*ui = cs->cs_ps->ps_ui;
	mr_unit_t	*un = cs->cs_un;

	un = md_unit_readerlock(ui);
	raid_write_io(un, cs);
}

void
raid_io_startup(mr_unit_t *un)
{
	md_raidcs_t	*waiting_list, *cs1;
	md_raidcs_t	*previous = NULL, *next = NULL;
	mdi_unit_t	*ui =  MDI_UNIT(un->c.un_self_id);
	kmutex_t	*io_list_mutex = &ui->ui_io_lock->io_list_mutex;

	ASSERT(MUTEX_HELD(&un->un_linlck_mx));
	mutex_enter(io_list_mutex);

	/*
	 * check to be sure there are no reader locks outstanding.  If
	 * there are not then pass on the writer lock.
	 */
	waiting_list = ui->ui_io_lock->io_list_front;
	while (waiting_list) {
		ASSERT(waiting_list->cs_flags & MD_RCS_WAITING);
		ASSERT(! (waiting_list->cs_flags & MD_RCS_LLOCKD));
		for (cs1 = un->un_linlck_chn; cs1; cs1 = cs1->cs_linlck_next)
			if (raid_io_overlaps(waiting_list, cs1) == 1)
				break;
		/*
		 * there was an IOs that overlaps this io so go onto
		 * the next io in the waiting list
		 */
		if (cs1) {
			previous = waiting_list;
			waiting_list = waiting_list->cs_linlck_next;
			continue;
		}

		/*
		 * There are no IOs that overlap this, so remove it from
		 * the waiting queue, and start it
		 */

		if (raid_check_pw(waiting_list)) {
			ASSERT(waiting_list->cs_flags & MD_RCS_WAITING);
			previous = waiting_list;
			waiting_list = waiting_list->cs_linlck_next;
			continue;
		}
		ASSERT(waiting_list->cs_flags & MD_RCS_WAITING);

		next = waiting_list->cs_linlck_next;
		if (previous)
			previous->cs_linlck_next = next;
		else
			ui->ui_io_lock->io_list_front = next;

		if (ui->ui_io_lock->io_list_front == NULL)
			ui->ui_io_lock->io_list_back = NULL;

		if (ui->ui_io_lock->io_list_back == waiting_list)
			ui->ui_io_lock->io_list_back = previous;

		waiting_list->cs_linlck_next = NULL;
		waiting_list->cs_flags &= ~MD_RCS_WAITING;
		STAT_DEC(raid_write_queue_length);
		if (raid_line_writer_lock(waiting_list, 0))
			panic("region locking corrupted");

		ASSERT(waiting_list->cs_flags & MD_RCS_LLOCKD);
		daemon_request(&md_mstr_daemon, raid_startio,
		    (daemon_queue_t *)waiting_list, REQ_OLD);
		waiting_list = next;

	}
	mutex_exit(io_list_mutex);
}

void
raid_line_exit(md_raidcs_t *cs)
{
	mr_unit_t	*un;

	un = cs->cs_ps->ps_un;
	STAT_CHECK(raid_line_lock_wait, MUTEX_HELD(&un->un_linlck_mx));
	mutex_enter(&un->un_linlck_mx);
	if (cs->cs_flags & MD_RCS_READER)
		STAT_DEC(raid_reader_locks_active);
	else
		STAT_DEC(raid_write_locks_active);

	if (cs->cs_linlck_prev)
		cs->cs_linlck_prev->cs_linlck_next = cs->cs_linlck_next;
	else
		un->un_linlck_chn = cs->cs_linlck_next;
	if (cs->cs_linlck_next)
		cs->cs_linlck_next->cs_linlck_prev = cs->cs_linlck_prev;

	cs->cs_flags &= ~MD_RCS_LLOCKD;

	if (un->un_linlck_flg)
		cv_broadcast(&un->un_linlck_cv);

	un->un_linlck_flg = 0;
	cs->cs_line = MD_DISKADDR_ERROR;

	raid_cancel_pwslot(cs);
	/*
	 * now that the lock is droped go ahead and see if there are any
	 * other writes that can be started up
	 */
	raid_io_startup(un);

	mutex_exit(&un->un_linlck_mx);
}

/*
 * NAMES:	raid_line, raid_pcolumn, raid_dcolumn
 * DESCRIPTION: RAID metadevice APIs for mapping segment # to line #,
 *		data column # and parity column #.
 * PARAMETERS:	int segment - segment number
 *		mr_unit_t *un - pointer to an unit structure
 * RETURNS:	raid_line returns line #
 *		raid_dcolumn returns data column #
 *		raid_pcolumn returns parity column #
 */
static diskaddr_t
raid_line(diskaddr_t segment, mr_unit_t *un)
{
	diskaddr_t	adj_seg;
	diskaddr_t	line;
	diskaddr_t	max_orig_segment;

	max_orig_segment = (un->un_origcolumncnt - 1) * un->un_segsincolumn;
	if (segment >= max_orig_segment) {
		adj_seg = segment - max_orig_segment;
		line = adj_seg % un->un_segsincolumn;
	} else {
		line = segment / (un->un_origcolumncnt - 1);
	}
	return (line);
}

uint_t
raid_dcolumn(diskaddr_t segment, mr_unit_t *un)
{
	diskaddr_t	adj_seg;
	diskaddr_t	line;
	diskaddr_t	max_orig_segment;
	uint_t		column;

	max_orig_segment = (un->un_origcolumncnt - 1) * un->un_segsincolumn;
	if (segment >= max_orig_segment) {
		adj_seg = segment - max_orig_segment;
		column = un->un_origcolumncnt  +
		    (uint_t)(adj_seg / un->un_segsincolumn);
	} else {
		line = segment / (un->un_origcolumncnt - 1);
		column = (uint_t)((segment %
		    (un->un_origcolumncnt - 1) + line) % un->un_origcolumncnt);
	}
	return (column);
}

uint_t
raid_pcolumn(diskaddr_t segment, mr_unit_t *un)
{
	diskaddr_t	adj_seg;
	diskaddr_t	line;
	diskaddr_t	max_orig_segment;
	uint_t		column;

	max_orig_segment = (un->un_origcolumncnt - 1) * un->un_segsincolumn;
	if (segment >= max_orig_segment) {
		adj_seg = segment - max_orig_segment;
		line = adj_seg % un->un_segsincolumn;
	} else {
		line = segment / (un->un_origcolumncnt - 1);
	}
	column = (uint_t)((line + (un->un_origcolumncnt - 1)) %
	    un->un_origcolumncnt);
	return (column);
}


/*
 * Is called in raid_iosetup to probe each column to insure
 * that all the columns are in 'okay' state and meet the
 * 'full line' requirement.  If any column is in error,
 * we don't want to enable the 'full line' flag.  Previously,
 * we would do so and disable it only when a error is
 * detected after the first 'full line' io which is too late
 * and leads to the potential data corruption.
 */
static int
raid_check_cols(mr_unit_t *un)
{
	buf_t		bp;
	char		*buf;
	mr_column_t	*colptr;
	minor_t		mnum = MD_SID(un);
	int		i;
	int		err = 0;

	buf = kmem_zalloc((uint_t)DEV_BSIZE, KM_SLEEP);

	for (i = 0; i < un->un_totalcolumncnt; i++) {
		md_dev64_t tmpdev;

		colptr = &un->un_column[i];

		tmpdev = colptr->un_dev;
		/*
		 * Open by device id
		 * If this device is hotspared
		 * use the hotspare key
		 */
		tmpdev = md_resolve_bydevid(mnum, tmpdev, HOTSPARED(un, i) ?
		    colptr->un_hs_key : colptr->un_orig_key);

		if (tmpdev == NODEV64) {
			err = 1;
			break;
		}

		colptr->un_dev = tmpdev;

		bzero((caddr_t)&bp, sizeof (buf_t));
		bp.b_back = &bp;
		bp.b_forw = &bp;
		bp.b_flags = (B_READ | B_BUSY);
		sema_init(&bp.b_io, 0, NULL,
		    SEMA_DEFAULT, NULL);
		sema_init(&bp.b_sem, 0, NULL,
		    SEMA_DEFAULT, NULL);
		bp.b_edev = md_dev64_to_dev(colptr->un_dev);
		bp.b_lblkno = colptr->un_pwstart;
		bp.b_bcount = DEV_BSIZE;
		bp.b_bufsize = DEV_BSIZE;
		bp.b_un.b_addr = (caddr_t)buf;
		(void) md_call_strategy(&bp, 0, NULL);
		if (biowait(&bp)) {
			err = 1;
			break;
		}
	}

	kmem_free(buf, DEV_BSIZE);
	return (err);
}

/*
 * NAME:	raid_iosetup
 * DESCRIPTION: RAID metadevice specific I/O set up routine which does
 *		all the necessary calculations to determine the location
 *		of the segement for the I/O.
 * PARAMETERS:	mr_unit_t *un - unit number of RAID metadevice
 *		diskaddr_t	blkno - block number of the I/O attempt
 *		size_t		blkcnt - block count for this I/O
 *		md_raidcs_t *cs - child structure for each segmented I/O
 *
 * NOTE:	The following is an example of a raid disk layer out:
 *
 *		Total Column = 5
 *		Original Column = 4
 *		Segment Per Column = 10
 *
 *			Col#0	Col#1	Col#2	Col#3	Col#4	Col#5	Col#6
 *		-------------------------------------------------------------
 *		line#0	Seg#0	Seg#1	Seg#2	Parity	Seg#30	Seg#40
 *		line#1	Parity	Seg#3	Seg#4	Seg#5	Seg#31
 *		line#2	Seg#8	Parity	Seg#6	Seg#7	Seg#32
 *		line#3	Seg#10	Seg#11	Parity	Seg#9	Seg#33
 *		line#4	Seg#12	Seg#13	Seg#14	Parity	Seg#34
 *		line#5	Parity	Seg#15	Seg#16	Seg#17	Seg#35
 *		line#6	Seg#20	Parity	Seg#18	Seg#19	Seg#36
 *		line#7	Seg#22	Seg#23	Parity	Seg#21	Seg#37
 *		line#8	Seg#24	Seg#25	Seg#26	Parity	Seg#38
 *		line#9	Parity	Seg#27	Seg#28	Seg#29	Seg#39
 */
static size_t
raid_iosetup(
	mr_unit_t	*un,
	diskaddr_t	blkno,
	size_t		blkcnt,
	md_raidcs_t	*cs
)
{
	diskaddr_t	segment;
	diskaddr_t	segstart;
	diskaddr_t	segoff;
	size_t		leftover;
	diskaddr_t	line;
	uint_t		iosize;
	uint_t		colcnt;

	/* caculate the segment# and offset for the block */
	segment = blkno / un->un_segsize;
	segstart = segment * un->un_segsize;
	segoff = blkno - segstart;
	iosize = un->un_iosize - 1;
	colcnt = un->un_totalcolumncnt - 1;
	line = raid_line(segment, un);
	cs->cs_dcolumn = raid_dcolumn(segment, un);
	cs->cs_pcolumn = raid_pcolumn(segment, un);
	cs->cs_dflags = un->un_column[cs->cs_dcolumn].un_devflags;
	cs->cs_pflags = un->un_column[cs->cs_pcolumn].un_devflags;
	cs->cs_line = line;

	if ((cs->cs_ps->ps_flags & MD_RPS_WRITE) &&
	    (UNIT_STATE(un) & RCS_OKAY) &&
	    (segoff == 0) &&
	    (un->un_totalcolumncnt == un->un_origcolumncnt) &&
	    (un->un_segsize < un->un_iosize) &&
	    (un->un_iosize <= un->un_maxio) &&
	    (blkno == line * un->un_segsize * colcnt) &&
	    (blkcnt >= ((un->un_totalcolumncnt -1) * un->un_segsize)) &&
	    (raid_state_cnt(un, RCS_OKAY) == un->un_origcolumncnt) &&
	    (raid_check_cols(un) == 0)) {

		md_raidcbuf_t	**cbufp;
		md_raidcbuf_t	*cbuf;
		int		i, j;

		STAT_INC(raid_full_line_writes);
		leftover = blkcnt - (un->un_segsize * colcnt);
		ASSERT(blkcnt >= (un->un_segsize * colcnt));
		cs->cs_blkno = line * un->un_segsize;
		cs->cs_blkcnt = un->un_segsize;
		cs->cs_lastblk = cs->cs_blkno + cs->cs_blkcnt - 1;
		cs->cs_bcount = dbtob(cs->cs_blkcnt);
		cs->cs_flags |= MD_RCS_LINE;

		cbufp = &cs->cs_buflist;
		for (i = 0; i < un->un_totalcolumncnt; i++) {
			j = cs->cs_dcolumn + i;
			j = j % un->un_totalcolumncnt;

			if ((j == cs->cs_dcolumn) || (j == cs->cs_pcolumn))
				continue;
			cbuf = kmem_cache_alloc(raid_cbuf_cache,
			    MD_ALLOCFLAGS);
			raid_cbuf_init(cbuf);
			cbuf->cbuf_un = cs->cs_un;
			cbuf->cbuf_ps = cs->cs_ps;
			cbuf->cbuf_column = j;
			cbuf->cbuf_bcount = dbtob(un->un_segsize);
			*cbufp = cbuf;
			cbufp = &cbuf->cbuf_next;
		}
		return (leftover);
	}

	leftover = blkcnt - (un->un_segsize - segoff);
	if (blkcnt > (un->un_segsize - segoff))
		blkcnt -= leftover;
	else
		leftover = 0;

	if (blkcnt > (size_t)iosize) {
		leftover += (blkcnt - iosize);
		blkcnt = iosize;
	}

	/* calculate the line# and column# for the segment */
	cs->cs_flags &= ~MD_RCS_LINE;
	cs->cs_blkno = line * un->un_segsize + segoff;
	cs->cs_blkcnt = (uint_t)blkcnt;
	cs->cs_lastblk = cs->cs_blkno + cs->cs_blkcnt - 1;
	cs->cs_bcount = dbtob((uint_t)blkcnt);
	return (leftover);
}

/*
 * NAME:	raid_done
 * DESCRIPTION: RAID metadevice I/O done interrupt routine
 * PARAMETERS:	struct buf *bp - pointer to a buffer structure
 */
static void
raid_done(struct buf *bp)
{
	md_raidcs_t	*cs;
	int		flags, frags;

	sema_v(&bp->b_io);
	cs = (md_raidcs_t *)bp->b_chain;

	ASSERT(cs != NULL);

	mutex_enter(&cs->cs_mx);
	if (bp->b_flags & B_ERROR) {
		cs->cs_flags |= MD_RCS_ERROR;
		cs->cs_flags &= ~(MD_RCS_ISCALL);
	}

	flags = cs->cs_flags;
	frags = --cs->cs_frags;
	mutex_exit(&cs->cs_mx);
	if (frags != 0) {
		return;
	}

	if (flags & MD_RCS_ERROR) {
		if (cs->cs_error_call) {
			daemon_request(&md_done_daemon, cs->cs_error_call,
			    (daemon_queue_t *)cs, REQ_OLD);
		}
		return;
	}

	if (flags & MD_RCS_ISCALL) {
		cs->cs_flags &= ~(MD_RCS_ISCALL);
		(*(cs->cs_call))(cs);
		return;
	}
	daemon_request(&md_done_daemon, cs->cs_call,
	    (daemon_queue_t *)cs, REQ_OLD);
}
/*
 * the flag RIO_EXTRA is used when dealing with a column in the process
 * of being resynced. During the resync, writes may have to take place
 * on both the original component and a hotspare component.
 */
#define	RIO_DATA	0x00100		/* use data buffer & data column */
#define	RIO_PARITY	0x00200		/* use parity buffer & parity column */
#define	RIO_WRITE	0x00400		/* issue a write */
#define	RIO_READ	0x00800		/* issue a read */
#define	RIO_PWIO	0x01000		/* do the I/O to the prewrite entry */
#define	RIO_ALT		0x02000		/* do write to alternate device */
#define	RIO_EXTRA	0x04000		/* use extra buffer */

#define	RIO_COLMASK	0x000ff

#define	RIO_PREWRITE	RIO_WRITE | RIO_PWIO

/*
 * NAME:	raidio
 * DESCRIPTION: RAID metadevice write routine
 * PARAMETERS:	md_raidcs_t *cs - pointer to a child structure
 */
static void
raidio(md_raidcs_t *cs, int flags)
{
	buf_t		*bp;
	int		column;
	int		flag;
	void		*private;
	mr_unit_t	*un;
	int		iosize;
	diskaddr_t	pwstart;
	diskaddr_t	devstart;
	md_dev64_t	dev;

	un = cs->cs_un;

	ASSERT(IO_READER_HELD(un));
	ASSERT(UNIT_READER_HELD(un));

	if (flags & RIO_DATA) {
		if (flags & RIO_EXTRA)
			bp = &cs->cs_hbuf;
		else
			bp = &cs->cs_dbuf;
		bp->b_un.b_addr = cs->cs_dbuffer;
		column = cs->cs_dcolumn;
	} else {
		if (flags & RIO_EXTRA)
			bp = &cs->cs_hbuf;
		else
			bp = &cs->cs_pbuf;
		bp->b_un.b_addr = cs->cs_pbuffer;
		column = cs->cs_pcolumn;
	}
	if (flags & RIO_COLMASK)
		column = (flags & RIO_COLMASK) - 1;

	bp->b_bcount = cs->cs_bcount;
	bp->b_bufsize = cs->cs_bcount;
	iosize = un->un_iosize;

	/* check if the hotspared device will be used */
	if (flags & RIO_ALT && (flags & RIO_WRITE)) {
		pwstart = un->un_column[column].un_alt_pwstart;
		devstart = un->un_column[column].un_alt_devstart;
		dev = un->un_column[column].un_alt_dev;
	} else {
		pwstart = un->un_column[column].un_pwstart;
		devstart = un->un_column[column].un_devstart;
		dev = un->un_column[column].un_dev;
	}

	/* if not writing to log skip log header */
	if ((flags & RIO_PWIO) == 0) {
		bp->b_lblkno = devstart + cs->cs_blkno;
		bp->b_un.b_addr += DEV_BSIZE;
	} else {
		bp->b_bcount += DEV_BSIZE;
		bp->b_bufsize = bp->b_bcount;
		if (flags & RIO_DATA) {
			bp->b_lblkno = cs->cs_dpwslot * iosize + pwstart;
		} else { /* not DATA -> PARITY */
			bp->b_lblkno = cs->cs_ppwslot * iosize + pwstart;
		}
	}

	bp->b_flags &= ~(B_READ | B_WRITE | B_ERROR | nv_available);
	bp->b_flags |= B_BUSY;
	if (flags & RIO_READ) {
		bp->b_flags |= B_READ;
	} else {
		bp->b_flags |= B_WRITE;
		if ((nv_available && nv_parity && (flags & RIO_PARITY)) ||
		    (nv_available && nv_prewrite && (flags & RIO_PWIO)))
			bp->b_flags |= nv_available;
	}
	bp->b_iodone = (int (*)())raid_done;
	bp->b_edev = md_dev64_to_dev(dev);

	ASSERT((bp->b_edev != 0) && (bp->b_edev != NODEV));

	private = cs->cs_strategy_private;
	flag = cs->cs_strategy_flag;

	md_call_strategy(bp, flag, private);
}

/*
 * NAME:	genstandardparity
 * DESCRIPTION: This routine
 * PARAMETERS:	md_raidcs_t *cs - pointer to a child structure
 */
static void
genstandardparity(md_raidcs_t *cs)
{
	uint_t		*dbuf, *pbuf;
	size_t		wordcnt;
	uint_t		dsum = 0;
	uint_t		psum = 0;

	ASSERT((cs->cs_bcount & 0x3) == 0);

	wordcnt = cs->cs_bcount / sizeof (uint_t);

	dbuf = (uint_t *)(void *)(cs->cs_dbuffer + DEV_BSIZE);
	pbuf = (uint_t *)(void *)(cs->cs_pbuffer + DEV_BSIZE);

	/* Word aligned */
	if (((uintptr_t)cs->cs_addr & 0x3) == 0) {
		uint_t	*uwbuf = (uint_t *)(void *)(cs->cs_addr);
		uint_t	uval;

		while (wordcnt--) {
			uval = *uwbuf++;
			psum ^= (*pbuf = ((*pbuf ^ *dbuf) ^ uval));
			++pbuf;
			*dbuf = uval;
			dsum ^= uval;
			++dbuf;
		}
	} else {
		uchar_t	*ubbuf = (uchar_t *)(cs->cs_addr);
		union {
			uint_t	wb;
			uchar_t	bb[4];
		} cb;

		while (wordcnt--) {
			cb.bb[0] = *ubbuf++;
			cb.bb[1] = *ubbuf++;
			cb.bb[2] = *ubbuf++;
			cb.bb[3] = *ubbuf++;
			psum ^= (*pbuf = ((*pbuf ^ *dbuf) ^ cb.wb));
			++pbuf;
			*dbuf = cb.wb;
			dsum ^= cb.wb;
			++dbuf;
		}
	}

	RAID_FILLIN_RPW(cs->cs_dbuffer, cs->cs_un, dsum, cs->cs_pcolumn,
	    cs->cs_blkno, cs->cs_blkcnt, cs->cs_pwid,
	    2, cs->cs_dcolumn, RAID_PWMAGIC);

	RAID_FILLIN_RPW(cs->cs_pbuffer, cs->cs_un, psum, cs->cs_dcolumn,
	    cs->cs_blkno, cs->cs_blkcnt, cs->cs_pwid,
	    2, cs->cs_pcolumn, RAID_PWMAGIC);
}

static void
genlineparity(md_raidcs_t *cs)
{

	mr_unit_t	*un = cs->cs_un;
	md_raidcbuf_t	*cbuf;
	uint_t		*pbuf, *dbuf;
	uint_t		*uwbuf;
	uchar_t		*ubbuf;
	size_t		wordcnt;
	uint_t		psum = 0, dsum = 0;
	size_t		count = un->un_segsize * DEV_BSIZE;
	uint_t		col;
	buf_t		*bp;

	ASSERT((cs->cs_bcount & 0x3) == 0);

	pbuf = (uint_t *)(void *)(cs->cs_pbuffer + DEV_BSIZE);
	dbuf = (uint_t *)(void *)(cs->cs_dbuffer + DEV_BSIZE);
	uwbuf = (uint_t *)(void *)(cs->cs_addr);
	ubbuf = (uchar_t *)(void *)(cs->cs_addr);

	wordcnt = count / sizeof (uint_t);

	/* Word aligned */
	if (((uintptr_t)cs->cs_addr & 0x3) == 0) {
		uint_t	 uval;

		while (wordcnt--) {
			uval = *uwbuf++;
			*dbuf = uval;
			*pbuf = uval;
			dsum ^= uval;
			++pbuf;
			++dbuf;
		}
	} else {
		union {
			uint_t	wb;
			uchar_t	bb[4];
		} cb;

		while (wordcnt--) {
			cb.bb[0] = *ubbuf++;
			cb.bb[1] = *ubbuf++;
			cb.bb[2] = *ubbuf++;
			cb.bb[3] = *ubbuf++;
			*dbuf = cb.wb;
			*pbuf = cb.wb;
			dsum ^= cb.wb;
			++pbuf;
			++dbuf;
		}
	}

	RAID_FILLIN_RPW(cs->cs_dbuffer, un, dsum, cs->cs_pcolumn,
	    cs->cs_blkno, cs->cs_blkcnt, cs->cs_pwid,
	    un->un_totalcolumncnt, cs->cs_dcolumn, RAID_PWMAGIC);

	raidio(cs, RIO_PREWRITE | RIO_DATA);

	for (cbuf = cs->cs_buflist; cbuf; cbuf = cbuf->cbuf_next) {

		dsum = 0;
		pbuf = (uint_t *)(void *)(cs->cs_pbuffer + DEV_BSIZE);
		dbuf = (uint_t *)(void *)(cbuf->cbuf_buffer + DEV_BSIZE);

		wordcnt = count / sizeof (uint_t);

		col = cbuf->cbuf_column;

		/* Word aligned */
		if (((uintptr_t)cs->cs_addr & 0x3) == 0) {
			uint_t	uval;

			/*
			 * Only calculate psum when working on the last
			 * data buffer.
			 */
			if (cbuf->cbuf_next == NULL) {
				psum = 0;
				while (wordcnt--) {
					uval = *uwbuf++;
					*dbuf = uval;
					psum ^= (*pbuf ^= uval);
					dsum ^= uval;
					++dbuf;
					++pbuf;
				}
			} else {
				while (wordcnt--) {
					uval = *uwbuf++;
					*dbuf = uval;
					*pbuf ^= uval;
					dsum ^= uval;
					++dbuf;
					++pbuf;
				}
			}
		} else {
			union {
				uint_t	wb;
				uchar_t	bb[4];
			} cb;

			/*
			 * Only calculate psum when working on the last
			 * data buffer.
			 */
			if (cbuf->cbuf_next == NULL) {
				psum = 0;
				while (wordcnt--) {
					cb.bb[0] = *ubbuf++;
					cb.bb[1] = *ubbuf++;
					cb.bb[2] = *ubbuf++;
					cb.bb[3] = *ubbuf++;
					*dbuf = cb.wb;
					psum ^= (*pbuf ^= cb.wb);
					dsum ^= cb.wb;
					++dbuf;
					++pbuf;
				}
			} else {
				while (wordcnt--) {
					cb.bb[0] = *ubbuf++;
					cb.bb[1] = *ubbuf++;
					cb.bb[2] = *ubbuf++;
					cb.bb[3] = *ubbuf++;
					*dbuf = cb.wb;
					*pbuf ^= cb.wb;
					dsum ^= cb.wb;
					++dbuf;
					++pbuf;
				}
			}
		}
		RAID_FILLIN_RPW(cbuf->cbuf_buffer, un, dsum, cs->cs_pcolumn,
		    cs->cs_blkno, cs->cs_blkcnt, cs->cs_pwid,
		    un->un_totalcolumncnt, col, RAID_PWMAGIC);

		/*
		 * fill in buffer for write to prewrite area
		 */
		bp = &cbuf->cbuf_bp;
		bp->b_un.b_addr = cbuf->cbuf_buffer;
		bp->b_bcount = cbuf->cbuf_bcount + DEV_BSIZE;
		bp->b_bufsize = bp->b_bcount;
		bp->b_lblkno = (cbuf->cbuf_pwslot * un->un_iosize) +
		    un->un_column[col].un_pwstart;
		bp->b_flags = B_WRITE | B_BUSY;
		if (nv_available && nv_prewrite)
			bp->b_flags |= nv_available;
		bp->b_iodone = (int (*)())raid_done;
		bp->b_edev = md_dev64_to_dev(un->un_column[col].un_dev);
		bp->b_chain = (struct buf *)cs;
		md_call_strategy(bp,
		    cs->cs_strategy_flag, cs->cs_strategy_private);
	}

	RAID_FILLIN_RPW(cs->cs_pbuffer, un, psum, cs->cs_dcolumn,
	    cs->cs_blkno, cs->cs_blkcnt, cs->cs_pwid,
	    un->un_totalcolumncnt, cs->cs_pcolumn, RAID_PWMAGIC);

	raidio(cs, RIO_PREWRITE | RIO_PARITY);
}

/*
 * NAME:	raid_readregenloop
 * DESCRIPTION: RAID metadevice write routine
 * PARAMETERS:	md_raidcs_t *cs - pointer to a child structure
 */
static void
raid_readregenloop(md_raidcs_t *cs)
{
	mr_unit_t	*un;
	md_raidps_t	*ps;
	uint_t		*dbuf;
	uint_t		*pbuf;
	size_t		wordcnt;

	un = cs->cs_un;

	/*
	 * XOR the parity with data bytes, must skip the
	 * pre-write entry header in all data/parity buffers
	 */
	wordcnt = cs->cs_bcount / sizeof (uint_t);
	dbuf = (uint_t *)(void *)(cs->cs_dbuffer + DEV_BSIZE);
	pbuf = (uint_t *)(void *)(cs->cs_pbuffer + DEV_BSIZE);
	while (wordcnt--)
		*dbuf++ ^= *pbuf++;

	/* bump up the loop count */
	cs->cs_loop++;

	/* skip the errored component */
	if (cs->cs_loop == cs->cs_dcolumn)
		cs->cs_loop++;

	if (cs->cs_loop != un->un_totalcolumncnt) {
		cs->cs_frags = 1;
		raidio(cs, RIO_PARITY | RIO_READ | (cs->cs_loop + 1));
		return;
	}
	/* reaching the end sof loop */
	ps = cs->cs_ps;
	bcopy(cs->cs_dbuffer + DEV_BSIZE, cs->cs_addr, cs->cs_bcount);
	raid_free_child(cs, 1);

	/* decrement readfrags */
	raid_free_parent(ps, RFP_DECR_READFRAGS | RFP_RLS_LOCK);
}

/*
 * NAME:	raid_read_io
 * DESCRIPTION: RAID metadevice read I/O routine
 * PARAMETERS:	mr_unit_t *un - pointer to a unit structure
 *		md_raidcs_t *cs - pointer to a child structure
 */
static void
raid_read_io(mr_unit_t *un, md_raidcs_t *cs)
{
	int	flag;
	void	*private;
	buf_t	*bp;
	buf_t	*pb = cs->cs_ps->ps_bp;
	mr_column_t	*column;

	flag = cs->cs_strategy_flag;
	private = cs->cs_strategy_private;
	column = &un->un_column[cs->cs_dcolumn];

	/*
	 * The component to be read is good, simply set up bp structure
	 * and call low level md routine doing the read.
	 */

	if (COLUMN_ISOKAY(un, cs->cs_dcolumn) ||
	    (COLUMN_ISLASTERR(un, cs->cs_dcolumn) &&
	    (cs->cs_flags & MD_RCS_RECOVERY) == 0)) {
		dev_t ddi_dev; /* needed for bioclone, so not md_dev64_t */
		ddi_dev = md_dev64_to_dev(column->un_dev);

		bp = &cs->cs_dbuf;
		bp = md_bioclone(pb, cs->cs_offset, cs->cs_bcount, ddi_dev,
		    column->un_devstart + cs->cs_blkno,
		    (int (*)())raid_done, bp, KM_NOSLEEP);

		bp->b_chain = (buf_t *)cs;

		cs->cs_frags = 1;
		cs->cs_error_call = raid_read_error;
		cs->cs_retry_call = raid_read_retry;
		cs->cs_flags |= MD_RCS_ISCALL;
		cs->cs_stage = RAID_READ_DONE;
		cs->cs_call = raid_stage;

		ASSERT(bp->b_edev != 0);

		md_call_strategy(bp, flag, private);
		return;
	}

	/*
	 * The component to be read is bad, have to go through
	 * raid specific method to read data from other members.
	 */
	cs->cs_loop = 0;
	/*
	 * NOTE: always get dbuffer before pbuffer
	 *	 and get both buffers before pwslot
	 *	 otherwise a deadlock could be introduced.
	 */
	raid_mapin_buf(cs);
	getdbuffer(cs);
	getpbuffer(cs);
	if (cs->cs_loop == cs->cs_dcolumn)
		cs->cs_loop++;

	/* zero out data buffer for use as a data sink */
	bzero(cs->cs_dbuffer + DEV_BSIZE, cs->cs_bcount);
	cs->cs_stage = RAID_NONE;
	cs->cs_call = raid_readregenloop;
	cs->cs_error_call = raid_read_error;
	cs->cs_retry_call = raid_read_no_retry;
	cs->cs_frags = 1;

	/* use parity buffer to read other columns */
	raidio(cs, RIO_PARITY | RIO_READ | (cs->cs_loop + 1));
}

/*
 * NAME:	raid_read
 * DESCRIPTION: RAID metadevice write routine
 * PARAMETERS:	mr_unit_t *un - pointer to a unit structure
 *		md_raidcs_t *cs - pointer to a child structure
 */
static int
raid_read(mr_unit_t *un, md_raidcs_t *cs)
{
	int		error = 0;
	md_raidps_t	*ps;
	mdi_unit_t	*ui;
	minor_t		mnum;

	ASSERT(IO_READER_HELD(un));
	ps = cs->cs_ps;
	ui = ps->ps_ui;
	raid_line_reader_lock(cs, 0);
	un = (mr_unit_t *)md_unit_readerlock(ui);
	ASSERT(UNIT_STATE(un) != RUS_INIT);
	mnum = MD_SID(un);
	cs->cs_un = un;

	/* make sure the read doesn't go beyond the end of the column */
	if (cs->cs_blkno + cs->cs_blkcnt >
	    un->un_segsize * un->un_segsincolumn) {
		error = ENXIO;
	}
	if (error)
		goto rerror;

	if (un->un_state & RUS_REGEN) {
		raid_regen_parity(cs);
		un = MD_UNIT(mnum);
		cs->cs_un = un;
	}

	raid_read_io(un, cs);
	return (0);

rerror:
	raid_error_parent(ps, error);
	raid_free_child(cs, 1);
	/* decrement readfrags */
	raid_free_parent(ps, RFP_DECR_READFRAGS | RFP_RLS_LOCK);
	return (0);
}

/*
 * NAME:	raid_write_err_retry
 * DESCRIPTION: RAID metadevice write retry routine
 *		write was for parity or data only;
 *		complete write with error, no recovery possible
 * PARAMETERS:	mr_unit_t *un - pointer to a unit structure
 *		md_raidcs_t *cs - pointer to a child structure
 */
/*ARGSUSED*/
static void
raid_write_err_retry(mr_unit_t *un, md_raidcs_t *cs)
{
	md_raidps_t	*ps = cs->cs_ps;
	int		flags = RFP_DECR_FRAGS | RFP_RLS_LOCK;

	/* decrement pwfrags if needed, and frags */
	if (!(cs->cs_flags & MD_RCS_PWDONE))
		flags |= RFP_DECR_PWFRAGS;
	raid_error_parent(ps, EIO);
	raid_free_child(cs, 1);
	raid_free_parent(ps, flags);
}

/*
 * NAME:	raid_write_err_retry
 * DESCRIPTION: RAID metadevice write retry routine
 *		 write is too far along to retry and parent
 *		 has already been signaled with iodone.
 * PARAMETERS:	mr_unit_t *un - pointer to a unit structure
 *		md_raidcs_t *cs - pointer to a child structure
 */
/*ARGSUSED*/
static void
raid_write_no_retry(mr_unit_t *un, md_raidcs_t *cs)
{
	md_raidps_t	*ps = cs->cs_ps;
	int		flags = RFP_DECR_FRAGS | RFP_RLS_LOCK;

	/* decrement pwfrags if needed, and frags */
	if (!(cs->cs_flags & MD_RCS_PWDONE))
		flags |= RFP_DECR_PWFRAGS;
	raid_free_child(cs, 1);
	raid_free_parent(ps, flags);
}

/*
 * NAME:	raid_write_retry
 * DESCRIPTION: RAID metadevice write retry routine
 * PARAMETERS:	mr_unit_t *un - pointer to a unit structure
 *		md_raidcs_t *cs - pointer to a child structure
 */
static void
raid_write_retry(mr_unit_t *un, md_raidcs_t *cs)
{
	md_raidps_t	*ps;

	ps = cs->cs_ps;

	/* re-initialize the buf_t structure for raid_write() */
	cs->cs_dbuf.b_chain = (struct buf *)cs;
	cs->cs_dbuf.b_back = &cs->cs_dbuf;
	cs->cs_dbuf.b_forw = &cs->cs_dbuf;
	cs->cs_dbuf.b_flags = B_BUSY;	/* initialize flags */
	cs->cs_dbuf.b_error = 0;	/* initialize error */
	cs->cs_dbuf.b_offset = -1;
	/* Initialize semaphores */
	sema_init(&cs->cs_dbuf.b_io, 0, NULL,
	    SEMA_DEFAULT, NULL);
	sema_init(&cs->cs_dbuf.b_sem, 0, NULL,
	    SEMA_DEFAULT, NULL);

	cs->cs_pbuf.b_chain = (struct buf *)cs;
	cs->cs_pbuf.b_back = &cs->cs_pbuf;
	cs->cs_pbuf.b_forw = &cs->cs_pbuf;
	cs->cs_pbuf.b_flags = B_BUSY;	/* initialize flags */
	cs->cs_pbuf.b_error = 0;	/* initialize error */
	cs->cs_pbuf.b_offset = -1;
	sema_init(&cs->cs_pbuf.b_io, 0, NULL,
	    SEMA_DEFAULT, NULL);
	sema_init(&cs->cs_pbuf.b_sem, 0, NULL,
	    SEMA_DEFAULT, NULL);

	cs->cs_hbuf.b_chain = (struct buf *)cs;
	cs->cs_hbuf.b_back = &cs->cs_hbuf;
	cs->cs_hbuf.b_forw = &cs->cs_hbuf;
	cs->cs_hbuf.b_flags = B_BUSY;	/* initialize flags */
	cs->cs_hbuf.b_error = 0;	/* initialize error */
	cs->cs_hbuf.b_offset = -1;
	sema_init(&cs->cs_hbuf.b_io, 0, NULL,
	    SEMA_DEFAULT, NULL);
	sema_init(&cs->cs_hbuf.b_sem, 0, NULL,
	    SEMA_DEFAULT, NULL);

	cs->cs_flags &= ~(MD_RCS_ERROR);
	/*
	 * If we have already done'ed the i/o but have done prewrite
	 * on this child, then reset PWDONE flag and bump pwfrags before
	 * restarting i/o.
	 * If pwfrags is zero, we have already 'iodone'd the i/o so
	 * leave things alone.  We don't want to re-'done' it.
	 */
	mutex_enter(&ps->ps_mx);
	if (cs->cs_flags & MD_RCS_PWDONE) {
		cs->cs_flags &= ~MD_RCS_PWDONE;
		ps->ps_pwfrags++;
	}
	mutex_exit(&ps->ps_mx);
	raid_write_io(un, cs);
}

/*
 * NAME:	raid_wrerr
 * DESCRIPTION: RAID metadevice write routine
 * PARAMETERS:	md_raidcs_t *cs - pointer to a child structure
 * LOCKS:	must obtain unit writer lock while calling raid_error_state
 *		since a unit or column state transition may take place.
 *		must obtain unit reader lock to retry I/O.
 */
static void
raid_wrerr(md_raidcs_t *cs)
{
	md_raidps_t	*ps;
	mdi_unit_t	*ui;
	mr_unit_t	*un;
	md_raidcbuf_t	*cbuf;

	ps = cs->cs_ps;
	ui = ps->ps_ui;

	un = (mr_unit_t *)md_unit_writerlock(ui);
	ASSERT(un != 0);

	if (cs->cs_dbuf.b_flags & B_ERROR)
		(void) raid_error_state(un, &cs->cs_dbuf);
	if (cs->cs_pbuf.b_flags & B_ERROR)
		(void) raid_error_state(un, &cs->cs_pbuf);
	if (cs->cs_hbuf.b_flags & B_ERROR)
		(void) raid_error_state(un, &cs->cs_hbuf);
	for (cbuf = cs->cs_buflist; cbuf; cbuf = cbuf->cbuf_next)
		if (cbuf->cbuf_bp.b_flags & B_ERROR)
			(void) raid_error_state(un, &cbuf->cbuf_bp);

	md_unit_writerexit(ui);

	ps->ps_flags |= MD_RPS_HSREQ;

	un = (mr_unit_t *)md_unit_readerlock(ui);

	/* now attempt the appropriate retry routine */
	(*(cs->cs_retry_call))(un, cs);
}
/*
 * NAMES:	raid_write_error
 * DESCRIPTION: I/O error handling routine for a RAID metadevice write
 * PARAMETERS:	md_raidcs_t *cs - pointer to child structure
 */
/*ARGSUSED*/
static void
raid_write_error(md_raidcs_t *cs)
{
	md_raidps_t	*ps;
	mdi_unit_t	*ui;
	mr_unit_t	*un;
	md_raidcbuf_t	*cbuf;
	set_t		setno;

	ps = cs->cs_ps;
	ui = ps->ps_ui;
	un = cs->cs_un;

	setno = MD_UN2SET(un);

	/*
	 * locate each buf that is in error on this io and then
	 * output an error message
	 */
	if ((cs->cs_dbuf.b_flags & B_ERROR) &&
	    (COLUMN_STATE(un, cs->cs_dcolumn) != RCS_ERRED) &&
	    (COLUMN_STATE(un, cs->cs_dcolumn) != RCS_LAST_ERRED))
		cmn_err(CE_WARN, "md %s: write error on %s",
		    md_shortname(MD_SID(un)),
		    md_devname(setno, md_expldev(cs->cs_dbuf.b_edev), NULL, 0));

	if ((cs->cs_pbuf.b_flags & B_ERROR) &&
	    (COLUMN_STATE(un, cs->cs_pcolumn) != RCS_ERRED) &&
	    (COLUMN_STATE(un, cs->cs_pcolumn) != RCS_LAST_ERRED))
		cmn_err(CE_WARN, "md %s: write error on %s",
		    md_shortname(MD_SID(un)),
		    md_devname(setno, md_expldev(cs->cs_pbuf.b_edev), NULL, 0));

	for (cbuf = cs->cs_buflist; cbuf; cbuf = cbuf->cbuf_next)
		if ((cbuf->cbuf_bp.b_flags & B_ERROR) &&
		    (COLUMN_STATE(un, cbuf->cbuf_column) != RCS_ERRED) &&
		    (COLUMN_STATE(un, cbuf->cbuf_column) != RCS_LAST_ERRED))
			cmn_err(CE_WARN, "md %s: write error on %s",
			    md_shortname(MD_SID(un)),
			    md_devname(setno, md_expldev(cbuf->cbuf_bp.b_edev),
			    NULL, 0));

	md_unit_readerexit(ui);

	ASSERT(cs->cs_frags == 0);

	/* now schedule processing for possible state change */
	daemon_request(&md_mstr_daemon, raid_wrerr,
	    (daemon_queue_t *)cs, REQ_OLD);

}

/*
 * NAME:	raid_write_ponly
 * DESCRIPTION: RAID metadevice write routine
 *		in the case where only the parity column can be written
 * PARAMETERS:	md_raidcs_t *cs - pointer to a child structure
 */
static void
raid_write_ponly(md_raidcs_t *cs)
{
	md_raidps_t	*ps;
	mr_unit_t	*un = cs->cs_un;

	ps = cs->cs_ps;
	/* decrement pwfrags if needed, but not frags */
	ASSERT(!(cs->cs_flags & MD_RCS_PWDONE));
	raid_free_parent(ps, RFP_DECR_PWFRAGS);
	cs->cs_flags |= MD_RCS_PWDONE;
	cs->cs_frags = 1;
	cs->cs_stage = RAID_WRITE_PONLY_DONE;
	cs->cs_call = raid_stage;
	cs->cs_error_call = raid_write_error;
	cs->cs_retry_call = raid_write_no_retry;
	if (WRITE_ALT(un, cs->cs_pcolumn)) {
		cs->cs_frags++;
		raidio(cs, RIO_ALT | RIO_EXTRA | RIO_PARITY | RIO_WRITE);
	}
	raidio(cs, RIO_PARITY | RIO_WRITE);
}

/*
 * NAME:	raid_write_ploop
 * DESCRIPTION: RAID metadevice write routine, constructs parity from
 *		data in other columns.
 * PARAMETERS:	md_raidcs_t *cs - pointer to a child structure
 */
static void
raid_write_ploop(md_raidcs_t *cs)
{
	mr_unit_t *un = cs->cs_un;
	uint_t *dbuf;
	uint_t *pbuf;
	size_t wordcnt;
	uint_t psum = 0;

	wordcnt = cs->cs_bcount / sizeof (uint_t);
	dbuf = (uint_t *)(void *)(cs->cs_dbuffer + DEV_BSIZE);
	pbuf = (uint_t *)(void *)(cs->cs_pbuffer + DEV_BSIZE);
	while (wordcnt--)
		*pbuf++ ^= *dbuf++;
	cs->cs_loop++;

	/*
	 * build parity from scratch using new data,
	 * skip reading the data and parity columns.
	 */
	while (cs->cs_loop == cs->cs_dcolumn || cs->cs_loop == cs->cs_pcolumn)
		cs->cs_loop++;

	if (cs->cs_loop != un->un_totalcolumncnt) {
		cs->cs_frags = 1;
		raidio(cs, RIO_DATA | RIO_READ | (cs->cs_loop + 1));
		return;
	}

	/* construct checksum for parity buffer */
	wordcnt = cs->cs_bcount / sizeof (uint_t);
	pbuf = (uint_t *)(void *)(cs->cs_pbuffer + DEV_BSIZE);
	while (wordcnt--) {
		psum ^= *pbuf;
		pbuf++;
	}
	RAID_FILLIN_RPW(cs->cs_pbuffer, un, psum, -1,
	    cs->cs_blkno, cs->cs_blkcnt, cs->cs_pwid,
	    1, cs->cs_pcolumn, RAID_PWMAGIC);

	cs->cs_stage = RAID_NONE;
	cs->cs_call = raid_write_ponly;
	cs->cs_error_call = raid_write_error;
	cs->cs_retry_call = raid_write_err_retry;
	cs->cs_frags = 1;
	if (WRITE_ALT(un, cs->cs_pcolumn)) {
		cs->cs_frags++;
		raidio(cs, RIO_ALT | RIO_EXTRA | RIO_PARITY | RIO_PREWRITE);
	}
	raidio(cs, RIO_PARITY | RIO_PREWRITE);
}

/*
 * NAME:	raid_write_donly
 * DESCRIPTION: RAID metadevice write routine
 *		Completed writing data to prewrite entry
 *		in the case where only the data column can be written
 * PARAMETERS:	md_raidcs_t *cs - pointer to a child structure
 */
static void
raid_write_donly(md_raidcs_t *cs)
{
	md_raidps_t	*ps;
	mr_unit_t	*un = cs->cs_un;

	ps = cs->cs_ps;
	/* WARNING: don't release unit reader lock here... */
	/* decrement pwfrags if needed, but not frags */
	ASSERT(!(cs->cs_flags & MD_RCS_PWDONE));
	raid_free_parent(ps, RFP_DECR_PWFRAGS);
	cs->cs_flags |= MD_RCS_PWDONE;
	cs->cs_frags = 1;
	cs->cs_stage = RAID_WRITE_DONLY_DONE;
	cs->cs_call = raid_stage;
	cs->cs_error_call = raid_write_error;
	cs->cs_retry_call = raid_write_err_retry;
	if (WRITE_ALT(un, cs->cs_dcolumn)) {
		cs->cs_frags++;
		raidio(cs, RIO_ALT | RIO_EXTRA | RIO_DATA | RIO_WRITE);
	}
	raidio(cs, RIO_DATA | RIO_WRITE);
}

/*
 * NAME:	raid_write_got_old
 * DESCRIPTION: RAID metadevice write routine
 *		completed read of old data and old parity
 * PARAMETERS:	md_raidcs_t *cs - pointer to a child structure
 */
static void
raid_write_got_old(md_raidcs_t *cs)
{
	mr_unit_t *un = cs->cs_un;

	ASSERT(IO_READER_HELD(cs->cs_un));
	ASSERT(UNIT_READER_HELD(cs->cs_un));

	raid_mapin_buf(cs);
	genstandardparity(cs);
	cs->cs_frags = 2;
	cs->cs_call = raid_stage;
	cs->cs_stage = RAID_PREWRITE_DONE;
	cs->cs_error_call = raid_write_error;
	cs->cs_retry_call = raid_write_retry;

	if (WRITE_ALT(un, cs->cs_dcolumn)) {
		cs->cs_frags++;
		raidio(cs, RIO_ALT | RIO_EXTRA | RIO_DATA | RIO_PREWRITE);
	}

	if (WRITE_ALT(un, cs->cs_pcolumn)) {
		cs->cs_frags++;
		raidio(cs, RIO_ALT | RIO_EXTRA | RIO_PARITY | RIO_PREWRITE);
	}
	ASSERT(cs->cs_frags < 4);
	raidio(cs,  RIO_DATA | RIO_PREWRITE);
	raidio(cs,  RIO_PARITY | RIO_PREWRITE);
}

/*
 * NAME:	raid_write_io
 * DESCRIPTION: RAID metadevice write I/O routine
 * PARAMETERS:	mr_unit_t *un -  pointer to a unit structure
 *		md_raidcs_t *cs - pointer to a child structure
 */

/*ARGSUSED*/
static void
raid_write_io(mr_unit_t *un, md_raidcs_t *cs)
{
	md_raidps_t	*ps = cs->cs_ps;
	uint_t		*dbuf;
	uint_t		*ubuf;
	size_t		wordcnt;
	uint_t		dsum = 0;
	int		pcheck;
	int		dcheck;

	ASSERT((un->un_column[cs->cs_pcolumn].un_devstate &
	    RCS_INIT) == 0);
	ASSERT((un->un_column[cs->cs_dcolumn].un_devstate &
	    RCS_INIT) == 0);
	ASSERT(IO_READER_HELD(un));
	ASSERT(UNIT_READER_HELD(un));
	ASSERT(cs->cs_flags & MD_RCS_HAVE_PW_SLOTS);
	if (cs->cs_flags & MD_RCS_LINE) {

		mr_unit_t	*un = cs->cs_un;

		ASSERT(un->un_origcolumncnt == un->un_totalcolumncnt);
		raid_mapin_buf(cs);
		cs->cs_frags = un->un_origcolumncnt;
		cs->cs_call = raid_stage;
		cs->cs_error_call = raid_write_error;
		cs->cs_retry_call = raid_write_no_retry;
		cs->cs_stage = RAID_LINE_PWDONE;
		genlineparity(cs);
		return;
	}

	pcheck = erred_check_line(un, cs, &un->un_column[cs->cs_pcolumn]);
	dcheck = erred_check_line(un, cs, &un->un_column[cs->cs_dcolumn]);
	cs->cs_resync_check = pcheck << RCL_PARITY_OFFSET || dcheck;

	if (pcheck == RCL_ERRED && dcheck == RCL_ERRED) {
		int err = EIO;

		if ((un->un_column[cs->cs_pcolumn].un_devstate ==
		    RCS_LAST_ERRED) ||
		    (un->un_column[cs->cs_dcolumn].un_devstate ==
		    RCS_LAST_ERRED))
			err = ENXIO;
		raid_error_parent(ps, err);
		ASSERT(!(cs->cs_flags & MD_RCS_PWDONE));
		raid_free_child(cs, 1);
		raid_free_parent(ps,  RFP_DECR_FRAGS
		    | RFP_RLS_LOCK | RFP_DECR_PWFRAGS);
		return;
	}

	if (pcheck & RCL_ERRED) {
		/*
		 * handle case of only having data drive
		 */
		raid_mapin_buf(cs);
		wordcnt = cs->cs_bcount / sizeof (uint_t);

		dbuf = (uint_t *)(void *)(cs->cs_dbuffer + DEV_BSIZE);
		ubuf = (uint_t *)(void *)(cs->cs_addr);

		while (wordcnt--) {
			*dbuf = *ubuf;
			dsum ^= *ubuf;
			dbuf++;
			ubuf++;
		}
		RAID_FILLIN_RPW(cs->cs_dbuffer, un, dsum, -1,
		    cs->cs_blkno, cs->cs_blkcnt, cs->cs_pwid,
		    1, cs->cs_dcolumn, RAID_PWMAGIC);
		cs->cs_frags = 1;
		cs->cs_stage = RAID_NONE;
		cs->cs_call = raid_write_donly;
		cs->cs_error_call = raid_write_error;
		cs->cs_retry_call = raid_write_err_retry;
		if (WRITE_ALT(un, cs->cs_dcolumn)) {
			cs->cs_frags++;
			raidio(cs, RIO_DATA | RIO_ALT | RIO_EXTRA |
			    RIO_PREWRITE);
		}
		raidio(cs, RIO_DATA | RIO_PREWRITE);
		return;
	}

	if (dcheck & RCL_ERRED) {
		/*
		 * handle case of only having parity drive
		 * build parity from scratch using new data,
		 * skip reading the data and parity columns.
		 */
		raid_mapin_buf(cs);
		cs->cs_loop = 0;
		while (cs->cs_loop == cs->cs_dcolumn ||
		    cs->cs_loop == cs->cs_pcolumn)
			cs->cs_loop++;

		/* copy new data in to begin building parity */
		bcopy(cs->cs_addr, cs->cs_pbuffer + DEV_BSIZE, cs->cs_bcount);
		cs->cs_stage = RAID_NONE;
		cs->cs_call = raid_write_ploop;
		cs->cs_error_call = raid_write_error;
		cs->cs_retry_call = raid_write_err_retry;
		cs->cs_frags = 1;
		raidio(cs, RIO_DATA | RIO_READ | (cs->cs_loop + 1));
		return;
	}
	/*
	 * handle normal cases
	 * read old data and old parity
	 */
	cs->cs_frags = 2;
	cs->cs_stage = RAID_NONE;
	cs->cs_call = raid_write_got_old;
	cs->cs_error_call = raid_write_error;
	cs->cs_retry_call = raid_write_retry;
	ASSERT(ps->ps_magic == RAID_PSMAGIC);
	raidio(cs, RIO_DATA | RIO_READ);
	raidio(cs, RIO_PARITY | RIO_READ);
}

static void
raid_enqueue(md_raidcs_t *cs)
{
	mdi_unit_t	*ui = cs->cs_ps->ps_ui;
	kmutex_t	*io_list_mutex = &ui->ui_io_lock->io_list_mutex;
	md_raidcs_t	*cs1;

	mutex_enter(io_list_mutex);
	ASSERT(! (cs->cs_flags & MD_RCS_LLOCKD));
	if (ui->ui_io_lock->io_list_front == NULL) {
		ui->ui_io_lock->io_list_front = cs;
		ui->ui_io_lock->io_list_back = cs;
	} else {
		cs1 = ui->ui_io_lock->io_list_back;
		cs1->cs_linlck_next = cs;
		ui->ui_io_lock->io_list_back = cs;
	}
	STAT_INC(raid_write_waits);
	STAT_MAX(raid_max_write_q_length, raid_write_queue_length);
	cs->cs_linlck_next = NULL;
	mutex_exit(io_list_mutex);
}

/*
 * NAME:	raid_write
 * DESCRIPTION: RAID metadevice write routine
 * PARAMETERS:	mr_unit_t *un -  pointer to a unit structure
 *		md_raidcs_t *cs - pointer to a child structure
 */

/*ARGSUSED*/
static int
raid_write(mr_unit_t *un, md_raidcs_t *cs)
{
	int		error = 0;
	md_raidps_t	*ps;
	mdi_unit_t	*ui;
	minor_t		mnum;
	clock_t		timeout;

	ASSERT(IO_READER_HELD(un));
	ps = cs->cs_ps;
	ui = ps->ps_ui;

	ASSERT(UNIT_STATE(un) != RUS_INIT);
	if (UNIT_STATE(un) == RUS_LAST_ERRED)
		error = EIO;

	/* make sure the write doesn't go beyond the column */
	if (cs->cs_blkno + cs->cs_blkcnt > un->un_segsize * un->un_segsincolumn)
		error = ENXIO;
	if (error)
		goto werror;

	getresources(cs);

	/*
	 * this is an advisory loop that keeps the waiting lists short
	 * to reduce cpu time.  Since there is a race introduced by not
	 * aquiring all the correct mutexes, use a cv_timedwait to be
	 * sure the write always will wake up and start.
	 */
	while (raid_check_pw(cs)) {
		mutex_enter(&un->un_mx);
		(void) drv_getparm(LBOLT, &timeout);
		timeout += md_wr_wait;
		un->un_rflags |= MD_RFLAG_NEEDPW;
		STAT_INC(raid_prewrite_waits);
		(void) cv_timedwait(&un->un_cv, &un->un_mx, timeout);
		un->un_rflags &= ~MD_RFLAG_NEEDPW;
		mutex_exit(&un->un_mx);
	}

	if (raid_line_writer_lock(cs, 1))
		return (0);

	un = (mr_unit_t *)md_unit_readerlock(ui);
	cs->cs_un = un;
	mnum = MD_SID(un);

	if (un->un_state & RUS_REGEN) {
		raid_regen_parity(cs);
		un = MD_UNIT(mnum);
		cs->cs_un = un;
	}

	raid_write_io(un, cs);
	return (0);
werror:
	/* aquire unit reader lock sinc raid_free_child always drops it */
	raid_error_parent(ps, error);
	raid_free_child(cs, 0);
	/* decrement both pwfrags and frags */
	raid_free_parent(ps, RFP_DECR_PWFRAGS | RFP_DECR_FRAGS | RFP_RLS_LOCK);
	return (0);
}


/*
 * NAMES:	raid_stage
 * DESCRIPTION: post-processing routine for a RAID metadevice
 * PARAMETERS:	md_raidcs_t *cs - pointer to child structure
 */
static void
raid_stage(md_raidcs_t *cs)
{
	md_raidps_t	*ps = cs->cs_ps;
	mr_unit_t	*un = cs->cs_un;
	md_raidcbuf_t	*cbuf;
	buf_t		*bp;
	void		*private;
	int		flag;

	switch (cs->cs_stage) {
	case RAID_READ_DONE:
		raid_free_child(cs, 1);
		/* decrement readfrags */
		raid_free_parent(ps, RFP_DECR_READFRAGS | RFP_RLS_LOCK);
		return;

	case RAID_WRITE_DONE:
	case RAID_WRITE_PONLY_DONE:
	case RAID_WRITE_DONLY_DONE:
		/*
		 *  Completed writing real parity and/or data.
		 */
		ASSERT(cs->cs_flags & MD_RCS_PWDONE);
		raid_free_child(cs, 1);
		/* decrement frags but not pwfrags */
		raid_free_parent(ps, RFP_DECR_FRAGS | RFP_RLS_LOCK);
		return;

	case RAID_PREWRITE_DONE:
		/*
		 * completed writing data and parity to prewrite entries
		 */
		/*
		 * WARNING: don't release unit reader lock here..
		 * decrement pwfrags but not frags
		 */
		raid_free_parent(ps, RFP_DECR_PWFRAGS);
		cs->cs_flags |= MD_RCS_PWDONE;
		cs->cs_frags = 2;
		cs->cs_stage = RAID_WRITE_DONE;
		cs->cs_call = raid_stage;
		cs->cs_error_call = raid_write_error;
		cs->cs_retry_call = raid_write_no_retry;
		if (WRITE_ALT(un, cs->cs_pcolumn)) {
			cs->cs_frags++;
			raidio(cs, RIO_ALT | RIO_EXTRA | RIO_PARITY |
			    RIO_WRITE);
		}
		if (WRITE_ALT(un, cs->cs_dcolumn)) {
			cs->cs_frags++;
			raidio(cs, RIO_ALT | RIO_EXTRA | RIO_DATA | RIO_WRITE);
		}
		ASSERT(cs->cs_frags < 4);
		raidio(cs, RIO_DATA | RIO_WRITE);
		raidio(cs, RIO_PARITY | RIO_WRITE);
		if (cs->cs_pw_inval_list) {
			raid_free_pwinvalidate(cs);
		}
		return;

	case RAID_LINE_PWDONE:
		ASSERT(cs->cs_frags == 0);
		raid_free_parent(ps, RFP_DECR_PWFRAGS);
		cs->cs_flags |= MD_RCS_PWDONE;
		cs->cs_frags = un->un_origcolumncnt;
		cs->cs_call = raid_stage;
		cs->cs_error_call = raid_write_error;
		cs->cs_retry_call = raid_write_no_retry;
		cs->cs_stage = RAID_WRITE_DONE;
		for (cbuf = cs->cs_buflist; cbuf; cbuf = cbuf->cbuf_next) {
			/*
			 * fill in buffer for write to prewrite area
			 */
			bp = &cbuf->cbuf_bp;
			bp->b_back = bp;
			bp->b_forw = bp;
			bp->b_un.b_addr = cbuf->cbuf_buffer + DEV_BSIZE;
			bp->b_bcount = cbuf->cbuf_bcount;
			bp->b_bufsize = cbuf->cbuf_bcount;
			bp->b_lblkno =
			    un->un_column[cbuf->cbuf_column].un_devstart +
			    cs->cs_blkno;
			bp->b_flags &= ~(B_READ | B_WRITE | B_ERROR);
			bp->b_flags &= ~nv_available;
			bp->b_flags |= B_WRITE | B_BUSY;
			bp->b_iodone = (int (*)())raid_done;
			bp->b_edev = md_dev64_to_dev(
			    un->un_column[cbuf->cbuf_column].un_dev);
			bp->b_chain = (struct buf *)cs;
			private = cs->cs_strategy_private;
			flag = cs->cs_strategy_flag;
			md_call_strategy(bp, flag, private);
		}
		raidio(cs, RIO_DATA | RIO_WRITE);
		raidio(cs, RIO_PARITY | RIO_WRITE);
		if (cs->cs_pw_inval_list) {
			raid_free_pwinvalidate(cs);
		}
		return;

	default:
		ASSERT(0);
		break;
	}
}
/*
 * NAME:	md_raid_strategy
 * DESCRIPTION: RAID metadevice I/O oprations entry point.
 * PARAMETERS:	buf_t	  *pb - pointer to a user I/O buffer
 *		int	 flag - metadevice specific flag
 *		void *private - carry over flag ??
 *
 */

void
md_raid_strategy(buf_t *pb, int flag, void *private)
{
	md_raidps_t	*ps;
	md_raidcs_t	*cs;
	int		doing_writes;
	int		err;
	mr_unit_t	*un;
	mdi_unit_t	*ui;
	size_t		count;
	diskaddr_t	blkno;
	caddr_t		addr;
	off_t		offset;
	int		colcnt;
	minor_t		mnum;
	set_t		setno;

	ui = MDI_UNIT(getminor(pb->b_edev));
	md_kstat_waitq_enter(ui);
	un = (mr_unit_t *)md_io_readerlock(ui);
	setno = MD_MIN2SET(getminor(pb->b_edev));

	if ((flag & MD_NOBLOCK) == 0) {
		if (md_inc_iocount(setno) != 0) {
			pb->b_flags |= B_ERROR;
			pb->b_error = ENXIO;
			pb->b_resid = pb->b_bcount;
			md_kstat_waitq_exit(ui);
			md_io_readerexit(ui);
			biodone(pb);
			return;
		}
	} else {
		md_inc_iocount_noblock(setno);
	}

	mnum = MD_SID(un);
	colcnt = un->un_totalcolumncnt - 1;
	count = pb->b_bcount;

	STAT_CHECK(raid_512, count == 512);
	STAT_CHECK(raid_1024, count == 1024);
	STAT_CHECK(raid_1024_8192, count > 1024 && count < 8192);
	STAT_CHECK(raid_8192, count == 8192);
	STAT_CHECK(raid_8192_bigger, count > 8192);

	(void *) md_unit_readerlock(ui);
	if (!(flag & MD_STR_NOTTOP)) {
		err = md_checkbuf(ui, (md_unit_t *)un, pb); /* check and map */
		if (err != 0) {
			md_kstat_waitq_exit(ui);
			md_io_readerexit(ui);
			return;
		}
	}
	md_unit_readerexit(ui);

	STAT_INC(raid_total_io);

	/* allocate a parent structure for the user I/O */
	ps = kmem_cache_alloc(raid_parent_cache, MD_ALLOCFLAGS);
	raid_parent_init(ps);

	/*
	 * Save essential information from the original buffhdr
	 * in the md_save structure.
	 */
	ps->ps_un = un;
	ps->ps_ui = ui;
	ps->ps_bp = pb;
	ps->ps_addr = pb->b_un.b_addr;

	if ((pb->b_flags & B_READ) == 0) {
		ps->ps_flags |= MD_RPS_WRITE;
		doing_writes = 1;
		STAT_INC(raid_writes);
	} else {
		ps->ps_flags |= MD_RPS_READ;
		doing_writes = 0;
		STAT_INC(raid_reads);
	}

	count = lbtodb(pb->b_bcount);	/* transfer count (in blocks) */
	blkno = pb->b_lblkno;		/* block number on device */
	addr  = 0;
	offset = 0;
	ps->ps_pwfrags = 1;
	ps->ps_frags = 1;
	md_kstat_waitq_to_runq(ui);

	do {
		cs = kmem_cache_alloc(raid_child_cache, MD_ALLOCFLAGS);
		raid_child_init(cs);
		cs->cs_ps = ps;
		cs->cs_un = un;
		cs->cs_mdunit = mnum;
		cs->cs_strategy_flag = flag;
		cs->cs_strategy_private = private;
		cs->cs_addr = addr;
		cs->cs_offset = offset;
		count = raid_iosetup(un, blkno, count, cs);
		if (cs->cs_flags & MD_RCS_LINE) {
			blkno += (cs->cs_blkcnt * colcnt);
			offset += (cs->cs_bcount * colcnt);
		} else {
			blkno +=  cs->cs_blkcnt;
			offset += cs->cs_bcount;
		}
		/* for each cs bump up the ps_pwfrags and ps_frags fields */
		if (count) {
			mutex_enter(&ps->ps_mx);
			ps->ps_pwfrags++;
			ps->ps_frags++;
			mutex_exit(&ps->ps_mx);
			if (doing_writes)
				(void) raid_write(un, cs);
			else
				(void) raid_read(un, cs);
		}
	} while (count);
	if (doing_writes) {
		(void) raid_write(un, cs);
	} else
		(void) raid_read(un, cs);

	if (! (flag & MD_STR_NOTTOP) && panicstr) {
		while (! (ps->ps_flags & MD_RPS_DONE)) {
			md_daemon(1, &md_done_daemon);
			drv_usecwait(10);
		}
		kmem_cache_free(raid_parent_cache, ps);
	}
}

/*
 * NAMES:	raid_snarf
 * DESCRIPTION: RAID metadevice SNARF entry point
 * PARAMETERS:	md_snarfcmd_t cmd,
 *		set_t setno
 * RETURNS:
 */
static int
raid_snarf(md_snarfcmd_t cmd, set_t setno)
{
	mr_unit_t	*un;
	mddb_recid_t	recid;
	int		gotsomething;
	int		all_raid_gotten;
	mddb_type_t	typ1;
	uint_t		ncol;
	mddb_de_ic_t	*dep;
	mddb_rb32_t	*rbp;
	size_t		newreqsize;
	mr_unit_t	*big_un;
	mr_unit32_od_t	*small_un;


	if (cmd == MD_SNARF_CLEANUP)
		return (0);

	all_raid_gotten = 1;
	gotsomething = 0;
	typ1 = (mddb_type_t)md_getshared_key(setno,
	    raid_md_ops.md_driver.md_drivername);
	recid = mddb_makerecid(setno, 0);

	while ((recid = mddb_getnextrec(recid, typ1, 0)) > 0) {
		if (mddb_getrecprivate(recid) & MD_PRV_GOTIT) {
			continue;
		}

		dep = mddb_getrecdep(recid);
		dep->de_flags = MDDB_F_RAID;
		rbp = dep->de_rb;
		switch (rbp->rb_revision) {
		case MDDB_REV_RB:
		case MDDB_REV_RBFN:
			if ((rbp->rb_private & MD_PRV_CONVD) == 0) {
				/*
				 * This means, we have an old and small record
				 * and this record hasn't already been
				 * converted.  Before we create an incore
				 * metadevice from this we have to convert it to
				 * a big record.
				 */
				small_un =
				    (mr_unit32_od_t *)mddb_getrecaddr(recid);
				ncol = small_un->un_totalcolumncnt;
				newreqsize = sizeof (mr_unit_t) +
				    ((ncol - 1) * sizeof (mr_column_t));
				big_un = (mr_unit_t *)kmem_zalloc(newreqsize,
				    KM_SLEEP);
				raid_convert((caddr_t)small_un, (caddr_t)big_un,
				    SMALL_2_BIG);
				kmem_free(small_un, dep->de_reqsize);
				dep->de_rb_userdata = big_un;
				dep->de_reqsize = newreqsize;
				un = big_un;
				rbp->rb_private |= MD_PRV_CONVD;
			} else {
				/*
				 * Record has already been converted.  Just
				 * get its address.
				 */
				un = (mr_unit_t *)mddb_getrecaddr(recid);
			}
			un->c.un_revision &= ~MD_64BIT_META_DEV;
			break;
		case MDDB_REV_RB64:
		case MDDB_REV_RB64FN:
			/* Big device */
			un = (mr_unit_t *)mddb_getrecaddr(recid);
			un->c.un_revision |= MD_64BIT_META_DEV;
			un->c.un_flag |= MD_EFILABEL;
			break;
		}
		MDDB_NOTE_FN(rbp->rb_revision, un->c.un_revision);

		/*
		 * Create minor device node for snarfed entry.
		 */
		(void) md_create_minor_node(MD_MIN2SET(MD_SID(un)), MD_SID(un));

		if (MD_UNIT(MD_SID(un)) != NULL) {
			mddb_setrecprivate(recid, MD_PRV_PENDDEL);
			continue;
		}
		all_raid_gotten = 0;
		if (raid_build_incore((void *)un, 1) == 0) {
			mddb_setrecprivate(recid, MD_PRV_GOTIT);
			md_create_unit_incore(MD_SID(un), &raid_md_ops, 1);
			gotsomething = 1;
		} else if (un->mr_ic) {
			kmem_free(un->un_column_ic, sizeof (mr_column_ic_t) *
			    un->un_totalcolumncnt);
			kmem_free(un->mr_ic, sizeof (*un->mr_ic));
		}
	}

	if (!all_raid_gotten) {
		return (gotsomething);
	}

	recid = mddb_makerecid(setno, 0);
	while ((recid = mddb_getnextrec(recid, typ1, 0)) > 0)
		if (!(mddb_getrecprivate(recid) & MD_PRV_GOTIT))
			mddb_setrecprivate(recid, MD_PRV_PENDDEL);

	return (0);
}

/*
 * NAMES:	raid_halt
 * DESCRIPTION: RAID metadevice HALT entry point
 * PARAMETERS:	md_haltcmd_t cmd -
 *		set_t	setno -
 * RETURNS:
 */
static int
raid_halt(md_haltcmd_t cmd, set_t setno)
{
	set_t		i;
	mdi_unit_t	*ui;
	minor_t		mnum;

	if (cmd == MD_HALT_CLOSE)
		return (0);

	if (cmd == MD_HALT_OPEN)
		return (0);

	if (cmd == MD_HALT_UNLOAD)
		return (0);

	if (cmd == MD_HALT_CHECK) {
		for (i = 0; i < md_nunits; i++) {
			mnum = MD_MKMIN(setno, i);
			if ((ui = MDI_UNIT(mnum)) == NULL)
				continue;
			if (ui->ui_opsindex != raid_md_ops.md_selfindex)
				continue;
			if (md_unit_isopen(ui))
				return (1);
		}
		return (0);
	}

	if (cmd != MD_HALT_DOIT)
		return (1);

	for (i = 0; i < md_nunits; i++) {
		mnum = MD_MKMIN(setno, i);
		if ((ui = MDI_UNIT(mnum)) == NULL)
			continue;
		if (ui->ui_opsindex != raid_md_ops.md_selfindex)
			continue;
		reset_raid((mr_unit_t *)MD_UNIT(mnum), mnum, 0);
	}
	return (0);
}

/*
 * NAMES:	raid_close_all_devs
 * DESCRIPTION: Close all the devices of the unit.
 * PARAMETERS:	mr_unit_t *un - pointer to unit structure
 * RETURNS:
 */
void
raid_close_all_devs(mr_unit_t *un, int init_pw, int md_cflags)
{
	int		i;
	mr_column_t	*device;

	for (i = 0; i < un->un_totalcolumncnt; i++) {
		device = &un->un_column[i];
		if (device->un_devflags & MD_RAID_DEV_ISOPEN) {
			ASSERT((device->un_dev != (md_dev64_t)0) &&
			    (device->un_dev != NODEV64));
			if ((device->un_devstate & RCS_OKAY) && init_pw)
				(void) init_pw_area(un, device->un_dev,
				    device->un_pwstart, i);
			md_layered_close(device->un_dev, md_cflags);
			device->un_devflags &= ~MD_RAID_DEV_ISOPEN;
		}
	}
}

/*
 * NAMES:	raid_open_all_devs
 * DESCRIPTION: Open all the components (columns) of the device unit.
 * PARAMETERS:	mr_unit_t *un - pointer to unit structure
 * RETURNS:
 */
static int
raid_open_all_devs(mr_unit_t *un, int md_oflags)
{
	minor_t		mnum = MD_SID(un);
	int		i;
	int		not_opened = 0;
	int		commit = 0;
	int		col = -1;
	mr_column_t	*device;
	set_t		setno = MD_MIN2SET(MD_SID(un));
	side_t		side = mddb_getsidenum(setno);
	mdkey_t		key;
	mdi_unit_t	*ui = MDI_UNIT(mnum);

	ui->ui_tstate &= ~MD_INACCESSIBLE;

	for (i = 0; i < un->un_totalcolumncnt; i++) {
		md_dev64_t tmpdev;

		device = &un->un_column[i];

		if (COLUMN_STATE(un, i) & RCS_ERRED) {
			not_opened++;
			continue;
		}

		if (device->un_devflags & MD_RAID_DEV_ISOPEN)
			continue;

		tmpdev = device->un_dev;
		/*
		 * Open by device id
		 */
		key = HOTSPARED(un, i) ?
		    device->un_hs_key : device->un_orig_key;
		if ((md_getmajor(tmpdev) != md_major) &&
		    md_devid_found(setno, side, key) == 1) {
			tmpdev = md_resolve_bydevid(mnum, tmpdev, key);
		}
		if (md_layered_open(mnum, &tmpdev, md_oflags)) {
			device->un_dev = tmpdev;
			not_opened++;
			continue;
		}
		device->un_dev = tmpdev;
		device->un_devflags |= MD_RAID_DEV_ISOPEN;
	}

	/* if open errors and errored devices are 1 then device can run */
	if (not_opened > 1) {
		cmn_err(CE_WARN,
		    "md: %s failed to open. open error on %s\n",
		    md_shortname(MD_SID(un)),
		    md_devname(MD_UN2SET(un), device->un_orig_dev, NULL, 0));

		ui->ui_tstate |= MD_INACCESSIBLE;

		SE_NOTIFY(EC_SVM_STATE, ESC_SVM_OPEN_FAIL, SVM_TAG_METADEVICE,
		    MD_UN2SET(un), MD_SID(un));

		return (not_opened > 1);
	}

	for (i = 0; i < un->un_totalcolumncnt; i++) {
		device = &un->un_column[i];
		if (device->un_devflags & MD_RAID_DEV_ISOPEN) {
			if (device->un_devstate & RCS_LAST_ERRED) {
			/*
			 * At this point in time there is a possibility
			 * that errors were the result of a controller
			 * failure with more than a single column on it
			 * so clear out last errored columns and let errors
			 * re-occur is necessary.
			 */
				raid_set_state(un, i, RCS_OKAY, 0);
				commit++;
			}
			continue;
		}
		ASSERT(col == -1);
		col = i;
	}

	if (col != -1) {
		raid_set_state(un, col, RCS_ERRED, 0);
		commit++;
	}

	if (commit)
		raid_commit(un, NULL);

	if (col != -1) {
		if (COLUMN_STATE(un, col) & RCS_ERRED) {
			SE_NOTIFY(EC_SVM_STATE, ESC_SVM_ERRED,
			    SVM_TAG_METADEVICE, MD_UN2SET(un), MD_SID(un));
		} else if (COLUMN_STATE(un, col) & RCS_LAST_ERRED) {
			SE_NOTIFY(EC_SVM_STATE, ESC_SVM_LASTERRED,
			    SVM_TAG_METADEVICE, MD_UN2SET(un), MD_SID(un));
		}
	}

	return (0);
}

/*
 * NAMES:	raid_internal_open
 * DESCRIPTION: Do the actual RAID open
 * PARAMETERS:	minor_t mnum - minor number of the RAID device
 *		int flag -
 *		int otyp -
 *		int md_oflags - RAID open flags
 * RETURNS:	0 if successful, nonzero otherwise
 */
int
raid_internal_open(minor_t mnum, int flag, int otyp, int md_oflags)
{
	mr_unit_t	*un;
	mdi_unit_t	*ui;
	int		err = 0;
	int		replay_error = 0;

	ui = MDI_UNIT(mnum);
	ASSERT(ui != NULL);

	un = (mr_unit_t *)md_unit_openclose_enter(ui);
	/*
	 * this MUST be checked before md_unit_isopen is checked.
	 * raid_init_columns sets md_unit_isopen to block reset, halt.
	 */
	if ((UNIT_STATE(un) & (RUS_INIT | RUS_DOI)) &&
	    !(md_oflags & MD_OFLG_ISINIT)) {
		md_unit_openclose_exit(ui);
		return (EAGAIN);
	}

	if ((md_oflags & MD_OFLG_ISINIT) || md_unit_isopen(ui)) {
		err = md_unit_incopen(mnum, flag, otyp);
		goto out;
	}

	md_unit_readerexit(ui);

	un = (mr_unit_t *)md_unit_writerlock(ui);
	if (raid_open_all_devs(un, md_oflags) == 0) {
		if ((err = md_unit_incopen(mnum, flag, otyp)) != 0) {
			md_unit_writerexit(ui);
			un = (mr_unit_t *)md_unit_readerlock(ui);
			raid_close_all_devs(un, 0, md_oflags);
			goto out;
		}
	} else {
		/*
		 * if this unit contains more than two errored components
		 * should return error and close all opened devices
		 */

		md_unit_writerexit(ui);
		un = (mr_unit_t *)md_unit_readerlock(ui);
		raid_close_all_devs(un, 0, md_oflags);
		md_unit_openclose_exit(ui);
		SE_NOTIFY(EC_SVM_STATE, ESC_SVM_OPEN_FAIL, SVM_TAG_METADEVICE,
		    MD_UN2SET(un), MD_SID(un));
		return (ENXIO);
	}

	if (!(MD_STATUS(un) & MD_UN_REPLAYED)) {
		replay_error = raid_replay(un);
		MD_STATUS(un) |= MD_UN_REPLAYED;
	}

	md_unit_writerexit(ui);
	un = (mr_unit_t *)md_unit_readerlock(ui);

	if ((replay_error == RAID_RPLY_READONLY) &&
	    ((flag & (FREAD | FWRITE)) == FREAD)) {
		md_unit_openclose_exit(ui);
		return (0);
	}

	/* allocate hotspare if possible */
	(void) raid_hotspares();


out:
	md_unit_openclose_exit(ui);
	return (err);
}
/*
 * NAMES:	raid_open
 * DESCRIPTION: RAID metadevice OPEN entry point
 * PARAMETERS:	dev_t dev -
 *		int flag -
 *		int otyp -
 *		cred_t * cred_p -
 *		int md_oflags -
 * RETURNS:
 */
/*ARGSUSED1*/
static int
raid_open(dev_t *dev, int flag, int otyp, cred_t *cred_p, int md_oflags)
{
	int		error = 0;

	if (error = raid_internal_open(getminor(*dev), flag, otyp, md_oflags)) {
		return (error);
	}
	return (0);
}

/*
 * NAMES:	raid_internal_close
 * DESCRIPTION: RAID metadevice CLOSE actual implementation
 * PARAMETERS:	minor_t - minor number of the RAID device
 *		int otyp -
 *		int init_pw -
 *		int md_cflags - RAID close flags
 * RETURNS:	0 if successful, nonzero otherwise
 */
/*ARGSUSED*/
int
raid_internal_close(minor_t mnum, int otyp, int init_pw, int md_cflags)
{
	mdi_unit_t	*ui = MDI_UNIT(mnum);
	mr_unit_t	*un;
	int		err = 0;

	/* single thread */
	un = (mr_unit_t *)md_unit_openclose_enter(ui);

	/* count closed */
	if ((err = md_unit_decopen(mnum, otyp)) != 0)
		goto out;
	/* close devices, if necessary */
	if (! md_unit_isopen(ui) || (md_cflags & MD_OFLG_PROBEDEV)) {
		raid_close_all_devs(un, init_pw, md_cflags);
	}

	/* unlock, return success */
out:
	md_unit_openclose_exit(ui);
	return (err);
}

/*
 * NAMES:	raid_close
 * DESCRIPTION: RAID metadevice close entry point
 * PARAMETERS:	dev_t dev -
 *		int flag -
 *		int otyp -
 *		cred_t * cred_p -
 *		int md_oflags -
 * RETURNS:
 */
/*ARGSUSED1*/
static int
raid_close(dev_t dev, int flag, int otyp, cred_t *cred_p, int md_cflags)
{
	int retval;

	(void) md_io_writerlock(MDI_UNIT(getminor(dev)));
	retval = raid_internal_close(getminor(dev), otyp, 1, md_cflags);
	(void) md_io_writerexit(MDI_UNIT(getminor(dev)));
	return (retval);
}

/*
 * raid_probe_close_all_devs
 */
void
raid_probe_close_all_devs(mr_unit_t *un)
{
	int		i;
	mr_column_t	*device;

	for (i = 0; i < un->un_totalcolumncnt; i++) {
		device = &un->un_column[i];

		if (device->un_devflags & MD_RAID_DEV_PROBEOPEN) {
			md_layered_close(device->un_dev,
			    MD_OFLG_PROBEDEV);
			device->un_devflags &= ~MD_RAID_DEV_PROBEOPEN;
		}
	}
}
/*
 * Raid_probe_dev:
 *
 * On entry the unit writerlock is held
 */
static int
raid_probe_dev(mdi_unit_t *ui, minor_t mnum)
{
	mr_unit_t	*un;
	int		i;
	int		not_opened = 0;
	int		commit = 0;
	int		col = -1;
	mr_column_t	*device;
	int		md_devopen = 0;

	if (md_unit_isopen(ui))
		md_devopen++;

	un = MD_UNIT(mnum);
	/*
	 * If the state has been set to LAST_ERRED because
	 * of an error when the raid device was open at some
	 * point in the past, don't probe. We really don't want
	 * to reset the state in this case.
	 */
	if (UNIT_STATE(un) == RUS_LAST_ERRED)
		return (0);

	ui->ui_tstate &= ~MD_INACCESSIBLE;

	for (i = 0; i < un->un_totalcolumncnt; i++) {
		md_dev64_t tmpdev;

		device = &un->un_column[i];
		if (COLUMN_STATE(un, i) & RCS_ERRED) {
			not_opened++;
			continue;
		}

		tmpdev = device->un_dev;
		/*
		 * Currently the flags passed are not needed since
		 * there cannot be an underlying metadevice. However
		 * they are kept here for consistency.
		 *
		 * Open by device id
		 */
		tmpdev = md_resolve_bydevid(mnum, tmpdev, HOTSPARED(un, i)?
		    device->un_hs_key : device->un_orig_key);
		if (md_layered_open(mnum, &tmpdev,
		    MD_OFLG_CONT_ERRS | MD_OFLG_PROBEDEV)) {
			device->un_dev = tmpdev;
			not_opened++;
			continue;
		}
		device->un_dev = tmpdev;

		device->un_devflags |= MD_RAID_DEV_PROBEOPEN;
	}

	/*
	 * The code below is careful on setting the LAST_ERRED state.
	 *
	 * If open errors and exactly one device has failed we can run.
	 * If more then one device fails we have to figure out when to set
	 * LAST_ERRED state.  The rationale is to avoid unnecessary resyncs
	 * since they are painful and time consuming.
	 *
	 * When more than one component/column fails there are 2 scenerios.
	 *
	 * 1. Metadevice has NOT been opened: In this case, the behavior
	 *    mimics the open symantics. ie. Only the first failed device
	 *    is ERRED and LAST_ERRED is not set.
	 *
	 * 2. Metadevice has been opened: Here the read/write sematics are
	 *    followed. The first failed devicce is ERRED and on the next
	 *    failed device LAST_ERRED is set.
	 */

	if (not_opened > 1 && !md_devopen) {
		cmn_err(CE_WARN,
		    "md: %s failed to open. open error on %s\n",
		    md_shortname(MD_SID(un)),
		    md_devname(MD_UN2SET(un), device->un_orig_dev, NULL, 0));
		SE_NOTIFY(EC_SVM_STATE, ESC_SVM_OPEN_FAIL, SVM_TAG_METADEVICE,
		    MD_UN2SET(un), MD_SID(un));
		raid_probe_close_all_devs(un);
		ui->ui_tstate |= MD_INACCESSIBLE;
		return (not_opened > 1);
	}

	if (!md_devopen) {
		for (i = 0; i < un->un_totalcolumncnt; i++) {
			device = &un->un_column[i];
			if (device->un_devflags & MD_RAID_DEV_PROBEOPEN) {
				if (device->un_devstate & RCS_LAST_ERRED) {
					/*
					 * At this point in time there is a
					 * possibility that errors were the
					 * result of a controller failure with
					 * more than a single column on it so
					 * clear out last errored columns and
					 * let errors re-occur is necessary.
					 */
					raid_set_state(un, i, RCS_OKAY, 0);
					commit++;
					}
				continue;
			}
			ASSERT(col == -1);
			/*
			 * note if multiple devices are failing then only
			 * the last one is marked as error
			 */
			col = i;
		}

		if (col != -1) {
			raid_set_state(un, col, RCS_ERRED, 0);
			commit++;
		}

	} else {
		for (i = 0; i < un->un_totalcolumncnt; i++) {
			device = &un->un_column[i];

			/* if we have LAST_ERRED go ahead and commit. */
			if (un->un_state & RUS_LAST_ERRED)
				break;
			/*
			 * could not open the component
			 */

			if (!(device->un_devflags & MD_RAID_DEV_PROBEOPEN)) {
				col = i;
				raid_set_state(un, col, RCS_ERRED, 0);
				commit++;
			}
		}
	}

	if (commit)
		raid_commit(un, NULL);

	if (col != -1) {
		if (COLUMN_STATE(un, col) & RCS_ERRED) {
			SE_NOTIFY(EC_SVM_STATE, ESC_SVM_ERRED,
			    SVM_TAG_METADEVICE, MD_UN2SET(un), MD_SID(un));
		} else if (COLUMN_STATE(un, col) & RCS_LAST_ERRED) {
			SE_NOTIFY(EC_SVM_STATE, ESC_SVM_LASTERRED,
			    SVM_TAG_METADEVICE, MD_UN2SET(un), MD_SID(un));
		}
	}

	raid_probe_close_all_devs(un);
	return (0);
}

static int
raid_imp_set(
	set_t	setno
)
{
	mddb_recid_t    recid;
	int		i, gotsomething;
	mddb_type_t	typ1;
	mddb_de_ic_t	*dep;
	mddb_rb32_t	*rbp;
	mr_unit_t	*un64;
	mr_unit32_od_t	*un32;
	md_dev64_t	self_devt;
	minor_t		*self_id;	/* minor needs to be updated */
	md_parent_t	*parent_id;	/* parent needs to be updated */
	mddb_recid_t	*record_id;	 /* record id needs to be updated */
	hsp_t		*hsp_id;

	gotsomething = 0;

	typ1 = (mddb_type_t)md_getshared_key(setno,
	    raid_md_ops.md_driver.md_drivername);
	recid = mddb_makerecid(setno, 0);

	while ((recid = mddb_getnextrec(recid, typ1, 0)) > 0) {
		if (mddb_getrecprivate(recid) & MD_PRV_GOTIT)
			continue;

		dep = mddb_getrecdep(recid);
		rbp = dep->de_rb;

		switch (rbp->rb_revision) {
		case MDDB_REV_RB:
		case MDDB_REV_RBFN:
			/*
			 * Small device
			 */
			un32 = (mr_unit32_od_t *)mddb_getrecaddr(recid);
			self_id = &(un32->c.un_self_id);
			parent_id = &(un32->c.un_parent);
			record_id = &(un32->c.un_record_id);
			hsp_id = &(un32->un_hsp_id);

			for (i = 0; i < un32->un_totalcolumncnt; i++) {
				mr_column32_od_t *device;

				device = &un32->un_column[i];
				if (!md_update_minor(setno, mddb_getsidenum
				    (setno), device->un_orig_key))
					goto out;

				if (device->un_hs_id != 0)
					device->un_hs_id =
					    MAKERECID(setno, device->un_hs_id);
			}
			break;
		case MDDB_REV_RB64:
		case MDDB_REV_RB64FN:
			un64 = (mr_unit_t *)mddb_getrecaddr(recid);
			self_id = &(un64->c.un_self_id);
			parent_id = &(un64->c.un_parent);
			record_id = &(un64->c.un_record_id);
			hsp_id = &(un64->un_hsp_id);

			for (i = 0; i < un64->un_totalcolumncnt; i++) {
				mr_column_t	*device;

				device = &un64->un_column[i];
				if (!md_update_minor(setno, mddb_getsidenum
				    (setno), device->un_orig_key))
					goto out;

				if (device->un_hs_id != 0)
					device->un_hs_id =
					    MAKERECID(setno, device->un_hs_id);
			}
			break;
		}

		/*
		 * If this is a top level and a friendly name metadevice,
		 * update its minor in the namespace.
		 */
		if ((*parent_id == MD_NO_PARENT) &&
		    ((rbp->rb_revision == MDDB_REV_RBFN) ||
		    (rbp->rb_revision == MDDB_REV_RB64FN))) {

			self_devt = md_makedevice(md_major, *self_id);
			if (!md_update_top_device_minor(setno,
			    mddb_getsidenum(setno), self_devt))
				goto out;
		}

		/*
		 * Update unit with the imported setno
		 */
		mddb_setrecprivate(recid, MD_PRV_GOTIT);

		*self_id = MD_MKMIN(setno, MD_MIN2UNIT(*self_id));

		if (*hsp_id != -1)
			*hsp_id = MAKERECID(setno, DBID(*hsp_id));

		if (*parent_id != MD_NO_PARENT)
			*parent_id = MD_MKMIN(setno, MD_MIN2UNIT(*parent_id));
		*record_id = MAKERECID(setno, DBID(*record_id));
		gotsomething = 1;
	}

out:
	return (gotsomething);
}

static md_named_services_t raid_named_services[] = {
	{raid_hotspares,			"poke hotspares"	},
	{raid_rename_check,			MDRNM_CHECK		},
	{raid_rename_lock,			MDRNM_LOCK		},
	{(intptr_t (*)()) raid_rename_unlock,	MDRNM_UNLOCK		},
	{(intptr_t (*)()) raid_probe_dev,	"probe open test"	},
	{NULL,					0			}
};

md_ops_t raid_md_ops = {
	raid_open,		/* open */
	raid_close,		/* close */
	md_raid_strategy,	/* strategy */
	NULL,			/* print */
	NULL,			/* dump */
	NULL,			/* read */
	NULL,			/* write */
	md_raid_ioctl,		/* ioctl, */
	raid_snarf,		/* raid_snarf */
	raid_halt,		/* raid_halt */
	NULL,			/* aread */
	NULL,			/* awrite */
	raid_imp_set,		/* import set */
	raid_named_services
};

static void
init_init()
{
	/* default to a second */
	if (md_wr_wait == 0)
		md_wr_wait = md_hz >> 1;

	raid_parent_cache = kmem_cache_create("md_raid_parent",
	    sizeof (md_raidps_t), 0, raid_parent_constructor,
	    raid_parent_destructor, raid_run_queue, NULL, NULL, 0);
	raid_child_cache = kmem_cache_create("md_raid_child",
	    sizeof (md_raidcs_t) - sizeof (buf_t) + biosize(), 0,
	    raid_child_constructor, raid_child_destructor,
	    raid_run_queue, NULL, NULL, 0);
	raid_cbuf_cache = kmem_cache_create("md_raid_cbufs",
	    sizeof (md_raidcbuf_t), 0, raid_cbuf_constructor,
	    raid_cbuf_destructor, raid_run_queue, NULL, NULL, 0);
}

static void
fini_uninit()
{
	kmem_cache_destroy(raid_parent_cache);
	kmem_cache_destroy(raid_child_cache);
	kmem_cache_destroy(raid_cbuf_cache);
	raid_parent_cache = raid_child_cache = raid_cbuf_cache = NULL;
}

/* define the module linkage */
MD_PLUGIN_MISC_MODULE("raid module", init_init(), fini_uninit())
