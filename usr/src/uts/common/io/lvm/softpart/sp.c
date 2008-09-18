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
 * Soft partitioning metadevice driver (md_sp).
 *
 * This file contains the primary operations of the soft partitioning
 * metadevice driver.  This includes all routines for normal operation
 * (open/close/read/write).  Please see mdvar.h for a definition of
 * metadevice operations vector (md_ops_t).  This driver is loosely
 * based on the stripe driver (md_stripe).
 *
 * All metadevice administration is done through the use of ioctl's.
 * As such, all administrative routines appear in sp_ioctl.c.
 *
 * Soft partitions are represented both in-core and in the metadb with a
 * unit structure.  The soft partition-specific information in the unit
 * structure includes the following information:
 *	- Device information (md_dev64_t & md key) about the device on which
 *	  the soft partition is built.
 *	- Soft partition status information.
 *	- The size of the soft partition and number of extents used to
 *	  make up that size.
 *	- An array of exents which define virtual/physical offset
 *	  mappings and lengths for each extent.
 *
 * Typical soft partition operation proceeds as follows:
 *	- The unit structure is fetched from the metadb and placed into
 *	  an in-core array (as with other metadevices).  This operation
 *	  is performed via sp_build_incore( ) and takes place during
 *	  "snarfing" (when all metadevices are brought in-core at
 *	  once) and when a new soft partition is created.
 *	- A soft partition is opened via sp_open( ).  At open time the
 *	  the soft partition unit structure is verified with the soft
 *	  partition on-disk structures.  Additionally, the soft partition
 *	  status is checked (only soft partitions in the OK state may be
 *	  opened).
 *	- Soft partition I/O is performed via sp_strategy( ) which relies on
 *	  a support routine, sp_mapbuf( ), to do most of the work.
 *	  sp_mapbuf( ) maps a buffer to a particular extent via a binary
 *	  search of the extent array in the soft partition unit structure.
 *	  Once a translation has been performed, the I/O is passed down
 *	  to the next layer, which may be another metadevice or a physical
 *	  disk.  Since a soft partition may contain multiple, non-contiguous
 *	  extents, a single I/O may have to be fragmented.
 *	- Soft partitions are closed using sp_close.
 *
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
#include <sys/lvm/mdvar.h>
#include <sys/lvm/md_sp.h>
#include <sys/lvm/md_convert.h>
#include <sys/lvm/md_notify.h>
#include <sys/lvm/md_crc.h>
#include <sys/modctl.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/debug.h>

#include <sys/sysevent/eventdefs.h>
#include <sys/sysevent/svm.h>

md_ops_t		sp_md_ops;
#ifndef	lint
char			_depends_on[] = "drv/md";
md_ops_t		*md_interface_ops = &sp_md_ops;
#endif

extern unit_t		md_nunits;
extern set_t		md_nsets;
extern md_set_t		md_set[];

extern int		md_status;
extern major_t		md_major;
extern mdq_anchor_t	md_done_daemon;
extern mdq_anchor_t	md_sp_daemon;
extern kmutex_t		md_mx;
extern kcondvar_t	md_cv;
extern md_krwlock_t	md_unit_array_rw;

static kmem_cache_t	*sp_parent_cache = NULL;
static kmem_cache_t	*sp_child_cache = NULL;
static void		sp_send_stat_ok(mp_unit_t *);
static void		sp_send_stat_err(mp_unit_t *);

/*
 * FUNCTION:	sp_parent_constructor()
 * INPUT:	none.
 * OUTPUT:	ps	- parent save structure initialized.
 * RETURNS:	void *	- ptr to initialized parent save structure.
 * PURPOSE:	initialize parent save structure.
 */
/*ARGSUSED1*/
static int
sp_parent_constructor(void *p, void *d1, int d2)
{
	mutex_init(&((md_spps_t *)p)->ps_mx,
	    NULL, MUTEX_DEFAULT, NULL);
	return (0);
}

static void
sp_parent_init(md_spps_t *ps)
{
	bzero(ps, offsetof(md_spps_t, ps_mx));
}

/*ARGSUSED1*/
static void
sp_parent_destructor(void *p, void *d)
{
	mutex_destroy(&((md_spps_t *)p)->ps_mx);
}

/*
 * FUNCTION:	sp_child_constructor()
 * INPUT:	none.
 * OUTPUT:	cs	- child save structure initialized.
 * RETURNS:	void *	- ptr to initialized child save structure.
 * PURPOSE:	initialize child save structure.
 */
/*ARGSUSED1*/
static int
sp_child_constructor(void *p, void *d1, int d2)
{
	bioinit(&((md_spcs_t *)p)->cs_buf);
	return (0);
}

static void
sp_child_init(md_spcs_t *cs)
{
	cs->cs_mdunit = 0;
	cs->cs_ps = NULL;
	md_bioreset(&cs->cs_buf);
}

/*ARGSUSED1*/
static void
sp_child_destructor(void *p, void *d)
{
	biofini(&((md_spcs_t *)p)->cs_buf);
}

/*
 * FUNCTION:	sp_run_queue()
 * INPUT:	none.
 * OUTPUT:	none.
 * RETURNS:	void.
 * PURPOSE:	run the md_daemon to clean up memory pool.
 */
/*ARGSUSED*/
static void
sp_run_queue(void *d)
{
	if (!(md_status & MD_GBL_DAEMONS_LIVE))
		md_daemon(1, &md_done_daemon);
}


/*
 * FUNCTION:	sp_build_incore()
 * INPUT:	p		- ptr to unit structure.
 *		snarfing	- flag to tell us we are snarfing.
 * OUTPUT:	non.
 * RETURNS:	int	- 0 (always).
 * PURPOSE:	place unit structure into in-core unit array (keyed from
 *		minor number).
 */
int
sp_build_incore(void *p, int snarfing)
{
	mp_unit_t	*un = (mp_unit_t *)p;
	minor_t		mnum;
	set_t		setno;
	md_dev64_t	tmpdev;

	mnum = MD_SID(un);

	if (MD_UNIT(mnum) != NULL)
		return (0);

	MD_STATUS(un) = 0;

	if (snarfing) {
		/*
		 * if we are snarfing, we get the device information
		 * from the metadb record (using the metadb key for
		 * that device).
		 */
		setno = MD_MIN2SET(mnum);

		tmpdev = md_getdevnum(setno, mddb_getsidenum(setno),
		    un->un_key, MD_NOTRUST_DEVT);
		un->un_dev = tmpdev;
	}

	/* place various information in the in-core data structures */
	md_nblocks_set(mnum, un->c.un_total_blocks);
	MD_UNIT(mnum) = un;

	return (0);
}

/*
 * FUNCTION:	reset_sp()
 * INPUT:	un		- unit structure to be reset/removed.
 *		mnum		- minor number to be reset/removed.
 *		removing	- flag to tell us if we are removing
 *				  permanently or just reseting in-core
 *				  structures.
 * OUTPUT:	none.
 * RETURNS:	void.
 * PURPOSE:	used to either simply reset in-core structures or to
 *		permanently remove metadevices from the metadb.
 */
void
reset_sp(mp_unit_t *un, minor_t mnum, int removing)
{
	sv_dev_t	*sv;
	mddb_recid_t	vtoc_id;

	/* clean up in-core structures */
	md_destroy_unit_incore(mnum, &sp_md_ops);

	md_nblocks_set(mnum, -1ULL);
	MD_UNIT(mnum) = NULL;

	/*
	 * Attempt release of minor node
	 */
	md_remove_minor_node(mnum);

	if (!removing)
		return;

	/* we are removing the soft partition from the metadb */

	/*
	 * Save off device information so we can get to
	 * it after we do the mddb_deleterec().
	 */
	sv = (sv_dev_t *)kmem_alloc(sizeof (sv_dev_t), KM_SLEEP);
	sv->setno = MD_MIN2SET(mnum);
	sv->key = un->un_key;
	vtoc_id = un->c.un_vtoc_id;

	/*
	 * Remove self from the namespace
	 */
	if (un->c.un_revision & MD_FN_META_DEV) {
		(void) md_rem_selfname(un->c.un_self_id);
	}

	/* Remove the unit structure */
	mddb_deleterec_wrapper(un->c.un_record_id);

	if (vtoc_id)
		mddb_deleterec_wrapper(vtoc_id);

	SE_NOTIFY(EC_SVM_CONFIG, ESC_SVM_DELETE, TAG_METADEVICE,
	    MD_MIN2SET(mnum), MD_MIN2UNIT(mnum));

	/*
	 * remove the underlying device name from the metadb.  if other
	 * soft partitions are built on this device, this will simply
	 * decrease the reference count for this device.  otherwise the
	 * name record for this device will be removed from the metadb.
	 */
	md_rem_names(sv, 1);
	kmem_free(sv, sizeof (sv_dev_t));
}

/*
 * FUNCTION:	sp_send_stat_msg
 * INPUT:	un	- unit reference
 *		status	- status to be sent to master node
 *			MD_SP_OK - soft-partition is now OK
 *			MD_SP_ERR	"	"	 errored
 * OUTPUT:	none.
 * RETURNS:	void.
 * PURPOSE:	send a soft-partition status change to the master node. If the
 *		message succeeds we simply return. If it fails we panic as the
 *		cluster-wide view of the metadevices is now inconsistent.
 * CALLING CONTEXT:
 *	Blockable. No locks can be held.
 */
static void
sp_send_stat_msg(mp_unit_t *un, sp_status_t status)
{
	md_mn_msg_sp_setstat_t	sp_msg;
	md_mn_kresult_t	*kres;
	set_t		setno = MD_UN2SET(un);
	int		rval;
	const char	*str = (status == MD_SP_ERR) ? "MD_SP_ERR" : "MD_SP_OK";

	sp_msg.sp_setstat_mnum = MD_SID(un);
	sp_msg.sp_setstat_status = status;

	kres = kmem_alloc(sizeof (md_mn_kresult_t), KM_SLEEP);

	rval = mdmn_ksend_message(setno, MD_MN_MSG_SP_SETSTAT2, MD_MSGF_NO_LOG,
	    (char *)&sp_msg, sizeof (sp_msg), kres);

	if (!MDMN_KSEND_MSG_OK(rval, kres)) {
		mdmn_ksend_show_error(rval, kres, "MD_MN_MSG_SP_SETSTAT2");

		/*
		 * Panic as we are now in an inconsistent state.
		 */

		cmn_err(CE_PANIC, "md: %s: %s could not be set on all nodes\n",
		    md_shortname(MD_SID(un)), str);
	}

	kmem_free(kres, sizeof (md_mn_kresult_t));
}

/*
 * FUNCTION:	sp_finish_error
 * INPUT:	ps	- parent save structure for error-ed I/O.
 *		lock_held	- set if the unit readerlock is held
 * OUTPUT:	none.
 * RETURNS:	void.
 * PURPOSE:	report a driver error
 */
static void
sp_finish_error(md_spps_t *ps, int lock_held)
{
	struct buf	*pb = ps->ps_bp;
	mdi_unit_t	*ui = ps->ps_ui;
	md_dev64_t	un_dev;			/* underlying device */
	md_dev64_t	md_dev = md_expldev(pb->b_edev); /* metadev in error */
	char		*str;

	un_dev = md_expldev(ps->ps_un->un_dev);
	/* set error type */
	if (pb->b_flags & B_READ) {
		str = "read";
	} else {
		str = "write";
	}


	SPPS_FREE(sp_parent_cache, ps);
	pb->b_flags |= B_ERROR;

	md_kstat_done(ui, pb, 0);

	if (lock_held) {
		md_unit_readerexit(ui);
	}
	md_biodone(pb);

	cmn_err(CE_WARN, "md: %s: %s error on %s",
	    md_shortname(md_getminor(md_dev)), str,
	    md_devname(MD_DEV2SET(md_dev), un_dev, NULL, 0));
}


/*
 * FUNCTION:	sp_xmit_ok
 * INPUT:	dq	- daemon queue referencing failing ps structure
 * OUTPUT:	none.
 * RETURNS:	void.
 * PURPOSE:	send a message to the master node in a multi-owner diskset to
 *		update all attached nodes view of the soft-part to be MD_SP_OK.
 * CALLING CONTEXT:
 *	Blockable. No unit lock held.
 */
static void
sp_xmit_ok(daemon_queue_t *dq)
{
	md_spps_t	*ps = (md_spps_t *)dq;

	/* Send a MD_MN_MSG_SP_SETSTAT to the master */
	sp_send_stat_msg(ps->ps_un, MD_SP_OK);

	/*
	 * Successfully transmitted error state to all nodes, now release this
	 * parent structure.
	 */
	SPPS_FREE(sp_parent_cache, ps);
}

/*
 * FUNCTION:	sp_xmit_error
 * INPUT:	dq	- daemon queue referencing failing ps structure
 * OUTPUT:	none.
 * RETURNS:	void.
 * PURPOSE:	send a message to the master node in a multi-owner diskset to
 *		update all attached nodes view of the soft-part to be MD_SP_ERR.
 * CALLING CONTEXT:
 *	Blockable. No unit lock held.
 */
static void
sp_xmit_error(daemon_queue_t *dq)
{
	md_spps_t	*ps = (md_spps_t *)dq;

	/* Send a MD_MN_MSG_SP_SETSTAT to the master */
	sp_send_stat_msg(ps->ps_un, MD_SP_ERR);

	/*
	 * Successfully transmitted error state to all nodes, now release this
	 * parent structure.
	 */
	SPPS_FREE(sp_parent_cache, ps);
}
static void
sp_send_stat_ok(mp_unit_t *un)
{
	minor_t		mnum = MD_SID(un);
	md_spps_t	*ps;

	ps = kmem_cache_alloc(sp_parent_cache, MD_ALLOCFLAGS);
	sp_parent_init(ps);
	ps->ps_un = un;
	ps->ps_ui = MDI_UNIT(mnum);

	daemon_request(&md_sp_daemon, sp_xmit_ok, (daemon_queue_t *)ps,
	    REQ_OLD);
}

static void
sp_send_stat_err(mp_unit_t *un)
{
	minor_t		mnum = MD_SID(un);
	md_spps_t	*ps;

	ps = kmem_cache_alloc(sp_parent_cache, MD_ALLOCFLAGS);
	sp_parent_init(ps);
	ps->ps_un = un;
	ps->ps_ui = MDI_UNIT(mnum);

	daemon_request(&md_sp_daemon, sp_xmit_error, (daemon_queue_t *)ps,
	    REQ_OLD);
}


/*
 * FUNCTION:	sp_error()
 * INPUT:	ps	- parent save structure for error-ed I/O.
 * OUTPUT:	none.
 * RETURNS:	void.
 * PURPOSE:	report a driver error.
 * CALLING CONTEXT:
 *	Interrupt - non-blockable
 */
static void
sp_error(md_spps_t *ps)
{
	set_t		setno = MD_UN2SET(ps->ps_un);

	/*
	 * Drop the mutex associated with this request before (potentially)
	 * enqueuing the free onto a separate thread. We have to release the
	 * mutex before destroying the parent structure.
	 */
	if (!(ps->ps_flags & MD_SPPS_DONTFREE)) {
		if (MUTEX_HELD(&ps->ps_mx)) {
			mutex_exit(&ps->ps_mx);
		}
	} else {
		/*
		 * this should only ever happen if we are panicking,
		 * since DONTFREE is only set on the parent if panicstr
		 * is non-NULL.
		 */
		ASSERT(panicstr);
	}

	/*
	 * For a multi-owner set we need to send a message to the master so that
	 * all nodes get the errored status when we first encounter it. To avoid
	 * deadlocking when multiple soft-partitions encounter an error on one
	 * physical unit we drop the unit readerlock before enqueueing the
	 * request. That way we can service any messages that require a
	 * writerlock to be held. Additionally, to avoid deadlocking when at
	 * the bottom of a metadevice stack and a higher level mirror has
	 * multiple requests outstanding on this soft-part, we clone the ps
	 * that failed and pass the error back up the stack to release the
	 * reference that this i/o may have in the higher-level metadevice.
	 * The other nodes in the cluster just have to modify the soft-part
	 * status and we do not need to block the i/o completion for this.
	 */
	if (MD_MNSET_SETNO(setno)) {
		md_spps_t	*err_ps;
		err_ps = kmem_cache_alloc(sp_parent_cache, MD_ALLOCFLAGS);
		sp_parent_init(err_ps);

		err_ps->ps_un = ps->ps_un;
		err_ps->ps_ui = ps->ps_ui;

		md_unit_readerexit(ps->ps_ui);

		daemon_request(&md_sp_daemon, sp_xmit_error,
		    (daemon_queue_t *)err_ps, REQ_OLD);

		sp_finish_error(ps, 0);

		return;
	} else {
		ps->ps_un->un_status = MD_SP_ERR;
	}

	/* Flag the error */
	sp_finish_error(ps, 1);

}

/*
 * FUNCTION:	sp_mapbuf()
 * INPUT:	un	- unit structure for soft partition we are doing
 *			  I/O on.
 *		voff	- virtual offset in soft partition to map.
 *		bcount	- # of blocks in the I/O.
 * OUTPUT:	bp	- translated buffer to be passed down to next layer.
 * RETURNS:	1	- request must be fragmented, more work to do,
 *		0	- request satisified, no more work to do
 *		-1	- error
 * PURPOSE:	Map the the virtual offset in the soft partition (passed
 *		in via voff) to the "physical" offset on whatever the soft
 *		partition is built on top of.  We do this by doing a binary
 *		search of the extent array in the soft partition unit
 *		structure.  Once the current extent is found, we do the
 *		translation, determine if the I/O will cross extent
 *		boundaries (if so, we have to fragment the I/O), then
 *		fill in the buf structure to be passed down to the next layer.
 */
static int
sp_mapbuf(
	mp_unit_t	*un,
	sp_ext_offset_t	voff,
	sp_ext_length_t	bcount,
	buf_t		*bp
)
{
	int		lo, mid, hi, found, more;
	size_t		new_bcount;
	sp_ext_offset_t new_blkno;
	sp_ext_offset_t	new_offset;
	sp_ext_offset_t	ext_endblk;
	md_dev64_t	new_edev;
	extern unsigned	md_maxphys;

	found = 0;
	lo = 0;
	hi = un->un_numexts - 1;

	/*
	 * do a binary search to find the extent that contains the
	 * starting offset.  after this loop, mid contains the index
	 * of the correct extent.
	 */
	while (lo <= hi && !found) {
		mid = (lo + hi) / 2;
		/* is the starting offset contained within the mid-ext? */
		if (voff >= un->un_ext[mid].un_voff &&
		    voff < un->un_ext[mid].un_voff + un->un_ext[mid].un_len)
			found = 1;
		else if (voff < un->un_ext[mid].un_voff)
			hi = mid - 1;
		else /* voff > un->un_ext[mid].un_voff + un->un_ext[mid].len */
			lo = mid + 1;
	}

	if (!found) {
		cmn_err(CE_WARN, "sp_mapbuf: invalid offset %llu.\n", voff);
		return (-1);
	}

	/* translate to underlying physical offset/device */
	new_offset = voff - un->un_ext[mid].un_voff;
	new_blkno = un->un_ext[mid].un_poff + new_offset;
	new_edev = un->un_dev;

	/* determine if we need to break the I/O into fragments */
	ext_endblk = un->un_ext[mid].un_voff + un->un_ext[mid].un_len;
	if (voff + btodb(bcount) > ext_endblk) {
		new_bcount = dbtob(ext_endblk - voff);
		more = 1;
	} else {
		new_bcount = bcount;
		more = 0;
	}

	/* only break up the I/O if we're not built on another metadevice */
	if ((md_getmajor(new_edev) != md_major) && (new_bcount > md_maxphys)) {
		new_bcount = md_maxphys;
		more = 1;
	}
	if (bp != (buf_t *)NULL) {
		/* do bp updates */
		bp->b_bcount = new_bcount;
		bp->b_lblkno = new_blkno;
		bp->b_edev = md_dev64_to_dev(new_edev);
	}
	return (more);
}

/*
 * FUNCTION:	sp_validate()
 * INPUT:	un	- unit structure to be validated.
 * OUTPUT:	none.
 * RETURNS:	0	- soft partition ok.
 *		-1	- error.
 * PURPOSE:	called on open to sanity check the soft partition.  In
 *		order to open a soft partition:
 *		- it must have at least one extent
 *		- the extent info in core and on disk must match
 *		- it may not be in an intermediate state (which would
 *		  imply that a two-phase commit was interrupted)
 *
 *		If the extent checking fails (B_ERROR returned from the read
 *		strategy call) _and_ we're a multi-owner diskset, we send a
 *		message to the master so that all nodes inherit the same view
 *		of the soft partition.
 *		If we are checking a soft-part that is marked as in error, and
 *		we can actually read and validate the watermarks we send a
 *		message to clear the error to the master node.
 */
static int
sp_validate(mp_unit_t *un)
{
	uint_t		ext;
	struct buf	*buf;
	sp_ext_length_t	len;
	mp_watermark_t	*wm;
	set_t		setno;
	int		reset_error = 0;

	setno = MD_UN2SET(un);

	/* sanity check unit structure components ?? */
	if (un->un_status != MD_SP_OK) {
		if (un->un_status != MD_SP_ERR) {
			cmn_err(CE_WARN, "md: %s: open failed, soft partition "
			    "status is %u.",
			    md_shortname(MD_SID(un)),
			    un->un_status);
			return (-1);
		} else {
			cmn_err(CE_WARN, "md: %s: open of soft partition "
			    "in Errored state.",
			    md_shortname(MD_SID(un)));
			reset_error = 1;
		}
	}

	if (un->un_numexts == 0) {
		cmn_err(CE_WARN, "md: %s: open failed, soft partition does "
		    "not have any extents.", md_shortname(MD_SID(un)));
		return (-1);
	}

	len = 0LL;
	for (ext = 0; ext < un->un_numexts; ext++) {

		/* tally extent lengths to check total size */
		len += un->un_ext[ext].un_len;

		/* allocate buffer for watermark */
		buf = getrbuf(KM_SLEEP);

		/* read watermark */
		buf->b_flags = B_READ;
		buf->b_edev = md_dev64_to_dev(un->un_dev);
		buf->b_iodone = NULL;
		buf->b_proc = NULL;
		buf->b_bcount = sizeof (mp_watermark_t);
		buf->b_lblkno = un->un_ext[ext].un_poff - 1;
		buf->b_bufsize = sizeof (mp_watermark_t);
		buf->b_un.b_addr = kmem_alloc(sizeof (mp_watermark_t),
		    KM_SLEEP);

		/*
		 * make the call non-blocking so that it is not affected
		 * by a set take.
		 */
		md_call_strategy(buf, MD_STR_MAPPED|MD_NOBLOCK, NULL);
		(void) biowait(buf);

		if (buf->b_flags & B_ERROR) {
			cmn_err(CE_WARN, "md: %s: open failed, could not "
			    "read watermark at block %llu for extent %u, "
			    "error %d.", md_shortname(MD_SID(un)),
			    buf->b_lblkno, ext, buf->b_error);
			kmem_free(buf->b_un.b_addr, sizeof (mp_watermark_t));
			freerbuf(buf);

			/*
			 * If we're a multi-owner diskset we send a message
			 * indicating that this soft-part has an invalid
			 * extent to the master node. This ensures a consistent
			 * view of the soft-part across the cluster.
			 */
			if (MD_MNSET_SETNO(setno)) {
				sp_send_stat_err(un);
			}
			return (-1);
		}

		wm = (mp_watermark_t *)buf->b_un.b_addr;

		/* make sure the checksum is correct first */
		if (crcchk((uchar_t *)wm, (uint_t *)&wm->wm_checksum,
		    (uint_t)sizeof (mp_watermark_t), (uchar_t *)NULL)) {
			cmn_err(CE_WARN, "md: %s: open failed, watermark "
			    "at block %llu for extent %u does not have a "
			    "valid checksum 0x%08x.", md_shortname(MD_SID(un)),
			    buf->b_lblkno, ext, wm->wm_checksum);
			kmem_free(buf->b_un.b_addr, sizeof (mp_watermark_t));
			freerbuf(buf);
			return (-1);
		}

		if (wm->wm_magic != MD_SP_MAGIC) {
			cmn_err(CE_WARN, "md: %s: open failed, watermark "
			    "at block %llu for extent %u does not have a "
			    "valid watermark magic number, expected 0x%x, "
			    "found 0x%x.", md_shortname(MD_SID(un)),
			    buf->b_lblkno, ext, MD_SP_MAGIC, wm->wm_magic);
			kmem_free(buf->b_un.b_addr, sizeof (mp_watermark_t));
			freerbuf(buf);
			return (-1);
		}

		/* make sure sequence number matches the current extent */
		if (wm->wm_seq != ext) {
			cmn_err(CE_WARN, "md: %s: open failed, watermark "
			    "at block %llu for extent %u has invalid "
			    "sequence number %u.", md_shortname(MD_SID(un)),
			    buf->b_lblkno, ext, wm->wm_seq);
			kmem_free(buf->b_un.b_addr, sizeof (mp_watermark_t));
			freerbuf(buf);
			return (-1);
		}

		/* make sure watermark length matches unit structure */
		if (wm->wm_length != un->un_ext[ext].un_len) {
			cmn_err(CE_WARN, "md: %s: open failed, watermark "
			    "at block %llu for extent %u has inconsistent "
			    "length, expected %llu, found %llu.",
			    md_shortname(MD_SID(un)), buf->b_lblkno,
			    ext, un->un_ext[ext].un_len,
			    (u_longlong_t)wm->wm_length);
			kmem_free(buf->b_un.b_addr, sizeof (mp_watermark_t));
			freerbuf(buf);
			return (-1);
		}

		/*
		 * make sure the type is a valid soft partition and not
		 * a free extent or the end.
		 */
		if (wm->wm_type != EXTTYP_ALLOC) {
			cmn_err(CE_WARN, "md: %s: open failed, watermark "
			    "at block %llu for extent %u is not marked "
			    "as in-use, type = %u.", md_shortname(MD_SID(un)),
			    buf->b_lblkno, ext, wm->wm_type);
			kmem_free(buf->b_un.b_addr, sizeof (mp_watermark_t));
			freerbuf(buf);
			return (-1);
		}
		/* free up buffer */
		kmem_free(buf->b_un.b_addr, sizeof (mp_watermark_t));
		freerbuf(buf);
	}

	if (len != un->un_length) {
		cmn_err(CE_WARN, "md: %s: open failed, computed length "
		    "%llu != expected length %llu.", md_shortname(MD_SID(un)),
		    len, un->un_length);
		return (-1);
	}

	/*
	 * If we're a multi-owner set _and_ reset_error is set, we should clear
	 * the error condition on all nodes in the set. Use SP_SETSTAT2 with
	 * MD_SP_OK.
	 */
	if (MD_MNSET_SETNO(setno) && reset_error) {
		sp_send_stat_ok(un);
	}
	return (0);
}

/*
 * FUNCTION:	sp_done()
 * INPUT:	child_buf	- buffer attached to child save structure.
 *				  this is the buffer on which I/O has just
 *				  completed.
 * OUTPUT:	none.
 * RETURNS:	0	- success.
 *		1	- error.
 * PURPOSE:	called on I/O completion.
 */
static int
sp_done(struct buf *child_buf)
{
	struct buf	*parent_buf;
	mdi_unit_t	*ui;
	md_spps_t	*ps;
	md_spcs_t	*cs;

	/* find the child save structure to which this buffer belongs */
	cs = (md_spcs_t *)((caddr_t)child_buf -
	    (sizeof (md_spcs_t) - sizeof (buf_t)));
	/* now get the parent save structure */
	ps = cs->cs_ps;
	parent_buf = ps->ps_bp;

	mutex_enter(&ps->ps_mx);
	/* pass any errors back up to the parent */
	if (child_buf->b_flags & B_ERROR) {
		ps->ps_flags |= MD_SPPS_ERROR;
		parent_buf->b_error = child_buf->b_error;
	}
	/* mapout, if needed */
	if (child_buf->b_flags & B_REMAPPED)
		bp_mapout(child_buf);

	ps->ps_frags--;
	if (ps->ps_frags != 0) {
		/*
		 * if this parent has more children, we just free the
		 * child and return.
		 */
		kmem_cache_free(sp_child_cache, cs);
		mutex_exit(&ps->ps_mx);
		return (1);
	}
	/* there are no more children */
	kmem_cache_free(sp_child_cache, cs);
	if (ps->ps_flags & MD_SPPS_ERROR) {
		sp_error(ps);
		return (1);
	}
	ui = ps->ps_ui;
	if (!(ps->ps_flags & MD_SPPS_DONTFREE)) {
		mutex_exit(&ps->ps_mx);
	} else {
		/*
		 * this should only ever happen if we are panicking,
		 * since DONTFREE is only set on the parent if panicstr
		 * is non-NULL.
		 */
		ASSERT(panicstr);
	}
	SPPS_FREE(sp_parent_cache, ps);
	md_kstat_done(ui, parent_buf, 0);
	md_unit_readerexit(ui);
	md_biodone(parent_buf);
	return (0);
}

/*
 * FUNCTION:	md_sp_strategy()
 * INPUT:	parent_buf	- parent buffer
 *		flag		- flags
 *		private		- private data
 * OUTPUT:	none.
 * RETURNS:	void.
 * PURPOSE:	Soft partitioning I/O strategy.  Performs the main work
 *		needed to do I/O to a soft partition.  The basic
 *		algorithm is as follows:
 *			- Allocate a child save structure to keep track
 *			  of the I/O we are going to pass down.
 *			- Map the I/O to the correct extent in the soft
 *			  partition (see sp_mapbuf()).
 *			- bioclone() the buffer and pass it down the
 *			  stack using md_call_strategy.
 *			- If the I/O needs to split across extents,
 *			  repeat the above steps until all fragments
 *			  are finished.
 */
static void
md_sp_strategy(buf_t *parent_buf, int flag, void *private)
{
	md_spps_t	*ps;
	md_spcs_t	*cs;
	int		more;
	mp_unit_t	*un;
	mdi_unit_t	*ui;
	size_t		current_count;
	off_t		current_offset;
	sp_ext_offset_t	current_blkno;
	buf_t		*child_buf;
	set_t		setno = MD_MIN2SET(getminor(parent_buf->b_edev));
	int		strat_flag = flag;

	/*
	 * When doing IO to a multi owner meta device, check if set is halted.
	 * We do this check without the needed lock held, for performance
	 * reasons.
	 * If an IO just slips through while the set is locked via an
	 * MD_MN_SUSPEND_SET, we don't care about it.
	 * Only check for suspension if we are a top-level i/o request
	 * (MD_STR_NOTTOP is cleared in 'flag');
	 */
	if ((md_set[setno].s_status & (MD_SET_HALTED | MD_SET_MNSET)) ==
	    (MD_SET_HALTED | MD_SET_MNSET)) {
		if ((flag & MD_STR_NOTTOP) == 0) {
			mutex_enter(&md_mx);
			/* Here we loop until the set is no longer halted */
			while (md_set[setno].s_status & MD_SET_HALTED) {
				cv_wait(&md_cv, &md_mx);
			}
			mutex_exit(&md_mx);
		}
	}

	ui = MDI_UNIT(getminor(parent_buf->b_edev));

	md_kstat_waitq_enter(ui);

	un = (mp_unit_t *)md_unit_readerlock(ui);

	if ((flag & MD_NOBLOCK) == 0) {
		if (md_inc_iocount(setno) != 0) {
			parent_buf->b_flags |= B_ERROR;
			parent_buf->b_error = ENXIO;
			parent_buf->b_resid = parent_buf->b_bcount;
			md_kstat_waitq_exit(ui);
			md_unit_readerexit(ui);
			biodone(parent_buf);
			return;
		}
	} else {
		md_inc_iocount_noblock(setno);
	}

	if (!(flag & MD_STR_NOTTOP)) {
		if (md_checkbuf(ui, (md_unit_t *)un, parent_buf) != 0) {
			md_kstat_waitq_exit(ui);
			return;
		}
	}

	ps = kmem_cache_alloc(sp_parent_cache, MD_ALLOCFLAGS);
	sp_parent_init(ps);

	/*
	 * Save essential information from the original buffhdr
	 * in the parent.
	 */
	ps->ps_un = un;
	ps->ps_ui = ui;
	ps->ps_bp = parent_buf;
	ps->ps_addr = parent_buf->b_un.b_addr;

	current_count = parent_buf->b_bcount;
	current_blkno = (sp_ext_offset_t)parent_buf->b_blkno;
	current_offset  = 0;

	/*
	 * if we are at the top and we are panicking,
	 * we don't free in order to save state.
	 */
	if (!(flag & MD_STR_NOTTOP) && (panicstr != NULL))
		ps->ps_flags |= MD_SPPS_DONTFREE;

	md_kstat_waitq_to_runq(ui);

	ps->ps_frags++;

	/*
	 * Mark this i/o as MD_STR_ABR if we've had ABR enabled on this
	 * metadevice.
	 */
	if (ui->ui_tstate & MD_ABR_CAP)
		strat_flag |= MD_STR_ABR;

	/*
	 * this loop does the main work of an I/O.  we allocate a
	 * a child save for each buf, do the logical to physical
	 * mapping, decide if we need to frag the I/O, clone the
	 * new I/O to pass down the stack.  repeat until we've
	 * taken care of the entire buf that was passed to us.
	 */
	do {
		cs = kmem_cache_alloc(sp_child_cache, MD_ALLOCFLAGS);
		sp_child_init(cs);
		child_buf = &cs->cs_buf;
		cs->cs_ps = ps;

		more = sp_mapbuf(un, current_blkno, current_count, child_buf);
		if (more == -1) {
			parent_buf->b_flags |= B_ERROR;
			parent_buf->b_error = EIO;
			md_kstat_done(ui, parent_buf, 0);
			md_unit_readerexit(ui);
			md_biodone(parent_buf);
			kmem_cache_free(sp_parent_cache, ps);
			return;
		}

		child_buf = md_bioclone(parent_buf, current_offset,
		    child_buf->b_bcount, child_buf->b_edev,
		    child_buf->b_blkno, sp_done, child_buf,
		    KM_NOSLEEP);
		/* calculate new offset, counts, etc... */
		current_offset += child_buf->b_bcount;
		current_count -=  child_buf->b_bcount;
		current_blkno +=  (sp_ext_offset_t)(btodb(child_buf->b_bcount));

		if (more) {
			mutex_enter(&ps->ps_mx);
			ps->ps_frags++;
			mutex_exit(&ps->ps_mx);
		}

		md_call_strategy(child_buf, strat_flag, private);
	} while (more);

	if (!(flag & MD_STR_NOTTOP) && (panicstr != NULL)) {
		while (!(ps->ps_flags & MD_SPPS_DONE)) {
			md_daemon(1, &md_done_daemon);
		}
		kmem_cache_free(sp_parent_cache, ps);
	}
}

/*
 * FUNCTION:	sp_directed_read()
 * INPUT:	mnum	- minor number
 *		vdr	- vol_directed_rd_t from user
 *		mode	- access mode for copying data out.
 * OUTPUT:	none.
 * RETURNS:	0	- success
 *		Exxxxx	- failure error-code
 * PURPOSE:	Construct the necessary sub-device i/o requests to perform the
 *		directed read as requested by the user. This is essentially the
 *		same as md_sp_strategy() with the exception being that the
 *		underlying 'md_call_strategy' is replaced with an ioctl call.
 */
int
sp_directed_read(minor_t mnum, vol_directed_rd_t *vdr, int mode)
{
	md_spps_t	*ps;
	md_spcs_t	*cs;
	int		more;
	mp_unit_t	*un;
	mdi_unit_t	*ui;
	size_t		current_count;
	off_t		current_offset;
	sp_ext_offset_t	current_blkno;
	buf_t		*child_buf, *parent_buf;
	void		*kbuffer;
	vol_directed_rd_t	cvdr;
	caddr_t		userbuf;
	offset_t	useroff;
	int		ret = 0;

	ui = MDI_UNIT(mnum);

	md_kstat_waitq_enter(ui);

	bzero(&cvdr, sizeof (cvdr));

	un = (mp_unit_t *)md_unit_readerlock(ui);

	/*
	 * Construct a parent_buf header which reflects the user-supplied
	 * request.
	 */

	kbuffer = kmem_alloc(vdr->vdr_nbytes, KM_NOSLEEP);
	if (kbuffer == NULL) {
		vdr->vdr_flags |= DKV_DMR_ERROR;
		md_kstat_waitq_exit(ui);
		md_unit_readerexit(ui);
		return (ENOMEM);
	}

	parent_buf = getrbuf(KM_NOSLEEP);
	if (parent_buf == NULL) {
		vdr->vdr_flags |= DKV_DMR_ERROR;
		md_kstat_waitq_exit(ui);
		md_unit_readerexit(ui);
		kmem_free(kbuffer, vdr->vdr_nbytes);
		return (ENOMEM);
	}
	parent_buf->b_un.b_addr = kbuffer;
	parent_buf->b_flags = B_READ;
	parent_buf->b_bcount = vdr->vdr_nbytes;
	parent_buf->b_lblkno = lbtodb(vdr->vdr_offset);
	parent_buf->b_edev = un->un_dev;


	ps = kmem_cache_alloc(sp_parent_cache, MD_ALLOCFLAGS);
	sp_parent_init(ps);

	/*
	 * Save essential information from the original buffhdr
	 * in the parent.
	 */
	ps->ps_un = un;
	ps->ps_ui = ui;
	ps->ps_bp = parent_buf;
	ps->ps_addr = parent_buf->b_un.b_addr;

	current_count = parent_buf->b_bcount;
	current_blkno = (sp_ext_offset_t)parent_buf->b_lblkno;
	current_offset  = 0;

	md_kstat_waitq_to_runq(ui);

	ps->ps_frags++;
	vdr->vdr_bytesread = 0;

	/*
	 * this loop does the main work of an I/O.  we allocate a
	 * a child save for each buf, do the logical to physical
	 * mapping, decide if we need to frag the I/O, clone the
	 * new I/O to pass down the stack.  repeat until we've
	 * taken care of the entire buf that was passed to us.
	 */
	do {
		cs = kmem_cache_alloc(sp_child_cache, MD_ALLOCFLAGS);
		sp_child_init(cs);
		child_buf = &cs->cs_buf;
		cs->cs_ps = ps;

		more = sp_mapbuf(un, current_blkno, current_count, child_buf);
		if (more == -1) {
			ret = EIO;
			vdr->vdr_flags |= DKV_DMR_SHORT;
			kmem_cache_free(sp_child_cache, cs);
			goto err_out;
		}

		cvdr.vdr_flags = vdr->vdr_flags;
		cvdr.vdr_side = vdr->vdr_side;
		cvdr.vdr_nbytes = child_buf->b_bcount;
		cvdr.vdr_offset = ldbtob(child_buf->b_lblkno);
		/* Work out where we are in the allocated buffer */
		useroff = (offset_t)(uintptr_t)kbuffer;
		useroff = useroff + (offset_t)current_offset;
		cvdr.vdr_data = (void *)(uintptr_t)useroff;
		child_buf = md_bioclone(parent_buf, current_offset,
		    child_buf->b_bcount, child_buf->b_edev,
		    child_buf->b_blkno, NULL,
		    child_buf, KM_NOSLEEP);
		/* calculate new offset, counts, etc... */
		current_offset += child_buf->b_bcount;
		current_count -=  child_buf->b_bcount;
		current_blkno +=  (sp_ext_offset_t)(btodb(child_buf->b_bcount));

		if (more) {
			mutex_enter(&ps->ps_mx);
			ps->ps_frags++;
			mutex_exit(&ps->ps_mx);
		}

		ret = md_call_ioctl(child_buf->b_edev, DKIOCDMR, &cvdr,
		    (mode | FKIOCTL), NULL);

		/*
		 * Free the child structure as we've finished with it.
		 * Normally this would be done by sp_done() but we're just
		 * using md_bioclone() to segment the transfer and we never
		 * issue a strategy request so the iodone will not be called.
		 */
		kmem_cache_free(sp_child_cache, cs);
		if (ret == 0) {
			/* copyout the returned data to vdr_data + offset */
			userbuf = (caddr_t)kbuffer;
			userbuf += (caddr_t)(cvdr.vdr_data) - (caddr_t)kbuffer;
			if (ddi_copyout(userbuf, vdr->vdr_data,
			    cvdr.vdr_bytesread, mode)) {
				ret = EFAULT;
				goto err_out;
			}
			vdr->vdr_bytesread += cvdr.vdr_bytesread;
		} else {
			goto err_out;
		}
	} while (more);

	/*
	 * Update the user-supplied vol_directed_rd_t structure with the
	 * contents of the last issued child request.
	 */
	vdr->vdr_flags = cvdr.vdr_flags;
	vdr->vdr_side = cvdr.vdr_side;
	bcopy(cvdr.vdr_side_name, vdr->vdr_side_name, VOL_SIDENAME);

err_out:
	if (ret != 0) {
		vdr->vdr_flags |= DKV_DMR_ERROR;
	}
	if (vdr->vdr_bytesread != vdr->vdr_nbytes) {
		vdr->vdr_flags |= DKV_DMR_SHORT;
	}
	kmem_cache_free(sp_parent_cache, ps);
	kmem_free(kbuffer, vdr->vdr_nbytes);
	freerbuf(parent_buf);
	md_unit_readerexit(ui);
	return (ret);
}

/*
 * FUNCTION:	sp_snarf()
 * INPUT:	cmd	- snarf cmd.
 *		setno	- set number.
 * OUTPUT:	none.
 * RETURNS:	1	- soft partitions were snarfed.
 *		0	- no soft partitions were snarfed.
 * PURPOSE:	Snarf soft partition metadb records into their in-core
 *		structures.  This routine is called at "snarf time" when
 *		md loads and gets all metadevices records into memory.
 *		The basic algorithm is simply to walk the soft partition
 *		records in the metadb and call the soft partitioning
 *		build_incore routine to set up the in-core structures.
 */
static int
sp_snarf(md_snarfcmd_t cmd, set_t setno)
{
	mp_unit_t	*un;
	mddb_recid_t	recid;
	int		gotsomething;
	int		all_sp_gotten;
	mddb_type_t	rec_type;
	mddb_de_ic_t	*dep;
	mddb_rb32_t	*rbp;
	mp_unit_t	*big_un;
	mp_unit32_od_t	*small_un;
	size_t		newreqsize;


	if (cmd == MD_SNARF_CLEANUP)
		return (0);

	all_sp_gotten = 1;
	gotsomething = 0;

	/* get the record type */
	rec_type = (mddb_type_t)md_getshared_key(setno,
	    sp_md_ops.md_driver.md_drivername);
	recid = mddb_makerecid(setno, 0);

	/*
	 * walk soft partition records in the metadb and call
	 * sp_build_incore to build in-core structures.
	 */
	while ((recid = mddb_getnextrec(recid, rec_type, 0)) > 0) {
		/* if we've already gotten this record, go to the next one */
		if (mddb_getrecprivate(recid) & MD_PRV_GOTIT)
			continue;


		dep = mddb_getrecdep(recid);
		dep->de_flags = MDDB_F_SOFTPART;
		rbp = dep->de_rb;

		switch (rbp->rb_revision) {
		case MDDB_REV_RB:
		case MDDB_REV_RBFN:
			if ((rbp->rb_private & MD_PRV_CONVD) == 0) {
				/*
				 * This means, we have an old and small record.
				 * And this record hasn't already been converted
				 * :-o before we create an incore metadevice
				 * from this we have to convert it to a big
				 * record.
				 */
				small_un =
				    (mp_unit32_od_t *)mddb_getrecaddr(recid);
				newreqsize = sizeof (mp_unit_t) +
				    ((small_un->un_numexts - 1) *
				    sizeof (struct mp_ext));
				big_un = (mp_unit_t *)kmem_zalloc(newreqsize,
				    KM_SLEEP);
				softpart_convert((caddr_t)small_un,
				    (caddr_t)big_un, SMALL_2_BIG);
				kmem_free(small_un, dep->de_reqsize);
				dep->de_rb_userdata = big_un;
				dep->de_reqsize = newreqsize;
				rbp->rb_private |= MD_PRV_CONVD;
				un = big_un;
			} else {
				/* Record has already been converted */
				un = (mp_unit_t *)mddb_getrecaddr(recid);
			}
			un->c.un_revision &= ~MD_64BIT_META_DEV;
			break;
		case MDDB_REV_RB64:
		case MDDB_REV_RB64FN:
			/* Large device */
			un = (mp_unit_t *)mddb_getrecaddr(recid);
			un->c.un_revision |= MD_64BIT_META_DEV;
			un->c.un_flag |= MD_EFILABEL;
			break;
		}
		MDDB_NOTE_FN(rbp->rb_revision, un->c.un_revision);

		/*
		 * Create minor node for snarfed entry.
		 */
		(void) md_create_minor_node(MD_MIN2SET(MD_SID(un)), MD_SID(un));

		if (MD_UNIT(MD_SID(un)) != NULL) {
			/* unit is already in-core */
			mddb_setrecprivate(recid, MD_PRV_PENDDEL);
			continue;
		}
		all_sp_gotten = 0;
		if (sp_build_incore((void *)un, 1) == 0) {
			mddb_setrecprivate(recid, MD_PRV_GOTIT);
			md_create_unit_incore(MD_SID(un), &sp_md_ops, 0);
			gotsomething = 1;
		}
	}

	if (!all_sp_gotten)
		return (gotsomething);
	/* double-check records */
	recid = mddb_makerecid(setno, 0);
	while ((recid = mddb_getnextrec(recid, rec_type, 0)) > 0)
		if (!(mddb_getrecprivate(recid) & MD_PRV_GOTIT))
			mddb_setrecprivate(recid, MD_PRV_PENDDEL);

	return (0);
}

/*
 * FUNCTION:	sp_halt()
 * INPUT:	cmd	- halt cmd.
 *		setno	- set number.
 * RETURNS:	0	- success.
 *		1	- err.
 * PURPOSE:	Perform driver halt operations.  As with stripe, we
 *		support MD_HALT_CHECK and MD_HALT_DOIT.  The first
 *		does a check to see if halting can be done safely
 *		(no open soft partitions), the second cleans up and
 *		shuts down the driver.
 */
static int
sp_halt(md_haltcmd_t cmd, set_t setno)
{
	int		i;
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
			if (ui->ui_opsindex != sp_md_ops.md_selfindex)
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
		if (ui->ui_opsindex != sp_md_ops.md_selfindex)
			continue;
		reset_sp((mp_unit_t *)MD_UNIT(mnum), mnum, 0);
	}

	return (0);
}

/*
 * FUNCTION:	sp_open_dev()
 * INPUT:	un	- unit structure.
 *		oflags	- open flags.
 * OUTPUT:	none.
 * RETURNS:	0		- success.
 *		non-zero	- err.
 * PURPOSE:	open underlying device via md_layered_open.
 */
static int
sp_open_dev(mp_unit_t *un, int oflags)
{
	minor_t		mnum = MD_SID(un);
	int		err;
	md_dev64_t	tmpdev;
	set_t		setno = MD_MIN2SET(MD_SID(un));
	side_t		side = mddb_getsidenum(setno);

	tmpdev = un->un_dev;
	/*
	 * Do the open by device id if underlying is regular
	 */
	if ((md_getmajor(tmpdev) != md_major) &&
	    md_devid_found(setno, side, un->un_key) == 1) {
		tmpdev = md_resolve_bydevid(mnum, tmpdev, un->un_key);
	}
	err = md_layered_open(mnum, &tmpdev, oflags);
	un->un_dev = tmpdev;

	if (err)
		return (ENXIO);

	return (0);
}

/*
 * FUNCTION:	sp_open()
 * INPUT:	dev		- device to open.
 *		flag		- pass-through flag.
 *		otyp		- pass-through open type.
 *		cred_p		- credentials.
 *		md_oflags	- open flags.
 * OUTPUT:	none.
 * RETURNS:	0		- success.
 *		non-zero	- err.
 * PURPOSE:	open a soft partition.
 */
/* ARGSUSED */
static int
sp_open(
	dev_t		*dev,
	int		flag,
	int		otyp,
	cred_t		*cred_p,
	int		md_oflags
)
{
	minor_t		mnum = getminor(*dev);
	mdi_unit_t	*ui = MDI_UNIT(mnum);
	mp_unit_t	*un;
	int		err = 0;
	set_t		setno;

	/*
	 * When doing an open of a multi owner metadevice, check to see if this
	 * node is a starting node and if a reconfig cycle is underway.
	 * If so, the system isn't sufficiently set up enough to handle the
	 * open (which involves I/O during sp_validate), so fail with ENXIO.
	 */
	setno = MD_MIN2SET(mnum);
	if ((md_set[setno].s_status & (MD_SET_MNSET | MD_SET_MN_START_RC)) ==
	    (MD_SET_MNSET | MD_SET_MN_START_RC)) {
			return (ENXIO);
	}

	/* grab necessary locks */
	un = (mp_unit_t *)md_unit_openclose_enter(ui);
	setno = MD_UN2SET(un);

	/* open underlying device, if necessary */
	if (! md_unit_isopen(ui) || (md_oflags & MD_OFLG_PROBEDEV)) {
		if ((err = sp_open_dev(un, md_oflags)) != 0)
			goto out;

		if (MD_MNSET_SETNO(setno)) {
			/* For probe, don't incur the overhead of validate */
			if (!(md_oflags & MD_OFLG_PROBEDEV)) {
				/*
				 * Don't call sp_validate while
				 * unit_openclose lock is held.  So, actually
				 * open the device, drop openclose lock,
				 * call sp_validate, reacquire openclose lock,
				 * and close the device.  If sp_validate
				 * succeeds, then device will be re-opened.
				 */
				if ((err = md_unit_incopen(mnum, flag,
				    otyp)) != 0)
					goto out;

				mutex_enter(&ui->ui_mx);
				ui->ui_lock |= MD_UL_OPENINPROGRESS;
				mutex_exit(&ui->ui_mx);
				md_unit_openclose_exit(ui);
				if (otyp != OTYP_LYR)
					rw_exit(&md_unit_array_rw.lock);

				err = sp_validate(un);

				if (otyp != OTYP_LYR)
					rw_enter(&md_unit_array_rw.lock,
					    RW_READER);
				(void) md_unit_openclose_enter(ui);
				(void) md_unit_decopen(mnum, otyp);
				mutex_enter(&ui->ui_mx);
				ui->ui_lock &= ~MD_UL_OPENINPROGRESS;
				cv_broadcast(&ui->ui_cv);
				mutex_exit(&ui->ui_mx);
				/*
				 * Should be in the same state as before
				 * the sp_validate.
				 */
				if (err != 0) {
					/* close the device opened above */
					md_layered_close(un->un_dev, md_oflags);
					err = EIO;
					goto out;
				}
			}
			/*
			 * As we're a multi-owner metadevice we need to ensure
			 * that all nodes have the same idea of the status.
			 * sp_validate() will mark the device as errored (if
			 * it cannot read the watermark) or ok (if it was
			 * previously errored but the watermark is now valid).
			 * This code-path is only entered on the non-probe open
			 * so we will maintain the errored state during a probe
			 * call. This means the sys-admin must metarecover -m
			 * to reset the soft-partition error.
			 */
		} else {
			/* For probe, don't incur the overhead of validate */
			if (!(md_oflags & MD_OFLG_PROBEDEV) &&
			    (err = sp_validate(un)) != 0) {
				/* close the device opened above */
				md_layered_close(un->un_dev, md_oflags);
				err = EIO;
				goto out;
			} else {
				/*
				 * we succeeded in validating the on disk
				 * format versus the in core, so reset the
				 * status if it's in error
				 */
				if (un->un_status == MD_SP_ERR) {
					un->un_status = MD_SP_OK;
				}
			}
		}
	}

	/* count open */
	if ((err = md_unit_incopen(mnum, flag, otyp)) != 0)
		goto out;

out:
	md_unit_openclose_exit(ui);
	return (err);
}

/*
 * FUNCTION:	sp_close()
 * INPUT:	dev		- device to close.
 *		flag		- pass-through flag.
 *		otyp		- pass-through type.
 *		cred_p		- credentials.
 *		md_cflags	- close flags.
 * OUTPUT:	none.
 * RETURNS:	0		- success.
 *		non-zero	- err.
 * PURPOSE:	close a soft paritition.
 */
/* ARGSUSED */
static int
sp_close(
	dev_t		dev,
	int		flag,
	int		otyp,
	cred_t		*cred_p,
	int		md_cflags
)
{
	minor_t		mnum = getminor(dev);
	mdi_unit_t	*ui = MDI_UNIT(mnum);
	mp_unit_t	*un;
	int		err = 0;

	/* grab necessary locks */
	un = (mp_unit_t *)md_unit_openclose_enter(ui);

	/* count closed */
	if ((err = md_unit_decopen(mnum, otyp)) != 0)
		goto out;

	/* close devices, if necessary */
	if (! md_unit_isopen(ui) || (md_cflags & MD_OFLG_PROBEDEV)) {
		md_layered_close(un->un_dev, md_cflags);
	}

	/*
	 * If a MN set and transient capabilities (eg ABR/DMR) are set,
	 * clear these capabilities if this is the last close in
	 * the cluster
	 */
	if (MD_MNSET_SETNO(MD_UN2SET(un)) &&
	    (ui->ui_tstate & MD_ABR_CAP)) {
		md_unit_openclose_exit(ui);
		mdmn_clear_all_capabilities(mnum);
		return (0);
	}
	/* unlock, return success */
out:
	md_unit_openclose_exit(ui);
	return (err);
}


/* used in sp_dump routine */
static struct buf dumpbuf;

/*
 * FUNCTION:	sp_dump()
 * INPUT:	dev	- device to dump to.
 *		addr	- address to dump.
 *		blkno	- blkno on device.
 *		nblk	- number of blocks to dump.
 * OUTPUT:	none.
 * RETURNS:	result from bdev_dump.
 * PURPOSE:  This routine dumps memory to the disk.  It assumes that
 *           the memory has already been mapped into mainbus space.
 *           It is called at disk interrupt priority when the system
 *           is in trouble.
 *           NOTE: this function is defined using 32-bit arguments,
 *           but soft partitioning is internally 64-bit.  Arguments
 *           are casted where appropriate.
 */
static int
sp_dump(dev_t dev, caddr_t addr, daddr_t blkno, int nblk)
{
	mp_unit_t	*un;
	buf_t		*bp;
	sp_ext_length_t	nb;
	daddr_t		mapblk;
	int		result;
	int		more;
	int		saveresult = 0;

	/*
	 * Don't need to grab the unit lock.
	 * Cause nothing else is supposed to be happenning.
	 * Also dump is not supposed to sleep.
	 */
	un = (mp_unit_t *)MD_UNIT(getminor(dev));

	if ((diskaddr_t)blkno >= un->c.un_total_blocks)
		return (EINVAL);

	if (((diskaddr_t)blkno + nblk) > un->c.un_total_blocks)
		return (EINVAL);

	bp = &dumpbuf;
	nb = (sp_ext_length_t)dbtob(nblk);
	do {
		bzero((caddr_t)bp, sizeof (*bp));
		more = sp_mapbuf(un, (sp_ext_offset_t)blkno, nb, bp);
		nblk = (int)(btodb(bp->b_bcount));
		mapblk = bp->b_blkno;
		result = bdev_dump(bp->b_edev, addr, mapblk, nblk);
		if (result)
			saveresult = result;

		nb -= bp->b_bcount;
		addr += bp->b_bcount;
		blkno += nblk;
	} while (more);

	return (saveresult);
}

static int
sp_imp_set(
	set_t	setno
)
{
	mddb_recid_t	recid;
	int		gotsomething;
	mddb_type_t	rec_type;
	mddb_de_ic_t	*dep;
	mddb_rb32_t	*rbp;
	mp_unit_t	*un64;
	mp_unit32_od_t	*un32;
	md_dev64_t	self_devt;
	minor_t		*self_id;	/* minor needs to be updated */
	md_parent_t	*parent_id;	/* parent needs to be updated */
	mddb_recid_t	*record_id;	/* record id needs to be updated */

	gotsomething = 0;

	rec_type = (mddb_type_t)md_getshared_key(setno,
	    sp_md_ops.md_driver.md_drivername);
	recid = mddb_makerecid(setno, 0);

	while ((recid = mddb_getnextrec(recid, rec_type, 0)) > 0) {
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
			un32 = (mp_unit32_od_t *)mddb_getrecaddr(recid);
			self_id = &(un32->c.un_self_id);
			parent_id = &(un32->c.un_parent);
			record_id = &(un32->c.un_record_id);

			if (!md_update_minor(setno, mddb_getsidenum
			    (setno), un32->un_key))
				goto out;
			break;

		case MDDB_REV_RB64:
		case MDDB_REV_RB64FN:
			un64 = (mp_unit_t *)mddb_getrecaddr(recid);
			self_id = &(un64->c.un_self_id);
			parent_id = &(un64->c.un_parent);
			record_id = &(un64->c.un_record_id);

			if (!md_update_minor(setno, mddb_getsidenum
			    (setno), un64->un_key))
				goto out;
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
		 *
		 */
		mddb_setrecprivate(recid, MD_PRV_GOTIT);

		*self_id = MD_MKMIN(setno, MD_MIN2UNIT(*self_id));
		if (*parent_id != MD_NO_PARENT)
			*parent_id = MD_MKMIN(setno, MD_MIN2UNIT(*parent_id));
		*record_id = MAKERECID(setno, DBID(*record_id));

		gotsomething = 1;
	}

out:
	return (gotsomething);
}

static md_named_services_t sp_named_services[] = {
	{NULL,					0}
};

md_ops_t sp_md_ops = {
	sp_open,		/* open */
	sp_close,		/* close */
	md_sp_strategy,		/* strategy */
	NULL,			/* print */
	sp_dump,		/* dump */
	NULL,			/* read */
	NULL,			/* write */
	md_sp_ioctl,		/* ioctl, */
	sp_snarf,		/* snarf */
	sp_halt,		/* halt */
	NULL,			/* aread */
	NULL,			/* awrite */
	sp_imp_set,		/* import set */
	sp_named_services
};

static void
init_init()
{
	sp_parent_cache = kmem_cache_create("md_softpart_parent",
	    sizeof (md_spps_t), 0, sp_parent_constructor,
	    sp_parent_destructor, sp_run_queue, NULL, NULL, 0);
	sp_child_cache = kmem_cache_create("md_softpart_child",
	    sizeof (md_spcs_t) - sizeof (buf_t) + biosize(), 0,
	    sp_child_constructor, sp_child_destructor, sp_run_queue,
	    NULL, NULL, 0);
}

static void
fini_uninit()
{
	kmem_cache_destroy(sp_parent_cache);
	kmem_cache_destroy(sp_child_cache);
	sp_parent_cache = sp_child_cache = NULL;
}

/* define the module linkage */
MD_PLUGIN_MISC_MODULE("soft partition module", init_init(), fini_uninit())
