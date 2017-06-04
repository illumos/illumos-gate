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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/ksynch.h>
#include <sys/cmn_err.h>
#include <sys/kmem.h>
#include <sys/stat.h>
#include <sys/errno.h>

#include "../solaris/nsc_thread.h"
#ifdef DS_DDICT
#include "../contract.h"
#endif
#include <sys/nsctl/nsctl.h>

#include <sys/kmem.h>
#include <sys/ddi.h>

#include <sys/sdt.h>		/* dtrace is S10 or later */

#include "rdc_io.h"
#include "rdc_bitmap.h"
#include "rdc_diskq.h"
#include "rdc_clnt.h"

#include <sys/unistat/spcs_s.h>
#include <sys/unistat/spcs_s_k.h>
#include <sys/unistat/spcs_errors.h>

extern nsc_io_t *_rdc_io_hc;

int rdc_diskq_coalesce = 0;

int
_rdc_rsrv_diskq(rdc_group_t *group)
{
	int rc = 0;

	mutex_enter(&group->diskqmutex);
	if (group->diskqfd == NULL) {
		mutex_exit(&group->diskqmutex);
		return (EIO);
	} else if ((group->diskqrsrv == 0) &&
	    (rc = nsc_reserve(group->diskqfd, 0)) != 0) {
		cmn_err(CE_WARN,
		    "!rdc: nsc_reserve(%s) failed %d\n",
		    nsc_pathname(group->diskqfd), rc);
	} else {
		group->diskqrsrv++;
	}

	mutex_exit(&group->diskqmutex);
	return (rc);
}

void
_rdc_rlse_diskq(rdc_group_t *group)
{
	mutex_enter(&group->diskqmutex);
	if (group->diskqrsrv > 0 && --group->diskqrsrv == 0) {
		nsc_release(group->diskqfd);
	}
	mutex_exit(&group->diskqmutex);
}

void
rdc_wait_qbusy(disk_queue *q)
{
	ASSERT(MUTEX_HELD(QLOCK(q)));
	while (q->busycnt > 0)
		cv_wait(&q->busycv, QLOCK(q));
}

void
rdc_set_qbusy(disk_queue *q)
{
	ASSERT(MUTEX_HELD(QLOCK(q)));
	q->busycnt++;
}

void
rdc_clr_qbusy(disk_queue *q)
{
	ASSERT(MUTEX_HELD(QLOCK(q)));
	q->busycnt--;
	if (q->busycnt == 0)
		cv_broadcast(&q->busycv);
}

int
rdc_lookup_diskq(char *pathname)
{
	rdc_u_info_t *urdc;
#ifdef DEBUG
	rdc_k_info_t *krdc;
#endif
	int index;

	for (index = 0; index < rdc_max_sets; index++) {
		urdc = &rdc_u_info[index];
#ifdef DEBUG
		krdc = &rdc_k_info[index];
#endif
		ASSERT(krdc->index == index);
		ASSERT(urdc->index == index);
		if (!IS_ENABLED(urdc))
			continue;

		if (strncmp(pathname, urdc->disk_queue,
		    NSC_MAXPATH) == 0)
			return (index);
	}

	return (-1);
}

void
rdc_unintercept_diskq(rdc_group_t *grp)
{
	if (!RDC_IS_DISKQ(grp))
		return;
	if (grp->q_tok)
		(void) nsc_unregister_path(grp->q_tok, 0);
	grp->q_tok = NULL;
}

void
rdc_close_diskq(rdc_group_t *grp)
{

	if (grp == NULL) {
#ifdef DEBUG
		cmn_err(CE_WARN, "!rdc_close_diskq: NULL group!");
#endif
		return;
	}

	if (grp->diskqfd) {
		if (nsc_close(grp->diskqfd) != 0) {
#ifdef DEBUG
			cmn_err(CE_WARN, "!nsc_close on diskq failed");
#else
			;
			/*EMPTY*/
#endif
		}
		grp->diskqfd = 0;
		grp->diskqrsrv = 0;
	}
	bzero(&grp->diskq.disk_hdr, sizeof (diskq_header));
}

/*
 * nsc_open the diskq and attach
 * the nsc_fd to krdc->diskqfd
 */
int
rdc_open_diskq(rdc_k_info_t *krdc)
{
	rdc_u_info_t *urdc;
	rdc_group_t *grp;
	int sts;
	nsc_size_t size;
	char *diskqname;
	int mutexheld = 0;

	grp = krdc->group;
	urdc = &rdc_u_info[krdc->index];

	mutex_enter(&grp->diskqmutex);
	mutexheld++;
	if (&urdc->disk_queue[0] == '\0') {
		goto fail;
	}

	diskqname = &urdc->disk_queue[0];

	if (grp->diskqfd == NULL) {
		grp->diskqfd = nsc_open(diskqname,
		    NSC_RDCHR_ID|NSC_DEVICE|NSC_WRITE, 0, 0, 0);
		if (grp->diskqfd == NULL) {
			cmn_err(CE_WARN, "!rdc_open_diskq: Unable to open %s",
			    diskqname);
			goto fail;
		}
	}
	if (!grp->q_tok)
		grp->q_tok = nsc_register_path(urdc->disk_queue,
		    NSC_DEVICE | NSC_CACHE, _rdc_io_hc);

	grp->diskqrsrv = 0; /* init reserve count */

	mutex_exit(&grp->diskqmutex);
	mutexheld--;
	/* just test a reserve release */
	sts = _rdc_rsrv_diskq(grp);
	if (!RDC_SUCCESS(sts)) {
		cmn_err(CE_WARN, "!rdc_open_diskq: Reserve failed for %s",
		    diskqname);
		goto fail;
	}
	sts = nsc_partsize(grp->diskqfd, &size);
	_rdc_rlse_diskq(grp);

	if ((sts == 0) && (size < 1)) {
		rdc_unintercept_diskq(grp);
		rdc_close_diskq(grp);
		goto fail;
	}

	return (0);

fail:
	bzero(&urdc->disk_queue, NSC_MAXPATH);
	if (mutexheld)
		mutex_exit(&grp->diskqmutex);
	return (-1);

}

/*
 * rdc_count_vecs
 * simply vec++'s until sb_addr is null
 * returns number of vectors encountered
 */
int
rdc_count_vecs(nsc_vec_t *vec)
{
	nsc_vec_t	*vecp;
	int i = 0;
	vecp = vec;
	while (vecp->sv_addr) {
		vecp++;
		i++;
	}
	return (i+1);
}
/*
 * rdc_setid2idx
 * given setid, return index
 */
int
rdc_setid2idx(int setid)
{

	int index = 0;

	for (index = 0; index < rdc_max_sets; index++) {
		if (rdc_u_info[index].setid == setid)
			break;
	}
	if (index >= rdc_max_sets)
		index = -1;
	return (index);
}

/*
 * rdc_idx2setid
 * given an index, return its setid
 */
int
rdc_idx2setid(int index)
{
	return (rdc_u_info[index].setid);
}

/*
 * rdc_fill_ioheader
 * fill in all the stuff you want to save on disk
 * at the beginnig of each queued write
 */
void
rdc_fill_ioheader(rdc_aio_t *aio, io_hdr *hd, int qpos)
{
	ASSERT(MUTEX_HELD(&rdc_k_info[aio->index].group->diskq.disk_qlock));

	hd->dat.magic = RDC_IOHDR_MAGIC;
	hd->dat.type = RDC_QUEUEIO;
	hd->dat.pos = aio->pos;
	hd->dat.hpos = aio->pos;
	hd->dat.qpos = qpos;
	hd->dat.len = aio->len;
	hd->dat.flag = aio->flag;
	hd->dat.iostatus = aio->iostatus;
	hd->dat.setid = rdc_idx2setid(aio->index);
	hd->dat.time = nsc_time();
	if (!aio->handle)
		hd->dat.flag |= RDC_NULL_BUF; /* no real data to queue */
}

/*
 * rdc_dump_iohdrs
 * give back the iohdr list
 * and clear out q->lastio
 */
void
rdc_dump_iohdrs(disk_queue *q)
{
	io_hdr *p, *r;

	ASSERT(MUTEX_HELD(QLOCK(q)));

	p = q->iohdrs;
	while (p) {
		r = p->dat.next;
		kmem_free(p, sizeof (*p));
		q->hdrcnt--;
		p = r;
	}
	q->iohdrs = q->hdr_last = NULL;
	q->hdrcnt = 0;
	if (q->lastio->handle)
		(void) nsc_free_buf(q->lastio->handle);
	bzero(&(*q->lastio), sizeof (*q->lastio));
}

/*
 * rdc_fail_diskq
 * set flags, throw away q info
 * clean up what you can
 * wait for flusher threads to stop (taking into account this may be one)
 * takes group_lock, so conf, many, and bitmap may not be held
 */
void
rdc_fail_diskq(rdc_k_info_t *krdc, int wait, int flag)
{
	rdc_k_info_t *p;
	rdc_u_info_t *q = &rdc_u_info[krdc->index];
	rdc_group_t *group = krdc->group;
	disk_queue *dq = &krdc->group->diskq;

	if (IS_STATE(q, RDC_DISKQ_FAILED))
		return;

	if (!(flag & RDC_NOFAIL))
		cmn_err(CE_WARN, "!disk queue %s failure", q->disk_queue);

	if (flag & RDC_DOLOG) {
		rdc_group_enter(krdc);
		rdc_group_log(krdc, RDC_NOFLUSH | RDC_ALLREMOTE,
		    "disk queue failed");
		rdc_group_exit(krdc);
	}
	mutex_enter(QHEADLOCK(dq));
	mutex_enter(QLOCK(dq));
	/*
	 * quick stop of the flushers
	 * other cleanup is done on the un-failing of the diskq
	 */
	SET_QHEAD(dq, RDC_DISKQ_DATA_OFF);
	SET_QTAIL(dq, RDC_DISKQ_DATA_OFF);
	SET_QNXTIO(dq, RDC_DISKQ_DATA_OFF);
	SET_LASTQTAIL(dq, 0);

	rdc_dump_iohdrs(dq);

	mutex_exit(QLOCK(dq));
	mutex_exit(QHEADLOCK(dq));

	bzero(krdc->bitmap_ref, krdc->bitmap_size * BITS_IN_BYTE *
	    BMAP_REF_PREF_SIZE);

	if (flag & RDC_DOLOG) /* otherwise, we already have the conf lock */
		rdc_group_enter(krdc);

	else if (!(flag & RDC_GROUP_LOCKED))
		ASSERT(MUTEX_HELD(&rdc_conf_lock));

	if (!(flag & RDC_NOFAIL)) {
		rdc_set_flags(q, RDC_DISKQ_FAILED);
	}
	rdc_clr_flags(q, RDC_QUEUING);

	for (p = krdc->group_next; p != krdc; p = p->group_next) {
		q = &rdc_u_info[p->index];
		if (!IS_ENABLED(q))
			continue;
		if (!(flag & RDC_NOFAIL)) {
			rdc_set_flags(q, RDC_DISKQ_FAILED);
		}
		rdc_clr_flags(q, RDC_QUEUING);
		bzero(p->bitmap_ref, p->bitmap_size * BITS_IN_BYTE *
		    BMAP_REF_PREF_SIZE);
		/* RDC_QUEUING is cleared in group_log() */
	}

	if (flag & RDC_DOLOG)
		rdc_group_exit(krdc);

	/* can't wait for myself to go away, I'm a flusher */
	if (wait & RDC_WAIT)
		while (group->rdc_thrnum)
			delay(2);

}

/*
 * rdc_stamp_diskq
 * write out diskq header info
 * must have disk_qlock held
 * if rsrvd flag is 0, the nsc_reserve is done
 */
int
rdc_stamp_diskq(rdc_k_info_t *krdc, int rsrvd, int failflags)
{
	nsc_vec_t	vec[2];
	nsc_buf_t	*head = NULL;
	rdc_group_t	*grp;
	rdc_u_info_t	*urdc;
	disk_queue	*q;
	int		rc, flags;

	grp = krdc->group;
	q = &krdc->group->diskq;

	ASSERT(MUTEX_HELD(&q->disk_qlock));

	urdc = &rdc_u_info[krdc->index];

	if (!rsrvd && _rdc_rsrv_diskq(grp)) {
		cmn_err(CE_WARN, "!rdc_stamp_diskq: %s reserve failed",
		    urdc->disk_queue);
		mutex_exit(QLOCK(q));
		rdc_fail_diskq(krdc, RDC_NOWAIT, failflags);
		mutex_enter(QLOCK(q));
		return (-1);
	}
	flags = NSC_WRITE | NSC_NOCACHE | NSC_NODATA;
	rc = nsc_alloc_buf(grp->diskqfd, 0, 1, flags, &head);

	if (!RDC_SUCCESS(rc)) {
		cmn_err(CE_WARN, "!Alloc buf failed for disk queue %s",
		    &urdc->disk_queue[0]);
		mutex_exit(QLOCK(q));
		rdc_fail_diskq(krdc, RDC_NOWAIT, failflags);
		mutex_enter(QLOCK(q));
		return (-1);
	}
	vec[0].sv_len = FBA_SIZE(1);
	vec[0].sv_addr = (uchar_t *)&q->disk_hdr;
	vec[1].sv_len = 0;
	vec[1].sv_addr = NULL;

	head->sb_vec = &vec[0];

#ifdef DEBUG_DISKQ
	cmn_err(CE_NOTE, "!rdc_stamp_diskq: hdr: %p magic: %x state: "
	    "%x head: %d tail: %d size: %d nitems: %d blocks: %d",
	    q, QMAGIC(q), QSTATE(q), QHEAD(q),
	    QTAIL(q), QSIZE(q), QNITEMS(q), QBLOCKS(q));
#endif

	rc = nsc_write(head, 0, 1, 0);

	if (!RDC_SUCCESS(rc)) {
		if (!rsrvd)
			_rdc_rlse_diskq(grp);
		cmn_err(CE_CONT, "!disk queue %s failed rc %d",
		    &urdc->disk_queue[0], rc);
		mutex_exit(QLOCK(q));
		rdc_fail_diskq(krdc, RDC_NOWAIT, failflags);
		mutex_enter(QLOCK(q));
		return (-1);
	}

	(void) nsc_free_buf(head);
	if (!rsrvd)
		_rdc_rlse_diskq(grp);

	return (0);
}

/*
 * rdc_init_diskq_header
 * load initial values into the header
 */
void
rdc_init_diskq_header(rdc_group_t *grp, dqheader *header)
{
	int rc;
	int type = 0;
	disk_queue *q = &grp->diskq;

	ASSERT(MUTEX_HELD(QLOCK(q)));

	/* save q type if this is a failure */
	if (QSTATE(q) & RDC_QNOBLOCK)
		type = RDC_QNOBLOCK;
	bzero(header, sizeof (*header));
	header->h.magic = RDC_DISKQ_MAGIC;
	header->h.vers = RDC_DISKQ_VERS;
	header->h.state |= (RDC_SHUTDOWN_BAD|type); /* SHUTDOWN_OK on suspend */
	header->h.head_offset = RDC_DISKQ_DATA_OFF;
	header->h.tail_offset = RDC_DISKQ_DATA_OFF;
	header->h.nitems = 0;
	header->h.blocks = 0;
	header->h.qwrap = 0;
	SET_QNXTIO(q, QHEAD(q));
	SET_QCOALBOUNDS(q, RDC_DISKQ_DATA_OFF);

	/* do this last, as this might be a failure. get the kernel state ok */
	rc = _rdc_rsrv_diskq(grp);
	if (!RDC_SUCCESS(rc)) {
		cmn_err(CE_WARN, "!init_diskq_hdr: Reserve failed for queue");
		return;
	}
	(void) nsc_partsize(grp->diskqfd, &header->h.disk_size);
	_rdc_rlse_diskq(grp);

}

/*
 * rdc_unfail_diskq
 * the diskq failed for some reason, lets try and re-start it
 * the old stuff has already been thrown away
 * should just be called from rdc_sync
 */
void
rdc_unfail_diskq(rdc_k_info_t *krdc)
{
	rdc_k_info_t *p;
	rdc_u_info_t *q = &rdc_u_info[krdc->index];
	rdc_group_t *group = krdc->group;
	disk_queue *dq = &group->diskq;

	rdc_group_enter(krdc);
	rdc_clr_flags(q, RDC_ASYNC);
	/* someone else won the race... */
	if (!IS_STATE(q, RDC_DISKQ_FAILED)) {
		rdc_group_exit(krdc);
		return;
	}
	rdc_clr_flags(q, RDC_DISKQ_FAILED);
	for (p = krdc->group_next; p != krdc; p = p->group_next) {
		q = &rdc_u_info[p->index];
		if (!IS_ENABLED(q))
			continue;
		rdc_clr_flags(q, RDC_DISKQ_FAILED);
		rdc_clr_flags(q, RDC_ASYNC);
		if (IS_STATE(q, RDC_QUEUING))
			rdc_clr_flags(q, RDC_QUEUING);
	}
	rdc_group_exit(krdc);

	mutex_enter(QLOCK(dq));

	rdc_init_diskq_header(group, &group->diskq.disk_hdr);
	/* real i/o to the queue */
	/* clear RDC_AUXSYNCIP because we cannot halt a sync that's not here */
	krdc->aux_state &= ~RDC_AUXSYNCIP;
	if (rdc_stamp_diskq(krdc, 0, RDC_GROUP_LOCKED | RDC_DOLOG) < 0) {
		mutex_exit(QLOCK(dq));
		goto fail;
	}

	SET_QNXTIO(dq, QHEAD(dq));
	SET_QHDRCNT(dq, 0);
	SET_QSTATE(dq, RDC_SHUTDOWN_BAD); /* only suspend can write good */
	dq->iohdrs = NULL;
	dq->hdr_last = NULL;

	/* should be none, but.. */
	rdc_dump_iohdrs(dq);

	mutex_exit(QLOCK(dq));


fail:
	krdc->aux_state |= RDC_AUXSYNCIP;
	return;

}

int
rdc_read_diskq_header(rdc_k_info_t *krdc)
{
	int rc;
	diskq_header *header;
	rdc_u_info_t *urdc = &rdc_u_info[krdc->index];

	if (krdc->group->diskqfd == NULL) {
		char buf[NSC_MAXPATH];
		(void) snprintf(buf, NSC_MAXPATH, "%s:%s", urdc->secondary.intf,
		    &urdc->secondary.intf[0]);
		cmn_err(CE_WARN, "!Disk Queue Header read failed for %s",
		    &urdc->group_name[0] == '\0' ? buf:
		    &urdc->group_name[0]);
		return (-1);
	}

	header = &krdc->group->diskq.disk_hdr.h;
	if (_rdc_rsrv_diskq(krdc->group)) {
		return (-1);
	}

	rc = rdc_ns_io(krdc->group->diskqfd, NSC_RDBUF, 0,
	    (uchar_t *)header, sizeof (diskq_header));

	_rdc_rlse_diskq(krdc->group);

	if (!RDC_SUCCESS(rc)) {
		char buf[NSC_MAXPATH];
		(void) snprintf(buf, NSC_MAXPATH, "%s:%s", urdc->secondary.intf,
		    &urdc->secondary.file[0]);
		cmn_err(CE_WARN, "!Disk Queue Header read failed(%d) for %s",
		    rc, &urdc->group_name[0] == '\0' ? buf :
		    &urdc->group_name[0]);
		return (-1);
	}
	return (0);
}

/*
 * rdc_stop_diskq_flusher
 */
void
rdc_stop_diskq_flusher(rdc_k_info_t *krdc)
{
	disk_queue q, *qp;
	rdc_group_t *group;
#ifdef DEBUG
	cmn_err(CE_NOTE, "!stopping flusher threads");
#endif
	group = krdc->group;
	qp = &krdc->group->diskq;

	/* save the queue info */
	q = *qp;

	/* lie a little */
	SET_QTAIL(qp, RDC_DISKQ_DATA_OFF);
	SET_QHEAD(qp, RDC_DISKQ_DATA_OFF);
	SET_QSTATE(qp, RDC_QDISABLEPEND);
	SET_QSTATE(qp, RDC_STOPPINGFLUSH);

	/* drop locks to allow flushers to die */
	mutex_exit(QLOCK(qp));
	mutex_exit(QHEADLOCK(qp));
	rdc_group_exit(krdc);

	while (group->rdc_thrnum)
		delay(2);

	rdc_group_enter(krdc);
	mutex_enter(QHEADLOCK(qp));
	mutex_enter(QLOCK(qp));

	CLR_QSTATE(qp, RDC_STOPPINGFLUSH);
	*qp = q;
}

/*
 * rdc_enable_diskq
 * open the diskq
 * and stamp the header onto it.
 */
int
rdc_enable_diskq(rdc_k_info_t *krdc)
{
	rdc_group_t *group;
	disk_queue *q;

	group = krdc->group;
	q = &group->diskq;

	if (rdc_open_diskq(krdc) < 0)
		goto fail;

	mutex_enter(QLOCK(q));
	rdc_init_diskq_header(group, &group->diskq.disk_hdr);

	if (rdc_stamp_diskq(krdc, 0, RDC_NOLOG) < 0) {
		mutex_exit(QLOCK(q));
		goto fail;
	}

	SET_QNXTIO(q, QHEAD(q));

	mutex_exit(QLOCK(q));
	return (0);

fail:
	mutex_enter(&group->diskqmutex);
	rdc_close_diskq(group);
	mutex_exit(&group->diskqmutex);

	/* caller has to fail diskq after dropping conf & many locks */
	return (RDC_EQNOADD);
}

/*
 * rdc_resume_diskq
 * open the diskq and read the header
 */
int
rdc_resume_diskq(rdc_k_info_t *krdc)
{
	rdc_u_info_t *urdc;
	rdc_group_t *group;
	disk_queue *q;
	int rc = 0;

	urdc = &rdc_u_info[krdc->index];
	group = krdc->group;
	q = &group->diskq;

	if (rdc_open_diskq(krdc) < 0) {
		rc = RDC_EQNOADD;
		goto fail;
	}

	mutex_enter(QLOCK(q));

	rdc_init_diskq_header(group, &group->diskq.disk_hdr);

	if (rdc_read_diskq_header(krdc) < 0) {
		SET_QSTATE(q, RDC_QBADRESUME);
		rc = RDC_EQNOADD;
	}

	/* check diskq magic number */
	if (QMAGIC(q) != RDC_DISKQ_MAGIC) {
		cmn_err(CE_WARN, "!SNDR: unable to resume diskq %s,"
		    " incorrect magic number in header", urdc->disk_queue);
		rdc_init_diskq_header(group, &group->diskq.disk_hdr);
		SET_QSTATE(q, RDC_QBADRESUME);
		rc = RDC_EQNOADD;
	} else switch (QVERS(q)) {
		diskq_header1 h1;	/* version 1 header */
		diskq_header *hc;	/* current header */

#ifdef	NSC_MULTI_TERABYTE
		case RDC_DISKQ_VER_ORIG:
			/* version 1 diskq header, upgrade to 64bit version */
		h1 = *(diskq_header1 *)(&group->diskq.disk_hdr.h);
		hc = &group->diskq.disk_hdr.h;

		cmn_err(CE_WARN, "!SNDR: old version header for diskq %s,"
		    " upgrading to current version", urdc->disk_queue);
		hc->vers = RDC_DISKQ_VERS;
		hc->state = h1.state;
		hc->head_offset = h1.head_offset;
		hc->tail_offset = h1.tail_offset;
		hc->disk_size = h1.disk_size;
		hc->nitems = h1.nitems;
		hc->blocks = h1.blocks;
		hc->qwrap = h1.qwrap;
		hc->auxqwrap = h1.auxqwrap;
		hc->seq_last = h1.seq_last;
		hc->ack_last = h1.ack_last;

		if (hc->nitems > 0) {
			cmn_err(CE_WARN, "!SNDR: unable to resume diskq %s,"
			    " old version Q contains data", urdc->disk_queue);
			rdc_init_diskq_header(group, &group->diskq.disk_hdr);
			SET_QSTATE(q, RDC_QBADRESUME);
			rc = RDC_EQNOADD;
		}
		break;
#else
		case RDC_DISKQ_VER_64BIT:
			cmn_err(CE_WARN, "!SNDR: unable to resume diskq %s,"
			    " diskq header newer than current version",
			    urdc->disk_queue);
			rdc_init_diskq_header(group, &group->diskq.disk_hdr);
			SET_QSTATE(q, RDC_QBADRESUME);
			rc = RDC_EQNOADD;
		break;
#endif
		case RDC_DISKQ_VERS:
			/* okay, current version diskq */
		break;
		default:
			cmn_err(CE_WARN, "!SNDR: unable to resume diskq %s,"
			    " unknown diskq header version", urdc->disk_queue);
			rdc_init_diskq_header(group, &group->diskq.disk_hdr);
			SET_QSTATE(q, RDC_QBADRESUME);
			rc = RDC_EQNOADD;
		break;
	}
	if (IS_QSTATE(q, RDC_SHUTDOWN_BAD)) {
		cmn_err(CE_WARN, "!SNDR: unable to resume diskq %s,"
		    " unsafe shutdown", urdc->disk_queue);
		rdc_init_diskq_header(group, &group->diskq.disk_hdr);
		SET_QSTATE(q, RDC_QBADRESUME);
		rc = RDC_EQNOADD;
	}

	CLR_QSTATE(q, RDC_SHUTDOWN_OK);
	SET_QSTATE(q, RDC_SHUTDOWN_BAD);

	/* bad, until proven not bad */
	if (rdc_stamp_diskq(krdc, 0, RDC_NOLOG) < 0) {
		rdc_fail_diskq(krdc, RDC_NOWAIT, RDC_NOLOG);
		rc = RDC_EQNOADD;
	}

	SET_QNXTIO(q, QHEAD(q));
	group->diskq.nitems_hwm = QNITEMS(q);
	group->diskq.blocks_hwm = QBLOCKS(q);

	mutex_exit(QLOCK(q));

#ifdef DEBUG
	cmn_err(CE_NOTE, "!rdc_resume_diskq: resuming diskq %s \n",
	    urdc->disk_queue);
	cmn_err(CE_NOTE, "!qinfo: " QDISPLAY(q));
#endif
	if (rc == 0)
		return (0);

fail:

	/* caller has to set the diskq failed after dropping it's locks */
	return (rc);

}

int
rdc_suspend_diskq(rdc_k_info_t *krdc)
{
	int rc;
	rdc_u_info_t *urdc = &rdc_u_info[krdc->index];
	disk_queue *q;

	q = &krdc->group->diskq;

	/* grab both diskq locks as we are going to kill the flusher */
	mutex_enter(QHEADLOCK(q));
	mutex_enter(QLOCK(q));

	if ((krdc->group->rdc_thrnum) && (!IS_QSTATE(q, RDC_STOPPINGFLUSH))) {
		SET_QSTATE(q, RDC_STOPPINGFLUSH);
		rdc_stop_diskq_flusher(krdc);
		CLR_QSTATE(q, RDC_STOPPINGFLUSH);
	}

	krdc->group->diskq.disk_hdr.h.state &= ~RDC_SHUTDOWN_BAD;
	krdc->group->diskq.disk_hdr.h.state |= RDC_SHUTDOWN_OK;
	krdc->group->diskq.disk_hdr.h.state &= ~RDC_QBADRESUME;

	/* let's make sure that the flusher has stopped.. */
	if (krdc->group->rdc_thrnum) {
		mutex_exit(QLOCK(q));
		mutex_exit(QHEADLOCK(q));
		rdc_group_exit(krdc);

		while (krdc->group->rdc_thrnum)
			delay(5);

		rdc_group_enter(krdc);
		mutex_enter(QLOCK(q));
		mutex_enter(QHEADLOCK(q));
	}
	/* write refcount to the bitmap */
	if ((rc = rdc_write_refcount(krdc)) < 0) {
		rdc_group_exit(krdc);
		goto fail;
	}

	if (!QEMPTY(q)) {
		rdc_set_flags(urdc, RDC_QUEUING);
	} else {
		rdc_clr_flags(urdc, RDC_QUEUING);
	}

	/* fill in diskq header info */
	krdc->group->diskq.disk_hdr.h.state &= ~RDC_QDISABLEPEND;

#ifdef DEBUG
	cmn_err(CE_NOTE, "!suspending disk queue\n" QDISPLAY(q));
#endif

	/* to avoid a possible deadlock, release in order, and reacquire */
	mutex_exit(QLOCK(q));
	mutex_exit(QHEADLOCK(q));

	if (krdc->group->count > 1) {
		rdc_group_exit(krdc);
		goto fail; /* just stamp on the last suspend */
	}
	rdc_group_exit(krdc); /* in case this stamp fails */
	mutex_enter(QLOCK(q));

	rc = rdc_stamp_diskq(krdc, 0, RDC_NOLOG);

	mutex_exit(QLOCK(q));

fail:
	rdc_group_enter(krdc);

	/* diskq already failed if stamp failed */

	return (rc);
}

/*
 * copy orig aio to copy, including the nsc_buf_t
 */
int
rdc_dup_aio(rdc_aio_t *orig, rdc_aio_t *copy)
{
	int rc;
	bcopy(orig, copy, sizeof (*orig));
	copy->handle = NULL;

	if (orig->handle == NULL) /* no buf to alloc/copy */
		return (0);

	rc = nsc_alloc_abuf(orig->pos, orig->len, 0, &copy->handle);
	if (!RDC_SUCCESS(rc)) {
#ifdef DEBUG
		cmn_err(CE_WARN, "!rdc_dup_aio: alloc_buf failed (%d)", rc);
#endif
		return (rc);
	}
	rc = nsc_copy(orig->handle, copy->handle, orig->pos,
	    orig->pos, orig->len);
	if (!RDC_SUCCESS(rc)) {
		(void) nsc_free_buf(copy->handle);
#ifdef DEBUG
		cmn_err(CE_WARN, "!rdc_dup_aio: copy buf failed (%d)", rc);
#endif
		return (rc);
	}
	return (0);
}

/*
 * rdc_qfill_shldwakeup()
 * 0 if the memory queue has filled, and the low water
 * mark has not been reached. 0 if diskq is empty.
 * 1 if less than low water mark
 * net_queue mutex is already held
 */
int
rdc_qfill_shldwakeup(rdc_k_info_t *krdc)
{
	rdc_group_t *group = krdc->group;
	rdc_u_info_t *urdc = &rdc_u_info[krdc->index];
	net_queue *nq = &group->ra_queue;
	disk_queue *dq = &group->diskq;

	ASSERT(MUTEX_HELD(&nq->net_qlock));

	if (!RDC_IS_DISKQ(krdc->group))
		return (0);

	if (nq->qfill_sleeping != RDC_QFILL_ASLEEP)
		return (0);

	if (nq->qfflags & RDC_QFILLSTOP)
		return (1);

	if (nq->qfflags & RDC_QFILLSLEEP)
		return (0);

	if (IS_STATE(urdc, RDC_LOGGING) || IS_STATE(urdc, RDC_SYNCING))
		return (0);

	mutex_enter(QLOCK(dq));
	if ((QNXTIO(dq) == QTAIL(dq)) && !IS_QSTATE(dq, RDC_QFULL)) {
		mutex_exit(QLOCK(dq));
		return (0);
	}
	mutex_exit(QLOCK(dq));

	if (nq->qfill_sleeping == RDC_QFILL_ASLEEP) {
		if (nq->hwmhit) {
			if (nq->blocks <= RDC_LOW_QBLOCKS) {
				nq->hwmhit = 0;
			} else {
				return (0);
			}
		}
#ifdef DEBUG_DISKQ_NOISY
		cmn_err(CE_NOTE, "!Waking up diskq->memq flusher, flags 0x%x"
		    " idx: %d", rdc_get_vflags(urdc), urdc->index);
#endif
		return (1);
	}
	return (0);

}

/*
 * rdc_diskq_enqueue
 * enqueue one i/o to the diskq
 * after appending some metadata to the front
 */
int
rdc_diskq_enqueue(rdc_k_info_t *krdc, rdc_aio_t *aio)
{
	nsc_vec_t	*vec = NULL;
	nsc_buf_t	*bp = NULL;
	nsc_buf_t	*qbuf = NULL;
	io_hdr		*iohdr = NULL;
	disk_queue	*q;
	rdc_group_t	*group;
	int		numvecs;
	int		i, j, rc = 0;
	int		retries = 0;
	rdc_u_info_t	*urdc;
	nsc_size_t	iofbas; /* len of io + io header len */
	int		qtail;
	int		delay_time = 2;
	int 		print_msg = 1;

#ifdef DEBUG_WRITER_UBERNOISE
	int		qhead;
#endif
	urdc = &rdc_u_info[krdc->index];
	group = krdc->group;
	q = &group->diskq;

	mutex_enter(QLOCK(q));

	/*
	 * there is a thread that is blocking because the queue is full,
	 * don't try to set up this write until all is clear
	 * check before and after for logging or failed queue just
	 * in case a thread was in flight while the queue was full,
	 * and in the proccess of failing
	 */
	while (IS_QSTATE(q, RDC_QFULL)) {
		if (IS_STATE(urdc, RDC_DISKQ_FAILED) ||
		    (IS_STATE(urdc, RDC_LOGGING) &&
		    !IS_STATE(urdc, RDC_QUEUING))) {
			mutex_exit(QLOCK(q));
			if (aio->handle)
				(void) nsc_free_buf(aio->handle);
			return (-1);
		}
		cv_wait(&q->qfullcv, QLOCK(q));

		if (IS_STATE(urdc, RDC_DISKQ_FAILED) ||
		    (IS_STATE(urdc, RDC_LOGGING) &&
		    !IS_STATE(urdc, RDC_QUEUING))) {
			mutex_exit(QLOCK(q));
			if (aio->handle)
				(void) nsc_free_buf(aio->handle);
			return (-1);
		}

	}

	SET_QSTATE(q, QTAILBUSY);

	if (aio->handle == NULL) {
		/* we're only going to write the header to the queue */
		numvecs = 2; /* kmem_alloc io header + null terminate */
		iofbas = FBA_LEN(sizeof (io_hdr));

	} else {
		/* find out how many vecs */
		numvecs = rdc_count_vecs(aio->handle->sb_vec) + 1;
		iofbas = aio->len + FBA_LEN(sizeof (io_hdr));
	}

	/*
	 * this, in conjunction with QTAILBUSY, will prevent
	 * premature dequeuing
	 */

	SET_LASTQTAIL(q, QTAIL(q));

	iohdr = (io_hdr *) kmem_zalloc(sizeof (io_hdr), KM_NOSLEEP);
	vec = (nsc_vec_t *) kmem_zalloc(sizeof (nsc_vec_t) * numvecs,
	    KM_NOSLEEP);

	if (!vec || !iohdr) {
		if (!vec) {
			cmn_err(CE_WARN, "!vec kmem alloc failed");
		} else {
			cmn_err(CE_WARN, "!iohdr kmem alloc failed");
		}
		if (vec)
			kmem_free(vec, sizeof (*vec));
		if (iohdr)
			kmem_free(iohdr, sizeof (*iohdr));
		CLR_QSTATE(q, QTAILBUSY);
		SET_LASTQTAIL(q, 0);
		mutex_exit(QLOCK(q));
		if (aio->handle)
			(void) nsc_free_buf(aio->handle);
		return (ENOMEM);
	}

	vec[numvecs - 1].sv_len = 0;
	vec[numvecs - 1].sv_addr = 0;

	/* now add the write itself */
	bp = aio->handle;

	for (i = 1, j = 0; bp && bp->sb_vec[j].sv_addr &&
	    i < numvecs; i++, j++) {
		vec[i].sv_len = bp->sb_vec[j].sv_len;
		vec[i].sv_addr = bp->sb_vec[j].sv_addr;
	}

retry:

	/* check for queue wrap, then check for overflow */
	if (IS_STATE(urdc, RDC_DISKQ_FAILED) ||
	    (IS_STATE(urdc, RDC_LOGGING) && !IS_STATE(urdc, RDC_QUEUING))) {
		kmem_free(iohdr, sizeof (*iohdr));
		kmem_free(vec, sizeof (*vec) * numvecs);
		CLR_QSTATE(q, QTAILBUSY);
		SET_LASTQTAIL(q, 0);
		if (IS_QSTATE(q, RDC_QFULL)) { /* wakeup blocked threads */
			CLR_QSTATE(q, RDC_QFULL);
			cv_broadcast(&q->qfullcv);
		}
		mutex_exit(QLOCK(q));
		if (aio->handle)
			(void) nsc_free_buf(aio->handle);

		return (-1);
	}

	if (QTAILSHLDWRAP(q, iofbas)) {
		/*
		 * just go back to the beginning of the disk
		 * it's not worth the trouble breaking up the write
		 */
#ifdef DEBUG_DISKQWRAP
		cmn_err(CE_NOTE, "!wrapping Q tail: " QDISPLAY(q));
#endif
		/*LINTED*/
		WRAPQTAIL(q);
	}

	/*
	 * prepend the write's metadata
	 */
	rdc_fill_ioheader(aio, iohdr, QTAIL(q));

	vec[0].sv_len = FBA_SIZE(1);
	vec[0].sv_addr = (uchar_t *)iohdr;

	/* check for tail < head */

	if (!(FITSONQ(q, iofbas))) {
		/*
		 * don't allow any more writes to start
		 */
		SET_QSTATE(q, RDC_QFULL);
		mutex_exit(QLOCK(q));

		if ((!group->rdc_writer) && !IS_STATE(urdc, RDC_LOGGING))
			(void) rdc_writer(krdc->index);

		delay(delay_time);
		q->throttle_delay += delay_time;
		retries++;
		delay_time *= 2; /* fairly aggressive */
		if ((retries >= 8) || (delay_time >= 256)) {
			delay_time = 2;
			if (print_msg) {
				cmn_err(CE_WARN, "!enqueue: disk queue %s full",
				    &urdc->disk_queue[0]);
				print_msg = 0;
#ifdef DEBUG
				cmn_err(CE_WARN, "!qinfo: " QDISPLAY(q));
#else
				cmn_err(CE_CONT, "!qinfo: " QDISPLAYND(q));
#endif
			}
			/*
			 * if this is a no-block queue, or this is a blocking
			 * queue that is not flushing. reset and log
			 */
			if ((QSTATE(q) & RDC_QNOBLOCK) ||
			    (IS_STATE(urdc, RDC_QUEUING))) {

				if (IS_STATE(urdc, RDC_QUEUING)) {
		cmn_err(CE_WARN, "!SNDR: disk queue %s full and not flushing. "
		    "giving up", &urdc->disk_queue[0]);
		cmn_err(CE_WARN, "!SNDR: %s:%s entering logging mode",
		    urdc->secondary.intf, urdc->secondary.file);
				}

				rdc_fail_diskq(krdc, RDC_WAIT,
				    RDC_DOLOG | RDC_NOFAIL);
				kmem_free(iohdr, sizeof (*iohdr));
				kmem_free(vec, sizeof (*vec) * numvecs);
				mutex_enter(QLOCK(q));
				CLR_QSTATE(q, QTAILBUSY | RDC_QFULL);
				cv_broadcast(&q->qfullcv);
				mutex_exit(QLOCK(q));
				SET_LASTQTAIL(q, 0);
				if (aio->handle)
					(void) nsc_free_buf(aio->handle);
				return (ENOMEM);
			}
		}

		mutex_enter(QLOCK(q));
		goto retry;

	}

	qtail = QTAIL(q);
#ifdef DEBUG_WRITER_UBERNOISE
	qhead = QHEAD(q);
#endif

	/* update tail pointer, nitems on queue and blocks on queue */
	INC_QTAIL(q, iofbas); /* increment tail over i/o size + ioheader size */
	INC_QNITEMS(q, 1);
	/* increment counter for i/o blocks only */
	INC_QBLOCKS(q, (iofbas - FBA_LEN(sizeof (io_hdr))));

	if (QNITEMS(q) > q->nitems_hwm)
		q->nitems_hwm = QNITEMS(q);
	if (QBLOCKS(q) > q->blocks_hwm)
		q->blocks_hwm = QBLOCKS(q);

	if (IS_QSTATE(q, RDC_QFULL)) {
		CLR_QSTATE(q, RDC_QFULL);
		cv_broadcast(&q->qfullcv);
	}

	mutex_exit(QLOCK(q));

	/*
	 * if (krdc->io_kstats) {
	 *	mutex_enter(krdc->io_kstats->ks_lock);
	 *	kstat_waitq_enter(KSTAT_IO_PTR(krdc->io_kstats));
	 *	mutex_exit(krdc->io_kstats->ks_lock);
	 * }
	 */

	DTRACE_PROBE(rdc_diskq_rsrv);

	if (_rdc_rsrv_diskq(group)) {
		cmn_err(CE_WARN, "!rdc_enqueue: %s reserve failed",
		    &urdc->disk_queue[0]);
		rdc_fail_diskq(krdc, RDC_WAIT, RDC_DOLOG);
		kmem_free(iohdr, sizeof (*iohdr));
		kmem_free(vec, sizeof (*vec) * numvecs);
		mutex_enter(QLOCK(q));
		CLR_QSTATE(q, QTAILBUSY);
		SET_LASTQTAIL(q, 0);
		mutex_exit(QLOCK(q));
		if (aio->handle)
			(void) nsc_free_buf(aio->handle);
		return (-1);
	}

/* XXX for now do this, but later pre-alloc handle in enable/resume */

	DTRACE_PROBE(rdc_diskq_alloc_start);
	rc = nsc_alloc_buf(group->diskqfd, qtail, iofbas,
	    NSC_NOCACHE | NSC_WRITE | NSC_NODATA, &qbuf);

	DTRACE_PROBE(rdc_diskq_alloc_end);

	if (!RDC_SUCCESS(rc)) {
		cmn_err(CE_WARN, "!disk queue %s alloc failed(%d) %" NSC_SZFMT,
		    &urdc->disk_queue[0], rc, iofbas);
		rdc_fail_diskq(krdc, RDC_WAIT, RDC_DOLOG);
		rc = ENOMEM;
		goto fail;
	}
	/* move vec and write to queue */
	qbuf->sb_vec = &vec[0];

#ifdef DEBUG_WRITER_UBERNOISE

	cmn_err(CE_NOTE, "!about to write to queue, qbuf: %p, qhead: %d, "
	    "qtail: %d, len: %d contents: %c%c%c%c%c",
	    (void *) qbuf, qhead, qtail, iofbas,
	    qbuf->sb_vec[1].sv_addr[0],
	    qbuf->sb_vec[1].sv_addr[1],
	    qbuf->sb_vec[1].sv_addr[2],
	    qbuf->sb_vec[1].sv_addr[3],
	    qbuf->sb_vec[1].sv_addr[4]);
	cmn_err(CE_CONT, "!qinfo: " QDISPLAYND(q));

#endif

	DTRACE_PROBE2(rdc_diskq_nswrite_start, int, qtail, nsc_size_t, iofbas);
	rc = nsc_write(qbuf, qtail, iofbas, 0);
	DTRACE_PROBE2(rdc_diskq_nswrite_end, int, qtail, nsc_size_t, iofbas);

	if (!RDC_SUCCESS(rc)) {
		cmn_err(CE_WARN, "!disk queue %s write failed %d",
		    &urdc->disk_queue[0], rc);
		rdc_fail_diskq(krdc, RDC_WAIT, RDC_DOLOG);
		goto fail;

	}

	mutex_enter(QLOCK(q));

	SET_LASTQTAIL(q, 0);
	CLR_QSTATE(q, QTAILBUSY);

	mutex_exit(QLOCK(q));

fail:

	/*
	 * return what should be returned
	 * the aio is returned in _rdc_write after status is gathered.
	 */

	if (qbuf)
		qbuf->sb_vec = 0;
	(void) nsc_free_buf(qbuf);

	if (aio->handle)
		(void) nsc_free_buf(aio->handle);

	_rdc_rlse_diskq(group);
	DTRACE_PROBE(rdc_diskq_rlse);

	/* free the iohdr and the vecs */

	if (iohdr)
		kmem_free(iohdr, sizeof (*iohdr));
	if (vec)
		kmem_free(vec, sizeof (*vec) * numvecs);

	/* if no flusher running, start one */
	if ((!krdc->group->rdc_writer) && !IS_STATE(urdc, RDC_LOGGING))
		(void) rdc_writer(krdc->index);

	return (rc);
}

/*
 * place this on the pending list of io_hdr's out for flushing
 */
void
rdc_add_iohdr(io_hdr *header, rdc_group_t *group)
{
	disk_queue *q = NULL;
#ifdef DEBUG
	io_hdr *p;
#endif

	q = &group->diskq;

	/* paranoia */
	header->dat.next = NULL;

	mutex_enter(QLOCK(q));
#ifdef DEBUG /* AAAH! double flush!? */
	p = q->iohdrs;
	while (p) {
		if (p->dat.qpos == header->dat.qpos) {
			cmn_err(CE_WARN, "!ADDING DUPLICATE HEADER %" NSC_SZFMT,
			    p->dat.qpos);
			kmem_free(header, sizeof (*header));
			mutex_exit(QLOCK(q));
			return;
		}
		p = p->dat.next;
	}
#endif
	if (q->iohdrs == NULL) {
		q->iohdrs = q->hdr_last = header;
		q->hdrcnt = 1;
		mutex_exit(QLOCK(q));
		return;
	}

	q->hdr_last->dat.next = header;
	q->hdr_last = header;
	q->hdrcnt++;
	mutex_exit(QLOCK(q));
	return;

}

/*
 * mark an io header as flushed. If it is the qhead,
 * then update the qpointers
 * free the io_hdrs
 * called after the bitmap is cleared by flusher
 */
void
rdc_clr_iohdr(rdc_k_info_t *krdc, nsc_size_t qpos)
{
	rdc_group_t *group = krdc->group;
	disk_queue *q = NULL;
	io_hdr	*hp = NULL;
	io_hdr	*p = NULL;
	int found = 0;
	int cnt = 0;

#ifndef NSC_MULTI_TERABYTE
	ASSERT(qpos >= 0);	/* assertion to validate change for 64bit */
	if (qpos < 0) /* not a diskq offset */
		return;
#endif

	q = &group->diskq;
	mutex_enter(QLOCK(q));

	hp = p = q->iohdrs;

	/* find outstanding io_hdr */
	while (hp) {
		if (hp->dat.qpos == qpos) {
			found++;
			break;
		}
		cnt++;
		p = hp;
		hp = hp->dat.next;
	}

	if (!found) {
		if (RDC_BETWEEN(QHEAD(q), QNXTIO(q), qpos)) {
#ifdef DEBUG
			cmn_err(CE_WARN, "!iohdr already cleared? "
			"qpos %" NSC_SZFMT " cnt %d ", qpos, cnt);
			cmn_err(CE_WARN, "!Qinfo: " QDISPLAY(q));
#endif
			mutex_exit(QLOCK(q));
			return;
		}
		mutex_exit(QLOCK(q));
		return;
	}

	/* mark it as flushed */
	hp->dat.iostatus = RDC_IOHDR_DONE;

	/*
	 * if it is the head pointer, travel the list updating the queue
	 * pointers until the next unflushed is reached, freeing on the way.
	 */
	while (hp && (hp->dat.qpos == QHEAD(q)) &&
	    (hp->dat.iostatus == RDC_IOHDR_DONE)) {
#ifdef DEBUG_FLUSHER_UBERNOISE
		cmn_err(CE_NOTE, "!clr_iohdr info: magic %x type %d pos %d"
		    " qpos %d hpos %d len %d flag 0x%x iostatus %x setid %d",
		    hp->dat.magic, hp->dat.type, hp->dat.pos, hp->dat.qpos,
		    hp->dat.hpos, hp->dat.len, hp->dat.flag,
		    hp->dat.iostatus, hp->dat.setid);
#endif
		if (hp->dat.flag & RDC_NULL_BUF) {
			INC_QHEAD(q, FBA_LEN(sizeof (io_hdr)));
		} else {
			INC_QHEAD(q, FBA_LEN(sizeof (io_hdr)) + hp->dat.len);
			DEC_QBLOCKS(q, hp->dat.len);
		}

		DEC_QNITEMS(q, 1);

		if (QHEADSHLDWRAP(q)) { /* simple enough */
#ifdef DEBUG_DISKQWRAP
			cmn_err(CE_NOTE, "!wrapping Q head: " QDISPLAY(q));
#endif
			/*LINTED*/
			WRAPQHEAD(q);
		}

		/* get rid of the iohdr */
		if (hp == q->iohdrs) {
			q->iohdrs = hp->dat.next;
			kmem_free(hp, sizeof (*hp));
			hp = q->iohdrs;
		} else {
			if (hp == q->hdr_last)
				q->hdr_last = p;
			p->dat.next = hp->dat.next;
			kmem_free(hp, sizeof (*hp));
			hp = p->dat.next;
		}
		q->hdrcnt--;
	}

	if (QEMPTY(q) && !IS_QSTATE(q, RDC_QFULL) &&
	    !(IS_QSTATE(q, RDC_QDISABLEPEND))) {
#ifdef DEBUG_FLUSHER_UBERNOISE
		rdc_u_info_t *urdc = &rdc_u_info[krdc->index];
		cmn_err(CE_NOTE, "!clr_iohdr: diskq %s empty, "
		    "resetting defaults", urdc->disk_queue);
#endif

		rdc_init_diskq_header(group, &q->disk_hdr);
		SET_QNXTIO(q, QHEAD(q));
	}

	/* wakeup any blocked enqueue threads */
	cv_broadcast(&q->qfullcv);
	mutex_exit(QLOCK(q));
}

/*
 * put in whatever useful checks we can on the io header
 */
int
rdc_iohdr_ok(io_hdr *hdr)
{
	if (hdr->dat.magic != RDC_IOHDR_MAGIC)
		goto bad;
	return (1);
bad:

#ifdef DEBUG
	cmn_err(CE_WARN, "!Bad io header magic %x type %d pos %" NSC_SZFMT
	    " hpos %" NSC_SZFMT " qpos %" NSC_SZFMT " len %" NSC_SZFMT
	    " flag %d iostatus %d setid %d", hdr->dat.magic,
	    hdr->dat.type, hdr->dat.pos, hdr->dat.hpos, hdr->dat.qpos,
	    hdr->dat.len, hdr->dat.flag, hdr->dat.iostatus, hdr->dat.setid);
#else
	cmn_err(CE_WARN, "!Bad io header retrieved");
#endif
	return (0);
}

/*
 * rdc_netqueue_insert()
 * add an item to a netqueue. No locks necessary as it should only
 * be used in a single threaded manor. If that changes, then
 * a lock or assertion should be done here
 */
void
rdc_netqueue_insert(rdc_aio_t *aio, net_queue *q)
{
	rdc_k_info_t *krdc = &rdc_k_info[aio->index];

	/* paranoid check for bit set */
	RDC_CHECK_BIT(krdc, aio->pos, aio->len);

	if (q->net_qhead == NULL) {
		q->net_qhead = q->net_qtail = aio;

	} else {
		q->net_qtail->next = aio;
		q->net_qtail = aio;
	}
	q->blocks += aio->len;
	q->nitems++;

	if (q->nitems > q->nitems_hwm) {
		q->nitems_hwm = q->nitems;
	}
	if (q->blocks > q->blocks_hwm) {
		q->nitems_hwm = q->blocks;
	}
}

/*
 * rdc_fill_aio(aio, hdr)
 * take the pertinent info from an io_hdr and stick it in
 * an aio, including seq number, abuf.
 */
void
rdc_fill_aio(rdc_group_t *grp, rdc_aio_t *aio, io_hdr *hdr, nsc_buf_t *abuf)
{
	if (hdr->dat.flag & RDC_NULL_BUF) {
		aio->handle = NULL;
	} else {
		aio->handle = abuf;
	}
	aio->qhandle = abuf;
	aio->pos = hdr->dat.pos;
	aio->qpos = hdr->dat.qpos;
	aio->len = hdr->dat.len;
	aio->flag = hdr->dat.flag;
	if ((aio->index = rdc_setid2idx(hdr->dat.setid)) < 0)
		return;
	mutex_enter(&grp->diskq.disk_qlock);
	if (grp->ra_queue.qfflags & RDC_QFILLSLEEP) {
		mutex_exit(&grp->diskq.disk_qlock);
		aio->seq = RDC_NOSEQ;
		return;
	}
	if (abuf && aio->qhandle) {
		abuf->sb_user++;
	}
	aio->seq = grp->seq++;
	if (grp->seq < aio->seq)
		grp->seq = RDC_NEWSEQ + 1;
	mutex_exit(&grp->diskq.disk_qlock);
	hdr->dat.iostatus = aio->seq;

}

#ifdef DEBUG
int maxaios_perbuf = 0;
int midaios_perbuf = 0;
int aveaios_perbuf = 0;
int totaios_perbuf = 0;
int buf2qcalls = 0;

void
calc_perbuf(int items)
{
	if (totaios_perbuf < 0) {
		maxaios_perbuf = 0;
		midaios_perbuf = 0;
		aveaios_perbuf = 0;
		totaios_perbuf = 0;
		buf2qcalls = 0;
	}

	if (items > maxaios_perbuf)
		maxaios_perbuf = items;
	midaios_perbuf = maxaios_perbuf / 2;
	totaios_perbuf += items;
	aveaios_perbuf = totaios_perbuf / buf2qcalls;
}
#endif

/*
 * rdc_discard_tmpq()
 * free up the passed temporary queue
 * NOTE: no cv's or mutexes have been initialized
 */
void
rdc_discard_tmpq(net_queue *q)
{
	rdc_aio_t *aio;

	if (q == NULL)
		return;

	while (q->net_qhead) {
		aio = q->net_qhead;
		q->net_qhead = q->net_qhead->next;
		if (aio->qhandle) {
			aio->qhandle->sb_user--;
			if (aio->qhandle->sb_user == 0) {
				rdc_fixlen(aio);
				(void) nsc_free_buf(aio->qhandle);
			}
		}
		kmem_free(aio, sizeof (*aio));
		q->nitems--;
	}
	kmem_free(q, sizeof (*q));

}

/*
 * rdc_diskq_buf2queue()
 * take a chunk of the diskq, parse it and assemble
 * a chain of rdc_aio_t's.
 * updates QNXTIO()
 */
net_queue *
rdc_diskq_buf2queue(rdc_group_t *grp, nsc_buf_t **abuf, int index)
{
	rdc_aio_t *aio = NULL;
	nsc_vec_t *vecp = NULL;
	uchar_t *vaddr = NULL;
	uchar_t *ioaddr = NULL;
	net_queue *netq = NULL;
	io_hdr  *hdr = NULL;
	nsc_buf_t *buf = *abuf;
	rdc_u_info_t *urdc = &rdc_u_info[index];
	rdc_k_info_t *krdc = &rdc_k_info[index];
	disk_queue *dq = &grp->diskq;
	net_queue *nq = &grp->ra_queue;
	int nullbuf = 0;
	nsc_off_t endobuf;
	nsc_off_t bufoff;
	int vlen;
	nsc_off_t fpos;
	long bufcnt = 0;
	int nullblocks = 0;
	int fail = 1;

	if (buf == NULL)
		return (NULL);

	netq = kmem_zalloc(sizeof (*netq), KM_NOSLEEP);
	if (netq == NULL) {
		cmn_err(CE_WARN, "!SNDR: unable to allocate net queue");
		return (NULL);
	}

	vecp = buf->sb_vec;
	vlen = vecp->sv_len;
	vaddr = vecp->sv_addr;
	bufoff = buf->sb_pos;
	endobuf = bufoff + buf->sb_len;

#ifdef DEBUG_FLUSHER_UBERNOISE
	cmn_err(CE_WARN, "!BUFFOFFENTER %d", bufoff);
#endif
	/* CONSTCOND */
	while (1) {
		if (IS_STATE(urdc, RDC_LOGGING) ||
		    (nq->qfflags & RDC_QFILLSLEEP)) {
			fail = 0;
			goto fail;
		}
#ifdef DEBUG_FLUSHER_UBERNOISE
		cmn_err(CE_WARN, "!BUFFOFF_0 %d", bufoff);
#endif

		if ((vaddr == NULL) || (vlen == 0))
			break;

		if (vlen <= 0) {
			vecp++;
			vaddr = vecp->sv_addr;
			vlen = vecp->sv_len;
			if (vaddr == NULL)
				break;
		}

		/* get the iohdr information */

		hdr = kmem_zalloc(sizeof (*hdr), KM_NOSLEEP);
		if (hdr == NULL) {
			cmn_err(CE_WARN,
			    "!SNDR: unable to alocate net queue header");
			goto fail;
		}

		ioaddr = (uchar_t *)hdr;

		bcopy(vaddr, ioaddr, sizeof (*hdr));

		if (!rdc_iohdr_ok(hdr)) {
			cmn_err(CE_WARN,
			    "!unable to retrieve i/o data from queue %s "
			    "at offset %" NSC_SZFMT " bp: %" NSC_SZFMT " bl: %"
			    NSC_SZFMT, urdc->disk_queue,
			    bufoff, buf->sb_pos, buf->sb_len);
#ifdef DEBUG_DISKQ
			cmn_err(CE_WARN, "!FAILING QUEUE state: %x",
			    rdc_get_vflags(urdc));
			cmn_err(CE_WARN, "!qinfo: " QDISPLAY(dq));
			cmn_err(CE_WARN, "!VADDR %p, IOADDR %p", vaddr, ioaddr);
			cmn_err(CE_WARN, "!BUF %p", buf);
#endif
			cmn_err(CE_WARN, "!qinfo: " QDISPLAYND(dq));

			goto fail;
		}

		nullbuf = hdr->dat.flag & RDC_NULL_BUF;

		bufoff += FBA_NUM(sizeof (*hdr));

		/* out of buffer, set nxtio to re read this last hdr */
		if (!nullbuf && ((bufoff + hdr->dat.len) > endobuf)) {
			break;
		}

		bufcnt += FBA_NUM(sizeof (*hdr));

		aio = kmem_zalloc(sizeof (*aio), KM_NOSLEEP);
		if (aio == NULL) {
			bufcnt -= FBA_NUM(sizeof (*hdr));
			cmn_err(CE_WARN, "!SNDR: net queue aio alloc failed");
			goto fail;
		}

		if (!nullbuf) {
			/* move to next iohdr in big buf */
			bufoff += hdr->dat.len;
			bufcnt += hdr->dat.len;
		}

		rdc_fill_aio(grp, aio, hdr, buf);

		if (aio->index < 0) {
			cmn_err(CE_WARN, "!Set id %d not found or no longer "
			    "enabled, failing disk queue", hdr->dat.setid);
			kmem_free(aio, sizeof (*aio));
			goto fail;
		}
		if (aio->seq == RDC_NOSEQ) {
			kmem_free(aio, sizeof (*aio));
			fail = 0;
			goto fail;
		}
		if (aio->handle == NULL)
			nullblocks += aio->len;

		rdc_add_iohdr(hdr, grp);
		hdr = NULL; /* don't accidentally free on break or fail */
		rdc_netqueue_insert(aio, netq);

		/* no more buffer, skip the below logic */
		if ((bufoff + FBA_NUM(sizeof (*hdr))) >= endobuf) {
			break;
		}

		fpos = bufoff - buf->sb_pos;
		vecp = buf->sb_vec;
		for (; fpos >= FBA_NUM(vecp->sv_len); vecp++)
			fpos -= FBA_NUM(vecp->sv_len);
		vlen = vecp->sv_len - FBA_SIZE(fpos);
		vaddr = vecp->sv_addr + FBA_SIZE(fpos);
		/* abuf = NULL; */

	}

	/* free extraneous header */
	if (hdr) {
		kmem_free(hdr, sizeof (*hdr));
		hdr = NULL;
	}

	/*
	 * probably won't happen, but if we didn't goto fail, but
	 * we don't contain anything meaningful.. return NULL
	 * and let the flusher or the sleep/wakeup routines
	 * decide
	 */
	if (netq && netq->nitems == 0) {
		kmem_free(netq, sizeof (*netq));
		return (NULL);
	}

#ifdef DEBUG
	buf2qcalls++;
	calc_perbuf(netq->nitems);
#endif
	if (IS_STATE(urdc, RDC_LOGGING) ||
	    nq->qfflags & RDC_QFILLSLEEP) {
		fail = 0;
		goto fail;
	}

	mutex_enter(QLOCK(dq));
	INC_QNXTIO(dq, bufcnt);
	mutex_exit(QLOCK(dq));

	netq->net_qtail->orig_len = nullblocks; /* overload */

	return (netq);

fail:

	if (hdr) {
		kmem_free(hdr, sizeof (*hdr));
	}

	if (netq) {
		if (netq->nitems > 0) {
			/* the never can happen case ... */
			if ((netq->nitems == 1) &&
			    (netq->net_qhead->handle == NULL)) {
				(void) nsc_free_buf(buf);
				*abuf = NULL;
			}

		}
		rdc_discard_tmpq(netq);
	}

	mutex_enter(QLOCK(dq));
	rdc_dump_iohdrs(dq);
	mutex_exit(QLOCK(dq));

	if (fail) { /* real failure, not just state change */
#ifdef DEBUG
		cmn_err(CE_WARN, "!rdc_diskq_buf2queue: failing disk queue %s",
		    urdc->disk_queue);
#endif
		rdc_fail_diskq(krdc, RDC_NOWAIT, RDC_DOLOG);
	}

	return (NULL);

}

/*
 * rdc_diskq_unqueue
 * remove one chunk from the diskq belonging to
 * rdc_k_info[index]
 * updates the head and tail pointers in the disk header
 * but does not write. The header should be written on ack
 * flusher should free whatever..
 */
rdc_aio_t *
rdc_diskq_unqueue(int index)
{
	int rc, rc1, rc2;
	nsc_off_t qhead;
	int nullhandle = 0;
	io_hdr *iohdr;
	rdc_aio_t *aio = NULL;
	nsc_buf_t *buf = NULL;
	nsc_buf_t *abuf = NULL;
	rdc_group_t *group = NULL;
	disk_queue *q = NULL;
	rdc_k_info_t *krdc = &rdc_k_info[index];
	rdc_u_info_t *urdc = &rdc_u_info[index];

	group = krdc->group;
	q = &group->diskq;

	if (group->diskqfd == NULL) /* we've been disabled */
		return (NULL);

	aio = kmem_zalloc(sizeof (*aio), KM_NOSLEEP);
	if (!aio) {
		return (NULL);
	}

	iohdr = kmem_zalloc(sizeof (*iohdr), KM_NOSLEEP);
	if (!iohdr) {
		kmem_free(aio, sizeof (*aio));
		return (NULL);
	}

	mutex_enter(QLOCK(q));
	rdc_set_qbusy(q); /* make sure no one disables the queue */
	mutex_exit(QLOCK(q));

	DTRACE_PROBE(rdc_diskq_unq_rsrv);

	if (_rdc_rsrv_diskq(group)) {
		cmn_err(CE_WARN, "!rdc_unqueue: %s reserve failed",
		    urdc->disk_queue);
		goto fail;
	}

	mutex_enter(QHEADLOCK(q));
	mutex_enter(QLOCK(q));

	if (IS_STATE(urdc, RDC_DISKQ_FAILED) || IS_STATE(urdc, RDC_LOGGING)) {
		rdc_clr_qbusy(q);
		mutex_exit(QLOCK(q));
		mutex_exit(QHEADLOCK(q));
		kmem_free(aio, sizeof (*aio));
		kmem_free(iohdr, sizeof (*iohdr));
		return (NULL);
	}

	if (QNXTIOSHLDWRAP(q)) {
#ifdef DEBUG_DISKQWRAP
		cmn_err(CE_NOTE, "!wrapping Q nxtio: " QDISPLAY(q));
#endif
		/*LINTED*/
		WRAPQNXTIO(q);
	}

	/* read the metainfo at q->nxt_io first */
	if (QNXTIO(q) == QTAIL(q)) { /* empty */

		_rdc_rlse_diskq(group);
		if (q->lastio->handle)
			(void) nsc_free_buf(q->lastio->handle);
		bzero(&(*q->lastio), sizeof (*q->lastio));

		mutex_exit(QHEADLOCK(q));
		rdc_clr_qbusy(q);
		mutex_exit(QLOCK(q));
		kmem_free(aio, sizeof (*aio));
		kmem_free(iohdr, sizeof (*iohdr));
		return (NULL);
	}

	qhead = QNXTIO(q);

	/*
	 * have to drop the lock here, sigh. Cannot block incoming io
	 * we have to wait until after this read to find out how
	 * much to increment QNXTIO. Might as well grab the seq then too
	 */

	while ((qhead == LASTQTAIL(q)) && (IS_QSTATE(q, QTAILBUSY))) {
		mutex_exit(QLOCK(q));
#ifdef DEBUG_DISKQ
		cmn_err(CE_NOTE, "!Qtail busy delay lastqtail: %d", qhead);
#endif
		delay(5);
		mutex_enter(QLOCK(q));
	}
	mutex_exit(QLOCK(q));

	DTRACE_PROBE(rdc_diskq_iohdr_read_start);

	rc = rdc_ns_io(group->diskqfd, NSC_READ, qhead,
	    (uchar_t *)iohdr, FBA_SIZE(1));

	DTRACE_PROBE(rdc_diskq_iohdr_read_end);

	if (!RDC_SUCCESS(rc) || !rdc_iohdr_ok(iohdr)) {
		cmn_err(CE_WARN, "!unable to retrieve i/o data from queue %s"
		    " at offset %" NSC_SZFMT " rc %d", urdc->disk_queue,
		    qhead, rc);
#ifdef DEBUG_DISKQ
		cmn_err(CE_WARN, "!qinfo: " QDISPLAY(q));
#endif
		mutex_exit(QHEADLOCK(q));
		goto fail;
	}

/* XXX process buffer here, creating rdc_aio_t's */

	mutex_enter(QLOCK(q));
	/* update the next pointer */
	if (iohdr->dat.flag == RDC_NULL_BUF) {
		INC_QNXTIO(q, FBA_LEN(sizeof (io_hdr)));
		nullhandle = 1;
	} else {
		INC_QNXTIO(q, (FBA_LEN(sizeof (io_hdr)) + iohdr->dat.len));
	}

	aio->seq = group->seq++;
	if (group->seq < aio->seq)
		group->seq = RDC_NEWSEQ + 1;

	mutex_exit(QLOCK(q));
	mutex_exit(QHEADLOCK(q));

#ifdef DEBUG_FLUSHER_UBERNOISE
	p = &iohdr->dat;
	cmn_err(CE_NOTE, "!unqueued iohdr from %d pos: %d len: %d flag: %d "
	    "iostatus: %d setid: %d time: %d", qhead, p->pos, p->len,
	    p->flag, p->iostatus, p->setid, p->time);
#endif

	if (nullhandle) /* nothing to get from queue */
		goto nullbuf;

	/* now that we know how much to get (iohdr.dat.len), get it */
	DTRACE_PROBE(rdc_diskq_unq_allocbuf1_start);

	rc = nsc_alloc_buf(group->diskqfd, qhead + 1, iohdr->dat.len,
	    NSC_NOCACHE | NSC_READ, &buf);

	DTRACE_PROBE(rdc_diskq_unq_allocbuf1_end);

	/* and get somewhere to keep it for a bit */
	DTRACE_PROBE(rdc_diskq_unq_allocbuf2_start);

	rc1 = nsc_alloc_abuf(qhead + 1, iohdr->dat.len, 0, &abuf);

	DTRACE_PROBE(rdc_diskq_unq_allocbuf2_end);

	if (!RDC_SUCCESS(rc) || !RDC_SUCCESS(rc1)) { /* uh-oh */
		cmn_err(CE_WARN, "!disk queue %s read failure",
		    urdc->disk_queue);
		goto fail;
	}

	/* move it on over... */
	rc2 = nsc_copy(buf, abuf, qhead + 1, qhead + 1, iohdr->dat.len);

	if (!RDC_SUCCESS(rc2)) {
#ifdef DEBUG
		cmn_err(CE_WARN, "!nsc_copy failed for diskq unqueue");
#endif
		goto fail;
	}

	/* let go of the real buf, we've got the abuf  */
	(void) nsc_free_buf(buf);
	buf = NULL;

	aio->handle = abuf;
	/* Hack in the original sb_pos */
	aio->handle->sb_pos = iohdr->dat.hpos;

	/* skip the RDC_HANDLE_LIMITS check */
	abuf->sb_user |= RDC_DISKQUE;

nullbuf:
	if (nullhandle) {
		aio->handle = NULL;
	}

	/* set up the rest of the aio values, seq set above ... */
	aio->pos = iohdr->dat.pos;
	aio->qpos = iohdr->dat.qpos;
	aio->len = iohdr->dat.len;
	aio->flag = iohdr->dat.flag;
	aio->index = rdc_setid2idx(iohdr->dat.setid);
	if (aio->index < 0) { /* uh-oh */
#ifdef DEBUG
		cmn_err(CE_WARN, "!rdc_diskq_unqueue: index < 0");
#endif
		goto fail;
	}


#ifdef DEBUG_FLUSHER_UBERNOISE_STAMP
	h = &q->disk_hdr.h;
	cmn_err(CE_NOTE, "!stamping diskq header:\n"
	    "magic: %x\nstate: %d\nhead_offset: %d\n"
	    "tail_offset: %d\ndisk_size: %d\nnitems: %d\nblocks: %d\n",
	    h->magic, h->state, h->head_offset, h->tail_offset,
	    h->disk_size, h->nitems, h->blocks);
#endif

	_rdc_rlse_diskq(group);

	mutex_enter(QLOCK(q));
	rdc_clr_qbusy(q);
	mutex_exit(QLOCK(q));

	DTRACE_PROBE(rdc_diskq_unq_rlse);

	iohdr->dat.iostatus = aio->seq;
	rdc_add_iohdr(iohdr, group);

#ifdef DEBUG_FLUSHER_UBERNOISE
	if (!nullhandle) {
		cmn_err(CE_NOTE, "!UNQUEUING, %p"
		    " contents: %c%c%c%c%c pos: %d len: %d",
		    (void *)aio->handle,
		    aio->handle->sb_vec[0].sv_addr[0],
		    aio->handle->sb_vec[0].sv_addr[1],
		    aio->handle->sb_vec[0].sv_addr[2],
		    aio->handle->sb_vec[0].sv_addr[3],
		    aio->handle->sb_vec[0].sv_addr[4],
		    aio->handle->sb_pos, aio->handle->sb_len);
	} else {
		cmn_err(CE_NOTE, "!UNQUEUING, NULL " QDISPLAY(q));
	}
	cmn_err(CE_NOTE, "!qinfo: " QDISPLAY(q));
#endif

	return (aio);

fail:
	if (aio)
		kmem_free(aio, sizeof (*aio));
	if (iohdr)
		kmem_free(iohdr, sizeof (*iohdr));
	if (buf)
		(void) nsc_free_buf(buf);
	if (abuf)
		(void) nsc_free_buf(abuf);

	_rdc_rlse_diskq(group);
#ifdef DEBUG
	cmn_err(CE_WARN, "!diskq_unqueue: failing diskq");
#endif
	mutex_enter(QLOCK(q));
	rdc_clr_qbusy(q);
	mutex_exit(QLOCK(q));

	rdc_fail_diskq(krdc, RDC_NOWAIT, RDC_DOLOG);

	return (NULL);
}

int
rdc_diskq_inuse(rdc_set_t *set, char *diskq)
{
	rdc_u_info_t *urdc;
	char *group;
	int index;

	group = set->group_name;

	ASSERT(MUTEX_HELD(&rdc_conf_lock));

	if ((rdc_lookup_bitmap(diskq) >= 0) ||
	    (rdc_lookup_configured(diskq) >= 0)) {
		return (1);
	}
	for (index = 0; index < rdc_max_sets; index++) {
		urdc = &rdc_u_info[index];

		if (!IS_ENABLED(urdc))
			continue;

		/* same diskq different group */
		if ((strcmp(urdc->disk_queue, diskq) == 0) &&
		    (urdc->group_name[0] == '\0' ||
		    strcmp(urdc->group_name, group))) {
			return (1);
		}
	}
	/* last, but not least, lets see if someone is getting really funky */
	if ((strcmp(set->disk_queue, set->primary.file) == 0) ||
	    (strcmp(set->disk_queue, set->primary.bitmap) == 0)) {
		return (1);
	}

	return (0);

}

#ifdef DEBUG
int maxlen = 0;
int avelen = 0;
int totalen = 0;
int lencalls = 0;

void
update_lenstats(int len)
{
	if (lencalls == 0) {
		lencalls = 1;
		avelen = 0;
		maxlen = 0;
		totalen = 0;
	}

	if (len > maxlen)
		maxlen = len;
	totalen += len;
	avelen = totalen / lencalls;
}
#endif

/*
 * rdc_calc_len()
 * returns the size of the diskq that can be read for dequeuing
 * always <= RDC_MAX_DISKQREAD
 */
int
rdc_calc_len(rdc_k_info_t *krdc, disk_queue *dq)
{
	nsc_size_t len = 0;

	ASSERT(MUTEX_HELD(QLOCK(dq)));

	/* ---H-----N-----T--- */
	if (QNXTIO(dq) < QTAIL(dq)) {

		len = min(RDC_MAX_DISKQREAD, QTAIL(dq) - QNXTIO(dq));

	/* ---T-----H-----N--- */
	} else if (QNXTIO(dq) > QTAIL(dq)) {
		if (QWRAP(dq)) {
			len = min(RDC_MAX_DISKQREAD, QWRAP(dq) - QNXTIO(dq));
		} else { /* should never happen */
			len = min(RDC_MAX_DISKQREAD, QSIZE(dq) - QNXTIO(dq));
		}
	} else if (QNXTIO(dq) == QTAIL(dq)) {
		if (QWRAP(dq) && !IS_QSTATE(dq, QNXTIOWRAPD))
			len = min(RDC_MAX_DISKQREAD, QWRAP(dq) - QNXTIO(dq));
	}

	len = min(len, krdc->maxfbas);

#ifdef DEBUG
	lencalls++;
	update_lenstats(len);
#endif

	return ((int)len);
}

/*
 * lie a little if we can, so we don't get tied up in
 * _nsc_wait_dbuf() on the next read. sb_len MUST be
 * restored before nsc_free_buf() however, or we will
 * be looking at memory leak city..
 * so update the entire queue with the info as well
 * and the one that ends up freeing it, can fix the len
 * IMPORTANT: This assumes that we are not cached, in
 * 3.2 caching was turned off for data volumes, if that
 * changes, then this must too
 */
void
rdc_trim_buf(nsc_buf_t *buf, net_queue *q)
{
	rdc_aio_t *p;
	int len;

	if (buf == NULL || q == NULL)
		return;

	if (q && (buf->sb_len >
	    (q->blocks + q->nitems - q->net_qtail->orig_len))) {
		len = buf->sb_len;
		buf->sb_len = (q->blocks + q->nitems - q->net_qtail->orig_len);
	}

	p = q->net_qhead;
	do {
		p->orig_len = len;
		p = p->next;

	} while (p);

}

/*
 * rdc_read_diskq_buf()
 * read a large as possible chunk of the diskq into a nsc_buf_t
 * and convert it to a net_queue of rdc_aio_t's to be appended
 * to the group's netqueue
 */
net_queue *
rdc_read_diskq_buf(int index)
{
	nsc_buf_t *buf = NULL;
	net_queue *tmpnq = NULL;
	disk_queue *dq = NULL;
	rdc_k_info_t *krdc = &rdc_k_info[index];
	rdc_u_info_t *urdc = &rdc_u_info[index];
	rdc_group_t *group = krdc->group;
	net_queue *nq = &group->ra_queue;
	int len = 0;
	int rc;
	int fail = 0;
	int offset = 0;

	if (group == NULL || group->diskqfd == NULL) {
		DTRACE_PROBE(rdc_read_diskq_buf_bail1);
		return (NULL);
	}

	dq = &group->diskq;

	mutex_enter(QLOCK(dq));
	rdc_set_qbusy(dq); /* prevent disables on the queue */
	mutex_exit(QLOCK(dq));

	if (_rdc_rsrv_diskq(group)) {
		cmn_err(CE_WARN, "!rdc_readdiskqbuf: %s reserve failed",
		    urdc->disk_queue);
		mutex_enter(QLOCK(dq));
		rdc_clr_qbusy(dq); /* prevent disables on the queue */
		mutex_exit(QLOCK(dq));
		return (NULL);
	}

	mutex_enter(QHEADLOCK(dq));
	mutex_enter(QLOCK(dq));

	if (IS_STATE(urdc, RDC_DISKQ_FAILED) ||
	    IS_STATE(urdc, RDC_LOGGING) ||
	    (nq->qfflags & RDC_QFILLSLEEP)) {
		mutex_exit(QLOCK(dq));
		mutex_exit(QHEADLOCK(dq));
		DTRACE_PROBE(rdc_read_diskq_buf_bail2);
		goto done;
	}

	/*
	 * real corner case here, we need to let the flusher wrap first.
	 * we've gotten too far ahead, so just delay and try again
	 */
	if (IS_QSTATE(dq, QNXTIOWRAPD) && AUXQWRAP(dq)) {
		mutex_exit(QLOCK(dq));
		mutex_exit(QHEADLOCK(dq));
		goto done;
	}

	if (QNXTIOSHLDWRAP(dq)) {
#ifdef DEBUG_DISKQWRAP
		cmn_err(CE_NOTE, "!wrapping Q nxtio: " QDISPLAY(dq));
#endif
		/*LINTED*/
		WRAPQNXTIO(dq);
	}

	/* read the metainfo at q->nxt_io first */
	if (!QNITEMS(dq)) { /* empty */

		if (dq->lastio->handle)
			(void) nsc_free_buf(dq->lastio->handle);
		bzero(&(*dq->lastio), sizeof (*dq->lastio));
		mutex_exit(QLOCK(dq));
		mutex_exit(QHEADLOCK(dq));
		DTRACE_PROBE(rdc_read_diskq_buf_bail3);
		goto done;
	}


	len = rdc_calc_len(krdc, dq);

	if ((len <= 0) || (IS_STATE(urdc, RDC_LOGGING)) ||
	    (IS_STATE(urdc, RDC_DISKQ_FAILED)) ||
	    (nq->qfflags & RDC_QFILLSLEEP)) {
		mutex_exit(QLOCK(dq));
		mutex_exit(QHEADLOCK(dq));
		/*
		 * a write could be trying to get on the queue, or if
		 * the queue is really really small, a complete image
		 * of it could be on the net queue waiting for flush.
		 * the latter being a fairly stupid scenario and a gross
		 * misconfiguration.. but what the heck, why make the thread
		 * thrash around.. just pause a little here.
		 */
		if (len <= 0)
			delay(50);

		DTRACE_PROBE3(rdc_read_diskq_buf_bail4, int, len,
		    int, rdc_get_vflags(urdc), int, nq->qfflags);

		goto done;
	}

	DTRACE_PROBE2(rdc_calc_len, int, len, int, (int)QNXTIO(dq));

#ifdef DEBUG_FLUSHER_UBERNOISE
	cmn_err(CE_WARN, "!CALC_LEN(%d) h:%d n%d t%d, w%d",
	    len, QHEAD(dq), QNXTIO(dq), QTAIL(dq), QWRAP(dq));
	cmn_err(CE_CONT, "!qinfo: " QDISPLAYND(dq));
#endif
	SET_QCOALBOUNDS(dq, QNXTIO(dq) + len);

	while ((LASTQTAIL(dq) > 0) && !QWRAP(dq) &&
	    ((QNXTIO(dq) + len) >= LASTQTAIL(dq)) &&
	    (IS_QSTATE(dq, QTAILBUSY))) {
		mutex_exit(QLOCK(dq));

#ifdef DEBUG_FLUSHER_UBERNOISE
		cmn_err(CE_NOTE, "!Qtail busy delay nxtio %d len %d "
		    "lastqtail: %d", QNXTIO(dq), len, LASTQTAIL(dq));
#endif
		delay(20);
		mutex_enter(QLOCK(dq));
	}

	offset = QNXTIO(dq);

	/*
	 * one last check to see if we have gone logging, or should.
	 * we may have released the mutex above, so check again
	 */
	if ((IS_STATE(urdc, RDC_LOGGING)) ||
	    (IS_STATE(urdc, RDC_DISKQ_FAILED)) ||
	    (nq->qfflags & RDC_QFILLSLEEP)) {
		mutex_exit(QLOCK(dq));
		mutex_exit(QHEADLOCK(dq));
		goto done;
	}

	mutex_exit(QLOCK(dq));
	mutex_exit(QHEADLOCK(dq));

	DTRACE_PROBE2(rdc_buf2q_preread, int, offset, int, len);

	rc = nsc_alloc_buf(group->diskqfd, offset, len,
	    NSC_NOCACHE | NSC_READ, &buf);

	if (!RDC_SUCCESS(rc)) {
		cmn_err(CE_WARN, "!disk queue %s read failure pos %" NSC_SZFMT
		    " len %d", urdc->disk_queue, QNXTIO(dq), len);
		fail++;
		buf = NULL;
		DTRACE_PROBE(rdc_read_diskq_buf_bail5);
		goto done;
	}

	DTRACE_PROBE2(rdc_buf2q_postread, int, offset, nsc_size_t, buf->sb_len);

	/*
	 * convert buf to a net_queue. buf2queue will
	 * update the QNXTIO pointer for us, based on
	 * the last readable queue item
	 */
	tmpnq = rdc_diskq_buf2queue(group, &buf, index);

#ifdef DEBUG_FLUSHER_UBERNOISE
	cmn_err(CE_NOTE, "!QBUF p: %d l: %d p+l: %d users: %d qblocks: %d ",
	    "qitems: %d WASTED: %d", buf->sb_pos, buf->sb_len,
	    buf->sb_pos+buf->sb_len, buf->sb_user, tmpnq?tmpnq->blocks:-1,
	    tmpnq?tmpnq->nitems:-1,
	    tmpnq?((buf->sb_len-tmpnq->nitems) - tmpnq->blocks):-1);
#endif

	DTRACE_PROBE3(rdc_buf2que_returned, net_queue *, tmpnq?tmpnq:0,
	    uint64_t, tmpnq?tmpnq->nitems:0,
	    uint_t, tmpnq?tmpnq->net_qhead->seq:0);
done:

	/* we don't need to retain the buf */
	if (tmpnq == NULL)
		if (buf) {
			(void) nsc_free_buf(buf);
			buf = NULL;
		}

	rdc_trim_buf(buf, tmpnq);

	mutex_enter(QLOCK(dq));
	rdc_clr_qbusy(dq);
	mutex_exit(QLOCK(dq));

	_rdc_rlse_diskq(group);

	if (fail) {
		rdc_fail_diskq(krdc, RDC_NOWAIT, RDC_DOLOG);
		tmpnq = NULL;
	}

	return (tmpnq);
}

/*
 * rdc_dequeue()
 * removes the head of the memory queue
 */
rdc_aio_t *
rdc_dequeue(rdc_k_info_t *krdc, int *rc)
{
	net_queue *q = &krdc->group->ra_queue;
	disk_queue *dq = &krdc->group->diskq;
	rdc_u_info_t *urdc = &rdc_u_info[krdc->index];
	rdc_aio_t *aio;

	*rc = 0;

	if (q == NULL)
		return (NULL);

	mutex_enter(&q->net_qlock);

	aio = q->net_qhead;

	if (aio == NULL) {
#ifdef DEBUG
		if (q->nitems != 0 || q->blocks != 0 || q->net_qtail != 0) {
			cmn_err(CE_PANIC,
			    "rdc_dequeue(1): q %p, q blocks %" NSC_SZFMT
			    " , nitems %" NSC_SZFMT ", qhead %p qtail %p",
			    (void *) q, q->blocks, q->nitems,
			    (void *) aio, (void *) q->net_qtail);
		}
#endif

		mutex_exit(&q->net_qlock);

		if ((!IS_STATE(urdc, RDC_LOGGING)) &&
		    (!(q->qfflags & RDC_QFILLSLEEP)) &&
		    (!IS_STATE(urdc, RDC_SYNCING)) && (QNITEMS(dq) > 0)) {
			*rc = EAGAIN;
		}

		goto done;
	}

	/* aio remove from q */

	q->net_qhead = aio->next;
	aio->next = NULL;

	if (q->net_qtail == aio)
		q->net_qtail = q->net_qhead;

	q->blocks -= aio->len;
	q->nitems--;

#ifdef DEBUG
	if (q->net_qhead == NULL) {
		if (q->nitems != 0 || q->blocks != 0 || q->net_qtail != 0) {
			cmn_err(CE_PANIC, "rdc_dequeue(2): q %p, q blocks %"
			    NSC_SZFMT " nitems %" NSC_SZFMT
			    " , qhead %p qtail %p",
			    (void *) q, q->blocks, q->nitems,
			    (void *) q->net_qhead, (void *) q->net_qtail);
		}
	}
#endif
	mutex_exit(&q->net_qlock);
done:

	mutex_enter(&q->net_qlock);

	if (rdc_qfill_shldwakeup(krdc))
		cv_broadcast(&q->qfcv);

	/*
	 * clear EAGAIN if
	 * logging or q filler thread is sleeping or stopping altogether
	 * or if q filler thread is dead already
	 * or if syncing, this will return a null aio, with no error code set
	 * telling the flusher to die
	 */
	if (*rc == EAGAIN) {
		if (IS_STATE(urdc, RDC_LOGGING) ||
		    (q->qfflags & (RDC_QFILLSLEEP | RDC_QFILLSTOP)) ||
		    (IS_QSTATE(dq, (RDC_QDISABLEPEND | RDC_STOPPINGFLUSH))) ||
		    (q->qfill_sleeping == RDC_QFILL_DEAD) ||
		    (IS_STATE(urdc, RDC_SYNCING)))
			*rc = 0;
	}

	mutex_exit(&q->net_qlock);

	return (aio);

}

/*
 * rdc_qfill_shldsleep()
 * returns 1 if the qfilling code should cv_wait() 0 if not.
 * reasons for going into cv_wait();
 * there is nothing in the diskq to flush to mem.
 * the memory queue has gotten too big and needs more flushing attn.
 */
int
rdc_qfill_shldsleep(rdc_k_info_t *krdc)
{
	net_queue *nq = &krdc->group->ra_queue;
	disk_queue *dq = &krdc->group->diskq;
	rdc_u_info_t *urdc = &rdc_u_info[krdc->index];

	ASSERT(MUTEX_HELD(&nq->net_qlock));

	if (!RDC_IS_DISKQ(krdc->group))
		return (1);

	if (nq->qfflags & RDC_QFILLSLEEP) {
#ifdef DEBUG_DISKQ_NOISY
	cmn_err(CE_NOTE, "!Sleeping diskq->memq flusher: QFILLSLEEP idx: %d",
	    krdc->index);
#endif
		return (1);
	}

	if (IS_STATE(urdc, RDC_LOGGING) || IS_STATE(urdc, RDC_SYNCING)) {
#ifdef DEBUG_DISKQ_NOISY
	cmn_err(CE_NOTE, "!Sleeping diskq->memq flusher: Sync|Log (0x%x)"
	    " idx: %d", rdc_get_vflags(urdc), urdc->index);
#endif
		return (1);
	}

	mutex_enter(QLOCK(dq));
	if ((QNXTIO(dq) == QTAIL(dq)) && !IS_QSTATE(dq, RDC_QFULL)) {
#ifdef DEBUG_DISKQ_NOISY
		cmn_err(CE_NOTE, "!Sleeping diskq->memq flusher: QEMPTY");
#endif
		mutex_exit(QLOCK(dq));
		return (1);
	}
	mutex_exit(QLOCK(dq));

	if (nq->blocks >= RDC_MAX_QBLOCKS) {
		nq->hwmhit = 1;
		/* stuck flushers ? */
#ifdef DEBUG_DISKQ_NOISY
		cmn_err(CE_NOTE, "!Sleeping diskq->memq flusher: memq full:"
		    " seq: %d seqack %d", krdc->group->seq,
		    krdc->group->seqack);
#endif
		return (1);
	}

	return (0);
}

/*
 * rdc_join_netqueues(a, b)
 * appends queue b to queue a updating all the queue info
 * as it is assumed queue a is the important one,
 * it's mutex must be held. no one can add to queue b
 */
void
rdc_join_netqueues(net_queue *q, net_queue *tmpq)
{
	ASSERT(MUTEX_HELD(&q->net_qlock));

	if (q->net_qhead == NULL) { /* empty */
#ifdef DEBUG
		if (q->blocks != 0 || q->nitems != 0) {
			cmn_err(CE_PANIC, "rdc filler: q %p, qhead 0, "
			    " q blocks %" NSC_SZFMT ", nitems %" NSC_SZFMT,
			    (void *) q, q->blocks, q->nitems);
		}
#endif
		q->net_qhead = tmpq->net_qhead;
		q->net_qtail = tmpq->net_qtail;
		q->nitems = tmpq->nitems;
		q->blocks = tmpq->blocks;
	} else {
		q->net_qtail->next = tmpq->net_qhead;
		q->net_qtail = tmpq->net_qtail;
		q->nitems += tmpq->nitems;
		q->blocks += tmpq->blocks;
	}

	if (q->nitems > q->nitems_hwm) {
		q->nitems_hwm = q->nitems;
	}

	if (q->blocks > q->blocks_hwm) {
		q->blocks_hwm = q->blocks;
	}
}

/*
 * rdc_qfiller_thr() single thread that moves
 * data from the diskq to a memory queue for
 * the flusher to pick up.
 */
void
rdc_qfiller_thr(rdc_k_info_t *krdc)
{
	rdc_group_t *grp = krdc->group;
	rdc_u_info_t *urdc = &rdc_u_info[krdc->index];
	net_queue *q = &grp->ra_queue;
	net_queue *tmpq = NULL;
	int index = krdc->index;

	q->qfill_sleeping = RDC_QFILL_AWAKE;
	while (!(q->qfflags & RDC_QFILLSTOP)) {
		if (!RDC_IS_DISKQ(grp) ||
		    IS_STATE(urdc, RDC_LOGGING) ||
		    IS_STATE(urdc, RDC_DISKQ_FAILED) ||
		    (q->qfflags & RDC_QFILLSLEEP)) {
			goto nulltmpq;
		}

		DTRACE_PROBE(qfiller_top);
		tmpq = rdc_read_diskq_buf(index);

		if (tmpq == NULL)
			goto nulltmpq;

		if ((q->qfflags & RDC_QFILLSLEEP) ||
		    IS_STATE(urdc, RDC_LOGGING)) {
			rdc_discard_tmpq(tmpq);
			goto nulltmpq;
		}

		mutex_enter(&q->net_qlock);

		/* race with log, redundant yet paranoid */
		if ((q->qfflags & RDC_QFILLSLEEP) ||
		    IS_STATE(urdc, RDC_LOGGING)) {
			rdc_discard_tmpq(tmpq);
			mutex_exit(&q->net_qlock);
			goto nulltmpq;
		}


		rdc_join_netqueues(q, tmpq);
		kmem_free(tmpq, sizeof (*tmpq));
		tmpq = NULL;

		mutex_exit(&q->net_qlock);
nulltmpq:
		/*
		 * sleep for a while if we can.
		 * the enqueuing or flushing code will
		 * wake us if if necessary.
		 */
		mutex_enter(&q->net_qlock);
		while (rdc_qfill_shldsleep(krdc)) {
			q->qfill_sleeping = RDC_QFILL_ASLEEP;
			DTRACE_PROBE(qfiller_sleep);
			cv_wait(&q->qfcv, &q->net_qlock);
			DTRACE_PROBE(qfiller_wakeup);
			q->qfill_sleeping = RDC_QFILL_AWAKE;
			if (q->qfflags & RDC_QFILLSTOP) {
#ifdef DEBUG_DISKQ
			cmn_err(CE_NOTE,
			    "!rdc_qfiller_thr: recieved kill signal");
#endif
				mutex_exit(&q->net_qlock);
				goto done;
			}
		}
		mutex_exit(&q->net_qlock);

	DTRACE_PROBE(qfiller_bottom);
	}
done:
	DTRACE_PROBE(qfiller_done);
	q->qfill_sleeping = RDC_QFILL_DEAD; /* the big sleep */

#ifdef DEBUG
	cmn_err(CE_NOTE, "!rdc_qfiller_thr stopping");
#endif
	q->qfflags &= ~RDC_QFILLSTOP;

}

int
_rdc_add_diskq(int index, char *diskq)
{
	rdc_k_info_t *krdc, *kp;
	rdc_u_info_t *urdc, *up;
	rdc_group_t *group;
	int rc;

	krdc = &rdc_k_info[index];
	urdc = &rdc_u_info[index];
	group = krdc->group;

	if (!diskq || urdc->disk_queue[0]) { /* how'd that happen? */
#ifdef DEBUG
		cmn_err(CE_WARN, "!NULL diskq in _rdc_add_diskq");
#endif
		rc = -1;
		goto fail;
	}

	/* if the enable fails, this is bzero'ed */
	(void) strncpy(urdc->disk_queue, diskq, NSC_MAXPATH);
	group->flags &= ~RDC_MEMQUE;
	group->flags |= RDC_DISKQUE;

#ifdef DEBUG
	cmn_err(CE_NOTE, "!adding diskq to group %s", urdc->group_name);
#endif
	mutex_enter(&rdc_conf_lock);
	rc = rdc_enable_diskq(krdc);
	mutex_exit(&rdc_conf_lock);

	if (rc == RDC_EQNOADD) {
		goto fail;
	}

	RDC_ZERO_BITREF(krdc);
	for (kp = krdc->group_next; kp != krdc; kp = kp->group_next) {
		up = &rdc_u_info[kp->index];
		(void) strncpy(up->disk_queue, diskq, NSC_MAXPATH);
		/* size lives in the diskq structure, already set by enable */
		RDC_ZERO_BITREF(kp);
	}

fail:
	return (rc);

}

/*
 * add a diskq to an existing set/group
 */
int
rdc_add_diskq(rdc_config_t *uparms, spcs_s_info_t kstatus)
{
	char *diskq;
	int rc;
	int index;
	rdc_k_info_t *krdc, *this;
	rdc_u_info_t *urdc;
	rdc_group_t *group;
	nsc_size_t vol_size = 0;
	nsc_size_t req_size = 0;

	mutex_enter(&rdc_conf_lock);
	index = rdc_lookup_byname(uparms->rdc_set);
	mutex_exit(&rdc_conf_lock);
	if (index < 0) {
		spcs_s_add(kstatus, RDC_EALREADY, uparms->rdc_set->primary.file,
		    uparms->rdc_set->secondary.file);
		rc = RDC_EALREADY;
		goto failed;
	}
	urdc = &rdc_u_info[index];
	krdc = &rdc_k_info[index];
	this = &rdc_k_info[index];
	group = krdc->group;
	diskq = uparms->rdc_set->disk_queue;

	if (!IS_ASYNC(urdc)) {
		spcs_s_add(kstatus, RDC_EQWRONGMODE, urdc->primary.intf,
		    urdc->primary.file, urdc->secondary.intf,
		    urdc->secondary.file);
		rc = RDC_EQNOQUEUE;
		goto failed;
	}

	do {
		if (!IS_STATE(urdc, RDC_LOGGING)) {
			spcs_s_add(kstatus, RDC_EQNOTLOGGING,
			    uparms->rdc_set->disk_queue);
			rc = RDC_EQNOTLOGGING;
			goto failed;
		}
		/* make sure that we have enough bitmap vol */
		req_size = RDC_BITMAP_FBA + FBA_LEN(krdc->bitmap_size);
		req_size += FBA_LEN(krdc->bitmap_size * BITS_IN_BYTE);

		rc = _rdc_rsrv_devs(krdc, RDC_BMP, RDC_INTERNAL);

		if (!RDC_SUCCESS(rc)) {
			cmn_err(CE_WARN,
			    "!rdc_open_diskq: Bitmap reserve failed");
			spcs_s_add(kstatus, RDC_EBITMAP,
			    urdc->primary.bitmap);
			rc = RDC_EBITMAP;
			goto failed;
		}

		(void) nsc_partsize(krdc->bitmapfd, &vol_size);

		_rdc_rlse_devs(krdc, RDC_BMP);

		if (vol_size < req_size) {
			spcs_s_add(kstatus, RDC_EBITMAP2SMALL,
			    urdc->primary.bitmap);
			rc = RDC_EBITMAP2SMALL;
			goto failed;
		}

		krdc = krdc->group_next;
		urdc = &rdc_u_info[krdc->index];

	} while (krdc != this);

	if (urdc->disk_queue[0] != '\0') {
		spcs_s_add(kstatus, RDC_EQALREADY, urdc->primary.intf,
		    urdc->primary.file, urdc->secondary.intf,
		    urdc->secondary.file);
		rc = RDC_EQALREADY;
		goto failed;
	}

	if (uparms->options & RDC_OPT_SECONDARY) { /* how'd we get here? */
		spcs_s_add(kstatus, RDC_EQWRONGMODE);
		rc = RDC_EQWRONGMODE;
		goto failed;
	}

	mutex_enter(&rdc_conf_lock);
	if (rdc_diskq_inuse(uparms->rdc_set, uparms->rdc_set->disk_queue)) {
		spcs_s_add(kstatus, RDC_EDISKQINUSE,
		    uparms->rdc_set->disk_queue);
		rc = RDC_EDISKQINUSE;
		mutex_exit(&rdc_conf_lock);
		goto failed;
	}
	mutex_exit(&rdc_conf_lock);

	rdc_group_enter(krdc);
	rc = _rdc_add_diskq(urdc->index, diskq);
	if (rc < 0 || rc == RDC_EQNOADD) {
		group->flags &= ~RDC_DISKQUE;
		group->flags |= RDC_MEMQUE;
		spcs_s_add(kstatus, RDC_EQNOADD, uparms->rdc_set->disk_queue);
		rc = RDC_EQNOADD;
	}
	rdc_group_exit(krdc);
failed:
	return (rc);
}

int
_rdc_init_diskq(rdc_k_info_t *krdc)
{
	rdc_group_t *group = krdc->group;
	disk_queue  *q = &group->diskq;

	rdc_init_diskq_header(group, &group->diskq.disk_hdr);
	SET_QNXTIO(q, QHEAD(q));

	if (rdc_stamp_diskq(krdc, 0, RDC_NOLOG) < 0)
		goto fail;

	return (0);
fail:
	return (-1);
}

/*
 * inititalize the disk queue. This is a destructive
 * operation that will not check for emptiness of the queue.
 */
int
rdc_init_diskq(rdc_config_t *uparms, spcs_s_info_t kstatus)
{
	int rc = 0;
	int index;
	rdc_k_info_t *krdc, *kp;
	rdc_u_info_t *urdc, *up;
	rdc_set_t    *uset;
	rdc_group_t  *group;
	disk_queue   *qp;

	uset = uparms->rdc_set;

	mutex_enter(&rdc_conf_lock);
	index = rdc_lookup_byname(uset);
	mutex_exit(&rdc_conf_lock);
	if (index < 0) {
		spcs_s_add(kstatus, RDC_EALREADY, uset->primary.file,
		    uset->secondary.file);
		rc = RDC_EALREADY;
		goto fail;
	}

	krdc = &rdc_k_info[index];
	urdc = &rdc_u_info[index];
	group = krdc->group;
	qp = &group->diskq;

	if (!IS_STATE(urdc, RDC_SYNCING) && !IS_STATE(urdc, RDC_LOGGING)) {
		spcs_s_add(kstatus, RDC_EQUEISREP, urdc->disk_queue);
		rc = RDC_EQUEISREP;
		goto fail;
	}

	/*
	 * a couple of big "ifs" here. in the first implementation
	 * neither of these will be possible. This will come into
	 * play when we persist the queue across reboots
	 */
	if (!(uparms->options & RDC_OPT_FORCE_QINIT)) {
		if (!QEMPTY(qp)) {
			if (group->rdc_writer) {
				spcs_s_add(kstatus, RDC_EQFLUSHING,
				    urdc->disk_queue);
				rc = RDC_EQFLUSHING;
			} else {
				spcs_s_add(kstatus, RDC_EQNOTEMPTY,
				    urdc->disk_queue);
				rc = RDC_EQNOTEMPTY;
			}
			goto fail;
		}
	}

	mutex_enter(QLOCK(qp));
	if (_rdc_init_diskq(krdc) < 0) {
		mutex_exit(QLOCK(qp));
		goto fail;
	}
	rdc_dump_iohdrs(qp);

	rdc_group_enter(krdc);

	rdc_clr_flags(urdc, RDC_QUEUING);
	for (kp = krdc->group_next; kp != krdc; kp = kp->group_next) {
		up = &rdc_u_info[kp->index];
		rdc_clr_flags(up, RDC_QUEUING);
	}
	rdc_group_exit(krdc);

	mutex_exit(QLOCK(qp));

	return (0);
fail:
	/* generic queue failure */
	if (!rc) {
		spcs_s_add(kstatus, RDC_EQINITFAIL, urdc->disk_queue);
		rc = RDC_EQINITFAIL;
	}

	return (rc);
}

int
_rdc_kill_diskq(rdc_u_info_t *urdc)
{
	rdc_k_info_t *krdc = &rdc_k_info[urdc->index];
	rdc_group_t *group = krdc->group;
	disk_queue *q = &group->diskq;
	rdc_u_info_t *up;
	rdc_k_info_t *p;

	group->flags |= RDC_DISKQ_KILL;
#ifdef DEBUG
	cmn_err(CE_NOTE, "!disabling disk queue %s", urdc->disk_queue);
#endif

	mutex_enter(QLOCK(q));
	rdc_init_diskq_header(group, &q->disk_hdr);
	rdc_dump_iohdrs(q);

	/*
	 * nsc_close the queue and zero out the queue name
	 */
	rdc_wait_qbusy(q);
	rdc_close_diskq(group);
	mutex_exit(QLOCK(q));
	SET_QSIZE(q, 0);
	rdc_clr_flags(urdc, RDC_DISKQ_FAILED);
	bzero(urdc->disk_queue, NSC_MAXPATH);
	for (p = krdc->group_next; p != krdc; p = p->group_next) {
		up = &rdc_u_info[p->index];
		rdc_clr_flags(up, RDC_DISKQ_FAILED);
		bzero(up->disk_queue, NSC_MAXPATH);
	}

#ifdef DEBUG
	cmn_err(CE_NOTE, "!_rdc_kill_diskq: enabling memory queue");
#endif
	group->flags &= ~(RDC_DISKQUE|RDC_DISKQ_KILL);
	group->flags |= RDC_MEMQUE;
	return (0);
}

/*
 * remove this diskq regardless of whether it is draining or not
 * stops the flusher by invalidating the qdata (ie, instant empty)
 * remove the disk qeueue from the group, leaving the group with a memory
 * queue.
 */
int
rdc_kill_diskq(rdc_config_t *uparms, spcs_s_info_t kstatus)
{
	int rc;
	int index;
	rdc_u_info_t *urdc;
	rdc_k_info_t *krdc;
	rdc_set_t *rdc_set = uparms->rdc_set;

	mutex_enter(&rdc_conf_lock);
	index = rdc_lookup_byname(uparms->rdc_set);
	mutex_exit(&rdc_conf_lock);

	if (index < 0) {
		spcs_s_add(kstatus, RDC_EALREADY, rdc_set->primary.file,
		    rdc_set->secondary.file);
		rc = RDC_EALREADY;
		goto failed;
	}

	urdc = &rdc_u_info[index];
	krdc = &rdc_k_info[index];

	if (!RDC_IS_DISKQ(krdc->group)) {
		spcs_s_add(kstatus, RDC_EQNOQUEUE, rdc_set->primary.intf,
		    rdc_set->primary.file, rdc_set->secondary.intf,
		    rdc_set->secondary.file);
		rc = RDC_EQNOQUEUE;
		goto failed;
	}

/*
 *	if (!IS_STATE(urdc, RDC_LOGGING)) {
 *		spcs_s_add(kstatus, RDC_EQNOTLOGGING,
 *		    uparms->rdc_set->disk_queue);
 *		rc = RDC_EQNOTLOGGING;
 *		goto failed;
 *	}
 */
	rdc_unintercept_diskq(krdc->group); /* stop protecting queue */
	rdc_group_enter(krdc); /* to prevent further flushing */
	rc = _rdc_kill_diskq(urdc);
	rdc_group_exit(krdc);

failed:
	return (rc);
}

/*
 * remove a diskq from a group.
 * removal of a diskq from a set, or rather
 * a set from a queue, is done by reconfigging out
 * of the group. This removes the diskq from a whole
 * group and replaces it with a memory based queue
 */
#define	NUM_RETRIES	15	/* Number of retries to wait if no progress */
int
rdc_rem_diskq(rdc_config_t *uparms, spcs_s_info_t kstatus)
{
	int index;
	rdc_u_info_t *urdc;
	rdc_k_info_t *krdc;
	rdc_k_info_t *this;
	volatile rdc_group_t *group;
	volatile disk_queue *diskq;
	int threads, counter;
	long blocks;

	mutex_enter(&rdc_conf_lock);
	index = rdc_lookup_byname(uparms->rdc_set);
	mutex_exit(&rdc_conf_lock);
	if (index < 0) {
		spcs_s_add(kstatus, RDC_EALREADY, uparms->rdc_set->primary.file,
		    uparms->rdc_set->secondary.file);
		return (RDC_EALREADY);
	}

	urdc = &rdc_u_info[index];
	this = &rdc_k_info[index];
	krdc = &rdc_k_info[index];

	do {
		if (!IS_STATE(urdc, RDC_LOGGING)) {
			spcs_s_add(kstatus, RDC_EQNOTLOGGING,
			    urdc->disk_queue);
			return (RDC_EQNOTLOGGING);
		}
		krdc = krdc->group_next;
		urdc = &rdc_u_info[krdc->index];

	} while (krdc != this);

	/*
	 * If there is no group or diskq configured, we can leave now
	 */
	if (!(group = krdc->group) || !(diskq = &group->diskq))
		return (0);


	/*
	 * Wait if not QEMPTY or threads still active
	 */
	counter = 0;
	while (!QEMPTY(diskq) || group->rdc_thrnum) {

		/*
		 * Capture counters to determine if progress is being made
		 */
		blocks = QBLOCKS(diskq);
		threads = group->rdc_thrnum;

		/*
		 * Wait
		 */
		delay(HZ);

		/*
		 * Has the group or disk queue gone away while delayed?
		 */
		if (!(group = krdc->group) || !(diskq = &group->diskq))
			return (0);

		/*
		 * Are we still seeing progress?
		 */
		if (blocks == QBLOCKS(diskq) && threads == group->rdc_thrnum) {
			/*
			 * No progress see, decrement retry counter
			 */
			if (counter++ > NUM_RETRIES) {
				/*
				 * No progress seen, increment retry counter
				 */
				int rc = group->rdc_thrnum ?
				    RDC_EQFLUSHING : RDC_EQNOTEMPTY;
				spcs_s_add(kstatus, rc, urdc->disk_queue);
				return (rc);
			}
		} else {
			/*
			 * Reset counter, as we've made progress
			 */
			counter = 0;
		}
	}

	return (0);
}
