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
 * Copyright (c) 1992, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * Routines for writing audit records.
 */

#include <sys/door.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/statvfs.h>	/* for statfs */
#include <sys/vnode.h>
#include <sys/file.h>
#include <sys/vfs.h>
#include <sys/user.h>
#include <sys/uio.h>
#include <sys/reboot.h>
#include <sys/kmem.h>		/* for KM_SLEEP */
#include <sys/resource.h>	/* for RLIM_INFINITY */
#include <sys/cmn_err.h>	/* panic */
#include <sys/systm.h>
#include <sys/debug.h>
#include <sys/sysmacros.h>
#include <sys/syscall.h>
#include <sys/zone.h>

#include <c2/audit.h>
#include <c2/audit_kernel.h>
#include <c2/audit_record.h>
#include <c2/audit_kevents.h>
#include <c2/audit_door_infc.h>

static void	au_dequeue(au_kcontext_t *, au_buff_t *);
static void	audit_async_finish_backend(void *);
static int	audit_sync_block(au_kcontext_t *);
/*
 * each of these two tables are indexed by the values AU_DBUF_COMPLETE
 * through AU_DBUF_LAST; the content is the next state value.  The
 * first table determines the next state for a buffer which is not the
 * end of a record and the second table determines the state for a
 * buffer which is the end of a record.  The initial state is
 * AU_DBUF_COMPLETE.
 */
static int state_if_part[] = {
    AU_DBUF_FIRST, AU_DBUF_MIDDLE, AU_DBUF_MIDDLE, AU_DBUF_FIRST};
static int state_if_not_part[] = {
    AU_DBUF_COMPLETE, AU_DBUF_LAST, AU_DBUF_LAST, AU_DBUF_COMPLETE};
/*
 * Write to an audit descriptor.
 * Add the au_membuf to the descriptor chain and free the chain passed in.
 */
void
au_uwrite(token_t *m)
{
	au_write(&(u_ad), m);
}

void
au_write(caddr_t *d, token_t *m)
{
	if (d == NULL) {
		au_toss_token(m);
		return;
	}
	if (m == (token_t *)0) {
		printf("au_write: null token\n");
		return;
	}

	if (*d == NULL)
		*d = (caddr_t)m;
	else
		(void) au_append_rec((au_buff_t *)*d, m, AU_PACK);
}

/*
 * Close an audit descriptor.
 * Use the second parameter to indicate if it should be written or not.
 */
void
au_close(au_kcontext_t *kctx, caddr_t *d, int flag, au_event_t e_type,
    au_emod_t e_mod, timestruc_t *e_time)
{
	token_t *dchain;	/* au_membuf chain which is the tokens */
	t_audit_data_t *tad = U2A(u);

	ASSERT(tad != NULL);
	ASSERT(d != NULL);
	ASSERT(kctx != NULL);

	if ((dchain = (token_t *)*d) == (token_t *)NULL)
		return;

	*d = NULL;

	/*
	 * If async then defer; or if requested, defer the closing/queueing to
	 * syscall end, unless no syscall is active or the syscall is _exit.
	 */
	if ((flag & AU_DONTBLOCK) || ((flag & AU_DEFER) &&
	    (tad->tad_scid != 0) && (tad->tad_scid != SYS_exit))) {
		au_close_defer(dchain, flag, e_type, e_mod, e_time);
		return;
	}
	au_close_time(kctx, dchain, flag, e_type, e_mod, e_time);
}

/*
 * Defer closing/queueing of an audit descriptor. For async events, queue
 * via softcall. Otherwise, defer by queueing the record onto the tad; at
 * syscall end time it will be pulled off.
 */
void
au_close_defer(token_t *dchain, int flag, au_event_t e_type, au_emod_t e_mod,
    timestruc_t *e_time)
{
	au_defer_info_t	*attr;
	t_audit_data_t *tad = U2A(u);

	ASSERT(tad != NULL);

	/* If not to be written, toss the record. */
	if ((flag & AU_OK) == 0) {
		au_toss_token(dchain);
		return;
	}

	attr = kmem_alloc(sizeof (au_defer_info_t), KM_NOSLEEP);
	/* If no mem available, failing silently is the best recourse */
	if (attr == NULL) {
		au_toss_token(dchain);
		return;
	}

	attr->audi_next = NULL;
	attr->audi_ad = dchain;
	attr->audi_e_type = e_type;
	attr->audi_e_mod = e_mod;
	attr->audi_flag = flag;
	if (e_time != NULL)
		attr->audi_atime = *e_time;
	else
		gethrestime(&attr->audi_atime);

	/*
	 * All async events must be queued via softcall to avoid possible
	 * sleeping in high interrupt context. softcall will ensure it's
	 * done on a dedicated software-level interrupt thread.
	 */
	if (flag & AU_DONTBLOCK) {
		softcall(audit_async_finish_backend, attr);
		audit_async_done(NULL, 0);
		return;
	}

	/*
	 * If not an async event, defer by queuing onto the tad until
	 * syscall end. No locking is needed because the tad is per-thread.
	 */
	if (tad->tad_defer_head)
		tad->tad_defer_tail->audi_next = attr;
	else
		tad->tad_defer_head = attr;
	tad->tad_defer_tail = attr;
}


/*
 * Save the time in the event header. If time is not specified (i.e., pointer
 * is NULL), use the current time.  This code is fairly ugly since it needs
 * to support both 32- and 64-bit environments and can be called indirectly
 * from both au_close() (for kernel audit) and from audit() (userland audit).
 */
/*ARGSUSED*/
static void
au_save_time(adr_t *hadrp, timestruc_t *time, int size)
{
	struct {
		uint32_t sec;
		uint32_t usec;
	} tv;
	timestruc_t	now;

	if (time == NULL) {
		gethrestime(&now);
		time = &now;
	}

#ifdef _LP64
	if (size)
		adr_int64(hadrp, (int64_t *)time, 2);
	else
#endif
	{
		tv.sec = (uint32_t)time->tv_sec;
		tv.usec = (uint32_t)time->tv_nsec;
		adr_int32(hadrp, (int32_t *)&tv, 2);
	}
}


/*
 * Close an audit descriptor.
 * If time of event is specified, use it in the record, otherwise use the
 * current time.
 */
void
au_close_time(au_kcontext_t *kctx, token_t *dchain, int flag, au_event_t e_type,
    au_emod_t e_mod, timestruc_t *etime)
{
	token_t		*record;	/* au_membuf chain == the record */
	int		byte_count;
	token_t		*m;		/* for potential sequence token */
	adr_t		hadr;		/* handle for header token */
	adr_t		sadr;		/* handle for sequence token */
	size_t		zone_length;	/* length of zonename token */
	uint32_t	auditing;

	ASSERT(dchain != NULL);

	/* If not to be written, toss the record */
	if ((flag & AU_OK) == 0) {
		au_toss_token(dchain);
		return;
	}
	/* if auditing not enabled, then don't generate an audit record */
	ASSERT(U2A(u) != NULL);
	ASSERT(kctx != NULL);

	auditing = (U2A(u)->tad_audit == AUC_UNSET)
	    ? kctx->auk_auditstate
	    : U2A(u)->tad_audit;

	if (auditing & ~(AUC_AUDITING | AUC_INIT_AUDIT)) {
		/*
		 * at system boot, neither is set yet we want to generate
		 * an audit record.
		 */
		if (e_type != AUE_SYSTEMBOOT) {
			au_toss_token(dchain);
			return;
		}
	}

	/* Count up the bytes used in the record. */
	byte_count = au_token_size(dchain);

	/*
	 * add in size of header token (always present).
	 */
	byte_count += sizeof (char) + sizeof (int32_t) +
	    sizeof (char) + 2 * sizeof (short) + sizeof (timestruc_t);

	if (kctx->auk_hostaddr_valid)
		byte_count += sizeof (int32_t) +
		    kctx->auk_info.ai_termid.at_type;

	/*
	 * add in size of zonename token (zero if !AUDIT_ZONENAME)
	 */
	if (kctx->auk_policy & AUDIT_ZONENAME) {
		zone_length = au_zonename_length(NULL);
		byte_count += zone_length;
	} else {
		zone_length = 0;
	}
	/* add in size of (optional) trailer token */
	if (kctx->auk_policy & AUDIT_TRAIL)
		byte_count += 7;

	/* add in size of (optional) sequence token */
	if (kctx->auk_policy & AUDIT_SEQ)
		byte_count += 5;

	/* build the header */
	if (kctx->auk_hostaddr_valid)
		record = au_to_header_ex(byte_count, e_type, e_mod);
	else
		record = au_to_header(byte_count, e_type, e_mod);

	/*
	 * If timestamp was specified, save it in header now. Otherwise,
	 * save reference to header so we can update time/data later
	 * and artificially adjust pointer to the time/date field of header.
	 */
	adr_start(&hadr, memtod(record, char *));
	hadr.adr_now += sizeof (char) + sizeof (int32_t) +
	    sizeof (char) + 2 * sizeof (short);
	if (kctx->auk_hostaddr_valid)
		hadr.adr_now += sizeof (int32_t) +
		    kctx->auk_info.ai_termid.at_type;
	if (etime != NULL) {
		au_save_time(&hadr, etime, 1);
		hadr.adr_now = (char *)NULL;
	}

	/* append body of audit record */
	(void) au_append_rec(record, dchain, AU_PACK);

	/* add (optional) zonename token */
	if (zone_length > 0) {
		m = au_to_zonename(zone_length, NULL);
		(void) au_append_rec(record, m, AU_PACK);
	}

	/* Add an (optional) sequence token. NULL offset if none */
	if (kctx->auk_policy & AUDIT_SEQ) {
		/* get the sequence token */
		m = au_to_seq();

		/* link to audit record (i.e. don't pack the data) */
		(void) au_append_rec(record, m, AU_LINK);

		/*
		 * advance to count field of sequence token by skipping
		 * the token type byte.
		 */
		adr_start(&sadr, memtod(m, char *));
		sadr.adr_now += 1;
	} else {
		sadr.adr_now = NULL;
	}
	/* add (optional) trailer token */
	if (kctx->auk_policy & AUDIT_TRAIL) {
		(void) au_append_rec(record, au_to_trailer(byte_count),
		    AU_PACK);
	}

	/*
	 * 1 - use 64 bit version of audit tokens for 64 bit kernels.
	 * 0 - use 32 bit version of audit tokens for 32 bit kernels.
	 */
#ifdef _LP64
	au_enqueue(kctx, record, &hadr, &sadr, 1, flag & AU_DONTBLOCK);
#else
	au_enqueue(kctx, record, &hadr, &sadr, 0, flag & AU_DONTBLOCK);
#endif
	AS_INC(as_totalsize, byte_count, kctx);
}

/*ARGSUSED*/
void
au_enqueue(au_kcontext_t *kctx, au_buff_t *m, adr_t *hadrp, adr_t *sadrp,
    int size, int dontblock)
{
	if (kctx == NULL)
		return;

	mutex_enter(&(kctx->auk_queue.lock));

	if (!dontblock && (kctx->auk_queue.cnt >= kctx->auk_queue.hiwater) &&
	    audit_sync_block(kctx)) {
		mutex_exit(&(kctx->auk_queue.lock));
		au_free_rec(m);
		return;
	}

	/* Fill in date and time if needed */
	if (hadrp->adr_now) {
		au_save_time(hadrp, NULL, size);
	}

	/* address will be non-zero only if AUDIT_SEQ set */
	if (sadrp->adr_now) {
		kctx->auk_sequence++;
		adr_int32(sadrp, (int32_t *)&(kctx->auk_sequence), 1);
	}

	if (kctx->auk_queue.head)
		kctx->auk_queue.tail->next_rec = m;
	else
		kctx->auk_queue.head = m;

	kctx->auk_queue.tail = m;

	if (++(kctx->auk_queue.cnt) >
	    kctx->auk_queue.lowater && kctx->auk_queue.rd_block)
		cv_broadcast(&(kctx->auk_queue.read_cv));

	mutex_exit(&(kctx->auk_queue.lock));

	/* count # audit records put onto kernel audit queue */
	AS_INC(as_enqueue, 1, kctx);
}

/*
 * Dequeue and free buffers upto and including "freeto"
 * Keeps the queue lock long but acquires it only once when doing
 * bulk dequeueing.
 */
static void
au_dequeue(au_kcontext_t *kctx, au_buff_t *freeto)
{
	au_buff_t *m, *l, *lastl;
	int n = 0;

	ASSERT(kctx != NULL);

	mutex_enter(&(kctx->auk_queue.lock));

	ASSERT(kctx->auk_queue.head != NULL);
	ASSERT(freeto != NULL);

	l = m = kctx->auk_queue.head;

	do {
		n++;
		lastl = l;
		l = l->next_rec;
	} while (l != NULL && freeto != lastl);

	kctx->auk_queue.cnt -= n;
	lastl->next_rec = NULL;
	kctx->auk_queue.head = l;

	/* Freeto must exist in the list */
	ASSERT(freeto == lastl);

	if (kctx->auk_queue.cnt <= kctx->auk_queue.lowater &&
	    kctx->auk_queue.wt_block)
		cv_broadcast(&(kctx->auk_queue.write_cv));

	mutex_exit(&(kctx->auk_queue.lock));

	while (m) {
		l = m->next_rec;
		au_free_rec(m);
		m = l;
	}
	AS_INC(as_written, n, kctx);
}

/*
 * audit_sync_block()
 * If we've reached the high water mark, we look at the policy to see
 * if we sleep or we should drop the audit record.
 * This function is called with the auk_queue.lock held and the check
 * performed one time already as an optimization.  Caller should unlock.
 * Returns 1 if the caller needs to free the record.
 */
static int
audit_sync_block(au_kcontext_t *kctx)
{
	ASSERT(MUTEX_HELD(&(kctx->auk_queue.lock)));
	/*
	 * Loop while we are at the high watermark.
	 */
	do {
		if (((U2A(u)->tad_audit != AUC_UNSET)
		    ? (U2A(u)->tad_audit != AUC_AUDITING)
		    : (kctx->auk_auditstate != AUC_AUDITING)) ||
		    (kctx->auk_policy & AUDIT_CNT)) {

			/* just count # of dropped audit records */
			AS_INC(as_dropped, 1, kctx);

			return (1);
		}

		/* kick reader awake if its asleep */
		if (kctx->auk_queue.rd_block &&
		    kctx->auk_queue.cnt > kctx->auk_queue.lowater)
			cv_broadcast(&(kctx->auk_queue.read_cv));

		/* keep count of # times blocked */
		AS_INC(as_wblocked, 1, kctx);

		/* sleep now, until woken by reader */
		kctx->auk_queue.wt_block++;
		cv_wait(&(kctx->auk_queue.write_cv), &(kctx->auk_queue.lock));
		kctx->auk_queue.wt_block--;
	} while (kctx->auk_queue.cnt >= kctx->auk_queue.hiwater);

	return (0);
}

/*
 * audit_async_block()
 * if we've reached the high water mark, we look at the ahlt policy to see
 * if we reboot we should drop the audit record.
 * Returns 1 if blocked.
 */
static int
audit_async_block(au_kcontext_t *kctx, caddr_t *rpp)
{
	ASSERT(kctx != NULL);

	mutex_enter(&(kctx->auk_queue.lock));
	/* see if we've reached high water mark */
	if (kctx->auk_queue.cnt >= kctx->auk_queue.hiwater) {
		mutex_exit(&(kctx->auk_queue.lock));

		audit_async_drop(rpp, AU_BACKEND);
		return (1);
	}
	mutex_exit(&(kctx->auk_queue.lock));
	return (0);
}

/*
 * au_door_upcall.  auditdoor() may change vp without notice, so
 * some locking seems in order.
 *
 */
#define	AGAIN_TICKS	10

static int
au_door_upcall(au_kcontext_t *kctx, au_dbuf_t *aubuf)
{
	int		rc;
	door_arg_t	darg;
	int		retry = 1;
	int		ticks_to_wait;

	darg.data_ptr = (char *)aubuf;
	darg.data_size = AU_DBUF_HEADER + aubuf->aub_size;

	darg.desc_ptr = NULL;
	darg.desc_num = 0;

	while (retry == 1) {
		/* non-zero means return results expected */
		darg.rbuf = (char *)aubuf;
		darg.rsize = darg.data_size;

		retry = 0;
		mutex_enter(&(kctx->auk_svc_lock));
		rc = door_upcall(kctx->auk_current_vp, &darg, NULL,
		    SIZE_MAX, 0);
		if (rc != 0) {
			mutex_exit(&(kctx->auk_svc_lock));
			if (rc == EAGAIN)
				ticks_to_wait = AGAIN_TICKS;
			else
				return (rc);

			mutex_enter(&(kctx->auk_eagain_mutex));
			(void) cv_reltimedwait(&(kctx->auk_eagain_cv),
			    &(kctx->auk_eagain_mutex), ticks_to_wait,
			    TR_CLOCK_TICK);
			mutex_exit(&(kctx->auk_eagain_mutex));

			retry = 1;
		} else
			mutex_exit(&(kctx->auk_svc_lock));	/* no retry */
	}	/* end while (retry == 1) */
	if (darg.rbuf == NULL)
		return (-1);

	/* return code from door server */
	return (*(int *)darg.rbuf);
}

/*
 * Write an audit control message to the door handle.  The message
 * structure depends on message_code and at present the only control
 * message defined is for a policy change.  These are infrequent,
 * so no memory is held for control messages.
 */
int
au_doormsg(au_kcontext_t *kctx, uint32_t message_code, void *message)
{
	int		rc;
	au_dbuf_t	*buf;
	size_t		alloc_size;

	switch (message_code) {
	case AU_DBUF_POLICY:
		alloc_size = AU_DBUF_HEADER + sizeof (uint32_t);
		buf = kmem_alloc(alloc_size, KM_SLEEP);
		buf->aub_size = sizeof (uint32_t);
		*(uint32_t *)buf->aub_buf = *(uint32_t *)message;
		break;
	case AU_DBUF_SHUTDOWN:
		alloc_size = AU_DBUF_HEADER;
		buf = kmem_alloc(alloc_size, KM_SLEEP);
		buf->aub_size = 0;
		break;
	default:
		return (1);
	}

	buf->aub_type = AU_DBUF_NOTIFY | message_code;
	rc = au_door_upcall(kctx, buf);
	kmem_free(buf, alloc_size);

	return (rc);
}

/*
 * Write audit information to the door handle.  au_doorio is called with
 * one or more complete audit records on the queue and outputs those
 * records in buffers of up to auk_queue.buflen in size.
 */
int
au_doorio(au_kcontext_t *kctx)
{
	off_t		off;	/* space used in buffer */
	ssize_t		used;	/* space used in au_membuf */
	token_t		*cAR;	/* current AR being processed */
	token_t		*cMB;	/* current au_membuf being processed */
	token_t		*sp;	/* last AR processed */
	char		*bp;	/* start of free space in staging buffer */
	unsigned char	*cp;	/* ptr to data to be moved */
	int		error = 0;  /* return from door upcall */

	/*
	 * size (data left in au_membuf - space in buffer)
	 */
	ssize_t		sz;
	ssize_t		len;	/* len of data to move, size of AR */
	ssize_t		curr_sz = 0;	/* amount of data written during now */
	/*
	 * partial_state is AU_DBUF_COMPLETE...LAST; see audit_door_infc.h
	 */
	int		part    = 0;	/* partial audit record written */
	int		partial_state = AU_DBUF_COMPLETE;
	/*
	 * Has the write buffer changed length due to a auditctl(2)?
	 * Initial allocation is from audit_start.c/audit_init()
	 */
	if (kctx->auk_queue.bufsz != kctx->auk_queue.buflen) {
		size_t new_sz = kctx->auk_queue.bufsz;

		kmem_free(kctx->auk_dbuffer, AU_DBUF_HEADER +
		    kctx->auk_queue.buflen);

		kctx->auk_dbuffer = kmem_alloc(AU_DBUF_HEADER + new_sz,
		    KM_SLEEP);

		/* omit the 64 bit header */
		kctx->auk_queue.buflen = new_sz;
	}
	if (!kctx->auk_queue.head)
		goto nodata;

	sp   = NULL;	/* no record copied */
	off  = 0;	/* no space used in buffer */
	used = 0;	/* no data processed in au_membuf */
	cAR  = kctx->auk_queue.head;	/* start at head of queue */
	cMB  = cAR;	/* start with first au_membuf of record */

	/* start at beginning of buffer */
	bp   = &(kctx->auk_dbuffer->aub_buf[0]);

	while (cMB) {
		part = 1;	/* indicate audit record being processed */

		cp  = memtod(cMB, unsigned char *); /* buffer ptr */

		sz  = (ssize_t)cMB->len - used;	/* data left in au_membuf */
		/* len to move */
		len = (ssize_t)MIN(sz, kctx->auk_queue.buflen - off);

		/* move the data */
		bcopy(cp + used, bp + off, len);
		used += len; /* update used au_membuf */
		off  += len; /* update offset into buffer */

		if (used >= (ssize_t)cMB->len) {
			/* advance to next au_membuf */
			used = 0;
			cMB  = cMB->next_buf;
		}
		if (cMB == NULL) {
			/* advance to next audit record */
			sp   = cAR;
			cAR  = cAR->next_rec;
			cMB  = cAR;
			part = 0;	/* have a complete record */
		}
		error = 0;
		if ((kctx->auk_queue.buflen == off) || (part == 0)) {
			if (part)
				partial_state = state_if_part[partial_state];
			else
				partial_state =
				    state_if_not_part[partial_state];

			kctx->auk_dbuffer->aub_type = partial_state;
			kctx->auk_dbuffer->aub_size = off;
			error = au_door_upcall(kctx, kctx->auk_dbuffer);
			if (error != 0)
				goto nodata;
			/*
			 * if we've successfully written an audit record,
			 * free records up to last full record copied
			 */
			if (sp)
				au_dequeue(kctx, sp);

				/* Update size */
			curr_sz += off;

				/* reset auk_dbuffer pointers */
			sp = NULL;
			off  = 0;
		}
	}	/* while(cMB) */
nodata:
	return (error);
}

/*
 * Clean up thread audit state to clear out asynchronous audit record
 * generation error recovery processing. Note that this is done on a
 * per-thread basis and thus does not need any locking.
 */
void
audit_async_done(caddr_t *rpp, int flags)
{
	t_audit_data_t *tad = U2A(u);

	/* clean up the tad unless called from softcall backend */
	if (!(flags & AU_BACKEND)) {
		ASSERT(tad != NULL);
		ASSERT(tad->tad_ctrl & TAD_ERRJMP);

		tad->tad_ctrl &= ~TAD_ERRJMP;
		tad->tad_errjmp = NULL;
	}

	/* clean out partial audit record */
	if ((rpp != NULL) && (*rpp != NULL)) {
		au_toss_token((au_buff_t *)*rpp);
		*rpp = NULL;
	}
}

/*
 * implement the audit policy for asynchronous events generated within
 * the kernel.
 * XXX might need locks around audit_policy check.
 */
void
audit_async_drop(caddr_t *rpp, int flags)
{
	au_kcontext_t	*kctx;

	/* could not generate audit record, clean up */
	audit_async_done((caddr_t *)rpp, flags);

	kctx = GET_KCTX_GZ;

	/* just drop the record and return */
	if (((audit_policy & AUDIT_AHLT) == 0) ||
	    (kctx->auk_auditstate == AUC_INIT_AUDIT)) {
		/* just count # of dropped audit records */
		AS_INC(as_dropped, 1, kctx);
		return;
	}

	/*
	 * There can be a lot of data in the audit queue. We
	 * will first sync the file systems then attempt to
	 * shutdown the kernel so that a memory dump is
	 * performed.
	 */
	sync();
	sync();

	/*
	 * now shut down. What a cruel world it has been
	 */
	panic("non-attributable halt. should dump core");
	/* No return */
}

int
audit_async_start(label_t *jb, au_event_t event, int sorf)
{
	t_audit_data_t *tad = U2A(u);
	au_state_t estate;
	int success = 0, failure = 0;
	au_kcontext_t	*kctx = GET_KCTX_GZ;

	/* if audit state off, then no audit record generation */
	if ((kctx->auk_auditstate != AUC_AUDITING) &&
	    (kctx->auk_auditstate != AUC_INIT_AUDIT))
		return (1);

	/*
	 * preselect asynchronous event
	 * XXX should we check for out-of-range???
	 */
	estate = kctx->auk_ets[event];

	if (sorf & AUM_SUCC)
		success = kctx->auk_info.ai_namask.as_success & estate;
	if (sorf & AUM_FAIL)
		failure = kctx->auk_info.ai_namask.as_failure & estate;

	if ((success | failure) == 0)
		return (1);

	ASSERT(tad->tad_errjmp == NULL);
	tad->tad_errjmp = (void *)jb;
	tad->tad_ctrl |= TAD_ERRJMP;

	return (0);
}

/*
 * Complete auditing of an async event. The AU_DONTBLOCK flag to au_close will
 * result in the backend routine being invoked from softcall, so all the real
 * work can be done in a safe context.
 */
void
audit_async_finish(caddr_t *ad, au_event_t aid, au_emod_t amod,
    timestruc_t *e_time)
{
	au_kcontext_t	*kctx;

	kctx  = GET_KCTX_GZ;

	au_close(kctx, ad, AU_DONTBLOCK | AU_OK, aid, PAD_NONATTR|amod, e_time);
}

/*
 * Backend routine to complete an async audit. Invoked from softcall.
 * (Note: the blocking and the queuing below both involve locking which can't
 * be done safely in high interrupt context due to the chance of sleeping on
 * the corresponding adaptive mutex. Hence the softcall.)
 */
static void
audit_async_finish_backend(void *addr)
{
	au_kcontext_t	*kctx;
	au_defer_info_t	*attr = (au_defer_info_t *)addr;

	if (attr == NULL)
		return;		/* won't happen unless softcall is broken */

	kctx  = GET_KCTX_GZ;

	if (audit_async_block(kctx, (caddr_t *)&attr->audi_ad)) {
		kmem_free(attr, sizeof (au_defer_info_t));
		return;
	}

	/*
	 * Call au_close_time to complete the audit with the saved values.
	 *
	 * For the exit-prom event, use the current time instead of the
	 * saved time as a better approximation. (Because the time saved via
	 * gethrestime during prom-exit handling would not yet be caught up
	 * after the system was idled in the debugger for a period of time.)
	 */
	if (attr->audi_e_type == AUE_EXITPROM) {
		au_close_time(kctx, (token_t *)attr->audi_ad, attr->audi_flag,
		    attr->audi_e_type, attr->audi_e_mod, NULL);
	} else {
		au_close_time(kctx, (token_t *)attr->audi_ad, attr->audi_flag,
		    attr->audi_e_type, attr->audi_e_mod, &attr->audi_atime);
	}

	AS_INC(as_generated, 1, kctx);
	AS_INC(as_nonattrib, 1, kctx);

	kmem_free(attr, sizeof (au_defer_info_t));
}
