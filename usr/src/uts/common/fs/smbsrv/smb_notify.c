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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2020 Tintri by DDN, Inc.  All rights reserved.
 * Copyright 2020-2023 RackTop Systems, Inc.
 */

/*
 * File Change Notification (FCN)
 * Common parts shared by SMB1 & SMB2
 */

/*
 * This command notifies the client when the specified directory
 * has changed, and optionally returns the names of files and
 * directories that changed, and how they changed.  The caller
 * specifies a "Completion Filter" to select which kinds of
 * changes they want to know about.
 *
 * When a change that's in the CompletionFilter is made to the directory,
 * the command completes.  The names of the files that have changed since
 * the last time the command was issued are returned to the client.
 * If too many files have changed since the last time the command was
 * issued, then zero bytes are returned and an alternate status code
 * is returned in the Status field of the response.
 *
 * The CompletionFilter is a mask created as the sum of any of the
 * following flags:
 *
 * FILE_NOTIFY_CHANGE_FILE_NAME        0x00000001
 * FILE_NOTIFY_CHANGE_DIR_NAME         0x00000002
 * FILE_NOTIFY_CHANGE_NAME             0x00000003
 * FILE_NOTIFY_CHANGE_ATTRIBUTES       0x00000004
 * FILE_NOTIFY_CHANGE_SIZE             0x00000008
 * FILE_NOTIFY_CHANGE_LAST_WRITE       0x00000010
 * FILE_NOTIFY_CHANGE_LAST_ACCESS      0x00000020
 * FILE_NOTIFY_CHANGE_CREATION         0x00000040
 * FILE_NOTIFY_CHANGE_EA               0x00000080
 * FILE_NOTIFY_CHANGE_SECURITY         0x00000100
 * FILE_NOTIFY_CHANGE_STREAM_NAME      0x00000200
 * FILE_NOTIFY_CHANGE_STREAM_SIZE      0x00000400
 * FILE_NOTIFY_CHANGE_STREAM_WRITE     0x00000800
 *
 *
 * The response contains FILE_NOTIFY_INFORMATION structures, as defined
 * below.  The NextEntryOffset field of the structure specifies the offset,
 * in bytes, from the start of the current entry to the next entry in the
 * list.  If this is the last entry in the list, this field is zero.  Each
 * entry in the list must be longword aligned, so NextEntryOffset must be a
 * multiple of four.
 *
 * typedef struct {
 *     ULONG NextEntryOffset;
 *     ULONG Action;
 *     ULONG FileNameLength;
 *     WCHAR FileName[1];
 * } FILE_NOTIFY_INFORMATION;
 *
 * Where Action describes what happened to the file named FileName:
 *
 * FILE_ACTION_ADDED            0x00000001
 * FILE_ACTION_REMOVED          0x00000002
 * FILE_ACTION_MODIFIED         0x00000003
 * FILE_ACTION_RENAMED_OLD_NAME 0x00000004
 * FILE_ACTION_RENAMED_NEW_NAME 0x00000005
 * FILE_ACTION_ADDED_STREAM     0x00000006
 * FILE_ACTION_REMOVED_STREAM   0x00000007
 * FILE_ACTION_MODIFIED_STREAM  0x00000008
 *
 * The internal interface between SMB1 and/or SMB2 protocol handlers
 * and this module has some sophistication to allow for:
 * (1) code sharing between SMB1 and SMB2(+)
 * (2) efficient handling of non-blocking scenarios
 * (3) long blocking calls without tying up a thread
 *
 * The interface has three calls (like a three act play)
 *
 * smb_notify_act1:
 *	Validate parameters, setup ofile buffer.
 *	If data already available, return it, all done.
 *	(In the "all done" case, skip act2 & act3.)
 *	If no data available, return a special error
 *	("STATUS_PENDING") to tell the caller they must
 *	proceed with calls to act2 & act3.
 *
 * smb_notify_act2:
 *	Arrange wakeup after event delivery or cancellation.
 *	Return leaving the SR with no worker thread.
 *
 * smb_notify_act3:
 *	New taskq work thread runs this after the wakeup
 *	or cancellation arranged in act2 happens.  This
 *	returns the notification data and retires the SR.
 *
 * In the SMB2 notify handler, we call act1 during the initial
 * synchronous handling of the request.  If that returns anything
 * other than STATUS_PENDING, that request is fully complete.
 * If act1 returns STATUS_PENDING, SMB2 calls act2 as it's
 * "go async" handler, which arranges to call act3 later.
 *
 * In the SMB1 notify handler there is not separate sync. & async
 * handler so act1 and (if necessary) act2 are both called during
 * the initial handling of the request.
 *
 * About notify event buffering:
 *
 * An important (and poorly documented) feature of SMB notify is
 * that once a notify call has happened on a given directory handle,
 * the system CONTINUES to post events to the notify event buffer
 * for the handle, even when SMB notify calls are NOT running.
 * When the client next comes back with a notify call, we return
 * any events that were posted while they were "away".  This is
 * how clients track directory changes without missing events.
 *
 * About simultaneous notify calls:
 *
 * Note that SMB "notify" calls are destructive to events, much like
 * reading data from a pipe.  It therefore makes little sense to
 * allow multiple simultaneous callers.  However, we permit it
 * (like Windows does) as follows:  When multiple notify calls
 * are waiting for events, the next event wakes them all, and
 * only the last one out clears the event buffer.  They all get
 * whatever events are pending at the time they woke up.
 *
 * About NT_STATUS_NOTIFY_ENUM_DIR
 *
 * One more caution about NT_STATUS_NOTIFY_ENUM_DIR:  Some clients
 * are stupid about re-reading the directory almost continuously when
 * there are changes happening in the directory.  We want to bound
 * the rate of such directory re-reading, so before returning an
 * NT_STATUS_NOTIFY_ENUM_DIR, we delay just a little.  The length
 * of the delay can be adjusted via smb_notify_enum_dir_delay,
 * though it's not expected that should need to be changed.
 */

#include <smbsrv/smb_kproto.h>
#include <sys/sdt.h>

/*
 * Length of the short delay we impose before returning
 * NT_STATUS_NOTIFY_ENUM_DIR (See above)
 */
int smb_notify_enum_dir_delay = 100; /* mSec. */

static uint32_t smb_notify_get_events(smb_request_t *);
static void smb_notify_cancel(smb_request_t *);
static void smb_notify_wakeup(smb_request_t *);
static void smb_notify_dispatch2(smb_request_t *);
static void smb_notify_encode_action(smb_ofile_t *,
	uint32_t, const char *);


/*
 * smb_notify_act1()
 *
 * Check for events and consume, non-blocking.
 * Special return STATUS_PENDING means:
 * No events; caller must call "act2" next.
 *
 * See overall design notes, top of file.
 */
uint32_t
smb_notify_act1(smb_request_t *sr, uint32_t buflen, uint32_t filter)
{
	smb_ofile_t	*of;
	smb_node_t	*node;
	smb_notify_t	*nc;
	uint32_t	status;

	/*
	 * Validate parameters
	 */
	if ((of = sr->fid_ofile) == NULL)
		return (NT_STATUS_INVALID_HANDLE);
	nc = &of->f_notify;
	node = of->f_node;
	if (node == NULL || !smb_node_is_dir(node)) {
		/* Notify change is only valid on directories. */
		return (NT_STATUS_INVALID_PARAMETER);
	}

	if ((of->f_granted_access & FILE_LIST_DIRECTORY) == 0)
		return (NT_STATUS_ACCESS_DENIED);

	mutex_enter(&of->f_mutex);

	/*
	 * It's possible this ofile has started closing, in which case
	 * we must not subscribe it for events etc.
	 */
	if (of->f_state != SMB_OFILE_STATE_OPEN) {
		mutex_exit(&of->f_mutex);
		return (NT_STATUS_FILE_CLOSED);
	}

	/*
	 * On the first FCN call with this ofile, subscribe to
	 * events on the node.  The corresponding unsubscribe
	 * happens in smb_ofile_delete().
	 */
	if (nc->nc_subscribed == B_FALSE) {
		nc->nc_subscribed = B_TRUE;
		smb_node_fcn_subscribe(node);
		/* In case this happened before we subscribed. */
		if (node->flags & NODE_FLAGS_DELETE_ON_CLOSE) {
			nc->nc_events |= FILE_NOTIFY_CHANGE_EV_DELETE;
		}
		/*
		 * Windows only lets you set these on the first call,
		 * so we may as well do the same.
		 */
		nc->nc_buffer.max_bytes = buflen;
		nc->nc_filter = filter;
	}
	/*
	 * If we already have events, consume them.
	 */
	sr->raw_data.max_bytes = buflen;
	if (nc->nc_events != 0) {
		status = smb_notify_get_events(sr);
	} else {
		/* Caller will come back for act2 */
		status = NT_STATUS_PENDING;
	}

	mutex_exit(&of->f_mutex);

	/*
	 * See: About NT_STATUS_NOTIFY_ENUM_DIR (above)
	 */
	if (status == NT_STATUS_NOTIFY_ENUM_DIR &&
	    smb_notify_enum_dir_delay > 0)
		delay(MSEC_TO_TICK(smb_notify_enum_dir_delay));

	return (status);
}

/*
 * smb_notify_act2()
 *
 * Prepare to wait for events after act1 found that none were pending.
 * Assume the wait may be for a very long time.  (hours, days...)
 * Special return STATUS_PENDING means the SR will later be
 * scheduled again on a new worker thread, and this thread
 * MUST NOT touch it any longer (return SDRC_SR_KEPT).
 *
 * See overall design notes, top of file.
 */
uint32_t
smb_notify_act2(smb_request_t *sr)
{
	smb_ofile_t	*of;
	smb_notify_t	*nc;
	uint32_t	status;

	/*
	 * Sanity checks.
	 */
	if ((of = sr->fid_ofile) == NULL)
		return (NT_STATUS_INVALID_HANDLE);
	nc = &of->f_notify;

	/*
	 * Prepare for a potentially long wait for events.
	 * Normally transition from ACTIVE to WAITING_FCN1.
	 */
	mutex_enter(&sr->sr_mutex);
	switch (sr->sr_state) {
	case SMB_REQ_STATE_ACTIVE:
		/*
		 * This sr has no worker thread until smb_notify_act3
		 * or smb_notify_cancel (later, via taskq_dispatch).
		 */
		sr->sr_state = SMB_REQ_STATE_WAITING_FCN1;
		sr->cancel_method = smb_notify_cancel;
		sr->sr_worker = NULL;
		status = NT_STATUS_PENDING;
		break;

	case SMB_REQ_STATE_CANCELLED:
		status = NT_STATUS_CANCELLED;
		break;
	default:
		status = NT_STATUS_INTERNAL_ERROR;
		break;
	}
	mutex_exit(&sr->sr_mutex);

	/*
	 * Arrange to get smb_notify_wakeup() calls,
	 * and check for any notify change events that
	 * may have arrived before we entered f_mutex
	 *
	 * Note that smb_notify_cancel may run after we drop
	 * the sr_mutex, so sr_state may change to cancelled.
	 * In that case, the smb_notify_wakeup does nothing.
	 * Note that smb_notify_wakeup is exempt from the
	 * "MUST NOT touch" (the SR) rule described above.
	 */
	if (status == NT_STATUS_PENDING) {
		mutex_enter(&of->f_mutex);
		list_insert_tail(&nc->nc_waiters, sr);
		if (nc->nc_events != 0) {
			smb_notify_wakeup(sr);
		}
		mutex_exit(&of->f_mutex);
	}

	/* Note: Never NT_STATUS_NOTIFY_ENUM_DIR here. */
	ASSERT(status != NT_STATUS_NOTIFY_ENUM_DIR);

	return (status);
}

/*
 * smb_notify_act3()
 *
 * This runs via the 2nd taskq_dispatch call, after we've either
 * seen a change notify event, or the request has been cancelled.
 * Complete it here.  This returns to SMB1 or SMB2 code to send
 * the response and free the request.
 *
 * See overall design notes, top of file.
 */
uint32_t
smb_notify_act3(smb_request_t *sr)
{
	smb_ofile_t	*of;
	smb_notify_t	*nc;
	uint32_t	status;

	of = sr->fid_ofile;
	ASSERT(of != NULL);
	nc = &of->f_notify;

	mutex_enter(&sr->sr_mutex);
	ASSERT3P(sr->sr_worker, ==, NULL);
	sr->sr_worker = curthread;

switch_state:
	switch (sr->sr_state) {
	case SMB_REQ_STATE_WAITING_FCN2:
		/*
		 * Got smb_notify_wakeup.
		 */
		sr->sr_state = SMB_REQ_STATE_ACTIVE;
		status = 0;
		break;
	case SMB_REQ_STATE_CANCEL_PENDING:
		/* cancel_method running. wait. */
		cv_wait(&sr->sr_st_cv, &sr->sr_mutex);
		goto switch_state;
	case SMB_REQ_STATE_CANCELLED:
		/*
		 * Got smb_notify_cancel
		 */
		status = NT_STATUS_CANCELLED;
		break;
	default:
		status = NT_STATUS_INTERNAL_ERROR;
		break;
	}
	sr->cancel_method = NULL;
	mutex_exit(&sr->sr_mutex);

	/*
	 * The actual SMB notify work.
	 */
	mutex_enter(&of->f_mutex);
	list_remove(&nc->nc_waiters, sr);
	if (status == 0)
		status = smb_notify_get_events(sr);
	mutex_exit(&of->f_mutex);

	/*
	 * See: About NT_STATUS_NOTIFY_ENUM_DIR (above)
	 */
	if (status == NT_STATUS_NOTIFY_ENUM_DIR &&
	    smb_notify_enum_dir_delay > 0)
		delay(MSEC_TO_TICK(smb_notify_enum_dir_delay));

	return (status);
}

static uint32_t
smb_notify_get_events(smb_request_t *sr)
{
	smb_ofile_t	*of;
	smb_notify_t	*nc;
	uint32_t	status;
	int		len;

	of = sr->fid_ofile;
	ASSERT(of != NULL);
	ASSERT(MUTEX_HELD(&of->f_mutex));
	nc = &of->f_notify;

	DTRACE_PROBE2(notify__get__events,
	    smb_request_t *, sr,
	    uint32_t, nc->nc_events);

	/*
	 * Special events which override other events
	 */
	if (nc->nc_events & FILE_NOTIFY_CHANGE_EV_CLOSED) {
		status = NT_STATUS_NOTIFY_CLEANUP;
		goto out;
	}
	if (nc->nc_events & FILE_NOTIFY_CHANGE_EV_DELETE) {
		status = NT_STATUS_DELETE_PENDING;
		goto out;
	}
	if (nc->nc_events & FILE_NOTIFY_CHANGE_EV_SUBDIR) {
		status = NT_STATUS_NOTIFY_ENUM_DIR;
		goto out;
	}
	if (nc->nc_events & FILE_NOTIFY_CHANGE_EV_OVERFLOW) {
		status = NT_STATUS_NOTIFY_ENUM_DIR;
		goto out;
	}

	/*
	 * Normal events (FILE_NOTIFY_VALID_MASK)
	 *
	 * At this point there should be some, or else
	 * some sort of bug woke us up for nothing.
	 */
	if ((nc->nc_events & FILE_NOTIFY_VALID_MASK) == 0) {
		status = NT_STATUS_INTERNAL_ERROR;
		goto out;
	}

	/*
	 * Many Windows clients call change notify with a
	 * zero-length buffer, expecting all events to be
	 * reported as _ENUM_DIR.  Testing max_bytes here
	 * because ROOM_FOR check below says "yes" if both
	 * max_bytes and the amount we ask for are zero.
	 */
	if (nc->nc_buffer.max_bytes <= 0) {
		status = NT_STATUS_NOTIFY_ENUM_DIR;
		goto out;
	}

	/*
	 * Client gave us a non-zero output buffer, and
	 * there was no overflow event (checked above)
	 * so there should be some event data.
	 */
	if ((len = nc->nc_buffer.chain_offset) <= 0) {
		status = NT_STATUS_INTERNAL_ERROR;
		goto out;
	}

	/*
	 * If the current SR has a smaller output buffer
	 * then what was setup by some previous notify,
	 * we could have more data than will fit.
	 */
	if (!MBC_ROOM_FOR(&sr->raw_data, len)) {
		/* Would overflow caller's buffer. */
		status = NT_STATUS_NOTIFY_ENUM_DIR;
		goto out;
	}

	/*
	 * Copy the event data to sr->raw_data.  In the copy,
	 * zap the NextEntryOffset in the last entry, and
	 * trim any extra bytes at the tail.
	 */
	(void) smb_mbc_copy(&sr->raw_data, &nc->nc_buffer, 0, len);
	(void) smb_mbc_poke(&sr->raw_data, nc->nc_last_off, "l", 0);
	smb_mbuf_trim(sr->raw_data.chain, len);
	status = 0;

out:
	/*
	 * If there are no other SRs waiting on this ofile,
	 * mark all events consumed, except for those that
	 * remain until the ofile is closed.  That means
	 * clear all bits EXCEPT: _EV_CLOSED, _EV_DELETE
	 *
	 * If there are other waiters (rare) all will get
	 * the currently pending events, and then the
	 * the last one out will clear the events.
	 */
	if (list_is_empty(&nc->nc_waiters)) {
		nc->nc_buffer.chain_offset = 0;
		nc->nc_events &= (FILE_NOTIFY_CHANGE_EV_CLOSED |
		    FILE_NOTIFY_CHANGE_EV_DELETE);
	}

	return (status);
}

/*
 * Called by common code after a transition from
 * state WAITING_FCN1 to state CANCEL_PENDING.
 */
static void
smb_notify_cancel(smb_request_t *sr)
{
	ASSERT3U(sr->sr_state, ==, SMB_REQ_STATE_CANCEL_PENDING);
	smb_notify_dispatch2(sr);
}

/*
 * Called after ofile event delivery to take a waiting smb request
 * from state FCN1 to state FCN2.  This may be called many times
 * (as events are delivered) but it must (exactly once) schedule
 * the taskq job to run smb_notify_act3().  Only the event that
 * takes us from state FCN1 to FCN2 schedules the taskq job.
 */
static void
smb_notify_wakeup(smb_request_t *sr)
{
	boolean_t do_disp = B_FALSE;

	SMB_REQ_VALID(sr);

	mutex_enter(&sr->sr_mutex);
	if (sr->sr_state == SMB_REQ_STATE_WAITING_FCN1) {
		sr->sr_state = SMB_REQ_STATE_WAITING_FCN2;
		do_disp = B_TRUE;
	}
	mutex_exit(&sr->sr_mutex);

	if (do_disp) {
		smb_notify_dispatch2(sr);
	}
}

/*
 * smb_notify_dispatch2()
 * Schedule a 2nd taskq call to finish up a change notify request;
 * (smb_notify_act3) either completing it or cancelling it.
 */
static void
smb_notify_dispatch2(smb_request_t *sr)
{
	void (*tq_func)(void *);
	taskqid_t tqid;

	/*
	 * Both of these call smb_notify_act3(), returning
	 * to version-specific code to send the response.
	 */
	if (sr->session->dialect >= SMB_VERS_2_BASE)
		tq_func = smb2_change_notify_finish;
	else
		tq_func = smb_nt_transact_notify_finish;

	tqid = taskq_dispatch(sr->sr_server->sv_notify_pool,
	    tq_func, sr, TQ_SLEEP);
	VERIFY(tqid != TASKQID_INVALID);
}


/*
 * What completion filter (masks) apply to each of the
 * FILE_ACTION_... events.
 */
static const uint32_t
smb_notify_action_mask[] = {
	0,  /* not used */

	/* FILE_ACTION_ADDED	 */
	FILE_NOTIFY_CHANGE_NAME |
	FILE_NOTIFY_CHANGE_LAST_WRITE,

	/* FILE_ACTION_REMOVED	 */
	FILE_NOTIFY_CHANGE_NAME |
	FILE_NOTIFY_CHANGE_LAST_WRITE,

	/* FILE_ACTION_MODIFIED	 */
	FILE_NOTIFY_CHANGE_ATTRIBUTES |
	FILE_NOTIFY_CHANGE_SIZE |
	FILE_NOTIFY_CHANGE_LAST_WRITE |
	FILE_NOTIFY_CHANGE_LAST_ACCESS |
	FILE_NOTIFY_CHANGE_CREATION |
	FILE_NOTIFY_CHANGE_EA |
	FILE_NOTIFY_CHANGE_SECURITY,

	/* FILE_ACTION_RENAMED_OLD_NAME */
	FILE_NOTIFY_CHANGE_NAME |
	FILE_NOTIFY_CHANGE_LAST_WRITE,

	/* FILE_ACTION_RENAMED_NEW_NAME */
	FILE_NOTIFY_CHANGE_NAME |
	FILE_NOTIFY_CHANGE_LAST_WRITE,

	/* FILE_ACTION_ADDED_STREAM */
	FILE_NOTIFY_CHANGE_STREAM_NAME,

	/* FILE_ACTION_REMOVED_STREAM */
	FILE_NOTIFY_CHANGE_STREAM_NAME,

	/* FILE_ACTION_MODIFIED_STREAM */
	FILE_NOTIFY_CHANGE_STREAM_SIZE |
	FILE_NOTIFY_CHANGE_STREAM_WRITE,

	/* FILE_ACTION_SUBDIR_CHANGED */
	FILE_NOTIFY_CHANGE_EV_SUBDIR,

	/* FILE_ACTION_DELETE_PENDING */
	FILE_NOTIFY_CHANGE_EV_DELETE,

	/* FILE_ACTION_HANDLE_CLOSED */
	FILE_NOTIFY_CHANGE_EV_CLOSED,
};
static const int smb_notify_action_nelm =
	sizeof (smb_notify_action_mask) /
	sizeof (smb_notify_action_mask[0]);

/*
 * smb_notify_ofile
 *
 * Post an event to the change notify buffer for this ofile,
 * subject to the mask that selects subscribed event types.
 * If an SR is waiting for events and we've delivered some,
 * wake the SR.
 */
void
smb_notify_ofile(smb_ofile_t *of, uint_t action, const char *name)
{
	smb_notify_t	*nc;
	smb_request_t	*sr;
	uint32_t	filter, events;

	SMB_OFILE_VALID(of);

	mutex_enter(&of->f_mutex);
	nc = &of->f_notify;

	/*
	 * Compute the filter & event bits for this action,
	 * which determine whether we'll post the event.
	 * Note: always sensitive to: delete, closed.
	 */
	filter = nc->nc_filter |
	    FILE_NOTIFY_CHANGE_EV_DELETE |
	    FILE_NOTIFY_CHANGE_EV_CLOSED;
	VERIFY(action < smb_notify_action_nelm);
	if (action < smb_notify_action_nelm)
		events = smb_notify_action_mask[action];
	else
		events = 0;
	if ((filter & events) == 0)
		goto unlock_out;

	/*
	 * OK, we're going to post this event.
	 */
	switch (action) {
	case FILE_ACTION_ADDED:
	case FILE_ACTION_REMOVED:
	case FILE_ACTION_MODIFIED:
	case FILE_ACTION_RENAMED_OLD_NAME:
	case FILE_ACTION_RENAMED_NEW_NAME:
	case FILE_ACTION_ADDED_STREAM:
	case FILE_ACTION_REMOVED_STREAM:
	case FILE_ACTION_MODIFIED_STREAM:
		/*
		 * Append this event to the buffer.
		 * Also keep track of events seen.
		 */
		smb_notify_encode_action(of, action, name);
		nc->nc_events |= events;
		break;

	case FILE_ACTION_SUBDIR_CHANGED:
	case FILE_ACTION_DELETE_PENDING:
	case FILE_ACTION_HANDLE_CLOSED:
		/*
		 * These are "internal" events, and therefore
		 * are not appended to the response buffer.
		 * Just record the event flags and wakeup.
		 */
		nc->nc_events |= events;
		break;

	default:
		ASSERT(0);	/* bogus action */
		break;
	}

	sr = list_head(&nc->nc_waiters);
	while (sr != NULL) {
		smb_notify_wakeup(sr);
		sr = list_next(&nc->nc_waiters, sr);
	}

unlock_out:
	mutex_exit(&of->f_mutex);
}

/*
 * Encode a FILE_NOTIFY_INFORMATION struct.
 */
static void
smb_notify_encode_action(smb_ofile_t *of,
    uint32_t action, const char *fname)
{
	smb_notify_t *nc = &of->f_notify;
	mbuf_chain_t *mbc;
	uint32_t namelen, totlen;

	ASSERT(nc != NULL);
	ASSERT(FILE_ACTION_ADDED <= action &&
	    action <= FILE_ACTION_MODIFIED_STREAM);
	ASSERT(fname != NULL);
	ASSERT(MUTEX_HELD(&of->f_mutex));

	/* Once we've run out of room, stop trying to append. */
	if ((nc->nc_events & FILE_NOTIFY_CHANGE_EV_OVERFLOW) != 0)
		return;

	if (fname == NULL)
		return;
	namelen = smb_wcequiv_strlen(fname);
	if (namelen == 0)
		return;

	/*
	 * Layout is: 3 DWORDS, Unicode string, pad(4).
	 */
	mbc = &nc->nc_buffer;
	totlen = (12 + namelen + 3) & ~3;
	if (MBC_ROOM_FOR(mbc, totlen) == 0) {
		nc->nc_events |= FILE_NOTIFY_CHANGE_EV_OVERFLOW;
		return;
	}

	/*
	 * Keep track of where this entry starts (nc_last_off)
	 * because after we put all entries, we need to zap
	 * the NextEntryOffset field in the last one.
	 */
	nc->nc_last_off = mbc->chain_offset;

	/*
	 * Encode this entry, then 4-byte alignment padding.
	 *
	 * Note that smb_mbc_encodef with a "U" code puts a
	 * Unicode string with a null termination.  We don't
	 * want a null, but do want alignment padding.  We
	 * get that by encoding with "U.." at the end of the
	 * encoding string, which gets us two bytes for the
	 * Unicode NULL, and two more zeros for the "..".
	 * We then "back up" the chain_offset (finger) so it's
	 * correctly 4-byte aligned.  We will sometimes have
	 * written a couple more bytes than needed, but we'll
	 * just overwrite those with the next entry.  At the
	 * end, we trim the mbuf chain to the correct length.
	 */
	(void) smb_mbc_encodef(mbc, "lllU..",
	    totlen, /* NextEntryOffset */
	    action, namelen, fname);
	mbc->chain_offset = nc->nc_last_off + totlen;
}
