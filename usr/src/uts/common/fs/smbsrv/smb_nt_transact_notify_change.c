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
 * Copyright 2012 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * File Change Notification (FCN)
 */

/*
 * SMB: nt_transact_notify_change
 *
 *  Client Setup Words                 Description
 *  ================================== =================================
 *
 *  ULONG CompletionFilter;            Specifies operation to monitor
 *  USHORT Fid;                        Fid of directory to monitor
 *  BOOLEAN WatchTree;                 TRUE = watch all subdirectories too
 *  UCHAR Reserved;                    MBZ
 *
 * This command notifies the client when the directory specified by Fid is
 * modified.  It also returns the name(s) of the file(s) that changed.  The
 * command completes once the directory has been modified based on the
 * supplied CompletionFilter.  The command is a "single shot" and therefore
 * needs to be reissued to watch for more directory changes.
 *
 * A directory file must be opened before this command may be used.  Once
 * the directory is open, this command may be used to begin watching files
 * and subdirectories in the specified directory for changes.  The first
 * time the command is issued, the MaxParameterCount field in the transact
 * header determines the size of the buffer that will be used at the server
 * to buffer directory change information between issuances of the notify
 * change commands.
 *
 * When a change that is in the CompletionFilter is made to the directory,
 * the command completes.  The names of the files that have changed since
 * the last time the command was issued are returned to the client.  The
 * ParameterCount field of the response indicates the number of bytes that
 * are being returned.  If too many files have changed since the last time
 * the command was issued, then zero bytes are returned and an alternate
 * status code is returned in the Status field of the response.
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
 *  Server Response                    Description
 *  ================================== ================================
 *  ParameterCount                     # of bytes of change data
 *  Parameters[ ParameterCount ]       FILE_NOTIFY_INFORMATION
 *                                      structures
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
 */

#include <smbsrv/smb_kproto.h>
#include <sys/sdt.h>

/*
 * We add this flag to the CompletionFilter (see above) when the
 * client sets WatchTree.  Must not overlap FILE_NOTIFY_VALID_MASK.
 */
#define	NODE_FLAGS_WATCH_TREE		0x10000000
#if (NODE_FLAGS_WATCH_TREE & FILE_NOTIFY_VALID_MASK)
#error "NODE_FLAGS_WATCH_TREE"
#endif

static void smb_notify_sr(smb_request_t *, uint_t, const char *);

static int smb_notify_encode_action(struct smb_request *, struct smb_xa *,
	uint32_t, char *);

/*
 * smb_nt_transact_notify_change
 *
 * Handle and SMB NT transact NOTIFY CHANGE request.
 * Basically, wait until "something has changed", and either
 * return information about what changed, or return a special
 * error telling the client "many things changed".
 *
 * The implementation uses a per-node list of waiting notify
 * requests like this one, each with a blocked worker thead.
 * Later, FEM and/or smbsrv events wake these threads, which
 * then send the reply to the client.
 */
smb_sdrc_t
smb_nt_transact_notify_change(smb_request_t *sr, struct smb_xa *xa)
{
	uint32_t		CompletionFilter;
	unsigned char		WatchTree;
	smb_error_t		err;
	int			rc;
	smb_node_t		*node;

	if (smb_mbc_decodef(&xa->req_setup_mb, "lwb",
	    &CompletionFilter, &sr->smb_fid, &WatchTree) != 0) {
		smbsr_error(sr, NT_STATUS_INVALID_PARAMETER, 0, 0);
		return (SDRC_ERROR);
	}
	CompletionFilter &= FILE_NOTIFY_VALID_MASK;
	if (WatchTree)
		CompletionFilter |= NODE_FLAGS_WATCH_TREE;

	smbsr_lookup_file(sr);
	if (sr->fid_ofile == NULL) {
		smbsr_error(sr, NT_STATUS_INVALID_HANDLE, ERRDOS, ERRbadfid);
		return (SDRC_ERROR);
	}

	node = sr->fid_ofile->f_node;
	if (node == NULL || !smb_node_is_dir(node)) {
		/*
		 * Notify change requests are only valid on directories.
		 */
		smbsr_error(sr, NT_STATUS_NOT_A_DIRECTORY, 0, 0);
		return (SDRC_ERROR);
	}

	/*
	 * Prepare to receive event data.
	 */
	sr->sr_ncr.nc_flags = CompletionFilter;
	ASSERT(sr->sr_ncr.nc_action == 0);
	ASSERT(sr->sr_ncr.nc_fname == NULL);
	sr->sr_ncr.nc_fname = kmem_zalloc(MAXNAMELEN, KM_SLEEP);

	/*
	 * Subscribe to events on this node.
	 */
	smb_node_fcn_subscribe(node, sr);

	/*
	 * Wait for subscribed events to arrive.
	 * Expect SMB_REQ_STATE_EVENT_OCCURRED
	 * or SMB_REQ_STATE_CANCELED when signaled.
	 * Note it's possible (though rare) to already
	 * have SMB_REQ_STATE_CANCELED here.
	 */
	mutex_enter(&sr->sr_mutex);
	if (sr->sr_state == SMB_REQ_STATE_ACTIVE)
		sr->sr_state = SMB_REQ_STATE_WAITING_EVENT;
	while (sr->sr_state == SMB_REQ_STATE_WAITING_EVENT) {
		cv_wait(&sr->sr_ncr.nc_cv, &sr->sr_mutex);
	}
	if (sr->sr_state == SMB_REQ_STATE_EVENT_OCCURRED)
		sr->sr_state = SMB_REQ_STATE_ACTIVE;
	mutex_exit(&sr->sr_mutex);

	/*
	 * Unsubscribe from events on this node.
	 */
	smb_node_fcn_unsubscribe(node, sr);

	/*
	 * Build the reply
	 */

	switch (sr->sr_state) {

	case SMB_REQ_STATE_ACTIVE:
		/*
		 * If we have event data, marshall it now, else just
		 * say "many things changed". Note that when we are
		 * woken by a WatchTree event (action == 0) then we
		 * don't have true event details, and only know the
		 * directory under which something changed.  In that
		 * case we just say "many things changed".
		 */
		if (sr->sr_ncr.nc_action != 0 && 0 ==
		    smb_notify_encode_action(sr, xa,
		    sr->sr_ncr.nc_action, sr->sr_ncr.nc_fname)) {
			rc = SDRC_SUCCESS;
			break;
		}
		/*
		 * This error says "many things changed".
		 */
		err.status = NT_STATUS_NOTIFY_ENUM_DIR;
		err.errcls   = ERRDOS;
		err.errcode  = ERROR_NOTIFY_ENUM_DIR;
		smbsr_set_error(sr, &err);
		rc = SDRC_ERROR;
		break;

	case SMB_REQ_STATE_CANCELED:
		err.status   = NT_STATUS_CANCELLED;
		err.errcls   = ERRDOS;
		err.errcode  = ERROR_OPERATION_ABORTED;
		smbsr_set_error(sr, &err);
		rc = SDRC_ERROR;
		break;

	default:
		ASSERT(0);
		err.status   = NT_STATUS_INTERNAL_ERROR;
		err.errcls   = ERRDOS;
		err.errcode  = ERROR_INTERNAL_ERROR;
		smbsr_set_error(sr, &err);
		rc = SDRC_ERROR;
		break;
	}

	if (sr->sr_ncr.nc_fname != NULL) {
		kmem_free(sr->sr_ncr.nc_fname, MAXNAMELEN);
		sr->sr_ncr.nc_fname = NULL;
	}

	return (rc);
}

/*
 * Encode a FILE_NOTIFY_INFORMATION struct.
 *
 * We only ever put one of these in a response, so this
 * does not bother handling appending additional ones.
 */
static int
smb_notify_encode_action(struct smb_request *sr, struct smb_xa *xa,
	uint32_t action, char *fname)
{
	uint32_t namelen;
	int rc;

	if (action < FILE_ACTION_ADDED ||
	    action > FILE_ACTION_MODIFIED_STREAM)
		return (-1);

	namelen = smb_ascii_or_unicode_strlen(sr, fname);
	if (namelen == 0)
		return (-1);

	rc = smb_mbc_encodef(&xa->rep_data_mb, "%lllu", sr,
	    0, /* NextEntryOffset */
	    action, namelen, fname);
	return (rc);
}

/*
 * smb_notify_file_closed
 *
 * Cancel any change-notify calls on this open file.
 */
void
smb_notify_file_closed(struct smb_ofile *of)
{
	smb_session_t	*ses;
	smb_request_t	*sr;
	smb_slist_t	*list;

	SMB_OFILE_VALID(of);
	ses = of->f_session;
	SMB_SESSION_VALID(ses);
	list = &ses->s_req_list;

	smb_slist_enter(list);

	sr = smb_slist_head(list);
	while (sr) {
		SMB_REQ_VALID(sr);
		if (sr->sr_state == SMB_REQ_STATE_WAITING_EVENT &&
		    sr->fid_ofile == of) {
			smb_request_cancel(sr);
		}
		sr = smb_slist_next(list, sr);
	}

	smb_slist_exit(list);
}


/*
 * smb_notify_event
 *
 * Post an event to the watchers on a given node.
 *
 * This makes one exception for RENAME, where we expect a
 * pair of events for the {old,new} directory element names.
 * This only delivers an event for the "new" name.
 *
 * The event delivery mechanism does not implement delivery of
 * multiple events for one "NT Notify" call.  One could do that,
 * but modern clients don't actually use the event data.  They
 * set a max. received data size of zero, which means we discard
 * the data and send the special "lots changed" error instead.
 * Given that, there's not really any point in implementing the
 * delivery of multiple events.  In fact, we don't even need to
 * implement single event delivery, but do so for completeness,
 * for debug convenience, and to be nice to older clients that
 * may actually want some event data instead of the error.
 *
 * Given that we only deliver a single event for an "NT Notify"
 * caller, we want to deliver the "new" name event.  (The "old"
 * name event is less important, even ignored by some clients.)
 * Since we know these are delivered in pairs, we can simply
 * discard the "old" name event, knowing that the "new" name
 * event will be delivered immediately afterwards.
 *
 * So, why do event sources post the "old name" event at all?
 * (1) For debugging, so we see both {old,new} names here.
 * (2) If in the future someone decides to implement the
 * delivery of both {old,new} events, the changes can be
 * mostly isolated to this file.
 */
void
smb_notify_event(smb_node_t *node, uint_t action, const char *name)
{
	smb_request_t	*sr;
	smb_node_fcn_t	*fcn;

	SMB_NODE_VALID(node);
	fcn = &node->n_fcn;

	if (action == FILE_ACTION_RENAMED_OLD_NAME)
		return; /* see above */

	mutex_enter(&fcn->fcn_mutex);

	sr = list_head(&fcn->fcn_watchers);
	while (sr) {
		smb_notify_sr(sr, action, name);
		sr = list_next(&fcn->fcn_watchers, sr);
	}

	mutex_exit(&fcn->fcn_mutex);
}

/*
 * What completion filter (masks) apply to each of the
 * FILE_ACTION_... events.
 */
static const uint32_t
smb_notify_action_mask[] = {
	/* 0: Special, used by smb_node_notify_parents() */
	NODE_FLAGS_WATCH_TREE,

	/* FILE_ACTION_ADDED	 */
	FILE_NOTIFY_CHANGE_NAME,

	/* FILE_ACTION_REMOVED	 */
	FILE_NOTIFY_CHANGE_NAME,

	/* FILE_ACTION_MODIFIED	 */
	FILE_NOTIFY_CHANGE_ATTRIBUTES |
	FILE_NOTIFY_CHANGE_SIZE |
	FILE_NOTIFY_CHANGE_LAST_WRITE |
	FILE_NOTIFY_CHANGE_LAST_ACCESS |
	FILE_NOTIFY_CHANGE_CREATION |
	FILE_NOTIFY_CHANGE_EA |
	FILE_NOTIFY_CHANGE_SECURITY,

	/* FILE_ACTION_RENAMED_OLD_NAME */
	FILE_NOTIFY_CHANGE_NAME,

	/* FILE_ACTION_RENAMED_NEW_NAME */
	FILE_NOTIFY_CHANGE_NAME,

	/* FILE_ACTION_ADDED_STREAM */
	FILE_NOTIFY_CHANGE_STREAM_NAME,

	/* FILE_ACTION_REMOVED_STREAM */
	FILE_NOTIFY_CHANGE_STREAM_NAME,

	/* FILE_ACTION_MODIFIED_STREAM */
	FILE_NOTIFY_CHANGE_STREAM_SIZE |
	FILE_NOTIFY_CHANGE_STREAM_WRITE,
};
static const int smb_notify_action_nelm =
	sizeof (smb_notify_action_mask) /
	sizeof (smb_notify_action_mask[0]);

/*
 * smb_notify_sr
 *
 * Post an event to an smb request waiting on some node.
 *
 * Note that node->fcn.mutex is held.  This implies a
 * lock order: node->fcn.mutex, then sr_mutex
 */
static void
smb_notify_sr(smb_request_t *sr, uint_t action, const char *name)
{
	smb_notify_change_req_t	*ncr;
	uint32_t	mask;

	SMB_REQ_VALID(sr);
	ncr = &sr->sr_ncr;

	/*
	 * Compute the completion filter mask bits for which
	 * we will signal waiting notify requests.
	 */
	if (action >= smb_notify_action_nelm) {
		ASSERT(0);
		return;
	}
	mask = smb_notify_action_mask[action];

	mutex_enter(&sr->sr_mutex);
	if (sr->sr_state == SMB_REQ_STATE_WAITING_EVENT &&
	    (ncr->nc_flags & mask) != 0) {
		sr->sr_state = SMB_REQ_STATE_EVENT_OCCURRED;
		/*
		 * Save event data in the sr_ncr field so the
		 * reply handler can return it.
		 */
		ncr->nc_action = action;
		if (name != NULL)
			(void) strlcpy(ncr->nc_fname, name, MAXNAMELEN);
		cv_signal(&ncr->nc_cv);
	}
	mutex_exit(&sr->sr_mutex);
}
