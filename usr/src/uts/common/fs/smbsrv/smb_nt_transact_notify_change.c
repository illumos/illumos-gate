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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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

#include <smbsrv/smb_incl.h>
#include <sys/sdt.h>

static void smb_reply_notify_change_request(smb_request_t *);

/*
 * smb_nt_transact_notify_change
 *
 * This function is responsible for processing NOTIFY CHANGE requests.
 * Requests are stored in a global queue. This queue is processed when
 * a monitored directory is changed or client cancels one of its already
 * sent requests.
 */
smb_sdrc_t
smb_nt_transact_notify_change(struct smb_request *sr, struct smb_xa *xa)
{
	uint32_t		CompletionFilter;
	unsigned char		WatchTree;
	smb_node_t		*node;

	if (smb_decode_mbc(&xa->req_setup_mb, "lwb",
	    &CompletionFilter, &sr->smb_fid, &WatchTree) != 0)
		return (SDRC_UNSUPPORTED);

	sr->fid_ofile = smb_ofile_lookup_by_fid(sr->tid_tree, sr->smb_fid);
	if (sr->fid_ofile == NULL) {
		smbsr_error(sr, NT_STATUS_INVALID_HANDLE, ERRDOS, ERRbadfid);
		return (SDRC_ERROR_REPLY);
	}

	node = sr->fid_ofile->f_node;

	if (node->attr.sa_vattr.va_type != VDIR) {
		/*
		 * Notify change requests are only valid on directories.
		 */
		smbsr_error(sr, NT_STATUS_NOT_A_DIRECTORY, 0, 0);
		return (SDRC_ERROR_REPLY);
	}

	mutex_enter(&sr->sr_mutex);
	switch (sr->sr_state) {
	case SMB_REQ_STATE_ACTIVE:
		node->waiting_event++;
		node->flags |= NODE_FLAGS_NOTIFY_CHANGE;
		if ((node->flags & NODE_FLAGS_CHANGED) == 0) {
			sr->sr_ncr.nc_node = node;
			sr->sr_ncr.nc_flags = CompletionFilter;
			if (WatchTree)
				sr->sr_ncr.nc_flags |= NODE_FLAGS_WATCH_TREE;

			sr->sr_keep = B_TRUE;
			sr->sr_state = SMB_REQ_STATE_WAITING_EVENT;
			smb_slist_insert_tail(&smb_info.si_ncr_list, sr);

			/*
			 * Monitor events system-wide.
			 *
			 * XXX: smb_node_ref() and smb_node_release()
			 * take &node->n_lock.  May need alternate forms
			 * of these routines if node->n_lock is taken
			 * around calls to smb_fem_fcn_install() and
			 * smb_fem_fcn_uninstall().
			 */

			smb_fem_fcn_install(node);

			mutex_exit(&sr->sr_mutex);
			return (SDRC_NO_REPLY);
		} else {
			/* node already changed, reply immediately */
			if (--node->waiting_event == 0)
				node->flags &=
				    ~(NODE_FLAGS_NOTIFY_CHANGE |
				    NODE_FLAGS_CHANGED);
			mutex_exit(&sr->sr_mutex);
			return (SDRC_NORMAL_REPLY);
		}

	case SMB_REQ_STATE_CANCELED:
		mutex_exit(&sr->sr_mutex);
		smbsr_error(sr, NT_STATUS_CANCELLED, 0, 0);
		return (SDRC_ERROR_REPLY);

	default:
		ASSERT(0);
		mutex_exit(&sr->sr_mutex);
		return (SDRC_NORMAL_REPLY);
	}
}

/*
 * smb_reply_notify_change_request
 *
 * This function sends appropriate response to an already queued NOTIFY CHANGE
 * request. If node is changed (reply == NODE_FLAGS_CHANGED), a normal reply is
 * sent.
 * If client cancels the request or session dropped, an NT_STATUS_CANCELED
 * is sent in reply.
 */
static void
smb_reply_notify_change_request(smb_request_t *sr)
{
	smb_node_t	*node;
	int		total_bytes, n_setup, n_param, n_data;
	int		param_off, param_pad, data_off, data_pad;
	struct		smb_xa *xa;
	smb_error_t	err;

	xa = sr->r_xa;
	node = sr->sr_ncr.nc_node;

	if (--node->waiting_event == 0) {
		node->flags &= ~(NODE_FLAGS_NOTIFY_CHANGE | NODE_FLAGS_CHANGED);
		smb_fem_fcn_uninstall(node);
	}

	mutex_enter(&sr->sr_mutex);
	switch (sr->sr_state) {

	case SMB_REQ_STATE_EVENT_OCCURRED:
		sr->sr_state = SMB_REQ_STATE_ACTIVE;

		/* many things changed */

		(void) smb_encode_mbc(&xa->rep_data_mb, "l", 0L);

		/* setup the NT transact reply */

		n_setup = MBC_LENGTH(&xa->rep_setup_mb);
		n_param = MBC_LENGTH(&xa->rep_param_mb);
		n_data  = MBC_LENGTH(&xa->rep_data_mb);

		n_setup = (n_setup + 1) / 2; /* Convert to setup words */
		param_pad = 1; /* must be one */
		param_off = param_pad + 32 + 37 + (n_setup << 1) + 2;
		/* Pad to 4 bytes */
		data_pad = (4 - ((param_off + n_param) & 3)) % 4;
		/* Param off from hdr */
		data_off = param_off + n_param + data_pad;
		total_bytes = param_pad + n_param + data_pad + n_data;

		(void) smbsr_encode_result(sr, 18+n_setup, total_bytes,
		    "b 3. llllllllb C w #. C #. C",
		    18 + n_setup,	/* wct */
		    n_param,		/* Total Parameter Bytes */
		    n_data,		/* Total Data Bytes */
		    n_param,		/* Total Parameter Bytes this buffer */
		    param_off,		/* Param offset from header start */
		    0,			/* Param displacement */
		    n_data,		/* Total Data Bytes this buffer */
		    data_off,		/* Data offset from header start */
		    0,			/* Data displacement */
		    n_setup,		/* suwcnt */
		    &xa->rep_setup_mb,	/* setup[] */
		    total_bytes,	/* Total data bytes */
		    param_pad,
		    &xa->rep_param_mb,
		    data_pad,
		    &xa->rep_data_mb);
		break;

	case SMB_REQ_STATE_CANCELED:
		err.severity = ERROR_SEVERITY_ERROR;
		err.status   = NT_STATUS_CANCELLED;
		err.errcls   = ERRDOS;
		err.errcode  = ERROR_OPERATION_ABORTED;
		smbsr_set_error(sr, &err);

		(void) smb_encode_mbc(&sr->reply, "bwbw",
		    (short)0, 0L, (short)0, 0L);
		sr->smb_wct = 0;
		sr->smb_bcc = 0;
		break;
	default:
		ASSERT(0);
	}
	mutex_exit(&sr->sr_mutex);

	/* Setup the header */
	(void) smb_poke_mbc(&sr->reply, 0, SMB_HEADER_ED_FMT,
	    sr->first_smb_com,
	    sr->smb_rcls,
	    sr->smb_reh,
	    sr->smb_err,
	    sr->smb_flg | SMB_FLAGS_REPLY,
	    sr->smb_flg2,
	    sr->smb_pid_high,
	    sr->smb_sig,
	    sr->smb_tid,
	    sr->smb_pid,
	    sr->smb_uid,
	    sr->smb_mid);

	if (sr->session->signing.flags & SMB_SIGNING_ENABLED)
		smb_sign_reply(sr, NULL);

	/* send the reply */
	DTRACE_PROBE1(ncr__reply, struct smb_request *, sr)
	(void) smb_session_send(sr->session, 0, &sr->reply);
	smbsr_cleanup(sr);

	mutex_enter(&sr->sr_mutex);
	sr->sr_state = SMB_REQ_STATE_COMPLETED;
	mutex_exit(&sr->sr_mutex);
	smb_request_free(sr);
}

/*
 * smb_process_session_notify_change_queue
 *
 * This function traverses notify change request queue and sends
 * cancel replies to all of requests that are related to a specific
 * session.
 */
void
smb_process_session_notify_change_queue(struct smb_session *session)
{
	smb_request_t	*sr;
	smb_request_t	*tmp;
	boolean_t	sig = B_FALSE;

	smb_slist_enter(&smb_info.si_ncr_list);
	smb_slist_enter(&smb_info.si_nce_list);
	sr = smb_slist_head(&smb_info.si_ncr_list);
	while (sr) {
		ASSERT(sr->sr_magic == SMB_REQ_MAGIC);
		tmp = smb_slist_next(&smb_info.si_ncr_list, sr);
		if (sr->session == session) {
			mutex_enter(&sr->sr_mutex);
			switch (sr->sr_state) {
			case SMB_REQ_STATE_WAITING_EVENT:
				smb_slist_obj_move(
				    &smb_info.si_nce_list,
				    &smb_info.si_ncr_list,
				    sr);
				sr->sr_state = SMB_REQ_STATE_CANCELED;
				sig = B_TRUE;
				break;
			default:
				ASSERT(0);
				break;
			}
			mutex_exit(&sr->sr_mutex);
		}
		sr = tmp;
	}
	smb_slist_exit(&smb_info.si_nce_list);
	smb_slist_exit(&smb_info.si_ncr_list);
	if (sig) {
		smb_thread_signal(&smb_info.si_thread_notify_change);
	}
}

/*
 * smb_process_file_notify_change_queue
 *
 * This function traverses notify change request queue and sends
 * cancel replies to all of requests that are related to the
 * specified file.
 */
void
smb_process_file_notify_change_queue(struct smb_ofile *of)
{
	smb_request_t	*sr;
	smb_request_t	*tmp;
	boolean_t	sig = B_FALSE;

	smb_slist_enter(&smb_info.si_ncr_list);
	smb_slist_enter(&smb_info.si_nce_list);
	sr = smb_slist_head(&smb_info.si_ncr_list);
	while (sr) {
		ASSERT(sr->sr_magic == SMB_REQ_MAGIC);
		tmp = smb_slist_next(&smb_info.si_ncr_list, sr);
		if (sr->fid_ofile == of) {
			mutex_enter(&sr->sr_mutex);
			switch (sr->sr_state) {
			case SMB_REQ_STATE_WAITING_EVENT:
				smb_slist_obj_move(
				    &smb_info.si_nce_list,
				    &smb_info.si_ncr_list,
				    sr);
				sr->sr_state = SMB_REQ_STATE_CANCELED;
				sig = B_TRUE;
				break;
			default:
				ASSERT(0);
				break;
			}
			mutex_exit(&sr->sr_mutex);
		}
		sr = tmp;
	}
	smb_slist_exit(&smb_info.si_nce_list);
	smb_slist_exit(&smb_info.si_ncr_list);
	if (sig) {
		smb_thread_signal(&smb_info.si_thread_notify_change);
	}
}

/*
 * smb_reply_specific_cancel_request
 *
 * This function searches global request list for a specific request. If found,
 * moves the request to event queue and kicks the notify change daemon.
 */

void
smb_reply_specific_cancel_request(struct smb_request *zsr)
{
	smb_request_t	*sr;
	smb_request_t	*tmp;
	boolean_t	sig = B_FALSE;

	smb_slist_enter(&smb_info.si_ncr_list);
	smb_slist_enter(&smb_info.si_nce_list);
	sr = smb_slist_head(&smb_info.si_ncr_list);
	while (sr) {
		ASSERT(sr->sr_magic == SMB_REQ_MAGIC);
		tmp = smb_slist_next(&smb_info.si_ncr_list, sr);
		if ((sr->session == zsr->session) &&
		    (sr->smb_sid == zsr->smb_sid) &&
		    (sr->smb_uid == zsr->smb_uid) &&
		    (sr->smb_pid == zsr->smb_pid) &&
		    (sr->smb_tid == zsr->smb_tid) &&
		    (sr->smb_mid == zsr->smb_mid)) {
			mutex_enter(&sr->sr_mutex);
			switch (sr->sr_state) {
			case SMB_REQ_STATE_WAITING_EVENT:
				smb_slist_obj_move(
				    &smb_info.si_nce_list,
				    &smb_info.si_ncr_list,
				    sr);
				sr->sr_state = SMB_REQ_STATE_CANCELED;
				sig = B_TRUE;
				break;
			default:
				ASSERT(0);
				break;
			}
			mutex_exit(&sr->sr_mutex);
		}
		sr = tmp;
	}
	smb_slist_exit(&smb_info.si_nce_list);
	smb_slist_exit(&smb_info.si_ncr_list);
	if (sig) {
		smb_thread_signal(&smb_info.si_thread_notify_change);
	}
}

/*
 * smb_process_node_notify_change_queue
 *
 * This function searches notify change request queue and sends
 * 'NODE MODIFIED' reply to all requests which are related to a
 * specific node.
 * WatchTree flag: We handle this flag in a special manner just
 * for DAVE clients. When something is changed, we notify all
 * requests which came from DAVE clients on the same volume which
 * has been modified. We don't care about the tree that they wanted
 * us to monitor. any change in any part of the volume will lead
 * to notifying all notify change requests from DAVE clients on the
 * different parts of the volume hierarchy.
 */
void
smb_process_node_notify_change_queue(struct smb_node *node)
{
	smb_request_t	*sr;
	smb_request_t	*tmp;
	boolean_t	sig = B_FALSE;

	if (!(node->flags & NODE_FLAGS_NOTIFY_CHANGE))
		return;

	node->flags |= NODE_FLAGS_CHANGED;

	smb_slist_enter(&smb_info.si_ncr_list);
	smb_slist_enter(&smb_info.si_nce_list);
	sr = smb_slist_head(&smb_info.si_ncr_list);
	while (sr) {
		ASSERT(sr->sr_magic == SMB_REQ_MAGIC);
		tmp = smb_slist_next(&smb_info.si_ncr_list, sr);
		/*
		 * send notify if:
		 * - it's a request for the same node or
		 * - it's a request from a DAVE client, its 'watch tree'
		 *   flag is set and monitors a tree on the same volume.
		 */
		if ((sr->sr_ncr.nc_node == node) ||
		    ((sr->sr_ncr.nc_flags & NODE_FLAGS_WATCH_TREE) &&
		    (sr->session->native_os == NATIVE_OS_MACOS) &&
		    !fsd_cmp(&sr->sr_ncr.nc_node->tree_fsd, &node->tree_fsd))) {
			mutex_enter(&sr->sr_mutex);
			switch (sr->sr_state) {
			case SMB_REQ_STATE_WAITING_EVENT:
				smb_slist_obj_move(
				    &smb_info.si_nce_list,
				    &smb_info.si_ncr_list,
				    sr);
				sr->sr_state = SMB_REQ_STATE_EVENT_OCCURRED;
				sig = B_TRUE;
				break;
			default:
				ASSERT(0);
				break;
			}
			mutex_exit(&sr->sr_mutex);
		}
		sr = tmp;
	}
	smb_slist_exit(&smb_info.si_nce_list);
	smb_slist_exit(&smb_info.si_ncr_list);
	if (sig) {
		smb_thread_signal(&smb_info.si_thread_notify_change);
	}
}

/*
 * smb_notify_change_daemon
 *
 * This function processes notify change event list and send appropriate
 * responses to the requests. This function executes in the system as an
 * indivdual thread.
 */

void
smb_notify_change_daemon(smb_thread_t *thread, void *si_void)
{
	smb_request_t	*sr;
	smb_request_t	*tmp;
	list_t		sr_list;
	smb_info_t	*si = si_void;

	list_create(&sr_list, sizeof (smb_request_t),
	    offsetof(smb_request_t, sr_ncr.nc_lnd));

	ASSERT(si != NULL);

	while (smb_thread_continue(thread)) {

		while (smb_slist_move_tail(&sr_list, &si->si_nce_list)) {
			sr = list_head(&sr_list);
			while (sr) {
				ASSERT(sr->sr_magic == SMB_REQ_MAGIC);
				tmp = list_next(&sr_list, sr);
				list_remove(&sr_list, sr);
				smb_reply_notify_change_request(sr);
				sr = tmp;
			}
		}
	}

	list_destroy(&sr_list);
}

/*
 * smb_notify_change_event_queue_dump
 *
 * Dumps all requests in NCE queue to the system log.
 */
void
smb_notify_change_event_queue_dump()
{
	smb_request_t	*sr;
	int		i = 0;

	smb_slist_enter(&smb_info.si_nce_list);
	sr = smb_slist_head(&smb_info.si_nce_list);
	while (sr) {
		ASSERT(sr->sr_magic == SMB_REQ_MAGIC);
		ASSERT((sr->sr_state == SMB_REQ_STATE_CANCELED) ||
		    (sr->sr_state == SMB_REQ_STATE_EVENT_OCCURRED));
		i++;
		sr = smb_slist_next(&smb_info.si_nce_list, sr);
	}
	smb_slist_exit(&smb_info.si_nce_list);
}

/*
 * smb_notify_change_req_queue_dump
 *
 * Dumps all requests in NCR queue to the system log.
 */
void
smb_notify_change_req_queue_dump()
{
	smb_request_t	*sr;
	int		i = 0;

	smb_slist_enter(&smb_info.si_ncr_list);
	sr = smb_slist_head(&smb_info.si_ncr_list);
	while (sr) {
		ASSERT(sr->sr_magic == SMB_REQ_MAGIC);
		ASSERT(sr->sr_state == SMB_REQ_STATE_WAITING_EVENT);
		i++;
		sr = smb_slist_next(&smb_info.si_ncr_list, sr);
	}
	smb_slist_exit(&smb_info.si_ncr_list);
}
