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
 * SMB: write_raw
 * 5.27       WRITE_RAW: Write Raw Bytes
 *
 * The Write Block Raw protocol is used to maximize the performance of
 * writing a large block of data from the client to the server.  The Write
 * Block Raw command's scope includes files, Named Pipes, and spooled
 * output (can be used in place COM_WRITE_PRINT_FILE ).
 *
 *  Client Request              Description
 *  ==========================  =========================================
 *
 *  UCHAR WordCount;            Count of parameter words = 12
 *  USHORT Fid;                 File handle
 *  USHORT Count;               Total bytes, including this buffer
 *  USHORT Reserved;
 *  ULONG Offset;               Offset in file to begin write
 *  ULONG Timeout;
 *  USHORT WriteMode;           Write mode:
 *                              bit 0 - complete write to disk and send
 *                              final result response
 *                              bit 1 - return Remaining (pipe/dev)
 *                              (see WriteAndX for #defines)
 *  ULONG Reserved2;
 *  USHORT DataLength;          Number of data bytes this buffer
 *  USHORT DataOffset;          Offset (from header start) to data
 *  USHORT ByteCount;           Count of data bytes
 *  UCHAR Pad[];                Pad to SHORT or LONG
 *  UCHAR Data[];               Data (# = DataLength)
 *
 *  First Server Response          Description
 *  ============================== =====================================
 *
 *  UCHAR WordCount;               Count of parameter words = 1
 *  USHORT Remaining;              Bytes remaining to be read if pipe
 *  USHORT ByteCount;              Count of data bytes = 0
 *
 *  Final Server Response              Description
 *  ================================== =================================
 *
 *  UCHAR Command (in SMB header)      SMB_COM_WRITE_COMPLETE
 *
 *  UCHAR WordCount;                   Count of parameter words = 1
 *  USHORT Count;                      Total number of bytes written
 *  USHORT ByteCount;                  Count of data bytes = 0
 *
 * The first response format will be that of the final server response in
 * the case where the server gets an error while writing the data sent
 * along with the request.  Thus Count is the number of bytes which did get
 * written any time an error is returned.  If an error occurs after the
 * first response has been sent allowing the client to send the remaining
 * data, the final response should not be sent unless write through is set.
 * Rather the server should return this "write behind" error on the next
 * access to the Fid.
 *
 * The client must guarantee that there is (and will be) no other request
 * on the connection for the duration of this request.  The server will
 * reserve enough resources to receive the data and respond with a response
 * SMB as defined above.  The client then sends the raw data in one send.
 * Thus the server is able to receive up to 65,535 bytes of data directly
 * into the server buffer.  The amount of data transferred is expected to
 * be larger than the negotiated buffer size for this protocol.
 *
 * The reason that no other requests can be active on the connection for
 * the duration of the request is that if other receives are present on the
 * connection, there is normally no way to guarantee that the data will be
 * received into the correct server buffer, rather the data may fill one
 * (or more) of the other buffers.  Also if the client is sending other
 * requests on the connection, a request may land in the buffer that the
 * server has allocated for the this SMB's data.
 *
 * Whether or not SMB_COM_WRITE_RAW is supported is returned in the
 * response to SMB_COM_NEGOTIATE.  SMB_COM_WRITE_RAW is not supported for
 * connectionless clients.
 *
 * When write through is not specified ((WriteMode & 01) == 0) this SMB is
 * assumed to be a form of write behind.  The transport layer guarantees
 * delivery of all secondary requests from the client.  Thus no "got the
 * data you sent" SMB is needed.  If an error should occur at the server
 * end, all bytes must be received and thrown away.  If an error occurs
 * while writing data to disk such as disk full, the next access of the
 * file handle (another write, close, read, etc.) will return the fact that
 * the error occurred.
 *
 * If write through is specified ((WriteMode & 01) != 0), the server will
 * receive the data, write it to disk and then send a final response
 * indicating the result of the write.  The total number of bytes written
 * is also returned in this response in the Count field.
 *
 * The flow for the SMB_COM_WRITE_RAW SMB is:
 *
 * client -----> SMB_COM_WRITE_RAW request (optional data) >-------> server
 * client <------------------< OK send (more) data <---------------- server
 * client  ----------------------> raw data >----------------------> server
 * client  <---< data on disk or error (write through only) <------- server
 *
 * This protocol is set up such that the SMB_COM_WRITE_RAW request may also
 * carry data.  This is an optimization in that up to the server's buffer
 * size (MaxCount from SMB_COM_NEGOTIATE response), minus the size of the
 * SMB_COM_WRITE_RAW SMB request, may be sent along with the request.  Thus
 * if the server is busy and unable to support the raw write of the
 * remaining data, the data sent along with the request has been delivered
 * and need not be sent again.  The server will write any data sent in the
 * request (and wait for it to be on the disk or device if write through is
 * set), prior to sending the response.
 *
 * The specific responses error class ERRSRV, error codes ERRusempx and
 * ERRusestd, indicate that the server is temporarily out of the resources
 *
 * needed to support the raw write of the remaining data, but that any data
 * sent along with the request has been successfully written.  The client
 * should then write the remaining data using a different type of SMB write
 * request, or delay and retry using SMB_COM_WRITE_RAW.  If a write error
 * occurs writing the initial data, it will be returned and the write raw
 * request is implicitly denied.
 *
 * The return field Remaining is returned for named pipes only.  It is used
 * to return the number of bytes currently available in the pipe.  This
 * information can then be used by the client to know when a subsequent
 * (non blocking) read of the pipe may return some data.  Of course when
 * the read request is actually received by the server there may be more or
 * less actual data in the pipe (more data has been written to the pipe /
 * device or another reader drained it).  If the information is currently
 * not available or the request is NOT for a pipe or the server does not
 * support this feature, a -1 value should be returned.
 *
 * If the negotiated dialect is NT LM 0.12 or later, and the response to
 * the SMB_COM_NEGOTIATE SMB has CAP_LARGE_FILES set in the Capabilities
 * field, an additional request format is allowed which accommodates very
 * large files having 64 bit offsets:
 *
 *  Client Request                     Description
 *  ================================== =================================
 *   UCHAR WordCount;                   Count of parameter words = 14
 *   USHORT Fid;                       File handle
 *   USHORT Count;                     Total bytes, including this
 *                                      buffer
 *   USHORT Reserved;
 *   ULONG Offset;                     Offset in file to begin write
 *   ULONG Timeout;
 *   USHORT WriteMode;                 Write mode:
 *                                      bit 0 - complete write to disk
 *                                      and send final result response
 *                                      bit 1 - return Remaining
 *                                      (pipe/dev)
 *   ULONG Reserved2;
 *   USHORT DataLength;                Number of data bytes this buffer
 *   USHORT DataOffset;                Offset (from header start) to
 *                                      data
 *   ULONG OffsetHigh;                 Upper 32 bits of offset
 *   USHORT ByteCount;                  Count of data bytes
 *   UCHAR Pad[];                       Pad to SHORT or LONG
 *   UCHAR Data[];                     Data (# = DataLength)
 *
 * In this case the final offset in the file is formed by combining
 * OffsetHigh and Offset, the resulting offset must not be negative.
 */

#include <sys/sdt.h>
#include <smbsrv/smb_incl.h>
#include <smbsrv/smb_fsops.h>
#include <smbsrv/mbuf.h>
#include <smbsrv/netbios.h>

extern uint32_t smb_keep_alive;

static int smb_write_raw_helper(smb_request_t *, struct uio *, int,
    offset_t *, uint32_t *);
static int smb_transfer_write_raw_data(smb_request_t *, uint16_t);

#define	WR_MODE_WR_THRU	1

smb_sdrc_t
smb_pre_write_raw(smb_request_t *sr)
{
	int rc = 0;

	DTRACE_SMB_2(op__WriteRaw__start, smb_request_t *, sr,
	    smb_rw_param_t *, sr->arg.rw);

	return ((rc == 0) ? SDRC_SUCCESS : SDRC_ERROR);
}

void
smb_post_write_raw(smb_request_t *sr)
{
	DTRACE_SMB_2(op__WriteRaw__done, smb_request_t *, sr,
	    smb_rw_param_t *, sr->arg.rw);
}

smb_sdrc_t
smb_com_write_raw(struct smb_request *sr)
{
	int			rc = 0;
	int			session_send_rc = 0;
	unsigned short		addl_xfer_count;
	unsigned short		count;
	unsigned short		write_mode, data_offset, data_length;
	offset_t		off;
	uint32_t		off_low, off_high, timeout;
	uint32_t		lcount = 0;
	uint32_t		addl_lcount = 0;
	struct uio		uio;
	iovec_t			iovec;
	int			stability;
	struct mbuf_chain	reply;
	smb_node_t		*fnode;
	smb_error_t		err;

	if (sr->session->s_state != SMB_SESSION_STATE_WRITE_RAW_ACTIVE)
		return (SDRC_DROP_VC);

	if (sr->smb_wct == 12) {
		off_high = 0;
		rc = smbsr_decode_vwv(sr, "ww2.llw4.ww", &sr->smb_fid, &count,
		    &off_low, &timeout, &write_mode, &data_length,
		    &data_offset);
		data_offset -= 59;
	} else {
		rc = smbsr_decode_vwv(sr, "ww2.llw4.wwl", &sr->smb_fid, &count,
		    &off_low, &timeout, &write_mode, &data_length,
		    &data_offset, &off_high);
		data_offset -= 63;
	}

	if (rc != 0)
		return (SDRC_ERROR);

	off = ((offset_t)off_high << 32) | off_low;
	addl_xfer_count = count - data_length;

	sr->fid_ofile = smb_ofile_lookup_by_fid(sr->tid_tree, sr->smb_fid);
	if (sr->fid_ofile == NULL) {
		smbsr_error(sr, NT_STATUS_INVALID_HANDLE, ERRDOS, ERRbadfid);
		return (SDRC_ERROR);
	}

	fnode = sr->fid_ofile->f_node;
	stability = ((write_mode & WR_MODE_WR_THRU) ||
	    (fnode->flags & NODE_FLAGS_WRITE_THROUGH)) ? FSYNC : 0;

	if (STYPE_ISDSK(sr->tid_tree->t_res_type)) {
		/*
		 * See comments in smb_write.c
		 */
		if (fnode->attr.sa_vattr.va_type != VDIR) {
			rc = smb_lock_range_access(sr, fnode, off,
			    count, B_TRUE);
			if (rc != NT_STATUS_SUCCESS) {
				smbsr_error(sr, rc, ERRSRV, ERRaccess);
				return (SDRC_ERROR);
			}
		}
	}

	/*
	 * Make sure any raw write data that is supposed to be
	 * contained in this SMB is actually present.
	 */
	if (sr->smb_data.chain_offset + data_offset + data_length >
	    sr->smb_data.max_bytes) {
		/* Error handling code will wake up the session daemon */
		return (SDRC_ERROR);
	}

	/*
	 * Init uio (resid will get filled in later)
	 */
	uio.uio_iov = &iovec;
	uio.uio_iovcnt = 1;
	uio.uio_segflg = UIO_SYSSPACE;
	uio.uio_loffset = off;

	/*
	 * Send response if there is additional data to transfer.  This
	 * will prompt the client to send the remaining data.
	 */
	if (addl_xfer_count != 0) {
		MBC_INIT(&reply, MLEN);
		(void) smb_mbc_encodef(&reply, SMB_HEADER_ED_FMT "bww",
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
		    sr->smb_mid, 1, -1, 0);

		if (sr->session->signing.flags & SMB_SIGNING_ENABLED)
			smb_sign_reply(sr, &reply);

		session_send_rc = smb_session_send(sr->session, 0, &reply);

		/*
		 * If the session response failed we're not going to
		 * return an error just yet -- we can still write the
		 * data we received along with the SMB even if the
		 * response failed.  If it failed, we need to force the
		 * stability level to "write-through".
		 */
		stability = (session_send_rc == 0) ? stability : FSYNC;
	}

	/*
	 * While the response is in flight (and the data begins to arrive)
	 * write out the first data segment.  Start by setting up the
	 * iovec list for the first transfer.
	 */
	iovec.iov_base = sr->smb_data.chain->m_data +
	    sr->smb_data.chain_offset + data_offset;
	iovec.iov_len = data_length;
	uio.uio_resid = data_length;

	/*
	 * smb_write_raw_helper will call smb_opipe_write or
	 * smb_fsop_write as appropriate, handle the NODE_FLAGS_SET_SIZE
	 * flag (if set) and update the other f_node fields.  It's possible
	 * that data_length may be 0 for this transfer but we still want
	 * process it since it will update the file state (seek position,
	 * file size (possibly), etc).
	 */
	rc = smb_write_raw_helper(sr, &uio, stability, &off, &lcount);

	/*
	 * If our initial session response failed then we're done.  Return
	 * failure.  The client will know we wrote some of the data because
	 * of the transfer count (count - lcount) in the response.
	 */
	if (session_send_rc != 0) {
		sr->smb_rcls = ERRSRV;
		sr->smb_err  = ERRusestd;
		goto write_raw_transfer_failed;
	}

	/*
	 * If we have more data to read then go get it
	 */
	if (addl_xfer_count) {
		/*
		 * This is the only place where a worker thread should
		 * directly read from the session socket.  If the data
		 * is read successfully then the buffer (sr->sr_raw_data_buf)
		 * will need to be freed after the data is written.
		 */
		if (smb_transfer_write_raw_data(sr, addl_xfer_count) != 0) {
			/*
			 * Raw data transfer failed
			 */
			goto write_raw_transfer_failed;
		}

		/*
		 * Fill in next iov entry
		 */
		iovec.iov_base = sr->sr_raw_data_buf;
		iovec.iov_len = addl_xfer_count;
		uio.uio_resid = addl_xfer_count;
	}

	/*
	 * Wake up session daemon since we now have all of our data and
	 * it's safe for the session daemon to resume processing SMB's.
	 */
	sr->session->s_write_raw_status = 0;
	sr->session->s_state = SMB_SESSION_STATE_NEGOTIATED;

	/*
	 * If we didn't write all the data from the first segment then
	 * there's not much point in continuing (we still wanted to
	 * read any additional data above since we don't necessarily
	 * want to drop the connection and we need to read through
	 * to the next SMB).
	 */
	if ((rc != 0) || (lcount != data_length)) {
		goto notify_write_raw_complete;
	}

	/*
	 * Write any additional data
	 */
	if (addl_xfer_count) {
		rc = smb_write_raw_helper(sr, &uio, stability, &off,
		    &addl_lcount);
	}

	/*
	 * If we were called in "Write-behind" mode ((write_mode & 1) == 0)
	 * and the transfer was successful then we don't need to send
	 * any further response.  If we were called in "Write-Through" mode
	 * ((write_mode & 1) == 1) or if the transfer failed we need to
	 * send a completion notification.  The "count" value will indicate
	 * whether the transfer was successful.
	 */
	if ((rc != 0) || (write_mode & WR_MODE_WR_THRU) ||
	    (lcount + addl_lcount != count)) {
		goto notify_write_raw_complete;
	}

	/*
	 * Free raw write buffer (allocated in smb_transfer_write_raw_data)
	 */
	kmem_free(sr->sr_raw_data_buf, sr->sr_raw_data_length);

	(void) smb_session_send(sr->session, SESSION_KEEP_ALIVE, NULL);
	return (SDRC_NO_REPLY);

write_raw_transfer_failed:
	/*
	 * Raw data transfer failed, wake up session
	 * daemon
	 */
	sr->session->s_write_raw_status = 20;
	sr->session->s_state = SMB_SESSION_STATE_NEGOTIATED;

notify_write_raw_complete:
	/*
	 * If we had an error fill in the appropriate error code
	 */
	if (rc != 0) {
		smbsr_map_errno(rc, &err);
		smbsr_set_error(sr, &err);
	}

	/*
	 * Free raw write buffer if present (from smb_transfer_write_raw_data)
	 */
	if (sr->sr_raw_data_buf != NULL) {
		kmem_free(sr->sr_raw_data_buf, sr->sr_raw_data_length);
	}
	/* Write complete notification */
	sr->first_smb_com = SMB_COM_WRITE_COMPLETE;
	rc = smbsr_encode_result(sr, 1, 0, "bww", 1,
	    count - (lcount + addl_lcount), 0);
	return ((rc == 0) ? SDRC_SUCCESS : SDRC_ERROR);
}



/*
 * smb_write_raw_helper
 *
 * This function will call smb_opipe_write or smb_fsop_write as appropriate,
 * handle the NODE_FLAGS_SET_SIZE flag (if set) and update the other f_node
 * fields.  It's possible that data_length may be 0 for this transfer but
 * we still want process it since it will update the file state (seek
 * position, file size (possibly), etc).
 *
 * Returns 0 for success, non-zero for failure
 */
static int
smb_write_raw_helper(struct smb_request *sr, struct uio *uiop,
    int stability, offset_t *offp, uint32_t *lcountp)
{
	smb_node_t *fnode;
	int rc = 0;

	if (STYPE_ISIPC(sr->tid_tree->t_res_type)) {
		*lcountp = uiop->uio_resid;

		if ((rc = smb_opipe_write(sr, uiop)) != 0)
			*lcountp = 0;
	} else {
		fnode = sr->fid_ofile->f_node;
		rc = smb_fsop_write(sr, sr->user_cr, fnode,
		    uiop, lcountp, &fnode->attr, stability);

		if (rc == 0) {

			fnode->flags |= NODE_FLAGS_SYNCATIME;

			if (fnode->flags & NODE_FLAGS_SET_SIZE) {
				if ((*offp + *lcountp) >= fnode->n_size) {
					fnode->flags &= ~NODE_FLAGS_SET_SIZE;
					fnode->n_size = *offp + *lcountp;
				}
			}
		}
	}

	*offp += *lcountp;
	mutex_enter(&sr->fid_ofile->f_mutex);
	sr->fid_ofile->f_seek_pos = *offp;
	mutex_exit(&sr->fid_ofile->f_mutex);

	return (rc);
}


/*
 * smb_handle_write_raw
 *
 * Called from smb_session_daemon() when the SMB command is SMB_COM_WRITE_RAW.
 * Dispatches the command to the worker thread and waits until the worker
 * has completed processing the command.
 *
 * Returns 0 for success, non-zero for failure
 */
int
smb_handle_write_raw(smb_session_t *session, smb_request_t *sr)
{
	int	drop_reason = 0;

	/*
	 * Set flag to indicate that we are waiting for raw data.  The
	 * worker thread will actually retrieve the raw data directly
	 * from the socket.  This should be the only case when a worker
	 * thread reads from the session socket.  When the data is read
	 * the worker will clear the flag.
	 */
	smb_rwx_rwenter(&session->s_lock, RW_WRITER);
	switch (session->s_state) {
	case SMB_SESSION_STATE_NEGOTIATED:
	case SMB_SESSION_STATE_OPLOCK_BREAKING:
		session->s_state = SMB_SESSION_STATE_WRITE_RAW_ACTIVE;
		smb_rwx_rwexit(&session->s_lock);
		sr->sr_state = SMB_REQ_STATE_SUBMITTED;
		(void) taskq_dispatch(session->s_server->sv_thread_pool,
		    smb_session_worker, sr, TQ_SLEEP);
		smb_rwx_rwenter(&session->s_lock, RW_READER);
		while (session->s_state == SMB_SESSION_STATE_WRITE_RAW_ACTIVE) {
			(void) smb_rwx_rwwait(&session->s_lock, -1);
		}
		drop_reason = session->s_write_raw_status;
		break;
	default:
		drop_reason = 21;
		break;
	}
	smb_rwx_rwexit(&session->s_lock);
	return (drop_reason);
}

/*
 * smb_transfer_write_raw_data
 *
 * Handles the second transfer phase of SMB_COM_WRITE_RAW.  smb_com_write_raw()
 * will process the parameters and data from the SMB and send the initial
 * SMB response.  This function reads the remaining data from the socket
 * as it arrives from the client.
 *
 * Clients may send KEEP_ALIVE messages (when using NBT) between the first
 * and second parts of write raw requests.  The only session transport
 * types accepted here are SESSION_MESSAGE or SESSION_KEEP_ALIVE.
 *
 * Returns 0 for success, non-zero for failure
 */
int
smb_transfer_write_raw_data(smb_request_t *sr, uint16_t addl_xfer_count)
{
	smb_session_t *session = sr->session;
	smb_xprt_t hdr;
	uint8_t *data_buf;

	do {
		if (smb_session_xprt_gethdr(session, &hdr) != 0)
			return (-1);

		if ((hdr.xh_type == SESSION_MESSAGE) ||
		    (hdr.xh_type == SESSION_KEEP_ALIVE)) {
			session->keep_alive = smb_keep_alive;
		} else {
			return (-1);
		}
	} while (hdr.xh_type == SESSION_KEEP_ALIVE);

	if (hdr.xh_length < addl_xfer_count) {
		/*
		 * Less data than we were expecting.
		 */
		return (-1);
	}

	data_buf = kmem_alloc(hdr.xh_length, KM_SLEEP);

	if (smb_sorecv(session->sock, data_buf, hdr.xh_length) != 0) {
		kmem_free(data_buf, hdr.xh_length);
		sr->sr_raw_data_buf = NULL;
		sr->sr_raw_data_length = 0;
		return (-1);
	}

	sr->sr_raw_data_buf = data_buf;
	sr->sr_raw_data_length = hdr.xh_length;
	return (0);
}
