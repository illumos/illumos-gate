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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

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
#include <smbsrv/smb_kproto.h>
#include <smbsrv/smb_fsops.h>
#include <smbsrv/netbios.h>

extern uint32_t smb_keep_alive;

static int smb_transfer_write_raw_data(smb_request_t *, smb_rw_param_t *);

smb_sdrc_t
smb_pre_write_raw(smb_request_t *sr)
{
	smb_rw_param_t *param;
	uint32_t off_low;
	uint32_t timeout;
	uint32_t off_high;
	uint16_t datalen;
	uint16_t total;
	int rc;

	param = smb_srm_zalloc(sr, sizeof (smb_rw_param_t));
	sr->arg.rw = param;
	param->rw_magic = SMB_RW_MAGIC;

	if (sr->smb_wct == 12) {
		rc = smbsr_decode_vwv(sr, "ww2.llw4.ww", &sr->smb_fid, &total,
		    &off_low, &timeout, &param->rw_mode, &datalen,
		    &param->rw_dsoff);

		param->rw_offset = (uint64_t)off_low;
		param->rw_dsoff -= 59;
	} else {
		rc = smbsr_decode_vwv(sr, "ww2.llw4.wwl", &sr->smb_fid, &total,
		    &off_low, &timeout, &param->rw_mode, &datalen,
		    &param->rw_dsoff, &off_high);

		param->rw_offset = ((uint64_t)off_high << 32) | off_low;
		param->rw_dsoff -= 63;
	}

	param->rw_count = (uint32_t)datalen;
	param->rw_total = (uint32_t)total;
	param->rw_vdb.vdb_uio.uio_loffset = (offset_t)param->rw_offset;

	DTRACE_SMB_2(op__WriteRaw__start, smb_request_t *, sr,
	    smb_rw_param_t *, sr->arg.rw);

	smb_rwx_rwenter(&sr->session->s_lock, RW_WRITER);

	return ((rc == 0) ? SDRC_SUCCESS : SDRC_ERROR);
}

void
smb_post_write_raw(smb_request_t *sr)
{
	DTRACE_SMB_2(op__WriteRaw__done, smb_request_t *, sr,
	    smb_rw_param_t *, sr->arg.rw);

	smb_rwx_rwexit(&sr->session->s_lock);
}

smb_sdrc_t
smb_com_write_raw(struct smb_request *sr)
{
	smb_rw_param_t		*param = sr->arg.rw;
	int			rc = 0;
	int			session_send_rc = 0;
	uint16_t		addl_xfer_count;
	offset_t		addl_xfer_offset;
	struct mbuf_chain	reply;
	smb_error_t		err;

	if (sr->session->s_state != SMB_SESSION_STATE_WRITE_RAW_ACTIVE)
		return (SDRC_DROP_VC);

	smbsr_lookup_file(sr);
	if (sr->fid_ofile == NULL) {
		smbsr_error(sr, NT_STATUS_INVALID_HANDLE, ERRDOS, ERRbadfid);
		return (SDRC_ERROR);
	}

	sr->user_cr = smb_ofile_getcred(sr->fid_ofile);

	/*
	 * Send response if there is additional data to transfer.
	 * This will prompt the client to send the remaining data.
	 */
	addl_xfer_count = param->rw_total - param->rw_count;
	addl_xfer_offset = param->rw_count;

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
		 * If the response failed, force write-through and
		 * complete the write before dealing with the error.
		 */
		if (session_send_rc != 0)
			param->rw_mode = SMB_WRMODE_WRITE_THRU;
	}

	/*
	 * While the response is in flight (and the data begins to arrive)
	 * write out the first data segment.
	 */
	if (smbsr_decode_data(sr, "#.#B", param->rw_dsoff, param->rw_count,
	    &param->rw_vdb) != 0)
		return (SDRC_ERROR);

	if (param->rw_count > 0)
		rc = smb_common_write(sr, param);

	if (session_send_rc != 0) {
		sr->smb_rcls = ERRSRV;
		sr->smb_err  = ERRusestd;
		goto write_raw_transfer_failed;
	}

	/*
	 * If we have more data to read then go get it
	 */
	if (addl_xfer_count > 0) {
		/*
		 * This is the only place where a worker thread should
		 * directly read from the session socket.  If the data
		 * is read successfully then the buffer (sr->sr_raw_data_buf)
		 * will need to be freed after the data is written.
		 */
		param->rw_offset += addl_xfer_offset;
		param->rw_vdb.vdb_uio.uio_loffset = param->rw_offset;
		param->rw_vdb.vdb_iovec[0].iov_len = addl_xfer_count;
		param->rw_vdb.vdb_uio.uio_resid = addl_xfer_count;
		if (smb_transfer_write_raw_data(sr, param) != 0)
			goto write_raw_transfer_failed;
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
	if (rc != 0)
		goto notify_write_raw_complete;

	/*
	 * Write any additional data
	 */
	if (addl_xfer_count > 0) {
		rc = smb_common_write(sr, param);
		addl_xfer_offset += param->rw_count;
	}

	/*
	 * If we were called in "Write-behind" mode and the transfer was
	 * successful then we don't need to send any further response.
	 * If we were called in "Write-Through" mode or if the transfer
	 * failed we need to send a completion notification.  The "count"
	 * value will indicate whether the transfer was successful.
	 */
	if ((rc != 0) || SMB_WRMODE_IS_STABLE(param->rw_mode))
		goto notify_write_raw_complete;

	(void) smb_session_send(sr->session, SESSION_KEEP_ALIVE, NULL);
	return (SDRC_NO_REPLY);

write_raw_transfer_failed:
	/*
	 * Raw data transfer failed, wake up session daemon
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

	sr->first_smb_com = SMB_COM_WRITE_COMPLETE;
	rc = smbsr_encode_result(sr, 1, 0, "bww", 1, addl_xfer_offset, 0);
	return ((rc == 0) ? SDRC_SUCCESS : SDRC_ERROR);
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
smb_transfer_write_raw_data(smb_request_t *sr, smb_rw_param_t *param)
{
	smb_session_t *session = sr->session;
	smb_xprt_t hdr;
	void *pbuf;

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

	if (hdr.xh_length < param->rw_vdb.vdb_uio.uio_resid)
		return (-1); /* Less data than we were expecting. */

	pbuf = smb_srm_alloc(sr, hdr.xh_length);
	if (smb_sorecv(session->sock, pbuf, hdr.xh_length) != 0)
		return (-1);

	param->rw_vdb.vdb_iovec[0].iov_base = pbuf;
	param->rw_vdb.vdb_uio.uio_iovcnt = 1;
	param->rw_vdb.vdb_uio.uio_segflg = UIO_SYSSPACE;
	param->rw_vdb.vdb_uio.uio_extflg = UIO_COPY_DEFAULT;
	return (0);
}
