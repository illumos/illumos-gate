/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2015 Joyent, Inc.
 */

/*
 * Logic to manage an individual connection to a remote host.
 *
 * For more information, see the big theory statement in
 * lib/varpd/svp/common/libvarpd_svp.c.
 */

#include <assert.h>
#include <umem.h>
#include <errno.h>
#include <strings.h>
#include <unistd.h>
#include <stddef.h>
#include <sys/uio.h>
#include <sys/debug.h>

#include <libvarpd_svp.h>

int svp_conn_query_timeout = 30;
static int svp_conn_backoff_tbl[] = { 1, 2, 4, 8, 16, 32 };
static int svp_conn_nbackoff = sizeof (svp_conn_backoff_tbl) / sizeof (int);

typedef enum svp_conn_act {
	SVP_RA_NONE	= 0x00,
	SVP_RA_DEGRADE	= 0x01,
	SVP_RA_RESTORE	= 0x02,
	SVP_RA_ERROR	= 0x03,
	SVP_RA_CLEANUP	= 0x04
} svp_conn_act_t;

static void
svp_conn_inject(svp_conn_t *scp)
{
	int ret;
	assert(MUTEX_HELD(&scp->sc_lock));

	if (scp->sc_flags & SVP_CF_USER)
		return;
	scp->sc_flags |= SVP_CF_USER;
	if ((ret = svp_event_inject(&scp->sc_event)) != 0)
		libvarpd_panic("failed to inject event: %d\n", ret);
}

static void
svp_conn_degrade(svp_conn_t *scp)
{
	svp_remote_t *srp = scp->sc_remote;

	assert(MUTEX_HELD(&srp->sr_lock));
	assert(MUTEX_HELD(&scp->sc_lock));

	if (scp->sc_flags & SVP_CF_DEGRADED)
		return;

	scp->sc_flags |= SVP_CF_DEGRADED;
	srp->sr_ndconns++;
	if (srp->sr_ndconns == srp->sr_tconns)
		svp_remote_degrade(srp, SVP_RD_REMOTE_FAIL);
}

static void
svp_conn_restore(svp_conn_t *scp)
{
	svp_remote_t *srp = scp->sc_remote;

	assert(MUTEX_HELD(&srp->sr_lock));
	assert(MUTEX_HELD(&scp->sc_lock));

	if (!(scp->sc_flags & SVP_CF_DEGRADED))
		return;

	scp->sc_flags &= ~SVP_CF_DEGRADED;
	if (srp->sr_ndconns == srp->sr_tconns)
		svp_remote_restore(srp, SVP_RD_REMOTE_FAIL);
	srp->sr_ndconns--;
}

static void
svp_conn_add(svp_conn_t *scp)
{
	svp_remote_t *srp = scp->sc_remote;

	assert(MUTEX_HELD(&srp->sr_lock));
	assert(MUTEX_HELD(&scp->sc_lock));

	if (scp->sc_flags & SVP_CF_ADDED)
		return;

	list_insert_tail(&srp->sr_conns, scp);
	scp->sc_flags |= SVP_CF_ADDED;
	srp->sr_tconns++;
}

static void
svp_conn_remove(svp_conn_t *scp)
{
	svp_remote_t *srp = scp->sc_remote;

	assert(MUTEX_HELD(&srp->sr_lock));
	assert(MUTEX_HELD(&scp->sc_lock));

	if (!(scp->sc_flags & SVP_CF_ADDED))
		return;

	scp->sc_flags &= ~SVP_CF_ADDED;
	if (scp->sc_flags & SVP_CF_DEGRADED)
		srp->sr_ndconns--;
	srp->sr_tconns--;
	if (srp->sr_tconns == srp->sr_ndconns)
		svp_remote_degrade(srp, SVP_RD_REMOTE_FAIL);
}

static svp_query_t *
svp_conn_query_find(svp_conn_t *scp, uint32_t id)
{
	svp_query_t *sqp;

	assert(MUTEX_HELD(&scp->sc_lock));

	for (sqp = list_head(&scp->sc_queries); sqp != NULL;
	    sqp = list_next(&scp->sc_queries, sqp)) {
		if (sqp->sq_header.svp_id == id)
			break;
	}

	return (sqp);
}

static svp_conn_act_t
svp_conn_backoff(svp_conn_t *scp)
{
	assert(MUTEX_HELD(&scp->sc_lock));

	if (close(scp->sc_socket) != 0)
		libvarpd_panic("failed to close socket %d: %d\n",
		    scp->sc_socket, errno);
	scp->sc_socket = -1;

	scp->sc_cstate = SVP_CS_BACKOFF;
	scp->sc_nbackoff++;
	if (scp->sc_nbackoff >= svp_conn_nbackoff) {
		scp->sc_btimer.st_value =
		    svp_conn_backoff_tbl[svp_conn_nbackoff - 1];
	} else {
		scp->sc_btimer.st_value =
		    svp_conn_backoff_tbl[scp->sc_nbackoff - 1];
	}
	svp_timer_add(&scp->sc_btimer);

	if (scp->sc_nbackoff > svp_conn_nbackoff)
		return (SVP_RA_DEGRADE);
	return (SVP_RA_NONE);
}

static svp_conn_act_t
svp_conn_connect(svp_conn_t *scp)
{
	int ret;
	struct sockaddr_in6 in6;

	assert(MUTEX_HELD(&scp->sc_lock));
	assert(scp->sc_cstate == SVP_CS_BACKOFF ||
	    scp->sc_cstate == SVP_CS_INITIAL);
	assert(scp->sc_socket == -1);
	if (scp->sc_cstate == SVP_CS_INITIAL)
		scp->sc_nbackoff = 0;

	scp->sc_socket = socket(AF_INET6, SOCK_STREAM | SOCK_NONBLOCK, 0);
	if (scp->sc_socket == -1) {
		scp->sc_error = SVP_CE_SOCKET;
		scp->sc_errno = errno;
		scp->sc_cstate = SVP_CS_ERROR;
		return (SVP_RA_DEGRADE);
	}

	bzero(&in6, sizeof (struct sockaddr_in6));
	in6.sin6_family = AF_INET6;
	in6.sin6_port = htons(scp->sc_remote->sr_rport);
	bcopy(&scp->sc_addr, &in6.sin6_addr,  sizeof (struct in6_addr));
	ret = connect(scp->sc_socket, (struct sockaddr *)&in6,
	    sizeof (struct sockaddr_in6));
	if (ret != 0) {
		boolean_t async = B_FALSE;

		switch (errno) {
		case EACCES:
		case EADDRINUSE:
		case EAFNOSUPPORT:
		case EALREADY:
		case EBADF:
		case EISCONN:
		case ELOOP:
		case ENOENT:
		case ENOSR:
		case EWOULDBLOCK:
			libvarpd_panic("unanticipated connect errno %d", errno);
			break;
		case EINPROGRESS:
		case EINTR:
			async = B_TRUE;
		default:
			break;
		}

		/*
		 * So, we will be connecting to this in the future, advance our
		 * state and make sure that we poll for the next round.
		 */
		if (async == B_TRUE) {
			scp->sc_cstate = SVP_CS_CONNECTING;
			scp->sc_event.se_events = POLLOUT | POLLHUP;
			ret = svp_event_associate(&scp->sc_event,
			    scp->sc_socket);
			if (ret == 0)
				return (SVP_RA_NONE);
			scp->sc_error = SVP_CE_ASSOCIATE;
			scp->sc_errno = ret;
			scp->sc_cstate = SVP_CS_ERROR;
			return (SVP_RA_DEGRADE);
		} else {
			/*
			 * This call failed, which means that we obtained one of
			 * the following:
			 *
			 * EADDRNOTAVAIL
			 * ECONNREFUSED
			 * EIO
			 * ENETUNREACH
			 * EHOSTUNREACH
			 * ENXIO
			 * ETIMEDOUT
			 *
			 * Therefore we need to set ourselves into backoff and
			 * wait for that to clear up.
			 */
			return (svp_conn_backoff(scp));
		}
	}

	/*
	 * We've connected. Successfully move ourselves to the bound
	 * state and start polling.
	 */
	scp->sc_cstate = SVP_CS_ACTIVE;
	scp->sc_event.se_events = POLLIN | POLLRDNORM | POLLHUP;
	ret = svp_event_associate(&scp->sc_event, scp->sc_socket);
	if (ret == 0)
		return (SVP_RA_RESTORE);
	scp->sc_error = SVP_CE_ASSOCIATE;
	scp->sc_cstate = SVP_CS_ERROR;

	return (SVP_RA_DEGRADE);
}

/*
 * This should be the first call we get after a connect. If we have successfully
 * connected, we should see a writeable event. We may also see an error or a
 * hang up. In either of these cases, we transition to error mode. If there is
 * also a readable event, we ignore it at the moment and just let a
 * reassociation pick it up so we can simplify the set of state transitions that
 * we have.
 */
static svp_conn_act_t
svp_conn_poll_connect(port_event_t *pe, svp_conn_t *scp)
{
	int ret, err;
	socklen_t sl = sizeof (err);
	if (!(pe->portev_events & POLLOUT)) {
		scp->sc_errno = 0;
		scp->sc_error = SVP_CE_NOPOLLOUT;
		scp->sc_cstate = SVP_CS_ERROR;
		return (SVP_RA_DEGRADE);
	}

	ret = getsockopt(scp->sc_socket, SOL_SOCKET, SO_ERROR, &err, &sl);
	if (ret != 0)
		libvarpd_panic("unanticipated getsockopt error");
	if (err != 0) {
		return (svp_conn_backoff(scp));
	}

	scp->sc_cstate = SVP_CS_ACTIVE;
	scp->sc_event.se_events = POLLIN | POLLRDNORM | POLLHUP;
	ret = svp_event_associate(&scp->sc_event, scp->sc_socket);
	if (ret == 0)
		return (SVP_RA_RESTORE);
	scp->sc_error = SVP_CE_ASSOCIATE;
	scp->sc_errno = ret;
	scp->sc_cstate = SVP_CS_ERROR;
	return (SVP_RA_DEGRADE);
}

static svp_conn_act_t
svp_conn_pollout(svp_conn_t *scp)
{
	svp_query_t *sqp;
	svp_req_t *req;
	size_t off;
	struct iovec iov[2];
	int nvecs = 0;
	ssize_t ret;

	assert(MUTEX_HELD(&scp->sc_lock));

	/*
	 * We need to find a query and start writing it out.
	 */
	if (scp->sc_output.sco_query == NULL) {
		for (sqp = list_head(&scp->sc_queries); sqp != NULL;
		    sqp = list_next(&scp->sc_queries, sqp)) {
			if (sqp->sq_state != SVP_QUERY_INIT)
				continue;
			break;
		}

		if (sqp == NULL) {
			scp->sc_event.se_events &= ~POLLOUT;
			return (SVP_RA_NONE);
		}

		scp->sc_output.sco_query = sqp;
		scp->sc_output.sco_offset = 0;
		sqp->sq_state = SVP_QUERY_WRITING;
		svp_query_crc32(&sqp->sq_header, sqp->sq_rdata, sqp->sq_rsize);
	}

	sqp = scp->sc_output.sco_query;
	req = &sqp->sq_header;
	off = scp->sc_output.sco_offset;
	if (off < sizeof (svp_req_t)) {
		iov[nvecs].iov_base = (void *)((uintptr_t)req + off);
		iov[nvecs].iov_len = sizeof (svp_req_t) - off;
		nvecs++;
		off = 0;
	} else {
		off -= sizeof (svp_req_t);
	}

	iov[nvecs].iov_base = (void *)((uintptr_t)sqp->sq_rdata + off);
	iov[nvecs].iov_len = sqp->sq_rsize - off;
	nvecs++;

	do {
		ret = writev(scp->sc_socket, iov, nvecs);
	} while (ret == -1 && errno == EAGAIN);
	if (ret == -1) {
		switch (errno) {
		case EAGAIN:
			scp->sc_event.se_events |= POLLOUT;
			return (SVP_RA_NONE);
		case EIO:
		case ENXIO:
		case ECONNRESET:
			return (SVP_RA_ERROR);
		default:
			libvarpd_panic("unexpected errno: %d", errno);
		}
	}

	sqp->sq_acttime = gethrtime();
	scp->sc_output.sco_offset += ret;
	if (ret >= sizeof (svp_req_t) + sqp->sq_rsize) {
		sqp->sq_state = SVP_QUERY_READING;
		scp->sc_output.sco_query = NULL;
		scp->sc_output.sco_offset = 0;
		scp->sc_event.se_events |= POLLOUT;
	}
	return (SVP_RA_NONE);
}

static boolean_t
svp_conn_pollin_validate(svp_conn_t *scp)
{
	svp_query_t *sqp;
	uint32_t nsize;
	uint16_t nvers, nop;
	svp_req_t *resp = &scp->sc_input.sci_req;

	assert(MUTEX_HELD(&scp->sc_lock));

	nvers = ntohs(resp->svp_ver);
	nop = ntohs(resp->svp_op);
	nsize = ntohl(resp->svp_size);

	if (nvers != SVP_CURRENT_VERSION) {
		(void) bunyan_warn(svp_bunyan, "unsupported version",
		    BUNYAN_T_IP, "remote_ip", &scp->sc_addr,
		    BUNYAN_T_INT32, "remote_port", scp->sc_remote->sr_rport,
		    BUNYAN_T_INT32, "version", nvers,
		    BUNYAN_T_INT32, "operation", nop,
		    BUNYAN_T_INT32, "response_id", resp->svp_id,
		    BUNYAN_T_END);
		return (B_FALSE);
	}

	if (nop != SVP_R_VL2_ACK && nop != SVP_R_VL3_ACK &&
	    nop != SVP_R_LOG_ACK && nop != SVP_R_LOG_RM_ACK) {
		(void) bunyan_warn(svp_bunyan, "unsupported operation",
		    BUNYAN_T_IP, "remote_ip", &scp->sc_addr,
		    BUNYAN_T_INT32, "remote_port", scp->sc_remote->sr_rport,
		    BUNYAN_T_INT32, "version", nvers,
		    BUNYAN_T_INT32, "operation", nop,
		    BUNYAN_T_INT32, "response_id", resp->svp_id,
		    BUNYAN_T_END);
		return (B_FALSE);
	}

	sqp = svp_conn_query_find(scp, resp->svp_id);
	if (sqp == NULL) {
		(void) bunyan_warn(svp_bunyan, "unknown response id",
		    BUNYAN_T_IP, "remote_ip", &scp->sc_addr,
		    BUNYAN_T_INT32, "remote_port", scp->sc_remote->sr_rport,
		    BUNYAN_T_INT32, "version", nvers,
		    BUNYAN_T_INT32, "operation", nop,
		    BUNYAN_T_INT32, "response_id", resp->svp_id,
		    BUNYAN_T_END);
		return (B_FALSE);
	}

	if (sqp->sq_state != SVP_QUERY_READING) {
		(void) bunyan_warn(svp_bunyan,
		    "got response for unexpecting query",
		    BUNYAN_T_IP, "remote_ip", &scp->sc_addr,
		    BUNYAN_T_INT32, "remote_port", scp->sc_remote->sr_rport,
		    BUNYAN_T_INT32, "version", nvers,
		    BUNYAN_T_INT32, "operation", nop,
		    BUNYAN_T_INT32, "response_id", resp->svp_id,
		    BUNYAN_T_INT32, "query_state", sqp->sq_state,
		    BUNYAN_T_END);
		return (B_FALSE);
	}

	if ((nop == SVP_R_VL2_ACK && nsize != sizeof (svp_vl2_ack_t)) ||
	    (nop == SVP_R_VL3_ACK && nsize != sizeof (svp_vl3_ack_t)) ||
	    (nop == SVP_R_LOG_RM_ACK && nsize != sizeof (svp_lrm_ack_t))) {
		(void) bunyan_warn(svp_bunyan, "response size too large",
		    BUNYAN_T_IP, "remote_ip", &scp->sc_addr,
		    BUNYAN_T_INT32, "remote_port", scp->sc_remote->sr_rport,
		    BUNYAN_T_INT32, "version", nvers,
		    BUNYAN_T_INT32, "operation", nop,
		    BUNYAN_T_INT32, "response_id", resp->svp_id,
		    BUNYAN_T_INT32, "response_size", nsize,
		    BUNYAN_T_INT32, "expected_size", nop == SVP_R_VL2_ACK ?
		    sizeof (svp_vl2_ack_t) : sizeof (svp_vl3_ack_t),
		    BUNYAN_T_INT32, "query_state", sqp->sq_state,
		    BUNYAN_T_END);
		return (B_FALSE);
	}

	/*
	 * The valid size is anything <= to what the user requested, but at
	 * least svp_log_ack_t bytes large.
	 */
	if (nop == SVP_R_LOG_ACK) {
		const char *msg = NULL;
		if (nsize < sizeof (svp_log_ack_t))
			msg = "response size too small";
		else if (nsize > ((svp_log_req_t *)sqp->sq_rdata)->svlr_count)
			msg = "response size too large";
		if (msg != NULL) {
			(void) bunyan_warn(svp_bunyan, msg,
			    BUNYAN_T_IP, "remote_ip", &scp->sc_addr,
			    BUNYAN_T_INT32, "remote_port",
			    scp->sc_remote->sr_rport,
			    BUNYAN_T_INT32, "version", nvers,
			    BUNYAN_T_INT32, "operation", nop,
			    BUNYAN_T_INT32, "response_id", resp->svp_id,
			    BUNYAN_T_INT32, "response_size", nsize,
			    BUNYAN_T_INT32, "expected_size",
			    ((svp_log_req_t *)sqp->sq_rdata)->svlr_count,
			    BUNYAN_T_INT32, "query_state", sqp->sq_state,
			    BUNYAN_T_END);
			return (B_FALSE);
		}
	}

	sqp->sq_size = nsize;
	scp->sc_input.sci_query = sqp;
	if (nop == SVP_R_VL2_ACK || nop == SVP_R_VL3_ACK ||
	    nop == SVP_R_LOG_RM_ACK) {
		sqp->sq_wdata = &sqp->sq_wdun;
		sqp->sq_wsize = sizeof (svp_query_data_t);
	} else {
		VERIFY(nop == SVP_R_LOG_ACK);
		assert(sqp->sq_wdata != NULL);
		assert(sqp->sq_wsize != 0);
	}

	return (B_TRUE);
}

static svp_conn_act_t
svp_conn_pollin(svp_conn_t *scp)
{
	size_t off, total;
	ssize_t ret;
	svp_query_t *sqp;
	uint32_t crc;
	uint16_t nop;

	assert(MUTEX_HELD(&scp->sc_lock));

	/*
	 * No query implies that we're reading in the header and that the offset
	 * is associted with it.
	 */
	off = scp->sc_input.sci_offset;
	sqp = scp->sc_input.sci_query;
	if (scp->sc_input.sci_query == NULL) {
		svp_req_t *resp = &scp->sc_input.sci_req;

		assert(off < sizeof (svp_req_t));

		do {
			ret = read(scp->sc_socket,
			    (void *)((uintptr_t)resp + off),
			    sizeof (svp_req_t) - off);
		} while (ret == -1 && errno == EINTR);
		if (ret == -1) {
			switch (errno) {
			case EAGAIN:
				scp->sc_event.se_events |= POLLIN | POLLRDNORM;
				return (SVP_RA_NONE);
			case EIO:
			case ECONNRESET:
				return (SVP_RA_ERROR);
				break;
			default:
				libvarpd_panic("unexpeted read errno: %d",
				    errno);
			}
		} else if (ret == 0) {
			/* Try to reconnect to the remote host */
			return (SVP_RA_ERROR);
		}

		/* Didn't get all the data we need */
		if (off + ret < sizeof (svp_req_t)) {
			scp->sc_input.sci_offset += ret;
			scp->sc_event.se_events |= POLLIN | POLLRDNORM;
			return (SVP_RA_NONE);
		}

		if (svp_conn_pollin_validate(scp) != B_TRUE)
			return (SVP_RA_ERROR);
	}

	sqp = scp->sc_input.sci_query;
	assert(sqp != NULL);
	sqp->sq_acttime = gethrtime();
	total = ntohl(scp->sc_input.sci_req.svp_size);
	do {
		ret = read(scp->sc_socket,
		    (void *)((uintptr_t)sqp->sq_wdata + off),
		    total - off);
	} while (ret == -1 && errno == EINTR);

	if (ret == -1) {
		switch (errno) {
		case EAGAIN:
			scp->sc_event.se_events |= POLLIN | POLLRDNORM;
			return (SVP_RA_NONE);
		case EIO:
		case ECONNRESET:
			return (SVP_RA_ERROR);
			break;
		default:
			libvarpd_panic("unexpeted read errno: %d", errno);
		}
	} else if (ret == 0) {
		/* Try to reconnect to the remote host */
		return (SVP_RA_ERROR);
	}

	if (ret + off < total) {
		scp->sc_input.sci_offset += ret;
		return (SVP_RA_NONE);
	}

	nop = ntohs(scp->sc_input.sci_req.svp_op);
	crc = scp->sc_input.sci_req.svp_crc32;
	svp_query_crc32(&scp->sc_input.sci_req, sqp->sq_wdata, total);
	if (crc != scp->sc_input.sci_req.svp_crc32) {
		(void) bunyan_info(svp_bunyan, "crc32 mismatch",
		    BUNYAN_T_IP, "remote ip", &scp->sc_addr,
		    BUNYAN_T_INT32, "remote port", scp->sc_remote->sr_rport,
		    BUNYAN_T_INT32, "version",
		    ntohs(scp->sc_input.sci_req.svp_ver),
		    BUNYAN_T_INT32, "operation", nop,
		    BUNYAN_T_INT32, "response id",
		    ntohl(scp->sc_input.sci_req.svp_id),
		    BUNYAN_T_INT32, "query state", sqp->sq_state,
		    BUNYAN_T_UINT32, "msg_crc", ntohl(crc),
		    BUNYAN_T_UINT32, "calc_crc",
		    ntohl(scp->sc_input.sci_req.svp_crc32),
		    BUNYAN_T_END);
		return (SVP_RA_ERROR);
	}
	scp->sc_input.sci_query = NULL;
	scp->sc_input.sci_offset = 0;

	if (nop == SVP_R_VL2_ACK) {
		svp_vl2_ack_t *sl2a = sqp->sq_wdata;
		sqp->sq_status = ntohl(sl2a->sl2a_status);
	} else if (nop == SVP_R_VL3_ACK) {
		svp_vl3_ack_t *sl3a = sqp->sq_wdata;
		sqp->sq_status = ntohl(sl3a->sl3a_status);
	} else if (nop == SVP_R_LOG_ACK) {
		svp_log_ack_t *svla = sqp->sq_wdata;
		sqp->sq_status = ntohl(svla->svla_status);
	} else if (nop == SVP_R_LOG_RM_ACK) {
		svp_lrm_ack_t *svra = sqp->sq_wdata;
		sqp->sq_status = ntohl(svra->svra_status);
	} else {
		libvarpd_panic("unhandled nop: %d", nop);
	}

	list_remove(&scp->sc_queries, sqp);
	mutex_exit(&scp->sc_lock);

	/*
	 * We have to release all of our resources associated with this entry
	 * before we call the callback. After we call it, the memory will be
	 * lost to time.
	 */
	svp_query_release(sqp);
	sqp->sq_func(sqp, sqp->sq_arg);
	mutex_enter(&scp->sc_lock);
	scp->sc_event.se_events |= POLLIN | POLLRDNORM;

	return (SVP_RA_NONE);
}

static svp_conn_act_t
svp_conn_reset(svp_conn_t *scp)
{
	svp_remote_t *srp = scp->sc_remote;

	assert(MUTEX_HELD(&srp->sr_lock));
	assert(MUTEX_HELD(&scp->sc_lock));

	assert(svp_event_dissociate(&scp->sc_event, scp->sc_socket) ==
	    ENOENT);
	if (close(scp->sc_socket) != 0)
		libvarpd_panic("failed to close socket %d: %d", scp->sc_socket,
		    errno);
	scp->sc_flags &= ~SVP_CF_TEARDOWN;
	scp->sc_socket = -1;
	scp->sc_cstate = SVP_CS_INITIAL;
	scp->sc_input.sci_query = NULL;
	scp->sc_output.sco_query = NULL;

	svp_remote_reassign(srp, scp);

	return (svp_conn_connect(scp));
}

/*
 * This is our general state transition function. We're called here when we want
 * to advance part of our state machine as well as to re-arm ourselves. We can
 * also end up here from the standard event loop as a result of having a user
 * event posted.
 */
static void
svp_conn_handler(port_event_t *pe, void *arg)
{
	svp_conn_t *scp = arg;
	svp_remote_t *srp = scp->sc_remote;
	svp_conn_act_t ret = SVP_RA_NONE;
	svp_conn_state_t oldstate;

	mutex_enter(&scp->sc_lock);

	/*
	 * Check if one of our event interrupts is set. An event interrupt, such
	 * as having to be reaped or be torndown is notified by a
	 * PORT_SOURCE_USER event that tries to take care of this. However,
	 * because of the fact that the event loop can be ongoing despite this,
	 * we may get here before the PORT_SOURCE_USER has casued us to get
	 * here. In such a case, if the PORT_SOURCE_USER event is tagged, then
	 * we're going to opt to do nothing here and wait for it to come and
	 * tear us down. That will also indicate to us that we have nothing to
	 * worry about as far as general timing and the like goes.
	 */
	if ((scp->sc_flags & SVP_CF_UFLAG) != 0 &&
	    (scp->sc_flags & SVP_CF_USER) != 0 &&
	    pe != NULL &&
	    pe->portev_source != PORT_SOURCE_USER) {
		mutex_exit(&scp->sc_lock);
		return;
	}

	if (pe != NULL && pe->portev_source == PORT_SOURCE_USER) {
		scp->sc_flags &= ~SVP_CF_USER;
		if ((scp->sc_flags & SVP_CF_UFLAG) == 0) {
			mutex_exit(&scp->sc_lock);
			return;
		}
	}

	/* Check if this needs to be freed */
	if (scp->sc_flags & SVP_CF_REAP) {
		mutex_exit(&scp->sc_lock);
		svp_conn_destroy(scp);
		return;
	}

	/* Check if this needs to be reset */
	if (scp->sc_flags & SVP_CF_TEARDOWN) {
		/* Make sure any other users of this are disassociated */
		ret = SVP_RA_ERROR;
		goto out;
	}

	switch (scp->sc_cstate) {
	case SVP_CS_INITIAL:
	case SVP_CS_BACKOFF:
		assert(pe == NULL);
		ret = svp_conn_connect(scp);
		break;
	case SVP_CS_CONNECTING:
		assert(pe != NULL);
		ret = svp_conn_poll_connect(pe, scp);
		break;
	case SVP_CS_ACTIVE:
	case SVP_CS_WINDDOWN:
		assert(pe != NULL);
		oldstate = scp->sc_cstate;
		if (pe->portev_events & POLLOUT)
			ret = svp_conn_pollout(scp);
		if (ret == SVP_RA_NONE && (pe->portev_events & POLLIN))
			ret = svp_conn_pollin(scp);

		if (oldstate == SVP_CS_WINDDOWN &&
		    (list_is_empty(&scp->sc_queries) || ret != SVP_RA_NONE)) {
			ret = SVP_RA_CLEANUP;
		}

		if (ret == SVP_RA_NONE) {
			int err;
			if ((err = svp_event_associate(&scp->sc_event,
			    scp->sc_socket)) != 0) {
				scp->sc_error = SVP_CE_ASSOCIATE;
				scp->sc_errno = err;
				scp->sc_cstate = SVP_CS_ERROR;
				ret = SVP_RA_DEGRADE;
			}
		}
		break;
	default:
		libvarpd_panic("svp_conn_handler encountered unexpected "
		    "state: %d", scp->sc_cstate);
	}
out:
	mutex_exit(&scp->sc_lock);

	if (ret == SVP_RA_NONE)
		return;

	mutex_enter(&srp->sr_lock);
	mutex_enter(&scp->sc_lock);
	if (ret == SVP_RA_ERROR)
		ret = svp_conn_reset(scp);

	if (ret == SVP_RA_DEGRADE)
		svp_conn_degrade(scp);
	if (ret == SVP_RA_RESTORE)
		svp_conn_restore(scp);

	if (ret == SVP_RA_CLEANUP) {
		svp_conn_remove(scp);
		scp->sc_flags |= SVP_CF_REAP;
		svp_conn_inject(scp);
	}
	mutex_exit(&scp->sc_lock);
	mutex_exit(&srp->sr_lock);
}

static void
svp_conn_backtimer(void *arg)
{
	svp_conn_t *scp = arg;

	svp_conn_handler(NULL, scp);
}

/*
 * This fires every svp_conn_query_timeout seconds. Its purpos is to determine
 * if we haven't heard back on a request with in svp_conn_query_timeout seconds.
 * If any of the svp_conn_query_t's that have been started (indicated by
 * svp_query_t`sq_acttime != -1), and more than svp_conn_query_timeout seconds
 * have passed, we basically tear this connection down and reassign outstanding
 * queries.
 */
static void
svp_conn_querytimer(void *arg)
{
	int ret;
	svp_query_t *sqp;
	svp_conn_t *scp = arg;
	hrtime_t now = gethrtime();

	mutex_enter(&scp->sc_lock);

	/*
	 * If we're not in the active state, then we don't care about this as
	 * we're already either going to die or we have no connections to worry
	 * about.
	 */
	if (scp->sc_cstate != SVP_CS_ACTIVE) {
		mutex_exit(&scp->sc_lock);
		return;
	}

	for (sqp = list_head(&scp->sc_queries); sqp != NULL;
	    sqp = list_next(&scp->sc_queries, sqp)) {
		if (sqp->sq_acttime == -1)
			continue;
		if ((now - sqp->sq_acttime) / NANOSEC > svp_conn_query_timeout)
			break;
	}

	/* Nothing timed out, we're good here */
	if (sqp == NULL) {
		mutex_exit(&scp->sc_lock);
		return;
	}

	(void) bunyan_warn(svp_bunyan, "query timed out on connection",
	    BUNYAN_T_IP, "remote_ip", &scp->sc_addr,
	    BUNYAN_T_INT32, "remote_port", scp->sc_remote->sr_rport,
	    BUNYAN_T_INT32, "operation", ntohs(sqp->sq_header.svp_op),
	    BUNYAN_T_END);

	/*
	 * Begin the tear down process for this connect. If we lose the
	 * disassociate, then we don't inject an event. See the big theory
	 * statement in libvarpd_svp.c for more information.
	 */
	scp->sc_flags |= SVP_CF_TEARDOWN;

	ret = svp_event_dissociate(&scp->sc_event, scp->sc_socket);
	if (ret == 0)
		svp_conn_inject(scp);
	else
		VERIFY(ret == ENOENT);

	mutex_exit(&scp->sc_lock);
}

/*
 * This connection has fallen out of DNS, figure out what we need to do with it.
 */
void
svp_conn_fallout(svp_conn_t *scp)
{
	svp_remote_t *srp = scp->sc_remote;

	assert(MUTEX_HELD(&srp->sr_lock));

	mutex_enter(&scp->sc_lock);
	switch (scp->sc_cstate) {
	case SVP_CS_ERROR:
		/*
		 * Connection is already inactive, so it's safe to tear down.
		 * Fire it off through the state machine to tear down via the
		 * backoff timer.
		 */
		svp_conn_remove(scp);
		scp->sc_flags |= SVP_CF_REAP;
		svp_conn_inject(scp);
		break;
	case SVP_CS_INITIAL:
	case SVP_CS_BACKOFF:
	case SVP_CS_CONNECTING:
		/*
		 * Here, we have something actively going on, so we'll let it be
		 * clean up the next time we hit the event loop by the event
		 * loop itself. As it has no connections, there isn't much to
		 * really do, though we'll take this chance to go ahead and
		 * remove it from the remote.
		 */
		svp_conn_remove(scp);
		scp->sc_flags |= SVP_CF_REAP;
		svp_conn_inject(scp);
		break;
	case SVP_CS_ACTIVE:
	case SVP_CS_WINDDOWN:
		/*
		 * If there are no outstanding queries, then we should simply
		 * clean this up now,t he same way we would with the others.
		 * Othewrise, as we know the event loop is ongoing, we'll make
		 * sure that these entries get cleaned up once they're done.
		 */
		scp->sc_cstate = SVP_CS_WINDDOWN;
		if (list_is_empty(&scp->sc_queries)) {
			svp_conn_remove(scp);
			scp->sc_flags |= SVP_CF_REAP;
			svp_conn_inject(scp);
		}
		break;
	default:
		libvarpd_panic("svp_conn_fallout encountered"
		    "unkonwn state");
	}
	mutex_exit(&scp->sc_lock);
}

int
svp_conn_create(svp_remote_t *srp, const struct in6_addr *addr)
{
	int ret;
	svp_conn_t *scp;

	assert(MUTEX_HELD(&srp->sr_lock));
	scp = umem_zalloc(sizeof (svp_conn_t), UMEM_DEFAULT);
	if (scp == NULL)
		return (ENOMEM);

	if ((ret = mutex_init(&scp->sc_lock, USYNC_THREAD | LOCK_ERRORCHECK,
	    NULL)) != 0) {
		umem_free(scp, sizeof (svp_conn_t));
		return (ret);
	}

	scp->sc_remote = srp;
	scp->sc_event.se_func = svp_conn_handler;
	scp->sc_event.se_arg = scp;
	scp->sc_btimer.st_func = svp_conn_backtimer;
	scp->sc_btimer.st_arg = scp;
	scp->sc_btimer.st_oneshot = B_TRUE;
	scp->sc_btimer.st_value = 1;

	scp->sc_qtimer.st_func = svp_conn_querytimer;
	scp->sc_qtimer.st_arg = scp;
	scp->sc_qtimer.st_oneshot = B_FALSE;
	scp->sc_qtimer.st_value = svp_conn_query_timeout;

	scp->sc_socket = -1;

	list_create(&scp->sc_queries, sizeof (svp_query_t),
	    offsetof(svp_query_t, sq_lnode));
	scp->sc_gen = srp->sr_gen;
	bcopy(addr, &scp->sc_addr, sizeof (struct in6_addr));
	scp->sc_cstate = SVP_CS_INITIAL;
	mutex_enter(&scp->sc_lock);
	svp_conn_add(scp);
	mutex_exit(&scp->sc_lock);

	/* Now that we're locked and loaded, add our timers */
	svp_timer_add(&scp->sc_qtimer);
	svp_timer_add(&scp->sc_btimer);

	return (0);
}

/*
 * At the time of calling, the entry has been removed from all lists. In
 * addition, the entries state should be SVP_CS_ERROR, therefore, we know that
 * the fd should not be associated with the event loop. We'll double check that
 * just in case. We should also have already been removed from the remote's
 * list.
 */
void
svp_conn_destroy(svp_conn_t *scp)
{
	int ret;

	mutex_enter(&scp->sc_lock);
	if (scp->sc_cstate != SVP_CS_ERROR)
		libvarpd_panic("asked to tear down an active connection");
	if (scp->sc_flags & SVP_CF_ADDED)
		libvarpd_panic("asked to remove a connection still in "
		    "the remote list\n");
	if (!list_is_empty(&scp->sc_queries))
		libvarpd_panic("asked to remove a connection with non-empty "
		    "query list");

	if ((ret = svp_event_dissociate(&scp->sc_event, scp->sc_socket)) !=
	    ENOENT) {
		libvarpd_panic("dissociate failed or was actually "
		    "associated: %d", ret);
	}
	mutex_exit(&scp->sc_lock);

	/* Verify our timers are killed */
	svp_timer_remove(&scp->sc_btimer);
	svp_timer_remove(&scp->sc_qtimer);

	if (scp->sc_socket != -1 && close(scp->sc_socket) != 0)
		libvarpd_panic("failed to close svp_conn_t`scp_socket fd "
		    "%d: %d", scp->sc_socket, errno);

	list_destroy(&scp->sc_queries);
	umem_free(scp, sizeof (svp_conn_t));
}

void
svp_conn_queue(svp_conn_t *scp, svp_query_t *sqp)
{
	assert(MUTEX_HELD(&scp->sc_lock));
	assert(scp->sc_cstate == SVP_CS_ACTIVE);

	sqp->sq_acttime = -1;
	list_insert_tail(&scp->sc_queries, sqp);
	if (!(scp->sc_event.se_events & POLLOUT)) {
		scp->sc_event.se_events |= POLLOUT;
		/*
		 * If this becomes frequent, we should instead give up on this
		 * set of connections instead of aborting.
		 */
		if (svp_event_associate(&scp->sc_event, scp->sc_socket) != 0)
			libvarpd_panic("svp_event_associate failed somehow");
	}
}
