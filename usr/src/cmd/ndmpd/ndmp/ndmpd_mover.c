/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * BSD 3 Clause License
 *
 * Copyright (c) 2007, The Storage Networking Industry Association.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 	- Redistributions of source code must retain the above copyright
 *	  notice, this list of conditions and the following disclaimer.
 *
 * 	- Redistributions in binary form must reproduce the above copyright
 *	  notice, this list of conditions and the following disclaimer in
 *	  the documentation and/or other materials provided with the
 *	  distribution.
 *
 *	- Neither the name of The Storage Networking Industry Association (SNIA)
 *	  nor the names of its contributors may be used to endorse or promote
 *	  products derived from this software without specific prior written
 *	  permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
/* Copyright (c) 2007, The Storage Networking Industry Association. */
/* Copyright (c) 1996, 1997 PDC, Network Appliance. All Rights Reserved */
/* Copyright 2014 Nexenta Systems, Inc.  All rights reserved. */

#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "ndmpd_common.h"
#include "ndmpd.h"
#include <sys/mtio.h>

/*
 * Maximum mover record size
 */
#define	MAX_MOVER_RECSIZE	(512*KILOBYTE)

static int create_listen_socket_v2(ndmpd_session_t *session, ulong_t *addr,
    ushort_t *port);
static int tape_read(ndmpd_session_t *session, char *data);
static int change_tape(ndmpd_session_t *session);
static int discard_data(ndmpd_session_t *session, ulong_t length);
static int mover_tape_read_one_buf(ndmpd_session_t *session, tlm_buffer_t *buf);
static int mover_socket_write_one_buf(ndmpd_session_t *session,
    tlm_buffer_t *buf);
static int start_mover_for_restore(ndmpd_session_t *session);
static int mover_socket_read_one_buf(ndmpd_session_t *session,
    tlm_buffer_t *buf, long read_size);
static int mover_tape_write_one_buf(ndmpd_session_t *session,
    tlm_buffer_t *buf);
static int start_mover_for_backup(ndmpd_session_t *session);
static boolean_t is_writer_running_v3(ndmpd_session_t *session);
static int mover_pause_v3(ndmpd_session_t *session,
    ndmp_mover_pause_reason reason);
static int mover_tape_write_v3(ndmpd_session_t *session, char *data,
    ssize_t length);
static int mover_tape_flush_v3(ndmpd_session_t *session);
static int mover_tape_read_v3(ndmpd_session_t *session, char *data);
static int create_listen_socket_v3(ndmpd_session_t *session, ulong_t *addr,
    ushort_t *port);
static void mover_data_read_v3(void *cookie, int fd, ulong_t mode);
static void accept_connection(void *cookie, int fd, ulong_t mode);
static void mover_data_write_v3(void *cookie, int fd, ulong_t mode);
static void accept_connection_v3(void *cookie, int fd, ulong_t mode);
static ndmp_error mover_connect_sock(ndmpd_session_t *session,
    ndmp_mover_mode mode, ulong_t addr, ushort_t port);
static boolean_t is_writer_running(ndmpd_session_t *session);
static int set_socket_nonblock(int sock);


int ndmp_max_mover_recsize = MAX_MOVER_RECSIZE; /* patchable */

#define	TAPE_READ_ERR		-1
#define	TAPE_NO_WRITER_ERR	-2

/*
 * Set non-blocking mode for socket.
 */
static int
set_socket_nonblock(int sock)
{
	int flags;

	flags = fcntl(sock, F_GETFL, 0);
	if (flags < 0)
		return (0);
	return (fcntl(sock, F_SETFL, flags|O_NONBLOCK) == 0);
}

/*
 * ************************************************************************
 * NDMP V2 HANDLERS
 * ************************************************************************
 */

/*
 * ndmpd_mover_get_state_v2
 *
 * This handler handles the mover_get_state request.
 * Status information for the mover state machine is returned.
 *
 * Parameters:
 *   connection (input) - connection handle.
 *   body       (input) - request message body.
 *
 * Returns:
 *   void
 */
/*ARGSUSED*/
void
ndmpd_mover_get_state_v2(ndmp_connection_t *connection, void *body)
{
	ndmp_mover_get_state_reply_v2 reply;
	ndmpd_session_t *session = ndmp_get_client_data(connection);

	reply.error = NDMP_NO_ERR;
	reply.state = session->ns_mover.md_state;
	reply.pause_reason = session->ns_mover.md_pause_reason;
	reply.halt_reason = session->ns_mover.md_halt_reason;
	reply.record_size = session->ns_mover.md_record_size;
	reply.record_num = session->ns_mover.md_record_num;
	reply.data_written =
	    long_long_to_quad(session->ns_mover.md_data_written);
	reply.seek_position =
	    long_long_to_quad(session->ns_mover.md_seek_position);
	reply.bytes_left_to_read =
	    long_long_to_quad(session->ns_mover.md_bytes_left_to_read);
	reply.window_offset =
	    long_long_to_quad(session->ns_mover.md_window_offset);
	reply.window_length =
	    long_long_to_quad(session->ns_mover.md_window_length);

	ndmp_send_reply(connection, (void *) &reply,
	    "sending tape_get_state reply");
}


/*
 * ndmpd_mover_listen_v2
 *
 * This handler handles mover_listen requests.
 *
 * Parameters:
 *   connection (input) - connection handle.
 *   body       (input) - request message body.
 *
 * Returns:
 *   void
 */
void
ndmpd_mover_listen_v2(ndmp_connection_t *connection, void *body)
{
	ndmp_mover_listen_request_v2 *request;
	ndmp_mover_listen_reply_v2 reply;
	ndmpd_session_t *session = ndmp_get_client_data(connection);
	ulong_t addr;
	ushort_t port;

	request = (ndmp_mover_listen_request_v2 *)body;

	if (session->ns_mover.md_state != NDMP_MOVER_STATE_IDLE ||
	    session->ns_data.dd_state != NDMP_DATA_STATE_IDLE) {
		NDMP_LOG(LOG_DEBUG, "Invalid state");
		reply.error = NDMP_ILLEGAL_STATE_ERR;
		ndmp_send_reply(connection, (void *) &reply,
		    "sending mover_listen reply");
		return;
	}
	session->ns_mover.md_mode = request->mode;

	if (request->addr_type == NDMP_ADDR_LOCAL) {
		reply.mover.addr_type = NDMP_ADDR_LOCAL;
	} else {
		if (create_listen_socket_v2(session, &addr, &port) < 0) {
			reply.error = NDMP_IO_ERR;
			ndmp_send_reply(connection, (void *) &reply,
			    "sending mover_listen reply");
			return;
		}
		reply.mover.addr_type = NDMP_ADDR_TCP;
		reply.mover.ndmp_mover_addr_u.addr.ip_addr = htonl(addr);
		reply.mover.ndmp_mover_addr_u.addr.port = htons(port);
	}

	session->ns_mover.md_state = NDMP_MOVER_STATE_LISTEN;

	/*
	 * ndmp window should always set by client during restore
	 */

	/* Set the default window. */
	session->ns_mover.md_window_offset = 0;
	session->ns_mover.md_window_length = MAX_WINDOW_SIZE;
	session->ns_mover.md_position = 0;

	reply.error = NDMP_NO_ERR;
	ndmp_send_reply(connection, (void *) &reply,
	    "sending mover_listen reply");
}


/*
 * ndmpd_mover_continue_v2
 *
 * This handler handles mover_continue requests.
 *
 * Parameters:
 *   connection (input) - connection handle.
 *   body       (input) - request message body.
 *
 * Returns:
 *   void
 */
/*ARGSUSED*/
void
ndmpd_mover_continue_v2(ndmp_connection_t *connection, void *body)
{
	ndmp_mover_continue_reply reply;
	ndmpd_session_t *session = ndmp_get_client_data(connection);

	if (session->ns_mover.md_state != NDMP_MOVER_STATE_PAUSED) {
		NDMP_LOG(LOG_DEBUG, "Invalid state");

		reply.error = NDMP_ILLEGAL_STATE_ERR;
		ndmp_send_reply(connection, (void *) &reply,
		    "sending mover_continue reply");
		return;
	}
	session->ns_mover.md_state = NDMP_MOVER_STATE_ACTIVE;
	reply.error = NDMP_NO_ERR;
	ndmp_send_reply(connection, (void *) &reply,
	    "sending mover_continue reply");
}


/*
 * ndmpd_mover_abort_v2
 *
 * This handler handles mover_abort requests.
 *
 * Parameters:
 *   connection (input) - connection handle.
 *   body       (input) - request message body.
 *
 * Returns:
 *   void
 */
/*ARGSUSED*/
void
ndmpd_mover_abort_v2(ndmp_connection_t *connection, void *body)
{
	ndmp_mover_abort_reply reply;
	ndmpd_session_t *session = ndmp_get_client_data(connection);

	if (session->ns_mover.md_state == NDMP_MOVER_STATE_IDLE ||
	    session->ns_mover.md_state == NDMP_MOVER_STATE_HALTED) {
		NDMP_LOG(LOG_DEBUG, "Invalid state");

		reply.error = NDMP_ILLEGAL_STATE_ERR;
		ndmp_send_reply(connection, (void *) &reply,
		    "sending mover_abort reply");
		return;
	}

	reply.error = NDMP_NO_ERR;
	ndmp_send_reply(connection, (void *) &reply,
	    "sending mover_abort reply");

	ndmpd_mover_error(session, NDMP_MOVER_HALT_ABORTED);
	ndmp_stop_buffer_worker(session);
}


/*
 * ndmpd_mover_stop_v2
 *
 * This handler handles mover_stop requests.
 *
 * Parameters:
 *   connection (input) - connection handle.
 *   body       (input) - request message body.
 *
 * Returns:
 *   void
 */
/*ARGSUSED*/
void
ndmpd_mover_stop_v2(ndmp_connection_t *connection, void *body)
{
	ndmp_mover_stop_reply reply;
	ndmpd_session_t *session = ndmp_get_client_data(connection);

	if (session->ns_mover.md_state != NDMP_MOVER_STATE_HALTED) {
		NDMP_LOG(LOG_DEBUG, "Invalid state");

		reply.error = NDMP_ILLEGAL_STATE_ERR;
		ndmp_send_reply(connection, (void *) &reply,
		    "sending mover_stop reply");
		return;
	}

	ndmp_waitfor_op(session);
	reply.error = NDMP_NO_ERR;
	ndmp_send_reply(connection, (void *) &reply,
	    "sending mover_stop reply");

	ndmp_lbr_cleanup(session);
	ndmpd_mover_cleanup(session);
	(void) ndmpd_mover_init(session);
	(void) ndmp_lbr_init(session);
}


/*
 * ndmpd_mover_set_window_v2
 *
 * This handler handles mover_set_window requests.
 *
 *
 * Parameters:
 *   connection (input) - connection handle.
 *   body       (input) - request message body.
 *
 * Returns:
 *   void
 */
void
ndmpd_mover_set_window_v2(ndmp_connection_t *connection, void *body)
{
	ndmp_mover_set_window_request *request;
	ndmp_mover_set_window_reply reply;
	ndmpd_session_t *session = ndmp_get_client_data(connection);

	request = (ndmp_mover_set_window_request *) body;

	/*
	 * The NDMPv2 specification states that "a window can be set only
	 * when in the listen or paused state."
	 *
	 * See the comment in ndmpd_mover_set_window_v3 regarding the reason for
	 * allowing it in the idle state as well.
	 */
	if (session->ns_mover.md_state != NDMP_MOVER_STATE_IDLE &&
	    session->ns_mover.md_state != NDMP_MOVER_STATE_PAUSED &&
	    session->ns_mover.md_state != NDMP_MOVER_STATE_LISTEN) {
		reply.error = NDMP_ILLEGAL_STATE_ERR;
		NDMP_LOG(LOG_DEBUG, "Invalid state %d",
		    session->ns_mover.md_state);
	} else {
		if (quad_to_long_long(request->length) == 0) {
			reply.error = NDMP_ILLEGAL_ARGS_ERR;
			NDMP_LOG(LOG_DEBUG, "Invalid window size %d",
			    quad_to_long_long(request->length));
		} else {
			reply.error = NDMP_NO_ERR;
			session->ns_mover.md_window_offset =
			    quad_to_long_long(request->offset);
			session->ns_mover.md_window_length =
			    quad_to_long_long(request->length);
			session->ns_mover.md_position =
			    session->ns_mover.md_window_offset;
		}
	}

	ndmp_send_reply(connection, (void *) &reply,
	    "sending mover_set_window reply");
}


/*
 * ndmpd_mover_read_v2
 *
 * This handler handles mover_read requests. If the requested offset is
 * outside of the current window, the mover is paused and a notify_mover_paused
 * request is sent notifying the client that a seek is required. If the
 * requested offest is within the window but not within the current record,
 * then the tape is positioned to the record containing the requested offest.
 * The requested amount of data is then read from the tape device and written
 * to the data connection.
 *
 * Parameters:
 *   connection (input) - connection handle.
 *   body       (input) - request message body.
 *
 * Returns:
 *   void
 */
void
ndmpd_mover_read_v2(ndmp_connection_t *connection, void *body)
{
	ndmp_mover_read_request *request = (ndmp_mover_read_request *) body;
	ndmp_mover_read_reply reply;
	ndmpd_session_t *session = ndmp_get_client_data(connection);
	int err;

	if (session->ns_mover.md_state != NDMP_MOVER_STATE_ACTIVE ||
	    session->ns_mover.md_bytes_left_to_read != 0 ||
	    session->ns_mover.md_mode != NDMP_MOVER_MODE_WRITE) {
		NDMP_LOG(LOG_DEBUG, "Invalid state");
		reply.error = NDMP_ILLEGAL_STATE_ERR;
		ndmp_send_reply(connection, &reply,
		    "sending mover_read reply");
		return;
	}
	if (session->ns_tape.td_fd == -1) {
		NDMP_LOG(LOG_DEBUG, "Tape device is not open");
		reply.error = NDMP_DEV_NOT_OPEN_ERR;
		ndmp_send_reply(connection, &reply,
		    "sending mover_read reply");
		return;
	}

	reply.error = NDMP_NO_ERR;
	ndmp_send_reply(connection, &reply, "sending mover_read reply");

	err = ndmpd_mover_seek(session, quad_to_long_long(request->offset),
	    quad_to_long_long(request->length));
	if (err < 0) {
		ndmpd_mover_error(session, NDMP_MOVER_HALT_INTERNAL_ERROR);
		return;
	}
	/*
	 * Just return if we are waiting for the NDMP client to
	 * complete the seek.
	 */
	if (err == 1)
		return;

	/*
	 * Start the mover for restore in the 3-way backups.
	 */
	if (start_mover_for_restore(session) < 0)
		ndmpd_mover_error(session, NDMP_MOVER_HALT_INTERNAL_ERROR);
}


/*
 * ndmpd_mover_close_v2
 *
 * This handler handles mover_close requests.
 *
 * Parameters:
 *   connection (input) - connection handle.
 *   body       (input) - request message body.
 *
 * Returns:
 *   void
 */
/*ARGSUSED*/
void
ndmpd_mover_close_v2(ndmp_connection_t *connection, void *body)
{
	ndmp_mover_close_reply reply;
	ndmpd_session_t *session = ndmp_get_client_data(connection);

	if (session->ns_mover.md_state != NDMP_MOVER_STATE_PAUSED) {
		NDMP_LOG(LOG_DEBUG, "Invalid state");

		reply.error = NDMP_ILLEGAL_STATE_ERR;
		ndmp_send_reply(connection, &reply,
		    "sending mover_close reply");
		return;
	}
	free(session->ns_mover.md_data_addr_v4.tcp_addr_v4);

	reply.error = NDMP_NO_ERR;
	ndmp_send_reply(connection, &reply, "sending mover_close reply");

	ndmpd_mover_error(session, NDMP_MOVER_HALT_CONNECT_CLOSED);
}


/*
 * ndmpd_mover_set_record_size_v2
 *
 * This handler handles mover_set_record_size requests.
 *
 * Parameters:
 *   connection (input) - connection handle.
 *   body       (input) - request message body.
 *
 * Returns:
 *   void
 */
void
ndmpd_mover_set_record_size_v2(ndmp_connection_t *connection, void *body)
{
	ndmp_mover_set_record_size_request *request;
	ndmp_mover_set_record_size_reply reply;
	ndmpd_session_t *session = ndmp_get_client_data(connection);

	request = (ndmp_mover_set_record_size_request *) body;

	session->ns_mover.md_record_size = request->len;
	session->ns_mover.md_buf = realloc(session->ns_mover.md_buf,
	    request->len);

	reply.error = NDMP_NO_ERR;
	ndmp_send_reply(connection, &reply,
	    "sending mover_set_record_size reply");
}


/*
 * ************************************************************************
 * NDMP V3 HANDLERS
 * ************************************************************************
 */

/*
 * ndmpd_mover_get_state_v3
 *
 * This handler handles the ndmp_mover_get_state_request.
 * Status information for the mover state machine is returned.
 *
 * Parameters:
 *   connection (input) - connection handle.
 *   body       (input) - request message body.
 *
 * Returns:
 *   void
 */
/*ARGSUSED*/
void
ndmpd_mover_get_state_v3(ndmp_connection_t *connection, void *body)
{
	ndmp_mover_get_state_reply_v3 reply;
	ndmpd_session_t *session = ndmp_get_client_data(connection);

	(void) memset((void*)&reply, 0, sizeof (reply));

	reply.error = NDMP_NO_ERR;
	reply.state = session->ns_mover.md_state;
	reply.pause_reason = session->ns_mover.md_pause_reason;
	reply.halt_reason = session->ns_mover.md_halt_reason;
	reply.record_size = session->ns_mover.md_record_size;
	reply.record_num = session->ns_mover.md_record_num;
	reply.data_written =
	    long_long_to_quad(session->ns_mover.md_data_written);
	reply.seek_position =
	    long_long_to_quad(session->ns_mover.md_seek_position);
	reply.bytes_left_to_read =
	    long_long_to_quad(session->ns_mover.md_bytes_left_to_read);
	reply.window_offset =
	    long_long_to_quad(session->ns_mover.md_window_offset);
	reply.window_length =
	    long_long_to_quad(session->ns_mover.md_window_length);
	if (session->ns_mover.md_state != NDMP_MOVER_STATE_IDLE)
		ndmp_copy_addr_v3(&reply.data_connection_addr,
		    &session->ns_mover.md_data_addr);

	ndmp_send_reply(connection, &reply,
	    "sending ndmp_mover_get_state reply");
}


/*
 * ndmpd_mover_listen_v3
 *
 * This handler handles ndmp_mover_listen_requests.
 * A TCP/IP socket is created that is used to listen for
 * and accept data connections initiated by a remote
 * data server.
 *
 * Parameters:
 *   connection (input) - connection handle.
 *   body       (input) - request message body.
 *
 * Returns:
 *   void
 */
void
ndmpd_mover_listen_v3(ndmp_connection_t *connection, void *body)
{
	ndmp_mover_listen_request_v3 *request;
	ndmp_mover_listen_reply_v3 reply;
	ndmpd_session_t *session = ndmp_get_client_data(connection);
	ulong_t addr;
	ushort_t port;

	request = (ndmp_mover_listen_request_v3 *)body;

	(void) memset((void*)&reply, 0, sizeof (reply));
	reply.error = NDMP_NO_ERR;

	if (request->mode != NDMP_MOVER_MODE_READ &&
	    request->mode != NDMP_MOVER_MODE_WRITE) {
		reply.error = NDMP_ILLEGAL_ARGS_ERR;
		NDMP_LOG(LOG_DEBUG, "Invalid mode %d", request->mode);
	} else if (!ndmp_valid_v3addr_type(request->addr_type)) {
		reply.error = NDMP_ILLEGAL_ARGS_ERR;
		NDMP_LOG(LOG_DEBUG, "Invalid address type %d",
		    request->addr_type);
	} else if (session->ns_mover.md_state != NDMP_MOVER_STATE_IDLE) {
		reply.error = NDMP_ILLEGAL_STATE_ERR;
		NDMP_LOG(LOG_DEBUG,
		    "Invalid mover state to process listen request");
	} else if (session->ns_data.dd_state != NDMP_DATA_STATE_IDLE) {
		reply.error = NDMP_ILLEGAL_STATE_ERR;
		NDMP_LOG(LOG_DEBUG,
		    "Invalid data state to process listen request");
	} else if (session->ns_tape.td_fd == -1) {
		reply.error = NDMP_DEV_NOT_OPEN_ERR;
		NDMP_LOG(LOG_DEBUG, "No tape device open");
	} else if (request->mode == NDMP_MOVER_MODE_READ &&
	    session->ns_tape.td_mode == NDMP_TAPE_READ_MODE) {
		reply.error = NDMP_PERMISSION_ERR;
		NDMP_LOG(LOG_ERR, "Write protected device.");
	}

	if (reply.error != NDMP_NO_ERR) {
		ndmp_send_reply(connection, &reply,
		    "error sending ndmp_mover_listen reply");
		return;
	}

	switch (request->addr_type) {
	case NDMP_ADDR_LOCAL:
		reply.data_connection_addr.addr_type = NDMP_ADDR_LOCAL;
		session->ns_mover.md_data_addr.addr_type = NDMP_ADDR_LOCAL;
		reply.error = NDMP_NO_ERR;
		break;
	case NDMP_ADDR_TCP:
		if (create_listen_socket_v3(session, &addr, &port) < 0) {
			reply.error = NDMP_IO_ERR;
			break;
		}
		reply.error = NDMP_NO_ERR;
		reply.data_connection_addr.addr_type = NDMP_ADDR_TCP;
		reply.data_connection_addr.tcp_ip_v3 = htonl(addr);
		reply.data_connection_addr.tcp_port_v3 = htons(port);
		session->ns_mover.md_data_addr.addr_type = NDMP_ADDR_TCP;
		session->ns_mover.md_data_addr.tcp_ip_v3 = addr;
		session->ns_mover.md_data_addr.tcp_port_v3 = ntohs(port);
		NDMP_LOG(LOG_DEBUG, "listen_socket: %d",
		    session->ns_mover.md_listen_sock);
		break;
	default:
		reply.error = NDMP_ILLEGAL_ARGS_ERR;
		NDMP_LOG(LOG_DEBUG, "Invalid address type: %d",
		    request->addr_type);
	}

	if (reply.error == NDMP_NO_ERR) {
		session->ns_mover.md_mode = request->mode;
		session->ns_mover.md_state = NDMP_MOVER_STATE_LISTEN;
	}

	ndmp_send_reply(connection, &reply,
	    "error sending ndmp_mover_listen reply");
}


/*
 * ndmpd_mover_continue_v3
 *
 * This handler handles ndmp_mover_continue_requests.
 *
 * Parameters:
 *   connection (input) - connection handle.
 *   body       (input) - request message body.
 *
 * Returns:
 *   void
 */
/*ARGSUSED*/
void
ndmpd_mover_continue_v3(ndmp_connection_t *connection, void *body)
{
	ndmp_mover_continue_reply reply;
	ndmpd_session_t *session = ndmp_get_client_data(connection);
	ndmp_lbr_params_t *nlp = ndmp_get_nlp(session);
	int ret;

	(void) memset((void*)&reply, 0, sizeof (reply));

	if (session->ns_mover.md_state != NDMP_MOVER_STATE_PAUSED) {
		NDMP_LOG(LOG_DEBUG, "Invalid state");
		reply.error = NDMP_ILLEGAL_STATE_ERR;
		ndmp_send_reply(connection, (void *) &reply,
		    "sending mover_continue reply");
		return;
	}

	if (session->ns_protocol_version == NDMPV4 &&
	    !session->ns_mover.md_pre_cond) {
		NDMP_LOG(LOG_DEBUG, "Precondition check");
		reply.error = NDMP_PRECONDITION_ERR;
		ndmp_send_reply(connection, (void *) &reply,
		    "sending mover_continue reply");
		return;
	}
	/*
	 * Restore the file handler if the mover is remote to the data
	 * server and the handler was removed pending the continuation of a
	 * seek request. The handler is removed in mover_data_write().
	 */
	if (session->ns_mover.md_pause_reason == NDMP_MOVER_PAUSE_SEEK &&
	    session->ns_mover.md_sock != -1) {
		/*
		 * If we are here, it means that we needed DMA interference
		 * for seek. We should be on the right window, so we do not
		 * need the DMA interference anymore.
		 * We do another seek inside the Window to move to the
		 * exact position on the tape.
		 * If the resore is running without DAR the pause reason should
		 * not be seek.
		 */
		ret = ndmpd_mover_seek(session,
		    session->ns_mover.md_seek_position,
		    session->ns_mover.md_bytes_left_to_read);
		if (ret < 0) {
			ndmpd_mover_error(session,
			    NDMP_MOVER_HALT_INTERNAL_ERROR);
			return;
		}

		if (!ret) {
			if (ndmpd_add_file_handler(session, (void*) session,
			    session->ns_mover.md_sock, NDMPD_SELECT_MODE_WRITE,
			    HC_MOVER, mover_data_write_v3) < 0)
				ndmpd_mover_error(session,
				    NDMP_MOVER_HALT_INTERNAL_ERROR);
		} else {
			/*
			 * This should not happen because we should be in the
			 * right window. This means that DMA does not follow
			 * the V3 spec.
			 */
			NDMP_LOG(LOG_DEBUG, "DMA Error.");
			ndmpd_mover_error(session,
			    NDMP_MOVER_HALT_INTERNAL_ERROR);
			return;
		}
	}

	(void) mutex_lock(&nlp->nlp_mtx);
	session->ns_mover.md_state = NDMP_MOVER_STATE_ACTIVE;
	session->ns_mover.md_pause_reason = NDMP_MOVER_PAUSE_NA;
	/* The tape has been likely exchanged, reset tape block counter */
	session->ns_tape.td_record_count = 0;
	(void) cond_broadcast(&nlp->nlp_cv);
	(void) mutex_unlock(&nlp->nlp_mtx);

	reply.error = NDMP_NO_ERR;
	ndmp_send_reply(connection, (void *) &reply,
	    "sending mover_continue reply");
}


/*
 * ndmpd_mover_abort_v3
 *
 * This handler handles mover_abort requests.
 *
 * Parameters:
 *   connection (input) - connection handle.
 *   body       (input) - request message body.
 *
 * Returns:
 *   void
 */
/*ARGSUSED*/
void
ndmpd_mover_abort_v3(ndmp_connection_t *connection, void *body)
{
	ndmp_mover_abort_reply reply;
	ndmpd_session_t *session = ndmp_get_client_data(connection);

	if (session->ns_mover.md_state == NDMP_MOVER_STATE_IDLE ||
	    session->ns_mover.md_state == NDMP_MOVER_STATE_HALTED) {
		NDMP_LOG(LOG_DEBUG, "Invalid state");

		reply.error = NDMP_ILLEGAL_STATE_ERR;
		ndmp_send_reply(connection, (void *) &reply,
		    "sending mover_abort reply");
		return;
	}

	reply.error = NDMP_NO_ERR;
	ndmp_send_reply(connection, (void *) &reply,
	    "sending mover_abort reply");

	ndmpd_mover_error(session, NDMP_MOVER_HALT_ABORTED);
}


/*
 * ndmpd_mover_set_window_v3
 *
 * This handler handles mover_set_window requests.
 *
 *
 * Parameters:
 *   connection (input) - connection handle.
 *   body       (input) - request message body.
 *
 * Returns:
 *   void
 */
void
ndmpd_mover_set_window_v3(ndmp_connection_t *connection, void *body)
{
	ndmp_mover_set_window_request *request;
	ndmp_mover_set_window_reply reply;
	ndmpd_session_t *session = ndmp_get_client_data(connection);

	request = (ndmp_mover_set_window_request *) body;

	/*
	 * Note: The spec says that the window can be set only in the listen
	 * and paused states.  We let this happen when mover is in the idle
	 * state as well.  I can't rememebr which NDMP client (net_backup 4.5
	 * or net_worker 6.1.1) forced us to do this!
	 */
	if (session->ns_mover.md_state != NDMP_MOVER_STATE_IDLE &&
	    session->ns_mover.md_state != NDMP_MOVER_STATE_LISTEN &&
	    session->ns_mover.md_state != NDMP_MOVER_STATE_PAUSED) {
		reply.error = NDMP_ILLEGAL_STATE_ERR;
		NDMP_LOG(LOG_DEBUG, "Invalid state %d",
		    session->ns_mover.md_state);
	} else if (session->ns_mover.md_record_size == 0) {
		if (session->ns_protocol_version == NDMPV4)
			reply.error = NDMP_PRECONDITION_ERR;
		else
			reply.error = NDMP_ILLEGAL_ARGS_ERR;
		NDMP_LOG(LOG_DEBUG, "Invalid record size 0");
	} else
		reply.error = NDMP_NO_ERR;

	if (quad_to_long_long(request->length) == 0) {
		reply.error = NDMP_ILLEGAL_ARGS_ERR;
		NDMP_LOG(LOG_DEBUG, "Invalid window size %d",
		    quad_to_long_long(request->length));
	}

	if (reply.error != NDMP_NO_ERR) {
		ndmp_send_reply(connection, (void *) &reply,
		    "sending mover_set_window_v3 reply");
		return;
	}

	session->ns_mover.md_pre_cond = TRUE;
	session->ns_mover.md_window_offset = quad_to_long_long(request->offset);
	session->ns_mover.md_window_length = quad_to_long_long(request->length);

	/*
	 * We have to update the position for DAR. DAR needs this
	 * information to position to the right index on tape,
	 * especially when we span the tapes.
	 */
#ifdef	NO_POSITION_CHANGE
	/*
	 * Do not change the mover position if we are reading from
	 * the tape.  In this way, we can use the position+window_length
	 * to know how much we can write to a tape before pausing with
	 * EOW reason.
	 */
	if (session->ns_mover.md_mode != NDMP_MOVER_MODE_WRITE)
#endif	/* NO_POSITION_CHANGE */
		session->ns_mover.md_position =
		    session->ns_mover.md_window_offset;

	ndmp_send_reply(connection, (void *) &reply,
	    "sending mover_set_window_v3 reply");
}


/*
 * ndmpd_mover_read_v3
 *
 * This handler handles ndmp_mover_read_requests.
 * If the requested offset is outside of the current window, the mover
 * is paused and a notify_mover_paused request is sent notifying the
 * client that a seek is required. If the requested offest is within
 * the window but not within the current record, then the tape is
 * positioned to the record containing the requested offest. The requested
 * amount of data is then read from the tape device and written to the
 * data connection.
 *
 * Parameters:
 *   connection (input) - connection handle.
 *   body       (input) - request message body.
 *
 * Returns:
 *   void
 */
void
ndmpd_mover_read_v3(ndmp_connection_t *connection, void *body)
{
	ndmp_mover_read_request *request = (ndmp_mover_read_request *)body;
	ndmp_mover_read_reply reply;
	ndmpd_session_t *session = ndmp_get_client_data(connection);
	int err;

	(void) memset((void*)&reply, 0, sizeof (reply));

	if (session->ns_mover.md_state != NDMP_MOVER_STATE_ACTIVE ||
	    session->ns_mover.md_mode != NDMP_MOVER_MODE_WRITE) {
		reply.error = NDMP_ILLEGAL_STATE_ERR;
		NDMP_LOG(LOG_DEBUG, "Invalid state");
	} else if (session->ns_mover.md_bytes_left_to_read != 0) {
		reply.error = NDMP_READ_IN_PROGRESS_ERR;
		NDMP_LOG(LOG_DEBUG, "In progress");
	} else if (session->ns_tape.td_fd == -1) {
		reply.error = NDMP_DEV_NOT_OPEN_ERR;
		NDMP_LOG(LOG_DEBUG, "Tape device is not open");
	} else if (quad_to_long_long(request->length) == 0 ||
	    (quad_to_long_long(request->length) == MAX_WINDOW_SIZE &&
	    quad_to_long_long(request->offset) != 0)) {
		reply.error = NDMP_ILLEGAL_ARGS_ERR;
		NDMP_LOG(LOG_DEBUG, "Illegal args");
	} else {
		reply.error = NDMP_NO_ERR;
	}

	ndmp_send_reply(connection, (void *) &reply,
	    "sending ndmp_mover_read_reply");
	if (reply.error != NDMP_NO_ERR)
		return;

	err = ndmpd_mover_seek(session, quad_to_long_long(request->offset),
	    quad_to_long_long(request->length));
	if (err < 0) {
		ndmpd_mover_error(session, NDMP_MOVER_HALT_INTERNAL_ERROR);
		return;
	}

	/*
	 * Just return if we are waiting for the DMA to complete the seek.
	 */
	if (err == 1)
		return;

	/*
	 * Setup a handler function that will be called when
	 * data can be written to the data connection without blocking.
	 */
	if (ndmpd_add_file_handler(session, (void*)session,
	    session->ns_mover.md_sock, NDMPD_SELECT_MODE_WRITE, HC_MOVER,
	    mover_data_write_v3) < 0) {
		ndmpd_mover_error(session, NDMP_MOVER_HALT_INTERNAL_ERROR);
		return;
	}
}


/*
 * ndmpd_mover_set_record_size_v3
 *
 * This handler handles mover_set_record_size requests.
 *
 * Parameters:
 *   connection (input) - connection handle.
 *   body       (input) - request message body.
 *
 * Returns:
 *   void
 */
void
ndmpd_mover_set_record_size_v3(ndmp_connection_t *connection, void *body)
{
	ndmp_mover_set_record_size_request *request;
	ndmp_mover_set_record_size_reply reply;
	ndmpd_session_t *session = ndmp_get_client_data(connection);
	char *cp;

	request = (ndmp_mover_set_record_size_request *) body;

	if (session->ns_mover.md_state != NDMP_MOVER_STATE_IDLE) {
		reply.error = NDMP_ILLEGAL_STATE_ERR;
		NDMP_LOG(LOG_DEBUG, "Invalid mover state %d",
		    session->ns_mover.md_state);
	} else if (request->len > (unsigned int)ndmp_max_mover_recsize) {
		reply.error = NDMP_ILLEGAL_ARGS_ERR;
		NDMP_LOG(LOG_DEBUG,
		    "Invalid argument %d, should be > 0 and <= %d",
		    request->len, ndmp_max_mover_recsize);
	} else if (request->len == session->ns_mover.md_record_size)
		reply.error = NDMP_NO_ERR;
	else if (!(cp = realloc(session->ns_mover.md_buf, request->len))) {
		reply.error = NDMP_NO_MEM_ERR;
	} else {
		reply.error = NDMP_NO_ERR;
		session->ns_mover.md_buf = cp;
		session->ns_mover.md_record_size = request->len;
		session->ns_mover.md_window_offset = 0;
		session->ns_mover.md_window_length = 0;
	}

	ndmp_send_reply(connection, (void *) &reply,
	    "sending mover_set_record_size reply");
}


/*
 * ndmpd_mover_connect_v3
 *   Request handler. Connects the mover to either a local
 *   or remote data server.
 *
 * Parameters:
 *   connection (input) - connection handle.
 *   body       (input) - request message body.
 *
 * Returns:
 *   void
 */
void
ndmpd_mover_connect_v3(ndmp_connection_t *connection, void *body)
{
	ndmp_mover_connect_request_v3 *request;
	ndmp_mover_connect_reply_v3 reply;
	ndmpd_session_t *session = ndmp_get_client_data(connection);

	request = (ndmp_mover_connect_request_v3*)body;

	(void) memset((void*)&reply, 0, sizeof (reply));

	if (request->mode != NDMP_MOVER_MODE_READ &&
	    request->mode != NDMP_MOVER_MODE_WRITE) {
		reply.error = NDMP_ILLEGAL_ARGS_ERR;
		NDMP_LOG(LOG_DEBUG, "Invalid mode %d", request->mode);
	} else if (!ndmp_valid_v3addr_type(request->addr.addr_type)) {
		reply.error = NDMP_ILLEGAL_ARGS_ERR;
		NDMP_LOG(LOG_DEBUG, "Invalid address type %d",
		    request->addr.addr_type);
	} else if (session->ns_mover.md_state != NDMP_MOVER_STATE_IDLE) {
		reply.error = NDMP_ILLEGAL_STATE_ERR;
		NDMP_LOG(LOG_DEBUG, "Invalid state %d: mover is not idle",
		    session->ns_mover.md_state);
	} else if (session->ns_tape.td_fd == -1) {
		reply.error = NDMP_DEV_NOT_OPEN_ERR;
		NDMP_LOG(LOG_DEBUG, "No tape device open");
	} else if (request->mode == NDMP_MOVER_MODE_READ &&
	    session->ns_tape.td_mode == NDMP_TAPE_READ_MODE) {
		reply.error = NDMP_WRITE_PROTECT_ERR;
		NDMP_LOG(LOG_ERR, "Write protected device.");
	} else
		reply.error = NDMP_NO_ERR;

	if (reply.error != NDMP_NO_ERR) {
		ndmp_send_reply(connection, (void *) &reply,
		    "sending ndmp_mover_connect reply");
		return;
	}

	switch (request->addr.addr_type) {
	case NDMP_ADDR_LOCAL:
		/*
		 * Verify that the data server is listening for a
		 * local connection.
		 */
		if (session->ns_data.dd_state != NDMP_DATA_STATE_LISTEN ||
		    session->ns_data.dd_listen_sock != -1) {
			NDMP_LOG(LOG_DEBUG,
			    "Data server is not in local listen state");
			reply.error = NDMP_ILLEGAL_STATE_ERR;
		} else
			session->ns_data.dd_state = NDMP_DATA_STATE_CONNECTED;
		break;

	case NDMP_ADDR_TCP:
		reply.error = mover_connect_sock(session, request->mode,
		    request->addr.tcp_ip_v3, request->addr.tcp_port_v3);
		break;

	default:
		reply.error = NDMP_ILLEGAL_ARGS_ERR;
		NDMP_LOG(LOG_DEBUG, "Invalid address type %d",
		    request->addr.addr_type);
	}

	if (reply.error == NDMP_NO_ERR) {
		session->ns_mover.md_data_addr.addr_type =
		    request->addr.addr_type;
		session->ns_mover.md_state = NDMP_MOVER_STATE_ACTIVE;
		session->ns_mover.md_mode = request->mode;
	}

	ndmp_send_reply(connection, (void *) &reply,
	    "sending ndmp_mover_connect reply");
}


/*
 * ************************************************************************
 * NDMP V4 HANDLERS
 * ************************************************************************
 */

/*
 * ndmpd_mover_get_state_v4
 *
 * This handler handles the ndmp_mover_get_state_request.
 * Status information for the mover state machine is returned.
 *
 * Parameters:
 *   connection (input) - connection handle.
 *   body       (input) - request message body.
 *
 * Returns:
 *   void
 */
/*ARGSUSED*/
void
ndmpd_mover_get_state_v4(ndmp_connection_t *connection, void *body)
{
	ndmp_mover_get_state_reply_v4 reply;
	ndmpd_session_t *session = ndmp_get_client_data(connection);

	(void) memset((void*)&reply, 0, sizeof (reply));

	reply.error = NDMP_NO_ERR;
	reply.state = session->ns_mover.md_state;
	reply.mode = session->ns_mover.md_mode;
	reply.pause_reason = session->ns_mover.md_pause_reason;
	reply.halt_reason = session->ns_mover.md_halt_reason;
	reply.record_size = session->ns_mover.md_record_size;
	reply.record_num = session->ns_mover.md_record_num;
	reply.bytes_moved =
	    long_long_to_quad(session->ns_mover.md_data_written);
	reply.seek_position =
	    long_long_to_quad(session->ns_mover.md_seek_position);
	reply.bytes_left_to_read =
	    long_long_to_quad(session->ns_mover.md_bytes_left_to_read);
	reply.window_offset =
	    long_long_to_quad(session->ns_mover.md_window_offset);
	reply.window_length =
	    long_long_to_quad(session->ns_mover.md_window_length);
	if (session->ns_mover.md_state != NDMP_MOVER_STATE_IDLE)
		ndmp_copy_addr_v4(&reply.data_connection_addr,
		    &session->ns_mover.md_data_addr_v4);

	ndmp_send_reply(connection, (void *) &reply,
	    "sending ndmp_mover_get_state reply");
	free(reply.data_connection_addr.tcp_addr_v4);
}


/*
 * ndmpd_mover_listen_v4
 *
 * This handler handles ndmp_mover_listen_requests.
 * A TCP/IP socket is created that is used to listen for
 * and accept data connections initiated by a remote
 * data server.
 *
 * Parameters:
 *   connection (input) - connection handle.
 *   body       (input) - request message body.
 *
 * Returns:
 *   void
 */
void
ndmpd_mover_listen_v4(ndmp_connection_t *connection, void *body)
{
	ndmp_mover_listen_request_v4 *request;

	ndmp_mover_listen_reply_v4 reply;
	ndmpd_session_t *session = ndmp_get_client_data(connection);
	ulong_t addr;
	ushort_t port;

	request = (ndmp_mover_listen_request_v4 *)body;

	(void) memset((void*)&reply, 0, sizeof (reply));
	reply.error = NDMP_NO_ERR;

	if (request->mode != NDMP_MOVER_MODE_READ &&
	    request->mode != NDMP_MOVER_MODE_WRITE) {
		reply.error = NDMP_ILLEGAL_ARGS_ERR;
		NDMP_LOG(LOG_DEBUG, "Invalid mode %d", request->mode);
	} else if (!ndmp_valid_v3addr_type(request->addr_type)) {
		reply.error = NDMP_ILLEGAL_ARGS_ERR;
		NDMP_LOG(LOG_DEBUG, "Invalid address type %d",
		    request->addr_type);
	} else if (session->ns_mover.md_state != NDMP_MOVER_STATE_IDLE) {
		reply.error = NDMP_ILLEGAL_STATE_ERR;
		NDMP_LOG(LOG_DEBUG,
		    "Invalid mover state to process listen request");
	} else if (session->ns_data.dd_state != NDMP_DATA_STATE_IDLE) {
		reply.error = NDMP_ILLEGAL_STATE_ERR;
		NDMP_LOG(LOG_DEBUG,
		    "Invalid data state to process listen request");
	} else if (session->ns_tape.td_fd == -1) {
		reply.error = NDMP_DEV_NOT_OPEN_ERR;
		NDMP_LOG(LOG_DEBUG, "No tape device open");
	} else if (session->ns_mover.md_record_size == 0) {
		reply.error = NDMP_PRECONDITION_ERR;
		NDMP_LOG(LOG_DEBUG, "Invalid record size 0");
	} else if (request->mode == NDMP_MOVER_MODE_READ &&
	    session->ns_tape.td_mode == NDMP_TAPE_READ_MODE) {
		reply.error = NDMP_PERMISSION_ERR;
		NDMP_LOG(LOG_ERR, "Write protected device.");
	}

	if (reply.error != NDMP_NO_ERR) {
		ndmp_send_reply(connection, (void *) &reply,
		    "error sending ndmp_mover_listen reply");
		return;
	}

	switch (request->addr_type) {
	case NDMP_ADDR_LOCAL:
		reply.connect_addr.addr_type = NDMP_ADDR_LOCAL;
		session->ns_mover.md_data_addr.addr_type = NDMP_ADDR_LOCAL;
		reply.error = NDMP_NO_ERR;
		break;
	case NDMP_ADDR_TCP:
		if (create_listen_socket_v3(session, &addr, &port) < 0) {
			reply.error = NDMP_IO_ERR;
			break;
		}
		reply.error = NDMP_NO_ERR;

		session->ns_mover.md_data_addr_v4.addr_type = NDMP_ADDR_TCP;
		session->ns_mover.md_data_addr_v4.tcp_len_v4 = 1;
		session->ns_mover.md_data_addr_v4.tcp_addr_v4 =
		    ndmp_malloc(sizeof (ndmp_tcp_addr_v4));

		session->ns_mover.md_data_addr_v4.tcp_ip_v4(0) = addr;
		session->ns_mover.md_data_addr_v4.tcp_port_v4(0) = ntohs(port);

		ndmp_copy_addr_v4(&reply.connect_addr,
		    &session->ns_mover.md_data_addr_v4);

		/* For compatibility with V3 */
		session->ns_mover.md_data_addr.addr_type = NDMP_ADDR_TCP;
		session->ns_mover.md_data_addr.tcp_ip_v3 = addr;
		session->ns_mover.md_data_addr.tcp_port_v3 = ntohs(port);
		NDMP_LOG(LOG_DEBUG, "listen_socket: %d",
		    session->ns_mover.md_listen_sock);
		break;
	default:
		reply.error = NDMP_ILLEGAL_ARGS_ERR;
		NDMP_LOG(LOG_DEBUG, "Invalid address type: %d",
		    request->addr_type);
	}

	if (reply.error == NDMP_NO_ERR) {
		session->ns_mover.md_mode = request->mode;
		session->ns_mover.md_state = NDMP_MOVER_STATE_LISTEN;
	}

	ndmp_send_reply(connection, (void *) &reply,
	    "error sending ndmp_mover_listen reply");
	free(reply.connect_addr.tcp_addr_v4);
}

/*
 * ndmpd_mover_connect_v4
 *   Request handler. Connects the mover to either a local
 *   or remote data server.
 *
 * Parameters:
 *   connection (input) - connection handle.
 *   body       (input) - request message body.
 *
 * Returns:
 *   void
 */
void
ndmpd_mover_connect_v4(ndmp_connection_t *connection, void *body)
{
	ndmp_mover_connect_request_v4 *request;
	ndmp_mover_connect_reply_v4 reply;
	ndmpd_session_t *session = ndmp_get_client_data(connection);

	request = (ndmp_mover_connect_request_v4 *)body;
	(void) memset((void*)&reply, 0, sizeof (reply));

	if (request->mode != NDMP_MOVER_MODE_READ &&
	    request->mode != NDMP_MOVER_MODE_WRITE) {
		reply.error = NDMP_ILLEGAL_ARGS_ERR;
		NDMP_LOG(LOG_DEBUG, "Invalid mode %d", request->mode);
	} else if (!ndmp_valid_v3addr_type(request->addr.addr_type)) {
		reply.error = NDMP_ILLEGAL_ARGS_ERR;
		NDMP_LOG(LOG_DEBUG, "Invalid address type %d",
		    request->addr.addr_type);
	} else if (session->ns_mover.md_state != NDMP_MOVER_STATE_IDLE) {
		reply.error = NDMP_ILLEGAL_STATE_ERR;
		NDMP_LOG(LOG_DEBUG, "Invalid state %d: mover is not idle",
		    session->ns_mover.md_state);
	} else if (session->ns_tape.td_fd == -1) {
		reply.error = NDMP_DEV_NOT_OPEN_ERR;
		NDMP_LOG(LOG_DEBUG, "No tape device open");
	} else if (request->mode == NDMP_MOVER_MODE_READ &&
	    session->ns_tape.td_mode == NDMP_TAPE_READ_MODE) {
		reply.error = NDMP_PERMISSION_ERR;
		NDMP_LOG(LOG_ERR, "Write protected device.");
	} else if (session->ns_mover.md_record_size == 0) {
		reply.error = NDMP_PRECONDITION_ERR;
		NDMP_LOG(LOG_DEBUG, "Invalid record size 0");
	} else
		reply.error = NDMP_NO_ERR;

	if (reply.error != NDMP_NO_ERR) {
		ndmp_send_reply(connection, (void *) &reply,
		    "sending ndmp_mover_connect reply");
		return;
	}

	switch (request->addr.addr_type) {
	case NDMP_ADDR_LOCAL:
		/*
		 * Verify that the data server is listening for a
		 * local connection.
		 */
		if (session->ns_data.dd_state != NDMP_DATA_STATE_LISTEN ||
		    session->ns_data.dd_listen_sock != -1) {
			NDMP_LOG(LOG_DEBUG,
			    "Data server is not in local listen state");
			reply.error = NDMP_ILLEGAL_STATE_ERR;
		} else
			session->ns_data.dd_state = NDMP_DATA_STATE_CONNECTED;
		break;

	case NDMP_ADDR_TCP:
		reply.error = mover_connect_sock(session, request->mode,
		    request->addr.tcp_ip_v4(0), request->addr.tcp_port_v4(0));
		break;

	default:
		reply.error = NDMP_ILLEGAL_ARGS_ERR;
		NDMP_LOG(LOG_DEBUG, "Invalid address type %d",
		    request->addr.addr_type);
	}

	if (reply.error == NDMP_NO_ERR) {
		session->ns_mover.md_data_addr.addr_type =
		    request->addr.addr_type;
		session->ns_mover.md_state = NDMP_MOVER_STATE_ACTIVE;
		session->ns_mover.md_mode = request->mode;
	}

	ndmp_send_reply(connection, (void *) &reply,
	    "sending ndmp_mover_connect reply");
}



/*
 * ************************************************************************
 * LOCALS
 * ************************************************************************
 */

/*
 * ndmpd_local_write
 *
 * Writes data to the mover.
 * Buffers and write data to the tape device.
 * A full tape record is buffered before being written.
 *
 * Parameters:
 *   session    (input) - session pointer.
 *   data       (input) - data to be written.
 *   length     (input) - data length.
 *
 * Returns:
 *   0 - data successfully written.
 *  -1 - error.
 */
int
ndmpd_local_write(ndmpd_session_t *session, char *data, ulong_t length)
{
	ulong_t count = 0;
	ssize_t n;
	ulong_t len;

	/*
	 * A length of 0 indicates that any buffered data should be
	 * flushed to tape.
	 */
	if (length == 0) {
		if (session->ns_mover.md_w_index == 0)
			return (0);

		(void) memset(
		    &session->ns_mover.md_buf[session->ns_mover.md_w_index],
		    0, session->ns_mover.md_record_size -
		    session->ns_mover.md_w_index);

		n = mover_tape_write_v3(session, session->ns_mover.md_buf,
		    session->ns_mover.md_record_size);
		if (n <= 0) {
			ndmpd_mover_error(session,
			    (n == 0 ? NDMP_MOVER_HALT_ABORTED :
			    NDMP_MOVER_HALT_INTERNAL_ERROR));
			return (-1);
		}
		session->ns_mover.md_position += n;
		session->ns_mover.md_data_written +=
		    session->ns_mover.md_w_index;
		session->ns_mover.md_record_num++;
		session->ns_mover.md_w_index = 0;
		return (0);
	}
	/* Break the data into records. */
	while (count < length) {
		/*
		 * Determine if data needs to be buffered or
		 * can be written directly from user supplied location.
		 * We can fast path the write if there is no pending
		 * buffered data and there is at least a full record's worth
		 * of data to be written.
		 */
		if (session->ns_mover.md_w_index == 0 &&
		    length - count >= session->ns_mover.md_record_size) {
			n = mover_tape_write_v3(session, &data[count],
			    session->ns_mover.md_record_size);
			if (n <= 0) {
				ndmpd_mover_error(session,
				    (n == 0 ? NDMP_MOVER_HALT_ABORTED :
				    NDMP_MOVER_HALT_INTERNAL_ERROR));
				return (-1);
			}
			session->ns_mover.md_position += n;
			session->ns_mover.md_data_written += n;
			session->ns_mover.md_record_num++;
			count += n;
			continue;
		}
		/* Buffer the data */
		len = length - count;
		if (len > session->ns_mover.md_record_size -
		    session->ns_mover.md_w_index)
			len = session->ns_mover.md_record_size -
			    session->ns_mover.md_w_index;

		(void) memcpy(
		    &session->ns_mover.md_buf[session->ns_mover.md_w_index],
		    &data[count], len);
		session->ns_mover.md_w_index += len;
		count += len;

		/* Write the buffer if its full */
		if (session->ns_mover.md_w_index ==
		    session->ns_mover.md_record_size) {
			n = mover_tape_write_v3(session,
			    session->ns_mover.md_buf,
			    session->ns_mover.md_record_size);
			if (n <= 0) {
				ndmpd_mover_error(session,
				    (n == 0 ? NDMP_MOVER_HALT_ABORTED :
				    NDMP_MOVER_HALT_INTERNAL_ERROR));
				return (-1);
			}
			session->ns_mover.md_position += n;
			session->ns_mover.md_data_written += n;
			session->ns_mover.md_record_num++;
			session->ns_mover.md_w_index = 0;
		}
	}

	return (0);
}


/*
 * ndmpd_remote_write
 *
 * Writes data to the remote mover.
 *
 * Parameters:
 *   session    (input) - session pointer.
 *   data       (input) - data to be written.
 *   length     (input) - data length.
 *
 * Returns:
 *   0 - data successfully written.
 *  -1 - error.
 */
int
ndmpd_remote_write(ndmpd_session_t *session, char *data, ulong_t length)
{
	ssize_t n;
	ulong_t count = 0;

	while (count < length) {
		if (session->ns_eof == TRUE ||
		    session->ns_data.dd_abort == TRUE)
			return (-1);

		if ((n = write(session->ns_data.dd_sock, &data[count],
		    length - count)) < 0) {
			NDMP_LOG(LOG_ERR, "Socket write error: %m.");
			return (-1);
		}
		count += n;
	}

	return (0);
}

/*
 * ndmpd_local_read
 *
 * Reads data from the local tape device.
 * Full tape records are read and buffered.
 *
 * Parameters:
 *   session (input) - session pointer.
 *   data    (input) - location to store data.
 *   length  (input) - data length.
 *
 * Returns:
 *   0 - data successfully read.
 *  -1 - error.
 *   1 - session terminated or operation aborted.
 */
int
ndmpd_local_read(ndmpd_session_t *session, char *data, ulong_t length)
{
	ulong_t count = 0;
	ssize_t n;
	ulong_t len;
	ndmp_notify_mover_paused_request pause_request;

	/*
	 * Automatically increase the seek window if necessary.
	 * This is needed in the event the module attempts to read
	 * past a seek window set via a prior call to ndmpd_seek() or
	 * the module has not issued a seek. If no seek was issued then
	 * pretend that a seek was issued to read the entire tape.
	 */
	if (length > session->ns_mover.md_bytes_left_to_read) {
		/* ndmpd_seek() never called? */
		if (session->ns_data.dd_read_length == 0) {
			session->ns_mover.md_bytes_left_to_read = ~0LL;
			session->ns_data.dd_read_offset = 0LL;
			session->ns_data.dd_read_length = ~0LL;
		} else {
			session->ns_mover.md_bytes_left_to_read = length;
			session->ns_data.dd_read_offset =
			    session->ns_mover.md_position;
			session->ns_data.dd_read_length = length;
		}
	}
	/*
	 * Read as many records as necessary to satisfy the request.
	 */
	while (count < length) {
		/*
		 * If the end of the mover window has been reached,
		 * then notify the client that a new data window is needed.
		 */
		if (session->ns_mover.md_position >=
		    session->ns_mover.md_window_offset +
		    session->ns_mover.md_window_length) {

			session->ns_mover.md_state = NDMP_MOVER_STATE_PAUSED;
			session->ns_mover.md_pause_reason =
			    NDMP_MOVER_PAUSE_SEEK;
			pause_request.reason = NDMP_MOVER_PAUSE_SEEK;
			pause_request.seek_position =
			    long_long_to_quad(session->ns_mover.md_position);

			if (ndmp_send_request(session->ns_connection,
			    NDMP_NOTIFY_MOVER_PAUSED, NDMP_NO_ERR,
			    (void *) &pause_request, 0) < 0) {
				NDMP_LOG(LOG_DEBUG,
				    "Sending notify_mover_paused request");
				ndmpd_mover_error(session,
				    NDMP_MOVER_HALT_INTERNAL_ERROR);
				return (-1);
			}
			/*
			 * Wait until the state is changed by
			 * an abort or continue request.
			 */
			if (ndmp_wait_for_mover(session) != 0)
				return (1);
		}
		len = length - count;

		/*
		 * Prevent reading past the end of the window.
		 */
		if (len >
		    session->ns_mover.md_window_offset +
		    session->ns_mover.md_window_length -
		    session->ns_mover.md_position)
			len = session->ns_mover.md_window_offset +
			    session->ns_mover.md_window_length -
			    session->ns_mover.md_position;

		/*
		 * Copy from the data buffer first.
		 */
		if (session->ns_mover.md_w_index -
		    session->ns_mover.md_r_index != 0) {
			/*
			 * Limit the copy to the amount of data in the buffer.
			 */
			if (len > session->ns_mover.md_w_index -
			    session->ns_mover.md_r_index)
				len = session->ns_mover.md_w_index
				    - session->ns_mover.md_r_index;

			(void) memcpy((void *) &data[count],
			    &session->ns_mover.md_buf[session->
			    ns_mover.md_r_index], len);
			count += len;
			session->ns_mover.md_r_index += len;
			session->ns_mover.md_bytes_left_to_read -= len;
			session->ns_mover.md_position += len;
			continue;
		}
		/*
		 * Determine if data needs to be buffered or
		 * can be read directly to user supplied location.
		 * We can fast path the read if at least a full record
		 * needs to be read and there is no seek pending.
		 * This is done to eliminate a buffer copy.
		 */
		if (len >= session->ns_mover.md_record_size &&
		    session->ns_mover.md_position >=
		    session->ns_mover.md_seek_position) {
			n = tape_read(session, &data[count]);
			if (n <= 0) {
				if (n == TAPE_NO_WRITER_ERR)
					return (1);

				ndmpd_mover_error(session,
				    (n == 0 ? NDMP_MOVER_HALT_ABORTED :
				    NDMP_MOVER_HALT_INTERNAL_ERROR));
				return (n == 0) ? (1) : (-1);
			}
			count += n;
			session->ns_mover.md_bytes_left_to_read -= n;
			session->ns_mover.md_position += n;
			continue;
		}
		/* Read the next record into the buffer. */
		n = tape_read(session, session->ns_mover.md_buf);
		if (n <= 0) {
			if (n == TAPE_NO_WRITER_ERR)
				return (1);

			ndmpd_mover_error(session,
			    (n == 0 ? NDMP_MOVER_HALT_ABORTED :
			    NDMP_MOVER_HALT_INTERNAL_ERROR));
			return (n == 0) ? (1) : (-1);
		}
		session->ns_mover.md_w_index = n;
		session->ns_mover.md_r_index = 0;

		NDMP_LOG(LOG_DEBUG, "n: %d", n);

		/*
		 * Discard data if the current data stream position is
		 * prior to the seek position. This is necessary if a seek
		 * request set the seek pointer to a position that is not a
		 * record boundary. The seek request handler can only position
		 * to the start of a record.
		 */
		if (session->ns_mover.md_position <
		    session->ns_mover.md_seek_position) {
			session->ns_mover.md_r_index =
			    session->ns_mover.md_seek_position -
			    session->ns_mover.md_position;
			session->ns_mover.md_position =
			    session->ns_mover.md_seek_position;
		}
	}

	return (0);
}


/*
 * ndmpd_remote_read
 *
 * Reads data from the remote mover.
 *
 * Parameters:
 *   session (input) - session pointer.
 *   data    (input) - data to be written.
 *   length  (input) - data length.
 *
 * Returns:
 *   0 - data successfully read.
 *  -1 - error.
 *   1 - session terminated or operation aborted.
 */
int
ndmpd_remote_read(ndmpd_session_t *session, char *data, ulong_t length)
{
	ulong_t count = 0;
	ssize_t n;
	ulong_t len;
	ndmp_notify_data_read_request request;

	while (count < length) {
		len = length - count;

		/*
		 * If the end of the seek window has been reached then
		 * send an ndmp_read request to the client.
		 * The NDMP client will then send a mover_data_read request to
		 * the remote mover and the mover will send more data.
		 * This condition can occur if the module attempts to read past
		 * a seek window set via a prior call to ndmpd_seek() or
		 * the module has not issued a seek. If no seek was issued then
		 * pretend that a seek was issued to read the entire tape.
		 */
		if (session->ns_mover.md_bytes_left_to_read == 0) {
			/* ndmpd_seek() never called? */
			if (session->ns_data.dd_read_length == 0) {
				session->ns_mover.md_bytes_left_to_read = ~0LL;
				session->ns_data.dd_read_offset = 0LL;
				session->ns_data.dd_read_length = ~0LL;
			} else {
				session->ns_mover.md_bytes_left_to_read = len;
				session->ns_data.dd_read_offset =
				    session->ns_mover.md_position;
				session->ns_data.dd_read_length = len;
			}

			request.offset =
			    long_long_to_quad(session->ns_data.dd_read_offset);
			request.length =
			    long_long_to_quad(session->ns_data.dd_read_length);

			if (ndmp_send_request_lock(session->ns_connection,
			    NDMP_NOTIFY_DATA_READ, NDMP_NO_ERR,
			    (void *) &request, 0) < 0) {
				NDMP_LOG(LOG_DEBUG,
				    "Sending notify_data_read request");
				return (-1);
			}
		}
		if (session->ns_eof == TRUE ||
		    session->ns_data.dd_abort == TRUE)
			return (1);

		/*
		 * If the module called ndmpd_seek() prior to reading all of the
		 * data that the remote mover was requested to send, then the
		 * excess data from the seek has to be discardd.
		 */
		if (session->ns_mover.md_discard_length != 0) {
			n = discard_data(session,
			    (ulong_t)session->ns_mover.md_discard_length);
			if (n < 0)
				return (-1);
			session->ns_mover.md_discard_length -= n;
			continue;
		}
		/*
		 * Don't attempt to read more data than the remote is sending.
		 */
		if (len > session->ns_mover.md_bytes_left_to_read)
			len = session->ns_mover.md_bytes_left_to_read;

		NDMP_LOG(LOG_DEBUG, "len: %u", len);

		if ((n = read(session->ns_data.dd_sock, &data[count],
		    len)) < 0) {
			NDMP_LOG(LOG_ERR, "Socket read error: %m.");
			return (-1);
		}
		/* read returns 0 if the connection was closed */
		if (n == 0)
			return (-1);

		count += n;
		session->ns_mover.md_bytes_left_to_read -= n;
		session->ns_mover.md_position += n;
	}

	return (0);
}

/* *** ndmpd internal functions ***************************************** */

/*
 * ndmpd_mover_init
 *
 * Initialize mover specific session variables.
 * Don't initialize variables such as record_size that need to
 * persist across data operations. A client may open a connection and
 * do multiple backups after setting the record_size.
 *
 * Parameters:
 *   session (input) - session pointer.
 *
 * Returns:
 *   0 - success.
 *  -1 - error.
 */
int
ndmpd_mover_init(ndmpd_session_t *session)
{
	session->ns_mover.md_state = NDMP_MOVER_STATE_IDLE;
	session->ns_mover.md_pause_reason = NDMP_MOVER_PAUSE_NA;
	session->ns_mover.md_halt_reason = NDMP_MOVER_HALT_NA;
	session->ns_mover.md_data_written = 0LL;
	session->ns_mover.md_seek_position = 0LL;
	session->ns_mover.md_bytes_left_to_read = 0LL;
	session->ns_mover.md_window_offset = 0LL;
	session->ns_mover.md_window_length = MAX_WINDOW_SIZE;
	session->ns_mover.md_position = 0LL;
	session->ns_mover.md_discard_length = 0;
	session->ns_mover.md_record_num = 0;
	session->ns_mover.md_record_size = 0;
	session->ns_mover.md_listen_sock = -1;
	session->ns_mover.md_pre_cond = FALSE;
	session->ns_mover.md_sock = -1;
	session->ns_mover.md_r_index = 0;
	session->ns_mover.md_w_index = 0;
	session->ns_mover.md_buf = ndmp_malloc(MAX_RECORD_SIZE);
	if (!session->ns_mover.md_buf)
		return (-1);

	if (ndmp_get_version(session->ns_connection) == NDMPV3) {
		session->ns_mover.md_mode = NDMP_MOVER_MODE_READ;
		(void) memset(&session->ns_mover.md_data_addr, 0,
		    sizeof (ndmp_addr_v3));
	}
	return (0);
}


/*
 * ndmpd_mover_shut_down
 *
 * Shutdown the mover. It closes all the sockets.
 *
 * Parameters:
 *   session (input) - session pointer.
 *
 * Returns:
 *   void
 */
void
ndmpd_mover_shut_down(ndmpd_session_t *session)
{
	ndmp_lbr_params_t *nlp;

	if ((nlp = ndmp_get_nlp(session)) == NULL)
		return;

	(void) mutex_lock(&nlp->nlp_mtx);
	if (session->ns_mover.md_listen_sock != -1) {
		NDMP_LOG(LOG_DEBUG, "mover.listen_sock: %d",
		    session->ns_mover.md_listen_sock);
		(void) ndmpd_remove_file_handler(session,
		    session->ns_mover.md_listen_sock);
		(void) close(session->ns_mover.md_listen_sock);
		session->ns_mover.md_listen_sock = -1;
	}
	if (session->ns_mover.md_sock != -1) {
		NDMP_LOG(LOG_DEBUG, "mover.sock: %d",
		    session->ns_mover.md_sock);
		(void) ndmpd_remove_file_handler(session,
		    session->ns_mover.md_sock);
		(void) close(session->ns_mover.md_sock);
		session->ns_mover.md_sock = -1;
	}
	(void) cond_broadcast(&nlp->nlp_cv);
	(void) mutex_unlock(&nlp->nlp_mtx);
}


/*
 * ndmpd_mover_cleanup
 *
 * Parameters:
 *   session (input) - session pointer.
 *
 * Returns:
 *   void
 */
void
ndmpd_mover_cleanup(ndmpd_session_t *session)
{
	NDMP_FREE(session->ns_mover.md_buf);
}


/*
 * ndmpd_mover_connect
 *   Create a connection to the specified mover.
 *
 * Parameters:
 *   session (input) - session pointer
 *
 * Returns:
 *   error code.
 */
ndmp_error
ndmpd_mover_connect(ndmpd_session_t *session, ndmp_mover_mode mover_mode)
{
	ndmp_mover_addr *mover = &session->ns_data.dd_mover;
	struct sockaddr_in sin;
	int sock = -1;

	if (mover->addr_type == NDMP_ADDR_TCP) {
		if (mover->ndmp_mover_addr_u.addr.ip_addr) {
			(void) memset((void *) &sin, 0, sizeof (sin));
			sin.sin_family = AF_INET;
			sin.sin_addr.s_addr =
			    htonl(mover->ndmp_mover_addr_u.addr.ip_addr);
			sin.sin_port =
			    htons(mover->ndmp_mover_addr_u.addr.port);

			/*
			 * If the address type is TCP but both the address and
			 * the port number are zero, we have to use a different
			 * socket than the mover socket. This can happen when
			 * using NDMP disk to disk copy (AKA D2D copy).
			 * The NDMPCopy client will send a zero address to
			 * direct the server to use the mover socket as the
			 * data socket to receive the recovery data.
			 */
			if (sin.sin_addr.s_addr == 0 && sin.sin_port == 0) {
				session->ns_data.dd_sock =
				    session->ns_mover.md_sock;
				return (NDMP_NO_ERR);
			}

			NDMP_LOG(LOG_DEBUG, "addr: %u port: %u",
			    mover->ndmp_mover_addr_u.addr.ip_addr,
			    (ulong_t)sin.sin_port);

			if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
				NDMP_LOG(LOG_DEBUG, "Socket error: %m");
				return (NDMP_IO_ERR);
			}
			if (connect(sock, (struct sockaddr *)&sin,
			    sizeof (sin)) < 0) {
				NDMP_LOG(LOG_DEBUG, "Connect error: %m");
				(void) close(sock);
				return (NDMP_IO_ERR);
			}
			set_socket_options(sock);
		} else {
			if ((session->ns_mover.md_state !=
			    NDMP_MOVER_STATE_ACTIVE) ||
			    (session->ns_mover.md_sock == -1)) {

				NDMP_LOG(LOG_DEBUG,
				    "Not in active  state mover"
				    "  state = %d or Invalid mover sock=%d",
				    session->ns_mover.md_state,
				    session->ns_mover.md_sock);
				return (NDMP_ILLEGAL_STATE_ERR);
			}

			sock = session->ns_mover.md_sock;
			NDMP_LOG(LOG_DEBUG,
			    "session: 0x%x setting data sock fd: %d to be"
			    " same as listen_sock", session, sock);
		}

		NDMP_LOG(LOG_DEBUG, "sock fd: %d", sock);

		session->ns_data.dd_sock = sock;

		NDMP_LOG(LOG_DEBUG, "data.mover_sock: %u", sock);

		return (NDMP_NO_ERR);
	}
	/* Local mover connection. */

	if (session->ns_mover.md_state != NDMP_MOVER_STATE_LISTEN) {
		NDMP_LOG(LOG_DEBUG, "Mover is not in listen state");
		return (NDMP_ILLEGAL_STATE_ERR);
	}
	if (session->ns_tape.td_fd == -1) {
		NDMP_LOG(LOG_DEBUG, "Tape device not open");
		return (NDMP_DEV_NOT_OPEN_ERR);
	}
	if (mover_mode == NDMP_MOVER_MODE_READ &&
	    session->ns_tape.td_mode == NDMP_TAPE_READ_MODE) {
		NDMP_LOG(LOG_ERR, "Write protected device.");
		return (NDMP_WRITE_PROTECT_ERR);
	}
	session->ns_mover.md_state = NDMP_MOVER_STATE_ACTIVE;
	session->ns_mover.md_mode = mover_mode;

	return (NDMP_NO_ERR);
}



/*
 * ndmpd_mover_seek
 *
 * Seek to the requested data stream position.
 * If the requested offset is outside of the current window,
 * the mover is paused and a notify_mover_paused request is sent
 * notifying the client that a seek is required.
 * If the requested offest is within the window but not within the
 * current record, then the tape is positioned to the record containing
 * the requested offest.
 * The requested amount of data is then read from the tape device and
 * written to the data connection.
 *
 * Parameters:
 *   session (input) - session pointer.
 *   offset  (input) - data stream position to seek to.
 *   length  (input) - amount of data that will be read.
 *
 * Returns:
 *   1 - seek pending completion by the NDMP client.
 *   0 - seek successfully completed.
 *  -1 - error.
 */
int
ndmpd_mover_seek(ndmpd_session_t *session, u_longlong_t offset,
    u_longlong_t length)
{
	int ctlcmd;
	int ctlcnt;
	u_longlong_t tape_position;
	u_longlong_t buf_position;
	ndmp_notify_mover_paused_request pause_request;

	session->ns_mover.md_seek_position = offset;
	session->ns_mover.md_bytes_left_to_read = length;

	/*
	 * If the requested position is outside of the window,
	 * notify the client that a seek is required.
	 */
	if (session->ns_mover.md_seek_position <
	    session->ns_mover.md_window_offset ||
	    session->ns_mover.md_seek_position >=
	    session->ns_mover.md_window_offset +
	    session->ns_mover.md_window_length) {
		NDMP_LOG(LOG_DEBUG, "MOVER_PAUSE_SEEK(%llu)",
		    session->ns_mover.md_seek_position);

		session->ns_mover.md_w_index = 0;
		session->ns_mover.md_r_index = 0;

		session->ns_mover.md_state = NDMP_MOVER_STATE_PAUSED;
		session->ns_mover.md_pause_reason = NDMP_MOVER_PAUSE_SEEK;
		pause_request.reason = NDMP_MOVER_PAUSE_SEEK;
		pause_request.seek_position = long_long_to_quad(offset);

		if (ndmp_send_request(session->ns_connection,
		    NDMP_NOTIFY_MOVER_PAUSED, NDMP_NO_ERR,
		    (void *) &pause_request, 0) < 0) {
			NDMP_LOG(LOG_DEBUG,
			    "Sending notify_mover_paused request");
			return (-1);
		}
		return (1);
	}
	/*
	 * Determine the data stream position of the first byte in the
	 * data buffer.
	 */
	buf_position = session->ns_mover.md_position -
	    (session->ns_mover.md_position % session->ns_mover.md_record_size);

	/*
	 * Determine the data stream position of the next byte that
	 * will be read from tape.
	 */
	tape_position = buf_position;
	if (session->ns_mover.md_w_index != 0)
		tape_position += session->ns_mover.md_record_size;

	/*
	 * Check if requested position is for data that has been read and is
	 * in the buffer.
	 */
	if (offset >= buf_position && offset < tape_position) {
		session->ns_mover.md_position = offset;
		session->ns_mover.md_r_index = session->ns_mover.md_position -
		    buf_position;

		NDMP_LOG(LOG_DEBUG, "pos %llu r_index %u",
		    session->ns_mover.md_position,
		    session->ns_mover.md_r_index);

		return (0);
	}

	ctlcmd = 0;
	if (tape_position > session->ns_mover.md_seek_position) {
		/* Need to seek backward. */
		ctlcmd = MTBSR;
		ctlcnt = (int)((tape_position - offset - 1)
		    / session->ns_mover.md_record_size) + 1;
		tape_position -= ((u_longlong_t)(((tape_position - offset - 1) /
		    session->ns_mover.md_record_size) + 1) *
		    (u_longlong_t)session->ns_mover.md_record_size);

	} else if (offset >= tape_position + session->ns_mover.md_record_size) {
		/* Need to seek forward. */
		ctlcmd = MTFSR;
		ctlcnt = (int)((offset - tape_position)
		    / session->ns_mover.md_record_size);
		tape_position += ((u_longlong_t)(((offset - tape_position) /
		    session->ns_mover.md_record_size)) *
		    (u_longlong_t)session->ns_mover.md_record_size);
	}
	/* Reposition the tape if necessary. */
	if (ctlcmd) {
		NDMP_LOG(LOG_DEBUG, "cmd %d count %d",
		    ctlcmd, ctlcnt);
		(void) ndmp_mtioctl(session->ns_tape.td_fd, ctlcmd, ctlcnt);
	}

	session->ns_mover.md_position = tape_position;
	session->ns_mover.md_r_index = 0;
	session->ns_mover.md_w_index = 0;

	NDMP_LOG(LOG_DEBUG, "pos %llu", session->ns_mover.md_position);

	return (0);
}


/* ** static functions ************************************************** */

/*
 * create_listen_socket_v2
 *
 * Creates a socket for listening for accepting data connections.
 *
 * Parameters:
 *   session (input)  - session pointer.
 *   addr    (output) - location to store address of socket.
 *   port    (output) - location to store port of socket.
 *
 * Returns:
 *   0 - success.
 *  -1 - error.
 */
static int
create_listen_socket_v2(ndmpd_session_t *session, ulong_t *addr, ushort_t *port)
{
	session->ns_mover.md_listen_sock = ndmp_create_socket(addr, port);
	if (session->ns_mover.md_listen_sock < 0)
		return (-1);

	/*
	 * Add a file handler for the listen socket.
	 * ndmpd_select will call accept_connection when a
	 * connection is ready to be accepted.
	 */
	if (ndmpd_add_file_handler(session, (void *) session,
	    session->ns_mover.md_listen_sock, NDMPD_SELECT_MODE_READ, HC_MOVER,
	    accept_connection) < 0) {
		(void) close(session->ns_mover.md_listen_sock);
		session->ns_mover.md_listen_sock = -1;
		return (-1);
	}

	NDMP_LOG(LOG_DEBUG, "addr: 0x%x, port: %d", *addr, *port);
	return (0);
}

/*
 * accept_connection
 *
 * Accept a data connection from a data server.
 * Called by ndmpd_select when a connection is pending on
 * the mover listen socket.
 *
 * Parameters:
 *   cookie  (input) - session pointer.
 *   fd      (input) - file descriptor.
 *   mode    (input) - select mode.
 *
 * Returns:
 *   void.
 */
/*ARGSUSED*/
static void
accept_connection(void *cookie, int fd, ulong_t mode)
{
	ndmpd_session_t *session = (ndmpd_session_t *)cookie;
	struct sockaddr_in from;
	int from_len;

	from_len = sizeof (from);
	session->ns_mover.md_sock = accept(fd, (struct sockaddr *)&from,
	    &from_len);

	(void) ndmpd_remove_file_handler(session, fd);
	(void) close(session->ns_mover.md_listen_sock);
	session->ns_mover.md_listen_sock = -1;

	if (session->ns_mover.md_sock < 0) {
		NDMP_LOG(LOG_DEBUG, "Accept error: %m");
		ndmpd_mover_error(session, NDMP_MOVER_HALT_CONNECT_ERROR);
		return;
	}
	set_socket_options(session->ns_mover.md_sock);

	NDMP_LOG(LOG_DEBUG, "sock fd: %d", session->ns_mover.md_sock);

	if (session->ns_mover.md_mode == NDMP_MOVER_MODE_READ) {
		if (start_mover_for_backup(session) < 0) {
			ndmpd_mover_error(session,
			    NDMP_MOVER_HALT_INTERNAL_ERROR);
			return;
		}
		NDMP_LOG(LOG_DEBUG, "Backup connection established by %s:%d",
		    inet_ntoa(IN_ADDR(from.sin_addr.s_addr)),
		    ntohs(from.sin_port));
	} else {
		NDMP_LOG(LOG_DEBUG, "Restore connection established by %s:%d",
		    inet_ntoa(IN_ADDR(from.sin_addr.s_addr)),
		    ntohs(from.sin_port));
	}

	NDMP_LOG(LOG_DEBUG, "Received connection");

	session->ns_mover.md_state = NDMP_MOVER_STATE_ACTIVE;
}

/*
 * tape_read
 *
 * Reads a data record from tape. Detects and handles EOT conditions.
 *
 * Parameters:
 *   session (input) - session pointer.
 *   data    (input) - location to read data to.
 *
 * Returns:
 *    0 - operation aborted.
 *   -1 - tape read error.
 *   otherwise - number of bytes read.
 */
static int
tape_read(ndmpd_session_t *session, char *data)
{
	ssize_t n;
	int err;
	int count = session->ns_mover.md_record_size;

	for (; ; ) {
		n = read(session->ns_tape.td_fd, data, count);
		if (n < 0) {
			NDMP_LOG(LOG_ERR, "Tape read error: %m.");
			return (TAPE_READ_ERR);
		}
		NS_ADD(rtape, n);

		if (n == 0) {
			if (!is_writer_running(session))
				return (TAPE_NO_WRITER_ERR);

			/*
			 * End of media reached.
			 * Notify client and wait for the client to
			 * either abort the data operation or continue the
			 * operation after changing the tape.
			 */
			NDMP_APILOG((void*)session, NDMP_LOG_NORMAL,
			    ++ndmp_log_msg_id,
			    "End of tape reached. Load next tape");

			NDMP_LOG(LOG_DEBUG,
			    "End of tape reached. Load next tape");

			err = change_tape(session);

			/* Operation aborted or connection terminated? */
			if (err < 0) {
				/*
				 * K.L. Go back one record if it is read
				 * but not used.
				 */

				if (count != session->ns_mover.md_record_size) {
					(void) ndmp_mtioctl(
					    session->ns_tape.td_fd, MTBSR, 1);
				}
				return (0);
			}
			/* Retry the read from the new tape. */
			continue;
		}

		/* Change to pass Veritas Netbackup prequal test. */
		data += n;
		count -= n;
		if (count <= 0) {
			session->ns_mover.md_record_num++;
			session->ns_tape.td_record_count++;
			return (n);
		}
	}
}

/*
 * change_tape
 *
 * Send a notify_pause request (protocol version 1) or
 * notify_mover_pause request (protocol version 2) to the
 * NDMP client to inform
 * the client that a tape volume change is required.
 * Process messages until the data/mover operation is either aborted
 * or continued.
 *
 * Parameters:
 *   client_data (input) - session pointer.
 *
 * Returns:
 *   0 - operation has been continued.
 *  -1 - operation has been aborted.
 */
static int
change_tape(ndmpd_session_t *session)
{
	ndmp_notify_mover_paused_request request;

	session->ns_mover.md_state = NDMP_MOVER_STATE_PAUSED;

	if (session->ns_mover.md_mode == NDMP_MOVER_MODE_READ)
		session->ns_mover.md_pause_reason = NDMP_MOVER_PAUSE_EOM;
	else
		session->ns_mover.md_pause_reason = NDMP_MOVER_PAUSE_EOF;

	request.reason = session->ns_mover.md_pause_reason;
	request.seek_position = long_long_to_quad(0LL);

	NDMP_LOG(LOG_DEBUG, "ndmp_send_request: MOVER_PAUSED, reason: %d",
	    session->ns_mover.md_pause_reason);

	if (ndmp_send_request(session->ns_connection,
	    NDMP_NOTIFY_MOVER_PAUSED, NDMP_NO_ERR,
	    (void *) &request, 0) < 0) {
		NDMP_LOG(LOG_DEBUG,
		    "Sending notify_mover_paused request");
		return (-1);
	}
	/*
	 * Wait for until the state is changed by
	 * an abort or continue request.
	 */
	return (ndmp_wait_for_mover(session));
}


/*
 * discard_data
 *
 * Read and discard data from the data connection.
 * Called when a module has called ndmpd_seek() prior to
 * reading all of the data from the previous seek.
 *
 * Parameters:
 *   session (input) - session pointer.
 *
 * Returns:
 *   number of bytes read and discarded.
 *  -1 - error.
 */
static int
discard_data(ndmpd_session_t *session, ulong_t length)
{
	int n;
	char *addr;

	if ((addr = ndmp_malloc(length)) == NULL)
		return (-1);

	/* Read and discard the data. */
	n = read(session->ns_mover.md_sock, addr, length);
	if (n < 0) {
		NDMP_LOG(LOG_ERR, "Socket read error: %m.");
		free(addr);
		return (-1);
	}

	free(addr);
	return (n);
}


/*
 * mover_tape_read_one_buf
 *
 * Read one buffer from the tape. This is used by mover_tape_reader
 *
 * Parameters:
 *   session (input) - session pointer.
 *   buf (input) - buffer read
 *
 * Returns:
 *   0: on success
 *  -1: otherwise
 */
static int
mover_tape_read_one_buf(ndmpd_session_t *session, tlm_buffer_t *buf)
{
	int n;

	tlm_buffer_mark_empty(buf);

	/*
	 * If the end of the mover window has been reached,
	 * then notify the client that a seek is needed.
	 * Remove the file handler to prevent this function from
	 * being called. The handler will be reinstalled in
	 * ndmpd_mover_continue.
	 */

	if (session->ns_mover.md_position >=
	    session->ns_mover.md_window_offset +
	    session->ns_mover.md_window_length) {
		ndmp_notify_mover_paused_request pause_request;

		NDMP_LOG(LOG_DEBUG, "end of mover window");

		session->ns_mover.md_state = NDMP_MOVER_STATE_PAUSED;
		session->ns_mover.md_pause_reason = NDMP_MOVER_PAUSE_SEEK;
		pause_request.reason = NDMP_MOVER_PAUSE_SEEK;
		pause_request.seek_position =
		    long_long_to_quad(session->ns_mover.md_position);

		if (ndmp_send_request(session->ns_connection,
		    NDMP_NOTIFY_MOVER_PAUSED, NDMP_NO_ERR,
		    (void *) &pause_request, 0) < 0) {
			NDMP_LOG(LOG_DEBUG,
			    "Sending notify_mover_paused request");
			ndmpd_mover_error(session,
			    NDMP_MOVER_HALT_INTERNAL_ERROR);
		}
		buf->tb_errno = EIO;
		return (TAPE_READ_ERR);
	}

	n = tape_read(session, buf->tb_buffer_data);

	NDMP_LOG(LOG_DEBUG, "read %d bytes from tape", n);

	if (n <= 0) {
		if (n < 0)
			ndmpd_mover_error(session,
			    (n == 0 ? NDMP_MOVER_HALT_ABORTED :
			    NDMP_MOVER_HALT_INTERNAL_ERROR));
		return (TAPE_READ_ERR);
	}

	buf->tb_full = TRUE;
	buf->tb_buffer_size = session->ns_mover.md_record_size;

	/*
	 * Discard data if the current data stream position is
	 * prior to the seek position. This is necessary if a seek
	 * request set the seek pointer to a position that is not a
	 * record boundary. The seek request handler can only position
	 * to the start of a record.
	 */
	if (session->ns_mover.md_position < session->ns_mover.md_seek_position)
		session->ns_mover.md_position =
		    session->ns_mover.md_seek_position;

	return (0);
}


/*
 * mover_tape_reader
 *
 * Mover tape reader thread. It is launched when the mover is started
 * for restore.
 *
 * Parameters:
 *   session (input) - session pointer.
 *
 * Returns:
 *   0: on success
 *  -1: otherwise
 */
int
mover_tape_reader(ndmpd_session_t *session)
{
	int bidx;	/* buffer index */
	int rv;
	ndmp_lbr_params_t *nlp;
	tlm_buffer_t *buf;
	tlm_buffers_t *bufs;
	tlm_cmd_t *lcmd;	/* Local command */
	tlm_commands_t *cmds;	/* Commands structure */

	if ((nlp = ndmp_get_nlp(session)) == NULL) {
		NDMP_LOG(LOG_DEBUG, "nlp == NULL");
		return (-1);
	}

	cmds = &nlp->nlp_cmds;
	lcmd = cmds->tcs_command;
	bufs = lcmd->tc_buffers;

	lcmd->tc_ref++;
	cmds->tcs_reader_count++;

	/*
	 * Let our parent thread know that we are running.
	 */
	tlm_cmd_signal(cmds->tcs_command, TLM_TAPE_READER);

	buf = tlm_buffer_in_buf(bufs, &bidx);
	while (cmds->tcs_reader == TLM_RESTORE_RUN &&
	    lcmd->tc_reader == TLM_RESTORE_RUN) {
		buf = tlm_buffer_in_buf(bufs, NULL);

		if (buf->tb_full) {
			NDMP_LOG(LOG_DEBUG, "R%d", bidx);
			/*
			 * The buffer is still full, wait for the consumer
			 * thread to use it.
			 */
			tlm_buffer_out_buf_timed_wait(bufs, 100);

		} else {
			NDMP_LOG(LOG_DEBUG, "r%d", bidx);

			rv = mover_tape_read_one_buf(session, buf);
			/*
			 * If there was an error while reading, such as
			 * end of stream.
			 */
			if (rv < 0) {
				NDMP_LOG(LOG_DEBUG, "Exiting, rv: %d", rv);
				break;
			}

			/*
			 * Can we do more buffering?
			 */
			if (is_buffer_erroneous(buf)) {
				NDMP_LOG(LOG_DEBUG,
				    "Exiting, errno: %d, eot: %d, eof: %d",
				    buf->tb_errno, buf->tb_eot, buf->tb_eof);
				break;
			}

			(void) tlm_buffer_advance_in_idx(bufs);
			tlm_buffer_release_in_buf(bufs);
			bidx = bufs->tbs_buffer_in;
		}
	}

	/* If the consumer is waiting for us, wake it up. */
	tlm_buffer_release_in_buf(bufs);

	/*
	 * Clean up.
	 */
	cmds->tcs_reader_count--;
	lcmd->tc_ref--;
	lcmd->tc_writer = TLM_STOP;
	return (0);
}


/*
 * mover_socket_write_one_buf
 *
 * Write one buffer to the network socket. This is used by mover_socket_writer
 *
 * Parameters:
 *   session (input) - session pointer.
 *   buf (input) - buffer read
 *
 * Returns:
 *   0: on success
 *  -1: otherwise
 */
static int
mover_socket_write_one_buf(ndmpd_session_t *session, tlm_buffer_t *buf)
{
	int n;

	/* Write the data to the data connection. */
	errno = 0;
	n = write(session->ns_mover.md_sock, buf->tb_buffer_data,
	    buf->tb_buffer_size);

	NDMP_LOG(LOG_DEBUG, "n: %d, len: %d", n, buf->tb_buffer_size);

	if (n < 0) {
		NDMP_LOG(LOG_DEBUG, "n: %d, errno: %m", n);
		ndmpd_mover_error(session, NDMP_MOVER_HALT_CONNECT_CLOSED);
		return (-1);
	}

	session->ns_mover.md_position += n;
	session->ns_mover.md_bytes_left_to_read -= n;
	tlm_buffer_mark_empty(buf);

	/*
	 * If the read limit has been reached,
	 * then remove the file handler to prevent this
	 * function from getting called. The next mover_read request
	 * will reinstall the handler.
	 */
	if (session->ns_mover.md_bytes_left_to_read == 0) {
		NDMP_LOG(LOG_DEBUG, "bytes_left_to_read == 0");
		(void) ndmpd_remove_file_handler(session,
		    session->ns_mover.md_sock);
		return (-1);
	}

	return (0);
}



/*
 * mover_socket_writer
 *
 * Mover's socket writer thread. This thread sends the read buffer
 * from the tape to the data server through the network socket.
 *
 * Parameters:
 *   session (input) - session pointer.
 *
 * Returns:
 *   0: on success
 *  -1: otherwise
 */
int
mover_socket_writer(ndmpd_session_t *session)
{
	int bidx;	/* buffer index */
	ndmp_lbr_params_t *nlp;
	tlm_buffer_t *buf;
	tlm_buffers_t *bufs;
	tlm_cmd_t *lcmd;	/* Local command */
	tlm_commands_t *cmds;	/* Commands structure */

	if ((nlp = ndmp_get_nlp(session)) == NULL) {
		NDMP_LOG(LOG_DEBUG, "nlp == NULL");
		return (-1);
	}

	cmds = &nlp->nlp_cmds;
	lcmd = cmds->tcs_command;
	bufs = lcmd->tc_buffers;

	lcmd->tc_ref++;
	cmds->tcs_writer_count++;

	/*
	 * Let our parent thread know that we are running.
	 */
	tlm_cmd_signal(cmds->tcs_command, TLM_SOCK_WRITER);

	bidx = bufs->tbs_buffer_out;
	while (cmds->tcs_writer != (int)TLM_ABORT &&
	    lcmd->tc_writer != (int)TLM_ABORT) {
		buf = &bufs->tbs_buffer[bidx];

		if (buf->tb_full) {
			NDMP_LOG(LOG_DEBUG, "w%d", bidx);

			if (mover_socket_write_one_buf(session, buf) < 0) {
				NDMP_LOG(LOG_DEBUG,
				    "mover_socket_write_one_buf() < 0");
				break;
			}

			(void) tlm_buffer_advance_out_idx(bufs);
			tlm_buffer_release_out_buf(bufs);
			bidx = bufs->tbs_buffer_out;
		} else {
			if (lcmd->tc_writer != TLM_RESTORE_RUN) {
				/* No more data is coming, time to exit */
				NDMP_LOG(LOG_DEBUG, "Time to exit");
				break;
			}
			NDMP_LOG(LOG_DEBUG, "W%d", bidx);
			/*
			 * The buffer is not full, wait for the producer
			 * thread to fill it.
			 */
			tlm_buffer_in_buf_timed_wait(bufs, 100);
		}
	}

	if (cmds->tcs_writer == (int)TLM_ABORT)
		NDMP_LOG(LOG_DEBUG, "cmds->tcs_writer == (int)TLM_ABORT");
	if (lcmd->tc_writer == (int)TLM_ABORT)
		NDMP_LOG(LOG_DEBUG, "lcmd->tc_writer == TLM_ABORT");

	/* If the producer is waiting for us, wake it up. */
	tlm_buffer_release_out_buf(bufs);

	/*
	 * Clean up.
	 */
	cmds->tcs_writer_count--;
	lcmd->tc_ref--;
	lcmd->tc_reader = TLM_STOP;
	return (0);
}


/*
 * start_mover_for_restore
 *
 * Creates the mover tape reader and network writer threads for
 * the mover to perform the 3-way restore.
 *
 * Parameters:
 *   session (input) - session pointer.
 *
 * Returns:
 *   0: on success
 *  -1: otherwise
 */
static int
start_mover_for_restore(ndmpd_session_t *session)
{
	ndmp_lbr_params_t *nlp;
	tlm_commands_t *cmds;
	long xfer_size;
	int rc;

	if ((nlp = ndmp_get_nlp(session)) == NULL) {
		NDMP_LOG(LOG_DEBUG, "nlp == NULL");
		return (-1);
	}

	cmds = &nlp->nlp_cmds;
	(void) memset(cmds, 0, sizeof (*cmds));
	cmds->tcs_reader = cmds->tcs_writer = TLM_RESTORE_RUN;
	xfer_size = ndmp_buffer_get_size(session);
	cmds->tcs_command = tlm_create_reader_writer_ipc(FALSE, xfer_size);
	if (cmds->tcs_command == NULL)
		return (-1);

	cmds->tcs_command->tc_reader = TLM_RESTORE_RUN;
	cmds->tcs_command->tc_writer = TLM_RESTORE_RUN;

	/*
	 * We intentionnally don't wait for the threads to start since the
	 * reply of the request (which resulted in calling this function)
	 * must be sent to the client before probable errors are sent
	 * to the client.
	 */
	rc = pthread_create(NULL, NULL, (funct_t)mover_tape_reader, session);
	if (rc == 0) {
		tlm_cmd_wait(cmds->tcs_command, TLM_TAPE_READER);
	} else {
		NDMP_LOG(LOG_DEBUG, "Launch mover_tape_reader: %s",
		    strerror(rc));
		return (-1);
	}

	rc = pthread_create(NULL, NULL, (funct_t)mover_socket_writer, session);
	if (rc == 0) {
		tlm_cmd_wait(cmds->tcs_command, TLM_SOCK_WRITER);
	} else {
		NDMP_LOG(LOG_DEBUG, "Launch mover_socket_writer: %s",
		    strerror(rc));
		return (-1);
	}

	tlm_release_reader_writer_ipc(cmds->tcs_command);
	return (0);
}


/*
 * mover_socket_read_one_buf
 *
 * Read one buffer from the network socket for the mover. This is used
 * by mover_socket_reader
 *
 * Parameters:
 *   session (input) - session pointer.
 *   buf (input) - buffer read
 *   read_size (input) - size to be read
 *
 * Returns:
 *   0: on success
 *  -1: otherwise
 */
static int
mover_socket_read_one_buf(ndmpd_session_t *session, tlm_buffer_t *buf,
    long read_size)
{
	int n, index;
	long toread;

	tlm_buffer_mark_empty(buf);
	for (index = 0, toread = read_size; toread > 0; ) {
		errno = 0;
		NDMP_LOG(LOG_DEBUG, "index: %d, toread: %d", index, toread);

		n = read(session->ns_mover.md_sock, &buf->tb_buffer_data[index],
		    toread);
		if (n == 0) {
			NDMP_LOG(LOG_DEBUG, "n: %d", n);
			break;
		} else if (n > 0) {
			NDMP_LOG(LOG_DEBUG, "n: %d", n);
			index += n;
			toread -= n;
		} else {
			buf->tb_eof = TRUE;
			buf->tb_errno = errno;
			buf->tb_buffer_size = 0;
			NDMP_LOG(LOG_DEBUG, "n: %d, errno: %m", n);
			return (-1);
		}
	}

	if (index > 0) {
		buf->tb_full = TRUE;
		buf->tb_buffer_size = read_size;
		if (read_size > 0)
			(void) memset(&buf->tb_buffer_data[index], 0,
			    read_size - index);
	} else {
		buf->tb_eof = TRUE;
		buf->tb_buffer_size = 0;
	}

	NDMP_LOG(LOG_DEBUG, "full: %d, eot: %d, eof: %d,"
	    " errno: %d, size: %d, data: 0x%x",
	    buf->tb_full, buf->tb_eot, buf->tb_eof, buf->tb_errno,
	    buf->tb_buffer_size, buf->tb_buffer_data);

	return (0);
}



/*
 * mover_socket_reader
 *
 * Mover socket reader thread. This is used when reading data from the
 * network socket for performing remote backups.
 *
 * Parameters:
 *   session (input) - session pointer.
 *
 * Returns:
 *   0: on success
 *  -1: otherwise
 */
int
mover_socket_reader(ndmpd_session_t *session)
{
	int bidx;	/* buffer index */
	ndmp_lbr_params_t *nlp;
	tlm_buffer_t *buf;
	tlm_buffers_t *bufs;
	tlm_cmd_t *lcmd;	/* Local command */
	tlm_commands_t *cmds;	/* Commands structure */
	static int nr = 0;

	if ((nlp = ndmp_get_nlp(session)) == NULL) {
		NDMP_LOG(LOG_DEBUG, "nlp == NULL");
		return (-1);
	}

	cmds = &nlp->nlp_cmds;
	lcmd = cmds->tcs_command;
	bufs = lcmd->tc_buffers;

	lcmd->tc_ref++;
	cmds->tcs_reader_count++;

	/*
	 * Let our parent thread know that we are running.
	 */
	tlm_cmd_signal(cmds->tcs_command, TLM_SOCK_READER);

	bidx = bufs->tbs_buffer_in;
	while (cmds->tcs_reader == TLM_BACKUP_RUN &&
	    lcmd->tc_reader == TLM_BACKUP_RUN) {
		buf = &bufs->tbs_buffer[bidx];

		if (buf->tb_full) {
			NDMP_LOG(LOG_DEBUG, "R%d", bidx);
			/*
			 * The buffer is still full, wait for the consumer
			 * thread to use it.
			 */
			tlm_buffer_out_buf_timed_wait(bufs, 100);
		} else {
			NDMP_LOG(LOG_DEBUG, "r%d, nr: %d", bidx, ++nr);

			(void) mover_socket_read_one_buf(session, buf,
			    bufs->tbs_data_transfer_size);

			/*
			 * Can we do more buffering?
			 */
			if (is_buffer_erroneous(buf)) {
				NDMP_LOG(LOG_DEBUG,
				    "Exiting, errno: %d, eot: %d, eof: %d",
				    buf->tb_errno, buf->tb_eot, buf->tb_eof);
				break;
			}

			(void) tlm_buffer_advance_in_idx(bufs);
			tlm_buffer_release_in_buf(bufs);
			bidx = bufs->tbs_buffer_in;
		}
	}

	if (cmds->tcs_reader != TLM_BACKUP_RUN)
		NDMP_LOG(LOG_DEBUG, "cmds->tcs_reader != TLM_BACKUP_RUN");
	if (lcmd->tc_reader != TLM_BACKUP_RUN)
		NDMP_LOG(LOG_DEBUG, "lcmd->tc_reader != TLM_BACKUP_RUN");
	NDMP_LOG(LOG_DEBUG, "nr: %d", nr);

	/* If the consumer is waiting for us, wake it up. */
	tlm_buffer_release_in_buf(bufs);

	/*
	 * Clean up.
	 */
	cmds->tcs_reader_count--;
	lcmd->tc_ref--;
	lcmd->tc_writer = TLM_STOP;
	return (0);
}


/*
 * mover_tape_writer_one_buf
 *
 * Write one buffer for the mover to the local tape device. This is
 * used by mover_tape_writer thread.
 *
 * Parameters:
 *   session (input) - session pointer.
 *   buf (input) - buffer read
 *
 * Returns:
 *   0: on success
 *  -1: otherwise
 */
static int
mover_tape_write_one_buf(ndmpd_session_t *session, tlm_buffer_t *buf)
{
	int n;

	NDMP_LOG(LOG_DEBUG, "full: %d, eot: %d, eof: %d,"
	    " errno: %d, size: %d, data: 0x%x",
	    buf->tb_full, buf->tb_eot, buf->tb_eof, buf->tb_errno,
	    buf->tb_buffer_size, buf->tb_buffer_data);

	n = mover_tape_write_v3(session, buf->tb_buffer_data,
	    buf->tb_buffer_size);

	NDMP_LOG(LOG_DEBUG, "n: %d", n);

	if (n <= 0) {
		ndmpd_mover_error(session, (n == 0 ? NDMP_MOVER_HALT_ABORTED
		    : NDMP_MOVER_HALT_INTERNAL_ERROR));
		return (-1);
	}
	session->ns_mover.md_position += n;
	session->ns_mover.md_data_written += n;
	session->ns_mover.md_record_num++;

	NDMP_LOG(LOG_DEBUG, "Calling tlm_buffer_mark_empty(buf)");
	tlm_buffer_mark_empty(buf);

	return (0);
}


/*
 * mover_tape_writer
 *
 * Mover tape writer thread. This is used for performing remote backups
 * in a 3-way configuration. It writes the data from network socket to
 * the locally attached tape device.
 *
 * Parameters:
 *   session (input) - session pointer.
 *
 * Returns:
 *   0: on success
 *  -1: otherwise
 */
int
mover_tape_writer(ndmpd_session_t *session)
{
	int bidx;
	ndmp_lbr_params_t *nlp;
	tlm_buffer_t *buf;
	tlm_buffers_t *bufs;
	tlm_cmd_t *lcmd;
	tlm_commands_t *cmds;
	static int nw = 0;

	if ((nlp = ndmp_get_nlp(session)) == NULL) {
		NDMP_LOG(LOG_DEBUG, "nlp == NULL");
		return (-1);
	}

	cmds = &nlp->nlp_cmds;
	lcmd = cmds->tcs_command;
	bufs = lcmd->tc_buffers;

	lcmd->tc_ref++;
	cmds->tcs_writer_count++;

	/*
	 * Let our parent thread know that we are running.
	 */
	tlm_cmd_signal(cmds->tcs_command, TLM_TAPE_WRITER);

	bidx = bufs->tbs_buffer_out;
	buf = &bufs->tbs_buffer[bidx];
	while (cmds->tcs_writer != (int)TLM_ABORT &&
	    lcmd->tc_writer != (int)TLM_ABORT) {
		if (buf->tb_full) {
			NDMP_LOG(LOG_DEBUG, "w%d, nw: %d", bidx, ++nw);

			if (mover_tape_write_one_buf(session, buf) < 0) {
				NDMP_LOG(LOG_DEBUG,
				    "mover_tape_write_one_buf() failed");
				break;
			}

			(void) tlm_buffer_advance_out_idx(bufs);
			tlm_buffer_release_out_buf(bufs);
			bidx = bufs->tbs_buffer_out;
			buf = &bufs->tbs_buffer[bidx];
		} else {
			if (lcmd->tc_writer != TLM_BACKUP_RUN) {
				/* No more data is coming, time to exit */
				NDMP_LOG(LOG_DEBUG, "Time to exit");
				break;
			}
			NDMP_LOG(LOG_DEBUG, "W%d", bidx);
			/*
			 * The buffer is not full, wait for the producer
			 * thread to fill it.
			 */
			tlm_buffer_in_buf_timed_wait(bufs, 100);
		}
	}

	if (cmds->tcs_writer == (int)TLM_ABORT)
		NDMP_LOG(LOG_DEBUG, "cmds->tcs_writer == TLM_ABORT");
	if (lcmd->tc_writer == (int)TLM_ABORT)
		NDMP_LOG(LOG_DEBUG, "lcmd->tc_writer == TLM_ABORT");
	NDMP_LOG(LOG_DEBUG, "nw: %d", nw);

	if (buf->tb_errno == 0) {
		ndmpd_mover_error(session, NDMP_MOVER_HALT_CONNECT_CLOSED);
	} else {
		NDMP_LOG(LOG_DEBUG, "buf->tb_errno: %d", buf->tb_errno);
		ndmpd_mover_error(session, NDMP_MOVER_HALT_INTERNAL_ERROR);
	}

	/* If the producer is waiting for us, wake it up. */
	tlm_buffer_release_out_buf(bufs);

	/*
	 * Clean up.
	 */
	cmds->tcs_writer_count--;
	lcmd->tc_ref--;
	lcmd->tc_reader = TLM_STOP;
	return (0);
}


/*
 * start_mover_for_backup
 *
 * Starts a remote backup by running socket reader and tape
 * writer threads. The mover runs a remote backup in a 3-way backup
 * configuration.
 *
 * Parameters:
 *   session (input) - session pointer.
 *
 * Returns:
 *   0: on success
 *  -1: otherwise
 */
static int
start_mover_for_backup(ndmpd_session_t *session)
{
	ndmp_lbr_params_t *nlp;
	tlm_commands_t *cmds;
	int rc;

	if ((nlp = ndmp_get_nlp(session)) == NULL) {
		NDMP_LOG(LOG_DEBUG, "nlp == NULL");
		return (-1);
	}

	cmds = &nlp->nlp_cmds;
	(void) memset(cmds, 0, sizeof (*cmds));
	cmds->tcs_reader = cmds->tcs_writer = TLM_BACKUP_RUN;
	cmds->tcs_command = tlm_create_reader_writer_ipc(TRUE,
	    session->ns_mover.md_record_size);
	if (cmds->tcs_command == NULL)
		return (-1);

	cmds->tcs_command->tc_reader = TLM_BACKUP_RUN;
	cmds->tcs_command->tc_writer = TLM_BACKUP_RUN;

	/*
	 * We intentionally don't wait for the threads to start since the
	 * reply of the request (which resulted in calling this function)
	 * must be sent to the client before probable errors are sent
	 * to the client.
	 */
	rc = pthread_create(NULL, NULL, (funct_t)mover_socket_reader, session);
	if (rc == 0) {
		tlm_cmd_wait(cmds->tcs_command, TLM_SOCK_READER);
	} else {
		NDMP_LOG(LOG_DEBUG, "Launch mover_socket_reader: %s",
		    strerror(rc));
		return (-1);
	}

	rc = pthread_create(NULL, NULL, (funct_t)mover_tape_writer, session);
	if (rc == 0) {
		tlm_cmd_wait(cmds->tcs_command, TLM_TAPE_WRITER);
	} else {
		NDMP_LOG(LOG_DEBUG, "Launch mover_tape_writer: %s",
		    strerror(rc));
		return (-1);
	}

	tlm_release_reader_writer_ipc(cmds->tcs_command);
	return (0);
}


/*
 * is_writer_running
 *
 * Find out if the writer thread has started or not.
 *
 * Parameters:
 *   session (input) - session pointer.
 *
 * Returns:
 *   0: not started
 *   non-zero: started
 *	Note: non-zero is also returned if the backup type is
 *		neither TAR nor DUMP.  I.e. the is_writer_running()
 *		check does not apply in this case and things should
 * 		appear successful.
 */
static boolean_t
is_writer_running(ndmpd_session_t *session)
{
	boolean_t rv;
	ndmp_lbr_params_t *nlp;

	if (session && (session->ns_butype > NDMP_BUTYPE_DUMP))
		return (1);

	if (session == NULL)
		rv = 0;
	else if ((nlp = ndmp_get_nlp(session)) == NULL)
		rv = 0;
	else
		rv = (nlp->nlp_cmds.tcs_writer_count > 0);

	return (rv);
}


/*
 * is_writer_running_v3
 *
 * Find out if the writer thread has started or not.
 *
 * Parameters:
 *   session (input) - session pointer.
 *
 * Returns:
 *   0: not started
 *   non-zero: started
 *	Note: non-zero is also returned if the backup type is
 *		neither TAR nor DUMP.  I.e. the is_writer_running()
 *		check does not apply in this case and things should
 * 		appear successful.
 */
static boolean_t
is_writer_running_v3(ndmpd_session_t *session)
{
	boolean_t rv;
	ndmp_lbr_params_t *nlp;

	if (session && (session->ns_butype > NDMP_BUTYPE_DUMP))
		return (1);

	if (session == NULL)
		rv = 0;
	else if (session->ns_mover.md_data_addr.addr_type == NDMP_ADDR_TCP)
		rv = 1;
	else if ((nlp = ndmp_get_nlp(session)) == NULL)
		rv = 0;
	else
		rv = (nlp->nlp_cmds.tcs_writer_count > 0);

	return (rv);
}


/*
 * ndmpd_mover_error_send
 *
 * This function sends the notify message to the client.
 *
 * Parameters:
 *   session (input) - session pointer.
 *   reason  (input) - halt reason.
 *
 * Returns:
 *   Error code
 */
int
ndmpd_mover_error_send(ndmpd_session_t *session, ndmp_mover_halt_reason reason)
{
	ndmp_notify_mover_halted_request req;

	req.reason = reason;
	req.text_reason = "";

	return (ndmp_send_request(session->ns_connection,
	    NDMP_NOTIFY_MOVER_HALTED, NDMP_NO_ERR, (void *)&req, 0));
}


/*
 * ndmpd_mover_error_send_v4
 *
 * This function sends the notify message to the client.
 *
 * Parameters:
 *   session (input) - session pointer.
 *   reason  (input) - halt reason.
 *
 * Returns:
 *   Error code
 */
int
ndmpd_mover_error_send_v4(ndmpd_session_t *session,
    ndmp_mover_halt_reason reason)
{
	ndmp_notify_mover_halted_request_v4 req;

	req.reason = reason;

	return (ndmp_send_request(session->ns_connection,
	    NDMP_NOTIFY_MOVER_HALTED, NDMP_NO_ERR, (void *)&req, 0));
}


/*
 * ndmpd_mover_error
 *
 * This function is called when an unrecoverable mover error
 * has been detected. A notify message is sent to the client and the
 * mover is placed into the halted state.
 *
 * Parameters:
 *   session (input) - session pointer.
 *   reason  (input) - halt reason.
 *
 * Returns:
 *   void.
 */
void
ndmpd_mover_error(ndmpd_session_t *session, ndmp_mover_halt_reason reason)
{
	ndmp_lbr_params_t *nlp = ndmp_get_nlp(session);

	if (session->ns_mover.md_state == NDMP_MOVER_STATE_HALTED ||
	    (session->ns_protocol_version > NDMPV2 &&
	    session->ns_mover.md_state == NDMP_MOVER_STATE_IDLE))
		return;

	if (session->ns_protocol_version == NDMPV4) {
		if (ndmpd_mover_error_send_v4(session, reason) < 0)
			NDMP_LOG(LOG_DEBUG,
			    "Error sending notify_mover_halted request");
	} else {
		/* No media error in V3 */
		if (reason == NDMP_MOVER_HALT_MEDIA_ERROR)
			reason = NDMP_MOVER_HALT_INTERNAL_ERROR;
		if (ndmpd_mover_error_send(session, reason) < 0)
			NDMP_LOG(LOG_DEBUG,
			    "Error sending notify_mover_halted request");
	}

	(void) mutex_lock(&nlp->nlp_mtx);
	if (session->ns_mover.md_listen_sock != -1) {
		(void) ndmpd_remove_file_handler(session,
		    session->ns_mover.md_listen_sock);
		(void) close(session->ns_mover.md_listen_sock);
		session->ns_mover.md_listen_sock = -1;
	}
	if (session->ns_mover.md_sock != -1) {
		(void) ndmpd_remove_file_handler(session,
		    session->ns_mover.md_sock);
		(void) close(session->ns_mover.md_sock);
		session->ns_mover.md_sock = -1;
	}

	session->ns_mover.md_state = NDMP_MOVER_STATE_HALTED;
	session->ns_mover.md_halt_reason = reason;
	(void) cond_broadcast(&nlp->nlp_cv);
	(void) mutex_unlock(&nlp->nlp_mtx);
}


/*
 * mover_pause_v3
 *
 * Send an ndmp_notify_mover_paused request to the
 * NDMP client to inform the client that its attention is required.
 * Process messages until the data/mover operation is either aborted
 * or continued.
 *
 * Parameters:
 *   client_data (input) - session pointer.
 *   reason (input) - pause reason.
 *
 * Returns:
 *   0 - operation has been continued.
 *  -1 - operation has been aborted.
 */
static int
mover_pause_v3(ndmpd_session_t *session, ndmp_mover_pause_reason reason)
{
	int rv;
	ndmp_notify_mover_paused_request request;

	rv = 0;
	session->ns_mover.md_state = NDMP_MOVER_STATE_PAUSED;
	session->ns_mover.md_pause_reason = reason;
	session->ns_mover.md_pre_cond = FALSE;

	request.reason = session->ns_mover.md_pause_reason;
	request.seek_position =
	    long_long_to_quad(session->ns_mover.md_position);

	if (ndmp_send_request(session->ns_connection, NDMP_NOTIFY_MOVER_PAUSED,
	    NDMP_NO_ERR, (void *)&request, 0) < 0) {
		NDMP_LOG(LOG_DEBUG,
		    "Error sending notify_mover_paused_request");
		return (-1);
	}

	/*
	 * 3-way operations are single-thread.  The same thread
	 * should process the messages.
	 *
	 * 2-way operations are multi-thread.  The main thread
	 * processes the messages.  We just need to wait and
	 * see if the mover state changes or the operation aborts.
	 */
	if (session->ns_mover.md_data_addr.addr_type == NDMP_ADDR_TCP) {
		/*
		 * Process messages until the state is changed by
		 * an abort, continue, or close request .
		 */
		for (; ; ) {
			if (ndmpd_select(session, TRUE, HC_CLIENT) < 0)
				return (-1);

			if (session->ns_eof == TRUE)
				return (-1);

			switch (session->ns_mover.md_state) {
			case NDMP_MOVER_STATE_ACTIVE:
				session->ns_tape.td_record_count = 0;
				return (0);

			case NDMP_MOVER_STATE_PAUSED:
				continue;

			default:
				return (-1);
			}
		}

	} else {
		if (session->ns_mover.md_data_addr.addr_type ==
		    NDMP_ADDR_LOCAL) {
			rv = ndmp_wait_for_mover(session);
		} else {
			NDMP_LOG(LOG_DEBUG, "Invalid address type %d",
			    session->ns_mover.md_data_addr.addr_type);
			rv = -1;
		}
	}

	return (rv);
}


/*
 * mover_tape_write_v3
 *
 * Writes a data record to tape. Detects and handles EOT conditions.
 *
 * Parameters:
 *   session (input) - session pointer.
 *   data    (input) - data to be written.
 *   length  (input) - length of data to be written.
 *
 * Returns:
 *    0 - operation aborted by client.
 *   -1 - error.
 *   otherwise - number of bytes written.
 */
static int
mover_tape_write_v3(ndmpd_session_t *session, char *data, ssize_t length)
{
	ssize_t n;
	ssize_t count = length;

	while (count > 0) {
		/*
		 * Enforce mover window on write.
		 */
		if (session->ns_mover.md_position >=
		    session->ns_mover.md_window_offset +
		    session->ns_mover.md_window_length) {
			NDMP_LOG(LOG_DEBUG, "MOVER_PAUSE_EOW");

			if (mover_pause_v3(session, NDMP_MOVER_PAUSE_EOW) < 0)
				/* Operation aborted or connection terminated */
				return (-1);

		}

		n = write(session->ns_tape.td_fd, data, count);
		if (n < 0) {
			NDMP_LOG(LOG_ERR, "Tape write error: %m.");
			return (-1);
		} else if (n > 0) {
			NS_ADD(wtape, n);
			count -= n;
			data += n;
			session->ns_tape.td_record_count++;
		}

		/* EOM handling */
		if (count > 0) {
			struct mtget mtstatus;

			(void) ioctl(session->ns_tape.td_fd, MTIOCGET,
			    &mtstatus);
			NDMP_LOG(LOG_DEBUG, "EOM detected (%d written bytes, "
			    "mover record %d, file #%d, block #%d)", n,
			    session->ns_tape.td_record_count,
			    mtstatus.mt_fileno, mtstatus.mt_blkno);

			/*
			 * Notify the client to either abort the operation
			 * or change the tape.
			 */
			NDMP_APILOG((void*)session, NDMP_LOG_NORMAL,
			    ++ndmp_log_msg_id,
			    "End of tape reached. Load next tape");

			if (mover_pause_v3(session, NDMP_MOVER_PAUSE_EOM) < 0)
				/* Operation aborted or connection terminated */
				return (-1);
		}
	}

	return (length);
}


/*
 * mover_tape_flush_v3
 *
 * Writes all remaining buffered data to tape. A partial record is
 * padded out to a full record with zeros.
 *
 * Parameters:
 *   session (input) - session pointer.
 *   data    (input) - data to be written.
 *   length  (input) - length of data to be written.
 *
 * Returns:
 *   -1 - error.
 *   otherwise - number of bytes written.
 */
static int
mover_tape_flush_v3(ndmpd_session_t *session)
{
	int n;

	if (session->ns_mover.md_w_index == 0)
		return (0);

	(void) memset((void*)&session->ns_mover.md_buf[session->
	    ns_mover.md_w_index], 0,
	    session->ns_mover.md_record_size - session->ns_mover.md_w_index);

	n = mover_tape_write_v3(session, session->ns_mover.md_buf,
	    session->ns_mover.md_record_size);
	if (n < 0) {
		NDMP_LOG(LOG_ERR, "Tape write error: %m.");
		return (-1);
	}

	session->ns_mover.md_w_index = 0;
	session->ns_mover.md_position += n;
	return (n);
}


/*
 * ndmpd_local_write_v3
 *
 * Buffers and writes data to the tape device.
 * A full tape record is buffered before being written.
 *
 * Parameters:
 *   session    (input) - session pointer.
 *   data       (input) - data to be written.
 *   length     (input) - data length.
 *
 * Returns:
 *   0 - data successfully written.
 *  -1 - error.
 */
int
ndmpd_local_write_v3(ndmpd_session_t *session, char *data, ulong_t length)
{
	ulong_t count = 0;
	ssize_t n;
	ulong_t len;

	if (session->ns_mover.md_state == NDMP_MOVER_STATE_IDLE ||
	    session->ns_mover.md_state == NDMP_MOVER_STATE_LISTEN ||
	    session->ns_mover.md_state == NDMP_MOVER_STATE_HALTED) {
		NDMP_LOG(LOG_DEBUG, "Invalid mover state to write data");
		return (-1);
	}

	/*
	 * A length of 0 indicates that any buffered data should be
	 * flushed to tape.
	 */
	if (length == 0) {
		if (session->ns_mover.md_w_index == 0)
			return (0);

		(void) memset((void*)&session->ns_mover.md_buf[session->
		    ns_mover.md_w_index], 0, session->ns_mover.md_record_size -
		    session->ns_mover.md_w_index);

		n = mover_tape_write_v3(session, session->ns_mover.md_buf,
		    session->ns_mover.md_record_size);
		if (n <= 0) {
			ndmpd_mover_error(session,
			    (n == 0 ?  NDMP_MOVER_HALT_ABORTED :
			    NDMP_MOVER_HALT_MEDIA_ERROR));
			return (-1);
		}

		session->ns_mover.md_position += n;
		session->ns_mover.md_data_written +=
		    session->ns_mover.md_w_index;
		session->ns_mover.md_record_num++;
		session->ns_mover.md_w_index = 0;
		return (0);
	}

	/* Break the data into records. */
	while (count < length) {
		/*
		 * Determine if data needs to be buffered or
		 * can be written directly from user supplied location.
		 * We can fast path the write if there is no pending
		 * buffered data and there is at least a full records worth
		 * of data to be written.
		 */
		if (session->ns_mover.md_w_index == 0 &&
		    length - count >= session->ns_mover.md_record_size) {
			n = mover_tape_write_v3(session, &data[count],
			    session->ns_mover.md_record_size);
			if (n <= 0) {
				ndmpd_mover_error(session,
				    (n == 0 ?  NDMP_MOVER_HALT_ABORTED :
				    NDMP_MOVER_HALT_MEDIA_ERROR));
				return (-1);
			}

			session->ns_mover.md_position += n;
			session->ns_mover.md_data_written += n;
			session->ns_mover.md_record_num++;
			count += n;
			continue;
		}

		/* Buffer the data */
		len = length - count;
		if (len > session->ns_mover.md_record_size -
		    session->ns_mover.md_w_index)
			len = session->ns_mover.md_record_size -
			    session->ns_mover.md_w_index;

		(void) memcpy(&session->ns_mover.md_buf[session->
		    ns_mover.md_w_index], &data[count], len);
		session->ns_mover.md_w_index += len;
		count += len;

		/* Write the buffer if its full */
		if (session->ns_mover.md_w_index ==
		    session->ns_mover.md_record_size) {
			n = mover_tape_write_v3(session,
			    session->ns_mover.md_buf,
			    session->ns_mover.md_record_size);
			if (n <= 0) {
				ndmpd_mover_error(session,
				    (n == 0 ?  NDMP_MOVER_HALT_ABORTED :
				    NDMP_MOVER_HALT_MEDIA_ERROR));
				return (-1);
			}

			session->ns_mover.md_position += n;
			session->ns_mover.md_data_written += n;
			session->ns_mover.md_record_num++;
			session->ns_mover.md_w_index = 0;
		}
	}

	return (0);
}


/*
 * mover_data_read_v3
 *
 * Reads backup data from the data connection and writes the
 * received data to the tape device.
 *
 * Parameters:
 *   cookie  (input) - session pointer.
 *   fd      (input) - file descriptor.
 *   mode    (input) - select mode.
 *
 * Returns:
 *   void.
 */
/*ARGSUSED*/
static void
mover_data_read_v3(void *cookie, int fd, ulong_t mode)
{
	ndmpd_session_t *session = (ndmpd_session_t *)cookie;
	int n;
	ulong_t index;

	n = read(fd, &session->ns_mover.md_buf[session->ns_mover.md_w_index],
	    session->ns_mover.md_record_size - session->ns_mover.md_w_index);

	/*
	 * Since this function is only called when select believes data
	 * is available to be read, a return of zero indicates the
	 * connection has been closed.
	 */
	if (n <= 0) {
		if (n == 0) {
			NDMP_LOG(LOG_DEBUG, "Data connection closed");
			ndmpd_mover_error(session,
			    NDMP_MOVER_HALT_CONNECT_CLOSED);
		} else {
			/* Socket is non-blocking, perhaps there are no data */
			if (errno == EAGAIN) {
				NDMP_LOG(LOG_ERR, "No data to read");
				return;
			}

			NDMP_LOG(LOG_ERR, "Failed to read from socket: %m");
			ndmpd_mover_error(session,
			    NDMP_MOVER_HALT_INTERNAL_ERROR);
		}

		/* Save the index since mover_tape_flush_v3 resets it. */
		index = session->ns_mover.md_w_index;

		/* Flush any buffered data to tape. */
		if (mover_tape_flush_v3(session) > 0) {
			session->ns_mover.md_data_written += index;
			session->ns_mover.md_record_num++;
		}

		return;
	}

	NDMP_LOG(LOG_DEBUG, "n %d", n);

	session->ns_mover.md_w_index += n;

	if (session->ns_mover.md_w_index == session->ns_mover.md_record_size) {
		n = mover_tape_write_v3(session, session->ns_mover.md_buf,
		    session->ns_mover.md_record_size);
		if (n <= 0) {
			ndmpd_mover_error(session,
			    (n == 0 ? NDMP_MOVER_HALT_ABORTED :
			    NDMP_MOVER_HALT_MEDIA_ERROR));
			return;
		}

		session->ns_mover.md_position += n;
		session->ns_mover.md_w_index = 0;
		session->ns_mover.md_data_written += n;
		session->ns_mover.md_record_num++;
	}
}

/*
 * mover_tape_read_v3
 *
 * Reads a data record from tape. Detects and handles EOT conditions.
 *
 * Parameters:
 *   session (input) - session pointer.
 *   data    (input) - location to read data to.
 *
 * Returns:
 *   0 - operation aborted.
 *   TAPE_READ_ERR - tape read IO error.
 *   TAPE_NO_WRITER_ERR - no writer is running during tape read
 *   otherwise - number of bytes read.
 */
static int
mover_tape_read_v3(ndmpd_session_t *session, char *data)
{
	int pause_reason;
	ssize_t	 n;
	int err;
	int count;

	count = session->ns_mover.md_record_size;
	while (count > 0) {
		pause_reason = NDMP_MOVER_PAUSE_NA;

		n = read(session->ns_tape.td_fd, data, count);
		if (n < 0) {
			/*
			 * If at beginning of file and read fails with EIO,
			 * then it's repeated attempt to read at EOT.
			 */
			if (errno == EIO && tape_is_at_bof(session)) {
				NDMP_LOG(LOG_DEBUG, "Repeated read at EOT");
				pause_reason = NDMP_MOVER_PAUSE_EOM;
				NDMP_APILOG((void*)session, NDMP_LOG_NORMAL,
				    ++ndmp_log_msg_id,
				    "End of tape reached. Load next tape");
			}
			/*
			 * According to NDMPv4 spec preferred error code when
			 * trying to read from blank tape is NDMP_EOM_ERR.
			 */
			else if (errno == EIO && tape_is_at_bot(session)) {
				NDMP_LOG(LOG_ERR,
				    "Blank tape detected, returning EOM");
				NDMP_APILOG((void*)session, NDMP_LOG_NORMAL,
				    ++ndmp_log_msg_id,
				    "Blank tape. Load another tape");
				pause_reason = NDMP_MOVER_PAUSE_EOM;
			} else {
				NDMP_LOG(LOG_ERR, "Tape read error: %m.");
				return (TAPE_READ_ERR);
			}
		} else if (n > 0) {
			NS_ADD(rtape, n);
			data += n;
			count -= n;
			session->ns_tape.td_record_count++;
		} else {
			if (!is_writer_running_v3(session))
				return (TAPE_NO_WRITER_ERR);

			/*
			 * End of file or media reached. Notify client and
			 * wait for the client to either abort the data
			 * operation or continue the operation after changing
			 * the tape.
			 */
			if (tape_is_at_bof(session)) {
				NDMP_LOG(LOG_DEBUG, "EOT detected");
				pause_reason = NDMP_MOVER_PAUSE_EOM;
				NDMP_APILOG((void*)session, NDMP_LOG_NORMAL,
				    ++ndmp_log_msg_id, "End of medium reached");
			} else {
				NDMP_LOG(LOG_DEBUG, "EOF detected");
				/* reposition the tape to BOT side of FM */
				fm_dance(session);
				pause_reason = NDMP_MOVER_PAUSE_EOF;
				NDMP_APILOG((void*)session, NDMP_LOG_NORMAL,
				    ++ndmp_log_msg_id, "End of file reached.");
			}
		}

		if (pause_reason != NDMP_MOVER_PAUSE_NA) {
			err = mover_pause_v3(session, pause_reason);

			/* Operation aborted or connection terminated? */
			if (err < 0) {
				return (0);
			}
			/* Retry the read from new location */
		}
	}
	return (session->ns_mover.md_record_size);
}


/*
 * mover_data_write_v3
 *
 * Reads backup data from the tape device and writes the
 * data to the data connection.
 * This function is called by ndmpd_select when the data connection
 * is ready for more data to be written.
 *
 * Parameters:
 *   cookie  (input) - session pointer.
 *   fd      (input) - file descriptor.
 *   mode    (input) - select mode.
 *
 * Returns:
 *   void.
 */
/*ARGSUSED*/
static void
mover_data_write_v3(void *cookie, int fd, ulong_t mode)
{
	ndmpd_session_t *session = (ndmpd_session_t *)cookie;
	int n;
	ulong_t len;
	u_longlong_t wlen;
	ndmp_notify_mover_paused_request pause_request;

	/*
	 * If the end of the mover window has been reached,
	 * then notify the client that a seek is needed.
	 * Remove the file handler to prevent this function from
	 * being called. The handler will be reinstalled in
	 * ndmpd_mover_continue.
	 */
	if (session->ns_mover.md_position >= session->ns_mover.md_window_offset
	    + session->ns_mover.md_window_length) {
		NDMP_LOG(LOG_DEBUG,
		    "MOVER_PAUSE_SEEK(%llu)", session->ns_mover.md_position);

		session->ns_mover.md_w_index = 0;
		session->ns_mover.md_r_index = 0;

		session->ns_mover.md_state = NDMP_MOVER_STATE_PAUSED;
		session->ns_mover.md_pause_reason = NDMP_MOVER_PAUSE_SEEK;
		pause_request.reason = NDMP_MOVER_PAUSE_SEEK;
		pause_request.seek_position =
		    long_long_to_quad(session->ns_mover.md_position);
		session->ns_mover.md_seek_position =
		    session->ns_mover.md_position;

		(void) ndmpd_remove_file_handler(session, fd);

		if (ndmp_send_request(session->ns_connection,
		    NDMP_NOTIFY_MOVER_PAUSED, NDMP_NO_ERR,
		    (void *)&pause_request, 0) < 0) {
			NDMP_LOG(LOG_DEBUG,
			    "Sending notify_mover_paused request");
			ndmpd_mover_error(session,
			    NDMP_MOVER_HALT_INTERNAL_ERROR);
		}
		return;
	}

	/*
	 * Read more data into the tape buffer if the buffer is empty.
	 */
	if (session->ns_mover.md_w_index == 0) {
		n = mover_tape_read_v3(session, session->ns_mover.md_buf);

		NDMP_LOG(LOG_DEBUG,
		    "read %u bytes from tape", n);

		if (n <= 0) {
			ndmpd_mover_error(session, (n == 0 ?
			    NDMP_MOVER_HALT_ABORTED
			    : NDMP_MOVER_HALT_MEDIA_ERROR));
			return;
		}

		/*
		 * Discard data if the current data stream position is
		 * prior to the seek position. This is necessary if a seek
		 * request set the seek pointer to a position that is not a
		 * record boundary. The seek request handler can only position
		 * to the start of a record.
		 */
		if (session->ns_mover.md_position <
		    session->ns_mover.md_seek_position) {
			session->ns_mover.md_r_index =
			    session->ns_mover.md_seek_position -
			    session->ns_mover.md_position;
			session->ns_mover.md_position =
			    session->ns_mover.md_seek_position;
		}

		session->ns_mover.md_w_index = n;
		session->ns_mover.md_record_num++;
	}

	/*
	 * The limit on the total amount of data to be sent can be
	 * dictated by either the end of the mover window or the end of the
	 * seek window.
	 * First determine which window applies and then determine if the
	 * send length needs to be less than a full record to avoid
	 * exceeding the window.
	 */
	if (session->ns_mover.md_position +
	    session->ns_mover.md_bytes_left_to_read >
	    session->ns_mover.md_window_offset +
	    session->ns_mover.md_window_length)
		wlen = session->ns_mover.md_window_offset +
		    session->ns_mover.md_window_length -
		    session->ns_mover.md_position;
	else
		wlen = session->ns_mover.md_bytes_left_to_read;

	NDMP_LOG(LOG_DEBUG, "wlen window restrictions: %llu", wlen);

	/*
	 * Now limit the length to the amount of data in the buffer.
	 */
	if (wlen > session->ns_mover.md_w_index - session->ns_mover.md_r_index)
		wlen = session->ns_mover.md_w_index -
		    session->ns_mover.md_r_index;

	len = wlen & 0xffffffff;
	NDMP_LOG(LOG_DEBUG,
	    "buffer restrictions: wlen %llu len %u", wlen, len);

	/*
	 * Write the data to the data connection.
	 */
	n = write(session->ns_mover.md_sock,
	    &session->ns_mover.md_buf[session->ns_mover.md_r_index], len);

	if (n < 0) {
		/* Socket is non-blocking, perhaps the write queue is full */
		if (errno == EAGAIN) {
			NDMP_LOG(LOG_ERR, "Cannot write to socket");
			return;
		}
		NDMP_LOG(LOG_ERR, "Failed to write to socket: %m");
		ndmpd_mover_error(session, NDMP_MOVER_HALT_CONNECT_CLOSED);
		return;
	}

	NDMP_LOG(LOG_DEBUG,
	    "wrote %u of %u bytes to data connection position %llu r_index %lu",
	    n, len, session->ns_mover.md_position,
	    session->ns_mover.md_r_index);

	session->ns_mover.md_r_index += n;
	session->ns_mover.md_position += n;
	session->ns_mover.md_bytes_left_to_read -= n;

	/*
	 * If all data in the buffer has been written,
	 * zero the buffer indices. The next call to this function
	 * will read more data from the tape device into the buffer.
	 */
	if (session->ns_mover.md_r_index == session->ns_mover.md_w_index) {
		session->ns_mover.md_r_index = 0;
		session->ns_mover.md_w_index = 0;
	}

	/*
	 * If the read limit has been reached,
	 * then remove the file handler to prevent this
	 * function from getting called. The next mover_read request
	 * will reinstall the handler.
	 */
	if (session->ns_mover.md_bytes_left_to_read == 0)
		(void) ndmpd_remove_file_handler(session, fd);
}


/*
 * accept_connection_v3
 *
 * Accept a data connection from a data server.
 * Called by ndmpd_select when a connection is pending on
 * the mover listen socket.
 *
 * Parameters:
 *   cookie  (input) - session pointer.
 *   fd      (input) - file descriptor.
 *   mode    (input) - select mode.
 *
 * Returns:
 *   void.
 */
/*ARGSUSED*/
static void
accept_connection_v3(void *cookie, int fd, ulong_t mode)
{
	ndmpd_session_t *session = (ndmpd_session_t *)cookie;
	int from_len;
	struct sockaddr_in from;

	from_len = sizeof (from);
	session->ns_mover.md_sock = accept(fd, (struct sockaddr *)&from,
	    &from_len);

	NDMP_LOG(LOG_DEBUG, "sin: port %d addr %s", ntohs(from.sin_port),
	    inet_ntoa(IN_ADDR(from.sin_addr.s_addr)));

	(void) ndmpd_remove_file_handler(session, fd);
	(void) close(session->ns_mover.md_listen_sock);
	session->ns_mover.md_listen_sock = -1;

	if (session->ns_mover.md_sock < 0) {
		NDMP_LOG(LOG_DEBUG, "Accept error: %m");
		ndmpd_mover_error(session, NDMP_MOVER_HALT_CONNECT_ERROR);
		return;
	}

	/*
	 * Save the peer address.
	 */
	session->ns_mover.md_data_addr.tcp_ip_v3 = from.sin_addr.s_addr;
	session->ns_mover.md_data_addr.tcp_port_v3 = ntohs(from.sin_port);

	/* Set the parameter of the new socket */
	set_socket_options(session->ns_mover.md_sock);

	/*
	 * Backup/restore is handled by a callback called from main event loop,
	 * which reads/writes data to md_sock socket. IO on socket must be
	 * non-blocking, otherwise ndmpd would be unable to process other
	 * incoming requests.
	 */
	if (!set_socket_nonblock(session->ns_mover.md_sock)) {
		NDMP_LOG(LOG_ERR, "Could not set non-blocking mode "
		    "on socket: %m");
		ndmpd_mover_error(session, NDMP_MOVER_HALT_INTERNAL_ERROR);
		return;
	}

	NDMP_LOG(LOG_DEBUG, "sock fd: %d", session->ns_mover.md_sock);

	if (session->ns_mover.md_mode == NDMP_MOVER_MODE_READ) {
		if (ndmpd_add_file_handler(session, (void*)session,
		    session->ns_mover.md_sock, NDMPD_SELECT_MODE_READ,
		    HC_MOVER, mover_data_read_v3) < 0) {
			ndmpd_mover_error(session,
			    NDMP_MOVER_HALT_INTERNAL_ERROR);
			return;
		}
		NDMP_LOG(LOG_DEBUG, "Backup connection established by %s:%d",
		    inet_ntoa(IN_ADDR(from.sin_addr.s_addr)),
		    ntohs(from.sin_port));
	} else {
		NDMP_LOG(LOG_DEBUG, "Restore connection established by %s:%d",
		    inet_ntoa(IN_ADDR(from.sin_addr.s_addr)),
		    ntohs(from.sin_port));
	}

	session->ns_mover.md_state = NDMP_MOVER_STATE_ACTIVE;
}


/*
 * create_listen_socket_v3
 *
 * Creates a socket for listening for accepting data connections.
 *
 * Parameters:
 *   session (input)  - session pointer.
 *   addr    (output) - location to store address of socket.
 *   port    (output) - location to store port of socket.
 *
 * Returns:
 *   0 - success.
 *  -1 - error.
 */
static int
create_listen_socket_v3(ndmpd_session_t *session, ulong_t *addr, ushort_t *port)
{
	session->ns_mover.md_listen_sock = ndmp_create_socket(addr, port);
	if (session->ns_mover.md_listen_sock < 0)
		return (-1);

	/*
	 * Add a file handler for the listen socket.
	 * ndmpd_select will call accept_connection when a
	 * connection is ready to be accepted.
	 */
	if (ndmpd_add_file_handler(session, (void *) session,
	    session->ns_mover.md_listen_sock, NDMPD_SELECT_MODE_READ, HC_MOVER,
	    accept_connection_v3) < 0) {
		(void) close(session->ns_mover.md_listen_sock);
		session->ns_mover.md_listen_sock = -1;
		return (-1);
	}
	NDMP_LOG(LOG_DEBUG, "IP %s port %d",
	    inet_ntoa(*(struct in_addr *)addr), ntohs(*port));
	return (0);
}


/*
 * mover_connect_sock
 *
 * Connect the mover to the specified address
 *
 * Parameters:
 *   session (input)  - session pointer.
 *   mode    (input)  - mover mode.
 *   addr    (output) - location to store address of socket.
 *   port    (output) - location to store port of socket.
 *
 * Returns:
 *   error code.
 */
static ndmp_error
mover_connect_sock(ndmpd_session_t *session, ndmp_mover_mode mode,
    ulong_t addr, ushort_t port)
{
	int sock;

	sock = ndmp_connect_sock_v3(addr, port);
	if (sock < 0)
		return (NDMP_CONNECT_ERR);

	/*
	 * Backup/restore is handled by a callback called from main event loop,
	 * which reads/writes data to md_sock socket. IO on socket must be
	 * non-blocking, otherwise ndmpd would be unable to process other
	 * incoming requests.
	 */
	if (!set_socket_nonblock(sock)) {
		NDMP_LOG(LOG_ERR, "Could not set non-blocking mode "
		    "on socket: %m");
		(void) close(sock);
		return (NDMP_CONNECT_ERR);
	}

	if (mode == NDMP_MOVER_MODE_READ) {
		if (ndmpd_add_file_handler(session, (void*)session, sock,
		    NDMPD_SELECT_MODE_READ, HC_MOVER, mover_data_read_v3) < 0) {
			(void) close(sock);
			return (NDMP_CONNECT_ERR);
		}
	}
	session->ns_mover.md_sock = sock;
	session->ns_mover.md_data_addr.addr_type = NDMP_ADDR_TCP;
	session->ns_mover.md_data_addr.tcp_ip_v3 = ntohl(addr);
	session->ns_mover.md_data_addr.tcp_port_v3 = port;
	return (NDMP_NO_ERR);
}


/*
 * ndmpd_local_read_v3
 *
 * Reads data from the local tape device.
 * Full tape records are read and buffered.
 *
 * Parameters:
 *   session (input) - session pointer.
 *   data    (input) - location to store data.
 *   length  (input) - data length.
 *
 * Returns:
 *   1 - no read error but no writer running
 *   0 - data successfully read.
 *  -1 - error.
 */
int
ndmpd_local_read_v3(ndmpd_session_t *session, char *data, ulong_t length)
{
	ulong_t count;
	ulong_t len;
	ssize_t n;

	count = 0;
	if (session->ns_mover.md_state == NDMP_MOVER_STATE_IDLE ||
	    session->ns_mover.md_state == NDMP_MOVER_STATE_LISTEN ||
	    session->ns_mover.md_state == NDMP_MOVER_STATE_HALTED) {
		NDMP_LOG(LOG_DEBUG, "Invalid mover state to read data");
		return (-1);
	}

	/*
	 * Automatically increase the seek window if necessary.
	 * This is needed in the event the module attempts to read
	 * past a seek window set via a prior call to ndmpd_seek() or
	 * the module has not issued a seek. If no seek was issued then
	 * pretend that a seek was issued to read the entire tape.
	 */
	if (length > session->ns_mover.md_bytes_left_to_read) {
		/* ndmpd_seek() never called? */
		if (session->ns_data.dd_read_length == 0) {
			session->ns_mover.md_bytes_left_to_read = ~0LL;
			session->ns_data.dd_read_offset = 0LL;
			session->ns_data.dd_read_length = ~0LL;
		} else {
			session->ns_mover.md_bytes_left_to_read = length;
			session->ns_data.dd_read_offset =
			    session->ns_mover.md_position;
			session->ns_data.dd_read_length = length;
		}
	}

	/*
	 * Read as many records as necessary to satisfy the request.
	 */
	while (count < length) {
		/*
		 * If the end of the mover window has been reached,
		 * then notify the client that a new data window is needed.
		 */
		if (session->ns_mover.md_position >=
		    session->ns_mover.md_window_offset +
		    session->ns_mover.md_window_length) {
			if (mover_pause_v3(session,
			    NDMP_MOVER_PAUSE_SEEK) < 0) {
				ndmpd_mover_error(session,
				    NDMP_MOVER_HALT_INTERNAL_ERROR);
				return (-1);
			}
			continue;
		}

		len = length - count;

		/*
		 * Prevent reading past the end of the window.
		 */
		if (len > session->ns_mover.md_window_offset +
		    session->ns_mover.md_window_length -
		    session->ns_mover.md_position)
			len = session->ns_mover.md_window_offset +
			    session->ns_mover.md_window_length -
			    session->ns_mover.md_position;

		/*
		 * Copy from the data buffer first.
		 */
		if (session->ns_mover.md_w_index -
		    session->ns_mover.md_r_index != 0) {
			/*
			 * Limit the copy to the amount of data in the buffer.
			 */
			if (len > session->ns_mover.md_w_index -
			    session->ns_mover.md_r_index)
				len = session->ns_mover.md_w_index -
				    session->ns_mover.md_r_index;
			(void) memcpy((void*)&data[count],
			    &session->ns_mover.md_buf[session->
			    ns_mover.md_r_index], len);
			count += len;
			session->ns_mover.md_r_index += len;
			session->ns_mover.md_bytes_left_to_read -= len;
			session->ns_mover.md_position += len;
			continue;
		}

		/*
		 * Determine if data needs to be buffered or
		 * can be read directly to user supplied location.
		 * We can fast path the read if at least a full record
		 * needs to be read and there is no seek pending.
		 * This is done to eliminate a buffer copy.
		 */
		if (len >= session->ns_mover.md_record_size &&
		    session->ns_mover.md_position >=
		    session->ns_mover.md_seek_position) {
			n = mover_tape_read_v3(session, &data[count]);
			if (n <= 0) {
				if (n == TAPE_NO_WRITER_ERR)
					return (1);

				ndmpd_mover_error(session,
				    (n == 0 ? NDMP_MOVER_HALT_ABORTED :
				    NDMP_MOVER_HALT_MEDIA_ERROR));
				return ((n == 0) ? 1 : -1);
			}

			count += n;
			session->ns_mover.md_bytes_left_to_read -= n;
			session->ns_mover.md_position += n;
			session->ns_mover.md_record_num++;
			continue;
		}

		/* Read the next record into the buffer. */
		n = mover_tape_read_v3(session, session->ns_mover.md_buf);
		if (n <= 0) {
			if (n == TAPE_NO_WRITER_ERR)
				return (1);

			ndmpd_mover_error(session,
			    (n == 0 ? NDMP_MOVER_HALT_ABORTED :
			    NDMP_MOVER_HALT_MEDIA_ERROR));
			return ((n == 0) ? 1 : -1);
		}

		session->ns_mover.md_w_index = n;
		session->ns_mover.md_r_index = 0;
		session->ns_mover.md_record_num++;

		NDMP_LOG(LOG_DEBUG, "n: %d", n);

		/*
		 * Discard data if the current data stream position is
		 * prior to the seek position. This is necessary if a seek
		 * request set the seek pointer to a position that is not a
		 * record boundary. The seek request handler can only position
		 * to the start of a record.
		 */
		if (session->ns_mover.md_position <
		    session->ns_mover.md_seek_position) {
			session->ns_mover.md_r_index =
			    session->ns_mover.md_seek_position -
			    session->ns_mover.md_position;
			session->ns_mover.md_position =
			    session->ns_mover.md_seek_position;
		}
	}

	return (0);
}
