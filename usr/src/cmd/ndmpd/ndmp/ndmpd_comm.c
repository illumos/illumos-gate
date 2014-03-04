/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
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

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <libinetutil.h>
#include "ndmpd.h"
#include "ndmpd_common.h"

#define	NDMP_PROC_ERR	-1
#define	NDMP_PROC_MSG	1
#define	NDMP_PROC_REP	0
#define	NDMP_PROC_REP_ERR	2

/*
 * The ndmp connection version can be set through command line. If command line
 * is not specified it will be set from the ndmp SMF version property.
 */
int ndmp_ver = 0;

/*
 * The NDMP listening port number
 */
int ndmp_port = 0;

/*
 * Restore path mechanism definition
 * 0 means partial path restore and
 * 1 means full path restore.
 * Refer to NDMP_FULL_RESTORE_PATH for partial path and full path definition.
 */
int ndmp_full_restore_path = 1;

/*
 * Do we support Direct Access Restore?
 */
int ndmp_dar_support = 0;

/*
 * ndmp_connection_t handler function
 */
static ndmpd_file_handler_func_t connection_file_handler;

extern ndmp_handler_t ndmp_msghdl_tab[];

static int ndmp_readit(void *connection_handle,
    caddr_t buf,
    int len);
static int ndmp_writeit(void *connection_handle,
    caddr_t buf,
    int len);
static int ndmp_recv_msg(ndmp_connection_t *connection);
static int ndmp_process_messages(ndmp_connection_t *connection,
    boolean_t reply_expected);
static ndmp_msg_handler_t *ndmp_get_handler(ndmp_connection_t *connection,
    ndmp_message message);
static boolean_t ndmp_check_auth_required(ndmp_message message);
static ndmp_handler_t *ndmp_get_interface(ndmp_message message);
void *ndmpd_worker(void *ptarg);

#ifdef	lint
bool_t
xdr_ndmp_header(XDR *xdrs, ndmp_header *objp)
{
	xdrs = xdrs;
	objp = objp;
	return (0);
}
#endif	/* lint */

/*
 * ndmp_create_connection
 *
 * Allocate and initialize a connection structure.
 *
 * Parameters:
 *   handler_tbl (input) - message handlers.
 *
 * Returns:
 *   NULL - error
 *   connection pointer
 *
 * Notes:
 *   The returned connection should be destroyed using
 *   ndmp_destroy_connection().
 */
ndmp_connection_t *
ndmp_create_connection(void)
{
	ndmp_connection_t *connection;

	connection = ndmp_malloc(sizeof (ndmp_connection_t));
	if (connection == NULL)
		return (NULL);

	connection->conn_sock = -1;
	connection->conn_my_sequence = 0;
	connection->conn_authorized = FALSE;
	connection->conn_eof = FALSE;
	connection->conn_msginfo.mi_body = 0;
	connection->conn_version = ndmp_ver;
	connection->conn_client_data = 0;
	(void) mutex_init(&connection->conn_lock, 0, NULL);
	connection->conn_xdrs.x_ops = 0;

	xdrrec_create(&connection->conn_xdrs, 0, 0, (caddr_t)connection,
	    ndmp_readit, ndmp_writeit);

	if (connection->conn_xdrs.x_ops == 0) {
		NDMP_LOG(LOG_DEBUG, "xdrrec_create failed");
		(void) mutex_destroy(&connection->conn_lock);
		(void) close(connection->conn_sock);
		free(connection);
		return (0);
	}
	return ((ndmp_connection_t *)connection);
}

/*
 * ndmp_destroy_connection
 *
 * Shutdown a connection and release allocated resources.
 *
 * Parameters:
 *   connection_handle (Input) - connection handle.
 *
 * Returns:
 *   void
 */
void
ndmp_destroy_connection(ndmp_connection_t *connection_handle)
{
	ndmp_connection_t *connection = (ndmp_connection_t *)connection_handle;

	if (connection->conn_sock >= 0) {
		(void) mutex_destroy(&connection->conn_lock);
		(void) close(connection->conn_sock);
		connection->conn_sock = -1;
	}
	xdr_destroy(&connection->conn_xdrs);
	free(connection);
}


/*
 * ndmp_close
 *
 * Close a connection.
 *
 * Parameters:
 *   connection_handle (Input) - connection handle.
 *
 * Returns:
 *   void
 */
void
ndmp_close(ndmp_connection_t *connection_handle)
{
	ndmp_connection_t *connection = (ndmp_connection_t *)connection_handle;

	ndmpd_audit_disconnect(connection);
	if (connection->conn_sock >= 0) {
		(void) mutex_destroy(&connection->conn_lock);
		(void) close(connection->conn_sock);
		connection->conn_sock = -1;
	}
	connection->conn_eof = TRUE;

	/*
	 * We should close all the tapes that are used by this connection.
	 * In some cases the ndmp client opens a tape, but does not close the
	 * tape and closes the connection.
	 */
	ndmp_open_list_release(connection_handle);
}

/*
 * ndmp_start_worker
 *
 * Initializes and starts a ndmp_worker thread
 */
int
ndmp_start_worker(ndmpd_worker_arg_t *argp)
{
	pthread_attr_t tattr;
	int rc;

	(void) pthread_attr_init(&tattr);
	(void) pthread_attr_setdetachstate(&tattr, PTHREAD_CREATE_DETACHED);
	rc = pthread_create(NULL, &tattr, ndmpd_worker, (void *)argp);
	(void) pthread_attr_destroy(&tattr);
	return (rc);
}

/*
 * ndmp_run
 *
 * Creates a socket for listening and accepting connections
 * from NDMP clients.
 * Accepts connections and passes each connection to the connection
 * handler.
 *
 * Parameters:
 *   port (input)   -  NDMP server port.
 *		     If 0, the port number will be retrieved from
 *		     the network service database. If not found there,
 *		     the default NDMP port number (from ndmp.x)
 *		     will be used.
 *   handler (input) - connection handler function.
 *
 * Returns:
 *   This function normally never returns unless there's error.
 *   -1 : error
 *
 * Notes:
 *   This function does not return unless encountering an error
 *   related to the listen socket.
 */
int
ndmp_run(ulong_t port, ndmp_con_handler_func_t con_handler_func)
{
	int ns;
	int on;
	int server_socket;
	unsigned int ipaddr;
	struct sockaddr_in sin;
	ndmpd_worker_arg_t *argp;

	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = INADDR_ANY;
	sin.sin_port = htons(port);

	if ((server_socket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		NDMP_LOG(LOG_DEBUG, "Socket error: %m");
		return (-1);
	}

	on = 1;
	(void) setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR,
	    (char *)&on, sizeof (on));


	if (bind(server_socket, (struct sockaddr *)&sin, sizeof (sin)) < 0) {
		NDMP_LOG(LOG_DEBUG, "bind error: %m");
		(void) close(server_socket);
		return (-1);
	}
	if (listen(server_socket, 5) < 0) {
		NDMP_LOG(LOG_DEBUG, "listen error: %m");
		(void) close(server_socket);
		return (-1);
	}

	for (; ; ) {
		if ((ns = tcp_accept(server_socket, &ipaddr)) < 0) {
			NDMP_LOG(LOG_DEBUG, "tcp_accept error: %m");
			continue;
		}
		NDMP_LOG(LOG_DEBUG, "connection fd: %d", ns);
		set_socket_options(ns);

		if ((argp = ndmp_malloc(sizeof (ndmpd_worker_arg_t))) != NULL) {
			argp->nw_sock = ns;
			argp->nw_ipaddr = ipaddr;
			argp->nw_con_handler_func = con_handler_func;
			(void) ndmp_start_worker(argp);
		}
	}
}

/*
 * ndmpd_worker thread
 *
 * Parameters:
 *   argp (input) - structure containing socket and handler function
 *
 * Returns:
 *   0 - successful connection.
 *  -1 - error.
 */
void *
ndmpd_worker(void *ptarg)
{
	int sock;
	ndmp_connection_t *connection;
	ndmpd_worker_arg_t *argp = (ndmpd_worker_arg_t *)ptarg;

	if (!argp)
		return ((void *)-1);

	NS_INC(trun);
	sock = argp->nw_sock;

	if ((connection = ndmp_create_connection()) == NULL) {
		(void) close(sock);
		free(argp);
		exit(1);
	}

	/* initialize auditing session */
	if (adt_start_session(&connection->conn_ah, NULL, 0) != 0) {
		free(argp);
		return ((void *)-1);
	}

	((ndmp_connection_t *)connection)->conn_sock = sock;
	(*argp->nw_con_handler_func)(connection);
	(void) adt_end_session(connection->conn_ah);
	ndmp_destroy_connection(connection);
	NS_DEC(trun);

	free(argp);
	return (NULL);
}

/*
 * ndmp_process_requests
 *
 * Reads the next request message into the stream buffer.
 * Processes messages until the stream buffer is empty.
 *
 * Parameters:
 *   connection_handle (input) - connection handle.
 *
 * Returns:
 *   0 - 1 or more messages successfully processed.
 *  -1 - error; connection no longer established.
 */
int
ndmp_process_requests(ndmp_connection_t *connection_handle)
{
	int rv;
	ndmp_connection_t *connection = (ndmp_connection_t *)connection_handle;

	(void) mutex_lock(&connection->conn_lock);
	rv = 0;
	if (ndmp_process_messages(connection, FALSE) < 0)
		rv = -1;

	(void) mutex_unlock(&connection->conn_lock);
	return (rv);
}


/*
 * ndmp_send_request
 *
 * Send an NDMP request message.
 *
 * Parameters:
 *   connection_handle (input) - connection pointer.
 *   message (input) - message number.
 *   err (input)  - error code to place in header.
 *   request_data (input) - message body.
 *   reply (output) - reply message. If 0, reply will be
 *				discarded.
 *
 * Returns:
 *   0	- successful send.
 *  -1	- error.
 *   otherwise - error from reply header.
 *
 * Notes:
 *   - The reply body is only returned if the error code is NDMP_NO_ERR.
 */
int
ndmp_send_request(ndmp_connection_t *connection_handle, ndmp_message message,
    ndmp_error err, void *request_data, void **reply)
{
	ndmp_connection_t *connection = (ndmp_connection_t *)connection_handle;
	ndmp_header header;
	ndmp_msg_handler_t *handler;
	int r;
	struct timeval time;

	/* Lookup info necessary for processing this request. */
	if (!(handler = ndmp_get_handler(connection, message))) {
		NDMP_LOG(LOG_DEBUG, "Sending message 0x%x: not supported",
		    message);
		return (-1);
	}
	(void) gettimeofday(&time, 0);

	header.sequence = ++(connection->conn_my_sequence);
	header.time_stamp = time.tv_sec;
	header.message_type = NDMP_MESSAGE_REQUEST;
	header.message = message;
	header.reply_sequence = 0;
	header.error = err;

	connection->conn_xdrs.x_op = XDR_ENCODE;
	if (!xdr_ndmp_header(&connection->conn_xdrs, &header)) {
		NDMP_LOG(LOG_DEBUG,
		    "Sending message 0x%x: encoding request header", message);
		(void) xdrrec_endofrecord(&connection->conn_xdrs, 1);
		return (-1);
	}
	if (err == NDMP_NO_ERR && handler->mh_xdr_request && request_data) {
		if (!(*handler->mh_xdr_request)(&connection->conn_xdrs,
		    request_data)) {
			NDMP_LOG(LOG_DEBUG,
			    "Sending message 0x%x: encoding request body",
			    message);
			(void) xdrrec_endofrecord(&connection->conn_xdrs, 1);
			return (-1);
		}
	}
	(void) xdrrec_endofrecord(&connection->conn_xdrs, 1);

	if (handler->mh_xdr_reply == 0) {
		NDMP_LOG(LOG_DEBUG, "handler->mh_xdr_reply == 0");
		return (0);
	}

	/*
	 * Process messages until the reply to this request has been
	 * processed.
	 */
	for (; ; ) {
		r = ndmp_process_messages(connection, TRUE);

		/* connection error? */
		if (r < 0)
			return (-1);

		/* no reply received? */
		if (r == 0)
			continue;

		/* reply received? */
		if (r == 1) {
			if (message !=
			    connection->conn_msginfo.mi_hdr.message) {
				NDMP_LOG(LOG_DEBUG,
				    "Received unexpected reply 0x%x",
				    connection->conn_msginfo.mi_hdr.message);
				ndmp_free_message(connection_handle);
				return (-1);
			}
			if (reply != NULL)
				*reply = connection->conn_msginfo.mi_body;
			else
				ndmp_free_message(connection_handle);

			return (connection->conn_msginfo.mi_hdr.error);
		}
		/* error handling reply */

		return (-1);
	}
}


/*
 * ndmp_send_request_lock
 *
 * A wrapper for ndmp_send_request with locks.
 *
 * Parameters:
 *   connection_handle (input) - connection pointer.
 *   message (input) - message number.
 *   err (input) - error code to place in header.
 *   request_data (input) - message body.
 *   reply (output) - reply message. If 0, reply will be
 *				discarded.
 *
 * Returns:
 *   0	- successful send.
 *  -1	- error.
 *   otherwise - error from reply header.
 *
 * Notes:
 *   - The reply body is only returned if the error code is NDMP_NO_ERR.
 */
int
ndmp_send_request_lock(ndmp_connection_t *connection_handle,
    ndmp_message message, ndmp_error err, void *request_data, void **reply)
{
	int rv;
	ndmp_connection_t *connection = (ndmp_connection_t *)connection_handle;

	(void) mutex_lock(&connection->conn_lock);

	rv = ndmp_send_request(connection_handle, message, err, request_data,
	    reply);
	(void) mutex_unlock(&connection->conn_lock);
	return (rv);
}


/*
 * ndmp_send_response
 *
 * Send an NDMP reply message.
 *
 * Parameters:
 *   connection_handle  (input)  - connection pointer.
 *   err	       (input)  - error code to place in header.
 *   reply	     (input)  - reply message body.
 *
 * Returns:
 *   0 - successful send.
 *  -1 - error.
 *
 * Notes:
 *   - The body is only sent if the error code is NDMP_NO_ERR.
 */
int
ndmp_send_response(ndmp_connection_t *connection_handle, ndmp_error err,
    void *reply)
{
	ndmp_connection_t *connection = (ndmp_connection_t *)connection_handle;
	ndmp_header header;
	struct timeval time;

	(void) gettimeofday(&time, 0);

	header.sequence = ++(connection->conn_my_sequence);
	header.time_stamp = time.tv_sec;
	header.message_type = NDMP_MESSAGE_REPLY;
	header.message = connection->conn_msginfo.mi_hdr.message;
	header.reply_sequence = connection->conn_msginfo.mi_hdr.sequence;
	header.error = err;

	connection->conn_xdrs.x_op = XDR_ENCODE;
	if (!xdr_ndmp_header(&connection->conn_xdrs, &header)) {
		NDMP_LOG(LOG_DEBUG, "Sending message 0x%x: "
		    "encoding reply header",
		    header.message);
		(void) xdrrec_endofrecord(&connection->conn_xdrs, 1);
		return (-1);
	}
	if (err == NDMP_NO_ERR &&
	    connection->conn_msginfo.mi_handler->mh_xdr_reply &&
	    reply) {
		if (!(*connection->conn_msginfo.mi_handler->mh_xdr_reply)(
		    &connection->conn_xdrs, reply)) {
			NDMP_LOG(LOG_DEBUG,
			    "Sending message 0x%x: encoding reply body",
			    header.message);
			(void) xdrrec_endofrecord(&connection->conn_xdrs, 1);
			return (-1);
	}
	}
	(void) xdrrec_endofrecord(&connection->conn_xdrs, 1);
	return (0);
}

/*
 * ndmp_free_message
 *
 * Free the memory of NDMP message body.
 *
 * Parameters:
 *   connection_handle  (input)  - connection pointer.
 *
 * Returns:
 *   void
 *
 */
void
ndmp_free_message(ndmp_connection_t *connection_handle)
{
	ndmp_connection_t *connection = (ndmp_connection_t *)connection_handle;

	if (connection->conn_msginfo.mi_handler == NULL ||
	    connection->conn_msginfo.mi_body == NULL)
		return;

	connection->conn_xdrs.x_op = XDR_FREE;
	if (connection->conn_msginfo.mi_hdr.message_type ==
	    NDMP_MESSAGE_REQUEST) {
		if (connection->conn_msginfo.mi_handler->mh_xdr_request)
			(*connection->conn_msginfo.mi_handler->mh_xdr_request)(
			    &connection->conn_xdrs,
			    connection->conn_msginfo.mi_body);
	} else {
		if (connection->conn_msginfo.mi_handler->mh_xdr_reply)
			(*connection->conn_msginfo.mi_handler->mh_xdr_reply)(
			    &connection->conn_xdrs,
			    connection->conn_msginfo.mi_body);
	}

	(void) free(connection->conn_msginfo.mi_body);
	connection->conn_msginfo.mi_body = 0;
}

/*
 * ndmp_get_fd
 *
 * Returns the connection file descriptor.
 *
 * Parameters:
 *   connection_handle (input) - connection handle
 *
 * Returns:
 *   >=0 - file descriptor.
 *   -1  - connection not open.
 */
int
ndmp_get_fd(ndmp_connection_t *connection_handle)
{
	return (((ndmp_connection_t *)connection_handle)->conn_sock);
}


/*
 * ndmp_set_client_data
 *
 * This function provides a means for the library client to provide
 * a pointer to some user data structure that is retrievable by
 * each message handler via ndmp_get_client_data.
 *
 * Parameters:
 *   connection_handle  (input) - connection handle.
 *   client_data	(input) - user data pointer.
 *
 * Returns:
 *   void
 */
void
ndmp_set_client_data(ndmp_connection_t *connection_handle, void *client_data)
{
	((ndmp_connection_t *)connection_handle)->conn_client_data =
	    client_data;
}


/*
 * ndmp_get_client_data
 *
 * This function provides a means for the library client to provide
 * a pointer to some user data structure that is retrievable by
 * each message handler via ndmp_get_client_data.
 *
 * Parameters:
 *   connection_handle (input) - connection handle.
 *
 * Returns:
 *   client data pointer.
 */
void *
ndmp_get_client_data(ndmp_connection_t *connection_handle)
{
	return (((ndmp_connection_t *)connection_handle)->conn_client_data);
}


/*
 * ndmp_set_version
 *
 * Sets the NDMP protocol version to be used on the connection.
 *
 * Parameters:
 *   connection_handle  (input) - connection handle.
 *   version	   (input) - protocol version.
 *
 * Returns:
 *   void
 */
void
ndmp_set_version(ndmp_connection_t *connection_handle, ushort_t version)
{
	((ndmp_connection_t *)connection_handle)->conn_version = version;
}


/*
 * ndmp_get_version
 *
 * Gets the NDMP protocol version in use on the connection.
 *
 * Parameters:
 *   connection_handle  (input) - connection handle.
 *   version	   (input) - protocol version.
 *
 * Returns:
 *   void
 */
ushort_t
ndmp_get_version(ndmp_connection_t *connection_handle)
{
	return (((ndmp_connection_t *)connection_handle)->conn_version);
}


/*
 * ndmp_set_authorized
 *
 * Mark the connection as either having been authorized or not.
 *
 * Parameters:
 *   connection_handle  (input) - connection handle.
 *   authorized	(input) - TRUE or FALSE.
 *
 * Returns:
 *   void
 */
void
ndmp_set_authorized(ndmp_connection_t *connection_handle, boolean_t authorized)
{
	((ndmp_connection_t *)connection_handle)->conn_authorized = authorized;
}


/*
 * ndmpd_main
 *
 * NDMP main function called from main().
 *
 * Parameters:
 *   void
 *
 * Returns:
 *   void
 */
void
ndmpd_main(void)
{
	char *propval;

	ndmp_load_params();

	/*
	 * Find ndmp port number to be used. If ndmpd is run as command line
	 * and port number is supplied, use that port number. If port number is
	 * is not supplied, find out if ndmp port property is set. If ndmp
	 * port property is set, use that port number otherwise use the defaule
	 * port number.
	 */
	if (ndmp_port == 0) {
		if ((propval = ndmpd_get_prop(NDMP_TCP_PORT)) == NULL ||
		    *propval == 0)
			ndmp_port = NDMPPORT;
		else
			ndmp_port = strtol(propval, 0, 0);
	}

	if (ndmp_run(ndmp_port, connection_handler) == -1)
		perror("ndmp_run ERROR");
}

/*
 * connection_handler
 *
 * NDMP connection handler.
 * Waits for, reads, and processes NDMP requests on a connection.
 *
 * Parameters:
 *   connection (input) - connection handle.
 *
 * Return:
 *   void
 */
void
connection_handler(ndmp_connection_t *connection)
{
	static int conn_id = 1;
	ndmpd_session_t session;
	ndmp_notify_connected_request req;
	int connection_fd;

	(void) memset(&session, 0, sizeof (session));
	session.ns_connection = connection;
	session.ns_eof = FALSE;
	/*
	 * The 'protocol_version' must be 1 at first, since the client talks
	 * to the server in version 1 then they can move to a higher
	 * protocol version.
	 */
	session.ns_protocol_version = ndmp_ver;

	session.ns_scsi.sd_is_open = -1;
	session.ns_scsi.sd_devid = -1;

	session.ns_scsi.sd_sid = 0;
	session.ns_scsi.sd_lun = 0;
	session.ns_scsi.sd_valid_target_set = 0;
	(void) memset(session.ns_scsi.sd_adapter_name, 0,
	    sizeof (session.ns_scsi.sd_adapter_name));

	session.ns_tape.td_fd = -1;
	session.ns_tape.td_sid = 0;
	session.ns_tape.td_lun = 0;
	(void) memset(session.ns_tape.td_adapter_name, 0,
	    sizeof (session.ns_tape.td_adapter_name));
	session.ns_tape.td_pos = 0;
	session.ns_tape.td_record_count = 0;
	session.ns_file_handler_list = 0;

	(void) ndmpd_data_init(&session);
	ndmpd_file_history_init(&session);
	if (ndmpd_mover_init(&session) < 0)
		return;

	if (ndmp_lbr_init(&session) < 0)
		return;

	/*
	 * Setup defaults here. The init functions can not set defaults
	 * since the init functions are called by the stop request handlers
	 * and client set variables need to persist across data operations.
	 */
	session.ns_mover.md_record_size = MAX_RECORD_SIZE;

	ndmp_set_client_data(connection, (void *)&session);

	req.reason = NDMP_CONNECTED;
	req.protocol_version = ndmp_ver;
	req.text_reason = "";

	if (ndmp_send_request_lock(connection, NDMP_NOTIFY_CONNECTION_STATUS,
	    NDMP_NO_ERR, (void *)&req, 0) < 0) {
		NDMP_LOG(LOG_DEBUG, "Connection terminated");
		return;
	}
	connection_fd = ndmp_get_fd(connection);

	NDMP_LOG(LOG_DEBUG, "connection_fd: %d", connection_fd);

	/*
	 * Add the handler function for the connection to the DMA.
	 */
	if (ndmpd_add_file_handler(&session, (void *)&session, connection_fd,
	    NDMPD_SELECT_MODE_READ, HC_CLIENT, connection_file_handler) != 0) {
		NDMP_LOG(LOG_DEBUG, "Could not register session handler.");
		return;
	}

	/*
	 * Register the connection in the list of active connections.
	 */
	if (ndmp_connect_list_add(connection, &conn_id) != 0) {
		NDMP_LOG(LOG_ERR,
		    "Could not register the session to the server.");
		(void) ndmpd_remove_file_handler(&session, connection_fd);
		return;
	}

	session.hardlink_q = hardlink_q_init();

	while (session.ns_eof == FALSE)
		(void) ndmpd_select(&session, TRUE, HC_ALL);

	hardlink_q_cleanup(session.hardlink_q);

	NDMP_LOG(LOG_DEBUG, "Connection terminated");

	(void) ndmpd_remove_file_handler(&session, connection_fd);

	if (session.ns_scsi.sd_is_open != -1) {
		NDMP_LOG(LOG_DEBUG, "scsi.is_open: %d",
		    session.ns_scsi.sd_is_open);
		(void) ndmp_open_list_del(session.ns_scsi.sd_adapter_name,
		    session.ns_scsi.sd_sid, session.ns_scsi.sd_lun);
	}
	if (session.ns_tape.td_fd != -1) {
		NDMP_LOG(LOG_DEBUG, "tape.fd: %d", session.ns_tape.td_fd);
		(void) close(session.ns_tape.td_fd);
		(void) ndmp_open_list_del(session.ns_tape.td_adapter_name,
		    session.ns_tape.td_sid, session.ns_tape.td_lun);
	}
	ndmpd_mover_shut_down(&session);
	ndmp_lbr_cleanup(&session);
	ndmpd_data_cleanup(&session);
	ndmpd_file_history_cleanup(&session, FALSE);
	ndmpd_mover_cleanup(&session);

	(void) ndmp_connect_list_del(connection);
}


/*
 * connection_file_handler
 *
 * ndmp_connection_t file handler function.
 * Called by ndmpd_select when data is available to be read on the
 * NDMP connection.
 *
 * Parameters:
 *   cookie (input) - session pointer.
 *   fd      (input) - connection file descriptor.
 *   mode    (input) - select mode.
 *
 * Returns:
 *   void.
 */
/*ARGSUSED*/
static void
connection_file_handler(void *cookie, int fd, ulong_t mode)
{
	ndmpd_session_t *session = (ndmpd_session_t *)cookie;

	if (ndmp_process_requests(session->ns_connection) < 0)
		session->ns_eof = TRUE;
}


/* ************* private functions *************************************** */

/*
 * ndmp_readit
 *
 * Low level read routine called by the xdrrec library.
 *
 * Parameters:
 *   connection (input) - connection pointer.
 *   buf	(input) - location to store received data.
 *   len	(input) - max number of bytes to read.
 *
 * Returns:
 *   >0 - number of bytes received.
 *   -1 - error.
 */
static int
ndmp_readit(void *connection_handle, caddr_t buf, int len)
{
	ndmp_connection_t *connection = (ndmp_connection_t *)connection_handle;

	len = read(connection->conn_sock, buf, len);
	if (len <= 0) {
		/* ndmp_connection_t has been closed. */
		connection->conn_eof = TRUE;
		return (-1);
	}
	return (len);
}

/*
 * ndmp_writeit
 *
 * Low level write routine called by the xdrrec library.
 *
 * Parameters:
 *   connection (input) - connection pointer.
 *   buf	(input) - location to store received data.
 *   len	(input) - max number of bytes to read.
 *
 * Returns:
 *   >0 - number of bytes sent.
 *   -1 - error.
 */
static int
ndmp_writeit(void *connection_handle, caddr_t buf, int len)
{
	ndmp_connection_t *connection = (ndmp_connection_t *)connection_handle;
	register int n;
	register int cnt;

	for (cnt = len; cnt > 0; cnt -= n, buf += n) {
		if ((n = write(connection->conn_sock, buf, cnt)) < 0) {
			connection->conn_eof = TRUE;
			return (-1);
		}
	}

	return (len);
}


/*
 * ndmp_recv_msg
 *
 * Read the next message.
 *
 * Parameters:
 *   connection (input)  - connection pointer.
 *   msg	(output) - received message.
 *
 * Returns:
 *   0 - Message successfully received.
 *   error number - Message related error.
 *  -1 - Error decoding the message header.
 */
static int
ndmp_recv_msg(ndmp_connection_t *connection)
{
	bool_t(*xdr_func) (XDR *, ...) = NULL;

	/* Decode the header. */
	connection->conn_xdrs.x_op = XDR_DECODE;
	(void) xdrrec_skiprecord(&connection->conn_xdrs);
	if (!xdr_ndmp_header(&connection->conn_xdrs,
	    &connection->conn_msginfo.mi_hdr))
		return (-1);

	/* Lookup info necessary for processing this message. */
	if ((connection->conn_msginfo.mi_handler = ndmp_get_handler(connection,
	    connection->conn_msginfo.mi_hdr.message)) == 0) {
		NDMP_LOG(LOG_DEBUG, "Message 0x%x not supported",
		    connection->conn_msginfo.mi_hdr.message);
		return (NDMP_NOT_SUPPORTED_ERR);
	}
	connection->conn_msginfo.mi_body = 0;

	if (connection->conn_msginfo.mi_hdr.error != NDMP_NO_ERR)
		return (0);

	/* Determine body type */
	if (connection->conn_msginfo.mi_hdr.message_type ==
	    NDMP_MESSAGE_REQUEST) {
		if (ndmp_check_auth_required(
		    connection->conn_msginfo.mi_hdr.message) &&
		    !connection->conn_authorized) {
			NDMP_LOG(LOG_DEBUG,
			    "Processing request 0x%x:connection not authorized",
			    connection->conn_msginfo.mi_hdr.message);
			return (NDMP_NOT_AUTHORIZED_ERR);
		}
		if (connection->conn_msginfo.mi_handler->mh_sizeof_request >
		    0) {
			xdr_func =
			    connection->conn_msginfo.mi_handler->mh_xdr_request;
			if (xdr_func == NULL) {
				NDMP_LOG(LOG_DEBUG,
				    "Processing request 0x%x: no xdr function "
				    "in handler table",
				    connection->conn_msginfo.mi_hdr.message);
				return (NDMP_NOT_SUPPORTED_ERR);
			}
			connection->conn_msginfo.mi_body = ndmp_malloc(
			    connection->conn_msginfo.mi_handler->
			    mh_sizeof_request);
			if (connection->conn_msginfo.mi_body == NULL)
				return (NDMP_NO_MEM_ERR);

			(void) memset(connection->conn_msginfo.mi_body, 0,
			    connection->conn_msginfo.mi_handler->
			    mh_sizeof_request);
		}
	} else {
		if (connection->conn_msginfo.mi_handler->mh_sizeof_reply > 0) {
			xdr_func =
			    connection->conn_msginfo.mi_handler->mh_xdr_reply;
			if (xdr_func == NULL) {
				NDMP_LOG(LOG_DEBUG,
				    "Processing reply 0x%x: no xdr function "
				    "in handler table",
				    connection->conn_msginfo.mi_hdr.message);
				return (NDMP_NOT_SUPPORTED_ERR);
			}
			connection->conn_msginfo.mi_body = ndmp_malloc(
			    connection->conn_msginfo.mi_handler->
			    mh_sizeof_reply);
			if (connection->conn_msginfo.mi_body == NULL)
				return (NDMP_NO_MEM_ERR);

			(void) memset(connection->conn_msginfo.mi_body, 0,
			    connection->conn_msginfo.mi_handler->
			    mh_sizeof_reply);
		}
	}

	/* Decode message arguments if needed */
	if (xdr_func) {
		if (!(*xdr_func)(&connection->conn_xdrs,
		    connection->conn_msginfo.mi_body)) {
			NDMP_LOG(LOG_DEBUG,
			    "Processing message 0x%x: error decoding arguments",
			    connection->conn_msginfo.mi_hdr.message);
			free(connection->conn_msginfo.mi_body);
			connection->conn_msginfo.mi_body = 0;
			return (NDMP_XDR_DECODE_ERR);
		}
	}
	return (0);
}

/*
 * ndmp_process_messages
 *
 * Reads the next message into the stream buffer.
 * Processes messages until the stream buffer is empty.
 *
 * This function processes all data in the stream buffer before returning.
 * This allows functions like poll() to be used to determine when new
 * messages have arrived. If only some of the messages in the stream buffer
 * were processed and then poll was called, poll() could block waiting for
 * a message that had already been received and read into the stream buffer.
 *
 * This function processes both request and reply messages.
 * Request messages are dispatched using the appropriate function from the
 * message handling table.
 * Only one reply messages may be pending receipt at a time.
 * A reply message, if received, is placed in connection->conn_msginfo
 * before returning to the caller.
 * Errors are reported if a reply is received but not expected or if
 * more than one reply message is received
 *
 * Parameters:
 *   connection     (input)  - connection pointer.
 *   reply_expected (output) - TRUE  - a reply message is expected.
 *			     FALSE - no reply message is expected and
 *			     an error will be reported if a reply
 *			     is received.
 *
 * Returns:
 *   NDMP_PROC_REP_ERR - 1 or more messages successfully processed,
 *   	error processing reply message.
 *   NDMP_PROC_REP_ERR - 1 or more messages successfully processed,
 *	reply seen.
 *   NDMP_PROC_REP_ERR - 1 or more messages successfully processed,
 * 	no reply seen.
 *   NDMP_PROC_REP_ERR - error; connection no longer established.
 *
 * Notes:
 *   If the peer is generating a large number of requests, a caller
 *   looking for a reply will be blocked while the requests are handled.
 *   This is because this function does not return until the stream
 *   buffer is empty.
 *   Code needs to be added to allow a return if the stream buffer
 *   is not empty but there is data available on the socket. This will
 *   prevent poll() from blocking and prevent a caller looking for a reply
 *   from getting blocked by a bunch of requests.
 */
static int
ndmp_process_messages(ndmp_connection_t *connection, boolean_t reply_expected)
{
	msg_info_t reply_msginfo;
	boolean_t reply_read = FALSE;
	boolean_t reply_error = FALSE;
	int err;

	NDMP_LOG(LOG_DEBUG, "reply_expected: %s",
	    reply_expected == TRUE ? "TRUE" : "FALSE");

	(void) memset((void *)&reply_msginfo, 0, sizeof (msg_info_t));

	do {
		(void) memset((void *)&connection->conn_msginfo, 0,
		    sizeof (msg_info_t));

		if ((err = ndmp_recv_msg(connection)) != NDMP_NO_ERR) {
			if (connection->conn_eof) {
				NDMP_LOG(LOG_DEBUG, "detected eof");
				return (NDMP_PROC_ERR);
			}
			if (err < 1) {
				NDMP_LOG(LOG_DEBUG, "error decoding header");

				/*
				 * Error occurred decoding the header.
				 * Don't send a reply since we don't know
				 * the message or if the message was even
				 * a request message.  To be safe, assume
				 * that the message was a reply if a reply
				 * was expected. Need to do this to prevent
				 * hanging ndmp_send_request() waiting for a
				 * reply.  Don't set reply_read so that the
				 * reply will be processed if it is received
				 * later.
				 */
				if (reply_read == FALSE)
					reply_error = TRUE;

				continue;
			}
			if (connection->conn_msginfo.mi_hdr.message_type
			    != NDMP_MESSAGE_REQUEST) {
				NDMP_LOG(LOG_DEBUG, "received reply: 0x%x",
				    connection->conn_msginfo.mi_hdr.message);

				if (reply_expected == FALSE ||
				    reply_read == TRUE)
					NDMP_LOG(LOG_DEBUG,
					    "Unexpected reply message: 0x%x",
					    connection->conn_msginfo.mi_hdr.
					    message);

				ndmp_free_message((ndmp_connection_t *)
				    connection);

				if (reply_read == FALSE) {
					reply_read = TRUE;
					reply_error = TRUE;
				}
				continue;
			}
			NDMP_LOG(LOG_DEBUG, "received request: 0x%x",
			    connection->conn_msginfo.mi_hdr.message);

			(void) ndmp_send_response((ndmp_connection_t *)
			    connection, err, NULL);
			ndmp_free_message((ndmp_connection_t *)connection);
			continue;
		}
		if (connection->conn_msginfo.mi_hdr.message_type
		    != NDMP_MESSAGE_REQUEST) {
			NDMP_LOG(LOG_DEBUG, "received reply: 0x%x",
			    connection->conn_msginfo.mi_hdr.message);

			if (reply_expected == FALSE || reply_read == TRUE) {
				NDMP_LOG(LOG_DEBUG,
				    "Unexpected reply message: 0x%x",
				    connection->conn_msginfo.mi_hdr.message);
				ndmp_free_message((ndmp_connection_t *)
				    connection);
				continue;
			}
			reply_read = TRUE;
			reply_msginfo = connection->conn_msginfo;
			continue;
		}
		NDMP_LOG(LOG_DEBUG, "received request: 0x%x",
		    connection->conn_msginfo.mi_hdr.message);

		/*
		 * The following is needed to catch an improperly constructed
		 * handler table or to deal with an NDMP client that is not
		 * conforming to the negotiated protocol version.
		 */
		if (connection->conn_msginfo.mi_handler->mh_func == NULL) {
			NDMP_LOG(LOG_DEBUG, "No handler for message 0x%x",
			    connection->conn_msginfo.mi_hdr.message);

			(void) ndmp_send_response((ndmp_connection_t *)
			    connection, NDMP_NOT_SUPPORTED_ERR, NULL);
			ndmp_free_message((ndmp_connection_t *)connection);
			continue;
		}
		/*
		 * Call the handler function.
		 * The handler will send any necessary reply.
		 */
		(*connection->conn_msginfo.mi_handler->mh_func) (connection,
		    connection->conn_msginfo.mi_body);

		ndmp_free_message((ndmp_connection_t *)connection);

	} while (xdrrec_eof(&connection->conn_xdrs) == FALSE &&
	    connection->conn_eof == FALSE);

	NDMP_LOG(LOG_DEBUG, "no more messages in stream buffer");

	if (connection->conn_eof == TRUE) {
		if (reply_msginfo.mi_body)
			free(reply_msginfo.mi_body);
		return (NDMP_PROC_ERR);
	}
	if (reply_error) {
		if (reply_msginfo.mi_body)
			free(reply_msginfo.mi_body);
		return (NDMP_PROC_REP_ERR);
	}
	if (reply_read) {
		connection->conn_msginfo = reply_msginfo;
		return (NDMP_PROC_MSG);
	}
	return (NDMP_PROC_REP);
}


/*
 * ndmp_get_interface
 *
 * Return the NDMP interface (e.g. config, scsi, tape) for the
 * specific message.
 *
 * Parameters:
 *   message (input) - message number.
 *
 * Returns:
 *   NULL - message not found.
 *   pointer to handler info.
 */
static ndmp_handler_t *
ndmp_get_interface(ndmp_message message)
{
	ndmp_handler_t *ni = &ndmp_msghdl_tab[(message >> 8) % INT_MAXCMD];

	if ((message & 0xff) >= ni->hd_cnt)
		return (NULL);

	/* Sanity check */
	if (ni->hd_msgs[message & 0xff].hm_message != message)
		return (NULL);

	return (ni);
}

/*
 * ndmp_get_handler
 *
 * Return the handler info for the specified NDMP message.
 *
 * Parameters:
 *   connection (input) - connection pointer.
 *   message (input) - message number.
 *
 * Returns:
 *   NULL - message not found.
 *   pointer to handler info.
 */
static ndmp_msg_handler_t *
ndmp_get_handler(ndmp_connection_t *connection, ndmp_message message)
{
	ndmp_msg_handler_t *handler = NULL;

	ndmp_handler_t *ni = ndmp_get_interface(message);
	int ver = connection->conn_version;

	if (ni)
		handler = &ni->hd_msgs[message & 0xff].hm_msg_v[ver - 2];

	return (handler);
}

/*
 * ndmp_check_auth_required
 *
 * Check if the connection needs to be authenticated before
 * this message is being processed.
 *
 * Parameters:
 *   message (input) - message number.
 *
 * Returns:
 *   TRUE - required
 *   FALSE - not required
 */
static boolean_t
ndmp_check_auth_required(ndmp_message message)
{
	boolean_t auth_req = FALSE;
	ndmp_handler_t *ni = ndmp_get_interface(message);

	if (ni)
		auth_req = ni->hd_msgs[message & 0xff].hm_auth_required;

	return (auth_req);
}

/*
 * tcp_accept
 *
 * A wrapper around accept for retrying and getting the IP address
 *
 * Parameters:
 *   listen_sock (input) - the socket for listening
 *   inaddr_p (output) - the IP address of peer connection
 *
 * Returns:
 *   socket for the accepted connection
 *   -1: error
 */
int
tcp_accept(int listen_sock, unsigned int *inaddr_p)
{
	struct sockaddr_in	sin;
	int			sock, i;
	int			try;

	for (try = 0; try < 3; try++) {
		i = sizeof (sin);
		sock = accept(listen_sock, (struct sockaddr *)&sin, &i);
		if (sock < 0) {
			continue;
		}
		*inaddr_p = sin.sin_addr.s_addr;
		return (sock);
	}
	return (-1);
}


/*
 * tcp_get_peer
 *
 * Get the peer IP address for a connection
 *
 * Parameters:
 *   sock (input) - the active socket
 *   inaddr_p (output) - the IP address of peer connection
 *   port_p (output) - the port number of peer connection
 *
 * Returns:
 *   socket for the accepted connection
 *   -1: error
 */
int
tcp_get_peer(int sock, unsigned int *inaddr_p, int *port_p)
{
	struct sockaddr_in sin;
	int i, rc;

	i = sizeof (sin);
	rc = getpeername(sock, (struct sockaddr *)&sin, &i);
	if (rc != 0)
		return (-1);

	if (inaddr_p)
		*inaddr_p = sin.sin_addr.s_addr;

	if (port_p)
		*port_p = ntohs(sin.sin_port);

	return (sock);

}

/*
 * gethostaddr
 *
 * Get the IP address string of the current host
 *
 * Parameters:
 *   void
 *
 * Returns:
 *   IP address
 *   NULL: error
 */
char *
gethostaddr(void)
{
	static char s[MAXHOSTNAMELEN];
	struct hostent *h;
	struct in_addr in;
	char *p;

	if (gethostname(s, sizeof (s)) == -1)
		return (NULL);

	if ((h = gethostbyname(s)) == NULL)
		return (NULL);

	p = h->h_addr_list[0];
	(void) memcpy(&in.s_addr, p, sizeof (in.s_addr));
	return (inet_ntoa(in));
}


/*
 * get_default_nic_addr
 *
 * Get the IP address of the default NIC
 */
char *
get_default_nic_addr(void)
{
	struct ifaddrlist *al = NULL;
	char errmsg[ERRBUFSIZE];
	struct in_addr addr;
	int nifs;

	nifs = ifaddrlist(&al, AF_INET, LIFC_EXTERNAL_SOURCE, errmsg);
	if (nifs <= 0)
		return (NULL);

	/* pick the first interface's address */
	addr = al[0].addr.addr;
	free(al);

	return (inet_ntoa(IN_ADDR(addr.s_addr)));
}


/*
 * ndmpd_audit_backup
 *
 * Generate AUE_ndmp_backup audit record
 */
/*ARGSUSED*/
void
ndmpd_audit_backup(ndmp_connection_t *conn,
    char *path, int dest, char *local_path, int result)
{
	adt_event_data_t *event;

	if ((event = adt_alloc_event(conn->conn_ah, ADT_ndmp_backup)) == NULL) {
		NDMP_LOG(LOG_ERR, "Audit failure: %m.");
		return;
	}
	event->adt_ndmp_backup.source = path;

	if (dest == NDMP_ADDR_LOCAL) {
		event->adt_ndmp_backup.local_dest = local_path;
	} else {
		event->adt_ndmp_backup.remote_dest = conn->conn_sock;
	}

	if (result == 0) {
		if (adt_put_event(event, ADT_SUCCESS, ADT_SUCCESS) != 0)
			NDMP_LOG(LOG_ERR, "Audit failure: %m.");
	} else {
		if (adt_put_event(event, ADT_FAILURE, result) != 0)
			NDMP_LOG(LOG_ERR, "Audit failure: %m.");
	}

	adt_free_event(event);
}


/*
 * ndmpd_audit_restore
 *
 * Generate AUE_ndmp_restore audit record
 */
/*ARGSUSED*/
void
ndmpd_audit_restore(ndmp_connection_t *conn,
    char *path, int dest, char *local_path, int result)
{
	adt_event_data_t *event;

	if ((event = adt_alloc_event(conn->conn_ah,
	    ADT_ndmp_restore)) == NULL) {
		NDMP_LOG(LOG_ERR, "Audit failure: %m.");
		return;
	}
	event->adt_ndmp_restore.destination = path;

	if (dest == NDMP_ADDR_LOCAL) {
		event->adt_ndmp_restore.local_source = local_path;
	} else {
		event->adt_ndmp_restore.remote_source = conn->conn_sock;
	}

	if (result == 0) {
		if (adt_put_event(event, ADT_SUCCESS, ADT_SUCCESS) != 0)
			NDMP_LOG(LOG_ERR, "Audit failure: %m.");
	} else {
		if (adt_put_event(event, ADT_FAILURE, result) != 0)
			NDMP_LOG(LOG_ERR, "Audit failure: %m.");
	}

	adt_free_event(event);
}


/*
 * ndmpd_audit_connect
 *
 * Generate AUE_ndmp_connect audit record
 */
/*ARGSUSED*/
void
ndmpd_audit_connect(ndmp_connection_t *conn, int result)
{
	adt_event_data_t *event;
	adt_termid_t *termid;

	if (adt_load_termid(conn->conn_sock, &termid) != 0) {
		NDMP_LOG(LOG_ERR, "Audit failure: %m.");
		return;
	}

	if (adt_set_user(conn->conn_ah, ADT_NO_ATTRIB, ADT_NO_ATTRIB,
	    ADT_NO_ATTRIB, ADT_NO_ATTRIB, termid, ADT_NEW) != 0) {
		NDMP_LOG(LOG_ERR, "Audit failure: %m.");
		free(termid);
		return;
	}
	free(termid);

	if ((event = adt_alloc_event(conn->conn_ah,
	    ADT_ndmp_connect)) == NULL) {
		NDMP_LOG(LOG_ERR, "Audit failure: %m.");
		return;
	}

	if (result == 0) {
		if (adt_put_event(event, ADT_SUCCESS, ADT_SUCCESS) != 0)
			NDMP_LOG(LOG_ERR, "Audit failure: %m.");
	} else {
		if (adt_put_event(event, ADT_FAILURE, result) != 0)
			NDMP_LOG(LOG_ERR, "Audit failure: %m.");
	}

	adt_free_event(event);
}


/*
 * ndmpd_audit_disconnect
 *
 * Generate AUE_ndmp_disconnect audit record
 */
/*ARGSUSED*/
void
ndmpd_audit_disconnect(ndmp_connection_t *conn)
{
	adt_event_data_t *event;

	if ((event = adt_alloc_event(conn->conn_ah,
	    ADT_ndmp_disconnect)) == NULL) {
		NDMP_LOG(LOG_ERR, "Audit failure: %m.");
		return;
	}
	if (adt_put_event(event, ADT_SUCCESS, ADT_SUCCESS) != 0)
		NDMP_LOG(LOG_ERR, "Audit failure: %m.");

	adt_free_event(event);
}

void *
ndmp_malloc(size_t size)
{
	void *data;

	if ((data = calloc(1, size)) == NULL) {
		NDMP_LOG(LOG_ERR, "Out of memory.");
	}

	return (data);
}

/*
 * get_backup_path_v3
 *
 * Get the backup path from the NDMP environment variables.
 *
 * Parameters:
 *   params (input) - pointer to the parameters structure.
 *
 * Returns:
 *   The backup path: if anything is specified
 *   NULL: Otherwise
 */
char *
get_backup_path_v3(ndmpd_module_params_t *params)
{
	char *bkpath;

	bkpath = MOD_GETENV(params, "PREFIX");
	if (!bkpath)
		bkpath = MOD_GETENV(params, "FILESYSTEM");


	if (!bkpath) {
		MOD_LOGV3(params, NDMP_LOG_ERROR,
		    "Backup path not defined.\n");
	} else {
		NDMP_LOG(LOG_DEBUG, "bkpath: \"%s\"", bkpath);
	}

	return (bkpath);
}

/*
 * get_backup_path
 *
 * Find the backup path from the environment variables (v2)
 */
char *
get_backup_path_v2(ndmpd_module_params_t *params)
{
	char *bkpath;

	bkpath = MOD_GETENV(params, "PREFIX");
	if (bkpath == NULL)
		bkpath = MOD_GETENV(params, "FILESYSTEM");

	if (bkpath == NULL) {
		MOD_LOG(params, "Error: restore path not specified.\n");
		return (NULL);
	}

	if (*bkpath != '/') {
		MOD_LOG(params, "Error: relative backup path not allowed.\n");
		return (NULL);
	}

	return (bkpath);
}
