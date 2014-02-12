/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
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
/* Copyright 2014 Nexenta Systems, Inc. All rights reserved. */

#include <sys/types.h>
#include <errno.h>
#include <pwd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/queue.h>
#include <arpa/inet.h>
#include <md5.h>
#include <shadow.h>
#include <crypt.h>
#include <alloca.h>
#include "ndmpd_common.h"
#include "ndmpd.h"
#include <libndmp.h>
#include <ndmpd_door.h>
#include <security/pam_appl.h>


static int ndmpd_connect_auth_text(char *uname, char *auth_id,
    char *auth_password);
static int ndmpd_connect_auth_md5(char *uname, char *auth_id, char *auth_digest,
    unsigned char *auth_challenge);
static struct conn_list *ndmp_connect_list_find(ndmp_connection_t *connection);
static void create_md5_digest(unsigned char *digest, char *passwd,
    unsigned char *challenge);
static struct conn_list *ndmp_connect_list_find_id(int id);

/* routines for connection info */
void ndmp_connect_list_get(ndmp_door_ctx_t *enc_ctx);
static void connection_get(struct conn_list *clp, ndmp_door_ctx_t *enc_ctx);
static void ndmp_connect_get_conn(struct conn_list *clp,
    ndmp_door_ctx_t *enc_ctx);
static void ndmp_connect_get_v2(ndmp_connection_t *connection,
    ndmp_door_ctx_t *enc_ctx);
static void ndmp_connect_get_scsi_v2(ndmpd_session_t *session,
    ndmp_door_ctx_t *enc_ctx);
static void ndmp_connect_get_tape_v2(ndmpd_session_t *session,
    ndmp_door_ctx_t *enc_ctx);
static void ndmp_connect_get_mover_v2(ndmpd_session_t *session,
    ndmp_door_ctx_t *enc_ctx);
static void ndmp_connect_get_data_v2(ndmpd_session_t *session,
    ndmp_door_ctx_t *enc_ctx);
static void ndmp_connect_get_v3(ndmp_connection_t *connection,
    ndmp_door_ctx_t *enc_ctx);
static void ndmp_connect_get_mover_v3(ndmpd_session_t *session,
    ndmp_door_ctx_t *enc_ctx);
static void ndmp_connect_get_data_v3(ndmpd_session_t *session,
    ndmp_door_ctx_t *enc_ctx);
void ndmpd_get_devs(ndmp_door_ctx_t *enc_ctx);

#ifndef LIST_FOREACH
#define	LIST_FOREACH(var, head, field)					\
	for ((var) = (head)->lh_first; (var); (var) = (var)->field.le_next)
#endif /* LIST_FOREACH */

/*
 * List of active connections.
 */
struct conn_list {
	LIST_ENTRY(conn_list) cl_q;
	int cl_id;
	ndmp_connection_t *cl_conn;
};
LIST_HEAD(cl_head, conn_list);

/*
 * Head of the active connections.
 */
static struct cl_head cl_head;

mutex_t cl_mutex = DEFAULTMUTEX;


/*
 * Set this variable to non-zero to print verbose information.
 */
int ndmp_connect_print_verbose = 0;


/*
 * ************************************************************************
 * NDMP V2 HANDLERS
 * ************************************************************************
 */

/*
 * ndmpd_connect_open_v2
 *
 * This handler sets the protocol version to be used on the connection.
 *
 * Parameters:
 *   connection (input) - connection handle.
 *   body       (input) - request message body.
 *
 * Returns:
 *   void
 */

void
ndmpd_connect_open_v2(ndmp_connection_t *connection, void *body)
{
	ndmp_connect_open_request *request = (ndmp_connect_open_request *)body;
	ndmp_connect_open_reply reply;
	ndmpd_session_t *session;

	reply.error = NDMP_NO_ERR;

	if (!(session = (ndmpd_session_t *)ndmp_get_client_data(connection)))
		return;

	if (session->ns_mover.md_state != NDMP_MOVER_STATE_IDLE ||
	    session->ns_data.dd_state != NDMP_DATA_STATE_IDLE)
		reply.error = NDMP_ILLEGAL_STATE_ERR;
	else if (request->protocol_version > ndmp_ver)
		reply.error = NDMP_ILLEGAL_ARGS_ERR;

	ndmp_send_reply(connection, (void *) &reply,
	    "sending connect_open reply");

	/*
	 * Set the protocol version.
	 * Must wait until after sending the reply since the reply
	 * must be sent using the same protocol version that was used
	 * to process the request.
	 */
	if (reply.error == NDMP_NO_ERR) {
		NDMP_LOG(LOG_DEBUG, "set ver to: %d",
		    request->protocol_version);
		ndmp_set_version(connection, request->protocol_version);
		session->ns_protocol_version = request->protocol_version;
	}
}


/*
 * ndmpd_connect_client_auth_v2
 *
 * This handler authorizes the NDMP connection.
 *
 * Parameters:
 *   connection (input) - connection handle.
 *   msginfo    (input) - request message.
 *
 * Returns:
 *   void
 */
void
ndmpd_connect_client_auth_v2(ndmp_connection_t *connection, void *body)
{
	ndmp_connect_client_auth_request *request;
	ndmp_connect_client_auth_reply reply;
	ndmp_auth_text *auth;
	ndmpd_session_t *session;
	ndmp_auth_md5 *md5;
	unsigned char md5_digest[16];
	char *passwd, *dec_passwd;
	char *uname;

	request = (ndmp_connect_client_auth_request *)body;
	NDMP_LOG(LOG_DEBUG, "auth_type:%s",
	    request->auth_data.auth_type == NDMP_AUTH_NONE ? "None" :
	    (request->auth_data.auth_type == NDMP_AUTH_TEXT ? "Text" :
	    (request->auth_data.auth_type == NDMP_AUTH_MD5 ? "MD5" :
	    "Invalid")));

	reply.error = NDMP_NO_ERR;

	switch (request->auth_data.auth_type) {
	case NDMP_AUTH_NONE:
		/*
		 * Allow no authorization for development.
		 * Comment the following for a non-secure production server.
		 */
		NDMP_LOG(LOG_ERR, "Authorization denied.");
		NDMP_LOG(LOG_ERR,
		    "Authorization type should be md5 or cleartext.");
		reply.error = NDMP_ILLEGAL_ARGS_ERR;
		ndmpd_audit_connect(connection, EINVAL);
		break;

	case NDMP_AUTH_TEXT:
		/* Check authorization.  */
		if ((uname = ndmpd_get_prop(NDMP_CLEARTEXT_USERNAME)) == NULL ||
		    *uname == 0) {
			NDMP_LOG(LOG_ERR, "Authorization denied.");
			NDMP_LOG(LOG_ERR, "User name is not set at server.");
			reply.error = NDMP_NOT_AUTHORIZED_ERR;
			ndmp_set_authorized(connection, FALSE);
			ndmp_send_reply(connection, (void *) &reply,
			    "sending ndmp_connect_client_auth reply");
			ndmpd_audit_connect(connection,
			    ADT_FAIL_PAM + PAM_AUTH_ERR);
			return;
		}
		auth = &request->auth_data.ndmp_auth_data_u.auth_text;
		if (strcmp(uname, auth->user) != 0) {
			NDMP_LOG(LOG_ERR,
			    "Authorization denied. Not a valid user.");
			reply.error = NDMP_NOT_AUTHORIZED_ERR;
			ndmpd_audit_connect(connection,
			    ADT_FAIL_PAM + PAM_AUTH_ERR);
			break;
		}
		passwd = ndmpd_get_prop(NDMP_CLEARTEXT_PASSWORD);
		if (!passwd || !*passwd) {
			NDMP_LOG(LOG_ERR, "Authorization denied.");
			NDMP_LOG(LOG_ERR,
			    "Cleartext password is not set at server.");
			reply.error = NDMP_NOT_AUTHORIZED_ERR;
			ndmp_set_authorized(connection, FALSE);
			ndmp_send_reply(connection, (void *) &reply,
			    "sending ndmp_connect_client_auth reply");
			ndmpd_audit_connect(connection,
			    ADT_FAIL_PAM + PAM_AUTH_ERR);
			return;
		} else {
			dec_passwd = ndmp_base64_decode(passwd);
		}
		if (!dec_passwd || !*dec_passwd ||
		    strcmp(auth->password, dec_passwd) != 0) {
			NDMP_LOG(LOG_ERR,
			    "Authorization denied. Invalid password.");
			reply.error = NDMP_NOT_AUTHORIZED_ERR;
		} else {
			NDMP_LOG(LOG_DEBUG, "Authorization granted.");
		}
		ndmpd_audit_connect(connection, reply.error ?
		    ADT_FAIL_PAM + PAM_AUTH_ERR : 0);

		free(dec_passwd);
		break;

	case NDMP_AUTH_MD5:
		/* Check authorization.  */
		if ((uname = ndmpd_get_prop(NDMP_CRAM_MD5_USERNAME)) == NULL ||
		    *uname == 0) {
			NDMP_LOG(LOG_ERR, "Authorization denied.");
			NDMP_LOG(LOG_ERR,  "User name is not set at server.");
			reply.error = NDMP_NOT_AUTHORIZED_ERR;
			ndmp_set_authorized(connection, FALSE);
			ndmp_send_reply(connection, (void *) &reply,
			    "sending ndmp_connect_client_auth reply");
			ndmpd_audit_connect(connection,
			    ADT_FAIL_PAM + PAM_AUTH_ERR);
			return;
		}
		md5 = &request->auth_data.ndmp_auth_data_u.auth_md5;
		passwd = ndmpd_get_prop(NDMP_CRAM_MD5_PASSWORD);
		if (!passwd || !*passwd) {
			NDMP_LOG(LOG_ERR, "Authorization denied.");
			NDMP_LOG(LOG_ERR, "MD5 password is not set at server.");
			reply.error = NDMP_NOT_AUTHORIZED_ERR;
			ndmp_set_authorized(connection, FALSE);
			ndmp_send_reply(connection, (void *) &reply,
			    "sending ndmp_connect_client_auth reply");
			ndmpd_audit_connect(connection,
			    ADT_FAIL_PAM + PAM_AUTH_ERR);
			return;
		} else {
			dec_passwd = ndmp_base64_decode(passwd);
		}
		session = ndmp_get_client_data(connection);
		create_md5_digest(md5_digest, dec_passwd,
		    session->ns_challenge);

		if (strcmp(uname, md5->user) != 0) {
			NDMP_LOG(LOG_ERR,
			    "Authorization denied. Not a valid user.");
			reply.error = NDMP_NOT_AUTHORIZED_ERR;
		} else if (memcmp(md5_digest, md5->auth_digest,
		    sizeof (md5_digest)) != 0) {
			NDMP_LOG(LOG_ERR,
			    "Authorization denied. Invalid password.");
			reply.error = NDMP_NOT_AUTHORIZED_ERR;
		} else {
			NDMP_LOG(LOG_DEBUG, "Authorization granted");
		}
		ndmpd_audit_connect(connection, reply.error ?
		    ADT_FAIL_PAM + PAM_AUTH_ERR : 0);

		free(dec_passwd);
		break;

	default:
		reply.error = NDMP_ILLEGAL_ARGS_ERR;
	}

	if (reply.error == NDMP_NO_ERR)
		ndmp_set_authorized(connection, TRUE);
	else
		ndmp_set_authorized(connection, FALSE);

	ndmp_send_reply(connection, (void *) &reply,
	    "sending ndmp_connect_client_auth reply");
}


/*
 * ndmpd_connect_server_auth_v2
 *
 * This handler authenticates the server to the client.
 *
 * Parameters:
 *   connection (input) - connection handle.
 *   msginfo    (input) - request message.
 *
 * Returns:
 *   void
 */
void
ndmpd_connect_server_auth_v2(ndmp_connection_t *connection, void *body)
{
	ndmp_connect_server_auth_request *request;
	ndmp_connect_server_auth_reply reply;

	request = (ndmp_connect_server_auth_request *)body;

	NDMP_LOG(LOG_DEBUG, "auth_type:%s",
	    request->client_attr.auth_type == NDMP_AUTH_NONE ? "None" :
	    (request->client_attr.auth_type == NDMP_AUTH_TEXT ? "Text" :
	    (request->client_attr.auth_type == NDMP_AUTH_MD5 ? "MD5" :
	    "Invalid")));

	reply.error = NDMP_NO_ERR;
	reply.auth_result.auth_type = request->client_attr.auth_type;
	switch (request->client_attr.auth_type) {
	case NDMP_AUTH_NONE:
		break;

	case NDMP_AUTH_TEXT:
		reply.auth_result.ndmp_auth_data_u.auth_text.user = "ndmpd";
		reply.auth_result.ndmp_auth_data_u.auth_text.password =
		    "ndmpsdk";
		break;

	case NDMP_AUTH_MD5:
		reply.error = NDMP_ILLEGAL_ARGS_ERR;
		break;

	default:
		reply.error = NDMP_ILLEGAL_ARGS_ERR;
	}

	ndmp_send_reply(connection, (void *) &reply,
	    "sending ndmp_connect_auth reply");
}


/*
 * ndmpd_connect_close_v2
 *
 * This handler closes the connection.
 *
 * Parameters:
 *   connection (input) - connection handle.
 *   msginfo    (input) - request message.
 *
 * Returns:
 *   void
 */
/*ARGSUSED*/
void
ndmpd_connect_close_v2(ndmp_connection_t *connection, void *body)
{
	ndmpd_session_t *session;

	if ((session = (ndmpd_session_t *)ndmp_get_client_data(connection))) {
		(void) ndmp_close(connection);
		session->ns_eof = TRUE;
	}
}

/*
 * ************************************************************************
 * NDMP V3 HANDLERS
 * ************************************************************************
 */

/*
 * ndmpd_connect_client_auth_v3
 *
 * This handler authorizes the NDMP connection.
 *
 * Parameters:
 *   connection (input) - connection handle.
 *   msginfo    (input) - request message.
 *
 * Returns:
 *   void
 */
void
ndmpd_connect_client_auth_v3(ndmp_connection_t *connection, void *body)
{
	ndmp_connect_client_auth_request_v3 *request;
	ndmp_connect_client_auth_reply_v3 reply;
	ndmp_auth_text_v3 *auth;
	ndmpd_session_t *session;
	ndmp_auth_md5_v3 *md5;
	struct in_addr addr;
	char *uname;
	char *type;

	request = (ndmp_connect_client_auth_request_v3 *)body;
	NDMP_LOG(LOG_DEBUG, "auth_type %s",
	    request->auth_data.auth_type == NDMP_AUTH_NONE ? "None" :
	    request->auth_data.auth_type == NDMP_AUTH_TEXT ? "Text" :
	    request->auth_data.auth_type == NDMP_AUTH_MD5 ? "MD5" : "Invalid");

	reply.error = NDMP_NO_ERR;

	switch (request->auth_data.auth_type) {
	case NDMP_AUTH_NONE:
		type = "none";
		reply.error = NDMP_NOT_SUPPORTED_ERR;
		ndmpd_audit_connect(connection, ENOTSUP);
		break;

	case NDMP_AUTH_TEXT:
		/* Check authorization.  */
		if ((uname = ndmpd_get_prop(NDMP_CLEARTEXT_USERNAME)) == NULL ||
		    *uname == 0) {
			NDMP_LOG(LOG_ERR, "Authorization denied.");
			NDMP_LOG(LOG_ERR, "User name is not set at server.");
			reply.error = NDMP_NOT_AUTHORIZED_ERR;
			ndmp_set_authorized(connection, FALSE);
			ndmp_send_reply(connection, (void *) &reply,
			    "sending ndmp_connect_client_auth reply");
			ndmpd_audit_connect(connection,
			    ADT_FAIL_PAM + PAM_AUTH_ERR);
			return;
		}
		type = "text";
		auth = &request->auth_data.ndmp_auth_data_v3_u.auth_text;
		reply.error = ndmpd_connect_auth_text(uname, auth->auth_id,
		    auth->auth_password);
		ndmpd_audit_connect(connection, reply.error ?
		    ADT_FAIL_PAM + PAM_AUTH_ERR : 0);
		break;

	case NDMP_AUTH_MD5:
		/* Check authorization.  */
		if ((uname = ndmpd_get_prop(NDMP_CRAM_MD5_USERNAME)) == NULL ||
		    *uname == 0) {
			NDMP_LOG(LOG_ERR, "Authorization denied.");
			NDMP_LOG(LOG_ERR, "User name is not set at server.");
			reply.error = NDMP_NOT_AUTHORIZED_ERR;
			ndmp_set_authorized(connection, FALSE);
			ndmp_send_reply(connection, (void *) &reply,
			    "sending ndmp_connect_client_auth reply");
			ndmpd_audit_connect(connection,
			    ADT_FAIL_PAM + PAM_AUTH_ERR);
			return;
		}
		type = "md5";
		session = ndmp_get_client_data(connection);
		md5 = &request->auth_data.ndmp_auth_data_v3_u.auth_md5;
		reply.error = ndmpd_connect_auth_md5(uname, md5->auth_id,
		    md5->auth_digest, session->ns_challenge);
		ndmpd_audit_connect(connection, reply.error ?
		    ADT_FAIL_PAM + PAM_AUTH_ERR : 0);
		break;

	default:
		type = "unknown";
		reply.error = NDMP_ILLEGAL_ARGS_ERR;
		ndmpd_audit_connect(connection, EINVAL);
	}

	if (reply.error == NDMP_NO_ERR) {
		ndmp_set_authorized(connection, TRUE);
	} else {
		ndmp_set_authorized(connection, FALSE);
		if (tcp_get_peer(connection->conn_sock, &addr.s_addr,
		    NULL) != -1) {
			NDMP_LOG(LOG_ERR,
			    "Authorization(%s) denied for %s.", type,
			    inet_ntoa(IN_ADDR(addr)));
		}
	}

	ndmp_send_reply(connection, (void *) &reply,
	    "sending ndmp_connect_auth reply");
}


/*
 * ndmpd_connect_close_v3
 *
 * Close the connection to the DMA.
 * Send the SHUTDOWN message before closing the socket connection to the DMA.
 *
 * Parameters:
 *   connection (input) - connection handle.
 *   msginfo    (input) - request message.
 *
 * Returns:
 *   void
 */
/*ARGSUSED*/
void
ndmpd_connect_close_v3(ndmp_connection_t *connection, void *body)
{
	ndmpd_session_t *session;
	ndmp_lbr_params_t *nlp;
	ndmp_notify_connected_request req;

	if (!(session = (ndmpd_session_t *)ndmp_get_client_data(connection)))
		return;
	if ((nlp = ndmp_get_nlp(session)) == NULL)
		return;

	NDMP_LOG(LOG_DEBUG, "ver: %u",
	    session->ns_protocol_version);

	/* Send the SHUTDOWN message before closing the connection. */
	req.reason = NDMP_SHUTDOWN;
	req.protocol_version = session->ns_protocol_version;
	req.text_reason = "Connection closed by server.";

	if (ndmp_send_request(connection, NDMP_NOTIFY_CONNECTION_STATUS,
	    NDMP_NO_ERR, (void *) &req, 0) < 0) {
		NDMP_LOG(LOG_NOTICE, "Sending connection shutdown notify");
		return;
	}

	(void) mutex_lock(&nlp->nlp_mtx);
	ndmp_close(connection);
	session->ns_eof = TRUE;
	(void) cond_broadcast(&nlp->nlp_cv);
	(void) mutex_unlock(&nlp->nlp_mtx);
}

/*
 * ************************************************************************
 * NDMP V4 HANDLERS
 * ************************************************************************
 */

/*
 * ************************************************************************
 * LOCALS
 * ************************************************************************
 */

/*
 * create_md5_digest
 *
 * This function uses the MD5 message-digest algorithm described
 * in RFC1321 to authenticate the client using a shared secret (password).
 * The message used to compute the MD5 digest is a concatenation of password,
 * null padding, the 64 byte fixed length challenge and a repeat of the
 * password. The length of the null padding is chosen to result in a 128 byte
 * fixed length message. The lengh of the padding can be computed as
 * 64 - 2*(length of the password). The client digest is computed using the
 * server challenge from the NDMP_CONFIG_GET_AUTH_ATTR reply.
 *
 * Parameters:
 *   digest (output) - 16 bytes MD5 digest
 *   passwd (input) - user password
 *   challenge (input) - 64 bytes server challenge
 *
 * Returns:
 *   void
 */
static void
create_md5_digest(unsigned char *digest, char *passwd, unsigned char *challenge)
{
	char buf[130];
	char *p = &buf[0];
	int len, i;
	MD5_CTX md;
	char *pwd;

	*p = 0;
	pwd = passwd;
	if ((len = strlen(pwd)) > MD5_PASS_LIMIT)
		len = MD5_PASS_LIMIT;
	(void) memcpy(p, pwd, len);
	p += len;

	for (i = 0; i < MD5_CHALLENGE_SIZE - 2 * len; i++)
		*p++ = 0;

	(void) memcpy(p, challenge, MD5_CHALLENGE_SIZE);
	p += MD5_CHALLENGE_SIZE;
	(void) strlcpy(p, pwd, MD5_PASS_LIMIT);

	MD5Init(&md);
	MD5Update(&md, buf, 128);
	MD5Final(digest, &md);
}

/*
 * ndmp_connect_list_find
 *
 * Find the element in the active connection list.
 *
 * Parameters:
 *   connection (input) - connection handler.
 *
 * Returns:
 *   NULL - error
 *   connection list element pointer
 */
static struct conn_list *
ndmp_connect_list_find(ndmp_connection_t *connection)
{
	struct conn_list *clp;

	NDMP_LOG(LOG_DEBUG, "connection: 0x%p",
	    connection);

	LIST_FOREACH(clp, &cl_head, cl_q) {
		if (clp->cl_conn == connection) {
			(void) mutex_unlock(&cl_mutex);
			return (clp);
		}
	}
	return (NULL);
}

/*
 * ndmpconnect_list_add
 *
 * Add the new connection to the list of the active connections.
 *
 * Parameters:
 *   connection (input) - connection handler.
 *   id (input/output) - pointer to connection id.
 *
 * Returns:
 *   0 - success
 *  -1 - error
 */
int
ndmp_connect_list_add(ndmp_connection_t *connection, int *id)
{
	struct conn_list *clp;

	if (connection == NULL) {
		NDMP_LOG(LOG_DEBUG, "Invalid argument");
		return (-1);
	}

	if ((clp = ndmp_malloc(sizeof (struct conn_list))) == NULL)
		return (-1);

	clp->cl_conn = connection;
	clp->cl_id = *id;

	(void) mutex_lock(&cl_mutex);
	LIST_INSERT_HEAD(&cl_head, clp, cl_q);
	(*id)++;
	(void) mutex_unlock(&cl_mutex);

	return (0);
}

/*
 * ndmp_connect_list_del
 *
 * Delete the specified connection from the list.
 *
 * Parameters:
 *   connection (input) - connection handler.
 *
 * Returns:
 *   0 - success
 *  -1 - error
 */
int
ndmp_connect_list_del(ndmp_connection_t *connection)
{
	struct conn_list *clp;

	(void) mutex_lock(&cl_mutex);
	if (!(clp = ndmp_connect_list_find(connection))) {
		(void) mutex_unlock(&cl_mutex);
		NDMP_LOG(LOG_DEBUG, "connection not found");
		return (-1);
	}

	LIST_REMOVE(clp, cl_q);
	(void) mutex_unlock(&cl_mutex);
	free(clp);

	return (0);
}


/*
 * ndmpconnect_list_find_id
 *
 * Find the element specified by its id in the list of active connections.
 *
 * Parameters:
 *   id (input) - connection id.
 *
 * Returns:
 *   NULL - error
 *   connection list element pointer
 */
static struct conn_list *
ndmp_connect_list_find_id(int id)
{
	struct conn_list *clp;

	NDMP_LOG(LOG_DEBUG, "id: %d", id);

	(void) mutex_lock(&cl_mutex);
	LIST_FOREACH(clp, &cl_head, cl_q) {
		if (clp->cl_id == id) {
			(void) mutex_unlock(&cl_mutex);
			return (clp);
		}
	}

	(void) mutex_unlock(&cl_mutex);
	return (NULL);
}

/*
 * Get common fields of the active connection.
 */
static void
ndmp_connect_get_conn(struct conn_list *clp, ndmp_door_ctx_t *enc_ctx)
{
	int port;
	struct in_addr addr;
	char cl_addr[NDMP_CL_ADDR_LEN];
	ndmpd_session_t *session;

	if (!(session = (ndmpd_session_t *)ndmp_get_client_data(clp->cl_conn)))
		return;

	ndmp_door_put_int32(enc_ctx, clp->cl_id);
	ndmp_door_put_int32(enc_ctx, session->ns_protocol_version);
	ndmp_door_put_int32(enc_ctx, clp->cl_conn->conn_authorized);
	ndmp_door_put_int32(enc_ctx, session->ns_eof);
	if (tcp_get_peer(clp->cl_conn->conn_sock, &(addr.s_addr), &port) != -1)
		(void) snprintf(cl_addr, NDMP_CL_ADDR_LEN, "%s:%d",
		    (char *)inet_ntoa(addr), port);
	else
		cl_addr[0] = '\0';
	ndmp_door_put_string(enc_ctx, cl_addr);
}

/*
 * Get the connection SCSI info.
 */
static void
ndmp_connect_get_scsi_v2(ndmpd_session_t *session, ndmp_door_ctx_t *enc_ctx)
{
	ndmp_door_put_int32(enc_ctx, session->ns_scsi.sd_is_open);
	ndmp_door_put_string(enc_ctx, session->ns_scsi.sd_adapter_name);
	ndmp_door_put_int32(enc_ctx, session->ns_scsi.sd_valid_target_set);
	if (session->ns_scsi.sd_valid_target_set) {
		ndmp_door_put_int32(enc_ctx, session->ns_scsi.sd_sid);
		ndmp_door_put_int32(enc_ctx, session->ns_scsi.sd_lun);
	}
}

/*
 * Get the connection tape info.
 */
static void
ndmp_connect_get_tape_v2(ndmpd_session_t *session, ndmp_door_ctx_t *enc_ctx)
{
	char dev_name[NDMP_TAPE_DEV_NAME];

	ndmp_door_put_int32(enc_ctx, session->ns_tape.td_fd);
	if (session->ns_tape.td_fd != -1) {
		ndmp_door_put_uint64(enc_ctx, session->ns_tape.td_record_count);
		ndmp_door_put_int32(enc_ctx, session->ns_tape.td_mode);
		(void) snprintf(dev_name, NDMP_TAPE_DEV_NAME, "%st%02x%x",
		    session->ns_tape.td_adapter_name, session->ns_tape.td_sid,
		    session->ns_tape.td_lun);
		ndmp_door_put_string(enc_ctx, dev_name);
		ndmp_door_put_string(enc_ctx, session->ns_tape.td_adapter_name);
		ndmp_door_put_int32(enc_ctx, session->ns_tape.td_sid);
		ndmp_door_put_int32(enc_ctx, session->ns_tape.td_lun);
	}
}

/*
 * Get the connection mover info.
 */
static void
ndmp_connect_get_mover_v2(ndmpd_session_t *session, ndmp_door_ctx_t *enc_ctx)
{
	ndmp_door_put_int32(enc_ctx, session->ns_mover.md_state);
	ndmp_door_put_int32(enc_ctx, session->ns_mover.md_mode);
	ndmp_door_put_int32(enc_ctx, session->ns_mover.md_pause_reason);
	ndmp_door_put_int32(enc_ctx, session->ns_mover.md_halt_reason);
	ndmp_door_put_uint64(enc_ctx, session->ns_mover.md_record_size);
	ndmp_door_put_uint64(enc_ctx, session->ns_mover.md_record_num);
	ndmp_door_put_uint64(enc_ctx, session->ns_mover.md_position);
	ndmp_door_put_uint64(enc_ctx, session->ns_mover.md_window_offset);
	ndmp_door_put_uint64(enc_ctx, session->ns_mover.md_window_length);
	ndmp_door_put_int32(enc_ctx, session->ns_mover.md_sock);
}

/*
 * Get the connection common data info.
 */
static void
ndmp_connect_get_data_common(ndmpd_session_t *session, ndmp_door_ctx_t *enc_ctx)
{
	int i;
	ndmp_pval *ep;
	int len;

	ndmp_door_put_int32(enc_ctx, session->ns_data.dd_operation);
	ndmp_door_put_int32(enc_ctx, session->ns_data.dd_state);
	ndmp_door_put_int32(enc_ctx, session->ns_data.dd_halt_reason);
	ndmp_door_put_int32(enc_ctx, session->ns_data.dd_sock);
	ndmp_door_put_int32(enc_ctx, session->ns_data.dd_mover.addr_type);
	ndmp_door_put_int32(enc_ctx, session->ns_data.dd_abort);
	ndmp_door_put_uint64(enc_ctx, session->ns_data.dd_read_offset);
	ndmp_door_put_uint64(enc_ctx, session->ns_data.dd_read_length);
	ndmp_door_put_uint64(enc_ctx, session->ns_data.dd_data_size);
	/* verify data.env has as much data as in session->ns_data.dd_env_len */
	len = 0;
	ep = session->ns_data.dd_env;
	for (i = 0; ep && i < session->ns_data.dd_env_len; i++, ep++)
		len++;

	/* put the len */
	(void) mutex_lock(&session->ns_lock);
	ndmp_door_put_uint64(enc_ctx, len);
	ep = session->ns_data.dd_env;
	for (i = 0; i < len; i++, ep++) {
		ndmp_door_put_string(enc_ctx, ep->name);
		ndmp_door_put_string(enc_ctx, ep->value);
	}
	(void) mutex_unlock(&session->ns_lock);
}

/*
 * Get the connection data info.
 */
static void
ndmp_connect_get_data_v2(ndmpd_session_t *session, ndmp_door_ctx_t *enc_ctx)
{
	int i;
	ndmp_name *np;
	char tcp_addr[NDMP_TCP_ADDR_SIZE];

	ndmp_connect_get_data_common(session, enc_ctx);

	switch (session->ns_data.dd_mover.addr_type) {
	case NDMP_ADDR_LOCAL:
		(void) snprintf(tcp_addr, NDMP_TCP_ADDR_SIZE, "%s", "Local");
		ndmp_door_put_string(enc_ctx, tcp_addr);
		break;
	case NDMP_ADDR_TCP:
		(void) snprintf(tcp_addr, NDMP_TCP_ADDR_SIZE, "%s:%d",
		    (char *)inet_ntoa(IN_ADDR(
		    session->ns_data.dd_mover.ndmp_mover_addr_u.addr.ip_addr)),
		    session->ns_data.dd_mover.ndmp_mover_addr_u.addr.port);
		ndmp_door_put_string(enc_ctx, tcp_addr);
		break;
	default:
		(void) snprintf(tcp_addr, NDMP_TCP_ADDR_SIZE, "%s", "Unknown");
		ndmp_door_put_string(enc_ctx, tcp_addr);
	}

	ndmp_door_put_uint64(enc_ctx, session->ns_data.dd_nlist_len);
	np = session->ns_data.dd_nlist;
	for (i = 0; np && i < (int)session->ns_data.dd_nlist_len; i++, np++) {
		ndmp_door_put_string(enc_ctx, np->name);
		ndmp_door_put_string(enc_ctx, np->dest);
	}
}

/*
 * Get V2 connection info.
 */
static void
ndmp_connect_get_v2(ndmp_connection_t *connection, ndmp_door_ctx_t *enc_ctx)
{
	ndmpd_session_t *session;

	if ((session = (ndmpd_session_t *)ndmp_get_client_data(connection))) {
		ndmp_connect_get_scsi_v2(session, enc_ctx);
		ndmp_connect_get_tape_v2(session, enc_ctx);
		ndmp_connect_get_mover_v2(session, enc_ctx);
		ndmp_connect_get_data_v2(session, enc_ctx);
	}
}

/*
 * Get the V3 connection mover info.
 */
static void
ndmp_connect_get_mover_v3(ndmpd_session_t *session, ndmp_door_ctx_t *enc_ctx)
{
	char tcp_addr[NDMP_TCP_ADDR_SIZE];

	/* get all the V2 mover data first */
	ndmp_connect_get_mover_v2(session, enc_ctx);

	/* get the V3 mover data now */
	ndmp_door_put_int32(enc_ctx, session->ns_mover.md_listen_sock);
	ndmp_door_put_int32(enc_ctx, session->ns_mover.md_data_addr.addr_type);
	tcp_addr[0] = '\0';
	(void) snprintf(tcp_addr, NDMP_TCP_ADDR_SIZE, "%s:%d",
	    (char *)
	    inet_ntoa(IN_ADDR(session->ns_mover.md_data_addr.tcp_ip_v3)),
	    (int)session->ns_mover.md_data_addr.tcp_port_v3);
	ndmp_door_put_string(enc_ctx, tcp_addr);
}

/*
 * Get the connection data info.
 */
static void
ndmp_connect_get_data_v3(ndmpd_session_t *session, ndmp_door_ctx_t *enc_ctx)
{
	ulong_t i;
	mem_ndmp_name_v3_t *np;
	char tcp_addr[NDMP_TCP_ADDR_SIZE];

	ndmp_connect_get_data_common(session, enc_ctx);

	(void) snprintf(tcp_addr, NDMP_TCP_ADDR_SIZE, "%s:%d",
	    (char *)inet_ntoa(IN_ADDR(session->ns_data.dd_data_addr.tcp_ip_v3)),
	    (int)session->ns_data.dd_data_addr.tcp_port_v3);
	ndmp_door_put_string(enc_ctx, tcp_addr);
	ndmp_door_put_int32(enc_ctx, session->ns_data.dd_listen_sock);
	ndmp_door_put_uint64(enc_ctx,
	    session->ns_data.dd_module.dm_stats.ms_bytes_processed);
	ndmp_door_put_uint64(enc_ctx, session->ns_data.dd_nlist_len);
	np = session->ns_data.dd_nlist_v3;
	for (i = 0; np && i < (int)session->ns_data.dd_nlist_len; i++, np++) {
		ndmp_door_put_string(enc_ctx, np->nm3_opath);
		ndmp_door_put_string(enc_ctx, np->nm3_dpath);
		ndmp_door_put_uint64(enc_ctx, np->nm3_node);
		ndmp_door_put_uint64(enc_ctx, np->nm3_fh_info);
	}
}

/*
 * Get V3 connection info.
 */
static void
ndmp_connect_get_v3(ndmp_connection_t *connection, ndmp_door_ctx_t *enc_ctx)
{
	ndmpd_session_t *session;

	if ((session = (ndmpd_session_t *)ndmp_get_client_data(connection))) {
		ndmp_connect_get_scsi_v2(session, enc_ctx);
		ndmp_connect_get_tape_v2(session, enc_ctx);
		ndmp_connect_get_mover_v3(session, enc_ctx);
		ndmp_connect_get_data_v3(session, enc_ctx);
	}
}

/*
 * Get the list of all active sessions to the clients.  For each version,
 * call the appropriate get function.
 */
static void
connection_get(struct conn_list *clp, ndmp_door_ctx_t *enc_ctx)
{
	ndmpd_session_t *session;

	session = (ndmpd_session_t *)ndmp_get_client_data(clp->cl_conn);
	if (!session) {
		ndmp_door_put_int32(enc_ctx, NDMP_SESSION_NODATA);
		return;
	}
	ndmp_door_put_int32(enc_ctx, NDMP_SESSION_DATA);

	switch (session->ns_protocol_version) {
	case NDMPV2:
		ndmp_connect_get_conn(clp, enc_ctx);
		ndmp_connect_get_v2(clp->cl_conn, enc_ctx);
		break;
	case NDMPV3:
	case NDMPV4:
		ndmp_connect_get_conn(clp, enc_ctx);
		ndmp_connect_get_v3(clp->cl_conn, enc_ctx);
		break;
	default:
		NDMP_LOG(LOG_DEBUG,
		    "Invalid session (0x%p) version 0x%x", session,
		    session->ns_protocol_version);
	}
}

/*
 * ndmpd_connect_kill
 *
 * Kill the connection based on its version.
 *
 * Parameters:
 *   connection (input) - connection handler.
 *
 * Returns:
 *   0 - success
 *  -1 - error
 */
int
ndmpd_connect_kill(ndmp_connection_t *connection)
{
	ndmpd_session_t *session;

	if (!(session = (ndmpd_session_t *)ndmp_get_client_data(connection)))
		return (-1);

	switch (session->ns_protocol_version) {
	case NDMPV2:
		ndmpd_connect_close_v2(connection, (void *)NULL);
		break;
	case NDMPV3:
	case NDMPV4:
		ndmpd_connect_close_v3(connection, (void *)NULL);
		break;
	default:
		NDMP_LOG(LOG_DEBUG,
		    "Invalid session (0x%p) version 0x%x", session,
		    session->ns_protocol_version);
	}

	return (0);
}

/*
 * Get the list of all active sessions to the clients.
 */
void
ndmp_connect_list_get(ndmp_door_ctx_t *enc_ctx)
{
	int n;
	struct conn_list *clp;

	n = 0;
	(void) mutex_lock(&cl_mutex);
	LIST_FOREACH(clp, &cl_head, cl_q) {
		n++;
	}
	/* write number of connections */
	ndmp_door_put_int32(enc_ctx, n);
	n = 0;
	LIST_FOREACH(clp, &cl_head, cl_q) {
		connection_get(clp, enc_ctx);
		n++;
	}
	(void) mutex_unlock(&cl_mutex);
}

/*
 * ndmpd_connect_kill_id
 *
 * Find a connection by its id and kill it.
 *
 * Parameters:
 *   id (input) - connection id.
 *
 * Returns:
 *   0 - success
 *  -1 - error
 */
int
ndmpd_connect_kill_id(int id)
{
	struct conn_list *clp;

	if (!(clp = ndmp_connect_list_find_id(id)))
		return (-1);

	return (ndmpd_connect_kill(clp->cl_conn));
}

/* Get the devices info */
void
ndmpd_get_devs(ndmp_door_ctx_t *enc_ctx)
{
	int i, n;
	sasd_drive_t *sd;
	scsi_link_t *slink;

	if ((n = sasd_dev_count()) == 0) {
		ndmp_door_put_int32(enc_ctx, n);
		NDMP_LOG(LOG_DEBUG, "No device attached.");
		return;
	}
	ndmp_door_put_int32(enc_ctx, n);

	for (i = 0; i < n; i++) {
		sd = sasd_drive(i);
		slink = sasd_dev_slink(i);

		ndmp_door_put_int32(enc_ctx, slink->sl_type);
		ndmp_door_put_string(enc_ctx, sd->sd_name);
		ndmp_door_put_int32(enc_ctx, slink->sl_lun);
		ndmp_door_put_int32(enc_ctx, slink->sl_sid);
		ndmp_door_put_string(enc_ctx, sd->sd_vendor);
		ndmp_door_put_string(enc_ctx, sd->sd_id);
		ndmp_door_put_string(enc_ctx, sd->sd_rev);
		ndmp_door_put_string(enc_ctx, sd->sd_serial);
		ndmp_door_put_string(enc_ctx, sd->sd_wwn);
	}
}

/*
 * ndmpd_connect_auth_text
 *
 * Checks text authorization.
 *
 * Parameters:
 *   auth_id (input) - user name
 *   auth_password(input) - password
 *
 * Returns:
 *   NDMP_NO_ERR: on success
 *   Other NDMP_ error: invalid user name and password
 */
int
ndmpd_connect_auth_text(char *uname, char *auth_id, char *auth_password)
{
	char *passwd, *dec_passwd;
	int rv;

	if (strcmp(uname, auth_id) != 0) {
		rv = NDMP_NOT_AUTHORIZED_ERR;
	} else {
		passwd = ndmpd_get_prop(NDMP_CLEARTEXT_PASSWORD);
		if (!passwd || !*passwd) {
			rv = NDMP_NOT_AUTHORIZED_ERR;
		} else {
			dec_passwd = ndmp_base64_decode(passwd);
			if (dec_passwd == NULL || *dec_passwd == 0)
				rv = NDMP_NOT_AUTHORIZED_ERR;
			else if (strcmp(auth_password, dec_passwd) != 0)
				rv = NDMP_NOT_AUTHORIZED_ERR;
			else
				rv = NDMP_NO_ERR;

			free(dec_passwd);
		}
	}

	if (rv == NDMP_NO_ERR) {
		NDMP_LOG(LOG_DEBUG, "Authorization granted.");
	} else {
		NDMP_LOG(LOG_ERR, "Authorization denied.");
	}

	return (rv);
}


/*
 * ndmpd_connect_auth_md5
 *
 * Checks MD5 authorization.
 *
 * Parameters:
 *   auth_id (input) - user name
 *   auth_digest(input) - MD5 digest
 * 	This is a 16 bytes digest info which is a MD5 transform of 128 bytes
 * 	message (password + padding + server challenge + password). Server
 * 	challenge is a 64 bytes random string per NDMP session sent out to the
 * 	client on demand (See NDMP_CONFIG_GET_AUTH_ATTR command).
 *
 * Returns:
 *   NDMP_NO_ERR: on success
 *   Other NDMP_ error: invalid user name and password
 */
int
ndmpd_connect_auth_md5(char *uname, char *auth_id, char *auth_digest,
    unsigned char *auth_challenge)
{
	char *passwd, *dec_passwd;
	unsigned char digest[16];
	int rv;

	if (strcmp(uname, auth_id) != 0) {
		rv = NDMP_NOT_AUTHORIZED_ERR;
	} else {
		passwd = ndmpd_get_prop(NDMP_CRAM_MD5_PASSWORD);
		if (passwd == NULL || *passwd == 0) {
			rv = NDMP_NOT_AUTHORIZED_ERR;
		} else {
			dec_passwd = ndmp_base64_decode(passwd);

			if (dec_passwd == NULL || *dec_passwd == 0) {
				rv = NDMP_NOT_AUTHORIZED_ERR;
			} else {
				create_md5_digest(digest, dec_passwd,
				    auth_challenge);
				if (memcmp(digest, auth_digest,
				    sizeof (digest)) != 0) {
					rv = NDMP_NOT_AUTHORIZED_ERR;
				} else {
					rv = NDMP_NO_ERR;
				}
			}
			free(dec_passwd);
		}
	}

	if (rv == NDMP_NO_ERR) {
		NDMP_LOG(LOG_DEBUG, "Authorization granted.");
	} else {
		NDMP_LOG(LOG_ERR, "Authorization denied.");
	}

	return (rv);
}
