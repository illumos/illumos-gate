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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * ldom_xmpp_client.c	Extensible Messaging and Presence Protocol (XMPP)
 *
 * Implement an xmpp client to subscribe for domain events from the ldmd.
 * Notify fmd module clients upon receiving the events.
 *
 */

#include "ldom_xmpp_client.h"
#include "ldom_alloc.h"
#include "ldom_utils.h"

#include <stdio.h>
#include <signal.h>
#include <strings.h>
#include <unistd.h>
#include <errno.h>

#include <netdb.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <libxml/parser.h>
#include <openssl/ssl.h>

typedef enum conn_state {
	CONN_STATE_UNKNOWN,
	CONN_STATE_TLS,
	CONN_STATE_FEATURE,
	CONN_STATE_LDM_INTERFACE,
	CONN_STATE_LDM_EVENT,
	CONN_STATE_DONE,
	CONN_STATE_FAILURE,
	CONN_STATE_MAX
} conn_state_t;

typedef struct xmpp_conn {
	int			fd;
	int			state;
	boolean_t		tls_started;
	SSL			*ssl;
	xmlParserCtxtPtr	parser;
} xmpp_conn_t;

/* Forward declaration */
static int iowrite(xmpp_conn_t *conn, char *buf, int size);
static void start_element(void *state, const xmlChar *name,
	const xmlChar **attrs);
static void end_element(void *state, const xmlChar *name);
static void error_func(void *state, const char *msg, ...);
static void xmpp_close(xmpp_conn_t *conn);
static int start_tls(xmpp_conn_t *conn);
static void handle_ldm_resp(xmpp_conn_t *conn, char *buf, size_t buf_size);
static void handle_ldm_event(xmpp_conn_t *conn, char *buf, size_t buf_size);

static int xmpp_enable = 0;
static int xmpp_notify_pipe[2];
static pthread_t xmpp_tid = 0;
static pthread_mutex_t xmpp_tid_lock = PTHREAD_MUTEX_INITIALIZER;

static client_list_t clt_list = { NULL, NULL, PTHREAD_MUTEX_INITIALIZER };


#define	FUNCTION_ADD(_function, _pointer, _lib, _func_name, _ret)	\
	_function = (_pointer)dlsym(_lib, _func_name);			\
	if (_function == NULL) {					\
		_ret += -1;						\
	}

/*
 * Prototypes and pointers to functions needed from libssl.
 */
typedef void (*SSL_load_error_strings_pt)(void);
typedef int (*SSL_library_init_pt)(void);
typedef SSL_CTX *(*SSL_CTX_new_pt)(const SSL_METHOD *method);
typedef SSL_METHOD *(*SSLv23_client_method_pt)(void);
typedef int (*SSL_write_pt)(SSL *ssl, const void *buf, int num);
typedef int (*SSL_CTX_use_PrivateKey_file_pt)(SSL_CTX *ctx, const char *file,
    int type);
typedef void (*RAND_seed_pt)(const void *buf, int num);
typedef int (*SSL_get_error_pt)(const SSL *ssl, int ret);
typedef long (*ERR_get_error_pt)(void);
typedef char *(*ERR_error_string_pt)(unsigned long e, char *buf);
typedef int (*SSL_connect_pt)(SSL *ssl);
typedef int (*SSL_CTX_use_certificate_chain_file_pt)(SSL_CTX *ctx,
    const char *file);
typedef int (*SSL_set_fd_pt)(SSL *ssl, int fd);
typedef void (*SSL_free_pt)(SSL *ssl);
typedef int (*SSL_read_pt)(SSL *ssl, void *buf, int num);
typedef SSL *(*SSL_new_pt)(SSL_CTX *ctx);
typedef SSL_CTX *(*SSL_get_SSL_CTX_pt)(const SSL *ssl);
typedef void (*SSL_CTX_free_pt)(SSL_CTX *ctx);

static SSL_load_error_strings_pt SSL_load_error_strings_f = NULL;
static SSL_library_init_pt SSL_library_init_f = NULL;
static SSL_CTX_new_pt SSL_CTX_new_f = NULL;
static SSLv23_client_method_pt SSLv23_client_method_f = NULL;
static SSL_write_pt SSL_write_f = NULL;
static SSL_CTX_use_PrivateKey_file_pt SSL_CTX_use_PrivateKey_file_f = NULL;
static RAND_seed_pt RAND_seed_f = NULL;
static SSL_get_error_pt SSL_get_error_f = NULL;
static ERR_get_error_pt ERR_get_error_f = NULL;
static ERR_error_string_pt ERR_error_string_f = NULL;
static SSL_connect_pt SSL_connect_f = NULL;
static SSL_CTX_use_certificate_chain_file_pt
SSL_CTX_use_certificate_chain_file_f = NULL;
static SSL_set_fd_pt SSL_set_fd_f = NULL;
static SSL_free_pt SSL_free_f = NULL;
static SSL_read_pt SSL_read_f = NULL;
static SSL_new_pt SSL_new_f = NULL;
static SSL_get_SSL_CTX_pt SSL_get_SSL_CTX_f = NULL;
static SSL_CTX_free_pt SSL_CTX_free_f = NULL;

static void *xmpp_dl = NULL;

static ldom_event_info_t event_table[] = {
	{ LDOM_EVENT_UNKNOWN, "unknown" },
	{ LDOM_EVENT_ADD, "add-domain" },
	{ LDOM_EVENT_REMOVE, "remove-domain" },
	{ LDOM_EVENT_BIND, "bind-domain" },
	{ LDOM_EVENT_UNBIND, "unbind-domain" },
	{ LDOM_EVENT_START, "start-domain" },
	{ LDOM_EVENT_STOP, "stop-domain" },
	{ LDOM_EVENT_RESET, "domain-reset" },
	{ LDOM_EVENT_PANIC, "panic-domain" },
	{ LDOM_EVENT_MAX, NULL }
};
static int event_table_size = \
		sizeof (event_table) / sizeof (ldom_event_info_t);

static xmlSAXHandler xml_handler = {
	NULL,		/* internalSubsetSAXFunc */
	NULL,		/* isStandaloneSAXFunc */
	NULL,		/* hasInternalSubsetSAXFunc */
	NULL,		/* hasExternalSubsetSAXFunc */
	NULL,		/* resolveEntitySAXFunc */
	NULL,		/* getEntitySAXFunc */
	NULL,		/* entityDeclSAXFunc */
	NULL,		/* notationDeclSAXFunc */
	NULL,		/* attributeDeclSAXFunc */
	NULL,		/* elementDeclSAXFunc */
	NULL,		/* unparsedEntityDeclSAXFunc */
	NULL,		/* setDocumentLocatorSAXFunc */
	NULL,		/* startDocumentSAXFunc */
	NULL,		/* endDocumentSAXFunc */
	start_element,	/* startElementSAXFunc */
	end_element,	/* endElementSAXFunc */
	NULL,		/* referenceSAXFunc */
	NULL,		/* charactersSAXFunc */
	NULL,		/* ignorableWhitespaceSAXFunc */
	NULL,		/* processingInstructionSAXFunc */
	NULL,		/* commentSAXFunc */
	NULL,		/* warningSAXFunc */
	error_func,	/* errorSAXFunc */
	NULL,		/* fatalErrorSAXFunc */
	NULL,		/* getParameterEntitySAXFunc */
	NULL,		/* cdataBlockSAXFunc */
	NULL,		/* externalSubsetSAXFunc */
	0,		/* unsigned int */
	NULL,		/* void * _private */
	NULL,		/* startElementNsSAX2Func */
	NULL,		/* endElementNsSAX2Func */
	NULL		/* xmlStructuredErrorFunc */
};

static void
end_element(void *state, const xmlChar *name)
{
	xmpp_conn_t	*conn = (xmpp_conn_t *)state;

	if (xmlStrcmp(name, STREAM_NODE) == 0) {
		conn->state = CONN_STATE_DONE;
	} else if (xmlStrcmp(name, STARTTLS_NODE) == 0) {
		(void) iowrite(conn, START_TLS, strlen(START_TLS));
	} else if (xmlStrcmp(name, PROCEED_NODE) == 0) {
		if (start_tls(conn)) {
			conn->state = CONN_STATE_FAILURE;
		}
	} else if (xmlStrcmp(name, FEATURE_NODE) == 0) {
		if (conn->state == CONN_STATE_TLS) {
			conn->state = CONN_STATE_FEATURE;
			(void) iowrite(conn, (char *)LDM_REG_DOMAIN_EVENTS,
			    strlen((char *)LDM_REG_DOMAIN_EVENTS));
		}
	} else if (xmlStrcmp(name, XML_LDM_INTERFACE) == 0) {
		conn->state = CONN_STATE_LDM_INTERFACE;
	} else if (xmlStrcmp(name, XML_LDM_EVENT) == 0) {
		conn->state = CONN_STATE_LDM_EVENT;
	} else if (xmlStrcmp(name, XML_FAILURE) == 0) {
		conn->state = CONN_STATE_FAILURE;
	}
}

/*ARGSUSED*/
static void
start_element(void *state, const xmlChar *name, const xmlChar **attrs)
{
}

/*ARGSUSED*/
static void
error_func(void *state, const char *msg, ...)
{
}

static int
xmpp_connect(xmpp_conn_t *conn)
{
	int sock;
	struct sockaddr_in serveraddr;

	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		return (-1);
	}

	serveraddr.sin_family = AF_INET;
	serveraddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	serveraddr.sin_port = htons(XMPP_DEFAULT_PORT);
	if (connect(sock, (struct sockaddr *)(&serveraddr),
	    sizeof (struct sockaddr_in)) < 0) {
		return (-1);
	}

	(void) bzero(conn, sizeof (xmpp_conn_t));
	conn->fd = sock;
	conn->tls_started = B_FALSE;

	conn->parser = xmlCreatePushParserCtxt(&xml_handler, (void *) conn,
	    NULL, 0, NULL);
	if (conn->parser == NULL) {
		return (-1);
	}

	return (0);
}

static void
xmpp_close(xmpp_conn_t *conn)
{
	(void) close(conn->fd);
	conn->fd = -1;
	conn->state = CONN_STATE_UNKNOWN;
	if (conn->parser != NULL) {
		xmlFreeParserCtxt(conn->parser);
		conn->parser = NULL;
	}
	if (conn->tls_started) {
		SSL_free_f(conn->ssl);
		conn->ssl = NULL;
	}
	conn->tls_started = B_FALSE;
}

static int
ioread(xmpp_conn_t *conn, char *buf, int size)
{
	int count;
	if (conn->tls_started) {
		count = SSL_read_f(conn->ssl, buf, size);
	} else {
		count = read(conn->fd, buf, size);
	}
	if (count <= 0) {
		conn->state = CONN_STATE_FAILURE;
	}

	return (count);
}

static int
iowrite(xmpp_conn_t *conn, char *buf, int size)
{
	int count;

	if (conn->tls_started) {
		count = SSL_write_f(conn->ssl, buf, size);
	} else {
		count = send(conn->fd, buf, size, 0);
	}
	if (count <= 0) {
		conn->state = CONN_STATE_FAILURE;
	}

	return (count);
}

/*
 * notify_event()
 * Description:
 *     Notify all clients an event by going through the client list and invoke
 *     the callback functions.
 */
static void
notify_event(ldom_event_t event, char *ldom_name)
{
	client_info_t *p;

	(void) pthread_mutex_lock(&clt_list.lock);

	for (p = clt_list.head; p != NULL; p = p->next) {
		p->cb(ldom_name, event, p->data);
	}

	(void) pthread_mutex_unlock(&clt_list.lock);
}

/*
 * xmpp_client_thr()
 * Description:
 *     The main entry fo the xmpp client thread.
 */
/*ARGSUSED*/
static void *
xmpp_client_thr(void *data)
{
	int rc = 0;
	int cnt;
	char buf[XMPP_BUF_SIZE];
	xmpp_conn_t conn;
	pollfd_t pollfd[2];
	struct pollfd *pipe_fd = &pollfd[0];
	struct pollfd *recv_fd = &pollfd[1];

	while (xmpp_enable) {
		/* clear the conn struct */
		bzero(&conn, sizeof (xmpp_conn_t));

		/* keep making a connection until successfully */
		do {
			if (rc = xmpp_connect(&conn))
				(void) sleep(XMPP_SLEEP);
		} while (rc != 0 && xmpp_enable);

		/* write the stream node */
		cnt = iowrite(&conn, (char *)STREAM_START,
		    strlen((char *)STREAM_START));
		if (cnt != strlen((char *)STREAM_START)) {
			xmpp_close(&conn);
			(void) sleep(XMPP_SLEEP);
			continue;
		}

		pipe_fd->fd = xmpp_notify_pipe[1];	/* notification pipe */
		pipe_fd->events = POLLIN;
		recv_fd->fd = conn.fd;			/* XMPP connection */
		recv_fd->events = POLLIN;

		/* process input */
		while ((conn.state != CONN_STATE_FAILURE) &&
		    (conn.state != CONN_STATE_DONE) && xmpp_enable) {

			/* Wait for xmpp input or the notification */
			pipe_fd->revents = 0;
			recv_fd->revents = 0;
			if (poll(pollfd, 2, -1) <= 0) {
				break;
			} else if (pipe_fd->revents & POLLIN) {
				/* Receive a notification to exit */
				xmpp_close(&conn);
				pthread_exit((void *)NULL);
			}

			/*
			 * Assume the document size of a ldmd response is
			 * less than 1KB. This assumption is valid with the
			 * current ldmd implementation.
			 * Should the document size exceeds 1KB, the buffer
			 * size should be revisited accordingly.
			 */
			(void) memset(buf, 0, XMPP_BUF_SIZE);
			cnt = ioread(&conn, buf, XMPP_BUF_SIZE);
			if (cnt <= 0)
				break;
			if (rc = xmlParseChunk(conn.parser, buf, cnt, 0)) {
				conn.state = CONN_STATE_FAILURE;
			}

			switch (conn.state) {
			case CONN_STATE_LDM_INTERFACE:
				handle_ldm_resp(&conn, buf, cnt);
				break;
			case CONN_STATE_LDM_EVENT:
				handle_ldm_event(&conn, buf, cnt);
				break;
			default:
				break;
			}

			/*
			 * For now, the parser is reset after every read.
			 * It should only be reset once after the ssl is opened
			 * in the start_tls().
			 */
			(void) xmlCtxtResetPush(conn.parser, NULL, 0, NULL,
			    NULL);
		}
		xmpp_close(&conn);
		(void) sleep(XMPP_SLEEP);
	}
	return (NULL);
}

/*
 * find_client()
 * Description:
 *     Walk to the list to find a libldom client
 */
static client_info_t *
find_client(ldom_hdl_t *lhp)
{
	client_info_t *p;

	for (p = clt_list.head; p != NULL; p = p->next) {
		if (p->lhp == lhp)
			return (p);
	}

	return (NULL);
}

/*
 * xmpp_add_client()
 * Description:
 *     Add a libldom client from the client list.
 */
int
xmpp_add_client(ldom_hdl_t *lhp, ldom_reg_cb_t cb, ldom_cb_arg_t data)
{
	client_info_t *clt;

	(void) pthread_mutex_lock(&clt_list.lock);
	if (find_client(lhp)) {
		/* already exists */
		(void) pthread_mutex_unlock(&clt_list.lock);
		return (-1);
	}

	/* new client */
	clt = (client_info_t *)ldom_alloc(sizeof (client_info_t));
	clt->lhp = lhp;
	clt->cb = cb;
	clt->data = data;
	clt->next = NULL;
	clt->prev = NULL;

	if (clt_list.head == NULL && clt_list.tail == NULL) {
		clt_list.head = clt;
		clt_list.tail = clt;
	} else {
		/* append to the list */
		clt->prev = clt_list.tail;
		clt_list.tail->next  = clt;
		clt_list.tail = clt;
	}

	(void) pthread_mutex_unlock(&clt_list.lock);
	return (0);
}

/*
 * xmpp_remove_client()
 * Description:
 *     Remove a libldom client from the client list.
 */
int
xmpp_remove_client(ldom_hdl_t *lhp)
{
	client_info_t *p;

	(void) pthread_mutex_lock(&clt_list.lock);
	if ((p = find_client(lhp)) == NULL) {
		/* not present */
		(void) pthread_mutex_unlock(&clt_list.lock);
		return (-1);
	}

	if (clt_list.head == p && clt_list.tail == p) {
		/* single item list */
		clt_list.head = NULL;
		clt_list.tail = NULL;
	} else if (clt_list.head == p) {
		/* delete the head */
		clt_list.head = p->next;
		clt_list.head->prev = NULL;
	} else if (clt_list.tail == p) {
		/* delete the tail */
		clt_list.tail = p->prev;
		clt_list.tail->next = NULL;
	} else {
		/* delete a middle node */
		p->next->prev = p->prev;
		p->prev->next = p->next;
	}
	ldom_free(p, sizeof (client_info_t));

	(void) pthread_mutex_unlock(&clt_list.lock);
	return (0);
}

/*
 * xmpp_stop()
 * Description:
 *     Stop the xmpp client thread
 */
/*ARGSUSED*/
void
xmpp_stop(void)
{
	(void) pthread_mutex_lock(&xmpp_tid_lock);
	xmpp_enable = 0;
	if (xmpp_tid) {
		/*
		 * Write a byte to the pipe to notify the xmpp thread to exit.
		 * Then wait for it to exit.
		 */
		(void) write(xmpp_notify_pipe[0], "1", 1);
		(void) pthread_join(xmpp_tid, NULL);
		xmpp_tid = 0;
	}
	(void) pthread_mutex_unlock(&xmpp_tid_lock);
}

/*
 * xmpp_start()
 * Description:
 *     Start the xmpp client thread if have not done so.
 */
void
xmpp_start(void)
{
	xmpp_conn_t conn;

	/* Check if the xmmp thread has already started */
	(void) pthread_mutex_lock(&xmpp_tid_lock);
	if (xmpp_tid != 0) {
		(void) pthread_mutex_unlock(&xmpp_tid_lock);
		return;
	}

	/* Check if the ldmd supports xmpp by opening a connection */
	if (xmpp_connect(&conn)) {
		(void) pthread_mutex_unlock(&xmpp_tid_lock);
		return;
	}
	xmpp_close(&conn);
	xmpp_enable = 1;

	/*
	 * create xmpp client thread for receiving domain events.
	 * The notification pipe is for stopping the thread.
	 */
	(void) notify_setup(xmpp_notify_pipe);
	(void) pthread_create(&xmpp_tid, NULL, xmpp_client_thr, NULL);

	(void) pthread_mutex_unlock(&xmpp_tid_lock);

	/*
	 * Register a function to stop the above thread upon a termination
	 */
	(void) atexit(xmpp_stop);
}

/*
 * This routine will run through the first time we get a remote XMPP
 * connection. After that we will not need to do this again. It cannot be run
 * from main thread at start as we need to alert remote users if the TLS
 * handshake failed.
 */
static int
load_SSL_lib()
{
	int ret = 0;

	/* If we have already opened the library no need to do it again. */
	if (xmpp_dl != NULL)
		return (0);

	/*
	 * If the libssl.so in not in the default path, attempt to open it
	 * under /usr/sfw/lib.
	 */
	xmpp_dl = dlopen("libssl.so", RTLD_NOW);
	if (xmpp_dl == NULL) {
		xmpp_dl = dlopen("/usr/sfw/lib/libssl.so", RTLD_NOW);
		if (xmpp_dl == NULL)
			return (-1);
	}

	FUNCTION_ADD(SSL_load_error_strings_f, SSL_load_error_strings_pt,
	    xmpp_dl, "SSL_load_error_strings", ret);
	FUNCTION_ADD(SSL_library_init_f, SSL_library_init_pt, xmpp_dl,
	    "SSL_library_init", ret);
	FUNCTION_ADD(SSL_CTX_new_f, SSL_CTX_new_pt, xmpp_dl,
	    "SSL_CTX_new", ret);
	FUNCTION_ADD(SSLv23_client_method_f, SSLv23_client_method_pt, xmpp_dl,
	    "SSLv23_client_method", ret);
	FUNCTION_ADD(SSL_write_f, SSL_write_pt, xmpp_dl, "SSL_write", ret);
	FUNCTION_ADD(SSL_CTX_use_PrivateKey_file_f,
	    SSL_CTX_use_PrivateKey_file_pt, xmpp_dl,
	    "SSL_CTX_use_PrivateKey_file", ret);
	FUNCTION_ADD(RAND_seed_f, RAND_seed_pt, xmpp_dl, "RAND_seed", ret);
	FUNCTION_ADD(SSL_get_error_f, SSL_get_error_pt, xmpp_dl,
	    "SSL_get_error", ret);
	FUNCTION_ADD(ERR_get_error_f, ERR_get_error_pt, xmpp_dl,
	    "ERR_get_error", ret);
	FUNCTION_ADD(ERR_error_string_f, ERR_error_string_pt, xmpp_dl,
	    "ERR_error_string", ret);
	FUNCTION_ADD(SSL_connect_f, SSL_connect_pt, xmpp_dl, "SSL_connect",
	    ret);
	FUNCTION_ADD(SSL_CTX_use_certificate_chain_file_f,
	    SSL_CTX_use_certificate_chain_file_pt, xmpp_dl,
	    "SSL_CTX_use_certificate_chain_file", ret);
	FUNCTION_ADD(SSL_set_fd_f, SSL_set_fd_pt, xmpp_dl, "SSL_set_fd", ret);
	FUNCTION_ADD(SSL_free_f, SSL_free_pt, xmpp_dl, "SSL_free", ret);
	FUNCTION_ADD(SSL_read_f, SSL_read_pt, xmpp_dl, "SSL_read", ret);
	FUNCTION_ADD(SSL_new_f, SSL_new_pt, xmpp_dl, "SSL_new", ret);
	FUNCTION_ADD(SSL_get_SSL_CTX_f, SSL_get_SSL_CTX_pt, xmpp_dl,
	    "SSL_get_SSL_CTX", ret);
	FUNCTION_ADD(SSL_CTX_free_f, SSL_CTX_free_pt, xmpp_dl,
	    "SSL_CTX_free", ret);

	if (ret < 0)
		return (-1);
	else
		return (0);
}

/*
 * start_tls()
 * Description:
 *     Load the libssl.so if has not done so and open a ssl connection.
 *     It is assumed that there is one xmpp thread to use the ssl connection.
 *     If multi-thread xmpp clients use the ssl connection, addtional work is
 *     needed to ensure the usage of the ssl be thread-safe.
 */
static int
start_tls(xmpp_conn_t *conn)
{
	int		rv, urand_fd;
	SSL_CTX		*ssl_ctx;
	char		rand_buf[RAND_BUF_SIZE];

	rv = load_SSL_lib();
	if (rv == -1) {
		return (rv);
	}

	urand_fd = open("/dev/random", O_RDONLY);
	if (urand_fd == -1) {
		return (-1);
	}
	(void) read(urand_fd, rand_buf, RAND_BUF_SIZE);

	SSL_library_init_f();
	RAND_seed_f(rand_buf, RAND_BUF_SIZE);

	ssl_ctx = SSL_CTX_new_f(SSLv23_client_method_f());
	if (ssl_ctx == NULL) {
		return (-1);
	}
	conn->ssl = SSL_new_f(ssl_ctx);
	rv = SSL_set_fd_f(conn->ssl, conn->fd);
	if (rv == 0) {
		return (-1);
	}
	rv = SSL_connect_f(conn->ssl);
	if (rv != 1) {
		return (-1);
	}
	conn->tls_started = B_TRUE;
	conn->state = CONN_STATE_TLS;

	(void) iowrite(conn, STREAM_START, strlen(STREAM_START));

	return (0);
}

/*
 * Find and return the first-level subnode (if any) of 'node' which has name
 * 'name'.
 */
xmlNodePtr
xml_find_subnode(xmlNodePtr node, const xmlChar *name)
{
	xmlNodePtr subnode;

	if (node == NULL)
		return (NULL);

	subnode = node->xmlChildrenNode;
	while (subnode != NULL) {
		if (((char *)subnode->name != NULL) &&
		    (xmlStrcmp(subnode->name, name) == 0))
			break;
		subnode = subnode->next;
	}

	return (subnode);
}

/*
 * handle_ldm_resp()
 * Description:
 *     Parse the ldmd response of the domain event registration for the failure
 *     status. If found, set the connection to failure so that it will be
 *     closed and a new xmpp connection is established.
 */
void
handle_ldm_resp(xmpp_conn_t *conn, char *buf, size_t buf_size)
{
	xmlDocPtr	xml_output;
	xmlNodePtr	root, resp, status, cmd, action;
	char		*status_str, *action_str;

	if ((xml_output = xmlParseMemory((const char *)buf, buf_size)) == NULL)
		return;
	if ((root = xmlDocGetRootElement(xml_output)) == NULL)
		return;

	/* get the cmd node */
	if ((cmd = xml_find_subnode(root, XML_CMD)) == NULL)
		return;
	if (strcmp((char *)cmd->name, (char *)XML_CMD) != 0)
		return;

	/* get the action node and make sure it is the reg-domain-events */
	if ((action = xml_find_subnode(cmd, XML_ACTION)) == NULL) {
		return;
	}
	if ((action_str = (char *)xmlNodeGetContent(action)) == NULL)
		return;
	if (strcmp(action_str, XML_REGISTER_ACTION) != 0) {
		xmlFree(action_str);
		return;
	}
	xmlFree(action_str);

	/* check the status of the response */
	if ((resp = xml_find_subnode(cmd, XML_RESPONSE)) == NULL)
		return;
	if ((status = xml_find_subnode(resp, XML_STATUS)) == NULL)
		return;
	if ((status_str = (char *)xmlNodeGetContent(status)) == NULL)
		return;
	if (strcmp(status_str, (char *)XML_FAILURE) == 0) {
		conn->state = CONN_STATE_FAILURE;
	}
	xmlFree(status_str);
}

/*
 * handle_ldm_event()
 * Description:
 *     Parse the LDM_event for the ldom name and domain action. Then invokes
 *     the clients's callback to notify them the event.
 */
/*ARGSUSED*/
void
handle_ldm_event(xmpp_conn_t *conn, char *buf, size_t buf_size)
{
	int		i;
	xmlDocPtr	xml_output;
	xmlNodePtr	root, cmd, action, data, envelope, content;
	char		*action_str, *ldom_name;
	ldom_event_t	event = LDOM_EVENT_UNKNOWN;

	if ((xml_output = xmlParseMemory((const char *)buf, buf_size)) == NULL)
		return;
	if ((root = xmlDocGetRootElement(xml_output)) == NULL)
		return;

	/* get the action such as bind-domain, unbind-domain, etc. */
	if ((cmd = xml_find_subnode(root, XML_CMD)) == NULL)
		return;
	if ((action = xml_find_subnode(cmd, XML_ACTION)) == NULL) {
		return;
	}
	if ((action_str = (char *)xmlNodeGetContent(action)) == NULL)
		return;
	for (i = 0; i < event_table_size; i++) {
		if (event_table[i].name != NULL &&
		    strcasecmp(event_table[i].name, action_str) == 0) {
			event = event_table[i].id;
			break;
		}
	}
	xmlFree(action_str);

	/* get the ldom name */
	data = xml_find_subnode(cmd, XML_DATA);
	envelope = xml_find_subnode(data, XML_ENVELOPE);
	content = xml_find_subnode(envelope, XML_CONTENT);
	if ((ldom_name = (char *)xmlGetProp(content, XML_ATTR_ID)) == NULL)
		return;

	/* Notifies all the clients the event */
	if (VALID_LDOM_EVENT(event)) {
		notify_event(event, ldom_name);
	}

	xmlFree(ldom_name);
}
