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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * transport layer for audit_remote (handles connection establishment, gss
 * context initialization, message encryption and verification)
 *
 */

#include <assert.h>
#include <audit_plugin.h>
#include <errno.h>
#include <fcntl.h>
#include <gssapi/gssapi.h>
#include <libintl.h>
#include <mtmalloc.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <poll.h>
#include <pthread.h>

#include "audit_remote.h"


static int		sockfd = -1;
static struct hostent	*current_host;
static gss_OID		*current_mech_oid;
static in_port_t	current_port;
static boolean_t	flush_transq;

static char		*ver_str = "01";	/* supported protocol version */
static char		*ver_str_concat;	/* concat serv/client version */

static gss_ctx_id_t	gss_ctx;
static boolean_t	gss_ctx_initialized;

pthread_t		recv_tid;		/* receiving thread */
static pthread_once_t	recv_once_control = PTHREAD_ONCE_INIT;

extern int		timeout;		/* connection timeout */

extern pthread_mutex_t	plugin_mutex;
transq_hdr_t		transq_hdr;

/*
 * The three locks synchronize the simultaneous actions on top of transmission
 * queue, socket, gss_context.
 */
pthread_mutex_t		transq_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t		sock_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t		gss_ctx_lock = PTHREAD_MUTEX_INITIALIZER;

/* reset routine synchronization - required by the sending thread */
pthread_mutex_t		reset_lock = PTHREAD_MUTEX_INITIALIZER;
static boolean_t	reset_in_progress;	/* reset routine in progress */

#define	NP_CLOSE	-1		/* notification pipe - close message */
#define	NP_EXIT		-2		/* notification pipe - exit message */
boolean_t		notify_pipe_ready;
int			notify_pipe[2]; /* notif. pipe - receiving thread */

pthread_cond_t		reset_cv = PTHREAD_COND_INITIALIZER;
static close_rsn_t	recv_closure_rsn;

#define	MAX_TOK_LEN	(128 * 1000)	/* max token length we accept (B) */

/* transmission queue helpers */
static void		transq_dequeue(transq_node_t *);
static boolean_t	transq_enqueue(transq_node_t **, gss_buffer_t,
    uint64_t);
static int		transq_retransmit(void);

static boolean_t	init_poll(int);
static void		do_reset(int *, struct pollfd *, boolean_t);
static void		do_cleanup(int *, struct pollfd *, boolean_t);

static void		init_recv_record(void);
static void		*recv_record(void *);
static int		connect_timeout(int, struct sockaddr *, int);
static int		send_timeout(int, const char *, size_t);
static int		recv_timeout(int, char *, size_t);
static int		send_token(int *, gss_buffer_t);
static int		recv_token(int, gss_buffer_t);


/*
 * report_err() - wrapper, mainly due to enhance the code readability - report
 * error to syslog via call to __audit_syslog().
 */
static void
report_err(char *msg)
{
	__audit_syslog("audit_remote.so", LOG_CONS | LOG_NDELAY, LOG_DAEMON,
	    LOG_ERR, msg);

}


/*
 * report_gss_err() - GSS API error reporting
 */
static void
report_gss_err(char *msg, OM_uint32 maj_stat, OM_uint32 min_stat)
{
	gss_buffer_desc	msg_buf;
	OM_uint32	_min, msg_ctx;
	char		*err_msg;

	/* major stat */
	msg_ctx = 0;
	do {
		(void) gss_display_status(&_min, maj_stat, GSS_C_GSS_CODE,
		    *current_mech_oid, &msg_ctx, &msg_buf);
		(void) asprintf(&err_msg,
		    gettext("GSS API error - %s(%u): %.*s\n"), msg, maj_stat,
		    msg_buf.length, (char *)msg_buf.value);
		if (err_msg != NULL) {
			report_err(err_msg);
			free(err_msg);
		}
		(void) gss_release_buffer(&_min, &msg_buf);
	} while (msg_ctx);

	/* minor stat */
	msg_ctx = 0;
	do {
		(void) gss_display_status(&_min, min_stat, GSS_C_MECH_CODE,
		    *current_mech_oid, &msg_ctx, &msg_buf);
		(void) asprintf(&err_msg,
		    gettext("GSS mech error - %s(%u): %.*s\n"), msg, min_stat,
		    msg_buf.length, (char *)msg_buf.value);
		if (err_msg != NULL) {
			report_err(err_msg);
			free(err_msg);
		}
		(void) gss_release_buffer(&_min, &msg_buf);
	} while (msg_ctx);
}

/*
 * prot_ver_negotiate() - negotiate/acknowledge the protocol version. Currently,
 * there is only one version supported by the plugin - "01".
 * Note: connection must be initiated prior version negotiation
 */
static int
prot_ver_negotiate()
{
	gss_buffer_desc	out_buf, in_buf;
	size_t		ver_str_concat_sz;

	/*
	 * Set the version proposal string - once we support more than
	 * version "01" this part should be extended to solve the concatenation
	 * of supported version identifiers.
	 */
	out_buf.value = (void *)ver_str;
	out_buf.length = strlen((char *)out_buf.value);
	DPRINT((dfile, "Protocol version proposal (size=%d): %.*s\n",
	    out_buf.length, out_buf.length, (char *)out_buf.value));

	if (send_token(&sockfd, &out_buf) < 0) {
		DPRINT((dfile, "Sending protocol version token failed\n"));
		return (-1);
	}

	if (recv_token(sockfd, &in_buf) < 0) {
		DPRINT((dfile, "Receiving protocol version token failed\n"));
		return (-1);
	}

	/*
	 * Verify the sent/received string - memcmp() is sufficient here
	 * because we support only one version and it is represented by
	 * the "01" string. The received version has to be "01" string as well.
	 */
	if (out_buf.length != in_buf.length ||
	    memcmp(out_buf.value, in_buf.value, out_buf.length) != 0) {
		DPRINT((dfile, "Verification of the protocol version strings "
		    "failed [%d:%s][%d:%s]\n", out_buf.length,
		    (char *)out_buf.value, in_buf.length,
		    (char *)in_buf.value));
		free(in_buf.value);
		return (-1);
	}

	/*
	 * Prepare the concatenated client/server version strings later used
	 * as an application_data field in the gss_channel_bindings_struct
	 * structure.
	 */
	ver_str_concat_sz = out_buf.length + in_buf.length + 1;
	ver_str_concat = (char *)calloc(1, ver_str_concat_sz);
	if (ver_str_concat == NULL) {
		report_err(gettext("Memory allocation failed"));
		DPRINT((dfile, "Memory allocation failed: %s\n",
		    strerror(errno)));
		free(in_buf.value);
		return (-1);
	}
	(void) memcpy(ver_str_concat, out_buf.value, out_buf.length);
	(void) memcpy(ver_str_concat + out_buf.length, in_buf.value,
	    in_buf.length);
	DPRINT((dfile, "Concatenated version strings: %s\n", ver_str_concat));

	DPRINT((dfile, "Protocol version agreed.\n"));
	free(in_buf.value);
	return (0);
}

/*
 * sock_prepare() - creates and connects socket. Function returns
 * B_FALSE/B_TRUE on failure/success and sets the err_rsn accordingly to the
 * reason of failure.
 */
static boolean_t
sock_prepare(int *sockfdptr, struct hostent *host, close_rsn_t *err_rsn)
{
	struct sockaddr_storage	addr;
	struct sockaddr_in	*sin;
	struct sockaddr_in6	*sin6;
	size_t			addr_len;
	int			sock;

	DPRINT((dfile, "Creating socket for %s\n", host->h_name));
	bzero(&addr, sizeof (addr));
	addr.ss_family = host->h_addrtype;
	switch (host->h_addrtype) {
	case AF_INET:
		sin = (struct sockaddr_in *)&addr;
		addr_len = sizeof (struct sockaddr_in);
		bcopy(host->h_addr_list[0],
		    &(sin->sin_addr), sizeof (struct in_addr));
		sin->sin_port = current_port;
		break;
	case AF_INET6:
		sin6 = (struct sockaddr_in6 *)&addr;
		addr_len = sizeof (struct sockaddr_in6);
		bcopy(host->h_addr_list[0],
		    &(sin6->sin6_addr), sizeof (struct in6_addr));
		sin6->sin6_port = current_port;
		break;
	default:
		/* unknown address family */
		*err_rsn = RSN_UNKNOWN_AF;
		return (B_FALSE);
	}
	if ((sock = socket(addr.ss_family, SOCK_STREAM, 0)) == -1) {
		*err_rsn = RSN_SOCKET_CREATE;
		return (B_FALSE);
	}
	DPRINT((dfile, "Socket created, fd=%d, connecting..\n", sock));

	if (connect_timeout(sock, (struct sockaddr *)&addr, addr_len)) {
		(void) close(sock);
		*err_rsn = RSN_CONNECTION_CREATE;
		return (B_FALSE);
	}
	*sockfdptr = sock;
	DPRINT((dfile, "Connected to %s via fd=%d\n", host->h_name,
	    *sockfdptr));

	return (B_TRUE);
}

/*
 * establish_context() - establish the client/server GSS context.
 *
 * Note: connection must be established and version negotiated (in plain text)
 * prior to establishing context.
 */
static int
establish_context()
{
	gss_buffer_desc				send_tok, recv_tok, *token_ptr;
	OM_uint32				maj_stat, min_stat;
	OM_uint32				init_sec_min_stat, ret_flags;
	gss_name_t				gss_name;
	char					*gss_svc_name = "audit";
	char					*svc_name;
	struct gss_channel_bindings_struct	input_chan_bindings;

	/* GSS service name = gss_svc_name + "@" + remote hostname (fqdn) */
	(void) asprintf(&svc_name, "%s@%s", gss_svc_name, current_host->h_name);
	if (svc_name == NULL) {
		report_err(gettext("Cannot allocate service name\n"));
		DPRINT((dfile, "Memory allocation failed: %s\n",
		    strerror(errno)));
		return (-1);
	}
	DPRINT((dfile, "Service name: %s\n", svc_name));

	send_tok.value = svc_name;
	send_tok.length = strlen(svc_name);
	maj_stat = gss_import_name(&min_stat, &send_tok,
	    (gss_OID)GSS_C_NT_HOSTBASED_SERVICE, &gss_name);
	if (maj_stat != GSS_S_COMPLETE) {
		report_gss_err(gettext("initializing context"), maj_stat,
		    min_stat);
		free(svc_name);
		return (-1);
	}
	token_ptr = GSS_C_NO_BUFFER;
	gss_ctx = GSS_C_NO_CONTEXT;

	/* initialize channel binding */
	bzero(&input_chan_bindings, sizeof (input_chan_bindings));
	input_chan_bindings.initiator_addrtype = GSS_C_AF_NULLADDR;
	input_chan_bindings.acceptor_addrtype = GSS_C_AF_NULLADDR;
	input_chan_bindings.application_data.length = strlen(ver_str_concat);
	input_chan_bindings.application_data.value = ver_str_concat;

	(void) pthread_mutex_lock(&gss_ctx_lock);
	do {
		maj_stat = gss_init_sec_context(&init_sec_min_stat,
		    GSS_C_NO_CREDENTIAL, &gss_ctx, gss_name, *current_mech_oid,
		    GSS_C_MUTUAL_FLAG | GSS_C_REPLAY_FLAG | GSS_C_SEQUENCE_FLAG
		    | GSS_C_CONF_FLAG, 0, &input_chan_bindings, token_ptr,
		    NULL, &send_tok, &ret_flags, NULL);

		if (token_ptr != GSS_C_NO_BUFFER) {
			(void) gss_release_buffer(&min_stat, &recv_tok);
		}

		if (send_tok.length != 0) {
			DPRINT((dfile,
			    "Sending init_sec_context token (size=%d)\n",
			    send_tok.length));
			if (send_token(&sockfd, &send_tok) < 0) {
				free(svc_name);
				(void) gss_release_name(&min_stat, &gss_name);
				(void) pthread_mutex_unlock(&gss_ctx_lock);
				return (-1);
			}
		}
		if (send_tok.value != NULL) {
			free(send_tok.value);	/* freeing svc_name */
			send_tok.value = NULL;
			send_tok.length = 0;
		}

		if (maj_stat != GSS_S_COMPLETE &&
		    maj_stat != GSS_S_CONTINUE_NEEDED) {
			report_gss_err(gettext("initializing context"),
			    maj_stat, init_sec_min_stat);
			if (gss_ctx == GSS_C_NO_CONTEXT) {
				(void) gss_delete_sec_context(&min_stat,
				    &gss_ctx, GSS_C_NO_BUFFER);
			}
			(void) gss_release_name(&min_stat, &gss_name);
			(void) pthread_mutex_unlock(&gss_ctx_lock);
			return (-1);
		}

		if (maj_stat == GSS_S_CONTINUE_NEEDED) {
			DPRINT((dfile, "continue needed... "));
			if (recv_token(sockfd, &recv_tok) < 0) {
				(void) gss_release_name(&min_stat, &gss_name);
				(void) pthread_mutex_unlock(&gss_ctx_lock);
				return (-1);
			}
			token_ptr = &recv_tok;
		}
	} while (maj_stat == GSS_S_CONTINUE_NEEDED);
	(void) gss_release_name(&min_stat, &gss_name);

	DPRINT((dfile, "context established\n"));
	(void) pthread_mutex_unlock(&gss_ctx_lock);
	return (0);
}

/*
 * delete_context() - release GSS context.
 */
static void
delete_context()
{
	OM_uint32	min_stat;

	(void) gss_delete_sec_context(&min_stat, &gss_ctx, GSS_C_NO_BUFFER);
	DPRINT((dfile, "context deleted\n"));
}

/*
 * send_token() - send GSS token over the wire.
 */
static int
send_token(int *fdptr, gss_buffer_t tok)
{
	uint32_t	len;
	uint32_t	lensz;
	char		*out_buf;
	int		fd;

	(void) pthread_mutex_lock(&sock_lock);
	if (*fdptr == -1) {
		(void) pthread_mutex_unlock(&sock_lock);
		DPRINT((dfile, "Socket detected as closed.\n"));
		return (-1);
	}
	fd = *fdptr;

	len = htonl(tok->length);
	lensz = sizeof (len);

	out_buf = (char *)malloc((size_t)(lensz + tok->length));
	if (out_buf == NULL) {
		(void) pthread_mutex_unlock(&sock_lock);
		report_err(gettext("Memory allocation failed"));
		DPRINT((dfile, "Memory allocation failed: %s\n",
		    strerror(errno)));
		return (-1);
	}
	(void) memcpy((void *)out_buf, (void *)&len, lensz);
	(void) memcpy((void *)(out_buf + lensz), (void *)tok->value,
	    tok->length);

	if (send_timeout(fd, out_buf, (lensz + tok->length))) {
		(void) pthread_mutex_unlock(&sock_lock);
		free(out_buf);
		return (-1);
	}

	(void) pthread_mutex_unlock(&sock_lock);
	free(out_buf);
	return (0);
}


/*
 * recv_token() - receive GSS token over the wire.
 */
static int
recv_token(int fd, gss_buffer_t tok)
{
	uint32_t	len;

	if (recv_timeout(fd, (char *)&len, sizeof (len))) {
		return (-1);
	}
	len = ntohl(len);

	/* simple DOS prevention mechanism */
	if (len > MAX_TOK_LEN) {
		report_err(gettext("Indicated invalid token length"));
		DPRINT((dfile, "Indicated token length > %dB\n", MAX_TOK_LEN));
		return (-1);
	}

	tok->value = (char *)malloc(len);
	if (tok->value == NULL) {
		report_err(gettext("Memory allocation failed"));
		DPRINT((dfile, "Memory allocation failed: %s\n",
		    strerror(errno)));
		tok->length = 0;
		return (-1);
	}

	if (recv_timeout(fd, tok->value, len)) {
		free(tok->value);
		tok->value = NULL;
		tok->length = 0;
		return (-1);
	}

	tok->length = len;
	return (0);
}


/*
 * I/O functions
 */

/*
 * connect_timeout() - sets nonblocking I/O on a socket and timeout-connects
 */
static int
connect_timeout(int sockfd, struct sockaddr *name, int namelen)
{
	int			flags;
	struct pollfd		fds;
	int			rc;
	struct sockaddr_storage	addr;
	socklen_t		addr_len = sizeof (addr);


	flags = fcntl(sockfd, F_GETFL, 0);
	if (fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) == -1) {
		return (-1);
	}
	if (connect(sockfd, name, namelen)) {
		if (!(errno == EINTR || errno == EINPROGRESS ||
		    errno == EWOULDBLOCK)) {
			return (-1);
		}
	}
	fds.fd = sockfd;
	fds.events = POLLOUT;
	for (;;) {
		fds.revents = 0;
		rc = poll(&fds, 1, timeout * 1000);
		if (rc == 0) {	/* timeout */
			return (-1);
		} else if (rc < 0) {
			if (errno == EINTR || errno == EAGAIN) {
				continue;
			} else {
				return (-1);
			}
		}
		if (fds.revents) {
			if (getpeername(sockfd, (struct sockaddr *)&addr,
			    &addr_len))
				return (-1);
		} else {
			return (-1);
		}
		return (0);
	}
}

/*
 * send_timeout() - send data (in chunks if needed, each chunk in timeout secs).
 */
static int
send_timeout(int fd, const char *buf, size_t len)
{
	int		bytes;
	struct pollfd	fds;
	int		rc;

	fds.fd = fd;
	fds.events = POLLOUT;

	while (len) {
		fds.revents = 0;
		rc = poll(&fds, 1, timeout * 1000);
		if (rc == 0) {	/* timeout */
			return (-1);
		} else if (rc < 0) {
			if (errno == EINTR || errno == EAGAIN) {
				continue;
			} else {
				return (-1);
			}
		}
		if (!fds.revents) {
			return (-1);
		}

		bytes = write(fd, buf, len);
		if (bytes < 0) {
			if (errno == EINTR) {
				continue;
			} else {
				return (-1);
			}
		} else if (bytes == 0) {	/* eof */
			return (-1);
		}

		len -= bytes;
		buf += bytes;
	}

	return (0);
}

/*
 * recv_timeout() - receive data (in chunks if needed, each chunk in timeout
 * secs). In case the function is called from receiving thread, the function
 * cycles the poll() call in timeout seconds (waits for input from server).
 */
static int
recv_timeout(int fd, char *buf, size_t len)
{
	int		bytes;
	struct pollfd	fds;
	int		rc;

	fds.fd = fd;
	fds.events = POLLIN;

	while (len) {
		fds.revents = 0;
		rc = poll(&fds, 1, timeout * 1000);
		if (rc == 0) {			/* timeout */
			return (-1);
		} else if (rc < 0) {
			if (errno == EINTR || errno == EAGAIN) {
				continue;
			} else {
				return (-1);
			}
		}

		if (!fds.revents) {
			return (-1);
		}

		bytes = read(fd, buf, len);
		if (bytes < 0) {
			if (errno == EINTR) {
				continue;
			} else {
				return (-1);
			}
		} else if (bytes == 0) {	/* eof */
			return (-1);
		}

		len -= bytes;
		buf += bytes;
	}

	return (0);
}

/*
 * read_fd() - reads data of length len from the given file descriptor fd to the
 * buffer buf, in chunks if needed. Function returns B_FALSE on failure,
 * otherwise B_TRUE. Function preserves errno, if it was set by the read(2).
 */
static boolean_t
read_fd(int fd, char *buf, size_t len)
{
	int		bytes;
#ifdef DEBUG
	size_t		len_o = len;
#endif

	while (len) {
		bytes = read(fd, buf, len);
		if (bytes < 0) {		/* err */
			if (errno == EINTR || errno == EAGAIN) {
				continue;
			} else {
				return (B_FALSE);
			}
		} else if (bytes == 0) {	/* eof */
			return (B_FALSE);
		}

		len -= bytes;
		buf += bytes;
	}

	DPRINT((dfile, "read_fd: Read %d bytes.\n", len_o - len));
	return (B_TRUE);
}

/*
 * write_fd() - writes buf of length len to the opened file descriptor fd, in
 * chunks if needed. The data from the pipe are processed in the receiving
 * thread. Function returns B_FALSE on failure, otherwise B_TRUE. Function
 * preserves errno, if it was set by the write(2).
 */
static boolean_t
write_fd(int fd, char *buf, size_t len)
{
	int		bytes;
#ifdef DEBUG
	size_t		len_o = len;
#endif

	while (len) {
		bytes = write(fd, buf, len);
		if (bytes == -1) {		/* err */
			if (errno == EINTR || errno == EAGAIN) {
				continue;
			} else {
				return (B_FALSE);
			}
		}

		len -= bytes;
		buf += bytes;
	}

	DPRINT((dfile, "write_fd: Wrote %d bytes.\n", len_o - len));
	return (B_TRUE);
}

/*
 * Plug-in entry point
 */

/*
 * send_record() - send an audit record to a host opening a connection,
 * negotiate version and establish context if necessary.
 */
send_record_rc_t
send_record(struct hostlist_s *hostlptr, const char *input, size_t in_len,
    uint64_t sequence, close_rsn_t *err_rsn)
{
	gss_buffer_desc		in_buf, out_buf;
	OM_uint32		maj_stat, min_stat;
	int			conf_state;
	int			rc;
	transq_node_t		*node_ptr;
	uint64_t		seq_n;	/* sequence in the network byte order */
	boolean_t		init_sock_poll = B_FALSE;

	/*
	 * We need to grab the reset_lock here, to prevent eventual
	 * unsynchronized cleanup calls within the reset routine (reset caused
	 * by the receiving thread) and the initialization calls in the
	 * send_record() code path.
	 */
	(void) pthread_mutex_lock(&reset_lock);

	/*
	 * Check whether the socket was closed by the recv thread prior to call
	 * send_record() and behave accordingly to the reason of the closure.
	 */
	if (recv_closure_rsn != RSN_UNDEFINED) {
		*err_rsn = recv_closure_rsn;
		if (recv_closure_rsn == RSN_GSS_CTX_EXP) {
			rc = SEND_RECORD_RETRY;
		} else {
			rc = SEND_RECORD_NEXT;
		}
		recv_closure_rsn = RSN_UNDEFINED;
		(void) pthread_mutex_unlock(&reset_lock);
		return (rc);
	}

	/*
	 * Send request to other then previously used host.
	 */
	if (current_host != hostlptr->host) {
		DPRINT((dfile, "Set new host: %s\n", hostlptr->host->h_name));
		if (sockfd != -1) {
			(void) pthread_mutex_unlock(&reset_lock);
			reset_transport(DO_CLOSE, DO_SYNC);
			return (SEND_RECORD_RETRY);
		}
		current_host = (struct hostent *)hostlptr->host;
		current_mech_oid = &hostlptr->mech;
		current_port = hostlptr->port;
	}

	/* initiate the receiving thread */
	(void) pthread_once(&recv_once_control, init_recv_record);

	/* create and connect() socket, negotiate the protocol version */
	if (sockfd == -1) {
		/* socket operations */
		DPRINT((dfile, "Socket creation and connect\n"));
		if (!sock_prepare(&sockfd, current_host, err_rsn)) {
			/* we believe the err_rsn set by sock_prepare() */
			(void) pthread_mutex_unlock(&reset_lock);
			return (SEND_RECORD_NEXT);
		}

		/* protocol version negotiation */
		DPRINT((dfile, "Protocol version negotiation\n"));
		if (prot_ver_negotiate() != 0) {
			DPRINT((dfile,
			    "Protocol version negotiation failed\n"));
			(void) pthread_mutex_unlock(&reset_lock);
			reset_transport(DO_CLOSE, DO_SYNC);
			*err_rsn = RSN_PROTOCOL_NEGOTIATE;
			return (SEND_RECORD_NEXT);
		}

		/* let the socket be initiated for poll() */
		init_sock_poll = B_TRUE;
	}

	if (!gss_ctx_initialized) {
		DPRINT((dfile, "Establishing context..\n"));
		if (establish_context() != 0) {
			(void) pthread_mutex_unlock(&reset_lock);
			reset_transport(DO_CLOSE, DO_SYNC);
			*err_rsn = RSN_GSS_CTX_ESTABLISH;
			return (SEND_RECORD_NEXT);
		}
		gss_ctx_initialized = B_TRUE;
	}

	/* let the recv thread poll() on the sockfd */
	if (init_sock_poll) {
		init_sock_poll = B_FALSE;
		if (!init_poll(sockfd)) {
			*err_rsn = RSN_INIT_POLL;
			(void) pthread_mutex_unlock(&reset_lock);
			return (SEND_RECORD_RETRY);
		}
	}

	(void) pthread_mutex_unlock(&reset_lock);

	/* if not empty, retransmit contents of the transmission queue */
	if (flush_transq) {
		DPRINT((dfile, "Retransmitting remaining (%ld) tokens from "
		    "the transmission queue\n", transq_hdr.count));
		if ((rc = transq_retransmit()) == 2) { /* gss context exp */
			reset_transport(DO_CLOSE, DO_SYNC);
			*err_rsn = RSN_GSS_CTX_EXP;
			return (SEND_RECORD_RETRY);
		} else if (rc == 1) {
			reset_transport(DO_CLOSE, DO_SYNC);
			*err_rsn = RSN_OTHER_ERR;
			return (SEND_RECORD_NEXT);
		}
		flush_transq = B_FALSE;
	}

	/*
	 * Concatenate sequence number and the new record. Note, that the
	 * pointer to the chunk of memory allocated for the concatenated values
	 * is later passed to the transq_enqueu() function which stores the
	 * pointer in the transmission queue; subsequently called
	 * transq_dequeue() frees the allocated memory once the MIC is verified
	 * by the recv_record() function.
	 *
	 * If we return earlier than the transq_enqueue() is called, it's
	 * necessary to free the in_buf.value explicitly prior to return.
	 *
	 */
	in_buf.length = in_len + sizeof (sequence);
	in_buf.value = malloc(in_buf.length);
	if (in_buf.value == NULL) {
			report_err(gettext("Memory allocation failed"));
			DPRINT((dfile, "Memory allocation failed: %s\n",
			    strerror(errno)));
			reset_transport(DO_CLOSE, DO_SYNC);
			*err_rsn = RSN_MEMORY_ALLOCATE;
			return (SEND_RECORD_FAIL);
	}
	seq_n = htonll(sequence);
	(void) memcpy(in_buf.value, &seq_n, sizeof (seq_n));
	(void) memcpy((char *)in_buf.value + sizeof (seq_n), input, in_len);

	/* wrap sequence number and the new record to the per-message token */
	(void) pthread_mutex_lock(&gss_ctx_lock);
	if (gss_ctx != NULL) {
		maj_stat = gss_wrap(&min_stat, gss_ctx, 1, GSS_C_QOP_DEFAULT,
		    &in_buf, &conf_state, &out_buf);
		(void) pthread_mutex_unlock(&gss_ctx_lock);
		switch (maj_stat) {
		case GSS_S_COMPLETE:
			break;
		case GSS_S_CONTEXT_EXPIRED:
			reset_transport(DO_CLOSE, DO_SYNC);
			free(in_buf.value);
			*err_rsn = RSN_GSS_CTX_EXP;
			return (SEND_RECORD_RETRY);
		default:
			report_gss_err(gettext("gss_wrap message"), maj_stat,
			    min_stat);
			reset_transport(DO_CLOSE, DO_SYNC);
			free(in_buf.value);
			*err_rsn = RSN_OTHER_ERR;
			return (SEND_RECORD_NEXT);
		}
	} else {	/* GSS context deleted by the recv thread */
		(void) pthread_mutex_unlock(&gss_ctx_lock);
		reset_transport(DO_CLOSE, DO_SYNC);
		free(in_buf.value);
		*err_rsn = RSN_OTHER_ERR;
		return (SEND_RECORD_NEXT);
	}


	/* enqueue the to-be-sent token into transmission queue */
	(void) pthread_mutex_lock(&transq_lock);
	if (!transq_enqueue(&node_ptr, &in_buf, sequence)) {
		(void) pthread_mutex_unlock(&transq_lock);
		reset_transport(DO_CLOSE, DO_SYNC);
		free(in_buf.value);
		(void) gss_release_buffer(&min_stat, &out_buf);
		*err_rsn = RSN_OTHER_ERR;
		return (SEND_RECORD_RETRY);
	}
	DPRINT((dfile, "Token enqueued for later verification\n"));
	(void) pthread_mutex_unlock(&transq_lock);

	/* send token */
	if (send_token(&sockfd, &out_buf) < 0) {
		DPRINT((dfile, "Token sending failed\n"));
		reset_transport(DO_CLOSE, DO_SYNC);
		(void) gss_release_buffer(&min_stat, &out_buf);

		(void) pthread_mutex_lock(&transq_lock);
		transq_dequeue(node_ptr);
		(void) pthread_mutex_unlock(&transq_lock);

		*err_rsn = RSN_OTHER_ERR;
		return (SEND_RECORD_NEXT);
	}
	DPRINT((dfile, "Token sent (transq size = %ld)\n", transq_hdr.count));

	(void) gss_release_buffer(&min_stat, &out_buf);

	return (SEND_RECORD_SUCCESS);
}

/*
 * init_recv_record() - initialize the receiver thread
 */
static void
init_recv_record()
{
	DPRINT((dfile, "Initiating the recv thread\n"));
	(void) pthread_create(&recv_tid, NULL, recv_record, NULL);

}


/*
 * recv_record() - the receiver thread routine
 */
static void *
recv_record(void *arg __unused)
{
	OM_uint32		maj_stat, min_stat;
	gss_qop_t		qop_state;
	gss_buffer_desc		in_buf = GSS_C_EMPTY_BUFFER;
	gss_buffer_desc		in_buf_mic = GSS_C_EMPTY_BUFFER;
	transq_node_t		*cur_node;
	uint64_t		r_seq_num;	/* received sequence number */
	boolean_t		token_verified;
	boolean_t		break_flag;
	struct pollfd		fds[2];
	int			fds_cnt;
	struct pollfd		*pipe_fd = &fds[0];
	struct pollfd		*recv_fd = &fds[1];
	uint32_t		len;
	int			rc;
	pipe_msg_t		np_data;

	DPRINT((dfile, "Receiver thread initiated\n"));

	/*
	 * Fill in the information in the vector of file descriptors passed
	 * later on to the poll() function. In the initial state, there is only
	 * one struct pollfd in the vector which contains file descriptor of the
	 * notification pipe - notify_pipe[1]. There might be up to two file
	 * descriptors (struct pollfd) in the vector - notify_pipe[1] which
	 * resides in the vector during the entire life of the receiving thread,
	 * and the own file descriptor from which we read data sent by the
	 * remote server application.
	 */
	pipe_fd->fd = notify_pipe[1];
	pipe_fd->events = POLLIN;
	recv_fd->fd = -1;
	recv_fd->events = POLLIN;
	fds_cnt = 1;

	/*
	 * In the endless loop, try to grab some data from the socket or
	 * notify_pipe[1].
	 */
	for (;;) {

		pipe_fd->revents = 0;
		recv_fd->revents = 0;
		recv_closure_rsn = RSN_UNDEFINED;

		/* block on poll, thus rc != 0 */
		rc = poll(fds, fds_cnt, -1);
		if (rc == -1) {
			if (errno == EAGAIN || errno == EINTR) {
				/* silently continue on EAGAIN || EINTR */
				continue;
			} else {
				/* log the debug message in any other case */
				DPRINT((dfile, "poll() failed: %s\n",
				    strerror(errno)));
				report_err(gettext("poll() failed.\n"));
				continue;
			}
		}

		/*
		 * Receive a message from the notification pipe. Information
		 * from the notification pipe takes precedence over the received
		 * data from the remote server application.
		 *
		 * Notification pipe message format - message accepted
		 * from the notify pipe comprises of two parts (int ||
		 * boolean_t), where if the first part (sizeof (int)) equals
		 * NP_CLOSE, then the second part (sizeof (boolean_t)) signals
		 * the necessity of broadcasting (DO_SYNC/DO_NOT_SYNC) the end
		 * of the reset routine.
		 */
		if (pipe_fd->revents & POLLIN) {
			DPRINT((dfile, "An event on notify pipe detected\n"));
			if (!read_fd(pipe_fd->fd, (char *)&np_data,
			    sizeof (np_data))) {
				DPRINT((dfile, "Reading notify pipe failed: "
				    "%s\n", strerror(errno)));
				report_err(gettext("Reading notify pipe "
				    "failed"));
			} else {
				switch (np_data.sock_num) {
				case NP_EXIT:	/* exit receiving thread */
					do_cleanup(&fds_cnt, recv_fd,
					    np_data.sync);
					pthread_exit((void *)NULL);
					break;
				case NP_CLOSE:	/* close and remove recv_fd */
					do_reset(&fds_cnt, recv_fd,
					    np_data.sync);
					continue;
				default:	/* add rc_pipe to the fds */
					recv_fd->fd = np_data.sock_num;
					fds_cnt = 2;
					continue;
				}
			}
		}
		/* Receive a token from the remote server application */
		if (recv_fd->revents & POLLIN) {
			DPRINT((dfile, "An event on fd detected\n"));
			if (!read_fd(recv_fd->fd, (char *)&len, sizeof (len))) {
				DPRINT((dfile, "Token length recv failed\n"));
				recv_closure_rsn = RSN_TOK_RECV_FAILED;
				reset_transport(DO_CLOSE, DO_NOT_SYNC);
				continue;
			}
			len = ntohl(len);

			/* simple DOS prevention mechanism */
			if (len > MAX_TOK_LEN) {
				report_err(gettext("Indicated invalid token "
				    "length"));
				DPRINT((dfile, "Indicated token length > %dB\n",
				    MAX_TOK_LEN));
				recv_closure_rsn = RSN_TOK_TOO_BIG;
				reset_transport(DO_CLOSE, DO_NOT_SYNC);
				continue;
			}

			in_buf.value = (char *)malloc(len);
			if (in_buf.value == NULL) {
				report_err(gettext("Memory allocation failed"));
				DPRINT((dfile, "Memory allocation failed: %s\n",
				    strerror(errno)));
				recv_closure_rsn = RSN_MEMORY_ALLOCATE;
				reset_transport(DO_CLOSE, DO_NOT_SYNC);
				continue;
			}
			if (!read_fd(recv_fd->fd, (char *)in_buf.value, len)) {
				DPRINT((dfile, "Token value recv failed\n"));
				free(in_buf.value);
				recv_closure_rsn = RSN_TOK_RECV_FAILED;
				reset_transport(DO_CLOSE, DO_NOT_SYNC);
				continue;
			}

			in_buf.length = len;
		}

		/*
		 * Extract the sequence number and the MIC from
		 * the per-message token
		 */
		(void) memcpy(&r_seq_num, in_buf.value, sizeof (r_seq_num));
		r_seq_num = ntohll(r_seq_num);
		in_buf_mic.length = in_buf.length - sizeof (r_seq_num);
		in_buf_mic.value = (char *)in_buf.value + sizeof (r_seq_num);

		/*
		 * seq_num/r_seq_num - the sequence number does not need to
		 * be unique in the transmission queue. Any token in the
		 * transmission queue with the same seq_num as the acknowledge
		 * token received from the server is tested. This is due to the
		 * fact that the plugin cannot influence (in the current
		 * implementation) sequence numbers generated by the kernel (we
		 * are reusing record sequence numbers as a transmission queue
		 * sequence numbers). The probability of having two or more
		 * tokens in the transmission queue is low and at the same time
		 * the performance gain due to using sequence numbers is quite
		 * high.
		 *
		 * In case a harder condition with regard to duplicate sequence
		 * numbers in the transmission queue will be desired over time,
		 * the break_flag behavior used below should be
		 * removed/changed_accordingly.
		 */
		break_flag = B_FALSE;
		token_verified = B_FALSE;
		(void) pthread_mutex_lock(&transq_lock);
		cur_node = transq_hdr.head;
		while (cur_node != NULL && !break_flag) {
			if (cur_node->seq_num != r_seq_num) {
				cur_node = cur_node->next;
				continue;
			}

			(void) pthread_mutex_lock(&gss_ctx_lock);
			maj_stat = gss_verify_mic(&min_stat, gss_ctx,
			    &(cur_node->seq_token), &in_buf_mic,
			    &qop_state);
			(void) pthread_mutex_unlock(&gss_ctx_lock);

			if (!GSS_ERROR(maj_stat)) { /* the success case */
				switch (maj_stat) {
				/*
				 * All the GSS_S_OLD_TOKEN, GSS_S_UNSEQ_TOKEN,
				 * GSS_S_GAP_TOKEN are perceived as correct
				 * behavior of the server side. The plugin
				 * implementation is resistant to any of the
				 * above mention cases of returned status codes.
				 */
				/*FALLTHRU*/
				case GSS_S_OLD_TOKEN:
				case GSS_S_UNSEQ_TOKEN:
				case GSS_S_GAP_TOKEN:
				case GSS_S_COMPLETE:
					/*
					 * remove the verified record/node from
					 * the transmission queue
					 */
					transq_dequeue(cur_node);
					DPRINT((dfile, "Recv thread verified "
					    "the token (transq len = %ld)\n",
					    transq_hdr.count));

					token_verified = B_TRUE;
					break_flag = B_TRUE;
					break;

				/*
				 * Both the default case as well as
				 * GSS_S_DUPLICATE_TOKEN case should never
				 * occur. It's been left here for the sake of
				 * completeness.
				 * If any of the two cases occur, it is
				 * subsequently cought because we don't set
				 * the token_verified flag.
				 */
				/*FALLTHRU*/
				case GSS_S_DUPLICATE_TOKEN:
				default:
					break_flag = B_TRUE;
					break;
				} /* switch (maj_stat) */

			} else {	/* the failure case */
				report_gss_err(
				    gettext("signature verification of the "
				    "received token failed"),
				    maj_stat, min_stat);

				switch (maj_stat) {
				case GSS_S_CONTEXT_EXPIRED:
					/* retransmission necessary */
					recv_closure_rsn = RSN_GSS_CTX_EXP;
					break_flag = B_TRUE;
					DPRINT((dfile, "Recv thread detected "
					    "the GSS context expiration\n"));
					break;
				case GSS_S_BAD_SIG:
					DPRINT((dfile, "Bad signature "
					    "detected (seq_num = %lld)\n",
					    cur_node->seq_num));
					cur_node = cur_node->next;
					break;
				default:
					report_gss_err(
					    gettext("signature verification"),
					    maj_stat, min_stat);
					break_flag = B_TRUE;
					break;
				}
			}

		} /* while */
		(void) pthread_mutex_unlock(&transq_lock);

		if (in_buf.value != NULL) {
			free(in_buf.value);
			in_buf.value = NULL;
			in_buf.length = 0;
		}

		if (!token_verified) {
			/*
			 * Received, but unverifiable token is perceived as
			 * the protocol flow corruption with the penalty of
			 * reinitializing the client/server connection.
			 */
			DPRINT((dfile, "received unverifiable token\n"));
			report_err(gettext("received unverifiable token\n"));
			if (recv_closure_rsn == RSN_UNDEFINED) {
				recv_closure_rsn = RSN_TOK_UNVERIFIABLE;
			}
			reset_transport(DO_CLOSE, DO_NOT_SYNC);
		}

	} /* for (;;) */


}


/*
 * init_poll() - initiates the polling in the receiving thread via sending the
 * appropriate message over the notify pipe. Message format = (int ||
 * booleant_t), where the first part (sizeof (int)) contains the
 * newly_opened/to_be_polled socket file descriptor. The contents of the second
 * part (sizeof (boolean_t)) of the message works only as a padding here and no
 * action (no recv/send thread synchronisation) is made in the receiving thread
 * based on its value.
 */
static boolean_t
init_poll(int fd)
{
	pipe_msg_t	np_data;
	int		pipe_in = notify_pipe[0];

	np_data.sock_num = fd;
	np_data.sync = B_FALSE;	/* padding only */

	if (!write_fd(pipe_in, (char *)&np_data, sizeof (np_data))) {
		DPRINT((dfile, "Cannot write to the notify pipe\n"));
		report_err(gettext("writing to the notify pipe failed"));
		return (B_FALSE);
	}

	return (B_TRUE);
}


/*
 * reset_transport() - locked by the reset_lock initiates the reset of socket,
 * GSS security context and (possibly) flags the transq for retransmission; for
 * more detailed information see do_reset(). The reset_transport() also allows
 * the synchronization - waiting for the reset to be finished.
 *
 * do_close: DO_SYNC, DO_NOT_SYNC
 * sync_on_return: DO_EXIT (DO_NOT_CLOSE), DO_CLOSE (DO_NOT_EXIT)
 *
 */
void
reset_transport(boolean_t do_close, boolean_t sync_on_return)
{
	int		pipe_in = notify_pipe[0];
	pipe_msg_t	np_data;

	/*
	 * Check if the reset routine is in progress or whether it was already
	 * executed by some other thread.
	 */
	(void) pthread_mutex_lock(&reset_lock);
	if (reset_in_progress) {
		(void) pthread_mutex_unlock(&reset_lock);
		return;
	}
	reset_in_progress = B_TRUE;

	np_data.sock_num = (do_close ? NP_CLOSE : NP_EXIT);
	np_data.sync = sync_on_return;
	(void) write_fd(pipe_in, (char *)&np_data, sizeof (np_data));

	if (sync_on_return) {
		while (reset_in_progress) {
			(void) pthread_cond_wait(&reset_cv, &reset_lock);
			DPRINT((dfile, "Wait for sync\n"));
		}
		DPRINT((dfile, "Synced\n"));
	}
	(void) pthread_mutex_unlock(&reset_lock);

}


/*
 * do_reset() - the own reseting routine called from the recv thread. If the
 * synchronization was requested, signal the finish via conditional variable.
 */
static void
do_reset(int *fds_cnt, struct pollfd *recv_fd, boolean_t do_signal)
{

	(void) pthread_mutex_lock(&reset_lock);

	/* socket */
	(void) pthread_mutex_lock(&sock_lock);
	if (sockfd == -1) {
		DPRINT((dfile, "socket already closed\n"));
		(void) pthread_mutex_unlock(&sock_lock);
		goto out;
	} else {
		(void) close(sockfd);
		sockfd = -1;
		recv_fd->fd = -1;
		(void) pthread_mutex_unlock(&sock_lock);
	}
	*fds_cnt = 1;

	/* context */
	if (gss_ctx_initialized) {
		delete_context();
	}
	gss_ctx_initialized = B_FALSE;
	gss_ctx = NULL;

	/* mark transq to be flushed */
	(void) pthread_mutex_lock(&transq_lock);
	if (transq_hdr.count > 0) {
		flush_transq = B_TRUE;
	}
	(void) pthread_mutex_unlock(&transq_lock);

out:
	reset_in_progress = B_FALSE;
	if (do_signal) {
		(void) pthread_cond_broadcast(&reset_cv);
	}

	(void) pthread_mutex_unlock(&reset_lock);
}

/*
 * do_cleanup() - removes all the preallocated space by the plugin; prepares the
 * plugin/application to be gracefully finished. Even thought the function
 * allows execution without signalling the successful finish, it's recommended
 * to use it (we usually want to wait for cleanup before exiting).
 */
static void
do_cleanup(int *fds_cnt, struct pollfd *recv_fd, boolean_t do_signal)
{

	(void) pthread_mutex_lock(&reset_lock);

	/*
	 * socket
	 * note: keeping locking for safety, thought it shouldn't be necessary
	 * in current implementation - we get here only in case the sending code
	 * path calls auditd_plugin_close() (thus no socket manipulation) and
	 * the recv thread is doing the own socket closure.
	 */
	(void) pthread_mutex_lock(&sock_lock);
	if (sockfd != -1) {
		DPRINT((dfile, "Closing socket: %d\n", sockfd));
		(void) close(sockfd);
		sockfd = -1;
		recv_fd->fd = -1;
	}
	*fds_cnt = 1;
	(void) pthread_mutex_unlock(&sock_lock);

	/* context */
	if (gss_ctx_initialized) {
		DPRINT((dfile, "Deleting context: "));
		delete_context();
	}
	gss_ctx_initialized = B_FALSE;
	gss_ctx = NULL;

	/* transmission queue */
	(void) pthread_mutex_lock(&transq_lock);
	if (transq_hdr.count > 0) {
		DPRINT((dfile, "Deallocating the transmission queue "
		    "(len = %ld)\n", transq_hdr.count));
		while (transq_hdr.count > 0) {
			transq_dequeue(transq_hdr.head);
		}
	}
	(void) pthread_mutex_unlock(&transq_lock);

	/* notification pipe */
	if (notify_pipe_ready) {
		(void) close(notify_pipe[0]);
		(void) close(notify_pipe[1]);
		notify_pipe_ready = B_FALSE;
	}

	reset_in_progress = B_FALSE;
	if (do_signal) {
		(void) pthread_cond_broadcast(&reset_cv);
	}
	(void) pthread_mutex_unlock(&reset_lock);
}


/*
 * transq_dequeue() - dequeues given node pointed by the node_ptr from the
 * transmission queue. Transmission queue should be locked prior to use of this
 * function.
 */
static void
transq_dequeue(transq_node_t *node_ptr)
{

	if (node_ptr == NULL) {
		DPRINT((dfile, "transq_dequeue(): called with NULL pointer\n"));
		return;
	}

	free(node_ptr->seq_token.value);

	if (node_ptr->prev != NULL) {
		node_ptr->prev->next = node_ptr->next;
	}
	if (node_ptr->next != NULL) {
		node_ptr->next->prev = node_ptr->prev;
	}


	/* update the transq_hdr */
	if (node_ptr->next == NULL) {
		transq_hdr.end = node_ptr->prev;
	}
	if (node_ptr->prev == NULL) {
		transq_hdr.head = node_ptr->next;
	}

	transq_hdr.count--;

	free(node_ptr);
}


/*
 * transq_enqueue() - creates new node in (at the end of) the transmission
 * queue. in_ptoken_ptr is a pointer to the plain token in a form of
 * gss_buffer_desc. Function returns 0 on success and updates the *node_ptr to
 * point to a newly added transmission queue node. In case of any failure
 * function returns 1 and sets the *node_ptr to NULL.
 * Transmission queue should be locked prior to use of this function.
 */
static boolean_t
transq_enqueue(transq_node_t **node_ptr, gss_buffer_t in_seqtoken_ptr,
    uint64_t sequence)
{

	*node_ptr = calloc(1, sizeof (transq_node_t));
	if (*node_ptr == NULL) {
		report_err(gettext("Memory allocation failed"));
		DPRINT((dfile, "Memory allocation failed: %s\n",
		    strerror(errno)));
		goto errout;
	}

	/* value of the seq_token.value = (sequence number || plain token) */
	(*node_ptr)->seq_num = sequence;
	(*node_ptr)->seq_token.length = in_seqtoken_ptr->length;
	(*node_ptr)->seq_token.value = in_seqtoken_ptr->value;

	/* update the transq_hdr */
	if (transq_hdr.head == NULL) {
		transq_hdr.head = *node_ptr;
	}
	if (transq_hdr.end != NULL) {
		(transq_hdr.end)->next = *node_ptr;
		(*node_ptr)->prev = transq_hdr.end;
	}
	transq_hdr.end = *node_ptr;

	transq_hdr.count++;

	return (B_TRUE);

errout:
	if (*node_ptr != NULL) {
		if ((*node_ptr)->seq_token.value != NULL) {
			free((*node_ptr)->seq_token.value);
		}
		free(*node_ptr);
		*node_ptr = NULL;
	}
	return (B_FALSE);
}


/*
 * transq_retransmit() - traverse the transmission queue and try to, 1 by 1,
 * re-wrap the tokens with the recent context information and retransmit the
 * tokens from the transmission queue.
 * Function returns 2 on GSS context expiration, 1 on any other error, 0 on
 * successfully resent transmission queue.
 */
static int
transq_retransmit()
{

	OM_uint32	maj_stat, min_stat;
	transq_node_t	*cur_node = transq_hdr.head;
	gss_buffer_desc	out_buf;
	int		conf_state;

	DPRINT((dfile, "Retransmission of the remainder in the transqueue\n"));

	while (cur_node != NULL) {

		(void) pthread_mutex_lock(&transq_lock);
		(void) pthread_mutex_lock(&gss_ctx_lock);
		maj_stat = gss_wrap(&min_stat, gss_ctx, 1, GSS_C_QOP_DEFAULT,
		    &(cur_node->seq_token), &conf_state, &out_buf);
		(void) pthread_mutex_unlock(&gss_ctx_lock);

		switch (maj_stat) {
		case GSS_S_COMPLETE:
			break;
		case GSS_S_CONTEXT_EXPIRED:
			DPRINT((dfile, "Context expired.\n"));
			report_gss_err(gettext("gss_wrap message"), maj_stat,
			    min_stat);
			(void) pthread_mutex_unlock(&transq_lock);
			return (2);
		default:
			report_gss_err(gettext("gss_wrap message"), maj_stat,
			    min_stat);
			(void) pthread_mutex_unlock(&transq_lock);
			return (1);
		}

		DPRINT((dfile, "Sending transmission queue token (seq=%lld, "
		    "size=%d, transq len=%ld)\n", cur_node->seq_num,
		    out_buf.length, transq_hdr.count));
		if (send_token(&sockfd, &out_buf) < 0) {
			(void) gss_release_buffer(&min_stat, &out_buf);
			(void) pthread_mutex_unlock(&transq_lock);
			return (1);
		}
		(void) gss_release_buffer(&min_stat, &out_buf);

		cur_node = cur_node->next;
		(void) pthread_mutex_unlock(&transq_lock);

	} /* while */

	return (0);
}
