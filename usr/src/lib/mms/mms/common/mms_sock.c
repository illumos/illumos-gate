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
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#include <sys/types.h>
#include <sys/socket.h>
#include <pthread.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>
#include <libgen.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include "mms_network.h"
#include "mms_sym.h"
#include "mms_sock.h"
#include <mms_trace.h>

static void mms_gai_error(mms_err_t *err, int id, int n);


/* Protocol-independent IPv4/IPv6 client connection. */
int
mms_connect(char *host, char *service, void *ssl_data, mms_t *conn)
{
	int			 sockfd;
	int			 n;
	struct addrinfo		 hints;
	struct addrinfo		*res = NULL;
	struct addrinfo		*ressave;
	char			 host_str[MAXHOSTNAMELEN];
	char			*host_p = host;

	(void) memset(conn, 0, sizeof (mms_t));
	conn->mms_fd = -1;

	(void) memset(&hints, 0, sizeof (struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if (strcmp(host_p, "localhost") == 0) {
		/* getaddrinfo can't handle localhost so look up hostname */
		if (gethostname(host_str, sizeof (host_str)) != 0) {
			mms_sys_error(&conn->mms_err, MMS_ERR_GETHOSTNAME);
			return (1);
		}
		host_p = host_str;
	}

	if ((n = getaddrinfo(host_p, service, &hints, &res)) != 0) {
		mms_gai_error(&conn->mms_err, MMS_ERR_GETADDRINFO, n);
		return (1);
	}
	if (res == NULL) {
		mms_error(&conn->mms_err, MMS_ERR_RES_NULL);
		return (1);
	}
	ressave = res;

	do {
		sockfd = socket(res->ai_family, res->ai_socktype,
		    res->ai_protocol);

		if (sockfd < 0) {
			continue; /* ignore this one */
		}

		if (connect(sockfd, res->ai_addr, res->ai_addrlen) == 0) {
			break; /* success */
		}

		(void) close(sockfd);  /* ignore this one */
	} while ((res = res->ai_next) != NULL);

	freeaddrinfo(ressave);

	if (res == NULL) {
		mms_error(&conn->mms_err, MMS_ERR_SERVICE_NOT_FOUND);
		return (1);
	}

	conn->mms_fd = sockfd;

#ifdef	MMS_OPENSSL
	if (ssl_data && mms_ssl_connect(ssl_data, conn)) {
		return (1);
	}
#endif	/* MMS_OPENSSL */

	return (0);
}

/* Server accepts client connection. */
int
mms_accept(int serv_fd, void *ssl_data, mms_t *conn)
{
	int		sockfd = -1;
	struct sockaddr	sa;
	socklen_t	salen;

	(void) memset(conn, 0, sizeof (mms_t));
	conn->mms_fd = -1;

	salen = sizeof (struct sockaddr);
	while ((sockfd = accept(serv_fd, &sa, &salen)) < 0) {
		if (errno == EINTR || errno == ECONNABORTED) {
			continue;
		}
		mms_sys_error(&conn->mms_err, MMS_ERR_ACCEPT_FAILED);
		return (1);
	}

	conn->mms_fd = sockfd;

#ifdef	MMS_OPENSSL
	if (ssl_data && mms_ssl_accept(ssl_data, conn)) {
		return (1);
	}
#endif	/* MMS_OPENSSL */

	return (0);
}

/* Protocol-independent IPv4/IPv6 server listener. */
int
mms_listen(char *host, char *service, int *serv_fd, mms_err_t *err)
{
	int		listenfd;
	int		n;
	const int	on = 1;
	struct addrinfo hints;
	struct addrinfo *res = NULL;
	struct addrinfo *ressave;
	char		 host_str[MAXHOSTNAMELEN];
	char		*host_p = host;

	*serv_fd = -1;

	(void) memset(&hints, 0, sizeof (struct addrinfo));
	hints.ai_flags = AI_PASSIVE;
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if (strcmp(host_p, "localhost") == 0) {
		if (gethostname(host_str, sizeof (host_str)) != 0) {
			mms_sys_error(err, MMS_ERR_GETHOSTNAME);
			return (1);
		}
		host_p = host_str;
	}

	if ((n = getaddrinfo(host_p, service, &hints, &res)) != 0) {
		mms_gai_error(err, MMS_ERR_GETADDRINFO, n);
		return (1);
	}
	if (res == NULL) {
		mms_error(err, MMS_ERR_RES_NULL);
		return (1);
	}
	ressave = res;

	do {
		listenfd = socket(res->ai_family, res->ai_socktype,
		    res->ai_protocol);

		if (listenfd < 0)
			continue; /* error, try next one */

		if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &on,
		    sizeof (on)) < 0) {
			(void) close(listenfd);
			continue;
		}

		if (bind(listenfd, res->ai_addr, res->ai_addrlen) == 0) {
			break; /* success */
		}

		(void) close(listenfd); /* bind error, try next one */
	} while ((res = res->ai_next) != NULL);

	freeaddrinfo(ressave);

	if (listen(listenfd, MMS_BACKLOG) == -1) {
		mms_sys_error(err, MMS_ERR_LISTEN);
		return (1);
	}

	*serv_fd = listenfd;
	return (0);
}

/* Read from socket. */
int
mms_read(mms_t *conn, char *buf, int len)
{
	int	rc;

	if (conn->mms_ssl) {
#ifdef	MMS_OPENSSL
		rc = mms_ssl_read(conn, buf, len);
#endif	/* MMS_OPENSSL */
	} else {
		rc = read(conn->mms_fd, buf, len);
	}
	return (rc);
}

/* Should the read continue or be stopped? */
int
mms_read_has_error(mms_t *conn)
{
	if (conn->mms_ssl) {
#ifdef	MMS_OPENSSL
		return (mms_ssl_read_has_error(conn));
#endif	/* MMS_OPENSSL */
	} else {
		if (errno == EINTR) {
			return (0); /* continue */
		}
		mms_sys_error(&conn->mms_err, MMS_ERR_READ);
	}
	return (1); /* stop reading */
}

/* Write to the socket */
int
mms_write(mms_t *conn, struct iovec *iov, int iovcnt)
{
	int	rc;

	if (conn->mms_ssl) {
#ifdef	MMS_OPENSSL
		rc = mms_ssl_write(conn, iov, iovcnt);
#endif	/* MMS_OPENSSL */
	} else {
		rc = writev(conn->mms_fd, iov, iovcnt);
	}
	return (rc);
}

/* Should the write continue or be stopped. */
int
mms_write_has_error(mms_t *conn)
{
	if (conn->mms_ssl) {
#ifdef	MMS_OPENSSL
		return (mms_ssl_write_has_error(conn));
#endif	/* MMS_OPENSSL */
	} else {
		if (errno == EINTR) {
			return (0); /* continue */
		}
		mms_sys_error(&conn->mms_err, MMS_ERR_WRITE);
	}
	return (1); /* stop writing */
}

/* Close the socket. */
void
mms_close(mms_t *conn)
{
	mms_err_t err;

	if (conn == NULL) {
		return;
	}

	err = conn->mms_err; /* save any error info */

	if (conn->mms_ssl) {
#ifdef	MMS_OPENSSL
		mms_ssl_close(conn);
#endif	/* MMS_OPENSSL */
	} else if (conn->mms_fd >= 0) {
		(void) close(conn->mms_fd);
	}

	(void) memset(conn, 0, sizeof (mms_t));
	conn->mms_fd = -1;
	conn->mms_err = err;
}

void
mms_error(mms_err_t *err, int id)
{
	err->mms_id = id;
	err->mms_type = 0;
	err->mms_num = 0;
}

static void
mms_gai_error(mms_err_t *err, int id, int n)
{
	err->mms_id = id;
	err->mms_type = MMS_ERR_GAI;
	err->mms_num = n;
}

void
mms_sys_error(mms_err_t *err, int id)
{
	err->mms_id = id;
	err->mms_type = MMS_ERR_SYS;
	err->mms_num = errno;
}

/* Get error string */
void
mms_get_error_string(mms_err_t *err, char *ebuf, int ebuflen)
{
	int	id;

	if (err == NULL || ebuf == NULL || ebuflen < 1) {
		return;
	}

	if ((id = err->mms_id) == 0)
		id = MMS_ERR_NONE;

	/* turn error number into a string */
	switch (err->mms_type) {
	case MMS_ERR_SYS:
		if (err->mms_num) {
			(void) snprintf(ebuf, ebuflen, "%s (%lu) %s",
			    mms_sym_code_to_str(id),
			    err->mms_num,
			    strerror(err->mms_num));
		} else {
			(void) snprintf(ebuf, ebuflen, "%s",
			    mms_sym_code_to_str(id));
		}
		break;
	case MMS_ERR_GAI:
		if (err->mms_num) {
			(void) snprintf(ebuf, ebuflen, "%s (%lu) %s",
			    mms_sym_code_to_str(id),
			    err->mms_num,
			    gai_strerror(err->mms_num));
		} else {
			(void) snprintf(ebuf, ebuflen, "%s",
			    mms_sym_code_to_str(id));
		}
		break;
#ifdef	MMS_OPENSSL
	case MMS_ERR_SSL:
		mms_ssl_get_error_string(err, ebuf, ebuflen);
		break;
#endif	/* MMS_OPENSSL */
	default:
		if (err->mms_num) {
			(void) snprintf(ebuf, ebuflen, "%s (%lu)",
			    mms_sym_code_to_str(id),
			    err->mms_num);
		} else {
			(void) snprintf(ebuf, ebuflen, "%s",
			    mms_sym_code_to_str(id));
		}
		break;
	}
}
