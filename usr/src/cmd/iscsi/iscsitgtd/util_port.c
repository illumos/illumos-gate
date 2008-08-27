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

#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <assert.h>
#include <syslog.h>
#include <unistd.h>

#include "queue.h"
#include "port.h"
#include "iscsi_conn.h"
#include "utility.h"

pthread_mutex_t port_mutex;
int port_conn_num;
iscsi_conn_t	*conn_head = NULL;
iscsi_conn_t	*conn_tail = NULL;

void
port_init(void)
{
	(void) pthread_mutex_init(&port_mutex, NULL);
	port_conn_num = 0;
}

void
canonicalize_sockaddr(struct sockaddr_storage *st)
{
	struct in6_addr *addr6 = &((struct sockaddr_in6 *)st)->sin6_addr;

	/*
	 * If target address is IPv4 mapped IPv6 address convert it to IPv4
	 * address.
	 */
	if (st->ss_family == AF_INET6 &&
	    (IN6_IS_ADDR_V4MAPPED(addr6) || IN6_IS_ADDR_V4COMPAT(addr6))) {
		struct in_addr *addr = &((struct sockaddr_in *)st)->sin_addr;
		IN6_V4MAPPED_TO_INADDR(addr6, addr);
		st->ss_family = AF_INET;
	}
}


void *
port_watcher(void *v)
{
	int			s;
	int			fd;
	int			on = 1;
	char			debug[80];
	struct sockaddr_in	sin_ip;
	struct sockaddr_in6	sin6_ip;
	struct sockaddr_storage	st;
	socklen_t		socklen;
	iscsi_conn_t		*conn;
	port_args_t		*p = (port_args_t *)v;
	target_queue_t		*q = p->port_mgmtq;
	int			l;
	const int		just_say_no = 1;
	pthread_t		junk;

	/*
	 * Try creating an IPv6 socket first
	 * If failed, try creating an IPv4 socket
	 */
	if ((s = socket(PF_INET6, SOCK_STREAM, 0)) == -1) {

		queue_str(q, Q_GEN_ERRS, msg_log, "Opening IPv4 socket");
		if ((s = socket(PF_INET, SOCK_STREAM, 0)) == -1) {
			queue_str(q, Q_GEN_ERRS, msg_log,
			    "Can't open socket");
			return (NULL);
		} else {
			bzero(&sin_ip, sizeof (sin_ip));
			sin_ip.sin_family = AF_INET;
			sin_ip.sin_port = htons(p->port_num);
			sin_ip.sin_addr.s_addr = INADDR_ANY;

			(void) setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
			    (char *)&on, sizeof (on));

			if ((bind(s, (struct sockaddr *)&sin_ip,
			    sizeof (sin_ip))) < 0) {
				(void) snprintf(debug, sizeof (debug),
				    "bind on port %d failed, errno %d",
				    p->port_num, errno);
				queue_str(q, Q_GEN_ERRS, msg_status, debug);
				return (NULL);
			}
		}

	} else {

		queue_str(q, Q_GEN_DETAILS, msg_log, "Got IPv6 socket");
		bzero(&sin6_ip, sizeof (sin6_ip));
		sin6_ip.sin6_family = AF_INET6;
		sin6_ip.sin6_port = htons(p->port_num);
		sin6_ip.sin6_addr = in6addr_any;

		(void) setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char *)&on,
		    sizeof (on));

		if ((bind(s, (struct sockaddr *)&sin6_ip, sizeof (sin6_ip)))
		    < 0) {
			(void) snprintf(debug, sizeof (debug),
			    "bind on port %d failed, errno %d",
			    p->port_num, errno);
			queue_str(q, Q_GEN_ERRS, msg_status, debug);
			return (NULL);
		}
	}

	if (listen(s, 128) < 0) {
		queue_str(q, Q_GEN_ERRS, msg_status, "listen failed");
		return (NULL);
	}

	/*CONSTANTCONDITION*/
	while (1) {

		socklen = sizeof (st);
		if ((fd = accept(s, (struct sockaddr *)&st,
		    &socklen)) < 0) {
			if (errno != EINTR)
				queue_prt(q, Q_GEN_ERRS,
				    "accept failed, %s", strerror(errno));
			(void) sleep(1);
			continue;
		}

		l = 128 * 1024;
		if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (char *)&l,
		    sizeof (l)) < 0)
			queue_str(q, Q_GEN_ERRS, msg_status,
			    "setsockopt failed");
		if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (char *)&l,
		    sizeof (l)) < 0)
			queue_str(q, Q_GEN_ERRS, msg_status,
			    "setsockopt failed");
		l = 1;
		if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (char *)&l,
		    sizeof (l)) < 0)
			queue_str(q, Q_GEN_ERRS, msg_status,
			    "setsockopt keepalive failed");

		if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY,
		    (char *)&just_say_no, sizeof (just_say_no)) != 0)
			queue_str(q, Q_GEN_ERRS, msg_status,
			    "setsockopt NODELAY failed");

		if ((conn = calloc(1, sizeof (iscsi_conn_t))) == NULL) {
			/*
			 * If we fail to get memory this is all rather
			 * pointless, since it's unlikely that queue_str
			 * could malloc memory to send a message.
			 */
			queue_str(q, Q_GEN_ERRS, msg_status,
			    "connection malloc failed");
			return (NULL);
		}

		/*
		 * Save initiator address for future use.
		 */
		canonicalize_sockaddr(&st);
		conn->c_initiator_sockaddr = st;

		/*
		 * Save target address for future use.
		 */
		socklen = sizeof (st);
		if (getsockname(fd, (struct sockaddr *)&st, &socklen) == 0)
			canonicalize_sockaddr(&st);
		else
			st.ss_family = AF_UNSPEC;
		conn->c_target_sockaddr = st;

		conn->c_fd	= fd;
		conn->c_mgmtq	= q;
		conn->c_up_at	= time(NULL);
		conn->c_state	= S1_FREE;
		(void) pthread_mutex_init(&conn->c_mutex, NULL);
		(void) pthread_mutex_init(&conn->c_state_mutex, NULL);
		(void) pthread_mutex_lock(&port_mutex);
		conn->c_num	= port_conn_num++;
		if (conn_head == NULL) {
			conn_head = conn;
			assert(conn_tail == NULL);
			conn_tail = conn;
		} else {
			conn_tail->c_next = conn;
			conn->c_prev = conn_tail;
			conn_tail = conn;
		}
		(void) pthread_mutex_unlock(&port_mutex);

		(void) pthread_create(&junk, NULL, conn_process, conn);
	}
	return (NULL);
}

void
port_conn_remove(iscsi_conn_t *c)
{
	iscsi_conn_t	*n;

	(void) pthread_mutex_lock(&port_mutex);
	if (conn_head == c) {
		conn_head = c->c_next;
		if (conn_head == NULL)
			conn_tail = NULL;
		else
			conn_head->c_prev = NULL;
	} else {
		n = c->c_prev;
		n->c_next = c->c_next;
		if (c->c_next != NULL)
			c->c_next->c_prev = n;
		else {
			assert(conn_tail == c);
			conn_tail = n;
		}
	}

	/*
	 * The connection queue is freed here so that it's protected by
	 * locks. The main thread of the deamon when processing incoming
	 * management requests will send them on the connection queues.
	 * The main thread will grab the port_mutex so that we know the
	 * queue is still valid.
	 */
	queue_free(c->c_dataq, conn_queue_data_remove);
	(void) pthread_mutex_unlock(&port_mutex);
}
