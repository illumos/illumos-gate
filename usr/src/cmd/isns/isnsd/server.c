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

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <poll.h>
#ifdef DEBUG
#include <time.h>
#endif

#include "isns_server.h"
#include "isns_cache.h"
#include "isns_pdu.h"
#include "isns_msgq.h"
#include "isns_func.h"
#include "isns_log.h"
#include "isns_provider.h"

/* external functions */
#ifdef DEBUG
extern void dump_pdu1(isns_pdu_t *);
extern int verbose_tc;
#endif

extern boolean_t time_to_exit;

void *
isns_connection(
	void *arg
)
{
	int status = 0;

	conn_arg_t *conn;

	isns_pdu_t *pdu, *combined_pdu, *new_combined_pdu;
	uint8_t *payload_ptr;
	size_t pdu_sz;

	conn = (conn_arg_t *)arg;

	conn->out_packet.pdu = NULL;
	conn->out_packet.sz = 0;
	combined_pdu = NULL;
	pdu = NULL;

	while (status == 0 &&
	    time_to_exit == B_FALSE &&
	    isns_rcv_pdu(conn->so, &pdu, &pdu_sz, ISNS_RCV_TIMEOUT) > 0) {
		uint16_t flags = pdu->flags;
		if (ISNS_MSG_RECEIVED_ENABLED()) {
			char buf[INET6_ADDRSTRLEN];
			struct sockaddr_storage *ssp = &conn->ss;
			struct sockaddr_in *sinp = (struct sockaddr_in *)ssp;
			if (ssp->ss_family == AF_INET) {
				(void) inet_ntop(AF_INET,
				    (void *)&(sinp->sin_addr),
				    buf, sizeof (buf));
			} else {
				(void) inet_ntop(AF_INET6,
				    (void *)&(sinp->sin_addr),
				    buf, sizeof (buf));
			}
			ISNS_MSG_RECEIVED((uintptr_t)buf);
		}

		if ((flags & ISNS_FLAG_FIRST_PDU) == ISNS_FLAG_FIRST_PDU) {
			if (combined_pdu != NULL || pdu->seq != 0) {
				goto conn_done;
			}
			combined_pdu = pdu;
			pdu = NULL;
		} else {
			if (combined_pdu == NULL ||
			    combined_pdu->func_id != pdu->func_id ||
			    combined_pdu->xid != pdu->xid ||
			    (combined_pdu->seq + 1) != pdu->seq) {
				/* expect the first pdu, the same tranx id */
				/* and the next sequence id */
				goto conn_done;
			}
			new_combined_pdu = (isns_pdu_t *)malloc(
			    ISNSP_HEADER_SIZE +
			    combined_pdu->payload_len +
			    pdu->payload_len);
			if (new_combined_pdu == NULL) {
				goto conn_done;
			}
			(void) memcpy((void *)new_combined_pdu,
			    (void *)combined_pdu,
			    ISNSP_HEADER_SIZE + combined_pdu->payload_len);
			payload_ptr = new_combined_pdu->payload +
			    combined_pdu->payload_len;
			(void) memcpy((void *)payload_ptr,
			    (void *)pdu->payload,
			    pdu->payload_len);
			new_combined_pdu->seq = pdu->seq;
			free(combined_pdu);
			combined_pdu = new_combined_pdu;
			free(pdu);
			pdu = NULL;
		}
		if ((flags & ISNS_FLAG_LAST_PDU) == ISNS_FLAG_LAST_PDU) {
#ifdef DEBUG
			time_t t;
			clock_t c;

			dump_pdu1(combined_pdu);

			if (verbose_tc != 0) {
				t = time(NULL);
				c = clock();
			}
#endif

			conn->in_packet.pdu = combined_pdu;
			conn->out_packet.pl = 0;
			conn->ec = 0;

			if (packet_split_verify(conn) == 0) {
				(void) cache_lock(conn->lock);
				status = conn->handler(conn);
				conn->ec = cache_unlock(conn->lock, conn->ec);
			}

			switch (status) {
			case -1:
				/* error */
				break;
			case 0:
				status = isns_response(conn);

				isnslog(LOG_DEBUG, "isns_connection",
				    "Response status: %d.", status);
				if (ISNS_MSG_RESPONDED_ENABLED()) {
					char buf[INET6_ADDRSTRLEN];
					struct sockaddr_storage *ssp =
					    &conn->ss;
					struct sockaddr_in *sinp =
					    (struct sockaddr_in *)ssp;
					if (ssp->ss_family == AF_INET) {
						(void) inet_ntop(AF_INET,
						    (void *)&(sinp->sin_addr),
						    buf, sizeof (buf));
					} else {
						(void) inet_ntop(AF_INET6,
						    (void *)&(sinp->sin_addr),
						    buf, sizeof (buf));
					}
					ISNS_MSG_RESPONDED((uintptr_t)buf);
				}
				break;
			default:
				/* no need to send response message */
				status = 0;
				break;
			}

#ifdef DEBUG
			if (verbose_tc != 0) {
				t = time(NULL) - t;
				c = clock() - c;
				printf("time %d clock %.4lf -msg response\n",
				    t, c / (double)CLOCKS_PER_SEC);
			}
#endif
			free(combined_pdu);
			combined_pdu = NULL;
		}
	}

conn_done:
	if (pdu != NULL) {
		free(pdu);
	}
	if (combined_pdu != NULL) {
		free(combined_pdu);
	}
	(void) close(conn->so);
	(void) free(conn->out_packet.pdu);
	(void) free(conn);

	/* decrease the thread ref count */
	dec_thr_count();

	return (NULL);
}

/* the iSNS server port watcher */

void *
isns_port_watcher(
	/* LINTED E_FUNC_ARG_UNUSED */
	void *arg
)
{
	int s, f;
	int opt = 1;
	struct sockaddr_in sin;
	struct sockaddr_in *sinp;
	struct sockaddr_storage *ssp;
	socklen_t sslen;
	char buf[INET6_ADDRSTRLEN];
	pthread_t tid;
	struct pollfd fds;
	int poll_ret;

	conn_arg_t *conn;

	if ((s = socket(AF_INET, SOCK_STREAM, 0)) != -1) {
		/* IPv4 */
		isnslog(LOG_DEBUG, "isns_port_watcher", "IPv4 socket created.");
		(void) setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (void *)&opt,
		    sizeof (opt));

		sin.sin_family		= AF_INET;
		sin.sin_port		= htons(ISNS_DEFAULT_SERVER_PORT);
		sin.sin_addr.s_addr	= htonl(INADDR_ANY);

		if (bind(s, (struct sockaddr *)&sin, sizeof (sin)) < 0) {
			isnslog(LOG_DEBUG, "isns_port_watcher",
			    "binding on server port failed: %%m");
			goto watch_failed;
		}
		isnslog(LOG_DEBUG, "isns_port_watcher",
		    "successful binding on server port.");
	} else {
		isnslog(LOG_DEBUG, "isns_port_watcher",
		    "cannot create socket: %%m.");
		goto watch_failed;
	}

	if (listen(s, 5) < 0) {
		isnslog(LOG_DEBUG, "isns_port_watcher",
		    "listening on server port failed: %%m.");
		goto watch_failed;
	}
	isnslog(LOG_DEBUG, "isns_port_watcher", "listening on server port ok.");

	fds.fd = s;
	fds.events = (POLLIN | POLLRDNORM);
	fds.revents = 0;

	/* waiting for connections */
	for (;;) {
		if (time_to_exit) {
			return (NULL);
		}

		poll_ret = poll(&fds, 1, 1000);
		if (poll_ret <= 0) {
			continue;
		}

		/* allocate a connection argument */
		conn = (conn_arg_t *)malloc(sizeof (conn_arg_t));
		if (conn == NULL) {
			isnslog(LOG_DEBUG, "isns_port_watcher",
			    "malloc() failed.");
			goto watch_failed;
		}
		ssp = &conn->ss;
		sslen = sizeof (conn->ss);
		f = accept(s, (struct sockaddr *)ssp, &sslen);
		if (f < 0) {
			isnslog(LOG_DEBUG, "isns_port_watcher",
			    "accepting connection failed: %%m.");
			goto watch_failed;
		}
		sinp = (struct sockaddr_in *)ssp;
		if (ssp->ss_family == AF_INET) {
			(void) inet_ntop(AF_INET, (void *)&(sinp->sin_addr),
			    buf, sizeof (buf));
		} else {
			(void) inet_ntop(AF_INET6, (void *)&(sinp->sin_addr),
			    buf, sizeof (buf));
		}
		isnslog(LOG_DEBUG, "isns_port_watcher",
		    "connection from %s:%d.", buf,
		    sinp->sin_port);

		if (ISNS_CONNECTION_ACCEPTED_ENABLED()) {
			ISNS_CONNECTION_ACCEPTED((uintptr_t)buf);
		}

		conn->so = f;
		/* create an isns connection */
		if (pthread_create(&tid, NULL,
		    isns_connection, (void *)conn) != 0) {
			(void) close(f);
			(void) free(conn);
			isnslog(LOG_DEBUG, "isns_port_watcher",
			    "pthread_create() failed.");
		} else {
			/* increase the thread ref count */
			inc_thr_count();
		}
	}

watch_failed:
	shutdown_server();
	return (NULL);
}

static uint16_t xid = 0;
static pthread_mutex_t xid_mtx = PTHREAD_MUTEX_INITIALIZER;
uint16_t
get_server_xid(
)
{
	uint16_t tmp;

	(void) pthread_mutex_lock(&xid_mtx);
	tmp = ++ xid;
	(void) pthread_mutex_unlock(&xid_mtx);

	return (tmp);
}
