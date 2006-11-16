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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <unistd.h>
#include <strings.h>
#include <stdlib.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <sys/filio.h>
#include <utility.h>
#include <synch.h>
#include <sys/stropts.h>
#include <libxml/xmlreader.h>
#include <iscsitgt_impl.h>

#include "queue.h"
#include "port.h"
#include "utility.h"

static void
mgmt_monitor_queue(port_args_t *p)
{
	target_queue_t		*in		= p->port_dataq;
	msg_t			*m;
	int			process		= True;
	char			*data,
				*output;

	do {
		m = queue_message_get(in);
		switch (m->msg_type) {
		case msg_conn_lost:
			process = False;
			break;

		case msg_log:
			data = (char *)m->msg_data;
			output = NULL;
			tgt_buf_add(&output, "log", data);
			(void) write(p->port_socket, output, strlen(output));
			free(output);
			break;

		case msg_mgmt_rply:
			data = (char *)m->msg_data;
			output = NULL;
			tgt_buf_add(&output, "mgmt", data);
			(void) write(p->port_socket, output, strlen(output));
			free(output);
			free(data);
			m->msg_data = NULL;
			break;

		default:
			break;
		}

		if (m->msg_data)
			free(m->msg_data);
		queue_message_free(m);

	} while (process == True);
}

static void *
mgmt_process(void *v)
{
	port_args_t		*p		= (port_args_t *)v;
	int			nbytes,
				nmsgs,
				pval,
				ret;
	char			*buf;
	nfds_t			nfds		= 1;
	struct pollfd		fds[1];
	xmlTextReaderPtr	r;
	tgt_node_t		*node		= NULL;
	mgmt_request_t		m;

	fds[0].fd = p->port_socket;
	fds[0].events = POLLIN;

	m.m_q		= p->port_dataq;
	m.m_request	= mgmt_parse_xml;
	m.m_time	= time(NULL);
	m.m_targ_name	= NULL;

	while ((pval = poll(fds, nfds, -1)) != -1) {
		if ((nmsgs = ioctl(p->port_socket, FIONREAD, &nbytes)) == -1) {

			queue_message_set(p->port_dataq, 0, msg_conn_lost, 0);
			break;

		} else if ((nmsgs == 0) && (nbytes == 0)) {

			queue_message_set(p->port_dataq, 0, msg_conn_lost, 0);
			break;

		} else if ((buf = malloc(nbytes)) == NULL) {

			queue_message_set(p->port_dataq, 0, msg_conn_lost, 0);
			break;

		} else if (read(p->port_socket, buf, nbytes) != nbytes) {

			queue_message_set(p->port_dataq, 0, msg_conn_lost, 0);
			break;

		}

		buf[nbytes] = '\0';
		r = (xmlTextReaderPtr)xmlReaderForMemory(buf, nbytes,
		    NULL, NULL, 0);
		if (r != NULL) {
			ret = xmlTextReaderRead(r);
			while (ret == 1) {
				if (tgt_node_process(r, &node) == False)
					break;
				ret = xmlTextReaderRead(r);
			}
			if (node != NULL) {
				m.m_u.m_node = node;
				queue_message_set(p->port_mgmtq, 0,
					msg_mgmt_rqst, &m);
			}
			xmlFreeTextReader(r);
			tgt_node_free(node);
			node = NULL;
		}

	}

	if (pval == -1)
		queue_message_set(p->port_dataq, 0, msg_conn_lost, 0);
	(void) close(p->port_socket);
	p->port_socket = -1;
	return (NULL);
}

void *
port_management(void *v)
{
	int			s,
				fd,
				on = 1;
	struct sockaddr_in	sin_ip;
	struct sockaddr_in6	sin6_ip;
	socklen_t		fromlen;
	struct sockaddr_storage	from;
	port_args_t		*p = (port_args_t *)v;
	target_queue_t		*q = p->port_mgmtq;
	int			l;
	pthread_t		junk;
	char			debug[80];

	if ((s = socket(PF_INET6, SOCK_STREAM, 0)) == -1) {
		if ((s = socket(PF_INET, SOCK_STREAM, 0)) == -1) {
			queue_str(q, Q_GEN_ERRS, msg_status,
			    "Can't open socket");
			return (NULL);
		} else {

			bzero(&sin_ip, sizeof (sin_ip));
			sin_ip.sin_family	= AF_INET;
			sin_ip.sin_port		= htons(p->port_num);
			sin_ip.sin_addr.s_addr	= INADDR_ANY;

			(void) setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
			    (char *)&on, sizeof (on));

			if ((bind(s, (struct sockaddr *)&sin_ip,
				sizeof (sin_ip))) < 0) {
				(void) snprintf(debug, sizeof (debug),
				    "bind on port %d failed\n", p->port_num);
				queue_str(q, Q_GEN_ERRS, msg_status, debug);
				return (NULL);
			}
		}
	} else {

		bzero(&sin6_ip, sizeof (sin6_ip));
		sin6_ip.sin6_family	= AF_INET6;
		sin6_ip.sin6_port	= htons(p->port_num);
		sin6_ip.sin6_addr	= in6addr_any;

		(void) setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char *)&on,
		    sizeof (on));

		if ((bind(s, (struct sockaddr *)&sin6_ip, sizeof (sin6_ip)))
		    < 0) {
			(void) snprintf(debug, sizeof (debug),
			    "bind on port %d failed\n",
			    p->port_num);
			queue_str(q, Q_GEN_ERRS, msg_status, debug);
			return (NULL);
		}
	}

	if (listen(s, 5) < 0) {
		queue_str(q, Q_GEN_ERRS, msg_status, "listen failed");
		return (NULL);
	}

	/*CONSTANTCONDITION*/
	while (1) {
		fromlen = sizeof (from);
		if ((fd = accept(s, (struct sockaddr *)&from,
		    &fromlen)) < 0) {
			queue_str(q, Q_GEN_ERRS, msg_status, "accept failed");
			return (NULL);
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


		p->port_socket = fd;
		(void) pthread_create(&junk, NULL, mgmt_process, p);

		mgmt_monitor_queue(p);
	}
	return (NULL);
}
