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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>
#include <ctype.h>
#include <pthread.h>
#include <netdb.h>
#include <libintl.h>
#include <errno.h>
#include <assert.h>
#include <fcntl.h>
#include <sys/byteorder.h>

#include "isns_protocol.h"
#include "isns_client.h"
#include "queue.h"

extern target_queue_t	*mgmtq;

static	uint16_t	xid = 0;
static	pthread_mutex_t	xid_lock = PTHREAD_MUTEX_INITIALIZER;

/*
 * more than 1 processes can accessing get_xid
 */
static uint16_t
get_xid()
{
	uint16_t	tmp;

	(void) pthread_mutex_lock(&xid_lock);
	tmp = xid++;
	(void) pthread_mutex_unlock(&xid_lock);
	return (tmp);
}

void
ntoh_tlv(isns_tlv_t *tlv)
{
	uint32_t	val;

	tlv->attr_id = ntohl(tlv->attr_id);
	tlv->attr_len = ntohl(tlv->attr_len);

	switch (tlv->attr_id) {
		case ISNS_DELIMITER_ATTR_ID:
			break;
		case ISNS_ISCSI_NAME_ATTR_ID:
		case ISNS_EID_ATTR_ID:
		case ISNS_ISCSI_ALIAS_ATTR_ID:
		case ISNS_PORTAL_NAME_ATTR_ID:
		case ISNS_PG_ISCSI_NAME_ATTR_ID:
			break;

		case ISNS_PORTAL_IP_ADDR_ATTR_ID:
		case ISNS_PG_PORTAL_IP_ADDR_ATTR_ID:
			bcopy(tlv->attr_value, &val, 4);
			*tlv->attr_value = ntohl(val);
			break;

		default:
			switch (tlv->attr_len) {
				case 4:
					val = ntohl(
					    (uint32_t)(*tlv->attr_value));
					bcopy(&val, tlv->attr_value, 4);
					break;
				default:
					break;
			}
			break;
	}
}

/*
 * print_ntoh_tlv print network byte order tag-length-value attribute
 */
void
print_ntoh_tlv(isns_tlv_t *tlv)
{
	uint32_t	tag, len, val, pf_type;
	char		buf[256];
	struct sockaddr_in6	sin6;

	tag = ntohl(tlv->attr_id);
	len = ntohl(tlv->attr_len);

	if (len == 0) {
		queue_prt(mgmtq, Q_ISNS_DBG, "Zero length tag: %d\n", tag);
		return;
	}

	switch (tag) {
		case ISNS_DELIMITER_ATTR_ID:
			break;
		case ISNS_ISCSI_NAME_ATTR_ID:
		case ISNS_EID_ATTR_ID:
		case ISNS_ISCSI_ALIAS_ATTR_ID:
		case ISNS_PORTAL_NAME_ATTR_ID:
		case ISNS_PG_ISCSI_NAME_ATTR_ID:
			queue_prt(mgmtq, Q_ISNS_DBG,
			    "Tag %d: Value: %s\n", tag, tlv->attr_value);
			break;

		case ISNS_PORTAL_IP_ADDR_ATTR_ID:
		case ISNS_PG_PORTAL_IP_ADDR_ATTR_ID:
			bcopy(tlv->attr_value, &pf_type, 4);
			pf_type = ntohl(pf_type);
			pf_type = (pf_type == sizeof (in6_addr_t))
			    ? PF_INET6 : PF_INET;
			switch (pf_type) {
				case PF_INET:
					/* RFC2372 IPv4 mapped IPv6 address */
					if (inet_ntop(pf_type,
					    (void *)&tlv->attr_value[12],
					    buf, 256) == NULL) {
						syslog(LOG_ERR,
						    "inet_ntop failed");
						break;
					}
					queue_prt(mgmtq, Q_ISNS_DBG,
					    "IP_ADDR %s\n", buf);
					break;
				case PF_INET6:
					bcopy(tlv->attr_value, &sin6,
					    sizeof (struct sockaddr_in6));
					(void) inet_ntop(pf_type,
					    (void *)&sin6.sin6_addr,
					    buf, 256);
					break;
				default:
					queue_prt(mgmtq, Q_ISNS_DBG,
					    "unknown pf_type\n");
					break;
			}
			break;

		default:
			switch (len) {
				case 4:
					bcopy(tlv->attr_value, &val, 4);
					val = ntohl(val);
					queue_prt(mgmtq, Q_ISNS_DBG,
					    "Tag: %d Value: %ld\n", tag, val);
					break;
				default:
					break;
			}
			break;
	}
}

void
print_attr(isns_tlv_t *attr, void *pval, uint32_t ival)
{
	uint32_t	tag = ntohl(attr->attr_id);
	uint32_t	len = ntohl(attr->attr_len);
	uint32_t	pf_type;
	char		buf[256];

	queue_prt(mgmtq, Q_ISNS_DBG, "Tag: %d Length: %d\n", tag, len);
	switch (tag) {
		case ISNS_DELIMITER_ATTR_ID:
			break;

		case ISNS_ISCSI_NAME_ATTR_ID:
		case ISNS_EID_ATTR_ID:
		case ISNS_ISCSI_ALIAS_ATTR_ID:
		case ISNS_PORTAL_NAME_ATTR_ID:
		case ISNS_PG_ISCSI_NAME_ATTR_ID:
			if (len && pval != NULL) {
				queue_prt(mgmtq, Q_ISNS_DBG, "Value: %s\n",
				    attr->attr_value);
			}
			break;

		case ISNS_PORTAL_IP_ADDR_ATTR_ID:
		case ISNS_PG_PORTAL_IP_ADDR_ATTR_ID:
			if (len) {
				pf_type = (ival == sizeof (in6_addr_t))
				    ? PF_INET6 : PF_INET;
				(void) inet_ntop(pf_type, pval, buf, 256);
				queue_prt(mgmtq, Q_ISNS_DBG, "IP_ADDR %s\n",
				    buf);
			}
			break;

		default:
		switch (len) {
			case 4:
				queue_prt(mgmtq, Q_ISNS_DBG,
				    "Value: %d\n",
				    ntohl(*attr->attr_value));
				break;
			default:
				break;
		}
		break;
	}
}

void
print_isns_hdr(isns_hdr_t *hdr)
{
	queue_prt(mgmtq, Q_ISNS_DBG, "hdr->version %d\n", hdr->version);
	queue_prt(mgmtq, Q_ISNS_DBG, "hdr->func_id %x\n", hdr->func_id);
	queue_prt(mgmtq, Q_ISNS_DBG, "hdr->pdu_len %d\n", hdr->pdu_len);
	queue_prt(mgmtq, Q_ISNS_DBG, "hdr->flags %x\n", hdr->flags);
	queue_prt(mgmtq, Q_ISNS_DBG, "hdr->xid %d\n", hdr->xid);
	queue_prt(mgmtq, Q_ISNS_DBG, "hdr->seqid %d\n", hdr->seqid);
}

void
ntoh_isns_hdr(isns_hdr_t *hdr)
{
	hdr->version = ntohs(hdr->version);
	hdr->func_id = ntohs(hdr->func_id);
	hdr->pdu_len = ntohs(hdr->pdu_len);
	hdr->flags = ntohs(hdr->flags);
	hdr->xid = ntohs(hdr->xid);
	hdr->seqid = ntohs(hdr->seqid);
}

int
isns_append_attr(isns_pdu_t *pdu, uint32_t tag,  uint32_t len,
	void *pval, uint32_t ival)
{
	uint32_t	val;
	uint32_t	pad_len;
	uint16_t	pdu_len;
	isns_tlv_t	*attr;
	char		*tlv;

	if (pdu == NULL) {
		syslog(LOG_ALERT, "NULL PDU\n");
		return (-1);
	}

	/* get current pdu payload length */
	pdu_len = ntohs(pdu->payload_len);

	/* pad 4 bytes alignment */
	pad_len = PAD4(len);

	if ((pdu_len + pad_len) > MAX_PDU_PAYLOAD_SZ) {
		syslog(LOG_ALERT, "Exceeded PDU size\n");
		return (-1);
	}

	if ((attr = (isns_tlv_t *)malloc(ISNS_ATTR_SZ(pad_len))) == NULL) {
		syslog(LOG_ALERT, "Malloc error");
		return (-1);
	}
	bzero(attr, ISNS_ATTR_SZ(pad_len));
	attr->attr_id = htonl(tag);
	attr->attr_len = htonl(pad_len);

	switch (tag) {
		case ISNS_DELIMITER_ATTR_ID:
			break;

		case ISNS_ISCSI_NAME_ATTR_ID:
		case ISNS_EID_ATTR_ID:
		case ISNS_ISCSI_ALIAS_ATTR_ID:
		case ISNS_PORTAL_NAME_ATTR_ID:
		case ISNS_PG_ISCSI_NAME_ATTR_ID:
			if (len && pval != NULL) {
				bcopy(pval, attr->attr_value, len);
			}
			break;

		case ISNS_PORTAL_IP_ADDR_ATTR_ID:
		case ISNS_PG_PORTAL_IP_ADDR_ATTR_ID:
			if (len && ival == sizeof (in_addr_t)) {
				/* IPv4 */
				attr->attr_value[10] = 0xFF;
				attr->attr_value[11] = 0xFF;
				bcopy(pval, ((attr->attr_value) + 12), ival);
			} else if (len && ival == sizeof (in6_addr_t)) {
				/* IPv6 */
				bcopy(pval, attr->attr_value, ival);
			}
			break;

		default:
			switch (len) {
				case 4:
					val = htonl(ival);
					bcopy(&val, attr->attr_value, 4);
					break;
				default:
					break;
			}
			break;
	}

	/* copy attribute to pdu */
	tlv = (char *)pdu + ISNSP_HEADER_SIZE + pdu_len;
	bcopy(attr, tlv, ISNS_ATTR_SZ(pad_len));
	pdu->payload_len = htons(pdu_len + ISNS_ATTR_SZ(pad_len));

	/* debug only */
	print_ntoh_tlv(attr);

	free(attr);
	return (0);
}

int
isns_create_pdu(uint16_t func_id, uint32_t flags, isns_pdu_t **pdu)
{
	size_t	pdu_sz = MAX_PDU_SZ;

	if ((*pdu = (isns_pdu_t *)malloc(pdu_sz)) == NULL) {
		syslog(LOG_ERR, "isns_create_pdu malloc failure");
		return (-1);
	}

	bzero(*pdu, pdu_sz);
	(*pdu)->payload_len = 0;
	(*pdu)->seq = 0;
	(*pdu)->xid = htons(get_xid());
	(*pdu)->version = htons((uint16_t)ISNSP_VERSION);
	(*pdu)->func_id = htons((uint16_t)(func_id));
	(*pdu)->flags = htons((uint16_t)(flags | ISNS_FLAG_CLIENT |
	    ISNS_FLAG_FIRST_PDU | ISNS_FLAG_LAST_PDU));
	return (0);
}

void
isns_free_pdu(void *pdu)
{
	free(pdu);
}

/*
 * Desc: Open connection to the isns server
 * Args: isns server name or isns server ip-addr
 * Return: -1 if open failed, descriptor to socket if open succeeded
 */
int
isns_open(char *server)
{
	struct addrinfo		hints, *ai, *aip;
	struct sockaddr		*sa;
	struct sockaddr_in	sin;
	struct sockaddr_in6	sin6;
	size_t	sa_len;
	int	so;
	int	ret;
	fd_set rfdset;
	fd_set wfdset;
	fd_set errfdset;
	struct timeval timeout;
	Boolean_t shouldsockblock = False;
	int socket_ready = 0;
	timeout.tv_sec = 5;   /* 5 Secs Timeout */
	timeout.tv_usec = 0;   /* 0 uSecs Timeout */

	if (server == NULL) {
		syslog(LOG_ERR, "ISNS server ID required");
		return (-1);
	}

	bzero(&hints, sizeof (struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	if ((ret = getaddrinfo(server, NULL, NULL, &ai)) != 0) {
		syslog(LOG_ALERT, "getaddrinfo failed on server %s: %s", server,
		    gai_strerror(ret));
		return (-1);
	}

	aip = ai;
	do {
		so = socket(aip->ai_family, SOCK_STREAM, 0);
		if (so != -1) {

			/* set it to non blocking so connect wont hang */
			if (setsocknonblocking(so) == -1) {
				(void) close(so);
				continue;
			}

			sa_len = aip->ai_addrlen;
			switch (aip->ai_family) {
				case PF_INET:
					bzero(&sin,
					    sizeof (struct sockaddr_in));
					sa = (struct sockaddr *)&sin;
					bcopy(aip->ai_addr, sa, sa_len);
					sin.sin_port = htons(
					    ISNS_DEFAULT_SERVER_PORT);
					break;
				case PF_INET6:
					bzero(&sin6,
					    sizeof (struct sockaddr_in6));
					sa = (struct sockaddr *)&sin6;
					bcopy(aip->ai_addr, sa, sa_len);
					sin6.sin6_port =
					    htons(ISNS_DEFAULT_SERVER_PORT);
					break;
				default:
					syslog(LOG_ALERT, "Bad protocol");
					(void) close(so);
					continue;
			}

			ret = connect(so, sa, sa_len);
			if (ret == 0) {
				/*
				 * connection succeeded with out
				 * blocking
				 */
				shouldsockblock = True;
			}

			if (ret < 0) {
				if (errno == EINPROGRESS) {
					FD_ZERO(&rfdset);
					FD_ZERO(&wfdset);
					FD_ZERO(&errfdset);
					FD_SET(so, &rfdset);
					FD_SET(so, &wfdset);
					FD_SET(so, &errfdset);
					socket_ready =
					    select(so + 1, &rfdset, &wfdset,
					    &errfdset, &timeout);
					if (socket_ready < 0) {
						syslog(LOG_ALERT,
						    "failed to connect with"
						" isns, err=%d", errno);
						(void) close(so);
					} else if (socket_ready == 0) {
						syslog(LOG_ALERT,
						    "time out failed"
						    " to connect with isns");
						(void) close(so);
					} else { /* Socket is ready */
						/*
						 * Check if socket is ready
						 */
						if (is_socket_ready(so,
						    &rfdset, &wfdset,
						    &errfdset) == True)
							shouldsockblock = True;
						else
							(void) close(so);
					}
				} else {
					syslog(LOG_WARNING,
					    "Connect failed no progress");
					(void) close(so);
				}
			}

			if (shouldsockblock == True) {
				if (-1 == setsockblocking(so)) {
					(void) close(so);
					shouldsockblock = False;
				} else {
					freeaddrinfo(ai);
					return (so);
				}
			}

		}
	} while ((aip = aip->ai_next) != NULL);

	if (ai != NULL)
		freeaddrinfo(ai);
	return (-1);
}

/*
 * According to:
 * UNIX Network Programming Volume 1, Third Edition:
 * The Sockets Networking APIBOOK:
 *
 * When the connection completes successfully, the descriptor becomes
 * writable (p. 531 of TCPv2).
 * When the connection establishment encounters an error, the descriptor
 * becomes both readable and writable (p. 530 of TCPv2).
 */
Boolean_t
is_socket_ready(int so, fd_set *rfdset, fd_set *wfdset,
		    fd_set *errfdset)
{
	if ((FD_ISSET(so, wfdset) &&
	    FD_ISSET(so, rfdset)) ||
	    FD_ISSET(so, errfdset)) {
		return (False);
	} else {
		return (True);
	}
}

int
setsocknonblocking(int so)
{
	int flags;
	/* set it to non blocking */
	if (-1 == (flags = fcntl(so, F_GETFL, 0))) {
		syslog(LOG_WARNING,
		    "Failed to get socket flags. Blocking..");
		return (-1);
	}

	if (fcntl(so, F_SETFL, flags | O_NONBLOCK) == -1) {
		syslog(LOG_WARNING,
		    "Failed to set socket in non blocking mode");
		return (-1);
	}
	return (0);
}

int
setsockblocking(int so)
{
	int flags;
	/* set it to non blocking */
	if (-1 == (flags = fcntl(so, F_GETFL, 0))) {
		syslog(LOG_WARNING, " Failed to get flags on socket..");
		return (-1);
	}

	flags &= ~O_NONBLOCK;
	if (fcntl(so, F_SETFL, flags) == -1) {
		syslog(LOG_WARNING, " failed to set socket to blocking");
		return (-1);
	}
	return (0);
}


void
isns_close(int so)
{
	if (so) {
		(void) close(so);
	}
}

/*
 * isns_send allocated pdu, caller needs to free pdu when done processing
 */
int
isns_send(int so, isns_pdu_t *pdu)
{
	size_t	len;

	assert(pdu != NULL);

	len = ISNSP_HEADER_SIZE + ntohs(pdu->payload_len);
	if (send(so, pdu, len, 0) == -1) {
		syslog(LOG_ALERT, "isns_send failure");
		return (-1);
	}
	return (0);
}

/*
 * Desc: isns_recv malloc memory for the isns response message, user needs
 *	to isns_free() memory after process the response message.  The
 *	isns header is converted to host byte order, the remaining TLV
 *	attributes can be converted using ntoh_tlv()
 */
int
isns_recv(int so, isns_rsp_t **pdu)
{
	isns_hdr_t	hdr, hdr1;
	isns_rsp_t	*rsp;
	uint8_t		*ptr;
	size_t		total_pdu_len;
	int		len;
	uint16_t	xid_x, func_id_x, seqid_x;
	boolean_t	done;

	*pdu = NULL;
	total_pdu_len = 0;
	seqid_x = 0;
	done = FALSE;

	do {
		/* read pdu header 1st */
		do {
			len = recv(so, &hdr1, ISNSP_HEADER_SIZE, MSG_WAITALL);
		} while ((len == -1) && (errno == EINTR));

		if (len != ISNSP_HEADER_SIZE) {
			syslog(LOG_ALERT, "isns_recv fail to read header");
			return (-1);
		}

		/* normalize the pdu header for processing */
		bcopy(&hdr1, &hdr, sizeof (isns_hdr_t));
		ntoh_isns_hdr(&hdr);

		if (IS_1ST_PDU(hdr.flags)) {
			if (hdr.seqid != 0) {
				syslog(LOG_ALERT, "ISNS out of sequence");
				return (-1);
			}
			xid_x = hdr.xid;
			func_id_x = hdr.func_id;
		}

		if (IS_LAST_PDU(hdr.flags)) {
			done = TRUE;
		}

		/* verify seq, xid, func_id */
		if (seqid_x != hdr.seqid) {
			syslog(LOG_ALERT, "ISNS out of sequence");
			return (-1);
		}
		if (xid_x != hdr.xid || func_id_x != hdr.func_id) {
			syslog(LOG_ALERT, "Non matching xid or func_id");
			return (-1);
		}

		++seqid_x;	/* next expected seqid */

		/* malloc size + previous payload length */
		if ((ptr = malloc(ISNSP_HEADER_SIZE + hdr.pdu_len
		    + total_pdu_len)) == NULL) {
			syslog(LOG_ALERT, "Malloc failure");
			return (-1);
		}
		bzero(ptr, ISNSP_HEADER_SIZE + hdr.pdu_len);

		if (hdr.seqid == 0) {
			*pdu = (void *)ptr;
			bcopy(&hdr1, ptr, ISNSP_HEADER_SIZE);
			ptr += ISNSP_HEADER_SIZE;
			if ((len = recv(so, ptr, hdr.pdu_len, MSG_WAITALL))
			    != hdr.pdu_len) {
				syslog(LOG_ERR,
				    "isns_recv fail to read 1st payload");
				free(*pdu);
				*pdu = NULL;
				return (-1);
			}
		} else {
			/* merge the pdu */
			bcopy(*pdu, ptr, ISNSP_HEADER_SIZE + total_pdu_len);
			free(*pdu);
			*pdu = (void *)ptr;
			ptr += (ISNSP_HEADER_SIZE + total_pdu_len);
			if (recv(so, ptr, hdr.pdu_len, MSG_WAITALL)
			    != hdr.pdu_len) {
				syslog(LOG_ERR,
				    "isns_recv fail to read payload");
				free(*pdu);
				*pdu = NULL;
				return (-1);
			}
		}
		total_pdu_len += hdr.pdu_len;

	} while (done == FALSE);

	/* normalize the response status */
	rsp = (isns_rsp_t *)*pdu;
	rsp->pdu_len = htons(total_pdu_len);
	ntoh_isns_hdr((isns_hdr_t *)rsp);

	return (0);
}
