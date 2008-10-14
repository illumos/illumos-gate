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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <poll.h>
#include <errno.h>

#include "isns_server.h"
#include "isns_log.h"
#include "isns_pdu.h"

#define	ISNS_MAX_IOVEC		5
#define	MAX_XID			(2^16)
#define	MAX_RCV_RSP_COUNT	10	/* Maximum number of unmatched xid */
#define	ISNS_RCV_RETRY_MAX	2
#define	IPV4_RSVD_BYTES		10

/* externs */
#ifdef DEBUG
extern void dump_pdu2(isns_pdu_t *);
#endif

/*
 * local functions.
 */

size_t
isns_rcv_pdu(
	int fd,
	isns_pdu_t **pdu,
	size_t *pdu_size,
	int rcv_timeout
)
{
	int poll_cnt;
	struct pollfd fds;
	iovec_t iovec[ISNS_MAX_IOVEC];
	isns_pdu_t *tmp_pdu_hdr;
	ssize_t bytes_received, total_bytes_received = 0;
	struct msghdr msg;
	uint8_t *tmp_pdu_data;

	uint16_t payload_len = 0;

	/* initialize to zero */
	*pdu = NULL;
	*pdu_size = 0;

	fds.fd = fd;
	fds.events = (POLLIN | POLLRDNORM);
	fds.revents = 0;

	/* Receive the header first */
	tmp_pdu_hdr = (isns_pdu_t *)malloc(ISNSP_HEADER_SIZE);
	if (tmp_pdu_hdr == NULL) {
		return (0);
	}
	(void) memset((void *)&tmp_pdu_hdr[0], 0, ISNSP_HEADER_SIZE);
	(void) memset((void *)&iovec[0], 0, sizeof (iovec_t));
	iovec[0].iov_base = (void *)tmp_pdu_hdr;
	iovec[0].iov_len = ISNSP_HEADER_SIZE;

	/* Initialization of the message header. */
	bzero(&msg, sizeof (msg));
	msg.msg_iov = &iovec[0];
	/* msg.msg_flags   = MSG_WAITALL, */
	msg.msg_iovlen  = 1;

	/* Poll and receive the pdu header */
	poll_cnt = 0;
	do {
		int err = poll(&fds, 1, rcv_timeout * 1000);
		if (err <= 0) {
			poll_cnt ++;
		} else {
			bytes_received = recvmsg(fd, &msg, MSG_WAITALL);
			break;
		}
	} while (poll_cnt < ISNS_RCV_RETRY_MAX);

	if (poll_cnt >= ISNS_RCV_RETRY_MAX) {
		free(tmp_pdu_hdr);
		return (0);
	}

	if (bytes_received <= 0) {
		free(tmp_pdu_hdr);
		return (0);
	}

	total_bytes_received += bytes_received;

	payload_len = ntohs(tmp_pdu_hdr->payload_len);
	/* Verify the received payload len is within limit */
	if (payload_len > ISNSP_MAX_PAYLOAD_SIZE) {
		free(tmp_pdu_hdr);
		return (0);
	}

	/* Proceed to receive additional data. */
	tmp_pdu_data = malloc(payload_len);
	if (tmp_pdu_data == NULL) {
		free(tmp_pdu_hdr);
		return (0);
	}
	(void) memset((void *)&iovec[0], 0, sizeof (iovec_t));
	iovec[0].iov_base = (void *)tmp_pdu_data;
	iovec[0].iov_len = payload_len;

	/* Initialization of the message header. */
	bzero(&msg, sizeof (msg));
	msg.msg_iov = &iovec[0];
	/* msg.msg_flags   = MSG_WAITALL, */
	msg.msg_iovlen  = 1;

	/* poll and receive the pdu payload */
	poll_cnt = 0;
	do {
		int err = poll(&fds, 1, rcv_timeout * 1000);
		if (err <= 0) {
			poll_cnt ++;
		} else {
			bytes_received = recvmsg(fd, &msg, MSG_WAITALL);
			break;
		}
	} while (poll_cnt < ISNS_RCV_RETRY_MAX);

	if (poll_cnt >= ISNS_RCV_RETRY_MAX) {
		free(tmp_pdu_data);
		free(tmp_pdu_hdr);
		return (0);
	}

	if (bytes_received <= 0) {
		free(tmp_pdu_data);
		free(tmp_pdu_hdr);
		return (0);
	}

	total_bytes_received += bytes_received;

	*pdu_size = ISNSP_HEADER_SIZE + payload_len;
	(*pdu) = (isns_pdu_t *)malloc(*pdu_size);
	if (*pdu == NULL) {
		*pdu_size = 0;
		free(tmp_pdu_data);
		free(tmp_pdu_hdr);
		return (0);
	}
	(*pdu)->version = ntohs(tmp_pdu_hdr->version);
	(*pdu)->func_id = ntohs(tmp_pdu_hdr->func_id);
	(*pdu)->payload_len = payload_len;
	(*pdu)->flags = ntohs(tmp_pdu_hdr->flags);
	(*pdu)->xid = ntohs(tmp_pdu_hdr->xid);
	(*pdu)->seq = ntohs(tmp_pdu_hdr->seq);
	(void) memcpy(&((*pdu)->payload), tmp_pdu_data, payload_len);

	free(tmp_pdu_data);
	tmp_pdu_data = NULL;
	free(tmp_pdu_hdr);
	tmp_pdu_hdr = NULL;

	return (total_bytes_received);
}

int
isns_send_pdu(
	int fd,
	isns_pdu_t *pdu,
	size_t pl
)
{
	uint8_t *payload;
	uint16_t flags;
	uint16_t seq;
	iovec_t iovec[ISNS_MAX_IOVEC];
	struct msghdr msg = { 0 };

	size_t send_len;
	ssize_t bytes_sent;


	/* Initialization of the message header. */
	msg.msg_iov = &iovec[0];
	/* msg.msg_flags   = MSG_WAITALL, */
	msg.msg_iovlen  = 2;

	/*
	 * Initialize the pdu flags.
	 */
	flags = ISNS_FLAG_SERVER;
	flags |= ISNS_FLAG_FIRST_PDU;

	/*
	 * Initialize the pdu sequence id.
	 */
	seq = 0;

	iovec[0].iov_base = (void *)pdu;
	iovec[0].iov_len = (ISNSP_HEADER_SIZE);

	payload = pdu->payload;

#ifdef DEBUG
	pdu->flags = htons(flags);
	pdu->seq = htons(0);
	pdu->payload_len = htons(pl);
	dump_pdu2(pdu);
#endif

	do {
		/* set the payload for sending */
		iovec[1].iov_base = (void *)payload;

		if (pl > ISNSP_MAX_PAYLOAD_SIZE) {
			send_len = ISNSP_MAX_PAYLOAD_SIZE;
		} else {
			send_len = pl;
			/* set the last pdu flag */
			flags |= ISNS_FLAG_LAST_PDU;
		}
		iovec[1].iov_len = send_len;
		pdu->payload_len = htons(send_len);

		/* set the pdu flags */
		pdu->flags = htons(flags);
		/* set the pdu sequence id */
		pdu->seq = htons(seq);

		/* send the packet */
		bytes_sent = sendmsg(fd, &msg, 0);

		/* get rid of the first pdu flag */
		flags &= ~(ISNS_FLAG_FIRST_PDU);

		/* next part of payload */
		payload += send_len;
		pl -= send_len;

		/* add the length of header for verification */
		send_len += ISNSP_HEADER_SIZE;

		/* increase the sequence id by one */
		seq ++;
	} while (bytes_sent == send_len && pl > 0);

	if (bytes_sent == send_len) {
		return (0);
	} else {
		isnslog(LOG_DEBUG, "isns_send_pdu", "sending pdu failed.");
		return (-1);
	}
}

#define	RSP_PDU_FRAG_SZ	(ISNSP_MAX_PDU_SIZE / 10)
static int
pdu_reset(
	isns_pdu_t **rsp,
	size_t *sz
)
{
	int ec = 0;

	if (*rsp == NULL) {
		*rsp = (isns_pdu_t *)malloc(RSP_PDU_FRAG_SZ);
		if (*rsp != NULL) {
			*sz = RSP_PDU_FRAG_SZ;
		} else {
			ec = ISNS_RSP_INTERNAL_ERROR;
		}
	}

	return (ec);
}

int
pdu_reset_rsp(
	isns_pdu_t **rsp,
	size_t *pl,
	size_t *sz
)
{
	int ec = pdu_reset(rsp, sz);

	if (ec == 0) {
		/* leave space for status code */
		*pl = 4;
	}

	return (ec);
}

int
pdu_reset_scn(
	isns_pdu_t **pdu,
	size_t *pl,
	size_t *sz
)
{
	int ec = pdu_reset(pdu, sz);

	if (ec == 0) {
		*pl = 0;
	}

	return (ec);
}

int
pdu_reset_esi(
	isns_pdu_t **pdu,
	size_t *pl,
	size_t *sz
)
{
	return (pdu_reset_scn(pdu, pl, sz));
}

int
pdu_update_code(
	isns_pdu_t *pdu,
	size_t *pl,
	int code
)
{
	isns_resp_t *resp;

	resp = (isns_resp_t *)pdu->payload;

	/* reset the payload length */
	if (code != ISNS_RSP_SUCCESSFUL || *pl == 0) {
		*pl = 4;
	}

	resp->status = htonl(code);

	return (0);
}

int
pdu_add_tlv(
	isns_pdu_t **pdu,
	size_t *pl,
	size_t *sz,
	uint32_t attr_id,
	uint32_t attr_len,
	void *attr_data,
	int pflag
)
{
	int ec = 0;

	isns_pdu_t *new_pdu;
	size_t new_sz;

	isns_tlv_t *attr_tlv;
	uint8_t *payload_ptr;
	uint32_t normalized_attr_len;
	uint64_t attr_tlv_len;

	/* The attribute length must be 4-byte aligned. Section 5.1.3. */
	normalized_attr_len = (attr_len % 4) == 0 ? (attr_len) :
	    (attr_len + (4 - (attr_len % 4)));
	attr_tlv_len = ISNS_TLV_ATTR_ID_LEN
	    + ISNS_TLV_ATTR_LEN_LEN
	    + normalized_attr_len;
	/* Check if we are going to exceed the maximum PDU length. */
	if ((ISNSP_HEADER_SIZE + *pl + attr_tlv_len) > *sz) {
		new_sz = *sz + RSP_PDU_FRAG_SZ;
		new_pdu = (isns_pdu_t *)realloc(*pdu, new_sz);
		if (new_pdu != NULL) {
			*sz = new_sz;
			*pdu = new_pdu;
		} else {
			ec = ISNS_RSP_INTERNAL_ERROR;
			return (ec);
		}
	}

	attr_tlv = (isns_tlv_t *)malloc(attr_tlv_len);
	(void) memset((void *)attr_tlv, 0, attr_tlv_len);

	attr_tlv->attr_id = htonl(attr_id);

	switch (attr_id) {
		case ISNS_DELIMITER_ATTR_ID:
		break;

		case ISNS_PORTAL_IP_ADDR_ATTR_ID:
		case ISNS_PG_PORTAL_IP_ADDR_ATTR_ID:
			/* IPv6 */
			ASSERT(attr_len == sizeof (in6_addr_t));
			(void) memcpy(attr_tlv->attr_value, attr_data,
			    sizeof (in6_addr_t));
		break;

		case ISNS_EID_ATTR_ID:
		case ISNS_ISCSI_NAME_ATTR_ID:
		case ISNS_ISCSI_ALIAS_ATTR_ID:
		case ISNS_PG_ISCSI_NAME_ATTR_ID:
			(void) memcpy(attr_tlv->attr_value, (char *)attr_data,
			    attr_len);
		break;

		default:
			if (attr_len == 8) {
				if (pflag == 0) {
				/*
				 * In the iSNS protocol, there is only one
				 * attribute ISNS_TIMESTAMP_ATTR_ID which has
				 * 8 bytes length integer value and when the
				 * function "pdu_add_tlv" is called for adding
				 * the timestamp attribute, the value of
				 * the attribute is always passed in as its
				 * address, i.e. the pflag sets to 1.
				 * So it is an error when we get to this code
				 * path.
				 */
					ec = ISNS_RSP_INTERNAL_ERROR;
					return (ec);
				} else {
					*(uint64_t *)attr_tlv->attr_value =
					    *(uint64_t *)attr_data;
				}
			} else if (attr_len == 4) {
				if (pflag == 0) {
					*(uint32_t *)attr_tlv->attr_value =
					    htonl((uint32_t)attr_data);
				} else {
					*(uint32_t *)attr_tlv->attr_value =
					    *(uint32_t *)attr_data;
				}
			}
		break;
	}

	attr_tlv->attr_len = htonl(normalized_attr_len);
	/*
	 * Convert the network byte ordered payload length to host byte
	 * ordered for local address calculation.
	 */
	payload_ptr = (*pdu)->payload + *pl;
	(void) memcpy(payload_ptr, attr_tlv, attr_tlv_len);
	*pl += attr_tlv_len;

	/*
	 * The payload length might exceed the maximum length of a
	 * payload that isnsp allows, we will split the payload and
	 * set the size of each payload before they are sent.
	 */

	free(attr_tlv);
	attr_tlv = NULL;

	return (ec);
}

isns_tlv_t *
pdu_get_source(
	isns_pdu_t *pdu
)
{
	uint8_t *payload = &pdu->payload[0];
	uint16_t payload_len = pdu->payload_len;
	isns_tlv_t *tlv = NULL;

	/* response code */
	if (pdu->func_id & ISNS_RSP_MASK) {
		if (payload_len < 4) {
			return (NULL);
		}
		payload += 4;
		payload_len -= 4;
	}

	if (payload_len > 8) {
		tlv = (isns_tlv_t *)payload;
		tlv->attr_id = ntohl(tlv->attr_id);
		tlv->attr_len = ntohl(tlv->attr_len);
	}

	return (tlv);
}

isns_tlv_t *
pdu_get_key(
	isns_pdu_t *pdu,
	size_t *key_len
)
{
	uint8_t *payload = &pdu->payload[0];
	uint16_t payload_len = pdu->payload_len;
	isns_tlv_t *tlv, *key;

	/* reset */
	*key_len = 0;

	/* response code */
	if (pdu->func_id & ISNS_RSP_MASK) {
		if (payload_len <= 4) {
			return (NULL);
		}
		payload += 4;
		payload_len -= 4;
	}

	/* skip the soure */
	if (payload_len >= 8) {
		tlv = (isns_tlv_t *)payload;
		payload += (8 + tlv->attr_len);
		payload_len -= (8 + tlv->attr_len);
		key = (isns_tlv_t *)payload;
		while (payload_len >= 8) {
			tlv = (isns_tlv_t *)payload;
			tlv->attr_id = ntohl(tlv->attr_id);
			tlv->attr_len = ntohl(tlv->attr_len);
			if (tlv->attr_id == ISNS_DELIMITER_ATTR_ID) {
				break;
			}
			*key_len += (8 + tlv->attr_len);
			payload += (8 + tlv->attr_len);
			payload_len -= (8 + tlv->attr_len);
		}
	}

	if (*key_len >= 8) {
		return (key);
	}

	return (NULL);
}

isns_tlv_t *
pdu_get_operand(
	isns_pdu_t *pdu,
	size_t *op_len
)
{
	uint8_t *payload = &pdu->payload[0];
	uint16_t payload_len = pdu->payload_len;
	isns_tlv_t *tlv, *op = NULL;
	int found_op = 0;

	/* reset */
	*op_len = 0;

	/* response code */
	if (pdu->func_id & ISNS_RSP_MASK) {
		if (payload_len < 4) {
			return (NULL);
		}
		payload += 4;
		payload_len -= 4;
	}

	/* tlvs */
	while (payload_len >= 8) {
		tlv = (isns_tlv_t *)payload;
		if (found_op != 0) {
			tlv->attr_id = ntohl(tlv->attr_id);
			tlv->attr_len = ntohl(tlv->attr_len);
			payload += (8 + tlv->attr_len);
			payload_len -= (8 + tlv->attr_len);
		} else {
			payload += (8 + tlv->attr_len);
			payload_len -= (8 + tlv->attr_len);
			if (tlv->attr_id == ISNS_DELIMITER_ATTR_ID) {
				/* found it */
				op = (isns_tlv_t *)payload;
				*op_len = payload_len;
				found_op = 1;
			}
		}
	}

	if (*op_len >= 8) {
		return (op);
	}

	return (NULL);
}
