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

#include <sys/random.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <stdlib.h>

#include <netinet/in.h>
#include <sys/socket.h>

#include <md5.h>
#include "target.h"
#include "radius.h"

/* Forward declaration */

/*
 * Encode a CHAP-Password attribute. This function basically prepends
 * the identifier in front of chap_passwd and copy the results to
 * *result.
 */
static
void
encode_chap_password(int identifier,
    int chap_passwd_len,
    uint8_t *chap_passwd,
    uint8_t *result);

int
snd_radius_request(int sd,
    iscsi_ipaddr_t rsvr_ip_addr,
    uint32_t rsvr_port,
    radius_packet_data_t *req_data);

int
rcv_radius_response(int sd,
    uint8_t *shared_secret,
    uint32_t shared_secret_len,
    uint8_t *req_authenticator,
    radius_packet_data_t *resp_data);

/*
 * Annotate the radius_attr_t objects with authentication data.
 */
static
void
set_radius_attrs(radius_packet_data_t *req,
    char *target_chap_name,
    unsigned char *target_response,
    uint32_t responseLength,
    uint8_t *challenge,
uint32_t challengeLength);

/*
 * See radius_auth.h.
 */
/* ARGSUSED */
chap_validation_status_type
radius_chap_validate(char *target_chap_name,
    char *initiator_chap_name,
    uint8_t *challenge,
    uint32_t challengeLength,
    uint8_t *target_response,
    uint32_t responseLength,
    uint8_t identifier,
    iscsi_ipaddr_t rad_svr_ip_addr,
    uint32_t rad_svr_port,
    uint8_t *rad_svr_shared_secret,
    uint32_t rad_svr_shared_secret_len)
{
	chap_validation_status_type validation_status;
	int rcv_status;
	int sd;
	int rc;
	struct sockaddr_in sockaddr;
	radius_packet_data_t req;
	radius_packet_data_t resp;
	MD5_CTX context;
	uint8_t	md5_digest[16];		/* MD5 digest length 16 */
	uint8_t random_number[16];
	int fd;

	if (rad_svr_shared_secret_len == 0) {
		/* The secret must not be empty (section 3, RFC 2865) */
		return (CHAP_VALIDATION_BAD_RADIUS_SECRET);
	}

	bzero(&req, sizeof (radius_packet_data_t));

	req.identifier = identifier;
	req.code = RAD_ACCESS_REQ;
	set_radius_attrs(&req,
		target_chap_name,
		target_response,
		responseLength,
		challenge,
		challengeLength);

	/* Prepare the request authenticator */
	MD5Init(&context);
	bzero(&md5_digest, 16);
	/* First, the shared secret */
	MD5Update(&context, rad_svr_shared_secret, rad_svr_shared_secret_len);
	/* Then a unique number - use a random number */
	fd = open("/dev/random", O_RDONLY);
	if (fd == -1)
		return (CHAP_VALIDATION_INTERNAL_ERROR);
	(void) read(fd, &random_number, sizeof (random_number));
	(void) close(fd);
	MD5Update(&context, random_number, sizeof (random_number));
	MD5Final(md5_digest, &context);
	bcopy(md5_digest, &req.authenticator, RAD_AUTHENTICATOR_LEN);

	/* Create UDP socket */
	sd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sd < 0) {
		return (CHAP_VALIDATION_RADIUS_ACCESS_ERROR);
	}
	sockaddr.sin_family = AF_INET;
	sockaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	sockaddr.sin_port = htons(0);
	rc = bind(sd, (struct sockaddr *)&sockaddr, sizeof (sockaddr));
	if (rc < 0) {
		return (CHAP_VALIDATION_RADIUS_ACCESS_ERROR);
	}

	/* Send the authentication access request to the RADIUS server */
	if (snd_radius_request(sd,
		rad_svr_ip_addr,
		rad_svr_port,
		&req) == -1) {
		(void) close(sd);
		return (CHAP_VALIDATION_RADIUS_ACCESS_ERROR);
	}

	bzero(&resp, sizeof (radius_packet_data_t));
	/*  Analyze the response coming through from the same socket. */
	rcv_status = rcv_radius_response(sd,
	    rad_svr_shared_secret,
	    rad_svr_shared_secret_len,
	    req.authenticator, &resp);
	if (rcv_status == RAD_RSP_RCVD_SUCCESS) {
		if (resp.code == RAD_ACCESS_ACPT) {
			validation_status = CHAP_VALIDATION_PASSED;
		} else if (resp.code == RAD_ACCESS_REJ) {
			validation_status = CHAP_VALIDATION_INVALID_RESPONSE;
		} else {
			validation_status =
				CHAP_VALIDATION_UNKNOWN_RADIUS_CODE;
		}
	} else if (rcv_status == RAD_RSP_RCVD_AUTH_FAILED) {
		validation_status = CHAP_VALIDATION_BAD_RADIUS_SECRET;
	} else {
		validation_status = CHAP_VALIDATION_RADIUS_ACCESS_ERROR;
	}

	(void) close(sd);
	return (validation_status);
}

/* See forward declaration. */
static void
set_radius_attrs(radius_packet_data_t *req,
	char *target_chap_name,
	unsigned char *target_response,
	uint32_t responseLength,
	uint8_t *challenge,
	uint32_t challengeLength)
{
	req->attrs[0].attr_type_code = RAD_USER_NAME;
	(void) strncpy((char *)req->attrs[0].attr_value,
	    (const char *)target_chap_name,
	    strlen(target_chap_name));
	req->attrs[0].attr_value_len = strlen(target_chap_name);

	req->attrs[1].attr_type_code = RAD_CHAP_PASSWORD;
	bcopy(target_response,
	    (char *)req->attrs[1].attr_value,
	    min(responseLength, sizeof (req->attrs[1].attr_value)));
	/* A target response is an MD5 hash thus its length has to be 16. */
	req->attrs[1].attr_value_len = responseLength;

	req->attrs[2].attr_type_code = RAD_CHAP_CHALLENGE;
	bcopy(challenge,
	    (char *)req->attrs[2].attr_value,
	    min(challengeLength, sizeof (req->attrs[2].attr_value)));
	req->attrs[2].attr_value_len = challengeLength;

	/* 3 attributes associated with each RADIUS packet. */
	req->num_of_attrs = 3;
}

/*
 * See radius_packet.h.
 */
int
snd_radius_request(int sd,
	iscsi_ipaddr_t rsvr_ip_addr,
	uint32_t rsvr_port,
	radius_packet_data_t *req_data)
{
	int		i;		/* Loop counter. */
	int		data_len;
	int		len;
	ushort_t	total_length;	/* Has to be 2 octets in size */
	uint8_t		*ptr;		/* Pointer to RADIUS packet data */
	uint8_t		*length_ptr;	/* Points to the Length field of the */
					/* packet. */
	uint8_t		*data;		/* RADIUS data to be sent */
	radius_attr_t	*req_attr;	/* Request attributes */
	radius_packet_t	*packet;	/* Outbound RADIUS packet */
	union {
		struct sockaddr_in s_in4;
		struct sockaddr_in6 s_in6;
	} sa_rsvr;			/* Socket address of the server */

	/*
	 * Create a RADIUS packet with minimal length for now.
	 */
	total_length = MIN_RAD_PACKET_LEN;
	data = (uint8_t *)malloc(MAX_RAD_PACKET_LEN);
	packet = (radius_packet_t *)data;
	packet->code = req_data->code;
	packet->identifier = req_data->identifier;
	bcopy(req_data->authenticator, packet->authenticator,
	    RAD_AUTHENTICATOR_LEN);
	ptr = packet->data;

	/* Loop over all attributes of the request. */
	for (i = 0; i < req_data->num_of_attrs; i++) {
		if (total_length > MAX_RAD_PACKET_LEN) {
			/* The packet has exceed its maximum size. */
			free(data);
			return (-1);
		}

		req_attr = &req_data->attrs[i];
		*ptr++ = (req_attr->attr_type_code & 0xFF);
		length_ptr = ptr;
		/* Length is 2 octets - RFC 2865 section 3 */
		*ptr++ = 2;
		total_length += 2;

		/* If the attribute is CHAP-Password, encode it. */
		if (req_attr->attr_type_code == RAD_CHAP_PASSWORD) {
			/*
			 * Identifier plus CHAP response. RFC 2865
			 * section 5.3.
			 */
			uint8_t encoded_chap_passwd[RAD_CHAP_PASSWD_STR_LEN +
							RAD_IDENTIFIER_LEN +
							1];
			encode_chap_password
				(req_data->identifier,
				req_attr->attr_value_len,
				req_attr->attr_value,
				encoded_chap_passwd);

			req_attr->attr_value_len = RAD_CHAP_PASSWD_STR_LEN +
				RAD_IDENTIFIER_LEN;

			bcopy(encoded_chap_passwd,
				req_attr->attr_value,
				req_attr->attr_value_len);
		}

		len = req_attr->attr_value_len;
		*length_ptr += len;

		bcopy(req_attr->attr_value, ptr, req_attr->attr_value_len);
		ptr += req_attr->attr_value_len;

		total_length += len;
	} /* Done looping over all attributes */

	data_len = total_length;
	total_length = htons(total_length);
	bcopy(&total_length, packet->length, sizeof (ushort_t));

	/*
	 * Send the packet to the RADIUS server.
	 */
	bzero((char *)&sa_rsvr, sizeof (sa_rsvr));
	if (rsvr_ip_addr.i_insize == sizeof (in_addr_t)) {
		int ret;

		/* IPv4 */
		sa_rsvr.s_in4.sin_family = AF_INET;
		sa_rsvr.s_in4.sin_addr.s_addr =
			rsvr_ip_addr.i_addr.in4.s_addr;
		/*
		 * sin_port is of type u_short (or ushort_t - POSIX compliant).
		 */
		sa_rsvr.s_in4.sin_port = htons((ushort_t)rsvr_port);

		ret = sendto(sd, data, data_len, 0,
		    (struct sockaddr *)&sa_rsvr.s_in4,
		    sizeof (struct sockaddr_in));
		free(data);
		return (ret);
	} else if (rsvr_ip_addr.i_insize == sizeof (in6_addr_t)) {
		/* IPv6 */
		sa_rsvr.s_in6.sin6_family = AF_INET6;
		bcopy(sa_rsvr.s_in6.sin6_addr.s6_addr,
			rsvr_ip_addr.i_addr.in6.s6_addr, 16);
		/*
		 * sin6_port is of type in_port_t (i.e., uint16_t).
		 */
		sa_rsvr.s_in6.sin6_port = htons((in_port_t)rsvr_port);

		free(data);
		/* No IPv6 support for now. */
		return (-1);
	} else {
		/* Invalid IP address for RADIUS server. */
		free(data);
		return (-1);
	}
}

/*
 * See radius_packet.h.
 */
int
rcv_radius_response(int sd,
    uint8_t *shared_secret,
    uint32_t shared_secret_len,
    uint8_t *req_authenticator,
    radius_packet_data_t *resp_data)
{
	int			poll_cnt = 0;
	int			rcv_len = 0;
	radius_packet_t		*packet;
	MD5_CTX			context;
	uint8_t			*tmp_data;
	uint8_t			md5_digest[16]; /* MD5 Digest Length 16 */
	uint16_t		declared_len = 0;
	ushort_t		len;

	fd_set fdset;
	struct timeval timeout;

	tmp_data = (uint8_t *)malloc(MAX_RAD_PACKET_LEN);

	/*
	 * Poll and receive RADIUS packet.
	 */
	poll_cnt = 0;
	do {
		timeout.tv_sec = RAD_RCV_TIMEOUT;
		timeout.tv_usec = 0;

		FD_ZERO(&fdset);
		FD_SET(sd, &fdset);

		if (select(sd+1, &fdset, NULL, NULL, &timeout) < 0) {
			free(tmp_data);
			return (RAD_RSP_RCVD_PROTOCOL_ERR);
		}

		if (FD_ISSET(sd, &fdset)) {
			rcv_len = recv(sd, tmp_data, MAX_RAD_PACKET_LEN, 0);
			break;
		} else {
			poll_cnt++;
		}

	} while (poll_cnt < RAD_RETRY_MAX);

	if (poll_cnt >= RAD_RETRY_MAX) {
		free(tmp_data);
		return (RAD_RSP_RCVD_TIMEOUT);
	}

	if (rcv_len < 0) {
		/* Socket error. */
		free(tmp_data);
		return (RAD_RSP_RCVD_PROTOCOL_ERR);
	}

	packet = (radius_packet_t *)tmp_data;
	bcopy(packet->length, &len, sizeof (ushort_t));
	declared_len = ntohs(len);

	/*
	 * Check if the received packet length is within allowable range.
	 * RFC 2865 section 3.
	 */
	if (rcv_len < MIN_RAD_PACKET_LEN) {
		free(tmp_data);
		return (RAD_RSP_RCVD_PROTOCOL_ERR);
	} else if (rcv_len > MAX_RAD_PACKET_LEN) {
		free(tmp_data);
		return (RAD_RSP_RCVD_PROTOCOL_ERR);
	}

	/*
	 * Check if the declared packet length is within allowable range.
	 * RFC 2865 section 3.
	 */
	if (declared_len < MIN_RAD_PACKET_LEN) {
		free(tmp_data);
		return (RAD_RSP_RCVD_PROTOCOL_ERR);
	} else if (declared_len > MAX_RAD_PACKET_LEN) {
		free(tmp_data);
		return (RAD_RSP_RCVD_PROTOCOL_ERR);
	}

	/*
	 * Discard packet with received length shorter than declared
	 * length. RFC 2865 section 3.
	 */
	if (rcv_len < declared_len) {
		free(tmp_data);
		return (RAD_RSP_RCVD_PROTOCOL_ERR);
	}

	/*
	 * Authenticate the incoming packet, using the following algorithm
	 * (RFC 2865 section 3):
	 *
	 * 	MD5(Code+ID+Length+RequestAuth+Attributes+Secret)
	 *
	 * Code = RADIUS packet code
	 * ID = RADIUS packet identifier
	 * Length = Declared length of the packet
	 * RequestAuth = The request authenticator
	 * Attributes = The response attributes
	 * Secret = The shared secret
	 */
	MD5Init(&context);
	bzero(&md5_digest, 16);
	MD5Update(&context, &packet->code, 1);
	MD5Update(&context, &packet->identifier, 1);
	MD5Update(&context, packet->length, 2);
	MD5Update(&context, req_authenticator, RAD_AUTHENTICATOR_LEN);
	/* Include response attributes only if there is a payload */
	if (declared_len > RAD_PACKET_HDR_LEN) {
		/* Response Attributes */
		MD5Update(&context, packet->data,
			declared_len - RAD_PACKET_HDR_LEN);
	}
	MD5Update(&context, shared_secret, shared_secret_len);
	MD5Final(md5_digest, &context);

	if (bcmp(md5_digest, packet->authenticator, RAD_AUTHENTICATOR_LEN)
	    != 0) {
		free(tmp_data);
		return (RAD_RSP_RCVD_AUTH_FAILED);
	}

	/*
	 * If the received length is greater than the declared length,
	 * trust the declared length and shorten the packet (i.e., to
	 * treat the octets outside the range of the Length field as
	 * padding - RFC 2865 section 3).
	 */
	if (rcv_len > declared_len) {
		/* Clear the padding data. */
		bzero(tmp_data + declared_len, rcv_len - declared_len);
		rcv_len = declared_len;
	}

	/*
	 * Annotate the RADIUS packet data with the data we received from
	 * the server.
	 */
	resp_data->code = packet->code;
	resp_data->identifier = packet->identifier;

	free(tmp_data);
	return (RAD_RSP_RCVD_SUCCESS);
}

static
void
encode_chap_password(int identifier,
		int chap_passwd_len,
		uint8_t *chap_passwd,
		uint8_t *result)
{
	result[0] = (uint8_t)identifier;
	bcopy(chap_passwd, &result[1], chap_passwd_len);
}
