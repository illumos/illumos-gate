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

#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/iscsit/iscsi_if.h>
#include <sys/md5.h>

#include <sys/idm/idm.h>
#include <sys/idm/idm_so.h>
#include <sys/iscsit/radius_packet.h>
#include <sys/iscsit/radius_protocol.h>
#include <sys/ksocket.h>

static void encode_chap_password(int identifier, int chap_passwd_len,
    uint8_t *chap_passwd, uint8_t *result);

static size_t iscsit_net_recvmsg(ksocket_t socket, struct msghdr *msg,
    int timeout);

/*
 * See radius_packet.h.
 */
int
iscsit_snd_radius_request(ksocket_t socket, iscsi_ipaddr_t rsvr_ip_addr,
    uint32_t rsvr_port, radius_packet_data_t *req_data)
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
	int err;

	/*
	 * Create a RADIUS packet with minimal length for now.
	 */
	total_length = MIN_RAD_PACKET_LEN;
	data = kmem_zalloc(MAX_RAD_PACKET_LEN, KM_SLEEP);
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
			kmem_free(data, MAX_RAD_PACKET_LEN);
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
			uint8_t encoded_chap_passwd[
			    RAD_CHAP_PASSWD_STR_LEN + RAD_IDENTIFIER_LEN + 1];
			encode_chap_password(
			    req_data->identifier,
			    req_attr->attr_value_len,
			    req_attr->attr_value,
			    encoded_chap_passwd);

			req_attr->attr_value_len =
			    RAD_CHAP_PASSWD_STR_LEN + RAD_IDENTIFIER_LEN;

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

		/* IPv4 */
		sa_rsvr.s_in4.sin_family = AF_INET;
		sa_rsvr.s_in4.sin_addr.s_addr =
		    rsvr_ip_addr.i_addr.in4.s_addr;
		sa_rsvr.s_in4.sin_port = htons((ushort_t)rsvr_port);

		err = idm_sosendto(socket, data, data_len,
		    (struct sockaddr *)&sa_rsvr.s_in4,
		    sizeof (struct sockaddr_in));
		kmem_free(data, MAX_RAD_PACKET_LEN);
		return (err);
	} else if (rsvr_ip_addr.i_insize == sizeof (in6_addr_t)) {
		/* IPv6 */
		sa_rsvr.s_in6.sin6_family = AF_INET6;
		bcopy(rsvr_ip_addr.i_addr.in6.s6_addr,
		    sa_rsvr.s_in6.sin6_addr.s6_addr, sizeof (struct in6_addr));
		sa_rsvr.s_in6.sin6_port = htons((ushort_t)rsvr_port);

		err = idm_sosendto(socket, data, data_len,
		    (struct sockaddr *)&sa_rsvr.s_in6,
		    sizeof (struct sockaddr_in6));
		kmem_free(data, MAX_RAD_PACKET_LEN);
		return (err);
	} else {
		/* Invalid IP address for RADIUS server. */
		kmem_free(data, MAX_RAD_PACKET_LEN);
		return (-1);
	}
}

/*
 * See radius_packet.h.
 */
int
iscsit_rcv_radius_response(ksocket_t socket, uint8_t *shared_secret,
    uint32_t shared_secret_len, uint8_t *req_authenticator,
    radius_packet_data_t *resp_data)
{
	radius_packet_t		*packet;
	MD5_CTX			context;
	uint8_t			*tmp_data;
	uint8_t			md5_digest[16]; /* MD5 Digest Length 16 */
	uint16_t		declared_len = 0;
	size_t			received_len = 0;

	struct iovec		iov[1];
	struct nmsghdr		msg;

	tmp_data = kmem_zalloc(MAX_RAD_PACKET_LEN, KM_SLEEP);
	iov[0].iov_base = (char *)tmp_data;
	iov[0].iov_len	= MAX_RAD_PACKET_LEN;

	bzero(&msg, sizeof (msg));
	msg.msg_name		= NULL;
	msg.msg_namelen		= 0;
	msg.msg_control		= NULL;
	msg.msg_controllen	= 0;
	msg.msg_flags		= MSG_WAITALL;
	msg.msg_iov		= iov;
	msg.msg_iovlen		= 1;

	received_len = iscsit_net_recvmsg(socket, &msg, RAD_RCV_TIMEOUT);

	if (received_len <= (size_t)0) {
		kmem_free(tmp_data, MAX_RAD_PACKET_LEN);
		return (RAD_RSP_RCVD_NO_DATA);
	}

	/*
	 * Check if the received packet length is within allowable range.
	 * RFC 2865 section 3.
	 */
	if (received_len < MIN_RAD_PACKET_LEN) {
		kmem_free(tmp_data, MAX_RAD_PACKET_LEN);
		return (RAD_RSP_RCVD_PROTOCOL_ERR);
	} else if (received_len > MAX_RAD_PACKET_LEN) {
		kmem_free(tmp_data, MAX_RAD_PACKET_LEN);
		return (RAD_RSP_RCVD_PROTOCOL_ERR);
	}

	packet = (radius_packet_t *)tmp_data;
	bcopy(packet->length, &declared_len, sizeof (ushort_t));
	declared_len = ntohs(declared_len);

	/*
	 * Discard packet with received length shorter than declared
	 * length. RFC 2865 section 3.
	 */
	if (received_len < declared_len) {
		kmem_free(tmp_data, MAX_RAD_PACKET_LEN);
		return (RAD_RSP_RCVD_PROTOCOL_ERR);
	}

	/*
	 * Check if the declared packet length is within allowable range.
	 * RFC 2865 section 3.
	 */
	if (declared_len < MIN_RAD_PACKET_LEN) {
		kmem_free(tmp_data, MAX_RAD_PACKET_LEN);
		return (RAD_RSP_RCVD_PROTOCOL_ERR);
	} else if (declared_len > MAX_RAD_PACKET_LEN) {
		kmem_free(tmp_data, MAX_RAD_PACKET_LEN);
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

	/*
	 * Include response attributes only if there is a payload
	 * If the received length is greater than the declared length,
	 * trust the declared length and shorten the packet (i.e., to
	 * treat the octets outside the range of the Length field as
	 * padding - RFC 2865 section 3).
	 */
	if (declared_len > RAD_PACKET_HDR_LEN) {
		/* Response Attributes */
		MD5Update(&context, packet->data,
		    declared_len - RAD_PACKET_HDR_LEN);
	}
	MD5Update(&context, shared_secret, shared_secret_len);
	MD5Final(md5_digest, &context);

	if (bcmp(md5_digest, packet->authenticator, RAD_AUTHENTICATOR_LEN)
	    != 0) {
		kmem_free(tmp_data, MAX_RAD_PACKET_LEN);
		return (RAD_RSP_RCVD_AUTH_FAILED);
	}

	/*
	 * Annotate the RADIUS packet data with the data we received from
	 * the server.
	 */
	resp_data->code = packet->code;
	resp_data->identifier = packet->identifier;

	kmem_free(tmp_data, MAX_RAD_PACKET_LEN);
	return (RAD_RSP_RCVD_SUCCESS);
}

/*
 * encode_chap_password -
 *
 * Encode a CHAP-Password attribute. This function basically prepends
 * the identifier in front of chap_passwd and copy the results to
 * *result.
 */
static void
encode_chap_password(int identifier, int chap_passwd_len,
    uint8_t *chap_passwd, uint8_t *result)
{
	result[0] = (uint8_t)identifier;
	bcopy(chap_passwd, &result[1], chap_passwd_len);
}
/*
 * iscsi_net_recvmsg - receive message on socket
 */
/* ARGSUSED */
static size_t
iscsit_net_recvmsg(ksocket_t socket, struct msghdr *msg, int timeout)
{
	int		prflag	= msg->msg_flags;
	size_t		recv	= 0;
	struct sockaddr_in6 	l_addr, f_addr;
	socklen_t	l_addrlen;
	socklen_t	f_addrlen;

	bzero(&l_addr, sizeof (struct sockaddr_in6));
	bzero(&f_addr, sizeof (struct sockaddr_in6));
	l_addrlen = sizeof (struct sockaddr_in6);
	f_addrlen = sizeof (struct sockaddr_in6);
	/* If timeout requested on receive */
	if (timeout > 0) {
		boolean_t   loopback = B_FALSE;
		(void) ksocket_getsockname(socket, (struct sockaddr *)(&l_addr),
		    &l_addrlen, CRED());
		(void) ksocket_getpeername(socket, (struct sockaddr *)(&f_addr),
		    &f_addrlen, CRED());

		/* And this isn't a loopback connection */
		if (((struct sockaddr *)(&l_addr))->sa_family == AF_INET) {
			struct sockaddr_in *lin = (struct sockaddr_in *)
			    ((void *)(&l_addr));
			struct sockaddr_in *fin = (struct sockaddr_in *)
			    ((void *)(&f_addr));

			if ((lin->sin_family == fin->sin_family) &&
			    (bcmp(&lin->sin_addr, &fin->sin_addr,
			    sizeof (struct in_addr)) == 0)) {
				loopback = B_TRUE;
			}
		} else {
			struct sockaddr_in6 *lin6 = (struct sockaddr_in6 *)
			    ((void *)(&l_addr));
			struct sockaddr_in6 *fin6 = (struct sockaddr_in6 *)
			    ((void *)(&f_addr));

			if ((lin6->sin6_family == fin6->sin6_family) &&
			    (bcmp(&lin6->sin6_addr, &fin6->sin6_addr,
			    sizeof (struct in6_addr)) == 0)) {
				loopback = B_TRUE;
			}
		}
		if (loopback == B_FALSE) {
			struct timeval tl;
			tl.tv_sec = timeout;
			tl.tv_usec = 0;
			/* Set recv timeout */
			if (ksocket_setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO,
			    &tl, sizeof (struct timeval), CRED()))
				return (0);
		}
	}

	/*
	 * Receive the requested data.  Block until all
	 * data is received or timeout.
	 *
	 * resid occurs only when the connection is
	 * disconnected.  In that case it will return
	 * the amount of data that was not received.
	 * In general this is the total amount we
	 * requested.
	 */
	(void) ksocket_recvmsg(socket, msg, prflag, &recv, CRED());
	return (recv);
}
