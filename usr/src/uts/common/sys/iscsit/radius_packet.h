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

#ifndef	_RADIUS_PACKET_H
#define	_RADIUS_PACKET_H

#ifdef __cplusplus
extern "C" {
#endif

#include <netinet/in.h>
#include <sys/types.h>
#include <sys/ksocket.h>
#include <sys/iscsit/radius_protocol.h>

/* A total of RAD_RCV_TIMEOUT * RAD_RETRY_MAX seconds timeout. */
#define	RAD_RCV_TIMEOUT 5	/* Timeout for receiving RADIUS packet in */
				/*   sec. */
#define	RAD_RETRY_MAX   2	/* Max. # of times to retry receiving */
				/*   packet. */

/* Describes a RADIUS attribute */
typedef struct radius_attr {
	int	attr_type_code; /* RADIUS attribute type code, */
				/*   e.g. RAD_USER_PASSWORD, etc. */
	int	attr_value_len;
	uint8_t	attr_value[MAX_RAD_ATTR_VALUE_LEN];
} radius_attr_t;

/* Describes data fields of a RADIUS packet. */
typedef struct radius_packet_data {
	uint8_t		code;	/* RADIUS code, section 3, RFC 2865. */
	uint8_t		identifier;
	uint8_t		authenticator[RAD_AUTHENTICATOR_LEN];
	int		num_of_attrs;
	radius_attr_t attrs[4]; /* For this implementation each */
				/*   outbound RADIUS packet will only */
				/*   have 3 attributes associated with */
				/*   it thus the chosen size should be */
				/*   good enough. */
} radius_packet_data_t;

/*
 * Send a request to a RADIUS server.
 *
 * Returns > 0 on success, <= 0 on failure .
 *
 */
int
iscsit_snd_radius_request(ksocket_t socket,
    iscsi_ipaddr_t rsvr_ip_addr,
    uint32_t rsvr_port,
    radius_packet_data_t *packet_data);

#define	RAD_RSP_RCVD_SUCCESS		0
#define	RAD_RSP_RCVD_NO_DATA		1
#define	RAD_RSP_RCVD_TIMEOUT		2
#define	RAD_RSP_RCVD_PROTOCOL_ERR	3
#define	RAD_RSP_RCVD_AUTH_FAILED	4
/*
 * Receives a response from a RADIUS server.
 *
 * Return receive status.
 */
int
iscsit_rcv_radius_response(ksocket_t socket,
    uint8_t *shared_secret,
    uint32_t shared_secret_len,
    uint8_t *req_authenticator,
    radius_packet_data_t *resp_data);

#ifdef __cplusplus
}
#endif

#endif /* _RADIUS_PACKET_H */
