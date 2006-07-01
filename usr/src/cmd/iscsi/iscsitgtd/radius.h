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

#ifndef	_RADIUS_H
#define	_RADIUS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <netinet/in.h>
#include <sys/int_types.h>

/* Packet type. RFC 2865 section 4. */
#define	RAD_ACCESS_REQ		1	/* Authentication Request */
#define	RAD_ACCESS_ACPT		2	/* Authentication Accepted */
#define	RAD_ACCESS_REJ		3	/* Authentication Rejected */

/* RADIUS Attribute Types. RFC 2865 section 5. */
#define	RAD_USER_NAME		1
#define	RAD_CHAP_PASSWORD	3
#define	RAD_CHAP_CHALLENGE	60

/* RFC 2865 Section 3. The Identifier field is one octet. */
#define	RAD_IDENTIFIER_LEN	1

/* RFC 2865 Section 5.3. The String field is 16 octets. */
#define	RAD_CHAP_PASSWD_STR_LEN	16

/* RFC 2865 Section 3. Authenticator field is 16 octets. */
#define	RAD_AUTHENTICATOR_LEN	16

/* RFC 2865 Section 5: 1-253 octets */
#define	MAX_RAD_ATTR_VALUE_LEN	253

/* RFC 2865 Section 3. Minimum length 20 octets. */
#define	MIN_RAD_PACKET_LEN	20

/* RFC 2865 Section 3. Maximum length 4096 octets. */
#define	MAX_RAD_PACKET_LEN	4096

/* Maximum RADIUS shared secret length (in fact there is no defined limit) */
#define	MAX_RAD_SHARED_SECRET_LEN	128

/* RFC 2865 Section 3. Minimum RADIUS shared secret length */
#define	MIN_RAD_SHARED_SECRET_LEN	16

/* Raw RADIUS packet. RFC 2865 section 3. */
typedef struct radius_packet {
	uint8_t	code;		/* RADIUS code, section 3, RFC 2865 */
	uint8_t	identifier;	/* 1 octet in length. RFC 2865 section 3 */
	uint8_t	length[2];	/* 2 octets, or sizeof (u_short) */
	uint8_t	authenticator[RAD_AUTHENTICATOR_LEN];
	uint8_t	data[1];
} radius_packet_t;

/* Length of a RADIUS packet minus the payload */
#define	RAD_PACKET_HDR_LEN		20


typedef enum chap_validation_status_type {
	CHAP_VALIDATION_PASSED,			/* CHAP validation passed */
	CHAP_VALIDATION_INVALID_RESPONSE,	/* Invalid CHAP response */
	CHAP_VALIDATION_DUP_SECRET,		/* Same CHAP secret used */
						/* for authentication in the */
						/* other direction */
	CHAP_VALIDATION_UNKNOWN_AUTH_METHOD,	/* Unknown authentication */
						/*   method */
	CHAP_VALIDATION_INTERNAL_ERROR,		/* MISC internal error */
	CHAP_VALIDATION_RADIUS_ACCESS_ERROR,	/* Problem accessing RADIUS */
	CHAP_VALIDATION_BAD_RADIUS_SECRET,	/* Invalid RADIUS shared */
						/*   secret */
	CHAP_VALIDATION_UNKNOWN_RADIUS_CODE	/* Irrelevant or unknown */
						/*   RADIUS packet code */
						/*   returned */
} chap_validation_status_type;

typedef enum authentication_method_type {
	RADIUS_AUTHENTICATION,
	DIRECT_AUTHENTICATION
} authentication_method_type;

typedef struct  _IPAddress {
	union {
		struct in_addr	in4;
		struct in6_addr	in6;
	} i_addr;
	/* i_insize determines which is valid in the union above */
	int			i_insize;
} iscsi_ipaddr_t;

typedef struct radius_config {
	iscsi_ipaddr_t	rad_svr_addr;	/* IPv6 enabled */
	uint32_t	rad_svr_port;
	uint8_t		rad_svr_shared_secret[MAX_RAD_SHARED_SECRET_LEN];
	uint32_t	rad_svr_shared_secret_len;
} RADIUS_CONFIG;

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
 * Data in this structure is set by the user agent and consumed by
 * the driver.
 */
#define	MAX_RAD_SHARED_SECRET_LEN 128
typedef struct radius_props {
	uint32_t		r_vers;
	uint32_t		r_oid;
	union {
		struct in_addr	u_in4;
		struct in6_addr	u_in6;
	} r_addr;
	/*
	 * r_insize indicates which of the previous structs is valid.
	 */
	int			r_insize;

	uint32_t		r_port;
	uint8_t			r_shared_secret[MAX_RAD_SHARED_SECRET_LEN];
	boolean_t		r_radius_access;
	boolean_t		r_radius_config_valid;
	uint32_t		r_shared_secret_len;
} iscsi_radius_props_t;

/*
 * Send a request to a RADIUS server.
 *
 * Returns > 0 on success, <= 0 on failure .
 *
 */
int
snd_radius_request(int sd,
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
rcv_radius_response(int sd,
    uint8_t *shared_secret,
    uint32_t shared_secret_len,
    uint8_t *req_authenticator,
    radius_packet_data_t *resp_data);

/*
 * Function: radius_chap_validate
 *
 * Description: To validate a target response given the
 *              associated challenge via the specified
 *              RADIUS server.
 *
 * Arguments:
 *   target_chap_name - The CHAP name of the target being authenticated.
 *   initiator_chap_name - The CHAP name of the authenticating initiator.
 *   challenge - The CHAP challenge to which the target responded.
 *   target_response - The target's CHAP response to be validated.
 *   identifier - The identifier associated with the CHAP challenge.
 *   radius_server_ip_address - The IP address of the RADIUS server.
 *   radius_server_port - The port number of the RADIUS server.
 *   radius_shared_secret - The shared secret for accessing the RADIUS server.
 *   radius_shared_secret_len - The length of the shared secret.
 *
 * Return: See chap_validation_status_type.
 */
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
		uint32_t rad_svr_shared_secret_len);



#ifdef __cplusplus
}
#endif

#endif /* _RADIUS_H */
