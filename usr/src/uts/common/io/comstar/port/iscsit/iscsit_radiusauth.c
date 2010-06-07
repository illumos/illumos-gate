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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/random.h>
#include <sys/ddi.h>
#include <sys/md5.h>

#include <sys/iscsit/iscsi_if.h>
#include <sys/idm/idm.h>
#include <sys/idm/idm_so.h>
#include <sys/iscsit/radius_packet.h>
#include <sys/iscsit/radius_protocol.h>

#include "radius_auth.h"

/* Forward declaration */
/*
 * Annotate the radius_attr_t objects with authentication data.
 */
static
void
set_radius_attrs(radius_packet_data_t *req,
	char *target_chap_name,
	unsigned char *target_response,
	uint32_t response_length,
	uint8_t *challenge,
	uint32_t challenge_length);

/*
 * See radius_auth.h.
 */
/* ARGSUSED */
chap_validation_status_type
iscsit_radius_chap_validate(char *target_chap_name,
	char *initiator_chap_name,
	uint8_t *challenge,
	uint32_t challenge_length,
	uint8_t *target_response,
	uint32_t response_length,
	uint8_t identifier,
	iscsi_ipaddr_t rad_svr_ip_addr,
	uint32_t rad_svr_port,
	uint8_t *rad_svr_shared_secret,
	uint32_t rad_svr_shared_secret_len)
{
	chap_validation_status_type validation_status;
	char lbolt[64];
	int rcv_status;
	void *socket;
	radius_packet_data_t req;
	radius_packet_data_t resp;
	MD5_CTX context;
	uint8_t	md5_digest[16];		/* MD5 digest length 16 */
	uint8_t random_number[16];

	if (rad_svr_shared_secret_len == 0) {
		/* The secret must not be empty (section 3, RFC 2865) */
		cmn_err(CE_WARN, "empty RADIUS shared secret");
		return (CHAP_VALIDATION_BAD_RADIUS_SECRET);
	}

	bzero(&req, sizeof (radius_packet_data_t));

	req.identifier = identifier;
	req.code = RAD_ACCESS_REQ;
	set_radius_attrs(&req,
	    target_chap_name,
	    target_response,
	    response_length,
	    challenge,
	    challenge_length);

	/* Prepare the request authenticator */
	MD5Init(&context);
	bzero(&md5_digest, 16);
	/* First, the shared secret */
	MD5Update(&context, rad_svr_shared_secret, rad_svr_shared_secret_len);
	/* Then a unique number - use lbolt plus a random number */
	bzero(&lbolt, sizeof (lbolt));
	(void) snprintf(lbolt, sizeof (lbolt), "%lx", ddi_get_lbolt());
	MD5Update(&context, (uint8_t *)lbolt, strlen(lbolt));
	bzero(&random_number, sizeof (random_number));
	(void) random_get_pseudo_bytes(random_number, sizeof (random_number));
	MD5Update(&context, random_number, sizeof (random_number));
	MD5Final(md5_digest, &context);
	bcopy(md5_digest, &req.authenticator, RAD_AUTHENTICATOR_LEN);

	socket = idm_socreate(PF_INET, SOCK_DGRAM, 0);
	if (socket == NULL) {
		/* Error obtaining socket for RADIUS use */
		return (CHAP_VALIDATION_RADIUS_ACCESS_ERROR);
	}

	/* Send the authentication access request to the RADIUS server */
	if (iscsit_snd_radius_request(socket,
	    rad_svr_ip_addr,
	    rad_svr_port,
	    &req) != 0) {
		idm_soshutdown(socket);
		idm_sodestroy(socket);
		return (CHAP_VALIDATION_RADIUS_ACCESS_ERROR);
	}

	bzero(&resp, sizeof (radius_packet_data_t));
	/*  Analyze the response coming through from the same socket. */
	rcv_status = iscsit_rcv_radius_response(socket,
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

	/* Done! Close the socket. */
	idm_soshutdown(socket);
	idm_sodestroy(socket);

	return (validation_status);
}

/* See forward declaration. */
static void
set_radius_attrs(radius_packet_data_t *req,
	char *target_chap_name,
	unsigned char *target_response,
	uint32_t response_length,
	uint8_t *challenge,
	uint32_t challenge_length)
{
	req->attrs[0].attr_type_code = RAD_USER_NAME;
	(void) strncpy((char *)req->attrs[0].attr_value,
	    (const char *)target_chap_name,
	    strlen(target_chap_name));
	req->attrs[0].attr_value_len = strlen(target_chap_name);

	req->attrs[1].attr_type_code = RAD_CHAP_PASSWORD;
	bcopy(target_response,
	    (char *)req->attrs[1].attr_value,
	    min(response_length, sizeof (req->attrs[1].attr_value)));
	/* A target response is an MD5 hash thus its length has to be 16. */
	req->attrs[1].attr_value_len = 16;

	req->attrs[2].attr_type_code = RAD_CHAP_CHALLENGE;
	bcopy(challenge,
	    (char *)req->attrs[2].attr_value,
	    min(challenge_length, sizeof (req->attrs[2].attr_value)));
	req->attrs[2].attr_value_len = challenge_length;

	/* 3 attributes associated with each RADIUS packet. */
	req->num_of_attrs = 3;
}
