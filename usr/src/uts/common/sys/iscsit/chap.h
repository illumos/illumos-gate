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

#ifndef	_CHAP_H
#define	_CHAP_H

#ifdef __cplusplus
extern "C" {
#endif

#include <netinet/in.h>
#include <sys/int_types.h>

#include <sys/iscsit/iscsi_if.h>
#include <sys/iscsit/radius_protocol.h>

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

typedef struct radius_config {
	iscsi_ipaddr_t	rad_svr_addr;	/* IPv6 enabled */
	uint32_t	rad_svr_port;
	uint8_t		rad_svr_shared_secret[MAX_RAD_SHARED_SECRET_LEN];
	uint32_t	rad_svr_shared_secret_len;
} RADIUS_CONFIG;

/*
 * To validate a target CHAP response given the associated challenge.
 *
 * target_chap_name - The CHAP name of the target being authenticated.
 * initiator_chap_name - The CHAP name of the authenticating initiator.
 * challenge - The CHAP challenge to which the target responded.
 * target_response - The target's CHAP response to be validated.
 * identifier - The identifier associated with the CHAP challenge.
 * auth_method - The authentication method to be used.
 * auth_config_data - Any required configuration data to support the
 *                    specified authentication method.
 */
chap_validation_status_type
chap_validate(
	char *target_chap_name,
	char *initiator_chap_name,
	uint8_t *challenge,
	uint8_t *target_response,
	uint8_t identifier,
	authentication_method_type auth_method,
	void *auth_config_data);

#ifdef __cplusplus
}
#endif

#endif /* _CHAP_H */
