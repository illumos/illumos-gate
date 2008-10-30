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
#ifndef	_RADIUS_AUTH_H
#define	_RADIUS_AUTH_H

#ifdef __cplusplus
extern "C" {
#endif

#include <netinet/in.h>
#include <sys/iscsit/chap.h>

/*
 * Function: iscsit_radius_chap_validate
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
		uint32_t rad_svr_shared_secret_len);
#ifdef __cplusplus
}
#endif

#endif /* _RADIUS_AUTH_H */
