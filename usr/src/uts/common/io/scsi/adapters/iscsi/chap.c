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

#include "chap.h"
#include "radius_auth.h"

#include <netinet/in.h>
#include <sys/int_types.h>

chap_validation_status_type
chap_validate(char *target_chap_name,
	char *initiator_chap_name,
	uint8_t *challenge,
	uint8_t *target_response,
	uint8_t identifier,
	authentication_method_type auth_method,
	void *auth_config_data) {

	if (auth_method == RADIUS_AUTHENTICATION) {
		RADIUS_CONFIG *radius_config =
			(RADIUS_CONFIG *)auth_config_data;

		if (radius_config == 0) {
			return (CHAP_VALIDATION_INTERNAL_ERROR);
		}

		return (radius_chap_validate(
			target_chap_name,
			initiator_chap_name,
			challenge,
			target_response,
			identifier,
			radius_config->rad_svr_addr,
			radius_config->rad_svr_port,
			radius_config->rad_svr_shared_secret,
			radius_config->rad_svr_shared_secret_len));
	} else if (auth_method == DIRECT_AUTHENTICATION) {
		return (CHAP_VALIDATION_UNKNOWN_AUTH_METHOD);
	}

	return (CHAP_VALIDATION_UNKNOWN_AUTH_METHOD);
}
