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

#include <sys/types.h>
#include <sys/random.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#include <sys/socket.h>
#include <inet/tcp.h>

#include <sys/stmf.h>
#include <sys/stmf_ioctl.h>
#include <sys/portif.h>
#include <sys/idm/idm.h>
#include <sys/iscsit/chap.h>

#include "iscsit.h"
#include "radius_auth.h"

void
client_set_numeric_data(auth_key_block_t *keyBlock,
    int key_type,
    uint32_t numeric)
{
	auth_key_t *p;

	ASSERT(key_type < AUTH_KEY_TYPE_MAX);

	p = &keyBlock->key[key_type];
	p->value.numeric = numeric;
	p->present = 1;
}

void
client_set_string_data(auth_key_block_t *keyBlock,
    int key_type,
    char *string)
{
	auth_key_t *p;

	ASSERT(key_type < AUTH_KEY_TYPE_MAX);

	p = &keyBlock->key[key_type];
	p->value.string = string;
	p->present = 1;
}

void
client_set_binary_data(auth_key_block_t *keyBlock,
    int key_type,
    unsigned char *binary, unsigned int len)
{
	auth_key_t *p;

	ASSERT(key_type < AUTH_KEY_TYPE_MAX);

	p = &keyBlock->key[key_type];
	p->value.binary = binary;
	p->len = len;
	p->present = 1;
}

void
client_get_numeric_data(auth_key_block_t *keyBlock,
    int key_type,
    uint32_t *numeric)
{
	auth_key_t *p;

	ASSERT(key_type < AUTH_KEY_TYPE_MAX);

	p = &keyBlock->key[key_type];
	*numeric = p->value.numeric;
}

void
client_get_string_data(auth_key_block_t *keyBlock,
    int key_type,
    char **string)
{
	auth_key_t *p;

	ASSERT(key_type < AUTH_KEY_TYPE_MAX);

	p = &keyBlock->key[key_type];
	*string = p->value.string;
}

void
client_get_binary_data(auth_key_block_t *keyBlock,
    int key_type,
    unsigned char **binary, unsigned int *len)
{
	auth_key_t *p;

	ASSERT(key_type < AUTH_KEY_TYPE_MAX);

	p = &keyBlock->key[key_type];
	*binary = p->value.binary;
	*len = p->len;
}

int
client_auth_key_present(auth_key_block_t *keyBlock,
    int key_type)
{
	auth_key_t *p;

	ASSERT(key_type < AUTH_KEY_TYPE_MAX);

	p = &keyBlock->key[key_type];

	return (p->present != 0 ? 1 : 0);
}

/*ARGSUSED*/
void
client_compute_chap_resp(uchar_t *resp,
    unsigned int chap_i,
    uint8_t *password, int password_len,
    uchar_t *chap_c, unsigned int challenge_len)
{
	MD5_CTX		context;

	MD5Init(&context);

	/*
	 * id byte
	 */
	resp[0] = (uchar_t)chap_i;
	MD5Update(&context, resp, 1);

	/*
	 * shared secret
	 */
	MD5Update(&context, (uchar_t *)password, password_len);

	/*
	 * challenge value
	 */
	MD5Update(&context, chap_c, challenge_len);

	MD5Final(resp, &context);
}

int
iscsit_verify_chap_resp(iscsit_conn_login_t *lsm,
    unsigned int chap_i,
    uchar_t *chap_c, unsigned int challenge_len,
    uchar_t *chap_r, unsigned int resp_len)
{
	uchar_t		verifyData[iscsitAuthChapResponseLength];
	conn_auth_t	*auth = &lsm->icl_auth;

	/* Check if RADIUS access is enabled */
	if (auth->ca_use_radius == B_TRUE) {
		chap_validation_status_type	chap_valid_status;
		RADIUS_CONFIG		radius_cfg;
		struct sockaddr_storage *sa = &auth->ca_radius_server;
		struct sockaddr_in	*sin;
		struct sockaddr_in6	*sin6;

		/* Use RADIUS server to authentication target */
		sin = (struct sockaddr_in *)sa;
		radius_cfg.rad_svr_port = ntohs(sin->sin_port);
		if (sa->ss_family == AF_INET) {
			/* IPv4 */
			radius_cfg.rad_svr_addr.i_addr.in4.s_addr =
			    sin->sin_addr.s_addr;
			radius_cfg.rad_svr_addr.i_insize = sizeof (in_addr_t);
		} else if (sa->ss_family == AF_INET6) {
			/* IPv6 */
			sin6 = (struct sockaddr_in6 *)sa;
			bcopy(sin6->sin6_addr.s6_addr,
			    radius_cfg.rad_svr_addr.i_addr.in6.s6_addr,
			    sizeof (struct in6_addr));
			radius_cfg.rad_svr_addr.i_insize = sizeof (in6_addr_t);
		} else {
			return (ISCSI_AUTH_FAILED);
		}

		bcopy(auth->ca_radius_secret,
		    radius_cfg.rad_svr_shared_secret,
		    MAX_RAD_SHARED_SECRET_LEN);
		radius_cfg.rad_svr_shared_secret_len =
		    auth->ca_radius_secretlen;

		chap_valid_status = iscsit_radius_chap_validate(
		    auth->ca_ini_chapuser,
		    auth->ca_tgt_chapuser,
		    chap_c,
		    challenge_len,
		    chap_r,
		    resp_len,
		    chap_i,
		    radius_cfg.rad_svr_addr,
		    radius_cfg.rad_svr_port,
		    radius_cfg.rad_svr_shared_secret,
		    radius_cfg.rad_svr_shared_secret_len);

		if (chap_valid_status == CHAP_VALIDATION_PASSED) {
			return (ISCSI_AUTH_PASSED);
		}
		return (ISCSI_AUTH_FAILED);
	}

	/* Empty chap secret is not allowed */
	if (auth->ca_ini_chapsecretlen == 0) {
		return (ISCSI_AUTH_FAILED);
	}

	/* only MD5 is supported */
	if (resp_len != sizeof (verifyData)) {
		return (ISCSI_AUTH_FAILED);
	}

	client_compute_chap_resp(
	    &verifyData[0],
	    chap_i,
	    auth->ca_ini_chapsecret, auth->ca_ini_chapsecretlen,
	    chap_c, challenge_len);

	if (bcmp(chap_r, verifyData,
	    sizeof (verifyData)) != 0) {
		return (ISCSI_AUTH_FAILED);
	}

	/* chap response OK */
	return (ISCSI_AUTH_PASSED);
}

void
auth_random_set_data(uchar_t *data, unsigned int length)
{
	(void) random_get_pseudo_bytes(data, length);
}
