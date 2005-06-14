/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 *	crypto.h
 *
 *	Copyright (c) 1997, by Sun Microsystems, Inc.
 *	All rights reserved.
 *
 */

#ifndef _CRYPTO_H_
#define	_CRYPTO_H_

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <rpc/des_crypt.h>
#include <dh_gssapi.h>
#include <dhmech_prot.h>
#include "../crypto/md5.h"

typedef enum { ENCIPHER, DECIPHER } cipher_mode_t;

typedef OM_uint32 (*cipher_proc)(gss_buffer_t buf,
    dh_key_set_t keys, cipher_mode_t mode);
typedef OM_uint32 (*verifier_proc)(gss_buffer_t tok, gss_buffer_t msg,
    cipher_proc signer, dh_key_set_t keys, dh_signature_t signature);

/* Proto types */

void
__dh_release_buffer(gss_buffer_t b);

bool_t
__dh_is_valid_QOP(dh_qop_t qop);

OM_uint32
__QOPSeal(dh_qop_t qop, gss_buffer_t input, int conf_req,
	dh_key_set_t keys, gss_buffer_t output, int *conf_ret);

OM_uint32
__QOPUnSeal(dh_qop_t qop, gss_buffer_t input, int conf_req,
	    dh_key_set_t keys, gss_buffer_t output);

bool_t
__cmpsig(dh_signature_t, dh_signature_t);

OM_uint32
__verify_sig(dh_token_t, dh_qop_t, dh_key_set_t, dh_signature_t);

OM_uint32
__get_sig_size(dh_qop_t, unsigned int *);

OM_uint32
__mk_sig(dh_qop_t, char *, long, gss_buffer_t, dh_key_set_t, dh_signature_t);

OM_uint32
__alloc_sig(dh_qop_t, dh_signature_t);

bool_t
__dh_is_valid_QOP(dh_qop_t);

void
__free_signature(dh_signature_t);

#ifdef __cplusplus
}
#endif

#endif /* _CRYPTO_H_ */
