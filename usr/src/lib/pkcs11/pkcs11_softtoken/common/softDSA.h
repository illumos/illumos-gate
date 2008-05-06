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

#ifndef _SOFTDSA_H
#define	_SOFTDSA_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <security/pkcs11t.h>
#include <bignum.h>
#include "softObject.h"
#include "softSession.h"

/* DSA Signature is always 40 bytes */
#define	DSA_SIGNATURE_LENGTH	40
#define	MAX_DSA_KEY_LEN		(1024 >> 3)
#define	MIN_DSA_KEY_LEN		(512 >> 3)

#define	DSA_SUBPRIME_BITS	160
#define	DSA_SUBPRIME_BYTES	(DSA_SUBPRIME_BITS >> 3)

typedef struct soft_dsa_ctx {
	soft_object_t *key;
} soft_dsa_ctx_t;

typedef struct {
	int 	size;		/* key size in bits */
	BIGNUM	q;		/* q (160-bit prime) */
	BIGNUM	p;		/* p (<size-bit> prime) */
	BIGNUM	g;		/* g (the base) */
	BIGNUM	x;		/* private key (< q) */
	BIGNUM	y;		/* = g^x mod p */
	BIGNUM	k;		/* k (random number < q) */
	BIGNUM	r;		/* r (signiture 1st part) */
	BIGNUM	s;		/* s (signiture 2nd part) */
	BIGNUM	v;		/* v (verification value - should be = r ) */
	BIGNUM	p_rr;		/* 2^(2*(32*p->len)) mod p */
	BIGNUM	q_rr;		/* 2^(2*(32*q->len)) mod q */
} DSAkey;


/*
 * Function Prototypes.
 */

/* DSA */

CK_RV soft_dsa_sign_verify_init_common(soft_session_t *, CK_MECHANISM_PTR,
	soft_object_t *, boolean_t);

CK_RV soft_dsa_verify(soft_session_t *, CK_BYTE_PTR, CK_ULONG,
	CK_BYTE_PTR, CK_ULONG);

CK_RV soft_dsa_sign(soft_session_t *, CK_BYTE_PTR, CK_ULONG,
	CK_BYTE_PTR, CK_ULONG_PTR);

BIG_ERR_CODE DSA_key_init(DSAkey *, int);

void DSA_key_finish(DSAkey *);

CK_RV soft_dsa_genkey_pair(soft_object_t *, soft_object_t *);

CK_RV soft_dsa_digest_sign_common(soft_session_t *, CK_BYTE_PTR,
    CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR, boolean_t);

CK_RV soft_dsa_digest_verify_common(soft_session_t *, CK_BYTE_PTR,
    CK_ULONG, CK_BYTE_PTR, CK_ULONG, boolean_t);

#ifdef	__cplusplus
}
#endif

#endif /* _SOFTDSA_H */
