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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_FIPS_DSA_H
#define	_FIPS_DSA_H

#ifdef __cplusplus
extern "C" {
#endif

#define	FIPS_DSA_DIGEST_LENGTH		20 /*  160-bits */
#define	FIPS_DSA_SEED_LENGTH		20 /*  160-bits */
#define	FIPS_DSA_SUBPRIME_LENGTH	20 /*  160-bits */
#define	FIPS_DSA_SIGNATURE_LENGTH	40 /*  320-bits */
#define	FIPS_DSA_PRIME_LENGTH		128 /* 1024-bits */
#define	FIPS_DSA_BASE_LENGTH		128 /* 1024-bits */

typedef struct DSAParams_s {
	uint8_t		*prime;
	int		prime_len;
	uint8_t		*subprime;
	int		subprime_len;
	uint8_t		*base;
	int		base_len;
} DSAParams_t;

typedef struct fips_key_s {
	uint8_t		*key;
	int		key_len;
} fips_key_t;


/* DSA functions */
extern CK_RV fips_generate_dsa_key(DSAkey *, uint8_t *, int);
extern CK_RV fips_dsa_genkey_pair(DSAParams_t *,
	fips_key_t *, fips_key_t *, uint8_t *, int);
extern CK_RV fips_dsa_digest_sign(DSAParams_t *,
	fips_key_t *, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, uint8_t *, int);
extern CK_RV fips_dsa_verify(DSAParams_t *, fips_key_t *,
	CK_BYTE_PTR, CK_BYTE_PTR);

#ifdef	__cplusplus
}
#endif

#endif /* _FIPS_DSA_H */
