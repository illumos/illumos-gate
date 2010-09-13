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
 * Copyright 2002-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/sha1.h>
#include <sys/sha1_consts.h>
#include "hmac_sha1.h"

static void
HMACHashKey(uchar_t *hashedKey, const uchar_t *key, size_t klen)
{
	SHA1_CTX keyContext;

	SHA1Init(&keyContext);
	SHA1Update(&keyContext, key, klen);
	SHA1Final(hashedKey, &keyContext);
}

void
HMACInit(SHA1_CTX *sha1Context, const uchar_t *key, size_t klen)
{
	uchar_t hashedKey[20];
	const uchar_t *keyptr;
	uchar_t kipad[64];
	int i;

	if (klen > 64) {
		HMACHashKey(hashedKey, key, klen);
		keyptr = hashedKey;
		klen = 20;
	} else {
		keyptr = key;
	}

	/* kipad = K XOR ipad */
	for (i = 0; i < 64; i++) {
		kipad[i] = (i < klen ? keyptr[i] : 0) ^ 0x36;
	}

	SHA1Init(sha1Context);
	SHA1Update(sha1Context, kipad, 64);
}

void
HMACUpdate(SHA1_CTX *sha1Context, const uchar_t *data, size_t dlen)
{
	SHA1Update(sha1Context, data, dlen);
}

void
HMACFinal(SHA1_CTX *sha1Context, const uchar_t *key, size_t klen,
    uchar_t digest[20])
{
	uchar_t hashedKey[20];
	const uchar_t *keyptr;
	uchar_t kopad[64];
	int i;

	if (klen > 64) {
		HMACHashKey(hashedKey, key, klen);
		keyptr = hashedKey;
		klen = 20;
	} else {
		keyptr = key;
	}

	/* kopad = K XOR opad */
	for (i = 0; i < 64; i++) {
		kopad[i] = (i < klen ? keyptr[i] : 0) ^ 0x5c;
	}

	/* Compute H(kopad, H(kipad, text)) */
	SHA1Final(digest, sha1Context);

	SHA1Init(sha1Context);
	SHA1Update(sha1Context, kopad, 64);
	SHA1Update(sha1Context, digest, 20);
	SHA1Final(digest, sha1Context);
}
