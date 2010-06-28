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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

#if !defined(K_SOLARIS_PLATFORM) || defined(SOLARIS10)
#include "rijndael.h"
#else
#include <stdlib.h>
#include <aes_impl.h>
#endif 

#ifdef METAWARE
#include "sizet.h"
typedef unsigned char		uint8_t;
typedef unsigned short		uint16_t;
typedef unsigned int		uint32_t;
typedef unsigned long long	uint64_t;
#include <string.h>
#else
#ifndef WIN32
#include <strings.h>
#endif
#endif

#include "KMSAgentAESKeyWrap.h"

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

#ifdef WIN32
#define ovbcopy(x, y, z) memmove(y, x, z);
#else
#define ovbcopy(x, y, z) bcopy(x, y, z);
#endif

#ifndef K_SOLARIS_PLATFORM
/* similar to iovec except that it accepts const pointers */
struct vector {
	const void	*base;
	size_t		len;
};

#ifdef METAWARE
#define bcopy(s1, s2, n)  memcpy(s2, s1, n)
#endif

/*
 * AES Key Wrap (see RFC 3394).
 */
#endif /* K_SOLARIS_PLATFORM */

static const uint8_t aes_key_wrap_iv[8] =
	{ 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6 };

void aes_key_wrap (const uint8_t *kek,
                   size_t kek_len,
                   const uint8_t *pt,
                   size_t len,
                   uint8_t *ct)
{
#if !defined(K_SOLARIS_PLATFORM) || defined(SOLARIS10)
	rijndael_ctx ctx;
#else
	void *ks;
	size_t ks_size;
#endif
	uint8_t *a, *r, ar[16], t, b[16];
	size_t i;
	int j;

	/*
	 * Only allow lengths for 't' values that fit within a byte.  This 
	 * covers all reasonable uses of AES Key Wrap
	 */
	if (len > (255 / 6)) {
		return;
	}

	/* allow ciphertext and plaintext to overlap (ct == pt) */
	ovbcopy(pt, ct + 8, len * 8);

	a = ct;
	memcpy(a, aes_key_wrap_iv, 8);	/* default IV */

#if !defined(K_SOLARIS_PLATFORM) || defined(SOLARIS10)
	rijndael_set_key_enc_only(&ctx, (uint8_t *)kek, kek_len * 8);
#else
	ks = aes_alloc_keysched(&ks_size, 0);
	if (ks == NULL)
		return;
	aes_init_keysched(kek, kek_len * 8, ks);
#endif

	for (j = 0, t = 1; j < 6; j++) {
		r = ct + 8;
		for (i = 0; i < len; i++, t++) {
			memcpy(ar, a, 8);
			memcpy(ar + 8, r, 8);
#if !defined(K_SOLARIS_PLATFORM) || defined(SOLARIS10)
			rijndael_encrypt(&ctx, ar, b);
#else
			(void) aes_encrypt_block(ks, ar, b);
#endif

			b[7] ^= t;
			memcpy(a, &b[0], 8);
			memcpy(r, &b[8], 8);

			r += 8;
		}
	}
#if defined(K_SOLARIS_PLATFORM) && !defined(SOLARIS10)
	free(ks);
#endif
}

int aes_key_unwrap (const uint8_t *kek,
                    size_t kek_len,
                    const uint8_t *ct,
                    uint8_t *pt,
                    size_t len)
{
#if !defined(K_SOLARIS_PLATFORM) || defined(SOLARIS10)
	rijndael_ctx ctx;
#else
	void *ks;
	size_t ks_size;
#endif
	uint8_t a[8], *r, b[16], t, ar[16];
	size_t i;
	int j;

	/*
	 * Only allow lengths for 't' values that fit within a byte.  This
	 * covers all reasonable uses of AES Key Wrap
	 */
	if (len > (255 / 6)) {
		return (-1);
	}

	memcpy(a, ct, 8);
	/* allow ciphertext and plaintext to overlap (ct == pt) */
	ovbcopy(ct + 8, pt, len * 8);

#if !defined(K_SOLARIS_PLATFORM) || defined(SOLARIS10)
	rijndael_set_key(&ctx, (uint8_t *)kek, kek_len * 8);
#else
	ks = aes_alloc_keysched(&ks_size, 0);
	if (ks == NULL)
		return (-1);
	aes_init_keysched(kek, kek_len * 8, ks);
#endif

	for (j = 0, t = 6 * len; j < 6; j++) {
		r = pt + (len - 1) * 8;
		for (i = 0; i < len; i++, t--) {
			memcpy(&ar[0], a, 8);
			ar[7] ^= t;
			memcpy(&ar[8], r, 8);
#if !defined(K_SOLARIS_PLATFORM) || defined(SOLARIS10)
			rijndael_decrypt(&ctx, ar, b);
#else
			(void) aes_decrypt_block(ks, ar, b);
#endif
			memcpy(a, b, 8);
			memcpy(r, b + 8, 8);
			r -= 8;
		}
	}
#if defined(K_SOLARIS_PLATFORM) && !defined(SOLARIS10)
	free(ks);
#endif

	return memcmp(a, aes_key_wrap_iv, 8) != 0;
}
