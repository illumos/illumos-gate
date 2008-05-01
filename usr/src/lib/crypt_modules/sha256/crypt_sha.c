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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Portions of this code from crypt_bsdmd5.so (bsdmd5.c) :
 * ----------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <phk@login.dknet.dk> wrote this file.  As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return.   Poul-Henning Kamp
 * ----------------------------------------------------------------------------
 *
 * $FreeBSD: crypt.c,v 1.5 1996/10/14 08:34:02 phk Exp $
 *
 */

/*
 * Implements the specification from:
 *
 * From http://people.redhat.com/drepper/SHA-crypt.txt
 *
 * Portions of the code taken from inspired by or verified against the
 * source in the above document which is licensed as:
 *
 * "Released into the Public Domain by Ulrich Drepper <drepper@redhat.com>."
 */


#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <alloca.h>

#include <sha2.h>
#include <crypt.h>

#define	MAX_SALT_LEN	16
#define	ROUNDS_DEFAULT	5000
#define	ROUNDS_MIN	1000
#define	ROUNDS_MAX	999999999

#ifdef CRYPT_SHA256

#define	DIGEST_CTX	SHA256_CTX
#define	DIGESTInit	SHA256Init
#define	DIGESTUpdate	SHA256Update
#define	DIGESTFinal	SHA256Final
#define	DIGEST_LEN	SHA256_DIGEST_LENGTH
#define	MIXCHARS	32
static const char crypt_alg_magic[] = "$5$";

#elif CRYPT_SHA512

#define	DIGEST_CTX	SHA512_CTX
#define	DIGESTInit	SHA512Init
#define	DIGESTUpdate	SHA512Update
#define	DIGESTFinal	SHA512Final
#define	DIGEST_LEN	SHA512_DIGEST_LENGTH
#define	MIXCHARS	64
static const char crypt_alg_magic[] = "$6$";

#else
#error	"One of CRYPT_256 or CRYPT_512 must be defined"
#endif

static const int crypt_alg_magic_len = sizeof (crypt_alg_magic) - 1;
static const char rounds_prefix[] = "rounds=";


static uchar_t b64t[] =		/* 0 ... 63 => ascii - 64 */
	"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

#define	b64_from_24bit(B2, B1, B0, N) \
{ \
	uint_t w = ((B2) << 16) | ((B1) << 8) | (B0); \
	int n = (N); \
	while (--n >= 0 && ctbufflen > 0) { \
		*p++ = b64t[w & 0x3f]; \
		w >>= 6; \
		ctbufflen--; \
	} \
}

static void
to64(char *s, uint64_t v, int n)
{
	while (--n >= 0) {
		*s++ = b64t[v&0x3f];
		v >>= 6;
	}
}

char *
crypt_genhash_impl(char *ctbuffer,
	    size_t ctbufflen,
	    const char *plaintext,
	    const char *switchsalt,
	    const char **params)
{
	int salt_len, plaintext_len, i;
	char *salt;
	uchar_t A[DIGEST_LEN];
	uchar_t B[DIGEST_LEN];
	uchar_t DP[DIGEST_LEN];
	uchar_t DS[DIGEST_LEN];
	DIGEST_CTX ctxA, ctxB, ctxC, ctxDP, ctxDS;
	int rounds = ROUNDS_DEFAULT;
	boolean_t custom_rounds = B_FALSE;
	char *p;
	char *P, *Pp;
	char *S, *Sp;

	/* Refine the salt */
	salt = (char *)switchsalt;

	/* skip our magic string */
	if (strncmp((char *)salt, crypt_alg_magic, crypt_alg_magic_len) == 0) {
		salt += crypt_alg_magic_len;
	}

	if (strncmp(salt, rounds_prefix, sizeof (rounds_prefix) - 1) == 0) {
		char *num = salt + sizeof (rounds_prefix) - 1;
		char *endp;
		ulong_t srounds = strtoul(num, &endp, 10);
		if (*endp == '$') {
			salt = endp + 1;
			rounds = MAX(ROUNDS_MIN, MIN(srounds, ROUNDS_MAX));
			custom_rounds = B_TRUE;
		}
	}

	salt_len = MIN(strcspn(salt, "$"), MAX_SALT_LEN);
	plaintext_len = strlen(plaintext);

	/* 1. */
	DIGESTInit(&ctxA);

	/* 2. The password first, since that is what is most unknown */
	DIGESTUpdate(&ctxA, plaintext, plaintext_len);

	/* 3. Then the raw salt */
	DIGESTUpdate(&ctxA, salt, salt_len);

	/* 4. - 8. */
	DIGESTInit(&ctxB);
	DIGESTUpdate(&ctxB, plaintext, plaintext_len);
	DIGESTUpdate(&ctxB, salt, salt_len);
	DIGESTUpdate(&ctxB, plaintext, plaintext_len);
	DIGESTFinal(B, &ctxB);

	/* 9. - 10. */
	for (i = plaintext_len; i > MIXCHARS; i -= MIXCHARS)
		DIGESTUpdate(&ctxA, B, MIXCHARS);
	DIGESTUpdate(&ctxA, B, i);

	/* 11. */
	for (i = plaintext_len; i > 0; i >>= 1) {
		if ((i & 1) != 0) {
			DIGESTUpdate(&ctxA, B, MIXCHARS);
		} else {
			DIGESTUpdate(&ctxA, plaintext, plaintext_len);
		}
	}

	/* 12. */
	DIGESTFinal(A, &ctxA);

	/* 13. - 15. */
	DIGESTInit(&ctxDP);
	for (i = 0; i < plaintext_len; i++)
		DIGESTUpdate(&ctxDP, plaintext, plaintext_len);
	DIGESTFinal(DP, &ctxDP);

	/* 16. */
	Pp = P = alloca(plaintext_len);
	for (i = plaintext_len; i >= MIXCHARS; i -= MIXCHARS) {
		Pp = (char *)(memcpy(Pp, DP, MIXCHARS)) + MIXCHARS;
	}
	memcpy(Pp, DP, i);

	/* 17. - 19. */
	DIGESTInit(&ctxDS);
	for (i = 0; i < 16 + (uint8_t)A[0]; i++)
		DIGESTUpdate(&ctxDS, salt, salt_len);
	DIGESTFinal(DS, &ctxDS);

	/* 20. */
	Sp = S = alloca(salt_len);
	for (i = salt_len; i >= MIXCHARS; i -= MIXCHARS) {
		Sp = (char *)(memcpy(Sp, DS, MIXCHARS)) + MIXCHARS;
	}
	memcpy(Sp, DS, i);

	/*  21. */
	for (i = 0; i < rounds; i++) {
		DIGESTInit(&ctxC);

		if ((i & 1) != 0) {
			DIGESTUpdate(&ctxC, P, plaintext_len);
		} else {
			if (i == 0)
				DIGESTUpdate(&ctxC, A, MIXCHARS);
			else
				DIGESTUpdate(&ctxC, DP, MIXCHARS);
		}

		if (i % 3 != 0) {
			DIGESTUpdate(&ctxC, S, salt_len);
		}

		if (i % 7 != 0) {
			DIGESTUpdate(&ctxC, P, plaintext_len);
		}

		if ((i & 1) != 0) {
			if (i == 0)
				DIGESTUpdate(&ctxC, A, MIXCHARS);
			else
				DIGESTUpdate(&ctxC, DP, MIXCHARS);
		} else {
			DIGESTUpdate(&ctxC, P, plaintext_len);
		}
		DIGESTFinal(DP, &ctxC);
	}

	/* 22. Now make the output string */
	(void) strlcpy(ctbuffer, crypt_alg_magic, ctbufflen);
	if (custom_rounds) {
		(void) snprintf(ctbuffer, ctbufflen,
		    "%srounds=%zu$", ctbuffer, rounds);
	}

	(void) strncat(ctbuffer, (const char *)salt, MAX_SALT_LEN);
	(void) strlcat(ctbuffer, "$", ctbufflen);
	p = ctbuffer + strlen(ctbuffer);
	ctbufflen -= strlen(ctbuffer);

#ifdef CRYPT_SHA256
	b64_from_24bit(DP[ 0], DP[10], DP[20], 4);
	b64_from_24bit(DP[21], DP[ 1], DP[11], 4);
	b64_from_24bit(DP[12], DP[22], DP[ 2], 4);
	b64_from_24bit(DP[ 3], DP[13], DP[23], 4);
	b64_from_24bit(DP[24], DP[ 4], DP[14], 4);
	b64_from_24bit(DP[15], DP[25], DP[ 5], 4);
	b64_from_24bit(DP[ 6], DP[16], DP[26], 4);
	b64_from_24bit(DP[27], DP[ 7], DP[17], 4);
	b64_from_24bit(DP[18], DP[28], DP[ 8], 4);
	b64_from_24bit(DP[ 9], DP[19], DP[29], 4);
	b64_from_24bit(0, DP[31], DP[30], 3);
#elif CRYPT_SHA512
	b64_from_24bit(DP[ 0], DP[21], DP[42], 4);
	b64_from_24bit(DP[22], DP[43], DP[ 1], 4);
	b64_from_24bit(DP[44], DP[ 2], DP[23], 4);
	b64_from_24bit(DP[ 3], DP[24], DP[45], 4);
	b64_from_24bit(DP[25], DP[46], DP[ 4], 4);
	b64_from_24bit(DP[47], DP[ 5], DP[26], 4);
	b64_from_24bit(DP[ 6], DP[27], DP[48], 4);
	b64_from_24bit(DP[28], DP[49], DP[ 7], 4);
	b64_from_24bit(DP[50], DP[ 8], DP[29], 4);
	b64_from_24bit(DP[ 9], DP[30], DP[51], 4);
	b64_from_24bit(DP[31], DP[52], DP[10], 4);
	b64_from_24bit(DP[53], DP[11], DP[32], 4);
	b64_from_24bit(DP[12], DP[33], DP[54], 4);
	b64_from_24bit(DP[34], DP[55], DP[13], 4);
	b64_from_24bit(DP[56], DP[14], DP[35], 4);
	b64_from_24bit(DP[15], DP[36], DP[57], 4);
	b64_from_24bit(DP[37], DP[58], DP[16], 4);
	b64_from_24bit(DP[59], DP[17], DP[38], 4);
	b64_from_24bit(DP[18], DP[39], DP[60], 4);
	b64_from_24bit(DP[40], DP[61], DP[19], 4);
	b64_from_24bit(DP[62], DP[20], DP[41], 4);
	b64_from_24bit(0, 0, DP[63], 2);
#endif
	*p = '\0';

	(void) memset(A, 0, sizeof (A));
	(void) memset(B, 0, sizeof (B));
	(void) memset(DP, 0, sizeof (DP));
	(void) memset(DS, 0, sizeof (DS));

	return (ctbuffer);
}

char *
crypt_gensalt_impl(char *gsbuffer,
	    size_t gsbufflen,
	    const char *oldsalt,
	    const struct passwd *userinfo,
	    const char **params)
{
	int fd;
	int err;
	ssize_t got;
	uint64_t rndval;

	if ((fd = open("/dev/urandom", O_RDONLY)) == -1) {
		return (NULL);
	}

	(void) strlcpy(gsbuffer, crypt_alg_magic, gsbufflen);

	got = read(fd, &rndval, sizeof (rndval));
	if (got < sizeof (rndval)) {
		err = errno;
		(void) close(fd);
		errno = err;
		return (NULL);
	}

	to64(&gsbuffer[strlen(crypt_alg_magic)], rndval, sizeof (rndval));

	(void) close(fd);

	return (gsbuffer);
}
