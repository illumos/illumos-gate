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

/*
 * Portions of this code:
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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <errno.h>

#include <md5.h>
#include <crypt.h>

static const char crypt_alg_magic[] = "$1$";

#define	SALT_LEN	8

static uchar_t itoa64[] =		/* 0 ... 63 => ascii - 64 */
	"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

static void
to64(char *s, uint64_t v, int n)
{
	while (--n >= 0) {
		*s++ = itoa64[v & 0x3f];
		v >>= 6;
	}
}


/* ARGSUSED4 */
char *
crypt_genhash_impl(char *ctbuffer,
	    size_t ctbufflen,
	    const char *plaintext,
	    const char *switchsalt,
	    const char **params)
{
	char *p;
	int sl, l, pl, i;
	uchar_t *sp, *ep;
	uchar_t final[16]; /* XXX: 16 is some number from the orig source */
	MD5_CTX ctx, ctx1;
	const int crypt_alg_magic_len = strlen(crypt_alg_magic);

	/* Refine the salt */
	sp = (uchar_t *)switchsalt;

	/* skip our magic string */
	if (strncmp((char *)sp, crypt_alg_magic, crypt_alg_magic_len) == 0) {
		sp += crypt_alg_magic_len;
	}

	/* Salt stops at the first $, max SALT_LEN chars */
	for (ep = sp; *ep && *ep != '$' && ep < (sp + SALT_LEN); ep++)
		continue;

	sl = ep - sp;

	MD5Init(&ctx);

	/* The password first, since that is what is most unknown */
	MD5Update(&ctx, (uchar_t *)plaintext, strlen(plaintext));

	/* Then our magic string */
	MD5Update(&ctx, (uchar_t *)crypt_alg_magic, strlen(crypt_alg_magic));

	/* Then the raw salt */
	MD5Update(&ctx, (uchar_t *)sp, sl);

	/* Then just as many characters of the MD5(plaintext,salt,plaintext) */
	MD5Init(&ctx1);
	MD5Update(&ctx1, (uchar_t *)plaintext, strlen(plaintext));
	MD5Update(&ctx1, sp, sl);
	MD5Update(&ctx1, (uchar_t *)plaintext, strlen(plaintext));
	MD5Final(final, &ctx1);
	for (pl = strlen(plaintext); pl > 0; pl -= 16)
		MD5Update(&ctx, final, pl > 16 ? 16 : pl);

	/* Don't leave anything around in vm they could use. */
	(void) memset(final, 0, sizeof (final));

	/* Then something really weird... */
	for (i = strlen(plaintext); i; i >>= 1) {
		if (i & 1) {
			MD5Update(&ctx, final, 1);
		} else {
			MD5Update(&ctx, (uchar_t *)plaintext, 1);
		}
	}

	/* Now make the output string */
	(void) strlcpy(ctbuffer, crypt_alg_magic, ctbufflen);
	(void) strncat(ctbuffer, (const char *)sp, sl);
	(void) strlcat(ctbuffer, "$", ctbufflen);

	MD5Final(final, &ctx);

	/*
	 * and now, just to make sure things don't run too fast
	 * On a 60 Mhz Pentium this takes 34 msec, so you would
	 * need 30 seconds to build a 1000 entry dictionary...
	 */
	for (i = 0; i < 1000; i++) {
		MD5Init(&ctx1);
		if (i & 1)
			MD5Update(&ctx1, (uchar_t *)plaintext,
			    strlen(plaintext));
		else
			MD5Update(&ctx1, final, 16);

		if (i % 3)
			MD5Update(&ctx1, sp, sl);

		if (i % 7)
			MD5Update(&ctx1, (uchar_t *)plaintext,
			    strlen(plaintext));

		if (i & 1)
			MD5Update(&ctx1, final, 16);
		else
			MD5Update(&ctx1, (uchar_t *)plaintext,
			    strlen(plaintext));
		MD5Final(final, &ctx1);
	}

	p = ctbuffer + strlen(ctbuffer);

	l = (final[ 0]<<16) | (final[ 6]<<8) | final[12]; to64(p, l, 4); p += 4;
	l = (final[ 1]<<16) | (final[ 7]<<8) | final[13]; to64(p, l, 4); p += 4;
	l = (final[ 2]<<16) | (final[ 8]<<8) | final[14]; to64(p, l, 4); p += 4;
	l = (final[ 3]<<16) | (final[ 9]<<8) | final[15]; to64(p, l, 4); p += 4;
	l = (final[ 4]<<16) | (final[10]<<8) | final[ 5]; to64(p, l, 4); p += 4;
	l = final[11]; to64(p, l, 2); p += 2;
	*p = '\0';

	/* Don't leave anything around in vm they could use. */
	(void) memset(final, 0, sizeof (final));

	return (ctbuffer);
}


/* ARGSUSED2 */
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
