/*
 * Copyright (c) 1996, David Mazieres <dm@uun.org>
 * Copyright (c) 2008, Damien Miller <djm@openbsd.org>
 * Copyright (c) 2013, Markus Friedl <markus@openbsd.org>
 * Copyright (c) 2015 Joyent, Inc.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * arc4random(3C), derived from the OpenBSD version.
 *
 * To ensure that a parent process and any potential children see a different
 * state, we mmap the entire arc4_state_t structure and mark that page as
 * MC_INHERIT_ZERO. That ensures that the data is zeroed, and really the bit we
 * care about, arc4_init is set to B_FALSE, which will cause the child to
 * reinitialize it when they first use the interface.
 */

#include <synch.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/sysmacros.h>
#include <chacha.h>

#include "thr_uberdata.h"

#define	ARC4_KEYSZ	32
#define	ARC4_IVSZ	8
#define	ARC4_BLOCKSZ	64
#define	ARC4_KSBUFSZ	(16*ARC4_BLOCKSZ)	/* key stream byte size */
#define	ARC4_COUNT	1600000			/* bytes for rekeying */

typedef struct arc4_state {
	boolean_t	arc4_init;		/* Initialized? */
	size_t		arc4_have;		/* Valid bytes in arc4_buf */
	size_t		arc4_count;		/* bytes until reseed */
	chacha_ctx_t	arc4_chacha;		/* chacha context */
	uint8_t		arc4_buf[ARC4_KSBUFSZ];	/* keystream blocks */
} arc4_state_t;

static arc4_state_t *arc4;
static mutex_t arc4_lock = DEFAULTMUTEX;

static void
arc4_init(uint8_t *buf, size_t n)
{
	if (n < ARC4_KEYSZ + ARC4_IVSZ)
		abort();

	chacha_keysetup(&arc4->arc4_chacha, buf, ARC4_KEYSZ * 8, 0);
	chacha_ivsetup(&arc4->arc4_chacha, buf + ARC4_KEYSZ);
}

static void
arc4_rekey(uint8_t *data, size_t datalen)
{
	/* Fill in the keystream buffer */
	chacha_encrypt_bytes(&arc4->arc4_chacha, arc4->arc4_buf, arc4->arc4_buf,
	    sizeof (arc4->arc4_buf));

	/* mix in optional user provided data */
	if (data != NULL) {
		size_t i, m;

		m = MIN(datalen, ARC4_KEYSZ + ARC4_IVSZ);
		for (i = 0; i < m; i++)
			arc4->arc4_buf[i] ^= data[i];
	}

	/* immediately reinit for backtracking resistence */
	arc4_init(arc4->arc4_buf, ARC4_KEYSZ + ARC4_IVSZ);
	explicit_bzero(arc4->arc4_buf, ARC4_KEYSZ + ARC4_IVSZ);
	arc4->arc4_have = sizeof (arc4->arc4_buf) - ARC4_KEYSZ - ARC4_IVSZ;
}

static void
arc4_stir(size_t len)
{
	uint8_t rnd[ARC4_KEYSZ + ARC4_IVSZ];

	if (arc4->arc4_count <= len) {
		if (getentropy(rnd, sizeof (rnd)) == -1)
			abort();

		if (arc4->arc4_init == B_FALSE) {
			arc4_init(rnd, sizeof (rnd));
			arc4->arc4_init = B_TRUE;
		} else {
			arc4_rekey(rnd, sizeof (rnd));
		}
		explicit_bzero(rnd, sizeof (rnd));

		/* Invalidate the data buffer */
		arc4->arc4_have = 0;
		memset(arc4->arc4_buf, 0, sizeof (arc4->arc4_buf));
		arc4->arc4_count = ARC4_COUNT;
	}

	if (arc4->arc4_count <= len) {
		arc4->arc4_count = 0;
	} else {
		arc4->arc4_count -= len;
	}
}

static void
arc4_fill(uint8_t *buf, size_t n)
{
	if (arc4 == NULL) {
		size_t pgsz, mapsz;
		void *a;

		pgsz = sysconf(_SC_PAGESIZE);
		if (pgsz == -1)
			abort();
		mapsz = P2ROUNDUP(sizeof (arc4_state_t), pgsz);
		a = mmap(NULL, mapsz, PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANON, -1, 0);
		if (a == MAP_FAILED)
			abort();
		if (memcntl(a, mapsz, MC_INHERIT_ZERO, 0, 0, 0) != 0)
			abort();
		arc4 = a;
	}

	arc4_stir(n);
	while (n > 0) {
		if (arc4->arc4_have > 0) {
			uint8_t *keystream;
			size_t m = MIN(n, arc4->arc4_have);

			keystream = arc4->arc4_buf + sizeof (arc4->arc4_buf) -
			    arc4->arc4_have;
			memcpy(buf, keystream, m);
			explicit_bzero(keystream, m);
			buf += m;
			n -= m;
			arc4->arc4_have -= m;
		}
		if (arc4->arc4_have == 0)
			arc4_rekey(NULL, 0);
	}
}

uint32_t
arc4random(void)
{
	uint32_t out;

	lmutex_lock(&arc4_lock);
	arc4_fill((uint8_t *)&out, sizeof (uint32_t));
	lmutex_unlock(&arc4_lock);
	return (out);
}

void
arc4random_buf(void *buf, size_t n)
{
	lmutex_lock(&arc4_lock);
	arc4_fill(buf, n);
	lmutex_unlock(&arc4_lock);
}
