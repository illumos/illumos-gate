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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "mt.h"
#include <stdlib.h>
#include <mp.h>
#include <rpc/key_prot.h>
#include <rpcsvc/nis_dhext.h>
#include <thread.h>

extern long	random();
extern void	_mp_move(MINT *, MINT *);
extern void	des_setparity(char *);
static void	adjust();
void		__gen_dhkeys();

static MINT	*MODULUS_192_0;
static mutex_t	mod_192_0_lck = DEFAULTMUTEX;
static bool_t	first_time = TRUE;

/*
 * symbol names for the entry points into the Diffie-Hellman
 * GSS mech backend routines
 */
static char	dl_gen_funcname[] = "__dl_gen_dhkeys";
static char	dl_gen_common_funcname[] = "__dl_gen_common_dhkeys";

/*
 * Generate a seed
 */
static void
getseed(seed, seedsize, pass)
char *seed;
int seedsize;
unsigned char *pass;
{
	int i;
	int rseed;
	struct timeval tv;

	(void) gettimeofday(&tv, (struct timezone *)NULL);
	rseed = tv.tv_sec + tv.tv_usec;
	for (i = 0; i < 8; i++) {
		rseed ^= (rseed << 8) | pass[i];
	}
	(void) srandom(rseed);

	for (i = 0; i < seedsize; i++) {
		seed[i] = (random() & 0xff) ^ pass[i % 8];
	}
}

/*
 * Adjust the input key so that it is 0-filled on the left
 */
static void
adjust(keyout, keyin)
char keyout[HEXKEYBYTES + 1];
char *keyin;
{
	char *p;
	char *s;

	for (p = keyin; *p; p++)
		;
	for (s = keyout + HEXKEYBYTES; p >= keyin; p--, s--) {
		*s = *p;
	}
	while (s >= keyout) {
		*s-- = '0';
	}
}

/*
 * generate a Diffie-Hellman key-pair based on the given password.
 * public and secret are buffers of size HEXKEYBYTES + 1.
 */
void
__gen_dhkeys(public, secret, pass)
char *public;
char *secret;
char *pass;
{
	int i;

#define	BASEBITS	(8 * sizeof (short) - 1)
#define	BASE		(1 << BASEBITS)

	MINT *pk = mp_itom(0);
	MINT *sk = mp_itom(0);
	MINT *tmp;
	MINT *base = mp_itom(BASE/2);	/* BASE won't fit in a short */
	MINT *root = mp_itom(PROOT);
	MINT *modulus = mp_xtom(HEXMODULUS);
	unsigned short r;
	unsigned short seed[KEYSIZE/BASEBITS + 1];
	char *xkey;

	/* multiply base by 2 to get BASE */
	tmp = mp_itom(2);
	mp_mult(base, tmp, base);
	mp_mfree(tmp);

	getseed((char *)seed, (int)sizeof (seed), (uchar_t *)pass);
	for (i = 0; i < KEYSIZE/BASEBITS + 1; i++) {
		r = seed[i] % ((unsigned short)BASE);
		tmp = mp_itom(r);
		mp_mult(sk, base, sk);
		mp_madd(sk, tmp, sk);
		mp_mfree(tmp);
	}
	tmp = mp_itom(0);
	mp_mdiv(sk, modulus, tmp, sk);
	mp_mfree(tmp);
	mp_pow(root, sk, modulus, pk);
	xkey = mp_mtox(sk);
	(void) adjust(secret, xkey);
	xkey = mp_mtox(pk);
	(void) adjust(public, xkey);
	mp_mfree(sk);
	mp_mfree(base);
	mp_mfree(pk);
	mp_mfree(root);
	mp_mfree(modulus);
}


/*
 * Generic key size Diffie-Hellman key pair generation routine.  For classic
 * AUTH_DES, just call the current routine to handle it.  Else, call the
 * one in the appro GSS mech backend.
 *
 */
int
__gen_dhkeys_g(char *pkey,	/* out */
	char *skey,		/* out */
	keylen_t keylen,	/* in  */
	algtype_t algtype,	/* in  */
	char *pass)		/* in  */
{
	const int classic_des = keylen == 192 && algtype == 0;

	if (! pkey || ! skey || ! pass)
		return (0);

	if (classic_des) {
		__gen_dhkeys(pkey, skey, pass);
		return (1);
	} else {
		int (*dlfp)(); /* func ptr to dynamic loaded lib */

		if (dlfp = (int (*)())__nis_get_mechanism_symbol(keylen,
							algtype,
							dl_gen_funcname)) {
			(*dlfp)(pkey, skey, pass); /* void */
			return (1);
		}
	}

	return (0);
}


/*
 * Choose middle 64 bits of the common key to use as our des key, possibly
 * overwriting the lower order bits by setting parity.
 *
 * (copied/moved) from keyserv's setkey.c for the DH extensions.
 */
int
__extractdeskey(ck, deskey)
	MINT *ck;
	des_block *deskey;
{
	MINT *a;
	short r;
	int i;
	short base = (1 << 8);
	char *k;

	a = mp_itom(0);
	_mp_move(ck, a);
	for (i = 0; i < ((KEYSIZE - 64) / 2) / 8; i++) {
		mp_sdiv(a, base, a, &r);
	}
	k = deskey->c;
	for (i = 0; i < 8; i++) {
		mp_sdiv(a, base, a, &r);
		*k++ = r;
	}
	mp_mfree(a);
	des_setparity((char *)deskey);
	return (0);
}


/*
 * Set the modulus for all our 192bit (algtype=0) Diffie-Hellman operations
 */
static void
setmodulus_192_0(void)
{
	(void) mutex_lock(&mod_192_0_lck);
	if (first_time) {
		first_time = FALSE;
		MODULUS_192_0 = mp_xtom(HEXMODULUS);
	}
	(void) mutex_unlock(&mod_192_0_lck);
}

/*
 * Generic key size Diffie-Hellman common key generation routine.
 * For classic AUTH_DES, do it inline like it's already done in several
 * places (keyserv being one place).  For new long key sizes,
 * call the appro GSS mech backend routine.
 *
 * Arg 'keynum' is the size of the 'deskeys' array.  It should be a 1
 * classic AUTH_DES and a 3 for new long DH keys.
 *
 * Returns 1 on success and 0 on err.
 */
int
__gen_common_dhkeys_g(char *xpublic,	/* in  */
		char *xsecret,		/* in  */
		keylen_t keylen,	/* in  */
		algtype_t algtype,	/* in  */
		des_block deskeys[],	/* out */
		keynum_t keynum)	/* in  */
{
	const int classic_des = keylen == 192 && algtype == 0;

	if (! xpublic || ! xsecret || ! deskeys)
		return (0);

	if (classic_des) {
		MINT *common;
		MINT *public;
		MINT *secret;

		setmodulus_192_0();

		public = mp_xtom(xpublic);
		secret = mp_xtom(xsecret);
		common = mp_itom(0);
		mp_pow(public, secret, MODULUS_192_0, common);
		(void) __extractdeskey(common, &deskeys[0]);
		return (1);
	} else {
		int (*dlfp)(); /* func ptr to dynamically loaded lib */

		if (dlfp = (int (*)())__nis_get_mechanism_symbol(keylen,
						algtype,
						dl_gen_common_funcname)) {
			/* function called will have void return value */
			(*dlfp)(xpublic, xsecret, deskeys, keynum);
			return (1);
		}
	}

	return (0);
}
