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
 * Copyright 1997 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *	generic_key.c
 */

#include <mp.h>
#include <time.h>
#include <rpc/rpc.h>
#include <stdlib.h>

#define	BASEBITS		(8 * sizeof (char))
#define	BASE			(1 << BASEBITS)

extern void des_setparity(char *);
extern void des_setparity_g(des_block *);

/*
 * seed the random generator. Here we use the time of day and a supplied
 * password for generating the seed.
 */
static void
setseed(unsigned char *pass)
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
}

/*
 * Adjust the input key so that it is 0-filled on the left and store
 * the results in key out.
 */
static void
adjust(char *keyout, char *keyin, int keylen)
{
	char *p;
	char *s;
	int hexkeybytes = (keylen+3)/4;

	for (p = keyin; *p; p++);
	for (s = keyout + hexkeybytes; p >= keyin; p--, s--) {
		*s = *p;
	}
	while (s >= keyout) {
		*s-- = '0';
	}
}

/*
 * __generic_gen_dhkeys: Classic Diffie-Hellman key pair generation.
 * Generate a Diffie-Hellman key pair of a given key length using
 * the supplied modulus and root. To calculate the pair we generate
 * a random key of the appropriate key length modulo the modulus.
 * This random key is the private key of the key pair. We now compute
 * the public key as PublicKey = root^PrivateKey % modulus. This routine
 * make use of libmp to do the multiprecision interger arithmetic.
 */
void
__generic_gen_dhkeys(int keylen, /* Size of keys in bits */
		    char *xmodulus, /* The modulus */
		    int proot, /* The prime root */
		    char *public, /* Public key */
		    char *secret, /* Private key */
		    char *pass    /* password to seed with for private key */)
{
	int i, len;
	MINT *pk = mp_itom(0);	/* Initial public key */
	MINT *sk = mp_itom(0);	/* Initial private key */
	MINT *tmp;
	MINT *base = mp_itom(BASE); 	/* We shift by BASEBITS */
	MINT *root = mp_itom(proot);    /* We get the root as a MINT */
	/* Convert the modulus from a hex string to a MINT */
	MINT *modulus = mp_xtom(xmodulus);
	unsigned char seed;
	char *xkey;

	/* Seed the random generate */
	setseed((u_char *)pass);

	/*
	 * We will break up the private key into  groups of BASEBITS where
	 * BASEBITS is equal to the number of bits in an integer type.
	 * Curently, basebits is 8 so the integral type is a character.
	 * We will calculate the number of BASEBITS units that we need so
	 * that we have at least keylen bits.
	 */
	len = ((keylen + BASEBITS - 1) / BASEBITS);

	/*
	 * Now for each BASEBITS we calculate a new random number.
	 * Shift the private key by base bits and then add the
	 * generated random number.
	 */
	for (i = 0; i < len; i++) {
		/* get a random number */
		seed = random() ^ pass[i % 8];
		/* Convert it to a MINT */
		tmp = mp_itom(seed);
		/* Shift the private key */
		mp_mult(sk, base, sk);
		/* Add in the new low order bits */
		mp_madd(sk, tmp, sk);
		/* Free tmp */
		mp_mfree(tmp);
	}

	/* Set timp to 0 */
	tmp = mp_itom(0);
	/* We get the private keys as private key modulo the modulus */
	mp_mdiv(sk, modulus, tmp, sk);
	/* Done with tmp */
	mp_mfree(tmp);
	/* The public key is root^sk % modulus */
	mp_pow(root, sk, modulus, pk);
	/* Convert the private key to a hex string */
	xkey = mp_mtox(sk);
	/* Set leading zeros if necessary and store in secret */
	(void) adjust(secret, xkey, keylen);
	/* Done with xkey */
	free(xkey);
	/* Now set xkey to the hex representation of the public key */
	xkey = mp_mtox(pk);
	/* Set leading zeros and store in public */
	(void) adjust(public, xkey, keylen);

	/* Free storage */
	free(xkey);

	mp_mfree(sk);
	mp_mfree(base);
	mp_mfree(pk);
	mp_mfree(root);
	mp_mfree(modulus);
}

/*
 * Given a key extract keynum des keys
 */
static void
extractdeskeys(MINT *ck, int keylen, des_block keys[], int keynum)
{
	MINT *a;
	short r;
	int i;
	short base = (1 << 8);
	char *k;
	/* len is the total number of bits we need for keynum des keys */
	int len = 8 * sizeof (des_block) * keynum;
	extern void _mp_move(MINT *, MINT *);

	/* Create a MINT a to hold the common key */
	a = mp_itom(0);
	_mp_move(ck, a);


	/*
	 * Calculate the middle byte in the key. We will simply extract
	 * the middle bits of the key for the bits in our DES keys.
	 */
	for (i = 0; i < ((keylen - len)/2)/8; i++)
		mp_sdiv(a, base, a, &r); /* Shift the key by one byte */

	/*
	 * Now take our middle bits referenced by a and shove them
	 * into the array of DES keys.
	 */
	k = (char *)keys;
	for (i = 0; i < sizeof (des_block) * keynum; i++) {
		mp_sdiv(a, base, a, &r);
		*k++ = r;
	}

	/* We're done with a */
	mp_mfree(a);

	/* Set the DES parity for each key */
	for (i = 0; i < keynum; i++)
		if (keylen == 192) /* Old broken way for compatibility */
			des_setparity((char *)&keys[i]);
		else
			des_setparity_g(&keys[i]);
}


/*
 * __generic_common_dhkeys: Generate a set of DES keys based on
 * the Diffie-Hellman common key derived from the supplied key pair
 * of the given key length using the passed in modulus. The common key
 *  is calculated as:
 *
 *	ck = pk ^ sk % modulus
 *
 * We will use the above routine to extract a set of DES keys for the
 * caller.
 */
void
__generic_common_dhkeys(char *pkey, /* Public key of remote */
			char *skey, /* Our private key */
			int keylen, /* All the keys have this many bits */
			char *xmodulus, /* The modulus */
			des_block keys[], /* DES keys to fill */
			int keynum /* The number of DES keys to create */)
{
	/* Convert hex string representations to MINTS */
	MINT *pk = mp_xtom(pkey);
	MINT *sk = mp_xtom(skey);
	MINT *modulus = mp_xtom(xmodulus);
	/* Create a MINT for the common key */
	MINT *ck = mp_itom(0);

	/* ck = pk ^ sk % modulus */
	mp_pow(pk, sk, modulus, ck);

	/* Set the DES keys */
	extractdeskeys(ck, keylen, keys, keynum);

	/* Clean up */
	mp_mfree(pk);
	mp_mfree(sk);
	mp_mfree(modulus);
	mp_mfree(ck);
}
