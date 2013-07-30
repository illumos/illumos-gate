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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

/*
 * Hex encryption/decryption and utility routines
 */

#include "mt.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <rpc/rpc.h>
#include <rpc/key_prot.h>   /* for KEYCHECKSUMSIZE */
#include <rpc/des_crypt.h>
#include <string.h>
#include <rpcsvc/nis_dhext.h>
#include <md5.h>

#define	MD5HEXSIZE	32

extern int bin2hex(int len, unsigned char *binnum, char *hexnum);
extern int hex2bin(int len, char *hexnum, char *binnum);
static char hex[];	/* forward */
static char hexval();

int passwd2des(char *, char *);
static int weak_DES_key(des_block);

/*
 * For export control reasons, we want to limit the maximum size of
 * data that can be encrypted or decrypted.  We limit this to 1024
 * bits of key data, which amounts to 128 bytes.
 *
 * For the extended DH project, we have increased it to
 * 144 bytes (128key + 16checksum) to accomadate all the 128 bytes
 * being used by the new 1024bit keys plus 16 bytes MD5 checksum.
 * We discussed this with Sun's export control office and lawyers
 * and we have reason to believe this is ok for export.
 */
#define	MAX_KEY_CRYPT_LEN	144

/*
 * Encrypt a secret key given passwd
 * The secret key is passed and returned in hex notation.
 * Its length must be a multiple of 16 hex digits (64 bits).
 */
int
xencrypt(secret, passwd)
	char *secret;
	char *passwd;
{
	char key[8];
	char ivec[8];
	char *buf;
	int err;
	int len;

	len = (int)strlen(secret) / 2;
	if (len > MAX_KEY_CRYPT_LEN)
		return (0);
	buf = malloc((unsigned)len);
	(void) hex2bin(len, secret, buf);
	(void) passwd2des(passwd, key);
	(void) memset(ivec, 0, 8);

	err = cbc_crypt(key, buf, len, DES_ENCRYPT | DES_HW, ivec);
	if (DES_FAILED(err)) {
		free(buf);
		return (0);
	}
	(void) bin2hex(len, (unsigned char *) buf, secret);
	free(buf);
	return (1);
}

/*
 * Decrypt secret key using passwd
 * The secret key is passed and returned in hex notation.
 * Once again, the length is a multiple of 16 hex digits
 */
int
xdecrypt(secret, passwd)
	char *secret;
	char *passwd;
{
	char key[8];
	char ivec[8];
	char *buf;
	int err;
	int len;

	len = (int)strlen(secret) / 2;
	if (len > MAX_KEY_CRYPT_LEN)
		return (0);
	buf = malloc((unsigned)len);

	(void) hex2bin(len, secret, buf);
	(void) passwd2des(passwd, key);
	(void) memset(ivec, 0, 8);

	err = cbc_crypt(key, buf, len, DES_DECRYPT | DES_HW, ivec);
	if (DES_FAILED(err)) {
		free(buf);
		return (0);
	}
	(void) bin2hex(len, (unsigned char *) buf, secret);
	free(buf);
	return (1);
}

/*
 * Turn password into DES key
 */
int
passwd2des(pw, key)
	char *pw;
	char *key;
{
	int i;

	(void) memset(key, 0, 8);
	for (i = 0; *pw; i = (i+1) % 8) {
		key[i] ^= *pw++ << 1;
	}
	des_setparity(key);
	return (1);
}


/*
 * Hex to binary conversion
 */
int
hex2bin(len, hexnum, binnum)
	int len;
	char *hexnum;
	char *binnum;
{
	int i;

	for (i = 0; i < len; i++) {
		*binnum++ = 16 * hexval(hexnum[2 * i]) +
					hexval(hexnum[2 * i + 1]);
	}
	return (1);
}

/*
 * Binary to hex conversion
 */
int
bin2hex(len, binnum, hexnum)
	int len;
	unsigned char *binnum;
	char *hexnum;
{
	int i;
	unsigned val;

	for (i = 0; i < len; i++) {
		val = binnum[i];
		hexnum[i*2] = hex[val >> 4];
		hexnum[i*2+1] = hex[val & 0xf];
	}
	hexnum[len*2] = 0;
	return (1);
}

static char hex[16] = {
	'0', '1', '2', '3', '4', '5', '6', '7',
	'8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
};

static char
hexval(c)
	char c;
{
	if (c >= '0' && c <= '9') {
		return (c - '0');
	} else if (c >= 'a' && c <= 'z') {
		return (c - 'a' + 10);
	} else if (c >= 'A' && c <= 'Z') {
		return (c - 'A' + 10);
	} else {
		return (-1);
	}
}

/*
 * Generic key length/algorithm version of xencrypt().
 *
 * Encrypt a secret key given passwd.
 * The secret key is passed in hex notation.
 * Arg encrypted_secret will be set to point to the encrypted
 * secret key (NUL term, hex notation).
 *
 * Its length must be a multiple of 16 hex digits (64 bits).
 *
 * For 192-0 (AUTH_DES), then encrypt using the same method as xencrypt().
 *
 * If arg do_chksum is TRUE, append the checksum before the encrypt.
 * For 192-0, the checksum is done the same as in xencrypt().  For
 * bigger keys, MD5 is used.
 *
 * Arg netname can be NULL for 192-0.
 */
int
xencrypt_g(
	char *secret,			/* in  */
	keylen_t keylen,		/* in  */
	algtype_t algtype,		/* in  */
	const char *passwd,		/* in  */
	const char netname[],  		/* in  */
	char **encrypted_secret,	/* out */
	bool_t do_chksum)		/* in  */
{
	des_block key;
	char ivec[8];
	char *binkeybuf;
	int err;
	const int classic_des = keylen == 192 && algtype == 0;
	const int hexkeybytes = BITS2NIBBLES(keylen);
	const int keychecksumsize = classic_des ? KEYCHECKSUMSIZE : MD5HEXSIZE;
	const int binkeybytes = do_chksum ? keylen/8 + keychecksumsize/2 :
		keylen/8;
	const int bufsize = do_chksum ? hexkeybytes + keychecksumsize + 1 :
		hexkeybytes + 1;
	char *hexkeybuf;

	if (!secret || !keylen || !passwd || !encrypted_secret)
		return (0);

	if ((hexkeybuf = malloc(bufsize)) == 0)
		return (0);

	(void) memcpy(hexkeybuf, secret, hexkeybytes);
	if (do_chksum)
		if (classic_des) {
			(void) memcpy(hexkeybuf + hexkeybytes, secret,
					keychecksumsize);
		} else {
			MD5_CTX md5_ctx;
			char md5hexbuf[MD5HEXSIZE + 1] = {0};
			uint8_t digest[MD5HEXSIZE/2];

			MD5Init(&md5_ctx);
			MD5Update(&md5_ctx, (unsigned char *)hexkeybuf,
					hexkeybytes);
			MD5Final(digest, &md5_ctx);

			/* convert md5 binary digest to hex */
			(void) bin2hex(MD5HEXSIZE/2, digest, md5hexbuf);

			/* append the hex md5 string to the end of the key */
			(void) memcpy(hexkeybuf + hexkeybytes,
					(void *)md5hexbuf, MD5HEXSIZE);
		}
	hexkeybuf[bufsize - 1] = 0;

	if (binkeybytes > MAX_KEY_CRYPT_LEN) {
		free(hexkeybuf);
		return (0);
	}
	if ((binkeybuf = malloc((unsigned)binkeybytes)) == 0) {
		free(hexkeybuf);
		return (0);
	}

	(void) hex2bin(binkeybytes, hexkeybuf, binkeybuf);
	if (classic_des)
		(void) passwd2des((char *)passwd, key.c);
	else
		if (netname)
			(void) passwd2des_g(passwd, netname,
					(int)strlen(netname), &key, FALSE);
		else {
			free(hexkeybuf);
			return (0);
		}

	(void) memset(ivec, 0, 8);

	err = cbc_crypt(key.c, binkeybuf, binkeybytes, DES_ENCRYPT | DES_HW,
			ivec);
	if (DES_FAILED(err)) {
		free(hexkeybuf);
		free(binkeybuf);
		return (0);
	}
	(void) bin2hex(binkeybytes, (unsigned char *) binkeybuf, hexkeybuf);
	free(binkeybuf);
	*encrypted_secret = hexkeybuf;
	return (1);
}

/*
 * Generic key len and alg type for version of xdecrypt.
 *
 * Decrypt secret key using passwd.  The decrypted secret key
 * *overwrites* the supplied encrypted secret key.
 * The secret key is passed and returned in hex notation.
 * Once again, the length is a multiple of 16 hex digits.
 *
 * If 'do_chksum' is TRUE, the 'secret' buffer is assumed to contain
 * a checksum calculated by a call to xencrypt_g().
 *
 * If keylen is 192 and algtype is 0, then decrypt the same way
 * as xdecrypt().
 *
 * Arg netname can be NULL for 192-0.
 */
int
xdecrypt_g(
	char *secret,		/* out  */
	int keylen,		/* in  */
	int algtype,		/* in  */
	const char *passwd,	/* in  */
	const char netname[],	/* in  */
	bool_t do_chksum)	/* in  */
{
	des_block key;
	char ivec[8];
	char *buf;
	int err;
	int len;
	const int classic_des = keylen == 192 && algtype == 0;
	const int hexkeybytes = BITS2NIBBLES(keylen);
	const int keychecksumsize = classic_des ? KEYCHECKSUMSIZE : MD5HEXSIZE;

	len = (int)strlen(secret) / 2;
	if (len > MAX_KEY_CRYPT_LEN)
		return (0);
	if ((buf = malloc((unsigned)len)) == 0)
		return (0);

	(void) hex2bin(len, secret, buf);
	if (classic_des)
		(void) passwd2des((char *)passwd, key.c);
	else
		if (netname)
			(void) passwd2des_g(passwd, netname,
					(int)strlen(netname), &key, FALSE);
		else {
			free(buf);
			return (0);
		}
	(void) memset(ivec, 0, 8);

	err = cbc_crypt(key.c, buf, len, DES_DECRYPT | DES_HW, ivec);
	if (DES_FAILED(err)) {
		free(buf);
		return (0);
	}
	(void) bin2hex(len, (unsigned char *) buf, secret);
	free(buf);

	if (do_chksum)
		if (classic_des) {
			if (memcmp(secret, &(secret[hexkeybytes]),
					keychecksumsize) != 0) {
				secret[0] = 0;
				return (0);
			}
		} else {
			MD5_CTX md5_ctx;
			char md5hexbuf[MD5HEXSIZE + 1] = {0};
			uint8_t digest[MD5HEXSIZE/2];

			MD5Init(&md5_ctx);
			MD5Update(&md5_ctx, (unsigned char *)secret,
					hexkeybytes);
			MD5Final(digest, &md5_ctx);

			/* convert md5 binary digest to hex */
			(void) bin2hex(MD5HEXSIZE/2, digest, md5hexbuf);

			/* does the digest match the appended one? */
			if (memcmp(&(secret[hexkeybytes]),
					md5hexbuf, MD5HEXSIZE) != 0) {
				secret[0] = 0;
				return (0);
			}
		}

	secret[hexkeybytes] = '\0';

	return (1);
}


/*
 * Modified version of passwd2des(). passwd2des_g() uses the Kerberos
 * RFC 1510 algorithm to generate a DES key from a user password
 * and mix-in string. The mix-in is expected to be the netname.
 * This function to be used only for extended Diffie-Hellman keys.
 *
 * If altarg is TRUE, reverse the concat of passwd and mix-in.
 */
int
passwd2des_g(
	const char *pw,
	const char *mixin,
	int len,
	des_block *key, /* out */
	bool_t altalg)
{

	int  i, j, incr = 1;
	des_block ivec, tkey;
	char *text;
	int  plen, tlen;

	(void) memset(tkey.c, 0, 8);
	(void) memset(ivec.c, 0, 8);


/*
 * Concatentate the password and the mix-in string, fan-fold and XOR them
 * to the required eight byte initial DES key. Since passwords can be
 * expected to use mostly seven bit ASCII, left shift the password one
 * bit in order to preserve as much key space as possible.
 */

#define	KEYLEN sizeof (tkey.c)
	plen = strlen(pw);
	tlen = ((plen + len + (KEYLEN-1))/KEYLEN)*KEYLEN;
	if ((text = malloc(tlen)) == NULL) {
		return (0);
	}

	(void) memset(text, 0, tlen);

	if (!altalg) {

/*
 * Concatenate the password and the mix-in string, fan-fold and XOR them
 * to the required eight byte initial DES key. Since passwords can be
 * expected to use mostly seven bit ASCII, left shift the password one
 * bit in order to preserve as much key space as possible.
 */
		(void) memcpy(text, pw, plen);
		(void) memcpy(&text[plen], mixin, len);

		for (i = 0, j = 0; pw[j]; j++) {
			tkey.c[i] ^= pw[j] << 1;
			i += incr;
			if (i == 8) {
				i = 7;
				incr = -incr;
			} else if (i == -1) {
				i = 0;
				incr = -incr;
			}
		}

		for (j = 0; j < len; j++) {
			tkey.c[i] ^= mixin[j];
			i += incr;
			if (i == 8) {
				i = 7;
				incr = -incr;
			} else if (i == -1) {
				i = 0;
				incr = -incr;
			}
		}
	} else {  /* use alternative algorithm */
		(void) memcpy(text, mixin, len);
		(void) memcpy(&text[len], pw, plen);

		for (i = 0, j = 0; j < len; j++) {
			tkey.c[i] ^= mixin[j];
			i += incr;
			if (i == 8) {
				i = 7;
				incr = -incr;
			} else if (i == -1) {
				i = 0;
				incr = -incr;
			}
		}

		for (j = 0; pw[j]; j++) {
			tkey.c[i] ^= pw[j] << 1;
			i += incr;
			if (i == 8) {
				i = 7;
				incr = -incr;
			} else if (i == -1) {
				i = 0;
				incr = -incr;
			}
		}
	}
	des_setparity_g(&tkey);

	/*
	 * Use the temporary key to produce a DES CBC checksum for the text
	 * string; cbc_crypt returns the checksum in the ivec.
	 */
	(void) cbc_crypt(tkey.c, text, tlen, DES_ENCRYPT|DES_HW, ivec.c);
	des_setparity_g(&ivec);
	free(text);

	if (weak_DES_key(ivec)) {
		ivec.c[7] ^= 0xf0;
		/*
		 *  XORing with 0xf0 preserves parity, so no need to check
		 *  that again.
		 */
	}

	(void) memcpy((*key).c, ivec.c, sizeof (ivec.c));

	return (1);

}

struct DESkey {
	uint32_t h1;
	uint32_t h2;
};

/*
 * Weak and semiweak keys from "Applied Cryptography", second edition,
 * by Bruce Schneier, Wiley 1996.
 */
static struct DESkey weakDESkeys[] = {
	/* Weak keys */
	{0x01010101, 0x01010101},
	{0x1f1f1f1f, 0x1f1f1f1f},
	{0xe0e0e0e0, 0xe0e0e0e0},
	{0xfefefefe, 0xfefefefe},
	/* Semiweak keys */
	{0x01fe01fe, 0x01fe01fe},
	{0x1fe01fe0, 0x0ef10ef1},
	{0x01e001e0, 0x01f101f1},
	{0x1ffe1ffe, 0x0efe0efe},
	{0x011f011f, 0x010e010e},
	{0xe0fee0fe, 0xf1fef1fe},
	{0xfe01fe01, 0xfe01fe01},
	{0xe01fe01f, 0xf10ef10e},
	{0xe001e001, 0xf101f101},
	{0xfe1ffe1f, 0xfe0efe0e},
	{0x1f011f01, 0x0e010e01},
	{0xfee0fee0, 0xfef1fef1}
};

static int
weak_DES_key(des_block db)
{
	int i;

	for (i = 0; i < sizeof (weakDESkeys)/sizeof (struct DESkey); i++) {
		if (weakDESkeys[i].h1 == db.key.high &&
			weakDESkeys[i].h2 == db.key.low)
			return (1);
	}

	return (0);
}
