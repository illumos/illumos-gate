/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2003-2004, Jouni Malinen <jkmaline@cc.hut.fi>
 * Sun elects to license this software under the BSD license.
 * See README for more details.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>

#include <openssl/aes.h>
#include <openssl/hmac.h>
#include <openssl/rc4.h>

#include "wpa_enc.h"

/*
 * @kek: key encryption key (KEK)
 * @n: length of the wrapped key in 64-bit units; e.g., 2 = 128-bit = 16 bytes
 * @plain: plaintext key to be wrapped, n * 64 bit
 * @cipher: wrapped key, (n + 1) * 64 bit
 */
void
aes_wrap(uint8_t *kek, int n, uint8_t *plain, uint8_t *cipher)
{
	uint8_t *a, *r, b[16];
	int i, j;
	AES_KEY key;

	a = cipher;
	r = cipher + 8;

	/* 1) Initialize variables. */
	(void) memset(a, 0xa6, 8);
	(void) memcpy(r, plain, 8 * n);

	(void) AES_set_encrypt_key(kek, 128, &key);

	/*
	 * 2) Calculate intermediate values.
	 * For j = 0 to 5
	 * 	For i=1 to n
	 * 		B = AES(K, A | R[i])
	 * 		A = MSB(64, B) ^ t where t = (n*j)+i
	 * 		R[i] = LSB(64, B)
	 */
	for (j = 0; j <= 5; j++) {
		r = cipher + 8;
		for (i = 1; i <= n; i++) {
			(void) memcpy(b, a, 8);
			(void) memcpy(b + 8, r, 8);
			AES_encrypt(b, b, &key);
			(void) memcpy(a, b, 8);
			a[7] ^= n * j + i;
			(void) memcpy(r, b + 8, 8);
			r += 8;
		}
	}

	/*
	 * 3) Output the results.
	 *
	 * These are already in @cipher due to the location of temporary
	 * variables.
	 */
}

/*
 * @kek: key encryption key (KEK)
 * @n: length of the wrapped key in 64-bit units; e.g., 2 = 128-bit = 16 bytes
 * @cipher: wrapped key to be unwrapped, (n + 1) * 64 bit
 * @plain: plaintext key, n * 64 bit
 */
int
aes_unwrap(uint8_t *kek, int n, uint8_t *cipher, uint8_t *plain)
{
	uint8_t a[8], *r, b[16];
	int i, j;
	AES_KEY key;

	/* 1) Initialize variables. */
	(void) memcpy(a, cipher, 8);
	r = plain;
	(void) memcpy(r, cipher + 8, 8 * n);

	(void) AES_set_decrypt_key(kek, 128, &key);

	/*
	 * 2) Compute intermediate values.
	 * For j = 5 to 0
	 * 	For i = n to 1
	 * 		B = AES-1(K, (A ^ t) | R[i]) where t = n*j+i
	 * 		A = MSB(64, B)
	 * 		R[i] = LSB(64, B)
	 */
	for (j = 5; j >= 0; j--) {
		r = plain + (n - 1) * 8;
		for (i = n; i >= 1; i--) {
			(void) memcpy(b, a, 8);
			b[7] ^= n * j + i;

			(void) memcpy(b + 8, r, 8);
			AES_decrypt(b, b, &key);
			(void) memcpy(a, b, 8);
			(void) memcpy(r, b + 8, 8);
			r -= 8;
		}
	}

	/*
	 * 3) Output results.
	 *
	 * These are already in @plain due to the location of temporary
	 * variables. Just verify that the IV matches with the expected value.
	 */
	for (i = 0; i < 8; i++) {
		if (a[i] != 0xa6) {
			return (-1);
		}
	}

	return (0);
}

/* RFC 2104 */
void
hmac_sha1(unsigned char *key, unsigned int key_len,
    unsigned char *data, unsigned int data_len, unsigned char *mac)
{
	unsigned int mac_len = 0;
	(void) HMAC(EVP_sha1(), key, key_len, data, data_len, mac, &mac_len);
}


void
hmac_sha1_vector(unsigned char *key, unsigned int key_len, size_t num_elem,
    unsigned char *addr[], unsigned int *len, unsigned char *mac)
{
	unsigned char *buf, *ptr;
	int i, buf_len;

	buf_len = 0;
	for (i = 0; i < num_elem; i ++)
		buf_len += len[i];

	buf = malloc(buf_len);
	ptr = buf;

	for (i = 0; i < num_elem; i ++) {
		(void) memcpy(ptr, addr[i], len[i]);
		ptr += len[i];
	}

	hmac_sha1(key, key_len, buf, buf_len, mac);

	free(buf);
}


void
sha1_prf(unsigned char *key, unsigned int key_len,
    char *label, unsigned char *data, unsigned int data_len,
    unsigned char *buf, size_t buf_len)
{
	uint8_t zero = 0, counter = 0;
	size_t pos, plen;
	uint8_t hash[SHA1_MAC_LEN];
	size_t label_len = strlen(label);

	unsigned char *addr[4];
	unsigned int len[4];

	addr[0] = (uint8_t *)label;
	len[0] = label_len;
	addr[1] = &zero;
	len[1] = 1;
	addr[2] = data;
	len[2] = data_len;
	addr[3] = &counter;
	len[3] = 1;

	pos = 0;
	while (pos < buf_len) {
		plen = buf_len - pos;
		if (plen >= SHA1_MAC_LEN) {
			hmac_sha1_vector(key, key_len, 4, addr, len, &buf[pos]);
			pos += SHA1_MAC_LEN;
		} else {
			hmac_sha1_vector(key, key_len, 4, addr, len, hash);
			(void) memcpy(&buf[pos], hash, plen);
			break;
		}
		counter++;
	}
}

void
pbkdf2_sha1(char *passphrase, char *ssid, size_t ssid_len, int iterations,
    unsigned char *buf, size_t buflen)
{
	(void) PKCS5_PBKDF2_HMAC_SHA1(passphrase, -1, (unsigned char *)ssid,
	    ssid_len, iterations, buflen, buf);
}

void
rc4_skip(uint8_t *key, size_t keylen, size_t skip,
    uint8_t *data, size_t data_len)
{
	uint8_t *buf;
	size_t buf_len;

	buf_len = skip + data_len;
	buf = malloc(buf_len);

	bzero(buf, buf_len);
	bcopy(data, buf + skip, data_len);

	rc4(buf, buf_len, key, keylen);

	bcopy(buf + skip, data, data_len);
	free(buf);
}

void
rc4(uint8_t *buf, size_t len, uint8_t *key, size_t key_len)
{
	RC4_KEY k;

	RC4_set_key(&k, key_len, key);
	RC4(&k, len, buf, buf);
}

void
hmac_md5_vector(uint8_t *key, size_t key_len, size_t num_elem,
    uint8_t *addr[], size_t *len, uint8_t *mac)
{
	unsigned char *buf, *ptr;
	int i, buf_len;

	buf_len = 0;
	for (i = 0; i < num_elem; i ++)
		buf_len += len[i];

	buf = malloc(buf_len);
	ptr = buf;

	for (i = 0; i < num_elem; i ++) {
		(void) memcpy(ptr, addr[i], len[i]);
		ptr += len[i];
	}

	hmac_md5(key, key_len, buf, buf_len, mac);
	free(buf);
}

/* RFC 2104 */
void
hmac_md5(uint8_t *key, size_t key_len, uint8_t *data,
    size_t data_len, uint8_t *mac)
{
	unsigned int mac_len = 0;
	(void) HMAC(EVP_md5(), key, key_len, data, data_len, mac, &mac_len);
}
