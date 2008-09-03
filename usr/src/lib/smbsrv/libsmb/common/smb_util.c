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

#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/varargs.h>
#include <sys/types.h>
#include <smbsrv/string.h>
#include <smbsrv/libsmb.h>

#define	C2H(c)		"0123456789ABCDEF"[(c)]
#define	H2C(c)    (((c) >= '0' && (c) <= '9') ? ((c) - '0') :     \
	((c) >= 'a' && (c) <= 'f') ? ((c) - 'a' + 10) :         \
	((c) >= 'A' && (c) <= 'F') ? ((c) - 'A' + 10) :         \
	'\0')
#define	DEFAULT_SBOX_SIZE		256

/*
 *
 * hexdump
 *
 * Simple hex dump display function. Displays nbytes of buffer in hex and
 * printable format. Non-printing characters are shown as '.'. It is safe
 * to pass a null pointer. Each line begins with the offset. If nbytes is
 * 0, the line will be blank except for the offset. Example output:
 *
 * 00000000  54 68 69 73 20 69 73 20 61 20 70 72 6F 67 72 61  This is a progra
 * 00000010  6D 20 74 65 73 74 2E 00                          m test..
 *
 */
void
hexdump_offset(unsigned char *buffer, int nbytes, unsigned long *start)
{
	static char *hex = "0123456789ABCDEF";
	int i, count;
	int offset;
	unsigned char *p;
	char ascbuf[64];
	char hexbuf[64];
	char *ap = ascbuf;
	char *hp = hexbuf;

	if ((p = buffer) == NULL)
		return;

	offset = *start;

	*ap = '\0';
	*hp = '\0';
	count = 0;

	for (i = 0; i < nbytes; ++i) {
		if (i && (i % 16) == 0) {
			smb_tracef("%06X %s  %s", offset, hexbuf, ascbuf);
			ap = ascbuf;
			hp = hexbuf;
			count = 0;
			offset += 16;
		}

		ap += sprintf(ap, "%c",
		    (*p >= 0x20 && *p < 0x7F) ? *p : '.');
		hp += sprintf(hp, " %c%c",
		    hex[(*p >> 4) & 0x0F], hex[(*p & 0x0F)]);
		++p;
		++count;
	}

	if (count) {
		smb_tracef("%06X %-48s  %s", offset, hexbuf, ascbuf);
		offset += count;
	}

	*start = offset;
}

void
hexdump(unsigned char *buffer, int nbytes)
{
	unsigned long start = 0;

	hexdump_offset(buffer, nbytes, &start);
}

/*
 * bintohex
 *
 * Converts the given binary data (srcbuf) to
 * its equivalent hex chars (hexbuf).
 *
 * hexlen should be at least twice as srclen.
 * if hexbuf is not big enough returns 0.
 * otherwise returns number of valid chars in
 * hexbuf which is srclen * 2.
 */
size_t
bintohex(const char *srcbuf, size_t srclen,
    char *hexbuf, size_t hexlen)
{
	size_t outlen;
	char c;

	outlen = srclen << 1;

	if (hexlen < outlen)
		return (0);

	while (srclen-- > 0) {
		c = *srcbuf++;
		*hexbuf++ = C2H(c & 0xF);
		*hexbuf++ = C2H((c >> 4) & 0xF);
	}

	return (outlen);
}

/*
 * hextobin
 *
 * Converts hex to binary.
 *
 * Assuming hexbuf only contains hex digits (chars)
 * this function convert every two bytes of hexbuf
 * to one byte and put it in dstbuf.
 *
 * hexlen should be an even number.
 * dstlen should be at least half of hexlen.
 *
 * Returns 0 if sizes are not correct, otherwise
 * returns the number of converted bytes in dstbuf
 * which is half of hexlen.
 */
size_t
hextobin(const char *hexbuf, size_t hexlen,
    char *dstbuf, size_t dstlen)
{
	size_t outlen;

	if ((hexlen % 2) != 0)
		return (0);

	outlen = hexlen >> 1;
	if (dstlen < outlen)
		return (0);

	while (hexlen > 0) {
		*dstbuf = H2C(*hexbuf) & 0x0F;
		hexbuf++;
		*dstbuf++ |= (H2C(*hexbuf) << 4) & 0xF0;
		hexbuf++;

		hexlen -= 2;
	}

	return (outlen);
}

/*
 * trim_whitespace
 *
 * Trim leading and trailing whitespace chars (as defined by isspace)
 * from a buffer. Example; if the input buffer contained "  text  ",
 * it will contain "text", when we return. We assume that the buffer
 * contains a null terminated string. A pointer to the buffer is
 * returned.
 */
char *
trim_whitespace(char *buf)
{
	char *p = buf;
	char *q = buf;

	if (buf == NULL)
		return (NULL);

	while (*p && isspace(*p))
		++p;

	while ((*q = *p++) != 0)
		++q;

	if (q != buf) {
		while ((--q, isspace(*q)) != 0)
			*q = '\0';
	}

	return (buf);
}

/*
 * randomize
 *
 * Randomize the contents of the specified buffer.
 */
void
randomize(char *data, unsigned len)
{
	unsigned dwlen = len / 4;
	unsigned remlen = len % 4;
	unsigned tmp;
	unsigned i; /*LINTED E_BAD_PTR_CAST_ALIGN*/
	unsigned *p = (unsigned *)data;

	for (i = 0; i < dwlen; ++i)
		*p++ = random();

	if (remlen) {
		tmp = random();
		(void) memcpy(p, &tmp, remlen);
	}
}

/*
 * This is the hash mechanism used to encrypt passwords for commands like
 * SamrSetUserInformation. It uses a 256 byte s-box.
 */
void
rand_hash(
    unsigned char *data,
    size_t datalen,
    unsigned char *key,
    size_t keylen)
{
	unsigned char sbox[DEFAULT_SBOX_SIZE];
	unsigned char tmp;
	unsigned char index_i = 0;
	unsigned char index_j = 0;
	unsigned char j = 0;
	int i;

	for (i = 0; i < DEFAULT_SBOX_SIZE; ++i)
		sbox[i] = (unsigned char)i;

	for (i = 0; i < DEFAULT_SBOX_SIZE; ++i) {
		j += (sbox[i] + key[i % keylen]);

		tmp = sbox[i];
		sbox[i] = sbox[j];
		sbox[j] = tmp;
	}

	for (i = 0; i < datalen; ++i) {
		index_i++;
		index_j += sbox[index_i];

		tmp = sbox[index_i];
		sbox[index_i] = sbox[index_j];
		sbox[index_j] = tmp;

		tmp = sbox[index_i] + sbox[index_j];
		data[i] = data[i] ^ sbox[tmp];
	}
}
