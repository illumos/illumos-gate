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

#include <sys/types.h>
#include <nxge_fflp_hash.h>

static void nxge_crc32c_word(uint32_t *crcptr, const uint32_t *buf, int len);

/*
 * The crc32c algorithms are taken from sctp_crc32 implementation
 * common/inet/sctp_crc32.{c,h}
 *
 */

/*
 * Fast CRC32C calculation algorithm.  The basic idea is to look at it
 * four bytes (one word) at a time, using four tables.  The
 * standard algorithm in RFC 3309 uses one table.
 */

/*
 * SCTP uses reflected/reverse polynomial CRC32 with generating
 * polynomial 0x1EDC6F41L
 */
#define	SCTP_POLY 0x1EDC6F41L

/* CRC-CCITT Polynomial */
#define	CRC_CCITT_POLY 0x1021

/* The four CRC32c tables. */
static uint32_t crc32c_tab[4][256];

/* The four CRC-CCITT tables. */
static uint16_t crc_ccitt_tab[4][256];

/* the four tables for H1 Computation */
static uint32_t h1table[4][256];

#define	CRC_32C_POLY 0x1EDC6F41L

#define	COMPUTE_H1_BYTE(crc, data) \
	(crc = (crc<<8)^h1table[0][((crc >> 24) ^data) & 0xff])

static uint32_t
reflect_32(uint32_t b)
{
	int i;
	uint32_t rw = 0;

	for (i = 0; i < 32; i++) {
		if (b & 1) {
			rw |= 1 << (31 - i);
		}
		b >>= 1;
	}
	return (rw);
}

static uint32_t
flip32(uint32_t w)
{
	return (((w >> 24) | ((w >> 8) & 0xff00) |
	    ((w << 8) & 0xff0000) | (w << 24)));
}

/*
 * reference crc-ccitt implementation
 */

uint16_t
crc_ccitt(uint16_t crcin, uint8_t data)
{
	uint16_t mcrc, crc = 0, bits = 0;

	mcrc = (((crcin >> 8) ^ data) & 0xff) << 8;
	for (bits = 0; bits < 8; bits++) {
		crc = ((crc ^ mcrc) & 0x8000) ?
		    (crc << 1) ^ CRC_CCITT_POLY :
		    crc << 1;
		mcrc <<= 1;
	}
	return ((crcin << 8) ^ crc);
}

/*
 * Initialize the crc32c tables.
 */

void
nxge_crc32c_init(void)
{
	uint32_t index, bit, byte, crc;

	for (index = 0; index < 256; index++) {
		crc = reflect_32(index);
		for (byte = 0; byte < 4; byte++) {
			for (bit = 0; bit < 8; bit++) {
				crc = (crc & 0x80000000) ?
				    (crc << 1) ^ SCTP_POLY : crc << 1;
			}
#ifdef _BIG_ENDIAN
			crc32c_tab[3 - byte][index] = flip32(reflect_32(crc));
#else
			crc32c_tab[byte][index] = reflect_32(crc);
#endif
		}
	}
}

/*
 * Initialize the crc-ccitt tables.
 */

void
nxge_crc_ccitt_init(void)
{
	uint16_t crc;
	uint16_t index, bit, byte;

	for (index = 0; index < 256; index++) {
		crc = index << 8;
		for (byte = 0; byte < 4; byte++) {
			for (bit = 0; bit < 8; bit++) {
				crc = (crc & 0x8000) ?
				    (crc << 1) ^ CRC_CCITT_POLY : crc << 1;
			}
#ifdef _BIG_ENDIAN
			crc_ccitt_tab[3 - byte][index] = crc;
#else
			crc_ccitt_tab[byte][index] = crc;
#endif
		}
	}
}

/*
 * Lookup  the crc32c for a byte stream
 */

static void
nxge_crc32c_byte(uint32_t *crcptr, const uint8_t *buf, int len)
{
	uint32_t crc;
	int i;

	crc = *crcptr;
	for (i = 0; i < len; i++) {
#ifdef _BIG_ENDIAN
		crc = (crc << 8) ^ crc32c_tab[3][buf[i] ^ (crc >> 24)];
#else
		crc = (crc >> 8) ^ crc32c_tab[0][buf[i] ^ (crc & 0xff)];
#endif
	}
	*crcptr = crc;
}

/*
 * Lookup  the crc-ccitt for a byte stream
 */

static void
nxge_crc_ccitt_byte(uint16_t *crcptr, const uint8_t *buf, int len)
{
	uint16_t crc;
	int i;

	crc = *crcptr;
	for (i = 0; i < len; i++) {

#ifdef _BIG_ENDIAN
		crc = (crc << 8) ^ crc_ccitt_tab[3][buf[i] ^ (crc >> 8)];
#else
		crc = (crc << 8) ^ crc_ccitt_tab[0][buf[i] ^ (crc >> 8)];
#endif
	}
	*crcptr = crc;
}

/*
 * Lookup  the crc32c for a 32 bit word stream
 * Lookup is done fro the 4 bytes in parallel
 * from the tables computed earlier
 *
 */

static void
nxge_crc32c_word(uint32_t *crcptr, const uint32_t *buf, int len)
{
	uint32_t w, crc;
	int i;

	crc = *crcptr;
	for (i = 0; i < len; i++) {
		w = crc ^ buf[i];
		crc = crc32c_tab[0][w >> 24] ^
		    crc32c_tab[1][(w >> 16) & 0xff] ^
		    crc32c_tab[2][(w >> 8) & 0xff] ^
		    crc32c_tab[3][w & 0xff];
	}
	*crcptr = crc;
}

/*
 * Lookup  the crc-ccitt for a stream of bytes
 *
 * Since the parallel lookup version doesn't work yet,
 * use the byte stream version (lookup crc for a byte
 * at a time
 *
 */

uint16_t
nxge_crc_ccitt(uint16_t crc16, const uint8_t *buf, int len)
{
	nxge_crc_ccitt_byte(&crc16, buf, len);
	return (crc16);
}

/*
 * Lookup  the crc32c for a stream of bytes
 *
 * Tries to lookup the CRC on 4 byte words
 * If the buffer is not 4 byte aligned, first compute
 * with byte lookup until aligned. Then compute crc
 * for each 4 bytes. If there are bytes left at the end of
 * the buffer, then perform a byte lookup for the remaining bytes
 *
 *
 */

uint32_t
nxge_crc32c(uint32_t crc32, const uint8_t *buf, int len)
{
	int rem;

	rem = 4 - ((uintptr_t)buf) & 3;
	if (rem != 0) {
		if (len < rem) {
			rem = len;
		}
		nxge_crc32c_byte(&crc32, buf, rem);
		buf = buf + rem;
		len = len - rem;
	}
	if (len > 3) {
		nxge_crc32c_word(&crc32, (const uint32_t *) buf, len / 4);
	}
	rem = len & 3;
	if (rem != 0) {
		nxge_crc32c_byte(&crc32, buf + len - rem, rem);
	}
	return (crc32);
}

void
nxge_init_h1_table()
{
	uint32_t crc, bit, byte, index;

	for (index = 0; index < 256; index++) {
		crc = index << 24;
		for (byte = 0; byte < 4; byte++) {
			for (bit = 0; bit < 8; bit++) {
				crc = ((crc & 0x80000000)) ?
				    (crc << 1) ^ CRC_32C_POLY : crc << 1;
			}
			h1table[byte][index] = crc;
		}
	}
}

/*
 * Reference Neptune H1 computation function
 *
 * It is a slightly modified implementation of
 * CRC-32C implementation
 */

uint32_t
nxge_compute_h1_serial(uint32_t init_value, uint32_t *flow, uint32_t len)
{
	int bit, byte;
	uint32_t crc_h1 = init_value;
	uint8_t *buf;

	buf = (uint8_t *)flow;
	for (byte = 0; byte < len; byte++) {
		for (bit = 0; bit < 8; bit++) {
			crc_h1 = (((crc_h1 >> 24) & 0x80) ^
			    ((buf[byte] << bit) & 0x80)) ?
			    (crc_h1 << 1) ^ CRC_32C_POLY : crc_h1 << 1;
		}
	}

	return (crc_h1);
}

/*
 * table based implementation
 * uses 4 four tables in parallel
 * 1 for each byte of a 32 bit word
 *
 * This is the default h1 computing function
 *
 */

uint32_t
nxge_compute_h1_table4(uint32_t crcin, uint32_t *flow, uint32_t length)
{
	uint32_t w, fw, i, crch1 = crcin;
	uint32_t *buf;

	buf = (uint32_t *)flow;

	for (i = 0; i < length / 4; i++) {
#ifdef _BIG_ENDIAN
		fw = buf[i];
#else
		fw = flip32(buf[i]);
		fw = buf[i];
#endif
		w = crch1 ^ fw;
		crch1 = h1table[3][w >> 24] ^ h1table[2][(w >> 16) & 0xff] ^
		    h1table[1][(w >> 8) & 0xff] ^ h1table[0][w & 0xff];
	}
	return (crch1);
}

/*
 * table based implementation
 * uses a single table and computes h1 for a byte
 * at a time.
 *
 */

uint32_t
nxge_compute_h1_table1(uint32_t crcin, uint32_t *flow, uint32_t length)
{

	uint32_t i, crch1, tmp = crcin;
	uint8_t *buf;

	buf = (uint8_t *)flow;

	tmp = crcin;
	for (i = 0; i < length; i++) {
		crch1 = COMPUTE_H1_BYTE(tmp, buf[i]);
		tmp = crch1;
	}

	return (crch1);
}
