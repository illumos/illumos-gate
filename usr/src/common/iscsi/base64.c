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

#include <sys/types.h>
#ifdef _KERNEL
#include <sys/sunddi.h>
#include <sys/errno.h>
#else
#include <string.h>
#include <errno.h>
#endif	/* _KERNEL */

/*
 * base64 decoding table (from uudecode.c)
 */
/* BEGIN CSTYLED */
 static char base64_decode_tab[] = {
	'\377', '\377', '\377', '\377', '\377', '\377', '\377', '\377',
	'\377', '\377', '\377', '\377', '\377', '\377', '\377', '\377',
	'\377', '\377', '\377', '\377', '\377', '\377', '\377', '\377',
	'\377', '\377', '\377', '\377', '\377', '\377', '\377', '\377',
	'\377', '\377', '\377', '\377', '\377', '\377', '\377', '\377',
	'\377', '\377', '\377',     62, '\377', '\377', '\377',     63,
	    52,     53,     54,     55,     56,     57,     58,     59,
	    60,     61, '\377', '\377', '\377', '\377', '\377', '\377',
	'\377',      0,      1,      2,      3,      4,      5,      6,
	     7,      8,      9,     10,     11,     12,     13,     14,
	    15,     16,     17,     18,     19,     20,     21,     22,
	    23,     24,     25, '\377', '\377', '\377', '\377', '\377',
	'\377',     26,     27,     28,     29,     30,     31,     32,
	    33,     34,     35,     36,     37,     38,     39,     40,
	    41,     42,     43,     44,     45,     46,     47,     48,
	    49,     50,     51, '\377', '\377', '\377', '\377', '\377'
};
/* END CSTYLED */

/* true if the character is in the base64 encoding table */
#define	validbase64(c) (('A' <= (c) && (c) <= 'Z') || \
		('a' <= (c) && (c) <= 'z') || \
		('0' <= (c) && (c) <= '9') || \
		(c) == '+' || (c) == '/')

static int
outdec64(unsigned char *out, unsigned char *chr, int num)
{

	unsigned char char1, char2, char3, char4;
	unsigned char *outptr = out;
	int rc = 0;

	switch (num) {
	case 0:
	case 1:		/* these are impossible */
	default:
		break;
	case 2:		/* 2 base64 bytes == 1 decoded byte */
		char1 = base64_decode_tab[chr[0]] & 0xFF;
		char2 = base64_decode_tab[chr[1]] & 0xFF;
		*(outptr++) = ((char1 << 2) & 0xFC) |
		    ((char2 >> 4) & 0x03);
		rc = 1;
		break;
	case 3:		/* 3 base64 bytes == 2 decoded bytes */
		char1 = base64_decode_tab[chr[0]] & 0xFF;
		char2 = base64_decode_tab[chr[1]] & 0xFF;
		char3 = base64_decode_tab[chr[2]] & 0xFF;
		*(outptr++) = ((char1 << 2) & 0xFC) |
		    ((char2 >> 4) & 0x03);
		*(outptr++) = ((char2 << 4) & 0xF0) |
		    ((char3 >> 2) & 0x0F);
		rc = 2;
		break;
	case 4:		/* 4 base64 bytes == 3 decoded bytes */
		char1 = base64_decode_tab[chr[0]] & 0xFF;
		char2 = base64_decode_tab[chr[1]] & 0xFF;
		char3 = base64_decode_tab[chr[2]] & 0xFF;
		char4 = base64_decode_tab[chr[3]] & 0xFF;
		*(outptr++) = ((char1 << 2) & 0xFC) |
		    ((char2 >> 4) & 0x03);
		*(outptr++) = ((char2 << 4) & 0xF0) |
		    ((char3 >> 2) & 0x0F);
		*(outptr++) = ((char3 << 6) & 0xC0) |
		    (char4 & 0x3F);
		rc = 3;
		break;
	}
	return (rc);
}

#define	BUFSIZE	12

int
iscsi_base64_str_to_binary(char *hstr, int hstr_len,
    uint8_t *binary, int binary_buf_len, int *out_len)
{
	char	*iptr;
	uint8_t	tmp_out[BUFSIZE];
	int	octets, endseen, numbase64chars;
	unsigned char chr[4], curchr;

	/*
	 * base64 decode algorith, adapted from uudecode.c
	 *
	 * A valid base64 string is a multiple of 4 bytes in length
	 */
	if ((hstr_len % 4) != 0)
		return (EINVAL);

	endseen = numbase64chars = 0;
	*out_len = 0;
	iptr = hstr;

	while (((curchr = *(iptr++)) != '\0') &&
	    (((uintptr_t)iptr - (uintptr_t)hstr) <= hstr_len)) {
		/* decode chars */
		if (curchr == '=') /* if end */
			endseen++;

		if (validbase64(curchr))
			chr[numbase64chars++] = curchr;
		/*
		 * if we've gathered 4 base64 octets
		 * we need to decode and output them
		 */
		if (numbase64chars == 4) {
			octets = outdec64(tmp_out, chr, 4);
			numbase64chars = 0;

			if (*out_len + octets > binary_buf_len)
				return (E2BIG);

			(void) memcpy(binary + *out_len, tmp_out, octets);
			*out_len += octets;
		}

		/*
		 * handle any remaining base64 octets at end
		 */
		if (endseen && numbase64chars > 0) {
			octets = outdec64(tmp_out, chr, numbase64chars);
			numbase64chars = 0;
			if (*out_len + octets > binary_buf_len)
				return (E2BIG);

			(void) memcpy(binary + *out_len, tmp_out, octets);
			*out_len += octets;
		}
	}

	return (0);
}


static char base64_encode_tab[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	"abcdefghijklmnopqrstuvwxyz0123456789+/";

#define	ENC(c)	base64_encode_tab[(c) & 0x3f]

#define	BASE64_BUF_HAS_ROOM(bytes_needed) \
	((optr + (bytes_needed)) <= base64_str_buf + base64_buf_len)

int
iscsi_binary_to_base64_str(uint8_t *in_buf, int in_buf_len,
    char *base64_str_buf, int base64_buf_len)
{
	uint8_t		*iptr;
	char		*optr;
	int		in_bytes_remaining;

	/* base64 encode algorith, adapted from uuencode.c */
	iptr = in_buf;
	optr = base64_str_buf;

	/*
	 * read must be a multiple of 3 bytes for
	 * this algorithm to work, and also must
	 * be small enough that read_size * (4/3)
	 * will always be 76 bytes or less, since
	 * base64 lines can be no longer than that
	 */
	while (iptr + 3 <= in_buf + in_buf_len) {
		if (!BASE64_BUF_HAS_ROOM(4))
			return (E2BIG);

		*(optr++) = ENC(*iptr >> 2);
		*(optr++) = ENC((*iptr << 4) & 060 |
		    (*(iptr + 1) >> 4) & 017);
		*(optr++) = ENC((*(iptr + 1) << 2)
		    & 074 | (*(iptr + 2) >> 6) & 03);
		*(optr++) = ENC(*(iptr + 2) & 077);

		iptr += 3;
	}

	/* need output padding ? */
	in_bytes_remaining = ((uintptr_t)in_buf + in_buf_len) - (uintptr_t)iptr;
	/* ASSERT(in_bytes_remaining < 3); */
	switch (in_bytes_remaining) {
	case 0:
		/* no-op  - 24 bits of data encoded */
		if (!BASE64_BUF_HAS_ROOM(1))
			return (E2BIG);
		*(optr++) = '\0';
		break;
	case 1:
		/* 8 bits encoded - pad with 2 '=' */
		if (!BASE64_BUF_HAS_ROOM(5))
			return (E2BIG);
		*(optr++) = ENC((*iptr & 0xFC) >> 2);
		*(optr++) = ENC((*iptr & 0x03) << 4);
		*(optr++) = '=';
		*(optr++) = '=';
		*(optr++) = '\0';
		break;
	case 2:
		/* 16 bits encoded - pad with 1 '=' */
		if (!BASE64_BUF_HAS_ROOM(5))
			return (E2BIG);
		*(optr++) = ENC((*iptr & 0xFC) >> 2);
		*(optr++) = ENC(((*iptr & 0x03) << 4) |
		    ((*(iptr + 1) & 0xF0) >> 4));
		*(optr++) = ENC((*(iptr + 1) & 0x0F) << 2);
		*(optr++) = '=';
		*(optr++) = '\0';
		break;
	default:
		/* impossible */
		break;
	}

	return (0);
}
