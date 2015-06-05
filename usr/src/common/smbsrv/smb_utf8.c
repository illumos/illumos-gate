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
 *
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Multibyte/wide-char conversion routines. Wide-char encoding provides
 * a fixed size character encoding that maps to the Unicode 16-bit
 * (UCS-2) character set standard. Multibyte or UCS transformation
 * format (UTF) encoding is a variable length character encoding scheme
 * that s compatible with existing ASCII characters and guarantees that
 * the resultant strings do not contain embedded null characters. Both
 * types of encoding provide a null terminator: single byte for UTF-8
 * and a wide-char null for Unicode. See RFC 2044.
 *
 * The table below illustrates the UTF-8 encoding scheme. The letter x
 * indicates bits available for encoding the character value.
 *
 *	UCS-2			UTF-8 octet sequence (binary)
 *	0x0000-0x007F	0xxxxxxx
 *	0x0080-0x07FF	110xxxxx 10xxxxxx
 *	0x0800-0xFFFF	1110xxxx 10xxxxxx 10xxxxxx
 *
 * RFC 2044
 * UTF-8,a transformation format of UNICODE and ISO 10646
 * F. Yergeau
 * Alis Technologies
 * October 1996
 */

#if defined(_KERNEL) || defined(_FAKE_KERNEL)
#include <sys/types.h>
#include <sys/sunddi.h>
#else
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <strings.h>
#endif
#include <smbsrv/string.h>


/*
 * mbstowcs
 *
 * The mbstowcs() function converts a multibyte character string
 * mbstring into a wide character string wcstring. No more than
 * nwchars wide characters are stored. A terminating null wide
 * character is appended if there is room.
 *
 * Returns the number of wide characters converted, not counting
 * any terminating null wide character. Returns -1 if an invalid
 * multibyte character is encountered.
 */
size_t
smb_mbstowcs(smb_wchar_t *wcstring, const char *mbstring, size_t nwchars)
{
	int len;
	smb_wchar_t	*start = wcstring;

	while (nwchars--) {
		len = smb_mbtowc(wcstring, mbstring, MTS_MB_CHAR_MAX);
		if (len < 0) {
			*wcstring = 0;
			return ((size_t)-1);
		}

		if (*mbstring == 0)
			break;

		++wcstring;
		mbstring += len;
	}

	return (wcstring - start);
}


/*
 * mbtowc
 *
 * The mbtowc() function converts a multibyte character mbchar into
 * a wide character and stores the result in the object pointed to
 * by wcharp. Up to nbytes bytes are examined.
 *
 * If mbchar is NULL, mbtowc() returns zero to indicate that shift
 * states are not supported.  Shift states are used to switch between
 * representation modes using reserved bytes to signal shifting
 * without them being interpreted as characters.  If mbchar is null
 * mbtowc should return non-zero if the current locale requires shift
 * states.  Otherwise it should be return 0.
 *
 * If mbchar is non-null, returns the number of bytes processed in
 * mbchar.  If mbchar is invalid, returns -1.
 */
int /*ARGSUSED*/
smb_mbtowc(smb_wchar_t *wcharp, const char *mbchar, size_t nbytes)
{
	unsigned char mbyte;
	smb_wchar_t wide_char;
	int count;
	int bytes_left;

	if (mbchar == NULL)
		return (0); /* no shift states */

	/* 0xxxxxxx -> 1 byte ASCII encoding */
	if (((mbyte = *mbchar++) & 0x80) == 0) {
		if (wcharp)
			*wcharp = (smb_wchar_t)mbyte;

		return (mbyte ? 1 : 0);
	}

	/* 10xxxxxx -> invalid first byte */
	if ((mbyte & 0x40) == 0)
		return (-1);

	wide_char = mbyte;
	if ((mbyte & 0x20) == 0) {
		wide_char &= 0x1f;
		bytes_left = 1;
	} else if ((mbyte & 0x10) == 0) {
		wide_char &= 0x0f;
		bytes_left = 2;
	} else {
		return (-1);
	}

	count = 1;
	while (bytes_left--) {
		if (((mbyte = *mbchar++) & 0xc0) != 0x80)
			return (-1);

		count++;
		wide_char = (wide_char << 6) | (mbyte & 0x3f);
	}

	if (wcharp)
		*wcharp = wide_char;

	return (count);
}


/*
 * wctomb
 *
 * The wctomb() function converts a wide character wchar into a multibyte
 * character and stores the result in mbchar. The object pointed to by
 * mbchar must be large enough to accommodate the multibyte character.
 *
 * Returns the numberof bytes written to mbchar.
 */
int
smb_wctomb(char *mbchar, smb_wchar_t wchar)
{
	if ((wchar & ~0x7f) == 0) {
		*mbchar = (char)wchar;
		return (1);
	}

	if ((wchar & ~0x7ff) == 0) {
		*mbchar++ = (wchar >> 6) | 0xc0;
		*mbchar = (wchar & 0x3f) | 0x80;
		return (2);
	}

	*mbchar++ = (wchar >> 12) | 0xe0;
	*mbchar++ = ((wchar >> 6) & 0x3f) | 0x80;
	*mbchar = (wchar & 0x3f) | 0x80;
	return (3);
}


/*
 * wcstombs
 *
 * The wcstombs() function converts a wide character string wcstring
 * into a multibyte character string mbstring. Up to nbytes bytes are
 * stored in mbstring. Partial multibyte characters at the end of the
 * string are not stored. The multibyte character string is null
 * terminated if there is room.
 *
 * Returns the number of bytes converted, not counting the terminating
 * null byte.
 */
size_t
smb_wcstombs(char *mbstring, const smb_wchar_t *wcstring, size_t nbytes)
{
	char *start = mbstring;
	const smb_wchar_t *wcp = wcstring;
	smb_wchar_t wide_char = 0;
	char buf[4];
	size_t len;

	if ((mbstring == NULL) || (wcstring == NULL))
		return (0);

	while (nbytes > MTS_MB_CHAR_MAX) {
		wide_char = *wcp++;
		len = smb_wctomb(mbstring, wide_char);

		if (wide_char == 0)
			/*LINTED E_PTRDIFF_OVERFLOW*/
			return (mbstring - start);

		mbstring += len;
		nbytes -= len;
	}

	while (wide_char && nbytes) {
		wide_char = *wcp++;
		if ((len = smb_wctomb(buf, wide_char)) > nbytes) {
			*mbstring = 0;
			break;
		}

		bcopy(buf, mbstring, len);
		mbstring += len;
		nbytes -= len;
	}

	/*LINTED E_PTRDIFF_OVERFLOW*/
	return (mbstring - start);
}


/*
 * Returns the number of bytes that would be written if the multi-
 * byte string mbs was converted to a wide character string, not
 * counting the terminating null wide character.
 */
size_t
smb_wcequiv_strlen(const char *mbs)
{
	smb_wchar_t	wide_char;
	size_t bytes;
	size_t len = 0;

	while (*mbs) {
		bytes = smb_mbtowc(&wide_char, mbs, MTS_MB_CHAR_MAX);
		if (bytes == ((size_t)-1))
			return ((size_t)-1);

		len += sizeof (smb_wchar_t);
		mbs += bytes;
	}

	return (len);
}


/*
 * Returns the number of bytes that would be written if the multi-
 * byte string mbs was converted to a single byte character string,
 * not counting the terminating null character.
 */
size_t
smb_sbequiv_strlen(const char *mbs)
{
	smb_wchar_t	wide_char;
	size_t nbytes;
	size_t len = 0;

	while (*mbs) {
		nbytes = smb_mbtowc(&wide_char, mbs, MTS_MB_CHAR_MAX);
		if (nbytes == ((size_t)-1))
			return ((size_t)-1);

		if (wide_char & 0xFF00)
			len += sizeof (smb_wchar_t);
		else
			++len;

		mbs += nbytes;
	}

	return (len);
}


/*
 * stombs
 *
 * Convert a regular null terminated string 'string' to a UTF-8 encoded
 * null terminated multi-byte string 'mbstring'. Only full converted
 * UTF-8 characters will be written 'mbstring'. If a character will not
 * fit within the remaining buffer space or 'mbstring' will overflow
 * max_mblen, the conversion process will be terminated and 'mbstring'
 * will be null terminated.
 *
 * Returns the number of bytes written to 'mbstring', excluding the
 * terminating null character.
 *
 * If either mbstring or string is a null pointer, -1 is returned.
 */
int
smb_stombs(char *mbstring, char *string, int max_mblen)
{
	char *start = mbstring;
	unsigned char *p = (unsigned char *)string;
	int space_left = max_mblen;
	int	len;
	smb_wchar_t	wide_char;
	char buf[4];

	if (!mbstring || !string)
		return (-1);

	while (*p && space_left > 2) {
		wide_char = *p++;
		len = smb_wctomb(mbstring, wide_char);
		mbstring += len;
		space_left -= len;
	}

	if (*p) {
		wide_char = *p;
		if ((len = smb_wctomb(buf, wide_char)) < 2) {
			*mbstring = *buf;
			mbstring += len;
			space_left -= len;
		}
	}

	*mbstring = '\0';

	/*LINTED E_PTRDIFF_OVERFLOW*/
	return (mbstring - start);
}


/*
 * mbstos
 *
 * Convert a null terminated multi-byte string 'mbstring' to a regular
 * null terminated string 'string'.  A 1-byte character in 'mbstring'
 * maps to a 1-byte character in 'string'. A 2-byte character in
 * 'mbstring' will be mapped to 2-bytes, if the upper byte is non-null.
 * Otherwise the upper byte null will be discarded to ensure that the
 * output stream does not contain embedded null characters.
 *
 * If the input stream contains invalid multi-byte characters, a value
 * of -1 will be returned. Otherwise the length of 'string', excluding
 * the terminating null character, is returned.
 *
 * If either mbstring or string is a null pointer, -1 is returned.
 */
int
smb_mbstos(char *string, const char *mbstring)
{
	smb_wchar_t wc;
	unsigned char *start = (unsigned char *)string;
	int len;

	if (string == NULL || mbstring == NULL)
		return (-1);

	while (*mbstring) {
		if ((len = smb_mbtowc(&wc, mbstring, MTS_MB_CHAR_MAX)) < 0) {
			*string = 0;
			return (-1);
		}

		if (wc & 0xFF00) {
			/*LINTED E_BAD_PTR_CAST_ALIGN*/
			*((smb_wchar_t *)string) = wc;
			string += sizeof (smb_wchar_t);
		}
		else
		{
			*string = (unsigned char)wc;
			string++;
		}

		mbstring += len;
	}

	*string = 0;

	/*LINTED E_PTRDIFF_OVERFLOW*/
	return ((unsigned char *)string - start);
}
