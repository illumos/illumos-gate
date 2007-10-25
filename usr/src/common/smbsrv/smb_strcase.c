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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Case conversion functions for strings. Originally this module only
 * dealt with ASCII strings. It has been updated to support European
 * character set characters. The current implementation is based on
 * code page table lookup rather than simple character range checks.
 */

#ifdef _KERNEL
#include <sys/types.h>
#include <sys/sunddi.h>
#else
#include <stdio.h>
#include <string.h>
#endif
#include <smbsrv/ctype.h>
#include <smbsrv/codepage.h>
#include <smbsrv/cp_cyrillic.h>
#include <smbsrv/cp_latin1.h>
#include <smbsrv/cp_latin2.h>
#include <smbsrv/cp_latin3.h>
#include <smbsrv/cp_latin4.h>
#include <smbsrv/cp_latin5.h>
#include <smbsrv/cp_latin6.h>
#include <smbsrv/cp_usascii.h>

/*
 * Global pointer to the current code page. This is
 * defaulted to a standard ASCII table.
 */
static codepage_t *current_codepage = usascii_codepage;

/*
 * A flag indicating whether the codepage being used is ASCII
 * When this flag is set, string opeartions can go faster.
 */
static int is_unicode = 0;

/*
 * codepage_isupper
 *
 * Determine whether or not a character is an uppercase character.
 * This function operates on the current codepage table. Returns
 * non-zero if the character is uppercase. Otherwise returns zero.
 */
int
codepage_isupper(int c)
{
	unsigned short mask = is_unicode ? 0xffff : 0xff;

	return (current_codepage[c & mask].ctype & CODEPAGE_ISUPPER);
}


/*
 * codepage_islower
 *
 * Determine whether or not a character is an lowercase character.
 * This function operates on the current codepage table. Returns
 * non-zero if the character is lowercase. Otherwise returns zero.
 */
int
codepage_islower(int c)
{
	unsigned short mask = is_unicode ? 0xffff : 0xff;

	return (current_codepage[c & mask].ctype & CODEPAGE_ISLOWER);
}


/*
 * codepage_toupper
 *
 * Convert individual characters to their uppercase equivalent value.
 * If the specified character is lowercase, the uppercase value will
 * be returned. Otherwise the original value will be returned.
 */
int
codepage_toupper(int c)
{
	unsigned short mask = is_unicode ? 0xffff : 0xff;

	return (current_codepage[c & mask].upper);
}


/*
 * codepage_tolower
 *
 * Convert individual characters to their lowercase equivalent value.
 * If the specified character is uppercase, the lowercase value will
 * be returned. Otherwise the original value will be returned.
 */
int
codepage_tolower(int c)
{
	unsigned short mask = is_unicode ? 0xffff : 0xff;

	return (current_codepage[c & mask].lower);
}


/*
 * strupr
 *
 * Convert a string to uppercase using the appropriate codepage. The
 * string is converted in place. A pointer to the string is returned.
 * There is an assumption here that uppercase and lowercase values
 * always result encode to the same length.
 */
char *
utf8_strupr(char *s)
{
	mts_wchar_t c;
	char *p = s;

	while (*p) {
		if (mts_isascii(*p)) {
			*p = codepage_toupper(*p);
			p++;
		} else {
			if (mts_mbtowc(&c, p, MTS_MB_CHAR_MAX) < 0)
				return (0);

			if (c == 0)
				break;

			c = codepage_toupper(c);
			p += mts_wctomb(p, c);
		}
	}

	return (s);
}


/*
 * strlwr
 *
 * Convert a string to lowercase using the appropriate codepage. The
 * string is converted in place. A pointer to the string is returned.
 * There is an assumption here that uppercase and lowercase values
 * always result encode to the same length.
 */
char *
utf8_strlwr(char *s)
{
	mts_wchar_t c;
	char *p = s;

	while (*p) {
		if (mts_isascii(*p)) {
			*p = codepage_tolower(*p);
			p++;
		} else {
			if (mts_mbtowc(&c, p, MTS_MB_CHAR_MAX) < 0)
				return (0);

			if (c == 0)
				break;

			c = codepage_tolower(c);
			p += mts_wctomb(p, c);
		}
	}

	return (s);
}


/*
 * isstrlwr
 *
 * Returns 1 if string contains NO uppercase chars 0 otherwise. However,
 * -1 is returned if "s" is not a valid multi-byte string.
 */
int
utf8_isstrlwr(const char *s)
{
	mts_wchar_t c;
	int n;
	const char *p = s;

	while (*p) {
		if (mts_isascii(*p) && codepage_isupper(*p))
			return (0);
		else {
			if ((n = mts_mbtowc(&c, p, MTS_MB_CHAR_MAX)) < 0)
				return (-1);

			if (c == 0)
				break;

			if (codepage_isupper(c))
				return (0);

			p += n;
		}
	}

	return (1);
}


/*
 * isstrupr
 *
 * Returns 1 if string contains NO lowercase chars 0 otherwise. However,
 * -1 is returned if "s" is not a valid multi-byte string.
 */
int
utf8_isstrupr(const char *s)
{
	mts_wchar_t c;
	int n;
	const char *p = s;

	while (*p) {
		if (mts_isascii(*p) && codepage_islower(*p))
			return (0);
		else {
			if ((n = mts_mbtowc(&c, p, MTS_MB_CHAR_MAX)) < 0)
				return (-1);

			if (c == 0)
				break;

			if (codepage_islower(c))
				return (0);

			p += n;
		}
	}

	return (1);
}


/*
 * strcasecmp
 *
 * Compare the null-terminated strings s1 and s2 and return an integer
 * greater than, equal to, or less than 0, according as s1 is lexico
 * graphically greater than, equal to, or less than s2 after translation
 * of each corresponding character to lowercase. The strings themselves
 * are not modified.
 *
 * Out:    0 if strings are equal
 *       < 0 if first string < second string
 *       > 0 if first string > second string
 */
int
utf8_strcasecmp(const char *s1, const char *s2)
{
	mts_wchar_t c1, c2;
	int n1, n2;
	const char *p1 = s1;
	const char *p2 = s2;

	for (;;) {
		if (mts_isascii(*p1))
			c1 = *p1++;
		else {
			if ((n1 = mts_mbtowc(&c1, p1, MTS_MB_CHAR_MAX)) < 0)
				return (-1);
			p1 += n1;
		}

		if (mts_isascii(*p2))
			c2 = *p2++;
		else {
			if ((n2 = mts_mbtowc(&c2, p2, MTS_MB_CHAR_MAX)) < 0)
				return (1);
			p2 += n2;
		}

		if (c1 == 0 || c2 == 0)
			break;

		if (c1 == c2)
			continue;

		c1 = codepage_tolower(c1);
		c2 = codepage_tolower(c2);

		if (c1 != c2)
			break;
	}

	return ((int)c1 - (int)c2);
}


/*
 * strncasecmp
 *
 * Compare two null-terminated strings, s1 and s2, of at most len
 * characters and return an int greater than, equal to, or less than 0,
 * dependent on whether s1 is lexicographically greater than, equal to,
 * or less than s2 after translation of each corresponding character to
 * lowercase. The original strings are not modified.
 *
 * Out:    0 if strings are equal
 *       < 0 if first string < second string
 *       > 0 if first string > second string
 */
int
utf8_strncasecmp(const char *s1, const char *s2, int len)
{
	mts_wchar_t c1, c2;
	int n1, n2;
	const char *p1 = s1;
	const char *p2 = s2;

	if (len <= 0)
		return (0);

	while (len--) {
		if (mts_isascii(*p1))
			c1 = *p1++;
		else {
			if ((n1 = mts_mbtowc(&c1, p1, MTS_MB_CHAR_MAX)) < 0)
				return (-1);
			p1 += n1;
		}

		if (mts_isascii(*p2))
			c2 = *p2++;
		else {
			if ((n2 = mts_mbtowc(&c2, p2, MTS_MB_CHAR_MAX)) < 0)
				return (1);
			p2 += n2;
		}

		if (c1 == 0 || c2 == 0)
			break;

		if (c1 == c2)
			continue;

		c1 = codepage_tolower(c1);
		c2 = codepage_tolower(c2);

		if (c1 != c2)
			break;
	}

	return ((int)c1 - (int)c2);
}



int
utf8_isstrascii(const char *s)
{
	while (*s) {
		if (mts_isascii(*s) == 0)
			return (0);
		s++;
	}
	return (1);
}
