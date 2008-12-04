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

/*
 * Unicode conversions (yet more)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <iconv.h>
#include <libintl.h>

#include <sys/u8_textprep.h>

#include <netsmb/smb_lib.h>
#include "charsets.h"


/*
 * Number of unicode symbols in the string,
 * not including the 2-byte null terminator.
 * (multiply by two for storage size)
 */
size_t
unicode_strlen(const uint16_t *us)
{
	size_t len = 0;
	while (*us++)
		len++;
	return (len);
}

static char *convert_ucs2xx_to_utf8(iconv_t, const uint16_t *);

/*
 * Convert (native) Unicode string to UTF-8.
 * Returns allocated memory.
 */
char *
convert_unicode_to_utf8(uint16_t *us)
{
	static iconv_t cd1 = (iconv_t)-1;

	/* Get conversion descriptor (to, from) */
	if (cd1 == (iconv_t)-1)
		cd1 = iconv_open("UTF-8", "UCS-2");

	return (convert_ucs2xx_to_utf8(cd1, us));
}

/*
 * Convert little-endian Unicode string to UTF-8.
 * Returns allocated memory.
 */
char *
convert_leunicode_to_utf8(unsigned short *us)
{
	static iconv_t cd2 = (iconv_t)-1;

	/* Get conversion descriptor (to, from) */
	if (cd2 == (iconv_t)-1)
		cd2 = iconv_open("UTF-8", "UCS-2LE");

	return (convert_ucs2xx_to_utf8(cd2, us));
}

static char *
convert_ucs2xx_to_utf8(iconv_t cd, const uint16_t *us)
{
	char *obuf, *optr;
	const char *iptr;
	size_t  ileft, obsize, oleft, ret;

	if (cd == (iconv_t)-1) {
		smb_error(dgettext(TEXT_DOMAIN,
		    "iconv_open(UTF-8/UCS-2)"), -1);
		return (NULL);
	}

	iptr = (const char *)us;
	ileft = unicode_strlen(us);
	ileft *= 2; /* now bytes */

	/* Worst-case output size is 2x input size. */
	oleft = ileft * 2;
	obsize = oleft + 2; /* room for null */
	obuf = malloc(obsize);
	if (!obuf)
		return (NULL);
	optr = obuf;

	ret = iconv(cd, &iptr, &ileft, &optr, &oleft);
	*optr = '\0';
	if (ret == (size_t)-1) {
		smb_error(dgettext(TEXT_DOMAIN,
		    "iconv(%s) failed"), errno, obuf);
	}
	if (ileft) {
		smb_error(dgettext(TEXT_DOMAIN,
		    "iconv(%s) failed"), -1, obuf);
		/*
		 * XXX: What's better?  return NULL?
		 * The truncated string? << for now
		 */
	}

	return (obuf);
}

static uint16_t *convert_utf8_to_ucs2xx(iconv_t, const char *);

/*
 * Convert UTF-8 string to Unicode.
 * Returns allocated memory.
 */
uint16_t *
convert_utf8_to_unicode(const char *utf8_string)
{
	static iconv_t cd3 = (iconv_t)-1;

	/* Get conversion descriptor (to, from) */
	if (cd3 == (iconv_t)-1)
		cd3 = iconv_open("UCS-2", "UTF-8");
	return (convert_utf8_to_ucs2xx(cd3, utf8_string));
}

/*
 * Convert UTF-8 string to little-endian Unicode.
 * Returns allocated memory.
 */
uint16_t *
convert_utf8_to_leunicode(const char *utf8_string)
{
	static iconv_t cd4 = (iconv_t)-1;

	/* Get conversion descriptor (to, from) */
	if (cd4 == (iconv_t)-1)
		cd4 = iconv_open("UCS-2LE", "UTF-8");
	return (convert_utf8_to_ucs2xx(cd4, utf8_string));
}

static uint16_t *
convert_utf8_to_ucs2xx(iconv_t cd, const char *utf8_string)
{
	uint16_t *obuf, *optr;
	const char *iptr;
	size_t  ileft, obsize, oleft, ret;

	if (cd == (iconv_t)-1) {
		smb_error(dgettext(TEXT_DOMAIN,
		    "iconv_open(UCS-2/UTF-8)"), -1);
		return (NULL);
	}

	iptr = utf8_string;
	ileft = strlen(iptr);

	/* Worst-case output size is 2x input size. */
	oleft = ileft * 2;
	obsize = oleft + 2; /* room for null */
	obuf = malloc(obsize);
	if (!obuf)
		return (NULL);
	optr = obuf;

	ret = iconv(cd, &iptr, &ileft, (char **)&optr, &oleft);
	*optr = '\0';
	if (ret == (size_t)-1) {
		smb_error(dgettext(TEXT_DOMAIN,
		    "iconv(%s) failed"), errno, utf8_string);
	}
	if (ileft) {
		smb_error(dgettext(TEXT_DOMAIN,
		    "iconv(%s) failed"), -1, utf8_string);
		/*
		 * XXX: What's better?  return NULL?
		 * The truncated string? << for now
		 */
	}

	return (obuf);
}
