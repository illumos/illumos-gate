/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright(c) 2001 Sun Microsystems, Inc.
 * All rights reserved.
 */

#if defined UCS_2LE
static int unichr_to_ucs_2le (st, unichr, buf, buflen, uconv_num)
_iconv_st *st;
unsigned long unichr;
char	*buf;
size_t	buflen;
int	*uconv_num;
{
	int size = 0;

	if (unichr > 0x00ffff) {
	  unichr = ICV_CHAR_UCS2_REPLACEMENT;
	  *uconv_num = 1;
	}

	if (!st->bom_written) {
	  if (buflen < 4)
	    return 0;

	  *(buf + size++) = (uchar_t)0xff;
	  *(buf + size++) = (uchar_t)0xfe;
	  st->bom_written = true;
	}

	if (buflen < 2)
	  return 0;

	*(buf + size++) = (uchar_t)(unichr & 0xff);
	*(buf + size++) = (uchar_t)((unichr >> 8) & 0xff);

	return size;
}

#elif defined UCS_2BE
static int unichr_to_ucs_2be (st, unichr, buf, buflen, uconv_num)
_iconv_st *st;
unsigned long unichr;
char	*buf;
size_t	buflen;
int	*uconv_num;
{
	int size = 0;

	if (unichr > 0x00ffff) {
	  unichr = ICV_CHAR_UCS2_REPLACEMENT;
	  *uconv_num = 1;
	}

	if (!st->bom_written) {
	  if (buflen < 4)
	    return 0;

	  *(buf + size++) = (uchar_t)0xfe;
	  *(buf + size++) = (uchar_t)0xff;
	  st->bom_written = true;
	}

	if (buflen < 2)
	  return 0;

	*(buf + size++) = (uchar_t)((unichr >> 8) & 0xff);
	*(buf + size++) = (uchar_t)(unichr & 0xff);

	return size;
}

#elif defined UCS_4LE
static int unichr_to_ucs_4le (st, unichr, buf, buflen, uconv_num)
_iconv_st *st;
unsigned long unichr;
char	*buf;
size_t	buflen;
int	*uconv_num;
{
	int size = 0;

	if (unichr == 0xffffffff) {
	  unichr = ICV_CHAR_UCS2_REPLACEMENT;
	  *uconv_num = 1;
	}

	if (!st->bom_written) {
	  if (buflen < 8)
	    return 0;

	  *(buf + size++) = (uchar_t)0xff;
	  *(buf + size++) = (uchar_t)0xfe;
	  *(buf + size++) = (uchar_t)0;
	  *(buf + size++) = (uchar_t)0;
	  st->bom_written = true;
	}

	if (buflen < 4)
	  return 0;

	*(buf + size++) = (uchar_t)(unichr & 0xff);
	*(buf + size++) = (uchar_t)((unichr >> 8) & 0xff);
	*(buf + size++) = (uchar_t)((unichr >> 16) & 0xff);
	*(buf + size++) = (uchar_t)((unichr >> 24) & 0xff);

	return size;
}

#elif defined UCS_4BE
static int unichr_to_ucs_4be (st, unichr, buf, buflen, uconv_num)
_iconv_st *st;
unsigned long unichr;
char	*buf;
size_t	buflen;
int	*uconv_num;
{
	int size = 0;

	if (unichr == 0xffffffff) {
	  unichr = ICV_CHAR_UCS2_REPLACEMENT;
	  *uconv_num = 1;
	}

	if (!st->bom_written) {
	  if (buflen < 8)
	    return 0;

	  *(buf + size++) = (uchar_t)0;
	  *(buf + size++) = (uchar_t)0;
	  *(buf + size++) = (uchar_t)0xfe;
	  *(buf + size++) = (uchar_t)0xff;
	  st->bom_written = true;
	}

	if (buflen < 4)
	  return 0;

	*(buf + size++) = (uchar_t)((unichr >> 24) & 0xff);
	*(buf + size++) = (uchar_t)((unichr >> 16) & 0xff);
	*(buf + size++) = (uchar_t)((unichr >> 8) & 0xff);
	*(buf + size++) = (uchar_t)(unichr & 0xff);

	return size;
}

#else
static int unichr_to_utf8(_iconv_st *st, unsigned long unichr, char *buf,
	size_t buflen, int *uconv_num)
{
        if (unichr < 0x0080) {
                if (buflen < 1) {
                        errno = E2BIG;
                        return(0);
                }
                *buf = (char) unichr;
                return(1);
        }

	if (unichr >= 0x0080 && unichr <= 0x07ff) {
		if (buflen < 2) {
			errno = E2BIG;
			return(0);
		}
		*buf = (char)((unichr >> 6) & 0x1f) | 0xc0;
		*(buf+1) = (char)(unichr & 0x3f) | 0x80;
		return(2);
	}

	if (unichr >= 0x0800 && unichr <= 0xffff) {
		if (buflen < 3) {
			errno = E2BIG;
			return(0);
		}
		*buf = (char)((unichr >> 12) & 0xf) | 0xe0;
		*(buf+1) = (char)((unichr >>6) & 0x3f) | 0x80;
		*(buf+2) = (char)(unichr & 0x3f) | 0x80;
		return(3);
	}

	if (unichr >= 0x10000 && unichr <= 0x10ffff) {
	        if (buflen < 4) {
		     errno = E2BIG;
		     return(0);
		}

	        *buf = (char)((unichr >> 18) & 0x7) | 0xf0;
	        *(buf+1) = (char)((unichr >> 12) & 0x3f) | 0x80;
	        *(buf+2) = (char)((unichr >>6) & 0x3f) | 0x80;
	        *(buf+3) = (char)(unichr & 0x3f) | 0x80;
	        return(4);
	}

	/* unrecognized unicode character */
	if (buflen < 3) {
		errno = E2BIG;
		return(0);
	}
	*buf = (char)UTF8_NON_ID_CHAR1;
	*(buf+1) = (char)UTF8_NON_ID_CHAR2;
	*(buf+2) = (char)UTF8_NON_ID_CHAR3;

        /* non-identical conversions */
        *uconv_num = 1;

	return(3);
}
#endif

/*
vi:ts=8:ai:expandtab
*/
