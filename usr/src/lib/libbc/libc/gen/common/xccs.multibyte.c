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
 * Copyright 1990 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#if !defined(lint) && defined(SCCSIDS)
static  char *sccsid = "%Z%%M% %I%     %E% SMI";
#endif 

#include <stdio.h>
#include <sys/types.h>

#define CS377	0377
#define MASK	0x0000ffff
#define TOP1	0x80000000
#define TOP2	0x08000000


/*
 * mbtowc routines for the Xerox XCCS codeset standard
 */
int
_mbtowc_xccs(pwc, s, n)
	wchar_t *pwc;
	char *s;
	int n;
{
	static unsigned int CSselect = 0;
	static int CSlength = 1;
	wchar_t twchar = 0;

	/*
	 * If length is negative, return error
	 */
	if (n <= 0)
		return (-1);

	/*
	 * End of string ?
	 */
	if (*s == 0 && CSlength == 1)
		return (0);
	if (*s == 0 && *(s + 1) == 0 && CSlength == 2)
		return (0);

	/*
	 * Get a character
	 */
	if ((unsigned char)*s == CS377) {
		/*
		 * Switching code set
		 */
		++s;
		/*
		 * Change characteristics
		 */
		 if ((unsigned char)*s == CS377) {
			++s;
			/*
			 * two byte sequence
			 */
			 if (*s++ != 0)
				return (-1);
			 CSselect = 0;
			 CSlength = 2;
			 
		 }
		 else {
			/*
			 * Change CSselect
			 */
			 CSselect = (unsigned int)*s++;
			 CSlength = 1;
		}
	}

	/*
	 * Get a character and return
	 */
	 if (CSlength == 1) {
		twchar = CSselect;
	 }
	 else {
		twchar = *s++;
	 }
	 twchar = twchar << 8;
	 twchar = twchar | *s;
	 if (pwc)
		 *pwc = twchar & MASK;
	 /*
	  * Encode additional information
	  */
	 if (CSlength == 2)
		if (pwc)
			*pwc |= TOP1;
	 return (CSlength);
}

/*
 * wctomb routines
 */
int
_wctomb_xccs(s, pwc)
	char *s;
	wchar_t pwc;
{ 
	unsigned char upper, lower;
	char *old = s;
#ifdef DEBUG
	printf ("XCCS- xctomb\n");
#endif

	if (!s)
		return (0);

	/*
	 * Get lower and upper anyway
	 */
	lower = pwc & 0x00ff;
	upper = (pwc >> 8) & 0x00ff;
	if (lower == CS377 || upper == CS377)
		return (-1);
	if (pwc & TOP1) {	/* length == 2 */
		/*
		 * This was the marker.
		 * Emitt 3 additional characters.
		 */
		*s++ = CS377;
		*s++ = CS377;
		*s++ = 0;
		*s++ = upper;
		*s++ = lower;
	}
	else {
		/*
		 * This was the marker.
		 * Emitt 2 additional characters.
		 */
		*s++ = CS377;
		*s++ = upper;
		*s++ = lower;
	}
	return (s - old);
}


/*
 * mbstowcs routines
 */
size_t
_mbstowcs_xccs(pwc, s, n)
	wchar_t *pwc;
	char *s;
	int n;
{
	static unsigned int CSselect = 0;
	static int CSlength = 1;
	wchar_t twchar = 0;
	int cnt = 0;

	/*
	 * If length is negative, return error
	 */
	if (n <= 0)
		return (-1);

	/*
	 * End of string ?
	 */
	if (*s == 0 && CSlength == 1)
		return (0);
	if (*s == 0 && *(s + 1) == 0 && CSlength == 2)
		return (0);

	do {
		/*
		 * Check for an end of the string
		 */
		if (((*s == 0 && CSlength == 1)) ||
		   ((*s == 0 && *(s + 1) == 0 && CSlength == 2))) {
			*pwc = 0;
			++cnt;
			--n;
			break;
		}
		/*
		 * Get a character
		 */
		if ((unsigned char)*s == CS377) {
			++s;
			/*
			 * Change characterristics
			 */
			 if ((unsigned char)*s == CS377) {
				++s;
				/*
				 * two byte sequence
				 */
				 if (*s++ != 0)
					return (-1);
				 CSselect = 0;
				 CSlength = 2;
				 
			 }
			 else {
				/*
				 * Change CSselect
				 */
				 CSselect = (unsigned int)*s++;
				 CSlength = 1;
			}
		}

		/*
		 * Get a character and return
		 */
		 if (CSlength == 1) {
			twchar = CSselect;
		 }
		 else {
			twchar = *s++;
		 }
		 twchar = twchar << 8;
		 twchar = twchar | *s++;
		 *pwc = twchar & MASK;
		 if (CSlength == 2)
			*pwc |= TOP1;
		 ++pwc;
		 ++cnt;
		 --n;
	 } while (n >= 0);
	 return (cnt);
}


/*
 * wcstombs routines
 */
size_t
_wcstombs_xccs(s, pwc, n)
	char *s;
	wchar_t *pwc;
	int n;
{
	int cnt = 0;
	unsigned char lower, upper;
	int in_2byte = 0;
	int in_1byte = 0;
	int current = 0;

	if (n <= 0)
		return (-1);
	
	if (*pwc == 0)
		return (0);

	do {
		lower = *pwc & 0x00ff;
		upper = (*pwc >> 8) & 0x00ff;
		/*
		 * End of string ?
		 */
		if (lower == 0) {
			*s++ = 0;
			++cnt;
			--n;
			if (n == 0)
				break;
			*s++ = 0;
			++cnt;
			break;
		}
		if (lower == CS377 || upper == CS377)
			return (-1);
		if (*pwc & TOP1) {	/* length == 2 */
			if (in_2byte == 0) {
				/*
				 * This was the marker.
				 * Emitt 3 additional characters.
				 */
				*s++ = CS377; ++cnt; --n;
				*s++ = CS377; ++cnt; --n;
				*s++ = 0; ++cnt; --n;
				in_2byte = 1;
				in_1byte = 0;
			}
			*s++ = upper; ++cnt; --n;
			if (n == 0)
				break;
			*s++ = lower; ++cnt; --n;
			if (n == 0)
				break;
		}
		else {
			if ((in_1byte == 0 && in_2byte == 1) ||
			    (in_1byte == 1 && upper != current) ||
			    (in_1byte == 0 && in_2byte == 0 && upper != 0)) {
				/*
				 * This was the marker.
				 * Emitt 2 additional characters.
				 */
				*s++ = CS377; ++cnt; --n;
				if (n == 0)
					break;
				*s++ = upper; ++cnt; --n;
				if (n == 0)
					break;
				in_2byte = 0;
				in_1byte = 1;
				current = upper;
			}
			*s++ = lower; ++cnt; --n;
			if (n == 0)
				break;
		}
		++pwc;
	} while (n >= 0);
	return (cnt);
}
