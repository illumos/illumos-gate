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
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include "../inc/common_defs.h"

/*
 * convert utf8 string to unicode
 * return value: 0 - fail
 *               1 - success
 */
int
convert_utf8_to_ucs4(uchar_t *ib, int utf8_len, uint_t *unicode)
{
   uchar_t first_byte = *ib;
   uint_t u4;

   if ( number_of_bytes_in_utf8_char[first_byte] != utf8_len) return 0;

   u4 = (uint_t)(*ib++ & masks_tbl[utf8_len]);
   for (; utf8_len > 1; utf8_len--)
     {
	u4 = (u4 << ICV_UTF8_BIT_SHIFT) | (((uint_t) *ib) & ICV_UTF8_BIT_MASK);
	++ib;
     }

   *unicode = u4;

   return 1;
}

/*
 * check whether the input 'str' is valid UTF-8 byte sequence or not,
 * which lenght is specified by 'utf8_len'
 *
 * return: 0 - invalid byte sequence
 * 	   1 - valid byte sequence
 */
int
is_valid_utf8_string(uchar_t *str, int utf8_len)
{
   uint_t unicode = 0;
   uchar_t *ib = str;
   uchar_t first_byte;
   int is_second_byte = 0, len=utf8_len;

   if (number_of_bytes_in_utf8_char[*ib] == ICV_TYPE_ILLEGAL_CHAR ||
       number_of_bytes_in_utf8_char[*ib] != utf8_len ) return 0;

   first_byte = *ib;
   --utf8_len;
   ++ib;
   is_second_byte = 1;

   while (utf8_len != 0)
     {
	if (is_second_byte)
	  {
	     if ( *ib < valid_min_2nd_byte[first_byte] || *ib > valid_max_2nd_byte[first_byte] )
	        return 0;
	     is_second_byte = 0;
	  }
	else if ((*ib & 0xc0) != 0x80) /* 0x80 -- 0xbf */
		return 0;

        --utf8_len;
	++ib;
     }

   convert_utf8_to_ucs4(str, len, &unicode);
   if (unicode == 0xFFFE || unicode == 0xFFFF) return 0;

   return 1;
}
