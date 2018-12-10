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
 * Copyright (c) 1998-1999, 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 *
 * Following is how we process BOM and subsequent bytes in this program:
 * - UCS-2BE, UTF-16BE, UCS-4BE, UTF-32BE, UCS-2LE, UTF-16LE, UCS-4LE, and
 *   UTF-32LE don't care about BOM. From the beginning, they are properly
 *   serializedi without the BOM character.
 * - In other encodings, UCS-2, UCS-4, UTF-16, and UTF-32, the initial byte
 *   ordering is of the current processor's byte ordering. During the first
 *   iconv() call, if BOM appears as the first character of the entier
 *   iconv input stream, the byte order will be changed accordingly.
 *   We will use 'bom_written' data field of the conversion descriptor to
 *   save this particular information, in other words, whether we've been
 *   encountered the first character as the BOM.
 */


#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/isa_defs.h>
#include "ucs_to_unihan.h"
#include "common_def.h"
#include "common_han.h"

typedef struct {
  int         _magic;
  boolean     _need_byte_swap;
  boolean     _bom_written;
  boolean     _is_little_endian;

} _icv_state_t;

static hcode_type ucs_to_unihan (uint_t ucs_char);
extern hcode_type _utf8_to_unified_hangul (hcode_type);

void *
_icv_open()
{
  _icv_state_t *cd = (_icv_state_t *)calloc(1, sizeof(_icv_state_t));

  if (cd == (_icv_state_t *)NULL) {
    errno = ENOMEM;
    return((void *)-1);
  }

  cd->_magic = MAGIC_NUMBER;

#if defined(UTF_16BE) || defined(UCS_2BE) || defined(UCS_4BE) || \
	defined(UTF_32BE)
  cd->_is_little_endian = false;
  cd->_bom_written = true;
#elif defined(UTF_16LE) || defined(UCS_2LE) || defined(UCS_4LE) || \
	defined(UTF_32LE)
  cd->_is_little_endian = true;
  cd->_bom_written = true;
#elif defined(__IS_LITTLE_ENDIAN)
  cd->_is_little_endian = true;
#endif

  cd->_need_byte_swap = false;

  return((void *)cd);
}


void
_icv_close(_icv_state_t *cd)
{
  if (! cd)
    errno = EBADF;
  else
    free((void *)cd);
}


size_t
_icv_iconv(_icv_state_t *cd, char **inbuf, size_t *inbufleft, char **outbuf,
	   size_t *outbufleft)
{
  size_t ret_val = 0;
  uchar_t *ib;
  uchar_t *ob;
  uchar_t *ibtail;
  uchar_t *obtail;
  uint_t u4;
  uint_t u4_2;
  register int i;

  hcode_type unihan;
  unihan.code = 0x00;

  if (! cd) {
    errno = EBADF;
    return((size_t)-1);
  }

  if (!inbuf || !(*inbuf))
    return((size_t)0);

  ib = (uchar_t *)*inbuf;
  ob = (uchar_t *)*outbuf;
  ibtail = ib + *inbufleft;
  obtail = ob + *outbufleft;

#if defined(UCS_2) || defined(UCS_4) || defined(UTF_16) || defined(UTF_32)
  if (! cd->_bom_written) {
    if ((ibtail - ib) < ICV_FETCH_UCS_SIZE) {
      errno = EINVAL;
      ret_val = (size_t)-1;
      goto need_more_input_err;
    }

    for (u4 = 0, i = 0; i < ICV_FETCH_UCS_SIZE; i++)
      u4 = (u4 << 8) | ((uint_t)(*(ib + i)));

    /* Big endian, Little endian, or, not specified?? */
    if (u4 == ICV_BOM_IN_BIG_ENDIAN) {
      ib += ICV_FETCH_UCS_SIZE;
      cd->_is_little_endian = false;
    } else if (u4 == ICV_BOM_IN__IS_LITTLE_ENDIAN) {
      ib += ICV_FETCH_UCS_SIZE;
      cd->_is_little_endian = true;
    }
  }
  /*
   * Once BOM checking is done, regardless of whether we had the BOM or
   * not, we treat the BOM sequence as a ZWNBSP character from now on.
   */
  cd->_bom_written = true;
#endif

  while (ib < ibtail) {
    if ((ibtail - ib) < ICV_FETCH_UCS_SIZE) {
      errno = EINVAL;
      ret_val = (size_t)-1;
      break;
    }

    u4 = u4_2 = 0;
    if (cd->_is_little_endian) {
      for (i = ICV_FETCH_UCS_SIZE - 1; i >= 0; i--)
	u4 = (u4 << 8) | ((uint_t)(*(ib + i)));
    } else {
      for (i = 0; i < ICV_FETCH_UCS_SIZE; i++)
	u4 = (u4 << 8) | ((uint_t)(*(ib + i)));
    }

#if defined(UCS_2) || defined(UCS_2BE) || defined(UCS_2LE)
    if (u4 >= 0x00fffe || (u4 >= 0x00d800 && u4 <= 0x00dfff)) {
      errno = EILSEQ;
      ret_val = (size_t)-1;
      break;
    }
#elif defined(UTF_16) || defined(UTF_16BE) || defined(UTF_16LE)
    if ((u4 >= 0x00dc00 && u4 <= 0x00dfff) || u4 >= 0x00fffe) {
      errno = EILSEQ;
      ret_val = (size_t)-1;
      break;
    }

    if (u4 >= 0x00d800 && u4 <= 0x00dbff) {
      if ((ibtail - ib) < ICV_FETCH_UCS_SIZE_TWO) {
	errno = EINVAL;
	ret_val = (size_t)-1;
	break;
      }

      if (cd->_is_little_endian) {
	for (i = ICV_FETCH_UCS_SIZE_TWO - 1;
	     i >= ICV_FETCH_UCS_SIZE;
	     i--)
	  u4_2 = (u4_2<<8)|((uint_t)(*(ib + i)));
      } else {
	for (i = ICV_FETCH_UCS_SIZE;
	     i < ICV_FETCH_UCS_SIZE_TWO;
	     i++)
	  u4_2 = (u4_2<<8)|((uint_t)(*(ib + i)));
      }

      if (u4_2 < 0x00dc00 || u4_2 > 0x00dfff) {
	errno = EILSEQ;
	ret_val = (size_t)-1;
	break;
      }

      u4 = ((((u4 - 0x00d800) * 0x400) +
	     (u4_2 - 0x00dc00)) & 0x0fffff) + 0x010000;
    }
#elif defined(UTF_32) || defined(UTF_32BE) || defined(UTF_32LE)
    if (u4 == 0x00fffe || u4 == 0x00ffff || u4 > 0x10ffff ||
	(u4 >= 0x00d800 && u4 <= 0x00dfff)) {
      errno = EILSEQ;
      ret_val = (size_t)-1;
      break;
    }
#elif defined(UCS_4) || defined(UCS_4BE) || defined(UCS_4LE)
    if (u4 == 0x00fffe || u4 == 0x00ffff || u4 > 0x7fffffff ||
	(u4 >= 0x00d800 && u4 <= 0x00dfff)) {
      errno = EILSEQ;
      ret_val = (size_t)-1;
      break;
    }
#else
#error	"Fatal: one of the UCS macros need to be defined."
#endif

    /*
     * Once we reach here, the "u4" contains a valid character
     * and thus we don't do any other error checking in
     * the below.
     */

    unihan = ucs_to_unihan (u4);
    if(unihan.byte.byte1 == '\0' && unihan.byte.byte2 == '\0' && unihan.byte.byte3 == '\0')
    {
	*ob++ = unihan.byte.byte4;
	ib += ((u4_2) ? ICV_FETCH_UCS_SIZE_TWO : ICV_FETCH_UCS_SIZE);
	continue;
    }
    if (cd->_need_byte_swap){
      *ob++ = (uchar_t) unihan.byte.byte4;
      *ob++ = (uchar_t) unihan.byte.byte3;
    } else {
      *ob++ = (uchar_t) unihan.byte.byte3;
      *ob++ = (uchar_t) unihan.byte.byte4;
    }

    ib += ((u4_2) ? ICV_FETCH_UCS_SIZE_TWO : ICV_FETCH_UCS_SIZE);
  }

#if defined(UCS_2) || defined(UCS_4) || defined(UTF_16) || defined(UTF_32)
 need_more_input_err:
#endif
  *inbuf = (char *)ib;
  *inbufleft = ibtail - ib;
  *outbuf = (char *)ob;
  *outbufleft = obtail - ob;

  return(ret_val);
}

static hcode_type
ucs_to_unihan (uint_t ucs_char)
{
  hcode_type unihan_char;
  hcode_type utf8_char;
  unihan_char.code = 0x00;

  if (ucs_char <= 0x7f) {
    utf8_char.code = ucs_char;

  } else if (ucs_char <= 0x7ff) {
    utf8_char.byte.byte3 = (uchar_t)(0xc0 | ((ucs_char & 0x07c0) >> 6));
    utf8_char.byte.byte4 = (uchar_t)(0x80 |  (ucs_char & 0x003f));

  } else if (ucs_char <= 0x00ffff) {
    utf8_char.byte.byte2 = (uchar_t)(0xe0 | ((ucs_char & 0x0f000) >> 12));
    utf8_char.byte.byte3 = (uchar_t)(0x80 | ((ucs_char & 0x00fc0) >> 6));
    utf8_char.byte.byte4 = (uchar_t)(0x80 |  (ucs_char & 0x0003f));
  } else if (ucs_char <= 0x1fffff) {
    utf8_char.byte.byte1 = (uchar_t)(0xf0 | ((ucs_char & 0x01c0000) >> 18));
    utf8_char.byte.byte2 = (uchar_t)(0x80 | ((ucs_char & 0x003f000) >> 12));
    utf8_char.byte.byte3 = (uchar_t)(0x80 | ((ucs_char & 0x0000fc0) >> 6));
    utf8_char.byte.byte4 = (uchar_t)(0x80 |  (ucs_char & 0x000003f));
  } else
    utf8_char.code = 0x00;

  unihan_char = _utf8_to_unified_hangul (utf8_char);
  return unihan_char;
}
