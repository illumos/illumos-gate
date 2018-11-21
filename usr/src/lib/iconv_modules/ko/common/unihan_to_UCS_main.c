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
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 */


#include <errno.h>
#include <widec.h>
#include <stdlib.h>
#include <sys/isa_defs.h>
#include <sys/types.h>
#include "common_def.h"
#include "common_defs.h"
#include "common_han.h"
#include "uhang_utf_api.h"
#include "euc_utf_api.h"

typedef struct {
  int         _magic;
  boolean     _need_byte_swap;
} _icv_state_t;


extern hcode_type _unified_hangul_to_UCS2LE (hcode_type);

void *
_icv_open()
{
  _icv_state_t *h = (_icv_state_t *) malloc (sizeof (_icv_state_t));
  if (!h){
    errno = ENOMEM;
    return((void *)-1);
  }

  h->_magic = MAGIC_NUMBER;
#if defined(UCS_2BE)
  h->_need_byte_swap =false;
#elif defined(UCS_2LE)
  h->_need_byte_swap = true;
#endif

  return (void *)h;
}


void
_icv_close (_icv_state_t *cd)
{
  if (!cd || ((_icv_state_t *)cd)->_magic  != MAGIC_NUMBER)
    errno = EBADF;
}



size_t
_icv_iconv (_icv_state_t *cd, char** inbuf, size_t* inbufleft,
	    char** outbuf, size_t* outbufleft)
{
  size_t		ret_val = 0;
  unsigned char*	ib;
  unsigned char*	ob;
  unsigned char*	ibtail;
  unsigned char*	obtail;

  if (!cd || ((_icv_state_t *)cd)->_magic  != MAGIC_NUMBER)
    {
      errno = EBADF;
      return((size_t)-1);
    }

  if (!inbuf || !(*inbuf))
    return((size_t)0);

  ib = (unsigned char*)*inbuf;
  ob = (unsigned char*)*outbuf;
  ibtail = ib + *inbufleft;
  obtail = ob + *outbufleft;

  while (ib < ibtail)
    {
      if (*ib & 0x80)  /* Korean EUC doesn't have CS2 or CS3. */
	{
	  hcode_type unihan_code, ucs2_code;
	  int flag;

	  flag = 0;

	  if ((ibtail - ib) < 2)
	    {
	      errno = EINVAL;
	      ret_val = (size_t)-1;
	      break;
	    }


	  if(*ib<0xA1)
	    {
	      if((*(ib+1)>0x40 && *(ib+1)<0x5B) || (*(ib+1)>0x60 && *(ib+1)<0x7B) || (*(ib+1)>0x80 && *(ib+1)<0xFF))
		flag = 0;
	      else
		flag = 1;

	    }
	  else
	    {
	      if(*ib<0xC7)
		{
		  if((*(ib+1)>0x40 && *(ib+1)<0x5B) || (*(ib+1)>0x60 && *(ib+1)<0x7B) || (*(ib+1)>0x80 && *(ib+1)<0xFF))
		    flag = 0;
		  else
		    flag = 1;
		}
	      else
		{
		  if(*(ib+1)>0xA0 && *(ib+1)<0xFF)
		    flag = 0;
		  else
		    flag = 1;
		}

	    }

	  if(flag)
	    {
	      errno = EILSEQ;
	      ret_val = (size_t)-1;
	      break;
	    }

	  unihan_code.code = 0;
	  unihan_code.byte.byte3 = *ib;
	  unihan_code.byte.byte4 = *(ib + 1);

	  ucs2_code = _unified_hangul_to_UCS2LE (unihan_code);

	  if (ucs2_code.code != 0)
	    {
	      if ((obtail - ob) < 3)
		{
		  errno = E2BIG;
		  ret_val = (size_t)-1;
		  break;
		}
#if !defined(UCS_2LE) && !defined(UCS_2BE)
	      if (!cd->_bom_written){
		*ob++ = (uchar_t)0xff;
		*ob++ = (uchar_t)0xfe;

		cd->_bom_written = true;
	      }
#endif    /* !defined(UCS_2LE) && !defined(UCS_2BE) */
	      if (cd->_need_byte_swap)
		{
		  *ob++ = ucs2_code.byte.byte4;
		  *ob++ = ucs2_code.byte.byte3;
		}
	      else
		{
		  *ob++ = ucs2_code.byte.byte3;
		  *ob++ = ucs2_code.byte.byte4;
		}
	    }
	  else  /* FAILED - this means input char doesn't belong to
		 *	  input codeset. */
	    {
	      errno = EILSEQ;
	      ret_val = (size_t)-1;
	      break;
	    }
	  ib += 2;

	}
      else  /* CS0 */
	{
#if !defined(UCS_2LE) && !defined(UCS_2BE)
	  if (!cd->_bom_written)
	    {
	    if ((obtail - ob) < 3)
	      {
		errno = E2BIG;
		ret_val = (size_t) -1;
		break;
	      }
	    *ob++ = (uchar_t)0xff;
	    *ob++ = (uchar_t)0xfe;
	    cd->_bom_written = true;
	    }
	  else
#endif    /* !defined(UCS_2LE) && !defined(UCS_2BE) */
	    {
	      if ((obtail - ob) < 1)
	      {
		errno = E2BIG;
		ret_val = (size_t) -1;
		break;
	      }
	    }

	  if (cd->_need_byte_swap)
	    {
	      *ob++ = *ib++;
	      *ob++ = 0x00;
	    }
	  else
	    {
	      *ob++ = 0x00;
	      *ob++ = *ib++;
	    }
	}
    }

  *inbuf = (char*)ib;
  *inbufleft = ibtail - ib;
  *outbuf = (char*)ob;
  *outbufleft = obtail - ob;

  return(ret_val);
}
