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
 * Copyright (c) 1995 by Sun Microsystems, Inc.
 * All Rights Reserved.
 */


#include <stdio.h>
#include <libintl.h>
#include <stdlib.h>
#include <errno.h>
#include "ktable.h"
#include "hangulcode.h"

#define MSB 0x80
#define	MSB_OFF	0x7f

struct _cv_state {
	int _st_status;
	int _gstate;
};

enum _GSTATE { _nostate, _g0, _g1};

enum SHIFT_STAT {SHIFT_IN, SHIFT_OUT};


typedef struct __conv_desc {
	char			designated;
	enum { ASCII, WANSUNG }	state;
} _conv_desc;


/****  _ I C V _ O P E N  ****/

void* _icv_open()
{
	_conv_desc* cd = (_conv_desc*)malloc(sizeof(_conv_desc));

	if (cd == (_conv_desc*)NULL)
	{
		errno = ENOMEM;
		return((void*)-1);
	}

	cd->designated = 0;
	cd->state = ASCII;

	return((void*)cd);
}  /* end of int _icv_open(). */


/****  _ I C V _ C L O S E  ****/

void _icv_close(_conv_desc* cd)
{
	if (!cd)
		errno = EBADF;
	else
		free((void*)cd);
}  /* end of void _icv_close(_conv_desc*). */


/****  _ I C V _ I C O N V  ****/

size_t _icv_iconv(_conv_desc* cd, char** inbuf, size_t* inbufleft,
			char** outbuf, size_t* outbufleft)
{
	size_t		ret_val = 0;
	unsigned char*	ib;
	unsigned char*	ob;
	unsigned char*	ibtail;
	unsigned char*	obtail;

	if (!cd)
	{
		errno = EBADF;
		return((size_t)-1);
	}

	if (!inbuf || !(*inbuf))
	{
		if (cd->state == WANSUNG)
		{
			if (outbufleft && *outbufleft >= 1 && outbuf && *outbuf)
			{
				**outbuf = SI;
				(*outbuf)++;
				(*outbufleft)--;
			}
			else
			{
				errno = E2BIG;
				return((size_t)-1);
			}
		}

		cd->designated = 0;
		cd->state = ASCII;
		return((size_t)0);
	}

	ib = (unsigned char*)*inbuf;
	ob = (unsigned char*)*outbuf;
	ibtail = ib + *inbufleft;
	obtail = ob + *outbufleft;

	while (ib < ibtail)
	{
		if (!(*ib & 0x80))		/* 7 bits */
		{
			if (cd->state == WANSUNG)
			{
				if (ob >= obtail)
				{
					errno = E2BIG;
					ret_val = (size_t)-1;
					break;
				}
				*ob++ = SI;
				cd->state = ASCII;
			}
			if (ob >= obtail)
			{
				errno = E2BIG;
				ret_val = (size_t)-1;
				break;
			}
			*ob++ = *ib++;
		}
		else
		{
			if ((ibtail - ib) < 2)
			{
				errno = EINVAL;
				ret_val = (size_t)-1;
				break;
			}

			if (!cd->designated)
			{
				if ((obtail - ob) < 4)
				{
					errno = E2BIG;
					ret_val = (size_t)-1;
					break;
				}
				*ob++ = ESC;  *ob++ = '$';
				*ob++ = ')'; *ob++ = 'C';
				cd->designated = 1;
			}
			if (cd->state == ASCII)
			{
				if (ob >= obtail)
				{
					errno = E2BIG;
					ret_val = (size_t)-1;
					break;
				}
				*ob++ = SO;
				cd->state = WANSUNG;
			}

			if ((obtail - ob) < 2)
			{
				errno = E2BIG;
				ret_val = (size_t)-1;
				break;
			}
			*ob++ = *ib++ & 0x7F;
			*ob++ = *ib++ & 0x7F;
		}
	}

	*inbuf = (char*)ib;
	*inbufleft = ibtail - ib;
	*outbuf = (char*)ob;
	*outbufleft = obtail - ob;

	return(ret_val);
}  /* end of size_t _icv_iconv(_conv_desc*, char**, size_t*, char**, size_t*).*/

void *
_cv_open()
{
	struct _cv_state *st;

	if ((st = (struct _cv_state *)malloc(sizeof(struct _cv_state))) == NULL)
		return ((void *)-1);

	st->_st_status = SHIFT_IN;
	st->_gstate = _nostate;

	return (st);
}

void
_cv_close(struct _cv_state *st)
{
	free(st);
}


size_t
_cv_enconv(struct _cv_state *st, char **inbuf, size_t*inbytesleft,
				char **outbuf, size_t*outbytesleft)
{
	if (inbuf == NULL || *inbuf == NULL) { /* Reset request. */
		if (st->_st_status == SHIFT_OUT && *outbytesleft > 0)
		{
		    **outbuf = SI;
		    (*outbytesleft)--;
		    (*outbuf)++;
		}
		st->_st_status = SHIFT_IN;
		st->_gstate = _nostate;
		/*
		 * Note that no shift sequence is needed for
		 * thetarget encoding.
		 */
		return (0);
	}

	if ( st->_gstate == _nostate )
		st->_gstate = _g0;

	while (*inbytesleft > 0 && *outbytesleft > 0) {
	    if ( **inbuf & MSB ) {
		if (st->_st_status == SHIFT_IN ) {
		    if ( st->_gstate == _g0 ) {
			/*
			 * Check the outbytesleft : enough to hold ESC sequence
			 */
			if ( *outbytesleft < 4 ) {
			    break;
			}

			st->_gstate = _g1;

			**outbuf = ESC;
			(*outbuf)++, (*outbytesleft)--;
			**outbuf = '$';
			(*outbuf)++, (*outbytesleft)--;
			**outbuf = ')';
			(*outbuf)++, (*outbytesleft)--;
			**outbuf = 'C';
			(*outbuf)++, (*outbytesleft)--;

			if ( *outbytesleft <= 0 )
			    break;
		    }

		    st->_st_status = SHIFT_OUT;
		    **outbuf = SO;
		    (*outbuf)++, (*outbytesleft)--;

		    if ( *outbytesleft <= 0 )
			break;
		}

		**outbuf = **inbuf & MSB_OFF;
		(*outbuf)++, (*outbytesleft)--;

	    } else {
		if (st->_st_status == SHIFT_OUT) {
		    st->_st_status = SHIFT_IN;
		    **outbuf = SI;
		    (*outbuf)++, (*outbytesleft)--;

		    if ( *outbytesleft <= 0 )
			break;
		}

		**outbuf = **inbuf;
               (*outbuf)++, (*outbytesleft)--;

	    }

	    (*inbuf)++, (*inbytesleft)--;
	}
	return (*inbytesleft);
}
