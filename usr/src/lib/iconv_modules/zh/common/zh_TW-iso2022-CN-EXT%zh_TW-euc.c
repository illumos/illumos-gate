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
 * Copyright (c) 1997, by Sun Microsystems, Inc.
 * All rights reserved.
 */


/*
   Converts From:	ISO2022-CN-EXT encoding.
   Converts To:		Taiwanese EUC encoding ( CNS11643 )
 */

#include "iso2022-cn.h"
#include "gb2312_cns11643.h"


/* Forward reference the functions constrained to the scope of this file */
static int chinese_to_euc( _iconv_st*, unsigned char**, size_t*, int);
static int gb_to_euc( _iconv_st *st, unsigned char **outbuf, size_t *outbytesleft);


extern int errno;


size_t
_icv_iconv(_iconv_st *st, char **inbuf, size_t *inbytesleft,
				char **outbuf, size_t *outbytesleft)
{
	return iso2022_icv_iconv(st, inbuf, inbytesleft, (unsigned char**) outbuf, outbytesleft,
			chinese_to_euc);
}


static int
chinese_to_euc( _iconv_st *st, unsigned char **outbuf, size_t *outbytesleft, int plane_no )
{

	if ( st->SSfunc == NULL && st->SOcharset == 'A') {	/* GB2312 */
	    return gb_to_euc(st, outbuf, outbytesleft);
	}

	if ( plane_no < 0 )/* Not a CNS character */
	    return (1);

	if ( plane_no >= 2) {
	    if ( *outbytesleft < 4 ){
		    st->_errno = errno = E2BIG;
		    return (-1);
	    }
	    /* Output the multi-byte code and plane number */
	    *(*outbuf)++ = (unsigned char) MBYTE;
	    *(*outbuf)++ = (unsigned char) (PMASK + plane_no);
	    (*outbytesleft) -= 2;
	}

	if ( *outbytesleft < 2 ){ /* Redundant test if SS2 or SS3 character */
	    st->_errno = errno = E2BIG;
	    return (-1);
	}

	*(*outbuf)++ = (unsigned char) (st->keepc[0] | MSB);
	*(*outbuf)++ = (unsigned char) (st->keepc[1] | MSB);
	(*outbytesleft) -= 2;

	return (0);
}

static int make_cns(_iconv_st *st, unsigned long cnscode, unsigned char **outbuf, size_t *outbytesleft)
{
	int plane_no, ret;	/* return buffer size */

	ret = (int) (cnscode >> 16);
	switch (ret) {
	case 0x21:	/* 0x8EA1 - G */
	case 0x22:	/* 0x8EA2 - H */
	case 0x23:	/* 0x8EA3 - I */
	case 0x24:	/* 0x8EA4 - J */
	case 0x25:	/* 0x8EA5 - K */
	case 0x26:	/* 0x8EA6 - L */
	case 0x27:	/* 0x8EA7 - M */
	case 0x28:	/* 0x8EA8 - N */
	case 0x29:	/* 0x8EA9 - O */
	case 0x2a:	/* 0x8EAA - P */
	case 0x2b:	/* 0x8EAB - Q */
	case 0x2c:	/* 0x8EAC - R */
	case 0x2d:	/* 0x8EAD - S */
	case 0x2f:	/* 0x8EAF - U */
	case 0x30:	/* 0x8EB0 - V */
	    plane_no =  ret - 0x20;
	    break;
	case 0x2e:	/* 0x8EAE - T */
	    plane_no = 3;		/* CNS 11643-1992 */
	    break;
	default:
	    st->_errno = errno = EILSEQ;
	    return (0);
	}

	if ( plane_no >= 2) {
	    if ( *outbytesleft < 4 ){
		st->_errno = errno = E2BIG;
		return (-1);
	    }
	    /* Output the multi-byte code and plane number */
	    *(*outbuf)++ = (unsigned char) MBYTE;
	    *(*outbuf)++ = (unsigned char) (PMASK + plane_no);
	    (*outbytesleft) -= 2;
	}

	if ( *outbytesleft < 2 ){ /* Redundant test if SS2 or SS3 character */
	    st->_errno = errno = E2BIG;
	    return (-1);
	}

	*(*outbuf)++ = (unsigned char) (((cnscode >> 8) & 0xff) | MSB);
	*(*outbuf)++ = (unsigned char) ((cnscode & 0xff) | MSB);
	(*outbytesleft) -= 2;

	return (0);
}

static int
gb_cns_comp(const void *p1, const void *p2)
{
    gb_cns *ptr1 = (gb_cns*) p1, *ptr2 = (gb_cns*) p2;
    long result = ptr1->gbcode - ptr2->gbcode;
    return result == 0 ? 0 : result > 0 ? 1 : -1;
}

static int
gb_to_euc( _iconv_st *st, unsigned char **outbuf, size_t *outbytesleft )
{
	gb_cns *ptr, key;

	key.gbcode = (unsigned long) ((st->keepc[0] | MSB) << 8) + (st->keepc[1] | MSB);
	ptr = (gb_cns*) bsearch(&key, gb_cns_tab, BIG5MAX, sizeof(gb_cns), gb_cns_comp);

	if ( ptr && ptr->cnscode > 0 )
	    return make_cns(st, ptr->cnscode, outbuf, outbytesleft);
	else
	    return (1);
}
