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
   Converts To:		Taiwanese BIG5 encoding
 */

#include "iso2022-cn.h"
#include "cns11643_big5.h"
#include "gb2312_big5_TW.h"

/* Forward reference the functions constrained to the scope of this file */
static int chinese_to_big5( _iconv_st *, unsigned char **, size_t *, int);
static int gb_to_big5( _iconv_st*, unsigned char**, size_t* );

extern int errno;

size_t
_icv_iconv(_iconv_st *st, char **inbuf, size_t *inbytesleft,
				char **outbuf, size_t *outbytesleft)
{
	return iso2022_icv_iconv(st, inbuf, inbytesleft, (unsigned char**) outbuf, outbytesleft,
			chinese_to_big5);
}

static int
cns_big5_comp(const void *p1, const void *p2)
{
    table_t *ptr1 = (table_t*) p1, *ptr2 = (table_t*) p2;
    long result = ptr1->key - ptr2->key;
    return result == 0 ? 0 : result > 0 ? 1 : -1;
}

static int
chinese_to_big5( _iconv_st *st, unsigned char **outbuf, size_t *outbytesleft, int plane_no )
{

	table_t key, *ptr;
	if ( st->SSfunc == NULL && st->SOcharset == 'A') {	/* GB2312 */
	    return gb_to_big5(st, outbuf, outbytesleft);
	}

	if ( plane_no < 0 || plane_no > 2 )/* Not a big5 */
	    return (1);

	key.key = (unsigned long) ((st->keepc[0] & 0xff) << 8) + (st->keepc[1] & 0xff);
	if (plane_no == 1)
	    ptr = (table_t*) bsearch(&key, cns_big5_tab1, MAX_CNS1_NUM, sizeof(table_t), cns_big5_comp);
	else
	    ptr = (table_t*) bsearch(&key, cns_big5_tab2, MAX_CNS2_NUM, sizeof(table_t), cns_big5_comp);

	if ( ptr == 0 || ptr->value == 0 )
	    return (1); /* No BIG5 code for this CNS code */

	if ( *outbytesleft < 2 ){
	    st->_errno = errno = E2BIG;
	    return (-1);
	}
	*(*outbuf)++ = (unsigned char) ((ptr->value >> 8) & 0xff);
	*(*outbuf)++ = (unsigned char) (ptr->value & 0xff);
	(*outbytesleft) -= 2;

	return (0);
}


static int
gb_big5_comp(const void *p1, const void *p2)
{
    gb_big5 *ptr1 = (gb_big5*) p1, *ptr2 = (gb_big5*) p2;
    long result = ptr1->gbcode - ptr2->gbcode;
    return result == 0 ? 0 : result > 0 ? 1 : -1;
}

static int
gb_to_big5( _iconv_st *st, unsigned char **outbuf, size_t *outbytesleft )
{
	gb_big5 *ptr, key;

	key.gbcode = (unsigned long) ((st->keepc[0] | MSB) << 8) + (st->keepc[1] | MSB);
	ptr = (gb_big5*) bsearch(&key, gb_big5_tab, BIG5MAX, sizeof(gb_big5), gb_big5_comp);

	if ( ptr && ptr->big5code > 0 ) {
	    if ( *outbytesleft < 2 ){
		st->_errno = errno = E2BIG;
		return (-1);
	    }
	    *(*outbuf)++ = (unsigned char) ((ptr->big5code >> 8) & 0xff);
	    *(*outbuf)++ = (unsigned char) (ptr->big5code & 0xff);
	    (*outbytesleft) -= 2;

	    return (0);
	}
	else
	    return (1); /* No BIG5 code for this CNS code */
}
