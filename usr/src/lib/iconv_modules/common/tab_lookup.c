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

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>

#include "tab_lookup.h"   	/* table lookup data types */

int bisearch(unsigned long val, _icv_state *st, int n);

/*
 * Actual conversion; called from iconv().
 * Peforms conversion as per the parameters specified in
 * structure st.
 */
size_t
_icv_iconv_lu(_icv_state *st, unsigned char **ibuf, size_t *inbytesleft,
                              unsigned char **obuf, size_t *outbytesleft)
{
        int     	  idx, data_size;
	unsigned  long 	  search_val = 0, match_val;
	unsigned  char 	  **inbuf, **outbuf;

        inbuf  = (unsigned char **)ibuf;
        outbuf = (unsigned char **)obuf;

        if (st == NULL) {
                errno = EBADF;
                return ((size_t)-1);
        }

        if (inbuf == NULL || *inbuf == NULL) { /* Reset request */

	    return 0;
        }

        errno = 0;


        while (*inbytesleft > 0 && *outbytesleft > 0) {
	    fprintf(stderr, "INBL: %d , OUBL: %d \n",
		    *inbytesleft, *outbytesleft);
	    search_val = 0;

	    /*
	     * form a search member
	     * lookup character by character
	     */

	    if ( st->left_to_right ) {
	        /*
	         * create search val from the left code
	         */

	        data_size  = st->left_code_size;
	        while ( data_size > 0  ) {
		    search_val = ( search_val << 8 ) |  ( **inbuf );
		    data_size--;
	            (*inbuf)++;
	            (*inbytesleft)--;
	        }

	        idx = bisearch(search_val, st, st->table_size);
#ifdef TEST
		fprintf(stderr, "Match idx: %d \n", idx);
#endif

	        if ( idx >= 0 ) {
		    /*
		     * create matched code from the right column
		     */
		    match_val = st->table[idx].right_code;

	        } else {
		    match_val = NON_ID_CHAR;

	        }

	        /*
	         * Check sufficient space in the outbuf
	         */
	        if ( *outbytesleft >= st->right_code_size ) {

                    data_size  = st->right_code_size;
	            while ( data_size > 0 ) {
		        *(*outbuf + data_size-- - 1 ) =
			    (unsigned char) (match_val & 0xff);
#ifdef TEST
		        fprintf(stderr, "outbyte: %x \n",
			       (unsigned char) (match_val & 0xff));
#endif
		        match_val >>= 8;
	            }
	            (*outbuf) += st->right_code_size;
	            (*outbytesleft) -= st->right_code_size;

	        } else {
	            /* no space for outbytes */
	            errno = E2BIG;
		    return ((size_t)-1);
	        }
	    } else {
	        /* search from right to left */
	        /*
	         * create search val from the left code
	         */

	        data_size  = st->right_code_size;
	        while ( data_size > 0  ) {
		    search_val = ( search_val << 8 ) |  ( **inbuf );
		    data_size--;
	            (*inbuf)++;
	            (*inbytesleft)--;
	        }

	        idx = bisearch(search_val, st, st->table_size);

#ifdef TEST
		fprintf(stderr, "Match idx: %d \n", idx);
#endif

	        if ( idx >= 0 ) {
		    /*
		     * create matched code from the right column
		     */
		    match_val = st->table[idx].left_code;

	        } else {
		    match_val = UCS2_NON_ID_CHAR;

	        }

	        /*
	         * Check sufficient space in the outbuf
	         */
	        if ( *outbytesleft >= st->left_code_size ) {

                    data_size  = st->left_code_size;
	            while ( data_size > 0 ) {
		        *(*outbuf + data_size-- - 1 ) =
			    (unsigned char) (match_val & 0xff);
#ifdef TEST
		        fprintf(stderr, "outbyte: %x \n",
			       (unsigned char) (match_val & 0xff));
#endif
		        match_val >>= 8;
	            }
	            (*outbuf) += st->left_code_size;
	            (*outbytesleft) -= st->left_code_size;

	        } else {
	            /* no space for outbytes */
	            errno = E2BIG;
		    return ((size_t)-1);
	        }

	    }
#ifdef TEST
	    fprintf(stderr, "Search: %x  match: %x \n", search_val, match_val);
#endif

    }/* (*inbytesleft) && (*outbytesleft) */

    if ( *inbytesleft && (!(*outbytesleft)) ) {
	errno = E2BIG;
	return ((size_t)-1);
    }

    return (*inbytesleft);
}


/*
 * Performs the binary search in the lookup table of structure
 * st. Memebers (left_to_right, right_to_left)  control
 * the lookup direction.
 */
int bisearch(unsigned long val, _icv_state *st, int n)
{
    int low, high, mid;

#ifdef TEST
	    fprintf(stderr, "Search: %x limit: %d  \n", val, n);
#endif

    low = 0;
    high = n - 1;
    while ( low <= high ) {
	mid = (low + high) / 2;
	if ( st->left_to_right ) {
	    if ( val < st->table[mid].left_code )
		high = mid - 1;
	     else if ( val > st->table[mid].left_code )
		      low = mid + 1;
	     else /* found match */
		return mid;
	} else {
	    if ( val < st->table[mid].right_code )
		high = mid - 1;
	     else if ( val > st->table[mid].right_code )
		      low = mid + 1;
	     else /* found match */
		return mid;
        }

    }

    return (-1);
}
