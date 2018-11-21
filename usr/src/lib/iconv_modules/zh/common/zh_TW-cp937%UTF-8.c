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
#include "cp937_unicode.h"   	/* Cp937 to Unicode mapping table */


/*
 * Open; called from iconv_open()
 */
void *
_icv_open()
{

        _icv_state *st;

        if ((st = (_icv_state *)malloc(sizeof(_icv_state))) == NULL) {
                errno = ENOMEM;
                return ((void *) -1);
        }

        st->left_to_right = B_FALSE;
        st->right_to_left = B_TRUE;
        st->left_code_size = 2; /* byte */
        st->right_code_size = 2; /* byte */
        st->table = &cp937_ucs2_tab[0];
        st->table_size =  MAX_UCS_NUM;
	st->shift = SHIFT_IN;

	st->ustate = 0;
	st->_errno = 0;
        return ((void *)st);
}


/*
 * Close; called from iconv_close()
 */
void
_icv_close(_icv_state *st)
{
        if (st == NULL)
                errno = EBADF;
        else
                free(st);
}
