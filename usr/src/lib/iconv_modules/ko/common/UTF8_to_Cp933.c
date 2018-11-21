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
 *
 * $Id: UTF8_to_Cp933.c,v 1.4 2004/03/21 23:14:51 fzhang Exp $ SMI
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>

#include "tab_lookup.h"   	/* table lookup data types */
#include "ucs2_cp933.h"   	/* Unicode to CP933 mapping table */


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

        st->left_to_right = B_TRUE;
        st->right_to_left = B_FALSE;
        st->left_code_size = 2; /* byte */
        st->right_code_size = 2; /* byte */
        st->table = &ucs2_cp933_tab[0];
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


#ifdef TEST

/* test case 1 */
/*
char ibuf1[] = {0x0e, 0x57, 0x6c, 0x0f, 0x0e, 0x55, 0x67, 0x0f, 0x0e, 0x5a, 0x62, 0x57};
char obuf1[20];
*/

unsigned char ibuf1[] = {0x5f, 0x63, 0xd3, 0x69, 0x5f, 0x75, 0x63, 0x73, 0x32, 0x75, 0x74, 0x66};
unsigned char obuf1[38];

main()
{
        int i;
        struct _icv_state *st;
        size_t oleft, ileft;
        unsigned char *ip1 = &ibuf1[0], *op1 = &obuf1[0];

        /****************************** test case 1 *************************/

        ileft = sizeof(ibuf1);
        oleft = sizeof(obuf1);

        st = (_icv_state *)_icv_open();

        printf("TEST 1\n INPUT BUFFER: ");
        for (i = 0; i < ileft ; i++) {
            printf("%x ", 0xff&ibuf1[i]);
        }
        printf("\n");
        printf("OUTPUT: return value \n");
        printf("OUTPUT: return value %d errno: %d ",
                _icv_iconv(st, (char **)&ip1, &ileft, (char **)&op1, &oleft),
	        errno);

        printf("OUTPUT BUFFER: ");
        for (i = 0; i < (sizeof(obuf1) - oleft) ; i++) {
            printf("%x ", 0xff&obuf1[i]);
        }
        printf("\n\n\n");
        _icv_close(st);

}

#endif /* TEST */
