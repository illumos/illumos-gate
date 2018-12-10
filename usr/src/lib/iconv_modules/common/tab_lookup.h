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



typedef struct	_lookup_table {
    unsigned long		left_code;
    unsigned long		right_code;
} lookup_table;

typedef enum { SHIFT_OUT=0x0e, SHIFT_IN } SHIFT;

typedef struct _icv_state {
    boolean_t	left_to_right;		/* if true the search input characters
					 * in the left column
					 */
    boolean_t	right_to_left;		/*
					 * if true then search input characters
					 *  in the right column
					 */
    lookup_table	*table;		/* mapping table */
    int		table_size;		/* no of lookup records */
    int		left_code_size;		/* data size of the left code */
    int		right_code_size;	/* data size of the right code */

    char        keepc[6];       /* maximum # byte of UTF8 code */
    short       ustate;
    SHIFT	shift;
    int         _errno;         /* internal errno */

} _icv_state;


extern	int	errno;	/* external errno */

#define		UCS2_NON_ID_CHAR		0xFFFD
#define		NON_ID_CHAR			0x3F3F /* '??' */


extern
size_t
_icv_iconv_lu(_icv_state *st, unsigned char **ibuf, size_t *inbytesleft,
                              unsigned char **obuf, size_t *outbytesleft);
