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
    Header file for converting iso2022-CN-EXT to cns11643 and big5
*/

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#define MSB		0x80	/* Most significant bit */
#define MBYTE		0x8e	/* multi-byte (4 byte character) */
#define PMASK		0xa0	/* plane number mask */
#define ONEBYTE		0xff	/* The right most byte */

#define SI		0x0f	/* shift in */
#define SO		0x0e	/* shift out */
#define ESC		0x1b	/* escape */

#define SS2LOW		0x4e	/* SS2 escape sequence low byte */
#define SS3LOW		0x4f	/* SS3 escape sequence low byte */

#define NON_ID_CHAR	'_'		/* non-identified character */

typedef struct _icv_state {
	char	Sfunc;		/* Current shift function SI or SO. Also the current
				   state of the ISO state machine */
	short	SSfunc;		/* Current single shift function NONE, SS2, SS3 */
	short	ESCstate;	/* State of the ESC seq processing sub-machine. State
				   can be OFF, E0, E1, E2, E3, E4 */
	int	firstbyte;	/* False if waiting for second Chinese byte */
	char	keepc[2];	/* For the 2-byte Chinese character code */
	char	savbuf[4];	/* Save Esc seq here in the ESC seq processing
				   sub-machine. If illegal ESC seq and if
				   insufficient space to output it, these are processed
				   before any byte from the inbuf when _icv_iconv is
				   called again with more output space. In state SO an
				   illegal ESC sequence causes _icv_iconv()
				   to return with EILSEQ error. See processESCseq()
				   to know what is an illegal ESC sequence. */
	int	numsav;		/* The number of bytes saved in savbuf */
	char	SOcharset;	/* The current SO designation */
	char	SS2charset;	/* The current SS2 designation */
	char	SS3charset;	/* The current SS3 designation */
	size_t	nonidcount;	/* Keeps track of skipped input bytes in convertion */
	int	_errno;		/* Internal error number */
} _iconv_st;

enum	_ssfunc		{ NONE, SS2, SS3 };
enum	_escstate	{ OFF, E0, E1, E2, E3, E4 };
enum	_retProcESC 	{ NEEDMORE, DONE, INVALID };
enum	_truefalse	{ True, False };

void*	iso2022_icv_open();
void	iso2022_icv_close(_iconv_st*);
size_t	iso2022_icv_iconv(_iconv_st*, char**, size_t*, unsigned char**, size_t*, int (*)(_iconv_st*, unsigned char**, size_t*, int));
