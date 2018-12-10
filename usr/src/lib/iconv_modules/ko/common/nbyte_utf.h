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
 * Copyright (c) 1994 by Sun Microsystems, Inc.
 */



#ifndef _NBYTE2UTF_H_
#define _NBYTE2UTF_H_


#include "hangulcode.h"

typedef struct __conv_desc {
	int	cur_stat;
	int	cur_act;
	char	hbuf[5];
} _conv_desc;

int next_stat[14][21]={	/* next state table[current state][input] */
	/* input
	  0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15 16 17 18 19 20 */
/*state*/
/* 0 */ { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
/* 1 */ { 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 1, 1},
/* 2 */ { 0, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 3, 3, 3, 3, 3, 3, 3, 2, 1, 2},
/* 3 */ { 0, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 3, 3, 3, 3, 3, 3, 3, 2, 1, 2},
/* 4 */ { 0, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 8, 8, 8, 8, 5, 6, 7, 2, 1, 2},
/* 5 */ { 0, 4, 9,10,11,12,13,13,13,13,13, 3, 8, 3, 8, 3, 3, 3, 2, 1, 2},
/* 6 */ { 0, 4, 9,10,11,12,13,13,13,13,13, 3, 3, 8, 8, 3, 3, 3, 2, 1, 2},
/* 7 */ { 0, 4, 9,10,11,12,13,13,13,13,13, 3, 3, 3, 8, 3, 3, 3, 2, 1, 2},
/* 8 */ { 0, 4, 9,10,11,12,13,13,13,13,13, 3, 3, 3, 3, 3, 3, 3, 2, 1, 2},
/* 9 */ { 0, 4, 4, 4, 4, 4, 4,13, 4, 4, 4, 8, 8, 8, 8, 5, 6, 7, 2, 1, 2},
/*10 */ { 0, 4, 4, 4, 4, 4, 4, 4,13,13, 4, 8, 8, 8, 8, 5, 6, 7, 2, 1, 2},
/*11 */ { 0, 4,13, 4, 4,13, 4,13, 4,13,13, 8, 8, 8, 8, 5, 6, 7, 2, 1, 2},
/*12 */ { 0, 4, 4, 4, 4, 4, 4,13, 4, 4, 4, 8, 8, 8, 8, 5, 6, 7, 2, 1, 2},
/*13 */ { 0, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 8, 8, 8, 8, 5, 6, 7, 2, 1, 2}
};

int next_act[14][21]={	/* next action table[current state][input]  */
	/*input
	  0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15 16 17 18 19 20 */
/*state*/
/* 0 */ { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
/* 1 */ { 0, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 2, 4, 4},
/* 2 */ { 0, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,15,15,15,15,15,15,15, 1, 3, 4},
/* 3 */ { 0, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,15,15,15,15,15,15,15, 1, 3, 4},
/* 4 */ { 0, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 6, 6, 6, 6, 6, 6, 6,16,12,13},
/* 5 */ { 0, 9, 7, 7, 7, 7, 7, 7, 7, 7, 7,10,14,10,14,10,10,10,16,12,13},
/* 6 */ { 0, 9, 7, 7, 7, 7, 7, 7, 7, 7, 7,10,10,14,14,10,10,10,16,12,13},
/* 7 */ { 0, 9, 7, 7, 7, 7, 7, 7, 7, 7, 7,10,10,10,14,10,10,10,16,12,13},
/* 8 */ { 0, 9, 7, 7, 7, 7, 7, 7, 7, 7, 7,10,10,10,10,10,10,10,16,12,13},
/* 9 */ { 0, 9, 9, 9, 9, 9, 9, 8, 9, 9, 9,17,17,17,17,17,17,17,16,12,13},
/*10 */ { 0, 9, 9, 9, 9, 9, 9, 9, 8, 8, 9,17,17,17,17,17,17,17,16,12,13},
/*11 */ { 0, 9, 8, 9, 9, 8, 9, 8, 9, 8, 8,17,17,17,17,17,17,17,16,12,13},
/*12 */ { 0, 9, 9, 9, 9, 9, 9, 8, 9, 9, 9,17,17,17,17,17,17,17,16,12,13},
/*13 */ { 0, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,17,17,17,17,17,17,17,16,12,13}
};

#define	ADD_CONVERTED_CODE(K, ADD)\
	{\
		char	temp[5];\
		\
		temp[1] = cd->hbuf[1];\
		temp[2] = cd->hbuf[2];\
		temp[3] = cd->hbuf[3];\
		temp[4] = cd->hbuf[4];\
		if ((result = _johap_to_utf8(&ci, &v, &cf,\
				make_johap_code((K), temp))) == HANGUL)\
		{\
			if ((obtail - ob) < ((cf ? 9 : 6) + (ADD)))\
			{\
				errno = E2BIG;\
				ret_val = (size_t)-1;\
				break;\
			}\
			cd->hbuf[1] = temp[1];\
			cd->hbuf[2] = temp[2];\
			cd->hbuf[3] = temp[3];\
			cd->hbuf[4] = temp[4];\
			*ob++ = (char)((ci >> 16) & 0xFF);\
			*ob++ = (char)((ci >> 8) & 0xFF);\
			*ob++ = (char)(ci & 0xFF);\
			*ob++ = (char)((v >> 16) & 0xFF);\
			*ob++ = (char)((v >> 8) & 0xFF);\
			*ob++ = (char)(v & 0xFF);\
			if (cf)\
			{\
				*ob++ = (char)((cf >> 16) & 0xFF);\
				*ob++ = (char)((cf >> 8) & 0xFF);\
				*ob++ = (char)(cf & 0xFF);\
			}\
		}\
		else if (result == FAILED)\
		{\
			if ((obtail - ob) < 3)\
			{\
				errno = E2BIG;\
				ret_val = (size_t)-1;\
				break;\
			}\
			*ob++ = UTF8_NON_ID_CHAR1;\
			*ob++ = UTF8_NON_ID_CHAR2;\
			*ob++ = UTF8_NON_ID_CHAR3;\
			ret_val += 3;\
		}\
		else  /* result == ILLEGAL_SEQ */\
		{\
			errno = EILSEQ;\
			ret_val = (size_t)-1;\
			break;\
		}\
	}


#endif	/* _NBYTE2UTF_H_ */
