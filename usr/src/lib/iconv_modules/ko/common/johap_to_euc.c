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
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include "kctype.h"
#include "kdefs.h"
#include <errno.h>
#include "ktable.h"
#include "hangulcode.h"


KCHAR c2p();

KCHAR packtocomp(KCHAR comb2);


struct _cv_state {
	char **my_outbuf;
	size_t *my_outbytesleft;
	int invalid;
	int flush_obuf;
	char temp_obuf[5];
	int start_cnt;
	int end_cnt;
	char temp_ibuf[1];
	int ibuf_left;
};

static unsigned short _johap_to_wansung(unsigned short code);

void AddChar (char Char, struct _cv_state *st);

/****  _ I C V _ O P E N  ****/

void* _icv_open()
{
	return((void*)MAGIC_NUMBER);
}  /* end of void* _icv_open(). */


/****  _ I C V _ C L O S E  ****/

void _icv_close(int* cd)
{
	if (!cd || cd != (int*)MAGIC_NUMBER)
		errno = EBADF;
}  /* end of void _icv_close(int*). */


/****  _ I C V _ I C O N V  ****/

size_t _icv_iconv(int* cd, char** inbuf, size_t* inbufleft,
			char** outbuf, size_t* outbufleft)
{
	size_t		ret_val = 0;
	unsigned char*	ib;
	unsigned char*	ob;
	unsigned char*	ibtail;
	unsigned char*	obtail;

	if (!cd || cd != (int*)MAGIC_NUMBER)
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
		if (!(*ib & 0x80))
		{
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
			unsigned short	result;

			if ((ibtail - ib) < 2)
			{
				errno = EINVAL;
				ret_val = (size_t)-1;
				break;
			}

			result = _johap_to_wansung((unsigned short)(*ib)<<8 |
					(unsigned short)(*(ib + 1)));
			if (result != FAILED && result != ILLEGAL_SEQ)
			{
				if ((obtail - ob) < 2)
				{
					errno = E2BIG;
					ret_val = (size_t)-1;
					break;
				}
				*ob++ = (unsigned char)(result >> 8);
				*ob++ = (unsigned char)(result & 0xFF);
			}
			else
			{
				errno = EILSEQ;
				ret_val = (size_t)-1;
				break;
			}
			ib += 2;

		}
	}

	*inbuf = (char*)ib;
	*inbufleft = ibtail - ib;
	*outbuf = (char*)ob;
	*outbufleft = obtail - ob;

	return(ret_val);
}  /* end of size_t _icv_iconv(int*, char**, size_t*, char**, size_t*). */


/**** _ J O H A P _ T O _ W A N S U N G ****/

static unsigned short _johap_to_wansung(unsigned short code)
{
	short	ci, v, cf;
	short	mask;
	int	disp, i;
	long	cfbit;

	ci = CHOSUNG(code) - 0x0a;
	v = JOONGSUNG(code) - (unsigned short)JOONGSUNG(code) / 4 - 2;
	cf = JONGSUNG(code);

	if (v < 0)
		return(0xA4A0 + Y19_32[CHOSUNG(code) - 9]);
	if (ci < 0)
        {
		if (cf <= 1)
			return(0xA4BF + v);
		return(ILLEGAL_SEQ);
	}

	for (cfbit = cmp_bitmap[ci][v], disp = 0, i = 0; i < cf; i++)
	{
		if (cfbit & BIT_MASK)
			disp++;
		cfbit >>= 1;
	}

	if (!(cfbit & BIT_MASK))
		return(ILLEGAL_SEQ);

	code = cmp_srchtbl[ci][v] + disp;
	mask = cmp_srchtbl[ci][v] & 0xff;
	if ((mask + disp) > 0xfe)
		code += SKIP;

	return(code);
}  /* end og static unsigned short _johap_to_wansung(unsigned short). */

struct _cv_state  *
_cv_open()
{
        struct _cv_state *st;

        if ((st = (struct _cv_state *)malloc(sizeof(struct _cv_state))) == NULL)
                return ((void *)-1);

	st->invalid = 0;
	st->flush_obuf = 0;
	st->ibuf_left = 0;
	st->start_cnt = 0;
	st->end_cnt = 0;

        return (st);
}

void
_cv_close(st)
struct _cv_state *st;
{
        free(st);
}


size_t
_cv_enconv(st, inbuf, inbytesleft, outbuf, outbytesleft)
struct _cv_state *st;
char **inbuf;
size_t*inbytesleft;
char **outbuf;
size_t*outbytesleft;
{
	int	c, d;
	KCHAR	code;

        if (inbuf == NULL || *inbuf == NULL) { /* Reset request. */
		st->invalid = 0;
		st->flush_obuf = 0;
		st->ibuf_left = 0;
		st->start_cnt = 0;
		st->end_cnt = 0;
                return (0);
        }

	if (st->flush_obuf) {
		while ((*outbytesleft > 0) && (st->start_cnt < st->end_cnt)) {
			**outbuf = st->temp_obuf[st->start_cnt];
			(*outbuf)++;
			(*outbytesleft)--;
			(st->start_cnt)++;
		}

		if (st->start_cnt < st->end_cnt) {
			return(*inbytesleft);
		} else {
			st->flush_obuf = 0;
			st->start_cnt = 0;
			st->end_cnt = 0;
		}
	}

	st->my_outbuf = outbuf;
	st->my_outbytesleft = outbytesleft;

	while (*inbytesleft > 0 && *(st->my_outbytesleft) > 0) {

		if (st->ibuf_left) {
			c = st->temp_ibuf[0];
			st->ibuf_left = 0;
		} else {
			c = (**inbuf)&BYTE_MASK;
			(*inbuf)++, (*inbytesleft)--;
		}

		if (iskorea1(c)) {
			if ( *inbytesleft <= 0) {
				st->ibuf_left = 1;
				st->temp_ibuf[0] = c;
				return(*inbytesleft);
			}

			d = (**inbuf)&BYTE_MASK;
			(*inbuf)++, (*inbytesleft)--;
			code = c<<8|d;

                        if ((code = packtocomp(code)) == K_ILLEGAL) {
				AddChar ('?', st);
				AddChar ('?', st);
                        } else {
                                AddChar (code>>8, st);
                                AddChar (code&BYTE_MASK, st);
                        }
                        if (st->invalid) {
                                st->invalid = 0;
                                return(*inbytesleft);
                        }

		} else {		/* output normal Ascii code */
			AddChar (c, st);
			if (st->invalid) {
				st->invalid = 0;
				return(*inbytesleft);
			}
		}
	}
        return (*inbytesleft);
}

void
AddChar (Char, st)
char Char;
struct _cv_state *st;
{
	/* no more outbuf space */
	if (*(st->my_outbytesleft) <= 0) {
	    st->invalid = 1;
	    st->temp_obuf[st->end_cnt] = Char;
	    st->end_cnt++;
	    st->flush_obuf = 1;
	} else {
	    **(st->my_outbuf) = Char;
	    (*(st->my_outbuf))++, (*(st->my_outbytesleft))--;
	}
}

#ifdef TEST

/* test case 1 */
char ibuf1[] = {0xa8, 0x41, 0xa8, 0x42, 0x41, 0xa8 , 0x45};
char obuf1[20];

/* test case 2 */
char ibuf2[] = {0xa8, 0x41, 0xa8, 0x42, 0xa8};
char ibuf21[] = {0x45 , 0x41};
char obuf2[20];

/* test case 3 */
char ibuf3[] = {0xa8, 0x41, 0xa8, 0x42, 0xa8, 0x45 , 0x41};
char obuf3[5];


main()
{
        int i;
	struct _cv_state *st;
        size_t oleft, ileft;
        char *ip1 = &ibuf1[0], *op1 = &obuf1[0],
	     *ip2 = &ibuf2[0], *ip21 = &ibuf21[0], *op2 = &obuf2[0],
	     *ip3 = &ibuf3[0], *op3 = &obuf3[0];

	/****************************** test case 1 *************************/
        ileft = sizeof(ibuf1);
        oleft = sizeof(obuf1);

	st = _cv_open();

	printf("TEST 1\n INPUT BUFFER: ");
        for (i = 0; i < ileft ; i++) {
            printf("%x ", 0xff&ibuf1[i]);
        }
	printf("\n");
        printf("OUTPUT: return value %d ",
		_cv_enconv(st, &ip1, &ileft, &op1, &oleft));
	printf("ileft %d  oleft %d\n", ileft, oleft);
	printf("        flush_obuf %d  ibuf_left %d\n", st->flush_obuf,
							st->ibuf_left);
	printf("OUTPUT BUFFER: ");
        for (i = 0; i < (sizeof(obuf1) - oleft) ; i++) {
            printf("%x ", obuf1[i]);
        }
	printf("\n\n\n");
	_cv_close(st);

	/************************ test case 2 ******************************/
        ileft = sizeof(ibuf2);
        oleft = sizeof(obuf2);

	st = _cv_open();

	printf("TEST 2\nINPUT BUFFER: ");
        for (i = 0; i < ileft ; i++) {
            printf("%x ", 0xff&ibuf2[i]);
        }
	printf("\n");
        printf("OUTPUT: return value %d ",
		_cv_enconv(st, &ip2, &ileft, &op2, &oleft));
	printf("ileft %d  oleft %d\n", ileft, oleft);
	printf("        flush_obuf %d  ibuf_left %d\n", st->flush_obuf,
							st->ibuf_left);
	printf("OUTPUT BUFFER: ");
        for (i = 0; i < (sizeof(obuf2) - oleft) ; i++) {
            printf("%x ", obuf2[i]);
        }
	printf("\n\n");

        ileft = sizeof(ibuf21);
        oleft = sizeof(obuf2);
	op2 = &obuf2[0];
	printf("INPUT BUFFER: ");
        for (i = 0; i < ileft ; i++) {
            printf("%x ", 0xff&ibuf21[i]);
        }
	printf("\n");
        printf("OUTPUT: return value %d ",
		_cv_enconv(st, &ip21, &ileft, &op2, &oleft));
	printf("ileft %d  oleft %d\n", ileft, oleft);
	printf("        flush_obuf %d  ibuf_left %d\n", st->flush_obuf,
							st->ibuf_left);
	printf("OUTPUT BUFFER: ");
        for (i = 0; i < (sizeof(obuf2) - oleft) ; i++) {
            printf("%x ", obuf2[i]);
	}
	printf("\n\n\n");
	_cv_close(st);

	/************************ test case 3 ******************************/
        ileft = sizeof(ibuf3);
        oleft = sizeof(obuf3);

	st = _cv_open();

	printf("TEST 3\nINPUT BUFFER: ");
        for (i = 0; i < ileft ; i++) {
            printf("%x ", 0xff&ibuf3[i]);
        }
	printf("\n");
        printf("OUTPUT: return value %d ",
		_cv_enconv(st, &ip3, &ileft, &op3, &oleft));
	printf("ileft %d  oleft %d\n", ileft, oleft);
	printf("        flush_obuf %d  ibuf_left %d\n", st->flush_obuf,
							st->ibuf_left);
	printf("        strat_cnt %d   end_cnt %d\n", st->start_cnt,
							st->end_cnt);
	printf("OUTPUT BUFFER: ");
        for (i = 0; i < (sizeof(obuf3) - oleft) ; i++) {
            printf("%x ", obuf3[i]);
        }
	printf("\n\n");

	op3 = &obuf3[0];
        oleft = sizeof(obuf3);
        printf("OUTPUT: return value %d ",
		_cv_enconv(st, &ip3, &ileft, &op3, &oleft));
	printf("ileft %d  oleft %d\n", ileft, oleft);
	printf("        flush_obuf %d  ibuf_left %d\n", st->flush_obuf,
							st->ibuf_left);
	printf("        strat_cnt %d   end_cnt %d\n", st->start_cnt,
							st->end_cnt);
	printf("OUTPUT BUFFER: ");
        for (i = 0; i < (sizeof(obuf3) - oleft) ; i++) {
            printf("%x ", obuf3[i]);
	}
	printf("\n\n");

	op3 = &obuf3[0];
        oleft = sizeof(obuf3);
        printf("OUTPUT: return value %d ",
		_cv_enconv(st, &ip3, &ileft, &op3, &oleft));
	printf("ileft %d  oleft %d\n", ileft, oleft);
	printf("        flush_obuf %d  ibuf_left %d\n", st->flush_obuf,
							st->ibuf_left);
	printf("        strat_cnt %d   end_cnt %d\n", st->start_cnt,
							st->end_cnt);
	printf("OUTPUT BUFFER: ");
        for (i = 0; i < (sizeof(obuf3) - oleft) ; i++) {
            printf("%x ", obuf3[i]);
	}
	printf("\n\n\n");
	_cv_close(st);
}

/* expected output

TEST 1
 INPUT BUFFER: a8 41 a8 42 41 a8 45
OUTPUT: return value 0 ileft 0  oleft 13
        flush_obuf 0  ibuf_left 0
OUTPUT BUFFER: ffffffb0 ffffffa1 ffffffb0 ffffffa2 41 ffffffb0 ffffffa3


TEST 2
INPUT BUFFER: a8 41 a8 42 a8
OUTPUT: return value 0 ileft 0  oleft 16
        flush_obuf 0  ibuf_left 1
OUTPUT BUFFER: ffffffb0 ffffffa1 ffffffb0 ffffffa2

INPUT BUFFER: 45 41
OUTPUT: return value 0 ileft 0  oleft 17
        flush_obuf 0  ibuf_left 0
OUTPUT BUFFER: ffffffb0 ffffffa3 41


TEST 3
INPUT BUFFER: a8 41 a8 42 a8 45 41
OUTPUT: return value 1 ileft 1  oleft 0
        flush_obuf 1  ibuf_left 0
        strat_cnt 0   end_cnt 1
OUTPUT BUFFER: ffffffb0 ffffffa1 ffffffb0 ffffffa2 ffffffb0

OUTPUT: return value 0 ileft 0  oleft 3
        flush_obuf 0  ibuf_left 0
        strat_cnt 0   end_cnt 0
OUTPUT BUFFER: ffffffa3 41

OUTPUT: return value 0 ileft 0  oleft 5
        flush_obuf 0  ibuf_left 0
        strat_cnt 0   end_cnt 0
OUTPUT BUFFER:
*/

#endif /* TEST */
