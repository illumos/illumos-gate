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

void AddChar (char Char, struct _cv_state *st);
int write_21(KCHAR code_2, struct _cv_state *st);


static void echo_vowel(char*, int*);
static void echo_consonant(char*, int*);
static int _wansung_to_cvc(unsigned short code,
	unsigned char* ci_ret, unsigned char* v_ret, unsigned char* cf_ret);

typedef enum { ASCII, WANSUNG } _conv_desc;


/****  _ I C V _ O P E N  ****/

void* _icv_open()
{
	_conv_desc* cd = (_conv_desc*)malloc(sizeof(_conv_desc));

	if (cd == (_conv_desc*)NULL)
	{
		errno = ENOMEM;
		return((void*)-1);
	}

	*cd = ASCII;

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

size_t _icv_iconv(_conv_desc* state, char** inbuf, size_t* inbufleft,
			char** outbuf, size_t* outbufleft)
{
	size_t		ret_val = 0;
	unsigned char*	ib;
	unsigned char*	ob;
	unsigned char*	ibtail;
	unsigned char*	obtail;

	if (!state)
	{
		errno = EBADF;
		return((size_t)-1);
	}

	if (!inbuf || !(*inbuf))
	{
		if (*state == WANSUNG)
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

		*state = ASCII;
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
			if ((obtail - ob) < (*state == WANSUNG ? 2 : 1))
			{
				errno = E2BIG;
				ret_val = (size_t)-1;
				break;
			}
			if (*state == WANSUNG)
			{
				*ob++ = SI;
				*state = ASCII;
			}
			*ob++ = *ib++;
		}
		else
		{
			unsigned char	ci, v, cf;
			register int	ret, j;
			int		i;
			char		c[5];

			if ((ibtail - ib) < 2)
			{
				errno = EINVAL;
				ret_val = (size_t)-1;
				break;
			}

			ret = _wansung_to_cvc((unsigned short)(*ib) << 8 |
				(unsigned short)(*(ib + 1)), &ci, &v, &cf);
			i = 0;
			if (ret != ILLEGAL_SEQ && ret != FAILED)
			{
				c[i] = (char)Y19_32[ci != CVC_FILL ?
					ci + 1 : 0] + '@';
				if (c[i] > '@')
					i++;
				c[i] = (char)Y21_32[v != CVC_FILL ? v +
					(short)(v + 1) / 3 + 2 : 1] + '`';
				if (c[i] > 'a')
					echo_vowel(c, &i);
				c[i] = (char)Y28_32[cf != CVC_FILL ?
					cf - 1 : 0] + '@';
				if (c[i] > '@')
					echo_consonant(c, &i);

				if ((obtail - ob) < (i + (*state == ASCII ?
								1 : 0)))
				{
					errno = E2BIG;
					ret_val = (size_t)-1;
					break;
				}
				if (*state == ASCII)
				{
					*ob++ = SO;
					*state = WANSUNG;
				}
				for (j = 0; j < i; j++)
					*ob++ = c[j];
			}
			else
			{
				/* Let's assume the code is non-identical. */
				if (*state == WANSUNG)
				{
					if ((obtail - ob) < 3)
					{
						errno = E2BIG;
						ret_val = (size_t)-1;
						break;
					}
					*ob++ = SI;
					*state = ASCII;
				}
				else if ((obtail - ob) < 2)
				{
					errno = E2BIG;
					ret_val = (size_t)-1;
					break;
				}
				*ob++ = NON_IDENTICAL;
				*ob++ = NON_IDENTICAL;
				ret_val += 2;
			}
			ib += 2;
		}
	}

	*inbuf = (char*)ib;
	*inbufleft = ibtail - ib;
	*outbuf = (char*)ob;
	*outbufleft = obtail - ob;

	return(ret_val);
}  /* end of size_t _icv_iconv(_conv_desc*, char**, size_t*, char**, size_t*).*/


/****  E C H O _ V O W E L  ****/

static void echo_vowel(char* c,  int* i)
{
	if (c[*i] == 'm')  /* _|_|- */
	{
		c[(*i)++] = 'l';	/* _|_ */
		c[(*i)++] = 'b';	/* |- */
	}
	else if (c[*i] == 'n')  /* _|_H */
	{
		c[(*i)++] = 'l';	/* _|_ */
		c[(*i)++] = 'c';	/* H */
	}
	else if (c[*i] == 'o')  /* _|_| */
	{
		c[(*i)++] = 'l';	/* _|_ */
		c[(*i)++] = '|';	/* | */
	}
	else if (c[*i] == 't')  /* T-| */
	{
		c[(*i)++] = 's';	/* T */
		c[(*i)++] = 'f';	/* -| */
	}
	else if (c[*i] == 'u')  /* T-|| */
	{
		c[(*i)++] = 's';	/* T */
		c[(*i)++] = 'g';	/* -|| */
	}
	else if (c[*i] == 'v')  /* T| */
	{
		c[(*i)++] = 's';	/* T */
		c[(*i)++] = '|';	/* | */
	}
	else if (c[*i] == '{')  /* _| */
	{
		c[(*i)++] = 'z';	/* __ */
		c[(*i)++] = '|';	/* | */
	}
	else
		(*i)++;
}  /* end of static void echo_vowel(char*, int*). */


/****  E C H O _ C O N S O N A N T  ****/

static void echo_consonant(char* c,  int* i)
{
	if (c[*i] == 'C')  /* gs */
	{
		c[(*i)++] = 'A';	/* g */
		c[(*i)++] = 'U';	/* s */
	}
	else if (c[*i] == 'E')  /* nj */
	{
		c[(*i)++] = 'D';	/* n */
		c[(*i)++] = 'X';	/* j */
	}
	else if (c[*i] == 'F')  /* nh */
	{
		c[(*i)++] = 'D';	/* n */
		c[(*i)++] = '^';	/* h */
	}
	else if (c[*i] == 'J')  /* rg */
	{
		c[(*i)++] = 'I';	/* r */
		c[(*i)++] = 'A';	/* g */
	}
	else if (c[*i] == 'K')  /* rm */
	{
		c[(*i)++] = 'I';	/* r */
		c[(*i)++] = 'Q';	/* m */
	}
	else if (c[*i] == 'L')  /* rb */
	{
		c[(*i)++] = 'I';	/* r */
		c[(*i)++] = 'R';	/* b */
	}
	else if (c[*i] == 'M')  /* rs */
	{
		c[(*i)++] = 'I';	/* r */
		c[(*i)++] = 'U';	/* s */
	}
	else if (c[*i] == 'N')  /* rt */
	{
		c[(*i)++] = 'I';	/* r */
		c[(*i)++] = '\\';	/* t */
	}
	else if (c[*i] == 'O')  /* rp */
	{
		c[(*i)++] = 'I';	/* r */
		c[(*i)++] = ']';	/* p */
	}
	else if (c[*i] == 'P')  /* rh */
	{
		c[(*i)++] = 'I';	/* r */
		c[(*i)++] = '^';	/* h */
	}
	else if (c[*i] == 'T')  /* bs */
	{
		c[(*i)++] = 'R';	/* b */
		c[(*i)++] = 'U';	/* s */
	}
	else
		(*i)++;
}  /* end of static void echo_consonant(char*, int*). */


/**** _ W A N S U N G _ T O _ C V C ****/

static int _wansung_to_cvc(unsigned short code,
	unsigned char* ci_ret, unsigned char* v_ret, unsigned char* cf_ret)
{
	register short		h, i, l;
	short			ci, v, cf;
	short			disp;
	long			cfbit;

	*ci_ret = *v_ret = *cf_ret = CVC_FILL;

	if (code >= 0xB0A1 && code <= 0xC8FE)
	{
		if ((unsigned short)(code & 0xFF) < 0xA1)
			return(ILLEGAL_SEQ);

		for (h = CI_CNT, l = 0; ; )
		{
			ci = (l + h) / 2;
			if (l >= h)
				break;
			if (code < cmp_srchtbl[ci][0])
				h = ci - 1;
			else if (code < cmp_srchtbl[ci + 1][0])
				break;
			else
				l = ci + 1;
		}

		for (v = 1; ; )
		{
			if (code < cmp_srchtbl[ci][v])
			{
				while (!cmp_srchtbl[ci][--v])
					;
				break;
			}
			else if (v == V_CNT)
				break;
			v++;
		}

		disp = code - cmp_srchtbl[ci][v];
		if (((short)(cmp_srchtbl[ci][v] & 0xFF) + disp) > 0xFE)
			disp -= SKIP;

		for (cfbit = cmp_bitmap[ci][v], i = -1, cf = -1; i < disp; cf++)
		{
			if (cfbit & 0x01)
				i++;
			cfbit >>= 1;
		}

		if (cf == -1)
			return(FAILED);

		*ci_ret = (unsigned char)ci;
		*v_ret = (unsigned char)v;
		if (cf >= 2)
			*cf_ret = (unsigned char)cf;
		return(HANGUL);
	}

	/* Chosung-only */
	if ((code >= 0xA4A1 && code <= 0xA4BE) && (X32_19[code - 0xA4A0] != -1))
	{
		*ci_ret = (unsigned char)((X32_19[code - 0xA4A0] << 2) - 0xA0);
		return(HANJA_OR_SYMBOL);
	}
	else if (code >= 0xA4BF && code <= 0xA4D3)  /* Joongsung-only */
	{
		*v_ret = (unsigned char)(code - 0xA4BE);
		return(HANJA_OR_SYMBOL);
	}

	return(ILLEGAL_SEQ);
}  /* end of static int _wansung_to_cvc(unsigned short, unsigned char*,
					unsigned char*, unsigned char*). */

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

		if (iskorea1(c)) {/* Completion Code */
			if ( *inbytesleft <= 0) {
				st->ibuf_left = 1;
				st->temp_ibuf[0] = c;
				return(*inbytesleft);
			}

			d = (**inbuf)&BYTE_MASK;
			(*inbuf)++, (*inbytesleft)--;
			code = c<<8|d;


				/* output hangul character */
			if (iskorea2(code&BYTE_MASK) && !ishanja(c)) {

				if (ishangul(c)) {
					code = c2p(code);
					AddChar (0x0e, st);
					write_21(code, st);
					AddChar (0x0f, st);

				} else  if (ishaninit(code) || ishanmid(code)) {
					AddChar (0x0e, st);
					if (ishaninit(code)) {
						AddChar(code - 0xa4a0 + 0x40, st);
					} else {
						code -= 0xa4bf;
						code += (code/6) * 2 + 1;
						AddChar(code + 0x61, st);
					}
					AddChar (0x0f, st);

				/* other case */
				} else {
					AddChar ('?', st);
					AddChar ('?', st);
					/*AddChar (c);
					AddChar (code&BYTE_MASK);*/
				}

			} else {
				AddChar ('?', st);
				AddChar ('?', st);
			}

			if (st->invalid) { /* ran out of outbuf space */
				st->invalid = 0;
				return(*inbytesleft);
			}

		} else {		/* output normal Ascii code */
			AddChar (c, st);
			if (st->invalid) {
				st->invalid = 0;
				/*(*outbuf)--;
				(*outbytesleft)++;
				(*inbuf)--;
				(*inbytesleft)++;*/
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
char ibuf1[] = {0xbf, 0xc0, 0xbc, 0xbc, 0xc3, 0xa2 , 0x41};
char obuf1[20];

/* test case 2 */
char ibuf2[] = {0xbf, 0xc0, 0xbc, 0xbc, 0xc3};
char ibuf21[] = {0xa2 , 0x41};
char obuf2[20];

/* test case 3 */
char ibuf3[] = {0xbf, 0xc0, 0xbc, 0xbc, 0xc3, 0xa2 , 0x41};
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
 INPUT BUFFER: bf c0 bc bc c3 a2 41
OUTPUT: return value 0 ileft 0  oleft 6
        flush_obuf 0  ibuf_left 0
OUTPUT BUFFER: e 57 6c f e 55 67 f e 5a 62 57 f 41


TEST 2
INPUT BUFFER: bf c0 bc bc c3
OUTPUT: return value 0 ileft 0  oleft 12
        flush_obuf 0  ibuf_left 1
OUTPUT BUFFER: e 57 6c f e 55 67 f

INPUT BUFFER: a2 41
OUTPUT: return value 0 ileft 0  oleft 14
        flush_obuf 0  ibuf_left 0
OUTPUT BUFFER: e 5a 62 57 f 41


TEST 3
INPUT BUFFER: bf c0 bc bc c3 a2 41
OUTPUT: return value 3 ileft 3  oleft 0
        flush_obuf 1  ibuf_left 0
        strat_cnt 0   end_cnt 3
OUTPUT BUFFER: e 57 6c f e

OUTPUT: return value 1 ileft 1  oleft 0
        flush_obuf 1  ibuf_left 0
        strat_cnt 0   end_cnt 3
OUTPUT BUFFER: 55 67 f e 5a

OUTPUT: return value 0 ileft 0  oleft 1
        flush_obuf 0  ibuf_left 0
        strat_cnt 0   end_cnt 0
OUTPUT BUFFER: 62 57 f 41

*/
#endif /* TEST */
