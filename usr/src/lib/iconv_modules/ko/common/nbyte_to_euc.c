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
#include "kdefs.h"
#include <errno.h>
#include "ktable.h"
#include "nbyte_euc.h"

extern KCHAR getc_12();
extern KCHAR packtocomp();

struct _cv_state {
	char temp_ibuf[5];
	int  ibuf_left;
	int  istart, iend;
	char temp_obuf[1];
	int  flush_obuf;
};

int is_SI(char **inbuf, size_t *inbytesleft, struct _cv_state *st);

static int _johap_to_wansung(unsigned short* wcode, unsigned short code);

/****  _ I C V _ O P E N  ****/

void* _icv_open()
{
	_conv_desc* cd = (_conv_desc*)malloc(sizeof(_conv_desc));

	if (cd == (_conv_desc*)NULL)
	{
		errno = ENOMEM;
		return((void*)-1);
	}

	cd->cur_stat = 1;
	cd->hbuf[1] = cd->hbuf[2] = cd->hbuf[3] = cd->hbuf[4] = '\0';
	cd->cur_act = 0;

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

size_t _icv_iconv(_conv_desc* cd, char** inbuf, size_t* inbufleft,
			char** outbuf, size_t* outbufleft)
{
	size_t		ret_val = 0;
	unsigned char*	ib;
	unsigned char*	ob;
	unsigned char*	ibtail;
	unsigned char*	obtail;

	if (!cd)
	{
		errno = EBADF;
		return((size_t)-1);
	}

	if (!inbuf || !(*inbuf))
	{
		cd->cur_stat = 1;
		cd->hbuf[1] = cd->hbuf[2] = cd->hbuf[3] = cd->hbuf[4] = '\0';
		cd->cur_act = 0;
		return((size_t)0);
	}

	ib = (unsigned char*)*inbuf;
	ob = (unsigned char*)*outbuf;
	ibtail = ib + *inbufleft;
	obtail = ob + *outbufleft;

	while (ib < ibtail)
	{
		int		cur_input, action, state;
		char		result;
		int		input_conv(char);
		unsigned short	make_johap_code(int, char*);
		int		_johap_to_wansung(unsigned short*,
							unsigned short);

		cur_input = input_conv(*ib);
		action = next_act[cd->cur_stat][cur_input];
		state = next_stat[cd->cur_stat][cur_input];
		if (action == 4)
		{
			if (ob >= obtail)
			{
				errno = E2BIG;
				ret_val = (size_t)-1;
				break;
			}
			*ob++ = *ib;
		}
		else if (action >= 5 && action <= 8)
			cd->hbuf[action - 4] = *ib;
		else if (action == 9)
		{
			ADD_CONVERTED_CODE(0, 0);
			cd->hbuf[1] = *ib;
		}
		else if (action == 10)
		{
			ADD_CONVERTED_CODE(0, 0);
			cd->hbuf[2] = *ib;
			ADD_CONVERTED_CODE(0, 0);
		}
		else if (action == 11 || action == 12)
		{
			ADD_CONVERTED_CODE(0, 0);
		}
		else if (action == 13)
		{
			ADD_CONVERTED_CODE(0, 1);
			*ob++ = *ib;
		}
		else if (action == 14)
		{
			register char c1 = cd->hbuf[2], c2 = *ib;

			if (c1 == 'l' && c2 == 'b')  /* _|_ && |- */
				cd->hbuf[2] = 'm';
			else if (c1 == 'l' && c2 == 'c')  /* _|_ && H */
				cd->hbuf[2] = 'n';
			else if (c1 == 'l' && c2 == '|')  /* _|_ && | */
				cd->hbuf[2] = 'o';
			else if (c1 == 's' && c2 == 'f')  /* T && -| */
				cd->hbuf[2] = 't';
			else if (c1 == 's' && c2 == 'g')  /* T && -|| */
				cd->hbuf[2] = 'u';
			else if (c1 == 's' && c2 == '|')  /* T && | */
				cd->hbuf[2] = 'v';
			else if (c1 == 'z' && c2 == '|')  /* __ && | */
				cd->hbuf[2] = '{';
			else
				cd->hbuf[2] = *ib;  /* Just in case. */
		}
		else if (action == 15)
		{
			cd->hbuf[2] = *ib;
			ADD_CONVERTED_CODE(0, 0);
		}
		else if (action == 16)
		{
			ADD_CONVERTED_CODE(0, 0);
		}
		else if (action == 17)
		{
			ADD_CONVERTED_CODE(1, 0);
			cd->hbuf[2] = *ib;
		}
		cd->cur_act = action;
		cd->cur_stat = state;
		ib++;
	}

	*inbuf = (char*)ib;
	*inbufleft = ibtail - ib;
	*outbuf = (char*)ob;
	*outbufleft = obtail - ob;

	return(ret_val);
}  /* end of size_t _icv_iconv(_conv_desc*, char**, size_t*, char**, size_t*).*/


/****  I N P U T _ C O N V  ****/

int input_conv(char c)
{
	switch (c)
	{
		case 'H':	/* dd */
		case 'S':	/* bb */
		case 'Y':	/* jj */
			return(1);

		case 'A':	/* g */
			return(2);

		case 'D':	/* n */
			return(3);

		case 'I':	/* r */
			return(4);

		case 'R':	/* b */
			return(5);

		case 'B':	/* gg */
		case 'G':	/* d */
		case 'V':	/* ss */
		case 'W':	/* o */
		case 'Z':	/* ch */
		case '[':	/* k */
			return(6);

		case 'U':	/* s */
			return(7);

		case 'X':	/* j */
			return(8);

		case '^':	/* h */
			return(9);

		case 'Q':	/* m */
		case ']':	/* p */
		case '\\':	/* t */
			return(10);

		case 'k':	/* =|| */
		case 'd':	/* |= */
		case 'e':	/* |=| */
		case 'j':	/* =| */
		case 'r':	/* _||_ */
		case 'w':	/* TT */
			return(11);

		case 'b':	/* |- */
		case 'c':	/* H */
			return(12);

		case 'f':	/* -| */
		case 'g':	/* -|| */
			return(13);

		case '|':	/* | */
			return(14);

		case 'l':	/* _|_ */
			return(15);

		case 's':	/* T */
			return(16);

		case 'z':	/* __ */
			return(17);

		case '\016':
			return(18);

		case '\017':
		case '\024':
			return(19);

		default:
			return(20);
	}
}  /* end of int input_conv(char). */


/****  M A K E _ J O H A P _ C O D E  ****/

unsigned short make_johap_code(int n, char* temp)
{
	register unsigned short code = 0;
	char 			save ='\0';

	if (n == 1)
	{
		if (temp[4] == '\0')
		{
			save = temp[3];
			temp[3] = '\0';
		}
		else
		{
			save = temp[4];
			temp[4] = '\0';
		}
	}

	code = (temp[1] >= 'A' && temp[1] <= '^') ?
			(unsigned short)X32_19[temp[1] - '@']
			: (unsigned short)9;
	code = (code << 5) | (unsigned short)((temp[2] >= 'b' &&
				temp[2] <= '|') ? X32_21[temp[2] - '`']
						    : 1);
	code = (code << 5) | (unsigned short)((temp[3] >= 'A' &&
				temp[3] <= '^') ? X32_28[temp[3] - '@']
						    : 1);

	if (temp[4] >= 'A')
	{
		if (temp[3] == 'A' && temp[4] == 'U')  /* gs */
			code += 2;
		else if (temp[3] == 'D' && temp[4] == 'X')  /* nj */
			code++;
		else if (temp[3] == 'D' && temp[4] == '^')  /* nh */
			code += 2;
		else if (temp[3] == 'I' && temp[4] == 'A')  /* rg */
			code++;
		else if (temp[3] == 'I' && temp[4] == 'Q')  /* rm */
			code += 2;
		else if (temp[3] == 'I' && temp[4] == 'R')  /* rb */
			code += 3;
		else if (temp[3] == 'I' && temp[4] == 'U')  /* rs */
			code += 4;
		else if (temp[3] == 'I' && temp[4] == '\\')  /* rt */
			code += 5;
		else if (temp[3] == 'I' && temp[4] == ']')  /* rp */
			code += 6;
		else if (temp[3] == 'I' && temp[4] == '^')  /* rh */
			code += 7;
		else if (temp[3] == 'R' && temp[4] == 'U')  /* bs */
			code++;
		else if (temp[3] == 'U' && temp[4] == 'U')  /* ss */
			code++;
	}

	temp[1] = (n == 1) ? save : '\0';
	temp[2] = temp[3] = temp[4] = '\0';
	return(code | 0x8000);
}  /* end of unsigned short make_johap_code(int, char*). */


/****  _ J O H A P _ T O _ W A N S U N G  ****/

static int _johap_to_wansung(unsigned short* wcode, unsigned short code)
{
	register unsigned short	i;
	unsigned short 		ci, v, cf;
	unsigned short		mask, disp;
	long			cfbit;

	*wcode = 0;
	ci = CHOSUNG(code) - 0x0A;
	v = JOONGSUNG(code) - ((unsigned short)JOONGSUNG(code) / 4 + 2);
	cf = JONGSUNG(code);

	if (JOONGSUNG(code) - ((unsigned short)JOONGSUNG(code) / 4 + 2) < 0)
		*wcode = 0xA4A0 + Y19_32[ci + 1];
	else if (CHOSUNG(code) - 0x0A < 0)
	{
		if (cf <= 1)
			*wcode = 0xA4BF + v;
		else
			return(FAILED);
	}
	else
	{
		 if (cf < 2)
			cf = 1;

		cfbit = cmp_bitmap[ci][v];
		for (disp = 0, i = 0; i < cf; i++)
		{
			if (cfbit & BIT_MASK)
				disp++;
			cfbit >>= 1;
		}
		if (!(cfbit & BIT_MASK))
			return(FAILED);

		*wcode = cmp_srchtbl[ci][v] + disp;
		mask = cmp_srchtbl[ci][v] & 0xFF;

		*wcode += (((short)(mask + disp) > 0xFE) ? SKIP : 0);
	}

	return(HANGUL);
}  /* end of unsigned short _johap_to_wansung(unsigned short, unsigned short,
    *						unsigned short). */

void *
_cv_open()
{
        struct _cv_state *st;

        if ((st = (struct _cv_state *)malloc(sizeof(struct _cv_state))) == NULL)
                return ((void *)-1);

	st->ibuf_left = 0;
	st->istart = 0;
	st->iend = 0;
	st->flush_obuf = 0;

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
	unsigned short code;

        if (inbuf == NULL || *inbuf == NULL) { /* Reset request. */
		st->ibuf_left = 0;
		st->istart = 0;
		st->iend = 0;
		st->flush_obuf = 0;
                return (0);
        }

	if (st->flush_obuf) {
		**outbuf = st->temp_obuf[0];
		(*outbuf)++;
		(*outbytesleft)--;
		st->flush_obuf = 0;
		if (*outbytesleft <= 0) {
			return(*inbytesleft);
		}
	}

	while (*inbytesleft > 0 && *outbytesleft > 0) {
		if (!is_SI(inbuf, inbytesleft, st))
			break;

		code = getc_12(inbuf, inbytesleft, st);

		if (code&0x8000) {
			code = packtocomp(code);
			**outbuf = code>>8;
			(*outbuf)++, (*outbytesleft)--;
			if (*outbytesleft <= 0) {
				st->flush_obuf = 1;
				st->temp_obuf[0] = code&0xFF;
			} else {
				**outbuf = code&0xFF;
				(*outbuf)++, (*outbytesleft)--;
			}
		} else {
			**outbuf = code&0xFF;
			(*outbuf)++, (*outbytesleft)--;
		}
	}
        return (*inbytesleft);
}

int
is_SI(inbuf, inbytesleft, st)
char **inbuf;
size_t *inbytesleft;
struct _cv_state *st;
{
	size_t i, x;
	char *buf;
	int SO_found = 0, SI_found = 0;

	buf = *inbuf;
	for (i = *inbytesleft; i > 0; i--) {
	    /* if SO is found */
	    if (*buf == 0x0e) {
		SO_found = 1;
		break;
	    } else
		buf++;
	}

	if (SO_found || st->ibuf_left) {
	    while (i > 0) {
		i--;
	        /* if SI is found */
	        if (*buf == 0x0f) {
		    SI_found = 1;
		    break;
	        } else
		    buf++;
	    }
	}


	/* if input buffer is not complete, i.e., last SI is not there */
	/* NEED to check for size of left buffer vs. temp_ibuf[] size */
	if ((SO_found && !SI_found) || (st->ibuf_left && !SI_found)) {
		st->ibuf_left = 1;
		x = *inbytesleft;
		for (i = 0; i < x; i++) {
			st->temp_ibuf[st->iend] = **inbuf;
			st->iend++;
			(*inbuf)++;
			(*inbytesleft)--;
		}
		return(0);
	}
	return(1);
}

#ifdef TEST

/* test case 1 */
char ibuf1[] = {0x0e, 0x57, 0x6c, 0x0f, 0x0e, 0x55, 0x67, 0x0f, 0x0e, 0x5a, 0x62, 0x57, 0x0f};
char obuf1[20];

/* test case 2 */
char ibuf2[] = {0x0e, 0x57, 0x6c, 0x0f, 0x0e, 0x55};
char ibuf21[] = {0x67, 0x0f, 0x0e, 0x5a, 0x62, 0x57, 0x0f};
char obuf2[20];

/* test case 3 */
char ibuf3[] = {0x0e, 0x57, 0x6c, 0x0f, 0x0e, 0x55, 0x67, 0x0f, 0x0e, 0x5a, 0x62, 0x57, 0x0f};
char obuf3[4];

/* test case 3+ */
char obuf31[5];

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
            printf("%x ", 0xff&obuf1[i]);
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
            printf("%x ", 0xff&obuf2[i]);
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
            printf("%x ", 0xff&obuf2[i]);
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
        printf("        strat_cnt %d   end_cnt %d\n", st->istart,
                                                        st->iend);
        printf("OUTPUT BUFFER: ");
        for (i = 0; i < (sizeof(obuf3) - oleft) ; i++) {
            printf("%x ", 0xff&obuf3[i]);
        }
        printf("\n\n");

        op3 = &obuf3[0];
        oleft = sizeof(obuf3);
        printf("OUTPUT: return value %d ",
                _cv_enconv(st, &ip3, &ileft, &op3, &oleft));
        printf("ileft %d  oleft %d\n", ileft, oleft);
        printf("        flush_obuf %d  ibuf_left %d\n", st->flush_obuf,
                                                        st->ibuf_left);
        printf("        strat_cnt %d   end_cnt %d\n", st->istart,
                                                        st->iend);
        printf("OUTPUT BUFFER: ");
        for (i = 0; i < (sizeof(obuf3) - oleft) ; i++) {
            printf("%x ", 0xff&obuf3[i]);
        }
        printf("\n\n");

        op3 = &obuf3[0];
        oleft = sizeof(obuf3);
        printf("OUTPUT: return value %d ",
                _cv_enconv(st, &ip3, &ileft, &op3, &oleft));
        printf("ileft %d  oleft %d\n", ileft, oleft);
        printf("        flush_obuf %d  ibuf_left %d\n", st->flush_obuf,
                                                        st->ibuf_left);
        printf("        strat_cnt %d   end_cnt %d\n", st->istart,
                                                        st->iend);
        printf("OUTPUT BUFFER: ");
        for (i = 0; i < (sizeof(obuf3) - oleft) ; i++) {
            printf("%x ", 0xff&obuf3[i]);
        }
        printf("\n\n\n");
        _cv_close(st);

        /************************ test case 3+ ******************************/
        ip3 = &ibuf3[0];
	op3 = &obuf31[0];
        ileft = sizeof(ibuf3);
        oleft = sizeof(obuf31);

        st = _cv_open();

        printf("TEST 3+\nINPUT BUFFER: ");
        for (i = 0; i < ileft ; i++) {
            printf("%x ", 0xff&ibuf3[i]);
        }
        printf("\n");
        printf("OUTPUT: return value %d ",
                _cv_enconv(st, &ip3, &ileft, &op3, &oleft));
        printf("ileft %d  oleft %d\n", ileft, oleft);
        printf("        flush_obuf %d  ibuf_left %d\n", st->flush_obuf,
                                                        st->ibuf_left);
        printf("        strat_cnt %d   end_cnt %d\n", st->istart,
                                                        st->iend);
        printf("OUTPUT BUFFER: ");
        for (i = 0; i < (sizeof(obuf31) - oleft) ; i++) {
            printf("%x ", 0xff&obuf31[i]);
        }
        printf("\n\n");

        op3 = &obuf31[0];
        oleft = sizeof(obuf31);
        printf("OUTPUT: return value %d ",
                _cv_enconv(st, &ip3, &ileft, &op3, &oleft));
        printf("ileft %d  oleft %d\n", ileft, oleft);
        printf("        flush_obuf %d  ibuf_left %d\n", st->flush_obuf,
                                                        st->ibuf_left);
        printf("        strat_cnt %d   end_cnt %d\n", st->istart,
                                                        st->iend);
        printf("OUTPUT BUFFER: ");
        for (i = 0; i < (sizeof(obuf31) - oleft) ; i++) {
            printf("%x ", 0xff&obuf31[i]);
        }
        printf("\n\n");

        op3 = &obuf31[0];
        oleft = sizeof(obuf31);
        printf("OUTPUT: return value %d ",
                _cv_enconv(st, &ip3, &ileft, &op3, &oleft));
        printf("ileft %d  oleft %d\n", ileft, oleft);
        printf("        flush_obuf %d  ibuf_left %d\n", st->flush_obuf,
                                                        st->ibuf_left);
        printf("        strat_cnt %d   end_cnt %d\n", st->istart,
                                                        st->iend);
        printf("OUTPUT BUFFER: ");
        for (i = 0; i < (sizeof(obuf31) - oleft) ; i++) {
            printf("%x ", 0xff&obuf31[i]);
        }
        printf("\n\n\n");
        _cv_close(st);
}

/* expected output

TEST 1
 INPUT BUFFER: e 57 6c f e 55 67 f e 5a 62 57 f
OUTPUT: return value 0 ileft 0  oleft 14
        flush_obuf 0  ibuf_left 0
OUTPUT BUFFER: bf c0 bc bc c3 a2


TEST 2
INPUT BUFFER: e 57 6c f e 55
OUTPUT: return value 0 ileft 0  oleft 18
        flush_obuf 0  ibuf_left 1
OUTPUT BUFFER: bf c0

INPUT BUFFER: 67 f e 5a 62 57 f
OUTPUT: return value 0 ileft 0  oleft 16
        flush_obuf 0  ibuf_left 0
OUTPUT BUFFER: bc bc c3 a2


TEST 3
INPUT BUFFER: e 57 6c f e 55 67 f e 5a 62 57 f
OUTPUT: return value 5 ileft 5  oleft 0
        flush_obuf 0  ibuf_left 0
        strat_cnt 0   end_cnt 0
OUTPUT BUFFER: bf c0 bc bc

OUTPUT: return value 0 ileft 0  oleft 2
        flush_obuf 0  ibuf_left 0
        strat_cnt 0   end_cnt 0
OUTPUT BUFFER: c3 a2

OUTPUT: return value 0 ileft 0  oleft 4
        flush_obuf 0  ibuf_left 0
        strat_cnt 0   end_cnt 0
OUTPUT BUFFER:


TEST 3+
INPUT BUFFER: e 57 6c f e 55 67 f e 5a 62 57 f
OUTPUT: return value 0 ileft 0  oleft 0
        flush_obuf 1  ibuf_left 0
        strat_cnt 0   end_cnt 0
OUTPUT BUFFER: bf c0 bc bc c3

OUTPUT: return value 0 ileft 0  oleft 4
        flush_obuf 0  ibuf_left 0
        strat_cnt 0   end_cnt 0
OUTPUT BUFFER: a2

OUTPUT: return value 0 ileft 0  oleft 5
        flush_obuf 0  ibuf_left 0
        strat_cnt 0   end_cnt 0
OUTPUT BUFFER:

*/

#endif /* TEST */
