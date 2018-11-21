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
/* Copyright 1995 by Sun Microsystems, Inc.
 * All rights are reserved.
 */

#include <stdio.h>
#include <string.h>
#include "kdefs.h"
#include "ktable.h"

int input_typ(char c);

struct _cv_state {
	char temp_ibuf[5];
	int  ibuf_left;
	int  istart, iend;
	char temp_obuf[1];
	int  flush_obuf;
};

KCHAR packtocomp(KCHAR comb2);

#ifndef SUNVIEW
char vowel_mix(char c1,char c2);
#endif

/*
 * Hangul 7-bit(KS C 5601) to Standard 2-byte Combination code(87-3)
 */


static int cur_stat = 1;	/* current state of automata */
static int cur_act;		/* current action of automata */

static char han_buf[5] = {0,0,0,0,0 };	/* Hangul buffer */

static int temp_flag;		/* Hangul temporary flag */
static int han_temp = 0;	/* Hangul temporary while two
				   2-byte code are generated */

static int next_stat[14][21]={	/* next state table[current state][input] */
	/* input
	  0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15 16 17 18 19 20 */
/*state*/
/* 0 */ { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
/* 1 */	{ 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 1, 1},
/* 2 */	{ 0, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 3, 3, 3, 3, 3, 3, 3, 2, 1, 2},
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

static int next_act[14][21]={	/* next action table[current state][input]  */
	/*input
	  0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15 16 17 18 19 20 */
/*state*/
/* 0 */ { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
/* 1 */ { 0, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 2, 1, 4},/*4-1*/
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

KCHAR
getc_12(my_inbuf, my_inbytesleft, st)
char **my_inbuf;
size_t *my_inbytesleft;
struct _cv_state *st;
{
	register char	c;		/* input character */
	register int	cur_input;	/* type of input character */
	register KCHAR	code_2;		/* 2-byte char converted */
	KCHAR		make_2();

	if(temp_flag == 1){
		code_2 = han_temp;
		temp_flag = 0;
		return(code_2);
	}
	for(;;){		/* read 1 byte */
		if (st->ibuf_left) {
			c = st->temp_ibuf[st->istart];
			st->istart++;
			if (st->istart >= st->iend) {
				st->ibuf_left = 0;
				st->istart = 0;
				st->iend = 0;
			}
		} else {
			c = **my_inbuf;
			(*my_inbuf)++, (*my_inbytesleft)--;
		}
				/* run Hangul automata */
		cur_input = input_typ(c);
		cur_act = next_act[cur_stat][cur_input];
		cur_stat = next_stat[cur_stat][cur_input];
		switch (cur_act) {
			case 1:
				break;
			case 2:
				break;
			case 3:
				break;
			case 4:
				return(0x0000 | c);
			case 5:
				han_buf[1] = c;
				break;
			case 6:
				han_buf[2] = c;
				if((code_2=packtocomp(make_2(2))) == 0xFFFF){
					han_buf[2] = 0;
					code_2 = make_2(0);
					if (st->ibuf_left) {
						st->istart--;
					} else {
						(*my_inbuf)--, (*my_inbytesleft)++;
					}
					cur_stat = 2;
					return(code_2);
				}
				break;
			case 7:
				han_buf[3] = c;
				if((code_2=packtocomp(make_2(2))) == 0xFFFF){
					han_buf[3] = 0;
					code_2 = make_2(0);
					if (st->ibuf_left) {
						st->istart--;
					} else {
						(*my_inbuf)--, (*my_inbytesleft)++;
					}
					cur_stat = 2;
					return(code_2);
				}
				break;
			case 8:
				han_buf[4] = c;
				if((code_2=packtocomp(make_2(2))) == 0xFFFF){
					han_buf[4] = 0;
					code_2 = make_2(0);
					cur_stat = 2;
					if (st->ibuf_left) {
						st->istart--;
					} else {
						(*my_inbuf)--, (*my_inbytesleft)++;
					}
					return(code_2);
				}
				break;
			case 9:
				code_2 = make_2(0);
				han_buf[1] = c;
				return(code_2);
			case 10:
				code_2 = make_2(0);
				han_buf[2] = c;
				han_temp = make_2(0);
				temp_flag = 1;
				return(code_2);
			case 11:			/* Unused */
				return(make_2(0));
			case 12:
				return(make_2(0));
			case 13:
				code_2 = make_2(0);
				han_temp = (0x0000 | c);
				temp_flag = 1;
				return(code_2);
			case 14:
				han_buf[0] = han_buf[2]; /* Save */
				han_buf[2] = vowel_mix(han_buf[2],c);
				if((code_2=packtocomp(make_2(2))) == 0xFFFF){
					han_buf[2] = han_buf[0]; /* Recover */
					code_2 = make_2(0);
					if (st->ibuf_left) {
						st->istart--;
					} else {
						(*my_inbuf)--, (*my_inbytesleft)++;
					}
					cur_stat = 2;
					return(code_2);
				}
				break;
			case 15:
				han_buf[2] = c;
				return(make_2(0));
			case 16:
				return(make_2(0));
			case 17:
				code_2 = make_2(1);
				han_buf[2] = c;
				return(code_2);
			default:
				break;
		}
	}
}

int input_typ(char c)
{
	switch(c) {
		case D_DI_GUD:	/* double di-gud	0x48 'H' */
		case D_BI_UB:	/* double bi-ub		0x52 'S' */
		case D_JI_UD:	/* double ji-ud		0x59 'Y' */
			return(1);

		case GI_UG:	/* gi-ug 		0x41 'A' */
			return(2);

		case NI_UN:	/* ni-un		0x44 'D' */
			return(3);

		case RI_UL:	/* ri-ul		0x49 'I' */
			return(4);

		case BI_UB:	/* bi-ub		0x52 'R' */
			return(5);

		case D_GI_UG:	/* double gi-ug		0x42 'B' */
		case DI_GUD:	/* di-gud		0x47 'G' */
		case D_SI_OD:	/* double si-od		0x56 'V' */
		case YI_UNG:	/* yi-ung		0x57 'W' */
		case CHI_UD:	/* chi-ud		0x5a 'Z' */
		case KI_UK:	/* ki-uk		0x5b '[' */
			return(6);

		case SI_OD:	/* si-od		0x55 'U' */
			return(7);

		case JI_UD:	/* ji_ud		0x58 'X' */
			return(8);

		case HI_UD:	/* hi-ud		0x5e '^' */
			return(9);

		case MI_UM:	/* mi-um		0x51 'Q' */
		case PI_UP:	/* pi-up		0x5d ']' */
		case TI_GUT:	/* ti-gut		0x51 '\' */
			return(10);

		case YEA:	/* yea 			0x6b 'k' */
		case IA:	/* ia			0x64 'd' */
		case IYAI:	/* iyai			0x65 'e' */
		case IE:	/* ie			0x6a 'j' */
		case YO:	/* yo			0x72 'r' */
		case YU:	/* yu			0x77 'g' */
			return(11);

		case A:		/* a			0x62 'b' */
		case AE:	/* ae			0x63 'c' */
			return(12);

		case E:		/* e			0x66 'f' */
		case EA:	/* ea			0x67 'g' */
			return(13);

		case I:		/* i			0x7c '|' */
			return(14);

		case O:		/* o			0x6c 'l' */
			return(15);

		case U:		/* u			0x73 's' */
			return(16);

		case EU:	/* eu			0x7a 'z' */
			return(17);

		default:
			if(c == '\016')	/* Ctrl-N Hangul delimiter */
				return(18);
			if(c == '\017' || c == '\024')	/* Ctrl-O Ctrl-T English delimiter */
				return(19);
			return(20);
	}
}

/* This routine make 2-byte code from hangul buffer, if parameter (1)
    is given, han_buf[4] or han_buf[3] is eliminated before making a
    2-byte code and inserted han_buf[1] after 2-byte code is made */

KCHAR make_2(n)
register int n;
{
	register KCHAR code_2 = 0;
	register char tmp = 0;
	register int i;

			/* if n = 1, save han_buf[3] or han_buf[4] */
	if (n == 1) {
		if(han_buf[4]){
			tmp = han_buf[4];
			han_buf[4] = 0;
		} else{
			tmp = han_buf[3];
			han_buf[3] = 0;
		}
	}

	if(han_buf[1] > BEG_OF_CONSO){
		code_2 = code_2 | X32_19[han_buf[1] - BEG_OF_CONSO];
	} else {
		code_2 = 0x9;
	}

	if(han_buf[2] > BEG_OF_VOW){
		code_2 = ((code_2 << 5) | X32_21[han_buf[2] - BEG_OF_VOW]);
	} else{
		code_2 = (code_2 << 5) | 0x1;
	}

	if(han_buf[3] > BEG_OF_CONSO){
		code_2 = ((code_2 << 5) | X32_28[han_buf[3] - BEG_OF_CONSO]);
	} else {
		code_2 = code_2 << 5 | 0x01;
	}

	if(han_buf[4] > BEG_OF_CONSO){
		switch(han_buf[3]){
				/* process gi-ug si-od */
			case GI_UG:
				if(han_buf[4] == SI_OD){
					code_2 += 2;
				}
				break;

				/* process ni-un zi-ud, ni-un hi-ud */
			case NI_UN:
				switch (han_buf[4]) {
				case JI_UD:
					code_2++;
					break;
				case HI_UD:
					code_2 += 2;
					break;
				default:
					break;
				}
				break;

				/* process ri-ul gi-ug, ri-ul mi-um,
				     ri-ul bi-ub, ri-ul si-od, ri-ul ti-ut,
				     ri-ul pi-up, ri-ul hi-ud */
			case RI_UL:
				switch (han_buf[4]) {
				case GI_UG:
					code_2++;
					break;

				case MI_UM:
					code_2 += 2;
					break;

				case BI_UB:
					code_2 += 3;
					break;

				case SI_OD:
					code_2 += 4;
					break;

				case TI_GUT:
					code_2 += 5;
					break;

				case PI_UP:
					code_2 += 6;
					break;

				case HI_UD:
					code_2 += 7;
					break;

				default:
					break;
				}
				break;

				/* process bi-ub si-od */
			case BI_UB:
				if(han_buf[4] == SI_OD){
					code_2++;
				}
				break;

				/* process si-od si-od */
			case SI_OD:
				if(han_buf[4] == SI_OD){
					code_2++;
				}
				break;
		}
	}

				/* set 1st 7-bit of code_2 */
	code_2 = code_2 | 0x8000;

				/* initialize Hangul buffer */
	if(n != 2)
		for(i = 0; i < 5; i++){
			han_buf[i] = 0;
		}

	if(n == 1){			/* restore Hangul temporary */
		han_buf[1] = tmp;
	}

	return(code_2);
}

/* This routine make double vowel from han_buf[2] and input character c */

#ifndef SUNVIEW
char vowel_mix(char c1,char c2)
{
	register char c = '\0';	/* result double vowel */

	switch(c1){
				/* process o-a, o-ae, o-i */
		case O:
			switch (c2) {
			case A:
				c = c1 + 1;
				break;
			case AE:
				c = c1 + 2;
				break;
			case I:
				c = c1 + 3;
				break;
			}
			break;

				/* process u-oe, u-e, u-i */
		case U:
			switch (c2) {
			case E:
				c = c1 + 1;
				break;
			case EA:
				c = c1 + 2;
				break;
			case I:
				c = c1 + 3;
				break;
			}
			break;

				/* process eu-i */
		case EU:
			if(c2 == I){
				c = c1 + 1;
			}
			break;
	}
	return(c);
}
#endif
