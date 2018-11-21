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


#include <stdlib.h>
#include <errno.h>
#include "ktable.h"
#include "nbyte_utf.h"


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
		unsigned long	ci, v, cf;
		char		result;
		int		input_conv(char);
		unsigned short	make_johap_code(int, char*);
		extern char	_johap_to_utf8(unsigned long*, unsigned long*,
						unsigned long*, unsigned short);

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
