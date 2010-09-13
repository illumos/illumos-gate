/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"
	  /* from UCB 4.2 83/07/08 */

#include	<ctype.h>
#include	<stdlib.h>


char	_ctype_[] = { 0,

/*	 0	 	1	 2	 3	 4	 5	 6	 7  */

/* 0*/	_C,		_C,	_C,	_C,	_C,	_C,	_C,	_C,
/* 10*/	_C,		_S|_C,	_S|_C,	_S|_C,	_S|_C,	_S|_C,	_C,	_C,
/* 20*/	_C,		_C,	_C,	_C,	_C,	_C,	_C,	_C,
/* 30*/	_C,		_C,	_C,	_C,	_C,	_C,	_C,	_C,
/* 40*/	(char)(_S|_B),	_P,	_P,	_P,	_P,	_P,	_P,	_P,
/* 50*/	_P,		_P,	_P,	_P,	_P,	_P,	_P,	_P,
/* 60*/	_N|_X,		_N|_X,	_N|_X,	_N|_X,	_N|_X,	_N|_X,	_N|_X,	_N|_X,
/* 70*/	_N|_X,		_N|_X,	_P,	_P,	_P,	_P,	_P,	_P,
/*100*/	_P,		_U|_X,	_U|_X,	_U|_X,	_U|_X,	_U|_X,	_U|_X,	_U,
/*110*/	_U,		_U,	_U,	_U,	_U,	_U,	_U,	_U,
/*120*/	_U,		_U,	_U,	_U,	_U,	_U,	_U,	_U,
/*130*/	_U,		_U,	_U,	_P,	_P,	_P,	_P,	_P,
/*140*/	_P,		_L|_X,	_L|_X,	_L|_X,	_L|_X,	_L|_X,	_L|_X,	_L,
/*150*/	_L,		_L,	_L,	_L,	_L,	_L,	_L,	_L,
/*160*/	_L,		_L,	_L,	_L,	_L,	_L,	_L,	_L,
/*170*/	_L,		_L,	_L,	_P,	_P,	_P,	_P,	_C,
/*200*/	 0,	 	0,	 0,	 0,	 0,	 0,	 0,	 0,
	 0,	 	0,	 0,	 0,	 0,	 0,	 0,	 0,
	 0,	 	0,	 0,	 0,	 0,	 0,	 0,	 0,
	 0,	 	0,	 0,	 0,	 0,	 0,	 0,	 0,
	 0,	 	0,	 0,	 0,	 0,	 0,	 0,	 0,
	 0,	 	0,	 0,	 0,	 0,	 0,	 0,	 0,
	 0,	 	0,	 0,	 0,	 0,	 0,	 0,	 0,
	 0,	 	0,	 0,	 0,	 0,	 0,	 0,	 0,
	 0,	 	0,	 0,	 0,	 0,	 0,	 0,	 0,
	 0,	 	0,	 0,	 0,	 0,	 0,	 0,	 0,
	 0,	 	0,	 0,	 0,	 0,	 0,	 0,	 0,
	 0,	 	0,	 0,	 0,	 0,	 0,	 0,	 0,
	 0,	 	0,	 0,	 0,	 0,	 0,	 0,	 0,
	 0,	 	0,	 0,	 0,	 0,	 0,	 0,	 0,
	 0,	 	0,	 0,	 0,	 0,	 0,	 0,	 0,
	 0,	 	0,	 0,	 0,	 0,	 0,	 0,	 0
};

unsigned int	_mb_cur_max;

/* Now we also supply the functions in libc as well as the macros in
 * ctype.h
 */

#undef	isalpha
#undef	isupper
#undef	islower
#undef	isdigit
#undef	isxdigit
#undef	isspace
#undef	ispunct
#undef	isalnum
#undef	isprint
#undef	isgraph
#undef	iscntrl
#undef	isascii
#undef	toascii

extern int mbtowc();

int isalpha(c)	
register int c;
{
	return((_ctype_+1)[c]&(_U|_L));
}

int isupper(c)
register int c;
{
	return((_ctype_+1)[c]&_U);
}

int islower(c)	
register int c;
{
	return((_ctype_+1)[c]&_L);
}

int isdigit(c)	
register int c;
{
	return((_ctype_+1)[c]&_N);
}

int isxdigit(c)	
register int c;
{
	return((_ctype_+1)[c]&_X);
}


int isspace(c)	
register int c;
{
	return((_ctype_+1)[c]&_S);
}


int ispunct(c)	
register int c;
{
	return((_ctype_+1)[c]&_P);
}


int isalnum(c)	
register int c;
{
	return((_ctype_+1)[c]&(_U|_L|_N));
}


int isprint(c)	
register int c;
{
	return((_ctype_+1)[c]&(_P|_U|_L|_N|_B));
}


int isgraph(c)	
register int c;
{
	return((_ctype_+1)[c]&(_P|_U|_L|_N));
}


int iscntrl(c)	
register int c;
{
	return((_ctype_+1)[c]&_C);
}

int isascii(c)	
register int c;
{
	return((unsigned)(c)<=0177);
}

int toascii(c)	
register int c;
{
	return((c)&0177);
}

