/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1985-2011 AT&T Intellectual Property          *
*                      and is licensed under the                       *
*                 Eclipse Public License, Version 1.0                  *
*                    by AT&T Intellectual Property                     *
*                                                                      *
*                A copy of the License is available at                 *
*          http://www.eclipse.org/org/documents/epl-v10.html           *
*         (with md5 checksum b35adb5213ca9657e911e9befb180842)         *
*                                                                      *
*              Information and Software Systems Research               *
*                            AT&T Research                             *
*                           Florham Park NJ                            *
*                                                                      *
*                 Glenn Fowler <gsf@research.att.com>                  *
*                  David Korn <dgk@research.att.com>                   *
*                   Phong Vo <kpv@research.att.com>                    *
*                                                                      *
***********************************************************************/
#include	"sfhdr.h"

#if __STD_C
char *sffcvt(double dval, int n_digit, int* decpt, int* sign)
#else
char *sffcvt(dval,n_digit,decpt,sign)
double	dval;		/* value to convert */
int	n_digit;	/* number of digits wanted */
int*	decpt;		/* to return decimal point */
int*	sign;		/* to return sign */
#endif
{
	int		len;
	static char	buf[SF_MAXDIGITS];

	return _sfcvt(&dval,buf,sizeof(buf),n_digit,decpt,sign,&len,0);
}
