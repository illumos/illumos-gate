/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1986-2008 AT&T Intellectual Property          *
*                      and is licensed under the                       *
*                  Common Public License, Version 1.0                  *
*                    by AT&T Intellectual Property                     *
*                                                                      *
*                A copy of the License is available at                 *
*            http://www.opensource.org/licenses/cpl1.0.txt             *
*         (with md5 checksum 059e8cd6165cb4c31e351f2b69388fd9)         *
*                                                                      *
*              Information and Software Systems Research               *
*                            AT&T Research                             *
*                           Florham Park NJ                            *
*                                                                      *
*                 Glenn Fowler <gsf@research.att.com>                  *
*                                                                      *
***********************************************************************/
#pragma prototyped
/*
 * Glenn Fowler
 * AT&T Research
 *
 * preprocessor printf using ppputchar() buffering
 */

#include "pplib.h"

int
ppprintf(char* format, ...)
{
	va_list	ap;
	Sfio_t*	sp;

	if (!(sp = sfnew(NiL, pp.outp, MAXTOKEN, -1, SF_WRITE|SF_STRING)))
		error(3, "temporary buffer allocation error");
	va_start(ap, format);
	sfvprintf(sp, format, ap);
	va_end(ap);
	pp.outp += sfseek(sp, 0L, SEEK_CUR);
	ppcheckout();
	sfclose(sp);
	return 0;
}
