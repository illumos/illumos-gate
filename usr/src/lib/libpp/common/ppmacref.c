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
 * common preprocessor macro reference handler
 */

#include "pplib.h"

void
ppmacref(struct ppsymbol* sym, char* file, int line, int type, unsigned long sum)
{
	register char*	p;

	NoP(file);
	NoP(line);
	p = (pp.state & (DIRECTIVE|JOINING)) == DIRECTIVE ? pp.outp : pp.addp;
	p += sfsprintf(p, MAXTOKEN, "\n#%s %d", pp.lineid, error_info.line);
	p += sfsprintf(p, MAXTOKEN, "\n#%s %s:%s %s %d", dirname(PRAGMA), pp.pass, keyname(X_MACREF), sym->name, type);
	if (type > 0)
	{
		if (sym->macro && sym->macro->value)
			sum = strsum(sym->macro->value, (long)sym->macro->arity);
		p += sfsprintf(p, MAXTOKEN, " %lu", sum);
	}
	if ((pp.state & (DIRECTIVE|JOINING)) == DIRECTIVE)
	{
		pp.outp = p;
		ppcheckout();
	}
	else
	{
		*p++ = '\n';
		pp.addp = p;
		pp.state |= ADD;
	}
	pp.pending = pppendout();
}
