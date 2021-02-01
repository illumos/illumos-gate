/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1982-2012 AT&T Intellectual Property          *
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
*                  David Korn <dgk@research.att.com>                   *
*                                                                      *
***********************************************************************/
#pragma prototyped
/*
 * ulimit [-HSacdfmnstuv] [limit]
 *
 *   David Korn
 *   AT&T Labs
 *
 */

#include	<ast.h>
#include	<sfio.h>
#include	<error.h>
#include	"defs.h"
#include	"builtins.h"
#include	"name.h"
#include	"ulimit.h"
#ifndef SH_DICT
#   define SH_DICT	"libshell"
#endif

#ifdef _no_ulimit
	int	b_ulimit(int argc,char *argv[],Shbltin_t *context)
	{
		NOT_USED(argc);
		NOT_USED(argv);
		NOT_USED(context);
		errormsg(SH_DICT,ERROR_exit(2),e_nosupport);
		return(0);
	}
#else

static int infof(Opt_t* op, Sfio_t* sp, const char* s, Optdisc_t* dp)
{
	register const Limit_t*	tp;

	for (tp = shtab_limits; tp->option; tp++)
	{
		sfprintf(sp, "[%c=%d:%s?The %s", tp->option, tp - shtab_limits + 1, tp->name, tp->description);
		if(tp->type != LIM_COUNT)
			sfprintf(sp, " in %ss", e_units[tp->type]);
		sfprintf(sp, ".]");
	}
        return(1);
}

#define HARD	2
#define SOFT	4

int	b_ulimit(int argc,char *argv[],Shbltin_t *context)
{
	register char *limit;
	register int mode=0, n;
	register unsigned long hit = 0;
	Shell_t *shp = context->shp;
#ifdef _lib_getrlimit
	struct rlimit rlp;
#endif /* _lib_getrlimit */
	const Limit_t* tp;
	char* conf;
	int label, unit, nosupport;
	rlim_t i;
	char tmp[32];
        Optdisc_t disc;
        memset(&disc, 0, sizeof(disc));
        disc.version = OPT_VERSION;
        disc.infof = infof;
	opt_info.disc = &disc;
	while((n = optget(argv,sh_optulimit))) switch(n)
	{
		case 'H':
			mode |= HARD;
			continue;
		case 'S':
			mode |= SOFT;
			continue;
		case 'a':
			hit = ~0;
			break;
		default:
			if(n < 0)
				hit |= (1L<<(-(n+1)));
			else
				errormsg(SH_DICT,2, e_notimp, opt_info.name);
			break;
		case ':':
			errormsg(SH_DICT,2, "%s", opt_info.arg);
			break;
		case '?':
			errormsg(SH_DICT,ERROR_usage(2), "%s", opt_info.arg);
			break;
	}
	opt_info.disc = 0;
	/* default to -f */
	limit = argv[opt_info.index];
	if(hit==0)
		for(n=0; shtab_limits[n].option; n++)
			if(shtab_limits[n].index == RLIMIT_FSIZE)
			{
				hit |= (1L<<n);
				break;
			}
	/* only one option at a time for setting */
	label = (hit&(hit-1));
	if(error_info.errors || (limit && label) || argc>opt_info.index+1)
		errormsg(SH_DICT,ERROR_usage(2),optusage((char*)0));
	if(mode==0)
		mode = (HARD|SOFT);
	for(tp = shtab_limits; tp->option && hit; tp++,hit>>=1)
	{
		if(!(hit&1))
			continue;
		nosupport = (n = tp->index) == RLIMIT_UNKNOWN;
		unit = shtab_units[tp->type];
		if(limit)
		{
			if(shp->subshell && !shp->subshare)
				sh_subfork();
			if(strcmp(limit,e_unlimited)==0)
				i = INFINITY;
			else
			{
				char *last;
				/* an explicit suffix unit overrides the default */
				if((i=strtol(limit,&last,0))!=INFINITY && !*last)
					i *= unit;
				else if((i=strton(limit,&last,NiL,0))==INFINITY || *last)
				{
					if((i=sh_strnum(limit,&last,2))==INFINITY || *last)
						errormsg(SH_DICT,ERROR_system(1),e_number,limit);
					i *= unit;
				}
			}
			if(nosupport)
				errormsg(SH_DICT,ERROR_system(1),e_readonly,tp->name);
			else
			{
#ifdef _lib_getrlimit
				if(getrlimit(n,&rlp) <0)
					errormsg(SH_DICT,ERROR_system(1),e_number,limit);
				if(mode&HARD)
					rlp.rlim_max = i;
				if(mode&SOFT)
					rlp.rlim_cur = i;
				if(setrlimit(n,&rlp) <0)
					errormsg(SH_DICT,ERROR_system(1),e_overlimit,limit);
#else
				if((i=vlimit(n,i)) < 0)
					errormsg(SH_DICT,ERROR_system(1),e_number,limit);
#endif /* _lib_getrlimit */
			}
		}
		else
		{
			if(!nosupport)
			{
#ifdef  _lib_getrlimit
				if(getrlimit(n,&rlp) <0)
					errormsg(SH_DICT,ERROR_system(1),e_number,limit);
				if(mode&HARD)
					i = rlp.rlim_max;
				if(mode&SOFT)
					i = rlp.rlim_cur;
#else
#   ifdef _lib_ulimit
				n--;
#   endif /* _lib_ulimit */
				i = -1;
				if((i=vlimit(n,i)) < 0)
					errormsg(SH_DICT,ERROR_system(1),e_number,limit);
#endif /* _lib_getrlimit */
			}
			if(label)
			{
				if(tp->type != LIM_COUNT)
					sfsprintf(tmp,sizeof(tmp),"%s (%ss)", tp->description, e_units[tp->type]);
				else
					sfsprintf(tmp,sizeof(tmp),"%s", tp->name);
				sfprintf(sfstdout,"%-30s (-%c)  ",tmp,tp->option);
			}
			if(nosupport)
			{
				if(!tp->conf || !*(conf = astconf(tp->conf, NiL, NiL)))
					conf = (char*)e_nosupport;
				sfputr(sfstdout,conf,'\n');
			}
			else if(i!=INFINITY)
			{
				i += (unit-1);
				sfprintf(sfstdout,"%I*d\n",sizeof(i),i/unit);
			}
			else
				sfputr(sfstdout,e_unlimited,'\n');
		}
	}
	return(0);
}
#endif /* _no_ulimit */
