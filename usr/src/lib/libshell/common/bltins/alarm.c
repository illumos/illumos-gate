/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1982-2010 AT&T Intellectual Property          *
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
*                  David Korn <dgk@research.att.com>                   *
*                                                                      *
***********************************************************************/
#pragma prototyped
/*
 * alarm [-r] [varname [+]when]
 *
 *   David Korn
 *   AT&T Labs
 *
 */

#include	"defs.h"
#include	<error.h>
#include	<stak.h>
#include	"builtins.h"
#include	"FEATURE/time"

#define R_FLAG	1
#define L_FLAG	2

struct	tevent
{
	Namfun_t	fun;
	Namval_t	*node;
	Namval_t	*action;
	struct tevent	*next;
	long		milli;
	int		flags;
	void            *timeout;
	Shell_t		*sh;
};

static const char ALARM[] = "alarm";

static void	trap_timeout(void*);

/*
 * insert timeout item on current given list in sorted order
 */
static void *time_add(struct tevent *item, void *list)
{
	register struct tevent *tp = (struct tevent*)list;
	if(!tp || item->milli < tp->milli)
	{
		item->next = tp;
		list = (void*)item;
	}
	else
	{
		while(tp->next && item->milli > tp->next->milli)
			tp = tp->next;
		item->next = tp->next;
		tp->next = item;
	}
	tp = item;
	tp->timeout = (void*)sh_timeradd(tp->milli,tp->flags&R_FLAG,trap_timeout,(void*)tp);
	return(list);
}

/*
 * delete timeout item from current given list, delete timer
 */
static 	void *time_delete(register struct tevent *item, void *list)
{
	register struct tevent *tp = (struct tevent*)list;
	if(item==tp)
		list = (void*)tp->next;
	else
	{
		while(tp && tp->next != item)
			tp = tp->next;
		if(tp)
			tp->next = item->next;
	}
	if(item->timeout)
		timerdel((void*)item->timeout);
	return(list);
}

static void	print_alarms(void *list)
{
	register struct tevent *tp = (struct tevent*)list;
	while(tp)
	{
		if(tp->timeout)
		{
			register char *name = nv_name(tp->node);
			if(tp->flags&R_FLAG)
			{
				double d = tp->milli;
				sfprintf(sfstdout,e_alrm1,name,d/1000.);
			}
			else
				sfprintf(sfstdout,e_alrm2,name,nv_getnum(tp->node));
		}
		tp = tp->next;
	}
}

static void	trap_timeout(void* handle)
{
	register struct tevent *tp = (struct tevent*)handle;
	tp->sh->trapnote |= SH_SIGALRM;
	if(!(tp->flags&R_FLAG))
		tp->timeout = 0;
	tp->flags |= L_FLAG;
	tp->sh->sigflag[SIGALRM] |= SH_SIGALRM;
	if(sh_isstate(SH_TTYWAIT))
		sh_timetraps();
}

void	sh_timetraps(void)
{
	register struct tevent *tp, *tpnext;
	register struct tevent *tptop;
	while(1)
	{
		sh.sigflag[SIGALRM] &= ~SH_SIGALRM;
		tptop= (struct tevent*)sh.st.timetrap;
		for(tp=tptop;tp;tp=tpnext)
		{
			tpnext = tp->next;
			if(tp->flags&L_FLAG)
			{
				tp->flags &= ~L_FLAG;
				if(tp->action)
					sh_fun(tp->action,tp->node,(char**)0);
				tp->flags &= ~L_FLAG;
				if(!tp->flags)
				{
					nv_unset(tp->node);
					nv_close(tp->node);
				}
			}
		}
		if(!(sh.sigflag[SIGALRM]&SH_SIGALRM))
			break;
	}
}


/*
 * This trap function catches "alarm" actions only
 */
static char *setdisc(Namval_t *np, const char *event, Namval_t* action, Namfun_t
 *fp)
{
        register struct tevent *tp = (struct tevent*)fp;
	if(!event)
		return(action?"":(char*)ALARM);
	if(strcmp(event,ALARM)!=0)
	{
		/* try the next level */
		return(nv_setdisc(np, event, action, fp));
	}
	if(action==np)
		action = tp->action;
	else
		tp->action = action;
	return(action?(char*)action:"");
}

/*
 * catch assignments and set alarm traps
 */
static void putval(Namval_t* np, const char* val, int flag, Namfun_t* fp)
{
	register struct tevent *tp;
	register double d;
	if(val)
	{
		double now;
#ifdef timeofday
		struct timeval tmp;
		timeofday(&tmp);
		now = tmp.tv_sec + 1.e-6*tmp.tv_usec;
#else
		now = (double)time(NIL(time_t*));
#endif /* timeofday */
		nv_putv(np,val,flag,fp);
		d = nv_getnum(np);
		tp = (struct tevent*)fp;
		if(*val=='+')
		{
			double x = d + now;
			nv_putv(np,(char*)&x,NV_INTEGER,fp);
		}
		else
			d -= now;
		tp->milli = 1000*(d+.0005);
		if(tp->timeout)
			sh.st.timetrap = time_delete(tp,sh.st.timetrap);
		if(tp->milli > 0)
			sh.st.timetrap = time_add(tp,sh.st.timetrap);
	}
	else
	{
		tp = (struct tevent*)nv_stack(np, (Namfun_t*)0);
		sh.st.timetrap = time_delete(tp,sh.st.timetrap);
		if(tp->action)
			nv_close(tp->action);
		nv_unset(np);
		free((void*)fp);
	}
}

static const Namdisc_t alarmdisc =
{
	sizeof(struct tevent),
	putval,
	0,
	0,
	setdisc,
};

int	b_alarm(int argc,char *argv[],void *extra)
{
	register int n,rflag=0;
	register Namval_t *np;
	register struct tevent *tp;
	register Shell_t *shp = ((Shbltin_t*)extra)->shp;
	while (n = optget(argv, sh_optalarm)) switch (n)
	{
	    case 'r':
		rflag = R_FLAG;
		break;
	    case ':':
		errormsg(SH_DICT,2, "%s", opt_info.arg);
		break;
	    case '?':
		errormsg(SH_DICT,ERROR_usage(2), "%s", opt_info.arg);
		break;
	}
	argc -= opt_info.index;
	argv += opt_info.index;
	if(error_info.errors)
		errormsg(SH_DICT,ERROR_usage(2),optusage((char*)0));
	if(argc==0)
	{
		print_alarms(shp->st.timetrap);
		return(0);
	}
	if(argc!=2)
		errormsg(SH_DICT,ERROR_usage(2),optusage((char*)0));
	np = nv_open(argv[0],shp->var_tree,NV_NOARRAY|NV_VARNAME|NV_NOASSIGN);
	if(!nv_isnull(np))
		nv_unset(np);
	nv_setattr(np, NV_DOUBLE);
	if(!(tp = newof(NIL(struct tevent*),struct tevent,1,0)))
		errormsg(SH_DICT,ERROR_exit(1),e_nospace);
	tp->fun.disc = &alarmdisc;
	tp->flags = rflag;
	tp->node = np;
	tp->sh = shp;
	nv_stack(np,(Namfun_t*)tp);
	nv_putval(np, argv[1], 0);
	return(0);
}

