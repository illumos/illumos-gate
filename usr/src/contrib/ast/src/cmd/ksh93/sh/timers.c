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

#include	<ast.h>
#include	<sig.h>
#include	<error.h>
#include	"fault.h"
#include	"defs.h"
#include	"FEATURE/sigfeatures"
#include	"FEATURE/time"

typedef struct _timer
{
	double		wakeup;
	double		incr;
	struct _timer	*next;
	void 		(*action)(void*);
	void		*handle;
} Timer_t;

#define IN_ADDTIMEOUT	1
#define IN_SIGALRM	2
#define DEFER_SIGALRM	4
#define SIGALRM_CALL	8

static Timer_t *tptop, *tpmin, *tpfree;
static char time_state;

static double getnow(void)
{
	register double now;
#ifdef timeofday
	struct timeval tp;
	timeofday(&tp);
	now = tp.tv_sec + 1.e-6*tp.tv_usec;

#else
	now = (double)time((time_t*)0);
#endif /* timeofday */
	return(now+.001);
}

/*
 * set an alarm for <t> seconds
 */
static double setalarm(register double t)
{
#if defined(_lib_setitimer) && defined(ITIMER_REAL)
	struct itimerval tnew, told;
	tnew.it_value.tv_sec = t;
	tnew.it_value.tv_usec = 1.e6*(t- (double)tnew.it_value.tv_sec);
	if(t && tnew.it_value.tv_sec==0 && tnew.it_value.tv_usec<1000)
		tnew.it_value.tv_usec = 1000;
	tnew.it_interval.tv_sec = 0;
	tnew.it_interval.tv_usec = 0;
	if(setitimer(ITIMER_REAL,&tnew,&told) < 0)
		errormsg(SH_DICT,ERROR_system(1),e_alarm);
	t = told.it_value.tv_sec + 1.e-6*told.it_value.tv_usec;
#else
	unsigned seconds = (unsigned)t;
	if(t && seconds<1)
		seconds=1;
	t = (double)alarm(seconds);
#endif
	return(t);
}

/* signal handler for alarm call */
static void sigalrm(int sig)
{
	register Timer_t *tp, *tplast, *tpold, *tpnext;
	double now;
	static double left;
	NOT_USED(sig);
	left = 0;
	if(time_state&SIGALRM_CALL)
		time_state &= ~SIGALRM_CALL;
	else if(alarm(0))
		kill(getpid(),SIGALRM|SH_TRAP);
	if(time_state)
	{
		if(time_state&IN_ADDTIMEOUT)
			time_state |= DEFER_SIGALRM;
		errno = EINTR;
		return;
	}
	time_state |= IN_SIGALRM;
	sigrelease(SIGALRM);
	while(1)
	{
		now = getnow();
		tpold = tpmin = 0;
		for(tplast=0,tp=tptop; tp; tp=tpnext)
		{
			tpnext = tp->next;
			if(tp->action)
			{
				if(tp->wakeup <=now)
				{
					if(!tpold || tpold->wakeup>tp->wakeup)
						tpold = tp;
				}
				else
				{
					if(!tpmin || tpmin->wakeup>tp->wakeup)
						tpmin=tp;
				}
				tplast = tp;
			}
			else
			{
				if(tplast)
					tplast->next = tp->next;
				else
					tptop = tp->next;
				tp->next = tpfree;
				tpfree = tp;
			}
		}
		if((tp=tpold) && tp->incr)
		{
			while((tp->wakeup += tp->incr) <= now);
			if(!tpmin || tpmin->wakeup>tp->wakeup)
				tpmin=tp;
		}
		if(tpmin && (left==0 || (tp && tpmin->wakeup < (now+left))))
		{
			if(left==0)
				signal(SIGALRM,sigalrm);
			left = setalarm(tpmin->wakeup-now);
			if(left && (now+left) < tpmin->wakeup)
				setalarm(left);
			else
				left=tpmin->wakeup-now;
		}
		if(tp)
		{
			void	(*action)(void*);
			action = tp->action;
			if(!tp->incr)
				tp->action = 0;
			errno = EINTR;
			time_state &= ~IN_SIGALRM;
			(*action)(tp->handle);
			time_state |= IN_SIGALRM;
		}
		else
			break;
	}
	if(!tpmin)
		signal(SIGALRM,(sh.sigflag[SIGALRM]&SH_SIGFAULT)?sh_fault:SIG_DFL);
	time_state &= ~IN_SIGALRM;
	errno = EINTR;
}

static void oldalrm(void *handle)
{
	Handler_t fn = *(Handler_t*)handle;
	free(handle);
	(*fn)(SIGALRM);
}
	
void *sh_timeradd(unsigned long msec,int flags,void (*action)(void*),void *handle) 
{
	register Timer_t *tp;
	double t;
	Handler_t fn;
	t = ((double)msec)/1000.;
	if(t<=0 || !action)
		return((void*)0);
	if(tp=tpfree)
		tpfree = tp->next;
	else if(!(tp=(Timer_t*)malloc(sizeof(Timer_t))))
		return((void*)0);
	tp->wakeup = getnow() + t;
	tp->incr = (flags?t:0);
	tp->action = action;
	tp->handle = handle;
	time_state |= IN_ADDTIMEOUT;
	tp->next = tptop;
	tptop = tp;
	if(!tpmin || tp->wakeup < tpmin->wakeup)
	{
		tpmin = tp;
		fn = (Handler_t)signal(SIGALRM,sigalrm);
		if((t= setalarm(t))>0 && fn  && fn!=(Handler_t)sigalrm)
		{
			Handler_t *hp = (Handler_t*)malloc(sizeof(Handler_t));
			if(hp)
			{
				*hp = fn;
				sh_timeradd((long)(1000*t), 0, oldalrm, (void*)hp);
			}
		}
		tp = tptop;
	}
	else if(tpmin && !tpmin->action)
		time_state |= DEFER_SIGALRM;
	time_state &= ~IN_ADDTIMEOUT;
	if(time_state&DEFER_SIGALRM)
	{
		time_state=SIGALRM_CALL;
		sigalrm(SIGALRM);
		if(tp!=tptop)
			tp=0;
	}
	return((void*)tp);
}

/*
 * delete timer <tp>.  If <tp> is NULL, all timers are deleted
 */
void	timerdel(void *handle)
{
	register Timer_t *tp = (Timer_t*)handle;
	if(tp)
		tp->action = 0;
	else
	{
		for(tp=tptop; tp; tp=tp->next)
			tp->action = 0;
		if(tpmin)
		{
			tpmin = 0;
			setalarm((double)0);
		}
		signal(SIGALRM,(sh.sigflag[SIGALRM]&SH_SIGFAULT)?sh_fault:SIG_DFL);
	}
}

