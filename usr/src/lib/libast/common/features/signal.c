/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*           Copyright (c) 1985-2007 AT&T Knowledge Ventures            *
*                      and is licensed under the                       *
*                  Common Public License, Version 1.0                  *
*                      by AT&T Knowledge Ventures                      *
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
*                  David Korn <dgk@research.att.com>                   *
*                   Phong Vo <kpv@research.att.com>                    *
*                                                                      *
***********************************************************************/
#pragma prototyped
/*
 * Glenn Fowler
 * AT&T Bell Laboratories
 *
 * generate signal features
 */

#include <signal.h>

struct _m_
{
	char*		text;
	char*		name;
	int		value;
};

#define elementsof(x)	(sizeof(x)/sizeof(x[0]))

static struct _m_ map[] =
{
#ifdef SIGABRT
"Abort",			"ABRT",		SIGABRT,
#endif
#ifdef SIGAIO
"Asynchronous I/O",		"AIO",		SIGAIO,
#endif
#ifdef SIGALRM
"Alarm call",			"ALRM",		SIGALRM,
#endif
#ifdef SIGAPOLLO
"Apollo",			"APOLLO",	SIGAPOLLO,
#endif
#ifdef SIGBUS
"Bus error",			"BUS",		SIGBUS,
#endif
#ifdef SIGCHLD
"Child status change",		"CHLD",		SIGCHLD,
#endif
#ifdef SIGCLD
"Death of child", 		"CLD",		SIGCLD,
#endif
#ifdef SIGCONT
"Stopped process continued",	"CONT",		SIGCONT,
#endif
#ifdef SIGDANGER
"System crash soon",		"DANGER",	SIGDANGER,
#endif
#ifdef SIGDEBUG
"Debug trap",			"DEBUG",	SIGDEBUG,
#endif
#ifdef SIGDIL
"DIL trap",			"DIL",		SIGDIL,
#endif
#ifdef SIGEMT
"EMT trap",			"EMT",		SIGEMT,
#endif
#ifdef SIGERR
"ERR trap",			"ERR",		SIGERR,
#endif
#ifdef SIGEXIT
"Exit",				"EXIT",		SIGEXIT,
#endif
#ifdef SIGFPE
"Floating exception",		"FPE",		SIGFPE,
#endif
#ifdef SIGFREEZE
"CPR freeze",			"FREEZE",	SIGFREEZE,
#endif
#ifdef SIGHUP
"Hangup",			"HUP",		SIGHUP,
#endif
#ifdef SIGILL
"Illegal instruction",		"ILL",		SIGILL,
#endif
#ifdef SIGINT
"Interrupt",			"INT",		SIGINT,
#endif
#ifdef SIGIO
"IO possible",			"IO",		SIGIO,
#endif
#ifdef SIGIOT
"IOT trap",			"IOT",		SIGIOT,
#endif
#ifdef SIGKILL
"Killed",			"KILL",		SIGKILL,
#endif
#ifdef SIGLAB
"Security label changed",	"LAB",		SIGLAB,
#endif
#ifdef SIGLOST
"Resources lost",		"LOST",		SIGLOST,
#endif
#ifdef SIGLWP
"Thread event",			"LWP",		SIGLWP,
#endif
#ifdef SIGMIGRATE
"Migrate process",		"MIGRATE",	SIGMIGRATE,
#endif
#ifdef SIGPHONE
"Phone status change",		"PHONE",	SIGPHONE,
#endif
#ifdef SIGPIPE
"Broken pipe",			"PIPE",		SIGPIPE,
#endif
#ifdef SIGPOLL
"Poll event",			"POLL",		SIGPOLL,
#endif
#ifdef SIGPROF
"Profile timer alarm",		"PROF",		SIGPROF,
#endif
#ifdef SIGPWR
"Power fail",			"PWR",		SIGPWR,
#endif
#ifdef SIGQUIT
"Quit",				"QUIT",		SIGQUIT,
#endif
#ifdef SIGSEGV
"Memory fault",			"SEGV",		SIGSEGV,
#endif
#ifdef SIGSOUND
"Sound completed",		"SOUND",	SIGSOUND,
#endif
#ifdef SIGSSTOP
"Sendable stop",		"SSTOP",	SIGSSTOP,
#endif
#ifdef gould
"Stack overflow",		"STKOV",	28,
#endif
#ifdef SIGSTOP
"Stopped (signal)",		"STOP",		SIGSTOP,
#endif
#ifdef SIGSYS
"Bad system call", 		"SYS",		SIGSYS,
#endif
#ifdef SIGTERM
"Terminated",			"TERM",		SIGTERM,
#endif
#ifdef SIGTHAW
"CPR thaw",			"THAW",		SIGTHAW,
#endif
#ifdef SIGTINT
"Interrupt (terminal)",		"TINT",		SIGTINT,
#endif
#ifdef SIGTRAP
"Trace trap",			"TRAP",		SIGTRAP,
#endif
#ifdef SIGTSTP
"Stopped",			"TSTP",		SIGTSTP,
#endif
#ifdef SIGTTIN
"Stopped (tty input)",		"TTIN",		SIGTTIN,
#endif
#ifdef SIGTTOU
"Stopped (tty output)",		"TTOU",		SIGTTOU,
#endif
#ifdef SIGURG
"Urgent IO",			"URG",		SIGURG,
#endif
#ifdef SIGUSR1
"User signal 1",		"USR1",		SIGUSR1,
#endif
#ifdef SIGUSR2
"User signal 2",		"USR2",		SIGUSR2,
#endif
#ifdef SIGVTALRM
"Virtual timer alarm",		"VTALRM",	SIGVTALRM,
#endif
#ifdef SIGWAITING
"All threads blocked",		"WAITING",	SIGWAITING,
#endif
#ifdef SIGWINCH
"Window change", 		"WINCH",	SIGWINCH,
#endif
#ifdef SIGWIND
"Window change",		"WIND",		SIGWIND,
#endif
#ifdef SIGWINDOW
"Window change",		"WINDOW",	SIGWINDOW,
#endif
#ifdef SIGXCPU
"CPU time limit",		"XCPU",		SIGXCPU,
#endif
#ifdef SIGXFSZ
"File size limit",		"XFSZ",		SIGXFSZ,
#endif
0
};

#define RANGE_MIN	(1<<14)
#define RANGE_MAX	(1<<13)
#define RANGE_RT	(1<<12)

#define RANGE_SIG	(~(RANGE_MIN|RANGE_MAX|RANGE_RT))

static int		index[64];

int
main()
{
	register int	i;
	register int	j;
	register int	k;
	int		n;

	k = 0;
	for (i = 0; map[i].name; i++)
		if ((j = map[i].value) > 0 && j < elementsof(index) && !index[j])
		{
			if (j > k) k = j;
			index[j] = i;
		}
#ifdef SIGRTMIN
	i = SIGRTMIN;
#ifdef SIGRTMAX
	j = SIGRTMAX;
#else
	j = i;
#endif
	if (j >= elementsof(index)) j = elementsof(index) - 1;
	if (i <= j && i > 0 && i < elementsof(index) && j > 0 && j < elementsof(index))
	{
		if (j > k) k = j;
		index[i] = RANGE_MIN | RANGE_RT;
		n = 1;
		while (++i < j)
			index[i] = RANGE_RT | n++;
		index[j] = RANGE_MAX | RANGE_RT | n;
	}
#endif
	printf("#pragma prototyped\n");
	printf("#define SIG_MAX	%d\n", k);
	printf("\n");
	printf("static const char* const	sig_name[] =\n");
	printf("{\n");
	for (i = 0; i <= k; i++)
		if (!(j = index[i])) printf("	\"%d\",\n", i);
		else if (j & RANGE_RT)
		{
			if (j & RANGE_MIN) printf("	\"RTMIN\",\n");
			else if (j & RANGE_MAX) printf("	\"RTMAX\",\n");
			else printf("	\"RT%d\",\n", j & RANGE_SIG);
		}
		else printf("	\"%s\",\n", map[j].name);
	printf("	0\n");
	printf("};\n");
	printf("\n");
	printf("static const char* const	sig_text[] =\n");
	printf("{\n");
	for (i = 0; i <= k; i++)
		if (!(j = index[i])) printf("	\"Signal %d\",\n", i);
		else if (j & RANGE_RT) printf("	\"Realtime priority %d%s\",\n", j & RANGE_SIG, (j & RANGE_MIN) ? " (lo)" : (j & RANGE_MAX) ? " (hi)" : "");
		else printf("	\"%s\",\n", map[j].text);
	printf("	0\n");
	printf("};\n");
	return 0;
}
