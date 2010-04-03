/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*          Copyright (c) 1985-2010 AT&T Intellectual Property          *
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
*                  David Korn <dgk@research.att.com>                   *
*                   Phong Vo <kpv@research.att.com>                    *
*                                                                      *
***********************************************************************/
#pragma prototyped
/*
 * Glenn Fowler
 * AT&T Research
 *
 * generate signal features
 */

#include "FEATURE/standards"

#define strsignal	______strsignal

#include <signal.h>

#undef	strsignal

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
#define HAD_SIGABRT	1
"Abort",			"ABRT",		SIGABRT,
#endif
#ifdef SIGAIO
#define HAD_SIGAIO	1
"Asynchronous I/O",		"AIO",		SIGAIO,
#endif
#ifdef SIGALRM
#define HAD_SIGALRM	1
"Alarm call",			"ALRM",		SIGALRM,
#endif
#ifdef SIGAPOLLO
#define HAD_SIGAPOLLO	1
"Apollo",			"APOLLO",	SIGAPOLLO,
#endif
#ifdef SIGBUS
#define HAD_SIGBUS	1
"Bus error",			"BUS",		SIGBUS,
#endif
#ifdef SIGCHLD
#define HAD_SIGCHLD	1
"Child status change",		"CHLD",		SIGCHLD,
#endif
#ifdef SIGCLD
#define HAD_SIGCLD	1
"Death of child", 		"CLD",		SIGCLD,
#endif
#ifdef SIGCONT
#define HAD_SIGCONT	1
"Stopped process continued",	"CONT",		SIGCONT,
#endif
#ifdef SIGDANGER
#define HAD_SIGDANGER	1
"System crash soon",		"DANGER",	SIGDANGER,
#endif
#ifdef SIGDEBUG
#define HAD_SIGDEBUG	1
"Debug trap",			"DEBUG",	SIGDEBUG,
#endif
#ifdef SIGDIL
#define HAD_SIGDIL	1
"DIL trap",			"DIL",		SIGDIL,
#endif
#ifdef SIGEMT
#define HAD_SIGEMT	1
"EMT trap",			"EMT",		SIGEMT,
#endif
#ifdef SIGERR
#define HAD_SIGERR	1
"ERR trap",			"ERR",		SIGERR,
#endif
#ifdef SIGEXIT
#define HAD_SIGEXIT	1
"Exit",				"EXIT",		SIGEXIT,
#endif
#ifdef SIGFPE
#define HAD_SIGFPE	1
"Floating exception",		"FPE",		SIGFPE,
#endif
#ifdef SIGFREEZE
#define HAD_SIGFREEZE	1
"CPR freeze",			"FREEZE",	SIGFREEZE,
#endif
#ifdef SIGHUP
#define HAD_SIGHUP	1
"Hangup",			"HUP",		SIGHUP,
#endif
#ifdef SIGILL
#define HAD_SIGILL	1
"Illegal instruction",		"ILL",		SIGILL,
#endif
#ifdef SIGINT
#define HAD_SIGINT	1
"Interrupt",			"INT",		SIGINT,
#endif
#ifdef SIGIO
#define HAD_SIGIO	1
"IO possible",			"IO",		SIGIO,
#endif
#ifdef SIGIOT
#define HAD_SIGIOT	1
"IOT trap",			"IOT",		SIGIOT,
#endif
#ifdef SIGKILL
#define HAD_SIGKILL	1
"Killed",			"KILL",		SIGKILL,
#endif
#ifdef SIGLAB
#define HAD_SIGLAB	1
"Security label changed",	"LAB",		SIGLAB,
#endif
#ifdef SIGLOST
#define HAD_SIGLOST	1
"Resources lost",		"LOST",		SIGLOST,
#endif
#ifdef SIGLWP
#define HAD_SIGLWP	1
"Thread event",			"LWP",		SIGLWP,
#endif
#ifdef SIGMIGRATE
#define HAD_SIGMIGRATE	1
"Migrate process",		"MIGRATE",	SIGMIGRATE,
#endif
#ifdef SIGPHONE
#define HAD_SIGPHONE	1
"Phone status change",		"PHONE",	SIGPHONE,
#endif
#ifdef SIGPIPE
#define HAD_SIGPIPE	1
"Broken pipe",			"PIPE",		SIGPIPE,
#endif
#ifdef SIGPOLL
#define HAD_SIGPOLL	1
"Poll event",			"POLL",		SIGPOLL,
#endif
#ifdef SIGPROF
#define HAD_SIGPROF	1
"Profile timer alarm",		"PROF",		SIGPROF,
#endif
#ifdef SIGPWR
#define HAD_SIGPWR	1
"Power fail",			"PWR",		SIGPWR,
#endif
#ifdef SIGQUIT
#define HAD_SIGQUIT	1
"Quit",				"QUIT",		SIGQUIT,
#endif
#ifdef SIGSEGV
#define HAD_SIGSEGV	1
"Memory fault",			"SEGV",		SIGSEGV,
#endif
#ifdef SIGSOUND
#define HAD_SIGSOUND	1
"Sound completed",		"SOUND",	SIGSOUND,
#endif
#ifdef SIGSSTOP
#define HAD_SIGSSTOP	1
"Sendable stop",		"SSTOP",	SIGSSTOP,
#endif
#ifdef gould
#define HAD_gould	1
"Stack overflow",		"STKOV",	28,
#endif
#ifdef SIGSTOP
#define HAD_SIGSTOP	1
"Stopped (signal)",		"STOP",		SIGSTOP,
#endif
#ifdef SIGSYS
#define HAD_SIGSYS	1
"Bad system call", 		"SYS",		SIGSYS,
#endif
#ifdef SIGTERM
#define HAD_SIGTERM	1
"Terminated",			"TERM",		SIGTERM,
#endif
#ifdef SIGTHAW
#define HAD_SIGTHAW	1
"CPR thaw",			"THAW",		SIGTHAW,
#endif
#ifdef SIGTINT
#define HAD_SIGTINT	1
"Interrupt (terminal)",		"TINT",		SIGTINT,
#endif
#ifdef SIGTRAP
#define HAD_SIGTRAP	1
"Trace trap",			"TRAP",		SIGTRAP,
#endif
#ifdef SIGTSTP
#define HAD_SIGTSTP	1
"Stopped",			"TSTP",		SIGTSTP,
#endif
#ifdef SIGTTIN
#define HAD_SIGTTIN	1
"Stopped (tty input)",		"TTIN",		SIGTTIN,
#endif
#ifdef SIGTTOU
#define HAD_SIGTTOU	1
"Stopped (tty output)",		"TTOU",		SIGTTOU,
#endif
#ifdef SIGURG
#define HAD_SIGURG	1
"Urgent IO",			"URG",		SIGURG,
#endif
#ifdef SIGUSR1
#define HAD_SIGUSR1	1
"User signal 1",		"USR1",		SIGUSR1,
#endif
#ifdef SIGUSR2
#define HAD_SIGUSR2	1
"User signal 2",		"USR2",		SIGUSR2,
#endif
#ifdef SIGVTALRM
#define HAD_SIGVTALRM	1
"Virtual timer alarm",		"VTALRM",	SIGVTALRM,
#endif
#ifdef SIGWAITING
#define HAD_SIGWAITING	1
"All threads blocked",		"WAITING",	SIGWAITING,
#endif
#ifdef SIGWINCH
#define HAD_SIGWINCH	1
"Window change", 		"WINCH",	SIGWINCH,
#endif
#ifdef SIGWIND
#define HAD_SIGWIND	1
"Window change",		"WIND",		SIGWIND,
#endif
#ifdef SIGWINDOW
#define HAD_SIGWINDOW	1
"Window change",		"WINDOW",	SIGWINDOW,
#endif
#ifdef SIGXCPU
#define HAD_SIGXCPU	1
"CPU time limit",		"XCPU",		SIGXCPU,
#endif
#ifdef SIGXFSZ
#define HAD_SIGXFSZ	1
"File size limit",		"XFSZ",		SIGXFSZ,
#endif
#include "FEATURE/siglist"
0
};

#define RANGE_MIN	(1<<14)
#define RANGE_MAX	(1<<13)
#define RANGE_RT	(1<<12)

#define RANGE_SIG	(~(RANGE_MIN|RANGE_MAX|RANGE_RT))

static int		mapindex[1024];

#if _lib_strsignal
extern char*		strsignal(int);
#endif

int
main()
{
	register int	i;
	register int	j;
	register int	k;
	int		m;
	int		n;
#if _lib_strsignal
	char*		s;
#endif

	k = 0;
	for (i = 0; map[i].name; i++)
		if ((j = map[i].value) > 0 && j < elementsof(mapindex) && !mapindex[j])
		{
			if (j > k)
				k = j;
			mapindex[j] = i;
		}
#ifdef SIGRTMIN
	i = SIGRTMIN;
#ifdef SIGRTMAX
	j = SIGRTMAX;
#else
	j = i;
#endif
	if (j >= elementsof(mapindex))
		j = elementsof(mapindex) - 1;
	if (i <= j && i > 0 && i < elementsof(mapindex) && j > 0 && j < elementsof(mapindex))
	{
		if (j > k)
			k = j;
		mapindex[i] = RANGE_MIN | RANGE_RT;
		n = 1;
		while (++i < j)
			mapindex[i] = RANGE_RT | n++;
		mapindex[j] = RANGE_MAX | RANGE_RT | n;
	}
#endif
	printf("#pragma prototyped\n");
	printf("#define SIG_MAX	%d\n", k);
	printf("\n");
	printf("static const char* const	sig_name[] =\n");
	printf("{\n");
	for (i = 0; i <= k; i++)
		if (!(j = mapindex[i]))
			printf("	\"%d\",\n", i);
		else if (j & RANGE_RT)
		{
			if (j & RANGE_MIN)
				printf("	\"RTMIN\",\n");
			else if (j & RANGE_MAX)
				printf("	\"RTMAX\",\n");
			else
			{
				m = j & RANGE_SIG;
				if (m > n / 2)
					printf("	\"RTMAX-%d\",\n", n - m);
				else
					printf("	\"RTMIN+%d\",\n", m);
			}
		}
		else
			printf("	\"%s\",\n", map[j].name);
	printf("	0\n");
	printf("};\n");
	printf("\n");
	printf("static const char* const	sig_text[] =\n");
	printf("{\n");
	for (i = 0; i <= k; i++)
		if (!(j = mapindex[i]))
			printf("	\"Signal %d\",\n", i);
		else if (j & RANGE_RT)
			printf("	\"Realtime priority %d%s\",\n", j & RANGE_SIG, (j & RANGE_MIN) ? " (lo)" : (j & RANGE_MAX) ? " (hi)" : "");
		else if (map[j].text)
			printf("	\"%s\",\n", map[j].text);
#if _lib_strsignal
		else if (s = strsignal(i))
			printf("	\"%s\",\n", s);
#endif
		else
			printf("	\"Signal %d\",\n", i);
	printf("	0\n");
	printf("};\n");
	return 0;
}
