/***********************************************************************
*                                                                      *
*               This software is part of the ast package               *
*           Copyright (c) 1982-2007 AT&T Knowledge Ventures            *
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
*                  David Korn <dgk@research.att.com>                   *
*                                                                      *
***********************************************************************/
#include	<ast.h>
#include	"shtable.h"
#include	"fault.h"

#if defined(SIGCLD) && !defined(SIGCHLD)
#   define SIGCHLD	SIGCLD
#endif

#define VAL(sig,mode)	((sig+1)|(mode)<<SH_SIGBITS)
#define TRAP(n)		(((n)|SH_TRAP)-1)

#ifndef ERROR_dictionary
#   define  ERROR_dictionary(s)	(s)
#endif
#define S(s)		ERROR_dictionary(s)

/*
 * This is a table that gives numbers and default settings to each signal
 * The signal numbers go in the low bits and the attributes go in the high bits
 */

const struct shtable2 shtab_signals[] =
{
#ifdef SIGABRT
	"ABRT",		VAL(SIGABRT,SH_SIGDONE), 	S("Abort"),
#endif /*SIGABRT */
#ifdef SIGAIO
	"AIO",		VAL(SIGAIO,SH_SIGIGNORE), 	S("Asynchronous I/O"),
#endif /*SIGAIO */
#ifdef SIGALRM
	"ALRM",		VAL(SIGALRM,SH_SIGDONE),	S("Alarm call"),
#endif /* SIGALRM */
#ifdef SIGAPOLLO
	"APOLLO",	VAL(SIGAPOLLO,0),		"SIGAPOLLO"),
#endif /* SIGAPOLLO */
#ifdef SIGBUS
	"BUS",		VAL(SIGBUS,SH_SIGDONE),		S("Bus error"),
#endif /* SIGBUS */
#ifdef SIGCHLD
	"CHLD",		VAL(SIGCHLD,SH_SIGFAULT), 	S("Death of Child"),
#   ifdef SIGCLD
#	if SIGCLD!=SIGCHLD
	    "CLD",	VAL(SIGCLD,SH_SIGFAULT),	S("Death of Child"),
#	endif
#   endif	/* SIGCLD */
#else
#   ifdef SIGCLD
	"CLD",		VAL(SIGCLD,SH_SIGFAULT),	S("Death of Child"),
#   endif	/* SIGCLD */
#endif	/* SIGCHLD */
#ifdef SIGCONT
	"CONT",		VAL(SIGCONT,SH_SIGIGNORE),	S("Stopped process continued"),
#endif	/* SIGCONT */
	"DEBUG",	VAL(TRAP(SH_DEBUGTRAP),0),	"",
#ifdef SIGDIL
	"DIL",		VAL(SIGDIL,0),			S("DIL signal"),
#endif	/* SIGDIL */
#ifdef SIGEMT
	"EMT",		VAL(SIGEMT,SH_SIGDONE),		S("EMT trap"),
#endif	/* SIGEMT */
	"ERR",		VAL(TRAP(SH_ERRTRAP),0),	"",
#ifdef SIGERR
	"ERR",		VAL(SIGERR,0),			"",
#endif /* SIGERR */
	"EXIT",		VAL(0,0),			"",
	"FPE",		VAL(SIGFPE,SH_SIGDONE),		S("Floating exception"),
#ifdef SIGFREEZE
	"FREEZE",	VAL(SIGFREEZE,SH_SIGIGNORE),	S("Special signal used by CPR"),
#endif	/* SIGFREEZE */
	"HUP",		VAL(SIGHUP,SH_SIGDONE),		S("Hangup"),
	"ILL",		VAL(SIGILL,SH_SIGDONE),		S("Illegal instruction"),
#ifdef JOBS
	"INT",		VAL(SIGINT,SH_SIGINTERACTIVE),	S("Interrupt"),
#else
	"INT",		VAL(SIGINT,SH_SIGINTERACTIVE),	"",
#endif /* JOBS */
#ifdef SIGIO
	"IO",		VAL(SIGIO,SH_SIGIGNORE),	S("IO signal"),
#endif	/* SIGIO */
#ifdef SIGIOT
	"IOT",		VAL(SIGIOT,SH_SIGDONE),		S("Abort"),
#endif	/* SIGIOT */
	"KEYBD",	VAL(TRAP(SH_KEYTRAP),0),	"",
#ifdef SIGKILL
	"KILL",		VAL(SIGKILL,0),			S("Killed"),
#endif /* SIGKILL */
#ifdef SIGLAB
	"LAB",		VAL(SIGLAB,0),			S("Security label changed"),
#endif	/* SIGLAB */
#ifdef SIGLOST
	"LOST",		VAL(SIGLOST,SH_SIGDONE),	S("Resources lost"),
#endif	/* SIGLOST */
#ifdef SIGLWP
	"LWP",		VAL(SIGLWP,SH_SIGIGNORE),	S("Special signal used by thread library"),
#endif	/* SIGLWP */
#ifdef SIGPHONE
	"PHONE",	VAL(SIGPHONE,0),		S("Phone interrupt"),
#endif	/* SIGPHONE */
#ifdef SIGPIPE
#ifdef JOBS
	"PIPE",		VAL(SIGPIPE,SH_SIGDONE),	S("Broken Pipe"),
#else
	"PIPE",		VAL(SIGPIPE,SH_SIGDONE),	 "",
#endif /* JOBS */
#endif /* SIGPIPE */
#ifdef SIGPOLL
	"POLL",		VAL(SIGPOLL,SH_SIGDONE),	S("Polling alarm"),
#endif	/* SIGPOLL */
#ifdef SIGPROF
	"PROF",		VAL(SIGPROF,SH_SIGDONE), 	S("Profiling time alarm"),
#endif	/* SIGPROF */
#ifdef SIGPWR
#   if SIGPWR>0
	"PWR",		VAL(SIGPWR,SH_SIGIGNORE),	S("Power fail"),
#   endif
#endif	/* SIGPWR */
#ifdef SIGQUIT
	"QUIT",		VAL(SIGQUIT,SH_SIGDONE|SH_SIGINTERACTIVE),	S("Quit"),
#ifdef __SIGRTMIN
#undef	SIGRTMIN
#define SIGRTMIN	__SIGRTMIN
#else
#ifdef _SIGRTMIN
#undef	SIGRTMIN
#define SIGRTMIN	_SIGRTMIN
#endif 
#endif
#ifdef SIGRTMIN
	"RTMIN",	VAL(SIGRTMIN,0),		S("Lowest priority realtime signal"),
#endif	/* SIGRTMIN */
#ifdef __SIGRTMAX
#undef	SIGRTMAX
#define SIGRTMAX	__SIGRTMAX
#else
#ifdef _SIGRTMAX
#undef	SIGRTMAX
#define SIGRTMAX	_SIGRTMAX
#endif 
#endif
#ifdef SIGRTMAX
	"RTMAX",	VAL(SIGRTMAX,0),		S("Highest priority realtime signal"),
#endif	/* SIGRTMAX */
#endif	/* SIGQUIT */
	"SEGV",		VAL(SIGSEGV,0),			S("Memory fault"),
#ifdef SIGSTOP
	"STOP",		VAL(SIGSTOP,0),			S("Stopped (SIGSTOP)"),
#endif	/* SIGSTOP */
#ifdef SIGSYS
	"SYS",		VAL(SIGSYS,SH_SIGDONE),		S("Bad system call"),
#endif	/* SIGSYS */
	"TERM",		VAL(SIGTERM,SH_SIGDONE|SH_SIGINTERACTIVE),	S("Terminated"),
#ifdef SIGTINT
#   ifdef JOBS
	"TINT",		VAL(SIGTINT,0),			S("Interrupt"),
#   else
	"TINT",		VAL(SIGTINT,0),			"".
#   endif /* JOBS */
#endif	/* SIGTINT */
#ifdef SIGTRAP
	"TRAP",		VAL(SIGTRAP,SH_SIGDONE),	S("Trace/BPT trap"),
#endif	/* SIGTRAP */
#ifdef SIGTSTP
	"TSTP",		VAL(SIGTSTP,0),			S("Stopped"),
#endif	/* SIGTSTP */
#ifdef SIGTTIN
	"TTIN",		VAL(SIGTTIN,0),			S("Stopped (SIGTTIN)"),
#endif	/* SIGTTIN */
#ifdef SIGTTOU
	"TTOU",		VAL(SIGTTOU,0),			S("Stopped(SIGTTOU)"),
#endif	/* SIGTTOU */
#ifdef SIGURG
	"URG",		VAL(SIGURG,SH_SIGIGNORE),	S("Socket interrupt"),
#endif	/* SIGURG */
#ifdef SIGUSR1
	"USR1",		VAL(SIGUSR1,SH_SIGDONE),	 S("User signal 1"),
#endif	/* SIGUSR1 */
#ifdef SIGUSR2
	"USR2",		VAL(SIGUSR2,SH_SIGDONE),	 S("User signal 2"),
#endif	/* SIGUSR2 */
#ifdef SIGVTALRM
	"VTALRM",	VAL(SIGVTALRM,SH_SIGDONE),	S("Virtual time alarm"),
#endif	/* SIGVTALRM */
#ifdef SIGWINCH
	"WINCH",	VAL(SIGWINCH,SH_SIGIGNORE),	S("Window size change"),
#endif	/* SIGWINCH */
#ifdef SIGMIGRATE
	"MIGRATE",		VAL(SIGMIGRATE,0),	S("Migrate process"),
#endif	/* SIGMIGRATE */
#ifdef SIGDANGER
	"DANGER",		VAL(SIGDANGER,0),	S("System crash soon"),
#endif	/* SIGDANGER */
#ifdef SIGSOUND
	"SOUND",		VAL(SIGSOUND,0),	S("Sound completed"),
#endif	/* SIGSOUND */
#ifdef SIGTHAW
	"THAW",			VAL(SIGTHAW,SH_SIGIGNORE),	S("Special signal used by CPR"),
#endif	/* SIGTHAW */
#ifdef SIGWAITING
	"WAITING",		VAL(SIGWAITING,SH_SIGIGNORE),	S("All threads blocked"),
#endif	/* SIGWAITING */
#ifdef SIGXCPU
	"XCPU",		VAL(SIGXCPU,SH_SIGDONE|SH_SIGINTERACTIVE),	S("Exceeded CPU time limit"),
#endif	/* SIGXCPU */
#ifdef SIGXFSZ
	"XFSZ",		VAL(SIGXFSZ,SH_SIGDONE|SH_SIGINTERACTIVE),	S("Exceeded file size limit"),
#endif	/* SIGXFSZ */
	"",	0,	0
};
