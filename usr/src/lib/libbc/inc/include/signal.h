#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Copyright (c) 1982 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 *
 * Copyright (c) 1987 by Sun Microsystems, Inc.
 */

#ifndef	__signal_h
#define	__signal_h

#ifndef	_POSIX_SOURCE
#include <sys/signal.h>
#else
/*
 * All of the below is drawn from sys/signal.h.  Adding anything here means you
 * add it in sys/signal.h as well.
 */
#define	SIGHUP	1	/* hangup */
#define	SIGINT	2	/* interrupt */
#define	SIGQUIT	3	/* quit */
#define	SIGILL	4	/* illegal instruction (not reset when caught) */
#define	SIGTRAP	5	/* trace trap (not reset when caught) */
#define	SIGIOT	6	/* IOT instruction */
#define	SIGABRT 6	/* used by abort, replace SIGIOT in the future */
#define	SIGEMT	7	/* EMT instruction */
#define	SIGFPE	8	/* floating point exception */
#define	SIGKILL	9	/* kill (cannot be caught or ignored) */
#define	SIGBUS	10	/* bus error */
#define	SIGSEGV	11	/* segmentation violation */
#define	SIGSYS	12	/* bad argument to system call */
#define	SIGPIPE	13	/* write on a pipe with no one to read it */
#define	SIGALRM	14	/* alarm clock */
#define	SIGTERM	15	/* software termination signal from kill */
#define	SIGURG	16	/* urgent condition on IO channel */
#define	SIGSTOP	17	/* sendable stop signal not from tty */
#define	SIGTSTP	18	/* stop signal from tty */
#define	SIGCONT	19	/* continue a stopped process */
#define	SIGCHLD	20	/* to parent on child stop or exit */
#define	SIGCLD	20	/* System V name for SIGCHLD */
#define	SIGTTIN	21	/* to readers pgrp upon background tty read */
#define	SIGTTOU	22	/* like TTIN for output if (tp->t_local&LTOSTOP) */
#define	SIGIO	23	/* input/output possible signal */
#define	SIGPOLL	SIGIO	/* System V name for SIGIO */
#define	SIGXCPU	24	/* exceeded CPU time limit */
#define	SIGXFSZ	25	/* exceeded file size limit */
#define	SIGVTALRM 26	/* virtual time alarm */
#define	SIGPROF	27	/* profiling time alarm */
#define	SIGWINCH 28	/* window changed */
#define	SIGLOST 29	/* resource lost (eg, record-lock lost) */
#define	SIGUSR1 30	/* user defined signal 1 */
#define	SIGUSR2 31	/* user defined signal 2 */

/* signal() args & returns */
#define	SIG_ERR		(void (*)())-1
#define	SIG_DFL		(void (*)())0
#define	SIG_IGN		(void (*)())1
#define	SIG_HOLD	(void (*)())3

/* sigprocmask flags */
#define	SIG_BLOCK		0x0001
#define	SIG_UNBLOCK		0x0002
#define	SIG_SETMASK		0x0004

/* sa_flags flag; also supports all the sigvec flags in sys/signal.h */
#define	SA_NOCLDSTOP	0x0008	/* don't send a SIGCHLD on child stop */

#include <sys/stdtypes.h>	/* for sigset_t */

struct sigaction {
	void 		(*sa_handler)();
	sigset_t	sa_mask;
	int		sa_flags;
};
void	(*signal())();
int	kill(/* pid_t p, int sig */);
int	sigaction(/* int signo,
	    struct sigaction *act, struct sigaction *oldact */);
int	sigaddset(/* sigset_t *mask, int signo */);
int	sigdelset(/* sigset_t *mask, int signo */);
int	sigemptyset(/* sigset_t *mask */);
int	sigfillset(/* sigset_t *mask */);
int	sigismember(/* sigset_t *mask, int signo */);
int	sigpending(/* sigset_t *set */);
int	sigprocmask(/* int how, sigset_t *set, *oldset */);
int	sigsuspend(/* sigset_t *mask */);

#endif	/* _POSIX_SOURCE */
#endif	/* !__signal_h */
