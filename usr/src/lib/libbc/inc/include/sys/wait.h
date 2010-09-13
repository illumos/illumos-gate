/*
 * Copyright 1989 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 1982, 1986 Regents of the University of California.
 * All rights reserved. The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#ifndef	__sys_wait_h
#define	__sys_wait_h

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file holds definitions relevant to the wait system call.
 * Some of the options here are available only through the ``wait3''
 * entry point; the old entry point with one argument has more fixed
 * semantics, never returning status of unstopped children, hanging until
 * a process terminates if any are outstanding, and never returns
 * detailed information about process resource utilization (<vtimes.h>).
 */

#ifndef	_POSIX_SOURCE
#define	__wait		wait
#define	w_termsig	__w_termsig
#define	w_coredump	__w_coredump
#define	w_retcode	__w_retcode
#define	w_stopval	__w_stopval
#define	w_stopsig	__w_stopsig
#define	WSTOPPED	_WSTOPPED
#endif	/* !_POSIX_SOURCE */

/*
 * Structure of the information in the first word returned by both
 * wait and wait3.  If w_stopval==WSTOPPED, then the second structure
 * describes the information returned, else the first.  See WUNTRACED below.
 */
union __wait	{
	int	w_status;		/* used in syscall */
	/*
	 * Terminated process status.
	 */
	struct {
		unsigned short	w_Fill1:16;	/* high 16 bits unused */
		unsigned short	w_Retcode:8;	/* exit code if w_termsig==0 */
		unsigned short	w_Coredump:1;	/* core dump indicator */
		unsigned short	w_Termsig:7;	/* termination signal */
	} w_T;
	/*
	 * Stopped process status.  Returned
	 * only for traced children unless requested
	 * with the WUNTRACED option bit.
	 */
	struct {
		unsigned short	w_Fill2:16;	/* high 16 bits unused */
		unsigned short	w_Stopsig:8;	/* signal that stopped us */
		unsigned short	w_Stopval:8;	/* == W_STOPPED if stopped */
	} w_S;
};
#define	__w_termsig	w_T.w_Termsig
#define	__w_coredump	w_T.w_Coredump
#define	__w_retcode	w_T.w_Retcode
#define	__w_stopval	w_S.w_Stopval
#define	__w_stopsig	w_S.w_Stopsig
#define	_WSTOPPED	0177	/* value of s.stopval if process is stopped */

/*
 * Option bits for the second argument of wait3.  WNOHANG causes the
 * wait to not hang if there are no stopped or terminated processes, rather
 * returning an error indication in this case (pid==0).  WUNTRACED
 * indicates that the caller should receive status about untraced children
 * which stop due to signals.  If children are stopped and a wait without
 * this option is done, it is as though they were still running... nothing
 * about them is returned.
 */
#define	WNOHANG		1	/* dont hang in wait */
#define	WUNTRACED	2	/* tell about stopped, untraced children */

#define	WIFSTOPPED(x)	(((union __wait*)&(x))->__w_stopval == _WSTOPPED)
#define	WIFSIGNALED(x)	(((union __wait*)&(x))->__w_stopval != _WSTOPPED && \
			((union __wait*)&(x))->__w_termsig != 0)
#define	WIFEXITED(x)	(((union __wait*)&(x))->__w_stopval != _WSTOPPED && \
			((union __wait*)&(x))->__w_termsig == 0)
#define	WEXITSTATUS(x)	(((union __wait*)&(x))->__w_retcode)
#define	WTERMSIG(x)	(((union __wait*)&(x))->__w_termsig)
#define	WSTOPSIG(x)	(((union __wait*)&(x))->__w_stopsig)

#include <sys/stdtypes.h>

pid_t	wait(/* int *loc */);
pid_t	waitpid(/* pid_t pid, int *loc, int opts */);

#endif	/* !__sys_wait_h */
