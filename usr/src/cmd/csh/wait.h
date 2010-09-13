/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 *
 *	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T
 *	  All Rights Reserved
 *
 * Copyright (c) 1980 Regents of the University of California.
 * All rights reserved.  The Berkeley Software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file holds definitions relevant to the wait system call.
 * Some of the options here are available only through the ``wait3''
 * entry point; the old entry point with one argument has more fixed
 * semantics, never returning status of unstopped children, hanging until
 * a process terminates if any are outstanding, and never returns
 * detailed information about process resource utilization (<vtimes.h>).
 */

#ifndef _sys_wait_h
#define	_sys_wait_h

#include <sys/isa_defs.h>	/* included for _LITTLE_ENDIAN define	*/

/*
 * Structure of the information in the first word returned by both
 * wait and wait3.  If w_stopval==WSTOPPED, then the second structure
 * describes the information returned, else the first.  See WUNTRACED below.
 */
union wait	{
	int	w_status;		/* used in syscall */
	/*
	 * Terminated process status.
	 */
	struct {
#if	defined(_LITTLE_ENDIAN)
		unsigned short	w_Termsig:7;	/* termination signal */
		unsigned short	w_Coredump:1;	/* core dump indicator */
		unsigned short	w_Retcode:8;	/* exit code if w_termsig==0 */
#elif	defined(_BIG_ENDIAN)
		unsigned short	w_Fill1:16;	/* high 16 bits unused */
		unsigned short	w_Retcode:8;	/* exit code if w_termsig==0 */
		unsigned short	w_Coredump:1;	/* core dump indicator */
		unsigned short	w_Termsig:7;	/* termination signal */
#else
#error	NO ENDIAN defined.
#endif
	} w_T;
	/*
	 * Stopped process status.  Returned
	 * only for traced children unless requested
	 * with the WUNTRACED option bit.
	 */
	struct {
#if	defined(_LITTLE_ENDIAN)
		unsigned short	w_Stopval:8;	/* == W_STOPPED if stopped */
		unsigned short	w_Stopsig:8;	/* signal that stopped us */
#elif	defined(_BIG_ENDIAN)
		unsigned short	w_Fill2:16;	/* high 16 bits unused */
		unsigned short	w_Stopsig:8;	/* signal that stopped us */
		unsigned short	w_Stopval:8;	/* == W_STOPPED if stopped */
#else
#error	NO ENDIAN defined.
#endif
	} w_S;
};
#define	w_termsig	w_T.w_Termsig
#define	w_coredump	w_T.w_Coredump
#define	w_retcode	w_T.w_Retcode
#define	w_stopval	w_S.w_Stopval
#define	w_stopsig	w_S.w_Stopsig


#define	WSTOPPED	0177	/* value of s.stopval if process is stopped */
#define	WCONTFLG	0177777	/* value of w.w_status due to SIGCONT, sysV */

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

#define	WIFSTOPPED(x)	((x).w_stopval == WSTOPPED)
#define	WIFSIGNALED(x)	((x).w_stopval != WSTOPPED && (x).w_termsig != 0)
#define	WIFEXITED(x)	((x).w_stopval != WSTOPPED && (x).w_termsig == 0)

extern pid_t csh_wait3(union wait *w, int options, struct rusage *rp);
extern pid_t csh_wait_noreap(void);

#endif /* _sys_wait_h */
