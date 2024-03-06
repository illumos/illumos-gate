/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * Copyright (c) 1980 Regents of the University of California.
 * All rights reserved. The Berkeley Software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#include "sh.h"
#include "sh.dir.h"
#include "sh.proc.h"
#include "wait.h"
#include "sh.tconst.h"

/*
 * C Shell - functions that manage processes, handling hanging, termination
 */

bool	neednote;
bool	pjobs;
static struct process *pprevious;
static short	pmaxindex;
static struct process proclist;
static struct process *pcurrent;
struct process *pcurrjob;
static struct process *pholdjob;

#define	BIGINDEX	9	/* largest desirable job index */

void	pjwait(struct process *);
void	pflush(struct process *);
void	pclrcurr(struct process *);
void	padd(struct command *);
void	pads(tchar *);
void	ptprint(struct process *);
void	pkill(tchar **, int);
void	pstart(struct process *, int);
void	okpcntl(void);
struct process	*pgetcurr(struct process *);
struct process	*pfind(tchar *);

/*
 * pchild - called at interrupt level by the SIGCHLD signal
 *	indicating that at least one child has terminated or stopped
 *	thus at least one wait system call will definitely return a
 *	childs status.  Top level routines (like pwait) must be sure
 *	to mask interrupts when playing with the proclist data structures!
 */
void
pchild(int signal __unused)
{
	struct process *pp;
	struct process	*fp;
	int pid;
	union wait w;
	int jobflags;
	struct rusage ru;

#ifdef TRACE
	tprintf("TRACE- pchile()\n");
#endif
loop:
	pid = csh_wait3(&w, (setintr ? WNOHANG|WUNTRACED:WNOHANG), &ru);
	/*
	 * SysV sends a SIGCHLD when the child process
	 * receives a SIGCONT, and result of that action is ignored here
	 */
	if (w.w_status == WCONTFLG)
		return;
	if (pid <= 0) {
		if (errno == EINTR) {
			errno = 0;
			goto loop;
		}
		return;
	}
	for (pp = proclist.p_next; pp != PNULL; pp = pp->p_next)
		if (pid == pp->p_pid)
			goto found;
	goto loop;
found:
	if (pid == atoi_(value(S_child /* "child" */)))
		unsetv(S_child /* "child" */);
	pp->p_flags &= ~(PRUNNING|PSTOPPED|PREPORTED);
	if (WIFSTOPPED(w)) {
		pp->p_flags |= PSTOPPED;
		pp->p_reason = w.w_stopsig;
	} else {
		if (pp->p_flags & (PTIME|PPTIME) || adrof(S_time /* "time" */))
			(void) gettimeofday(&pp->p_etime, (struct timezone *)0);
		pp->p_rusage = ru;
		if (WIFSIGNALED(w)) {
			if (w.w_termsig == SIGINT)
				pp->p_flags |= PINTERRUPTED;
			else
				pp->p_flags |= PSIGNALED;
			if (w.w_coredump)
				pp->p_flags |= PDUMPED;
			pp->p_reason = w.w_termsig;
		} else {
			pp->p_reason = w.w_retcode;
			if (pp->p_reason != 0)
				pp->p_flags |= PAEXITED;
			else
				pp->p_flags |= PNEXITED;
		}
	}
	jobflags = 0;
	fp = pp;
	do {
		if ((fp->p_flags & (PPTIME|PRUNNING|PSTOPPED)) == 0 &&
		    !child && adrof(S_time /* "time" */) &&
		    fp->p_rusage.ru_utime.tv_sec+fp->p_rusage.ru_stime.tv_sec >=
		    atoi_(value(S_time /* "time" */)))
			fp->p_flags |= PTIME;
		jobflags |= fp->p_flags;
	} while ((fp = fp->p_friends) != pp);
	pp->p_flags &= ~PFOREGND;
	if (pp == pp->p_friends && (pp->p_flags & PPTIME)) {
		pp->p_flags &= ~PPTIME;
		pp->p_flags |= PTIME;
	}
	if ((jobflags & (PRUNNING|PREPORTED)) == 0) {
		fp = pp;
		do {
			if (fp->p_flags&PSTOPPED)
				fp->p_flags |= PREPORTED;
		} while ((fp = fp->p_friends) != pp);
		while (fp->p_pid != fp->p_jobid)
			fp = fp->p_friends;
		if (jobflags&PSTOPPED) {
			if (pcurrent && pcurrent != fp)
				pprevious = pcurrent;
			pcurrent = fp;
		} else
			pclrcurr(fp);
		if (jobflags&PFOREGND) {
			if (jobflags & (PSIGNALED|PSTOPPED|PPTIME) ||
#ifdef IIASA
			    jobflags & PAEXITED ||
#endif
			    !eq(dcwd->di_name, fp->p_cwd->di_name)) {
				;	/* print in pjwait */
			}
		} else {
			if (jobflags&PNOTIFY || adrof(S_notify /* "notify" */)) {
				write_string("\015\n");
				flush();
				(void) pprint(pp, NUMBER|NAME|REASON);
				if ((jobflags&PSTOPPED) == 0)
					pflush(pp);
			} else {
				fp->p_flags |= PNEEDNOTE;
				neednote++;
			}
		}
	}
	goto loop;
}

void
pnote(void)
{
	struct process *pp;
	int flags, omask;

#ifdef TRACE
	tprintf("TRACE- pnote()\n");
#endif
	neednote = 0;
	for (pp = proclist.p_next; pp != PNULL; pp = pp->p_next) {
		if (pp->p_flags & PNEEDNOTE) {
			omask = sigblock(sigmask(SIGCHLD));
			pp->p_flags &= ~PNEEDNOTE;
			flags = pprint(pp, NUMBER|NAME|REASON);
			if ((flags&(PRUNNING|PSTOPPED)) == 0)
				pflush(pp);
			(void) sigsetmask(omask);
		}
	}
}

/*
 * pwait - wait for current job to terminate, maintaining integrity
 *	of current and previous job indicators.
 */
void
pwait(void)
{
	struct process *fp, *pp;
	int omask;

#ifdef TRACE
	tprintf("TRACE- pwait()\n");
#endif
	/*
	 * Here's where dead procs get flushed.
	 */
	omask = sigblock(sigmask(SIGCHLD));
	for (pp = (fp = &proclist)->p_next; pp != PNULL; pp = (fp = pp)->p_next)
		if (pp->p_pid == 0) {
			fp->p_next = pp->p_next;
			xfree(pp->p_command);
			if (pp->p_cwd && --pp->p_cwd->di_count == 0)
				if (pp->p_cwd->di_next == 0)
					dfree(pp->p_cwd);
			xfree((tchar *)pp);
			pp = fp;
		}
	(void) sigsetmask(omask);
	pjwait(pcurrjob);
}

/*
 * pjwait - wait for a job to finish or become stopped
 *	It is assumed to be in the foreground state (PFOREGND)
 */
void
pjwait(struct process *pp)
{
	struct process *fp;
	int jobflags, reason, omask;

#ifdef TRACE
	tprintf("TRACE- pjwait()\n");
#endif
	while (pp->p_pid != pp->p_jobid)
		pp = pp->p_friends;
	fp = pp;
	do {
		if ((fp->p_flags&(PFOREGND|PRUNNING)) == PRUNNING)
			printf("BUG: waiting for background job!\n");
	} while ((fp = fp->p_friends) != pp);
	/*
	 * Now keep pausing as long as we are not interrupted (SIGINT),
	 * and the target process, or any of its friends, are running
	 */
	fp = pp;
	omask = sigblock(sigmask(SIGCHLD));
	for (;;) {
		jobflags = 0;
		do
			jobflags |= fp->p_flags;
		while ((fp = (fp->p_friends)) != pp);
		if ((jobflags & PRUNNING) == 0)
			break;
		/*
		 * At this point, csh used to call:
		 *	sigpause(sigblock(0) &~ sigmask(SIGCHLD));
		 * expecting to receive a SIGCHLD signal from the
		 * termination of the child and to invoke the
		 * signal handler, pchild(), as a result.
		 *
		 * However, vfork() now causes a vfork()'d child to
		 * have all of its active signal handlers reset to
		 * SIG_DFL, to forstall parent memory corruption due
		 * to race conditions with signal handling.
		 *
		 * If this instance of csh is itself a child of vfork(),
		 * which can happen when the top-level csh performs a
		 * command substitution inside an i/o redirection, like:
		 *	/bin/echo foo >`/bin/echo trash`
		 * then we will never receive SIGCHLD.  To accommodate
		 * this, we wait until one of our children terminates
		 * (without actually reaping the child) and call the
		 * SIGCHLD signal handler (pchild()) directly.
		 */
		if (csh_wait_noreap() > 0)
			pchild(SIGCHLD);	/* simulate receipt of SIGCHLD */
	}
	(void) sigsetmask(omask);
	if (tpgrp > 0)			/* get tty back */
		(void) ioctl(FSHTTY, TIOCSPGRP,  (char *)&tpgrp);
	if ((jobflags&(PSIGNALED|PSTOPPED|PTIME)) ||
	    !eq(dcwd->di_name, fp->p_cwd->di_name)) {
		if (jobflags&PSTOPPED)
			printf("\n");
		(void) pprint(pp, AREASON|SHELLDIR);
	}
	if ((jobflags&(PINTERRUPTED|PSTOPPED)) && setintr &&
	    (!gointr || !eq(gointr, S_MINUS /* "-" */))) {
		if ((jobflags & PSTOPPED) == 0)
			pflush(pp);
		pintr1(0);
		/*NOTREACHED*/
	}
	reason = 0;
	fp = pp;
	do {
		if (fp->p_reason)
			reason = fp->p_flags & (PSIGNALED|PINTERRUPTED) ?
				fp->p_reason | ABN_TERM : fp->p_reason;
	} while ((fp = fp->p_friends) != pp);
	set(S_status /* "status" */, putn(reason));
	if (reason && exiterr)
		exitstat();
	pflush(pp);
}

/*
 * dowait - wait for all processes to finish
 */
void
dowait(void)
{
	struct process *pp;
	int omask;

#ifdef TRACE
	tprintf("TRACE- dowait()\n");
#endif
	pjobs++;
	omask = sigblock(sigmask(SIGCHLD));
loop:
	for (pp = proclist.p_next; pp; pp = pp->p_next)
		if (pp->p_pid && /* pp->p_pid == pp->p_jobid && */
		    pp->p_flags&PRUNNING) {
			sigpause(0);
			goto loop;
		}
	(void) sigsetmask(omask);
	pjobs = 0;
}

/*
 * pflushall - flush all jobs from list (e.g. at fork())
 */
void
pflushall(void)
{
	struct process	*pp;

#ifdef TRACE
	tprintf("TRACE- pflush()\n");
#endif
	for (pp = proclist.p_next; pp != PNULL; pp = pp->p_next)
		if (pp->p_pid)
			pflush(pp);
}

/*
 * pflush - flag all process structures in the same job as the
 *	the argument process for deletion.  The actual free of the
 *	space is not done here since pflush is called at interrupt level.
 */
void
pflush(struct process *pp)
{
	struct process *np;
	int index;

#ifdef TRACE
	tprintf("TRACE- pflush()\n");
#endif
	if (pp->p_pid == 0) {
		printf("BUG: process flushed twice");
		return;
	}
	while (pp->p_pid != pp->p_jobid)
		pp = pp->p_friends;
	pclrcurr(pp);
	if (pp == pcurrjob)
		pcurrjob = 0;
	index = pp->p_index;
	np = pp;
	do {
		np->p_index = np->p_pid = 0;
		np->p_flags &= ~PNEEDNOTE;
	} while ((np = np->p_friends) != pp);
	if (index == pmaxindex) {
		for (np = proclist.p_next, index = 0; np; np = np->p_next)
			if (np->p_index > (tchar)index)
				index = np->p_index;
		pmaxindex = index;
	}
}

/*
 * pclrcurr - make sure the given job is not the current or previous job;
 *	pp MUST be the job leader
 */
void
pclrcurr(struct process *pp)
{

#ifdef TRACE
	tprintf("TRACE- pclrcurr()\n");
#endif
	if (pp == pcurrent)
		if (pprevious != PNULL) {
			pcurrent = pprevious;
			pprevious = pgetcurr(pp);
		} else {
			pcurrent = pgetcurr(pp);
			pprevious = pgetcurr(pp);
		}
	else if (pp == pprevious)
		pprevious = pgetcurr(pp);
}

/* +4 here is 1 for '\0', 1 ea for << >& >> */
tchar	command[PMAXLEN+4];
int	cmdlen;
tchar	*cmdp;
/*
 * palloc - allocate a process structure and fill it up.
 *	an important assumption is made that the process is running.
 */
void
palloc(int pid, struct command *t)
{
	struct process	*pp;
	int i;

#ifdef TRACE
	tprintf("TRACE- palloc()\n");
#endif
	pp = (struct process *)xcalloc(1, sizeof (struct process));
	pp->p_pid = pid;
	pp->p_flags = t->t_dflg & FAND ? PRUNNING : PRUNNING|PFOREGND;
	if (t->t_dflg & FTIME)
		pp->p_flags |= PPTIME;
	cmdp = command;
	cmdlen = 0;
	padd(t);
	*cmdp++ = 0;
	if (t->t_dflg & FPOU) {
		pp->p_flags |= PPOU;
		if (t->t_dflg & FDIAG)
			pp->p_flags |= PDIAG;
	}
	pp->p_command = savestr(command);
	if (pcurrjob) {
		struct process *fp;
		/* careful here with interrupt level */
		pp->p_cwd = 0;
		pp->p_index = pcurrjob->p_index;
		pp->p_friends = pcurrjob;
		pp->p_jobid = pcurrjob->p_pid;
		for (fp = pcurrjob; fp->p_friends != pcurrjob; fp = fp->p_friends)
			;
		fp->p_friends = pp;
	} else {
		pcurrjob = pp;
		pp->p_jobid = pid;
		pp->p_friends = pp;
		pp->p_cwd = dcwd;
		dcwd->di_count++;
		if (pmaxindex < BIGINDEX)
			pp->p_index = ++pmaxindex;
		else {
			struct process *np;

			for (i = 1; ; i++) {
				for (np = proclist.p_next; np; np = np->p_next)
					if (np->p_index == i)
						goto tryagain;
				pp->p_index = i;
				if (i > pmaxindex)
					pmaxindex = i;
				break;
			tryagain:;
			}
		}
		pprevious = pcurrent;
		pcurrent = pp;
	}
	pp->p_next = proclist.p_next;
	proclist.p_next = pp;
	(void) gettimeofday(&pp->p_btime, (struct timezone *)0);
}

void
padd(struct command *t)
{
	tchar **argp;

#ifdef TRACE
	tprintf("TRACE- padd()\n");
#endif
	if (t == 0)
		return;
	switch (t->t_dtyp) {

	case TPAR:
		pads(S_LBRASP /* "( " */);
		padd(t->t_dspr);
		pads(S_SPRBRA /* " )" */);
		break;

	case TCOM:
		for (argp = t->t_dcom; *argp; argp++) {
			pads(*argp);
			if (argp[1])
				pads(S_SP /* " " */);
		}
		break;

	case TOR:
	case TAND:
	case TFIL:
	case TLST:
		padd(t->t_dcar);
		switch (t->t_dtyp) {
		case TOR:
			pads(S_SPBARBARSP /* " || " */);
			break;
		case TAND:
			pads(S_SPANDANDSP /* " && " */);
			break;
		case TFIL:
			pads(S_SPBARSP /* " | " */);
			break;
		case TLST:
			pads(S_SEMICOLONSP /* "; " */);
			break;
		}
		padd(t->t_dcdr);
		return;
	}
	if ((t->t_dflg & FPIN) == 0 && t->t_dlef) {
		pads((t->t_dflg & FHERE) ? S_SPLESLESSP /* " << " */ : S_SPLESSP /* " < " */);
		pads(t->t_dlef);
	}
	if ((t->t_dflg & FPOU) == 0 && t->t_drit) {
		pads((t->t_dflg & FCAT) ? S_SPGTRGTRSP /* " >>" */ : S_SPGTR /* " >" */);
		if (t->t_dflg & FDIAG)
			pads(S_AND /* "&" */);
		pads(S_SP /* " " */);
		pads(t->t_drit);
	}
}

void
pads(tchar *cp)
{
	int i = strlen_(cp);

#ifdef TRACE
	tprintf("TRACE- pads()\n");
#endif
	if (cmdlen >= PMAXLEN)
		return;
	if (cmdlen + i >= PMAXLEN) {
		(void) strcpy_(cmdp, S_SPPPP /* " ..." */);
		cmdlen = PMAXLEN;
		cmdp += 4;
		return;
	}
	(void) strcpy_(cmdp, cp);
	cmdp += i;
	cmdlen += i;
}

/*
 * psavejob - temporarily save the current job on a one level stack
 *	so another job can be created.  Used for { } in exp6
 *	and `` in globbing.
 */
void
psavejob(void)
{

#ifdef TRACE
	tprintf("TRACE- psavejob()\n");
#endif
	pholdjob = pcurrjob;
	pcurrjob = PNULL;
}

/*
 * prestjob - opposite of psavejob.  This may be missed if we are interrupted
 *	somewhere, but pendjob cleans up anyway.
 */
void
prestjob(void)
{

#ifdef TRACE
	tprintf("TRACE- prestjob()\n");
#endif
	pcurrjob = pholdjob;
	pholdjob = PNULL;
}

/*
 * pendjob - indicate that a job (set of commands) has been completed
 *	or is about to begin.
 */
void
pendjob(void)
{
	struct process *pp, *tp;

#ifdef TRACE
	tprintf("TRACE- pendjob()\n");
#endif
	if (pcurrjob && (pcurrjob->p_flags&(PFOREGND|PSTOPPED)) == 0) {
		pp = pcurrjob;
		while (pp->p_pid != pp->p_jobid)
			pp = pp->p_friends;
		printf("[%d]", pp->p_index);
		tp = pp;
		do {
			printf(" %d", pp->p_pid);
			pp = pp->p_friends;
		} while (pp != tp);
		printf("\n");
	}
	pholdjob = pcurrjob = 0;
}

/*
 * pprint - print a job
 */
int
pprint(struct process *pp, int flag)
{
	int status, reason;
	struct process *tp;
	extern char *linp, linbuf[];
	int jobflags, pstatus;
	char *format;

#ifdef TRACE
	tprintf("TRACE- pprint()\n");
#endif
	while (pp->p_pid != pp->p_jobid)
		pp = pp->p_friends;
	if (pp == pp->p_friends && (pp->p_flags & PPTIME)) {
		pp->p_flags &= ~PPTIME;
		pp->p_flags |= PTIME;
	}
	tp = pp;
	status = reason = -1;
	jobflags = 0;
	do {
		jobflags |= pp->p_flags;
		pstatus = pp->p_flags & PALLSTATES;
		if (tp != pp && linp != linbuf && !(flag&FANCY) &&
		    (pstatus == status && pp->p_reason == reason ||
		    !(flag&REASON)))
			printf(" ");
		else {
			if (tp != pp && linp != linbuf)
				printf("\n");
			if (flag&NUMBER)
				if (pp == tp)
					printf("[%d]%s %c ", pp->p_index,
					    pp->p_index < 10 ? " " : "",
					    pp == pcurrent ? '+' :
						(pp == pprevious ? (tchar) '-'
							: (tchar) ' '));
				else
					printf("       ");
			if (flag&FANCY)
				printf("%5d ", pp->p_pid);
			if (flag&(REASON|AREASON)) {
				if (flag&NAME)
					format = "%-21s";
				else
					format = "%s";
				if (pstatus == status)
					if (pp->p_reason == reason) {
						printf(format, "");
						goto prcomd;
					} else
						reason = pp->p_reason;
				else {
					status = pstatus;
					reason = pp->p_reason;
				}
				switch (status) {

				case PRUNNING:
					printf(format, "Running ");
					break;

				case PINTERRUPTED:
				case PSTOPPED:
				case PSIGNALED:
					if ((flag&(REASON|AREASON))
					    && reason != SIGINT
					    && reason != SIGPIPE)
						printf(format,
						    strsignal(pp->p_reason));
					break;

				case PNEXITED:
				case PAEXITED:
					if (flag & REASON)
						if (pp->p_reason)
							printf("Exit %-16d", pp->p_reason);
						else
							printf(format, "Done");
					break;

				default:
					printf("BUG: status=%-9o", status);
				}
			}
		}
prcomd:
		if (flag&NAME) {
			printf("%t", pp->p_command);
			if (pp->p_flags & PPOU)
				printf(" |");
			if (pp->p_flags & PDIAG)
				printf("&");
		}
		if (flag&(REASON|AREASON) && pp->p_flags&PDUMPED)
			printf(" (core dumped)");
		if (tp == pp->p_friends) {
			if (flag&AMPERSAND)
				printf(" &");
			if (flag&JOBDIR &&
			    !eq(tp->p_cwd->di_name, dcwd->di_name)) {
				printf(" (wd: ");
				dtildepr(value(S_home /* "home" */), tp->p_cwd->di_name);
				printf(")");
			}
		}
		if (pp->p_flags&PPTIME && !(status&(PSTOPPED|PRUNNING))) {
			if (linp != linbuf)
				printf("\n\t");
			{ static struct rusage zru;
			    prusage(&zru, &pp->p_rusage, &pp->p_etime,
			    &pp->p_btime);
			}
		}
		if (tp == pp->p_friends) {
			if (linp != linbuf)
				printf("\n");
			if (flag&SHELLDIR && !eq(tp->p_cwd->di_name, dcwd->di_name)) {
				printf("(wd now: ");
				dtildepr(value(S_home /* "home" */), dcwd->di_name);
				printf(")\n");
			}
		}
	} while ((pp = pp->p_friends) != tp);
	if (jobflags&PTIME && (jobflags&(PSTOPPED|PRUNNING)) == 0) {
		if (jobflags & NUMBER)
			printf("       ");
		ptprint(tp);
	}
	return (jobflags);
}

void
ptprint(struct process *tp)
{
	struct timeval tetime, diff;
	static struct timeval ztime;
	struct rusage ru;
	static struct rusage zru;
	struct process *pp = tp;

#ifdef TRACE
	tprintf("TRACE- ptprint()\n");
#endif
	ru = zru;
	tetime = ztime;
	do {
		ruadd(&ru, &pp->p_rusage);
		tvsub(&diff, &pp->p_etime, &pp->p_btime);
		if (timercmp(&diff, &tetime, >))
			tetime = diff;
	} while ((pp = pp->p_friends) != tp);
	prusage(&zru, &ru, &tetime, &ztime);
}

/*
 * dojobs - print all jobs
 */
void
dojobs(tchar **v)
{
	struct process *pp;
	int flag = NUMBER|NAME|REASON;
	int i;

#ifdef TRACE
	tprintf("TRACE- dojobs()\n");
#endif
	if (chkstop)
		chkstop = 2;
	if (*++v) {
		if (v[1] || !eq(*v, S_DASHl /* "-l" */))
			error("Usage: jobs [ -l ]");
		flag |= FANCY|JOBDIR;
	}
	for (i = 1; i <= pmaxindex; i++)
		for (pp = proclist.p_next; pp; pp = pp->p_next)
			if (pp->p_index == i && pp->p_pid == pp->p_jobid) {
				pp->p_flags &= ~PNEEDNOTE;
				if (!(pprint(pp, flag) & (PRUNNING|PSTOPPED)))
					pflush(pp);
				break;
			}
}

/*
 * dofg - builtin - put the job into the foreground
 */
void
dofg(tchar **v)
{
	struct process *pp;

#ifdef TRACE
	tprintf("TRACE- dofg()\n");
#endif
	okpcntl();
	++v;
	do {
		pp = pfind(*v);
		pstart(pp, 1);
		pjwait(pp);
	} while (*v && *++v);
}

/*
 * %... - builtin - put the job into the foreground
 */
void
dofg1(tchar **v)
{
	struct process *pp;

#ifdef TRACE
	tprintf("TRACE- untty()\n");
#endif
	okpcntl();
	pp = pfind(v[0]);
	pstart(pp, 1);
	pjwait(pp);
}

/*
 * dobg - builtin - put the job into the background
 */
void
dobg(tchar **v)
{
	struct process *pp;

#ifdef TRACE
	tprintf("TRACE- dobg()\n");
#endif
	okpcntl();
	++v;
	do {
		pp = pfind(*v);
		pstart(pp, 0);
	} while (*v && *++v);
}

/*
 * %... & - builtin - put the job into the background
 */
void
dobg1(tchar **v)
{
	struct process *pp;

#ifdef TRACE
	tprintf("TRACE- dobg1()\n");
#endif
	pp = pfind(v[0]);
	pstart(pp, 0);
}

/*
 * dostop - builtin - stop the job
 */
void
dostop(tchar **v)
{

#ifdef TRACE
	tprintf("TRACE- dostop()\n");
#endif
	pkill(++v, SIGSTOP);
}

/*
 * dokill - builtin - superset of kill (1)
 */
void
dokill(tchar **v)
{
	int signum;
	tchar *name;

#ifdef TRACE
	tprintf("TRACE- dokill()\n");
#endif
	v++;
	if (v[0] && v[0][0] == '-') {
		if (v[0][1] == 'l') {
			for (signum = 1; signum <= NSIG-1; signum++) {
				char	sbuf[BUFSIZ];
				if (sig2str(signum, sbuf) == 0)
					printf("%s ", sbuf);
				if (signum % 8 == 0)
					Putchar('\n');
			}
			Putchar('\n');
			return;
		}
		if (digit(v[0][1])) {
			if (chkalldigit_(v[0]+1) != 0) {
				setname(v[0]+1);
				bferr("Unknown signal; kill -l lists signals");
			}
			signum = atoi_(v[0]+1);
			if (signum < 0 || signum > NSIG)
				bferr("Bad signal number");
		} else {
			int	signo;
			char	sbuf[BUFSIZ];
			name = &v[0][1];
			tstostr(sbuf, name);
			if (str2sig(sbuf, &signo) == 0) {
				signum = signo;
				goto gotsig;
			}
			if (eq(name, S_IOT /* "IOT" */)) {
				signum = SIGABRT;
				goto gotsig;
			}
			setname(name);
			bferr("Unknown signal; kill -l lists signals");
		}
gotsig:
		v++;
	} else
		signum = SIGTERM;
	pkill(v, signum);
}

void
pkill(tchar **v, int signum)
{
	struct process *pp, *np;
	int jobflags = 0;
	int omask, pid, err = 0;
	tchar *cp;

#ifdef TRACE
	tprintf("TRACE- pkill()\n");
#endif
	omask = sigmask(SIGCHLD);
	if (setintr)
		omask |= sigmask(SIGINT);
	omask = sigblock(omask) & ~omask;
	while (*v) {
		cp = globone(*v);
		if (*cp == '%') {
			np = pp = pfind(cp);
			do
				jobflags |= np->p_flags;
			while ((np = np->p_friends) != pp);
			switch (signum) {

			case SIGSTOP:
			case SIGTSTP:
			case SIGTTIN:
			case SIGTTOU:
				if ((jobflags & PRUNNING) == 0) {
					/* %s -> %t */
					printf("%t: Already stopped\n", cp);
					err++;
					goto cont;
				}
			}
			if (killpg(pp->p_jobid, signum) < 0) {
				/* %s -> %t */
				printf("%t: ", cp);
				printf("%s\n", strerror(errno));
				err++;
			}
			if (signum == SIGTERM || signum == SIGHUP)
				(void) killpg(pp->p_jobid, SIGCONT);
		} else if (!(digit(*cp) || *cp == '-'))
			bferr("Arguments should be jobs or process id's");
		else {
			pid = atoi_(cp);
			if (kill(pid, signum) < 0) {
				printf("%d: ", pid);
				printf("%s\n", strerror(errno));
				err++;
				goto cont;
			}
			if (signum == SIGTERM || signum == SIGHUP)
				(void) kill(pid, SIGCONT);
		}
cont:
		xfree(cp);
		v++;
	}
	(void) sigsetmask(omask);
	if (err)
		error(NULL);
}

/*
 * pstart - start the job in foreground/background
 */
void
pstart(struct process *pp, int foregnd)
{
	struct process *np;
	int omask, jobflags = 0;

#ifdef TRACE
	tprintf("TRACE- pstart()\n");
#endif
	omask = sigblock(sigmask(SIGCHLD));
	np = pp;
	do {
		jobflags |= np->p_flags;
		if (np->p_flags&(PRUNNING|PSTOPPED)) {
			np->p_flags |= PRUNNING;
			np->p_flags &= ~PSTOPPED;
			if (foregnd)
				np->p_flags |= PFOREGND;
			else
				np->p_flags &= ~PFOREGND;
		}
	} while ((np = np->p_friends) != pp);

	if (foregnd)
		pclrcurr(pp);
	else
	{
		if (pprevious && (pprevious->p_flags & PSTOPPED))
		{
			pcurrent = pprevious;
			pprevious = pgetcurr(PNULL);
		}
		else
		{
			pcurrent = pgetcurr(pp);
			if (!pcurrent || (pcurrent->p_flags & PRUNNING))
				pcurrent = pp;
			else
				pprevious = pp;
		}
	}
	(void) pprint(pp, foregnd ? NAME|JOBDIR : NUMBER|NAME|AMPERSAND);
	if (foregnd)
		(void) ioctl(FSHTTY, TIOCSPGRP,  (char *)&pp->p_jobid);
	if (jobflags&PSTOPPED)
		(void) killpg(pp->p_jobid, SIGCONT);
	(void) sigsetmask(omask);
}

void
panystop(int neednl)
{
	struct process *pp;

#ifdef TRACE
	tprintf("TRACE- panystop()\n");
#endif
	chkstop = 2;
	for (pp = proclist.p_next; pp; pp = pp->p_next)
		if (pp->p_flags & PSTOPPED)
			error("\nThere are stopped jobs" + 1 - neednl);
}

struct process *
pfind(tchar *cp)
{
	struct process *pp, *np;

#ifdef TRACE
	tprintf("TRACE- pfind()\n");
#endif
	if (cp == 0 || cp[1] == 0 || eq(cp, S_PARCENTPARCENT /* "%%" */) ||
					eq(cp, S_PARCENTPLUS /* "%+" */)) {
		if (pcurrent == PNULL)
			if ((pcurrent = pgetcurr(PNULL)) == PNULL)
				bferr("No current job");
		return (pcurrent);
	}
	if (eq(cp, S_PARCENTMINUS /* "%-" */) ||
	    eq(cp, S_PARCENTSHARP /* "%#" */)) {
		if (pprevious == PNULL)
			bferr("No previous job");
		return (pprevious);
	}
	if (digit(cp[1])) {
		int index = atoi_(cp+1);
		for (pp = proclist.p_next; pp; pp = pp->p_next)
			if (pp->p_index == index && pp->p_pid == pp->p_jobid)
				return (pp);
		bferr("No such job");
	}
	np = PNULL;
	for (pp = proclist.p_next; pp; pp = pp->p_next)
		if (pp->p_pid == pp->p_jobid) {
			if (cp[1] == '?') {
				tchar *dp;
				for (dp = pp->p_command; *dp; dp++) {
					if (*dp != cp[2])
						continue;
					if (prefix(cp+2, dp))
						goto match;
				}
			} else if (prefix(cp+1, pp->p_command)) {
match:
				if (np)
					bferr("Ambiguous");
				np = pp;
			}
		}
	if (np)
		return (np);
	if (cp[1] == '?')
		bferr("No job matches pattern");
	else
		bferr("No such job");
	/*NOTREACHED*/
}

/*
 * pgetcurr - find most recent job that is not pp, preferably stopped
 */
struct process *
pgetcurr(struct process *pp)
{
	struct process *np;
	struct process *xp = PNULL;

#ifdef TRACE
	tprintf("TRACE- pgetcurr()\n");
#endif
	for (np = proclist.p_next; np; np = np->p_next)
		if (np != pcurrent && np != pp && np->p_pid &&
		    np->p_pid == np->p_jobid) {
			if (np->p_flags & PSTOPPED)
				return (np);
			if (xp == PNULL)
				xp = np;
		}
	return (xp);
}

/*
 * donotify - flag the job so as to report termination asynchronously
 */
void
donotify(tchar **v)
{
	struct process *pp;

#ifdef TRACE
	tprintf("TRACE- donotify()\n");
#endif
	pp = pfind(*++v);
	pp->p_flags |= PNOTIFY;
}

/*
 * Do the fork and whatever should be done in the child side that
 * should not be done if we are not forking at all (like for simple builtin's)
 * Also do everything that needs any signals fiddled with in the parent side
 *
 * Wanttty tells whether process and/or tty pgrps are to be manipulated:
 *	-1:	leave tty alone; inherit pgrp from parent
 *	 0:	already have tty; manipulate process pgrps only
 *	 1:	want to claim tty; manipulate process and tty pgrps
 * It is usually just the value of tpgrp.
 *
 * argument:
 *	 t:	command we are forking for
 */
int
pfork(struct command *t, int wanttty)
{
	int pid;
	bool ignint = 0;
	int pgrp, omask;
	int child_pid;

#ifdef TRACE
	tprintf("TRACE- pfork()\n");
#endif
	/*
	 * A child will be uninterruptible only under very special
	 * conditions. Remember that the semantics of '&' is
	 * implemented by disconnecting the process from the tty so
	 * signals do not need to ignored just for '&'.
	 * Thus signals are set to default action for children unless:
	 *	we have had an "onintr -" (then specifically ignored)
	 *	we are not playing with signals (inherit action)
	 */
	if (setintr)
		ignint = (tpgrp == -1 && (t->t_dflg&FINT))
		    || (gointr && eq(gointr, S_MINUS /* "-" */));
	/*
	 * Hold SIGCHLD until we have the process installed in our table.
	 */
	omask = sigblock(sigmask(SIGCHLD));
	while ((pid = fork()) < 0)
		if (setintr == 0)
			sleep(FORKSLEEP);
		else {
			(void) sigsetmask(omask);
			error("Fork failed");
		}

	/*
	 * setup the process group
	 */
	if (pid == 0)
		child_pid = getpid();
	else
		child_pid = pid;
	pgrp = pcurrjob ? pcurrjob->p_jobid : child_pid;

	if (pid == 0) {
		int sigttou;
		settimes();
		pflushall();
		pcurrjob = PNULL;
		child++;
		if (setintr) {
			setintr = 0;		/* until I think otherwise */
			/*
			 * Children just get blown away on SIGINT, SIGQUIT
			 * unless "onintr -" seen.
			 */
			(void) signal(SIGINT, ignint ? SIG_IGN : SIG_DFL);
			(void) signal(SIGQUIT, ignint ? SIG_IGN : SIG_DFL);
			if (wanttty >= 0) {
				/* make stoppable */
				(void) signal(SIGTSTP, SIG_DFL);
				(void) signal(SIGTTIN, SIG_DFL);
				(void) signal(SIGTTOU, SIG_DFL);
			}
			(void) signal(SIGTERM, parterm);
		} else if (tpgrp == -1 && (t->t_dflg&FINT)) {
			(void) signal(SIGINT, SIG_IGN);
			(void) signal(SIGQUIT, SIG_IGN);
		}
		if (wanttty >= 0 && tpgrp >= 0)
			(void) setpgid(0, pgrp);
		if (wanttty > 0) {
			sigttou = sigblock(sigmask(SIGTTOU) |
					    sigmask(SIGTTIN) |
					    sigmask(SIGTSTP));
			(void) ioctl(FSHTTY, TIOCSPGRP,  (char *)&pgrp);
			sigsetmask(sigttou);
		}
		if (tpgrp > 0)
			tpgrp = 0;		/* gave tty away */
		/*
		 * Nohup and nice apply only to TCOM's but it would be
		 * nice (?!?) if you could say "nohup (foo;bar)"
		 * Then the parser would have to know about nice/nohup/time
		 */
		if (t->t_dflg & FNOHUP)
			(void) signal(SIGHUP, SIG_IGN);
		if (t->t_dflg & FNICE)
			(void) setpriority(PRIO_PROCESS, 0, t->t_nice);
	} else {
		if (wanttty >= 0 && tpgrp >= 0)
			setpgid(pid, pgrp);
		palloc(pid, t);
		(void) sigsetmask(omask);
	}

	return (pid);
}

void
okpcntl(void)
{
#ifdef TRACE
	tprintf("TRACE- okpcntl()\n");
#endif

	if (tpgrp == -1)
		error("No job control in this shell");
	if (tpgrp == 0)
		error("No job control in subshells");
}

void
hupforegnd(void)
{
	struct process *pp;
	int omask;

	omask = sigblock(sigmask(SIGCHLD));
	for (pp = (&proclist)->p_next; pp != PNULL; pp = pp->p_next)
		if (pp->p_pid > 0) {
			if (pp->p_flags & PFOREGND)
				(void) kill(pp->p_pid, SIGHUP);
		}
	(void) sigsetmask(omask);
}
