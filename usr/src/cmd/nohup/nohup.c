/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

#include <stdio.h>
#include <stdlib.h>
#include <nl_types.h>
#include <locale.h>
#include <signal.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <libproc.h>
#include <dirent.h>
#include <ctype.h>
#include <sys/time.h>

#define	NOHUP_PERM	(S_IRUSR | S_IWUSR)

#define	NOHUP_NOEXEC	126
#define	NOHUP_ERROR	127

#ifdef XPG4
#define	OPTSTR	""
#else
#define	OPTSTR	"pFag"

static int pnohup(int, char **);

static struct ps_prochandle *g_proc;
static int g_wrfd;
static int g_rdfd;

static int g_dirty;
static volatile int g_interrupt = 0;
#endif

static int opt_p = 0;
static int opt_g = 0;
static int opt_a = 0;
static int opt_F = 0;

static char *pname;

static char nout[PATH_MAX] = "nohup.out";

static int
open_file(void)
{
	char *home;
	int fd;
	int flags = O_CREAT | O_WRONLY | O_APPEND;

	if ((fd = open(nout, flags, NOHUP_PERM)) < 0) {
		if ((home = getenv("HOME")) == NULL)
			return (-1);

		if ((snprintf(nout, sizeof (nout),
		    "%s/nohup.out", home) >= sizeof (nout)) ||
		    (fd = open(nout, flags, NOHUP_PERM)) < 0) {
			return (-1);
		}

	}

	(void) fprintf(stderr, gettext("Sending output to %s\n"), nout);

	return (fd);
}

int
main(int argc, char **argv)
{
	int fd = -1;
	int opt;
	int err;

	if ((pname = strrchr(argv[0], '/')) == NULL)
		pname = argv[0];
	else
		argv[0] = ++pname;		/* for getopt */

	(void) setlocale(LC_ALL, "");

#ifndef TEXT_DOMAIN
#define	TEXT_DOMAIN "SYS_TEST"
#endif

	(void) textdomain(TEXT_DOMAIN);

	while ((opt = getopt(argc, argv, OPTSTR)) != EOF) {
		switch (opt) {
		case 'p':
			opt_p = 1;
			break;
		case 'F':
			opt_F = 1;
			break;
		case 'a':
			opt_a = 1;
			break;
		case 'g':
			opt_g = 1;
			break;
		default:
			goto usage;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc == 0)
		goto usage;			/* need at least one argument */

#ifndef XPG4
	if (opt_p && opt_g)
		goto usage;

	if (opt_p || opt_g)
		return (pnohup(argc, argv));

	if (opt_a || opt_F)
		goto usage;			/* only valid with -p or -g */
#endif

	argv[argc] = NULL;

	(void) signal(SIGHUP, SIG_IGN);		/* POSIX.2 only SIGHUP */
#ifndef XPG4
	(void) signal(SIGQUIT, SIG_IGN);	/* Solaris compatibility */
#endif

	if (isatty(STDOUT_FILENO)) {
		if ((fd = open_file()) < 0)
			goto err;

		(void) dup2(fd, STDOUT_FILENO);
	}

	if (isatty(STDERR_FILENO)) {
		if (fd < 0 && (fd = open_file()) < 0)
			goto err;

		(void) dup2(fd, STDERR_FILENO);
	}

	if (fd >= 0)
		(void) close(fd);

	(void) execvp(argv[0], argv);
	err = errno;

	(void) freopen("/dev/tty", "w", stderr);
	(void) fprintf(stderr, gettext("nohup: %s: %s\n"), argv[0],
	    strerror(err));

	return (err == ENOENT ? NOHUP_ERROR : NOHUP_NOEXEC);

err:
	(void) fprintf(stderr, gettext("nohup: cannot open/create "
	    "nohup.out: %s\n"), strerror(errno));
	return (NOHUP_ERROR);

usage:
#ifdef XPG4
	(void) fprintf(stderr,
	    gettext("usage: nohup command [argument ...]\n"));
#else
	(void) fprintf(stderr, gettext("usage:\n"
	    "\tnohup command [argument ...]\n"
	    "\tnohup -p [-Fa] pid [pid ...]\n"
	    "\tnohup -g [-Fa] pgid [pgid ...]\n"));
#endif
	return (NOHUP_ERROR);
}

#ifndef XPG4

/*
 * File descriptor iteration interface.
 */
typedef int proc_fd_iter_f(void *, int);

static int
Pfd_iter(struct ps_prochandle *P, proc_fd_iter_f *cb, void *data)
{
	char file[64];
	dirent_t *dentp;
	DIR *dirp;
	int ret = 0;

	if (Pstate(P) == PS_DEAD)
		return (-1);

	(void) sprintf(file, "/proc/%d/fd", (int)Pstatus(P)->pr_pid);
	if ((dirp = opendir(file)) == NULL)
		return (-1);

	while ((dentp = readdir(dirp)) != NULL) {
		if (dentp->d_name[0] == '.')
			continue;

		if ((ret = cb(data, atoi(dentp->d_name))) != 0)
			break;
	}

	(void) closedir(dirp);

	return (ret);
}

/*ARGSUSED*/
static int
fd_cb(void *data, int fd)
{
	struct stat64 sbuf;
	int flags;
	int *fdp;
	int oflags;
	char *file;
	int tmpfd;

	/*
	 * See if this fd refers to the controlling tty.
	 */
	if (pr_fstat64(g_proc, fd, &sbuf) == -1 ||
	    sbuf.st_rdev != Ppsinfo(g_proc)->pr_ttydev)
		return (0);

	/*
	 * tty's opened for input are usually O_RDWR so that the program
	 * can change terminal settings. We assume that if there's a
	 * controlling tty in the STDIN_FILENO file descriptor that is
	 * effectively used only for input. If standard in gets dup'ed to
	 * other file descriptors, then we're out of luck unless the
	 * program is nice enough to fcntl it to be O_RDONLY. We close the
	 * file descriptor before we call open to handle the case that
	 * there are no available file descriptors left in the victim. If
	 * our call to pr_open fails, we try to reopen the controlling tty.
	 */
	flags = pr_fcntl(g_proc, fd, F_GETFL, NULL, 0);
	if ((flags & O_ACCMODE) == O_RDONLY || fd == STDIN_FILENO) {
		fdp = &g_rdfd;
		oflags = O_RDONLY;
		file = "/dev/null";
	} else {
		fdp = &g_wrfd;
		oflags = O_RDWR | O_APPEND;
		file = &nout[0];
	}

	if (*fdp < 0) {
		(void) pr_close(g_proc, fd);

		tmpfd = pr_open(g_proc, file, oflags, 0);

		if (tmpfd < 0) {
			(void) fprintf(stderr,
			    gettext("nohup: process %d cannot open %s: %s\n"),
			    Pstatus(g_proc)->pr_pid, file, strerror(errno));

			goto err;
		}

		if (tmpfd != fd) {
			(void) pr_fcntl(g_proc, tmpfd, F_DUP2FD,
			    (void *)(uintptr_t)fd, 0);
			(void) pr_close(g_proc, tmpfd);
		}

		*fdp = fd;
	} else {
		(void) pr_fcntl(g_proc, *fdp, F_DUP2FD, (void *)(uintptr_t)fd,
		    0);
	}

	return (0);

err:
	/*
	 * The victim couldn't open nohup.out so we'll have it try to reopen
	 * its terminal. If this fails, we are left with little recourse.
	 */
	tmpfd = pr_open(g_proc, "/dev/tty", O_RDWR, 0);

	if (tmpfd != fd && tmpfd >= 0) {
		(void) pr_fcntl(g_proc, tmpfd, F_DUP2FD, (void *)(uintptr_t)fd,
		    0);
		(void) pr_close(g_proc, tmpfd);
	}

	return (1);
}

static int
lwp_restartable(short syscall)
{
	switch (syscall) {
	case SYS_read:
	case SYS_readv:
	case SYS_pread:
	case SYS_pread64:
	case SYS_write:
	case SYS_writev:
	case SYS_pwrite:
	case SYS_pwrite64:
	case SYS_ioctl:
	case SYS_fcntl:
	case SYS_getmsg:
	case SYS_getpmsg:
	case SYS_putmsg:
	case SYS_putpmsg:
	case SYS_recv:
	case SYS_recvmsg:
	case SYS_recvfrom:
	case SYS_send:
	case SYS_sendmsg:
	case SYS_sendto:
		return (1);
	}

	return (0);
}

/*ARGSUSED*/
static int
lwp_abort(void *data, const lwpstatus_t *lsp)
{
	struct ps_lwphandle *L;
	int err;

	/*
	 * Continue if this lwp isn't asleep in a restartable syscall.
	 */
	if (!(lsp->pr_flags & PR_ASLEEP) || !lwp_restartable(lsp->pr_syscall))
		return (0);

	L = Lgrab(g_proc, lsp->pr_lwpid, &err);
	(void) Lsetrun(L, 0, PRSABORT);
	Lfree(L);

	/*
	 * Indicate that we have aborted a syscall.
	 */
	g_dirty = 1;

	return (0);
}

/*ARGSUSED*/
static int
lwp_restart(void *data, const lwpstatus_t *lsp)
{
	struct ps_lwphandle *L;
	int err;

	/*
	 * If any lwp is still sleeping in a restartable syscall, it means
	 * the lwp is wedged and we've screwed up.
	 */
	if (lsp->pr_flags & PR_ASLEEP) {
		if (!lwp_restartable(lsp->pr_syscall))
			return (0);
		(void) fprintf(stderr, gettext("nohup: LWP %d failed "
		    "to abort syscall (%d) in process %d\n"),
		    lsp->pr_lwpid, lsp->pr_syscall, Pstatus(g_proc)->pr_pid);
		return (1);
	}

	if (lsp->pr_why == PR_SYSEXIT && lsp->pr_errno == EINTR) {
		L = Lgrab(g_proc, lsp->pr_lwpid, &err);
		(void) Lputareg(L, R_R0, ERESTART);
		Lsync(L);
		Lfree(L);
	}

	return (0);
}

static int
do_pnohup(struct ps_prochandle *P)
{
	int sig = 0;
	struct sigaction sa;
	const pstatus_t *psp;

	psp = Pstatus(P);

	/*
	 * Make sure there's a pending procfs stop directive.
	 */
	(void) Pdstop(P);

	if (Pcreate_agent(P) != 0) {
		(void) fprintf(stderr, gettext("nohup: cannot control "
		    "process %d\n"), psp->pr_pid);
		goto err_no_agent;
	}

	/*
	 * Set the disposition of SIGHUP and SIGQUIT to SIG_IGN. If either
	 * signal is handled by the victim, only adjust the disposition if
	 * the -a flag is set.
	 */
	if (!opt_a && pr_sigaction(P, SIGHUP, NULL, &sa) != 0) {
		(void) fprintf(stderr, gettext("nohup: cannot read "
		    "disposition of SIGHUP for %d\n"), psp->pr_pid);
		goto no_sigs;
	}

	if (!opt_a && sa.sa_handler != SIG_DFL && sa.sa_handler != SIG_IGN) {
		(void) fprintf(stderr, gettext("nohup: SIGHUP already handled "
		    "by %d; use -a to force process to ignore\n"), psp->pr_pid);
		goto no_sigs;
	}

	if (!opt_a && pr_sigaction(P, SIGQUIT, NULL, &sa) != 0) {
		(void) fprintf(stderr, gettext("nohup: cannot read "
		    "disposition of SIGQUIT for %d\n"), psp->pr_pid);
		goto no_sigs;
	}

	if (!opt_a && sa.sa_handler != SIG_DFL && sa.sa_handler != SIG_IGN) {
		(void) fprintf(stderr, gettext("nohup: SIGQUIT already handled "
		    "by %d; use -a to force process to ignore\n"), psp->pr_pid);
		goto no_sigs;
	}

	sa.sa_handler = SIG_IGN;

	if (pr_sigaction(P, SIGHUP, &sa, NULL) != 0) {
		(void) fprintf(stderr, gettext("nohup: cannot set "
		    "disposition of SIGHUP for %d\n"), psp->pr_pid);
		goto no_sigs;
	}

	if (pr_sigaction(P, SIGQUIT, &sa, NULL) != 0) {
		(void) fprintf(stderr, gettext("nohup: cannot set "
		    "disposition of SIGQUIT for %d\n"), psp->pr_pid);
		goto no_sigs;
	}

no_sigs:
	Pdestroy_agent(P);

	/*
	 * We need to close and reassign some file descriptors, but we
	 * need to be careful about how we do it. If we send in the agent
	 * to close some fd and there's an lwp asleep in the kernel due to
	 * a syscall using that fd, then we have a problem. The normal
	 * sequence of events is the close syscall wakes up any threads
	 * that have the fd in question active (see kthread.t_activefd)
	 * and then waits for those threads to wake up and release the
	 * file descriptors (they then continue to user-land to return
	 * EBADF from the syscall). However, recall that if the agent lwp
	 * is present in a process, no other lwps can run, so if the agent
	 * lwp itself is making the call to close(2) (or something else
	 * like dup2 that involves a call to closeandsetf()) then we're in
	 * pretty bad shape. The solution is to abort and restart any lwp
	 * asleep in a syscall on the off chance that it may be using one
	 * of the file descriptors that we want to manipulate.
	 */

	/*
	 * We may need to chase some lwps out of the kernel briefly, so we
	 * send SIGCONT to the process if it was previously stopped due to
	 * a job control signal, and save the current signal to repost it
	 * when we detatch from the victim. A process that is stopped due
	 * to job control will start running as soon as we send SIGCONT
	 * since there is no procfs stop command pending; we use Pdstop to
	 * post a procfs stop request (above).
	 */
	if ((psp->pr_lwp.pr_flags & PR_STOPPED) &&
	    psp->pr_lwp.pr_why == PR_JOBCONTROL) {
		sig = psp->pr_lwp.pr_what;
		(void) kill(psp->pr_pid, SIGCONT);
		(void) Pwait(P, 0);
	}

	(void) Psysexit(P, 0, 1);

	/*
	 * Abort each syscall; set g_dirty if any lwp was asleep.
	 */
	g_dirty = 0;
	g_proc = P;
	(void) Plwp_iter(P, lwp_abort, NULL);

	if (g_dirty) {
		/*
		 * Block until each lwp that was asleep in a syscall has
		 * wandered back up to user-land.
		 */
		(void) Pwait(P, 0);

		/*
		 * Make sure that each lwp has successfully aborted its
		 * syscall and that the syscall gets restarted when we
		 * detach later.
		 */
		if (Plwp_iter(P, lwp_restart, NULL) != 0)
			goto err_no_agent;
	}

	(void) Psysexit(P, 0, 0);

	if (Pcreate_agent(P) != 0) {
		(void) fprintf(stderr, gettext("nohup: cannot control "
		    "process %d\n"), psp->pr_pid);
		goto err_no_agent;
	}

	/*
	 * See if the victim has access to the nohup.out file we created.
	 * If the user does something that would invalidate the result
	 * of this call from here until the call to pr_open, the process
	 * may be left in an inconsistent state -- we assume that the user
	 * is not intentionally trying to shoot himself in the foot.
	 */
	if (pr_access(P, nout, R_OK | W_OK) != 0) {
		(void) fprintf(stderr, gettext("nohup: process %d can not "
		    "access %s: %s\n"), psp->pr_pid, nout, strerror(errno));
		goto err_agent;
	}

	/*
	 * Redirect output to the controlling tty to nohup.out and tty
	 * input to read from /dev/null.
	 */

	g_wrfd = -1;
	g_rdfd = -1;

	(void) Pfd_iter(P, fd_cb, NULL);

	Pdestroy_agent(P);
	if (sig != 0)
		(void) kill(psp->pr_pid, sig);

	return (0);

err_agent:
	Pdestroy_agent(P);
err_no_agent:
	if (sig != 0)
		(void) kill(psp->pr_pid, sig);
	return (-1);
}

/*ARGSUSED*/
static void
intr(int sig)
{
	g_interrupt = 1;
}

static int
pnohup(int argc, char **argv)
{
	struct ps_prochandle *P;
	int i, j;
	int flag = 0;
	int gcode;
	int nh_fd = -1;
	char *fname;
	char *home;
	int nerrs = 0;

	/*
	 * Catch signals from the terminal.
	 */
	if (sigset(SIGHUP, SIG_IGN) == SIG_DFL)
		(void) sigset(SIGHUP, intr);
	if (sigset(SIGINT, SIG_IGN) == SIG_DFL)
		(void) sigset(SIGINT, intr);
	if (sigset(SIGQUIT, SIG_IGN) == SIG_DFL)
		(void) sigset(SIGQUIT, intr);
	(void) sigset(SIGPIPE, intr);
	(void) sigset(SIGTERM, intr);

	if (opt_F)
		flag |= PGRAB_FORCE;

	/*
	 * Set nout to be the full path name of nohup.out and fname to be
	 * the simplified path name:
	 * nout = /cwd/nohup.out	fname = nohup.out
	 * nout = $HOME/nohup.out	fname = $HOME/nohup.out
	 */
	if (getcwd(nout, sizeof (nout) - strlen("/nohup.out") - 1) != NULL) {
		fname = &nout[strlen(nout)];
		(void) strcpy(fname, "/nohup.out");
		fname++;

		nh_fd = open(nout, O_WRONLY | O_CREAT, NOHUP_PERM);
	}

	if (nh_fd == -1 && (home = getenv("HOME")) != NULL) {
		if (snprintf(nout, sizeof (nout),
		    "%s/nohup.out", home) < sizeof (nout)) {
			nh_fd = open(nout, O_WRONLY | O_CREAT, NOHUP_PERM);
			fname = &nout[0];
		}
	}

	if (nh_fd == -1) {
		(void) fprintf(stderr, gettext("nohup: cannot open/create "
		    "nohup.out: %s\n"), strerror(errno));

		return (NOHUP_ERROR);
	}

	if (opt_g) {
		pid_t *pgids;
		int npgids;
		int success;

		/*
		 * Make nohup its own process group leader so that we
		 * don't accidently send SIGSTOP to this process.
		 */
		(void) setpgid(0, 0);

		/*
		 * If a list of process group ids is specified, we want to
		 * first SIGSTOP the whole process group so that we can be
		 * sure not to miss any processes that belong to the group
		 * (it's harder to hit a moving target). We then iterate
		 * over all the processes on the system looking for
		 * members of the given process group to apply the
		 * do_pnohup function to. If the process was stopped due
		 * to our SIGSTOP, we send the process SIGCONT; if the
		 * process was already stopped, we leave it alone.
		 */
		pgids = calloc(argc, sizeof (pid_t));
		pgids[0] = getpid();
		npgids = 1;

		for (i = 0; i < argc; i++) {
			dirent_t *dent;
			DIR *dirp;
			psinfo_t psinfo;
			const pstatus_t *psp;
			pid_t pgid;
			char *end;
			hrtime_t kill_time, stop_time;

			if (isdigit(*argv[i])) {
				pgid = strtol(argv[i], &end, 10);

				/*
				 * kill(2) with pid = 0 or -1 has a special
				 * meaning, so don't let pgid be 0 or 1.
				 */
				if (*end == '\0' && pgid > 1)
					goto pgid_ok;
			}

			(void) fprintf(stderr, gettext("nohup: "
			    "bad process group %s\n"), argv[i]);
			nerrs++;
			continue;

pgid_ok:
			/*
			 * We don't want to nohup a process group twice.
			 */
			for (j = 0; j < npgids; j++) {
				if (pgids[j] == pgid)
					break;
			}

			if (j != npgids)
				continue;

			pgids[npgids++] = pgid;

			/*
			 * Have the kernel stop all members of the process
			 * group; record the time we stopped the process
			 * group so that we can tell if a member stopped
			 * because of this call to kill(2) or if it was
			 * already stopped when we got here. If the user
			 * job control stops the victim between the call
			 * to gethrtime(2) and kill(2), we may send
			 * SIGCONT when we really shouldn't -- we assume
			 * that the user is not trying to shoot himself in
			 * the foot.
			 */
			kill_time = gethrtime();
			if (kill(-pgid, SIGSTOP) == -1) {
				(void) fprintf(stderr, gettext("nohup: cannot "
				    "stop process group %d: %s\n"), pgid,
				    errno != ESRCH ? strerror(errno) :
				    gettext("No such process group"));

				nerrs++;
				continue;
			}

			dirp = opendir("/proc");
			success = 0;
			while ((dent = readdir(dirp)) != NULL && !g_interrupt) {
				if (dent->d_name[0] == '.')
					continue;

				if (proc_arg_psinfo(dent->d_name,
				    PR_ARG_PIDS, &psinfo, &gcode) == -1)
					continue;

				if (psinfo.pr_pgid != pgid)
					continue;

				/*
				 * Ignore zombies.
				 */
				if (psinfo.pr_nlwp == 0)
					continue;

				if ((P = proc_arg_grab(dent->d_name,
				    PR_ARG_PIDS, flag, &gcode)) == NULL) {
					(void) fprintf(stderr, gettext("nohup: "
					    "cannot examine %s: %s\n"),
					    dent->d_name, Pgrab_error(gcode));

					(void) kill(psinfo.pr_pid, SIGCONT);
					continue;
				}

				/*
				 * This implicitly restarts any process that
				 * was stopped via job control any time after
				 * the call to kill(2). This is the desired
				 * behavior since nohup is busy trying to
				 * disassociate a process from its controlling
				 * terminal.
				 */
				psp = Pstatus(P);
				if (psp->pr_lwp.pr_why == PR_JOBCONTROL) {
					stop_time =
					    psp->pr_lwp.pr_tstamp.tv_sec;
					stop_time *= (hrtime_t)NANOSEC;
					stop_time +=
					    psp->pr_lwp.pr_tstamp.tv_nsec;
				} else {
					stop_time = 0;
				}

				if (do_pnohup(P) == 0)
					success = 1;

				/*
				 * If the process was stopped because of
				 * our call to kill(2) (i.e. if it stopped
				 * some time after kill_time) then restart
				 * the process.
				 */
				if (kill_time <= stop_time)
					(void) kill(psinfo.pr_pid, SIGCONT);

				Prelease(P, 0);
			}

			/*
			 * If we didn't successfully nohup any member of the
			 * process group.
			 */
			if (!success)
				nerrs++;

			(void) closedir(dirp);
		}
	} else {
		for (i = 0; i < argc && !g_interrupt; i++) {
			if ((P = proc_arg_grab(argv[i], PR_ARG_PIDS, flag,
			    &gcode)) == NULL) {
				(void) fprintf(stderr,
				    gettext("nohup: cannot examine %s: %s\n"),
				    argv[i], Pgrab_error(gcode));

				nerrs++;
				continue;
			}

			if (do_pnohup(P) != 0)
				nerrs++;

			Prelease(P, 0);
		}
	}

	(void) close(nh_fd);

	if (argc == nerrs)
		return (NOHUP_ERROR);

	(void) fprintf(stderr, gettext("Sending output to %s\n"), fname);

	return (0);
}

#endif /* !XPG4 */
