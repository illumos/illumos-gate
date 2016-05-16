/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright (c) 1989, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2015, Joyent, Inc.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/

#include <stdio.h>
#include <stdio_ext.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <string.h>
#include <memory.h>
#include <signal.h>
#include <wait.h>
#include <limits.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/times.h>
#include <sys/fstyp.h>
#include <sys/fsid.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <libproc.h>
#include <priv.h>
#include "ramdata.h"
#include "proto.h"
#include "htbl.h"

/*
 * The user can trace individual threads by using the 'pid/1,3-6,8-' syntax.
 * This structure keeps track of pid/lwp specifications.  If there are no LWPs
 * specified, then 'lwps' will be NULL.
 */
typedef struct proc_set {
	pid_t		pid;
	const char 	*lwps;
} proc_set_t;

/*
 * Function prototypes for static routines in this file.
 */
void	setup_basetime(hrtime_t, struct timeval *);
int	xcreat(char *);
void	setoutput(int);
void	report(private_t *, time_t);
void	prtim(timestruc_t *);
void	pids(char *, proc_set_t *);
void	psargs(private_t *);
int	control(private_t *, pid_t);
int	grabit(private_t *, proc_set_t *);
void	release(private_t *, pid_t);
void	intr(int);
int	wait4all(void);
void	letgo(private_t *);
void	child_to_file();
void	file_to_parent();
void	per_proc_init();
int	lib_sort(const void *, const void *);
int	key_sort(const void *, const void *);

void	*worker_thread(void *);
void	main_thread(int);

/*
 * Test for empty set.
 * is_empty() should not be called directly.
 */
int	is_empty(const uint32_t *, size_t);
#define	isemptyset(sp) \
	is_empty((uint32_t *)(sp), sizeof (*(sp)) / sizeof (uint32_t))

/*
 * OR the second set into the first set.
 * or_set() should not be called directly.
 */
void	or_set(uint32_t *, const uint32_t *, size_t);
#define	prorset(sp1, sp2) \
	or_set((uint32_t *)(sp1), (uint32_t *)(sp2), \
	sizeof (*(sp1)) / sizeof (uint32_t))

/* fetch or allocate thread-private data */
private_t *
get_private()
{
	void *value;
	private_t *pri = NULL;

	if (thr_getspecific(private_key, &value) == 0)
		pri = value;
	if (pri == NULL) {
		pri = my_malloc(sizeof (*pri), NULL);
		(void) memset(pri, 0, sizeof (*pri));
		pri->sys_path = my_malloc(pri->sys_psize = 16, NULL);
		pri->sys_string = my_malloc(pri->sys_ssize = 32, NULL);
		if (thr_setspecific(private_key, pri) == ENOMEM)
			abend("memory allocation failure", NULL);
	}
	return (pri);
}

/* destructor function for thread-private data */
void
free_private(void *value)
{
	private_t *pri = value;

	if (pri->sys_path)
		free(pri->sys_path);
	if (pri->sys_string)
		free(pri->sys_string);
	if (pri->exec_string)
		free(pri->exec_string);
	if (pri->str_buffer)
		free(pri->str_buffer);
	free(pri);
}

/*
 * This is called by the main thread (via create_thread())
 * and is also called from other threads in worker_thread()
 * while holding truss_lock.  No further locking is required.
 */
void
insert_lwpid(lwpid_t lwpid)
{
	int i;

	truss_nlwp++;
	for (i = 0; i < truss_maxlwp; i++) {
		if (truss_lwpid[i] == 0)
			break;
	}
	if (i == truss_maxlwp) {
		/* double the size of the array */
		truss_lwpid = my_realloc(truss_lwpid,
		    truss_maxlwp * 2 * sizeof (lwpid_t), NULL);
		(void) memset(&truss_lwpid[truss_maxlwp], 0,
		    truss_maxlwp * sizeof (lwpid_t));
		truss_maxlwp *= 2;
	}
	truss_lwpid[i] = lwpid;
}

/*
 * This is called from the first worker thread to encounter one of
 * (leave_hung || interrupt || sigusr1).  It must notify all other
 * worker threads of the same condition.  truss_lock is held.
 */
void
broadcast_signals(void)
{
	static int int_notified = FALSE;
	static int usr1_notified = FALSE;
	static int usr2_notified = FALSE;
	lwpid_t my_id = thr_self();
	lwpid_t lwpid;
	int i;

	if (interrupt && !int_notified) {
		int_notified = TRUE;
		for (i = 0; i < truss_maxlwp; i++) {
			if ((lwpid = truss_lwpid[i]) != 0 && lwpid != my_id)
				(void) thr_kill(lwpid, interrupt);
		}
	}
	if (sigusr1 && !usr1_notified) {
		usr1_notified = TRUE;
		for (i = 0; i < truss_maxlwp; i++) {
			if ((lwpid = truss_lwpid[i]) != 0 && lwpid != my_id)
				(void) thr_kill(lwpid, SIGUSR1);
		}
	}
	if (leave_hung && !usr2_notified) {
		usr2_notified = TRUE;
		for (i = 0; i < truss_maxlwp; i++) {
			if ((lwpid = truss_lwpid[i]) != 0 && lwpid != my_id)
				(void) thr_kill(lwpid, SIGUSR2);
		}
	}
}

static struct ps_lwphandle *
grab_lwp(lwpid_t who)
{
	struct ps_lwphandle *Lwp;
	int gcode;

	if ((Lwp = Lgrab(Proc, who, &gcode)) == NULL) {
		if (gcode != G_NOPROC) {
			(void) fprintf(stderr,
			    "%s: cannot grab LWP %u in process %d,"
			    " reason: %s\n",
			    command, who, (int)Pstatus(Proc)->pr_pid,
			    Lgrab_error(gcode));
			interrupt = SIGTERM;	/* post an interrupt */
		}
	}
	return (Lwp);
}

/*
 * Iteration function called for each initial lwp in the controlled process.
 */
/* ARGSUSED */
int
create_thread(void *arg, const lwpstatus_t *Lsp)
{
	struct ps_lwphandle *new_Lwp;
	lwpid_t lwpid;
	int *count = arg;

	if (lwptrace(Pstatus(Proc)->pr_pid, Lsp->pr_lwpid))
		*count += 1;

	if ((new_Lwp = grab_lwp(Lsp->pr_lwpid)) != NULL) {
		if (thr_create(NULL, 0, worker_thread, new_Lwp,
		    THR_BOUND | THR_SUSPENDED, &lwpid) != 0)
			abend("cannot create lwp to follow child lwp", NULL);
		insert_lwpid(lwpid);
	}
	return (0);
}

int
main(int argc, char *argv[])
{
	private_t *pri;
	struct tms tms;
	struct rlimit rlim;
	int ofd = -1;
	int opt;
	int i;
	int first;
	int errflg = FALSE;
	int badname = FALSE;
	proc_set_t *grab = NULL;
	const pstatus_t *Psp;
	const lwpstatus_t *Lsp;
	int sharedmem;

	/* a few of these need to be initialized to NULL */
	Cp = NULL;
	fcall_tbl = NULL;

	/*
	 * Make sure fd's 0, 1, and 2 are allocated,
	 * just in case truss was invoked from init.
	 */
	while ((i = open("/dev/null", O_RDWR)) >= 0 && i < 2)
		;
	if (i > 2)
		(void) close(i);

	starttime = times(&tms);	/* for elapsed timing */

	/* this should be per-traced-process */
	pagesize = sysconf(_SC_PAGESIZE);

	/* command name (e.g., "truss") */
	if ((command = strrchr(argv[0], '/')) != NULL)
		command++;
	else
		command = argv[0];

	/* set up the initial private data */
	(void) mutex_init(&truss_lock, USYNC_THREAD, NULL);
	(void) mutex_init(&count_lock, USYNC_THREAD, NULL);
	(void) cond_init(&truss_cv, USYNC_THREAD, NULL);
	if (thr_keycreate(&private_key, free_private) == ENOMEM)
		abend("memory allocation failure", NULL);
	pri = get_private();

	Euid = geteuid();
	Egid = getegid();
	Ruid = getuid();
	Rgid = getgid();
	ancestor = getpid();

	prfillset(&trace);	/* default: trace all system calls */
	premptyset(&verbose);	/* default: no syscall verbosity */
	premptyset(&rawout);	/* default: no raw syscall interpretation */

	prfillset(&signals);	/* default: trace all signals */

	prfillset(&faults);	/* default: trace all faults */
	prdelset(&faults, FLTPAGE);	/* except this one */

	premptyset(&readfd);	/* default: dump no buffers */
	premptyset(&writefd);

	premptyset(&syshang);	/* default: hang on no system calls */
	premptyset(&sighang);	/* default: hang on no signals */
	premptyset(&flthang);	/* default: hang on no faults */

	(void) sigemptyset(&emptyset);	/* for unblocking all signals */
	(void) sigfillset(&fillset);	/* for blocking all signals */

#define	OPTIONS	"FpfcaeildDEht:T:v:x:s:S:m:M:u:U:r:w:o:"
	while ((opt = getopt(argc, argv, OPTIONS)) != EOF) {
		switch (opt) {
		case 'F':		/* force grabbing (no O_EXCL) */
			Fflag = PGRAB_FORCE;
			break;
		case 'p':		/* grab processes */
			pflag = TRUE;
			break;
		case 'f':		/* follow children */
			fflag = TRUE;
			break;
		case 'c':		/* don't trace, just count */
			cflag = TRUE;
			iflag = TRUE;	/* implies no interruptable syscalls */
			break;
		case 'a':		/* display argument lists */
			aflag = TRUE;
			break;
		case 'e':		/* display environments */
			eflag = TRUE;
			break;
		case 'i':		/* don't show interruptable syscalls */
			iflag = TRUE;
			break;
		case 'l':		/* show lwp id for each syscall */
			lflag = TRUE;
			break;
		case 'h':		/* debugging: report hash stats */
			hflag = TRUE;
			break;
		case 'd':		/* show time stamps */
			dflag = TRUE;
			break;
		case 'D':		/* show time deltas */
			Dflag = TRUE;
			break;
		case 'E':
			Eflag = TRUE;	/* show syscall times */
			break;
		case 't':		/* system calls to trace */
			if (syslist(optarg, &trace, &tflag))
				badname = TRUE;
			break;
		case 'T':		/* system calls to hang process */
			if (syslist(optarg, &syshang, &Tflag))
				badname = TRUE;
			break;
		case 'v':		/* verbose interpretation of syscalls */
			if (syslist(optarg, &verbose, &vflag))
				badname = TRUE;
			break;
		case 'x':		/* raw interpretation of syscalls */
			if (syslist(optarg, &rawout, &xflag))
				badname = TRUE;
			break;
		case 's':		/* signals to trace */
			if (siglist(pri, optarg, &signals, &sflag))
				badname = TRUE;
			break;
		case 'S':		/* signals to hang process */
			if (siglist(pri, optarg, &sighang, &Sflag))
				badname = TRUE;
			break;
		case 'm':		/* machine faults to trace */
			if (fltlist(optarg, &faults, &mflag))
				badname = TRUE;
			break;
		case 'M':		/* machine faults to hang process */
			if (fltlist(optarg, &flthang, &Mflag))
				badname = TRUE;
			break;
		case 'u':		/* user library functions to trace */
			if (liblist(optarg, 0))
				badname = TRUE;
			break;
		case 'U':		/* user library functions to hang */
			if (liblist(optarg, 1))
				badname = TRUE;
			break;
		case 'r':		/* show contents of read(fd) */
			if (fdlist(optarg, &readfd))
				badname = TRUE;
			break;
		case 'w':		/* show contents of write(fd) */
			if (fdlist(optarg, &writefd))
				badname = TRUE;
			break;
		case 'o':		/* output file for trace */
			oflag = TRUE;
			if (ofd >= 0)
				(void) close(ofd);
			if ((ofd = xcreat(optarg)) < 0) {
				perror(optarg);
				badname = TRUE;
			}
			break;
		default:
			errflg = TRUE;
			break;
		}
	}

	if (badname)
		exit(2);

	/* if -a or -e was specified, force tracing of exec() */
	if (aflag || eflag)
		praddset(&trace, SYS_execve);

	/*
	 * Make sure that all system calls, signals, and machine faults
	 * that hang the process are added to their trace sets.
	 */
	prorset(&trace, &syshang);
	prorset(&signals, &sighang);
	prorset(&faults, &flthang);

	argc -= optind;
	argv += optind;

	/* collect the specified process ids */
	if (pflag && argc > 0) {
		grab = my_malloc(argc * sizeof (proc_set_t),
		    "memory for process-ids");
		while (argc-- > 0)
			pids(*argv++, grab);
	}

	if (errflg || (argc <= 0 && ngrab <= 0)) {
		(void) fprintf(stderr,
	"usage:\t%s [-fcaeildDEF] [-[tTvx] [!]syscalls] [-[sS] [!]signals]\\\n",
		    command);
		(void) fprintf(stderr,
	"\t[-[mM] [!]faults] [-[rw] [!]fds] [-[uU] [!]libs:[:][!]funcs]\\\n");
		(void) fprintf(stderr,
		    "\t[-o outfile]  command | -p pid[/lwps] ...\n");
		exit(2);
	}

	if (argc > 0) {		/* create the controlled process */
		int err;
		char path[PATH_MAX];

		Proc = Pcreate(argv[0], &argv[0], &err, path, sizeof (path));
		if (Proc == NULL) {
			switch (err) {
			case C_PERM:
				(void) fprintf(stderr,
				    "%s: cannot trace set-id or "
				    "unreadable object file: %s\n",
				    command, path);
				break;
			case C_LP64:
				(void) fprintf(stderr,
				    "%s: cannot control _LP64 "
				    "program: %s\n",
				    command, path);
				break;
			case C_NOEXEC:
				(void) fprintf(stderr,
				    "%s: cannot execute program: %s\n",
				    command, argv[0]);
				break;
			case C_NOENT:
				(void) fprintf(stderr,
				    "%s: cannot find program: %s\n",
				    command, argv[0]);
				break;
			case C_STRANGE:
				break;
			default:
				(void) fprintf(stderr, "%s: %s\n",
				    command, Pcreate_error(err));
				break;
			}
			exit(2);
		}
		if (fflag || Dynpat != NULL)
			(void) Psetflags(Proc, PR_FORK);
		else
			(void) Punsetflags(Proc, PR_FORK);
		Psp = Pstatus(Proc);
		Lsp = &Psp->pr_lwp;
		pri->lwpstat = Lsp;
		data_model = Psp->pr_dmodel;
		created = Psp->pr_pid;
		make_pname(pri, 0);
		(void) sysentry(pri, 1);
		pri->length = 0;
		if (!cflag && prismember(&trace, SYS_execve)) {
			pri->exec_string = my_realloc(pri->exec_string,
			    strlen(pri->sys_string) + 1, NULL);
			(void) strcpy(pri->exec_pname, pri->pname);
			(void) strcpy(pri->exec_string, pri->sys_string);
			pri->length += strlen(pri->sys_string);
			pri->exec_lwpid = pri->lwpstat->pr_lwpid;
			pri->sys_leng = 0;
			*pri->sys_string = '\0';
		}
		pri->syslast = Psp->pr_stime;
		pri->usrlast = Psp->pr_utime;
	}

	/*
	 * Now that we have created the victim process,
	 * give ourself a million file descriptors.
	 * This is enough to deal with a multithreaded
	 * victim process that has half a million lwps.
	 */
	rlim.rlim_cur = 1024 * 1024;
	rlim.rlim_max = 1024 * 1024;
	if ((Euid != 0 || setrlimit(RLIMIT_NOFILE, &rlim) != 0) &&
	    getrlimit(RLIMIT_NOFILE, &rlim) == 0) {
		/*
		 * Failing the million, give ourself as many
		 * file descriptors as we can get.
		 */
		rlim.rlim_cur = rlim.rlim_max;
		(void) setrlimit(RLIMIT_NOFILE, &rlim);
	}
	(void) enable_extended_FILE_stdio(-1, -1);

	setoutput(ofd);		/* establish truss output */
	istty = isatty(1);

	if (setvbuf(stdout, (char *)NULL, _IOFBF, MYBUFSIZ) != 0)
		abend("setvbuf() failure", NULL);

	/*
	 * Set up signal dispositions.
	 */
	if (created && (oflag || !istty)) {	/* ignore interrupts */
		(void) sigset(SIGHUP, SIG_IGN);
		(void) sigset(SIGINT, SIG_IGN);
		(void) sigset(SIGQUIT, SIG_IGN);
	} else {				/* receive interrupts */
		if (sigset(SIGHUP, SIG_IGN) == SIG_DFL)
			(void) sigset(SIGHUP, intr);
		if (sigset(SIGINT, SIG_IGN) == SIG_DFL)
			(void) sigset(SIGINT, intr);
		if (sigset(SIGQUIT, SIG_IGN) == SIG_DFL)
			(void) sigset(SIGQUIT, intr);
	}
	(void) sigset(SIGTERM, intr);
	(void) sigset(SIGUSR1, intr);
	(void) sigset(SIGUSR2, intr);
	(void) sigset(SIGPIPE, intr);

	/* don't accumulate zombie children */
	(void) sigset(SIGCLD, SIG_IGN);

	/* create shared mem space for global mutexes */

	sharedmem = (fflag || Dynpat != NULL || ngrab > 1);
	gps = (void *)mmap(NULL, sizeof (struct global_psinfo),
	    PROT_READ|PROT_WRITE,
	    MAP_ANON | (sharedmem? MAP_SHARED : MAP_PRIVATE),
	    -1, (off_t)0);
	if (gps == MAP_FAILED)
		abend("cannot allocate ", "memory for counts");
	i = sharedmem? USYNC_PROCESS : USYNC_THREAD;
	(void) mutex_init(&gps->ps_mutex0, i, NULL);
	(void) mutex_init(&gps->ps_mutex1, i, NULL);
	(void) mutex_init(&gps->fork_lock, i, NULL);
	(void) cond_init(&gps->fork_cv, i, NULL);


	/* config tmp file if counting and following */
	if (fflag && cflag) {
		char *tmps = tempnam("/var/tmp", "truss");
		sfd = open(tmps, O_CREAT|O_APPEND|O_EXCL|O_RDWR, 0600);
		if (sfd == -1)
			abend("Error creating tmpfile", NULL);
		if (unlink(tmps) == -1)
			abend("Error unlinking tmpfile", NULL);
		free(tmps);
		tmps = NULL;
	}

	if (created) {
		per_proc_init();
		procadd(created, NULL);
		show_cred(pri, TRUE, FALSE);
	} else {		/* grab the specified processes */
		int gotone = FALSE;

		i = 0;
		while (i < ngrab) {		/* grab first process */
			if (grabit(pri, &grab[i++])) {
				Psp = Pstatus(Proc);
				Lsp = &Psp->pr_lwp;
				gotone = TRUE;
				break;
			}
		}
		if (!gotone)
			abend(NULL, NULL);
		per_proc_init();
		while (i < ngrab) {		/* grab the remainder */
			proc_set_t *set = &grab[i++];

			(void) mutex_lock(&truss_lock);
			switch (fork()) {
			case -1:
				(void) fprintf(stderr,
			"%s: cannot fork to control process, pid# %d\n",
				    command, (int)set->pid);
				/* FALLTHROUGH */
			default:
				(void) mutex_unlock(&truss_lock);
				continue;	/* parent carries on */

			case 0:			/* child grabs process */
				(void) mutex_unlock(&truss_lock);
				Pfree(Proc);
				descendent = TRUE;
				if (grabit(pri, set)) {
					Psp = Pstatus(Proc);
					Lsp = &Psp->pr_lwp;
					per_proc_init();
					break;
				}
				exit(2);
			}
			break;
		}
		free(grab);
	}


	/*
	 * If running setuid-root, become root for real to avoid
	 * affecting the per-user limitation on the maximum number
	 * of processes (one benefit of running setuid-root).
	 */
	if (Rgid != Egid)
		(void) setgid(Egid);
	if (Ruid != Euid)
		(void) setuid(Euid);

	if (!created && aflag && prismember(&trace, SYS_execve)) {
		psargs(pri);
		Flush();
	}

	if (created && Pstate(Proc) != PS_STOP)	/* assertion */
		if (!(interrupt | sigusr1))
			abend("ASSERT error: process is not stopped", NULL);

	traceeven = trace;		/* trace these system calls */

	/* trace these regardless, even if we don't report results */
	praddset(&traceeven, SYS_exit);
	praddset(&traceeven, SYS_lwp_create);
	praddset(&traceeven, SYS_lwp_exit);
	praddset(&traceeven, SYS_execve);
	praddset(&traceeven, SYS_openat);
	praddset(&traceeven, SYS_openat64);
	praddset(&traceeven, SYS_open);
	praddset(&traceeven, SYS_open64);
	praddset(&traceeven, SYS_vfork);
	praddset(&traceeven, SYS_forksys);

	/* for I/O buffer dumps, force tracing of read()s and write()s */
	if (!isemptyset(&readfd)) {
		praddset(&traceeven, SYS_read);
		praddset(&traceeven, SYS_readv);
		praddset(&traceeven, SYS_pread);
		praddset(&traceeven, SYS_pread64);
		praddset(&traceeven, SYS_recv);
		praddset(&traceeven, SYS_recvfrom);
		praddset(&traceeven, SYS_recvmsg);
	}
	if (!isemptyset(&writefd)) {
		praddset(&traceeven, SYS_write);
		praddset(&traceeven, SYS_writev);
		praddset(&traceeven, SYS_pwrite);
		praddset(&traceeven, SYS_pwrite64);
		praddset(&traceeven, SYS_send);
		praddset(&traceeven, SYS_sendto);
		praddset(&traceeven, SYS_sendmsg);
	}

	if (cflag || Eflag) {
		Psetsysentry(Proc, &traceeven);
	}
	Psetsysexit(Proc, &traceeven);

	/* special case -- cannot trace sysexit because context is changed */
	if (prismember(&trace, SYS_context)) {
		(void) Psysentry(Proc, SYS_context, TRUE);
		(void) Psysexit(Proc, SYS_context, FALSE);
		prdelset(&traceeven, SYS_context);
	}

	/* special case -- trace exec() on entry to get the args */
	(void) Psysentry(Proc, SYS_execve, TRUE);

	/* special case -- sysexit never reached */
	(void) Psysentry(Proc, SYS_exit, TRUE);
	(void) Psysentry(Proc, SYS_lwp_exit, TRUE);
	(void) Psysexit(Proc, SYS_exit, FALSE);
	(void) Psysexit(Proc, SYS_lwp_exit, FALSE);

	Psetsignal(Proc, &signals);	/* trace these signals */
	Psetfault(Proc, &faults);	/* trace these faults */

	/* for function call tracing */
	if (Dynpat != NULL) {
		/* trace these regardless, to deal with function calls */
		(void) Pfault(Proc, FLTBPT, TRUE);
		(void) Pfault(Proc, FLTTRACE, TRUE);

		/* needed for x86 */
		(void) Psetflags(Proc, PR_BPTADJ);

		/*
		 * Find functions and set breakpoints on grabbed process.
		 * A process stopped on exec() gets its breakpoints set below.
		 */
		if ((Lsp->pr_why != PR_SYSENTRY &&
		    Lsp->pr_why != PR_SYSEXIT) ||
		    Lsp->pr_what != SYS_execve) {
			establish_breakpoints();
			establish_stacks();
		}
	}

	/*
	 * Use asynchronous-stop for multithreaded truss.
	 * truss runs one lwp for each lwp in the target process.
	 */
	(void) Psetflags(Proc, PR_ASYNC);

	/* flush out all tracing flags now. */
	Psync(Proc);

	/*
	 * If we grabbed a running process, set it running again.
	 * Since we are tracing lwp_create() and lwp_exit(), the
	 * lwps will not change in the process until we create all
	 * of the truss worker threads.
	 * We leave a created process stopped so its exec() can be reported.
	 */
	first = created? FALSE : TRUE;
	if (!created &&
	    ((Pstate(Proc) == PS_STOP && Lsp->pr_why == PR_REQUESTED) ||
	    (Lsp->pr_flags & PR_DSTOP)))
		first = FALSE;

	main_thread(first);
	return (0);
}

/*
 * Called from main() and from control() after fork().
 */
void
main_thread(int first)
{
	private_t *pri = get_private();
	struct tms tms;
	int flags;
	int retc;
	int i;
	int count;

	/*
	 * Block all signals in the main thread.
	 * Some worker thread will receive signals.
	 */
	(void) thr_sigsetmask(SIG_SETMASK, &fillset, NULL);

	/*
	 * If we are dealing with a previously hung process,
	 * arrange not to leave it hung on the same system call.
	 */
	primary_lwp = (first && Pstate(Proc) == PS_STOP)?
	    Pstatus(Proc)->pr_lwp.pr_lwpid : 0;

	/*
	 * Create worker threads to match the lwps in the target process.
	 */
	truss_nlwp = 0;
	truss_maxlwp = 1;
	truss_lwpid = my_realloc(truss_lwpid, sizeof (lwpid_t), NULL);
	truss_lwpid[0] = 0;
	count = 0;
	(void) Plwp_iter(Proc, create_thread, &count);

	if (count == 0) {
		(void) printf("(Warning: no matching active LWPs found, "
		    "waiting)\n");
		Flush();
	}

	/*
	 * Set all of the truss worker threads running now.
	 */
	(void) mutex_lock(&truss_lock);
	for (i = 0; i < truss_maxlwp; i++) {
		if (truss_lwpid[i])
			(void) thr_continue(truss_lwpid[i]);
	}
	(void) mutex_unlock(&truss_lock);

	/*
	 * Wait until all worker threads terminate.
	 */
	while (thr_join(0, NULL, NULL) == 0)
		continue;

	(void) Punsetflags(Proc, PR_ASYNC);
	Psync(Proc);
	if (sigusr1)
		letgo(pri);
	flags = PRELEASE_CLEAR;
	if (leave_hung)
		flags |= PRELEASE_HANG;
	Prelease(Proc, flags);

	procdel();
	retc = (leave_hung? 0 : wait4all());

	if (!descendent) {
		interrupt = 0;	/* another interrupt kills the report */
		if (cflag) {
			if (fflag)
				file_to_parent();
			report(pri, times(&tms) - starttime);
		}
	} else if (cflag && fflag) {
		child_to_file();
	}

	exit(retc);	/* exit with exit status of created process, else 0 */
}

void *
worker_thread(void *arg)
{
	struct ps_lwphandle *Lwp = (struct ps_lwphandle *)arg;
	const pstatus_t *Psp = Pstatus(Proc);
	const lwpstatus_t *Lsp = Lstatus(Lwp);
	struct syscount *scp;
	lwpid_t who = Lsp->pr_lwpid;
	int first = (who == primary_lwp);
	private_t *pri = get_private();
	int req_flag = 0;
	int leave_it_hung = FALSE;
	int reset_traps = FALSE;
	int gcode;
	int what;
	int ow_in_effect = 0;
	long ow_syscall = 0;
	long ow_subcode = 0;
	char *ow_string = NULL;
	sysset_t full_set;
	sysset_t running_set;
	int dotrace = lwptrace(Psp->pr_pid, Lsp->pr_lwpid);

	pri->Lwp = Lwp;
	pri->lwpstat = Lsp;
	pri->syslast = Lsp->pr_stime;
	pri->usrlast = Lsp->pr_utime;
	make_pname(pri, 0);

	prfillset(&full_set);

	/* we were created with all signals blocked; unblock them */
	(void) thr_sigsetmask(SIG_SETMASK, &emptyset, NULL);

	/*
	 * Run this loop until the victim lwp terminates or we receive
	 * a termination condition (leave_hung | interrupt | sigusr1).
	 */
	for (;;) {
		if (interrupt | sigusr1) {
			(void) Lstop(Lwp, MILLISEC);
			if (Lstate(Lwp) == PS_RUN)
				break;
		}
		if (Lstate(Lwp) == PS_RUN) {
			/* millisecond timeout is for sleeping syscalls */
			uint_t tout = (iflag || req_flag)? 0 : MILLISEC;

			/*
			 * If we are to leave this lwp stopped in sympathy
			 * with another lwp that has been left hung, or if
			 * we have been interrupted or instructed to release
			 * our victim process, and this lwp is stopped but
			 * not on an event of interest to /proc, then just
			 * leave it in that state.
			 */
			if ((leave_hung | interrupt | sigusr1) &&
			    (Lsp->pr_flags & (PR_STOPPED|PR_ISTOP))
			    == PR_STOPPED)
				break;

			(void) Lwait(Lwp, tout);
			if (Lstate(Lwp) == PS_RUN &&
			    tout != 0 && !(interrupt | sigusr1)) {
				(void) mutex_lock(&truss_lock);
				if ((Lsp->pr_flags & PR_STOPPED) &&
				    Lsp->pr_why == PR_JOBCONTROL)
					req_flag = jobcontrol(pri, dotrace);
				else
					req_flag = requested(pri, req_flag,
					    dotrace);
				(void) mutex_unlock(&truss_lock);
			}
			continue;
		}
		data_model = Psp->pr_dmodel;
		if (Lstate(Lwp) == PS_UNDEAD)
			break;
		if (Lstate(Lwp) == PS_LOST) {	/* we lost control */
			/*
			 * After exec(), only one LWP remains in the process.
			 * /proc makes the thread following that LWP receive
			 * EAGAIN (PS_LOST) if the program being exec()ed
			 * is a set-id program.  Every other controlling
			 * thread receives ENOENT (because its LWP vanished).
			 * We are the controlling thread for the exec()ing LWP.
			 * We must wait until all of our siblings terminate
			 * before attempting to reopen the process.
			 */
			(void) mutex_lock(&truss_lock);
			while (truss_nlwp > 1)
				(void) cond_wait(&truss_cv, &truss_lock);
			if (Preopen(Proc) == 0) { /* we got control back */
				/*
				 * We have to free and re-grab the LWP.
				 * The process is guaranteed to be at exit
				 * from exec() or execve() and have only
				 * one LWP, namely this one, and the LWP
				 * is guaranteed to have lwpid == 1.
				 * This "cannot fail".
				 */
				who = 1;
				Lfree(Lwp);
				pri->Lwp = Lwp =
				    Lgrab(Proc, who, &gcode);
				if (Lwp == NULL)
					abend("Lgrab error: ",
					    Lgrab_error(gcode));
				pri->lwpstat = Lsp = Lstatus(Lwp);
				(void) mutex_unlock(&truss_lock);
				continue;
			}

			/* we really lost it */
			if (pri->exec_string && *pri->exec_string) {
				if (pri->exec_pname[0] != '\0')
					(void) fputs(pri->exec_pname, stdout);
				timestamp(pri);
				(void) fputs(pri->exec_string, stdout);
				(void) fputc('\n', stdout);
			} else if (pri->length) {
				(void) fputc('\n', stdout);
			}
			if (pri->sys_valid)
				(void) printf(
			"%s\t*** cannot trace across exec() of %s ***\n",
				    pri->pname, pri->sys_path);
			else
				(void) printf(
				"%s\t*** lost control of process ***\n",
				    pri->pname);
			pri->length = 0;
			Flush();
			(void) mutex_unlock(&truss_lock);
			break;
		}
		if (Lstate(Lwp) != PS_STOP) {
			(void) fprintf(stderr,
			    "%s: state = %d\n", command, Lstate(Lwp));
			abend(pri->pname, "uncaught status of subject lwp");
		}

		make_pname(pri, 0);

		(void) mutex_lock(&truss_lock);

		what = Lsp->pr_what;
		req_flag = 0;

		switch (Lsp->pr_why) {
		case PR_REQUESTED:
			break;
		case PR_SIGNALLED:
			req_flag = signalled(pri, req_flag, dotrace);
			if (Sflag && !first && prismember(&sighang, what))
				leave_it_hung = TRUE;
			break;
		case PR_FAULTED:
			if (what == FLTBPT) {
				int rval;

				(void) Pstop(Proc, 0);
				rval = function_trace(pri, first, 0, dotrace);
				if (rval == 1)
					leave_it_hung = TRUE;
				if (rval >= 0)
					break;
			}
			if (faulted(pri, dotrace) &&
			    Mflag && !first && prismember(&flthang, what))
				leave_it_hung = TRUE;
			break;
		case PR_JOBCONTROL:	/* can't happen except first time */
			req_flag = jobcontrol(pri, dotrace);
			break;
		case PR_SYSENTRY:
			/* protect ourself from operating system error */
			if (what <= 0 || what > PRMAXSYS)
				what = PRMAXSYS;
			pri->length = 0;
			/*
			 * ow_in_effect checks to see whether or not we
			 * are attempting to quantify the time spent in
			 * a one way system call.  This is necessary as
			 * some system calls never return, yet it is desireable
			 * to determine how much time the traced process
			 * spends in these calls.  To do this, a one way
			 * flag is set on SYSENTRY when the call is recieved.
			 * After this, the call mask for the SYSENTRY events
			 * is filled so that the traced process will stop
			 * on the entry to the very next system call.
			 * This appears to the the best way to determine
			 * system time elapsed between a one way system call.
			 * Once the next call occurs, values that have been
			 * stashed are used to record the correct syscall
			 * and time, and the SYSENTRY event mask is restored
			 * so that the traced process may continue.
			 */
			if (dotrace && ow_in_effect) {
				if (cflag) {
					(void) mutex_lock(&count_lock);
					scp = Cp->syscount[ow_syscall];
					if (ow_subcode != -1)
						scp += ow_subcode;
					scp->count++;
					accumulate(&scp->stime,
					    &Lsp->pr_stime, &pri->syslast);
					accumulate(&Cp->usrtotal,
					    &Lsp->pr_utime, &pri->usrlast);
					pri->syslast = Lsp->pr_stime;
					pri->usrlast = Lsp->pr_utime;
					(void) mutex_unlock(&count_lock);
				} else if (Eflag) {
					putpname(pri);
					timestamp(pri);
					(void) printf("%s\n", ow_string);
					free(ow_string);
					ow_string = NULL;
					pri->syslast = Lsp->pr_stime;
				}
				ow_in_effect = 0;
				Psetsysentry(Proc, &running_set);
			}

			/*
			 * Special cases.  Most syscalls are traced on exit.
			 */
			switch (what) {
			case SYS_exit:			/* exit() */
			case SYS_lwp_exit:		/* lwp_exit() */
			case SYS_context:		/* [get|set]context() */
				if (dotrace && cflag &&
				    prismember(&trace, what)) {
					ow_in_effect = 1;
					ow_syscall = what;
					ow_subcode = getsubcode(pri);
					pri->syslast = Lsp->pr_stime;
					running_set =
					    (Pstatus(Proc))->pr_sysentry;
					Psetsysentry(Proc, &full_set);
				} else if (dotrace && Eflag &&
				    prismember(&trace, what)) {
					(void) sysentry(pri, dotrace);
					ow_in_effect = 1;
					ow_string = my_malloc(
					    strlen(pri->sys_string) + 1, NULL);
					(void) strcpy(ow_string,
					    pri->sys_string);
					running_set =
					    (Pstatus(Proc))->pr_sysentry;
					Psetsysentry(Proc, &full_set);
					pri->syslast = Lsp->pr_stime;
				} else if (dotrace &&
				    prismember(&trace, what)) {
					(void) sysentry(pri, dotrace);
					putpname(pri);
					timestamp(pri);
					pri->length +=
					    printf("%s\n", pri->sys_string);
					Flush();
				}
				pri->sys_leng = 0;
				*pri->sys_string = '\0';

				if (what == SYS_exit)
					exit_called = TRUE;
				break;
			case SYS_execve:
				show_cred(pri, FALSE, TRUE);
				(void) sysentry(pri, dotrace);
				if (dotrace && !cflag &&
				    prismember(&trace, what)) {
					pri->exec_string =
					    my_realloc(pri->exec_string,
					    strlen(pri->sys_string) + 1,
					    NULL);
					(void) strcpy(pri->exec_pname,
					    pri->pname);
					(void) strcpy(pri->exec_string,
					    pri->sys_string);
					pri->length += strlen(pri->sys_string);
					pri->exec_lwpid = Lsp->pr_lwpid;
				}
				pri->sys_leng = 0;
				*pri->sys_string = '\0';
				break;
			default:
				if (dotrace && (cflag || Eflag) &&
				    prismember(&trace, what)) {
					pri->syslast = Lsp->pr_stime;
				}
				break;
			}
			if (dotrace && Tflag && !first &&
			    (prismember(&syshang, what) ||
			    (exit_called && prismember(&syshang, SYS_exit))))
				leave_it_hung = TRUE;
			break;
		case PR_SYSEXIT:
			/* check for write open of a /proc file */
			if (what == SYS_openat || what == SYS_openat64 ||
			    what == SYS_open || what == SYS_open64) {
				int readonly;

				(void) sysentry(pri, dotrace);
				pri->Errno = Lsp->pr_errno;
				pri->ErrPriv = Lsp->pr_errpriv;
				readonly =
				    ((what == SYS_openat ||
				    what == SYS_openat64) &&
				    pri->sys_nargs > 2 &&
				    (pri->sys_args[2]&0x3) == O_RDONLY) ||
				    ((what == SYS_open ||
				    what == SYS_open64) &&
				    pri->sys_nargs > 1 &&
				    (pri->sys_args[1]&0x3) == O_RDONLY);
				if ((pri->Errno == 0 || pri->Errno == EBUSY) &&
				    pri->sys_valid && !readonly) {
					int rv = checkproc(pri);
					if (rv == 1 && Fflag != PGRAB_FORCE) {
						/*
						 * The process opened itself
						 * and no -F flag was specified.
						 * Just print the open() call
						 * and let go of the process.
						 */
						if (dotrace && !cflag &&
						    prismember(&trace, what)) {
							putpname(pri);
							timestamp(pri);
							(void) printf("%s\n",
							    pri->sys_string);
							Flush();
						}
						sigusr1 = TRUE;
						(void) mutex_unlock(
						    &truss_lock);
						goto out;
					}
					if (rv == 2) {
						/*
						 * Process opened someone else.
						 * The open is being reissued.
						 * Don't report this one.
						 */
						pri->sys_leng = 0;
						*pri->sys_string = '\0';
						pri->sys_nargs = 0;
						break;
					}
				}
			}
			if (what == SYS_execve && pri->Errno == 0) {
				/*
				 * Refresh the data model on exec() in case it
				 * is different from the parent.  Lwait()
				 * doesn't update process-wide status, so we
				 * have to explicitly call Pstopstatus() to get
				 * the new state.
				 */
				(void) Pstopstatus(Proc, PCNULL, 0);
				data_model = Psp->pr_dmodel;
			}
			if (sysexit(pri, dotrace))
				Flush();
			if (what == SYS_lwp_create && pri->Rval1 != 0) {
				struct ps_lwphandle *new_Lwp;
				lwpid_t lwpid;

				if ((new_Lwp = grab_lwp(pri->Rval1)) != NULL) {
					(void) thr_sigsetmask(SIG_SETMASK,
					    &fillset, NULL);
					if (thr_create(NULL, 0, worker_thread,
					    new_Lwp, THR_BOUND | THR_SUSPENDED,
					    &lwpid) != 0)
						abend("cannot create lwp ",
						    "to follow child lwp");
					insert_lwpid(lwpid);
					(void) thr_continue(lwpid);
					(void) thr_sigsetmask(SIG_SETMASK,
					    &emptyset, NULL);
				}
			}
			pri->sys_nargs = 0;
			if (dotrace && Tflag && !first &&
			    prismember(&syshang, what))
				leave_it_hung = TRUE;
			if (what == SYS_execve && pri->Errno == 0) {
				is_vfork_child = FALSE;
				reset_breakpoints();
				/*
				 * exec() resets the calling LWP's lwpid to 1.
				 * If the LWP has changed its lwpid, then
				 * we have to free and re-grab the LWP
				 * in order to keep libproc consistent.
				 * This "cannot fail".
				 */
				if (who != Lsp->pr_lwpid) {
					/*
					 * We must wait for all of our
					 * siblings to terminate.
					 */
					while (truss_nlwp > 1)
						(void) cond_wait(&truss_cv,
						    &truss_lock);
					who = Lsp->pr_lwpid;
					Lfree(Lwp);
					pri->Lwp = Lwp =
					    Lgrab(Proc, who, &gcode);
					if (Lwp == NULL)
						abend("Lgrab error: ",
						    Lgrab_error(gcode));
					pri->lwpstat = Lsp = Lstatus(Lwp);
				}
			}
			break;
		default:
			req_flag = 0;
			(void) fprintf(stderr,
			    "unknown reason for stopping: %d/%d\n",
			    Lsp->pr_why, what);
			abend(NULL, NULL);
		}

		if (pri->child) {	/* controlled process fork()ed */
			if (fflag || Dynpat != NULL)  {
				if (Lsp->pr_why == PR_SYSEXIT &&
				    (Lsp->pr_what == SYS_vfork ||
				    (Lsp->pr_what == SYS_forksys &&
				    Lsp->pr_sysarg[0] == 2))) {
					is_vfork_child = TRUE;
					(void) Pstop(Proc, 0);
				}
				if (control(pri, pri->child)) {
					(void) mutex_unlock(&truss_lock);
					pri->child = 0;
					if (!fflag) {
						/*
						 * If this is vfork(), then
						 * this clears the breakpoints
						 * in the parent's address space
						 * as well as in the child's.
						 */
						clear_breakpoints();
						Prelease(Proc, PRELEASE_CLEAR);
						_exit(0);
					}
					main_thread(FALSE);
					/* NOTREACHED */
				}

				/*
				 * Here, we are still the parent truss.
				 * If the child messes with the breakpoints and
				 * this is vfork(), we have to set them again.
				 */
				if (Dynpat != NULL && is_vfork_child && !fflag)
					reset_traps = TRUE;
				is_vfork_child = FALSE;
			}
			pri->child = 0;
		}

		if (leave_it_hung) {
			(void) mutex_unlock(&truss_lock);
			break;
		}

		if (reset_traps) {
			/*
			 * To recover from vfork, we must catch the lwp
			 * that issued the vfork() when it returns to user
			 * level, with all other lwps remaining stopped.
			 * For this purpose, we have directed all lwps to
			 * stop and we now set the vfork()ing lwp running
			 * with the PRSTEP flag.  We expect to capture it
			 * when it stops again showing PR_FAULTED/FLTTRACE.
			 * We are holding truss_lock, so no other threads
			 * in truss will set any other lwps in the victim
			 * process running.
			 */
			reset_traps = FALSE;
			(void) Lsetrun(Lwp, 0, PRSTEP);
			do {
				(void) Lwait(Lwp, 0);
			} while (Lstate(Lwp) == PS_RUN);
			if (Lstate(Lwp) == PS_STOP &&
			    Lsp->pr_why == PR_FAULTED &&
			    Lsp->pr_what == FLTTRACE) {
				reestablish_traps();
				(void) Lsetrun(Lwp, 0, PRCFAULT|PRSTOP);
			} else {
				(void) printf("%s\t*** Expected PR_FAULTED/"
				    "FLTTRACE stop following vfork()\n",
				    pri->pname);
			}
		}

		if (Lstate(Lwp) == PS_STOP) {
			int flags = 0;

			if (interrupt | sigusr1) {
				(void) mutex_unlock(&truss_lock);
				break;
			}
			/*
			 * If we must leave this lwp hung is sympathy with
			 * another lwp that is being left hung on purpose,
			 * then push the state onward toward PR_REQUESTED.
			 */
			if (leave_hung) {
				if (Lsp->pr_why == PR_REQUESTED) {
					(void) mutex_unlock(&truss_lock);
					break;
				}
				flags |= PRSTOP;
			}
			if (Lsetrun(Lwp, 0, flags) != 0 &&
			    Lstate(Lwp) != PS_LOST &&
			    Lstate(Lwp) != PS_UNDEAD) {
				(void) mutex_unlock(&truss_lock);
				perror("Lsetrun");
				abend("cannot start subject lwp", NULL);
				/* NOTREACHED */
			}
		}
		first = FALSE;

		(void) mutex_unlock(&truss_lock);
	}

out:
	/* block all signals in preparation for exiting */
	(void) thr_sigsetmask(SIG_SETMASK, &fillset, NULL);

	if (Lstate(Lwp) == PS_UNDEAD || Lstate(Lwp) == PS_LOST)
		(void) mutex_lock(&truss_lock);
	else {
		(void) Lstop(Lwp, MILLISEC);
		(void) mutex_lock(&truss_lock);
		if (Lstate(Lwp) == PS_STOP &&
		    Lsp->pr_why == PR_FAULTED &&
		    Lsp->pr_what == FLTBPT)
			(void) function_trace(pri, 0, 1, dotrace);
	}

	if (dotrace && ow_in_effect) {
		if (cflag) {
			(void) mutex_lock(&count_lock);
			scp = Cp->syscount[ow_syscall];
			if (ow_subcode != -1)
				scp += ow_subcode;
			scp->count++;
			accumulate(&scp->stime,
			    &Lsp->pr_stime, &pri->syslast);
			accumulate(&Cp->usrtotal,
			    &Lsp->pr_utime, &pri->usrlast);
			pri->syslast = Lsp->pr_stime;
			pri->usrlast = Lsp->pr_utime;
			(void) mutex_unlock(&count_lock);
		} else if (Eflag) {
			putpname(pri);
			timestamp(pri);
			(void) printf("%s\n", ow_string);
			free(ow_string);
			ow_string = NULL;
			pri->syslast = Lsp->pr_stime;
		}
		ow_in_effect = 0;
		Psetsysentry(Proc, &running_set);
	}

	if (Lstate(Lwp) == PS_UNDEAD || Lstate(Lwp) == PS_LOST) {
		/*
		 * The victim thread has exited or we lost control of
		 * the process.  Remove ourself from the list of all
		 * truss threads and notify everyone waiting for this.
		 */
		lwpid_t my_id = thr_self();
		int i;

		for (i = 0; i < truss_maxlwp; i++) {
			if (truss_lwpid[i] == my_id) {
				truss_lwpid[i] = 0;
				break;
			}
		}
		if (--truss_nlwp != 0) {
			(void) cond_broadcast(&truss_cv);
		} else {
			/*
			 * The last truss worker thread is terminating.
			 * The address space is gone (UNDEAD) or is
			 * inaccessible (LOST) so we cannot clear the
			 * breakpoints.  Just report the htable stats.
			 */
			report_htable_stats();
		}
	} else {
		/*
		 * The victim thread is not a zombie thread, and we have not
		 * lost control of the process.  We must have gotten here due
		 * to (leave_hung || leave_it_hung || interrupt || sigusr1).
		 * In these cases, we must carefully uninstrument the process
		 * and either set it running or leave it stopped and abandoned.
		 */
		static int nstopped = 0;
		static int cleared = 0;

		if (leave_it_hung)
			leave_hung = TRUE;
		if ((leave_hung | interrupt | sigusr1) == 0)
			abend("(leave_hung | interrupt | sigusr1) == 0", NULL);

		/*
		 * The first truss thread through here needs to instruct all
		 * application threads to stop -- they're not necessarily
		 * going to stop on their own.
		 */
		if (nstopped++ == 0)
			(void) Pdstop(Proc);

		/*
		 * Notify all other worker threads about the reason
		 * for being here (leave_hung || interrupt || sigusr1).
		 */
		broadcast_signals();

		/*
		 * Once the last thread has reached this point, then and
		 * only then is it safe to remove breakpoints and other
		 * instrumentation.  Since breakpoints are executed without
		 * truss_lock held, a monitor thread can't exit until all
		 * breakpoints have been removed, and we can't be sure the
		 * procedure to execute a breakpoint won't temporarily
		 * reinstall a breakpont.  Accordingly, we need to wait
		 * until all threads are in a known state.
		 */
		while (nstopped != truss_nlwp)
			(void) cond_wait(&truss_cv, &truss_lock);

		/*
		 * All truss threads have reached this point.
		 * One of them clears the breakpoints and
		 * wakes up everybody else to finish up.
		 */
		if (cleared++ == 0) {
			/*
			 * All threads should already be stopped,
			 * but just to be safe...
			 */
			(void) Pstop(Proc, MILLISEC);
			clear_breakpoints();
			(void) Psysexit(Proc, SYS_vfork, FALSE);
			(void) Psysexit(Proc, SYS_forksys, FALSE);
			(void) Punsetflags(Proc, PR_FORK);
			Psync(Proc);
			fflag = 0;
			(void) cond_broadcast(&truss_cv);
		}

		if (!leave_hung && Lstate(Lwp) == PS_STOP)
			(void) Lsetrun(Lwp, 0, 0);
	}

	(void) Lfree(Lwp);
	(void) mutex_unlock(&truss_lock);
	return (NULL);
}

/*
 * Give a base date for time stamps, adjusted to the
 * stop time of the selected (first or created) process.
 */
void
setup_basetime(hrtime_t basehrtime, struct timeval *basedate)
{
	const pstatus_t *Psp = Pstatus(Proc);
	(void) mutex_lock(&count_lock);
	Cp->basetime = Psp->pr_lwp.pr_tstamp;
	(void) mutex_unlock(&count_lock);

	if ((dflag|Dflag) && !cflag) {
		const struct tm *ptm;
		const char *ptime;
		const char *pdst;
		hrtime_t delta = basehrtime -
		    ((hrtime_t)Cp->basetime.tv_sec * NANOSEC +
		    Cp->basetime.tv_nsec);

		if (delta > 0) {
			basedate->tv_sec -= (time_t)(delta / NANOSEC);
			basedate->tv_usec -= (delta % NANOSEC) / 1000;
			if (basedate->tv_usec < 0) {
				basedate->tv_sec--;
				basedate->tv_usec += MICROSEC;
			}
		}
		ptm = localtime(&basedate->tv_sec);
		ptime = asctime(ptm);
		if ((pdst = tzname[ptm->tm_isdst ? 1 : 0]) == NULL)
			pdst = "???";
		if (dflag) {
			(void) printf(
			    "Base time stamp:  %ld.%4.4ld  [ %.20s%s %.4s ]\n",
			    basedate->tv_sec, basedate->tv_usec / 100,
			    ptime, pdst, ptime + 20);
			Flush();
		}
	}
}

/*
 * Performs per-process initializations. If truss is following a victim
 * process it will fork additional truss processes to follow new processes
 * created.  Here is where each new truss process gets its per-process data
 * initialized.
 */

void
per_proc_init()
{
	void *pmem;
	struct timeval basedate;
	hrtime_t basehrtime;
	struct syscount *scp;
	int i;
	timestruc_t c_basetime;

	/* Make sure we only configure the basetime for the first truss proc */

	if (Cp == NULL) {
		pmem = my_malloc(sizeof (struct counts) + maxsyscalls() *
		    sizeof (struct syscount), NULL);
		Cp = (struct counts *)pmem;
		basehrtime = gethrtime();
		(void) gettimeofday(&basedate, NULL);
		setup_basetime(basehrtime, &basedate);
	}

	c_basetime = Cp->basetime;

	(void) memset(Cp, 0, sizeof (struct counts) + maxsyscalls() *
	    sizeof (struct syscount));

	Cp->basetime = c_basetime;

	if (fcall_tbl != NULL)
		destroy_hash(fcall_tbl);
	fcall_tbl = init_hash(4096);

	(void) mutex_lock(&count_lock);
	scp = (struct syscount *)(Cp + 1);
	for (i = 0; i <= PRMAXSYS; i++) {
		Cp->syscount[i] = scp;
		scp += nsubcodes(i);
	}
	(void) mutex_unlock(&count_lock);
}


/*
 * Writes child state to a tempfile where it can be read and
 * accumulated by the parent process. The file descriptor is shared
 * among the processes.  Ordering of writes does not matter, it is, however,
 * necessary to ensure that all writes are atomic.
 */

void
child_to_file()
{
	hiter_t *itr;
	hentry_t *ntry;
	hdntry_t fentry;
	char *s = NULL;
	char *t = NULL;
	unsigned char *buf = NULL;
	size_t bufsz = 0;
	size_t i = 0;
	size_t j = 0;

	/* ensure that we are in fact a child process */
	if (!descendent)
		return;

	/* enumerate fcall_tbl (tbl locked until freed) */
	if (Dynpat != NULL) {
		itr = iterate_hash(fcall_tbl);

		ntry = iter_next(itr);
		while (ntry != NULL) {
			fentry.type = HD_hashntry;
			fentry.count = ntry->count;
			s = ntry->key;
			t = ntry->lib;
			i = strlen(s) + 1;
			j = strlen(t) + 1;
			fentry.sz_key = i;
			fentry.sz_lib = j;
			if (i + sizeof (fentry) > bufsz) {
				buf = my_realloc(buf, i + j + sizeof (fentry),
				    NULL);
				bufsz = i + j + sizeof (fentry);
			}
			(void) memcpy(buf, &fentry, sizeof (fentry));
			(void) strlcpy((char *)(buf + sizeof (fentry)), t, j);
			(void) strlcpy((char *)(buf + sizeof (fentry) + j),
			    s, i);
			if (write(sfd, buf, sizeof (fentry) + i + j) == -1)
				abend("Error writing to tmp file", NULL);
			ntry = iter_next(itr);
		}
		iter_free(itr);
	}

	/* Now write the count/syscount structs down */
	bufsz = sizeof (fentry) + (sizeof (struct counts) + maxsyscalls() *
	    sizeof (struct syscount));
	buf = my_realloc(buf, bufsz, NULL);
	fentry.type = HD_cts_syscts;
	fentry.count = 0;	/* undefined, really */
	fentry.sz_key = bufsz - sizeof (fentry);
	fentry.sz_lib = 0;	/* also undefined */
	(void) memcpy(buf, &fentry, sizeof (fentry));
	(void) memcpy((char *)(buf + sizeof (fentry)), Cp,
	    bufsz - sizeof (fentry));
	if (write(sfd, buf, bufsz) == -1)
		abend("Error writing cts/syscts to tmpfile", NULL);

	free(buf);
}

/*
 * The following reads entries from the tempfile back to the parent
 * so that information can be collected and summed for overall statistics.
 * This reads records out of the tempfile.  If they are hash table entries,
 * the record is merged with the hash table kept by the parent process.
 * If the information is a struct count/struct syscount pair, they are
 * copied and added into the count/syscount array kept by the parent.
 */

void
file_to_parent()
{
	hdntry_t ntry;
	char *s = NULL;
	char *t = NULL;
	size_t c_offset = 0;
	size_t filesz;
	size_t t_strsz = 0;
	size_t s_strsz = 0;
	struct stat fsi;

	if (descendent)
		return;

	if (fstat(sfd, &fsi) == -1)
		abend("Error stat-ing tempfile", NULL);
	filesz = fsi.st_size;

	while (c_offset < filesz) {
		/* first get hdntry */
		if (pread(sfd, &ntry, sizeof (hdntry_t), c_offset) !=
		    sizeof (hdntry_t))
			abend("Unable to perform full read of hdntry", NULL);
		c_offset += sizeof (hdntry_t);

		switch (ntry.type) {
		case HD_hashntry:

			/* first get lib string */
			if (ntry.sz_lib > t_strsz) {
				t = my_realloc(t, ntry.sz_lib, NULL);
				t_strsz = ntry.sz_lib;
			}

			(void) memset(t, 0, t_strsz);

			/* now actually get the string */
			if (pread(sfd, t, ntry.sz_lib, c_offset) != ntry.sz_lib)
				abend("Unable to perform full read of lib str",
				    NULL);
			c_offset += ntry.sz_lib;

			/* now get key string */

			if (ntry.sz_key > s_strsz) {
				s = my_realloc(s, ntry.sz_key, NULL);
				s_strsz = ntry.sz_key;
			}
			(void) memset(s, 0, s_strsz);
			if (pread(sfd, s, ntry.sz_key, c_offset) != ntry.sz_key)
				abend("Unable to perform full read of key str",
				    NULL);
			c_offset += ntry.sz_key;

			add_fcall(fcall_tbl, t, s, ntry.count);
			break;

		case HD_cts_syscts:
		{
			struct counts *ncp;
			size_t bfsz = sizeof (struct counts) + maxsyscalls()
			    * sizeof (struct syscount);
			int i;
			struct syscount *sscp;

			if (ntry.sz_key != bfsz)
				abend("cts/syscts size does not sanity check",
				    NULL);
			ncp = my_malloc(ntry.sz_key, NULL);

			if (pread(sfd, ncp, ntry.sz_key, c_offset) !=
			    ntry.sz_key)
				abend("Unable to perform full read of cts",
				    NULL);
			c_offset += ntry.sz_key;

			sscp = (struct syscount *)(ncp + 1);

			(void) mutex_lock(&count_lock);

			Cp->usrtotal.tv_sec += ncp->usrtotal.tv_sec;
			Cp->usrtotal.tv_nsec += ncp->usrtotal.tv_nsec;
			if (Cp->usrtotal.tv_nsec >= NANOSEC) {
				Cp->usrtotal.tv_nsec -= NANOSEC;
				Cp->usrtotal.tv_sec++;
			}
			for (i = 0; i <= PRMAXSYS; i++) {
				ncp->syscount[i] = sscp;
				sscp += nsubcodes(i);
			}

			for (i = 0; i <= PRMAXFAULT; i++) {
				Cp->fltcount[i] += ncp->fltcount[i];
			}

			for (i = 0; i <= PRMAXSIG; i++) {
				Cp->sigcount[i] += ncp->sigcount[i];
			}

			for (i = 0; i <= PRMAXSYS; i++) {
				struct syscount *scp = Cp->syscount[i];
				struct syscount *nscp = ncp->syscount[i];
				int n = nsubcodes(i);
				int subcode;

				for (subcode = 0; subcode < n; subcode++,
				    scp++, nscp++) {
					scp->count += nscp->count;
					scp->error += nscp->error;
					scp->stime.tv_sec += nscp->stime.tv_sec;
					scp->stime.tv_nsec +=
					    nscp->stime.tv_nsec;
					if (scp->stime.tv_nsec >= NANOSEC) {
						scp->stime.tv_nsec -= NANOSEC;
						scp->stime.tv_sec++;
					}
				}
			}
			(void) mutex_unlock(&count_lock);
			free(ncp);
			break;
		}
		default:

			abend("Unknown file entry type encountered", NULL);
			break;

		}

		if (fstat(sfd, &fsi) == -1)
			abend("Error stat-ing tempfile", NULL);
		filesz = fsi.st_size;
	}
	if (s != NULL)
		free(s);
	if (t != NULL)
		free(t);
}

void
make_pname(private_t *pri, id_t tid)
{
	if (!cflag) {
		int ff = (fflag || ngrab > 1);
		int lf = (lflag | tid | (Thr_agent != NULL) | (truss_nlwp > 1));
		pid_t pid = Pstatus(Proc)->pr_pid;
		id_t lwpid = pri->lwpstat->pr_lwpid;

		if (ff != pri->pparam.ff ||
		    lf != pri->pparam.lf ||
		    pid != pri->pparam.pid ||
		    lwpid != pri->pparam.lwpid ||
		    tid != pri->pparam.tid) {
			char *s = pri->pname;

			if (ff)
				s += sprintf(s, "%d", (int)pid);
			if (lf)
				s += sprintf(s, "/%d", (int)lwpid);
			if (tid)
				s += sprintf(s, "@%d", (int)tid);
			if (ff || lf)
				*s++ = ':', *s++ = '\t';
			if (ff && lf && s < pri->pname + 9)
				*s++ = '\t';
			*s = '\0';
			pri->pparam.ff = ff;
			pri->pparam.lf = lf;
			pri->pparam.pid = pid;
			pri->pparam.lwpid = lwpid;
			pri->pparam.tid = tid;
		}
	}
}

/*
 * Print the pri->pname[] string, if any.
 */
void
putpname(private_t *pri)
{
	if (pri->pname[0])
		(void) fputs(pri->pname, stdout);
}

/*
 * Print the timestamp, if requested (-d, -D, or -E).
 */
void
timestamp(private_t *pri)
{
	const lwpstatus_t *Lsp = pri->lwpstat;
	int seconds;
	int fraction;

	if (!(dflag|Dflag|Eflag) || !(Lsp->pr_flags & PR_STOPPED))
		return;

	seconds = Lsp->pr_tstamp.tv_sec - Cp->basetime.tv_sec;
	fraction = Lsp->pr_tstamp.tv_nsec - Cp->basetime.tv_nsec;
	if (fraction < 0) {
		seconds--;
		fraction += NANOSEC;
	}
	/* fraction in 1/10 milliseconds, rounded up */
	fraction = (fraction + 50000) / 100000;
	if (fraction >= (MILLISEC * 10)) {
		seconds++;
		fraction -= (MILLISEC * 10);
	}

	if (dflag)		/* time stamp */
		(void) printf("%2d.%4.4d\t", seconds, fraction);

	if (Dflag) {		/* time delta */
		int oseconds = pri->seconds;
		int ofraction = pri->fraction;

		pri->seconds = seconds;
		pri->fraction = fraction;
		seconds -= oseconds;
		fraction -= ofraction;
		if (fraction < 0) {
			seconds--;
			fraction += (MILLISEC * 10);
		}
		(void) printf("%2d.%4.4d\t", seconds, fraction);
	}

	if (Eflag) {
		seconds = Lsp->pr_stime.tv_sec - pri->syslast.tv_sec;
		fraction = Lsp->pr_stime.tv_nsec - pri->syslast.tv_nsec;

		if (fraction < 0) {
			seconds--;
			fraction += NANOSEC;
		}
		/* fraction in 1/10 milliseconds, rounded up */
		fraction = (fraction + 50000) / 100000;
		if (fraction >= (MILLISEC * 10)) {
			seconds++;
			fraction -= (MILLISEC * 10);
		}
		(void) printf("%2d.%4.4d\t", seconds, fraction);
	}
}

/*
 * Create output file, being careful about
 * suid/sgid and file descriptor 0, 1, 2 issues.
 */
int
xcreat(char *path)
{
	int fd;
	int mode = 0666;

	if (Euid == Ruid && Egid == Rgid)	/* not set-id */
		fd = creat(path, mode);
	else if (access(path, F_OK) != 0) {	/* file doesn't exist */
		/* if directory permissions OK, create file & set ownership */

		char *dir;
		char *p;
		char dot[4];

		/* generate path for directory containing file */
		if ((p = strrchr(path, '/')) == NULL) {	/* no '/' */
			p = dir = dot;
			*p++ = '.';		/* current directory */
			*p = '\0';
		} else if (p == path) {			/* leading '/' */
			p = dir = dot;
			*p++ = '/';		/* root directory */
			*p = '\0';
		} else {				/* embedded '/' */
			dir = path;		/* directory path */
			*p = '\0';
		}

		if (access(dir, W_OK|X_OK) != 0) {
			/* not writeable/searchable */
			*p = '/';
			fd = -1;
		} else {	/* create file and set ownership correctly */
			*p = '/';
			if ((fd = creat(path, mode)) >= 0)
				(void) chown(path, (int)Ruid, (int)Rgid);
		}
	} else if (access(path, W_OK) != 0)	/* file not writeable */
		fd = -1;
	else
		fd = creat(path, mode);

	/*
	 * Make sure it's not one of 0, 1, or 2.
	 * This allows truss to work when spawned by init(1m).
	 */
	if (0 <= fd && fd <= 2) {
		int dfd = fcntl(fd, F_DUPFD, 3);
		(void) close(fd);
		fd = dfd;
	}

	/*
	 * Mark it close-on-exec so created processes don't inherit it.
	 */
	if (fd >= 0)
		(void) fcntl(fd, F_SETFD, FD_CLOEXEC);

	return (fd);
}

void
setoutput(int ofd)
{
	if (ofd < 0) {
		(void) close(1);
		(void) fcntl(2, F_DUPFD, 1);
	} else if (ofd != 1) {
		(void) close(1);
		(void) fcntl(ofd, F_DUPFD, 1);
		(void) close(ofd);
		/* if no stderr, make it the same file */
		if ((ofd = dup(2)) < 0)
			(void) fcntl(1, F_DUPFD, 2);
		else
			(void) close(ofd);
	}
}

/*
 * Accumulate time differencies:  a += e - s;
 */
void
accumulate(timestruc_t *ap, const timestruc_t *ep, const timestruc_t *sp)
{
	ap->tv_sec += ep->tv_sec - sp->tv_sec;
	ap->tv_nsec += ep->tv_nsec - sp->tv_nsec;
	if (ap->tv_nsec >= NANOSEC) {
		ap->tv_nsec -= NANOSEC;
		ap->tv_sec++;
	} else if (ap->tv_nsec < 0) {
		ap->tv_nsec += NANOSEC;
		ap->tv_sec--;
	}
}

int
lib_sort(const void *p1, const void *p2)
{
	int cmpr = 0;
	long i;
	long j;

	hentry_t *t1 = (hentry_t *)p1;
	hentry_t *t2 = (hentry_t *)p2;

	char *p = t1->lib;
	char *q = t2->lib;

	if ((cmpr = strcmp(p, q)) == 0) {
		i = t1->count;
		j = t2->count;
		if (i > j)
			return (-1);
		else if (i < j)
			return (1);
		else {
			p = t1->key;
			q = t2->key;
			return (strcmp(p, q));
		}
	} else
		return (cmpr);
}

void
report(private_t *pri, time_t lapse)	/* elapsed time, clock ticks */
{
	int i;
	long count;
	const char *name;
	long error;
	long total;
	long errtot;
	timestruc_t tickzero;
	timestruc_t ticks;
	timestruc_t ticktot;

	if (descendent)
		return;

	for (i = 0, total = 0; i <= PRMAXFAULT && !interrupt; i++) {
		if ((count = Cp->fltcount[i]) != 0) {
			if (total == 0)		/* produce header */
				(void) printf("faults -------------\n");

			name = proc_fltname(i, pri->flt_name,
			    sizeof (pri->flt_name));

			(void) printf("%s%s\t%4ld\n", name,
			    (((int)strlen(name) < 8)?
			    (const char *)"\t" : (const char *)""),
			    count);
			total += count;
		}
	}
	if (total && !interrupt)
		(void) printf("total:\t\t%4ld\n\n", total);

	for (i = 0, total = 0; i <= PRMAXSIG && !interrupt; i++) {
		if ((count = Cp->sigcount[i]) != 0) {
			if (total == 0)		/* produce header */
				(void) printf("signals ------------\n");
			name = signame(pri, i);
			(void) printf("%s%s\t%4ld\n", name,
			    (((int)strlen(name) < 8)?
			    (const char *)"\t" : (const char *)""),
			    count);
			total += count;
		}
	}
	if (total && !interrupt)
		(void) printf("total:\t\t%4ld\n\n", total);

	if ((Dynpat != NULL) && !interrupt) {
		size_t elem = elements_in_table(fcall_tbl);
		hiter_t *itr = iterate_hash(fcall_tbl);
		hentry_t *tmp = iter_next(itr);
		hentry_t *stbl = my_malloc(elem * sizeof (hentry_t), NULL);
		i = 0;
		while ((tmp != NULL) && (i < elem)) {
			stbl[i].prev = tmp->prev;
			stbl[i].next = tmp->next;
			stbl[i].lib = tmp->lib;
			stbl[i].key = tmp->key;
			stbl[i].count = tmp->count;
			tmp = iter_next(itr);
			i++;
		}
		qsort((void *)stbl, elem, sizeof (hentry_t),
		    lib_sort);
		(void) printf(
		    "\n%-20s %-40s %s\n", "Library:", "Function", "calls");
		for (i = 0; i < elem; i++) {
			(void) printf("%-20s %-40s %ld\n", stbl[i].lib,
			    stbl[i].key, stbl[i].count);
		}
		iter_free(itr);
		free(stbl);
		itr = NULL;
	}

	if (!interrupt)
		(void) printf(
		"\nsyscall               seconds   calls  errors\n");

	total = errtot = 0;
	tickzero.tv_sec = ticks.tv_sec = ticktot.tv_sec = 0;
	tickzero.tv_nsec = ticks.tv_nsec = ticktot.tv_nsec = 0;
	for (i = 0; i <= PRMAXSYS && !interrupt; i++) {
		struct syscount *scp = Cp->syscount[i];
		int n = nsubcodes(i);
		int subcode;

		for (subcode = 0; subcode < n; subcode++, scp++) {
			if ((count = scp->count) != 0 || scp->error) {
				(void) printf("%-19.19s ",
				    sysname(pri, i, subcode));

				ticks = scp->stime;
				accumulate(&ticktot, &ticks, &tickzero);
				prtim(&ticks);

				(void) printf(" %7ld", count);
				if ((error = scp->error) != 0)
					(void) printf(" %7ld", error);
				(void) fputc('\n', stdout);
				total += count;
				errtot += error;
			}
		}
	}

	if (!interrupt) {
		(void) printf(
		"                     --------  ------   ----\n");
		(void) printf("sys totals:         ");
		prtim(&ticktot);
		(void) printf(" %7ld %6ld\n", total, errtot);
	}

	if (!interrupt) {
		(void) printf("usr time:           ");
		prtim(&Cp->usrtotal);
		(void) fputc('\n', stdout);
	}

	if (!interrupt) {
		int hz = (int)sysconf(_SC_CLK_TCK);

		ticks.tv_sec = lapse / hz;
		ticks.tv_nsec = (lapse % hz) * (1000000000 / hz);
		(void) printf("elapsed:            ");
		prtim(&ticks);
		(void) fputc('\n', stdout);
	}
}

void
prtim(timestruc_t *tp)
{
	time_t sec;

	if ((sec = tp->tv_sec) != 0)			/* whole seconds */
		(void) printf("%5lu", sec);
	else
		(void) printf("     ");

	(void) printf(".%3.3ld", tp->tv_nsec/1000000);	/* fraction */
}

/*
 * Gather process id's.
 * Return 0 on success, != 0 on failure.
 */
void
pids(char *arg, proc_set_t *grab)
{
	pid_t pid = -1;
	int i;
	const char *lwps = NULL;

	if ((pid = proc_arg_xpsinfo(arg, PR_ARG_PIDS, NULL, &i, &lwps)) < 0) {
		(void) fprintf(stderr, "%s: cannot trace '%s': %s\n",
		    command, arg, Pgrab_error(i));
		return;
	}

	for (i = 0; i < ngrab; i++)
		if (grab[i].pid == pid)	/* duplicate */
			break;

	if (i == ngrab) {
		grab[ngrab].pid = pid;
		grab[ngrab].lwps = lwps;
		ngrab++;
	} else {
		(void) fprintf(stderr, "%s: duplicate process-id ignored: %d\n",
		    command, (int)pid);
	}
}

/*
 * Report psargs string.
 */
void
psargs(private_t *pri)
{
	pid_t pid = Pstatus(Proc)->pr_pid;
	psinfo_t psinfo;

	if (proc_get_psinfo(pid, &psinfo) == 0)
		(void) printf("%spsargs: %.64s\n",
		    pri->pname, psinfo.pr_psargs);
	else {
		perror("psargs()");
		(void) printf("%s\t*** Cannot read psinfo file for pid %d\n",
		    pri->pname, (int)pid);
	}
}

char *
fetchstring(private_t *pri, long addr, int maxleng)
{
	int nbyte;
	int leng = 0;
	char string[41];

	string[40] = '\0';
	if (pri->str_bsize == 0)  /* initial allocation of string buffer */
		pri->str_buffer =
		    my_malloc(pri->str_bsize = 16, "string buffer");
	*pri->str_buffer = '\0';

	for (nbyte = 40; nbyte == 40 && leng < maxleng; addr += 40) {
		if ((nbyte = Pread(Proc, string, 40, addr)) <= 0)
			return (leng? pri->str_buffer : NULL);
		if (nbyte > 0 &&
		    (nbyte = strlen(string)) > 0) {
			while (leng + nbyte >= pri->str_bsize)
				pri->str_buffer =
				    my_realloc(pri->str_buffer,
				    pri->str_bsize *= 2, "string buffer");
			(void) strcpy(pri->str_buffer+leng, string);
			leng += nbyte;
		}
	}

	if (leng > maxleng)
		leng = maxleng;
	pri->str_buffer[leng] = '\0';

	return (pri->str_buffer);
}

static priv_set_t *
getset(prpriv_t *p, priv_ptype_t set)
{
	return ((priv_set_t *)
	    &p->pr_sets[priv_getsetbyname(set) * p->pr_setsize]);
}

void
show_cred(private_t *pri, int new, int loadonly)
{
	prcred_t cred;
	prpriv_t *privs;

	if (proc_get_cred(Pstatus(Proc)->pr_pid, &cred, 0) < 0) {
		perror("show_cred() - credential");
		(void) printf("%s\t*** Cannot get credentials\n", pri->pname);
		return;
	}
	if ((privs = proc_get_priv(Pstatus(Proc)->pr_pid)) == NULL) {
		perror("show_cred() - privileges");
		(void) printf("%s\t*** Cannot get privileges\n", pri->pname);
		return;
	}

	if (!loadonly && !cflag && prismember(&trace, SYS_execve)) {
		if (new)
			credentials = cred;
		if ((new && cred.pr_ruid != cred.pr_suid) ||
		    cred.pr_ruid != credentials.pr_ruid ||
		    cred.pr_suid != credentials.pr_suid)
			(void) printf(
		"%s    *** SUID: ruid/euid/suid = %d / %d / %d  ***\n",
			    pri->pname,
			    (int)cred.pr_ruid,
			    (int)cred.pr_euid,
			    (int)cred.pr_suid);
		if ((new && cred.pr_rgid != cred.pr_sgid) ||
		    cred.pr_rgid != credentials.pr_rgid ||
		    cred.pr_sgid != credentials.pr_sgid)
			(void) printf(
		"%s    *** SGID: rgid/egid/sgid = %d / %d / %d  ***\n",
			    pri->pname,
			    (int)cred.pr_rgid,
			    (int)cred.pr_egid,
			    (int)cred.pr_sgid);
		if (privdata != NULL && cred.pr_euid != 0) {
			priv_set_t *npset = getset(privs, PRIV_PERMITTED);
			priv_set_t *opset = getset(privdata, PRIV_PERMITTED);
			char *s, *t;
			if (!priv_issubset(npset, opset)) {
				/* Use the to be freed privdata as scratch */
				priv_inverse(opset);
				priv_intersect(npset, opset);
				s = priv_set_to_str(opset, ',', PRIV_STR_SHORT);
				t = priv_set_to_str(npset, ',', PRIV_STR_SHORT);
				(void) printf("%s    *** FPRIV: P/E: %s ***\n",
				    pri->pname,
				    strlen(s) > strlen(t) ? t : s);
				free(s);
				free(t);
			}
		}
	}

	if (privdata != NULL)
		proc_free_priv(privdata);
	credentials = cred;
	privdata = privs;
}

/*
 * Take control of a child process.
 * We come here with truss_lock held.
 */
int
control(private_t *pri, pid_t pid)
{
	const pstatus_t *Psp;
	const lwpstatus_t *Lsp;
	pid_t childpid = 0;
	long flags;
	int rc;

	(void) mutex_lock(&gps->fork_lock);
	while (gps->fork_pid != 0)
		(void) cond_wait(&gps->fork_cv, &gps->fork_lock);
	gps->fork_pid = getpid();	/* parent pid */
	if ((childpid = fork()) == -1) {
		(void) printf("%s\t*** Cannot fork() to control process #%d\n",
		    pri->pname, (int)pid);
		Flush();
		gps->fork_pid = 0;
		(void) cond_broadcast(&gps->fork_cv);
		(void) mutex_unlock(&gps->fork_lock);
		release(pri, pid);
		return (FALSE);
	}

	if (childpid != 0) {
		/*
		 * The parent carries on, after a brief pause.
		 * The parent must wait until the child executes procadd(pid).
		 */
		while (gps->fork_pid != childpid)
			(void) cond_wait(&gps->fork_cv, &gps->fork_lock);
		gps->fork_pid = 0;
		(void) cond_broadcast(&gps->fork_cv);
		(void) mutex_unlock(&gps->fork_lock);
		return (FALSE);
	}

	childpid = getpid();
	descendent = TRUE;
	exit_called = FALSE;
	Pfree(Proc);	/* forget old process */

	/*
	 * The parent process owns the shared gps->fork_lock.
	 * The child must grab it again.
	 */
	(void) mutex_lock(&gps->fork_lock);

	/*
	 * Child grabs the process and retains the tracing flags.
	 */
	if ((Proc = Pgrab(pid, PGRAB_RETAIN, &rc)) == NULL) {
		(void) fprintf(stderr,
		    "%s: cannot control child process, pid# %d: %s\n",
		    command, (int)pid, Pgrab_error(rc));
		gps->fork_pid = childpid;
		(void) cond_broadcast(&gps->fork_cv);
		(void) mutex_unlock(&gps->fork_lock);
		exit(2);
	}

	per_proc_init();
	/*
	 * Add ourself to the set of truss processes
	 * and notify the parent to carry on.
	 */
	procadd(pid, NULL);
	gps->fork_pid = childpid;
	(void) cond_broadcast(&gps->fork_cv);
	(void) mutex_unlock(&gps->fork_lock);

	/*
	 * We may have grabbed the child before it is fully stopped on exit
	 * from fork.  Wait one second (at most) for it to settle down.
	 */
	(void) Pwait(Proc, MILLISEC);
	if (Rdb_agent != NULL)
		Rdb_agent = Prd_agent(Proc);

	Psp = Pstatus(Proc);
	Lsp = &Psp->pr_lwp;
	pri->lwpstat = Lsp;
	data_model = Psp->pr_dmodel;

	make_pname(pri, 0);

	pri->syslast = Psp->pr_stime;
	pri->usrlast = Psp->pr_utime;

	flags = PR_FORK | PR_ASYNC;
	if (Dynpat != NULL)
		flags |= PR_BPTADJ;	/* needed for x86 */
	(void) Psetflags(Proc, flags);

	return (TRUE);
}

/*
 * Take control of an existing process.
 */
int
grabit(private_t *pri, proc_set_t *set)
{
	const pstatus_t *Psp;
	const lwpstatus_t *Lsp;
	int gcode;

	/*
	 * Don't force the takeover unless the -F option was specified.
	 */
	if ((Proc = Pgrab(set->pid, Fflag, &gcode)) == NULL) {
		(void) fprintf(stderr, "%s: %s: %d\n",
		    command, Pgrab_error(gcode), (int)set->pid);
		pri->lwpstat = NULL;
		return (FALSE);
	}
	Psp = Pstatus(Proc);
	Lsp = &Psp->pr_lwp;
	pri->lwpstat = Lsp;

	make_pname(pri, 0);

	data_model = Psp->pr_dmodel;
	pri->syslast = Psp->pr_stime;
	pri->usrlast = Psp->pr_utime;

	if (fflag || Dynpat != NULL)
		(void) Psetflags(Proc, PR_FORK);
	else
		(void) Punsetflags(Proc, PR_FORK);
	procadd(set->pid, set->lwps);
	show_cred(pri, TRUE, FALSE);
	return (TRUE);
}

/*
 * Release process from control.
 */
void
release(private_t *pri, pid_t pid)
{
	/*
	 * The process in question is the child of a traced process.
	 * We are here to turn off the inherited tracing flags.
	 */
	int fd;
	char ctlname[100];
	long ctl[2];

	ctl[0] = PCSET;
	ctl[1] = PR_RLC;

	/* process is freshly forked, no need for exclusive open */
	(void) sprintf(ctlname, "/proc/%d/ctl", (int)pid);
	if ((fd = open(ctlname, O_WRONLY)) < 0 ||
	    write(fd, (char *)ctl, sizeof (ctl)) < 0) {
		perror("release()");
		(void) printf(
		    "%s\t*** Cannot release child process, pid# %d\n",
		    pri->pname, (int)pid);
		Flush();
	}
	if (fd >= 0)	/* run-on-last-close sets the process running */
		(void) close(fd);
}

void
intr(int sig)
{
	/*
	 * SIGUSR1 is special.  It is used by one truss process to tell
	 * another truss process to release its controlled process.
	 * SIGUSR2 is also special.  It is used to wake up threads waiting
	 * for a victim lwp to stop after an event that will leave the
	 * process hung (stopped and abandoned) has occurred.
	 */
	if (sig == SIGUSR1) {
		sigusr1 = TRUE;
	} else if (sig == SIGUSR2) {
		void *value;
		private_t *pri;
		struct ps_lwphandle *Lwp;

		if (thr_getspecific(private_key, &value) == 0 &&
		    (pri = value) != NULL &&
		    (Lwp = pri->Lwp) != NULL)
			(void) Lstop(Lwp, MILLISEC / 10);
	} else {
		interrupt = sig;
	}
}

void
errmsg(const char *s, const char *q)
{
	char msg[512];

	if (s || q) {
		msg[0] = '\0';
		if (command) {
			(void) strcpy(msg, command);
			(void) strcat(msg, ": ");
		}
		if (s)
			(void) strcat(msg, s);
		if (q)
			(void) strcat(msg, q);
		(void) strcat(msg, "\n");
		(void) write(2, msg, (size_t)strlen(msg));
	}
}

void
abend(const char *s, const char *q)
{
	(void) thr_sigsetmask(SIG_SETMASK, &fillset, NULL);
	if (Proc) {
		Flush();
		errmsg(s, q);
		clear_breakpoints();
		(void) Punsetflags(Proc, PR_ASYNC);
		Prelease(Proc, created? PRELEASE_KILL : PRELEASE_CLEAR);
		procdel();
		(void) wait4all();
	} else {
		errmsg(s, q);
	}
	exit(2);
}

/*
 * Allocate memory.
 * If allocation fails then print a message and abort.
 */
void *
my_realloc(void *buf, size_t size, const char *msg)
{
	if ((buf = realloc(buf, size)) == NULL) {
		if (msg != NULL)
			abend("cannot allocate ", msg);
		else
			abend("memory allocation failure", NULL);
	}

	return (buf);
}

void *
my_calloc(size_t nelem, size_t elsize, const char *msg)
{
	void *buf = NULL;

	if ((buf = calloc(nelem, elsize)) == NULL) {
		if (msg != NULL)
			abend("cannot allocate ", msg);
		else
			abend("memory allocation failure", NULL);
	}

	return (buf);
}

void *
my_malloc(size_t size, const char *msg)
{
	return (my_realloc(NULL, size, msg));
}

int
wait4all()
{
	int i;
	pid_t pid;
	int rc = 0;
	int status;

	for (i = 0; i < 10; i++) {
		while ((pid = wait(&status)) != -1) {
			/* return exit() code of the created process */
			if (pid == created) {
				if (WIFEXITED(status))
					rc = WEXITSTATUS(status);
				else
					rc |= 0x80; /* +128 to indicate sig */
			}
		}
		if (errno != EINTR && errno != ERESTART)
			break;
	}

	if (i >= 10)	/* repeated interrupts */
		rc = 2;

	return (rc);
}

void
letgo(private_t *pri)
{
	(void) printf("%s\t*** process otherwise traced, releasing ...\n",
	    pri->pname);
}

/*
 * Test for empty set.
 * support routine used by isemptyset() macro.
 */
int
is_empty(const uint32_t *sp,	/* pointer to set (array of int32's) */
	size_t n)		/* number of int32's in set */
{
	if (n) {
		do {
			if (*sp++)
				return (FALSE);
		} while (--n);
	}

	return (TRUE);
}

/*
 * OR the second set into the first.
 * The sets must be the same size.
 */
void
or_set(uint32_t *sp1, const uint32_t *sp2, size_t n)
{
	if (n) {
		do {
			*sp1++ |= *sp2++;
		} while (--n);
	}
}
