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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Portions Copyright 2007 Chad Mynhier
 * Copyright 2012 DEY Storage Systems, Inc.  All rights reserved.
 * Copyright (c) 2013 by Delphix. All rights reserved.
 * Copyright 2015, Joyent, Inc.
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <fcntl.h>
#include <string.h>
#include <strings.h>
#include <memory.h>
#include <errno.h>
#include <dirent.h>
#include <limits.h>
#include <signal.h>
#include <atomic.h>
#include <zone.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/param.h>
#include <sys/stack.h>
#include <sys/fault.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/systeminfo.h>

#include "libproc.h"
#include "Pcontrol.h"
#include "Putil.h"
#include "P32ton.h"

int	_libproc_debug;		/* set non-zero to enable debugging printfs */
int	_libproc_no_qsort;	/* set non-zero to inhibit sorting */
				/* of symbol tables */
int	_libproc_incore_elf;	/* only use in-core elf data */

sigset_t blockable_sigs;	/* signals to block when we need to be safe */
static	int	minfd;	/* minimum file descriptor returned by dupfd(fd, 0) */
char	procfs_path[PATH_MAX] = "/proc";

/*
 * Function prototypes for static routines in this module.
 */
static	void	deadcheck(struct ps_prochandle *);
static	void	restore_tracing_flags(struct ps_prochandle *);
static	void	Lfree_internal(struct ps_prochandle *, struct ps_lwphandle *);
static  prheader_t *read_lfile(struct ps_prochandle *, const char *);

/*
 * Ops vector functions for live processes.
 */

/*ARGSUSED*/
static ssize_t
Pread_live(struct ps_prochandle *P, void *buf, size_t n, uintptr_t addr,
    void *data)
{
	return (pread(P->asfd, buf, n, (off_t)addr));
}

/*ARGSUSED*/
static ssize_t
Pwrite_live(struct ps_prochandle *P, const void *buf, size_t n, uintptr_t addr,
    void *data)
{
	return (pwrite(P->asfd, buf, n, (off_t)addr));
}

/*ARGSUSED*/
static int
Pread_maps_live(struct ps_prochandle *P, prmap_t **Pmapp, ssize_t *nmapp,
    void *data)
{
	char mapfile[PATH_MAX];
	int mapfd;
	struct stat statb;
	ssize_t nmap;
	prmap_t *Pmap = NULL;

	(void) snprintf(mapfile, sizeof (mapfile), "%s/%d/map",
	    procfs_path, (int)P->pid);
	if ((mapfd = open(mapfile, O_RDONLY)) < 0 ||
	    fstat(mapfd, &statb) != 0 ||
	    statb.st_size < sizeof (prmap_t) ||
	    (Pmap = malloc(statb.st_size)) == NULL ||
	    (nmap = pread(mapfd, Pmap, statb.st_size, 0L)) <= 0 ||
	    (nmap /= sizeof (prmap_t)) == 0) {
		if (Pmap != NULL)
			free(Pmap);
		if (mapfd >= 0)
			(void) close(mapfd);
		Preset_maps(P); /* utter failure; destroy tables */
		return (-1);
	}
	(void) close(mapfd);

	*Pmapp = Pmap;
	*nmapp = nmap;

	return (0);
}

/*ARGSUSED*/
static void
Pread_aux_live(struct ps_prochandle *P, auxv_t **auxvp, int *nauxp, void *data)
{
	char auxfile[64];
	int fd;
	struct stat statb;
	auxv_t *auxv;
	ssize_t naux;

	(void) snprintf(auxfile, sizeof (auxfile), "%s/%d/auxv",
	    procfs_path, (int)P->pid);
	if ((fd = open(auxfile, O_RDONLY)) < 0) {
		dprintf("%s: failed to open %s: %s\n",
		    __func__, auxfile, strerror(errno));
		return;
	}

	if (fstat(fd, &statb) == 0 &&
	    statb.st_size >= sizeof (auxv_t) &&
	    (auxv = malloc(statb.st_size + sizeof (auxv_t))) != NULL) {
		if ((naux = read(fd, auxv, statb.st_size)) < 0 ||
		    (naux /= sizeof (auxv_t)) < 1) {
			dprintf("%s: read failed: %s\n",
			    __func__, strerror(errno));
			free(auxv);
		} else {
			auxv[naux].a_type = AT_NULL;
			auxv[naux].a_un.a_val = 0L;

			*auxvp = auxv;
			*nauxp = (int)naux;
		}
	}

	(void) close(fd);
}

/*ARGSUSED*/
static int
Pcred_live(struct ps_prochandle *P, prcred_t *pcrp, int ngroups, void *data)
{
	return (proc_get_cred(P->pid, pcrp, ngroups));
}

/*ARGSUSED*/
static int
Ppriv_live(struct ps_prochandle *P, prpriv_t **pprv, void *data)
{
	prpriv_t *pp;

	pp = proc_get_priv(P->pid);
	if (pp == NULL) {
		return (-1);
	}

	*pprv = pp;
	return (0);
}

/*ARGSUSED*/
static const psinfo_t *
Ppsinfo_live(struct ps_prochandle *P, psinfo_t *psinfo, void *data)
{
	if (proc_get_psinfo(P->pid, psinfo) == -1)
		return (NULL);

	return (psinfo);
}

/*ARGSUSED*/
static prheader_t *
Plstatus_live(struct ps_prochandle *P, void *data)
{
	return (read_lfile(P, "lstatus"));
}

/*ARGSUSED*/
static prheader_t *
Plpsinfo_live(struct ps_prochandle *P, void *data)
{
	return (read_lfile(P, "lpsinfo"));
}

/*ARGSUSED*/
static char *
Pplatform_live(struct ps_prochandle *P, char *s, size_t n, void *data)
{
	if (sysinfo(SI_PLATFORM, s, n) == -1)
		return (NULL);
	return (s);
}

/*ARGSUSED*/
static int
Puname_live(struct ps_prochandle *P, struct utsname *u, void *data)
{
	return (uname(u));
}

/*ARGSUSED*/
static char *
Pzonename_live(struct ps_prochandle *P, char *s, size_t n, void *data)
{
	if (getzonenamebyid(P->status.pr_zoneid, s, n) < 0)
		return (NULL);
	s[n - 1] = '\0';
	return (s);
}

/*
 * Callback function for Pfindexec().  We return a match if we can stat the
 * suggested pathname and confirm its device and inode number match our
 * previous information about the /proc/<pid>/object/a.out file.
 */
static int
stat_exec(const char *path, void *arg)
{
	struct stat64 *stp = arg;
	struct stat64 st;

	return (stat64(path, &st) == 0 && S_ISREG(st.st_mode) &&
	    stp->st_dev == st.st_dev && stp->st_ino == st.st_ino);
}

/*ARGSUSED*/
static char *
Pexecname_live(struct ps_prochandle *P, char *buf, size_t buflen, void *data)
{
	char exec_name[PATH_MAX];
	char cwd[PATH_MAX];
	char proc_cwd[64];
	struct stat64 st;
	int ret;

	/*
	 * Try to get the path information first.
	 */
	(void) snprintf(exec_name, sizeof (exec_name),
	    "%s/%d/path/a.out", procfs_path, (int)P->pid);
	if ((ret = readlink(exec_name, buf, buflen - 1)) > 0) {
		buf[ret] = '\0';
		(void) Pfindobj(P, buf, buf, buflen);
		return (buf);
	}

	/*
	 * Stat the executable file so we can compare Pfindexec's
	 * suggestions to the actual device and inode number.
	 */
	(void) snprintf(exec_name, sizeof (exec_name),
	    "%s/%d/object/a.out", procfs_path, (int)P->pid);

	if (stat64(exec_name, &st) != 0 || !S_ISREG(st.st_mode))
		return (NULL);

	/*
	 * Attempt to figure out the current working directory of the
	 * target process.  This only works if the target process has
	 * not changed its current directory since it was exec'd.
	 */
	(void) snprintf(proc_cwd, sizeof (proc_cwd),
	    "%s/%d/path/cwd", procfs_path, (int)P->pid);

	if ((ret = readlink(proc_cwd, cwd, PATH_MAX - 1)) > 0)
		cwd[ret] = '\0';

	(void) Pfindexec(P, ret > 0 ? cwd : NULL, stat_exec, &st);

	return (NULL);
}

#if defined(__i386) || defined(__amd64)
/*ARGSUSED*/
static int
Pldt_live(struct ps_prochandle *P, struct ssd *pldt, int nldt, void *data)
{
	return (proc_get_ldt(P->pid, pldt, nldt));
}
#endif

static const ps_ops_t P_live_ops = {
	.pop_pread	= Pread_live,
	.pop_pwrite	= Pwrite_live,
	.pop_read_maps	= Pread_maps_live,
	.pop_read_aux	= Pread_aux_live,
	.pop_cred	= Pcred_live,
	.pop_priv	= Ppriv_live,
	.pop_psinfo	= Ppsinfo_live,
	.pop_lstatus	= Plstatus_live,
	.pop_lpsinfo	= Plpsinfo_live,
	.pop_platform	= Pplatform_live,
	.pop_uname	= Puname_live,
	.pop_zonename	= Pzonename_live,
	.pop_execname	= Pexecname_live,
#if defined(__i386) || defined(__amd64)
	.pop_ldt	= Pldt_live
#endif
};

/*
 * This is the library's .init handler.
 */
#pragma init(_libproc_init)
void
_libproc_init(void)
{
	_libproc_debug = getenv("LIBPROC_DEBUG") != NULL;
	_libproc_no_qsort = getenv("LIBPROC_NO_QSORT") != NULL;
	_libproc_incore_elf = getenv("LIBPROC_INCORE_ELF") != NULL;

	(void) sigfillset(&blockable_sigs);
	(void) sigdelset(&blockable_sigs, SIGKILL);
	(void) sigdelset(&blockable_sigs, SIGSTOP);
}

void
Pset_procfs_path(const char *path)
{
	(void) snprintf(procfs_path, sizeof (procfs_path), "%s", path);
}

/*
 * Call set_minfd() once before calling dupfd() several times.
 * We assume that the application will not reduce its current file
 * descriptor limit lower than 512 once it has set at least that value.
 */
int
set_minfd(void)
{
	static mutex_t minfd_lock = DEFAULTMUTEX;
	struct rlimit rlim;
	int fd;

	if ((fd = minfd) < 256) {
		(void) mutex_lock(&minfd_lock);
		if ((fd = minfd) < 256) {
			if (getrlimit(RLIMIT_NOFILE, &rlim) != 0)
				rlim.rlim_cur = rlim.rlim_max = 0;
			if (rlim.rlim_cur >= 512)
				fd = 256;
			else if ((fd = rlim.rlim_cur / 2) < 3)
				fd = 3;
			membar_producer();
			minfd = fd;
		}
		(void) mutex_unlock(&minfd_lock);
	}
	return (fd);
}

int
dupfd(int fd, int dfd)
{
	int mfd;

	/*
	 * Make fd be greater than 255 (the 32-bit stdio limit),
	 * or at least make it greater than 2 so that the
	 * program will work when spawned by init(1m).
	 * Also, if dfd is non-zero, dup the fd to be dfd.
	 */
	if ((mfd = minfd) == 0)
		mfd = set_minfd();
	if (dfd > 0 || (0 <= fd && fd < mfd)) {
		if (dfd <= 0)
			dfd = mfd;
		dfd = fcntl(fd, F_DUPFD, dfd);
		(void) close(fd);
		fd = dfd;
	}
	/*
	 * Mark it close-on-exec so any created process doesn't inherit it.
	 */
	if (fd >= 0)
		(void) fcntl(fd, F_SETFD, FD_CLOEXEC);
	return (fd);
}

/*
 * Create a new controlled process.
 * Leave it stopped on successful exit from exec() or execve().
 * Return an opaque pointer to its process control structure.
 * Return NULL if process cannot be created (fork()/exec() not successful).
 */
struct ps_prochandle *
Pxcreate(const char *file,	/* executable file name */
	char *const *argv,	/* argument vector */
	char *const *envp,	/* environment */
	int *perr,	/* pointer to error return code */
	char *path,	/* if non-null, holds exec path name on return */
	size_t len)	/* size of the path buffer */
{
	char execpath[PATH_MAX];
	char procname[PATH_MAX];
	struct ps_prochandle *P;
	pid_t pid;
	int fd;
	char *fname;
	int rc;
	int lasterrno = 0;

	if (len == 0)	/* zero length, no path */
		path = NULL;
	if (path != NULL)
		*path = '\0';

	if ((P = malloc(sizeof (struct ps_prochandle))) == NULL) {
		*perr = C_STRANGE;
		return (NULL);
	}

	if ((pid = fork1()) == -1) {
		free(P);
		*perr = C_FORK;
		return (NULL);
	}

	if (pid == 0) {			/* child process */
		id_t id;
		extern char **environ;

		/*
		 * If running setuid or setgid, reset credentials to normal.
		 */
		if ((id = getgid()) != getegid())
			(void) setgid(id);
		if ((id = getuid()) != geteuid())
			(void) setuid(id);

		Pcreate_callback(P);	/* execute callback (see below) */
		(void) pause();		/* wait for PRSABORT from parent */

		/*
		 * This is ugly.  There is no execvep() function that takes a
		 * path and an environment.  We cheat here by replacing the
		 * global 'environ' variable right before we call this.
		 */
		if (envp)
			environ = (char **)envp;

		(void) execvp(file, argv);  /* execute the program */
		_exit(127);
	}

	/*
	 * Initialize the process structure.
	 */
	(void) memset(P, 0, sizeof (*P));
	(void) mutex_init(&P->proc_lock, USYNC_THREAD, NULL);
	P->flags |= CREATED;
	P->state = PS_RUN;
	P->pid = pid;
	P->asfd = -1;
	P->ctlfd = -1;
	P->statfd = -1;
	P->agentctlfd = -1;
	P->agentstatfd = -1;
	Pinit_ops(&P->ops, &P_live_ops);
	Pinitsym(P);

	/*
	 * Open the /proc/pid files.
	 */
	(void) snprintf(procname, sizeof (procname), "%s/%d/",
	    procfs_path, (int)pid);
	fname = procname + strlen(procname);
	(void) set_minfd();

	/*
	 * Exclusive write open advises others not to interfere.
	 * There is no reason for any of these open()s to fail.
	 */
	(void) strcpy(fname, "as");
	if ((fd = open(procname, (O_RDWR|O_EXCL))) < 0 ||
	    (fd = dupfd(fd, 0)) < 0) {
		dprintf("Pcreate: failed to open %s: %s\n",
		    procname, strerror(errno));
		rc = C_STRANGE;
		goto bad;
	}
	P->asfd = fd;

	(void) strcpy(fname, "status");
	if ((fd = open(procname, O_RDONLY)) < 0 ||
	    (fd = dupfd(fd, 0)) < 0) {
		dprintf("Pcreate: failed to open %s: %s\n",
		    procname, strerror(errno));
		rc = C_STRANGE;
		goto bad;
	}
	P->statfd = fd;

	(void) strcpy(fname, "ctl");
	if ((fd = open(procname, O_WRONLY)) < 0 ||
	    (fd = dupfd(fd, 0)) < 0) {
		dprintf("Pcreate: failed to open %s: %s\n",
		    procname, strerror(errno));
		rc = C_STRANGE;
		goto bad;
	}
	P->ctlfd = fd;

	(void) Pstop(P, 0);	/* stop the controlled process */

	/*
	 * Wait for process to sleep in pause().
	 * If the process has already called pause(), then it should be
	 * stopped (PR_REQUESTED) while asleep in pause and we are done.
	 * Else we set up to catch entry/exit to pause() and set the process
	 * running again, expecting it to stop when it reaches pause().
	 * There is no reason for this to fail other than an interrupt.
	 */
	(void) Psysentry(P, SYS_pause, 1);
	(void) Psysexit(P, SYS_pause, 1);
	for (;;) {
		if (P->state == PS_STOP &&
		    P->status.pr_lwp.pr_syscall == SYS_pause &&
		    (P->status.pr_lwp.pr_why == PR_REQUESTED ||
		    P->status.pr_lwp.pr_why == PR_SYSENTRY ||
		    P->status.pr_lwp.pr_why == PR_SYSEXIT))
			break;

		if (P->state != PS_STOP ||	/* interrupt or process died */
		    Psetrun(P, 0, 0) != 0) {	/* can't restart */
			if (errno == EINTR || errno == ERESTART)
				rc = C_INTR;
			else {
				dprintf("Pcreate: Psetrun failed: %s\n",
				    strerror(errno));
				rc = C_STRANGE;
			}
			goto bad;
		}

		(void) Pwait(P, 0);
	}
	(void) Psysentry(P, SYS_pause, 0);
	(void) Psysexit(P, SYS_pause, 0);

	/*
	 * Kick the process off the pause() and catch
	 * it again on entry to exec() or exit().
	 */
	(void) Psysentry(P, SYS_exit, 1);
	(void) Psysentry(P, SYS_execve, 1);
	if (Psetrun(P, 0, PRSABORT) == -1) {
		dprintf("Pcreate: Psetrun failed: %s\n", strerror(errno));
		rc = C_STRANGE;
		goto bad;
	}
	(void) Pwait(P, 0);
	if (P->state != PS_STOP) {
		dprintf("Pcreate: Pwait failed: %s\n", strerror(errno));
		rc = C_STRANGE;
		goto bad;
	}

	/*
	 * Move the process through instances of failed exec()s
	 * to reach the point of stopped on successful exec().
	 */
	(void) Psysexit(P, SYS_execve, TRUE);

	while (P->state == PS_STOP &&
	    P->status.pr_lwp.pr_why == PR_SYSENTRY &&
	    P->status.pr_lwp.pr_what == SYS_execve) {
		/*
		 * Fetch the exec path name now, before we complete
		 * the exec().  We may lose the process and be unable
		 * to get the information later.
		 */
		(void) Pread_string(P, execpath, sizeof (execpath),
		    (off_t)P->status.pr_lwp.pr_sysarg[0]);
		if (path != NULL)
			(void) strncpy(path, execpath, len);
		/*
		 * Set the process running and wait for
		 * it to stop on exit from the exec().
		 */
		(void) Psetrun(P, 0, 0);
		(void) Pwait(P, 0);

		if (P->state == PS_LOST &&		/* we lost control */
		    Preopen(P) != 0) {		/* and we can't get it back */
			rc = C_PERM;
			goto bad;
		}

		/*
		 * If the exec() failed, continue the loop, expecting
		 * there to be more attempts to exec(), based on PATH.
		 */
		if (P->state == PS_STOP &&
		    P->status.pr_lwp.pr_why == PR_SYSEXIT &&
		    P->status.pr_lwp.pr_what == SYS_execve &&
		    (lasterrno = P->status.pr_lwp.pr_errno) != 0) {
			/*
			 * The exec() failed.  Set the process running and
			 * wait for it to stop on entry to the next exec().
			 */
			(void) Psetrun(P, 0, 0);
			(void) Pwait(P, 0);

			continue;
		}
		break;
	}

	if (P->state == PS_STOP &&
	    P->status.pr_lwp.pr_why == PR_SYSEXIT &&
	    P->status.pr_lwp.pr_what == SYS_execve &&
	    P->status.pr_lwp.pr_errno == 0) {
		/*
		 * The process is stopped on successful exec() or execve().
		 * Turn off all tracing flags and return success.
		 */
		restore_tracing_flags(P);
#ifndef _LP64
		/* We must be a 64-bit process to deal with a 64-bit process */
		if (P->status.pr_dmodel == PR_MODEL_LP64) {
			rc = C_LP64;
			goto bad;
		}
#endif
		/*
		 * Set run-on-last-close so the controlled process
		 * runs even if we die on a signal.
		 */
		(void) Psetflags(P, PR_RLC);
		*perr = 0;
		return (P);
	}

	rc = lasterrno == ENOENT ? C_NOENT : C_NOEXEC;

bad:
	(void) kill(pid, SIGKILL);
	if (path != NULL && rc != C_PERM && rc != C_LP64)
		*path = '\0';
	Pfree(P);
	*perr = rc;
	return (NULL);
}

struct ps_prochandle *
Pcreate(
	const char *file,	/* executable file name */
	char *const *argv,	/* argument vector */
	int *perr,	/* pointer to error return code */
	char *path,	/* if non-null, holds exec path name on return */
	size_t len)	/* size of the path buffer */
{
	return (Pxcreate(file, argv, NULL, perr, path, len));
}

/*
 * Return a printable string corresponding to a Pcreate() error return.
 */
const char *
Pcreate_error(int error)
{
	const char *str;

	switch (error) {
	case C_FORK:
		str = "cannot fork";
		break;
	case C_PERM:
		str = "file is set-id or unreadable";
		break;
	case C_NOEXEC:
		str = "cannot execute file";
		break;
	case C_INTR:
		str = "operation interrupted";
		break;
	case C_LP64:
		str = "program is _LP64, self is not";
		break;
	case C_STRANGE:
		str = "unanticipated system error";
		break;
	case C_NOENT:
		str = "cannot find executable file";
		break;
	default:
		str = "unknown error";
		break;
	}

	return (str);
}

/*
 * Callback to execute in each child process created with Pcreate() after fork
 * but before it execs the new process image.  By default, we do nothing, but
 * by calling this function we allow the client program to define its own
 * version of the function which will interpose on our empty default.  This
 * may be useful for clients that need to modify signal dispositions, terminal
 * attributes, or process group and session properties for each new victim.
 */
/*ARGSUSED*/
void
Pcreate_callback(struct ps_prochandle *P)
{
	/* nothing to do here */
}

/*
 * Grab an existing process.
 * Return an opaque pointer to its process control structure.
 *
 * pid:		UNIX process ID.
 * flags:
 *	PGRAB_RETAIN	Retain tracing flags (default clears all tracing flags).
 *	PGRAB_FORCE	Grab regardless of whether process is already traced.
 *	PGRAB_RDONLY	Open the address space file O_RDONLY instead of O_RDWR,
 *                      and do not open the process control file.
 *	PGRAB_NOSTOP	Open the process but do not force it to stop.
 * perr:	pointer to error return code.
 */
struct ps_prochandle *
Pgrab(pid_t pid, int flags, int *perr)
{
	struct ps_prochandle *P;
	int fd, omode;
	char procname[PATH_MAX];
	char *fname;
	int rc = 0;

	/*
	 * PGRAB_RDONLY means that we do not open the /proc/<pid>/control file,
	 * and so it implies RETAIN and NOSTOP since both require control.
	 */
	if (flags & PGRAB_RDONLY)
		flags |= PGRAB_RETAIN | PGRAB_NOSTOP;

	if ((P = malloc(sizeof (struct ps_prochandle))) == NULL) {
		*perr = G_STRANGE;
		return (NULL);
	}

	P->asfd = -1;
	P->ctlfd = -1;
	P->statfd = -1;

again:	/* Come back here if we lose it in the Window of Vulnerability */
	if (P->ctlfd >= 0)
		(void) close(P->ctlfd);
	if (P->asfd >= 0)
		(void) close(P->asfd);
	if (P->statfd >= 0)
		(void) close(P->statfd);
	(void) memset(P, 0, sizeof (*P));
	(void) mutex_init(&P->proc_lock, USYNC_THREAD, NULL);
	P->ctlfd = -1;
	P->asfd = -1;
	P->statfd = -1;
	P->agentctlfd = -1;
	P->agentstatfd = -1;
	Pinit_ops(&P->ops, &P_live_ops);
	Pinitsym(P);

	/*
	 * Open the /proc/pid files
	 */
	(void) snprintf(procname, sizeof (procname), "%s/%d/",
	    procfs_path, (int)pid);
	fname = procname + strlen(procname);
	(void) set_minfd();

	/*
	 * Request exclusive open to avoid grabbing someone else's
	 * process and to prevent others from interfering afterwards.
	 * If this fails and the 'PGRAB_FORCE' flag is set, attempt to
	 * open non-exclusively.
	 */
	(void) strcpy(fname, "as");
	omode = (flags & PGRAB_RDONLY) ? O_RDONLY : O_RDWR;

	if (((fd = open(procname, omode | O_EXCL)) < 0 &&
	    (fd = ((flags & PGRAB_FORCE)? open(procname, omode) : -1)) < 0) ||
	    (fd = dupfd(fd, 0)) < 0) {
		switch (errno) {
		case ENOENT:
			rc = G_NOPROC;
			break;
		case EACCES:
		case EPERM:
			rc = G_PERM;
			break;
		case EMFILE:
			rc = G_NOFD;
			break;
		case EBUSY:
			if (!(flags & PGRAB_FORCE) || geteuid() != 0) {
				rc = G_BUSY;
				break;
			}
			/* FALLTHROUGH */
		default:
			dprintf("Pgrab: failed to open %s: %s\n",
			    procname, strerror(errno));
			rc = G_STRANGE;
			break;
		}
		goto err;
	}
	P->asfd = fd;

	(void) strcpy(fname, "status");
	if ((fd = open(procname, O_RDONLY)) < 0 ||
	    (fd = dupfd(fd, 0)) < 0) {
		switch (errno) {
		case ENOENT:
			rc = G_NOPROC;
			break;
		case EMFILE:
			rc = G_NOFD;
			break;
		default:
			dprintf("Pgrab: failed to open %s: %s\n",
			    procname, strerror(errno));
			rc = G_STRANGE;
			break;
		}
		goto err;
	}
	P->statfd = fd;

	if (!(flags & PGRAB_RDONLY)) {
		(void) strcpy(fname, "ctl");
		if ((fd = open(procname, O_WRONLY)) < 0 ||
		    (fd = dupfd(fd, 0)) < 0) {
			switch (errno) {
			case ENOENT:
				rc = G_NOPROC;
				break;
			case EMFILE:
				rc = G_NOFD;
				break;
			default:
				dprintf("Pgrab: failed to open %s: %s\n",
				    procname, strerror(errno));
				rc = G_STRANGE;
				break;
			}
			goto err;
		}
		P->ctlfd = fd;
	}

	P->state = PS_RUN;
	P->pid = pid;

	/*
	 * We are now in the Window of Vulnerability (WoV).  The process may
	 * exec() a setuid/setgid or unreadable object file between the open()
	 * and the PCSTOP.  We will get EAGAIN in this case and must start over.
	 * As Pstopstatus will trigger the first read() from a /proc file,
	 * we also need to handle EOVERFLOW here when 32-bit as an indicator
	 * that this process is 64-bit.  Finally, if the process has become
	 * a zombie (PS_UNDEAD) while we were trying to grab it, just remain
	 * silent about this and pretend there was no process.
	 */
	if (Pstopstatus(P, PCNULL, 0) != 0) {
#ifndef _LP64
		if (errno == EOVERFLOW) {
			rc = G_LP64;
			goto err;
		}
#endif
		if (P->state == PS_LOST) {	/* WoV */
			(void) mutex_destroy(&P->proc_lock);
			goto again;
		}

		if (P->state == PS_UNDEAD)
			rc = G_NOPROC;
		else
			rc = G_STRANGE;

		goto err;
	}

	/*
	 * If the process is a system process, we can't control it even as root
	 */
	if (P->status.pr_flags & PR_ISSYS) {
		rc = G_SYS;
		goto err;
	}
#ifndef _LP64
	/*
	 * We must be a 64-bit process to deal with a 64-bit process
	 */
	if (P->status.pr_dmodel == PR_MODEL_LP64) {
		rc = G_LP64;
		goto err;
	}
#endif

	/*
	 * Remember the status for use by Prelease().
	 */
	P->orig_status = P->status;	/* structure copy */

	/*
	 * Before stopping the process, make sure we are not grabbing ourselves.
	 * If we are, make sure we are doing it PGRAB_RDONLY.
	 */
	if (pid == getpid()) {
		/*
		 * Verify that the process is really ourself:
		 * Set a magic number, read it through the
		 * /proc file and see if the results match.
		 */
		uint32_t magic1 = 0;
		uint32_t magic2 = 2;

		errno = 0;

		if (Pread(P, &magic2, sizeof (magic2), (uintptr_t)&magic1)
		    == sizeof (magic2) &&
		    magic2 == 0 &&
		    (magic1 = 0xfeedbeef) &&
		    Pread(P, &magic2, sizeof (magic2), (uintptr_t)&magic1)
		    == sizeof (magic2) &&
		    magic2 == 0xfeedbeef &&
		    !(flags & PGRAB_RDONLY)) {
			rc = G_SELF;
			goto err;
		}
	}

	/*
	 * If the process is already stopped or has been directed
	 * to stop via /proc, do not set run-on-last-close.
	 */
	if (!(P->status.pr_lwp.pr_flags & (PR_ISTOP|PR_DSTOP)) &&
	    !(flags & PGRAB_RDONLY)) {
		/*
		 * Mark the process run-on-last-close so
		 * it runs even if we die from SIGKILL.
		 */
		if (Psetflags(P, PR_RLC) != 0) {
			if (errno == EAGAIN) {	/* WoV */
				(void) mutex_destroy(&P->proc_lock);
				goto again;
			}
			if (errno == ENOENT)	/* No complaint about zombies */
				rc = G_ZOMB;
			else {
				dprintf("Pgrab: failed to set RLC\n");
				rc = G_STRANGE;
			}
			goto err;
		}
	}

	/*
	 * If a stop directive is pending and the process has not yet stopped,
	 * then synchronously wait for the stop directive to take effect.
	 * Limit the time spent waiting for the process to stop by iterating
	 * at most 10 times. The time-out of 20 ms corresponds to the time
	 * between sending the stop directive and the process actually stopped
	 * as measured by DTrace on a slow, busy system. If the process doesn't
	 * stop voluntarily, clear the PR_DSTOP flag so that the code below
	 * forces the process to stop.
	 */
	if (!(flags & PGRAB_RDONLY)) {
		int niter = 0;
		while ((P->status.pr_lwp.pr_flags & (PR_STOPPED|PR_DSTOP)) ==
		    PR_DSTOP && niter < 10 &&
		    Pstopstatus(P, PCTWSTOP, 20) != 0) {
			niter++;
			if (flags & PGRAB_NOSTOP)
				break;
		}
		if (niter == 10 && !(flags & PGRAB_NOSTOP)) {
			/* Try it harder down below */
			P->status.pr_lwp.pr_flags &= ~PR_DSTOP;
		}
	}

	/*
	 * If the process is not already stopped or directed to stop
	 * and PGRAB_NOSTOP was not specified, stop the process now.
	 */
	if (!(P->status.pr_lwp.pr_flags & (PR_ISTOP|PR_DSTOP)) &&
	    !(flags & PGRAB_NOSTOP)) {
		/*
		 * Stop the process, get its status and signal/syscall masks.
		 */
		if (((P->status.pr_lwp.pr_flags & PR_STOPPED) &&
		    Pstopstatus(P, PCDSTOP, 0) != 0) ||
		    Pstopstatus(P, PCSTOP, 2000) != 0) {
#ifndef _LP64
			if (errno == EOVERFLOW) {
				rc = G_LP64;
				goto err;
			}
#endif
			if (P->state == PS_LOST) {	/* WoV */
				(void) mutex_destroy(&P->proc_lock);
				goto again;
			}
			if ((errno != EINTR && errno != ERESTART) ||
			    (P->state != PS_STOP &&
			    !(P->status.pr_flags & PR_DSTOP))) {
				if (P->state != PS_RUN && errno != ENOENT) {
					dprintf("Pgrab: failed to PCSTOP\n");
					rc = G_STRANGE;
				} else {
					rc = G_ZOMB;
				}
				goto err;
			}
		}

		/*
		 * Process should now either be stopped via /proc or there
		 * should be an outstanding stop directive.
		 */
		if (!(P->status.pr_flags & (PR_ISTOP|PR_DSTOP))) {
			dprintf("Pgrab: process is not stopped\n");
			rc = G_STRANGE;
			goto err;
		}
#ifndef _LP64
		/*
		 * Test this again now because the 32-bit victim process may
		 * have exec'd a 64-bit process in the meantime.
		 */
		if (P->status.pr_dmodel == PR_MODEL_LP64) {
			rc = G_LP64;
			goto err;
		}
#endif
	}

	/*
	 * Cancel all tracing flags unless the PGRAB_RETAIN flag is set.
	 */
	if (!(flags & PGRAB_RETAIN)) {
		(void) Psysentry(P, 0, FALSE);
		(void) Psysexit(P, 0, FALSE);
		(void) Psignal(P, 0, FALSE);
		(void) Pfault(P, 0, FALSE);
		Psync(P);
	}

	*perr = 0;
	return (P);

err:
	Pfree(P);
	*perr = rc;
	return (NULL);
}

/*
 * Return a printable string corresponding to a Pgrab() error return.
 */
const char *
Pgrab_error(int error)
{
	const char *str;

	switch (error) {
	case G_NOPROC:
		str = "no such process";
		break;
	case G_NOCORE:
		str = "no such core file";
		break;
	case G_NOPROCORCORE:
		str = "no such process or core file";
		break;
	case G_NOEXEC:
		str = "cannot find executable file";
		break;
	case G_ZOMB:
		str = "zombie process";
		break;
	case G_PERM:
		str = "permission denied";
		break;
	case G_BUSY:
		str = "process is traced";
		break;
	case G_SYS:
		str = "system process";
		break;
	case G_SELF:
		str = "attempt to grab self";
		break;
	case G_INTR:
		str = "operation interrupted";
		break;
	case G_LP64:
		str = "program is _LP64, self is not";
		break;
	case G_FORMAT:
		str = "file is not an ELF core file";
		break;
	case G_ELF:
		str = "libelf error";
		break;
	case G_NOTE:
		str = "core file is corrupt or missing required data";
		break;
	case G_STRANGE:
		str = "unanticipated system error";
		break;
	case G_ISAINVAL:
		str = "wrong ELF machine type";
		break;
	case G_BADLWPS:
		str = "bad lwp specification";
		break;
	case G_NOFD:
		str = "too many open files";
		break;
	default:
		str = "unknown error";
		break;
	}

	return (str);
}

/*
 * Free a process control structure.
 * Close the file descriptors but don't do the Prelease logic.
 */
void
Pfree(struct ps_prochandle *P)
{
	uint_t i;

	if (P->ucaddrs != NULL) {
		free(P->ucaddrs);
		P->ucaddrs = NULL;
		P->ucnelems = 0;
	}

	(void) mutex_lock(&P->proc_lock);
	if (P->hashtab != NULL) {
		struct ps_lwphandle *L;
		for (i = 0; i < HASHSIZE; i++) {
			while ((L = P->hashtab[i]) != NULL)
				Lfree_internal(P, L);
		}
		free(P->hashtab);
	}

	while (P->num_fd > 0) {
		fd_info_t *fip = list_next(&P->fd_head);
		list_unlink(fip);
		free(fip);
		P->num_fd--;
	}
	(void) mutex_unlock(&P->proc_lock);
	(void) mutex_destroy(&P->proc_lock);

	if (P->agentctlfd >= 0)
		(void) close(P->agentctlfd);
	if (P->agentstatfd >= 0)
		(void) close(P->agentstatfd);
	if (P->ctlfd >= 0)
		(void) close(P->ctlfd);
	if (P->asfd >= 0)
		(void) close(P->asfd);
	if (P->statfd >= 0)
		(void) close(P->statfd);
	Preset_maps(P);
	P->ops.pop_fini(P, P->data);

	/* clear out the structure as a precaution against reuse */
	(void) memset(P, 0, sizeof (*P));
	P->ctlfd = -1;
	P->asfd = -1;
	P->statfd = -1;
	P->agentctlfd = -1;
	P->agentstatfd = -1;

	free(P);
}

/*
 * Return the state of the process, one of the PS_* values.
 */
int
Pstate(struct ps_prochandle *P)
{
	return (P->state);
}

/*
 * Return the open address space file descriptor for the process.
 * Clients must not close this file descriptor, not use it
 * after the process is freed.
 */
int
Pasfd(struct ps_prochandle *P)
{
	return (P->asfd);
}

/*
 * Return the open control file descriptor for the process.
 * Clients must not close this file descriptor, not use it
 * after the process is freed.
 */
int
Pctlfd(struct ps_prochandle *P)
{
	return (P->ctlfd);
}

/*
 * Return a pointer to the process psinfo structure.
 * Clients should not hold on to this pointer indefinitely.
 * It will become invalid on Prelease().
 */
const psinfo_t *
Ppsinfo(struct ps_prochandle *P)
{
	return (P->ops.pop_psinfo(P, &P->psinfo, P->data));
}

/*
 * Return a pointer to the process status structure.
 * Clients should not hold on to this pointer indefinitely.
 * It will become invalid on Prelease().
 */
const pstatus_t *
Pstatus(struct ps_prochandle *P)
{
	return (&P->status);
}

static void
Pread_status(struct ps_prochandle *P)
{
	P->ops.pop_status(P, &P->status, P->data);
}

/*
 * Fill in a pointer to a process credentials structure.  The ngroups parameter
 * is the number of supplementary group entries allocated in the caller's cred
 * structure.  It should equal zero or one unless extra space has been
 * allocated for the group list by the caller.
 */
int
Pcred(struct ps_prochandle *P, prcred_t *pcrp, int ngroups)
{
	return (P->ops.pop_cred(P, pcrp, ngroups, P->data));
}

static prheader_t *
Plstatus(struct ps_prochandle *P)
{
	return (P->ops.pop_lstatus(P, P->data));
}

static prheader_t *
Plpsinfo(struct ps_prochandle *P)
{
	return (P->ops.pop_lpsinfo(P, P->data));
}


#if defined(__i386) || defined(__amd64)
/*
 * Fill in a pointer to a process LDT structure.
 * The caller provides a buffer of size 'nldt * sizeof (struct ssd)';
 * If pldt == NULL or nldt == 0, we return the number of existing LDT entries.
 * Otherwise we return the actual number of LDT entries fetched (<= nldt).
 */
int
Pldt(struct ps_prochandle *P, struct ssd *pldt, int nldt)
{
	return (P->ops.pop_ldt(P, pldt, nldt, P->data));

}
#endif	/* __i386 */

/* ARGSUSED */
void
Ppriv_free(struct ps_prochandle *P, prpriv_t *prv)
{
	free(prv);
}

/*
 * Return a malloced process privilege structure in *pprv.
 */
int
Ppriv(struct ps_prochandle *P, prpriv_t **pprv)
{
	return (P->ops.pop_priv(P, pprv, P->data));
}

int
Psetpriv(struct ps_prochandle *P, prpriv_t *pprv)
{
	int rc;
	long *ctl;
	size_t sz;

	if (P->state == PS_DEAD) {
		errno = EBADF;
		return (-1);
	}

	sz = PRIV_PRPRIV_SIZE(pprv) + sizeof (long);

	sz = ((sz - 1) / sizeof (long) + 1) * sizeof (long);

	ctl = malloc(sz);
	if (ctl == NULL)
		return (-1);

	ctl[0] = PCSPRIV;

	(void) memcpy(&ctl[1], pprv, PRIV_PRPRIV_SIZE(pprv));

	if (write(P->ctlfd, ctl, sz) != sz)
		rc = -1;
	else
		rc = 0;

	free(ctl);

	return (rc);
}

void *
Pprivinfo(struct ps_prochandle *P)
{
	core_info_t *core = P->data;

	/* Use default from libc */
	if (P->state != PS_DEAD)
		return (NULL);

	return (core->core_privinfo);
}

/*
 * Ensure that all cached state is written to the process.
 * The cached state is the LWP's signal mask and registers
 * and the process's tracing flags.
 */
void
Psync(struct ps_prochandle *P)
{
	int ctlfd = (P->agentctlfd >= 0)? P->agentctlfd : P->ctlfd;
	long cmd[6];
	iovec_t iov[12];
	int n = 0;

	if (P->flags & SETHOLD) {
		cmd[0] = PCSHOLD;
		iov[n].iov_base = (caddr_t)&cmd[0];
		iov[n++].iov_len = sizeof (long);
		iov[n].iov_base = (caddr_t)&P->status.pr_lwp.pr_lwphold;
		iov[n++].iov_len = sizeof (P->status.pr_lwp.pr_lwphold);
	}
	if (P->flags & SETREGS) {
		cmd[1] = PCSREG;
#ifdef __i386
		/* XX64 we should probably restore REG_GS after this */
		if (ctlfd == P->agentctlfd)
			P->status.pr_lwp.pr_reg[GS] = 0;
#elif defined(__amd64)
		/* XX64 */
#endif
		iov[n].iov_base = (caddr_t)&cmd[1];
		iov[n++].iov_len = sizeof (long);
		iov[n].iov_base = (caddr_t)&P->status.pr_lwp.pr_reg[0];
		iov[n++].iov_len = sizeof (P->status.pr_lwp.pr_reg);
	}
	if (P->flags & SETSIG) {
		cmd[2] = PCSTRACE;
		iov[n].iov_base = (caddr_t)&cmd[2];
		iov[n++].iov_len = sizeof (long);
		iov[n].iov_base = (caddr_t)&P->status.pr_sigtrace;
		iov[n++].iov_len = sizeof (P->status.pr_sigtrace);
	}
	if (P->flags & SETFAULT) {
		cmd[3] = PCSFAULT;
		iov[n].iov_base = (caddr_t)&cmd[3];
		iov[n++].iov_len = sizeof (long);
		iov[n].iov_base = (caddr_t)&P->status.pr_flttrace;
		iov[n++].iov_len = sizeof (P->status.pr_flttrace);
	}
	if (P->flags & SETENTRY) {
		cmd[4] = PCSENTRY;
		iov[n].iov_base = (caddr_t)&cmd[4];
		iov[n++].iov_len = sizeof (long);
		iov[n].iov_base = (caddr_t)&P->status.pr_sysentry;
		iov[n++].iov_len = sizeof (P->status.pr_sysentry);
	}
	if (P->flags & SETEXIT) {
		cmd[5] = PCSEXIT;
		iov[n].iov_base = (caddr_t)&cmd[5];
		iov[n++].iov_len = sizeof (long);
		iov[n].iov_base = (caddr_t)&P->status.pr_sysexit;
		iov[n++].iov_len = sizeof (P->status.pr_sysexit);
	}

	if (n == 0 || writev(ctlfd, iov, n) < 0)
		return;		/* nothing to do or write failed */

	P->flags &= ~(SETSIG|SETFAULT|SETENTRY|SETEXIT|SETHOLD|SETREGS);
}

/*
 * Reopen the /proc file (after PS_LOST).
 */
int
Preopen(struct ps_prochandle *P)
{
	int fd;
	char procname[PATH_MAX];
	char *fname;

	if (P->state == PS_DEAD || P->state == PS_IDLE)
		return (0);

	if (P->agentcnt > 0) {
		P->agentcnt = 1;
		Pdestroy_agent(P);
	}

	(void) snprintf(procname, sizeof (procname), "%s/%d/",
	    procfs_path, (int)P->pid);
	fname = procname + strlen(procname);

	(void) strcpy(fname, "as");
	if ((fd = open(procname, O_RDWR)) < 0 ||
	    close(P->asfd) < 0 ||
	    (fd = dupfd(fd, P->asfd)) != P->asfd) {
		dprintf("Preopen: failed to open %s: %s\n",
		    procname, strerror(errno));
		if (fd >= 0)
			(void) close(fd);
		return (-1);
	}
	P->asfd = fd;

	(void) strcpy(fname, "status");
	if ((fd = open(procname, O_RDONLY)) < 0 ||
	    close(P->statfd) < 0 ||
	    (fd = dupfd(fd, P->statfd)) != P->statfd) {
		dprintf("Preopen: failed to open %s: %s\n",
		    procname, strerror(errno));
		if (fd >= 0)
			(void) close(fd);
		return (-1);
	}
	P->statfd = fd;

	(void) strcpy(fname, "ctl");
	if ((fd = open(procname, O_WRONLY)) < 0 ||
	    close(P->ctlfd) < 0 ||
	    (fd = dupfd(fd, P->ctlfd)) != P->ctlfd) {
		dprintf("Preopen: failed to open %s: %s\n",
		    procname, strerror(errno));
		if (fd >= 0)
			(void) close(fd);
		return (-1);
	}
	P->ctlfd = fd;

	/*
	 * Set the state to PS_RUN and wait for the process to stop so that
	 * we re-read the status from the new P->statfd.  If this fails, Pwait
	 * will reset the state to PS_LOST and we fail the reopen.  Before
	 * returning, we also forge a bit of P->status to allow the debugger to
	 * see that we are PS_LOST following a successful exec.
	 */
	P->state = PS_RUN;
	if (Pwait(P, 0) == -1) {
#ifdef _ILP32
		if (errno == EOVERFLOW)
			P->status.pr_dmodel = PR_MODEL_LP64;
#endif
		P->status.pr_lwp.pr_why = PR_SYSEXIT;
		P->status.pr_lwp.pr_what = SYS_execve;
		P->status.pr_lwp.pr_errno = 0;
		return (-1);
	}

	/*
	 * The process should be stopped on exec (REQUESTED)
	 * or else should be stopped on exit from exec() (SYSEXIT)
	 */
	if (P->state == PS_STOP &&
	    (P->status.pr_lwp.pr_why == PR_REQUESTED ||
	    (P->status.pr_lwp.pr_why == PR_SYSEXIT &&
	    P->status.pr_lwp.pr_what == SYS_execve))) {
		/* fake up stop-on-exit-from-execve */
		if (P->status.pr_lwp.pr_why == PR_REQUESTED) {
			P->status.pr_lwp.pr_why = PR_SYSEXIT;
			P->status.pr_lwp.pr_what = SYS_execve;
			P->status.pr_lwp.pr_errno = 0;
		}
	} else {
		dprintf("Preopen: expected REQUESTED or "
		    "SYSEXIT(SYS_execve) stop\n");
	}

	return (0);
}

/*
 * Define all settable flags other than the microstate accounting flags.
 */
#define	ALL_SETTABLE_FLAGS (PR_FORK|PR_RLC|PR_KLC|PR_ASYNC|PR_BPTADJ|PR_PTRACE)

/*
 * Restore /proc tracing flags to their original values
 * in preparation for releasing the process.
 * Also called by Pcreate() to clear all tracing flags.
 */
static void
restore_tracing_flags(struct ps_prochandle *P)
{
	long flags;
	long cmd[4];
	iovec_t iov[8];

	if (P->flags & CREATED) {
		/* we created this process; clear all tracing flags */
		premptyset(&P->status.pr_sigtrace);
		premptyset(&P->status.pr_flttrace);
		premptyset(&P->status.pr_sysentry);
		premptyset(&P->status.pr_sysexit);
		if ((P->status.pr_flags & ALL_SETTABLE_FLAGS) != 0)
			(void) Punsetflags(P, ALL_SETTABLE_FLAGS);
	} else {
		/* we grabbed the process; restore its tracing flags */
		P->status.pr_sigtrace = P->orig_status.pr_sigtrace;
		P->status.pr_flttrace = P->orig_status.pr_flttrace;
		P->status.pr_sysentry = P->orig_status.pr_sysentry;
		P->status.pr_sysexit  = P->orig_status.pr_sysexit;
		if ((P->status.pr_flags & ALL_SETTABLE_FLAGS) !=
		    (flags = (P->orig_status.pr_flags & ALL_SETTABLE_FLAGS))) {
			(void) Punsetflags(P, ALL_SETTABLE_FLAGS);
			if (flags)
				(void) Psetflags(P, flags);
		}
	}

	cmd[0] = PCSTRACE;
	iov[0].iov_base = (caddr_t)&cmd[0];
	iov[0].iov_len = sizeof (long);
	iov[1].iov_base = (caddr_t)&P->status.pr_sigtrace;
	iov[1].iov_len = sizeof (P->status.pr_sigtrace);

	cmd[1] = PCSFAULT;
	iov[2].iov_base = (caddr_t)&cmd[1];
	iov[2].iov_len = sizeof (long);
	iov[3].iov_base = (caddr_t)&P->status.pr_flttrace;
	iov[3].iov_len = sizeof (P->status.pr_flttrace);

	cmd[2] = PCSENTRY;
	iov[4].iov_base = (caddr_t)&cmd[2];
	iov[4].iov_len = sizeof (long);
	iov[5].iov_base = (caddr_t)&P->status.pr_sysentry;
	iov[5].iov_len = sizeof (P->status.pr_sysentry);

	cmd[3] = PCSEXIT;
	iov[6].iov_base = (caddr_t)&cmd[3];
	iov[6].iov_len = sizeof (long);
	iov[7].iov_base = (caddr_t)&P->status.pr_sysexit;
	iov[7].iov_len = sizeof (P->status.pr_sysexit);

	(void) writev(P->ctlfd, iov, 8);

	P->flags &= ~(SETSIG|SETFAULT|SETENTRY|SETEXIT);
}

/*
 * Release the process.  Frees the process control structure.
 * flags:
 *	PRELEASE_CLEAR	Clear all tracing flags.
 *	PRELEASE_RETAIN	Retain current tracing flags.
 *	PRELEASE_HANG	Leave the process stopped and abandoned.
 *	PRELEASE_KILL	Terminate the process with SIGKILL.
 */
void
Prelease(struct ps_prochandle *P, int flags)
{
	if (P->state == PS_DEAD) {
		dprintf("Prelease: releasing handle %p PS_DEAD of pid %d\n",
		    (void *)P, (int)P->pid);
		Pfree(P);
		return;
	}

	if (P->state == PS_IDLE) {
		file_info_t *fptr = list_next(&P->file_head);
		dprintf("Prelease: releasing handle %p PS_IDLE of file %s\n",
		    (void *)P, fptr->file_pname);
		Pfree(P);
		return;
	}

	dprintf("Prelease: releasing handle %p pid %d\n",
	    (void *)P, (int)P->pid);

	if (P->ctlfd == -1) {
		Pfree(P);
		return;
	}

	if (P->agentcnt > 0) {
		P->agentcnt = 1;
		Pdestroy_agent(P);
	}

	/*
	 * Attempt to stop the process.
	 */
	P->state = PS_RUN;
	(void) Pstop(P, 1000);

	if (flags & PRELEASE_KILL) {
		if (P->state == PS_STOP)
			(void) Psetrun(P, SIGKILL, 0);
		(void) kill(P->pid, SIGKILL);
		Pfree(P);
		return;
	}

	/*
	 * If we lost control, all we can do now is close the files.
	 * In this case, the last close sets the process running.
	 */
	if (P->state != PS_STOP &&
	    (P->status.pr_lwp.pr_flags & (PR_ISTOP|PR_DSTOP)) == 0) {
		Pfree(P);
		return;
	}

	/*
	 * We didn't lose control; we do more.
	 */
	Psync(P);

	if (flags & PRELEASE_CLEAR)
		P->flags |= CREATED;

	if (!(flags & PRELEASE_RETAIN))
		restore_tracing_flags(P);

	if (flags & PRELEASE_HANG) {
		/* Leave the process stopped and abandoned */
		(void) Punsetflags(P, PR_RLC|PR_KLC);
		Pfree(P);
		return;
	}

	/*
	 * Set the process running if we created it or if it was
	 * not originally stopped or directed to stop via /proc
	 * or if we were given the PRELEASE_CLEAR flag.
	 */
	if ((P->flags & CREATED) ||
	    (P->orig_status.pr_lwp.pr_flags & (PR_ISTOP|PR_DSTOP)) == 0) {
		(void) Psetflags(P, PR_RLC);
		/*
		 * We do this repeatedly because the process may have
		 * more than one LWP stopped on an event of interest.
		 * This makes sure all of them are set running.
		 */
		do {
			if (Psetrun(P, 0, 0) == -1 && errno == EBUSY)
				break; /* Agent LWP may be stuck */
		} while (Pstopstatus(P, PCNULL, 0) == 0 &&
		    P->status.pr_lwp.pr_flags & (PR_ISTOP|PR_DSTOP));

		if (P->status.pr_lwp.pr_flags & (PR_ISTOP|PR_DSTOP))
			dprintf("Prelease: failed to set process running\n");
	}

	Pfree(P);
}

/* debugging */
void
prldump(const char *caller, lwpstatus_t *lsp)
{
	char name[32];
	uint32_t bits;

	switch (lsp->pr_why) {
	case PR_REQUESTED:
		dprintf("%s: REQUESTED\n", caller);
		break;
	case PR_SIGNALLED:
		dprintf("%s: SIGNALLED %s\n", caller,
		    proc_signame(lsp->pr_what, name, sizeof (name)));
		break;
	case PR_FAULTED:
		dprintf("%s: FAULTED %s\n", caller,
		    proc_fltname(lsp->pr_what, name, sizeof (name)));
		break;
	case PR_SYSENTRY:
		dprintf("%s: SYSENTRY %s\n", caller,
		    proc_sysname(lsp->pr_what, name, sizeof (name)));
		break;
	case PR_SYSEXIT:
		dprintf("%s: SYSEXIT %s\n", caller,
		    proc_sysname(lsp->pr_what, name, sizeof (name)));
		break;
	case PR_JOBCONTROL:
		dprintf("%s: JOBCONTROL %s\n", caller,
		    proc_signame(lsp->pr_what, name, sizeof (name)));
		break;
	case PR_SUSPENDED:
		dprintf("%s: SUSPENDED\n", caller);
		break;
	default:
		dprintf("%s: Unknown\n", caller);
		break;
	}

	if (lsp->pr_cursig)
		dprintf("%s: p_cursig  = %d\n", caller, lsp->pr_cursig);

	bits = *((uint32_t *)&lsp->pr_lwppend);
	if (bits)
		dprintf("%s: pr_lwppend = 0x%.8X\n", caller, bits);
}

/* debugging */
static void
prdump(struct ps_prochandle *P)
{
	uint32_t bits;

	prldump("Pstopstatus", &P->status.pr_lwp);

	bits = *((uint32_t *)&P->status.pr_sigpend);
	if (bits)
		dprintf("Pstopstatus: pr_sigpend = 0x%.8X\n", bits);
}

/*
 * Wait for the specified process to stop or terminate.
 * Or, just get the current status (PCNULL).
 * Or, direct it to stop and get the current status (PCDSTOP).
 * If the agent LWP exists, do these things to the agent,
 * else do these things to the process as a whole.
 */
int
Pstopstatus(struct ps_prochandle *P,
	long request,		/* PCNULL, PCDSTOP, PCSTOP, PCWSTOP */
	uint_t msec)		/* if non-zero, timeout in milliseconds */
{
	int ctlfd = (P->agentctlfd >= 0)? P->agentctlfd : P->ctlfd;
	long ctl[3];
	ssize_t rc;
	int err;
	int old_state = P->state;

	switch (P->state) {
	case PS_RUN:
		break;
	case PS_STOP:
		if (request != PCNULL && request != PCDSTOP)
			return (0);
		break;
	case PS_LOST:
		if (request != PCNULL) {
			errno = EAGAIN;
			return (-1);
		}
		break;
	case PS_UNDEAD:
	case PS_DEAD:
	case PS_IDLE:
		if (request != PCNULL) {
			errno = ENOENT;
			return (-1);
		}
		break;
	default:	/* corrupted state */
		dprintf("Pstopstatus: corrupted state: %d\n", P->state);
		errno = EINVAL;
		return (-1);
	}

	ctl[0] = PCDSTOP;
	ctl[1] = PCTWSTOP;
	ctl[2] = (long)msec;
	rc = 0;
	switch (request) {
	case PCSTOP:
		rc = write(ctlfd, &ctl[0], 3*sizeof (long));
		break;
	case PCWSTOP:
		rc = write(ctlfd, &ctl[1], 2*sizeof (long));
		break;
	case PCDSTOP:
		rc = write(ctlfd, &ctl[0], 1*sizeof (long));
		break;
	case PCNULL:
		if (P->state == PS_DEAD || P->state == PS_IDLE)
			return (0);
		break;
	default:	/* programming error */
		errno = EINVAL;
		return (-1);
	}
	err = (rc < 0)? errno : 0;
	Psync(P);

	if (P->agentstatfd < 0) {
		if (pread(P->statfd, &P->status,
		    sizeof (P->status), (off_t)0) < 0)
			err = errno;
	} else {
		if (pread(P->agentstatfd, &P->status.pr_lwp,
		    sizeof (P->status.pr_lwp), (off_t)0) < 0)
			err = errno;
		P->status.pr_flags = P->status.pr_lwp.pr_flags;
	}

	if (err) {
		switch (err) {
		case EINTR:		/* user typed ctl-C */
		case ERESTART:
			dprintf("Pstopstatus: EINTR\n");
			break;
		case EAGAIN:		/* we lost control of the the process */
		case EOVERFLOW:
			dprintf("Pstopstatus: PS_LOST, errno=%d\n", err);
			P->state = PS_LOST;
			break;
		default:		/* check for dead process */
			if (_libproc_debug) {
				const char *errstr;

				switch (request) {
				case PCNULL:
					errstr = "Pstopstatus PCNULL"; break;
				case PCSTOP:
					errstr = "Pstopstatus PCSTOP"; break;
				case PCDSTOP:
					errstr = "Pstopstatus PCDSTOP"; break;
				case PCWSTOP:
					errstr = "Pstopstatus PCWSTOP"; break;
				default:
					errstr = "Pstopstatus PC???"; break;
				}
				dprintf("%s: %s\n", errstr, strerror(err));
			}
			deadcheck(P);
			break;
		}
		if (err != EINTR && err != ERESTART) {
			errno = err;
			return (-1);
		}
	}

	if (!(P->status.pr_flags & PR_STOPPED)) {
		P->state = PS_RUN;
		if (request == PCNULL || request == PCDSTOP || msec != 0)
			return (0);
		dprintf("Pstopstatus: process is not stopped\n");
		errno = EPROTO;
		return (-1);
	}

	P->state = PS_STOP;

	if (_libproc_debug)	/* debugging */
		prdump(P);

	/*
	 * If the process was already stopped coming into Pstopstatus(),
	 * then don't use its PC to set P->sysaddr since it may have been
	 * changed since the time the process originally stopped.
	 */
	if (old_state == PS_STOP)
		return (0);

	switch (P->status.pr_lwp.pr_why) {
	case PR_SYSENTRY:
	case PR_SYSEXIT:
		if (Pissyscall_prev(P, P->status.pr_lwp.pr_reg[R_PC],
		    &P->sysaddr) == 0)
			P->sysaddr = P->status.pr_lwp.pr_reg[R_PC];
		break;
	case PR_REQUESTED:
	case PR_SIGNALLED:
	case PR_FAULTED:
	case PR_JOBCONTROL:
	case PR_SUSPENDED:
		break;
	default:
		errno = EPROTO;
		return (-1);
	}

	return (0);
}

/*
 * Wait for the process to stop for any reason.
 */
int
Pwait(struct ps_prochandle *P, uint_t msec)
{
	return (Pstopstatus(P, PCWSTOP, msec));
}

/*
 * Direct the process to stop; wait for it to stop.
 */
int
Pstop(struct ps_prochandle *P, uint_t msec)
{
	return (Pstopstatus(P, PCSTOP, msec));
}

/*
 * Direct the process to stop; don't wait.
 */
int
Pdstop(struct ps_prochandle *P)
{
	return (Pstopstatus(P, PCDSTOP, 0));
}

static void
deadcheck(struct ps_prochandle *P)
{
	int fd;
	void *buf;
	size_t size;

	if (P->statfd < 0)
		P->state = PS_UNDEAD;
	else {
		if (P->agentstatfd < 0) {
			fd = P->statfd;
			buf = &P->status;
			size = sizeof (P->status);
		} else {
			fd = P->agentstatfd;
			buf = &P->status.pr_lwp;
			size = sizeof (P->status.pr_lwp);
		}
		while (pread(fd, buf, size, (off_t)0) != size) {
			switch (errno) {
			default:
				P->state = PS_UNDEAD;
				break;
			case EINTR:
			case ERESTART:
				continue;
			case EAGAIN:
				P->state = PS_LOST;
				break;
			}
			break;
		}
		P->status.pr_flags = P->status.pr_lwp.pr_flags;
	}
}

/*
 * Get the value of one register from stopped process.
 */
int
Pgetareg(struct ps_prochandle *P, int regno, prgreg_t *preg)
{
	if (regno < 0 || regno >= NPRGREG) {
		errno = EINVAL;
		return (-1);
	}

	if (P->state == PS_IDLE) {
		errno = ENODATA;
		return (-1);
	}

	if (P->state != PS_STOP && P->state != PS_DEAD) {
		errno = EBUSY;
		return (-1);
	}

	*preg = P->status.pr_lwp.pr_reg[regno];
	return (0);
}

/*
 * Put value of one register into stopped process.
 */
int
Pputareg(struct ps_prochandle *P, int regno, prgreg_t reg)
{
	if (regno < 0 || regno >= NPRGREG) {
		errno = EINVAL;
		return (-1);
	}

	if (P->state != PS_STOP) {
		errno = EBUSY;
		return (-1);
	}

	P->status.pr_lwp.pr_reg[regno] = reg;
	P->flags |= SETREGS;	/* set registers before continuing */
	return (0);
}

int
Psetrun(struct ps_prochandle *P,
	int sig,	/* signal to pass to process */
	int flags)	/* PRSTEP|PRSABORT|PRSTOP|PRCSIG|PRCFAULT */
{
	int ctlfd = (P->agentctlfd >= 0) ? P->agentctlfd : P->ctlfd;
	int sbits = (PR_DSTOP | PR_ISTOP | PR_ASLEEP);

	long ctl[1 +					/* PCCFAULT	*/
	    1 + sizeof (siginfo_t)/sizeof (long) +	/* PCSSIG/PCCSIG */
	    2 ];					/* PCRUN	*/

	long *ctlp = ctl;
	size_t size;

	if (P->state != PS_STOP && (P->status.pr_lwp.pr_flags & sbits) == 0) {
		errno = EBUSY;
		return (-1);
	}

	Psync(P);	/* flush tracing flags and registers */

	if (flags & PRCFAULT) {		/* clear current fault */
		*ctlp++ = PCCFAULT;
		flags &= ~PRCFAULT;
	}

	if (flags & PRCSIG) {		/* clear current signal */
		*ctlp++ = PCCSIG;
		flags &= ~PRCSIG;
	} else if (sig && sig != P->status.pr_lwp.pr_cursig) {
		/* make current signal */
		siginfo_t *infop;

		*ctlp++ = PCSSIG;
		infop = (siginfo_t *)ctlp;
		(void) memset(infop, 0, sizeof (*infop));
		infop->si_signo = sig;
		ctlp += sizeof (siginfo_t) / sizeof (long);
	}

	*ctlp++ = PCRUN;
	*ctlp++ = flags;
	size = (char *)ctlp - (char *)ctl;

	P->info_valid = 0;	/* will need to update map and file info */

	/*
	 * If we've cached ucontext-list information while we were stopped,
	 * free it now.
	 */
	if (P->ucaddrs != NULL) {
		free(P->ucaddrs);
		P->ucaddrs = NULL;
		P->ucnelems = 0;
	}

	if (write(ctlfd, ctl, size) != size) {
		/* If it is dead or lost, return the real status, not PS_RUN */
		if (errno == ENOENT || errno == EAGAIN) {
			(void) Pstopstatus(P, PCNULL, 0);
			return (0);
		}
		/* If it is not in a jobcontrol stop, issue an error message */
		if (errno != EBUSY ||
		    P->status.pr_lwp.pr_why != PR_JOBCONTROL) {
			dprintf("Psetrun: %s\n", strerror(errno));
			return (-1);
		}
		/* Otherwise pretend that the job-stopped process is running */
	}

	P->state = PS_RUN;
	return (0);
}

ssize_t
Pread(struct ps_prochandle *P,
	void *buf,		/* caller's buffer */
	size_t nbyte,		/* number of bytes to read */
	uintptr_t address)	/* address in process */
{
	return (P->ops.pop_pread(P, buf, nbyte, address, P->data));
}

ssize_t
Pread_string(struct ps_prochandle *P,
	char *buf,		/* caller's buffer */
	size_t size,		/* upper limit on bytes to read */
	uintptr_t addr)		/* address in process */
{
	enum { STRSZ = 40 };
	char string[STRSZ + 1];
	ssize_t leng = 0;
	int nbyte;

	if (size < 2) {
		errno = EINVAL;
		return (-1);
	}

	size--;			/* ensure trailing null fits in buffer */

	*buf = '\0';
	string[STRSZ] = '\0';

	for (nbyte = STRSZ; nbyte == STRSZ && leng < size; addr += STRSZ) {
		if ((nbyte = P->ops.pop_pread(P, string, STRSZ, addr,
		    P->data)) <= 0) {
			buf[leng] = '\0';
			return (leng ? leng : -1);
		}
		if ((nbyte = strlen(string)) > 0) {
			if (leng + nbyte > size)
				nbyte = size - leng;
			(void) strncpy(buf + leng, string, nbyte);
			leng += nbyte;
		}
	}
	buf[leng] = '\0';
	return (leng);
}

ssize_t
Pwrite(struct ps_prochandle *P,
	const void *buf,	/* caller's buffer */
	size_t nbyte,		/* number of bytes to write */
	uintptr_t address)	/* address in process */
{
	return (P->ops.pop_pwrite(P, buf, nbyte, address, P->data));
}

int
Pclearsig(struct ps_prochandle *P)
{
	int ctlfd = (P->agentctlfd >= 0)? P->agentctlfd : P->ctlfd;
	long ctl = PCCSIG;

	if (write(ctlfd, &ctl, sizeof (ctl)) != sizeof (ctl))
		return (-1);
	P->status.pr_lwp.pr_cursig = 0;
	return (0);
}

int
Pclearfault(struct ps_prochandle *P)
{
	int ctlfd = (P->agentctlfd >= 0)? P->agentctlfd : P->ctlfd;
	long ctl = PCCFAULT;

	if (write(ctlfd, &ctl, sizeof (ctl)) != sizeof (ctl))
		return (-1);
	return (0);
}

/*
 * Set a breakpoint trap, return original instruction.
 */
int
Psetbkpt(struct ps_prochandle *P, uintptr_t address, ulong_t *saved)
{
	long ctl[1 + sizeof (priovec_t) / sizeof (long) +	/* PCREAD */
	    1 + sizeof (priovec_t) / sizeof (long)];	/* PCWRITE */
	long *ctlp = ctl;
	size_t size;
	priovec_t *iovp;
	instr_t bpt = BPT;
	instr_t old;

	if (P->state == PS_DEAD || P->state == PS_UNDEAD ||
	    P->state == PS_IDLE) {
		errno = ENOENT;
		return (-1);
	}

	/* fetch the old instruction */
	*ctlp++ = PCREAD;
	iovp = (priovec_t *)ctlp;
	iovp->pio_base = &old;
	iovp->pio_len = sizeof (old);
	iovp->pio_offset = address;
	ctlp += sizeof (priovec_t) / sizeof (long);

	/* write the BPT instruction */
	*ctlp++ = PCWRITE;
	iovp = (priovec_t *)ctlp;
	iovp->pio_base = &bpt;
	iovp->pio_len = sizeof (bpt);
	iovp->pio_offset = address;
	ctlp += sizeof (priovec_t) / sizeof (long);

	size = (char *)ctlp - (char *)ctl;
	if (write(P->ctlfd, ctl, size) != size)
		return (-1);

	/*
	 * Fail if there was already a breakpoint there from another debugger
	 * or DTrace's user-level tracing on x86.
	 */
	if (old == BPT) {
		errno = EBUSY;
		return (-1);
	}

	*saved = (ulong_t)old;
	return (0);
}

/*
 * Restore original instruction where a breakpoint was set.
 */
int
Pdelbkpt(struct ps_prochandle *P, uintptr_t address, ulong_t saved)
{
	instr_t old = (instr_t)saved;
	instr_t cur;

	if (P->state == PS_DEAD || P->state == PS_UNDEAD ||
	    P->state == PS_IDLE) {
		errno = ENOENT;
		return (-1);
	}

	/*
	 * If the breakpoint instruction we had placed has been overwritten
	 * with a new instruction, then don't try to replace it with the
	 * old instruction. Doing do can cause problems with self-modifying
	 * code -- PLTs for example. If the Pread() fails, we assume that we
	 * should proceed though most likely the Pwrite() will also fail.
	 */
	if (Pread(P, &cur, sizeof (cur), address) == sizeof (cur) &&
	    cur != BPT)
		return (0);

	if (Pwrite(P, &old, sizeof (old), address) != sizeof (old))
		return (-1);

	return (0);
}

/*
 * Common code for Pxecbkpt() and Lxecbkpt().
 * Develop the array of requests that will do the job, then
 * write them to the specified control file descriptor.
 * Return the non-zero errno if the write fails.
 */
static int
execute_bkpt(
	int ctlfd,		/* process or LWP control file descriptor */
	const fltset_t *faultset,	/* current set of traced faults */
	const sigset_t *sigmask,	/* current signal mask */
	uintptr_t address,		/* address of breakpint */
	ulong_t saved)			/* the saved instruction */
{
	long ctl[
	    1 + sizeof (sigset_t) / sizeof (long) +		/* PCSHOLD */
	    1 + sizeof (fltset_t) / sizeof (long) +		/* PCSFAULT */
	    1 + sizeof (priovec_t) / sizeof (long) +		/* PCWRITE */
	    2 +							/* PCRUN */
	    1 +							/* PCWSTOP */
	    1 +							/* PCCFAULT */
	    1 + sizeof (priovec_t) / sizeof (long) +		/* PCWRITE */
	    1 + sizeof (fltset_t) / sizeof (long) +		/* PCSFAULT */
	    1 + sizeof (sigset_t) / sizeof (long)];		/* PCSHOLD */
	long *ctlp = ctl;
	sigset_t unblock;
	size_t size;
	ssize_t ssize;
	priovec_t *iovp;
	sigset_t *holdp;
	fltset_t *faultp;
	instr_t old = (instr_t)saved;
	instr_t bpt = BPT;
	int error = 0;

	/* block our signals for the duration */
	(void) sigprocmask(SIG_BLOCK, &blockable_sigs, &unblock);

	/* hold posted signals */
	*ctlp++ = PCSHOLD;
	holdp = (sigset_t *)ctlp;
	prfillset(holdp);
	prdelset(holdp, SIGKILL);
	prdelset(holdp, SIGSTOP);
	ctlp += sizeof (sigset_t) / sizeof (long);

	/* force tracing of FLTTRACE */
	if (!(prismember(faultset, FLTTRACE))) {
		*ctlp++ = PCSFAULT;
		faultp = (fltset_t *)ctlp;
		*faultp = *faultset;
		praddset(faultp, FLTTRACE);
		ctlp += sizeof (fltset_t) / sizeof (long);
	}

	/* restore the old instruction */
	*ctlp++ = PCWRITE;
	iovp = (priovec_t *)ctlp;
	iovp->pio_base = &old;
	iovp->pio_len = sizeof (old);
	iovp->pio_offset = address;
	ctlp += sizeof (priovec_t) / sizeof (long);

	/* clear current signal and fault; set running w/ single-step */
	*ctlp++ = PCRUN;
	*ctlp++ = PRCSIG | PRCFAULT | PRSTEP;

	/* wait for stop, cancel the fault */
	*ctlp++ = PCWSTOP;
	*ctlp++ = PCCFAULT;

	/* restore the breakpoint trap */
	*ctlp++ = PCWRITE;
	iovp = (priovec_t *)ctlp;
	iovp->pio_base = &bpt;
	iovp->pio_len = sizeof (bpt);
	iovp->pio_offset = address;
	ctlp += sizeof (priovec_t) / sizeof (long);

	/* restore fault tracing set */
	if (!(prismember(faultset, FLTTRACE))) {
		*ctlp++ = PCSFAULT;
		*(fltset_t *)ctlp = *faultset;
		ctlp += sizeof (fltset_t) / sizeof (long);
	}

	/* restore the hold mask */
	*ctlp++ = PCSHOLD;
	*(sigset_t *)ctlp = *sigmask;
	ctlp += sizeof (sigset_t) / sizeof (long);

	size = (char *)ctlp - (char *)ctl;
	if ((ssize = write(ctlfd, ctl, size)) != size)
		error = (ssize == -1)? errno : EINTR;
	(void) sigprocmask(SIG_SETMASK, &unblock, NULL);
	return (error);
}

/*
 * Step over a breakpoint, i.e., execute the instruction that
 * really belongs at the breakpoint location (the current %pc)
 * and leave the process stopped at the next instruction.
 */
int
Pxecbkpt(struct ps_prochandle *P, ulong_t saved)
{
	int ctlfd = (P->agentctlfd >= 0)? P->agentctlfd : P->ctlfd;
	int rv, error;

	if (P->state != PS_STOP) {
		errno = EBUSY;
		return (-1);
	}

	Psync(P);

	error = execute_bkpt(ctlfd,
	    &P->status.pr_flttrace, &P->status.pr_lwp.pr_lwphold,
	    P->status.pr_lwp.pr_reg[R_PC], saved);
	rv = Pstopstatus(P, PCNULL, 0);

	if (error != 0) {
		if (P->status.pr_lwp.pr_why == PR_JOBCONTROL &&
		    error == EBUSY) {	/* jobcontrol stop -- back off */
			P->state = PS_RUN;
			return (0);
		}
		if (error == ENOENT)
			return (0);
		errno = error;
		return (-1);
	}

	return (rv);
}

/*
 * Install the watchpoint described by wp.
 */
int
Psetwapt(struct ps_prochandle *P, const prwatch_t *wp)
{
	long ctl[1 + sizeof (prwatch_t) / sizeof (long)];
	prwatch_t *cwp = (prwatch_t *)&ctl[1];

	if (P->state == PS_DEAD || P->state == PS_UNDEAD ||
	    P->state == PS_IDLE) {
		errno = ENOENT;
		return (-1);
	}

	ctl[0] = PCWATCH;
	cwp->pr_vaddr = wp->pr_vaddr;
	cwp->pr_size = wp->pr_size;
	cwp->pr_wflags = wp->pr_wflags;

	if (write(P->ctlfd, ctl, sizeof (ctl)) != sizeof (ctl))
		return (-1);

	return (0);
}

/*
 * Remove the watchpoint described by wp.
 */
int
Pdelwapt(struct ps_prochandle *P, const prwatch_t *wp)
{
	long ctl[1 + sizeof (prwatch_t) / sizeof (long)];
	prwatch_t *cwp = (prwatch_t *)&ctl[1];

	if (P->state == PS_DEAD || P->state == PS_UNDEAD ||
	    P->state == PS_IDLE) {
		errno = ENOENT;
		return (-1);
	}

	ctl[0] = PCWATCH;
	cwp->pr_vaddr = wp->pr_vaddr;
	cwp->pr_size = wp->pr_size;
	cwp->pr_wflags = 0;

	if (write(P->ctlfd, ctl, sizeof (ctl)) != sizeof (ctl))
		return (-1);

	return (0);
}

/*
 * Common code for Pxecwapt() and Lxecwapt().  Develop the array of requests
 * that will do the job, then write them to the specified control file
 * descriptor.  Return the non-zero errno if the write fails.
 */
static int
execute_wapt(
	int ctlfd,		/* process or LWP control file descriptor */
	const fltset_t *faultset,	/* current set of traced faults */
	const sigset_t *sigmask,	/* current signal mask */
	const prwatch_t *wp)		/* watchpoint descriptor */
{
	long ctl[
	    1 + sizeof (sigset_t) / sizeof (long) +		/* PCSHOLD */
	    1 + sizeof (fltset_t) / sizeof (long) +		/* PCSFAULT */
	    1 + sizeof (prwatch_t) / sizeof (long) +		/* PCWATCH */
	    2 +							/* PCRUN */
	    1 +							/* PCWSTOP */
	    1 +							/* PCCFAULT */
	    1 + sizeof (prwatch_t) / sizeof (long) +		/* PCWATCH */
	    1 + sizeof (fltset_t) / sizeof (long) +		/* PCSFAULT */
	    1 + sizeof (sigset_t) / sizeof (long)];		/* PCSHOLD */

	long *ctlp = ctl;
	int error = 0;

	sigset_t unblock;
	sigset_t *holdp;
	fltset_t *faultp;
	prwatch_t *prw;
	ssize_t ssize;
	size_t size;

	(void) sigprocmask(SIG_BLOCK, &blockable_sigs, &unblock);

	/*
	 * Hold all posted signals in the victim process prior to stepping.
	 */
	*ctlp++ = PCSHOLD;
	holdp = (sigset_t *)ctlp;
	prfillset(holdp);
	prdelset(holdp, SIGKILL);
	prdelset(holdp, SIGSTOP);
	ctlp += sizeof (sigset_t) / sizeof (long);

	/*
	 * Force tracing of FLTTRACE since we need to single step.
	 */
	if (!(prismember(faultset, FLTTRACE))) {
		*ctlp++ = PCSFAULT;
		faultp = (fltset_t *)ctlp;
		*faultp = *faultset;
		praddset(faultp, FLTTRACE);
		ctlp += sizeof (fltset_t) / sizeof (long);
	}

	/*
	 * Clear only the current watchpoint by setting pr_wflags to zero.
	 */
	*ctlp++ = PCWATCH;
	prw = (prwatch_t *)ctlp;
	prw->pr_vaddr = wp->pr_vaddr;
	prw->pr_size = wp->pr_size;
	prw->pr_wflags = 0;
	ctlp += sizeof (prwatch_t) / sizeof (long);

	/*
	 * Clear the current signal and fault; set running with single-step.
	 * Then wait for the victim to stop and cancel the FLTTRACE.
	 */
	*ctlp++ = PCRUN;
	*ctlp++ = PRCSIG | PRCFAULT | PRSTEP;
	*ctlp++ = PCWSTOP;
	*ctlp++ = PCCFAULT;

	/*
	 * Restore the current watchpoint.
	 */
	*ctlp++ = PCWATCH;
	(void) memcpy(ctlp, wp, sizeof (prwatch_t));
	ctlp += sizeof (prwatch_t) / sizeof (long);

	/*
	 * Restore fault tracing set if we modified it.
	 */
	if (!(prismember(faultset, FLTTRACE))) {
		*ctlp++ = PCSFAULT;
		*(fltset_t *)ctlp = *faultset;
		ctlp += sizeof (fltset_t) / sizeof (long);
	}

	/*
	 * Restore the hold mask to the current hold mask (i.e. the one
	 * before we executed any of the previous operations).
	 */
	*ctlp++ = PCSHOLD;
	*(sigset_t *)ctlp = *sigmask;
	ctlp += sizeof (sigset_t) / sizeof (long);

	size = (char *)ctlp - (char *)ctl;
	if ((ssize = write(ctlfd, ctl, size)) != size)
		error = (ssize == -1)? errno : EINTR;
	(void) sigprocmask(SIG_SETMASK, &unblock, NULL);
	return (error);
}

/*
 * Step over a watchpoint, i.e., execute the instruction that was stopped by
 * the watchpoint, and then leave the LWP stopped at the next instruction.
 */
int
Pxecwapt(struct ps_prochandle *P, const prwatch_t *wp)
{
	int ctlfd = (P->agentctlfd >= 0)? P->agentctlfd : P->ctlfd;
	int rv, error;

	if (P->state != PS_STOP) {
		errno = EBUSY;
		return (-1);
	}

	Psync(P);
	error = execute_wapt(ctlfd,
	    &P->status.pr_flttrace, &P->status.pr_lwp.pr_lwphold, wp);
	rv = Pstopstatus(P, PCNULL, 0);

	if (error != 0) {
		if (P->status.pr_lwp.pr_why == PR_JOBCONTROL &&
		    error == EBUSY) {	/* jobcontrol stop -- back off */
			P->state = PS_RUN;
			return (0);
		}
		if (error == ENOENT)
			return (0);
		errno = error;
		return (-1);
	}

	return (rv);
}

int
Psetflags(struct ps_prochandle *P, long flags)
{
	int rc;
	long ctl[2];

	ctl[0] = PCSET;
	ctl[1] = flags;

	if (write(P->ctlfd, ctl, 2*sizeof (long)) != 2*sizeof (long)) {
		rc = -1;
	} else {
		P->status.pr_flags |= flags;
		P->status.pr_lwp.pr_flags |= flags;
		rc = 0;
	}

	return (rc);
}

int
Punsetflags(struct ps_prochandle *P, long flags)
{
	int rc;
	long ctl[2];

	ctl[0] = PCUNSET;
	ctl[1] = flags;

	if (write(P->ctlfd, ctl, 2*sizeof (long)) != 2*sizeof (long)) {
		rc = -1;
	} else {
		P->status.pr_flags &= ~flags;
		P->status.pr_lwp.pr_flags &= ~flags;
		rc = 0;
	}

	return (rc);
}

/*
 * Common function to allow clients to manipulate the action to be taken
 * on receipt of a signal, receipt of machine fault, entry to a system call,
 * or exit from a system call.  We make use of our private prset_* functions
 * in order to make this code be common.  The 'which' parameter identifies
 * the code for the event of interest (0 means change the entire set), and
 * the 'stop' parameter is a boolean indicating whether the process should
 * stop when the event of interest occurs.  The previous value is returned
 * to the caller; -1 is returned if an error occurred.
 */
static int
Psetaction(struct ps_prochandle *P, void *sp, size_t size,
    uint_t flag, int max, int which, int stop)
{
	int oldval;

	if (which < 0 || which > max) {
		errno = EINVAL;
		return (-1);
	}

	if (P->state == PS_DEAD || P->state == PS_UNDEAD ||
	    P->state == PS_IDLE) {
		errno = ENOENT;
		return (-1);
	}

	oldval = prset_ismember(sp, size, which) ? TRUE : FALSE;

	if (stop) {
		if (which == 0) {
			prset_fill(sp, size);
			P->flags |= flag;
		} else if (!oldval) {
			prset_add(sp, size, which);
			P->flags |= flag;
		}
	} else {
		if (which == 0) {
			prset_empty(sp, size);
			P->flags |= flag;
		} else if (oldval) {
			prset_del(sp, size, which);
			P->flags |= flag;
		}
	}

	if (P->state == PS_RUN)
		Psync(P);

	return (oldval);
}

/*
 * Set action on specified signal.
 */
int
Psignal(struct ps_prochandle *P, int which, int stop)
{
	int oldval;

	if (which == SIGKILL && stop != 0) {
		errno = EINVAL;
		return (-1);
	}

	oldval = Psetaction(P, &P->status.pr_sigtrace, sizeof (sigset_t),
	    SETSIG, PRMAXSIG, which, stop);

	if (oldval != -1 && which == 0 && stop != 0)
		prdelset(&P->status.pr_sigtrace, SIGKILL);

	return (oldval);
}

/*
 * Set all signal tracing flags.
 */
void
Psetsignal(struct ps_prochandle *P, const sigset_t *set)
{
	if (P->state == PS_DEAD || P->state == PS_UNDEAD ||
	    P->state == PS_IDLE)
		return;

	P->status.pr_sigtrace = *set;
	P->flags |= SETSIG;

	if (P->state == PS_RUN)
		Psync(P);
}

/*
 * Set action on specified fault.
 */
int
Pfault(struct ps_prochandle *P, int which, int stop)
{
	return (Psetaction(P, &P->status.pr_flttrace, sizeof (fltset_t),
	    SETFAULT, PRMAXFAULT, which, stop));
}

/*
 * Set all machine fault tracing flags.
 */
void
Psetfault(struct ps_prochandle *P, const fltset_t *set)
{
	if (P->state == PS_DEAD || P->state == PS_UNDEAD ||
	    P->state == PS_IDLE)
		return;

	P->status.pr_flttrace = *set;
	P->flags |= SETFAULT;

	if (P->state == PS_RUN)
		Psync(P);
}

/*
 * Set action on specified system call entry.
 */
int
Psysentry(struct ps_prochandle *P, int which, int stop)
{
	return (Psetaction(P, &P->status.pr_sysentry, sizeof (sysset_t),
	    SETENTRY, PRMAXSYS, which, stop));
}

/*
 * Set all system call entry tracing flags.
 */
void
Psetsysentry(struct ps_prochandle *P, const sysset_t *set)
{
	if (P->state == PS_DEAD || P->state == PS_UNDEAD ||
	    P->state == PS_IDLE)
		return;

	P->status.pr_sysentry = *set;
	P->flags |= SETENTRY;

	if (P->state == PS_RUN)
		Psync(P);
}

/*
 * Set action on specified system call exit.
 */
int
Psysexit(struct ps_prochandle *P, int which, int stop)
{
	return (Psetaction(P, &P->status.pr_sysexit, sizeof (sysset_t),
	    SETEXIT, PRMAXSYS, which, stop));
}

/*
 * Set all system call exit tracing flags.
 */
void
Psetsysexit(struct ps_prochandle *P, const sysset_t *set)
{
	if (P->state == PS_DEAD || P->state == PS_UNDEAD ||
	    P->state == PS_IDLE)
		return;

	P->status.pr_sysexit = *set;
	P->flags |= SETEXIT;

	if (P->state == PS_RUN)
		Psync(P);
}

/*
 * Utility function to read the contents of a file that contains a
 * prheader_t at the start (/proc/pid/lstatus or /proc/pid/lpsinfo).
 * Returns a malloc()d buffer or NULL on failure.
 */
static prheader_t *
read_lfile(struct ps_prochandle *P, const char *lname)
{
	prheader_t *Lhp;
	char lpath[PATH_MAX];
	struct stat64 statb;
	int fd;
	size_t size;
	ssize_t rval;

	(void) snprintf(lpath, sizeof (lpath), "%s/%d/%s", procfs_path,
	    (int)P->status.pr_pid, lname);
	if ((fd = open(lpath, O_RDONLY)) < 0 || fstat64(fd, &statb) != 0) {
		if (fd >= 0)
			(void) close(fd);
		return (NULL);
	}

	/*
	 * 'size' is just the initial guess at the buffer size.
	 * It will have to grow if the number of lwps increases
	 * while we are looking at the process.
	 * 'size' must be larger than the actual file size.
	 */
	size = statb.st_size + 32;

	for (;;) {
		if ((Lhp = malloc(size)) == NULL)
			break;
		if ((rval = pread(fd, Lhp, size, 0)) < 0 ||
		    rval <= sizeof (prheader_t)) {
			free(Lhp);
			Lhp = NULL;
			break;
		}
		if (rval < size)
			break;
		/* need a bigger buffer */
		free(Lhp);
		size *= 2;
	}

	(void) close(fd);
	return (Lhp);
}

/*
 * LWP iteration interface.
 */
int
Plwp_iter(struct ps_prochandle *P, proc_lwp_f *func, void *cd)
{
	prheader_t *Lhp;
	lwpstatus_t *Lsp;
	long nlwp;
	int rv;

	switch (P->state) {
	case PS_RUN:
		(void) Pstopstatus(P, PCNULL, 0);
		break;

	case PS_STOP:
		Psync(P);
		break;

	case PS_IDLE:
		errno = ENODATA;
		return (-1);
	}

	/*
	 * For either live processes or cores, the single LWP case is easy:
	 * the pstatus_t contains the lwpstatus_t for the only LWP.
	 */
	if (P->status.pr_nlwp <= 1)
		return (func(cd, &P->status.pr_lwp));

	/*
	 * For the core file multi-LWP case, we just iterate through the
	 * list of LWP structs we read in from the core file.
	 */
	if (P->state == PS_DEAD) {
		core_info_t *core = P->data;
		lwp_info_t *lwp = list_prev(&core->core_lwp_head);
		uint_t i;

		for (i = 0; i < core->core_nlwp; i++, lwp = list_prev(lwp)) {
			if (lwp->lwp_psinfo.pr_sname != 'Z' &&
			    (rv = func(cd, &lwp->lwp_status)) != 0)
				break;
		}

		return (rv);
	}

	/*
	 * For the live process multi-LWP case, we have to work a little
	 * harder: the /proc/pid/lstatus file has the array of LWP structs.
	 */
	if ((Lhp = Plstatus(P)) == NULL)
		return (-1);

	for (nlwp = Lhp->pr_nent, Lsp = (lwpstatus_t *)(uintptr_t)(Lhp + 1);
	    nlwp > 0;
	    nlwp--, Lsp = (lwpstatus_t *)((uintptr_t)Lsp + Lhp->pr_entsize)) {
		if ((rv = func(cd, Lsp)) != 0)
			break;
	}

	free(Lhp);
	return (rv);
}

/*
 * Extended LWP iteration interface.
 * Iterate over all LWPs, active and zombie.
 */
int
Plwp_iter_all(struct ps_prochandle *P, proc_lwp_all_f *func, void *cd)
{
	prheader_t *Lhp = NULL;
	lwpstatus_t *Lsp;
	lwpstatus_t *sp;
	prheader_t *Lphp = NULL;
	lwpsinfo_t *Lpsp;
	long nstat;
	long ninfo;
	int rv;

retry:
	if (Lhp != NULL)
		free(Lhp);
	if (Lphp != NULL)
		free(Lphp);
	if (P->state == PS_RUN)
		(void) Pstopstatus(P, PCNULL, 0);
	(void) Ppsinfo(P);

	if (P->state == PS_STOP)
		Psync(P);

	/*
	 * For either live processes or cores, the single LWP case is easy:
	 * the pstatus_t contains the lwpstatus_t for the only LWP and
	 * the psinfo_t contains the lwpsinfo_t for the only LWP.
	 */
	if (P->status.pr_nlwp + P->status.pr_nzomb <= 1)
		return (func(cd, &P->status.pr_lwp, &P->psinfo.pr_lwp));

	/*
	 * For the core file multi-LWP case, we just iterate through the
	 * list of LWP structs we read in from the core file.
	 */
	if (P->state == PS_DEAD) {
		core_info_t *core = P->data;
		lwp_info_t *lwp = list_prev(&core->core_lwp_head);
		uint_t i;

		for (i = 0; i < core->core_nlwp; i++, lwp = list_prev(lwp)) {
			sp = (lwp->lwp_psinfo.pr_sname == 'Z')? NULL :
			    &lwp->lwp_status;
			if ((rv = func(cd, sp, &lwp->lwp_psinfo)) != 0)
				break;
		}

		return (rv);
	}

	/*
	 * For all other cases retrieve the array of lwpstatus_t's and
	 * lwpsinfo_t's.
	 */
	if ((Lhp = Plstatus(P)) == NULL)
		return (-1);
	if ((Lphp = Plpsinfo(P)) == NULL) {
		free(Lhp);
		return (-1);
	}

	/*
	 * If we are looking at a running process, or one we do not control,
	 * the active and zombie lwps in the process may have changed since
	 * we read the process status structure.  If so, just start over.
	 */
	if (Lhp->pr_nent != P->status.pr_nlwp ||
	    Lphp->pr_nent != P->status.pr_nlwp + P->status.pr_nzomb)
		goto retry;

	/*
	 * To be perfectly safe, prescan the two arrays, checking consistency.
	 * We rely on /proc giving us lwpstatus_t's and lwpsinfo_t's in the
	 * same order (the lwp directory order) in their respective files.
	 * We also rely on there being (possibly) more lwpsinfo_t's than
	 * lwpstatus_t's (the extra lwpsinfo_t's are for zombie lwps).
	 */
	Lsp = (lwpstatus_t *)(uintptr_t)(Lhp + 1);
	Lpsp = (lwpsinfo_t *)(uintptr_t)(Lphp + 1);
	nstat = Lhp->pr_nent;
	for (ninfo = Lphp->pr_nent; ninfo != 0; ninfo--) {
		if (Lpsp->pr_sname != 'Z') {
			/*
			 * Not a zombie lwp; check for matching lwpids.
			 */
			if (nstat == 0 || Lsp->pr_lwpid != Lpsp->pr_lwpid)
				goto retry;
			Lsp = (lwpstatus_t *)((uintptr_t)Lsp + Lhp->pr_entsize);
			nstat--;
		}
		Lpsp = (lwpsinfo_t *)((uintptr_t)Lpsp + Lphp->pr_entsize);
	}
	if (nstat != 0)
		goto retry;

	/*
	 * Rescan, this time for real.
	 */
	Lsp = (lwpstatus_t *)(uintptr_t)(Lhp + 1);
	Lpsp = (lwpsinfo_t *)(uintptr_t)(Lphp + 1);
	for (ninfo = Lphp->pr_nent; ninfo != 0; ninfo--) {
		if (Lpsp->pr_sname != 'Z') {
			sp = Lsp;
			Lsp = (lwpstatus_t *)((uintptr_t)Lsp + Lhp->pr_entsize);
		} else {
			sp = NULL;
		}
		if ((rv = func(cd, sp, Lpsp)) != 0)
			break;
		Lpsp = (lwpsinfo_t *)((uintptr_t)Lpsp + Lphp->pr_entsize);
	}

	free(Lhp);
	free(Lphp);
	return (rv);
}

core_content_t
Pcontent(struct ps_prochandle *P)
{
	core_info_t *core = P->data;

	if (P->state == PS_DEAD)
		return (core->core_content);
	if (P->state == PS_IDLE)
		return (CC_CONTENT_TEXT | CC_CONTENT_DATA | CC_CONTENT_CTF);

	return (CC_CONTENT_ALL);
}

/*
 * =================================================================
 * The remainder of the functions in this file are for the
 * control of individual LWPs in the controlled process.
 * =================================================================
 */

/*
 * Find an entry in the process hash table for the specified lwpid.
 * The entry will either point to an existing struct ps_lwphandle
 * or it will point to an empty slot for a new struct ps_lwphandle.
 */
static struct ps_lwphandle **
Lfind(struct ps_prochandle *P, lwpid_t lwpid)
{
	struct ps_lwphandle **Lp;
	struct ps_lwphandle *L;

	for (Lp = &P->hashtab[lwpid % (HASHSIZE - 1)];
	    (L = *Lp) != NULL; Lp = &L->lwp_hash)
		if (L->lwp_id == lwpid)
			break;
	return (Lp);
}

/*
 * Grab an LWP contained within the controlled process.
 * Return an opaque pointer to its LWP control structure.
 *	perr: pointer to error return code.
 */
struct ps_lwphandle *
Lgrab(struct ps_prochandle *P, lwpid_t lwpid, int *perr)
{
	struct ps_lwphandle **Lp;
	struct ps_lwphandle *L;
	int fd;
	char procname[PATH_MAX];
	char *fname;
	int rc = 0;

	(void) mutex_lock(&P->proc_lock);

	if (P->state == PS_UNDEAD || P->state == PS_IDLE)
		rc = G_NOPROC;
	else if (P->hashtab == NULL &&
	    (P->hashtab = calloc(HASHSIZE, sizeof (struct ps_lwphandle *)))
	    == NULL)
		rc = G_STRANGE;
	else if (*(Lp = Lfind(P, lwpid)) != NULL)
		rc = G_BUSY;
	else if ((L = malloc(sizeof (struct ps_lwphandle))) == NULL)
		rc = G_STRANGE;
	if (rc) {
		*perr = rc;
		(void) mutex_unlock(&P->proc_lock);
		return (NULL);
	}

	(void) memset(L, 0, sizeof (*L));
	L->lwp_ctlfd = -1;
	L->lwp_statfd = -1;
	L->lwp_proc = P;
	L->lwp_id = lwpid;
	*Lp = L;	/* insert into the hash table */

	if (P->state == PS_DEAD) {	/* core file */
		if (getlwpstatus(P, lwpid, &L->lwp_status) == -1) {
			rc = G_NOPROC;
			goto err;
		}
		L->lwp_state = PS_DEAD;
		*perr = 0;
		(void) mutex_unlock(&P->proc_lock);
		return (L);
	}

	/*
	 * Open the /proc/<pid>/lwp/<lwpid> files
	 */
	(void) snprintf(procname, sizeof (procname), "%s/%d/lwp/%d/",
	    procfs_path, (int)P->pid, (int)lwpid);
	fname = procname + strlen(procname);
	(void) set_minfd();

	(void) strcpy(fname, "lwpstatus");
	if ((fd = open(procname, O_RDONLY)) < 0 ||
	    (fd = dupfd(fd, 0)) < 0) {
		switch (errno) {
		case ENOENT:
			rc = G_NOPROC;
			break;
		default:
			dprintf("Lgrab: failed to open %s: %s\n",
			    procname, strerror(errno));
			rc = G_STRANGE;
			break;
		}
		goto err;
	}
	L->lwp_statfd = fd;

	if (pread(fd, &L->lwp_status, sizeof (L->lwp_status), (off_t)0) < 0) {
		switch (errno) {
		case ENOENT:
			rc = G_NOPROC;
			break;
		default:
			dprintf("Lgrab: failed to read %s: %s\n",
			    procname, strerror(errno));
			rc = G_STRANGE;
			break;
		}
		goto err;
	}

	(void) strcpy(fname, "lwpctl");
	if ((fd = open(procname, O_WRONLY)) < 0 ||
	    (fd = dupfd(fd, 0)) < 0) {
		switch (errno) {
		case ENOENT:
			rc = G_NOPROC;
			break;
		default:
			dprintf("Lgrab: failed to open %s: %s\n",
			    procname, strerror(errno));
			rc = G_STRANGE;
			break;
		}
		goto err;
	}
	L->lwp_ctlfd = fd;

	L->lwp_state =
	    ((L->lwp_status.pr_flags & (PR_STOPPED|PR_ISTOP))
	    == (PR_STOPPED|PR_ISTOP))?
	    PS_STOP : PS_RUN;

	*perr = 0;
	(void) mutex_unlock(&P->proc_lock);
	return (L);

err:
	Lfree_internal(P, L);
	*perr = rc;
	(void) mutex_unlock(&P->proc_lock);
	return (NULL);
}

/*
 * Return a printable string corresponding to an Lgrab() error return.
 */
const char *
Lgrab_error(int error)
{
	const char *str;

	switch (error) {
	case G_NOPROC:
		str = "no such LWP";
		break;
	case G_BUSY:
		str = "LWP already grabbed";
		break;
	case G_STRANGE:
		str = "unanticipated system error";
		break;
	default:
		str = "unknown error";
		break;
	}

	return (str);
}

/*
 * Free an LWP control structure.
 */
void
Lfree(struct ps_lwphandle *L)
{
	struct ps_prochandle *P = L->lwp_proc;

	(void) mutex_lock(&P->proc_lock);
	Lfree_internal(P, L);
	(void) mutex_unlock(&P->proc_lock);
}

static void
Lfree_internal(struct ps_prochandle *P, struct ps_lwphandle *L)
{
	*Lfind(P, L->lwp_id) = L->lwp_hash;	/* delete from hash table */
	if (L->lwp_ctlfd >= 0)
		(void) close(L->lwp_ctlfd);
	if (L->lwp_statfd >= 0)
		(void) close(L->lwp_statfd);

	/* clear out the structure as a precaution against reuse */
	(void) memset(L, 0, sizeof (*L));
	L->lwp_ctlfd = -1;
	L->lwp_statfd = -1;

	free(L);
}

/*
 * Return the state of the process, one of the PS_* values.
 */
int
Lstate(struct ps_lwphandle *L)
{
	return (L->lwp_state);
}

/*
 * Return the open control file descriptor for the LWP.
 * Clients must not close this file descriptor, nor use it
 * after the LWP is freed.
 */
int
Lctlfd(struct ps_lwphandle *L)
{
	return (L->lwp_ctlfd);
}

/*
 * Return a pointer to the LWP lwpsinfo structure.
 * Clients should not hold on to this pointer indefinitely.
 * It will become invalid on Lfree().
 */
const lwpsinfo_t *
Lpsinfo(struct ps_lwphandle *L)
{
	if (Plwp_getpsinfo(L->lwp_proc, L->lwp_id, &L->lwp_psinfo) == -1)
		return (NULL);

	return (&L->lwp_psinfo);
}

/*
 * Return a pointer to the LWP status structure.
 * Clients should not hold on to this pointer indefinitely.
 * It will become invalid on Lfree().
 */
const lwpstatus_t *
Lstatus(struct ps_lwphandle *L)
{
	return (&L->lwp_status);
}

/*
 * Given an LWP handle, return the process handle.
 */
struct ps_prochandle *
Lprochandle(struct ps_lwphandle *L)
{
	return (L->lwp_proc);
}

/*
 * Ensure that all cached state is written to the LWP.
 * The cached state is the LWP's signal mask and registers.
 */
void
Lsync(struct ps_lwphandle *L)
{
	int ctlfd = L->lwp_ctlfd;
	long cmd[2];
	iovec_t iov[4];
	int n = 0;

	if (L->lwp_flags & SETHOLD) {
		cmd[0] = PCSHOLD;
		iov[n].iov_base = (caddr_t)&cmd[0];
		iov[n++].iov_len = sizeof (long);
		iov[n].iov_base = (caddr_t)&L->lwp_status.pr_lwphold;
		iov[n++].iov_len = sizeof (L->lwp_status.pr_lwphold);
	}
	if (L->lwp_flags & SETREGS) {
		cmd[1] = PCSREG;
		iov[n].iov_base = (caddr_t)&cmd[1];
		iov[n++].iov_len = sizeof (long);
		iov[n].iov_base = (caddr_t)&L->lwp_status.pr_reg[0];
		iov[n++].iov_len = sizeof (L->lwp_status.pr_reg);
	}

	if (n == 0 || writev(ctlfd, iov, n) < 0)
		return;		/* nothing to do or write failed */

	L->lwp_flags &= ~(SETHOLD|SETREGS);
}

/*
 * Wait for the specified LWP to stop or terminate.
 * Or, just get the current status (PCNULL).
 * Or, direct it to stop and get the current status (PCDSTOP).
 */
static int
Lstopstatus(struct ps_lwphandle *L,
	long request,		/* PCNULL, PCDSTOP, PCSTOP, PCWSTOP */
	uint_t msec)		/* if non-zero, timeout in milliseconds */
{
	int ctlfd = L->lwp_ctlfd;
	long ctl[3];
	ssize_t rc;
	int err;

	switch (L->lwp_state) {
	case PS_RUN:
		break;
	case PS_STOP:
		if (request != PCNULL && request != PCDSTOP)
			return (0);
		break;
	case PS_LOST:
		if (request != PCNULL) {
			errno = EAGAIN;
			return (-1);
		}
		break;
	case PS_UNDEAD:
	case PS_DEAD:
		if (request != PCNULL) {
			errno = ENOENT;
			return (-1);
		}
		break;
	default:	/* corrupted state */
		dprintf("Lstopstatus: corrupted state: %d\n", L->lwp_state);
		errno = EINVAL;
		return (-1);
	}

	ctl[0] = PCDSTOP;
	ctl[1] = PCTWSTOP;
	ctl[2] = (long)msec;
	rc = 0;
	switch (request) {
	case PCSTOP:
		rc = write(ctlfd, &ctl[0], 3*sizeof (long));
		break;
	case PCWSTOP:
		rc = write(ctlfd, &ctl[1], 2*sizeof (long));
		break;
	case PCDSTOP:
		rc = write(ctlfd, &ctl[0], 1*sizeof (long));
		break;
	case PCNULL:
		if (L->lwp_state == PS_DEAD)
			return (0); /* Nothing else to do for cores */
		break;
	default:	/* programming error */
		errno = EINVAL;
		return (-1);
	}
	err = (rc < 0)? errno : 0;
	Lsync(L);

	if (pread(L->lwp_statfd, &L->lwp_status,
	    sizeof (L->lwp_status), (off_t)0) < 0)
		err = errno;

	if (err) {
		switch (err) {
		case EINTR:		/* user typed ctl-C */
		case ERESTART:
			dprintf("Lstopstatus: EINTR\n");
			break;
		case EAGAIN:		/* we lost control of the the process */
			dprintf("Lstopstatus: EAGAIN\n");
			L->lwp_state = PS_LOST;
			errno = err;
			return (-1);
		default:
			if (_libproc_debug) {
				const char *errstr;

				switch (request) {
				case PCNULL:
					errstr = "Lstopstatus PCNULL"; break;
				case PCSTOP:
					errstr = "Lstopstatus PCSTOP"; break;
				case PCDSTOP:
					errstr = "Lstopstatus PCDSTOP"; break;
				case PCWSTOP:
					errstr = "Lstopstatus PCWSTOP"; break;
				default:
					errstr = "Lstopstatus PC???"; break;
				}
				dprintf("%s: %s\n", errstr, strerror(err));
			}
			L->lwp_state = PS_UNDEAD;
			errno = err;
			return (-1);
		}
	}

	if ((L->lwp_status.pr_flags & (PR_STOPPED|PR_ISTOP))
	    != (PR_STOPPED|PR_ISTOP)) {
		L->lwp_state = PS_RUN;
		if (request == PCNULL || request == PCDSTOP || msec != 0)
			return (0);
		dprintf("Lstopstatus: LWP is not stopped\n");
		errno = EPROTO;
		return (-1);
	}

	L->lwp_state = PS_STOP;

	if (_libproc_debug)	/* debugging */
		prldump("Lstopstatus", &L->lwp_status);

	switch (L->lwp_status.pr_why) {
	case PR_SYSENTRY:
	case PR_SYSEXIT:
	case PR_REQUESTED:
	case PR_SIGNALLED:
	case PR_FAULTED:
	case PR_JOBCONTROL:
	case PR_SUSPENDED:
		break;
	default:
		errno = EPROTO;
		return (-1);
	}

	return (0);
}

/*
 * Wait for the LWP to stop for any reason.
 */
int
Lwait(struct ps_lwphandle *L, uint_t msec)
{
	return (Lstopstatus(L, PCWSTOP, msec));
}

/*
 * Direct the LWP to stop; wait for it to stop.
 */
int
Lstop(struct ps_lwphandle *L, uint_t msec)
{
	return (Lstopstatus(L, PCSTOP, msec));
}

/*
 * Direct the LWP to stop; don't wait.
 */
int
Ldstop(struct ps_lwphandle *L)
{
	return (Lstopstatus(L, PCDSTOP, 0));
}

/*
 * Get the value of one register from stopped LWP.
 */
int
Lgetareg(struct ps_lwphandle *L, int regno, prgreg_t *preg)
{
	if (regno < 0 || regno >= NPRGREG) {
		errno = EINVAL;
		return (-1);
	}

	if (L->lwp_state != PS_STOP) {
		errno = EBUSY;
		return (-1);
	}

	*preg = L->lwp_status.pr_reg[regno];
	return (0);
}

/*
 * Put value of one register into stopped LWP.
 */
int
Lputareg(struct ps_lwphandle *L, int regno, prgreg_t reg)
{
	if (regno < 0 || regno >= NPRGREG) {
		errno = EINVAL;
		return (-1);
	}

	if (L->lwp_state != PS_STOP) {
		errno = EBUSY;
		return (-1);
	}

	L->lwp_status.pr_reg[regno] = reg;
	L->lwp_flags |= SETREGS;	/* set registers before continuing */
	return (0);
}

int
Lsetrun(struct ps_lwphandle *L,
	int sig,	/* signal to pass to LWP */
	int flags)	/* PRSTEP|PRSABORT|PRSTOP|PRCSIG|PRCFAULT */
{
	int ctlfd = L->lwp_ctlfd;
	int sbits = (PR_DSTOP | PR_ISTOP | PR_ASLEEP);

	long ctl[1 +					/* PCCFAULT	*/
	    1 + sizeof (siginfo_t)/sizeof (long) +	/* PCSSIG/PCCSIG */
	    2 ];					/* PCRUN	*/

	long *ctlp = ctl;
	size_t size;

	if (L->lwp_state != PS_STOP &&
	    (L->lwp_status.pr_flags & sbits) == 0) {
		errno = EBUSY;
		return (-1);
	}

	Lsync(L);	/* flush registers */

	if (flags & PRCFAULT) {		/* clear current fault */
		*ctlp++ = PCCFAULT;
		flags &= ~PRCFAULT;
	}

	if (flags & PRCSIG) {		/* clear current signal */
		*ctlp++ = PCCSIG;
		flags &= ~PRCSIG;
	} else if (sig && sig != L->lwp_status.pr_cursig) {
		/* make current signal */
		siginfo_t *infop;

		*ctlp++ = PCSSIG;
		infop = (siginfo_t *)ctlp;
		(void) memset(infop, 0, sizeof (*infop));
		infop->si_signo = sig;
		ctlp += sizeof (siginfo_t) / sizeof (long);
	}

	*ctlp++ = PCRUN;
	*ctlp++ = flags;
	size = (char *)ctlp - (char *)ctl;

	L->lwp_proc->info_valid = 0; /* will need to update map and file info */
	L->lwp_proc->state = PS_RUN;
	L->lwp_state = PS_RUN;

	if (write(ctlfd, ctl, size) != size) {
		/* Pretend that a job-stopped LWP is running */
		if (errno != EBUSY || L->lwp_status.pr_why != PR_JOBCONTROL)
			return (Lstopstatus(L, PCNULL, 0));
	}

	return (0);
}

int
Lclearsig(struct ps_lwphandle *L)
{
	int ctlfd = L->lwp_ctlfd;
	long ctl = PCCSIG;

	if (write(ctlfd, &ctl, sizeof (ctl)) != sizeof (ctl))
		return (-1);
	L->lwp_status.pr_cursig = 0;
	return (0);
}

int
Lclearfault(struct ps_lwphandle *L)
{
	int ctlfd = L->lwp_ctlfd;
	long ctl = PCCFAULT;

	if (write(ctlfd, &ctl, sizeof (ctl)) != sizeof (ctl))
		return (-1);
	return (0);
}

/*
 * Step over a breakpoint, i.e., execute the instruction that
 * really belongs at the breakpoint location (the current %pc)
 * and leave the LWP stopped at the next instruction.
 */
int
Lxecbkpt(struct ps_lwphandle *L, ulong_t saved)
{
	struct ps_prochandle *P = L->lwp_proc;
	int rv, error;

	if (L->lwp_state != PS_STOP) {
		errno = EBUSY;
		return (-1);
	}

	Lsync(L);
	error = execute_bkpt(L->lwp_ctlfd,
	    &P->status.pr_flttrace, &L->lwp_status.pr_lwphold,
	    L->lwp_status.pr_reg[R_PC], saved);
	rv = Lstopstatus(L, PCNULL, 0);

	if (error != 0) {
		if (L->lwp_status.pr_why == PR_JOBCONTROL &&
		    error == EBUSY) {	/* jobcontrol stop -- back off */
			L->lwp_state = PS_RUN;
			return (0);
		}
		if (error == ENOENT)
			return (0);
		errno = error;
		return (-1);
	}

	return (rv);
}

/*
 * Step over a watchpoint, i.e., execute the instruction that was stopped by
 * the watchpoint, and then leave the LWP stopped at the next instruction.
 */
int
Lxecwapt(struct ps_lwphandle *L, const prwatch_t *wp)
{
	struct ps_prochandle *P = L->lwp_proc;
	int rv, error;

	if (L->lwp_state != PS_STOP) {
		errno = EBUSY;
		return (-1);
	}

	Lsync(L);
	error = execute_wapt(L->lwp_ctlfd,
	    &P->status.pr_flttrace, &L->lwp_status.pr_lwphold, wp);
	rv = Lstopstatus(L, PCNULL, 0);

	if (error != 0) {
		if (L->lwp_status.pr_why == PR_JOBCONTROL &&
		    error == EBUSY) {	/* jobcontrol stop -- back off */
			L->lwp_state = PS_RUN;
			return (0);
		}
		if (error == ENOENT)
			return (0);
		errno = error;
		return (-1);
	}

	return (rv);
}

int
Lstack(struct ps_lwphandle *L, stack_t *stkp)
{
	struct ps_prochandle *P = L->lwp_proc;
	uintptr_t addr = L->lwp_status.pr_ustack;

	if (P->status.pr_dmodel == PR_MODEL_NATIVE) {
		if (Pread(P, stkp, sizeof (*stkp), addr) != sizeof (*stkp))
			return (-1);
#ifdef _LP64
	} else {
		stack32_t stk32;

		if (Pread(P, &stk32, sizeof (stk32), addr) != sizeof (stk32))
			return (-1);

		stack_32_to_n(&stk32, stkp);
#endif
	}

	return (0);
}

int
Lmain_stack(struct ps_lwphandle *L, stack_t *stkp)
{
	struct ps_prochandle *P = L->lwp_proc;

	if (Lstack(L, stkp) != 0)
		return (-1);

	/*
	 * If the SS_ONSTACK flag is set then this LWP is operating on the
	 * alternate signal stack. We can recover the original stack from
	 * pr_oldcontext.
	 */
	if (!(stkp->ss_flags & SS_ONSTACK))
		return (0);

	if (P->status.pr_dmodel == PR_MODEL_NATIVE) {
		ucontext_t *ctxp = (void *)L->lwp_status.pr_oldcontext;

		if (Pread(P, stkp, sizeof (*stkp),
		    (uintptr_t)&ctxp->uc_stack) != sizeof (*stkp))
			return (-1);
#ifdef _LP64
	} else {
		ucontext32_t *ctxp = (void *)L->lwp_status.pr_oldcontext;
		stack32_t stk32;

		if (Pread(P, &stk32, sizeof (stk32),
		    (uintptr_t)&ctxp->uc_stack) != sizeof (stk32))
			return (-1);

		stack_32_to_n(&stk32, stkp);
#endif
	}

	return (0);
}

int
Lalt_stack(struct ps_lwphandle *L, stack_t *stkp)
{
	if (L->lwp_status.pr_altstack.ss_flags & SS_DISABLE) {
		errno = ENODATA;
		return (-1);
	}

	*stkp = L->lwp_status.pr_altstack;

	return (0);
}

/*
 * Add a mapping to the given proc handle.  Resizes the array as appropriate and
 * manages reference counts on the given file_info_t.
 *
 * The 'map_relocate' member is used to tell Psort_mappings() that the
 * associated file_map pointer needs to be relocated after the mappings have
 * been sorted.  It is only set for the first mapping, and has no meaning
 * outside these two functions.
 */
int
Padd_mapping(struct ps_prochandle *P, off64_t off, file_info_t *fp,
    prmap_t *pmap)
{
	map_info_t *mp;

	if (P->map_count == P->map_alloc) {
		size_t next = P->map_alloc ? P->map_alloc * 2 : 16;

		if ((P->mappings = realloc(P->mappings,
		    next * sizeof (map_info_t))) == NULL)
			return (-1);

		P->map_alloc = next;
	}

	mp = &P->mappings[P->map_count++];

	mp->map_offset = off;
	mp->map_pmap = *pmap;
	mp->map_relocate = 0;
	if ((mp->map_file = fp) != NULL) {
		if (fp->file_map == NULL) {
			fp->file_map = mp;
			mp->map_relocate = 1;
		}
		fp->file_ref++;
	}

	return (0);
}

static int
map_sort(const void *a, const void *b)
{
	const map_info_t *ap = a, *bp = b;

	if (ap->map_pmap.pr_vaddr < bp->map_pmap.pr_vaddr)
		return (-1);
	else if (ap->map_pmap.pr_vaddr > bp->map_pmap.pr_vaddr)
		return (1);
	else
		return (0);
}

/*
 * Sort the current set of mappings.  Should be called during target
 * initialization after all calls to Padd_mapping() have been made.
 */
void
Psort_mappings(struct ps_prochandle *P)
{
	int i;
	map_info_t *mp;

	qsort(P->mappings, P->map_count, sizeof (map_info_t), map_sort);

	/*
	 * Update all the file_map pointers to refer to the new locations.
	 */
	for (i = 0; i < P->map_count; i++) {
		mp = &P->mappings[i];
		if (mp->map_relocate)
			mp->map_file->file_map = mp;
		mp->map_relocate = 0;
	}
}

struct ps_prochandle *
Pgrab_ops(pid_t pid, void *data, const ps_ops_t *ops, int flags)
{
	struct ps_prochandle *P;

	if ((P = calloc(1, sizeof (*P))) == NULL) {
		return (NULL);
	}

	Pinit_ops(&P->ops, ops);
	(void) mutex_init(&P->proc_lock, USYNC_THREAD, NULL);
	P->pid = pid;
	P->state = PS_STOP;
	P->asfd = -1;
	P->ctlfd = -1;
	P->statfd = -1;
	P->agentctlfd = -1;
	P->agentstatfd = -1;
	Pinitsym(P);
	P->data = data;
	Pread_status(P);

	if (flags & PGRAB_INCORE) {
		P->flags |= INCORE;
	}

	return (P);
}
