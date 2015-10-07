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
 */

/*
 * Copyright (c) 2011 by Delphix. All rights reserved.
 */

#include "lint.h"
#include "thr_uberdata.h"
#include <sys/libc_kernel.h>
#include <sys/procset.h>
#include <sys/fork.h>
#include <dirent.h>
#include <alloca.h>
#include <spawn.h>
#include <paths.h>

#define	ALL_POSIX_SPAWN_FLAGS			\
		(POSIX_SPAWN_RESETIDS |		\
		POSIX_SPAWN_SETPGROUP |		\
		POSIX_SPAWN_SETSIGDEF |		\
		POSIX_SPAWN_SETSIGMASK |	\
		POSIX_SPAWN_SETSCHEDPARAM |	\
		POSIX_SPAWN_SETSCHEDULER |	\
		POSIX_SPAWN_SETSIGIGN_NP |	\
		POSIX_SPAWN_NOSIGCHLD_NP |	\
		POSIX_SPAWN_WAITPID_NP |	\
		POSIX_SPAWN_NOEXECERR_NP)

typedef struct {
	int		sa_psflags;	/* POSIX_SPAWN_* flags */
	int		sa_priority;
	int		sa_schedpolicy;
	pid_t		sa_pgroup;
	sigset_t	sa_sigdefault;
	sigset_t	sa_sigignore;
	sigset_t	sa_sigmask;
} spawn_attr_t;

typedef struct file_attr {
	struct file_attr *fa_next;	/* circular list of file actions */
	struct file_attr *fa_prev;
	enum {FA_OPEN, FA_CLOSE, FA_DUP2, FA_CLOSEFROM} fa_type;
	int		fa_need_dirbuf;	/* only consulted in the head action */
	char		*fa_path;	/* copied pathname for open() */
	uint_t		fa_pathsize;	/* size of fa_path[] array */
	int		fa_oflag;	/* oflag for open() */
	mode_t		fa_mode;	/* mode for open() */
	int		fa_filedes;	/* file descriptor for open()/close() */
	int		fa_newfiledes;	/* new file descriptor for dup2() */
} file_attr_t;

#if defined(_LP64)
#define	__open64	__open
#define	getdents64	getdents
#define	dirent64_t	dirent_t
#else
extern int getdents64(int, dirent64_t *, size_t);
#endif

extern const char **_environ;

/*
 * Support function:
 * Close all open file descriptors greater than or equal to lowfd.
 * This is executed in the child of vfork(), so we must not call
 * opendir() / readdir() because that would alter the parent's
 * address space.  We use the low-level getdents64() system call.
 * Return non-zero on error.
 */
static int
spawn_closefrom(int lowfd, void *buf)
{
	int procfd;
	int fd;
	int buflen;
	dirent64_t *dp;
	dirent64_t *dpend;

	if (lowfd <  0)
		lowfd = 0;

	/*
	 * Close lowfd right away as a hedge against failing
	 * to open the /proc file descriptor directory due
	 * all file descriptors being currently used up.
	 */
	(void) __close(lowfd++);

	if ((procfd = __open64("/proc/self/fd", O_RDONLY, 0)) < 0) {
		/*
		 * We could not open the /proc file descriptor directory.
		 * Just fail and be done with it.
		 */
		return (-1);
	}

	for (;;) {
		/*
		 * Collect a bunch of open file descriptors and close them.
		 * Repeat until the directory is exhausted.
		 */
		dp = (dirent64_t *)buf;
		if ((buflen = getdents64(procfd, dp, DIRBUF)) <= 0) {
			(void) __close(procfd);
			break;
		}
		dpend = (dirent64_t *)((uintptr_t)buf + buflen);
		do {
			/* skip '.', '..' and procfd */
			if (dp->d_name[0] != '.' &&
			    (fd = atoi(dp->d_name)) != procfd &&
			    fd >= lowfd)
				(void) __close(fd);
			dp = (dirent64_t *)((uintptr_t)dp + dp->d_reclen);
		} while (dp < dpend);
	}

	return (0);
}

static int
perform_flag_actions(spawn_attr_t *sap)
{
	int sig;
	struct sigaction action;

	if (sap->sa_psflags & POSIX_SPAWN_SETSIGMASK) {
		(void) __lwp_sigmask(SIG_SETMASK, &sap->sa_sigmask);
	}

	if (sap->sa_psflags & POSIX_SPAWN_SETSIGIGN_NP) {
		(void) memset(&action, 0, sizeof (action));
		action.sa_handler = SIG_IGN;
		for (sig = 1; sig < NSIG; sig++) {
			if (sigismember(&sap->sa_sigignore, sig))
				(void) __sigaction(sig, &action, NULL);
		}
	}

	if (sap->sa_psflags & POSIX_SPAWN_SETSIGDEF) {
		(void) memset(&action, 0, sizeof (action));
		action.sa_handler = SIG_DFL;
		for (sig = 1; sig < NSIG; sig++) {
			if (sigismember(&sap->sa_sigdefault, sig))
				(void) __sigaction(sig, &action, NULL);
		}
	}

	if (sap->sa_psflags & POSIX_SPAWN_RESETIDS) {
		if (setgid(getgid()) != 0 || setuid(getuid()) != 0)
			return (errno);
	}

	if (sap->sa_psflags & POSIX_SPAWN_SETPGROUP) {
		if (setpgid(0, sap->sa_pgroup) != 0)
			return (errno);
	}

	if (sap->sa_psflags & POSIX_SPAWN_SETSCHEDULER) {
		if (setparam(P_LWPID, P_MYID,
		    sap->sa_schedpolicy, sap->sa_priority) == -1)
			return (errno);
	} else if (sap->sa_psflags & POSIX_SPAWN_SETSCHEDPARAM) {
		if (setprio(P_LWPID, P_MYID, sap->sa_priority, NULL) == -1)
			return (errno);
	}

	return (0);
}

static int
perform_file_actions(file_attr_t *fap, void *dirbuf)
{
	file_attr_t *froot = fap;
	int fd;

	do {
		switch (fap->fa_type) {
		case FA_OPEN:
			fd = __open(fap->fa_path, fap->fa_oflag, fap->fa_mode);
			if (fd < 0)
				return (errno);
			if (fd != fap->fa_filedes) {
				if (__fcntl(fd, F_DUP2FD, fap->fa_filedes) < 0)
					return (errno);
				(void) __close(fd);
			}
			break;
		case FA_CLOSE:
			if (__close(fap->fa_filedes) == -1 &&
			    errno != EBADF)	/* already closed, no error */
				return (errno);
			break;
		case FA_DUP2:
			fd = __fcntl(fap->fa_filedes, F_DUP2FD,
			    fap->fa_newfiledes);
			if (fd < 0)
				return (errno);
			break;
		case FA_CLOSEFROM:
			if (spawn_closefrom(fap->fa_filedes, dirbuf))
				return (errno);
			break;
		}
	} while ((fap = fap->fa_next) != froot);

	return (0);
}

static int
forkflags(spawn_attr_t *sap)
{
	int flags = 0;

	if (sap != NULL) {
		if (sap->sa_psflags & POSIX_SPAWN_NOSIGCHLD_NP)
			flags |= FORK_NOSIGCHLD;
		if (sap->sa_psflags & POSIX_SPAWN_WAITPID_NP)
			flags |= FORK_WAITPID;
	}

	return (flags);
}

/*
 * set_error() / get_error() are used to guarantee that the local variable
 * 'error' is set correctly in memory on return from vfork() in the parent.
 */

static int
set_error(int *errp, int err)
{
	return (*errp = err);
}

static int
get_error(int *errp)
{
	return (*errp);
}

/*
 * For MT safety, do not invoke the dynamic linker after calling vfork().
 * If some other thread was in the dynamic linker when this thread's parent
 * called vfork() then the dynamic linker's lock would still be held here
 * (with a defunct owner) and we would deadlock ourself if we invoked it.
 *
 * Therefore, all of the functions we call here after returning from
 * vforkx() in the child are not and must never be exported from libc
 * as global symbols.  To do so would risk invoking the dynamic linker.
 */

int
posix_spawn(
	pid_t *pidp,
	const char *path,
	const posix_spawn_file_actions_t *file_actions,
	const posix_spawnattr_t *attrp,
	char *const *argv,
	char *const *envp)
{
	spawn_attr_t *sap = attrp? attrp->__spawn_attrp : NULL;
	file_attr_t *fap = file_actions? file_actions->__file_attrp : NULL;
	void *dirbuf = NULL;
	int error;		/* this will be set by the child */
	pid_t pid;

	if (attrp != NULL && sap == NULL)
		return (EINVAL);

	if (fap != NULL && fap->fa_need_dirbuf) {
		/*
		 * Preallocate the buffer for the call to getdents64() in
		 * spawn_closefrom() since we can't do it in the vfork() child.
		 */
		if ((dirbuf = lmalloc(DIRBUF)) == NULL)
			return (ENOMEM);
	}

	switch (pid = vforkx(forkflags(sap))) {
	case 0:			/* child */
		break;
	case -1:		/* parent, failure */
		if (dirbuf)
			lfree(dirbuf, DIRBUF);
		return (errno);
	default:		/* parent, success */
		/*
		 * We don't get here until the child exec()s or exit()s
		 */
		if (pidp != NULL && get_error(&error) == 0)
			*pidp = pid;
		if (dirbuf)
			lfree(dirbuf, DIRBUF);
		return (get_error(&error));
	}

	if (sap != NULL)
		if (set_error(&error, perform_flag_actions(sap)) != 0)
			_exit(_EVAPORATE);

	if (fap != NULL)
		if (set_error(&error, perform_file_actions(fap, dirbuf)) != 0)
			_exit(_EVAPORATE);

	(void) set_error(&error, 0);
	(void) execve(path, argv, envp);
	if (sap != NULL && (sap->sa_psflags & POSIX_SPAWN_NOEXECERR_NP))
		_exit(127);
	(void) set_error(&error, errno);
	_exit(_EVAPORATE);
	return (0);	/* not reached */
}

/*
 * Much of posix_spawnp() blatently stolen from execvp() (port/gen/execvp.c).
 */

extern int libc__xpg4;

static const char *
execat(const char *s1, const char *s2, char *si)
{
	int cnt = PATH_MAX + 1;
	char *s;
	char c;

	for (s = si; (c = *s1) != '\0' && c != ':'; s1++) {
		if (cnt > 0) {
			*s++ = c;
			cnt--;
		}
	}
	if (si != s && cnt > 0) {
		*s++ = '/';
		cnt--;
	}
	for (; (c = *s2) != '\0' && cnt > 0; s2++) {
		*s++ = c;
		cnt--;
	}
	*s = '\0';
	return (*s1? ++s1: NULL);
}

/* ARGSUSED */
int
posix_spawnp(
	pid_t *pidp,
	const char *file,
	const posix_spawn_file_actions_t *file_actions,
	const posix_spawnattr_t *attrp,
	char *const *argv,
	char *const *envp)
{
	spawn_attr_t *sap = attrp? attrp->__spawn_attrp : NULL;
	file_attr_t *fap = file_actions? file_actions->__file_attrp : NULL;
	void *dirbuf = NULL;
	const char *pathstr = (strchr(file, '/') == NULL)? getenv("PATH") : "";
	int xpg4 = libc__xpg4;
	int error = 0;		/* this will be set by the child */
	char path[PATH_MAX+4];
	const char *cp;
	pid_t pid;
	char **newargs;
	int argc;
	int i;

	if (attrp != NULL && sap == NULL)
		return (EINVAL);

	if (*file == '\0')
		return (EACCES);

	if (fap != NULL && fap->fa_need_dirbuf) {
		/*
		 * Preallocate the buffer for the call to getdents64() in
		 * spawn_closefrom() since we can't do it in the vfork() child.
		 */
		if ((dirbuf = lmalloc(DIRBUF)) == NULL)
			return (ENOMEM);
	}

	/*
	 * We may need to invoke the shell with a slightly modified
	 * argv[] array.  To do this we need to preallocate the array.
	 * We must call alloca() before calling vfork() because doing
	 * it after vfork() (in the child) would corrupt the parent.
	 */
	for (argc = 0; argv[argc] != NULL; argc++)
		continue;
	newargs = alloca((argc + 2) * sizeof (char *));

	switch (pid = vforkx(forkflags(sap))) {
	case 0:			/* child */
		break;
	case -1:		/* parent, failure */
		if (dirbuf)
			lfree(dirbuf, DIRBUF);
		return (errno);
	default:		/* parent, success */
		/*
		 * We don't get here until the child exec()s or exit()s
		 */
		if (pidp != NULL && get_error(&error) == 0)
			*pidp = pid;
		if (dirbuf)
			lfree(dirbuf, DIRBUF);
		return (get_error(&error));
	}

	if (sap != NULL)
		if (set_error(&error, perform_flag_actions(sap)) != 0)
			_exit(_EVAPORATE);

	if (fap != NULL)
		if (set_error(&error, perform_file_actions(fap, dirbuf)) != 0)
			_exit(_EVAPORATE);

	if (pathstr == NULL) {
		/*
		 * XPG4:  pathstr is equivalent to _CS_PATH, except that
		 * :/usr/sbin is appended when root, and pathstr must end
		 * with a colon when not root.  Keep these paths in sync
		 * with _CS_PATH in confstr.c.  Note that pathstr must end
		 * with a colon when not root so that when file doesn't
		 * contain '/', the last call to execat() will result in an
		 * attempt to execv file from the current directory.
		 */
		if (geteuid() == 0 || getuid() == 0) {
			if (!xpg4)
				pathstr = "/usr/sbin:/usr/ccs/bin:/usr/bin";
			else
				pathstr = "/usr/xpg4/bin:/usr/ccs/bin:"
				    "/usr/bin:/opt/SUNWspro/bin:/usr/sbin";
		} else {
			if (!xpg4)
				pathstr = "/usr/ccs/bin:/usr/bin:";
			else
				pathstr = "/usr/xpg4/bin:/usr/ccs/bin:"
				    "/usr/bin:/opt/SUNWspro/bin:";
		}
	}

	cp = pathstr;
	do {
		cp = execat(cp, file, path);
		/*
		 * 4025035 and 4038378
		 * if a filename begins with a "-" prepend "./" so that
		 * the shell can't interpret it as an option
		 */
		if (*path == '-') {
			char *s;

			for (s = path; *s != '\0'; s++)
				continue;
			for (; s >= path; s--)
				*(s + 2) = *s;
			path[0] = '.';
			path[1] = '/';
		}
		(void) set_error(&error, 0);
		(void) execve(path, argv, envp);
		if (set_error(&error, errno) == ENOEXEC) {
			newargs[0] = "sh";
			newargs[1] = path;
			for (i = 1; i <= argc; i++)
				newargs[i + 1] = argv[i];
			(void) set_error(&error, 0);
			(void) execve(_PATH_BSHELL, newargs, envp);
			if (sap != NULL &&
			    (sap->sa_psflags & POSIX_SPAWN_NOEXECERR_NP))
				_exit(127);
			(void) set_error(&error, errno);
			_exit(_EVAPORATE);
		}
	} while (cp);

	if (sap != NULL &&
	    (sap->sa_psflags & POSIX_SPAWN_NOEXECERR_NP)) {
		(void) set_error(&error, 0);
		_exit(127);
	}
	_exit(_EVAPORATE);
	return (0);	/* not reached */
}

int
posix_spawn_file_actions_init(
	posix_spawn_file_actions_t *file_actions)
{
	file_actions->__file_attrp = NULL;
	return (0);
}

int
posix_spawn_file_actions_destroy(
	posix_spawn_file_actions_t *file_actions)
{
	file_attr_t *froot = file_actions->__file_attrp;
	file_attr_t *fap;
	file_attr_t *next;

	if ((fap = froot) != NULL) {
		do {
			next = fap->fa_next;
			if (fap->fa_type == FA_OPEN)
				lfree(fap->fa_path, fap->fa_pathsize);
			lfree(fap, sizeof (*fap));
		} while ((fap = next) != froot);
	}
	file_actions->__file_attrp = NULL;
	return (0);
}

static void
add_file_attr(posix_spawn_file_actions_t *file_actions, file_attr_t *fap)
{
	file_attr_t *froot = file_actions->__file_attrp;

	if (froot == NULL) {
		fap->fa_next = fap->fa_prev = fap;
		file_actions->__file_attrp = froot = fap;
	} else {
		fap->fa_next = froot;
		fap->fa_prev = froot->fa_prev;
		froot->fa_prev->fa_next = fap;
		froot->fa_prev = fap;
	}

	/*
	 * Once set, __file_attrp no longer changes, so this assignment
	 * always goes into the first element in the list, as required.
	 */
	if (fap->fa_type == FA_CLOSEFROM)
		froot->fa_need_dirbuf = 1;
}

int
posix_spawn_file_actions_addopen(
	posix_spawn_file_actions_t *file_actions,
	int filedes,
	const char *path,
	int oflag,
	mode_t mode)
{
	file_attr_t *fap;

	if (filedes < 0)
		return (EBADF);
	if ((fap = lmalloc(sizeof (*fap))) == NULL)
		return (ENOMEM);

	fap->fa_pathsize = strlen(path) + 1;
	if ((fap->fa_path = lmalloc(fap->fa_pathsize)) == NULL) {
		lfree(fap, sizeof (*fap));
		return (ENOMEM);
	}
	(void) strcpy(fap->fa_path, path);

	fap->fa_type = FA_OPEN;
	fap->fa_oflag = oflag;
	fap->fa_mode = mode;
	fap->fa_filedes = filedes;
	add_file_attr(file_actions, fap);

	return (0);
}

int
posix_spawn_file_actions_addclose(
	posix_spawn_file_actions_t *file_actions,
	int filedes)
{
	file_attr_t *fap;

	if (filedes < 0)
		return (EBADF);
	if ((fap = lmalloc(sizeof (*fap))) == NULL)
		return (ENOMEM);

	fap->fa_type = FA_CLOSE;
	fap->fa_filedes = filedes;
	add_file_attr(file_actions, fap);

	return (0);
}

int
posix_spawn_file_actions_adddup2(
	posix_spawn_file_actions_t *file_actions,
	int filedes,
	int newfiledes)
{
	file_attr_t *fap;

	if (filedes < 0 || newfiledes < 0)
		return (EBADF);
	if ((fap = lmalloc(sizeof (*fap))) == NULL)
		return (ENOMEM);

	fap->fa_type = FA_DUP2;
	fap->fa_filedes = filedes;
	fap->fa_newfiledes = newfiledes;
	add_file_attr(file_actions, fap);

	return (0);
}

int
posix_spawn_file_actions_addclosefrom_np(
	posix_spawn_file_actions_t *file_actions,
	int lowfiledes)
{
	file_attr_t *fap;

	if (lowfiledes < 0)
		return (EBADF);
	if ((fap = lmalloc(sizeof (*fap))) == NULL)
		return (ENOMEM);
	fap->fa_type = FA_CLOSEFROM;
	fap->fa_filedes = lowfiledes;
	add_file_attr(file_actions, fap);

	return (0);
}

int
posix_spawnattr_init(
	posix_spawnattr_t *attr)
{
	if ((attr->__spawn_attrp = lmalloc(sizeof (posix_spawnattr_t))) == NULL)
		return (ENOMEM);
	/*
	 * Add default stuff here?
	 */
	return (0);
}

int
posix_spawnattr_destroy(
	posix_spawnattr_t *attr)
{
	spawn_attr_t *sap = attr->__spawn_attrp;

	if (sap == NULL)
		return (EINVAL);

	/*
	 * deallocate stuff here?
	 */
	lfree(sap, sizeof (*sap));
	attr->__spawn_attrp = NULL;
	return (0);
}

int
posix_spawnattr_setflags(
	posix_spawnattr_t *attr,
	short flags)
{
	spawn_attr_t *sap = attr->__spawn_attrp;

	if (sap == NULL ||
	    (flags & ~ALL_POSIX_SPAWN_FLAGS))
		return (EINVAL);

	sap->sa_psflags = flags;
	return (0);
}

int
posix_spawnattr_getflags(
	const posix_spawnattr_t *attr,
	short *flags)
{
	spawn_attr_t *sap = attr->__spawn_attrp;

	if (sap == NULL)
		return (EINVAL);

	*flags = sap->sa_psflags;
	return (0);
}

int
posix_spawnattr_setpgroup(
	posix_spawnattr_t *attr,
	pid_t pgroup)
{
	spawn_attr_t *sap = attr->__spawn_attrp;

	if (sap == NULL)
		return (EINVAL);

	sap->sa_pgroup = pgroup;
	return (0);
}

int
posix_spawnattr_getpgroup(
	const posix_spawnattr_t *attr,
	pid_t *pgroup)
{
	spawn_attr_t *sap = attr->__spawn_attrp;

	if (sap == NULL)
		return (EINVAL);

	*pgroup = sap->sa_pgroup;
	return (0);
}

int
posix_spawnattr_setschedparam(
	posix_spawnattr_t *attr,
	const struct sched_param *schedparam)
{
	spawn_attr_t *sap = attr->__spawn_attrp;

	if (sap == NULL)
		return (EINVAL);

	/*
	 * Check validity?
	 */
	sap->sa_priority = schedparam->sched_priority;
	return (0);
}

int
posix_spawnattr_getschedparam(
	const posix_spawnattr_t *attr,
	struct sched_param *schedparam)
{
	spawn_attr_t *sap = attr->__spawn_attrp;

	if (sap == NULL)
		return (EINVAL);

	schedparam->sched_priority = sap->sa_priority;
	return (0);
}

int
posix_spawnattr_setschedpolicy(
	posix_spawnattr_t *attr,
	int schedpolicy)
{
	spawn_attr_t *sap = attr->__spawn_attrp;

	if (sap == NULL || schedpolicy == SCHED_SYS)
		return (EINVAL);

	/*
	 * Cache the policy information for later use
	 * by the vfork() child of posix_spawn().
	 */
	if (get_info_by_policy(schedpolicy) == NULL)
		return (errno);

	sap->sa_schedpolicy = schedpolicy;
	return (0);
}

int
posix_spawnattr_getschedpolicy(
	const posix_spawnattr_t *attr,
	int *schedpolicy)
{
	spawn_attr_t *sap = attr->__spawn_attrp;

	if (sap == NULL)
		return (EINVAL);

	*schedpolicy = sap->sa_schedpolicy;
	return (0);
}

int
posix_spawnattr_setsigdefault(
	posix_spawnattr_t *attr,
	const sigset_t *sigdefault)
{
	spawn_attr_t *sap = attr->__spawn_attrp;

	if (sap == NULL)
		return (EINVAL);

	sap->sa_sigdefault = *sigdefault;
	return (0);
}

int
posix_spawnattr_getsigdefault(
	const posix_spawnattr_t *attr,
	sigset_t *sigdefault)
{
	spawn_attr_t *sap = attr->__spawn_attrp;

	if (sap == NULL)
		return (EINVAL);

	*sigdefault = sap->sa_sigdefault;
	return (0);
}

int
posix_spawnattr_setsigignore_np(
	posix_spawnattr_t *attr,
	const sigset_t *sigignore)
{
	spawn_attr_t *sap = attr->__spawn_attrp;

	if (sap == NULL)
		return (EINVAL);

	sap->sa_sigignore = *sigignore;
	return (0);
}

int
posix_spawnattr_getsigignore_np(
	const posix_spawnattr_t *attr,
	sigset_t *sigignore)
{
	spawn_attr_t *sap = attr->__spawn_attrp;

	if (sap == NULL)
		return (EINVAL);

	*sigignore = sap->sa_sigignore;
	return (0);
}

int
posix_spawnattr_setsigmask(
	posix_spawnattr_t *attr,
	const sigset_t *sigmask)
{
	spawn_attr_t *sap = attr->__spawn_attrp;

	if (sap == NULL)
		return (EINVAL);

	sap->sa_sigmask = *sigmask;
	return (0);
}

int
posix_spawnattr_getsigmask(
	const posix_spawnattr_t *attr,
	sigset_t *sigmask)
{
	spawn_attr_t *sap = attr->__spawn_attrp;

	if (sap == NULL)
		return (EINVAL);

	*sigmask = sap->sa_sigmask;
	return (0);
}

/*
 * Spawn a process to run "sh -c <cmd>".  Return the child's pid (in
 * *pidp), and a file descriptor (in *fdp) for reading or writing to the
 * child process, depending on the 'write' argument.
 * Return 0 on success; otherwise return an error code.
 */
int
posix_spawn_pipe_np(pid_t *pidp, int *fdp,
    const char *cmd, boolean_t write,
    posix_spawn_file_actions_t *fact, posix_spawnattr_t *attr)
{
	int	p[2];
	int	myside, yourside, stdio;
	const char *shpath = _PATH_BSHELL;
	const char *argvec[4] = { "sh", "-c", cmd, NULL };
	int	error;

	if (pipe(p) < 0)
		return (errno);

	if (access(shpath, X_OK))	/* XPG4 Requirement: */
		shpath = "";		/* force child to fail immediately */

	if (write) {
		/*
		 * Data is read from p[0] and written to p[1].
		 * 'stdio' is the fd in the child process that should be
		 * connected to the pipe.
		 */
		myside = p[1];
		yourside = p[0];
		stdio = STDIN_FILENO;
	} else {
		myside = p[0];
		yourside = p[1];
		stdio = STDOUT_FILENO;
	}

	error = posix_spawn_file_actions_addclose(fact, myside);
	if (yourside != stdio) {
		if (error == 0) {
			error = posix_spawn_file_actions_adddup2(fact,
			    yourside, stdio);
		}
		if (error == 0) {
			error = posix_spawn_file_actions_addclose(fact,
			    yourside);
		}
	}

	if (error)
		return (error);
	error = posix_spawn(pidp, shpath, fact, attr,
	    (char *const *)argvec, (char *const *)_environ);
	(void) close(yourside);
	if (error) {
		(void) close(myside);
		return (error);
	}

	*fdp = myside;
	return (0);
}
