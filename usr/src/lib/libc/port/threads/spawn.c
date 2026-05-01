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
 * Copyright 2026 Oxide Computer Company
 */

#include "lint.h"
#include "thr_uberdata.h"
#include <sys/sysmacros.h>
#include <limits.h>
#include <spawn.h>
#include <stdbool.h>
#include <sys/spawn_impl.h>
#include <paths.h>

extern const char **_environ;
extern int libc__xpg4;

extern pid_t __spawn(const char *, const void *, uint32_t, const void *,
    uint32_t);

/*
 * Add sz to the running total *lenp, refusing if the total would exceed
 * ARG_MAX. ARG_MAX is well below UINT32_MAX, so capping there also keeps the
 * marshalled totals and offsets within their uint32_t fields.
 */
static inline bool
spawn_addlen(size_t *lenp, size_t sz)
{
	if (sz > ARG_MAX - *lenp)
		return (false);
	*lenp += sz;
	return (true);
}

/*
 * Pack the argv[] and envp[] string vectors into sargs->sa_data as a single
 * blob of NUL-terminated strings. Called first with sargs == NULL to compute
 * the required buffer size, then again to populate the data and record the
 * offsets and counts. Returns false if the combined size would exceed ARG_MAX
 * or, on the second pass, would overflow the allocated buffer.
 */
static bool
spawn_marshal_argenv(spawn_args_t *sargs, char *const *argp, char *const *envp,
    size_t *lenp)
{
	struct vec {
		char *const *vec;
		uint32_t *off;
		uint32_t *cnt;
	} vecs[] = {
		{ .vec = argp },
		{ .vec = envp }
	};

	if (sargs != NULL) {
		vecs[0].off = &sargs->sa_arg_off;
		vecs[0].cnt = &sargs->sa_arg_cnt;
		vecs[1].off = &sargs->sa_env_off;
		vecs[1].cnt = &sargs->sa_env_cnt;
	}

	for (size_t i = 0; i < ARRAY_SIZE(vecs); i++) {
		struct vec *vec = &vecs[i];
		uint32_t cnt = 0;
		char *const *p;

		if (vec->off != NULL)
			*vec->off = (uint32_t)*lenp;

		for (p = vec->vec; p != NULL && *p != NULL; p++) {
			size_t sz = strlen(*p) + 1;

			if (sargs != NULL) {
				if (*lenp + sz > sargs->sa_datalen)
					return (false);
				(void) memcpy(&sargs->sa_data[*lenp], *p, sz);
			}
			if (!spawn_addlen(lenp, sz))
				return (false);
			cnt++;
		}

		if (vec->cnt != NULL)
			*vec->cnt = cnt;
	}

	return (true);
}

/*
 * Pack the spawn_attr_t, the resolved scheduling attributes, the circular
 * list of file_attr_t records and, for posix_spawnp(), the shell and search
 * path strings into sparam->sp_data.
 * Called first with sparam == NULL to compute the required buffer size, then
 * again to populate the data and record the offsets, lengths and counts.
 * Returns false if the combined size would exceed ARG_MAX or, on the second
 * pass, would overflow the allocated buffer.
 */
static bool
spawn_marshal_param(spawn_param_t *sparam, const spawn_attr_t *sa,
    const kspawn_sched_t *ksched, const file_attr_t *fa, const char *shell,
    const char *pathstr, size_t *lenp)
{
	if (sa != NULL) {
		size_t sz = sizeof (*sa);

		if (sparam != NULL) {
			if (*lenp + sz > sparam->sp_datalen)
				return (false);
			sparam->sp_attr_off = (uint32_t)*lenp;
			sparam->sp_attr_len = (uint32_t)sz;
			(void) memcpy(&sparam->sp_data[*lenp], sa, sz);
		}
		if (!spawn_addlen(lenp, sz))
			return (false);
	}

	if (ksched != NULL) {
		size_t sz = sizeof (*ksched);

		if (sparam != NULL) {
			if (*lenp + sz > sparam->sp_datalen)
				return (false);
			sparam->sp_sched_off = (uint32_t)*lenp;
			sparam->sp_sched_len = (uint32_t)sz;
			(void) memcpy(&sparam->sp_data[*lenp], ksched, sz);
		}
		if (!spawn_addlen(lenp, sz))
			return (false);
	}

	if (fa != NULL) {
		const file_attr_t *froot = fa;
		uint32_t cnt = 0;

		if (sparam != NULL)
			sparam->sp_fattr_off = (uint32_t)*lenp;

		do {
			/*
			 * Each record is padded so that the next remains
			 * 32-bit aligned.
			 */
			size_t sz = P2ROUNDUP(
			    sizeof (kfile_attr_t) + fa->fa_pathsize,
			    sizeof (uint32_t));

			if (sparam != NULL) {
				kfile_attr_t *ka;

				if (*lenp + sz > sparam->sp_datalen)
					return (false);

				ka = (kfile_attr_t *)&sparam->sp_data[*lenp];
				ka->kfa_len = sz;
				ka->kfa_type = fa->fa_type;
				ka->kfa_pathsize = fa->fa_pathsize;

				switch (fa->fa_type) {
				case FA_OPEN:
					ka->kfa_filedes = fa->fa_filedes;
					ka->kfa_oflag = fa->fa_oflag;
					ka->kfa_mode = fa->fa_mode;
					/* FALLTHROUGH */
				case FA_CHDIR:
					(void) memcpy(ka->kfa_path,
					    fa->fa_path, fa->fa_pathsize);
					break;
				case FA_DUP2:
					ka->kfa_newfiledes = fa->fa_newfiledes;
					/* FALLTHROUGH */
				case FA_CLOSE:
				case FA_CLOSEFROM:
				case FA_FCHDIR:
					ka->kfa_filedes = fa->fa_filedes;
					break;
				}
			}
			if (!spawn_addlen(lenp, sz))
				return (false);
			cnt++;
		} while ((fa = fa->fa_next) != froot);

		if (sparam != NULL)
			sparam->sp_fattr_cnt = cnt;
	}

	if (shell != NULL) {
		size_t sz = strlen(shell) + 1;

		if (sparam != NULL) {
			if (*lenp + sz > sparam->sp_datalen)
				return (false);
			sparam->sp_shell_off = (uint32_t)*lenp;
			sparam->sp_shell_len = (uint32_t)sz;
			(void) memcpy(&sparam->sp_data[*lenp], shell, sz);
		}
		if (!spawn_addlen(lenp, sz))
			return (false);
	}

	if (pathstr != NULL) {
		size_t sz = strlen(pathstr) + 1;

		if (sparam != NULL) {
			if (*lenp + sz > sparam->sp_datalen)
				return (false);
			sparam->sp_path_off = (uint32_t)*lenp;
			sparam->sp_path_len = (uint32_t)sz;
			(void) memcpy(&sparam->sp_data[*lenp], pathstr, sz);
		}
		if (!spawn_addlen(lenp, sz))
			return (false);
	}

	return (true);
}

static int
posix_spawn_common(pid_t *pidp, const char *path,
    const posix_spawn_file_actions_t *file_actions,
    const posix_spawnattr_t *attrp, char *const *argp, char *const *envp,
    const char *shell, const char *pathstr)
{
	spawn_attr_t *sa = (attrp != NULL) ? attrp->__spawn_attrp : NULL;
	file_attr_t *fa = (file_actions != NULL) ? file_actions->__file_attrp :
	    NULL;
	const kspawn_sched_t *ksched = NULL;
	kspawn_sched_t ks;
	spawn_args_t *sargs = NULL;
	spawn_param_t *sparam = NULL;
	pid_t pid;
	size_t datalen, len;
	int ret = 0;

	if (attrp != NULL && sa == NULL)
		return (EINVAL);

	/*
	 * The scheduling attributes are resolved here into the form that the
	 * child applies to itself in the kernel.
	 */
	if (sa != NULL && (sa->sa_psflags &
	    (POSIX_SPAWN_SETSCHEDULER | POSIX_SPAWN_SETSCHEDPARAM)) != 0) {
		ret = spawn_sched_resolve(sa->sa_psflags, sa->sa_schedpolicy,
		    sa->sa_priority, &ks);
		if (ret != 0)
			return (ret);
		ksched = &ks;
	}

	/*
	 * spawn(2) creates a brand-new child process that does not share the
	 * parent's address space, so every piece of state needed to set up the
	 * child must be copied into the kernel ahead of time. Marshal the
	 * spawn attributes, the list of file actions and, for posix_spawnp(),
	 * the shell and search path, into a single contiguous blob that the
	 * kernel can copy in and retain.
	 */
	datalen = 0;
	if (!spawn_marshal_param(NULL, sa, ksched, fa, shell, pathstr,
	    &datalen)) {
		ret = E2BIG;
		goto out;
	}
	if (datalen > 0) {
		len = sizeof (*sparam) + datalen;
		sparam = lmalloc(len);
		if (sparam == NULL) {
			ret = errno;
			goto out;
		}
		sparam->sp_size = len;
		sparam->sp_datalen = datalen;

		datalen = 0;
		if (!spawn_marshal_param(sparam, sa, ksched, fa, shell,
		    pathstr, &datalen) || datalen != sparam->sp_datalen) {
			ret = EINVAL;
			goto out;
		}
	}

	/*
	 * Likewise the argument and environment vectors. As supplied by the
	 * caller these are arrays of pointers into strings that may well be
	 * scattered around the parent's address space. Flatten the strings
	 * into a single contiguous blob that the kernel can copy in.
	 */
	datalen = 0;
	if (!spawn_marshal_argenv(NULL, argp, envp, &datalen)) {
		ret = E2BIG;
		goto out;
	}
	len = sizeof (*sargs) + datalen;
	sargs = lmalloc(len);
	if (sargs == NULL) {
		ret = errno;
		goto out;
	}
	sargs->sa_size = len;
	sargs->sa_datalen = datalen;

	datalen = 0;
	if (!spawn_marshal_argenv(sargs, argp, envp, &datalen) ||
	    datalen != sargs->sa_datalen) {
		ret = EINVAL;
		goto out;
	}

	pid = __spawn(path, sparam, sparam != NULL ? sparam->sp_size : 0,
	    sargs, sargs->sa_size);

	if (pid == -1) {
		ret = errno;
		goto out;
	}

	if (pidp != NULL)
		*pidp = pid;

out:
	if (sparam != NULL)
		lfree(sparam, sparam->sp_size);
	if (sargs != NULL)
		lfree(sargs, sargs->sa_size);
	return (ret);
}

int
posix_spawn(pid_t *pidp, const char *path,
    const posix_spawn_file_actions_t *file_actions,
    const posix_spawnattr_t *attrp, char *const *argp, char *const *envp)
{
	return (posix_spawn_common(pidp, path, file_actions, attrp,
	    argp, envp, NULL, NULL));
}

int
posix_spawnp(pid_t *pidp, const char *file,
    const posix_spawn_file_actions_t *file_actions,
    const posix_spawnattr_t *attrp, char *const *argp, char *const *envp)
{
	const char *pathstr =
	    (strchr(file, '/') == NULL) ? getenv("PATH") : "";

	if (*file == '\0')
		return (EACCES);

	if (pathstr == NULL) {
		/*
		 * XPG4:  pathstr is equivalent to _CS_PATH, except that
		 * :/usr/sbin is appended when root, and pathstr must end
		 * with a colon when not root.  Keep these paths in sync
		 * with _CS_PATH in confstr.c.  Note that pathstr must end
		 * with a colon when not root so that when file doesn't
		 * contain '/', the last attempt will be to exec the file
		 * from the current directory.
		 */
		if (geteuid() == 0 || getuid() == 0) {
			if (!libc__xpg4) {
				pathstr = "/usr/sbin:/usr/ccs/bin:/usr/bin";
			} else {
				pathstr = "/usr/xpg4/bin:/usr/ccs/bin:"
				    "/usr/bin:/opt/SUNWspro/bin:/usr/sbin";
			}
		} else {
			if (!libc__xpg4) {
				pathstr = "/usr/ccs/bin:/usr/bin:";
			} else {
				pathstr = "/usr/xpg4/bin:/usr/ccs/bin:"
				    "/usr/bin:/opt/SUNWspro/bin:";
			}
		}
	}

	return (posix_spawn_common(pidp, file, file_actions, attrp,
	    argp, envp, _PATH_BSHELL, pathstr));
}

int
posix_spawn_file_actions_init(posix_spawn_file_actions_t *file_actions)
{
	file_actions->__file_attrp = NULL;
	return (0);
}

int
posix_spawn_file_actions_destroy(posix_spawn_file_actions_t *file_actions)
{
	file_attr_t *froot = file_actions->__file_attrp;
	file_attr_t *fap;
	file_attr_t *next;

	if ((fap = froot) != NULL) {
		do {
			next = fap->fa_next;
			if (fap->fa_type == FA_OPEN || fap->fa_type == FA_CHDIR)
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
}

int
posix_spawn_file_actions_addopen(
    posix_spawn_file_actions_t *restrict file_actions,
    int filedes, const char *restrict path, int oflag, mode_t mode)
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
	(void) memcpy(fap->fa_path, path, fap->fa_pathsize);

	fap->fa_type = FA_OPEN;
	fap->fa_oflag = oflag;
	fap->fa_mode = mode;
	fap->fa_filedes = filedes;
	add_file_attr(file_actions, fap);

	return (0);
}

int
posix_spawn_file_actions_addclose(
    posix_spawn_file_actions_t *restrict file_actions, int filedes)
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
    posix_spawn_file_actions_t *restrict file_actions,
    int filedes, int newfiledes)
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
    posix_spawn_file_actions_t *restrict file_actions, int lowfiledes)
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
posix_spawn_file_actions_addchdir(
    posix_spawn_file_actions_t *restrict file_actions,
    const char *restrict path)
{
	file_attr_t *fap;

	if ((fap = lmalloc(sizeof (*fap))) == NULL)
		return (ENOMEM);

	fap->fa_pathsize = strlen(path) + 1;
	if ((fap->fa_path = lmalloc(fap->fa_pathsize)) == NULL) {
		lfree(fap, sizeof (*fap));
		return (ENOMEM);
	}
	(void) memcpy(fap->fa_path, path, fap->fa_pathsize);

	fap->fa_type = FA_CHDIR;
	add_file_attr(file_actions, fap);

	return (0);
}

int
posix_spawn_file_actions_addchdir_np(
    posix_spawn_file_actions_t *restrict file_actions,
    const char *restrict path)
{
	return (posix_spawn_file_actions_addchdir(file_actions, path));
}

int
posix_spawn_file_actions_addfchdir(
    posix_spawn_file_actions_t *restrict file_actions, int fd)
{
	file_attr_t *fap;

	if (fd < 0)
		return (EBADF);
	if ((fap = lmalloc(sizeof (*fap))) == NULL)
		return (ENOMEM);
	fap->fa_type = FA_FCHDIR;
	fap->fa_filedes = fd;
	add_file_attr(file_actions, fap);
	return (0);
}

int
posix_spawn_file_actions_addfchdir_np(
    posix_spawn_file_actions_t *restrict file_actions, int fd)
{
	return (posix_spawn_file_actions_addfchdir(file_actions, fd));
}

int
posix_spawnattr_init(posix_spawnattr_t *attr)
{
	if ((attr->__spawn_attrp = lmalloc(sizeof (posix_spawnattr_t))) == NULL)
		return (ENOMEM);
	/*
	 * Add default stuff here?
	 */
	return (0);
}

int
posix_spawnattr_destroy(posix_spawnattr_t *attr)
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
posix_spawnattr_setflags(posix_spawnattr_t *attr, short flags)
{
	spawn_attr_t *sap = attr->__spawn_attrp;

	if (sap == NULL ||
	    (flags & ~ALL_POSIX_SPAWN_FLAGS))
		return (EINVAL);

	sap->sa_psflags = flags;
	return (0);
}

int
posix_spawnattr_getflags(const posix_spawnattr_t *attr, short *flags)
{
	spawn_attr_t *sap = attr->__spawn_attrp;

	if (sap == NULL)
		return (EINVAL);

	*flags = sap->sa_psflags;
	return (0);
}

int
posix_spawnattr_setpgroup(posix_spawnattr_t *attr, pid_t pgroup)
{
	spawn_attr_t *sap = attr->__spawn_attrp;

	if (sap == NULL)
		return (EINVAL);

	sap->sa_pgroup = pgroup;
	return (0);
}

int
posix_spawnattr_getpgroup(const posix_spawnattr_t *attr, pid_t *pgroup)
{
	spawn_attr_t *sap = attr->__spawn_attrp;

	if (sap == NULL)
		return (EINVAL);

	*pgroup = sap->sa_pgroup;
	return (0);
}

int
posix_spawnattr_setschedparam(posix_spawnattr_t *attr,
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
posix_spawnattr_getschedparam(const posix_spawnattr_t *attr,
    struct sched_param *schedparam)
{
	spawn_attr_t *sap = attr->__spawn_attrp;

	if (sap == NULL)
		return (EINVAL);

	schedparam->sched_priority = sap->sa_priority;
	return (0);
}

int
posix_spawnattr_setschedpolicy(posix_spawnattr_t *attr, int schedpolicy)
{
	spawn_attr_t *sap = attr->__spawn_attrp;

	if (sap == NULL || schedpolicy == SCHED_SYS)
		return (EINVAL);

	/*
	 * Cache the policy information for later use by posix_spawn().
	 */
	if (get_info_by_policy(schedpolicy) == NULL)
		return (errno);

	sap->sa_schedpolicy = schedpolicy;
	return (0);
}

int
posix_spawnattr_getschedpolicy(const posix_spawnattr_t *attr, int *schedpolicy)
{
	spawn_attr_t *sap = attr->__spawn_attrp;

	if (sap == NULL)
		return (EINVAL);

	*schedpolicy = sap->sa_schedpolicy;
	return (0);
}

int
posix_spawnattr_setsigdefault(posix_spawnattr_t *attr,
    const sigset_t *sigdefault)
{
	spawn_attr_t *sap = attr->__spawn_attrp;

	if (sap == NULL)
		return (EINVAL);

	sap->sa_sigdefault = *sigdefault;
	return (0);
}

int
posix_spawnattr_getsigdefault(const posix_spawnattr_t *attr,
    sigset_t *sigdefault)
{
	spawn_attr_t *sap = attr->__spawn_attrp;

	if (sap == NULL)
		return (EINVAL);

	*sigdefault = sap->sa_sigdefault;
	return (0);
}

int
posix_spawnattr_setsigignore_np(posix_spawnattr_t *attr,
    const sigset_t *sigignore)
{
	spawn_attr_t *sap = attr->__spawn_attrp;

	if (sap == NULL)
		return (EINVAL);

	sap->sa_sigignore = *sigignore;
	return (0);
}

int
posix_spawnattr_getsigignore_np(const posix_spawnattr_t *attr,
    sigset_t *sigignore)
{
	spawn_attr_t *sap = attr->__spawn_attrp;

	if (sap == NULL)
		return (EINVAL);

	*sigignore = sap->sa_sigignore;
	return (0);
}

int
posix_spawnattr_setsigmask(posix_spawnattr_t *attr,
    const sigset_t *sigmask)
{
	spawn_attr_t *sap = attr->__spawn_attrp;

	if (sap == NULL)
		return (EINVAL);

	sap->sa_sigmask = *sigmask;
	return (0);
}

int
posix_spawnattr_getsigmask(const posix_spawnattr_t *attr,
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
