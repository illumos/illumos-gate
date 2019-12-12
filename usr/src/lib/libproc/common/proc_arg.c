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
 * Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2019 Joyent, Inc.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/proc.h>

#include <libgen.h>
#include <limits.h>
#include <alloca.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <ctype.h>
#include <errno.h>
#include <dirent.h>

#include "Pcontrol.h"

static int
open_psinfo(const char *arg, int *perr)
{
	/*
	 * Allocate enough space for procfs_path + arg + "/psinfo"
	 */
	char *path = alloca(strlen(arg) + strlen(procfs_path) + 9);

	struct stat64 st;
	int fd;

	if (strchr(arg, '/') == NULL) {
		(void) strcpy(path, procfs_path);
		(void) strcat(path, "/");
		(void) strcat(path, arg);
	} else
		(void) strcpy(path, arg);

	(void) strcat(path, "/psinfo");

	/*
	 * Attempt to open the psinfo file, and return the fd if we can
	 * confirm this is a regular file provided by /proc.
	 */
	if ((fd = open64(path, O_RDONLY)) >= 0) {
		if (fstat64(fd, &st) != 0 || !S_ISREG(st.st_mode) ||
		    strcmp(st.st_fstype, "proc") != 0) {
			(void) close(fd);
			fd = -1;
		}
	} else if (errno == EACCES || errno == EPERM)
		*perr = G_PERM;

	return (fd);
}

static int
open_core(const char *arg, int *perr)
{
#ifdef _BIG_ENDIAN
	uchar_t order = ELFDATA2MSB;
#else
	uchar_t order = ELFDATA2LSB;
#endif
	GElf_Ehdr ehdr;
	int fd;
	int is_noelf = -1;

	/*
	 * Attempt to open the core file, and return the fd if we can confirm
	 * this is an ELF file of type ET_CORE.
	 */
	if ((fd = open64(arg, O_RDONLY)) >= 0) {
		if (read(fd, &ehdr, sizeof (ehdr)) != sizeof (ehdr)) {
			(void) close(fd);
			fd = -1;
		} else if ((is_noelf = memcmp(&ehdr.e_ident[EI_MAG0], ELFMAG,
		    SELFMAG)) != 0 || ehdr.e_type != ET_CORE) {
			(void) close(fd);
			fd = -1;
			if (is_noelf == 0 &&
			    ehdr.e_ident[EI_DATA] != order)
				*perr = G_ISAINVAL;
		}
	} else if (errno == EACCES || errno == EPERM)
		*perr = G_PERM;

	return (fd);
}

/*
 * Make the error message precisely match the type of arguments the caller
 * wanted to process.  This ensures that a tool which only accepts pids does
 * not produce an error message saying "no such process or core file 'foo'".
 */
static int
open_error(int oflag)
{
	if ((oflag & PR_ARG_ANY) == PR_ARG_PIDS)
		return (G_NOPROC);

	if ((oflag & PR_ARG_ANY) == PR_ARG_CORES)
		return (G_NOCORE);

	return (G_NOPROCORCORE);
}

static void *
proc_grab_common(const char *arg, const char *path, int oflag, int gflag,
    int *perr, const char **lwps, psinfo_t *psp)
{
	psinfo_t psinfo;
	char *core;
	int fd;
	char *slash;
	struct ps_prochandle *Pr;

	*perr = 0;
	if (lwps)
		*lwps = NULL;

	if (lwps != NULL && (slash = strrchr(arg, '/')) != NULL) {
		/*
		 * Check to see if the user has supplied an lwp range.  First,
		 * try to grab it as a pid/lwp combo.
		 */
		*slash = '\0';
		if ((oflag & PR_ARG_PIDS) &&
		    (fd = open_psinfo(arg, perr)) != -1) {
			if (read(fd, &psinfo,
			    sizeof (psinfo_t)) == sizeof (psinfo_t)) {
				(void) close(fd);
				*lwps = slash + 1;
				*slash = '/';
				if (proc_lwp_range_valid(*lwps) != 0) {
					*perr = G_BADLWPS;
					return (NULL);
				}
				if (psp) {
					*psp = psinfo;
					return (psp);
				} else  {
					return (Pgrab(psinfo.pr_pid, gflag,
					    perr));
				}
			}
			(void) close(fd);
		}

		/*
		 * Next, try grabbing it as a corefile.
		 */
		if ((oflag & PR_ARG_CORES) &&
		    (fd = open_core(arg, perr)) != -1) {
			*lwps = slash + 1;
			*slash = '/';
			if (proc_lwp_range_valid(*lwps) != 0) {
				*perr = G_BADLWPS;
				return (NULL);
			}
			core = strdupa(arg);
			if ((Pr = Pfgrab_core(fd, path == NULL ?
			    dirname(core) : path, perr)) != NULL) {
				if (psp) {
					(void) memcpy(psp, Ppsinfo(Pr),
					    sizeof (psinfo_t));
					Prelease(Pr, 0);
					return (psp);
				} else {
					return (Pr);
				}
			}
		}

		*slash = '/';
	}

	if ((oflag & PR_ARG_PIDS) && (fd = open_psinfo(arg, perr)) != -1) {
		if (read(fd, &psinfo, sizeof (psinfo_t)) == sizeof (psinfo_t)) {
			(void) close(fd);
			if (psp) {
				*psp = psinfo;
				return (psp);
			} else {
				return (Pgrab(psinfo.pr_pid, gflag, perr));
			}
		}
		/*
		 * If the read failed, the process may have gone away;
		 * we continue checking for core files or fail with G_NOPROC
		 */
		(void) close(fd);
	}

	if ((oflag & PR_ARG_CORES) && (fd = open_core(arg, perr)) != -1) {
		core = strdupa(arg);
		if ((Pr = Pfgrab_core(fd, path == NULL ? dirname(core) : path,
		    perr)) != NULL) {
			if (psp) {
				(void) memcpy(psp, Ppsinfo(Pr),
				    sizeof (psinfo_t));
				Prelease(Pr, 0);
				return (psp);
			} else {
				return (Pr);
			}
		}
	}

	/*
	 * We were unable to open the corefile.  If we have no meaningful
	 * information, report the (ambiguous) error from open_error().
	 */

	if (*perr == 0)
		*perr = open_error(oflag);

	return (NULL);
}

struct ps_prochandle *
proc_arg_xgrab(const char *arg, const char *path, int oflag, int gflag,
    int *perr, const char **lwps)
{
	return (proc_grab_common(arg, path, oflag, gflag, perr, lwps, NULL));
}

struct ps_prochandle *
proc_arg_grab(const char *arg, int oflag, int gflag, int *perr)
{
	return (proc_grab_common(arg, NULL, oflag, gflag, perr, NULL, NULL));
}

pid_t
proc_arg_psinfo(const char *arg, int oflag, psinfo_t *psp, int *perr)
{
	psinfo_t psinfo;

	if (psp == NULL)
		psp = &psinfo;

	if (proc_grab_common(arg, NULL, oflag, 0, perr, NULL, psp) == NULL)
		return (-1);
	else
		return (psp->pr_pid);
}

pid_t
proc_arg_xpsinfo(const char *arg, int oflag, psinfo_t *psp, int *perr,
    const char **lwps)
{
	psinfo_t psinfo;

	if (psp == NULL)
		psp = &psinfo;

	if (proc_grab_common(arg, NULL, oflag, 0, perr, lwps, psp) == NULL)
		return (-1);
	else
		return (psp->pr_pid);
}

/*
 * Convert psinfo_t.pr_psargs string into itself, replacing unprintable
 * characters with space along the way.  Stop on a null character.
 */
void
proc_unctrl_psinfo(psinfo_t *psp)
{
	char *s = &psp->pr_psargs[0];
	size_t n = PRARGSZ;
	int c;

	while (n-- != 0 && (c = (*s & UCHAR_MAX)) != '\0') {
		if (!isprint(c))
			c = ' ';
		*s++ = (char)c;
	}

	*s = '\0';
}

static int
proc_lwp_get_range(char *range, id_t *low, id_t *high)
{
	if (*range == '-')
		*low = 0;
	else
		*low = (id_t)strtol(range, &range, 10);

	if (*range == '\0' || *range == ',') {
		*high = *low;
		return (0);
	}
	if (*range != '-') {
		return (-1);
	}
	range++;

	if (*range == '\0')
		*high = INT_MAX;
	else
		*high = (id_t)strtol(range, &range, 10);

	if (*range != '\0' && *range != ',') {
		return (-1);
	}

	if (*high < *low) {
		id_t tmp = *high;
		*high = *low;
		*low = tmp;
	}

	return (0);
}

/*
 * Determine if the specified lwpid is in the given set of lwpids.
 * The set can include multiple lwpid ranges separated by commas
 * and has the following syntax:
 *
 *	lwp_range[,lwp_range]*
 *
 * where lwp_range is specifed as:
 *
 *	-n			lwpid <= n
 *	n-m			n <= lwpid <= m
 *	n-			lwpid >= n
 *	n			lwpid == n
 */
int
proc_lwp_in_set(const char *set, lwpid_t lwpid)
{
	id_t low, high;
	id_t id = (id_t)lwpid;
	char *comma;
	char *range = (char *)set;

	/*
	 * A NULL set indicates that all LWPs are valid.
	 */
	if (set == NULL)
		return (1);

	while (range != NULL) {
		comma = strchr(range, ',');
		if (comma != NULL)
			*comma = '\0';
		if (proc_lwp_get_range(range, &low, &high) != 0) {
			if (comma != NULL)
				*comma = ',';
			return (0);
		}
		if (comma != NULL) {
			*comma = ',';
			range = comma + 1;
		} else {
			range = NULL;
		}
		if (id >= low && id <= high)
			return (1);
	}

	return (0);
}

int
proc_lwp_range_valid(const char *set)
{
	char *comma;
	char *range = (char *)set;
	id_t low, high;
	int ret;

	if (range == NULL || *range == '\0' || *range == ',')
		return (-1);

	while (range != NULL) {
		comma = strchr(range, ',');
		if (comma != NULL)
			*comma = '\0';
		if ((ret = proc_lwp_get_range(range, &low, &high)) != 0) {
			if (comma != NULL)
				*comma = ',';
			return (ret);
		}
		if (comma != NULL) {
			*comma = ',';
			range = comma + 1;
		} else {
			range = NULL;
		}
	}

	return (0);
}

/*
 * Walk all processes or LWPs in /proc and call func() for each.
 * Omit system processes (like process-IDs 0, 2, and 3).
 * Stop calling func() if it returns non 0 value and return it.
 */
int
proc_walk(proc_walk_f *func, void *arg, int flag)
{
	DIR *procdir;
	struct dirent *dirent;
	char *errptr;
	char pidstr[PATH_MAX];
	psinfo_t psinfo;
	lwpsinfo_t *lwpsinfo;
	prheader_t prheader;
	void *buf;
	char *ptr;
	int bufsz;
	id_t pid;
	int fd, i;
	int ret = 0;
	boolean_t walk_sys = B_FALSE;

	if ((flag & PR_WALK_INCLUDE_SYS) != 0)
		walk_sys = B_TRUE;
	flag &= ~PR_WALK_INCLUDE_SYS;

	if (flag != PR_WALK_PROC && flag != PR_WALK_LWP) {
		errno = EINVAL;
		return (-1);
	}
	if ((procdir = opendir(procfs_path)) == NULL)
		return (-1);
	while (dirent = readdir(procdir)) {
		if (dirent->d_name[0] == '.')	/* skip . and .. */
			continue;
		pid = (id_t)strtol(dirent->d_name, &errptr, 10);
		if (errptr != NULL && *errptr != '\0')
			continue;
		/* PR_WALK_PROC case */
		(void) snprintf(pidstr, sizeof (pidstr),
		    "%s/%ld/psinfo", procfs_path, pid);
		fd = open(pidstr, O_RDONLY);
		if (fd < 0)
			continue;
		if (read(fd, &psinfo, sizeof (psinfo)) != sizeof (psinfo) ||
		    ((psinfo.pr_flag & SSYS) != 0 && !walk_sys)) {
			(void) close(fd);
			continue;
		}
		(void) close(fd);
		if (flag == PR_WALK_PROC) {
			if ((ret = func(&psinfo, &psinfo.pr_lwp, arg)) != 0)
				break;
			continue;
		}
		/* PR_WALK_LWP case */
		(void) snprintf(pidstr, sizeof (pidstr),
		    "%s/%ld/lpsinfo", procfs_path, pid);
		fd = open(pidstr, O_RDONLY);
		if (fd < 0)
			continue;
		if (read(fd, &prheader, sizeof (prheader)) !=
		    sizeof (prheader)) {
			(void) close(fd);
			continue;
		}
		bufsz = prheader.pr_nent * prheader.pr_entsize;
		if ((buf = malloc(bufsz)) == NULL) {
			(void) close(fd);
			ret = -1;
			break;
		}
		ptr = buf;
		if (pread(fd, buf, bufsz, sizeof (prheader)) != bufsz) {
			free(buf);
			(void) close(fd);
			continue;
		}
		(void) close(fd);
		for (i = 0; i < prheader.pr_nent;
		    i++, ptr += prheader.pr_entsize) {
			/*LINTED ALIGNMENT*/
			lwpsinfo = (lwpsinfo_t *)ptr;
			if ((ret = func(&psinfo, lwpsinfo, arg)) != 0) {
				free(buf);
				break;
			}
		}
		free(buf);
	}
	(void) closedir(procdir);
	return (ret);
}
