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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#define	__EXTENSIONS__
#include <string.h>
#undef	__EXTENSIONS__

#include <libgen.h>
#include <limits.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <zone.h>

#include "libproc.h"
#include "Pcontrol.h"

/*
 * Pexecname.c - Way too much code to attempt to derive the full pathname of
 * the executable file from a process handle, be it dead or alive.
 */

/*
 * Once we've computed a cwd and a relative path, we use try_exec() to
 * form an absolute path, call resolvepath() on it, and then let the
 * caller's function do the final confirmation.
 */
static int
try_exec(struct ps_prochandle *P, const char *cwd, const char *path, char *buf,
    int (*isexec)(const char *, void *), void *isdata)
{
	int i;

	if (path[0] != '/')
		(void) snprintf(buf, PATH_MAX, "%s/%s", cwd, path);
	else
		(void) strcpy(buf, path);

	dprintf("try_exec \"%s\"\n", buf);

	(void) Pfindobj(P, buf, buf, PATH_MAX);
	if ((i = resolvepath(buf, buf, PATH_MAX)) > 0) {
		buf[i] = '\0';
		return (isexec(buf, isdata));
	}

	return (0); /* resolvepath failed */
}

/*
 * The Pfindexec function contains the logic for the executable name dance.
 * The caller provides a possible executable name or likely directory (the
 * aout parameter), and a function which is responsible for doing any
 * final confirmation on the executable pathname once a possible full
 * pathname has been chosen.
 */
char *
Pfindexec(struct ps_prochandle *P, const char *aout,
    int (*isexec)(const char *, void *), void *isdata)
{
	char cwd[PATH_MAX * 2];
	char path[PATH_MAX];
	char buf[PATH_MAX];
	struct stat st;
	uintptr_t addr;
	char *p = path, *q;

	dprintf("Pfindexec '%s'\n", aout);

	if (P->execname)
		return (P->execname); /* Already found */

	errno = 0; /* Set to zero so we can tell if stat() failed */

	/*
	 * First try: use the provided default value, if it is not a directory.
	 * If the aout parameter turns out to be a directory, this is
	 * interpreted as the directory to use as an alternate cwd for
	 * our subsequent attempts to locate the executable.
	 */
	if (aout != NULL && stat(aout, &st) == 0 && !S_ISDIR(st.st_mode)) {
		if (try_exec(P, ".", aout, buf, isexec, isdata))
			goto found;
		else
			aout = ".";

	} else if (aout == NULL || errno != 0)
		aout = ".";

	/*
	 * At this point 'aout' is either "." or an alternate cwd.  We use
	 * realpath(3c) to turn this into a full pathname free of ".", "..",
	 * and symlinks.  If this fails for some reason, fall back to "."
	 */
	if (realpath(aout, cwd) == NULL)
		(void) strcpy(cwd, ".");

	/*
	 * Second try: read the string pointed to by the AT_SUN_EXECNAME
	 * auxv element, saved when the program was exec'd.  If the full
	 * pathname try_exec() forms fails, try again using just the
	 * basename appended to our cwd.  If that also fails, and the process
	 * is in a zone, try again with the zone path instead of our cwd.
	 */
	if ((addr = Pgetauxval(P, AT_SUN_EXECNAME)) != (uintptr_t)-1L &&
	    Pread_string(P, path, sizeof (path), (off_t)addr) > 0) {
		char		zpath[PATH_MAX];
		const psinfo_t	*pi = Ppsinfo(P);

		if (try_exec(P, cwd, path, buf, isexec, isdata))
			goto found;

		if (strchr(path, '/') != NULL && (p = basename(path)) != NULL &&
		    try_exec(P, cwd, p, buf, isexec, isdata))
			goto found;

		if (getzoneid() == GLOBAL_ZONEID &&
		    pi->pr_zoneid != GLOBAL_ZONEID &&
		    zone_getattr(pi->pr_zoneid, ZONE_ATTR_ROOT, zpath,
		    sizeof (zpath)) != -1) {
			/*
			 * try_exec() only combines its cwd and path arguments
			 * if path is relative; but in our case even an absolute
			 * path inside a zone is a relative path from the global
			 * zone perspective. So we turn a non-global zone's
			 * absolute path into a relative path here before
			 * calling try_exec().
			 */
			p = (path[0] == '/') ? path + 1 : path;
			if (try_exec(P, zpath, p, buf, isexec, isdata))
				goto found;
		}
	}

	/*
	 * Third try: try using the first whitespace-separated token
	 * saved in the psinfo_t's pr_psargs (the initial value of argv[0]).
	 */
	if (Ppsinfo(P) != NULL) {
		(void) strncpy(path, P->psinfo.pr_psargs, PRARGSZ);
		path[PRARGSZ] = '\0';

		if ((p = strchr(path, ' ')) != NULL)
			*p = '\0';

		if (try_exec(P, cwd, path, buf, isexec, isdata))
			goto found;

		if (strchr(path, '/') != NULL && (p = basename(path)) != NULL &&
		    try_exec(P, cwd, p, buf, isexec, isdata))
			goto found;
	}

	/*
	 * Fourth try: read the string pointed to by argv[0] out of the
	 * stack in the process's address space.
	 */
	if (P->psinfo.pr_argv != NULL &&
	    Pread(P, &addr, sizeof (addr), P->psinfo.pr_argv) != -1 &&
	    Pread_string(P, path, sizeof (path), (off_t)addr) > 0) {

		if (try_exec(P, cwd, path, buf, isexec, isdata))
			goto found;

		if (strchr(path, '/') != NULL && (p = basename(path)) != NULL &&
		    try_exec(P, cwd, p, buf, isexec, isdata))
			goto found;
	}

	/*
	 * Fifth try: read the process's $PATH environment variable and
	 * search each directory named there for the name matching pr_fname.
	 */
	if (Pgetenv(P, "PATH", cwd, sizeof (cwd)) != NULL) {
		/*
		 * If the name from pr_psargs contains pr_fname as its
		 * leading string, then accept the name from pr_psargs
		 * because more bytes are saved there.  Otherwise use
		 * pr_fname because this gives us new information.
		 */
		(void) strncpy(path, P->psinfo.pr_psargs, PRARGSZ);
		path[PRARGSZ] = '\0';

		if ((p = strchr(path, ' ')) != NULL)
			*p = '\0';

		if (strchr(path, '/') != NULL || strncmp(path,
		    P->psinfo.pr_fname, strlen(P->psinfo.pr_fname)) != 0)
			(void) strcpy(path, P->psinfo.pr_fname);

		/*
		 * Now iterate over the $PATH elements, trying to form
		 * an executable pathname with each one.
		 */
		for (p = strtok_r(cwd, ":", &q); p != NULL;
		    p = strtok_r(NULL, ":", &q)) {

			if (*p != '/')
				continue; /* Ignore anything relative */

			if (try_exec(P, p, path, buf, isexec, isdata))
				goto found;
		}
	}

	errno = ENOENT;
	return (NULL);

found:
	if ((P->execname = strdup(buf)) == NULL)
		dprintf("failed to malloc; executable name is \"%s\"", buf);

	return (P->execname);
}

/*
 * Callback function for Pfindexec().  We return a match if we can stat the
 * suggested pathname and confirm its device and inode number match our
 * previous information about the /proc/<pid>/object/a.out file.
 */
static int
stat_exec(const char *path, struct stat64 *stp)
{
	struct stat64 st;

	return (stat64(path, &st) == 0 && S_ISREG(st.st_mode) &&
	    stp->st_dev == st.st_dev && stp->st_ino == st.st_ino);
}

/*
 * Return the full pathname for the executable file.  If the process handle is
 * a core file, we've already tried our best to get the executable name.
 * Otherwise, we make an attempt using Pfindexec().
 */
char *
Pexecname(struct ps_prochandle *P, char *buf, size_t buflen)
{
	if (P->execname != NULL) {
		(void) strncpy(buf, P->execname, buflen);
		return (buf);
	}

	if (P->state != PS_DEAD && P->state != PS_IDLE) {
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

		(void) Pfindexec(P, ret > 0 ? cwd : NULL,
		    (int (*)(const char *, void *))stat_exec, &st);
	}

	return (NULL);
}
