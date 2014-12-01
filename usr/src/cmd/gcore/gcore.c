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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <limits.h>
#include <libproc.h>
#include <sys/corectl.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <zone.h>

static char *pname;

static void
convert_path(const char *path, char *fname, size_t size,
    struct ps_prochandle *P)
{
	char *p, *s;
	ssize_t len;
	const psinfo_t *pip = Ppsinfo(P);
	int got_uts = 0;
	struct utsname uts;
	char exec[PATH_MAX];

	fname[size - 1] = '\0';
	size--;

	while ((p = strchr(path, '%')) != NULL && size != 0) {
		len = MIN(size, p - path);
		bcopy(path, fname, len);

		fname += len;
		if ((size -= len) == 0)
			break;

		p++;
		switch (*p) {
		case 'p':
			len = snprintf(fname, size, "%d", (int)pip->pr_pid);
			break;
		case 'u':
			len = snprintf(fname, size, "%d", (int)pip->pr_uid);
			break;
		case 'g':
			len = snprintf(fname, size, "%d", (int)pip->pr_gid);
			break;
		case 'f':
			len = snprintf(fname, size, "%s", pip->pr_fname);
			break;
		case 'd':
			len = 0;
			if (Pexecname(P, exec, sizeof (exec)) == NULL ||
			    exec[0] != '/' || (s = strrchr(exec, '/')) == NULL)
				break;

			*s = '\0';
			len = snprintf(fname, size, "%s", &exec[1]);
			break;
		case 'n':
			if (got_uts++ == 0)
				(void) uname(&uts);
			len = snprintf(fname, size, "%s", uts.nodename);
			break;
		case 'm':
			if (got_uts++ == 0)
				(void) uname(&uts);
			len = snprintf(fname, size, "%s", uts.machine);
			break;
		case 't':
			len = snprintf(fname, size, "%ld", (long)time(NULL));
			break;
		case 'z':
			/*
			 * getzonenamebyid() returns the size including the
			 * terminating null byte so we need to adjust len.
			 */
			if ((len = getzonenamebyid(pip->pr_zoneid, fname,
			    size)) < 0)
				len = snprintf(fname, size, "%d",
				    (int)pip->pr_zoneid);
			else
				len--;
			break;
		case '%':
			*fname = '%';
			len = 1;
			break;
		default:
			len = snprintf(fname, size, "%%%c", *p);
		}

		if (len >= size)
			return;

		fname += len;
		size -= len;

		path = p + 1;
	}

	(void) strncpy(fname, path, size);
}

static void
gcore(struct ps_prochandle *P, const char *fname, core_content_t content,
    int *errp)
{
	if (Pgcore(P, fname, content) == 0) {
		(void) printf("%s: %s dumped\n", pname, fname);
	} else {
		(void) fprintf(stderr, "%s: %s dump failed: %s\n", pname,
		    fname, errno == EBADE ? "unexpected short write" :
		    strerror(errno));
		(*errp)++;
	}
}

int
main(int argc, char **argv)
{
	struct ps_prochandle *P;
	int gerr;
	char *prefix = NULL;
	int opt;
	int opt_p = 0, opt_g = 0, opt_c = 0;
	int oflags = 0;
	int i;
	char fname[MAXPATHLEN];
	char path[MAXPATHLEN];
	int err = 0;
	core_content_t content = CC_CONTENT_DEFAULT;
	struct rlimit rlim;

	if ((pname = strrchr(argv[0], '/')) == NULL)
		pname = argv[0];
	else
		argv[0] = ++pname;		/* for getopt() */

	while ((opt = getopt(argc, argv, "o:Fgpc:")) != EOF) {
		switch (opt) {
		case 'o':
			prefix = optarg;
			break;
		case 'c':
			if (proc_str2content(optarg, &content) != 0) {
				(void) fprintf(stderr, "%s: invalid "
				    "content string '%s'\n", pname, optarg);
				goto usage;
			}
			opt_c = 1;
			break;
		case 'F':
			oflags |= PGRAB_FORCE;
			break;
		case 'p':
			opt_p = 1;
			break;
		case 'g':
			opt_g = 1;
			break;
		default:
			goto usage;
		}
	}

	if ((opt_p | opt_g) == 0) {
		if (prefix == NULL)
			prefix = "core";
	} else {
		int options;

		if ((options = core_get_options()) == -1) {
			perror("core_get_options()");
			return (1);
		}

		if (opt_p && !(options & CC_PROCESS_PATH)) {
			(void) fprintf(stderr, "%s: per-process core dumps "
			    "are disabled (ignoring -p)\n", pname);
			opt_p = 0;
		}

		if (opt_g && !(options & CC_GLOBAL_PATH)) {
			(void) fprintf(stderr, "%s: global core dumps "
			    "are disabled (ignoring -g)\n", pname);
			opt_g = 0;
		}

		if ((opt_p | opt_g) == 0 && prefix == NULL)
			return (1);
	}

	argc -= optind;
	argv += optind;

	if (argc == 0)
		goto usage;

	/*
	 * Make sure we'll have enough file descriptors to handle a target
	 * that has many many mappings.
	 */
	if (getrlimit(RLIMIT_NOFILE, &rlim) == 0) {
		rlim.rlim_cur = rlim.rlim_max;
		(void) setrlimit(RLIMIT_NOFILE, &rlim);
		(void) enable_extended_FILE_stdio(-1, -1);
	}

	for (i = 0; i < argc; i++) {
		P = proc_arg_grab(argv[i], PR_ARG_PIDS, oflags, &gerr);
		if (P == NULL) {
			(void) fprintf(stderr, "%s: cannot grab %s: %s\n",
			    pname, argv[i], Pgrab_error(gerr));
			err++;
			continue;
		}

		if (prefix != NULL) {
			(void) snprintf(path, sizeof (path), "%s.%%p", prefix);
			convert_path(path, fname, sizeof (fname), P);

			gcore(P, fname, content, &err);
		}

		if (opt_p) {
			pid_t pid = Pstatus(P)->pr_pid;
			(void) core_get_process_path(path, sizeof (path), pid);
			convert_path(path, fname, sizeof (fname), P);
			if (!opt_c)
				(void) core_get_process_content(&content, pid);

			gcore(P, fname, content, &err);
		}

		if (opt_g) {
			/*
			 * Global core files are always just readable and
			 * writable by their owner so we temporarily change
			 * the umask.
			 */
			mode_t oldmode = umask(S_IXUSR | S_IRWXG | S_IRWXO);

			(void) core_get_global_path(path, sizeof (path));
			convert_path(path, fname, sizeof (fname), P);
			if (!opt_c)
				(void) core_get_global_content(&content);

			gcore(P, fname, content, &err);

			(void) umask(oldmode);
		}

		Prelease(P, 0);
	}

	return (err != 0);

usage:
	(void) fprintf(stderr, "usage: %s "
	    "[ -pgF ] [ -o filename ] [ -c content ] pid ...\n", pname);
	return (2);
}
