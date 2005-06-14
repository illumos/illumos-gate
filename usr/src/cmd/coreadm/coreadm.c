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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <fcntl.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <libintl.h>
#include <locale.h>
#include <sys/stat.h>
#include <sys/corectl.h>
#include <libproc.h>

#define	E_SUCCESS	0		/* Exit status for success */
#define	E_ERROR		1		/* Exit status for error */
#define	E_USAGE		2		/* Exit status for usage error */

static	const	char	PATH_CONFIG[] = "/etc/coreadm.conf";
#define	CF_OWNER	0				/* Uid 0 (root) */
#define	CF_GROUP	1				/* Gid 1 (other) */
#define	CF_PERM	(S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)	/* Mode 0644 */

static	char		*command;
static	char		*glob_pattern;
static	size_t		glob_size;
static	core_content_t	glob_content = CC_CONTENT_INVALID;
static	char		*init_pattern;
static	size_t		init_size;
static	core_content_t	init_content = CC_CONTENT_INVALID;
static	char		*proc_pattern;
static	size_t		proc_size;
static	core_content_t	proc_content = CC_CONTENT_INVALID;
static	int		enable;
static	int		disable;

static	int		report_settings(void);
static	int		do_processes(int, char **);
static	int		do_modify(void);
static	int		do_update(void);
static	int		write_config(int);

static void
usage(void)
{
	(void) fprintf(stderr, gettext(
"usage:\n"));
	(void) fprintf(stderr, gettext(
"    %s [ -g pattern ] [ -i pattern ] [ -G content ] [ -I content ]\n"),
		command);
	(void) fprintf(stderr, gettext(
"            [ -e {global | process | global-setid | proc-setid | log} ]\n"));
	(void) fprintf(stderr, gettext(
"            [ -d {global | process | global-setid | proc-setid | log} ]\n"));
	(void) fprintf(stderr, gettext(
"    %s [ -p pattern ] [ -P content ] [ pid ... ]\n"), command);
	(void) fprintf(stderr, gettext(
"    %s -u\n"), command);
	exit(E_USAGE);
}

static int
perm(void)
{
	(void) fprintf(stderr, gettext("%s: insufficient privileges to "
	    "exercise the -[GIgiedu] options\n"), command);
	return (E_USAGE);
}

int
main(int argc, char **argv)
{
	int flag;
	int opt;
	int modify;
	int update = 0;
	int error = 0;
	int npids;
	char **pidlist;

	char curpid[11];
	char *curpid_ptr = &curpid[0];

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	/* command name (e.g., "coreadm") */
	if ((command = strrchr(argv[0], '/')) != NULL)
		command++;
	else
		command = argv[0];

	while ((opt = getopt(argc, argv, "g:G:i:I:p:P:e:d:u?")) != EOF) {
		switch (opt) {
		case 'g':
			glob_pattern = optarg;
			glob_size = strlen(glob_pattern) + 1;
			break;
		case 'i':
			init_pattern = optarg;
			init_size = strlen(init_pattern) + 1;
			break;
		case 'p':
			proc_pattern = optarg;
			proc_size = strlen(proc_pattern) + 1;
			break;
		case 'G':
			if (proc_str2content(optarg, &glob_content) != 0) {
				(void) fprintf(stderr, gettext("invalid "
				    "content string '%s'\n"), optarg);
				error = 1;
			}
			break;
		case 'I':
			if (proc_str2content(optarg, &init_content) != 0) {
				(void) fprintf(stderr, gettext("invalid "
				    "content string '%s'\n"), optarg);
				error = 1;
			}
			break;
		case 'P':
			if (proc_str2content(optarg, &proc_content) != 0) {
				(void) fprintf(stderr, gettext("invalid "
				    "content string '%s'\n"), optarg);
				error = 1;
			}
			break;
		case 'e':
		case 'd':
			if (strcmp(optarg, "global") == 0)
				flag = CC_GLOBAL_PATH;
			else if (strcmp(optarg, "process") == 0)
				flag = CC_PROCESS_PATH;
			else if (strcmp(optarg, "global-setid") == 0)
				flag = CC_GLOBAL_SETID;
			else if (strcmp(optarg, "proc-setid") == 0)
				flag = CC_PROCESS_SETID;
			else if (strcmp(optarg, "log") == 0)
				flag = CC_GLOBAL_LOG;
			else {
				flag = 0;
				error = 1;
			}
			if (opt == 'e') {
				enable |= flag;
				disable &= ~flag;
			} else {
				disable |= flag;
				enable &= ~flag;
			}
			break;
		case 'u':
			update = 1;
			break;
		case '?':
		default:
			error = 1;
			break;
		}
	}

	npids = argc - optind;
	pidlist = argv + optind;

	if (error)
		usage();

	/*
	 * If 'modify' is true, we must modify the system settings
	 * and update the configuration file with the new parameters.
	 */
	modify = glob_pattern != NULL || glob_content != CC_CONTENT_INVALID ||
		init_pattern != NULL || init_content != CC_CONTENT_INVALID ||
		(enable | disable) != 0;

	if (update && (modify || proc_pattern != NULL ||
	    proc_content != CC_CONTENT_INVALID || npids != 0)) {
		(void) fprintf(stderr,
		    gettext(
		    "%s: the -u option must stand alone\n"),
		    command);
		usage();
	}
	if (modify &&
	    (proc_pattern != NULL || proc_content != CC_CONTENT_INVALID)) {
		(void) fprintf(stderr,
		    gettext(
		    "%s: -[GIgied] and -[Pp] options are mutually exclusive\n"),
		    command);
		usage();
	}
	if (modify && npids != 0) {
		(void) fprintf(stderr,
		    gettext(
		    "%s: -[GIgied] options cannot have a process-id list\n"),
		    command);
		usage();
	}
	if ((proc_pattern != NULL || proc_content != CC_CONTENT_INVALID) &&
	    npids == 0) {
		(void) sprintf(curpid, "%u", (uint_t)getppid());
		npids = 1;
		pidlist = &curpid_ptr;
	}

	if (update)
		return (do_update());
	if (modify)
		return (do_modify());
	if (npids != 0)
		return (do_processes(npids, pidlist));

	return (report_settings());
}

static int
report_settings(void)
{
	int options;
	char global_path[PATH_MAX];
	char init_path[PATH_MAX];
	core_content_t gcontent, icontent;
	char content_str[80];

	if ((options = core_get_options()) == -1) {
		perror("core_get_options()");
		return (E_ERROR);
	}
	if (core_get_global_path(global_path, sizeof (global_path)) != 0) {
		perror("core_get_global_path()");
		return (E_ERROR);
	}
	if (core_get_default_path(init_path, sizeof (init_path)) != 0) {
		perror("core_get_default_path()");
		return (E_ERROR);
	}
	if (core_get_global_content(&gcontent) != 0) {
		perror("core_get_global_content()");
		return (E_ERROR);
	}
	if (core_get_default_content(&icontent) != 0) {
		perror("core_get_default_content()");
		return (E_ERROR);
	}
	(void) printf(gettext("     global core file pattern: %s\n"),
	    global_path);
	(void) proc_content2str(gcontent, content_str, sizeof (content_str));
	(void) printf(gettext("     global core file content: %s\n"),
	    content_str);
	(void) printf(gettext("       init core file pattern: %s\n"),
	    init_path);
	(void) proc_content2str(icontent, content_str, sizeof (content_str));
	(void) printf(gettext("       init core file content: %s\n"),
	    content_str);
	(void) printf(gettext("            global core dumps: %s\n"),
	    (options & CC_GLOBAL_PATH)? "enabled" : "disabled");
	(void) printf(gettext("       per-process core dumps: %s\n"),
	    (options & CC_PROCESS_PATH)? "enabled" : "disabled");
	(void) printf(gettext("      global setid core dumps: %s\n"),
	    (options & CC_GLOBAL_SETID)? "enabled" : "disabled");
	(void) printf(gettext(" per-process setid core dumps: %s\n"),
	    (options & CC_PROCESS_SETID)? "enabled" : "disabled");
	(void) printf(gettext("     global core dump logging: %s\n"),
	    (options & CC_GLOBAL_LOG)? "enabled" : "disabled");
	return (E_SUCCESS);
}

static int
do_processes(int npids, char **pidlist)
{
	char process_path[PATH_MAX];
	core_content_t content;
	pid_t pid;
	char *next;
	int rc = E_SUCCESS;
	char content_str[80];

	if (proc_pattern == NULL && proc_content == CC_CONTENT_INVALID) {
		while (npids-- > 0) {
			pid = strtol(*pidlist, &next, 10);
			if (*next != '\0' || !isdigit(**pidlist)) {
				(void) fprintf(stderr,
				    gettext("%s: invalid process-id\n"),
				    *pidlist);
				rc = E_USAGE;
			} else if (core_get_process_path(process_path,
			    sizeof (process_path), pid) != 0 ||
			    core_get_process_content(&content, pid) != 0) {
				perror(*pidlist);
				rc = E_USAGE;
			} else {
				(void) proc_content2str(content, content_str,
				    sizeof (content_str));
				(void) printf(gettext("%s:\t%s\t%s\n"),
				    *pidlist, process_path, content_str);
			}
			pidlist++;
		}
	} else {
		while (npids-- > 0) {
			pid = strtol(*pidlist, &next, 10);
			if (*next != '\0') {
				(void) fprintf(stderr,
				    gettext("%s: invalid process-id\n"),
				    *pidlist);
				rc = E_USAGE;
			} else {
				if (proc_pattern != NULL &&
				    core_set_process_path(proc_pattern,
				    proc_size, pid) != 0) {
					perror(*pidlist);
					rc = E_USAGE;
				}

				if (proc_content != CC_CONTENT_INVALID &&
				    core_set_process_content(
				    &proc_content, pid) != 0) {
					perror(*pidlist);
					rc = E_USAGE;
				}
			}
			pidlist++;
		}
	}

	return (rc);
}

static int
do_modify(void)
{
	int options;

	if ((options = core_get_options()) == -1) {
		perror("core_get_options()");
		return (E_ERROR);
	}
	options |= enable;
	options &= ~disable;
	if (core_set_options(options) != 0) {
		if (errno == EPERM)
			return (perm());
		perror("core_set_options()");
		return (E_ERROR);
	}
	if (glob_pattern != NULL &&
	    core_set_global_path(glob_pattern, glob_size) != 0) {
		if (errno == EPERM)
			return (perm());
		perror("core_set_global_path()");
		return (E_ERROR);
	}
	if (glob_content != CC_CONTENT_INVALID &&
	    core_set_global_content(&glob_content) != 0) {
		if (errno == EPERM)
			return (perm());
		perror("core_set_global_content()");
		return (E_ERROR);
	}
	if (init_pattern != NULL &&
	    core_set_default_path(init_pattern, init_size) != 0) {
		if (errno == EPERM)
			return (perm());
		perror("core_set_default_path()");
		return (E_ERROR);
	}
	if (init_content != CC_CONTENT_INVALID &&
	    core_set_default_content(&init_content) != 0) {
		if (errno == EPERM)
			return (perm());
		perror("core_set_default_content()");
		return (E_ERROR);
	}
	return (write_config(0));
}

/*
 * BUFSIZE must be large enough to contain the longest path plus some more.
 */
#define	BUFSIZE	(PATH_MAX + 80)

static int
yes(char *name, char *value, int line)
{
	if (strcmp(value, "yes") == 0)
		return (1);
	if (strcmp(value, "no") == 0)
		return (0);
	(void) fprintf(stderr,
		gettext(
		"\"%s\", line %d: warning: value must be yes or no: %s=%s\n"),
		PATH_CONFIG, line, name, value);
	return (0);
}

static int
do_update(void)
{
	FILE *fp;
	int line;
	int options;
	char gpattern[PATH_MAX];
	char ipattern[PATH_MAX];
	core_content_t gcontent, icontent;
	char buf[BUFSIZE];
	char name[BUFSIZE], value[BUFSIZE];
	int n;
	int len;

	/* defaults */
	options = CC_PROCESS_PATH;
	gpattern[0] = '\0';
	(void) strcpy(ipattern, "core");
	gcontent = icontent = CC_CONTENT_DEFAULT;

	if ((fp = fopen(PATH_CONFIG, "r")) == NULL) {
		/*
		 * No config file, just accept the current settings.
		 */
		return (write_config(1));
	}

	for (line = 1; fgets(buf, sizeof (buf), fp) != NULL; line++) {
		/*
		 * Skip comment lines and empty lines.
		 */
		if (buf[0] == '#' || buf[0] == '\n')
			continue;
		/*
		 * Look for "name=value", with optional whitespace on either
		 * side, terminated by a newline, and consuming the whole line.
		 */
		/* LINTED - unbounded string specifier */
		n = sscanf(buf, " %[^=]=%s \n%n", name, value, &len);
		if (n >= 1 && name[0] != '\0' &&
		    (n == 1 || len == strlen(buf))) {
			if (n == 1)
				value[0] = '\0';
			if (strcmp(name, "COREADM_GLOB_PATTERN") == 0) {
				(void) strcpy(gpattern, value);
				continue;
			}
			if (strcmp(name, "COREADM_GLOB_CONTENT") == 0) {
				(void) proc_str2content(value, &gcontent);
				continue;
			}
			if (strcmp(name, "COREADM_INIT_PATTERN") == 0) {
				(void) strcpy(ipattern, value);
				continue;
			}
			if (strcmp(name, "COREADM_INIT_CONTENT") == 0) {
				(void) proc_str2content(value, &icontent);
				continue;
			}
			if (strcmp(name, "COREADM_GLOB_ENABLED") == 0) {
				if (yes(name, value, line))
					options |= CC_GLOBAL_PATH;
				continue;
			}
			if (strcmp(name, "COREADM_PROC_ENABLED") == 0) {
				if (yes(name, value, line))
					options |= CC_PROCESS_PATH;
				else
					options &= ~CC_PROCESS_PATH;
				continue;
			}
			if (strcmp(name, "COREADM_GLOB_SETID_ENABLED") == 0) {
				if (yes(name, value, line))
					options |= CC_GLOBAL_SETID;
				continue;
			}
			if (strcmp(name, "COREADM_PROC_SETID_ENABLED") == 0) {
				if (yes(name, value, line))
					options |= CC_PROCESS_SETID;
				continue;
			}
			if (strcmp(name, "COREADM_GLOB_LOG_ENABLED") == 0) {
				if (yes(name, value, line))
					options |= CC_GLOBAL_LOG;
				continue;
			}
			(void) fprintf(stderr,
				gettext(
			"\"%s\", line %d: warning: invalid token: %s\n"),
				PATH_CONFIG, line, name);
		} else {
			(void) fprintf(stderr,
				gettext("\"%s\", line %d: syntax error\n"),
				PATH_CONFIG, line);
		}
	}
	(void) fclose(fp);
	if (core_set_options(options) != 0) {
		if (errno == EPERM)
			return (perm());
		perror("core_set_options()");
		return (E_ERROR);
	}
	if (core_set_global_path(gpattern, strlen(gpattern) + 1) != 0) {
		if (errno == EPERM)
			return (perm());
		perror("core_set_global_path()");
		return (E_ERROR);
	}
	if (core_set_default_path(ipattern, strlen(ipattern) + 1) != 0) {
		if (errno == EPERM)
			return (perm());
		perror("core_set_default_path()");
		return (E_ERROR);
	}
	if (core_set_global_content(&gcontent) != 0) {
		if (errno == EPERM)
			return (perm());
		perror("core_set_global_content()");
		return (E_ERROR);
	}
	if (core_set_default_content(&icontent) != 0) {
		if (errno == EPERM)
			return (perm());
		perror("core_set_default_content()");
		return (E_ERROR);
	}
	return (write_config(1));
}

static int
write_config(int justtry)
{
	int fd;
	FILE *fp;
	int options;
	char global_path[PATH_MAX];
	char init_path[PATH_MAX];
	core_content_t gcontent, icontent;
	char content_str[PRCONTENTBUFSZ];

	if ((fd = open(PATH_CONFIG, O_WRONLY | O_CREAT | O_TRUNC,
	    CF_PERM)) == -1) {
		/*
		 * If we're updating the kernel settings from the contents
		 * of the config file, it's not essential that we rewrite
		 * that file.
		 */
		if (justtry)
			return (E_SUCCESS);

		if (errno == EACCES) {
			(void) fprintf(stderr, gettext("%s: insufficient "
			    "privileges to update %s\n"), command, PATH_CONFIG);
			return (E_SUCCESS);
		}

		(void) fprintf(stderr, gettext("failed to open %s: %s\n"),
		    PATH_CONFIG, strerror(errno));
		return (E_ERROR);
	}
	if ((options = core_get_options()) == -1) {
		perror("core_get_options()");
		goto err;
	}
	if (core_get_global_path(global_path, sizeof (global_path)) != 0) {
		perror("core_get_global_path()");
		goto err;
	}
	if (core_get_default_path(init_path, sizeof (init_path)) != 0) {
		perror("core_get_default_path()");
		goto err;
	}
	if (core_get_global_content(&gcontent) != 0) {
		perror("core_get_global_content()");
		goto err;
	}
	if (core_get_default_content(&icontent) != 0) {
		perror("core_get_default_content()");
		goto err;
	}
	if ((fp = fdopen(fd, "w")) == NULL) {
		(void) fprintf(stderr,
		    gettext("failed to open stream for %s: %s\n"),
		    PATH_CONFIG, strerror(errno));
		goto err;
	}
	(void) fputs(
		"#\n"
		"# coreadm.conf\n"
		"#\n"
		"# Parameters for system core file configuration.\n"
		"# Do NOT edit this file by hand -- use coreadm(1) instead.\n"
		"#\n",
		fp);

	(void) fprintf(fp, "COREADM_GLOB_PATTERN=%s\n", global_path);
	(void) proc_content2str(gcontent, content_str, sizeof (content_str));
	(void) fprintf(fp, "COREADM_GLOB_CONTENT=%s\n", content_str);
	(void) fprintf(fp, "COREADM_INIT_PATTERN=%s\n", init_path);
	(void) proc_content2str(icontent, content_str, sizeof (content_str));
	(void) fprintf(fp, "COREADM_INIT_CONTENT=%s\n", content_str);

	(void) fprintf(fp, "COREADM_GLOB_ENABLED=%s\n",
		(options & CC_GLOBAL_PATH)? "yes" : "no");
	(void) fprintf(fp, "COREADM_PROC_ENABLED=%s\n",
		(options & CC_PROCESS_PATH)? "yes" : "no");
	(void) fprintf(fp, "COREADM_GLOB_SETID_ENABLED=%s\n",
		(options & CC_GLOBAL_SETID)? "yes" : "no");
	(void) fprintf(fp, "COREADM_PROC_SETID_ENABLED=%s\n",
		(options & CC_PROCESS_SETID)? "yes" : "no");
	(void) fprintf(fp, "COREADM_GLOB_LOG_ENABLED=%s\n",
		(options & CC_GLOBAL_LOG)? "yes" : "no");

	(void) fflush(fp);
	(void) fsync(fd);
	(void) fchmod(fd, CF_PERM);
	(void) fchown(fd, CF_OWNER, CF_GROUP);
	(void) fclose(fp);

	return (0);

err:
	(void) close(fd);
	return (E_ERROR);
}
