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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *	plabel - gets process label.
 */
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <locale.h>
#include <procfs.h>
#include <sys/proc.h>
#include <zone.h>

#include <sys/tsol/label_macro.h>

#include <tsol/label.h>

#define	s_flag	0x04
#define	S_flag	0x08

#define	INIT_ALLOC_LEN	1024
#define	MAX_ALLOC_NUM	11

static int look(char *);
static int perr(char *);
static void usage(void);

static char procname[64];

static unsigned int opt_flag = 0;
static char *cmd = NULL;

int
main(int argc, char **argv)
{
	int err, rc = 0;
	int opt;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN	"SYS_TEST"	/* Use this only if it weren't */
#endif
	(void) textdomain(TEXT_DOMAIN);

	if ((cmd = strrchr(argv[0], '/')) == NULL)
		cmd = argv[0];
	else
		cmd++;

	/* Error if labeling is not active. */
	if (!is_system_labeled()) {
		(void) fprintf(stderr,
		    gettext("%s: Trusted Extensions must be enabled\n"), cmd);
		return (1);
	}

	while ((opt = getopt(argc, argv, "sS")) != EOF) {
		switch (opt) {
		case 's':
			if (opt_flag & (s_flag | S_flag)) {
				usage();
				return (1);
			}
			opt_flag |= s_flag;
			break;

		case 'S':
			if (opt_flag & (s_flag | S_flag)) {
				usage();
				return (1);
			}
			opt_flag |= S_flag;
			break;
		default:
			usage();
			return (1);
		}
	}

	argc -= optind;
	argv += optind;
	if (argc == 0) {
		char pid[11]; /* 32 bit pids go to 4294967295 plus a NUL */

		(void) sprintf(pid, "%d", (int)getpid());
		rc = look(pid);
	} else {
		while (argc-- > 0) {
			err = look(*argv++);
			if (rc == 0)
				rc = err;
		}
	}
	return (rc);
}

static int
look(char *arg)
{
	int fd;
	m_label_t *plabel;
	psinfo_t info;		/* process information from /proc */
	char *str;
	int wordlen = DEF_NAMES;

	if (opt_flag == S_flag)
		wordlen = LONG_NAMES;
	else if (opt_flag == s_flag)
		wordlen = SHORT_NAMES;

	if (strchr(arg, '/') != NULL)
		(void) strncpy(procname, arg, sizeof (procname));
	else {
		(void) strcpy(procname, "/proc/");
		(void) strncat(procname, arg,
		    sizeof (procname) - strlen(procname));
	}
	(void) strlcat(procname, "/psinfo", sizeof (procname)
	    - strlen(procname));

	/*
	 * Open the process to be examined.
	 */
retry:
	if ((fd = open(procname, O_RDONLY)) < 0) {
		/*
		 * Make clean message for non-existent process.
		 */
		if (errno == ENOENT) {
			errno = ESRCH;
			perror(arg);
			return (1);
		}
		return (perr(NULL));
	}


	/*
	 * Get the info structure for the process and close quickly.
	 */
	if (read(fd, &info, sizeof (info)) < 0) {
		int	saverr = errno;

		(void) close(fd);
		if (saverr == EAGAIN)
			goto retry;
		if (saverr != ENOENT)
			perror(arg);
		return (1);
	}
	(void) close(fd);

	if (info.pr_lwp.pr_state == 0)  /* can't happen? */
		return (1);

	if ((plabel = getzonelabelbyid(info.pr_zoneid)) == NULL) {
		return (1);
	}

	/*
	 * The process label for global zone is admin_high
	 */
	if (info.pr_zoneid == GLOBAL_ZONEID) {
		_BSLHIGH(plabel);
	}

	if (label_to_str(plabel, &str, M_LABEL, wordlen) != 0) {
		perror(arg);
		return (2);
	}
	(void) printf("%s\n", str);
	m_label_free(plabel);
	free(str);
	return (0);
}


/*
 * usage()
 *
 * This routine is called whenever there is a usage type of error has
 * occured.  For example, when a invalid option has has been specified.
 *
 */
static void
usage(void)
{

	(void) fprintf(stderr, "Usage: \n");
	(void) fprintf(stderr,
	    gettext("	%s [pid ...]    \n"), cmd);
	(void) fprintf(stderr,
	    gettext("	%s -s  [pid ...] \n"), cmd);
	(void) fprintf(stderr,
	    gettext("	%s -S  [pid ...] \n"), cmd);
}

static int
perr(char *s) {

	if (s)
		(void) fprintf(stderr, "%s: ", procname);
	else
		s = procname;
	perror(s);
	return (1);
}
