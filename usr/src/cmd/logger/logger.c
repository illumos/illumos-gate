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
 * Copyright (c) 2013 Gary Mills
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */


#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <syslog.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <locale.h>
#include <limits.h>
#include <pwd.h>
#include <errno.h>

#define	LOG_MARK	(LOG_NFACILITIES << 3)	/* mark "facility" */
#define	LOGGER_BUFLEN	1024

struct code {
	char	*c_name;
	int	c_val;
};

static struct code	PriNames[] = {
	"panic",	LOG_EMERG,
	"emerg",	LOG_EMERG,
	"alert",	LOG_ALERT,
	"crit",		LOG_CRIT,
	"err",		LOG_ERR,
	"error",	LOG_ERR,
	"warn",		LOG_WARNING,
	"warning", 	LOG_WARNING,
	"notice",	LOG_NOTICE,
	"info",		LOG_INFO,
	"debug",	LOG_DEBUG,
	NULL,		-1
};

static struct code	FacNames[] = {
	"kern",		LOG_KERN,
	"user",		LOG_USER,
	"mail",		LOG_MAIL,
	"daemon",	LOG_DAEMON,
	"auth",		LOG_AUTH,
	"security",	LOG_AUTH,
	"mark",		LOG_MARK,
	"syslog",	LOG_SYSLOG,
	"lpr",		LOG_LPR,
	"news",		LOG_NEWS,
	"uucp",		LOG_UUCP,
	"altcron",	LOG_ALTCRON,
	"authpriv",	LOG_AUTHPRIV,
	"ftp",		LOG_FTP,
	"ntp",		LOG_NTP,
	"audit",	LOG_AUDIT,
	"console",	LOG_CONSOLE,
	"cron",		LOG_CRON,
	"local0",	LOG_LOCAL0,
	"local1",	LOG_LOCAL1,
	"local2",	LOG_LOCAL2,
	"local3",	LOG_LOCAL3,
	"local4",	LOG_LOCAL4,
	"local5",	LOG_LOCAL5,
	"local6",	LOG_LOCAL6,
	"local7",	LOG_LOCAL7,
	NULL,		-1
};

static int	pencode(char *);
static int	decode(char *, struct code *);
static void	bailout(char *, char *);
static void	usage(void);

/*
 *  LOGGER -- read and log utility
 *
 *	This routine reads from an input and arranges to write the
 *	result on the system log, along with a useful tag.
 */

int
main(int argc, char **argv)
{
	char tmp[23];
	char *tag = NULL;
	char *infile = NULL;
	char *buf = NULL;
	size_t buflen;
	int pri = LOG_NOTICE;
	int logflags = 0;
	int opt;
	int pid_len = 0;
	struct passwd *pw;
	uid_t u;
	char fmt_uid[16];
	char *p, *endp;
	size_t len;
	ptrdiff_t offset = 0;
	int status = 0;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"	/* Use this only if it weren't */
#endif
	(void) textdomain(TEXT_DOMAIN);
	/* initialize */

	while ((opt = getopt(argc, argv, "it:p:f:")) != EOF)
		switch (opt) {

		case 't':		/* tag */
			tag = optarg;
			break;

		case 'p':		/* priority */
			pri = pencode(optarg);
			break;

		case 'i':		/* log process id also */
			logflags |= LOG_PID;
			pid_len = sprintf(tmp, "%ld", (long)getpid());
			pid_len = (pid_len <= 0) ? 0 : pid_len +2;
			break;

		case 'f':		/* file to log */
			if (strcmp(optarg, "-") == 0)
				break;
			infile = optarg;
			if (freopen(infile, "r", stdin) == NULL) {
				(void) fprintf(stderr, gettext("logger: "));
				perror(infile);
				exit(1);
			}
			break;

		default:
			usage();
		}

	argc -= optind;
	argv = &argv[optind];

	if ((tag == NULL) && ((tag = getlogin()) == NULL)) {
		u = getuid();
		if ((pw = getpwuid(u)) == NULL) {
			(void) sprintf(fmt_uid, "%u", u);
			tag = fmt_uid;
		} else
			tag = pw->pw_name;
	}

	/* setup for logging */
	openlog(tag, logflags, 0);
	(void) fclose(stdout);

	/* log input line if appropriate */
	if (argc > 0) {
		/*
		 * Log arguments from command line
		 */
		int i;

		len = 0;
		for (i = 0; i < argc; i++) {
			len += strlen(argv[i]) + 1;	/* add 1 for <space> */
		}
		if ((buf = malloc(len + 1)) == NULL) {
			perror("logger");
			exit(1);
		}
		buf[0] = '\0';
		for (i = 0; i < argc; i++) {
			if (i != 0) {
				(void) strcat(buf, " ");
			}
			(void) strcat(buf, argv[i]);
		}
#ifdef DEBUG
		(void) fprintf(stderr, "len=%d, buf >%s<\n", len, buf);
#endif
		syslog(pri, "%s", buf);
	} else {
		/*
		 * Log arguments from stdin (or input file).
		 * When reading from stdin, logger grows its buffer if
		 * needed, to handle long lines.
		 */
		if ((buf = malloc(LOGGER_BUFLEN)) == NULL) {
			perror("logger");
			exit(1);
		}
		buflen = LOGGER_BUFLEN;
		p = buf;
		endp = buf + buflen;
		offset = 0;
		while (fgets(p, endp - p, stdin) != NULL) {
			len = strlen(p);
			if (p[len - 1] == '\n') {
#ifdef DEBUG
				(void) fprintf(stderr,
				    "p-buf =%d, len=%d, buflen=%d, buf >%s<\n",
				    p-buf, len, buflen, buf);
#endif
				syslog(pri, "%s", buf);
				p = buf;
				offset = 0;
			} else if (len < endp - p - 1) {
				/* short read or line with no <newline> */
				p += len;
				offset += len;
#ifdef DEBUG
				(void) fprintf(stderr,
				    "p-buf=%d, len=%d, buflen=%d, buf >%s<\n",
				    p-buf, len, buflen, buf);
#endif
				continue;
			} else {
				/* line longer than buflen, so get larger buf */
				buflen += LOGGER_BUFLEN;
				offset += len;
#ifdef DEBUG
				(void) fprintf(stderr,
				    "Realloc endp-p=%d, len=%d, offset=%d, "
				    "buflen %d\n",
				    endp - p, len, offset, buflen);
#endif
				if ((buf = realloc(buf, buflen)) == NULL) {
					perror("logger");
					exit(1);
				}
				p = buf + offset;
				endp = buf + buflen;
			}
		}	/* while */

		if (feof(stdin)) {
			if (p > buf) {
				/* the last line did not end with newline */
#ifdef DEBUG
				(void) fprintf(stderr,
				    "(2) p-buf=%d, len=%d, buflen=%d, "
				    "buf >%s<\n",
				    p-buf, len, buflen, buf);
#endif
				syslog(pri, "%s", buf);
			}
		} else {
			/*
			 * fgets() encountered an error.  Log unlogged data
			 * from earlier fgets() (if any).  Write null byte
			 * after last full read, in case the fgets() that
			 * encountered error removed it and failed to null
			 * terminate.
			 */
			perror("logger");
			if (p > buf) {
				*p = '\0';
				syslog(pri, "%s", buf);
			}
			status = 1;
		}
	}	/* else !(argc > 0) */
	free(buf);
	return (status);
}

/*
 *  Decode a symbolic name to a numeric value
 */


static int
pencode(char *s)
{
	char *p;
	int lev;
	int fac = 0;

	for (p = s; *s && *s != '.'; s++)
		;
	if (*s) {
		*s = '\0';
		fac = decode(p, FacNames);
		if (fac < 0)
			bailout("unknown facility name: ", p);
		*s++ = '.';
	} else
		s = p;
	lev = decode(s, PriNames);
	if (lev < 0)
		bailout("unknown priority name: ", s);

	return ((lev & LOG_PRIMASK) | (fac & LOG_FACMASK));
}


static int
decode(char *name, struct code *codetab)
{
	struct code *c;

	if (isdigit(*name))
		return (atoi(name));

	for (c = codetab; c->c_name; c++)
		if (strcasecmp(name, c->c_name) == 0)
			return (c->c_val);

	return (-1);
}


static void
bailout(char *a, char *b)
{
	(void) fprintf(stderr, gettext("logger: %s%s\n"), a, b);
	exit(1);
}


static void
usage(void)
{
	(void) fprintf(stderr, gettext(
	    "Usage:\tlogger string\n"
	    "\tlogger [-i] [-f filename] [-p priority] [-t tag] "
	    "[message] ...\n"));
	exit(1);
}
