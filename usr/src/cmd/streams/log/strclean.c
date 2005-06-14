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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.2.1.2	*/

#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stropts.h>
#include <ftw.h>
#include "sys/types.h"
#include "sys/stat.h"
#include "sys/stropts.h"
#include "sys/strlog.h"

#define	MSGSIZE 128
#define	NSECDAY (60*60*24)
#define	LOGDELAY 2
#define	LOGDEFAULT "/var/adm/streams"
#define	AGEDEFAULT 3
#define	DIRECTORY 040000
#define	ACCESS 07

static char prefix[128];
static time_t cutoff;


static int clean(const char *name, const struct stat *stp, int info);

int
main(int ac, char *av[])
{
	int age;
	int c, errflg;
	int fd;
	struct stat stbuf;
	struct strbuf ctl, dat;
	struct log_ctl lctl;
	char msg[MSGSIZE];
	char *logname;

	logname = LOGDEFAULT;
	age = AGEDEFAULT;
	errflg = 0;

	while ((c = getopt(ac, av, "d:a:")) != EOF) {
		switch (c) {
		case 'd':
			if (*optarg == '\0')
				errflg++;
			else
				logname = optarg;
			break;

		case 'a':
			if (*optarg == '\0')
				errflg++;
			else
				age = atoi(optarg);
			break;

		default:
			errflg++;
			break;
		}
	}

	if (errflg) {
		fprintf(stderr, "Usage: strclean [-d <logdir>] [-a <age>]\n");
		return (1);
	}

	if (age < 1) {
		fprintf(stderr, "strclean: <age> must be at least 1\n");
		return (2);
	}

	if ((stat(logname, &stbuf) < 0) || !(stbuf.st_mode & DIRECTORY)) {
		fprintf(stderr, "strclean: %s not a directory\n", logname);
		return (3);
	}

	if (access(logname, ACCESS) < 0) {
		fprintf(stderr, "strclean: cannot access directory %s\n",
		    logname);
		return (4);
	}

	cutoff = time(NULL) - age * NSECDAY;

	ctl.len = sizeof (struct log_ctl);
	ctl.maxlen = sizeof (struct log_ctl);
	ctl.buf = (caddr_t)&lctl;
	lctl.level = 0;
	lctl.flags = SL_ERROR|SL_NOTIFY;
	dat.buf = msg;
	dat.maxlen = MSGSIZE;
	sprintf(dat.buf,
	    "strclean - removing log files more than %d days old", age);
	dat.len = strlen(dat.buf) + 1;

	if ((fd = open("/dev/log", O_RDWR)) >= 0) {
		putmsg(fd, &ctl, &dat, 0);
		close(fd);
		sleep(LOGDELAY);
	}

	strcpy(prefix, logname);
	strcat(prefix, "/error.");

	ftw(logname, clean, 1);

	return (0);
}

/*
 * clean out all files in the log directory prefixed by 'prefix'
 * and that are older than 'cutoff' (these are globals above).
 */
static int
clean(const char *name, const struct stat *stp, int info)
{
	if (info != FTW_F)
		return (0);

	if (strncmp(name, prefix, strlen(prefix)) != 0)
		return (0);

	if (stp->st_mtime >= cutoff)
		return (0);

	if (unlink(name) < 0)
		fprintf(stderr, "strclean: unable to unlink file %s\n", name);

	return (0);
}
