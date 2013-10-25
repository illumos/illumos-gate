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
 */


#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/param.h>
#include <fcntl.h>
#include <sys/errno.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include <libgen.h>
#include "stdusers.h"


#define	FILE_BUFF	40960

static int suppress = 0;

static void usage(void);
static void file_copy(char *src_file, char *dest_file);
static void chown_file(const char *file, const char *group, const char *owner);
static char *find_basename(const char *str);
static int creatdir(char *fn);


void
usage(void)
{
	(void) fprintf(stderr,
	    "usage: install [-sd][-m mode][-g group][-u owner] "
	    "-f dir file ...\n");
}

void
file_copy(char *src_file, char *dest_file)
{
	int	src_fd;
	int	dest_fd;
	int	count;
	static char file_buff[FILE_BUFF];

	if ((src_fd = open(src_file, O_RDONLY))  == -1) {
		(void) fprintf(stderr, "install:file_copy: %s failed "
		    "(%d): %s\n", src_file, errno, strerror(errno));
		exit(1);
	}

	if ((dest_fd = open(dest_file, O_CREAT|O_WRONLY|O_TRUNC, 0755)) == -1) {
		(void) fprintf(stderr, "install:file_copy: %s failed "
		    "(%d): %s\n", dest_file, errno, strerror(errno));
		exit(1);
	}

	while ((count = read(src_fd, file_buff, FILE_BUFF)) > 0) {
		(void) write(dest_fd, file_buff, count);
	}

	if (count == -1) {
		(void) fprintf(stderr, "install:file_copy:read failed "
		    "(%d): %s\n", errno, strerror(errno));
		exit(1);
	}

	if (!suppress)
		(void) printf("%s installed as %s\n", src_file, dest_file);

	(void) close(src_fd);
	(void) close(dest_fd);
}


void
chown_file(const char *file, const char *group, const char *owner)
{
	gid_t	grp = (gid_t)-1;
	uid_t	own = (uid_t)-1;

	if (group) {
		grp = stdfind(group, groupnames);
		if (grp < 0)
			(void) fprintf(stderr, "unknown group(%s)\n", group);
	}

	if (owner) {
		own = stdfind(owner, usernames);
		if (own < 0) {
			(void) fprintf(stderr, "unknown owner(%s)\n", owner);
			exit(1);
		}

	}

	if (chown(file, own, grp) == -1) {
		(void) fprintf(stderr, "install:chown_file: failed "
		    "(%d): %s\n", errno, strerror(errno));
		exit(1);
	}
}


char *
find_basename(const char *str)
{
	int	i;
	int	len;

	len = strlen(str);

	for (i = len-1; i >= 0; i--)
		if (str[i] == '/')
			return ((char *)(str + i + 1));
	return ((char *)str);
}

int
creatdir(char *fn) {

	errno = 0;

	if (mkdirp(fn, 0755) == -1) {
		if (errno != EEXIST)
			return (errno);
	} else if (!suppress) {
		(void) printf("directory %s created\n", fn);
	}
	return (0);
}


int
main(int argc, char **argv)
{
	int	c;
	int	errflg = 0;
	int	dirflg = 0;
	char	*group = NULL;
	char	*owner = NULL;
	char	*dirb = NULL;
	char	*ins_file = NULL;
	int	mode = -1;
	char	dest_file[MAXPATHLEN];
	int	rv = 0;

	while ((c = getopt(argc, argv, "f:sm:du:g:")) != EOF) {
		switch (c) {
		case 'f':
			dirb = optarg;
			break;
		case 'g':
			group = optarg;
			break;
		case 'u':
			owner = optarg;
			break;
		case 'd':
			dirflg = 1;
			break;
		case 'm':
			mode = strtol(optarg, NULL, 8);
			break;
		case 's':
			suppress = 1;
			break;
		case '?':
			errflg++;
			break;
		}
	}

	if (errflg) {
		usage();
		return (1);
	}

	if (argc == optind) {
		usage();
		return (1);
	}

	if (!dirflg && (dirb == NULL)) {
		(void) fprintf(stderr,
		    "install: no destination directory specified.\n");
		return (1);
	}

	for (c = optind; c < argc; c++) {
		ins_file = argv[c];

		if (dirflg) {
			rv = creatdir(ins_file);
			if (rv) {
				(void) fprintf(stderr,
				    "install: creatdir %s (%d): %s\n",
				    ins_file, errno, strerror(errno));
				return (rv);
			}
			(void) strlcpy(dest_file, ins_file, MAXPATHLEN);

		} else {
			(void) strcat(strcat(strcpy(dest_file, dirb), "/"),
			    find_basename(ins_file));
			file_copy(ins_file, dest_file);
		}

		if (group || owner)
			chown_file(dest_file, group, owner);

		if (mode != -1) {
			(void) umask(0);
			if (chmod(dest_file, mode) == -1) {
				(void) fprintf(stderr,
				    "install: chmod of %s to mode %o failed "
				    "(%d): %s\n",
				    dest_file, mode, errno, strerror(errno));
				return (1);
			}
		}
	}
	return (0);
}
