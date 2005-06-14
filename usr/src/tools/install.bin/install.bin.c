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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"


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


#define	FILE_BUFF	40960

int supress = 0;


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
		perror(src_file);
		exit(1);
	}

	if ((dest_fd = open(dest_file, O_CREAT|O_WRONLY|O_TRUNC, 0755)) == -1) {
		perror(dest_file);
		exit(1);
	}

	while ((count = read(src_fd, file_buff, FILE_BUFF)) > 0) {
		write(dest_fd, file_buff, count);
	}

	if (count == -1) {
		perror("file_copy(read)");
		exit(1);
	}

	if (!supress)
		(void) printf("%s installed as %s\n", src_file, dest_file);

	close(src_fd);
	close(dest_fd);
}


void
chown_file(const char *file, const char *group, const char *owner)
{
	gid_t	grp;
	gid_t	own;

	if (group) {
		if (strcmp(group, "bin") == 0)
			grp = 2;
		else if (strcmp(group, "sys") == 0)
			grp = 3;
		else if (strcmp(group, "adm") == 0)
			grp = 4;
		else if (strcmp(group, "uucp") == 0)
			grp = 5;
		else if (strcmp(group, "mail") == 0)
			grp = 6;
		else if (strcmp(group, "tty") == 0)
			grp = 7;
		else if (strcmp(group, "lp") == 0)
			grp = 8;
		else if (strcmp(group, "other") == 0)
			grp = 1;
		else if (strcmp(group, "nuucp") == 0)
			grp = 9;
		else if (strcmp(group, "staff") == 0)
			grp = 10;
		else if (strcmp(group, "daemon") == 0)
			grp = 12;
		else if (strcmp(group, "root") == 0)
			grp = 0;
		else if (strcmp(group, "sysadmin") == 0)
			grp = 14;
		else if (strcmp(group, "smmsp") == 0)
			grp = 25;
		else if (strcmp(group, "nobody") == 0)
			grp = 60001;
		else if (strcmp(group, "noaccess") == 0)
			grp = 60002;
		else if (strcmp(group, "svvs_grp") == 0)
			grp = 101;
		else
			(void) fprintf(stderr, "unknown group(%s)\n", group);
	} else {
		grp = -1;
	}

	if (owner) {
		if (strcmp(owner, "bin") == 0)
			own = 2;
		else if (strcmp(owner, "daemon") == 0)
			own = 1;
		else if (strcmp(owner, "sys") == 0)
			own = 3;
		else if (strcmp(owner, "adm") == 0)
			own = 4;
		else if (strcmp(owner, "lp") == 0)
			own = 71;
		else if (strcmp(owner, "root") == 0)
			own = 0;
		else if (strcmp(owner, "uucp") == 0)
			own = 5;
		else if (strcmp(owner, "nuucp") == 0)
			own = 9;
		else if (strcmp(owner, "smmsp") == 0)
			own = 25;
		else if (strcmp(owner, "listen") == 0)
			own = 37;
		else if (strcmp(owner, "nobody") == 0)
			own = 60001;
		else if (strcmp(owner, "noaccess") == 0)
			own = 60002;
		/*
		 * This is a temporary HACK that should be removed!!!
		 */
		else if (strcmp(owner, "sysadm") == 0)
			own = 0;
		else {
			(void) fprintf(stderr, "unknown owner(%s)\n", owner);
			exit(1);
		}

	} else {
		own = -1;
	}

	if (chown(file, own, grp) == -1) {
		perror("chown");
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
			supress = 1;
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
			struct stat buf;

			if (stat(ins_file, &buf) == 0) {
				if ((buf.st_mode & S_IFMT) == S_IFDIR)
					continue;
			} else {
				if (errno != ENOENT) {
					perror("install: stat");
					return (1);
				}
			}

			(void) strcpy(dest_file, ins_file);

			if (mkdirp(dest_file, 0755) == -1) {
				if (!supress) {
					(void) printf(
					    "install: mkdirp of %s failed\n",
					    dest_file);
				}
			} else if (!supress) {
				(void) printf("directory %s created\n",
				    dest_file);
			}
		} else {
			(void) strcat(strcat(strcpy(dest_file, dirb), "/"),
			    find_basename(ins_file));
			file_copy(ins_file, dest_file);
		}

		if (group || owner)
			chown_file(dest_file, group, owner);

		if (mode != -1) {
			umask(0);
			if (chmod(dest_file, mode) == -1) {
				perror("chmod");
				return (1);
			}
		}
	}
	return (0);
}
