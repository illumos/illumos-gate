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


/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include	<stdio.h>
#include	<stdlib.h>
#include 	<limits.h>
#include	<string.h>
#include	<sys/fstyp.h>
#include	<errno.h>
#include	<sys/vfstab.h>
#include	<sys/wait.h>
#include	<sys/types.h>

#define	FSTYPE_MAX	8
#define	FULLPATH_MAX	64
#define	ARGV_MAX	1024
#define	VFS_PATH	"/usr/lib/fs"

extern char	*default_fstype();

char	*special = NULL;  /*  device special name  */
char	*fstype = NULL;	  /*  fstype name is filled in here  */
char	*cbasename;	  /* name of command */
char	*newargv[ARGV_MAX]; 	/* args for the fstype specific command  */
char	vfstab[] = VFSTAB;
	char	full_path[FULLPATH_MAX];
	char	*vfs_path = VFS_PATH;
int	newargc = 2;

struct commands {
	char *c_basename;
	char *c_optstr;
	char *c_usgstr;
} cmd_data[] = {
	"ff", "F:o:p:a:m:c:n:i:?IlsuV",
	"[-F FSType] [-V] [current_options] [-o specific_options] special ...",
	"ncheck", "F:o:?i:asV",
"[-F FSType] [-V] [current_options] [-o specific_options] [special ...]",
	NULL, "F:o:?V",
	"[-F FSType] [-V] [current_options] [-o specific_options] special ..."
	};
struct 	commands *c_ptr;

static void usage(char *cmd, char *usg);
static void exec_specific(void);
static void lookup(void);

int
main(int argc, char *argv[])
{
	FILE *fp;
	struct vfstab	vfsbuf;
	char *ptr;
	int	i;
	int	verbose = 0;		/* set if -V is specified */
	int	F_flg = 0;
	int	usgflag = 0;
	int	fs_flag = 0;
	int	arg;			/* argument from getopt() */
	extern	char *optarg;		/* getopt specific */
	extern	int optind;
	extern	int opterr;
	size_t	strlen();

	cbasename = ptr = argv[0];
	while (*ptr) {
		if (*ptr++ == '/')
			cbasename = ptr;
	}
	/*
	 * If there are no arguments and command is ncheck then the generic
	 * reads the VFSTAB and executes the specific module of
	 * each entry which has a numeric fsckpass field.
	 */

	if (argc == 1) {		/* no arguments or options */
		if (strcmp(cbasename, "ncheck") == 0) {
			/* open VFSTAB */
			if ((fp = fopen(VFSTAB, "r")) == NULL) {
				fprintf(stderr, "%s: cannot open vfstab\n",
				    cbasename);
				exit(2);
			}
			while ((i = getvfsent(fp, &vfsbuf)) == 0) {
				if (numbers(vfsbuf.vfs_fsckpass)) {
					fstype = vfsbuf.vfs_fstype;
					newargv[newargc]  = vfsbuf.vfs_special;
					exec_specific();
				}
			}
			exit(0);
		}
		fprintf(stderr, "Usage:\n");
		fprintf(stderr,
"%s [-F FSType] [-V] [current_options] [-o specific_options] special ...\n",
		    cbasename);
		exit(2);
	}

	for (c_ptr = cmd_data; ((c_ptr->c_basename != NULL) &&
	    (strcmp(c_ptr->c_basename, cbasename) != 0));  c_ptr++)
		;
	while ((arg = getopt(argc, argv, c_ptr->c_optstr)) != -1) {
			switch (arg) {
			case 'V':	/* echo complete command line */
				verbose = 1;
				break;
			case 'F':	/* FSType specified */
				F_flg++;
				fstype = optarg;
				break;
			case 'o':	/* FSType specific arguments */
				newargv[newargc++] = "-o";
				newargv[newargc++] = optarg;
				break;
			case '?':	/* print usage message */
				newargv[newargc++] = "-?";
				usgflag = 1;
				break;
			default:
				newargv[newargc] = (char *)malloc(3);
				sprintf(newargv[newargc++], "-%c", arg);
				if (optarg)
					newargv[newargc++] = optarg;
				break;
			}
			optarg = NULL;
	}
	if (F_flg > 1) {
		fprintf(stderr, "%s: more than one FSType specified\n",
			cbasename);
		usage(cbasename, c_ptr->c_usgstr);
	}
	if (F_flg && (strlen(fstype) > (size_t)FSTYPE_MAX)) {
		fprintf(stderr, "%s: FSType %s exceeds %d characters\n",
			cbasename, fstype, FSTYPE_MAX);
		exit(2);
	}
	if (optind == argc) {
		/* all commands except ncheck must exit now */
		if (strcmp(cbasename, "ncheck") != 0) {
			if ((F_flg) && (usgflag)) {
				exec_specific();
				exit(0);
			}
			usage(cbasename, c_ptr->c_usgstr);
		}
		if ((F_flg) && (usgflag)) {
			exec_specific();
			exit(0);
		}
		if (usgflag)
			usage(cbasename, c_ptr->c_usgstr);

		/* open VFSTAB */
		if ((fp = fopen(VFSTAB, "r")) == NULL) {
			fprintf(stderr, "%s: cannot open vfstab\n", cbasename);
			exit(2);
		}
		while ((i = getvfsent(fp, &vfsbuf)) == 0) {
			if (!numbers(vfsbuf.vfs_fsckpass))
				continue;
			if ((F_flg) && (strcmp(fstype, vfsbuf.vfs_fstype) != 0))
				continue;
			fs_flag++;
			fstype = vfsbuf.vfs_fstype;
			newargv[newargc] = vfsbuf.vfs_special;
			if (verbose) {
				printf("%s -F %s ", cbasename,
				    vfsbuf.vfs_fstype);
				for (i = 2; newargv[i]; i++)
					printf("%s\n", newargv[i]);
				continue;
			}
			exec_specific();
		}
		/*
		 * if (! fs_flag) {
		 *	if (sysfs(GETFSIND, fstype) == (-1)) {
		 *		fprintf(stderr,
		 *		"%s: FSType %s not installed in the kernel\n",
		 *			cbasename, fstype);
		 *		exit(1);
		 *	}
		 * }
		 */

		exit(0);
	}

	/* All other arguments must be specials */
	/*  perform a lookup if fstype is not specified  */

	for (; optind < argc; optind++)  {
		newargv[newargc] = argv[optind];
		special = newargv[newargc];
		if ((F_flg) && (usgflag)) {
			exec_specific();
			exit(0);
		}
		if (usgflag)
			usage(cbasename, c_ptr->c_usgstr);
		if (fstype == NULL)
			lookup();
		if (verbose) {
			printf("%s -F %s ", cbasename, fstype);
			for (i = 2; newargv[i]; i++)
				printf("%s ", newargv[i]);
			printf("\n");
			continue;
		}
		exec_specific();
		if (!F_flg)
			fstype = NULL;
	}
	return (0);
}

/* see if all numbers */
int
numbers(char *yp)
{
	if (yp == NULL)
		return (0);
	while ('0' <= *yp && *yp <= '9')
		yp++;
	if (*yp)
		return (0);
	return (1);
}

static void
usage(char *cmd, char *usg)
{
	fprintf(stderr, "Usage:\n");
	fprintf(stderr, "%s %s\n", cmd, usg);
	exit(2);
}


/*
 *  This looks up the /etc/vfstab entry given the device 'special'.
 *  It is called when the fstype is not specified on the command line.
 *
 *  The following global variables are used:
 *	special, fstype
 */

static void
lookup(void)
{
	FILE	*fd;
	int	ret;
	struct vfstab	vget, vref;

	if ((fd = fopen(vfstab, "r")) == NULL) {
		fprintf(stderr, "%s: cannot open vfstab\n", cbasename);
		exit(1);
	}
	vfsnull(&vref);
	vref.vfs_special = special;
	ret = getvfsany(fd, &vget, &vref);
	if (ret == -1) {
		rewind(fd);
		vfsnull(&vref);
		vref.vfs_fsckdev = special;
		ret = getvfsany(fd, &vget, &vref);
	}
	fclose(fd);

	switch (ret) {
	case -1:
		fstype = default_fstype(special);
		break;
	case 0:
		fstype = vget.vfs_fstype;
		break;
	case VFS_TOOLONG:
		fprintf(stderr, "%s: line in vfstab exceeds %d characters\n",
			cbasename, VFS_LINE_MAX-2);
		exit(1);
		break;
	case VFS_TOOFEW:
		fprintf(stderr, "%s: line in vfstab has too few entries\n",
			cbasename);
		exit(1);
		break;
	case VFS_TOOMANY:
		fprintf(stderr, "%s: line in vfstab has too many entries\n",
			cbasename);
		exit(1);
		break;
	}
}

static void
exec_specific(void)
{
int status, pid, ret;

	sprintf(full_path, "%s/%s/%s", vfs_path, fstype, cbasename);
	newargv[1] = &full_path[FULLPATH_MAX];
	while (*newargv[1]-- != '/');
	newargv[1] += 2;
	switch (pid = fork()) {
	case 0:
		execv(full_path, &newargv[1]);
		if (errno == ENOEXEC) {
			newargv[0] = "sh";
			newargv[1] = full_path;
			execv("/sbin/sh", &newargv[0]);
		}
		if (errno != ENOENT) {
			perror(cbasename);
			fprintf(stderr, "%s: cannot execute %s\n", cbasename,
			    full_path);
			exit(1);
		}
		if (sysfs(GETFSIND, fstype) == (-1)) {
			fprintf(stderr,
				"%s: FSType %s not installed in the kernel\n",
				cbasename, fstype);
			exit(1);
		}
		fprintf(stderr, "%s: operation not applicable for FSType %s\n",
		    cbasename, fstype);
		exit(1);
	case -1:
		fprintf(stderr, "%s: cannot fork process\n", cbasename);
		exit(2);
	default:
		/*
		 * if cannot exec specific, or fstype is not installed, exit
		 * after first 'exec_specific' to avoid printing duplicate
		 * error messages
		 */

		if (wait(&status) == pid) {
			ret = WHIBYTE(status);
			if (ret > 0) {
				exit(ret);
			}
		}
	}
}
