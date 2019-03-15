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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <locale.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/mntent.h>
#include <sys/fs/sdev_impl.h>


#define	READFLAG_RO	1
#define	READFLAG_RW	2


extern int	optind;
extern char	*optarg;

static char	typename[64], *myname;
static char	fstype[] = MNTTYPE_DEV;

static int	readflag;
static int	overlay;
static int	remount;

static char	*special;
static char	*mountpt;
static struct sdev_mountargs	mountargs;

static char	*myopts[] = {
#define	SUBOPT_READONLY		0
	"ro",
#define	SUBOPT_READWRITE	1
	"rw",
#define	SUBOPT_ATTRIBDIR	2
	"attrdir",
#define	SUBOPT_REMOUNT		3
	"remount",
	NULL
};


static void
usage(void)
{
	(void) fprintf(stderr, gettext(
	    "%s usage:\n%s [-F %s] [-r] [-o specific_options]"
	    " {special | mount_point}\n%s [-F %s] [-r] [-o specific_options]"
	    " special mount_point\n"), fstype, myname, fstype, myname, fstype);
	exit(1);
}


static int
do_mount(void)
{
	int	flags = MS_DATA;

	if (readflag == READFLAG_RO)
		flags |= MS_RDONLY;
	if (overlay)
		flags |= MS_OVERLAY;
	if (remount)
		flags |= MS_REMOUNT;

	if (mount(special, mountpt, flags, fstype, &mountargs,
	    sizeof (mountargs), NULL, 0)) {
		switch (errno) {
		case EPERM:
			(void) fprintf(stderr, gettext("%s: not super user\n"),
			    typename);
			break;
		case ENXIO:
			(void) fprintf(stderr, gettext("%s: %s no such "
			    "device\n"), typename, special);
			break;
		case ENOTDIR:
			(void) fprintf(stderr, gettext("%s: %s "
			    "not a directory\n"
			    "\tor a component of %s is not a directory\n"),
			    typename, mountpt, special);
			break;
		case ENOENT:
			(void) fprintf(stderr, gettext("%s: %s or %s, no such "
			    "file or directory\n"),
			    typename, special, mountpt);
			break;
		case EINVAL:
			(void) fprintf(stderr, gettext("%s: %s is not this "
			    "filesystem type.\n"), typename, special);
			break;
		case EBUSY:
			(void) fprintf(stderr, gettext("%s: %s "
			    "is already mounted, %s is busy,\n"
			    "\tor allowable number of mount points exceeded\n"),
			    typename, special, mountpt);
			break;
		case ENOTBLK:
			(void) fprintf(stderr, gettext("%s: %s not a block "
			    "device\n"), typename, special);
			break;
		case EROFS:
			(void) fprintf(stderr, gettext("%s: %s read-only "
			    "filesystem\n"), typename, special);
			break;
		case ENOSPC:
			(void) fprintf(stderr, gettext("%s: the state of %s "
			    "is not okay\n"
			    "\tand read/write mount was attempted\n"),
			    typename, special);
			break;
		default:
			(void) fprintf(stderr, gettext("%s: cannot mount %s: "
			    "%s\n"), typename, special, strerror(errno));
			break;
		}
		return (-1);
	}
	return (0);
}


/*
 * Wrapper around strdup().
 */
static char *
do_strdup(const char *s1)
{
	char	*str;

	str = strdup(s1);
	if (str == NULL) {
		(void) fprintf(stderr, gettext("%s: strdup failed: %s\n"),
		    typename, strerror(errno));
	}
	return (str);
}


/*
 * Wrapper around stat().
 */
static int
do_stat(const char *path, struct stat *buf)
{
	int	ret;

	ret = stat(path, buf);
	if (ret < 0) {
		(void) fprintf(stderr, gettext("%s: can't stat %s: %s\n"),
		    typename, path, strerror(errno));
	}
	return (ret);
}


/*
 * Wraper around realpath()
 */
static char *
do_realpath(const char *path, char *resolved_path)
{
	char	*ret;

	ret = realpath(path, resolved_path);
	if (ret == NULL) {
		(void) fprintf(stderr, gettext("%s: realpath %s failed: %s\n"),
		    typename, path, strerror(errno));
	}
	return (ret);
}


static int
parse_subopts(char *subopts)
{
	char	*value;
	char	path[PATH_MAX + 1];

	while (*subopts != '\0') {
		switch (getsubopt(&subopts, myopts, &value)) {
		case SUBOPT_READONLY:
			if (readflag == READFLAG_RW) {
				(void) fprintf(stderr, gettext("%s: both "
				    "read-only and read-write options "
				    "specified\n"), typename);
				return (-1);
			}
			readflag = READFLAG_RO;
			break;

		case SUBOPT_READWRITE:
			if (readflag == READFLAG_RO) {
				(void) fprintf(stderr, gettext("%s: both "
				    "read-only and read-write options "
				    "specified\n"), typename);
				return (-1);
			}
			readflag = READFLAG_RW;
			break;

		case SUBOPT_ATTRIBDIR:
			if (value == NULL) {
				(void) fprintf(stderr, gettext("%s: no "
				    "attribute directory\n"), typename);
				return (-1);
			} else {
				if (do_realpath(value, path) == NULL)
					return (-1);
				mountargs.sdev_attrdir =
				    (uint64_t)(uintptr_t)do_strdup(path);
				if (mountargs.sdev_attrdir == 0)
					return (-1);
			}
			break;

		case SUBOPT_REMOUNT:
			remount = 1;
			break;

		default:
			(void) fprintf(stderr, gettext("%s: illegal -o "
			    "suboption: %s\n"), typename, value);
			return (-1);
		}
	}
	return (0);
}


int
main(int argc, char **argv)
{
	struct stat	st;
	char		mntpath[PATH_MAX + 1];
	int		cc;

	(void) setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	if (myname = strrchr(argv[0], '/'))
		myname++;
	else
		myname = argv[0];
	(void) snprintf(typename, sizeof (typename), "%s %s", fstype, myname);
	argv[0] = typename;

	while ((cc = getopt(argc, argv, "?o:rmO")) != -1) {
		switch (cc) {
		case 'r':
			if (readflag == READFLAG_RW) {
				(void) fprintf(stderr, gettext("%s: both "
				    "read-only and read-write options "
				    "specified\n"), typename);
				return (1);
			}
			readflag = READFLAG_RO;
			break;

		case 'O':
			overlay = 1;
			break;

		case 'o':
			if (parse_subopts(optarg))
				return (1);
			break;

		default:
			usage();
			break;
		}
	}

	/*
	 * There must be at least 2 more arguments, the
	 * special file and the directory.
	 */
	if ((argc - optind) != 2)
		usage();

	special = argv[optind++];

	if (do_realpath(argv[optind++], mntpath) == NULL)
		return (1);
	mountpt = mntpath;

	if (mountpt) {
		if (do_stat(mountpt, &st) < 0)
			return (1);
		if (! S_ISDIR(st.st_mode)) {
			(void) fprintf(stderr, gettext("%s: %s is not a "
			    "directory\n"), typename, mountpt);
			return (1);
		}
	}

	if (mountargs.sdev_attrdir) {
		if (do_stat((const char *)(uintptr_t)mountargs.sdev_attrdir,
		    &st) < 0)
			return (1);
		if (! S_ISDIR(st.st_mode)) {
			(void) fprintf(stderr, gettext("%s: %s is not a "
			    "directory\n"), typename, mountargs.sdev_attrdir);
			return (1);
		}
	}

	/* Special checks if /dev is the mount point */
	/* Remount of /dev requires an attribute directory */
	if (strcmp(mountpt, "/dev") == 0 && remount &&
	    mountargs.sdev_attrdir == 0) {
		(void) fprintf(stderr, gettext("%s: missing attribute "
		    "directory\n"), typename);
		return (1);
	}

	(void) signal(SIGHUP,  SIG_IGN);
	(void) signal(SIGQUIT, SIG_IGN);
	(void) signal(SIGINT,  SIG_IGN);

	/* Perform the mount  */
	if (do_mount())
		return (1);

	return (0);
}
