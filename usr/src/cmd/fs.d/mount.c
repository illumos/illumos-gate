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
 * Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include	<stdio.h>
#include	<stdio_ext.h>
#include 	<limits.h>
#include 	<fcntl.h>
#include 	<unistd.h>
#include	<stdlib.h>
#include	<string.h>
#include	<stdarg.h>
#include	<sys/types.h>
#include	<sys/stat.h>
#include	<sys/statvfs.h>
#include	<errno.h>
#include	<sys/mnttab.h>
#include	<sys/mntent.h>
#include	<sys/mount.h>
#include	<sys/vfstab.h>
#include	<sys/param.h>
#include	<sys/wait.h>
#include	<sys/signal.h>
#include	<sys/resource.h>
#include	<stropts.h>
#include	<sys/conf.h>
#include	<locale.h>
#include	"fslib.h"

#define	VFS_PATH	"/usr/lib/fs"
#define	ALT_PATH	"/etc/fs"
#define	REMOTE		"/etc/dfs/fstypes"

#define	ARGV_MAX	16
#define	TIME_MAX	50
#define	FSTYPE_MAX	8
#define	REMOTE_MAX	64

#define	OLD	0
#define	NEW	1

#define	READONLY	0
#define	READWRITE	1
#define	SUID 		2
#define	NOSUID		3
#define	SETUID 		4
#define	NOSETUID	5
#define	DEVICES		6
#define	NODEVICES	7

#define	FORMAT	"%a %b %e %H:%M:%S %Y\n"	/* date time format */
				/* a - abbreviated weekday name */
				/* b - abbreviated month name */
				/* e - day of month */
				/* H - hour */
				/* M - minute */
				/* S - second */
				/* Y - Year */
				/* n - newline */

/*
 * The fs-local method understands this exit code to mean that one or
 * more failures occurred and that all the failures were of attempted
 * lofs mounts.
 */
#define	ALL_LOFS_FAILURES	111

extern int	optind;
extern char	*optarg;

extern void	usage(void);
extern char	*flags(char *, int);
extern char	*remote(char *, FILE *);
extern char	*default_fstype(char *);

char	*myopts[] = {
	MNTOPT_RO,
	MNTOPT_RW,
	MNTOPT_SUID,
	MNTOPT_NOSUID,
	MNTOPT_SETUID,
	MNTOPT_NOSETUID,
	MNTOPT_DEVICES,
	MNTOPT_NODEVICES,
	NULL
};

static char	*myname;		/* point to argv[0] */

/*
 * Set the limit to double the number of characters a user should be allowed to
 * type in one line.
 * This should cover the different shells, which don't use POSIX_MAX_INPUT,
 * and should cover the case where a long option string can be in
 * the /etc/vfstab file.
 */
char	mntflags[(_POSIX_MAX_INPUT+1) * 2];

char	realdir[MAXPATHLEN];	/* buffer for realpath() calls */
char	*vfstab = VFSTAB;
char	*mnttab = MNTTAB;
char	*specific_opts;		/* holds specific mount options */
char	*generic_opts;		/* holds generic mount options */
int	maxrun;
int	nrun;
int	failcnt;		/* total count of failures */
int	lofscnt;		/* presence of lofs prohibits parallel */
				/* mounting */
int	lofsfail;		/* count of failures of lofs mounts */
int	exitcode;
int	aflg, cflg, fflg, Fflg, gflg, oflg, pflg, rflg, vflg, Vflg, mflg, Oflg,
	dashflg, questflg, dflg, qflg;


/*
 * Each vfsent_t describes a vfstab entry.  It is used to manage and cleanup
 * each child that performs the particular mount for the entry.
 */

typedef struct vfsent {
	struct vfstab	v;		/* the vfstab entry */
	char		*rpath;		/* resolved pathname so far */
	int		mlevel;		/* how deep is this mount point */
	int		order;		/* vfstab serial order of this vfs */
	int		flag;
	pid_t		pid;		/* the pid of this mount process */
	int		exitcode;	/* process's exitcode */
#define	RDPIPE		0
#define	WRPIPE		1
	int		sopipe[2];	/* pipe attached to child's stdout */
	int		sepipe[2];	/* pipe attached to child's stderr */
	struct vfsent	*next;		/* used when in linked list */
} vfsent_t;

#define	VRPFAILED	0x01		/* most recent realpath failed on */
					/* this mount point */
#define	VNOTMOUNTED	0x02		/* mount point could not be mounted */

vfsent_t	*vfsll, *vfslltail;	/* head and tail of the global */
					/* linked list of vfstab entries */
vfsent_t	**vfsarray;		/* global array of vfsent_t's */
int		vfsarraysize;		/* length of the list */

/*
 * This structure is used to build a linked list of
 * mnttab structures from /etc/mnttab.
 */
typedef struct mountent {
	struct extmnttab	*ment;
	int		flag;
	struct mountent	*next;
} mountent_t;

#define	MSORTED		0x1

static vfsent_t **make_vfsarray(char **, int);
static vfsent_t	*new_vfsent(struct vfstab *, int);
static vfsent_t *getvfsall(char *, int);

static void	doexec(char *, char **);
static void	nomem();
static void	cleanup(int);
static char	*setrpath(vfsent_t *);
static int	dowait();
static int	setup_iopipe(vfsent_t *);
static void	setup_output(vfsent_t *);
static void	doio(vfsent_t *);
static void	do_mounts();
static int	parmount(char **, int, char *);
static int	mlevelcmp(const void *, const void *);
static int	mordercmp(const void *, const void *);
static int	check_fields(char *, char *);
static int	cleanupkid(pid_t, int);
static void	print_mnttab(int, int);
static void	vfserror(int, char *);
static void	mnterror(int);
static int	ignore(char *);

/*
 * This is /usr/sbin/mount: the generic command that in turn
 * execs the appropriate /usr/lib/fs/{fstype}/mount.
 * The -F flag and argument are NOT passed.
 * If the usr file system is not mounted a duplicate copy
 * can be found in /sbin and this version execs the
 * appropriate /etc/fs/{fstype}/mount
 *
 * If the -F fstype, special or directory are missing,
 * /etc/vfstab is searched to fill in the missing arguments.
 *
 * -V will print the built command on the stdout.
 * It isn't passed either.
 */
int
main(int argc, char *argv[])
{
	char	*special,	/* argument of special/resource */
	    *mountp,		/* argument of mount directory */
	    *fstype,		/* wherein the fstype name is filled */
	    *newargv[ARGV_MAX],	/* arg list for specific command */
	    *farg = NULL, *Farg = NULL;
	int	ii, ret, cc, fscnt;
	struct stat64	stbuf;
	struct vfstab	vget, vref;
	mode_t mode;
	FILE	*fd;

	(void) setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	myname = strrchr(argv[0], '/');
	if (myname)
		myname++;
	else
		myname = argv[0];
	if (myname == 0) myname = "path unknown";

	/* Process the args.  */

	while ((cc = getopt(argc, argv, "?acd:f:F:gmno:pqrvVO")) != -1)
		switch (cc) {
			case 'a':
				aflg++;
				break;
			case 'c':
				cflg++;
				break;

#ifdef DEBUG
			case 'd':
				dflg = atoi(optarg);
				break;
#endif

			case 'f':
				fflg++;
				farg = optarg;
				break;
			case 'F':
				Fflg++;
				Farg = optarg;
				break;
			case 'g':
				gflg++;
				break;
			case 'm':
				mflg++;
				break; /* do not update /etc/mnttab */
			case 'o':
				oflg++;
				if ((specific_opts = strdup(optarg)) == NULL)
					nomem();
				break; /* fstype dependent options */
			case 'O':
				Oflg++;
				break;
			case 'p':
				pflg++;
				break;
			case 'q':
				qflg++;
				break;
			case 'r':
				rflg++;
				generic_opts = "ro";
				break;
			case 'v':
				vflg++;
				break;
			case 'V':
				Vflg++;
				break;
			case '?':
				questflg++;
				break;
		}

	/* copy '--' to specific */
	if (strcmp(argv[optind-1], "--") == 0)
		dashflg++;

	/* option checking */
	/* more than two args not allowed if !aflg */
	if (!aflg && (argc - optind > 2))
		usage();

	/* pv mututally exclusive */
	if (pflg + vflg + aflg > 1) {
		fprintf(stderr, gettext
		    ("%s: -a, -p, and -v are mutually exclusive\n"),
		    myname);
		usage();
	}

	/*
	 * Can't have overlaying mounts on the same mount point during
	 * a parallel mount.
	 */
	if (aflg && Oflg) {
		fprintf(stderr, gettext
		    ("%s: -a and -O are mutually exclusive\n"), myname);
		usage();
	}

	/* dfF mutually exclusive */
	if (fflg + Fflg > 1) {
		fprintf(stderr, gettext
		    ("%s: More than one FSType specified\n"), myname);
		usage();
	}

	/* no arguments, only allow p,v,V or [F]? */
	if (!aflg && optind == argc) {
		if (cflg || fflg || mflg || oflg || rflg || qflg)
			usage();

		if (Fflg && !questflg)
			usage();

		if (questflg) {
			if (Fflg) {
				newargv[2] = "-?";
				newargv[3] = NULL;
				doexec(Farg, newargv);
			}
			usage();
		}
	}

	if (questflg)
		usage();

	/* one or two args, allow any but p,v */
	if (optind != argc && (pflg || vflg)) {
		fprintf(stderr,
gettext("%s: Cannot use -p and -v with arguments\n"), myname);
		usage();
	}


	/* if only reporting mnttab, generic prints mnttab and exits */
	if (!aflg && optind == argc) {
		if (Vflg) {
			printf("%s", myname);
			if (pflg)
				printf(" -p");
			if (vflg)
				printf(" -v");
			printf("\n");
			exit(0);
		}

		print_mnttab(vflg, pflg);
		exit(0);
	}

	/*
	 * Get filesystem type here.  If "-F FStype" is specified, use
	 * that fs type.  Otherwise, determine the fs type from /etc/vfstab
	 * if the entry exists.  Otherwise, determine the local or remote
	 * fs type from /etc/default/df or /etc/dfs/fstypes respectively.
	 */
	if (fflg) {
		if ((strcmp(farg, "S51K") != 0) &&
		    (strcmp(farg, "S52K") != 0)) {
			fstype = farg;
		}
		else
			fstype = "ufs";
	} else /* if (Fflg) */
		fstype = Farg;

	fscnt = argc - optind;
	if (aflg && (fscnt != 1))
		exit(parmount(argv + optind, fscnt, fstype));

	/*
	 * Then don't bother with the parallel over head.  Everything
	 * from this point is simple/normal single execution.
	 */
	aflg = 0;

	/* get special and/or mount-point from arg(s) */
	if (fscnt == 2)
		special = argv[optind++];
	else
		special = NULL;
	if (optind < argc)
		mountp = argv[optind++];
	else
		mountp = NULL;

	/* lookup only if we need to */
	if (fstype == NULL || specific_opts == NULL || special == NULL ||
	    mountp == NULL) {
		if ((fd = fopen(vfstab, "r")) == NULL) {
			if (fstype == NULL || special == NULL ||
			    mountp == NULL) {
				fprintf(stderr, gettext(
				    "%s: Cannot open %s\n"),
				    myname, vfstab);
				exit(1);
			} else {
				/*
				 * No vfstab, but we know what we want
				 * to mount.
				 */
				goto out;
			}
		}
		vfsnull(&vref);
		vref.vfs_special = special;
		vref.vfs_mountp = mountp;
		vref.vfs_fstype = fstype;

		/* get a vfstab entry matching mountp or special */
		while ((ret = getvfsany(fd, &vget, &vref)) > 0)
			vfserror(ret, vget.vfs_special);

		/* if no entry and there was only one argument */
		/* then the argument could be the special */
		/* and not mount point as we thought earlier */
		if (ret == -1 && special == NULL) {
			rewind(fd);
			special = vref.vfs_special = mountp;
			mountp = vref.vfs_mountp = NULL;
			/* skip erroneous lines; they were reported above */
			while ((ret = getvfsany(fd, &vget, &vref)) > 0)
				;
		}

		fclose(fd);

		if (ret == 0) {
			if (fstype == NULL)
				fstype = vget.vfs_fstype;
			if (special == NULL)
				special = vget.vfs_special;
			if (mountp == NULL)
				mountp = vget.vfs_mountp;
			if (oflg == 0 && vget.vfs_mntopts) {
				oflg++;
				specific_opts = vget.vfs_mntopts;
			}
		} else if (special == NULL) {
			if (stat64(mountp, &stbuf) == -1) {
				fprintf(stderr, gettext("%s: cannot stat %s\n"),
				    myname, mountp);
				exit(2);
			}
			if (((mode = (stbuf.st_mode & S_IFMT)) == S_IFBLK) ||
			    (mode == S_IFCHR)) {
				fprintf(stderr,
gettext("%s: mount point cannot be determined\n"),
				    myname);
				exit(1);
			} else
				{
				fprintf(stderr,
gettext("%s: special cannot be determined\n"),
				    myname);
				exit(1);
			}
		} else if (fstype == NULL)
			fstype = default_fstype(special);
	}

out:
	if (realpath(mountp, realdir) == NULL) {
		(void) fprintf(stderr, "mount: ");
		perror(mountp);
		exit(1);
	}

	if ((mountp = strdup(realdir)) == NULL)
		nomem();

	if (check_fields(fstype, mountp))
		exit(1);

	/* create the new arg list, and end the list with a null pointer */
	ii = 2;
	if (cflg)
		newargv[ii++] = "-c";
	if (gflg)
		newargv[ii++] = "-g";
	if (mflg)
		newargv[ii++] = "-m";
	/*
	 * The q option needs to go before the -o option as some
	 * filesystems complain during first pass option parsing.
	 */
	if (qflg)
		newargv[ii++] = "-q";
	if (oflg) {
		newargv[ii++] = "-o";
		newargv[ii++] = specific_opts;
	}
	if (Oflg)
		newargv[ii++] = "-O";
	if (rflg)
		newargv[ii++] = "-r";
	if (dashflg)
		newargv[ii++] = "--";
	newargv[ii++] = special;
	newargv[ii++] = mountp;
	newargv[ii] = NULL;

	doexec(fstype, newargv);
	return (0);
}

void
usage(void)
{
	fprintf(stderr,	gettext("Usage:\n%s [-v | -p]\n"), myname);
	fprintf(stderr, gettext(
	    "%s [-F FSType] [-V] [current_options] [-o specific_options]"),
	    myname);
	fprintf(stderr, gettext("\n\t{special | mount_point}\n"));

	fprintf(stderr, gettext(
	    "%s [-F FSType] [-V] [current_options] [-o specific_options]"),
	    myname);
	fprintf(stderr, gettext("\n\tspecial mount_point\n"));

	fprintf(stderr, gettext(
	"%s -a [-F FSType ] [-V] [current_options] [-o specific_options]\n"),
	    myname);
	fprintf(stderr, gettext("\t[mount_point ...]\n"));

	exit(1);
}

/*
 * Get rid of "dev=[hex string]" clause, if any.  It's not legal
 * when printing in vfstab format.
 */
void
elide_dev(char *mntopts)
{
	char *dev, *other;

	if (mntopts != NULL) {
		dev = strstr(mntopts, "dev=");
		if (dev != NULL) {
			other = strpbrk(dev, ",");
			if (other == NULL) {
				/* last option */
				if (dev != mntopts) {
					*--dev = '\0';
				} else {
					*dev = '\0';
				}
			} else {
				/* first or intermediate option */
				memmove(dev, other+1, strlen(other+1)+1);
			}
		}
	}
}

void
print_mnttab(int vflg, int pflg)
{
	FILE	*fd;
	FILE	*rfp;			/* this will be NULL if fopen fails */
	int	ret;
	char	time_buf[TIME_MAX];	/* array to hold date and time */
	struct extmnttab	mget;
	time_t	ltime;

	if ((fd = fopen(mnttab, "r")) == NULL) {
		fprintf(stderr, gettext("%s: Cannot open mnttab\n"), myname);
		exit(1);
	}
	rfp = fopen(REMOTE, "r");
	while ((ret = getextmntent(fd, &mget, sizeof (struct extmnttab)))
	    == 0) {
		if (ignore(mget.mnt_mntopts))
			continue;
		if (mget.mnt_special && mget.mnt_mountp &&
		    mget.mnt_fstype && mget.mnt_time) {
			ltime = atol(mget.mnt_time);
			cftime(time_buf, FORMAT, &ltime);
			if (pflg) {
				elide_dev(mget.mnt_mntopts);
				printf("%s - %s %s - no %s\n",
				    mget.mnt_special,
				    mget.mnt_mountp,
				    mget.mnt_fstype,
				    mget.mnt_mntopts != NULL ?
				    mget.mnt_mntopts : "-");
			} else if (vflg) {
				printf("%s on %s type %s %s%s on %s",
				    mget.mnt_special,
				    mget.mnt_mountp,
				    mget.mnt_fstype,
				    remote(mget.mnt_fstype, rfp),
				    flags(mget.mnt_mntopts, NEW),
				    time_buf);
			} else
				printf("%s on %s %s%s on %s",
				    mget.mnt_mountp,
				    mget.mnt_special,
				    remote(mget.mnt_fstype, rfp),
				    flags(mget.mnt_mntopts, OLD),
				    time_buf);
		}
	}
	if (ret > 0)
		mnterror(ret);
}

char	*
flags(char *mntopts, int flag)
{
	char	opts[sizeof (mntflags)];
	char	*value;
	int	rdwr = 1;
	int	suid = 1;
	int	devices = 1;
	int	setuid = 1;

	if (mntopts == NULL || *mntopts == '\0')
		return ("read/write/setuid/devices");

	strcpy(opts, "");
	while (*mntopts != '\0')  {
		switch (getsubopt(&mntopts, myopts, &value)) {
		case READONLY:
			rdwr = 0;
			break;
		case READWRITE:
			rdwr = 1;
			break;
		case SUID:
			suid = 1;
			break;
		case NOSUID:
			suid = 0;
			break;
		case SETUID:
			setuid = 1;
			break;
		case NOSETUID:
			setuid = 0;
			break;
		case DEVICES:
			devices = 1;
			break;
		case NODEVICES:
			devices = 0;
			break;
		default:
			/* cat '/' separator to mntflags */
			if (*opts != '\0' && value != NULL)
				strcat(opts, "/");
			strcat(opts, value);
			break;
		}
	}

	strcpy(mntflags, "");
	if (rdwr)
		strcat(mntflags, "read/write");
	else if (flag == OLD)
		strcat(mntflags, "read only");
	else
		strcat(mntflags, "read-only");
	if (suid) {
		if (setuid)
			strcat(mntflags, "/setuid");
		else
			strcat(mntflags, "/nosetuid");
		if (devices)
			strcat(mntflags, "/devices");
		else
			strcat(mntflags, "/nodevices");
	} else {
		strcat(mntflags, "/nosetuid/nodevices");
	}
	if (*opts != '\0') {
		strcat(mntflags, "/");
		strcat(mntflags, opts);
	}

	/*
	 * The assumed assertion
	 * 	assert (strlen(mntflags) < sizeof mntflags);
	 * is valid at this point in the code. Note that a call to "assert"
	 * is not appropriate in production code since it halts the program.
	 */
	return (mntflags);
}

char	*
remote(char *fstype, FILE *rfp)
{
	char	buf[BUFSIZ];
	char	*fs;
	extern char *strtok();

	if (rfp == NULL || fstype == NULL ||
	    strlen(fstype) > (size_t)FSTYPE_MAX)
		return ("");	/* not a remote */
	rewind(rfp);
	while (fgets(buf, sizeof (buf), rfp) != NULL) {
		fs = strtok(buf, " \t\n");
		if (strcmp(fstype, fs) == 0)
			return ("remote/");	/* is a remote fs */
	}
	return ("");	/* not a remote */
}


void
vfserror(int flag, char *special)
{
	if (special == NULL)
		special = "<null>";
	switch (flag) {
	case VFS_TOOLONG:
		fprintf(stderr,
gettext("%s: Warning: Line in vfstab for \"%s\" exceeds %d characters\n"),
		    myname, special, VFS_LINE_MAX-1);
		break;
	case VFS_TOOFEW:
		fprintf(stderr,
gettext("%s: Warning: Line for \"%s\" in vfstab has too few entries\n"),
		    myname, special);
		break;
	case VFS_TOOMANY:
		fprintf(stderr,
gettext("%s: Warning: Line for \"%s\" in vfstab has too many entries\n"),
		    myname, special);
		break;
	default:
		fprintf(stderr, gettext(
		    "%s: Warning: Error in line for \"%s\" in vfstab\n"),
		    myname, special);
	}
}

void
mnterror(int flag)
{
	switch (flag) {
	case MNT_TOOLONG:
		fprintf(stderr,
		    gettext("%s: Line in mnttab exceeds %d characters\n"),
		    myname, MNT_LINE_MAX-2);
		break;
	case MNT_TOOFEW:
		fprintf(stderr,
		    gettext("%s: Line in mnttab has too few entries\n"),
		    myname);
		break;
	case MNT_TOOMANY:
		fprintf(stderr,
		    gettext("%s: Line in mnttab has too many entries\n"),
		    myname);
		break;
	}
	exit(1);
}

void
doexec(char *fstype, char *newargv[])
{
	char	full_path[PATH_MAX];
	char	alter_path[PATH_MAX];
	char	*vfs_path = VFS_PATH;
	char	*alt_path = ALT_PATH;
	int	i;

	/* build the full pathname of the fstype dependent command. */
	sprintf(full_path, "%s/%s/%s", vfs_path, fstype, myname);
	sprintf(alter_path, "%s/%s/%s", alt_path, fstype, myname);
	newargv[1] = myname;

	if (Vflg) {
		printf("%s -F %s", newargv[1], fstype);
		for (i = 2; newargv[i]; i++)
			printf(" %s", newargv[i]);
		printf("\n");
		fflush(stdout);
		exit(0);
	}

	/*
	 * Try to exec the fstype dependent portion of the mount.
	 * See if the directory is there before trying to exec dependent
	 * portion.  This is only useful for eliminating the
	 * '..mount: not found' message when '/usr' is mounted
	 */
	if (access(full_path, 0) == 0) {
		execv(full_path, &newargv[1]);
		if (errno == EACCES) {
			fprintf(stderr,
			gettext("%s: Cannot execute %s - permission denied\n"),
			    myname, full_path);
		}
		if (errno == ENOEXEC) {
			newargv[0] = "sh";
			newargv[1] = full_path;
			execv("/sbin/sh", &newargv[0]);
		}
	}
	execv(alter_path, &newargv[1]);
	if (errno == EACCES) {
		fprintf(stderr, gettext(
		    "%s: Cannot execute %s - permission denied\n"),
		    myname, alter_path);
		exit(1);
	}
	if (errno == ENOEXEC) {
		newargv[0] = "sh";
		newargv[1] = alter_path;
		execv("/sbin/sh", &newargv[0]);
	}
	fprintf(stderr,
	    gettext("%s: Operation not applicable to FSType %s\n"),
	    myname, fstype);
	exit(1);
}

char *mntopts[] = { MNTOPT_IGNORE, NULL };
#define	IGNORE    0

/*
 * Return 1 if "ignore" appears in the options string
 */
int
ignore(char *opts)
{
	char *value;
	char *saveptr, *my_opts;
	int rval = 0;

	if (opts == NULL || *opts == NULL)
		return (0);

	/*
	 * we make a copy of the option string to pass to getsubopt(),
	 * because getsubopt() modifies the string.  We also save
	 * the original pointer returned by strdup, because getsubopt
	 * changes the pointer passed into it.  If strdup fails (unlikely),
	 * we act as if the "ignore" option isn't set rather than fail.
	 */

	if ((saveptr = my_opts = strdup(opts)) == NULL)
		nomem();

	while (*my_opts != '\0') {
		if (getsubopt(&my_opts, mntopts, &value) == IGNORE)
			rval = 1;
	}

	free(saveptr);

	return (rval);
}

/*
 * Perform the parallel version of mount.  If count == 0, mount all
 * vfstab filesystems with the automnt field == "yes".  Use fstype if
 * supplied.  If mntlist supplied, then attempt to only mount those.
 */

int
parmount(char **mntlist, int count, char *fstype)
{
	int 		maxfd =	OPEN_MAX;
	struct 		rlimit rl;
	vfsent_t	**vl, *vp;

	/*
	 * Process scaling.  After running a series
	 * of tests based on the number of simultaneous processes and
	 * processors available, optimum performance was achieved near or
	 * at (PROCN * 2).
	 */
	if ((maxrun = sysconf(_SC_NPROCESSORS_ONLN)) == -1)
		maxrun = 4;
	else
		maxrun = maxrun * 2 + 1;

	if (getrlimit(RLIMIT_NOFILE, &rl) == 0) {
		rl.rlim_cur = rl.rlim_max;
		if (setrlimit(RLIMIT_NOFILE, &rl) == 0)
			maxfd = (int)rl.rlim_cur;
	}
	(void) enable_extended_FILE_stdio(-1, -1);

	/*
	 * The parent needs to maintain 3 of its own fd's, plus 2 for
	 * each child (the stdout and stderr pipes).
	 */
	maxfd = (maxfd / 2) - 6;	/* 6 takes care of temporary  */
					/* periods of open fds */
	if (maxfd < maxrun)
		maxrun = maxfd;
	if (maxrun < 4)
		maxrun = 4;		/* sanity check */

	if (count == 0)
		mntlist = NULL;		/* used as a flag later */
	else
		fstype = NULL;		/* mount points supplied: */
					/* ignore fstype */
	/*
	 * Read the whole vfstab into a linked list for quick processing.
	 * On average, this is the most efficient way to collect and
	 * manipulate the vfstab data.
	 */
	vfsll = getvfsall(fstype, mntlist == NULL);

	/*
	 * Make an array out of the vfs linked list for sorting purposes.
	 */
	if (vfsll == NULL ||
	    (vfsarray = make_vfsarray(mntlist, count)) == NULL) {
		if (mntlist == NULL)	/* not an error - just none found */
			return (0);

		fprintf(stderr, gettext("%s: No valid entries found in %s\n"),
		    myname, vfstab);
		return (1);
	}

	/*
	 * Sort the entries based on their resolved path names
	 *
	 * If an lofs is encountered, then the original order of the vfstab
	 * file needs to be maintained until we are done mounting lofs's.
	 */
	if (!lofscnt)
		qsort((void *)vfsarray, vfsarraysize, sizeof (vfsent_t *),
		    mlevelcmp);

	/*
	 * Shrink the vfsll linked list down to the new list.  This will
	 * speed up the pid search in cleanupkid() later.
	 */
	vfsll = vfsarray[0];
	for (vl = vfsarray; vp = *vl; )
		vp->next = *++vl;

	/*
	 * Try to handle interrupts in a reasonable way.
	 */
	sigset(SIGHUP, cleanup);
	sigset(SIGQUIT, cleanup);
	sigset(SIGINT, cleanup);

	do_mounts();		/* do the mounts */

	if (failcnt > 0 && failcnt == lofsfail)
		return (ALL_LOFS_FAILURES);

	return (exitcode);
}

/*
 * Read all vstab (fp) entries into memory if fstype == NULL.
 * If fstype is specified, than read all those that match it.
 *
 * Returns a linked list.
 */
vfsent_t *
getvfsall(char *fstype, int takeall)
{
	vfsent_t	*vhead, *vtail;
	struct vfstab 	vget;
	FILE		*fp;
	int		cnt = 0, ret;

	if ((fp = fopen(vfstab, "r")) == NULL) {
		fprintf(stderr, gettext("%s: Cannot open %s\n"),
		    myname, vfstab);
		exit(1);
	}

	vhead = vtail = NULL;

	while ((ret = getvfsent(fp, &vget)) != -1) {
		vfsent_t *vp;

		if (ret > 0) {
			vfserror(ret, vget.vfs_mountp);
			continue;
		}

		/*
		 * If mount points were not specified, then we ignore
		 * entries that aren't marked "yes".
		 */
		if (takeall &&
		    (vget.vfs_automnt == NULL ||
		    strcmp(vget.vfs_automnt, "yes")))
			continue;

		if (fstype && vget.vfs_fstype &&
		    strcmp(fstype, vget.vfs_fstype))
			continue;

		if (vget.vfs_mountp == NULL ||
		    (vget.vfs_fstype && (strcmp(vget.vfs_fstype, "swap") == 0)))
			continue;

		if (check_fields(vget.vfs_fstype, vget.vfs_mountp)) {
			exitcode = 1;
			continue;
		}

		vp = new_vfsent(&vget, cnt);	/* create new vfs entry */
		if (vhead == NULL)
			vhead = vp;
		else
			vtail->next = vp;
		vtail = vp;
		cnt++;
	}
	fclose(fp);
	if (vtail == NULL) {
		vfsarraysize = 0;
		vfslltail = NULL;
		return (NULL);
	}
	vtail->next = NULL;
	vfslltail = vtail;	/* save it in the global variable */
	vfsarraysize = cnt;
	return (vhead);
}


/*
 * Returns an array of vfsent_t's based on vfsll & mntlist.
 */
vfsent_t **
make_vfsarray(char **mntlist, int count)
{
	vfsent_t 	*vp, *vmark, *vpprev, **vpp;
	int		ndx, found;

	if (vfsll == NULL)
		return (NULL);

	if (count > 0)
		vfsarraysize = count;

	vpp = (vfsent_t **)malloc(sizeof (*vpp) * (vfsarraysize + 1));
	if (vpp == NULL)
		nomem();

	if (mntlist == NULL) {
		/*
		 * No mount list specified: take all vfstab mount points.
		 */
		for (ndx = 0, vp = vfsll; vp; vp = vp->next) {
			(void) setrpath(vp);
			/*
			 * Sigh. lofs entries can complicate matters so much
			 * that the best way to avoid problems is to
			 * stop parallel mounting when an lofs is
			 * encountered, so we keep a count of how many
			 * there are.
			 * Fortunately this is rare.
			 */
			if (vp->v.vfs_fstype &&
			    (strcmp(vp->v.vfs_fstype, MNTTYPE_LOFS) == 0))
				lofscnt++;

			vpp[ndx++] = vp;
		}
		vpp[ndx] = NULL;
		return (vpp);
	}

	/*
	 * A list of mount points was specified on the command line
	 * and we need to search for each one.
	 */
	vpprev = vfslltail;
	vpprev->next = vfsll;	/* make a circle out of it */
	vmark = vp = vfsll;
	/*
	 * For each specified mount point:
	 */
	for (ndx = 0; *mntlist; mntlist++) {
		found = 0;
		/*
		 * Circle our entire linked list, looking for *mntlist.
		 */
		while (vp) {
			if (strcmp(*mntlist, vp->v.vfs_mountp) == 0) {
				vpp[ndx++] = vp;	/* found it. */
				(void) setrpath(vp);
				if (vp->v.vfs_fstype &&
				    (strcmp(vp->v.vfs_fstype,
				    MNTTYPE_LOFS) == 0))
					lofscnt++;

				if (vp == vpprev) {	/* list exhausted */
					vp = NULL;
					found++;
					break;
				}
				/*
				 * Remove it from the circular list.  vpprev
				 * remains unchanged.
				 */
				vp = vp->next;
				vpprev->next->next = NULL;
				vpprev->next = vp;
				/*
				 * Set vmark to the first elem that we check
				 * each time.
				 */
				vmark = vp;
				found++;
				break;
			}
			vpprev = vp;
			vp = vp->next;
			if (vp == vmark)	/* break out if we completed */
						/* the circle */
				break;
		}

		if (!found) {
			fprintf(stderr, gettext(
			    "%s: Warning: %s not found in %s\n"),
			    myname, *mntlist, vfstab);
			exitcode = 1;
		}
	}
	if (ndx == 0)
		return (NULL);

	vpp[ndx] = NULL;	/* null terminate the list */
	vfsarraysize = ndx;	/* adjust vfsarraysize */
	return (vpp);
}

/*
 * Performs the exec argument processing, all  of the child forking and
 * execing, and child cleanup.
 * Sets exitcode to non-zero if any errors occurred.
 */
void
do_mounts(void)
{
	int 		i, isave, cnt;
	vfsent_t 	*vp, *vpprev, **vl;
	char		*newargv[ARGV_MAX];
	pid_t		child;

	/*
	 * create the arg list once;  the only differences among
	 * the calls are the options, special and mountp fields.
	 */
	i = 2;
	if (cflg)
		newargv[i++] = "-c";
	if (gflg)
		newargv[i++] = "-g";
	if (mflg)
		newargv[i++] = "-m";
	if (Oflg)
		newargv[i++] = "-O";
	if (qflg)
		newargv[i++] = "-q";
	if (rflg)
		newargv[i++] = "-r";
	if (dashflg)
		newargv[i++] = "--";
	if (oflg) {
		newargv[i++] = "-o";
		newargv[i++] = specific_opts;
	}
	isave = i;

	/*
	 * Main loop for the mount processes
	 */
	vl = vfsarray;
	cnt = vfsarraysize;
	for (vpprev = *vl; vp = *vl; vpprev = vp, vl++, cnt--) {
		/*
		 * Check to see if we cross a mount level: e.g.,
		 * /a/b -> /a/b/c.  If so, we need to wait for all current
		 * mounts to finish, rerun realpath on the remaining mount
		 * points, and resort the list.
		 *
		 * Also, we mount serially as long as there are lofs's
		 * to mount to avoid improper mount ordering.
		 */
		if (vp->mlevel > vpprev->mlevel || lofscnt > 0) {
			vfsent_t **vlp;

			while (nrun > 0 && (dowait() != -1))
				;
			/*
			 * Gads! It's possible for real path mounts points to
			 * change after mounts are done at a lower mount
			 * level.
			 * Thus, we need to recalculate mount levels and
			 * resort the list from this point.
			 */
			for (vlp = vl; *vlp; vlp++)
				(void) setrpath(*vlp);
			/*
			 * Sort the remaining entries based on their newly
			 * resolved path names.
			 * Do not sort if we still have lofs's to mount.
			 */
			if (lofscnt == 0) {
				qsort((void *)vl, cnt, sizeof (vfsent_t *),
				    mlevelcmp);
				vp = *vl;
			}
		}

		if (vp->flag & VRPFAILED) {
			fprintf(stderr, gettext(
			    "%s: Nonexistent mount point: %s\n"),
			    myname, vp->v.vfs_mountp);
			vp->flag |= VNOTMOUNTED;
			exitcode = 1;
			continue;
		}

		/*
		 * If mount options were not specified on the command
		 * line, then use the ones found in the vfstab entry,
		 * if any.
		 */
		i = isave;
		if (!oflg && vp->v.vfs_mntopts) {
			newargv[i++] = "-o";
			newargv[i++] = vp->v.vfs_mntopts;
		}
		newargv[i++] = vp->v.vfs_special;
		newargv[i++] = vp->rpath;
		newargv[i] = NULL;

		/*
		 * This should never really fail.
		 */
		while (setup_iopipe(vp) == -1 && (dowait() != -1))
			;

		while (nrun >= maxrun && (dowait() != -1))	/* throttle */
			;

		if ((child = fork()) == -1) {
			perror("fork");
			cleanup(-1);
			/* not reached */
		}
		if (child == 0) {		/* child */
			signal(SIGHUP, SIG_IGN);
			signal(SIGQUIT, SIG_IGN);
			signal(SIGINT, SIG_IGN);
			setup_output(vp);
			doexec(vp->v.vfs_fstype, newargv);
			perror("exec");
			exit(1);
		}

		/* parent */
		(void) close(vp->sopipe[WRPIPE]);
		(void) close(vp->sepipe[WRPIPE]);
		vp->pid = child;
		nrun++;
	}
	/*
	 * Mostly done by now - wait and clean up the stragglers.
	 */
	cleanup(0);
}


/*
 * Setup stdout and stderr pipes for the children's output.
 */
int
setup_iopipe(vfsent_t *mp)
{
	/*
	 * Make a stdout and stderr pipe.  This should never fail.
	 */
	if (pipe(mp->sopipe) == -1)
		return (-1);
	if (pipe(mp->sepipe) == -1) {
		(void) close(mp->sopipe[RDPIPE]);
		(void) close(mp->sopipe[WRPIPE]);
		return (-1);
	}
	/*
	 * Don't block on an empty pipe.
	 */
	(void) fcntl(mp->sopipe[RDPIPE], F_SETFL, O_NDELAY|O_NONBLOCK);
	(void) fcntl(mp->sepipe[RDPIPE], F_SETFL, O_NDELAY|O_NONBLOCK);
	/*
	 * Don't pass extra fds into children.
	 */
	(void) fcntl(mp->sopipe[RDPIPE], F_SETFD, FD_CLOEXEC);
	(void) fcntl(mp->sepipe[RDPIPE], F_SETFD, FD_CLOEXEC);

	return (0);
}

/*
 * Called by a child to attach its stdout and stderr to the write side of
 * the pipes.
 */
void
setup_output(vfsent_t *vp)
{

	(void) close(fileno(stdout));
	(void) dup(vp->sopipe[WRPIPE]);
	(void) close(vp->sopipe[WRPIPE]);

	(void) close(fileno(stderr));
	(void) dup(vp->sepipe[WRPIPE]);
	(void) close(vp->sepipe[WRPIPE]);
}

/*
 * Parent uses this to print any stdout or stderr output issued by
 * the child.
 */
static void
doio(vfsent_t *vp)
{
	int bytes;
	char ibuf[BUFSIZ];

	while ((bytes = read(vp->sepipe[RDPIPE], ibuf, sizeof (ibuf))) > 0)
		write(fileno(stderr), ibuf, bytes);
	while ((bytes = read(vp->sopipe[RDPIPE], ibuf, sizeof (ibuf))) > 0)
		write(fileno(stdout), ibuf, bytes);

	(void) close(vp->sopipe[RDPIPE]);
	(void) close(vp->sepipe[RDPIPE]);
}

/*
 * Waits for 1 child to die.
 *
 * Returns -1 if no children are left to wait for.
 * Returns 0 if a child died without an error.
 * Returns 1 if a child died with an error.
 */
int
dowait(void)
{
	int child, wstat;

	if ((child = wait(&wstat)) == -1)
		return (-1);
	nrun--;
	return (cleanupkid(child, wstat) != 0);
}

/*
 * Locates the child mount process represented by pid, outputs any io
 * it may have, and returns its exit code.
 * Sets the global exitcode if an error occurred.
 */
int
cleanupkid(pid_t pid, int wstat)
{
	vfsent_t *vp, *prevp;
	int ret;

	if (WIFEXITED(wstat))		/* this should always be true */
		ret = WEXITSTATUS(wstat);
	else
		ret = 1;		/* assume some kind of error */
	if (ret) {
		exitcode = 1;
		failcnt++;
	}

	/*
	 * Find our child.
	 * This search gets smaller and smaller as children are cleaned
	 * up.
	 */
	for (prevp = NULL, vp = vfsll; vp; vp = vp->next) {
		if (vp->pid != pid) {
			prevp = vp;
			continue;
		}
		/*
		 * Found: let's remove it from this linked list.
		 */
		if (prevp) {
			prevp->next = vp->next;
			vp->next = NULL;
		}
		break;
	}

	if (vp == NULL) {
		/*
		 * This should never happen.
		 */
		fprintf(stderr, gettext(
		    "%s: Unknown child %d\n"), myname, pid);
		exitcode = 1;
		return (ret);
	}
	doio(vp);	/* Any output? */

	if (vp->v.vfs_fstype &&
	    (strcmp(vp->v.vfs_fstype, MNTTYPE_LOFS) == 0)) {
		lofscnt--;
		if (ret)
			lofsfail++;
	}

	vp->exitcode = ret;
	return (ret);
}


static vfsent_t zvmount = { 0 };

vfsent_t *
new_vfsent(struct vfstab *vin, int order)
{
	vfsent_t *new;

	new = (vfsent_t *)malloc(sizeof (*new));
	if (new == NULL)
		nomem();

	*new = zvmount;
	if (vin->vfs_special &&
	    (new->v.vfs_special = strdup(vin->vfs_special)) == NULL)
		nomem();
	if (vin->vfs_mountp &&
	    (new->v.vfs_mountp = strdup(vin->vfs_mountp)) == NULL)
		nomem();
	if (vin->vfs_fstype &&
	    (new->v.vfs_fstype = strdup(vin->vfs_fstype)) == NULL)
		nomem();
	/*
	 * If specific mount options were specified on the command
	 * line, then use those.  Else, use the ones on the vfstab
	 * line, if any.  In other words, specific options on the
	 * command line override those in /etc/vfstab.
	 */
	if (oflg) {
		if ((new->v.vfs_mntopts = strdup(specific_opts)) == NULL)
			nomem();
	} else if (vin->vfs_mntopts &&
	    (new->v.vfs_mntopts = strdup(vin->vfs_mntopts)) == NULL)
			nomem();

	new->order = order;
	return (new);
}

/*
 * Runs realpath on vp's mount point, records success or failure,
 * resets the mount level based on the new realpath, and returns
 * realpath()'s return value.
 */
char *
setrpath(vfsent_t *vp)
{
	char *rp;

	if ((rp = realpath(vp->v.vfs_mountp, realdir)) == NULL)
		vp->flag |= VRPFAILED;
	else
		vp->flag &= ~VRPFAILED;

	if (vp->rpath)
		free(vp->rpath);
	if ((vp->rpath = strdup(realdir)) == NULL)
		nomem();
	vp->mlevel = fsgetmlevel(vp->rpath);
	return (rp);
}


/*
 * sort first by mlevel (1...N), then by vfstab order.
 */
int
mlevelcmp(const void *a, const void *b)
{
	vfsent_t *a1, *b1;
	int	lcmp;

	a1 = *(vfsent_t **)a;
	b1 = *(vfsent_t **)b;

	lcmp = a1->mlevel - b1->mlevel;
	if (lcmp == 0)
		lcmp = a1->order - b1->order;
	return (lcmp);
}

/* sort by vfstab order.  0..N */
static int
mordercmp(const void *a, const void *b)
{
	vfsent_t *a1, *b1;

	a1 = *(vfsent_t **)a;
	b1 = *(vfsent_t **)b;
	return (a1->order - b1->order);
}

/*
 * cleanup the existing children and exit with an error
 * if asig != 0.
 */
void
cleanup(int asig)
{
	while (nrun > 0 && (dowait() != -1))
		;

	if (asig != 0)
		exit(1);
}


int
check_fields(char *fstype, char *mountp)
{
	struct stat64 stbuf;

	if (fstype == NULL) {
		fprintf(stderr,
		    gettext("%s: FSType cannot be determined\n"),
		    myname);
		return (1);
	}
	if (strlen(fstype) > (size_t)FSTYPE_MAX) {
		fprintf(stderr,
		    gettext("%s: FSType %s exceeds %d characters\n"),
		    myname, fstype, FSTYPE_MAX);
		return (1);
	}

	if (mountp == NULL) {
		fprintf(stderr,
		    gettext("%s: Mount point cannot be determined\n"),
		    myname);
		return (1);
	}
	if (*mountp != '/') {
		fprintf(stderr, gettext(
		    "%s: Mount point %s is not an absolute pathname.\n"),
		    myname, mountp);
		return (1);
	}
	/*
	 * Don't do some of these checks if aflg because a mount point may
	 * not exist now, but will be mounted before we get to it.
	 * This is one of the quirks of "secondary mounting".
	 */
	if (!aflg && stat64(mountp, &stbuf) < 0) {
		if (errno == ENOENT || errno == ENOTDIR)
			fprintf(stderr,
			    gettext("%s: Mount point %s does not exist.\n"),
			    myname, mountp);
		else {
			fprintf(stderr,
			    gettext("%s: Cannot stat mount point %s.\n"),
			    myname, mountp);
			perror(myname);
		}
		return (1);
	}
	return (0);
}

void
nomem(void)
{
	fprintf(stderr, gettext("%s: Out of memory\n"), myname);
	while (nrun > 0 && (dowait() != -1))
		;
	exit(1);
}
