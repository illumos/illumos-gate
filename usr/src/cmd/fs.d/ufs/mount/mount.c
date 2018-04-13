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

/*
 * mount
 */
#include <ctype.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#include <poll.h>
#include <sys/mkdev.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/mntent.h>
#include <stdlib.h>

#define	bcopy(f, t, n)	memcpy(t, f, n)
#define	bzero(s, n)	memset(s, 0, n)
#define	bcmp(s, d, n)	memcmp(s, d, n)

#define	index(s, r)	strchr(s, r)
#define	rindex(s, r)	strrchr(s, r)

#include <errno.h>
#include <sys/vfs.h>
#include <sys/stat.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/mnttab.h>
#include <sys/mount.h>
#include <sys/mntio.h>
#include <sys/wait.h>
#include <sys/fstyp.h>
#include <sys/fsid.h>
#include <sys/vfstab.h>
#include <sys/filio.h>
#include <sys/fs/ufs_fs.h>

#include <sys/fs/ufs_mount.h>
#include <sys/fs/ufs_filio.h>

#include <locale.h>
#include <fslib.h>

static int	ro = 0;
static int	largefiles = 0; /* flag - add default nolargefiles to mnttab */

static int	gflg = 0;
static int	mflg = 0;
static int 	Oflg = 0;
static int	qflg = 0;

#define	NAME_MAX	64		/* sizeof "fstype myname" */

static int	checkislog(char *);
static void	disable_logging(char *, char *);
static int	eatmntopt(struct mnttab *, char *);
static void	enable_logging(char *, char *);
static void	fixopts(struct mnttab *, char *);
static void	mountfs(struct mnttab *);
static void	replace_opts(char *, int, char *, char *);
static int	replace_opts_dflt(char *, int, const char *, const char *);
static void	rmopt(struct mnttab *, char *);
static void	rpterr(char *, char *);
static void	usage(void);

static char	fstype[] = MNTTYPE_UFS;
static char	opts[MAX_MNTOPT_STR];
static char	typename[NAME_MAX], *myname;
static char	*fop_subopts[] = { MNTOPT_ONERROR, NULL };
#define	NOMATCH	(-1)
#define	ONERROR	(0)		/* index within fop_subopts */

static struct fop_subopt {
	char	*str;
	int	 flag;
} fop_subopt_list[] = {
	{ UFSMNT_ONERROR_PANIC_STR,	UFSMNT_ONERROR_PANIC	},
	{ UFSMNT_ONERROR_LOCK_STR,	UFSMNT_ONERROR_LOCK	},
	{ UFSMNT_ONERROR_UMOUNT_STR,	UFSMNT_ONERROR_UMOUNT	},
	{ NULL,				UFSMNT_ONERROR_DEFAULT	}
};


/*
 * Check if the specified filesystem is already mounted.
 */
static boolean_t
in_mnttab(char *mountp)
{
	FILE *file;
	int found = B_FALSE;
	struct mnttab mntent;

	if ((file = fopen(MNTTAB, "r")) == NULL)
		return (B_FALSE);
	while (getmntent(file, &mntent) == 0) {
		if (mntent.mnt_mountp != NULL &&
		    strcmp(mntent.mnt_mountp, mountp) == 0 &&
		    mntent.mnt_fstype != NULL &&
		    strcmp(mntent.mnt_fstype, MNTTYPE_UFS) == 0) {
			found = B_TRUE;
			break;
		}
	}
	(void) fclose(file);
	return (found);
}

/*
 * Find opt in mntopt
 */
static char *
findopt(char *mntopt, char *opt)
{
	int nc, optlen = strlen(opt);

	while (*mntopt) {
		nc = strcspn(mntopt, ", =");
		if (strncmp(mntopt, opt, nc) == 0)
			if (optlen == nc)
				return (mntopt);
		mntopt += nc;
		mntopt += strspn(mntopt, ", =");
	}
	return (NULL);
}

int
main(int argc, char *argv[])
{
	struct mnttab mnt;
	int	c;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN	"SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	myname = strrchr(argv[0], '/');
	if (myname)
		myname++;
	else
		myname = argv[0];
	(void) snprintf(typename, sizeof (typename), "%s %s", fstype, myname);
	argv[0] = typename;

	opts[0] = '\0';

	/*
	 * Set options
	 */
	while ((c = getopt(argc, argv, "gmo:pqrVO")) != EOF) {
		switch (c) {

		case 'g':
			gflg++;
			break;

		case 'o':
			if (strlcpy(opts, optarg, sizeof (opts)) >=
			    sizeof (opts)) {
				(void) fprintf(stderr, gettext("option string "
				    "argument too long\n"));
			}
			break;

		case 'O':
			Oflg++;
			break;

		case 'r':
			ro++;
			break;

		case 'm':
			mflg++;
			break;

		case 'q':
			qflg++;
			break;

		default:
			usage();
		}
	}

	if ((argc - optind) != 2)
		usage();

	mnt.mnt_special = argv[optind];
	mnt.mnt_mountp = argv[optind+1];
	mnt.mnt_fstype = fstype;

	/*
	 * Process options.  The resulting options string overwrites the
	 * original.
	 *
	 * XXX:	This code doesn't do a good job of resolving options that are
	 *	specified multiple times or that are given in conflicting
	 *	forms (e.g., both "largefiles" and "nolargefiles").  It also
	 *	doesn't produce well defined behavior for options that may
	 *	also be specified as flags (e.g, "-r" and "ro"/"rw") when both
	 *	are present.
	 *
	 *	The proper way to deal with such conflicts is to start with
	 *	the default value (i.e., the one if no flag or option is
	 *	specified), override it with the last mentioned option pair
	 *	in the -o option string, and finally, override that with
	 *	the flag value. This allows "mount -r" command to mount a
	 *	file system read only that is listed rw in /etc/vfstab.
	 */
	mnt.mnt_mntopts = opts;
	if (findopt(mnt.mnt_mntopts, "m"))
		mflg++;
	if ((gflg || findopt(mnt.mnt_mntopts, MNTOPT_GLOBAL)) &&
	    findopt(mnt.mnt_mntopts, MNTOPT_NBMAND)) {
		(void) fprintf(stderr, gettext("NBMAND option not supported on"
		" global filesystem\n"));
		exit(32);
	}

	replace_opts(opts, ro, MNTOPT_RO, MNTOPT_RW);
	replace_opts(opts, largefiles, MNTOPT_NOLARGEFILES, MNTOPT_LARGEFILES);
	gflg = replace_opts_dflt(opts, gflg, MNTOPT_GLOBAL, MNTOPT_NOGLOBAL);

	if (findopt(mnt.mnt_mntopts, MNTOPT_RQ)) {
		rmopt(&mnt, MNTOPT_RQ);
		replace_opts(opts, 1, MNTOPT_QUOTA, MNTOPT_NOQUOTA);
	}

	mountfs(&mnt);
	return (0);
}

static void
reportlogerror(int ret, char *mp, char *special, char *cmd, fiolog_t *flp)
{
	/* No error */
	if ((ret != -1) && (flp->error == FIOLOG_ENONE))
		return;

	/* logging was not enabled/disabled */
	if (ret == -1 || flp->error != FIOLOG_ENONE)
		(void) fprintf(stderr, gettext("Could not %s logging"
		" for %s on %s.\n"), cmd, mp, special);

	/* ioctl returned error */
	if (ret == -1)
		return;

	/* Some more info */
	switch (flp->error) {
	case FIOLOG_ENONE :
		if (flp->nbytes_requested &&
		    (flp->nbytes_requested != flp->nbytes_actual)) {
			(void) fprintf(stderr, gettext("The log has been"
			" resized from %d bytes to %d bytes.\n"),
			    flp->nbytes_requested,
			    flp->nbytes_actual);
		}
		return;
	case FIOLOG_ETRANS :
		(void) fprintf(stderr, gettext("Solaris Volume Manager logging"
		" is already enabled.\n"));
		(void) fprintf(stderr, gettext("Please see the"
		" commands metadetach(1M)"
		" or metaclear(1M).\n"));
		break;
	case FIOLOG_EROFS :
		(void) fprintf(stderr, gettext("File system is mounted read "
		"only.\n"));
		(void) fprintf(stderr, gettext("Please see the remount "
		"option described in mount_ufs(1M).\n"));
		break;
	case FIOLOG_EULOCK :
		(void) fprintf(stderr, gettext("File system is locked.\n"));
		(void) fprintf(stderr, gettext("Please see the -u option "
		"described in lockfs(1M).\n"));
		break;
	case FIOLOG_EWLOCK :
		(void) fprintf(stderr, gettext("The file system could not be"
		" write locked.\n"));
		(void) fprintf(stderr, gettext("Please see the -w option "
		"described in lockfs(1M).\n"));
		break;
	case FIOLOG_ECLEAN :
		(void) fprintf(stderr, gettext("The file system may not be"
		" stable.\n"));
		(void) fprintf(stderr, gettext("Please see the -n option"
		" for fsck(1M).\n"));
		break;
	case FIOLOG_ENOULOCK :
		(void) fprintf(stderr, gettext("The file system could not be"
		" unlocked.\n"));
		(void) fprintf(stderr, gettext("Please see the -u option "
		"described in lockfs(1M).\n"));
		break;
	default :
		(void) fprintf(stderr, gettext("Unknown internal error"
		" %d.\n"), flp->error);
		break;
	}
}

static int
checkislog(char *mp)
{
	int fd;
	uint32_t islog;

	fd = open(mp, O_RDONLY);
	islog = 0;
	(void) ioctl(fd, _FIOISLOG, &islog);
	(void) close(fd);
	return ((int)islog);
}

static void
enable_logging(char *mp, char *special)
{
	int fd, ret, islog;
	fiolog_t fl;

	fd = open(mp, O_RDONLY);
	if (fd == -1) {
		perror(mp);
		return;
	}
	fl.nbytes_requested = 0;
	fl.nbytes_actual = 0;
	fl.error = FIOLOG_ENONE;
	ret = ioctl(fd, _FIOLOGENABLE, &fl);
	if (ret == -1)
		perror(mp);
	(void) close(fd);

	/* is logging enabled? */
	islog = checkislog(mp);

	/* report errors, if any */
	if (ret == -1 || !islog)
		reportlogerror(ret, mp, special, "enable", &fl);
}

static void
disable_logging(char *mp, char *special)
{
	int fd, ret, islog;
	fiolog_t fl;

	fd = open(mp, O_RDONLY);
	if (fd == -1) {
		perror(mp);
		return;
	}
	fl.error = FIOLOG_ENONE;
	ret = ioctl(fd, _FIOLOGDISABLE, &fl);
	if (ret == -1)
		perror(mp);
	(void) close(fd);

	/* is logging enabled? */
	islog = checkislog(mp);

	/* report errors, if any */
	if (ret == -1 || islog)
		reportlogerror(ret, mp, special, "disable", &fl);
}


/*
 * attempt to mount file system, return errno or 0
 */
void
mountfs(struct mnttab *mnt)
{
	char			 opt[MAX_MNTOPT_STR];
	char			 opt2[MAX_MNTOPT_STR];
	char			*opts =	opt;
	int			 flags = MS_OPTIONSTR;
	struct ufs_args		 args;
	int			 need_separator = 0;
	int			mount_attempts = 5;

	(void) bzero((char *)&args, sizeof (args));
	(void) strcpy(opts, mnt->mnt_mntopts);
	opt2[0] = '\0';

	flags |= Oflg ? MS_OVERLAY : 0;
	flags |= eatmntopt(mnt, MNTOPT_RO) ? MS_RDONLY : 0;
	flags |= eatmntopt(mnt, MNTOPT_REMOUNT) ? MS_REMOUNT : 0;
	flags |= eatmntopt(mnt, MNTOPT_GLOBAL) ? MS_GLOBAL : 0;

	if (eatmntopt(mnt, MNTOPT_NOINTR))
		args.flags |= UFSMNT_NOINTR;
	if (eatmntopt(mnt, MNTOPT_INTR))
		args.flags &= ~UFSMNT_NOINTR;
	if (eatmntopt(mnt, MNTOPT_SYNCDIR))
		args.flags |= UFSMNT_SYNCDIR;
	if (eatmntopt(mnt, MNTOPT_FORCEDIRECTIO)) {
		args.flags |= UFSMNT_FORCEDIRECTIO;
		args.flags &= ~UFSMNT_NOFORCEDIRECTIO;
	}
	if (eatmntopt(mnt, MNTOPT_NOFORCEDIRECTIO)) {
		args.flags |= UFSMNT_NOFORCEDIRECTIO;
		args.flags &= ~UFSMNT_FORCEDIRECTIO;
	}
	if (eatmntopt(mnt, MNTOPT_NOSETSEC))
		args.flags |= UFSMNT_NOSETSEC;
	if (eatmntopt(mnt, MNTOPT_LARGEFILES))
		args.flags |= UFSMNT_LARGEFILES;
	if (eatmntopt(mnt, MNTOPT_NOLARGEFILES))
		args.flags &= ~UFSMNT_LARGEFILES;
	args.flags |= UFSMNT_LOGGING;	/* default is logging */
	(void) eatmntopt(mnt, MNTOPT_LOGGING);
	if (eatmntopt(mnt, MNTOPT_NOLOGGING))
		args.flags &= ~UFSMNT_LOGGING;
	if (eatmntopt(mnt, MNTOPT_NOATIME))
		args.flags |= UFSMNT_NOATIME;
	if (eatmntopt(mnt, MNTOPT_DFRATIME))
		args.flags &= ~UFSMNT_NODFRATIME;
	if (eatmntopt(mnt, MNTOPT_NODFRATIME))
		args.flags |= UFSMNT_NODFRATIME;

	while (*opts != '\0') {
		char	*argval;

		switch (getsubopt(&opts, fop_subopts, &argval)) {
		case ONERROR:
			if (argval) {
				struct fop_subopt	*s;
				int			 found = 0;

				for (s = fop_subopt_list;
				    s->str && !found;
				    s++) {
					if (strcmp(argval, s->str) == 0) {
						args.flags |= s->flag;
						found = 1;
					}
				}
				if (!found) {
					usage();
				}

				if (need_separator)
					(void) strcat(opt2, ",");
				(void) strcat(opt2, MNTOPT_ONERROR);
				(void) strcat(opt2, "=");
				(void) strcat(opt2, argval);
				need_separator = 1;

			} else {
				args.flags |= UFSMNT_ONERROR_DEFAULT;
			}
			break;

		case NOMATCH:
		default:
			if (argval) {
				if (need_separator)
					(void) strcat(opt2, ",");
				(void) strcat(opt2, argval);
				need_separator = 1;
			}
			break;

		}
	}

	if (*opt2 != '\0')
		(void) strcpy(opt, opt2);
	opts = opt;
	if ((args.flags & UFSMNT_ONERROR_FLGMASK) == 0)
		args.flags |= UFSMNT_ONERROR_DEFAULT;

	(void) signal(SIGHUP,  SIG_IGN);
	(void) signal(SIGQUIT, SIG_IGN);
	(void) signal(SIGINT,  SIG_IGN);

	errno = 0;
	flags |= MS_DATA | MS_OPTIONSTR;
	if (mflg)
		flags |= MS_NOMNTTAB;
	if (flags & MS_REMOUNT) {
		replace_opts(mnt->mnt_mntopts, 1, MNTOPT_RW, MNTOPT_RO);
	}
	fixopts(mnt, opts);

	/*
	 * For global filesystems we want to pass in logging option
	 * so that it shows up in the mnttab of all nodes. We add
	 * logging option if its not specified.
	 */
	if (gflg || findopt(mnt->mnt_mntopts, MNTOPT_GLOBAL)) {
		if (!(flags & MS_RDONLY)) {
			if (mnt->mnt_mntopts[0] != '\0')
				(void) strcat(mnt->mnt_mntopts, ",");
			(void) strcat(mnt->mnt_mntopts, MNTOPT_LOGGING);
			args.flags |= UFSMNT_LOGGING;
		} else {
			/*
			 * Turn off logging for read only global mounts.
			 * It was set to logging as default above.
			 */
			if (mnt->mnt_mntopts[0] != '\0')
				(void) strcat(mnt->mnt_mntopts, ",");
			(void) strcat(mnt->mnt_mntopts, MNTOPT_NOLOGGING);
			args.flags &= ~UFSMNT_LOGGING;
		}
	}

again:	if (mount(mnt->mnt_special, mnt->mnt_mountp, flags, fstype,
	    &args, sizeof (args), mnt->mnt_mntopts, MAX_MNTOPT_STR) != 0) {
		if (errno == EBUSY && !(flags & MS_OVERLAY)) {
			/*
			 * Because of bug 6176743, any attempt to mount any
			 * filesystem could fail for reasons described in that
			 * bug.  We're trying to detect that situation here by
			 * checking that the filesystem we're mounting is not
			 * in /etc/mnttab yet.  When that bug is fixed, this
			 * code can be removed.
			 */
			if (!in_mnttab(mnt->mnt_mountp) &&
			    mount_attempts-- > 0) {
				(void) poll(NULL, 0, 50);
				goto again;
			}
		}
		rpterr(mnt->mnt_special, mnt->mnt_mountp);
		exit(32);
	}

	if (!(flags & MS_RDONLY)) {
		if (args.flags & UFSMNT_LOGGING)
			enable_logging(mnt->mnt_mountp, mnt->mnt_special);
		else
			disable_logging(mnt->mnt_mountp, mnt->mnt_special);
	}

	if (!qflg) {
		cmp_requested_to_actual_options(opts, mnt->mnt_mntopts,
		    mnt->mnt_special, mnt->mnt_mountp);
	}

	if (checkislog(mnt->mnt_mountp)) {
		/* update mnttab file if necessary */
		if (!mflg) {
			struct stat64 statb;
			struct mnttagdesc mtdesc;
			int fd;

			if (stat64(mnt->mnt_mountp, &statb) != 0)
				exit(32);
			/* do tag ioctl */
			mtdesc.mtd_major = major(statb.st_dev);
			mtdesc.mtd_minor = minor(statb.st_dev);
			mtdesc.mtd_mntpt = mnt->mnt_mountp;
			mtdesc.mtd_tag = MNTOPT_LOGGING;
			if ((fd = open(MNTTAB, O_RDONLY, 0)) < 0)
				exit(32);
			if (ioctl(fd, MNTIOC_SETTAG, &mtdesc) != 0) {
				(void) close(fd);
				exit(32);
			}
			(void) close(fd);
		}
	}
	exit(0);
}

/*
 * same as findopt but remove the option from the option string and return
 * true or false
 */
static int
eatmntopt(struct mnttab *mnt, char *opt)
{
	int has;

	has = (findopt(mnt->mnt_mntopts, opt) != NULL);
	rmopt(mnt, opt);
	return (has);
}

/*
 * remove an option string from the option list
 */
static void
rmopt(struct mnttab *mnt, char *opt)
{
	char *str;
	char *optstart;

	while (optstart = findopt(mnt->mnt_mntopts, opt)) {
		for (str = optstart;
		    *str != ','	&& *str != '\0' && *str != ' ';
		    str++)
			/* NULL */;
		if (*str == ',') {
			str++;
		} else if (optstart != mnt->mnt_mntopts) {
			optstart--;
		}
		while (*optstart++ = *str++)
			;
	}
}

/*
 * mnt->mnt_ops has un-eaten opts, opts is the original opts list.
 * Set mnt->mnt_opts to the original, the kernel will then remove
 * the ones it cannot deal with.
 * Set "opts" to the the original options for later comparison in
 * cmp_....().  But strip the options which aren't returned by
 * the kernel: "noglobal", "global" and "quota".
 * And strip the options which aren't set through mount: "logging",
 * "nologging" from those passed to mount(2).
 */
static void
fixopts(struct mnttab *mnt, char *opts)
{
	struct mnttab omnt;

	omnt.mnt_mntopts = opts;

	/*
	 * Options not passed to the kernel and possibly not returned;
	 * these are dealt with using ioctl; and the ioctl may fail.
	 */
	rmopt(&omnt, MNTOPT_LOGGING);
	rmopt(&omnt, MNTOPT_NOLOGGING);

	/*
	 * Set the options for ``/etc/mnttab'' to be the original
	 * options from main(); except for the option "f" and "remount".
	 */
	(void) strlcpy(mnt->mnt_mntopts, opts, MAX_MNTOPT_STR);
	rmopt(mnt, "f");
	rmopt(mnt, MNTOPT_REMOUNT);

	rmopt(&omnt, MNTOPT_GLOBAL);
	rmopt(&omnt, MNTOPT_NOGLOBAL);
	rmopt(&omnt, MNTOPT_QUOTA);
}

static void
usage(void)
{
	(void) fprintf(stdout, gettext(
"ufs usage:\n"
"mount [-F ufs] [generic options] [-o suboptions] {special | mount_point}\n"));
	(void) fprintf(stdout, gettext(
	"\tsuboptions are: \n"
	"\t	ro,rw,nosuid,remount,f,m,\n"
	"\t	global,noglobal,\n"
	"\t	largefiles,nolargefiles,\n"
	"\t	forcedirectio,noforcedirectio\n"
	"\t	logging,nologging,\n"
	"\t	nbmand,nonbmand,\n"
	"\t	onerror[={panic | lock | umount}]\n"));

	exit(32);
}

/*
 * Returns the next option in the option string.
 */
static char *
getnextopt(char **p)
{
	char *cp = *p;
	char *retstr;

	while (*cp && isspace(*cp))
		cp++;
	retstr = cp;
	while (*cp && *cp != ',')
		cp++;
	/* strip empty options */
	while (*cp == ',') {
		*cp = '\0';
		cp++;
	}
	*p = cp;
	return (retstr);
}

/*
 * "trueopt" and "falseopt" are two settings of a Boolean option.
 * If "flag" is true, forcibly set the option to the "true" setting; otherwise,
 * if the option isn't present, set it to the false setting.
 */
static void
replace_opts(char *options, int flag, char *trueopt, char *falseopt)
{
	char *f;
	char *tmpoptsp;
	int found;
	char tmptopts[MNTMAXSTR];

	(void) strcpy(tmptopts, options);
	tmpoptsp = tmptopts;
	(void) strcpy(options, "");

	found = 0;
	for (f = getnextopt(&tmpoptsp); *f; f = getnextopt(&tmpoptsp)) {
		if (options[0] != '\0')
			(void) strcat(options, ",");
		if (strcmp(f, trueopt) == 0) {
			(void) strcat(options, f);
			found++;
		} else if (strcmp(f, falseopt) == 0) {
			if (flag)
				(void) strcat(options, trueopt);
			else
				(void) strcat(options, f);
			found++;
		} else
			(void) strcat(options, f);
	}
	if (!found) {
		if (options[0] != '\0')
			(void) strcat(options, ",");
		(void) strcat(options, flag ? trueopt : falseopt);
	}
}

/*
 * "trueopt" and "falseopt" are two settings of a Boolean option and "dflt" is
 * a default value for the option.  Rewrite the contents of options to include
 * only the last mentioned occurrence of trueopt and falseopt.  If neither is
 * mentioned, append one or the other to options, according to the value of
 * dflt.  Return the resulting value of the option in boolean form.
 *
 * Note that the routine is implemented to have the resulting occurrence of
 * trueopt or falseopt appear at the end of the resulting option string.
 *
 * N.B.	This routine should take the place of replace_opts, but there are
 *	probably some compatibility issues to resolve before doing so.  It
 *	should certainly be used to handle new options that don't have
 *	compatibility issues.
 */
static int
replace_opts_dflt(
	char *options,
	int dflt,
	const char *trueopt,
	const char *falseopt)
{
	char *f;
	char *tmpoptsp;
	int last;
	char tmptopts[MNTMAXSTR];

	/*
	 * Transfer the contents of options to tmptopts, in anticipation of
	 * copying a subset of the contents back to options.
	 */
	(void) strcpy(tmptopts, options);
	tmpoptsp = tmptopts;
	(void) strcpy(options, "");

	/*
	 * Loop over each option value, copying non-matching values back into
	 * options and updating the last seen occurrence of trueopt or
	 * falseopt.
	 */
	last = dflt;
	for (f = getnextopt(&tmpoptsp); *f; f = getnextopt(&tmpoptsp)) {
		/* Check for both forms of the option of interest. */
		if (strcmp(f, trueopt) == 0) {
			last = 1;
		} else if (strcmp(f, falseopt) == 0) {
			last = 0;
		} else {
			/* Not what we're looking for; transcribe. */
			if (options[0] != '\0')
				(void) strcat(options, ",");
			(void) strcat(options, f);
		}
	}

	/*
	 * Transcribe the correct form of the option of interest, using the
	 * default value if it wasn't overwritten above.
	 */
	if (options[0] != '\0')
		(void) strcat(options, ",");
	(void) strcat(options, last ? trueopt : falseopt);

	return (last);
}

static void
rpterr(char *bs, char *mp)
{
	switch (errno) {
	case EPERM:
		(void) fprintf(stderr, gettext("%s: Insufficient privileges\n"),
		    myname);
		break;
	case ENXIO:
		(void) fprintf(stderr, gettext("%s: %s no such device\n"),
		    myname, bs);
		break;
	case ENOTDIR:
		(void) fprintf(stderr,
		    gettext(
	"%s: %s not a directory\n\tor a component of %s is not a directory\n"),
		    myname, mp, bs);
		break;
	case ENOENT:
		(void) fprintf(stderr, gettext(
		    "%s: %s or %s, no such file or directory\n"),
		    myname, bs, mp);
		break;
	case EINVAL:
		(void) fprintf(stderr, gettext("%s: %s is not this fstype\n"),
		    myname, bs);
		break;
	case EBUSY:
		(void) fprintf(stderr,
		    gettext("%s: %s is already mounted or %s is busy\n"),
		    myname, bs, mp);
		break;
	case ENOTBLK:
		(void) fprintf(stderr, gettext(
		    "%s: %s not a block device\n"), myname, bs);
		break;
	case EROFS:
		(void) fprintf(stderr, gettext("%s: %s write-protected\n"),
		    myname, bs);
		break;
	case ENOSPC:
		(void) fprintf(stderr, gettext(
		    "%s: The state of %s is not okay\n"
		    "\tand it was attempted to be mounted read/write\n"),
		    myname, bs);
		(void) printf(gettext(
		    "mount: Please run fsck and try again\n"));
		break;
	case EFBIG:
		(void) fprintf(stderr, gettext(
		    "%s: Large files may be present on %s,\n"
		    "\tand it was attempted to be mounted nolargefiles\n"),
		    myname, bs);
		break;
	default:
		perror(myname);
		(void) fprintf(stderr, gettext("%s: Cannot mount %s\n"),
		    myname, bs);
	}
}
