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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T */
/*	    All Rights Reserved */

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *
 *			mount.c
 *
 * Cachefs mount program.
 */

#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdarg.h>
#include <unistd.h>
#include <limits.h>
#include <errno.h>
#include <wait.h>
#include <ctype.h>
#include <fcntl.h>
#include <fslib.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <sys/mount.h>
#include <sys/mntent.h>
#include <sys/mnttab.h>
#include <sys/mntio.h>
#include <sys/fs/cachefs_fs.h>
#include <sys/utsname.h>
#include <rpc/rpc.h>
#include <kstat.h>
#undef MAX
#include <nfs/nfs.h>
#include <nfs/nfs_clnt.h>
#include <sys/mkdev.h>
#include "../common/subr.h"
#include "../common/cachefsd.h"

char *cfs_opts[] = {
#define	CFSOPT_BACKFSTYPE	0
	"backfstype",
#define	CFSOPT_CACHEDIR		1
	"cachedir",
#define	CFSOPT_CACHEID		2
	"cacheid",
#define	CFSOPT_BACKPATH		3
	"backpath",

#define	CFSOPT_WRITEAROUND	4
	"write-around",
#define	CFSOPT_NONSHARED	5
	"non-shared",

#define	CFSOPT_DISCONNECTABLE	6
	"disconnectable",
#define	CFSOPT_SOFT		7
	"soft",

#define	CFSOPT_NOCONST		8
	"noconst",
#define	CFSOPT_CODCONST		9
	"demandconst",

#define	CFSOPT_LOCALACCESS	10
	"local-access",
#define	CFSOPT_LAZYMOUNT	11
	"lazy-mount",

#define	CFSOPT_RW		12
	"rw",
#define	CFSOPT_RO		13
	"ro",
#define	CFSOPT_SUID		14
	"suid",
#define	CFSOPT_NOSUID		15
	"nosuid",
#define	CFSOPT_REMOUNT		16
	"remount",
#define	CFSOPT_FGSIZE		17
	"fgsize",
#define	CFSOPT_POPSIZE		18
	"popsize",
#define	CFSOPT_ACREGMIN		19
	"acregmin",
#define	CFSOPT_ACREGMAX		20
	"acregmax",
#define	CFSOPT_ACDIRMIN		21
	"acdirmin",
#define	CFSOPT_ACDIRMAX		22
	"acdirmax",
#define	CFSOPT_ACTIMEO		23
	"actimeo",
#define	CFSOPT_SLIDE		24
	"slide",
#define	CFSOPT_NOSETSEC		25
	"nosec",	/* XXX should we use MNTOPT_NOTSETSEC? */
#define	CFSOPT_LLOCK		26
	"llock",
#define	CFSOPT_NONOTIFY		27
	"nonotify",
#define	CFSOPT_SNR		28
	"snr",
#define	CFSOPT_NOFILL		29
	"nofill",
#ifdef CFS_NFSV3_PASSTHROUGH
#define	CFSOPT_NFSV3PASSTHROUGH	30
	"nfsv3pass",
#endif /* CFS_NFSV3_PASSTHROUGH */
	NULL
};

#define	MNTTYPE_CFS	"cachefs"	/* XXX - to be added to mntent.h */
					/* XXX - and should be cachefs */
#define	CFS_DEF_DIR	"/cache"	/* XXX - should be added to cfs.h */

#define	bad(val) (val == NULL || !isdigit(*val))

#define	VFS_PATH	"/usr/lib/fs"
#define	ALT_PATH	"/etc/fs"

/* forward references */
void usage(char *msgp);
void pr_err(char *fmt, ...);
int set_cfs_args(char *optionp, struct cachefs_mountargs *margsp, int *mflagp,
    char **backfstypepp, char **reducepp, int *notifyp, int *nfsv3pass);
int get_mount_point(char *cachedirp, char *specp, char **pathpp);
int dobackmnt(struct cachefs_mountargs *margsp, char *reducep, char *specp,
    char *backfstypep, char *mynamep, int readonly);
void doexec(char *fstype, char **newargv, char *myname);
char *get_back_fsid(char *specp);
char *get_cacheid(char *, char *);
void record_mount(char *mntp, char *specp, char *backfsp, char *backfstypep,
    char *cachedirp, char *cacheidp, char *optionp, char *reducep);
int daemon_notify(char *cachedirp, char *cacheidp);
int pingserver(char *backmntp);
int check_cache(char *cachedirp);
uint32_t cachefs_get_back_nfsvers(char *cfs_backfs, int nomnttab);
int cfs_nfsv4_build_opts(char *optionp, char *cfs_nfsv4ops);

int nomnttab;
int quiet;
/*
 *
 *			main
 *
 * Description:
 *	Main routine for the cachefs mount program.
 * Arguments:
 *	argc	number of command line arguments
 *	argv	list of command line arguments
 * Returns:
 *	Returns 0 for success, 1 an error was encountered.
 * Preconditions:
 */

int
main(int argc, char **argv)
{
	char *myname;
	char *optionp;
	char *opigp;
	int mflag;
	int readonly;
	struct cachefs_mountargs margs;
	char *backfstypep;
	char *reducep;
	char *specp;
	int xx;
	int stat_loc;
	char *newargv[20];
	char *mntp;
	pid_t pid;
	int mounted;
	int c;
	int lockid;
	int Oflg;
	char *strp;
	char servname[33];
	int notify = 1;
	struct stat64 statb;
	struct mnttagdesc mtdesc;
	char mops[MAX_MNTOPT_STR];
	char cfs_nfsv4ops[MAX_MNTOPT_STR];
	uint32_t nfsvers = 0;
	uint32_t nfsvers_error = FALSE;
	int nfsv3pass = 0;
	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN	"SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	if (argv[0]) {
		myname = strrchr(argv[0], '/');
		if (myname)
			myname++;
		else
			myname = argv[0];
	} else {
		myname = "path unknown";
	}

	optionp = NULL;
	nomnttab = 0;
	quiet = 0;
	readonly = 0;
	Oflg = 0;
	cfs_nfsv4ops[0] = '\0';

	/* process command line options */
	while ((c = getopt(argc, argv, "mo:Orq")) != EOF) {
		switch (c) {
		case 'm':	/* no entry in /etc/mnttab */
			nomnttab = 1;
			break;

		case 'o':
			optionp = optarg;
			break;

		case 'O':
			Oflg++;
			break;

		case 'r':	/* read only mount */
			readonly = 1;
			break;

		case 'q':
			quiet = 1;
			break;

		default:
			usage("invalid option");
			return (1);
		}
	}

	/* if -o not specified */
	if (optionp == NULL) {
		usage(gettext("\"-o backfstype\" must be specified"));
		return (1);
	}

	/* verify special device and mount point are specified */
	if (argc - optind < 2) {
		usage(gettext("must specify special device and mount point"));
		return (1);
	}

	/* Store mount point and special device. */
	specp = argv[argc - 2];
	mntp = argv[argc - 1];

	/* Initialize default mount values */
	margs.cfs_options.opt_flags = CFS_ACCESS_BACKFS;
	margs.cfs_options.opt_popsize = DEF_POP_SIZE;
	margs.cfs_options.opt_fgsize = DEF_FILEGRP_SIZE;
	margs.cfs_fsid = NULL;
	memset(margs.cfs_cacheid, 0, sizeof (margs.cfs_cacheid));
	margs.cfs_cachedir = CFS_DEF_DIR;
	margs.cfs_backfs = NULL;
	margs.cfs_acregmin = 0;
	margs.cfs_acregmax = 0;
	margs.cfs_acdirmin = 0;
	margs.cfs_acdirmax = 0;
	mflag = MS_OPTIONSTR;
	if (nomnttab)
		mflag |= MS_NOMNTTAB;
	backfstypep = NULL;

	/* process -o options */
	xx = set_cfs_args(optionp, &margs, &mflag, &backfstypep, &reducep,
	    &notify, &nfsv3pass);
	if (xx) {
		return (1);
	}
	strcpy(mops, optionp);

	/* backfstype has to be specified */
	if (backfstypep == NULL) {
		usage(gettext("\"-o backfstype\" must be specified"));
		return (1);
	}

	if ((strcmp(backfstypep, "nfs") != 0) &&
				(strcmp(backfstypep, "hsfs") != 0)) {
		pr_err(gettext("%s as backfstype is not supported."),
					backfstypep);
		return (1);
	}

	/* set default write mode if not specified */
	if ((margs.cfs_options.opt_flags &
	    (CFS_WRITE_AROUND|CFS_NONSHARED)) == 0) {
		margs.cfs_options.opt_flags |= CFS_WRITE_AROUND;
		if (strcmp(backfstypep, "hsfs") == 0)
			mflag |= MS_RDONLY;
	}

	/* if read-only was specified with the -r option */
	if (readonly) {
		mflag |= MS_RDONLY;
	}

	/* if overlay was specified with -O option */
	if (Oflg) {
		mflag |= MS_OVERLAY;
	}

	/* get the fsid of the backfs and the cacheid */
	margs.cfs_fsid = get_back_fsid(specp);
	if (margs.cfs_fsid == NULL) {
		pr_err(gettext("out of memory"));
		return (1);
	}

	/*
	 * If using this cachedir to mount a file system for the first time
	 * after reboot, the ncheck for the sanity of the cachedir
	 */
	if (first_time_ab(margs.cfs_cachedir))
		if (check_cache(margs.cfs_cachedir))
			return (1);

	/* get the front file system cache id if necessary */
	if (margs.cfs_cacheid[0] == '\0') {
		char *cacheid = get_cacheid(margs.cfs_fsid, mntp);

		if (cacheid == NULL) {
			pr_err(gettext("default cacheid too long"));
			return (1);
		}

		strcpy(margs.cfs_cacheid, cacheid);
	}

	/* lock the cache directory shared */
	lockid = cachefs_dir_lock(margs.cfs_cachedir, 1);
	if (lockid == -1) {
		/* exit if could not get the lock */
		return (1);
	}

	/* if no mount point was specified and we are not remounting */
	mounted = 0;
	if ((margs.cfs_backfs == NULL) &&
	    (((mflag & MS_REMOUNT) == 0) ||
	    (margs.cfs_options.opt_flags & CFS_SLIDE))) {
		/* if a disconnectable mount */
		xx = 0;
		if (margs.cfs_options.opt_flags & CFS_DISCONNECTABLE) {
			/* see if the server is alive */
			xx = pingserver(specp);
		}

		/* attempt to mount the back file system */
		if (xx == 0) {
			xx = dobackmnt(&margs, reducep, specp, backfstypep,
			    myname, readonly);
			/*
			 * nfs mount exits with a value of 32 if a timeout
			 * error occurs trying the mount.
			 */
			if (xx && (xx != 32)) {
				cachefs_dir_unlock(lockid);
				rmdir(margs.cfs_backfs);
				return (1);
			}
			if (xx == 0)
				mounted = 1;
		}
	}

	/*
	 * At this point the back file system should be mounted.
	 * Get NFS version information for the back filesystem if
	 * it is NFS. The version information is required
	 * because NFS version 4 is incompatible with cachefs
	 * and we provide pass-through support for NFS version 4
	 * with cachefs, aka the cachefs mount is installed but
	 * there is no caching. This is indicated to the kernel
	 * during the mount by setting the CFS_BACKFS_NFSV4 flag.
	 */
	if (margs.cfs_backfs != NULL && strcmp(backfstypep, "nfs") == 0) {

		nfsvers = cachefs_get_back_nfsvers(margs.cfs_backfs, nomnttab);
		switch (nfsvers) {
		case 2:
			break;

		case 3:
			if (nfsv3pass) {
				/* Force pass through (for debugging) */
				margs.cfs_options.opt_flags = CFS_BACKFS_NFSV4;
				if (cfs_nfsv4_build_opts(optionp,
						cfs_nfsv4ops) != 0) {
					nfsvers_error = TRUE;
					goto clean_backmnt;
				}
			}
			break;

		case 4:
			/*
			 * overwrite old option flags with NFSv4 flag.
			 * Note that will also operate in strict
			 * consistency mode. Clean up the option string
			 * to get rid of the cachefs-specific options
			 * to be in sync with the opt flags, otherwise
			 * these can make it into the mnttab and cause
			 * problems (esp. the disconnected option).
			 */
			margs.cfs_options.opt_flags = CFS_BACKFS_NFSV4;
			if (cfs_nfsv4_build_opts(optionp, cfs_nfsv4ops) != 0) {
				nfsvers_error = TRUE;
				goto clean_backmnt;
			}
			break;

		default:
			/* error, unknown version */
			nfsvers_error = TRUE;
			goto clean_backmnt;
		}
	}

	/*
	 * Grab server name from special file arg if it is there or set
	 * server name to "server unknown".
	 */
	margs.cfs_hostname = servname;
	strncpy(servname, specp, sizeof (servname));
	servname[sizeof (servname) - 1] = '\0';
	strp = strchr(servname, ':');
	if (strp == NULL) {
		margs.cfs_hostname = "server unknown";
		margs.cfs_backfsname = specp;
	} else {
		*strp = '\0';
		/*
		 * The rest of the special file arg is the name of
		 * the back filesystem.
		 */
		strp++;
		margs.cfs_backfsname = strp;
	}

	/* mount the cache file system */
	xx = mount((margs.cfs_backfs != NULL) ? margs.cfs_backfs : "nobackfs",
		mntp, mflag | MS_DATA, MNTTYPE_CFS,
		&margs, sizeof (margs),
		(cfs_nfsv4ops[0] == '\0' ? mops : cfs_nfsv4ops),
		MAX_MNTOPT_STR);
clean_backmnt:
	if (xx == -1 || nfsvers_error) {
		if (nfsvers_error) {
			pr_err(gettext("nfs version error."));
		} else if (errno == ESRCH) {
			pr_err(gettext("mount failed, options do not match."));
		} else if ((errno == EAGAIN) && (margs.cfs_backfs == NULL)) {
			pr_err(gettext("mount failed, server not responding."));
		} else {
			pr_err(gettext("mount failed %s"), strerror(errno));
		}

		/* try to unmount the back file system if we mounted it */
		if (mounted) {
			xx = 1;
			newargv[xx++] = "umount";
			newargv[xx++] = margs.cfs_backfs;
			newargv[xx++] = NULL;

			/* fork */
			if ((pid = fork()) == -1) {
				pr_err(gettext("could not fork: %s"),
				    strerror(errno));
				cachefs_dir_unlock(lockid);
				return (1);
			}

			/* if the child */
			if (pid == 0) {
				/* do the unmount */
				doexec(backfstypep, newargv, "umount");
			}

			/* else if the parent */
			else {
				wait(0);
			}
			rmdir(margs.cfs_backfs);
		}

		cachefs_dir_unlock(lockid);
		return (1);
	}

	/* release the lock on the cache directory */
	cachefs_dir_unlock(lockid);

	/* record the mount information in the fscache directory */
	record_mount(mntp, specp, margs.cfs_backfs, backfstypep,
		margs.cfs_cachedir, margs.cfs_cacheid,
		(cfs_nfsv4ops[0] == '\0' ? optionp : cfs_nfsv4ops), reducep);

	/* notify the daemon of the mount */
	if (notify)
		daemon_notify(margs.cfs_cachedir, margs.cfs_cacheid);

	/* update mnttab file if necessary */
	if (!nomnttab) {
		/*
		 * If we added the back file system, tag it with ignore,
		 * however, don't fail the mount after its done
		 * if the tag can't be added (eg., this would cause
		 * automounter problems).
		 */
		if (mounted) {
			FILE *mt;
			struct extmnttab mnt;

			if ((mt = fopen(MNTTAB, "r")) == NULL)
				return (1);
			while (getextmntent(mt, &mnt, sizeof (mnt)) != -1) {
				if (mnt.mnt_mountp != NULL &&
				    strcmp(margs.cfs_backfs,
					mnt.mnt_mountp) == 0) {
					/* found it, do tag ioctl */
					mtdesc.mtd_major = mnt.mnt_major;
					mtdesc.mtd_minor = mnt.mnt_minor;
					mtdesc.mtd_mntpt = margs.cfs_backfs;
					mtdesc.mtd_tag = MNTOPT_IGNORE;

					(void) ioctl(fileno(mt),
						MNTIOC_SETTAG, &mtdesc);
					break;
				}
			}
			fclose(mt);
		}
	}

	/* return success */
	return (0);
}


/*
 *
 *			usage
 *
 * Description:
 *	Prints a short usage message.
 * Arguments:
 *	msgp	message to include with the usage message
 * Returns:
 * Preconditions:
 */

void
usage(char *msgp)
{
	if (msgp) {
		pr_err(gettext("%s"), msgp);
	}

	fprintf(stderr,
	    gettext("Usage: mount -F cachefs [generic options] "
	    "-o backfstype=file_system_type[FSTypespecific_options] "
	    "special mount_point\n"));
}

/*
 *
 *			pr_err
 *
 * Description:
 *	Prints an error message to stderr.
 * Arguments:
 *	fmt	printf style format
 *	...	arguments for fmt
 * Returns:
 * Preconditions:
 *	precond(fmt)
 */

void
pr_err(char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	(void) fprintf(stderr, gettext("mount -F cachefs: "));
	(void) vfprintf(stderr, fmt, ap);
	(void) fprintf(stderr, "\n");
	va_end(ap);
}

/*
 *
 *			set_cfs_args
 *
 * Description:
 *	Parse the comma delimited set of options specified by optionp
 *	and puts the results in margsp, mflagp, and backfstypepp.
 *	A string is constructed of options which are not specific to
 *	cfs and is placed in reducepp.
 *	Pointers to strings are invalid if this routine is called again.
 *	No initialization is done on margsp, mflagp, or backfstypepp.
 * Arguments:
 *	optionp		string of comma delimited options
 *	margsp		option results for the mount dataptr arg
 *	mflagp		option results for the mount mflag arg
 *	backfstypepp	set to name of back file system type
 *	reducepp	set to the option string without cfs specific options
 * Returns:
 *	Returns 0 for success, -1 for an error.
 * Preconditions:
 *	precond(optionp)
 *	precond(margsp)
 *	precond(mflagp)
 *	precond(backfstypepp)
 *	precond(reducepp)
 */

int
set_cfs_args(char *optionp, struct cachefs_mountargs *margsp, int *mflagp,
    char **backfstypepp, char **reducepp, int *notifyp, int *nfsv3pass)
{
	static char *optstrp = NULL;
	static char *reducep = NULL;
	char *savep, *strp, *valp;
	int badopt;
	int ret;
	int o_backpath = 0;
	int o_writemode = 0;
	int xx;
	uint_t yy;
	struct stat64 sinfo;
	char *pbuf;

	/* free up any previous options */
	free(optstrp);
	optstrp = NULL;
	free(reducep);
	reducep = NULL;

	/* make a copy of the options so we can modify it */
	optstrp = strp = strdup(optionp);
	reducep = malloc(strlen(optionp) + 1000);
	if ((strp == NULL) || (reducep == NULL)) {
		pr_err(gettext("out of memory"));
		return (-1);
	}
	*reducep = '\0';

	/* parse the options */
	badopt = 0;
	ret = 0;
	while (*strp) {
		savep = strp;
		switch (getsubopt(&strp, cfs_opts, &valp)) {

		case CFSOPT_BACKFSTYPE:
			if (valp == NULL)
				badopt = 1;
			else
				*backfstypepp = valp;
			break;

		case CFSOPT_CACHEDIR:
			if (valp == NULL)
				badopt = 1;
			else {
				margsp->cfs_cachedir = valp;
				if (valp[0] != '/') {
				    pbuf = (char *)malloc(MAXPATHLEN +
						strlen(valp) + 3);
				    if (pbuf == NULL) {
					pr_err(gettext("out of memory"));
					badopt = 1;
					break;
				    }
				    if (getcwd(pbuf, MAXPATHLEN+1) == NULL) {
					pr_err(gettext("cachedir too long"));
					badopt = 1;
					break;
				    }
				    if (pbuf[strlen(pbuf)-1] != '/')
					strcat(pbuf, "/");
				    strcat(pbuf, valp);
				    margsp->cfs_cachedir = pbuf;
				}
			}
			break;

		case CFSOPT_CACHEID:
			if (valp == NULL) {
				badopt = 1;
				break;
			}

			if (strlen(valp) >= (size_t)C_MAX_MOUNT_FSCDIRNAME) {
				pr_err(gettext("cacheid too long"));
				badopt = 1;
				break;
			}

			memset(margsp->cfs_cacheid, 0, C_MAX_MOUNT_FSCDIRNAME);
			strcpy(margsp->cfs_cacheid, valp);
			break;

		case CFSOPT_BACKPATH:
			if (valp == NULL)
				badopt = 1;
			else {
				margsp->cfs_backfs = valp;
				o_backpath = 1;
			}
			break;

		case CFSOPT_WRITEAROUND:
			margsp->cfs_options.opt_flags |= CFS_WRITE_AROUND;
			o_writemode++;
			break;

		case CFSOPT_NONSHARED:
			margsp->cfs_options.opt_flags |= CFS_NONSHARED;
			o_writemode++;
			break;

		case CFSOPT_NOCONST:
			margsp->cfs_options.opt_flags |= CFS_NOCONST_MODE;
			break;

		case CFSOPT_CODCONST:
			margsp->cfs_options.opt_flags |= CFS_CODCONST_MODE;
			break;

		case CFSOPT_LOCALACCESS:
			margsp->cfs_options.opt_flags &= ~CFS_ACCESS_BACKFS;
			break;

		case CFSOPT_NOSETSEC:
			margsp->cfs_options.opt_flags |= CFS_NOACL;
			break;

		case CFSOPT_LLOCK:
			margsp->cfs_options.opt_flags |= CFS_LLOCK;
			strcat(reducep, ",");
			strcat(reducep, savep);
			break;

		case CFSOPT_REMOUNT:
			*mflagp |= MS_REMOUNT;
			break;

		case CFSOPT_SLIDE:
			margsp->cfs_options.opt_flags |= CFS_SLIDE;
			break;

		case CFSOPT_FGSIZE:
			if (bad(valp))
				badopt = 1;
			else
				margsp->cfs_options.opt_fgsize = atoi(valp);
			break;

		case CFSOPT_POPSIZE:
			if (bad(valp))
				badopt = 1;
			else
				margsp->cfs_options.opt_popsize =
				    atoi(valp) * 1024;
			break;

		case CFSOPT_ACREGMIN:
			if (bad(valp))
				badopt = 1;
			else
				margsp->cfs_acregmin = atoi(valp);
			break;

		case CFSOPT_ACREGMAX:
			if (bad(valp))
				badopt = 1;
			else
				margsp->cfs_acregmax = atoi(valp);
			break;

		case CFSOPT_ACDIRMIN:
			if (bad(valp))
				badopt = 1;
			else
				margsp->cfs_acdirmin = atoi(valp);
			break;

		case CFSOPT_ACDIRMAX:
			if (bad(valp))
				badopt = 1;
			else
				margsp->cfs_acdirmax = atoi(valp);
			break;

		case CFSOPT_ACTIMEO:
			if (bad(valp))
				badopt = 1;
			else {
				yy = atoi(valp);
				margsp->cfs_acregmin = yy;
				margsp->cfs_acregmax = yy;
				margsp->cfs_acdirmin = yy;
				margsp->cfs_acdirmax = yy;
			}
			/*
			 * Note that we do not pass the actimeo options
			 * to the back file system.  This change was
			 * made for Chart.  Chart needs noac or actimeo=0
			 * so it makes no sense to pass these options on.
			 * In theory it should be okay to not pass these
			 * options on for regular cachefs mounts since
			 * cachefs perform the required attribute caching.
			 */
			break;

#if 0
		case CFSOPT_LAZYMOUNT:
			margsp->cfs_options.opt_flags |= CFS_LAZYMOUNT;
			break;
#endif

		case CFSOPT_DISCONNECTABLE:
		case CFSOPT_SNR:
			margsp->cfs_options.opt_flags |= CFS_DISCONNECTABLE;
			break;

		case CFSOPT_NOFILL:
			margsp->cfs_options.opt_flags |= CFS_NOFILL;
			break;

		case CFSOPT_SOFT:
			margsp->cfs_options.opt_flags |= CFS_SOFT;
			break;

		case CFSOPT_NONOTIFY:
			*notifyp = 0;
			break;

#ifdef CFS_NFSV3_PASSTHROUGH
		case CFSOPT_NFSV3PASSTHROUGH:
			*nfsv3pass = 1;
			break;
#endif /* CFS_NFSV3_PASSTHROUGH */

		default:
			/*
			 * unknown or vfs layer option, save for the back
			 * file system
			 */
			strcat(reducep, ",");
			strcat(reducep, savep);
			break;
		}

		/* if a lexical error occurred */
		if (badopt) {
			pr_err(gettext("invalid argument to option: \"%s\""),
			    savep);
			badopt = 0;
			ret = -1;
		}
	}

	/*
	 * Should mount backfs soft if disconnectable & non-shared options
	 * are used. NFS soft option allows reads and writes to TIMEOUT
	 * when the server is not responding, which is crucial for
	 * disconnectable option to work all the time in non-shared mode.
	 *
	 * Should mount backfs semisoft if disconnectable & write-around
	 * are used. NFS semisoft option allows reads to TIMEOUT and
	 * write to block when the server is not responding, which is
	 * good for write around option because it is shared.
	 *
	 * Since disconnectable and strict options are conflicting,
	 * when disconnectable option is used, default option is set to
	 * demandconst.
	 */

	if (margsp->cfs_options.opt_flags & (CFS_DISCONNECTABLE | CFS_SOFT))
		if (margsp->cfs_options.opt_flags & CFS_NONSHARED) {
			strcat(reducep, ",soft,noprint");
			margsp->cfs_options.opt_flags |= CFS_CODCONST_MODE;
		}
		else
			strcat(reducep, ",semisoft,noprint");

	if (!(margsp->cfs_options.opt_flags & CFS_DISCONNECTABLE)) {
		/* not snr, no need to notify the cachefsd */
		*notifyp = 0;
	}

	/* additional nfs options needed so disconnectable will work */
	if (margsp->cfs_options.opt_flags & CFS_DISCONNECTABLE) {
		/*
		 * retry=0 so cachefs can mount if nfs mount fails
		 *   even with this nfs takes 3 minutes to give up
		 * actimeo=0 because NFS does not pick up new ctime after
		 *	rename
		 */
		strcat(reducep, ",retry=0");
		if (margsp->cfs_options.opt_flags & CFS_NONSHARED)
			strcat(reducep, ",actimeo=0");
	}

	/* check for conflicting options */
	xx = margsp->cfs_options.opt_flags;
	if (o_backpath & (xx & CFS_DISCONNECTABLE)) {
		pr_err(gettext("backpath cannot be used with disconnectable"));
		ret = -1;
	}
	if (margsp->cfs_acregmin > margsp->cfs_acregmax) {
		pr_err(gettext("acregmin cannot be greater than acregmax"));
		ret = -1;
	}
	if (margsp->cfs_acdirmin > margsp->cfs_acdirmax) {
		pr_err(gettext("acdirmin cannot be greater than acdirmax"));
		ret = -1;
	}

	xx = CFS_NOCONST_MODE | CFS_CODCONST_MODE;
	if ((margsp->cfs_options.opt_flags & xx) == xx) {
		pr_err(gettext("only one of noconst and demandconst"
			" may be specified"));
		ret = -1;
	}

	if (o_writemode > 1) {
		pr_err(gettext(
		    "only one of write-around or non-shared"
		    " may be specified"));
		ret = -1;
	}

	/* if an error occured */
	if (ret)
		return (-1);

	/* if there are any options which are not mount specific */
	if (*reducep)
		*reducepp = reducep + 1;
	else
		*reducepp = NULL;

	/* return success */
	return (0);
}

/*
 *
 *			get_mount_point
 *
 * Description:
 *	Makes a suitable mount point for the back file system.
 *	The name of the mount point created is stored in a malloced
 *	buffer in pathpp
 * Arguments:
 *	cachedirp	the name of the cache directory
 *	specp		the special name of the device for the file system
 *	pathpp		where to store the mount point
 * Returns:
 *	Returns 0 for success, -1 for an error.
 * Preconditions:
 *	precond(cachedirp)
 *	precond(specp)
 *	precond(pathpp)
 */

int
get_mount_point(char *cachedirp, char *specp, char **pathpp)
{
	char *strp;
	char *namep;
	struct stat64 stat1, stat2;
	int xx;
	int index;
	int max;

	/* make a copy of the special device name */
	specp = strdup(specp);
	if (specp == NULL) {
		pr_err(gettext("out of memory"));
		return (-1);
	}

	/* convert the special device name into a file name */
	strp = specp;
	while (strp = strchr(strp, '/')) {
		*strp = '_';
	}

	/* get some space for the path name */
	strp = malloc(MAXPATHLEN);
	if (strp == NULL) {
		pr_err(gettext("out of memory"));
		return (-1);
	}

	/* see if the mount directory is valid */
	/* backfs can contain large files */
	sprintf(strp, "%s/%s", cachedirp, BACKMNT_NAME);
	xx = stat64(strp, &stat1);
	if ((xx == -1) || !S_ISDIR(stat1.st_mode)) {
		pr_err(gettext("%s is not a valid cache."), strp);
		return (-1);
	}

	/* find a directory name we can use */
	max = 10000;
	namep = strp + strlen(strp);
	for (index = 1; index < max; index++) {

		/* construct a directory name to consider */
		if (index == 1)
			sprintf(namep, "/%s", specp);
		else
			sprintf(namep, "/%s_%d", specp, index);

		/* try to create the directory */
		xx = mkdir(strp, 0755);
		if (xx == 0) {
			/* done if the create succeeded */
			break;
		}
	}

	/* if the search failed */
	if (index >= max) {
		pr_err(gettext("could not create a directory"));
		return (-1);
	}

	/* return success */
	*pathpp = strp;
	return (0);
}


int
dobackmnt(struct cachefs_mountargs *margsp, char *reducep, char *specp,
    char *backfstypep, char *mynamep, int readonly)
{
	int xx;
	pid_t pid;
	char *newargv[20];
	int stat_loc;

	/* get a suitable mount point */
	xx = get_mount_point(margsp->cfs_cachedir, specp, &margsp->cfs_backfs);
	if (xx)
		return (1);

	/* construct argument list for mounting the back file system */
	xx = 1;
	newargv[xx++] = "mount";
	if (readonly)
		newargv[xx++] = "-r";
	if (nomnttab)
		newargv[xx++] = "-m";
	if (quiet)
		newargv[xx++] = "-q";
	if (reducep) {
		newargv[xx++] = "-o";
		newargv[xx++] = reducep;
	}
	newargv[xx++] = specp;
	newargv[xx++] = margsp->cfs_backfs;
	newargv[xx++] = NULL;

	/* fork */
	if ((pid = fork()) == -1) {
		pr_err(gettext("could not fork %s"), strerror(errno));
		return (1);
	}

	/* if the child */
	if (pid == 0) {
		/* do the mount */
		doexec(backfstypep, newargv, mynamep);
	}

	/* else if the parent */
	else {
		/* wait for the child to exit */
		if (wait(&stat_loc) == -1) {
			pr_err(gettext("wait failed %s"), strerror(errno));
			return (1);
		}

		if (!WIFEXITED(stat_loc)) {
			pr_err(gettext("back mount did not exit"));
			return (1);
		}

		xx = WEXITSTATUS(stat_loc);
		if (xx) {
			pr_err(gettext("back mount failed"));
			return (xx);
		}
	}

	return (0);
}

/*
 *
 *			doexec
 *
 * Description:
 *	Execs the specified program with the specified command line arguments.
 *	This function never returns.
 * Arguments:
 *	fstype		type of file system
 *	newargv		command line arguments
 *	progp		name of program to exec
 * Returns:
 * Preconditions:
 *	precond(fstype)
 *	precond(newargv)
 */

void
doexec(char *fstype, char *newargv[], char *progp)
{
	char	full_path[PATH_MAX];
	char	alter_path[PATH_MAX];
	char	*vfs_path = VFS_PATH;
	char	*alt_path = ALT_PATH;

	/* build the full pathname of the fstype dependent command. */
	sprintf(full_path, "%s/%s/%s", vfs_path, fstype, progp);
	sprintf(alter_path, "%s/%s/%s", alt_path, fstype, progp);

	/* if the program exists */
	if (access(full_path, 0) == 0) {
		/* invoke the program */
		execv(full_path, &newargv[1]);

		/* if wrong permissions */
		if (errno == EACCES) {
			pr_err(gettext("cannot execute %s %s"),
			    full_path, strerror(errno));
		}

		/* if it did not work and the shell might make it */
		if (errno == ENOEXEC) {
			newargv[0] = "sh";
			newargv[1] = full_path;
			execv("/sbin/sh", &newargv[0]);
		}
	}

	/* try the alternate path */
	execv(alter_path, &newargv[1]);

	/* if wrong permissions */
	if (errno == EACCES) {
		pr_err(gettext("cannot execute %s %s"),
		    alter_path, strerror(errno));
	}

	/* if it did not work and the shell might make it */
	if (errno == ENOEXEC) {
		newargv[0] = "sh";
		newargv[1] = alter_path;
		execv("/sbin/sh", &newargv[0]);
	}

	pr_err(gettext("operation not applicable to FSType %s"), fstype);
	exit(1);
}

/*
 *
 *			get_back_fsid
 *
 * Description:
 *	Determines a unique identifier for the back file system.
 * Arguments:
 *	specp	the special file of the back fs
 * Returns:
 *	Returns a malloc string which is the unique identifer
 *	or NULL on failure.  NULL is only returned if malloc fails.
 * Preconditions:
 *	precond(specp)
 */

char *
get_back_fsid(char *specp)
{
	return (strdup(specp));
}

/*
 *
 *			get_cacheid
 *
 * Description:
 *	Determines an identifier for the front file system cache.
 *	The returned string points to a static buffer which is
 *	overwritten on each call.
 *	The length of the returned string is < C_MAX_MOUNT_FSCDIRNAME.
 * Arguments:
 *	fsidp	back file system id
 *	mntp	front file system mount point
 * Returns:
 *	Returns a pointer to the string identifier, or NULL if the
 *	identifier was overflowed.
 * Preconditions:
 *	precond(fsidp)
 *	precond(mntp)
 */

char *
get_cacheid(char *fsidp, char *mntp)
{
	char *c1;
	static char buf[PATH_MAX];
	char mnt_copy[PATH_MAX];

	/* strip off trailing space in mountpoint -- autofs fallout */
	if (strlen(mntp) >= sizeof (mnt_copy))
		return (NULL);
	(void) strcpy(mnt_copy, mntp);
	c1 = mnt_copy + strlen(mnt_copy) - 1;
	if (*c1 == ' ')
		*c1 = '\0';

	if ((strlen(fsidp) + strlen(mnt_copy) + 2) >=
	    (size_t)C_MAX_MOUNT_FSCDIRNAME)
		return (NULL);

	strcpy(buf, fsidp);
	strcat(buf, ":");
	strcat(buf, mnt_copy);
	c1 = buf;
	while ((c1 = strpbrk(c1, "/")) != NULL)
		*c1 = '_';
	return (buf);
}


/*
 *
 *			check_cache
 *
 * Description:
 *	Checks the cache we are about to use.
 * Arguments:
 *	cachedirp	cachedirectory to check
 * Returns:
 *	Returns 0 for success, -1 for an error.
 * Preconditions:
 */
int
check_cache(cachedirp)
	char *cachedirp;
{
	char *fsck_argv[4];
	int status = 0;
	pid_t pid;

	fsck_argv[1] = "fsck";
	fsck_argv[2] = cachedirp;
	fsck_argv[3] = NULL;

	/* fork */
	if ((pid = fork()) == -1) {
		pr_err(gettext("could not fork %s"),
		    strerror(errno));
		return (1);
	}

	if (pid == 0) {
		/* do the fsck */
		doexec("cachefs", fsck_argv, "fsck");
	} else {
		/* wait for the child to exit */
		if (wait(&status) == -1) {
			pr_err(gettext("wait failed %s"),
			    strerror(errno));
			return (1);
		}

		if (!WIFEXITED(status)) {
			pr_err(gettext("cache fsck did not exit"));
			return (1);
		}

		if (WEXITSTATUS(status) != 0) {
			pr_err(gettext("cache fsck mount failed"));
			return (1);
		}
	}
	return (0);
}

/*
 *
 *			record_mount
 *
 * Description:
 *	Records mount information in a file in the fscache directory.
 * Arguments:
 * Returns:
 * Preconditions:
 */

void
record_mount(char *mntp, char *specp, char *backfsp, char *backfstypep,
    char *cachedirp, char *cacheidp, char *optionp, char *reducep)
{
	char buf[MAXPATHLEN*2];
	FILE *fout;
	time_t tval;

	tval = time(NULL);

	/* this file is < 2GB */
	sprintf(buf, "%s/%s/%s", cachedirp, cacheidp, CACHEFS_MNT_FILE);
	fout = fopen(buf, "w");
	if (fout == NULL) {
		pr_err(gettext("could not open %s, %d"), buf, errno);
		return;
	}

	fprintf(fout, "cachedir: %s\n", cachedirp);
	fprintf(fout, "mnt_point: %s\n", mntp);
	if (specp) {
		fprintf(fout, "special: %s\n", specp);
	}
	if (backfsp)
		fprintf(fout, "backpath: %s\n", backfsp);
	fprintf(fout, "backfstype: %s\n", backfstypep);
	fprintf(fout, "cacheid: %s\n", cacheidp);
	fprintf(fout, "cachefs_options: %s\n", optionp);
	if (reducep)
		fprintf(fout, "backfs_options: %s\n", reducep);
	fprintf(fout, "mount_time: %u\n", tval);

	fclose(fout);
}

int
daemon_notify(char *cachedirp, char *cacheidp)
{
	CLIENT *clnt;
	enum clnt_stat retval;
	int ret;
	int xx;
	int result;
	char *hostp;
	struct utsname info;
	struct cachefsd_fs_mounted args;

	/* get the host name */
	xx = uname(&info);
	if (xx == -1) {
		pr_err(gettext("cannot get host name, errno %d"), errno);
		return (1);
	}
	hostp = info.nodename;

	/* creat the connection to the daemon */
	clnt = clnt_create(hostp, CACHEFSDPROG, CACHEFSDVERS, "local");
	if (clnt == NULL) {
		pr_err(gettext("cachefsd is not running"));
		return (1);
	}

	args.mt_cachedir = cachedirp;
	args.mt_cacheid = cacheidp;
	retval = cachefsd_fs_mounted_1(&args, NULL, clnt);
	if (retval != RPC_SUCCESS) {
		clnt_perror(clnt, gettext("cachefsd is not responding"));
		clnt_destroy(clnt);
		return (1);
	}

	ret = 0;

	clnt_destroy(clnt);

	return (ret);
}

/* returns 0 if the server is alive, -1 if an error */
int
pingserver(char *backmntp)
{
	CLIENT *clnt;
	static struct timeval TIMEOUT = { 25, 0 };
	enum clnt_stat retval;
	int ret;
	int xx;
	char *hostp;
	char buf[MAXPATHLEN];
	char *pc;

	/* get the host name */
	strcpy(buf, backmntp);
	pc = strchr(buf, ':');
	if (pc == NULL) {
		/* no host name, pretend it works */
		return (0);
	}
	*pc = '\0';
	hostp = buf;

	/* create the connection to the mount daemon */
	clnt = clnt_create(hostp, NFS_PROGRAM, NFS_VERSION, "udp");
	if (clnt == NULL) {
		return (-1);
	}

	ret = 0;

	/* see if the mountd responds */
	retval = clnt_call(clnt, 0, xdr_void, NULL, xdr_void, NULL,
	    TIMEOUT);
	if (retval != RPC_SUCCESS) {
		ret = -1;
	}

	clnt_destroy(clnt);

	return (ret);
}

/*
 * first_time_ab  : first time after boot - returns non-zero value
 *                  if the cachedir is being used for the first time
 *                  after the system reboot, otherwise zero.
 */
int
first_time_ab(char *buf)
{
	struct stat sinfo;
	char name[MAXPATHLEN];
	int ufd;
	time32_t btime;

	sprintf(name, "%s/%s", buf, CACHEFS_UNMNT_FILE);
	if (stat(name, &sinfo) != 0)
		return (1);
	if (sinfo.st_size == 0)
		return (1);
	if ((ufd = open(name, O_RDONLY)) == -1)
		return (1);
	if (read(ufd, &btime, sizeof (time32_t)) == -1)
		return (1);
	close(ufd);
	if (get_boottime() != btime)
		return (1);
	return (0);
}

/*
 * cachefs_get_back_nfsvers
 *
 * Returns:	nfs version
 *
 * Params:
 *		cfs_backfs	- backfile system mountpoint
 *		nomnttab	- mnttab entry does not exist
 *
 * Uses the kstat interface to extract the nfs version for
 * the mount.
 */
uint32_t
cachefs_get_back_nfsvers(char *cfs_backfs, int nomnttab)
{
	kstat_ctl_t *kc = NULL;
	FILE *mnttab = NULL;
	struct extmnttab mnt;
	kstat_t *ksp;
	dev_t my_fsid = NODEV;
	struct mntinfo_kstat mik;
	uint32_t nfsvers = 0;
	struct stat64 st;

	/*
	 * Initialize kernel statistics facility.
	 */
	if ((kc = kstat_open()) == NULL) {
		pr_err(gettext("kstat_open() can't open /dev/kstat: %s"),
			strerror(errno));
		goto end;
	}

	/*
	 * Locate the mount information in the mnttab if the nomnttab
	 * flag is not set, otherwise look for the entry by doing
	 * stat'ting the mountpoint.
	 */
	if (!nomnttab) {
		if ((mnttab = fopen(MNTTAB, "r")) == NULL) {
			pr_err(gettext("can't open /etc/mnttab: %s"),
				strerror(errno));
			goto end;
		}

		while (getextmntent(mnttab, &mnt, sizeof (mnt)) != -1) {
			if (mnt.mnt_mountp == NULL ||
			    strcmp(cfs_backfs, mnt.mnt_mountp) != 0) {
				continue;
			}
			my_fsid = makedev(mnt.mnt_major, mnt.mnt_minor);
			break;
		}
	}

	if (my_fsid == NODEV) {
		if (stat64(cfs_backfs, &st) == -1) {
			pr_err(gettext("can't stat mountpoint: %s"),
				strerror(errno));
			goto end;
		} else {
			my_fsid = st.st_dev;
		}

	}

	/*
	 * Walk the kstat control structures to locate the
	 * structure that describes the nfs module/mntinfo
	 * statistics for the mounted backfilesystem.
	 */
	for (ksp = kc->kc_chain; ksp; ksp = ksp->ks_next) {

		if (ksp->ks_type != KSTAT_TYPE_RAW)
			continue;
		if (strcmp(ksp->ks_module, "nfs") != 0)
			continue;
		if (strcmp(ksp->ks_name, "mntinfo") != 0)
			continue;
		if ((my_fsid & MAXMIN) != ksp->ks_instance)
			continue;

		/*
		 * At this point we have located the
		 * kstat info for the mount, read the
		 * statistics and return version info.
		 */
		if (kstat_read(kc, ksp, &mik) == -1) {
			pr_err(gettext("kstat_read() can't read %s/%s: %s"),
				ksp->ks_module, ksp->ks_name, strerror(errno));
			goto end;
		}

		nfsvers = mik.mik_vers;
		break;
	}

end:
	if (kc)
		kstat_close(kc);
	if (mnttab)
		fclose(mnttab);

	return (nfsvers);
}

/*
 * cfs_nfsv4_build_opts
 *
 * Returns: 0 on success, -1 on failure
 *
 * Params:
 *	optionp		- original option pointer
 *	cfs_nfsv4ops	- modified options for nfsv4 cachefs mount
 *
 * Parse the comma delimited set of options specified by optionp
 * and clean out options that we don't want to use with NFSv4.
 */
int
cfs_nfsv4_build_opts(char *optionp, char *cfs_nfsv4ops)
{
	char *optstrp;
	char *strp;
	char *savep;
	char *valp;
	uint32_t first = TRUE;

	/* Make a copy of the options so we can modify it */
	optstrp = strp = strdup(optionp);
	if (strp == NULL) {
		pr_err(gettext("out of memory"));
		return (-1);
	}

	/* Parse the options, cfs_nfsv4ops is initialized in main */
	while (*strp) {
		savep = strp;
		switch (getsubopt(&strp, cfs_opts, &valp)) {

		/* Ignore options that set cfs option flags */
		case CFSOPT_WRITEAROUND:
		case CFSOPT_NONSHARED:
		case CFSOPT_NOCONST:
		case CFSOPT_CODCONST:
		case CFSOPT_LOCALACCESS:
		case CFSOPT_NOSETSEC:
		case CFSOPT_LLOCK:
		case CFSOPT_SLIDE:
		case CFSOPT_DISCONNECTABLE:
		case CFSOPT_SNR:
		case CFSOPT_NOFILL:
		case CFSOPT_SOFT:
			break;

		default:
			/*
			 * Copy in option for cachefs nfsv4 mount.
			 */
			snprintf(cfs_nfsv4ops, MAX_MNTOPT_STR,
				"%s%s%s", cfs_nfsv4ops, first ? "" : ",",
				savep);
			first = FALSE;
			break;
		}
	}
	free(optstrp);

	return (0);
}
