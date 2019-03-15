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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

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
 * Quota report
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <sys/param.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/filio.h>
#include <sys/mntent.h>
#include <sys/time.h>
#include <sys/fs/ufs_quota.h>
#include <sys/stat.h>
#include <sys/mnttab.h>
#include <sys/vfstab.h>
#include <pwd.h>

#define	LOGINNAMESIZE	8
struct username {
	struct username *u_next;
	uid_t u_uid;
	char u_name[LOGINNAMESIZE + 1];
};
#define	UHASH 997
static struct username *uhead[UHASH];

static struct username *lookup(uid_t);
static struct username *adduid(uid_t);
static int repquota(char *, char *, char *);
static void prquota(uid_t, struct dqblk *);
static void header(void);
static void usage(void);
static void fmttime(char *, long);
static char *hasvfsopt(struct vfstab *, char *);
static int quotactl(int, char *, uid_t, caddr_t);
static int oneof(char *, char **, int);

extern char *mntopt();
extern char *hasmntopt();

static int	vflag;		/* verbose */
static int	aflag;		/* all file systems */
static char **listbuf;

#define	QFNAME "quotas"
#define	CHUNK	50

#if DEV_BSIZE < 1024
#define	dbtok(x)	((x) / (1024 / DEV_BSIZE))
#else
#define	dbtok(x)	((x) * (DEV_BSIZE / 1024))
#endif

int
main(int argc, char **argv)
{
	struct mnttab mntp;
	struct vfstab vfsbuf;
	char **listp;
	int listcnt;
	int listmax = 0;
	char quotafile[MAXPATHLEN];
	FILE *mtab, *vfstab;
	int errs = 0;
	int	opt;

	if ((listbuf = malloc(sizeof (char *) * CHUNK)) == NULL) {
		(void) fprintf(stderr, "Can't alloc lisbuf array.");
		exit(31+1);
	}
	listmax = CHUNK;
	while ((opt = getopt(argc, argv, "avV")) != EOF)
		switch (opt) {
		case 'v':
			vflag++;
			break;

		case 'a':
			aflag++;
			break;

		case 'V': {
				/* Print command line */
				char	*optt;
				int	optc;

				(void) printf("repquota -F ufs ");
				for (optc = 1; optc < argc; optc++) {
					optt = argv[optc];
					if (optt)
						(void) printf(" %s ", optt);
				}
				(void) putchar('\n');
			}
			break;

		case '?':
		default:
			usage();
		}

	if (argc <= optind && !aflag)
		usage();

	/*
	 * Sync quota information to disk (as userdata).  On logging
	 * file systems, this operation does nothing because quota
	 * information is treated as metadata.  Logging file systems
	 * are dealt with below in repquota().
	 */
	if (quotactl(Q_ALLSYNC, NULL, 0, NULL) < 0 && errno == EINVAL && vflag)
		(void) printf("Warning: "
			"Quotas are not available in this kernel\n");

	/*
	 * If aflag go through vfstab and make a list of appropriate
	 * filesystems.
	 */
	if (aflag) {
		listp = listbuf;
		listcnt = 0;
		if ((vfstab = fopen(VFSTAB, "r")) == NULL) {
			(void) fprintf(stderr, "Can't open ");
			perror(VFSTAB);
			exit(31+8);
		}
		while (getvfsent(vfstab, &vfsbuf) == 0) {

			if (strcmp(vfsbuf.vfs_fstype, MNTTYPE_UFS) != 0 ||
			    (vfsbuf.vfs_mntopts == 0) ||
			    hasvfsopt(&vfsbuf, MNTOPT_RO) ||
			    (!hasvfsopt(&vfsbuf, MNTOPT_RQ) &&
			    !hasvfsopt(&vfsbuf, MNTOPT_QUOTA)))
				continue;

			*listp = malloc(strlen(vfsbuf.vfs_special) + 1);
			(void) strcpy(*listp, vfsbuf.vfs_special);
			listp++;
			listcnt++;
			/* grow listbuf if needed */
			if (listcnt >= listmax) {
				listmax += CHUNK;
				listbuf = realloc(listbuf,
					sizeof (char *) * listmax);
				if (listbuf == NULL) {
					(void) fprintf(stderr,
						"Can't grow listbuf.\n");
					exit(31+1);
				}
				listp = &listbuf[listcnt];
			}
		}
		(void) fclose(vfstab);
		*listp = (char *)0;
		listp = listbuf;
	} else {
		listp = &argv[optind];
		listcnt = argc - optind;
	}
	if ((mtab = fopen(MNTTAB, "r")) == NULL) {
		(void) fprintf(stderr, "Can't open ");
		perror(MNTTAB);
		exit(31+8);
	}
	while (getmntent(mtab, &mntp) == 0) {
		if (strcmp(mntp.mnt_fstype, MNTTYPE_UFS) == 0 &&
		    !hasmntopt(&mntp, MNTOPT_RO) &&
		    (oneof(mntp.mnt_special, listp, listcnt) ||
		    oneof(mntp.mnt_mountp, listp, listcnt))) {
			(void) snprintf(quotafile, sizeof (quotafile), "%s/%s",
				mntp.mnt_mountp, QFNAME);
			errs += repquota(mntp.mnt_special,
				mntp.mnt_mountp, quotafile);
		}
	}
	(void) fclose(mtab);
	while (listcnt--) {
		if (*listp)
			(void) fprintf(stderr, "Cannot report on %s\n", *listp);
		listp++;
	}
	if (errs > 0)
		exit(31+1);
	return (0);
}

static int
repquota(char *fsdev, char *fsfile, char *qffile)
{
	FILE *qf;
	uid_t uid;
	struct dqblk dqbuf;
	struct stat64 statb;

	if (vflag || aflag)
		(void) printf("%s (%s):\n", fsdev, fsfile);
	qf = fopen64(qffile, "r");
	if (qf == NULL) {
		perror(qffile);
		return (1);
	}
	if (fstat64(fileno(qf), &statb) < 0) {
		perror(qffile);
		(void) fclose(qf);
		return (1);
	}
	/*
	 * Flush the file system. On logging file systems, this makes
	 * sure that the quota information (as metadata) gets rolled
	 * forward.
	 */
	if (ioctl(fileno(qf), _FIOFFS, NULL) == -1) {
		perror(qffile);
		(void) fprintf(stderr, "%s: cannot flush file system.\n",
				qffile);
		(void) fclose(qf);
		return (1);
	}
	header();
	for (uid = 0; uid <= MAXUID && uid >= 0; uid++) {
		(void) fread(&dqbuf, sizeof (struct dqblk), 1, qf);
		if (feof(qf))
			break;
		if (!vflag &&
		    dqbuf.dqb_curfiles == 0 && dqbuf.dqb_curblocks == 0)
			continue;
		prquota(uid, &dqbuf);
	}
	(void) fclose(qf);
	return (0);
}

static void
header(void)
{
	(void) printf("                      Block limits"
		"                      File limits\n");
	(void) printf("User           used   soft   hard    timeleft"
		"    used   soft   hard    timeleft\n");
}

static void
prquota(uid_t uid, struct dqblk *dqp)
{
	struct timeval tv;
	struct username *up;
	char ftimeleft[80], btimeleft[80];

	if (dqp->dqb_bsoftlimit == 0 && dqp->dqb_bhardlimit == 0 &&
	    dqp->dqb_fsoftlimit == 0 && dqp->dqb_fhardlimit == 0)
		return;
	(void) time(&(tv.tv_sec));
	tv.tv_usec = 0;
	up = lookup(uid);
	if (up)
		(void) printf("%-10s", up->u_name);
	else
		(void) printf("#%-9ld", uid);
	if (dqp->dqb_bsoftlimit &&
	    dqp->dqb_curblocks >= dqp->dqb_bsoftlimit) {
		if (dqp->dqb_btimelimit == 0)
			(void) strcpy(btimeleft, "NOT STARTED");
		else if (dqp->dqb_btimelimit > tv.tv_sec)
			fmttime(btimeleft,
			    (long)(dqp->dqb_btimelimit - tv.tv_sec));
		else
			(void) strcpy(btimeleft, "EXPIRED");
	} else
		btimeleft[0] = '\0';

	if (dqp->dqb_fsoftlimit && dqp->dqb_curfiles >= dqp->dqb_fsoftlimit) {
		if (dqp->dqb_ftimelimit == 0)
			(void) strcpy(ftimeleft, "NOT STARTED");
		else if (dqp->dqb_ftimelimit > tv.tv_sec)
			fmttime(ftimeleft,
			    (long)(dqp->dqb_ftimelimit - tv.tv_sec));
		else
			(void) strcpy(ftimeleft, "EXPIRED");
	} else
		ftimeleft[0] = '\0';

	(void) printf("%c%c %6lu %6lu %6lu %11s %7lu %6lu %6lu %11s\n",
		(dqp->dqb_bsoftlimit &&
		    dqp->dqb_curblocks >= dqp->dqb_bsoftlimit) ? '+' : '-',
		(dqp->dqb_fsoftlimit &&
		    dqp->dqb_curfiles >= dqp->dqb_fsoftlimit) ? '+' : '-',
		dbtok(dqp->dqb_curblocks),
		dbtok(dqp->dqb_bsoftlimit),
		dbtok(dqp->dqb_bhardlimit),
		btimeleft,
		dqp->dqb_curfiles,
		dqp->dqb_fsoftlimit,
		dqp->dqb_fhardlimit,
		ftimeleft);
}

static void
fmttime(char *buf, long time)
{
	int i;
	static struct {
		int c_secs;		/* conversion units in secs */
		char *c_str;		/* unit string */
	} cunits [] = {
		{60*60*24*28, "months"},
		{60*60*24*7, "weeks"},
		{60*60*24, "days"},
		{60*60, "hours"},
		{60, "mins"},
		{1, "secs"}
	};

	if (time <= 0) {
		(void) strcpy(buf, "EXPIRED");
		return;
	}
	for (i = 0; i < sizeof (cunits) / sizeof (cunits[0]); i++) {
		if (time >= cunits[i].c_secs)
			break;
	}
	(void) sprintf(buf, "%.1f %s",
	    (double)time / cunits[i].c_secs, cunits[i].c_str);
}

static int
oneof(char *target, char **olistp, int on)
{
	char **listp = olistp;
	int n = on;

	while (n--) {
		if (*listp && strcmp(target, *listp) == 0) {
			*listp = (char *)0;
			return (1);
		}
		listp++;
	}
	return (0);
}

static struct username *
lookup(uid_t uid)
{
	struct passwd *pwp;
	struct username *up;

	for (up = uhead[uid % UHASH]; up != 0; up = up->u_next)
		if (up->u_uid == uid)
			return (up);
	if ((pwp = getpwuid((uid_t)uid)) == NULL)
		return ((struct username *)0);
	up = adduid(pwp->pw_uid);
	(void) strncpy(up->u_name, pwp->pw_name, sizeof (up->u_name));
	return (up);
}

/*
 * adduid() should *ONLY* be called from lookup in order
 * to avoid duplicate entries.
 */
static struct username *
adduid(uid_t uid)
{
	struct username *up, **uhp;

	up = calloc(1, sizeof (struct username));
	if (up == 0) {
		(void) fprintf(stderr,
			"out of memory for username structures\n");
		exit(31+1);
	}
	uhp = &uhead[uid % UHASH];
	up->u_next = *uhp;
	*uhp = up;
	up->u_uid = uid;
	return (up);
}

static void
usage(void)
{
	(void) fprintf(stderr, "ufs usage:\n");
	(void) fprintf(stderr, "\trepquota [-v] -a \n");
	(void) fprintf(stderr, "\trepquota [-v] filesys ...\n");
	exit(31+1);
}

static int
quotactl(int cmd, char *special, uid_t uid, caddr_t addr)
{
	int		fd;
	int		status;
	struct quotctl	quota;
	char		qfile[MAXPATHLEN];
	FILE		*fstab;
	struct mnttab	mntp;


	if ((special == NULL) && (cmd == Q_ALLSYNC)) {
	/*
	 * Find the mount point of the special device.   This is
	 * because the ioctl that implements the quotactl call has
	 * to go to a real file, and not to the block device.
	 */
		if ((fstab = fopen(MNTTAB, "r")) == NULL) {
			(void) fprintf(stderr, "%s: ", MNTTAB);
			perror("open");
			exit(31+1);
		}
		fd = -1;
		while ((status = getmntent(fstab, &mntp)) == 0) {

			if (strcmp(mntp.mnt_fstype, MNTTYPE_UFS) != 0 ||
			    hasmntopt(&mntp, MNTOPT_RO))
				continue;

			if ((strlcpy(qfile, mntp.mnt_mountp,
				sizeof (qfile)) >= sizeof (qfile)) ||
			    (strlcat(qfile, "/" QFNAME, sizeof (qfile)) >=
				sizeof (qfile))) {
				continue;
			}

			/* If we find *ANY* valid "quotas" file, use it */
			if ((fd = open64(qfile, O_RDONLY)) >= 0)
				break;
		}
		(void) fclose(fstab);
		if (fd == -1) {
			errno = ENOENT;
			(void) printf("quotactl: no quotas file "
				"on any mounted file system\n");
			return (-1);
		}
	}
	quota.op = cmd;
	quota.uid = uid;
	quota.addr = addr;
	status = ioctl(fd, Q_QUOTACTL, &quota);
	(void) close(fd);
	return (status);
}

static char *
hasvfsopt(struct vfstab *vfs, char *opt)
{
	char *f, *opts;
	static char *tmpopts;

	if (tmpopts == 0) {
		tmpopts = calloc(256, sizeof (char));
		if (tmpopts == 0)
			return (0);
	}
	(void) strcpy(tmpopts, vfs->vfs_mntopts);
	opts = tmpopts;
	f = mntopt(&opts);
	for (; *f; f = mntopt(&opts)) {
		if (strncmp(opt, f, strlen(opt)) == 0)
			return (f - tmpopts + vfs->vfs_mntopts);
	}
	return (NULL);
}
