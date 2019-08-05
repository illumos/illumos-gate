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
 * Turn quota on/off for a filesystem.
 */
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mntent.h>

#define	bcopy(f, t, n)    memcpy(t, f, n)
#define	bzero(s, n)	memset(s, 0, n)
#define	bcmp(s, d, n)	memcmp(s, d, n)

#define	index(s, r)	strchr(s, r)
#define	rindex(s, r)	strrchr(s, r)

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/file.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/fs/ufs_quota.h>
#include <stdio.h>
#include <sys/mnttab.h>
#include <errno.h>
#include <sys/vfstab.h>

int	vflag;		/* verbose */
int	aflag;		/* all file systems */

#define	QFNAME "quotas"
#define	CHUNK	50
char	**listbuf;
char	*mntopt(), *hasvfsopt(), *hasmntopt();
char	*whoami;

static void fixmntent();
static void mnterror();
static void usage(char *);
static int oneof();
static int quotaonoff();
static int quotactl(int, char *, uid_t, caddr_t);

extern int	optind;
extern char	*optarg;

int
main(int argc, char **argv)
{
	struct mnttab mntp;
	struct vfstab vfsbuf;
	char **listp;
	int listcnt;
	FILE *mtab, *vfstab, *tmp;
	int offmode = 0;
	int listmax = 0;
	int errs = 0;
	char *tmpname = "/etc/mnttab.temp";
	int		status;
	int		opt;
	mode_t		oldumask;
	struct stat	statbuf;

	whoami = (char *)rindex(*argv, '/') + 1;
	if (whoami == (char *)1)
		whoami = *argv;
	if (strcmp(whoami, "quotaoff") == 0)
		offmode++;
	else if (strcmp(whoami, "quotaon") != 0) {
		fprintf(stderr, "Name must be quotaon or quotaoff not %s\n",
			whoami);
		exit(31+1);
	}
	if ((listbuf = (char **)malloc(sizeof (char *) * CHUNK)) == NULL) {
		fprintf(stderr, "Can't alloc lisbuf array.");
		exit(31+1);
	}
	listmax = CHUNK;
	while ((opt = getopt(argc, argv, "avV")) != EOF) {
		switch (opt) {

		case 'v':
			vflag++;
			break;

		case 'a':
			aflag++;
			break;

		case 'V':		/* Print command line */
			{
				char		*opt_text;
				int		opt_cnt;

				(void) fprintf(stdout, "%s -F UFS ", whoami);
				for (opt_cnt = 1; opt_cnt < argc; opt_cnt++) {
					opt_text = argv[opt_cnt];
					if (opt_text)
						(void) fprintf(stdout, " %s ",
							opt_text);
				}
				(void) fprintf(stdout, "\n");
			}
			break;

		case '?':
			usage(whoami);
		}
	}
	if (argc <= optind && !aflag) {
		usage(whoami);
	}
	/*
	 * If aflag go through vfstab and make a list of appropriate
	 * filesystems.
	 */
	if (aflag) {

		listp = listbuf;
		listcnt = 0;

		vfstab = fopen(VFSTAB, "r");
		if (vfstab == NULL) {
			fprintf(stderr, "Can't open %s\n", VFSTAB);
			perror(VFSTAB);
			exit(31+1);
		}

		while ((status = getvfsent(vfstab, &vfsbuf)) == 0) {
			if (strcmp(vfsbuf.vfs_fstype, MNTTYPE_UFS) != 0 ||
			    (vfsbuf.vfs_mntopts == 0) ||
			    hasvfsopt(&vfsbuf, MNTOPT_RO) ||
			    (!hasvfsopt(&vfsbuf, MNTOPT_RQ) &&
			    !hasvfsopt(&vfsbuf, MNTOPT_QUOTA)))
				continue;
			*listp = malloc(strlen(vfsbuf.vfs_special) + 1);
			strcpy(*listp, vfsbuf.vfs_special);
			listp++;
			listcnt++;
			/* grow listbuf if needed */
			if (listcnt >= listmax) {
				listmax += CHUNK;
				listbuf = (char **)realloc(listbuf,
					sizeof (char *) * listmax);
				if (listbuf == NULL) {
					fprintf(stderr,
						"Can't grow listbuf.\n");
					exit(31+1);
				}
				listp = &listbuf[listcnt];
			}
		}
		fclose(vfstab);
		*listp = (char *)0;
		listp = listbuf;
	} else {
		listp = &argv[optind];
		listcnt = argc - optind;
	}

	/*
	 * Open real mnttab
	 */
	mtab = fopen(MNTTAB, "r");
	if (mtab == NULL) {
		fprintf(stderr, "Can't open %s\n", MNTTAB);
		perror(whoami);
		exit(31+1);
	}
	/* check every entry for validity before we change mnttab */
	while ((status = getmntent(mtab, &mntp)) == 0)
		;
	if (status > 0)
		mnterror(status);
	rewind(mtab);

	signal(SIGHUP,  SIG_IGN);
	signal(SIGQUIT, SIG_IGN);
	signal(SIGINT,  SIG_IGN);

	/*
	 * Loop through mnttab, if a file system gets turned on or off
	 * do the quota call.
	 */
	while ((status = getmntent(mtab, &mntp)) == 0) {
		if (strcmp(mntp.mnt_fstype, MNTTYPE_UFS) == 0 &&
		    !hasmntopt(&mntp, MNTOPT_RO) &&
		    (oneof(mntp.mnt_special, listp, listcnt) ||
		    oneof(mntp.mnt_mountp, listp, listcnt))) {
			errs += quotaonoff(&mntp, offmode);
		}
	}
	fclose(mtab);

	while (listcnt--) {
		if (*listp) {
			fprintf(stderr, "Cannot do %s\n", *listp);
			errs++;
		}
		listp++;
	}
	if (errs > 0)
		errs += 31;
	return (errs);
}

int
quotaonoff(struct mnttab *mntp, int offmode)
{

	if (offmode) {
		if (quotactl(Q_QUOTAOFF, mntp->mnt_mountp, (uid_t)0, NULL) < 0)
			goto bad;
		if (vflag)
			printf("%s: quotas turned off\n", mntp->mnt_mountp);
	} else {
		if (quotactl(Q_QUOTAON, mntp->mnt_mountp, (uid_t)0, NULL) <
		    0)
			goto bad;
		if (vflag)
			printf("%s: quotas turned on\n", mntp->mnt_mountp);
	}
	return (0);
bad:
	fprintf(stderr, "quotactl: ");
	perror(mntp->mnt_special);
	return (1);
}

int
oneof(char *target, char **olistp, int on)
{
	int n = on;
	char **listp = olistp;

	while (n--) {
		if (*listp && strcmp(target, *listp) == 0) {
			*listp = (char *)0;
			return (1);
		}
		listp++;
	}
	return (0);
}

void
usage(char *whoami)
{

	fprintf(stderr, "ufs usage:\n");
	fprintf(stderr, "\t%s [-v] -a\n", whoami);
	fprintf(stderr, "\t%s [-v] filesys ...\n", whoami);
		exit(31+1);
}


int
quotactl(int cmd, char *mountpt, uid_t uid, caddr_t addr)
{
	int		fd;
	int		status;
	struct quotctl	quota;
	char		qfile[MAXPATHLEN];

	if (mountpt == NULL || mountpt[0] == '\0') {
		errno = ENOENT;
		return (-1);
	}
	if ((strlcpy(qfile, mountpt, sizeof (qfile)) >= sizeof (qfile)) ||
	    (strlcat(qfile, "/" QFNAME, sizeof (qfile)) >= sizeof (qfile))) {
		errno = ENOENT;
		return (-1);
	}
	if ((fd = open64(qfile, O_RDWR)) < 0) {
		fprintf(stderr, "quotactl: %s ", qfile);
		perror("open");
		exit(31+1);
	}

	quota.op = cmd;
	quota.uid = uid;
	quota.addr = addr;
	status = ioctl(fd, Q_QUOTACTL, &quota);
	close(fd);
	return (status);
}

char *
hasvfsopt(struct vfstab *vfs, char *opt)
{
	char *f, *opts;
	static char *tmpopts;

	if (tmpopts == 0) {
		tmpopts = (char *)calloc(256, sizeof (char));
		if (tmpopts == 0)
			return (0);
	}
	strcpy(tmpopts, vfs->vfs_mntopts);
	opts = tmpopts;
	f = mntopt(&opts);
	for (; *f; f = mntopt(&opts)) {
		if (strncmp(opt, f, strlen(opt)) == 0)
			return (f - tmpopts + vfs->vfs_mntopts);
	}
	return (NULL);
}

void
mnterror(int flag)
{
	switch (flag) {
	case MNT_TOOLONG:
		fprintf(stderr, "%s: line in mnttab exceeds %d characters\n",
			whoami, MNT_LINE_MAX-2);
		break;
	case MNT_TOOFEW:
		fprintf(stderr, "%s: line in mnttab has too few entries\n",
			whoami);
		break;
	case MNT_TOOMANY:
		fprintf(stderr, "%s: line in mnttab has too many entries\n",
			whoami);
		break;
	}
	exit(1);
}
