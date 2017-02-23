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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright (c) 2016 by Delphix. All rights reserved.
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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Disk quota editor.
 */
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <errno.h>
#include <pwd.h>
#include <ctype.h>
#include <fcntl.h>
#include <string.h>
#include <strings.h>
#include <sys/mnttab.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/mntent.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/fs/ufs_quota.h>
#include <sys/fs/ufs_fs.h>
#include <sys/wait.h>
#include <unistd.h>
#include <iso/limits_iso.h>

#define	DEFEDITOR	"/usr/bin/vi"

#if DEV_BSIZE < 1024
#define	dbtok(x)	((x) / (1024 / DEV_BSIZE))
#define	ktodb(x)	((x) * (1024 / DEV_BSIZE))
#else
#define	dbtok(x)	((x) * (DEV_BSIZE / 1024))
#define	ktodb(x)	((x) / (DEV_BSIZE / 1024))
#endif

struct fsquot {
	struct fsquot *fsq_next;
	struct dqblk fsq_dqb;
	char *fsq_fs;
	char *fsq_dev;
	char *fsq_qfile;
};

static struct fsquot *fsqlist;

static char	tmpfil[] = "/tmp/EdP.aXXXXXX";
#define	QFNAME	"quotas"

static uid_t getentry(char *);
static int editit(void);
static void getprivs(uid_t);
static void putprivs(uid_t);
static void gettimes(uid_t);
static void puttimes(uid_t);
static char *next(char *, char *);
static int alldigits(char *);
static void fmttime(char *, ulong_t);
static int unfmttime(double, char *, uint32_t *);
static void setupfs(void);
static void getdiscq(uid_t);
static void putdiscq(uid_t);
static void sigsetmask(uint_t);
static uint_t sigblock(uint_t);
static void usage(void);
static int quotactl(int, char *, uid_t, caddr_t);

int
main(int argc, char **argv)
{
	uid_t	uid;
	char	*basename;
	int	opt;
	int	i;
	int	tmpfd = -1;

	basename = argv[0];
	if (argc < 2) {
		usage();
	}
	if (quotactl(Q_SYNC, (char *)NULL, 0, (caddr_t)NULL) < 0 &&
	    errno == EINVAL) {
		(void) printf("Warning: "
			"Quotas are not compiled into this kernel\n");
		(void) sleep(3);
	}
	if (getuid()) {
		(void) fprintf(stderr, "%s: permission denied\n", basename);
		exit(32);
	}
	setupfs();
	if (fsqlist == NULL) {
		(void) fprintf(stderr, "%s: no UFS filesystems with %s file\n",
		    MNTTAB, QFNAME);
		exit(32);
	}
	tmpfd = mkstemp(tmpfil);
	if (tmpfd == -1 || fchown(tmpfd, getuid(), getgid()) == -1) {
		fprintf(stderr, "failure in temporary file %s\n", tmpfil);
		exit(32);
	}
	(void) close(tmpfd);
	while ((opt = getopt(argc, argv, "p:tV")) != EOF)
		switch (opt) {
		case 't':
			gettimes(0);
			if (editit())
				puttimes(0);
			(void) unlink(tmpfil);
			exit(0);
			/*NOTREACHED*/

		case 'p':
			uid = getentry(optarg);
			if (uid > MAXUID) {
				(void) unlink(tmpfil);
				exit(32);
			}
			getprivs(uid);
			if (optind == argc) {
				(void) unlink(tmpfil);
				usage();
			}
			for (i = optind; i < argc; i++) {
				uid = getentry(argv[i]);
				if (uid > MAXUID) {
					(void) unlink(tmpfil);
					exit(32);
				}
				getdiscq(uid);
				putprivs(uid);
			}
			(void) unlink(tmpfil);
			exit(0);
			/*NOTREACHED*/

		case 'V':		/* Print command line */
			{
				char		*optt;
				int		optc;

				(void) printf("edquota -F UFS");
				for (optc = 1; optc < argc; optc++) {
					optt = argv[optc];
					if (optt)
						(void) printf(" %s ", optt);
				}
				(void) putchar('\n');
			}
			break;

		case '?':
			usage();
		}

	for (i = optind; i < argc; i++) {
		uid = getentry(argv[i]);
		if (uid > MAXUID)
			continue;
		getprivs(uid);
		if (editit())
			putprivs(uid);
		if (uid == 0) {
			(void) printf("edquota: Note that uid 0's quotas "
			    "are used as default values for other users,\n");
			(void) printf("not as a limit on the uid 0 user.\n");
		}
	}
	(void) unlink(tmpfil);
	return (0);
}

static uid_t
getentry(char *name)
{
	struct passwd *pw;
	uid_t uid;

	if (alldigits(name)) {
		errno = 0;
		uid = strtol(name, NULL, 10);
		if (errno == ERANGE) {
			/* name would cause overflow in uid */
			(void) fprintf(stderr, "edquota: uid %s too large\n",
			    name);
			(void) sleep(1);
			return (-1);
		}
	} else if (pw = getpwnam(name))
		uid = pw->pw_uid;
	else {
		(void) fprintf(stderr, "%s: no such user\n", name);
		(void) sleep(1);
		return (-1);
	}
	return (uid);
}

#define	RESPSZ	128

static int
editit(void)
{
	pid_t pid, xpid;
	char *ed;
	char resp[RESPSZ];
	int status, omask;

#define	mask(s)	(1 << ((s) - 1))
	omask = sigblock(mask(SIGINT)|mask(SIGQUIT)|mask(SIGHUP));

	if ((ed = getenv("EDITOR")) == (char *)0)
		ed = DEFEDITOR;

	/*CONSTANTCONDITION*/
	while (1) {
		if ((pid = fork()) < 0) {
			if (errno == EAGAIN) {
				(void) fprintf(stderr,
					"You have too many processes\n");
				return (0);
			}
			perror("fork");
			return (0);
		}
		if (pid == 0) {
			(void) sigsetmask(omask);
			(void) setgid(getgid());
			(void) setuid(getuid());
			(void) execlp(ed, ed, tmpfil, 0);
			(void) fprintf(stderr,
				"Can't exec editor \"%s\": ", ed);
			perror("");
			exit(32);
		}
		while ((xpid = wait(&status)) >= 0)
			if (xpid == pid)
				break;

		if (!isatty(fileno(stdin))) {	/* Non-interactive */
			break;
		}

		/*
		 * Certain editors can exit with a non-zero status even
		 * though everything is peachy. Best to ask the user what
		 * they really wants to do. (N.B.: if we're non-interactive
		 * we'll "break" the while loop before we get here.)
		 */
		if (WIFEXITED(status) && (WEXITSTATUS(status) != 0)) {
			(void) printf("Non-zero return from \"%s\", ", ed);
			(void) printf("updated file may contain errors.\n");
			/*CONSTANTCONDITION*/
			while (1) {
				(void) printf("Edit again (e) or quit, "
				    "discarding changes (q)? ");
				(void) fflush(stdout);
				if (gets(resp) == NULL) {
					return (0);
				}
				if ((*resp == 'e') || (*resp == 'q')) {
					break;
				}
			}

			if (*resp == 'e') {
				continue;
			} else {
				/*
				 * Since (*resp == 'q'), then we just
				 * want to break out of here and return
				 * the failure.
				 */
				break;
			}
		} else {
			break;	/* Successful return from editor */
		}
	}
	(void) sigsetmask(omask);
	return (!status);
}

static void
getprivs(uid_t uid)
{
	struct fsquot *fsqp;
	FILE *fd;

	getdiscq(uid);
	if ((fd = fopen64(tmpfil, "w")) == NULL) {
		(void) fprintf(stderr, "edquota: ");
		perror(tmpfil);
		(void) unlink(tmpfil);
		exit(32);
	}
	for (fsqp = fsqlist; fsqp; fsqp = fsqp->fsq_next)
		(void) fprintf(fd,
		    "fs %s blocks (soft = %lu, hard = %lu) "
		    "inodes (soft = %lu, hard = %lu)\n",
		    fsqp->fsq_fs,
		    dbtok(fsqp->fsq_dqb.dqb_bsoftlimit),
		    dbtok(fsqp->fsq_dqb.dqb_bhardlimit),
		    fsqp->fsq_dqb.dqb_fsoftlimit,
		    fsqp->fsq_dqb.dqb_fhardlimit);
	(void) fclose(fd);
}

static void
putprivs(uid_t uid)
{
	FILE *fd;
	uint64_t tmp_bsoftlimit, tmp_bhardlimit, tmp_fsoftlimit,
	    tmp_fhardlimit;
	char line[BUFSIZ];
	int changed = 0;
	uint32_t max_limit;
	int	quota_entry_printed;

	fd = fopen64(tmpfil, "r");
	if (fd == NULL) {
		(void) fprintf(stderr, "Can't re-read temp file!!\n");
		return;
	}
	while (fgets(line, sizeof (line), fd) != NULL) {
		struct fsquot *fsqp;
		char *cp, *dp;
		int n;

		cp = next(line, " \t");
		if (cp == NULL)
			break;
		*cp++ = '\0';
		while (*cp && *cp == '\t' && *cp == ' ')
			cp++;
		dp = cp, cp = next(cp, " \t");
		if (cp == NULL)
			break;
		*cp++ = '\0';
		for (fsqp = fsqlist; fsqp; fsqp = fsqp->fsq_next) {
			if (strcmp(dp, fsqp->fsq_fs) == 0)
				break;
		}
		if (fsqp == NULL) {
			(void) fprintf(stderr, "%s: unknown file system\n", cp);
			continue;
		}
		while (*cp && *cp == '\t' && *cp == ' ')
			cp++;

		/*
		 * At this point, dp points to the mount point of the
		 * file system and cp points to the remainder of the
		 * quota definition string.
		 */
		n = sscanf(cp,
		    "blocks (soft = %llu, hard = %llu) "
		    "inodes (soft = %llu, hard = %llu)\n",
			&tmp_bsoftlimit,
			&tmp_bhardlimit,
			&tmp_fsoftlimit,
			&tmp_fhardlimit);

		if (n != 4) {
			(void) fprintf(stderr, "%s: bad format\n", cp);
			continue;
		}

		/*
		 * The values in dqb_bsoftlimit and dqb_bhardlimit
		 * are specified in 1k blocks in the edited quota
		 * file (the one we're reading), but are specified in
		 * disk blocks in the data structure passed to quotactl().
		 * That means that the maximum allowed value for the
		 * hard and soft block limits in the edited quota file
		 * is the maximum number of disk blocks allowed in a
		 * quota (which is 2^32 - 1, since it's a 32-bit unsigned
		 * quantity), converted to 1k blocks.
		 */
		max_limit = dbtok(UINT_MAX);

		quota_entry_printed = 0; /* only print quota entry once */

		if (tmp_bsoftlimit > max_limit) {
			tmp_bsoftlimit = max_limit;
			if (!quota_entry_printed) {
				(void) fprintf(stderr, "%s %s%\n", dp, cp);
				quota_entry_printed = 1;
			}
			(void) fprintf(stderr,
	"error: soft limit for blocks exceeds maximum allowed value,\n"
	"    soft limit for blocks set to %lu\n", max_limit);
		}

		if (tmp_bhardlimit > max_limit) {
			tmp_bhardlimit = max_limit;
			if (!quota_entry_printed) {
				(void) fprintf(stderr, "%s %s%\n", dp, cp);
				quota_entry_printed = 1;
			}
			(void) fprintf(stderr,
	"error: hard limit for blocks exceeds maximum allowed value,\n"
	"    hard limit for blocks set to %lu\n", max_limit);
		}


		/*
		 * Now check the file limits against their maximum, which
		 * is UINT_MAX (since it must fit in a uint32_t).
		 */
		max_limit = UINT_MAX;

		if (tmp_fsoftlimit > max_limit) {
			tmp_fsoftlimit = max_limit;
			if (!quota_entry_printed) {
				(void) fprintf(stderr, "%s %s%\n", dp, cp);
				quota_entry_printed = 1;
			}
			(void) fprintf(stderr,
	"error: soft limit for files exceeds maximum allowed value,\n"
	"    soft limit for files set to %lu\n", max_limit);
		}

		if (tmp_fhardlimit > max_limit) {
			tmp_fhardlimit = max_limit;
			if (!quota_entry_printed) {
				(void) fprintf(stderr, "%s %s%\n", dp, cp);
				quota_entry_printed = 1;
			}
			(void) fprintf(stderr,
	"error: hard limit for files exceeds maximum allowed value,\n"
	"    hard limit for files set to %lu\n", max_limit);
		}

		changed++;
		tmp_bsoftlimit = ktodb(tmp_bsoftlimit);
		tmp_bhardlimit = ktodb(tmp_bhardlimit);
		/*
		 * It we are decreasing the soft limits, set the time limits
		 * to zero, in case the user is now over quota.
		 * the time limit will be started the next time the
		 * user does an allocation.
		 */
		if (tmp_bsoftlimit < fsqp->fsq_dqb.dqb_bsoftlimit)
			fsqp->fsq_dqb.dqb_btimelimit = 0;
		if (tmp_fsoftlimit < fsqp->fsq_dqb.dqb_fsoftlimit)
			fsqp->fsq_dqb.dqb_ftimelimit = 0;
		fsqp->fsq_dqb.dqb_bsoftlimit = tmp_bsoftlimit;
		fsqp->fsq_dqb.dqb_bhardlimit = tmp_bhardlimit;
		fsqp->fsq_dqb.dqb_fsoftlimit = tmp_fsoftlimit;
		fsqp->fsq_dqb.dqb_fhardlimit = tmp_fhardlimit;
	}
	(void) fclose(fd);
	if (changed)
		putdiscq(uid);
}

static void
gettimes(uid_t uid)
{
	struct fsquot *fsqp;
	FILE *fd;
	char btime[80], ftime[80];

	getdiscq(uid);
	if ((fd = fopen64(tmpfil, "w")) == NULL) {
		(void) fprintf(stderr, "edquota: ");
		perror(tmpfil);
		(void) unlink(tmpfil);
		exit(32);
	}
	for (fsqp = fsqlist; fsqp; fsqp = fsqp->fsq_next) {
		fmttime(btime, fsqp->fsq_dqb.dqb_btimelimit);
		fmttime(ftime, fsqp->fsq_dqb.dqb_ftimelimit);
		(void) fprintf(fd,
		    "fs %s blocks time limit = %s, files time limit = %s\n",
		    fsqp->fsq_fs, btime, ftime);
	}
	(void) fclose(fd);
}

static void
puttimes(uid_t uid)
{
	FILE *fd;
	char line[BUFSIZ];
	int changed = 0;
	double btimelimit, ftimelimit;
	char bunits[80], funits[80];

	fd = fopen64(tmpfil, "r");
	if (fd == NULL) {
		(void) fprintf(stderr, "Can't re-read temp file!!\n");
		return;
	}
	while (fgets(line, sizeof (line), fd) != NULL) {
		struct fsquot *fsqp;
		char *cp, *dp;
		int n;

		cp = next(line, " \t");
		if (cp == NULL)
			break;
		*cp++ = '\0';
		while (*cp && *cp == '\t' && *cp == ' ')
			cp++;
		dp = cp, cp = next(cp, " \t");
		if (cp == NULL)
			break;
		*cp++ = '\0';
		for (fsqp = fsqlist; fsqp; fsqp = fsqp->fsq_next) {
			if (strcmp(dp, fsqp->fsq_fs) == 0)
				break;
		}
		if (fsqp == NULL) {
			(void) fprintf(stderr, "%s: unknown file system\n", cp);
			continue;
		}
		while (*cp && *cp == '\t' && *cp == ' ')
			cp++;
		n = sscanf(cp,
		    "blocks time limit = %lf %[^,], "
		    "files time limit = %lf %s\n",
		    &btimelimit, bunits, &ftimelimit, funits);
		if (n != 4 ||
		    !unfmttime(btimelimit, bunits,
			&fsqp->fsq_dqb.dqb_btimelimit) ||
		    !unfmttime(ftimelimit, funits,
			&fsqp->fsq_dqb.dqb_ftimelimit)) {
			(void) fprintf(stderr, "%s: bad format\n", cp);
			continue;
		}
		changed++;
	}
	(void) fclose(fd);
	if (changed)
		putdiscq(uid);
}

static char *
next(char *cp, char *match)
{
	char *dp;

	while (cp && *cp) {
		for (dp = match; dp && *dp; dp++)
			if (*dp == *cp)
				return (cp);
		cp++;
	}
	return ((char *)0);
}

static int
alldigits(char *s)
{
	int c = *s++;

	do {
		if (!isdigit(c))
			return (0);
	} while ((c = *s++) != '\0');

	return (1);
}

static struct {
	int c_secs;			/* conversion units in secs */
	char *c_str;			/* unit string */
} cunits [] = {
	{60*60*24*28, "month"},
	{60*60*24*7, "week"},
	{60*60*24, "day"},
	{60*60, "hour"},
	{60, "min"},
	{1, "sec"}
};

static void
fmttime(char *buf, ulong_t time)
{
	double value;
	int i;

	if (time == 0) {
		(void) strcpy(buf, "0 (default)");
		return;
	}
	for (i = 0; i < sizeof (cunits) / sizeof (cunits[0]); i++)
		if (time >= cunits[i].c_secs)
			break;

	value = (double)time / cunits[i].c_secs;
	(void) sprintf(buf, "%.2f %s%s",
		value, cunits[i].c_str, value > 1.0 ? "s" : "");
}

static int
unfmttime(double value, char *units, uint32_t *timep)
{
	int i;

	if (value == 0.0) {
		*timep = 0;
		return (1);
	}
	for (i = 0; i < sizeof (cunits) / sizeof (cunits[0]); i++) {
		if (strncmp(cunits[i].c_str, units,
		    strlen(cunits[i].c_str)) == 0)
			break;
	}
	if (i >= sizeof (cunits) / sizeof (cunits[0]))
		return (0);
	*timep = (ulong_t)(value * cunits[i].c_secs);
	return (1);
}

static void
setupfs(void)
{
	struct mnttab mntp;
	struct fsquot *fsqp;
	struct stat64 statb;
	dev_t fsdev;
	FILE *mtab;
	char qfilename[MAXPATHLEN];

	if ((mtab = fopen(MNTTAB, "r")) == (FILE *)0) {
		perror("/etc/mnttab");
		exit(31+1);
	}
	while (getmntent(mtab, &mntp) == 0) {
		if (strcmp(mntp.mnt_fstype, MNTTYPE_UFS) != 0)
			continue;
		if (stat64(mntp.mnt_special, &statb) < 0)
			continue;
		if ((statb.st_mode & S_IFMT) != S_IFBLK)
			continue;
		fsdev = statb.st_rdev;
		(void) snprintf(qfilename, sizeof (qfilename), "%s/%s",
			mntp.mnt_mountp, QFNAME);
		if (stat64(qfilename, &statb) < 0 || statb.st_dev != fsdev)
			continue;
		fsqp = malloc(sizeof (struct fsquot));
		if (fsqp == NULL) {
			(void) fprintf(stderr, "out of memory\n");
			exit(31+1);
		}
		fsqp->fsq_next = fsqlist;
		fsqp->fsq_fs = strdup(mntp.mnt_mountp);
		fsqp->fsq_dev = strdup(mntp.mnt_special);
		fsqp->fsq_qfile = strdup(qfilename);
		if (fsqp->fsq_fs == NULL || fsqp->fsq_dev == NULL ||
		    fsqp->fsq_qfile == NULL) {
			(void) fprintf(stderr, "out of memory\n");
			exit(31+1);
		}
		fsqlist = fsqp;
	}
	(void) fclose(mtab);
}

static void
getdiscq(uid_t uid)
{
	struct fsquot *fsqp;
	int fd;

	for (fsqp = fsqlist; fsqp; fsqp = fsqp->fsq_next) {
		if (quotactl(Q_GETQUOTA, fsqp->fsq_dev, uid,
		    (caddr_t)&fsqp->fsq_dqb) != 0) {
			if ((fd = open64(fsqp->fsq_qfile, O_RDONLY)) < 0) {
				(void) fprintf(stderr, "edquota: ");
				perror(fsqp->fsq_qfile);
				continue;
			}
			(void) llseek(fd, (offset_t)dqoff(uid), L_SET);
			switch (read(fd, (char *)&fsqp->fsq_dqb,
			    sizeof (struct dqblk))) {
			case 0:
				/*
				 * Convert implicit 0 quota (EOF)
				 * into an explicit one (zero'ed dqblk)
				 */
				bzero((caddr_t)&fsqp->fsq_dqb,
				    sizeof (struct dqblk));
				break;

			case sizeof (struct dqblk):	/* OK */
				break;

			default:			/* ERROR */
				(void) fprintf(stderr,
				    "edquota: read error in ");
				perror(fsqp->fsq_qfile);
				break;
			}
			(void) close(fd);
		}
	}
}

static void
putdiscq(uid_t uid)
{
	struct fsquot *fsqp;

	for (fsqp = fsqlist; fsqp; fsqp = fsqp->fsq_next) {
		if (quotactl(Q_SETQLIM, fsqp->fsq_dev, uid,
		    (caddr_t)&fsqp->fsq_dqb) != 0) {
			int fd;

			if ((fd = open64(fsqp->fsq_qfile, O_RDWR)) < 0) {
				(void) fprintf(stderr, "edquota: ");
				perror(fsqp->fsq_qfile);
				continue;
			}
			(void) llseek(fd, (offset_t)dqoff(uid), L_SET);
			if (write(fd, (char *)&fsqp->fsq_dqb,
			    sizeof (struct dqblk)) != sizeof (struct dqblk)) {
				(void) fprintf(stderr, "edquota: ");
				perror(fsqp->fsq_qfile);
			}
			(void) close(fd);
		}
	}
}

static void
sigsetmask(uint_t omask)
{
	int i;

	for (i = 0; i < 32; i++)
		if (omask & (1 << i)) {
			if (sigignore(1 << i) == (int)SIG_ERR) {
				(void) fprintf(stderr,
				    "Bad signal 0x%x\n", (1 << i));
				exit(31+1);
			}
		}
}

static uint_t
sigblock(uint_t omask)
{
	uint_t previous = 0;
	uint_t temp;
	int i;

	for (i = 0; i < 32; i++)
		if (omask & (1 << i)) {
			if ((temp = sigignore(1 << i)) == (int)SIG_ERR) {
				(void) fprintf(stderr,
				    "Bad signal 0x%x\n", (1 << i));
				exit(31+1);
			}
			if (i == 0)
				previous = temp;
		}

	return (previous);
}

static void
usage(void)
{
	(void) fprintf(stderr, "ufs usage:\n");
	(void) fprintf(stderr, "\tedquota [-p username] username ...\n");
	(void) fprintf(stderr, "\tedquota -t\n");
	exit(1);
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

	if ((special == NULL) && (cmd == Q_SYNC)) {
		cmd = Q_ALLSYNC;
		/*
		 * need to find an acceptable fd to send this Q_ALLSYNC down
		 * on, it needs to be a ufs fd for vfs to at least call the
		 * real quotactl() in the kernel
		 * Here, try to simply find the starting mountpoint of the
		 * first mounted ufs file system
		 */
	}

	/*
	 * Find the mount point of the special device.   This is
	 * because the fcntl that implements the quotactl call has
	 * to go to a real file, and not to the block device.
	 */
	if ((fstab = fopen(MNTTAB, "r")) == NULL) {
		(void) fprintf(stderr, "%s: ", MNTTAB);
		perror("open");
		exit(31+1);
	}
	qfile[0] = '\0';
	while ((status = getmntent(fstab, &mntp)) == NULL) {
		/*
		 * check that it is a ufs file system
		 * for all quotactl()s except Q_ALLSYNC check that
		 * the file system is read-write since changes in the
		 * quotas file may be required
		 * for Q_ALLSYNC, this check is skipped since this option
		 * is to determine if quotas are configured into the system
		 */
		if (strcmp(mntp.mnt_fstype, MNTTYPE_UFS) != 0 ||
		    ((cmd != Q_ALLSYNC) && hasmntopt(&mntp, MNTOPT_RO)))
			continue;
		if (cmd == Q_ALLSYNC) {	/* implies (special==0) too */
			if (strlcpy(qfile, mntp.mnt_mountp,
				    sizeof (qfile)) >= sizeof (qfile)) {
				errno = ENOENT;
				return (-1);
			}
			break;
		}
		if (strcmp(special, mntp.mnt_special) == 0) {
			if (strlcpy(qfile, mntp.mnt_mountp,
				    sizeof (qfile)) >= sizeof (qfile)) {
				errno = ENOENT;
				return (-1);
			}
		}
	}
	(void) fclose(fstab);
	if (qfile[0] == '\0') {
		errno = ENOENT;
		return (-1);
	}
	{
		int open_flags;

		if (cmd == Q_ALLSYNC) {
			open_flags = O_RDONLY;
		} else {
			if (strlcat(qfile, "/" QFNAME, sizeof (qfile)) >=
			    sizeof (qfile)) {
				errno = ENOENT;
				return (-1);
			}
			open_flags = O_RDWR;
		}

		if ((fd = open64(qfile, open_flags)) < 0) {
			(void) fprintf(stderr, "quotactl: ");
			perror("open");
			exit(31+1);
		}
	}

	quota.op = cmd;
	quota.uid = uid;
	quota.addr = addr;
	status = ioctl(fd, Q_QUOTACTL, &quota);
	(void) close(fd);
	return (status);
}
