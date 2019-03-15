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
 * quot
 */

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <limits.h>
#include <pwd.h>
#include <sys/mnttab.h>
#include <sys/param.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/mntent.h>
#include <sys/vnode.h>
#include <sys/fs/ufs_inode.h>
#include <sys/fs/ufs_fs.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <fcntl.h>

#define	ISIZ	(MAXBSIZE/sizeof (struct dinode))
static union {
	struct fs u_sblock;
	char dummy[SBSIZE];
} sb_un;
#define	sblock sb_un.u_sblock
static struct dinode *itab;

struct du {
	struct	du *next;
	long	blocks;
	long	blocks30;
	long	blocks60;
	long	blocks90;
	long	nfiles;
	uid_t	uid;
	char	*u_name;
};
static struct du **du;

#define	UHASH 8209
static int	ndu;
#define	HASH(u) ((uint_t)(u) % UHASH)
static struct	du *duhashtbl[UHASH];

#define	TSIZE	2048
static int	sizes[TSIZE];
static offset_t overflow;

static int	nflg;
static int	fflg;
static int	cflg;
static int	vflg;
static int	hflg;
static int	aflg;
static long	now;

static unsigned	ino;

static void usage(void);
static void quotall(void);
static void qacct(struct dinode *);
static void bread(int, diskaddr_t, char *, int);
static void report(void);
static int getdev(char **);
static int check(char *, char *);
static struct du *adduid(uid_t);
static struct du *lookup(uid_t);
static void sortprep(void);
static void cleanup(void);

static void
usage()
{
	(void) fprintf(stderr, "ufs usage: quot [-nfcvha] [filesystem ...]\n");
}

int
main(int argc, char *argv[])
{
	int	opt;
	int	i;

	if (argc == 1) {
		(void) fprintf(stderr,
		    "ufs Usage: quot [-nfcvha] [filesystem ...]\n");
		return (32);
	}

	now = time(0);
	while ((opt = getopt(argc, argv, "nfcvhaV")) != EOF) {
		switch (opt) {
		case 'n':
			nflg++;
			break;
		case 'f':
			fflg++;
			break;
		case 'c':
			cflg++;
			break;
		case 'v':
			vflg++;
			break;
		case 'h':
			hflg++;
			break;
		case 'a':
			aflg++;
			break;
		case 'V':		/* Print command line */
			{
				char		*opt_text;
				int		opt_count;

				(void) fprintf(stdout, "quot -F UFS ");
				for (opt_count = 1; opt_count < argc;
				    opt_count++) {
					opt_text = argv[opt_count];
					if (opt_text)
						(void) fprintf(stdout, " %s ",
						    opt_text);
				}
				(void) fprintf(stdout, "\n");
			}
			break;
		case '?':
			usage();
			return (32);
		}
	}

	if (aflg) {
		quotall();
	}

	for (i = optind; i < argc; i++) {
		if ((getdev(&argv[i]) == 0) &&
			(check(argv[i], (char *)NULL) == 0)) {
				report();
				cleanup();
		}
	}
	return (0);
}

static void
quotall()
{
	FILE *fstab;
	struct mnttab mntp;
	char *cp;

	extern char *getfullrawname();

	fstab = fopen(MNTTAB, "r");
	if (fstab == NULL) {
		(void) fprintf(stderr, "quot: no %s file\n", MNTTAB);
		exit(32);
	}
	while (getmntent(fstab, &mntp) == 0) {
		if (strcmp(mntp.mnt_fstype, MNTTYPE_UFS) != 0)
			continue;

		if ((cp = getfullrawname(mntp.mnt_special)) == NULL)
			continue;

		if (*cp == '\0')
			continue;

		if (check(cp, mntp.mnt_mountp) == 0) {
			report();
			cleanup();
		}

		free(cp);
	}
	(void) fclose(fstab);
}

static int
check(char *file, char *fsdir)
{
	FILE *fstab;
	int i, j;
	int c, fd;


	/*
	 * Initialize tables between checks;
	 * because of the qsort done in report()
	 * the hash tables must be rebuilt each time.
	 */
	for (i = 0; i < TSIZE; i++)
		sizes[i] = 0;
	overflow = 0LL;
	ndu = 0;
	fd = open64(file, O_RDONLY);
	if (fd < 0) {
		(void) fprintf(stderr, "quot: ");
		perror(file);
		exit(32);
	}
	(void) printf("%s", file);
	if (fsdir == NULL) {
		struct mnttab mntp;

		fstab = fopen(MNTTAB, "r");
		if (fstab == NULL) {
			(void) fprintf(stderr, "quot: no %s file\n", MNTTAB);
			exit(32);
		}
		while (getmntent(fstab, &mntp) == 0) {
			if (strcmp(mntp.mnt_fstype, MNTTYPE_UFS) != 0)
				continue;
			if (strcmp(mntp.mnt_special, file) == 0) {
				fsdir = mntp.mnt_mountp;
				break;
			}
		}
	}
	if (fsdir != NULL && *fsdir != '\0')
		(void) printf(" (%s)", fsdir);
	(void) printf(":\n");
	sync();
	bread(fd, (diskaddr_t)SBLOCK, (char *)&sblock, SBSIZE);
	if (nflg) {
		if (isdigit(c = getchar()))
			(void) ungetc(c, stdin);
		else while (c != '\n' && c != EOF)
			c = getchar();
	}

	itab = (struct dinode *)calloc(sblock.fs_ipg, sizeof (struct dinode));
	if (itab == NULL) {
		(void) fprintf(stderr,
				"not enough memory to allocate tables\n");
		return (1);
	}

	ino = 0;
	for (c = 0; c < sblock.fs_ncg; c++) {
		bread(fd, (diskaddr_t)fsbtodb(&sblock, cgimin(&sblock, c)),
				(char *)itab,
				(int)(sblock.fs_ipg * sizeof (struct dinode)));
		for (j = 0; j < sblock.fs_ipg; j++, ino++) {
			if (ino < UFSROOTINO)
				continue;
			qacct(&itab[j]);
		}
	}
	(void) close(fd);
	return (0);
}

static void
qacct(struct dinode *ip)
{
	struct du *dp;
	long blks, frags, size;
	int n;
	static int fino;

	ip->di_mode = ip->di_smode;
	if (ip->di_suid != UID_LONG) {
		ip->di_uid = ip->di_suid;
	}
	if ((ip->di_mode & IFMT) == 0)
		return;
	/*
	 * By default, take block count in inode.  Otherwise (-h),
	 * take the size field and estimate the blocks allocated.
	 * The latter does not account for holes in files.
	 */
	if (!hflg)
		size = ip->di_blocks / 2;
	else {
		blks = lblkno(&sblock, ip->di_size);
		frags = blks * sblock.fs_frag +
			numfrags(&sblock, dblksize(&sblock, ip, blks));
		/*
		 * Must cast to offset_t because for a large file,
		 * frags multiplied by sblock.fs_fsize will not fit in a long.
		 * However, when divided by 1024, the end result will fit in
		 * the 32 bit size variable (40 bit UFS).
		 */
	    size = (long)((offset_t)frags * (offset_t)sblock.fs_fsize / 1024);
	}
	if (cflg) {
		if ((ip->di_mode&IFMT) != IFDIR && (ip->di_mode&IFMT) != IFREG)
			return;
		if (size >= TSIZE) {
			overflow += (offset_t)size;
			size = TSIZE-1;
		}
		sizes[size]++;
		return;
	}
	dp = lookup(ip->di_uid);
	if (dp == NULL)
		return;
	dp->blocks += size;
#define	DAY (60 * 60 * 24)	/* seconds per day */
	if (now - ip->di_atime > 30 * DAY)
		dp->blocks30 += size;
	if (now - ip->di_atime > 60 * DAY)
		dp->blocks60 += size;
	if (now - ip->di_atime > 90 * DAY)
		dp->blocks90 += size;
	dp->nfiles++;
	while (nflg) {
		if (fino == 0)
			if (scanf("%d", &fino) <= 0)
				return;
		if (fino > ino)
			return;
		if (fino < ino) {
			while ((n = getchar()) != '\n' && n != EOF)
				;
			fino = 0;
			continue;
		}
		if (dp->u_name)
			(void) printf("%.7s	", dp->u_name);
		else
			(void) printf("%ld	", (long)ip->di_uid);
		while ((n = getchar()) == ' ' || n == '\t')
			;
		(void) putchar(n);
		while (n != EOF && n != '\n') {
			n = getchar();
			(void) putchar(n);
		}
		fino = 0;
		break;
	}
}

static void
bread(int fd, diskaddr_t bno, char *buf, int cnt)
{
	int	ret;

	if (llseek(fd, (offset_t)(bno * DEV_BSIZE), SEEK_SET) < 0) {
		perror("llseek");
		exit(32);
	}

	if ((ret = read(fd, buf, cnt)) != cnt) {
		(void) fprintf(stderr, "quot: read returns %d (cnt = %d)\n",
						ret, cnt);
		(void) fprintf(stderr, "quot: read error at block %lld\n", bno);
		perror("read");
		exit(32);
	}
}

static int
qcmp(const void *arg1, const void *arg2)
{
	struct du **p1 = (struct du **)arg1;
	struct du **p2 = (struct du **)arg2;
	char *s1, *s2;

	if ((*p1)->blocks > (*p2)->blocks)
		return (-1);
	if ((*p1)->blocks < (*p2)->blocks)
		return (1);
	s1 = (*p1)->u_name;
	if (s1 == NULL)
		return (0);
	s2 = (*p2)->u_name;
	if (s2 == NULL)
		return (0);
	return (strcmp(s1, s2));
}

static void
report()
{
	int i;
	struct du **dp;
	int cnt;

	if (nflg)
		return;
	if (cflg) {
		long t = 0;

		for (i = 0; i < TSIZE - 1; i++)
			if (sizes[i]) {
				t += i*sizes[i];
				(void) printf("%d	%d	%ld\n",
								i, sizes[i], t);
			}
		if (sizes[TSIZE -1 ])
			(void) printf("%d	%d	%lld\n", TSIZE - 1,
			    sizes[TSIZE - 1], overflow + (offset_t)t);
		return;
	}
	sortprep();
	qsort(du, ndu, sizeof (du[0]), qcmp);
	for (cnt = 0, dp = &du[0]; dp && cnt != ndu; dp++, cnt++) {
		if ((*dp)->blocks == 0)
			return;
		(void) printf("%5ld\t", (*dp)->blocks);
		if (fflg)
			(void) printf("%5ld\t", (*dp)->nfiles);

		if ((*dp)->u_name)
			(void) printf("%-8s", (*dp)->u_name);
		else
			(void) printf("#%-8ld", (long)(*dp)->uid);
		if (vflg)
			(void) printf("\t%5ld\t%5ld\t%5ld",
			    (*dp)->blocks30, (*dp)->blocks60, (*dp)->blocks90);
		(void) printf("\n");
	}
}



static int
getdev(char **devpp)
{
	struct stat64 statb;
	FILE *fstab;
	struct mnttab mntp;
	char *cp;	/* Pointer to raw device name */

	extern char *getfullrawname();

	if (stat64(*devpp, &statb) < 0) {
		perror(*devpp);
		exit(32);
	}
	if ((statb.st_mode & S_IFMT) == S_IFCHR)
		return (0);
	if ((statb.st_mode & S_IFMT) == S_IFBLK) {
		/* If we can't get the raw name, keep the block name */
		if ((cp = getfullrawname(*devpp)) != NULL)
			*devpp = strdup(cp);
		return (0);
	}
	fstab = fopen(MNTTAB, "r");
	if (fstab == NULL) {
		(void) fprintf(stderr, "quot: no %s file\n", MNTTAB);
		exit(32);
	}
	while (getmntent(fstab, &mntp) == 0) {
		if (strcmp(mntp.mnt_mountp, *devpp) == 0) {
			if (strcmp(mntp.mnt_fstype, MNTTYPE_UFS) != 0) {
				(void) fprintf(stderr,
				    "quot: %s not ufs filesystem\n",
				    *devpp);
				exit(32);
			}
			/* If we can't get the raw name, use the block name */
			if ((cp = getfullrawname(mntp.mnt_special)) == NULL)
				cp = mntp.mnt_special;
			*devpp = strdup(cp);
			(void) fclose(fstab);
			return (0);
		}
	}
	(void) fclose(fstab);
	(void) fprintf(stderr, "quot: %s doesn't appear to be a filesystem.\n",
	    *devpp);
	usage();
	exit(32);
	/* NOTREACHED */
}

static struct du *
lookup(uid_t uid)
{
	struct	passwd *pwp;
	struct	du *up;

	for (up = duhashtbl[HASH(uid)]; up != NULL; up = up->next) {
		if (up->uid == uid)
			return (up);
	}

	pwp = getpwuid(uid);

	up = adduid(uid);
	if (up && pwp) {
		up->u_name = strdup(pwp->pw_name);
	}
	return (up);
}

static struct du *
adduid(uid_t uid)
{
	struct du *up, **uhp;

	up = (struct du *)calloc(1, sizeof (struct du));
	if (up == NULL) {
		(void) fprintf(stderr,
			"out of memory for du structures\n");
			exit(32);
	}

	uhp = &duhashtbl[HASH(uid)];
	up->next = *uhp;
	*uhp = up;
	up->uid = uid;
	up->u_name = NULL;
	ndu++;
	return (up);
}

static void
sortprep()
{
	struct du **dp, *ep;
	struct du **hp;
	int i, cnt = 0;

	dp = NULL;

	dp = (struct du **)calloc(ndu, sizeof (struct du **));
	if (dp == NULL) {
		(void) fprintf(stderr,
			"out of memory for du structures\n");
			exit(32);
	}

	for (hp = duhashtbl, i = 0; i != UHASH; i++) {
		if (hp[i] == NULL)
			continue;

		for (ep = hp[i]; ep; ep = ep->next) {
			dp[cnt++] = ep;
		}
	}
	du = dp;
}

static void
cleanup()
{
	int		i;
	struct du	*ep, *next;

	/*
	 * Release memory from hash table and du
	 */

	if (du) {
		free(du);
		du = NULL;
	}


	for (i = 0; i != UHASH; i++) {
		if (duhashtbl[i] == NULL)
			continue;
		ep = duhashtbl[i];
		while (ep) {
			next = ep->next;
			if (ep->u_name) {
				free(ep->u_name);
			}
			free(ep);
			ep = next;
		}
		duhashtbl[i] = NULL;
	}
}
