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

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * ff -- obtain file names from reading filesystem
 */

#define	NB		500
#define	MAXNINDIR	(MAXBSIZE / sizeof (daddr32_t))

#include <sys/param.h>
#include <sys/types.h>
#include <sys/mntent.h>
#include <sys/vnode.h>
#include <sys/fs/ufs_inode.h>
#include <sys/stat.h>
#include <sys/fs/ufs_fs.h>
#include <sys/fs/ufs_fsdir.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <pwd.h>
#include "roll_log.h"

#define	MIN_PHYS_READ	BBSIZE
#define	DAY		(24*60*60)


union {
	struct	fs	sblk;
	char xxx[SBSIZE];	/* because fs is variable length */
} real_fs;
#define	sblock real_fs.sblk

struct	dinode  *itab;	/*  = (struct dinode *)itab; */

struct 	dinode	*gip;

struct ilist {
	ino_t	ino;
	ushort_t	mode;
	uid_t	uid;
	gid_t	gid;
} ilist[NB];

struct	htab
{
	ino_t	h_ino;
	ino_t	h_pino;
	int	h_name_index;		/* index into string table */
} *htab;
char *strngtab;
long hsize;
int strngloc;
int strngtab_size;
#define	STRNGTAB_INCR	(1024*16)	/* amount to grow strngtab */
#define	MAX_STRNGTAB_INDEX()	(strngtab_size - 1)
#define	AVG_PATH_LEN	30		/* average (?) length of name */

struct dirstuff {
	int loc;
	struct dinode *ip;
	char dbuf[MAXBSIZE];
};
int	Aflg = 0;	/* accessed in n days */
int	Mflg = 0;	/* modified in n days */
int	Nflg = 0;	/* modified more recently than 'file' */
int	Cflg = 0;	/* changed within n days */
int	aflg = 0;	/* print the names `.'  and  `..' */
int	sflg = 0; /* print only special files and files with set-user-ID mode */
int	Sflg = 0;	/* print file size */
int	iflg = 0;	/* number of inodes being searched for */
int	Iflg = 0;	/* do not print i-number */
int	Lflg = 0;	/* supplementary list of multiply linked files */
int	mflg = 0;
int	pflg = 0;	/* a prefix exists */
int	uflg = 0;	/* print the owner's login name */
int	fi;
ino_t	ino;
int	nhent;
int	nxfile;
int	imax;		/* highest inode number */
int	inode_reads;
int	passwd_lookups;
int	Adelay;		/* Access delay */
int	Asign;		/* Access sign */
int	Mdelay;		/* Modify delay */
int	Msign;		/* Modify sign */
int	Cdelay;		/* change delay */
int	Csign;		/* change sign */
time_t	Nage;		/* Last modification time of the file */
char	*Lname;		/* filename for supplementary list */
FILE	*Lfile;		/* file for supplementary list */

/*
 * Function prototypes
 */
void check(char *file);
void pass1(struct dinode *ip);
void pass2(struct dinode *ip);
void pass3(struct dinode *ip);
struct direct *dreaddir(struct dirstuff *dirp);
int dotname(struct direct *dp);
void pname(FILE *stream, ino_t i, int lev);
struct htab *lookup(ino_t i, int ef);
void bread(diskaddr_t bno, char *buf, int cnt);
diskaddr_t bmap(diskaddr_t i);
struct dinode *ginode(ino_t inumber);
char *user_name(int uid);
int cmp(int a, int b, int s);
time_t mod_time(char *file);
void out_multilinks();
void usage();
int extend_strngtab(unsigned int size);

long	atol();
offset_t llseek();
char 	*strcpy();

char	*prefix;
time_t	Today;
int	nerror;


extern int	optind;
extern char	*optarg;

char *subopts [] = {
#define	A_FLAG		0
	"a",
#define	M_FLAG		1
	"m",
#define	S_FLAG		2
	"s",
	NULL
	};

int
main(int argc, char *argv[])
{
	long n;
	int	opt;
	char	*suboptions,	*value;
	char *p;
	int first = 0;

	Today = time((time_t *)0);
	while ((opt = getopt(argc, argv, "Ia:c:i:lm:n:o:p:su")) != EOF) {
		switch (opt) {

		case 'a':
			Aflg++;
			Adelay = atoi(optarg);
			Asign = optarg[0];
			break;

		case 'I':
			Iflg++;
			break;

		case 'c':
			Cflg++;
			Cdelay = atoi(optarg);
			Csign = optarg[0];
			break;

		case 'l':
			Lflg++;
			Lname = tmpnam((char *)0);
			if ((Lfile = fopen(Lname, "w+")) == NULL) {
				perror("open");
				(void) fprintf(stderr,
				"ff: unable to open temp file, -l ignored\n");
				Lflg = 0;
			}
			break;

		case 'm':
			Mflg++;
			Mdelay = atoi(optarg);
			Msign = optarg[0];
			break;

		case 'n':
			Nflg++;
			Nage = mod_time(optarg);
			break;

		case 'o':
			/*
			 * ufs specific options.
			 */
			suboptions = optarg;

			if (*suboptions == '\0')
				usage();
			while (*suboptions != '\0') {
				switch ((getsubopt(&suboptions,
							subopts, &value))) {

				case A_FLAG:
					aflg++;
					break;

				case M_FLAG:
					mflg++;
					break;

				case S_FLAG:
					sflg++;
					break;

				default:
					usage();
				}
			}
			break;

		case 'i':
			while ((p = (char *)strtok(((first++ == 0) ?
			optarg: ((char *)0)), ", ")) != NULL) {
				if ((n = atoi(p)) == 0)
					break;
				ilist[iflg].ino = n;
				nxfile = iflg;
				iflg++;
			}
			break;

		case 'p':
			prefix = optarg;
			pflg++;
			break;

		case 's':
			Sflg++;
			break;

		case 'u':
			uflg++;
			break;

		case '?':
			usage();
		}
	}
	argc -= optind;
	argv = &argv[optind];
	while (argc--) {
		check(*argv);
		argv++;
	}
	if (Lflg) {
		out_multilinks();
	}
	if (nerror)
		return (32);
	return (0);
}

void
check(char *file)
{
	int i, j, c;

	fi = open64(file, 0);
	if (fi < 0) {
		(void) fprintf(stderr, "ff: cannot open %s\n", file);
		nerror++;
		return;
	}
	nhent = 0;
	(void) printf("%s:\n", file);
	sync();
	bread(SBLOCK, (char *)&sblock, SBSIZE);
	if ((sblock.fs_magic != FS_MAGIC) &&
	    (sblock.fs_magic != MTB_UFS_MAGIC)) {
		(void) fprintf(stderr, "%s: not a ufs file system\n", file);
		nerror++;
		return;
	}

	if (sblock.fs_magic == FS_MAGIC &&
	    (sblock.fs_version != UFS_EFISTYLE4NONEFI_VERSION_2 &&
	    sblock.fs_version != UFS_VERSION_MIN)) {
		(void) fprintf(stderr, "%s: unrecognized version of UFS: %d\n",
		    file, sblock.fs_version);
		nerror++;
		return;
	}

	if (sblock.fs_magic == MTB_UFS_MAGIC &&
	    (sblock.fs_version > MTB_UFS_VERSION_1 ||
	    sblock.fs_version < MTB_UFS_VERSION_MIN)) {
		(void) fprintf(stderr, "%s: unrecognized version of UFS: %d\n",
		    file, sblock.fs_version);
		nerror++;
		return;
	}

	/* If fs is logged, roll the log. */
	if (sblock.fs_logbno) {
		switch (rl_roll_log(file)) {
		case RL_SUCCESS:
			/*
			 * Reread the superblock.  Rolling the log may have
			 * changed it.
			 */
			bread(SBLOCK, (char *)&sblock, SBSIZE);
			break;
		case RL_SYSERR:
			(void) printf("Warning: Cannot roll log for %s.  %s\n",
				file, strerror(errno));
			break;
		default:
			(void) printf("Warning: Cannot roll log for %s.\n ",
				file);
			break;
		}
	}


	itab = (struct dinode *)calloc(sblock.fs_ipg, sizeof (struct dinode));
	imax = sblock.fs_ncg * sblock.fs_ipg;

	hsize = sblock.fs_ipg * sblock.fs_ncg - sblock.fs_cstotal.cs_nifree + 1;
	htab = (struct htab *)calloc(hsize, sizeof (struct htab));

	if (!extend_strngtab(AVG_PATH_LEN * hsize)) {
		(void) printf("not enough memory to allocate tables\n");
		nerror++;
		return;
	}
	strngloc = 0;

	if ((itab == NULL) || (htab == NULL)) {
		(void) printf("not enough memory to allocate tables\n");
		nerror++;
		return;
	}
	ino = 0;
	for (c = 0; c < sblock.fs_ncg; c++) {
		bread(fsbtodb(&sblock, cgimin(&sblock, c)), (char *)itab,
		    (int)(sblock.fs_ipg * sizeof (struct dinode)));
		for (j = 0; j < sblock.fs_ipg; j++) {
			if (itab[j].di_smode != 0) {
				itab[j].di_mode = itab[j].di_smode;
				if (itab[j].di_suid != (o_uid_t)UID_LONG)
				itab[j].di_uid = (unsigned int)itab[j].di_suid;
				if (itab[j].di_sgid != GID_LONG)
				itab[j].di_gid = (unsigned int)itab[j].di_sgid;
				pass1(&itab[j]);
			}
			ino++;
		}
	}
	ilist[nxfile+1].ino = 0;
	ino = 0;
	for (c = 0; c < sblock.fs_ncg; c++) {
		bread(fsbtodb(&sblock, cgimin(&sblock, c)), (char *)itab,
		    (int)(sblock.fs_ipg * sizeof (struct dinode)));
		for (j = 0; j < sblock.fs_ipg; j++) {
			if (itab[j].di_smode != 0) {
				itab[j].di_mode = itab[j].di_smode;
				pass2(&itab[j]);
			}
			ino++;
		}
	}
	ino = 0;
	for (c = 0; c < sblock.fs_ncg; c++) {
		bread(fsbtodb(&sblock, cgimin(&sblock, c)), (char *)itab,
		    (int)(sblock.fs_ipg * sizeof (struct dinode)));
		for (j = 0; j < sblock.fs_ipg; j++) {
			if (itab[j].di_smode != 0) {
				itab[j].di_mode = itab[j].di_smode;
				pass3(&itab[j]);
			}
			ino++;
		}
	}
	(void) close(fi);
	for (i = iflg; i < NB; i++)
		ilist[i].ino = 0;
	nxfile = iflg;
	free(itab);
	free(htab);
	free(strngtab);
}

void
pass1(struct dinode *ip)
{
	int i;

	if (mflg)
		for (i = 0; i < iflg; i++)
			if (ino == ilist[i].ino) {
				ilist[i].mode = ip->di_mode;
				ilist[i].uid = ip->di_uid;
				ilist[i].gid = ip->di_gid;
			}
	if ((ip->di_mode & IFMT) != IFDIR) {
		if (sflg == 0 || nxfile >= NB)
			return;
		if ((ip->di_mode&IFMT) == IFBLK ||
		    (ip->di_mode&IFMT) == IFCHR || ip->di_mode&(ISUID|ISGID)) {
			ilist[nxfile].ino = ino;
			ilist[nxfile].mode = ip->di_mode;
			ilist[nxfile].uid = ip->di_uid;
			ilist[nxfile++].gid = ip->di_gid;
			return;
		}
	}
	(void) lookup(ino, 1);
}

void
pass2(struct dinode *ip)
{
	struct direct *dp;
	struct dirstuff dirp;
	struct htab *hp;

	if ((ip->di_mode&IFMT) != IFDIR)
		return;
	dirp.loc = 0;
	dirp.ip = ip;
	gip = ip;
	for (dp = dreaddir(&dirp); dp != NULL; dp = dreaddir(&dirp)) {
		int nmlen;

		if (dp->d_ino == 0)
			continue;
		hp = lookup(dp->d_ino, 0);
		if (hp == 0)
			continue;
		if (dotname(dp))
			continue;
		hp->h_pino = ino;
		nmlen = strlen(dp->d_name);

		if (strngloc + nmlen + 1 > MAX_STRNGTAB_INDEX()) {
			if (!extend_strngtab(STRNGTAB_INCR)) {
				perror("ncheck: can't grow string table\n");
				exit(32);
			}
		}

		hp->h_name_index = strngloc;
		(void) strcpy(&strngtab[strngloc], dp->d_name);
		strngloc += nmlen + 1;
	}
}

void
pass3(struct dinode *ip)
{
	struct direct *dp;
	struct dirstuff dirp;
	struct dinode   *dip;
	int k;

	if ((ip->di_mode&IFMT) != IFDIR)
		return;
	dirp.loc = 0;
	dirp.ip = ip;
	gip = ip;
	for (dp = dreaddir(&dirp); dp != NULL; dp = dreaddir(&dirp)) {
		if (aflg == 0 && dotname(dp))
			continue;
		if (sflg == 0 && iflg == 0)
			goto pr;
		for (k = 0; ilist[k].ino != 0; k++)
			if (ilist[k].ino == dp->d_ino)
				break;
		if (ilist[k].ino == 0)
			continue;
		if (mflg)
			(void) printf("mode %-6o uid %-5ld gid %-5ld ino ",
			    ilist[k].mode, ilist[k].uid, ilist[k].gid);
	pr:
		if (Sflg || uflg || Aflg || Mflg || Cflg || Nflg || Lflg)
			dip = ginode(dp->d_ino);
		if ((!Aflg ||
		cmp((Today - dip->di_un.di_icom.ic_atime)/DAY, Adelay,
		    Asign)) &&
		    (!Mflg || cmp((Today - dip->di_un.di_icom.ic_mtime)/DAY,
			Mdelay, Msign)) &&
		    (!Cflg || cmp((Today - dip->di_un.di_icom.ic_mtime)/DAY,
			Cdelay, Csign)) &&
		    (!Nflg || cmp(dip->di_un.di_icom.ic_mtime, Nage, '+'))) {
			if (Iflg == 0)
				(void) printf("%-5u\t", dp->d_ino);
			pname(stdout, ino, 0);
			(void) printf("/%s", dp->d_name);
			if (lookup(dp->d_ino, 0))
				(void) printf("/.");
			if (Sflg)
				(void) printf("\t%6lld",
				    dip->di_un.di_icom.ic_lsize);
			if (uflg)
				(void) printf("\t%s",
				    user_name(dip->di_un.di_icom.ic_uid));
			(void) printf("\n");
			if (Lflg && (dip->di_un.di_icom.ic_nlink > 1)) {
				(void) fprintf(Lfile, "%-5u\t",
					dp->d_ino);
				(void) fprintf(Lfile, "%-5u\t",
					dip->di_un.di_icom.ic_nlink);
				pname(Lfile, ino, 0);
				(void) fprintf(Lfile, "/%s\n", dp->d_name);
			}
		}
	}
}



/*
 * get next entry in a directory.
 */
struct direct *
dreaddir(struct dirstuff *dirp)
{
	struct direct *dp;
	diskaddr_t lbn, d;

	for (;;) {
		if (dirp->loc >= (int)dirp->ip->di_size)
			return (NULL);
		if (blkoff(&sblock, dirp->loc) == 0) {
			lbn = lblkno(&sblock, dirp->loc);
			d = bmap(lbn);
			if (d == 0)
				return (NULL);
			bread(fsbtodb(&sblock, d), dirp->dbuf,
			    (int)dblksize(&sblock, dirp->ip, (int)lbn));
		}
		dp = (struct direct *)
		    (dirp->dbuf + blkoff(&sblock, dirp->loc));
		dirp->loc += dp->d_reclen;
		if (dp->d_ino == 0)
			continue;
		return (dp);
	}
}

int
dotname(struct direct *dp)
{

	if (dp->d_name[0] == '.')
		if (dp->d_name[1] == 0 ||
		    (dp->d_name[1] == '.' && dp->d_name[2] == 0))
			return (1);
	return (0);
}

void
pname(FILE *stream, ino_t i, int lev)
{
	struct htab *hp;

	if (i == UFSROOTINO)
		return;
	if ((hp = lookup(i, 0)) == 0) {
		(void) fprintf(stream, "???");
		return;
	}
	if (lev > 10) {
		(void) fprintf(stream, "...");
		return;
	}
	pname(stream, hp->h_pino, ++lev);
	if (pflg)
		(void) fprintf(stream, "%s/%s", prefix,
			&(strngtab[hp->h_name_index]));
	else
		(void) fprintf(stream, "/%s",
			&(strngtab[hp->h_name_index]));
}

struct htab *
lookup(ino_t i, int ef)
{
	struct htab *hp;

	for (hp = &htab[(int)i%hsize]; hp->h_ino; ) {
		if (hp->h_ino == i)
			return (hp);
		if (++hp >= &htab[hsize])
			hp = htab;
	}
	if (ef == 0)
		return (0);
	if (++nhent >= hsize) {
		(void) fprintf(stderr,
		    "ff: hsize of %ld is too small\n", hsize);
		exit(32);
	}
	hp->h_ino = i;
	return (hp);
}

void
bread(diskaddr_t bno, char *buf, int cnt)
{
	int i;
	int got;
	offset_t offset;

	offset = (offset_t)bno * DEV_BSIZE;
	if (llseek(fi, offset, 0) == (offset_t)-1) {
		(void) fprintf(stderr,
		    "ff: llseek error %lx %lx\n",
		    ((long *)&offset)[0], ((long *)&offset)[1]);
		for (i = 0; i < cnt; i++)
			buf[i] = 0;
		return;
	}

	got = read((int)fi, buf, cnt);
	if (got != cnt) {
		perror("read");
		(void) fprintf(stderr,
			"ff: (wanted %d got %d blk %lld)\n", cnt, got, bno);
		for (i = 0; i < cnt; i++)
			buf[i] = 0;
	}
}

diskaddr_t
bmap(diskaddr_t i)
{
	daddr32_t ibuf[MAXNINDIR];

	if (i < NDADDR)
		return ((diskaddr_t)gip->di_db[i]);
	i -= NDADDR;
	if (i > NINDIR(&sblock)) {
		(void) fprintf(stderr, "ff    : %lu - huge directory\n", ino);
		return ((diskaddr_t)0);
	}
	bread(fsbtodb(&sblock, gip->di_ib[0]), (char *)ibuf, sizeof (ibuf));
	return ((diskaddr_t)ibuf[i]);
}

struct dinode *
ginode(ino_t inumber)
{
	diskaddr_t		iblk;
	diskaddr_t		dblk;
	int		ioff;
	static diskaddr_t	curr_dblk;
	static char	buf[MIN_PHYS_READ];
	struct dinode	*ibuf;

	if (inumber < UFSROOTINO || (int)inumber > imax) {
		(void) fprintf(stderr,
		    "bad inode number %ld to ginode\n", inumber);
		exit(32);
	}
	iblk = itod(&sblock, (int)inumber);
	dblk = fsbtodb(&sblock, iblk);
	ioff = itoo(&sblock, (int)inumber);
	if (dblk != curr_dblk) {
		bread(dblk, &buf[0], sizeof (buf));
		curr_dblk = dblk;
		inode_reads++;
	}
	ibuf = (struct dinode *)&buf[0];
	ibuf += ioff;
	return (ibuf);
}

#define	HASHNAMESIZE 16

struct name_ent {
	struct name_ent	*name_nxt;
	int		name_uid;
	char		*name_string;
};
struct name_ent *hashtable[HASHNAMESIZE];

char *
user_name(int uid)
{
	int		h_index;
	struct name_ent	*hp;
	struct passwd	*pwent;

	h_index = uid % HASHNAMESIZE;
	for (hp = hashtable[h_index]; hp != NULL; hp = hp->name_nxt) {
		if (hp->name_uid == uid) {
			return (hp->name_string);
		}
	}
	hp = (struct name_ent *)calloc(1, sizeof (struct name_ent));
	hp->name_nxt = hashtable[h_index];
	hp->name_uid = uid;
	hashtable[h_index] = hp;
	if ((pwent = getpwuid(uid)) == NULL) {
		hp->name_string = "unknown";
	} else {
		hp->name_string = (char *)strdup(pwent->pw_name);
	}
	passwd_lookups++;

	return (hp->name_string);
}

int
cmp(int a, int b, int s)
{
	if (s == '+')
		return (a > b);
	if (s == '-')
		return (a < -(b));
	return (a == b);
}

/*
 * We can't do this one by reading the disk directly, since there
 * is no guarantee that the file is even on a local disk.
 */
time_t
mod_time(char *file)
{
	struct stat64	stat_buf;

	if (stat64(file, &stat_buf) < 0) {
		(void) fprintf(stderr, "ff: can't stat '%s' - ignored\n", file);
		return (0);
	}
	return (stat_buf.st_mtime);
}

void
out_multilinks()
{
	int	length;

	if ((length = fseek(Lfile, 0L, 2)) < 0) {
		perror("fseek");
		exit(32);
	} else
		if ((length = ftell(Lfile)) > 0) {
			(void) fprintf(stdout,
			    "\nmultilink files\nIno\tLinks\tPathname\n\n");
			rewind(Lfile);
			while (length-- > 0)
				(void) putc(getc(Lfile), stdout);
		} else
			(void) fprintf(stdout, "No multilink files\n");
	(void) fclose(Lfile);
}

void
usage()
{
	(void) fprintf(stderr,
	    "ufs usage: ff [-F ufs] [generic options] [-o a,m,s] special\n");
	exit(32);
}

/*
 * Extend or create the string table.
 * Preserves contents.
 * Return non-zero for success.
 */
int
extend_strngtab(unsigned int size)
{
	strngtab_size += size;
	strngtab = (char *)realloc(strngtab, strngtab_size);

	return ((int)strngtab);
}
