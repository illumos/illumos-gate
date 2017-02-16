/* Portions Copyright 2006 Stephen P. Potter */

/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * Copyright (c) 1980 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

/*
 * ls
 *
 * 4.2bsd version for symbolic links, variable length
 * directory entries, block size in the inode, etc.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stddef.h>
#include <dirent.h>
#include <ctype.h>
#include <time.h>
#include <limits.h>
#include <locale.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/termios.h>
#include <sys/mkdev.h>
#include <sys/acl.h>

#define	dbtokb(nb)	((nb) / (1024 / DEV_BSIZE))

struct afile {
	char	ftype;		/* file type, e.g. 'd', 'c', 'f' */
	ino_t	fnum;		/* inode number of file */
	short	fflags;		/* mode&~S_IFMT, perhaps ISARG */
	nlink_t	fnl;		/* number of links */
	uid_t	fuid;		/* owner id */
	gid_t	fgid;		/* group id */
	off_t	fsize;		/* file size */
	blkcnt_t	fblks;		/* number of blocks used */
	time_t	fmtime;		/* time (modify or access or create) */
	char	*fname;		/* file name */
	char	*flinkto;	/* symbolic link value */
	char	acl;		/* acl access flag */
};

#define	ISARG	0x8000		/* extra ``mode'' */

static struct subdirs {
	char	*sd_name;
	struct	subdirs *sd_next;
} *subdirs;

static	int	aflg, dflg, gflg, lflg, sflg, tflg, uflg, iflg, fflg, cflg;
static	int	rflg = 1;
static	int	qflg, Aflg, Cflg, Fflg, Lflg, Rflg;

static	int	usetabs;

static	time_t	now, sixmonthsago, onehourfromnow;

static	char	*dotp = ".";

static	struct	winsize win;
static	int	twidth;

static	struct	afile *gstat(struct afile *, char *, int, off_t *);
static	int	fcmp(const void *, const void *);
static	char	*cat(char *, char *);
static	char	*savestr(char *);
static	char	*fmtentry(struct afile *);
static	char	*getname(), *getgroup();
static	void	formatd(char *, int);
static	void	formatf(struct afile *, struct afile *);
static	off_t	getdir(char *, struct afile **, struct afile **);

int
main(int argc, char **argv)
{
	int i;
	struct afile *fp0, *fplast;
	register struct afile *fp;
	struct termios trbuf;

	argc--, argv++;
	if (getuid() == 0)
		Aflg++;
	(void) time(&now);
	sixmonthsago = now - 6L*30L*24L*60L*60L;
	onehourfromnow = now + 60L*60L;
	now += 60;
	twidth = 80;
	if (isatty(1)) {
		qflg = Cflg = 1;
		(void) ioctl(1, TCGETS, &trbuf);
		if (ioctl(1, TIOCGWINSZ, &win) != -1)
			twidth = (win.ws_col == 0 ? 80 : win.ws_col);
		if ((trbuf.c_oflag & TABDLY) != TAB3)
			usetabs = 1;
	} else
		usetabs = 1;

	(void) setlocale(LC_ALL, "");		/* set local environment */

	while (argc > 0 && **argv == '-') {
		(*argv)++;
		while (**argv) {
			switch (*(*argv)++) {
			case 'C':
				Cflg = 1; break;
			case 'q':
				qflg = 1; break;
			case '1':
				Cflg = 0; break;
			case 'a':
				aflg++; break;
			case 'A':
				Aflg++; break;
			case 'c':
				cflg++; break;
			case 's':
				sflg++; break;
			case 'd':
				dflg++; break;
			case 'g':
				gflg++; break;
			case 'l':
				lflg++; break;
			case 'r':
				rflg = -1; break;
			case 't':
				tflg++; break;
			case 'u':
				uflg++; break;
			case 'i':
				iflg++; break;
			case 'f':
				fflg++; break;
			case 'L':
				Lflg++; break;
			case 'F':
				Fflg++; break;
			case 'R':
				Rflg++; break;
			}
		}
		argc--, argv++;
	}
	if (fflg) {
		aflg++; lflg = 0; sflg = 0; tflg = 0;
	}
	if (lflg)
		Cflg = 0;
	if (argc == 0) {
		argc++;
		argv = &dotp;
	}
	fp = (struct afile *)calloc(argc, sizeof (struct afile));
	if (fp == 0) {
		(void) fprintf(stderr, "ls: out of memory\n");
		exit(1);
	}
	fp0 = fp;
	for (i = 0; i < argc; i++) {
		if (gstat(fp, *argv, 1, (off_t *)0)) {
			fp->fname = *argv;
			fp->fflags |= ISARG;
			fp++;
		}
		argv++;
	}
	fplast = fp;
	qsort(fp0, fplast - fp0, sizeof (struct afile), fcmp);
	if (dflg) {
		formatf(fp0, fplast);
		exit(0);
	}
	if (fflg)
		fp = fp0;
	else {
		for (fp = fp0; fp < fplast && fp->ftype != 'd'; fp++)
			continue;
		formatf(fp0, fp);
	}
	if (fp < fplast) {
		if (fp > fp0)
			(void) printf("\n");
		for (;;) {
			formatd(fp->fname, argc > 1);
			while (subdirs) {
				struct subdirs *t;

				t = subdirs; subdirs = t->sd_next;
				(void) printf("\n");
				formatd(t->sd_name, 1);
				free(t->sd_name);
				free(t);
			}
			if (++fp == fplast)
				break;
			(void) printf("\n");
		}
	}
	return (0);
}

static void
formatd(char *name, int title)
{
	register struct afile *fp;
	register struct subdirs *dp;
	struct afile *dfp0, *dfplast;
	off_t nkb;

	nkb = getdir(name, &dfp0, &dfplast);
	if (dfp0 == 0)
		return;
	if (fflg == 0)
		qsort(dfp0, dfplast - dfp0, sizeof (struct afile), fcmp);
	if (title)
		(void) printf("%s:\n", name);
	if (lflg || sflg)
		(void) printf("total %lld\n", nkb);
	formatf(dfp0, dfplast);
	if (Rflg)
		for (fp = dfplast - 1; fp >= dfp0; fp--) {
			if (fp->ftype != 'd' ||
			    strcmp(fp->fname, ".") == 0 ||
			    strcmp(fp->fname, "..") == 0)
				continue;
			dp = (struct subdirs *)malloc(sizeof (struct subdirs));
			dp->sd_name = savestr(cat(name, fp->fname));
			dp->sd_next = subdirs; subdirs = dp;
		}
	for (fp = dfp0; fp < dfplast; fp++) {
		if ((fp->fflags&ISARG) == 0 && fp->fname)
			free(fp->fname);
		if (fp->flinkto)
			free(fp->flinkto);
	}
	free(dfp0);
}

static off_t
getdir(char *dir, struct afile **pfp0, struct afile **pfplast)
{
	register struct afile *fp;
	DIR *dirp;
	register struct dirent *dp;
	off_t nb;
	size_t nent = 20;

	/*
	 * This code (opendir, readdir, and the "for" loop) is arranged in
	 * this strange manner to handle the case where UNIX lets root open
	 * any directory for reading, but NFS does not let root read the
	 * openned directory.
	 */
	*pfp0 = *pfplast = NULL;
	if ((dirp = opendir(dir)) == NULL) {
		(void) printf("%s unreadable\n", dir);	/* not stderr! */
		return (0);
	}
	errno = 0;
	if (((dp = readdir(dirp)) == NULL) && (errno != 0)) {
		/* root reading across NFS can get to this error case */
		(void) printf("%s unreadable\n", dir);	/* not stderr! */
		(void) closedir(dirp);
		return (0);
	}
	fp = *pfp0 = (struct afile *)calloc(nent, sizeof (struct afile));
	*pfplast = *pfp0 + nent;
	for (nb = 0; dp != NULL; dp = readdir(dirp)) {
		if (dp->d_ino == 0)
			continue;
		if (aflg == 0 && dp->d_name[0] == '.' &&
		    (Aflg == 0 || dp->d_name[1] == 0 ||
		    dp->d_name[1] == '.' && dp->d_name[2] == 0))
			continue;
		if (gstat(fp, cat(dir, dp->d_name), Fflg+Rflg, &nb) == 0)
			continue;
		fp->fnum = dp->d_ino;
		fp->fname = savestr(dp->d_name);
		fp++;
		if (fp == *pfplast) {
			*pfp0 = (struct afile *)realloc((char *)*pfp0,
			    2 * nent * sizeof (struct afile));
			if (*pfp0 == 0) {
				(void) fprintf(stderr, "ls: out of memory\n");
				exit(1);
			}
			fp = *pfp0 + nent;
			*pfplast = fp + nent;
			nent *= 2;
		}
	}
	(void) closedir(dirp);
	*pfplast = fp;
	return (dbtokb(nb));
}


static struct afile *
gstat(struct afile *fp, char *file, int statarg, off_t *pnb)
{
	static struct afile azerofile;
	int (*statf)() = Lflg ? stat : lstat;
	int cc;
	char buf[PATH_MAX];
	int aclcnt;
	aclent_t *aclp;
	aclent_t *tp;
	o_mode_t groupperm, mask;
	int grouppermfound, maskfound;

	*fp = azerofile;
	fp->fflags = 0;
	fp->fnum = 0;
	fp->ftype = '-';
	if (statarg || sflg || lflg || tflg) {
		struct stat stb, stb1;

		if ((*statf)(file, &stb) < 0) {
			if (statf == lstat || lstat(file, &stb) < 0) {
				if (errno == ENOENT)
					(void) fprintf(stderr,
					    "%s not found\n", file);
				else {
					(void) fprintf(stderr, "ls: ");
					perror(file);
				}
				return (0);
			}
		}
		fp->fblks = stb.st_blocks;
		fp->fsize = stb.st_size;
		switch (stb.st_mode & S_IFMT) {
		case S_IFDIR:
			fp->ftype = 'd'; break;
		case S_IFDOOR:
			fp->ftype = 'D'; break;
		case S_IFBLK:
			fp->ftype = 'b'; fp->fsize = (off_t)stb.st_rdev; break;
		case S_IFCHR:
			fp->ftype = 'c'; fp->fsize = (off_t)stb.st_rdev; break;
		case S_IFSOCK:
			fp->ftype = 's'; fp->fsize = 0LL; break;
		case S_IFIFO:
			fp->ftype = 'p'; fp->fsize = 0LL; break;
		case S_IFLNK:
			fp->ftype = 'l';
			if (lflg) {
				cc = readlink(file, buf, BUFSIZ);
				if (cc >= 0) {
					/*
					 * here we follow the symbolic
					 * link to generate the proper
					 * Fflg marker for the object,
					 * eg, /bin -> /pub/bin/
					 */
					buf[cc] = 0;
					if (Fflg && !stat(file, &stb1))
						switch (stb1.st_mode & S_IFMT) {
						case S_IFDIR:
							buf[cc++] = '/';
							break;
						case S_IFDOOR:
							buf[cc++] = '>';
							break;
						case S_IFIFO:
							buf[cc++] = '|';
							break;
						case S_IFSOCK:
							buf[cc++] = '=';
							break;
						default:
							if ((stb1.st_mode &
							    ~S_IFMT) & 0111)
								buf[cc++] = '*';
							break;
						}
					buf[cc] = 0;
					fp->flinkto = savestr(buf);
				}
				break;
			}
			/*
			 *  this is a hack from UCB to avoid having
			 *  ls /bin behave differently from ls /bin/
			 *  when /bin is a symbolic link.  We hack the
			 *  hack to have that happen, but only for
			 *  explicit arguments, by inspecting pnb.
			 */
			if (pnb != (off_t *)0 || stat(file, &stb1) < 0)
				break;
			if ((stb1.st_mode & S_IFMT) == S_IFDIR) {
				stb = stb1;
				fp->ftype = 'd';
				fp->fsize = stb.st_size;
				fp->fblks = stb.st_blocks;
			}
			break;
		}
		fp->fnum = stb.st_ino;
		fp->fflags = stb.st_mode & ~S_IFMT;
		fp->fnl = stb.st_nlink;
		fp->fuid = stb.st_uid;
		fp->fgid = stb.st_gid;

		/* ACL: check acl entries count */
		if ((aclcnt = acl(file, GETACLCNT, 0, NULL)) >
		    MIN_ACL_ENTRIES) {

			/* this file has a non-trivial acl */

			fp->acl = '+';

			/*
			 * For files with non-trivial acls, the
			 * effective group permissions are the
			 * intersection of the GROUP_OBJ value and
			 * the CLASS_OBJ (acl mask) value. Determine
			 * both the GROUP_OBJ and CLASS_OBJ for this
			 * file and insert the logical AND of those
			 * two values in the group permissions field
			 * of the lflags value for this file.
			 */

			if ((aclp = (aclent_t *)malloc(
			    (sizeof (aclent_t)) * aclcnt)) == NULL) {
				perror("ls");
				exit(2);
			}

			if (acl(file, GETACL, aclcnt, aclp) < 0) {
				free(aclp);
				(void) fprintf(stderr, "ls: ");
				perror(file);
				return (0);
			}

			/*
			 * Until found in acl list, assume maximum
			 * permissions for both group and mask.  (Just
			 * in case the acl lacks either value for
			 * some reason.)
			 */
			groupperm = 07;
			mask = 07;
			grouppermfound = 0;
			maskfound = 0;
			for (tp = aclp; aclcnt--; tp++) {
				if (tp->a_type == GROUP_OBJ) {
					groupperm = tp->a_perm;
					grouppermfound = 1;
					continue;
				}
				if (tp->a_type == CLASS_OBJ) {
					mask = tp->a_perm;
					maskfound = 1;
				}
				if (grouppermfound && maskfound)
					break;
			}

			free(aclp);

			/* reset all the group bits */
			fp->fflags &= ~S_IRWXG;

			/*
			 * Now set them to the logical AND of the
			 * GROUP_OBJ permissions and the acl mask.
			 */

			fp->fflags |= (groupperm & mask) << 3;
		} else
			fp->acl = ' ';

		if (uflg)
			fp->fmtime = stb.st_atime;
		else if (cflg)
			fp->fmtime = stb.st_ctime;
		else
			fp->fmtime = stb.st_mtime;
		if (pnb)
			*pnb += stb.st_blocks;
	}
	return (fp);
}

static void
formatf(struct afile *fp0, struct afile *fplast)
{
	register struct afile *fp;
	int width = 0, w, nentry = fplast - fp0;
	int i, j, columns, lines;
	char *cp;

	if (fp0 == fplast)
		return;
	if (lflg || Cflg == 0)
		columns = 1;
	else {
		for (fp = fp0; fp < fplast; fp++) {
			int len = strlen(fmtentry(fp));

			if (len > width)
				width = len;
		}
		if (usetabs)
			width = (width + 8) &~ 7;
		else
			width += 2;
		columns = twidth / width;
		if (columns == 0)
			columns = 1;
	}
	lines = (nentry + columns - 1) / columns;
	for (i = 0; i < lines; i++) {
		for (j = 0; j < columns; j++) {
			fp = fp0 + j * lines + i;
			cp = fmtentry(fp);
			(void) printf("%s", cp);
			if (fp + lines >= fplast) {
				(void) printf("\n");
				break;
			}
			w = strlen(cp);
			while (w < width)
				if (usetabs) {
					w = (w + 8) &~ 7;
					(void) putchar('\t');
				} else {
					w++;
					(void) putchar(' ');
				}
		}
	}
}

static int
fcmp(const void *arg1, const void *arg2)
{
	const struct afile *f1 = arg1;
	const struct afile *f2 = arg2;

	if (dflg == 0 && fflg == 0) {
		if ((f1->fflags&ISARG) && f1->ftype == 'd') {
			if ((f2->fflags&ISARG) == 0 || f2->ftype != 'd')
				return (1);
		} else {
			if ((f2->fflags&ISARG) && f2->ftype == 'd')
				return (-1);
		}
	}
	if (tflg) {
		if (f2->fmtime == f1->fmtime)
			return (0);
		if (f2->fmtime > f1->fmtime)
			return (rflg);
		return (-rflg);
	}
	return (rflg * strcmp(f1->fname, f2->fname));
}

static char *
cat(char *dir, char *file)
{
	static char dfile[BUFSIZ];

	if (strlen(dir)+1+strlen(file)+1 > BUFSIZ) {
		(void) fprintf(stderr, "ls: filename too long\n");
		exit(1);
	}
	if (strcmp(dir, "") == 0 || strcmp(dir, ".") == 0) {
		(void) strcpy(dfile, file);
		return (dfile);
	}
	(void) strcpy(dfile, dir);
	if (dir[strlen(dir) - 1] != '/' && *file != '/')
		(void) strcat(dfile, "/");
	(void) strcat(dfile, file);
	return (dfile);
}

static char *
savestr(char *str)
{
	char *cp = malloc(strlen(str) + 1);

	if (cp == NULL) {
		(void) fprintf(stderr, "ls: out of memory\n");
		exit(1);
	}
	(void) strcpy(cp, str);
	return (cp);
}

static	char	*fmtinum(struct afile *);
static	char	*fmtsize(struct afile *);
static	char	*fmtlstuff(struct afile *);
static	char	*fmtmode(char *, int);

static char *
fmtentry(struct afile *fp)
{
	static char fmtres[BUFSIZ];
	register char *cp, *dp;

	(void) sprintf(fmtres, "%s%s%s",
	    iflg ? fmtinum(fp) : "",
	    sflg ? fmtsize(fp) : "",
	    lflg ? fmtlstuff(fp) : "");
	dp = &fmtres[strlen(fmtres)];
	for (cp = fp->fname; *cp; cp++)
		if (qflg && !isprint((unsigned char)*cp))
			*dp++ = '?';
		else
			*dp++ = *cp;
	/* avoid both "->" and trailing marks */
	if (Fflg && ! (lflg && fp->flinkto)) {
		if (fp->ftype == 'd')
			*dp++ = '/';
		else if (fp->ftype == 'D')
			*dp++ = '>';
		else if (fp->ftype == 'p')
			*dp++ = '|';
		else if (fp->ftype == 'l')
			*dp++ = '@';
		else if (fp->ftype == 's')
			*dp++ = '=';
		else if (fp->fflags & 0111)
			*dp++ = '*';
	}
	if (lflg && fp->flinkto) {
		(void) strcpy(dp, " -> "); dp += 4;
		for (cp = fp->flinkto; *cp; cp++)
			if (qflg && !isprint((unsigned char) *cp))
				*dp++ = '?';
			else
				*dp++ = *cp;
	}
	*dp++ = 0;
	return (fmtres);
}

static char *
fmtinum(struct afile *p)
{
	static char inumbuf[12];

	(void) sprintf(inumbuf, "%10llu ", p->fnum);
	return (inumbuf);
}

static char *
fmtsize(struct afile *p)
{
	static char sizebuf[32];

	(void) sprintf(sizebuf, (off_t)dbtokb(p->fblks) < 10000 ? "%4lld " : \
	    "%lld ", (off_t)dbtokb(p->fblks));
	return (sizebuf);
}

static char *
fmtlstuff(struct afile *p)
{
	static char lstuffbuf[256];
	char gname[32], uname[32], fsize[32], ftime[32];
	register char *lp = lstuffbuf;

	/* type mode uname gname fsize ftime */
/* get uname */
	{
		char *cp = getname(p->fuid);
		(void) sprintf(uname, "%-8s ", cp);
	}
/* get gname */
	if (gflg) {
		char *cp = getgroup(p->fgid);
		(void) sprintf(gname, "%-8s ", cp);
	}
/* get fsize */
	if (p->ftype == 'b' || p->ftype == 'c')
		(void) sprintf(fsize, "%3ld,%4ld",
		    major(p->fsize), minor(p->fsize));
	else if (p->ftype == 's')
		(void) sprintf(fsize, "%8d", 0);
	else
		(void) sprintf(fsize, p->fsize < 100000000 ? "%8lld" : \
		    "%lld", p->fsize);
/* get ftime */
	{
		char *cp = ctime(&p->fmtime);
		if ((p->fmtime < sixmonthsago) || (p->fmtime > onehourfromnow))
			(void) sprintf(ftime, " %-7.7s %-4.4s ", cp+4, cp+20);
		else
			(void) sprintf(ftime, " %-12.12s ", cp+4);
	}
/* splat */
	*lp++ = p->ftype;
	lp = fmtmode(lp, p->fflags);
	(void) sprintf(lp, "%c%3ld %s%s%s%s",
	    p->acl, p->fnl, uname, gflg ? gname : "", fsize, ftime);
	return (lstuffbuf);
}

static	int	m1[] =
	{ 1, S_IREAD>>0, 'r', '-' };
static	int	m2[] =
	{ 1, S_IWRITE>>0, 'w', '-' };
static	int	m3[] =
	{ 3, S_ISUID|(S_IEXEC>>0), 's', S_IEXEC>>0, 'x', S_ISUID, 'S', '-' };
static	int	m4[] =
	{ 1, S_IREAD>>3, 'r', '-' };
static	int	m5[] =
	{ 1, S_IWRITE>>3, 'w', '-' };
static	int	m6[] =
	{ 3, S_ISGID|(S_IEXEC>>3), 's', S_IEXEC>>3, 'x', S_ISGID, 'S', '-' };
static	int	m7[] =
	{ 1, S_IREAD>>6, 'r', '-' };
static	int	m8[] =
	{ 1, S_IWRITE>>6, 'w', '-' };
static	int	m9[] =
	{ 3, S_ISVTX|(S_IEXEC>>6), 't', S_ISVTX, 'T', S_IEXEC>>6, 'x', '-' };

static	int	*m[] = { m1, m2, m3, m4, m5, m6, m7, m8, m9};

static char *
fmtmode(char *lp, int flags)
{
	int **mp;

	for (mp = &m[0]; mp < &m[sizeof (m)/sizeof (m[0])]; ) {
		register int *pairp = *mp++;
		register int n = *pairp++;

		while (n-- > 0) {
			if ((flags&*pairp) == *pairp) {
				pairp++;
				break;
			} else
				pairp += 2;
		}
		*lp++ = *pairp;
	}
	return (lp);
}

/* rest should be done with nameserver or database */

#include <pwd.h>
#include <grp.h>
#include <utmpx.h>

#define	NMAX	(sizeof (((struct utmpx *)0)->ut_name))
#define	SCPYN(a, b)	strncpy(a, b, NMAX)


static struct cachenode {	/* this struct must be zeroed before using */
	struct cachenode *lesschild;	/* subtree whose entries < val */
	struct cachenode *grtrchild;	/* subtree whose entries > val */
	int val;			/* the uid or gid of this entry */
	int initted;			/* name has been filled in */
	char name[NMAX+1];		/* the string that val maps to */
} *names, *groups;

static struct cachenode *
findincache(struct cachenode **head, id_t val)
{
	register struct cachenode **parent = head;
	register struct cachenode *c = *parent;

	while (c != NULL) {
		if (val == c->val) {
			/* found it */
			return (c);
		} else if (val < c->val) {
			parent = &c->lesschild;
			c = c->lesschild;
		} else {
			parent = &c->grtrchild;
			c = c->grtrchild;
		}
	}

	/* not in the cache, make a new entry for it */
	*parent = c = (struct cachenode *)calloc(1, sizeof (struct cachenode));
	c->val = val;
	return (c);
}

static char *
getname(uid_t uid)
{
	struct cachenode *c;
	struct passwd *pw;

	c = findincache(&names, uid);
	if (c->initted == 0) {
		if ((pw = getpwuid(uid)) != NULL) {
			(void) SCPYN(&c->name[0], pw->pw_name);
		} else {
			(void) sprintf(&c->name[0], "%-8lu ", uid);
		}
		c->initted = 1;
	}
	return (&c->name[0]);
}

static char *
getgroup(gid_t gid)
{
	struct cachenode *c;
	struct group *gr;

	c = findincache(&groups, gid);
	if (c->initted == 0) {
		if ((gr = getgrgid(gid)) != NULL) {
			(void) SCPYN(&c->name[0], gr->gr_name);
		} else {
			(void) sprintf(&c->name[0], "%-8lu ", gid);
		}
		c->initted = 1;
	}
	return (&c->name[0]);
}
