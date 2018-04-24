/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * Copyright (c) 1983 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#include "restore.h"
#include <byteorder.h>
#include <stdlib.h>
#include <unistd.h>
#include <utime.h>

/*
 * Symbol table of directories read from tape.
 */
#define	HASHSIZE	1000
#define	INOHASH(val) (val % HASHSIZE)
struct inotab {
	struct inotab *t_next;
	ino_t	t_ino;
	offset_t t_seekpt;
	offset_t t_size;
	struct inotab *t_xattr;
};
static struct inotab *inotab[HASHSIZE];
static struct inotab *xattrlist = NULL;

/*
 * Information retained about directories.
 */
static struct modeinfo {
	ino_t	ino;
	time_t	timep[2];
	mode_t	mode;
	uid_t	uid;
	gid_t	gid;
	size_t	metasize;
} node;

/*
 * Global variables for this file.
 */
static off64_t	g_seekpt;		/* some people have a local seekpt */
static FILE	*df, *mf;
static char	dirfile[MAXPATHLEN] = "#";	/* No file */
static char	modefile[MAXPATHLEN] = "#";	/* No file */

static RST_DIR	*dirp;

#define	INIT_TEMPFILE(name, type) \
	if (name[0] == '#') { \
		if (tmpdir == (char *)NULL) /* can't happen; be paranoid */ \
			tmpdir = "/tmp"; \
		(void) snprintf(name, sizeof (name), \
		    "%s/rst" type "%ld.XXXXXX", tmpdir, dumpdate); \
		(void) mktemp(name); \
	}

#define	INIT_DIRFILE()	INIT_TEMPFILE(dirfile, "dir")
#define	INIT_MODEFILE()	INIT_TEMPFILE(modefile, "mode")

/*
 * Format of old style directories.
 */
#define	ODIRSIZ 14
struct odirect {
	ushort_t d_ino;
	char	d_name[ODIRSIZ];
};

#ifdef __STDC__
static ino_t search(ino_t, char	*);
static void putdir(char *, size_t);
static void putent(struct direct *);
static void skipmetadata(FILE *, size_t);
static void flushent(void);
static void dcvt(struct odirect *, struct direct *);
static RST_DIR *rst_initdirfile(char *);
static offset_t rst_telldir(RST_DIR *);
static void rst_seekdir(RST_DIR *, offset_t, offset_t);
static struct inotab *allocinotab(ino_t, struct dinode *, off64_t);
static void nodeflush(void);
static struct inotab *inotablookup(ino_t);
#else
static ino_t search();
static void putdir();
static void putent();
static void skipmetadata();
static void flushent();
static void dcvt();
static RST_DIR *rst_initdirfile();
static offset_t rst_telldir();
static void rst_seekdir();
static struct inotab *allocinotab();
static void nodeflush();
static struct inotab *inotablookup();
#endif

/*
 *	Extract directory contents, building up a directory structure
 *	on disk for extraction by name.
 *	If genmode is requested, save mode, owner, and times for all
 *	directories on the tape.
 */
void
extractdirs(int genmode)
{
	int ts;
	struct dinode *ip;
	int saverr;
	struct inotab *itp;
	struct direct nulldir;
	static char dotname[] = "."; /* dirlookup/psearch writes to its arg */

	vprintf(stdout, gettext("Extract directories from tape\n"));
	INIT_DIRFILE();
	if ((df = safe_fopen(dirfile, "w", 0600)) == (FILE *)NULL) {
		saverr = errno;
		(void) fprintf(stderr,
		    gettext("%s: %s - cannot create directory temporary\n"),
			progname, dirfile);
		errno = saverr;
		perror("fopen");
		done(1);
	}
	if (genmode != 0) {
		INIT_MODEFILE();
		if ((mf = safe_fopen(modefile, "w", 0600)) == (FILE *)NULL) {
			saverr = errno;
			(void) fprintf(stderr,
			    gettext("%s: %s - cannot create modefile \n"),
				progname, modefile);
			errno = saverr;
			perror("fopen");
			done(1);
		}
	}
	nulldir.d_ino = 0;
	nulldir.d_namlen = 1;
	(void) strcpy(nulldir.d_name, "/");
	/* LINTED DIRSIZ will always fit into a ushort_t */
	nulldir.d_reclen = (ushort_t)DIRSIZ(&nulldir);
	/* LINTED sign extension ok in assert */
	assert(DIRSIZ(&nulldir) == (ulong_t)nulldir.d_reclen);
	for (;;) {
		curfile.name = gettext("<directory file - name unknown>");
		curfile.action = USING;
		ip = curfile.dip;
		ts = curfile.ts;
		if (ts != TS_END && ts != TS_INODE) {
			getfile(null, null);
			continue;
		}
		if (ts == TS_INODE && ip == NULL) {
			(void) fprintf(stderr, gettext(
"%s: extractdirs: Failed internal consistency check, curfile.dip is NULL\n"),
			    progname);
			done(1);
		}
		if ((ts == TS_INODE && (ip->di_mode & IFMT) != IFDIR &&
		    (ip->di_mode & IFMT) != IFATTRDIR) ||
		    (ts == TS_END)) {
			(void) fflush(df);
			/* XXX Legitimate error, bad complaint string */
			if (ferror(df))
				panic("%s: %s\n", dirfile, strerror(errno));
			(void) fclose(df);
			rst_closedir(dirp);
			dirp = rst_initdirfile(dirfile);
			if (dirp == NULL)
				perror("initdirfile");
			if (mf != NULL) {
				(void) fflush(mf);
				/* XXX Legitimate error, bad complaint string */
				if (ferror(mf))
					panic("%s: %s\n",
					    modefile, strerror(errno));
				(void) fclose(mf);
			}
			if (dirlookup(dotname) == 0) {
				(void) fprintf(stderr, gettext(
				    "Root directory is not on tape\n"));
				done(1);
			}
			return;
		}
		itp = allocinotab(curfile.ino, ip, g_seekpt);
		getfile(putdir, null);
		if (mf != NULL)
			nodeflush();

		putent(&nulldir);
		flushent();
		itp->t_size = g_seekpt - itp->t_seekpt;
	}
}

/*
 * skip over all the directories on the tape
 */
void
skipdirs()
{
	while (curfile.dip != NULL &&
		((curfile.dip->di_mode & IFMT) == IFDIR ||
		(curfile.dip->di_mode & IFMT) == IFATTRDIR)) {
		skipfile();
	}
}

/*
 *	Recursively find names and inumbers of all files in subtree
 *	pname and pass them off to be processed.
 */
void
treescan(char *pname, ino_t ino, long (*todo)())
{
	struct inotab *itp;
	struct direct *dp;
	uint_t loclen;
	offset_t bpt;
	char locname[MAXCOMPLEXLEN];

	itp = inotablookup(ino);
	if (itp == NULL) {
		/*
		 * Pname is name of a simple file or an unchanged directory.
		 */
		(void) (*todo)(pname, ino, LEAF);
		return;
	}
	/*
	 * Pname is a dumped directory name.
	 */
	if ((*todo)(pname, ino, NODE) == FAIL)
		return;
	/*
	 * begin search through the directory
	 * skipping over "." and ".."
	 */
	loclen = complexcpy(locname, pname, MAXCOMPLEXLEN);
	locname[loclen-1] = '/';
	rst_seekdir(dirp, itp->t_seekpt, itp->t_seekpt);
	dp = rst_readdir(dirp); /* "." */

	if (dp != NULL && strcmp(dp->d_name, ".") == 0)
		dp = rst_readdir(dirp); /* ".." */
	else
		(void) fprintf(stderr,
		    gettext("Warning: `.' missing from directory %s\n"),
			pname);
	if (dp != NULL && strcmp(dp->d_name, "..") == 0)
		dp = rst_readdir(dirp); /* first real entry */
	else
		(void) fprintf(stderr,
		    gettext("Warning: `..' missing from directory %s\n"),
			pname);
	bpt = rst_telldir(dirp);
	/*
	 * a zero inode signals end of directory
	 */
	while (dp != NULL && dp->d_ino != 0) {
		locname[loclen] = '\0';
		if ((loclen + dp->d_namlen) >= (sizeof (locname) - 2)) {
			(void) fprintf(stderr,
			    gettext(
				"%s%s: ignoring name that exceeds %d char\n"),
			    locname, dp->d_name, MAXCOMPLEXLEN);
		} else {
			/* Always fits by if() condition */
			(void) strcpy(locname + loclen, dp->d_name);
			/* put a double null on string for lookupname() */
			locname[loclen+dp->d_namlen+1] = '\0';
			treescan(locname, dp->d_ino, todo);
			rst_seekdir(dirp, bpt, itp->t_seekpt);
		}
		dp = rst_readdir(dirp);
		bpt = rst_telldir(dirp);
	}
	if (dp == NULL)
		(void) fprintf(stderr,
			gettext("corrupted directory: %s.\n"), locname);
}

/*
 * Scan the directory table looking for extended attribute trees.
 * Recursively find names and inumbers in each tree and pass them
 * off to be processed.  If the always parameter is not set, only
 * process the attribute tree if the attribute tree parent is to
 * be extracted.
 */
void
attrscan(int always, long (*todo)())
{
	struct inotab *itp;
	struct entry *ep, *parent;
	struct direct *dp;
	char name[MAXCOMPLEXLEN];
	int len;

	for (itp = xattrlist; itp != NULL; itp = itp->t_xattr) {
		rst_seekdir(dirp, itp->t_seekpt, itp->t_seekpt);
		if ((dp = rst_readdir(dirp)) != NULL &&	/* "." */
		    (dp = rst_readdir(dirp)) != NULL &&	/* ".." */
		    strcmp(dp->d_name, "..") == 0) {
			if ((parent = lookupino(dp->d_ino)) != NULL) {
				if (!always &&
				    (parent->e_flags & (NEW|EXTRACT)) == 0)
					continue;
				len = complexcpy(name, myname(parent),
							MAXCOMPLEXLEN - 3);
				name[len] = '.';
				name[len+1] = '\0';
				name[len+2] = '\0';
				inattrspace = 1;
				if ((ep = lookupino(itp->t_ino)) == NULL) {
					ep = addentry(name, itp->t_ino,
								NODE|ROOT);
				}
				ep->e_flags |= XATTRROOT;
				treescan(name, itp->t_ino, todo);
				inattrspace = 0;
			} else {
				(void) fprintf(stderr,
			gettext("Warning: orphaned attribute directory\n"));
			}
		} else {
			(void) fprintf(stderr,
	    gettext("Warning: `..' missing from attribute directory\n"));
		}
	}
}

/*
 * Search the directory tree rooted at inode ROOTINO
 * for the path pointed at by n.  Note that n must be
 * modifiable, although it is returned in the same
 * condition it was given to us in.
 */
ino_t
psearch(char *n)
{
	char *cp, *cp1;
	ino_t ino;
	char c;

	ino = ROOTINO;
	if (*(cp = n) == '/')
		cp++;
next:
	cp1 = cp + 1;
	while (*cp1 != '/' && *cp1)
		cp1++;
	c = *cp1;
	*cp1 = 0;
	ino = search(ino, cp);
	if (ino == 0) {
		*cp1 = c;
		return (0);
	}
	*cp1 = c;
	if (c == '/') {
		cp = cp1+1;
		goto next;
	}
	return (ino);
}

/*
 * search the directory inode ino
 * looking for entry cp
 */
static ino_t
search(ino_t inum, char *cp)
{
	struct direct *dp;
	struct inotab *itp;
	uint_t len;

	itp = inotablookup(inum);
	if (itp == NULL)
		return (0);
	rst_seekdir(dirp, itp->t_seekpt, itp->t_seekpt);
	len = strlen(cp);
	do {
		dp = rst_readdir(dirp);
		if (dp == NULL || dp->d_ino == 0)
			return (0);
	} while (dp->d_namlen != len || strncmp(dp->d_name, cp, len) != 0);
	return (dp->d_ino);
}

/*
 * Put the directory entries in the directory file
 */
static void
putdir(char *buf, size_t size)
{
	struct direct cvtbuf;
	struct odirect *odp;
	struct odirect *eodp;
	struct direct *dp;
	size_t loc, i;

	if (cvtflag) {
		/*LINTED [buf is char[] in getfile, size % fs_fsize == 0]*/
		eodp = (struct odirect *)&buf[size];
		/*LINTED [buf is char[] in getfile]*/
		for (odp = (struct odirect *)buf; odp < eodp; odp++)
			if (odp->d_ino != 0) {
				dcvt(odp, &cvtbuf);
				putent(&cvtbuf);
			}
	} else {
		loc = 0;
		while (loc < size) {
			/*LINTED [buf is char[] in getfile, loc % 4 == 0]*/
			dp = (struct direct *)(buf + loc);
			normdirect(byteorder, dp);
			i = DIRBLKSIZ - (loc & (DIRBLKSIZ - 1));
			if (dp->d_reclen == 0 || (long)dp->d_reclen > i) {
				loc += i;
				continue;
			}
			loc += dp->d_reclen;
			if (dp->d_ino != 0) {
				putent(dp);
			}
		}
	}
}

/*
 * These variables are "local" to the following two functions.
 */
static char dirbuf[DIRBLKSIZ];
static int32_t dirloc = 0;
static int32_t prev = 0;

/*
 * add a new directory entry to a file.
 */
static void
putent(struct direct *dp)
{
	/* LINTED DIRSIZ will always fit in a ushort_t */
	dp->d_reclen = (ushort_t)DIRSIZ(dp);
	/* LINTED sign extension ok in assert */
	assert(DIRSIZ(dp) == (ulong_t)dp->d_reclen);
	if (dirloc + (long)dp->d_reclen > DIRBLKSIZ) {
		/*LINTED [prev += dp->d_reclen, prev % 4 == 0]*/
		((struct direct *)(dirbuf + prev))->d_reclen =
		    DIRBLKSIZ - prev;
		(void) fwrite(dirbuf, 1, DIRBLKSIZ, df);
		if (ferror(df))
			panic("%s: %s\n", dirfile, strerror(errno));
		dirloc = 0;
	}
	bcopy((char *)dp, dirbuf + dirloc, (size_t)dp->d_reclen);
	prev = dirloc;
	dirloc += dp->d_reclen;
}

/*
 * flush out a directory that is finished.
 */
static void
#ifdef __STDC__
flushent(void)
#else
flushent()
#endif
{

	/* LINTED prev += dp->d_reclen, prev % 4 == 0 */
	((struct direct *)(dirbuf + prev))->d_reclen = DIRBLKSIZ - prev;
	(void) fwrite(dirbuf, (size_t)dirloc, 1, df);
	if (ferror(df))
		panic("%s: %s\n", dirfile, strerror(errno));
	g_seekpt = ftello64(df);
	dirloc = 0;
}

static void
dcvt(struct odirect *odp, struct direct *ndp)
{

	(void) bzero((char *)ndp, sizeof (*ndp));
	ndp->d_ino =  odp->d_ino;
	/* Note that odp->d_name may not be null-terminated */
	/* LINTED assertion always true */
	assert(sizeof (ndp->d_name) > sizeof (odp->d_name));
	(void) strncpy(ndp->d_name, odp->d_name, sizeof (odp->d_name));
	ndp->d_name[sizeof (odp->d_name)] = '\0';
	/* LINTED: strlen will fit into d_namlen */
	ndp->d_namlen = strlen(ndp->d_name);

	/* LINTED sign extension ok in assert */
	assert(DIRSIZ(ndp) == (ulong_t)ndp->d_reclen);
	/* LINTED DIRSIZ always fits in ushort_t */
	ndp->d_reclen = (ushort_t)DIRSIZ(ndp);
}

/*
 * Initialize the directory file
 */
static RST_DIR *
rst_initdirfile(char *name)
{
	RST_DIR *dp;
	int fd;

	if ((fd = open(name, O_RDONLY | O_LARGEFILE)) == -1)
		return ((RST_DIR *)0);
	if ((dp = (RST_DIR *)malloc(sizeof (*dp))) == NULL) {
		(void) close(fd);
		return ((RST_DIR *)0);
	}
	dp->dd_fd = fd;
	dp->dd_loc = 0;
	dp->dd_refcnt = 1;
	return (dp);
}

/*
 * Simulate the opening of a directory
 */
RST_DIR *
rst_opendir(char *name)
{
	struct inotab *itp;
	ino_t ino;

	if ((ino = dirlookup(name)) > 0 &&
	    (itp = inotablookup(ino)) != NULL) {
		rst_seekdir(dirp, itp->t_seekpt, itp->t_seekpt);
		dirp->dd_refcnt++;
		return (dirp);
	}
	return ((RST_DIR *)0);
}

/*
 * Releases the hidden state created by rst_opendir().
 * Specifically, the dirp it provided to the caller is malloc'd.
 */
void
rst_closedir(RST_DIR *cdirp)
{
	if ((cdirp != NULL) && (--(cdirp->dd_refcnt) < 1))
		free(cdirp);
}

/*
 * return a pointer into a directory
 */
static offset_t
rst_telldir(RST_DIR *tdirp)
{
	offset_t pos = llseek(tdirp->dd_fd, (offset_t)0, SEEK_CUR);

	if (pos == (offset_t)-1) {
		perror("Could not determine position in directory file");
		done(1);
	}

	return ((pos - tdirp->dd_size) + tdirp->dd_loc);
}

/*
 * Seek to an entry in a directory.
 * Only values returned by ``rst_telldir'' should be passed to rst_seekdir.
 * This routine handles many directories in a single file.
 * It takes the base of the directory in the file, plus
 * the desired seek offset into it.
 */
static void
rst_seekdir(RST_DIR *sdirp, offset_t loc, offset_t base)
{

	if (loc == rst_telldir(sdirp))
		return;
	loc -= base;
	if (loc < 0)
		(void) fprintf(stderr,
			gettext("bad seek pointer to rst_seekdir %d\n"), loc);
	(void) llseek(sdirp->dd_fd, base + (loc & ~(DIRBLKSIZ - 1)), 0);
	sdirp->dd_loc = loc & (DIRBLKSIZ - 1);
	if (sdirp->dd_loc != 0)
		sdirp->dd_size = read(sdirp->dd_fd, sdirp->dd_buf, DIRBLKSIZ);
}

/*
 * get next entry in a directory.
 */
struct direct *
rst_readdir(RST_DIR *rdirp)
{
	struct direct *dp;

	for (;;) {
		if (rdirp->dd_loc == 0) {
			rdirp->dd_size = read(rdirp->dd_fd, rdirp->dd_buf,
			    DIRBLKSIZ);
			if (rdirp->dd_size <= 0) {
				dprintf(stderr,
					gettext("error reading directory\n"));
				return ((struct direct *)0);
			}
		}
		if (rdirp->dd_loc >= rdirp->dd_size) {
			rdirp->dd_loc = 0;
			continue;
		}
		/*LINTED [rvalue will be aligned on int boundary]*/
		dp = (struct direct *)(rdirp->dd_buf + rdirp->dd_loc);
		if (dp->d_reclen == 0 ||
		    (long)dp->d_reclen > (DIRBLKSIZ + 1 - rdirp->dd_loc)) {
			dprintf(stderr,
			    gettext("corrupted directory: bad reclen %d\n"),
				dp->d_reclen);
			return ((struct direct *)0);
		}
		rdirp->dd_loc += dp->d_reclen;
		if (dp->d_ino == 0 && strcmp(dp->d_name, "/") != 0)
			continue;
		if ((ino_t)(dp->d_ino) >= maxino) {
			dprintf(stderr,
				gettext("corrupted directory: bad inum %lu\n"),
				dp->d_ino);
			continue;
		}
		return (dp);
	}
}

/*
 * Set the mode, owner, and times for all new or changed directories
 */
void
#ifdef __STDC__
setdirmodes(void)
#else
setdirmodes()
#endif
{
	FILE *smf;
	struct entry *ep;
	char *cp, *metadata = NULL;
	size_t metasize = 0;
	int override = -1;
	int saverr;
	static int complained_chown = 0;
	static int complained_chmod = 0;
	int dfd;

	vprintf(stdout, gettext("Set directory mode, owner, and times.\n"));
	/* XXX if modefile[0] == '#', shouldn't we just bail here? */
	/* XXX why isn't it set already? */
	INIT_MODEFILE();
	smf = fopen64(modefile, "r");
	if (smf == NULL) {
		perror("fopen");
		(void) fprintf(stderr,
			gettext("cannot open mode file %s\n"), modefile);
		(void) fprintf(stderr,
			gettext("directory mode, owner, and times not set\n"));
		return;
	}
	clearerr(smf);
	for (;;) {
		(void) fread((char *)&node, 1, sizeof (node), smf);
		if (feof(smf))
			break;
		ep = lookupino(node.ino);
		if (command == 'i' || command == 'x') {
			if (ep == NIL) {
				skipmetadata(smf, node.metasize);
				continue;
			}
			if (ep->e_flags & EXISTED) {
				if (override < 0) {
					if (reply(gettext(
				"Directories already exist, set modes anyway"))
					    == FAIL)
						override = 0;
					else
						override = 1;
				}
				if (override == 0) {
					/* LINTED: result fits into short */
					ep->e_flags &= ~NEW;
					skipmetadata(smf, node.metasize);
					continue;
				}
			}
			if (node.ino == ROOTINO &&
			    reply(gettext("set owner/mode for '.'")) == FAIL) {
				skipmetadata(smf, node.metasize);
				continue;
			}
		}
		if (ep == NIL) {
			panic(gettext("cannot find directory inode %d\n"),
				node.ino);
			skipmetadata(smf, node.metasize);
			continue;
		}
		cp = myname(ep);
		resolve(myname(ep), &dfd, &cp);
		if (dfd != AT_FDCWD) {
			if (fchdir(dfd) < 0) {
				saverr = errno;
				(void) fprintf(stderr,
			    gettext("Can not set attribute context: %s\n"),
					strerror(saverr));
				(void) close(dfd);
				continue;
			}
		}
		if (chmod(cp, node.mode) < 0 && !complained_chmod) {
			saverr = errno;
			(void) fprintf(stderr,
			gettext("Can not set directory permissions: %s\n"),
				strerror(saverr));
			complained_chmod = 1;
		}
		if (node.metasize != 0) {
			if (node.metasize > metasize)
				metadata = realloc(metadata,
				    metasize = node.metasize);
			if (metadata == NULL) {
				(void) fprintf(stderr,
					gettext("Cannot malloc metadata\n"));
				done(1);
			}
			(void) fread(metadata, 1, node.metasize, smf);
			metaproc(cp, metadata, node.metasize);
		}

		/*
		 * BUG 4302943
		 * Since the ACLs must be set before fixing the ownership,
		 * chown should be called only after metaproc
		 */
		if (chown(cp, node.uid, node.gid) < 0 && !complained_chown) {
			saverr = errno;
			(void) fprintf(stderr,
			    gettext("Can not set directory ownership: %s\n"),
			    strerror(saverr));
			complained_chown = 1;
		}
		utime(cp, (struct utimbuf *)node.timep);
		/* LINTED: result fits into short */
		ep->e_flags &= ~NEW;
		if (dfd != AT_FDCWD) {
			fchdir(savepwd);
			(void) close(dfd);
		}
	}
	if (ferror(smf))
		panic(gettext("error setting directory modes\n"));
	if (metadata != NULL)
		(void) free(metadata);
	(void) fclose(smf);
}

void
skipmetadata(FILE *f, size_t size)
{
	/* XXX should we bail if this doesn't work? */
	/* LINTED unsigned -> signed conversion ok here */
	(void) fseeko(f, (off_t)size, SEEK_CUR);
}

/*
 * Generate a literal copy of a directory.
 */
int
genliteraldir(char *name, ino_t ino)
{
	struct inotab *itp;
	int ofile, dp;
	off64_t i;
	size_t size;
	char buf[BUFSIZ];

	itp = inotablookup(ino);
	if (itp == NULL) {
		(void) fprintf(stderr,
		    gettext("Cannot find directory inode %d named %s\n"),
		    ino, name);
		return (FAIL);
	}
	if ((ofile = creat(name, 0666)) < 0) {
		(void) fprintf(stderr, "%s: ", name);
		(void) fflush(stderr);
		perror(gettext("cannot create file"));
		return (FAIL);
	}
	rst_seekdir(dirp, itp->t_seekpt, itp->t_seekpt);
	dp = dup(dirp->dd_fd);
	if (dp < 0) {
		perror(gettext("dup(2) failed"));
		(void) close(ofile);
		(void) unlink(name);
		return (FAIL);
	}
	for (i = itp->t_size; i != 0; i -= size) {
		/* LINTED cast is safe due to comparison */
		size = i < BUFSIZ ? (size_t)i : BUFSIZ;
		/* XXX instead of done(), clean up and return FAIL? */
		if (read(dp, buf, size) == -1) {
			(void) fprintf(stderr, gettext(
				"read error extracting inode %d, name %s\n"),
				curfile.ino, curfile.name);
			perror("read");
			done(1);
		}
		if (write(ofile, buf, size) == -1) {
			(void) fprintf(stderr, gettext(
				"write error extracting inode %d, name %s\n"),
				curfile.ino, curfile.name);
			perror("write");
			done(1);
		}
	}
	(void) close(dp);
	(void) close(ofile);
	return (GOOD);
}

/*
 * Determine the type of an inode
 */
int
inodetype(ino_t ino)
{
	struct inotab *itp;

	itp = inotablookup(ino);
	if (itp == NULL)
		return (LEAF);
	return (NODE);
}

/*
 * Allocate and initialize a directory inode entry.
 * If requested, save its pertinent mode, owner, and time info.
 */
static struct inotab *
allocinotab(ino_t ino, struct dinode *dip, off64_t seekpt)
{
	struct inotab	*itp;

	itp = (struct inotab *)calloc(1, sizeof (*itp));
	if (itp == 0) {
		(void) fprintf(stderr,
		    gettext("no memory for directory table\n"));
		done(1);
	}
	itp->t_next = inotab[INOHASH(ino)];
	inotab[INOHASH(ino)] = itp;
	itp->t_ino = ino;
	itp->t_seekpt = seekpt;
	if ((dip->di_mode & IFMT) == IFATTRDIR) {
		itp->t_xattr = xattrlist;
		xattrlist = itp;
	}
	if (mf == NULL)
		return (itp);
	node.ino = ino;
	node.timep[0] = dip->di_atime;
	node.timep[1] = dip->di_mtime;
	node.mode = dip->di_mode;
	node.uid =
		dip->di_suid == UID_LONG ? dip->di_uid : (uid_t)dip->di_suid;
	node.gid =
		dip->di_sgid == GID_LONG ? dip->di_gid : (gid_t)dip->di_sgid;
	return (itp);
}

void
nodeflush()
{
	char *metadata;

	if (mf == NULL) {
		(void) fprintf(stderr, gettext(
		    "Inconsistency detected: modefile pointer is NULL\n"));
		done(1);
	}
	metaget(&metadata, &(node.metasize));
	(void) fwrite((char *)&node, 1, sizeof (node), mf);
	if (node.metasize != 0)
		(void) fwrite(metadata, 1, node.metasize, mf);
	if (ferror(mf))
		panic("%s: %s\n", modefile, strerror(errno));
}

/*
 * Look up an inode in the table of directories
 */
static struct inotab *
inotablookup(ino_t ino)
{
	struct inotab *itp;

	for (itp = inotab[INOHASH(ino)]; itp != NULL; itp = itp->t_next)
		if (itp->t_ino == ino)
			return (itp);
	return ((struct inotab *)0);
}

/*
 * Clean up and exit
 */
void
done(int exitcode)
{
	closemt(ALLOW_OFFLINE);		/* don't force offline on exit */
	if (modefile[0] != '#')
		(void) unlink(modefile);
	if (dirfile[0] != '#')
		(void) unlink(dirfile);
	exit(exitcode);
}
