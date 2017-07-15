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
#include <ctype.h>
#include <errno.h>
#include <syslog.h>
#include <limits.h>
/* LINTED: this file really is necessary */
#include <euc.h>
#include <widec.h>

/*
 * Insure that all the components of a pathname exist. Note that
 * lookupname() and addentry() both expect complex names as
 * input arguments, so a double NULL needs to be added to each name.
 */
void
pathcheck(char *name)
{
	char *cp, save;
	struct entry *ep;
	char *start;

	start = strchr(name, '/');
	if (start == 0)
		return;
	for (cp = start; *cp != '\0'; cp++) {
		if (*cp != '/')
			continue;
		*cp = '\0';
		save = *(cp+1);
		*(cp+1) = '\0';
		ep = lookupname(name);
		if (ep == NIL) {
			ep = addentry(name, psearch(name), NODE);
			newnode(ep);
		}
		/* LINTED: result fits in a short */
		ep->e_flags |= NEW|KEEP;
		*cp = '/';
		*(cp+1) = save;
	}
}

/*
 * Change a name to a unique temporary name.
 */
void
mktempname(struct entry *ep)
{
	char *newname;

	if (ep->e_flags & TMPNAME)
		badentry(ep, gettext("mktempname: called with TMPNAME"));
	/* LINTED: result fits in a short */
	ep->e_flags |= TMPNAME;
	newname = savename(gentempname(ep));
	renameit(myname(ep), newname);
	freename(ep->e_name);
	ep->e_name = newname;
	/* LINTED: savename guarantees strlen will fit */
	ep->e_namlen = strlen(ep->e_name);
}

/*
 * Generate a temporary name for an entry.
 */
char *
gentempname(struct entry *ep)
{
	static char name[MAXPATHLEN];
	struct entry *np;
	long i = 0;

	for (np = lookupino(ep->e_ino); np != NIL && np != ep; np = np->e_links)
		i++;
	if (np == NIL)
		badentry(ep, gettext("not on ino list"));
	(void) snprintf(name, sizeof (name), "%s%ld%lu", TMPHDR, i, ep->e_ino);
	return (name);
}

/*
 * Rename a file or directory.
 */
void
renameit(char *fp, char *tp)
{
	int fromfd, tofd;
	char *from, *to;
	char tobuf[MAXPATHLEN];
	char *pathend;

	resolve(fp, &fromfd, &from);
	/*
	 * The to pointer argument is assumed to be either a fully
	 * specified path (starting with "./") or a simple temporary
	 * file name (starting with TMPHDR).  If passed a simple temp
	 * file name, we need to set up the descriptors explicitly.
	 */
	if (strncmp(tp, TMPHDR, sizeof (TMPHDR) - 1) == 0) {
		tofd = fromfd;
		if ((pathend = strrchr(from, '/')) != NULL) {
			strncpy(tobuf, from, pathend - from + 1);
			tobuf[pathend - from + 1] = NULL;
			strlcat(tobuf, tp, sizeof (tobuf));
			to = tobuf;
		} else {
			to = tp;
		}
	} else
		resolve(tp, &tofd, &to);
	if (renameat(fromfd, from, tofd, to) < 0) {
		int saverr = errno;
		(void) fprintf(stderr,
		    gettext("Warning: cannot rename %s to %s: %s\n"),
		    from, to, strerror(saverr));
		(void) fflush(stderr);
	} else {
		vprintf(stdout, gettext("rename %s to %s\n"), from, to);
	}
	if (fromfd != AT_FDCWD) (void) close(fromfd);
	if (tofd != AT_FDCWD) (void) close(tofd);
}

/*
 * Create a new node (directory). Note that, because we have no
 * mkdirat() function, fchdir() must be used set up the appropriate
 * name space context prior to the call to mkdir() if we are
 * operating in attribute space.
 */
void
newnode(struct entry *np)
{
	char *cp;
	int dfd;

	if (np->e_type != NODE)
		badentry(np, gettext("newnode: not a node"));
	resolve(myname(np), &dfd, &cp);
	if (dfd != AT_FDCWD) {
		if (fchdir(dfd) < 0) {
			int saverr = errno;
			(void) fprintf(stderr,
				gettext("Warning: cannot create %s: %s"),
				cp, strerror(saverr));
			(void) fflush(stderr);
			(void) close(dfd);
			return;
		}
	}
	if (mkdir(cp, 0777) < 0) {
		int saverr = errno;
		/* LINTED: result fits in a short */
		np->e_flags |= EXISTED;
		(void) fprintf(stderr, gettext("Warning: "));
		(void) fflush(stderr);
		(void) fprintf(stderr, "%s: %s\n", cp, strerror(saverr));
	} else {
		vprintf(stdout, gettext("Make node %s\n"), cp);
	}
	if (dfd != AT_FDCWD) {
		fchdir(savepwd);
		(void) close(dfd);
	}
}

/*
 * Remove an old node (directory). See comment above on newnode()
 * for explanation of fchdir() use below.
 */
void
removenode(struct entry *ep)
{
	char *cp;
	int dfd;

	if (ep->e_type != NODE)
		badentry(ep, gettext("removenode: not a node"));
	if (ep->e_entries != NIL)
		badentry(ep, gettext("removenode: non-empty directory"));
	/* LINTED: result fits in a short */
	ep->e_flags |= REMOVED;
	/* LINTED: result fits in a short */
	ep->e_flags &= ~TMPNAME;
	resolve(myname(ep), &dfd, &cp);
	if (dfd != AT_FDCWD) {
		if (fchdir(dfd) < 0) {
			int saverr = errno;
			(void) fprintf(stderr,
				gettext("Warning: cannot remove %s: %s"),
				cp, strerror(saverr));
			(void) fflush(stderr);
			(void) close(dfd);
			return;
		}
	}
	if (rmdir(cp) < 0) {	/* NOTE: could use unlinkat (..,REMOVEDIR) */
		int saverr = errno;
		(void) fprintf(stderr, gettext("Warning: %s: %s\n"),
			cp, strerror(saverr));
		(void) fflush(stderr);
	} else {
		vprintf(stdout, gettext("Remove node %s\n"), cp);
	}
	if (dfd != AT_FDCWD) {
		(void) fchdir(savepwd);
		(void) close(dfd);
	}
}

/*
 * Remove a leaf.
 */
void
removeleaf(struct entry *ep)
{
	char *cp;
	int dfd;

	if (ep->e_type != LEAF)
		badentry(ep, gettext("removeleaf: not a leaf"));
	/* LINTED: result fits in a short */
	ep->e_flags |= REMOVED;
	/* LINTED: result fits in a short */
	ep->e_flags &= ~TMPNAME;
	resolve(myname(ep), &dfd, &cp);
	if (unlinkat(dfd, cp, 0) < 0) {
		int saverr = errno;
		(void) fprintf(stderr, gettext("Warning: %s: %s\n"),
			cp, strerror(saverr));
		(void) fflush(stderr);
	} else {
		vprintf(stdout, gettext("Remove leaf %s\n"), cp);
	}
	if (dfd != AT_FDCWD)
		(void) close(dfd);
}

/*
 * Create a link.
 *	This function assumes that the context has already been set
 *	for the link file to be created (i.e., we have "fchdir-ed"
 *	into attribute space already if this is an attribute link).
 */
int
lf_linkit(char *existing, char *new, int type)
{
	char linkbuf[MAXPATHLEN];
	struct stat64 s1[1], s2[1];
	char *name;
	int dfd, l, result;

	resolve(existing, &dfd, &name);
	if (dfd == -1) {
		(void) fprintf(stderr, gettext(
			"Warning: cannot restore %s link %s->%s\n"),
			(type == SYMLINK ? "symbolic" : "hard"), new, existing);
		result = FAIL;
		goto out;
	}
	if (type == SYMLINK) {
		if (symlink(name, new) < 0) {
			/* No trailing \0 from readlink(2) */
			if (((l = readlink(new, linkbuf, sizeof (linkbuf)))
			    > 0) &&
			    (l == strlen(name)) &&
			    (strncmp(linkbuf, name, l) == 0)) {
				vprintf(stdout,
				    gettext("Symbolic link %s->%s ok\n"),
				    new, name);
				result = GOOD;
				goto out;
			} else {
				int saverr = errno;
				(void) fprintf(stderr, gettext(
			    "Warning: cannot create symbolic link %s->%s: %s"),
				    new, name, strerror(saverr));
				(void) fflush(stderr);
				result = FAIL;
				goto out;
			}
		}
	} else if (type == HARDLINK) {
		if (link(name, new) < 0) {
			int saverr = errno;
			if ((stat64(name, s1) == 0) &&
			    (stat64(new, s2) == 0) &&
			    (s1->st_dev == s2->st_dev) &&
			    (s1->st_ino == s2->st_ino)) {
				vprintf(stdout,
				    gettext("Hard link %s->%s ok\n"),
				    new, name);
				result = GOOD;
				goto out;
			} else {
				(void) fprintf(stderr, gettext(
			    "Warning: cannot create hard link %s->%s: %s\n"),
				    new, name, strerror(saverr));
				(void) fflush(stderr);
				result = FAIL;
				goto out;
			}
		}
	} else {
		panic(gettext("%s: unknown type %d\n"), "linkit", type);
		result = FAIL;
		goto out;
	}
	result = GOOD;
	if (type == SYMLINK)
		vprintf(stdout, gettext("Create symbolic link %s->%s\n"),
		    new, name);
	else
		vprintf(stdout, gettext("Create hard link %s->%s\n"),
		    new, name);
out:
	if (dfd != AT_FDCWD) {
		(void) close(dfd);
	}
	return (result);
}

/*
 * Find lowest-numbered inode (above "start") that needs to be extracted.
 * Caller knows that a return value of maxino means there's nothing left.
 */
ino_t
lowerbnd(ino_t start)
{
	struct entry *ep;

	for (; start < maxino; start++) {
		ep = lookupino(start);
		if (ep == NIL || ep->e_type == NODE)
			continue;
		if (ep->e_flags & (NEW|EXTRACT))
			return (start);
	}
	return (start);
}

/*
 * Find highest-numbered inode (below "start") that needs to be extracted.
 */
ino_t
upperbnd(ino_t start)
{
	struct entry *ep;

	for (; start > ROOTINO; start--) {
		ep = lookupino(start);
		if (ep == NIL || ep->e_type == NODE)
			continue;
		if (ep->e_flags & (NEW|EXTRACT))
			return (start);
	}
	return (start);
}

/*
 * report on a badly formed entry
 */
void
badentry(struct entry *ep, char *msg)
{

	(void) fprintf(stderr, gettext("bad entry: %s\n"), msg);
	(void) fprintf(stderr, gettext("name: %s\n"), myname(ep));
	(void) fprintf(stderr, gettext("parent name %s\n"),
		myname(ep->e_parent));
	if (ep->e_sibling != NIL)
		(void) fprintf(stderr, gettext("sibling name: %s\n"),
		    myname(ep->e_sibling));
	if (ep->e_entries != NIL)
		(void) fprintf(stderr, gettext("next entry name: %s\n"),
		    myname(ep->e_entries));
	if (ep->e_links != NIL)
		(void) fprintf(stderr, gettext("next link name: %s\n"),
		    myname(ep->e_links));
	if (ep->e_xattrs != NIL)
		(void) fprintf(stderr, gettext("attribute root name: %s\n"),
		    myname(ep->e_xattrs));
	if (ep->e_next != NIL)
		(void) fprintf(stderr, gettext("next hashchain name: %s\n"),
		    myname(ep->e_next));
	(void) fprintf(stderr, gettext("entry type: %s\n"),
	    ep->e_type == NODE ? gettext("NODE") : gettext("LEAF"));
	(void) fprintf(stderr, gettext("inode number: %lu\n"), ep->e_ino);
	panic(gettext("flags: %s\n"), flagvalues(ep));
	/* Our callers are expected to handle our returning. */
}

/*
 * Construct a string indicating the active flag bits of an entry.
 */
char *
flagvalues(struct entry *ep)
{
	static char flagbuf[BUFSIZ];

	(void) strlcpy(flagbuf, gettext("|NIL"), sizeof (flagbuf));
	flagbuf[0] = '\0';
	if (ep->e_flags & REMOVED)
		(void) strlcat(flagbuf, gettext("|REMOVED"), sizeof (flagbuf));
	if (ep->e_flags & TMPNAME)
		(void) strlcat(flagbuf, gettext("|TMPNAME"), sizeof (flagbuf));
	if (ep->e_flags & EXTRACT)
		(void) strlcat(flagbuf, gettext("|EXTRACT"), sizeof (flagbuf));
	if (ep->e_flags & NEW)
		(void) strlcat(flagbuf, gettext("|NEW"), sizeof (flagbuf));
	if (ep->e_flags & KEEP)
		(void) strlcat(flagbuf, gettext("|KEEP"), sizeof (flagbuf));
	if (ep->e_flags & EXISTED)
		(void) strlcat(flagbuf, gettext("|EXISTED"), sizeof (flagbuf));
	if (ep->e_flags & XATTR)
		(void) strlcat(flagbuf, gettext("|XATTR"), sizeof (flagbuf));
	if (ep->e_flags & XATTRROOT)
		(void) strlcat(flagbuf, gettext("|XATTRROOT"),
						sizeof (flagbuf));
	return (&flagbuf[1]);
}

/*
 * Check to see if a name is on a dump tape.
 */
ino_t
dirlookup(char *name)
{
	ino_t ino;

	ino = psearch(name);
	if (ino == 0 || BIT(ino, dumpmap) == 0)
		(void) fprintf(stderr, gettext("%s is not on volume\n"), name);
	return (ino);
}

/*
 * Elicit a reply.
 */
int
reply(char *question)
{
	char *yesorno = gettext("yn"); /* must be two characters, "yes" first */
	int c;

	do	{
		(void) fprintf(stderr, "%s? [%s] ", question, yesorno);
		(void) fflush(stderr);
		c = getc(terminal);
		while (c != '\n' && getc(terminal) != '\n') {
			if (ferror(terminal)) {
				(void) fprintf(stderr, gettext(
					"Error reading response\n"));
				(void) fflush(stderr);
				return (FAIL);
			}
			if (feof(terminal))
				return (FAIL);
		}
		if (isupper(c))
			c = tolower(c);
	} while (c != yesorno[0] && c != yesorno[1]);
	if (c == yesorno[0])
		return (GOOD);
	return (FAIL);
}

/*
 * handle unexpected inconsistencies
 */
/*
 * Note that a panic w/ EOF on the tty means all panics will return...
 */
#ifdef __STDC__
#include <stdarg.h>

/* VARARGS1 */
void
panic(const char *msg, ...)
{
	va_list	args;

	va_start(args, msg);
	(void) vfprintf(stderr, msg, args);
	va_end(args);
	if (reply(gettext("abort")) == GOOD) {
		if (reply(gettext("dump core")) == GOOD)
			abort();
		done(1);
	}
}
#else
#include <varargs.h>

/* VARARGS1 */
void
panic(va_dcl)
{
	va_list	args;
	char	*msg;

	va_start(args);
	msg = va_arg(args, char *);
	(void) vfprintf(stderr, msg, args);
	va_end(args);
	if (reply(gettext("abort")) == GOOD) {
		if (reply(gettext("dump core")) == GOOD)
			abort();
		done(1);
	}
#endif

/*
 * Locale-specific version of ctime
 */
char *
lctime(time_t *tp)
{
	static char buf[256];
	struct tm *tm;

	tm = localtime(tp);
	(void) strftime(buf, sizeof (buf), "%c\n", tm);
	return (buf);
}

static int
statcmp(const struct stat *left, const struct stat *right)
{
	int result = 1;

	if ((left->st_dev == right->st_dev) &&
	    (left->st_ino == right->st_ino) &&
	    (left->st_mode == right->st_mode) &&
	    (left->st_nlink == right->st_nlink) &&
	    (left->st_uid == right->st_uid) &&
	    (left->st_gid == right->st_gid) &&
	    (left->st_rdev == right->st_rdev) &&
	    (left->st_ctim.tv_sec == right->st_ctim.tv_sec) &&
	    (left->st_ctim.tv_nsec == right->st_ctim.tv_nsec) &&
	    (left->st_mtim.tv_sec == right->st_mtim.tv_sec) &&
	    (left->st_mtim.tv_nsec == right->st_mtim.tv_nsec) &&
	    (left->st_blksize == right->st_blksize) &&
	    (left->st_blocks == right->st_blocks)) {
		result = 0;
	}

	return (result);
}

/*
 * Safely open a file.
 */
int
safe_open(int dfd, const char *filename, int mode, int perms)
{
	static int init_syslog = 1;
	int fd;
	int working_mode;
	int saverr;
	char *errtext;
	struct stat pre_stat, pre_lstat;
	struct stat post_stat, post_lstat;

	if (init_syslog) {
		openlog(progname, LOG_CONS, LOG_DAEMON);
		init_syslog = 0;
	}

	/*
	 * Don't want to be spoofed into trashing something we
	 * shouldn't, thus the following rigamarole.  If it doesn't
	 * exist, we create it and proceed.  Otherwise, require that
	 * what's there be a real file with no extraneous links and
	 * owned by whoever ran us.
	 *
	 * The silliness with using both lstat() and fstat() is to avoid
	 * race-condition games with someone replacing the file with a
	 * symlink after we've opened it.  If there was an flstat(),
	 * we wouldn't need the fstat().
	 *
	 * The initial open with the hard-coded flags is ok even if we
	 * are intending to open only for reading.  If it succeeds,
	 * then the file did not exist, and we'll synthesize an appropriate
	 * complaint below.  Otherwise, it does exist, so we won't be
	 * truncating it with the open.
	 */
	if ((fd = openat(dfd, filename,
	    O_WRONLY|O_CREAT|O_TRUNC|O_EXCL|O_LARGEFILE, perms)) < 0) {
		if (errno == EEXIST) {
			if (fstatat(dfd, filename, &pre_lstat,
						AT_SYMLINK_NOFOLLOW) < 0) {
				saverr = errno;
				(void) close(fd);
				errno = saverr;
				return (-1);
			}

			if (fstatat(dfd, filename, &pre_stat, 0) < 0) {
				saverr = errno;
				(void) close(fd);
				errno = saverr;
				return (-1);
			}

			working_mode = mode & (O_WRONLY|O_RDWR|O_RDONLY);
			working_mode |= O_LARGEFILE;

			if ((fd = openat(dfd, filename, working_mode)) < 0) {
				if (errno == ENOENT) {
					errtext = gettext(
"Unexpected condition detected: %s used to exist, but doesn't any longer\n");
					(void) fprintf(stderr, errtext,
					    filename);
					syslog(LOG_WARNING, errtext, filename);
					errno = ENOENT;
				}
				return (-1);
			}

			if (fstatat(fd, NULL, &post_lstat,
						AT_SYMLINK_NOFOLLOW) < 0) {
				saverr = errno;
				(void) close(fd);
				errno = saverr;
				return (-1);
			}

			if (fstatat(fd, NULL, &post_stat, 0) < 0) {
				saverr = errno;
				(void) close(fd);
				errno = saverr;
				return (-1);
			}

			if (statcmp(&pre_lstat, &post_lstat) != 0) {
				errtext = gettext(
"Unexpected condition detected: %s's lstat(2) information changed\n");
				(void) fprintf(stderr, errtext, filename);
				syslog(LOG_WARNING, errtext, filename);
				errno = EPERM;
				return (-1);
			}

			if (statcmp(&pre_stat, &post_stat) != 0) {
				errtext = gettext(
"Unexpected condition detected: %s's stat(2) information changed\n");
				(void) fprintf(stderr, errtext, filename);
				syslog(LOG_WARNING, errtext, filename);
				errno = EPERM;
				return (-1);
			}

			/*
			 * If inode, device, or type are wrong, bail out.
			 */
			if ((!S_ISREG(post_lstat.st_mode) ||
			    (post_stat.st_ino != post_lstat.st_ino) ||
			    (post_stat.st_dev != post_lstat.st_dev))) {
				errtext = gettext(
	    "Unexpected condition detected: %s is not a regular file\n");
				(void) fprintf(stderr, errtext, filename);
				syslog(LOG_WARNING, errtext, filename);
				(void) close(fd);
				errno = EPERM;
				return (-1);
			}

			/*
			 * Bad link count implies someone's linked our
			 * target to something else, which we probably
			 * shouldn't step on.
			 */
			if (post_lstat.st_nlink != 1) {
				errtext = gettext(
	    "Unexpected condition detected: %s must have exactly one link\n");
				(void) fprintf(stderr, errtext, filename);
				syslog(LOG_WARNING, errtext, filename);
				(void) close(fd);
				errno = EPERM;
				return (-1);
			}
			/*
			 * Root might make a file, but non-root might
			 * need to open it.  If the permissions let us
			 * get this far, then let it through.
			 */
			if (post_lstat.st_uid != getuid() &&
			    post_lstat.st_uid != 0) {
				errtext = gettext(
"Unsupported condition detected: %s must be owned by uid %ld or 0\n");
				(void) fprintf(stderr, errtext, filename,
				    (long)getuid());
				syslog(LOG_WARNING, errtext, filename,
				    (long)getuid());
				(void) close(fd);
				errno = EPERM;
				return (-1);
			}
			if (mode & (O_WRONLY|O_TRUNC)) {
				if (ftruncate(fd, (off_t)0) < 0) {
					(void) fprintf(stderr,
					    "ftruncate(%s): %s\n",
					    filename, strerror(errno));
					(void) close(fd);
					return (-1);
				}
			}
		} else {
			/*
			 * Didn't exist, but couldn't open it.
			 */
			return (-1);
		}
	} else {
		/*
		 * If truncating open succeeded for a read-only open,
		 * bail out, as we really shouldn't have succeeded.
		 */
		if (mode & O_RDONLY) {
			/* Undo the O_CREAT */
			(void) unlinkat(dfd, filename, 0);
			(void) fprintf(stderr, "open(%s): %s\n",
			    filename, strerror(ENOENT));
			(void) close(fd);
			errno = ENOENT;
			return (-1);
		}
	}

	return (fd);
}

/*
 * STDIO version of safe_open.  Equivalent to fopen64(...).
 */
FILE *
safe_fopen(const char *filename, const char *smode, int perms)
{
	int fd;
	int bmode;

	/*
	 * accepts only modes  "r", "r+", and "w"
	 */
	if (smode[0] == 'r') {
		if (smode[1] == '\0') {
			bmode = O_RDONLY;
		} else if ((smode[1] == '+') && (smode[2] == '\0')) {
			bmode = O_RDWR;
		}
	} else if ((smode[0] == 'w') && (smode[1] == '\0')) {
		bmode = O_WRONLY;
	} else {
		(void) fprintf(stderr,
		    gettext("internal error: safe_fopen: invalid mode `%s'\n"),
		    smode);
		return (NULL);
	}

	fd = safe_open(AT_FDCWD, filename, bmode, perms);

	/*
	 * caller is expected to report error.
	 */
	if (fd >= 0)
		return (fdopen(fd, smode));

	return ((FILE *)NULL);
}

/*
 * Read the contents of a directory.
 */
int
mkentry(char *name, ino_t ino, struct arglist *ap)
{
	struct afile *fp;

	if (ap->base == NULL) {
		ap->nent = 20;
		ap->base = (struct afile *)calloc((unsigned)ap->nent,
			sizeof (*(ap->base)));
		if (ap->base == NULL) {
			(void) fprintf(stderr,
				gettext("%s: out of memory\n"), ap->cmd);
			return (FAIL);
		}
	}
	if (ap->head == NULL)
		ap->head = ap->last = ap->base;
	fp = ap->last;
	fp->fnum = ino;
	fp->fname = savename(name);
	fp++;
	if (fp == ap->head + ap->nent) {
		ap->base = (struct afile *)realloc((char *)ap->base,
		    (size_t)(2 * ap->nent * (size_t)sizeof (*(ap->base))));
		if (ap->base == NULL) {
			(void) fprintf(stderr,
				gettext("%s: out of memory\n"), ap->cmd);
			return (FAIL);
		}
		ap->head = ap->base;
		fp = ap->head + ap->nent;
		ap->nent *= 2;
	}
	ap->last = fp;
	return (GOOD);
}

#ifdef __STDC__
static int gmatch(wchar_t *, wchar_t *);
static int addg(struct direct *, char *, char *, struct arglist *);
#else
static int gmatch();
static int addg();
#endif

/*
 * XXX  This value is ASCII (but not language) dependent.  In
 * ASCII, it is the DEL character (unlikely to appear in paths).
 * If you are compiling on an EBCDIC-based machine, re-define
 * this (0x7f is '"') to be something like 0x7 (DEL).  It's
 * either this hack or re-write the expand() algorithm...
 */
#define	DELIMCHAR	((char)0x7f)

/*
 * Expand a file name.
 * "as" is the pattern to expand.
 * "rflg" non-zero indicates that we're recursing.
 * "ap" is where to put the results of the expansion.
 *
 * Our caller guarantees that "as" is at least the string ".".
 */
int
expand(char *as, int rflg, struct arglist *ap)
{
	int		count, size;
	char		dir = 0;
	char		*rescan = 0;
	RST_DIR		*dirp;
	char		*s, *cs;
	int		sindex, rindexa, lindex;
	struct direct	*dp;
	char		slash;
	char		*rs;
	char		c;
	wchar_t 	w_fname[PATH_MAX+1];
	wchar_t		w_pname[PATH_MAX+1];

	/*
	 * check for meta chars
	 */
	s = cs = as;
	slash = 0;
	while (*cs != '*' && *cs != '?' && *cs != '[') {
		if (*cs++ == 0) {
			if (rflg && slash)
				break;
			else
				return (0);
		} else if (*cs == '/') {
			slash++;
		}
	}
	for (;;) {
		if (cs == s) {
			s = "";
			break;
		} else if (*--cs == '/') {
			*cs = 0;
			if (s == cs)
				s = "/";
			break;
		}
	}
	if ((dirp = rst_opendir(s)) != NULL)
		dir++;
	count = 0;
	if (*cs == 0)
		*cs++ = DELIMCHAR;
	if (dir) {
		/*
		 * check for rescan
		 */
		rs = cs;
		do {
			if (*rs == '/') {
				rescan = rs;
				*rs = 0;
			}
		} while (*rs++);
		/* LINTED: result fits into an int */
		sindex = (int)(ap->last - ap->head);
		(void) mbstowcs(w_pname, cs, PATH_MAX);
		w_pname[PATH_MAX - 1] = 0;
		while ((dp = rst_readdir(dirp)) != NULL && dp->d_ino != 0) {
			if (!dflag && BIT(dp->d_ino, dumpmap) == 0)
				continue;
			if ((*dp->d_name == '.' && *cs != '.'))
				continue;
			(void) mbstowcs(w_fname, dp->d_name, PATH_MAX);
			w_fname[PATH_MAX - 1] = 0;
			if (gmatch(w_fname, w_pname)) {
				if (addg(dp, s, rescan, ap) < 0) {
					rst_closedir(dirp);
					return (-1);
				}
				count++;
			}
		}
		if (rescan) {
			rindexa = sindex;
			/* LINTED: result fits into an int */
			lindex = (int)(ap->last - ap->head);
			if (count) {
				count = 0;
				while (rindexa < lindex) {
					size = expand(ap->head[rindexa].fname,
					    1, ap);
					if (size < 0) {
						rst_closedir(dirp);
						return (size);
					}
					count += size;
					rindexa++;
				}
			}
			/* LINTED: lint is confused about pointer size/type */
			bcopy((void *)(&ap->head[lindex]),
			    (void *)(&ap->head[sindex]),
			    (size_t)((ap->last - &ap->head[rindexa])) *
			    sizeof (*ap->head));
			ap->last -= lindex - sindex;
			*rescan = '/';
		}
		rst_closedir(dirp);
	}
	s = as;
	while ((c = *s) != '\0')
		*s++ = (c != DELIMCHAR ? c : '/');

	return (count);
}

/*
 * Check for a name match
 */
static int
gmatch(wchar_t *s, wchar_t *p)
{
	long	scc;	/* source character to text */
	wchar_t	c;	/* pattern character to match */
	char	ok;	/* [x-y] range match status */
	long	lc;	/* left character of [x-y] range */

	scc = *s++;
	switch (c = *p++) {

	case '[':
		ok = 0;
		lc = -1;
		while (c = *p++) {
			if (c == ']') {
				return (ok ? gmatch(s, p) : 0);
			} else if (c == '-') {
				wchar_t rc = *p++;
				/*
				 * Check both ends must belong to
				 * the same codeset.
				 */
				if (wcsetno(lc) != wcsetno(rc)) {
					/*
					 * If not, ignore the '-'
					 * operator and [x-y] is
					 * treated as if it were
					 * [xy].
					 */
					if (scc == lc)
						ok++;
					if (scc == (lc = rc))
						ok++;
				} else if (lc <= scc && scc <= rc)
					ok++;
			} else {
				lc = c;
				if (scc == lc)
					ok++;
			}
		}
		/* No closing bracket => failure */
		return (0);

	default:
		if (c != scc)
			return (0);
		/*FALLTHROUGH*/

	case '?':
		return (scc ? gmatch(s, p) : 0);

	case '*':
		if (*p == 0)
			return (1);
		s--;
		while (*s) {
			if (gmatch(s++, p))
				return (1);
		}
		return (0);

	case 0:
		return (scc == 0);
	}
}

/*
 * Construct a matched name.
 */
static int
addg(struct direct *dp, char *as1, char *as3, struct arglist *ap)
{
	char	*s1, *s2, *limit;
	int	c;
	char	buf[MAXPATHLEN + 1];

	s2 = buf;
	limit = buf + sizeof (buf) - 1;
	s1 = as1;
	while ((c = *s1++) != '\0' && s2 < limit) {
		if (c == DELIMCHAR) {
			*s2++ = '/';
			break;
		}
		/* LINTED narrowing cast */
		*s2++ = (char)c;
	}
	s1 = dp->d_name;
	while ((*s2 = *s1++) != '\0' && s2 < limit)
		s2++;
	s1 = as3;
	if (s1 != NULL && s2 < limit) {
		*s2++ = '/';

		while ((*s2++ = *++s1) != '\0' && s2 < limit) {
			continue;
			/*LINTED [empty loop body]*/
		}
	}
	*s2 = '\0';
	if (mkentry(buf, dp->d_ino, ap) == FAIL)
		return (-1);
	return (0);
}


/*
 * Resolve a "complex" pathname (as generated by myname()) into
 * a file descriptor and a relative path.  The file descriptor
 * will reference the hidden directory containing the attribute
 * named by the relative path.  If the provided path is not
 * complex, the returned file descriptor will be AT_FDCWD and rpath
 * will equal path.
 *
 * This function is intended to be used to transform a complex
 * pathname into a pair of handles that can be used to actually
 * manipulate the named file.  Since extended attributes have
 * an independant name space, a file descriptor for a directory
 * in the attribute name space is necessary to actually manipulate
 * the attribute file (via the path-relative xxxat() system calls
 * or a call to fchdir()).
 *
 * In the event of an error, the returned file descriptor will be
 * -1.  It is expected that callers will either check for this
 * condition directly, or attempt to use the descriptor, fail, and
 * generate an appropriate context-specific error message.
 *
 * This function is pretty much a no-op for "simple" (non-attribute)
 * paths.
 */
void
resolve(char *path, int *fd, char **rpath)
{
	int	tfd;

	*fd = tfd = AT_FDCWD;
	*rpath = path;
	path = *rpath + strlen(*rpath) +1;
	while (*path != '\0' &&
		(*fd = openat64(tfd, *rpath, O_RDONLY)) > 0) {
		if (tfd != AT_FDCWD) (void) close(tfd);
		tfd = *fd;
		*rpath = path;
		path = *rpath + strlen(*rpath) +1;
	}
	if (*fd == AT_FDCWD)
		return;
	if (*fd < 0 || (*fd = openat64(tfd, ".", O_RDONLY|O_XATTR)) < 0) {
		int saverr = errno;
		(void) fprintf(stderr,
			gettext("Warning: cannot fully resolve %s: %s"),
			path, strerror(saverr));
		(void) fflush(stderr);
	}
	if (tfd != AT_FDCWD) (void) close(tfd);
}

/*
 * Copy a complex pathname to another string.  Note that the
 * length returned by this function is the number of characters
 * up to (but not including) the final NULL.
 */
int
complexcpy(char *s1, char *s2, int max)
{
	int	nullseen = 0;
	int	len = 0;

	while (len++ < max) {
		*s1++ = *s2;
		if (*s2++ == '\0') {
			if (nullseen)
				return (len-1);
			else
				nullseen = 1;
		} else {
			nullseen = 0;
		}
	}
	*s1 = '\0';
	if (nullseen == 0)
		*--s1 = '\0';
	fprintf(stderr,
		gettext("Warning: unterminated source string in complexcpy\n"));
	return (max-1);
}
