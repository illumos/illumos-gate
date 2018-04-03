/*
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 1983 Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that the above copyright notice and this paragraph are
 * duplicated in all such forms and that any documentation,
 * advertising materials, and other materials related to such
 * distribution and use acknowledge that the software was developed
 * by the University of California, Berkeley.  The name of the
 * University may not be used to endorse or promote products derived
 * from this software without specific prior written permission.
 */

#include "defs.h"
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <ctype.h>
#include <krb5defs.h>

/*
 * If we want to write *to* the client rdist program, *from* the server
 * side (server-side child `rdist -Server' process exec'ed off of in.rshd),
 * we write to stdout/stderr, since there is a pipe connecting stdout/stderr
 * to the outside world (which is why we use `wrem' and not `rem').
 */
int wrem = 1;

#define	ack() 	(void) write(wrem, "\0\n", 2)
#define	err() 	(void) write(wrem, "\1\n", 2)

/*
 * Set when a desread() is reqd. in response()
 */

struct	linkbuf *ihead;		/* list of files with more than one link */
char	buf[RDIST_BUFSIZ];	/* general purpose buffer */
char	source[RDIST_BUFSIZ];	/* base source directory name */
char	destination[RDIST_BUFSIZ];	/* base destination directory name */
char	target[RDIST_BUFSIZ];	/* target/source directory name */
char	*tp;			/* pointer to end of target name */
char	*Tdest;			/* pointer to last T dest */
int	catname;		/* cat name to target name */
char	*stp[32];		/* stack of saved tp's for directories */
int	oumask;			/* old umask for creating files */

extern	FILE *lfp;		/* log file for mailing changes */

void	cleanup();
struct	linkbuf *savelink();
char	*strsub();

static void comment(char *s);
static void note();
static void hardlink(char *cmd);
void error();
void log();
static void recursive_remove(struct stat *stp);
static void recvf(char *cmd, int type);
static void query(char *name);
static void sendf(char *rname, int opts);
static void rmchk(int opts);
static void dospecial(char *cmd);
static void clean(char *cp);

/*
 * Server routine to read requests and process them.
 * Commands are:
 *	Tname	- Transmit file if out of date
 *	Vname	- Verify if file out of date or not
 *	Qname	- Query if file exists. Return mtime & size if it does.
 */
void
server()
{
	char cmdbuf[RDIST_BUFSIZ];
	register char *cp;

	signal(SIGHUP, cleanup);
	signal(SIGINT, cleanup);
	signal(SIGQUIT, cleanup);
	signal(SIGTERM, cleanup);
	signal(SIGPIPE, cleanup);

	rem = 0;
	oumask = umask(0);

	(void) sprintf(buf, "V%d\n", VERSION);
	(void) write(wrem, buf, strlen(buf));

	for (;;) {
		cp = cmdbuf;
		if (read(rem, cp, 1) <= 0)
			return;
		if (*cp++ == '\n') {
			error("server: expected control record\n");
			continue;
		}
		do {
			if (read(rem, cp, 1) != 1)
				cleanup();
		} while (*cp++ != '\n' && cp < &cmdbuf[RDIST_BUFSIZ]);
		*--cp = '\0';
		cp = cmdbuf;
		switch (*cp++) {
		case 'T':  /* init target file/directory name */
			catname = 1;	/* target should be directory */
			goto dotarget;

		case 't':  /* init target file/directory name */
			catname = 0;
		dotarget:
			if (exptilde(target, sizeof (target), cp) == NULL)
				continue;
			tp = target;
			while (*tp)
				tp++;
			ack();
			continue;

		case 'R':  /* Transfer a regular file. */
			recvf(cp, S_IFREG);
			continue;

		case 'D':  /* Transfer a directory. */
			recvf(cp, S_IFDIR);
			continue;

		case 'K':  /* Transfer symbolic link. */
			recvf(cp, S_IFLNK);
			continue;

		case 'k':  /* Transfer hard link. */
			hardlink(cp);
			continue;

		case 'E':  /* End. (of directory) */
			*tp = '\0';
			if (catname <= 0) {
				error("server: too many 'E's\n");
				continue;
			}
			tp = stp[--catname];
			*tp = '\0';
			ack();
			continue;

		case 'C':  /* Clean. Cleanup a directory */
			clean(cp);
			continue;

		case 'Q':  /* Query. Does the file/directory exist? */
			query(cp);
			continue;

		case 'S':  /* Special. Execute commands */
			dospecial(cp);
			continue;

#ifdef notdef
		/*
		 * These entries are reserved but not currently used.
		 * The intent is to allow remote hosts to have master copies.
		 * Currently, only the host rdist runs on can have masters.
		 */
		case 'X':  /* start a new list of files to exclude */
			except = bp = NULL;
		case 'x':  /* add name to list of files to exclude */
			if (*cp == '\0') {
				ack();
				continue;
			}
			if (*cp == '~') {
				if (exptilde(buf, sizeof (buf), cp) == NULL)
					continue;
				cp = buf;
			}
			if (bp == NULL)
				except = bp = expand(makeblock(NAME, cp),
				    E_VARS);
			else
				bp->b_next = expand(makeblock(NAME, cp),
				    E_VARS);
			while (bp->b_next != NULL)
				bp = bp->b_next;
			ack();
			continue;

		case 'I':  /* Install. Transfer file if out of date. */
			opts = 0;
			while (*cp >= '0' && *cp <= '7')
				opts = (opts << 3) | (*cp++ - '0');
			if (*cp++ != ' ') {
				error("server: options not delimited\n");
				return;
			}
			install(cp, opts);
			continue;

		case 'L':  /* Log. save message in log file */
			log(lfp, cp);
			continue;
#endif

		case '\1':
			nerrs++;
			continue;

		case '\2':
			return;

		default:
			error("server: unknown command '%s'\n", cp);
			continue;
		case '\0':
			continue;
		}
	}
}

/*
 * Update the file(s) if they are different.
 * destdir = 1 if destination should be a directory
 * (i.e., more than one source is being copied to the same destination).
 */
void
install(src, dest, destdir, opts)
	char *src, *dest;
	int destdir, opts;
{
	char *rname;
	char destcopy[RDIST_BUFSIZ];

	if (dest == NULL) {
		opts &= ~WHOLE; /* WHOLE mode only useful if renaming */
		dest = src;
	}

	if (nflag || debug) {
		printf("%s%s%s%s%s %s %s\n", opts & VERIFY ? "verify":"install",
			opts & WHOLE ? " -w" : "",
			opts & YOUNGER ? " -y" : "",
			opts & COMPARE ? " -b" : "",
			opts & REMOVE ? " -R" : "", src, dest);
		if (nflag)
			return;
	}

	rname = exptilde(target, sizeof (target), src);
	if (rname == NULL)
		return;
	tp = target;
	while (*tp)
		tp++;
	/*
	 * If we are renaming a directory and we want to preserve
	 * the directory heirarchy (-w), we must strip off the leading
	 * directory name and preserve the rest.
	 */
	if (opts & WHOLE) {
		while (*rname == '/')
			rname++;
		destdir = 1;
	} else {
		rname = rindex(target, '/');
		if (rname == NULL)
			rname = target;
		else
			rname++;
	}
	if (debug)
		printf("target = %s, rname = %s\n", target, rname);
	/*
	 * Pass the destination file/directory name to remote.
	 */
	if (snprintf(buf, sizeof (buf), "%c%s\n", destdir ? 'T' : 't', dest) >=
	    sizeof (buf)) {
		error("%s: Name too long\n", dest);
		return;
	}
	if (debug)
		printf("buf = %s", buf);
	(void) deswrite(rem, buf, strlen(buf), 0);

	if (response() < 0)
		return;

	strcpy(source, src);
	if (destdir) {
		strcpy(destcopy, dest);
		Tdest = destcopy;
		strcpy(destination, rname);
	} else {
		strcpy(destination, dest);
	}
	sendf(rname, opts);
	Tdest = 0;
}

#define	protoname()	(pw ? pw->pw_name : user)
#define	protogroup()	(gr ? gr->gr_name : group)
/*
 * Transfer the file or directory in target[].
 * rname is the name of the file on the remote host.
 */
void
sendf(rname, opts)
	char *rname;
	int opts;
{
	register struct subcmd *sc;
	struct stat stb;
	int sizerr, f, u, len;
	off_t i;
	DIR *d;
	struct dirent *dp;
	char *otp, *cp;
	extern struct subcmd *subcmds;
	static char user[15], group[15];

	if (debug)
		printf("sendf(%s, %x%s)\n", rname, opts, printb(opts, OBITS));

	if (except(target))
		return;
	if ((opts & FOLLOW ? stat(target, &stb) : lstat(target, &stb)) < 0) {
		error("%s: %s\n", target, strerror(errno));
		return;
	}
	if (index(rname, '\n')) {
		error("file name '%s' contains an embedded newline - "
		    "can't update\n", rname);
		return;
	}
	if ((u = update(rname, opts, &stb)) == 0) {
		if ((stb.st_mode & S_IFMT) == S_IFREG && stb.st_nlink > 1)
			(void) savelink(&stb, opts);
		return;
	}

	if (pw == NULL || pw->pw_uid != stb.st_uid)
		if ((pw = getpwuid(stb.st_uid)) == NULL) {
			log(lfp, "%s: no password entry for uid %d \n",
				target, stb.st_uid);
			pw = NULL;
			sprintf(user, ":%d", stb.st_uid);
		}
	if (gr == NULL || gr->gr_gid != stb.st_gid)
		if ((gr = getgrgid(stb.st_gid)) == NULL) {
			log(lfp, "%s: no name for group %d\n",
				target, stb.st_gid);
			gr = NULL;
			sprintf(group, ":%d", stb.st_gid);
		}
	if (u == 1) {
		if (opts & VERIFY) {
			log(lfp, "need to install: %s\n", target);
			goto dospecial;
		}
		log(lfp, "installing: %s\n", target);
		opts &= ~(COMPARE|REMOVE);
	}

	switch (stb.st_mode & S_IFMT) {
	case S_IFDIR:
		if ((d = opendir(target)) == NULL) {
			error("%s: %s\n", target, strerror(errno));
			return;
		}
		if (snprintf(buf, sizeof (buf), "D%o %04o 0 0 %s %s %s\n",
		    opts, stb.st_mode & 07777, protoname(), protogroup(),
		    rname) >= sizeof (buf)) {
			error("%s: Name too long\n", rname);
			closedir(d);
			return;
		}
		if (debug)
			printf("buf = %s", buf);
		(void) deswrite(rem, buf, strlen(buf), 0);
		if (response() < 0) {
			closedir(d);
			return;
		}

		if (opts & REMOVE)
			rmchk(opts);

		otp = tp;
		len = tp - target;
		while (dp = readdir(d)) {
			if ((strcmp(dp->d_name, ".") == 0)||
			    (strcmp(dp->d_name, "..") == 0))
				continue;
			if ((int)(len + 1 + strlen(dp->d_name)) >=
			    (int)(RDIST_BUFSIZ - 1)) {
				error("%.*s/%s: Name too long\n", len, target,
					dp->d_name);
				continue;
			}
			tp = otp;
			*tp++ = '/';
			cp = dp->d_name;
			while (*tp++ = *cp++)
				;
			tp--;
			sendf(dp->d_name, opts);
		}
		closedir(d);
		(void) deswrite(rem, "E\n", 2, 0);
		(void) response();
		tp = otp;
		*tp = '\0';
		return;

	case S_IFLNK:
		if (u != 1)
			opts |= COMPARE;
		if (stb.st_nlink > 1) {
			struct linkbuf *lp;

			if ((lp = savelink(&stb, opts)) != NULL) {
				/* install link */
				if (*lp->target == 0)
					len = snprintf(buf, sizeof (buf),
					    "k%o %s %s\n", opts, lp->pathname,
					    rname);
				else
					len = snprintf(buf, sizeof (buf),
					    "k%o %s/%s %s\n", opts, lp->target,
					    lp->pathname, rname);
				if (len >= sizeof (buf)) {
					error("%s: Name too long\n", rname);
					return;
				}
				if (debug)
					printf("buf = %s", buf);
				(void) deswrite(rem, buf, strlen(buf), 0);
				(void) response();
				return;
			}
		}
		(void) snprintf(buf, sizeof (buf), "K%o %o %ld %ld %s %s %s\n",
		    opts, stb.st_mode & 07777, stb.st_size, stb.st_mtime,
		    protoname(), protogroup(), rname);
		if (debug)
			printf("buf = %s", buf);
		(void) deswrite(rem, buf, strlen(buf), 0);
		if (response() < 0)
			return;
		sizerr = (readlink(target, buf, RDIST_BUFSIZ) != stb.st_size);
		(void) deswrite(rem, buf, stb.st_size, 0);
		if (debug)
			printf("readlink = %.*s\n", (int)stb.st_size, buf);
		goto done;

	case S_IFREG:
		break;

	default:
		error("%s: not a file or directory\n", target);
		return;
	}

	if (u == 2) {
		if (opts & VERIFY) {
			log(lfp, "need to update: %s\n", target);
			goto dospecial;
		}
		log(lfp, "updating: %s\n", target);
	}

	if (stb.st_nlink > 1) {
		struct linkbuf *lp;

		if ((lp = savelink(&stb, opts)) != NULL) {
			/* install link */
			if (*lp->target == 0)
				len = snprintf(buf, sizeof (buf), "k%o %s %s\n",
				    opts, lp->pathname, rname);
			else
				len = snprintf(buf, sizeof (buf),
				    "k%o %s/%s %s\n", opts, lp->target,
				    lp->pathname, rname);
			if (len >= sizeof (buf)) {
				error("%s: Name too long\n", rname);
				return;
			}
			if (debug)
				printf("buf = %s", buf);
			(void) deswrite(rem, buf, strlen(buf), 0);
			(void) response();
			return;
		}
	}

	if ((f = open(target, 0)) < 0) {
		error("%s: %s\n", target, strerror(errno));
		return;
	}
	(void) snprintf(buf, sizeof (buf), "R%o %o %ld %ld %s %s %s\n", opts,
		stb.st_mode & 07777, stb.st_size, stb.st_mtime,
		protoname(), protogroup(), rname);
	if (debug)
		printf("buf = %s", buf);
	(void) deswrite(rem, buf, strlen(buf), 0);

	if (response() < 0) {
		(void) close(f);
		return;
	}

	sizerr = 0;

	for (i = 0; i < stb.st_size; i += RDIST_BUFSIZ) {
		int amt = RDIST_BUFSIZ;
		if (i + amt > stb.st_size)
			amt = stb.st_size - i;
		if (sizerr == 0 && read(f, buf, amt) != amt)
			sizerr = 1;
		(void) deswrite(rem, buf, amt, 0);
	}
	(void) close(f);
done:
	if (sizerr) {
		error("%s: file changed size\n", target);
		(void) deswrite(rem, "\1\n", 2, 0);
	} else
		(void) deswrite(rem, "\0\n", 2, 0);
	f = response();

	if (f < 0 || f == 0 && (opts & COMPARE))
		return;
dospecial:
	for (sc = subcmds; sc != NULL; sc = sc->sc_next) {
		if (sc->sc_type != SPECIAL)
			continue;
		if (sc->sc_args != NULL && !inlist(sc->sc_args, target))
			continue;
		log(lfp, "special \"%s\"\n", sc->sc_name);
		if (opts & VERIFY)
			continue;
		(void) snprintf(buf, sizeof (buf), "SFILE=%s;%s\n", target,
		    sc->sc_name);
		if (debug)
			printf("buf = %s", buf);
		(void) deswrite(rem, buf, strlen(buf), 0);
		while (response() > 0)
			;
	}
}

struct linkbuf *
savelink(stp, opts)
	struct stat *stp;
	int opts;
{
	struct linkbuf *lp;

	for (lp = ihead; lp != NULL; lp = lp->nextp)
		if (lp->inum == stp->st_ino && lp->devnum == stp->st_dev) {
			lp->count--;
			return (lp);
		}
	lp = (struct linkbuf *)malloc(sizeof (*lp));
	if (lp == NULL)
		log(lfp, "out of memory, link information lost\n");
	else {
		lp->nextp = ihead;
		ihead = lp;
		lp->inum = stp->st_ino;
		lp->devnum = stp->st_dev;
		lp->count = stp->st_nlink - 1;

		if (strlcpy(lp->pathname,
		    opts & WHOLE ? target : strsub(source, destination, target),
		    sizeof (lp->pathname)) >= sizeof (lp->pathname)) {
			error("%s: target name too long\n", target);
		}

		if (Tdest) {
			if (strlcpy(lp->target, Tdest,
			    sizeof (lp->target)) >= sizeof (lp->target))
				error("%s: target name too long\n", Tdest);
		} else
			*lp->target = 0;
	}
	return (NULL);
}

/*
 * Check to see if file needs to be updated on the remote machine.
 * Returns 0 if no update, 1 if remote doesn't exist, 2 if out of date
 * and 3 if comparing binaries to determine if out of date.
 */
int
update(rname, opts, stp)
	char *rname;
	int opts;
	struct stat *stp;
{
	register char *cp, *s;
	register off_t size;
	register time_t mtime;

	if (debug)
		printf("update(%s, %x%s, %x)\n", rname, opts,
			printb(opts, OBITS), stp);

	/*
	 * Check to see if the file exists on the remote machine.
	 */
	if (snprintf(buf, sizeof (buf), "Q%s\n", rname) >= sizeof (buf)) {
		error("%s: Name too long\n", rname);
		return (0);
	}
	if (debug)
		printf("buf = %s", buf);
	(void) deswrite(rem, buf, strlen(buf), 0);
again:
	cp = s = buf;
more:
	do {
		if (desread(rem, cp, 1, 0) != 1)
			lostconn();
	} while (*cp++ != '\n' && cp < &buf[RDIST_BUFSIZ]);

	if (cp <  &buf[RDIST_BUFSIZ])
		*cp = '\0';
	if (debug) {
		printf("update reply:  ");
		switch (*s) {
			case 'Y':
			case 'N':
				putchar(*s);
				break;
			default:
				if (iscntrl(*s)) {
					putchar('^');
					putchar('A' + *s - 1);
				} else
					printf("%#x", *s & 0xff);
				break;
		}
		printf("%s", &s[1]);
	}

	switch (*s++) {
	case 'Y':
		break;

	case 'N':  /* file doesn't exist so install it */
		return (1);

	case '\1':
		nerrs++;
		if (*s != '\n') {
			if (!iamremote) {
				fflush(stdout);
				(void) write(2, s, cp - s);
			}
			if (lfp != NULL)
				(void) fwrite(s, 1, cp - s, lfp);
		}
		if (cp == &buf[RDIST_BUFSIZ] && *(cp - 1) != '\n') {
			/* preserve status code */
			cp = s;
			s = buf;
			goto more;
		}
		return (0);

	case '\3':
		*--cp = '\0';
		if (lfp != NULL)
			log(lfp, "update: note: %s\n", s);
		goto again;

	default:
		*--cp = '\0';
		error("update: unexpected response '%s'\n", s);
		return (0);
	}

	if (*s == '\n')
		return (2);

	if (opts & COMPARE)
		return (3);

	size = 0;
	while (isdigit(*s))
		size = size * 10 + (*s++ - '0');
	if (*s++ != ' ') {
		error("update: size not delimited\n");
		return (0);
	}
	mtime = 0;
	while (isdigit(*s))
		mtime = mtime * 10 + (*s++ - '0');
	if (*s != '\n') {
		error("update: mtime not delimited\n");
		return (0);
	}
	/*
	 * File needs to be updated?
	 */
	if (opts & YOUNGER) {
		if (stp->st_mtime == mtime)
			return (0);
		if (stp->st_mtime < mtime) {
			log(lfp, "Warning: %s: remote copy is newer\n", target);
			return (0);
		}
	} else if (stp->st_mtime == mtime && stp->st_size == size)
		return (0);
	return (2);
}

/*
 * Query. Check to see if file exists. Return one of the following:
 *	N\n		- doesn't exist
 *	Ysize mtime\n	- exists and its a regular file (size & mtime of file)
 *	Y\n		- exists and its a directory or symbolic link
 *	^Aerror message\n
 */
static void
query(name)
	char *name;
{
	struct stat stb;

	if (catname) {
		if (sizeof (target) - (tp - target) >= strlen(name) + 2) {
			(void) sprintf(tp, "/%s", name);
		} else {
			error("%.*s/%s: Name too long\n", tp - target,
			    target, name);
			return;
		}
	}

	if (lstat(target, &stb) < 0) {
		if (errno == ENOENT)
			(void) write(wrem, "N\n", 2);
		else
			error("%s:%s: %s\n", host, target, strerror(errno));
		*tp = '\0';
		return;
	}

	switch (stb.st_mode & S_IFMT) {
	case S_IFREG:
		(void) sprintf(buf, "Y%ld %ld\n", stb.st_size, stb.st_mtime);
		(void) write(wrem, buf, strlen(buf));
		break;

	case S_IFLNK:
	case S_IFDIR:
		(void) write(wrem, "Y\n", 2);
		break;

	default:
		error("%s: not a file or directory\n", name);
		break;
	}
	*tp = '\0';
}

static void
recvf(cmd, type)
	char *cmd;
	int type;
{
	register char *cp;
	int f, mode, opts, wrerr, olderrno;
	off_t i, size;
	time_t mtime;
	struct stat stb;
	struct timeval tvp[2];
	char *owner, *group;
	char new[RDIST_BUFSIZ];
	extern char *tmpname;

	cp = cmd;
	opts = 0;
	while (*cp >= '0' && *cp <= '7')
		opts = (opts << 3) | (*cp++ - '0');
	if (*cp++ != ' ') {
		error("recvf: options not delimited\n");
		return;
	}
	mode = 0;
	while (*cp >= '0' && *cp <= '7')
		mode = (mode << 3) | (*cp++ - '0');
	if (*cp++ != ' ') {
		error("recvf: mode not delimited\n");
		return;
	}
	size = 0;
	while (isdigit(*cp))
		size = size * 10 + (*cp++ - '0');
	if (*cp++ != ' ') {
		error("recvf: size not delimited\n");
		return;
	}
	mtime = 0;
	while (isdigit(*cp))
		mtime = mtime * 10 + (*cp++ - '0');
	if (*cp++ != ' ') {
		error("recvf: mtime not delimited\n");
		return;
	}
	owner = cp;
	while (*cp && *cp != ' ')
		cp++;
	if (*cp != ' ') {
		error("recvf: owner name not delimited\n");
		return;
	}
	*cp++ = '\0';
	group = cp;
	while (*cp && *cp != ' ')
		cp++;
	if (*cp != ' ') {
		error("recvf: group name not delimited\n");
		return;
	}
	*cp++ = '\0';

	if (type == S_IFDIR) {
		int	isdot;

		if (strcmp(cp, ".") == 0)
			isdot = 1;
		else
			isdot = 0;
		if (catname >= sizeof (stp) / sizeof (stp[0])) {
			error("%s:%s: too many directory levels\n",
				host, target);
			return;
		}
		stp[catname] = tp;
		if (catname++) {
			*tp++ = '/';
			while (*tp++ = *cp++)
				;
			tp--;
		}
		if (opts & VERIFY) {
			ack();
			return;
		}
		if (lstat(target, &stb) == 0) {
			if (ISDIR(stb.st_mode)) {
				if ((stb.st_mode & 07777) == mode) {
					ack();
					return;
				}
				sendrem("%s: Warning: remote mode %o != "
				    "local mode %o", target,
				    stb.st_mode & 07777, mode);
				return;
			}
			errno = ENOTDIR;
		} else if (errno == ENOENT && (mkdir(target, mode) == 0 ||
		    chkparent(target) == 0 &&
		    (isdot == 1 || mkdir(target, mode) == 0))) {
			if (chog(target, owner, group, mode) == 0)
				ack();
			return;
		}
		error("%s:%s: %s\n", host, target, strerror(errno));
		tp = stp[--catname];
		*tp = '\0';
		return;
	}

	if (catname) {
		if (sizeof (target) - (tp - target) >= strlen(cp) + 2) {
			(void) sprintf(tp, "/%s", cp);
		} else {
			error("%.*s/%s: Name too long\n", tp - target,
			    target, cp);
			return;
		}
	}
	cp = rindex(target, '/');
	if (cp == NULL)
		strcpy(new, tmpname);
	else if (cp == target)
		(void) sprintf(new, "/%s", tmpname);
	else {
		*cp = '\0';

		/*
		 * sizeof (target) =  RDIST_BUFSIZ and sizeof (tmpname) = 11
		 * RDIST_BUFSIZ = 50*1024 is much greater than PATH_MAX that is
		 * allowed by the kernel, so it's safe to call snprintf() here
		 */
		(void) snprintf(new, sizeof (new), "%s/%s", target, tmpname);
		*cp = '/';
	}

	if (type == S_IFLNK) {
		int j;

		ack();
		cp = buf;
		for (i = 0; i < size; i += j) {
			if ((j = read(rem, cp, size - i)) <= 0)
				cleanup();
			cp += j;
		}
		*cp = '\0';
		if (response() < 0) {
			err();
			return;
		}
		if (symlink(buf, new) < 0) {
			if (errno != ENOENT || chkparent(new) < 0 ||
			    symlink(buf, new) < 0)
				goto badn;
		}
		mode &= 0777;
		if (opts & COMPARE) {
			char tbuf[MAXPATHLEN];

			if ((i = readlink(target, tbuf, MAXPATHLEN)) >= 0 &&
			    i == size && strncmp(buf, tbuf, size) == 0) {
				(void) unlink(new);
				ack();
				return;
			}
			if (opts & VERIFY)
				goto differ;
		}
		goto fixup;
	}

	if ((f = creat(new, mode & ~06000)) < 0) {
		if (errno != ENOENT || chkparent(new) < 0 ||
		    (f = creat(new, mode & ~06000)) < 0)
			goto badn;
	}

	ack();
	wrerr = 0;
	for (i = 0; i < size; i += RDIST_BUFSIZ) {
		int amt = RDIST_BUFSIZ;

		cp = buf;
		if (i + amt > size)
			amt = size - i;
		do {
			int j = read(rem, cp, amt);
			if (j <= 0) {
				(void) close(f);
				(void) unlink(new);
				cleanup();
			}
			amt -= j;
			cp += j;
		} while (amt > 0);
		amt = RDIST_BUFSIZ;
		if (i + amt > size)
			amt = size - i;
		if (wrerr == 0 && write(f, buf, amt) != amt) {
			olderrno = errno;
			wrerr++;
		}
	}
	(void) close(f);

	if (response() < 0) {
		err();
		(void) unlink(new);
		return;
	}
	if (wrerr) {
		error("%s:%s: %s\n", host, new, strerror(olderrno));
		(void) unlink(new);
		return;
	}
	if (opts & COMPARE) {
		FILE *f1, *f2;
		int c;

		if ((f1 = fopen(target, "r")) == NULL)
			goto badt;
		if ((f2 = fopen(new, "r")) == NULL) {
		badn:
			error("%s:%s: %s\n", host, new, strerror(errno));
			(void) unlink(new);
			return;
		}
		while ((c = getc(f1)) == getc(f2))
			if (c == EOF) {
				(void) fclose(f1);
				(void) fclose(f2);
				(void) unlink(new);
				ack();
				return;
			}
		(void) fclose(f1);
		(void) fclose(f2);
		if (opts & VERIFY) {
		differ:
			(void) unlink(new);
			sendrem("need to update: %s", target);
			return;
		}
	}

	/*
	 * Set last modified time.  For type == S_IFDIR, the lstat above filled
	 * in stb.  Otherwise, do it now.
	 */
	if (type != S_IFDIR)
		(void) lstat(new, &stb);
	tvp[0].tv_sec = stb.st_atime;	/* old atime from target */
	tvp[0].tv_usec = 0;
	tvp[1].tv_sec = mtime;
	tvp[1].tv_usec = 0;
	if (utimes(new, tvp) < 0) {
		note("%s:utimes failed %s: %s", host, new, strerror(errno));
	}
	if (chog(new, owner, group, mode) < 0) {
		(void) unlink(new);
		return;
	}
fixup:
	if (rename(new, target) < 0) {
badt:
		error("%s:%s: %s\n", host, target, strerror(errno));
		(void) unlink(new);
		return;
	}
	if (opts & COMPARE) {
		sendrem("updated %s", target);
	} else
		ack();
}

/*
 * Creat a hard link to existing file.
 */
static void
hardlink(cmd)
	char *cmd;
{
	register char *cp;
	struct stat stb;
	char *oldname;
	int opts, exists = 0;
	char oldnamebuf[RDIST_BUFSIZ];

	cp = cmd;
	opts = 0;
	while (*cp >= '0' && *cp <= '7')
		opts = (opts << 3) | (*cp++ - '0');
	if (*cp++ != ' ') {
		error("hardlink: options not delimited\n");
		return;
	}
	oldname = cp;
	while (*cp && *cp != ' ')
		cp++;
	if (*cp != ' ') {
		error("hardlink: oldname name not delimited\n");
		return;
	}
	*cp++ = '\0';

	if (catname) {
		if (sizeof (target) - (tp - target) >= strlen(cp) + 2) {
			(void) sprintf(tp, "/%s", cp);
		} else {
			error("%.*s/%s: Name too long\n", tp - target,
			    target, cp);
			return;
		}
	}
	if (lstat(target, &stb) == 0) {
		int mode = stb.st_mode & S_IFMT;
		if (mode != S_IFREG && mode != S_IFLNK) {
			error("%s:%s: not a regular file\n", host, target);
			return;
		}
		exists = 1;
	}
	if (chkparent(target) < 0) {
		error("%s:%s: %s (no parent)\n",
			host, target, strerror(errno));
		return;
	}
	if (opts & VERIFY) {
		struct stat nstb;

		if (exists && lstat(oldname, &nstb) == 0 &&
		    nstb.st_mode == stb.st_mode &&
		    nstb.st_ino == stb.st_ino &&
		    nstb.st_dev == stb.st_dev) {
			ack();
			return;
		} else {
			sendrem("need to update: %s", target);
			return;
		}
	}
	if (exists && (unlink(target) < 0)) {
		error("%s:%s: %s (unlink)\n",
			host, target, strerror(errno));
		return;
	}
	if (*oldname == '~')
		oldname = exptilde(oldnamebuf, sizeof (oldnamebuf), oldname);
	if (link(oldname, target) < 0) {
		error("%s:can't link %s to %s\n",
			host, target, oldname);
		return;
	}
	ack();
}

/*
 * Check to see if parent directory exists and create one if not.
 */
int
chkparent(name)
	char *name;
{
	register char *cp;
	struct stat stb;

	cp = rindex(name, '/');
	if (cp == NULL || cp == name)
		return (0);
	*cp = '\0';
	if (lstat(name, &stb) < 0) {
		if (errno == ENOENT && chkparent(name) >= 0 &&
		    mkdir(name, 0777 & ~oumask) >= 0) {
			*cp = '/';
			return (0);
		}
	} else if (ISDIR(stb.st_mode)) {
		*cp = '/';
		return (0);
	}
	*cp = '/';
	return (-1);
}

/*
 * Change owner, group and mode of file.
 */
int
chog(file, owner, group, mode)
	char *file, *owner, *group;
	int mode;
{
	register int i;
	uid_t uid, gid;
	extern char user[];

	/*
	 * by default, set uid of file to the uid of the person running
	 * this program.
	 */
	uid = getuid();

	/*
	 * We'll use available privileges so we just try to do what
	 * the client specifies.  If the chown() fails we'll not
	 * add the set-[ug]id bits; and if we want to add the set-[ug]id
	 * bits and we're not permitted to do so, the OS will prevent us
	 * from doing so.
	 */
	if (*owner == ':') {
		uid = atoi(owner + 1);
	} else if (pw == NULL || strcmp(owner, pw->pw_name) != 0) {
		if ((pw = getpwnam(owner)) == NULL) {
			if (mode & 04000) {
				note("%s:%s: unknown login name, "
				    "clearing setuid", host, owner);
				mode &= ~04000;
			}
		} else {
			uid = pw->pw_uid;
		}
	} else {
		uid = pw->pw_uid;
	}

	if (*group == ':') {
		gid = atoi(group + 1);
		goto ok;
	}

	gid = -1;
	if (gr == NULL || strcmp(group, gr->gr_name) != 0) {
		if ((*group == ':' &&
		    (getgrgid(gid = atoi(group + 1)) == NULL)) ||
		    ((gr = getgrnam(group)) == NULL)) {
			if (mode & 02000) {
				note("%s:%s: unknown group", host, group);
				mode &= ~02000;
			}
		} else
			gid = gr->gr_gid;
	} else
		gid = gr->gr_gid;
ok:
	if (chown(file, uid, gid) < 0 ||
	    (mode & 07000) && chmod(file, mode) < 0) {
		note("%s: chown or chmod failed: file %s:  %s",
		    host, file, strerror(errno));
	}
	return (0);
}

/*
 * Check for files on the machine being updated that are not on the master
 * machine and remove them.
 */
static void
rmchk(opts)
	int opts;
{
	register char *cp, *s;
	struct stat stb;

	if (debug)
		printf("rmchk()\n");

	/*
	 * Tell the remote to clean the files from the last directory sent.
	 */
	(void) sprintf(buf, "C%o\n", opts & VERIFY);
	if (debug)
		printf("buf = %s", buf);
	(void) deswrite(rem, buf, strlen(buf), 0);
	if (response() < 0)
		return;
	for (;;) {
		cp = s = buf;
		do {
			if (desread(rem, cp, 1, 0) != 1)
				lostconn();
		} while (*cp++ != '\n' && cp < &buf[RDIST_BUFSIZ]);

		switch (*s++) {
		case 'Q': /* Query if file should be removed */
			/*
			 * Return the following codes to remove query.
			 * N\n -- file exists - DON'T remove.
			 * Y\n -- file doesn't exist - REMOVE.
			 */
			*--cp = '\0';
			(void) sprintf(tp, "/%s", s);
			if (debug)
				printf("check %s\n", target);
			if (except(target))
				(void) deswrite(rem, "N\n", 2, 0);
			else if (lstat(target, &stb) < 0)
				(void) deswrite(rem, "Y\n", 2, 0);
			else
				(void) deswrite(rem, "N\n", 2, 0);
			break;

		case '\0':
			*--cp = '\0';
			if (*s != '\0')
				log(lfp, "%s\n", s);
			break;

		case 'E':
			*tp = '\0';
			(void) deswrite(rem, "\0\n", 2, 0);
			return;

		case '\1':
		case '\2':
			nerrs++;
			if (*s != '\n') {
				if (!iamremote) {
					fflush(stdout);
					(void) write(2, s, cp - s);
				}
				if (lfp != NULL)
					(void) fwrite(s, 1, cp - s, lfp);
			}
			if (buf[0] == '\2')
				lostconn();
			break;

		default:
			error("rmchk: unexpected response '%s'\n", buf);
			(void) deswrite(rem, "\1\n", 2, 0);
		}
	}
}

/*
 * Check the current directory (initialized by the 'T' command to server())
 * for extraneous files and remove them.
 */
static void
clean(cp)
	register char *cp;
{
	DIR *d;
	register struct dirent *dp;
	struct stat stb;
	char *otp;
	int len, opts;

	opts = 0;
	while (*cp >= '0' && *cp <= '7')
		opts = (opts << 3) | (*cp++ - '0');
	if (*cp != '\0') {
		error("clean: options not delimited\n");
		return;
	}
	if ((d = opendir(target)) == NULL) {
		error("%s:%s: %s\n", host, target, strerror(errno));
		return;
	}
	ack();

	otp = tp;
	len = tp - target;
	while (dp = readdir(d)) {
		if ((strcmp(dp->d_name, ".") == 0) ||
		    (strcmp(dp->d_name, "..") == 0))
			continue;
		if ((int)(len + 1 + strlen(dp->d_name)) >=
		    (int)(RDIST_BUFSIZ - 1)) {
			error("%s:%s/%s: Name too long\n",
				host, target, dp->d_name);
			continue;
		}
		tp = otp;
		*tp++ = '/';
		cp = dp->d_name;
		while (*tp++ = *cp++)
			;
		tp--;
		if (lstat(target, &stb) < 0) {
			error("%s:%s: %s\n", host, target, strerror(errno));
			continue;
		}
		(void) snprintf(buf, sizeof (buf), "Q%s\n", dp->d_name);
		(void) write(wrem, buf, strlen(buf));
		cp = buf;
		do {
			if (read(rem, cp, 1) != 1)
				cleanup();
		} while (*cp++ != '\n' && cp < &buf[RDIST_BUFSIZ]);
		*--cp = '\0';
		cp = buf;
		if (*cp != 'Y')
			continue;
		if (opts & VERIFY) {
			sendrem("need to remove: %s", target);
		} else
			(void) recursive_remove(&stb);
	}
	closedir(d);
	(void) write(wrem, "E\n", 2);
	(void) response();
	tp = otp;
	*tp = '\0';
}

/*
 * Remove a file or directory (recursively) and send back an acknowledge
 * or an error message.
 */
static void
recursive_remove(stp)
	struct stat *stp;
{
	DIR *d;
	struct dirent *dp;
	register char *cp;
	struct stat stb;
	char *otp;
	int len;

	switch (stp->st_mode & S_IFMT) {
	case S_IFREG:
	case S_IFLNK:
		if (unlink(target) < 0)
			goto bad;
		goto removed;

	case S_IFDIR:
		break;

	default:
		error("%s:%s: not a plain file\n", host, target);
		return;
	}

	if ((d = opendir(target)) == NULL)
		goto bad;

	otp = tp;
	len = tp - target;
	while (dp = readdir(d)) {
		if ((strcmp(dp->d_name, ".") == 0) ||
		    (strcmp(dp->d_name, "..") == 0))
			continue;
		if ((int)(len + 1 + strlen(dp->d_name)) >=
		    (int)(RDIST_BUFSIZ - 1)) {
			error("%s:%s/%s: Name too long\n",
				host, target, dp->d_name);
			continue;
		}
		tp = otp;
		*tp++ = '/';
		cp = dp->d_name;
		while (*tp++ = *cp++)
			;
		tp--;
		if (lstat(target, &stb) < 0) {
			error("%s:%s: %s\n", host, target, strerror(errno));
			continue;
		}
		recursive_remove(&stb);
	}
	closedir(d);
	tp = otp;
	*tp = '\0';
	if (rmdir(target) < 0) {
bad:
		error("%s:%s: %s\n", host, target, strerror(errno));
		return;
	}
removed:
	sendrem("removed %s", target);
}

/*
 * Execute a shell command to handle special cases.
 */
static void
dospecial(cmd)
	char *cmd;
{
	int fd[2], status, pid, i;
	register char *cp, *s;
	char sbuf[RDIST_BUFSIZ];

	if (pipe(fd) < 0) {
		error("%s\n", strerror(errno));
		return;
	}
	if ((pid = fork()) == 0) {
		/*
		 * Return everything the shell commands print.
		 */
		(void) close(0);
		(void) close(1);
		(void) close(2);
		(void) open("/dev/null", 0);
		(void) dup(fd[1]);
		(void) dup(fd[1]);
		(void) close(fd[0]);
		(void) close(fd[1]);
		execl("/bin/sh", "sh", "-c", cmd, 0);
		_exit(127);
	}
	(void) close(fd[1]);
	s = sbuf;
	*s++ = '\0';
	while ((i = read(fd[0], buf, RDIST_BUFSIZ)) > 0) {
		cp = buf;
		do {
			*s++ = *cp++;
			if (cp[-1] != '\n') {
				if (s < &sbuf[RDIST_BUFSIZ - 1])
					continue;
				*s++ = '\n';
			}
			/*
			 * Throw away blank lines.
			 */
			if (s == &sbuf[2]) {
				s--;
				continue;
			}
			(void) write(wrem, sbuf, s - sbuf);
			s = &sbuf[1];
		} while (--i);
	}
	if (s > &sbuf[1]) {
		*s++ = '\n';
		(void) write(wrem, sbuf, s - sbuf);
	}
	while ((i = wait(&status)) != pid && i != -1)
		;
	if (i == -1)
		status = -1;
	(void) close(fd[0]);
	if (status)
		error("shell returned %d\n", status);
	else
		ack();
}

/*VARARGS2*/
void
log(fp, fmt, a1, a2, a3)
	FILE *fp;
	char *fmt;
	int a1, a2, a3;
{
	/* Print changes locally if not quiet mode */
	if (!qflag)
		printf(fmt, a1, a2, a3);

	/* Save changes (for mailing) if really updating files */
	if (!(options & VERIFY) && fp != NULL)
		fprintf(fp, fmt, a1, a2, a3);
}

/*VARARGS1*/
void
error(fmt, a1, a2, a3)
	char *fmt;
	int a1, a2, a3;
{
	static FILE *fp;

	nerrs++;
	if (!fp && !(fp = fdopen(rem, "w")))
		return;
	if (iamremote) {
		(void) fprintf(fp, "%crdist: ", 0x01);
		(void) fprintf(fp, fmt, a1, a2, a3);
		fflush(fp);
	} else {
		fflush(stdout);
		(void) fprintf(stderr, "rdist: ");
		(void) fprintf(stderr, fmt, a1, a2, a3);
		fflush(stderr);
	}
	if (lfp != NULL) {
		(void) fprintf(lfp, "rdist: ");
		(void) fprintf(lfp, fmt, a1, a2, a3);
		fflush(lfp);
	}
}

/*VARARGS1*/
void
fatal(fmt, a1, a2, a3)
	char *fmt;
	int a1, a2, a3;
{
	static FILE *fp;

	nerrs++;
	if (!fp && !(fp = fdopen(rem, "w")))
		return;
	if (iamremote) {
		(void) fprintf(fp, "%crdist: ", 0x02);
		(void) fprintf(fp, fmt, a1, a2, a3);
		fflush(fp);
	} else {
		fflush(stdout);
		(void) fprintf(stderr, "rdist: ");
		(void) fprintf(stderr, fmt, a1, a2, a3);
		fflush(stderr);
	}
	if (lfp != NULL) {
		(void) fprintf(lfp, "rdist: ");
		(void) fprintf(lfp, fmt, a1, a2, a3);
		fflush(lfp);
	}
	cleanup();
}

int
response()
{
	char *cp, *s;
	char resp[RDIST_BUFSIZ];

	if (debug)
		printf("response()\n");

	cp = s = resp;
more:
	do {
		if (desread(rem, cp, 1, 0) != 1)
			lostconn();
	} while (*cp++ != '\n' && cp < &resp[RDIST_BUFSIZ]);

	switch (*s++) {
	case '\0':
		*--cp = '\0';
		if (*s != '\0') {
			log(lfp, "%s\n", s);
			return (1);
		}
		return (0);
	case '\3':
		*--cp = '\0';
		log(lfp, "Note: %s\n", s);
		return (response());

	default:
		s--;
		/* FALLTHROUGH */
	case '\1':
	case '\2':
		nerrs++;
		if (*s != '\n') {
			if (!iamremote) {
				fflush(stdout);
				(void) write(2, s, cp - s);
			}
			if (lfp != NULL)
				(void) fwrite(s, 1, cp - s, lfp);
		}
		if (cp == &resp[RDIST_BUFSIZ] && *(cp - 1) != '\n') {
			/* preserve status code */
			cp = s;
			s = resp;
			goto more;
		}
		if (resp[0] == '\2')
			lostconn();
		return (-1);
	}
}

/*
 * Remove temporary files and do any cleanup operations before exiting.
 */
void
cleanup()
{
	(void) unlink(Tmpfile);
	exit(1);
}

static void
note(fmt, a1, a2, a3)
char *fmt;
int a1, a2, a3;
{
	static char buf[RDIST_BUFSIZ];
	(void) snprintf(buf, sizeof (buf) - 1, fmt, a1, a2, a3);
	comment(buf);
}

static void
comment(s)
char *s;
{
	char three = '\3';
	char nl = '\n';
	struct iovec iov[3];

	iov[0].iov_base = &three;
	iov[0].iov_len = sizeof (char);
	iov[1].iov_base = s;
	iov[1].iov_len = strlen(s);
	iov[2].iov_base = &nl;
	iov[2].iov_len = sizeof (char);
	(void) writev(rem, iov, 3);
}

/*
 * Send message to other end.
 * N.B.: uses buf[].
 */
void
sendrem(fmt, a1, a2, a3)
char *fmt;
int a1, a2, a3;
{
	register int len;

	buf[0] = '\0';
	len = snprintf(buf + 1, sizeof (buf) - 1, fmt, a1, a2, a3) + 2;
	if (len > sizeof (buf))
		len = sizeof (buf);
	buf[len - 1] = '\n';
	(void) write(wrem, buf, len);
}

/*
 * strsub(old, new, s)
 *
 * Return a pointer to a new string created by replacing substring old
 * with substring new in string s.  String s is assumed to begin with
 * substring old.
 */
char *
strsub(old, new, s)
	char *old, *new, *s;
{
	static char pbuf[PATH_MAX];
	register char *p, *q, *r, *plim;

	/* prepend new to pbuf */
	for (p = pbuf, q = new, plim = pbuf + sizeof (pbuf) - 1;
	/* CSTYLED */
	    *q && (p < plim);)
		*p++ = *q++;
	/* p now points to the byte in pbuf where more copying should begin */

	/* skip over the part of s which begins with old */
	for (r = old, q = s; *r; q++, r++)
		;
	/* q now points to the byte in s where more copying should begin */

	while (*q && (p < plim))
		*p++ = *q++;
	*p = '\0';

	return (pbuf);
}
