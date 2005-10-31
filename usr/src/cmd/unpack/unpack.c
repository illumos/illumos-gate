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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.21	*/

/*
 *	Huffman decompressor
 *	Usage:	pcat filename...
 *	or	unpack filename...
 */

#include <stdio.h>
#include <fcntl.h>
#include <setjmp.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <locale.h>
#include <utime.h>
#include <stdlib.h>
#include <limits.h>
#include <sys/param.h>
#include <dirent.h>
#include <sys/acl.h>
#include <aclutils.h>

static struct utimbuf u_times;

static jmp_buf env;
static struct	stat status;
static char	*argv0, *argvk;

/* rmflg, when set it's ok to rm arvk file on caught signals */
static int	rmflg = 0;

#define	SUF0	'.'
#define	SUF1	'z'
#define	US	037
#define	RS	036

/* variables associated with i/o */
static char	filename[MAXPATHLEN];

static short	infile;
static short	outfile;
static short	inleft;
static short 	is_eof = 0;
static char	*inp;
static char	*outp;
static char	inbuff[BUFSIZ];
static char	outbuff[BUFSIZ];

/* the dictionary */
static long	origsize;
static short	maxlev;
static short	intnodes[25];
static char	*tree[25];
static char	characters[256];
static char	*eof;

static void putch(char c);
static int expand();
static int decode();
static int getwdsize();
static int getch();
static int getdict();
static int mv_xattrs();

/* read in the dictionary portion and build decoding structures */
/* return 1 if successful, 0 otherwise */
int
getdict()
{
	register int c, i, nchildren;

	/*
	 * check two-byte header
	 * get size of original file,
	 * get number of levels in maxlev,
	 * get number of leaves on level i in intnodes[i],
	 * set tree[i] to point to leaves for level i
	 */
	eof = &characters[0];

	inbuff[6] = 25;
	inleft = read(infile, &inbuff[0], BUFSIZ);
	if (inleft < 0) {
		(void) fprintf(stderr, gettext(
			"%s: %s: read error: "), argv0, filename);
		perror("");
		return (0);
	}
	if (inbuff[0] != US)
		goto goof;

	if (inbuff[1] == US) {		/* oldstyle packing */
		if (setjmp(env))
			return (0);
		return (expand());
	}
	if (inbuff[1] != RS)
		goto goof;

	inp = &inbuff[2];
	origsize = 0;
	for (i = 0; i < 4; i++)
		origsize = origsize*256 + ((*inp++) & 0377);
	maxlev = *inp++ & 0377;
	if (maxlev > 24) {
goof:		(void) fprintf(stderr, gettext(
			"%s: %s: not in packed format\n"), argv0, filename);
		return (0);
	}
	for (i = 1; i <= maxlev; i++)
		intnodes[i] = *inp++ & 0377;
	for (i = 1; i <= maxlev; i++) {
		tree[i] = eof;
		for (c = intnodes[i]; c > 0; c--) {
			if (eof >= &characters[255])
				goto goof;
			*eof++ = *inp++;
		}
	}
	*eof++ = *inp++;
	intnodes[maxlev] += 2;
	inleft -= inp - &inbuff[0];
	if (inleft < 0)
		goto goof;

	/*
	 * convert intnodes[i] to be number of
	 * internal nodes possessed by level i
	 */

	nchildren = 0;
	for (i = maxlev; i >= 1; i--) {
		c = intnodes[i];
		intnodes[i] = nchildren /= 2;
		nchildren += c;
	}
	return (decode());
}

/* unpack the file */
/* return 1 if successful, 0 otherwise */
int
decode()
{
	register int bitsleft, c, i;
	int j, lev, cont = 1;
	char *p;

	outp = &outbuff[0];
	lev = 1;
	i = 0;
	while (cont) {
		if (inleft <= 0) {
			inleft = read(infile, inp = &inbuff[0], BUFSIZ);
			if (inleft < 0) {
				(void) fprintf(stderr, gettext(
					"%s: %s: read error: "),
					argv0, filename);
				perror("");
				return (0);
			}
		}
		if (--inleft < 0) {
uggh:			(void) fprintf(stderr, gettext(
				"%s: %s: unpacking error\n"),
				argv0, filename);
			return (0);
		}
		c = *inp++;
		bitsleft = 8;
		while (--bitsleft >= 0) {
			i *= 2;
			if (c & 0200)
				i++;
			c <<= 1;
			if ((j = i - intnodes[lev]) >= 0) {
				p = &tree[lev][j];
				if (p == eof) {
					c = outp - &outbuff[0];
				    if (write(outfile, &outbuff[0], c) != c) {
wrerr:						(void) fprintf(stderr, gettext(
						"%s: %s: write error: "),
							argv0, argvk);
						perror("");
						return (0);
					}
					origsize -= c;
					if (origsize != 0)
						goto uggh;
					return (1);
				}
				*outp++ = *p;
				if (outp == &outbuff[BUFSIZ]) {
					if (write(outfile, outp = &outbuff[0],
						    BUFSIZ) != BUFSIZ)
						goto wrerr;
					origsize -= BUFSIZ;
				}
				lev = 1;
				i = 0;
			} else
				lev++;
		}
	}
	return (1);	/* we won't get here , but lint is pleased */
}

int
main(int argc, char *argv[])
{
	extern int optind;
	int i, k;
	int error;
	int sep, errflg = 0, pcat = 0;
	register char *p1, *cp;
	int fcount = 0;		/* failure count */
	int max_name;
	void onsig(int);
	acl_t *aclp;


	if (signal(SIGHUP, SIG_IGN) != SIG_IGN)
#ifdef __STDC__
		signal((int)SIGHUP, onsig);
#else
		signal((int)SIGHUP, onsig);
#endif
	if (signal(SIGINT, SIG_IGN) != SIG_IGN)
#ifdef __STDC__
		signal((int)SIGINT, onsig);
#else
		signal((int)SIGINT, onsig);
#endif
	if (signal(SIGTERM, SIG_IGN) != SIG_IGN)
#ifdef __STDC__
		signal((int)SIGTERM, onsig);
#else
		signal(SIGTERM, onsig);
#endif

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	p1 = *argv;
	while (*p1++);	/* Point p1 to end of argv[0] string */
	while (--p1 >= *argv)
		if (*p1 == '/')break;
	*argv = p1 + 1;
	argv0 = argv[0];
	if (**argv == 'p')pcat++;	/* User entered pcat (or /xx/xx/pcat) */

	while (getopt(argc, argv, "") != EOF)
		++errflg;
	/*
	 * Check for invalid option.  Also check for missing
	 * file operand, ie: "unpack" or "pcat".
	 */
	argc -= optind;
	argv = &argv[optind];
	if (errflg || argc < 1) {
		(void) fprintf(stderr, gettext("usage: %s file...\n"), argv0);
		if (argc < 1) {
			/*
			 * return 1 for usage error when no file was specified
			 */
			return (1);
		}
	}
	/* loop through the file names */
	for (k = 0; k < argc; k++) {
		fcount++;	/* expect the worst */
		if (errflg) {
			/*
			 * invalid option; just count the number of files not
			 * unpacked
			 */
			continue;
		}
		/* remove any .z suffix the user may have added */
		for (cp = argv[k]; *cp != '\0'; ++cp)
			;
		if (cp[-1] == SUF1 && cp[-2] == SUF0) {
			*cp-- = '\0'; *cp-- = '\0'; *cp = '\0';
		}
		sep = -1;
		cp = filename;
		argvk = argv[k];
		/* copy argv[k] to filename and count chars in base name */
		for (i = 0; i < (MAXPATHLEN-3) && (*cp = argvk[i]); i++)
			if (*cp++ == '/')
				sep = i;
		/* add .z suffix to filename */
		*cp++ = SUF0;
		*cp++ = SUF1;
		*cp = '\0';
		if ((infile = open(filename, O_RDONLY)) == -1) {
			(void) fprintf(stderr, gettext(
				"%s: %s: cannot open: "),
				argv0, filename);
			perror("");
			goto done;
		}
		if (pcat)
			outfile = 1;	/* standard output */
		else {

			error = facl_get(infile, ACL_NO_TRIVIAL, &aclp);
			if (error != 0) {
				(void) printf(gettext(
				    "%s: %s: cannot retrieve ACL : %s\n"),
				argv0, filename, acl_strerror(error));
			}

			max_name = pathconf(filename, _PC_NAME_MAX);
			if (max_name == -1) {
				/* no limit on length of filename */
				max_name = _POSIX_NAME_MAX;
			}
			if (i >= (MAXPATHLEN-1) || (i - sep - 1) > max_name) {
				(void) fprintf(stderr, gettext(
					"%s: %s: file name too long\n"),
					argv0, argvk);
				goto done;
			}
			if (stat(argvk, &status) != -1) {
				(void) fprintf(stderr, gettext(
					"%s: %s: already exists\n"),
					argv0, argvk);
				goto done;
			}
			(void) fstat(infile, &status);
			if (status.st_nlink != 1) {
				(void) printf(gettext(
					"%s: %s: Warning: file has links\n"),
					argv0, filename);
			}
			if ((outfile = creat(argvk, status.st_mode)) == -1) {
				(void) fprintf(stderr, gettext(
					"%s: %s: cannot create: "),
					argv0, argvk);
				perror("");
				goto done;
			}
			rmflg = 1;
		}

		if (getdict() &&	/* unpack */
		    (pcat ||
			(pathconf(filename, _PC_XATTR_EXISTS) != 1) ||
				(mv_xattrs(infile, outfile,
					filename, 0) == 0))) {
			if (!pcat) {
				/*
				 * preserve acc & mod dates
				 */
				u_times.actime = status.st_atime;
				u_times.modtime = status.st_mtime;
				if (utime(argvk, &u_times) != 0) {
					errflg++;
					(void) fprintf(stderr, gettext(
					"%s: cannot change times on %s: "),
						argv0, argvk);
					perror("");
				}
				if (chmod(argvk, status.st_mode) != 0) {
					errflg++;
					(void) fprintf(stderr, gettext(
					"%s: cannot change mode to %o on %s: "),
					    argv0, (uint_t)status.st_mode,
					    argvk);
					perror("");
				}
				(void) chown(argvk,
						status.st_uid, status.st_gid);
				if (aclp && (facl_set(outfile, aclp) < 0)) {
					(void) printf(gettext("%s: cannot "
					    "set ACL on %s: "), argv0, argvk);
					perror("");
				}

				rmflg = 0;
				(void) printf(gettext("%s: %s: unpacked\n"),
					argv0, argvk);
				(void) unlink(filename);

			}
			if (!errflg)
				fcount--; 	/* success after all */
		}
		else
			if (!pcat) {
				if (pathconf(argvk, _PC_XATTR_EXISTS) == 1) {
					(void) mv_xattrs(outfile, infile,
						argvk, 1);
				}
				(void) unlink(argvk);
			}
done:		(void) close(infile);
		if (!pcat)
			(void) close(outfile);

		if (aclp)
			acl_free(aclp);
	}
	return (fcount);
}

/*
 * This code is for unpacking files that
 * were packed using the previous algorithm.
 */

static int	Tree[1024];

/* return 1 if successful, 0 otherwise */

int
expand()
{
	int tp, bit;
	short word;
	int keysize, i, *t;

	outp = outbuff;
	inp = &inbuff[2];
	inleft -= 2;

	origsize = ((long)(unsigned)getwdsize())*256*256;
	origsize += (unsigned)getwdsize();
	if (origsize == 0 || is_eof) {
		(void) fprintf(stderr, gettext(
			"%s: %s: not in packed format\n"),
			argv0, filename);
		return (0);
	}
	t = Tree;
	for (keysize = getwdsize(); keysize--; ) {
		if ((i = getch()) == 0377)
			*t++ = getwdsize();
		else {
				/*
				 * reached EOF unexpectedly
				 */
			if (is_eof) {
				(void) fprintf(stderr, gettext(
					"%s: %s: not in packed format\n"),
					argv0, filename);
				return (0);
			}
			*t++ = i & 0377;
		}
	}
		/*
		 * reached EOF unexpectedly
		 */
	if (is_eof) {
		(void) fprintf(stderr, gettext(
			"%s: %s: not in packed format\n"),
			argv0, filename);
		return (0);
	}


	bit = tp = 0;
	for (;;) {
		if (bit <= 0) {
			word = getwdsize();
			/*
			 * reached EOF unexpectedly
			 */
			if (word == 0 && is_eof && origsize > 0) {
				(void) fprintf(stderr, gettext(
					"%s: %s: not in packed format\n"),
					argv0, filename);
				return (0);
			}
			bit = 16;
		}
		tp += Tree[tp + (word < 0)];
		word <<= 1;
		bit--;
		if (Tree[tp] == 0) {
			putch(Tree[tp+1]);
			tp = 0;
			if ((origsize -= 1) == 0) {
				(void) write(outfile, outbuff, outp - outbuff);
				return (1);
			}
		}
	}
}

int
getch()
{
	if (inleft <= 0) {
		inleft = read(infile, inp = inbuff, BUFSIZ);
		if (inleft < 0) {
			(void) fprintf(stderr, gettext(
				"%s: %s: read error: "),
				argv0, filename);
			perror("");
			longjmp(env, 1);
		} else {		/* reached EOF, report it */
			if (inleft == 0) {
				is_eof = 1;
				return (EOF);
			}
		}
	}
	inleft--;
	return (*inp++ & 0377);
}

int
getwdsize()
{
	char c;
	int d;

	c = getch();
	d = getch();
	if (is_eof)
		return (0);
	d <<= 8;
	d |= c & 0377;
	return (d);
}

void
onsig(int sig)
{
				/* could be running as unpack or pcat	*/
				/* but rmflg is set only when running	*/
				/* as unpack and only when file is	*/
				/* created by unpack and not yet done	*/
	if (rmflg == 1)
		(void) unlink(argvk);
	exit(1);
}

void
putch(char c)
{
	int n;

	*outp++ = c;
	if (outp == &outbuff[BUFSIZ]) {
		n = write(outfile, outp = outbuff, BUFSIZ);
		if (n < BUFSIZ) {
			(void) fprintf(stderr, gettext(
				"%s: %s: write error: "),
				argv0, argvk);
			perror("");
			longjmp(env, 2);
		}
	}
}

/*
 * mv_xattrs - move (via renameat) all of the extended attributes
 *	associated with the file referenced by infd to the file
 *	referenced by outfd.  The infile and silent arguments are
 *	provided for error message processing.  This function
 *	returns 0 on success and -1 on error.
 */
static int
mv_xattrs(int infd, int outfd, char *infile, int silent)
{
	int indfd, outdfd, tmpfd;
	DIR *dirp = NULL;
	struct dirent *dp = NULL;
	int error = 0;
	char *etext;

	indfd = outdfd = tmpfd = -1;

	if ((indfd = openat(infd, ".", O_RDONLY|O_XATTR)) == -1) {
		etext = gettext("cannot open source");
		error = -1;
		goto out;
	}

	if ((outdfd = openat(outfd, ".", O_RDONLY|O_XATTR)) == -1) {
		etext = gettext("cannot open target");
		error = -1;
		goto out;
	}

	if ((tmpfd = dup(indfd)) == -1) {
		etext = gettext("cannot dup descriptor");
		error = -1;
		goto out;

	}
	if ((dirp = fdopendir(tmpfd)) == NULL) {
		etext = gettext("cannot access source");
		error = -1;
		goto out;
	}

	while (dp = readdir(dirp)) {
		if ((dp->d_name[0] == '.' && dp->d_name[1] == '\0') ||
		    (dp->d_name[0] == '.' && dp->d_name[1] == '.' &&
		    dp->d_name[2] == '\0'))
			continue;
		if ((renameat(indfd, dp->d_name, outdfd, dp->d_name)) == -1) {
			etext = dp->d_name;
			error = -1;
			goto out;
		}
	}
out:
	if (error == -1 && silent == 0) {
		fprintf(stderr, gettext(
			"unpack: %s: cannot move extended attributes, "),
			infile);
		perror(etext);
	}
	if (dirp)
		closedir(dirp);
	if (indfd != -1)
		close(indfd);
	if (outdfd != -1)
		close(outdfd);
	return (error);
}
