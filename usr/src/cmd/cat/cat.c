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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


/*
 *	Concatenate files.
 */

#include	<stdio.h>
#include	<stdlib.h>
#include	<ctype.h>
#include	<sys/types.h>
#include	<sys/stat.h>
#include	<locale.h>
#include	<unistd.h>
#include	<sys/mman.h>
#include	<errno.h>
#include	<string.h>

#include	<widec.h>
#include	<wctype.h>
#include	<limits.h>
#include	<libintl.h>
#define	IDENTICAL(A, B)	(A.st_dev == B.st_dev && A.st_ino == B.st_ino)

#define	MAXMAPSIZE	(8*1024*1024)	/* map at most 8MB */
#define	SMALLFILESIZE	(32*1024)	/* don't use mmap on little files */

static int vncat(FILE *);
static int cat(FILE *, struct stat *, struct stat *, char *);

static int	silent = 0;		/* s flag */
static int	visi_mode = 0;		/* v flag */
static int	visi_tab = 0;		/* t flag */
static int	visi_newline = 0;	/* e flag */
static int	bflg = 0;		/* b flag */
static int	nflg = 0;		/* n flag */
static long	ibsize;
static long	obsize;
static unsigned	char	buf[SMALLFILESIZE];


int
main(int argc, char **argv)
{
	FILE *fi;
	int c;
	extern	int optind;
	int	errflg = 0;
	int	stdinflg = 0;
	int	status = 0;
	int	estatus = 0;
	struct stat source, target;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"	/* Use this only if it weren't */
#endif
	(void) textdomain(TEXT_DOMAIN);

#ifdef STANDALONE
	/*
	 * If the first argument is NULL,
	 * discard arguments until we find cat.
	 */
	if (argv[0][0] == '\0')
		argc = getargv("cat", &argv, 0);
#endif

	/*
	 * Process the options for cat.
	 */

	while ((c = getopt(argc, argv, "usvtebn")) != EOF) {
		switch (c) {

		case 'u':

			/*
			 * If not standalone, set stdout to
			 * completely unbuffered I/O when
			 * the 'u' option is used.
			 */

#ifndef	STANDALONE
			setbuf(stdout, (char *)NULL);
#endif
			continue;

		case 's':

			/*
			 * The 's' option requests silent mode
			 * where no messages are written.
			 */

			silent++;
			continue;

		case 'v':

			/*
			 * The 'v' option requests that non-printing
			 * characters (with the exception of newlines,
			 * form-feeds, and tabs) be displayed visibly.
			 *
			 * Control characters are printed as "^x".
			 * DEL characters are printed as "^?".
			 * Non-printable  and non-contrlol characters with the
			 * 8th bit set are printed as "M-x".
			 */

			visi_mode++;
			continue;

		case 't':

			/*
			 * When in visi_mode, this option causes tabs
			 * to be displayed as "^I".
			 */

			visi_tab++;
			continue;

		case 'e':

			/*
			 * When in visi_mode, this option causes newlines
			 * and form-feeds to be displayed as "$" at the end
			 * of the line prior to the newline.
			 */

			visi_newline++;
			continue;

		case 'b':

			/*
			 * Precede each line output with its line number,
			 * but omit the line numbers from blank lines.
			 */

			bflg++;
			nflg++;
			continue;

		case 'n':

			/*
			 * Precede each line output with its line number.
			 */

			nflg++;
			continue;

		case '?':
			errflg++;
			break;
		}
		break;
	}

	if (errflg) {
		if (!silent)
			(void) fprintf(stderr,
			    gettext("usage: cat [ -usvtebn ] [-|file] ...\n"));
		exit(2);
	}

	/*
	 * Stat stdout to be sure it is defined.
	 */

	if (fstat(fileno(stdout), &target) < 0) {
		if (!silent)
			(void) fprintf(stderr,
			    gettext("cat: Cannot stat stdout\n"));
		exit(2);
	}
	obsize = target.st_blksize;

	/*
	 * If no arguments given, then use stdin for input.
	 */

	if (optind == argc) {
		argc++;
		stdinflg++;
	}

	/*
	 * Process each remaining argument,
	 * unless there is an error with stdout.
	 */


	for (argv = &argv[optind];
	    optind < argc && !ferror(stdout); optind++, argv++) {

		/*
		 * If the argument was '-' or there were no files
		 * specified, take the input from stdin.
		 */

		if (stdinflg ||
		    ((*argv)[0] == '-' && (*argv)[1] == '\0'))
			fi = stdin;
		else {
			/*
			 * Attempt to open each specified file.
			 */

			if ((fi = fopen(*argv, "r")) == NULL) {
				if (!silent)
					(void) fprintf(stderr, gettext(
					    "cat: cannot open %s: %s\n"),
					    *argv, strerror(errno));
				status = 2;
				continue;
			}
		}

		/*
		 * Stat source to make sure it is defined.
		 */

		if (fstat(fileno(fi), &source) < 0) {
			if (!silent)
				(void) fprintf(stderr,
				    gettext("cat: cannot stat %s: %s\n"),
				    (stdinflg) ? "-" : *argv, strerror(errno));
			status = 2;
			continue;
		}


		/*
		 * If the source is not a character special file, socket or a
		 * block special file, make sure it is not identical
		 * to the target.
		 */

		if (!S_ISCHR(target.st_mode) &&
		    !S_ISBLK(target.st_mode) &&
		    !S_ISSOCK(target.st_mode) &&
		    IDENTICAL(target, source)) {
			if (!silent)
			(void) fprintf(stderr,
			    gettext("cat: input/output files '%s' identical\n"),
			    stdinflg?"-": *argv);
			if (fclose(fi) != 0)
				(void) fprintf(stderr,
				    gettext("cat: close error: %s\n"),
				    strerror(errno));
			status = 2;
			continue;
		}
		ibsize = source.st_blksize;

		/*
		 * If in visible mode and/or nflg, use vncat;
		 * otherwise, use cat.
		 */

		if (visi_mode || nflg)
			estatus = vncat(fi);
		else
			estatus = cat(fi, &source, &target,
			    fi != stdin ? *argv : "standard input");

		if (estatus)
			status = estatus;

		/*
		 * If the input is not stdin, close the source file.
		 */

		if (fi != stdin) {
			if (fclose(fi) != 0)
				if (!silent)
					(void) fprintf(stderr,
					    gettext("cat: close error: %s\n"),
					    strerror(errno));
		}
	}

	/*
	 * Display any error with stdout operations.
	 */

	if (fclose(stdout) != 0) {
		if (!silent)
			perror(gettext("cat: close error"));
		status = 2;
	}
	return (status);
}



static int
cat(FILE *fi, struct stat *statp, struct stat *outp, char *filenm)
{
	int nitems;
	int nwritten;
	int offset;
	int fi_desc;
	long buffsize;
	char *bufferp;
	off_t mapsize, munmapsize;
	off_t filesize;
	off_t mapoffset;

	fi_desc = fileno(fi);
	if (S_ISREG(statp->st_mode) && (lseek(fi_desc, (off_t)0, SEEK_CUR)
	    == 0) && (statp->st_size > SMALLFILESIZE)) {
		mapsize = (off_t)MAXMAPSIZE;
		if (statp->st_size < mapsize)
			mapsize = statp->st_size;
		munmapsize = mapsize;

		/*
		 * Mmap time!
		 */
		bufferp = mmap((caddr_t)NULL, (size_t)mapsize, PROT_READ,
		    MAP_SHARED, fi_desc, (off_t)0);
		if (bufferp == (caddr_t)-1)
			mapsize = 0;	/* I guess we can't mmap today */
	} else
		mapsize = 0;		/* can't mmap non-regular files */

	if (mapsize != 0) {
		int	read_error = 0;
		char	x;

		/*
		 * NFS V2 will let root open a file it does not have permission
		 * to read. This read() is here to make sure that the access
		 * time on the input file will be updated. The VSC tests for
		 * cat do this:
		 *	cat file > /dev/null
		 * In this case the write()/mmap() pair will not read the file
		 * and the access time will not be updated.
		 */

		if (read(fi_desc, &x, 1) == -1)
			read_error = 1;
		mapoffset = 0;
		filesize = statp->st_size;
		for (;;) {
			/*
			 * Note that on some systems (V7), very large writes to
			 * a pipe return less than the requested size of the
			 * write.  In this case, multiple writes are required.
			 */
			offset = 0;
			nitems = (int)mapsize;
			do {
				if ((nwritten = write(fileno(stdout),
				    &bufferp[offset], (size_t)nitems)) < 0) {
					if (!silent) {
						if (read_error == 1)
							(void) fprintf(
							    stderr, gettext(
							    "cat: cannot read "
							    "%s: "), filenm);
						else
							(void) fprintf(stderr,
							    gettext(
							    "cat: write "
							    "error: "));
						perror("");
					}
					(void) munmap(bufferp,
					    (size_t)munmapsize);
					(void) lseek(fi_desc, (off_t)mapoffset,
					    SEEK_SET);
					return (2);
				}
				offset += nwritten;
			} while ((nitems -= nwritten) > 0);

			filesize -= mapsize;
			mapoffset += mapsize;
			if (filesize == 0)
				break;
			if (filesize < mapsize)
				mapsize = filesize;
			if (mmap(bufferp, (size_t)mapsize, PROT_READ,
			    MAP_SHARED|MAP_FIXED, fi_desc,
			    mapoffset) == (caddr_t)-1) {
				if (!silent)
					perror(gettext("cat: mmap error"));
				(void) munmap(bufferp, (size_t)munmapsize);
				(void) lseek(fi_desc, (off_t)mapoffset,
				    SEEK_SET);
				return (1);
			}
		}
		/*
		 * Move the file pointer past what we read. Shell scripts
		 * rely on cat to do this, so that successive commands in
		 * the script won't re-read the same data.
		 */
		(void) lseek(fi_desc, (off_t)mapoffset, SEEK_SET);
		(void) munmap(bufferp, (size_t)munmapsize);
	} else {
		if (S_ISREG(statp->st_mode) && S_ISREG(outp->st_mode)) {
			bufferp = (char *)buf;
			buffsize = SMALLFILESIZE;
		} else {
			if (obsize)
				/*
				 * common case, use output blksize
				 */
				buffsize = obsize;
			else if (ibsize)
				buffsize = ibsize;
			else
				buffsize = (long)BUFSIZ;

			if (buffsize <= SMALLFILESIZE) {
				bufferp = (char *)buf;
			} else if ((bufferp =
			    malloc((size_t)buffsize)) == NULL) {
				perror(gettext("cat: no memory"));
				return (1);
			}
		}

		/*
		 * While not end of file, copy blocks to stdout.
		 */
		while ((nitems = read(fi_desc, bufferp, (size_t)buffsize)) >
		    0) {
			offset = 0;
			/*
			 * Note that on some systems (V7), very large writes
			 * to a pipe return less than the requested size of
			 * the write.  In this case, multiple writes are
			 * required.
			 */
			do {
				nwritten = write(1, bufferp+offset,
				    (size_t)nitems);
				if (nwritten < 0) {
					if (!silent) {
						if (nwritten == -1)
							nwritten = 0l;
						(void) fprintf(stderr, gettext(\
"cat: output error (%d/%d characters written)\n"), nwritten, nitems);
						perror("");
					}
					if (bufferp != (char *)buf)
						free(bufferp);
					return (2);
				}
				offset += nwritten;
			} while ((nitems -= nwritten) > 0);
		}
		if (bufferp != (char *)buf)
			free(bufferp);
		if (nitems < 0) {
			(void) fprintf(stderr,
			    gettext("cat: input error on %s: "), filenm);
			perror("");
			return (1);
		}
	}

	return (0);
}

static int
vncat(fi)
	FILE *fi;
{
	int c;
	int	lno;
	int	boln;	/* = 1 if at beginning of line */
			/* = 0 otherwise */
	wchar_t	wc;
	int	len, n;
	unsigned char	*p1, *p2;

	lno = 1;
	boln = 1;
	p1 = p2 = buf;
	for (;;) {
		if (p1 >= p2) {
			p1 = buf;
			if ((len = fread(p1, 1, BUFSIZ, fi)) <= 0)
				break;
			p2 = p1 + len;
		}
		c = *p1++;

		/*
		 * Display newlines as "$<newline>"
		 * if visi_newline set
		 */
		if (c == '\n') {
			if (nflg && boln && !bflg)
				(void) printf("%6d\t", lno++);
			boln = 1;

			if (visi_mode && visi_newline)
				(void) putchar('$');
			(void) putchar(c);
			continue;
		}

		if (nflg && boln)
			(void) printf("%6d\t", lno++);
		boln = 0;

		/*
		 * For non-printable and non-cntrl chars,
		 * use the "M-x" notation.
		 */

		if (isascii(c)) {
			if (isprint(c) || visi_mode == 0) {
				(void) putchar(c);
				continue;
			}

			/*
			 * For non-printable ascii characters.
			 */

			if (iscntrl(c)) {
				/* For cntrl characters. */
				if ((c == '\t') || (c == '\f')) {
					/*
					 * Display tab as "^I" if visi_tab set
					 */
					if (visi_mode && visi_tab) {
						(void) putchar('^');
						(void) putchar(c^0100);
					} else
						(void) putchar(c);
					continue;
				}
				(void) putchar('^');
				(void) putchar(c^0100);
				continue;
			}
			continue;
		}

		/*
		 * For non-ascii characters.
		 */
		p1--;
		if ((len = (p2 - p1)) < MB_LEN_MAX) {
			for (n = 0; n < len; n++)
				buf[n] = *p1++;
			p1 = buf;
			p2 = p1 + n;
			if ((len = fread(p2, 1, BUFSIZ - n, fi)) > 0)
				p2 += len;
		}

		if ((len = (p2 - p1)) > MB_LEN_MAX)
			len = MB_LEN_MAX;

		if ((len = mbtowc(&wc, (char *)p1, len)) > 0) {
			if (iswprint(wc) || visi_mode == 0) {
				(void) putwchar(wc);
				p1 += len;
				continue;
			}
		}

		(void) putchar('M');
		(void) putchar('-');
		c -= 0200;

		if (isprint(c)) {
			(void) putchar(c);
		}

		/* For non-printable characters. */
		if (iscntrl(c)) {
			/* For cntrl characters. */
			if ((c == '\t') || (c == '\f')) {
				/*
				 * Display tab as "^I" if visi_tab set
				 */
				if (visi_mode && visi_tab) {
					(void) putchar('^');
					(void) putchar(c^0100);
				} else
					(void) putchar(c);
			} else {
				(void) putchar('^');
				(void) putchar(c^0100);
			}
		}
		p1++;
	}
	return (0);
}
