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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *	Huffman encoding program
 *	Usage:	pack [[ -f ] [ - ] [-/] filename ... ] filename ...
 *		- option: enable/disable listing of statistics
 */

#include <locale.h>
#include <stdarg.h>
#include <sys/isa_defs.h>
#include <sys/param.h>
#include <utime.h>
#include <sys/acl.h>
#include <aclutils.h>
#include <libcmdutils.h>

#undef lint

#define	END	256
#define	PACKED 017436 /* <US><RS> - Unlikely value */
#define	SUF0	'.'
#define	SUF1	'z'

struct stat status, ostatus;
static struct utimbuf u_times;

/* union for overlaying a long int with a set of four characters */
union FOUR {
	struct { long int lng; } lint;
	struct { char c0, c1, c2, c3; } chars;
};

/* character counters */
long	count [END+1];
union	FOUR insize;
long	outsize;
long	dictsize;
int	diffbytes;

/* i/o stuff */
char	vflag = 0;
int	force = 0;	/* allow forced packing for consistency in directory */

static	char filename [MAXPATHLEN];
static int max_name;

int	infile;		/* unpacked file */
int	outfile;	/* packed file */
char	inbuff [BUFSIZ];
char	outbuff [BUFSIZ+4];

/* variables associated with the tree */
int	maxlev;
int	levcount [25];
int	lastnode;
int	parent [2*END+1];

/* variables associated with the encoding process */
char	length [END+1];
long	bits [END+1];
union	FOUR mask;
long	inc;
#if defined(_LITTLE_ENDIAN)
char	*maskshuff[4]  = {&(mask.chars.c3),
			    &(mask.chars.c2),
			    &(mask.chars.c1),
			    &(mask.chars.c0)};
#elif defined(_BIG_ENDIAN)
char	*maskshuff[4]  = {&(mask.chars.c0),
			    &(mask.chars.c1),
			    &(mask.chars.c2),
			    &(mask.chars.c3)};
#else
#error Unknown byte ordering!
#endif

/* the heap */
int	n;
struct	heap {
	long int count;
	int node;
} heap [END+2];
#define	hmove(a, b) {(b).count = (a).count; (b).node = (a).node; }

static void heapify(int i);

/* Extended system attribute support */

static int saflg = 0;


/* gather character frequency statistics */
/* return 1 if successful, 0 otherwise */
int
input(char *source)
{
	register int i;
	for (i = 0; i < END; i++)
		count[i] = 0;
	while ((i = read(infile, inbuff, BUFSIZ)) > 0)
		while (i > 0)
			count[inbuff[--i]&0377] += 2;
	if (i == 0)
		return (1);
	(void) fprintf(stderr, gettext(
	    "pack: %s: read error - file unchanged: "), source);
	perror("");
	return (0);
}

/* encode the current file */
/* return 1 if successful, 0 otherwise */
int
output(char *source)
{
	int c, i, inleft;
	char *inp;
	register char **q, *outp;
	register int bitsleft;
	long temp;

	/* output ``PACKED'' header */
	outbuff[0] = 037; 	/* ascii US */
	outbuff[1] = 036; 	/* ascii RS */
	/* output the length and the dictionary */
	temp = insize.lint.lng;
	for (i = 5; i >= 2; i--) {
		outbuff[i] =  (char)(temp & 0377);
		temp >>= 8;
	}
	outp = &outbuff[6];
	*outp++ = maxlev;
	for (i = 1; i < maxlev; i++)
		*outp++ = levcount[i];
	*outp++ = levcount[maxlev]-2;
	for (i = 1; i <= maxlev; i++)
		for (c = 0; c < END; c++)
			if (length[c] == i)
				*outp++ = c;
	dictsize = outp-&outbuff[0];

	/* output the text */
	(void) lseek(infile, 0L, 0);
	outsize = 0;
	bitsleft = 8;
	inleft = 0;
	do {
		if (inleft <= 0) {
			inleft = read(infile, inp = &inbuff[0], BUFSIZ);
			if (inleft < 0) {
				(void) fprintf(stderr, gettext(
				    "pack: %s: read error - file unchanged: "),
				    source);
				perror("");
				return (0);
			}
		}
		c = (--inleft < 0) ? END : (*inp++ & 0377);
		mask.lint.lng = bits[c]<<bitsleft;
		q = &maskshuff[0];
		if (bitsleft == 8)
			*outp = **q++;
		else
			*outp |= **q++;
		bitsleft -= length[c];
		while (bitsleft < 0) {
			*++outp = **q++;
			bitsleft += 8;
		}
		if (outp >= &outbuff[BUFSIZ]) {
			if (write(outfile, outbuff, BUFSIZ) != BUFSIZ) {
wrerr:				(void) fprintf(stderr, gettext(
				    "pack: %s.z: write error - "
				    "file unchanged: "), source);
				perror("");
				return (0);
			}
			((union FOUR *)outbuff)->lint.lng =
			    ((union FOUR *)&outbuff[BUFSIZ])->lint.lng;
			outp -= BUFSIZ;
			outsize += BUFSIZ;
		}
	} while (c != END);
	if (bitsleft < 8)
		outp++;
	c = outp-outbuff;
	if (write(outfile, outbuff, c) != c)
		goto wrerr;
	outsize += c;
	return (1);
}

/* makes a heap out of heap[i],...,heap[n] */
void
heapify(int i)
{
	register int k;
	int lastparent;
	struct heap heapsubi;
	hmove(heap[i], heapsubi);
	lastparent = n/2;
	while (i <= lastparent) {
		k = 2*i;
		if (heap[k].count > heap[k+1].count && k < n)
			k++;
		if (heapsubi.count < heap[k].count)
			break;
		hmove(heap[k], heap[i]);
		i = k;
	}
	hmove(heapsubi, heap[i]);
}

/* return 1 after successful packing, 0 otherwise */
int
packfile(char *source)
{
	register int c, i, p;
	long bitsout;

	/* gather frequency statistics */
	if (input(source) == 0)
		return (0);

	/* put occurring chars in heap with their counts */
	diffbytes = -1;
	count[END] = 1;
	insize.lint.lng = n = 0;
	for (i = END; i >= 0; i--) {
		parent[i] = 0;
		if (count[i] > 0) {
			diffbytes++;
			insize.lint.lng += count[i];
			heap[++n].count = count[i];
			heap[n].node = i;
		}
	}
	if (diffbytes == 1) {
		(void) fprintf(stderr, gettext(
		    "pack: %s: trivial file - file unchanged\n"), source);
		return (0);
	}
	insize.lint.lng >>= 1;
	for (i = n/2; i >= 1; i--)
		heapify(i);

	/* build Huffman tree */
	lastnode = END;
	while (n > 1) {
		parent[heap[1].node] = ++lastnode;
		inc = heap[1].count;
		hmove(heap[n], heap[1]);
		n--;
		heapify(1);
		parent[heap[1].node] = lastnode;
		heap[1].node = lastnode;
		heap[1].count += inc;
		heapify(1);
	}
	parent[lastnode] = 0;

	/* assign lengths to encoding for each character */
	bitsout = maxlev = 0;
	for (i = 1; i <= 24; i++)
		levcount[i] = 0;
	for (i = 0; i <= END; i++) {
		c = 0;
		for (p = parent[i]; p != 0; p = parent[p])
			c++;
		levcount[c]++;
		length[i] = c;
		if (c > maxlev)
			maxlev = c;
		bitsout += c*(count[i]>>1);
	}
	if (maxlev > 24) {
		/* can't occur unless insize.lint.lng >= 2**24 */
		(void) fprintf(stderr, gettext(
		    "pack: %s: Huffman tree has too many levels - "
		    "file unchanged\n"), source);
		return (0);
	}

	/* don't bother if no compression results */
	outsize = ((bitsout+7)>>3)+6+maxlev+diffbytes;
	if ((insize.lint.lng+BUFSIZ-1)/BUFSIZ <=
	    (outsize+BUFSIZ-1)/BUFSIZ && !force) {
		(void) printf(gettext(
		    "pack: %s: no saving - file unchanged\n"), source);
		return (0);
	}

	/* compute bit patterns for each character */
	inc = 1L << 24;
	inc >>= maxlev;
	mask.lint.lng = 0;
	for (i = maxlev; i > 0; i--) {
		for (c = 0; c <= END; c++)
			if (length[c] == i) {
				bits[c] = mask.lint.lng;
				mask.lint.lng += inc;
			}
		mask.lint.lng &= ~inc;
		inc <<= 1;
	}

	return (output(source));
}

int
main(int argc, char *argv[])
{
	extern  int optind;
	register int i;
	register char *cp;
	int k, sep, errflg = 0;
	int c;
	int error;
	int fcount = 0; /* count failures */
	acl_t *aclp = NULL;
	char *progname;
	int sattr_exist = 0;
	int xattr_exist = 0;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"	/* Use this only if it weren't */
#endif
	(void) textdomain(TEXT_DOMAIN);

	if (progname = strrchr(argv[0], '/'))
		++progname;
	else
		progname = argv[0];

	while ((c = getopt(argc, argv, "f-/")) != EOF) {
		if (c == 'f')
			force++;
		else if (c == '/')
			saflg++;
		else
			++errflg;
	}
	/*
	 * Check for invalid option.  Also check for missing
	 * file operand, ie: "pack" or "pack -".
	 */
	argc -= optind;
	argv = &argv[optind];
	if (errflg || argc < 1 ||
	    (argc == 1 && (argv[0][0] == '-' || argv[0][0] == '/' &&
	    argv[0][1] == '\0'))) {
		(void) fprintf(stderr, gettext(
		    "usage: pack [-f] [-] [-/] file...\n"));
		if (argc < 1 ||
		    (argc == 1 && (argv[0][0] == '-' || argv[0][0] == '/') &&
		    argv[0][1] == '\0')) {
			/*
			 * return 1 for usage error when no file was specified
			 */
			return (1);
		}
	}

	/* loop through the file names */
	for (k = 0; k < argc; k++) {
		if (argv[k][0] == '-' && argv[k][1] == '\0') {
			vflag = 1 - vflag;
			continue;
		}
		fcount++; /* increase failure count - expect the worst */
		if (errflg) {
			/*
			 * invalid option; just count the number of files not
			 * packed
			 */
			continue;
		}
		/* remove any .z suffix the user may have added */
		for (cp = argv[k]; *cp != '\0'; ++cp)
			;
		if (cp[-1] == SUF1 && cp[-2] == SUF0) {
			*cp-- = '\0'; *cp-- = '\0'; *cp = '\0';
		}
		sep = -1;  cp = filename;
		max_name = pathconf(argv[k], _PC_NAME_MAX);
		if (max_name == -1) {
			/* pathname invalid or no limit on length of filename */
			max_name = _POSIX_NAME_MAX;
		}
		/* copy argv[k] to filename and count chars in base name */
		for (i = 0; i < (MAXPATHLEN-3) && (*cp = argv[k][i]); i++)
			if (*cp++ == '/') sep = i;
		if ((infile = open(filename, 0)) < 0) {
			(void) fprintf(stderr, gettext(
			    "pack: %s: cannot open: "), filename);
			perror("");
			continue;
		}
		if (i >= (MAXPATHLEN-3) || (i-sep) > (max_name - 1)) {
			(void) fprintf(stderr, gettext(
			    "pack: %s: file name too long\n"), argv[k]);
			continue;
		}
		(void) fstat(infile, &status);
		if (S_ISDIR(status.st_mode)) {
			(void) fprintf(stderr, gettext(
			    "pack: %s: cannot pack a directory\n"),
			    argv[k]);
			goto closein;
		}
		if (status.st_size == 0) {
			(void) fprintf(stderr, gettext(
			    "pack: %s: cannot pack a zero length file\n"),
			    argv[k]);
			goto closein;
		}
		if (status.st_nlink != 1) {
			(void) fprintf(stderr, gettext(
			    "pack: %s: has links\n"),
			    argv[k]);
			goto closein;
		}
		*cp++ = SUF0;  *cp++ = SUF1;  *cp = '\0';
		if (stat(filename, &ostatus) != -1) {
			(void) fprintf(stderr, gettext(
			    "pack: %s: already exists\n"), filename);
			goto closein;
		}
		if ((outfile = creat(filename, status.st_mode | O_RDONLY))
		    < 0) {
			(void) fprintf(stderr, gettext(
			    "pack: %s: cannot create: "), filename);
			perror("");
			goto closein;
		}

		error = facl_get(infile, ACL_NO_TRIVIAL, &aclp);

		if (error != 0) {
			(void) fprintf(stderr, gettext(
			    "pack: %s: cannot retrieve ACL: %s\n"), argv[k],
			    acl_strerror(error));
		}

		if (packfile(argv[k])) {
			if (pathconf(argv[k], _PC_XATTR_EXISTS) == 1)
				xattr_exist = 1;
			if (saflg && sysattr_support(argv[k],
			    _PC_SATTR_EXISTS) == 1)
				sattr_exist = 1;
			if (sattr_exist || xattr_exist) {
				if (mv_xattrs(progname, argv[k], filename,
				    sattr_exist, 0) != 0) {
				/* Move attributes back ... */
					xattr_exist = 0;
					sattr_exist = 0;
					if (pathconf(filename,
					    _PC_XATTR_EXISTS) == 1)
						xattr_exist = 1;
					if (saflg && sysattr_support(filename,
					    _PC_SATTR_EXISTS) == 1)
						sattr_exist = 1;
					if (xattr_exist || sattr_exist) {
						(void) mv_xattrs(progname,
						    filename, argv[k],
						    sattr_exist, 1);
						(void) unlink(filename);
						goto out;
					}
				} else {
					errno = 0;
					if (unlink(argv[k]) != 0) {
						(void) fprintf(stderr, gettext(
						    "pack: %s :cannot unlink:"),
						    argv[k]);
						if (errno == EPERM)
							perror("No permission");
						else
							perror("");
					}
				}
			} else {
				errno = 0;
				if (unlink(argv[k]) != 0) {
					(void) fprintf(stderr, gettext(
					    "pack: %s :cannot unlink"),
					    argv[k]);
					if (errno == EPERM)
						perror("No permission");
					else
						perror("");
				}
			}
			(void) printf(gettext(
			    "pack: %s: %.1f%% Compression\n"),
			    argv[k],
			    ((double)(-outsize+(insize.lint.lng))/
			    (double)insize.lint.lng)*100);
			/* output statistics */
			if (vflag) {
				(void) printf(gettext(
				    "\tfrom %ld to %ld bytes\n"),
				    insize.lint.lng, outsize);
				(void) printf(gettext(
				    "\tHuffman tree has %d levels below "
				    "root\n"), maxlev);
				(void) printf(gettext(
				    "\t%d distinct bytes in input\n"),
				    diffbytes);
				(void) printf(gettext(
				    "\tdictionary overhead = %ld bytes\n"),
				    dictsize);
				(void) printf(gettext(
				    "\teffective  entropy  = %.2f bits/byte\n"),
				    ((double)outsize / (double)insize.lint.lng)
				    * 8);
				(void) printf(gettext(
				    "\tasymptotic entropy  = %.2f bits/byte\n"),
				    ((double)(outsize-dictsize) /
				    (double)insize.lint.lng) * 8);
			}

			u_times.actime = status.st_atime;
			u_times.modtime = status.st_mtime;
			if (utime(filename, &u_times) != 0) {
				errflg++;
				(void) fprintf(stderr,
				    gettext(
				    "pack: cannot change times on %s: "),
				    filename);
				perror("");
			}
			if (chmod(filename, status.st_mode) != 0) {
				errflg++;
				(void) fprintf(stderr,
				    gettext(
				    "pack: can't change mode to %o on %s: "),
				    status.st_mode, filename);
				perror("");
			}
			(void) chown(filename, status.st_uid, status.st_gid);
			if (aclp && (facl_set(outfile, aclp) < 0)) {
				(void) fprintf(stderr, gettext(
				    "pack: %s: failed to set acl entries\n"),
				    filename);
				perror("");
			}
			if (!errflg)
				fcount--;  /* success after all */

		}
out:
		if (aclp) {
			acl_free(aclp);
			aclp = NULL;
		}

closein:	(void) close(outfile);
		(void) close(infile);
	}
	return (fcount);
}
