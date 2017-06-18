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
/*
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
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

#include <stdio.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/file.h>
#include <sys/fcntl.h>
#include <sys/mtio.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>

char *buff;				/* buffer for read/write */
int filen = 1;				/* file number being processed */
long count, lcount;			/* number of blocks for file */
extern void RUBOUT();
int nfile;				/* used for ??? */
off64_t size, tsize;			/* number of bytes in file, total */
int ln;
char *inf, *outf;
int copy;
size_t size_64K = 64 * 1024;
size_t size_256K = 256 * 1024;


int
main(int argc, char **argv)
{
	int	n, nw, inp, outp;
	struct mtop op;
	size_t buf_size = size_64K;

	if (argc <= 1 || argc > 3) {
		(void) fprintf(stderr, "Usage: tcopy src [dest]\n");
		return (1);
	}
	inf = argv[1];
	if (argc == 3) {
		outf = argv[2];
		copy = 1;
	}
	if ((inp = open(inf, O_RDONLY, 0666)) < 0) {
		(void) fprintf(stderr, "Can't open %s\n", inf);
		return (1);
	}
	if (copy) {
		if ((outp = open(outf, O_WRONLY, 0666)) < 0) {
			(void) fprintf(stderr, "Can't open %s\n", outf);
			return (3);
		}
	}
	if ((buff = malloc(buf_size)) == NULL) {
		(void) fprintf(stderr, "Can't allocate memory for tcopy\n");
		return (4);
	}
	if (signal(SIGINT, SIG_IGN) != SIG_IGN)
		(void) signal(SIGINT, RUBOUT);
	ln = -2;
	for (;;) {
		count++;
		errno = 0;
		while ((n = read(inp, buff, buf_size)) < 0 &&
		    errno == ENOMEM && buf_size < INT_MAX) {
			if (buf_size < size_256K)
				buf_size = size_256K;
			else
				buf_size *= 2;
			free(buff);
			if ((buff = malloc(buf_size)) == NULL) {
				(void) fprintf(stderr,
				    "Can't allocate memory for tcopy\n");
				return (4);
			}
			op.mt_op = MTFSF;	/* Rewind to start of file */
			op.mt_count = (daddr_t)0;
			if (ioctl(inp, MTIOCTOP, (char *)&op) < 0) {
				perror("Read record size");
				return (6);
			}
			errno = 0;
		}
		if (n > 0) {
			if (copy) {
				nw = write(outp, buff, (size_t)n);
				if (nw != n) {
					(void) fprintf(stderr, "write (%d) !="
					    " read (%d)\n", nw, n);
					(void) fprintf(stderr, "COPY "
					    "Aborted\n");
					return (5);
				}
			}
			size += n;
			if (n != ln) {
				if (ln > 0)
					if (count - lcount > 1)
						(void) printf("file %d: records"
						    " %ld to %ld: size %d\n",
						    filen, lcount, count-1, ln);
					else
						(void) printf("file %d: record"
						    " %ld: size %d\n",
						    filen, lcount, ln);
				ln = n;
				lcount = count;
			}
		} else {
			if (ln <= 0 && ln != -2) {
				(void) printf("eot\n");
				break;
			}
			if (ln > 0)
				if (count - lcount > 1)
					(void) printf("file %d: records %ld to"
					    " %ld: size " "%d\n",
					    filen, lcount, count-1, ln);
				else
					(void) printf("file %d: record %ld:"
					    " size %d\n", filen, lcount, ln);
			(void) printf("file %d: eof after %ld records:"
			    " %lld bytes\n", filen, count-1, size);
			if (copy) {
				op.mt_op = MTWEOF;
				op.mt_count = (daddr_t)1;
				if (ioctl(outp, MTIOCTOP, (char *)&op) < 0) {
					perror("Write EOF");
					return (6);
				}
			}
			filen++;
			count = 0;
			lcount = 0;
			tsize += size;
			size = 0;
			if (nfile && filen > nfile)
				break;
			ln = n;
		}
	}
	if (copy)
		(void) close(outp);
	(void) printf("total length: %lld bytes\n", tsize);
	return (0);
}

void
RUBOUT(void)
{
	if (count > lcount)
		--count;
	if (count)
		if (count > lcount)
			(void) printf("file %d: records %ld to %ld: size"
			    " %d\n", filen, lcount, count, ln);
		else
			(void) printf("file %d: record %ld: size %d\n",
			    filen, lcount, ln);
	(void) printf("interrupted at file %d: record %ld\n", filen, count);
	(void) printf("total length: %lld bytes\n", tsize+size);
	exit(1);
}
