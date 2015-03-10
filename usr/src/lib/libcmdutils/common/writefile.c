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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
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

#include "libcmdutils.h"


int
writefile(int fi, int fo, char *infile, char *outfile, char *asfile,
    char *atfile, struct stat *s1p, struct stat *s2p)
{
	int mapsize, munmapsize;
	caddr_t cp;
	off_t filesize = s1p->st_size;
	off_t offset;
	int nbytes;
	int remains;
	int n;
	size_t src_size;
	size_t targ_size;
	char *srcbuf;
	char *targbuf;

	if (asfile != NULL) {
		src_size = strlen(infile) + strlen(asfile) +
		    strlen(dgettext(TEXT_DOMAIN, " attribute ")) + 1;
	} else {
		src_size = strlen(infile) + 1;
	}
	srcbuf = malloc(src_size);
	if (srcbuf == NULL) {
		(void) fprintf(stderr,
		    dgettext(TEXT_DOMAIN, "could not allocate memory"
		    " for path buffer: "));
		return (1);
	}
	if (asfile != NULL) {
		(void) snprintf(srcbuf, src_size, "%s%s%s",
		    infile, dgettext(TEXT_DOMAIN, " attribute "), asfile);
	} else {
		(void) snprintf(srcbuf, src_size, "%s", infile);
	}

	if (atfile != NULL) {
		targ_size = strlen(outfile) + strlen(atfile) +
		    strlen(dgettext(TEXT_DOMAIN, " attribute ")) + 1;
	} else {
		targ_size = strlen(outfile) + 1;
	}
	targbuf = malloc(targ_size);
	if (targbuf == NULL) {
		(void) fprintf(stderr,
		    dgettext(TEXT_DOMAIN, "could not allocate memory"
		    " for path buffer: "));
		return (1);
	}
	if (atfile != NULL) {
		(void) snprintf(targbuf, targ_size, "%s%s%s",
		    outfile, dgettext(TEXT_DOMAIN, " attribute "), atfile);
	} else {
		(void) snprintf(targbuf, targ_size, "%s", outfile);
	}

	if (S_ISREG(s1p->st_mode) && s1p->st_size > SMALLFILESIZE) {
		/*
		 * Determine size of initial mapping.  This will determine the
		 * size of the address space chunk we work with.  This initial
		 * mapping size will be used to perform munmap() in the future.
		 */
		mapsize = MAXMAPSIZE;
		if (s1p->st_size < mapsize) mapsize = s1p->st_size;
		munmapsize = mapsize;

		/*
		 * Mmap time!
		 */
		if ((cp = mmap((caddr_t)NULL, mapsize, PROT_READ,
		    MAP_SHARED, fi, (off_t)0)) == MAP_FAILED)
			mapsize = 0;   /* can't mmap today */
	} else
		mapsize = 0;

	if (mapsize != 0) {
		offset = 0;

		for (;;) {
			nbytes = write(fo, cp, mapsize);
			/*
			 * if we write less than the mmaped size it's due to a
			 * media error on the input file or out of space on
			 * the output file.  So, try again, and look for errno.
			 */
			if ((nbytes >= 0) && (nbytes != (int)mapsize)) {
				remains = mapsize - nbytes;
				while (remains > 0) {
					nbytes = write(fo,
					    cp + mapsize - remains, remains);
					if (nbytes < 0) {
						if (errno == ENOSPC)
							perror(targbuf);
						else
							perror(srcbuf);
						(void) close(fi);
						(void) close(fo);
						(void) munmap(cp, munmapsize);
						if (S_ISREG(s2p->st_mode))
							(void) unlink(targbuf);
						return (1);
					}
					remains -= nbytes;
					if (remains == 0)
						nbytes = mapsize;
				}
			}
			/*
			 * although the write manual page doesn't specify this
			 * as a possible errno, it is set when the nfs read
			 * via the mmap'ed file is accessed, so report the
			 * problem as a source access problem, not a target file
			 * problem
			 */
			if (nbytes < 0) {
				if (errno == EACCES)
					perror(srcbuf);
				else
					perror(targbuf);
				(void) close(fi);
				(void) close(fo);
				(void) munmap(cp, munmapsize);
				if (S_ISREG(s2p->st_mode))
					(void) unlink(targbuf);
				if (srcbuf != NULL)
					free(srcbuf);
				if (targbuf != NULL)
					free(targbuf);
				return (1);
			}
			filesize -= nbytes;
			if (filesize == 0)
				break;
			offset += nbytes;
			if (filesize < mapsize)
				mapsize = filesize;
			if (mmap(cp, mapsize, PROT_READ, MAP_SHARED |
			    MAP_FIXED, fi, offset) == MAP_FAILED) {
				perror(srcbuf);
				(void) close(fi);
				(void) close(fo);
				(void) munmap(cp, munmapsize);
				if (S_ISREG(s2p->st_mode))
					(void) unlink(targbuf);
				if (srcbuf != NULL)
					free(srcbuf);
				if (targbuf != NULL)
					free(targbuf);
				return (1);
			}
		}
		(void) munmap(cp, munmapsize);
	} else {
		char buf[SMALLFILESIZE];
		for (;;) {
			n = read(fi, buf, sizeof (buf));
			if (n == 0) {
				return (0);
			} else if (n < 0) {
				(void) close(fi);
				(void) close(fo);
				if (S_ISREG(s2p->st_mode))
					(void) unlink(targbuf);
				if (srcbuf != NULL)
					free(srcbuf);
				if (targbuf != NULL)
					free(targbuf);
				return (1);
			} else if (write(fo, buf, n) != n) {
				(void) close(fi);
				(void) close(fo);
				if (S_ISREG(s2p->st_mode))
					(void) unlink(targbuf);
				if (srcbuf != NULL)
					free(srcbuf);
				if (targbuf != NULL)
					free(targbuf);
				return (1);
			}
		}
	}
	if (srcbuf != NULL)
		free(srcbuf);
	if (targbuf != NULL)
		free(targbuf);
	return (0);
}
