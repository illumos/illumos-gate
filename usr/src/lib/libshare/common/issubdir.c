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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

/*
 * Subdirectory detection: needed by exportfs and rpc.mountd.
 * The above programs call issubdir() frequently, so we make
 * it fast by caching the results of stat().
 */
#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <string.h>

#define	MAXSTATS MAXPATHLEN/2	/* maximum number of stat()'s to save */

#define	inoeq(ino1, ino2)	((ino1) == (ino2))
#define	deveq(dev1, dev2)	((dev1) == (dev2))

/*
 * dir1 is a subdirectory of dir2 within the same filesystem if
 *     (a) dir1 is identical to dir2
 *     (b) dir1's parent is dir2
 */
int
issubdir(char *dir1, char *dir2)
{
	struct stat st;
	struct stat parent_st;
	char *p;
	int index;

	static dev_t child_dev;
	static dev_t child_rdev;
	static ino_t child_ino[MAXSTATS];
	static int valid;
	static char childdir[MAXPATHLEN];
	static char child_fstype[_ST_FSTYPSZ];

	/*
	 * Get parent directory info
	 */
	if (stat(dir2, &parent_st) < 0) {
		return (0);
	}

	if (strcmp(childdir, dir1) != 0) {
		/*
		 * Not in cache: get child directory info
		 */
		p = strcpy(childdir, dir1) + strlen(dir1);
		index = 0;
		valid = 0;
		for (;;) {
			if (stat(childdir, &st) < 0) {
				childdir[0] = 0;	/* invalidate cache */
				return (0);
			}
			if (index == 0) {
				child_dev = st.st_dev;
				child_rdev = st.st_rdev;
				(void) strncpy(child_fstype, st.st_fstype,
				    sizeof (child_fstype));
			}
			if (index > 0 &&
			    (child_dev != st.st_dev ||
			    inoeq(child_ino[index - 1], st.st_ino))) {
				/*
				 * Hit root: done
				 */
				break;
			}
			child_ino[index++] = st.st_ino;
			if (S_ISDIR(st.st_mode)) {
				p = strcpy(p, "/..") + 3;
			} else {
				p = strrchr(childdir, '/');
				if (p == NULL) {
					p = strcpy(childdir, ".") + 1;
				} else {
					while (((p - 1) > childdir) &&
					    *(p - 1) == '/') {
						p--;
					}
					*p = '\0';
				}
			}
		}
		valid = index;
		(void) strlcpy(childdir, dir1, MAXPATHLEN);
	}

	/*
	 * Perform the test
	 */
	if (!deveq(parent_st.st_dev, child_dev)) {
		return (0);
	}

	/*
	 * Check rdev also in case of lofs
	 */
	if (((strcmp(parent_st.st_fstype, "lofs") == 0)) &&
	    (strcmp(child_fstype, "lofs") == 0)) {
		if (!deveq(parent_st.st_rdev, child_rdev)) {
			return (0);
		}
	}

	for (index = 0; index < valid; index++) {
		if (inoeq(child_ino[index], parent_st.st_ino)) {
			return (1);
		}
	}
	return (0);
}
