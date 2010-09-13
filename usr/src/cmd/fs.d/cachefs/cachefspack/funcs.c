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
 * Copyright 1996-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <locale.h>
#include <sys/types.h>
#include <sys/param.h>
#include <stdio.h>
#include <dirent.h>
#include <sys/acl.h>
#include <sys/fs/cachefs_fs.h>
#include <sys/fs/cachefs_dlog.h>
#include <sys/fs/cachefs_ioctl.h>
#include <errno.h>
#include <string.h>

extern int verbose;

/*
 * Function used by -d option to display pathname
 */
int
prtfn(char *pathnam, char *fnam, DIR *dirp, int depth)
{
	printf("%s\n", pathnam);
	return (0);
}

/*
 * Function used by -p option to pack pathname
 */
int
packfn(char *pathnam, char *fnam, DIR *dirp, int depth)
{
	cachefsio_pack_t pack;
	int xx;
	int len;

#ifdef DEBUG
	printf("packfn: pathnam = %s", pathnam);
	fflush(stdout);
	if (fnam != NULL) {
		printf("  fnam = %s\n",  fnam);
	} else {
		printf("\n");
	}
	printf("packfn: dirp    = %x depth = %d\n", dirp, depth);
	fflush(stdout);
#endif /* DEBUG */
	if (fnam != NULL) {
		len = strlen(fnam);
		if (len >= sizeof (pack.p_name)) {
			fprintf(stderr, gettext(
			    "cachefspack: file name too long - %s\n"),
			    pathnam);
			return (-1);
		}
#ifdef DEBUG
		printf("packfn: len = %d\n", len);
		fflush(stdout);
#endif /* DEBUG */
		while (fnam[len-1] == '/') {
		    len--;
		}
		strncpy(pack.p_name, fnam, len);
	} else {
		len = 0;
	}
	pack.p_name[len] = '\0';
	pack.p_status = 0;
#ifdef DEBUG
	printf("packfn: pack.p_name = %s  pack.p_status = %x\n",
		pack.p_name, pack.p_status);
	fflush(stdout);
#endif /* DEBUG */

	xx = ioctl(dirp->dd_fd, CACHEFSIO_PACK, &pack);
#ifdef DEBUG
	printf("packfn: xx = %x  errno = %d\n", xx, errno);
	fflush(stdout);
#endif /* DEBUG */
	if (xx) {
		if (errno == ENOTTY) {
			return (0);
		}
		if (errno == ENOSYS) {
			return (0);
		}
		fprintf(stderr, gettext("cachefspack: %s -  "), pathnam);
		perror(gettext("can't pack file"));
		return (-1);
	}
	return (0);
}

/*
 * Function used by -p option to unpack pathname
 */
int
unpackfn(char *pathnam, char *fnam, DIR *dirp, int depth)
{
	cachefsio_pack_t pack;
	int xx;
	int len;

#ifdef DEBUG
	printf("unpackfn: pathnam = %s ", pathnam);
	if (fnam != NULL) {
		printf("  fnam = %s\n", fnam);
	} else {
		printf("\n");
	}
	printf("unpackfn: dirp    = %x depth = %d\n", dirp, depth);
	fflush(stdout);
#endif /* DEBUG */
	if (fnam != NULL) {
		len = strlen(fnam);
		if (len >= sizeof (pack.p_name)) {
			fprintf(stderr, gettext(
			    "cachefspack: file name too long - %s\n"), pathnam);
			return (-1);
		}
		while (fnam[len-1] == '/') {
		    len--;
		}
		strncpy(pack.p_name, fnam, len);
	} else {
		len = 0;
	}
	pack.p_name[len] = '\0';
	pack.p_status = 0;
#ifdef DEBUG
	printf("unpackfn: pack.p_name = %s  pack.p_status = %x\n",
		pack.p_name, pack.p_status);
	fflush(stdout);
#endif /* DEBUG */

	xx = ioctl(dirp->dd_fd, CACHEFSIO_UNPACK, &pack);
#ifdef DEBUG
	printf("unpackfn: pack.p_name = %s  pack.p_status = %x\n",
		pack.p_name, pack.p_status);
	fflush(stdout);
#endif /* DEBUG */
	if (xx) {
		if (errno == ENOTTY) {
			return (0);
		}
		if (errno == ENOSYS) {
			return (0);
		}
		fprintf(stderr, gettext("cachefspack: %s - "), pathnam);
		perror(gettext("can't unpack file"));
		return (-1);
	}
	return (0);
}

/*
 * Function used by -i option to print status of pathname
 */
int
inquirefn(char *pathnam, char *fnam, DIR *dirp, int depth)
{
	cachefsio_pack_t pack;
	int xx;
	int len;

#ifdef DEBUG
	printf("inquirefn: pathnam = %s ", pathnam);
	if (fnam != NULL) {
		printf("fnam = %s\n", fnam);
	} else {
		printf("\n");
	}
	printf("inquirefn: dirp    = %x depth = %d\n", dirp, depth);
	fflush(stdout);
#endif /* DEBUG */
	if (fnam != NULL) {
		len = strlen(fnam);
		if (len >= sizeof (pack.p_name)) {
			fprintf(stderr,
			    gettext("cachefspack: file name too long - %s\n"),
			    pathnam);
			return (-1);
		}
		while (fnam[len-1] == '/') {
		    len--;
		}
		strncpy(pack.p_name, fnam, len);
	} else {
		len = 0;
	}
	pack.p_name[len] = '\0';
	pack.p_status = 0;
#ifdef DEBUG
	printf("inquirefn: pack.p_name = %s  pack.p_status = %x\n",
		pack.p_name, pack.p_status);
	fflush(stdout);
#endif /* DEBUG */

	xx = ioctl(dirp->dd_fd, CACHEFSIO_PACKINFO, &pack);
#ifdef DEBUG
	printf("inquirefn: xx = %x  errno = %d\n", xx, errno);
	fflush(stdout);
#endif /* DEBUG */
	if (xx) {
		if ((errno == ENOTTY) || (errno == ENOSYS)) {
#ifdef CFS_MSG
			fprintf(stderr, gettext("cachefspack:  "));
			fprintf(stderr,
			    gettext("%s - is not in a cacheFS file system\n"),
			    pathnam);
#endif /* CFS_MSG */
			return (-1);
		}
		fprintf(stderr, gettext("cachefspack: %s - "), pathnam);
		perror(gettext("can't get info"));
		return (-2);
	}

	printf(gettext("cachefspack: file %s "), pathnam);
	printf(gettext("marked packed %s, packed %s\n"),
	    (pack.p_status & CACHEFS_PACKED_FILE) ? "YES" : "NO",
	    (pack.p_status & CACHEFS_PACKED_DATA) ? "YES" : "NO");
	if (verbose) {
		printf(gettext("    nocache %s\n"),
		    (pack.p_status & CACHEFS_PACKED_NOCACHE) ?
		    "YES" : "NO");
	}
	return (0);
}
