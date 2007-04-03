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

/*
 * where.c - get full pathname including host:
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

#include <sys/mntent.h>

#include <sys/mnttab.h>
#include <sys/param.h>
#include <sys/stat.h>

#include <sharefs/share.h>
#include "sharetab.h"

extern	FILE	*setmntent();

FILE *setsharetab();
void endsharetab();



extern	int	Debug;

/*
 * where(pn, host, fsname, within)
 *
 * pn is the pathname we are looking for,
 * host gets the name of the host owning the file system,
 * fsname gets the file system name on the host,
 * within gets whatever is left from the pathname
 *
 * Returns: 0 if ERROR, 1 if OK
 */
int
where(pn, host, fsname, within)
char *pn;
char *host;
char *fsname;
char *within;
{
	struct stat sb;
	char curdir[MAXPATHLEN];
	char qualpn[MAXPATHLEN];
	char *p;

	if (Debug)
	    printf("where: pn %s\n", pn);

	if (stat(pn, &sb) < 0) {
		char *errstr;

		if ((errstr = strerror(errno)) == NULL)
			errstr = "unknown error";

		if (Debug)
		    printf("where: stat failed");
		strcpy(within, errstr);
		return (0);
	}
	/*
	 * first get the working directory,
	 */
	if (getcwd(curdir, MAXPATHLEN) == NULL) {
		sprintf(within, "Unable to get working directory (%s)",
			curdir);
		return (0);
	}
	if (chdir(pn) == 0) {
		getcwd(qualpn, MAXPATHLEN);
		chdir(curdir);
	} else {
		if (p = strrchr(pn, '/')) {
			*p = 0;
			chdir(pn);
			(void) getcwd(qualpn, MAXPATHLEN);
			chdir(curdir);
			strcat(qualpn, "/");
			strcat(qualpn, p+1);
		} else {
			strcpy(qualpn, curdir);
			strcat(qualpn, "/");
			strcat(qualpn, pn);
		}
	}
	return (findmount(qualpn, host, fsname, within));
}

/*
 * findmount(qualpn, host, fsname, within)
 *
 * Searches the mount table to find the appropriate file system
 * for a given absolute path name.
 * host gets the name of the host owning the file system,
 * fsname gets the file system name on the host,
 * within gets whatever is left from the pathname
 *
 * Returns: 0 on failure, 1 on success.
 */
int
findmount(qualpn, host, fsname, within)
char *qualpn;
char *host;
char *fsname;
char *within;
{
	FILE	*mfp;
	char	bestname[MAXPATHLEN];
	int	bestlen = 0,
	bestnfs = 0;
	struct	share *exp;
	struct	mnttab		mp,
	*mnt;
	char	*endhost;	/* points past the colon in name */
	int	i,
	len;

	if (Debug)
		printf("findmount: qualpn %s\n", qualpn);

	for (i = 0; i < 10; i++) {
		mfp = setmntent("/etc/mnttab", "r");
		if (mfp != NULL)
			break;
		sleep(1);
	}

	if (mfp == NULL) {
		sprintf(within, "mount table problem");
		return (0);
	}

	bestname[0] = '\0';
	while ((getmntent(mfp, &mp)) == 0) {
		if (strcmp(mp.mnt_fstype, "nfs") != 0)
			/*
			 * If it is not nfs filesystem type, skip the
			 * entry
			 */
			continue;

		len = preflen(qualpn, mp.mnt_mountp);

		if (Debug)
			printf("preflen: %d %s %s", len, qualpn, mp.mnt_mountp);

		if (qualpn[len] != '/' && qualpn[len] != '\0' && len > 1)
			/*
			 * If the last matching character is neither / nor
			 * the end of the pathname, not a real match
			 * (except for matching root, len==1)
			 */
			continue;

		if (len > bestlen) {
			bestlen = len;
			strncpy(bestname, mp.mnt_special, sizeof (bestname));
		}
		if (Debug)
			printf(" %s\n", bestname);
	}

	endmntent(mfp);

	endhost = strchr(bestname, ':');

	/*
	 * If the file system was of type NFS, then there should already
	 * be a host name, otherwise, use ours.
	 */
	if (endhost) {
		*endhost++ = 0;
		strncpy(host, bestname, MAXHOSTNAMELEN);
		strncpy(fsname, endhost, MAXPATHLEN);

		/*
		 * special case to keep the "/" when we match root
		 */
		if (bestlen == 1)
			bestlen = 0;
	} else {
		gethostname(host, MAXHOSTNAMELEN);

		/*
		 *	If this is our file system, try for an even longer
		 *	match from /etc/xtab.
		 */
		if (mfp = setsharetab()) {
			while (getshare(mfp, &exp) > 0)
				if (len = preflen(qualpn, exp->sh_path))
					if (len > bestlen) {
						bestlen = len;
						strncpy(bestname, exp->sh_path,
							sizeof (bestname));
					}
			endsharetab(mfp);
		}
		strncpy(fsname, qualpn, bestlen);
		fsname[bestlen] = 0;
	}
	strncpy(within, qualpn + bestlen, MAXPATHLEN);

	if (Debug)
		printf("findmount: qualpn %s\nhost %s\nfsname %s\nwithin %s\n",
			qualpn, host, fsname, within);
	return (1);
}

/*
 * Returns: length of second argument if it is a prefix of the
 * first argument, otherwise zero.
 */
int
preflen(str, pref)
char	*str, *pref;
{
	int len;

	len = strlen(pref);
	if (strncmp(str, pref, len) == 0)
		return (len);
	return (0);
}

FILE
*setsharetab()
{
	FILE	*f;

	f = fopen(SHARETAB, "r");
	if (f == NULL) {
		return (NULL);
	}

	return (f);
}


void
endsharetab(f)
FILE	*f;
{
	(void) fclose(f);
}
