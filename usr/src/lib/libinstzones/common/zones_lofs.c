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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libintl.h>
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/mntent.h>
#include <sys/mnttab.h>
#include <sys/param.h>
#include <libzonecfg.h>
#include "zones_strings.h"
#include "instzones_lib.h"

#define	MNTTAB	"/etc/mnttab"

#define	MNTTAB_HUNK	32

static struct mnttab *mountTable;
static size_t mountTableSize = 0;
static boolean_t createdFlag = B_FALSE;

/*
 * Name		: z_createMountTable
 * Description	: Populate the mountTable Array with mnttab entries
 * Arguments	: void
 * Returns	: int
 *		  0: The Mount Table was succesfully initialized
 *		 -1: There was an error during initialisation
 */
int
z_createMountTable(void)
{
	FILE *fp;
	struct mnttab ent;
	struct mnttab *entp;

	if (createdFlag) {
		return (0);
	}

	fp = fopen(MNTTAB, "r");
	if (fp == NULL) {
		_z_program_error(ERR_OPEN_READ, MNTTAB, errno,
		    strerror(errno));
		return (-1);
	}

	/* Put the entries into the table */
	mountTable = NULL;
	mountTableSize = 0;
	createdFlag = B_TRUE;
	while (getmntent(fp, &ent) == 0) {
		if (mountTableSize % MNTTAB_HUNK == 0) {
			mountTable = _z_realloc(mountTable,
			    (mountTableSize + MNTTAB_HUNK) * sizeof (ent));
		}
		entp = &mountTable[mountTableSize++];

		/*
		 * Zero out any fields we're not using.
		 */
		(void) memset(entp, 0, sizeof (*entp));

		if (ent.mnt_special != NULL)
			entp->mnt_special = _z_strdup(ent.mnt_special);
		if (ent.mnt_mntopts != NULL)
			entp->mnt_mntopts = _z_strdup(ent.mnt_mntopts);
		entp->mnt_mountp = _z_strdup(ent.mnt_mountp);
		entp->mnt_fstype = _z_strdup(ent.mnt_fstype);
	}

	(void) fclose(fp);
	return (0);
}

/*
 * Name		: findPathRWStatus
 * Description	: Check whether the given path is an mnttab entry
 * Arguments	: char * - The Path to be verified
 * Returns	: int
 *		  -1: The Path is NOT present in the table (mnttab)
 *		   0: The Path is present in the table and is mounted read-only
 *		   1: The Path is present in the table and is mounted read-write
 */
static int
findPathRWStatus(const char *a_path)
{
	int i;

	for (i = 0; i < mountTableSize; i++) {
		if (strcmp(a_path, mountTable[i].mnt_mountp) == 0) {
			if (hasmntopt(&mountTable[i], MNTOPT_RO) != NULL) {
				return (0);
			} else {
				return (1);
			}
		}
	}

	return (-1);
}


/*
 * Name		: z_isPathWritable
 * Description	: Check if the given path is in a writable area
 * Arguments	: char * - The Path to be verified
 * Returns	: int
 *		   0: The Path is under a read-only mount
 *		   1: The Path is under a read-write mount
 * NOTE		: This funcion automatically initialises
 *		  the mountPoint table if needed.
 */
int
z_isPathWritable(const char *a_str)
{
	int i, result, slen;
	char a_path[MAXPATHLEN];

	if (!createdFlag) {
		if (z_createMountTable() != 0) {
			return (1);
		}
	}

	(void) strlcpy(a_path, a_str, sizeof (a_path));
	slen = strlen(a_path);

	/*
	 * This for loop traverses Path backwards, incrementally removing the
	 * basename of Path and looking for the resultant directory in the
	 * mnttab.  Once found, it returns the rw status of that file system.
	 */
	for (i = slen; i > 0; i--) {
		if ((a_path[i] == '/') || (a_path[i] == '\0')) {
			a_path[i] = '\0';
			result = findPathRWStatus(a_path);
			if (result != -1) {
				return (result);
			}
		}
	}

	return (1);
}

/*
 * Name		: z_destroyMountTable
 * Description	: Clear the entries in the mount table
 * Arguments	: void
 * Returns	: void
 */
void
z_destroyMountTable(void)
{
	int i;

	if (!createdFlag) {
		return;
	}

	if (mountTable == NULL) {
		return;
	}

	for (i = 0; i < mountTableSize; i++) {
		free(mountTable[i].mnt_mountp);
		free(mountTable[i].mnt_fstype);
		free(mountTable[i].mnt_special);
		free(mountTable[i].mnt_mntopts);
		assert(mountTable[i].mnt_time == NULL);
	}

	free(mountTable);
	mountTable = NULL;
	mountTableSize = 0;
	createdFlag = B_FALSE;
}

/*
 * Name		: z_resolve_lofs
 * Description	: Loop over potential loopback mounts and symlinks in a
 *		  given path and resolve them all down to an absolute path.
 * Arguments	: char * - path to resolve.  path is in writable storage.
 *		  size_t - length of path storage.
 * Returns	: void
 */
void
z_resolve_lofs(char *path, size_t pathlen)
{
	int len, arlen, i;
	const char *altroot;
	char tmppath[MAXPATHLEN];
	boolean_t outside_altroot;

	if ((len = resolvepath(path, tmppath, sizeof (tmppath))) == -1)
		return;

	tmppath[len] = '\0';
	(void) strlcpy(path, tmppath, pathlen);

	if (z_createMountTable() == -1)
		return;

	altroot = zonecfg_get_root();
	arlen = strlen(altroot);
	outside_altroot = B_FALSE;
	for (;;) {
		struct mnttab *mnp;

		/* Search in reverse order to find longest match */
		for (i = mountTableSize; i > 0; i--) {
			mnp = &mountTable[i - 1];
			if (mnp->mnt_fstype == NULL ||
			    mnp->mnt_mountp == NULL ||
			    mnp->mnt_special == NULL)
				continue;
			len = strlen(mnp->mnt_mountp);
			if (strncmp(mnp->mnt_mountp, path, len) == 0 &&
			    (path[len] == '/' || path[len] == '\0'))
				break;
		}
		if (i <= 0)
			break;

		/* If it's not a lofs then we're done */
		if (strcmp(mnp->mnt_fstype, MNTTYPE_LOFS) != 0)
			break;

		if (outside_altroot) {
			char *cp;
			int olen = sizeof (MNTOPT_RO) - 1;

			/*
			 * If we run into a read-only mount outside of the
			 * alternate root environment, then the user doesn't
			 * want this path to be made read-write.
			 */
			if (mnp->mnt_mntopts != NULL &&
			    (cp = strstr(mnp->mnt_mntopts, MNTOPT_RO)) !=
			    NULL &&
			    (cp == mnp->mnt_mntopts || cp[-1] == ',') &&
			    (cp[olen] == '\0' || cp[olen] == ',')) {
				break;
			}
		} else if (arlen > 0 &&
		    (strncmp(mnp->mnt_special, altroot, arlen) != 0 ||
		    (mnp->mnt_special[arlen] != '\0' &&
		    mnp->mnt_special[arlen] != '/'))) {
			outside_altroot = B_TRUE;
		}
		/* use temporary buffer because new path might be longer */
		(void) snprintf(tmppath, sizeof (tmppath), "%s%s",
		    mnp->mnt_special, path + len);
		if ((len = resolvepath(tmppath, path, pathlen)) == -1)
			break;
		path[len] = '\0';
	}
}
