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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdlib.h>
#include <sys/types.h>
#include <stdio.h>
#include <sys/mnttab.h>
#include <sys/mntent.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <string.h>
#include <fcntl.h>

#include "statcommon.h"
#include "dsr.h"

static time_t mtime;
mnt_t *nfs;
static mnt_t *ufs;

static void build_mnt_list(FILE *);

mnt_t *
lookup_mntent_byname(char *nm)
{
	mnt_t *rv = 0;
	mnt_t *minfo;
	uint_t did_nfs;


	if (nm) {
		minfo = ufs;
		did_nfs = 0;
		while (minfo) {
			if (strcmp(nm, minfo->device_name)) {
				if (minfo->next != 0)
					minfo = minfo->next;
				else if (did_nfs == 0) {
					minfo = nfs;
					did_nfs = 1;
				}
				else
					minfo = 0;
			} else {
				rv = minfo;
				break;
			}
		}
	}
	return (rv);
}

void
do_mnttab(void)
{
	struct stat 	buf;
	FILE 		*mpt;
	struct flock    lb;

	if (stat(MNTTAB, &buf) == 0) {
		if (buf.st_mtime != mtime) {
			/*
			 * File has changed. Get the new file.
			 */
			if ((mpt = fopen(MNTTAB, "r"))) {
				lb.l_type = F_RDLCK;
				lb.l_whence = 0;
				lb.l_start = 0;
				lb.l_len = 0;
				(void) fcntl(fileno(mpt), F_SETLKW, &lb);
				build_mnt_list(mpt);
				mtime = buf.st_mtime;
				/*
				 * Lock goes away when we close the file.
				 */
				(void) fclose(mpt);
			}
		}
	}
}

static void
build_mnt_list(FILE *mpt)
{
	mnt_t *item;
	mnt_t **which;
	mnt_t *tmp;
	int  found;
	struct extmnttab mnt;

	if (mpt) {
		while (nfs) {
			free(nfs->device_name);
			free(nfs->mount_point);
			free(nfs->devinfo);
			tmp = nfs;
			nfs = nfs->next;
			free(tmp);
		}
		while (ufs) {
			free(ufs->device_name);
			free(ufs->mount_point);
			free(ufs->devinfo);
			tmp = ufs;
			ufs = ufs->next;
			free(tmp);
		}
		(void) memset(&mnt, 0, sizeof (struct extmnttab));

		resetmnttab(mpt);
		while ((found = getextmntent(mpt, &mnt,
			sizeof (struct extmnttab))) != -1) {
			if (found == 0) {
				if (strcmp(mnt.mnt_fstype, MNTTYPE_UFS) == 0)
					which = &ufs;
				else if (strcmp(mnt.mnt_fstype,
				    MNTTYPE_NFS) == 0)
					which = &nfs;
				else
					which = 0;
				if (which) {
					item = safe_alloc(sizeof (mnt_t));
					item->device_name =
						safe_strdup(mnt.mnt_special);
					item->mount_point =
						safe_strdup(mnt.mnt_mountp);
					item->devinfo =
						safe_strdup(mnt.mnt_mntopts);
					item->minor = mnt.mnt_minor;
					item->next = *which;
					*which = item;
				}
			}
		}
	}
}
