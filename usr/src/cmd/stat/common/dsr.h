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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_STAT_DSR_H
#define	_STAT_DSR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Description of each device identified
 */
typedef struct list_of_disks {
	char	*ks_name;	/* untranslated kstat name */
	char	*dsk;		/* in form of cNtNdN */
	char	*dname;		/* in form of /dev/dsk/cNtNdN */
	char	*devidstr;	/* in form of "id1,sd@XXXX" */
	struct list_of_disks *next;	/* link to next one */
} disk_list_t;

/*
 * Description of each mount point currently existing on the system.
 */
typedef struct mnt_info {
	char *device_name;
	char *mount_point;
	char *devinfo;
	uint_t minor;
	struct mnt_info *next;
} mnt_t;

void do_mnttab(void);
mnt_t *lookup_mntent_byname(char *);
disk_list_t *lookup_ks_name(char *, int);
char *lookup_nfs_name(char *, kstat_ctl_t *);
void cleanup_iodevs_snapshot();

#ifdef __cplusplus
}
#endif

#endif	/* _STAT_DSR_H */
