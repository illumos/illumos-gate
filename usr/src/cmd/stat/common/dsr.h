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
	char	*dtype;		/* device type: sd, ssd, md, st, etc. */
	int	dnum;		/* device number */
	char	*dsk;		/* in form of cNtNdN */
	char	*dname;		/* in form of /dev/dsk/cNtNdN */
	char	*devidstr;	/* in form of "id1,sd@XXXX" */
	uint_t	flags;		/* see SLICES_OK and PARTITIONS_OK above */
	int	devtype;	/* disk, metadevice, tape */
	uint_t	seen;		/* Used for diffing disk lists */
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

/*
 * A basic description of each device found
 * on the system by walking the device tree.
 * These entries are used to select the
 * relevent entries from the actual /dev
 * entries.
 */
typedef struct ldinfo {
	char *name;
	char *dtype;
	char *devidstr;
	int dnum;
	struct ldinfo *next;
} ldinfo_t;

/*
 * Optimization for lookup of kstats.
 * For each kstat prefix (e.g., 'sd')
 * found in a directory one of these
 * structures will be created.
 *
 * name: prefix of kstat name (e.g., 'ssd')
 * min:  smallest number seen from kstat
 *       name (e.g., 101 from 'sd101')
 * max:  largest number seen from kstat
 * list_start: beginning of disk_list structures
 * 	for this kstat type in the main list for
 *	this directory
 * list_end: end of entries for this kstat type
 * 	in this directory.
 */
typedef struct dev_name {
	char *name;
	uint_t min;
	uint_t max;
	disk_list_t *list_start;
	disk_list_t *list_end;
	struct dev_name *next;
} dev_name_t;

/*
 * Definition of a "type" of disk device.
 * Tied to the directory containing entries
 * for that device. Divides the list of
 * devices into localized chunks and allows
 * quick determination as to whether an entry
 * exists or whether we need to look at the
 * devices upon a state change.
 */
typedef struct dir_info {
	char *name;		/* directory name */
	time_t mtime;		/* mod time */
	disk_list_t *list;	/* master list of devices */
	dev_name_t *nf;		/* lists per name */
	uint_t skip_lookup;	/* skip lookup if device */
				/* does not have partitions */
	char *dtype;		/* Type of device */
	char *trimstr;		/* What do we prune */
	char  trimchr;		/* Char denoting end */
				/* of interesting data */
} dir_info_t;

/*
 * The following are used to control treatment of kstat names
 * which fall beyond the number of disk partitions allowed on
 * the particular ISA. PARTITIONS_OK is set only on an Intel
 * system.
 */
#define	SLICES_OK	1
#define	PARTITIONS_OK	2

void do_mnttab(void);
mnt_t *lookup_mntent_byname(char *);
disk_list_t *lookup_ks_name(char *);
char *lookup_nfs_name(char *, kstat_ctl_t *);

#ifdef __cplusplus
}
#endif

#endif	/* _STAT_DSR_H */
