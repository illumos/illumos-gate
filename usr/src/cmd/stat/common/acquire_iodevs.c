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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "statcommon.h"
#include "dsr.h"

#include <sys/dklabel.h>
#include <sys/dktp/fdisk.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <strings.h>
#include <errno.h>
#include <limits.h>

static void insert_iodev(struct snapshot *ss, struct iodev_snapshot *iodev);

static struct iodev_snapshot *
make_controller(int cid)
{
	struct iodev_snapshot *new;

	new = safe_alloc(sizeof (struct iodev_snapshot));
	(void) memset(new, 0, sizeof (struct iodev_snapshot));
	new->is_type = IODEV_CONTROLLER;
	new->is_id.id = cid;
	new->is_parent_id.id = IODEV_NO_ID;

	(void) snprintf(new->is_name, sizeof (new->is_name), "c%d", cid);

	return (new);
}

static struct iodev_snapshot *
find_iodev_by_name(struct iodev_snapshot *list, const char *name)
{
	struct iodev_snapshot *pos;
	struct iodev_snapshot *pos2;

	for (pos = list; pos; pos = pos->is_next) {
		if (strcmp(pos->is_name, name) == 0)
			return (pos);

		pos2 = find_iodev_by_name(pos->is_children, name);
		if (pos2 != NULL)
			return (pos2);
	}

	return (NULL);
}

static enum iodev_type
parent_iodev_type(enum iodev_type type)
{
	switch (type) {
		case IODEV_CONTROLLER: return (0);
		case IODEV_NFS: return (0);
		case IODEV_TAPE: return (0);
		case IODEV_IOPATH: return (IODEV_DISK);
		case IODEV_DISK: return (IODEV_CONTROLLER);
		case IODEV_PARTITION: return (IODEV_DISK);
	}
	return (IODEV_UNKNOWN);
}

static int
id_match(struct iodev_id *id1, struct iodev_id *id2)
{
	return (id1->id == id2->id &&
		strcmp(id1->tid, id2->tid) == 0);
}

static struct iodev_snapshot *
find_parent(struct snapshot *ss, struct iodev_snapshot *iodev)
{
	enum iodev_type parent_type = parent_iodev_type(iodev->is_type);
	struct iodev_snapshot *pos;
	struct iodev_snapshot *pos2;

	if (parent_type == 0 || parent_type == IODEV_UNKNOWN)
		return (NULL);

	if (iodev->is_parent_id.id == IODEV_NO_ID &&
	    iodev->is_parent_id.tid[0] == '\0')
		return (NULL);

	if (parent_type == IODEV_CONTROLLER) {
		for (pos = ss->s_iodevs; pos; pos = pos->is_next) {
			if (pos->is_type != IODEV_CONTROLLER)
				continue;
			if (pos->is_id.id != iodev->is_parent_id.id)
				continue;
			return (pos);
		}

		if (!(ss->s_types & SNAP_CONTROLLERS))
			return (NULL);

		pos = make_controller(iodev->is_parent_id.id);
		insert_iodev(ss, pos);
		return (pos);
	}

	/* IODEV_DISK parent */
	for (pos = ss->s_iodevs; pos; pos = pos->is_next) {
		if (id_match(&iodev->is_parent_id, &pos->is_id) &&
		    pos->is_type == IODEV_DISK)
			return (pos);
		if (pos->is_type != IODEV_CONTROLLER)
			continue;
		for (pos2 = pos->is_children; pos2; pos2 = pos2->is_next) {
			if (pos2->is_type != IODEV_DISK)
				continue;
			if (id_match(&iodev->is_parent_id, &pos2->is_id))
				return (pos2);
		}
	}

	return (NULL);
}

static void
list_del(struct iodev_snapshot **list, struct iodev_snapshot *pos)
{
	if (*list == pos)
		*list = pos->is_next;
	if (pos->is_next)
		pos->is_next->is_prev = pos->is_prev;
	if (pos->is_prev)
		pos->is_prev->is_next = pos->is_next;
	pos->is_prev = pos->is_next = NULL;
}

static void
insert_before(struct iodev_snapshot **list, struct iodev_snapshot *pos,
    struct iodev_snapshot *new)
{
	if (pos == NULL) {
		new->is_prev = new->is_next = NULL;
		*list = new;
		return;
	}

	new->is_next = pos;
	new->is_prev = pos->is_prev;
	if (pos->is_prev)
		pos->is_prev->is_next = new;
	else
		*list = new;
	pos->is_prev = new;
}

static void
insert_after(struct iodev_snapshot **list, struct iodev_snapshot *pos,
    struct iodev_snapshot *new)
{
	if (pos == NULL) {
		new->is_prev = new->is_next = NULL;
		*list = new;
		return;
	}

	new->is_next = pos->is_next;
	new->is_prev = pos;
	if (pos->is_next)
		pos->is_next->is_prev = new;
	pos->is_next = new;
}

static void
insert_into(struct iodev_snapshot **list, struct iodev_snapshot *iodev)
{
	struct iodev_snapshot *tmp = *list;
	if (*list == NULL) {
		*list = iodev;
		return;
	}

	for (;;) {
		if (iodev_cmp(tmp, iodev) > 0) {
			insert_before(list, tmp, iodev);
			return;
		}

		if (tmp->is_next == NULL)
			break;

		tmp = tmp->is_next;
	}

	insert_after(list, tmp, iodev);
}

static int
disk_or_partition(enum iodev_type type)
{
	return (type == IODEV_DISK || type == IODEV_PARTITION);
}

static void
insert_iodev(struct snapshot *ss, struct iodev_snapshot *iodev)
{
	struct iodev_snapshot *parent = find_parent(ss, iodev);
	struct iodev_snapshot **list;

	if (parent != NULL) {
		list = &parent->is_children;
		parent->is_nr_children++;
	} else {
		list = &ss->s_iodevs;
		ss->s_nr_iodevs++;
	}

	insert_into(list, iodev);
}

static int
iodev_match(struct iodev_snapshot *dev, struct iodev_filter *df)
{
	size_t i;
	int is_floppy = (strncmp(dev->is_name, "fd", 2) == 0);

	/* no filter, pass */
	if (df == NULL)
		return (1);

	/* no filtered names, pass if not floppy and skipped */
	if (df->if_nr_names == NULL)
		return (!(df->if_skip_floppy && is_floppy));

	for (i = 0; i < df->if_nr_names; i++) {
		if (strcmp(dev->is_name, df->if_names[i]) == 0)
			return (1);
		if (dev->is_pretty != NULL &&
		    strcmp(dev->is_pretty, df->if_names[i]) == 0)
			return (1);
	}

	/* not found in specified names, fail match */
	return (0);
}

/* select which I/O devices to collect stats for */
static void
choose_iodevs(struct snapshot *ss, struct iodev_snapshot *iodevs,
    struct iodev_filter *df)
{
	struct iodev_snapshot *pos = iodevs;
	int nr_iodevs = df ? df->if_max_iodevs : UNLIMITED_IODEVS;

	if (nr_iodevs == UNLIMITED_IODEVS)
		nr_iodevs = INT_MAX;

	while (pos && nr_iodevs) {
		struct iodev_snapshot *tmp = pos;
		pos = pos->is_next;

		if (!iodev_match(tmp, df))
			continue;

		list_del(&iodevs, tmp);
		insert_iodev(ss, tmp);

		--nr_iodevs;
	}

	pos = iodevs;

	/* now insert any iodevs into the remaining slots */
	while (pos && nr_iodevs) {
		struct iodev_snapshot *tmp = pos;
		pos = pos->is_next;

		if (df && df->if_skip_floppy &&
			strncmp(tmp->is_name, "fd", 2) == 0)
			continue;

		list_del(&iodevs, tmp);
		insert_iodev(ss, tmp);

		--nr_iodevs;
	}

	/* clear the unwanted ones */
	pos = iodevs;
	while (pos) {
		struct iodev_snapshot *tmp = pos;
		pos = pos->is_next;
		free_iodev(tmp);
	}
}

static int
collate_controller(struct iodev_snapshot *controller,
    struct iodev_snapshot *disk)
{
	controller->is_stats.nread += disk->is_stats.nread;
	controller->is_stats.nwritten += disk->is_stats.nwritten;
	controller->is_stats.reads += disk->is_stats.reads;
	controller->is_stats.writes += disk->is_stats.writes;
	controller->is_stats.wtime += disk->is_stats.wtime;
	controller->is_stats.wlentime += disk->is_stats.wlentime;
	controller->is_stats.rtime += disk->is_stats.rtime;
	controller->is_stats.rlentime += disk->is_stats.rlentime;
	controller->is_crtime += disk->is_crtime;
	controller->is_snaptime += disk->is_snaptime;
	if (kstat_add(&disk->is_errors, &controller->is_errors))
		return (errno);
	return (0);
}

static int
acquire_iodev_stats(struct iodev_snapshot *list, kstat_ctl_t *kc)
{
	struct iodev_snapshot *pos;
	int err = 0;

	for (pos = list; pos; pos = pos->is_next) {
		/* controllers don't have stats (yet) */
		if (pos->is_ksp != NULL) {
			if (kstat_read(kc, pos->is_ksp, &pos->is_stats) == -1)
				return (errno);
			/* make sure crtime/snaptime is updated */
			pos->is_crtime = pos->is_ksp->ks_crtime;
			pos->is_snaptime = pos->is_ksp->ks_snaptime;
		}

		if ((err = acquire_iodev_stats(pos->is_children, kc)))
			return (err);

		if (pos->is_type == IODEV_CONTROLLER) {
			struct iodev_snapshot *pos2 = pos->is_children;

			for (; pos2; pos2 = pos2->is_next) {
				if ((err = collate_controller(pos, pos2)))
					return (err);
			}
		}
	}

	return (0);
}

static int
acquire_iodev_errors(struct snapshot *ss, kstat_ctl_t *kc)
{
	kstat_t *ksp;

	if (!(ss->s_types && SNAP_IODEV_ERRORS))
		return (0);

	for (ksp = kc->kc_chain; ksp; ksp = ksp->ks_next) {
		char kstat_name[KSTAT_STRLEN];
		char *dname = kstat_name;
		char *ename = ksp->ks_name;
		struct iodev_snapshot *iodev;

		if (ksp->ks_type != KSTAT_TYPE_NAMED)
			continue;
		if (strncmp(ksp->ks_class, "device_error", 12) != 0 &&
		    strncmp(ksp->ks_class, "iopath_error", 12) != 0)
			continue;

		/*
		 * Some drivers may not follow the naming convention
		 * for error kstats (i.e., drivername,err) so
		 * be sure we don't walk off the end.
		 */
		while (*ename && *ename != ',') {
			*dname = *ename;
			dname++;
			ename++;
		}
		*dname = '\0';

		iodev = find_iodev_by_name(ss->s_iodevs, kstat_name);

		if (iodev == NULL)
			continue;

		if (kstat_read(kc, ksp, NULL) == -1)
			return (errno);
		if (kstat_copy(ksp, &iodev->is_errors) == -1)
			return (errno);
	}

	return (0);
}

static void
get_ids(struct iodev_snapshot *iodev, const char *pretty)
{
	int ctr, disk, slice, ret;
	char *target;
	const char *p1;
	const char *p2;

	if (pretty == NULL)
		return;

	if (sscanf(pretty, "c%d", &ctr) != 1)
		return;

	p1 = pretty;
	while (*p1 && *p1 != 't')
		++p1;

	if (!*p1)
		return;
	++p1;

	p2 = p1;
	while (*p2 && *p2 != 'd')
		++p2;

	if (!*p2 || p2 == p1)
		return;

	target = safe_alloc(1 + p2 - p1);
	(void) strlcpy(target, p1, 1 + p2 - p1);

	ret = sscanf(p2, "d%d%*[sp]%d", &disk, &slice);

	if (ret == 2 && iodev->is_type == IODEV_PARTITION) {
		iodev->is_id.id = slice;
		iodev->is_parent_id.id = disk;
		(void) strlcpy(iodev->is_parent_id.tid, target, KSTAT_STRLEN);
	} else if (ret == 1) {
		if (iodev->is_type == IODEV_DISK) {
			iodev->is_id.id = disk;
			(void) strlcpy(iodev->is_id.tid, target, KSTAT_STRLEN);
			iodev->is_parent_id.id = ctr;
		} else if (iodev->is_type == IODEV_IOPATH) {
			iodev->is_parent_id.id = disk;
			(void) strlcpy(iodev->is_parent_id.tid,
				target, KSTAT_STRLEN);
		}
	}

	free(target);
}

static char *
get_slice(int partition, disk_list_t *dl)
{
	char *tmpbuf;
	size_t tmplen;

	if (!(dl->flags & SLICES_OK))
		return (NULL);
	if (partition < 0 || partition >= NDKMAP)
		return (NULL);

	/* space for 's', and integer < NDKMAP (16) */
	tmplen = strlen(dl->dsk) + strlen("sXX") + 1;
	tmpbuf = safe_alloc(tmplen);

	/*
	 * This is a regular slice. Create the name and
	 * copy it for use by the calling routine.
	 */
	(void) snprintf(tmpbuf, tmplen, "%ss%d", dl->dsk, partition);
	return (tmpbuf);
}

static char *
get_intel_partition(int partition, disk_list_t *dl)
{
	char *tmpbuf;
	size_t tmplen;

	if (partition <= 0 || !(dl->flags & PARTITIONS_OK))
		return (NULL);

	/*
	 * See if it falls in the range of allowable partitions. The
	 * fdisk partitions show up after the traditional slices so we
	 * determine which partition we're in and return that.
	 * The NUMPART + 1 is not a mistake. There are currently
	 * FD_NUMPART + 1 partitions that show up in the device directory.
	 */
	partition -= NDKMAP;
	if (partition < 0 || partition >= (FD_NUMPART + 1))
		return (NULL);

	/* space for 'p', and integer < NDKMAP (16) */
	tmplen = strlen(dl->dsk) + strlen("pXX") + 1;
	tmpbuf = safe_alloc(tmplen);

	(void) snprintf(tmpbuf, tmplen, "%sp%d", dl->dsk, partition);
	return (tmpbuf);
}

static void
get_pretty_name(enum snapshot_types types, struct iodev_snapshot *iodev,
	kstat_ctl_t *kc)
{
	disk_list_t *dl;
	char *pretty = NULL;
	char *tmp;
	int partition;

	if (iodev->is_type == IODEV_NFS) {
		if (!(types & SNAP_IODEV_PRETTY))
			return;

		iodev->is_pretty = lookup_nfs_name(iodev->is_name, kc);
		return;
	}

	if (iodev->is_type == IODEV_IOPATH) {
		char buf[KSTAT_STRLEN];
		size_t len;

		tmp = iodev->is_name;
		while (*tmp && *tmp != '.')
			tmp++;
		if (!*tmp)
			return;
		(void) strlcpy(buf, iodev->is_name, 1 + tmp - iodev->is_name);
		dl = lookup_ks_name(buf, (types & SNAP_IODEV_DEVID) ? 1 : 0);
		if (dl == NULL || dl->dsk == NULL)
			return;
		len = strlen(dl->dsk) + strlen(tmp) + 1;
		pretty = safe_alloc(len);
		(void) strlcpy(pretty, dl->dsk, len);
		(void) strlcat(pretty, tmp, len);
		goto out;
	}

	dl = lookup_ks_name(iodev->is_name, (types & SNAP_IODEV_DEVID) ? 1 : 0);
	if (dl == NULL)
		return;

	if (dl->dsk)
		pretty = safe_strdup(dl->dsk);

	if (types & SNAP_IODEV_PRETTY) {
		if (dl->dname)
			iodev->is_dname = safe_strdup(dl->dname);
	}

	if (dl->devidstr)
		iodev->is_devid = safe_strdup(dl->devidstr);

	/* look for a possible partition number */
	tmp = iodev->is_name;
	while (*tmp && *tmp != ',')
		tmp++;
	if (*tmp != ',')
		goto out;

	tmp++;
	partition = (int)(*tmp - 'a');

	if (iodev->is_type == IODEV_PARTITION) {
		char *part;
		if ((part = get_slice(partition, dl)) == NULL)
			part = get_intel_partition(partition, dl);
		if (part != NULL) {
			free(pretty);
			pretty = part;
		}
	}

out:
	get_ids(iodev, pretty);

	/* only fill in the pretty name if specifically asked for */
	if (types & SNAP_IODEV_PRETTY) {
		iodev->is_pretty = pretty;
	} else {
		free(pretty);
	}
}

static enum iodev_type
get_iodev_type(kstat_t *ksp)
{
	if (strcmp(ksp->ks_class, "disk") == 0)
		return (IODEV_DISK);
	if (strcmp(ksp->ks_class, "partition") == 0)
		return (IODEV_PARTITION);
	if (strcmp(ksp->ks_class, "nfs") == 0)
		return (IODEV_NFS);
	if (strcmp(ksp->ks_class, "iopath") == 0)
		return (IODEV_IOPATH);
	if (strcmp(ksp->ks_class, "tape") == 0)
		return (IODEV_TAPE);
	return (IODEV_UNKNOWN);
}

int
iodev_cmp(struct iodev_snapshot *io1, struct iodev_snapshot *io2)
{
	/* neutral sort order between disk and part */
	if (!disk_or_partition(io1->is_type) ||
		!disk_or_partition(io2->is_type)) {
		if (io1->is_type < io2->is_type)
			return (-1);
		if (io1->is_type > io2->is_type)
			return (1);
	}

	/* controller doesn't have ksp */
	if (io1->is_ksp && io2->is_ksp) {
		if (strcmp(io1->is_module, io2->is_module) != 0)
			return (strcmp(io1->is_module, io2->is_module));
		if (io1->is_instance < io2->is_instance)
			return (-1);
		if (io1->is_instance > io2->is_instance)
			return (1);
	} else {
		if (io1->is_id.id < io2->is_id.id)
			return (-1);
		if (io1->is_id.id > io2->is_id.id)
			return (1);
	}

	return (strcmp(io1->is_name, io2->is_name));
}

int
acquire_iodevs(struct snapshot *ss, kstat_ctl_t *kc, struct iodev_filter *df)
{
	kstat_t *ksp;
	int err = 0;
	struct iodev_snapshot *pos;
	struct iodev_snapshot *list = NULL;

	ss->s_nr_iodevs = 0;

	/*
	 * Call cleanup_iodevs_snapshot() so that a cache miss in
	 * lookup_ks_name() will result in a fresh snapshot.
	 */
	cleanup_iodevs_snapshot();

	for (ksp = kc->kc_chain; ksp; ksp = ksp->ks_next) {
		enum iodev_type type;

		if (ksp->ks_type != KSTAT_TYPE_IO)
			continue;

		/* e.g. "usb_byte_count" is not handled */
		if ((type = get_iodev_type(ksp)) == IODEV_UNKNOWN)
			continue;

		if (df && !(type & df->if_allowed_types))
			continue;

		if ((pos = malloc(sizeof (struct iodev_snapshot))) == NULL) {
			err = errno;
			goto out;
		}

		(void) memset(pos, 0, sizeof (struct iodev_snapshot));

		pos->is_type = type;
		pos->is_crtime = ksp->ks_crtime;
		pos->is_snaptime = ksp->ks_snaptime;
		pos->is_id.id = IODEV_NO_ID;
		pos->is_parent_id.id = IODEV_NO_ID;
		pos->is_ksp = ksp;
		pos->is_instance = ksp->ks_instance;

		(void) strlcpy(pos->is_module, ksp->ks_module, KSTAT_STRLEN);
		(void) strlcpy(pos->is_name, ksp->ks_name, KSTAT_STRLEN);
		get_pretty_name(ss->s_types, pos, kc);

		/*
		 * We must insert in sort order so e.g. vmstat -l
		 * chooses in order.
		 */
		insert_into(&list, pos);
	}

	choose_iodevs(ss, list, df);

	/* before acquire_stats for collate_controller()'s benefit */
	if (ss->s_types & SNAP_IODEV_ERRORS) {
		if ((err = acquire_iodev_errors(ss, kc)) != 0)
			goto out;
	}

	if ((err = acquire_iodev_stats(ss->s_iodevs, kc)) != 0)
		goto out;

	err = 0;
out:
	return (err);
}

void
free_iodev(struct iodev_snapshot *iodev)
{
	while (iodev->is_children) {
		struct iodev_snapshot *tmp = iodev->is_children;
		iodev->is_children = iodev->is_children->is_next;
		free_iodev(tmp);
	}

	free(iodev->is_errors.ks_data);
	free(iodev->is_pretty);
	free(iodev->is_dname);
	free(iodev->is_devid);
	free(iodev);
}
