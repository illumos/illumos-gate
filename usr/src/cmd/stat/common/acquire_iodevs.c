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
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include "statcommon.h"
#include "dsr.h"

#include <sys/dklabel.h>
#include <sys/dktp/fdisk.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stddef.h>
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
		case IODEV_IOPATH_LT: return (0);
		case IODEV_IOPATH_LI: return (0);
		case IODEV_NFS: return (0);
		case IODEV_TAPE: return (0);
		case IODEV_IOPATH_LTI: return (IODEV_DISK);
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

/*
 * Introduce an index into the list to speed up insert_into looking for the
 * right position in the list. This index is an AVL tree of all the
 * iodev_snapshot in the list.
 */
static int
avl_iodev_cmp(const void* is1, const void* is2)
{
	int c = iodev_cmp((struct iodev_snapshot *)is1,
	    (struct iodev_snapshot *)is2);

	if (c > 0)
		return (1);

	if (c < 0)
		return (-1);

	return (0);
}

static void
ix_new_list(struct iodev_snapshot *elem)
{
	avl_tree_t *l = malloc(sizeof (avl_tree_t));

	elem->avl_list = l;
	if (l == NULL)
		return;

	avl_create(l, avl_iodev_cmp, sizeof (struct iodev_snapshot),
	    offsetof(struct iodev_snapshot, avl_link));

	avl_add(l, elem);
}

static void
ix_list_del(struct iodev_snapshot *elem)
{
	avl_tree_t *l = elem->avl_list;

	if (l == NULL)
		return;

	elem->avl_list = NULL;

	avl_remove(l, elem);
	if (avl_numnodes(l) == 0) {
		avl_destroy(l);
		free(l);
	}
}

static void
ix_insert_here(struct iodev_snapshot *pos, struct iodev_snapshot *elem, int ba)
{
	avl_tree_t *l = pos->avl_list;
	elem->avl_list = l;

	if (l == NULL)
		return;

	avl_insert_here(l, elem, pos, ba);
}

static void
list_del(struct iodev_snapshot **list, struct iodev_snapshot *pos)
{
	ix_list_del(pos);

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
		ix_new_list(new);
		return;
	}

	new->is_next = pos;
	new->is_prev = pos->is_prev;
	if (pos->is_prev)
		pos->is_prev->is_next = new;
	else
		*list = new;
	pos->is_prev = new;

	ix_insert_here(pos, new, AVL_BEFORE);
}

static void
insert_after(struct iodev_snapshot **list, struct iodev_snapshot *pos,
    struct iodev_snapshot *new)
{
	if (pos == NULL) {
		new->is_prev = new->is_next = NULL;
		*list = new;
		ix_new_list(new);
		return;
	}

	new->is_next = pos->is_next;
	new->is_prev = pos;
	if (pos->is_next)
		pos->is_next->is_prev = new;
	pos->is_next = new;

	ix_insert_here(pos, new, AVL_AFTER);
}

static void
insert_into(struct iodev_snapshot **list, struct iodev_snapshot *iodev)
{
	struct iodev_snapshot *tmp = *list;
	avl_tree_t *l;
	void *p;
	avl_index_t where;

	if (*list == NULL) {
		*list = iodev;
		ix_new_list(iodev);
		return;
	}

	/*
	 * Optimize the search: instead of walking the entire list
	 * (which can contain thousands of nodes), search in the AVL
	 * tree the nearest node and reposition the startup point to
	 * this node rather than always starting from the beginning
	 * of the list.
	 */
	l = tmp->avl_list;
	if (l != NULL) {
		p = avl_find(l, iodev, &where);
		if (p == NULL) {
			p = avl_nearest(l, where, AVL_BEFORE);
		}
		if (p != NULL) {
			tmp = (struct iodev_snapshot *)p;
		}
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

static int
disk_or_partition_or_iopath(enum iodev_type type)
{
	return (type == IODEV_DISK || type == IODEV_PARTITION ||
	    type == IODEV_IOPATH_LTI);
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

/* return 1 if dev passes filter */
static int
iodev_match(struct iodev_snapshot *dev, struct iodev_filter *df)
{
	int	is_floppy = (strncmp(dev->is_name, "fd", 2) == 0);
	char	*isn, *ispn, *ifn;
	char	*path;
	int	ifnl;
	size_t	i;

	/* no filter, pass */
	if (df == NULL)
		return (1);		/* pass */

	/* no filtered names, pass if not floppy and skipped */
	if (df->if_nr_names == NULL)
		return (!(df->if_skip_floppy && is_floppy));

	isn = dev->is_name;
	ispn = dev->is_pretty;
	for (i = 0; i < df->if_nr_names; i++) {
		ifn = df->if_names[i];
		ifnl = strlen(ifn);
		path = strchr(ifn, '.');

		if ((strcmp(isn, ifn) == 0) ||
		    (ispn && (strcmp(ispn, ifn) == 0)))
			return (1);	/* pass */

		/* if filter is a path allow partial match */
		if (path &&
		    ((strncmp(isn, ifn, ifnl) == 0) ||
		    (ispn && (strncmp(ispn, ifn, ifnl) == 0))))
			return (1);	/* pass */
	}

	return (0);			/* fail */
}

/* return 1 if path is an mpxio path associated with dev */
static int
iodev_path_match(struct iodev_snapshot *dev, struct iodev_snapshot *path)
{
	char	*dn, *pn;
	int	dnl;

	dn = dev->is_name;
	pn = path->is_name;
	dnl = strlen(dn);

	if ((strncmp(pn, dn, dnl) == 0) && (pn[dnl] == '.'))
		return (1);			/* yes */

	return (0);				/* no */
}

/* select which I/O devices to collect stats for */
static void
choose_iodevs(struct snapshot *ss, struct iodev_snapshot *iodevs,
    struct iodev_filter *df)
{
	struct iodev_snapshot	*pos, *ppos, *tmp, *ptmp;
	int			nr_iodevs;
	int			nr_iodevs_orig;

	nr_iodevs = df ? df->if_max_iodevs : UNLIMITED_IODEVS;
	nr_iodevs_orig = nr_iodevs;

	if (nr_iodevs == UNLIMITED_IODEVS)
		nr_iodevs = INT_MAX;

	/* add the full matches */
	pos = iodevs;
	while (pos && nr_iodevs) {
		tmp = pos;
		pos = pos->is_next;

		if (!iodev_match(tmp, df))
			continue;	/* failed full match */

		list_del(&iodevs, tmp);
		insert_iodev(ss, tmp);

		/*
		 * Add all mpxio paths associated with match above. Added
		 * paths don't count against nr_iodevs.
		 */
		if (strchr(tmp->is_name, '.') == NULL) {
		ppos = iodevs;
		while (ppos) {
			ptmp = ppos;
			ppos = ppos->is_next;

			if (!iodev_path_match(tmp, ptmp))
				continue;	/* not an mpxio path */

			list_del(&iodevs, ptmp);
			insert_iodev(ss, ptmp);
			if (pos == ptmp)
				pos = ppos;
		}
		}

		nr_iodevs--;
	}

	/*
	 * If we had a filter, and *nothing* passed the filter then we
	 * don't want to fill the  remaining slots - it is just confusing
	 * if we don that, it makes it look like the filter code is broken.
	 */
	if ((df->if_nr_names == NULL) || (nr_iodevs != nr_iodevs_orig)) {
		/* now insert any iodevs into the remaining slots */
		pos = iodevs;
		while (pos && nr_iodevs) {
			tmp = pos;
			pos = pos->is_next;

			if (df && df->if_skip_floppy &&
			    strncmp(tmp->is_name, "fd", 2) == 0)
				continue;

			list_del(&iodevs, tmp);
			insert_iodev(ss, tmp);

			--nr_iodevs;
		}
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
		} else if (iodev->is_type == IODEV_IOPATH_LTI) {
			iodev->is_parent_id.id = disk;
			(void) strlcpy(iodev->is_parent_id.tid,
			    target, KSTAT_STRLEN);
		}
	}

	free(target);
}

static void
get_pretty_name(enum snapshot_types types, struct iodev_snapshot *iodev,
	kstat_ctl_t *kc)
{
	disk_list_t	*dl;
	char		*pretty = NULL;

	if (iodev->is_type == IODEV_NFS) {
		if (!(types & SNAP_IODEV_PRETTY))
			return;

		iodev->is_pretty = lookup_nfs_name(iodev->is_name, kc);
		return;
	}

	/* lookup/translate the kstat name */
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

	get_ids(iodev, pretty);

	/*
	 * we fill in pretty name wether it is asked for or not because
	 * it could be used in a filter by match_iodevs.
	 */
	iodev->is_pretty = pretty;
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
		return (IODEV_IOPATH_LTI);
	if (strcmp(ksp->ks_class, "tape") == 0)
		return (IODEV_TAPE);
	return (IODEV_UNKNOWN);
}

/* get the lun/target/initiator from the name, return 1 on success */
static int
get_lti(char *s,
	char *lname, int *l, char *tname, int *t, char *iname, int *i)
{
	int  num = 0;

	num = sscanf(s, "%[a-z]%d%*[.]%[a-z]%d%*[.]%[a-z_]%d", lname, l,
	    tname, t, iname, i);
	return ((num == 6) ? 1 : 0);
}


/* get the lun, target, and initiator name and instance */
static void
get_path_info(struct iodev_snapshot *io, char *mod, size_t modlen, int *type,
    int *inst, char *name, size_t size)
{

	/*
	 * If it is iopath or ssd then pad the name with i/t/l so we can sort
	 * by alpha order and set type for IOPATH to DISK since we want to
	 * have it grouped with its ssd parent. The lun can be 5 digits,
	 * the target can be 4 digits, and the initiator can be 3 digits and
	 * the padding is done appropriately for string comparisons.
	 */
	if (disk_or_partition_or_iopath(io->is_type)) {
		int i1, t1, l1;
		char tname[KSTAT_STRLEN], iname[KSTAT_STRLEN];
		char *ptr, lname[KSTAT_STRLEN];

		i1 = t1 = l1 = 0;
		(void) get_lti(io->is_name, lname, &l1, tname, &t1, iname, &i1);
		*type = io->is_type;
		if (io->is_type == IODEV_DISK) {
			(void) snprintf(name, size, "%s%05d", lname, l1);
		} else if (io->is_type == IODEV_PARTITION) {
			ptr = strchr(io->is_name, ',');
			(void) snprintf(name, size, "%s%05d%s", lname, l1, ptr);
		} else {
			(void) snprintf(name, size, "%s%05d.%s%04d.%s%03d",
			    lname, l1, tname, t1, iname, i1);
			/* set to disk so we sort with disks */
			*type = IODEV_DISK;
		}
		(void) strlcpy(mod, lname, modlen);
		*inst = l1;
	} else {
		(void) strlcpy(mod, io->is_module, modlen);
		(void) strlcpy(name, io->is_name, size);
		*type = io->is_type;
		*inst = io->is_instance;
	}
}

int
iodev_cmp(struct iodev_snapshot *io1, struct iodev_snapshot *io2)
{
	int	type1, type2;
	int	inst1, inst2;
	char	name1[KSTAT_STRLEN], name2[KSTAT_STRLEN];
	char	mod1[KSTAT_STRLEN], mod2[KSTAT_STRLEN];

	get_path_info(io1, mod1, sizeof (mod1), &type1, &inst1, name1,
	    sizeof (name1));
	get_path_info(io2, mod2, sizeof (mod2), &type2, &inst2, name2,
	    sizeof (name2));
	if ((!disk_or_partition(type1)) ||
	    (!disk_or_partition(type2))) {
		/* neutral sort order between disk and part */
		if (type1 < type2) {
			return (-1);
		}
		if (type1 > type2) {
			return (1);
		}
	}

	/* controller doesn't have ksp */
	if (io1->is_ksp && io2->is_ksp) {
		if (strcmp(mod1, mod2) != 0) {
			return (strcmp(mod1, mod2));
		}
		if (inst1 < inst2) {
			return (-1);
		}
		if (inst1 > inst2) {
			return (1);
		}
	} else {
		if (io1->is_id.id < io2->is_id.id) {
			return (-1);
		}
		if (io1->is_id.id > io2->is_id.id) {
			return (1);
		}
	}

	return (strcmp(name1, name2));
}

/* update the target reads and writes */
static void
update_target(struct iodev_snapshot *tgt, struct iodev_snapshot *path)
{
	tgt->is_stats.reads += path->is_stats.reads;
	tgt->is_stats.writes += path->is_stats.writes;
	tgt->is_stats.nread += path->is_stats.nread;
	tgt->is_stats.nwritten += path->is_stats.nwritten;
	tgt->is_stats.wcnt += path->is_stats.wcnt;
	tgt->is_stats.rcnt += path->is_stats.rcnt;

	/*
	 * Stash the t_delta in the crtime for use in show_disk
	 * NOTE: this can't be done in show_disk because the
	 * itl entry is removed for the old format
	 */
	tgt->is_crtime += hrtime_delta(path->is_crtime, path->is_snaptime);
	tgt->is_snaptime += path->is_snaptime;
	tgt->is_nr_children += 1;
}

/*
 * Create a new synthetic device entry of the specified type. The supported
 * synthetic types are IODEV_IOPATH_LT and IODEV_IOPATH_LI.
 */
static struct iodev_snapshot *
make_extended_device(int type, struct iodev_snapshot *old)
{
	struct iodev_snapshot	*tptr = NULL;
	char			*ptr;
	int			lun, tgt, initiator;
	char			lun_name[KSTAT_STRLEN];
	char			tgt_name[KSTAT_STRLEN];
	char			initiator_name[KSTAT_STRLEN];

	if (old == NULL)
		return (NULL);
	if (get_lti(old->is_name,
	    lun_name, &lun, tgt_name, &tgt, initiator_name, &initiator) != 1) {
		return (NULL);
	}
	tptr = safe_alloc(sizeof (*old));
	bzero(tptr, sizeof (*old));
	if (old->is_pretty != NULL) {
		tptr->is_pretty = safe_alloc(strlen(old->is_pretty) + 1);
		(void) strcpy(tptr->is_pretty, old->is_pretty);
	}
	bcopy(&old->is_parent_id, &tptr->is_parent_id,
	    sizeof (old->is_parent_id));

	tptr->is_type = type;

	if (type == IODEV_IOPATH_LT) {
		/* make new synthetic entry that is the LT */
		/* set the id to the target id */
		tptr->is_id.id = tgt;
		(void) snprintf(tptr->is_id.tid, sizeof (tptr->is_id.tid),
		    "%s%d", tgt_name, tgt);
		(void) snprintf(tptr->is_name, sizeof (tptr->is_name),
		    "%s%d.%s%d", lun_name, lun, tgt_name, tgt);

		if (old->is_pretty) {
			ptr = strrchr(tptr->is_pretty, '.');
			if (ptr)
				*ptr = '\0';
		}
	} else if (type == IODEV_IOPATH_LI) {
		/* make new synthetic entry that is the LI */
		/* set the id to the initiator number */
		tptr->is_id.id = initiator;
		(void) snprintf(tptr->is_id.tid, sizeof (tptr->is_id.tid),
		    "%s%d", initiator_name, initiator);
		(void) snprintf(tptr->is_name, sizeof (tptr->is_name),
		    "%s%d.%s%d", lun_name, lun, initiator_name, initiator);

		if (old->is_pretty) {
			ptr = strchr(tptr->is_pretty, '.');
			if (ptr)
				(void) snprintf(ptr + 1,
				    strlen(tptr->is_pretty) + 1,
				    "%s%d", initiator_name, initiator);
		}
	}
	return (tptr);
}

/*
 * This is to get the original -X LI format (e.g. ssd1.fp0). When an LTI kstat
 * is found - traverse the children looking for the same initiator and sum
 * them up. Add an LI entry and delete all of the LTI entries with the same
 * initiator.
 */
static int
create_li_delete_lti(struct snapshot *ss, struct iodev_snapshot *list)
{
	struct iodev_snapshot	*pos, *entry, *parent;
	int			lun, tgt, initiator;
	char			lun_name[KSTAT_STRLEN];
	char			tgt_name[KSTAT_STRLEN];
	char			initiator_name[KSTAT_STRLEN];
	int			err;

	for (entry = list; entry; entry = entry->is_next) {
		if ((err = create_li_delete_lti(ss, entry->is_children)) != 0)
			return (err);

		if (entry->is_type == IODEV_IOPATH_LTI) {
			parent = find_parent(ss, entry);
			if (get_lti(entry->is_name, lun_name, &lun,
			    tgt_name, &tgt, initiator_name, &initiator) != 1) {
				return (1);
			}

			pos = (parent == NULL) ? NULL : parent->is_children;
			for (; pos; pos = pos->is_next) {
				if (pos->is_id.id != -1 &&
				    pos->is_id.id == initiator &&
				    pos->is_type == IODEV_IOPATH_LI) {
					/* found the same initiator */
					update_target(pos, entry);
					list_del(&parent->is_children, entry);
					free_iodev(entry);
					parent->is_nr_children--;
					entry = pos;
					break;
				}
			}

			if (!pos) {
				/* make the first LI entry */
				pos = make_extended_device(
				    IODEV_IOPATH_LI, entry);
				update_target(pos, entry);

				if (parent) {
					insert_before(&parent->is_children,
					    entry, pos);
					list_del(&parent->is_children, entry);
					free_iodev(entry);
				} else {
					insert_before(&ss->s_iodevs, entry,
					    pos);
					list_del(&ss->s_iodevs, entry);
					free_iodev(entry);
				}
				entry = pos;
			}
		}
	}
	return (0);
}

/*
 * We have the LTI kstat, now add an entry for the LT that sums up all of
 * the LTI's with the same target(t).
 */
static int
create_lt(struct snapshot *ss, struct iodev_snapshot *list)
{
	struct iodev_snapshot	*entry, *parent, *pos;
	int			lun, tgt, initiator;
	char			lun_name[KSTAT_STRLEN];
	char			tgt_name[KSTAT_STRLEN];
	char			initiator_name[KSTAT_STRLEN];
	int			err;

	for (entry = list; entry; entry = entry->is_next) {
		if ((err = create_lt(ss, entry->is_children)) != 0)
			return (err);

		if (entry->is_type == IODEV_IOPATH_LTI) {
			parent = find_parent(ss, entry);
			if (get_lti(entry->is_name, lun_name, &lun,
			    tgt_name, &tgt, initiator_name, &initiator) != 1) {
				return (1);
			}

			pos = (parent == NULL) ? NULL : parent->is_children;
			for (; pos; pos = pos->is_next) {
				if (pos->is_id.id != -1 &&
				    pos->is_id.id == tgt &&
				    pos->is_type == IODEV_IOPATH_LT) {
					/* found the same target */
					update_target(pos, entry);
					break;
				}
			}

			if (!pos) {
				pos = make_extended_device(
				    IODEV_IOPATH_LT, entry);
				update_target(pos, entry);

				if (parent) {
					insert_before(&parent->is_children,
					    entry, pos);
					parent->is_nr_children++;
				} else {
					insert_before(&ss->s_iodevs,
					    entry, pos);
				}
			}
		}
	}
	return (0);
}

/* Find the longest is_name field to aid formatting of output */
static int
iodevs_is_name_maxlen(struct iodev_snapshot *list)
{
	struct iodev_snapshot	*entry;
	int			max = 0, cmax, len;

	for (entry = list; entry; entry = entry->is_next) {
		cmax = iodevs_is_name_maxlen(entry->is_children);
		max = (cmax > max) ? cmax : max;
		len = strlen(entry->is_name);
		max = (len > max) ? len : max;
	}
	return (max);
}

int
acquire_iodevs(struct snapshot *ss, kstat_ctl_t *kc, struct iodev_filter *df)
{
	kstat_t	*ksp;
	struct	iodev_snapshot *pos;
	struct	iodev_snapshot *list = NULL;
	int	err = 0;

	ss->s_nr_iodevs = 0;
	ss->s_iodevs_is_name_maxlen = 0;

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

	if (ss->s_types & SNAP_IOPATHS_LTI) {
		/*
		 * -Y: kstats are LTI, need to create a synthetic LT
		 * for -Y output.
		 */
		if ((err = create_lt(ss, ss->s_iodevs)) != 0) {
			return (err);
		}
	}
	if (ss->s_types & SNAP_IOPATHS_LI) {
		/*
		 * -X: kstats are LTI, need to create a synthetic LI and
		 * delete the LTI for -X output
		 */
		if ((err = create_li_delete_lti(ss, ss->s_iodevs)) != 0) {
			return (err);
		}
	}

	/* determine width of longest is_name */
	ss->s_iodevs_is_name_maxlen = iodevs_is_name_maxlen(ss->s_iodevs);

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

	if (iodev->avl_list) {
		avl_remove(iodev->avl_list, iodev);
		if (avl_numnodes(iodev->avl_list) == 0) {
			avl_destroy(iodev->avl_list);
			free(iodev->avl_list);
		}
	}

	free(iodev->is_errors.ks_data);
	free(iodev->is_pretty);
	free(iodev->is_dname);
	free(iodev->is_devid);
	free(iodev);
}
