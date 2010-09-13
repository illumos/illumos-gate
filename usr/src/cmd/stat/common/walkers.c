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

#include <string.h>
#include <errno.h>

/* max size of report change annotations */
#define	LIST_SIZE 512

static char cpus_added[LIST_SIZE];
static char cpus_removed[LIST_SIZE];

static int
cpu_walk(struct snapshot *old, struct snapshot *new,
    snapshot_cb cb, void *data)
{
	int changed = 0;
	int i;

	/* CPUs can change state but not re-order */
	for (i = 0; i < new->s_nr_cpus; i++) {
		struct cpu_snapshot *cpu = NULL;
		struct cpu_snapshot *newcpu = &new->s_cpus[i];
		if (old)
			cpu = &old->s_cpus[i];
		cb(cpu, newcpu, data);
		if (cpu == NULL)
			changed = 1;
		else {
			/*
			 * We only care about off/on line transitions
			 */
			if ((CPU_ACTIVE(cpu) && !CPU_ACTIVE(newcpu)) ||
			    (!CPU_ACTIVE(cpu) && CPU_ACTIVE(newcpu)))
				changed = 1;
			if ((new->s_types & SNAP_PSETS) &&
				cpu->cs_pset_id != newcpu->cs_pset_id)
				changed = 1;
		}

	}

	return (changed);
}

static int
pset_walk(struct snapshot *old, struct snapshot *new,
    snapshot_cb cb, void *data)
{
	int i = 0;
	int j = 0;
	int changed = 0;

	while (old && i < old->s_nr_psets && j < new->s_nr_psets) {
		if (old->s_psets[i].ps_id < new->s_psets[j].ps_id) {
			cb(&old->s_psets[i], NULL, data);
			i++;
			changed = 1;
		} else if (old->s_psets[i].ps_id > new->s_psets[j].ps_id) {
			cb(NULL, &new->s_psets[j], data);
			j++;
			changed = 1;
		} else {
			cb(&old->s_psets[i], &new->s_psets[j], data);
			i++;
			j++;
		}
	}

	while (old && i < old->s_nr_psets) {
		cb(&old->s_psets[i], NULL, data);
		i++;
		changed = 1;
	}

	while (j < new->s_nr_psets) {
		cb(NULL, &new->s_psets[j], data);
		j++;
		changed = 1;
	}

	return (changed);
}

static int
iodev_walk(struct iodev_snapshot *d1, struct iodev_snapshot *d2,
    snapshot_cb cb, void *data)
{
	int changed = 0;

	while (d1 && d2) {
		if (strcmp(d1->is_name, d2->is_name) < 0) {
			changed = 1;
			cb(d1, NULL, data);
			(void) iodev_walk(d1->is_children, NULL, cb, data);
			d1 = d1->is_next;
		} else if (strcmp(d1->is_name, d2->is_name) > 0) {
			changed = 1;
			cb(NULL, d2, data);
			(void) iodev_walk(NULL, d2->is_children, cb, data);
			d2 = d2->is_next;
		} else {
			cb(d1, d2, data);
			changed |= iodev_walk(d1->is_children,
					d2->is_children, cb, data);
			d1 = d1->is_next;
			d2 = d2->is_next;
		}
	}

	while (d1) {
		changed = 1;
		cb(d1, NULL, data);
		(void) iodev_walk(d1->is_children, NULL, cb, data);
		d1 = d1->is_next;
	}

	while (d2) {
		changed = 1;
		cb(NULL, d2, data);
		(void) iodev_walk(NULL, d2->is_children, cb, data);
		d2 = d2->is_next;
	}

	return (changed);
}

int
snapshot_walk(enum snapshot_types type, struct snapshot *old,
    struct snapshot *new, snapshot_cb cb, void *data)
{
	int changed = 0;

	switch (type) {
	case SNAP_CPUS:
		changed = cpu_walk(old, new, cb, data);
		break;

	case SNAP_PSETS:
		changed = pset_walk(old, new, cb, data);
		break;

	case SNAP_CONTROLLERS:
	case SNAP_IODEVS:
	case SNAP_IOPATHS_LI:
	case SNAP_IOPATHS_LTI:
		changed = iodev_walk(old ? old->s_iodevs : NULL,
		    new->s_iodevs, cb, data);
		break;

	default:
		break;
	}

	return (changed);
}

static void
add_nr_to_list(char *buf, unsigned long nr)
{
	char tmp[LIST_SIZE];

	(void) snprintf(tmp, LIST_SIZE, "%lu", nr);

	if (strlen(buf))
		(void) strlcat(buf, ", ", LIST_SIZE);

	(void) strlcat(buf, tmp, LIST_SIZE);
}

static void
cpu_report(void *v1, void *v2, void *data)
{
	int *pset = (int *)data;
	struct cpu_snapshot *c1 = (struct cpu_snapshot *)v1;
	struct cpu_snapshot *c2 = (struct cpu_snapshot *)v2;

	if (*pset && c1->cs_pset_id != c2->cs_pset_id) {
		(void) printf("<<processor %d moved from pset: %d to: %d>>\n",
		    c1->cs_id, c1->cs_pset_id, c2->cs_pset_id);
	}

	if (c1->cs_state == c2->cs_state)
		return;

	if (CPU_ONLINE(c1->cs_state) && !CPU_ONLINE(c2->cs_state))
		add_nr_to_list(cpus_removed, c1->cs_id);

	if (!CPU_ONLINE(c1->cs_state) && CPU_ONLINE(c2->cs_state))
		add_nr_to_list(cpus_added, c2->cs_id);
}

/*ARGSUSED*/
static void
pset_report(void *v1, void *v2, void *data)
{
	struct pset_snapshot *p1 = (struct pset_snapshot *)v1;
	struct pset_snapshot *p2 = (struct pset_snapshot *)v2;

	if (p2 == NULL) {
		(void) printf("<<pset destroyed: %u>>\n", p1->ps_id);
		return;
	}

	if (p1 == NULL)
		(void) printf("<<pset created: %u>>\n", p2->ps_id);
}

static void
get_child_list(struct iodev_snapshot *iodev, char *buf)
{
	char tmp[LIST_SIZE];
	struct iodev_snapshot *pos = iodev->is_children;

	while (pos) {
		if (pos->is_type == IODEV_PARTITION) {
			add_nr_to_list(buf, pos->is_id.id);
		} else if (pos->is_type == IODEV_DISK) {
			if (strlen(buf))
				(void) strlcat(buf, ", ", LIST_SIZE);
			(void) strlcat(buf, "t", LIST_SIZE);
			(void) strlcat(buf, pos->is_id.tid, LIST_SIZE);
			(void) strlcat(buf, "d", LIST_SIZE);
			*tmp = '\0';
			add_nr_to_list(tmp, pos->is_id.id);
			(void) strlcat(buf, tmp, LIST_SIZE);
		}
		pos = pos->is_next;
	}
}

static void
iodev_changed(struct iodev_snapshot *iodev, int added)
{
	char tmp[LIST_SIZE];
	int is_disk = iodev->is_type == IODEV_DISK;
	char *name = iodev->is_name;

	if (iodev->is_pretty)
		name = iodev->is_pretty;

	switch (iodev->is_type) {
	case IODEV_IOPATH_LT:
	case IODEV_IOPATH_LI:
	case IODEV_IOPATH_LTI:
		(void) printf("<<multi-path %s: %s>>\n",
		    added ? "added" : "removed", name);
		break;
	case IODEV_PARTITION:
		(void) printf("<<partition %s: %s>>\n",
		    added ? "added" : "removed", name);
		break;
	case IODEV_NFS:
		(void) printf("<<NFS %s: %s>>\n",
		    added ? "mounted" : "unmounted", name);
		break;
	case IODEV_TAPE:
		(void) printf("<<device %s: %s>>\n",
		    added ? "added" : "removed", name);
		break;
	case IODEV_CONTROLLER:
	case IODEV_DISK:
		*tmp = '\0';
		get_child_list(iodev, tmp);
		(void) printf("<<%s %s: %s", is_disk ? "disk" : "controller",
		    added ? "added" : "removed", name);
		if (!*tmp) {
			(void) printf(">>\n");
			return;
		}
		(void) printf(" (%s %s)>>\n", is_disk ? "slices" : "disks",
		    tmp);
		break;
	};
}

static void
iodev_report(struct iodev_snapshot *d1, struct iodev_snapshot *d2)
{
	while (d1 && d2) {
		if (iodev_cmp(d1, d2) < 0) {
			iodev_changed(d1, 0);
			d1 = d1->is_next;
		} else if (iodev_cmp(d1, d2) > 0) {
			iodev_changed(d2, 1);
			d2 = d2->is_next;
		} else {
			iodev_report(d1->is_children, d2->is_children);
			d1 = d1->is_next;
			d2 = d2->is_next;
		}
	}

	while (d1) {
		iodev_changed(d1, 0);
		d1 = d1->is_next;
	}

	while (d2) {
		iodev_changed(d2, 1);
		d2 = d2->is_next;
	}
}

void
snapshot_report_changes(struct snapshot *old, struct snapshot *new)
{
	int pset;

	if (old == NULL || new == NULL)
		return;

	if (old->s_types != new->s_types)
		return;

	pset = old->s_types & SNAP_PSETS;

	cpus_removed[0] = '\0';
	cpus_added[0] = '\0';

	if (old->s_types & SNAP_CPUS)
		(void) snapshot_walk(SNAP_CPUS, old, new, cpu_report, &pset);

	if (cpus_added[0]) {
		(void) printf("<<processors added: %s>>\n",
		    cpus_added);
	}
	if (cpus_removed[0]) {
		(void) printf("<<processors removed: %s>>\n",
		    cpus_removed);
	}
	if (pset) {
		(void) snapshot_walk(SNAP_PSETS, old, new,
		    pset_report, NULL);
	}

	iodev_report(old->s_iodevs, new->s_iodevs);
}

/*ARGSUSED*/
static void
dummy_cb(void *v1, void *v2, void *data)
{
}

int
snapshot_has_changed(struct snapshot *old, struct snapshot *new)
{
	int ret = 0;
	int cpu_mask = SNAP_CPUS | SNAP_PSETS | SNAP_SYSTEM;
	int iodev_mask = SNAP_CONTROLLERS | SNAP_IODEVS |
			SNAP_IOPATHS_LI | SNAP_IOPATHS_LTI;

	if (old == NULL)
		return (1);

	if (new == NULL)
		return (EINVAL);

	if (old->s_types != new->s_types)
		return (EINVAL);

	if (!ret && (old->s_types & cpu_mask))
		ret = snapshot_walk(SNAP_CPUS, old, new, dummy_cb, NULL);
	if (!ret && (old->s_types & SNAP_PSETS))
		ret = snapshot_walk(SNAP_PSETS, old, new, dummy_cb, NULL);
	if (!ret && (old->s_types & iodev_mask))
		ret = snapshot_walk(SNAP_IODEVS, old, new, dummy_cb, NULL);

	return (ret);
}
