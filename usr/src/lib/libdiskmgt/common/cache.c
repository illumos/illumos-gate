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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright 2024 Sebastian Wiedenroth
 */

#include <fcntl.h>
#include <libdevinfo.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libintl.h>
#include <synch.h>
#include <sys/sunddi.h>
#include <sys/types.h>
#include <libgen.h>
#include <syslog.h>

#include "libdiskmgt.h"
#include "disks_private.h"
#include "partition.h"

#define	ALIASES		0
#define	DEVPATHS	1

/*
 * Set DM_LIBDISKMGT_DEBUG in the environment.	Two levels of debugging:
 *    1 - errors, warnings and minimal tracing information
 *    2 - verbose information
 * All output prints on stderr.
 */
int dm_debug = 0;

/* Lock protecting the cached data */
static rwlock_t		cache_lock = DEFAULTRWLOCK;
static disk_t		*disk_listp = NULL;
static controller_t	*controller_listp = NULL;
static bus_t		*bus_listp = NULL;
static int		cache_loaded = 0;

descriptor_t		*desc_listp = NULL;

static void		clear_descriptors(void *gp);
static void		clr_ctrl_disk_ptr(controller_t *cp, disk_t *dp);
static void		clr_path_disk_ptr(path_t *pp, disk_t *dp);
static void		del_drive(disk_t *dp);
static void		del_drive_by_name(char *name);
static descriptor_t	*have_desc(int type, void *gp, char *name, char *mname);
static int		initialize();
static int		make_descriptors(int type);
static int		match_disk(disk_t *oldp, disk_t *newp);
static int		match_aliases(disk_t *d1p, disk_t *d2p);
static int		match_alias(alias_t *ap, alias_t *listp);
static descriptor_t	*new_descriptor(dm_desc_type_t type, void *op,
			    char *name, char *mname);
static void		rewalk_tree();
static void		update_desc(descriptor_t *descp, disk_t *newdisksp,
			    controller_t *newctrlp, bus_t *newbusp);
static void		update_desc_busp(descriptor_t *descp, bus_t *busp);
static void		update_desc_ctrlp(descriptor_t *descp,
			    controller_t *newstrlp);
static void		update_desc_diskp(descriptor_t *descp,
			    disk_t *newdisksp);
static void		update_desc_pathp(descriptor_t *descp,
			    controller_t *newctrlp);

/*
 * We only cache some of the data that we can obtain.  For much of the data
 * (e.g. slices & disks getting repartitioned) there are no events which would
 * enable us to cache.	As more events are added we can cache more information.
 *
 * Currently we cache the information we get from the dev tree walk.  This is
 * basically the information about the drives, aliases, devpaths, controllers
 * and paths.  We do not cache any information related to media, partitions
 * or slices.
 *
 * A fundamental part of the API design is that the application can hold on
 * to a set of descriptors for an indeterminate amount of time.	 Even if the
 * application does not hold descriptors there is a window of time between the
 * call that gets the descriptor and the use of the descriptor to get more
 * information.	 Because of this, the cache design must work even if the object
 * that the descriptor refers to no longer exists.
 *
 * Given this requirement, the code implements a two level cache.  The
 * descriptors that the application gets are really pointers into the first
 * level of the cache.	This first level contains the actual descriptors.
 * These descriptors in turn refer to the objects we build from the dev tree
 * walk which represent the drives and controllers.  This is the second level
 * in the cache.
 *
 * When we update the second level of the cache (the drives and controllers)
 * we go through the first level (the descriptors) and update the pointers
 * in those descriptors to refer to the new objects in the second level.  If
 * the object that the descriptor referred to is no longer in existence, we
 * just null out the pointer in the descriptor.	 In this way the code that
 * uses the descriptors knows that the object referred to by the descriptor
 * no longer exists.
 *
 * We keep a reference count in the descriptors.  This is incremented when
 * we hand out a pointer to the descriptor and decremented when the application
 * frees the descriptor it has.	 When the reference count goes to 0 we garbage
 * collect the descriptors.  In this way we only have to update active
 * descriptors when we refresh the cache after an event.
 *
 * An example of the flow when we create descriptors:
 *    dm_get_descriptors			libdiskmgt.c
 *	drive_get_descriptors			drive.c
 *	    cache_get_descriptors		cache.c
 *		make_descriptors		cache.c
 *		    drive_make_descriptors	drive.c
 *			cache_load_desc		cache.c
 *		{update refcnts on descriptors & return them}
 *
 * The idea behind cache_get_descriptors and cache_load_desc is that we
 * seperate the act of making the descriptor within the cache (which requires
 * us to call back out to one of the object functions - drive_make_descriptors)
 * from the act of handing out the descriptor (which requires us to increment
 * the refcnt).	 In this way we keep all of the refcnt handling centralized
 * in one function instead of forcing each object to ensure it replicates
 * the refcnt handling correctly.
 *
 * Descriptors use two different kinds of indrection to refer to their
 * corresponding object.  For objects we cache (controllers, paths & drives)
 * the descriptor keeps a pointer to that object.  For objects that we
 * dynamically build, the descriptor uses a combination of a pointer to the
 * base object (usually the drive) along with a name (e.g. the media name or
 * the alias).	For objects that are based on media (e.g. a slice) we actually
 * have to maintain a pointer (to the disk) and two names (e.g. the slice name
 * and the media name which is the secondary name).
 */

void
cache_free_alias(alias_t *aliasp)
{
	slice_t	*dp;

	free(aliasp->alias);
	free(aliasp->kstat_name);
	free(aliasp->wwn);

	/* free devpaths */
	dp = aliasp->devpaths;
	while (dp != NULL) {
		slice_t	*nextp;

		nextp = dp->next;
		free(dp->devpath);
		free(dp);
		dp = nextp;
	}

	/* free orig_paths */
	dp = aliasp->orig_paths;
	while (dp != NULL) {
		slice_t	*nextp;

		nextp = dp->next;
		free(dp->devpath);
		free(dp);
		dp = nextp;
	}

	free(aliasp);
}

void
cache_free_bus(bus_t *bp)
{
	free(bp->name);
	free(bp->btype);
	free(bp->kstat_name);
	free(bp->pname);
	free(bp->controllers);
	free(bp);
}

void
cache_free_controller(controller_t *cp)
{
	free(cp->name);
	free(cp->kstat_name);
	free(cp->disks);
	if (cp->paths != NULL) {
		int i;

		for (i = 0; cp->paths[i]; i++) {
			/* free the path since it can't exist w/o the ctrlr */
			cache_free_path(cp->paths[i]);
		}
		free(cp->paths);
	}

	free(cp);
}

void
cache_free_descriptor(descriptor_t *desc)
{
	if (!cache_is_valid_desc(desc)) {
		return;
	}

	desc->refcnt--;

	if (desc->refcnt <= 0) {
		free(desc->name);
		free(desc->secondary_name);
		if (desc->prev == NULL) {
			/* this is the first descriptor, update head ptr */
			desc_listp = desc->next;
		} else {
			desc->prev->next = desc->next;
		}
		if (desc->next != NULL) {
			desc->next->prev = desc->prev;
		}
		free(desc);
	}
}

void
cache_free_descriptors(descriptor_t **desc_list)
{
	int i;

	for (i = 0; desc_list[i]; i++) {
		cache_free_descriptor(desc_list[i]);
	}

	free(desc_list);
}

void
cache_free_disk(disk_t *dp)
{
	alias_t	*ap;

	free(dp->device_id);
	if (dp->devid != NULL) {
		devid_free(dp->devid);
	}
	free(dp->kernel_name);
	free(dp->product_id);
	free(dp->vendor_id);
	free(dp->controllers);
	free(dp->serial);
	/* the path objects are freed when we free the controller */
	free(dp->paths);
	ap = dp->aliases;
	while (ap != NULL) {
		alias_t	*nextp;

		nextp = ap->next;
		cache_free_alias(ap);
		ap = nextp;
	}

	free(dp);
}

void
cache_free_path(path_t *pp)
{
	free(pp->name);
	free(pp->disks);
	free(pp->states);

	if (pp->wwns) {
		int i;

		for (i = 0; pp->wwns[i]; i++) {
			free(pp->wwns[i]);
		}
		free(pp->wwns);
	}

	free(pp);
}

bus_t *
cache_get_buslist()
{
	if (initialize() != 0) {
		return (NULL);
	}

	return (bus_listp);
}

controller_t *
cache_get_controllerlist()
{
	if (initialize() != 0) {
		return (NULL);
	}

	return (controller_listp);
}

/*
 * This routine will either get the existing descriptor from the descriptor
 * cache or make make a new descriptor and put it in the descriptor cache and
 * return a pointer to that descriptor.	 We increment the refcnt when we hand
 * out the descriptor.
 */
descriptor_t *
cache_get_desc(int type, void *gp, char *name, char *secondary_name, int *errp)
{
	descriptor_t	*dp;

	*errp = 0;
	if ((dp = have_desc(type, gp, name, secondary_name)) == NULL) {
		/* make a new desc */
		if ((dp = new_descriptor(type, gp, name, secondary_name))
		    == NULL) {
			*errp = ENOMEM;
		}
	}

	if (dp != NULL) {
		dp->refcnt++;
	}

	return (dp);
}

descriptor_t **
cache_get_descriptors(int type, int *errp)
{
	descriptor_t	**descs;
	descriptor_t	*descp;
	int		cnt = 0;
	int		pos;

	if ((*errp = make_descriptors(type)) != 0) {
		return (NULL);
	}

	/* count the number of active descriptors in the descriptor cache */
	descp = desc_listp;
	while (descp != NULL) {
		if (descp->type == type && descp->p.generic != NULL) {
			cnt++;
		}
		descp = descp->next;
	}

	descs = (descriptor_t **)calloc(cnt + 1, sizeof (descriptor_t *));
	if (descs == NULL) {
		*errp = ENOMEM;
		return (NULL);
	}

	pos = 0;
	descp = desc_listp;
	while (descp != NULL) {
		if (descp->type == type && descp->p.generic != NULL) {
			/* update refcnts before handing out the descriptors */
			descp->refcnt++;
			descs[pos++] = descp;
		}
		descp = descp->next;
	}
	descs[pos] = NULL;

	*errp = 0;
	return (descs);
}

disk_t *
cache_get_disklist()
{
	if (initialize() != 0) {
		return (NULL);
	}

	return (disk_listp);
}

int
cache_is_valid_desc(descriptor_t *d)
{
	descriptor_t	*descp;

	for (descp = desc_listp; descp != NULL; descp = descp->next) {
		if (descp == d) {
			return (1);
		}
	}

	return (0);
}

/*
 * This function is called by the *_make_descriptors function
 * (e.g. drive_make_descriptors) within each of the objects.  This function
 * makes sure that the descriptor is built in the descriptor cache but
 * it does not hand out the descriptors, so the refcnt is never incremented.
 */
void
cache_load_desc(int type, void *gp, char *name, char *secondary_name, int *errp)
{
	*errp = 0;
	if (have_desc(type, gp, name, secondary_name) == NULL) {
		/* make a new desc */
		if (new_descriptor(type, gp, name, secondary_name) == NULL) {
			*errp = ENOMEM;
		}
	}
}

void
cache_rlock()
{
	(void) rw_rdlock(&cache_lock);
}

void
cache_unlock()
{
	(void) rw_unlock(&cache_lock);
}

/*
 * This function is called when we get a devtree event.	 Type is either add
 * or delete of a drive.
 *
 * For delete, we need to clean up the 2nd level structures and clean up
 * the pointers between the them.  We also clear the descriptor ptr.
 */
void
cache_update(dm_event_type_t ev_type, char *devname)
{
	char *orig_name;

	cache_wlock();

	/* update the cache */
	switch (ev_type) {
	case DM_EV_DISK_ADD:
		rewalk_tree();
		events_new_event(devname, DM_DRIVE, DM_EV_TADD);
		break;
	case DM_EV_DISK_DELETE:
		orig_name = devname;
		devname = basename(devname);
		del_drive_by_name(devname);
		events_new_event(orig_name, DM_DRIVE, DM_EV_TREMOVE);
		break;
	}

	cache_unlock();
}

void
cache_wlock()
{
	(void) rw_wrlock(&cache_lock);
}

/*
 * Clear any descriptors that point at the specified cached object.
 * We must go through the whole list since there can be multiple descriptors
 * referencing the same object (i.e. drive/media/slice descriptors all point
 * to the same drive object).  The list is usually small (0 size) so this
 * is not a big deal.
 */
static void
clear_descriptors(void *gp)
{
	descriptor_t	*descp;

	for (descp = desc_listp; descp != NULL; descp = descp->next) {
		if (descp->p.generic == gp)	{
			/* clear descriptor */
			descp->p.generic = NULL;
		}
	}
}

/* remove the ptr from the controller to the specified disk */
static void
clr_ctrl_disk_ptr(controller_t *cp, disk_t *dp)
{
	int i;

	for (i = 0; cp->disks[i]; i++) {
		if (dp == cp->disks[i]) {
			int j;

			for (j = i; cp->disks[j]; j++) {
				cp->disks[j] = cp->disks[j + 1];
			}
			return;
		}
	}
}

/* remove the ptr from the path to the specified disk */
static void
clr_path_disk_ptr(path_t *pp, disk_t *dp)
{
	int i;

	for (i = 0; pp->disks[i]; i++) {
		if (dp == pp->disks[i]) {
			int j;

			for (j = i; pp->disks[j]; j++) {
				pp->disks[j] = pp->disks[j + 1];
			}
			return;
		}
	}
}

static void
del_drive(disk_t *dp)
{
	int	i;
	disk_t	*listp;
	disk_t	*prev = NULL;

	clear_descriptors(dp);

	/* clear any ptrs from controllers to this drive */
	if (dp->controllers != NULL) {
		for (i = 0; dp->controllers[i]; i++) {
			clr_ctrl_disk_ptr(dp->controllers[i], dp);
		}
	}

	/* clear any ptrs from paths to this drive */
	if (dp->paths != NULL) {
		for (i = 0; dp->paths[i]; i++) {
			clr_path_disk_ptr(dp->paths[i], dp);
		}
	}

	/* clear drive from disk list */
	for (listp = disk_listp; listp != NULL; listp = listp->next) {
		if (dp == listp) {
			if (prev == NULL) {
				disk_listp = dp->next;
			} else {
				prev->next = dp->next;
			}

			break;
		}

		if (prev == NULL) {
			prev = disk_listp;
		} else {
			prev = prev->next;
		}
	}

	cache_free_disk(dp);
}

/*
 * Delete cached drive info when we get a devtree drive delete event.
 */
static void
del_drive_by_name(char *name)
{
	disk_t	*listp;

	for (listp = disk_listp; listp != NULL; listp = listp->next) {
		alias_t	*ap;

		for (ap = listp->aliases; ap; ap = ap->next) {
			if (libdiskmgt_str_eq(name, ap->alias)) {
				del_drive(listp);
				return;
			}
		}
	}
}

static descriptor_t *
have_desc(int type, void *gp, char *name, char *secondary_name)
{
	descriptor_t	*descp;

	if (name != NULL && name[0] == 0) {
		name = NULL;
	}

	if (secondary_name != NULL && secondary_name[0] == 0) {
		secondary_name = NULL;
	}

	descp = desc_listp;
	while (descp != NULL) {
		if (descp->type == type && descp->p.generic == gp &&
		    libdiskmgt_str_eq(descp->name, name)) {
			if (type == DM_SLICE || type == DM_PARTITION ||
			    type == DM_PATH) {
				if (libdiskmgt_str_eq(descp->secondary_name,
				    secondary_name)) {
					return (descp);
				}
			} else {
				return (descp);
			}
		}
		descp = descp->next;
	}

	return (NULL);
}

static int
initialize()
{
	struct search_args	args;

	if (cache_loaded) {
		return (0);
	}

	libdiskmgt_init_debug();

	findevs(&args);

	if (args.dev_walk_status != 0) {
		return (args.dev_walk_status);
	}

	disk_listp = args.disk_listp;
	controller_listp = args.controller_listp;
	bus_listp = args.bus_listp;

	cache_loaded = 1;

	/*
	 * Only start the event thread if we are not doing an install
	 */
	if (getenv("_LIBDISKMGT_INSTALL") == NULL) {
		if (events_start_event_watcher() != 0) {
			/*
			 * Log a message about the failure to start
			 * sysevents and continue on.
			 */
			syslog(LOG_WARNING, dgettext(TEXT_DOMAIN,
			    "libdiskmgt: sysevent thread for cache "
			    "events failed to start\n"));
		}
	}
	return (0);
}

static int
make_descriptors(int type)
{
	int	error;

	if ((error = initialize()) != 0) {
		return (error);
	}

	switch (type) {
	case DM_DRIVE:
		error = drive_make_descriptors();
		break;
	case DM_BUS:
		error = bus_make_descriptors();
		break;
	case DM_CONTROLLER:
		error = controller_make_descriptors();
		break;
	case DM_PATH:
		error = path_make_descriptors();
		break;
	case DM_ALIAS:
		error = alias_make_descriptors();
		break;
	case DM_MEDIA:
		error = media_make_descriptors();
		break;
	case DM_PARTITION:
		error = partition_make_descriptors();
		break;
	case DM_SLICE:
		error = slice_make_descriptors();
		break;
	}

	return (error);
}

static int
match_alias(alias_t *ap, alias_t *listp)
{
	if (ap->alias == NULL) {
		return (0);
	}

	while (listp != NULL) {
		if (libdiskmgt_str_eq(ap->alias, listp->alias)) {
			return (1);
		}
		listp = listp->next;
	}

	return (0);
}

static int
match_aliases(disk_t *d1p, disk_t *d2p)
{
	alias_t *ap;

	if (d1p->aliases == NULL || d2p->aliases == NULL) {
		return (0);
	}

	ap = d1p->aliases;
	while (ap != NULL) {
		if (match_alias(ap, d2p->aliases)) {
			return (1);
		}
		ap = ap->next;
	}

	return (0);
}

static int
match_disk(disk_t *oldp, disk_t *newp)
{
	if (oldp->devid != NULL) {
		if (newp->devid != NULL &&
		    devid_compare(oldp->devid, newp->devid) == 0) {
			return (1);
		}

	} else {
		/* oldp device id is null */
		if (newp->devid == NULL) {
			/* both disks have no device id, check aliases */
			if (match_aliases(oldp, newp)) {
				return (1);
			}
		}
	}

	return (0);
}

static descriptor_t *
new_descriptor(dm_desc_type_t type, void *op, char *name, char *secondary_name)
{
	descriptor_t	*d;

	if (name != NULL && name[0] == 0) {
		name = NULL;
	}

	if (secondary_name != NULL && secondary_name[0] == 0) {
		secondary_name = NULL;
	}

	d = (descriptor_t *)malloc(sizeof (descriptor_t));
	if (d == NULL) {
		return (NULL);
	}
	d->type = type;
	switch (type) {
	case DM_CONTROLLER:
		d->p.controller = op;
		break;
	case DM_BUS:
		d->p.bus = op;
		break;
	default:
		d->p.disk = op;
		break;
	}
	if (name != NULL) {
		d->name = strdup(name);
		if (d->name == NULL) {
			free(d);
			return (NULL);
		}
	} else {
		d->name = NULL;
	}

	if (type == DM_SLICE || type == DM_PARTITION) {
		if (secondary_name != NULL) {
			d->secondary_name = strdup(secondary_name);
			if (d->secondary_name == NULL) {
				free(d->name);
				free(d);
				return (NULL);
			}
		} else {
			d->secondary_name = NULL;
		}
	} else {
		d->secondary_name = NULL;
	}

	d->refcnt = 0;

	/* add this descriptor to the head of the list */
	if (desc_listp != NULL) {
		desc_listp->prev = d;
	}
	d->prev = NULL;
	d->next = desc_listp;
	desc_listp = d;

	return (d);
}

static void
rewalk_tree()
{
	struct search_args	args;
	disk_t			*free_disklistp;
	controller_t		*free_controllerlistp;
	bus_t			*free_buslistp;

	findevs(&args);

	if (args.dev_walk_status == 0) {
		descriptor_t	*descp;

		/* walk the existing descriptors and update the ptrs */
		descp = desc_listp;
		while (descp != NULL) {
			update_desc(descp, args.disk_listp,
			    args.controller_listp, args.bus_listp);
			descp = descp->next;
		}

		/* update the cached object ptrs */
		free_disklistp = disk_listp;
		free_controllerlistp = controller_listp;
		free_buslistp = bus_listp;
		disk_listp = args.disk_listp;
		controller_listp = args.controller_listp;
		bus_listp = args.bus_listp;

	} else {
		free_disklistp = args.disk_listp;
		free_controllerlistp = args.controller_listp;
		free_buslistp = args.bus_listp;
	}

	/*
	 * Free the memory from either the old cached objects or the failed
	 * update objects.
	 */
	while (free_disklistp != NULL) {
		disk_t *nextp;

		nextp = free_disklistp->next;
		cache_free_disk(free_disklistp);
		free_disklistp = nextp;
	}
	while (free_controllerlistp != NULL) {
		controller_t *nextp;

		nextp = free_controllerlistp->next;
		cache_free_controller(free_controllerlistp);
		free_controllerlistp = nextp;
	}
	while (free_buslistp != NULL) {
		bus_t *nextp;

		nextp = free_buslistp->next;
		cache_free_bus(free_buslistp);
		free_buslistp = nextp;
	}
}

/*
 * Walk the new set of cached objects and update the descriptor ptr to point
 * to the correct new object.  If there is no object any more, set the desc
 * ptr to null.
 */
static void
update_desc(descriptor_t *descp, disk_t *newdisksp, controller_t *newctrlp,
    bus_t *newbusp)
{
	/* if the descriptor is already dead, we're done */
	if (descp->p.generic == NULL) {
		return;
	}

	/*
	 * All descriptors use a disk ptr except for controller descriptors
	 * and path descriptors.
	 */

	switch (descp->type) {
	case DM_BUS:
		update_desc_busp(descp, newbusp);
		break;
	case DM_CONTROLLER:
		update_desc_ctrlp(descp, newctrlp);
		break;
	case DM_PATH:
		update_desc_pathp(descp, newctrlp);
		break;
	default:
		update_desc_diskp(descp, newdisksp);
		break;
	}
}

static void
update_desc_busp(descriptor_t *descp, bus_t *busp)
{
	/* walk the new objects and find the correct bus */
	for (; busp; busp = busp->next) {
		if (libdiskmgt_str_eq(descp->p.bus->name, busp->name)) {
			descp->p.bus = busp;
			return;
		}
	}

	/* we did not find the controller any more, clear the ptr in the desc */
	descp->p.bus = NULL;
}

static void
update_desc_ctrlp(descriptor_t *descp, controller_t *newctrlp)
{
	/* walk the new objects and find the correct controller */
	for (; newctrlp; newctrlp = newctrlp->next) {
		if (libdiskmgt_str_eq(descp->p.controller->name,
		    newctrlp->name)) {
			descp->p.controller = newctrlp;
			return;
		}
	}

	/* we did not find the controller any more, clear the ptr in the desc */
	descp->p.controller = NULL;
}

static void
update_desc_diskp(descriptor_t *descp, disk_t *newdisksp)
{
	/* walk the new objects and find the correct disk */
	for (; newdisksp; newdisksp = newdisksp->next) {
		if (match_disk(descp->p.disk, newdisksp)) {
			descp->p.disk = newdisksp;
			return;
		}
	}

	/* we did not find the disk any more, clear the ptr in the descriptor */
	descp->p.disk = NULL;
}

static void
update_desc_pathp(descriptor_t *descp, controller_t *newctrlp)
{
	/* walk the new objects and find the correct path */
	for (; newctrlp; newctrlp = newctrlp->next) {
		path_t	**pp;

		pp = newctrlp->paths;
		if (pp != NULL) {
			int i;

			for (i = 0; pp[i]; i++) {
				if (libdiskmgt_str_eq(descp->p.path->name,
				    pp[i]->name)) {
					descp->p.path = pp[i];
					return;
				}
			}
		}
	}

	/* we did not find the path any more, clear the ptr in the desc */
	descp->p.path = NULL;
}
