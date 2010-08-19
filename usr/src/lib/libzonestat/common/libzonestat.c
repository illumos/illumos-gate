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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <alloca.h>
#include <assert.h>
#include <door.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <strings.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <zonestat.h>
#include <zonestat_impl.h>

#define	ZSD_PCT_INT	10000
#define	ZSD_PCT_DOUBLE	10000.0

#define	ZSD_ONE_CPU	100

#ifndef	MIN
#define	MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif
#ifndef	MAX
#define	MAX(a, b) (((a) > (b)) ? (a) : (b))
#endif

#define	ZS_MAXTS(a, b) ((b).tv_sec > (a).tv_sec || \
	((b).tv_sec == (a).tv_sec && (b).tv_nsec > (a).tv_nsec) ? (b) : (a))


/* Compute max, treating ZS_LIMIT_NONE as zero */
#define	ZS_MAXOF(a, b) { \
	if ((b) != ZS_LIMIT_NONE) { \
		if ((a) == ZS_LIMIT_NONE) \
			(a) = (b); \
		else if ((b) > (a)) \
		(b) = (a); \
	} \
	}

/* Add two caps together, treating ZS_LIMIT_NONE as zero */
#define	ZS_ADD_CAP(a, b) { \
	if ((b) != ZS_LIMIT_NONE) { \
		if ((a) == ZS_LIMIT_NONE) \
			(a) = (b); \
		else \
		(a) += (b); \
	} \
	}

#define	ZS_MAXOFTS(a, b) { \
    if ((b).tv_sec > (a).tv_sec) (a) = (b); \
    else if ((b).tv_nsec > (a).tv_nsec) (a) = (b); }

/*
 * Functions for reading and manipulating resource usage.
 */
static int
zs_connect_zonestatd()
{
	int fd;

	fd = open(ZS_DOOR_PATH, O_RDONLY);
	return (fd);
}

static zs_zone_t *
zs_lookup_zone_byid(zs_usage_t *u, zoneid_t zid)
{
	zs_zone_t *zone;

	for (zone = list_head(&u->zsu_zone_list); zone != NULL;
	    zone = list_next(&u->zsu_zone_list, zone)) {
		if (zone->zsz_id == zid)
			return (zone);
	}
	return (NULL);
}

static zs_zone_t *
zs_lookup_zone_byname(zs_usage_t *u, char *name)
{
	zs_zone_t *zone;

	for (zone = list_head(&u->zsu_zone_list); zone != NULL;
	    zone = list_next(&u->zsu_zone_list, zone)) {
		if (strcmp(zone->zsz_name, name) == 0)
			return (zone);
	}
	return (NULL);
}

static zs_usage_t *
zs_usage_alloc()
{
	zs_usage_t *u;
	zs_system_t *s;

	u = (zs_usage_t *)calloc(sizeof (zs_usage_t), 1);
	if (u == NULL)
		return (NULL);

	s = (zs_system_t *)calloc(sizeof (zs_system_t), 1);
	if (s == NULL) {
		free(u);
		return (NULL);
	}

	u->zsu_mmap = B_FALSE;
	u->zsu_system = s;
	list_create(&u->zsu_zone_list, sizeof (zs_zone_t),
	    offsetof(zs_zone_t, zsz_next));
	list_create(&u->zsu_pset_list, sizeof (zs_pset_t),
	    offsetof(zs_pset_t, zsp_next));

	return (u);
}

static void
zs_zone_add_usage(zs_zone_t *old, zs_zone_t *new, int func)
{

	if (func == ZS_COMPUTE_USAGE_HIGH) {

		/* Compute max of caps */
		ZS_MAXOF(old->zsz_cpu_cap, new->zsz_cpu_cap);
		ZS_MAXOF(old->zsz_cpu_shares, new->zsz_cpu_shares);
		ZS_MAXOF(old->zsz_ram_cap, new->zsz_ram_cap);
		ZS_MAXOF(old->zsz_locked_cap, new->zsz_locked_cap);
		ZS_MAXOF(old->zsz_vm_cap, new->zsz_vm_cap);
		ZS_MAXOF(old->zsz_processes_cap, new->zsz_processes_cap);
		ZS_MAXOF(old->zsz_lwps_cap, new->zsz_lwps_cap);
		ZS_MAXOF(old->zsz_shm_cap, new->zsz_shm_cap);
		ZS_MAXOF(old->zsz_shmids_cap, new->zsz_shmids_cap);
		ZS_MAXOF(old->zsz_semids_cap, new->zsz_semids_cap);
		ZS_MAXOF(old->zsz_msgids_cap, new->zsz_msgids_cap);
		ZS_MAXOF(old->zsz_lofi_cap, new->zsz_lofi_cap);

		/* Compute max memory and limit usages */
		ZS_MAXOF(old->zsz_usage_ram, new->zsz_usage_ram);
		ZS_MAXOF(old->zsz_usage_locked, new->zsz_usage_locked);
		ZS_MAXOF(old->zsz_usage_ram, new->zsz_usage_ram);

		ZS_MAXOF(old->zsz_processes, new->zsz_processes);
		ZS_MAXOF(old->zsz_lwps, new->zsz_lwps);
		ZS_MAXOF(old->zsz_shm, new->zsz_shm);
		ZS_MAXOF(old->zsz_shmids, new->zsz_shmids);
		ZS_MAXOF(old->zsz_semids, new->zsz_semids);
		ZS_MAXOF(old->zsz_msgids, new->zsz_msgids);
		ZS_MAXOF(old->zsz_lofi, new->zsz_lofi);

		ZS_MAXOF(old->zsz_cpus_online, new->zsz_cpus_online);

		ZS_MAXOFTS(old->zsz_cpu_usage, new->zsz_cpu_usage);
		ZS_MAXOFTS(old->zsz_pset_time, new->zsz_pset_time);
		ZS_MAXOFTS(old->zsz_cap_time, new->zsz_cap_time);
		ZS_MAXOFTS(old->zsz_share_time, new->zsz_share_time);
		return;
	}

	ZS_ADD_CAP(old->zsz_cpu_cap, new->zsz_cpu_cap);
	ZS_ADD_CAP(old->zsz_ram_cap, new->zsz_ram_cap);
	ZS_ADD_CAP(old->zsz_locked_cap, new->zsz_locked_cap);
	ZS_ADD_CAP(old->zsz_vm_cap, new->zsz_vm_cap);
	ZS_ADD_CAP(old->zsz_processes_cap, new->zsz_processes_cap);
	ZS_ADD_CAP(old->zsz_lwps_cap, new->zsz_lwps_cap);
	ZS_ADD_CAP(old->zsz_shm_cap, new->zsz_shm_cap);
	ZS_ADD_CAP(old->zsz_shmids_cap, new->zsz_shmids_cap);
	ZS_ADD_CAP(old->zsz_semids_cap, new->zsz_semids_cap);
	ZS_ADD_CAP(old->zsz_msgids_cap, new->zsz_msgids_cap);
	ZS_ADD_CAP(old->zsz_lofi_cap, new->zsz_lofi_cap);

	/* Add in memory and limit usages */
	old->zsz_usage_ram += new->zsz_usage_ram;
	old->zsz_usage_locked += new->zsz_usage_locked;
	old->zsz_usage_vm += new->zsz_usage_vm;

	old->zsz_processes += new->zsz_processes;
	old->zsz_lwps += new->zsz_lwps;
	old->zsz_shm += new->zsz_shm;
	old->zsz_shmids += new->zsz_shmids;
	old->zsz_semids += new->zsz_semids;
	old->zsz_msgids += new->zsz_msgids;
	old->zsz_lofi += new->zsz_lofi;

	old->zsz_cpus_online += new->zsz_cpus_online;
	old->zsz_cpu_shares += new->zsz_cpu_shares;

	TIMESTRUC_ADD_TIMESTRUC(old->zsz_cpu_usage, new->zsz_cpu_usage);
	TIMESTRUC_ADD_TIMESTRUC(old->zsz_pset_time, new->zsz_pset_time);
	TIMESTRUC_ADD_TIMESTRUC(old->zsz_cap_time, new->zsz_cap_time);
	TIMESTRUC_ADD_TIMESTRUC(old->zsz_share_time, new->zsz_share_time);
}

static int
zs_usage_compute_zones(zs_usage_t *ures, zs_usage_t *uold, zs_usage_t *unew,
    int func)
{
	zs_system_t *sres;
	zs_zone_t *zold, *znew, *zres;

	sres = ures->zsu_system;
	/*
	 * Walk zones, assume lists are always sorted the same.  Include
	 * all zones that exist in the new usage.
	 */
	zold = list_head(&uold->zsu_zone_list);
	znew = list_head(&unew->zsu_zone_list);

	while (zold != NULL && znew != NULL) {

		int cmp;

		cmp = strcmp(zold->zsz_name, znew->zsz_name);
		if (cmp > 0) {
			/*
			 * Old interval does not contain zone in new
			 * interval.  Zone is new.  Add zone to result.
			 */
			if (ures != unew) {
				zres = (zs_zone_t *)calloc(sizeof (zs_zone_t),
				    1);
				if (zres == NULL)
					return (-1);
				*zres = *znew;

				zres->zsz_system = sres;
				list_link_init(&zres->zsz_next);
				zres->zsz_intervals = 0;
				if (ures == uold)
					list_insert_before(&uold->zsu_zone_list,
					    zold, zres);
				else
					list_insert_tail(&ures->zsu_zone_list,
					    zres);

			} else {
				zres = znew;
			}

			if (func == ZS_COMPUTE_USAGE_AVERAGE)
				zres->zsz_intervals++;

			znew = list_next(&unew->zsu_zone_list, znew);
			continue;

		} else if (cmp < 0) {
			/*
			 * Start interval contains zones that is not in the
			 * end interval.  This zone is gone.  Leave zone in
			 * old usage, but do not add it to result usage
			 */
			zold = list_next(&uold->zsu_zone_list, zold);
			continue;
		}

		/* Zone is in both start and end interval.  Compute interval */
		if (ures == uold) {
			zres = zold;
		} else if (ures == unew) {
			zres = znew;
		} else {
			/* add zone to new usage */
			zres = (zs_zone_t *)calloc(sizeof (zs_zone_t), 1);
			if (zres == NULL)
				return (-1);
			*zres = *znew;
			zres->zsz_system = sres;
			list_insert_tail(&ures->zsu_zone_list, zres);
		}
		if (func == ZS_COMPUTE_USAGE_AVERAGE)
			zres->zsz_intervals++;
		if (func == ZS_COMPUTE_USAGE_INTERVAL) {
			/*
			 * If zone is in the old interval, but has been
			 * rebooted, don't subtract its old interval usage
			 */
			if (zres->zsz_hrstart > uold->zsu_hrtime) {
				znew = list_next(&unew->zsu_zone_list, znew);
				zold = list_next(&uold->zsu_zone_list, zold);
				continue;
			}
			TIMESTRUC_DELTA(zres->zsz_cpu_usage,
			    znew->zsz_cpu_usage, zold->zsz_cpu_usage);
			TIMESTRUC_DELTA(zres->zsz_cap_time, znew->zsz_cap_time,
			    zold->zsz_cap_time);
			TIMESTRUC_DELTA(zres->zsz_share_time,
			    znew->zsz_share_time, zold->zsz_share_time);
			TIMESTRUC_DELTA(zres->zsz_pset_time,
			    znew->zsz_pset_time, zold->zsz_pset_time);
		} else {
			zs_zone_add_usage(zres, znew, func);
		}
		znew = list_next(&unew->zsu_zone_list, znew);
		zold = list_next(&uold->zsu_zone_list, zold);
	}

	if (ures == unew)
		return (0);

	/* Add in any remaining zones in the new interval */
	while (znew != NULL) {
		zres = (zs_zone_t *)calloc(sizeof (zs_zone_t), 1);
		if (zres == NULL)
			return (-1);
		*zres = *znew;
		zres->zsz_system = sres;
		if (func == ZS_COMPUTE_USAGE_AVERAGE)
			zres->zsz_intervals++;
		if (ures == uold)
			list_insert_tail(&uold->zsu_zone_list, zres);
		else
			list_insert_tail(&ures->zsu_zone_list, zres);

		znew = list_next(&unew->zsu_zone_list, znew);
	}
	return (0);
}

static void
zs_pset_zone_add_usage(zs_pset_zone_t *old, zs_pset_zone_t *new, int func)
{
	if (func == ZS_COMPUTE_USAGE_HIGH) {
		ZS_MAXOF(old->zspz_cpu_shares, new->zspz_cpu_shares);
		ZS_MAXOFTS(old->zspz_cpu_usage, new->zspz_cpu_usage);
		return;
	}
	old->zspz_cpu_shares += new->zspz_cpu_shares;
	TIMESTRUC_ADD_TIMESTRUC(old->zspz_cpu_usage, new->zspz_cpu_usage);
}

static int
zs_usage_compute_pset_usage(zs_usage_t *uold, zs_usage_t *ures,
    zs_pset_t *pres, zs_pset_t *pold, zs_pset_t *pnew, int func)
{
	zs_pset_zone_t *puold, *punew, *pures;

	/*
	 * Walk psets usages, assume lists are always sorted the same.  Include
	 * all pset usages that exist in the new pset.
	 */
	if (pold == NULL)
		puold = NULL;
	else
		puold = list_head(&pold->zsp_usage_list);
	punew = list_head(&pnew->zsp_usage_list);

	while (puold != NULL && punew != NULL) {

		int cmp;

		cmp = strcmp(puold->zspz_zone->zsz_name,
		    punew->zspz_zone->zsz_name);
		if (cmp > 0) {
			/*
			 * Old interval does not contain usage new
			 * interval.  Usage is new.
			 */
			if (pres != pnew) {
				pures = (zs_pset_zone_t *)malloc(
				    sizeof (zs_pset_zone_t));
				if (pures == NULL)
					return (-1);
				*pures = *punew;

				pures->zspz_pset = pres;
				pures->zspz_zone = zs_lookup_zone_byname(ures,
				    punew->zspz_zone->zsz_name);
				assert(pures->zspz_zone != NULL);
				pures->zspz_intervals = 0;
				if (pres == pold)
					list_insert_before(
					    &pold->zsp_usage_list, puold,
					    pures);
				else
					list_insert_tail(&pres->zsp_usage_list,
					    pures);
			} else {
				pures = punew;
			}
			if (func == ZS_COMPUTE_USAGE_AVERAGE)
				pures->zspz_intervals++;
			else if (func == ZS_COMPUTE_USAGE_TOTAL) {
				/* Add pset's time so far to the zone usage */
				TIMESTRUC_ADD_TIMESTRUC(
				    pures->zspz_zone->zsz_pset_time,
				    pres->zsp_total_time);
				pures->zspz_zone->zsz_cpus_online +=
				    pres->zsp_online;
			}

			punew = list_next(&pnew->zsp_usage_list, punew);
			continue;
		} else if (cmp < 0) {

			/*
			 * Old interval contains pset_zone that is not in the
			 * new interval.  This zone is no longer using the
			 * pset.  Leave pset_zone in old interval, but do not
			 * add it to result usage.
			 *
			 * For total utilization, add pset time to zone that
			 * has run in this pset before.
			 */
			if (func == ZS_COMPUTE_USAGE_TOTAL) {
				/* Add new pset time to the zone usage */
				TIMESTRUC_ADD_TIMESTRUC(
				    puold->zspz_zone->zsz_pset_time,
				    pnew->zsp_total_time);
				puold->zspz_zone->zsz_cpus_online +=
				    pnew->zsp_online;
			}
			puold = list_next(&pold->zsp_usage_list, puold);
			continue;
		}
		/*
		 * Zone is using pset in both start and end interval.  Compute
		 * interval
		 */
		if (pres == pold) {
			pures = puold;
		} else if (pres == pnew) {
			pures = punew;
		} else {
			pures = (zs_pset_zone_t *)malloc(
			    sizeof (zs_pset_zone_t));
			if (pures == NULL)
				return (-1);
			*pures = *punew;
			pures->zspz_pset = pres;
			pures->zspz_zone = zs_lookup_zone_byname(ures,
			    punew->zspz_zone->zsz_name);
			assert(pures->zspz_zone != NULL);
			list_insert_tail(&pres->zsp_usage_list, pures);
		}
		if (func == ZS_COMPUTE_USAGE_AVERAGE)
			pures->zspz_intervals++;

		if (func == ZS_COMPUTE_USAGE_INTERVAL) {
			/*
			 * If pset usage has been destroyed and re-created
			 * since start interval, don't subtract the start
			 * interval.
			 */
			if (punew->zspz_hrstart > uold->zsu_hrtime) {
				punew = list_next(&pnew->zsp_usage_list, punew);
				puold = list_next(&pold->zsp_usage_list, puold);
				continue;
			}
			TIMESTRUC_DELTA(pures->zspz_cpu_usage,
			    punew->zspz_cpu_usage, puold->zspz_cpu_usage);
		} else {
			zs_pset_zone_add_usage(pures, punew, func);
		}
		punew = list_next(&pnew->zsp_usage_list, punew);
		puold = list_next(&pold->zsp_usage_list, puold);
	}
	if (func == ZS_COMPUTE_USAGE_TOTAL) {
		while (puold != NULL) {
			TIMESTRUC_ADD_TIMESTRUC(
			    puold->zspz_zone->zsz_pset_time,
			    pnew->zsp_total_time);
			puold->zspz_zone->zsz_cpus_online +=
			    pnew->zsp_online;
			puold = list_next(&pold->zsp_usage_list, puold);
		}
	}

	/* No need to add new pset zone usages if result pset is new pset */
	if (pres == pnew)
		return (0);

	/* Add in any remaining new psets in the new interval */
	while (punew != NULL) {
		pures = (zs_pset_zone_t *)calloc(sizeof (zs_pset_zone_t), 1);
		if (pures == NULL)
			return (-1);
		*pures = *punew;
		pures->zspz_pset = pres;
		pures->zspz_zone = zs_lookup_zone_byname(ures,
		    punew->zspz_zone->zsz_name);
		assert(pures->zspz_zone  != NULL);
		if (func == ZS_COMPUTE_USAGE_AVERAGE)
			pures->zspz_intervals++;
		if (pres == pold)
			list_insert_tail(&pold->zsp_usage_list, pures);
		else
			list_insert_tail(&pres->zsp_usage_list, pures);

		punew = list_next(&pnew->zsp_usage_list, punew);
	}
	return (0);
}

static void
zs_pset_add_usage(zs_pset_t *old, zs_pset_t *new, int func)
{

	if (func == ZS_COMPUTE_USAGE_HIGH) {
		ZS_MAXOF(old->zsp_online, new->zsp_online);
		ZS_MAXOF(old->zsp_size, new->zsp_size);
		ZS_MAXOF(old->zsp_min, new->zsp_min);
		ZS_MAXOF(old->zsp_max, new->zsp_max);
		ZS_MAXOF(old->zsp_importance, new->zsp_importance);
		ZS_MAXOF(old->zsp_cpu_shares, new->zsp_cpu_shares);
		ZS_MAXOFTS(old->zsp_total_time, new->zsp_total_time);
		ZS_MAXOFTS(old->zsp_usage_kern, new->zsp_usage_kern);
		ZS_MAXOFTS(old->zsp_usage_zones, new->zsp_usage_zones);
		return;
	}
	old->zsp_online += new->zsp_online;
	old->zsp_size += new->zsp_size;
	old->zsp_min += new->zsp_min;
	old->zsp_max += new->zsp_max;
	old->zsp_importance += new->zsp_importance;
	old->zsp_cpu_shares += new->zsp_cpu_shares;
	TIMESTRUC_ADD_TIMESTRUC(old->zsp_total_time, new->zsp_total_time);
	TIMESTRUC_ADD_TIMESTRUC(old->zsp_usage_kern, new->zsp_usage_kern);
	TIMESTRUC_ADD_TIMESTRUC(old->zsp_usage_zones, new->zsp_usage_zones);
}

static int
zs_usage_compute_psets(zs_usage_t *ures, zs_usage_t *uold, zs_usage_t *unew,
    int func)
{
	zs_pset_t *pold, *pnew, *pres;

	/*
	 * Walk psets, assume lists are always sorted the same.  Include
	 * all psets that exist at the end of the interval.
	 */
	pold = list_head(&uold->zsu_pset_list);
	pnew = list_head(&unew->zsu_pset_list);

	while (pold != NULL && pnew != NULL) {

		int cmp;

		cmp = strcmp(pold->zsp_name, pnew->zsp_name);
		if (cmp > 0) {
			/*
			 * Old interval does not contain pset in new
			 * interval.  Pset is new.
			 */
			if (ures != unew) {
				pres = (zs_pset_t *)malloc(sizeof (zs_pset_t));
				if (pres == NULL)
					return (-1);
				*pres = *pnew;
				pres->zsp_intervals = 0;
				list_create(&pres->zsp_usage_list,
				    sizeof (zs_pset_zone_t),
				    offsetof(zs_pset_zone_t, zspz_next));

				if (ures == uold)
					list_insert_before(&uold->zsu_pset_list,
					    pold, pres);
				else
					list_insert_tail(&ures->zsu_pset_list,
					    pres);

			} else {
				pres = pnew;
			}
			if (zs_usage_compute_pset_usage(uold, ures, pres,
			    NULL, pnew, func) != 0)
				return (-1);

			if (func == ZS_COMPUTE_USAGE_AVERAGE ||
			    func == ZS_COMPUTE_USAGE_TOTAL)
				pres->zsp_intervals++;
			pnew = list_next(&unew->zsu_pset_list, pnew);
			continue;

		} else if (cmp < 0) {
			/*
			 * Start interval contains psets that is not in the
			 * end interval.  This pset is gone.  Leave pset in
			 * old usage, but do not add it to result usage.
			 */
			pold = list_next(&uold->zsu_pset_list, pold);
			continue;
		}

		/* Pset is in both start and end interval.  Compute interval */
		if (ures == uold) {
			pres = pold;
		} else if (ures == unew) {
			pres = pnew;
		} else {
			pres = (zs_pset_t *)calloc(sizeof (zs_pset_t), 1);
			if (pres == NULL)
				return (-1);

			*pres = *pnew;
			list_create(&pres->zsp_usage_list,
			    sizeof (zs_pset_zone_t),
			    offsetof(zs_pset_zone_t, zspz_next));
			list_insert_tail(&ures->zsu_pset_list, pres);
		}
		if (func == ZS_COMPUTE_USAGE_AVERAGE ||
		    func == ZS_COMPUTE_USAGE_TOTAL)
			pres->zsp_intervals++;
		if (func == ZS_COMPUTE_USAGE_INTERVAL) {
			/*
			 * If pset as been destroyed and re-created since start
			 * interval, don't subtract the start interval.
			 */
			if (pnew->zsp_hrstart > uold->zsu_hrtime) {
				goto usages;
			}
			TIMESTRUC_DELTA(pres->zsp_total_time,
			    pnew->zsp_total_time, pold->zsp_total_time);

			TIMESTRUC_DELTA(pres->zsp_usage_kern,
			    pnew->zsp_usage_kern, pold->zsp_usage_kern);
			TIMESTRUC_DELTA(pres->zsp_usage_zones,
			    pnew->zsp_usage_zones, pold->zsp_usage_zones);
		} else {
			zs_pset_add_usage(pres, pnew, func);
		}
usages:
		if (zs_usage_compute_pset_usage(uold, ures, pres, pold,
		    pnew, func) != 0)
			return (-1);

		pnew = list_next(&unew->zsu_pset_list, pnew);
		pold = list_next(&uold->zsu_pset_list, pold);
	}

	if (ures == unew)
		return (0);

	/* Add in any remaining psets in the new interval */
	while (pnew != NULL) {
		pres = (zs_pset_t *)calloc(sizeof (zs_pset_t), 1);
		if (pres == NULL)
			return (-1);
		*pres = *pnew;
		list_create(&pres->zsp_usage_list,
		    sizeof (zs_pset_zone_t),
		    offsetof(zs_pset_zone_t, zspz_next));
		if (func == ZS_COMPUTE_USAGE_AVERAGE ||
		    func == ZS_COMPUTE_USAGE_TOTAL)
			pres->zsp_intervals++;
		if (ures == uold)
			list_insert_tail(&uold->zsu_pset_list, pres);
		else
			list_insert_tail(&ures->zsu_pset_list, pres);

		if (zs_usage_compute_pset_usage(uold, ures, pres, NULL,
		    pnew, func) != 0)
			return (-1);

		pnew = list_next(&unew->zsu_pset_list, pnew);
	}
	return (0);
}

static int
zs_zone_name(zs_zone_t *zone, char *name, size_t len)
{
	return (strlcpy(name, zone->zsz_name, len));
}

static zoneid_t
zs_zone_id(zs_zone_t *zone)
{
	return (zone->zsz_id);
}

static uint_t
zs_zone_iptype(zs_zone_t *zone)
{
	return (zone->zsz_iptype);
}

static uint_t
zs_zone_cputype(zs_zone_t *zone)
{
	return (zone->zsz_cputype);
}

static int
zs_zone_poolname(zs_zone_t *zone, char *name, size_t len)
{
	return (strlcpy(name, zone->zsz_pool, len));
}

static int
zs_zone_psetname(zs_zone_t *zone, char *name, size_t len)
{
	return (strlcpy(name, zone->zsz_pset, len));
}

static uint_t
zs_zone_schedulers(zs_zone_t *zone)
{
	return (zone->zsz_scheds);
}

static uint64_t
zs_ts_used_scale(timestruc_t *total, timestruc_t *used, uint64_t scale,
    boolean_t cap_at_100)
{
	double dtotal, dused, pct, dscale;

	/* If no time yet, treat as zero */
	if (total->tv_sec == 0 && total->tv_nsec == 0)
		return (0);

	dtotal = (double)total->tv_sec +
	    ((double)total->tv_nsec / (double)NANOSEC);
	dused = (double)used->tv_sec +
	    ((double)used->tv_nsec / (double)NANOSEC);

	dscale = (double)scale;
	pct = dused / dtotal * dscale;
	if (cap_at_100 && pct > dscale)
		pct = dscale;

	return ((uint_t)pct);
}

/*
 * Convert total and used time into percent used.
 */
static uint_t
zs_ts_used_pct(timestruc_t *total, timestruc_t *used, boolean_t cap_at_100)
{
	return ((uint_t)zs_ts_used_scale(total, used, ZSD_PCT_INT, cap_at_100));
}

/*
 * Convert total and used time, plus number of cpus, into number of cpus
 * used, where 100 equals 1 cpu used.
 */
static uint64_t
zs_ts_used_cpus(timestruc_t *total, timestruc_t *used, uint_t ncpus,
    boolean_t cap_at_100)
{
	return (zs_ts_used_scale(total, used, ncpus * ZSD_ONE_CPU, cap_at_100));
}

static uint64_t
zs_zone_cpu_shares(zs_zone_t *zone)
{
	/* No processes found in FSS */
	if ((zone->zsz_scheds & ZS_SCHED_FSS) == 0)
		return (ZS_LIMIT_NONE);

	return (zone->zsz_cpu_shares);
}

static uint64_t
zs_zone_cpu_cap(zs_zone_t *zone)
{
	return (zone->zsz_cpu_cap);
}

static uint64_t
zs_zone_cpu_cap_used(zs_zone_t *zone)
{
	if (zone->zsz_cpu_cap == ZS_LIMIT_NONE)
		return (ZS_LIMIT_NONE);

	return (zs_ts_used_cpus(&zone->zsz_cap_time, &zone->zsz_cpu_usage,
	    zone->zsz_cpus_online, B_TRUE));
}

static uint64_t
zs_zone_cpu_shares_used(zs_zone_t *zone)
{
	if (zone->zsz_cpu_shares == ZS_LIMIT_NONE)
		return (ZS_LIMIT_NONE);

	if (zone->zsz_cpu_shares == ZS_SHARES_UNLIMITED)
		return (ZS_LIMIT_NONE);

	if ((zone->zsz_scheds & ZS_SCHED_FSS) == 0)
		return (ZS_LIMIT_NONE);

	return (zs_ts_used_scale(&zone->zsz_share_time, &zone->zsz_cpu_usage,
	    zone->zsz_cpu_shares, B_FALSE));
}

static void
zs_zone_cpu_cap_time(zs_zone_t *zone, timestruc_t *ts)
{
	*ts = zone->zsz_cap_time;
}

static void
zs_zone_cpu_share_time(zs_zone_t *zone, timestruc_t *ts)
{
	*ts = zone->zsz_share_time;
}

static void
zs_zone_cpu_cap_time_used(zs_zone_t *zone, timestruc_t *ts)
{
	*ts = zone->zsz_cpu_usage;
}

static void
zs_zone_cpu_share_time_used(zs_zone_t *zone, timestruc_t *ts)
{
	*ts = zone->zsz_cpu_usage;
}


static uint64_t
zs_uint64_used_scale(uint64_t total, uint64_t used, uint64_t scale,
    boolean_t cap_at_100)
{
	double dtotal, dused, pct, dscale;

	/* If no time yet, treat as zero */
	if (total == 0)
		return (0);

	dtotal = (double)total;
	dused = (double)used;

	dscale = (double)scale;
	pct = dused / dtotal * dscale;
	if (cap_at_100 && pct > dscale)
		pct = dscale;

	return ((uint64_t)pct);
}

/*
 * Convert a total and used value into a percent used.
 */
static uint_t
zs_uint64_used_pct(uint64_t total, uint64_t used, boolean_t cap_at_100)
{
	return ((uint_t)zs_uint64_used_scale(total, used, ZSD_PCT_INT,
	    cap_at_100));
}

static uint_t
zs_zone_cpu_cap_pct(zs_zone_t *zone)
{
	if (zone->zsz_cpu_cap == ZS_LIMIT_NONE)
		return (ZS_PCT_NONE);

	return (zs_ts_used_pct(&zone->zsz_cap_time, &zone->zsz_cpu_usage,
	    B_TRUE));
}

static uint_t
zs_zone_cpu_shares_pct(zs_zone_t *zone)
{
	if (zone->zsz_cpu_shares == ZS_LIMIT_NONE)
		return (ZS_PCT_NONE);

	if (zone->zsz_cpu_shares == ZS_SHARES_UNLIMITED)
		return (ZS_PCT_NONE);

	if ((zone->zsz_scheds & ZS_SCHED_FSS) == 0)
		return (ZS_PCT_NONE);

	return (zs_ts_used_pct(&zone->zsz_share_time, &zone->zsz_cpu_usage,
	    B_FALSE));
}

static uint64_t
zs_zone_physical_memory_cap(zs_zone_t *zone)
{
	return (zone->zsz_ram_cap);
}

static uint64_t
zs_zone_virtual_memory_cap(zs_zone_t *zone)
{
	return (zone->zsz_vm_cap);
}

static uint64_t
zs_zone_locked_memory_cap(zs_zone_t *zone)
{
	return (zone->zsz_locked_cap);
}

static uint64_t
zs_zone_physical_memory_cap_used(zs_zone_t *zone)
{
	if (zone->zsz_ram_cap == ZS_LIMIT_NONE)
		return (ZS_LIMIT_NONE);

	return (zone->zsz_usage_ram);
}

static uint64_t
zs_zone_virtual_memory_cap_used(zs_zone_t *zone)
{
	if (zone->zsz_vm_cap == ZS_LIMIT_NONE)
		return (ZS_LIMIT_NONE);

	return (zone->zsz_usage_vm);
}

static uint64_t
zs_zone_locked_memory_cap_used(zs_zone_t *zone)
{
	if (zone->zsz_locked_cap == ZS_LIMIT_NONE)
		return (ZS_LIMIT_NONE);

	return (zone->zsz_usage_locked);
}

static int
zs_pset_name(zs_pset_t *pset, char *name, size_t len)
{
	return (strlcpy(name, pset->zsp_name, len));
}

static psetid_t
zs_pset_id(zs_pset_t *pset)
{
	return (pset->zsp_id);
}

static uint64_t
zs_pset_size(zs_pset_t *pset)
{
	return (pset->zsp_size);
}

static uint64_t
zs_pset_online(zs_pset_t *pset)
{
	return (pset->zsp_online);
}

uint64_t
zs_pset_min(zs_pset_t *pset)
{
	return (pset->zsp_min);
}

uint64_t
zs_pset_max(zs_pset_t *pset)
{
	return (pset->zsp_max);
}

static uint_t
zs_pset_schedulers(zs_pset_t *pset)
{
	return (pset->zsp_scheds);
}

static uint_t
zs_pset_zone_schedulers(zs_pset_zone_t *pz)
{
	return (pz->zspz_scheds);
}

static uint64_t
zs_pset_cpu_shares(zs_pset_t *pset)
{
	if (!(pset->zsp_scheds & ZS_SCHED_FSS))
		return (ZS_LIMIT_NONE);

	return (pset->zsp_cpu_shares);
}

static uint64_t
zs_pset_zone_cpu_shares(zs_pset_zone_t *pz)
{
	if (!(pz->zspz_scheds & ZS_SCHED_FSS))
		return (ZS_LIMIT_NONE);

	return (pz->zspz_cpu_shares);
}

static uint_t
zs_pset_cputype(zs_pset_t *pset)
{
	return (pset->zsp_cputype);
}

static void
zs_pset_usage_all(zs_pset_t *pset, timestruc_t *ts)
{
	timestruc_t tot;

	tot = pset->zsp_usage_kern;
	TIMESTRUC_ADD_TIMESTRUC(tot, pset->zsp_usage_zones);
	*ts = tot;
}

static void
zs_pset_usage_idle(zs_pset_t *pset, timestruc_t *ts)
{
	timestruc_t tot, time, idle;

	tot = pset->zsp_usage_kern;
	TIMESTRUC_ADD_TIMESTRUC(tot, pset->zsp_usage_zones);
	time = pset->zsp_total_time;
	TIMESTRUC_DELTA(idle, time, tot);
	*ts = idle;
}

static void
zs_pset_usage_kernel(zs_pset_t *pset, timestruc_t *ts)
{
	*ts = pset->zsp_usage_kern;
}

static void
zs_pset_usage_zones(zs_pset_t *pset, timestruc_t *ts)
{
	*ts = pset->zsp_usage_zones;
}

static uint_t
zs_pset_usage_all_pct(zs_pset_t *pset)
{
	timestruc_t tot;

	tot = pset->zsp_usage_kern;
	TIMESTRUC_ADD_TIMESTRUC(tot, pset->zsp_usage_zones);

	return (zs_ts_used_pct(&pset->zsp_total_time, &tot, B_TRUE));
}

static uint_t
zs_pset_usage_idle_pct(zs_pset_t *pset)
{
	timestruc_t tot, idle;

	tot = pset->zsp_usage_kern;
	TIMESTRUC_ADD_TIMESTRUC(tot, pset->zsp_usage_zones);
	TIMESTRUC_DELTA(idle, pset->zsp_total_time, tot);

	return (zs_ts_used_pct(&pset->zsp_total_time, &idle, B_TRUE));
}

static uint_t
zs_pset_usage_kernel_pct(zs_pset_t *pset)
{
	return (zs_ts_used_pct(&pset->zsp_total_time, &pset->zsp_usage_kern,
	    B_TRUE));
}

static uint_t
zs_pset_usage_zones_pct(zs_pset_t *pset)
{
	return (zs_ts_used_pct(&pset->zsp_total_time, &pset->zsp_usage_zones,
	    B_TRUE));
}

static uint_t
zs_pset_usage_all_cpus(zs_pset_t *pset)
{
	timestruc_t tot;

	tot = pset->zsp_usage_kern;
	TIMESTRUC_ADD_TIMESTRUC(tot, pset->zsp_usage_zones);
	return (zs_ts_used_cpus(&pset->zsp_total_time, &tot, pset->zsp_online,
	    B_TRUE));
}

static uint_t
zs_pset_usage_idle_cpus(zs_pset_t *pset)
{
	timestruc_t tot, idle;

	tot = pset->zsp_usage_kern;
	TIMESTRUC_ADD_TIMESTRUC(tot, pset->zsp_usage_zones);
	TIMESTRUC_DELTA(idle, pset->zsp_total_time, tot);

	return (zs_ts_used_cpus(&pset->zsp_total_time, &tot, pset->zsp_online,
	    B_TRUE));
}

static uint_t
zs_pset_usage_kernel_cpus(zs_pset_t *pset)
{
	return (zs_ts_used_cpus(&pset->zsp_total_time, &pset->zsp_usage_kern,
	    pset->zsp_online, B_TRUE));
}

static uint64_t
zs_pset_usage_zones_cpus(zs_pset_t *pset)
{
	return (zs_ts_used_cpus(&pset->zsp_total_time, &pset->zsp_usage_zones,
	    pset->zsp_online, B_TRUE));
}

static void
zs_pset_zone_usage_time(zs_pset_zone_t *pz, timestruc_t *t)
{
	*t = pz->zspz_cpu_usage;
}

static uint_t
zs_pset_zone_usage_cpus(zs_pset_zone_t *pz)
{
	return (zs_ts_used_cpus(&pz->zspz_pset->zsp_total_time,
	    &pz->zspz_cpu_usage, pz->zspz_pset->zsp_online, B_TRUE));
}

static uint_t
zs_pset_zone_usage_pct_pset(zs_pset_zone_t *pz)
{
	return (zs_ts_used_pct(&pz->zspz_pset->zsp_total_time,
	    &pz->zspz_cpu_usage, B_TRUE));
}

static uint64_t
zs_pset_zone_cpu_cap(zs_pset_zone_t *pz)
{
	return (pz->zspz_zone->zsz_cpu_cap);
}

static uint_t
zs_pset_zone_usage_pct_cpu_cap(zs_pset_zone_t *pz)
{
	zs_zone_t *zone = pz->zspz_zone;

	if (zone->zsz_cpu_cap == ZS_LIMIT_NONE) {
		return (ZS_PCT_NONE);
	}
	return (zs_ts_used_pct(&zone->zsz_cap_time,
	    &pz->zspz_cpu_usage, B_TRUE));
}

/*
 * Return the fraction of total shares for a pset allocated to the zone.
 */
static uint_t
zs_pset_zone_usage_pct_pset_shares(zs_pset_zone_t *pz)
{
	zs_pset_t *pset = pz->zspz_pset;

	if (!(pz->zspz_scheds & ZS_SCHED_FSS))
		return (ZS_PCT_NONE);

	if (pz->zspz_cpu_shares == ZS_LIMIT_NONE)
		return (ZS_PCT_NONE);

	if (pz->zspz_cpu_shares == ZS_SHARES_UNLIMITED)
		return (ZS_PCT_NONE);

	if (pz->zspz_pset->zsp_cpu_shares == 0)
		return (0);

	if (pz->zspz_cpu_shares == 0)
		return (0);

	return (zs_uint64_used_pct(pset->zsp_cpu_shares, pz->zspz_cpu_shares,
	    B_TRUE));
}

/*
 * Of a zones shares, what percent of cpu time is it using.  For instance,
 * if a zone has 50% of shares, and is using 50% of the cpu time, then it is
 * using 100% of its share.
 */
static uint_t
zs_pset_zone_usage_pct_cpu_shares(zs_pset_zone_t *pz)
{
	timestruc_t tot, time;
	double sharefactor;
	double total;
	double used;
	double pct;

	if (!(pz->zspz_scheds & ZS_SCHED_FSS))
		return (ZS_PCT_NONE);

	if (pz->zspz_cpu_shares == ZS_LIMIT_NONE)
		return (ZS_PCT_NONE);

	if (pz->zspz_cpu_shares == ZS_SHARES_UNLIMITED)
		return (ZS_PCT_NONE);

	if (pz->zspz_cpu_shares == 0)
		return (ZS_PCT_NONE);

	sharefactor = (double)zs_pset_zone_usage_pct_pset_shares(pz);

	/* Common scaling function won't do sharefactor. */
	time = pz->zspz_pset->zsp_total_time;
	tot = pz->zspz_cpu_usage;

	total = (double)time.tv_sec +
	    ((double)time.tv_nsec / (double)NANOSEC);
	total = total * (sharefactor / ZSD_PCT_DOUBLE);
	used = (double)tot.tv_sec +
	    ((double)tot.tv_nsec / (double)NANOSEC);

	pct = used / total * ZSD_PCT_DOUBLE;
	/* Allow percent of share used to exceed 100% */
	return ((uint_t)pct);
}

static void
zs_cpu_total_time(zs_usage_t *usage, timestruc_t *ts)
{
	*ts = usage->zsu_system->zss_cpu_total_time;
}

static void
zs_cpu_usage_all(zs_usage_t *usage, timestruc_t *ts)
{
	timestruc_t tot;

	tot.tv_sec = 0;
	tot.tv_nsec = 0;
	TIMESTRUC_ADD_TIMESTRUC(tot, usage->zsu_system->zss_cpu_usage_kern);
	TIMESTRUC_ADD_TIMESTRUC(tot, usage->zsu_system->zss_cpu_usage_zones);
	*ts = tot;
}

static void
zs_cpu_usage_idle(zs_usage_t *usage, timestruc_t *ts)
{
	timestruc_t tot, time, idle;

	tot.tv_sec = 0;
	tot.tv_nsec = 0;
	tot = usage->zsu_system->zss_cpu_usage_kern;
	TIMESTRUC_ADD_TIMESTRUC(tot, usage->zsu_system->zss_cpu_usage_zones);
	time = usage->zsu_system->zss_cpu_total_time;
	TIMESTRUC_DELTA(idle, time, tot);
	*ts = idle;
}

static uint_t
zs_cpu_usage_all_pct(zs_usage_t *usage)
{
	timestruc_t tot;

	tot = usage->zsu_system->zss_cpu_usage_kern;
	TIMESTRUC_ADD_TIMESTRUC(tot, usage->zsu_system->zss_cpu_usage_zones);

	return (zs_ts_used_pct(&usage->zsu_system->zss_cpu_total_time,
	    &tot, B_TRUE));
}


static uint_t
zs_cpu_usage_idle_pct(zs_usage_t *usage)
{
	timestruc_t tot, idle;

	tot = usage->zsu_system->zss_cpu_usage_kern;
	TIMESTRUC_ADD_TIMESTRUC(tot, usage->zsu_system->zss_cpu_usage_zones);
	TIMESTRUC_DELTA(idle, usage->zsu_system->zss_cpu_total_time, tot);

	return (zs_ts_used_pct(&usage->zsu_system->zss_cpu_total_time,
	    &idle, B_TRUE));
}

static void
zs_cpu_usage_kernel(zs_usage_t *usage, timestruc_t *ts)
{
	*ts = usage->zsu_system->zss_cpu_usage_kern;
}

static uint_t
zs_cpu_usage_kernel_pct(zs_usage_t *usage)
{
	return (zs_ts_used_pct(&usage->zsu_system->zss_cpu_total_time,
	    &usage->zsu_system->zss_cpu_usage_kern, B_TRUE));
}

static void
zs_cpu_usage_zones(zs_usage_t *usage, timestruc_t *ts)
{
	*ts = usage->zsu_system->zss_cpu_usage_zones;
}


static uint_t
zs_cpu_usage_zones_pct(zs_usage_t *usage)
{
	return (zs_ts_used_pct(&usage->zsu_system->zss_cpu_total_time,
	    &usage->zsu_system->zss_cpu_usage_zones, B_TRUE));
}


static void
zs_cpu_usage_zone(zs_zone_t *zone, timestruc_t *ts)
{
	*ts = zone->zsz_cpu_usage;
}

static uint64_t
zs_cpu_total_cpu(zs_usage_t *usage)
{
	return (usage->zsu_system->zss_ncpus_online * ZSD_ONE_CPU);
}

static uint64_t
zs_cpu_usage_all_cpu(zs_usage_t *usage)
{
	timestruc_t tot;

	tot = usage->zsu_system->zss_cpu_usage_kern;
	TIMESTRUC_ADD_TIMESTRUC(tot, usage->zsu_system->zss_cpu_usage_zones);

	return (zs_ts_used_cpus(&usage->zsu_system->zss_cpu_total_time,
	    &tot, usage->zsu_system->zss_ncpus_online, B_TRUE));
}

static uint64_t
zs_cpu_usage_idle_cpu(zs_usage_t *usage)
{
	timestruc_t tot, idle;

	tot = usage->zsu_system->zss_cpu_usage_kern;
	TIMESTRUC_ADD_TIMESTRUC(tot, usage->zsu_system->zss_cpu_usage_zones);
	TIMESTRUC_DELTA(idle, usage->zsu_system->zss_cpu_total_time, tot);

	return (zs_ts_used_cpus(&usage->zsu_system->zss_cpu_total_time,
	    &idle, usage->zsu_system->zss_ncpus_online, B_TRUE));
}

static uint64_t
zs_cpu_usage_kernel_cpu(zs_usage_t *usage)
{
	return (zs_ts_used_cpus(&usage->zsu_system->zss_cpu_total_time,
	    &usage->zsu_system->zss_cpu_usage_kern,
	    usage->zsu_system->zss_ncpus_online, B_TRUE));
}

static uint64_t
zs_cpu_usage_zones_cpu(zs_usage_t *usage)
{
	return (zs_ts_used_cpus(&usage->zsu_system->zss_cpu_total_time,
	    &usage->zsu_system->zss_cpu_usage_kern,
	    usage->zsu_system->zss_ncpus_online, B_TRUE));
}

static uint64_t
zs_cpu_usage_zone_cpu(zs_zone_t *zone)
{
	return (zs_ts_used_cpus(&zone->zsz_pset_time, &zone->zsz_cpu_usage,
	    zone->zsz_cpus_online, B_TRUE));
}

static uint_t
zs_cpu_usage_zone_pct(zs_zone_t *zone)
{
	return (zs_ts_used_pct(&zone->zsz_pset_time, &zone->zsz_cpu_usage,
	    B_TRUE));
}

static uint64_t
zs_physical_memory_total(zs_usage_t *usage)
{
	return (usage->zsu_system->zss_ram_total);
}


static uint64_t
zs_physical_memory_usage_all(zs_usage_t *usage)
{
	return (usage->zsu_system->zss_ram_kern +
	    usage->zsu_system->zss_ram_zones);
}

static uint_t
zs_physical_memory_usage_all_pct(zs_usage_t *usage)
{
	zs_system_t *system = usage->zsu_system;

	return (zs_uint64_used_pct(system->zss_ram_total,
	    (system->zss_ram_kern + system->zss_ram_zones), B_TRUE));
}

static uint64_t
zs_physical_memory_usage_free(zs_usage_t *usage)
{
	return (usage->zsu_system->zss_ram_total -
	    (usage->zsu_system->zss_ram_kern +
	    usage->zsu_system->zss_ram_zones));
}

static uint_t
zs_physical_memory_usage_free_pct(zs_usage_t *usage)
{
	return (ZSD_PCT_INT - zs_physical_memory_usage_all_pct(usage));
}

static uint64_t
zs_physical_memory_usage_kernel(zs_usage_t *usage)
{
	return (usage->zsu_system->zss_ram_kern);
}

static uint_t
zs_physical_memory_usage_kernel_pct(zs_usage_t *usage)
{
	zs_system_t *system = usage->zsu_system;

	return (zs_uint64_used_pct(system->zss_ram_total,
	    system->zss_ram_kern, B_TRUE));
}

static uint64_t
zs_physical_memory_usage_zones(zs_usage_t *usage)
{
	return (usage->zsu_system->zss_ram_zones);
}

static uint_t
zs_physical_memory_usage_zones_pct(zs_usage_t *usage)
{
	zs_system_t *system = usage->zsu_system;

	return (zs_uint64_used_pct(system->zss_ram_total,
	    system->zss_ram_zones, B_TRUE));
}

static uint64_t
zs_physical_memory_usage_zone(zs_zone_t *zone)
{
	return (zone->zsz_usage_ram);
}

static uint_t
zs_physical_memory_usage_zone_pct(zs_zone_t *zone)
{
	zs_system_t *system = zone->zsz_system;

	return (zs_uint64_used_pct(system->zss_ram_total,
	    zone->zsz_usage_ram, B_TRUE));
}

static uint_t
zs_zone_physical_memory_cap_pct(zs_zone_t *zone)
{
	if (zone->zsz_ram_cap == ZS_LIMIT_NONE)
		return (ZS_PCT_NONE);

	if (zone->zsz_ram_cap == 0) {
		return (0);
	}

	/* Allow ram cap to exeed 100% */
	return (zs_uint64_used_pct(zone->zsz_ram_cap,
	    zone->zsz_usage_ram, B_FALSE));
}
static uint64_t
zs_virtual_memory_total(zs_usage_t *usage)
{
	return (usage->zsu_system->zss_vm_total);
}

static uint64_t
zs_virtual_memory_usage_all(zs_usage_t *usage)
{
	return (usage->zsu_system->zss_vm_kern +
	    usage->zsu_system->zss_vm_zones);
}
static uint64_t
zs_virtual_memory_usage_free(zs_usage_t *usage)
{
	return (usage->zsu_system->zss_vm_total -
	    (usage->zsu_system->zss_vm_kern +
	    usage->zsu_system->zss_vm_zones));
}
static uint_t
zs_virtual_memory_usage_all_pct(zs_usage_t *usage)
{
	zs_system_t *system = usage->zsu_system;

	return (zs_uint64_used_pct(system->zss_vm_total,
	    (system->zss_vm_kern + system->zss_vm_zones), B_TRUE));

}

static uint_t
zs_virtual_memory_usage_free_pct(zs_usage_t *usage)
{
	return (ZSD_PCT_INT - zs_virtual_memory_usage_all_pct(usage));

}
static uint64_t
zs_virtual_memory_usage_kernel(zs_usage_t *usage)
{
	return (usage->zsu_system->zss_vm_kern);
}

static uint_t
zs_virtual_memory_usage_kernel_pct(zs_usage_t *usage)
{
	zs_system_t *system = usage->zsu_system;

	return (zs_uint64_used_pct(system->zss_vm_total,
	    system->zss_vm_kern, B_TRUE));
}

static uint64_t
zs_virtual_memory_usage_zones(zs_usage_t *usage)
{
	return (usage->zsu_system->zss_vm_zones);
}

static uint_t
zs_virtual_memory_usage_zones_pct(zs_usage_t *usage)
{
	zs_system_t *system = usage->zsu_system;

	return (zs_uint64_used_pct(system->zss_vm_total,
	    system->zss_vm_zones, B_TRUE));
}

static uint64_t
zs_virtual_memory_usage_zone(zs_zone_t *zone)
{
	return (zone->zsz_usage_vm);
}

static uint_t
zs_virtual_memory_usage_zone_pct(zs_zone_t *zone)
{
	zs_system_t *system = zone->zsz_system;

	return (zs_uint64_used_pct(system->zss_vm_total,
	    zone->zsz_usage_vm, B_TRUE));

}

static uint_t
zs_zone_virtual_memory_cap_pct(zs_zone_t *zone)
{
	if (zone->zsz_vm_cap == ZS_LIMIT_NONE)
		return (ZS_PCT_NONE);

	if (zone->zsz_vm_cap == 0)
		return (0);

	return (zs_uint64_used_pct(zone->zsz_vm_cap,
	    zone->zsz_usage_vm, B_TRUE));
}

static uint64_t
zs_locked_memory_total(zs_usage_t *usage)
{
	return (usage->zsu_system->zss_ram_total);
}

static uint64_t
zs_locked_memory_usage_all(zs_usage_t *usage)
{
	return (usage->zsu_system->zss_locked_kern +
	    usage->zsu_system->zss_locked_zones);
}
static uint64_t
zs_locked_memory_usage_free(zs_usage_t *usage)
{
	return (usage->zsu_system->zss_ram_total -
	    (usage->zsu_system->zss_locked_kern +
	    usage->zsu_system->zss_locked_zones));
}

static uint_t
zs_locked_memory_usage_all_pct(zs_usage_t *usage)
{
	zs_system_t *system = usage->zsu_system;

	return (zs_uint64_used_pct(system->zss_ram_total,
	    (system->zss_locked_kern + system->zss_locked_zones), B_TRUE));
}

static uint_t
zs_locked_memory_usage_free_pct(zs_usage_t *usage)
{
	return (ZSD_PCT_INT - zs_locked_memory_usage_all_pct(usage));

}

static uint64_t
zs_locked_memory_usage_kernel(zs_usage_t *usage)
{
	return (usage->zsu_system->zss_locked_kern);
}

static uint_t
zs_locked_memory_usage_kernel_pct(zs_usage_t *usage)
{
	zs_system_t *system = usage->zsu_system;

	return (zs_uint64_used_pct(system->zss_ram_total,
	    system->zss_locked_kern, B_TRUE));
}

static uint64_t
zs_locked_memory_usage_zones(zs_usage_t *usage)
{
	return (usage->zsu_system->zss_locked_zones);
}

static uint_t
zs_locked_memory_usage_zones_pct(zs_usage_t *usage)
{
	zs_system_t *system = usage->zsu_system;

	return (zs_uint64_used_pct(system->zss_ram_total,
	    system->zss_locked_zones, B_TRUE));
}

static uint64_t
zs_locked_memory_usage_zone(zs_zone_t *zone)
{
	return (zone->zsz_usage_locked);
}

static uint_t
zs_locked_memory_usage_zone_pct(zs_zone_t *zone)
{
	zs_system_t *system = zone->zsz_system;

	return (zs_uint64_used_pct(system->zss_ram_total,
	    zone->zsz_usage_locked, B_TRUE));
}

static uint_t
zs_zone_locked_memory_cap_pct(zs_zone_t *zone)
{
	if (zone->zsz_locked_cap == ZS_LIMIT_NONE)
		return (ZS_PCT_NONE);

	if (zone->zsz_locked_cap == 0)
		return (0);

	return (zs_uint64_used_pct(zone->zsz_locked_cap,
	    zone->zsz_usage_locked, B_TRUE));

}
static uint64_t
zs_disk_swap_total(zs_usage_t *usage)
{
	return (usage->zsu_system->zss_swap_total);
}

static uint64_t
zs_disk_swap_usage_all(zs_usage_t *usage)
{
	return (usage->zsu_system->zss_swap_used);
}

static uint_t
zs_disk_swap_usage_all_pct(zs_usage_t *usage)
{
	return (zs_uint64_used_pct(usage->zsu_system->zss_swap_total,
	    usage->zsu_system->zss_swap_used, B_TRUE));
}

static uint64_t
zs_disk_swap_usage_free(zs_usage_t *usage)
{
	return (usage->zsu_system->zss_swap_total -
	    usage->zsu_system->zss_swap_used);
}

static uint_t
zs_disk_swap_usage_free_pct(zs_usage_t *usage)
{
	return (ZSD_PCT_INT - zs_disk_swap_usage_all_pct(usage));
}

static uint64_t
zs_processes_total(zs_usage_t *usage)
{
	return (usage->zsu_system->zss_processes_max);
}

static uint64_t
zs_lwps_total(zs_usage_t *usage)
{
	return (usage->zsu_system->zss_lwps_max);
}

static uint64_t
zs_shm_total(zs_usage_t *usage)
{
	return (usage->zsu_system->zss_shm_max);
}

static uint64_t
zs_shmids_total(zs_usage_t *usage)
{
	return (usage->zsu_system->zss_shmids_max);
}

static uint64_t
zs_semids_total(zs_usage_t *usage)
{
	return (usage->zsu_system->zss_semids_max);
}

static uint64_t
zs_msgids_total(zs_usage_t *usage)
{
	return (usage->zsu_system->zss_msgids_max);
}

static uint64_t
zs_lofi_total(zs_usage_t *usage)
{
	return (usage->zsu_system->zss_lofi_max);
}

static uint64_t
zs_processes_usage_all(zs_usage_t *usage)
{
	return (usage->zsu_system->zss_processes);
}

static uint64_t
zs_lwps_usage_all(zs_usage_t *usage)
{
	return (usage->zsu_system->zss_lwps);
}

static uint64_t
zs_shm_usage_all(zs_usage_t *usage)
{
	return (usage->zsu_system->zss_shm);
}

static uint64_t
zs_shmids_usage_all(zs_usage_t *usage)
{
	return (usage->zsu_system->zss_shmids);
}

static uint64_t
zs_semids_usage_all(zs_usage_t *usage)
{
	return (usage->zsu_system->zss_semids);
}

static uint64_t
zs_msgids_usage_all(zs_usage_t *usage)
{
	return (usage->zsu_system->zss_msgids);
}

static uint64_t
zs_lofi_usage_all(zs_usage_t *usage)
{
	return (usage->zsu_system->zss_lofi);
}
static uint64_t
zs_processes_usage_all_pct(zs_usage_t *usage)
{
	zs_system_t *system = usage->zsu_system;

	return (zs_uint64_used_pct(system->zss_processes_max,
	    system->zss_processes, B_TRUE));
}

static uint_t
zs_lwps_usage_all_pct(zs_usage_t *usage)
{
	zs_system_t *system = usage->zsu_system;

	return (zs_uint64_used_pct(system->zss_lwps_max,
	    system->zss_lwps, B_TRUE));
}

static uint_t
zs_shm_usage_all_pct(zs_usage_t *usage)
{
	zs_system_t *system = usage->zsu_system;

	return (zs_uint64_used_pct(system->zss_shm_max,
	    system->zss_shm, B_TRUE));
}

static uint_t
zs_shmids_usage_all_pct(zs_usage_t *usage)
{
	zs_system_t *system = usage->zsu_system;

	return (zs_uint64_used_pct(system->zss_shmids_max,
	    system->zss_shmids, B_TRUE));
}

static uint64_t
zs_semids_usage_all_pct(zs_usage_t *usage)
{
	zs_system_t *system = usage->zsu_system;

	return (zs_uint64_used_pct(system->zss_semids_max,
	    system->zss_semids, B_TRUE));
}

static uint64_t
zs_msgids_usage_all_pct(zs_usage_t *usage)
{
	zs_system_t *system = usage->zsu_system;

	return (zs_uint64_used_pct(system->zss_msgids_max,
	    system->zss_msgids, B_TRUE));
}

static uint64_t
zs_lofi_usage_all_pct(zs_usage_t *usage)
{
	zs_system_t *system = usage->zsu_system;

	return (zs_uint64_used_pct(system->zss_lofi_max,
	    system->zss_lofi, B_TRUE));
}

static uint64_t
zs_processes_usage_zone(zs_zone_t *zone)
{
	return (zone->zsz_processes);
}

static uint64_t
zs_lwps_usage_zone(zs_zone_t *zone)
{
	return (zone->zsz_lwps);
}

static uint64_t
zs_shm_usage_zone(zs_zone_t *zone)
{
	return (zone->zsz_shm);
}

static uint64_t
zs_shmids_usage_zone(zs_zone_t *zone)
{
	return (zone->zsz_shmids);
}

static uint64_t
zs_semids_usage_zone(zs_zone_t *zone)
{
	return (zone->zsz_semids);
}

static uint64_t
zs_msgids_usage_zone(zs_zone_t *zone)
{
	return (zone->zsz_msgids);
}

static uint64_t
zs_lofi_usage_zone(zs_zone_t *zone)
{
	return (zone->zsz_lofi);
}

static uint_t
zs_processes_usage_zone_pct(zs_zone_t *zone)
{
	zs_system_t *system = zone->zsz_system;

	return (zs_uint64_used_pct(system->zss_processes_max,
	    zone->zsz_processes, B_TRUE));
}

static uint_t
zs_lwps_usage_zone_pct(zs_zone_t *zone)
{
	zs_system_t *system = zone->zsz_system;

	return (zs_uint64_used_pct(system->zss_lwps_max,
	    zone->zsz_lwps, B_TRUE));
}

static uint_t
zs_shm_usage_zone_pct(zs_zone_t *zone)
{
	zs_system_t *system = zone->zsz_system;

	return (zs_uint64_used_pct(system->zss_shm_max,
	    zone->zsz_shm, B_TRUE));
}

static uint_t
zs_shmids_usage_zone_pct(zs_zone_t *zone)
{
	zs_system_t *system = zone->zsz_system;

	return (zs_uint64_used_pct(system->zss_shmids_max,
	    zone->zsz_shmids, B_TRUE));
}

static uint_t
zs_semids_usage_zone_pct(zs_zone_t *zone)
{
	zs_system_t *system = zone->zsz_system;

	return (zs_uint64_used_pct(system->zss_semids_max,
	    zone->zsz_semids, B_TRUE));
}

static uint_t
zs_msgids_usage_zone_pct(zs_zone_t *zone)
{
	zs_system_t *system = zone->zsz_system;

	return (zs_uint64_used_pct(system->zss_msgids_max,
	    zone->zsz_msgids, B_TRUE));
}

static uint_t
zs_lofi_usage_zone_pct(zs_zone_t *zone)
{
	zs_system_t *system = zone->zsz_system;

	return (zs_uint64_used_pct(system->zss_lofi_max,
	    zone->zsz_lofi, B_TRUE));
}

static uint_t
zs_processes_zone_cap_pct(zs_zone_t *zone)
{
	if (zone->zsz_processes_cap == ZS_LIMIT_NONE)
		return (ZS_PCT_NONE);

	if (zone->zsz_processes_cap == 0)
		return (0);

	return (zs_uint64_used_pct(zone->zsz_processes_cap,
	    zone->zsz_processes, B_TRUE));
}

static uint_t
zs_lwps_zone_cap_pct(zs_zone_t *zone)
{
	if (zone->zsz_lwps_cap == ZS_LIMIT_NONE)
		return (ZS_PCT_NONE);

	if (zone->zsz_lwps_cap == 0)
		return (0);

	return (zs_uint64_used_pct(zone->zsz_lwps_cap, zone->zsz_lwps, B_TRUE));
}

static uint_t
zs_shm_zone_cap_pct(zs_zone_t *zone)
{
	if (zone->zsz_shm_cap == ZS_LIMIT_NONE)
		return (ZS_PCT_NONE);

	if (zone->zsz_shm_cap == 0)
		return (0);

	return (zs_uint64_used_pct(zone->zsz_shm_cap, zone->zsz_shm, B_TRUE));
}

static uint_t
zs_shmids_zone_cap_pct(zs_zone_t *zone)
{
	if (zone->zsz_shmids_cap == ZS_LIMIT_NONE)
		return (ZS_PCT_NONE);

	if (zone->zsz_shmids_cap == 0)
		return (0);

	return (zs_uint64_used_pct(zone->zsz_shmids_cap, zone->zsz_shmids,
	    B_TRUE));
}

static uint_t
zs_semids_zone_cap_pct(zs_zone_t *zone)
{
	if (zone->zsz_semids_cap == ZS_LIMIT_NONE)
		return (ZS_PCT_NONE);

	if (zone->zsz_semids_cap == 0)
		return (0);

	return (zs_uint64_used_pct(zone->zsz_semids_cap, zone->zsz_semids,
	    B_TRUE));
}

static uint_t
zs_msgids_zone_cap_pct(zs_zone_t *zone)
{
	if (zone->zsz_msgids_cap == ZS_LIMIT_NONE)
		return (ZS_PCT_NONE);

	if (zone->zsz_msgids_cap == 0)
		return (0);

	return (zs_uint64_used_pct(zone->zsz_msgids_cap, zone->zsz_msgids,
	    B_TRUE));
}

static uint_t
zs_lofi_zone_cap_pct(zs_zone_t *zone)
{
	if (zone->zsz_lofi_cap == ZS_LIMIT_NONE)
		return (ZS_PCT_NONE);

	if (zone->zsz_lofi_cap == 0)
		return (0);

	return (zs_uint64_used_pct(zone->zsz_lofi_cap, zone->zsz_lofi,
	    B_TRUE));
}

/* All funcs this line should be static */

void
zs_close(zs_ctl_t *ctl)
{
	(void) close(ctl->zsctl_door);
	zs_usage_free(ctl->zsctl_start);
	free(ctl);
}

/*
 * ERRORS
 *
 *	EINTR   signal received, process forked, or zonestatd exited
 *      ESRCH	zonestatd not responding
 */
static zs_usage_t *
zs_usage_read_internal(zs_ctl_t *ctl, int init)
{
	int fd = -1;
	uint_t i, j;
	zs_usage_t *usage;
	zs_zone_t *zone = NULL;
	zs_pset_t *pset = NULL;
	zs_pset_zone_t *pz;
	char *next;
	uint64_t cmd[2];
	door_arg_t params;

	fd = ctl->zsctl_door;
	cmd[0] = ZSD_CMD_READ;
	cmd[1] = ctl->zsctl_gen;
	params.data_ptr = (char *)cmd;
	params.data_size = sizeof (cmd);
	params.desc_ptr = NULL;
	params.desc_num = 0;
	params.rbuf = NULL;
	params.rsize = 0;

	if (door_call(fd, &params) != 0) {
		if (errno != EINTR)
			errno = ESRCH;
		return (NULL);
	}

	if (params.rbuf == NULL) {
		errno = ESRCH;
		return (NULL);
	}
	/* LINTED */
	usage = (zs_usage_t *)params.data_ptr;
	ctl->zsctl_gen = usage->zsu_gen;
	usage->zsu_mmap = B_TRUE;
	usage->zsu_intervals = 0;

	list_create(&usage->zsu_zone_list, sizeof (zs_zone_t),
	    offsetof(zs_zone_t, zsz_next));
	list_create(&usage->zsu_pset_list, sizeof (zs_pset_t),
	    offsetof(zs_pset_t, zsp_next));

	/* Fix up next pointers inside usage_t */
	next = (char *)usage;
	next += sizeof (zs_usage_t);

	/* LINTED */
	usage->zsu_system = (zs_system_t *)next;
	next += sizeof (zs_system_t);

	for (i = 0; i < usage->zsu_nzones; i++) {
		/* LINTED */
		zone = (zs_zone_t *)next;
		list_insert_tail(&usage->zsu_zone_list, zone);
		next += sizeof (zs_zone_t);
		zone->zsz_system = usage->zsu_system;
		zone->zsz_intervals = 0;
	}

	for (i = 0; i < usage->zsu_npsets; i++) {
		/* LINTED */
		pset = (zs_pset_t *)next;
		list_insert_tail(&usage->zsu_pset_list, pset);
		next += sizeof (zs_pset_t);
		list_create(&pset->zsp_usage_list, sizeof (zs_pset_zone_t),
		    offsetof(zs_pset_zone_t, zspz_next));
		for (j = 0; j < pset->zsp_nusage; j++) {
			/* LINTED */
			pz = (zs_pset_zone_t *)next;
			list_insert_tail(&pset->zsp_usage_list, pz);
			next += sizeof (zs_pset_zone_t);
			pz->zspz_pset = pset;
			pz->zspz_zone =
			    zs_lookup_zone_byid(usage, pz->zspz_zoneid);
			assert(pz->zspz_zone != NULL);
			pz->zspz_intervals = 0;
		}
		pset->zsp_intervals = 0;
	}
	if (init)
		return (usage);

	/*
	 * If current usage tracking started after start usage, then
	 * no need to subtract start usage.  This really can't happen,
	 * as zonestatd should never start over while this client is
	 * connected.
	 */
	if (usage->zsu_hrstart > ctl->zsctl_start->zsu_hrtime) {
		return (usage);
	}

	/*
	 * Compute usage relative to first open.  Usage returned by
	 * zonestatd starts at an arbitrary point in the past.
	 *
	 */

	(void) zs_usage_compute(usage, ctl->zsctl_start, usage,
	    ZS_COMPUTE_USAGE_INTERVAL);

	return (usage);
}

zs_usage_t *
zs_usage_read(zs_ctl_t *ctl)
{
	return (zs_usage_read_internal(ctl, B_FALSE));
}

/*
 * Open connection to zonestatd.  NULL of failure, with errno set:
 *
 *  EPERM:  Insufficent privilege (no PRIV_PROC_INFO)
 *  ESRCH:  Zones monitoring service not available or responding
 *  ENOTSUP: Incompatiable zones monitoring service version.
 *  EINTR: Server exited or client forked.
 *  ENOMEM: as malloc(3c)
 *  EAGAIN: asl malloc(3c)
 *
 */
zs_ctl_t *
zs_open()
{
	zs_ctl_t *ctl;
	int cmd[2];
	int *res;
	int fd;
	door_arg_t params;
	door_desc_t *door;
	int errno_save;

	ctl = calloc(sizeof (zs_ctl_t), 1);
	if (ctl == NULL)
		return (NULL);

	fd = zs_connect_zonestatd();
	if (fd < 0) {
		free(ctl);
		errno = ESRCH;
		return (NULL);
	}

	cmd[0] = ZSD_CMD_CONNECT;
	cmd[1] = ZS_VERSION;
	params.data_ptr = (char *)cmd;
	params.data_size = sizeof (cmd);
	params.desc_ptr = NULL;
	params.desc_num = 0;
	params.rbuf = NULL;
	params.rsize = 0;
	if (door_call(fd, &params) != 0) {
		errno_save = errno;
		free(ctl);
		(void) close(fd);
		if (errno_save == EINTR)
			errno = EINTR;
		else
			errno = ESRCH;
		return (NULL);
	}
	(void) close(fd);
	/* LINTED */
	res = (int *)params.data_ptr;
	if (res[1] == ZSD_STATUS_VERSION_MISMATCH) {
		free(ctl);
		errno = ENOTSUP;
		return (NULL);
	}
	if (res[1] == ZSD_STATUS_PERMISSION) {
		free(ctl);
		errno = EPERM;
		return (NULL);
	}
	if (res[1] != ZSD_STATUS_OK) {
		free(ctl);
		errno = ESRCH;
		return (NULL);
	}

	door = params.desc_ptr;
	if (door == NULL) {
		free(ctl);
		return (NULL);
	}
	ctl->zsctl_door = door->d_data.d_desc.d_descriptor;

	if (params.data_ptr != (char *)cmd)
		(void) munmap(params.data_ptr, params.data_size);


	/*
	 * Get the initial usage from zonestatd.  This creates a
	 * zero-point on which to base future usages returned by
	 * zs_read().
	 */
	ctl->zsctl_start = zs_usage_read_internal(ctl, B_TRUE);
	if (ctl->zsctl_start == NULL) {
		errno_save = errno;
		(void) close(ctl->zsctl_door);
		free(ctl);
		if (errno_save == EINTR)
			errno = EINTR;
		else
			errno = ESRCH;
		return (NULL);
	}
	return (ctl);
}

/*
 * Return NULL on error.
 *
 * ERRORS:
 *		EINVAL:  Invalid function.
 */
zs_usage_t *
zs_usage_compute(zs_usage_t *ures, zs_usage_t *uold, zs_usage_t *unew,
    int func)
{
	zs_system_t *sold, *snew, *sres;
	boolean_t alloced = B_FALSE;

	if (func != ZS_COMPUTE_USAGE_INTERVAL &&
	    func != ZS_COMPUTE_USAGE_TOTAL &&
	    func != ZS_COMPUTE_USAGE_AVERAGE &&
	    func != ZS_COMPUTE_USAGE_HIGH)
		assert(0);

	if (ures == NULL) {
		alloced = B_TRUE;
		ures = zs_usage_alloc();
		if (ures == NULL)
			return (NULL);
	}

	sres = ures->zsu_system;
	sold = uold->zsu_system;
	snew = unew->zsu_system;

	switch (func) {
	case ZS_COMPUTE_USAGE_INTERVAL:
		/* Use system totals from newer interval */
		if (sres != snew)
			*sres = *snew;

		TIMESTRUC_DELTA(sres->zss_cpu_total_time,
		    snew->zss_cpu_total_time, sold->zss_cpu_total_time);
		TIMESTRUC_DELTA(sres->zss_cpu_usage_kern,
		    snew->zss_cpu_usage_kern, sold->zss_cpu_usage_kern);
		TIMESTRUC_DELTA(sres->zss_cpu_usage_zones,
		    snew->zss_cpu_usage_zones, sold->zss_cpu_usage_zones);
		break;
	case ZS_COMPUTE_USAGE_HIGH:

		/* Find max cpus */
		sres->zss_ncpus = MAX(sold->zss_ncpus, snew->zss_ncpus);
		sres->zss_ncpus_online = MAX(sold->zss_ncpus_online,
		    snew->zss_ncpus_online);

		/* Find max cpu times */
		sres->zss_cpu_total_time = ZS_MAXTS(sold->zss_cpu_total_time,
		    snew->zss_cpu_total_time);
		sres->zss_cpu_usage_kern = ZS_MAXTS(sold->zss_cpu_usage_kern,
		    snew->zss_cpu_usage_kern);
		sres->zss_cpu_usage_zones = ZS_MAXTS(sold->zss_cpu_usage_zones,
		    snew->zss_cpu_usage_zones);

		/* These don't change */
		sres->zss_processes_max = snew->zss_processes_max;
		sres->zss_lwps_max = snew->zss_lwps_max;
		sres->zss_shm_max = snew->zss_shm_max;
		sres->zss_shmids_max = snew->zss_shmids_max;
		sres->zss_semids_max = snew->zss_semids_max;
		sres->zss_msgids_max = snew->zss_msgids_max;
		sres->zss_lofi_max = snew->zss_lofi_max;
		/*
		 * Add in memory values and limits.  Scale memory to
		 * avoid overflow.
		 */
		sres->zss_ram_total = MAX(sold->zss_ram_total,
		    snew->zss_ram_total);
		sres->zss_ram_kern = MAX(sold->zss_ram_kern,
		    snew->zss_ram_kern);
		sres->zss_ram_zones = MAX(sold->zss_ram_zones,
		    snew->zss_ram_zones);
		sres->zss_locked_kern = MAX(sold->zss_locked_kern,
		    snew->zss_locked_kern);
		sres->zss_locked_zones = MAX(sold->zss_locked_zones,
		    snew->zss_locked_zones);
		sres->zss_vm_total = MAX(sold->zss_vm_total,
		    snew->zss_vm_total);
		sres->zss_vm_kern = MAX(sold->zss_vm_kern,
		    snew->zss_vm_kern);
		sres->zss_vm_zones = MAX(sold->zss_vm_zones,
		    snew->zss_vm_zones);
		sres->zss_swap_total = MAX(sold->zss_swap_total,
		    snew->zss_swap_total);
		sres->zss_swap_used = MAX(sold->zss_swap_used,
		    snew->zss_swap_used);

		sres->zss_processes = MAX(sold->zss_processes,
		    snew->zss_processes);
		sres->zss_lwps = MAX(sold->zss_lwps, snew->zss_lwps);
		sres->zss_shm = MAX(sold->zss_shm, snew->zss_shm);
		sres->zss_shmids = MAX(sold->zss_shmids, snew->zss_shmids);
		sres->zss_semids = MAX(sold->zss_semids, snew->zss_semids);
		sres->zss_msgids = MAX(sold->zss_msgids, snew->zss_msgids);
		sres->zss_lofi = MAX(sold->zss_msgids, snew->zss_lofi);
	break;
	case ZS_COMPUTE_USAGE_TOTAL:
		/* FALLTHROUGH */
	case ZS_COMPUTE_USAGE_AVERAGE:
		ures->zsu_intervals++;

		/*
		 * Add cpus.  The total report will divide this by the
		 * number of intervals to give the average number of cpus
		 * over all intervals.
		 */
		sres->zss_ncpus = sold->zss_ncpus + snew->zss_ncpus;
		sres->zss_ncpus_online = sold->zss_ncpus_online +
		    snew->zss_ncpus_online;

		/* Add in cpu times */
		sres->zss_cpu_total_time = sold->zss_cpu_total_time;
		TIMESTRUC_ADD_TIMESTRUC(sres->zss_cpu_total_time,
		    snew->zss_cpu_total_time);
		sres->zss_cpu_usage_kern = sold->zss_cpu_usage_kern;
		TIMESTRUC_ADD_TIMESTRUC(sres->zss_cpu_usage_kern,
		    snew->zss_cpu_usage_kern);
		sres->zss_cpu_usage_zones = sold->zss_cpu_usage_zones;
		TIMESTRUC_ADD_TIMESTRUC(sres->zss_cpu_usage_zones,
		    snew->zss_cpu_usage_zones);

		/* These don't change */
		sres->zss_processes_max = snew->zss_processes_max;
		sres->zss_lwps_max = snew->zss_lwps_max;
		sres->zss_shm_max = snew->zss_shm_max;
		sres->zss_shmids_max = snew->zss_shmids_max;
		sres->zss_semids_max = snew->zss_semids_max;
		sres->zss_msgids_max = snew->zss_msgids_max;
		sres->zss_lofi_max = snew->zss_lofi_max;
		/*
		 * Add in memory values and limits.  Scale memory to
		 * avoid overflow.
		 */
		if (sres != sold) {
			sres->zss_ram_total = sold->zss_ram_total / 1024;
			sres->zss_ram_kern = sold->zss_ram_kern / 1024;
			sres->zss_ram_zones = sold->zss_ram_zones / 1024;
			sres->zss_locked_kern = sold->zss_locked_kern / 1024;
			sres->zss_locked_zones = sold->zss_locked_zones / 1024;
			sres->zss_vm_total = sold->zss_vm_total / 1024;
			sres->zss_vm_kern = sold->zss_vm_kern / 1024;
			sres->zss_vm_zones = sold->zss_vm_zones / 1024;
			sres->zss_swap_total = sold->zss_swap_total / 1024;
			sres->zss_swap_used = sold->zss_swap_used / 1024;

			sres->zss_processes = sold->zss_processes;
			sres->zss_lwps = sold->zss_lwps;
			sres->zss_shm = sold->zss_shm / 1024;
			sres->zss_shmids = sold->zss_shmids;
			sres->zss_semids = sold->zss_semids;
			sres->zss_msgids = sold->zss_msgids;
			sres->zss_lofi = sold->zss_lofi;
		}
		/* Add in new values. */
		sres->zss_ram_total += (snew->zss_ram_total / 1024);
		sres->zss_ram_kern += (snew->zss_ram_kern / 1024);
		sres->zss_ram_zones += (snew->zss_ram_zones / 1024);
		sres->zss_locked_kern += (snew->zss_locked_kern / 1024);
		sres->zss_locked_zones += (snew->zss_locked_zones / 1024);
		sres->zss_vm_total += (snew->zss_vm_total / 1024);
		sres->zss_vm_kern += (snew->zss_vm_kern / 1024);
		sres->zss_vm_zones += (snew->zss_vm_zones / 1024);
		sres->zss_swap_total += (snew->zss_swap_total / 1024);
		sres->zss_swap_used += (snew->zss_swap_used / 1024);
		sres->zss_processes += snew->zss_processes;
		sres->zss_lwps += snew->zss_lwps;
		sres->zss_shm += (snew->zss_shm / 1024);
		sres->zss_shmids += snew->zss_shmids;
		sres->zss_semids += snew->zss_semids;
		sres->zss_msgids += snew->zss_msgids;
		sres->zss_lofi += snew->zss_lofi;
		break;
	default:
		if (alloced)
			zs_usage_free(ures);
		assert(0);
	}
	if (zs_usage_compute_zones(ures, uold, unew, func) != 0)
		goto err;

	if (zs_usage_compute_psets(ures, uold, unew, func) != 0)
		goto err;

	return (ures);
err:
	if (alloced)
		zs_usage_free(ures);
	return (NULL);
}

void
zs_usage_free(zs_usage_t *usage)
{
	zs_zone_t *zone, *ztmp;
	zs_pset_t *pset, *ptmp;
	zs_pset_zone_t *pz, *pztmp;

	if (usage->zsu_mmap) {
		(void) munmap((void *)usage, usage->zsu_size);
		return;
	}
	free(usage->zsu_system);
	zone = list_head(&usage->zsu_zone_list);
	while (zone != NULL) {
			ztmp = zone;
			zone = list_next(&usage->zsu_zone_list, zone);
			free(ztmp);
	}
	pset = list_head(&usage->zsu_pset_list);
	while (pset != NULL) {
		pz = list_head(&pset->zsp_usage_list);
		while (pz != NULL) {
			pztmp = pz;
			pz = list_next(&pset->zsp_usage_list, pz);
			free(pztmp);
		}
		ptmp = pset;
		pset = list_next(&usage->zsu_pset_list, pset);
		free(ptmp);
	}
	free(usage);
}

zs_usage_set_t *
zs_usage_set_alloc()
{
	zs_usage_set_t *set;

	set = calloc(sizeof (zs_usage_set_t), 1);
	if (set == NULL)
		return (NULL);

	if ((set->zsus_total = zs_usage_alloc()) == NULL)
		goto err;
	if ((set->zsus_avg = zs_usage_alloc()) == NULL)
		goto err;
	if ((set->zsus_high = zs_usage_alloc()) == NULL)
		goto err;

	return (set);

err:
	if (set->zsus_total != NULL)
		free(set->zsus_total);
	if (set->zsus_avg != NULL)
		free(set->zsus_avg);
	if (set->zsus_high != NULL)
		free(set->zsus_high);

	return (NULL);
}

void
zs_usage_set_free(zs_usage_set_t *set)
{
	zs_usage_free(set->zsus_total);
	zs_usage_free(set->zsus_avg);
	zs_usage_free(set->zsus_high);
	free(set);
}

int
zs_usage_set_add(zs_usage_set_t *set, zs_usage_t *usage)
{

	/* Compute ongoing functions for usage set */
	(void) zs_usage_compute(set->zsus_high, set->zsus_high, usage,
	    ZS_COMPUTE_USAGE_HIGH);

	(void) zs_usage_compute(set->zsus_total, set->zsus_total, usage,
	    ZS_COMPUTE_USAGE_TOTAL);

	(void) zs_usage_compute(set->zsus_avg, set->zsus_avg, usage,
	    ZS_COMPUTE_USAGE_AVERAGE);

	set->zsus_count++;
	zs_usage_free(usage);
	return (0);
}

int
zs_usage_set_count(zs_usage_set_t *set)
{
	return (set->zsus_count);
}

zs_usage_t *
zs_usage_set_compute(zs_usage_set_t *set,  int func)
{
	zs_usage_t *u;
	zs_system_t *s;
	zs_zone_t *z;
	zs_pset_t *p;
	zs_pset_zone_t *pz;
	uint_t intervals;
	boolean_t average;

	switch (func) {
	case ZS_COMPUTE_SET_HIGH:
		return (set->zsus_high);
	case ZS_COMPUTE_SET_TOTAL:
		u = set->zsus_total;
		average = B_FALSE;
		break;
	case ZS_COMPUTE_SET_AVERAGE:
		u = set->zsus_avg;
		average = B_TRUE;
		break;
	default:
		assert(0);
	}

	s = u->zsu_system;

	s->zss_ram_total /= u->zsu_intervals;
	s->zss_ram_total *= 1024;
	s->zss_ram_kern /= u->zsu_intervals;
	s->zss_ram_kern *= 1024;
	s->zss_ram_zones /= u->zsu_intervals;
	s->zss_ram_zones *= 1024;
	s->zss_locked_kern /= u->zsu_intervals;
	s->zss_locked_kern *= 1024;
	s->zss_locked_zones /= u->zsu_intervals;
	s->zss_locked_zones *= 1024;
	s->zss_vm_total /= u->zsu_intervals;
	s->zss_vm_total *= 1024;
	s->zss_vm_kern /= u->zsu_intervals;
	s->zss_vm_kern *= 1024;
	s->zss_vm_zones /= u->zsu_intervals;
	s->zss_vm_zones *= 1024;
	s->zss_swap_total /= u->zsu_intervals;
	s->zss_swap_total *= 1024;
	s->zss_swap_used /= u->zsu_intervals;
	s->zss_swap_used *= 1024;
	s->zss_processes /= u->zsu_intervals;
	s->zss_lwps /= u->zsu_intervals;
	s->zss_shm /= u->zsu_intervals;
	s->zss_shm *= 1024;
	s->zss_shmids /= u->zsu_intervals;
	s->zss_semids /= u->zsu_intervals;
	s->zss_msgids /= u->zsu_intervals;
	s->zss_lofi /= u->zsu_intervals;

	s->zss_ncpus /= u->zsu_intervals;
	s->zss_ncpus_online /= u->zsu_intervals;

	for (z = list_head(&u->zsu_zone_list); z != NULL;
	    z = list_next(&u->zsu_zone_list, z)) {

		if (average) {
			intervals = z->zsz_intervals;
		} else {
			assert(z->zsz_intervals == 0);
			intervals = u->zsu_intervals;
		}

		if (z->zsz_cpu_cap != ZS_LIMIT_NONE)
			z->zsz_cpu_cap /= z->zsz_intervals;
		if (z->zsz_ram_cap != ZS_LIMIT_NONE)
			z->zsz_ram_cap /= z->zsz_intervals;
		if (z->zsz_vm_cap != ZS_LIMIT_NONE)
			z->zsz_vm_cap /= z->zsz_intervals;
		if (z->zsz_locked_cap != ZS_LIMIT_NONE)
			z->zsz_locked_cap /= z->zsz_intervals;
		if (z->zsz_processes_cap != ZS_LIMIT_NONE)
			z->zsz_processes_cap /= z->zsz_intervals;
		if (z->zsz_lwps_cap != ZS_LIMIT_NONE)
			z->zsz_lwps_cap /= z->zsz_intervals;
		if (z->zsz_shm_cap != ZS_LIMIT_NONE)
			z->zsz_shm_cap /= z->zsz_intervals;
		if (z->zsz_shmids_cap != ZS_LIMIT_NONE)
			z->zsz_shmids_cap /= z->zsz_intervals;
		if (z->zsz_semids_cap != ZS_LIMIT_NONE)
			z->zsz_semids_cap /= z->zsz_intervals;
		if (z->zsz_msgids_cap != ZS_LIMIT_NONE)
			z->zsz_msgids_cap /= z->zsz_intervals;
		if (z->zsz_lofi_cap != ZS_LIMIT_NONE)
			z->zsz_lofi_cap /= z->zsz_intervals;

		z->zsz_usage_ram /= intervals;
		z->zsz_usage_locked /= intervals;
		z->zsz_usage_vm /= intervals;
		z->zsz_processes /= intervals;
		z->zsz_lwps /= intervals;
		z->zsz_shm /= intervals;
		z->zsz_shmids /= intervals;
		z->zsz_semids /= intervals;
		z->zsz_msgids /= intervals;
		z->zsz_lofi /= intervals;
		z->zsz_cpus_online /= intervals;
		z->zsz_cpu_shares /= intervals;
	}
	for (p = list_head(&u->zsu_pset_list); p != NULL;
	    p = list_next(&u->zsu_pset_list, p)) {

		intervals = p->zsp_intervals;

		p->zsp_online /= intervals;
		p->zsp_size /= intervals;
		p->zsp_min /= intervals;
		p->zsp_max /= intervals;
		p->zsp_importance /= intervals;
		p->zsp_cpu_shares /= intervals;

		for (pz = list_head(&p->zsp_usage_list); pz != NULL;
		    pz = list_next(&p->zsp_usage_list, pz)) {

			if (average) {
				intervals = pz->zspz_intervals;
			} else {
				assert(pz->zspz_intervals == 0);
				intervals = p->zsp_intervals;
			}
			pz->zspz_cpu_shares /= intervals;
		}
	}
	return (u);
}

/*
 * Returns 0 on success.  Trips assert on invalid property.
 */
void
zs_resource_property(zs_usage_t *u, int res, int prop, zs_property_t *p)
{
	switch (res)  {
	case ZS_RESOURCE_CPU:
		switch (prop) {
		case ZS_RESOURCE_PROP_CPU_TOTAL:
			p->zsp_id = prop;
			p->zsp_type = ZS_PROP_TYPE_UINT64;
			p->zsp_v.zsv_uint64 = u->zsu_system->zss_ncpus;
			break;
		case ZS_RESOURCE_PROP_CPU_ONLINE:
			p->zsp_id = prop;
			p->zsp_type = ZS_PROP_TYPE_UINT64;
			p->zsp_v.zsv_uint64 = u->zsu_system->zss_ncpus_online;
			break;
		default:
			assert(0);
		}
		break;
	case ZS_RESOURCE_RAM_RSS:
	case ZS_RESOURCE_RAM_LOCKED:
	case ZS_RESOURCE_VM:
	case ZS_RESOURCE_DISK_SWAP:
	case ZS_RESOURCE_LWPS:
	case ZS_RESOURCE_PROCESSES:
	case ZS_RESOURCE_SHM_MEMORY:
	case ZS_RESOURCE_SHM_IDS:
	case ZS_RESOURCE_SEM_IDS:
	case ZS_RESOURCE_MSG_IDS:
		/* FALLTHROUGH */
	default:
		assert(0);
	}
}

/*
 * Returns one of ZS_RESOURCE_TYPE_* on success.  Asserts on invalid
 * resource.
 */
int
zs_resource_type(int res)
{
	switch (res)  {
	case ZS_RESOURCE_CPU:
		return (ZS_RESOURCE_TYPE_TIME);
		break;
	case ZS_RESOURCE_RAM_RSS:
	case ZS_RESOURCE_RAM_LOCKED:
	case ZS_RESOURCE_VM:
	case ZS_RESOURCE_DISK_SWAP:
	case ZS_RESOURCE_SHM_MEMORY:
		return (ZS_RESOURCE_TYPE_BYTES);
		break;
	case ZS_RESOURCE_LWPS:
	case ZS_RESOURCE_PROCESSES:
	case ZS_RESOURCE_SHM_IDS:
	case ZS_RESOURCE_SEM_IDS:
	case ZS_RESOURCE_MSG_IDS:
		return (ZS_RESOURCE_TYPE_COUNT);
		break;
	default:
		assert(0);
		return (0);
	}
}

/*
 * Get total available resource on system
 */
uint64_t
zs_resource_total_uint64(zs_usage_t *u, int res)
{
	uint64_t v;

	switch (res)  {
	case ZS_RESOURCE_CPU:
		v = zs_cpu_total_cpu(u);
		break;
	case ZS_RESOURCE_RAM_RSS:
		v = zs_physical_memory_total(u);
		break;
	case ZS_RESOURCE_RAM_LOCKED:
		v = zs_locked_memory_total(u);
		break;
	case ZS_RESOURCE_VM:
		v = zs_virtual_memory_total(u);
		break;
	case ZS_RESOURCE_DISK_SWAP:
		v = zs_disk_swap_total(u);
		break;
	case ZS_RESOURCE_LWPS:
		v = zs_lwps_total(u);
		break;
	case ZS_RESOURCE_PROCESSES:
		v = zs_processes_total(u);
		break;
	case ZS_RESOURCE_SHM_MEMORY:
		v = zs_shm_total(u);
		break;
	case ZS_RESOURCE_SHM_IDS:
		v = zs_shmids_total(u);
		break;
	case ZS_RESOURCE_SEM_IDS:
		v = zs_semids_total(u);
		break;
	case ZS_RESOURCE_MSG_IDS:
		v = zs_msgids_total(u);
		break;
	case ZS_RESOURCE_LOFI:
		v = zs_lofi_total(u);
		break;
	default:
		assert(0);
	}
	return (v);
}

/*
 * Get amount of used resource.
 */
uint64_t
zs_resource_used_uint64(zs_usage_t *u, int res, int user)
{
	uint64_t v;

	switch (res)  {
	case ZS_RESOURCE_CPU:
		switch (user) {
		case ZS_USER_ALL:
			v = zs_cpu_usage_all_cpu(u);
			break;
		case ZS_USER_KERNEL:
			v = zs_cpu_usage_kernel_cpu(u);
			break;
		case ZS_USER_ZONES:
			v = zs_cpu_usage_zones_cpu(u);
			break;
		case ZS_USER_FREE:
			v = zs_cpu_usage_idle_cpu(u);
			break;
		default:
			assert(0);
		}
		break;
	case ZS_RESOURCE_RAM_RSS:
		switch (user) {
		case ZS_USER_ALL:
			v = zs_physical_memory_usage_all(u);
			break;
		case ZS_USER_KERNEL:
			v = zs_physical_memory_usage_kernel(u);
			break;
		case ZS_USER_ZONES:
			v = zs_physical_memory_usage_zones(u);
			break;
		case ZS_USER_FREE:
			v = zs_physical_memory_usage_free(u);
			break;
		default:
			assert(0);
		}
		break;
	case ZS_RESOURCE_RAM_LOCKED:
		switch (user) {
		case ZS_USER_ALL:
			v = zs_locked_memory_usage_all(u);
			break;
		case ZS_USER_KERNEL:
			v = zs_locked_memory_usage_kernel(u);
			break;
		case ZS_USER_ZONES:
			v = zs_locked_memory_usage_zones(u);
			break;
		case ZS_USER_FREE:
			v = zs_locked_memory_usage_free(u);
			break;
		default:
			assert(0);
		}
		break;
	case ZS_RESOURCE_VM:
		switch (user) {
		case ZS_USER_ALL:
			v = zs_virtual_memory_usage_all(u);
			break;
		case ZS_USER_KERNEL:
			v = zs_virtual_memory_usage_kernel(u);
			break;
		case ZS_USER_ZONES:
			v = zs_virtual_memory_usage_zones(u);
			break;
		case ZS_USER_FREE:
			v = zs_virtual_memory_usage_free(u);
			break;
		default:
			assert(0);
		}
		break;
	case ZS_RESOURCE_DISK_SWAP:
		switch (user) {
		case ZS_USER_ALL:
			v = zs_disk_swap_usage_all(u);
			break;
		case ZS_USER_FREE:
			v = zs_disk_swap_usage_free(u);
			break;
		case ZS_USER_KERNEL:
		case ZS_USER_ZONES:
			/* FALLTHROUGH */
		default:
			assert(0);
		}
		break;
	case ZS_RESOURCE_LWPS:
		switch (user) {
		case ZS_USER_ALL:
		case ZS_USER_ZONES:
			v = zs_lwps_usage_all(u);
			break;
		case ZS_USER_FREE:
			v = zs_lwps_total(u) - zs_lwps_usage_all(u);
			break;
		case ZS_USER_KERNEL:
			v = 0;
			break;
		default:
			assert(0);
		}
		break;
	case ZS_RESOURCE_PROCESSES:
		switch (user) {
		case ZS_USER_ALL:
		case ZS_USER_ZONES:
			v = zs_processes_usage_all(u);
			break;
		case ZS_USER_FREE:
			v = zs_processes_total(u) - zs_processes_usage_all(u);
			break;
		case ZS_USER_KERNEL:
			v = 0;
			break;
		default:
			assert(0);
		}
		break;
	case ZS_RESOURCE_SHM_MEMORY:
		switch (user) {
		case ZS_USER_ALL:
		case ZS_USER_ZONES:
			v = zs_shm_usage_all(u);
			break;
		case ZS_USER_FREE:
			v = zs_shm_total(u) -
			    zs_shm_usage_all(u);
			break;
		case ZS_USER_KERNEL:
			v = 0;
			break;
		default:
			assert(0);
		}
		break;
	case ZS_RESOURCE_SHM_IDS:
		switch (user) {
		case ZS_USER_ALL:
		case ZS_USER_ZONES:
			v = zs_shmids_usage_all(u);
			break;
		case ZS_USER_FREE:
			v = zs_shmids_total(u) - zs_shmids_usage_all(u);
			break;
		case ZS_USER_KERNEL:
			v = 0;
			break;
		default:
			assert(0);
		}
		break;
	case ZS_RESOURCE_SEM_IDS:
		switch (user) {
		case ZS_USER_ALL:
		case ZS_USER_ZONES:
			v = zs_semids_usage_all(u);
			break;
		case ZS_USER_FREE:
			v = zs_semids_total(u) - zs_semids_usage_all(u);
			break;
		case ZS_USER_KERNEL:
			v = 0;
			break;
		default:
			assert(0);
		}
		break;
	case ZS_RESOURCE_MSG_IDS:
		switch (user) {
		case ZS_USER_ALL:
		case ZS_USER_ZONES:
			v = zs_msgids_usage_all(u);
			break;
		case ZS_USER_FREE:
			v = zs_msgids_total(u) - zs_msgids_usage_all(u);
			break;
		case ZS_USER_KERNEL:
			v = 0;
			break;
		default:
			assert(0);
		}
		break;
	case ZS_RESOURCE_LOFI:
		switch (user) {
		case ZS_USER_ALL:
		case ZS_USER_ZONES:
			v = zs_lofi_usage_all(u);
			break;
		case ZS_USER_FREE:
			v = zs_lofi_total(u) - zs_lofi_usage_all(u);
			break;
		case ZS_USER_KERNEL:
			v = 0;
			break;
		default:
			assert(0);
		}
		break;

	default:
		assert(0);
	}
	return (v);
}

/*
 * Get used resource as a percent of total resource.
 */
uint_t
zs_resource_used_pct(zs_usage_t *u, int res, int user)
{
	uint64_t v;

	switch (res)  {
	case ZS_RESOURCE_CPU:
		switch (user) {
		case ZS_USER_ALL:
			v = zs_cpu_usage_all_pct(u);
			break;
		case ZS_USER_KERNEL:
			v = zs_cpu_usage_kernel_pct(u);
			break;
		case ZS_USER_ZONES:
			v = zs_cpu_usage_zones_pct(u);
			break;
		case ZS_USER_FREE:
			v = zs_cpu_usage_idle_pct(u);
			break;
		default:
			assert(0);
		}
		break;
	case ZS_RESOURCE_RAM_RSS:
		switch (user) {
		case ZS_USER_ALL:
			v = zs_physical_memory_usage_all_pct(u);
			break;
		case ZS_USER_KERNEL:
			v = zs_physical_memory_usage_kernel_pct(u);
			break;
		case ZS_USER_ZONES:
			v = zs_physical_memory_usage_zones_pct(u);
			break;
		case ZS_USER_FREE:
			v = zs_physical_memory_usage_free_pct(u);
			break;
		default:
			assert(0);
		}
		break;
	case ZS_RESOURCE_RAM_LOCKED:
		switch (user) {
		case ZS_USER_ALL:
			v = zs_locked_memory_usage_all_pct(u);
			break;
		case ZS_USER_KERNEL:
			v = zs_locked_memory_usage_kernel_pct(u);
			break;
		case ZS_USER_ZONES:
			v = zs_locked_memory_usage_zones_pct(u);
			break;
		case ZS_USER_FREE:
			v = zs_locked_memory_usage_free_pct(u);
			break;
		default:
			assert(0);
		}
		break;
	case ZS_RESOURCE_VM:
		switch (user) {
		case ZS_USER_ALL:
			v = zs_virtual_memory_usage_all_pct(u);
			break;
		case ZS_USER_KERNEL:
			v = zs_virtual_memory_usage_kernel_pct(u);
			break;
		case ZS_USER_ZONES:
			v = zs_virtual_memory_usage_zones_pct(u);
			break;
		case ZS_USER_FREE:
			v = zs_virtual_memory_usage_free_pct(u);
			break;
		default:
			assert(0);
		}
		break;
	case ZS_RESOURCE_DISK_SWAP:
		switch (user) {
		case ZS_USER_ALL:
			v = zs_disk_swap_usage_all_pct(u);
			break;
		case ZS_USER_FREE:
			v = zs_disk_swap_usage_free_pct(u);
			break;
		case ZS_USER_KERNEL:
		case ZS_USER_ZONES:
			/* FALLTHROUGH */
		default:
			assert(0);
		}
		break;
	case ZS_RESOURCE_LWPS:
		switch (user) {
		case ZS_USER_ALL:
		case ZS_USER_ZONES:
			v = zs_lwps_usage_all_pct(u);
			break;
		case ZS_USER_FREE:
			v = ZSD_PCT_INT - zs_lwps_usage_all_pct(u);
			break;
		case ZS_USER_KERNEL:
			v = 0;
			break;
		default:
			assert(0);
		}
		break;
	case ZS_RESOURCE_PROCESSES:
		switch (user) {
		case ZS_USER_ALL:
		case ZS_USER_ZONES:
			v = zs_processes_usage_all_pct(u);
			break;
		case ZS_USER_FREE:
			v = ZSD_PCT_INT - zs_processes_usage_all_pct(u);
			break;
		case ZS_USER_KERNEL:
			v = 0;
			break;
		default:
			assert(0);
		}
		break;
	case ZS_RESOURCE_SHM_MEMORY:
		switch (user) {
		case ZS_USER_ALL:
		case ZS_USER_ZONES:
			v = zs_shm_usage_all_pct(u);
			break;
		case ZS_USER_FREE:
			v = ZSD_PCT_INT - zs_shm_usage_all_pct(u);
			break;
		case ZS_USER_KERNEL:
			v = 0;
			break;
		default:
			assert(0);
		}
		break;
	case ZS_RESOURCE_SHM_IDS:
			switch (user) {
		case ZS_USER_ALL:
		case ZS_USER_ZONES:
			v = zs_shmids_usage_all_pct(u);
			break;
		case ZS_USER_FREE:
			v = ZSD_PCT_INT - zs_shmids_usage_all_pct(u);
			break;
		case ZS_USER_KERNEL:
			v = 0;
			break;
		default:
			assert(0);
		}
		break;
	case ZS_RESOURCE_SEM_IDS:
			switch (user) {
		case ZS_USER_ALL:
		case ZS_USER_ZONES:
			v = zs_semids_usage_all_pct(u);
			break;
		case ZS_USER_FREE:
			v = ZSD_PCT_INT - zs_semids_usage_all_pct(u);
			break;
		case ZS_USER_KERNEL:
			v = 0;
			break;
		default:
			assert(0);
		}
		break;
	case ZS_RESOURCE_MSG_IDS:
		switch (user) {
		case ZS_USER_ALL:
		case ZS_USER_ZONES:
			v = zs_msgids_usage_all_pct(u);
			break;
		case ZS_USER_FREE:
			v = ZSD_PCT_INT - zs_msgids_usage_all_pct(u);
			break;
		case ZS_USER_KERNEL:
			v = 0;
			break;
		default:
			assert(0);
		}
		break;
	case ZS_RESOURCE_LOFI:
		switch (user) {
		case ZS_USER_ALL:
		case ZS_USER_ZONES:
			v = zs_lofi_usage_all_pct(u);
			break;
		case ZS_USER_FREE:
			v = ZSD_PCT_INT - zs_lofi_usage_all_pct(u);
			break;
		case ZS_USER_KERNEL:
			v = 0;
			break;
		default:
			assert(0);
		}
		break;
	default:
		assert(0);
	}

	return (v);
}

/*
 * Get resource used by individual zone.
 */
uint64_t
zs_resource_used_zone_uint64(zs_zone_t *z, int res)
{
	uint64_t v;

	switch (res)  {
	case ZS_RESOURCE_CPU:
		v = zs_cpu_usage_zone_cpu(z);
		break;
	case ZS_RESOURCE_RAM_RSS:
		v = zs_physical_memory_usage_zone(z);
		break;
	case ZS_RESOURCE_RAM_LOCKED:
		v = zs_locked_memory_usage_zone(z);
		break;
	case ZS_RESOURCE_VM:
		v = zs_virtual_memory_usage_zone(z);
		break;
	case ZS_RESOURCE_DISK_SWAP:
		assert(0);
		break;
	case ZS_RESOURCE_LWPS:
		v = zs_lwps_usage_zone(z);
		break;
	case ZS_RESOURCE_PROCESSES:
		v = zs_processes_usage_zone(z);
		break;
	case ZS_RESOURCE_SHM_MEMORY:
		v = zs_shm_usage_zone(z);
		break;
	case ZS_RESOURCE_SHM_IDS:
		v = zs_shmids_usage_zone(z);
		break;
	case ZS_RESOURCE_SEM_IDS:
		v = zs_semids_usage_zone(z);
		break;
	case ZS_RESOURCE_MSG_IDS:
		v = zs_msgids_usage_zone(z);
		break;
	case ZS_RESOURCE_LOFI:
		v = zs_lofi_usage_zone(z);
		break;
	default:
		assert(0);
	}
	return (v);
}

/*
 * Get resource used by individual zone as percent
 */
uint_t
zs_resource_used_zone_pct(zs_zone_t *z, int res)
{
	uint_t v;

	switch (res)  {
	case ZS_RESOURCE_CPU:
		v = zs_cpu_usage_zone_pct(z);
		break;
	case ZS_RESOURCE_RAM_RSS:
		v = zs_physical_memory_usage_zone_pct(z);
		break;
	case ZS_RESOURCE_RAM_LOCKED:
		v = zs_locked_memory_usage_zone_pct(z);
		break;
	case ZS_RESOURCE_VM:
		v = zs_virtual_memory_usage_zone_pct(z);
		break;
	case ZS_RESOURCE_DISK_SWAP:
		assert(0);
		break;
	case ZS_RESOURCE_LWPS:
		v = zs_lwps_usage_zone_pct(z);
		break;
	case ZS_RESOURCE_PROCESSES:
		v = zs_processes_usage_zone_pct(z);
		break;
	case ZS_RESOURCE_SHM_MEMORY:
		v = zs_shm_usage_zone_pct(z);
		break;
	case ZS_RESOURCE_SHM_IDS:
		v = zs_shmids_usage_zone_pct(z);
		break;
	case ZS_RESOURCE_SEM_IDS:
		v = zs_semids_usage_zone_pct(z);
		break;
	case ZS_RESOURCE_MSG_IDS:
		v = zs_msgids_usage_zone_pct(z);
		break;
	case ZS_RESOURCE_LOFI:
		v = zs_lofi_usage_zone_pct(z);
		break;
	default:
		assert(0);
	}
	return (v);
}

/*
 * Get total time available for a resource
 */
void
zs_resource_total_time(zs_usage_t *u, int res, timestruc_t *t)
{
	switch (res)  {
	case ZS_RESOURCE_CPU:
		zs_cpu_total_time(u, t);
		break;
	case ZS_RESOURCE_RAM_RSS:
	case ZS_RESOURCE_RAM_LOCKED:
	case ZS_RESOURCE_VM:
	case ZS_RESOURCE_DISK_SWAP:
	case ZS_RESOURCE_LWPS:
	case ZS_RESOURCE_PROCESSES:
	case ZS_RESOURCE_SHM_MEMORY:
	case ZS_RESOURCE_SHM_IDS:
	case ZS_RESOURCE_SEM_IDS:
	case ZS_RESOURCE_MSG_IDS:
		/* FALLTHROUGH */
	default:
		assert(0);
	}
}

/*
 * Get total time used for a resource
 */
void
zs_resource_used_time(zs_usage_t *u, int res, int user, timestruc_t *t)
{
	switch (res)  {
	case ZS_RESOURCE_CPU:
		switch (user) {
		case ZS_USER_ALL:
			zs_cpu_usage_all(u, t);
			break;
		case ZS_USER_KERNEL:
			zs_cpu_usage_kernel(u, t);
			break;
		case ZS_USER_ZONES:
			zs_cpu_usage_zones(u, t);
			break;
		case ZS_USER_FREE:
			zs_cpu_usage_idle(u, t);
			break;
		default:
			assert(0);
		}
		break;
	case ZS_RESOURCE_RAM_RSS:
	case ZS_RESOURCE_RAM_LOCKED:
	case ZS_RESOURCE_VM:
	case ZS_RESOURCE_DISK_SWAP:
	case ZS_RESOURCE_LWPS:
	case ZS_RESOURCE_PROCESSES:
	case ZS_RESOURCE_SHM_MEMORY:
	case ZS_RESOURCE_SHM_IDS:
	case ZS_RESOURCE_SEM_IDS:
	case ZS_RESOURCE_MSG_IDS:
		/* FALLTHROUGH */
	default:
		assert(0);
	}
}

/*
 * Get total resource time used for a particular zone
 */
void
zs_resource_used_zone_time(zs_zone_t *z, int res, timestruc_t *t)
{
	switch (res)  {
	case ZS_RESOURCE_CPU:
		zs_cpu_usage_zone(z, t);
		break;
	case ZS_RESOURCE_RAM_RSS:
	case ZS_RESOURCE_RAM_LOCKED:
	case ZS_RESOURCE_VM:
	case ZS_RESOURCE_DISK_SWAP:
	case ZS_RESOURCE_SHM_MEMORY:
	case ZS_RESOURCE_LWPS:
	case ZS_RESOURCE_PROCESSES:
	case ZS_RESOURCE_SHM_IDS:
	case ZS_RESOURCE_SEM_IDS:
	case ZS_RESOURCE_MSG_IDS:
		/* FALLTHROUGH */
	default:
		assert(0);
	}
}


int
zs_zone_list(zs_usage_t *usage, zs_zone_t **zonelist, int num)
{
	int i = 0;
	zs_zone_t *zone, *tmp;

	/* copy what fits of the zone list into the buffer */
	for (zone = list_head(&usage->zsu_zone_list); zone != NULL;
	    zone = list_next(&usage->zsu_zone_list, zone)) {

		/* put the global zone at the first position */
		if (i < num) {
			if (zone->zsz_id == GLOBAL_ZONEID) {
				tmp = zonelist[0];
				zonelist[i] = tmp;
				zonelist[0] = zone;
			} else {
				zonelist[i] = zone;
			}
		}
		i++;
	}
	return (i);
}

zs_zone_t *
zs_zone_first(zs_usage_t *usage)
{
	return (list_head(&usage->zsu_zone_list));
}

zs_zone_t *
zs_zone_next(zs_usage_t *usage, zs_zone_t *zone)
{
	return (list_next(&usage->zsu_zone_list, zone));
}


/*
 * Gets a zone property
 */
void
zs_zone_property(zs_zone_t *zone, int prop, zs_property_t *p)
{
	switch (prop) {
	case ZS_ZONE_PROP_NAME:
		p->zsp_type = ZS_PROP_TYPE_STRING;
		p->zsp_id = prop;
		(void) zs_zone_name(zone, p->zsp_v.zsv_string,
		    sizeof (p->zsp_v.zsv_string));
		break;
	case ZS_ZONE_PROP_ID:
		p->zsp_type = ZS_PROP_TYPE_INT;
		p->zsp_id = prop;
		p->zsp_v.zsv_int = zs_zone_id(zone);
		break;
	case ZS_ZONE_PROP_IPTYPE:
		p->zsp_type = ZS_PROP_TYPE_UINT;
		p->zsp_id = prop;
		p->zsp_v.zsv_uint = zs_zone_iptype(zone);
		break;
	case ZS_ZONE_PROP_CPUTYPE:
		p->zsp_type = ZS_PROP_TYPE_UINT;
		p->zsp_id = prop;
		p->zsp_v.zsv_uint = zs_zone_cputype(zone);
		break;
	case ZS_ZONE_PROP_SCHEDULERS:
		p->zsp_type = ZS_PROP_TYPE_UINT;
		p->zsp_id = prop;
		p->zsp_v.zsv_uint = zs_zone_schedulers(zone);
		break;
	case ZS_ZONE_PROP_CPU_SHARES:
		p->zsp_type = ZS_PROP_TYPE_UINT64;
		p->zsp_id = prop;
		p->zsp_v.zsv_uint64 = zs_zone_cpu_shares(zone);
		break;
	case ZS_ZONE_PROP_POOLNAME:
		p->zsp_type = ZS_PROP_TYPE_STRING;
		p->zsp_id = prop;
		(void) zs_zone_poolname(zone, p->zsp_v.zsv_string,
		    sizeof (p->zsp_v.zsv_string));
		break;
	case ZS_ZONE_PROP_PSETNAME:
		p->zsp_type = ZS_PROP_TYPE_STRING;
		p->zsp_id = prop;
		(void) zs_zone_psetname(zone, p->zsp_v.zsv_string,
		    sizeof (p->zsp_v.zsv_string));
		break;
	/* Not implemented */
	case ZS_ZONE_PROP_DEFAULT_SCHED:
	case ZS_ZONE_PROP_UPTIME:
	case ZS_ZONE_PROP_BOOTTIME:
		/* FALLTHROUGH */
	default:
		assert(0);
	}
}

int
zs_zone_limit_type(int limit)
{
	switch (limit) {
	case ZS_LIMIT_CPU:
	case ZS_LIMIT_CPU_SHARES:
		return (ZS_LIMIT_TYPE_TIME);
	case ZS_LIMIT_RAM_RSS:
	case ZS_LIMIT_RAM_LOCKED:
	case ZS_LIMIT_VM:
	case ZS_LIMIT_SHM_MEMORY:
		return (ZS_LIMIT_TYPE_BYTES);
	case ZS_LIMIT_LWPS:
	case ZS_LIMIT_PROCESSES:
	case ZS_LIMIT_SHM_IDS:
	case ZS_LIMIT_MSG_IDS:
	case ZS_LIMIT_SEM_IDS:
		return (ZS_LIMIT_TYPE_COUNT);
	default:
		assert(0);
		return (0);
	}
}
/*
 * Gets the zones limit.  Returns ZS_LIMIT_NONE if no limit set.
 */
uint64_t
zs_zone_limit_uint64(zs_zone_t *z, int limit)
{
	uint64_t v;

	switch (limit) {
	case ZS_LIMIT_CPU:
		v = zs_zone_cpu_cap(z);
		break;
	case ZS_LIMIT_CPU_SHARES:
		v = zs_zone_cpu_shares(z);
		break;
	case ZS_LIMIT_RAM_RSS:
		v = zs_zone_physical_memory_cap(z);
		break;
	case ZS_LIMIT_RAM_LOCKED:
		v = zs_zone_locked_memory_cap(z);
		break;
	case ZS_LIMIT_VM:
		v = zs_zone_virtual_memory_cap(z);
		break;
	case ZS_LIMIT_LWPS:
		v = z->zsz_lwps_cap;
		break;
	case ZS_LIMIT_PROCESSES:
		v = z->zsz_processes_cap;
		break;
	case ZS_LIMIT_SHM_MEMORY:
		v = z->zsz_shm_cap;
		break;
	case ZS_LIMIT_SHM_IDS:
		v = z->zsz_shmids_cap;
		break;
	case ZS_LIMIT_SEM_IDS:
		v = z->zsz_semids_cap;
		break;
	case ZS_LIMIT_MSG_IDS:
		v = z->zsz_msgids_cap;
		break;
	case ZS_LIMIT_LOFI:
		v = z->zsz_lofi_cap;
		break;
	default:
		assert(0);
	}
	return (v);
}

/*
 * Gets the amount of resource used for a limit.  Returns ZS_LIMIT_NONE if
 * no limit configured.
 */
uint64_t
zs_zone_limit_used_uint64(zs_zone_t *z, int limit)
{
	uint64_t v;

	switch (limit) {
	case ZS_LIMIT_CPU:
		v = zs_zone_cpu_cap_used(z);
		break;
	case ZS_LIMIT_CPU_SHARES:
		v = zs_zone_cpu_shares_used(z);
		break;
	case ZS_LIMIT_RAM_RSS:
		v = zs_zone_physical_memory_cap_used(z);
		break;
	case ZS_LIMIT_RAM_LOCKED:
		v = zs_zone_locked_memory_cap_used(z);
		break;
	case ZS_LIMIT_VM:
		v = zs_zone_virtual_memory_cap_used(z);
		break;
	case ZS_LIMIT_LWPS:
		v = z->zsz_lwps;
		break;
	case ZS_LIMIT_PROCESSES:
		v = z->zsz_processes;
		break;
	case ZS_LIMIT_SHM_MEMORY:
		v = z->zsz_shm;
		break;
	case ZS_LIMIT_SHM_IDS:
		v = z->zsz_shmids;
		break;
	case ZS_LIMIT_SEM_IDS:
		v = z->zsz_semids;
		break;
	case ZS_LIMIT_MSG_IDS:
		v = z->zsz_msgids;
		break;
	case ZS_LIMIT_LOFI:
		v = z->zsz_lofi;
		break;
	default:
		assert(0);
	}
	return (v);
}

/*
 * Gets time used under limit.  Time is zero if no limit is configured
 */
void
zs_zone_limit_time(zs_zone_t *z, int limit, timestruc_t *v)
{
	switch (limit) {
	case ZS_LIMIT_CPU:
		if (z->zsz_cpu_cap == ZS_LIMIT_NONE) {
			v->tv_sec = 0;
			v->tv_nsec = 0;
			break;
		}
		zs_zone_cpu_cap_time(z, v);
		break;
	case ZS_LIMIT_CPU_SHARES:
		if (z->zsz_cpu_shares == ZS_LIMIT_NONE ||
		    z->zsz_cpu_shares == ZS_SHARES_UNLIMITED ||
		    z->zsz_cpu_shares == 0 ||
		    (z->zsz_scheds & ZS_SCHED_FSS) == 0) {
			v->tv_sec = 0;
			v->tv_nsec = 0;
			break;
		}
		zs_zone_cpu_share_time(z, v);
		break;
	case ZS_LIMIT_RAM_RSS:
	case ZS_LIMIT_RAM_LOCKED:
	case ZS_LIMIT_VM:
	case ZS_LIMIT_SHM_MEMORY:
	case ZS_LIMIT_LWPS:
	case ZS_LIMIT_PROCESSES:
	case ZS_LIMIT_SHM_IDS:
	case ZS_LIMIT_MSG_IDS:
	case ZS_LIMIT_SEM_IDS:
		/* FALLTHROUGH */
	default:
		assert(0);
	}
}

/*
 * Errno is set on error:
 *
 *	EINVAL: No such property
 *	ENOENT: No time value for the specified limit.
 *	ESRCH:  No limit is configured.
 *
 * If no limit is configured, the value will be ZS_PCT_NONE
 */
void
zs_zone_limit_used_time(zs_zone_t *z, int limit, timestruc_t *t)
{
	switch (limit) {
	case ZS_LIMIT_CPU:
		if (z->zsz_cpu_cap == ZS_LIMIT_NONE) {
			t->tv_sec = 0;
			t->tv_nsec = 0;
			break;
		}
		zs_zone_cpu_cap_time_used(z, t);
		break;
	case ZS_LIMIT_CPU_SHARES:
		if (z->zsz_cpu_shares == ZS_LIMIT_NONE ||
		    z->zsz_cpu_shares == ZS_SHARES_UNLIMITED ||
		    z->zsz_cpu_shares == 0 ||
		    (z->zsz_scheds & ZS_SCHED_FSS) == 0) {
			t->tv_sec = 0;
			t->tv_nsec = 0;
			break;
		}
		zs_zone_cpu_share_time_used(z, t);
		break;
	case ZS_LIMIT_RAM_RSS:
	case ZS_LIMIT_RAM_LOCKED:
	case ZS_LIMIT_VM:
	case ZS_LIMIT_SHM_MEMORY:
	case ZS_LIMIT_LWPS:
	case ZS_LIMIT_PROCESSES:
	case ZS_LIMIT_SHM_IDS:
	case ZS_LIMIT_MSG_IDS:
	case ZS_LIMIT_SEM_IDS:
		/* FALLTHROUGH */
	default:
		assert(0);
	}
}

/*
 * Get a zones usage as a percent of the limit.  Return ZS_PCT_NONE if
 * no limit is configured.
 */
uint_t
zs_zone_limit_used_pct(zs_zone_t *z, int limit)
{
	uint_t v;

	switch (limit) {
	case ZS_LIMIT_CPU:
		v = zs_zone_cpu_cap_pct(z);
		break;
	case ZS_LIMIT_CPU_SHARES:
		v = zs_zone_cpu_shares_pct(z);
		break;
	case ZS_LIMIT_RAM_RSS:
		v = zs_zone_physical_memory_cap_pct(z);
		break;
	case ZS_LIMIT_RAM_LOCKED:
		v = zs_zone_locked_memory_cap_pct(z);
		break;
	case ZS_LIMIT_VM:
		v = zs_zone_virtual_memory_cap_pct(z);
		break;
	case ZS_LIMIT_LWPS:
		v = zs_lwps_zone_cap_pct(z);
		break;
	case ZS_LIMIT_PROCESSES:
		v = zs_processes_zone_cap_pct(z);
		break;
	case ZS_LIMIT_SHM_MEMORY:
		v = zs_shm_zone_cap_pct(z);
		break;
	case ZS_LIMIT_SHM_IDS:
		v = zs_shmids_zone_cap_pct(z);
		break;
	case ZS_LIMIT_SEM_IDS:
		v = zs_semids_zone_cap_pct(z);
		break;
	case ZS_LIMIT_MSG_IDS:
		v = zs_msgids_zone_cap_pct(z);
		break;
	case ZS_LIMIT_LOFI:
		v = zs_lofi_zone_cap_pct(z);
		break;
	default:
		assert(0);
	}
	return (v);
}

int
zs_pset_list(zs_usage_t *usage, zs_pset_t **psetlist, int num)
{
	int i = 0;
	zs_pset_t *pset, *tmp;

	/* copy what fits of the pset list into the buffer */
	for (pset = list_head(&usage->zsu_pset_list); pset != NULL;
	    pset = list_next(&usage->zsu_pset_list, pset)) {

		/* put the default pset at the first position */
		if (i < num) {
			if (pset->zsp_id == ZS_PSET_DEFAULT) {
				tmp = psetlist[0];
				psetlist[i] = tmp;
				psetlist[0] = pset;
			} else {
				psetlist[i] = pset;
			}
		}
		i++;
	}
	return (i);
}

zs_pset_t *
zs_pset_first(zs_usage_t *usage)
{
	return (list_head(&usage->zsu_pset_list));
}

zs_pset_t *
zs_pset_next(zs_usage_t *usage, zs_pset_t *pset)
{
	return (list_next(&usage->zsu_pset_list, pset));
}

/*
 * Get various properties on a pset.
 */
void
zs_pset_property(zs_pset_t *pset, int prop, zs_property_t *p)
{
	switch (prop) {

	case ZS_PSET_PROP_NAME:
		p->zsp_type = ZS_PROP_TYPE_STRING;
		p->zsp_id = prop;
		(void) zs_pset_name(pset, p->zsp_v.zsv_string,
		    sizeof (p->zsp_v.zsv_string));
		break;
	case ZS_PSET_PROP_ID:
		p->zsp_type = ZS_PROP_TYPE_INT;
		p->zsp_id = prop;
		p->zsp_v.zsv_int = zs_pset_id(pset);
		break;
	case ZS_PSET_PROP_CPUTYPE:
		p->zsp_type = ZS_PROP_TYPE_UINT;
		p->zsp_id = prop;
		p->zsp_v.zsv_uint = zs_pset_cputype(pset);
		break;
	case ZS_PSET_PROP_SIZE:
		p->zsp_type = ZS_PROP_TYPE_UINT64;
		p->zsp_id = prop;
		p->zsp_v.zsv_uint64 = zs_pset_size(pset);
		break;
	case ZS_PSET_PROP_ONLINE:
		p->zsp_type = ZS_PROP_TYPE_UINT64;
		p->zsp_id = prop;
		p->zsp_v.zsv_uint64 = zs_pset_online(pset);
		break;
	case ZS_PSET_PROP_MIN:
		p->zsp_type = ZS_PROP_TYPE_UINT64;
		p->zsp_id = prop;
		p->zsp_v.zsv_uint64 = zs_pset_min(pset);
		break;
	case ZS_PSET_PROP_MAX:
		p->zsp_type = ZS_PROP_TYPE_UINT64;
		p->zsp_id = prop;
		p->zsp_v.zsv_uint64 = zs_pset_max(pset);
		break;
	case ZS_PSET_PROP_CPU_SHARES:
		p->zsp_type = ZS_PROP_TYPE_UINT64;
		p->zsp_id = prop;
		p->zsp_v.zsv_uint64 = zs_pset_cpu_shares(pset);
		break;
	case ZS_PSET_PROP_SCHEDULERS:
		p->zsp_type = ZS_PROP_TYPE_UINT;
		p->zsp_id = prop;
		p->zsp_v.zsv_uint = zs_pset_schedulers(pset);
		break;
	/* Not implemented */
	case ZS_PSET_PROP_CREATETIME:
	case ZS_PSET_PROP_LOAD_1MIN:
	case ZS_PSET_PROP_LOAD_5MIN:
	case ZS_PSET_PROP_LOAD_15MIN:
		/* FALLTHROUGH */
	default:
		assert(0);
	}
}

void
zs_pset_total_time(zs_pset_t *pset, timestruc_t *t)
{
	*t = pset->zsp_total_time;
}

uint64_t
zs_pset_total_cpus(zs_pset_t *pset)
{
	return (pset->zsp_online * ZSD_ONE_CPU);
}

/*
 * Get total time used for pset
 */
void
zs_pset_used_time(zs_pset_t *pset, int user, timestruc_t *t)
{
	switch (user) {
	case ZS_USER_ALL:
		zs_pset_usage_all(pset, t);
		break;
	case ZS_USER_KERNEL:
		zs_pset_usage_kernel(pset, t);
		break;
	case ZS_USER_ZONES:
		zs_pset_usage_zones(pset, t);
		break;
	case ZS_USER_FREE:
		zs_pset_usage_idle(pset, t);
		break;
	default:
		assert(0);
	}
}

/*
 * Returns 0 on success.  -1 on failure.
 *
 * ERRORS
 *      EINVAL:  Invalid user.
 *
 */
uint64_t
zs_pset_used_cpus(zs_pset_t *pset, int user)
{
	uint_t v;

	switch (user) {
	case ZS_USER_ALL:
		v = zs_pset_usage_all_cpus(pset);
		break;
	case ZS_USER_KERNEL:
		v = zs_pset_usage_kernel_cpus(pset);
		break;
	case ZS_USER_ZONES:
		v = zs_pset_usage_zones_cpus(pset);
		break;
	case ZS_USER_FREE:
		v = zs_pset_usage_idle_cpus(pset);
		break;
	default:
		assert(0);
	}
	return (v);
}
/*
 * Get percent of pset cpu time used
 */
uint_t
zs_pset_used_pct(zs_pset_t *pset, int user)
{
	uint_t v;

	switch (user) {
	case ZS_USER_ALL:
		v = zs_pset_usage_all_pct(pset);
		break;
	case ZS_USER_KERNEL:
		v = zs_pset_usage_kernel_pct(pset);
		break;
	case ZS_USER_ZONES:
		v = zs_pset_usage_zones_pct(pset);
		break;
	case ZS_USER_FREE:
		v = zs_pset_usage_idle_pct(pset);
		break;
	default:
		assert(0);
	}
	return (v);
}

int
zs_pset_zone_list(zs_pset_t *pset, zs_pset_zone_t **zonelist, int num)
{
	int i = 0;
	zs_pset_zone_t *zone, *tmp;

	/* copy what fits of the pset's zone list into the buffer */
	for (zone = list_head(&pset->zsp_usage_list); zone != NULL;
	    zone = list_next(&pset->zsp_usage_list, zone)) {

		/* put the global zone at the first position */
		if (i < num) {
			if (zone->zspz_zone->zsz_id == GLOBAL_ZONEID) {
				tmp = zonelist[0];
				zonelist[i] = tmp;
				zonelist[0] = zone;
			} else {
				zonelist[i] = zone;
			}
		}
		i++;
	}
	return (i);
}

zs_pset_zone_t *
zs_pset_zone_first(zs_pset_t *pset)
{
	return (list_head(&pset->zsp_usage_list));
}

zs_pset_zone_t *
zs_pset_zone_next(zs_pset_t *pset, zs_pset_zone_t *pz)
{
	return (list_next(&pset->zsp_usage_list, pz));
}

zs_pset_t *
zs_pset_zone_get_pset(zs_pset_zone_t *pz)
{
	return (pz->zspz_pset);
}

zs_zone_t *
zs_pset_zone_get_zone(zs_pset_zone_t *pz)
{
	return (pz->zspz_zone);
}

/*
 * Get a property describing a zone's usage of a pset
 */
void
zs_pset_zone_property(zs_pset_zone_t *pz, int prop, zs_property_t *p)
{
	switch (prop) {

	case ZS_PZ_PROP_CPU_CAP:
		p->zsp_type = ZS_PROP_TYPE_UINT64;
		p->zsp_id = prop;
		p->zsp_v.zsv_uint64 = (int)zs_pset_zone_cpu_cap(pz);
		break;
	case ZS_PZ_PROP_CPU_SHARES:
		p->zsp_type = ZS_PROP_TYPE_UINT64;
		p->zsp_id = prop;
		p->zsp_v.zsv_uint64 = (int)zs_pset_zone_cpu_shares(pz);
		break;
	case ZS_PZ_PROP_SCHEDULERS:
		p->zsp_type = ZS_PROP_TYPE_UINT;
		p->zsp_id = prop;
		p->zsp_v.zsv_uint = (int)zs_pset_zone_schedulers(pz);
		break;
	default:
		assert(0);
	}
}

void
zs_pset_zone_used_time(zs_pset_zone_t *pz, timestruc_t *t)
{
	zs_pset_zone_usage_time(pz, t);
}

uint64_t
zs_pset_zone_used_cpus(zs_pset_zone_t *pz)
{
	return (zs_pset_zone_usage_cpus(pz));
}

/*
 * Get percent of a psets cpus used by a zone
 */
uint_t
zs_pset_zone_used_pct(zs_pset_zone_t *pz, int type)
{
	uint_t v;

	switch (type) {
	case ZS_PZ_PCT_PSET:
		v = zs_pset_zone_usage_pct_pset(pz);
		break;
	case ZS_PZ_PCT_CPU_CAP:
		v = zs_pset_zone_usage_pct_cpu_cap(pz);
		break;
	case ZS_PZ_PCT_PSET_SHARES:
		v = zs_pset_zone_usage_pct_pset_shares(pz);
		break;
	case ZS_PZ_PCT_CPU_SHARES:
		v = zs_pset_zone_usage_pct_cpu_shares(pz);
		break;
	default:
		assert(0);
	}
	return (v);
}

/*
 * returns similar to malloc
 */
zs_property_t *
zs_property_alloc()
{
	return ((zs_property_t *)malloc(sizeof (zs_property_t)));
}

size_t
zs_property_size()
{
	return (sizeof (zs_property_t));
}

void
zs_property_free(zs_property_t *p)
{
	free(p);
}

int
zs_property_type(zs_property_t *p)
{
	return (p->zsp_type);
}

int
zs_property_id(zs_property_t *p)
{
	return (p->zsp_id);
}

char *
zs_property_string(zs_property_t *p)
{
	assert(p->zsp_type == ZS_PROP_TYPE_STRING);
	return (p->zsp_v.zsv_string);
}

double
zs_property_double(zs_property_t *p)
{
	assert(p->zsp_type == ZS_PROP_TYPE_DOUBLE);
	return (p->zsp_v.zsv_double);
}

void
zs_property_time(zs_property_t *p, timestruc_t *t)
{
	assert(p->zsp_type == ZS_PROP_TYPE_TIME);
	*t = p->zsp_v.zsv_ts;
}

uint64_t
zs_property_uint64(zs_property_t *p)
{
	assert(p->zsp_type == ZS_PROP_TYPE_UINT64);
	return (p->zsp_v.zsv_uint64);
}

int64_t
zs_property_int64(zs_property_t *p)
{
	assert(p->zsp_type == ZS_PROP_TYPE_INT64);
	return (p->zsp_v.zsv_int64);
}

uint_t
zs_property_uint(zs_property_t *p)
{
	assert(p->zsp_type == ZS_PROP_TYPE_UINT);
	return (p->zsp_v.zsv_uint);
}

int
zs_property_int(zs_property_t *p)
{
	assert(p->zsp_type == ZS_PROP_TYPE_INT);
	return (p->zsp_v.zsv_uint);
}
