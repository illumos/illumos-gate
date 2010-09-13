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

/*
 * sa_kstat - kstat statistic adapter, collects statistic data provided
 * by kstat.
 */

#include <locale.h>
#include <string.h>
#include <assert.h>
#include <kstat.h>
#include <pool.h>
#include "utils.h"
#include <sys/pset.h>
#include "poolstat.h"
#include "poolstat_utils.h"

/* marks 'sdata_t' element as updated	*/
#define	SD_UPDATED	1

/* Specified value for an invalid set.	*/
#define	INVALID_SET	-2

/* statistic data	*/
typedef struct sdata {
	kstat_t		sd_oks;		/* old kstat	*/
	kstat_t		sd_nks;		/* new kstat	*/
	void		*sd_udata; 	/* user data	*/
	uint_t		sd_state;	/* state of this data (UPDATED)	*/
	struct sdata	*sd_next;
} sdata_t;

/* pset user data	*/
typedef struct {
	psetid_t opset;		/* old pset sysid	*/
	psetid_t npset;		/* new pset sysid	*/
} pset_ud_t;

/* shortcuts to access set's id in 'pset_ud_t'		*/
#define	SD_OPSET(p)	(((pset_ud_t *)(p)->sd_udata)->opset)
#define	SD_NPSET(p)	(((pset_ud_t *)(p)->sd_udata)->npset)

static	kstat_ctl_t	*ks_ctl;	/* libkstat handle		*/
static  sdata_t		*cpu_list;	/* list with cpu statistics	*/

static sdata_t *update_sdata_list(sdata_t *, kstat_ctl_t *, char *, int,
	char *, int *);
static void update_cpu_list(sdata_t *list);
static void update_pset_stats(statistic_bag_t *, sdata_t *);

/*ARGSUSED*/
void
sa_kstat_init(void *unused)
{
	if ((ks_ctl = kstat_open()) == NULL)
		die(gettext(ERR_KSTAT_OPEN), get_errstr());
}

void
sa_kstat_update(statistic_bag_t *sbag, int flags)
{
	/* The SA_REFRESH flag forces the update of local data structures. */
	if (flags & SA_REFRESH) {
		int	ks_error = 0;

		if (kstat_chain_update(ks_ctl) == -1)
			die(gettext(ERR_KSTAT_DATA), get_errstr());
		cpu_list = update_sdata_list(cpu_list, ks_ctl, "cpu",
							-1, "sys", &ks_error);
		if (ks_error)
			die(gettext(ERR_KSTAT_DATA), get_errstr());

		/* update info about cpu binding to processor sets	*/
		update_cpu_list(cpu_list);
	}

	if (strcmp(sbag->sb_type, PSET_TYPE_NAME) == 0) {
		update_pset_stats(sbag, cpu_list);
	} else if (strcmp(sbag->sb_type, POOL_TYPE_NAME) == 0) {
		return;
	} else {
		die(gettext(ERR_UNSUPP_STYPE), sbag->sb_type);
	}

}

static void *
safe_kstat_data_lookup(kstat_t *ksp, char *name)
{
	void *dp;

	if ((dp = kstat_data_lookup(ksp, name)) == NULL)
		die(gettext(ERR_KSTAT_DLOOKUP),
			ksp->ks_name, name, get_errstr());

	return (dp);
}

/*
 * Find the delta over the interval between new_ksp and old_ksp.
 * If old_ksp->ks_data is NULL and 'oz' is set then pretend
 * that old_ksp is zero otherwise return 0.
 */
static uint64_t
delta(kstat_t *new_ksp, kstat_t *old_ksp, char *name, int oz)
{
	kstat_named_t *new_ksn;
	kstat_named_t *old_ksn;

	new_ksn = (kstat_named_t *)safe_kstat_data_lookup(new_ksp, name);
	if (old_ksp == NULL || old_ksp->ks_data == NULL)
		return ((oz == 1) ? new_ksn->value.ui64 : 0);
	old_ksn = (kstat_named_t *)safe_kstat_data_lookup(old_ksp, name);

	return (new_ksn->value.ui64 - old_ksn->value.ui64);
}

/*
 * Create a clone of the passed kstat_t structure 'kstat_t'. If
 * 'fr' flag is set free the old ks_data structure in 'dst'.
 */
static void
kstat_clone(kstat_t *src, kstat_t *dst, int fr)
{
	if (fr)
		FREE(dst->ks_data);
	*dst = *src;
	if (src->ks_data != NULL) {
		dst->ks_data = ZALLOC(src->ks_data_size);
		(void) memcpy(dst->ks_data, src->ks_data, src->ks_data_size);
	} else {
		dst->ks_data = NULL;
		dst->ks_data_size = 0;
	}
}

/*
 * Erase the data from 'src'.
 */
static void
kstat_erase(kstat_t *src)
{
	FREE(src->ks_data);
	(void) memset(src, 0, sizeof (*src));
}

/*
 * Create a new statistic data object with its own copy of the passed
 * kstat.
 */
static sdata_t *
sdata_new(kstat_t *ksp)
{
	sdata_t *sdp;

	NEW0(sdp);
	kstat_clone(ksp, &sdp->sd_nks, 0);

	return (sdp);
}

static void
sdata_free(sdata_t *sdp)
{
	FREE(sdp->sd_oks.ks_data);
	FREE(sdp->sd_nks.ks_data);
	FREE(sdp->sd_udata);
	FREE(sdp);
}

/*
 * Create new or update an existing list of cpu statistics. For each
 * cpu two kstats are kept. One old kstat which contains the data from
 * the previous scan, and new with the current data. The old and the new
 * kstats *must* be for the same instance and have the same kid.
 * If 'instance' argument is set to -1 don't use it as a filter.
 */
static sdata_t *
update_sdata_list(sdata_t *list, kstat_ctl_t *kc, char *module,
		int instance, char *name, int *errp)
{
	kstat_t *ksp;
	sdata_t	*sdp, *sdpp; /* kstat instance pointer/previous-pointer */

	for (ksp = kc->kc_chain; ksp; ksp = ksp->ks_next) {
		if (strcmp(ksp->ks_module, module) == 0 &&
			(name == NULL || strcmp(ksp->ks_name, name) == 0) &&
			(instance == -1 || ksp->ks_instance == instance)) {
			if (kstat_read(kc, ksp, NULL) == -1) {
				*errp = -1;
				return (list);
			}
			/*
			 * Find the kstat in the existing list:
			 * If we find one for the same instance and with the
			 * same ks_kid we'll save it as old_kstat.
			 * If we find one for the same instance but with a
			 * different ks_kid we'll removed it.
			 */
			for (sdpp = sdp = list; sdp; sdp = sdp->sd_next) {
				if (ksp->ks_instance ==
						sdp->sd_nks.ks_instance) {
					if (ksp->ks_kid == sdp->sd_nks.ks_kid) {
						kstat_clone(&sdp->sd_nks,
							&sdp->sd_oks, 1);
					} else {
						kstat_erase(&sdp->sd_oks);
					}
					kstat_clone(ksp, &sdp->sd_nks, 1);
					sdp->sd_state |= SD_UPDATED;
					break;
				}
				sdpp = sdp;
			}
			/* add a new kstat instance	*/
			if (!sdp) {
				/* first instance	*/
				if (!list) {
					list = sdata_new(ksp);
					list->sd_state |= SD_UPDATED;
				} else {
					sdpp->sd_next = sdata_new(ksp);
					sdpp->sd_next->sd_state |= SD_UPDATED;
				}
			}
		}
	}

	/* remove untouched statistics	*/
	sdp = list;
	sdpp = NULL;
	while (sdp != NULL) {

		if (sdp->sd_state & SD_UPDATED) {
			sdp->sd_state &= ~SD_UPDATED;
			sdpp = sdp;
			sdp = sdp->sd_next;
		} else {
			sdata_t *tmp;

			if (sdpp == NULL)
				list = sdp->sd_next;
			else
				sdpp->sd_next = sdp->sd_next;
			tmp = sdp->sd_next;
			sdata_free(sdp);
			sdp = tmp;
		}
	}

	*errp = 0;
	return (list);
}

/*
 * Update the pset assignment information for each cpu in the statistic
 * data list.
 */
static void
update_cpu_list(sdata_t *list)
{
	sdata_t	*sdp;

	for (sdp = list; sdp; sdp = sdp->sd_next) {
		/* for new CPU create a new user data object	*/
		if (sdp->sd_udata == NULL) {
			sdp->sd_udata = ZALLOC(sizeof (pset_ud_t));
			/*
			 * set its pset to invalid, so it will not be
			 * used in statistics calculation.
			 */
			SD_NPSET(sdp) = INVALID_SET;
		}
		/* copy the pset assignment information to the previous stat */
		SD_OPSET(sdp) = SD_NPSET(sdp);
		/* set the current assignment	*/
		if (pset_assign(PS_QUERY, sdp->sd_nks.ks_instance,
			&(SD_NPSET(sdp))) == -1)
			SD_NPSET(sdp) = INVALID_SET;
	}
}

/*
 * Update statistic data for pset. Calculate the CPU usage in a pset.
 */
static void
update_pset_stats(statistic_bag_t *sbag, sdata_t *list)
{
	sdata_t	*sdp;
	pset_statistic_bag_t *bag = (pset_statistic_bag_t *)sbag->bag;
	uint64_t allticks, ust, kst, ist, wst;

	ust = kst = ist = wst = 0;
	for (sdp = list; sdp; sdp = sdp->sd_next) {
		/*
		 * only calculate for the asked pset id and if the cpu belongs
		 * to the same set in the previous and in the current snapshot.
		 * It means that the usage for CPUs that were rebound during
		 * the sampling interval are not charged to any set.
		 */
		if ((SD_OPSET(sdp) == SD_NPSET(sdp)) &&
			(SD_NPSET(sdp) == bag->pset_sb_sysid)) {
			ust += delta(&sdp->sd_nks, &sdp->sd_oks,
				"cpu_ticks_user", 0);
			kst += delta(&sdp->sd_nks, &sdp->sd_oks,
				"cpu_ticks_kernel", 0);
			ist += delta(&sdp->sd_nks, &sdp->sd_oks,
				"cpu_ticks_idle", 0);
			wst += delta(&sdp->sd_nks, &sdp->sd_oks,
				"cpu_ticks_wait", 0);
		}
	}

	if ((allticks = ust + kst + wst + ist) != 0) {
		bag->pset_sb_used =
			(double)(ust + kst) / allticks * bag->pset_sb_size;
	} else {
		bag->pset_sb_used = 0.0;
	}
}
