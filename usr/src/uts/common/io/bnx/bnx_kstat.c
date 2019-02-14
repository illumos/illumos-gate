/*
 * Copyright 2014-2017 Cavium, Inc.
 * The contents of this file are subject to the terms of the Common Development
 * and Distribution License, v.1,  (the "License").
 *
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the License at available
 * at http://opensource.org/licenses/CDDL-1.0
 *
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2019, Joyent, Inc.
 */

#include "bnx.h"

typedef struct {
	kstat_named_t version;
	kstat_named_t versionFW;
	kstat_named_t chipName;
	kstat_named_t intrAlloc;
	kstat_named_t intrFired;
	kstat_named_t intrInDisabled;
	kstat_named_t intrNoChange;
} bnx_kstat_t;

#define	BNX_KSTAT_SIZE (sizeof (bnx_kstat_t) / sizeof (kstat_named_t))


static int
bnx_kstat_update(kstat_t *kstats, int rw)
{
	bnx_kstat_t *pStats = (bnx_kstat_t *)kstats->ks_data;
	um_device_t *pUM = (um_device_t *)kstats->ks_private;

	if (rw == KSTAT_WRITE) {
		return (EACCES);
	}

	mutex_enter(&pUM->kstatMutex);

	(void) strncpy(pStats->version.value.c, pUM->version,
	    sizeof (pStats->version.value.c));
	(void) strncpy(pStats->versionFW.value.c, pUM->versionFW,
	    sizeof (pStats->versionFW.value.c));
	(void) strncpy(pStats->chipName.value.c,  pUM->chipName,
	    sizeof (pStats->chipName.value.c));
	(void) strncpy(pStats->intrAlloc.value.c, pUM->intrAlloc,
	    sizeof (pStats->intrAlloc.value.c));
	pStats->intrFired.value.ui64 = pUM->intr_count;
	pStats->intrInDisabled.value.ui64 = pUM->intr_in_disabled;
	pStats->intrNoChange.value.ui64 = pUM->intr_no_change;

	mutex_exit(&pUM->kstatMutex);

	return (0);
}

#define	BNX_KSTAT(f, t)	kstat_named_init(&pStats->f, #f, t)

boolean_t
bnx_kstat_init(um_device_t *pUM)
{
	bnx_kstat_t *pStats;

	if ((pUM->kstats = kstat_create("bnx", pUM->instance, "statistics",
	    "net", KSTAT_TYPE_NAMED, BNX_KSTAT_SIZE, 0)) == NULL) {
		cmn_err(CE_WARN, "%s: Failed to create kstat", pUM->dev_name);
		return (B_FALSE);
	}

	pStats = (bnx_kstat_t *)pUM->kstats->ks_data;

	BNX_KSTAT(version, KSTAT_DATA_CHAR);
	BNX_KSTAT(versionFW, KSTAT_DATA_CHAR);
	BNX_KSTAT(chipName, KSTAT_DATA_CHAR);
	BNX_KSTAT(intrAlloc, KSTAT_DATA_CHAR);
	BNX_KSTAT(intrFired, KSTAT_DATA_UINT64);
	BNX_KSTAT(intrInDisabled, KSTAT_DATA_UINT64);
	BNX_KSTAT(intrNoChange, KSTAT_DATA_UINT64);

	pUM->kstats->ks_update  = bnx_kstat_update;
	pUM->kstats->ks_private = (void *)pUM;

	mutex_init(&pUM->kstatMutex, NULL,
	    MUTEX_DRIVER, DDI_INTR_PRI(pUM->intrPriority));

	kstat_install(pUM->kstats);

	return (B_TRUE);
}

void
bnx_kstat_fini(um_device_t *pUM)
{
	if (pUM->kstats) {
		kstat_delete(pUM->kstats);
		pUM->kstats = NULL;
	}

	mutex_destroy(&pUM->kstatMutex);
}
