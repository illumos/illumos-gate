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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2016 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Disk status library
 *
 * This library is responsible for querying health and other status information
 * from disk drives.  It is intended to be a generic interface, however only
 * SCSI (and therefore SATA) disks are currently supported.  The library is
 * capable of detecting the following status conditions:
 *
 *	- Predictive failure
 *	- Overtemp
 *	- Self-test failure
 *	- Solid State Media wearout
 */

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <libdevinfo.h>
#include <libdiskstatus.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fm/io/scsi.h>
#include <sys/stat.h>
#include <unistd.h>

#include "ds_impl.h"
#include "ds_scsi.h"

static ds_transport_t *ds_transports[] = {
	&ds_scsi_sim_transport,
	&ds_scsi_uscsi_transport
};

#define	NTRANSPORTS	(sizeof (ds_transports) / sizeof (ds_transports[0]))

/*
 * Open a handle to a disk.  This will fail if the device cannot be opened, or
 * if no suitable transport exists for communicating with the device.
 */
disk_status_t *
disk_status_open(const char *path, int *error)
{
	disk_status_t *dsp;
	ds_transport_t *t;
	int i;

	if ((dsp = calloc(sizeof (disk_status_t), 1)) == NULL) {
		*error = EDS_NOMEM;
		return (NULL);
	}

	if ((dsp->ds_fd = open(path, O_RDWR)) < 0) {
		*error = EDS_CANT_OPEN;
		free(dsp);
		return (NULL);
	}

	if ((dsp->ds_path = strdup(path)) == NULL) {
		*error = EDS_NOMEM;
		disk_status_close(dsp);
		return (NULL);
	}

	for (i = 0; i < NTRANSPORTS; i++) {
		t = ds_transports[i];

		dsp->ds_transport = t;

		nvlist_free(dsp->ds_state);
		dsp->ds_state = NULL;
		if (nvlist_alloc(&dsp->ds_state, NV_UNIQUE_NAME, 0) != 0) {
			*error = EDS_NOMEM;
			disk_status_close(dsp);
			return (NULL);
		}

		if ((dsp->ds_data = t->dt_open(dsp)) == NULL) {
			if (dsp->ds_error != EDS_NO_TRANSPORT) {
				*error = dsp->ds_error;
				disk_status_close(dsp);
				return (NULL);
			}
		} else {
			dsp->ds_error = 0;
			break;
		}
	}

	if (dsp->ds_error == EDS_NO_TRANSPORT) {
		*error = dsp->ds_error;
		disk_status_close(dsp);
		return (NULL);
	}

	return (dsp);
}

/*
 * Close a handle to a disk.
 */
void
disk_status_close(disk_status_t *dsp)
{
	nvlist_free(dsp->ds_state);
	nvlist_free(dsp->ds_predfail);
	nvlist_free(dsp->ds_overtemp);
	nvlist_free(dsp->ds_testfail);
	nvlist_free(dsp->ds_ssmwearout);
	if (dsp->ds_data)
		dsp->ds_transport->dt_close(dsp->ds_data);
	(void) close(dsp->ds_fd);
	free(dsp->ds_path);
	free(dsp);
}

void
disk_status_set_debug(boolean_t value)
{
	ds_debug = value;
}

/*
 * Query basic information
 */
const char *
disk_status_path(disk_status_t *dsp)
{
	return (dsp->ds_path);
}

int
disk_status_errno(disk_status_t *dsp)
{
	return (dsp->ds_error);
}

nvlist_t *
disk_status_get(disk_status_t *dsp)
{
	nvlist_t *nvl = NULL;
	nvlist_t *faults = NULL;
	int err;

	/*
	 * Scan (or rescan) the current device.
	 */
	nvlist_free(dsp->ds_testfail);
	nvlist_free(dsp->ds_predfail);
	nvlist_free(dsp->ds_overtemp);
	nvlist_free(dsp->ds_ssmwearout);
	dsp->ds_ssmwearout = NULL;
	dsp->ds_testfail = dsp->ds_overtemp = dsp->ds_predfail = NULL;
	dsp->ds_faults = 0;

	/*
	 * Even if there is an I/O failure when trying to scan the device, we
	 * can still return the current state.
	 */
	if (dsp->ds_transport->dt_scan(dsp->ds_data) != 0 &&
	    dsp->ds_error != EDS_IO)
		return (NULL);

	if ((err = nvlist_alloc(&nvl, NV_UNIQUE_NAME, 0)) != 0)
		goto nverror;

	if ((err = nvlist_add_string(nvl, "protocol", "scsi")) != 0 ||
	    (err = nvlist_add_nvlist(nvl, "status", dsp->ds_state)) != 0)
		goto nverror;

	/*
	 * Construct the list of faults.
	 */
	if ((err = nvlist_alloc(&faults, NV_UNIQUE_NAME, 0)) != 0)
		goto nverror;

	if (dsp->ds_predfail != NULL) {
		if ((err = nvlist_add_boolean_value(faults,
		    FM_EREPORT_SCSI_PREDFAIL,
		    (dsp->ds_faults & DS_FAULT_PREDFAIL) != 0)) != 0 ||
		    (err = nvlist_add_nvlist(nvl, FM_EREPORT_SCSI_PREDFAIL,
		    dsp->ds_predfail)) != 0)
			goto nverror;
	}

	if (dsp->ds_testfail != NULL) {
		if ((err = nvlist_add_boolean_value(faults,
		    FM_EREPORT_SCSI_TESTFAIL,
		    (dsp->ds_faults & DS_FAULT_TESTFAIL) != 0)) != 0 ||
		    (err = nvlist_add_nvlist(nvl, FM_EREPORT_SCSI_TESTFAIL,
		    dsp->ds_testfail)) != 0)
			goto nverror;
	}

	if (dsp->ds_overtemp != NULL) {
		if ((err = nvlist_add_boolean_value(faults,
		    FM_EREPORT_SCSI_OVERTEMP,
		    (dsp->ds_faults & DS_FAULT_OVERTEMP) != 0)) != 0 ||
		    (err = nvlist_add_nvlist(nvl, FM_EREPORT_SCSI_OVERTEMP,
		    dsp->ds_overtemp)) != 0)
			goto nverror;
	}

	if (dsp->ds_ssmwearout != NULL) {
		if ((err = nvlist_add_boolean_value(faults,
		    FM_EREPORT_SCSI_SSMWEAROUT,
		    (dsp->ds_faults & DS_FAULT_SSMWEAROUT) != 0)) != 0 ||
		    (err = nvlist_add_nvlist(nvl, FM_EREPORT_SCSI_SSMWEAROUT,
		    dsp->ds_ssmwearout)) != 0)
			goto nverror;
	}

	if ((err = nvlist_add_nvlist(nvl, "faults", faults)) != 0)
		goto nverror;

	nvlist_free(faults);
	return (nvl);

nverror:
	assert(err == ENOMEM);
	nvlist_free(nvl);
	nvlist_free(faults);
	(void) ds_set_errno(dsp, EDS_NOMEM);
	return (NULL);
}
