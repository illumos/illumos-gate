/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */
/*
 * Copyright (c) 2013, Joyent, Inc. All rights reserved.
 * Copyright 2023 Racktop Systems, Inc.
 */

#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stropts.h>
#include <string.h>
#include <strings.h>

#include <fm/topo_mod.h>
#include <fm/topo_list.h>

#include <sys/scsi/adapters/mpi/mpi2_type.h>
#include <sys/scsi/adapters/mpi/mpi2.h>
#include <sys/scsi/adapters/mpi/mpi2_init.h>
#include <sys/scsi/adapters/mpt_sas/mptsas_ioctl.h>

#include "disk.h"
#include "disk_drivers.h"

/*
 * Request the SAS address of the disk (if any) attached to this mpt_sas
 * instance at (Enclosure Number, Slot Number).  The function returns
 * -1 on error and sets errno to ENOENT _only_ if the /devices node
 * (*devctl) does not exist.
 */
static int
get_sas_address(topo_mod_t *mod, char *devctl, uint32_t enclosure,
    uint32_t slot, char **sas_address)
{
	int ret = -1, en = ENXIO;
	int fd, i;
	mptsas_get_disk_info_t gdi;
	mptsas_disk_info_t *di;
	size_t disz;

	bzero(&gdi, sizeof (gdi));

	if ((fd = open(devctl, O_RDWR)) == -1) {
		en = errno;
		topo_mod_dprintf(mod, "could not open '%s' for ioctl: %s\n",
		    devctl, strerror(errno));
		errno = en;
		return (-1);
	}

	if (ioctl(fd, MPTIOCTL_GET_DISK_INFO, &gdi) == -1) {
		if (errno != ENOENT)
			en = errno;
		topo_mod_dprintf(mod, "ioctl 1 on '%s' failed: %s\n", devctl,
		    strerror(errno));
		goto out;
	}

	gdi.DiskInfoArraySize = disz = sizeof (mptsas_disk_info_t) *
	    gdi.DiskCount;
	gdi.PtrDiskInfoArray = di = topo_mod_alloc(mod, disz);
	if (di == NULL) {
		topo_mod_dprintf(mod, "memory allocation failed\n");
		en = ENOMEM;
		goto out;
	}

	if (ioctl(fd, MPTIOCTL_GET_DISK_INFO, &gdi) == -1) {
		if (errno != ENOENT)
			en = errno;
		topo_mod_dprintf(mod, "ioctl 2 on '%s' failed: %s\n", devctl,
		    strerror(errno));
		topo_mod_free(mod, di, disz);
		goto out;
	}

	for (i = 0; i < gdi.DiskCount; i++) {
		if (di[i].Enclosure == enclosure && di[i].Slot == slot) {
			char sas[17]; /* 16 hex digits and NUL */
			(void) snprintf(sas, 17, "%llx", di[i].SasAddress);
			topo_mod_dprintf(mod, "found mpt_sas disk (%d/%d) "
			    "with adddress %s\n", enclosure, slot, sas);
			*sas_address = topo_mod_strdup(mod, sas);
			en = ret = 0;
			break;
		}
	}

	topo_mod_free(mod, di, disz);
out:
	(void) close(fd);
	errno = en;
	return (ret);
}

int
disk_mptsas_find_disk(topo_mod_t *mod, tnode_t *baynode, char **sas_address)
{
	char *devctl = NULL;
	uint32_t enclosure, slot;
	int err;
	char *elem, *lastp;
	int ret = -1;

	/*
	 * Get the required properties from the node.  These come from
	 * the static XML mapping.
	 */
	if (topo_prop_get_string(baynode, TOPO_PGROUP_BINDING,
	    TOPO_BINDING_DEVCTL, &devctl, &err) != 0 ||
	    topo_prop_get_uint32(baynode, TOPO_PGROUP_BINDING,
	    TOPO_BINDING_ENCLOSURE, &enclosure, &err) != 0 ||
	    topo_prop_get_uint32(baynode, TOPO_PGROUP_BINDING,
	    TOPO_BINDING_SLOT, &slot, &err) != 0) {
		if (devctl != NULL)
			topo_mod_strfree(mod, devctl);
		topo_mod_dprintf(mod, "bay node was missing mpt_sas binding "
		    "properties\n");
		return (-1);
	}

	/*
	 * devctl is a (potentially) pipe-separated list of different device
	 * paths to try.
	 */
	if ((elem = topo_mod_strsplit(mod, devctl, "|", &lastp)) != NULL) {
		boolean_t done = B_FALSE;
		do {
			topo_mod_dprintf(mod, "trying mpt_sas instance at %s\n",
			    elem);

			ret = get_sas_address(mod, elem, enclosure,
			    slot, sas_address);

			/*
			 * Only try further devctl paths from the list if this
			 * one was not found:
			 */
			if (ret == 0 || errno != ENOENT) {
				done = B_TRUE;
			} else {
				topo_mod_dprintf(mod, "instance not found\n");
			}

			topo_mod_strfree(mod, elem);

		} while (!done && (elem = topo_mod_strsplit(mod, NULL, "|",
		    &lastp)) != NULL);
	}

	topo_mod_strfree(mod, devctl);
	return (ret);
}
