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

#include <sys/scsi/adapters/mpt_sas/mpi/mpi2_type.h>
#include <sys/scsi/adapters/mpt_sas/mpi/mpi2.h>
#include <sys/scsi/adapters/mpt_sas/mpi/mpi2_init.h>
#include <sys/scsi/adapters/mpt_sas/mptsas_ioctl.h>

#include "disk.h"
#include "disk_drivers.h"

static int
get_sas_address(topo_mod_t *mod, char *devctl, uint32_t enclosure,
    uint32_t slot, char **sas_address)
{
	int fd, err, i;
	mptsas_get_disk_info_t gdi;
	mptsas_disk_info_t *di;
	size_t disz;

	bzero(&gdi, sizeof (gdi));

	if ((fd = open(devctl, O_RDWR)) == -1) {
		topo_mod_dprintf(mod, "could not open '%s' for ioctl: %s\n",
		    devctl, strerror(errno));
		return (-1);
	}

	if (ioctl(fd, MPTIOCTL_GET_DISK_INFO, &gdi) == -1) {
		topo_mod_dprintf(mod, "ioctl 1 on '%s' failed: %s\n", devctl,
		    strerror(errno));
		(void) close(fd);
		return (-1);
	}

	gdi.DiskInfoArraySize = disz = sizeof (mptsas_disk_info_t) *
	    gdi.DiskCount;
	gdi.PtrDiskInfoArray = di = topo_mod_alloc(mod, disz);
	if (di == NULL) {
		topo_mod_dprintf(mod, "memory allocation failed\n");
		(void) close(fd);
		return (-1);
	}

	if (ioctl(fd, MPTIOCTL_GET_DISK_INFO, &gdi) == -1) {
		topo_mod_dprintf(mod, "ioctl 2 on '%s' failed: %s\n", devctl,
		    strerror(errno));
		topo_mod_free(mod, di, disz);
		(void) close(fd);
		return (-1);
	}

	err = -1;
	for (i = 0; i < gdi.DiskCount; i++) {
		if (di[i].Enclosure == enclosure && di[i].Slot == slot) {
			char sas[17]; /* 16 hex digits and NUL */
			(void) snprintf(sas, 17, "%llx", di[i].SasAddress);
			topo_mod_dprintf(mod, "found mpt_sas disk (%d/%d) "
			    "with adddress %s\n", enclosure, slot, sas);
			*sas_address = topo_mod_strdup(mod, sas);
			err = 0;
			break;
		}
	}

	topo_mod_free(mod, di, disz);
	(void) close(fd);
	return (err);
}

int
disk_mptsas_find_disk(topo_mod_t *mod, tnode_t *baynode, char **sas_address)
{
	char *devctl = NULL;
	uint32_t enclosure, slot;
	int err;

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

	return (get_sas_address(mod, devctl, enclosure, slot, sas_address));

}
