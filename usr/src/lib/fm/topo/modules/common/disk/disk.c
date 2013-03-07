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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 */
/*
 * Copyright (c) 2013, Joyent, Inc.  All rights reserved.
 */

#include <strings.h>
#include <devid.h>
#include <pthread.h>
#include <inttypes.h>
#include <sys/dkio.h>
#include <sys/scsi/scsi_types.h>
#include <fm/topo_mod.h>
#include <fm/topo_list.h>
#include <fm/libdiskstatus.h>
#include <sys/fm/protocol.h>
#include "disk.h"
#include "disk_drivers.h"

static int disk_enum(topo_mod_t *, tnode_t *, const char *,
	topo_instance_t, topo_instance_t, void *, void *);

static const topo_modops_t disk_ops =
	{ disk_enum, NULL };

static const topo_modinfo_t disk_info =
	{DISK, FM_FMRI_SCHEME_HC, DISK_VERSION, &disk_ops};

static int
disk_declare_driver(topo_mod_t *mod, tnode_t *baynode, topo_list_t *dlistp,
    char *driver)
{
	int err;

	if (strcmp("mpt_sas", driver) == 0) {
		char *sas_address = NULL;
		tnode_t *child = NULL;

		if ((err = disk_mptsas_find_disk(mod, baynode,
		    &sas_address)) != 0)
			return (err);

		err = disk_declare_addr(mod, baynode, dlistp,
		    sas_address, &child);
		topo_mod_strfree(mod, sas_address);

		return (err);
	}

	topo_mod_dprintf(mod, "unknown disk driver '%s'\n", driver);
	return (-1);
}

/*ARGSUSED*/
static int
disk_enum(topo_mod_t *mod, tnode_t *baynode,
    const char *name, topo_instance_t min, topo_instance_t max,
    void *arg, void *notused)
{
	char		*device, *driver;
	int		err;
	nvlist_t	*fmri;
	topo_list_t	*dlistp = topo_mod_getspecific(mod);

	if (strcmp(name, DISK) != 0) {
		topo_mod_dprintf(mod, "disk_enum: "
		    "only know how to enumerate %s components.\n", DISK);
		return (-1);
	}

	/* set the parent fru */
	if (topo_node_resource(baynode, &fmri, &err) != 0) {
		topo_mod_dprintf(mod, "disk_enum: "
		    "topo_node_resource error %s\n", topo_strerror(err));
		return (-1);
	}
	if (topo_node_fru_set(baynode, fmri, 0, &err) != 0) {
		topo_mod_dprintf(mod, "disk_enum: "
		    "topo_node_fru error %s\n", topo_strerror(err));
		nvlist_free(fmri);
		return (-1);
	}
	nvlist_free(fmri);

	/*
	 * For internal storage, first check to see if we need to
	 * request more detail from an HBA driver.
	 */
	if (topo_prop_get_string(baynode, TOPO_PGROUP_BINDING,
	    TOPO_BINDING_DRIVER, &driver, &err) == 0) {
		err = disk_declare_driver(mod, baynode, dlistp, driver);

		topo_mod_strfree(mod, driver);
		return (err);
	} else if (err != ETOPO_PROP_NOENT) {
		topo_mod_dprintf(mod, "disk_enum: "
		    "binding error %s\n", topo_strerror(err));
		return (-1);
	}

	/*
	 * For internal storage, get the path to the occupant from the
	 * binding group of the bay node
	 */
	if (topo_prop_get_string(baynode, TOPO_PGROUP_BINDING,
	    TOPO_BINDING_OCCUPANT, &device, &err) != 0) {
		topo_mod_dprintf(mod, "disk_enum: "
		    "binding error %s\n", topo_strerror(err));
		return (-1);
	}


	/* locate and topo enumerate the disk with that path */
	err = disk_declare_path(mod, baynode, dlistp, device);

	topo_mod_strfree(mod, device);
	return (err);
}

/*ARGSUSED*/
int
_topo_init(topo_mod_t *mod, topo_version_t version)
{
	topo_list_t *dlistp;

	/*
	 * Turn on module debugging output
	 */
	if (getenv("TOPODISKDEBUG") != NULL)
		topo_mod_setdebug(mod);
	topo_mod_dprintf(mod, "_topo_init: "
	    "initializing %s enumerator\n", DISK);

	if (topo_mod_register(mod, &disk_info, TOPO_VERSION) != 0) {
		topo_mod_dprintf(mod, "_topo_init: "
		    "%s registration failed: %s\n", DISK, topo_mod_errmsg(mod));
		return (-1);		/* mod errno already set */
	}

	if ((dlistp = topo_mod_zalloc(mod, sizeof (topo_list_t))) == NULL) {
		topo_mod_dprintf(mod, "_topo_inti: failed to allocate "
		    "disk list");
		return (-1);
	}

	if (dev_list_gather(mod, dlistp) != 0) {
		topo_mod_unregister(mod);
		topo_mod_free(mod, dlistp, sizeof (topo_list_t));
		topo_mod_dprintf(mod, "_topo_init: "
		    "failed to locate disks");
		return (-1);
	}

	topo_mod_dprintf(mod, "_topo_init: "
	    "%s enumerator initialized\n", DISK);

	topo_mod_setspecific(mod, dlistp);

	return (0);
}

void
_topo_fini(topo_mod_t *mod)
{
	topo_list_t *dlistp = topo_mod_getspecific(mod);
	dev_list_free(mod, dlistp);
	topo_mod_free(mod, dlistp, sizeof (topo_list_t));
	topo_mod_unregister(mod);
	topo_mod_dprintf(mod, "_topo_fini: "
	    "%s enumerator uninitialized\n", DISK);
}
