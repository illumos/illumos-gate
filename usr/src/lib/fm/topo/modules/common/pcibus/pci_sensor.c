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
 * Copyright 2020 Oxide Computer Company
 */

/*
 * Construct sensors based on the ksensor framework for PCI devices. The kernel
 * will create devices such that they show up
 * /dev/sensors/temperature/pci/<bus>.<func>/<sensors>. This iterates and adds a
 * sensor for the device based on the total number that exist for all of them.
 */

#include <sys/types.h>
#include <dirent.h>
#include <string.h>
#include <errno.h>
#include <fm/topo_mod.h>
#include <fm/topo_hc.h>
#include <pcibus.h>
#include <topo_sensor.h>

int
pci_create_dev_sensors(topo_mod_t *mod, tnode_t *dev)
{
	int ret;
	DIR *d;
	char path[PATH_MAX];
	topo_instance_t binst, dinst;
	struct dirent *ent;
	tnode_t *parent = topo_node_parent(dev);

	binst = topo_node_instance(parent);
	dinst = topo_node_instance(dev);

	if (snprintf(path, sizeof (path), "/dev/sensors/temperature/pci/%x.%x",
	    binst, dinst) >= sizeof (path)) {
		topo_mod_dprintf(mod, "failed to construct temp sensor "
		    "directory path, path too long");
		return (topo_mod_seterrno(mod, EMOD_UKNOWN_ENUM));
	}

	topo_mod_dprintf(mod, "searching for sensors in %s", path);

	d = opendir(path);
	if (d == NULL) {
		if (errno == ENOENT) {
			return (0);
		}

		topo_mod_dprintf(mod, "failed to open %s: %s", path,
		    strerror(errno));
		return (topo_mod_seterrno(mod, EMOD_UKNOWN_ENUM));
	}

	while ((ent = readdir(d)) != NULL) {
		char spath[PATH_MAX];

		if (strcmp(ent->d_name, ".") == 0 ||
		    strcmp(ent->d_name, "..") == 0) {
			continue;
		}

		if (snprintf(spath, sizeof (spath), "%s/%s", path,
		    ent->d_name) >= sizeof (spath)) {
			topo_mod_dprintf(mod, "failed to construct temp sensor "
			    "path for %s/%s, path too long", path, ent->d_name);
			ret = topo_mod_seterrno(mod, EMOD_UKNOWN_ENUM);
			goto out;
		}

		topo_mod_dprintf(mod, "attempting to create sensor at %s",
		    spath);
		if ((ret = topo_sensor_create_temp_sensor(mod, dev, spath,
		    ent->d_name)) < 0) {
			goto out;
		}

	}
	ret = 0;

out:
	(void) closedir(d);

	return (ret);
}
