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
 * Copyright 2018 Joyent, Inc.
 *
 * Convenience routines for identifying current or available devices that are
 * suitable for PCI passthrough to a bhyve guest.
 */

#include <libdevinfo.h>
#include <libppt.h>

#include <sys/param.h>
#include <sys/stat.h>
#include <sys/list.h>
#include <strings.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <pcidb.h>
#include <glob.h>

typedef struct node_data {
	pcidb_hdl_t *nd_db;
	list_t nd_matches;
	nvlist_t *nd_nvl;
	int nd_err;
} node_data_t;

typedef struct ppt_match {
	list_node_t pm_list;
	char pm_path[MAXPATHLEN];
	char pm_vendor[5];
	char pm_device[5];
} ppt_match_t;

static boolean_t
is_pci(di_node_t di_node)
{
	char *svals;

	if (di_prop_lookup_strings(DDI_DEV_T_ANY, di_parent_node(di_node),
	    "device_type", &svals) != 1)
		return (B_FALSE);

	return (strcmp(svals, "pci") == 0 || strcmp(svals, "pciex") == 0);
}

static int
populate_int_prop(di_node_t di_node, nvlist_t *nvl, const char *name, int *ival)
{
	char val[20];
	int *ivals;
	int err;

	if (di_prop_lookup_ints(DDI_DEV_T_ANY, di_node, name, &ivals) != 1)
		return (errno);

	(void) snprintf(val, sizeof (val), "%x", ivals[0]);

	err = nvlist_add_string(nvl, name, val);

	if (err == 0 && ival != NULL)
		*ival = ivals[0];

	return (err);
}

static int
dev_getlabel(pcidb_hdl_t *db, int vid, int did, char *buf, size_t buflen)
{
	pcidb_vendor_t *vend = NULL;
	pcidb_device_t *dev = NULL;

	if ((vend = pcidb_lookup_vendor(db, vid)) == NULL)
		return (ENOENT);

	if ((dev = pcidb_lookup_device_by_vendor(vend, did)) == NULL)
		return (ENOENT);

	(void) snprintf(buf, buflen, "%s %s", pcidb_vendor_name(vend),
	    pcidb_device_name(dev));

	return (0);
}

static nvlist_t *
dev_getinfo(di_node_t di_node, pcidb_hdl_t *db,
    const char *dev, const char *path)
{
	char label[MAXPATHLEN];
	nvlist_t *nvl = NULL;
	int vid, did;
	int err;

	if ((err = nvlist_alloc(&nvl, NV_UNIQUE_NAME, 0)) != 0)
		goto out;

	if (dev != NULL && (err = nvlist_add_string(nvl, "dev", dev)) != 0)
		goto out;
	if ((err = nvlist_add_string(nvl, "path", path)) != 0)
		goto out;
	if ((err = populate_int_prop(di_node, nvl, "vendor-id", &vid)) != 0)
		goto out;
	if ((err = populate_int_prop(di_node, nvl, "device-id", &did)) != 0)
		goto out;
	if ((err = populate_int_prop(di_node, nvl,
	    "subsystem-vendor-id", NULL)) != 0)
		goto out;
	if ((err = populate_int_prop(di_node, nvl, "subsystem-id", NULL)) != 0)
		goto out;
	if ((err = populate_int_prop(di_node, nvl, "revision-id", NULL)) != 0)
		goto out;

	err = dev_getlabel(db, vid, did, label, sizeof (label));

	if (err == 0) {
		err = nvlist_add_string(nvl, "label", label);
	} else if (err == ENOENT) {
		err = 0;
	}

out:
	if (err) {
		nvlist_free(nvl);
		errno = err;
		return (NULL);
	}

	return (nvl);
}

/*
 * /devices/pci0@0/....@0,1:ppt -> /pci0@0/...@0,1
 */
static const char *
fs_to_phys_path(char *fspath)
{
	const char prefix[] = "/devices";
	char *c;

	if ((c = strrchr(fspath, ':')) != NULL && strcmp(c, ":ppt") == 0)
		*c = '\0';

	c = fspath;

	if (strncmp(c, prefix, sizeof (prefix) - 1) == 0)
		c += sizeof (prefix) - 1;

	return (c);
}

/*
 * Return an nvlist representing the mappings of /dev/ppt* devices to physical
 * devices.  Of the form:
 *
 * /pci@0,0/... {
 *  dev: "/dev/ppt0"
 *  path: "/pci@0,0/..."
 *  vendor-id: "8086"
 *  device-id: "1528"
 *  subsystem-vendor-id: "8086"
 *  subsystem-id: "1528"
 *  revision-id: "1"
 *  label: "Intel Corporation ..."
 * },
 * /pci@0,0/...
 *
 * The nvlist should be freed by the caller.
 */
nvlist_t *
ppt_list_assigned(void)
{
	di_node_t di_root = DI_NODE_NIL;
	pcidb_hdl_t *db = NULL;
	nvlist_t *nvl = NULL;
	glob_t gl;
	int err;

	bzero(&gl, sizeof (gl));

	if ((di_root = di_init("/", DINFOCACHE)) == DI_NODE_NIL)
		return (NULL);

	if ((db = pcidb_open(PCIDB_VERSION)) == NULL) {
		err = errno;
		goto out;
	}

	if ((err = nvlist_alloc(&nvl, NV_UNIQUE_NAME, 0)) != 0)
		goto out;

	if ((err = glob("/dev/ppt*", GLOB_KEEPSTAT | GLOB_ERR,
	    NULL, &gl)) != 0) {
		err = (err == GLOB_NOMATCH) ? 0 : errno;
		goto out;
	}

	for (size_t i = 0; i < gl.gl_pathc; i++) {
		char fspath[MAXPATHLEN];
		nvlist_t *info_nvl;
		di_node_t di_node;
		const char *path;

		if (!S_ISLNK(gl.gl_statv[i]->st_mode))
			continue;

		if (realpath(gl.gl_pathv[i], fspath) == NULL) {
			err = errno;
			goto out;
		}

		path = fs_to_phys_path(fspath);

		/*
		 * path argument is treated as const.
		 */
		if ((di_node = di_lookup_node(di_root, (char *)path)) == NULL) {
			err = errno;
			goto out;
		}

		if (!is_pci(di_node))
			continue;

		info_nvl = dev_getinfo(di_node, db, gl.gl_pathv[i], path);

		if (info_nvl == NULL) {
			err = errno;
			goto out;
		}

		err = nvlist_add_nvlist(nvl, path, info_nvl);
		nvlist_free(info_nvl);

		if (err)
			goto out;
	}

out:
	if (di_root != DI_NODE_NIL)
		di_fini(di_root);

	pcidb_close(db);
	globfree(&gl);

	if (err) {
		nvlist_free(nvl);
		errno = err;
		return (NULL);
	}

	return (nvl);
}

/*
 * Read in our list of potential PPT devices.  A boot-module provided file
 * explicitly over-rides anything delivered.
 */
static int
get_matches(list_t *listp)
{
	int err = 0;
	FILE *fp;

	list_create(listp, sizeof (ppt_match_t),
	    offsetof(ppt_match_t, pm_list));

	if ((fp = fopen("/system/boot/etc/ppt_matches", "r")) == NULL) {
		if (errno != ENOENT)
			return (errno);

		if ((fp = fopen("/etc/ppt_matches", "r")) == NULL) {
			if (errno == ENOENT)
				return (0);
			return (errno);
		}
	}

	for (;;) {
		char *line = NULL;
		ppt_match_t *pm;
		size_t cap = 0;
		ssize_t read;

		if ((read = getline(&line, &cap, fp)) <= 0) {
			free(line);
			break;
		}

		if (line[read - 1] == '\n')
			line[read - 1] = '\0';

		if ((pm = malloc(sizeof (*pm))) == NULL) {
			err = errno;
			free(line);
			goto out;
		}

		bzero(pm, sizeof (*pm));

		if (sscanf(line, "pciex%4s,%4s", &pm->pm_vendor,
		    &pm->pm_device) == 2 ||
		    sscanf(line, "pci%4s,%4s", &pm->pm_vendor,
		    &pm->pm_device) == 2 ||
		    sscanf(line, "pciex%4s", &pm->pm_vendor) == 1 ||
		    sscanf(line, "pci%4s", &pm->pm_vendor) == 1) {
			list_insert_tail(listp, pm);
		} else if (line[0] == '/') {
			(void) strlcpy(pm->pm_path, line, sizeof (pm->pm_path));
			list_insert_tail(listp, pm);
		} else {
			/*
			 * Ignore any line we don't understand.
			 */
			free(pm);
		}

		free(line);
	}

out:
	(void) fclose(fp);
	return (err);
}

static boolean_t
match_ppt(list_t *matches, nvlist_t *nvl)
{
	char *vendor;
	char *device;
	char *path;

	if (nvlist_lookup_string(nvl, "path", &path) != 0 ||
	    nvlist_lookup_string(nvl, "vendor-id", &vendor) != 0 ||
	    nvlist_lookup_string(nvl, "device-id", &device) != 0)
		return (B_FALSE);

	for (ppt_match_t *pm = list_head(matches); pm != NULL;
	    pm = list_next(matches, pm)) {
		if (pm->pm_path[0] != '\0' && strcmp(pm->pm_path, path) == 0)
			return (B_TRUE);

		if (pm->pm_vendor[0] != '\0' &&
		    strcmp(pm->pm_vendor, vendor) == 0) {
			if (pm->pm_device[0] == '\0')
				return (B_TRUE);
			if (strcmp(pm->pm_device, device) == 0)
				return (B_TRUE);
		}
	}

	return (B_FALSE);
}

static int
inspect_node(di_node_t di_node, void *arg)
{
	node_data_t *data = arg;
	nvlist_t *info_nvl = NULL;
	char *devname = NULL;
	const char *driver;
	char *path = NULL;

	if (!is_pci(di_node))
		return (DI_WALK_CONTINUE);

	driver = di_driver_name(di_node);

	if (driver != NULL && strcmp(driver, "ppt") == 0) {
		if (asprintf(&devname, "/dev/ppt%d",
		    di_instance(di_node)) < 0) {
			data->nd_err = errno;
			goto out;
		}
	}

	if ((path = di_devfs_path(di_node)) == NULL) {
		data->nd_err = ENOENT;
		goto out;
	}

	info_nvl = dev_getinfo(di_node, data->nd_db, devname, path);

	if (info_nvl == NULL)
		goto out;

	if (devname == NULL && !match_ppt(&data->nd_matches, info_nvl))
		goto out;

	data->nd_err = nvlist_add_nvlist(data->nd_nvl, path, info_nvl);

out:
	free(path);
	free(devname);
	nvlist_free(info_nvl);
	return (data->nd_err ? DI_WALK_TERMINATE : DI_WALK_CONTINUE);
}

/*
 * Like ppt_list_assigned() output, but includes all devices that could be used
 * for passthrough, whether assigned or not.
 */
nvlist_t *
ppt_list(void)
{
	node_data_t nd = { NULL, };
	di_node_t di_root;
	int err;

	if ((di_root = di_init("/", DINFOCACHE)) == DI_NODE_NIL)
		return (NULL);

	if ((err = get_matches(&nd.nd_matches)) != 0)
		goto out;

	if ((nd.nd_db = pcidb_open(PCIDB_VERSION)) == NULL) {
		err = errno;
		goto out;
	}

	if ((err = nvlist_alloc(&nd.nd_nvl, NV_UNIQUE_NAME, 0)) != 0)
		goto out;

	if ((err = di_walk_node(di_root, DI_WALK_CLDFIRST,
	    &nd, inspect_node)) != 0)
		goto out;

	err = nd.nd_err;

out:
	pcidb_close(nd.nd_db);

	for (ppt_match_t *pm = list_head(&nd.nd_matches); pm != NULL; ) {
		ppt_match_t *next = list_next(&nd.nd_matches, pm);
		free(pm);
		pm = next;
	}

	if (di_root != DI_NODE_NIL)
		di_fini(di_root);

	if (err) {
		nvlist_free(nd.nd_nvl);
		errno = err;
		return (NULL);
	}

	return (nd.nd_nvl);
}

/*
 * Given a physical path such as "/devices/pci0@0...", return the "/dev/pptX"
 * that is bound to it, if any.  The "/devices/" prefix is optional.  The
 * physical path may have the ":ppt" minor name suffix.
 *
 * Returns ENOENT if no such PPT device exists.
 */
int
ppt_devpath_to_dev(const char *inpath, char *buf, size_t buflen)
{
	char fspath[MAXPATHLEN] = "";
	nvpair_t *nvp = NULL;
	const char *devpath;
	int err = ENOENT;
	nvlist_t *nvl;

	if (strlcat(fspath, inpath, sizeof (fspath)) >= sizeof (fspath))
		return (ENAMETOOLONG);

	devpath = fs_to_phys_path(fspath);

	if ((nvl = ppt_list_assigned()) == NULL)
		return (errno);

	while ((nvp = nvlist_next_nvpair(nvl, nvp)) != NULL) {
		const char *name = nvpair_name(nvp);
		char *ppt = NULL;
		nvlist_t *props;

		(void) nvpair_value_nvlist(nvp, &props);

		if (strcmp(name, devpath) == 0) {
			(void) nvlist_lookup_string(props, "dev", &ppt);

			err = 0;

			if (strlcpy(buf, ppt, buflen) >= buflen)
				err = ENAMETOOLONG;
			break;
		}
	}

	nvlist_free(nvl);
	return (err);
}
