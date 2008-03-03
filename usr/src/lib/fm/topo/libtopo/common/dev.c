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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <limits.h>
#include <strings.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <alloca.h>
#include <devid.h>
#include <sys/stat.h>
#include <libnvpair.h>
#include <fm/topo_mod.h>
#include <sys/fm/protocol.h>

#include <topo_method.h>
#include <topo_subr.h>
#include <dev.h>

static int dev_enum(topo_mod_t *, tnode_t *, const char *, topo_instance_t,
    topo_instance_t, void *, void *);
static void dev_release(topo_mod_t *, tnode_t *);
static int dev_fmri_nvl2str(topo_mod_t *, tnode_t *, topo_version_t,
    nvlist_t *, nvlist_t **);
static int dev_fmri_str2nvl(topo_mod_t *, tnode_t *, topo_version_t,
    nvlist_t *, nvlist_t **);
static int dev_fmri_create_meth(topo_mod_t *, tnode_t *, topo_version_t,
    nvlist_t *, nvlist_t **);
static int dev_fmri_present(topo_mod_t *, tnode_t *, topo_version_t,
    nvlist_t *, nvlist_t **);
static int dev_fmri_unusable(topo_mod_t *, tnode_t *, topo_version_t,
    nvlist_t *, nvlist_t **);

static const topo_method_t dev_methods[] = {
	{ TOPO_METH_NVL2STR, TOPO_METH_NVL2STR_DESC, TOPO_METH_NVL2STR_VERSION,
	    TOPO_STABILITY_INTERNAL, dev_fmri_nvl2str },
	{ TOPO_METH_STR2NVL, TOPO_METH_STR2NVL_DESC, TOPO_METH_STR2NVL_VERSION,
	    TOPO_STABILITY_INTERNAL, dev_fmri_str2nvl },
	{ TOPO_METH_FMRI, TOPO_METH_FMRI_DESC, TOPO_METH_FMRI_VERSION,
	    TOPO_STABILITY_INTERNAL, dev_fmri_create_meth },
	{ TOPO_METH_PRESENT, TOPO_METH_PRESENT_DESC, TOPO_METH_PRESENT_VERSION,
	    TOPO_STABILITY_INTERNAL, dev_fmri_present },
	{ TOPO_METH_UNUSABLE, TOPO_METH_UNUSABLE_DESC,
	    TOPO_METH_UNUSABLE_VERSION, TOPO_STABILITY_INTERNAL,
	    dev_fmri_unusable },
	{ NULL }
};

static const topo_modops_t dev_ops =
	{ dev_enum, dev_release };
static const topo_modinfo_t dev_info =
	{ "dev", FM_FMRI_SCHEME_DEV, DEV_VERSION, &dev_ops };

int
dev_init(topo_mod_t *mod, topo_version_t version)
{
	if (getenv("TOPOHCDEBUG"))
		topo_mod_setdebug(mod);
	topo_mod_dprintf(mod, "initializing dev builtin\n");

	if (version != DEV_VERSION)
		return (topo_mod_seterrno(mod, EMOD_VER_NEW));

	if (topo_mod_register(mod, &dev_info, TOPO_VERSION) != 0) {
		topo_mod_dprintf(mod, "failed to register dev_info: "
		    "%s\n", topo_mod_errmsg(mod));
		return (-1);
	}

	return (0);
}

void
dev_fini(topo_mod_t *mod)
{
	topo_mod_unregister(mod);
}

/*ARGSUSED*/
static int
dev_enum(topo_mod_t *mod, tnode_t *pnode, const char *name,
    topo_instance_t min, topo_instance_t max, void *notused1, void *notused2)
{
	(void) topo_method_register(mod, pnode, dev_methods);
	return (0);
}

static void
dev_release(topo_mod_t *mod, tnode_t *node)
{
	topo_method_unregister_all(mod, node);
}

static ssize_t
fmri_nvl2str(nvlist_t *nvl, char *buf, size_t buflen)
{
	nvlist_t *anvl = NULL;
	uint8_t version;
	ssize_t size = 0;
	char *devid = NULL;
	char *devpath = NULL;
	char *achas = NULL;
	char *adom = NULL;
	char *aprod = NULL;
	char *asrvr = NULL;
	char *ahost = NULL;
	int more_auth = 0;
	int err;

	if (nvlist_lookup_uint8(nvl, FM_VERSION, &version) != 0 ||
	    version > FM_DEV_SCHEME_VERSION)
		return (-1);

	/* Get authority, if present */
	err = nvlist_lookup_nvlist(nvl, FM_FMRI_AUTHORITY, &anvl);
	if (err != 0 && err != ENOENT)
		return (-1);

	/* Get devid, if present */
	err = nvlist_lookup_string(nvl, FM_FMRI_DEV_ID, &devid);
	if (err != 0 && err != ENOENT)
		return (-1);

	/* There must be a device path present */
	err = nvlist_lookup_string(nvl, FM_FMRI_DEV_PATH, &devpath);
	if (err != 0 || devpath == NULL)
		return (-1);

	if (anvl != NULL) {
		(void) nvlist_lookup_string(anvl,
		    FM_FMRI_AUTH_PRODUCT, &aprod);
		(void) nvlist_lookup_string(anvl,
		    FM_FMRI_AUTH_CHASSIS, &achas);
		(void) nvlist_lookup_string(anvl,
		    FM_FMRI_AUTH_DOMAIN, &adom);
		(void) nvlist_lookup_string(anvl,
		    FM_FMRI_AUTH_SERVER, &asrvr);
		(void) nvlist_lookup_string(anvl,
		    FM_FMRI_AUTH_HOST, &ahost);
		if (aprod != NULL)
			more_auth++;
		if (achas != NULL)
			more_auth++;
		if (adom != NULL)
			more_auth++;
		if (asrvr != NULL)
			more_auth++;
		if (ahost != NULL)
			more_auth++;
	}

	/* dev:// */
	topo_fmristr_build(&size,
	    buf, buflen, FM_FMRI_SCHEME_DEV, NULL, "://");

	/* authority, if any */
	if (aprod != NULL)
		topo_fmristr_build(&size,
		    buf, buflen, aprod, FM_FMRI_AUTH_PRODUCT "=",
		    --more_auth > 0 ? "," : NULL);
	if (achas != NULL)
		topo_fmristr_build(&size,
		    buf, buflen, achas, FM_FMRI_AUTH_CHASSIS "=",
		    --more_auth > 0 ? "," : NULL);
	if (adom != NULL)
		topo_fmristr_build(&size,
		    buf, buflen, adom, FM_FMRI_AUTH_DOMAIN "=",
		    --more_auth > 0 ? "," : NULL);
	if (asrvr != NULL)
		topo_fmristr_build(&size,
		    buf, buflen, asrvr, FM_FMRI_AUTH_SERVER "=",
		    --more_auth > 0 ? "," : NULL);
	if (ahost != NULL)
		topo_fmristr_build(&size,
		    buf, buflen, ahost, FM_FMRI_AUTH_HOST "=",
		    NULL);

	/* device-id part, topo_fmristr_build does nothing if devid is NULL */
	topo_fmristr_build(&size,
	    buf, buflen, devid, "/:" FM_FMRI_DEV_ID "=", NULL);

	/* device-path part */
	topo_fmristr_build(&size, buf, buflen, devpath, "/", NULL);

	return (size);
}

/*ARGSUSED*/
static int
dev_fmri_nvl2str(topo_mod_t *mod, tnode_t *node, topo_version_t version,
    nvlist_t *nvl, nvlist_t **out)
{
	ssize_t len;
	char *name = NULL;
	nvlist_t *fmristr;

	if (version > TOPO_METH_NVL2STR_VERSION)
		return (topo_mod_seterrno(mod, EMOD_VER_NEW));

	if ((len = fmri_nvl2str(nvl, NULL, 0)) == 0 ||
	    (name = topo_mod_alloc(mod, len + 1)) == NULL ||
	    fmri_nvl2str(nvl, name, len + 1) == 0) {
		if (name != NULL)
			topo_mod_free(mod, name, len + 1);
		return (topo_mod_seterrno(mod, EMOD_FMRI_NVL));
	}

	if (topo_mod_nvalloc(mod, &fmristr, NV_UNIQUE_NAME) != 0)
		return (topo_mod_seterrno(mod, EMOD_FMRI_NVL));
	if (nvlist_add_string(fmristr, "fmri-string", name) != 0) {
		topo_mod_free(mod, name, len + 1);
		nvlist_free(fmristr);
		return (topo_mod_seterrno(mod, EMOD_FMRI_NVL));
	}
	topo_mod_free(mod, name, len + 1);
	*out = fmristr;

	return (0);
}

/*ARGSUSED*/
static int
dev_fmri_str2nvl(topo_mod_t *mod, tnode_t *node, topo_version_t version,
    nvlist_t *in, nvlist_t **out)
{
	nvlist_t *fmri;
	char *devpath;
	char *devid = NULL;
	char *str;
	int err;

	if (version > TOPO_METH_STR2NVL_VERSION)
		return (topo_mod_seterrno(mod, EMOD_VER_NEW));

	if (nvlist_lookup_string(in, "fmri-string", &str) != 0)
		return (topo_mod_seterrno(mod, EMOD_FMRI_NVL));

	/* We're expecting a string version of a dev scheme FMRI */
	if (strncmp(str, "dev:///", 7) != 0)
		return (topo_mod_seterrno(mod, EMOD_FMRI_MALFORM));

	devpath = str + 7;
	if (strncmp(devpath, ":" FM_FMRI_DEV_ID "=", 7) == 0) {
		char *n;
		int len;

		n = strchr(devpath + 7, '/');
		if (n == NULL)
			return (topo_mod_seterrno(mod, EMOD_FMRI_MALFORM));
		len = n - (devpath + 7);
		devid = alloca(len + 1);
		(void) memcpy(devid, devpath + 7, len);
		devid[len] = 0;
		devpath = n + 1;
	}

	/* the device-path should start with a slash */
	if (*devpath != '/')
		return (topo_mod_seterrno(mod, EMOD_FMRI_MALFORM));

	if (topo_mod_nvalloc(mod, &fmri, NV_UNIQUE_NAME) != 0)
		return (topo_mod_seterrno(mod, EMOD_FMRI_NVL));

	err = nvlist_add_uint8(fmri, FM_VERSION, FM_DEV_SCHEME_VERSION);
	err |= nvlist_add_string(fmri, FM_FMRI_SCHEME, FM_FMRI_SCHEME_DEV);
	err |= nvlist_add_string(fmri, FM_FMRI_DEV_PATH, devpath);
	if (devid != NULL)
		err |= nvlist_add_string(fmri, FM_FMRI_DEV_ID, devid);

	if (err != 0) {
		nvlist_free(fmri);
		return (topo_mod_seterrno(mod, EMOD_FMRI_NVL));
	}
	*out = fmri;

	return (0);
}

/*ARGSUSED*/
static int
dev_fmri_present(topo_mod_t *mod, tnode_t *node, topo_version_t version,
    nvlist_t *in, nvlist_t **out)
{
	uint8_t fmversion;
	char *devpath = NULL;
	uint32_t present;
	char *devid = NULL, *path;
	ddi_devid_t id;
	ddi_devid_t matchid;
	di_node_t dnode;
	struct stat sb;
	int len;

	if (version > TOPO_METH_PRESENT_VERSION)
		return (topo_mod_seterrno(mod, EMOD_VER_NEW));

	if (nvlist_lookup_uint8(in, FM_VERSION, &fmversion) != 0 ||
	    fmversion > FM_DEV_SCHEME_VERSION ||
	    nvlist_lookup_string(in, FM_FMRI_DEV_PATH, &devpath) != 0)
		return (topo_mod_seterrno(mod, EMOD_FMRI_MALFORM));

	(void) nvlist_lookup_string(in, FM_FMRI_DEV_ID, &devid);

	if (devpath == NULL || strlen(devpath) == 0)
		return (topo_mod_seterrno(mod, EMOD_FMRI_MALFORM));

	/*
	 * stat() the device node in devfs. This will tell us if the device is
	 * present or not. Don't stat the minor,  just the whole device.
	 * If the device is present and there is a devid, it must also match.
	 * so di_init that one node. No need for DINFOFORCE.
	 */
	len =  strlen(devpath) + strlen("/devices") + 1;
	path = topo_mod_alloc(mod, len);
	(void) snprintf(path, len, "/devices%s", devpath);
	if (devid == NULL) {
		if (stat(path, &sb) != -1)
			present = 1;
		else if ((dnode = di_init("/", DINFOCACHE)) == DI_NODE_NIL)
			present = 0;
		else {
			if (di_lookup_node(dnode, devpath) == DI_NODE_NIL)
				present = 0;
			else
				present = 1;
			di_fini(dnode);
		}
	} else {
		if (stat(path, &sb) == -1)
			present = 0;
		else if ((dnode = di_init(devpath, DINFOCPYONE)) == DI_NODE_NIL)
			present = 0;
		else {
			if ((id = di_devid(dnode)) == NULL ||
			    devid_str_decode(devid, &matchid, NULL) != 0)
				present = 0;
			else {
				if (devid_compare(id, matchid) != 0)
					present = 0;
				else
					present = 1;
				devid_free(matchid);
			}
			di_fini(dnode);
		}
	}
	topo_mod_free(mod, path, len);

	if (topo_mod_nvalloc(mod, out, NV_UNIQUE_NAME) != 0)
		return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
	if (nvlist_add_uint32(*out, TOPO_METH_PRESENT_RET, present) != 0) {
		nvlist_free(*out);
		return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
	}

	return (0);
}

/*ARGSUSED*/
static int
dev_fmri_unusable(topo_mod_t *mod, tnode_t *node, topo_version_t version,
    nvlist_t *in, nvlist_t **out)
{
	di_node_t dnode;
	uint8_t fmversion;
	char *devpath = NULL;
	uint32_t unusable;
	uint_t state;

	if (version > TOPO_METH_PRESENT_VERSION)
		return (topo_mod_seterrno(mod, EMOD_VER_NEW));

	if (nvlist_lookup_uint8(in, FM_VERSION, &fmversion) != 0 ||
	    fmversion > FM_DEV_SCHEME_VERSION ||
	    nvlist_lookup_string(in, FM_FMRI_DEV_PATH, &devpath) != 0)
		return (topo_mod_seterrno(mod, EMOD_FMRI_MALFORM));

	if (devpath == NULL)
		return (topo_mod_seterrno(mod, EMOD_FMRI_MALFORM));

	if ((dnode = di_init(devpath, DINFOCPYONE)) == DI_NODE_NIL) {
		if (errno != ENXIO)
			return (topo_mod_seterrno(mod, EMOD_UKNOWN_ENUM));
		unusable = 1;
	} else {
		uint_t retired = di_retired(dnode);
		state = di_state(dnode);
		if (retired || (state & (DI_DEVICE_OFFLINE | DI_DEVICE_DOWN |
		    DI_BUS_QUIESCED | DI_BUS_DOWN)))
			unusable = 1;
		else
			unusable = 0;
		di_fini(dnode);
	}

	if (topo_mod_nvalloc(mod, out, NV_UNIQUE_NAME) != 0)
		return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
	if (nvlist_add_uint32(*out, TOPO_METH_UNUSABLE_RET, unusable) != 0) {
		nvlist_free(*out);
		return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
	}

	return (0);
}

static nvlist_t *
dev_fmri_create(topo_mod_t *mp, const char *id, const char *path)
{
	nvlist_t *out = NULL;
	int e;

	if (topo_mod_nvalloc(mp, &out, NV_UNIQUE_NAME) != 0) {
		(void) topo_mod_seterrno(mp, EMOD_FMRI_NVL);
		return (NULL);
	}
	e = nvlist_add_string(out, FM_FMRI_SCHEME, FM_FMRI_SCHEME_DEV);
	e |= nvlist_add_uint8(out, FM_VERSION, FM_DEV_SCHEME_VERSION);
	e |= nvlist_add_string(out, FM_FMRI_DEV_PATH, path);

	if (id != NULL)
		e |= nvlist_add_string(out, FM_FMRI_DEV_ID, id);

	if (e == 0)
		return (out);

	topo_mod_dprintf(mp, "construction of dev nvl failed");
	(void) topo_mod_seterrno(mp, EMOD_FMRI_NVL);
	nvlist_free(out);
	return (NULL);
}

/*ARGSUSED*/
static int
dev_fmri_create_meth(topo_mod_t *mp, tnode_t *node, topo_version_t version,
    nvlist_t *in, nvlist_t **out)
{
	nvlist_t *args = NULL;
	char *path, *id = NULL;

	if (version > TOPO_METH_FMRI_VERSION)
		return (topo_mod_seterrno(mp, EMOD_VER_NEW));

	if (nvlist_lookup_nvlist(in, TOPO_METH_FMRI_ARG_NVL, &args) != 0 ||
	    nvlist_lookup_string(args, FM_FMRI_DEV_PATH, &path) != 0) {
		topo_mod_dprintf(mp, "no path string in method argument\n");
		return (topo_mod_seterrno(mp, EMOD_METHOD_INVAL));
	}

	(void) nvlist_lookup_string(args, FM_FMRI_DEV_ID, &id);

	if ((*out = dev_fmri_create(mp, id, path)) == NULL)
		return (-1);
	return (0);
}
