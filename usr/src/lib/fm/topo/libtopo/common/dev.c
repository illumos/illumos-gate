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
 * Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.
 */

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
#include <fm/fmd_fmri.h>
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
static int dev_fmri_replaced(topo_mod_t *, tnode_t *, topo_version_t,
    nvlist_t *, nvlist_t **);
static int dev_fmri_unusable(topo_mod_t *, tnode_t *, topo_version_t,
    nvlist_t *, nvlist_t **);
static int dev_fmri_service_state(topo_mod_t *, tnode_t *, topo_version_t,
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
	{ TOPO_METH_REPLACED, TOPO_METH_REPLACED_DESC,
	    TOPO_METH_REPLACED_VERSION, TOPO_STABILITY_INTERNAL,
	    dev_fmri_replaced },
	{ TOPO_METH_UNUSABLE, TOPO_METH_UNUSABLE_DESC,
	    TOPO_METH_UNUSABLE_VERSION, TOPO_STABILITY_INTERNAL,
	    dev_fmri_unusable },
	{ TOPO_METH_SERVICE_STATE, TOPO_METH_SERVICE_STATE_DESC,
	    TOPO_METH_SERVICE_STATE_VERSION, TOPO_STABILITY_INTERNAL,
	    dev_fmri_service_state },
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
	char *devid = NULL, *tpl0id = NULL;
	char *devpath = NULL;
	ssize_t size = 0;
	uint8_t version;
	int err;

	if (nvlist_lookup_uint8(nvl, FM_VERSION, &version) != 0 ||
	    version > FM_DEV_SCHEME_VERSION)
		return (-1);

	/* Get devid, if present */
	err = nvlist_lookup_string(nvl, FM_FMRI_DEV_ID, &devid);
	if (err != 0 && err != ENOENT)
		return (-1);

	/* Get target-port-l0id, if present */
	err = nvlist_lookup_string(nvl, FM_FMRI_DEV_TGTPTLUN0, &tpl0id);
	if (err != 0 && err != ENOENT)
		return (-1);

	/* There must be a device path present */
	err = nvlist_lookup_string(nvl, FM_FMRI_DEV_PATH, &devpath);
	if (err != 0 || devpath == NULL)
		return (-1);

	/*
	 * dev:///
	 *
	 * The dev scheme does not render fmri authority information
	 * in the string form of an fmri.  It is meaningless to
	 * transmit a dev scheme fmri outside of the immediate fault
	 * manager.
	 */
	topo_fmristr_build(&size,
	    buf, buflen, FM_FMRI_SCHEME_DEV, NULL, ":///");

	/* device-id part, topo_fmristr_build does nothing if devid is NULL */
	topo_fmristr_build(&size,
	    buf, buflen, devid, ":" FM_FMRI_DEV_ID "=", NULL);

	/* target-port-l0id part */
	topo_fmristr_build(&size,
	    buf, buflen, tpl0id, ":" FM_FMRI_DEV_TGTPTLUN0 "=", NULL);

	/*
	 * device-path part; the devpath should always start with a /
	 * so you'd think we don't need to add a further / prefix here;
	 * however past implementation has always added the / if
	 * there is a devid component so we continue to do that
	 * so strings match exactly as before.  So we can have:
	 *
	 *	dev:////pci@0,0/...
	 *	dev:///<devid-and-tpl0>//pci@0,0/...
	 *
	 *	where <devid-and-tpl0> =
	 *			[:devid=<devid>][:target-port-l0id=<tpl0>]
	 */
	topo_fmristr_build(&size, buf, buflen, devpath,
	    devid || tpl0id ? "/" : NULL, NULL);

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
	char *cur, *devid = NULL, *tpl0id = NULL;
	char *str, *strcp;
	nvlist_t *fmri;
	char *devpath;
	size_t len;
	int err;

	if (version > TOPO_METH_STR2NVL_VERSION)
		return (topo_mod_seterrno(mod, EMOD_VER_NEW));

	if (nvlist_lookup_string(in, "fmri-string", &str) != 0)
		return (topo_mod_seterrno(mod, EMOD_FMRI_NVL));

	len = strlen(str);

	/*
	 * We're expecting a string version of a dev scheme FMRI, and
	 * no fmri authority information.
	 *
	 * The shortest legal string would be "dev:////" (len 8) for a string
	 * with no FMRI auth info, no devid or target-port-l0id and
	 * an empty devpath string.
	 */
	if (len < 8 || strncmp(str, "dev:///", 7) != 0)
		return (topo_mod_seterrno(mod, EMOD_FMRI_MALFORM));

	strcp = alloca(len + 1);
	(void) memcpy(strcp, str, len);
	strcp[len] = '\0';
	cur = strcp + 7;	/* already parsed "dev:///" */

	/*
	 * If the first character after the "/" that terminates the (empty)
	 * fmri authority is a colon then we have devid and/or target-port-l0id
	 * info.  They could be in either order.
	 *
	 * If not a colon then it must be the / that begins the devpath.
	 */
	if (*cur == ':') {
		char *eos, *part[2];
		int i;
		/*
		 * Look ahead to the "/" that starts the devpath.  If not
		 * found or if straight after the : then we're busted.
		 */
		eos = devpath = strchr(cur, '/');
		if (devpath == NULL || devpath == cur + 1)
			return (topo_mod_seterrno(mod, EMOD_FMRI_MALFORM));

		part[0] = ++cur;

		/*
		 * Replace the initial "/" of the devpath with a NUL
		 * to terminate the string before it.  We'll undo this
		 * before rendering devpath.
		 */
		*eos = '\0';

		/*
		 * We should now have a NUL-terminated string matching
		 * foo=<pat1>[:bar=<pat2>] (we stepped over the initial :)
		 * Look for a second colon; if found there must be space
		 * after it for the additional component, but no more colons.
		 */
		if ((part[1] = strchr(cur, ':')) != NULL) {
			if (part[1] + 1 == eos ||
			    strchr(part[1] + 1, ':') != NULL)
				return (topo_mod_seterrno(mod,
				    EMOD_FMRI_MALFORM));
			*part[1] = '\0'; /* terminate part[0] */
			part[1]++;
		}

		for (i = 0; i < 2; i++) {
			char *eq;

			if (!part[i])
				continue;

			if ((eq = strchr(part[i], '=')) == NULL ||
			    *(eq + 1) == '\0')
				return (topo_mod_seterrno(mod,
				    EMOD_FMRI_MALFORM));

			*eq = '\0';
			if (strcmp(part[i], FM_FMRI_DEV_ID) == 0)
				devid = eq + 1;
			else if (strcmp(part[i], FM_FMRI_DEV_TGTPTLUN0) == 0)
				tpl0id = eq + 1;
			else
				return (topo_mod_seterrno(mod,
				    EMOD_FMRI_MALFORM));
		}

		if (devid == NULL && tpl0id == NULL)
			return (topo_mod_seterrno(mod, EMOD_FMRI_MALFORM));

		cur = devpath;	/* initial slash is NULled */
	} else if (*cur != '/') {
		/* the device-path should start with a slash */
		return (topo_mod_seterrno(mod, EMOD_FMRI_MALFORM));
	} else {
		devpath = cur;
	}

	if (topo_mod_nvalloc(mod, &fmri, NV_UNIQUE_NAME) != 0)
		return (topo_mod_seterrno(mod, EMOD_FMRI_NVL));

	err = nvlist_add_uint8(fmri, FM_VERSION, FM_DEV_SCHEME_VERSION);
	err |= nvlist_add_string(fmri, FM_FMRI_SCHEME, FM_FMRI_SCHEME_DEV);

	if (devid != NULL)
		err |= nvlist_add_string(fmri, FM_FMRI_DEV_ID, devid);

	if (tpl0id != NULL)
		err |= nvlist_add_string(fmri, FM_FMRI_DEV_TGTPTLUN0, tpl0id);

	if (devid != NULL || tpl0id != NULL)
		*devpath = '/';	/* we NULed this earlier; put it back */

	/* step over repeated initial / in the devpath */
	while (*(devpath + 1) == '/')
		devpath++;

	err |= nvlist_add_string(fmri, FM_FMRI_DEV_PATH, devpath);

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
	len = strlen(devpath) + strlen("/devices") + 1;
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
dev_fmri_replaced(topo_mod_t *mod, tnode_t *node, topo_version_t version,
    nvlist_t *in, nvlist_t **out)
{
	uint8_t fmversion;
	char *devpath = NULL;
	uint32_t rval;
	char *devid = NULL, *path;
	ddi_devid_t id;
	ddi_devid_t matchid;
	di_node_t dnode;
	struct stat sb;
	int len;

	if (version > TOPO_METH_REPLACED_VERSION)
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
	len = strlen(devpath) + strlen("/devices") + 1;
	path = topo_mod_alloc(mod, len);
	(void) snprintf(path, len, "/devices%s", devpath);
	if (devid == NULL) {
		if (stat(path, &sb) != -1)
			rval = FMD_OBJ_STATE_UNKNOWN;
		else if ((dnode = di_init("/", DINFOCACHE)) == DI_NODE_NIL)
			rval = FMD_OBJ_STATE_NOT_PRESENT;
		else {
			if (di_lookup_node(dnode, devpath) == DI_NODE_NIL)
				rval = FMD_OBJ_STATE_NOT_PRESENT;
			else
				rval = FMD_OBJ_STATE_UNKNOWN;
			di_fini(dnode);
		}
	} else {
		if (stat(path, &sb) == -1)
			rval = FMD_OBJ_STATE_NOT_PRESENT;
		else if ((dnode = di_init(devpath, DINFOCPYONE)) == DI_NODE_NIL)
			rval = FMD_OBJ_STATE_NOT_PRESENT;
		else {
			if ((id = di_devid(dnode)) == NULL ||
			    devid_str_decode(devid, &matchid, NULL) != 0)
				rval = FMD_OBJ_STATE_UNKNOWN;
			else {
				if (devid_compare(id, matchid) != 0)
					rval = FMD_OBJ_STATE_REPLACED;
				else
					rval = FMD_OBJ_STATE_STILL_PRESENT;
				devid_free(matchid);
			}
			di_fini(dnode);
		}
	}
	topo_mod_free(mod, path, len);

	if (topo_mod_nvalloc(mod, out, NV_UNIQUE_NAME) != 0)
		return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
	if (nvlist_add_uint32(*out, TOPO_METH_REPLACED_RET, rval) != 0) {
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

	if (version > TOPO_METH_UNUSABLE_VERSION)
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

/*ARGSUSED*/
static int
dev_fmri_service_state(topo_mod_t *mod, tnode_t *node, topo_version_t version,
    nvlist_t *in, nvlist_t **out)
{
	di_node_t dnode;
	uint8_t fmversion;
	char *devpath = NULL;
	uint32_t service_state;
	uint_t state;

	if (version > TOPO_METH_SERVICE_STATE_VERSION)
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
		service_state = FMD_SERVICE_STATE_UNUSABLE;
	} else {
		uint_t retired = di_retired(dnode);
		state = di_state(dnode);
		if (retired || (state & (DI_DEVICE_OFFLINE | DI_DEVICE_DOWN |
		    DI_BUS_QUIESCED | DI_BUS_DOWN)))
			service_state = FMD_SERVICE_STATE_UNUSABLE;
		else if (state & DI_DEVICE_DEGRADED)
			service_state = FMD_SERVICE_STATE_DEGRADED;
		else
			service_state = FMD_SERVICE_STATE_OK;
		di_fini(dnode);
	}

	if (topo_mod_nvalloc(mod, out, NV_UNIQUE_NAME) != 0)
		return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
	if (nvlist_add_uint32(*out, TOPO_METH_SERVICE_STATE_RET,
	    service_state) != 0) {
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
