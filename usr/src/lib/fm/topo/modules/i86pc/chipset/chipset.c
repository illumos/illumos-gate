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
 * Copyright 2019 Joyent, Inc.
 */

/*
 * Chipset Enumeration
 *
 * Most x86 systems have some form of chipset which are components that exist on
 * the motherboard that provide additional services that range from I/O such as
 * memory and PCIe controllers (though as of this writing those mostly are a
 * part of the CPU now) to additional functionality like Ethernet and USB
 * controllers. At the moment, this module opts to enumerate a chipset node if
 * there's something that exists under it that we care about such as:
 *
 *   o Temperature sensors
 *   o Firmware modules
 *
 * If we do not detect anything, then we do not bother enumerating and trying to
 * determine the different chipsets that are on the system. Currently, the only
 * method for doing this is the presence of an Intel platform controller hub
 * (PCH) temperature sensor.
 */

#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>

#include <sys/fm/protocol.h>
#include <fm/topo_mod.h>
#include <fm/topo_list.h>
#include <fm/topo_method.h>

#include <topo_sensor.h>

#define	CHIPSET_VERSION	1

/*
 * This is the path to the temperature sensor that, if present, indicates we
 * should construct a chipset node.
 */
static const char *topo_chipset_temp_sensor =
	"/dev/sensors/temperature/pch/ts.0";

/*
 * Attempt to determine if there is enough information for us to enumerate a
 * chipset node, which usually means that we would enumerate something under it
 * such as a temperature sensor or provide information about some piece of
 * firmware that it has. Currently, if there is no temperature sensor, then we
 * don't consider one to be present and don't do anything else.
 */
static boolean_t
topo_chipset_present(void)
{
	struct stat st;

	if (stat(topo_chipset_temp_sensor, &st) == 0 &&
	    S_ISCHR(st.st_mode)) {
		return (B_TRUE);
	}

	return (B_FALSE);
}

static int
topo_chipset_enum(topo_mod_t *mod, tnode_t *pnode, const char *name,
    topo_instance_t min, topo_instance_t max, void *modarg, void *data)
{
	int ret;
	nvlist_t *fmri = NULL, *auth = NULL, *presource = NULL;
	tnode_t *tn = NULL;
	const topo_instance_t inst = 0;

	topo_mod_dprintf(mod, "chipset_enum: asked to enumerate %s", name);

	if (strcmp(name, CHIPSET) != 0) {
		topo_mod_dprintf(mod, "chipset_enum: asked to enumerate "
		    "unknown component");
		return (topo_mod_seterrno(mod, EMOD_UKNOWN_ENUM));
	}

	if (!topo_chipset_present()) {
		topo_mod_dprintf(mod, "chipset_enum: no device present", name);
		return (0);
	}

	if ((auth = topo_mod_auth(mod, pnode)) == NULL) {
		topo_mod_dprintf(mod, "chipset_enum: failed to get topo "
		    "auth: %s", topo_mod_errmsg(mod));
		/* topo_mod_auth() sets the module error */
		ret = -1;
		goto err;
	}

	if ((fmri = topo_mod_hcfmri(mod, pnode, FM_HC_SCHEME_VERSION,
	    CHIPSET, inst, NULL, auth, NULL, NULL, NULL)) == NULL) {
		topo_mod_dprintf(mod, "chipset_enum: failed to get FMRI: %s",
		    topo_mod_errmsg(mod));
		/* topo_mod_hcfmri() sets the module error */
		ret = -1;
		goto err;
	}

	if ((tn = topo_node_bind(mod, pnode, CHIPSET, inst, fmri)) == NULL) {
		topo_mod_dprintf(mod, "chipset_enum: failed to bind node: %s",
		    topo_mod_errmsg(mod));
		ret = -1;
		goto err;
	}

	if (topo_node_resource(pnode, &presource, &ret) != 0) {
		topo_mod_dprintf(mod, "chipset_enum: failed to get parent "
		    "resource %s\n", topo_strerror(ret));
		ret = topo_mod_seterrno(mod, ret);
		goto err;
	}

	if (topo_node_fru_set(tn, presource, 0, &ret) != 0) {
		topo_mod_dprintf(mod, "chipset_enum: failed to set FRU: %s",
		    topo_strerror(ret));
		ret = topo_mod_seterrno(mod, ret);
		goto err;
	}

	/*
	 * Finally, create the temperature sensor.
	 */
	if ((ret = topo_sensor_create_temp_sensor(mod, tn,
	    topo_chipset_temp_sensor, "temp")) != 0) {
		topo_mod_dprintf(mod, "failed to create chipset temperature "
		    "sensor");
		goto err;
	}

	nvlist_free(auth);
	nvlist_free(fmri);
	nvlist_free(presource);
	return (0);
err:
	nvlist_free(auth);
	nvlist_free(fmri);
	nvlist_free(presource);
	topo_node_unbind(tn);
	return (ret);
}

static const topo_modops_t chipset_ops = {
	topo_chipset_enum, NULL
};

static topo_modinfo_t chipset_mod = {
	CHIPSET, FM_FMRI_SCHEME_HC, CHIPSET_VERSION, &chipset_ops
};

int
_topo_init(topo_mod_t *mod, topo_version_t version)
{
	if (getenv("TOPOCHIPSETDEBUG") != NULL) {
		topo_mod_setdebug(mod);
	}

	topo_mod_dprintf(mod, "_mod_init: initializing %s enumerator\n",
	    CHIPSET);

	if (version != -1) {

	}

	if (topo_mod_register(mod, &chipset_mod, TOPO_VERSION) != 0) {
		return (-1);
	}

	return (0);
}

void
_topo_fini(topo_mod_t *mod)
{
}
