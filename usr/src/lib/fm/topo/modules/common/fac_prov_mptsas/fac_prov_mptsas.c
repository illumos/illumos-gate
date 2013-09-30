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

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <strings.h>
#include <limits.h>
#include <alloca.h>
#include <errno.h>
#include <libnvpair.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/fm/protocol.h>
#include <fm/libtopo.h>
#include <fm/topo_mod.h>

#include "sys/scsi/adapters/mpt_sas/mptsas_ioctl.h"

#define	TOPO_METH_MPTSAS_LED_MODE_VERSION	0

static int fac_prov_mptsas_enum(topo_mod_t *, tnode_t *, const char *,
    topo_instance_t, topo_instance_t, void *, void *);

/*
 * mpt_sas facility provider methods
 */
static int mptsas_led_mode(topo_mod_t *, tnode_t *, topo_version_t,
    nvlist_t *, nvlist_t **);

const topo_modops_t mptsas_ops = { fac_prov_mptsas_enum, NULL };

const topo_modinfo_t mptsas_info =
	{ "mpt_sas facility provider", FM_FMRI_SCHEME_HC, TOPO_VERSION,
	&mptsas_ops };

static const topo_method_t mptsas_fac_methods[] = {
	{ "mptsas_led_mode", TOPO_PROP_METH_DESC,
	    TOPO_METH_MPTSAS_LED_MODE_VERSION,
	    TOPO_STABILITY_INTERNAL, mptsas_led_mode },
	{ NULL }
};

/*ARGSUSED*/
int
_topo_init(topo_mod_t *mod, topo_version_t version)
{
	if (getenv("TOPOFACMPTSASDEBUG") != NULL)
		topo_mod_setdebug(mod);

	return (topo_mod_register(mod, &mptsas_info, TOPO_VERSION));
}

void
_topo_fini(topo_mod_t *mod)
{
	topo_mod_unregister(mod);
}

static int
do_led_control(topo_mod_t *mod, char *devctl, uint16_t enclosure,
    uint16_t slot, uint8_t led, uint32_t *ledmode, boolean_t set)
{
	int fd;
	mptsas_led_control_t lc;

	bzero(&lc, sizeof (lc));

	lc.Command = set ? MPTSAS_LEDCTL_FLAG_SET : MPTSAS_LEDCTL_FLAG_GET;
	lc.Enclosure = enclosure;
	lc.Slot = slot;
	lc.Led = led;
	lc.LedStatus = *ledmode;

	if ((fd = open(devctl, (set ? O_RDWR : O_RDONLY))) == -1) {
		topo_mod_dprintf(mod, "devctl open failed: %s",
		    strerror(errno));
		return (-1);
	}

	if (ioctl(fd, MPTIOCTL_LED_CONTROL, &lc) == -1) {
		if (errno == ENOENT) {
			/*
			 * If there is not presently a target attached for
			 * a particular enclosure/slot pair then the driver
			 * does not track LED status for this bay.  Assume
			 * all LEDs are off.
			 */
			lc.LedStatus = 0;
		} else {
			topo_mod_dprintf(mod, "led control ioctl failed: %s",
			    strerror(errno));
			(void) close(fd);
			return (-1);
		}
	}

	*ledmode = lc.LedStatus ? TOPO_LED_STATE_ON : TOPO_LED_STATE_OFF;

	(void) close(fd);
	return (0);
}

static int
mptsas_led_mode(topo_mod_t *mod, tnode_t *node, topo_version_t vers,
    nvlist_t *in, nvlist_t **nvout)
{
	int err, ret = 0;
	tnode_t *pnode = topo_node_parent(node);
	uint32_t type, ledmode = 0;
	nvlist_t *pargs, *nvl;
	char *driver = NULL, *devctl = NULL;
	uint32_t enclosure, slot;
	uint8_t mptsas_led;
	boolean_t set;

	if (vers > TOPO_METH_MPTSAS_LED_MODE_VERSION)
		return (topo_mod_seterrno(mod, ETOPO_METHOD_VERNEW));

	if (topo_prop_get_string(pnode, TOPO_PGROUP_BINDING,
	    TOPO_BINDING_DRIVER, &driver, &err) != 0 ||
	    strcmp("mpt_sas", driver) != 0) {
		topo_mod_dprintf(mod, "%s: Facility driver was not mpt_sas",
		    __func__);
		ret = topo_mod_seterrno(mod, EMOD_NVL_INVAL);
		goto out;
	}
	if (topo_prop_get_uint32(node, TOPO_PGROUP_FACILITY, TOPO_FACILITY_TYPE,
	    &type, &err) != 0) {
		topo_mod_dprintf(mod, "%s: Failed to lookup %s property "
		    "(%s)", __func__, TOPO_FACILITY_TYPE, topo_strerror(err));
		return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
	}
	switch (type) {
	case (TOPO_LED_TYPE_SERVICE):
		mptsas_led = MPTSAS_LEDCTL_LED_FAIL;
		break;
	case (TOPO_LED_TYPE_LOCATE):
		mptsas_led = MPTSAS_LEDCTL_LED_IDENT;
		break;
	case (TOPO_LED_TYPE_OK2RM):
		mptsas_led = MPTSAS_LEDCTL_LED_OK2RM;
		break;
	default:
		topo_mod_dprintf(mod, "%s: Invalid LED type: 0x%x\n", __func__,
		    type);
		return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
	}
	if (topo_prop_get_string(pnode, TOPO_PGROUP_BINDING,
	    TOPO_BINDING_DEVCTL, &devctl, &err) != 0 ||
	    topo_prop_get_uint32(pnode, TOPO_PGROUP_BINDING,
	    TOPO_BINDING_ENCLOSURE, &enclosure, &err) != 0 ||
	    topo_prop_get_uint32(pnode, TOPO_PGROUP_BINDING,
	    TOPO_BINDING_SLOT, &slot, &err) != 0) {
		topo_mod_dprintf(mod, "%s: Facility was missing mpt_sas binding"
		    " properties\n", __func__);
		ret = topo_mod_seterrno(mod, EMOD_NVL_INVAL);
		goto out;
	}

	if ((nvlist_lookup_nvlist(in, TOPO_PROP_PARGS, &pargs) == 0) &&
	    nvlist_exists(pargs, TOPO_PROP_VAL_VAL)) {
		/*
		 * Set the LED mode
		 */
		set = B_TRUE;
		if ((ret = nvlist_lookup_uint32(pargs, TOPO_PROP_VAL_VAL,
		    &ledmode)) != 0) {
			topo_mod_dprintf(mod, "%s: Failed to lookup %s nvpair "
			    "(%s)\n", __func__, TOPO_PROP_VAL_VAL,
			    strerror(ret));
			ret = topo_mod_seterrno(mod, EMOD_NVL_INVAL);
			goto out;
		}
		topo_mod_dprintf(mod, "%s: Setting LED mode to %s\n", __func__,
		    ledmode ? "ON" : "OFF");
	} else {
		/*
		 * Get the LED mode
		 */
		set = B_FALSE;
		topo_mod_dprintf(mod, "%s: Getting LED mode\n", __func__);
	}

	if (do_led_control(mod, devctl, enclosure, slot, mptsas_led, &ledmode,
	    set) != 0) {
		topo_mod_dprintf(mod, "%s: do_led_control failed", __func__);
		ret = topo_mod_seterrno(mod, EMOD_UNKNOWN);
		goto out;
	}

	if (topo_mod_nvalloc(mod, &nvl, NV_UNIQUE_NAME) != 0 ||
	    nvlist_add_string(nvl, TOPO_PROP_VAL_NAME, TOPO_LED_MODE) != 0 ||
	    nvlist_add_uint32(nvl, TOPO_PROP_VAL_TYPE, TOPO_TYPE_UINT32) != 0 ||
	    nvlist_add_uint32(nvl, TOPO_PROP_VAL_VAL, ledmode) != 0) {
		topo_mod_dprintf(mod, "%s: Failed to allocate 'out' nvlist\n",
		    __func__);
		nvlist_free(nvl);
		ret = topo_mod_seterrno(mod, EMOD_NOMEM);
		goto out;
	}
	*nvout = nvl;

out:
	if (driver != NULL)
		topo_mod_strfree(mod, driver);
	if (devctl != NULL)
		topo_mod_strfree(mod, devctl);
	return (ret);
}

/*ARGSUSED*/
static int
fac_prov_mptsas_enum(topo_mod_t *mod, tnode_t *rnode, const char *name,
    topo_instance_t min, topo_instance_t max, void *arg, void *unused)
{
	if (topo_node_flags(rnode) == TOPO_NODE_FACILITY) {
		if (topo_method_register(mod, rnode, mptsas_fac_methods) != 0) {
			topo_mod_dprintf(mod, "%s: topo_method_register() "
			    "failed: %s", __func__, topo_mod_errmsg(mod));
			return (-1);
		}
		return (0);
	}

	topo_mod_dprintf(mod, "%s: unexpected node flags %x", __func__,
	    topo_node_flags(rnode));
	return (-1);
}
