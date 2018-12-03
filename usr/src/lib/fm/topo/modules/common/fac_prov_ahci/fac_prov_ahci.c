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
 * Copyright (c) 2018, Joyent, Inc.
 */

#include <unistd.h>
#include <stropts.h>
#include <fcntl.h>
#include <libnvpair.h>
#include <string.h>
#include <strings.h>
#include <sys/fm/protocol.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fm/libtopo.h>
#include <fm/topo_mod.h>
#include <libgen.h>

#include "sys/sata/adapters/ahci/ahciem.h"

#define	TOPO_METH_AHCI_LED_MODE_VERSION	0

/*
 * This enum is used to more clearly demonstrate the mapping between libtopo's
 * concept of LED types and the types represented in AHCI.
 */
typedef enum {
	AHCI_FAC_IDENT,
	AHCI_FAC_FAULT
} ahci_fac_led_t;

static int fac_prov_ahci_enum(topo_mod_t *, tnode_t *, const char *,
    topo_instance_t, topo_instance_t, void *, void *);

/*
 * ahci facility provider methods
 */
static int ahci_led_mode(topo_mod_t *, tnode_t *, topo_version_t,
    nvlist_t *, nvlist_t **);

static const topo_modops_t ahci_ops = { fac_prov_ahci_enum, NULL };

static const topo_modinfo_t ahci_info =
	{ "ahci facility provider", FM_FMRI_SCHEME_HC, TOPO_VERSION,
	&ahci_ops };

static const topo_method_t ahci_fac_methods[] = {
	{ "ahci_led_mode", TOPO_PROP_METH_DESC,
	    TOPO_METH_AHCI_LED_MODE_VERSION,
	    TOPO_STABILITY_INTERNAL, ahci_led_mode },
	{ NULL }
};

int
_topo_init(topo_mod_t *mod, topo_version_t version)
{
	if (getenv("TOPOFACAHCIDEBUG") != NULL)
		topo_mod_setdebug(mod);

	return (topo_mod_register(mod, &ahci_info, TOPO_VERSION));
}

void
_topo_fini(topo_mod_t *mod)
{
	topo_mod_unregister(mod);
}

/*
 * Get or set the LED state for a given LED of type (facility node type, port).
 * This function returns -1 on error.
 */
static int
do_led_control(topo_mod_t *mod, const char *devctl, uint32_t port,
    ahci_fac_led_t fac_type, uint32_t *ledmode, boolean_t set)
{
	int fd = -1, ret = -1;

	if ((fd = open(devctl, (set ? O_RDWR : O_RDONLY))) == -1) {
		topo_mod_dprintf(mod, "devctl open failed: %s",
		    strerror(errno));
		goto out;
	}

	if (set) {
		ahci_ioc_em_set_t ahci_set;
		uint32_t led_status = *ledmode;
		uint_t op, leds;

		switch (fac_type) {
		case AHCI_FAC_IDENT:
			leds = AHCI_EM_LED_IDENT_ENABLE;
			break;
		case AHCI_FAC_FAULT:
			leds = AHCI_EM_LED_FAULT_ENABLE;
			break;
		default:
			topo_mod_dprintf(mod, "invalid facility node type: %d",
			    fac_type);
			goto out;
		}

		if (led_status) {
			op = AHCI_EM_IOC_SET_OP_ADD;
		} else {
			op = AHCI_EM_IOC_SET_OP_REM;
		}

		bzero(&ahci_set, sizeof (ahci_set));
		ahci_set.aiems_port = port;
		ahci_set.aiems_op = op;
		ahci_set.aiems_leds = leds;

		if (ioctl(fd, AHCI_EM_IOC_SET, &ahci_set) == -1) {
			topo_mod_dprintf(mod, "ioctl failed: %s",
			    strerror(errno));
			goto out;
		}
	} else {
		uint_t led_set = 0;
		ahci_ioc_em_get_t ahci_get;

		bzero(&ahci_get, sizeof (ahci_get));
		if (ioctl(fd, AHCI_EM_IOC_GET, &ahci_get) == -1) {
			topo_mod_dprintf(mod, "led control ioctl failed: %s",
			    strerror(errno));
			goto out;
		}

		switch (fac_type) {
		case AHCI_FAC_IDENT:
			led_set = ahci_get.aiemg_status[port] &
			    AHCI_EM_LED_IDENT_ENABLE;
			break;
		case AHCI_FAC_FAULT:
			led_set = ahci_get.aiemg_status[port] &
			    AHCI_EM_LED_FAULT_ENABLE;
			break;
		default:
			topo_mod_dprintf(mod, "invalid facility node type: %d",
			    fac_type);
			goto out;
		}

		*ledmode = (led_set != 0) ?
		    TOPO_LED_STATE_ON : TOPO_LED_STATE_OFF;
	}
	ret = 0;

out:
	if (fd >= 0) {
		(void) close(fd);
	}
	return (ret);
}

static int
ahci_led_mode(topo_mod_t *mod, tnode_t *node, topo_version_t vers,
    nvlist_t *in, nvlist_t **nvout)
{
	int err, ret = 0;
	tnode_t *pnode = topo_node_parent(node);
	uint32_t type, ledmode = 0, ahci_port;
	nvlist_t *pargs, *nvl;
	char *devctl = NULL;
	boolean_t set;
	ahci_fac_led_t fac_type;

	if (vers > TOPO_METH_AHCI_LED_MODE_VERSION) {
		return (topo_mod_seterrno(mod, ETOPO_METHOD_VERNEW));
	}

	if (topo_prop_get_uint32(node, TOPO_PGROUP_FACILITY, TOPO_FACILITY_TYPE,
	    &type, &err) != 0) {
		topo_mod_dprintf(mod, "%s: Failed to lookup %s property "
		    "(%s)", __func__, TOPO_FACILITY_TYPE, topo_strerror(err));
		return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
	}

	/*
	 * While the AHCI specification includes bits for locate, fault, and
	 * activity LEDs, we generally only need to account for locate and fault
	 * LEDs, as activity LEDs are typically disabled in hardware.
	 */
	switch (type) {
	case (TOPO_LED_TYPE_SERVICE):
		fac_type = AHCI_FAC_FAULT;
		break;
	case (TOPO_LED_TYPE_LOCATE):
		fac_type = AHCI_FAC_IDENT;
		break;
	default:
		topo_mod_dprintf(mod, "%s: Invalid LED type: 0x%x\n", __func__,
		    type);
		ret = topo_mod_seterrno(mod, EMOD_NVL_INVAL);
		return (ret);
	}

	if (topo_prop_get_string(pnode, TOPO_PGROUP_BINDING,
	    TOPO_BINDING_DEVCTL, &devctl, &err) != 0 ||
	    topo_prop_get_uint32(pnode, TOPO_PGROUP_BINDING,
	    TOPO_BINDING_PORT, &ahci_port, &err) != 0) {
		topo_mod_dprintf(mod, "%s: Facility was missing ahci binding "
		    "properties\n", __func__);
		ret = topo_mod_seterrno(mod, EMOD_NVL_INVAL);
		goto out;
	}

	if ((nvlist_lookup_nvlist(in, TOPO_PROP_PARGS, &pargs) == 0) &&
	    nvlist_exists(pargs, TOPO_PROP_VAL_VAL)) {
		/*
		 * Set the LED mode.
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
	ret = do_led_control(mod, devctl, ahci_port, fac_type, &ledmode, set);

	if (ret == -1) {
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
	topo_mod_strfree(mod, devctl);
	return (ret);
}

static int
fac_prov_ahci_enum(topo_mod_t *mod, tnode_t *rnode, const char *name,
    topo_instance_t min, topo_instance_t max, void *arg, void *unused)
{

	if (topo_node_flags(rnode) == TOPO_NODE_FACILITY) {
		if (topo_method_register(mod, rnode, ahci_fac_methods) != 0) {
			topo_mod_dprintf(mod, "%s: topo_method_register() "
			    "failed: %s", __func__, topo_mod_errmsg(mod));
			return (-1);
		}
		return (0);
	}

	topo_mod_dprintf(mod, "%s: unexpected node flags 0x%x", __func__,
	    topo_node_flags(rnode));
	return (-1);
}
