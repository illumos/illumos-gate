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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Facility node support for SES enclosures.  We support the following facility
 * nodes, based on the node type:
 *
 * 	bay
 * 		indicator=ident
 * 		indicator=fail
 * 		indicator=ok2rm
 * 		sensor=fault
 *
 * 	controller
 * 		indicator=ident
 * 		indicator=fail
 *
 * 	fan
 * 		indicator=ident
 * 		indicator=fail
 * 		sensor=speed
 * 		sensor=fault
 *
 * 	psu
 * 		indicator=ident
 * 		indicator=fail
 * 		sensor=status
 *
 * 	ses-enclosure
 * 		indicator=ident
 * 		indicator=fail
 * 		sensor=fault
 * 		sensor=<name>	(temperature)
 * 		sensor=<name>	(voltage)
 * 		sensor=<name>	(current)
 *
 * Most of these are handled by a single method that supports getting and
 * setting boolean properties on the node.  The fan speed sensor requires a
 * special handler, while the analog enclosure sensors all have similar
 * behavior and can be grouped together using a common method.
 */

#include "ses.h"
#include "disk.h"

#include <string.h>

static int ses_indicator_mode(topo_mod_t *, tnode_t *, topo_version_t,
    nvlist_t *, nvlist_t **);
static int ses_sensor_reading(topo_mod_t *, tnode_t *, topo_version_t,
    nvlist_t *, nvlist_t **);
static int ses_sensor_state(topo_mod_t *, tnode_t *, topo_version_t,
    nvlist_t *, nvlist_t **);
static int ses_psu_state(topo_mod_t *, tnode_t *, topo_version_t,
    nvlist_t *, nvlist_t **);

#define	SES_SUPP_WARN_UNDER	0x01
#define	SES_SUPP_WARN_OVER	0x02
#define	SES_SUPP_CRIT_UNDER	0x04
#define	SES_SUPP_CRIT_OVER	0x08

typedef struct ses_sensor_desc {
	int		sd_type;
	int		sd_units;
	const char	*sd_propname;
	double		sd_multiplier;
} ses_sensor_desc_t;

#define	TOPO_METH_SES_MODE_VERSION	0
#define	TOPO_METH_SES_READING_VERSION	0
#define	TOPO_METH_SES_STATE_VERSION	0
#define	TOPO_METH_SES_PSU_VERSION	0

#define	TOPO_METH_SES_READING_PROP	"propname"
#define	TOPO_METH_SES_READING_MULT	"multiplier"

#define	TOPO_METH_SES_STATE_PROP	"propname"

#define	TOPO_METH_SES_MODE_PROP		"property-name"
#define	TOPO_METH_SES_MODE_ALTPROP	"alternate-property"

static const topo_method_t ses_indicator_methods[] = {
	{ "ses_indicator_mode", TOPO_PROP_METH_DESC,
	    TOPO_METH_SES_MODE_VERSION, TOPO_STABILITY_INTERNAL,
	    ses_indicator_mode }
};

static const topo_method_t ses_sensor_methods[] = {
	{ "ses_sensor_reading", TOPO_PROP_METH_DESC,
	    TOPO_METH_SES_READING_VERSION, TOPO_STABILITY_INTERNAL,
	    ses_sensor_reading },
	{ "ses_sensor_state", TOPO_PROP_METH_DESC,
	    TOPO_METH_SES_STATE_VERSION, TOPO_STABILITY_INTERNAL,
	    ses_sensor_state },
	{ "ses_psu_state", TOPO_PROP_METH_DESC,
	    TOPO_METH_SES_PSU_VERSION, TOPO_STABILITY_INTERNAL,
	    ses_psu_state },
};

/*
 * Get or set an indicator.  This method is invoked with arguments indicating
 * the property to query to retrieve the value.  Some elements (enclosures and
 * devices) support a request property that is distinct from an array-detected
 * property.  Either of these conditions will result in the indicator being
 * lit, so we have to check both properties.
 */
static int
ses_indicator_mode(topo_mod_t *mod, tnode_t *tn, topo_version_t vers,
    nvlist_t *in, nvlist_t **out)
{
	ses_node_t *np;
	nvlist_t *args, *pargs, *props;
	char *propname, *altprop;
	uint32_t mode;
	boolean_t current, altcurrent;
	nvlist_t *nvl;
	ses_enum_target_t *tp = topo_node_getspecific(tn);

	if (vers > TOPO_METH_SES_MODE_VERSION)
		return (topo_mod_seterrno(mod, ETOPO_METHOD_VERNEW));

	if (nvlist_lookup_nvlist(in, TOPO_PROP_ARGS, &args) != 0 ||
	    nvlist_lookup_string(args, TOPO_METH_SES_MODE_PROP,
	    &propname) != 0) {
		topo_mod_dprintf(mod, "invalid arguments to 'mode' method\n");
		return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
	}

	if (nvlist_lookup_string(args, TOPO_METH_SES_MODE_ALTPROP,
	    &altprop) != 0)
		altprop = NULL;

	if ((np = ses_node_lock(mod, tn)) == NULL) {
		topo_mod_dprintf(mod, "failed to lookup ses node in 'mode' "
		    "method\n");
		return (-1);
	}
	verify((props = ses_node_props(np)) != NULL);

	if (nvlist_lookup_nvlist(in, TOPO_PROP_PARGS, &pargs) == 0 &&
	    nvlist_exists(pargs, TOPO_PROP_VAL_VAL)) {
		/* set operation */
		if (nvlist_lookup_uint32(pargs, TOPO_PROP_VAL_VAL,
		    &mode) != 0) {
			topo_mod_dprintf(mod, "invalid type for indicator "
			    "mode property");
			(void) topo_mod_seterrno(mod, EMOD_NVL_INVAL);
			goto error;
		}

		if (mode != TOPO_LED_STATE_OFF && mode != TOPO_LED_STATE_ON) {
			topo_mod_dprintf(mod, "invalid indicator mode %d\n",
			    mode);
			(void) topo_mod_seterrno(mod, EMOD_NVL_INVAL);
			goto error;
		}

		nvl = NULL;
		if (topo_mod_nvalloc(mod, &nvl, NV_UNIQUE_NAME) != 0 ||
		    nvlist_add_boolean_value(nvl, propname,
		    mode == TOPO_LED_STATE_ON ? B_TRUE : B_FALSE) != 0) {
			nvlist_free(nvl);
			(void) topo_mod_seterrno(mod, EMOD_NOMEM);
			goto error;
		}

		if (ses_node_ctl(np, SES_CTL_OP_SETPROP, nvl) != 0) {
			topo_mod_dprintf(mod, "failed to set indicator: %s\n",
			    ses_errmsg());
			nvlist_free(nvl);
			goto error;
		}

		tp->set_snaptime = 0;
		nvlist_free(nvl);
	} else {
		/* get operation */
		if (nvlist_lookup_boolean_value(props,
		    propname, &current) != 0) {
			topo_mod_dprintf(mod, "failed to lookup %s in node "
			    "properties\n", propname);
			(void) topo_mod_seterrno(mod, EMOD_METHOD_NOTSUP);
			goto error;
		}

		if (altprop != NULL && nvlist_lookup_boolean_value(props,
		    altprop, &altcurrent) == 0)
			current |= altcurrent;

		mode = current ? TOPO_LED_STATE_ON : TOPO_LED_STATE_OFF;
	}

	nvl = NULL;
	if (topo_mod_nvalloc(mod, &nvl, NV_UNIQUE_NAME) != 0 ||
	    nvlist_add_string(nvl, TOPO_PROP_VAL_NAME,
	    TOPO_LED_MODE) != 0 ||
	    nvlist_add_uint32(nvl, TOPO_PROP_VAL_TYPE, TOPO_TYPE_UINT32) != 0 ||
	    nvlist_add_uint32(nvl, TOPO_PROP_VAL_VAL, mode) != 0) {
		nvlist_free(nvl);
		(void) topo_mod_seterrno(mod, EMOD_NOMEM);
		goto error;
	}

	ses_node_unlock(mod, tn);
	*out = nvl;
	return (0);

error:
	ses_node_unlock(mod, tn);
	return (-1);
}

/*
 * Read the given sensor value.  This just looks up the value in the node
 * properties, and multiplies by a fixed value (determined when the method is
 * instantiated).
 */
static int
ses_sensor_reading(topo_mod_t *mod, tnode_t *tn, topo_version_t vers,
    nvlist_t *in, nvlist_t **out)
{
	ses_node_t *np;
	nvlist_t *args, *props;
	char *prop;
	double raw, multiplier;
	uint64_t current;
	int64_t scurrent;
	nvlist_t *nvl;

	if (vers > TOPO_METH_SES_MODE_VERSION)
		return (topo_mod_seterrno(mod, ETOPO_METHOD_VERNEW));

	if (nvlist_lookup_nvlist(in, TOPO_PROP_ARGS, &args) != 0 ||
	    nvlist_lookup_string(args, TOPO_METH_SES_READING_PROP,
	    &prop) != 0) {
		topo_mod_dprintf(mod,
		    "invalid arguments to 'reading' method\n");
		return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
	}

	if (nvlist_lookup_double(args, TOPO_METH_SES_READING_MULT,
	    &multiplier) != 0)
		multiplier = 1;

	if ((np = ses_node_lock(mod, tn)) == NULL) {
		topo_mod_dprintf(mod, "failed to lookup ses node in 'mode' "
		    "method\n");
		return (-1);
	}
	verify((props = ses_node_props(np)) != NULL);

	if (nvlist_lookup_uint64(props, prop, &current) == 0) {
		raw = (double)current;
	} else if (nvlist_lookup_int64(props, prop, &scurrent) == 0) {
		raw = (double)scurrent;
	} else {
		topo_mod_dprintf(mod, "failed to lookup %s in node "
		    "properties\n", prop);
		ses_node_unlock(mod, tn);
		return (topo_mod_seterrno(mod, EMOD_METHOD_NOTSUP));
	}

	ses_node_unlock(mod, tn);

	nvl = NULL;
	if (topo_mod_nvalloc(mod, &nvl, NV_UNIQUE_NAME) != 0 ||
	    nvlist_add_string(nvl, TOPO_PROP_VAL_NAME,
	    TOPO_SENSOR_READING) != 0 ||
	    nvlist_add_uint32(nvl, TOPO_PROP_VAL_TYPE, TOPO_TYPE_DOUBLE) != 0 ||
	    nvlist_add_double(nvl, TOPO_PROP_VAL_VAL, raw * multiplier) != 0) {
		nvlist_free(nvl);
		return (topo_mod_seterrno(mod, EMOD_NOMEM));
	}

	*out = nvl;
	return (0);
}

/*
 * Returns the current sensor state.  This can be invoked for one of two
 * different types of sensors: threshold or discrete sensors.  For discrete
 * sensors, we expect a name of a boolean property and indicate
 * asserted/deasserted based on that.  For threshold sensors, we check for the
 * standard warning/critical properties and translate that into the appropriate
 * topo state.
 */
/*ARGSUSED*/
static int
ses_sensor_state(topo_mod_t *mod, tnode_t *tn, topo_version_t vers,
    nvlist_t *in, nvlist_t **out)
{
	nvlist_t *nvl, *args, *props;
	boolean_t value;
	uint64_t status;
	uint32_t state;
	ses_node_t *np;
	char *prop;

	if (nvlist_lookup_nvlist(in, TOPO_PROP_ARGS, &args) != 0) {
		topo_mod_dprintf(mod,
		    "invalid arguments to 'state' method\n");
		return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
	}

	if ((np = ses_node_lock(mod, tn)) == NULL) {
		topo_mod_dprintf(mod, "failed to lookup ses node in 'mode' "
		    "method\n");
		return (-1);
	}
	verify((props = ses_node_props(np)) != NULL);

	if (nvlist_lookup_uint64(props, SES_PROP_STATUS_CODE, &status) != 0)
		status = SES_ESC_UNSUPPORTED;

	state = 0;
	if (nvlist_lookup_string(args, TOPO_METH_SES_STATE_PROP,
	    &prop) == 0) {
		/* discrete (fault) sensor */

		if (status == SES_ESC_UNRECOVERABLE)
			state |= TOPO_SENSOR_STATE_GENERIC_FAIL_NONRECOV;
		else if (status == SES_ESC_CRITICAL)
			state |= TOPO_SENSOR_STATE_GENERIC_FAIL_CRITICAL;
		else if (nvlist_lookup_boolean_value(props, prop,
		    &value) == 0 && value)
			state |= TOPO_SENSOR_STATE_GENERIC_FAIL_NONRECOV;
		else
			state |= TOPO_SENSOR_STATE_GENERIC_FAIL_DEASSERTED;
	} else {
		/* threshold sensor */
		if (nvlist_lookup_boolean_value(props,
		    SES_PROP_WARN_UNDER, &value) == 0 && value)
			state |= TOPO_SENSOR_STATE_THRESH_LOWER_NONCRIT;
		if (nvlist_lookup_boolean_value(props,
		    SES_PROP_WARN_OVER, &value) == 0 && value)
			state |= TOPO_SENSOR_STATE_THRESH_UPPER_NONCRIT;
		if (nvlist_lookup_boolean_value(props,
		    SES_PROP_CRIT_UNDER, &value) == 0 && value)
			state |= TOPO_SENSOR_STATE_THRESH_LOWER_CRIT;
		if (nvlist_lookup_boolean_value(props,
		    SES_PROP_CRIT_OVER, &value) == 0 && value)
			state |= TOPO_SENSOR_STATE_THRESH_UPPER_CRIT;
	}

	ses_node_unlock(mod, tn);

	nvl = NULL;
	if (topo_mod_nvalloc(mod, &nvl, NV_UNIQUE_NAME) != 0 ||
	    nvlist_add_string(nvl, TOPO_PROP_VAL_NAME,
	    TOPO_SENSOR_STATE) != 0 ||
	    nvlist_add_uint32(nvl, TOPO_PROP_VAL_TYPE, TOPO_TYPE_UINT32) != 0 ||
	    nvlist_add_uint32(nvl, TOPO_PROP_VAL_VAL, state) != 0) {
		nvlist_free(nvl);
		return (topo_mod_seterrno(mod, EMOD_NOMEM));
	}

	*out = nvl;
	return (0);
}

/*
 * Read the status of a PSU.  This is such a specialized operation that it has
 * its own method instead of trying to piggyback on ses_sensor_state().  We
 * use the following mapping to get to the standard topo power supply states:
 *
 *	acfail		-> INPUT_LOST
 *	dcfail		-> INPUT_LOST
 *	undervoltage	-> INPUT_RANGE
 *	overvoltage	-> INPUT_RANGE_PRES
 *	overcurrent	-> INPUT_RANGE_PRES
 *	overtemp	-> (none)
 *
 * If we ever have a need for reading overtemp, we can expand the topo
 * representation for power supplies, but at the moment this seems unnecessary.
 */
/*ARGSUSED*/
static int
ses_psu_state(topo_mod_t *mod, tnode_t *tn, topo_version_t vers,
    nvlist_t *in, nvlist_t **out)
{
	nvlist_t *nvl, *props;
	boolean_t value;
	uint32_t state;
	ses_node_t *np;

	if ((np = ses_node_lock(mod, tn)) == NULL) {
		topo_mod_dprintf(mod, "failed to lookup ses node in 'mode' "
		    "method\n");
		return (-1);
	}
	verify((props = ses_node_props(np)) != NULL);

	state = 0;
	if ((nvlist_lookup_boolean_value(props, SES_PSU_PROP_DC_FAIL,
	    &value) == 0 && value) ||
	    (nvlist_lookup_boolean_value(props, SES_PSU_PROP_AC_FAIL,
	    &value) == 0 && value))
		state |= TOPO_SENSOR_STATE_POWER_SUPPLY_INPUT_LOST;

	if (nvlist_lookup_boolean_value(props, SES_PSU_PROP_DC_UNDER_VOLTAGE,
	    &value) == 0 && value)
		state |= TOPO_SENSOR_STATE_POWER_SUPPLY_INPUT_RANGE;

	if ((nvlist_lookup_boolean_value(props, SES_PSU_PROP_DC_OVER_VOLTAGE,
	    &value) == 0 && value) ||
	    (nvlist_lookup_boolean_value(props, SES_PSU_PROP_DC_OVER_CURRENT,
	    &value) == 0 && value))
		state |= TOPO_SENSOR_STATE_POWER_SUPPLY_INPUT_RANGE_PRES;

	ses_node_unlock(mod, tn);

	nvl = NULL;
	if (topo_mod_nvalloc(mod, &nvl, NV_UNIQUE_NAME) != 0 ||
	    nvlist_add_string(nvl, TOPO_PROP_VAL_NAME,
	    TOPO_SENSOR_STATE) != 0 ||
	    nvlist_add_uint32(nvl, TOPO_PROP_VAL_TYPE, TOPO_TYPE_UINT32) != 0 ||
	    nvlist_add_uint32(nvl, TOPO_PROP_VAL_VAL, state) != 0) {
		nvlist_free(nvl);
		return (topo_mod_seterrno(mod, EMOD_NOMEM));
	}

	*out = nvl;
	return (0);
}

/*
 * Create a facility node, either a sensor or an indicator.
 */
static tnode_t *
ses_add_fac_common(topo_mod_t *mod, tnode_t *pnode, const char *name,
    const char *type, uint64_t nodeid)
{
	tnode_t *tn;
	topo_pgroup_info_t pgi;
	int err;
	ses_enum_target_t *stp = topo_node_getspecific(pnode);

	if ((tn = topo_node_facbind(mod, pnode, name, type)) == NULL) {
		topo_mod_dprintf(mod, "failed to bind facility node %s\n",
		    name);
		return (NULL);
	}

	stp->set_refcount++;
	topo_node_setspecific(tn, stp);

	pgi.tpi_name = TOPO_PGROUP_FACILITY;
	pgi.tpi_namestab = TOPO_STABILITY_PRIVATE;
	pgi.tpi_datastab = TOPO_STABILITY_PRIVATE;
	pgi.tpi_version = 1;

	if (topo_pgroup_create(tn, &pgi, &err) != 0) {
		topo_mod_dprintf(mod, "failed to create facility property "
		    "group: %s\n", topo_strerror(err));
		topo_node_unbind(tn);
		return (NULL);
	}

	/*
	 * We need the node-id property for each facility node.
	 */
	pgi.tpi_name = TOPO_PGROUP_SES;
	pgi.tpi_namestab = TOPO_STABILITY_PRIVATE;
	pgi.tpi_datastab = TOPO_STABILITY_PRIVATE;
	pgi.tpi_version = TOPO_VERSION;

	if (topo_pgroup_create(tn, &pgi, &err) != 0) {
		topo_mod_dprintf(mod, "failed to create ses property "
		    "group: %s\n", topo_strerror(err));
		topo_node_unbind(tn);
		return (NULL);
	}

	if (topo_prop_set_uint64(tn, TOPO_PGROUP_SES,
	    TOPO_PROP_NODE_ID, TOPO_PROP_IMMUTABLE,
	    nodeid, &err) != 0) {
		topo_mod_dprintf(mod,
		    "failed to create property %s: %s\n",
		    TOPO_PROP_NODE_ID, topo_strerror(err));
		topo_node_unbind(tn);
		return (NULL);
	}

	return (tn);
}

/*
 * Add an indicator.  This can be represented by a single property, or by the
 * union of two elements when SES is capable of distinguishing between
 * requested failure and detected failure.
 */
static int
ses_add_indicator(topo_mod_t *mod, tnode_t *pnode, uint64_t nodeid,
    int type, const char *name, const char *propname, const char *altprop)
{
	tnode_t *tn;
	int err;
	nvlist_t *nvl;

	/* create facility node and add methods */
	if ((tn = ses_add_fac_common(mod, pnode, name,
	    TOPO_FAC_TYPE_INDICATOR, nodeid)) == NULL)
		return (-1);

	if (topo_method_register(mod, tn, ses_indicator_methods) < 0) {
		topo_mod_dprintf(mod, "failed to register facility methods\n");
		topo_node_unbind(tn);
		return (-1);
	}

	/* set standard properties */
	if (topo_prop_set_uint32(tn, TOPO_PGROUP_FACILITY,
	    TOPO_FACILITY_TYPE, TOPO_PROP_IMMUTABLE, type, &err) != 0) {
		topo_mod_dprintf(mod,
		    "failed to set facility node properties: %s\n",
		    topo_strerror(err));
		topo_node_unbind(tn);
		return (-1);
	}

	/* 'mode' property */
	nvl = NULL;
	if (topo_mod_nvalloc(mod, &nvl, NV_UNIQUE_NAME) != 0 ||
	    nvlist_add_string(nvl, TOPO_METH_SES_MODE_PROP,
	    propname) != 0 ||
	    (altprop != NULL && nvlist_add_string(nvl,
	    TOPO_METH_SES_MODE_ALTPROP, altprop) != 0)) {
		nvlist_free(nvl);
		topo_mod_dprintf(mod, "failed to setup method arguments\n");
		topo_node_unbind(tn);
		return (topo_mod_seterrno(mod, EMOD_NOMEM));
	}

	if (topo_prop_method_register(tn, TOPO_PGROUP_FACILITY,
	    TOPO_LED_MODE, TOPO_TYPE_UINT32, "ses_indicator_mode",
	    nvl, &err) != 0) {
		nvlist_free(nvl);
		topo_mod_dprintf(mod, "failed to register reading method: %s\n",
		    topo_strerror(err));
		return (-1);
	}

	if (topo_prop_setmutable(tn, TOPO_PGROUP_FACILITY,
	    TOPO_LED_MODE, &err) != 0) {
		nvlist_free(nvl);
		topo_mod_dprintf(mod, "failed to set property as mutable: %s\n",
		    topo_strerror(err));
		return (-1);
	}

	nvlist_free(nvl);
	return (0);
}

static tnode_t *
ses_add_sensor_common(topo_mod_t *mod, tnode_t *pnode, uint64_t nodeid,
    const char *name, const char *class, int type)
{
	tnode_t *tn;
	int err;

	/* create facility node and add methods */
	if ((tn = ses_add_fac_common(mod, pnode, name,
	    TOPO_FAC_TYPE_SENSOR, nodeid)) == NULL)
		return (NULL);

	if (topo_method_register(mod, tn, ses_sensor_methods) < 0) {
		topo_mod_dprintf(mod, "failed to register facility methods\n");
		topo_node_unbind(tn);
		return (NULL);
	}

	/* set standard properties */
	if (topo_prop_set_string(tn, TOPO_PGROUP_FACILITY,
	    TOPO_SENSOR_CLASS, TOPO_PROP_IMMUTABLE,
	    class, &err) != 0 ||
	    topo_prop_set_uint32(tn, TOPO_PGROUP_FACILITY,
	    TOPO_FACILITY_TYPE, TOPO_PROP_IMMUTABLE,
	    type, &err) != 0) {
		topo_mod_dprintf(mod,
		    "failed to set facility node properties: %s\n",
		    topo_strerror(err));
		topo_node_unbind(tn);
		return (NULL);
	}

	return (tn);
}

/*
 * Add an analog (threshold) sensor to the enclosure.  This is used for fan
 * speed, voltage, current, and temperature sensors.
 */
static int
ses_add_sensor(topo_mod_t *mod, tnode_t *pnode, uint64_t nodeid,
    const char *name, const ses_sensor_desc_t *sdp)
{
	tnode_t *tn;
	int err;
	nvlist_t *nvl;

	if ((tn = ses_add_sensor_common(mod, pnode, nodeid, name,
	    TOPO_SENSOR_CLASS_THRESHOLD, sdp->sd_type)) == NULL)
		return (-1);

	if (topo_prop_set_uint32(tn, TOPO_PGROUP_FACILITY,
	    TOPO_SENSOR_UNITS, TOPO_PROP_IMMUTABLE, sdp->sd_units, &err) != 0) {
		topo_mod_dprintf(mod,
		    "failed to set facility node properties: %s\n",
		    topo_strerror(err));
		topo_node_unbind(tn);
		return (-1);
	}

	/* 'reading' property */
	nvl = NULL;
	if (topo_mod_nvalloc(mod, &nvl, NV_UNIQUE_NAME) != 0 ||
	    nvlist_add_string(nvl, TOPO_METH_SES_READING_PROP,
	    sdp->sd_propname) != 0 ||
	    (sdp->sd_multiplier != 0 &&
	    nvlist_add_double(nvl, TOPO_METH_SES_READING_MULT,
	    sdp->sd_multiplier) != 0)) {
		nvlist_free(nvl);
		topo_mod_dprintf(mod, "failed to setup method arguments\n");
		topo_node_unbind(tn);
		return (-1);
	}

	if (topo_prop_method_register(tn, TOPO_PGROUP_FACILITY,
	    TOPO_SENSOR_READING, TOPO_TYPE_DOUBLE, "ses_sensor_reading",
	    nvl, &err) != 0) {
		nvlist_free(nvl);
		topo_mod_dprintf(mod, "failed to register reading method: %s\n",
		    topo_strerror(err));
		return (-1);
	}

	nvlist_free(nvl);
	if (topo_mod_nvalloc(mod, &nvl, NV_UNIQUE_NAME) != 0) {
		topo_mod_dprintf(mod, "failed to setup method arguments\n");
		topo_node_unbind(tn);
		return (-1);
	}

	/* 'state' property */
	if (topo_prop_method_register(tn, TOPO_PGROUP_FACILITY,
	    TOPO_SENSOR_STATE, TOPO_TYPE_UINT32, "ses_sensor_state",
	    nvl, &err) != 0) {
		nvlist_free(nvl);
		topo_mod_dprintf(mod, "failed to register state method: %s\n",
		    topo_strerror(err));
		return (-1);
	}

	nvlist_free(nvl);
	return (0);
}

/*
 * Add a discrete sensor for simple boolean values.  This is used to indicate
 * externally-detected failures for fans, bays, and enclosures.
 */
static int
ses_add_discrete(topo_mod_t *mod, tnode_t *pnode, uint64_t nodeid,
    const char *name, const char *prop)
{
	tnode_t *tn;
	int err;
	nvlist_t *nvl;

	if ((tn = ses_add_sensor_common(mod, pnode, nodeid, name,
	    TOPO_SENSOR_CLASS_DISCRETE,
	    TOPO_SENSOR_TYPE_GENERIC_FAILURE)) == NULL)
		return (-1);

	nvl = NULL;
	if (topo_mod_nvalloc(mod, &nvl, NV_UNIQUE_NAME) != 0 ||
	    nvlist_add_string(nvl, TOPO_METH_SES_STATE_PROP, prop) != 0) {
		nvlist_free(nvl);
		topo_mod_dprintf(mod, "failed to setup method arguments\n");
		topo_node_unbind(tn);
		return (-1);
	}

	/* 'state' property */
	if (topo_prop_method_register(tn, TOPO_PGROUP_FACILITY,
	    TOPO_SENSOR_STATE, TOPO_TYPE_UINT32, "ses_sensor_state",
	    nvl, &err) != 0) {
		nvlist_free(nvl);
		topo_mod_dprintf(mod, "failed to register state method: %s\n",
		    topo_strerror(err));
		return (-1);
	}

	nvlist_free(nvl);
	return (0);
}

/*ARGSUSED*/
static int
ses_add_psu_status(topo_mod_t *mod, tnode_t *pnode, uint64_t nodeid)
{
	tnode_t *tn;
	int err;
	nvlist_t *nvl;

	/* create facility node and add methods */
	if ((tn = ses_add_sensor_common(mod, pnode, nodeid, "status",
	    TOPO_SENSOR_CLASS_DISCRETE,
	    TOPO_SENSOR_TYPE_POWER_SUPPLY)) == NULL)
		return (-1);

	if (topo_mod_nvalloc(mod, &nvl, NV_UNIQUE_NAME) != 0) {
		nvlist_free(nvl);
		topo_mod_dprintf(mod, "failed to setup method arguments\n");
		topo_node_unbind(tn);
		return (-1);
	}

	/* 'state' property */
	if (topo_prop_method_register(tn, TOPO_PGROUP_FACILITY,
	    TOPO_SENSOR_STATE, TOPO_TYPE_UINT32, "ses_psu_state",
	    nvl, &err) != 0) {
		nvlist_free(nvl);
		topo_mod_dprintf(mod, "failed to register state method: %s\n",
		    topo_strerror(err));
		return (-1);
	}

	nvlist_free(nvl);
	return (0);
}

/*ARGSUSED*/
int
ses_node_enum_facility(topo_mod_t *mod, tnode_t *tn, topo_version_t vers,
    nvlist_t *in, nvlist_t **out)
{
	ses_node_t *np;
	nvlist_t *props;
	uint64_t type, nodeid;
	ses_sensor_desc_t sd = { 0 };

	if ((np = ses_node_lock(mod, tn)) == NULL)
		return (-1);

	assert(ses_node_type(np) == SES_NODE_ELEMENT);
	nodeid = ses_node_id(np);
	verify((props = ses_node_props(np)) != NULL);
	verify(nvlist_lookup_uint64(props, SES_PROP_ELEMENT_TYPE, &type) == 0);

	if (type != SES_ET_DEVICE && type != SES_ET_ARRAY_DEVICE &&
	    type != SES_ET_COOLING && type != SES_ET_POWER_SUPPLY) {
		ses_node_unlock(mod, tn);
		return (0);
	}

	/*
	 * Every element supports an 'ident' indicator.  All elements also
	 * support a 'fail' indicator, but the properties used to represent
	 * this condition differs between elements.
	 */
	if (ses_add_indicator(mod, tn, nodeid, TOPO_LED_TYPE_LOCATE, "ident",
	    SES_PROP_IDENT, NULL) != 0)
		goto error;

	switch (type) {
	case SES_ET_DEVICE:
	case SES_ET_ARRAY_DEVICE:
		/*
		 * Disks support an additional 'ok2rm' indicator, as well as
		 * externally detected 'fail' sensor.
		 */
		if (ses_add_indicator(mod, tn, nodeid, TOPO_LED_TYPE_SERVICE,
		    "fail", SES_DEV_PROP_FAULT_RQSTD,
		    SES_DEV_PROP_FAULT_SENSED) != 0 ||
		    ses_add_indicator(mod, tn, nodeid, TOPO_LED_TYPE_OK2RM,
		    "ok2rm", SES_PROP_RMV, SES_PROP_RMV) != 0 ||
		    ses_add_discrete(mod, tn, nodeid, "fault",
		    SES_DEV_PROP_FAULT_SENSED) != 0)
			goto error;
		break;

	case SES_ET_COOLING:
		/*
		 * Add the fan speed sensor, and a discrete sensor for
		 * detecting failure.
		 */
		sd.sd_type = TOPO_SENSOR_TYPE_THRESHOLD_STATE;
		sd.sd_units = TOPO_SENSOR_UNITS_RPM;
		sd.sd_propname = SES_COOLING_PROP_FAN_SPEED;
		if (ses_add_indicator(mod, tn, nodeid, TOPO_LED_TYPE_SERVICE,
		    "fail", SES_PROP_FAIL, NULL) != 0 ||
		    ses_add_sensor(mod, tn, nodeid, "speed", &sd) != 0 ||
		    ses_add_discrete(mod, tn, nodeid, "fault",
		    SES_PROP_FAIL) != 0)
			goto error;
		break;

	case SES_ET_POWER_SUPPLY:
		/*
		 * For power supplies, we have a number of different sensors:
		 * acfail, dcfail, overtemp, undervoltate, overvoltage,
		 * and overcurrent.  Rather than expose these all as individual
		 * sensors, we lump them together into a 'status' sensor of
		 * type TOPO_SENSOR_TYPE_POWER_SUPPLY and export the
		 * appropriate status flags as defined by the libtopo standard.
		 */
		if (ses_add_indicator(mod, tn, nodeid, TOPO_LED_TYPE_SERVICE,
		    "fail", SES_PROP_FAIL, NULL) != 0)
			goto error;

		if (ses_add_psu_status(mod, tn, nodeid) != 0)
			goto error;
		break;

	default:
		return (0);
	}

	ses_node_unlock(mod, tn);
	return (0);

error:
	ses_node_unlock(mod, tn);
	return (-1);
}

/*
 * Add enclosure-wide sensors (temperature, voltage, and current) beneath the
 * given aggregate.
 */
static int
ses_add_enclosure_sensors(topo_mod_t *mod, tnode_t *tn, ses_node_t *agg,
    uint64_t type)
{
	ses_node_t *child;
	const char *defaultname;
	char *desc, *name;
	char rawname[64];
	nvlist_t *props, *aprops;
	uint64_t index, nodeid;
	ses_sensor_desc_t sd = { 0 };
	size_t len;

	switch (type) {
	case SES_ET_TEMPERATURE_SENSOR:
		sd.sd_type = TOPO_SENSOR_TYPE_TEMP;
		sd.sd_units = TOPO_SENSOR_UNITS_DEGREES_C;
		sd.sd_propname = SES_TEMP_PROP_TEMP;
		defaultname = "temperature";
		break;

	case SES_ET_VOLTAGE_SENSOR:
		sd.sd_type = TOPO_SENSOR_TYPE_VOLTAGE;
		sd.sd_units = TOPO_SENSOR_UNITS_VOLTS;
		sd.sd_propname = SES_VS_PROP_VOLTAGE_MV;
		sd.sd_multiplier = 0.001;
		defaultname = "voltage";
		break;

	case SES_ET_CURRENT_SENSOR:
		sd.sd_type = TOPO_SENSOR_TYPE_CURRENT;
		sd.sd_units = TOPO_SENSOR_UNITS_AMPS;
		sd.sd_propname = SES_CS_PROP_CURRENT_MA;
		sd.sd_multiplier = 0.001;
		defaultname = "current";
		break;

	default:
		return (0);
	}

	aprops = ses_node_props(agg);

	for (child = ses_node_child(agg); child != NULL;
	    child = ses_node_sibling(child)) {
		/*
		 * The only tricky part here is getting the name for the
		 * sensor, where we follow the algorithm of the standard
		 * elements.
		 */
		props = ses_node_props(child);
		nodeid = ses_node_id(child);
		if (nvlist_lookup_uint64(props, SES_PROP_ELEMENT_CLASS_INDEX,
		    &index) != 0)
			continue;

		if (nvlist_lookup_string(props, SES_PROP_DESCRIPTION,
		    &desc) == 0 && desc[0] != '\0') {
			(void) strlcpy(rawname, desc, sizeof (rawname));
		} else {
			if (nvlist_lookup_string(aprops,
			    SES_PROP_CLASS_DESCRIPTION, &desc) != 0 ||
			    desc[0] == '\0')
				desc = (char *)defaultname;

			len = strlen(desc);
			while (len > 0 && desc[len - 1] == ' ')
				len--;

			(void) snprintf(rawname, sizeof (rawname),
			    "%.*s %llu", len, desc, index);
		}

		if ((name = disk_auth_clean(mod, rawname)) == NULL)
			return (-1);

		if (ses_add_sensor(mod, tn, nodeid, name, &sd) != 0) {
			topo_mod_strfree(mod, name);
			return (-1);
		}

		topo_mod_strfree(mod, name);
	}

	return (0);
}

/*ARGSUSED*/
int
ses_enc_enum_facility(topo_mod_t *mod, tnode_t *tn, topo_version_t vers,
    nvlist_t *in, nvlist_t **out)
{
	ses_node_t *np, *agg;
	nvlist_t *aprops;
	uint64_t type, nodeid;

	if ((np = ses_node_lock(mod, tn)) == NULL)
		return (-1);

	assert(ses_node_type(np) == SES_NODE_ENCLOSURE);
	nodeid = ses_node_id(np);

	/*
	 * 'ident' and 'fail' LEDs, and 'fault' sensor.
	 */
	if (ses_add_indicator(mod, tn, nodeid, TOPO_LED_TYPE_LOCATE, "ident",
	    SES_PROP_IDENT, NULL) != 0 ||
	    ses_add_indicator(mod, tn, nodeid, TOPO_LED_TYPE_SERVICE, "fail",
	    SES_PROP_FAIL_REQ, SES_PROP_FAIL) != 0 ||
	    ses_add_discrete(mod, tn, nodeid, "fault", SES_PROP_FAIL) != 0)
		goto error;

	/*
	 * Environmental sensors (temperature, voltage, current).  We have no
	 * way of knowing if any of these sensors correspond to a particular
	 * element, so we just attach them to the enclosure as a whole.  In the
	 * future, some vendor-specific libses plugin knowledge could let us
	 * make this correlation clearer.
	 */
	for (agg = ses_node_child(np); agg != NULL;
	    agg = ses_node_sibling(agg)) {
		if (ses_node_type(agg) != SES_NODE_AGGREGATE)
			continue;

		verify((aprops = ses_node_props(agg)) != NULL);
		if (nvlist_lookup_uint64(aprops, SES_PROP_ELEMENT_TYPE,
		    &type) != 0)
			continue;

		if (ses_add_enclosure_sensors(mod, tn, agg, type) != 0)
			goto error;
	}

	ses_node_unlock(mod, tn);
	return (0);

error:
	ses_node_unlock(mod, tn);
	return (-1);
}
