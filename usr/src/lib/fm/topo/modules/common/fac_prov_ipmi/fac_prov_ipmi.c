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
 * Copyright (c) 2018, Joyent, Inc.
 */
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <limits.h>
#include <alloca.h>
#include <errno.h>
#include <libnvpair.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/fm/protocol.h>
#include <fm/libtopo.h>
#include <fm/topo_mod.h>
#include <libipmi.h>

#define	BUFSZ	128

#define	BAY_PRESENT_LED_MASK	0x01

/*
 * The largest possible SDR ID length is 2^5+1
 */
#define	MAX_ID_LEN	33

#define	TOPO_METH_IPMI_PLATFORM_MESSAGE_VERSION	0
#define	TOPO_METH_IPMI_READING_VERSION		0
#define	TOPO_METH_IPMI_STATE_VERSION		0
#define	TOPO_METH_IPMI_MODE_VERSION		0
#define	TOPO_METH_X4500_MODE_VERSION		0
#define	TOPO_METH_BAY_LOCATE_VERSION		0
#define	TOPO_METH_BAY_MODE_VERSION		0
#define	TOPO_METH_CHASSIS_SERVICE_VERSION	0
#define	TOPO_METH_IPMI_ENTITY_VERSION		0
#define	TOPO_METH_DIMM_IPMI_ENTITY_VERSION	0
#define	TOPO_METH_CHASSIS_IDENT_VERSION		0

static int fac_prov_ipmi_enum(topo_mod_t *, tnode_t *, const char *,
    topo_instance_t, topo_instance_t, void *, void *);

/*
 * IPMI facility provider methods
 */
static int ipmi_sensor_enum(topo_mod_t *, tnode_t *, topo_version_t,
    nvlist_t *, nvlist_t **);
static int ipmi_entity(topo_mod_t *, tnode_t *, topo_version_t, nvlist_t *,
    nvlist_t **);
static int dimm_ipmi_entity(topo_mod_t *, tnode_t *, topo_version_t, nvlist_t *,
    nvlist_t **);
static int cs_ipmi_entity(topo_mod_t *, tnode_t *, topo_version_t, nvlist_t *,
    nvlist_t **);
static int ipmi_platform_message(topo_mod_t *, tnode_t *, topo_version_t,
    nvlist_t *, nvlist_t **);
static int ipmi_sensor_reading(topo_mod_t *, tnode_t *, topo_version_t,
    nvlist_t *, nvlist_t **);
static int ipmi_sensor_state(topo_mod_t *, tnode_t *, topo_version_t,
    nvlist_t *, nvlist_t **);
static int ipmi_indicator_mode(topo_mod_t *, tnode_t *, topo_version_t,
    nvlist_t *, nvlist_t **);
static int bay_locate_mode(topo_mod_t *, tnode_t *, topo_version_t,
    nvlist_t *, nvlist_t **);
static int x4500_present_mode(topo_mod_t *, tnode_t *, topo_version_t,
    nvlist_t *, nvlist_t **);
static int bay_indicator_mode(topo_mod_t *, tnode_t *, topo_version_t,
    nvlist_t *, nvlist_t **);
static int chassis_service_mode(topo_mod_t *, tnode_t *, topo_version_t,
    nvlist_t *, nvlist_t **);
static int chassis_ident_mode(topo_mod_t *, tnode_t *, topo_version_t,
    nvlist_t *, nvlist_t **);

const topo_modops_t ipmi_ops = { fac_prov_ipmi_enum, NULL };

const topo_modinfo_t ipmi_info =
	{ "IPMI facility provider", FM_FMRI_SCHEME_HC, TOPO_VERSION,
	&ipmi_ops };

static const topo_method_t ipmi_node_methods[] = {
	{ TOPO_METH_FAC_ENUM, TOPO_METH_FAC_ENUM_DESC, 0,
	    TOPO_STABILITY_INTERNAL, ipmi_sensor_enum },
	{ TOPO_METH_IPMI_ENTITY, TOPO_PROP_METH_DESC,
	    TOPO_METH_IPMI_ENTITY_VERSION,
	    TOPO_STABILITY_INTERNAL, ipmi_entity },
	{ "dimm_ipmi_entity", TOPO_PROP_METH_DESC,
	    TOPO_METH_DIMM_IPMI_ENTITY_VERSION,
	    TOPO_STABILITY_INTERNAL, dimm_ipmi_entity },
	{ "cs_ipmi_entity", TOPO_PROP_METH_DESC,
	    TOPO_METH_DIMM_IPMI_ENTITY_VERSION,
	    TOPO_STABILITY_INTERNAL, cs_ipmi_entity },
	{ TOPO_METH_SENSOR_FAILURE, TOPO_METH_SENSOR_FAILURE_DESC,
	    TOPO_METH_SENSOR_FAILURE_VERSION, TOPO_STABILITY_INTERNAL,
	    topo_method_sensor_failure },
	{ NULL }
};

static const topo_method_t ipmi_fac_methods[] = {
	{ "ipmi_platform_message", TOPO_PROP_METH_DESC,
	    TOPO_METH_IPMI_PLATFORM_MESSAGE_VERSION,
	    TOPO_STABILITY_INTERNAL, ipmi_platform_message },
	{ "ipmi_sensor_reading", TOPO_PROP_METH_DESC,
	    TOPO_METH_IPMI_READING_VERSION,
	    TOPO_STABILITY_INTERNAL, ipmi_sensor_reading },
	{ "ipmi_sensor_state", TOPO_PROP_METH_DESC,
	    TOPO_METH_IPMI_STATE_VERSION,
	    TOPO_STABILITY_INTERNAL, ipmi_sensor_state },
	{ "ipmi_indicator_mode", TOPO_PROP_METH_DESC,
	    TOPO_METH_IPMI_MODE_VERSION,
	    TOPO_STABILITY_INTERNAL, ipmi_indicator_mode },
	{ "bay_locate_mode", TOPO_PROP_METH_DESC,
	    TOPO_METH_BAY_LOCATE_VERSION,
	    TOPO_STABILITY_INTERNAL, bay_locate_mode },
	{ "bay_indicator_mode", TOPO_PROP_METH_DESC,
	    TOPO_METH_BAY_MODE_VERSION,
	    TOPO_STABILITY_INTERNAL, bay_indicator_mode },
	{ "chassis_service_mode", TOPO_PROP_METH_DESC,
	    TOPO_METH_CHASSIS_SERVICE_VERSION,
	    TOPO_STABILITY_INTERNAL, chassis_service_mode },
	{ "chassis_ident_mode", TOPO_PROP_METH_DESC,
	    TOPO_METH_CHASSIS_SERVICE_VERSION,
	    TOPO_STABILITY_INTERNAL, chassis_ident_mode },
	{ "x4500_present_mode", TOPO_PROP_METH_DESC,
	    TOPO_METH_CHASSIS_SERVICE_VERSION,
	    TOPO_STABILITY_INTERNAL, x4500_present_mode },
	{ TOPO_METH_IPMI_ENTITY, TOPO_PROP_METH_DESC,
	    TOPO_METH_IPMI_ENTITY_VERSION,
	    TOPO_STABILITY_INTERNAL, ipmi_entity },
	{ "dimm_ipmi_entity", TOPO_PROP_METH_DESC,
	    TOPO_METH_DIMM_IPMI_ENTITY_VERSION,
	    TOPO_STABILITY_INTERNAL, dimm_ipmi_entity },
	{ "cs_ipmi_entity", TOPO_PROP_METH_DESC,
	    TOPO_METH_DIMM_IPMI_ENTITY_VERSION,
	    TOPO_STABILITY_INTERNAL, dimm_ipmi_entity },
	{ NULL }
};

struct entity_info {
	uint32_t ei_id;
	uint32_t ei_inst;
	topo_mod_t *ei_mod;
	tnode_t *ei_node;
	char **ei_list;
	uint_t ei_listsz;
};

struct sensor_data {
	char sd_entity_ref[MAX_ID_LEN];
	uint8_t sd_units;
	uint32_t sd_stype;
	uint32_t sd_rtype;
	char *sd_class;
	ipmi_sdr_full_sensor_t *sd_fs_sdr;
};

/*ARGSUSED*/
int
_topo_init(topo_mod_t *mod, topo_version_t version)
{
	if (getenv("TOPOFACIPMIDEBUG") != NULL)
		topo_mod_setdebug(mod);

	return (topo_mod_register(mod, &ipmi_info, TOPO_VERSION));
}

void
_topo_fini(topo_mod_t *mod)
{
	topo_mod_unregister(mod);
}

static void
strarr_free(topo_mod_t *mod, char **arr, uint_t nelems)
{
	for (int i = 0; i < nelems; i++)
		topo_mod_strfree(mod, arr[i]);
	topo_mod_free(mod, arr, (nelems * sizeof (char *)));
}

/*
 * Some platforms (most notably G1/2N) use the 'platform event message' command
 * to manipulate disk fault LEDs over IPMI, but uses the standard sensor
 * reading to read the value.  This method implements this alternative
 * interface for these platforms.
 */
/*ARGSUSED*/
static int
ipmi_platform_message(topo_mod_t *mod, tnode_t *node, topo_version_t vers,
    nvlist_t *in, nvlist_t **out)
{
	char *entity_ref;
	ipmi_sdr_compact_sensor_t *csp;
	ipmi_handle_t *hdl;
	int err, ret;
	uint32_t mode;
	nvlist_t *pargs, *nvl;
	ipmi_platform_event_message_t pem;
	ipmi_sensor_reading_t *reading;

	if (vers > TOPO_METH_IPMI_PLATFORM_MESSAGE_VERSION)
		return (topo_mod_seterrno(mod, ETOPO_METHOD_VERNEW));

	/*
	 * Get an IPMI handle and then lookup the generic device locator sensor
	 * data record referenced by the entity_ref prop val
	 */
	if ((hdl = topo_mod_ipmi_hold(mod)) == NULL) {
		topo_mod_dprintf(mod, "Failed to get IPMI handle\n");
		return (-1);
	}

	if (topo_prop_get_string(node, TOPO_PGROUP_FACILITY, "entity_ref",
	    &entity_ref, &err) != 0) {
		topo_mod_dprintf(mod, "Failed to lookup entity_ref property "
		    "(%s)", topo_strerror(err));
		topo_mod_ipmi_rele(mod);
		return (-1);
	}

	if ((csp = ipmi_sdr_lookup_compact_sensor(hdl, entity_ref)) == NULL) {
		topo_mod_dprintf(mod, "Failed to lookup SDR for %s (%s)\n",
		    entity_ref, ipmi_errmsg(hdl));
		topo_mod_strfree(mod, entity_ref);
		topo_mod_ipmi_rele(mod);
		return (-1);
	}

	/*
	 * Now look for a private argument list to figure out whether we're
	 * doing a get or a set operation, and then do it.
	 */
	if ((nvlist_lookup_nvlist(in, TOPO_PROP_PARGS, &pargs) == 0) &&
	    nvlist_exists(pargs, TOPO_PROP_VAL_VAL)) {
		/*
		 * Set the LED mode
		 */
		if ((ret = nvlist_lookup_uint32(pargs, TOPO_PROP_VAL_VAL,
		    &mode)) != 0) {
			topo_mod_dprintf(mod, "Failed to lookup %s nvpair "
			    "(%s)\n", TOPO_PROP_VAL_VAL, strerror(ret));
			topo_mod_strfree(mod, entity_ref);
			(void) topo_mod_seterrno(mod, EMOD_NVL_INVAL);
			topo_mod_ipmi_rele(mod);
			return (-1);
		}

		if (mode != TOPO_LED_STATE_OFF &&
		    mode != TOPO_LED_STATE_ON) {
			topo_mod_dprintf(mod, "Invalid property value: %d\n",
			    mode);
			topo_mod_strfree(mod, entity_ref);
			(void) topo_mod_seterrno(mod, EMOD_NVL_INVAL);
			topo_mod_ipmi_rele(mod);
			return (-1);
		}

		pem.ipem_sensor_type = csp->is_cs_type;
		pem.ipem_sensor_num = csp->is_cs_number;
		pem.ipem_event_type = csp->is_cs_reading_type;

		/*
		 * The spec states that any values between 0x20 and 0x29 are
		 * legitimate for "system software".  However, some versions of
		 * Sun's ILOM rejects messages over /dev/ipmi0 with a generator
		 * of 0x20, so we use 0x21 instead.
		 */
		pem.ipem_generator = 0x21;
		pem.ipem_event_dir = 0;
		pem.ipem_rev = 0x04;
		if (mode == TOPO_LED_STATE_ON)
			pem.ipem_event_data[0] = 1;
		else
			pem.ipem_event_data[0] = 0;
		pem.ipem_event_data[1] = 0xff;
		pem.ipem_event_data[2] = 0xff;

		if (ipmi_event_platform_message(hdl, &pem) < 0) {
			topo_mod_dprintf(mod, "Failed to set LED mode for %s "
			    "(%s)\n", entity_ref, ipmi_errmsg(hdl));
			topo_mod_strfree(mod, entity_ref);
			topo_mod_ipmi_rele(mod);
			return (-1);
		}
	} else {
		/*
		 * Get the LED mode
		 */
		if ((reading = ipmi_get_sensor_reading(hdl, csp->is_cs_number))
		    == NULL) {
			topo_mod_dprintf(mod, "Failed to get sensor reading "
			    "for sensor %s: %s\n", entity_ref,
			    ipmi_errmsg(hdl));
			topo_mod_strfree(mod, entity_ref);
			topo_mod_ipmi_rele(mod);
			return (-1);
		}

		if (reading->isr_state &
		    TOPO_SENSOR_STATE_GENERIC_STATE_ASSERTED)
			mode = TOPO_LED_STATE_ON;
		else
			mode = TOPO_LED_STATE_OFF;
	}
	topo_mod_strfree(mod, entity_ref);

	topo_mod_ipmi_rele(mod);

	if (topo_mod_nvalloc(mod, &nvl, NV_UNIQUE_NAME) != 0 ||
	    nvlist_add_string(nvl, TOPO_PROP_VAL_NAME, TOPO_LED_MODE) != 0 ||
	    nvlist_add_uint32(nvl, TOPO_PROP_VAL_TYPE, TOPO_TYPE_UINT32) != 0 ||
	    nvlist_add_uint32(nvl, TOPO_PROP_VAL_VAL, mode) != 0) {
		topo_mod_dprintf(mod, "Failed to allocate 'out' nvlist\n");
		nvlist_free(nvl);
		return (topo_mod_seterrno(mod, EMOD_NOMEM));
	}
	*out = nvl;

	return (0);
}

/*ARGSUSED*/
static int
ipmi_sensor_state(topo_mod_t *mod, tnode_t *node, topo_version_t vers,
    nvlist_t *in, nvlist_t **out)
{
	char **entity_refs;
	uint_t nelems;
	ipmi_sdr_t *sdr = NULL;
	ipmi_sensor_reading_t *reading;
	ipmi_handle_t *hdl;
	int err, i;
	uint8_t sensor_num;
	uint32_t e_id, e_inst;
	ipmi_sdr_full_sensor_t *fsensor;
	ipmi_sdr_compact_sensor_t *csensor;
	nvlist_t *nvl;
	boolean_t found_sdr = B_FALSE;
	tnode_t *pnode;

	if (vers > TOPO_METH_IPMI_STATE_VERSION)
		return (topo_mod_seterrno(mod, ETOPO_METHOD_VERNEW));

	if (topo_prop_get_string_array(node, TOPO_PGROUP_FACILITY, "entity_ref",
	    &entity_refs, &nelems, &err) != 0) {
		topo_mod_dprintf(mod, "%s: Failed to lookup entity_ref "
		    "property (%s)", __func__, topo_strerror(err));
		return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
	}

	if ((hdl = topo_mod_ipmi_hold(mod)) == NULL) {
		topo_mod_dprintf(mod, "Failed to get IPMI handle\n");
		strarr_free(mod, entity_refs, nelems);
		return (-1);
	}

	pnode = topo_node_parent(node);
	if (topo_prop_get_uint32(pnode, TOPO_PGROUP_IPMI,
	    TOPO_PROP_IPMI_ENTITY_ID, &e_id, &err) != 0 ||
	    topo_prop_get_uint32(pnode, TOPO_PGROUP_IPMI,
	    TOPO_PROP_IPMI_ENTITY_INST, &e_inst, &err) != 0) {
		e_id = IPMI_ET_UNSPECIFIED;
		e_inst = 0;
	}

	for (i = 0; i < nelems; i++) {
		if ((sdr = ipmi_sdr_lookup_precise(hdl, entity_refs[i],
		    (uint8_t)e_id, (uint8_t)e_inst)) != NULL) {
			found_sdr = B_TRUE;
			break;
		} else
			topo_mod_dprintf(mod, "Failed to lookup SDR for %s "
			    "(%s)\n", entity_refs[i], ipmi_errmsg(hdl));
	}

	if (! found_sdr) {
		strarr_free(mod, entity_refs, nelems);
		topo_mod_ipmi_rele(mod);
		return (-1);
	}

	switch (sdr->is_type) {
		case IPMI_SDR_TYPE_FULL_SENSOR:
			fsensor = (ipmi_sdr_full_sensor_t *)sdr->is_record;
			sensor_num = fsensor->is_fs_number;
			break;
		case IPMI_SDR_TYPE_COMPACT_SENSOR:
			csensor = (ipmi_sdr_compact_sensor_t *)sdr->is_record;
			sensor_num = csensor->is_cs_number;
			break;
		default:
			topo_mod_dprintf(mod, "%s does not refer to a full or "
			    "compact SDR\n", entity_refs[i]);
			topo_mod_ipmi_rele(mod);
			strarr_free(mod, entity_refs, nelems);
			return (-1);
	}
	if ((reading = ipmi_get_sensor_reading(hdl, sensor_num))
	    == NULL) {
		topo_mod_dprintf(mod, "Failed to get sensor reading for sensor "
		    "%s, sensor_num=%d (%s)\n", entity_refs[i], sensor_num,
		    ipmi_errmsg(hdl));
		strarr_free(mod, entity_refs, nelems);
		topo_mod_ipmi_rele(mod);
		return (-1);
	}
	strarr_free(mod, entity_refs, nelems);
	topo_mod_ipmi_rele(mod);

	if (topo_mod_nvalloc(mod, &nvl, NV_UNIQUE_NAME) != 0 ||
	    nvlist_add_string(nvl, TOPO_PROP_VAL_NAME,
	    TOPO_SENSOR_STATE) != 0 ||
	    nvlist_add_uint32(nvl, TOPO_PROP_VAL_TYPE, TOPO_TYPE_UINT32) != 0 ||
	    nvlist_add_uint32(nvl, TOPO_PROP_VAL_VAL, reading->isr_state)
	    != 0) {
		topo_mod_dprintf(mod, "Failed to allocate 'out' nvlist\n");
		nvlist_free(nvl);
		return (topo_mod_seterrno(mod, EMOD_NOMEM));
	}
	*out = nvl;

	return (0);
}

/*ARGSUSED*/
static int
ipmi_sensor_reading(topo_mod_t *mod, tnode_t *node, topo_version_t vers,
    nvlist_t *in, nvlist_t **out)
{
	char **entity_refs, reading_str[BUFSZ];
	uint_t nelems;
	int err = 0, i;
	ipmi_sdr_t *sdr = NULL;
	ipmi_sdr_full_sensor_t *fsensor;
	ipmi_sensor_reading_t  *reading;
	double conv_reading;
	ipmi_handle_t *hdl;
	nvlist_t *nvl;
	boolean_t found_sdr = B_FALSE;
	uint8_t sensor_num;
	uint32_t e_id, e_inst;
	tnode_t *pnode;

	if (vers > TOPO_METH_IPMI_READING_VERSION)
		return (topo_mod_seterrno(mod, ETOPO_METHOD_VERNEW));

	if (topo_prop_get_string_array(node, TOPO_PGROUP_FACILITY, "entity_ref",
	    &entity_refs, &nelems, &err) != 0) {
		topo_mod_dprintf(mod, "Failed to lookup entity_ref property "
		    "(%s)", topo_strerror(err));
		return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
	}

	if ((hdl = topo_mod_ipmi_hold(mod)) == NULL) {
		topo_mod_dprintf(mod, "Failed to get IPMI handle\n");
		strarr_free(mod, entity_refs, nelems);
		return (-1);
	}

	pnode = topo_node_parent(node);
	if (topo_prop_get_uint32(pnode, TOPO_PGROUP_IPMI,
	    TOPO_PROP_IPMI_ENTITY_ID, &e_id, &err) != 0 ||
	    topo_prop_get_uint32(pnode, TOPO_PGROUP_IPMI,
	    TOPO_PROP_IPMI_ENTITY_INST, &e_inst, &err) != 0) {
		e_id = IPMI_ET_UNSPECIFIED;
		e_inst = 0;
	}

	for (i = 0; i < nelems; i++) {
		if ((sdr = ipmi_sdr_lookup_precise(hdl, entity_refs[i],
		    (uint8_t)e_id, (uint8_t)e_inst)) != NULL) {
			found_sdr = B_TRUE;
			break;
		} else
			topo_mod_dprintf(mod, "Failed to lookup SDR for %s "
			    "(%s)\n", entity_refs[i], ipmi_errmsg(hdl));
	}

	if (! found_sdr) {
		strarr_free(mod, entity_refs, nelems);
		topo_mod_ipmi_rele(mod);
		return (-1);
	}
	switch (sdr->is_type) {
		case IPMI_SDR_TYPE_FULL_SENSOR:
			fsensor = (ipmi_sdr_full_sensor_t *)sdr->is_record;
			sensor_num = fsensor->is_fs_number;
			break;
		default:
			topo_mod_dprintf(mod, "%s does not refer to a full "
			    "sensor SDR\n", entity_refs[i]);
			topo_mod_ipmi_rele(mod);
			strarr_free(mod, entity_refs, nelems);
			return (-1);
	}

	if ((reading = ipmi_get_sensor_reading(hdl, sensor_num)) == NULL) {
		topo_mod_dprintf(mod, "Failed to get sensor reading for sensor "
		    "%s, sensor_num=%d (%s)\n", entity_refs[i],
		    sensor_num, ipmi_errmsg(hdl));
		strarr_free(mod, entity_refs, nelems);
		topo_mod_ipmi_rele(mod);
		return (-1);
	}
	topo_mod_ipmi_rele(mod);

	if (ipmi_sdr_conv_reading(fsensor, reading->isr_reading, &conv_reading)
	    != 0) {
		topo_mod_dprintf(mod, "Failed to convert sensor reading for "
		    "sensor %s (%s)\n", entity_refs[i], ipmi_errmsg(hdl));
		strarr_free(mod, entity_refs, nelems);
		return (-1);
	}
	strarr_free(mod, entity_refs, nelems);

	(void) snprintf(reading_str, BUFSZ, "%f", conv_reading);
	if (topo_mod_nvalloc(mod, &nvl, NV_UNIQUE_NAME) != 0 ||
	    nvlist_add_string(nvl, TOPO_PROP_VAL_NAME,
	    TOPO_SENSOR_READING) != 0 ||
	    nvlist_add_uint32(nvl, TOPO_PROP_VAL_TYPE, TOPO_TYPE_DOUBLE) != 0 ||
	    nvlist_add_double(nvl, TOPO_PROP_VAL_VAL, conv_reading) != 0) {
		topo_mod_dprintf(mod, "Failed to allocate 'out' nvlist\n");
		nvlist_free(nvl);
		return (topo_mod_seterrno(mod, EMOD_NOMEM));
	}
	*out = nvl;

	return (0);
}

static int
ipmi_indicator_mode(topo_mod_t *mod, tnode_t *node, topo_version_t vers,
    nvlist_t *in, nvlist_t **out)
{
	char **entity_refs;
	uint_t nelems;
	ipmi_sdr_generic_locator_t *gdl = NULL;
	ipmi_handle_t *hdl;
	int err, ret, i;
	uint8_t ledmode;
	uint32_t mode_in;
	nvlist_t *pargs, *nvl;
	boolean_t found_sdr = B_FALSE;

	if (vers > TOPO_METH_IPMI_MODE_VERSION)
		return (topo_mod_seterrno(mod, ETOPO_METHOD_VERNEW));

	/*
	 * Get an IPMI handle and then lookup the generic device locator sensor
	 * data record referenced by the entity_ref prop val
	 */
	if ((hdl = topo_mod_ipmi_hold(mod)) == NULL) {
		topo_mod_dprintf(mod, "Failed to get IPMI handle\n");
		return (-1);
	}

	if (topo_prop_get_string_array(node, TOPO_PGROUP_FACILITY, "entity_ref",
	    &entity_refs, &nelems, &err) != 0) {
		topo_mod_dprintf(mod, "Failed to lookup entity_ref property "
		    "(%s)", topo_strerror(err));
		topo_mod_ipmi_rele(mod);
		return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
	}

	for (i = 0; i < nelems; i++) {
		if ((gdl = ipmi_sdr_lookup_generic(hdl, entity_refs[i]))
		    != NULL) {
			found_sdr = B_TRUE;
			break;
		} else
			topo_mod_dprintf(mod, "Failed to lookup SDR for %s "
			    "(%s)\n", entity_refs[i], ipmi_errmsg(hdl));
	}

	if (! found_sdr) {
		strarr_free(mod, entity_refs, nelems);
		topo_mod_ipmi_rele(mod);
		return (-1);
	}

	/*
	 * Now look for a private argument list to figure out whether we're
	 * doing a get or a set operation, and then do it.
	 */
	if ((nvlist_lookup_nvlist(in, TOPO_PROP_PARGS, &pargs) == 0) &&
	    nvlist_exists(pargs, TOPO_PROP_VAL_VAL)) {
		/*
		 * Set the LED mode
		 */
		if ((ret = nvlist_lookup_uint32(pargs, TOPO_PROP_VAL_VAL,
		    &mode_in)) != 0) {
			topo_mod_dprintf(mod, "Failed to lookup %s nvpair "
			    "(%s)\n", TOPO_PROP_VAL_VAL, strerror(ret));
			strarr_free(mod, entity_refs, nelems);
			topo_mod_ipmi_rele(mod);
			return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
		}
		if (mode_in != TOPO_LED_STATE_OFF &&
		    mode_in != TOPO_LED_STATE_ON) {
			topo_mod_dprintf(mod, "Invalid property value: %d\n",
			    mode_in);
			strarr_free(mod, entity_refs, nelems);
			topo_mod_ipmi_rele(mod);
			return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
		}
		ledmode = (uint8_t)mode_in;
		if (ipmi_sunoem_led_set(hdl, gdl, ledmode) < 0) {
			topo_mod_dprintf(mod, "%s: Failed to set LED mode for "
			    "%s (%s) to %s\n", __func__, entity_refs[i],
			    ipmi_errmsg(hdl), ledmode ? "ON" : "OFF");
			strarr_free(mod, entity_refs, nelems);
			topo_mod_ipmi_rele(mod);
			return (-1);
		}
	} else {
		/*
		 * Get the LED mode
		 */
		if (ipmi_sunoem_led_get(hdl, gdl, &ledmode) < 0) {
			topo_mod_dprintf(mod, "%s: Failed to get LED mode for "
			    "%s (%s)\n", __func__, entity_refs[i],
			    ipmi_errmsg(hdl));
			strarr_free(mod, entity_refs, nelems);
			topo_mod_ipmi_rele(mod);
			return (-1);
		}
	}
	strarr_free(mod, entity_refs, nelems);
	topo_mod_ipmi_rele(mod);

	if (topo_mod_nvalloc(mod, &nvl, NV_UNIQUE_NAME) != 0 ||
	    nvlist_add_string(nvl, TOPO_PROP_VAL_NAME, TOPO_LED_MODE) != 0 ||
	    nvlist_add_uint32(nvl, TOPO_PROP_VAL_TYPE, TOPO_TYPE_UINT32) != 0 ||
	    nvlist_add_uint32(nvl, TOPO_PROP_VAL_VAL, ledmode) != 0) {
		topo_mod_dprintf(mod, "Failed to allocate 'out' nvlist\n");
		nvlist_free(nvl);
		return (topo_mod_seterrno(mod, EMOD_NOMEM));
	}
	*out = nvl;

	return (0);
}

/*
 * On most Sun platforms there is no seperate locate LED for the drive bays.
 * This propmethod simulates a locate LED by blinking the ok2rm LED.
 *
 * LED control is through a the Sun OEM led/get commands.  This propmethod can
 * work on X4500/X4540 with ILOM 2.x and on
 * X4140/X4240/X4440/X4500/X4540/X4150/X4250 and X4450 platforms with ILOM 3.x.
 */
static int
bay_locate_mode(topo_mod_t *mod, tnode_t *node, topo_version_t vers,
    nvlist_t *in, nvlist_t **out)
{
	char **entity_refs;
	uint_t nelems;
	ipmi_sdr_generic_locator_t *gdl = NULL;
	ipmi_handle_t *hdl;
	int err, ret, i;
	uint8_t ledmode;
	uint32_t mode_in;
	nvlist_t *pargs, *nvl;
	boolean_t found_sdr = B_FALSE;

	if (vers > TOPO_METH_BAY_LOCATE_VERSION)
		return (topo_mod_seterrno(mod, ETOPO_METHOD_VERNEW));

	/*
	 * Get an IPMI handle and then lookup the generic device locator sensor
	 * data record referenced by the entity_ref prop val
	 */
	if ((hdl = topo_mod_ipmi_hold(mod)) == NULL) {
		topo_mod_dprintf(mod, "Failed to get IPMI handle\n");
		return (-1);
	}

	if (topo_prop_get_string_array(node, TOPO_PGROUP_FACILITY, "entity_ref",
	    &entity_refs, &nelems, &err) != 0) {
		topo_mod_dprintf(mod, "Failed to lookup entity_ref property "
		    "(%s)", topo_strerror(err));
		topo_mod_ipmi_rele(mod);
		return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
	}

	for (i = 0; i < nelems; i++) {
		if ((gdl = ipmi_sdr_lookup_generic(hdl, entity_refs[i]))
		    != NULL) {
			found_sdr = B_TRUE;
			break;
		} else
			topo_mod_dprintf(mod, "Failed to lookup SDR for %s "
			    "(%s)\n", entity_refs[i], ipmi_errmsg(hdl));
	}

	if (! found_sdr) {
		strarr_free(mod, entity_refs, nelems);
		topo_mod_ipmi_rele(mod);
		return (-1);
	}

	/*
	 * Now look for a private argument list to figure out whether we're
	 * doing a get or a set operation, and then do it.
	 */
	if ((nvlist_lookup_nvlist(in, TOPO_PROP_PARGS, &pargs) == 0) &&
	    nvlist_exists(pargs, TOPO_PROP_VAL_VAL)) {
		/*
		 * Set the LED mode
		 */
		if ((ret = nvlist_lookup_uint32(pargs, TOPO_PROP_VAL_VAL,
		    &mode_in)) != 0) {
			topo_mod_dprintf(mod, "Failed to lookup %s nvpair "
			    "(%s)\n", TOPO_PROP_VAL_VAL, strerror(ret));
			strarr_free(mod, entity_refs, nelems);
			topo_mod_ipmi_rele(mod);
			return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
		}
		if (mode_in != TOPO_LED_STATE_OFF &&
		    mode_in != TOPO_LED_STATE_ON) {
			topo_mod_dprintf(mod, "Invalid property value: %d\n",
			    mode_in);
			strarr_free(mod, entity_refs, nelems);
			topo_mod_ipmi_rele(mod);
			return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
		}
		if (mode_in == TOPO_LED_STATE_ON)
			ledmode = IPMI_SUNOEM_LED_MODE_FAST;
		else
			ledmode = IPMI_SUNOEM_LED_MODE_OFF;
		if (ipmi_sunoem_led_set(hdl, gdl, ledmode) < 0) {
			topo_mod_dprintf(mod, "Failed to set LED mode for %s "
			    "(%s)\n", entity_refs[i], ipmi_errmsg(hdl));
			strarr_free(mod, entity_refs, nelems);
			topo_mod_ipmi_rele(mod);
			return (-1);
		}
	} else {
		/*
		 * Get the LED mode
		 */
		if (ipmi_sunoem_led_get(hdl, gdl, &ledmode) < 0) {
			topo_mod_dprintf(mod, "Failed to get LED mode for %s "
			    "(%s)\n", entity_refs[i], ipmi_errmsg(hdl));
			strarr_free(mod, entity_refs, nelems);
			topo_mod_ipmi_rele(mod);
			return (-1);
		}
	}
	strarr_free(mod, entity_refs, nelems);
	topo_mod_ipmi_rele(mod);

	if (ledmode == IPMI_SUNOEM_LED_MODE_SLOW ||
	    ledmode == IPMI_SUNOEM_LED_MODE_FAST)
		ledmode = TOPO_LED_STATE_ON;
	else
		ledmode = TOPO_LED_STATE_OFF;

	if (topo_mod_nvalloc(mod, &nvl, NV_UNIQUE_NAME) != 0 ||
	    nvlist_add_string(nvl, TOPO_PROP_VAL_NAME, TOPO_LED_MODE) != 0 ||
	    nvlist_add_uint32(nvl, TOPO_PROP_VAL_TYPE, TOPO_TYPE_UINT32) != 0 ||
	    nvlist_add_uint32(nvl, TOPO_PROP_VAL_VAL, ledmode) != 0) {
		topo_mod_dprintf(mod, "Failed to allocate 'out' nvlist\n");
		nvlist_free(nvl);
		return (topo_mod_seterrno(mod, EMOD_NOMEM));
	}
	*out = nvl;

	return (0);
}

/*
 * This is a method for the "mode" property that is specific for the ok2rm and
 * service drive bay LED's on the X4500/X4540 platforms running ILOM 2.x and
 * for X4140/X4240/X4440/X4500/X4540/X4150/X4250 and X4450 platforms running
 * ILOM 3.x.
 *
 * For ILOM 2.x, the LED's are controlled by a Sun OEM led set command
 *
 * For ILOM 3.x platforms the LED's are controlled by sending a platform event
 * message for the appropriate DBP/HDD##/STATE compact SDR.
 *
 * For both ILOM 2 and ILOM 3, the current LED mode can be obtained by a
 * Sun OEM led get command.
 */
static int
bay_indicator_mode(topo_mod_t *mod, tnode_t *node, topo_version_t vers,
    nvlist_t *in, nvlist_t **out)
{
	char **entity_refs;
	uint_t nelems;
	ipmi_sdr_compact_sensor_t *cs = NULL;
	ipmi_sdr_generic_locator_t *gdl = NULL;
	ipmi_deviceid_t *sp_devid;
	ipmi_platform_event_message_t pem;
	ipmi_handle_t *hdl;
	int err, ret, i;
	uint32_t type, ledmode;
	uint8_t mode_in, ev_off;
	nvlist_t *pargs, *nvl;
	boolean_t found_sdr = B_FALSE;

	if (vers > TOPO_METH_BAY_MODE_VERSION)
		return (topo_mod_seterrno(mod, ETOPO_METHOD_VERNEW));

	if (topo_prop_get_uint32(node, TOPO_PGROUP_FACILITY, TOPO_FACILITY_TYPE,
	    &type, &err) != 0) {
		topo_mod_dprintf(mod, "Failed to lookup %s property "
		    "(%s)", TOPO_FACILITY_TYPE, topo_strerror(err));
		return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
	}
	switch (type) {
	case (TOPO_LED_TYPE_SERVICE):
		ev_off = 0x01;
		break;
	case (TOPO_LED_TYPE_OK2RM):
		ev_off = 0x03;
		break;
	default:
		topo_mod_dprintf(mod, "Invalid LED type: 0x%x\n", type);
		return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
	}

	if (topo_prop_get_string_array(node, TOPO_PGROUP_FACILITY, "entity_ref",
	    &entity_refs, &nelems, &err) != 0) {
		topo_mod_dprintf(mod, "Failed to lookup entity_ref property "
		    "(%s)", topo_strerror(err));
		return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
	}

	/*
	 * Figure out whether the SP is running ILOM 2.x or ILOM 3.x
	 */
	if ((hdl = topo_mod_ipmi_hold(mod)) == NULL) {
		topo_mod_dprintf(mod, "Failed to get IPMI handle\n");
		strarr_free(mod, entity_refs, nelems);
		return (-1);
	}

	if ((sp_devid = ipmi_get_deviceid(hdl)) == NULL) {
		topo_mod_dprintf(mod, "%s: GET DEVICEID command failed (%s)\n",
		    __func__, ipmi_errmsg(hdl));
		strarr_free(mod, entity_refs, nelems);
		topo_mod_ipmi_rele(mod);
		return (-1);
	}

	/*
	 * Now lookup the propmethod argument list and figure out whether we're
	 * doing a get or a set operation, and then do it.
	 */
	if ((nvlist_lookup_nvlist(in, TOPO_PROP_PARGS, &pargs) == 0) &&
	    nvlist_exists(pargs, TOPO_PROP_VAL_VAL)) {
		/*
		 * Set the LED mode
		 */
		if ((ret = nvlist_lookup_uint32(pargs, TOPO_PROP_VAL_VAL,
		    &ledmode)) != 0) {
			topo_mod_dprintf(mod, "Failed to lookup %s nvpair "
			    "(%s)\n", TOPO_PROP_VAL_VAL, strerror(ret));
			strarr_free(mod, entity_refs, nelems);
			topo_mod_ipmi_rele(mod);
			return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
		}

		topo_mod_dprintf(mod, "%s: Setting LED mode to %s\n", __func__,
		    ledmode ? "ON" : "OFF");

		if (sp_devid->id_firm_major == 2) {
			for (i = 0; i < nelems; i++) {
				if ((gdl = ipmi_sdr_lookup_generic(hdl,
				    entity_refs[i])) != NULL) {
					found_sdr = B_TRUE;
					break;
				} else
					topo_mod_dprintf(mod,
					    "Failed to lookup SDR for %s(%s)\n",
					    entity_refs[i], ipmi_errmsg(hdl));
			}

			if (! found_sdr) {
				strarr_free(mod, entity_refs, nelems);
				topo_mod_ipmi_rele(mod);
				return (-1);
			}

			if (ipmi_sunoem_led_set(hdl, gdl, (uint8_t)ledmode)
			    < 0) {
				topo_mod_dprintf(mod,
				    "Failed to set LED mode for %s (%s)\n",
				    entity_refs[i], ipmi_errmsg(hdl));
				strarr_free(mod, entity_refs, nelems);
				topo_mod_ipmi_rele(mod);
				return (-1);
			}
		} else {
			for (i = 0; i < nelems; i++) {
				if ((cs = ipmi_sdr_lookup_compact_sensor(hdl,
				    entity_refs[i])) != NULL) {
					found_sdr = B_TRUE;
					break;
				} else
					topo_mod_dprintf(mod,
					    "Failed to lookup SDR for %s(%s)\n",
					    entity_refs[i], ipmi_errmsg(hdl));
			}

			if (! found_sdr) {
				strarr_free(mod, entity_refs, nelems);
				topo_mod_ipmi_rele(mod);
				return (-1);
			}

			pem.ipem_generator = IPMI_SEL_SYSTEM;
			pem.ipem_rev = IPMI_EV_REV15;
			pem.ipem_sensor_type = IPMI_ST_BAY;
			pem.ipem_sensor_num = cs->is_cs_number;
			pem.ipem_event_type =  IPMI_RT_SPECIFIC;
			if (ledmode == TOPO_LED_STATE_ON)
				pem.ipem_event_dir = 0;
			else
				pem.ipem_event_dir = 1;

			pem.ipem_event_data[0] = ev_off;
			pem.ipem_event_data[1] = 0xff;
			pem.ipem_event_data[2] = 0xff;

			if (ipmi_event_platform_message(hdl, &pem) != 0) {
				topo_mod_dprintf(mod, "%s: Failed to send "
				    "platform event mesg for %s (%s)\n",
				    __func__, entity_refs[i], ipmi_errmsg(hdl));
				strarr_free(mod, entity_refs, nelems);
				topo_mod_ipmi_rele(mod);
				return (-1);
			}
		}
	} else {
		/*
		 * Get the LED mode
		 */
		for (i = 0; i < nelems; i++) {
			if ((gdl = ipmi_sdr_lookup_generic(hdl, entity_refs[i]))
			    != NULL) {
				found_sdr = B_TRUE;
				break;
			} else
				topo_mod_dprintf(mod, "%s: Failed to lookup "
				    "SDR for %s (%s)\n", __func__,
				    entity_refs[i], ipmi_errmsg(hdl));
		}

		if (! found_sdr) {
			strarr_free(mod, entity_refs, nelems);
			topo_mod_ipmi_rele(mod);
			return (-1);
		}
		if (ipmi_sunoem_led_get(hdl, gdl, &mode_in) < 0) {
			topo_mod_dprintf(mod, "%s: Failed to get LED mode for "
			    "%s (%s)\n", __func__, entity_refs[i],
			    ipmi_errmsg(hdl));
			strarr_free(mod, entity_refs, nelems);
			topo_mod_ipmi_rele(mod);
			return (-1);
		}
		ledmode = mode_in;
	}
	strarr_free(mod, entity_refs, nelems);
	topo_mod_ipmi_rele(mod);

	if (topo_mod_nvalloc(mod, &nvl, NV_UNIQUE_NAME) != 0 ||
	    nvlist_add_string(nvl, TOPO_PROP_VAL_NAME, TOPO_LED_MODE) != 0 ||
	    nvlist_add_uint32(nvl, TOPO_PROP_VAL_TYPE, TOPO_TYPE_UINT32) != 0 ||
	    nvlist_add_uint32(nvl, TOPO_PROP_VAL_VAL, ledmode) != 0) {
		topo_mod_dprintf(mod, "Failed to allocate 'out' nvlist\n");
		nvlist_free(nvl);
		return (topo_mod_seterrno(mod, EMOD_NOMEM));
	}
	*out = nvl;
	return (0);
}

/*
 * This propmethod is for controlling the present LED on the drive bays for
 * the X4500 platform.
 */
static int
x4500_present_mode(topo_mod_t *mod, tnode_t *node, topo_version_t vers,
    nvlist_t *in, nvlist_t **out)
{
	char **entity_refs;
	uint_t nelems;
	ipmi_sdr_compact_sensor_t *cs = NULL;
	ipmi_set_sensor_reading_t sr_out = { 0 };
	ipmi_handle_t *hdl;
	int err, ret, i;
	uint32_t ledmode;
	nvlist_t *pargs, *nvl;
	boolean_t found_sdr = B_FALSE;

	if (vers > TOPO_METH_X4500_MODE_VERSION)
		return (topo_mod_seterrno(mod, ETOPO_METHOD_VERNEW));

	if (topo_prop_get_string_array(node, TOPO_PGROUP_FACILITY, "entity_ref",
	    &entity_refs, &nelems, &err) != 0) {
		topo_mod_dprintf(mod, "Failed to lookup entity_ref property "
		    "(%s)", topo_strerror(err));
		return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
	}

	if ((hdl = topo_mod_ipmi_hold(mod)) == NULL) {
		topo_mod_dprintf(mod, "Failed to get IPMI handle\n");
		strarr_free(mod, entity_refs, nelems);
		return (-1);
	}
	for (i = 0; i < nelems; i++) {
		if ((cs = ipmi_sdr_lookup_compact_sensor(hdl, entity_refs[i]))
		    != NULL) {
			found_sdr = B_TRUE;
			break;
		} else
			topo_mod_dprintf(mod, "Failed to lookup SDR for %s "
			    "(%s)\n", entity_refs[i],
			    ipmi_errmsg(hdl));
	}

	if (! found_sdr) {
		strarr_free(mod, entity_refs, nelems);
		topo_mod_ipmi_rele(mod);
		return (-1);
	}

	/*
	 * Now lookup the propmethod argument list and figure out whether we're
	 * doing a get or a set operation, and then do it.
	 */
	if ((nvlist_lookup_nvlist(in, TOPO_PROP_PARGS, &pargs) == 0) &&
	    nvlist_exists(pargs, TOPO_PROP_VAL_VAL)) {
		/*
		 * Set the LED mode
		 */
		if ((ret = nvlist_lookup_uint32(pargs, TOPO_PROP_VAL_VAL,
		    &ledmode)) != 0) {
			topo_mod_dprintf(mod, "Failed to lookup %s nvpair "
			    "(%s)\n", TOPO_PROP_VAL_VAL, strerror(ret));
			strarr_free(mod, entity_refs, nelems);
			topo_mod_ipmi_rele(mod);
			return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
		}

		topo_mod_dprintf(mod, "%s: Setting LED mode to %s\n", __func__,
		    ledmode ? "ON" : "OFF");

		if (ledmode == TOPO_LED_STATE_OFF) {
			sr_out.iss_deassert_state = BAY_PRESENT_LED_MASK;
			sr_out.iss_deassrt_op = IPMI_SENSOR_OP_SET;
		} else if (ledmode == TOPO_LED_STATE_ON) {
			sr_out.iss_assert_state = BAY_PRESENT_LED_MASK;
			sr_out.iss_assert_op = IPMI_SENSOR_OP_SET;
		} else {
			topo_mod_dprintf(mod, "%s: Invalid LED mode: "
			    "%d\n", __func__, ledmode);
			strarr_free(mod, entity_refs, nelems);
			topo_mod_ipmi_rele(mod);
			return (-1);
		}
		sr_out.iss_id = cs->is_cs_number;
		topo_mod_dprintf(mod, "Setting LED mode (mask=0x%x)\n",
		    BAY_PRESENT_LED_MASK);
		if (ipmi_set_sensor_reading(hdl, &sr_out) != 0) {
			topo_mod_dprintf(mod, "%s: Failed to set "
			    "sensor reading for %s (%s)\n", __func__,
			    entity_refs[i], ipmi_errmsg(hdl));
			strarr_free(mod, entity_refs, nelems);
			topo_mod_ipmi_rele(mod);
			return (-1);
		}
	} else {
		/*
		 * Get the LED mode
		 */
		ipmi_sensor_reading_t *sr_in;

		topo_mod_dprintf(mod, "Getting LED mode\n");
		if ((sr_in = ipmi_get_sensor_reading(hdl, cs->is_cs_number))
		    == NULL) {
			topo_mod_dprintf(mod, "Failed to get sensor reading "
			    "for sensor %s (sensor num: %d) (error: %s)\n",
			    entity_refs[i], cs->is_cs_number, ipmi_errmsg(hdl));
			strarr_free(mod, entity_refs, nelems);
			topo_mod_ipmi_rele(mod);
			return (-1);
		}
		if (sr_in->isr_state & (uint16_t)BAY_PRESENT_LED_MASK)
			ledmode = TOPO_LED_STATE_ON;
		else
			ledmode = TOPO_LED_STATE_OFF;
	}
	strarr_free(mod, entity_refs, nelems);
	topo_mod_ipmi_rele(mod);

	if (topo_mod_nvalloc(mod, &nvl, NV_UNIQUE_NAME) != 0 ||
	    nvlist_add_string(nvl, TOPO_PROP_VAL_NAME, TOPO_LED_MODE) != 0 ||
	    nvlist_add_uint32(nvl, TOPO_PROP_VAL_TYPE, TOPO_TYPE_UINT32) != 0 ||
	    nvlist_add_uint32(nvl, TOPO_PROP_VAL_VAL, ledmode) != 0) {
		topo_mod_dprintf(mod, "Failed to allocate 'out' nvlist\n");
		nvlist_free(nvl);
		return (topo_mod_seterrno(mod, EMOD_NOMEM));
	}
	*out = nvl;
	return (0);
}

/*
 * This is a property method for controlling the chassis service LED on
 * ILOM 3.x based platforms.
 */
static int
chassis_service_mode(topo_mod_t *mod, tnode_t *node, topo_version_t vers,
    nvlist_t *in, nvlist_t **out)
{
	char **entity_refs;
	uint_t nelems;
	ipmi_sdr_generic_locator_t *gdl = NULL;
	ipmi_deviceid_t *sp_devid;
	ipmi_platform_event_message_t pem;
	ipmi_handle_t *hdl;
	int err, ret, i;
	uint8_t ledmode;
	uint32_t mode_in;
	nvlist_t *pargs, *nvl;
	boolean_t found_sdr = B_FALSE;

	if (vers > TOPO_METH_CHASSIS_SERVICE_VERSION)
		return (topo_mod_seterrno(mod, ETOPO_METHOD_VERNEW));

	/*
	 * Get an IPMI handle and then lookup the generic device locator record
	 * referenced by the entity_ref prop val
	 */
	if ((hdl = topo_mod_ipmi_hold(mod)) == NULL) {
		topo_mod_dprintf(mod, "Failed to get IPMI handle\n");
		return (-1);
	}

	if (topo_prop_get_string_array(node, TOPO_PGROUP_FACILITY, "entity_ref",
	    &entity_refs, &nelems, &err) != 0) {
		topo_mod_dprintf(mod, "Failed to lookup entity_ref property "
		    "(%s)", topo_strerror(err));
		topo_mod_ipmi_rele(mod);
		return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
	}

	for (i = 0; i < nelems; i++) {
		if ((gdl = ipmi_sdr_lookup_generic(hdl, entity_refs[i]))
		    != NULL) {
			found_sdr = B_TRUE;
			break;
		} else
			topo_mod_dprintf(mod, "Failed to lookup SDR for %s "
			    "(%s)\n", entity_refs[i], ipmi_errmsg(hdl));
	}

	if (! found_sdr) {
		strarr_free(mod, entity_refs, nelems);
		topo_mod_ipmi_rele(mod);
		return (-1);
	}

	/*
	 * Now lookup the propmethod argument list and figure out whether we're
	 * doing a get or a set operation, and then do it.
	 */
	if ((nvlist_lookup_nvlist(in, TOPO_PROP_PARGS, &pargs) == 0) &&
	    nvlist_exists(pargs, TOPO_PROP_VAL_VAL)) {
		/*
		 * Set the LED mode
		 */
		if ((ret = nvlist_lookup_uint32(pargs, TOPO_PROP_VAL_VAL,
		    &mode_in)) != 0) {
			topo_mod_dprintf(mod, "Failed to lookup %s nvpair "
			    "(%s)\n", TOPO_PROP_VAL_VAL, strerror(ret));
			strarr_free(mod, entity_refs, nelems);
			topo_mod_ipmi_rele(mod);
			return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
		}

		/*
		 * Determine which IPMI mechanism to use to set the LED mode
		 * based on whether the SP is running ILOM 2 or later.
		 */
		if ((sp_devid = ipmi_get_deviceid(hdl)) == NULL) {
			topo_mod_dprintf(mod, "%s: GET DEVICEID command failed "
			"(%s)\n", __func__, ipmi_errmsg(hdl));
			strarr_free(mod, entity_refs, nelems);
			topo_mod_ipmi_rele(mod);
			return (-1);
		}

		topo_mod_dprintf(mod, "%s: Setting LED mode to %s\n", __func__,
		    mode_in ? "ON" : "OFF");

		if (sp_devid->id_firm_major == 2) {
			if (mode_in != TOPO_LED_STATE_OFF &&
			    mode_in != TOPO_LED_STATE_ON) {
				topo_mod_dprintf(mod, "Invalid property value: "
				    "%d\n", mode_in);
				strarr_free(mod, entity_refs, nelems);
				topo_mod_ipmi_rele(mod);
				return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
			}
			if (ipmi_sunoem_led_set(hdl, gdl, (uint8_t)mode_in)
			    < 0) {
				topo_mod_dprintf(mod, "Failed to set LED mode "
				    "for %s (%s)\n", entity_refs[i],
				    ipmi_errmsg(hdl));
				strarr_free(mod, entity_refs, nelems);
				topo_mod_ipmi_rele(mod);
				return (-1);
			}
		} else {
			pem.ipem_generator = IPMI_SEL_SYSTEM;
			pem.ipem_rev = IPMI_EV_REV15;
			pem.ipem_sensor_type = IPMI_ST_SYSTEM;
			pem.ipem_sensor_num = 0x00;
			pem.ipem_event_type =  IPMI_RT_SPECIFIC;
			if (mode_in == TOPO_LED_STATE_ON)
				pem.ipem_event_dir = 0;
			else
				pem.ipem_event_dir = 1;

			pem.ipem_event_data[0] = 0x02;
			pem.ipem_event_data[1] = 0xff;
			pem.ipem_event_data[2] = 0xff;

			topo_mod_dprintf(mod, "Sending platform event\n");
			if (ipmi_event_platform_message(hdl, &pem) != 0) {
				topo_mod_dprintf(mod, "%s: Failed to send "
				    "platform event mesg for sensor 0 (%s)\n",
				    __func__, ipmi_errmsg(hdl));
				strarr_free(mod, entity_refs, nelems);
				topo_mod_ipmi_rele(mod);
				return (-1);
			}
		}
	} else {
		/*
		 * Get the LED mode
		 */
		if (ipmi_sunoem_led_get(hdl, gdl, &ledmode) < 0) {
			topo_mod_dprintf(mod, "%s: Failed to get LED mode for "
			    "%s (%s)\n", __func__, entity_refs[i],
			    ipmi_errmsg(hdl));
			strarr_free(mod, entity_refs, nelems);
			topo_mod_ipmi_rele(mod);
			return (-1);
		}
	}
	strarr_free(mod, entity_refs, nelems);
	topo_mod_ipmi_rele(mod);

	if (topo_mod_nvalloc(mod, &nvl, NV_UNIQUE_NAME) != 0 ||
	    nvlist_add_string(nvl, TOPO_PROP_VAL_NAME, TOPO_LED_MODE) != 0 ||
	    nvlist_add_uint32(nvl, TOPO_PROP_VAL_TYPE, TOPO_TYPE_UINT32) != 0 ||
	    nvlist_add_uint32(nvl, TOPO_PROP_VAL_VAL, ledmode) != 0) {
		topo_mod_dprintf(mod, "Failed to allocate 'out' nvlist\n");
		nvlist_free(nvl);
		return (topo_mod_seterrno(mod, EMOD_NOMEM));
	}
	*out = nvl;
	return (0);
}

/*
 * This is a property method for controlling the chassis identify LED using
 * generic IPMI mechanisms.
 */
/*ARGSUSED*/
static int
chassis_ident_mode(topo_mod_t *mod, tnode_t *node, topo_version_t vers,
    nvlist_t *in, nvlist_t **out)
{
	ipmi_handle_t *hdl;
	int ret;
	uint32_t modeval;
	boolean_t assert_ident;
	nvlist_t *pargs, *nvl;
	ipmi_chassis_status_t *chs;

	if (vers > TOPO_METH_CHASSIS_IDENT_VERSION)
		return (topo_mod_seterrno(mod, ETOPO_METHOD_VERNEW));

	if ((hdl = topo_mod_ipmi_hold(mod)) == NULL) {
		topo_mod_dprintf(mod, "Failed to get IPMI handle\n");
		return (-1);
	}

	/*
	 * Now lookup the propmethod argument list and figure out whether we're
	 * doing a get or a set operation, and then do it.
	 */
	if ((nvlist_lookup_nvlist(in, TOPO_PROP_PARGS, &pargs) == 0) &&
	    nvlist_exists(pargs, TOPO_PROP_VAL_VAL)) {
		/*
		 * Set the LED mode
		 */
		if ((ret = nvlist_lookup_uint32(pargs, TOPO_PROP_VAL_VAL,
		    &modeval)) != 0) {
			topo_mod_dprintf(mod, "Failed to lookup %s nvpair "
			    "(%s)\n", TOPO_PROP_VAL_VAL, strerror(ret));
			topo_mod_ipmi_rele(mod);
			return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
		}

		assert_ident = modeval ? B_TRUE : B_FALSE;
		topo_mod_dprintf(mod, "%s: Setting LED mode to %s\n", __func__,
		    assert_ident ? "ON" : "OFF");
		if (ipmi_chassis_identify(hdl, assert_ident) != 0) {
			topo_mod_ipmi_rele(mod);
			return (topo_mod_seterrno(mod, EMOD_UNKNOWN));
		}

	} else {
		/*
		 * Get the LED mode
		 */
		if ((chs = ipmi_chassis_status(hdl)) == NULL ||
		    !chs->ichs_identify_supported) {
			free(chs);
			topo_mod_ipmi_rele(mod);
			return (topo_mod_seterrno(mod, EMOD_UNKNOWN));
		}
		/*
		 * ichs_identify_state is a 2-bit value with the following
		 * semantics:
		 * 0 - ident is off
		 * 1 - ident is temporarily on
		 * 2 - ident is indefinitely on
		 * 3 - reserved
		 */
		switch (chs->ichs_identify_state) {
		case 0:
			modeval = TOPO_LED_STATE_OFF;
			break;
		case 1:
		case 2:
			modeval = TOPO_LED_STATE_ON;
			break;
		default:
			free(chs);
			topo_mod_ipmi_rele(mod);
			return (topo_mod_seterrno(mod, EMOD_UNKNOWN));
		}
		free(chs);
	}
	topo_mod_ipmi_rele(mod);

	if (topo_mod_nvalloc(mod, &nvl, NV_UNIQUE_NAME) != 0 ||
	    nvlist_add_string(nvl, TOPO_PROP_VAL_NAME, TOPO_LED_MODE) != 0 ||
	    nvlist_add_uint32(nvl, TOPO_PROP_VAL_TYPE, TOPO_TYPE_UINT32) != 0 ||
	    nvlist_add_uint32(nvl, TOPO_PROP_VAL_VAL, modeval) != 0) {
		topo_mod_dprintf(mod, "Failed to allocate 'out' nvlist\n");
		nvlist_free(nvl);
		return (topo_mod_seterrno(mod, EMOD_NOMEM));
	}
	*out = nvl;
	return (0);
}

#define	ISBITSET(MASK, BIT)	((MASK & BIT) == BIT)

struct sensor_thresh {
	uint8_t	sthr_threshbit;
	const char *sthr_propname;
	uint8_t sthr_threshoff;
};

static const struct sensor_thresh threshset[] = {
	{ IPMI_SENSOR_THRESHOLD_LOWER_NONCRIT, TOPO_PROP_THRESHOLD_LNC,
	    offsetof(ipmi_sensor_thresholds_t, ithr_lower_noncrit) },
	{ IPMI_SENSOR_THRESHOLD_LOWER_CRIT, TOPO_PROP_THRESHOLD_LCR,
	    offsetof(ipmi_sensor_thresholds_t, ithr_lower_crit) },
	{ IPMI_SENSOR_THRESHOLD_LOWER_NONRECOV, TOPO_PROP_THRESHOLD_LNR,
	    offsetof(ipmi_sensor_thresholds_t, ithr_lower_nonrec) },
	{ IPMI_SENSOR_THRESHOLD_UPPER_NONCRIT, TOPO_PROP_THRESHOLD_UNC,
	    offsetof(ipmi_sensor_thresholds_t, ithr_upper_noncrit) },
	{ IPMI_SENSOR_THRESHOLD_UPPER_CRIT, TOPO_PROP_THRESHOLD_UCR,
	    offsetof(ipmi_sensor_thresholds_t, ithr_upper_crit) },
	{ IPMI_SENSOR_THRESHOLD_UPPER_NONRECOV, TOPO_PROP_THRESHOLD_UNR,
	    offsetof(ipmi_sensor_thresholds_t, ithr_upper_nonrec) }
};

static uint_t num_thresholds =
    sizeof (threshset) / sizeof (struct sensor_thresh);

static int
set_thresh_prop(topo_mod_t *mod, tnode_t *fnode, ipmi_sdr_full_sensor_t *fs,
    uint8_t raw_thresh, const struct sensor_thresh *thresh)
{
	int err;
	double conv_thresh;

	if (ipmi_sdr_conv_reading(fs, raw_thresh, &conv_thresh) != 0) {
		topo_mod_dprintf(mod, "Failed to convert threshold %s on node "
		    "%s", thresh->sthr_propname, topo_node_name(fnode));
		return (topo_mod_seterrno(mod, EMOD_PARTIAL_ENUM));
	}
	if (topo_prop_set_double(fnode, TOPO_PGROUP_FACILITY,
	    thresh->sthr_propname, TOPO_PROP_IMMUTABLE, conv_thresh, &err) !=
	    0) {
		topo_mod_dprintf(mod, "Failed to set property %s on node %s "
		    "(%s)", thresh->sthr_propname, topo_node_name(fnode),
		    topo_strerror(err));
		return (topo_mod_seterrno(mod, err));
	}
	return (0);
}

static int
make_sensor_node(topo_mod_t *mod, tnode_t *pnode, struct sensor_data *sd,
    ipmi_handle_t *hdl)
{
	int err, ret, i;
	tnode_t *fnode;
	char *ftype = "sensor", facname[MAX_ID_LEN], **entity_refs;
	topo_pgroup_info_t pgi;
	nvlist_t *arg_nvl = NULL;
	ipmi_sensor_thresholds_t thresh = { 0 };
	uint8_t mask;

	/*
	 * Some platforms have '/' characters in the IPMI entity name, but '/'
	 * has a special meaning for FMRI's so we change them to '.' before
	 * binding the node into the topology.
	 */
	(void) strcpy(facname, sd->sd_entity_ref);
	for (i = 0; facname[i]; i++)
		if (facname[i] == '/')
			facname[i] = '.';

	if ((fnode = topo_node_facbind(mod, pnode, facname, ftype)) == NULL) {
		topo_mod_dprintf(mod, "Failed to bind facility node: %s\n",
		    facname);
		/* errno set */
		return (-1);
	}

	pgi.tpi_name = TOPO_PGROUP_FACILITY;
	pgi.tpi_namestab = TOPO_STABILITY_PRIVATE;
	pgi.tpi_datastab = TOPO_STABILITY_PRIVATE;
	pgi.tpi_version = 1;
	if (topo_pgroup_create(fnode, &pgi, &err) != 0) {
		if (err != ETOPO_PROP_DEFD) {
			topo_mod_dprintf(mod,  "pgroups create failure: %s\n",
			    topo_strerror(err));
			topo_node_unbind(fnode);
			return (topo_mod_seterrno(mod, err));
		}
	}
	if (topo_method_register(mod, fnode, ipmi_fac_methods) < 0) {
		topo_mod_dprintf(mod, "make_fac_node: "
		    "failed to register facility methods");
		topo_node_unbind(fnode);
		/* errno set */
		return (-1);
	}
	/*
	 * For both threshold and discrete sensors we set up a propmethod for
	 * getting the sensor state and properties to hold the entity ref,
	 * sensor class and sensor type.
	 */
	if ((entity_refs = topo_mod_alloc(mod, sizeof (char *))) == NULL)
		return (topo_mod_seterrno(mod, EMOD_NOMEM));

	entity_refs[0] = topo_mod_strdup(mod, sd->sd_entity_ref);

	if (topo_prop_set_string_array(fnode, TOPO_PGROUP_FACILITY,
	    "entity_ref", TOPO_PROP_IMMUTABLE, (const char **)entity_refs, 1,
	    &err) != 0) {
		topo_mod_dprintf(mod, "%s: Failed to set entity_ref property "
		    "on node: %s=%d (%s)\n", __func__, topo_node_name(fnode),
		    topo_node_instance(fnode), topo_strerror(err));
		strarr_free(mod, entity_refs, 1);
		return (topo_mod_seterrno(mod, err));
	}
	strarr_free(mod, entity_refs, 1);

	if (topo_prop_set_string(fnode, TOPO_PGROUP_FACILITY, TOPO_SENSOR_CLASS,
	    TOPO_PROP_IMMUTABLE, sd->sd_class, &err) != 0) {
		topo_mod_dprintf(mod, "Failed to set %s property on node: "
		    "%s=%d (%s)\n", TOPO_SENSOR_CLASS, topo_node_name(fnode),
		    topo_node_instance(fnode), topo_strerror(err));
		return (topo_mod_seterrno(mod, err));
	}
	if (topo_prop_set_uint32(fnode, TOPO_PGROUP_FACILITY,
	    TOPO_FACILITY_TYPE, TOPO_PROP_IMMUTABLE, sd->sd_stype, &err) != 0) {
		topo_mod_dprintf(mod, "Failed to set %s property on node: "
		    "%s=%d (%s)\n", TOPO_FACILITY_TYPE, topo_node_name(fnode),
		    topo_node_instance(fnode), topo_strerror(err));
		return (topo_mod_seterrno(mod, err));
	}
	if (topo_mod_nvalloc(mod, &arg_nvl, NV_UNIQUE_NAME) < 0) {
		topo_node_unbind(fnode);
		return (topo_mod_seterrno(mod, EMOD_NOMEM));
	}

	if ((ret = nvlist_add_string(arg_nvl, "ipmi_entity", sd->sd_entity_ref))
	    != 0) {
		topo_mod_dprintf(mod, "Failed build arg nvlist (%s)\n",
		    strerror(ret));
		nvlist_free(arg_nvl);
		return (topo_mod_seterrno(mod, EMOD_NOMEM));
	}

	if (topo_prop_method_register(fnode, TOPO_PGROUP_FACILITY,
	    TOPO_SENSOR_STATE, TOPO_TYPE_UINT32, "ipmi_sensor_state", arg_nvl,
	    &err) != 0) {
		topo_mod_dprintf(mod, "Failed to register %s propmeth on fac "
		    "node %s (%s)\n", TOPO_SENSOR_STATE, topo_node_name(fnode),
		    topo_strerror(err));
		nvlist_free(arg_nvl);
		return (topo_mod_seterrno(mod, err));
	}

	/*
	 * If it's a discrete sensor then we're done.  For threshold sensors,
	 * there are additional properties to set up.
	 */
	if (strcmp(sd->sd_class, TOPO_SENSOR_CLASS_THRESHOLD) != 0) {
		nvlist_free(arg_nvl);
		return (0);
	}

	/*
	 * Create properties to expose the analog sensor reading, the unit
	 * type and the upper and lower thresholds, if available.
	 */
	if (topo_prop_method_register(fnode, TOPO_PGROUP_FACILITY,
	    TOPO_SENSOR_READING, TOPO_TYPE_DOUBLE, "ipmi_sensor_reading",
	    arg_nvl, &err) != 0) {
		topo_mod_dprintf(mod, "Failed to register %s propmeth on fac "
		    "node %s (%s)\n", TOPO_SENSOR_READING,
		    topo_node_name(fnode), topo_strerror(err));
		nvlist_free(arg_nvl);
		return (topo_mod_seterrno(mod, err));
	}
	if (topo_prop_set_uint32(fnode, TOPO_PGROUP_FACILITY,
	    TOPO_SENSOR_UNITS, TOPO_PROP_IMMUTABLE, sd->sd_units, &err) != 0) {
		topo_mod_dprintf(mod, "Failed to set units property on node "
		    "%s (%s)\n", topo_node_name(fnode), topo_strerror(err));
		nvlist_free(arg_nvl);
		return (topo_mod_seterrno(mod, err));
	}
	nvlist_free(arg_nvl);

	/*
	 * It is possible (though unusual) for a compact sensor record to
	 * represent a threshold sensor.  However, due to how
	 * ipmi_sdr_conv_reading() is currently implemented, we only support
	 * gathering threshold readings on sensors enumerated from Full Sensor
	 * Records.
	 */
	if (sd->sd_fs_sdr == NULL)
		return (0);

	if (ipmi_get_sensor_thresholds(hdl, &thresh,
	    sd->sd_fs_sdr->is_fs_number) != 0) {
		topo_mod_dprintf(mod, "Failed to get sensor thresholds for "
		    "node %s (%s)\n", topo_node_name(fnode), ipmi_errmsg(hdl));
		return (topo_mod_seterrno(mod, EMOD_PARTIAL_ENUM));
	}

	/*
	 * The IPMI Get Sensor Thresholds command returns a bitmask describing
	 * which of the 3 upper and lower thresholds are readable.  Iterate
	 * through those and create a topo property for each threshold that is
	 * readable.
	 */
	mask = thresh.ithr_readable_mask;
	for (i = 0; i < num_thresholds; i++) {
		if (!ISBITSET(mask, threshset[i].sthr_threshbit))
			continue;

		if (set_thresh_prop(mod, fnode, sd->sd_fs_sdr,
		    *(uint8_t *)((char *)&thresh +
		    threshset[i].sthr_threshoff), &threshset[i]) != 0) {
			/* errno set */
			return (-1);
		}
	}
	return (0);
}

static boolean_t
seq_search(char *key, char **list, uint_t nelem)
{
	for (int i = 0; i < nelem; i++)
		if (strcmp(key, list[i]) == 0)
			return (B_TRUE);
	return (B_FALSE);
}

/* ARGSUSED */
static int
sdr_callback(ipmi_handle_t *hdl, const char *id, ipmi_sdr_t *sdr, void *data)
{
	uint8_t sensor_entity, sensor_inst;
	int sensor_idlen;
	ipmi_sdr_full_sensor_t *f_sensor = NULL;
	ipmi_sdr_compact_sensor_t *c_sensor = NULL;
	struct sensor_data sd;
	struct entity_info *ei = (struct entity_info *)data;

	switch (sdr->is_type) {
		case IPMI_SDR_TYPE_FULL_SENSOR:
			f_sensor =
			    (ipmi_sdr_full_sensor_t *)sdr->is_record;
			sensor_entity = f_sensor->is_fs_entity_id;
			sensor_inst = f_sensor->is_fs_entity_instance;
			sensor_idlen = f_sensor->is_fs_idlen;
			(void) strncpy(sd.sd_entity_ref,
			    f_sensor->is_fs_idstring,
			    f_sensor->is_fs_idlen);
			sd.sd_entity_ref[sensor_idlen] = '\0';
			sd.sd_units = f_sensor->is_fs_unit2;
			sd.sd_stype = f_sensor->is_fs_type;
			sd.sd_rtype = f_sensor->is_fs_reading_type;
			sd.sd_fs_sdr = f_sensor;
			break;
		case IPMI_SDR_TYPE_COMPACT_SENSOR:
			c_sensor =
			    (ipmi_sdr_compact_sensor_t *)sdr->is_record;
			sensor_entity = c_sensor->is_cs_entity_id;
			sensor_inst = c_sensor->is_cs_entity_instance;
			sensor_idlen = c_sensor->is_cs_idlen;
			(void) strncpy(sd.sd_entity_ref,
			    c_sensor->is_cs_idstring,
			    sensor_idlen);
			sd.sd_entity_ref[sensor_idlen] = '\0';
			sd.sd_units = c_sensor->is_cs_unit2;
			sd.sd_stype = c_sensor->is_cs_type;
			sd.sd_rtype = c_sensor->is_cs_reading_type;
			sd.sd_fs_sdr = NULL;
			break;
		default:
			return (0);
	}
	if (sd.sd_rtype == IPMI_RT_THRESHOLD)
		sd.sd_class = TOPO_SENSOR_CLASS_THRESHOLD;
	else
		sd.sd_class = TOPO_SENSOR_CLASS_DISCRETE;

	/*
	 * We offset the threshold and generic sensor reading types by 0x100
	 */
	if (sd.sd_rtype >= 0x1 && sd.sd_rtype <= 0xc)
		sd.sd_stype = sd.sd_rtype + 0x100;

	if ((ei->ei_list != NULL && seq_search(sd.sd_entity_ref,
	    ei->ei_list, ei->ei_listsz) == B_TRUE) ||
	    (sensor_entity == ei->ei_id && sensor_inst == ei->ei_inst)) {

		if (make_sensor_node(ei->ei_mod, ei->ei_node, &sd, hdl) != 0) {
			topo_mod_dprintf(ei->ei_mod, "Failed to create sensor "
			    "node for %s\n", sd.sd_entity_ref);
			if (topo_mod_errno(ei->ei_mod) != EMOD_NODE_DUP)
				return (-1);
		}
	}
	return (0);
}

static int
get_entity_info(topo_mod_t *mod, tnode_t *node, ipmi_handle_t *hdl,
    struct entity_info *ei)
{
	char **entity_refs;
	int err;
	uint_t nelems;
	ipmi_sdr_t *ref_sdr;
	ipmi_sdr_full_sensor_t *fsensor;
	ipmi_sdr_compact_sensor_t *csensor;
	ipmi_sdr_fru_locator_t *floc;
	ipmi_sdr_generic_locator_t *gloc;
	boolean_t found_sdr = B_FALSE;

	/*
	 * Use the entity ref to lookup the SDR, which will have the entity ID
	 * and instance.
	 */
	if (topo_prop_get_string_array(node, TOPO_PGROUP_IPMI,
	    "entity_ref", &entity_refs, &nelems, &err) != 0) {
		topo_mod_dprintf(mod, "%s: Failed to lookup entity_ref "
		    "property on %s=%d (%s)\n", __func__, topo_node_name(node),
		    topo_node_instance(node), topo_strerror(err));
		topo_mod_ipmi_rele(mod);
		return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
	}

	for (int i = 0; i < nelems; i++) {
		if ((ref_sdr = ipmi_sdr_lookup(hdl, entity_refs[i])) != NULL) {
			found_sdr = B_TRUE;
			break;
		} else
			topo_mod_dprintf(mod, "%s: Failed to lookup SDR for %s "
			    "(%s)\n", __func__, entity_refs[i],
			    ipmi_errmsg(hdl));
	}
	strarr_free(mod, entity_refs, nelems);
	if (! found_sdr) {
		topo_mod_ipmi_rele(mod);
		return (-1);
	}

	switch (ref_sdr->is_type) {
		case IPMI_SDR_TYPE_FULL_SENSOR:
			fsensor = (ipmi_sdr_full_sensor_t *)ref_sdr->is_record;
			ei->ei_id = fsensor->is_fs_entity_id;
			ei->ei_inst = fsensor->is_fs_entity_instance;
			break;
		case IPMI_SDR_TYPE_COMPACT_SENSOR:
			csensor
			    = (ipmi_sdr_compact_sensor_t *)ref_sdr->is_record;
			ei->ei_id = csensor->is_cs_entity_id;
			ei->ei_inst = csensor->is_cs_entity_instance;
			break;
		case IPMI_SDR_TYPE_FRU_LOCATOR:
			floc = (ipmi_sdr_fru_locator_t *)ref_sdr->is_record;
			ei->ei_id = floc->is_fl_entity;
			ei->ei_inst = floc->is_fl_instance;
			break;
		case IPMI_SDR_TYPE_GENERIC_LOCATOR:
			gloc = (ipmi_sdr_generic_locator_t *)ref_sdr->is_record;
			ei->ei_id = gloc->is_gl_entity;
			ei->ei_inst = gloc->is_gl_instance;
			break;
		default:
			topo_mod_dprintf(mod, "Failed to determine entity id "
			    "and instance\n", ipmi_errmsg(hdl));
			topo_mod_ipmi_rele(mod);
			return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
	}
	return (0);
}

/* ARGSUSED */
static int
ipmi_sensor_enum(topo_mod_t *mod, tnode_t *node, topo_version_t vers,
    nvlist_t *in, nvlist_t **out)
{
	int err, ret = -1;
	struct entity_info ei = {0};
	ipmi_handle_t *hdl;

	if ((hdl = topo_mod_ipmi_hold(mod)) == NULL) {
		topo_mod_dprintf(mod, "Failed to get IPMI handle\n");
		return (-1);
	}

	/*
	 * For cases where the records in the SDR are hopelessly broken, then
	 * we'll resort to hardcoding a list of sensor entities that should be
	 * bound to this particular node.  Otherwise, we'll first check if the
	 * properties for the associated IPMI entity id and instance exist.  If
	 * not, we check for a property referencing an IPMI entity name on which
	 * we can lookup the entity ID and instance.  If none of the above pans
	 * out, then we bail out.
	 */
	if (topo_prop_get_string_array(node, TOPO_PGROUP_IPMI,
	    TOPO_PROP_IPMI_ENTITY_LIST, &ei.ei_list, &ei.ei_listsz, &err)
	    != 0 && (topo_prop_get_uint32(node, TOPO_PGROUP_IPMI,
	    TOPO_PROP_IPMI_ENTITY_ID, &ei.ei_id, &err) != 0 ||
	    topo_prop_get_uint32(node, TOPO_PGROUP_IPMI,
	    TOPO_PROP_IPMI_ENTITY_INST, &ei.ei_inst, &err) != 0)) {
		if (get_entity_info(mod, node, hdl, &ei) != 0)
			goto out;
	}
	ei.ei_node = node;
	ei.ei_mod = mod;

	/*
	 * Now iterate through all of the full and compact sensor data records
	 * and create a sensor facility node for each record that matches our
	 * entity ID and instance
	 */
	if ((ret = ipmi_sdr_iter(hdl, sdr_callback, &ei)) != 0) {
		topo_mod_dprintf(mod, "ipmi_sdr_iter() failed\n");
	}
out:
	topo_mod_ipmi_rele(mod);
	if (ei.ei_list != NULL)
		strarr_free(mod, ei.ei_list, ei.ei_listsz);

	return (ret);
}

static int
ipmi_entity(topo_mod_t *mod, tnode_t *node, topo_version_t vers,
    nvlist_t *in, nvlist_t **out)
{
	char **fmtarr, **entity_refs, buf[BUFSZ];
	tnode_t *refnode;
	uint_t nelems;
	int ret, inst1, inst2;
	uint32_t offset, nparams;
	nvlist_t *args, *nvl;

	if (vers > TOPO_METH_IPMI_ENTITY_VERSION)
		return (topo_mod_seterrno(mod, ETOPO_METHOD_VERNEW));

	if ((ret = nvlist_lookup_nvlist(in, TOPO_PROP_ARGS, &args)) != 0) {
		topo_mod_dprintf(mod, "Failed to lookup 'args' list (%s)\n",
		    strerror(ret));
		return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
	}
	if ((ret = nvlist_lookup_uint32(args, "offset", &offset)) != 0) {
		topo_mod_dprintf(mod, "Failed to lookup 'offset' arg (%s)\n",
		    strerror(ret));
		return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
	}
	if ((ret = nvlist_lookup_uint32(args, "nparams", &nparams)) != 0) {
		topo_mod_dprintf(mod, "Failed to lookup 'nparams' arg (%s)\n",
		    strerror(ret));
		return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
	}
	if (nvlist_lookup_string_array(args, "format", &fmtarr, &nelems) != 0) {
		topo_mod_dprintf(mod, "Failed to lookup 'format' arg (%s)\n",
		    strerror(errno));
		return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
	}

	if ((entity_refs = topo_mod_alloc(mod, (nelems * sizeof (char *))))
	    == NULL)
		return (topo_mod_seterrno(mod, EMOD_NOMEM));

	if (topo_node_flags(node) & TOPO_NODE_FACILITY)
		refnode = topo_node_parent(node);
	else
		refnode = node;

	for (int i = 0; i < nelems; i++) {
		switch (nparams) {
		case 1:
			/* LINTED: E_SEC_PRINTF_VAR_FMT */
			(void) snprintf(buf, BUFSZ, fmtarr[i],
			    (topo_node_instance(refnode) + offset));
			break;
		case 2:
			inst1 = topo_node_instance(topo_node_parent(refnode))
			    + offset;
			inst2 = topo_node_instance(refnode) + offset;
			/* LINTED: E_SEC_PRINTF_VAR_FMT */
			(void) snprintf(buf, BUFSZ, fmtarr[i], inst1, inst2);
			break;
		default:
			topo_mod_dprintf(mod, "Invalid 'nparams' argval (%d)\n",
			    nparams);
			strarr_free(mod, entity_refs, nelems);
			return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
		}
		entity_refs[i] = topo_mod_strdup(mod, buf);
	}
	if (topo_mod_nvalloc(mod, &nvl, NV_UNIQUE_NAME) != 0 ||
	    nvlist_add_string(nvl, TOPO_PROP_VAL_NAME, "entity_ref") != 0 ||
	    nvlist_add_uint32(nvl, TOPO_PROP_VAL_TYPE,
	    TOPO_TYPE_STRING_ARRAY) != 0 ||
	    nvlist_add_string_array(nvl, TOPO_PROP_VAL_VAL, entity_refs,
	    nelems) != 0) {

		topo_mod_dprintf(mod, "Failed to allocate 'out' nvlist\n");
		strarr_free(mod, entity_refs, nelems);
		nvlist_free(nvl);
		return (topo_mod_seterrno(mod, EMOD_NOMEM));
	}
	strarr_free(mod, entity_refs, nelems);
	*out = nvl;

	return (0);
}

/* ARGSUSED */
static int
dimm_ipmi_entity(topo_mod_t *mod, tnode_t *node, topo_version_t vers,
    nvlist_t *in, nvlist_t **out)
{
	char **fmtarr, **entity_refs, buf[BUFSZ];
	tnode_t *chip, *dimm;
	int ret;
	uint_t nelems;
	uint32_t offset;
	nvlist_t *args, *nvl;

	if ((ret = nvlist_lookup_nvlist(in, TOPO_PROP_ARGS, &args)) != 0) {
		topo_mod_dprintf(mod, "Failed to lookup 'args' list (%s)\n",
		    strerror(ret));
		return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
	}
	if ((ret = nvlist_lookup_uint32(args, "offset", &offset)) != 0) {
		topo_mod_dprintf(mod, "Failed to lookup 'offset' arg (%s)\n",
		    strerror(ret));
		return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
	}
	if (nvlist_lookup_string_array(args, "format", &fmtarr, &nelems) != 0) {
		topo_mod_dprintf(mod, "Failed to lookup 'format' arg (%s)\n",
		    strerror(errno));
		return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
	}

	if ((entity_refs = topo_mod_alloc(mod, (nelems * sizeof (char *))))
	    == NULL)
		return (topo_mod_seterrno(mod, EMOD_NOMEM));

	if (topo_node_flags(node) & TOPO_NODE_FACILITY)
		dimm = topo_node_parent(node);
	else
		dimm = node;

	chip = topo_node_parent(topo_node_parent(dimm));

	for (int i = 0; i < nelems; i++) {
		/* LINTED: E_SEC_PRINTF_VAR_FMT */
		(void) snprintf(buf, BUFSZ, fmtarr[i], topo_node_instance(chip),
		    (topo_node_instance(dimm) + offset));
		entity_refs[i] = topo_mod_strdup(mod, buf);
	}

	if (topo_mod_nvalloc(mod, &nvl, NV_UNIQUE_NAME) != 0 ||
	    nvlist_add_string(nvl, TOPO_PROP_VAL_NAME, "entity_ref") != 0 ||
	    nvlist_add_uint32(nvl, TOPO_PROP_VAL_TYPE,
	    TOPO_TYPE_STRING_ARRAY) != 0 ||
	    nvlist_add_string_array(nvl, TOPO_PROP_VAL_VAL, entity_refs, nelems)
	    != 0) {
		topo_mod_dprintf(mod, "Failed to allocate 'out' nvlist\n");
		strarr_free(mod, entity_refs, nelems);
		nvlist_free(nvl);
		return (topo_mod_seterrno(mod, EMOD_NOMEM));
	}
	strarr_free(mod, entity_refs, nelems);
	*out = nvl;

	return (0);
}

/* ARGSUSED */
static int
cs_ipmi_entity(topo_mod_t *mod, tnode_t *node, topo_version_t vers,
    nvlist_t *in, nvlist_t **out)
{
	char **fmtarr, **entity_refs, buf[BUFSZ];
	tnode_t *chip, *chan, *cs;
	int ret, dimm_num;
	uint_t nelems;
	uint32_t offset;
	nvlist_t *args, *nvl;

	if ((ret = nvlist_lookup_nvlist(in, TOPO_PROP_ARGS, &args)) != 0) {
		topo_mod_dprintf(mod, "Failed to lookup 'args' list (%s)\n",
		    strerror(ret));
		return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
	}
	if ((ret = nvlist_lookup_uint32(args, "offset", &offset)) != 0) {
		topo_mod_dprintf(mod, "Failed to lookup 'offset' arg (%s)\n",
		    strerror(ret));
		return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
	}
	if (nvlist_lookup_string_array(args, "format", &fmtarr, &nelems) != 0) {
		topo_mod_dprintf(mod, "Failed to lookup 'format' arg (%s)\n",
		    strerror(errno));
		return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
	}

	if ((entity_refs = topo_mod_alloc(mod, (nelems * sizeof (char *))))
	    == NULL)
		return (topo_mod_seterrno(mod, EMOD_NOMEM));

	if (topo_node_flags(node) & TOPO_NODE_FACILITY) {
		cs = topo_node_parent(node);
		chip = topo_node_parent(topo_node_parent(topo_node_parent(cs)));
		chan = topo_node_parent(cs);

		dimm_num = topo_node_instance(cs) - (topo_node_instance(cs) % 2)
		    + topo_node_instance(cs) + offset;
	} else {
		cs = node;
		chip = topo_node_parent(topo_node_parent(topo_node_parent(cs)));
		chan = topo_node_parent(cs);

		dimm_num = topo_node_instance(cs) - (topo_node_instance(cs) % 2)
		    + topo_node_instance(chan) + offset;
	}

	for (int i = 0; i < nelems; i++) {
		/* LINTED: E_SEC_PRINTF_VAR_FMT */
		(void) snprintf(buf, BUFSZ, fmtarr[i], topo_node_instance(chip),
		    dimm_num);
		entity_refs[i] = topo_mod_strdup(mod, buf);
	}

	if (topo_mod_nvalloc(mod, &nvl, NV_UNIQUE_NAME) != 0 ||
	    nvlist_add_string(nvl, TOPO_PROP_VAL_NAME, "entity_ref") != 0 ||
	    nvlist_add_uint32(nvl, TOPO_PROP_VAL_TYPE,
	    TOPO_TYPE_STRING_ARRAY) != 0 ||
	    nvlist_add_string_array(nvl, TOPO_PROP_VAL_VAL, entity_refs, nelems)
	    != 0) {
		topo_mod_dprintf(mod, "Failed to allocate 'out' nvlist\n");
		strarr_free(mod, entity_refs, nelems);
		nvlist_free(nvl);
		return (topo_mod_seterrno(mod, EMOD_NOMEM));
	}
	strarr_free(mod, entity_refs, nelems);
	*out = nvl;

	return (0);
}

/*ARGSUSED*/
static int
fac_prov_ipmi_enum(topo_mod_t *mod, tnode_t *rnode, const char *name,
    topo_instance_t min, topo_instance_t max, void *arg, void *unused)
{
	topo_pgroup_info_t pgi;
	int err;

	if (topo_node_flags(rnode) == TOPO_NODE_DEFAULT) {
		pgi.tpi_name = TOPO_PGROUP_IPMI;
		pgi.tpi_namestab = TOPO_STABILITY_PRIVATE;
		pgi.tpi_datastab = TOPO_STABILITY_PRIVATE;
		pgi.tpi_version = 1;
		if (topo_pgroup_create(rnode, &pgi, &err) != 0) {
			if (err != ETOPO_PROP_DEFD) {
				topo_mod_dprintf(mod,
				    "pgroups create failure: %s\n",
				    topo_strerror(err));
				return (-1);
			}
		}
		if (topo_method_register(mod, rnode, ipmi_node_methods) != 0) {
			topo_mod_dprintf(mod, "fac_prov_ipmi_enum: "
			    "topo_method_register() failed: %s",
			    topo_mod_errmsg(mod));
			return (-1);
		}
	} else {
		if (topo_method_register(mod, rnode, ipmi_fac_methods) != 0) {
			topo_mod_dprintf(mod, "fac_prov_ipmi_enum: "
			    "topo_method_register() failed: %s",
			    topo_mod_errmsg(mod));
			return (-1);
		}
	}
	return (0);
}
