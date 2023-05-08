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
 * Copyright 2019, Joyent, Inc.
 * Copyright 2020 Oxide Computer Company
 */

/*
 * This file provides routines to interact with the kernel sensor framework.
 * Currently, modules that require interacting with a kernel sensor need to
 * build this file as part of the module. This takes care of all the work of
 * setting up and creating the sensor, given a path to that sensor.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <libnvpair.h>
#include <sys/sensors.h>
#include <sys/fm/protocol.h>
#include <fm/topo_mod.h>

#define	TOPO_METH_TOPO_SENSOR_SCALAR		"topo_sensor_scalar_reading"
#define	TOPO_METH_TOPO_SENSOR_SCALAR_DESC	"Kernel Sensor Scalar Reading"
#define	TOPO_METH_TOPO_SENSOR_SCALAR_VERSION	0

static int
topo_sensor_scalar_read(topo_mod_t *mod, tnode_t *node, topo_version_t vers,
    nvlist_t *in, nvlist_t **out)
{
	int fd = -1, ret;
	nvlist_t *args, *nvl;
	char *path;
	sensor_ioctl_scalar_t scalar;
	double value;

	if (vers != TOPO_METH_TOPO_SENSOR_SCALAR_VERSION) {
		return (topo_mod_seterrno(mod, ETOPO_METHOD_VERNEW));
	}

	if (nvlist_lookup_nvlist(in, TOPO_PROP_ARGS, &args) != 0 ||
	    nvlist_lookup_string(args, TOPO_IO_DEV_PATH, &path) != 0) {
		topo_mod_dprintf(mod, "failed to lookup sensor path from "
		    "property %s", TOPO_IO_DEV_PATH);
		return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
	}

	if ((fd = open(path, O_RDONLY)) < 0) {
		topo_mod_dprintf(mod, "failed to open sensor path %s: %s",
		    path, strerror(errno));
		return (topo_mod_seterrno(mod, EMOD_UNKNOWN));
	}

	(void) memset(&scalar, '\0', sizeof (scalar));
	if (ioctl(fd, SENSOR_IOCTL_SCALAR, &scalar) != 0) {
		topo_mod_dprintf(mod, "failed to read sensor %s: %s", path,
		    strerror(errno));
		ret = topo_mod_seterrno(mod, EMOD_UNKNOWN);
		goto out;
	}

	/*
	 * Check to see if we need to change the value to get it into an
	 * accurate reading. Positive granularities indicate that the sensor
	 * reading is in a fractional number of units and that each unit
	 * contains scalar.sis_gran steps. A negative number means that the
	 * sensor reading represents scalar.sis_gran units.
	 */
	value = (double)scalar.sis_value;
	if (scalar.sis_gran > 1) {
		value /= (double)scalar.sis_gran;
	} else if (scalar.sis_gran < -1) {
		value *= (double)labs(scalar.sis_gran);
	}

	if (topo_mod_nvalloc(mod, &nvl, NV_UNIQUE_NAME) != 0) {
		topo_mod_dprintf(mod, "failed to allocate output nvl");
		ret = topo_mod_seterrno(mod, EMOD_NOMEM);
		goto out;
	}

	if (nvlist_add_string(nvl, TOPO_PROP_VAL_NAME, TOPO_SENSOR_READING) !=
	    0 ||
	    nvlist_add_uint32(nvl, TOPO_PROP_VAL_TYPE, TOPO_TYPE_DOUBLE) != 0 ||
	    nvlist_add_double(nvl, TOPO_PROP_VAL_VAL, value) != 0) {
		topo_mod_dprintf(mod, "failed to add members to output "
		    "sensor nvlist");
		nvlist_free(nvl);
		ret = topo_mod_seterrno(mod, EMOD_NOMEM);
		goto out;
	}

	*out = nvl;
	ret = 0;
out:
	if (fd >= 0) {
		(void) close(fd);
	}
	return (ret);
}

static const topo_method_t topo_sensor_scalar_fac_methods[] = {
	{ TOPO_METH_TOPO_SENSOR_SCALAR, TOPO_METH_TOPO_SENSOR_SCALAR_DESC,
		TOPO_METH_TOPO_SENSOR_SCALAR_VERSION, TOPO_STABILITY_INTERNAL,
		topo_sensor_scalar_read },
	{ NULL }
};

static topo_sensor_unit_t
topo_sensor_units(const sensor_ioctl_scalar_t *scalar)
{
	switch (scalar->sis_unit) {
	case SENSOR_UNIT_CELSIUS:
		return (TOPO_SENSOR_UNITS_DEGREES_C);
	case SENSOR_UNIT_FAHRENHEIT:
		return (TOPO_SENSOR_UNITS_DEGREES_F);
	case SENSOR_UNIT_KELVIN:
		return (TOPO_SENSOR_UNITS_DEGREES_K);
	case SENSOR_UNIT_VOLTS:
		return (TOPO_SENSOR_UNITS_VOLTS);
	case SENSOR_UNIT_AMPS:
		return (TOPO_SENSOR_UNITS_AMPS);
	default:
		return (TOPO_SENSOR_UNITS_UNSPECIFIED);
	}
}

int
topo_sensor_create_scalar_sensor(topo_mod_t *mod, tnode_t *pnode,
    const char *path, const char *fname)
{
	int fd, ret, err;
	sensor_ioctl_kind_t sik;
	sensor_ioctl_scalar_t scalar;
	uint32_t topo_type;
	tnode_t *fnode = NULL;
	topo_pgroup_info_t pgi;
	nvlist_t *reader_arg = NULL;

	topo_mod_dprintf(mod, "attempting to create sensor for %s at %s",
	    topo_node_name(pnode), path);

	(void) memset(&sik, '\0', sizeof (sik));
	(void) memset(&scalar, '\0', sizeof (scalar));

	if ((fd = open(path, O_RDONLY)) < 0) {
		topo_mod_dprintf(mod, "failed to open sensor path %s: %s",
		    path, strerror(errno));

		/*
		 * We always try to create sensors; however, they may not exist
		 * or be supported on the system in question.  Therefore ENOENT
		 * is totally acceptable.
		 */
		if (errno == ENOENT) {
			return (0);
		}
		return (topo_mod_seterrno(mod, EMOD_UNKNOWN));
	}

	if (ioctl(fd, SENSOR_IOCTL_KIND, &sik) != 0) {
		topo_mod_dprintf(mod, "failed to verify sensor kind for sensor "
		    "%s: %s", path, strerror(errno));
		ret = topo_mod_seterrno(mod, EMOD_UNKNOWN);
		goto out;
	}

	switch (sik.sik_kind) {
	case SENSOR_KIND_TEMPERATURE:
		topo_type = TOPO_SENSOR_TYPE_TEMP;
		break;
	case SENSOR_KIND_VOLTAGE:
		topo_type = TOPO_SENSOR_TYPE_VOLTAGE;
		break;
	case SENSOR_KIND_CURRENT:
		topo_type = TOPO_SENSOR_TYPE_CURRENT;
		break;
	default:
		topo_mod_dprintf(mod, "unknown sensor kind for %s, found 0x%"
		    PRIx64, path, sik.sik_kind);
		ret = topo_mod_seterrno(mod, EMOD_UNKNOWN);
		goto out;

	}

	if (ioctl(fd, SENSOR_IOCTL_SCALAR, &scalar) != 0) {
		topo_mod_dprintf(mod, "failed to read scalar sensor %s: %s",
		    path, strerror(errno));
		ret = topo_mod_seterrno(mod, EMOD_UNKNOWN);
		goto out;
	}

	(void) close(fd);
	fd = -1;

	if ((fnode = topo_node_facbind(mod, pnode, fname,
	    TOPO_FAC_TYPE_SENSOR)) == NULL) {
		topo_mod_dprintf(mod, "failed to bind sensor facility "
		    "node to %s: %d", path, topo_mod_errno(mod));
		ret = -1;
		goto out;
	}

	pgi.tpi_name = TOPO_PGROUP_FACILITY;
	pgi.tpi_namestab = TOPO_STABILITY_PRIVATE;
	pgi.tpi_datastab = TOPO_STABILITY_PRIVATE;
	pgi.tpi_version = 1;

	if (topo_pgroup_create(fnode, &pgi, &err) != 0) {
		topo_mod_dprintf(mod, "failed to create facility pgroup: %s",
		    topo_strerror(err));
		ret = topo_mod_seterrno(mod, err);
		goto out;
	}

	if (topo_prop_set_string(fnode, TOPO_PGROUP_FACILITY,
	    TOPO_SENSOR_CLASS, TOPO_PROP_IMMUTABLE,
	    TOPO_SENSOR_CLASS_THRESHOLD, &err) != 0 ||
	    topo_prop_set_uint32(fnode, TOPO_PGROUP_FACILITY,
	    TOPO_FACILITY_TYPE, TOPO_PROP_IMMUTABLE, topo_type, &err) != 0 ||
	    topo_prop_set_uint32(fnode, TOPO_PGROUP_FACILITY,
	    TOPO_SENSOR_UNITS, TOPO_PROP_IMMUTABLE, topo_sensor_units(&scalar),
	    &err) != 0) {
		topo_mod_dprintf(mod, "failed to set properties for sensor "
		    "%s: %s", path, topo_strerror(err));
		ret = topo_mod_seterrno(mod, err);
		goto out;

	}

	if (topo_method_register(mod, fnode, topo_sensor_scalar_fac_methods) <
	    0) {
		topo_mod_dprintf(mod, "failed to register reading methods on "
		    "%s", path);
		ret = -1;
		goto out;
	}

	if (topo_mod_nvalloc(mod, &reader_arg, NV_UNIQUE_NAME) != 0 ||
	    nvlist_add_string(reader_arg, TOPO_IO_DEV_PATH, path) != 0) {
		topo_mod_dprintf(mod, "Failed to set up reader argument nvl");
		ret = topo_mod_seterrno(mod, EMOD_NOMEM);
		goto out;
	}

	if (topo_prop_method_register(fnode, TOPO_PGROUP_FACILITY,
	    TOPO_SENSOR_READING, TOPO_TYPE_DOUBLE, TOPO_METH_TOPO_SENSOR_SCALAR,
	    reader_arg, &err) != 0) {
		topo_mod_dprintf(mod, "failed to set argument for sensor %s: "
		    "%s", path, topo_strerror(err));
		ret = topo_mod_seterrno(mod, err);
		goto out;
	}

	topo_mod_dprintf(mod, "created sensor at %s", path);

	nvlist_free(reader_arg);
	return (0);
out:
	if (fd >= 0) {
		(void) close(fd);
	}

	topo_node_unbind(fnode);
	nvlist_free(reader_arg);
	return (ret);
}
