/***************************************************************************
 *
 * devinfo_cpu : cpu devices
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Licensed under the Academic Free License version 2.1
 *
 **************************************************************************/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <string.h>
#include <kstat.h>
#include <sys/utsname.h>
#include <libdevinfo.h>
#include <sys/systeminfo.h>

#include "../osspec.h"
#include "../logger.h"
#include "../hald.h"
#include "../hald_dbus.h"
#include "../device_info.h"
#include "../util.h"
#include "devinfo_cpu.h"

static HalDevice *devinfo_cpu_add(HalDevice *, di_node_t, char *, char *);

DevinfoDevHandler devinfo_cpu_handler = {
	devinfo_cpu_add,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL
};

static HalDevice *
devinfo_cpu_add(HalDevice *parent, di_node_t node, char *devfs_path, char *device_type)
{

	HalDevice	*d;
	char		*prom_device_type = NULL;
	int		*int_cpu_id;
	static int	cpu_id = -1;
	uint64_t	clock_mhz;
	di_prom_handle_t phdl;
	kstat_ctl_t	*kc;
	kstat_t		*ksp;
	kstat_named_t	*ksdata;
	dbus_bool_t	is_supp_freqs;
	char		udi[HAL_PATH_MAX];
	char		*driver_name, *s;
	char		cpu_devfs_path[HAL_PATH_MAX];

	/*
	 * If it is x86, the software device tree node will have the
	 * device_type information which is the one passed above. If it is
	 * NULL, check if the node has a PROM entry, and check the device_type
	 * in case of sparc. Else return NULL
	 */
	if (device_type == NULL) {
		/*
		 * Check the device type if it has a PROM entry. Because
		 * in sparc, the device_type entry will in the PROM node
		 */
		if (di_nodeid (node) == DI_PROM_NODEID) {
			phdl = di_prom_init ();
			if (phdl == DI_PROM_HANDLE_NIL) {
				HAL_ERROR (("Error in Initializing the PROM "
				    "handle to find cpu device: %s",
				    strerror (errno)));
				return (NULL);
			}
			if (di_prom_prop_lookup_strings (phdl, node,
			    "device_type", &prom_device_type) == -1) {
				di_prom_fini (phdl);
				return (NULL);
			}
			if (strcmp (prom_device_type, "cpu") != 0) {
				di_prom_fini (phdl);
				return (NULL);
			}
			/*
			 * Get cpuid if available
			 */
			if (di_prom_prop_lookup_ints (phdl, node,
			    "cpuid", &int_cpu_id) > 0) {
				cpu_id = *int_cpu_id;
			} else {
				/*
				 * There is no cpuid entry in this arch.Just
				 * increment the cpuid which will be the
				 * current instance
				 */
				++cpu_id;
			}
			di_prom_fini (phdl);
		} else {
			return (NULL);
		}

	} else if (strcmp (device_type, "cpu") == 0) {
		/*
		 * This is a x86 arch, because software device tree node
		 * has the device_type entry for cpu. The "reg" property
		 * will have the cpuid. If not just increment the cpuid
		 * which will be the current cpu instance in the kstat
		 */
		if (di_prop_lookup_ints (DDI_DEV_T_ANY, node,
		    "reg", &int_cpu_id) > 0) {
			cpu_id = *int_cpu_id;
		} else {
			/*
			 * There is no cpuid entry in this arch. Just
			 * increment the cpuid which will be the
			 * current instance
			 */
			++cpu_id;
		}

	} else {
		return (NULL);
	}

	HAL_DEBUG (("CPUID=> %x", cpu_id));

	d = hal_device_new ();

	/*
	 * devinfo_set_default_properties () uses di_instance() as part of
	 * the udi. For some solaris devices like cpu di_instance() is not
	 * present and it returns -1. For the udi to be unique can use the
	 * cpu_id.
	 */
	hal_device_property_set_string (d, "info.parent",
	    "/org/freedesktop/Hal/devices/local");

	/*
	 * If cpu driver is not installed, then devfs_path returned by
	 * libdevinfo will be same for all cpu's.
	 * Since HAL stores the devices in its tree based on the devfs_path,
	 * To make it unique, will be concatenating devfs_path with cpu_id
	 */
	if (di_driver_name (node) == NULL) {
		snprintf (cpu_devfs_path, HAL_PATH_MAX, "%s_%d",
		    devfs_path, cpu_id);
	} else {
		snprintf (cpu_devfs_path, HAL_PATH_MAX, "%s", devfs_path);
	}

	HAL_DEBUG(("DevfsPath=> %s, CPUID=> %d", cpu_devfs_path, cpu_id));

	hal_util_compute_udi (hald_get_gdl (), udi, sizeof (udi),
	    "/org/freedesktop/Hal/devices%s_%d", cpu_devfs_path, cpu_id);
	hal_device_set_udi (d, udi);
	hal_device_property_set_string (d, "info.udi", udi);
	if (di_prop_lookup_strings (DDI_DEV_T_ANY, node, "model", &s) > 0) {
		hal_device_property_set_string (d, "info.product", s);
	} else {
		hal_device_property_set_string (d, "info.product",
		    di_node_name (node));
	}
	hal_device_property_set_string (d, "solaris.devfs_path",
	    cpu_devfs_path);
	if ((driver_name = di_driver_name (node)) != NULL) {
		hal_device_property_set_string (d, "info.solaris.driver",
		    driver_name);
	}

	hal_device_add_capability (d, "processor");

	hal_device_property_set_int (d, "processor.number", cpu_id);

	/*
	 * Get the cpu related info from the kstat
	 */
	kc = kstat_open ();
	if (kc == NULL) {
		HAL_ERROR (("Could not open kstat to get cpu info: %s",
		    strerror (errno)));
		goto next;
	}

	ksp = kstat_lookup (kc, "cpu_info", cpu_id, NULL);
	if (ksp == NULL) {
		HAL_ERROR (("Could not lookup kstat to get cpu info: %s",
		    strerror (errno)));
		if (kc) {
			kstat_close (kc);
		}
		return (NULL);
	}

	kstat_read (kc, ksp, NULL);
	ksdata = (kstat_named_t *)kstat_data_lookup (ksp, "clock_MHz");
	if (ksdata == NULL) {
		HAL_ERROR (("Could not get kstat clock_MHz data for cpu: %s",
		    strerror (errno)));
		goto next;
	}
	clock_mhz = (uint64_t)ksdata->value.l;

	if (hal_device_property_set_uint64 (d, "processor.maximum_speed",
	    clock_mhz) == FALSE) {
		HAL_INFO (("Could not set the processor speed device prop"));
	}


	ksdata = (kstat_named_t *)kstat_data_lookup (ksp,
	    "supported_frequencies_Hz");
	if (ksdata == NULL) {
		HAL_INFO (("Could not get kstat supported_frequencies_Hz data"
		    " for cpu: %s", strerror (errno)));
		is_supp_freqs = FALSE;
	} else {
		/*
		 * If more than one freq is supported, then they are seperated
		 * by a ":"
		 */
		if (strstr (ksdata->value.str.addr.ptr, ":") == NULL) {
			is_supp_freqs = FALSE;
		} else {
			is_supp_freqs = TRUE;
		}
	}

	if (hal_device_property_set_bool (d, "processor.can_throttle",
	    is_supp_freqs) == FALSE) {
		HAL_INFO (("Could not set the processor.can_throttle"
		    " device prop"));
	}

next:
	if (kc) {
		kstat_close (kc);
	}

	devinfo_add_enqueue (d, cpu_devfs_path, &devinfo_cpu_handler);
	return (d);
}
