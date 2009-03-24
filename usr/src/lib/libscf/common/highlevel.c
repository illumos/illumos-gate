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
 * This file contains high level functions used by multiple utilities.
 */

#include "libscf_impl.h"

#include <assert.h>
#include <libuutil.h>
#include <string.h>
#include <stdlib.h>
#include <sys/systeminfo.h>
#include <sys/uadmin.h>
#include <sys/utsname.h>

#ifdef	__x86
#include <smbios.h>

/*
 * Check whether the platform is on the fastreboot_blacklist.
 * Return 1 if the platform has been blacklisted, 0 otherwise.
 */
static int
scf_is_fb_blacklisted(void)
{
	smbios_hdl_t *shp;
	smbios_system_t sys;
	smbios_info_t info;

	id_t id;
	int err;
	int i;

	scf_simple_prop_t *prop = NULL;
	ssize_t numvals;
	char *platform_name;

	int blacklisted = 0;

	/*
	 * If there's no SMBIOS, assume it's blacklisted.
	 */
	if ((shp = smbios_open(NULL, SMB_VERSION, 0, &err)) == NULL)
		return (1);

	/*
	 * If we can't read system info, assume it's blacklisted.
	 */
	if ((id = smbios_info_system(shp, &sys)) == SMB_ERR ||
	    smbios_info_common(shp, id, &info) == SMB_ERR) {
		blacklisted = 1;
		goto fb_out;
	}

	/*
	 * If we can't read the "platforms" property from property group
	 * BOOT_CONFIG_PG_FBBLACKLIST, assume no platforms have
	 * been blacklisted.
	 */
	if ((prop = scf_simple_prop_get(NULL, FMRI_BOOT_CONFIG,
	    BOOT_CONFIG_PG_FBBLACKLIST, "platforms")) == NULL)
		goto fb_out;

	numvals = scf_simple_prop_numvalues(prop);

	for (i = 0; i < numvals; i++) {
		platform_name = scf_simple_prop_next_astring(prop);
		if (platform_name == NULL)
			break;
		if (strcmp(platform_name, info.smbi_product) == 0) {
			blacklisted = 1;
			break;
		}
	}

fb_out:
	smbios_close(shp);
	scf_simple_prop_free(prop);

	return (blacklisted);
}
#endif	/* __x86 */

/*
 * Get config properties from svc:/system/boot-config:default.
 * It prints errors with uu_warn().
 */
void
scf_get_boot_config(uint8_t *boot_config)
{
	assert(boot_config);
	*boot_config = 0;

#ifndef	__x86
	return;
#else
	{
		/*
		 * Property vector for BOOT_CONFIG_PG_PARAMS property group.
		 */
		scf_propvec_t ua_boot_config[] = {
			{ "fastreboot_default", NULL, SCF_TYPE_BOOLEAN, NULL,
			    UA_FASTREBOOT_DEFAULT },
			{ FASTREBOOT_ONPANIC, NULL, SCF_TYPE_BOOLEAN, NULL,
			    UA_FASTREBOOT_ONPANIC },
			{ NULL }
		};
		scf_propvec_t	*prop;

		for (prop = ua_boot_config; prop->pv_prop != NULL; prop++)
			prop->pv_ptr = boot_config;
		prop = NULL;
		if (scf_read_propvec(FMRI_BOOT_CONFIG, BOOT_CONFIG_PG_PARAMS,
		    B_TRUE, ua_boot_config, &prop) != SCF_FAILED) {
			/*
			 * Unset both flags if the platform has been
			 * blacklisted.
			 */
			if (scf_is_fb_blacklisted())
				*boot_config &= ~(UA_FASTREBOOT_DEFAULT |
				    UA_FASTREBOOT_ONPANIC);
			return;
		}
#if defined(FASTREBOOT_DEBUG)
		if (prop != NULL) {
			(void) uu_warn("Service %s property '%s/%s' "
			    "not found.\n", FMRI_BOOT_CONFIG,
			    BOOT_CONFIG_PG_PARAMS, prop->pv_prop);
		} else {
			(void) uu_warn("Unable to read service %s "
			    "property '%s': %s\n", FMRI_BOOT_CONFIG,
			    BOOT_CONFIG_PG_PARAMS, scf_strerror(scf_error()));
		}
#endif	/* FASTREBOOT_DEBUG */
	}
#endif	/* __x86 */
}

/*
 * Check whether Fast Reboot is the default operating mode.
 * Return 0 if
 *   1. the platform is xVM
 * or
 *   2. svc:/system/boot-config:default service doesn't exist,
 * or
 *   3. property "fastreboot_default" doesn't exist,
 * or
 *   4. value of property "fastreboot_default" is set to 0.
 * or
 *   5. the platform has been blacklisted.
 * Return non-zero otherwise.
 */
int
scf_is_fastboot_default(void)
{
	uint8_t	boot_config = 0;
	char procbuf[SYS_NMLN];

	/*
	 * If we are on xVM, do not fast reboot by default.
	 */
	if (sysinfo(SI_PLATFORM, procbuf, sizeof (procbuf)) == -1 ||
	    strcmp(procbuf, "i86xpv") == 0)
		return (0);

	scf_get_boot_config(&boot_config);
	return (boot_config & UA_FASTREBOOT_DEFAULT);
}
