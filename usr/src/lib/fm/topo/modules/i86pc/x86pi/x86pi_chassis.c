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
 * Create chassis topology node from SMBIOS Type 3 structure
 */

#include <sys/types.h>
#include <strings.h>
#include <fm/topo_mod.h>
#include <fm/topo_hc.h>
#include <sys/systeminfo.h>
#include <sys/smbios_impl.h>
#include <x86pi_impl.h>


tnode_t *
x86pi_gen_chassis(topo_mod_t *mod, tnode_t *t_parent, smbios_hdl_t *shp,
    int smb_id, int instance)
{
	int			rv;
	smbios_info_t		ip;
	smbios_chassis_t	ch;
	x86pi_hcfmri_t		ch_hcfmri;
	tnode_t			*ch_node;
	char			*f = "x86pi_gen_chassis";


	/* init fmri struct */
	bzero(&ch_hcfmri, sizeof (x86pi_hcfmri_t));

	/* grab SMBIOS strings */
	rv = smbios_info_common(shp, smb_id, &ip);
	if (rv != 0) {
		return (NULL);
	}

	/* grab SMBIOS type 3 struct */
	rv = smbios_info_chassis(shp, smb_id, &ch);
	if (rv != 0) {
		return (NULL);
	}

	/* populate string entries */
	ch_hcfmri.serial_number = x86pi_cleanup_smbios_str(mod,
	    ip.smbi_serial, 0);
	ch_hcfmri.version = x86pi_cleanup_smbios_str(mod, ip.smbi_version, 0);
	ch_hcfmri.manufacturer = x86pi_cleanup_smbios_str(mod,
	    ip.smbi_manufacturer, 0);

	/* set hc_name and instance */
	ch_hcfmri.hc_name = topo_mod_strdup(mod, "chassis");
	ch_hcfmri.instance = instance;

	topo_mod_dprintf(mod, "%s: instance (%d)\n", f, ch_hcfmri.instance);
	topo_mod_dprintf(mod, "%s: hc name (%s)\n", f, ch_hcfmri.hc_name);
	topo_mod_dprintf(mod, "%s: Serial Number (%s)\n",
	    f, ch_hcfmri.serial_number);
	topo_mod_dprintf(mod, "%s: Version (%s)\n", f, ch_hcfmri.version);
	topo_mod_dprintf(mod, "%s: Manufacturer (%s)\n",
	    f, ch_hcfmri.manufacturer);

	/* create topo node */
	if (!instance) {
		/* First Chassis SMBIOS Record is Chassis topo instance 0 */
		rv = x86pi_enum_generic(mod, &ch_hcfmri, t_parent, NULL,
		    &ch_node, 0);
	} else {
		rv = x86pi_enum_generic(mod, &ch_hcfmri, t_parent, t_parent,
		    &ch_node, 0);
	}
	if (rv != 0) {
		topo_mod_dprintf(mod, "%s: failed to create %d tnode\n", f,
		    instance);
		return (NULL);
	}

	/* free up strings */
	if (ch_hcfmri.serial_number != NULL) {
		topo_mod_strfree(mod, (char *)ch_hcfmri.serial_number);
	}
	if (ch_hcfmri.version != NULL) {
		topo_mod_strfree(mod, (char *)ch_hcfmri.version);
	}
	if (ch_hcfmri.manufacturer != NULL) {
		topo_mod_strfree(mod, (char *)ch_hcfmri.manufacturer);
	}
	if (ch_hcfmri.hc_name != NULL) {
		topo_mod_strfree(mod, (char *)ch_hcfmri.hc_name);
	}

	return (ch_node);
}
