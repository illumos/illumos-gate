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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * sun4u specific DDI implementation
 */
#include <sys/bootconf.h>
#include <sys/conf.h>
#include <sys/machsystm.h>
#include <sys/idprom.h>
#include <sys/promif.h>


/*
 * Favored drivers of this implementation
 * architecture.  These drivers MUST be present for
 * the system to boot at all.
 */
char *impl_module_list[] = {
	"rootnex",
	"options",
	"sad",		/* Referenced via init_tbl[] */
	"pseudo",
	"clone",
	"scsi_vhci",
	(char *)0
};

/*
 * Check the status of the device node passed as an argument.
 *
 *	if ((status is OKAY) || (status is DISABLED))
 *		return DDI_SUCCESS
 *	else
 *		print a warning and return DDI_FAILURE
 */
/*ARGSUSED*/
int
check_status(int id, char *buf, dev_info_t *parent)
{
	char status_buf[64];
	extern int status_okay(int, char *, int);

	/*
	 * is the status okay?
	 */
	if (status_okay(id, status_buf, sizeof (status_buf)))
		return (DDI_SUCCESS);

	return (DDI_FAILURE);
}

/*
 * For Devices which are assigned to another logical domain, the
 * firmware modifies the various PCI properties so that no
 * driver will attach in the case where the OS instances does not
 * support ldoms direct I/O.  Since we do not support it, we can
 * restore those properties to their expected values.
 * See FWARC/2009/535.
 */
/*ARGSUSED*/
void
translate_devid(dev_info_t *dip)
{
	int devid, venid, ssid, ssvid, rev, class_code;
	char *new_compat[7];
	int i;
	int compat_entry_length = 30;
	int ncompat = 7;

	if ((devid = ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "real-device-id", -1)) == -1)
		return;
	if ((venid = ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "real-vendor-id", -1)) == -1)
		return;

	(void) ddi_prop_update_int(DDI_DEV_T_NONE, dip, "device-id", devid);
	(void) ddi_prop_update_int(DDI_DEV_T_NONE, dip, "vendor-id", venid);

	class_code = ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "real-class-code", 0);
	(void) ddi_prop_update_int(DDI_DEV_T_NONE, dip, "class-clode",
	    class_code);

	ssvid = ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "real-subsystem-vendor-id", -1);
	if (ssvid != -1)
		(void) ddi_prop_update_int(DDI_DEV_T_NONE, dip,
		    "subsystem-vendor-id", ssvid);

	ssid = ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "real-subsystem-id", -1);
	if (ssid != -1)
		(void) ddi_prop_update_int(DDI_DEV_T_NONE, dip, "subsystem-id",
		    ssid);

	rev = ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "real-revision-id", 0);
	(void) ddi_prop_update_int(DDI_DEV_T_NONE, dip, "revision-id", rev);

	for (i = 0; i < ncompat; ++i) {
		new_compat[i] = kmem_zalloc(compat_entry_length, KM_NOSLEEP);
		if (new_compat[i] == NULL) {
			cmn_err(CE_WARN, "translate_devid: kmem_alloc "
			    "failed\n");
			ncompat = i;
			goto cleanup;
		}
	}

	(void) sprintf(new_compat[0], "pciex%x,%x.%x.%x.%x",
	    venid, devid, ssvid, ssid, rev);
	(void) sprintf(new_compat[1], "pciex%x,%x.%x.%x",
	    venid, devid, ssvid, ssid);
	(void) sprintf(new_compat[2], "pciex%x,%x.%x", venid, devid, rev);
	(void) sprintf(new_compat[3], "pciex%x,%x", venid, devid);
	(void) sprintf(new_compat[4], "pciexclass,%06x", class_code);
	(void) sprintf(new_compat[5], "pciexclass,%04x", class_code >> 8);
	(void) sprintf(new_compat[6], "pci%x,%x", venid, devid);

	(void) ddi_prop_update_string_array(DDI_DEV_T_NONE, dip, "compatible",
	    (char **)new_compat, 7);

cleanup:
	for (i = 0; i < ncompat; ++i)
		kmem_free(new_compat[i], compat_entry_length);

	(void) ddi_prop_update_int(DDI_DEV_T_NONE, dip, "ddi-assigned", 0);
	(void) ddi_prop_update_int(DDI_DEV_T_NONE, dip, DDI_NO_AUTODETACH, 1);
}
