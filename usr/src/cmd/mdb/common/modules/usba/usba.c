/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2000-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Routines extracted from usr/src/uts/common/io/usb/usba/usba.c.
 */

#include <sys/mdb_modapi.h>
#include <sys/usb/usba.h>
#include <sys/usb/usba/usba_types.h>
#include <sys/usb/usba/usba_impl.h>
#include <sys/usb/usba/hcdi_impl.h>
#include <sys/file.h>
#include <sys/sunndi.h>


/*
 * check whether this dip is the root hub.
 * dip_addr is address of the devinfo struct in the core image (not local space)
 */
static int
mdb_usba_is_root_hub(struct dev_info *dip)
{
	uintptr_t	p = (uintptr_t)dip->devi_hw_prop_ptr;

	while (p != 0) {
		ddi_prop_t prop;
		char prop_name[128];

		if (mdb_vread(&prop, sizeof (prop), p) == -1) {
			mdb_warn("failed to read property");
			break;
		}
		if (mdb_readstr(prop_name, sizeof (prop_name),
		    (uintptr_t)prop.prop_name) == -1) {
			mdb_warn("failed to read property name");
		}

		if (strcmp(prop_name, "root-hub") == 0) {

			return (1);
		}

		p = (uintptr_t)prop.prop_next;
	}

	return (0);
}


/*
 * retrieve hcdi structure from the dip
 *
 * dip_addr is address of the devinfo struct in the core image (not local space)
 */
uintptr_t
mdb_usba_hcdi_get_hcdi(struct dev_info *dip)
{
	return ((uintptr_t)dip->devi_driver_data);
}


/*
 * get usba_device pointer in the devi
 *
 * dip_addr is address of the devinfo struct in the core image (not local space)
 */
uintptr_t
mdb_usba_get_usba_device(uintptr_t dip_addr)
{
	struct dev_info	devinfo;

	if (mdb_vread(&devinfo, sizeof (struct dev_info), dip_addr) == -1) {
		mdb_warn("failed to read dev_info at %p", dip_addr);

		return (0);
	}

	/*
	 * we cannot use parent_data in the usb node because its
	 * bus parent (eg. PCI nexus driver) uses this data
	 *
	 * we cannot use driver data in the other usb nodes since
	 * usb drivers may need to use this
	 */
	if (mdb_usba_is_root_hub(&devinfo)) {
		usba_hcdi_t hcdi_struct;
		uintptr_t hcdi_addr = mdb_usba_hcdi_get_hcdi(&devinfo);

		if (!hcdi_addr) {

			return (0);
		}

		/* Read hcdi struct into local address space. */
		if (mdb_vread(&hcdi_struct, sizeof (usba_hcdi_t),
		    hcdi_addr) == -1) {
			mdb_warn("failed to read hcdi struct");

			return (0);
		}

		return ((uintptr_t)hcdi_struct.hcdi_usba_device);

	} else {
		struct dev_info	devinfo;

		if (mdb_vread(&devinfo, sizeof (struct dev_info),
		    dip_addr) == -1) {
			mdb_warn("failed to read dev_info at %p", dip_addr);

			return (0);
		}

		/* casts needed to keep lint happy */
		return ((uintptr_t)devinfo.devi_parent_data);
	}
}
