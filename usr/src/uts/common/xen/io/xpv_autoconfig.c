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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/hypervisor.h>
#include <sys/sunndi.h>
#include <sys/sunddi.h>
#include <sys/ddi_subrdefs.h>
#include <sys/bootconf.h>
#include <sys/psw.h>
#include <sys/modctl.h>
#include <sys/errno.h>
#include <sys/reboot.h>
#include <sys/hypervisor.h>
#include <xen/sys/xenbus_comms.h>
#include <xen/sys/xenbus_impl.h>
#include <xen/sys/xendev.h>

extern int xen_boot_debug;

/*
 * Internal structures and functions
 */
int xendev_nounload = 0;
void xendev_enumerate(int);

/*
 * Interface routines
 */

static struct modlmisc modlmisc = {
	&mod_miscops, "virtual device probe"
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modlmisc, NULL
};

int
_init(void)
{
	int	err;

	if ((err = mod_install(&modlinkage)) != 0)
		return (err);

	impl_bus_add_probe(xendev_enumerate);
	return (0);
}

int
_fini(void)
{
	int	err;

	if (xendev_nounload)
		return (EBUSY);

	if ((err = mod_remove(&modlinkage)) != 0)
		return (err);

	impl_bus_delete_probe(xendev_enumerate);
	return (0);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}


/*
 * This functions is invoked twice, first time with reprogram=0 to
 * set up the xpvd portion of the device tree. The second time is
 * ignored.
 */
void
xendev_enumerate(int reprogram)
{
	dev_info_t *dip;

	if (reprogram != 0)
		return;

	ndi_devi_alloc_sleep(ddi_root_node(), "xpvd",
	    (pnode_t)DEVI_SID_NODEID, &dip);

	(void) ndi_devi_bind_driver(dip, 0);

	/*
	 * Too early to enumerate split device drivers in domU
	 * since we need to create taskq thread during enumeration.
	 * So, we only enumerate softdevs and console here.
	 */
	xendev_enum_all(dip, B_TRUE);
}
