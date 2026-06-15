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
 * Copyright 2026 OmniOS Community Edition (OmniOSce) Association.
 */

#include <sys/modctl.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/x86_archext.h>

/*
 * hvmboot_rootconf() exists to force attach all xdf disk driver nodes
 * before the cmdk disk driver comes along and tries to access any of
 * these nodes (which usually happens when mounting the root disk device
 * in an hvm environment).
 *
 * hvmboot_rootconf() also force attaches xnf network driver nodes so
 * that the boot interface can be plumbed when booted via the network.
 *
 * This module is part of the base i86pc platform and so is always present.
 * It must therefore do nothing unless we are running under Xen HVM.  On
 * bare metal there is no xpvd nexus to configure.
 */
int
hvmboot_rootconf()
{
	dev_info_t	*xpvd_dip;
	major_t		dev_major;

	if ((get_hwenv() & HW_XEN_HVM) == 0)
		return (0);

	dev_major = ddi_name_to_major("xdf");
	if (dev_major == (major_t)-1)
		cmn_err(CE_PANIC, "unable to load xdf disk driver");

	if (resolve_pathname("/xpvd", &xpvd_dip, NULL, NULL) != 0)
		cmn_err(CE_PANIC, "unable to configure /xpvd nexus");

	(void) ndi_devi_config_driver(xpvd_dip, 0, dev_major);

	dev_major = ddi_name_to_major("xnf");
	if (dev_major == (major_t)-1)
		cmn_err(CE_PANIC, "unable to load xnf network driver");
	(void) ndi_devi_config_driver(xpvd_dip, 0, dev_major);

	ndi_rele_devi(xpvd_dip);
	return (0);
}

static struct modlmisc modlmisc = {
	&mod_miscops, "hvm_bootstrap misc module"
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modlmisc, NULL
};

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

int
_init()
{
	return (mod_install(&modlinkage));
}

int
_fini()
{
	return (EBUSY);
}
