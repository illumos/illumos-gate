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

/*
 * Determine the PCI configuration mechanism recommended by the BIOS.
 */

#include <sys/types.h>
#include <sys/sunddi.h>
#include <sys/pci_impl.h>
#include <sys/ddi_subrdefs.h>
#include <sys/bootconf.h>
#include <sys/psw.h>
#include <sys/modctl.h>
#include <sys/errno.h>
#include <sys/pci.h>
#include <sys/pci_cfgspace.h>
#include <sys/reboot.h>
#include <sys/pci_cfgspace_impl.h>
#include <sys/mutex.h>

extern int pci_boot_debug;

/*
 * Interface routines
 */
void pci_enumerate(int);
void pci_setup_tree(void);
void pci_reprogram(void);

static struct modlmisc modlmisc = {
	&mod_miscops, "PCI BIOS interface"
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

	impl_bus_add_probe(pci_enumerate);
	return (0);
}

int
_fini(void)
{
	int	err;

	if ((err = mod_remove(&modlinkage)) != 0)
		return (err);

	impl_bus_delete_probe(pci_enumerate);
	return (0);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}


/*
 * This function is invoked twice: first time, with reprogram=0 to
 * set up the PCI portion of the device tree. The second time is
 * for reprogramming devices not set up by the BIOS.
 */
void
pci_enumerate(int reprogram)
{
	extern void add_pci_fixes(void);
	extern void undo_pci_fixes(void);

	add_pci_fixes();

	if (reprogram) {
		pci_reprogram();
		undo_pci_fixes();
		return;
	}

	/* setup device tree */
	pci_setup_tree();
	undo_pci_fixes();
}
